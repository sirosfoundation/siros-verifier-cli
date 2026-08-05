"""DeviceRequest/DeviceResponse handling - ISO/IEC 18013-5 §8.3.2.1.2, §8.3.2.1.2.3.

Builds multi-document, multi-namespace DeviceRequests, and decodes
DeviceResponse down to IssuerAuth (COSE_Sign1) and the embedded
MobileSecurityObject (MSO).

IssuerAuth signatures, certificate chains, and DeviceAuth are DECODED ONLY,
never cryptographically verified and never checked against a trust anchor -
trust evaluation is out of scope for this tool. Every field here is
UNVERIFIED input from the peer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import cbor2
from cryptography import x509

# ISO 18013-5 Table 15.
STATUS_NAMES = {
    0: "OK",
    10: "General error",
    11: "CBOR decoding error",
    12: "CBOR validation error",
}

# ISO 18013-5 Table 9 - only 0 has a document-defined meaning; other codes
# are RFU (positive) or application-specific (negative).
ERROR_CODE_NAMES = {0: "Data not returned"}

# RFC 9053 Table 5 (COSE algorithms likely to appear on an mdoc/mDL).
COSE_ALG_NAMES = {
    -7: "ES256",
    -35: "ES384",
    -36: "ES512",
    -8: "EdDSA",
}


@dataclass
class DocRequest:
    doc_type: str
    namespaces: dict[str, list[str]]


def build_device_request(doc_requests: list[DocRequest]) -> bytes:
    requests = []
    for dr in doc_requests:
        name_spaces = {ns: {claim: True for claim in claims} for ns, claims in dr.namespaces.items()}
        items_request = {"docType": dr.doc_type, "nameSpaces": name_spaces}
        requests.append({"itemsRequest": cbor2.CBORTag(24, cbor2.dumps(items_request))})
    return cbor2.dumps({"version": "1.0", "docRequests": requests})


def build_session_establishment(e_reader_key_tag: cbor2.CBORTag, encrypted_device_request: bytes) -> bytes:
    return cbor2.dumps({"eReaderKey": e_reader_key_tag, "data": encrypted_device_request})


def _unwrap_tagged24(value):
    """cbor2 decodes tag 24 as a CBORTag whose .value is the raw inner bytes -
    unwrap and decode it. Falls through unchanged if not a tag-24 wrapper
    (some encoders skip the outer wrapping)."""
    if isinstance(value, cbor2.CBORTag) and value.tag == 24:
        return cbor2.loads(value.value)
    return value


@dataclass
class CertificateInfo:
    subject: str
    issuer: str
    serial_number: int
    not_before: datetime | None
    not_after: datetime | None

    @classmethod
    def from_der(cls, der: bytes) -> CertificateInfo:
        cert = x509.load_der_x509_certificate(der)
        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        return cls(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=cert.serial_number,
            not_before=not_before,
            not_after=not_after,
        )


@dataclass
class MobileSecurityObject:
    version: str | None
    digest_algorithm: str | None
    doc_type: str | None
    value_digests: dict
    device_key: dict | None
    validity_info: dict

    @classmethod
    def from_cbor(cls, mso: dict) -> MobileSecurityObject:
        return cls(
            version=mso.get("version"),
            digest_algorithm=mso.get("digestAlgorithm"),
            doc_type=mso.get("docType"),
            value_digests=mso.get("valueDigests", {}),
            device_key=(mso.get("deviceKeyInfo") or {}).get("deviceKey"),
            validity_info=mso.get("validityInfo", {}),
        )


@dataclass
class IssuerAuthInfo:
    alg: int | None
    alg_name: str
    certificates: list[CertificateInfo] = field(default_factory=list)
    mso: MobileSecurityObject | None = None

    @classmethod
    def from_cose_sign1(cls, cose_sign1: list) -> IssuerAuthInfo:
        protected_bytes, unprotected, payload, _signature = cose_sign1
        protected = cbor2.loads(protected_bytes) if protected_bytes else {}
        alg = protected.get(1, unprotected.get(1))
        alg_name = COSE_ALG_NAMES.get(alg, f"unknown({alg})" if alg is not None else "none")

        x5chain = unprotected.get(33)
        der_certs: list[bytes]
        if x5chain is None:
            der_certs = []
        elif isinstance(x5chain, bytes):
            der_certs = [x5chain]
        else:
            der_certs = list(x5chain)
        certificates = [CertificateInfo.from_der(der) for der in der_certs]

        mso_cbor = _unwrap_tagged24(cbor2.loads(payload)) if payload else None
        mso = MobileSecurityObject.from_cbor(mso_cbor) if isinstance(mso_cbor, dict) else None

        return cls(alg=alg, alg_name=alg_name, certificates=certificates, mso=mso)


@dataclass
class ParsedElement:
    identifier: str
    value: object
    digest_id: int | None


@dataclass
class ParsedDocument:
    doc_type: str
    namespaces: dict[str, list[ParsedElement]]
    issuer_auth: IssuerAuthInfo | None
    device_namespaces: dict[str, dict]
    device_auth_type: str | None  # "deviceSignature" | "deviceMac" | None
    errors: dict


@dataclass
class DeviceResponseResult:
    version: str | None
    status: int
    status_name: str
    documents: list[ParsedDocument]
    document_errors: list[dict]


def _parse_issuer_signed_namespaces(name_spaces_cbor: dict) -> dict[str, list[ParsedElement]]:
    namespaces: dict[str, list[ParsedElement]] = {}
    for ns, tagged_items in name_spaces_cbor.items():
        elements = []
        for tagged_item in tagged_items:
            item = _unwrap_tagged24(tagged_item)
            elements.append(
                ParsedElement(
                    identifier=item["elementIdentifier"],
                    value=item["elementValue"],
                    digest_id=item.get("digestID"),
                )
            )
        namespaces[ns] = elements
    return namespaces


def _parse_document(doc: dict) -> ParsedDocument:
    issuer_signed = doc.get("issuerSigned", {})
    namespaces = _parse_issuer_signed_namespaces(issuer_signed.get("nameSpaces", {}))

    issuer_auth_cbor = issuer_signed.get("issuerAuth")
    issuer_auth = IssuerAuthInfo.from_cose_sign1(issuer_auth_cbor) if issuer_auth_cbor else None

    device_signed = doc.get("deviceSigned") or {}
    device_namespaces = _unwrap_tagged24(device_signed.get("nameSpaces")) or {} if device_signed else {}
    device_auth = device_signed.get("deviceAuth") or {}
    device_auth_type = next(iter(device_auth), None)

    return ParsedDocument(
        doc_type=doc["docType"],
        namespaces=namespaces,
        issuer_auth=issuer_auth,
        device_namespaces=device_namespaces,
        device_auth_type=device_auth_type,
        errors=doc.get("errors", {}),
    )


def parse_device_response(plaintext: bytes) -> DeviceResponseResult:
    device_response = cbor2.loads(plaintext)
    status = device_response.get("status", 0)
    documents = [_parse_document(doc) for doc in device_response.get("documents", [])]
    return DeviceResponseResult(
        version=device_response.get("version"),
        status=status,
        status_name=STATUS_NAMES.get(status, f"unknown({status})"),
        documents=documents,
        document_errors=device_response.get("documentErrors", []),
    )
