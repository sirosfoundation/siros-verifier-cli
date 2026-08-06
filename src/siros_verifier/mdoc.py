"""DeviceRequest/DeviceResponse handling - ISO/IEC 18013-5 §8.3.2.1.2, §8.3.2.1.2.3.

Builds multi-document, multi-namespace DeviceRequests, and decodes
DeviceResponse down to IssuerAuth (COSE_Sign1) and the embedded
MobileSecurityObject (MSO). Per-element digests and IssuerAuth's signature
are verified against the certificate presented in the message itself (see
verify.py); DeviceAuth verification additionally needs session context and
runs separately via verify_device_auth().

None of this is trust evaluation: certificate chains are never validated
against an IACA root and revocation is never checked - a "valid" signature
here means "internally consistent with the presented key", not "trustworthy".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from siros_verifier import crypto, verify

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
    signature_valid: bool | None = None  # None = not attempted (no cert / unsupported alg)

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

        signature_valid = None
        if der_certs:
            try:
                leaf_public_key = x509.load_der_x509_certificate(der_certs[0]).public_key()
                signature_valid = verify.verify_cose_sign1(cose_sign1, leaf_public_key)
            except verify.UnsupportedAlgorithm:
                signature_valid = None

        mso_cbor = _unwrap_tagged24(cbor2.loads(payload)) if payload else None
        mso = MobileSecurityObject.from_cbor(mso_cbor) if isinstance(mso_cbor, dict) else None

        return cls(
            alg=alg, alg_name=alg_name, certificates=certificates, mso=mso, signature_valid=signature_valid
        )


@dataclass
class ParsedElement:
    identifier: str
    value: object
    digest_id: int | None
    digest_valid: bool | None = None  # None = not attempted (no MSO / no matching digest)


@dataclass
class ParsedDocument:
    doc_type: str
    namespaces: dict[str, list[ParsedElement]]
    issuer_auth: IssuerAuthInfo | None
    device_namespaces: dict[str, dict]
    device_auth_type: str | None  # "deviceSignature" | "deviceMac" | None
    errors: dict
    device_auth_cbor: dict = field(default_factory=dict)
    device_namespaces_raw: bytes | None = None
    device_auth_valid: bool | None = None  # set by verify_device_auth(), which needs session context


@dataclass
class DeviceResponseResult:
    version: str | None
    status: int
    status_name: str
    documents: list[ParsedDocument]
    document_errors: list[dict]


def _parse_issuer_signed_namespaces(
    name_spaces_cbor: dict, mso: MobileSecurityObject | None
) -> dict[str, list[ParsedElement]]:
    namespaces: dict[str, list[ParsedElement]] = {}
    for ns, tagged_items in name_spaces_cbor.items():
        elements = []
        for tagged_item in tagged_items:
            item = _unwrap_tagged24(tagged_item)
            digest_id = item.get("digestID")

            digest_valid = None
            expected_digest = (mso.value_digests.get(ns, {}) if mso else {}).get(digest_id)
            if mso is not None and mso.digest_algorithm is not None and expected_digest is not None:
                try:
                    digest_valid = verify.verify_digest(
                        mso.digest_algorithm, cbor2.dumps(tagged_item), expected_digest
                    )
                except verify.UnsupportedAlgorithm:
                    digest_valid = None

            elements.append(
                ParsedElement(
                    identifier=item["elementIdentifier"],
                    value=item["elementValue"],
                    digest_id=digest_id,
                    digest_valid=digest_valid,
                )
            )
        namespaces[ns] = elements
    return namespaces


def _parse_document(doc: dict) -> ParsedDocument:
    issuer_signed = doc.get("issuerSigned", {})
    issuer_auth_cbor = issuer_signed.get("issuerAuth")
    issuer_auth = IssuerAuthInfo.from_cose_sign1(issuer_auth_cbor) if issuer_auth_cbor else None
    namespaces = _parse_issuer_signed_namespaces(
        issuer_signed.get("nameSpaces", {}), issuer_auth.mso if issuer_auth else None
    )

    device_signed = doc.get("deviceSigned") or {}
    device_namespaces_tag = device_signed.get("nameSpaces")
    device_namespaces = (_unwrap_tagged24(device_namespaces_tag) or {}) if device_namespaces_tag else {}
    device_namespaces_raw = cbor2.dumps(device_namespaces_tag) if device_namespaces_tag is not None else None
    device_auth = device_signed.get("deviceAuth") or {}
    device_auth_type = next(iter(device_auth), None)

    return ParsedDocument(
        doc_type=doc["docType"],
        namespaces=namespaces,
        issuer_auth=issuer_auth,
        device_namespaces=device_namespaces,
        device_auth_type=device_auth_type,
        errors=doc.get("errors", {}),
        device_auth_cbor=device_auth,
        device_namespaces_raw=device_namespaces_raw,
    )


def verify_device_auth(
    doc: ParsedDocument, session_transcript: bytes, e_reader_priv: ec.EllipticCurvePrivateKey
) -> bool | None:
    """Verify DeviceAuth (deviceSignature or deviceMac) against the deviceKey
    bound in the MSO - ISO 18013-5 §9.1.3. Requires the reader's own ephemeral
    private key and the SessionTranscript, so this runs as a separate pass
    over an already-parsed ParsedDocument rather than inside parse_device_response."""
    mso = doc.issuer_auth.mso if doc.issuer_auth else None
    if not doc.device_auth_type or mso is None or mso.device_key is None or doc.device_namespaces_raw is None:
        return None
    try:
        device_pub = crypto.cose_key_to_public_key(mso.device_key)
    except ValueError:
        return None

    device_authentication = [
        "DeviceAuthentication",
        cbor2.loads(session_transcript),
        doc.doc_type,
        # device_namespaces_raw is already-serialized bytes (DeviceNameSpacesBytes,
        # #6.24(bstr .cbor DeviceNameSpaces)) - decode it back to a CBORTag first so
        # it's embedded as a nested CBOR item here, matching session_transcript's own
        # treatment above. Embedding the raw bytes directly would encode it as an
        # EXTRA CBOR byte string wrapping those bytes, producing different bytes than
        # what the mdoc actually signed (which embeds the tag24 item directly, per
        # ISO 18013-5 - the same class of bug this tool's own commit history already
        # fixed once for the outer DeviceAuthentication/SessionTranscript wrapping).
        cbor2.loads(doc.device_namespaces_raw),
    ]
    detached_payload = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(device_authentication)))

    try:
        if doc.device_auth_type == "deviceSignature":
            return verify.verify_cose_sign1(
                doc.device_auth_cbor["deviceSignature"], device_pub, detached_payload=detached_payload
            )
        if doc.device_auth_type == "deviceMac":
            if not isinstance(device_pub, ec.EllipticCurvePublicKey):
                return None
            zab = e_reader_priv.exchange(ec.ECDH(), device_pub)
            emac_key = crypto.derive_emac_key(zab, session_transcript)
            return verify.verify_cose_mac0(
                doc.device_auth_cbor["deviceMac"], emac_key, detached_payload=detached_payload
            )
    except verify.UnsupportedAlgorithm:
        return None
    return None


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
