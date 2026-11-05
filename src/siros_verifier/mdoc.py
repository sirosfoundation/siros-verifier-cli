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

import io
from dataclasses import dataclass, field
from datetime import datetime, timezone

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


class MdocStructureError(ValueError):
    """The DeviceResponse violates a required CBOR or mdoc container shape."""


@dataclass
class DocRequest:
    doc_type: str
    namespaces: dict[str, list[str]]


def build_device_request(doc_requests: list[DocRequest]) -> bytes:
    requests = []
    for dr in doc_requests:
        name_spaces = {ns: {claim: False for claim in claims} for ns, claims in dr.namespaces.items()}
        items_request = {"docType": dr.doc_type, "nameSpaces": name_spaces}
        requests.append({"itemsRequest": cbor2.CBORTag(24, cbor2.dumps(items_request))})
    return cbor2.dumps({"version": "1.0", "docRequests": requests})


def build_session_establishment(e_reader_key_tag: cbor2.CBORTag, encrypted_device_request: bytes) -> bytes:
    return cbor2.dumps({"eReaderKey": e_reader_key_tag, "data": encrypted_device_request})


def _preserve_bignum_tag(tag: int):
    def decode(value: bytes, _immutable: bool) -> cbor2.CBORTag:
        integer = int.from_bytes(value, "big")
        return cbor2.CBORTag(tag, integer if tag == 2 else -1 - integer)

    return decode


_BIGNUM_DECODERS = {2: _preserve_bignum_tag(2), 3: _preserve_bignum_tag(3)}


def _unwrap_tagged24(value):
    """Decode exactly one CBOR item from a required tag-24 byte string."""
    if not isinstance(value, cbor2.CBORTag) or value.tag != 24 or not isinstance(value.value, bytes):
        raise MdocStructureError("expected tag-24 encoded bytes")
    stream = io.BytesIO(value.value)
    decoded = cbor2.CBORDecoder(stream, semantic_decoders=_BIGNUM_DECODERS).decode()
    if stream.tell() != len(value.value):
        raise MdocStructureError("trailing data in tag-24 encoded bytes")
    return decoded


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
        if not isinstance(mso, dict):
            raise MdocStructureError("MSO must be a map")
        value_digests = mso.get("valueDigests", {})
        if not isinstance(value_digests, dict):
            raise MdocStructureError("MSO valueDigests must be a map")
        device_key_info = mso.get("deviceKeyInfo") or {}
        if not isinstance(device_key_info, dict):
            raise MdocStructureError("MSO deviceKeyInfo must be a map")
        return cls(
            version=mso.get("version"),
            digest_algorithm=mso.get("digestAlgorithm"),
            doc_type=mso.get("docType"),
            value_digests=value_digests,
            device_key=device_key_info.get("deviceKey"),
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
        if not isinstance(cose_sign1, list) or len(cose_sign1) != 4:
            raise MdocStructureError("IssuerAuth must be a four-element COSE_Sign1 array")
        protected_bytes, unprotected, payload, signature = cose_sign1
        if not isinstance(protected_bytes, bytes) or not isinstance(unprotected, dict):
            raise MdocStructureError("invalid IssuerAuth COSE headers")
        if not isinstance(payload, bytes) or not isinstance(signature, bytes):
            raise MdocStructureError("invalid IssuerAuth COSE payload or signature")
        protected = cbor2.loads(protected_bytes) if protected_bytes else {}
        alg = protected.get(1, unprotected.get(1))
        if alg is not None and type(alg) is not int:
            raise MdocStructureError("COSE algorithm must be an integer")
        alg_name = COSE_ALG_NAMES.get(alg, f"unknown({alg})") if alg is not None else "none"

        x5chain = unprotected.get(33)
        der_certs: list[bytes]
        if x5chain is None:
            der_certs = []
        elif isinstance(x5chain, bytes):
            der_certs = [x5chain]
        else:
            der_certs = list(x5chain)
        if any(not isinstance(der, bytes) for der in der_certs):
            raise MdocStructureError("IssuerAuth x5chain entries must be bytes")
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
    status: int | None
    status_name: str
    documents: list[ParsedDocument]
    document_errors: list[dict]


def _parse_issuer_signed_namespaces(
    name_spaces_cbor: dict, mso: MobileSecurityObject | None
) -> dict[str, list[ParsedElement]]:
    if not isinstance(name_spaces_cbor, dict):
        raise MdocStructureError("issuerSigned nameSpaces must be a map")
    if mso is None:
        raise MdocStructureError("issuerSigned content requires an MSO")

    namespaces: dict[str, list[ParsedElement]] = {}
    for ns, tagged_items in name_spaces_cbor.items():
        if not isinstance(ns, str):
            raise MdocStructureError("issuer namespace must be text")
        if not isinstance(tagged_items, list):
            raise MdocStructureError(f"issuer namespace {ns!r} must contain an array")
        digests = mso.value_digests.get(ns)
        if not isinstance(digests, dict):
            raise MdocStructureError(f"issuer namespace {ns!r} is absent from valueDigests")
        for digest_id, expected_digest in digests.items():
            if type(digest_id) is not int or not isinstance(expected_digest, bytes):
                raise MdocStructureError(f"invalid valueDigests entry for namespace {ns!r}")

        elements = []
        seen_digest_ids: set[int] = set()
        seen_identifiers: set[str] = set()
        for tagged_item in tagged_items:
            item = _unwrap_tagged24(tagged_item)
            if not isinstance(item, dict):
                raise MdocStructureError("IssuerSignedItem must be a map")
            digest_id = item.get("digestID")
            if type(digest_id) is not int or not -(1 << 64) <= digest_id < (1 << 64):
                raise MdocStructureError("IssuerSignedItem digestID must be an ordinary integer")
            if digest_id in seen_digest_ids:
                raise MdocStructureError("duplicate_digest_id")
            seen_digest_ids.add(digest_id)

            random = item.get("random")
            if not isinstance(random, bytes) or len(random) < 16:
                raise MdocStructureError("IssuerSignedItem random must contain at least 16 bytes")
            identifier = item.get("elementIdentifier")
            if not isinstance(identifier, str):
                raise MdocStructureError("IssuerSignedItem elementIdentifier must be text")
            if identifier in seen_identifiers:
                raise MdocStructureError("duplicate_element")
            seen_identifiers.add(identifier)
            if "elementValue" not in item:
                raise MdocStructureError("IssuerSignedItem is missing elementValue")

            expected_digest = digests.get(digest_id)
            if expected_digest is None:
                raise MdocStructureError("digest_id_not_in_mso")
            digest_valid = None
            if mso.digest_algorithm is not None:
                try:
                    digest_valid = verify.verify_digest(mso.digest_algorithm, cbor2.dumps(tagged_item), expected_digest)
                except verify.UnsupportedAlgorithm:
                    digest_valid = None

            elements.append(
                ParsedElement(
                    identifier=identifier,
                    value=item["elementValue"],
                    digest_id=digest_id,
                    digest_valid=digest_valid,
                )
            )
        namespaces[ns] = elements
    return namespaces


def _parse_document(doc: dict) -> ParsedDocument:
    if not isinstance(doc, dict) or not isinstance(doc.get("docType"), str):
        raise MdocStructureError("document docType must be text")
    issuer_signed = doc.get("issuerSigned", {})
    if not isinstance(issuer_signed, dict):
        raise MdocStructureError("issuerSigned must be a map")
    issuer_auth_cbor = issuer_signed.get("issuerAuth")
    issuer_auth = IssuerAuthInfo.from_cose_sign1(issuer_auth_cbor) if issuer_auth_cbor else None
    namespaces = _parse_issuer_signed_namespaces(
        issuer_signed.get("nameSpaces", {}), issuer_auth.mso if issuer_auth else None
    )

    device_signed = doc.get("deviceSigned") or {}
    if not isinstance(device_signed, dict):
        raise MdocStructureError("deviceSigned must be a map")
    device_namespaces_tag = device_signed.get("nameSpaces")
    device_namespaces = _unwrap_tagged24(device_namespaces_tag)
    device_namespaces_raw = cbor2.dumps(device_namespaces_tag)
    device_auth = device_signed.get("deviceAuth") or {}
    if not isinstance(device_auth, dict):
        raise MdocStructureError("deviceAuth must be a map")
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
    if not isinstance(doc.device_auth_cbor, dict) or len(doc.device_auth_cbor) != 1:
        return None
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
            structure = doc.device_auth_cbor["deviceSignature"]
            if not isinstance(structure, list) or len(structure) != 4 or structure[2] is not None:
                return None
            return verify.verify_cose_sign1(structure, device_pub, detached_payload=detached_payload)
        if doc.device_auth_type == "deviceMac":
            if not isinstance(device_pub, ec.EllipticCurvePublicKey):
                return None
            structure = doc.device_auth_cbor["deviceMac"]
            if not isinstance(structure, list) or len(structure) != 4 or structure[2] is not None:
                return None
            zab = e_reader_priv.exchange(ec.ECDH(), device_pub)
            emac_key = crypto.derive_emac_key(zab, session_transcript)
            return verify.verify_cose_mac0(structure, emac_key, detached_payload=detached_payload)
    except verify.UnsupportedAlgorithm:
        return None
    return None


def parse_device_response(plaintext: bytes) -> DeviceResponseResult:
    device_response = cbor2.loads(plaintext)
    if not isinstance(device_response, dict):
        raise MdocStructureError("DeviceResponse must be a map")
    raw_documents = device_response.get("documents", [])
    if not isinstance(raw_documents, list):
        raise MdocStructureError("DeviceResponse documents must be an array")
    raw_status = device_response.get("status")
    status = raw_status if type(raw_status) is int else None
    status_name = STATUS_NAMES.get(status, f"unknown({status})") if status is not None else f"unknown({raw_status})"
    documents = [_parse_document(doc) for doc in raw_documents]
    return DeviceResponseResult(
        version=device_response.get("version"),
        status=status,
        status_name=status_name,
        documents=documents,
        document_errors=device_response.get("documentErrors", []),
    )


def _aware_datetime(value: object) -> datetime | None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        return None
    return value


def _valid_error_code(code: object) -> bool:
    return type(code) is int and -(1 << 64) <= code < (1 << 64)


def _valid_document_errors(errors: object) -> bool:
    return isinstance(errors, list) and all(
        isinstance(item, dict)
        and all(isinstance(doc_type, str) and _valid_error_code(code) for doc_type, code in item.items())
        for item in errors
    )


def _valid_element_errors(errors: object) -> bool:
    return isinstance(errors, dict) and all(
        isinstance(namespace, str)
        and isinstance(items, dict)
        and all(isinstance(identifier, str) and _valid_error_code(code) for identifier, code in items.items())
        for namespace, items in errors.items()
    )


def validate_device_response(
    response: DeviceResponseResult, doc_requests: list[DocRequest], *, now: datetime | None = None
) -> list[str]:
    """Return request/cryptographic validation failures; an empty list permits disclosure.

    Every requested document type, namespace, and element is required. Unrequested
    document types are rejected, while additional valid issuer-signed claims are
    allowed. Nonempty device-signed namespaces are rejected until their MSO
    keyAuthorizations can be enforced. No trust decision is made here.
    """
    errors: list[str] = []
    if response.version != "1.0":
        errors.append("unsupported_version")
    if type(response.status) is not int or response.status != 0:
        errors.append("response_status_not_ok")
    if not response.documents:
        errors.append("document_count")
    if not _valid_document_errors(response.document_errors):
        errors.append("invalid_document_errors")

    for requested in doc_requests:
        if not any(doc.doc_type == requested.doc_type for doc in response.documents):
            errors.append(f"requested_doc_type_missing: {requested.doc_type}")

    current_time = now or datetime.now(timezone.utc)
    if _aware_datetime(current_time) is None:
        raise ValueError("now must be timezone-aware")

    for index, doc in enumerate(response.documents):
        prefix = f"document {index} ({doc.doc_type})"
        matching_requests = [request for request in doc_requests if request.doc_type == doc.doc_type]
        if not matching_requests:
            errors.append(f"{prefix}: doc_type_not_requested")

        issuer_auth = doc.issuer_auth
        if issuer_auth is None:
            errors.append(f"{prefix}: issuer_auth_missing")
        elif issuer_auth.signature_valid is not True:
            errors.append(f"{prefix}: issuer_signature_not_valid")

        mso = issuer_auth.mso if issuer_auth else None
        if mso is None:
            errors.append(f"{prefix}: mso_missing")
        else:
            if mso.version != "1.0":
                errors.append(f"{prefix}: mso_version")
            if mso.doc_type != doc.doc_type:
                errors.append(f"{prefix}: doc_type_mismatch")

            if not isinstance(mso.validity_info, dict):
                errors.append(f"{prefix}: validity_info")
            else:
                validity = {
                    name: _aware_datetime(mso.validity_info.get(name)) for name in ("signed", "validFrom", "validUntil")
                }
                if any(value is None for value in validity.values()):
                    errors.append(f"{prefix}: validity_info")
                else:
                    signed = validity["signed"]
                    valid_from = validity["validFrom"]
                    valid_until = validity["validUntil"]
                    assert signed is not None and valid_from is not None and valid_until is not None
                    if current_time < signed:
                        errors.append(f"{prefix}: signed_in_future")
                    if current_time < valid_from:
                        errors.append(f"{prefix}: not_yet_valid")
                    if current_time >= valid_until:
                        errors.append(f"{prefix}: expired")

        for namespace, elements in doc.namespaces.items():
            for element in elements:
                if element.digest_valid is not True:
                    errors.append(f"{prefix}: element_digest_not_valid: {namespace}.{element.identifier}")

        if doc.device_auth_valid is not True:
            errors.append(f"{prefix}: device_auth_not_valid")
        if not isinstance(doc.device_namespaces, dict) or doc.device_namespaces:
            errors.append(f"{prefix}: device_namespaces_unsupported")
        if not _valid_element_errors(doc.errors):
            errors.append(f"{prefix}: invalid_errors")

        for requested in matching_requests:
            for namespace, requested_elements in requested.namespaces.items():
                disclosed_elements = doc.namespaces.get(namespace)
                if disclosed_elements is None:
                    errors.append(f"{prefix}: requested_namespace_missing: {namespace}")
                    continue
                disclosed = {element.identifier for element in disclosed_elements}
                for identifier in requested_elements:
                    if identifier not in disclosed:
                        errors.append(f"{prefix}: requested_element_missing: {namespace}.{identifier}")

    return errors
