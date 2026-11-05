import datetime

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from helpers import cose_key_from_public_key, make_self_signed_cert_der, sign_es256_raw, tagged24

from siros_verifier.mdoc import (
    DocRequest,
    MdocStructureError,
    ParsedElement,
    build_device_request,
    build_session_establishment,
    parse_device_response,
    validate_device_response,
)

GIVEN_NAME_ITEM = {"digestID": 1, "random": b"\x01" * 16, "elementIdentifier": "given_name", "elementValue": "Alice"}


def build_device_response_bytes(
    *,
    with_device_signature: bool = True,
    tamper_signature: bool = False,
    tamper_digest: bool = False,
    status: object = 0,
    issuer_items: list | None = None,
    bignum_value_digest_keys: bool = False,
) -> bytes:
    now = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)

    issuer_signed_items = issuer_items if issuer_items is not None else [tagged24(GIVEN_NAME_ITEM)]
    value_digests = {}
    for item in issuer_signed_items:
        item_value = cbor2.loads(item.value) if isinstance(item, cbor2.CBORTag) else item
        if not isinstance(item_value, dict):
            continue
        digest_id = item_value.get("digestID")
        if type(digest_id) is not int and not isinstance(digest_id, cbor2.CBORTag):
            continue
        tagged_item = item if isinstance(item, cbor2.CBORTag) else tagged24(item_value)
        correct_digest = hashes.Hash(hashes.SHA256())
        correct_digest.update(cbor2.dumps(tagged_item))
        digest_key = cbor2.CBORTag(2, b"\x01") if bignum_value_digest_keys else digest_id
        value_digests[digest_key] = correct_digest.finalize() if not tamper_digest else b"\x00" * 32

    device_key_priv = ec.generate_private_key(ec.SECP256R1())

    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "valueDigests": {"org.iso.18013.5.1": value_digests},
        "deviceKeyInfo": {"deviceKey": cose_key_from_public_key(device_key_priv.public_key())},
        "docType": "org.iso.18013.5.1.mDL",
        "validityInfo": {"signed": now, "validFrom": now, "validUntil": now + datetime.timedelta(days=30)},
    }
    mso_payload = cbor2.dumps(tagged24(mso))

    ds_priv = ec.generate_private_key(ec.SECP256R1())
    cert_der = make_self_signed_cert_der(ds_priv)
    protected = cbor2.dumps({1: -7})  # ES256
    sig_structure = cbor2.dumps(["Signature1", protected, b"", mso_payload])
    signature = sign_es256_raw(ds_priv, sig_structure) if not tamper_signature else b"\x00" * 64
    issuer_auth = [protected, {33: cert_der}, mso_payload, signature]

    # DeviceAuth verification needs session context (see test_cli_read.py); here just
    # exercise the decode path with a syntactically-present but unverified deviceAuth.
    device_auth = {"deviceSignature": [b"", {}, None, b"\x00" * 64]} if with_device_signature else {}

    document = {
        "docType": "org.iso.18013.5.1.mDL",
        "issuerSigned": {
            "nameSpaces": {"org.iso.18013.5.1": issuer_signed_items},
            "issuerAuth": issuer_auth,
        },
        "deviceSigned": {"nameSpaces": tagged24({}), "deviceAuth": device_auth},
    }

    device_response = {"version": "1.0", "documents": [document], "status": status}
    return cbor2.dumps(device_response)


def test_build_device_request_shape():
    raw = build_device_request([DocRequest(doc_type="org.iso.18013.5.1.mDL", namespaces={"org.iso.18013.5.1": ["given_name"]})])
    decoded = cbor2.loads(raw)
    assert decoded["version"] == "1.0"
    items_request_bytes = decoded["docRequests"][0]["itemsRequest"]
    assert items_request_bytes.tag == 24
    items_request = cbor2.loads(items_request_bytes.value)
    assert items_request["docType"] == "org.iso.18013.5.1.mDL"
    assert items_request["nameSpaces"]["org.iso.18013.5.1"]["given_name"] is False


def test_build_session_establishment_shape():
    e_reader_key_tag = cbor2.CBORTag(24, b"fake-cose-key")
    raw = build_session_establishment(e_reader_key_tag, b"ciphertext")
    decoded = cbor2.loads(raw)
    assert decoded["eReaderKey"].value == b"fake-cose-key"
    assert decoded["data"] == b"ciphertext"


def test_parse_device_response_full_document():
    result = parse_device_response(build_device_response_bytes())
    assert result.status == 0
    assert result.status_name == "OK"
    assert len(result.documents) == 1

    doc = result.documents[0]
    assert doc.doc_type == "org.iso.18013.5.1.mDL"
    assert doc.namespaces["org.iso.18013.5.1"][0].identifier == "given_name"
    assert doc.namespaces["org.iso.18013.5.1"][0].value == "Alice"
    assert doc.namespaces["org.iso.18013.5.1"][0].digest_valid is True
    assert doc.device_auth_type == "deviceSignature"
    assert doc.device_namespaces == {}

    assert doc.issuer_auth is not None
    assert doc.issuer_auth.alg_name == "ES256"
    assert doc.issuer_auth.signature_valid is True
    assert len(doc.issuer_auth.certificates) == 1
    assert doc.issuer_auth.certificates[0].subject == "CN=Test Document Signer"

    assert doc.issuer_auth.mso is not None
    assert doc.issuer_auth.mso.digest_algorithm == "SHA-256"
    assert doc.issuer_auth.mso.doc_type == "org.iso.18013.5.1.mDL"
    assert doc.issuer_auth.mso.validity_info["signed"] == datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)


def test_parse_device_response_detects_invalid_signature():
    result = parse_device_response(build_device_response_bytes(tamper_signature=True))
    assert result.documents[0].issuer_auth.signature_valid is False


def test_parse_device_response_detects_digest_mismatch():
    result = parse_device_response(build_device_response_bytes(tamper_digest=True))
    assert result.documents[0].namespaces["org.iso.18013.5.1"][0].digest_valid is False
    # tampering the digest doesn't touch the MSO signature itself
    assert result.documents[0].issuer_auth.signature_valid is True


def test_parse_device_response_without_device_auth():
    result = parse_device_response(build_device_response_bytes(with_device_signature=False))
    assert result.documents[0].device_auth_type is None


def test_parse_device_response_status_error_has_no_documents():
    device_response = {"version": "1.0", "status": 10}
    result = parse_device_response(cbor2.dumps(device_response))
    assert result.status == 10
    assert result.status_name == "General error"
    assert result.documents == []


VALIDATION_NOW = datetime.datetime(2024, 1, 15, tzinfo=datetime.timezone.utc)
MDOC_REQUEST = DocRequest(doc_type="org.iso.18013.5.1.mDL", namespaces={"org.iso.18013.5.1": ["given_name"]})


def validatable_response(**kwargs):
    result = parse_device_response(build_device_response_bytes(**kwargs))
    result.documents[0].device_auth_valid = True
    return result


def validation_errors(result, requests=None):
    return validate_device_response(result, requests or [MDOC_REQUEST], now=VALIDATION_NOW)


def test_validate_device_response_accepts_valid_requested_claims():
    assert validation_errors(validatable_response()) == []


def test_validate_device_response_allows_additional_valid_claims():
    result = validatable_response()
    result.documents[0].namespaces["org.iso.18013.5.1"].append(
        ParsedElement(identifier="extra_claim", value="allowed", digest_id=2, digest_valid=True)
    )
    assert validation_errors(result) == []


@pytest.mark.parametrize("failure", ["issuer", "digest", "device"])
def test_validate_device_response_rejects_cryptographic_failures(failure):
    result = validatable_response()
    if failure == "issuer":
        result.documents[0].issuer_auth.signature_valid = False
    elif failure == "digest":
        result.documents[0].namespaces["org.iso.18013.5.1"][0].digest_valid = None
    else:
        result.documents[0].device_auth_valid = None
    assert validation_errors(result)


def test_validate_device_response_requires_every_requested_element():
    request = DocRequest(doc_type="org.iso.18013.5.1.mDL", namespaces={"org.iso.18013.5.1": ["family_name"]})
    errors = validation_errors(validatable_response(), [request])
    assert any("requested_element_missing" in error for error in errors)


def test_validate_device_response_rejects_unrequested_document_type():
    request = DocRequest(doc_type="example.other", namespaces={"example": ["claim"]})
    errors = validation_errors(validatable_response(), [request])
    assert any("requested_doc_type_missing" in error for error in errors)
    assert any("doc_type_not_requested" in error for error in errors)


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("validFrom", datetime.datetime(2024, 1, 20, tzinfo=datetime.timezone.utc), "not_yet_valid"),
        ("validUntil", datetime.datetime(2024, 1, 14, tzinfo=datetime.timezone.utc), "expired"),
        ("signed", datetime.datetime(2024, 1, 20, tzinfo=datetime.timezone.utc), "signed_in_future"),
        ("signed", None, "validity_info"),
    ],
)
def test_validate_device_response_enforces_mso_validity(field, value, code):
    result = validatable_response()
    result.documents[0].issuer_auth.mso.validity_info[field] = value
    assert any(code in error for error in validation_errors(result))


def test_validate_device_response_rejects_non_map_validity_info():
    result = validatable_response()
    result.documents[0].issuer_auth.mso.validity_info = []
    assert any("validity_info" in error for error in validation_errors(result))


def test_validate_device_response_enforces_mso_document_type():
    result = validatable_response()
    result.documents[0].issuer_auth.mso.doc_type = "example.other"
    assert any("doc_type_mismatch" in error for error in validation_errors(result))


def test_validate_device_response_enforces_envelope():
    result = validatable_response()
    result.version = "2.0"
    result.status = 10
    errors = validation_errors(result)
    assert "unsupported_version" in errors
    assert "response_status_not_ok" in errors


@pytest.mark.parametrize("status", [False, 0.0, 10, [], {}])
def test_validate_device_response_requires_integer_zero_status(status):
    result = validatable_response(status=status)
    assert "response_status_not_ok" in validation_errors(result)


@pytest.mark.parametrize("errors", [[], {"ns": []}, {"ns": {"claim": True}}])
def test_validate_device_response_rejects_malformed_element_errors(errors):
    result = validatable_response()
    result.documents[0].errors = errors
    assert any("invalid_errors" in error for error in validation_errors(result))


@pytest.mark.parametrize("errors", [{}, [{"doc": False}], [{"doc": []}], [{"doc": 1 << 20000}]])
def test_validate_device_response_rejects_malformed_document_errors(errors):
    result = validatable_response()
    result.document_errors = errors
    assert "invalid_document_errors" in validation_errors(result)


def test_validate_device_response_requires_status_member():
    decoded = cbor2.loads(build_device_response_bytes())
    del decoded["status"]
    result = parse_device_response(cbor2.dumps(decoded))
    result.documents[0].device_auth_valid = True
    assert "response_status_not_ok" in validation_errors(result)


def test_parse_rejects_duplicate_digest_id_with_valid_digests():
    with pytest.raises(MdocStructureError, match="duplicate_digest_id"):
        parse_device_response(build_device_response_bytes(issuer_items=[tagged24(GIVEN_NAME_ITEM), tagged24(GIVEN_NAME_ITEM)]))


def test_parse_rejects_duplicate_element_identifier_with_valid_digests():
    other = dict(GIVEN_NAME_ITEM, digestID=2, elementValue="Mallory")
    with pytest.raises(MdocStructureError, match="duplicate_element"):
        parse_device_response(build_device_response_bytes(issuer_items=[tagged24(GIVEN_NAME_ITEM), tagged24(other)]))


@pytest.mark.parametrize(
    "items",
    [
        [GIVEN_NAME_ITEM],
        [tagged24(dict(GIVEN_NAME_ITEM, random=b""))],
        [tagged24(dict(GIVEN_NAME_ITEM, digestID=True))],
        [tagged24(dict(GIVEN_NAME_ITEM, digestID=[]))],
        [tagged24(dict(GIVEN_NAME_ITEM, digestID=cbor2.CBORTag(2, b"\x01")))],
        [tagged24(dict(GIVEN_NAME_ITEM, elementIdentifier=1))],
        [tagged24({"digestID": 1, "random": b"\x01" * 16, "elementIdentifier": "given_name"})],
        [cbor2.CBORTag(24, cbor2.dumps(GIVEN_NAME_ITEM) + b"\x00")],
    ],
    ids=["bare-map", "empty-random", "bool-digest-id", "list-digest-id", "bignum-digest-id", "integer-identifier", "missing-value", "trailing-tag-data"],
)
def test_parse_rejects_malformed_issuer_items(items):
    with pytest.raises(MdocStructureError):
        parse_device_response(build_device_response_bytes(issuer_items=items))


def test_parse_rejects_bignum_value_digest_key():
    with pytest.raises(MdocStructureError):
        parse_device_response(build_device_response_bytes(bignum_value_digest_keys=True))


@pytest.mark.parametrize(
    "name_spaces",
    [
        {1: []},
        {"org.iso.18013.5.1": {}},
        {"org.iso.18013.5.1": [], "other": []},
    ],
    ids=["integer-namespace", "map-instead-of-array", "namespace-absent-from-value-digests"],
)
def test_parse_rejects_malformed_namespaces(name_spaces):
    decoded = cbor2.loads(build_device_response_bytes())
    decoded["documents"][0]["issuerSigned"]["nameSpaces"] = name_spaces
    with pytest.raises(MdocStructureError):
        parse_device_response(cbor2.dumps(decoded))
