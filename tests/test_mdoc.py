import datetime

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from helpers import cose_key_from_public_key, make_self_signed_cert_der, sign_es256_raw, tagged24

from siros_verifier.mdoc import (
    DocRequest,
    build_device_request,
    build_session_establishment,
    parse_device_response,
)

GIVEN_NAME_ITEM = {"digestID": 1, "random": b"\x01" * 16, "elementIdentifier": "given_name", "elementValue": "Alice"}


def build_device_response_bytes(
    *, with_device_signature: bool = True, tamper_signature: bool = False, tamper_digest: bool = False
) -> bytes:
    now = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)

    issuer_signed_item = tagged24(GIVEN_NAME_ITEM)
    correct_digest = hashes.Hash(hashes.SHA256())
    correct_digest.update(cbor2.dumps(issuer_signed_item))
    digest = correct_digest.finalize() if not tamper_digest else b"\x00" * 32

    device_key_priv = ec.generate_private_key(ec.SECP256R1())

    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "valueDigests": {"org.iso.18013.5.1": {1: digest}},
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
            "nameSpaces": {"org.iso.18013.5.1": [issuer_signed_item]},
            "issuerAuth": issuer_auth,
        },
        "deviceSigned": {"nameSpaces": tagged24({}), "deviceAuth": device_auth},
    }

    device_response = {"version": "1.0", "documents": [document], "status": 0}
    return cbor2.dumps(device_response)


def test_build_device_request_shape():
    raw = build_device_request([DocRequest(doc_type="org.iso.18013.5.1.mDL", namespaces={"org.iso.18013.5.1": ["given_name"]})])
    decoded = cbor2.loads(raw)
    assert decoded["version"] == "1.0"
    items_request_bytes = decoded["docRequests"][0]["itemsRequest"]
    assert items_request_bytes.tag == 24
    items_request = cbor2.loads(items_request_bytes.value)
    assert items_request["docType"] == "org.iso.18013.5.1.mDL"
    assert items_request["nameSpaces"]["org.iso.18013.5.1"]["given_name"] is True


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
