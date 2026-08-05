"""End-to-end test of `siros-verify read` against a fake wallet peer.

Exercises the full pipeline (engagement parsing, ECDH, HKDF, AES-GCM framing,
DeviceRequest/DeviceResponse, IssuerAuth/MSO/digest/DeviceAuth verification,
text and JSON rendering) without a Bluetooth adapter by monkeypatching
`ble.exchange` with a fake peer that performs the real device-side crypto
(including genuinely valid signatures) and returns real SessionData.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import uuid

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from helpers import cose_key_from_public_key, make_self_signed_cert_der, sign_es256_raw, tagged24

from siros_verifier import ble, cli, crypto

DOC_TYPE = "org.iso.18013.5.1.mDL"


@pytest.fixture
def wallet_engagement():
    device_priv = ec.generate_private_key(ec.SECP256R1())
    e_device_key_tag = crypto.cose_key_tag(device_priv.public_key())
    peripheral_uuid = uuid.uuid4()
    de = {
        0: "1.0",
        1: [1, e_device_key_tag],
        2: [[2, 1, {0: True, 1: False, 10: peripheral_uuid.bytes}]],
    }
    de_bytes = cbor2.dumps(de)
    mdoc_uri = "mdoc:" + base64.urlsafe_b64encode(de_bytes).rstrip(b"=").decode()
    return device_priv, de_bytes, mdoc_uri


def make_signed_document(session_transcript_bytes: bytes, *, given_name: str = "Alice", tamper_device_signature: bool = False) -> dict:
    now = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)

    issuer_signed_item = tagged24(
        {"digestID": 1, "random": b"\x00" * 16, "elementIdentifier": "given_name", "elementValue": given_name}
    )
    item_digest = hashes.Hash(hashes.SHA256())
    item_digest.update(cbor2.dumps(issuer_signed_item))

    device_key_priv = ec.generate_private_key(ec.SECP256R1())  # SDeviceKey, distinct from EDeviceKey
    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "valueDigests": {"org.iso.18013.5.1": {1: item_digest.finalize()}},
        "deviceKeyInfo": {"deviceKey": cose_key_from_public_key(device_key_priv.public_key())},
        "docType": DOC_TYPE,
        "validityInfo": {"signed": now, "validFrom": now, "validUntil": now + datetime.timedelta(days=1)},
    }
    mso_payload = cbor2.dumps(tagged24(mso))

    ds_priv = ec.generate_private_key(ec.SECP256R1())
    cert_der = make_self_signed_cert_der(ds_priv)
    protected = cbor2.dumps({1: -7})  # ES256
    issuer_sig_structure = cbor2.dumps(["Signature1", protected, b"", mso_payload])
    issuer_auth = [protected, {33: cert_der}, mso_payload, sign_es256_raw(ds_priv, issuer_sig_structure)]

    device_namespaces_tag = tagged24({})
    device_authentication = [
        "DeviceAuthentication",
        cbor2.loads(session_transcript_bytes),
        DOC_TYPE,
        cbor2.dumps(device_namespaces_tag),
    ]
    detached_payload = cbor2.dumps(tagged24(device_authentication))
    device_protected = cbor2.dumps({1: -7})
    device_sig_structure = cbor2.dumps(["Signature1", device_protected, b"", detached_payload])
    device_signature = sign_es256_raw(device_key_priv, device_sig_structure)
    if tamper_device_signature:
        device_signature = b"\x00" * 64
    device_auth = {"deviceSignature": [device_protected, {}, None, device_signature]}

    return {
        "docType": DOC_TYPE,
        "issuerSigned": {"nameSpaces": {"org.iso.18013.5.1": [issuer_signed_item]}, "issuerAuth": issuer_auth},
        "deviceSigned": {"nameSpaces": device_namespaces_tag, "deviceAuth": device_auth},
    }


def make_fake_exchange(device_priv, de_bytes, **document_kwargs):
    async def fake_exchange(peripheral_uuid, session_establishment_bytes, scan_timeout, response_timeout, log=lambda _: None):
        se = cbor2.loads(session_establishment_bytes)
        e_reader_key_tag = se["eReaderKey"]
        reader_pub = crypto.cose_key_to_public_key(cbor2.loads(e_reader_key_tag.value))
        zab = device_priv.exchange(ec.ECDH(), reader_pub)
        transcript = crypto.build_session_transcript(de_bytes, e_reader_key_tag, None)
        sk_reader, sk_device = crypto.derive_session_keys(zab, transcript)

        # sanity-check the reader's request decrypts correctly with the device's own derivation
        cbor2.loads(AESGCM(sk_reader).decrypt(crypto.gcm_iv(crypto.READER_IDENTIFIER, 1), se["data"], b""))

        document = make_signed_document(transcript, **document_kwargs)
        device_response = cbor2.dumps({"version": "1.0", "documents": [document], "status": 0})
        ciphertext = AESGCM(sk_device).encrypt(crypto.gcm_iv(crypto.MDOC_IDENTIFIER, 1), device_response, b"")
        session_data_bytes = cbor2.dumps({"data": ciphertext})
        return ble.ExchangeResult(
            session_data_bytes=session_data_bytes,
            negotiated_mtu=185,
            chunk_size=182,
            device_address="AA:BB:CC:DD:EE:FF",
        )

    return fake_exchange


def test_read_end_to_end_text(wallet_engagement, monkeypatch, capsys):
    device_priv, de_bytes, mdoc_uri = wallet_engagement
    monkeypatch.setattr(ble, "exchange", make_fake_exchange(device_priv, de_bytes))

    args = cli.build_parser().parse_args(["read", mdoc_uri])
    rc = asyncio.run(cli.run_read(args))

    assert rc == 0
    out = capsys.readouterr().out
    assert "given_name = 'Alice' [digest OK]" in out
    assert "issuerAuth: alg=ES256 signature=VALID" in out
    assert "deviceAuth: deviceSignature VALID" in out


def test_read_end_to_end_json(wallet_engagement, monkeypatch, capsys):
    device_priv, de_bytes, mdoc_uri = wallet_engagement
    monkeypatch.setattr(ble, "exchange", make_fake_exchange(device_priv, de_bytes))

    args = cli.build_parser().parse_args(["read", mdoc_uri, "--json"])
    rc = asyncio.run(cli.run_read(args))

    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out[out.index("{") :])
    assert payload["status"] == 0
    doc = payload["documents"][0]
    assert doc["namespaces"]["org.iso.18013.5.1"][0]["value"] == "Alice"
    assert doc["namespaces"]["org.iso.18013.5.1"][0]["digest_valid"] is True
    assert doc["issuer_auth"]["signature_valid"] is True
    assert doc["issuer_auth"]["certificates"][0]["subject"] == "CN=Test Document Signer"
    assert doc["device_auth_valid"] is True


def test_read_end_to_end_detects_tampered_device_signature(wallet_engagement, monkeypatch, capsys):
    device_priv, de_bytes, mdoc_uri = wallet_engagement
    monkeypatch.setattr(ble, "exchange", make_fake_exchange(device_priv, de_bytes, tamper_device_signature=True))

    args = cli.build_parser().parse_args(["read", mdoc_uri])
    rc = asyncio.run(cli.run_read(args))

    assert rc == 0  # DeviceResponse status is still OK - verification failure is reported, not fatal
    out = capsys.readouterr().out
    assert "deviceAuth: deviceSignature INVALID" in out
