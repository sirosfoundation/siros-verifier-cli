"""End-to-end test of `siros-verify read` against a fake wallet peer.

Exercises the full pipeline (engagement parsing, ECDH, HKDF, AES-GCM framing,
DeviceRequest/DeviceResponse, IssuerAuth/MSO decode, text and JSON rendering)
without a Bluetooth adapter by monkeypatching `ble.exchange` with a fake
peer that performs the real device-side crypto and returns real SessionData.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import uuid

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from siros_verifier import ble, cli, crypto


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


def make_signed_document(given_name: str = "Alice") -> dict:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test DS")])
    now = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    item = cbor2.CBORTag(
        24,
        cbor2.dumps(
            {"digestID": 1, "random": b"\x00" * 16, "elementIdentifier": "given_name", "elementValue": given_name}
        ),
    )
    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "valueDigests": {"org.iso.18013.5.1": {1: b"\x01" * 32}},
        "deviceKeyInfo": {"deviceKey": {1: 2, -1: 1, -2: b"\x02" * 32, -3: b"\x03" * 32}},
        "docType": "org.iso.18013.5.1.mDL",
        "validityInfo": {"signed": now, "validFrom": now, "validUntil": now + datetime.timedelta(days=1)},
    }
    issuer_auth = [
        cbor2.dumps({1: -7}),
        {33: cert_der},
        cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso))),
        b"\x00" * 64,
    ]
    return {
        "docType": "org.iso.18013.5.1.mDL",
        "issuerSigned": {"nameSpaces": {"org.iso.18013.5.1": [item]}, "issuerAuth": issuer_auth},
        "deviceSigned": {
            "nameSpaces": cbor2.CBORTag(24, cbor2.dumps({})),
            "deviceAuth": {"deviceSignature": [b"", {}, None, b"\x00" * 64]},
        },
    }


def make_fake_exchange(device_priv, de_bytes):
    async def fake_exchange(peripheral_uuid, session_establishment_bytes, scan_timeout, response_timeout, log=lambda _: None):
        se = cbor2.loads(session_establishment_bytes)
        e_reader_key_tag = se["eReaderKey"]
        reader_pub = crypto.cose_key_to_public_key(cbor2.loads(e_reader_key_tag.value))
        zab = device_priv.exchange(ec.ECDH(), reader_pub)
        transcript = crypto.build_session_transcript(de_bytes, e_reader_key_tag, None)
        sk_reader, sk_device = crypto.derive_session_keys(zab, transcript)

        # sanity-check the reader's request decrypts correctly with the device's own derivation
        cbor2.loads(AESGCM(sk_reader).decrypt(crypto.gcm_iv(crypto.READER_IDENTIFIER, 1), se["data"], b""))

        device_response = cbor2.dumps({"version": "1.0", "documents": [make_signed_document()], "status": 0})
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
    assert "given_name = 'Alice'" in out
    assert "issuerAuth: alg=ES256 [UNVERIFIED SIGNATURE]" in out
    assert "deviceAuth: deviceSignature [UNVERIFIED]" in out


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
    assert doc["issuer_auth"]["certificates"][0]["subject"] == "CN=Test DS"
