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
from cryptography.hazmat.primitives import hmac as hmac_primitive
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


def make_signed_document(
    session_transcript_bytes: bytes,
    *,
    given_name: str = "Alice",
    tamper_device_signature: bool = False,
    replay_inline_device_signature: bool = False,
    replay_inline_device_auth: bool = False,
    device_auth_method: str = "signature",
    e_reader_pub: ec.EllipticCurvePublicKey | None = None,
    device_namespaces: object = None,
    device_namespaces_tagged: bool = True,
    additional_device_auth: dict | None = None,
    errors: object = None,
) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc)

    issuer_signed_items = [
        tagged24(
            {"digestID": 1, "random": b"\x00" * 16, "elementIdentifier": "given_name", "elementValue": given_name}
        ),
        tagged24(
            {"digestID": 2, "random": b"\x01" * 16, "elementIdentifier": "family_name", "elementValue": "Smith"}
        ),
    ]
    value_digests = {}
    for item in issuer_signed_items:
        item_digest = hashes.Hash(hashes.SHA256())
        item_digest.update(cbor2.dumps(item))
        value_digests[cbor2.loads(item.value)["digestID"]] = item_digest.finalize()

    device_key_priv = ec.generate_private_key(ec.SECP256R1())  # SDeviceKey, distinct from EDeviceKey
    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "valueDigests": {"org.iso.18013.5.1": value_digests},
        "deviceKeyInfo": {"deviceKey": cose_key_from_public_key(device_key_priv.public_key())},
        "docType": DOC_TYPE,
        "validityInfo": {
            "signed": now,
            "validFrom": now - datetime.timedelta(minutes=1),
            "validUntil": now + datetime.timedelta(days=1),
        },
    }
    mso_payload = cbor2.dumps(tagged24(mso))

    ds_priv = ec.generate_private_key(ec.SECP256R1())
    cert_der = make_self_signed_cert_der(ds_priv)
    protected = cbor2.dumps({1: -7})  # ES256
    issuer_sig_structure = cbor2.dumps(["Signature1", protected, b"", mso_payload])
    issuer_auth = [protected, {33: cert_der}, mso_payload, sign_es256_raw(ds_priv, issuer_sig_structure)]

    raw_device_namespaces = device_namespaces if device_namespaces is not None else {}
    device_namespaces_tag = tagged24(raw_device_namespaces) if device_namespaces_tagged else raw_device_namespaces
    replay_inline = replay_inline_device_signature or replay_inline_device_auth
    signing_transcript_bytes = session_transcript_bytes
    signing_reader_pub = e_reader_pub
    if replay_inline:
        current_transcript = cbor2.loads(session_transcript_bytes)
        historical_reader_priv = ec.generate_private_key(ec.SECP256R1())
        signing_reader_pub = historical_reader_priv.public_key()
        historical_reader_key = crypto.cose_key_tag(signing_reader_pub)
        signing_transcript_bytes = crypto.build_session_transcript(
            current_transcript[0].value, historical_reader_key, current_transcript[2]
        )
    device_authentication = [
        "DeviceAuthentication",
        cbor2.loads(signing_transcript_bytes),
        DOC_TYPE,
        # Embed the tag object itself (a nested CBOR item), not its serialized
        # bytes - the latter would double-bstr-wrap DeviceNameSpacesBytes,
        # producing different signed bytes than a real mdoc's DeviceAuthentication
        # (see mdoc.verify_device_auth's matching fix/comment).
        device_namespaces_tag,
    ]
    detached_payload = cbor2.dumps(tagged24(device_authentication))
    cose_payload = detached_payload if replay_inline else None
    if device_auth_method == "mac":
        assert e_reader_pub is not None
        zab = device_key_priv.exchange(ec.ECDH(), signing_reader_pub)
        emac_key = crypto.derive_emac_key(zab, signing_transcript_bytes)
        device_protected = cbor2.dumps({1: 5})
        mac_structure = cbor2.dumps(["MAC0", device_protected, b"", detached_payload])
        mac = hmac_primitive.HMAC(emac_key, hashes.SHA256())
        mac.update(mac_structure)
        tag = mac.finalize()
        device_auth = {"deviceMac": [device_protected, {}, cose_payload, tag]}
    else:
        device_protected = cbor2.dumps({1: -7})
        device_sig_structure = cbor2.dumps(["Signature1", device_protected, b"", detached_payload])
        device_signature = sign_es256_raw(device_key_priv, device_sig_structure)
        if tamper_device_signature:
            device_signature = b"\x00" * 64
        device_auth = {"deviceSignature": [device_protected, {}, cose_payload, device_signature]}
    device_auth.update(additional_device_auth or {})

    return {
        "docType": DOC_TYPE,
        "issuerSigned": {"nameSpaces": {"org.iso.18013.5.1": issuer_signed_items}, "issuerAuth": issuer_auth},
        "deviceSigned": {"nameSpaces": device_namespaces_tag, "deviceAuth": device_auth},
        "errors": errors if errors is not None else {},
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

        document = make_signed_document(transcript, e_reader_pub=reader_pub, **document_kwargs)
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


def test_read_accepts_detached_device_mac(wallet_engagement, monkeypatch, capsys):
    device_priv, de_bytes, mdoc_uri = wallet_engagement
    monkeypatch.setattr(ble, "exchange", make_fake_exchange(device_priv, de_bytes, device_auth_method="mac"))

    args = cli.build_parser().parse_args(["read", mdoc_uri, "--json"])
    rc = asyncio.run(cli.run_read(args))

    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out[out.index("{") :])
    assert payload["documents"][0]["device_auth_type"] == "deviceMac"
    assert payload["documents"][0]["device_auth_valid"] is True


@pytest.mark.parametrize("json_output", [False, True])
def test_read_rejects_inline_historical_device_mac(wallet_engagement, monkeypatch, capsys, json_output):
    device_priv, de_bytes, mdoc_uri = wallet_engagement
    monkeypatch.setattr(
        ble,
        "exchange",
        make_fake_exchange(device_priv, de_bytes, device_auth_method="mac", replay_inline_device_auth=True),
    )

    argv = ["read", mdoc_uri] + (["--json"] if json_output else [])
    args = cli.build_parser().parse_args(argv)
    rc = asyncio.run(cli.run_read(args))

    assert rc == 1
    captured = capsys.readouterr()
    assert "device_auth_not_valid" in captured.err
    assert "given_name" not in captured.out
    assert "family_name" not in captured.out


def test_read_dump_cbor_does_not_retain_response(wallet_engagement, monkeypatch, capsys, tmp_path):
    device_priv, de_bytes, mdoc_uri = wallet_engagement
    monkeypatch.setattr(ble, "exchange", make_fake_exchange(device_priv, de_bytes))

    args = cli.build_parser().parse_args(["read", mdoc_uri, "--dump-cbor", str(tmp_path)])
    rc = asyncio.run(cli.run_read(args))

    assert rc == 0
    assert {path.name for path in tmp_path.iterdir()} == {
        "engagement.cbor",
        "device_request.cbor",
        "session_establishment.cbor",
    }
    captured = capsys.readouterr()
    assert "SessionData/DeviceResponse dumps are disabled" in captured.err


@pytest.mark.parametrize("json_output", [False, True])
@pytest.mark.parametrize("failure", ["tampered", "replay"])
def test_read_end_to_end_rejects_invalid_device_auth(wallet_engagement, monkeypatch, capsys, json_output, failure):
    device_priv, de_bytes, mdoc_uri = wallet_engagement
    document_kwargs = {"tamper_device_signature": True} if failure == "tampered" else {"replay_inline_device_signature": True}
    monkeypatch.setattr(ble, "exchange", make_fake_exchange(device_priv, de_bytes, **document_kwargs))

    argv = ["read", mdoc_uri] + (["--json"] if json_output else [])
    args = cli.build_parser().parse_args(argv)
    rc = asyncio.run(cli.run_read(args))

    assert rc == 1
    captured = capsys.readouterr()
    assert "device_auth_not_valid" in captured.err
    assert "given_name" not in captured.out
    assert "family_name" not in captured.out


@pytest.mark.parametrize("json_output", [False, True])
@pytest.mark.parametrize(
    ("document_kwargs", "expected_error"),
    [
        ({"device_namespaces": {"org.iso.18013.5.1": {"device_claim": "value"}}}, "device_namespaces_unsupported"),
        ({"errors": {"org.iso.18013.5.1": {"other": []}}}, "invalid_errors"),
        ({"errors": {"org.iso.18013.5.1": {"other": 1 << 20000}}}, "invalid_errors"),
        ({"device_namespaces": []}, "device_namespaces_unsupported"),
        ({"device_namespaces": [], "device_namespaces_tagged": False}, "malformed DeviceResponse"),
        ({"device_namespaces": {}, "device_namespaces_tagged": False}, "malformed DeviceResponse"),
        ({"additional_device_auth": {"deviceMac": [b"", {}, None, b""]}}, "device_auth_not_valid"),
    ],
)
def test_read_rejects_unsafe_response_content(
    wallet_engagement, monkeypatch, capsys, json_output, document_kwargs, expected_error
):
    device_priv, de_bytes, mdoc_uri = wallet_engagement
    monkeypatch.setattr(ble, "exchange", make_fake_exchange(device_priv, de_bytes, **document_kwargs))

    argv = ["read", mdoc_uri] + (["--json"] if json_output else [])
    args = cli.build_parser().parse_args(argv)
    rc = asyncio.run(cli.run_read(args))

    assert rc == 1
    captured = capsys.readouterr()
    assert expected_error in captured.err
    assert "given_name" not in captured.out
    assert "family_name" not in captured.out


@pytest.mark.parametrize("json_output", [False, True])
def test_read_escapes_validation_diagnostics(wallet_engagement, monkeypatch, capsys, json_output):
    device_priv, de_bytes, mdoc_uri = wallet_engagement
    monkeypatch.setattr(ble, "exchange", make_fake_exchange(device_priv, de_bytes))
    monkeypatch.setattr(cli.mdoc, "validate_device_response", lambda *args, **kwargs: ["bad\x1b[31m\nforged"])
    argv = ["read", mdoc_uri] + (["--json"] if json_output else [])
    args = cli.build_parser().parse_args(argv)

    rc = asyncio.run(cli.run_read(args))

    assert rc == 1
    captured = capsys.readouterr()
    assert "\x1b" not in captured.err
    assert "\nforged" not in captured.err
    assert "bad\\x1b[31m\\nforged" in captured.err
    assert "given_name" not in captured.out


def test_read_escapes_session_data_status(wallet_engagement, monkeypatch, capsys):
    _device_priv, _de_bytes, mdoc_uri = wallet_engagement

    async def fake_exchange(*args, **kwargs):
        return ble.ExchangeResult(
            session_data_bytes=cbor2.dumps({"status": "bad\x1b[2J"}),
            negotiated_mtu=185,
            chunk_size=182,
            device_address="AA:BB:CC:DD:EE:FF",
        )

    monkeypatch.setattr(ble, "exchange", fake_exchange)
    args = cli.build_parser().parse_args(["read", mdoc_uri])
    rc = asyncio.run(cli.run_read(args))

    assert rc == 1
    captured = capsys.readouterr()
    assert "\x1b" not in captured.err
    assert "bad\\x1b[2J" in captured.err
