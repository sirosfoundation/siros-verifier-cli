"""Unit tests for the `fuzz` scenario helpers, plus end-to-end tests of the
ciphertext-level `fuzz` scenarios against a fake wallet peer that reacts the
way a real mdoc's own SessionData decrypt/decode would (returning a status
code rather than crashing) - same technique test_cli_read.py uses for `read`.

The transport-level scenarios (drop-mid-chunk, disconnect-after-connect,
rapid-reconnect) drive bleak's BleakClient/BleakScanner directly and, like
the rest of ble.py's real GATT connect loop, are exercised on real hardware
rather than unit tested - see the README's "what's verified" section.
"""

from __future__ import annotations

import asyncio
import uuid

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from siros_verifier import ble, cli, crypto, fuzz


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
    import base64

    mdoc_uri = "mdoc:" + base64.urlsafe_b64encode(de_bytes).rstrip(b"=").decode()
    return device_priv, de_bytes, mdoc_uri


# ── Pure scenario-construction helpers ──────────────────────────────────


def test_corrupt_ciphertext_changes_bytes_and_length():
    original = b"\x01\x02\x03\x04"
    corrupted = fuzz.corrupt_ciphertext(original)
    assert corrupted != original
    assert len(corrupted) == len(original)


def test_corrupt_ciphertext_rejects_empty():
    with pytest.raises(ValueError, match="empty"):
        fuzz.corrupt_ciphertext(b"")


def test_truncate_session_establishment_drops_tail():
    original = bytes(range(100))
    truncated = fuzz.truncate_session_establishment(original, keep_fraction=0.5)
    assert truncated == original[:50]
    assert truncated != original


@pytest.mark.parametrize("keep_fraction", [0.0, 1.0, -0.1, 1.5])
def test_truncate_session_establishment_rejects_out_of_range_fraction(keep_fraction):
    with pytest.raises(ValueError, match="keep_fraction"):
        fuzz.truncate_session_establishment(b"x" * 10, keep_fraction=keep_fraction)


def test_build_garbage_request_session_establishment_does_not_decrypt_to_valid_device_request():
    sk_reader = b"\x00" * 32
    e_reader_priv = ec.generate_private_key(ec.SECP256R1())
    e_reader_key_tag = crypto.cose_key_tag(e_reader_priv.public_key())

    session_establishment_bytes = fuzz.build_garbage_request_session_establishment(e_reader_key_tag, sk_reader)
    se = cbor2.loads(session_establishment_bytes)
    plaintext = AESGCM(sk_reader).decrypt(crypto.gcm_iv(crypto.READER_IDENTIFIER, 1), se["data"], b"")
    # Decrypts fine (real key, real GCM tag) - the payload itself just isn't
    # a DeviceRequest. cbor2 may or may not raise on truly random bytes, but
    # even when it doesn't, it won't produce the expected dict shape.
    try:
        decoded = cbor2.loads(plaintext)
    except cbor2.CBORDecodeError:
        return
    assert not (isinstance(decoded, dict) and "docRequests" in decoded)


def test_build_corrupt_ciphertext_session_establishment_fails_gcm_tag_check():
    sk_reader = b"\x00" * 32
    e_reader_priv = ec.generate_private_key(ec.SECP256R1())
    e_reader_key_tag = crypto.cose_key_tag(e_reader_priv.public_key())
    device_request_bytes = cbor2.dumps({"version": "1.0", "docRequests": []})

    session_establishment_bytes = fuzz.build_corrupt_ciphertext_session_establishment(
        e_reader_key_tag, sk_reader, device_request_bytes
    )
    se = cbor2.loads(session_establishment_bytes)
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        AESGCM(sk_reader).decrypt(crypto.gcm_iv(crypto.READER_IDENTIFIER, 1), se["data"], b"")


# ── End-to-end `fuzz` scenarios against a fake wallet peer ──────────────


def make_fake_exchange_reacting_like_a_real_mdoc(device_priv, de_bytes):
    """Unlike test_cli_read.py's fake peer (which always succeeds), this one
    mimics how a real mdoc's own decrypt/decode would react to each
    ciphertext-level fuzz scenario: a SessionData carrying a status code,
    not a crash - exactly the behavior these scenarios exist to check for."""

    async def fake_exchange(peripheral_uuid, session_establishment_bytes, scan_timeout, response_timeout, log=lambda _: None):
        try:
            se = cbor2.loads(session_establishment_bytes)
        except cbor2.CBORDecodeError:
            return ble.ExchangeResult(
                session_data_bytes=cbor2.dumps({"status": 11}),  # CBOR decoding error
                negotiated_mtu=185,
                chunk_size=182,
                device_address="AA:BB:CC:DD:EE:FF",
            )
        e_reader_key_tag = se["eReaderKey"]
        reader_pub = crypto.cose_key_to_public_key(cbor2.loads(e_reader_key_tag.value))
        zab = device_priv.exchange(ec.ECDH(), reader_pub)
        transcript = crypto.build_session_transcript(de_bytes, e_reader_key_tag, None)
        sk_reader, sk_device = crypto.derive_session_keys(zab, transcript)

        from cryptography.exceptions import InvalidTag

        try:
            plaintext = AESGCM(sk_reader).decrypt(crypto.gcm_iv(crypto.READER_IDENTIFIER, 1), se["data"], b"")
        except InvalidTag:
            return ble.ExchangeResult(
                session_data_bytes=cbor2.dumps({"status": 10}),  # session encryption error
                negotiated_mtu=185,
                chunk_size=182,
                device_address="AA:BB:CC:DD:EE:FF",
            )

        try:
            device_request = cbor2.loads(plaintext)
            is_device_request = isinstance(device_request, dict) and "docRequests" in device_request
        except cbor2.CBORDecodeError:
            is_device_request = False
        if not is_device_request:
            return ble.ExchangeResult(
                session_data_bytes=cbor2.dumps({"status": 11}),  # CBOR decoding/validation error
                negotiated_mtu=185,
                chunk_size=182,
                device_address="AA:BB:CC:DD:EE:FF",
            )

        # A real DeviceRequest was received (shouldn't happen for these scenarios) - echo a trivial OK response.
        device_response = cbor2.dumps({"version": "1.0", "documents": [], "status": 0})
        ciphertext = AESGCM(sk_device).encrypt(crypto.gcm_iv(crypto.MDOC_IDENTIFIER, 1), device_response, b"")
        return ble.ExchangeResult(
            session_data_bytes=cbor2.dumps({"data": ciphertext}),
            negotiated_mtu=185,
            chunk_size=182,
            device_address="AA:BB:CC:DD:EE:FF",
        )

    return fake_exchange


@pytest.mark.parametrize(
    "scenario",
    [fuzz.Scenario.GARBAGE_CBOR_REQUEST.value, fuzz.Scenario.CORRUPT_CIPHERTEXT.value],
)
def test_fuzz_ciphertext_scenarios_report_expected_status(wallet_engagement, monkeypatch, capsys, scenario):
    device_priv, de_bytes, mdoc_uri = wallet_engagement
    monkeypatch.setattr(ble, "exchange", make_fake_exchange_reacting_like_a_real_mdoc(device_priv, de_bytes))

    args = cli.build_parser().parse_args(["fuzz", mdoc_uri, scenario])
    rc = asyncio.run(cli.run_fuzz(args))

    assert rc == 0
    err = capsys.readouterr().err
    assert "expected/correct response" in err


def test_fuzz_truncated_session_establishment_reports_expected_status(wallet_engagement, monkeypatch, capsys):
    device_priv, de_bytes, mdoc_uri = wallet_engagement
    monkeypatch.setattr(ble, "exchange", make_fake_exchange_reacting_like_a_real_mdoc(device_priv, de_bytes))

    args = cli.build_parser().parse_args(
        ["fuzz", mdoc_uri, fuzz.Scenario.TRUNCATED_SESSION_ESTABLISHMENT.value, "--keep-fraction", "0.5"]
    )
    rc = asyncio.run(cli.run_fuzz(args))

    assert rc == 0
    err = capsys.readouterr().err
    assert "expected/correct response" in err


def test_fuzz_rejects_central_client_mode():
    """Central-client-mode scenarios (this tool as GATT peripheral) aren't
    implemented yet - --mode central shouldn't even be an accepted choice."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["fuzz", "mdoc:AAAA", "garbage-cbor-request", "--mode", "central"])
