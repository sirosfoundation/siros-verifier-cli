import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from helpers import sign_es256_raw

from siros_verifier.verify import UnsupportedAlgorithm, verify_cose_mac0, verify_cose_sign1, verify_digest


def build_cose_sign1(private_key: ec.EllipticCurvePrivateKey, payload: bytes, alg: int = -7) -> list:
    protected = cbor2.dumps({1: alg})
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    signature = sign_es256_raw(private_key, sig_structure)
    return [protected, {}, payload, signature]


def test_verify_cose_sign1_ecdsa_valid():
    key = ec.generate_private_key(ec.SECP256R1())
    cose_sign1 = build_cose_sign1(key, payload=b"hello mdoc")
    assert verify_cose_sign1(cose_sign1, key.public_key()) is True


def test_verify_cose_sign1_ecdsa_rejects_tampered_payload():
    key = ec.generate_private_key(ec.SECP256R1())
    cose_sign1 = build_cose_sign1(key, payload=b"hello mdoc")
    cose_sign1[2] = b"tampered payload!"
    assert verify_cose_sign1(cose_sign1, key.public_key()) is False


def test_verify_cose_sign1_ecdsa_rejects_wrong_key():
    key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    cose_sign1 = build_cose_sign1(key, payload=b"hello mdoc")
    assert verify_cose_sign1(cose_sign1, other_key.public_key()) is False


def test_verify_cose_sign1_eddsa_valid():
    key = ed25519.Ed25519PrivateKey.generate()
    payload = b"hello mdoc"
    protected = cbor2.dumps({1: -8})
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    signature = key.sign(sig_structure)
    cose_sign1 = [protected, {}, payload, signature]
    assert verify_cose_sign1(cose_sign1, key.public_key()) is True


def test_verify_cose_sign1_detached_payload():
    key = ec.generate_private_key(ec.SECP256R1())
    detached = b"DeviceAuthenticationBytes go here"
    protected = cbor2.dumps({1: -7})
    sig_structure = cbor2.dumps(["Signature1", protected, b"", detached])
    signature = sign_es256_raw(key, sig_structure)
    cose_sign1 = [protected, {}, None, signature]
    assert verify_cose_sign1(cose_sign1, key.public_key(), detached_payload=detached) is True


def test_verify_cose_sign1_raises_without_payload_or_detached():
    key = ec.generate_private_key(ec.SECP256R1())
    cose_sign1 = [cbor2.dumps({1: -7}), {}, None, b"\x00" * 64]
    with pytest.raises(UnsupportedAlgorithm):
        verify_cose_sign1(cose_sign1, key.public_key())


def test_verify_cose_sign1_unsupported_alg_raises():
    key = ec.generate_private_key(ec.SECP256R1())
    protected = cbor2.dumps({1: -999})
    cose_sign1 = [protected, {}, b"payload", b"\x00" * 64]
    with pytest.raises(UnsupportedAlgorithm):
        verify_cose_sign1(cose_sign1, key.public_key())


def test_verify_cose_mac0_valid_and_invalid():
    mac_key = b"\x11" * 32
    payload = b"detached device auth content"
    protected = cbor2.dumps({1: 5})  # HMAC 256/256
    mac_struct = cbor2.dumps(["MAC0", protected, b"", payload])

    from cryptography.hazmat.primitives import hmac as hmac_primitive

    h = hmac_primitive.HMAC(mac_key, hashes.SHA256())
    h.update(mac_struct)
    tag = h.finalize()

    cose_mac0 = [protected, {}, payload, tag]
    assert verify_cose_mac0(cose_mac0, mac_key) is True

    wrong_key = b"\x22" * 32
    assert verify_cose_mac0(cose_mac0, wrong_key) is False


def test_verify_cose_mac0_unsupported_alg_raises():
    protected = cbor2.dumps({1: -7})  # not HMAC
    cose_mac0 = [protected, {}, b"payload", b"\x00" * 32]
    with pytest.raises(UnsupportedAlgorithm):
        verify_cose_mac0(cose_mac0, b"\x00" * 32)


def test_verify_digest_matches_and_mismatches():
    data = b"issuer signed item bytes"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    expected = digest.finalize()

    assert verify_digest("SHA-256", data, expected) is True
    assert verify_digest("SHA-256", data, b"\x00" * 32) is False


def test_verify_digest_unsupported_algorithm_raises():
    with pytest.raises(UnsupportedAlgorithm):
        verify_digest("SHA-1", b"data", b"digest")
