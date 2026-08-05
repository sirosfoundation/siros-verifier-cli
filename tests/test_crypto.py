import cbor2
from cryptography.hazmat.primitives.asymmetric import ec

from siros_verifier.crypto import (
    build_session_transcript,
    cose_key_tag,
    cose_key_to_public_key,
    decrypt_device_message,
    derive_session_keys,
    encrypt_reader_message,
)


def test_cose_key_roundtrip():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    tag = cose_key_tag(pub)
    assert tag.tag == 24
    cose_key = cbor2.loads(tag.value)
    recovered = cose_key_to_public_key(cose_key)
    assert recovered.public_numbers() == pub.public_numbers()


def test_cose_key_to_public_key_rejects_non_ec2():
    import pytest

    with pytest.raises(ValueError):
        cose_key_to_public_key({1: 1, -1: 1, -2: b"x", -3: b"y"})  # kty=OKP, not EC2


def test_derive_session_keys_matches_between_reader_and_device_roles():
    # Mirrors the ECKA-DH symmetry the protocol relies on: both sides derive
    # the same SKReader/SKDevice pair from their own private + the peer's public key.
    reader_priv = ec.generate_private_key(ec.SECP256R1())
    device_priv = ec.generate_private_key(ec.SECP256R1())

    device_engagement_bytes = b"\x01\x02\x03"
    e_reader_key_tag = cose_key_tag(reader_priv.public_key())
    transcript = build_session_transcript(device_engagement_bytes, e_reader_key_tag, None)

    zab_reader = reader_priv.exchange(ec.ECDH(), device_priv.public_key())
    zab_device = device_priv.exchange(ec.ECDH(), reader_priv.public_key())
    assert zab_reader == zab_device

    sk_reader_1, sk_device_1 = derive_session_keys(zab_reader, transcript)
    sk_reader_2, sk_device_2 = derive_session_keys(zab_device, transcript)
    assert sk_reader_1 == sk_reader_2
    assert sk_device_1 == sk_device_2
    assert sk_reader_1 != sk_device_1


def test_encrypt_decrypt_roundtrip():
    key = b"\x00" * 32
    plaintext = b"device request bytes"
    ciphertext = encrypt_reader_message(key, counter=1, plaintext=plaintext)
    # cross-check against decrypt_device_message using the same key/counter/identifier scheme
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from siros_verifier.crypto import MDOC_IDENTIFIER, READER_IDENTIFIER, gcm_iv

    assert AESGCM(key).decrypt(gcm_iv(READER_IDENTIFIER, 1), ciphertext, b"") == plaintext

    device_ciphertext = AESGCM(key).encrypt(gcm_iv(MDOC_IDENTIFIER, 1), plaintext, b"")
    assert decrypt_device_message(key, counter=1, ciphertext=device_ciphertext) == plaintext
