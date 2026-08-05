"""Session crypto for ISO/IEC 18013-5 device retrieval (§9.1.1, §9.1.2).

Pure functions only - no I/O, no BLE. ECKA-DH key agreement, HKDF-SHA256
session key derivation, COSE_Key encode/decode for P-256 points, and the
AES-GCM framing used for SessionEstablishment/SessionData.
"""

from __future__ import annotations

import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

READER_IDENTIFIER = bytes(8)
MDOC_IDENTIFIER = bytes(7) + b"\x01"


def cose_key_tag(pub: ec.EllipticCurvePublicKey) -> cbor2.CBORTag:
    """Tag-24-wrapped COSE_Key for an uncompressed P-256 public point."""
    numbers = pub.public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    cose_key = {1: 2, -1: 1, -2: x, -3: y}  # kty=EC2, crv=P-256
    return cbor2.CBORTag(24, cbor2.dumps(cose_key))


def cose_key_to_public_key(cose_key: dict) -> ec.EllipticCurvePublicKey:
    """Decode a (untagged) COSE_Key map into an EC public key. Only P-256 EC2 keys."""
    if cose_key.get(1) != 2:
        raise ValueError(f"unsupported COSE kty {cose_key.get(1)!r}, expected 2 (EC2)")
    if cose_key.get(-1) != 1:
        raise ValueError(f"unsupported COSE crv {cose_key.get(-1)!r}, expected 1 (P-256)")
    x = cose_key[-2]
    y = cose_key[-3]
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
    ).public_key()


def build_session_transcript(
    device_engagement_bytes: bytes,
    e_reader_key_tag: cbor2.CBORTag,
    handover: object | None,
) -> bytes:
    """Bare (untagged) SessionTranscript array bytes - ISO 18013-5 §9.1.5.1.

    `handover` is None for QR engagement, or [HandoverSelectMessage,
    HandoverRequestMessage] for NFC static/negotiated handover.
    """
    transcript = [
        cbor2.CBORTag(24, device_engagement_bytes),
        e_reader_key_tag,
        handover,
    ]
    return cbor2.dumps(transcript)


def _transcript_salt(session_transcript: bytes) -> bytes:
    """salt = SHA-256(tag-24-wrapped SessionTranscriptBytes), shared by SKReader/
    SKDevice (§9.1.1.5) and EMacKey (§9.1.3.5) derivation."""
    session_transcript_bytes = cbor2.dumps(cbor2.CBORTag(24, session_transcript))
    digest = hashes.Hash(hashes.SHA256())
    digest.update(session_transcript_bytes)
    return digest.finalize()


def derive_session_keys(zab: bytes, session_transcript: bytes) -> tuple[bytes, bytes]:
    """ECKA-DH -> HKDF-SHA256(SKReader/SKDevice) - ISO 18013-5 §9.1.1.5."""
    salt = _transcript_salt(session_transcript)
    sk_reader = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"SKReader").derive(zab)
    sk_device = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"SKDevice").derive(zab)
    return sk_reader, sk_device


def derive_emac_key(zab: bytes, session_transcript: bytes) -> bytes:
    """ECKA-DH(SDeviceKey/EReaderKey) -> HKDF-SHA256(EMacKey) - ISO 18013-5 §9.1.3.5."""
    salt = _transcript_salt(session_transcript)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"EMacKey").derive(zab)


def gcm_iv(identifier: bytes, counter: int) -> bytes:
    """IV = identifier(8) || big-endian counter(4) - ISO 18013-5 §9.1.1.5 Table 8."""
    return identifier + struct.pack(">I", counter)


def encrypt_reader_message(sk_reader: bytes, counter: int, plaintext: bytes) -> bytes:
    return AESGCM(sk_reader).encrypt(gcm_iv(READER_IDENTIFIER, counter), plaintext, b"")


def decrypt_device_message(sk_device: bytes, counter: int, ciphertext: bytes) -> bytes:
    return AESGCM(sk_device).decrypt(gcm_iv(MDOC_IDENTIFIER, counter), ciphertext, b"")
