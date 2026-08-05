"""Shared test fixtures for building real (correctly signed) COSE structures."""

from __future__ import annotations

import datetime

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID


def sign_es256_raw(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign `message` with ES256 and return the raw r||s COSE signature (not DER)."""
    der_sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    key_len = (private_key.curve.key_size + 7) // 8
    return r.to_bytes(key_len, "big") + s.to_bytes(key_len, "big")


def make_self_signed_cert_der(private_key: ec.EllipticCurvePrivateKey, common_name: str = "Test Document Signer") -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(12345)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def tagged24(obj) -> cbor2.CBORTag:
    return cbor2.CBORTag(24, cbor2.dumps(obj))


def cose_key_from_public_key(pub: ec.EllipticCurvePublicKey) -> dict:
    numbers = pub.public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    return {1: 2, -1: 1, -2: x, -3: y}
