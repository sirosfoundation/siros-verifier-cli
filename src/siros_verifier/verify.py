"""Cryptographic verification of COSE signatures/MACs and MSO digests -
ISO/IEC 18013-5 §9.1.2.5 (digests), §9.1.3 (mdoc/device authentication),
§9.3.1 (issuer data authentication, signature step only).

This module checks whether a signature/MAC/digest is internally VALID given
the key or certificate presented in the message itself. It does NOT evaluate
trust: it never checks whether an IssuerAuth certificate chains to a trusted
IACA root, is unrevoked, or is otherwise policy-compliant. "Valid" here means
"consistent with the presented key", not "trustworthy" - trust evaluation
remains out of scope for this tool.
"""

from __future__ import annotations

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as hmac_primitive
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# RFC 9053 Table 5 - ECDSA algorithms this tool can verify.
ECDSA_ALG_HASHES = {
    -7: hashes.SHA256(),  # ES256
    -35: hashes.SHA384(),  # ES384
    -36: hashes.SHA512(),  # ES512
}
EDDSA_ALG = -8
HMAC_256_256_ALG = 5  # RFC 9053 Table 7

# ISO 18013-5 Table 21.
DIGEST_ALGORITHMS: dict[str, hashes.HashAlgorithm] = {
    "SHA-256": hashes.SHA256(),
    "SHA-384": hashes.SHA384(),
    "SHA-512": hashes.SHA512(),
}


class UnsupportedAlgorithm(ValueError):
    """The algorithm/key combination isn't one this tool can verify - not a
    verification failure, just "not attempted"."""


def _sig_structure(context: str, protected_bytes: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    """RFC 9052 §4.4 Sig_structure / §6.3 MAC_structure - same shape, different context string."""
    return cbor2.dumps([context, protected_bytes, external_aad, payload])


def _cose_alg(cose_struct: list) -> int:
    protected_bytes, unprotected = cose_struct[0], cose_struct[1]
    protected = cbor2.loads(protected_bytes) if protected_bytes else {}
    alg = protected.get(1, unprotected.get(1))
    if alg is None:
        raise UnsupportedAlgorithm("no alg (label 1) in COSE protected/unprotected header")
    return alg


def verify_cose_sign1(
    cose_sign1: list,
    public_key,
    detached_payload: bytes | None = None,
    external_aad: bytes = b"",
) -> bool:
    """Verify a COSE_Sign1 = [protected, unprotected, payload, signature].
    `detached_payload` is required when `payload` is null (as for DeviceAuth)."""
    protected_bytes, _unprotected, payload, signature = cose_sign1
    message_payload = payload if payload is not None else detached_payload
    if message_payload is None:
        raise UnsupportedAlgorithm("COSE_Sign1 payload is null and no detached content was supplied")
    alg = _cose_alg(cose_sign1)
    sig_struct = _sig_structure("Signature1", protected_bytes, message_payload, external_aad)

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        hash_alg = ECDSA_ALG_HASHES.get(alg)
        if hash_alg is None:
            raise UnsupportedAlgorithm(f"unsupported ECDSA COSE alg {alg}")
        key_len = (public_key.curve.key_size + 7) // 8
        if len(signature) != 2 * key_len:
            return False
        r = int.from_bytes(signature[:key_len], "big")
        s = int.from_bytes(signature[key_len:], "big")
        try:
            public_key.verify(encode_dss_signature(r, s), sig_struct, ec.ECDSA(hash_alg))
            return True
        except InvalidSignature:
            return False

    if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        if alg != EDDSA_ALG:
            raise UnsupportedAlgorithm(f"unsupported EdDSA COSE alg {alg}")
        try:
            public_key.verify(signature, sig_struct)
            return True
        except InvalidSignature:
            return False

    raise UnsupportedAlgorithm(f"unsupported public key type {type(public_key)!r}")


def verify_cose_mac0(
    cose_mac0: list,
    mac_key: bytes,
    detached_payload: bytes | None = None,
    external_aad: bytes = b"",
) -> bool:
    """Verify a COSE_Mac0 = [protected, unprotected, payload, tag]. Only
    HMAC 256/256 (the only algorithm ISO 18013-5 §9.1.3.5 permits) is supported."""
    protected_bytes, _unprotected, payload, tag = cose_mac0
    message_payload = payload if payload is not None else detached_payload
    if message_payload is None:
        raise UnsupportedAlgorithm("COSE_Mac0 payload is null and no detached content was supplied")
    alg = _cose_alg(cose_mac0)
    if alg != HMAC_256_256_ALG:
        raise UnsupportedAlgorithm(f"unsupported MAC COSE alg {alg}, only HMAC 256/256 ({HMAC_256_256_ALG}) is supported")
    mac_struct = _sig_structure("MAC0", protected_bytes, message_payload, external_aad)
    h = hmac_primitive.HMAC(mac_key, hashes.SHA256())
    h.update(mac_struct)
    try:
        h.verify(tag)
        return True
    except InvalidSignature:
        return False


def verify_digest(digest_algorithm: str, issuer_signed_item_bytes: bytes, expected_digest: bytes) -> bool:
    """ISO 18013-5 §9.1.2.5: digest = Hash(IssuerSignedItemBytes)."""
    algorithm = DIGEST_ALGORITHMS.get(digest_algorithm)
    if algorithm is None:
        raise UnsupportedAlgorithm(f"unsupported digestAlgorithm {digest_algorithm!r}")
    digest = hashes.Hash(algorithm)
    digest.update(issuer_signed_item_bytes)
    return digest.finalize() == expected_digest
