"""Deliberately malformed / abusive ISO/IEC 18013-5 BLE proximity interactions.

`read` drives a normal, well-formed transaction. Each scenario here reuses
the same engagement decode / ECDH / session-key derivation, but deviates in
exactly one way, to exercise the mdoc's error handling rather than its happy
path. This tool has no way to inspect the mdoc's own internal state (that's
the wallet app's job) - a human watching the wallet's screen is the real
oracle for "did it recover cleanly" vs "did it hang or crash". These
scenarios' own output just reports what was actually put on the wire and how
the BLE transport itself behaved (timings, exceptions).

A few other useful stress cases need no code here at all - see the README:
- requesting a docType/namespace the wallet has no matching credential for
  (`read --request nonexistent.doc.type:ns:claim`)
- mixing a valid and an invalid docType in the same DeviceRequest (repeat
  `--request`)
- racing both BLE modes against each other (`read --mode peripheral` and
  `read --mode central` against the same engagement, concurrently)
"""

from __future__ import annotations

import enum
import os

import cbor2

from siros_verifier import crypto, mdoc


class Scenario(str, enum.Enum):
    GARBAGE_CBOR_REQUEST = "garbage-cbor-request"
    CORRUPT_CIPHERTEXT = "corrupt-ciphertext"
    TRUNCATED_SESSION_ESTABLISHMENT = "truncated-session-establishment"
    DROP_MID_CHUNK = "drop-mid-chunk"
    DISCONNECT_AFTER_CONNECT = "disconnect-after-connect"
    RAPID_RECONNECT = "rapid-reconnect"


SCENARIO_DESCRIPTIONS: dict[Scenario, str] = {
    Scenario.GARBAGE_CBOR_REQUEST: (
        "Send a structurally valid, correctly-encrypted SessionEstablishment "
        "whose decrypted DeviceRequest is random bytes, not CBOR at all."
    ),
    Scenario.CORRUPT_CIPHERTEXT: (
        "Encrypt a real DeviceRequest, then flip a bit in the ciphertext - "
        "AES-GCM's integrity check should fail on decrypt."
    ),
    Scenario.TRUNCATED_SESSION_ESTABLISHMENT: (
        "Build a real SessionEstablishment, then truncate the encoded bytes "
        "before sending - the outer CBOR structure itself is incomplete."
    ),
    Scenario.DROP_MID_CHUNK: (
        "Start a real chunked SessionEstablishment transfer, then disconnect "
        "before sending the final chunk."
    ),
    Scenario.DISCONNECT_AFTER_CONNECT: (
        "Connect (optionally writing STATE_START), then disconnect "
        "immediately without ever sending a request."
    ),
    Scenario.RAPID_RECONNECT: (
        "Connect and disconnect repeatedly in quick succession, without ever "
        "sending a request."
    ),
}

# Scenarios handled entirely by ble.exchange() once given the "wrong"
# session_establishment_bytes - no bespoke transport code needed.
CIPHERTEXT_LEVEL_SCENARIOS = (
    Scenario.GARBAGE_CBOR_REQUEST,
    Scenario.CORRUPT_CIPHERTEXT,
    Scenario.TRUNCATED_SESSION_ESTABLISHMENT,
)

# Scenarios that need their own transport loop (see ble.py) because they
# never complete a normal message exchange.
TRANSPORT_LEVEL_SCENARIOS = (
    Scenario.DROP_MID_CHUNK,
    Scenario.DISCONNECT_AFTER_CONNECT,
    Scenario.RAPID_RECONNECT,
)


def corrupt_ciphertext(ciphertext: bytes) -> bytes:
    """Flip the low bit of the last byte. Any single-bit change anywhere in
    an AES-GCM ciphertext (including inside its 16-byte authentication tag)
    invalidates the whole message on decrypt - which byte doesn't matter for
    what this is testing."""
    if not ciphertext:
        raise ValueError("ciphertext is empty, nothing to corrupt")
    return ciphertext[:-1] + bytes([ciphertext[-1] ^ 0x01])


def build_garbage_request_session_establishment(
    e_reader_key_tag: cbor2.CBORTag, sk_reader: bytes, size: int = 64
) -> bytes:
    """A SessionEstablishment whose encrypted payload decrypts to `size`
    random bytes instead of a CBOR-encoded DeviceRequest."""
    garbage = os.urandom(size)
    ciphertext = crypto.encrypt_reader_message(sk_reader, 1, garbage)
    return mdoc.build_session_establishment(e_reader_key_tag, ciphertext)


def build_corrupt_ciphertext_session_establishment(
    e_reader_key_tag: cbor2.CBORTag, sk_reader: bytes, device_request_bytes: bytes
) -> bytes:
    """A SessionEstablishment carrying a real DeviceRequest, with the
    ciphertext tampered with after encryption."""
    ciphertext = crypto.encrypt_reader_message(sk_reader, 1, device_request_bytes)
    return mdoc.build_session_establishment(e_reader_key_tag, corrupt_ciphertext(ciphertext))


def truncate_session_establishment(session_establishment_bytes: bytes, keep_fraction: float = 0.7) -> bytes:
    """Drop the tail of an otherwise-valid SessionEstablishment's own CBOR
    encoding - a different failure point than a corrupted-but-complete inner
    ciphertext (see `corrupt_ciphertext`): the mdoc's outer CBOR decode of
    the message itself should fail here, before it ever reaches AES-GCM."""
    if not 0 < keep_fraction < 1:
        raise ValueError(f"keep_fraction must be strictly between 0 and 1, got {keep_fraction}")
    keep = max(1, int(len(session_establishment_bytes) * keep_fraction))
    return session_establishment_bytes[:keep]
