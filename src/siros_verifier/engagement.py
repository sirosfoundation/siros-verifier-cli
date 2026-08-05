"""DeviceEngagement parsing - ISO/IEC 18013-5 §8.2.1.

Decodes the CBOR structure carried in a `mdoc:` QR-code URI (or, for NFC
static/negotiated handover, the raw Handover Select NDEF payload) into a
structured, inspectable form - independent of how it was transported and
independent of BLE, so it can be exercised offline (`siros-verify engagement
decode`) as well as feeding the live `siros-verify read` flow.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec

from siros_verifier.crypto import cose_key_to_public_key

# ISO 18013-5 Table 11 (BLE DeviceRetrievalMethod options).
BLE_PERIPHERAL_SERVER_MODE_UUID_KEY = 10
BLE_CENTRAL_CLIENT_MODE_UUID_KEY = 11
BLE_RETRIEVAL_METHOD_TYPE = 2


class UnsupportedEngagementError(ValueError):
    """Raised when the engagement is well-formed but this tool can't drive it."""


@dataclass
class DeviceEngagement:
    raw_bytes: bytes
    version: str
    cipher_suite: int
    e_device_key_pub: ec.EllipticCurvePublicKey
    e_device_key_bytes: bytes  # EDeviceKeyBytes as transmitted - needed by crypto.compute_ident
    retrieval_methods: list
    peripheral_server_uuid: uuid.UUID | None
    central_client_uuid: uuid.UUID | None

    @property
    def supports_peripheral_server_mode(self) -> bool:
        """True if the mdoc offers a peripheral-server-mode UUID, i.e. it will
        act as the BLE GATT peripheral and this tool must connect as central -
        the only mode this tool can currently drive."""
        return self.peripheral_server_uuid is not None


def _decode_ble_options(retrieval_methods: list) -> tuple[uuid.UUID | None, uuid.UUID | None]:
    ble_options = next(
        (m[2] for m in retrieval_methods if m[0] == BLE_RETRIEVAL_METHOD_TYPE), None
    )
    if ble_options is None:
        return None, None

    def uuid_at(key: int) -> uuid.UUID | None:
        raw = ble_options.get(key)
        return None if raw is None else uuid.UUID(bytes=raw)

    return (
        uuid_at(BLE_PERIPHERAL_SERVER_MODE_UUID_KEY),
        uuid_at(BLE_CENTRAL_CLIENT_MODE_UUID_KEY),
    )


def parse(de_bytes: bytes) -> DeviceEngagement:
    """Parse raw (untagged) DeviceEngagement CBOR bytes."""
    de = cbor2.loads(de_bytes)

    version = de[0]
    security = de[1]  # [cipherSuite, EDeviceKeyBytes]
    cipher_suite = security[0]
    e_device_key_tag = security[1]
    e_device_key_bytes = cbor2.dumps(e_device_key_tag)
    cose_key = cbor2.loads(e_device_key_tag.value)
    e_device_key_pub = cose_key_to_public_key(cose_key)

    retrieval_methods = de.get(2, [])
    peripheral_uuid, central_uuid = _decode_ble_options(retrieval_methods)

    if peripheral_uuid is None and central_uuid is None:
        raise UnsupportedEngagementError(
            "engagement offers no BLE retrieval method (no ConnectionMethod of type 2)"
        )

    return DeviceEngagement(
        raw_bytes=de_bytes,
        version=version,
        cipher_suite=cipher_suite,
        e_device_key_pub=e_device_key_pub,
        e_device_key_bytes=e_device_key_bytes,
        retrieval_methods=retrieval_methods,
        peripheral_server_uuid=peripheral_uuid,
        central_client_uuid=central_uuid,
    )


def parse_mdoc_uri(mdoc_uri: str) -> DeviceEngagement:
    """Decode a `mdoc:` URI (base64url, no padding) into a DeviceEngagement."""
    if not mdoc_uri.startswith("mdoc:"):
        raise ValueError("expected a URI starting with 'mdoc:'")
    encoded = mdoc_uri.removeprefix("mdoc:")
    padded = encoded + "=" * (-len(encoded) % 4)
    return parse(base64.urlsafe_b64decode(padded))


def read_qr_image(path: str) -> str:
    """Decode a `mdoc:` URI out of a QR code image file. Requires the `qr`
    extra (pyzbar + Pillow) to be installed."""
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as zbar_decode
    except ImportError as exc:
        raise ImportError(
            "reading QR images requires the 'qr' extra: pip install 'siros-verifier-cli[qr]'"
        ) from exc

    symbols = zbar_decode(Image.open(path))
    if not symbols:
        raise ValueError(f"no QR code found in {path}")
    return symbols[0].data.decode("ascii")
