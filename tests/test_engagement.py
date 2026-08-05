import base64
import uuid

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from siros_verifier.crypto import cose_key_tag
from siros_verifier.engagement import UnsupportedEngagementError, parse, parse_mdoc_uri

PERIPHERAL_UUID = uuid.uuid4()
CENTRAL_UUID = uuid.uuid4()


def build_engagement_bytes(peripheral_uuid=None, central_uuid=None) -> tuple[bytes, ec.EllipticCurvePublicKey]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    e_device_key_bytes = cose_key_tag(pub)  # same tag-24-wrapped COSE_Key shape as EDeviceKeyBytes
    security = [1, e_device_key_bytes]

    ble_options = {0: peripheral_uuid is not None, 1: central_uuid is not None}
    if peripheral_uuid is not None:
        ble_options[10] = peripheral_uuid.bytes
    if central_uuid is not None:
        ble_options[11] = central_uuid.bytes
    retrieval_methods = [[2, 1, ble_options]]

    de = {0: "1.0", 1: security, 2: retrieval_methods}
    return cbor2.dumps(de), pub


def test_parse_peripheral_server_mode():
    de_bytes, pub = build_engagement_bytes(peripheral_uuid=PERIPHERAL_UUID)
    de = parse(de_bytes)
    assert de.version == "1.0"
    assert de.peripheral_server_uuid == PERIPHERAL_UUID
    assert de.central_client_uuid is None
    assert de.supports_peripheral_server_mode
    assert de.e_device_key_pub.public_numbers() == pub.public_numbers()
    assert de.e_device_key_bytes == cbor2.dumps(cose_key_tag(pub))


def test_parse_central_client_mode_only():
    de_bytes, _pub = build_engagement_bytes(central_uuid=CENTRAL_UUID)
    de = parse(de_bytes)
    assert de.peripheral_server_uuid is None
    assert de.central_client_uuid == CENTRAL_UUID
    assert not de.supports_peripheral_server_mode


def test_parse_rejects_engagement_without_ble():
    priv = ec.generate_private_key(ec.SECP256R1())
    e_device_key_bytes = cose_key_tag(priv.public_key())
    de = {0: "1.0", 1: [1, e_device_key_bytes], 2: []}
    with pytest.raises(UnsupportedEngagementError):
        parse(cbor2.dumps(de))


def test_parse_mdoc_uri_roundtrip():
    de_bytes, _pub = build_engagement_bytes(peripheral_uuid=PERIPHERAL_UUID)
    encoded = base64.urlsafe_b64encode(de_bytes).rstrip(b"=").decode("ascii")
    de = parse_mdoc_uri(f"mdoc:{encoded}")
    assert de.peripheral_server_uuid == PERIPHERAL_UUID


def test_parse_mdoc_uri_rejects_wrong_scheme():
    with pytest.raises(ValueError):
        parse_mdoc_uri("https://example.com")
