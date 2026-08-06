"""Unit tests for cli.py helpers that don't need a full BLE round trip."""

from __future__ import annotations

import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from siros_verifier import cli
from siros_verifier.engagement import DeviceEngagement


def _engagement(*, peripheral: bool, central: bool) -> DeviceEngagement:
    return DeviceEngagement(
        raw_bytes=b"",
        version="1.0",
        cipher_suite=1,
        e_device_key_pub=ec.generate_private_key(ec.SECP256R1()).public_key(),
        e_device_key_bytes=b"",
        retrieval_methods=[],
        peripheral_server_uuid=uuid.uuid4() if peripheral else None,
        central_client_uuid=uuid.uuid4() if central else None,
    )


def test_resolve_mode_auto_prefers_peripheral_when_both_offered():
    de = _engagement(peripheral=True, central=True)
    assert cli._resolve_mode("auto", de) is True


def test_resolve_mode_auto_falls_back_to_central_when_only_central_offered():
    de = _engagement(peripheral=False, central=True)
    assert cli._resolve_mode("auto", de) is False


def test_resolve_mode_central_overrides_auto_preference_when_both_offered():
    de = _engagement(peripheral=True, central=True)
    assert cli._resolve_mode("central", de) is False


def test_resolve_mode_peripheral_explicit_when_both_offered():
    de = _engagement(peripheral=True, central=True)
    assert cli._resolve_mode("peripheral", de) is True


def test_resolve_mode_central_errors_when_not_offered():
    de = _engagement(peripheral=True, central=False)
    with pytest.raises(SystemExit, match="doesn't offer mdoc central client mode"):
        cli._resolve_mode("central", de)


def test_resolve_mode_peripheral_errors_when_not_offered():
    de = _engagement(peripheral=False, central=True)
    with pytest.raises(SystemExit, match="doesn't offer mdoc peripheral server mode"):
        cli._resolve_mode("peripheral", de)
