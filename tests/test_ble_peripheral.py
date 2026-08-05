"""Unit tests for ble_peripheral's state machine, against a fake bless server -
no real bless install or Bluetooth adapter needed (same technique test_qr.py
uses for _require_camera_deps)."""

from __future__ import annotations

import asyncio
import uuid
from typing import ClassVar

import pytest

from siros_verifier import ble, ble_peripheral


class _FakeProps:
    read = "read"
    write_without_response = "write_without_response"
    notify = "notify"


class _FakePerms:
    readable = "readable"
    writeable = "writeable"


class _FakeCharacteristic:
    def __init__(self, char_uuid, value):
        self.uuid = char_uuid
        self.value = value


class FakeBlessServer:
    """Mirrors bless 0.3.0's real shape: a single server-wide
    read_request_func/write_request_func, invoked as func(characteristic) /
    func(characteristic, value) - ble_peripheral.py dispatches by
    characteristic.uuid itself, exactly as it would against the real bless.
    `trigger_write(uuid, value)` simulates the mdoc writing a characteristic."""

    instances: ClassVar[list[FakeBlessServer]] = []

    def __init__(self, name, loop):
        self.characteristics: dict[str, _FakeCharacteristic] = {}
        self.notified_chunks: dict[str, list[bytes]] = {}
        self.stopped = False
        self.read_request_func = None
        self.write_request_func = None
        FakeBlessServer.instances.append(self)

    async def add_new_service(self, uuid):
        pass

    async def add_new_characteristic(self, service_uuid, char_uuid, properties, value, permissions):
        self.characteristics[char_uuid] = _FakeCharacteristic(char_uuid, value)

    def get_characteristic(self, char_uuid):
        return self.characteristics[char_uuid]

    def update_value(self, service_uuid, char_uuid):
        self.notified_chunks.setdefault(char_uuid, []).append(bytes(self.characteristics[char_uuid].value))
        return True

    async def start(self):
        pass

    async def stop(self):
        self.stopped = True

    def trigger_write(self, char_uuid, value):
        self.write_request_func(self.characteristics[char_uuid], value)


@pytest.fixture(autouse=True)
def fake_bless(monkeypatch):
    FakeBlessServer.instances.clear()
    monkeypatch.setattr(ble_peripheral, "_require_bless", lambda: (FakeBlessServer, _FakeProps, _FakePerms))


def reassemble(chunks: list[bytes]) -> bytes:
    reassembler = ble.Reassembler()
    result = None
    for chunk in chunks:
        result = reassembler.feed(chunk)
    return result


async def _drive_exchange(central_client_uuid, e_device_key_bytes, session_establishment_bytes, response_bytes):
    task = asyncio.create_task(
        ble_peripheral.exchange(
            central_client_uuid, e_device_key_bytes, session_establishment_bytes, advertise_timeout=5.0, response_timeout=5.0
        )
    )
    await asyncio.sleep(0)  # let exchange() construct the server and register characteristics
    server = FakeBlessServer.instances[-1]

    server.trigger_write(ble_peripheral.STATE_UUID, ble.STATE_START)
    await asyncio.sleep(0)  # let exchange() past start_future, run the notify loop, then await response_future

    for chunk in ble.chunk_message(response_bytes, max_chunk_size=20):
        server.trigger_write(ble_peripheral.CLIENT2SERVER_UUID, chunk)

    result = await task
    return result, server


def test_exchange_sets_ident_characteristic_from_compute_ident():
    from siros_verifier import crypto

    e_device_key_bytes = b"\x01" * 40

    async def run():
        task = asyncio.create_task(
            ble_peripheral.exchange(uuid.uuid4(), e_device_key_bytes, b"se", advertise_timeout=5.0, response_timeout=5.0)
        )
        await asyncio.sleep(0)
        server = FakeBlessServer.instances[-1]
        assert bytes(server.characteristics[ble_peripheral.IDENT_UUID].value) == crypto.compute_ident(e_device_key_bytes)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())


def test_exchange_full_round_trip():
    async def run():
        return await _drive_exchange(uuid.uuid4(), b"\x02" * 40, b"session establishment bytes", b"session data response bytes")

    (result, server) = asyncio.run(run())

    assert result.session_data_bytes == b"session data response bytes"
    assert reassemble(server.notified_chunks[ble_peripheral.SERVER2CLIENT_UUID]) == b"session establishment bytes"
    assert server.stopped


def test_exchange_raises_device_not_found_on_advertise_timeout():
    async def run():
        with pytest.raises(ble.DeviceNotFoundError):
            await ble_peripheral.exchange(uuid.uuid4(), b"\x03" * 40, b"se", advertise_timeout=0.05, response_timeout=1.0)

    asyncio.run(run())
    assert FakeBlessServer.instances[-1].stopped


def test_exchange_stops_server_even_on_response_timeout():
    async def run():
        task = asyncio.create_task(
            ble_peripheral.exchange(uuid.uuid4(), b"\x04" * 40, b"se", advertise_timeout=5.0, response_timeout=0.05)
        )
        await asyncio.sleep(0)
        server = FakeBlessServer.instances[-1]
        server.trigger_write(ble_peripheral.STATE_UUID, ble.STATE_START)
        with pytest.raises(asyncio.TimeoutError):
            await task
        assert server.stopped

    asyncio.run(run())
