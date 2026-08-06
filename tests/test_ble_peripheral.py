"""Unit tests for ble_peripheral's state machine, against a fake bless server -
no real bless install or Bluetooth adapter needed (same technique test_qr.py
uses for _require_camera_deps)."""

from __future__ import annotations

import asyncio
import uuid
from enum import Flag, auto
from typing import ClassVar

import pytest

from siros_verifier import ble, ble_peripheral


class _FakeProps(Flag):
    """A real `Flag` enum (not plain strings) - matches bless's own
    `GATTCharacteristicProperties`/`GATTDescriptorProperties` shape, since
    ble_peripheral.py combines flags with `|` (e.g. `notify | write_without_response`)."""

    read = auto()
    write_without_response = auto()
    notify = auto()


class _FakeDescriptorProps(Flag):
    read = auto()
    write = auto()


class _FakePerms(Flag):
    readable = auto()
    writeable = auto()


class _FakeCharacteristic:
    def __init__(self, char_uuid, value):
        self.uuid = char_uuid
        self.value = value
        self.descriptors: dict[str, bytearray] = {}


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

    async def add_new_descriptor(self, service_uuid, char_uuid, desc_uuid, properties, value, permissions):
        self.characteristics[char_uuid].descriptors[desc_uuid] = value

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
    monkeypatch.setattr(
        ble_peripheral, "_require_bless", lambda: (FakeBlessServer, _FakeProps, _FakePerms, _FakeDescriptorProps)
    )


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


def test_exchange_registers_cccd_on_both_notify_characteristics():
    """A real central (BleCentralClient.kt) subscribes to STATE and
    SERVER2CLIENT via their CCCD before ever writing STATE_START - without
    one, a real GATT client has no standard descriptor to write to and
    stalls forever (see ble_peripheral.CCCD_UUID's doc comment)."""

    async def run():
        task = asyncio.create_task(
            ble_peripheral.exchange(uuid.uuid4(), b"\x05" * 40, b"se", advertise_timeout=5.0, response_timeout=5.0)
        )
        await asyncio.sleep(0)
        server = FakeBlessServer.instances[-1]
        for char_uuid in (ble_peripheral.STATE_UUID, ble_peripheral.SERVER2CLIENT_UUID):
            assert ble_peripheral.CCCD_UUID in server.characteristics[char_uuid].descriptors
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())


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
