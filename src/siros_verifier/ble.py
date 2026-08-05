"""BLE GATT transport for mdoc central-client mode - ISO/IEC 18013-5 §8.3.3.1.1.2, §11.1.3.4.

The mdoc acts as the GATT peripheral/server; this tool is the central,
scanning for the peripheral-server-mode service UUID advertised in the
DeviceEngagement, then writing/reading the three fixed characteristics in
Table 5 of the spec. Only this role is implemented - see
`engagement.DeviceEngagement.supports_peripheral_server_mode`.

Chunking/reassembly (pure, no BLE) is kept separate from the bleak-driven
connect/exchange coroutine so the wire framing can be unit tested without
a Bluetooth adapter.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass

from bleak import BleakClient, BleakScanner

# Fixed characteristic UUIDs, ISO/IEC 18013-5 Table 5 ("mdoc service").
STATE_UUID = "00000001-a123-48ce-896b-4c76973373e6"
CLIENT2SERVER_UUID = "00000002-a123-48ce-896b-4c76973373e6"
SERVER2CLIENT_UUID = "00000003-a123-48ce-896b-4c76973373e6"

STATE_START = b"\x01"
STATE_END = b"\x02"

# §11.1.3.4: chunk size must respect both MTU-3 and the Bluetooth Core
# Specification's absolute 512-byte max attribute value length.
MIN_CHUNK_SIZE = 20
MAX_CHUNK_SIZE = 512


class DeviceNotFoundError(RuntimeError):
    pass


def negotiate_chunk_size(mtu_size: int) -> int:
    return min(max(mtu_size - 3, MIN_CHUNK_SIZE), MAX_CHUNK_SIZE)


def chunk_message(message: bytes, max_chunk_size: int) -> list[bytes]:
    """Each part prefixed 0x01 (more) or 0x00 (last). max_chunk_size is the
    TOTAL wire size (prefix + payload) allowed per part."""
    if max_chunk_size <= 1:
        raise ValueError(f"max_chunk_size must allow at least 1 payload byte alongside the prefix, was {max_chunk_size}")
    payload_size = max_chunk_size - 1
    if not message:
        return [b"\x00"]
    chunks = []
    offset = 0
    while offset < len(message):
        end = min(offset + payload_size, len(message))
        is_last = end == len(message)
        chunks.append((b"\x00" if is_last else b"\x01") + message[offset:end])
        offset = end
    return chunks


class Reassembler:
    """Feeds prefixed chunks in; returns the complete message once the
    "last chunk" (0x00) marker arrives, else None."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> bytes | None:
        is_last = chunk[0] == 0x00
        self._buffer.extend(chunk[1:])
        if not is_last:
            return None
        result = bytes(self._buffer)
        self._buffer.clear()
        return result


@dataclass
class ExchangeResult:
    session_data_bytes: bytes
    negotiated_mtu: int
    chunk_size: int
    device_address: str


async def scan_for_peripheral(peripheral_uuid: uuid.UUID, scan_timeout: float, log=lambda _: None):
    log(f"Scanning for service {peripheral_uuid} ...")
    device = await BleakScanner.find_device_by_filter(
        lambda d, adv: str(peripheral_uuid).lower() in [str(u).lower() for u in (adv.service_uuids or [])],
        timeout=scan_timeout,
    )
    if device is None:
        raise DeviceNotFoundError(
            f"no advertising device found for service {peripheral_uuid} within {scan_timeout}s - "
            "is the wallet's proximity-engagement screen open and in range?"
        )
    return device


async def exchange(
    peripheral_uuid: uuid.UUID,
    session_establishment_bytes: bytes,
    scan_timeout: float,
    response_timeout: float,
    log=lambda _: None,
) -> ExchangeResult:
    """Connect as central to the mdoc peripheral, send SessionEstablishment,
    and return the raw (still session-encrypted) SessionData response bytes."""
    device = await scan_for_peripheral(peripheral_uuid, scan_timeout, log)
    log(f"Found {device.address}, connecting...")

    reassembler = Reassembler()
    response_future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def on_server2client(_char, data: bytearray) -> None:
        message = reassembler.feed(bytes(data))
        if message is not None and not response_future.done():
            response_future.set_result(message)

    async with BleakClient(device) as client:
        log(f"Connected. Negotiated MTU: {client.mtu_size}")
        await client.start_notify(SERVER2CLIENT_UUID, on_server2client)
        await client.write_gatt_char(STATE_UUID, STATE_START, response=False)

        chunk_size = negotiate_chunk_size(client.mtu_size)
        log(f"Sending SessionEstablishment ({len(session_establishment_bytes)} bytes, {chunk_size}-byte chunks)...")
        for chunk in chunk_message(session_establishment_bytes, chunk_size):
            await client.write_gatt_char(CLIENT2SERVER_UUID, chunk, response=False)

        log("Waiting for SessionData response...")
        try:
            session_data_bytes = await asyncio.wait_for(response_future, timeout=response_timeout)
        finally:
            await client.write_gatt_char(STATE_UUID, STATE_END, response=False)
        negotiated_mtu = client.mtu_size

    return ExchangeResult(
        session_data_bytes=session_data_bytes,
        negotiated_mtu=negotiated_mtu,
        chunk_size=chunk_size,
        device_address=device.address,
    )
