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
from bleak.exc import BleakError

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
            # A malformed request commonly makes the mdoc disconnect before
            # any response arrives - that's the expected/correct reaction,
            # not a transport failure, so a stale-connection error here must
            # not clobber the real TimeoutError/DeviceNotFoundError the
            # caller is already handling.
            try:
                await client.write_gatt_char(STATE_UUID, STATE_END, response=False)
            except BleakError as exc:
                log(f"(couldn't send STATE_END, mdoc likely already disconnected: {exc})")
        negotiated_mtu = client.mtu_size

    return ExchangeResult(
        session_data_bytes=session_data_bytes,
        negotiated_mtu=negotiated_mtu,
        chunk_size=chunk_size,
        device_address=device.address,
    )


@dataclass
class ChunkDropResult:
    device_address: str
    chunks_sent: int
    chunks_total: int


async def exchange_dropping_tail(
    peripheral_uuid: uuid.UUID,
    session_establishment_bytes: bytes,
    scan_timeout: float,
    keep_fraction: float,
    log=lambda _: None,
) -> ChunkDropResult:
    """Connect, start a real SessionEstablishment transfer, then disconnect
    partway through instead of sending the final (0x00-prefixed) chunk -
    `keep_fraction` of the chunks are sent, rounded down, and always at
    least one short of the full set. Used by the `fuzz drop-mid-chunk`
    scenario: the mdoc's own reassembler is left holding a partial message
    it will never complete, checking that its own timeout/abort path
    recovers instead of leaving the GATT connection open indefinitely."""
    device = await scan_for_peripheral(peripheral_uuid, scan_timeout, log)
    log(f"Found {device.address}, connecting...")
    async with BleakClient(device) as client:
        log(f"Connected. Negotiated MTU: {client.mtu_size}")
        await client.start_notify(SERVER2CLIENT_UUID, lambda *_args: None)
        await client.write_gatt_char(STATE_UUID, STATE_START, response=False)
        chunk_size = negotiate_chunk_size(client.mtu_size)
        chunks = chunk_message(session_establishment_bytes, chunk_size)
        keep = max(1, min(len(chunks) - 1, int(len(chunks) * keep_fraction))) if len(chunks) > 1 else len(chunks)
        log(f"Sending {keep}/{len(chunks)} chunks, then disconnecting without completing the transfer...")
        for chunk in chunks[:keep]:
            await client.write_gatt_char(CLIENT2SERVER_UUID, chunk, response=False)
        # Deliberately no final chunk, no STATE_END - just fall out of
        # `async with`, which disconnects without waiting for a response.
    return ChunkDropResult(device_address=device.address, chunks_sent=keep, chunks_total=len(chunks))


async def connect_and_disconnect(
    peripheral_uuid: uuid.UUID,
    scan_timeout: float,
    write_state_start: bool,
    log=lambda _: None,
) -> str:
    """Connect as central, optionally write STATE_START, then disconnect
    immediately - no DeviceRequest is ever sent. Exercises the mdoc's
    handling of a reader that connects and vanishes before doing anything
    useful. Returns the connected device's address."""
    device = await scan_for_peripheral(peripheral_uuid, scan_timeout, log)
    log(f"Found {device.address}, connecting...")
    async with BleakClient(device) as client:
        log(f"Connected. Negotiated MTU: {client.mtu_size}")
        if write_state_start:
            await client.write_gatt_char(STATE_UUID, STATE_START, response=False)
        log("Disconnecting immediately, without sending any request data.")
    return device.address


@dataclass
class ReconnectCycleResult:
    cycle: int
    connect_seconds: float
    error: str | None


async def rapid_reconnect_probe(
    peripheral_uuid: uuid.UUID,
    scan_timeout: float,
    cycles: int,
    delay_seconds: float,
    log=lambda _: None,
) -> list[ReconnectCycleResult]:
    """Connect and immediately disconnect, `cycles` times in a row (with
    `delay_seconds` between attempts) - no DeviceRequest is ever sent.
    Stress-tests the mdoc's own GATT-server re-advertise/teardown path
    under reader churn: a role that doesn't tear down promptly on its own
    failure/disconnect can leave a stale connection blocking the next
    attempt, or fail to re-advertise at all after enough cycles."""
    results: list[ReconnectCycleResult] = []
    for cycle in range(1, cycles + 1):
        start = asyncio.get_running_loop().time()
        error: str | None = None
        try:
            device = await scan_for_peripheral(peripheral_uuid, scan_timeout, log)
            async with BleakClient(device) as client:
                log(f"[{cycle}/{cycles}] connected (MTU {client.mtu_size}), disconnecting immediately")
        except Exception as exc:  # noqa: BLE001 - reporting every failure mode is the point of this probe
            error = f"{type(exc).__name__}: {exc}"
            log(f"[{cycle}/{cycles}] FAILED: {error}")
        elapsed = asyncio.get_running_loop().time() - start
        results.append(ReconnectCycleResult(cycle=cycle, connect_seconds=elapsed, error=error))
        if cycle < cycles and delay_seconds > 0:
            await asyncio.sleep(delay_seconds)
    return results
