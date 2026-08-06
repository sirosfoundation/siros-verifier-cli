"""BLE GATT transport for mdoc central-client mode (reader-as-peripheral) -
ISO/IEC 18013-5 §8.3.3.1.1.3, §11.1.3.1, Table 6.

The READER acts as the GATT peripheral/server here - the mirror image of
`ble.py`: it advertises `centralClientModeUuid` as its own service UUID, and
the mdoc connects as GATT central/client. Framing/chunking and all session
crypto are unchanged from peripheral-server mode - `ble.chunk_message`,
`ble.Reassembler`, `ble.ExchangeResult`, and the STATE_START/STATE_END byte
values are reused as-is; only the transport role is different.

Uses `bless` (github.com/kevincar/bless), bleak's cross-platform GATT-server
sibling, since bleak itself is central/client-only on every platform. `bless`
0.3.0 has only ONE read/write callback for the whole server (set via the
`read_request_func`/`write_request_func` properties, invoked as
`func(characteristic)` / `func(characteristic, value)`) rather than
per-characteristic callbacks, so dispatch by `characteristic.uuid` below.

UNVERIFIED ON REAL HARDWARE beyond the mocked unit tests: this and
siros-sdk-kotlin's BleCentralClient.kt (the mdoc-as-GATT-client counterpart)
are two currently-untested-against-each-other halves of the same handshake.
Test against a real mdoc central-client-mode implementation (or
BleCentralClient.kt on a real Android device) before relying on this.
"""

from __future__ import annotations

import asyncio
import uuid

from siros_verifier import ble, crypto

# ISO 18013-5 Table 6 ("mdoc reader service" - present when the READER is the GATT server).
STATE_UUID = "00000005-a123-48ce-896b-4c76973373e6"
CLIENT2SERVER_UUID = "00000006-a123-48ce-896b-4c76973373e6"
SERVER2CLIENT_UUID = "00000007-a123-48ce-896b-4c76973373e6"
IDENT_UUID = "00000008-a123-48ce-896b-4c76973373e6"

# Client Characteristic Configuration Descriptor (Bluetooth SIG, 0x2902) - the
# standard descriptor a GATT client writes to subscribe to a notify/indicate
# characteristic. `bless` (as of 0.3.0) never adds this automatically for a
# characteristic registered with `notify` properties - confirmed via a real
# Android central (`BluetoothGattCharacteristic.getDescriptors()` came back
# empty for STATE/SERVER2CLIENT after real GATT service discovery), which
# left `BleCentralClient.kt`'s (correct, spec-compliant) CCCD write with
# nothing to write to, silently stalling the whole handshake before
# STATE_START. Must be added explicitly per notify characteristic.
CCCD_UUID = "00002902-0000-1000-8000-00805f9b34fb"

# bless does not expose a stable, cross-backend way to read the negotiated
# ATT MTU per connected central as of 0.3.x - conservatively chunk at the
# BLE 4.0 default MTU (23) minus the 3-byte ATT header. Real adapters
# typically negotiate higher, so this only means more (still correct)
# chunks, never a framing error.
PERIPHERAL_CHUNK_SIZE = ble.MIN_CHUNK_SIZE


def _require_bless():
    try:
        from bless import (
            BlessServer,
            GATTAttributePermissions,
            GATTCharacteristicProperties,
            GATTDescriptorProperties,
        )
    except ImportError as exc:
        raise ImportError(
            "mdoc central client mode requires the 'peripheral' extra: "
            "pip install 'siros-verifier-cli[peripheral]' (Linux/BlueZ is the tested backend)"
        ) from exc
    return BlessServer, GATTCharacteristicProperties, GATTAttributePermissions, GATTDescriptorProperties


async def exchange(
    central_client_uuid: uuid.UUID,
    e_device_key_bytes: bytes,
    session_establishment_bytes: bytes,
    advertise_timeout: float,
    response_timeout: float,
    log=lambda _: None,
) -> ble.ExchangeResult:
    """Advertise as a BLE peripheral offering `central_client_uuid`, wait for
    the mdoc to connect and write STATE_START, notify SessionEstablishment,
    then collect and return the raw (still session-encrypted) SessionData
    response bytes."""
    BlessServer, Props, Perms, GATTDescriptorProperties = _require_bless()

    loop = asyncio.get_running_loop()
    start_future: asyncio.Future[None] = loop.create_future()
    response_future: asyncio.Future[bytes] = loop.create_future()
    reassembler = ble.Reassembler()

    def on_read(characteristic):
        return characteristic.value

    def on_write(characteristic, value):
        characteristic.value = value
        if characteristic.uuid == STATE_UUID:
            if bytes(value) == ble.STATE_START and not start_future.done():
                start_future.set_result(None)
        elif characteristic.uuid == CLIENT2SERVER_UUID:
            message = reassembler.feed(bytes(value))
            if message is not None and not response_future.done():
                response_future.set_result(message)

    server = BlessServer(name="siros-verify", loop=loop)
    server.read_request_func = on_read
    server.write_request_func = on_write

    service_uuid = str(central_client_uuid)
    await server.add_new_service(service_uuid)

    await server.add_new_characteristic(
        service_uuid, IDENT_UUID, Props.read, bytearray(crypto.compute_ident(e_device_key_bytes)), Perms.readable
    )
    # State is bidirectional here too, mirroring peripheral-server-mode's own
    # State characteristic (notify + write-without-response) - the mdoc
    # (BleCentralClient.kt) subscribes to it via CCCD before ever writing
    # STATE_START, so `notify` must be set even though this side never
    # actually notifies on it.
    await server.add_new_characteristic(
        service_uuid, STATE_UUID, Props.notify | Props.write_without_response, None, Perms.writeable
    )
    await server.add_new_characteristic(
        service_uuid, CLIENT2SERVER_UUID, Props.write_without_response, None, Perms.writeable
    )
    await server.add_new_characteristic(service_uuid, SERVER2CLIENT_UUID, Props.notify, None, Perms.readable)

    # bless doesn't add a CCCD (0x2902) automatically for notify/indicate
    # characteristics (see CCCD_UUID's doc comment) - without one, a real
    # central has no standard descriptor to write to subscribe, and stalls
    # forever before ever writing STATE_START. Read+write, matching the
    # Bluetooth SIG's own CCCD definition (a client reads it to see current
    # subscription state, writes it to change subscription state).
    await server.add_new_descriptor(
        service_uuid, STATE_UUID, CCCD_UUID, GATTDescriptorProperties.read | GATTDescriptorProperties.write,
        bytearray(2), Perms.readable | Perms.writeable,
    )
    await server.add_new_descriptor(
        service_uuid, SERVER2CLIENT_UUID, CCCD_UUID, GATTDescriptorProperties.read | GATTDescriptorProperties.write,
        bytearray(2), Perms.readable | Perms.writeable,
    )

    log(f"Advertising service {central_client_uuid} ...")
    await server.start()
    try:
        log("Waiting for the mdoc to connect and write STATE_START...")
        try:
            await asyncio.wait_for(start_future, timeout=advertise_timeout)
        except asyncio.TimeoutError as exc:
            raise ble.DeviceNotFoundError(
                f"no mdoc wrote STATE_START within {advertise_timeout}s - "
                "is the wallet scanning for mdoc central client mode?"
            ) from exc

        log(
            f"Sending SessionEstablishment ({len(session_establishment_bytes)} bytes, "
            f"{PERIPHERAL_CHUNK_SIZE}-byte chunks)..."
        )
        server2client = server.get_characteristic(SERVER2CLIENT_UUID)
        for chunk in ble.chunk_message(session_establishment_bytes, PERIPHERAL_CHUNK_SIZE):
            server2client.value = bytearray(chunk)
            server.update_value(service_uuid, SERVER2CLIENT_UUID)

        log("Waiting for the mdoc's SessionData response...")
        session_data_bytes = await asyncio.wait_for(response_future, timeout=response_timeout)
    finally:
        await server.stop()

    return ble.ExchangeResult(
        session_data_bytes=session_data_bytes,
        negotiated_mtu=PERIPHERAL_CHUNK_SIZE + 3,
        chunk_size=PERIPHERAL_CHUNK_SIZE,
        device_address="(not exposed by bless in peripheral mode)",
    )
