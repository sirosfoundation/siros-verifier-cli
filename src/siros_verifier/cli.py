"""Commandline entrypoint: `siros-verify {read,engagement}`."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec

from siros_verifier import ble, crypto, display, engagement, mdoc
from siros_verifier.engagement import DeviceEngagement, UnsupportedEngagementError

TRUST_BANNER = (
    "This tool decodes and displays IssuerAuth/DeviceAuth signatures and certificate\n"
    "chains but does NOT verify them and does NOT evaluate trust. Every credential\n"
    "and claim shown is UNVERIFIED input from the peer - do not make trust decisions\n"
    "based on this output."
)

DEFAULT_REQUESTS = ["org.iso.18013.5.1.mDL:org.iso.18013.5.1:given_name,family_name"]

# ISO 18013-5 Table 20 (SessionData status codes).
SESSION_STATUS_NAMES = {10: "Error: session encryption", 11: "Error: CBOR decoding", 20: "Session termination"}


def parse_requests(specs: list[str]) -> list[mdoc.DocRequest]:
    """Parse repeated `--request DOCTYPE:NAMESPACE:CLAIM,CLAIM,...` flags,
    merging namespaces for repeated doc types into a single DocRequest."""
    namespaces_by_doctype: dict[str, dict[str, list[str]]] = {}
    order: list[str] = []
    for spec in specs:
        parts = spec.split(":", 2)
        if len(parts) != 3:
            raise ValueError(f"--request must be DOCTYPE:NAMESPACE:CLAIM,CLAIM,... , got {spec!r}")
        doc_type, namespace, claims = parts
        claim_list = [c.strip() for c in claims.split(",") if c.strip()]
        if not claim_list:
            raise ValueError(f"--request has no claims: {spec!r}")
        if doc_type not in namespaces_by_doctype:
            namespaces_by_doctype[doc_type] = {}
            order.append(doc_type)
        namespaces_by_doctype[doc_type].setdefault(namespace, []).extend(claim_list)
    return [mdoc.DocRequest(doc_type=dt, namespaces=namespaces_by_doctype[dt]) for dt in order]


def _resolve_engagement_uri(args: argparse.Namespace) -> str:
    if args.qr_image:
        return engagement.read_qr_image(args.qr_image)
    if args.mdoc_uri:
        return args.mdoc_uri
    raise SystemExit("error: provide either a `mdoc:...` URI or --qr-image")


def _resolve_handover(args: argparse.Namespace) -> list | None:
    handover_select: bytes | None = None
    if args.nfc_handover_hex:
        handover_select = bytes.fromhex(args.nfc_handover_hex)
    elif args.nfc_handover_file:
        handover_select = Path(args.nfc_handover_file).read_bytes()
    if handover_select is None:
        return None
    return [handover_select, None]  # NFCHandover, static handover => Request message is null


def _dump_cbor(dump_dir: str | None, name: str, data: bytes) -> None:
    if not dump_dir:
        return
    out_dir = Path(dump_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / name).write_bytes(data)


def cmd_engagement_decode(args: argparse.Namespace) -> int:
    uri = _resolve_engagement_uri(args)
    try:
        de = engagement.parse_mdoc_uri(uri)
    except UnsupportedEngagementError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print_engagement(de)
    return 0


def print_engagement(de: DeviceEngagement) -> None:
    print(f"version: {de.version}")
    print(f"cipher suite: {de.cipher_suite}")
    numbers = de.e_device_key_pub.public_numbers()
    print(f"EDeviceKey.Pub: x={numbers.x:064x} y={numbers.y:064x}")
    print(f"peripheral server mode UUID: {de.peripheral_server_uuid or '(not offered)'}")
    print(f"central client mode UUID:    {de.central_client_uuid or '(not offered)'}")
    if not de.supports_peripheral_server_mode:
        print(
            "\nNOTE: this engagement only offers mdoc central client mode (the mdoc "
            "connects to a reader advertising as BLE peripheral). This tool only "
            "drives mdoc peripheral server mode (reader as BLE central) - see README.",
            file=sys.stderr,
        )


async def run_read(args: argparse.Namespace) -> int:
    uri = _resolve_engagement_uri(args)
    de = engagement.parse_mdoc_uri(uri)
    print_engagement(de)
    _dump_cbor(args.dump_cbor, "engagement.cbor", de.raw_bytes)

    if not de.supports_peripheral_server_mode:
        print(
            "\nerror: engagement does not offer mdoc peripheral server mode "
            "(no key 10 in BleOptions) - this tool cannot drive central client mode",
            file=sys.stderr,
        )
        return 1
    peripheral_uuid = de.peripheral_server_uuid
    assert peripheral_uuid is not None  # guaranteed by supports_peripheral_server_mode above

    e_reader_priv = ec.generate_private_key(ec.SECP256R1())
    e_reader_key_tag = crypto.cose_key_tag(e_reader_priv.public_key())

    handover = _resolve_handover(args)
    session_transcript = crypto.build_session_transcript(de.raw_bytes, e_reader_key_tag, handover)
    zab = e_reader_priv.exchange(ec.ECDH(), de.e_device_key_pub)
    sk_reader, sk_device = crypto.derive_session_keys(zab, session_transcript)

    doc_requests = parse_requests(args.request or DEFAULT_REQUESTS)
    device_request_bytes = mdoc.build_device_request(doc_requests)
    _dump_cbor(args.dump_cbor, "device_request.cbor", device_request_bytes)

    ciphertext = crypto.encrypt_reader_message(sk_reader, 1, device_request_bytes)
    session_establishment_bytes = mdoc.build_session_establishment(e_reader_key_tag, ciphertext)
    _dump_cbor(args.dump_cbor, "session_establishment.cbor", session_establishment_bytes)

    log = (lambda msg: print(msg)) if args.verbose else (lambda _msg: None)
    print()
    try:
        result = await ble.exchange(
            peripheral_uuid,
            session_establishment_bytes,
            scan_timeout=args.scan_timeout,
            response_timeout=args.response_timeout,
            log=log,
        )
    except (ble.DeviceNotFoundError, asyncio.TimeoutError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _dump_cbor(args.dump_cbor, "session_data.cbor", result.session_data_bytes)
    session_data = cbor2.loads(result.session_data_bytes)
    if "data" not in session_data:
        status = session_data.get("status")
        name = SESSION_STATUS_NAMES.get(status, f"unknown({status})")
        print(f"error: mdoc returned SessionData with no data, status={status} ({name})", file=sys.stderr)
        return 1

    plaintext = crypto.decrypt_device_message(sk_device, 1, session_data["data"])
    _dump_cbor(args.dump_cbor, "device_response.cbor", plaintext)
    response = mdoc.parse_device_response(plaintext)

    if args.json:
        print(display.to_json(response))
    else:
        print_device_response(response)
    return 0 if response.status == 0 else 1


def print_device_response(response: mdoc.DeviceResponseResult) -> None:
    print("\n--- DeviceResponse ---")
    print(f"version: {response.version}")
    print(f"status: {response.status} ({response.status_name})")
    for error in response.document_errors:
        for doc_type, code in error.items():
            name = mdoc.ERROR_CODE_NAMES.get(code, "application-specific" if code < 0 else "RFU")
            print(f"document error: {doc_type} -> {code} ({name})")

    for doc in response.documents:
        print(f"\ndocType: {doc.doc_type}")
        for ns, elements in doc.namespaces.items():
            print(f"  namespace {ns}:")
            for element in elements:
                print(f"    {element.identifier} = {display.format_value(element.value)}")

        if doc.device_namespaces:
            print("  deviceSigned nameSpaces:")
            for ns, items in doc.device_namespaces.items():
                print(f"    {ns}:")
                for identifier, value in items.items():
                    print(f"      {identifier} = {display.format_value(value)}")

        for ns, error_items in doc.errors.items():
            for identifier, code in error_items.items():
                name = mdoc.ERROR_CODE_NAMES.get(code, "application-specific" if code < 0 else "RFU")
                print(f"  error: {ns}.{identifier} -> {code} ({name})")

        if doc.issuer_auth:
            ia = doc.issuer_auth
            print(f"  issuerAuth: alg={ia.alg_name} [UNVERIFIED SIGNATURE]")
            for cert in ia.certificates:
                print(f"    certificate: subject={cert.subject}")
                print(f"                 issuer={cert.issuer} serial={cert.serial_number:x}")
                print(f"                 validity={cert.not_before} .. {cert.not_after}")
            if ia.mso:
                mso = ia.mso
                print(f"  MSO: version={mso.version} digestAlgorithm={mso.digest_algorithm} docType={mso.doc_type}")
                signed = mso.validity_info.get("signed")
                valid_from = mso.validity_info.get("validFrom")
                valid_until = mso.validity_info.get("validUntil")
                print(f"       signed={signed} validFrom={valid_from} validUntil={valid_until}")

        if doc.device_auth_type:
            print(f"  deviceAuth: {doc.device_auth_type} [UNVERIFIED]")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siros-verify",
        description=(
            "Commandline ISO/IEC 18013-5 BLE proximity verifier for debugging mdoc "
            "device retrieval. Trust evaluation is out of scope: signatures and "
            "certificate chains are decoded, never verified."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_engagement_source_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("mdoc_uri", nargs="?", help="The 'mdoc:...' URI encoded in the engagement QR code")
        p.add_argument("--qr-image", help="Read the mdoc: URI from a QR code image file (requires the 'qr' extra)")

    read_parser = subparsers.add_parser("read", help="Perform a full BLE device retrieval and display the result")
    add_engagement_source_args(read_parser)
    read_parser.add_argument(
        "--request",
        action="append",
        metavar="DOCTYPE:NAMESPACE:CLAIM,CLAIM",
        help=f"Requested document/namespace/claims, repeatable (default: {DEFAULT_REQUESTS[0]})",
    )
    read_parser.add_argument("--nfc-handover-hex", help="Hex-encoded Handover Select NDEF message (NFC static handover)")
    read_parser.add_argument("--nfc-handover-file", help="File containing the raw Handover Select NDEF message")
    read_parser.add_argument("--scan-timeout", type=float, default=10.0)
    read_parser.add_argument("--response-timeout", type=float, default=15.0)
    read_parser.add_argument("--json", action="store_true", help="Print the DeviceResponse as JSON instead of text")
    read_parser.add_argument("--dump-cbor", metavar="DIR", help="Write raw CBOR of each protocol message to DIR")
    read_parser.add_argument("-v", "--verbose", action="store_true", help="Log BLE transport progress")
    read_parser.set_defaults(handler=lambda args: asyncio.run(run_read(args)))

    engagement_parser = subparsers.add_parser("engagement", help="Inspect a DeviceEngagement without connecting")
    engagement_subparsers = engagement_parser.add_subparsers(dest="engagement_command", required=True)
    decode_parser = engagement_subparsers.add_parser("decode", help="Decode and print a DeviceEngagement")
    add_engagement_source_args(decode_parser)
    decode_parser.set_defaults(handler=cmd_engagement_decode)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "read":
        print(TRUST_BANNER, file=sys.stderr)
    sys.exit(args.handler(args))
