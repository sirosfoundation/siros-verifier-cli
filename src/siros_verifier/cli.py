"""Commandline entrypoint: `siros-verify {read,engagement}`."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec

from siros_verifier import ble, ble_peripheral, crypto, display, engagement, mdoc, qr
from siros_verifier.engagement import DeviceEngagement, UnsupportedEngagementError

TRUST_BANNER = (
    "This tool cryptographically verifies IssuerAuth/DeviceAuth signatures, MACs, and\n"
    "digests against the key/certificate presented in the message itself. It does NOT\n"
    "evaluate trust: certificate chains are never validated against an IACA root, and\n"
    "revocation is never checked. A VALID result means \"internally consistent\", not\n"
    "\"trustworthy\" - do not make trust decisions based on this output."
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
    if getattr(args, "qr_camera", False):
        return qr.scan_camera(
            timeout=args.qr_camera_timeout,
            camera_index=args.camera_index,
            log=lambda msg: print(msg, file=sys.stderr),
        )
    if args.qr_image:
        return engagement.read_qr_image(args.qr_image)
    if args.mdoc_uri:
        return args.mdoc_uri
    raise SystemExit("error: provide a `mdoc:...` URI, --qr-image, or --qr-camera")


def _resolve_handover(args: argparse.Namespace) -> list | None:
    handover_select: bytes | None = None
    if args.nfc_handover_hex:
        handover_select = bytes.fromhex(args.nfc_handover_hex)
    elif args.nfc_handover_file:
        handover_select = Path(args.nfc_handover_file).read_bytes()
    if handover_select is None:
        return None
    return [handover_select, None]  # NFCHandover, static handover => Request message is null


def _resolve_mode(mode: str, de: DeviceEngagement) -> bool:
    """Returns True to use mdoc peripheral server mode (this tool connects
    as a GATT central, via `ble.exchange`), False to use mdoc central client
    mode (this tool advertises as a GATT peripheral, via
    `ble_peripheral.exchange`).

    `mode='auto'` (the default) prefers peripheral server mode whenever the
    engagement offers it - matching most real readers, and this tool's own
    original behavior before `--mode` existed. An engagement that offers
    BOTH modes (as siros-sdk-kotlin/swift's sample apps always do) can never
    have its central-client-mode role exercised under 'auto', since
    peripheral server mode always wins - `--mode central` overrides that
    preference to specifically test the mdoc's central-client-mode GATT
    client role instead.
    """
    if mode == "peripheral":
        if not de.supports_peripheral_server_mode:
            raise SystemExit("error: --mode peripheral requested but this engagement doesn't offer mdoc peripheral server mode")
        return True
    if mode == "central":
        if de.central_client_uuid is None:
            raise SystemExit("error: --mode central requested but this engagement doesn't offer mdoc central client mode")
        return False
    return de.supports_peripheral_server_mode


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
            "\nNOTE: this engagement only offers mdoc central client mode - this tool "
            "will advertise as a BLE peripheral and wait for the mdoc to connect "
            "(requires the 'peripheral' extra; UNVERIFIED ON REAL HARDWARE - see README).",
            file=sys.stderr,
        )


async def run_read(args: argparse.Namespace) -> int:
    uri = _resolve_engagement_uri(args)
    de = engagement.parse_mdoc_uri(uri)
    print_engagement(de)
    _dump_cbor(args.dump_cbor, "engagement.cbor", de.raw_bytes)

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

    use_peripheral_mode = _resolve_mode(args.mode, de)

    log = (lambda msg: print(msg)) if args.verbose else (lambda _msg: None)
    print()
    try:
        if use_peripheral_mode:
            assert de.peripheral_server_uuid is not None  # guaranteed by _resolve_mode
            result = await ble.exchange(
                de.peripheral_server_uuid,
                session_establishment_bytes,
                scan_timeout=args.scan_timeout,
                response_timeout=args.response_timeout,
                log=log,
            )
        else:
            assert de.central_client_uuid is not None  # parse() rejects engagements offering neither UUID
            result = await ble_peripheral.exchange(
                de.central_client_uuid,
                de.e_device_key_bytes,
                session_establishment_bytes,
                advertise_timeout=args.advertise_timeout,
                response_timeout=args.response_timeout,
                log=log,
            )
    except (ble.DeviceNotFoundError, asyncio.TimeoutError, ImportError) as exc:
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
    for doc in response.documents:
        doc.device_auth_valid = mdoc.verify_device_auth(doc, session_transcript, e_reader_priv)

    if args.json:
        print(display.to_json(response))
    else:
        print_device_response(response)
    return 0 if response.status == 0 else 1


def _verdict(value: bool | None, true_word: str = "VALID", false_word: str = "INVALID") -> str:
    if value is None:
        return "NOT VERIFIED (unsupported algorithm or missing key/cert)"
    return true_word if value else false_word


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
                digest_note = f" [digest {_verdict(element.digest_valid, 'OK', 'MISMATCH')}]" if element.digest_id is not None else ""
                print(f"    {element.identifier} = {display.format_value(element.value)}{digest_note}")

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
            print(f"  issuerAuth: alg={ia.alg_name} signature={_verdict(ia.signature_valid)}")
            for cert in ia.certificates:
                print(f"    certificate: subject={cert.subject}")
                print(f"                 issuer={cert.issuer} serial={cert.serial_number:x}")
                print(f"                 validity={cert.not_before} .. {cert.not_after} [chain/trust NOT evaluated]")
            if ia.mso:
                mso = ia.mso
                print(f"  MSO: version={mso.version} digestAlgorithm={mso.digest_algorithm} docType={mso.doc_type}")
                signed = mso.validity_info.get("signed")
                valid_from = mso.validity_info.get("validFrom")
                valid_until = mso.validity_info.get("validUntil")
                print(f"       signed={signed} validFrom={valid_from} validUntil={valid_until}")

        if doc.device_auth_type:
            print(f"  deviceAuth: {doc.device_auth_type} {_verdict(doc.device_auth_valid)}")


def cmd_qr_scan(args: argparse.Namespace) -> int:
    try:
        text = qr.scan_camera(
            timeout=args.timeout,
            camera_index=args.camera_index,
            log=lambda msg: print(msg, file=sys.stderr),
        )
    except (ImportError, RuntimeError, qr.QrNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(text)
    return 0


def cmd_qr_show(args: argparse.Namespace) -> int:
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8").strip()
    elif args.text:
        text = args.text
    else:
        text = sys.stdin.read().strip()
    try:
        path = qr.show_in_browser(text, title=args.title)
    except ImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Opened {path} in a browser tab", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siros-verify",
        description=(
            "Commandline ISO/IEC 18013-5 BLE proximity verifier for debugging mdoc "
            "device retrieval. Signatures/MACs/digests are verified against the "
            "presented key; trust evaluation (chain/IACA/revocation) is out of scope."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_engagement_source_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("mdoc_uri", nargs="?", help="The 'mdoc:...' URI encoded in the engagement QR code")
        p.add_argument("--qr-image", help="Read the mdoc: URI from a QR code image file (requires the 'qr' extra)")
        p.add_argument(
            "--qr-camera",
            action="store_true",
            help="Scan the mdoc: URI with a webcam instead (requires the 'camera' extra)",
        )
        p.add_argument(
            "--camera-index",
            type=int,
            default=None,
            help="Pin --qr-camera to one camera device index (default: try every detected camera)",
        )
        p.add_argument("--qr-camera-timeout", type=float, default=30.0, help="Seconds to wait for --qr-camera")

    read_parser = subparsers.add_parser("read", help="Perform a full BLE device retrieval and display the result")
    add_engagement_source_args(read_parser)
    read_parser.add_argument(
        "--request",
        action="append",
        metavar="DOCTYPE:NAMESPACE:CLAIM,CLAIM",
        help=f"Requested document/namespace/claims, repeatable (default: {DEFAULT_REQUESTS[0]})",
    )
    read_parser.add_argument(
        "--mode",
        choices=["auto", "peripheral", "central"],
        default="auto",
        help=(
            "Which BLE retrieval mode to use when the engagement offers both mdoc peripheral "
            "server mode ('peripheral') and mdoc central client mode ('central') - default 'auto' "
            "prefers peripheral server mode if offered. An engagement offering both modes can never "
            "have its central-client-mode role exercised under 'auto'; pass 'central' to specifically "
            "test that role instead (requires the 'peripheral' extra)."
        ),
    )
    read_parser.add_argument("--nfc-handover-hex", help="Hex-encoded Handover Select NDEF message (NFC static handover)")
    read_parser.add_argument("--nfc-handover-file", help="File containing the raw Handover Select NDEF message")
    read_parser.add_argument("--scan-timeout", type=float, default=10.0, help="mdoc peripheral server mode: seconds to scan for the mdoc")
    read_parser.add_argument(
        "--advertise-timeout",
        type=float,
        default=30.0,
        help="mdoc central client mode: seconds to advertise while waiting for the mdoc to connect (requires the 'peripheral' extra)",
    )
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

    qr_parser = subparsers.add_parser("qr", help="Webcam QR capture / browser QR display convenience helpers")
    qr_subparsers = qr_parser.add_subparsers(dest="qr_command", required=True)

    scan_parser = qr_subparsers.add_parser("scan", help="Scan a QR code with a webcam and print the decoded text")
    scan_parser.add_argument(
        "--camera-index", type=int, default=None, help="Pin to one camera device index (default: try all)"
    )
    scan_parser.add_argument("--timeout", type=float, default=30.0)
    scan_parser.set_defaults(handler=cmd_qr_scan)

    show_parser = qr_subparsers.add_parser("show", help="Display text as a QR code in a browser tab")
    show_parser.add_argument("text", nargs="?", help="Text to encode (reads stdin if omitted)")
    show_parser.add_argument("--file", help="Read the text to encode from a file instead of the positional arg")
    show_parser.add_argument("--title", default="siros-verify")
    show_parser.set_defaults(handler=cmd_qr_show)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "read":
        print(TRUST_BANNER, file=sys.stderr)
    sys.exit(args.handler(args))
