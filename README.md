# siros-verifier-cli

A commandline **ISO/IEC 18013-5 BLE proximity verifier**, for debugging mdoc
device retrieval from the terminal: drives a full device-retrieval
transaction with nothing but the host machine's own Bluetooth adapter - no
phone, Waydroid, Flutter, or reader app required on this side.

This is a debugging and protocol-conformance tool, not a conformant mdoc
reader application. **Trust evaluation is explicitly out of scope**:
IssuerAuth signatures, certificate chains, and DeviceAuth are decoded and
displayed, but never cryptographically verified and never checked against a
trust anchor. Every credential and claim this tool prints is **UNVERIFIED**
input from the peer - don't make trust decisions based on its output.

Compare with [siros-verifier-app](https://github.com/sirosfoundation/siros-verifier-app)
(a native Flutter verifier with the same protocol core, for on-device use) -
this tool targets the terminal: scripting, CI, and inspecting the raw wire
protocol (CBOR dumps, COSE headers, MSO fields) that a phone UI hides.

## How it works

```
mdoc (wallet, GATT peripheral)         siros-verify (GATT central)
────────────────────────────           ───────────────────────────
Display QR (mdoc:…)     ─────────────▶  Decode DeviceEngagement
                        ◀──── BLE ────  Scan for peripheral-server UUID, connect
                        ◀─────────────  Send SessionEstablishment (ECDH + AES-GCM)
Return SessionData       ─────────────▶  Decrypt & display DeviceResponse
```

1. **Engagement** - decode the `mdoc:` URI (or NFC static handover payload) into a `DeviceEngagement`
2. **Key agreement** - generate an ephemeral P-256 key pair, ECDH with the mdoc's `EDeviceKey`
3. **Session keys** - derive `SKReader`/`SKDevice` via HKDF-SHA256 over the `SessionTranscript`
4. **BLE transport** - scan for the peripheral-server-mode service UUID, connect as GATT central
5. **Request** - encrypt a `DeviceRequest` (AES-256-GCM) for one or more docType/namespace/claims
6. **Response** - decrypt the `DeviceResponse`, decode `IssuerAuth` (COSE_Sign1) and the MSO, display everything

Only **mdoc peripheral server mode** (§8.3.3.1.1.2) is supported - i.e. the
mdoc acts as the BLE GATT peripheral and this tool connects as central. An
engagement that only offers **mdoc central client mode** (this tool would
have to advertise as a BLE peripheral and wait for the mdoc to connect) is
detected and reported, not silently mishandled.

## Install

```bash
pip install -e .
# or, for reading engagement QR codes straight from an image file:
pip install -e ".[qr]"
```

Requires Python ≥3.10 and a Bluetooth adapter on the host.

## Usage

Open a wallet's proximity-engagement screen (QR code + BLE advertising), get
the `mdoc:...` URI onto this machine (scan it, or decode a screenshot with
`zbarimg`, or pass `--qr-image`), then:

```bash
siros-verify read 'mdoc:AAAA...' \
    --request org.iso.18013.5.1.mDL:org.iso.18013.5.1:given_name,family_name
```

Request multiple documents/namespaces by repeating `--request`:

```bash
siros-verify read 'mdoc:AAAA...' \
    --request org.iso.18013.5.1.mDL:org.iso.18013.5.1:given_name,family_name,portrait \
    --request org.iso.18013.5.1.mDL:org.iso.18013.5.1.aamva:DHS_compliance
```

Other useful flags:

- `--json` - print the decoded `DeviceResponse` as JSON instead of text
- `--dump-cbor DIR` - write the raw CBOR of every protocol message (engagement, request, session establishment, session data, response) to `DIR`, for offline analysis
- `--qr-image screenshot.png` - decode the engagement URI from a QR image (requires the `qr` extra)
- `--nfc-handover-hex HEX` / `--nfc-handover-file FILE` - if engagement happened via NFC static handover instead of QR
- `-v` - log BLE transport progress (scan, connect, MTU, chunking)

Inspect a `DeviceEngagement` offline, without connecting to anything:

```bash
siros-verify engagement decode 'mdoc:AAAA...'
```

## What gets decoded (and what doesn't)

- ✅ DeviceEngagement, DeviceRequest/DeviceResponse, SessionEstablishment/SessionData
- ✅ IssuerAuth (COSE_Sign1): algorithm, x5chain certificates, embedded MobileSecurityObject (digestAlgorithm, valueDigests, deviceKeyInfo, validityInfo)
- ✅ DeviceAuth presence (deviceSignature/deviceMac) and deviceSigned namespaces
- ✅ Per-document and per-element error codes (Table 8/9/15/20 of ISO 18013-5)
- ❌ Signature verification of IssuerAuth or DeviceAuth
- ❌ Certificate chain / IACA trust anchor validation
- ❌ mdoc central client mode (reader-as-peripheral) - detected, not driven

## Roadmap

- SD-JWT VC credential support (currently mdoc/CBOR only)

## Development

```bash
pip install -e ".[dev]"
ruff check .
mypy src
pytest
```

## License

BSD 2-Clause - see [LICENSE](LICENSE).
