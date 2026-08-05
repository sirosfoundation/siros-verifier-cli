# siros-verifier-cli

[![CI](https://github.com/sirosfoundation/siros-verifier-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-verifier-cli/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sirosfoundation/siros-verifier-cli/actions/workflows/codeql.yml/badge.svg)](https://github.com/sirosfoundation/siros-verifier-cli/actions/workflows/codeql.yml)
[![SonarCloud](https://sonarcloud.io/api/project_badges/measure?project=sirosfoundation_siros-verifier-cli&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=sirosfoundation_siros-verifier-cli)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/siros-verifier-cli/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/siros-verifier-cli)
[![PyPI Python versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](LICENSE)

A commandline **ISO/IEC 18013-5 BLE proximity verifier**, for debugging mdoc
device retrieval from the terminal: drives a full device-retrieval
transaction with nothing but the host machine's own Bluetooth adapter - no
phone, Waydroid, Flutter, or reader app required on this side.

This is a debugging and protocol-conformance tool, not a conformant mdoc
reader application. **Trust evaluation is explicitly out of scope**:
IssuerAuth/DeviceAuth signatures, MACs, and MSO digests are cryptographically
verified against the key/certificate presented in the message itself, but
certificate chains are never validated against an IACA root and revocation is
never checked. A **VALID** result means "internally consistent with the
presented key", never "trustworthy" - don't make trust decisions based on
this tool's output.

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
Return SessionData       ─────────────▶  Decrypt & verify DeviceResponse
```

1. **Engagement** - decode the `mdoc:` URI (or NFC static handover payload) into a `DeviceEngagement`
2. **Key agreement** - generate an ephemeral P-256 key pair, ECDH with the mdoc's `EDeviceKey`
3. **Session keys** - derive `SKReader`/`SKDevice` via HKDF-SHA256 over the `SessionTranscript`
4. **BLE transport** - scan for the peripheral-server-mode service UUID, connect as GATT central
5. **Request** - encrypt a `DeviceRequest` (AES-256-GCM) for one or more docType/namespace/claims
6. **Response** - decrypt the `DeviceResponse`; verify `IssuerAuth` (COSE_Sign1), per-element MSO digests, and `DeviceAuth` (COSE_Sign1/COSE_Mac0); display everything

Only **mdoc peripheral server mode** (§8.3.3.1.1.2) is supported - i.e. the
mdoc acts as the BLE GATT peripheral and this tool connects as central. An
engagement that only offers **mdoc central client mode** (this tool would
have to advertise as a BLE peripheral and wait for the mdoc to connect) is
detected and reported, not silently mishandled.

## Install

```bash
pip install -e .
# or, to read/display engagement QR codes without a phone-to-laptop file transfer:
pip install -e ".[qr]"       # decode a QR image file, or render text as a QR page in a browser
pip install -e ".[camera]"   # scan a QR code live with a webcam
```

Requires Python ≥3.10 and a Bluetooth adapter on the host.

## Usage

Open a wallet's proximity-engagement screen (QR code + BLE advertising), get
the `mdoc:...` URI onto this machine, then:

```bash
siros-verify read 'mdoc:AAAA...' \
    --request org.iso.18013.5.1.mDL:org.iso.18013.5.1:given_name,family_name
```

Getting the URI onto this machine doesn't require a phone screenshot round trip:

```bash
siros-verify read --qr-camera --request ...   # scan the phone's QR with a webcam live
siros-verify read --qr-image screenshot.png    # or decode a QR image file
```

`--qr-camera` probes every camera the OS exposes by default (handy on a
laptop with more than one) - pass `--camera-index N` to pin to one.

Request multiple documents/namespaces by repeating `--request`:

```bash
siros-verify read 'mdoc:AAAA...' \
    --request org.iso.18013.5.1.mDL:org.iso.18013.5.1:given_name,family_name,portrait \
    --request org.iso.18013.5.1.mDL:org.iso.18013.5.1.aamva:DHS_compliance
```

Other useful flags:

- `--json` - print the decoded `DeviceResponse` as JSON instead of text
- `--dump-cbor DIR` - write the raw CBOR of every protocol message (engagement, request, session establishment, session data, response) to `DIR`, for offline analysis
- `--nfc-handover-hex HEX` / `--nfc-handover-file FILE` - if engagement happened via NFC static handover instead of QR
- `-v` - log BLE transport progress (scan, connect, MTU, chunking)

Inspect a `DeviceEngagement` offline, without connecting to anything (also supports `--qr-image`/`--qr-camera`):

```bash
siros-verify engagement decode 'mdoc:AAAA...'
```

### QR convenience helpers

Independent of `read`/`engagement`, two small utilities for moving text
between this machine and a phone without files or messaging apps:

```bash
siros-verify qr scan                       # webcam -> decoded text on stdout
siros-verify qr show 'mdoc:AAAA...'         # text -> QR code opened in a browser tab, for a phone to scan
echo 'some text' | siros-verify qr show     # also reads from stdin
```

## What's verified (and what isn't)

- ✅ DeviceEngagement, DeviceRequest/DeviceResponse, SessionEstablishment/SessionData - decoded
- ✅ IssuerAuth (COSE_Sign1) signature - verified against the x5chain leaf certificate's public key
- ✅ Per-element digests - recomputed and checked against the MSO's `valueDigests`
- ✅ DeviceAuth (`deviceSignature`/`deviceMac`) - verified against the MSO's `deviceKey` (needs the reader's own ephemeral key + SessionTranscript, so this runs after parsing)
- ✅ Per-document and per-element error codes (Table 8/9/15/20 of ISO 18013-5)
- ❌ Certificate chain / IACA trust anchor validation - **not done, ever**
- ❌ Revocation checking - **not done, ever**
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
