# Physical interoperability evidence

Date: 2026-11-05 (UTC)

This page records manual interoperability tests between the Python CLI and the native Android holder. These are development evidence, not a conformance certification or a production trust decision.

## Holder and request

- Device: Pixel 10a, USB serial `5B261JEA308385`, unlocked with Bluetooth enabled.
- Application: `org.siros.sdk.sample` 0.21.4 debug, APK SHA-256 `bc72329b032bc26f67dfd3d3ed8cbe90d784946c907186348c6bb3ce9ef4b4eb`.
- Wallet backend: `https://sirosid-gdc-wallet-proxy.fly.dev`, tenant `default`, with the existing wallet restored.
- Credential: one `org.iso.18013.5.1.mDL` issued by the GDC E2E test issuer.
- Request: only `given_name` and `family_name` in `org.iso.18013.5.1`, all with `intentToRetain=false`.
- Engagement: a fresh QR screenshot for each run, one mDL and one request/response round trip per run.
- Consent: the wallet displayed the two requested claims and the presentation was explicitly approved with **Share**.

The initial BLE runs used the `fix/mdoc-intent-retention` reader branch. The go-trust runs used the AuthZEN implementation and the local `go-trust-allow` development fixture.

## BLE retrieval roles

| Command | Holder role | CLI role | Result |
| --- | --- | --- | --- |
| `read --qr-image pixel-proximity-peripheral.png --mode peripheral --scan-timeout 20 --response-timeout 30 -v` | GATT peripheral/server | GATT central/client | Exit 0; DeviceResponse status 0; IssuerAuth ES256 valid; both digests OK; DeviceAuth valid. |
| `read --qr-image pixel-proximity-central.png --mode central --advertise-timeout 30 --response-timeout 30 -v` | GATT central/client | GATT peripheral/server via `bless` | Exit 0; DeviceResponse status 0; IssuerAuth ES256 valid; both digests OK; DeviceAuth valid. |

The first run negotiated the default MTU 23 and transferred the 245-byte SessionEstablishment in 20-byte chunks. The second advertised the engagement's central-client UUID, received the holder connection and `STATE_START`, sent SessionEstablishment in 20-byte chunks, and received SessionData.

These runs establish real QR/BLE radio and mdoc protocol interoperability plus internal cryptographic consistency. The two initial runs did not perform IACA chain/revocation validation or go-trust authorization, so they are not trusted-claim evidence.

## Live go-trust gate

The local development PDP accepted `POST http://127.0.0.1:9095/evaluation`; the incorrect `/v1/evaluate` route returned 404.

- After an otherwise valid Pixel presentation, `POST http://127.0.0.1:9095/v1/evaluate` returned HTTP 404. The CLI exited 1 and printed no claims.
- A fresh presentation using `POST http://127.0.0.1:9095/evaluation` received an explicit permit for one document. The CLI printed `go-trust: explicit permit for 1 document(s)`, exited 0, and displayed the two requested claims only after the permit.
- The permit run was repeated after the ordered-DER and `aiohttp` hardening at commit `965e758`; it again exited 0 and released claims only after the permit.

This proves the live fail-closed network gate against the real go-trust API. The allow-all development fixture proves gating only; it does not establish production issuer trust. Subsequent strict and AuthZEN revisions added the structural, cryptographic, rendering, timeout, and disclosure-gate regressions recorded in their PR test suites.

## NFC boundary

NFC static handover was active on the holder but was not exercised. The Python CLI currently requires externally supplied Handover Select bytes and lacks NFC NDEF/APDU acquisition. Physical NFC evidence still requires a second NFC-capable device or a supported host NFC reader.

## Android 16 KB observation

Android displayed a debug-app 16 KB page-size compatibility warning. The app ran after dismissing it. Inspection found the SIROS-owned arm64/x86_64 native libraries, including `libnymauth_native.so` and `libsiros_verifier_core_ffi.so`, structurally compatible. The complete sample app was not yet clean because third-party JNA, zstd-jni, and some AndroidX binaries failed checks. Final packaging still requires dependency upgrades and full APK/AAB structural and runtime validation.
