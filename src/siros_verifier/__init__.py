"""siros-verifier-cli: a commandline ISO/IEC 18013-5 BLE proximity verifier.

Implements the "mdoc reader" side of a device-retrieval transaction (device
engagement parsing, BLE GATT central-client transport, session crypto,
DeviceRequest/DeviceResponse handling) for debugging wallets and BLE
peripheral implementations.

IssuerAuth/DeviceAuth signatures, MACs, and MSO digests are cryptographically
verified against the key/certificate presented in the message itself. Trust
evaluation (certificate chain validation against an IACA root, revocation,
trust-list lookups) is explicitly out of scope: a "valid" result here means
"internally consistent with the presented key", never "trustworthy". Do not
use this tool's output to make trust decisions.
"""

__version__ = "0.1.0"
