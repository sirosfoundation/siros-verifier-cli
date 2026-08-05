"""siros-verifier-cli: a commandline ISO/IEC 18013-5 BLE proximity verifier.

Implements the "mdoc reader" side of a device-retrieval transaction (device
engagement parsing, BLE GATT central-client transport, session crypto,
DeviceRequest/DeviceResponse handling) for debugging wallets and BLE
peripheral implementations.

Trust evaluation (reader/issuer certificate chain validation, revocation,
trust-list lookups) is explicitly out of scope: IssuerAuth signatures and
certificate chains are decoded and displayed, never verified. Every document
this tool accepts is UNVERIFIED - do not use it to make trust decisions.
"""

__version__ = "0.1.0"
