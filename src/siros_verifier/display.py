"""Human-readable and JSON-safe rendering of decoded mdoc structures.

Kept separate from mdoc.py so the parsing layer stays free of presentation
concerns - it just returns dataclasses/plain CBOR values.
"""

from __future__ import annotations

import dataclasses
import datetime
import json

import cbor2

_BINARY_PREVIEW_LEN = 32

# Magic bytes for image formats mdocs commonly embed (e.g. the "portrait" element).
_IMAGE_SIGNATURES = {
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
}


def _detect_image_kind(data: bytes) -> str | None:
    for sig, kind in _IMAGE_SIGNATURES.items():
        if data.startswith(sig):
            return kind
    return None


def format_value(value: object) -> str:
    """One-line human-readable rendering of a decoded CBOR/mdoc value."""
    if isinstance(value, bytes):
        kind = _detect_image_kind(value)
        if kind:
            return f"<{kind} image, {len(value)} bytes>"
        preview = value[:_BINARY_PREVIEW_LEN].hex()
        suffix = "..." if len(value) > _BINARY_PREVIEW_LEN else ""
        return f"h'{preview}{suffix}' ({len(value)} bytes)"
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    if isinstance(value, cbor2.CBORTag):
        return f"#6.{value.tag}({format_value(value.value)})"
    if isinstance(value, dict):
        inner = ", ".join(f"{k}: {format_value(v)}" for k, v in value.items())
        return "{" + inner + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(format_value(v) for v in value) + "]"
    return repr(value)


def to_jsonable(value: object) -> object:
    """Recursively convert decoded values (dataclasses, CBOR tags, bytes,
    dates, ...) into something `json.dumps` can serialize."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    if isinstance(value, cbor2.CBORTag):
        return {"tag": value.tag, "value": to_jsonable(value.value)}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    return value


def to_json(value: object, indent: int = 2) -> str:
    return json.dumps(to_jsonable(value), indent=indent, ensure_ascii=False)


class TreePrinter:
    """Minimal indented tree printer for the `read`/`engagement decode` output."""

    def __init__(self, out) -> None:
        self._out = out

    def line(self, depth: int, text: str) -> None:
        self._out.write(("  " * depth) + text + "\n")
