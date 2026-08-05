"""QR code convenience helpers - not part of ISO 18013-5, just developer-experience
shortcuts for getting a `mdoc:` engagement URI off a phone screen and onto this
machine (webcam capture), and for displaying arbitrary text as a scannable QR
code (browser display) without a phone-to-laptop file transfer step.
"""

from __future__ import annotations

import base64
import io
import tempfile
import time
import webbrowser
from pathlib import Path

_CHROME_CANDIDATES = ("chrome", "google-chrome", "chromium", "chromium-browser")


class QrNotFoundError(RuntimeError):
    pass


def _require_camera_deps():
    try:
        import cv2
        from PIL import Image
        from pyzbar.pyzbar import decode as zbar_decode
    except ImportError as exc:
        raise ImportError(
            "scanning a QR code with the camera requires the 'camera' extra: "
            "pip install 'siros-verifier-cli[camera]'"
        ) from exc
    return cv2, Image, zbar_decode


def scan_camera(
    timeout: float = 30.0,
    camera_index: int | None = None,
    max_probe_index: int = 8,
    log=lambda _msg: None,
) -> str:
    """Decode the first QR code seen within `timeout` seconds.

    If `camera_index` is None (the default), every camera the OS exposes
    (probed up to `max_probe_index`) is polled in round-robin - useful on a
    laptop with more than one camera (built-in + an external/USB webcam)
    where the wallet's QR could be in view of any of them. Pass a specific
    `camera_index` to pin to one camera instead.
    """
    cv2, Image, zbar_decode = _require_camera_deps()

    indices = [camera_index] if camera_index is not None else list(range(max_probe_index + 1))
    captures = []
    for index in indices:
        capture = cv2.VideoCapture(index)
        if capture.isOpened():
            captures.append((index, capture))
        else:
            capture.release()

    if not captures:
        detail = f"camera {camera_index}" if camera_index is not None else "any camera"
        raise RuntimeError(f"could not open {detail}")

    log(f"Scanning camera(s) {[i for i, _c in captures]} for a QR code (timeout {timeout}s)...")
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for index, capture in captures:
                ok, frame = capture.read()
                if not ok:
                    continue
                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                symbols = zbar_decode(Image.fromarray(rgb))
                if symbols:
                    log(f"QR code found on camera {index}")
                    return symbols[0].data.decode("ascii")
    finally:
        for _index, capture in captures:
            capture.release()
    raise QrNotFoundError(f"no QR code seen within {timeout}s")


def _require_display_deps():
    try:
        import qrcode
    except ImportError as exc:
        raise ImportError(
            "displaying a QR code requires the 'qr' extra: pip install 'siros-verifier-cli[qr]'"
        ) from exc
    return qrcode


def render_qr_html(data: str, title: str = "siros-verify") -> str:
    """Render `data` as a self-contained HTML page with an embedded QR code PNG."""
    qrcode = _require_display_deps()
    image = qrcode.make(data)
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    png_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    escaped = data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
  body {{ display: flex; flex-direction: column; align-items: center; justify-content: center;
          min-height: 100vh; margin: 0; font-family: monospace; background: #fff; color: #111; }}
  img {{ width: min(80vw, 480px); height: min(80vw, 480px); image-rendering: pixelated; }}
  code {{ margin-top: 1em; max-width: 90vw; word-break: break-all; font-size: 0.8em; color: #555; }}
</style></head>
<body>
  <img src="data:image/png;base64,{png_b64}" alt="QR code">
  <code>{escaped}</code>
</body></html>
"""


def show_in_browser(data: str, title: str = "siros-verify") -> Path:
    """Write a temporary HTML page rendering `data` as a QR code and open it in
    a browser (Chrome if registered, else the OS default)."""
    html = render_qr_html(data, title=title)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", prefix="siros-verify-qr-", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(html)
    path = Path(tmp.name)

    url = path.as_uri()
    for browser_name in _CHROME_CANDIDATES:
        try:
            webbrowser.get(browser_name).open(url)
            return path
        except webbrowser.Error:
            continue
    webbrowser.open(url)
    return path
