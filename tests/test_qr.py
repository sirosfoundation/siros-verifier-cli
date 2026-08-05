import time

import pytest

from siros_verifier import qr


def test_render_qr_html_embeds_data_and_png():
    html = qr.render_qr_html("mdoc:AAAA", title="test title")
    assert "<title>test title</title>" in html
    assert "data:image/png;base64," in html
    assert "mdoc:AAAA" in html


def test_render_qr_html_escapes_special_characters():
    html = qr.render_qr_html("<script>&</script>")
    assert "<script>" not in html.split("</style>")[1]  # not injected outside the intended <code> block
    assert "&lt;script&gt;&amp;&lt;/script&gt;" in html


class _FakeCapture:
    def __init__(self, frames):
        self._frames = list(frames)
        self.released = False

    def isOpened(self):
        return True

    def read(self):
        if self._frames:
            return True, self._frames.pop(0)
        return True, "frame"

    def release(self):
        self.released = True


class _FakeCv2:
    COLOR_BGR2RGB = 0

    def __init__(self, captures):
        self._captures = captures

    def VideoCapture(self, index):
        return self._captures[index]

    def cvtColor(self, frame, _flag):
        return frame


class _FakeImage:
    @staticmethod
    def fromarray(frame):
        return frame


def test_scan_camera_returns_first_decoded_symbol(monkeypatch):
    capture = _FakeCapture(frames=["frame1"])
    fake_cv2 = _FakeCv2({0: capture})

    class _Symbol:
        data = b"mdoc:decoded-from-camera"

    monkeypatch.setattr(qr, "_require_camera_deps", lambda: (fake_cv2, _FakeImage, lambda _img: [_Symbol()]))

    result = qr.scan_camera(timeout=5.0, camera_index=0)
    assert result == "mdoc:decoded-from-camera"
    assert capture.released


def test_scan_camera_raises_when_no_camera_opens(monkeypatch):
    class _ClosedCapture(_FakeCapture):
        def isOpened(self):
            return False

    fake_cv2 = _FakeCv2({0: _ClosedCapture(frames=[])})
    monkeypatch.setattr(qr, "_require_camera_deps", lambda: (fake_cv2, _FakeImage, lambda _img: []))

    with pytest.raises(RuntimeError):
        qr.scan_camera(timeout=1.0, camera_index=0)


def test_scan_camera_times_out_when_nothing_found(monkeypatch):
    capture = _FakeCapture(frames=[])
    fake_cv2 = _FakeCv2({0: capture})
    monkeypatch.setattr(qr, "_require_camera_deps", lambda: (fake_cv2, _FakeImage, lambda _img: []))

    start = time.monotonic()
    with pytest.raises(qr.QrNotFoundError):
        qr.scan_camera(timeout=0.05, camera_index=0)
    assert time.monotonic() - start < 2.0  # sanity: didn't hang
    assert capture.released


def test_scan_camera_tries_all_cameras_when_index_omitted(monkeypatch):
    class _Symbol:
        data = b"mdoc:from-second-camera"

    captures = {i: _FakeCapture(frames=[]) for i in range(9)}
    captures[3] = _FakeCapture(frames=["frame"])
    fake_cv2 = _FakeCv2(captures)

    def decode(frame):
        return [_Symbol()] if frame == "frame" else []

    monkeypatch.setattr(qr, "_require_camera_deps", lambda: (fake_cv2, _FakeImage, decode))

    result = qr.scan_camera(timeout=5.0, camera_index=None)
    assert result == "mdoc:from-second-camera"
    assert all(c.released for c in captures.values())
