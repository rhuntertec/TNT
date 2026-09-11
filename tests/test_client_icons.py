"""Tests for client.icons and tools/make_icons.py (no GUI, no network)."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client import icons  # noqa: E402

ALL_SIZES = (16, 24, 32, 48, 64, 128, 256)


def _close(a, b, tol=40) -> bool:
    return all(abs(int(x) - int(y)) <= tol for x, y in zip(a[:3], b[:3]))


def _pixels(img):
    """RGBA tuples of every pixel (Pillow 12 deprecates getdata())."""
    raw = img.convert("RGBA").tobytes()
    return [tuple(raw[i:i + 4]) for i in range(0, len(raw), 4)]


# --------------------------------------------------------------------------- make_icon
@pytest.mark.parametrize("size", ALL_SIZES)
def test_make_icon_size_and_mode(size):
    img = icons.make_icon(size)
    assert isinstance(img, Image.Image)
    assert img.size == (size, size)
    assert img.mode == "RGBA"


def test_make_icon_has_transparent_corners_and_red_body():
    img = icons.make_icon(128)
    # corners are outside the rotated stick: fully transparent
    for xy in ((0, 0), (127, 0), (0, 127)):
        assert img.getpixel(xy)[3] == 0
    # somewhere on the canvas there are red body pixels and ink outline pixels
    px = _pixels(img)
    assert any(_close(p, icons.RED, 24) and p[3] > 200 for p in px), "no red body pixels"
    assert any(_close(p, icons.INK, 24) and p[3] > 200 for p in px), "no ink outline pixels"
    assert any(_close(p, icons.ORANGE, 30) and p[3] > 200 for p in px), "no orange spark pixels"


@pytest.mark.parametrize("light", ["green", "yellow", "red", "grey"])
def test_status_dot_colour_bottom_right(light):
    size = 64
    img = icons.make_icon(size, light)
    assert img.size == (size, size) and img.mode == "RGBA"
    # dot centre is at 0.78 * size (see _draw_dot); the pixel there is the fill colour
    c = int(round(0.78 * size))
    p = img.getpixel((c, c))
    assert p[3] > 200
    assert _close(p, icons.LIGHT_COLOURS[light], 30), (light, p)


def test_dot_only_when_requested():
    plain = icons.make_icon(64)
    dotted = icons.make_icon(64, "green")
    c = int(round(0.78 * 64))
    assert not _close(plain.getpixel((c, c)), icons.GREEN, 20) or plain.getpixel((c, c))[3] < 200
    assert _close(dotted.getpixel((c, c)), icons.GREEN, 30)


def test_unknown_light_falls_back_to_grey():
    img = icons.make_icon(64, "purple")
    c = int(round(0.78 * 64))
    assert _close(img.getpixel((c, c)), icons.GREY, 30)


def test_light_is_case_insensitive():
    a = icons.make_icon(48, "Green")
    b = icons.make_icon(48, "green")
    assert a.tobytes() == b.tobytes()


def test_too_small_raises():
    with pytest.raises(ValueError):
        icons.make_icon(4)


def test_label_drawn_at_48_and_above():
    """The label band carries 'TNT' text from 48 px; smaller sizes get ticks/plain band."""
    with_label = icons._draw_stick(48 * icons._SS, with_label=True)
    without = icons._draw_stick(48 * icons._SS, with_label=False)
    assert with_label.tobytes() != without.tobytes()
    # text is ink-coloured pixels inside the cream band area (x 0.28..0.66, y 0.50..0.70)
    u = 48 * icons._SS
    band = with_label.crop((int(0.34 * u), int(0.53 * u), int(0.60 * u), int(0.67 * u)))
    ink_px = sum(1 for p in _pixels(band) if _close(p, icons.INK, 30) and p[3] > 200)
    assert ink_px > 20


# --------------------------------------------------------------------------- make_ico
def test_make_ico_writes_all_sizes(tmp_path):
    path = icons.make_ico(tmp_path / "sub" / "tnt.ico")
    assert path.is_file() and path.stat().st_size > 1000
    # ICO header: reserved(2) type(2)=1 count(2)
    head = path.read_bytes()[:6]
    reserved, kind, count = struct.unpack("<HHH", head)
    assert reserved == 0 and kind == 1
    assert count == len(ALL_SIZES)
    with Image.open(path) as ico:
        assert ico.format == "ICO"
        sizes = set(ico.info.get("sizes", set()))
        assert sizes == {(s, s) for s in ALL_SIZES}
        for s in ALL_SIZES:
            ico.size = (s, s)
            ico.load()
            assert ico.size == (s, s)


def test_make_ico_custom_sizes(tmp_path):
    path = icons.make_ico(tmp_path / "small.ico", sizes=(16, 32))
    with Image.open(path) as ico:
        assert set(ico.info["sizes"]) == {(16, 16), (32, 32)}
    with pytest.raises(ValueError):
        icons.make_ico(tmp_path / "bad.ico", sizes=(1, 2, 4))


# --------------------------------------------------------------------------- tools/make_icons.py
def test_make_icons_tool_writes_assets(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    import make_icons  # noqa: E402

    written = make_icons.generate(tmp_path)
    names = {p.relative_to(tmp_path).as_posix() for p in written}
    assert names == {"assets/tnt.ico", "assets/tnt-256.png", "ui/assets/logo.png"}
    for p in written:
        assert p.is_file() and p.stat().st_size > 0
    with Image.open(tmp_path / "ui" / "assets" / "logo.png") as png:
        assert png.format == "PNG" and png.size == (256, 256) and png.mode == "RGBA"
    with Image.open(tmp_path / "assets" / "tnt-256.png") as png:
        assert png.size == (256, 256)
    with Image.open(tmp_path / "assets" / "tnt.ico") as ico:
        assert set(ico.info["sizes"]) == {(s, s) for s in ALL_SIZES}


def test_make_icons_cli(tmp_path, capsys):
    sys.path.insert(0, str(ROOT / "tools"))
    import make_icons  # noqa: E402

    rc = make_icons.main(["--root", str(tmp_path), "--sizes", "16,32,48"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "tnt.ico" in out and "logo.png" in out
    with Image.open(tmp_path / "assets" / "tnt.ico") as ico:
        assert set(ico.info["sizes"]) == {(16, 16), (32, 32), (48, 48)}


def test_repo_assets_exist():
    """tools/make_icons.py must have been run so the build has its icon."""
    assert (ROOT / "assets" / "tnt.ico").is_file()
    assert (ROOT / "assets" / "tnt-256.png").is_file()
    assert (ROOT / "ui" / "assets" / "logo.png").is_file()


# =========================================================================== client/tray.py
# Everything below exercises the GUI-free parts of the tray client: argument parsing,
# status/tooltip text, the inline HTML pages, the JS-bridge helpers, the HTTP client and
# the tray-menu actions against a tiny stub API. pywebview / pystray are never imported.
import json  # noqa: E402
import os  # noqa: E402
import threading  # noqa: E402
from http.server import BaseHTTPRequestHandler, HTTPServer  # noqa: E402

from client import tray  # noqa: E402


class _StubApi(BaseHTTPRequestHandler):
    """Minimal fake of the routes the client uses (loopback, port 0)."""

    paused = False
    speed_running = True

    def log_message(self, *args):  # silence the test output
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/health":
            self._send(200, {"ok": True})
        elif self.path == "/api/status":
            self._send(200, {
                "version": "1.0.0", "paused": _StubApi.paused, "overall_light": "green",
                "targets": [{"id": 1, "host": "10.0.0.251", "light": "green"},
                            {"id": 2, "host": "1.1.1.1", "light": "green"},
                            {"id": 3, "host": "totalelectronics.com", "light": "green"}],
                "outages": {"active": [], "total_active": None, "count_24h": 0, "last": None, "monitoring": True},
            })
        else:
            self._send(404, {"error": {"code": "not_found", "message": "no such route"}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if self.path == "/api/speedtests/run":
            if _StubApi.speed_running:
                self._send(409, {"error": {"code": "conflict", "message": "speed test already running"}})
            else:
                self._send(200, {"started": True})
        elif self.path == "/api/monitoring/pause":
            _StubApi.paused = True
            self._send(200, {"paused": True})
        elif self.path == "/api/monitoring/resume":
            _StubApi.paused = False
            self._send(200, {"paused": False})
        else:
            self._send(404, {"error": {"code": "not_found", "message": "no such route"}})


@pytest.fixture
def stub_api():
    _StubApi.paused = False
    _StubApi.speed_running = True
    server = HTTPServer(("127.0.0.1", 0), _StubApi)
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=3)


@pytest.fixture
def client_home(tmp_path, monkeypatch):
    """Keep client.json / client.log out of the real %LOCALAPPDATA%."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    return tmp_path / "TNT"


# ---- args ----------------------------------------------------------------------------
def test_parse_args_defaults():
    a = tray.parse_args([])
    assert a.port == 7130 and a.minimized is False and a.url is None and a.debug is False
    assert tray.service_url(a) == "http://127.0.0.1:7130"


def test_parse_args_overrides():
    a = tray.parse_args(["--minimized", "--port", "7135", "--url", "http://127.0.0.1:7136/"])
    assert a.minimized is True and a.port == 7135
    assert tray.service_url(a) == "http://127.0.0.1:7136"  # trailing slash stripped
    with pytest.raises(SystemExit):
        tray.parse_args(["--port", "0"])


# ---- status text -----------------------------------------------------------------------
def _status(light="green", paused=False, targets=3, lights=None, total=None):
    lights = lights or [light] * targets
    return {"overall_light": light, "paused": paused,
            "targets": [{"id": i, "host": f"h{i}", "light": lt} for i, lt in enumerate(lights)],
            "outages": {"total_active": total}}


def test_light_summary_and_tooltip():
    assert tray.light_summary(None) == ("grey", "service unreachable")
    assert tray.light_summary(_status()) == ("green", "all green")
    assert tray.light_summary(_status(paused=True)) == ("grey", "monitoring paused")
    assert tray.light_summary(_status(targets=0)) == ("grey", "no targets")
    assert tray.light_summary(_status("yellow", lights=["green", "yellow", "green"])) == ("yellow", "1 target degraded")
    assert tray.light_summary(_status("red", lights=["red", "red", "green"])) == ("red", "2 targets down")
    assert tray.light_summary(_status("red", total={"kind": "total_internet"})) == ("red", "internet outage")
    assert tray.light_summary(_status("red", total={"kind": "total_local"})) == ("red", "local network outage")
    assert tray.light_summary({"overall_light": "purple", "targets": [{"light": "grey"}]}) == ("grey", "no data yet")

    tip = tray.tooltip_text(_status())
    assert tip.startswith("TNT — 3 targets · all green")
    assert "monitoring keeps running" in tip and len(tip) <= tray.TOOLTIP_MAX
    assert tray.tooltip_text(_status(targets=1)).startswith("TNT — 1 target · ")
    assert tray.tooltip_text(None).startswith("TNT — service unreachable")


# ---- inline pages ----------------------------------------------------------------------
@pytest.mark.parametrize("theme", ["light", "dark", "bogus"])
def test_inline_pages_are_self_contained(theme, tmp_path):
    url = "http://127.0.0.1:7135"
    start = tray.starting_html(url, theme)
    err = tray.error_html(url, tmp_path / "client.log", theme)
    for page in (start, err):
        assert page.lstrip().lower().startswith("<!doctype html>")
        assert "<style>" in page and url in page
        assert 'data-theme="' + ("dark" if theme == "dark" else "light") + '"' in page
        # no external resources: the pages must work while the internet is down
        assert "<link" not in page and "<script src" not in page and "@import" not in page
        assert "cdn" not in page.lower()
        assert "#FFF7E8" in page and "#2B2438" in page  # the UI's light palette
    assert "TNT is starting" in start
    assert "services.msc" in err and "TNTService" in err and "7135" in err
    assert str(tmp_path / "client.log") in err and "tnt-service.log" in err


# ---- bridge helpers --------------------------------------------------------------------
def test_clean_filename_and_b64():
    assert tray._clean_filename("C:/x/y/TNT-report.pdf") == "TNT-report.pdf"
    assert tray._clean_filename('bad:name?.pdf') == "bad_name_.pdf"
    assert tray._clean_filename("") == "TNT-export.bin"
    assert tray._decode_b64("aGVsbG8") == b"hello"  # missing padding
    assert tray._decode_b64("data:application/pdf;base64,aGVs bG8=\n") == b"hello"


def test_js_bridge_without_a_window(client_home):
    app = tray.ClientApp(tray.parse_args(["--port", "7139"]))
    bridge = tray.JsBridge(app)
    info = bridge.client_info()
    assert info["version"] and info["pid"] == os.getpid()
    assert bridge.open_path(str(client_home / "definitely-missing")) is False
    assert bridge.save_file("x.pdf", "aGVsbG8=") is None  # no window yet -> None, never raises
    assert bridge.set_theme("purple") is False
    assert bridge.set_theme("dark") is True and app.theme == "dark"
    assert tray.load_state().get("theme") == "dark"  # persisted under the temp LOCALAPPDATA
    assert tray.client_log_path() == client_home / "client.log"


# ---- HTTP client -----------------------------------------------------------------------
def test_service_client_against_stub(stub_api):
    c = tray.ServiceClient(stub_api + "/")
    assert c.base_url == stub_api
    assert c.health() is True
    st = c.status()
    assert isinstance(st, dict) and len(st["targets"]) == 3
    code, data = c.get("/api/nope")
    assert code == 404 and data["error"]["code"] == "not_found"
    code, data = c.post("/api/speedtests/run")
    assert code == 409


def test_service_client_unreachable():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens there now
    c = tray.ServiceClient(f"http://127.0.0.1:{port}")
    assert c.health(timeout=1.0) is False
    assert c.get("/api/status", timeout=1.0) == (0, None)


# ---- tray menu actions (no pystray: TrayIcon.notify/set_state are no-ops before start) --
def test_menu_actions_against_stub(stub_api, client_home):
    app = tray.ClientApp(tray.parse_args(["--url", stub_api]))
    notes = []
    app.tray.notify = lambda message, title="TNT": notes.append(message)

    st = app.refresh_status()
    assert st["paused"] is False and app._last_status is st

    app.run_speedtest()
    assert notes[-1] == "A speed test is already running."
    _StubApi.speed_running = False
    app.run_speedtest()
    assert notes[-1].startswith("Speed test started")

    app.toggle_pause()
    assert notes[-1] == "Monitoring paused." and app._last_status["paused"] is True
    app.toggle_pause()
    assert notes[-1] == "Monitoring resumed." and app._last_status["paused"] is False

    # diagnostics before the service page is shown queues the hash for the navigator
    app.window = None
    app.open_diagnostics()
    assert app._pending_hash == "#diagnostics" and app._wake.is_set()


# ---- single instance -------------------------------------------------------------------
@pytest.mark.skipif(os.name != "nt", reason="Win32 named mutex")
def test_single_instance_mutex():
    name = f"Local\\TNT.Client.test{os.getpid()}"
    assert tray.acquire_single_instance(name) is True
    assert tray.acquire_single_instance(name) is False  # already owned by this process
    tray.release_single_instance()
    assert tray.find_window("TNT test window that does not exist 0x5150") == 0
