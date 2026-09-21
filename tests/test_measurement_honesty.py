"""Measurement honesty in the speed test and the traceroute (1.21.2 deep review, sections 3 and 10).

* A speed-test phase whose flows stall is measured over the time the phase really ran, not up to its
  last byte, so a line that was dead for most of the phase reads as the slow line it is, and the stall
  is named in the result's note. A healthy line's figure does not move.
* An upload phase that acknowledges nothing is a visible "upload not measured" note on the result
  (and a pattern finding), not the silent ``upload_mbps: None`` of a test that never tried.
* An HTTP error body that is an HTML page (a captive portal) reaches ``SpeedResult.error`` as the
  status and the page's title in plain text only, never as markup.
* A traceroute keeps going past a silent stretch of routers, like tracert, and still says
  "no reply after hop N" when the tail really is silent, in bounded time.

Every address here is a documentation address; no test touches the network beyond 127.0.0.1.
"""
from __future__ import annotations

import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

import pytest

from tnt.config import Config
from tnt.db import Database
from tnt.events import EventBus
from tnt.icmp import PingResult
from tnt.speedtest import base, cloudflare, fastcom, patterns
from tnt.speedtest.base import HttpError, TransferPhase, mbps
from tnt.traceroute import DEFAULT_TIMEOUT_MS, REVERSE_DNS_DEADLINE_S, SILENT_HOPS_LIMIT, TRACE_PROBE_BUDGET_S, Tracer

from tests.test_ui import browser_page, mock  # noqa: F401  (fixtures: the mock API and a headless browser)


# =========================================================================== fake clock phases

class FakeClock:
    """A clock the test moves by hand; the phase reads it from every thread."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = float(now)
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self.now

    def advance(self, s: float) -> None:
        with self._lock:
            self.now += float(s)

    def set(self, t: float) -> None:
        with self._lock:
            self.now = float(t)


T0 = 1000.0


def _wait_closed(ph: TransferPhase) -> None:
    """A stalled recv(): nothing arrives until the controller closes the phase."""
    ph._stop.wait(10)


def _stall_until(ph: TransferPhase, clock: FakeClock, t: float) -> None:
    """Nothing moves until *t*; asking the phase whether to stop then records the time budget ending
    exactly there (the controller's own poll would notice it up to 0.1 s of real time later)."""
    clock.set(t)
    ph.should_stop()


@pytest.fixture(autouse=True)
def _clear_cooldowns():
    base.clear_cooldowns()
    yield
    base.clear_cooldowns()


def test_a_download_that_stalls_after_a_burst_reads_as_the_average_over_the_whole_phase():
    """50 MB arrive in 0.4 s, then the line is dead for the rest of the 8 s phase (production settings).
    It used to read 1000 Mbps: the clock stopped at the last byte."""
    clock = FakeClock(T0)
    phase = TransferPhase("download", duration_s=8, byte_budget=50_000_000, clock=clock)

    def worker(ph: TransferPhase, idx: int) -> None:
        for _ in range(200):                        # 250 kB every 2 ms: a gigabit burst
            ph.on_bytes(250_000)
            clock.advance(0.002)
        _stall_until(ph, clock, T0 + 8.0)
        _wait_closed(ph)

    stats = phase.run(worker, 1)
    assert stats.bytes == 50_000_000 and stats.errors == 0
    assert stats.seconds == pytest.approx(8.0, abs=0.01)
    assert stats.mbps == pytest.approx(mbps(50_000_000, 8.0), rel=0.02)       # 50 Mbps, not 1000
    assert stats.stalled is True and stats.stall_s == pytest.approx(7.6, abs=0.05)
    assert "stalled" in base.phase_note(stats) and "7.6 s" in base.phase_note(stats)


def test_a_time_budget_noticed_late_still_ends_the_phase_when_it_ran_out():
    """Nobody looks at the clock while every flow is stalled but the controller, which polls every 0.1 s (here it
    first looks 0.3 s late): the phase still lasted its 8 s, not 8.3 s."""
    clock = FakeClock(T0)
    phase = TransferPhase("download", duration_s=8, byte_budget=50_000_000, clock=clock)

    def worker(ph: TransferPhase, idx: int) -> None:
        for _ in range(40):
            ph.on_bytes(250_000)
            clock.advance(0.01)
        clock.set(T0 + 8.3)
        _wait_closed(ph)

    stats = phase.run(worker, 1)
    assert stats.seconds == pytest.approx(8.0, abs=0.001)
    assert stats.mbps_full == pytest.approx(mbps(10_000_000, 8.0), rel=0.001)


def test_a_stall_in_the_middle_of_the_phase_is_inside_the_steady_window():
    """10 MB over 0-1 s, nothing until 7 s, 10 MB over 7-8 s. The steady window used to start at the
    first byte after the ramp cutoff (7 s) and report 80 Mbps; 2-8 s really moved 10 MB."""
    clock = FakeClock(T0)
    phase = TransferPhase("download", duration_s=8, byte_budget=500_000_000, clock=clock)

    def worker(ph: TransferPhase, idx: int) -> None:
        for _ in range(40):
            ph.on_bytes(250_000)
            clock.advance(0.025)
        clock.advance(6.0)                          # dead for 6 s, across the 25 % ramp cutoff at 2 s
        for _ in range(40):
            if not ph.on_bytes(250_000):
                return
            clock.advance(0.025)
        while ph.on_bytes(1):                       # the next chunk lands after the time budget ended
            clock.advance(0.025)

    stats = phase.run(worker, 1)
    assert stats.bytes >= 20_000_000 and stats.seconds == pytest.approx(8.0, abs=0.05)
    assert stats.mbps_full == pytest.approx(20.0, rel=0.03)
    assert stats.mbps == pytest.approx(mbps(10_000_000, 6.0), rel=0.05)      # ~13 Mbps, not 80
    assert stats.stalled is True and stats.stall_s == pytest.approx(6.0, abs=0.05)


def test_an_upload_that_stops_being_acknowledged_reads_as_the_average_over_the_whole_phase():
    """Acked mode: 20 MB acknowledged in 0.5 s, then no acknowledgement for the rest of the phase."""
    clock = FakeClock(T0)
    phase = TransferPhase("upload", duration_s=8, byte_budget=20_000_000, clock=clock, acked=True, tail_s=2.0)

    def worker(ph: TransferPhase, idx: int) -> None:
        for _ in range(80):
            ph.on_bytes(250_000)
            ph.ack(250_000)
            clock.advance(0.00625)
        _stall_until(ph, clock, T0 + 8.0)
        clock.set(T0 + 10.0)                        # the tail runs out too: the phase closes
        _wait_closed(ph)

    stats = phase.run(worker, 1)
    assert stats.acked_bytes == 20_000_000 and stats.errors == 0
    assert stats.seconds == pytest.approx(8.0, abs=0.01)
    assert stats.mbps == pytest.approx(mbps(20_000_000, 8.0), rel=0.02)       # 20 Mbps, not 320
    assert stats.stalled is True
    assert "nothing was acknowledged" in base.phase_note(stats)


def test_a_steady_fast_download_reads_the_same_as_before():
    """400 Mbps with no stall: the byte budget is met at 1 s and the phase runs on to its 1.5 s minimum.
    The figure is the line rate, as it always was, and no stall is reported."""
    clock = FakeClock(T0)
    phase = TransferPhase("download", duration_s=8, byte_budget=50_000_000, clock=clock)

    def worker(ph: TransferPhase, idx: int) -> None:
        while ph.on_bytes(250_000):                 # 250 kB every 5 ms = 400 Mbps
            clock.advance(0.005)

    stats = phase.run(worker, 1)
    assert stats.seconds == pytest.approx(1.5, abs=0.01)
    assert stats.mbps == pytest.approx(400.0, rel=0.01)
    assert stats.mbps_full == pytest.approx(400.0, rel=0.01)
    assert stats.stalled is False and stats.stall_s < 0.05
    assert base.phase_note(stats) is None


def test_a_steady_slow_download_that_runs_to_the_time_budget_reads_the_same_as_before():
    clock = FakeClock(T0)
    phase = TransferPhase("download", duration_s=8, byte_budget=50_000_000, clock=clock)

    def worker(ph: TransferPhase, idx: int) -> None:
        while ph.on_bytes(250_000):                 # 250 kB every 100 ms = 20 Mbps
            clock.advance(0.1)

    stats = phase.run(worker, 1)
    assert stats.seconds == pytest.approx(8.0, abs=0.11)
    assert stats.mbps == pytest.approx(20.0, rel=0.02)
    assert stats.stalled is False


@pytest.mark.parametrize("every_s", [0.5, 2.0])
def test_a_healthy_upload_acknowledged_every_request_reads_the_line_rate_and_no_stall(every_s):
    """Acknowledgements arrive once per request, so they are seconds apart on one connection (the
    requests are sized for about 2 s each): that is not a stall, and the figure is the line rate."""
    clock = FakeClock(T0)
    phase = TransferPhase("upload", duration_s=8, byte_budget=10 ** 9, clock=clock, acked=True, tail_s=2.0)
    body = int(20e6 / 8 * every_s)                  # 20 Mbps

    def worker(ph: TransferPhase, idx: int) -> None:
        while ph.on_bytes(body):
            clock.advance(every_s)
            if not ph.ack(body):
                return

    stats = phase.run(worker, 1)
    assert stats.mbps == pytest.approx(20.0, rel=0.03)
    assert stats.stalled is False and base.phase_note(stats) is None


# =========================================================================== a local fake Cloudflare / fast.com

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    up_mode = "ack"            # "ack" | "never" (read the body, never answer) | "refuse" (403 to every upload)
    trace_status = 200
    trace_body = b"fl=1\nip=203.0.113.5\ncolo=TST\nloc=US\n"
    trace_ctype = "text/plain"
    release = threading.Event()

    def log_message(self, *args):
        pass

    def _send(self, status, body, ctype="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/cdn-cgi/trace":
            self._send(self.trace_status, self.trace_body, self.trace_ctype)
        elif parts.path == "/__down":
            n = int(parse_qs(parts.query).get("bytes", ["0"])[0])
            self._send(200, b"Z" * n, "application/octet-stream")
        elif parts.path == "/netflix/speedtest/v2":
            host, port = self.server.server_address[:2]
            self._send(200, (
                '{"client": {"ip": "203.0.113.9", "asn": "64500"}, "targets": ['
                f'{{"url": "http://{host}:{port}/speedtest?c=us", "location": {{"city": "Anytown", "country": "US"}}}}]}}'
            ).encode(), "application/json")
        elif parts.path.startswith("/speedtest/range/"):
            a, b = parts.path.rsplit("/", 1)[1].split("-")
            self._send(200, b"Z" * (int(b) - int(a) + 1), "application/octet-stream")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        while n > 0:
            data = self.rfile.read(min(65536, n))
            if not data:
                return
            n -= len(data)
        if self.up_mode == "never":
            self.release.wait(30)                  # the body is in; the answer never comes
            return
        if self.up_mode == "refuse":
            self._send(403, b"forbidden")
            return
        self._send(200, b"ok")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setattr(_Handler, "release", threading.Event())
    srv = _Server(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    host, port = srv.server_address[:2]
    monkeypatch.setattr(cloudflare, "HOST", host)
    monkeypatch.setattr(cloudflare, "PORT", port)
    monkeypatch.setattr(cloudflare, "SCHEME", "http")
    monkeypatch.setattr(fastcom, "API_HOST", host)
    monkeypatch.setattr(fastcom, "API_PORT", port)
    monkeypatch.setattr(fastcom, "API_SCHEME", "http")
    yield host, port
    _Handler.release.set()
    srv.shutdown()
    srv.server_close()
    t.join(2)


@pytest.fixture
def cfg(tmp_path):
    c = Config(tmp_path / "config.json")
    c.update({"speedtest": {"download_mb": 1, "upload_mb": 1, "duration_s": 2, "connections": 2}}, persist=False)
    return c


# =========================================================================== an upload that acknowledges nothing

@pytest.mark.parametrize("backend", [cloudflare.CloudflareBackend, fastcom.FastComBackend])
def test_an_upload_that_acknowledges_nothing_is_a_visible_upload_not_measured_note(backend, server, cfg, monkeypatch):
    """Downloads work, every upload hangs after its body is sent (an upstream fault, a shaper starving uploads).
    The download reading stays; the result says the upload could not be measured, and why."""
    monkeypatch.setattr(_Handler, "up_mode", "never")
    res = backend().run(cfg)
    assert res.ok is True, res.error
    assert res.download_mbps and res.download_mbps > 0
    assert res.upload_mbps is None
    assert res.error is not None and res.error.startswith(base.UPLOAD_NOT_MEASURED)
    assert "no upload request was acknowledged" in res.error and "kB sent" in res.error
    assert res.raw["upload"]["acked_bytes"] == 0 and res.raw["upload"]["bytes"] > 0
    assert res.raw["upload"]["error"] == res.error.split(": ", 1)[1]


def test_an_upload_the_server_refuses_says_so_rather_than_blaming_the_line(server, cfg, monkeypatch):
    """A fast.com server that answers every upload POST with 403 (an OCA that takes no uploads; Cloudflare's 403 is a
    bot block and fails the run as rate limited instead): the note says the requests failed and how."""
    monkeypatch.setattr(_Handler, "up_mode", "refuse")
    res = fastcom.FastComBackend().run(cfg)
    assert res.ok is True and res.upload_mbps is None
    assert res.error.startswith(base.UPLOAD_NOT_MEASURED + ": 6 upload requests failed and nothing was acknowledged")
    assert res.error.endswith("(last: HTTP 403: forbidden)")
    assert base.UPLOAD_REFUSED + ", which says nothing about the line" in res.error
    assert "?" not in res.error                     # never the server's query string (fast.com's carries a token)



def _upload_stats(errors: int, last_error: Optional[str], sent: int = 512_000) -> base.PhaseStats:
    return base.PhaseStats(name="upload", bytes=sent, seconds=8.0, requests=errors, errors=errors, aborted=False,
                           mbps=None, acked_bytes=0, acked=True, last_error=last_error)


def test_an_upload_whose_every_request_timed_out_points_at_the_line():
    """A dead upstream against the production settings: each request's socket times out, so the phase has errors and
    nothing acknowledged. That is the line (or something on it), and the note says so, like the no-error case does."""
    text = base.upload_not_measured(_upload_stats(4, "TimeoutError: timed out"))
    assert text == ("4 upload requests failed and nothing was acknowledged (512 kB sent): the upload is down, or too "
                    "slow to finish one request in the phase (last: TimeoutError: timed out)")
    assert base.UPLOAD_REFUSED not in text


@pytest.mark.parametrize("last", ["HTTP 403: forbidden", "HTTP 405: method not allowed", "HTTP 413"])
def test_an_upload_the_server_refused_says_it_was_the_server_not_the_line(last):
    text = base.upload_not_measured(_upload_stats(6, last))
    assert text == (f"6 upload requests failed and nothing was acknowledged (512 kB sent): {base.UPLOAD_REFUSED}, "
                    f"which says nothing about the line (last: {last})")
    assert "the upload is down" not in text


def test_an_upload_the_server_failed_with_a_5xx_blames_neither_the_line_nor_a_refusal():
    text = base.upload_not_measured(_upload_stats(3, "HTTP 502: bad gateway"))
    assert "the upload is down" not in text and base.UPLOAD_REFUSED not in text
    assert text.endswith("(last: HTTP 502: bad gateway)")

def test_a_clean_test_carries_no_note(server, cfg):
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.ok is True and res.upload_mbps and res.error is None


NOW = 1_700_000_000.0


def _ok_row(ts: float, up: Optional[float] = 20.0, note: Optional[str] = None) -> Dict[str, Any]:
    return {"ts": ts, "ok": True, "backend": "cloudflare", "download_mbps": 100.0, "upload_mbps": up,
            "latency_ms": 15.0, "error": note}


def test_the_patterns_count_tests_whose_upload_could_not_be_measured():
    rows = [_ok_row(NOW - i * 900) for i in range(20)]
    note = base.UPLOAD_NOT_MEASURED + ": no upload request was acknowledged within 10 s (256 kB sent)"
    rows += [_ok_row(NOW - 50 - i * 900, up=None, note=note) for i in range(3)]
    p = patterns.analyse_patterns(rows, NOW, 50, 0, days=7)
    assert p["ok_count"] == 23 and p["median_up"] == 20.0
    assert "The upload could not be measured in 3 of 23 tests in the last 7 days, while the download worked." in p["findings"]
    assert "Speeds look consistent across the day and week." not in p["findings"]


def test_the_patterns_tell_a_server_refusing_the_upload_apart_from_a_dead_upstream():
    """A fast.com cache server that takes no uploads fails the upload of every test it serves: that is the server, and
    the finding must not point the technician at the line."""
    rows = [_ok_row(NOW - i * 900) for i in range(20)]
    refused = base.UPLOAD_NOT_MEASURED + ": " + base.upload_not_measured(_upload_stats(6, "HTTP 403: forbidden"))
    dead = base.UPLOAD_NOT_MEASURED + ": " + base.upload_not_measured(_upload_stats(4, "TimeoutError: timed out"))
    rows += [_ok_row(NOW - 50 - i * 900, up=None, note=refused) for i in range(2)]
    rows += [_ok_row(NOW - 70, up=None, note=dead)]
    p = patterns.analyse_patterns(rows, NOW, 50, 0, days=7)
    assert "The upload could not be measured in 1 of 23 tests in the last 7 days, while the download worked." in p["findings"]
    assert ("The test server refused the upload in 2 of 23 tests in the last 7 days: that is the server, "
            "not this line.") in p["findings"]


def test_the_patterns_count_tests_that_stalled():
    rows = [_ok_row(NOW - i * 900) for i in range(20)]
    rows[3]["error"] = "download stalled: nothing arrived for 7.6 s of the 8.0 s phase"
    p = patterns.analyse_patterns(rows, NOW, 50, 0, days=7)
    assert "1 test stalled part-way: nothing moved for several seconds." in p["findings"]


def test_a_test_that_never_tried_the_upload_is_not_counted_as_unmeasured():
    rows = [_ok_row(NOW - i * 900, up=None) for i in range(10)]
    p = patterns.analyse_patterns(rows, NOW, 50, 0, days=7)
    assert not any("could not be measured" in f for f in p["findings"])


def test_the_speed_page_and_the_toast_show_the_note_of_an_ok_test(browser_page, mock, monkeypatch):  # noqa: F811
    """The Speed page's latest result shows the note of an ok test with no upload figure; before, the only sign
    was the dash."""
    note = base.UPLOAD_NOT_MEASURED + ": no upload request was acknowledged within 10 s (256 kB sent)"
    with mock.state.lock:
        rows = list(mock.state.speedtests)
        last = dict(rows[-1], ok=True, upload_mbps=None, error=note)
        rows[-1] = last
    monkeypatch.setattr(mock.state, "speedtests", rows)
    dom = browser_page("#speed")
    view = dom.split('id="view"', 1)[1]
    m = re.search(r'<div class="muted small speed-note"(?: [^>]*)?>(.*?)</div>', view, re.S)
    assert m, "no note under the latest result"
    assert "Upload not measured: no upload request was acknowledged within 10 s (256 kB sent)" in m.group(1)
    assert "Last test failed" not in view



def test_the_history_summary_leaves_unmeasured_uploads_out_of_the_upload_average(browser_page, mock, monkeypatch):  # noqa: F811
    """The summary over the history chart ("8 tests · avg ↓ 100 ↑ 30 Mbps") counted an unmeasured upload as 0 Mbps, so
    every test whose upload could not be measured dragged the shown average down (to 15 here); the chart's own
    average line already left them out."""
    note = base.UPLOAD_NOT_MEASURED + ": no upload request was acknowledged (256 kB sent): " + base.UPLOAD_LINE_HINT
    now = time.time()
    with mock.state.lock:
        template = {k: v for k, v in mock.state.speedtests[-1].items()}
        rows = [r for r in mock.state.speedtests if r["ts"] < now - 30 * 3600]
    for k in range(8, 0, -1):
        measured = k % 2 == 0
        rows.append(dict(template, id=len(rows) + 1, ts=now - k * 1800, ok=True, download_mbps=100.0,
                         upload_mbps=30.0 if measured else None, error=None if measured else note))
    monkeypatch.setattr(mock.state, "speedtests", rows)
    dom = browser_page("#speed")
    m = re.search(r"(\d+) tests · avg ↓ ([\d.]+) ↑ ([\d.]+) Mbps", dom)
    assert m, "no history summary"
    assert m.group(1) == "8" and float(m.group(2)) == 100.0
    assert float(m.group(3)) == 30.0

def test_the_toast_of_an_ok_test_with_a_note_is_a_warning_that_carries_the_note():
    from pathlib import Path
    app = (Path(__file__).resolve().parent.parent / "ui" / "js" / "app.js").read_text(encoding="utf-8")
    handler = app.split("ev.on('speedtest.done'", 1)[1].split("});", 1)[0]
    assert "const noted = r && r.ok && r.error;" in handler
    assert "(noted ? ' · ' + r.error : '')" in handler
    assert "r.ok && !noted ? 'ok' : 'warn'" in handler


# =========================================================================== HTML error bodies

PORTAL = (b"<!DOCTYPE html><html><head><title>Hotel &amp; Conference Wi-Fi \xe2\x80\x93 sign in</title>"
          b"<script>alert(1)</script></head><body><img src=x onerror=\"alert(2)\"><form>...</form></body></html>")


def test_a_captive_portal_page_becomes_the_status_and_its_title_in_plain_text(server, cfg, monkeypatch):
    monkeypatch.setattr(_Handler, "trace_status", 511)
    monkeypatch.setattr(_Handler, "trace_body", PORTAL)
    monkeypatch.setattr(_Handler, "trace_ctype", "text/html; charset=utf-8")
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.ok is False
    assert res.error == "HttpError: HTTP 511 for /cdn-cgi/trace: Hotel & Conference Wi-Fi – sign in"
    assert "<" not in res.error and ">" not in res.error


def test_an_html_page_sent_as_plain_text_is_still_reduced_to_its_title(server, cfg, monkeypatch):
    monkeypatch.setattr(_Handler, "trace_status", 502)
    monkeypatch.setattr(_Handler, "trace_body", b"  \n" + PORTAL)
    monkeypatch.setattr(_Handler, "trace_ctype", "text/plain")
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.error.endswith(": Hotel & Conference Wi-Fi – sign in")


@pytest.mark.parametrize("body, ctype, want", [
    (b"<html><body><img src=x onerror=alert(1)>Log in</body></html>", "text/html", "an HTML page"),
    (b"<html><title>&lt;img src=x onerror=alert(1)&gt;" + b"x" * 300 + b"</title></html>", "text/html", None),
    (b"slow down", "text/plain", "slow down"),
    (b"<b>bold</b> plain words", "text/plain", "bold plain words"),
])
def test_error_details_never_carry_markup_and_stay_short(body, ctype, want):
    text = base.error_detail(body, ctype)
    assert "<" not in text and ">" not in text
    assert len(text) <= base.ERROR_DETAIL_MAX
    if want is not None:
        assert text == want
    else:
        assert text.startswith("img src=x onerror=alert(1)") and text.endswith("…")


def test_the_download_and_upload_paths_reduce_an_html_error_too(server, monkeypatch):
    host, port = server

    def portal(self):
        self._send(511, PORTAL, "text/html")
    monkeypatch.setattr(_Handler, "do_GET", portal)
    http_ = base.Http(host, port, scheme="http", timeout=5)
    with pytest.raises(HttpError) as down:
        http_.download("/__down?bytes=1000", lambda n: True)
    assert str(down.value) == "HTTP 511 for /__down?bytes=1000: Hotel & Conference Wi-Fi – sign in"

    def portal_post(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        self._send(511, PORTAL, "text/html")
    monkeypatch.setattr(_Handler, "do_POST", portal_post)
    with pytest.raises(HttpError) as up:
        http_.upload("/__up", 1000, lambda n: True)
    assert str(up.value) == "HTTP 511 for /__up: Hotel & Conference Wi-Fi – sign in"
    http_.close()


# =========================================================================== traceroute past a silent core

TARGET = "198.51.100.7"
GATEWAY = "10.0.0.251"
CGNAT = "100.64.0.1"
PUBLIC = "203.0.113.9"


class ScriptedPinger:
    def __init__(self, script: Dict[int, List[Tuple[Any, ...]]]) -> None:
        self.script = script
        self.calls: List[int] = []

    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> PingResult:
        idx = self.calls.count(ttl)
        self.calls.append(ttl)
        seq = self.script.get(ttl, [(None, None)])
        responder, rtt = seq[min(idx, len(seq) - 1)][:2]
        if responder is None:
            return PingResult(False, None, 11010, "Request timed out", None, size, ip, responder=None)
        if responder == ip:
            return PingResult(True, rtt, 0, None, 52, size, ip, responder=ip)
        return PingResult(False, rtt, 11013, f"TTL expired in transit (reply from {responder})", None, size, ip,
                          responder=responder)


def _tracer(script):
    bus = EventBus()
    events: List[Dict[str, Any]] = []
    bus.subscribe(lambda e: events.append(e))
    pinger = ScriptedPinger(script)
    tracer = Tracer(pinger, bus, resolver=lambda h: h, reverse=lambda ip: None,
                    gateway_fn=lambda: GATEWAY, local_fn=lambda: "10.0.0.112")
    return tracer, pinger, events


THREE_ROUTERS = {1: [(GATEWAY, 1.0)], 2: [(CGNAT, 4.0)], 3: [(PUBLIC, 9.0)]}


def test_a_trace_goes_on_past_six_silent_routers_to_the_destination_at_hop_ten():
    script = dict(THREE_ROUTERS)
    script[10] = [(TARGET, 40.0)]                   # TTL 4-9 never answer (a core that sends no TTL-expired)
    tracer, pinger, events = _tracer(script)
    res = tracer.trace(TARGET)
    assert res["complete"] is True and res["error"] is None
    assert [h["ttl"] for h in res["hops"]] == list(range(1, 11))
    assert res["hops"][-1]["kind"] == "destination" and res["hops"][-1]["ip"] == TARGET
    assert [h["kind"] for h in res["hops"][3:9]] == ["unknown"] * 6
    assert events[-1]["data"]["complete"] is True and events[-1]["data"]["hops"] == 10


def test_a_trace_whose_tail_is_silent_still_says_no_reply_after_the_last_router():
    tracer, pinger, events = _tracer(dict(THREE_ROUTERS))
    res = tracer.trace(TARGET)
    assert res["complete"] is False and res["error"] == "no reply after hop 3"
    assert [h["ttl"] for h in res["hops"]] == list(range(1, 31))       # to max_hops, like tracert
    assert all(h["kind"] == "unknown" for h in res["hops"][3:])
    assert events[-1]["data"]["error"] == "no reply after hop 3"


def test_a_long_silent_run_drops_to_one_probe_per_hop_so_the_trace_stays_bounded():
    tracer, pinger, _ = _tracer(dict(THREE_ROUTERS))
    tracer.trace(TARGET)
    per_ttl = {ttl: pinger.calls.count(ttl) for ttl in set(pinger.calls)}
    assert all(per_ttl[t] == 3 for t in range(1, 4 + SILENT_HOPS_LIMIT))              # answered + the first silent run
    assert all(per_ttl[t] == 1 for t in range(4 + SILENT_HOPS_LIMIT, 31))
    # the worst case at the defaults, nothing answering at all: every probe waits out its timeout, and the whole trace
    # still ends inside a minute, well within the client's 120 s wait (it used to give up after 22.5 s, wrongly)
    tracer, pinger, _ = _tracer({})
    tracer.trace(TARGET)
    assert len(pinger.calls) == SILENT_HOPS_LIMIT * 3 + (30 - SILENT_HOPS_LIMIT)
    assert len(pinger.calls) * DEFAULT_TIMEOUT_MS / 1000.0 <= 60.0


def test_a_router_answering_after_a_silent_run_gets_full_probes_again():
    script = dict(THREE_ROUTERS)
    script[12] = [(PUBLIC, 20.0)]
    tracer, pinger, _ = _tracer(script)
    res = tracer.trace(TARGET, max_hops=14)
    # the one probe that found a router is followed by the rest of that hop's probes, and the next hop gets them all
    assert pinger.calls.count(11) == 1 and pinger.calls.count(12) == 3 and pinger.calls.count(13) == 3
    assert res["hops"][11]["ip"] == PUBLIC and len(res["hops"][11]["rtts"]) == 3
    assert len(res["hops"][10]["rtts"]) == 1                     # a quiet hop shows the one probe it was sent
    assert res["error"] == "destination not reached within 14 hops"



def test_a_destination_that_drops_the_one_probe_of_a_quiet_hop_is_found_a_hop_later_and_still_reached():
    """The accepted cost of the one-probe tail: deep in a silent run, a destination whose first echo at TTL 12 is lost
    (the rest would have been answered) shows as a silent hop 12 with its one probe lost, and the trace completes at
    hop 13 on the next TTL. The destination and "complete" are right; the hop count is one too many, as it is in
    tracert whenever every probe of a hop is lost."""
    script = dict(THREE_ROUTERS)
    script[12] = [(None, None), (TARGET, 30.0), (TARGET, 30.0)]
    script[13] = [(TARGET, 30.0)]
    tracer, pinger, _ = _tracer(script)
    res = tracer.trace(TARGET)
    assert res["complete"] is True and res["error"] is None
    assert res["hops"][11]["ip"] is None and res["hops"][11]["rtts"] == [None]
    assert res["hops"][-1]["ttl"] == 13 and res["hops"][-1]["kind"] == "destination"

def test_a_trace_where_nothing_answers_says_so_for_every_hop():
    tracer, pinger, _ = _tracer({})
    res = tracer.trace(TARGET, max_hops=12)
    assert res["complete"] is False and len(res["hops"]) == 12
    assert res["error"] == "no reply from any of the 12 hops"


def test_the_traceroute_table_counts_loss_against_the_probes_a_hop_was_really_sent():
    """A quiet hop deep in a silent run was sent one probe: "1/1", not "1/3" lost."""
    from pathlib import Path
    js = (Path(__file__).resolve().parent.parent / "ui" / "js" / "tools" / "traceroute.js").read_text(encoding="utf-8")
    assert "function sentProbes(hop, probes) { return Array.isArray(hop.rtts) && hop.rtts.length ? hop.rtts.length : probes; }" in js
    assert "(hop.loss || 0) + '/' + sentProbes(hop, probes)" in js
    assert "probes = sentProbes(hop, probes);" in js.split("function hopNode(hop, probes) {", 1)[1][:200]


class TimedPinger(ScriptedPinger):
    """A ScriptedPinger whose probes take time on a fake clock: an unanswered one its whole timeout."""

    def __init__(self, script: Dict[int, List[Tuple[Any, ...]]], clock: FakeClock) -> None:
        super().__init__(script)
        self.clock = clock

    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> PingResult:
        r = super().ping(ip, size=size, timeout_ms=timeout_ms, ttl=ttl)
        self.clock.advance((timeout_ms if r.responder is None else (r.rtt_ms or 1.0)) / 1000.0)
        return r


def _timed_tracer(script):
    clock = FakeClock()
    pinger = TimedPinger(script, clock)
    tracer = Tracer(pinger, EventBus(), resolver=lambda h: h, reverse=lambda ip: None,
                    gateway_fn=lambda: GATEWAY, local_fn=lambda: "10.0.0.112", monotonic=clock)
    return tracer, pinger, clock


# the client (ui/js/api.js) waits 120 s for POST /api/tools/traceroute; the probing must end well inside that,
# leaving room for the 4 s of reverse DNS and the hop locations
CLIENT_WAIT_S = 120.0


@pytest.mark.parametrize("max_hops,timeout_ms", [(30, 3000), (64, 2000), (64, 1500), (64, 5000)])
def test_a_silent_tail_with_slow_settings_still_ends_inside_the_clients_wait(max_hops, timeout_ms):
    """Settings the Tools page accepts: 30 hops at a 3 s timeout silent after hop 2 used to take 114 s of probing, and
    64 hops at 2 s about 148 s, past the client's 120 s wait: the page said "Request timed out" while the service
    carried on. The probing now stops at its time limit, and the result says where replies stopped and why it ended."""
    script = {1: [(GATEWAY, 1.0)], 2: [(CGNAT, 4.0)]}
    tracer, pinger, clock = _timed_tracer(script)
    res = tracer.trace(TARGET, max_hops=max_hops, timeout_ms=timeout_ms)
    probing_s = clock() - T0
    assert probing_s <= TRACE_PROBE_BUDGET_S
    assert TRACE_PROBE_BUDGET_S + REVERSE_DNS_DEADLINE_S < CLIENT_WAIT_S - 10
    assert res["complete"] is False
    n = len(res["hops"])
    assert [h["ttl"] for h in res["hops"]] == list(range(1, n + 1)) and n < max_hops
    assert res["error"] == (f"no reply after hop 2; stopped at hop {n}, the {TRACE_PROBE_BUDGET_S:.0f} s "
                            f"time limit for a trace")


def test_a_trace_at_the_default_settings_is_not_cut_by_the_time_limit():
    tracer, pinger, clock = _timed_tracer(dict(THREE_ROUTERS))
    res = tracer.trace(TARGET)
    assert len(res["hops"]) == 30 and res["error"] == "no reply after hop 3"
    assert clock() - T0 <= 60.0


def test_a_trace_where_nothing_answers_before_the_time_limit_says_so():
    tracer, pinger, clock = _timed_tracer({})
    res = tracer.trace(TARGET, max_hops=64, timeout_ms=5000)
    n = len(res["hops"])
    assert clock() - T0 <= TRACE_PROBE_BUDGET_S
    assert res["error"] == f"no reply from any of the {n} hops tried; stopped at the {TRACE_PROBE_BUDGET_S:.0f} s time limit for a trace"


def test_a_trace_cut_by_the_time_limit_after_an_answering_hop_says_the_destination_was_not_reached():
    # every hop answers, slowly (a router rate-limiting its TTL-expired replies, each taking 1.2 s)
    script = {ttl: [(f"203.0.113.{ttl}", 1200.0)] for ttl in range(1, 65)}
    tracer, pinger, clock = _timed_tracer(script)
    res = tracer.trace(TARGET, max_hops=64, probes=5)
    n = len(res["hops"])
    assert clock() - T0 <= TRACE_PROBE_BUDGET_S and n < 64
    assert res["error"] == f"destination not reached by hop {n}; stopped at the {TRACE_PROBE_BUDGET_S:.0f} s time limit for a trace"


def test_the_service_waits_for_the_trace_no_longer_than_its_probing_limit_allows():
    """trace() joins the worker for the probing time plus DNS and grace: capped by the probing limit, so a stuck worker
    is given up on before the client stops waiting."""
    import inspect
    from tnt import traceroute as tr
    src = inspect.getsource(tr.Tracer.trace)
    assert "min(max_hops * probes * timeout_ms / 1000.0, TRACE_PROBE_BUDGET_S)" in src
    assert TRACE_PROBE_BUDGET_S + tr.REVERSE_DNS_DEADLINE_S + tr.WAIT_GRACE_S < CLIENT_WAIT_S
