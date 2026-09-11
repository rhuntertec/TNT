"""Tests for tnt.speedtest (no network unless marked ``network``)."""
from __future__ import annotations

import email.utils
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from tnt.config import Config
from tnt.db import Database
from tnt.events import EventBus
from tnt import speedtest as st
from tnt.speedtest import base, cloudflare, fastcom, patterns
from tnt.speedtest import scheduler as sched_mod
from tnt.speedtest.base import SpeedResult, TransferPhase


# --------------------------------------------------------------------------- helpers / fixtures

def wait_until(pred, timeout=5.0, step=0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return pred()


class FakeClock:
    def __init__(self, now: float) -> None:
        self.now = float(now)
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self.now

    def advance(self, s: float) -> None:
        with self._lock:
            self.now += float(s)


@pytest.fixture
def cfg(tmp_path):
    c = Config(tmp_path / "config.json")
    c.update({"speedtest": {"download_mb": 1, "upload_mb": 1, "duration_s": 2, "connections": 2}}, persist=False)
    return c


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "t.db")
    yield d
    d.close()


@pytest.fixture
def bus():
    return EventBus()


@pytest.fixture(autouse=True)
def _exact_budget_phases(monkeypatch):
    """The production phase keeps transferring for MIN_DURATION_S after the byte budget and
    reports the steady-state figure (ramp-up excluded). The unit tests below reason about
    exact byte budgets and whole-window Mbps, so switch both refinements off by default;
    test_phase_min_duration_and_steady_state re-enables them explicitly."""
    monkeypatch.setattr(TransferPhase, "MIN_DURATION_S", 0.0)
    monkeypatch.setattr(TransferPhase, "RAMP_FRACTION", 0.0)


@pytest.fixture(autouse=True)
def _clear_cooldowns():
    """The rate-limit cooldown registry is module-level: never leak one between tests."""
    base.clear_cooldowns()
    yield
    base.clear_cooldowns()


# --------------------------------------------------------------------------- fake Cloudflare / fast.com server

class _FakeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Knobs tests flip via monkeypatch: delay before acknowledging an upload body,
    # and a sleep between download chunks (a trickling / hung server).
    up_ack_delay_s = 0.0
    down_trickle_s = 0.0
    # Rate limiting: answer ``limit_status`` (429/403) to requests whose scope is in
    # ``limit_scope`` ({"trace", "down", "up", "api", "range_get", "range_post"}) and whose
    # size is >= ``limit_min_bytes``; ``limit_retry_after`` becomes the Retry-After header.
    # Every refusal is appended to ``limit_hits`` as (scope, nbytes).
    limit_status = None
    limit_scope = frozenset()
    limit_min_bytes = 0
    limit_retry_after = None
    limit_hits: list = []

    def log_message(self, *args):  # silence
        pass

    def _limited(self, scope, nbytes=0):
        if not self.limit_status or scope not in self.limit_scope or nbytes < self.limit_min_bytes:
            return False
        self.limit_hits.append((scope, nbytes))
        extra = {"Retry-After": str(self.limit_retry_after)} if self.limit_retry_after is not None else None
        self._send(self.limit_status, b"slow down", extra=extra)
        return True

    def _send(self, status, body, ctype="text/plain", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _stream(self, n, extra=None):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(n))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        chunk = b"Z" * 65536
        remaining = n
        while remaining > 0:
            k = min(len(chunk), remaining)
            self.wfile.write(chunk[:k])
            self.wfile.flush()
            remaining -= k
            if self.down_trickle_s and remaining > 0:
                time.sleep(self.down_trickle_s)

    def _drain(self):
        n = int(self.headers.get("Content-Length") or 0)
        remaining = n
        while remaining > 0:
            data = self.rfile.read(min(65536, remaining))
            if not data:
                break
            remaining -= len(data)
        return n

    def do_GET(self):
        if "Mozilla" not in self.headers.get("User-Agent", ""):
            self._send(403, b"forbidden")
            return
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        if parts.path == "/cdn-cgi/trace":
            if self._limited("trace"):
                return
            self._send(200, b"fl=1\nh=speed.cloudflare.com\nip=203.0.113.5\nts=1.0\ncolo=TST\nloc=US\n")
        elif parts.path == "/__down":
            n = int(q.get("bytes", ["0"])[0])
            if self._limited("down", n):
                return
            self._stream(n, {"server-timing": 'cfSpeedEdge;dur=1, cfSpeedWorker;dur=2, '
                                              'cfL4;desc="?proto=TCP&rtt=1500&min_rtt=1200&rtt_var=100&sent=1&recv=1&lost=0&retrans=0"'})
        elif parts.path == "/netflix/speedtest/v2":
            if self._limited("api"):
                return
            host, port = self.server.server_address[:2]
            body = json.dumps({
                "client": {"ip": "203.0.113.9", "asn": "64500", "location": {"city": "Anytown", "country": "US"}},
                "targets": [
                    {"name": "a", "url": f"http://{host}:{port}/speedtest?c=us&n=1",
                     "location": {"city": "Anytown", "country": "US"}},
                    {"name": "b", "url": f"http://{host}:{port}/speedtest?c=us&n=2",
                     "location": {"city": "Anytown", "country": "US"}},
                ],
            }).encode()
            self._send(200, body, "application/json")
        elif parts.path.startswith("/speedtest/range/"):
            a, b = parts.path.rsplit("/", 1)[1].split("-")
            n = int(b) - int(a) + 1
            if self._limited("range_get", n):
                return
            self._stream(n)
        else:
            self._send(404, b"not found")

    def do_POST(self):
        parts = urlsplit(self.path)
        n = self._drain()
        if parts.path == "/__up" or parts.path.startswith("/speedtest/range/"):
            if self._limited("up" if parts.path == "/__up" else "range_post", n):
                return
            if self.up_ack_delay_s:
                time.sleep(self.up_ack_delay_s)
            self._send(200, b"ok")
        else:
            self._send(404, b"not found")


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):  # aborted downloads are expected
        pass


@pytest.fixture
def fake_server():
    srv = _QuietServer(("127.0.0.1", 0), _FakeHandler)
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    yield srv.server_address[0], srv.server_address[1]
    srv.shutdown()
    srv.server_close()
    t.join(2)


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------- base helpers

def test_math_helpers():
    assert base.median([]) is None
    assert base.median([3, 1, 2]) == 2
    assert base.median([4, 1, 3, 2]) == 2.5
    assert base.mean_abs_delta([]) is None
    assert base.mean_abs_delta([5.0]) == 0.0
    assert base.mean_abs_delta([10, 12, 9]) == pytest.approx(2.5)
    assert base.mbps(0, 1) is None
    assert base.mbps(1_000_000, 0) is None
    assert base.mbps(12_500_000, 1.0) == pytest.approx(100.0)


def test_speedresult_to_dict_and_db_roundtrip(db):
    r = SpeedResult(ok=True, ts=1.5e9, backend="x", download_mbps=1.5, raw={"a": 1})
    d = r.to_dict()
    assert d["ok"] is True and d["raw"] == {"a": 1} and d["backend"] == "x"
    rid = db.add_speedtest(d)
    row = db.last_speedtest()
    assert row["id"] == rid and row["download_mbps"] == 1.5 and json.loads(row["raw_json"]) == {"a": 1}


def test_budgets_from_config(cfg):
    b = base.budgets(cfg)
    assert b["download_bytes"] == 1_000_000 and b["upload_bytes"] == 1_000_000
    assert b["duration_s"] == 2 and b["connections"] == 2 and b["timeout_s"] == 120


def test_transfer_phase_byte_budget():
    calls = []
    phase = TransferPhase("download", duration_s=5, byte_budget=1_000_000, progress=lambda p, f: calls.append((p, f)))

    def worker(ph, idx):
        while ph.on_bytes(50_000):
            time.sleep(0.001)

    stats = phase.run(worker, 3)
    assert stats.bytes >= 1_000_000
    assert stats.mbps is not None and stats.mbps > 0
    assert stats.seconds < 3
    assert not stats.aborted
    assert calls[0] == ("download", 0.0) and calls[-1] == ("download", 1.0)
    assert all(0.0 <= f <= 1.0 for _, f in calls)


def test_transfer_phase_time_budget():
    phase = TransferPhase("upload", duration_s=0.5, byte_budget=10 ** 12)

    def worker(ph, idx):
        while ph.on_bytes(1000):
            time.sleep(0.005)

    t0 = time.perf_counter()
    stats = phase.run(worker, 2)
    assert 0.4 <= time.perf_counter() - t0 <= 2.0
    assert stats.name == "upload" and stats.bytes > 0 and stats.mbps


def test_transfer_phase_cancel():
    cancel = threading.Event()
    phase = TransferPhase("download", duration_s=10, byte_budget=10 ** 12, cancel=cancel)

    def worker(ph, idx):
        while ph.on_bytes(10):
            time.sleep(0.005)

    threading.Timer(0.1, cancel.set).start()
    t0 = time.perf_counter()
    stats = phase.run(worker, 2)
    assert time.perf_counter() - t0 < 2.0
    assert stats.aborted


def test_transfer_phase_acked_mode_counts_only_acknowledged_bytes():
    """Uploads: bytes handed to the kernel are not throughput; only acked ones count."""
    phase = TransferPhase("upload", duration_s=5, byte_budget=400_000, acked=True, tail_s=1.0)
    events = []

    def worker(ph, idx):
        # Each "request": push 100 kB instantly (kernel-buffered), the server acks 0.1 s later.
        while not ph.should_stop():
            for _ in range(10):
                if not ph.on_bytes(10_000):
                    return
            time.sleep(0.1)
            events.append(("ack", ph.ack(100_000)))
            ph.add_request()

    t0 = time.perf_counter()
    stats = phase.run(worker, 2)
    wall = time.perf_counter() - t0
    assert stats.acked_bytes == 400_000 and stats.bytes == 400_000
    assert stats.requests == 4 and not stats.aborted
    # the budget was pushed within milliseconds, but the figure covers the acks (>= 2 rounds x 0.1 s)
    assert stats.seconds >= 0.19
    assert stats.mbps == pytest.approx(400_000 * 8 / stats.seconds / 1e6, rel=1e-6)
    assert wall < 2.0
    assert all(ok for _, ok in events)


def test_transfer_phase_acked_mode_ignores_stragglers_after_tail():
    phase = TransferPhase("upload", duration_s=5, byte_budget=100_000, acked=True, tail_s=0.15)
    late = {}

    def fast(ph):
        while ph.on_bytes(50_000) and ph.remaining_bytes() > 0:
            pass
        ph.ack(100_000)          # completes at once

    def straggler(ph):
        ph.on_bytes(50_000)
        time.sleep(0.6)          # response arrives long after the tail
        late["ack"] = ph.ack(50_000)

    def worker(ph, idx):
        (fast if idx == 0 else straggler)(ph)

    t0 = time.perf_counter()
    stats = phase.run(worker, 2)
    assert time.perf_counter() - t0 < 1.5          # did not wait for the straggler
    assert stats.acked_bytes == 100_000 and stats.bytes == 150_000
    assert stats.mbps is not None
    assert wait_until(lambda: "ack" in late, timeout=2.0)
    assert late["ack"] is False                    # late ack rejected, figure unchanged


def test_transfer_phase_acked_mode_no_acks_means_no_figure():
    phase = TransferPhase("upload", duration_s=0.5, byte_budget=10 ** 9, acked=True, tail_s=0.1)

    def worker(ph, idx):
        while ph.on_bytes(10_000):
            time.sleep(0.005)

    stats = phase.run(worker, 2)
    assert stats.bytes > 0 and stats.acked_bytes == 0 and stats.mbps is None


def test_next_request_size():
    assert base.next_request_size(0, 1.0, 1.0, 64_000, 2_000_000) == 64_000
    assert base.next_request_size(100_000, 0.0, 1.0, 64_000, 2_000_000) == 64_000
    assert base.next_request_size(128_000, 2.0, 1.0, 64_000, 2_000_000) == 64_000     # 64 kB/s -> min
    assert base.next_request_size(500_000, 1.0, 1.0, 64_000, 2_000_000) == 500_000
    assert base.next_request_size(128_000, 0.01, 1.0, 64_000, 2_000_000) == 2_000_000  # fast -> cap
    assert base.next_request_size(10, 1.0, 1.0, 100, 50) == 100                        # lo wins over a bad hi


def test_run_guard_cancel_and_deadline():
    clock = FakeClock(100.0)
    cancel = threading.Event()
    g = base.RunGuard(cancel, 5.0, clock=clock)
    assert not g.is_set() and g.remaining() == 5.0 and g.socket_timeout() == 5.0
    base.check_cancel(g)
    clock.advance(4.5)
    assert g.socket_timeout() == 1.0                # never below 1 s, never past the deadline
    clock.advance(0.5)
    assert g.is_set() and g.timed_out and not g.cancelled
    assert g.reason().startswith("timed out after 5 s")
    with pytest.raises(base.Cancelled):
        base.check_cancel(g)
    cancel.set()
    assert g.cancelled and not g.timed_out and g.reason() == base.CANCELLED
    assert base.RunGuard.timeout_for(g) == 1.0
    assert base.RunGuard.timeout_for(threading.Event()) == base.SOCKET_TIMEOUT_S
    assert base.RunGuard.timeout_for(None) == base.SOCKET_TIMEOUT_S
    # TransferPhase accepts the guard as its cancel flag
    ph = TransferPhase("download", 5, 10 ** 9, cancel=g)
    assert ph.should_stop() and not ph.on_bytes(1)


# --------------------------------------------------------------------------- cloudflare parsing

def test_parse_trace():
    t = cloudflare.parse_trace("fl=1f2\nh=speed.cloudflare.com\nip=198.51.100.23\ncolo=AMS\nloc=NL\n\nbad line\n")
    assert t["ip"] == "198.51.100.23" and t["colo"] == "AMS" and t["loc"] == "NL"
    assert "bad line" not in t
    assert cloudflare.parse_trace("") == {}


def test_parse_server_timing():
    st_ = cloudflare.parse_server_timing('cfSpeedEdge;dur=5, cfSpeedWorker;dur=325, cfL4;desc="?proto=TCP&rtt=20156, x"')
    assert st_["cfSpeedEdge"]["dur"] == 5.0
    assert st_["cfSpeedWorker"]["dur"] == 325.0
    assert st_["cfL4"]["desc"] == "?proto=TCP&rtt=20156, x"
    assert cloudflare.parse_server_timing(None) == {}
    assert cloudflare.parse_server_timing("bogus;dur=abc") == {"bogus": {}}


def test_server_time_ms_and_edge_info():
    assert cloudflare.server_time_ms({"server-timing": "cfSpeedEdge;dur=5, cfSpeedWorker;dur=325"}) == 325.0
    assert cloudflare.server_time_ms({"server-timing": "cfRequestDuration;dur=12.5"}) == 12.5
    assert cloudflare.server_time_ms({}) == 0.0
    info = cloudflare.edge_tcp_info({"server-timing": 'cfL4;desc="?proto=TCP&rtt=20156&min_rtt=19000&rtt_var=500&lost=1&retrans=2"'})
    assert info["tcp_rtt_ms"] == pytest.approx(20.156)
    assert info["tcp_min_rtt_ms"] == 19.0 and info["tcp_lost"] == 1 and info["tcp_retrans"] == 2
    assert cloudflare.edge_tcp_info({}) == {}


# --------------------------------------------------------------------------- fast.com parsing

def test_fastcom_range_path_and_targets():
    assert fastcom.range_path("https://h.example/speedtest?c=us&x=1", 0, 1048575) == "/speedtest/range/0-1048575?c=us&x=1"
    assert fastcom.range_path("https://h.example/", 0, 0) == "/speedtest/range/0-0"
    client, targets = fastcom.parse_targets(json.dumps({
        "client": {"ip": "1.2.3.4", "asn": "64500", "location": {"city": "Elsewhere", "country": "US"}},
        "targets": [{"name": "n", "url": "https://ipv4-c001-any001-ix.1.oca.example.net/speedtest?c=us",
                     "location": {"city": "Anytown", "country": "US"}}, {"url": "garbage"}],
    }))
    assert client["ip"] == "1.2.3.4"
    assert len(targets) == 1
    t = targets[0]
    assert t["host"] == "ipv4-c001-any001-ix.1.oca.example.net" and t["scheme"] == "https" and t["port"] is None
    assert fastcom.describe_server(t) == "fast.com ipv4-c001-any001-ix (Anytown, US)"
    with pytest.raises(ValueError):
        fastcom.parse_targets({"targets": []})
    # a malformed port in one target URL skips that target instead of blowing up the parse
    _, targets = fastcom.parse_targets({"targets": [{"url": "https://h.example:abc/speedtest"},
                                                    {"url": "https://ok.example:8443/speedtest?c=us"}]})
    assert [t["host"] for t in targets] == ["ok.example"] and targets[0]["port"] == 8443


# --------------------------------------------------------------------------- HTTP backends against the fake server

def test_cloudflare_backend_local(cfg, fake_server, monkeypatch):
    host, port = fake_server
    monkeypatch.setattr(cloudflare, "HOST", host)
    monkeypatch.setattr(cloudflare, "PORT", port)
    monkeypatch.setattr(cloudflare, "SCHEME", "http")
    prog = []
    res = cloudflare.CloudflareBackend().run(cfg, progress=lambda p, f: prog.append((p, f)))
    assert res.ok, res.error
    assert res.backend == "cloudflare"
    assert res.server == "Cloudflare TST" and res.external_ip == "203.0.113.5"
    assert res.download_mbps and res.download_mbps > 0
    assert res.upload_mbps and res.upload_mbps > 0
    assert res.latency_ms is not None and res.jitter_ms is not None
    assert res.raw["download"]["bytes"] >= 1_000_000 and res.raw["upload"]["bytes"] >= 1_000_000
    assert len(res.raw["latency_samples_ms"]) == cloudflare.LATENCY_COUNT
    assert res.raw["tcp_min_rtt_ms"] == 1.2
    phases = {p for p, _ in prog}
    assert {"connect", "latency", "download", "upload", "done"} <= phases
    assert all(0.0 <= f <= 1.0 for _, f in prog) and prog[-1] == ("done", 1.0)
    assert res.duration_s > 0
    # the result is persistable as-is
    d = res.to_dict()
    assert isinstance(d["raw"], dict)


def test_cloudflare_backend_failure_and_cancel(cfg, monkeypatch):
    monkeypatch.setattr(cloudflare, "HOST", "127.0.0.1")
    monkeypatch.setattr(cloudflare, "PORT", _closed_port())
    monkeypatch.setattr(cloudflare, "SCHEME", "http")
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.ok is False and res.error
    cancel = threading.Event()
    cancel.set()
    res = cloudflare.CloudflareBackend().run(cfg, cancel=cancel)
    assert res.ok is False and res.error == "cancelled"


def test_cloudflare_available(cfg):
    ok, detail = cloudflare.CloudflareBackend().available(cfg)
    assert ok and "cloudflare" in detail


def test_cloudflare_upload_is_not_inflated_by_buffered_bytes(cfg, fake_server, monkeypatch):
    """A server that takes 0.3 s to acknowledge each body: the upload figure must
    cover the acks, not the instant at which the bytes left the client."""
    host, port = fake_server
    monkeypatch.setattr(cloudflare, "HOST", host)
    monkeypatch.setattr(cloudflare, "PORT", port)
    monkeypatch.setattr(cloudflare, "SCHEME", "http")
    monkeypatch.setattr(_FakeHandler, "up_ack_delay_s", 0.3)
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.ok, res.error
    up = res.raw["upload"]
    assert up["acked_bytes"] > 0 and up["bytes"] >= up["acked_bytes"]
    assert up["seconds"] >= 0.3                                  # first ack cannot land earlier
    assert res.upload_mbps == pytest.approx(up["acked_bytes"] * 8 / up["seconds"] / 1e6, rel=0.01)
    # pushing 1 MB to localhost takes milliseconds; the old accounting would report thousands of Mbps
    assert res.upload_mbps < 100


def test_cloudflare_run_is_bounded_by_timeout_s(cfg, fake_server, monkeypatch):
    """A server that trickles bytes must not hold the run past speedtest.timeout_s."""
    host, port = fake_server
    monkeypatch.setattr(cloudflare, "HOST", host)
    monkeypatch.setattr(cloudflare, "PORT", port)
    monkeypatch.setattr(cloudflare, "SCHEME", "http")
    monkeypatch.setattr(_FakeHandler, "down_trickle_s", 0.2)          # 1 MB = 16 chunks = ~3 s per request
    real = base.budgets
    monkeypatch.setattr(cloudflare, "budgets", lambda c: {**real(c), "timeout_s": 1.0, "duration_s": 30})
    t0 = time.perf_counter()
    res = cloudflare.CloudflareBackend().run(cfg)
    assert time.perf_counter() - t0 < 6
    assert res.ok is False and res.error.startswith("timed out after 1 s")
    assert res.error != base.CANCELLED
    assert res.raw["download"]["bytes"] > 0                           # it was mid-download when it hit


def test_fastcom_backend_local(cfg, fake_server, monkeypatch):
    host, port = fake_server
    monkeypatch.setattr(fastcom, "API_HOST", host)
    monkeypatch.setattr(fastcom, "API_PORT", port)
    monkeypatch.setattr(fastcom, "API_SCHEME", "http")
    prog = []
    res = fastcom.FastComBackend().run(cfg, progress=lambda p, f: prog.append((p, f)))
    assert res.ok, res.error
    assert res.backend == "fastcom"
    assert res.server.startswith("fast.com") and "Anytown" in res.server
    assert res.external_ip == "203.0.113.9" and res.isp == "AS64500"
    assert res.download_mbps and res.download_mbps > 0
    assert res.upload_mbps and res.upload_mbps > 0
    assert res.latency_ms is not None
    assert len(res.raw["targets"]) == 2
    assert prog[-1] == ("done", 1.0)


def test_fastcom_backend_failure(cfg, monkeypatch):
    monkeypatch.setattr(fastcom, "API_HOST", "127.0.0.1")
    monkeypatch.setattr(fastcom, "API_PORT", _closed_port())
    monkeypatch.setattr(fastcom, "API_SCHEME", "http")
    res = fastcom.FastComBackend().run(cfg)
    assert res.ok is False and res.error


def test_speed_tests_start_no_process(cfg, fake_server, monkeypatch):
    """Both backends are built in and run inside the LocalSystem service: selecting, checking and
    running them (the one-shot runner included) starts no program (README "Security model")."""
    import os
    import subprocess

    spawned = []

    def refuse(name):
        def spawn(*args, **kwargs):
            spawned.append((name, args))
            raise AssertionError(f"a speed test started a process via {name}")
        return spawn

    monkeypatch.setattr(subprocess, "Popen", refuse("subprocess.Popen"))     # run/call/check_output go through Popen
    for name in ("system", "startfile", "spawnv", "spawnve", "execv", "execve"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, refuse(f"os.{name}"))
    host, port = fake_server
    monkeypatch.setattr(cloudflare, "HOST", host)
    monkeypatch.setattr(cloudflare, "PORT", port)
    monkeypatch.setattr(cloudflare, "SCHEME", "http")
    monkeypatch.setattr(fastcom, "API_HOST", host)
    monkeypatch.setattr(fastcom, "API_PORT", port)
    monkeypatch.setattr(fastcom, "API_SCHEME", "http")

    assert [b["name"] for b in st.available_backends(cfg)] == ["cloudflare", "fastcom"]
    for backend in ("cloudflare", "fastcom"):
        cfg.update({"speedtest": {"backend": backend}}, persist=False)
        assert st.select_backend(cfg).name == backend
        res = st.run_speedtest(cfg)
        assert res.ok, res.error
        assert res.backend == backend and res.download_mbps > 0
    assert spawned == []


# --------------------------------------------------------------------------- selection / runner

def test_select_backend_auto_uses_the_built_in_backends_in_order(cfg):
    assert cfg.get("speedtest.backend") == "auto"
    assert st.select_backend(cfg).name == "cloudflare"
    assert st.BACKEND_ORDER == ("cloudflare", "fastcom") and set(st.BACKENDS) == set(st.BACKEND_ORDER)
    assert st.DEFAULT_BACKEND == st.BACKEND_ORDER[0]


def test_select_backend_explicit_and_fallback(cfg, monkeypatch):
    cfg.update({"speedtest": {"backend": "fastcom"}}, persist=False)
    assert st.select_backend(cfg).name == "fastcom"
    cfg.update({"speedtest": {"backend": "cloudflare"}}, persist=False)
    assert st.select_backend(cfg).name == "cloudflare"
    # an explicit backend that cannot run falls back to the other one
    monkeypatch.setattr(cloudflare.CloudflareBackend, "available", lambda self, c: (False, "fake outage"))
    assert st.select_backend(cfg).name == "fastcom"
    assert st.get_backend("fastcom") is st.BACKENDS["fastcom"] and st.get_backend("nope") is None
    assert isinstance(st.BACKENDS["cloudflare"], base.SpeedBackend)


def test_select_backend_unknown_name_falls_back_to_the_first_available(monkeypatch):
    """A name no backend answers to (only reachable without Config's validation) never raises."""
    class RawConfig:
        def __init__(self, values):
            self.values = values

        def get(self, key, default=None):
            return self.values.get(key, default)

    assert st.select_backend(RawConfig({"speedtest.backend": "retired"})).name == "cloudflare"
    monkeypatch.setattr(cloudflare.CloudflareBackend, "available", lambda self, c: (False, "fake outage"))
    assert st.select_backend(RawConfig({"speedtest.backend": "retired"})).name == "fastcom"


def test_available_backends_shape(cfg):
    lst = st.available_backends(cfg)
    assert [b["name"] for b in lst] == ["cloudflare", "fastcom"]
    assert all(set(b) == {"name", "available", "detail", "cooldown_until"} for b in lst)
    assert lst[0]["available"] and lst[1]["available"]
    assert all(b["cooldown_until"] is None for b in lst)


def test_run_speedtest_never_raises(cfg, monkeypatch):
    class Boom:
        name = "boom"

        def available(self, c):
            return True, ""

        def run(self, c, progress=None, cancel=None):
            raise RuntimeError("kaboom")

    monkeypatch.setattr(sched_mod, "select_backend", lambda c: Boom())
    res = st.run_speedtest(cfg)
    assert res.ok is False and "kaboom" in res.error and res.backend == "boom"

    class NoResult(Boom):
        def run(self, c, progress=None, cancel=None):
            return None

    monkeypatch.setattr(sched_mod, "select_backend", lambda c: NoResult())
    res = st.run_speedtest(cfg)
    assert res.ok is False and res.error


# --------------------------------------------------------------------------- patterns

NOW = (1_800_000_000 // 86400) * 86400  # midnight UTC


def _rows(now, days=7, step=900, down=None, up=20.0, lat=None):
    start = now - days * 86400
    rows = []
    for i in range(int(days * 86400 / step)):
        ts = start + i * step
        hour = int((ts % 86400) // 3600)
        day = (ts - start) // 86400
        weekday = (int(ts // 86400) + 3) % 7
        d = down(ts, hour, day, weekday) if down else 100.0
        l = lat(ts, hour, day, weekday) if lat else 15.0
        rows.append({"id": i, "ts": float(ts), "ok": True, "backend": "fake", "server": None, "isp": None,
                     "external_ip": None, "latency_ms": l, "jitter_ms": 1.0, "download_mbps": d,
                     "upload_mbps": up, "packet_loss_pct": None, "duration_s": 5.0, "error": None})
    return rows


def _failed(ts):
    return {"id": 9999, "ts": float(ts), "ok": False, "backend": "fake", "download_mbps": None,
            "upload_mbps": None, "latency_ms": None, "error": "boom"}


def test_patterns_hour_slowdown_failures_slow_tests():
    rows = _rows(NOW, down=lambda ts, h, d, w: 60.0 if h in (19, 20, 21) else 100.0)
    rows += [_failed(NOW - 3600), _failed(NOW - 7200), _failed(NOW - 10800)]
    for k, days_back in enumerate((6, 1)):  # two very slow tests at 10:00, placed symmetrically so the trend stays flat
        rows.append({**rows[0], "id": 5000 + k, "ts": float(NOW - days_back * 86400 + 10 * 3600 + 1), "download_mbps": 30.0})
    p = patterns.analyse_patterns(rows, NOW, 50, 0, days=7)
    assert p["days"] == 7
    assert p["count"] == 672 + 5 and p["ok_count"] == 674
    assert p["median_down"] == 100.0 and p["median_up"] == 20.0
    assert p["min_down"]["value"] == 30.0 and p["max_down"]["value"] == 100.0
    assert len(p["by_hour"]) == 24 and [b["hour"] for b in p["by_hour"]] == list(range(24))
    assert p["by_hour"][19]["avg_down"] == 60.0 and p["by_hour"][3]["avg_down"] == 100.0
    assert p["by_hour"][3]["avg_up"] == 20.0 and p["by_hour"][3]["avg_latency"] == 15.0
    assert sum(b["count"] for b in p["by_hour"]) == 674
    assert len(p["by_weekday"]) == 7 and sum(b["count"] for b in p["by_weekday"]) == 674
    assert len(p["slow_tests"]) == 2
    assert all(s["pct_of_median"] == 30.0 and s["download_mbps"] == 30.0 for s in p["slow_tests"])
    assert p["slow_tests"][0]["ts"] > p["slow_tests"][1]["ts"]
    findings = p["findings"]
    hour_f = [f for f in findings if "slower between 19:00 and 22:00" in f]
    assert hour_f and "~40%" in hour_f[0]
    assert "3 tests failed in the last 7 days." in findings
    assert any(f.startswith("2 tests came in below 50%") for f in findings)
    assert abs(p["trend_down_pct_per_day"]) < 0.5


def test_patterns_trend_sign():
    down_trend = patterns.analyse_patterns(_rows(NOW, down=lambda ts, h, d, w: 100.0 - 3.0 * d), NOW, 50, 0, days=7)
    assert down_trend["trend_down_pct_per_day"] < -1.0
    assert any("trending down" in f for f in down_trend["findings"])
    up_trend = patterns.analyse_patterns(_rows(NOW, down=lambda ts, h, d, w: 80.0 + 3.0 * d), NOW, 50, 0, days=7)
    assert up_trend["trend_down_pct_per_day"] > 1.0
    assert any("trending up" in f for f in up_trend["findings"])
    flat = patterns.analyse_patterns(_rows(NOW), NOW, 50, 0, days=7)
    assert flat["trend_down_pct_per_day"] == 0.0
    assert "Speeds look consistent across the day and week." in flat["findings"]


def test_patterns_weekday_latency_asymmetry():
    rows = _rows(NOW, down=lambda ts, h, d, w: 50.0 if w == 5 else 100.0, up=5.0,
                 lat=lambda ts, h, d, w: 200.0 if (h == 12 and ts % 3600 == 0 and d < 5) else 15.0)  # 1 spike/day x 5 days
    p = patterns.analyse_patterns(rows, NOW, 50, 0, days=7)
    assert any("slower on Saturdays" in f and "~50%" in f for f in p["findings"])
    assert not any("slower between" in f for f in p["findings"])
    assert any(f.startswith("Latency spiked in 5 tests") for f in p["findings"])
    assert any(f.startswith("Upload (~5.0 Mbps) is under 10%") for f in p["findings"])
    assert p["by_weekday"][5]["avg_down"] == 50.0 and p["by_weekday"][5]["name"] == "Saturday"


def test_patterns_empty_and_sparse():
    p = patterns.analyse_patterns([], NOW, 50, 0)
    assert p["count"] == 0 and p["ok_count"] == 0 and p["days"] == 7
    assert p["median_down"] is None and p["min_down"] is None and p["max_down"] is None
    assert len(p["by_hour"]) == 24 and all(b["count"] == 0 and b["avg_down"] is None for b in p["by_hour"])
    assert p["slow_tests"] == [] and p["trend_down_pct_per_day"] == 0.0
    assert p["findings"] == ["No speed tests in the last 7 days."]
    sparse = patterns.analyse_patterns(_rows(NOW)[:3], NOW, 50, 0, days=1)
    assert sparse["count"] == 3 and any("Not enough tests" in f for f in sparse["findings"])
    only_failed = patterns.analyse_patterns([_failed(NOW - 10)], NOW, 50, 0, days=1)
    assert only_failed["findings"][0].startswith("All 1 speed tests")
    # garbage rows are ignored, days derived from the span when not given
    p = patterns.analyse_patterns([None, {"ok": True}, {"ts": NOW - 3 * 86400 - 5, "ok": True, "download_mbps": 10}], NOW, 50, 0)
    assert p["count"] == 1 and p["days"] == 4


def test_patterns_tz_offset_buckets():
    row = {"ts": float(NOW + 12 * 3600), "ok": True, "download_mbps": 50.0, "upload_mbps": 10.0, "latency_ms": 20.0}
    p = patterns.analyse_patterns([row], NOW + 13 * 3600, 50, -18000, days=1)  # UTC-5 -> 07:00 local
    assert p["by_hour"][7]["count"] == 1 and p["by_hour"][12]["count"] == 0
    p = patterns.analyse_patterns([row], NOW + 13 * 3600, 50, 0, days=1)
    assert p["by_hour"][12]["count"] == 1


# --------------------------------------------------------------------------- scheduler

class FakeBackend:
    name = "fake"

    def __init__(self, block=False, ok=True):
        self.calls = []
        self.gate = threading.Event()
        self.started = threading.Event()
        self.block = block
        self.ok = ok

    def available(self, config):
        return True, "fake"

    def run(self, config, progress=None, cancel=None):
        self.calls.append(time.time())
        self.started.set()
        if progress:
            progress("latency", 0.5)
            progress("download", 0.25)
            progress("download", 0.251)   # below the change threshold -> not re-published
            progress("download", 1.0)
        if self.block:
            while not self.gate.is_set() and not (cancel is not None and cancel.is_set()):
                time.sleep(0.01)
        if not self.ok:
            return SpeedResult(ok=False, ts=time.time(), backend="fake", error="fake failure", duration_s=0.1)
        return SpeedResult(ok=True, ts=time.time(), backend="fake", server="Fake", download_mbps=100.0,
                           upload_mbps=20.0, latency_ms=10.0, jitter_ms=1.0, duration_s=1.0, raw={"x": 1})


@pytest.fixture
def fake_backend(monkeypatch):
    fb = FakeBackend()
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: fb)
    return fb


def _events(bus):
    seen = []
    bus.subscribe(seen.append)
    return seen


def test_scheduler_runs_on_schedule(db, cfg, bus, fake_backend):
    cfg.update({"speedtest": {"interval_min": 5}}, persist=False)
    clock = FakeClock(1_000_000.0)
    events = _events(bus)
    s = st.SpeedScheduler(db, cfg, bus, clock=clock, poll_s=0.01)
    s.start()
    try:
        assert s.next_run_ts == 1_000_060.0
        assert not s.running and s.last_result is None
        clock.advance(59)
        time.sleep(0.15)
        assert fake_backend.calls == []
        clock.advance(1)
        assert wait_until(lambda: len(fake_backend.calls) == 1)
        assert wait_until(lambda: not s.running and s.last_result is not None)
        assert s.next_run_ts == 1_000_060.0 + 300.0
        rows = db.list_speedtests(0, 2e9)
        assert len(rows) == 1 and rows[0]["ts"] == 1_000_060.0 and rows[0]["download_mbps"] == 100.0
        assert rows[0]["backend"] == "fake" and rows[0]["ok"] is True
        types = [e["type"] for e in events]
        assert types[0] == "speedtest.start"
        assert types.count("speedtest.done") == 1
        assert types.count("speedtest.progress") == 3          # latency 0.5, download 0.25, download 1.0 (0.251 deduped)
        start = next(e for e in events if e["type"] == "speedtest.start")
        assert start["data"]["backend"] == "fake" and start["data"]["trigger"] == "scheduled" and start["data"]["ts"] == 1_000_060.0
        done = next(e for e in events if e["type"] == "speedtest.done")
        assert done["data"]["result"]["download_mbps"] == 100.0 and done["data"]["result"]["id"] == rows[0]["id"]
        assert done["data"]["result"]["ts"] == 1_000_060.0
        assert s.last_result["id"] == rows[0]["id"] and s.progress == {"phase": "idle", "pct": 0.0}
        # interval change applies at the next tick; second run at the scheduled time
        cfg.update({"speedtest": {"interval_min": 10}}, persist=False)
        assert s.next_run_ts == 1_000_360.0
        clock.advance(300)
        assert wait_until(lambda: len(fake_backend.calls) == 2)
        assert wait_until(lambda: not s.running)
        assert s.next_run_ts == 1_000_360.0 + 600.0
        assert len(db.list_speedtests(0, 2e9)) == 2
    finally:
        s.stop()
    assert not s.running


def test_scheduler_progress_events_dedup(db, cfg, bus, fake_backend):
    clock = FakeClock(0.0)
    events = _events(bus)
    s = st.SpeedScheduler(db, cfg, bus, clock=clock, poll_s=0.01)
    s.start()
    try:
        clock.advance(60)
        assert wait_until(lambda: any(e["type"] == "speedtest.done" for e in events))
        prog = [(e["data"]["phase"], e["data"]["pct"]) for e in events if e["type"] == "speedtest.progress"]
        assert prog == [("latency", 0.5), ("download", 0.25), ("download", 1.0)]
    finally:
        s.stop()


def test_scheduler_run_now_and_running_flag(db, cfg, bus, monkeypatch):
    fb = FakeBackend(block=True)
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: fb)
    cfg.update({"speedtest": {"interval_min": 15}}, persist=False)
    clock = FakeClock(5_000.0)
    events = _events(bus)
    s = st.SpeedScheduler(db, cfg, bus, clock=clock, poll_s=0.01)
    s.start()
    try:
        assert s.run_now() is True
        assert fb.started.wait(2)
        assert s.running is True
        assert s.run_now() is False
        assert s.status()["running"] is True and s.status()["progress"]["phase"] == "download"
        # a scheduled tick while the manual run is in progress is skipped, not queued
        clock.advance(60)
        assert wait_until(lambda: any(e["type"] == "speedtest.skipped" for e in events))
        skipped = next(e for e in events if e["type"] == "speedtest.skipped")
        assert "already running" in skipped["data"]["reason"]
        assert len(fb.calls) == 1
        clock.advance(100)
        fb.gate.set()
        assert wait_until(lambda: not s.running)
        assert s.run_now() is True
        assert wait_until(lambda: len(fb.calls) == 2)
        fb.gate.set()
        assert wait_until(lambda: not s.running)
        # manual runs push the next scheduled run out by one interval
        assert s.next_run_ts == 5_160.0 + 15 * 60
        assert len(db.list_speedtests(0, 2e9)) == 2
        done = [e for e in events if e["type"] == "speedtest.done"]
        assert len(done) == 2 and all(e["data"]["trigger"] == "manual" for e in done)
    finally:
        s.stop()


def test_scheduler_stop_cancels_running_test(db, cfg, bus, monkeypatch):
    fb = FakeBackend(block=True)
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: fb)
    s = st.SpeedScheduler(db, cfg, bus, clock=FakeClock(0.0), poll_s=0.01)
    s.start()
    assert s.run_now()
    assert fb.started.wait(2)
    t0 = time.perf_counter()
    s.stop()
    assert time.perf_counter() - t0 < 3
    assert not s.running
    assert not any(t.name in ("speedtest-scheduler", "speedtest-run") and t.is_alive() for t in threading.enumerate())


class CancelAwareBackend(FakeBackend):
    """Blocks until cancelled and then answers like the real backends do."""

    def run(self, config, progress=None, cancel=None):
        self.calls.append(time.time())
        self.started.set()
        while not (cancel is not None and cancel.is_set()) and not self.gate.is_set():
            time.sleep(0.01)
        if cancel is not None and cancel.is_set():
            return base.failed_result("fake", time.time(), base.CANCELLED, 0.1)
        return SpeedResult(ok=True, ts=time.time(), backend="fake", download_mbps=1.0)


def test_scheduler_cancelled_run_is_not_recorded_as_a_failure(db, cfg, bus, monkeypatch):
    fb = CancelAwareBackend()
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: fb)
    events = _events(bus)
    s = st.SpeedScheduler(db, cfg, bus, clock=FakeClock(0.0), poll_s=0.01)
    s.start()
    assert s.run_now() and fb.started.wait(2)
    s.stop()
    assert wait_until(lambda: any(e["type"] == "speedtest.done" for e in events))
    done = next(e for e in events if e["type"] == "speedtest.done")
    assert done["data"]["result"]["error"] == "cancelled" and "id" not in done["data"]["result"]
    assert db.list_speedtests(0, 2e9) == []                 # no history row ...
    assert db.list_events(10) == []                          # ... and no "speed test failed" event
    assert s.last_result is None and not s.running
    # a genuine failure after a restart is still recorded
    fb2 = FakeBackend(ok=False)
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: fb2)
    s.start()
    try:
        assert s.run_now()
        assert wait_until(lambda: not s.running and s.last_result is not None)
        assert len(db.list_speedtests(0, 2e9)) == 1 and db.list_events(10)[0]["level"] == "warning"
    finally:
        s.stop()


def test_scheduler_run_now_releases_flag_when_thread_cannot_start(db, cfg, bus, fake_backend):
    s = st.SpeedScheduler(db, cfg, bus, clock=FakeClock(0.0), poll_s=0.01)

    def boom(self):
        raise RuntimeError("can't start new thread")

    with pytest.MonkeyPatch.context() as mp:          # scoped: keeps the fake_backend patch intact
        mp.setattr(threading.Thread, "start", boom)
        with pytest.raises(RuntimeError):
            s.run_now()
    assert not s.running and s.progress == {"phase": "idle", "pct": 0.0}
    assert s.run_now() is True                                # not stuck on "already running"
    assert wait_until(lambda: not s.running and s.last_result is not None)
    assert len(fake_backend.calls) == 1


def test_scheduler_start_event_names_the_backend_that_runs(db, cfg, bus, monkeypatch):
    """select_backend is consulted once per run: the start event and the run agree."""
    picks = []
    fb = FakeBackend()

    def select(c):
        picks.append(1)
        return fb

    monkeypatch.setattr(sched_mod, "select_backend", select)
    events = _events(bus)
    s = st.SpeedScheduler(db, cfg, bus, clock=FakeClock(0.0), poll_s=0.01)
    picks.clear()
    assert s.run_now()
    assert wait_until(lambda: any(e["type"] == "speedtest.done" for e in events))
    assert len(picks) == 1
    assert next(e for e in events if e["type"] == "speedtest.start")["data"]["backend"] == "fake"


def test_scheduler_skips_when_disabled_or_internet_down(db, cfg, bus, fake_backend):
    cfg.update({"speedtest": {"enabled": False, "interval_min": 1}}, persist=False)
    clock = FakeClock(100.0)
    events = _events(bus)
    down = {"value": False}
    s = st.SpeedScheduler(db, cfg, bus, clock=clock, poll_s=0.01, internet_down=lambda: down["value"])
    s.start()
    try:
        clock.advance(60)
        assert wait_until(lambda: any(e["type"] == "speedtest.skipped" for e in events))
        assert events[-1]["data"]["reason"] == "disabled"
        assert s.next_run_ts == 160.0 + 60.0
        assert fake_backend.calls == [] and db.list_speedtests(0, 2e9) == []
        assert s.status()["enabled"] is False
        cfg.update({"speedtest": {"enabled": True}}, persist=False)
        down["value"] = True
        clock.advance(60)
        assert wait_until(lambda: len([e for e in events if e["type"] == "speedtest.skipped"]) == 2)
        assert events[-1]["data"]["reason"] == "internet outage"
        assert fake_backend.calls == [] and db.list_speedtests(0, 2e9) == []
        down["value"] = False
        clock.advance(60)
        assert wait_until(lambda: len(fake_backend.calls) == 1)
        assert wait_until(lambda: not s.running)
        assert len(db.list_speedtests(0, 2e9)) == 1
    finally:
        s.stop()


def test_scheduler_status_history_patterns_and_failure_event(db, cfg, bus, monkeypatch):
    fb = FakeBackend(ok=False)
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: fb)
    now = float(NOW + 12 * 3600)
    # pre-existing history is exposed as "last" on start
    for i in range(5):
        db.add_speedtest({"ts": now - 3600 * (i + 1), "ok": True, "backend": "cloudflare", "download_mbps": 100 + i,
                          "upload_mbps": 20, "latency_ms": 12, "raw": {"seed": i}})
    clock = FakeClock(now)
    s = st.SpeedScheduler(db, cfg, bus, clock=clock, poll_s=0.01)
    s.start()
    try:
        status = s.status()
        assert set(status) == {"enabled", "running", "next_run_ts", "last", "backend", "interval_min", "progress",
                               "effective_interval_min", "interval_reason"}
        assert status["enabled"] is True and status["running"] is False and status["backend"] == "fake"
        assert status["interval_min"] == 15 and status["next_run_ts"] == now + 60
        assert status["effective_interval_min"] == 15 and status["interval_reason"] is None
        assert status["last"]["download_mbps"] == 100 and status["last"]["raw"] == {"seed": 0}
        assert "raw_json" not in status["last"] and status["last"]["ok"] is True
        hist = s.history(now - 86400, now)
        assert len(hist) == 5 and hist[0]["ts"] > hist[-1]["ts"] and "raw_json" not in hist[0]
        assert len(s.history(now - 86400, now, limit=2)) == 2
        p = s.patterns(days=1, now=now)
        assert p["days"] == 1 and p["count"] == 5 and p["median_down"] == 102.0
        assert len(p["by_hour"]) == 24
        # a failed run is persisted, becomes "last" and writes a warning event
        clock.advance(60)
        assert wait_until(lambda: s.status()["last"]["ok"] is False)
        assert wait_until(lambda: not s.running)
        last = db.last_speedtest()
        assert last["ok"] is False and last["error"] == "fake failure" and last["ts"] == now + 60
        ev = db.list_events(5)
        assert ev and ev[0]["category"] == "speedtest" and ev[0]["level"] == "warning" and "fake failure" in ev[0]["message"]
        assert s.patterns(days=1, now=now + 61)["ok_count"] == 5
        assert s.patterns(days=1, now=now + 61)["count"] == 6
    finally:
        s.stop()


def test_scheduler_restart_and_loop_survives_errors(db, cfg, bus, fake_backend, monkeypatch):
    clock = FakeClock(0.0)
    s = st.SpeedScheduler(db, cfg, bus, clock=clock, poll_s=0.01)
    s.start()
    s.start()  # idempotent
    s.stop()
    s.start()
    try:
        assert s.next_run_ts == 60.0
        # a broken db must not kill the loop
        monkeypatch.setattr(db, "add_speedtest", lambda d: (_ for _ in ()).throw(RuntimeError("db down")))
        clock.advance(60)
        assert wait_until(lambda: len(fake_backend.calls) == 1)
        assert wait_until(lambda: not s.running)
        assert s.last_result is not None and "id" not in s.last_result
        assert s.next_run_ts == 60.0 + 15 * 60
    finally:
        s.stop()


def test_local_tz_offset():
    off = st.local_tz_offset_s(time.time())
    assert isinstance(off, int) and -14 * 3600 <= off <= 14 * 3600


def test_package_exports():
    for name in ("SpeedResult", "SpeedBackend", "CloudflareBackend", "FastComBackend",
                 "available_backends", "select_backend", "run_speedtest", "SpeedScheduler", "analyse_patterns"):
        assert hasattr(st, name), name
    assert st.CloudflareBackend.name == "cloudflare"
    assert st.FastComBackend.name == "fastcom"
    assert sorted(st.BACKENDS) == ["cloudflare", "fastcom"]


# --------------------------------------------------------------------------- history from older releases

def test_results_of_a_removed_backend_still_load_and_report(db, cfg, bus, caplog):
    """Rows saved by 1.6.x's external speed-test CLI backend ("ookla") stay readable after the
    upgrade: history, the scheduler's last result, patterns and the PDF report treat the stored
    backend name as a plain label, and selection is unaffected."""
    from tnt import export_pdf

    now = 1_800_000_000.0
    old = {"ts": now - 3600, "ok": True, "backend": "ookla", "server": "Example ISP (Springfield, United States)",
           "isp": "Example Fiber", "external_ip": "203.0.113.7", "latency_ms": 12.57, "jitter_ms": 1.23,
           "download_mbps": 100.0, "upload_mbps": 20.0, "packet_loss_pct": 0.5, "duration_s": 31.2, "error": None,
           "raw": {"type": "result", "download": {"bandwidth": 12500000}, "result": {"id": "abcd-1234"}}}
    rid = db.add_speedtest(old)
    rows = db.list_speedtests(now - 7200, now)
    assert [(r["id"], r["backend"], r["download_mbps"]) for r in rows] == [(rid, "ookla", 100.0)]
    assert db.last_speedtest()["backend"] == "ookla"

    s = st.SpeedScheduler(db, cfg, bus, clock=FakeClock(now), poll_s=0.01)
    s.start()
    try:
        status = s.status()
        assert status["last"]["backend"] == "ookla" and status["last"]["ok"] is True
        assert status["last"]["raw"]["result"]["id"] == "abcd-1234"
        assert status["backend"] == "cloudflare"
        assert [r["backend"] for r in s.history(now - 7200, now)] == ["ookla"]
        p = s.patterns(days=7, now=now)
        assert p["count"] == 1 and p["median_down"] == 100.0
    finally:
        s.stop()

    assert export_pdf._gather_speed(db, now - 7200, now, export_pdf._Clock(0))["backends"] == {"ookla": 1}
    with caplog.at_level("ERROR", logger="tnt.export_pdf"):
        pdf = export_pdf.build_report(db, now - 86400, now, tz_offset_s=0)
    assert pdf.startswith(b"%PDF") and not [r for r in caplog.records if r.levelname == "ERROR"]


# --------------------------------------------------------------------------- rate limiting

def _point_cloudflare(monkeypatch, fake_server):
    host, port = fake_server
    monkeypatch.setattr(cloudflare, "HOST", host)
    monkeypatch.setattr(cloudflare, "PORT", port)
    monkeypatch.setattr(cloudflare, "SCHEME", "http")


def _point_fastcom(monkeypatch, fake_server):
    host, port = fake_server
    monkeypatch.setattr(fastcom, "API_HOST", host)
    monkeypatch.setattr(fastcom, "API_PORT", port)
    monkeypatch.setattr(fastcom, "API_SCHEME", "http")


def _limit(monkeypatch, status, scope, min_bytes=0, retry_after=None):
    monkeypatch.setattr(_FakeHandler, "limit_status", status)
    monkeypatch.setattr(_FakeHandler, "limit_scope", frozenset(scope))
    monkeypatch.setattr(_FakeHandler, "limit_min_bytes", min_bytes)
    monkeypatch.setattr(_FakeHandler, "limit_retry_after", retry_after)
    hits = []
    monkeypatch.setattr(_FakeHandler, "limit_hits", hits)
    return hits


def test_parse_retry_after_seconds_and_http_date():
    assert base.parse_retry_after(None) is None and base.parse_retry_after("") is None
    assert base.parse_retry_after("3400") == 3400
    assert base.parse_retry_after(" 12.9 ") == 12
    assert base.parse_retry_after("-5") == 0
    assert base.parse_retry_after("soon") is None and base.parse_retry_after("nan") is None
    now = 1_800_000_000.0
    future = email.utils.formatdate(now + 600, usegmt=True)            # IMF-fixdate, e.g. "Wed, 21 Oct 2015 07:28:00 GMT"
    assert base.parse_retry_after(future, now=now) in (599, 600)
    assert base.parse_retry_after(email.utils.formatdate(now - 600, usegmt=True), now=now) == 0
    assert base.parse_retry_after("Sunday, 06-Nov-94 08:49:37 GMT", now=now) == 0     # obsolete RFC 850 form, in the past
    # policy: default when absent, floor and cap when present
    assert base.retry_after_s(None) == base.DEFAULT_RETRY_AFTER_S == 900
    assert base.retry_after_s("garbage") == 900
    assert base.retry_after_s("3400") == 3400
    assert base.retry_after_s("7200") == base.MAX_RETRY_AFTER_S == 3600
    assert base.retry_after_s("0") == base.MIN_RETRY_AFTER_S == 60
    assert base.retry_after_s(future, now=now) in (599, 600)
    assert base.clamp_retry_after(None) == 900 and base.clamp_retry_after(float("nan")) == 900
    assert base.clamp_retry_after("120") == 120
    err = base.HttpError(429, "/x", "slow", headers={"retry-after": "42"})
    assert err.rate_limited and err.retry_after == 42 and err.detail == "slow"
    assert base.HttpError(403, "/x").rate_limited and not base.HttpError(500, "/x").rate_limited
    assert base.HttpError(429, "/x").retry_after is None


def test_cooldown_registry_and_backend_availability(cfg, monkeypatch):
    now = 1_800_000_000.0
    clock = FakeClock(now)
    monkeypatch.setattr(base, "cooldown_clock", clock)
    assert base.get_cooldown("cloudflare") is None and base.all_cooldowns() == {}
    cd = base.set_cooldown("cloudflare", 3400, status=429)
    assert cd.backend == "cloudflare" and cd.since == now and cd.until == now + 3400 and cd.status == 429
    assert cd.remaining() == 3400
    expect = "cooling down after HTTP 429 until " + time.strftime("%H:%M", time.localtime(now + 3400))
    assert cd.describe() == expect
    assert cloudflare.CloudflareBackend().available(cfg) == (False, expect)
    assert fastcom.FastComBackend().available(cfg)[0] is True
    # extend-only: a shorter cooldown never cuts an existing one short, a longer one extends it
    assert base.set_cooldown("Cloudflare", 60).until == now + 3400
    assert base.set_cooldown("cloudflare", 4000, status=403).until == now + 4000
    assert base.get_cooldown("cloudflare").status == 403
    assert set(base.all_cooldowns()) == {"cloudflare"}
    clock.advance(3999)
    assert base.get_cooldown("cloudflare") is not None and base.get_cooldown("cloudflare").remaining() == 1
    clock.advance(1)
    assert base.get_cooldown("cloudflare") is None                       # expired entries vanish
    assert cloudflare.CloudflareBackend().available(cfg)[0] is True
    base.set_cooldown("fastcom", 100)
    base.clear_cooldowns("fastcom")
    assert base.get_cooldown("fastcom") is None
    base.set_cooldown("fastcom", 100)
    base.clear_cooldowns()
    assert base.all_cooldowns() == {}


def test_rate_limited_result_shape():
    r = base.rate_limited_result("x", 1.0, 429, 3400, "phase refused", 0.5, {"a": 1}, server="S")
    assert r.ok is False and r.backend == "x" and r.server == "S" and r.duration_s == 0.5
    assert r.error.startswith("rate limited (HTTP 429, retry after 3400 s): phase refused")
    assert r.raw == {"a": 1, "rate_limited": True, "retry_after_s": 3400, "http_status": 429}
    assert base.get_cooldown("x") is not None and base.get_cooldown("x").status == 429
    assert base.is_rate_limited(r) and base.is_rate_limited(r.to_dict())
    assert not base.is_rate_limited(SpeedResult(ok=True, ts=1.0, backend="x"))
    assert not base.is_rate_limited(base.failed_result("x", 1.0, "boom"))
    # no Retry-After -> default; 403 is spelt out; cooldown=False leaves the registry alone
    r2 = base.rate_limited_result("y", 1.0, 403, None, cooldown=False)
    assert r2.error.startswith("rate limited (HTTP 403 forbidden, retry after 900 s)")
    assert r2.raw["retry_after_s"] == 900 and r2.raw["http_status"] == 403
    assert base.get_cooldown("y") is None
    # SpeedResult keeps its public fields (raw only gains keys)
    assert set(SpeedResult.__dataclass_fields__) == {"ok", "ts", "backend", "server", "isp", "external_ip", "latency_ms",
                                                      "jitter_ms", "download_mbps", "upload_mbps", "packet_loss_pct",
                                                      "duration_s", "error", "raw"}


def test_phase_hard_remaining_and_rate_limit_accounting():
    phase = TransferPhase("download", 5, 1_000_000)                     # MAX_BYTES_FACTOR 3 -> cap 3 MB
    assert phase.remaining_bytes() == 1_000_000 and phase.remaining_bytes(hard=True) == 3_000_000
    phase.add_bytes(1_500_000)
    assert phase.remaining_bytes() == 0 and phase.remaining_bytes(hard=True) == 1_500_000
    phase.note_rate_limit(100)                                          # a 429 a smaller chunk got around
    phase.note_rate_limit(3400, gave_up=True, status=429)
    phase.note_rate_limit(None, gave_up=True, status=403)
    stats = phase.run(lambda ph, i: None, 2)
    assert stats.rate_limit_hits == 3 and stats.rate_limited == 2
    assert stats.retry_after_s == 3400 and stats.rate_limit_status == 403
    d = stats.to_dict()
    assert d["rate_limit_hits"] == 3 and d["rate_limited"] == 2 and d["retry_after_s"] == 3400
    # the phase-level judgement: every worker refused, or nothing counted and at least one refused
    mk = lambda mbps, rl: base.PhaseStats("download", 0, 0.0, 0, 0, False, mbps, rate_limited=rl)  # noqa: E731
    assert mk(None, 1).rate_limited_phase(4) is True
    assert mk(10.0, 1).rate_limited_phase(4) is False
    assert mk(10.0, 4).rate_limited_phase(4) is True
    assert mk(None, 0).rate_limited_phase(4) is False


def test_cloudflare_rate_limited_download_phase(cfg, fake_server, monkeypatch):
    """429 on every __down of >= 1 byte (the bytes=0 latency probes pass): the worker halves
    its chunk down to the minimum, gives up, and the run is a rate-limited failure."""
    _point_cloudflare(monkeypatch, fake_server)
    hits = _limit(monkeypatch, 429, {"down"}, min_bytes=1, retry_after="3400")
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.ok is False
    assert res.error.startswith("rate limited (HTTP 429, retry after 3400 s)"), res.error
    assert res.raw["rate_limited"] is True and res.raw["retry_after_s"] == 3400 and res.raw["http_status"] == 429
    assert res.server == "Cloudflare TST" and res.latency_ms is not None      # what was measured is kept
    dl = res.raw["download"]
    assert dl["rate_limited"] == 2 and dl["bytes"] == 0 and dl["retry_after_s"] == 3400
    # per worker: 3 MB (hard cap of a 1 MB budget) -> 1.5 MB -> 1 MB, each refused = 3 hits;
    # the size halved is the one refused, so the cap never makes a worker re-ask for the same size
    assert dl["rate_limit_hits"] == 6 and len(hits) == 6
    assert sorted(n for _, n in hits) == [1_000_000, 1_000_000, 1_500_000, 1_500_000, 3_000_000, 3_000_000]
    assert "upload" not in res.raw                                          # never got that far
    cd = base.get_cooldown("cloudflare")
    assert cd is not None and cd.status == 429 and 3395 <= cd.remaining() <= 3400
    ok, detail = cloudflare.CloudflareBackend().available(cfg)
    assert ok is False and detail.startswith("cooling down after HTTP 429 until ")


def test_cloudflare_rate_limited_latency_probes_and_defaults(cfg, fake_server, monkeypatch):
    """429 without Retry-After on everything (incl. bytes=0): the probes are refused ->
    rate-limited result with the 900 s default and no transfer phase at all."""
    _point_cloudflare(monkeypatch, fake_server)
    hits = _limit(monkeypatch, 429, {"down"})
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.ok is False and res.error.startswith("rate limited (HTTP 429, retry after 900 s)")
    assert res.raw["retry_after_s"] == 900 and res.raw["rate_limited"] is True
    assert "download" not in res.raw and len(hits) == 1
    assert base.get_cooldown("cloudflare").remaining() <= 900


def test_cloudflare_rate_limited_variants(cfg, fake_server, monkeypatch):
    _point_cloudflare(monkeypatch, fake_server)
    # Retry-After as an HTTP-date
    when = email.utils.formatdate(time.time() + 1800, usegmt=True)
    _limit(monkeypatch, 429, {"trace"}, retry_after=when)
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.ok is False and res.error.startswith("rate limited") and 1790 <= res.raw["retry_after_s"] <= 1800
    base.clear_cooldowns()
    # 403 (bot block): no halving, immediate give-up, spelt out, cooldown status 403
    hits = _limit(monkeypatch, 403, {"down"}, min_bytes=1)
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.ok is False and res.error.startswith("rate limited (HTTP 403 forbidden, retry after 900 s)")
    assert res.raw["http_status"] == 403 and res.raw["download"]["rate_limited"] == 2 and len(hits) == 2
    assert base.get_cooldown("cloudflare").status == 403
    base.clear_cooldowns()
    # a cap above 1 h is clamped
    _limit(monkeypatch, 429, {"trace"}, retry_after="86400")
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.raw["retry_after_s"] == 3600 and "retry after 3600 s" in res.error
    base.clear_cooldowns()
    # only big chunks refused: the halving works around it, the reading is real, no cooldown
    hits = _limit(monkeypatch, 429, {"down"}, min_bytes=2_000_000, retry_after="3400")
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.ok, res.error
    assert res.download_mbps > 0 and res.raw["download"]["rate_limit_hits"] >= 1
    assert res.raw["download"]["rate_limited"] == 0 and "rate_limited" not in res.raw
    assert hits and all(n >= 2_000_000 for _, n in hits)
    assert base.get_cooldown("cloudflare") is None
    # upload phase refused (download fine): still a rate-limited failure, the download stats are kept
    hits = _limit(monkeypatch, 429, {"up"}, retry_after="600")
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.ok is False and res.error.startswith("rate limited (HTTP 429, retry after 600 s): upload phase refused")
    assert res.raw["download"]["mbps"] > 0 and res.raw["upload"]["rate_limited"] == 2 and len(hits) == 2
    assert base.get_cooldown("cloudflare").status == 429


def test_fastcom_rate_limited(cfg, fake_server, monkeypatch):
    _point_fastcom(monkeypatch, fake_server)
    # the API itself
    hits = _limit(monkeypatch, 429, {"api"}, retry_after="1200")
    res = fastcom.FastComBackend().run(cfg)
    assert res.ok is False and res.error.startswith("rate limited (HTTP 429, retry after 1200 s): /netflix/speedtest/v2")
    assert res.raw["rate_limited"] is True and res.raw["retry_after_s"] == 1200 and len(hits) == 1
    assert fastcom.FastComBackend().available(cfg)[0] is False and base.get_cooldown("fastcom").status == 429
    base.clear_cooldowns()
    # every download range of >= 2 bytes (the 0-0 latency probes pass): halving, then give up
    hits = _limit(monkeypatch, 429, {"range_get"}, min_bytes=2)
    res = fastcom.FastComBackend().run(cfg)
    assert res.ok is False and res.error.startswith("rate limited (HTTP 429, retry after 900 s): download phase refused")
    assert res.raw["download"]["rate_limited"] == 2 and res.raw["download"]["bytes"] == 0
    # 3 MB (the hard cap, well below the 25 MiB range) -> 1.5 MB -> 1 MB per worker: 6 hits, not 12
    assert sorted(n for _, n in hits) == [1_000_000, 1_000_000, 1_500_000, 1_500_000, 3_000_000, 3_000_000]
    assert res.server.startswith("fast.com") and res.latency_ms is not None
    base.clear_cooldowns()
    # 403 on the upload POSTs = an OCA that does not take uploads: not a rate limit
    hits = _limit(monkeypatch, 403, {"range_post"})
    res = fastcom.FastComBackend().run(cfg)
    assert res.ok, res.error
    assert res.download_mbps > 0 and res.upload_mbps is None and "error" in res.raw["upload"]
    assert res.raw["upload"]["rate_limited"] == 0 and base.get_cooldown("fastcom") is None and hits
    # 429 on the upload POSTs is
    hits = _limit(monkeypatch, 429, {"range_post"}, retry_after="300")
    res = fastcom.FastComBackend().run(cfg)
    assert res.ok is False and res.error.startswith("rate limited (HTTP 429, retry after 300 s): upload phase refused")
    assert base.get_cooldown("fastcom") is not None and len(hits) == 2


def test_select_backend_and_run_speedtest_respect_cooldowns(cfg, monkeypatch):
    now = 1_800_000_000.0
    clock = FakeClock(now)
    monkeypatch.setattr(base, "cooldown_clock", clock)
    assert st.select_backend(cfg).name == "cloudflare"
    base.set_cooldown("cloudflare", 900)
    assert st.select_backend(cfg).name == "fastcom"                      # auto: the other built-in backend
    cfg.update({"speedtest": {"backend": "fastcom"}}, persist=False)
    assert st.select_backend(cfg).name == "fastcom"
    cfg.update({"speedtest": {"backend": "cloudflare"}}, persist=False)
    assert st.select_backend(cfg).name == "fastcom"                      # explicit but cooling: fall back
    assert st.alternative_backend(cfg, exclude=("cloudflare",)).name == "fastcom"
    assert st.alternative_backend(cfg, exclude=("cloudflare", "fastcom")) is None
    lst = {b["name"]: b for b in st.available_backends(cfg)}
    assert lst["cloudflare"]["available"] is False and "cooling down after HTTP 429 until" in lst["cloudflare"]["detail"]
    assert lst["cloudflare"]["cooldown_until"] == now + 900 and lst["fastcom"]["cooldown_until"] is None
    # both cooling: nothing can run -> a clear failed result, no network touched
    base.set_cooldown("fastcom", 600, status=403)
    assert st.alternative_backend(cfg, exclude=("cloudflare",)) is None
    assert st.select_backend(cfg).name == "cloudflare"                   # explicit, no fallback: returned as-is
    res = st.run_speedtest(cfg)
    assert res.ok is False and res.backend == "cloudflare"
    assert res.error.startswith("rate limited: cloudflare is cooling down after HTTP 429 until ")
    assert res.raw["rate_limited"] is True and res.raw["cooldown"] is True and res.raw["retry_after_s"] == 900
    assert res.raw["http_status"] == 429 and res.raw["cooldown_until"] == now + 900
    cfg.update({"speedtest": {"backend": "auto"}}, persist=False)
    assert st.select_backend(cfg).name == "cloudflare"
    res = st.run_speedtest(cfg, backend=st.BACKENDS["fastcom"])
    assert res.ok is False and res.error.startswith("rate limited: fastcom is cooling down after HTTP 403 until ")
    assert res.raw["retry_after_s"] == 600
    clock.advance(601)
    assert st.select_backend(cfg).name == "fastcom"                      # fastcom's cooldown has expired
    clock.advance(300)
    assert st.select_backend(cfg).name == "cloudflare"


def test_run_speedtest_registers_cooldown_from_a_custom_backend(cfg, monkeypatch):
    class Limited:
        name = "custom"

        def available(self, c):
            return True, ""

        def run(self, c, progress=None, cancel=None):
            return SpeedResult(ok=False, ts=time.time(), backend="custom", error="rate limited by someone",
                               raw={"rate_limited": True, "retry_after_s": 120, "http_status": 429})

    now = 1_800_000_000.0
    monkeypatch.setattr(base, "cooldown_clock", FakeClock(now))
    res = st.run_speedtest(cfg, backend=Limited())
    assert res.ok is False and base.is_rate_limited(res)
    cd = base.get_cooldown("custom")
    assert cd is not None and cd.until == now + 120 and cd.status == 429

    class Greedy(Limited):
        name = "greedy"

        def run(self, c, progress=None, cancel=None):
            return SpeedResult(ok=False, ts=time.time(), backend="greedy", error="rate limited",
                               raw={"rate_limited": True, "retry_after_s": 10 * 86400, "http_status": "x"})

    st.run_speedtest(cfg, backend=Greedy())
    cd = base.get_cooldown("greedy")                                   # clamped, status defaulted
    assert cd is not None and cd.until == now + base.MAX_RETRY_AFTER_S and cd.status == 429


def test_request_counts_are_modest_on_a_fast_link(cfg, fake_server, monkeypatch):
    """Production phases (1.5 s minimum, 3 x budget cap) against a localhost server that
    is faster than gigabit: the default budgets must not turn into dozens of requests.
    Before requests were sized against the hard cap this run made hundreds."""
    monkeypatch.setattr(TransferPhase, "MIN_DURATION_S", 1.5)
    monkeypatch.setattr(TransferPhase, "RAMP_FRACTION", 0.25)
    _point_cloudflare(monkeypatch, fake_server)
    cfg.update({"speedtest": {"download_mb": 50, "upload_mb": 20, "duration_s": 8, "connections": 4}}, persist=False)
    res = cloudflare.CloudflareBackend().run(cfg)
    assert res.ok, res.error
    dl, ul = res.raw["download"], res.raw["upload"]
    assert dl["bytes"] >= 50_000_000 and ul["acked_bytes"] >= 20_000_000
    assert dl["requests"] <= 40, dl
    assert ul["requests"] <= 40, ul
    assert ul["requests"] >= 4 and dl["requests"] >= 4
    assert cloudflare.UPLOAD_BODY_BYTES == 4_000_000 and cloudflare.UPLOAD_TARGET_S == pytest.approx(2.0)
    assert cloudflare.DOWNLOAD_CHUNK_BYTES == 5_000_000


class RateLimitedBackend(FakeBackend):
    """Answers like a Cloudflare backend that is being refused."""

    name = "cf"

    def run(self, config, progress=None, cancel=None):
        self.calls.append(time.time())
        self.started.set()
        return base.rate_limited_result("cf", time.time(), 429, 3400, "download phase refused", 0.2)


def test_scheduler_falls_back_to_the_other_backend_when_rate_limited(db, cfg, bus, monkeypatch):
    limited = RateLimitedBackend()
    other = FakeBackend()
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: limited)
    picks = []
    monkeypatch.setattr(sched_mod, "alternative_backend", lambda c, exclude=(): picks.append(tuple(exclude)) or other)
    clock = FakeClock(1_000_000.0)
    monkeypatch.setattr(base, "cooldown_clock", clock)
    events = _events(bus)
    s = st.SpeedScheduler(db, cfg, bus, clock=clock, poll_s=0.01)
    s.start()
    try:
        clock.advance(60)
        assert wait_until(lambda: any(e["type"] == "speedtest.done" for e in events))
        assert wait_until(lambda: not s.running)
        assert len(limited.calls) == 1 and len(other.calls) == 1
        assert picks == [("cf", "cf")]
        rows = db.list_speedtests(0, 2e9)
        assert len(rows) == 1 and rows[0]["ok"] is True and rows[0]["backend"] == "fake"
        raw = json.loads(db.last_speedtest()["raw_json"])
        assert raw["x"] == 1                                              # the fallback's own raw ...
        assert raw["rate_limited_attempts"][0]["backend"] == "cf"         # ... plus the refused attempt
        assert raw["rate_limited_attempts"][0]["retry_after_s"] == 3400
        starts = [e["data"] for e in events if e["type"] == "speedtest.start"]
        assert [x["backend"] for x in starts] == ["cf", "fake"]
        assert starts[1]["attempt"] == 2 and starts[1]["after"] == "cf" and starts[1]["ts"] == 1_000_060.0
        assert [e["type"] for e in events].count("speedtest.done") == 1
        assert not any(e["type"] == "speedtest.skipped" for e in events)
        assert db.list_events(10) == []                                   # not a failure
        assert s.last_result["backend"] == "fake" and s.last_result["ok"] is True
        status = s.status()
        assert status["effective_interval_min"] == 15 and status["interval_reason"] is None
        assert s.next_run_ts == 1_000_060.0 + 900
    finally:
        s.stop()


def test_scheduler_rate_limited_skip_and_adaptive_spacing(db, cfg, bus, monkeypatch):
    limited = RateLimitedBackend()
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: limited)
    monkeypatch.setattr(sched_mod, "alternative_backend", lambda c, exclude=(): None)
    clock = FakeClock(1_000_000.0)
    monkeypatch.setattr(base, "cooldown_clock", clock)
    events = _events(bus)
    s = st.SpeedScheduler(db, cfg, bus, clock=clock, poll_s=0.01)
    s.start()
    try:
        # 1st slot: nothing can run -> skipped (reason "rate limited"), done published, no row
        clock.advance(60)
        assert wait_until(lambda: any(e["type"] == "speedtest.skipped" for e in events))
        assert wait_until(lambda: not s.running)
        skipped = [e["data"] for e in events if e["type"] == "speedtest.skipped"]
        assert skipped[0]["reason"] == "rate limited" and skipped[0]["retry_after_s"] == 3400
        assert skipped[0]["detail"].startswith("cf: rate limited (HTTP 429, retry after 3400 s)")
        done = [e["data"] for e in events if e["type"] == "speedtest.done"]
        assert len(done) == 1 and done[0]["result"]["ok"] is False and "id" not in done[0]["result"]
        assert done[0]["result"]["error"].startswith("rate limited")
        assert db.list_speedtests(0, 2e9) == [] and s.last_result is None
        ev = db.list_events(10)
        assert len(ev) == 1 and ev[0]["level"] == "warning" and ev[0]["message"].startswith("speed test skipped: rate limited")
        status = s.status()
        assert status["effective_interval_min"] == 15 and status["interval_reason"] is None
        assert s.next_run_ts == 1_000_060.0 + 900 == skipped[0]["next_run_ts"]
        # 2nd within the hour: interval doubles to 30 min, next run pushed out accordingly
        clock.advance(900)
        assert wait_until(lambda: len([e for e in events if e["type"] == "speedtest.skipped"]) == 2)
        assert wait_until(lambda: not s.running)
        status = s.status()
        assert status["interval_min"] == 15 and status["effective_interval_min"] == 30
        assert status["interval_reason"].startswith("rate limited 2 times in the last hour; tests spaced 30 min")
        assert s.next_run_ts == 1_000_960.0 + 1800
        # 3rd: doubles again, capped at 60 min
        clock.advance(1800)
        assert wait_until(lambda: len([e for e in events if e["type"] == "speedtest.skipped"]) == 3)
        assert wait_until(lambda: not s.running)
        assert s.status()["effective_interval_min"] == 60 and s.next_run_ts == 1_002_760.0 + 3600
        assert len(limited.calls) == 3 and db.list_speedtests(0, 2e9) == []
        # a success returns to the configured interval
        ok_backend = FakeBackend()
        monkeypatch.setattr(sched_mod, "select_backend", lambda c: ok_backend)
        clock.advance(3600)
        assert wait_until(lambda: len(ok_backend.calls) == 1)
        assert wait_until(lambda: not s.running and s.last_result is not None)
        status = s.status()
        assert status["effective_interval_min"] == 15 and status["interval_reason"] is None
        assert s.next_run_ts == 1_006_360.0 + 900
        assert len(db.list_speedtests(0, 2e9)) == 1
        # a manual run while limited also produces a (non-persisted) done so the UI resets
        monkeypatch.setattr(sched_mod, "select_backend", lambda c: limited)
        n_done = len([e for e in events if e["type"] == "speedtest.done"])
        assert s.run_now()
        assert wait_until(lambda: len([e for e in events if e["type"] == "speedtest.done"]) == n_done + 1)
        assert wait_until(lambda: not s.running)
        assert len(db.list_speedtests(0, 2e9)) == 1 and s.last_result["ok"] is True
    finally:
        s.stop()


def test_scheduler_configured_interval_above_the_cap_is_not_doubled(db, cfg, bus, monkeypatch):
    cfg.update({"speedtest": {"interval_min": 120}}, persist=False)
    limited = RateLimitedBackend()
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: limited)
    monkeypatch.setattr(sched_mod, "alternative_backend", lambda c, exclude=(): None)
    clock = FakeClock(0.0)
    monkeypatch.setattr(base, "cooldown_clock", clock)
    s = st.SpeedScheduler(db, cfg, bus, clock=clock, poll_s=0.01)
    s.start()
    try:
        for _ in range(2):
            assert s.run_now()
            assert wait_until(lambda: not s.running)
            clock.advance(60)
        status = s.status()
        assert status["interval_min"] == 120 and status["effective_interval_min"] == 120
        assert status["interval_reason"] is None
    finally:
        s.stop()


class _EarlyRefuseHandler(_FakeHandler):
    """Answers 429 to /__up *before* reading the body and drops the connection - what an
    edge rate limiter in front of the upload endpoint does."""

    def do_POST(self):
        if urlsplit(self.path).path == "/__up":
            self._send(429, b"slow", extra={"Retry-After": "600", "Connection": "close"})
            self.close_connection = True
            return
        super().do_POST()


def test_cloudflare_upload_refused_before_the_body_is_read_degrades_gracefully(cfg, monkeypatch):
    """With a 4 MB body the client's send() fails (Windows discards the buffered 429 once the
    reset arrives), so the limit cannot be recognised; the worker must then stop after a
    bounded number of attempts and the run keeps the download reading with upload unknown."""
    srv = _QuietServer(("127.0.0.1", 0), _EarlyRefuseHandler)
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    try:
        _point_cloudflare(monkeypatch, srv.server_address[:2])
        monkeypatch.setattr(cloudflare, "UPLOAD_FIRST_BYTES", 4_000_000)
        cfg.update({"speedtest": {"download_mb": 1, "upload_mb": 20, "duration_s": 4, "connections": 2}}, persist=False)
        t0 = time.perf_counter()
        res = cloudflare.CloudflareBackend().run(cfg)
        assert time.perf_counter() - t0 < 4.0
        assert res.ok, res.error
        assert res.download_mbps > 0 and res.upload_mbps is None
        ul = res.raw["upload"]
        assert ul["requests"] == 0 and 0 < ul["errors"] <= 3 * 2 and "error" in ul
        assert not base.is_rate_limited(res) and base.get_cooldown("cloudflare") is None
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(2)


def test_scheduler_end_to_end_fallback_through_real_selection(db, cfg, bus, fake_server, monkeypatch):
    """Nothing monkeypatched in the scheduler: the fake server refuses Cloudflare, the
    scheduler's own alternative_backend() picks fast.com against the same server, the
    fast.com reading is what gets persisted, and while Cloudflare cools down every
    later slot goes straight to fast.com without touching Cloudflare again."""
    _point_cloudflare(monkeypatch, fake_server)
    _point_fastcom(monkeypatch, fake_server)
    hits = _limit(monkeypatch, 429, {"trace"}, retry_after="3400")
    clock = FakeClock(1_000_000.0)
    monkeypatch.setattr(base, "cooldown_clock", clock)
    events = _events(bus)
    s = st.SpeedScheduler(db, cfg, bus, clock=clock, poll_s=0.01)
    s.start()
    try:
        assert s.status()["backend"] == "cloudflare"
        clock.advance(60)
        assert wait_until(lambda: any(e["type"] == "speedtest.done" for e in events), timeout=20)
        assert wait_until(lambda: not s.running)
        rows = db.list_speedtests(0, 2e9)
        assert len(rows) == 1 and rows[0]["ok"] is True and rows[0]["backend"] == "fastcom"
        assert rows[0]["download_mbps"] > 0 and rows[0]["ts"] == 1_000_060.0
        raw = json.loads(db.last_speedtest()["raw_json"])
        assert raw["rate_limited_attempts"] == [{
            "backend": "cloudflare", "error": raw["rate_limited_attempts"][0]["error"],
            "retry_after_s": 3400, "http_status": 429}]
        assert raw["rate_limited_attempts"][0]["error"].startswith("rate limited (HTTP 429, retry after 3400 s)")
        assert [(h[0]) for h in hits] == ["trace"]
        starts = [e["data"] for e in events if e["type"] == "speedtest.start"]
        assert [x["backend"] for x in starts] == ["cloudflare", "fastcom"] and starts[1]["after"] == "cloudflare"
        assert not any(e["type"] == "speedtest.skipped" for e in events) and db.list_events(10) == []
        status = s.status()
        assert status["backend"] == "fastcom" and status["effective_interval_min"] == 15
        assert status["last"]["backend"] == "fastcom" and status["last"]["ok"] is True
        lst = {b["name"]: b for b in st.available_backends(cfg)}
        assert lst["cloudflare"]["available"] is False and lst["cloudflare"]["cooldown_until"] == 1_000_060.0 + 3400
        assert lst["cloudflare"]["detail"].startswith("cooling down after HTTP 429 until ")
        assert lst["fastcom"]["available"] is True and lst["fastcom"]["cooldown_until"] is None
        # next slot: fast.com directly, Cloudflare not contacted
        clock.advance(900)
        assert wait_until(lambda: len(db.list_speedtests(0, 2e9)) == 2, timeout=20)
        assert wait_until(lambda: not s.running)
        assert [(h[0]) for h in hits] == ["trace"]
        assert [e["data"]["backend"] for e in events if e["type"] == "speedtest.start"] == ["cloudflare", "fastcom", "fastcom"]
        assert "rate_limited_attempts" not in json.loads(db.last_speedtest()["raw_json"])
        # cooldown over (and the server no longer refusing): back to Cloudflare
        monkeypatch.setattr(_FakeHandler, "limit_status", None)
        clock.advance(3400)
        assert wait_until(lambda: len(db.list_speedtests(0, 2e9)) == 3, timeout=20)
        assert wait_until(lambda: not s.running)
        assert db.last_speedtest()["backend"] == "cloudflare" and s.status()["backend"] == "cloudflare"
    finally:
        s.stop()


def test_scheduler_end_to_end_both_backends_refused(db, cfg, bus, fake_server, monkeypatch):
    """Both backends refused by the server: one request each, then both on
    cooldown; the slot is skipped (no row); the next slot is refused locally without a
    single request; a later success after the cooldowns resets the spacing."""
    _point_cloudflare(monkeypatch, fake_server)
    _point_fastcom(monkeypatch, fake_server)
    hits = _limit(monkeypatch, 429, {"trace", "api"}, retry_after="1200")
    clock = FakeClock(1_000_000.0)
    monkeypatch.setattr(base, "cooldown_clock", clock)
    events = _events(bus)
    s = st.SpeedScheduler(db, cfg, bus, clock=clock, poll_s=0.01)
    s.start()
    try:
        clock.advance(60)
        assert wait_until(lambda: any(e["type"] == "speedtest.skipped" for e in events), timeout=20)
        assert wait_until(lambda: not s.running)
        assert sorted(h[0] for h in hits) == ["api", "trace"]
        skipped = [e["data"] for e in events if e["type"] == "speedtest.skipped"]
        assert skipped[0]["reason"] == "rate limited" and skipped[0]["retry_after_s"] == 1200
        assert "cloudflare: rate limited (HTTP 429" in skipped[0]["detail"] and "fastcom: rate limited (HTTP 429" in skipped[0]["detail"]
        assert skipped[0]["next_run_ts"] == 1_000_060.0 + 900
        done = [e["data"]["result"] for e in events if e["type"] == "speedtest.done"]
        assert len(done) == 1 and done[0]["ok"] is False and done[0]["backend"] == "fastcom" and "id" not in done[0]
        assert [a["backend"] for a in done[0]["raw"]["rate_limited_attempts"]] == ["cloudflare", "fastcom"]
        assert db.list_speedtests(0, 2e9) == [] and s.last_result is None
        assert set(base.all_cooldowns()) == {"cloudflare", "fastcom"}
        assert s.status()["backend"] == "cloudflare"          # auto: the first one, to be refused locally
        # next slot: refused locally (both cooling) - the server sees nothing; 2nd outcome -> 30 min
        clock.advance(900)
        assert wait_until(lambda: len([e for e in events if e["type"] == "speedtest.skipped"]) == 2, timeout=20)
        assert wait_until(lambda: not s.running)
        assert sorted(h[0] for h in hits) == ["api", "trace"]
        done = [e["data"]["result"] for e in events if e["type"] == "speedtest.done"]
        assert done[1]["error"].startswith("rate limited: cloudflare is cooling down after HTTP 429 until ")
        assert done[1]["raw"]["cooldown"] is True and 0 < done[1]["raw"]["retry_after_s"] <= 1200
        assert [a["backend"] for a in done[1]["raw"]["rate_limited_attempts"]] == ["cloudflare"]
        status = s.status()
        assert status["effective_interval_min"] == 30 and status["interval_reason"].startswith("rate limited 2 times")
        assert s.next_run_ts == 1_000_960.0 + 1800
        ev = db.list_events(10)
        assert len(ev) == 2 and all(e["level"] == "warning" and e["message"].startswith("speed test skipped: rate limited") for e in ev)
        # cooldowns expired and the server relents: a real reading, back to 15 min
        monkeypatch.setattr(_FakeHandler, "limit_status", None)
        clock.advance(1800)
        assert wait_until(lambda: len(db.list_speedtests(0, 2e9)) == 1, timeout=20)
        assert wait_until(lambda: not s.running)
        assert db.last_speedtest()["backend"] == "cloudflare" and db.last_speedtest()["ok"] is True
        status = s.status()
        assert status["effective_interval_min"] == 15 and status["interval_reason"] is None
        assert base.all_cooldowns() == {}
    finally:
        s.stop()


# --------------------------------------------------------------------------- real network

@pytest.mark.network
def test_cloudflare_backend_real_network(cfg):
    cfg.update({"speedtest": {"download_mb": 2, "upload_mb": 1, "duration_s": 2, "connections": 2}}, persist=False)
    prog = []
    res = st.CloudflareBackend().run(cfg, progress=lambda p, f: prog.append((p, f)))
    assert res.ok, res.error
    assert res.server.startswith("Cloudflare ") and res.external_ip
    assert res.download_mbps > 0 and res.upload_mbps > 0
    assert res.latency_ms is not None and res.latency_ms < 1000
    assert res.raw["download"]["bytes"] >= 2_000_000
    assert prog[-1] == ("done", 1.0)
    assert res.duration_s < 30
