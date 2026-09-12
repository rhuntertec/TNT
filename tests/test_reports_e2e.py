"""End to end: Full Scans through the real service, from the HTTP request to the saved report, its PDFs and a comparison.

The real pieces run in a temporary data directory: the :class:`tnt.engine.Engine` start steps a Full Scan needs
(``_start_config``, ``_start_db``, ``_start_bus``, ``_start_speed``, ``_start_reports``, ``_start_api``), the SQLite
database, the event bus, the :class:`tnt.speedtest.SpeedScheduler`, the engine's own Discovery runner
(``Engine.discovery_start``), :class:`tnt.reports.ReportManager`, ``Engine._on_net_changed`` and the HTTP API with its SSE
stream on an ephemeral loopback port; the engine's own ``stop()`` shuts it all down.  Only the edges are fakes: the
speed-test backend (``scheduler.select_backend``), the Discovery scanner, the adapter snapshot (``netinfo.netinfo_snapshot``
and ``Engine.netinfo_summary``), the host name, and the Wi-Fi snapshot, which the test posts the way a TNT window does when
the job reaches its Wi-Fi phase on ``GET /api/events``.  No packet leaves the machine.

History is synthetic and seeded before the manager starts: per-minute ping rows of a gateway and two internet targets
(the oldest three days back, an hour on the previous network, then network A and network B), outages inside and outside
the windows, speed tests inside and outside them, and the "joined this network" marker plus the "network changed" events
row an earlier service run left.  Scan 1 (named with PATCH, Wi-Fi posted) runs on network A; a live ``net.changed`` then
moves the PC to network B; scan 2 gets no Wi-Fi snapshot and times out; scan 3 is cancelled during its speed test.
Addresses are RFC 1918 / RFC 5737, MACs locally administered, sites and SSIDs invented.
"""
from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import re
import threading
import time
import zlib
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from tnt import arp, netinfo, reports
from tnt.speedtest import scheduler as sched_mod
from tnt.speedtest.base import CANCELLED, SpeedResult

WAIT_S = 20.0               # real-time ceiling for anything asynchronous (normally well under a second)
HOUR = 3600
DAY = 86400
CONFIG = {"speedtest": {"enabled": False}}     # no scheduled test: only the scans' own
JOB_KEYS = {"id", "site", "started_ts", "status", "phase", "pct", "message", "phases", "report_id", "error", "window_start",
            "window_reason", "network_id", "network", "suggested_site"}
PHASE_KEYS = {"key", "status", "message", "started_ts", "finished_ts"}
ROW_KEYS = {"id", "site", "created_ts", "completed_ts", "status", "summary", "network_id"}

#: the two networks this fake PC is on: the adapter snapshot, the engine's summary of it and what Discovery finds there
NETWORKS: Dict[str, Dict[str, Any]] = {
    "A": {
        "gateway": "192.168.50.1", "cidr": "192.168.50.0/24", "nic": "Ethernet",
        "adapter": {"index": 7, "name": "Ethernet", "description": "Example Gigabit Adapter", "mac": "02:00:5E:00:53:07",
                    "type_name": "Ethernet", "status": "up", "speed_bps": 1_000_000_000, "dhcp_enabled": True,
                    "dhcp_server": "192.168.50.1", "is_physical": True, "primary_ipv4": "192.168.50.112",
                    "ipv4": [{"address": "192.168.50.112", "prefix": 24, "family": 4, "netmask": "255.255.255.0",
                              "network": "192.168.50.0/24"}],
                    "gateways": ["192.168.50.1"], "dns": ["192.168.50.1", "198.51.100.53"], "warnings": []},
        "hosts": [
            {"ip": "192.168.50.1", "hostname": "router.example", "mac": "02:00:5E:10:00:01", "vendor": None, "ping_ok": True,
             "rtt_ms": 0.6, "open_ports": [80, 443], "device_type": "Router"},
            {"ip": "192.168.50.20", "hostname": None, "mac": "02:00:5E:10:00:14", "vendor": None, "ping_ok": True,
             "rtt_ms": 1.4, "open_ports": [554], "device_type": "Camera"},
            {"ip": "192.168.50.21", "hostname": "cam-lobby", "mac": "02:00:5E:10:00:15", "vendor": None, "ping_ok": False,
             "rtt_ms": None, "open_ports": [80, 554], "device_type": "Camera"},
            {"ip": "192.168.50.60", "hostname": "desk-phone", "mac": "02:00:5E:10:00:3C", "vendor": None, "ping_ok": True,
             "rtt_ms": 2.0, "open_ports": [80, 5060], "device_type": "Phone"},
        ],
    },
    "B": {
        "gateway": "10.20.30.1", "cidr": "10.20.30.0/24", "nic": "Wi-Fi",
        "adapter": {"index": 9, "name": "Wi-Fi", "description": "Example Wi-Fi 6E Adapter", "mac": "02:00:5E:00:53:09",
                    "type_name": "Wi-Fi", "status": "up", "speed_bps": 866_000_000, "dhcp_enabled": True,
                    "dhcp_server": "10.20.30.1", "is_physical": True, "primary_ipv4": "10.20.30.45",
                    "ipv4": [{"address": "10.20.30.45", "prefix": 24, "family": 4, "netmask": "255.255.255.0",
                              "network": "10.20.30.0/24"}],
                    "gateways": ["10.20.30.1"], "dns": ["10.20.30.1"], "warnings": [{"code": "no_dns", "message": "x"}]},
        "hosts": [
            {"ip": "10.20.30.1", "hostname": None, "mac": "02:00:5E:30:00:01", "vendor": None, "ping_ok": True,
             "rtt_ms": 1.1, "open_ports": [80, 443], "device_type": "Router"},
            {"ip": "10.20.30.51", "hostname": None, "mac": "02:00:5E:30:00:33", "vendor": None, "ping_ok": True,
             "rtt_ms": 3.0, "open_ports": [554], "device_type": "Camera"},
        ],
    },
}
#: (download, upload, latency, jitter) of each scan's own speed test, in turn
SPEEDS = [(94.2, 18.6, 12.3, 1.1), (150.0, 40.0, 9.0, 0.8), (60.0, 10.0, 20.0, 2.0)]
PUBLIC_IP = "203.0.113.10"
#: ping minutes per target: (sent, received, avg_ms) before the join, on network A and on network B
PING = {
    "gateway": {"old": (60, 30, 9.0), "A": (60, 60, 0.8), "B": (60, 60, 2.0)},
    "198.51.100.20": {"old": (60, 30, 120.0), "A": (60, 59, 18.0), "B": (60, 58, 30.0)},
    "example.net": {"old": (60, 30, 140.0), "A": (60, 60, 22.0), "B": (60, 60, 40.0)},
}
#: the access points a TNT window's survey reads at the site, as the page posts them (in range, strongest first)
APS = [
    {"bssid": "02:00:5E:20:00:01", "ssid": "Acme-Staff", "hidden": False, "rssi": -48, "quality": 90, "band": "5", "channel": 36,
     "center_channel": 42, "width_mhz": 80, "freq_mhz": 5180, "phy": "ax", "generation": "Wi-Fi 6", "security": "WPA3-Personal",
     "max_rate_mbps": 1201, "connected": True, "first_seen": 0.0, "last_seen": 0.0},
    {"bssid": "02:00:5E:20:00:03", "ssid": "Acme-Guest", "hidden": False, "rssi": -55, "band": "5", "channel": 36, "width_mhz": 80,
     "generation": "Wi-Fi 6", "security": "OWE", "connected": False},
    {"bssid": "02:00:5E:20:00:02", "ssid": "Acme-Staff", "hidden": False, "rssi": -61, "band": "2.4", "channel": 6, "width_mhz": 20,
     "generation": "Wi-Fi 6", "security": "WPA3-Personal", "connected": False},
    {"bssid": "02:00:5E:20:00:06", "ssid": "", "hidden": True, "rssi": -75, "band": "2.4", "channel": 6, "width_mhz": 20,
     "generation": "Wi-Fi 4", "security": "WPA2-Personal", "connected": False},
    {"bssid": "02:00:5E:20:00:05", "ssid": "Harbor Cafe Guest", "hidden": False, "rssi": -82, "band": "2.4", "channel": 11,
     "width_mhz": 20, "generation": "Wi-Fi 5", "security": "Open", "connected": False},
]


# --------------------------------------------------------------------------- the edges
class World:
    """Which network the fake PC is on, as the adapter snapshot and the engine's summary show it."""

    def __init__(self) -> None:
        self.name = "A"

    @property
    def net(self) -> Dict[str, Any]:
        return NETWORKS[self.name]

    def snapshot(self) -> Dict[str, Any]:
        """``netinfo.netinfo_snapshot()``."""
        net = self.net
        return {"ts": time.time(), "internet_nic_index": net["adapter"]["index"], "default_gateway": net["gateway"],
                "public_hint": None, "adapters": [json.loads(json.dumps(net["adapter"]))]}

    def summary(self) -> Dict[str, Any]:
        """``Engine.netinfo_summary()``."""
        net = self.net
        return {"internet_nic": {"name": net["nic"], "network": net["cidr"], "gateway": net["gateway"], "warnings": []},
                "local_nic": None, "adapter_count": 1}


class FakeBackend:
    """A speed-test backend: :data:`SPEEDS` in turn, held at the gate while ``hold`` is set (until cancelled)."""

    name = "fake"

    def __init__(self) -> None:
        self.results = list(SPEEDS)
        self.gate = threading.Event()
        self.gate.set()
        self.calls = 0

    def available(self, config: Any) -> Tuple[bool, str]:
        return True, "fake"

    def run(self, config: Any, progress: Any = None, cancel: Any = None) -> SpeedResult:
        self.calls += 1
        if progress:
            for phase, frac in (("latency", 1.0), ("download", 0.5), ("download", 1.0), ("upload", 1.0)):
                progress(phase, frac)
        while not self.gate.is_set() and not (cancel is not None and cancel.is_set()):
            time.sleep(0.01)
        if cancel is not None and cancel.is_set():
            return SpeedResult(ok=False, ts=time.time(), backend="fake", error=CANCELLED, duration_s=0.1)
        down, up, latency, jitter = self.results.pop(0)
        return SpeedResult(ok=True, ts=time.time(), backend="fake", server="Example Colo", isp="Example ISP", external_ip=PUBLIC_IP,
                           download_mbps=down, upload_mbps=up, latency_ms=latency, jitter_ms=jitter, packet_loss_pct=0.0,
                           duration_s=1.0, raw={"synthetic": True})


class FakeScanner:
    """Stands in for ``tnt.discovery.DiscoveryScanner``: the hosts of the network the fake PC is on."""

    def __init__(self, world: World) -> None:
        self.world = world
        self.scans: List[Tuple[str, List[int]]] = []
        self.stopped = False

    def default_cidr(self) -> str:
        return self.world.net["cidr"]

    def parse_range(self, text: str) -> str:
        ipaddress.ip_network(text, strict=False)
        return text

    def stop(self) -> None:
        self.stopped = True

    def scan(self, range_text: str, ports: Any = None, progress: Any = None, cancel: Any = None) -> Any:
        self.scans.append((range_text, list(ports or [])))
        hosts = [dict(h) for h in self.world.net["hosts"]]
        if progress:
            progress({"phase": "ping", "done": 254, "total": 254, "found": len(hosts), "elapsed_s": 0.1})
            progress({"phase": "ports", "done": len(hosts), "total": len(hosts), "found": len(hosts), "elapsed_s": 0.2})
        result = {"ts": time.time(), "cidr": range_text, "ports": list(ports or []), "method": "native", "hosts": hosts,
                  "scanned": 254, "duration_s": 18.44, "ok": True, "error": None, "cancelled": False}
        return SimpleNamespace(to_dict=lambda: dict(result))


class EventStream:
    """``GET /api/events`` read on a thread: every frame as ``(type, data)``."""

    def __init__(self, port: int) -> None:
        self.frames: List[Tuple[str, Dict[str, Any]]] = []
        self.cond = threading.Condition()
        self.conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
        self.thread = threading.Thread(target=self._read, name="test-reports-sse", daemon=True)
        self.thread.start()

    def _read(self) -> None:
        try:
            self.conn.request("GET", "/api/events")
            resp = self.conn.getresponse()
            kind, data = None, []
            while True:
                line = resp.readline()
                if not line:
                    return
                text = line.decode("utf-8").rstrip("\r\n")
                if text.startswith("event: "):
                    kind = text[7:]
                elif text.startswith("data: "):
                    data.append(text[6:])
                elif not text and kind is not None:
                    with self.cond:
                        self.frames.append((kind, json.loads("\n".join(data)) if data else {}))
                        self.cond.notify_all()
                    kind, data = None, []
        except (OSError, ValueError, http.client.HTTPException):
            return

    def mark(self) -> int:
        with self.cond:
            return len(self.frames)

    def since(self, mark: int, kind: str) -> List[Dict[str, Any]]:
        with self.cond:
            return [d for t, d in self.frames[mark:] if t == kind]

    def wait(self, kind: str, pred: Callable[[Dict[str, Any]], bool] = lambda d: True, since: int = 0,
             what: str = "", timeout: float = WAIT_S) -> Dict[str, Any]:
        """The first ``kind`` frame after *since* that *pred* accepts."""
        deadline = time.monotonic() + timeout
        with self.cond:
            while True:
                for t, d in self.frames[since:]:
                    if t == kind and pred(d):
                        return d
                left = deadline - time.monotonic()
                if left <= 0:
                    raise AssertionError(f"no {kind} event {what} within {timeout} s; saw {[t for t, _ in self.frames[since:]]}")
                self.cond.wait(min(left, 0.25))

    def close(self) -> None:
        try:
            self.conn.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- helpers
def until(fn: Callable[[], Any], what: str, timeout: float = WAIT_S) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = fn()
        if value:
            return value
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}; last value {value!r}")
        time.sleep(0.05)


def call(port: int, method: str, path: str, body: Any = None) -> Tuple[int, Dict[str, str], Any]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        conn.request(method, path, body=data, headers={"Content-Type": "application/json"} if data is not None else {})
        resp = conn.getresponse()
        payload = resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        if headers.get("content-type", "").startswith("application/json"):
            return resp.status, headers, json.loads(payload)
        return resp.status, headers, payload
    finally:
        conn.close()


def ok(port: int, method: str, path: str, body: Any = None) -> Any:
    status, _headers, data = call(port, method, path, body)
    assert status == 200, (method, path, status, data)
    return data


def event_data(frame: Dict[str, Any]) -> Dict[str, Any]:
    """An event's own data: the SSE layer adds the bus event's ``ts`` to every payload (``tnt.api.sse.event_payload``)."""
    assert isinstance(frame.get("ts"), (int, float)), frame
    return {k: v for k, v in frame.items() if k != "ts"}


def expected_ping(host: str, parts: List[Tuple[str, int]]) -> Dict[str, float]:
    """Samples, lost, loss % and the reply-weighted average of *host*'s seeded minutes: ``[(segment, minutes)]``."""
    samples = received = 0
    weighted = 0.0
    for segment, minutes in parts:
        sent, rec, avg = PING[host][segment]
        samples += minutes * sent
        received += minutes * rec
        weighted += minutes * rec * avg
    return {"samples": samples, "lost": samples - received, "loss_pct": round(100.0 * (samples - received) / samples, 2),
            "avg_ms": round(weighted / received, 2)}


def pdf_text(pdf: bytes) -> bytes:
    """The page content streams, decoded (reportlab writes them ASCII85 + Flate)."""
    out = b""
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        raw = m.group(1).strip()
        try:
            raw = base64.a85decode(raw, adobe=True)
        except ValueError:
            pass
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            pass
        out += raw
    return out


def assert_valid_pdf(pdf: bytes) -> int:
    """A structurally sound PDF (header, trailer, a cross-reference table whose every offset points at its object, a page
    tree whose count matches its pages); returns the page count."""
    assert pdf.startswith(b"%PDF-1.") and pdf.rstrip().endswith(b"%%EOF")
    m = re.search(rb"startxref\s+(\d+)\s+%%EOF\s*$", pdf)
    assert m, "no startxref"
    xref_at = int(m.group(1))
    head = re.compile(rb"xref\s+0\s+(\d+)\s+").match(pdf, xref_at)
    assert head, "startxref does not point at the cross-reference table"
    count = int(head.group(1))
    entries = re.findall(rb"(\d{10}) (\d{5}) ([nf])", pdf[head.end():head.end() + 20 * count + 40])[:count]
    assert len(entries) == count
    for number, (offset, _gen, kind) in enumerate(entries):
        if kind == b"n":
            assert re.compile(rb"%d 0 obj" % number).match(pdf, int(offset)), f"object {number} is not at {offset}"
    pages = len(re.findall(rb"/Type\s*/Page(?![s\w])", pdf))
    tree = re.search(rb"/Count\s+(\d+)", pdf)
    assert pages >= 1 and tree and int(tree.group(1)) == pages
    assert b"trailer" in pdf[xref_at:] and b"/Root" in pdf[xref_at:]
    return pages


# --------------------------------------------------------------------------- the service
def seed_history(db: Any, now: float) -> SimpleNamespace:
    """The monitoring history an earlier service run left (see the module docstring)."""
    minute = int(now // 60) * 60                 # the current minute is not stored yet: a minute row is written when the next starts
    joined = minute - 4 * HOUR                   # this PC joined network A
    moved = minute - 90 * 60                     # ... and moves to network B during the test (the net.changed is dated back)
    oldest = minute - 3 * DAY
    segments = {"old": (joined - HOUR, 60), "A": (joined, (moved - joined) // 60), "B": (moved, (minute - moved) // 60)}
    ids: Dict[str, int] = {}
    for host, label in (("gateway", "Gateway"), ("198.51.100.20", None), ("example.net", "Example")):
        tid = int(db.add_target(host, label, kind="auto" if host == "gateway" else "internet")["id"])
        ids[host] = tid
        db.upsert_ping_minute(tid, oldest, 60, 60, 50.0, 49.0, 55.0, 0.5)
        for segment, (start, minutes) in segments.items():
            sent, rec, avg = PING[host][segment]
            for i in range(minutes):
                db.upsert_ping_minute(tid, start + i * 60, sent, rec, avg, avg * 0.8, avg + 4.0, 0.5)
    # outages: one before the join, two on network A, one still open on network B
    early = db.open_outage("total_local", None, joined - 30 * 60, note="no network connection")
    db.close_outage(early, joined - 20 * 60, 0)
    whole = db.open_outage("total_internet", None, joined + HOUR)
    db.close_outage(whole, joined + HOUR + 300, 0)
    single = db.open_outage("target", ids["198.51.100.20"], joined + 100 * 60, host="198.51.100.20")
    db.close_outage(single, joined + 100 * 60 + 120, 110, sent=120)
    db.open_outage("target", ids["example.net"], minute - 20 * 60, host="example.net")
    # speed tests: one before the join, one on network A
    for ts, down in ((joined - 2 * HOUR, 300.0), (joined + 30 * 60, 88.0)):
        db.add_speedtest({"ts": ts, "ok": True, "backend": "fake", "server": "Example Colo", "download_mbps": down, "upload_mbps": 17.0,
                          "latency_ms": 13.0, "jitter_ms": 1.0, "packet_loss_pct": 0.0, "duration_s": 9.0})
    # the marker and the events row an earlier run wrote when this PC joined network A
    db.set_meta(reports.NET_JOINED_META_KEY, json.dumps({"ts": joined, "gateway": "192.168.50.1", "networks": ["192.168.50.0/24"],
                                                         "nic": "Ethernet", "seen_ts": joined}))
    db.add_event("info", "network", "network changed: Ethernet: 192.168.50.112/24 · gateway 192.168.50.1", ts=joined)
    return SimpleNamespace(minute=minute, joined=float(joined), moved=float(moved), oldest=oldest, ids=ids,
                           segments={k: v[1] for k, v in segments.items()}, started=float(joined + 600))


@pytest.fixture
def service(data_dir, monkeypatch):
    """The engine's Full Scan parts on fake edges, with seeded history, its API on an ephemeral port and a live event stream."""
    from tnt.engine import Engine

    world = World()
    backend = FakeBackend()
    monkeypatch.setattr(sched_mod, "select_backend", lambda config: backend)
    monkeypatch.setattr(netinfo, "netinfo_snapshot", world.snapshot)
    # the routers' MACs, as the ARP table would list them once the pinger reached each gateway (never this PC's own table)
    monkeypatch.setattr(arp, "get_arp_table", lambda: {"192.168.50.1": "02:00:5E:10:00:01", "10.20.30.1": "02:00:5E:30:00:01"})
    monkeypatch.setattr(reports, "socket", SimpleNamespace(gethostname=lambda: "BENCH-01"))
    (data_dir / "config.json").write_text(json.dumps(CONFIG), encoding="utf-8")

    eng = Engine(console=True, port=0, data_dir=data_dir)
    eng.netinfo_summary = world.summary
    stream: Optional[EventStream] = None
    try:
        eng._start_config()
        eng._start_db()
        eng._start_bus()
        assert eng.db is not None and not eng.errors, eng.errors
        seeded = seed_history(eng.db, time.time())
        eng.started_ts = seeded.started           # the service run that is now going: it started on network A
        with eng._lock:
            eng._running = True                   # the engine's own stop() tears the parts started here down
        eng._start_speed()
        eng.discovery = FakeScanner(world)
        eng._start_reports()
        eng._start_api()
        assert eng.speed is not None and eng.reports is not None and eng.api is not None and not eng.errors, eng.errors
        eng.reports.wifi_wait_s = WAIT_S          # a posted snapshot is expected in time; scan 2 shortens it
        stream = EventStream(eng.api.port)
        stream.wait("hello", what="(the stream's greeting)")
        yield SimpleNamespace(eng=eng, port=eng.api.port, world=world, backend=backend, stream=stream, seeded=seeded)
    finally:
        if stream is not None:
            stream.close()
        backend.gate.set()
        eng.stop()


# --------------------------------------------------------------------------- the test
def test_full_scans_through_the_real_service(service):
    eng, port, stream, seeded, world = service.eng, service.port, service.stream, service.seeded, service.world
    db = eng.db

    # the manager compared network A with the marker at start: same network, so the join time stands
    until(lambda: (reports.parse_marker(db.get_meta(reports.NET_JOINED_META_KEY)) or {}).get("seen_ts") == seeded.started,
          "the start-up network check")
    assert eng.reports.joined_ts() == seeded.joined
    assert ok(port, "GET", "/api/reports") == {"reports": [], "total": 0}
    assert ok(port, "GET", "/api/reports/scan") == {"job": None}

    # ---- scan 1: started unnamed, named while it runs, Wi-Fi posted when the event stream announces the phase
    mark = stream.mark()
    job = ok(port, "POST", "/api/reports/scan", {})["job"]
    assert set(job) == JOB_KEYS and job["status"] == "running" and job["site"] is None and job["phase"] == "speed"
    assert [p["key"] for p in job["phases"]] == list(reports.PHASES) and all(set(p) == PHASE_KEYS for p in job["phases"])
    status, _h, busy = call(port, "POST", "/api/reports/scan", {"site": "Northside Warehouse"})
    assert status == 409 and busy["error"]["code"] == "busy" and busy["job"]["id"] == job["id"]
    named = ok(port, "PATCH", "/api/reports/scan", {"site": "  Acme   Dental "})["job"]
    assert named["id"] == job["id"] and named["site"] == "Acme Dental"
    waiting = stream.wait("report.progress", lambda d: d["job"]["id"] == job["id"] and d["job"]["phase"] == "wifi", mark,
                          "(phase wifi)")["job"]
    assert waiting["status"] == "running" and {p["key"]: p["status"] for p in waiting["phases"]}["wifi"] == "running"
    snapshot = {"available": True, "state": "ok", "error": None, "collected_ts": round(time.time(), 3),
                "interfaces": [{"guid": "{7E57AB1E-0000-4000-8000-0000000000A7}", "description": "Example Wi-Fi 6E Adapter",
                                "state": "connected", "connected_bssid": "02:00:5E:20:00:01", "connected_ssid": "Acme-Staff"}],
                "aps": [dict(a) for a in APS]}
    posted = ok(port, "POST", "/api/reports/scan/wifi", snapshot)["job"]
    assert posted["id"] == job["id"] and posted["message"] == "Wi-Fi scan received: 5 access points"
    saved = event_data(stream.wait("report.saved", since=mark, what="(scan 1)"))
    assert set(saved) == {"id", "site", "status"} and saved["site"] == "Acme Dental" and saved["status"] == "complete"
    r1 = saved["id"]
    progress = [d["job"] for d in stream.since(mark, "report.progress") if d["job"]["id"] == job["id"]]
    assert all(set(j) == JOB_KEYS for j in progress)
    assert [j["pct"] for j in progress] == sorted(j["pct"] for j in progress), "the percentage never goes back"
    assert {j["phase"] for j in progress} >= {"speed", "discovery", "wifi", "finalize"}
    assert progress[-1]["status"] == "saved" and progress[-1]["report_id"] == r1 and progress[-1]["pct"] == 100
    done = ok(port, "GET", "/api/reports/scan")["job"]
    assert done["status"] == "saved" and done["report_id"] == r1 and [p["status"] for p in done["phases"]] == ["done"] * 5
    status, _h, late = call(port, "POST", "/api/reports/scan/wifi", snapshot)
    assert status == 409 and late["error"]["code"] == "not_waiting"

    rep1 = ok(port, "GET", f"/api/reports/{r1}")
    assert set(rep1) == ROW_KEYS | {"data"} and rep1["site"] == "Acme Dental" and rep1["status"] == "complete"
    assert rep1["created_ts"] == job["started_ts"]
    data = rep1["data"]
    assert set(data) == {"meta", "network", "speed", "ping", "outages", "discovery", "wifi"}
    assert all(data[k]["available"] for k in data if k != "meta")
    meta = data["meta"]
    assert meta["site"] == "Acme Dental" and meta["hostname"] == "BENCH-01" and meta["created_ts"] == job["started_ts"]
    assert [(p["key"], p["status"]) for p in meta["scan_phases"]] == [(k, "done") for k in reports.PHASES]
    # network A, from the adapter snapshot; the public address and ISP from the scan's own speed test
    nic = data["network"]["internet_nic"]
    assert (nic["name"], nic["ipv4"], nic["prefix"], nic["gateway"], nic["mac"], nic["link_bps"], nic["internet"]) == \
        ("Ethernet", "192.168.50.112", 24, "192.168.50.1", "02:00:5E:00:53:07", 1_000_000_000, True)
    assert data["network"]["public_ip"] == PUBLIC_IP and data["network"]["isp"] == "Example ISP"
    # the scan's own speed test (stored, and found again in the window with the one tested on network A)
    speed = data["speed"]
    assert (speed["result"]["download_mbps"], speed["result"]["upload_mbps"], speed["result"]["latency_ms"]) == (94.2, 18.6, 12.3)
    assert speed["result"]["ok"] is True and speed["result"]["id"] is not None
    assert speed["window"]["count"] == 2 and speed["window"]["download_min"] == 88.0 and speed["window"]["download_max"] == 94.2
    # the window: from the time this PC joined network A to the moment the scan started; the older, worse minutes are left out
    ping = data["ping"]
    assert (ping["window_reason"], ping["window_start"], ping["window_end"]) == ("network_change", seeded.joined, job["started_ts"])
    targets = {t["host"]: t for t in ping["targets"]}
    assert [t["role"] for t in ping["targets"]] == ["gateway", "internet", "internet"] and set(targets) == set(PING)
    both = [("A", seeded.segments["A"]), ("B", seeded.segments["B"])]
    for host in PING:
        want = expected_ping(host, both)
        assert {k: targets[host][k] for k in want} == pytest.approx(want, abs=0.011), host
    assert targets["gateway"]["max_ms"] == 6.0 and targets["gateway"]["p95_ms"] == 2.0 and targets["gateway"]["jitter_ms"] == 0.5
    assert targets["example.net"]["label"] == "Example"
    # outages: the whole-internet one and the single target one on network A, the open one on network B (cut at the window end)
    out = data["outages"]
    assert out["count"] == 3 and out["by_kind"] == {"target": 2, "total_local": 0, "total_internet": 1, "gap": 0}
    assert (out["network_outages"], out["target_outages"]) == (1, 2), "the internet outage and two single-target outages"
    assert out["network_down_s"] == 300.0 and out["items_total"] == 3
    assert [(i["kind"], i["host"], i["open"], i["name"]) for i in out["items"]] == [
        ("target", "example.net", True, "Example (example.net)"), ("target", "198.51.100.20", False, "198.51.100.20"),
        ("total_internet", None, False, None)]
    assert out["items"][0]["end_ts"] == pytest.approx(job["started_ts"], abs=0.01)
    assert out["longest_s"] == 300.0, "the longest network outage, not the single target still down"
    assert out["monitored_s"] == pytest.approx(job["started_ts"] - seeded.joined, abs=0.2)
    assert out["items"][1]["duration_s"] == 120.0 and 0 < out["items"][1]["missed_pct"] <= 100
    assert (job["window_start"], job["window_reason"]) == (seeded.joined, "network_change")
    # Discovery over the default range and ports, through the engine's runner
    disc = data["discovery"]
    assert eng.discovery.scans == [("192.168.50.0/24", [int(p) for p in eng.config.get("discovery.ports")])]
    assert disc["range"] == "192.168.50.0/24" and disc["host_count"] == 4 and disc["duration_s"] == 18.4
    assert disc["device_types"] == {"Router": 1, "Camera": 2, "Phone": 1} and disc["run_id"] == db.list_discovery_runs(1)[0]["id"]
    assert [h["ip"] for h in disc["hosts"]] == ["192.168.50.1", "192.168.50.20", "192.168.50.21", "192.168.50.60"]
    # Wi-Fi from the posted snapshot
    wifi = data["wifi"]
    assert wifi["aps_count"] == 5 and wifi["networks"] == 3 and wifi["adapter"] == "Example Wi-Fi 6E Adapter"
    assert wifi["connected"] == {"ssid": "Acme-Staff", "bssid": "02:00:5E:20:00:01", "rssi": -48, "band": "5", "channel": 36,
                                 "width_mhz": 80, "channel_aps": 2, "overlap_aps": 2}
    assert wifi["bands"]["2.4"]["busiest_channel"] == 6 and wifi["bands"]["2.4"]["busiest_channel_aps"] == 2
    assert wifi["bands"]["5"]["strongest_rssi"] == -48 and wifi["bands"]["6"]["aps"] == 0
    assert [a["rssi"] for a in wifi["aps"]] == [-48, -55, -61, -75, -82]
    # the summary is the service's own reading of that data
    summary = rep1["summary"]
    assert summary == reports.build_summary(data)
    assert (summary["download_mbps"], summary["gateway_avg_ms"], summary["outages"], summary["downtime_s"], summary["hosts"],
            summary["wifi_aps"], summary["wifi_connected_rssi"]) == (94.2, targets["gateway"]["avg_ms"], 3, 300.0, 4, 5, -48)
    assert summary["window_hours"] == pytest.approx((job["started_ts"] - seeded.joined) / 3600.0, abs=0.06)
    status_reports = ok(port, "GET", "/api/status")["reports"]
    assert status_reports["count"] == 1 and status_reports["sites"] == 1 and status_reports["last"]["id"] == r1
    assert status_reports["job"]["status"] == "saved"

    # ---- the PC moves to network B; scan 2 gets no Wi-Fi snapshot and gives up on it
    world.name = "B"
    eng._on_net_changed({"generation": 2, "ts": seeded.moved, "default_gateway": "10.20.30.1", "previous_gateway": "192.168.50.1",
                         "internet_nic": {"name": "Wi-Fi", "networks": ["10.20.30.0/24"]},
                         "summary": "Wi-Fi: 10.20.30.45/24 · gateway 10.20.30.1"})
    until(lambda: eng.reports.joined_ts() == seeded.moved, "the join time of network B")
    until(lambda: (reports.parse_marker(db.get_meta(reports.NET_JOINED_META_KEY)) or {}).get("gateway_mac") == "02:00:5E:30:00:01",
          "network B's router MAC in the marker")
    until(lambda: any(e["category"] == "network" and "10.20.30.45" in e["message"] for e in db.list_events(20)),
          "the network changed events row")
    eng.reports.wifi_wait_s = 1.0
    mark = stream.mark()
    job2 = ok(port, "POST", "/api/reports/scan", {"site": "Maple Street Office"})["job"]
    assert job2["site"] == "Maple Street Office" and job2["id"] != job["id"]
    saved2 = event_data(stream.wait("report.saved", since=mark, what="(scan 2)"))
    assert saved2["site"] == "Maple Street Office" and saved2["status"] == "partial"
    r2 = saved2["id"]
    progress2 = [d["job"] for d in stream.since(mark, "report.progress") if d["job"]["id"] == job2["id"]]
    wifi_phase = next(p for p in progress2[-1]["phases"] if p["key"] == "wifi")
    assert (wifi_phase["status"], wifi_phase["message"]) == ("skipped", reports.NO_WINDOW_REASON)
    assert all(p["status"] == "done" for p in progress2[-1]["phases"] if p["key"] != "wifi")
    rep2 = ok(port, "GET", f"/api/reports/{r2}")
    d2 = rep2["data"]
    assert d2["wifi"]["available"] is False and d2["wifi"]["reason"] == reports.NO_WINDOW_REASON and d2["wifi"]["aps"] == []
    assert set(d2["wifi"]["bands"]) == {"2.4", "5", "6"}, "an uncollected section keeps its full shape"
    assert d2["network"]["internet_nic"]["name"] == "Wi-Fi" and d2["network"]["internet_nic"]["gateway"] == "10.20.30.1"
    assert d2["network"]["warnings"] == ["no_dns"] and d2["discovery"]["range"] == "10.20.30.0/24"
    assert d2["discovery"]["device_types"] == {"Router": 1, "Camera": 1}
    assert (d2["ping"]["window_reason"], d2["ping"]["window_start"], d2["ping"]["window_end"]) == \
        ("network_change", seeded.moved, job2["started_ts"])
    targets2 = {t["host"]: t for t in d2["ping"]["targets"]}
    for host in PING:
        want = expected_ping(host, [("B", seeded.segments["B"])])
        assert {k: targets2[host][k] for k in want} == pytest.approx(want, abs=0.011), host
    assert d2["outages"]["count"] == 1 and d2["outages"]["items"][0]["open"] is True
    assert d2["speed"]["window"]["count"] == 2 and d2["speed"]["window"]["download_avg"] == pytest.approx((94.2 + 150.0) / 2, abs=0.01)
    assert rep2["summary"] == reports.build_summary(d2) and rep2["summary"]["wifi_aps"] is None

    # ---- compare scan 2 (A, being judged) with scan 1 (B, the reference)
    comparison = ok(port, "GET", f"/api/reports/compare?a={r2}&b={r1}")
    assert comparison == reports.compare_reports(rep2, rep1)
    assert comparison["a"] == {"id": r2, "site": "Maple Street Office", "created_ts": rep2["created_ts"], "status": "partial"}
    rows = {s["key"]: {r["key"]: r for r in s["rows"]} for s in comparison["sections"]}
    assert [s["key"] for s in comparison["sections"]] == ["speed", "ping", "outages", "wifi", "discovery"]
    assert rows["speed"]["download_mbps"]["better"] == "a" and rows["speed"]["latency_ms"]["better"] == "a"
    assert rows["ping"]["internet_avg_ms"]["better"] == "b" and "host:198.51.100.20:avg_ms" in rows["ping"]
    assert rows["ping"]["host:example.net:avg_ms"]["label"] == "Example average"
    assert rows["ping"]["gateway_avg_ms"]["note"].startswith("Windows: A ")
    wifi_section = next(s for s in comparison["sections"] if s["key"] == "wifi")
    assert wifi_section["note"] == f"A: {reports.NO_WINDOW_REASON}"
    assert rows["wifi"]["connected_rssi"]["a"] is None and rows["wifi"]["connected_rssi"]["b"] == -48
    assert rows["wifi"]["connected_rssi"]["better"] is None
    assert rows["discovery"]["hosts"]["higher_is_better"] is None and rows["discovery"]["hosts"]["delta"] == -2
    for query, code in (("?a=abc&b=1", 400), (f"?a={r2}", 400), (f"?a={r2}&b=999", 404)):
        assert call(port, "GET", "/api/reports/compare" + query)[0] == code, query

    # ---- both PDFs
    status, headers, pdf = call(port, "GET", f"/api/reports/{r1}/pdf")
    assert status == 200 and headers["content-type"] == "application/pdf"
    assert re.fullmatch(r'attachment; filename="TNT-report-Acme-Dental-\d{4}-\d{2}-\d{2}-\d{4}\.pdf"', headers["content-disposition"])
    assert 1 <= assert_valid_pdf(pdf) <= 3
    text = pdf_text(pdf)
    for needle in (b"Site report: Acme Dental", b"192.168.50.112", b"Acme-Staff", b"example.net", b"Example Colo"):
        assert needle in text, needle
    status, headers, pdf = call(port, "GET", f"/api/reports/compare/pdf?a={r2}&b={r1}")
    assert status == 200 and headers["content-type"] == "application/pdf"
    assert headers["content-disposition"] == 'attachment; filename="TNT-compare-Maple-Street-Office-vs-Acme-Dental.pdf"'
    assert 1 <= assert_valid_pdf(pdf) <= 2
    assert b"Comparison: Maple Street Office vs Acme Dental" in pdf_text(pdf)

    # ---- the saved reports: list, search, sites, rename
    listed = ok(port, "GET", "/api/reports")
    assert listed["total"] == 2 and [r["id"] for r in listed["reports"]] == [r2, r1]
    assert all(set(r) == ROW_KEYS for r in listed["reports"]) and listed["reports"][1]["summary"] == rep1["summary"]
    assert [r["id"] for r in ok(port, "GET", "/api/reports?q=DENTAL")["reports"]] == [r1]
    sites = ok(port, "GET", "/api/reports/sites?q=a")
    assert [s["site"] for s in sites["sites"]] == ["Acme Dental", "Maple Street Office"] and sites["total"] == 2
    mark = stream.mark()
    renamed = ok(port, "PATCH", f"/api/reports/{r1}", {"site": " Acme  Dental   North "})
    assert set(renamed) == ROW_KEYS and renamed["site"] == "Acme Dental North"
    assert event_data(stream.wait("report.updated", since=mark, what="(rename)")) == {"id": r1, "site": "Acme Dental North"}
    assert ok(port, "GET", f"/api/reports/{r1}")["data"]["meta"]["site"] == "Acme Dental North"
    assert ok(port, "PATCH", "/api/reports/scan", {"site": "Maple Street Office East"})["job"]["report_id"] == r2
    assert ok(port, "GET", f"/api/reports/{r2}")["site"] == "Maple Street Office East", "naming the last scan renames its report"

    # ---- scan 3: cancelled during its own speed test; nothing is saved, the test is not stored
    tests_before = len(db.list_speedtests(0, time.time() + 60))
    service.backend.gate.clear()
    mark = stream.mark()
    job3 = ok(port, "POST", "/api/reports/scan", {"site": "Northside Warehouse"})["job"]
    stream.wait("report.progress", lambda d: d["job"]["id"] == job3["id"] and d["job"]["message"] == "Running the speed test", mark,
                "(scan 3 speed test)")
    cancelled = ok(port, "DELETE", "/api/reports/scan")["job"]
    assert cancelled["id"] == job3["id"] and cancelled["status"] == "cancelled" and cancelled["phase"] is None
    assert [p["status"] for p in cancelled["phases"]] == ["skipped"] * 5 and cancelled["report_id"] is None
    until(lambda: not eng.speed.running, "the cancelled speed test to end")
    service.backend.gate.set()
    time.sleep(0.3)
    assert ok(port, "GET", "/api/reports/scan")["job"]["status"] == "cancelled"
    assert len(db.list_speedtests(0, time.time() + 60)) == tests_before and ok(port, "GET", "/api/reports")["total"] == 2
    assert stream.since(mark, "report.saved") == [] and len(eng.discovery.scans) == 2
    assert call(port, "POST", "/api/reports/scan/wifi", snapshot)[2]["error"]["code"] == "not_waiting"
    status, _h, refused = call(port, "PATCH", "/api/reports/scan", {"site": "Too Late"})
    assert status == 409 and refused["error"]["code"] == "not_running"

    # ---- delete
    mark = stream.mark()
    assert ok(port, "DELETE", f"/api/reports/{r2}") == {"ok": True}
    assert event_data(stream.wait("report.deleted", since=mark, what="(delete)")) == {"id": r2}
    assert call(port, "GET", f"/api/reports/{r2}")[0] == 404 and call(port, "DELETE", f"/api/reports/{r2}")[0] == 404
    assert call(port, "GET", f"/api/reports/compare?a={r1}&b={r2}")[0] == 404
    assert ok(port, "GET", "/api/reports")["total"] == 1

    # ---- the Reports page asks for up to 500 sites at once
    for i in range(1, 211):
        site = f"Example Site {i:03d}"
        db.add_report(site, reports.site_key(site), seeded.oldest + i, seeded.oldest + i + 90, "complete", "test", {}, {})
    many = ok(port, "GET", "/api/reports/sites?limit=500")
    assert many["total"] == 211 and len(many["sites"]) == 211 and many["sites"][0]["site"] == "Acme Dental North"
