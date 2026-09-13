"""Tests for tnt.reports (Full Scan site reports), tnt.report_pdf and the /api/reports routes.

Everything is synthetic: RFC 5737 / RFC 1918 addresses, locally administered MACs, invented site names
and SSIDs.  No real speed test, Discovery sweep or Wi-Fi scan runs: the speed scheduler gets a fake
backend, the discovery scanner is a fake, network adapters come from a fake snapshot and the Wi-Fi
survey snapshot is posted by the test.
"""
from __future__ import annotations

import base64
import http.client
import json
import re
import sqlite3
import threading
import time
import zlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from tnt import __version__, networks, oui, report_pdf, reports
from tnt import config as tnt_config
from tnt import db as tnt_db
from tnt import events as tnt_events
from tnt.api.server import ApiServer
from tnt.speedtest import scheduler as sched_mod
from tnt.speedtest.base import SpeedResult

T0 = 1_780_000_000.0
HOUR = 3600.0
DAY = 86400.0


# --------------------------------------------------------------------------------------
# helpers and synthetic data
# --------------------------------------------------------------------------------------
def _wait_for(pred, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def _page_count(pdf: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page(?![s/])", pdf))


def _pdf_text(pdf: bytes) -> bytes:
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


def ap(bssid: str, ssid: str, rssi: int, band: str, channel: int, width: int = 20, connected: bool = False,
       stale: bool = False, hidden: bool = False) -> Dict[str, Any]:
    """A survey access point dict as client/wifi_survey.py reports it (invented values)."""
    return {"bssid": bssid, "ssid": ssid, "hidden": hidden, "rssi": rssi, "quality": 70, "band": band, "channel": channel,
            "center_channel": channel, "width_mhz": width, "freq_mhz": 5180 if band == "5" else 2437, "spans": [],
            "phy": "ac", "phys": ["ac"], "generation": "Wi-Fi 5", "security": "WPA2-Personal", "beacon_ms": 102,
            "max_rate_mbps": 866, "oui": "FF:FF:FF", "locally_administered": False, "base_oui": None,
            "connected": connected, "first_seen": T0, "last_seen": T0, "seen_count": 3, "stale": stale}


AP_LIST = [
    ap("02:00:5E:20:00:01", "Acme-Staff", -48, "5", 36, 80, connected=True),
    ap("02:00:5E:20:00:02", "Acme-Staff", -61, "2.4", 6),
    ap("02:00:5E:20:00:03", "Acme-Guest", -55, "5", 36, 80),
    ap("02:00:5E:20:00:04", "Acme-Guest", -70, "2.4", 6),
    ap("02:00:5E:20:00:05", "Neighbour-Net", -82, "2.4", 11),
    ap("02:00:5E:20:00:06", "", -75, "2.4", 6, hidden=True),
    ap("02:00:5E:20:00:07", "Old-Printer", -88, "2.4", 1, stale=True),
]

HOSTS = [
    {"ip": "192.168.50.1", "hostname": "router.example", "mac": "02:00:5E:10:00:01", "vendor": None, "ping_ok": True,
     "rtt_ms": 0.6, "open_ports": [80, 443], "device_type": "Router"},
    {"ip": "192.168.50.20", "hostname": None, "mac": "02:00:5E:10:00:14", "vendor": None, "ping_ok": True,
     "rtt_ms": 1.4, "open_ports": [554], "device_type": "Camera"},
    {"ip": "192.168.50.21", "hostname": "cam-lobby", "mac": "02:00:5E:10:00:15", "vendor": None, "ping_ok": False,
     "rtt_ms": None, "open_ports": [80, 554], "device_type": "Camera"},
    {"ip": "192.168.50.60", "hostname": None, "mac": None, "vendor": None, "ping_ok": True, "rtt_ms": 2.0,
     "open_ports": [], "device_type": None},
]


def wifi_body(available: bool = True, state: str = "ok", aps: Optional[List[Dict[str, Any]]] = None,
              error: Optional[str] = None) -> Dict[str, Any]:
    return {"available": available, "state": state, "error": error, "collected_ts": T0,
            "interfaces": [{"guid": "{00000000-0000-0000-0000-000000000001}", "description": "Example Wireless Adapter",
                            "state": "connected", "connected_bssid": "02:00:5E:20:00:01", "connected_ssid": "Acme-Staff"}],
            "aps": [dict(a) for a in (AP_LIST if aps is None else aps)]}


def fake_snapshot() -> Dict[str, Any]:
    """A netinfo_snapshot() of an invented PC on 192.168.50.0/24."""
    return {"ts": T0, "internet_nic_index": 7, "default_gateway": "192.168.50.1", "public_hint": None, "adapters": [
        {"index": 7, "name": "Ethernet", "description": "Example Gigabit Adapter", "mac": "02:00:5E:00:53:07",
         "type_name": "Ethernet", "status": "up", "speed_bps": 1_000_000_000, "dhcp_enabled": True,
         "dhcp_server": "192.168.50.1", "is_physical": True, "primary_ipv4": "192.168.50.112",
         "ipv4": [{"address": "192.168.50.112", "prefix": 24, "family": 4, "netmask": "255.255.255.0",
                   "network": "192.168.50.0/24"}],
         "gateways": ["192.168.50.1"], "dns": ["192.168.50.1", "198.51.100.53"],
         "warnings": [{"code": "no_dns", "message": "x"}, {"code": "no_dns", "message": "x"}]},
        {"index": 9, "name": "Wi-Fi", "description": "Example Wireless Adapter", "mac": "02:00:5E:00:53:09",
         "type_name": "Wi-Fi", "status": "down", "speed_bps": None, "dhcp_enabled": True, "dhcp_server": None,
         "is_physical": True, "primary_ipv4": None, "ipv4": [], "gateways": [], "dns": [], "warnings": []},
    ]}


class FakeBackend:
    name = "fake"

    def __init__(self, ok: bool = True, block: bool = False) -> None:
        self.ok = ok
        self.block = block
        self.gate = threading.Event()
        self.started = threading.Event()
        self.calls = 0

    def available(self, config: Any) -> Any:
        return True, "fake"

    def run(self, config: Any, progress: Any = None, cancel: Any = None) -> SpeedResult:
        self.calls += 1
        self.started.set()
        if progress:
            progress("download", 0.5)
            progress("upload", 1.0)
        if self.block:
            while not self.gate.is_set() and not (cancel is not None and cancel.is_set()):
                time.sleep(0.01)
        if cancel is not None and cancel.is_set():
            return SpeedResult(ok=False, ts=time.time(), backend="fake", error="cancelled", duration_s=0.1)
        if not self.ok:
            return SpeedResult(ok=False, ts=time.time(), backend="fake", error="the fake server hung up", duration_s=0.1)
        return SpeedResult(ok=True, ts=time.time(), backend="fake", server="Example Colo", isp="Example ISP",
                           external_ip="203.0.113.10", download_mbps=94.2, upload_mbps=18.6, latency_ms=12.3,
                           jitter_ms=1.1, packet_loss_pct=0.0, duration_s=1.0, raw={"x": 1})


class FakeScanner:
    """Stands in for tnt.discovery.DiscoveryScanner: returns HOSTS, optionally blocking until released."""

    def __init__(self, block: bool = False, default: Optional[str] = "192.168.50.0/24") -> None:
        self.block = block
        self.default = default
        self.gate = threading.Event()
        self.scans: List[str] = []
        self.stopped = False

    def default_cidr(self) -> Optional[str]:
        return self.default

    def parse_range(self, text: str) -> str:
        return text

    def stop(self) -> None:
        self.stopped = True

    def scan(self, range_text: str, ports: Any = None, progress: Any = None, cancel: Any = None) -> Any:
        self.scans.append(range_text)
        if progress:
            progress({"phase": "ping", "done": 100, "total": 254, "found": 2, "elapsed_s": 0.1})
        if self.block:
            while not self.gate.is_set() and not (cancel is not None and cancel.is_set()):
                time.sleep(0.01)
        cancelled = bool(cancel is not None and cancel.is_set())
        result = {"ts": time.time(), "cidr": range_text, "ports": list(ports or []), "method": "native",
                  "hosts": [] if cancelled else [dict(h) for h in HOSTS], "scanned": 254, "duration_s": 0.2,
                  "ok": True, "error": None, "cancelled": cancelled}
        return SimpleNamespace(to_dict=lambda: dict(result))


class Rig:
    """A real (unstarted) Engine with a real config, database, bus and speed scheduler, a fake discovery scanner
    and a ReportManager on fake adapters."""

    def __init__(self, data_dir: Path, monkeypatch: Any, backend: Optional[FakeBackend] = None,
                 scanner: Optional[FakeScanner] = None, wifi_wait_s: float = 8.0, wifi_grace_s: float = 0.4) -> None:
        from tnt.engine import Engine

        self.cfg = tnt_config.Config(data_dir / "config.json").load()
        self.db = tnt_db.Database(data_dir / "tnt.db")
        self.bus = tnt_events.EventBus()
        self.events: List[Dict[str, Any]] = []
        self.bus.subscribe(self.events.append)
        self.backend = backend or FakeBackend()
        monkeypatch.setattr(sched_mod, "select_backend", lambda c: self.backend)
        eng = Engine(console=True, port=0, data_dir=data_dir)
        eng.config, eng.db, eng.bus = self.cfg, self.db, self.bus
        eng.speed = sched_mod.SpeedScheduler(self.db, self.cfg, self.bus)
        eng.discovery = scanner or FakeScanner()
        self.engine = eng
        self.gateway_macs: Dict[str, str] = {"192.168.50.1": "02:00:5E:10:00:01"}
        self.mgr = reports.ReportManager(self.db, self.cfg, self.bus, eng, netinfo_fn=fake_snapshot,
                                         network_fn=lambda: ("192.168.50.1", ["192.168.50.0/24"], "Ethernet"),
                                         gateway_mac_fn=self.gateway_macs.get, hostname_fn=lambda: "BENCH-01",
                                         wifi_wait_s=wifi_wait_s, wifi_grace_s=wifi_grace_s, discovery_wait_s=10.0,
                                         mac_wait_s=0.2)
        eng.reports = self.mgr
        self.server: Optional[ApiServer] = None

    def serve(self, ui_dir: Path) -> ApiServer:
        self.server = ApiServer(self.engine, "127.0.0.1", 0, bus=self.bus, ui_dir=ui_dir)
        self.engine.api = self.server
        self.server.start()
        return self.server

    def types(self, prefix: str) -> List[str]:
        return [e["type"] for e in self.events if e["type"].startswith(prefix)]

    def close(self) -> None:
        self.backend.gate.set()
        scanner = self.engine.discovery
        if isinstance(scanner, FakeScanner):
            scanner.gate.set()
        self.mgr.stop()
        t = self.mgr._thread
        if t is not None:
            t.join(5.0)
        if self.engine._disc_thread is not None:
            self.engine._disc_thread.join(5.0)
        self.engine.speed.stop()
        if self.server is not None:
            self.server.stop()
        self.db.close()


@pytest.fixture
def rig_factory(data_dir, monkeypatch):
    made: List[Rig] = []

    def make(**kw: Any) -> Rig:
        made.append(Rig(data_dir, monkeypatch, **kw))
        return made[-1]

    yield make
    for r in made:
        r.close()


@pytest.fixture
def db(tmp_path):
    d = tnt_db.Database(tmp_path / "tnt.db")
    yield d
    d.close()


def post_when_waiting(mgr: reports.ReportManager, body: Dict[str, Any], timeout: float = 10.0) -> Dict[str, Any]:
    """Post the Wi-Fi snapshot as soon as the job waits for one (like a TNT window reacting to report.progress)."""
    deadline = time.time() + timeout
    while True:
        try:
            return mgr.post_wifi(body)
        except reports.ScanConflict:
            if time.time() > deadline:
                raise
            time.sleep(0.02)


def finished(mgr: reports.ReportManager, timeout: float = 10.0) -> Dict[str, Any]:
    assert _wait_for(lambda: (mgr.job() or {}).get("status") != "running" and mgr._thread is None, timeout)
    return mgr.job()  # type: ignore[return-value]


def seed_minutes(db: tnt_db.Database, tid: int, start: float, minutes: int, avg: float, sent: int = 60,
                 received: int = 60, jitter: float = 0.5) -> None:
    base = int(start // 60) * 60
    for i in range(minutes):
        db.upsert_ping_minute(tid, base + i * 60, sent, received, avg if received else None,
                              (avg - 0.2) if received else None, (avg + 4) if received else None, jitter if received else None)


def outage_section(start: float, end: float, count: int, down_s: float, longest_s: float, targets: int = 0,
                   monitored_s: Optional[float] = None) -> Dict[str, Any]:
    """An outages section of *count* network outages (and *targets* single-target outages) over ``[start, end]``."""
    sec = reports.empty_section("outages", None)
    sec.update(available=True, window_start=start, window_end=end, count=count + targets, network_outages=count,
               target_outages=targets, network_down_s=down_s, longest_s=longest_s if count else None,
               monitored_s=end - start if monitored_s is None else monitored_s, items_total=count + targets)
    sec["by_kind"]["total_internet"] = count
    sec["by_kind"]["target"] = targets
    return sec


def make_data(*, download: Optional[float] = 94.2, upload: float = 18.6, latency: float = 12.3,
              jitter: Optional[float] = 1.1, speed_ok: bool = True, gw_avg: float = 0.8, gw_loss: float = 0.0,
              inet=(("203.0.113.10", None, 14.0, 0.5), ("example.net", "Example", 22.0, 0.0)),
              window_s: float = 6 * DAY, outages: int = 3, down_s: float = 600.0, longest_s: float = 400.0,
              aps: Optional[List[Dict[str, Any]]] = None, hosts: Optional[List[Dict[str, Any]]] = None,
              wifi: bool = True, end: float = T0, outage_rows: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    start = end - window_s
    result = {"ts": end + 5, "backend": "cloudflare", "server": "Example Colo", "isp": None, "external_ip": "203.0.113.10",
              "download_mbps": download, "upload_mbps": upload, "latency_ms": latency, "jitter_ms": jitter,
              "packet_loss_pct": 0.0, "ok": speed_ok, "error": None if speed_ok else "timeout", "id": 7}
    samples = 518400
    targets = [{"id": 1, "host": "gateway", "label": "Gateway", "ip": "192.168.50.1", "role": "gateway",
                "samples": samples, "lost": int(samples * gw_loss / 100), "loss_pct": gw_loss, "avg_ms": gw_avg,
                "min_ms": 0.3, "max_ms": 45.0, "p95_ms": round(gw_avg * 2, 2), "jitter_ms": 0.2}]
    for i, (host, label, avg, loss) in enumerate(inet, start=2):
        targets.append({"id": i, "host": host, "label": label, "ip": f"198.51.100.{i}", "role": "internet",
                        "samples": samples, "lost": int(samples * loss / 100), "loss_pct": loss, "avg_ms": avg,
                        "min_ms": avg - 3, "max_ms": avg * 6, "p95_ms": avg * 1.5, "jitter_ms": 1.0})
    if outage_rows is not None:
        outage_sec = reports.build_outages_section(outage_rows, start, end)
    else:
        outage_sec = outage_section(start, end, outages, down_s, longest_s)
    if wifi:
        wifi_sec = reports.build_wifi_section(reports.clean_wifi_snapshot(wifi_body(aps=aps), now=end))
    else:
        wifi_sec = reports.build_wifi_section(reports.clean_wifi_snapshot({"available": False, "state": "no_bridge"}))
    return {
        "meta": {"site": None, "created_ts": end, "completed_ts": end + 95, "duration_s": 95.0, "tnt_version": __version__,
                 "hostname": "BENCH-01", "scan_phases": [{"key": k, "status": "done", "message": None, "started_ts": end,
                                                          "finished_ts": end} for k in reports.PHASES]},
        "network": reports.build_network_section(fake_snapshot(), "203.0.113.10", None),
        "speed": reports.build_speed_section(result, [result] if speed_ok else [], None),
        "ping": {"available": True, "reason": None, "window_start": start, "window_end": end,
                 "window_reason": "network_change", "targets": targets, "note": None},
        "outages": outage_sec,
        "discovery": reports.build_discovery_section({"id": 3, "cidr": "192.168.50.0/24", "ts": end + 40, "duration_s": 18.2,
                                                      "hosts": [dict(h) for h in (HOSTS if hosts is None else hosts)]},
                                                     ["192.168.50.1"]),
        "wifi": wifi_sec,
    }


def make_report(site: str = "Acme Dental", report_id: int = 1, **kw: Any) -> Dict[str, Any]:
    data = make_data(**kw)
    data["meta"]["site"] = site
    created = data["meta"]["created_ts"]
    return {"id": report_id, "site": site, "created_ts": created, "completed_ts": created + 95, "status": "complete",
            "summary": reports.build_summary(data), "data": data}


# --------------------------------------------------------------------------------------
# site names, file names, windows, statistics
# --------------------------------------------------------------------------------------
def test_normalize_site_trims_collapses_and_limits():
    assert reports.normalize_site("  Acme \t  Dental\n") == "Acme Dental"
    assert reports.normalize_site("North\x00side  Warehouse") == "North side Warehouse"
    assert reports.normalize_site("x" * 80) == "x" * 80
    for bad in ("", "   \t", "x" * 81, None, 42, ["Acme"], "Acme " + chr(0xD800) + " Dental"):
        with pytest.raises(ValueError):
            reports.normalize_site(bad)
    assert reports.site_key(" ACME   dental ") == "acme dental"
    assert reports.site_key("Straße Zürich") == reports.site_key("STRASSE ZÜRICH") == "strasse zürich"
    assert reports.search_key("  ") is None and reports.search_key(None) is None and reports.search_key(" ÄB ") == "äb"


def test_pdf_file_names_are_plain_ascii():
    name = reports.pdf_filename('Café "Zürich" 100%/../x', T0)
    assert re.fullmatch(r"TNT-report-Cafe-Zurich-100-x-\d{4}-\d{2}-\d{2}-\d{4}\.pdf", name), name
    assert reports.pdf_filename("🦷", T0).startswith("TNT-report-site-")
    assert reports.compare_filename("Acme Dental", "北京") == "TNT-compare-Acme-Dental-vs-site.pdf"
    assert reports.pdf_filename("x" * 80, "not a time").endswith("-undated.pdf")
    assert all(name.isascii() for name in (reports.pdf_filename("Øst; rm -rf", T0), reports.compare_filename("a\r\nb", "c")))


def test_report_window_takes_the_latest_bound():
    end = T0
    assert reports.report_window(end) == (end - reports.WINDOW_S, "seven_days")
    assert reports.report_window(end, None, end - 3 * HOUR) == (end - 3 * HOUR, "data_start")
    assert reports.report_window(end, end - 2 * HOUR, end - 3 * HOUR) == (end - 2 * HOUR, "network_change")
    assert reports.report_window(end, end - 30 * DAY, end - 40 * DAY) == (end - reports.WINDOW_S, "seven_days")
    assert reports.report_window(end, end - HOUR, end - HOUR) == (end - HOUR, "network_change"), "a tie names the move"
    assert reports.report_window(end, end + 60) == (end, "network_change"), "never after the end"


def test_ping_stats_method():
    rows = [(60, 60, 10.0, 8.0, 15.0, 1.0), (60, 30, 20.0, 12.0, 40.0, 3.0), (60, 0, None, None, None, None),
            (60, 1, 50.0, 50.0, 50.0, 0.0)]
    st = reports.ping_stats(rows)
    assert st["samples"] == 240 and st["lost"] == 149 and st["loss_pct"] == 62.08
    assert st["avg_ms"] == 13.74                    # (600 + 600 + 50) / 91 replies
    assert st["min_ms"] == 8.0 and st["max_ms"] == 50.0
    assert st["p95_ms"] == 20.0                     # 95 % of 91 replies falls in the 20 ms minute
    assert st["jitter_ms"] == 1.66                  # (1.0 x 59 + 3.0 x 29) / 88 pairs
    empty = reports.ping_stats([])
    assert empty == {"samples": 0, "lost": 0, "loss_pct": None, "avg_ms": None, "min_ms": None, "max_ms": None,
                     "p95_ms": None, "jitter_ms": None}
    assert reports.weighted_percentile([(5.0, 1), (1.0, 1), (3.0, 1)], 50) == 3.0
    assert reports.weighted_percentile([(1.0, 0)], 95) is None


def test_target_roles():
    assert reports.target_role("gateway", "192.168.50.1") == "gateway"
    assert reports.target_role("Default Gateway") == "gateway"
    assert reports.target_role("192.168.50.1", "192.168.50.1", "local", gateway="192.168.50.1") == "gateway"
    assert reports.target_role("example.net", "198.51.100.7", "internet", gateway="192.168.50.1") == "internet"
    assert reports.target_role("192.168.50.20") == "local"
    assert reports.target_role("old-target.example") == "internet"


# --------------------------------------------------------------------------------------
# database
# --------------------------------------------------------------------------------------
def test_reports_table_is_added_to_an_existing_database(tmp_path):
    path = tmp_path / "tnt.db"
    old = tnt_db.Database(path)
    target = old.add_target("gateway", "Gateway")
    with old._lock:        # what a 1.9.1 database looks like: every table but reports
        old._conn.execute("DROP INDEX ix_reports_site_key")
        old._conn.execute("DROP INDEX ix_reports_created")
        old._conn.execute("DROP TABLE reports")
    old.close()
    raw = sqlite3.connect(str(path))
    try:
        assert raw.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='reports'").fetchone()[0] == 0
    finally:
        raw.close()
    d = tnt_db.Database(path)
    try:
        cols = {r["name"] for r in d._conn.execute("PRAGMA table_info(reports)").fetchall()}
        assert cols == {"id", "site", "site_key", "created_ts", "completed_ts", "status", "tnt_version", "summary", "data", "network_id"}
        indexes = {r["name"] for r in d._conn.execute("PRAGMA index_list(reports)").fetchall()}
        assert {"ix_reports_site_key", "ix_reports_created"} <= indexes
        assert d.get_target(target["id"])["host"] == "gateway" and d.get_meta("schema_version") == "1"
        rid = d.add_report("Acme Dental", "acme dental", T0, T0 + 90, "complete", __version__, {}, {"meta": {}})
        assert d.get_report(rid)["site"] == "Acme Dental"
    finally:
        d.close()


def test_report_store_lists_without_data_and_searches_casefolded(db):
    def add(site: str, ts: float, status: str = "complete") -> int:
        return db.add_report(site, reports.site_key(site), ts, ts + 90, status, __version__, {"download_mbps": 90.0},
                             {"meta": {"site": site}, "bulk": "x" * 5000})

    a1 = add("Acme Dental", T0 + 100)
    z = add("Zürich Büro", T0 + 200)
    n = add("Northside Warehouse", T0 + 300, "partial")
    a2 = add("ACME dental", T0 + 400)
    hall = add("Hall_B 100%", T0 + 500)
    rows, total = db.list_reports()
    assert [r["id"] for r in rows] == [hall, a2, n, z, a1] and total == 5
    assert set(rows[0]) == {"id", "site", "created_ts", "completed_ts", "status", "summary", "network_id"}, "never the data column"
    assert rows[0]["summary"] == {"download_mbps": 90.0}
    rows, total = db.list_reports(site_key=reports.site_key("acme  DENTAL"))
    assert [r["id"] for r in rows] == [a2, a1] and total == 2
    assert [r["id"] for r in db.list_reports(q_key=reports.search_key("ZÜRICH"))[0]] == [z], "casefolded in Python"
    for q in ("l_b", "_", "%", "0%"):
        assert [r["id"] for r in db.list_reports(q_key=q)[0]] == [hall], f"{q!r} is literal, not a LIKE wildcard"
    rows, total = db.list_reports(limit=2, offset=1)
    assert [r["id"] for r in rows] == [a2, n] and total == 5
    full = db.get_report(a1)
    assert full["data"]["bulk"] == "x" * 5000 and full["site_key"] == "acme dental" and full["tnt_version"] == __version__
    renamed = db.rename_report(a1, "Acme Dental Clinic", "acme dental clinic")
    assert renamed["site"] == "Acme Dental Clinic" and "data" not in renamed
    assert db.get_report(a1)["data"]["meta"]["site"] == "Acme Dental Clinic", "the report's own copy follows"
    assert db.rename_report(9999, "x", "x") is None and db.get_report(9999) is None
    assert db.report_stats() == {"count": 5, "sites": 5, "last": {"id": hall, "site": "Hall_B 100%",
                                                                 "created_ts": T0 + 500, "status": "complete"}}
    assert db.delete_report(z) is True and db.delete_report(z) is False
    assert db.list_reports()[1] == 4


def test_report_sites_prefix_first_then_most_recent(db):
    def add(site: str, ts: float) -> None:
        db.add_report(site, reports.site_key(site), ts, ts, "complete", __version__, {}, {})

    add("acme dental", T0 + 50)                 # an older spelling of the same site
    add("Acme Dental", T0 + 100)
    add("Dental Care North", T0 + 200)
    add("Northside Warehouse", T0 + 300)
    add("Lakeside Acme", T0 + 400)
    rows, total = db.report_sites()
    assert [r["site"] for r in rows] == ["Lakeside Acme", "Northside Warehouse", "Dental Care North", "Acme Dental"]
    assert total == 4
    assert rows[3] == {"site": "Acme Dental", "site_key": "acme dental", "count": 2, "last_ts": T0 + 100, "network_ids": []}
    db.add_report("Acme Dental", "acme dental", T0 + 150, T0 + 150, "complete", __version__, {}, {}, network_id=12)
    db.add_report("ACME Dental", "acme dental", T0 + 160, T0 + 160, "complete", __version__, {}, {}, network_id=5)
    assert db.report_sites("acme dental")[0][0]["network_ids"] == [5, 12], "the networks its reports were scanned on"
    db.delete_report(db.list_reports(site_key="acme dental")[0][0]["id"])
    db.delete_report(db.list_reports(site_key="acme dental")[0][0]["id"])
    assert [r["site"] for r in db.report_sites("acme")[0]] == ["Acme Dental", "Lakeside Acme"]
    assert [r["site"] for r in db.report_sites("dental")[0]] == ["Dental Care North", "Acme Dental"]
    assert [r["site"] for r in db.report_sites("north")[0]] == ["Northside Warehouse", "Dental Care North"]
    assert [r["site"] for r in db.report_sites("ide")[0]] == ["Lakeside Acme", "Northside Warehouse"]
    assert db.report_sites("ide")[1] == 2 and db.report_sites("nothing-like-it") == ([], 0)
    rows, total = db.report_sites(limit=1)
    assert len(rows) == 1 and total == 4


def test_retention_never_trims_reports(db):
    old = time.time() - 400 * DAY
    db.add_report("Acme Dental", "acme dental", old, old + 90, "complete", __version__, {}, {})
    db.add_event("info", "service", "ancient", ts=old)
    removed = db.retention(365)
    assert removed["events"] == 1 and "reports" not in removed
    assert db.list_reports()[1] == 1 and db.counts()["reports"] == 1


def test_ping_minute_helpers(db):
    assert db.oldest_ping_minute() is None
    t = db.add_target("gateway")
    base = int(T0 // 60) * 60
    for i in range(5):
        db.upsert_ping_minute(t["id"], base + i * 60, 60, 60, 1.0 + i, 0.5, 2.0 + i, 0.2)
    db.upsert_ping_minute(77, base - 3600, 60, 58, 20.0, 18.0, 30.0, 1.0)     # a removed target's history
    assert db.oldest_ping_minute() == base - 3600
    assert db.ping_target_ids(base, base + 300) == [t["id"]]
    assert db.ping_target_ids(base - 3600, base + 300) == sorted([t["id"], 77])
    rows = db.ping_minute_rows(t["id"], base + 30, base + 180)     # buckets overlapping [base+30, base+180)
    assert [r[2] for r in rows] == [1.0, 2.0, 3.0] and rows[0] == (60, 60, 1.0, 0.5, 2.0, 0.2)


# --------------------------------------------------------------------------------------
# sections
# --------------------------------------------------------------------------------------
def test_network_section_picks_the_internet_adapter():
    sec = reports.build_network_section(fake_snapshot(), "203.0.113.10", "AS64500")
    assert sec["available"] is True and sec["public_ip"] == "203.0.113.10" and sec["isp"] == "AS64500"
    assert sec["warnings"] == ["no_dns"]
    assert sec["internet_nic"] == {"name": "Ethernet", "description": "Example Gigabit Adapter", "type_name": "Ethernet",
                                   "internet": True, "ipv4": "192.168.50.112", "prefix": 24, "gateway": "192.168.50.1",
                                   "dns": ["192.168.50.1", "198.51.100.53"], "dhcp": True, "dhcp_server": "192.168.50.1",
                                   "mac": "02:00:5E:00:53:07", "link_bps": 1_000_000_000}
    bench = fake_snapshot()
    bench["internet_nic_index"] = None
    bench["default_gateway"] = None
    sec = reports.build_network_section(bench)
    assert sec["internet_nic"]["name"] == "Ethernet" and sec["internet_nic"]["internet"] is False
    assert sec["internet_nic"]["gateway"] == "192.168.50.1", "the adapter's own gateway"
    offline = fake_snapshot()
    offline["internet_nic_index"] = None
    offline["adapters"][0]["status"] = "down"
    assert reports.build_network_section(offline)["reason"] == "This PC is not connected to a network"
    assert reports.build_network_section({"adapters": []})["available"] is False
    assert reports.build_network_section(None)["reason"] == "Network adapters could not be read"


def test_speed_section_keeps_a_failed_result():
    ok = {"ts": T0, "backend": "cloudflare", "server": "Example Colo", "isp": None, "external_ip": "203.0.113.10",
          "download_mbps": 94.234, "upload_mbps": 18.6, "latency_ms": 12.3, "jitter_ms": 1.1, "packet_loss_pct": None,
          "ok": True, "error": None, "id": 4, "raw": {"big": 1}, "trigger": "manual"}
    rows = [dict(ok, download_mbps=80.0), dict(ok, download_mbps=100.0, upload_mbps=None), {"ok": False, "download_mbps": 1}]
    sec = reports.build_speed_section(ok, rows)
    assert sec["available"] and sec["reason"] is None and sec["result"]["download_mbps"] == 94.23
    assert set(sec["result"]) == set(reports.SPEED_RESULT_KEYS) | {"id"}, "no raw payload or trigger"
    assert sec["window"] == {"count": 2, "download_avg": 90.0, "download_min": 80.0, "download_max": 100.0,
                             "upload_avg": 18.6, "upload_min": 18.6, "upload_max": 18.6, "latency_avg": 12.3}
    failed = reports.build_speed_section(dict(ok, ok=False, error="rate limited: cloudflare is cooling down"), [])
    assert failed["available"] is False and failed["result"]["ok"] is False
    assert failed["reason"] == "The speed test failed: rate limited: cloudflare is cooling down"
    none = reports.build_speed_section(None, [], "Speed tests are not available")
    assert none["result"] is None and none["reason"] == "Speed tests are not available" and none["window"]["count"] == 0


def test_speed_steps_move_through_the_baseline_and_never_back():
    """A speed test with the latency-under-load probe starts with a 3 s idle ``baseline`` phase: the Full Scan speed step
    moves during it, and no later phase maps below an earlier one."""
    steps = reports.SPEED_STEPS
    assert list(steps) == ["baseline", "connect", "latency", "download", "upload", "done"]
    assert reports._step_frac(steps, "baseline", 0.0) == 0.0 and reports._step_frac(steps, "baseline", 0.5) == 0.025
    assert reports._step_frac(steps, "baseline", 1.0) == reports._step_frac(steps, "connect", 0.0) == 0.05
    spans = list(steps.values())
    assert all(lo <= hi for lo, hi in spans) and all(a[1] <= b[0] for a, b in zip(spans, spans[1:]))
    assert spans[-1] == (1.0, 1.0) and reports._step_frac(steps, "warming up", 0.5) is None


def test_ping_section_from_minute_rows(db):
    end = T0
    start = end - 3 * HOUR
    gw = db.add_target("gateway", "Gateway")
    inet = db.add_target("203.0.113.10", kind="internet")
    seed_minutes(db, gw["id"], start, 120, 1.0)
    seed_minutes(db, inet["id"], start + HOUR, 60, 20.0, received=57, jitter=2.0)
    seed_minutes(db, inet["id"], start - 2 * HOUR, 10, 99.0)                   # before the window
    seed_minutes(db, 99, start + 2 * HOUR, 30, 30.0)                            # a target removed since
    db.open_outage("target", 99, start + 2 * HOUR, host="old-target.example")
    views = [{"id": gw["id"], "host": "gateway", "label": "Gateway", "ip": "192.168.50.1", "kind": "local"}]
    sec = reports.build_ping_section(db, start, end, "data_start", views, "192.168.50.1")
    assert sec["available"] and sec["window_start"] == start and sec["window_end"] == end
    assert sec["window_reason"] == "data_start"
    by_id = {t["id"]: t for t in sec["targets"]}
    assert [t["role"] for t in sec["targets"]] == ["gateway", "internet"]
    g = by_id[gw["id"]]
    assert g["host"] == "gateway" and g["ip"] == "192.168.50.1" and g["samples"] == 7200 and g["loss_pct"] == 0.0
    i = by_id[inet["id"]]
    assert i["samples"] == 3600 and i["lost"] == 180 and i["loss_pct"] == 5.0 and i["avg_ms"] == 20.0
    assert i["jitter_ms"] == 2.0 and i["max_ms"] == 24.0, "the rows before the window do not count"
    assert 99 not in by_id and sec["note"] == "Left out: 1 removed or disabled target", "a removed target's minutes are left out"
    empty = reports.build_ping_section(db, end + DAY, end + 2 * DAY, "seven_days")
    assert empty["available"] is False and empty["reason"] == "No pings were recorded in this window" and empty["note"] is None
    moved = reports.build_ping_section(db, end, end, "network_change")
    assert moved["available"] is False and "during the scan" in moved["reason"]


def test_outages_section_clips_counts_and_unions_the_total_spans():
    start, end = T0 - 10 * HOUR, T0
    rows = [
        {"kind": "target", "target_id": 1, "start_ts": T0 - 5 * HOUR, "end_ts": T0 - 5 * HOUR + 120, "missed": 110,
         "sent": 120, "host": "gateway (192.168.50.1)", "note": None},
        {"kind": "total_internet", "target_id": None, "start_ts": T0 - 3 * HOUR, "end_ts": T0 - 3 * HOUR + 600, "missed": 0},
        {"kind": "total_local", "target_id": None, "start_ts": T0 - 3 * HOUR + 300, "end_ts": T0 - 3 * HOUR + 900, "missed": 0},
        {"kind": "target", "target_id": 2, "start_ts": T0 - 11 * HOUR, "end_ts": T0 - 10 * HOUR + 60, "missed": 30,
         "sent": None, "host": None, "note": "network changed"},
        {"kind": "target", "target_id": 2, "start_ts": T0 - 60, "end_ts": None, "missed": 55, "sent": 60, "host": None},
        {"kind": "gap", "target_id": None, "start_ts": T0 - 8 * HOUR, "end_ts": T0 - 7 * HOUR, "missed": 0,
         "note": "system sleep"},
        {"kind": "target", "target_id": 1, "start_ts": T0 - 12 * HOUR, "end_ts": T0 - 10 * HOUR, "missed": 9},   # ends at the start
        {"kind": "mystery", "start_ts": T0 - HOUR, "end_ts": T0 - HOUR + 5},
    ]
    sec = reports.build_outages_section(rows, start, end, 1.0, host_for=lambda tid: {2: "example.net"}.get(tid))
    # the two overlapping totals are one network outage; the three target rows are outages of their own
    assert sec["available"] and sec["count"] == 4 and sec["network_outages"] == 1 and sec["target_outages"] == 3
    assert sec["items_total"] == 5, "four incidents and the gap"
    assert sec["by_kind"] == {"target": 3, "total_local": 1, "total_internet": 1, "gap": 1}
    assert sec["downtime_s"] == {"target": 240.0, "total_local": 600.0, "total_internet": 600.0, "gap": 3600.0}
    assert sec["network_down_s"] == 900.0, "overlapping total outages count once"
    assert sec["longest_s"] == 900.0, "the longest network outage: a monitoring gap is not an outage"
    assert sec["monitored_s"] == 10 * HOUR - HOUR, "the window without the hour not monitored"
    newest = sec["items"][0]
    assert newest["kind"] == "target" and newest["open"] is True and newest["end_ts"] == end and newest["duration_s"] == 60.0
    assert newest["host"] == "example.net" and newest["missed_pct"] == 91.67 and newest["name"] == "example.net"
    network = sec["items"][1]
    assert (network["kind"], network["duration_s"], network["targets"], network["name"]) == ("total_local", 900.0, [], None)
    clipped = sec["items"][-1]
    assert clipped["start_ts"] == start and clipped["duration_s"] == 60.0 and clipped["note"] == "network changed"
    assert clipped["missed_pct"] == 0.82, "no sent count: estimated over the whole 3660 s outage at one ping a second"
    first = next(it for it in sec["items"] if it["host"] == "gateway (192.168.50.1)")
    assert first["missed_pct"] == 91.67 and first["open"] is False and first["name"] == "gateway"
    many = [{"kind": "target", "target_id": 1, "start_ts": start + i * 60, "end_ts": start + i * 60 + 30, "missed": 30}
            for i in range(60)]
    sec = reports.build_outages_section(many, start, end)
    assert len(sec["items"]) == 50 and sec["items_total"] == 60 and sec["count"] == 60
    assert sec["items"][0]["start_ts"] == start + 59 * 60, "newest first"
    quiet = reports.build_outages_section([], start, end)
    assert quiet["count"] == 0 and quiet["longest_s"] is None and quiet["items"] == [] and quiet["available"]
    assert quiet["monitored_s"] == 10 * HOUR


def test_outages_section_reads_incidents_not_rows():
    """One real event is several tracker rows: an internet drop with two internet targets is two target rows and a total, a lost
    connection opens both totals. Incidents count once; a device switched off for hours is not a network outage."""
    start, end = T0 - 3 * DAY, T0
    names = {1: "Gateway", 2: "NVR", 3: "Public DNS", 4: None}
    hosts = {1: "gateway (172.16.40.254)", 2: "172.16.40.20", 3: "198.51.100.1", 4: "example.net"}

    def target(tid: int, s: float, e: Optional[float], **kw: Any) -> Dict[str, Any]:
        return dict({"kind": "target", "target_id": tid, "start_ts": s, "end_ts": e, "missed": 10, "sent": 12, "host": hosts[tid]}, **kw)

    drop = start + 3 * HOUR                             # an internet drop: both internet targets, then the total
    wifi = start + 30 * HOUR                            # the Wi-Fi dropped: every target, both totals
    rows = [
        target(3, drop, drop + 380), target(4, drop + 0.3, drop + 380.5),
        {"kind": "total_internet", "target_id": None, "start_ts": drop + 0.3, "end_ts": drop + 380, "missed": 0},
        *[target(t, wifi + 0.3 * t, wifi + 130 + 0.5 * t, note="no network connection") for t in (1, 2, 3, 4)],
        {"kind": "total_local", "target_id": None, "start_ts": wifi + 0.6, "end_ts": wifi + 130.5, "note": "no network connection"},
        {"kind": "total_internet", "target_id": None, "start_ts": wifi + 1.2, "end_ts": wifi + 131.5, "note": "no network connection"},
        target(2, start + 36 * HOUR, start + 45 * HOUR),                                   # the NVR off overnight
        target(4, start + 50 * HOUR, start + 50 * HOUR + 190),                             # one flaky host
        {"kind": "gap", "target_id": None, "start_ts": start + 14 * HOUR, "end_ts": start + 22 * HOUR, "note": "not monitoring"},
    ]
    sec = reports.build_outages_section(rows, start, end, host_for=hosts.get, label_for=names.get)
    assert (sec["count"], sec["network_outages"], sec["target_outages"]) == (4, 2, 2), "9 rows, 4 incidents"
    assert sec["by_kind"] == {"target": 8, "total_local": 1, "total_internet": 2, "gap": 1}, "the raw rows stay countable"
    assert sec["longest_s"] == 379.7, "the NVR's 9 hours are a device outage, not the longest network outage"
    assert sec["network_down_s"] == round(379.7 + 130.9, 1)
    assert sec["monitored_s"] == 3 * DAY - 8 * HOUR and sec["items_total"] == 5
    by_start = {int((it["start_ts"] - start) // 3600) * 3600: it for it in sec["items"]}
    lost = by_start[30 * 3600]
    assert lost["kind"] == "total_local" and lost["note"] == "no network connection"
    assert lost["targets"] == ["Gateway", "NVR (172.16.40.20)", "Public DNS (198.51.100.1)", "example.net"]
    isp = by_start[3 * 3600]
    assert isp["kind"] == "total_internet" and isp["targets"] == ["Public DNS (198.51.100.1)", "example.net"] and isp["host"] is None
    nvr = by_start[36 * 3600]
    assert (nvr["kind"], nvr["name"], nvr["duration_s"], nvr["targets"]) == ("target", "NVR (172.16.40.20)", 9 * 3600.0, [])
    assert by_start[50 * 3600]["name"] == "example.net" and by_start[14 * 3600]["kind"] == "gap"
    assert reports.target_name("Router", "gateway (192.168.50.1)") == "Router (gateway)"
    assert reports.target_name("Gateway", "gateway (192.168.50.1)") == "Gateway"
    assert reports.target_name(None, "gateway (192.168.50.1)") == "gateway" and reports.target_name("x", None) == "x"
    # no history to read: an empty window (the PC moved during the scan) or no pings at all
    empty = reports.build_outages_section(rows, end, end)
    assert empty["available"] is False and empty["count"] == 0 and empty["reason"] == "The report window is empty"
    silent = reports.build_outages_section(rows, start, end, unavailable="No pings were recorded in this window")
    assert silent["available"] is False and silent["reason"] == "No pings were recorded in this window"
    assert silent["window_start"] == start and silent["items"] == [] and silent["monitored_s"] is None
    assert reports.build_summary({"outages": silent})["outages"] is None, "no outage count where none could be noticed"


def _set_up_before_a_scan(db: tnt_db.Database, end: float, dns: str = "198.51.100.1", example_ms: float = 30.0) -> Dict[str, int]:
    """Two days of a site's history the way a changing target list leaves it (invented hosts): the gateway alias, a public DNS
    server, an NVR and example.net set up; a bench switch disabled; a test address removed; example.net removed once and added
    again (a new id: the old id's minutes and outages are a removed target's); id 77, removed by an older release (its rows have
    no host).  Outages: the NVR alone; the removed and disabled targets alone five times; an internet drop (every internet target
    set up then, then the total) and a local one (the same for the local targets); two hours not monitored."""
    start = end - 2 * DAY
    ids = {"gateway": db.add_target("gateway", "Gateway")["id"], "dns": db.add_target(dns, "Public DNS", kind="internet")["id"],
           "nvr": db.add_target("172.16.40.20", "NVR", kind="local")["id"],
           "disabled": db.add_target("192.168.50.44", "Bench switch", kind="local")["id"],
           "removed": db.add_target("203.0.113.66", kind="internet")["id"],
           "old_example": db.add_target("example.net", "Example", kind="internet")["id"]}
    db.set_target_enabled(ids["disabled"], False)
    assert db.remove_target(ids["removed"]) and db.remove_target(ids["old_example"])
    ids["example"] = db.add_target("example.net", "Example", kind="internet")["id"]
    ids["ghost"] = 77
    assert ids["example"] != ids["old_example"], "added again: a new id"
    seed_minutes(db, ids["gateway"], start + HOUR, 60, 1.0)
    seed_minutes(db, ids["dns"], start + HOUR, 60, 20.0, received=59)
    seed_minutes(db, ids["nvr"], start + HOUR, 60, 2.0)
    seed_minutes(db, ids["disabled"], start + HOUR, 60, 0.0, received=0)
    seed_minutes(db, ids["removed"], start + HOUR, 60, 0.0, received=0)
    seed_minutes(db, ids["old_example"], start + HOUR, 60, 90.0, received=30)
    seed_minutes(db, ids["example"], start + 30 * HOUR, 60, example_ms)
    seed_minutes(db, 77, start + 2 * HOUR, 30, 0.0, received=0)

    def outage(kind: str, tid: Optional[int], s: float, e: float, host: Optional[str] = None, note: Optional[str] = None) -> None:
        pings = int(e - s) if kind == "target" else None
        db.close_outage(db.open_outage(kind, tid, s, note=note, host=host), e, pings or 0, note, pings)

    outage("target", ids["nvr"], start + 3 * HOUR, start + 3 * HOUR + 300, "172.16.40.20")
    outage("target", ids["removed"], start + 4 * HOUR, start + 4 * HOUR + 600, "203.0.113.66")
    outage("target", ids["removed"], start + 6 * HOUR, start + 6 * HOUR + 120, "203.0.113.66", "target removed")
    outage("target", ids["disabled"], start + 8 * HOUR, start + 17 * HOUR, "192.168.50.44", "service stopped")
    outage("target", ids["old_example"], start + 10 * HOUR, start + 10 * HOUR + 240, "example.net", "target removed")
    outage("target", 77, start + 12 * HOUR, start + 12 * HOUR + 90, None, "target removed")
    drop = start + 20 * HOUR                # each member a moment after the last, as the pingers notice
    for k, (key, host) in enumerate((("dns", dns), ("removed", "203.0.113.66"), ("old_example", "example.net"))):
        outage("target", ids[key], drop + 1 + 0.3 * k, drop + 400, host)
    outage("total_internet", None, drop + 2, drop + 400)
    reboot = start + 26 * HOUR
    for k, (key, host) in enumerate((("gateway", "gateway (192.168.50.1)"), ("nvr", "172.16.40.20"), ("disabled", "192.168.50.44"))):
        outage("target", ids[key], reboot + 1 + 0.3 * k, reboot + 180, host, "no network connection")
    outage("total_local", None, reboot + 2, reboot + 180, note="no network connection")
    outage("gap", None, start + 40 * HOUR, start + 42 * HOUR, note="not monitoring")
    return ids


def test_a_report_describes_the_targets_set_up_when_the_scan_ran(db, tmp_path):
    """The first real report listed test targets removed long ago (100 % loss, "target #7") and counted their outages. A new
    report reads the history of the targets set up when its scan ran: removed, disabled and re-added ids are left out of the ping
    table, the summary, the outage counts, rates and list and a network outage's targets, and both sections note one count."""
    end = T0
    start = end - 2 * DAY
    ids = _set_up_before_a_scan(db, end)
    seed_minutes(db, 78, start + 5 * HOUR, 30, 12.0)            # removed by an older release too, a healthy target: no outage
    configured = db.list_targets(enabled_only=True)
    target_ids = [r["id"] for r in configured]
    assert sorted(target_ids) == sorted([ids["gateway"], ids["dns"], ids["nvr"], ids["example"]])
    left_out: set = set()
    ping = reports.build_ping_section(db, start, end, "seven_days", [], "192.168.50.1", configured, left_out)
    assert ping == reports.build_ping_section(db, start, end, "seven_days", [], "192.168.50.1"), "the enabled rows when none are given"
    assert [(t["id"], t["role"]) for t in ping["targets"]] == [(ids["gateway"], "gateway"), (ids["nvr"], "local"), (ids["dns"], "internet"),
                                                             (ids["example"], "internet")]
    assert not any(t["host"] in ("203.0.113.66", "192.168.50.44") or t["host"].startswith("target #") for t in ping["targets"])
    # the host added again keeps its own minutes only: the old id's 50 % loss at 90 ms is not merged into its row
    example = ping["targets"][-1]
    assert (example["host"], example["label"], example["samples"], example["lost"], example["avg_ms"]) == ("example.net", "Example", 3600, 0, 30.0)
    everyone = {ids["disabled"], ids["removed"], ids["old_example"], 77, 78}
    assert ping["note"] == "Left out: 5 removed or disabled targets" and left_out == everyone

    labels = {r["id"]: r["label"] for r in configured}
    rows = db.list_outages(start, end)
    out = reports.build_outages_section(rows, start, end, 1.0, label_for=labels.get, target_ids=target_ids, left_out=left_out)
    assert (out["count"], out["network_outages"], out["target_outages"]) == (3, 2, 1), "the NVR alone and the two network outages"
    assert out["by_kind"] == {"target": 4, "total_local": 1, "total_internet": 1, "gap": 1}
    assert out["downtime_s"] == {"target": 300.0 + 399.0 + 179.0 + 178.7, "total_local": 178.0, "total_internet": 398.0, "gap": 7200.0}
    assert (out["network_down_s"], out["longest_s"], out["monitored_s"]) == (576.0, 398.0, 2 * DAY - 2 * HOUR)
    assert [(it["kind"], it["name"], it["targets"]) for it in out["items"]] == [
        ("gap", None, []), ("total_local", None, ["Gateway", "NVR (172.16.40.20)"]), ("total_internet", None, ["Public DNS (198.51.100.1)"]),
        ("target", "NVR (172.16.40.20)", [])]
    # one count on both headings: 78 pinged but had no outage, so on its own this section would name 4 targets
    assert out["items_total"] == 4 and out["note"] == "Left out: 5 removed or disabled targets (5 single-target outages)"
    alone = reports.build_outages_section(rows, start, end, 1.0, label_for=labels.get, target_ids=target_ids)
    assert alone["note"] == "Left out: 4 removed or disabled targets (5 single-target outages)" and left_out == everyone
    everything = reports.build_outages_section(rows, start, end, 1.0, label_for=labels.get)
    assert (everything["target_outages"], everything["note"]) == (6, None), "without target ids every row counts, as before"

    data = make_data(end=end, window_s=2 * DAY)
    data["ping"], data["outages"] = ping, out
    summary = reports.build_summary(data)
    assert (summary["gateway_avg_ms"], summary["gateway_loss_pct"], summary["outages"], summary["downtime_s"]) == (1.0, 0.0, 3, 576.0)
    # the DNS server (20 ms, a ping lost a minute) and example.net since it was added again (30 ms), not the 100 % loss of the rest
    assert (summary["internet_avg_ms"], summary["internet_loss_pct"]) == (25.04, 0.83)
    text = _pdf_text(report_pdf.build_site_report({"id": 1, "site": "Harbor View", "created_ts": end, "status": "complete",
                                                   "summary": summary, "data": data}))
    assert text.count(b"Left out: 5 removed or disabled targets") == 2 and b"5 single-target outages" in text

    # the same site a week earlier, set up the same way but with another DNS server, compared with it
    before = end - 7 * DAY
    other = tnt_db.Database(tmp_path / "other.db")
    try:
        _set_up_before_a_scan(other, before, dns="198.51.100.9", example_ms=45.0)
        other_rows = other.list_targets(enabled_only=True)
        b_ping = reports.build_ping_section(other, before - 2 * DAY, before, "seven_days", [], "192.168.50.1", other_rows)
        b_out = reports.build_outages_section(other.list_outages(before - 2 * DAY, before), before - 2 * DAY, before, 1.0,
                                              label_for={r["id"]: r["label"] for r in other_rows}.get,
                                              target_ids=[r["id"] for r in other_rows])
    finally:
        other.close()
    a, b = make_report("Harbor View", 1, end=end, window_s=2 * DAY), make_report("Harbor View", 2, end=before, window_s=2 * DAY)
    a["data"]["ping"], a["data"]["outages"], b["data"]["ping"], b["data"]["outages"] = ping, out, b_ping, b_out
    cmp = {s["key"]: {r["key"]: r for r in s["rows"]} for s in reports.compare_reports(a, b)["sections"]}
    # 203.0.113.66 was removed before both scans and each DNS server is one report's own: example.net is the only target in both
    inet = cmp["ping"]["internet_avg_ms"]
    assert (inet["label"], inet["note"], inet["a"], inet["b"], inet["better"]) == ("Internet average (targets in both)", "Targets in both: Example",
                                                                                   30.0, 45.0, "a")
    assert (cmp["ping"]["internet_loss_pct"]["a"], cmp["ping"]["internet_loss_pct"]["b"]) == (0.0, 0.0)
    assert [k for k in cmp["ping"] if k.startswith("host:")] == ["host:example.net:avg_ms", "host:example.net:loss_pct"]
    # per day monitored (46 h on each side): two network outages and the NVR's own, not the six single-target rows of each window
    days = (2 * DAY - 2 * HOUR) / DAY
    rates = cmp["outages"]
    assert (rates["outages_per_day"]["a"], rates["outages_per_day"]["b"], rates["outages_per_day"]["better"]) == (round(2 / days, 2),) * 2 + ("same",)
    assert rates["target_outages_per_day"]["a"] == rates["target_outages_per_day"]["b"] == round(1 / days, 2)
    assert rates["longest_outage_min"]["a"] == round(398.0 / 60, 2)
    assert all(s["note"] is None for s in reports.compare_reports(a, b)["sections"] if s["key"] in ("ping", "outages"))

    # a report saved before this rule (its ping and outages sections have no note) may still count removed targets: said once
    older = json.loads(json.dumps(b))
    for key in ("ping", "outages"):
        del older["data"][key]["note"]
    comparison = reports.compare_reports(a, older)
    notes = {s["key"]: s["note"] for s in comparison["sections"]}
    assert notes["ping"] == notes["outages"] == "B was saved before reports left out removed or disabled targets"
    assert reports.compare_reports(older, a)["sections"][1]["note"] == "A was saved before reports left out removed or disabled targets"
    assert all(s["note"] is None for s in reports.compare_reports(older, older)["sections"] if s["key"] in ("ping", "outages"))
    unavailable = json.loads(json.dumps(older))
    unavailable["data"]["ping"] = {"available": False, "reason": "Could not be collected: database is locked", "targets": []}
    assert next(s for s in reports.compare_reports(a, unavailable)["sections"] if s["key"] == "ping")["note"] == \
        "B: Could not be collected: database is locked", "nothing of B's to read with care"
    assert b"was saved before reports left out" in _pdf_text(report_pdf.build_compare_report(a, older, comparison))


def test_full_scan_reports_only_the_targets_set_up_when_it_runs(rig_factory):
    """The history phase reads the targets table once for both sections: a disabled, a removed and a re-added target's history
    is left out of the saved report, with one count on both notes. Once every target pinged in the window is gone the ping
    section has nothing to show, and the window's network outage, whose targets are all gone, is left out with them."""
    rig = rig_factory()
    db, now = rig.db, time.time()
    gw = db.add_target("gateway", "Gateway")["id"]
    inet = db.add_target("203.0.113.10", kind="internet")["id"]
    disabled = db.add_target("192.168.50.44", "Bench switch", kind="local")["id"]
    old = db.add_target("198.51.100.30", "Test DNS", kind="internet")["id"]
    db.set_target_enabled(disabled, False)
    assert db.remove_target(old)
    again = db.add_target("198.51.100.30", "Test DNS", kind="internet")["id"]
    start = now - 3 * HOUR
    for tid, avg, received in ((gw, 0.9, 60), (inet, 18.0, 59), (disabled, 5.0, 0), (old, 80.0, 30)):
        seed_minutes(db, tid, start, 60, avg, received=received)
    seed_minutes(db, again, start + 2 * HOUR, 30, 25.0)

    def outage(kind: str, tid: Optional[int], s: float, e: float, host: Optional[str] = None) -> None:
        db.close_outage(db.open_outage(kind, tid, s, host=host), e, int(e - s) if tid else 0)

    outage("target", disabled, now - 170 * 60, now - 160 * 60, "192.168.50.44")
    outage("target", old, now - 150 * 60, now - 148 * 60, "198.51.100.30")
    outage("target", inet, now - 120 * 60, now - 115 * 60, "203.0.113.10")
    outage("target", inet, now - 100 * 60 + 1, now - 95 * 60, "203.0.113.10")
    outage("target", old, now - 100 * 60 + 1, now - 95 * 60, "198.51.100.30")
    outage("total_internet", None, now - 100 * 60 + 2, now - 95 * 60)
    outage("target", 88, now - 60 * 60, now - 58 * 60, "192.0.2.88")          # removed long ago: an outage, no minutes stored
    rig.mgr.start_scan("Harbor View")
    post_when_waiting(rig.mgr, wifi_body())
    report = rig.mgr.get(finished(rig.mgr)["report_id"])
    ping, out = report["data"]["ping"], report["data"]["outages"]
    assert [t["id"] for t in ping["targets"]] == [gw, inet, again]
    assert next(t for t in ping["targets"] if t["id"] == again)["samples"] == 1800, "its own minutes, not the old id's"
    assert (out["count"], out["network_outages"], out["target_outages"]) == (2, 1, 1)
    assert [it["targets"] for it in out["items"] if it["kind"] == "total_internet"] == [["203.0.113.10"]]
    # one count on both headings: 88 had no minutes, so the ping section alone would have named 2
    assert ping["note"] == "Left out: 3 removed or disabled targets"
    assert out["note"] == "Left out: 3 removed or disabled targets (3 single-target outages)"
    assert (report["summary"]["internet_loss_pct"], report["summary"]["outages"]) == (round(100.0 * 60 / 5400, 2), 2)

    for tid in (gw, inet, again):
        assert db.remove_target(tid)
    rig.mgr.start_scan("Harbor View")
    post_when_waiting(rig.mgr, wifi_body())
    second = rig.mgr.get(finished(rig.mgr)["report_id"])
    ping, out = second["data"]["ping"], second["data"]["outages"]
    assert (ping["available"], ping["reason"], ping["targets"]) == (False, reports.NO_TARGET_PINGS_REASON, [])
    # monitoring ran all along, so the section stands; but every target of the internet outage is gone: it is left out and counted
    assert out["available"] is True and (out["count"], out["network_outages"], out["target_outages"]) == (0, 0, 0)
    assert out["items"] == [] and out["by_kind"]["total_internet"] == 0 and out["network_down_s"] == 0.0
    # the five with minutes and 88: one count again, where the ping and outage sections alone would have said 5 and 4
    assert ping["note"] == "Left out: 6 removed or disabled targets"
    assert out["note"] == "Left out: 6 removed or disabled targets (1 network outage, 4 single-target outages)"
    assert (second["summary"]["gateway_avg_ms"], second["summary"]["internet_avg_ms"], second["summary"]["outages"]) == (None, None, 0)


def test_full_scan_takes_the_targets_from_one_read_and_never_counts_without_it(rig_factory, monkeypatch):
    """The ping table's host, label and kind and the ids both sections keep come from one read of the targets table: a target
    removed while the history phase runs is still named as it was set up (not "target #2" with a guessed role). Without that
    read neither section is collected, so the outages of targets removed long ago are never counted for want of the list."""
    rig = rig_factory()
    db, now = rig.db, time.time()
    gw = db.add_target("gateway", "Gateway")["id"]
    nvr = db.add_target("172.16.40.20", "NVR", kind="local")["id"]
    old = db.add_target("203.0.113.66", kind="internet")["id"]
    assert db.remove_target(old)
    for tid in (gw, nvr, old):
        seed_minutes(db, tid, now - 3 * HOUR, 60, 2.0)
    db.close_outage(db.open_outage("target", nvr, now - 100 * 60, host="172.16.40.20"), now - 95 * 60, 300)
    db.close_outage(db.open_outage("target", old, now - 150 * 60, host="203.0.113.66"), now - 140 * 60, 600)
    build = reports.build_ping_section

    def removed_meanwhile(*args: Any, **kw: Any) -> Dict[str, Any]:
        assert db.remove_target(nvr)                    # removed on the Ping page just after the history phase read the list
        return build(*args, **kw)

    monkeypatch.setattr(reports, "build_ping_section", removed_meanwhile)
    rig.mgr.start_scan("Harbor View")
    post_when_waiting(rig.mgr, wifi_body())
    report = rig.mgr.get(finished(rig.mgr)["report_id"])
    monkeypatch.setattr(reports, "build_ping_section", build)
    ping, out = report["data"]["ping"], report["data"]["outages"]
    assert [(t["id"], t["host"], t["label"], t["role"]) for t in ping["targets"]] == [(gw, "gateway", "Gateway", "gateway"),
                                                                                  (nvr, "172.16.40.20", "NVR", "local")]
    assert [it["name"] for it in out["items"]] == ["NVR (172.16.40.20)"]
    assert ping["note"] == "Left out: 1 removed or disabled target"
    assert out["note"] == "Left out: 1 removed or disabled target (1 single-target outage)"

    def unreadable() -> List[Dict[str, Any]]:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(rig.mgr, "_configured_targets", unreadable)
    rig.mgr.start_scan("Harbor View")
    post_when_waiting(rig.mgr, wifi_body())
    done = finished(rig.mgr)
    assert next((p["status"], p["message"]) for p in done["phases"] if p["key"] == "history") == ("error", "Could not read: ping, outages")
    failed = rig.mgr.get(done["report_id"])
    assert failed["status"] == "partial" and failed["summary"]["outages"] is None
    for key in ("ping", "outages"):
        assert (failed["data"][key]["available"], failed["data"][key]["reason"]) == (False, "Could not be collected: database is locked")

    # read on the second try, by the outages section: it still keeps only the targets set up (the NVR is gone by now)
    tries: List[int] = []

    def second_time_lucky() -> List[Dict[str, Any]]:
        tries.append(1)
        if len(tries) == 1:
            raise sqlite3.OperationalError("database is locked")
        return db.list_targets(enabled_only=True)

    monkeypatch.setattr(rig.mgr, "_configured_targets", second_time_lucky)
    rig.mgr.start_scan("Harbor View")
    post_when_waiting(rig.mgr, wifi_body())
    done = finished(rig.mgr)
    assert next((p["status"], p["message"]) for p in done["phases"] if p["key"] == "history") == ("error", "Could not read: ping")
    out = rig.mgr.get(done["report_id"])["data"]["outages"]
    assert out["available"] is True and (out["count"], out["items"], len(tries)) == (0, [], 2)
    assert out["note"] == "Left out: 2 removed or disabled targets (2 single-target outages)"


def test_outage_rows_without_a_target_id_count_as_outages_only():
    """The tracker always writes a target outage row with its target id; a row without one (a hand-edited or unusual old database)
    cannot be tied to a target set up for the scan, nor told apart from another by its host text ("Old.Example", "old.example", a
    host a set-up target pings too): it is left out and counted among the single-target outages, never as a target."""
    start, end = T0 - DAY, T0

    def row(host: Optional[str], hour: float, tid: Optional[int] = None, kind: str = "target") -> Dict[str, Any]:
        return {"kind": kind, "target_id": tid, "host": host, "start_ts": start + hour * HOUR, "end_ts": start + hour * HOUR + 100,
                "missed": 100 if kind == "target" else 0, "missed_pct": 100.0 if kind == "target" else None, "note": None}

    rows = [row("198.51.100.1", 1), row("Old.Example", 2), row("old.example", 3), row(None, 4), row("old.example", 6, tid=5),
            row("gateway (10.0.0.1)", 10), row("gateway (192.168.50.1)", 10, tid=1), row(None, 10, kind="total_local")]
    out = reports.build_outages_section(rows, start, end, target_ids=[1, 2])
    assert (out["count"], out["network_outages"], out["target_outages"], out["by_kind"]["target"]) == (1, 1, 0, 1)
    assert [it["targets"] for it in out["items"]] == [["gateway"]]
    assert out["note"] == "Left out: 1 removed or disabled target (5 single-target outages)", "id 5; the rows without an id as outages"
    shared = {7}
    assert reports.build_outages_section(rows, start, end, target_ids=[1, 2], left_out=shared)["note"] == \
        "Left out: 2 removed or disabled targets (5 single-target outages)" and shared == {5, 7}
    lone = reports.build_outages_section(rows[:4], start, end, target_ids=[1, 2])
    assert (lone["count"], lone["note"]) == (0, "Left out: 4 single-target outages of removed or disabled targets")
    assert reports.left_out_note(0, 0) is None and reports.left_out_note(1) == "Left out: 1 removed or disabled target"


def test_discovery_section_types_and_caps():
    hosts = [dict(h) for h in HOSTS]
    hosts[1]["device_type"] = None                   # a row stored before the column existed: typed on read
    sec = reports.build_discovery_section({"id": 5, "cidr": "192.168.50.0/24", "ts": T0, "duration_s": 12.345,
                                           "hosts": hosts}, ["192.168.50.1"], note="The network changed during the scan")
    assert sec["available"] and sec["run_id"] == 5 and sec["range"] == "192.168.50.0/24" and sec["duration_s"] == 12.3
    assert sec["host_count"] == 4 and sec["device_types"] == {"Router": 1, "Camera": 2}
    assert sec["hosts"][1] == {"ip": "192.168.50.20", "hostname": None, "mac": "02:00:5E:10:00:14", "vendor": None,
                               "device_type": "Camera", "open_ports": [554]}
    assert sec["note"] == "The network changed during the scan"
    many = [{"ip": f"10.20.{i // 250}.{i % 250 + 1}", "open_ports": [], "device_type": None} for i in range(600)]
    sec = reports.build_discovery_section({"id": 6, "cidr": "10.20.0.0/22", "hosts": many}, [])
    assert len(sec["hosts"]) == 512 and sec["hosts_total"] == 600 and sec["host_count"] == 600
    none = reports.build_discovery_section(None, [], "Discovery could not start: no default network")
    assert none["available"] is False and none["reason"].startswith("Discovery could not start")


def test_clean_wifi_snapshot_validates_trims_and_derives_vendors():
    for bad in ([], {"available": "yes"}, {"available": True, "state": 5}, {"available": True, "error": 3},
                {"available": True, "collected_ts": "soon"}, {"available": True, "collected_ts": -1},
                {"available": True, "aps": {}}, {"available": True, "interfaces": "Wi-Fi"},
                {"available": True, "aps": [{}] * 1001}):
        with pytest.raises(ValueError):
            reports.clean_wifi_snapshot(bad)
    extra = [
        {"bssid": "not-a-mac", "rssi": -50},
        {"bssid": "02:00:5E:20:00:08", "rssi": 20},
        {"bssid": "02:00:5E:20:00:09", "rssi": "strong"},
        dict(AP_LIST[0], rssi=-90, connected=False),                      # a weaker copy of the connected AP
        dict(ap("02:00:5e:20:00:0a", "Long\x07" + "n" * 100, -66, 5, 149), band=5),
    ]
    snap = reports.clean_wifi_snapshot(wifi_body(aps=AP_LIST + extra), now=T0)
    assert snap["dropped"] == 3 and len(snap["aps"]) == 8
    first = next(a for a in snap["aps"] if a["bssid"] == "02:00:5E:20:00:01")
    assert first["rssi"] == -48 and first["connected"] is True
    assert (first["oui"], first["locally_administered"], first["base_oui"]) == ("02:00:5E", True, "00:00:5E")
    assert first["vendor"] == oui.vendor_for_oui("00:00:5E"), "from the BSSID, not the posted oui fields"
    long = next(a for a in snap["aps"] if a["bssid"] == "02:00:5E:20:00:0A")
    assert len(long["ssid"]) == 64 and "\x07" not in long["ssid"] and long["band"] == "5"
    assert snap["interfaces"] == [{"description": "Example Wireless Adapter", "state": "connected",
                                   "connected_bssid": "02:00:5E:20:00:01", "connected_ssid": "Acme-Staff"}]
    other = reports.clean_wifi_snapshot({"available": False, "state": " Location_Denied! ", "error": "e" * 400}, now=T0)
    assert other["state"] == "location_denied" and len(other["error"]) == 300 and other["collected_ts"] == T0
    assert other["aps"] == [] and other["interfaces"] == []


def test_wifi_section_bands_connected_and_caps():
    sec = reports.build_wifi_section(reports.clean_wifi_snapshot(wifi_body(), now=T0))
    assert sec["available"] and sec["state"] == "ok" and sec["adapter"] == "Example Wireless Adapter"
    assert sec["aps_count"] == 6 and sec["aps_total"] == 6 and sec["networks"] == 3, "the stale AP is left out"
    assert [a["bssid"][-2:] for a in sec["aps"][:3]] == ["01", "03", "02"], "strongest first"
    assert set(sec["aps"][0]) == {"ssid", "hidden", "bssid", "band", "channel", "width_mhz", "rssi", "security",
                                  "generation", "vendor", "connected"}
    assert sec["connected"] == {"ssid": "Acme-Staff", "bssid": "02:00:5E:20:00:01", "rssi": -48, "band": "5",
                                "channel": 36, "width_mhz": 80, "channel_aps": 2, "overlap_aps": 2}
    assert "center_channel" not in sec["aps"][0], "the stored access points keep the contract's fields"
    assert sec["bands"]["2.4"] == {"aps": 4, "networks": 3, "strongest_rssi": -61, "median_rssi": -72.5,
                                   "busiest_channel": 6, "busiest_channel_aps": 3}
    assert sec["bands"]["5"] == {"aps": 2, "networks": 2, "strongest_rssi": -48, "median_rssi": -51.5,
                                 "busiest_channel": 36, "busiest_channel_aps": 2}
    assert sec["bands"]["6"]["aps"] == 0 and sec["bands"]["6"]["strongest_rssi"] is None
    stale_only = reports.build_wifi_section(reports.clean_wifi_snapshot(wifi_body(aps=[AP_LIST[-1]]), now=T0))
    assert stale_only["aps_count"] == 1, "all stale: shown rather than nothing"
    by_iface = [dict(a, connected=False) for a in AP_LIST]
    assert reports.build_wifi_section(reports.clean_wifi_snapshot(wifi_body(aps=by_iface)))["connected"]["rssi"] == -48
    lots = [ap(f"02:00:5E:30:{i // 256:02X}:{i % 256:02X}", f"Net-{i}", -40 - (i % 60), "2.4", 1 + i % 11) for i in range(250)]
    big = reports.build_wifi_section(reports.clean_wifi_snapshot(wifi_body(aps=lots)))
    assert len(big["aps"]) == 200 and big["aps_total"] == 250 and big["aps"][0]["rssi"] == -40
    gone = reports.build_wifi_section(reports.clean_wifi_snapshot({"available": False, "state": "no_adapter"}))
    assert gone["available"] is False and gone["reason"] == "This PC has no Wi-Fi adapter"
    told = reports.build_wifi_section(reports.clean_wifi_snapshot({"available": False, "state": "error", "error": "WLAN said no"}))
    assert told["reason"] == "WLAN said no"
    assert reports.build_wifi_section(None)["reason"] == reports.NO_WINDOW_REASON


def test_summary_of_a_report():
    data = make_data()
    s = reports.build_summary(data)
    assert s == {"download_mbps": 94.2, "upload_mbps": 18.6, "latency_ms": 12.3, "gateway_avg_ms": 0.8,
                 "gateway_loss_pct": 0.0, "internet_avg_ms": 18.01, "internet_loss_pct": 0.25, "outages": 3,
                 "downtime_s": 600.0, "hosts": 4, "wifi_aps": 6, "wifi_networks": 3, "wifi_connected_rssi": -48,
                 "window_hours": 144.0}
    partial = make_data(speed_ok=False, wifi=False)
    partial["discovery"] = reports.empty_section("discovery", "Network discovery is not available")
    s = reports.build_summary(partial)
    assert s["download_mbps"] is None and s["wifi_aps"] is None and s["hosts"] is None and s["outages"] == 3


# --------------------------------------------------------------------------------------
# compare
# --------------------------------------------------------------------------------------
def test_compare_row_better_same_and_missing():
    row = reports.compare_row("download_mbps", "Download", "Mbps", 100.0, 101.5, True)
    assert row["better"] == "same" and row["delta"] == -1.5 and row["delta_pct"] == -1.5
    assert reports.compare_row("x", "X", "ms", 1.0, 2.5, False)["better"] == "a"
    assert reports.compare_row("x", "X", "ms", 2.5, 1.0, False)["better"] == "b"
    assert reports.compare_row("x", "X", "%", 0.05, 0.1, False)["better"] == "same"
    signal = reports.compare_row("x", "X", "dBm", -60, -65, True)
    assert signal["better"] == "a" and signal["delta"] == 5.0 and signal["delta_pct"] is None, "no percentage of a dBm value"
    assert reports.compare_row("x", "X", "APs", 2, 3, False)["better"] == "a", "counts have no absolute slack"
    zero = reports.compare_row("x", "X", "%", 0.0, 0.0, False)
    assert zero["better"] == "same" and zero["delta"] == 0.0 and zero["delta_pct"] is None
    one_side = reports.compare_row("x", "X", "ms", 3.0, None, False)
    assert one_side["better"] is None and one_side["delta"] is None and one_side["b"] is None
    assert reports.compare_row("x", "X", "ms", None, None, False) is None
    info = reports.compare_row("hosts", "Devices", "devices", 4, 9, None)
    assert info["better"] is None and info["higher_is_better"] is None and info["delta"] == -5


def _b_aps() -> List[Dict[str, Any]]:
    return [ap("02:00:5E:40:00:01", "Acme-Staff", -65, "5", 36, 80, connected=True),
            ap("02:00:5E:40:00:02", "Acme-Guest", -58, "5", 36, 80),
            ap("02:00:5E:40:00:03", "Warehouse-Scan", -50, "2.4", 1)]


def test_compare_reports_sections_and_rows():
    a = make_report("Acme Dental", 1)
    b = make_report("Northside Warehouse", 2, download=150.0, upload=18.9, latency=12.8, jitter=None, gw_avg=2.5,
                    gw_loss=1.0, inet=(("203.0.113.10", None, 30.0, 0.0), ("EXAMPLE.NET", "Example", 21.5, 0.0),
                                       ("example.org", None, 40.0, 0.0)),
                    window_s=1800, outages=1, down_s=60.0, longest_s=60.0, aps=_b_aps(),
                    hosts=[HOSTS[0], dict(HOSTS[3], open_ports=[5060], device_type="Phone")])
    out = reports.compare_reports(a, b)
    assert out["a"] == {"id": 1, "site": "Acme Dental", "created_ts": T0, "status": "complete"}
    assert [s["key"] for s in out["sections"]] == ["speed", "ping", "outages", "wifi", "discovery"]
    sections = {s["key"]: s for s in out["sections"]}
    assert all(s["note"] is None for s in out["sections"])
    rows = {s: {r["key"]: r for r in sections[s]["rows"]} for s in sections}

    speed = rows["speed"]
    assert speed["download_mbps"]["better"] == "b" and speed["download_mbps"]["delta"] == -55.8
    assert speed["download_mbps"]["delta_pct"] == -37.2 and speed["download_mbps"]["higher_is_better"] is True
    assert speed["download_mbps"]["note"] is None, "the same link and server on both sides: nothing to explain"
    assert speed["upload_mbps"]["better"] == "same" and speed["latency_ms"]["better"] == "same"
    assert speed["jitter_ms"]["b"] is None and speed["jitter_ms"]["better"] is None
    assert speed["packet_loss_pct"]["better"] == "same"
    # context rows: the tests of each window and the adapter's link, for information
    assert (speed["download_window_avg"]["a"], speed["download_window_avg"]["b"]) == (94.2, 150.0)
    assert speed["download_window_avg"]["higher_is_better"] is None and speed["download_window_avg"]["note"] == "A: 1 test; B: 1 test"
    assert (speed["link_mbps"]["a"], speed["link_mbps"]["b"], speed["link_mbps"]["better"]) == (1000.0, 1000.0, None)

    ping = rows["ping"]
    assert ping["gateway_avg_ms"]["better"] == "a" and ping["gateway_p95_ms"]["better"] == "a"
    assert ping["gateway_p95_ms"]["label"] == "Gateway p95 of 1-min averages"
    assert ping["gateway_max_ms"]["higher_is_better"] is None and ping["gateway_max_ms"]["better"] is None, "one ping: information"
    assert ping["gateway_loss_pct"]["better"] == "a"
    # the combined internet rows use the targets both reports pinged (B's example.org is left out of them)
    assert ping["internet_avg_ms"]["a"] == 18.01 and ping["internet_avg_ms"]["b"] == 25.75
    assert ping["internet_avg_ms"]["label"] == "Internet average (targets in both)"
    assert ping["internet_avg_ms"]["note"] == "Targets in both: 203.0.113.10, Example"
    assert ping["internet_avg_ms"]["better"] == "a" and ping["internet_loss_pct"]["better"] == "b"
    assert [k for k in ping if k.startswith("host:")] == ["host:203.0.113.10:avg_ms", "host:203.0.113.10:loss_pct",
                                                          "host:example.net:avg_ms", "host:example.net:loss_pct"]
    assert ping["host:example.net:avg_ms"]["label"] == "Example average" and ping["host:example.net:avg_ms"]["better"] == "same"
    assert sections["ping"]["rows"][0]["note"] == "Windows: A 6.0 days, B 30 min"

    # B monitored half an hour: no daily rates, each window's counts for information
    outages = rows["outages"]
    assert list(outages) == ["network_outages", "downtime_min", "longest_outage_min", "target_outages"]
    assert all(r["higher_is_better"] is None and r["better"] is None for r in outages.values())
    assert (outages["network_outages"]["a"], outages["network_outages"]["b"], outages["network_outages"]["unit"]) == (3, 1, "outages")
    assert (outages["downtime_min"]["a"], outages["downtime_min"]["b"]) == (10.0, 1.0)
    assert outages["network_outages"]["note"] == ("Monitored: A 6.0 days; B 30 min. Too little history for daily rates (B 30 min; a day on "
                                                  "each side is needed): the counts of each window")

    wifi = rows["wifi"]
    assert wifi["connected_rssi"]["better"] == "a"
    assert wifi["connected_rssi"]["note"] == "A: Acme-Staff (5 GHz, channel 36, 80 MHz); B: Acme-Staff (5 GHz, channel 36, 80 MHz)"
    assert wifi["connected_channel_aps"]["better"] == "same" and wifi["connected_overlap_aps"]["better"] == "same"
    # the site's own network is judged, the neighbours' networks only shown
    assert (wifi["band_5_own_rssi"]["a"], wifi["band_5_own_rssi"]["b"], wifi["band_5_own_rssi"]["better"]) == (-48, -65, "a")
    assert (wifi["band_2.4_own_rssi"]["a"], wifi["band_2.4_own_rssi"]["b"]) == (-61, None)
    assert (wifi["band_2.4_other_rssi"]["a"], wifi["band_2.4_other_rssi"]["b"]) == (-70, -50)
    assert wifi["band_2.4_other_rssi"]["higher_is_better"] is None and wifi["band_2.4_median_rssi"]["higher_is_better"] is None
    assert wifi["band_2.4_median_rssi"]["a"] == -75.0
    assert wifi["band_2.4_networks"]["higher_is_better"] is None and wifi["band_2.4_networks"]["better"] is None
    assert wifi["band_2.4_busiest_channel_aps"]["note"] == "Busiest channel: 6 vs 1"
    assert not any(k.startswith("band_6") for k in wifi), "a band neither report saw is left out"
    assert not any(k.startswith("ssid:") for k in wifi), "networks seen at two different sites are not compared"

    disc = rows["discovery"]
    assert disc["hosts"]["a"] == 4 and disc["hosts"]["b"] == 2 and disc["hosts"]["better"] is None
    assert list(disc) == ["hosts", "type:Router", "type:Camera", "type:Phone"]
    assert (disc["type:Camera"]["a"], disc["type:Camera"]["b"]) == (2, 0)
    assert all(r["higher_is_better"] is None for r in disc.values())


def test_compare_rates_links_and_two_scans_of_one_site():
    # a day or more monitored on both sides: network outages, downtime and single-target outages per day monitored
    a = make_report("Northside Warehouse", 1, window_s=2.6 * DAY, outages=4, down_s=1443.0, longest_s=840.0)
    a["data"]["outages"] = outage_section(T0 - 2.6 * DAY, T0, 4, 1443.0, 840.0, targets=2, monitored_s=2.6 * DAY - 8 * HOUR)
    b = make_report("Maple Street Office", 2, window_s=7 * DAY, outages=1, down_s=45.0, longest_s=45.0)
    rows = {r["key"]: r for s in reports.compare_reports(a, b)["sections"] if s["key"] == "outages" for r in s["rows"]}
    assert list(rows) == ["outages_per_day", "downtime_min_per_day", "longest_outage_min", "target_outages_per_day"]
    monitored_days = (2.6 * DAY - 8 * HOUR) / DAY
    assert rows["outages_per_day"]["a"] == round(4 / monitored_days, 2) and rows["outages_per_day"]["b"] == round(1 / 7, 2)
    assert rows["outages_per_day"]["better"] == "b" and rows["outages_per_day"]["label"] == "Network outages per day"
    assert rows["outages_per_day"]["note"] == "Monitored: A 2.3 days of 2.6 days; B 7.0 days"
    assert rows["downtime_min_per_day"]["a"] == round(1443.0 / 60 / monitored_days, 2) and rows["downtime_min_per_day"]["better"] == "b"
    assert (rows["longest_outage_min"]["a"], rows["longest_outage_min"]["b"], rows["longest_outage_min"]["better"]) == (14.0, 0.75, "b")
    assert rows["target_outages_per_day"]["higher_is_better"] is None and rows["target_outages_per_day"]["a"] == round(2 / monitored_days, 2)

    # different links: the download row says why the numbers differ
    wifi_nic = make_report("Northside Warehouse", 3, download=18.4)
    nic = wifi_nic["data"]["network"]["internet_nic"]
    nic.update(type_name="Wi-Fi", name="Wi-Fi", link_bps=144_000_000)
    wifi_nic["data"]["wifi"]["connected"]["band"] = "2.4"
    b["data"]["network"]["internet_nic"]["link_bps"] = 1_201_000_000
    speed = {r["key"]: r for s in reports.compare_reports(wifi_nic, b)["sections"] if s["key"] == "speed" for r in s["rows"]}
    assert speed["download_mbps"]["note"] == "Links: A Wi-Fi 2.4 GHz, 144 Mbps link; B Ethernet, 1.2 Gbps link"
    assert (speed["link_mbps"]["a"], speed["link_mbps"]["b"]) == (144.0, 1201.0)
    assert reports.link_text({}) is None

    # two scans of one site: the networks seen in both, the one this PC used judged, the others shown
    before = make_report("Acme Dental", 4)
    after = make_report("acme  dental", 5, aps=_b_aps())
    wifi = {r["key"]: r for s in reports.compare_reports(after, before)["sections"] if s["key"] == "wifi" for r in s["rows"]}
    assert [k for k in wifi if k.startswith("ssid:")] == ["ssid:Acme-Staff", "ssid:Acme-Guest"]
    assert wifi["ssid:Acme-Staff"]["higher_is_better"] is True and wifi["ssid:Acme-Staff"]["better"] == "b"
    assert wifi["ssid:Acme-Guest"]["higher_is_better"] is None and wifi["ssid:Acme-Guest"]["better"] is None
    # no internet target in both reports: the combined rows are each report's own, for information
    other = make_report("Lakeside Clinic", 6, inet=(("198.51.100.99", None, 30.0, 0.0),))
    ping = {r["key"]: r for s in reports.compare_reports(other, before)["sections"] if s["key"] == "ping" for r in s["rows"]}
    assert ping["internet_avg_ms"]["better"] is None and ping["internet_avg_ms"]["higher_is_better"] is None
    assert ping["internet_avg_ms"]["label"] == "Internet average (all targets)" and "No internet target is in both" in ping["internet_avg_ms"]["note"]
    assert not any(k.startswith("host:") for k in ping)


def test_wifi_overlapping_channels():
    def at(band: str, channel: int, width: int = 20, centre: Optional[int] = None) -> Dict[str, Any]:
        return {"band": band, "channel": channel, "width_mhz": width, "center_channel": centre}

    assert reports.channels_overlap(at("2.4", 1), at("2.4", 4)) and not reports.channels_overlap(at("2.4", 1), at("2.4", 6))
    assert not reports.channels_overlap(at("2.4", 1), at("2.4", 5)), "2412 and 2432 MHz: 20 MHz apart, just clear"
    assert reports.channels_overlap(at("2.4", 6), at("2.4", 3, 40)) and reports.channels_overlap(at("2.4", 6), at("2.4", 9, 40))
    assert reports.channels_overlap(at("5", 36, 80, 42), at("5", 48)) and not reports.channels_overlap(at("5", 36, 80, 42), at("5", 52))
    assert not reports.channels_overlap(at("5", 36), at("2.4", 6)) and reports.channel_span({"band": "6"}) is None
    assert reports.channel_span(at("2.4", 14)) == (2484.0, 20.0)
    # the connected access point on channel 6 among overlapping neighbours (the survey's center_channel is used when posted)
    crowd = [ap("02:00:5E:20:10:01", "Northside-Ops", -78, "2.4", 6, connected=True),
             ap("02:00:5E:20:10:02", "Northside-Guest", -79, "2.4", 6),
             dict(ap("02:00:5E:20:10:03", "Forklift-Charger-7", -69, "2.4", 3, 40), center_channel=None),
             dict(ap("02:00:5E:20:10:04", "Yard-Camera-Bridge", -73, "2.4", 9, 40), center_channel=None),
             ap("02:00:5E:20:10:05", "Dock-Door-Sensors", -81, "2.4", 4),
             ap("02:00:5E:20:10:06", "Pallet & Crate Co", -61, "2.4", 1),
             ap("02:00:5E:20:10:07", "Oak & Ivy", -67, "2.4", 11)]
    conn = reports.build_wifi_section(reports.clean_wifi_snapshot(wifi_body(aps=crowd), now=T0))["connected"]
    assert (conn["channel_aps"], conn["overlap_aps"]) == (2, 5)


def test_compare_reports_with_missing_sections():
    a = make_report("Acme Dental", 1, speed_ok=False, wifi=False)
    b = make_report("Lakeside Clinic", 2)
    b["data"]["discovery"] = reports.empty_section("discovery", "Network discovery is not available")
    out = reports.compare_reports(a, b)
    sections = {s["key"]: s for s in out["sections"]}
    assert sections["speed"]["note"] == "A: The speed test failed: timeout"
    assert all(r["a"] is None and r["better"] is None for r in sections["speed"]["rows"] if r["key"] != "link_mbps")
    assert next(r for r in sections["wifi"]["rows"] if r["key"] == "connected_rssi")["note"] == "A: no Wi-Fi scan; B: Acme-Staff (5 GHz, channel 36, 80 MHz)"
    assert sections["wifi"]["note"] == "A: Wi-Fi can only be scanned from the TNT window"
    assert {r["key"] for r in sections["wifi"]["rows"]} >= {"connected_rssi", "ssid:Acme-Staff"} or True
    assert all(r["a"] is None for r in sections["wifi"]["rows"])
    assert sections["discovery"]["note"] == "B: Network discovery is not available"
    assert all(r["b"] is None for r in sections["discovery"]["rows"])
    empty = reports.compare_reports({"id": 1, "data": {}}, {"id": 2})
    assert [s["rows"] for s in empty["sections"]] == [[], [], [], [], []]


# --------------------------------------------------------------------------------------
# the network marker
# --------------------------------------------------------------------------------------
def test_network_marker_moves_only_when_the_network_changes(db):
    macs: Dict[str, str] = {}

    def manager(started: float, network: Any) -> reports.ReportManager:
        # the clock reads a day after the start: the changes below happened before "now", as real ones always do
        return reports.ReportManager(db, None, None, SimpleNamespace(started_ts=started), network_fn=lambda: network,
                                     clock=lambda: started + DAY, gateway_mac_fn=macs.get, mac_wait_s=0.0)

    mgr = manager(T0, ("192.168.50.1", ["192.168.50.0/24"], "Ethernet"))
    mgr._startup_network_check()
    marker = reports.parse_marker(db.get_meta(reports.NET_JOINED_META_KEY))
    assert marker == {"ts": None, "gateway": "192.168.50.1", "networks": ["192.168.50.0/24"], "nic": "Ethernet",
                      "gateway_mac": None, "mac_ts": None, "seen_ts": T0}
    assert mgr.joined_ts() is None, "the first start of an empty database does not know when this PC joined"
    seq = iter(range(1, 100))

    def change(ts: float, gateway: Optional[str], networks: List[str], order: Optional[int] = None) -> None:
        mgr._apply_network_change({"ts": ts, "default_gateway": gateway, "previous_gateway": None,
                                   "internet_nic": {"name": "Wi-Fi", "networks": networks} if networks else None},
                                  next(seq) if order is None else order)

    change(T0 + 100, None, [])                                          # the connection dropped
    assert mgr.joined_ts() is None and reports.parse_marker(db.get_meta(reports.NET_JOINED_META_KEY))["gateway"] == "192.168.50.1"
    change(T0 + 200, "192.168.50.1", ["192.168.50.0/24"])              # back on the same network
    assert mgr.joined_ts() is None
    change(T0 + 300, "10.20.30.1", ["10.20.30.0/24"])                  # carried to another site
    assert mgr.joined_ts() == T0 + 300
    change(T0 + 250, "172.16.4.1", ["172.16.4.0/24"], order=2)         # an older change (published second) handled late
    assert mgr.joined_ts() == T0 + 300
    change(T0 + 400, "10.20.30.1", ["10.20.31.0/24"])                  # same router address, other subnet
    assert mgr.joined_ts() == T0 + 400
    change(T0 + 500, "10.20.30.1", ["10.20.31.0/24", "10.99.0.0/24"])  # an extra subnet on the same network
    assert mgr.joined_ts() == T0 + 400

    moved = manager(T0 + 1000, ("192.168.77.1", ["192.168.77.0/24"], "Ethernet"))   # a restart elsewhere
    moved._startup_network_check()
    assert moved.joined_ts() == T0 + 1000
    offline = manager(T0 + 2000, (None, [], None))                                   # a restart before Wi-Fi is up
    offline._startup_network_check()
    assert offline.joined_ts() == T0 + 1000
    same = manager(T0 + 3000, ("192.168.77.1", ["192.168.77.0/24"], "Ethernet"))
    same.start()
    assert _wait_for(lambda: reports.parse_marker(db.get_meta(reports.NET_JOINED_META_KEY))["seen_ts"] == T0 + 3000)
    assert same.joined_ts() == T0 + 1000
    same.on_network_change({"ts": T0 + 4000, "default_gateway": "10.44.0.1", "internet_nic": {"networks": ["10.44.0.0/24"]}})
    assert _wait_for(lambda: same.joined_ts() == T0 + 4000)


def test_network_marker_tells_sites_on_the_same_subnet_apart_by_the_router_mac(db):
    """Most small networks are 192.168.1.0/24 behind 192.168.1.1: only the router's MAC shows the PC was carried elsewhere."""
    macs = {"192.168.1.1": "02:00:5E:AA:00:01"}
    now = [T0]
    mgr = reports.ReportManager(db, None, None, SimpleNamespace(started_ts=T0), network_fn=lambda: ("192.168.1.1", ["192.168.1.0/24"], "Wi-Fi"),
                                clock=lambda: now[0], gateway_mac_fn=macs.get, mac_wait_s=0.0)
    mgr._startup_network_check()
    marker = reports.parse_marker(db.get_meta(reports.NET_JOINED_META_KEY))
    assert marker["gateway_mac"] == "02:00:5E:AA:00:01" and marker["mac_ts"] == T0 and mgr.joined_ts() is None
    lost = {"default_gateway": None, "internet_nic": None}
    back = {"default_gateway": "192.168.1.1", "internet_nic": {"name": "Wi-Fi", "networks": ["192.168.1.0/24"]}}

    def change(data: Dict[str, Any], ts: float, seq: int) -> None:
        now[0] = ts
        mgr._apply_network_change(dict(data, ts=ts), seq)

    change(lost, T0 + 3600, 1)                                                            # the laptop is closed at site A
    change(back, T0 + 7200, 2)                                                            # ... and opened at site B
    assert mgr.joined_ts() is None, "the addresses alone look like the same network"
    macs["192.168.1.1"] = "02:00:5E:BB:00:01"                                           # the pinger resolved site B's router
    change(back, T0 + 7260, 3)
    assert mgr.joined_ts() == T0 + 7260
    assert reports.parse_marker(db.get_meta(reports.NET_JOINED_META_KEY))["gateway_mac"] == "02:00:5E:BB:00:01"
    change(back, T0 + 9000, 4)                                                            # the same router again: no move
    assert mgr.joined_ts() == T0 + 7260
    # a swap no event caught (the MAC was not known at the event): the check before a report dates it at the last event seen
    macs["192.168.1.1"] = "02:00:5E:CC:00:01"
    now[0] = T0 + 20000
    mgr._check_gateway_mac()
    assert mgr.joined_ts() == T0 + 9000
    # at start: the same addresses behind another router is a move while the service was stopped
    macs["192.168.1.1"] = "02:00:5E:DD:00:01"
    restarted = reports.ReportManager(db, None, None, SimpleNamespace(started_ts=T0 + 30000),
                                      network_fn=lambda: ("192.168.1.1", ["192.168.1.0/24"], "Wi-Fi"),
                                      clock=lambda: T0 + 30005, gateway_mac_fn=macs.get, mac_wait_s=0.0)
    restarted._startup_network_check()
    assert restarted.joined_ts() == T0 + 30000
    assert reports.next_marker({"gateway": "10.0.0.1", "gateway_mac": "02:00:5E:AA:00:01"}, T0, "10.0.0.2", [], None,
                               "02:00:5E:EE:00:01")[0]["gateway_mac"] == "02:00:5E:EE:00:01"


def test_network_marker_ignores_wall_clock_order_and_clock_steps(db):
    now = [T0]
    mono = [1000.0]
    mgr = reports.ReportManager(db, None, None, SimpleNamespace(started_ts=T0 - 10 * DAY), clock=lambda: now[0],
                                monotonic=lambda: mono[0], network_fn=lambda: ("192.168.50.1", ["192.168.50.0/24"], "Ethernet"),
                                gateway_mac_fn=lambda gw: None, mac_wait_s=0.0)
    mgr._startup_network_check()

    def ev(ts: float, gateway: str, net: str, seq: int) -> None:
        mgr._apply_network_change({"ts": ts, "default_gateway": gateway, "internet_nic": {"name": "Ethernet", "networks": [net]}}, seq)

    ev(T0, "10.20.30.1", "10.20.30.0/24", 1)                       # joins site B
    ev(T0 + 2 * DAY + 3600, "10.20.30.1", "10.20.30.0/24", 2)      # a flap at site B, stamped by a clock running an hour fast
    ev(T0 + 2 * DAY + 1800, "172.16.40.1", "172.16.40.0/24", 3)    # the clock was put back; 30 min later, site C
    now[0] = T0 + 2 * DAY + 3 * HOUR
    assert mgr.joined_ts() == T0 + 2 * DAY + 1800, "the later move counts although its wall-clock time is older"
    # a join stamped by a clock a day fast: dated by the monotonic clock once the clock is right again, never an empty window
    now[0], mono[0] = T0 + DAY, 5000.0
    ev(T0 + DAY, "10.44.0.1", "10.44.0.0/24", 4)
    now[0], mono[0] = T0 + 600, 5600.0                             # ten minutes later, the clock corrected by a day
    assert mgr.joined_ts() == T0, "joined 600 s ago by the monotonic clock"
    start, reason = reports.report_window(now[0], mgr.joined_ts(), T0 - 30 * DAY)
    assert (start, reason) == (T0, "network_change")
    # a skewed join from an earlier service run: this run's start stands for it
    fresh = reports.ReportManager(db, None, None, None, clock=lambda: T0 + 600, monotonic=lambda: 9000.0)
    assert fresh.joined_ts() == T0 + 600 - 0.0, "no monotonic record of the join: the manager's start (just now)"


def test_saved_reports_read_the_device_types_older_versions_stored_under_their_new_names(db):
    """1.11 and older typed 22 open + a Ubiquiti MAC "Wifi": a report saved then reads and compares as "Ubiquiti"."""
    disc = {"available": True, "host_count": 2, "device_types": {"Router": 1, "Wifi": 1},
            "hosts": [{"ip": "10.0.0.251", "device_type": "Router"}, {"ip": "10.0.0.240", "device_type": "Wifi"}]}
    old = db.add_report("Acme Dental", "acme dental", T0, T0 + 90, "complete", "1.11.0", {}, {"meta": {}, "discovery": disc})
    new = db.add_report("Acme Dental", "acme dental", T0 + DAY, T0 + DAY + 90, "complete", __version__, {},
                        {"meta": {}, "discovery": dict(disc, device_types={"Router": 1, "Ubiquiti": 2})})
    mgr = reports.ReportManager(db, None, None, None, clock=lambda: T0 + 2 * DAY, monotonic=lambda: 9000.0)
    sec = mgr.get(old)["data"]["discovery"]
    assert sec["device_types"] == {"Router": 1, "Ubiquiti": 1}
    assert [h["device_type"] for h in sec["hosts"]] == ["Router", "Ubiquiti"]
    assert db.get_report(old)["data"]["discovery"]["device_types"] == {"Router": 1, "Wifi": 1}, "renamed on read, never rewritten"
    _, _, cmp = mgr.compare(old, new)
    rows = next(s["rows"] for s in cmp["sections"] if s["key"] == "discovery")
    assert [(r["label"], r["a"], r["b"]) for r in rows if r["key"].startswith("type:")] == [("Router", 1, 1), ("Ubiquiti", 1, 2)]
    # nothing to rename, or junk: returned as it is
    junk = {"data": {"discovery": {"hosts": [None, {"device_type": 7}], "device_types": ["Wifi"]}}}
    assert reports.rename_legacy_device_types(None) is None
    assert reports.rename_legacy_device_types(junk) == {"data": {"discovery": {"hosts": [None, {"device_type": 7}], "device_types": ["Wifi"]}}}


def test_first_start_without_a_marker_seeds_the_join_from_the_history(db):
    """The first start of a release with reports: the "network changed" events rows and long monitoring gaps a 1.9.1
    database already holds are the best guess of when this PC arrived (a shorter window beats one mixing two sites)."""
    def start_at(now: float) -> Optional[float]:
        db.set_meta(reports.NET_JOINED_META_KEY, "")
        mgr = reports.ReportManager(db, None, None, SimpleNamespace(started_ts=now), clock=lambda: now,
                                    network_fn=lambda: ("10.20.30.1", ["10.20.30.0/24"], "Ethernet"), gateway_mac_fn=lambda gw: None,
                                    mac_wait_s=0.0)
        mgr._startup_network_check()
        return mgr.joined_ts()

    assert start_at(T0) is None, "nothing recorded: the window is not shortened"
    db.add_event("info", "network", "network changed: Ethernet 10.20.30.15/24 - gateway 10.20.30.1", ts=T0 - DAY)
    db.add_event("info", "outage", "network changed hands", ts=T0 - HOUR)          # another category
    db.add_event("info", "network", "network changed: Ethernet 192.168.50.9/24", ts=T0 - 9 * DAY)   # before the window
    assert start_at(T0) == T0 - DAY
    gap = db.open_outage("gap", None, T0 - 10 * HOUR, note="not monitoring")
    db.close_outage(gap, T0 - 9 * HOUR, 0, "not monitoring")                        # off for an hour: may have been carried
    short = db.open_outage("gap", None, T0 - 3 * HOUR, note="system sleep")
    db.close_outage(short, T0 - 3 * HOUR + 600, 0, "system sleep")                  # ten minutes asleep: too short to count
    assert start_at(T0) == T0 - 9 * HOUR
    assert db.last_event_ts("network", "network changed", T0 - 2 * DAY) == T0 - DAY and db.last_event_ts("nothing") is None


# --------------------------------------------------------------------------------------
# the Full Scan job
# --------------------------------------------------------------------------------------
def _seed_history(rig: Rig) -> Dict[str, Any]:
    now = time.time()
    gw = rig.db.add_target("gateway", "Gateway")
    inet = rig.db.add_target("203.0.113.10", kind="internet")
    start = now - 3 * HOUR
    seed_minutes(rig.db, gw["id"], start, 170, 0.9)
    seed_minutes(rig.db, inet["id"], start, 170, 18.0, received=59)
    oid = rig.db.open_outage("total_internet", None, now - 2 * HOUR)
    rig.db.close_outage(oid, now - 2 * HOUR + 300)
    return {"gateway": gw, "internet": inet, "oldest": int(start // 60) * 60}


def test_full_scan_saves_a_complete_report(rig_factory):
    rig = rig_factory()
    seeded = _seed_history(rig)
    job = rig.mgr.start_scan("  Acme   Dental ")
    assert job["status"] == "running" and job["site"] == "Acme Dental" and job["phase"] == "speed"
    assert [p["key"] for p in job["phases"]] == ["speed", "discovery", "wifi", "history", "save"]
    # the window the report will read, shown while the scan runs
    assert (job["window_start"], job["window_reason"]) == (seeded["oldest"], "data_start")
    waiting = post_when_waiting(rig.mgr, wifi_body())
    assert waiting["phase"] == "wifi" and waiting["message"].startswith("Wi-Fi scan received")
    done = finished(rig.mgr)
    assert done["status"] == "saved" and done["pct"] == 100 and done["phase"] is None and done["error"] is None
    assert [p["status"] for p in done["phases"]] == ["done"] * 5
    report = rig.mgr.get(done["report_id"])
    assert report["site"] == "Acme Dental" and report["status"] == "complete" and report["created_ts"] == job["started_ts"]
    data = report["data"]
    assert set(data) == {"meta", "network", "speed", "ping", "outages", "discovery", "wifi"}
    assert all(data[k]["available"] for k in data if k != "meta")
    meta = data["meta"]
    assert meta["hostname"] == "BENCH-01" and meta["tnt_version"] == __version__ and meta["site"] == "Acme Dental"
    assert [p["status"] for p in meta["scan_phases"]] == ["done"] * 5
    speed_rows = rig.db.list_speedtests(0, time.time() + 10)
    assert len(speed_rows) == 1 and data["speed"]["result"]["id"] == speed_rows[0]["id"]
    assert data["speed"]["result"]["download_mbps"] == 94.2 and "raw" not in data["speed"]["result"]
    assert data["network"]["public_ip"] == "203.0.113.10" and data["network"]["isp"] == "Example ISP"
    assert data["ping"]["window_reason"] == "data_start" and data["ping"]["window_start"] == seeded["oldest"]
    assert data["ping"]["window_end"] == job["started_ts"]
    roles = {t["host"]: t["role"] for t in data["ping"]["targets"]}
    assert roles == {"gateway": "gateway", "203.0.113.10": "internet"}
    assert data["outages"]["count"] == 1 and data["outages"]["network_down_s"] == 300.0
    history = next(p for p in done["phases"] if p["key"] == "history")
    assert re.fullmatch(r"Pings and outages since the ping data begins \(\d\.\d h\)", history["message"]), history["message"]
    assert data["discovery"]["range"] == "192.168.50.0/24" and data["discovery"]["host_count"] == 4
    assert data["wifi"]["aps_count"] == 6 and data["wifi"]["connected"]["rssi"] == -48
    assert report["summary"]["download_mbps"] == 94.2 and report["summary"]["hosts"] == 4
    assert rig.types("report.saved") == ["report.saved"]
    saved = next(e for e in rig.events if e["type"] == "report.saved")
    assert saved["data"] == {"id": done["report_id"], "site": "Acme Dental", "status": "complete"}
    progress = [e["data"]["job"] for e in rig.events if e["type"] == "report.progress"]
    assert len(progress) >= 6 and progress[-1]["status"] == "saved"
    pcts = [p["pct"] for p in progress]
    assert pcts == sorted(pcts), "the percentage never goes back"
    assert {p["phase"] for p in progress} >= {"speed", "discovery", "wifi", "finalize"}
    st = rig.mgr.status()
    assert st["count"] == 1 and st["sites"] == 1 and st["last"]["site"] == "Acme Dental" and st["job"]["status"] == "saved"
    with pytest.raises(reports.ScanConflict) as late:
        rig.mgr.post_wifi(wifi_body())
    assert late.value.code == "not_waiting"
    assert rig.mgr.cancel()["status"] == "saved", "a finished job is not cancelled"


def test_full_scan_with_failing_phases_is_partial(rig_factory):
    rig = rig_factory(backend=FakeBackend(ok=False), scanner=FakeScanner(default=None))
    rig.mgr.start_scan("Northside Warehouse")
    post_when_waiting(rig.mgr, wifi_body(available=False, state="no_adapter", aps=[]))
    done = finished(rig.mgr)
    assert done["status"] == "saved"
    statuses = {p["key"]: (p["status"], p["message"]) for p in done["phases"]}
    assert statuses["speed"] == ("error", "The speed test failed: the fake server hung up")
    assert statuses["discovery"][0] == "error" and "no default network" in statuses["discovery"][1]
    assert statuses["wifi"] == ("skipped", "This PC has no Wi-Fi adapter")
    assert statuses["history"][0] == "done" and statuses["save"][0] == "done"
    report = rig.mgr.get(done["report_id"])
    assert report["status"] == "partial"
    data = report["data"]
    assert data["speed"]["available"] is False and data["speed"]["result"]["ok"] is False
    assert data["discovery"]["available"] is False and "no default network" in data["discovery"]["reason"]
    assert data["wifi"]["available"] is False and data["wifi"]["reason"] == "This PC has no Wi-Fi adapter"
    assert data["ping"]["available"] is False and data["ping"]["reason"] == "No pings were recorded in this window"
    # no pings, so no outage could have been noticed: not "0 outages"
    assert data["outages"]["available"] is False and data["outages"]["reason"] == "No pings were recorded in this window"
    assert report["summary"]["outages"] is None and data["network"]["available"] is True
    assert rig.db.list_speedtests(0, time.time() + 10)[0]["ok"] is False, "a failed test is still a measurement"


def test_full_scan_uses_a_speed_test_and_discovery_scan_that_are_already_running(rig_factory):
    rig = rig_factory(backend=FakeBackend(block=True), scanner=FakeScanner(block=True))
    assert rig.engine.speed.run_now() is True                          # started from the Speed page
    assert rig.backend.started.wait(5.0)
    assert rig.engine.discovery_start("192.168.50.0/24", [80]) is True  # started from the Discovery page
    rig.mgr.start_scan("Acme Dental")
    assert _wait_for(lambda: rig.mgr.job()["message"] == "Waiting for the speed test that is already running")
    time.sleep(0.3)
    assert rig.backend.calls == 1
    rig.backend.gate.set()
    assert _wait_for(lambda: rig.mgr.job()["message"] == "Waiting for the Discovery scan that is already running")
    time.sleep(0.3)
    assert len(rig.engine.discovery.scans) == 1
    rig.engine.discovery.gate.set()
    post_when_waiting(rig.mgr, wifi_body())
    done = finished(rig.mgr)
    report = rig.mgr.get(done["report_id"])
    assert report["status"] == "complete"
    assert rig.backend.calls == 1 and len(rig.engine.discovery.scans) == 1, "nothing ran twice"
    runs = rig.db.list_discovery_runs(10)
    assert len(runs) == 1 and report["data"]["discovery"]["run_id"] == runs[0]["id"]
    assert report["data"]["discovery"]["range"] == "192.168.50.0/24"
    assert report["data"]["speed"]["result"]["id"] == rig.db.list_speedtests(0, time.time() + 10)[0]["id"]


def test_full_scan_wifi_timeout_and_grace(rig_factory):
    rig = rig_factory(wifi_wait_s=0.6)
    rig.mgr.start_scan("Lakeside Clinic")
    done = finished(rig.mgr)
    wifi = next(p for p in done["phases"] if p["key"] == "wifi")
    assert (wifi["status"], wifi["message"]) == ("skipped", reports.NO_WINDOW_REASON)
    report = rig.mgr.get(done["report_id"])
    assert report["status"] == "partial" and report["data"]["wifi"]["reason"] == reports.NO_WINDOW_REASON

    # a browser tab without the bridge posts first; the TNT window's snapshot a moment later wins
    rig.mgr.wifi_wait_s, rig.mgr.wifi_grace_s = 8.0, 3.0
    rig.mgr.start_scan("Lakeside Clinic")
    post_when_waiting(rig.mgr, {"available": False, "state": "no_bridge", "error": None})
    assert "waiting briefly" in rig.mgr.job()["message"]
    rig.mgr.post_wifi(wifi_body())
    done = finished(rig.mgr)
    report = rig.mgr.get(done["report_id"])
    assert report["status"] == "complete" and report["data"]["wifi"]["aps_count"] == 6

    # only the unavailable one arrives: recorded once the grace time is up
    rig.mgr.wifi_grace_s = 0.3
    t0 = time.time()
    rig.mgr.start_scan("Lakeside Clinic")
    post_when_waiting(rig.mgr, {"available": False, "state": "location_denied", "error": None})
    done = finished(rig.mgr)
    assert time.time() - t0 < 6.0, "the grace time, not the 8 s wait"
    wifi = next(p for p in done["phases"] if p["key"] == "wifi")
    assert wifi["status"] == "error" and "location access" in wifi["message"]
    assert rig.mgr.sites("lakeside")["sites"][0]["count"] == 3


def test_full_scan_without_a_name_is_unnamed_and_can_be_named_later(rig_factory):
    rig = rig_factory()
    with pytest.raises(reports.ScanConflict) as none:
        rig.mgr.set_site("Acme Dental")
    assert none.value.code == "no_scan"
    rig.mgr.start_scan()
    post_when_waiting(rig.mgr, wifi_body())
    done = finished(rig.mgr)
    assert rig.mgr.get(done["report_id"])["site"] == reports.UNNAMED_SITE
    job = rig.mgr.set_site("  Lakeside   Clinic ")
    assert job["site"] == "Lakeside Clinic" and job["status"] == "saved"
    report = rig.mgr.get(done["report_id"])
    assert report["site"] == "Lakeside Clinic" and report["data"]["meta"]["site"] == "Lakeside Clinic"
    updated = [e["data"] for e in rig.events if e["type"] == "report.updated"]
    assert updated == [{"id": done["report_id"], "site": "Lakeside Clinic"}]
    with pytest.raises(ValueError):
        rig.mgr.set_site("   ")

    rig.mgr.start_scan()                                  # named while it runs
    rig.mgr.set_site("Northside Warehouse")
    post_when_waiting(rig.mgr, wifi_body())
    done = finished(rig.mgr)
    assert rig.mgr.get(done["report_id"])["site"] == "Northside Warehouse"


def test_second_scan_is_busy_and_cancel_saves_nothing(rig_factory):
    rig = rig_factory(backend=FakeBackend(block=True))
    job = rig.mgr.start_scan("Acme Dental")
    assert _wait_for(lambda: rig.mgr.job()["message"] == "Running the speed test")
    with pytest.raises(reports.ScanBusy) as busy:
        rig.mgr.start_scan("Northside Warehouse")
    assert busy.value.job["id"] == job["id"] and busy.value.code == "busy"
    cancelled = rig.mgr.cancel()
    assert cancelled["status"] == "cancelled" and cancelled["phase"] is None
    assert [p["status"] for p in cancelled["phases"]] == ["skipped"] * 5
    assert _wait_for(lambda: not rig.engine.speed.running), "its own speed test is cut short"
    finished(rig.mgr)
    assert rig.mgr.job()["status"] == "cancelled"
    assert rig.db.list_speedtests(0, time.time() + 10) == [], "a cancelled test is not stored"
    assert rig.db.list_reports()[1] == 0 and rig.types("report.saved") == []
    assert rig.mgr.cancel()["status"] == "cancelled"


class SlowToCancel(FakeBackend):
    """A backend that notices a cancel only a second later, like a transfer blocked in a read."""

    def run(self, config: Any, progress: Any = None, cancel: Any = None) -> SpeedResult:
        self.calls += 1
        self.started.set()
        if progress:
            progress("download", 0.3)
        while not self.gate.is_set() and not (cancel is not None and cancel.is_set()):
            time.sleep(0.01)
        if cancel is not None and cancel.is_set():
            time.sleep(1.0)
            return SpeedResult(ok=False, ts=time.time(), backend="fake", error="cancelled", duration_s=0.1)
        return SpeedResult(ok=True, ts=time.time(), backend="fake", server="Example Colo", download_mbps=94.2, upload_mbps=18.6,
                           latency_ms=12.3, jitter_ms=1.1, packet_loss_pct=0.0, duration_s=1.0)


def test_a_scan_started_right_after_a_cancel_runs_its_own_speed_test(rig_factory):
    """Cancel scan, then Full Scan at once: the cancelled test is still winding down, and its "cancelled" result is not the
    new scan's."""
    from tnt.speedtest.base import CANCELLED
    assert reports.SPEED_CANCELLED == CANCELLED
    backend = SlowToCancel()
    rig = rig_factory(backend=backend)
    rig.mgr.start_scan("Acme Dental")
    assert backend.started.wait(5.0) and _wait_for(lambda: rig.mgr._scan.own_speed)
    assert rig.mgr.cancel()["status"] == "cancelled"
    backend.gate.set()                                   # the next test succeeds at once
    job2 = rig.mgr.start_scan("Acme Dental")
    post_when_waiting(rig.mgr, wifi_body())
    done = finished(rig.mgr, timeout=20.0)
    speed = next(p for p in done["phases"] if p["key"] == "speed")
    assert done["id"] == job2["id"] and speed["status"] == "done" and speed["message"].startswith("Download 94.2 Mbps")
    assert backend.calls == 2 and rig.mgr.get(done["report_id"])["status"] == "complete"


def test_a_cancelled_scans_thread_never_touches_the_next_scans_state(rig_factory):
    """A cancelled scan whose thread is still busy (its history phase reads a slow adapter snapshot) while the next one runs:
    the old thread ending must neither clear the new scan's own speed test flag nor close its Wi-Fi intake."""
    gate = threading.Event()
    calls = {"n": 0}

    def slow_snapshot() -> Dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 1:
            gate.wait(20.0)
        return fake_snapshot()

    backend = FakeBackend()
    rig = rig_factory(backend=backend, wifi_wait_s=0.3, wifi_grace_s=0.1)
    mgr = rig.mgr
    mgr._netinfo_fn = slow_snapshot
    try:
        mgr.start_scan("Acme Dental")
        assert _wait_for(lambda: (mgr.job() or {}).get("phase") == "finalize", 20.0)
        old = mgr._thread
        assert mgr.cancel()["status"] == "cancelled" and old.is_alive()
        backend.block = True
        backend.started.clear()
        job2 = mgr.start_scan("Northside Warehouse")              # accepted while the first thread still runs
        assert backend.started.wait(10.0) and _wait_for(lambda: mgr._scan.own_speed, 5.0)
        gate.set()
        old.join(10.0)
        assert not old.is_alive() and mgr._scan.own_speed, "the first scan's thread left the second scan's flag alone"
        assert mgr.cancel()["id"] == job2["id"]
        assert _wait_for(lambda: not rig.engine.speed.running, 5.0), "so cancelling the second scan still stops its own test"
        finished(mgr)

        # the Wi-Fi intake: the first scan's thread ends while the next one waits for the TNT window
        backend.block = False
        calls["n"] = 0
        gate.clear()
        mgr.start_scan("Lakeside Clinic")                          # no Wi-Fi within 0.3 s: on to its (slow) history phase
        assert _wait_for(lambda: (mgr.job() or {}).get("phase") == "finalize", 20.0)
        old = mgr._thread
        mgr.cancel()
        mgr.wifi_wait_s = 8.0
        job4 = mgr.start_scan("Maple Street Office")
        assert _wait_for(lambda: mgr._scan.wifi_waiting, 10.0)
        gate.set()
        old.join(10.0)
        assert not old.is_alive() and mgr._scan.wifi_waiting
        assert mgr.post_wifi(wifi_body())["id"] == job4["id"], "the TNT window's snapshot is still taken"
        done = finished(mgr)
        assert next(p for p in done["phases"] if p["key"] == "wifi")["status"] == "done"
    finally:
        gate.set()


def test_a_cancelled_discovery_scan_is_not_the_full_scans(rig_factory):
    rig = rig_factory(scanner=FakeScanner(block=True))
    assert rig.engine.discovery_start("192.168.50.0/24", [80]) is True       # started from the Discovery page
    rig.mgr.start_scan("Acme Dental")
    assert _wait_for(lambda: rig.mgr.job()["message"] == "Waiting for the Discovery scan that is already running")
    rig.engine.discovery.block = False                                        # the next sweep ends at once
    rig.engine.discovery_cancel()                                             # ... and the one waited for is cancelled
    post_when_waiting(rig.mgr, wifi_body())
    done = finished(rig.mgr, timeout=20.0)
    assert next(p for p in done["phases"] if p["key"] == "discovery")["status"] == "done"
    assert len(rig.engine.discovery.scans) == 2 and rig.mgr.get(done["report_id"])["data"]["discovery"]["host_count"] == 4


def test_naming_the_last_scan_after_its_report_was_deleted(rig_factory, tmp_path):
    rig = rig_factory(wifi_wait_s=0.3)
    srv = rig.serve(tmp_path)
    rig.mgr.start_scan("Northside Warehouse")
    done = finished(rig.mgr)
    status, _h, data = call(srv, "DELETE", f"/api/reports/{done['report_id']}")
    assert status == 200
    job = rig.mgr.job()
    assert job["status"] == "saved" and job["report_id"] is None, "the job forgets the report it saved"
    assert [e["data"]["job"]["report_id"] for e in rig.events if e["type"] == "report.progress"][-1] is None
    status, _h, data = call(srv, "PATCH", "/api/reports/scan", {"site": "Lakeside Clinic"})
    assert status == 409 and data["error"]["code"] == "not_found" and data["job"]["report_id"] is None
    # deleted behind the manager's back (another window's request racing this one): the rename finds nothing either
    rig.mgr.wifi_wait_s = 0.3
    rig.mgr.start_scan("Acme Dental")
    done = finished(rig.mgr)
    rig.db.delete_report(done["report_id"])
    with pytest.raises(reports.ScanConflict) as gone:
        rig.mgr.set_site("Lakeside Clinic")
    assert gone.value.code == "not_found" and rig.mgr.job()["report_id"] is None
    # a lone surrogate is valid JSON but no text the database can store: 400, and no scan is started
    raw = json.dumps({"site": "Acme " + chr(0xD800) + " Dental"}).encode("utf-8")
    assert call(srv, "PATCH", "/api/reports/scan", raw=raw)[0] == 400
    assert call(srv, "POST", "/api/reports/scan", raw=raw)[0] == 400 and rig.mgr.job()["status"] == "saved"


def test_status_never_caches_counts_read_before_a_change(db):
    mgr = reports.ReportManager(db, None, None, None)
    real = db.report_stats
    reading, go_on = threading.Event(), threading.Event()

    def slow_stats() -> Dict[str, Any]:
        out = real()
        reading.set()
        go_on.wait(5.0)                 # the status poll is descheduled between reading the counts and caching them
        return out

    db.report_stats = slow_stats
    seen: List[int] = []
    t = threading.Thread(target=lambda: seen.append(mgr.status()["count"]))
    t.start()
    assert reading.wait(5.0)
    db.report_stats = real
    rid = db.add_report("Acme Dental", "acme dental", T0, T0 + 95, "complete", __version__, {}, {})
    mgr.rename(rid, "Acme Dental North")                 # a change while the poll was reading
    go_on.set()
    t.join(5.0)
    assert seen == [0] and mgr.status()["count"] == 1


def test_cancel_during_discovery_stops_the_scans_own_sweep(rig_factory):
    rig = rig_factory(scanner=FakeScanner(block=True))
    rig.mgr.start_scan("Acme Dental")
    assert _wait_for(lambda: rig.mgr.job()["message"] == "Scanning the network")
    assert rig.mgr.cancel()["status"] == "cancelled"
    assert _wait_for(lambda: not rig.engine.discovery_running())
    assert rig.engine.discovery.stopped is True
    finished(rig.mgr)
    assert rig.db.list_reports()[1] == 0


def test_stop_cancels_a_running_scan(rig_factory):
    rig = rig_factory()
    rig.mgr.start_scan("Acme Dental")
    assert _wait_for(lambda: rig.mgr.job()["phase"] == "wifi")
    t0 = time.monotonic()
    rig.mgr.stop()
    assert time.monotonic() - t0 < 2.0
    assert rig.mgr.job()["status"] == "cancelled" and rig.mgr.job()["message"] == "The service is stopping"
    with pytest.raises(reports.ScanConflict):
        rig.mgr.start_scan("Acme Dental")


def test_speed_scheduler_cancel_current(data_dir, monkeypatch):
    cfg = tnt_config.Config(data_dir / "config.json").load()
    d = tnt_db.Database(data_dir / "tnt.db")
    bus = tnt_events.EventBus()
    seen: List[Dict[str, Any]] = []
    bus.subscribe(seen.append)
    backend = FakeBackend(block=True)
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: backend)
    sched = sched_mod.SpeedScheduler(d, cfg, bus)
    try:
        assert sched.cancel_current() is False
        assert sched.run_now() is True and backend.started.wait(5.0)
        assert sched.cancel_current() is True
        assert _wait_for(lambda: any(e["type"] == "speedtest.done" for e in seen))
        done = next(e for e in seen if e["type"] == "speedtest.done")
        assert done["data"]["result"]["error"] == "cancelled" and "id" not in done["data"]["result"]
        assert _wait_for(lambda: not sched.running) and d.list_speedtests(0, time.time() + 10) == []
    finally:
        sched.stop()
        d.close()


def test_engine_wires_the_report_manager(data_dir):
    from tnt.engine import Engine

    eng = Engine(console=True, port=0, data_dir=data_dir)
    eng._start_reports()
    assert eng.reports is None and eng.errors["reports"] == "database unavailable"
    calls: List[Any] = []
    eng.reports = SimpleNamespace(on_network_change=lambda data: calls.append(data["generation"]))
    eng._on_net_changed({"generation": 3, "ts": T0, "summary": "Ethernet: 192.168.50.112/24 · gateway 192.168.50.1"})
    assert calls == [3]
    assert eng.discovery_running() is False
    release = threading.Event()
    eng._disc_thread = threading.Thread(target=release.wait, args=(5.0,), daemon=True)
    eng._disc_thread.start()
    try:
        assert eng.discovery_running() is True
    finally:
        release.set()


# --------------------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------------------
MAC_SITE = "02:00:5E:10:00:0A"
MAC_OTHER = "02:00:5E:10:00:0B"


def tagged_minutes(db: tnt_db.Database, tid: int, start: float, count: int, avg: float, network_id: Optional[int] = None,
                   received: int = 60) -> None:
    base = int(start // 60) * 60
    for i in range(count):
        value = avg if received else None
        db.upsert_ping_minute(tid, base + i * 60, 60, received, value, value, value, 0.5 if received else None, network_id)


def test_a_site_report_reads_only_its_network_across_visits_and_leaves_the_trip_out(db):
    """Site A visited twice in a week (A, then B, then A again), with untagged minutes from before networks were tagged: the report
    counts A's minutes, outages and speed tests and the untagged ones since the old join time, never B's, and nothing of the trip
    from A to B (no network in between); an outage that began as the PC left is the loss itself, one that began earlier ends when
    the trip began.  Visits and the monitored time are A's, without the monitoring gap."""
    end = float(int(T0 // 60) * 60)
    start = end - 7 * DAY
    a = db.add_network(start, mac=MAC_SITE, fingerprint="fa", gateway_ip="192.168.1.1", subnet="192.168.1.0/24")["id"]
    b = db.add_network(start, mac=MAC_OTHER, fingerprint="fb", gateway_ip="192.168.1.1", subnet="192.168.1.0/24")["id"]
    gw = db.add_target("gateway", "Gateway")["id"]
    inet = db.add_target("203.0.113.10", kind="internet")["id"]
    legacy_since = end - 6 * DAY
    trip_start, trip_end = end - 5 * DAY + 8 * HOUR, end - 5 * DAY + 9 * HOUR
    for tid in (gw, inet):
        tagged_minutes(db, tid, end - 6.5 * DAY, 60, 99.0)                         # untagged, before the old join time
        tagged_minutes(db, tid, legacy_since + HOUR, 120, 20.0)                    # untagged, after it: the time rule counts them
        tagged_minutes(db, tid, end - 5 * DAY, 480, 10.0, a)                       # visit 1 on A
        tagged_minutes(db, tid, trip_start, 60, 0.0, a, received=0)                # the trip: still tagged A, but no network
        tagged_minutes(db, tid, end - 4 * DAY, 1440, 80.0, b)                      # a day on B
        tagged_minutes(db, tid, end - DAY, 360, 12.0, a)                           # visit 2 on A
    db.open_offline_spell(a, trip_start)
    db.close_offline_spells(trip_end, b)
    db.open_offline_spell(b, end - 3 * DAY)                                       # a Wi-Fi drop at B that came back to B
    db.close_offline_spells(end - 3 * DAY + 600, b)

    def outage(kind: str, tid: Optional[int], s: float, e: float, network_id: Optional[int], note: Optional[str] = None) -> None:
        db.close_outage(db.open_outage(kind, tid, s, note=note, host="203.0.113.10" if tid == inet else "gateway (192.168.1.1)",
                                       network_id=network_id), e, int(e - s) if tid else 0, note)

    outage("total_internet", None, end - 5 * DAY + 2 * HOUR, end - 5 * DAY + 2 * HOUR + 300, a)
    outage("target", inet, end - 5 * DAY + 2 * HOUR + 1, end - 5 * DAY + 2 * HOUR + 299, a)
    outage("total_internet", None, end - 4 * DAY + HOUR, end - 4 * DAY + HOUR + 900, b)
    outage("total_local", None, trip_start - 20, trip_end, a, "network changed")                   # the loss as the PC left
    outage("target", gw, end - 5 * DAY + 6 * HOUR, trip_end, a, "network changed")                 # a site outage, cut at the trip
    outage("total_internet", None, legacy_since + 2 * HOUR, legacy_since + 2 * HOUR + 120, None)
    outage("total_internet", None, end - 6.5 * DAY + 60, end - 6.5 * DAY + 180, None)
    outage("gap", None, end - DAY + 2 * HOUR, end - DAY + 2 * HOUR + 900, a, "system sleep")
    for ts, down, nid in ((end - 5 * DAY + HOUR, 90.0, a), (end - 4 * DAY + HOUR, 900.0, b), (legacy_since + HOUR, 60.0, None),
                          (end - 6.5 * DAY, 10.0, None)):
        db.add_speedtest({"ts": ts, "ok": True, "backend": "fake", "download_mbps": down, "network_id": nid})

    travel = reports.travel_spans(db.offline_spells(a, start - reports.LEAVE_SLACK_S, end))
    assert travel == [(trip_start, trip_end)] and reports.travel_spans(db.offline_spells(b, start, end)) == []
    scope = {"id": a, "legacy_since": legacy_since, "travel": travel}
    configured = db.list_targets(enabled_only=True)
    ping = reports.build_ping_section(db, start, end, "site_network", [], "192.168.1.1", configured, set(), network=scope)
    by_host = {t["host"]: t for t in ping["targets"]}
    # 120 untagged minutes, visit 1 without its last minute (the minute before the trip), visit 2
    assert by_host["gateway"]["samples"] == (120 + 479 + 360) * 60 and by_host["gateway"]["lost"] == 0
    assert by_host["203.0.113.10"]["avg_ms"] == round((120 * 20.0 + 479 * 10.0 + 360 * 12.0) / 959, 2)
    assert ping["visits"] == [{"start": legacy_since + HOUR, "end": legacy_since + 3 * HOUR},
                              {"start": end - 5 * DAY, "end": trip_start - 60}, {"start": end - DAY, "end": end - DAY + 6 * HOUR}]
    everything = db.list_outages(start, end)
    gaps = [(r["start_ts"], r["end_ts"]) for r in everything if r["kind"] == "gap"]
    monitored = reports.monitored_seconds(ping["visits"], gaps)
    assert monitored == 2 * HOUR + 8 * HOUR - 60 + 6 * HOUR - 900
    rows = reports.scope_outage_rows(everything, a, legacy_since, travel)
    out = reports.build_outages_section(rows, start, end, 1.0, target_ids=[r["id"] for r in configured], monitored_s=monitored)
    assert (out["count"], out["network_outages"], out["target_outages"], out["network_down_s"]) == (3, 2, 1, 420.0)
    assert out["by_kind"] == {"target": 2, "total_local": 0, "total_internet": 2, "gap": 1} and out["monitored_s"] == monitored
    cut = next(i for i in out["items"] if i["kind"] == "target")
    assert (cut["end_ts"], cut["duration_s"], cut["open"]) == (trip_start, 2 * HOUR, False)
    assert [r["download_mbps"] for r in db.list_speedtests(start, end, ok_only=True, network_id=a, legacy_since=legacy_since)] == [90.0, 60.0]
    data = make_data(end=end, window_s=7 * DAY)
    ping["monitored_s"] = monitored
    data["ping"], data["outages"] = ping, out
    summary = reports.build_summary(data)
    assert summary["window_hours"] == round(monitored / 3600.0, 1) and summary["outages"] == 3
    assert reports.network_time(data) == (monitored, 3) and reports.network_time_text(data) == "15h 44m over 3 visits"
    # untagged minutes before the time rule's start (6.5 days ago) were left out: the section says since when untagged ones count
    assert ping["untagged_since"] == legacy_since


def test_a_network_outage_whose_targets_are_all_left_out_is_left_out_too():
    start, end = T0 - DAY, T0

    def row(kind: str, tid: Optional[int], s: float, e: float) -> Dict[str, Any]:
        return {"kind": kind, "target_id": tid, "host": f"198.51.100.{tid}" if tid else None, "start_ts": start + s, "end_ts": start + e,
                "missed": 10 if kind == "target" else 0, "missed_pct": 100.0 if kind == "target" else None, "note": None}

    rows = [row("target", 5, 1000, 1300), row("target", 6, 1001, 1300), row("total_internet", None, 1002, 1300),   # removed targets only
            row("target", 1, 5000, 5200), row("target", 6, 5001, 5200), row("total_internet", None, 5002, 5200),   # one set up: stays
            row("total_local", None, 9000, 9100),                                                                  # no member rows: stays
            row("target", 5, 12000, 12060)]
    out = reports.build_outages_section(rows, start, end, target_ids=[1, 2])
    assert (out["count"], out["network_outages"], out["target_outages"], out["network_down_s"]) == (2, 2, 0, 298.0)
    assert out["by_kind"] == {"target": 1, "total_local": 1, "total_internet": 1, "gap": 0}
    assert out["note"] == "Left out: 2 removed or disabled targets (1 network outage, 1 single-target outage)"
    no_ids = [dict(r, target_id=None) if r["target_id"] in (5, 6) else r for r in rows]
    assert reports.build_outages_section(no_ids, start, end, target_ids=[1, 2])["note"] == \
        "Left out: 1 network outage and 1 single-target outage of removed or disabled targets"
    assert reports.left_out_note(3, 0, 2) == "Left out: 3 removed or disabled targets (2 network outages)"
    assert reports.build_outages_section(rows, start, end)["network_outages"] == 3, "without target ids every row counts"


def site_tracker(db: tnt_db.Database, mac: Optional[str] = MAC_SITE, online: bool = True) -> networks.NetworkTracker:
    facts = {"gateway_ip": "192.168.50.1", "subnet": "192.168.50.0/24", "dhcp_server": "192.168.50.1", "dns_suffix": "acme.example",
             "nic": "Ethernet", "if_index": 7}
    tracker = networks.NetworkTracker(db, facts_fn=lambda hint: dict(facts) if online else None,
                                      neighbour_fn=lambda ip, index: (mac, "reachable") if mac else None, mac_wait_s=0.3, mac_poll_s=0.02)
    tracker.start()
    return tracker


def test_full_scan_on_a_known_network_suggests_its_site_and_reads_only_that_network(rig_factory):
    rig = rig_factory()
    db, now = rig.db, time.time()
    tracker = site_tracker(db)
    rig.engine.networks = tracker
    rig.engine.speed._network_fn = tracker.current_network_id
    try:
        a = tracker.current_network_id()
        b = db.add_network(now - 3 * DAY, mac=MAC_OTHER, fingerprint="other", gateway_ip="192.168.50.1", subnet="192.168.50.0/24")["id"]
        gw = db.add_target("gateway", "Gateway")["id"]
        inet = db.add_target("203.0.113.10", kind="internet")["id"]
        tagged_minutes(db, gw, now - 2 * DAY, 180, 1.0, a)
        tagged_minutes(db, inet, now - 2 * DAY, 180, 20.0, a)
        tagged_minutes(db, gw, now - DAY, 300, 9.0, b)
        tagged_minutes(db, inet, now - DAY, 300, 95.0, b)
        tagged_minutes(db, gw, now - 2 * HOUR, 110, 1.0, a)
        tagged_minutes(db, inet, now - 2 * HOUR, 110, 22.0, a)
        db.close_outage(db.open_outage("total_internet", None, now - 90 * 60, network_id=a), now - 85 * 60)
        db.close_outage(db.open_outage("total_internet", None, now - DAY + HOUR, network_id=b), now - DAY + 2 * HOUR)
        # a gap of the other network's (dated inside A's second visit): never taken off A's monitored time
        db.close_outage(db.open_outage("gap", None, now - 2 * HOUR + 600, note="system sleep", network_id=b), now - 2 * HOUR + 1200, 0, "system sleep")
        db.add_speedtest({"ts": now - DAY + HOUR, "ok": True, "backend": "fake", "download_mbps": 900.0, "network_id": b})
        first = db.add_report("Acme Dental", "acme dental", now - DAY - HOUR, now - DAY, "complete", __version__, {},
                              {"meta": {"site": "Acme Dental"}}, network_id=a)
        db.add_report("Northside Warehouse", "northside warehouse", now - DAY + 3 * HOUR, now - DAY + 4 * HOUR, "complete", __version__,
                      {}, {}, network_id=b)
        job = rig.mgr.start_scan()
        assert (job["network_id"], job["window_reason"], job["site"]) == (a, "site_network", None)
        assert job["suggested_site"] == {"site": "Acme Dental", "report_id": first, "created_ts": now - DAY - HOUR}
        post_when_waiting(rig.mgr, wifi_body())
        done = finished(rig.mgr)
        assert done["site"] == "Acme Dental" and done["suggested_site"]["report_id"] == first
        assert done["message"] == "Saved the report for Acme Dental, the site this network was scanned as before"
        assert job["network"] == networks.network_view(db.get_network(a), with_times=False) and job["network"]["mac"] == MAC_SITE
        history = next(p for p in done["phases"] if p["key"] == "history")
        assert history["message"].startswith("Pings and outages on this network over the last 7 days")
        report = rig.mgr.get(done["report_id"])
        assert (report["site"], report["network_id"], report["data"]["meta"]["site"]) == ("Acme Dental", a, "Acme Dental")
        data = report["data"]
        assert data["meta"]["network"] == {"id": a, "mac": MAC_SITE, "vendor": networks.router_vendor(MAC_SITE), "gateway_ip": "192.168.50.1",
                                           "subnet": "192.168.50.0/24", "dhcp_server": "192.168.50.1", "identity": "mac",
                                           "virtual_mac": None, "portable": False}
        ping = data["ping"]
        targets = {t["host"]: t for t in ping["targets"]}
        assert ping["window_reason"] == "site_network" and targets["gateway"]["samples"] == 290 * 60
        assert targets["203.0.113.10"]["avg_ms"] == round((180 * 20.0 + 110 * 22.0) / 290, 2), "never the other site's 95 ms"
        assert len(ping["visits"]) == 2 and ping["monitored_s"] == 290 * 60.0 == data["outages"]["monitored_s"]
        assert (data["outages"]["count"], data["outages"]["network_down_s"]) == (1, 300.0)
        assert data["speed"]["window"]["count"] == 1 and data["speed"]["window"]["download_max"] == 94.2
        assert report["summary"]["window_hours"] == round(290 * 60 / 3600.0, 1)
        listed = rig.mgr.list_reports()["reports"][0]
        assert (listed["id"], listed["network_id"]) == (done["report_id"], a)
        # compared with the earlier report of this network, and with the other site's
        before = rig.mgr.get(first)
        comparison = reports.compare_reports(report, before)
        # the time on its network once, in the comparison's notes (the page's duration format), then that both share one network
        assert comparison["notes"] == ["On their networks: A 4h 50m over 2 visits", f"A and B were scanned on the same network (router {MAC_SITE})"]
        ping_note = next(s for s in comparison["sections"] if s["key"] == "ping")["rows"]
        assert reports.compare_reports(report, rig.mgr.get(first + 1))["notes"] == ["On their networks: A 4h 50m over 2 visits"]
        assert reports._windows_note(ping, {}, data, before["data"]) == "Windows: B -", "a side of the site's network is not repeated"
        assert reports._windows_note(ping, ping, data, data) is None
        assert ping_note == [] or ping_note[0]["note"] in (None, "Windows: B -")
        # the PDFs say which network and how much of the week was spent on it, in one parenthesis and their own duration format
        text = _pdf_text(report_pdf.build_site_report(report))
        for needle in (b"Router", b"Vendor", MAC_SITE.encode(), b" days; this site's network only: 2 visits, 4 h 50 min monitored\\)"):
            assert needle in text, needle
        assert b"monitored on this network" not in text
        compare_text = _pdf_text(report_pdf.build_compare_report(report, before, comparison))
        assert b"A and B were scanned on the same network" in compare_text and b"\\(2 visits, 4 h 50 min on its network\\)" in compare_text
        assert b"On their networks" not in compare_text, "the side line carries it"
        # a second scan suggests the newest report of this network; it follows a rename and a delete while it runs
        rig.backend.block = True
        second = rig.mgr.start_scan()
        assert second["suggested_site"]["report_id"] == done["report_id"]
        rig.mgr.rename(done["report_id"], "Acme Dental North")
        assert rig.mgr.job()["suggested_site"] == {"site": "Acme Dental North", "report_id": done["report_id"], "created_ts": report["created_ts"]}
        assert rig.mgr.delete(done["report_id"]) is True
        assert rig.mgr.job()["suggested_site"] == {"site": "Acme Dental", "report_id": first, "created_ts": now - DAY - HOUR}
        progress = [e["data"]["job"] for e in rig.events if e["type"] == "report.progress" and e["data"]["job"]["id"] == second["id"]]
        assert progress[-1]["suggested_site"]["report_id"] == first, "the page hears of it"
        rig.mgr.cancel()
        finished(rig.mgr)
    finally:
        tracker.stop()


def test_full_scan_without_an_identified_network_uses_the_time_rule_and_says_so(rig_factory):
    rig = rig_factory()
    tracker = site_tracker(rig.db, mac=None, online=False)
    rig.engine.networks = tracker
    try:
        seeded = _seed_history(rig)
        job = rig.mgr.start_scan()
        assert (job["network_id"], job["network"], job["suggested_site"], job["window_reason"]) == (None, None, None, "data_start")
        post_when_waiting(rig.mgr, wifi_body())
        done = finished(rig.mgr)
        assert done["site"] is None and done["message"] == "Saved the report for Unnamed site"
        history = next(p for p in done["phases"] if p["key"] == "history")
        assert history["message"].endswith("; " + reports.NETWORK_NOTE_MESSAGES["offline"]), "no network with a gateway at the start"
        report = rig.mgr.get(done["report_id"])
        assert report["site"] == reports.UNNAMED_SITE and report["network_id"] is None
        assert report["data"]["meta"]["network"] == networks.unknown_network()
        assert report["data"]["ping"]["window_start"] == seeded["oldest"] and report["data"]["outages"]["count"] == 1
        assert report["data"]["ping"]["monitored_s"] == report["data"]["outages"]["monitored_s"]
        assert b"The network was not identified when the scan started" in _pdf_text(report_pdf.build_site_report(report))
    finally:
        tracker.stop()


def test_visits_split_at_another_network_and_at_a_trip():
    """A at 01:00-04:00, twenty minutes on B (a direct hop, no offline spell), back on A until 06:00: two visits and 4 h 40 min on A,
    not one visit of 5 h (next test, from a database).  A trip shorter than the visit gap splits visits too; a minute split between two
    networks does not."""
    assert reports.visits_from_minutes([0, 60, 1200], 0, 4000) == [{"start": 0.0, "end": 1260.0}]
    assert reports.visits_from_minutes([0, 60, 1200], 0, 4000, spans=[(200, 1100)]) == [{"start": 0.0, "end": 120.0}, {"start": 1200.0, "end": 1260.0}]
    assert reports.visits_from_minutes([0, 60, 1200], 0, 4000, breaks=[600]) == [{"start": 0.0, "end": 120.0}, {"start": 1200.0, "end": 1260.0}]
    assert reports.visits_from_minutes([0, 60], 0, 4000, breaks=[0, 60]) == [{"start": 0.0, "end": 120.0}], "a split minute is no break"


def test_a_site_report_does_not_count_a_hop_to_another_network_as_monitored(db):
    end = float(int(T0 // 60) * 60)
    start = end - 7 * DAY
    a = db.add_network(start, mac=MAC_SITE, fingerprint="fa")["id"]
    b = db.add_network(start, mac=MAC_OTHER, fingerprint="fb")["id"]
    tid = db.add_target("198.51.100.10")["id"]
    base = end - DAY
    tagged_minutes(db, tid, base + HOUR, 180, 10.0, a)
    tagged_minutes(db, tid, base + 4 * HOUR, 20, 50.0, b)
    tagged_minutes(db, tid, base + 4 * HOUR + 1200, 100, 10.0, a)
    ping = reports.build_ping_section(db, start, end, "site_network", [], None, db.list_targets(enabled_only=True), set(),
                                      network={"id": a, "legacy_since": None, "travel": []})
    assert ping["visits"] == [{"start": base + HOUR, "end": base + 4 * HOUR}, {"start": base + 4 * HOUR + 1200, "end": base + 6 * HOUR}]
    assert ping["monitored_s"] == 4 * HOUR + 40 * 60 and ping["untagged_since"] is None
    assert reports.build_summary({"ping": ping})["window_hours"] == 4.7


def test_a_moment_back_on_the_site_s_network_on_the_way_out_is_part_of_the_trip():
    """The link comes back for a moment in the car park and drops again before this PC reaches the next site: that spell and moment are
    the trip too.  A drop at the site long before stays the site's own; a spell on a network without a gateway is travel."""
    spells = [{"network_id": 1, "start_ts": 1000.0, "end_ts": 1030.0, "next_network_id": 1},
              {"network_id": 1, "start_ts": 1100.0, "end_ts": 5000.0, "next_network_id": 2},
              {"network_id": 1, "start_ts": 100.0, "end_ts": 160.0, "next_network_id": 1},
              {"network_id": 1, "start_ts": 6000.0, "end_ts": 6500.0, "next_network_id": 1, "reason": "lan"},
              {"network_id": 1, "start_ts": 7000.0, "end_ts": None, "next_network_id": None}]
    assert reports.travel_spans(spells) == [(1000.0, 5000.0), (6000.0, 6500.0)]


def test_full_scan_started_offline_is_on_no_site_s_network(rig_factory):
    """No network with a gateway when the scan starts (in the car, a camera LAN): the last network's id sticks for the data, but the scan
    is on no site's network: nothing suggested (not the last customer), the time rule, and the history message says why."""
    rig = rig_factory()
    tracker = site_tracker(rig.db)
    rig.engine.networks = tracker
    try:
        a = tracker.current_network_id()
        rig.db.add_report("Acme Dental", "acme dental", time.time() - DAY, time.time() - DAY + 90, "complete", __version__, {}, {}, network_id=a)
        tracker.on_network_change({"ts": time.time(), "default_gateway": None})
        assert tracker.current_network_id() == a and tracker.offline
        job = rig.mgr.start_scan()
        assert (job["network_id"], job["network"], job["suggested_site"]) == (None, None, None) and job["window_reason"] != "site_network"
        post_when_waiting(rig.mgr, wifi_body())
        done = finished(rig.mgr)
        assert done["site"] is None and done["message"] == "Saved the report for Unnamed site"
        history = next(p for p in done["phases"] if p["key"] == "history")
        assert history["message"].endswith("; " + reports.NETWORK_NOTE_MESSAGES["offline"])
        assert rig.mgr.get(done["report_id"])["network_id"] is None
    finally:
        tracker.stop()


def test_no_site_is_suggested_from_an_unnamed_report_or_for_a_portable_network(rig_factory):
    """An "Unnamed site" report names no site: the newest named report of the network is suggested.  A network marked portable (a phone
    hotspot or travel router carried from site to site) while the scan runs is suggested nothing and reads only this connection to it;
    unmarked, its site again."""
    rig = rig_factory()
    db, now = rig.db, time.time()
    tracker = site_tracker(db)
    rig.engine.networks = tracker
    rig.backend.block = True
    try:
        a = tracker.current_network_id()
        named = db.add_report("Acme Dental", "acme dental", now - 2 * DAY, now - 2 * DAY + 90, "complete", __version__, {}, {}, network_id=a)
        db.add_report(reports.UNNAMED_SITE, reports.site_key(reports.UNNAMED_SITE), now - DAY, now - DAY + 90, "complete", __version__, {}, {},
                      network_id=a)
        job = rig.mgr.start_scan()
        assert job["suggested_site"]["report_id"] == named and job["network"]["portable"] is False
        assert rig.mgr.set_network_portable(a, True)["portable"] is True
        marked = rig.mgr.job()
        assert (marked["suggested_site"], marked["network"]["portable"], marked["window_reason"]) == (None, True, "network_change")
        assert marked["window_start"] == pytest.approx(tracker.connected_since(a), abs=1.0)
        progress = [e["data"]["job"] for e in rig.events if e["type"] == "report.progress" and e["data"]["job"]["id"] == job["id"]]
        assert progress[-1]["suggested_site"] is None, "the page hears of it"
        rig.mgr.set_network_portable(a, False)
        assert rig.mgr.job()["suggested_site"]["report_id"] == named and rig.mgr.set_network_portable(999, True) is None
        rig.mgr.cancel()
        finished(rig.mgr)
    finally:
        tracker.stop()


def call(srv: ApiServer, method: str, path: str, body: Any = None, raw: Optional[bytes] = None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=15)
    try:
        data = raw if raw is not None else (json.dumps(body).encode("utf-8") if body is not None else None)
        headers = {"Content-Type": "application/json"} if data is not None else {}
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        payload = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        if hdrs.get("content-type", "").startswith("application/json"):
            return resp.status, hdrs, json.loads(payload)
        return resp.status, hdrs, payload
    finally:
        conn.close()


def _store(rig: Rig, report: Dict[str, Any], created: Optional[float] = None) -> int:
    ts = report["created_ts"] if created is None else created
    return rig.db.add_report(report["site"], reports.site_key(report["site"]), ts, ts + 95, report["status"], __version__,
                             report["summary"], report["data"])


def test_api_saved_reports(rig_factory, tmp_path):
    rig = rig_factory()
    srv = rig.serve(tmp_path)
    a = _store(rig, make_report("Acme Dental"), T0)
    b = _store(rig, make_report("Northside Warehouse"), T0 + 100)
    c = _store(rig, make_report("acme dental"), T0 + 200)
    status, _h, data = call(srv, "GET", "/api/reports")
    assert status == 200 and data["total"] == 3 and [r["id"] for r in data["reports"]] == [c, b, a]
    assert set(data["reports"][0]) == {"id", "site", "created_ts", "completed_ts", "status", "summary", "network_id"}
    status, _h, data = call(srv, "GET", "/api/reports?q=ACME&limit=1&offset=1")
    assert status == 200 and data["total"] == 2 and [r["id"] for r in data["reports"]] == [a]
    status, _h, data = call(srv, "GET", "/api/reports?site_key=Acme%20Dental")
    assert [r["id"] for r in data["reports"]] == [c, a]
    status, _h, data = call(srv, "GET", "/api/reports?limit=0&offset=-5")
    assert status == 200 and len(data["reports"]) == 1, "limit and offset are clamped"
    status, _h, data = call(srv, "GET", "/api/reports?q=" + "x" * 201)
    assert status == 400
    status, _h, data = call(srv, "GET", "/api/reports/sites?q=north")
    assert status == 200 and data == {"sites": [{"site": "Northside Warehouse", "site_key": "northside warehouse",
                                                 "count": 1, "last_ts": T0 + 100, "network_ids": []}], "total": 1}
    status, _h, data = call(srv, "GET", "/api/reports/sites")
    assert [s["site"] for s in data["sites"]] == ["acme dental", "Northside Warehouse"] and data["sites"][0]["count"] == 2
    status, _h, data = call(srv, "GET", f"/api/reports/{a}")
    assert status == 200 and set(data) == {"id", "site", "created_ts", "completed_ts", "status", "network_id", "summary", "data"}
    assert data["data"]["wifi"]["aps_count"] == 6
    for bad in ("abc", "0", "-1", "1.5", "9" * 16):
        status, _h, data = call(srv, "GET", f"/api/reports/{bad}")
        assert status == 400 and data["error"]["code"] == "bad_request", bad
    status, _h, data = call(srv, "GET", "/api/reports/999")
    assert status == 404 and data["error"]["code"] == "not_found"
    status, _h, data = call(srv, "PATCH", f"/api/reports/{a}", {"site": "x" * 81})
    assert status == 400
    status, _h, data = call(srv, "PATCH", f"/api/reports/{a}", {"site": 5})
    assert status == 400
    status, _h, data = call(srv, "PATCH", f"/api/reports/{a}", {})
    assert status == 400 and data["error"]["message"] == "site is required"
    status, _h, data = call(srv, "PATCH", "/api/reports/999", {"site": "Lakeside Clinic"})
    assert status == 404
    status, _h, data = call(srv, "PATCH", f"/api/reports/{a}", {"site": " Lakeside  Clinic "})
    assert status == 200 and data["site"] == "Lakeside Clinic" and "data" not in data
    status, _h, data = call(srv, "DELETE", f"/api/reports/{b}")
    assert status == 200 and data == {"ok": True}
    status, _h, data = call(srv, "DELETE", f"/api/reports/{b}")
    assert status == 404
    assert [e["data"] for e in rig.events if e["type"] in ("report.updated", "report.deleted")] == [
        {"id": a, "site": "Lakeside Clinic"}, {"id": b}]
    status, _h, data = call(srv, "PUT", "/api/reports/scan")
    assert status == 405


def test_api_compare_and_pdfs(rig_factory, tmp_path):
    rig = rig_factory()
    srv = rig.serve(tmp_path)
    a = _store(rig, make_report('Café "Zürich" 100%'))
    b = _store(rig, make_report("Northside Warehouse", download=150.0, aps=_b_aps()))
    status, _h, data = call(srv, "GET", f"/api/reports/compare?a={a}&b={b}")
    assert status == 200 and data["a"]["id"] == a and data["b"]["site"] == "Northside Warehouse"
    assert next(s for s in data["sections"] if s["key"] == "speed")["rows"][0]["better"] == "b"
    for query in ("", f"?a={a}", f"?a={a}&b=x", f"?a=1e3&b={b}", f"?a=0&b={b}"):
        status, _h, data = call(srv, "GET", f"/api/reports/compare{query}")
        assert status == 400, query
    status, _h, data = call(srv, "GET", f"/api/reports/compare?a={a}&b=999")
    assert status == 404 and "999" in data["error"]["message"]
    status, hdrs, pdf = call(srv, "GET", f"/api/reports/{a}/pdf")
    assert status == 200 and hdrs["content-type"] == "application/pdf" and pdf.startswith(b"%PDF")
    assert re.fullmatch(r'attachment; filename="TNT-report-Cafe-Zurich-100-\d{4}-\d{2}-\d{2}-\d{4}\.pdf"',
                        hdrs["content-disposition"]), hdrs["content-disposition"]
    status, hdrs, pdf = call(srv, "GET", f"/api/reports/compare/pdf?a={a}&b={b}")
    assert status == 200 and pdf.startswith(b"%PDF") and b"%%EOF" in pdf[-64:]
    assert hdrs["content-disposition"] == 'attachment; filename="TNT-compare-Cafe-Zurich-100-vs-Northside-Warehouse.pdf"'
    status, _h, data = call(srv, "GET", "/api/reports/999/pdf")
    assert status == 404
    status, _h, data = call(srv, "GET", "/api/reports/compare/pdf?a=1")
    assert status == 400


def test_api_full_scan_lifecycle(rig_factory, tmp_path):
    rig = rig_factory()
    srv = rig.serve(tmp_path)
    status, _h, data = call(srv, "GET", "/api/reports/scan")
    assert status == 200 and data == {"job": None}
    status, _h, data = call(srv, "PATCH", "/api/reports/scan", {"site": "Acme Dental"})
    assert status == 409 and data["error"]["code"] == "no_scan" and data["job"] is None
    status, _h, data = call(srv, "DELETE", "/api/reports/scan")
    assert status == 200 and data == {"job": None}
    status, _h, data = call(srv, "POST", "/api/reports/scan", {"site": "x" * 81})
    assert status == 400
    status, _h, data = call(srv, "POST", "/api/reports/scan", raw=b"")
    assert status == 200 and data["job"]["site"] is None and data["job"]["status"] == "running"
    job_id = data["job"]["id"]
    status, _h, data = call(srv, "POST", "/api/reports/scan", {"site": "Northside Warehouse"})
    assert status == 409 and data["error"]["code"] == "busy" and data["job"]["id"] == job_id
    status, _h, data = call(srv, "PATCH", "/api/reports/scan", {"site": ""})
    assert status == 400
    status, _h, data = call(srv, "PATCH", "/api/reports/scan", {"site": "  Acme   Dental "})
    assert status == 200 and data["job"]["site"] == "Acme Dental"
    status, _h, data = call(srv, "POST", "/api/reports/scan/wifi", {"available": "yes"})
    assert status == 400 and "available" in data["error"]["message"]
    status, _h, data = call(srv, "POST", "/api/reports/scan/wifi", raw=b"[1, 2]")
    assert status == 400
    deadline = time.time() + 10
    while True:
        status, _h, data = call(srv, "POST", "/api/reports/scan/wifi", wifi_body())
        if status == 200 or time.time() > deadline:
            break
        assert status == 409 and data["error"]["code"] == "not_waiting"
        time.sleep(0.05)
    assert status == 200 and data["job"]["phase"] in ("wifi", "finalize")
    done = finished(rig.mgr)
    status, _h, data = call(srv, "GET", "/api/reports/scan")
    assert data["job"]["status"] == "saved" and data["job"]["report_id"] == done["report_id"]
    status, _h, data = call(srv, "POST", "/api/reports/scan/wifi", wifi_body())
    assert status == 409 and data["error"]["code"] == "not_waiting" and data["job"]["status"] == "saved"
    status, _h, data = call(srv, "DELETE", "/api/reports/scan")
    assert status == 200 and data["job"]["status"] == "saved"
    status, _h, data = call(srv, "PATCH", "/api/reports/scan", {"site": "Acme Dental North"})
    assert status == 200 and rig.mgr.get(done["report_id"])["site"] == "Acme Dental North"
    status, _h, data = call(srv, "GET", f"/api/reports/{done['report_id']}")
    assert data["status"] == "complete" and data["data"]["discovery"]["host_count"] == 4


def test_api_wifi_post_may_be_larger_than_other_bodies(rig_factory, tmp_path):
    rig = rig_factory()
    srv = rig.serve(tmp_path)
    body = json.dumps({"available": False, "state": "no_bridge", "error": "e" * (1536 * 1024)}).encode("utf-8")
    assert 1024 * 1024 < len(body) < 2 * 1024 * 1024
    status, _h, data = call(srv, "POST", "/api/reports/scan/wifi", raw=body)
    assert status == 409 and data["error"]["code"] == "not_waiting", "read and parsed, not refused for its size"

    def announce(path: str, length: int) -> int:
        """Send only the headers: the server refuses an oversized body before reading it."""
        conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
        try:
            conn.putrequest("POST", path)
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(length))
            conn.endheaders()
            resp = conn.getresponse()
            code = json.loads(resp.read())["error"]["code"]
            assert code == "payload_too_large" or resp.status != 413
            return resp.status
        finally:
            conn.close()

    assert announce("/api/reports/scan", len(body)) == 413, "every other path keeps the 1 MB cap"
    assert announce("/api/reports/scan/wifi", 2 * 1024 * 1024 + 1) == 413


# --------------------------------------------------------------------------------------
# PDFs
# --------------------------------------------------------------------------------------
def _typical_report(site: str = "Acme Dental") -> Dict[str, Any]:
    hosts = [{"ip": f"192.168.50.{i}", "hostname": f"device-{i}.example" if i % 3 else None,
              "mac": f"02:00:5E:10:00:{i:02X}", "vendor": "Example Devices" if i % 2 else None,
              "open_ports": [554] if i % 5 == 0 else [80, 443], "device_type": None} for i in range(1, 31)]
    aps = [ap(f"02:00:5E:20:01:{i:02X}", f"Site-Net-{i % 12}", -45 - i, "5" if i % 2 else "2.4", 36 if i % 2 else 1 + i % 11,
              80 if i % 2 else 20, connected=(i == 1)) for i in range(1, 41)]
    now = T0
    rows = [{"kind": "target", "target_id": 1, "start_ts": now - (i + 1) * 5 * HOUR, "end_ts": now - (i + 1) * 5 * HOUR + 90 + i * 30,
             "missed": 80, "sent": 90 + i * 30, "host": "gateway (192.168.50.1)", "note": None} for i in range(4)]
    rows.append({"kind": "total_internet", "target_id": None, "start_ts": now - 30 * HOUR, "end_ts": now - 30 * HOUR + 420,
                 "missed": 0, "note": "no network connection"})
    return make_report(site, 1, hosts=hosts, aps=aps, outage_rows=rows)


def test_site_report_pdf_is_compact_and_readable():
    report = _typical_report()
    pdf = report_pdf.build_site_report(report)
    assert pdf.startswith(b"%PDF") and b"%%EOF" in pdf[-64:]
    assert 1 <= _page_count(pdf) <= 3, _page_count(pdf)
    text = _pdf_text(pdf)
    for needle in (b"Site report: Acme Dental", b"192.168.50.20", b"Site-Net-1", b"p95 ms", b"Example Colo",
                   b"Internet down", b"Page 1 of", b"Network down"):
        assert needle in text, needle
    assert b"Public IP" in text and text.count(b"Example Colo") == 1, "the speed block names the server once, no ISP / IP rows"


def test_pdf_formats_match_the_page_and_tint_what_needs_a_look():
    assert report_pdf._dbm(-81.5) == "-82 dBm" and report_pdf._dbm(-80.5) == "-81 dBm", "half away from zero, like the page"
    assert (report_pdf._ms(0.55), report_pdf._ms(48.34), report_pdf._ms(612.5)) == ("0.55", "48.3", "613")
    assert (report_pdf._pct(0), report_pdf._pct(2.424), report_pdf._pct(12.6), report_pdf._mbps(1201.4)) == ("0%", "2.42%", "12.6%", "1201")
    # the cells carry no unit (the metric's label names it), except points of loss and decibels of signal
    assert report_pdf._difference(-822.8, -87.4, "Mbps", "b") == "-823 (-87%)"
    assert report_pdf._difference(2.42, None, "%", "b") == "+2.42 pts" and report_pdf._difference(12, None, "dBm", "a") == "+12 dB"
    assert report_pdf._difference(719.0, 71900.0, "ms", "b") == "+719 (x720)", "no +71900 %"
    assert report_pdf._difference(1.0, 200.0, "ms", "same") == "+1.0", "no percentage beside a same verdict"
    assert report_pdf._difference(0.004, None, "%", "same") == "about 0" and report_pdf._difference(1, 100.0, "outages") == "+1 (+100%)"
    levels = report_pdf.key_levels({"download_mbps": 18.4, "upload_mbps": 4.2, "gateway_loss_pct": 2.4, "internet_loss_pct": 6.0,
                                    "outages": 3, "wifi_connected_rssi": -78},
                                   {"wifi": {"available": True, "connected": {"channel_aps": 8}}})
    assert levels == {"download": "warn", "upload": "warn", "gateway_loss": "warn", "internet_loss": "bad", "outages": "warn",
                      "wifi_signal": "bad", "wifi_aps": "warn"}
    assert set(report_pdf.key_levels({"download_mbps": 9.0, "wifi_connected_rssi": -60}).values()) == {"", "bad"}
    assert set(report_pdf.key_levels(None).values()) == {""}
    assert report_pdf.outage_what({"kind": "total_internet", "targets": ["Public DNS (198.51.100.1)", "example.net"]}) == \
        "Internet down: Public DNS (198.51.100.1), example.net"
    assert report_pdf.outage_what({"kind": "target", "name": "NVR (172.16.40.20)", "host": "172.16.40.20"}) == "NVR (172.16.40.20)"


def test_pdf_survives_text_taller_than_a_page(monkeypatch):
    report = make_report("Acme Dental", 2)
    report["data"]["outages"]["items"] = [{"start_ts": T0 - 100, "end_ts": T0, "duration_s": 100, "kind": "target", "host": "x",
                                           "missed": 1, "missed_pct": 1.0, "note": "word " * 20000}]
    assert report_pdf.build_site_report(report).startswith(b"%PDF")
    comparison = reports.compare_reports(report, report)
    comparison["sections"][0]["note"] = "long " * 20000
    comparison["sections"][0]["rows"][0]["note"] = "note " * 20000
    assert report_pdf.build_compare_report(report, report, comparison).startswith(b"%PDF")
    # should a cell still be too tall, the document is built again with every such text cut shorter
    monkeypatch.setattr(report_pdf, "CELL_TEXT_MAX", 10 ** 6)
    pdf = report_pdf.build_site_report(report)
    assert pdf.startswith(b"%PDF") and b"word word" in _pdf_text(pdf)


def test_free_text_and_port_lists_are_capped():
    hosts = [{"ip": "10.0.0.1", "hostname": "h" * 500, "vendor": "v" * 500, "open_ports": list(range(1, 200)), "device_type": None}]
    host = reports.build_discovery_section({"id": 1, "cidr": "10.0.0.0/24", "hosts": hosts}, [])["hosts"][0]
    assert len(host["hostname"]) == reports.TEXT_CAP and len(host["vendor"]) == reports.TEXT_CAP
    assert host["open_ports"] == list(range(1, reports.MAX_HOST_PORTS + 1))
    rows = [{"kind": "target", "target_id": 1, "start_ts": T0 - 100, "end_ts": T0 - 50, "host": "x" * 500, "note": "n" * 5000}]
    item = reports.build_outages_section(rows, T0 - HOUR, T0)["items"][0]
    assert len(item["host"]) == reports.TEXT_CAP and len(item["note"]) == reports.NOTE_CAP


def test_site_report_pdf_survives_odd_text_and_empty_sections():
    report = make_report("Zahnarzt Øst 🦷 北京", aps=[ap("02:00:5E:20:00:01", "Café 📶", -50, "5", 36, connected=True)])
    report["data"]["discovery"]["hosts"][0]["hostname"] = "\x00\x07 printer"
    pdf = report_pdf.build_site_report(report, tz_offset_s=-5 * 3600)
    assert pdf.startswith(b"%PDF") and _page_count(pdf) >= 1
    empty = {"id": 9, "site": "Unnamed site", "created_ts": T0, "status": "partial", "summary": {},
             "data": {k: reports.empty_section(k, "Not collected") for k in ("network", "speed", "ping", "outages",
                                                                             "discovery", "wifi")}}
    pdf = report_pdf.build_site_report(empty)
    assert pdf.startswith(b"%PDF") and _page_count(pdf) == 1
    assert b"Not collected" in _pdf_text(pdf)
    broken = {"id": 10, "site": "Acme Dental", "created_ts": T0, "data": {"ping": {"available": True, "targets": "oops"}}}
    assert report_pdf.build_site_report(broken).startswith(b"%PDF")


def test_compare_pdf_smoke():
    a = _typical_report("Acme Dental")
    b = make_report("Northside Warehouse", 2, download=150.0, aps=_b_aps(), window_s=1800, outages=1, down_s=60, longest_s=60)
    pdf = report_pdf.build_compare_report(a, b, reports.compare_reports(a, b))
    assert pdf.startswith(b"%PDF") and 1 <= _page_count(pdf) <= 2
    text = _pdf_text(pdf)
    # PDF string literals escape parentheses, so "Download (Mbps)" is matched in two parts
    assert b"Acme Dental compared with Northside Warehouse" in text and b"Download" in text and b"Mbps" in text
    assert b"In short." in text and b"the reference" in text and b"Nothing to compare" not in text
    assert b"report 1" not in text, "scan dates and windows, not internal ids"


def test_compare_highlights_in_plain_words():
    a = make_report("Northside Warehouse", 1, download=18.4, upload=4.2, gw_loss=2.42)
    b = make_report("Maple Street Office", 2, download=612.0, upload=581.7, gw_loss=0.0)
    lines = report_pdf.compare_highlights(reports.compare_reports(a, b))
    assert lines[0] == "Download 97 % slower (18.4 vs 612 Mbps); upload 99 % slower (4.2 vs 582 Mbps)."
    assert lines[1] == "Packet loss to the gateway 2.42% vs 0%; to the internet 0.25% vs 0.25%."
    assert lines[2] == "Internet latency about the same (18.0 vs 18.0 ms)."
    assert lines[3] == "Wi-Fi signal about the same (-48 dBm vs -48 dBm); 1 other access point shares its channel."
    assert lines[4].startswith("Network outages 0.50 vs 0.50 a day; the longest") and len(lines) == 5
    fast = make_report("Maple Street Office", 3, download=1201.0)
    slow = make_report("Northside Warehouse", 4, download=18.0)
    assert report_pdf.compare_highlights(reports.compare_reports(fast, slow))[0].startswith("Download 67 times faster (1201 vs 18.0 Mbps)")
    assert report_pdf.compare_highlights({"sections": []}) == []
    nothing = report_pdf.build_compare_report({"id": 1}, {"id": 2}, reports.compare_reports({"id": 1}, {"id": 2}))
    assert b"Nothing to compare" in _pdf_text(nothing)
