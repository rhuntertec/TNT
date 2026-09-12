"""Tests for tnt.api (router, server, routes, SSE), tnt.engine, tnt.diagnostics and tnt.service.

Everything runs against a FakeEngine whose sub-components return contract-shaped
dicts; the HTTP server is started on port 0 (never 7130).  No network access.
"""
from __future__ import annotations

import http.client
import json
import logging
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from tnt import SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME, __version__
from tnt import config as tnt_config
from tnt import db as tnt_db
from tnt import events as tnt_events
from tnt.api import routes as api_routes
from tnt.api import server as api_server
from tnt.api.routes import ApiError, Request, Router
from tnt.api.server import ApiServer, is_loopback, preflight_port
from tnt.api.sse import SseHub

T0 = 1_700_000_000.0


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------
def _view(tid: int, host: str, kind: str = "internet", light: str = "green") -> Dict[str, Any]:
    win = {"seconds": 60, "sent": 60, "received": 60, "lost": 0, "loss_pct": 0.0,
           "avg_ms": 20.3, "min_ms": 19.0, "max_ms": 24.0, "jitter_ms": 0.8}
    day = {"sent": 86400, "received": 86390, "lost": 10, "loss_pct": 0.01, "avg_ms": 20.1, "min_ms": 18.0, "max_ms": 91.0}
    return {"id": tid, "host": host, "label": None, "kind": kind, "ip": host, "enabled": True,
            "resolved": True, "resolve_error": None, "light": light, "in_outage": False,
            "last": {"ts": T0, "ok": True, "rtt_ms": 20.0}, "consecutive_missed": 0, "consecutive_ok": 412,
            "window": win, "day": day, "since_ts": T0}


class FakePing:
    def __init__(self) -> None:
        self.views: Dict[int, Dict[str, Any]] = {}
        self._next = 1
        self.paused = False

    def targets(self) -> List[Dict[str, Any]]:
        return [dict(v) for v in self.views.values()]

    def target(self, tid: int) -> Optional[Dict[str, Any]]:
        v = self.views.get(tid)
        return dict(v) if v else None

    def add_target(self, host: str, label: Optional[str] = None) -> Dict[str, Any]:
        if not host or " " in host:
            raise ValueError(f"invalid host {host!r}")
        for v in self.views.values():
            if v["host"].lower() == host.lower():
                return dict(v)
        tid = self._next
        self._next += 1
        v = _view(tid, host, light="grey" if self.paused else "green")
        v["label"] = label
        self.views[tid] = v
        return dict(v)

    def remove_target(self, tid: int) -> bool:
        return self.views.pop(tid, None) is not None

    def load_defaults(self) -> List[Dict[str, Any]]:
        self.add_target("10.0.0.251")
        self.add_target("1.1.1.1")
        return self.targets()

    def samples(self, tid: int, seconds: int = 300) -> List[Any]:
        return [SimpleNamespace(ts=T0 + i, ok=True, rtt_ms=20.0 + i) for i in range(3)]

    def stats(self, tid: int, seconds: int) -> Dict[str, Any]:
        return {"sent": 3, "received": 3, "lost": 0, "loss_pct": 0.0, "avg_ms": 21.0, "min_ms": 20.0,
                "max_ms": 22.0, "jitter_ms": 1.0, "last_rtt_ms": 22.0}

    def light(self, tid: int) -> str:
        return self.views[tid]["light"]

    def set_paused(self, paused: bool) -> None:
        self.paused = bool(paused)
        for v in self.views.values():
            v["light"] = "grey" if self.paused else "green"

    def add_sample_listener(self, fn: Any) -> Any:
        return lambda: None


class FakeOutages:
    def status(self) -> Dict[str, Any]:
        return {"active": [], "total_active": None, "count_24h": 0, "last": None, "monitoring": True}

    def list(self, start_ts: float, end_ts: float) -> List[Dict[str, Any]]:  # noqa: A003
        return []

    def timeline(self, hours: float = 24, now: Optional[float] = None) -> Dict[str, Any]:
        now = now or time.time()
        return {"start_ts": now - hours * 3600, "end_ts": now, "hours": hours,
                "segments": [], "total_segments": [], "gaps": [], "targets": []}

    def on_target_removed(self, target_id: int) -> None:
        pass


class FakeSpeed:
    def __init__(self) -> None:
        self.running = False

    def status(self) -> Dict[str, Any]:
        return {"enabled": True, "running": self.running, "next_run_ts": T0 + 900, "last": None,
                "backend": "cloudflare", "interval_min": 15, "progress": {}}

    def history(self, start_ts: float, end_ts: float, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        return []

    def run_now(self) -> bool:
        if self.running:
            return False
        self.running = True
        return True

    def patterns(self, days: int = 7, now: Optional[float] = None) -> Dict[str, Any]:
        return {"days": days, "count": 0, "ok_count": 0, "median_down": None, "median_up": None,
                "by_hour": [], "by_weekday": [], "slow_tests": [], "findings": [], "trend_down_pct_per_day": None}

    def stop(self) -> None:
        pass


class FakeDiscovery:
    """Scripted scanner: ``block=True`` makes scan() wait for cancel."""

    def __init__(self, block: bool = False) -> None:
        self.block = block
        self.running = False
        self.progress = None
        self.last_run_ts = None
        self.stopped = False

    def default_cidr(self) -> str:
        return "10.0.0.0/24"

    def parse_range(self, text: str) -> str:
        if "bad" in text:
            raise ValueError(f"bad range {text!r}")
        return text

    def stop(self) -> None:
        self.stopped = True

    def scan(self, range_text: str, ports: Optional[List[int]] = None, progress: Any = None, cancel: Any = None) -> Any:
        self.running = True
        if progress:
            progress({"phase": "ping", "done": 1, "total": 4, "found": 1, "elapsed_s": 0.01})
        if self.block and cancel is not None:
            cancel.wait(5.0)
        cancelled = bool(cancel is not None and cancel.is_set())
        self.running = False
        result = {"ts": time.time(), "cidr": range_text, "ports": list(ports or []), "method": "native",
                  "hosts": [] if cancelled else [{"ip": "10.0.0.1", "hostname": "gw", "mac": "AA:BB:CC:DD:EE:FF",
                                                  "vendor": "ACME", "ping_ok": True, "rtt_ms": 1.0, "open_ports": [80]}],
                  "scanned": 4, "duration_s": 0.01, "ok": True, "error": None, "cancelled": cancelled}
        result["found"] = len(result["hosts"])
        return SimpleNamespace(to_dict=lambda: dict(result))


DHCP_SERVER = {"adapter": "Ethernet", "nic_ip": "10.0.0.112", "server_ip": "10.0.0.251", "source_ip": "10.0.0.251",
               "offered_ip": "10.0.0.191", "lease_s": 86400, "router": "10.0.0.251", "mask": "255.255.255.0",
               "dns": ["10.0.0.251"], "known": True, "answered": True}
DHCP_LEASE = {"ip": "172.16.4.101", "mac": "AA:BB:CC:DD:EE:01", "hostname": "cam-12", "vendor": "Hikvision",
              "ping_ok": True, "rtt_ms": 1.2, "open_ports": [80, 554], "client_id": "01aabbccddee01", "state": "bound",
              "first_ts": T0, "last_ts": T0, "expires_ts": T0 + 3600, "probed_ts": T0, "probing": False}


class DhcpConflictLike(RuntimeError):
    """Shaped like tnt.dhcp.DhcpConflict (the routes match by attribute, not by class)."""

    def __init__(self, servers: List[Dict[str, Any]], scan: Dict[str, Any]) -> None:
        super().__init__("another DHCP server is active")
        self.servers = servers
        self.scan = scan


class FakeDhcp:
    """Contract-shaped DHCP server tool: status/summary/leases/scan/start/stop/settings/forget."""

    def __init__(self) -> None:
        self.running = False
        self.since_ts: Optional[float] = None
        self.error: Optional[str] = None
        self.other_servers: List[Dict[str, Any]] = [dict(DHCP_SERVER)]
        self.leases_by_mac: Dict[str, Dict[str, Any]] = {}
        self.settings = {"adapter": "", "pool_start": "", "pool_end": "", "pool_size": 5, "lease_s": 3600,
                         "static_ip": "172.16.4.100", "static_prefix": 24, "ping_check": True, "scan_wait_s": 8}
        self.last_scan: Optional[Dict[str, Any]] = None
        self.calls: List[Any] = []
        self.fail_with: Optional[BaseException] = None

    def _pool(self) -> Dict[str, Any]:
        auto = not (self.settings["pool_start"] and self.settings["pool_end"])
        return {"start": self.settings["pool_start"] or "172.16.4.101", "end": self.settings["pool_end"] or "172.16.4.105",
                "size": int(self.settings["pool_size"]), "auto": auto}

    def scan(self, wait_s: Optional[float] = None) -> Dict[str, Any]:
        self.calls.append(("scan", wait_s))
        self.last_scan = {"ts": T0, "duration_s": 0.01, "wait_s": wait_s or self.settings["scan_wait_s"],
                          "servers": [dict(s) for s in self.other_servers],
                          "probed": [{"adapter": "Ethernet", "ip": "10.0.0.112"}], "errors": []}
        return dict(self.last_scan)

    def start(self, force: bool = False) -> Dict[str, Any]:
        self.calls.append(("start", force))
        if self.fail_with is not None:
            raise self.fail_with
        if not force:
            scan = self.scan()
            if scan["servers"]:
                raise DhcpConflictLike(scan["servers"], scan)
        self.running = True
        self.since_ts = T0
        return self.status()

    def stop(self, restore_nic: bool = True) -> Dict[str, Any]:
        self.calls.append(("stop", restore_nic))
        self.running = False
        self.since_ts = None
        return self.status()

    def leases(self) -> List[Dict[str, Any]]:
        return [dict(v) for v in self.leases_by_mac.values()]

    def forget_lease(self, mac: str) -> bool:
        self.calls.append(("forget", mac))
        return self.leases_by_mac.pop(mac, None) is not None

    def update_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append(("settings", dict(patch)))
        if "lease_s" in patch and not 120 <= int(patch["lease_s"]) <= 604800:
            raise ValueError("lease_s must be between 120 and 604800 seconds")
        if patch.get("pool_start") == "300.1.1.1":
            raise ValueError("pool_start is not an IPv4 address")
        self.settings.update(patch)
        return self.status()

    def summary(self) -> Dict[str, Any]:
        bound = sum(1 for v in self.leases_by_mac.values() if v["state"] == "bound")
        offered = sum(1 for v in self.leases_by_mac.values() if v["state"] == "offered")
        return {"available": True, "running": self.running, "adapter": "Ethernet",
                "server_ip": "172.16.4.100" if self.running else None,
                "pool": {k: self._pool()[k] for k in ("start", "end", "size")},
                "bound": bound, "offered": offered, "since_ts": self.since_ts, "error": self.error}

    def status(self) -> Dict[str, Any]:
        s = self.summary()
        return {
            "available": True, "running": self.running, "since_ts": self.since_ts, "error": self.error, "warning": None,
            "adapter": {"name": "Ethernet", "index": 12, "mac": "00:00:5E:00:53:10", "ip": "10.0.0.112", "prefix": 24,
                        "mask": "255.255.255.0", "dhcp_enabled": True, "gateway": "10.0.0.251", "is_physical": True,
                        "type_name": "Ethernet", "is_internet": True, "will_change": True, "changed": self.running,
                        "static_ip": "172.16.4.100", "static_prefix": 24},
            "adapters": [{"name": "Ethernet", "index": 12, "ip": "10.0.0.112", "prefix": 24, "dhcp_enabled": True,
                          "is_physical": True, "type_name": "Ethernet", "is_internet": True, "status": "up"}],
            "server_ip": "172.16.4.100", "pool": self._pool(), "lease_s": int(self.settings["lease_s"]),
            "gateway": "172.16.4.100", "dns": [], "ping_check": bool(self.settings["ping_check"]),
            "clients": self.leases(), "counts": {"bound": s["bound"], "offered": s["offered"], "total": len(self.leases_by_mac)},
            "scan": dict(self.last_scan) if self.last_scan else None,
            "firewall": {"rule": "TNT DHCP server (UDP 67 in)", "ok": None, "error": None},
            "settings": dict(self.settings),
        }


LAN_PEER = {"id": "6f1c0d2e9a4b", "hostname": "DESK-02", "ip": "10.0.0.42", "version": __version__,
            "last_seen_ts": T0, "age_s": 1.5, "adapter": "Ethernet"}
LAN_RESULT = {"ts": T0, "peer": {"ip": "10.0.0.42", "hostname": "DESK-02"}, "seconds": 5, "upload_mbps": 941.2,
              "download_mbps": 938.7, "latency_ms": 0.4, "duration_s": 10.4, "error": None}


class FakeLan:
    """Contract-shaped LAN peer discovery + throughput tool (tnt.lanpeers.LanPeers)."""

    def __init__(self) -> None:
        self.listening = True
        self.error: Optional[str] = None
        self.enabled = True
        self.peers: List[Dict[str, Any]] = [dict(LAN_PEER)]
        self.throughput_running = False
        self.calls: List[Any] = []
        self.fail_with: Optional[BaseException] = None
        self._last: Optional[Dict[str, Any]] = None

    def peers_view(self) -> Dict[str, Any]:
        self.calls.append(("peers",))
        return {"self": {"id": "0a1b2c3d4e5f", "hostname": "DESK-01", "ip": "10.0.0.112", "version": __version__, "port": 7133},
                "peers": [dict(p) for p in self.peers], "listening": self.listening, "error": self.error,
                "enabled": self.enabled}

    def set_enabled(self, on: Any) -> Dict[str, Any]:
        """Like LanPeers.set_enabled: coerce, persist, start/stop, return the peers view."""
        self.calls.append(("set_enabled", on))
        if self.fail_with is not None:
            raise self.fail_with
        self.enabled = bool(on)
        self.listening = self.enabled
        self.error = None if self.enabled else "disabled"
        self.peers = [dict(LAN_PEER)] if self.enabled else []
        return self.peers_view()

    def run_throughput(self, peer_ip: str, seconds: int = 5) -> Dict[str, Any]:
        self.calls.append(("throughput", peer_ip, seconds))
        if self.fail_with is not None:
            raise self.fail_with
        if self.throughput_running:
            raise RuntimeError("a throughput test is already running")
        if not any(p["ip"] == peer_ip for p in self.peers):
            raise ValueError(f"{peer_ip} is not a known peer")
        self._last = dict(LAN_RESULT, peer={"ip": peer_ip, "hostname": "DESK-02"}, seconds=seconds)
        return dict(self._last)

    def last_throughput(self) -> Optional[Dict[str, Any]]:
        return dict(self._last) if self._last else None


def _trace_dict(host: str, **kw: Any) -> Dict[str, Any]:
    """A contract-shaped tnt.traceroute result (TRACE / HOP dicts)."""
    gw = {"ttl": 1, "ip": "10.0.0.251", "alt_ips": [], "hostname": "router.lan", "rtts": [0.8, 0.9, 1.0], "avg_ms": 0.9,
          "min_ms": 0.8, "max_ms": 1.0, "loss": 0, "responder_status": 11013, "kind": "gateway", "label": "Gateway",
          "location": None}
    dst = dict(gw, ttl=2, ip="198.51.100.7", hostname=None, rtts=[20.0, None, 21.0], avg_ms=20.5, min_ms=20.0, max_ms=21.0,
               loss=1, responder_status=0, kind="destination", label="Destination")
    return {"host": host, "target_ip": "198.51.100.7", "ts": T0, "duration_s": 0.4, "max_hops": kw.get("max_hops", 30),
            "probes": kw.get("probes", 3), "timeout_ms": kw.get("timeout_ms", 1500), "complete": True, "error": None,
            "pc": {"ip": "10.0.0.112", "hostname": "DESK-01"}, "gateway": "10.0.0.251", "hops": [gw, dst]}


class FakeTracer:
    """Stand-in for tnt.traceroute.Tracer (trace / last / running)."""

    def __init__(self) -> None:
        self.running = False
        self.last: Optional[Dict[str, Any]] = None
        self.calls: List[Any] = []
        self.fail_with: Optional[BaseException] = None

    def trace(self, host: str, **kw: Any) -> Dict[str, Any]:
        self.calls.append((host, dict(kw)))
        if self.fail_with is not None:
            raise self.fail_with
        if self.running:
            raise RuntimeError("a traceroute is already running")
        self.last = _trace_dict(host, **kw)
        return dict(self.last)


GEO = {"ip": "203.0.113.9", "place": "Anytown, TX", "place_full": "Anytown, Texas, United States", "city": "Anytown",
       "region": "Texas", "region_code": "TX", "country": "United States", "country_code": "US", "lat": 32.95,
       "lon": -96.73, "asn": 64500, "as_org": "Example Broadband", "isp": "Example Broadband", "month": "2026-09"}


class FakeGeoIp:
    """Stand-in for tnt.geoip.GeoIpManager; set as ``engine.geoip`` inside the IP location tests only."""

    def __init__(self, enabled: bool = True, location: Optional[Dict[str, Any]] = None) -> None:
        self.enabled = enabled
        self.location = location
        self.fail = False
        self.lookups: List[str] = []
        self.hop_calls: List[Any] = []
        self.checks = 0

    def status(self) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "state": "disabled", "available": False, "month": None, "bytes": None,
                    "installed_ts": None, "checked_ts": None, "next_check_ts": None, "download": None, "error": None}
        return {"enabled": True, "state": "ready", "available": True, "month": "2026-09", "bytes": 1234,
                "installed_ts": T0, "checked_ts": T0, "next_check_ts": T0 + 3600, "download": None, "error": None}

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        self.lookups.append(ip)
        if self.fail:
            raise RuntimeError("lookup failed")
        if not self.enabled or ip == "10.0.0.1":
            return None
        return dict(GEO, ip=ip)

    def files(self) -> List[Dict[str, Any]]:
        return [{"name": "dbip-city-lite-2026-09.mmdb", "bytes": 1000}, {"name": "dbip-asn-lite-2026-09.mmdb", "bytes": 234}]

    def origin(self) -> Optional[Any]:
        return (32.95, -96.73)

    def check_now(self) -> bool:
        self.checks += 1
        return self.enabled

    def locate_hop(self, ip: Any, hostname: Optional[str] = None, min_ms: Optional[float] = None, origin: Any = None,
                   kind: Optional[str] = None) -> Optional[Dict[str, Any]]:
        self.hop_calls.append((ip, hostname, min_ms, origin, kind))
        return dict(self.location) if self.location else None


class FakeEngine:
    def __init__(self, config: Any, db: Any, bus: Any) -> None:
        self.version = __version__
        self.started_ts = time.time() - 5
        self.console = True
        self.config = config
        self.db = db
        self.bus = bus
        self.pinger = None
        self.ping = FakePing()
        self.outages = FakeOutages()
        self.speed = FakeSpeed()
        self.discovery = FakeDiscovery()
        self.dhcp = FakeDhcp()
        self.lan = FakeLan()
        # no ``tracer`` attribute: like the real Engine, the traceroute route creates it lazily
        self.api = None
        self.errors: Dict[str, str] = {}
        self._disc_running = False
        self._disc_range: Optional[str] = None
        self._disc_ports: List[int] = []

    def overall_light(self) -> str:
        if self.ping is None:
            return "grey"
        rank = {"grey": 0, "green": 1, "yellow": 2, "red": 3}
        worst = max((rank[v["light"]] for v in self.ping.views.values()), default=0)
        return {v: k for k, v in rank.items()}[worst]

    def discovery_start(self, range_text: Optional[str], ports: Optional[List[int]]) -> bool:
        if self._disc_running:
            return False
        rt = range_text or self.discovery.default_cidr()
        self.discovery.parse_range(rt)
        self._disc_running = True
        self._disc_range = rt
        self._disc_ports = list(ports or self.config.get("discovery.ports"))
        return True

    def discovery_cancel(self) -> bool:
        was = self._disc_running
        self._disc_running = False
        return was

    def discovery_status(self) -> Dict[str, Any]:
        return {"running": self._disc_running, "progress": None, "range": self._disc_range, "ports": self._disc_ports,
                "default_range": "10.0.0.0/24", "default_ports": [80, 443], "last_run": None}

    def set_paused(self, paused: bool) -> bool:
        self.ping.set_paused(paused)
        return self.ping.paused

    def add_target(self, host: str, label: Optional[str] = None) -> Dict[str, Any]:
        return self.ping.add_target(host, label)

    def remove_target(self, tid: int) -> bool:
        return self.ping.remove_target(tid)

    def netinfo_summary(self) -> Dict[str, Any]:
        return {"internet_nic": {"name": "Ethernet", "ipv4": "10.0.0.112", "network": "10.0.0.0/24", "gateway": "10.0.0.251"},
                "adapter_count": 2}


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _no_file_logging(monkeypatch, tmp_path):
    """Keep the global logging config untouched (setup_logging is idempotent & process-wide)."""
    from tnt import logging_setup

    def fake_setup(console: bool = False, level: int = logging.INFO, log_dir: Optional[Path] = None) -> Path:
        d = Path(log_dir) if log_dir else tmp_path / "logs"
        d.mkdir(parents=True, exist_ok=True)
        return d / "tnt-service.log"

    monkeypatch.setattr(logging_setup, "setup_logging", fake_setup)


@pytest.fixture
def ui_dir(tmp_path) -> Path:
    ui = tmp_path / "ui"
    (ui / "css").mkdir(parents=True)
    (ui / "index.html").write_text("<!doctype html><title>TNT test UI</title>", encoding="utf-8")
    (ui / "css" / "app.css").write_text("body{margin:0}", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("TOP-SECRET-CONTENT", encoding="utf-8")
    return ui


@pytest.fixture
def engine(data_dir):
    cfg = tnt_config.Config(data_dir / "config.json").load()
    db = tnt_db.Database(data_dir / "tnt.db")
    bus = tnt_events.EventBus()
    eng = FakeEngine(cfg, db, bus)
    yield eng
    db.close()


@pytest.fixture
def server(engine, ui_dir):
    srv = ApiServer(engine, "127.0.0.1", 0, bus=engine.bus, ui_dir=ui_dir)
    engine.api = srv
    srv.start()
    assert srv.running and srv.port not in (0, 7130)
    yield srv
    srv.stop()
    assert not srv.running


def call(srv: Any, method: str, path: str, body: Any = None, raw: Optional[bytes] = None,
         headers: Optional[Dict[str, str]] = None):
    """Return ``(status, lower-cased headers dict, body bytes)``."""
    conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
    try:
        data = raw if raw is not None else (json.dumps(body).encode("utf-8") if body is not None else None)
        hdrs = dict(headers or {})
        if data is not None:
            hdrs.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, payload
    finally:
        conn.close()


def call_json(srv: Any, method: str, path: str, body: Any = None, raw: Optional[bytes] = None):
    status, headers, payload = call(srv, method, path, body, raw)
    assert headers["content-type"].startswith("application/json"), headers
    return status, (json.loads(payload) if payload else None)


# ---------------------------------------------------------------------------
# router
# ---------------------------------------------------------------------------
def test_router_path_params_404_405():
    r = Router()
    r.add("GET", "/api/targets/{id}/samples", lambda req: ("samples", req.params))
    r.add("DELETE", "/api/targets/{id}", lambda req: "deleted")
    r.add("GET", "/api/health", lambda req: {"ok": True})

    handler, params = r.match("GET", "/api/targets/42/samples")
    assert params == {"id": "42"}
    assert handler(Request("GET", "/api/targets/42/samples", params=params)) == ("samples", {"id": "42"})

    handler, params = r.match("delete", "/api/targets/7/")  # case-insensitive method, trailing slash
    assert params == {"id": "7"} and handler(Request("DELETE", "/x")) == "deleted"

    with pytest.raises(ApiError) as e404:
        r.match("GET", "/api/nothing")
    assert e404.value.status == 404 and e404.value.code == "not_found"

    with pytest.raises(ApiError) as e405:
        r.match("POST", "/api/targets/7")
    assert e405.value.status == 405 and e405.value.headers["Allow"] == "DELETE"
    assert e405.value.to_dict() == {"error": {"code": "method_not_allowed", "message": e405.value.message}}

    with pytest.raises(ApiError):
        r.match("GET", "/api/targets/1/2/samples")  # params never span a slash


def test_request_helpers():
    req = Request("GET", "/x", query={"seconds": "12.7", "from": "100", "to": "50"}, params={"id": "abc"}, body=b"[1,2]")
    assert req.query_int("seconds", 5, lo=1, hi=10) == 10
    assert req.query_int("missing", 5) == 5
    with pytest.raises(ApiError) as exc:
        req.int_param("id")
    assert exc.value.status == 400
    with pytest.raises(ApiError):
        req.time_range()  # from > to
    with pytest.raises(ApiError):
        req.json_object()  # list, not object
    assert Request("POST", "/x", body=b"  ").json() == {}
    start, end = Request("GET", "/x", query={"to": "1000"}).time_range(100.0)
    assert (start, end) == (900.0, 1000.0)


# ---------------------------------------------------------------------------
# server basics: errors, static, HEAD, headers
# ---------------------------------------------------------------------------
def test_json_error_shape_and_server_header(server):
    status, headers, payload = call(server, "GET", "/api/does-not-exist")
    assert status == 404
    assert headers["server"] == f"TNT/{__version__}"
    assert headers["content-type"].startswith("application/json")
    data = json.loads(payload)
    assert set(data) == {"error"} and set(data["error"]) == {"code", "message"}
    assert data["error"]["code"] == "not_found"

    status, headers, payload = call(server, "PUT", "/api/health")
    assert status == 405 and json.loads(payload)["error"]["code"] == "method_not_allowed"
    assert "GET" in headers["allow"]

    status, data = call_json(server, "POST", "/api/targets", raw=b"{not json")
    assert status == 400 and data["error"]["code"] == "bad_request" and "JSON" in data["error"]["message"]

    status, data = call_json(server, "GET", "/api/health")
    assert status == 200 and data == {"ok": True}


def test_static_files_index_head_and_mime(server, ui_dir):
    status, headers, payload = call(server, "GET", "/")
    assert status == 200 and b"TNT test UI" in payload
    assert headers["content-type"] == "text/html; charset=utf-8"
    assert headers["cache-control"] == "no-cache"

    status, headers, payload = call(server, "GET", "/index.html")
    assert status == 200 and b"TNT test UI" in payload

    status, headers, payload = call(server, "HEAD", "/")
    assert status == 200 and payload == b"" and int(headers["content-length"]) > 0

    status, headers, payload = call(server, "GET", "/css/app.css")
    assert status == 200 and headers["content-type"] == "text/css; charset=utf-8" and payload == b"body{margin:0}"

    status, headers, payload = call(server, "GET", "/missing.js")
    assert status == 404 and json.loads(payload)["error"]["code"] == "not_found"

    status, headers, payload = call(server, "POST", "/index.html")
    assert status == 405


def test_static_path_traversal_blocked(server, ui_dir):
    for path in ("/../secret.txt", "/%2e%2e/secret.txt", "/css/../../secret.txt", "/css/..%5c..%5csecret.txt",
                 "/..%2fsecret.txt", "/%5c..%5csecret.txt"):
        status, headers, payload = call(server, "GET", path)
        assert status in (400, 404), path
        assert b"TOP-SECRET" not in payload, path
    assert (ui_dir.parent / "secret.txt").exists()  # the file was there to be leaked


def test_body_too_large_is_rejected(server):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    try:
        conn.putrequest("PUT", "/api/settings")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(2 * 1024 * 1024))
        conn.endheaders()
        resp = conn.getresponse()
        assert resp.status == 413
        assert json.loads(resp.read())["error"]["code"] == "payload_too_large"
    finally:
        conn.close()


def test_reports_routes_need_the_report_manager(server):
    """The fake engine has no ``reports``: every /api/reports route is 503 and /api/status carries null.
    Only the Full Scan's Wi-Fi post may exceed the 1 MB body cap (tests/test_reports.py sends one)."""
    for method, path in (("GET", "/api/reports"), ("GET", "/api/reports/sites"), ("GET", "/api/reports/scan"),
                         ("POST", "/api/reports/scan"), ("POST", "/api/reports/scan/wifi"), ("GET", "/api/reports/1"),
                         ("GET", "/api/reports/1/pdf"), ("GET", "/api/reports/compare?a=1&b=2")):
        status, data = call_json(server, method, path)
        assert status == 503 and data["error"]["code"] == "unavailable", path
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["reports"] is None
    assert api_server.body_limit("/api/reports/scan/wifi/") == 2 * 1024 * 1024
    assert api_server.body_limit("/api/settings") == api_server.MAX_BODY_BYTES == 1024 * 1024


def test_server_threads_are_daemons(server):
    assert server.httpd.daemon_threads is True
    assert any(t.name == "tnt-api" and t.daemon for t in threading.enumerate())


def test_malformed_request_line_gets_json_error(server):
    """Errors raised by the stdlib parser (before any route runs) keep the JSON error shape."""
    def raw_request(payload: bytes) -> bytes:
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        try:
            sock.sendall(payload)
            raw = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                raw += chunk
        finally:
            sock.close()
        return raw

    raw = raw_request(b"BREW /api/health HTTP/1.1\r\nHost: x\r\n\r\n")  # 501 from handle_one_request
    head, _, body = raw.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 501")
    assert b"content-type: application/json" in head.lower()
    data = json.loads(body)
    assert set(data) == {"error"} and set(data["error"]) == {"code", "message"}

    # before the version is parsed the stdlib answers as HTTP/0.9 (body only): still JSON
    raw = raw_request(b"GET /api/health HTTP/9.9\r\nHost: x\r\n\r\n")
    data = json.loads(raw)
    assert set(data) == {"error"} and "9.9" in data["error"]["message"]


def test_server_bind_skips_reverse_dns(engine, ui_dir, monkeypatch):
    """HTTPServer.server_bind() would call socket.getfqdn() (reverse DNS, can hang for
    seconds while the internet is down); the TNT server must not depend on it."""
    def boom(*a, **k):
        raise AssertionError("getfqdn must not be called by the API server")

    monkeypatch.setattr(socket, "getfqdn", boom)
    srv = ApiServer(engine, "127.0.0.1", 0, bus=engine.bus, ui_dir=ui_dir)
    srv.start()
    try:
        assert srv.running and srv.httpd.server_name == "127.0.0.1" and srv.httpd.server_port == srv.port
        status, data = call_json(srv, "GET", "/api/health")
        assert data == {"ok": True}
    finally:
        srv.stop()


def test_stale_listener_is_released_before_rebind(engine, ui_dir):
    """If the accept loop dies the bound socket must not block a later start() on the same port."""
    srv = ApiServer(engine, "127.0.0.1", 0, bus=engine.bus, ui_dir=ui_dir)
    srv.start()
    port = srv.port
    try:
        srv.httpd.shutdown()          # the loop exits; the thread ends; the socket stays bound
        assert _wait_for(lambda: not srv.running, 5.0)
        assert srv.httpd is not None  # stop() was never called: the stale server is still referenced
        srv.start()                   # must close the stale listener and rebind the same port
        assert srv.running and srv.port == port
        status, data = call_json(srv, "GET", "/api/health")
        assert data == {"ok": True}
    finally:
        srv.stop()


# ---------------------------------------------------------------------------
# loopback only + port preflight
# ---------------------------------------------------------------------------
def test_is_loopback():
    assert is_loopback("127.0.0.1") and is_loopback("127.5.5.5") and is_loopback("::1") and is_loopback("::ffff:127.0.0.1")
    assert not is_loopback("10.0.0.5") and not is_loopback("192.168.1.1") and not is_loopback("") and not is_loopback("nope")
    assert not is_loopback("fe80::1%12")


def test_non_loopback_client_is_refused(server, monkeypatch):
    monkeypatch.setattr(api_server, "is_loopback", lambda ip: False)
    status, data = call_json(server, "GET", "/api/health")
    assert status == 403 and data["error"]["code"] == "forbidden"
    status, headers, payload = call(server, "GET", "/")
    assert status == 403


def test_port_preflight_message_and_start_failure(engine):
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    try:
        with pytest.raises(RuntimeError) as exc:
            preflight_port("127.0.0.1", port)
        msg = str(exc.value)
        assert f"netstat -ano | findstr :{port}" in msg
        assert "TNT_PORT" in msg and "api.port in config.json" in msg     # how to move TNT off the port
        assert "already in use" in msg and str(port) in msg and "30 s" in msg

        srv = ApiServer(engine, "127.0.0.1", port, bus=engine.bus)
        with pytest.raises(RuntimeError) as exc2:
            srv.start()
        assert f"findstr :{port}" in str(exc2.value)
        assert not srv.running and srv.last_error is None or f":{port}" in str(srv.last_error or "")
        srv.stop()  # safe even though it never started
    finally:
        blocker.close()
    preflight_port("127.0.0.1", 0)  # a free (ephemeral) port passes silently


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
def test_status_shape(server, engine):
    engine.ping.add_target("1.1.1.1")
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200
    expected = {"version", "started_ts", "uptime_s", "mode", "monitoring", "paused", "overall_light",
                "targets", "outages", "speed", "discovery", "netinfo", "net", "settings", "map", "dhcp"}
    assert expected <= set(data)
    assert data["version"] == __version__ and data["mode"] == "console"
    assert set(data["dhcp"]) == {"available", "running", "adapter", "server_ip", "pool", "bound", "offered", "since_ts", "error"}
    assert data["dhcp"]["running"] is False and data["dhcp"]["pool"] == {"start": "172.16.4.101", "end": "172.16.4.105", "size": 5}
    assert data["monitoring"] is True and data["paused"] is False
    assert data["overall_light"] == "green"
    assert data["targets"][0]["host"] == "1.1.1.1" and "window" in data["targets"][0]
    assert set(data["outages"]) == {"active", "total_active", "count_24h", "last", "monitoring"}
    assert data["speed"]["backend"] == "cloudflare" and "next_run_ts" in data["speed"]
    assert data["discovery"] == {"running": False, "progress": None, "last_run": None}
    assert data["netinfo"]["internet_nic"]["name"] == "Ethernet" and data["netinfo"]["adapter_count"] == 2
    # no network watcher on this engine: generation 0, the rest from the netinfo summary
    assert data["net"] == {"generation": 0, "changed_ts": None, "default_gateway": "10.0.0.251", "internet_nic": "Ethernet",
                           "summary": None, "networks": [], "network_id": None}
    assert data["settings"] == {"theme": "light", "loaded": True}
    assert data["uptime_s"] >= 5


def test_networks_current_and_the_status_network_id(server, engine):
    status, data = call_json(server, "GET", "/api/networks/current")
    assert status == 200 and data == {"network": None}, "no network tracker on this engine"
    from tnt import networks as networks_mod

    facts = {"gateway_ip": "10.0.0.251", "subnet": "10.0.0.0/24", "dhcp_server": "10.0.0.251", "dns_suffix": "lan", "nic": "Ethernet",
             "if_index": 12}
    tracker = networks_mod.NetworkTracker(engine.db, facts_fn=lambda hint: dict(facts),
                                          neighbour_fn=lambda ip, index: ("02:00:5E:00:53:FB", "reachable"))
    tracker.start()
    engine.networks = tracker
    try:
        nid = tracker.current_network_id()
        status, data = call_json(server, "GET", "/api/networks/current")
        net = data["network"]
        assert status == 200 and set(net) == {"id", "mac", "vendor", "gateway_ip", "subnet", "dhcp_server", "identity", "virtual_mac",
                                              "portable", "first_seen", "last_seen", "last_report", "offline"}
        assert (net["id"], net["mac"], net["identity"], net["gateway_ip"], net["subnet"], net["dhcp_server"], net["last_report"],
                net["portable"], net["offline"]) == (nid, "02:00:5E:00:53:FB", "mac", "10.0.0.251", "10.0.0.0/24", "10.0.0.251", None, False, False)
        rid = engine.db.add_report("Harbor View", "harbor view", T0, T0 + 90, "complete", __version__, {}, {}, network_id=nid)
        engine.db.add_report("Unnamed site", "unnamed site", T0 + 60, T0 + 150, "complete", __version__, {}, {}, network_id=nid)
        status, data = call_json(server, "GET", "/api/networks/current")
        assert data["network"]["last_report"] == {"id": rid, "site": "Harbor View", "created_ts": T0}, "an unnamed report names no site"
        status, data = call_json(server, "GET", "/api/status")
        assert data["net"]["network_id"] == nid
        # PATCH /api/networks/{id}: a network carried from site to site (a hotspot), or not; it needs the report manager
        status, data = call_json(server, "PATCH", f"/api/networks/{nid}", {"portable": True})
        assert status == 503
        from tnt import reports as reports_mod

        engine.reports = reports_mod.ReportManager(engine.db, None, None, engine, networks=tracker)
        status, data = call_json(server, "PATCH", f"/api/networks/{nid}", {"portable": True})
        assert status == 200 and data["network"]["id"] == nid and data["network"]["portable"] is True and "first_seen" not in data["network"]
        assert call_json(server, "GET", "/api/networks/current")[1]["network"]["portable"] is True
        for body, code in (({}, 400), ({"portable": "yes"}, 400), ({"portable": 1}, 400)):
            assert call_json(server, "PATCH", f"/api/networks/{nid}", body)[0] == code, body
        for path, code in (("/api/networks/0", 400), ("/api/networks/abc", 400), ("/api/networks/999", 404)):
            assert call_json(server, "PATCH", path, {"portable": False})[0] == code, path
        assert call_json(server, "PATCH", f"/api/networks/{nid}", {"portable": False})[1]["network"]["portable"] is False
    finally:
        tracker.stop()
        engine.networks = None
        engine.reports = None


def test_targets_post_delete_defaults_samples(server, engine):
    status, view = call_json(server, "POST", "/api/targets", {"host": "8.8.8.8", "label": "Google"})
    assert status == 201 and view["host"] == "8.8.8.8" and view["label"] == "Google" and view["light"] == "green"
    tid = view["id"]

    status, lst = call_json(server, "GET", "/api/targets")
    assert status == 200 and [t["id"] for t in lst] == [tid]

    status, data = call_json(server, "POST", "/api/targets", {"host": ""})
    assert status == 400 and data["error"]["code"] == "bad_request"
    status, data = call_json(server, "POST", "/api/targets", {"host": "bad host"})
    assert status == 400  # ValueError from the ping manager -> 400
    status, data = call_json(server, "POST", "/api/targets", raw=b"[1]")
    assert status == 400

    status, data = call_json(server, "GET", f"/api/targets/{tid}/samples?seconds=60")
    assert status == 200 and data["target_id"] == tid
    assert data["samples"] == [[T0, 20.0], [T0 + 1, 21.0], [T0 + 2, 22.0]]

    status, data = call_json(server, "DELETE", f"/api/targets/{tid}")
    assert status == 200 and data == {"removed": True}
    status, data = call_json(server, "DELETE", f"/api/targets/{tid}")
    assert status == 404 and data["error"]["code"] == "not_found"
    status, data = call_json(server, "DELETE", "/api/targets/abc")
    assert status == 400
    status, data = call_json(server, "GET", "/api/targets/999/samples")
    assert status == 404

    status, lst = call_json(server, "POST", "/api/targets/defaults")
    assert status == 200 and sorted(t["host"] for t in lst) == ["1.1.1.1", "10.0.0.251"]


def test_target_history_uses_db(server, engine):
    status, data = call_json(server, "GET", "/api/targets/1/history")
    assert status == 404
    row = engine.db.add_target("1.1.1.1")
    # two minutes ago: unambiguously inside the default [now-24h, now) window
    # (a row for the *current* minute is excluded during the first second of a minute)
    minute = int(time.time() // 60 * 60) - 120
    engine.db.upsert_ping_minute(row["id"], minute, 60, 59, 20.0, 18.0, 25.0, 0.5)
    status, data = call_json(server, "GET", f"/api/targets/{row['id']}/history")
    assert status == 200 and data["target_id"] == row["id"]
    assert len(data["minutes"]) == 1 and data["summary"]["sent"] == 60 and data["summary"]["received"] == 59
    status, data = call_json(server, "GET", f"/api/targets/{row['id']}/history?from=abc")
    assert status == 400


def test_settings_put_returns_changed_keys_and_persists(server, engine, data_dir):
    status, data = call_json(server, "GET", "/api/settings")
    assert status == 200 and data["ui"]["theme"] == "light" and data["api"]["port"] == 7130

    status, data = call_json(server, "PUT", "/api/settings", {"ui": {"theme": "dark"}, "ping": {"loaded": False}})
    assert status == 200
    assert data["changed"] == ["ping.loaded", "ui.theme"]
    assert data["settings"]["ui"]["theme"] == "dark" and data["settings"]["ping"]["loaded"] is False

    fresh = tnt_config.Config(data_dir / "config.json").load()
    assert fresh.get("ui.theme") == "dark" and fresh.get("ping.loaded") is False
    assert json.loads((data_dir / "config.json").read_text(encoding="utf-8"))["ui"]["theme"] == "dark"

    status, data = call_json(server, "PUT", "/api/settings", {"ui": {"theme": "dark"}})
    assert status == 200 and data["changed"] == []
    status, data = call_json(server, "PUT", "/api/settings", raw=b"[1, 2]")
    assert status == 400
    status, data = call_json(server, "PUT", "/api/settings", {"speedtest": {"backend": "bogus"}})
    assert status == 200 and data["settings"]["speedtest"]["backend"] == "auto"  # validated, not changed
    # a section that is not an object is refused, not silently reset to its defaults
    status, data = call_json(server, "PUT", "/api/settings", {"ping": {"ttl": 64}, "speedtest": None})
    assert status == 400 and "speedtest" in data["error"]["message"]
    status, data = call_json(server, "GET", "/api/settings")
    assert data["ping"]["ttl"] != 64 and data["speedtest"]["backend"] == "auto"

    status, data = call_json(server, "GET", "/api/status")
    assert data["settings"] == {"theme": "dark", "loaded": False}


def test_settings_put_and_patch_ignore_settings_removed_in_1_7_0(server, engine, data_dir):
    """A client older than 1.7.0 may still send the removed speed-test CLI / scanner settings. Like
    any key this version does not know they are no error (200, the rest of the body applies), but
    being retired they are dropped rather than kept, and the retired backend value becomes "auto"."""
    removed = {"speedtest": {"ookla_path": "C:\\Program Files\\TNT\\bin\\speedtest.exe", "ookla_server_id": 1234},
               "discovery": {"use_nmap": "always", "nmap_path": "C:\\Program Files (x86)\\Nmap"}}
    events: List[Dict[str, Any]] = []
    engine.bus.subscribe(events.append)
    status, data = call_json(server, "PUT", "/api/settings", removed)
    assert status == 200 and data["changed"] == [] and events == []    # nothing stored, nothing announced

    body = {"speedtest": {**removed["speedtest"], "interval_min": 30}, "discovery": dict(removed["discovery"])}
    for method in ("PUT", "PATCH"):
        status, data = call_json(server, method, "/api/settings", body)
        assert status == 200
        assert data["changed"] == (["speedtest.interval_min"] if method == "PUT" else [])
        assert data["settings"]["speedtest"]["interval_min"] == 30
        for section, keys in removed.items():
            assert not set(keys) & set(data["settings"][section])
    status, data = call_json(server, "PATCH", "/api/settings", {"speedtest": {"backend": "fastcom"}})
    assert status == 200 and data["changed"] == ["speedtest.backend"]
    status, data = call_json(server, "PUT", "/api/settings", {"speedtest": {"backend": "ookla"}})
    assert status == 200 and data["changed"] == ["speedtest.backend"] and data["settings"]["speedtest"]["backend"] == "auto"

    on_disk = json.loads((data_dir / "config.json").read_text(encoding="utf-8"))
    assert on_disk["speedtest"]["interval_min"] == 30 and on_disk["speedtest"]["backend"] == "auto"
    for section, keys in removed.items():
        assert not set(keys) & set(on_disk[section])
    status, data = call_json(server, "GET", "/api/settings")
    assert status == 200 and not set(removed["discovery"]) & set(data["discovery"])


def test_monitoring_pause_resume(server, engine):
    engine.ping.add_target("1.1.1.1")
    status, data = call_json(server, "POST", "/api/monitoring/pause")
    assert status == 200 and data == {"paused": True}
    status, data = call_json(server, "GET", "/api/status")
    assert data["paused"] is True and data["monitoring"] is False and data["overall_light"] == "grey"
    status, data = call_json(server, "POST", "/api/monitoring/resume")
    assert status == 200 and data == {"paused": False}


def test_outages_and_speedtest_routes(server, engine):
    status, data = call_json(server, "GET", "/api/outages")
    assert status == 200 and data["outages"] == [] and data["status"]["count_24h"] == 0
    status, data = call_json(server, "GET", "/api/outages/timeline?hours=6")
    assert status == 200 and data["hours"] == 6 and "segments" in data and "total_segments" in data

    status, data = call_json(server, "GET", "/api/speedtests?limit=10")
    assert status == 200 and data["results"] == [] and data["status"]["backend"] == "cloudflare"
    status, data = call_json(server, "POST", "/api/speedtests/run")
    assert status == 200 and data == {"started": True}
    status, data = call_json(server, "POST", "/api/speedtests/run")
    assert status == 409 and data["error"]["code"] == "conflict"
    status, data = call_json(server, "GET", "/api/speedtests/patterns?days=3")
    assert status == 200 and data["days"] == 3 and "findings" in data


def test_discovery_routes(server, engine):
    status, data = call_json(server, "GET", "/api/discovery/status")
    assert status == 200
    assert {"running", "progress", "default_range", "default_ports"} <= set(data)
    assert data["default_range"] == "10.0.0.0/24" and data["running"] is False

    status, data = call_json(server, "POST", "/api/discovery/scan", {})
    assert status == 200 and data["started"] is True and data["range"] == "10.0.0.0/24"
    assert data["ports"] == engine.config.get("discovery.ports")
    status, data = call_json(server, "POST", "/api/discovery/scan", {"range": "10.0.0.0/30"})
    assert status == 409
    status, data = call_json(server, "POST", "/api/discovery/cancel")
    assert status == 200 and data == {"cancelled": True}
    status, data = call_json(server, "POST", "/api/discovery/scan", {"range": "bad", "ports": [22]})
    assert status == 400
    status, data = call_json(server, "POST", "/api/discovery/scan", {"range": "10.0.0.0/30", "ports": [0]})
    assert status == 400
    engine.discovery_cancel()
    status, data = call_json(server, "POST", "/api/discovery/scan", {"range": "10.0.0.1-10.0.0.9", "ports": "22, 80"})
    assert status == 200 and data["ports"] == [22, 80]

    status, data = call_json(server, "GET", "/api/discovery/runs")
    assert status == 200 and data == {"runs": []}
    status, data = call_json(server, "GET", "/api/discovery/last")
    assert status == 200 and data is None
    status, data = call_json(server, "GET", "/api/discovery/runs/99")
    assert status == 404

    run_id = engine.db.add_discovery_run({"ts": T0, "cidr": "10.0.0.0/24", "ports": [80], "method": "native",
                                          "duration_s": 1.0, "scanned": 254, "ok": True},
                                         [{"ip": "10.0.0.9", "ping_ok": True, "open_ports": [80]}])
    status, data = call_json(server, "GET", f"/api/discovery/runs/{run_id}")
    assert status == 200 and data["hosts"][0]["ip"] == "10.0.0.9" and data["hosts"][0]["open_ports"] == [80]
    status, data = call_json(server, "GET", "/api/discovery/last")
    assert data["id"] == run_id
    status, data = call_json(server, "GET", "/api/discovery/runs?limit=5")
    assert len(data["runs"]) == 1 and data["runs"][0]["found"] == 1


# ---------------------------------------------------------------------------
# DHCP server tool
# ---------------------------------------------------------------------------
def test_dhcp_status_leases_and_scan_routes(server, engine):
    status, data = call_json(server, "GET", "/api/dhcp/status")
    assert status == 200
    expected = {"available", "running", "since_ts", "error", "warning", "adapter", "adapters", "server_ip", "pool",
                "lease_s", "gateway", "dns", "ping_check", "clients", "counts", "scan", "firewall", "settings"}
    assert expected <= set(data)
    assert data["running"] is False and data["adapter"]["will_change"] is True and data["dns"] == []
    assert data["pool"] == {"start": "172.16.4.101", "end": "172.16.4.105", "size": 5, "auto": True}
    assert data["gateway"] == data["server_ip"] == "172.16.4.100"
    assert data["firewall"]["rule"] == "TNT DHCP server (UDP 67 in)" and data["scan"] is None
    assert data["adapters"][0]["name"] == "Ethernet" and data["clients"] == []

    engine.dhcp.leases_by_mac[DHCP_LEASE["mac"]] = dict(DHCP_LEASE)
    status, data = call_json(server, "GET", "/api/dhcp/leases")
    assert status == 200 and data == {"leases": [DHCP_LEASE]}
    status, data = call_json(server, "GET", "/api/dhcp/status")
    assert data["counts"] == {"bound": 1, "offered": 0, "total": 1} and data["clients"][0]["open_ports"] == [80, 554]

    status, data = call_json(server, "POST", "/api/dhcp/scan")   # no body at all
    assert status == 200
    assert set(data) == {"ts", "duration_s", "wait_s", "servers", "probed", "errors"}
    assert data["servers"] == [DHCP_SERVER] and data["probed"] == [{"adapter": "Ethernet", "ip": "10.0.0.112"}]
    assert engine.dhcp.calls[-1] == ("scan", None)
    status, data = call_json(server, "POST", "/api/dhcp/scan", {"wait_s": 3})
    assert status == 200 and data["wait_s"] == 3.0 and engine.dhcp.calls[-1] == ("scan", 3.0)
    status, data = call_json(server, "POST", "/api/dhcp/scan", {"wait_s": 999})
    assert status == 200 and engine.dhcp.calls[-1] == ("scan", 30.0)    # clamped like dhcp.scan_wait_s
    for bad in ("abc", True, "inf"):
        status, data = call_json(server, "POST", "/api/dhcp/scan", {"wait_s": bad})
        assert status == 400 and data["error"]["code"] == "bad_request", bad
    status, data = call_json(server, "GET", "/api/dhcp/status")
    assert data["scan"]["servers"] == [DHCP_SERVER]   # the last scan sticks to the status


def test_dhcp_start_conflict_force_and_stop(server, engine):
    status, data = call_json(server, "POST", "/api/dhcp/start", {})
    assert status == 409
    assert data["error"] == {"code": "dhcp_server_present", "message": "Another DHCP server is active on this network"}
    assert data["servers"] == [DHCP_SERVER]
    assert data["scan"]["servers"] == [DHCP_SERVER] and data["scan"]["probed"][0]["adapter"] == "Ethernet"
    assert engine.dhcp.running is False and engine.dhcp.calls[0] == ("start", False)

    # force is a JSON boolean or nothing: a string, a number or an object must not skip the
    # second-server safety scan (bool("no") is True)
    for bad in ("yes", "no", 1, 0, {}, [], None, "true"):
        n = len(engine.dhcp.calls)
        status, data = call_json(server, "POST", "/api/dhcp/start", {"force": bad})
        assert status == 400 and data["error"] == {"code": "bad_request", "message": "force must be true or false"}, bad
        assert len(engine.dhcp.calls) == n and engine.dhcp.running is False
    status, data = call_json(server, "POST", "/api/dhcp/start", {"force": False})
    assert status == 409 and engine.dhcp.calls[-2:] == [("start", False), ("scan", None)]

    status, data = call_json(server, "POST", "/api/dhcp/start", {"force": True})
    assert status == 200 and data["running"] is True and data["since_ts"] == T0 and data["adapter"]["changed"] is True
    assert data["adapter"]["is_internet"] is True and data["adapters"][0]["is_internet"] is True
    assert engine.dhcp.calls[-1] == ("start", True)
    status, data = call_json(server, "GET", "/api/status")
    assert data["dhcp"]["running"] is True and data["dhcp"]["server_ip"] == "172.16.4.100" and data["dhcp"]["adapter"] == "Ethernet"

    status, data = call_json(server, "POST", "/api/dhcp/stop")
    assert status == 200 and data["running"] is False and data["since_ts"] is None
    assert engine.dhcp.calls[-1] == ("stop", True)

    # no other server around: a plain start (no body) succeeds without force
    engine.dhcp.other_servers = []
    status, data = call_json(server, "POST", "/api/dhcp/start")
    assert status == 200 and data["running"] is True
    call_json(server, "POST", "/api/dhcp/stop")

    # a RuntimeError that is not a conflict (bind failure, netsh failure) is a 500 with the message
    engine.dhcp.fail_with = RuntimeError("UDP port 67 is already in use (another DHCP server on this PC?)")
    status, data = call_json(server, "POST", "/api/dhcp/start", {"force": True})
    assert status == 500 and data["error"]["code"] == "internal_error" and "UDP port 67" in data["error"]["message"]
    engine.dhcp.fail_with = ValueError("no usable network adapter")
    status, data = call_json(server, "POST", "/api/dhcp/start", {"force": True})
    assert status == 400 and data["error"]["message"] == "no usable network adapter"
    status, data = call_json(server, "POST", "/api/dhcp/start", raw=b"[1]")
    assert status == 400


def test_dhcp_settings_and_forget_routes(server, engine):
    status, data = call_json(server, "PUT", "/api/dhcp/settings",
                             {"adapter": "Ethernet", "pool_start": "10.0.0.113", "pool_end": "10.0.0.117", "lease_s": 600, "ping_check": False})
    assert status == 200 and data["settings"]["adapter"] == "Ethernet" and data["lease_s"] == 600 and data["ping_check"] is False
    assert data["pool"] == {"start": "10.0.0.113", "end": "10.0.0.117", "size": 5, "auto": False}
    assert engine.dhcp.calls[-1] == ("settings", {"adapter": "Ethernet", "pool_start": "10.0.0.113", "pool_end": "10.0.0.117",
                                                  "lease_s": 600, "ping_check": False})
    status, data = call_json(server, "PUT", "/api/dhcp/settings", {"pool_size": 10})
    assert status == 200 and data["pool"]["size"] == 10
    status, data = call_json(server, "PUT", "/api/dhcp/settings", {"lease_s": 5})
    assert status == 400 and "lease_s" in data["error"]["message"]
    status, data = call_json(server, "PUT", "/api/dhcp/settings", {"pool_start": "300.1.1.1"})
    assert status == 400 and data["error"]["code"] == "bad_request"
    status, data = call_json(server, "PUT", "/api/dhcp/settings", {"static_ip": "1.2.3.4"})
    assert status == 400 and "static_ip" in data["error"]["message"] and "accepted" in data["error"]["message"]
    status, data = call_json(server, "PUT", "/api/dhcp/settings", {})
    assert status == 400
    status, data = call_json(server, "PUT", "/api/dhcp/settings", raw=b"[]")
    assert status == 400

    engine.dhcp.leases_by_mac[DHCP_LEASE["mac"]] = dict(DHCP_LEASE)
    status, data = call_json(server, "DELETE", "/api/dhcp/leases/aa-bb-cc-dd-ee-01")   # normalised
    assert status == 200 and data == {"ok": True} and engine.dhcp.calls[-1] == ("forget", "AA:BB:CC:DD:EE:01")
    status, data = call_json(server, "DELETE", "/api/dhcp/leases/AA:BB:CC:DD:EE:01")
    assert status == 404 and data["error"]["code"] == "not_found"
    status, data = call_json(server, "DELETE", "/api/dhcp/leases/not-a-mac")
    assert status == 400 and data["error"]["code"] == "bad_request"
    status, data = call_json(server, "DELETE", "/api/dhcp/leases/AABBCCDDEE")
    assert status == 400


def test_dhcp_routes_503_when_component_missing(server, engine):
    engine.dhcp = None
    for method, path, body in (("GET", "/api/dhcp/status", None), ("GET", "/api/dhcp/leases", None),
                               ("POST", "/api/dhcp/scan", {}), ("POST", "/api/dhcp/start", {"force": True}),
                               ("POST", "/api/dhcp/stop", None), ("PUT", "/api/dhcp/settings", {"lease_s": 600}),
                               ("DELETE", "/api/dhcp/leases/AA:BB:CC:DD:EE:01", None)):
        status, data = call_json(server, method, path, body)
        assert status == 503 and data["error"]["code"] == "unavailable", (method, path)
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["dhcp"] is None

    class Broken:
        def summary(self):
            raise RuntimeError("no dhcp for you")

    engine.dhcp = Broken()
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["dhcp"] is None and data["version"] == __version__


def test_traceroute_routes(server, engine):
    engine.tracer = FakeTracer()
    status, data = call_json(server, "GET", "/api/tools/traceroute/last")
    assert status == 200 and data == {"trace": None, "running": False}

    status, data = call_json(server, "POST", "/api/tools/traceroute", {"host": "www.example"})
    assert status == 200 and data["host"] == "www.example" and data["complete"] is True and data["error"] is None
    assert set(data) == {"host", "target_ip", "ts", "duration_s", "max_hops", "probes", "timeout_ms", "complete", "error",
                         "pc", "gateway", "hops"}
    assert set(data["hops"][0]) == {"ttl", "ip", "alt_ips", "hostname", "rtts", "avg_ms", "min_ms", "max_ms", "loss",
                                    "responder_status", "kind", "label", "location"}
    assert data["hops"][1]["rtts"] == [20.0, None, 21.0] and data["hops"][1]["kind"] == "destination"
    assert engine.tracer.calls[-1] == ("www.example", {"max_hops": 30, "probes": 3, "timeout_ms": 1500, "resolve_names": True})

    status, data = call_json(server, "POST", "/api/tools/traceroute",
                             {"host": " [2606:4700::1111] ", "max_hops": 12, "probes": "2", "timeout_ms": 800.0,
                              "resolve_names": False})
    assert status == 200
    assert engine.tracer.calls[-1] == ("2606:4700::1111", {"max_hops": 12, "probes": 2, "timeout_ms": 800, "resolve_names": False})
    status, data = call_json(server, "POST", "/api/tools/traceroute", {"host": "1.1.1.1", "max_hops": None, "resolve_names": None})
    assert status == 200 and engine.tracer.calls[-1][1]["max_hops"] == 30 and engine.tracer.calls[-1][1]["resolve_names"] is True

    status, data = call_json(server, "GET", "/api/tools/traceroute/last")
    assert status == 200 and data["running"] is False and data["trace"]["host"] == "1.1.1.1"

    n = len(engine.tracer.calls)
    for body in ({}, {"host": ""}, {"host": "   "}, {"host": 42}, {"host": ["a"]}, {"host": "bad host"}, {"host": "a" * 254},
                 {"host": "evil;rm"}, {"host": "[]"}, {"host": "x", "max_hops": 0}, {"host": "x", "max_hops": 65},
                 {"host": "x", "probes": 6}, {"host": "x", "probes": 0}, {"host": "x", "timeout_ms": 100},
                 {"host": "x", "timeout_ms": 5001}, {"host": "x", "timeout_ms": "nan"}, {"host": "x", "timeout_ms": "1e400"},
                 {"host": "x", "max_hops": True}, {"host": "x", "probes": [3]}, {"host": "x", "resolve_names": "yes"},
                 {"host": "x", "resolve_names": 1}):
        status, data = call_json(server, "POST", "/api/tools/traceroute", body)
        assert status == 400 and data["error"]["code"] == "bad_request", body
    assert len(engine.tracer.calls) == n     # validation happens before the tracer is touched
    status, data = call_json(server, "POST", "/api/tools/traceroute", raw=b"[]")
    assert status == 400

    engine.tracer.fail_with = ValueError("could not resolve nope.invalid")
    status, data = call_json(server, "POST", "/api/tools/traceroute", {"host": "nope.invalid"})
    assert status == 400 and data["error"] == {"code": "bad_request", "message": "could not resolve nope.invalid"}
    engine.tracer.fail_with = RuntimeError("a traceroute is already running")
    status, data = call_json(server, "POST", "/api/tools/traceroute", {"host": "x"})
    assert status == 409 and data["error"] == {"code": "conflict", "message": "a traceroute is already running"}
    engine.tracer.fail_with = RuntimeError("the ICMP engine is not available")
    status, data = call_json(server, "POST", "/api/tools/traceroute", {"host": "x"})
    assert status == 500 and data["error"]["code"] == "internal_error" and "ICMP" in data["error"]["message"]
    engine.tracer.fail_with = None
    engine.tracer.running = True
    status, data = call_json(server, "GET", "/api/tools/traceroute/last")
    assert status == 200 and data["running"] is True and data["trace"]["host"] == "1.1.1.1"
    status, data = call_json(server, "POST", "/api/tools/traceroute", {"host": "x"})
    assert status == 409


def test_traceroute_503_without_pinger_then_lazy_tracer(server, engine):
    assert not hasattr(engine, "tracer") and engine.pinger is None
    status, data = call_json(server, "POST", "/api/tools/traceroute", {"host": "198.51.100.7"})
    assert status == 503 and data["error"]["code"] == "unavailable"
    assert not hasattr(engine, "tracer")
    status, data = call_json(server, "GET", "/api/tools/traceroute/last")
    assert status == 200 and data == {"trace": None, "running": False}

    # with a pinger the route builds a real Tracer on first use and keeps it on the engine
    from tnt.icmp import PingResult
    from tnt.traceroute import Tracer

    class OneHopPinger:
        def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
            return PingResult(True, 0.7, 0, None, 64, size, ip, responder=ip)

    seen: List[Dict[str, Any]] = []
    engine.bus.subscribe(lambda e: seen.append(e) if e["type"].startswith("trace.") else None)
    engine.pinger = OneHopPinger()
    status, data = call_json(server, "POST", "/api/tools/traceroute", {"host": "198.51.100.7", "probes": 1, "resolve_names": False})
    assert status == 200 and data["complete"] is True and len(data["hops"]) == 1, data
    assert data["hops"][0]["kind"] == "destination" and data["hops"][0]["rtts"] == [0.7] and data["hops"][0]["hostname"] is None
    assert isinstance(engine.tracer, Tracer) and engine.tracer.last["host"] == "198.51.100.7"
    assert [e["type"] for e in seen] == ["trace.start", "trace.hop", "trace.done"]
    status, data = call_json(server, "GET", "/api/tools/traceroute/last")
    assert status == 200 and data["running"] is False and data["trace"]["target_ip"] == "198.51.100.7"
    first = engine.tracer
    status, data = call_json(server, "POST", "/api/tools/traceroute", {"host": "198.51.100.7", "probes": 1, "resolve_names": False})
    assert status == 200 and engine.tracer is first


# ---------------------------------------------------------------------------
# IP location (tnt.geoip)
# ---------------------------------------------------------------------------
def test_status_geoip_null_without_component_and_status_with_it(server, engine):
    from tnt import geoip

    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and "geoip" in data and data["geoip"] is None
    engine.geoip = FakeGeoIp()
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["geoip"] == engine.geoip.status() and set(data["geoip"]) == set(geoip.STATUS_KEYS)
    engine.geoip.enabled = False
    status, data = call_json(server, "GET", "/api/status")
    assert data["geoip"]["state"] == "disabled" and set(data["geoip"]) == set(geoip.STATUS_KEYS)

    def boom() -> Dict[str, Any]:
        raise RuntimeError("status failed")

    engine.geoip.status = boom        # one broken component only blanks its own key
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["geoip"] is None and data["version"] == __version__


def test_geoip_routes(server, engine):
    from urllib.parse import urlencode

    def lookup_path(ip: str) -> str:
        return "/api/geoip/lookup?" + urlencode({"ip": ip})

    for method, path in (("GET", "/api/geoip"), ("GET", lookup_path("203.0.113.9")), ("POST", "/api/geoip/check")):
        status, data = call_json(server, method, path)
        assert status == 503 and data["error"]["code"] == "unavailable", path

    gm = engine.geoip = FakeGeoIp()
    status, data = call_json(server, "GET", "/api/geoip")
    assert status == 200 and data == gm.status()
    status, data = call_json(server, "GET", "/api/geoip/lookup?ip=203.0.113.9")
    assert status == 200 and data == {"ip": "203.0.113.9", "result": dict(GEO, ip="203.0.113.9")}
    status, data = call_json(server, "GET", lookup_path("10.0.0.1"))
    assert status == 200 and data == {"ip": "10.0.0.1", "result": None}

    n = len(gm.lookups)
    for bad in ("", "nope", "999.1.1.1", "1" * 65, "203.0.113.9/24", "[]", "%12"):
        status, data = call_json(server, "GET", lookup_path(bad))
        assert status == 400 and data["error"] == {"code": "bad_request", "message": "ip must be an IPv4 or IPv6 address"}, bad
    status, data = call_json(server, "GET", "/api/geoip/lookup")
    assert status == 400 and data["error"]["code"] == "bad_request"
    assert len(gm.lookups) == n       # nothing invalid reaches the manager

    status, data = call_json(server, "GET", lookup_path("[2001:db8::1]"))
    assert status == 200 and data["ip"] == "2001:db8::1" and gm.lookups[-1] == "2001:db8::1"
    status, data = call_json(server, "GET", lookup_path("fe80::1%12"))
    assert status == 200 and data["ip"] == "fe80::1" and gm.lookups[-1] == "fe80::1"
    status, data = call_json(server, "GET", lookup_path(" 2001:DB8:0::5 "))
    assert status == 200 and data["ip"] == "2001:db8::5" and data["result"]["ip"] == "2001:db8::5"
    gm.fail = True                    # a lookup that raises is a null result, not a 500
    status, data = call_json(server, "GET", lookup_path("203.0.113.9"))
    assert status == 200 and data == {"ip": "203.0.113.9", "result": None}
    gm.fail = False

    status, data = call_json(server, "POST", "/api/geoip/check")
    assert status == 200 and data == gm.status() and gm.checks == 1
    gm.enabled = False
    status, data = call_json(server, "POST", "/api/geoip/check")
    assert status == 409 and data["error"] == {"code": "conflict", "message": "IP location is switched off"}
    assert gm.checks == 2
    status, data = call_json(server, "GET", lookup_path("203.0.113.9"))
    assert status == 200 and data == {"ip": "203.0.113.9", "result": None}
    status, data = call_json(server, "GET", "/api/geoip")
    assert status == 200 and data["state"] == "disabled"


def test_settings_toggle_geoip(server, engine, data_dir):
    seen: List[Dict[str, Any]] = []
    engine.bus.subscribe(lambda e: seen.append(e) if e["type"] == "settings.changed" else None)
    status, data = call_json(server, "GET", "/api/settings")
    assert status == 200 and data["geoip"] == {"enabled": True}

    status, data = call_json(server, "PUT", "/api/settings", {"geoip": {"enabled": False}})
    assert status == 200 and data["changed"] == ["geoip.enabled"] and data["settings"]["geoip"] == {"enabled": False}
    assert tnt_config.Config(data_dir / "config.json").load().get("geoip.enabled") is False
    assert _wait_for(lambda: len(seen) >= 1)
    assert seen[-1]["data"]["keys"] == ["geoip.enabled"] and seen[-1]["data"]["settings"]["geoip"] == {"enabled": False}

    status, data = call_json(server, "PATCH", "/api/settings", {"geoip": {"enabled": True}})
    assert status == 200 and data["changed"] == ["geoip.enabled"]
    status, data = call_json(server, "PUT", "/api/settings", {"geoip": "x"})
    assert status == 400 and "must be an object" in data["error"]["message"]
    status, data = call_json(server, "GET", "/api/settings")
    assert status == 200 and data["geoip"] == {"enabled": True}


def test_lazy_tracer_gets_the_geo_provider(server, engine):
    from tnt.icmp import PingResult

    class OneHopPinger:
        def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
            return PingResult(True, 0.7, 0, None, 64, size, ip, responder=ip)

    loc = {"text": "Richardson, TX", "source": "database", "hint": None, "db_text": "Richardson, TX", "asn": 64510,
           "as_org": "Example Transit, Inc."}
    engine.pinger = OneHopPinger()
    gm = engine.geoip = FakeGeoIp(location=loc)
    body = {"host": "198.51.100.7", "probes": 1, "resolve_names": False}
    status, data = call_json(server, "POST", "/api/tools/traceroute", body)
    assert status == 200 and data["hops"][0]["location"] == loc
    assert gm.hop_calls == [("198.51.100.7", None, 0.7, (32.95, -96.73), "destination")]
    status, data = call_json(server, "GET", "/api/tools/traceroute/last")
    assert status == 200 and data["trace"]["hops"][0]["location"] == loc

    # the provider is asked on every trace: without the component the same tracer gives null locations
    engine.geoip = None
    status, data = call_json(server, "POST", "/api/tools/traceroute", body)
    assert status == 200 and data["hops"][0]["location"] is None and len(gm.hop_calls) == 1


def test_diagnostics_geoip_section_with_the_component(engine):
    from tnt import diagnostics, geoip

    engine.geoip = FakeGeoIp()
    d = diagnostics.collect(engine)
    assert set(d["geoip"]) == set(geoip.DIAG_KEYS)
    assert d["geoip"] == {"available": True, "status": engine.geoip.status(), "files": engine.geoip.files()}


def test_lan_peer_and_throughput_routes(server, engine):
    status, data = call_json(server, "GET", "/api/tools/lan/peers")
    assert status == 200 and set(data) == {"self", "peers", "listening", "error", "enabled"}
    assert set(data["self"]) == {"id", "hostname", "ip", "version", "port"}
    assert set(data["peers"][0]) == {"id", "hostname", "ip", "version", "last_seen_ts", "age_s", "adapter"}
    assert data["listening"] is True and data["error"] is None and data["peers"][0]["ip"] == "10.0.0.42"

    status, data = call_json(server, "GET", "/api/tools/lan/throughput/last")
    assert status == 200 and data == {"result": None, "running": False}

    status, data = call_json(server, "POST", "/api/tools/lan/throughput", {"peer": "10.0.0.42"})
    assert status == 200
    assert set(data) == {"ts", "peer", "seconds", "upload_mbps", "download_mbps", "latency_ms", "duration_s", "error"}
    assert data["peer"] == {"ip": "10.0.0.42", "hostname": "DESK-02"} and data["seconds"] == 5 and data["error"] is None
    assert engine.lan.calls[-1] == ("throughput", "10.0.0.42", 5)
    status, data = call_json(server, "POST", "/api/tools/lan/throughput", {"peer": " 10.0.0.42 ", "seconds": "12"})
    assert status == 200 and data["seconds"] == 12 and engine.lan.calls[-1] == ("throughput", "10.0.0.42", 12)
    status, data = call_json(server, "GET", "/api/tools/lan/throughput/last")
    assert status == 200 and data["running"] is False and data["result"]["seconds"] == 12

    n = len(engine.lan.calls)
    for body in ({}, {"peer": ""}, {"peer": None}, {"peer": "DESK-02"}, {"peer": "fe80::1"}, {"peer": "300.1.1.1"}, {"peer": 42},
                 {"peer": "10.0.0.42/24"}, {"peer": "10.0.0.42", "seconds": 1}, {"peer": "10.0.0.42", "seconds": 21},
                 {"peer": "10.0.0.42", "seconds": True}, {"peer": "10.0.0.42", "seconds": "inf"},
                 {"peer": "10.0.0.42", "seconds": "five"}):
        status, data = call_json(server, "POST", "/api/tools/lan/throughput", body)
        assert status == 400 and data["error"]["code"] == "bad_request", body
    assert len(engine.lan.calls) == n
    status, data = call_json(server, "POST", "/api/tools/lan/throughput", raw=b"[]")
    assert status == 400

    status, data = call_json(server, "POST", "/api/tools/lan/throughput", {"peer": "10.0.0.99"})   # ValueError -> 400
    assert status == 400 and data["error"]["message"] == "10.0.0.99 is not a known peer"
    engine.lan.throughput_running = True
    status, data = call_json(server, "POST", "/api/tools/lan/throughput", {"peer": "10.0.0.42"})
    assert status == 409 and data["error"] == {"code": "conflict", "message": "a throughput test is already running"}
    status, data = call_json(server, "GET", "/api/tools/lan/throughput/last")
    assert status == 200 and data["running"] is True and data["result"]["seconds"] == 12
    engine.lan.throughput_running = False
    engine.lan.fail_with = RuntimeError("peer went away")
    status, data = call_json(server, "POST", "/api/tools/lan/throughput", {"peer": "10.0.0.42"})
    assert status == 500 and data["error"] == {"code": "internal_error", "message": "peer went away"}
    engine.lan.fail_with = None
    engine.lan.error = "UDP 7133 is in use"
    engine.lan.listening = False
    status, data = call_json(server, "GET", "/api/tools/lan/peers")
    assert status == 200 and data["listening"] is False and data["error"] == "UDP 7133 is in use"


def test_lan_settings_switch_route(server, engine):
    """PUT /api/tools/lan/settings: a JSON bool only, and the peers view comes straight back."""
    status, data = call_json(server, "PUT", "/api/tools/lan/settings", {"enabled": False})
    assert status == 200 and engine.lan.calls[-2:] == [("set_enabled", False), ("peers",)]
    assert engine.lan.enabled is False
    assert data == engine.lan.peers_view()                      # the peers view, not a bespoke reply
    assert set(data) == {"self", "peers", "listening", "error", "enabled"}
    assert data["enabled"] is False and data["listening"] is False and data["error"] == "disabled" and data["peers"] == []
    status, peers = call_json(server, "GET", "/api/tools/lan/peers")
    assert status == 200 and peers["enabled"] is False and peers["listening"] is False and peers["error"] == "disabled"

    status, data = call_json(server, "PUT", "/api/tools/lan/settings", {"enabled": True})
    assert status == 200 and engine.lan.calls[-2:] == [("set_enabled", True), ("peers",)]
    assert engine.lan.enabled is True
    assert data["enabled"] is True and data["listening"] is True and data["error"] is None
    assert data["peers"][0]["ip"] == "10.0.0.42"

    # enabled is a JSON boolean or nothing: "yes"/1/null must never switch discovery off (or on)
    n = len(engine.lan.calls)
    for bad, message in (({"enabled": "yes"}, "enabled must be true or false"),
                         ({"enabled": "true"}, "enabled must be true or false"),
                         ({"enabled": "false"}, "enabled must be true or false"),
                         ({"enabled": 1}, "enabled must be true or false"),
                         ({"enabled": 0}, "enabled must be true or false"),
                         ({"enabled": None}, "enabled must be true or false"),
                         ({"enabled": {}}, "enabled must be true or false"),
                         ({"enabled": []}, "enabled must be true or false"),
                         ({}, "nothing to update; accepted keys: enabled"),
                         ({"on": True}, "unknown LAN setting(s) on; accepted: enabled"),
                         ({"enabled": True, "bogus": 1}, "unknown LAN setting(s) bogus; accepted: enabled")):
        status, data = call_json(server, "PUT", "/api/tools/lan/settings", bad)
        assert status == 400 and data["error"] == {"code": "bad_request", "message": message}, bad
    status, data = call_json(server, "PUT", "/api/tools/lan/settings", raw=b"[]")
    assert status == 400 and data["error"]["code"] == "bad_request"
    assert len(engine.lan.calls) == n and engine.lan.enabled is True      # nothing reached the component

    # a component failure keeps the usual mapping (RuntimeError -> 500 with the message)
    engine.lan.fail_with = RuntimeError("could not save the setting: disk full")
    status, data = call_json(server, "PUT", "/api/tools/lan/settings", {"enabled": False})
    assert status == 500 and data["error"] == {"code": "internal_error", "message": "could not save the setting: disk full"}
    engine.lan.fail_with = None


def test_lan_routes_503_when_component_missing(server, engine):
    engine.lan = None
    for method, path, body in (("GET", "/api/tools/lan/peers", None),
                               ("POST", "/api/tools/lan/throughput", {"peer": "10.0.0.42"}),
                               ("PUT", "/api/tools/lan/settings", {"enabled": True}),
                               ("PUT", "/api/tools/lan/settings", {"enabled": "nonsense"}),
                               ("GET", "/api/tools/lan/throughput/last", None)):
        status, data = call_json(server, method, path, body)
        assert status == 503 and data["error"]["code"] == "unavailable", path
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["version"] == __version__


# ---------------------------------------------------------------------------
# GET /api/oui (vendor names for the WiFi tile; only 24-bit prefixes reach the service)
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_oui(monkeypatch):
    """``tnt.oui.vendor_for_oui`` backed by a synthetic registry; records every lookup."""
    from tnt import oui

    calls: List[str] = []
    registry = {"AC:DE:48": "Synthetic Networks Ltd", "00:00:5E": "Synthetic Standards Body"}

    def fake(prefix: str) -> Optional[str]:
        calls.append(prefix)
        return registry.get(prefix)

    monkeypatch.setattr(oui, "vendor_for_oui", fake)
    return calls


def test_request_query_all():
    req = Request("GET", "/x", query={"prefix": "b"}, raw_query="prefix=a&x=1&prefix=b&prefix=")
    assert req.query_all("prefix") == ["a", "b", ""] and req.query_all("x") == ["1"] and req.query_all("none") == []
    assert Request("GET", "/x", query={"prefix": "only"}).query_all("prefix") == ["only"], "built without a raw query"


def test_oui_route_repeated_and_comma_separated_prefixes(server, fake_oui):
    status, data = call_json(server, "GET", "/api/oui?prefix=ac:de:48&prefix=00-00-5e&prefix=02AABB")
    assert status == 200
    assert data == {"vendors": {"AC:DE:48": "Synthetic Networks Ltd", "00:00:5E": "Synthetic Standards Body", "02:AA:BB": None}}
    assert list(data["vendors"]) == ["AC:DE:48", "00:00:5E", "02:AA:BB"] and fake_oui == ["AC:DE:48", "00:00:5E", "02:AA:BB"]
    fake_oui.clear()
    status, data = call_json(server, "GET", "/api/oui?prefix=AC:DE:48,%2000:00:5E&prefix=ac-de-48")
    assert status == 200 and list(data["vendors"]) == ["AC:DE:48", "00:00:5E"] and fake_oui == ["AC:DE:48", "00:00:5E"], \
        "a prefix asked for twice is looked up once"
    status, data = call_json(server, "GET", "/api/oui?prefix=AC%3ADE%3A48")
    assert status == 200 and data == {"vendors": {"AC:DE:48": "Synthetic Networks Ltd"}}


@pytest.mark.parametrize("query, needle", [
    ("", "prefix is required"),
    ("?prefix=", "prefix is required"),
    ("?prefix=,%20,", "prefix is required"),
    ("?vendor=AC:DE:48", "prefix is required"),
    ("?prefix=AC:DE", "is not a 24-bit OUI prefix"),
    ("?prefix=AC:DE:48:00", "is not a 24-bit OUI prefix"),
    ("?prefix=AC:DE:48:00:11:22", "is not a 24-bit OUI prefix"),      # a whole MAC is refused, never cut down
    ("?prefix=AC:DE-48", "is not a 24-bit OUI prefix"),               # one separator style per prefix
    ("?prefix=AC.DE.48", "is not a 24-bit OUI prefix"),
    ("?prefix=ACDE4G", "is not a 24-bit OUI prefix"),
    ("?prefix=AC:DE:48&prefix=nope", "is not a 24-bit OUI prefix"),
])
def test_oui_route_rejects_malformed_prefixes(server, fake_oui, query, needle):
    status, data = call_json(server, "GET", "/api/oui" + query)
    assert status == 400 and data["error"]["code"] == "bad_request" and needle in data["error"]["message"], query
    assert fake_oui == []


def test_oui_route_takes_at_most_256_prefixes(server, fake_oui):
    many = [f"AC:{i // 256:02X}:{i % 256:02X}" for i in range(256)]
    status, data = call_json(server, "GET", "/api/oui?prefix=" + ",".join(many))
    assert status == 200 and len(data["vendors"]) == 256 and len(fake_oui) == 256
    status, data = call_json(server, "GET", "/api/oui?" + "&".join(f"prefix={p}" for p in many + ["AC:DF:00"]))
    assert status == 400 and data["error"]["message"] == "at most 256 prefixes per request, got 257"
    status, data = call_json(server, "GET", "/api/oui?prefix=" + ",".join(["AC:DE:48"] * 257))
    assert status == 400, "the limit counts what was sent, before duplicates are merged"


def test_oui_route_get_only_and_degrades(server, monkeypatch):
    from tnt import oui

    status, data = call_json(server, "POST", "/api/oui?prefix=AC:DE:48", {})
    assert status == 405 and data["error"]["code"] == "method_not_allowed"

    def boom(prefix):
        raise RuntimeError("registry corrupt")

    monkeypatch.setattr(oui, "vendor_for_oui", boom)
    status, data = call_json(server, "GET", "/api/oui?prefix=AC:DE:48")
    assert status == 200 and data == {"vendors": {"AC:DE:48": None}}, "one failed lookup is null, not a 500"
    monkeypatch.setitem(sys.modules, "tnt.oui", None)
    status, data = call_json(server, "GET", "/api/oui?prefix=AC:DE:48")
    assert status == 503 and data["error"]["code"] == "unavailable"
    status, data = call_json(server, "GET", "/api/oui?prefix=bad")
    assert status == 400, "input is validated before the lookup module is needed"


def test_vendor_for_oui_normalises_and_skips_unregistrable_prefixes():
    from tnt import oui

    assert [oui.normalize_oui(p) for p in ("00-00-5e", "00005E", " 00:00:5e ", "00:00-5E", "0000:5E", "00:00:5E:01", 7, None)] \
        == ["00:00:5E", "00:00:5E", "00:00:5E", None, None, None, None, None]
    name = oui.vendor_for_oui("00-00-5E")
    assert isinstance(name, str) and name and name == oui.vendor_for_oui("00005e"), "IANA's block is in netaddr's registry"
    for prefix in ("02:00:5E", "01:00:5E", "FF:FF:FF", "not-an-oui", None):
        assert oui.vendor_for_oui(prefix) is None, prefix


def test_dhcp_config_section_validation():
    cfg = tnt_config.validate({})
    assert cfg["dhcp"] == {"adapter": "", "pool_start": "", "pool_end": "", "pool_size": 5, "lease_s": 3600,
                           "static_ip": "172.16.4.100", "static_prefix": 24, "ping_check": True, "scan_wait_s": 8}
    cfg = tnt_config.validate({"dhcp": {"pool_size": 9999, "lease_s": 1, "static_prefix": 33, "scan_wait_s": 0.5,
                                        "ping_check": 0, "adapter": "  Ethernet 2 ",
                                        "pool_start": " 10.0.0.113 ", "pool_end": "10.0.0.117"}})
    assert cfg["dhcp"]["pool_size"] == 250 and cfg["dhcp"]["lease_s"] == 120
    assert cfg["dhcp"]["static_prefix"] == 30 and cfg["dhcp"]["scan_wait_s"] == 2
    assert cfg["dhcp"]["ping_check"] is False and cfg["dhcp"]["adapter"] == "Ethernet 2"
    assert cfg["dhcp"]["pool_start"] == "10.0.0.113" and cfg["dhcp"]["pool_end"] == "10.0.0.117"
    assert tnt_config.validate({"dhcp": {"static_prefix": 1, "scan_wait_s": 1000}})["dhcp"] == {
        **tnt_config.DEFAULTS["dhcp"], "static_prefix": 8, "scan_wait_s": 30}
    # bad / non-IPv4 addresses: pool bounds fall back to "" (automatic), the static address to the default
    cfg = tnt_config.validate({"dhcp": {"pool_start": "300.1.1.1", "pool_end": "fe80::1", "static_ip": "not an ip"}})
    assert cfg["dhcp"]["pool_start"] == "" and cfg["dhcp"]["pool_end"] == "" and cfg["dhcp"]["static_ip"] == "172.16.4.100"
    cfg = tnt_config.validate({"dhcp": {"pool_start": None, "pool_end": 42, "static_ip": "", "ping_check": "yes"}})
    assert cfg["dhcp"]["pool_start"] == "" and cfg["dhcp"]["pool_end"] == "" and cfg["dhcp"]["static_ip"] == "172.16.4.100"
    assert cfg["dhcp"]["ping_check"] is True
    cfg = tnt_config.validate({"dhcp": {"static_ip": "192.168.50.1", "pool_size": float("nan"), "lease_s": True,
                                        "scan_wait_s": float("inf")}})
    assert cfg["dhcp"]["static_ip"] == "192.168.50.1"
    assert cfg["dhcp"]["pool_size"] == 5 and cfg["dhcp"]["lease_s"] == 3600 and cfg["dhcp"]["scan_wait_s"] == 8
    # the on/off state is not a setting: an "enabled" key is kept as an unknown key but means nothing
    assert "enabled" not in tnt_config.DEFAULTS["dhcp"]


def test_query_and_body_validation_never_500s(server, engine, monkeypatch):
    """nan/inf/huge numbers, impossible dates and absurd JSON nesting are 400, not 500."""
    engine.ping.add_target("1.1.1.1")
    row = engine.db.add_target("1.1.1.1")
    for path in (
        "/api/targets/1/samples?seconds=inf",
        "/api/outages/timeline?hours=nan",
        "/api/outages/timeline?hours=inf",
        f"/api/targets/{row['id']}/history?from=1e19",
        f"/api/targets/{row['id']}/history?to=-5",
        "/api/outages?from=nan",
        "/api/speedtests?limit=inf",
        "/api/discovery/runs?limit=1e400",
    ):
        status, data = call_json(server, "GET", path)
        assert status == 400 and data["error"]["code"] == "bad_request", path
    # numbers within range still work and are clamped, not rejected
    status, data = call_json(server, "GET", "/api/outages/timeline?hours=999999")
    assert status == 200
    status, data = call_json(server, "GET", f"/api/targets/{row['id']}/history?from=100&to=200")
    assert status == 200 and data["from"] == 100.0 and data["to"] == 200.0

    fake = types.ModuleType("tnt.export_pdf")
    fake.range_bounds = lambda kind, now, custom_from=None, custom_to=None: (custom_from, custom_to)
    fake.build_report = lambda *a, **k: b"%PDF-1.4\n"
    monkeypatch.setitem(sys.modules, "tnt.export_pdf", fake)
    monkeypatch.setitem(sys.modules, "tnt.netinfo", None)
    for frm, to in (("0001-01-01", "2024-01-02"), ("2024-01-01", "9999-12-31"), ("nan", "2024-01-02"),
                    ("-1e300", "2024-01-02"), ("2024-13-45", "2024-01-02"), ("1e19", "1e19")):
        status, data = call_json(server, "POST", "/api/export", {"range": "custom", "from": frm, "to": to})
        assert status == 400 and data["error"]["code"] == "bad_request", (frm, to)
    status, headers, body = call(server, "POST", "/api/export", {"range": "custom", "from": "2024-01-01", "to": "2024-01-02"})
    assert status == 200 and body.startswith(b"%PDF")

    deep = b"[" * 200_000 + b"]" * 200_000
    status, data = call_json(server, "PUT", "/api/settings", raw=deep)
    assert status == 400 and "nesting" in data["error"]["message"]
    status, data = call_json(server, "POST", "/api/targets", raw=b"\xff\xfe\x00")
    assert status == 400


def test_status_degrades_when_a_component_raises(server, engine):
    class Broken:
        def status(self):
            raise RuntimeError("tracker exploded")

        def targets(self):
            raise RuntimeError("no targets for you")

        paused = False

    engine.ping.add_target("1.1.1.1")
    engine.outages = Broken()
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["outages"] is None and data["targets"][0]["host"] == "1.1.1.1"
    engine.ping = Broken()
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["targets"] == [] and data["monitoring"] is False and data["overall_light"] == "grey"


def test_unavailable_component_returns_503(server, engine):
    engine.speed = None
    status, data = call_json(server, "GET", "/api/speedtests")
    assert status == 503 and data["error"]["code"] == "unavailable"
    status, data = call_json(server, "POST", "/api/speedtests/run")
    assert status == 503
    engine.ping = None
    status, data = call_json(server, "GET", "/api/targets")
    assert status == 503 and data["error"]["code"] == "unavailable"
    status, data = call_json(server, "GET", "/api/status")  # status degrades instead of failing
    assert status == 200 and data["targets"] == [] and data["monitoring"] is False and data["speed"] is None


def test_netinfo_route_is_lazy(server, monkeypatch):
    fake = types.ModuleType("tnt.netinfo")
    fake.netinfo_snapshot = lambda: {"ts": T0, "adapters": [], "internet_nic_index": None, "default_gateway": None, "public_hint": None}
    monkeypatch.setitem(sys.modules, "tnt.netinfo", fake)
    status, data = call_json(server, "GET", "/api/netinfo")
    assert status == 200 and data["adapters"] == [] and data["ts"] == T0
    assert data["generation"] == 0 and data["changed_ts"] is None      # no network watcher on this engine
    monkeypatch.setitem(sys.modules, "tnt.netinfo", None)
    status, data = call_json(server, "GET", "/api/netinfo")
    assert status == 503 and data["error"]["code"] == "unavailable"


def test_status_and_netinfo_carry_the_network_generation(server, engine, monkeypatch):
    from tnt import diagnostics

    fake = types.ModuleType("tnt.netinfo")
    fake.netinfo_snapshot = lambda: {"ts": T0, "adapters": [], "internet_nic_index": 12, "default_gateway": "10.20.30.1",
                                     "public_hint": None}
    monkeypatch.setitem(sys.modules, "tnt.netinfo", fake)
    summary = "Ethernet 2: 10.20.30.45/24 · gateway 10.20.30.1"
    engine.netwatch = SimpleNamespace(
        state=lambda: {"generation": 3, "changed_ts": T0 + 60, "default_gateway": "10.20.30.1", "internet_nic": "Ethernet 2",
                       "summary": summary, "networks": ["10.20.30.0/24", "172.16.20.0/24"], "running": True, "poll_s": 5.0,
                       "polls": 40, "failures": 0, "last_error": None, "pending": False},
        last_event=lambda: {"generation": 3, "summary": summary})
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200
    # the summary is what a page that missed the event shows; the networks tell a scan of this PC's subnets from another's
    assert data["net"] == {"generation": 3, "changed_ts": T0 + 60, "default_gateway": "10.20.30.1", "internet_nic": "Ethernet 2",
                           "summary": summary, "networks": ["10.20.30.0/24", "172.16.20.0/24"], "network_id": None}
    status, data = call_json(server, "GET", "/api/netinfo")
    assert status == 200 and data["generation"] == 3 and data["changed_ts"] == T0 + 60 and data["default_gateway"] == "10.20.30.1"
    net = diagnostics.collect(engine)["network"]
    assert net["available"] is True and net["generation"] == 3 and net["last_change"]["summary"] == summary
    # a watcher whose state() fails degrades to the netinfo summary: never a 500
    def broken():
        raise RuntimeError("watcher exploded")

    engine.netwatch = SimpleNamespace(state=broken)
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200
    assert data["net"] == {"generation": 0, "changed_ts": None, "default_gateway": "10.0.0.251", "internet_nic": "Ethernet",
                           "summary": None, "networks": [], "network_id": None}
    status, data = call_json(server, "GET", "/api/netinfo")
    assert status == 200 and data["generation"] == 0 and data["changed_ts"] is None
    engine.netwatch = None
    assert diagnostics.collect(engine)["network"] == {"available": False}


# ---------------------------------------------------------------------------
# SSE
# ---------------------------------------------------------------------------
def _read_sse_frames(port: int, want: str, frames: List[str], ready: threading.Event, timeout: float = 10.0) -> None:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", "/api/events")
        resp = conn.getresponse()
        frames.append(f"__status__ {resp.status} {resp.getheader('Content-Type')} {resp.getheader('Cache-Control')}")
        buf: List[str] = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = resp.readline()
            if not line:
                break
            text = line.decode("utf-8")
            buf.append(text)
            if text in ("\n", "\r\n"):
                frame = "".join(buf)
                buf = []
                frames.append(frame)
                if "event: hello" in frame:
                    ready.set()
                if want in frame:
                    break
    finally:
        conn.close()


def test_sse_stream_delivers_hello_and_published_event(server, engine):
    frames: List[str] = []
    ready = threading.Event()
    t = threading.Thread(target=_read_sse_frames, args=(server.port, "event: ping.sample", frames, ready), daemon=True)
    t.start()
    assert ready.wait(10), frames
    assert server.clients_sse == 1
    engine.bus.publish("ping.sample", {"target_id": 1, "ok": True, "rtt_ms": 12.5, "light": "green"}, ts=T0)
    t.join(10)
    assert not t.is_alive(), frames

    assert frames[0].startswith("__status__ 200 text/event-stream") and "no-cache" in frames[0]
    hello = next(f for f in frames if "event: hello" in f)
    assert "retry: 3000" in hello
    data = json.loads(hello.split("data: ", 1)[1].strip())
    assert data["version"] == __version__ and isinstance(data["ts"], float)

    sample = next(f for f in frames if "event: ping.sample" in f)
    payload = json.loads(sample.split("data: ", 1)[1].strip())
    assert payload == {"target_id": 1, "ok": True, "rtt_ms": 12.5, "light": "green", "ts": T0}

    deadline = time.time() + 5
    while server.clients_sse and time.time() < deadline:
        time.sleep(0.05)
    assert server.clients_sse == 0


def test_sse_client_is_kicked_on_server_stop(engine, ui_dir):
    srv = ApiServer(engine, "127.0.0.1", 0, bus=engine.bus, ui_dir=ui_dir)
    srv.start()
    frames: List[str] = []
    ready = threading.Event()
    t = threading.Thread(target=_read_sse_frames, args=(srv.port, "event: never", frames, ready, 15.0), daemon=True)
    t.start()
    assert ready.wait(10)
    t0 = time.monotonic()
    srv.stop()
    t.join(5)
    assert not t.is_alive() and time.monotonic() - t0 < 5.0


def test_sse_hub_never_blocks_and_drops_oldest():
    bus = tnt_events.EventBus()
    hub = SseHub(bus, maxsize=3)
    assert hub.attached
    q = hub.subscribe()
    t0 = time.perf_counter()
    for i in range(10):
        bus.publish("e", {"i": i})
    assert time.perf_counter() - t0 < 1.0
    items = []
    while True:
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            break
    assert [it["data"]["i"] for it in items] == [7, 8, 9]
    assert hub.dropped == 7 and hub.published == 10 and hub.client_count() == 1
    hub.close()
    assert not hub.attached and q.get_nowait() is None  # STOP sentinel wakes the client loop
    bus.publish("e", {"i": 99})
    assert q.empty()


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------
def test_export_returns_pdf_with_injected_module(server, engine, monkeypatch, data_dir):
    fake = types.ModuleType("tnt.export_pdf")
    calls: Dict[str, Any] = {}

    def range_bounds(kind, now, custom_from=None, custom_to=None):
        calls["range"] = (kind, custom_from, custom_to)
        return (now - 86400, now) if kind != "custom" else (custom_from, custom_to)

    def build_report(db, start_ts, end_ts, *, title="TNT Network Report", targets=None, netinfo=None, tz_offset_s=None):
        calls["build"] = (db, start_ts, end_ts, targets, tz_offset_s)
        return b"%PDF-1.4\n%fake report\n%%EOF\n"

    fake.range_bounds = range_bounds
    fake.build_report = build_report
    monkeypatch.setitem(sys.modules, "tnt.export_pdf", fake)
    monkeypatch.setitem(sys.modules, "tnt.netinfo", None)  # no adapter scan during the test
    engine.ping.add_target("1.1.1.1")

    status, headers, body = call(server, "POST", "/api/export", {"range": "daily"})
    assert status == 200
    assert headers["content-type"] == "application/pdf"
    assert body.startswith(b"%PDF") and int(headers["content-length"]) == len(body)
    assert re.fullmatch(r"attachment; filename=TNT-report-\d{8}-\d{8}\.pdf", headers["content-disposition"])
    assert calls["build"][0] is engine.db and calls["build"][3][0]["host"] == "1.1.1.1"
    assert isinstance(calls["build"][4], int)
    saved = list((data_dir / "exports").glob("TNT-report-*.pdf"))
    assert saved and saved[0].read_bytes() == body

    status, headers, body = call(server, "POST", "/api/export", {"range": "custom", "from": "2024-01-01", "to": "2024-01-07"})
    assert status == 200 and "TNT-report-20240101-20240107.pdf" in headers["content-disposition"]
    status, data = call_json(server, "POST", "/api/export", {"range": "custom"})
    assert status == 400
    status, data = call_json(server, "POST", "/api/export", {"range": "hourly"})
    assert status == 400

    monkeypatch.setitem(sys.modules, "tnt.export_pdf", None)  # import raises ImportError -> 503
    status, data = call_json(server, "POST", "/api/export", {"range": "weekly"})
    assert status == 503 and data["error"]["code"] == "unavailable"


# ---------------------------------------------------------------------------
# diagnostics
# ---------------------------------------------------------------------------
def test_diagnostics_collect_shape_and_isolated_failures(server, engine, data_dir):
    from tnt import diagnostics

    engine.ping.add_target("1.1.1.1")
    d = diagnostics.collect(engine)
    for key in ("service", "os", "api", "db", "logs", "ping", "outages", "speedtest", "discovery",
                "threads", "memory_mb", "cpu_pct", "recent_log", "recent_events", "errors_24h"):
        assert key in d, key
    assert d["service"]["version"] == __version__ and d["service"]["mode"] == "console"
    assert d["service"]["pid"] == os.getpid() and d["service"]["data_dir"] == str(data_dir)
    assert d["os"]["hostname"] == socket.gethostname() and "caption" in d["os"]
    assert d["api"]["port"] == server.port and d["api"]["clients_sse"] == 0 and d["api"]["running"] is True
    assert d["db"]["counts"]["targets"] == 0 and d["db"]["size_bytes"] > 0
    assert d["logs"]["dir"] == str(data_dir / "logs") and d["logs"]["ping_log_files"] == 0
    assert d["ping"]["paused"] is False and d["ping"]["targets"][0]["host"] == "1.1.1.1"
    assert set(d["ping"]["targets"][0]) >= {"id", "host", "ip", "kind", "thread_alive", "last_ts", "light"}
    assert d["outages"]["count_24h"] == 0 and d["outages"]["open"] == []
    assert d["speedtest"]["selected"] == "cloudflare" and d["speedtest"]["running"] is False
    assert [b["name"] for b in d["speedtest"]["backends"]] == ["cloudflare", "fastcom"]
    assert d["discovery"]["running"] is False and d["discovery"]["available"] is True
    assert set(d["discovery"]) == {"available", "running", "progress", "last_run_ts"}   # + last_run once a run exists
    assert any(t["name"] == "tnt-api" and t["alive"] and t["daemon"] for t in d["threads"])
    assert isinstance(d["memory_mb"], float) and d["memory_mb"] > 1
    assert isinstance(d["cpu_pct"], float)
    assert isinstance(d["recent_log"], list) and isinstance(d["recent_events"], list)
    assert isinstance(d["errors_24h"], int)
    assert d["geoip"] == {"available": False, "status": None, "files": []}

    class BrokenDb:
        path = "broken"

        def size_bytes(self):
            raise RuntimeError("boom")

    engine.db = BrokenDb()
    d2 = diagnostics.collect(engine)
    assert "boom" in d2["db"]["error"]
    assert "error" not in d2["service"] and "error" not in d2["ping"]

    status, data = call_json(server, "GET", "/api/diagnostics")
    assert status == 200 and "boom" in data["db"]["error"] and data["api"]["port"] == server.port


def test_diagnostics_tail_log(server, data_dir):
    from tnt import diagnostics

    log_file = data_dir / "logs" / "tnt-service.log"
    log_file.write_text("".join(f"line {i}\n" for i in range(300)), encoding="utf-8")
    out = diagnostics.tail_log(5)
    assert out["file"] == str(log_file) and out["lines"] == [f"line {i}" for i in range(295, 300)]
    assert diagnostics.tail_log(1000)["lines"][0] == "line 0"
    missing = diagnostics.tail_log(10, data_dir / "nope.log")
    assert missing["lines"] == [] and missing["exists"] is False

    status, data = call_json(server, "GET", "/api/diagnostics/log?lines=3")
    assert status == 200 and data["lines"] == ["line 297", "line 298", "line 299"] and data["file"] == str(log_file)


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------
def test_engine_overall_light(data_dir):
    from tnt.engine import Engine

    eng = Engine(console=True, port=0, data_dir=data_dir)
    assert os.environ["TNT_DATA_DIR"] == str(data_dir)
    assert eng.overall_light() == "grey"
    eng.ping = FakePing()
    assert eng.overall_light() == "grey"
    eng.ping.add_target("a")
    eng.ping.add_target("b")
    assert eng.overall_light() == "green"
    eng.ping.views[2]["light"] = "yellow"
    assert eng.overall_light() == "yellow"
    # a single target being down is only "yellow": red is reserved for a full outage
    eng.ping.views[1]["light"] = "red"
    assert eng.overall_light() == "yellow"
    eng.outages = SimpleNamespace(status=lambda: {"total_active": {"kind": "total_internet"}, "active": []})
    assert eng.overall_light() == "red"
    eng.outages = SimpleNamespace(status=lambda: {"total_active": None, "active": []})
    assert eng.overall_light() == "yellow"
    eng.ping.set_paused(True)
    assert eng.overall_light() == "grey"


def _wait_for(pred, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


#: what Engine.discovery_status() (GET /api/discovery/status) returns
DISCOVERY_STATUS_KEYS = {"available", "running", "progress", "range", "ports", "started_ts", "last_run", "default_range",
                         "default_ports"}


def test_engine_discovery_flow(data_dir):
    from tnt.engine import Engine

    eng = Engine(console=True, port=0, data_dir=data_dir)
    eng.config = tnt_config.Config(data_dir / "config.json").load()
    eng.db = tnt_db.Database(data_dir / "tnt.db")
    eng.bus = tnt_events.EventBus()
    eng.discovery = FakeDiscovery(block=True)
    events: List[Dict[str, Any]] = []
    eng.bus.subscribe(lambda e: events.append(e))
    try:
        with pytest.raises(ValueError):
            eng.discovery_start("bad range", None)
        assert eng.discovery_start(None, None) is True  # default range + default ports
        st = eng.discovery_status()
        # the exact key set; tools/mock_api.py returns the same one (tests/test_ui.py)
        assert set(st) == DISCOVERY_STATUS_KEYS
        assert st["running"] is True and st["range"] == "10.0.0.0/24" and st["ports"] == eng.config.get("discovery.ports")
        assert st["default_range"] == "10.0.0.0/24" and st["last_run"] is None
        assert eng.discovery_start("10.0.0.0/30", [80]) is False  # already running
        assert _wait_for(lambda: any(e["type"] == "discovery.progress" for e in events))
        eng._on_net_changed({"generation": 1, "summary": "Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"})   # moved mid-scan
        assert eng.discovery_cancel() is True
        assert _wait_for(lambda: any(e["type"] == "discovery.done" for e in events))
        done = next(e for e in events if e["type"] == "discovery.done")
        assert done["data"]["cancelled"] is True and done["data"]["run_id"] == 1 and done["data"]["found"] == 0
        assert done["data"]["network_changed"] is True
        assert eng.discovery.stopped is True
        assert _wait_for(lambda: not eng.discovery_status()["running"])

        eng.discovery = FakeDiscovery()
        events.clear()
        assert eng.discovery_start("10.0.0.0/30", [80, 443]) is True
        assert _wait_for(lambda: any(e["type"] == "discovery.done" for e in events))
        done = next(e for e in events if e["type"] == "discovery.done")
        assert done["data"] == {**done["data"], "run_id": 2, "ok": True, "cancelled": False, "found": 1, "cidr": "10.0.0.0/30",
                                "network_changed": False}
        run = eng.db.get_discovery_run(2)
        assert run["cidr"] == "10.0.0.0/30" and run["ports"] == [80, 443] and run["hosts"][0]["ip"] == "10.0.0.1"
        assert run["hosts"][0]["vendor"] == "ACME" and run["found"] == 1
        st = eng.discovery_status()
        assert st["running"] is False and st["last_run"]["id"] == 2 and st["last_run"]["found"] == 1
        assert set(st) == DISCOVERY_STATUS_KEYS and st["started_ts"] is None
        assert set(st["last_run"]) == {"id", "ts", "cidr", "found", "duration_s", "ok", "error"}
        assert [e["type"] for e in events][:2] == ["discovery.start", "discovery.progress"]
        assert eng.discovery_cancel() is False
        assert any("discovery" == e["category"] for e in eng.db.list_events(10))
    finally:
        eng.db.close()


def test_engine_on_net_changed_resets_caches_and_tells_every_component(data_dir):
    from tnt.engine import Engine

    eng = Engine(console=True, port=0, data_dir=data_dir)
    eng.db = tnt_db.Database(data_dir / "tnt.db")
    calls: List[Any] = []

    class Component:
        def __init__(self, name: str, fail: bool = False) -> None:
            self.name, self.fail = name, fail

        def on_network_change(self, data: Dict[str, Any]) -> None:
            calls.append((self.name, data["generation"]))
            if self.fail:
                raise RuntimeError("boom")

    eng.ping, eng.linkmap, eng.lan, eng.dhcp = Component("ping", fail=True), Component("linkmap"), Component("lan"), Component("dhcp")
    eng.outages = Component("outages")
    eng._netinfo_cache, eng._netinfo_cache_ts = {"internet_nic": {"name": "Wi-Fi"}, "adapter_count": 2}, time.time()
    eng._disc_defaults, eng._disc_defaults_ts = {"default_range": "192.168.10.0/24"}, time.time()
    release = threading.Event()
    eng._disc_thread = threading.Thread(target=release.wait, args=(5.0,), daemon=True)
    eng._disc_thread.start()
    try:
        eng._on_net_changed({"generation": 4, "ts": T0, "summary": "Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"})
        assert calls == [("ping", 4), ("outages", 4), ("linkmap", 4), ("lan", 4), ("dhcp", 4)], \
            "a failing component never stops the rest"
        assert eng._netinfo_cache is None and eng._netinfo_cache_ts == 0.0
        assert eng._disc_defaults == {} and eng._disc_defaults_ts == 0.0 and eng._disc_net_changed is True
        assert _wait_for(lambda: any(e["category"] == "network" for e in eng.db.list_events(10)))
        row = next(e for e in eng.db.list_events(10) if e["category"] == "network")
        assert row["level"] == "info" and row["message"] == "network changed: Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"
        assert row["ts"] == T0, "stamped with the change, not with whenever the database took the row"
    finally:
        release.set()
        eng.db.close()


def test_engine_network_rows_are_coalesced_while_the_network_flaps(data_dir, monkeypatch):
    from tnt.engine import Engine

    monkeypatch.setattr(Engine, "NET_EVENT_ROW_GAP_S", 0.6)
    eng = Engine(console=True, port=0, data_dir=data_dir)
    eng.db = tnt_db.Database(data_dir / "tnt.db")

    def rows() -> List[Dict[str, Any]]:
        return [e for e in eng.db.list_events(20) if e["category"] == "network"]

    try:
        eng._on_net_changed({"generation": 1, "ts": T0, "summary": "Wi-Fi disconnected · No network connection"})
        assert _wait_for(lambda: len(rows()) == 1)
        for gen in (2, 3, 4):                                   # the network keeps flapping within the gap
            eng._on_net_changed({"generation": gen, "ts": T0 + gen, "summary": f"Wi-Fi: 192.168.50.{gen}/24 · gateway 192.168.50.1"})
        time.sleep(0.2)
        assert len(rows()) == 1, "held back while the gap runs"
        assert _wait_for(lambda: len(rows()) == 2, 3.0), "one row for all of them when it is up"
        newest = rows()[0]
        assert newest["message"] == "network changed 3 more times, now: Wi-Fi: 192.168.50.4/24 · gateway 192.168.50.1"
        assert newest["ts"] == T0 + 4
        # one change held back reads like any other, and stop() writes what is still held back
        eng._on_net_changed({"generation": 5, "ts": T0 + 5, "summary": "Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"})
        eng._flush_net_rows()
        assert rows()[0]["message"] == "network changed: Ethernet: 10.20.30.45/24 · gateway 10.20.30.1" and len(rows()) == 3
        assert eng._net_row_timer is None and eng._net_row_pending is None
    finally:
        eng._flush_net_rows()
        eng.db.close()


def test_engine_sleep_gap_wakes_the_network_watcher(data_dir):
    from tnt.engine import Engine

    eng = Engine(console=True, port=0, data_dir=data_dir)
    pokes: List[str] = []
    eng.netwatch = SimpleNamespace(poll_soon=lambda: pokes.append("poke"))
    eng._monitoring_gap(T0, T0 + 3600, "system sleep")
    assert pokes == ["poke"]
    eng._monitoring_gap(T0, T0 + 60, "monitoring paused")
    assert pokes == ["poke"], "only a sleep can have carried the machine to another network"


def test_engine_start_and_stop_smoke(data_dir):
    """Real Engine with whatever sibling modules exist; missing ones must degrade, not crash."""
    from tnt.engine import Engine

    seed = tnt_db.Database(data_dir / "tnt.db")
    seed.set_meta("defaults_loaded", "1")  # never auto-add real targets during tests
    seed.set_meta("last_heartbeat", str(time.time() - 600))
    stale = seed.open_outage("target", 1, time.time() - 900)
    seed.close()

    eng = Engine(console=True, port=0, data_dir=data_dir)
    t0 = time.monotonic()
    eng.start()
    try:
        assert time.monotonic() - t0 < 10.0
        assert eng.running and eng.config is not None and eng.db is not None and eng.bus is not None
        assert eng.api is not None and eng.api.running and eng.api.port not in (0, 7130)
        assert eng.config.get("api.port") == 7130  # port 0 cannot live in the config
        status, data = call_json(eng.api, "GET", "/api/status")
        assert status == 200 and data["version"] == __version__ and data["mode"] == "console"
        assert data["overall_light"] in ("green", "yellow", "red", "grey")
        status, data = call_json(eng.api, "GET", "/api/health")
        assert data == {"ok": True}
        status, data = call_json(eng.api, "GET", "/api/diagnostics")
        assert status == 200 and data["service"]["mode"] == "console"
        assert _wait_for(lambda: float(eng.db.get_meta("last_heartbeat")) > time.time() - 60)
        assert eng.db.get_outage(stale)["end_ts"] is not None  # closed at startup
        assert any(o["kind"] == "gap" for o in eng.db.list_outages(time.time() - 3600, time.time()))
        assert _wait_for(lambda: any("started" in e["message"] for e in eng.db.list_events(20)))
        assert eng.discovery_status()["running"] is False
        # the DHCP server tool is constructed but never listening after a start (or its
        # module is missing/broken, which only degrades that feature)
        if eng.dhcp is not None:
            assert eng.dhcp.running is False
            status, data = call_json(eng.api, "GET", "/api/dhcp/status")
            assert status == 200 and data["running"] is False
        else:
            assert "dhcp" in eng.errors
        assert eng.db.get_meta("dhcp.nic_changed") in (None, "")
        # the network watcher runs from the start and /api/status carries its generation
        assert eng.netwatch is not None and eng.netwatch.running and "netwatch" not in eng.errors
        status, data = call_json(eng.api, "GET", "/api/status")
        assert isinstance(data["net"]["generation"], int) and set(data["net"]) == {"generation", "changed_ts",
                                                                                   "default_gateway", "internet_nic",
                                                                                   "summary", "networks", "network_id"}
        # the network tracker runs from the start, before every writer
        assert eng.networks is not None and "networks" not in eng.errors
        assert data["net"]["network_id"] == eng.networks.current_network_id()
        # site reports: the manager runs from the start (no scan) and its routes answer
        assert eng.reports is not None and "reports" not in eng.errors
        assert data["reports"] == {"count": 0, "sites": 0, "last": None, "job": None}
        status, data = call_json(eng.api, "GET", "/api/reports")
        assert status == 200 and data == {"reports": [], "total": 0}
        status, data = call_json(eng.api, "GET", "/api/reports/scan")
        assert status == 200 and data == {"job": None}
        # IP location: the manager runs from the start on the data folder (its first check waits; tests are offline)
        from tnt import geoip, paths

        assert eng.geoip is not None and "geoip" not in eng.errors and paths.geoip_dir() == data_dir / "geoip"
        status, data = call_json(eng.api, "GET", "/api/status")
        assert data["geoip"]["state"] in ("starting", "error", "ready") and set(data["geoip"]) == set(geoip.STATUS_KEYS)
        assert "public_geo" in data["map"]
        assert eng.start() is None  # idempotent
    finally:
        t1 = time.monotonic()
        eng.stop()
        assert time.monotonic() - t1 < 8.5
    assert not eng.running and not eng.api.running
    eng.stop()  # idempotent
    check = tnt_db.Database(data_dir / "tnt.db")
    try:
        assert any("stopped" in e["message"] for e in check.list_events(5))
        assert float(check.get_meta("last_heartbeat")) > time.time() - 60
    finally:
        check.close()
    assert not any(t.name in ("tnt-api", "tnt-maint", "tnt-netwatch", "tnt-reports-scan") and t.is_alive()
                   for t in threading.enumerate())
    assert _wait_for(lambda: not any(t.name == "tnt-geoip" and t.is_alive() for t in threading.enumerate()), 3.0)


def test_engine_wires_dhcp_restore_construct_and_stop(data_dir, monkeypatch):
    """Start order: dhcp-restore (before the pinger) -> ... -> DhcpServer constructed with the
    db/config/bus/pinger and the firewall program path; stop() stops it after the API."""
    from tnt import engine as engine_mod
    from tnt.engine import Engine

    seed = tnt_db.Database(data_dir / "tnt.db")
    seed.set_meta("defaults_loaded", "1")
    seed.set_meta("dhcp.nic_changed", json.dumps({"adapter": "Ethernet", "index": 12, "mac": "00:00:5E:00:53:10",
                                                  "static_ip": "172.16.4.100", "prefix": 24, "ts": T0}))
    seed.close()

    order: List[str] = []
    fake = types.ModuleType("tnt.dhcp")

    class FakeDhcpServer(FakeDhcp):
        def __init__(self, db, config, bus, pinger=None, clock=time.time, **kw):
            super().__init__()
            self.ctor = {"db": db, "config": config, "bus": bus, "pinger": pinger, **kw}
            order.append("construct")

        def stop(self, restore_nic: bool = True):
            order.append("stop")
            return super().stop(restore_nic)

    def restore_nic_on_start(db, runner=None):
        order.append("restore")
        rec = json.loads(db.get_meta("dhcp.nic_changed") or "{}")
        db.set_meta("dhcp.nic_changed", "")
        return {"adapter": rec.get("adapter"), "restored": True}

    fake.DhcpServer = FakeDhcpServer
    fake.restore_nic_on_start = restore_nic_on_start
    fake.DhcpConflict = DhcpConflictLike
    monkeypatch.setitem(sys.modules, "tnt.dhcp", fake)
    real_start_pinger = Engine._start_pinger
    monkeypatch.setattr(Engine, "_start_pinger", lambda self: (order.append("pinger"), real_start_pinger(self)) and None)

    eng = Engine(console=True, port=0, data_dir=data_dir)
    eng.start()
    try:
        assert order == ["restore", "pinger", "construct"]
        assert "dhcp" not in eng.errors and "dhcp-restore" not in eng.errors
        # the lease returning for the restored adapter is labelled as TNT's own change for a while
        assert eng.netwatch is not None and eng.netwatch._own_marker()["adapter"] == "Ethernet"
        assert eng.netwatch._own_marker()["phase"] == "restored"
        assert isinstance(eng.dhcp, FakeDhcpServer)
        assert eng.dhcp.ctor["db"] is eng.db and eng.dhcp.ctor["config"] is eng.config and eng.dhcp.ctor["bus"] is eng.bus
        assert eng.dhcp.ctor["pinger"] is eng.pinger
        assert eng.dhcp.ctor["exe_path"] == Engine._dhcp_exe_path() and os.path.isfile(eng.dhcp.ctor["exe_path"])
        assert eng.db.get_meta("dhcp.nic_changed") in (None, "")
        assert any(e["category"] == "dhcp" and "restored" in e["message"] for e in eng.db.list_events(20))
        status, data = call_json(eng.api, "GET", "/api/status")
        assert data["dhcp"]["running"] is False and data["dhcp"]["adapter"] == "Ethernet"
        status, data = call_json(eng.api, "POST", "/api/dhcp/start", {"force": True})
        assert status == 200 and data["running"] is True
    finally:
        eng.stop()
    assert order[-1] == "stop" and eng.dhcp.running is False and eng.dhcp.calls[-1] == ("stop", True)
    # firewall program path: the frozen exe itself; in a dev run the *base* interpreter (the
    # image Windows Firewall matches) is preferred over the venv launcher when it exists
    monkeypatch.setattr(engine_mod.paths, "is_frozen", lambda: True)
    assert Engine._dhcp_exe_path() == sys.executable
    monkeypatch.setattr(engine_mod.paths, "is_frozen", lambda: False)
    base = data_dir / "base-python.exe"
    base.write_bytes(b"MZ")
    monkeypatch.setattr(sys, "_base_executable", str(base), raising=False)
    assert Engine._dhcp_exe_path() == str(base)
    monkeypatch.setattr(sys, "_base_executable", str(data_dir / "missing.exe"), raising=False)
    assert Engine._dhcp_exe_path() == sys.executable   # a base path that does not exist is not used
    monkeypatch.setattr(sys, "_base_executable", sys.executable, raising=False)
    assert Engine._dhcp_exe_path() == sys.executable


def test_engine_dhcp_skipped_without_db_and_started_after_retry(data_dir, monkeypatch):
    from tnt import engine as engine_mod
    from tnt.engine import Engine

    fake = types.ModuleType("tnt.dhcp")
    calls: List[str] = []
    fake.DhcpServer = lambda db, config, bus, pinger=None, **kw: (calls.append("construct"), FakeDhcp())[1]
    fake.restore_nic_on_start = lambda db, runner=None: calls.append("restore")
    monkeypatch.setitem(sys.modules, "tnt.dhcp", fake)
    monkeypatch.setattr(Engine, "DB_RETRY_S", 0.2)

    attempts = {"n": 0}
    from tnt import db as db_mod

    real_cls = db_mod.Database

    def flaky(path, *a, **k):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("database is locked by a backup tool")
        db = real_cls(path, *a, **k)
        db.set_meta("defaults_loaded", "1")   # never auto-add real targets during tests
        return db

    monkeypatch.setattr(db_mod, "Database", flaky)   # the engine imports it lazily on every open
    assert engine_mod.Engine is Engine
    eng = Engine(console=True, port=0, data_dir=data_dir)
    eng.start()
    try:
        assert eng.db is None and eng.dhcp is None
        assert eng.errors["dhcp"] == "database unavailable" and calls == []
        assert eng.reports is None and eng.errors["reports"] == "database unavailable"
        assert _wait_for(lambda: eng.db is not None and eng.dhcp is not None, 5.0)
        assert calls == ["restore", "construct"] and "dhcp" not in eng.errors
        assert _wait_for(lambda: eng.reports is not None, 5.0) and "reports" not in eng.errors
    finally:
        eng.stop()


def test_engine_api_bind_failure_retries_in_background(data_dir, monkeypatch):
    from tnt import engine as engine_mod
    from tnt.engine import Engine

    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    seed = tnt_db.Database(data_dir / "tnt.db")
    seed.set_meta("defaults_loaded", "1")
    seed.close()
    monkeypatch.setattr(engine_mod, "API_RETRY_INTERVAL_S", 0.2)
    eng = Engine(console=True, port=port, data_dir=data_dir)
    eng.start()
    try:
        assert eng.running and eng.api is not None and not eng.api.running
        assert eng.api_error and f"findstr :{port}" in eng.api_error
        assert eng.config.get("api.port") == 7130  # the override never touches the config
        assert not (data_dir / "config.json").exists() or json.loads((data_dir / "config.json").read_text())["api"]["port"] == 7130
        assert any(t.name == "tnt-api-retry" for t in threading.enumerate())
        blocker.close()
        assert _wait_for(lambda: eng.api.running and eng.api_error is None, 5.0)
        status, data = call_json(eng.api, "GET", "/api/health")
        assert data == {"ok": True}
        assert eng.api.port == port
        # regression: a PUT /settings from a dev/console run must not persist the
        # overridden port into the (possibly shared) service config.json
        status, data = call_json(eng.api, "PUT", "/api/settings", {"ui": {"theme": "dark"}})
        assert status == 200 and data["changed"] == ["ui.theme"] and data["settings"]["api"]["port"] == 7130
        assert json.loads((data_dir / "config.json").read_text(encoding="utf-8"))["api"]["port"] == 7130
    finally:
        blocker.close()
        eng.stop()


def test_engine_discovery_cancel_does_not_block_on_scanner_stop(data_dir):
    """DiscoveryScanner.stop() waits up to 5 s for the scan to end; neither the API
    request nor Engine.stop() may hang on it (the cancel event does the real work)."""
    from tnt.engine import Engine

    class SlowStopDiscovery(FakeDiscovery):
        def __init__(self) -> None:
            super().__init__(block=True)
            self.stop_calls = 0

        def stop(self, timeout: float = 5.0) -> bool:
            self.stop_calls += 1
            time.sleep(4.0)
            return True

    eng = Engine(console=True, port=0, data_dir=data_dir)
    eng.config = tnt_config.Config(data_dir / "config.json").load()
    eng.db = tnt_db.Database(data_dir / "tnt.db")
    eng.bus = tnt_events.EventBus()
    eng.discovery = SlowStopDiscovery()
    events: List[Dict[str, Any]] = []
    eng.bus.subscribe(lambda e: events.append(e))
    try:
        assert eng.discovery_start("10.0.0.0/30", [80]) is True
        assert _wait_for(lambda: any(e["type"] == "discovery.progress" for e in events))
        t0 = time.monotonic()
        assert eng.discovery_cancel() is True
        assert time.monotonic() - t0 < 2.5
        assert _wait_for(lambda: any(e["type"] == "discovery.done" for e in events))
        assert next(e for e in events if e["type"] == "discovery.done")["data"]["cancelled"] is True
        assert _wait_for(lambda: eng.discovery.stop_calls == 1, 6.0)
        assert _wait_for(lambda: not eng.discovery_status()["running"])
        with pytest.raises(ValueError):
            eng.discovery_start("10.0.0.0/30", [80, 70000])  # engine validates ports too
        with pytest.raises(ValueError):
            eng.discovery_start("10.0.0.0/30", ["x"])
    finally:
        eng.db.close()


def test_engine_stop_is_bounded_when_db_close_hangs(data_dir, monkeypatch):
    """A VACUUM in flight holds the db lock: stop() must not wait on db.close() forever."""
    from tnt.engine import Engine

    seed = tnt_db.Database(data_dir / "tnt.db")
    seed.set_meta("defaults_loaded", "1")
    seed.close()
    eng = Engine(console=True, port=0, data_dir=data_dir)
    eng.start()
    assert eng.api is not None and eng.api.running
    real_close = eng.db.close

    def slow_close() -> None:
        time.sleep(6.0)
        real_close()

    monkeypatch.setattr(eng.db, "close", slow_close)
    t0 = time.monotonic()
    eng.stop()
    assert time.monotonic() - t0 < 5.0
    assert not eng.running and not eng.api.running


def test_clock_jump_guard():
    from tnt.engine import _clock_jumped

    assert not _clock_jumped(1000.0 + 30.0, 1000.0, 60.0)      # normal: 30 s ahead
    assert not _clock_jumped(1000.0 - 5.0, 1000.0, 60.0)       # overdue is fine
    assert _clock_jumped(1000.0 + 3600.0, 1000.0, 60.0)        # the clock was stepped back an hour


def test_next_retention_ts_is_0315_local():
    import datetime as dt

    from tnt.engine import _next_retention_ts

    now = dt.datetime(2026, 3, 10, 12, 0, 0).timestamp()
    nxt = dt.datetime.fromtimestamp(_next_retention_ts(now))
    assert (nxt.hour, nxt.minute, nxt.second) == (3, 15, 0) and nxt.date() == dt.date(2026, 3, 11)
    early = dt.datetime(2026, 3, 10, 2, 0, 0).timestamp()
    assert dt.datetime.fromtimestamp(_next_retention_ts(early)).date() == dt.date(2026, 3, 10)


# ---------------------------------------------------------------------------
# service / __main__
# ---------------------------------------------------------------------------
def test_service_version_help_and_bad_args(capsys):
    from tnt import service

    assert service.main(["--version"]) == 0
    assert __version__ in capsys.readouterr().out
    assert service.main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "--console" in out and "install" in out
    assert service.main(["--console", "--port", "abc"]) == 2
    assert "invalid port" in capsys.readouterr().err
    assert service.parse_console_args(["--port=7137", "--data-dir", "D:\\x"]) == {"port": 7137, "data_dir": "D:\\x"}
    with pytest.raises(ValueError):
        service.parse_console_args(["--bogus"])


def test_selfcheck_modules_include_geoip():
    import importlib

    from tnt import service

    mods = list(service.SELFCHECK_MODULES)
    for name in ("mmap", "tnt.mmdb", "tnt.geohints", "tnt.geohints_data", "tnt.geoip"):
        assert name in mods, name
        importlib.import_module(name)
    assert mods[mods.index("tnt.netwatch") + 1:mods.index("tnt.netwatch") + 5] == ["tnt.mmdb", "tnt.geohints",
                                                                                   "tnt.geohints_data", "tnt.geoip"]


def test_selfcheck_geoip_checks_are_offline(monkeypatch):
    import tempfile

    from tnt import service

    def no_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the IP location selfcheck must not touch the network")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    made: List[str] = []
    real_mkdtemp = tempfile.mkdtemp

    def mkdtemp(*args: Any, **kwargs: Any) -> str:
        folder = real_mkdtemp(*args, **kwargs)
        made.append(folder)
        return folder

    monkeypatch.setattr(tempfile, "mkdtemp", mkdtemp)
    checks = service._geoip_selfchecks()
    assert [c[0] for c in checks] == ["geohints data", "MMDB reader (mmap)", "gzip stream", "Windows certificate store"]
    for name, ok, detail in checks:
        assert isinstance(ok, bool) and isinstance(detail, str), name
        if name == "Windows certificate store" and sys.platform != "win32":
            continue
        assert ok is True, (name, detail)
    assert dict((c[0], c[2]) for c in checks)["MMDB reader (mmap)"].endswith(" bytes")
    assert len(made) == 1 and Path(made[0]).name.startswith("tnt-selfcheck-") and not Path(made[0]).exists()


def test_service_cli_output_survives_missing_streams(monkeypatch):
    """Frozen service processes have no console: stdout/stderr may be None."""
    from tnt import service

    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    service._out("hello")
    service._err("oops")
    assert service.main(["--version"]) == 0
    assert service.main(["--console", "--port", "x"]) == 2


def test_sc_start_gives_up_early_when_service_dies(monkeypatch):
    from tnt import service

    calls: List[List[str]] = []

    def runner(args: List[str]):
        calls.append(list(args))
        if args[0] == "query":
            return 0, "        STATE              : 1  STOPPED\n"
        return 0, "[SC] StartService ok"

    t0 = time.monotonic()
    assert service.sc_start(runner=runner) == 1
    assert time.monotonic() - t0 < 5.0
    assert calls[0] == ["start", SERVICE_NAME] and all(c[0] == "query" for c in calls[1:])
    # waiting for STOPPED still honours the requested state
    assert service.sc_stop(runner=runner) == 0


def test_python_m_tnt_version_subprocess():
    root = Path(__file__).resolve().parent.parent
    proc = subprocess.run([sys.executable, "-m", "tnt", "--version"], capture_output=True, text=True, timeout=60, cwd=str(root))
    assert proc.returncode == 0 and __version__ in proc.stdout


def test_service_sc_commands_when_frozen(monkeypatch, capsys):
    from tnt import service

    calls: List[List[str]] = []
    replies: Dict[str, Any] = {}

    def runner(args: List[str]):
        calls.append(list(args))
        if args[0] == "query":
            return 0, "SERVICE_NAME: TNTService\n        STATE              : %s\n" % replies.get("state", "4  RUNNING")
        return replies.get(args[0], (0, "[SC] ok"))

    exe = r"C:\Program Files\TNT\TNTService.exe"
    assert service.sc_install(runner=runner, exe=exe) == 0
    create, desc, fail = calls[:3]
    assert create[:2] == ["create", SERVICE_NAME]
    assert create[create.index("binPath=") + 1] == f'"{exe}"'
    assert create[create.index("start=") + 1] == "auto"
    assert create[create.index("DisplayName=") + 1] == SERVICE_DISPLAY_NAME
    assert desc == ["description", SERVICE_NAME, SERVICE_DESCRIPTION]
    assert fail[:2] == ["failure", SERVICE_NAME]
    assert fail[fail.index("actions=") + 1] == "restart/5000/restart/10000/restart/30000"
    assert fail[fail.index("reset=") + 1] == "86400"
    cmdline = subprocess.list2cmdline(service._sc_argv(create))
    assert cmdline.lower().endswith("sc.exe") is False and 'binPath= "\\"C:\\Program Files\\TNT\\TNTService.exe\\""' in cmdline
    assert "start= auto" in cmdline

    calls.clear()
    replies["create"] = (1073, "[SC] CreateService FAILED 1073: The specified service already exists.")
    assert service.sc_install(runner=runner, exe=exe) == 0  # re-install: binPath is refreshed with sc config
    assert [c[0] for c in calls] == ["create", "config", "description", "failure"]
    assert calls[1][calls[1].index("binPath=") + 1] == f'"{exe}"' and calls[1][calls[1].index("start=") + 1] == "auto"
    del replies["create"]

    calls.clear()
    assert service.sc_start(runner=runner) == 0 and calls[0] == ["start", SERVICE_NAME]
    calls.clear()
    replies["state"] = "1  STOPPED"
    assert service.sc_stop(runner=runner) == 0 and calls[0] == ["stop", SERVICE_NAME]
    calls.clear()
    replies["stop"] = (1062, "[SC] ControlService FAILED 1062")
    assert service.sc_remove(runner=runner) == 0
    assert [c[0] for c in calls] == ["stop", "delete"]
    replies["query"] = (1060, "not installed")
    calls.clear()
    replies["create"] = (5, "Access is denied.")
    assert service.sc_install(runner=runner, exe=exe) == 5
    assert "Administrator" in capsys.readouterr().err

    # main() dispatches to the sc handlers only when frozen
    monkeypatch.setattr(service.paths, "is_frozen", lambda: True)
    seen: List[str] = []
    for name in ("install", "remove", "start", "stop", "restart", "status"):
        monkeypatch.setitem(service.SC_HANDLERS, name, (lambda n: (lambda *a, **k: seen.append(n) or 0))(name))
    for name in ("install", "remove", "start", "stop", "restart", "status"):
        assert service.main([name]) == 0
    assert seen == ["install", "remove", "start", "stop", "restart", "status"]
    assert service.main(["bogus"]) == 2


def test_console_mode_serves_and_exits_cleanly(data_dir, capsys):
    from tnt import service

    seed = tnt_db.Database(data_dir / "tnt.db")
    seed.set_meta("defaults_loaded", "1")
    seed.close()
    stop = threading.Event()
    result: Dict[str, int] = {}

    def run() -> None:
        result["rc"] = service.run_console(port=0, data_dir=str(data_dir), stop_event=stop)

    t = threading.Thread(target=run, name="console-runner", daemon=True)
    t.start()
    out = ""
    deadline = time.time() + 15
    m = None
    while time.time() < deadline and m is None:
        out += capsys.readouterr().out
        m = re.search(r"serving http://127\.0\.0\.1:(\d+)/", out)
        if m is None:
            time.sleep(0.05)
    assert m is not None, out
    port = int(m.group(1))
    assert port not in (0, 7130)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", "/api/health")
        assert json.loads(conn.getresponse().read()) == {"ok": True}
    finally:
        conn.close()
    stop.set()
    t.join(15)
    assert not t.is_alive()
    out += capsys.readouterr().out
    assert result["rc"] == 0 and "stopping" in out and "stopped" in out
