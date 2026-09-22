"""Tests for tnt.api (router, server, routes, SSE), tnt.engine, tnt.diagnostics and tnt.service.

Everything runs against a FakeEngine whose sub-components return contract-shaped
dicts; the HTTP server is started on port 0 (never 7130).  No network access.
"""
from __future__ import annotations

import http.client
import io
import json
import logging
import os
import queue
import re
import socket
import struct
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
from tnt import capture as tnt_capture
from tnt import natcheck as tnt_natcheck
from tnt import pktmon as tnt_pktmon
from tnt import portcheck as tnt_portcheck
from tnt import switchport as tnt_switchport
from tnt import tftp as tnt_tftp
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
        v["name"] = None
        self.views[tid] = v
        return dict(v)

    def remove_target(self, tid: int) -> bool:
        return self.views.pop(tid, None) is not None

    def set_target_name(self, tid: Any, name: Optional[str]) -> Optional[Dict[str, Any]]:
        try:
            v = self.views.get(int(tid))
        except (TypeError, ValueError):
            v = None
        if v is None:
            return None
        v["name"] = (str(name).strip()[:80] if name is not None else "") or None
        return dict(v)

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
                "segments": [], "total_segments": [], "gaps": [], "targets": [], "cleared": []}

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


class FakeUpdate:
    """Stand-in for tnt.updater.UpdateManager; set as ``engine.update`` inside the update tests only."""

    def __init__(self, enabled: bool = True, available: bool = True) -> None:
        self.enabled = enabled
        self.available = available
        self.checks = 0
        self.installs = 0
        self.install_error: Optional[str] = None

    def status(self) -> Dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "state": "disabled", "current_version": __version__, "latest_version": None,
                    "latest_ts": None, "notes_url": None, "asset": None, "checked_ts": None, "next_check_ts": None,
                    "download": None, "error": None, "auto_install": False}
        return {"enabled": True, "state": "available" if self.available else "up_to_date", "current_version": __version__,
                "latest_version": "9.9.9" if self.available else None, "latest_ts": T0, "notes_url": "https://n",
                "asset": {"name": "TNT-Setup-9.9.9.exe", "bytes": 42} if self.available else None,
                "checked_ts": T0, "next_check_ts": T0 + 3600, "download": None, "error": None, "auto_install": False}

    def check_now(self) -> bool:
        self.checks += 1
        return self.enabled

    def request_install(self) -> None:
        if self.install_error is not None:
            raise RuntimeError(self.install_error)
        self.installs += 1


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



def test_throughput_route_needs_the_monitor_then_hands_over_its_view(server, engine):
    """The fake engine has no ``throughput``: 503 until one is attached.  Once it is, the route is
    a straight pass-through - the window is clamped by the monitor, not by the router, so there is
    one definition of "which windows exist" rather than two that can drift."""
    from tnt import throughput as tp_mod

    status, data = call_json(server, "GET", "/api/throughput")
    assert status == 503 and data["error"]["code"] == "unavailable"

    asked: List[Any] = []

    class FakeMonitor:
        def view(self, window_s: Any = None) -> Dict[str, Any]:
            asked.append(window_s)
            return {"ts": 1.0, "window_s": tp_mod.clamp_window(window_s), "step_s": 1,
                    "history_s": tp_mod.HISTORY_S, "windows": list(tp_mod.WINDOWS), "nics": [], "note": None}

    engine.throughput = FakeMonitor()
    status, data = call_json(server, "GET", "/api/throughput")
    assert status == 200 and set(data) == set(tp_mod.VIEW_KEYS) and asked == [None]
    status, data = call_json(server, "GET", "/api/throughput?window_s=1800")
    assert status == 200 and data["window_s"] == 1800 and asked[-1] == "1800"
    # a stale page's window is answered rather than refused: the card's whole job is to draw a line
    status, data = call_json(server, "GET", "/api/throughput?window_s=nonsense")
    assert status == 200 and data["window_s"] == tp_mod.DEFAULT_WINDOW_S



def test_faults_route_needs_the_watcher_then_hands_over_its_view(server, engine):
    """No start route and nothing to gate: the watch is always on and sends nothing, so there is
    no work a caller could trigger."""
    from tnt import faults as fault_mod

    status, data = call_json(server, "GET", "/api/faults")
    assert status == 503 and data["error"]["code"] == "unavailable"
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["faults"] is None

    class FakeWatcher:
        def view(self) -> Dict[str, Any]:
            return {"ts": 1.0, "watching_since": 0.5, "watched_s": 0.5, "level": "good",
                    "findings": [], "nics": [], "arp": {}, "note": None}

        def tile(self) -> Dict[str, Any]:
            return {"available": True, "reason": None, "level": "good", "bad": 0, "warn": 0,
                    "headline": "No faults found", "watched_s": 0.5, "clean_s": 0.0, "ts": 1.0}

    engine.faults = FakeWatcher()
    status, data = call_json(server, "GET", "/api/faults")
    assert status == 200 and set(data) == set(fault_mod.VIEW_KEYS)
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and set(data["faults"]) == set(fault_mod.TILE_KEYS)
    # a tile() that blows up must not take /api/status down with it
    engine.faults = type("Boom", (), {"tile": lambda self: (_ for _ in ()).throw(OSError("nope")),
                                      "view": FakeWatcher.view})()
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["faults"] is None


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
                "targets", "outages", "speed", "discovery", "netinfo", "net", "settings", "map", "dhcp", "tftp"}
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


def test_target_rename_route(server, engine):
    status, view = call_json(server, "POST", "/api/targets", {"host": "8.8.8.8", "label": "Google"})
    tid = view["id"]
    assert view["name"] is None
    status, view = call_json(server, "PATCH", f"/api/targets/{tid}", {"name": "  Google DNS  "})
    assert status == 200 and view["name"] == "Google DNS" and view["label"] == "Google" and view["id"] == tid
    status, lst = call_json(server, "GET", "/api/targets")
    assert [t["name"] for t in lst] == ["Google DNS"]
    # null or blank clears the custom name (reverts to the label/host)
    for blank in (None, "   "):
        status, view = call_json(server, "PATCH", f"/api/targets/{tid}", {"name": blank})
        assert status == 200 and view["name"] is None, blank
    status, data = call_json(server, "PATCH", "/api/targets/999999", {"name": "x"})
    assert status == 404 and data["error"]["code"] == "not_found"
    engine.ping = None
    status, data = call_json(server, "PATCH", f"/api/targets/{tid}", {"name": "x"})
    assert status == 503 and data["error"]["code"] == "unavailable"


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
    assert data["cleared"] == []            # the cleared history spans (tnt.history), none here

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


def test_status_update_null_without_component_and_status_with_it(server, engine):
    from tnt import updater

    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and "update" in data and data["update"] is None
    engine.update = FakeUpdate()
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["update"] == engine.update.status() and set(data["update"]) == set(updater.STATUS_KEYS)
    engine.update.enabled = False
    status, data = call_json(server, "GET", "/api/status")
    assert data["update"]["state"] == "disabled" and set(data["update"]) == set(updater.STATUS_KEYS)


def test_update_status_and_check_routes(server, engine):
    for method, path in (("GET", "/api/update"), ("POST", "/api/update/check")):
        status, data = call_json(server, method, path)
        assert status == 503 and data["error"]["code"] == "unavailable", path
    um = engine.update = FakeUpdate()
    status, data = call_json(server, "GET", "/api/update")
    assert status == 200 and data == um.status()
    status, data = call_json(server, "POST", "/api/update/check")
    assert status == 200 and data == um.status() and um.checks == 1
    um.enabled = False
    status, data = call_json(server, "POST", "/api/update/check")
    assert status == 409 and data["error"] == {"code": "conflict", "message": "Automatic updates are switched off"}


def test_update_install_route_needs_an_administrator(server, engine):
    um = engine.update = FakeUpdate()
    server.wifi_reveal_check = lambda peer, local: "denied"
    status, data = call_body(server, "POST", "/api/update/install")
    assert status == 403 and data["error"] == {"code": "admin_required", "message": api_routes.UPDATE_ADMIN_REQUIRED_MSG}
    for check in (lambda peer, local: "unknown", lambda peer, local: None):
        server.wifi_reveal_check = check
        status, data = call_body(server, "POST", "/api/update/install")
        assert status == 403 and data["error"] == {"code": "admin_required", "message": api_routes.UPDATE_ADMIN_UNVERIFIED_MSG}
    assert um.installs == 0
    server.wifi_reveal_check = lambda peer, local: "allowed"
    status, data = call_body(server, "POST", "/api/update/install")
    assert status == 200 and data == um.status() and um.installs == 1


def test_update_install_route_refuses_a_page_of_another_origin(server, engine):
    um = engine.update = FakeUpdate()
    server.wifi_reveal_check = lambda peer, local: "allowed"
    status, data = call_body(server, "POST", "/api/update/install",
                             headers={"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
    assert status == 403 and data["error"]["code"] == "forbidden"
    assert um.installs == 0        # refused before the component is even asked


def test_update_install_route_409_and_503(server, engine):
    server.wifi_reveal_check = lambda peer, local: "allowed"
    status, data = call_body(server, "POST", "/api/update/install")
    assert status == 503 and data["error"]["code"] == "unavailable"      # no update component
    um = engine.update = FakeUpdate()
    um.install_error = "No update is available to install"
    status, data = call_body(server, "POST", "/api/update/install")
    assert status == 409 and data["error"] == {"code": "conflict", "message": "No update is available to install"}


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
# ---------------------------------------------------------------------------
# quick tools: DNS lookup, Flush DNS, IP release/renew
# ---------------------------------------------------------------------------
DNS_RESULT = {"name": "www.example.com", "type": None, "server": None, "resolver": {"name": "dns.example.net", "address": "192.0.2.53"},
              "answer_name": "www.example.com", "addresses": ["192.0.2.10", "2001:db8::10"], "aliases": [],
              "records": [{"type": "A", "name": "www.example.com", "value": "192.0.2.10", "ttl": 300},
                          {"type": "AAAA", "name": "www.example.com", "value": "2001:db8::10", "ttl": 300}],
              "authoritative": False, "ok": True, "error": None, "duration_ms": 41, "ts": T0}
FLUSH_RESULT = {"ok": True, "method": "native", "error": None, "duration_ms": 3, "ts": T0}
RENEW_RESULT = {"ok": True, "address": "192.0.2.44", "adapter": "Ethernet",
                "adapters": [{"name": "Ethernet", "released": True, "renewed": True, "error": None}], "warnings": [],
                "paused_monitoring": False, "method": "native", "error": None, "duration_ms": 5400, "ts": T0}
QUICK_TOOL_PATHS = ("/api/tools/dns/lookup", "/api/tools/dns/flush", "/api/tools/ip/renew")


def call_body(srv: Any, method: str, path: str, body: Any = None, headers: Optional[Dict[str, str]] = None):
    status, _headers, payload = call(srv, method, path, body, headers=headers)
    return status, (json.loads(payload) if payload else None)


@pytest.fixture
def fake_nettools(monkeypatch):
    """``tnt.nettools.dns_lookup`` / ``flush_dns`` replaced (validation kept): nothing reaches a DNS server or the cache."""
    from tnt import nettools

    calls: List[Any] = []

    def lookup(name: Any, server: Any = None, record_type: Any = None, **kw: Any) -> Dict[str, Any]:
        calls.append(("lookup", name, server, record_type))
        qname, srv, rtype = nettools.validate_lookup(name, server, record_type)
        return dict(DNS_RESULT, name=qname, type=rtype, server=srv)

    def flush(**kw: Any) -> Dict[str, Any]:
        calls.append(("flush",))
        return dict(FLUSH_RESULT)

    monkeypatch.setattr(nettools, "dns_lookup", lookup)
    monkeypatch.setattr(nettools, "flush_dns", flush)
    return calls


DNS_TYPE_TEXT = '"{}" is not a DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR or NAPTR)'
DNS_IP_TYPE_TEXT = "An IP address is looked up as PTR: type a DNS name to ask for other record types"


def test_dns_lookup_route(server, fake_nettools):
    from tnt import nettools

    status, data = call_body(server, "POST", "/api/tools/dns/lookup", {"name": "www.example.com"})
    assert status == 200 and data == DNS_RESULT and list(data) == list(DNS_RESULT) == list(nettools.DNS_RESULT_KEYS)
    status, data = call_body(server, "POST", "/api/tools/dns/lookup", {"name": "www.example.com.", "server": "dns.example.net"})
    assert status == 200 and data["name"] == "www.example.com" and data["server"] == "dns.example.net"
    status, data = call_body(server, "POST", "/api/tools/dns/lookup", {"name": "192.0.2.10", "server": None})
    assert status == 200 and data["server"] is None and data["type"] is None
    # a record type is trimmed and matched in any case; null or empty is Auto; an address takes PTR
    for body, rtype in (({"name": "example.com", "type": " mx "}, "MX"), ({"name": "example.com", "type": "naptr"}, "NAPTR"),
                        ({"name": "example.com", "type": None}, None), ({"name": "example.com", "type": ""}, None),
                        ({"name": "192.0.2.10", "type": "Ptr"}, "PTR"), ({"name": "example.com", "type": "all"}, "ALL"),
                        ({"name": "192.0.2.10", "type": "ALL"}, "ALL")):
        status, data = call_body(server, "POST", "/api/tools/dns/lookup", body)
        assert status == 200 and data["type"] == rtype and list(data) == list(DNS_RESULT), body
    assert fake_nettools == [("lookup", "www.example.com", None, None), ("lookup", "www.example.com.", "dns.example.net", None),
                             ("lookup", "192.0.2.10", None, None), ("lookup", "example.com", None, " mx "),
                             ("lookup", "example.com", None, "naptr"), ("lookup", "example.com", None, None),
                             ("lookup", "example.com", None, ""), ("lookup", "192.0.2.10", None, "Ptr"),
                             ("lookup", "example.com", None, "all"), ("lookup", "192.0.2.10", None, "ALL")]
    for body, message in (({}, "Type a DNS name or IP address to look up"), ({"name": "   "}, "Type a DNS name or IP address to look up"),
                          ({"name": "-type=any"}, '"-type=any" is not a DNS name or IP address'),
                          ({"name": "www.example.com", "server": "-x"}, '"-x" is not a DNS server name or IP address'),
                          ({"name": 5}, "name must be text"), ({"name": ["www.example.com"]}, "name must be text"),
                          ({"name": "www.example.com", "server": 53}, "server must be text or null"),
                          ({"name": "example.com", "type": 15}, "type must be text or null"),
                          ({"name": "example.com", "type": ["MX"]}, "type must be text or null"),
                          # the route checks the name, the server and the type in turn
                          ({"name": 5, "server": 53, "type": 15}, "name must be text"),
                          ({"name": "example.com", "server": 53, "type": 15}, "server must be text or null"),
                          ({"name": "example.com", "type": "ANY"}, DNS_TYPE_TEXT.format("ANY")),
                          ({"name": "example.com", "type": "  -type=mx "}, DNS_TYPE_TEXT.format("-type=mx")),
                          ({"name": "192.0.2.10", "type": "MX"}, DNS_IP_TYPE_TEXT),
                          # then the service: the name, the server, the type, and last an address with another type
                          ({"name": "  ", "type": "ANY"}, "Type a DNS name or IP address to look up"),
                          ({"name": "example.com", "server": "-x", "type": "ANY"}, '"-x" is not a DNS server name or IP address'),
                          ({"name": "192.0.2.10", "type": "ANY"}, DNS_TYPE_TEXT.format("ANY")),
                          ([1], "JSON body must be an object")):
        status, data = call_body(server, "POST", "/api/tools/dns/lookup", body)
        assert status == 400 and data["error"] == {"code": "bad_request", "message": message}, body
    status, _data = call_body(server, "GET", "/api/tools/dns/lookup")
    assert status == 405


def test_dns_lookup_route_hands_the_type_to_the_service(server, monkeypatch):
    """The route's call fits the real ``tnt.nettools.dns_lookup``: the type reaches it and a type it refuses is a 400.  The
    server choice is stubbed, so no DNS server is asked even if the call were wrong."""
    from tnt import nettools

    asked: List[Any] = []
    monkeypatch.setattr(nettools, "_resolve_server", lambda *a, **kw: asked.append(a) or (None, nettools.NO_SERVER_TEXT))
    status, data = call_body(server, "POST", "/api/tools/dns/lookup", {"name": "example.com", "type": "caa"})
    assert status == 200 and list(data) == list(nettools.DNS_RESULT_KEYS)
    assert data == {**data, "name": "example.com", "type": "CAA", "ok": False, "error": nettools.NO_SERVER_TEXT}
    for body, message in (({"name": "192.0.2.10", "type": "NAPTR"}, DNS_IP_TYPE_TEXT),
                          ({"name": "example.com", "type": "HINFO"}, DNS_TYPE_TEXT.format("HINFO"))):
        status, data = call_body(server, "POST", "/api/tools/dns/lookup", body)
        assert status == 400 and data["error"] == {"code": "bad_request", "message": message}, body
    assert len(asked) == 1, "a refused lookup never chooses a server"


def test_dns_flush_route(server, fake_nettools, monkeypatch):
    from tnt import nettools

    status, data = call_body(server, "POST", "/api/tools/dns/flush")
    assert status == 200 and data == FLUSH_RESULT and fake_nettools == [("flush",)]
    monkeypatch.setattr(nettools, "flush_dns", lambda **kw: dict(FLUSH_RESULT, ok=False, error="Windows did not flush the DNS cache"))
    status, data = call_body(server, "POST", "/api/tools/dns/flush")
    assert status == 200 and data["ok"] is False and data["error"] == "Windows did not flush the DNS cache"


def test_quick_tool_routes_503_when_the_module_cannot_be_imported(server, monkeypatch):
    monkeypatch.setitem(sys.modules, "tnt.nettools", None)
    for path, body in (("/api/tools/dns/lookup", {"name": "www.example.com"}), ("/api/tools/dns/flush", None)):
        status, data = call_body(server, "POST", path, body)
        assert status == 503 and data["error"]["code"] == "unavailable", path


@pytest.mark.parametrize("path", QUICK_TOOL_PATHS)
def test_quick_tools_refuse_a_page_of_another_origin(server, engine, fake_nettools, path):
    ran: List[int] = []
    engine.ip_release_renew = lambda: ran.append(1) or dict(RENEW_RESULT)
    checks: List[Any] = []
    server.wifi_reveal_check = lambda peer, local: checks.append(peer) or "allowed"
    body = {"name": "www.example.com"}
    # a cross-site POST or a foreign Origin is refused by the server's CSRF guard before routing; the route itself
    # refuses same-site (another port on localhost), with its own message
    for headers in ({"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site", "Origin": "http://localhost:8081"}):
        status, data = call_body(server, "POST", path, body, headers=headers)
        assert status == 403 and data["error"]["code"] == "forbidden"
    status, data = call_body(server, "POST", path, body, headers={"Sec-Fetch-Site": "same-site"})
    assert status == 403 and data["error"] == {"code": "forbidden", "message": api_routes.QUICK_TOOLS_CROSS_ORIGIN_MSG}
    assert fake_nettools == [] and ran == [] and checks == [], "refused before anything runs, the admin check included"
    status, _data = call_body(server, "POST", path, body,
                              headers={"Sec-Fetch-Site": "same-origin", "Origin": f"http://127.0.0.1:{server.port}"})
    assert status == 200


def test_ip_renew_route_needs_an_administrator(server, engine, monkeypatch):
    ran: List[int] = []
    engine.ip_release_renew = lambda: ran.append(1) or dict(RENEW_RESULT)
    seen: List[Any] = []
    server.wifi_reveal_check = lambda peer, local: seen.append((peer, local)) or "denied"
    status, data = call_body(server, "POST", "/api/tools/ip/renew")
    assert status == 403 and data["error"] == {"code": "admin_required", "message": api_routes.IP_RENEW_ADMIN_REQUIRED_MSG}
    peer, local = seen[0]
    assert peer[0].startswith("127.") and int(local[1]) == server.port

    def boom(peer: Any, local: Any) -> str:
        raise RuntimeError("token read exploded")

    for check in (lambda peer, local: "unknown", lambda peer, local: None, boom):
        server.wifi_reveal_check = check
        status, data = call_body(server, "POST", "/api/tools/ip/renew")
        assert status == 403 and data["error"] == {"code": "admin_required", "message": api_routes.IP_RENEW_ADMIN_UNVERIFIED_MSG}
    import tnt.peer

    monkeypatch.setattr(tnt.peer, "reveal_allowed", lambda peer, local: "denied")
    server.wifi_reveal_check = None                                  # the production path: tnt.peer decides
    status, data = call_body(server, "POST", "/api/tools/ip/renew")
    assert status == 403 and data["error"]["message"] == api_routes.IP_RENEW_ADMIN_REQUIRED_MSG
    assert ran == []
    server.wifi_reveal_check = lambda peer, local: "allowed"
    status, data = call_body(server, "POST", "/api/tools/ip/renew")
    assert status == 200 and data == RENEW_RESULT and list(data) == list(RENEW_RESULT) and ran == [1]


def test_ip_renew_route_503_and_409(server, engine):
    server.wifi_reveal_check = lambda peer, local: "allowed"
    status, data = call_body(server, "POST", "/api/tools/ip/renew")
    assert status == 503 and data["error"]["code"] == "unavailable"         # an engine without ip_release_renew

    def busy() -> Dict[str, Any]:
        raise RuntimeError("An IP release/renew is already running")

    engine.ip_release_renew = busy
    status, data = call_body(server, "POST", "/api/tools/ip/renew")
    assert status == 409 and data["error"] == {"code": "conflict", "message": "An IP release/renew is already running"}


# ---------------------------------------------------------------------------
# network tools: NAT check, switch port, port-forward test, packet capture, TFTP server
# ---------------------------------------------------------------------------
NAT_RESULT = {**dict.fromkeys(tnt_natcheck.NAT_RESULT_KEYS), "ts": T0, "generation": 3, "duration_ms": 840,
              "verdict": "single_nat", "confidence": "high", "title": tnt_natcheck.NAT_TEXT["single_nat"][0],
              "explanation": tnt_natcheck.NAT_TEXT["single_nat"][1], "public_ip": "203.0.113.5"}
SWITCH_ADAPTER = {"name": "Ethernet", "index": 21, "mac": "02:00:5e:10:00:01"}
SWITCH_JOB = {**dict.fromkeys(tnt_switchport.SWITCH_JOB_KEYS), "state": "idle", "neighbors": [], "generation": 3}
PORT_RESULT = {**dict.fromkeys(tnt_portcheck.PORTCHECK_RESULT_KEYS), "ts": T0, "generation": 3, "port": 8000,
               "protocol": "tcp", "public_ip": "203.0.113.5", "reachable": True, "provider": "portchecker.io",
               "detail": tnt_portcheck.PORTCHECKER_OPEN_DETAIL, "nat_verdict": "single_nat", "duration_ms": 1240}
CAPTURE_NAME = "TNT-capture-20260101-120000.pcapng"
CAPTURE_BYTES = b"\x0a\x0d\x0d\x0a" + bytes(24)
CAPTURE_FILE = {"name": CAPTURE_NAME, "size": 4096, "created_ts": T0, "packets": 12}
CAPTURE_ADAPTER = {**dict.fromkeys(tnt_capture.CAPTURE_ADAPTER_KEYS), **SWITCH_ADAPTER,
                   "type_name": "Ethernet", "wifi": False}
CAPTURE_LIMITS = {**dict.fromkeys(tnt_capture.LIMIT_KEYS), "max_rows": tnt_capture.MAX_ROWS,
                  "max_packets": tnt_capture.MAX_PACKETS, "seconds": list(tnt_capture.CAPTURE_SECONDS),
                  "sizes_mb": list(tnt_capture.CAPTURE_SIZES_MB), "default_seconds": tnt_capture.DEFAULT_SECONDS,
                  "default_mb": tnt_capture.DEFAULT_MB}
CAPTURE_SESSION = {**dict.fromkeys(tnt_capture.SESSION_KEYS), "id": 1, "state": "capturing", "source": "live",
                   "adapter": CAPTURE_ADAPTER, "file": None, "saved": False, "started_ts": T0, "first_ts": None,
                   "elapsed_s": 0.0, "packets": 0, "shown": 0, "bytes": 0, "dropped": 0, "truncated": False,
                   "calls": 0, "stop_reason": None, "error": None, "ts": T0}
CAPTURE_ROW = {**dict.fromkeys(tnt_capture.ROW_KEYS), "no": 1, "ts": T0, "rel": 0.0, "src": "192.0.2.10",
               "dst": "192.0.2.1", "src_mac": "02:00:5e:10:00:01", "dst_mac": "02:00:5e:10:00:02", "proto": "ICMP",
               "sport": None, "dport": None, "length": 74, "info": "Echo (ping) request"}
CAPTURE_CALL_ID = "tnt-test-call-1-9f2c1a7b"
CAPTURE_CALL = {"id": CAPTURE_CALL_ID, "call_id": "tnt-test-call-1", "from_uri": "sip:alice@192.0.2.10",
                "to_uri": "sip:bob@192.0.2.20", "state": "answered"}
CAPTURE_WAV = b"RIFF" + bytes(4) + b"WAVEfmt " + bytes(8)


class FakeNatChecker:
    """Stand-in for tnt.natcheck.NatChecker (last / running / run); every call is recorded."""

    def __init__(self) -> None:
        self.calls: List[Any] = []
        self.result: Optional[Dict[str, Any]] = None
        self.busy = False
        self.fail_with: Optional[BaseException] = None

    def last(self) -> Optional[Dict[str, Any]]:
        self.calls.append(("last",))
        return dict(self.result) if self.result else None

    def running(self) -> bool:
        self.calls.append(("running",))
        return self.busy

    def run(self) -> Dict[str, Any]:
        self.calls.append(("run",))
        if self.fail_with is not None:
            raise self.fail_with
        self.result = dict(NAT_RESULT)
        return dict(self.result)


class FakeSwitchPort:
    """Stand-in for tnt.switchport.SwitchPortFinder (status / start / stop)."""

    def __init__(self) -> None:
        self.calls: List[Any] = []
        self.job = dict(SWITCH_JOB)
        self.fail_with: Optional[BaseException] = None

    def status(self) -> Dict[str, Any]:
        self.calls.append(("status",))
        return {"job": dict(self.job), "adapters": [dict(SWITCH_ADAPTER, is_internet=True)], "available": True, "reason": None}

    def start(self, adapter: Optional[str] = None, seconds: Any = 65) -> Dict[str, Any]:
        self.calls.append(("start", adapter, seconds))
        if self.fail_with is not None:
            raise self.fail_with
        self.job = dict(self.job, state="listening", adapter=dict(SWITCH_ADAPTER), started_ts=T0,
                        listen_s=65 if seconds is None else seconds, elapsed_s=0.0, ts=T0)
        return dict(self.job)

    def stop(self) -> Dict[str, Any]:
        self.calls.append(("stop",))
        if self.job["state"] == "listening":
            self.job = dict(self.job, state="cancelled")
        return dict(self.job)


class FakePortChecker:
    """Stand-in for tnt.portcheck.PortChecker: the service's own port check, then PORT_RESULT."""

    def __init__(self) -> None:
        self.calls: List[Any] = []
        self.fail_with: Optional[BaseException] = None

    def test(self, port: Any) -> Dict[str, Any]:
        self.calls.append(("test", port))
        if self.fail_with is not None:
            raise self.fail_with
        return dict(PORT_RESULT, port=tnt_portcheck.validate_port(port))


class CaptureCalls(list):
    """The capture fake's ``calls``: the recorder every fake here keeps, and - because ``GET /api/capture/calls`` asks
    the manager for ``mgr.calls`` itself - the SIP call list method too."""

    def __init__(self, answer: List[Dict[str, Any]]) -> None:
        super().__init__()
        self.answer = answer

    def __call__(self) -> List[Dict[str, Any]]:
        self.append(("calls",))
        return [dict(call) for call in self.answer]


class FakeCaptureManager:
    """Stand-in for tnt.capture.CaptureManager, the live analyser behind /api/capture (status / start / stop / save /
    discard / open_file / packets / packet / calls / call_audio / file_download / delete_file / files / tile);
    ``opened`` keeps every file object handed out for a download.  ``tile()`` is never recorded: /api/status asks for it
    on every poll."""

    def __init__(self) -> None:
        self.calls = CaptureCalls([dict(CAPTURE_CALL)])
        self.session: Optional[Dict[str, Any]] = None
        self.file_list = [dict(CAPTURE_FILE)]
        self.opened: List[Any] = []
        self.fail_with: Optional[BaseException] = None

    def _call(self, *call: Any) -> None:
        self.calls.append(call)
        if self.fail_with is not None:
            raise self.fail_with

    def _session(self) -> Optional[Dict[str, Any]]:
        return dict(self.session) if self.session is not None else None

    def status(self) -> Dict[str, Any]:
        self._call("status")
        return {**dict.fromkeys(tnt_capture.CAPTURE_STATUS_KEYS), "available": True, "reason": None,
                "adapters": [dict(CAPTURE_ADAPTER)], "session": self._session(),
                "files": [dict(f) for f in self.file_list], "limits": dict(CAPTURE_LIMITS)}

    def start(self, *, adapter: Any, **kwargs: Any) -> Dict[str, Any]:
        self._call("start", adapter, kwargs)
        self.session = dict(CAPTURE_SESSION)
        return dict(self.session)

    def stop(self) -> Optional[Dict[str, Any]]:
        self._call("stop")
        if self.session is None:
            return None
        self.session = dict(self.session, state="stopped", stop_reason="user", elapsed_s=2.5)
        return dict(self.session)

    def save(self) -> Dict[str, Any]:
        self._call("save")
        self.session = dict(self.session or CAPTURE_SESSION, state="stopped", saved=True, file=CAPTURE_NAME)
        return dict(self.session)

    def discard(self) -> None:
        self._call("discard")
        self.session = None

    def open_file(self, name: Any) -> Dict[str, Any]:
        self._call("open_file", name)
        self.session = dict(CAPTURE_SESSION, state="loaded", source="file", adapter=None, file=name, saved=True,
                            packets=12, shown=12)
        return dict(self.session)

    def packets(self, *, since: Any = None, limit: Any = None, ip: Any = None, mac: Any = None,
                protos: Any = None) -> Dict[str, Any]:
        self._call("packets", since, limit, ip, mac, list(protos or []))
        return {**dict.fromkeys(tnt_capture.PACKETS_KEYS), "rows": [dict(CAPTURE_ROW)], "total": 12, "shown": 12,
                "matched": 1, "last": 1, "dropped_before": False, "session": self._session()}

    def packet(self, no: Any) -> Dict[str, Any]:
        self._call("packet", no)
        return {**dict.fromkeys(tnt_capture.DETAIL_KEYS), "row": dict(CAPTURE_ROW),
                "layers": [{"name": "ETH", "summary": "02:00:5e:10:00:01 -> 02:00:5e:10:00:02", "start": 0,
                            "length": 14, "fields": []}],
                "hex": ["0000  02 00 5e 10 00 02 02 00  5e 10 00 01 08 00"], "bytes": 74}

    def call_audio(self, call_id: Any) -> bytes:
        self._call("call_audio", call_id)
        return CAPTURE_WAV

    def file_download(self, name: Any) -> Any:
        self._call("file_download", name)
        self.opened.append(io.BytesIO(CAPTURE_BYTES))
        return self.opened[-1], len(CAPTURE_BYTES)

    def delete_file(self, name: Any) -> List[Dict[str, Any]]:
        self._call("delete_file", name)
        self.file_list = [f for f in self.file_list if f["name"] != name]
        return [dict(f) for f in self.file_list]

    def files(self) -> List[Dict[str, Any]]:
        self._call("files")
        return [dict(f) for f in self.file_list]

    def tile(self) -> Dict[str, Any]:
        session = self.session or {}
        return {**dict.fromkeys(tnt_capture.TILE_KEYS), "available": True, "reason": None,
                "running": session.get("state") == "capturing", "adapter": (session.get("adapter") or {}).get("name"),
                "packets": int(session.get("packets") or 0), "calls": int(session.get("calls") or 0),
                "files": len(self.file_list)}


class FakeTftpServer:
    """Stand-in for tnt.tftp.TftpServer with the service's own argument checks."""

    def __init__(self) -> None:
        self.calls: List[Any] = []
        self.running = False
        self.uploads = False
        self.settings = {"adapter": "", "max_upload_mb": 4096}
        self.fail_with: Optional[BaseException] = None

    def summary(self) -> Dict[str, Any]:
        return {"available": True, "running": self.running, "adapter": "Ethernet" if self.running else None,
                "listen_ips": ["192.0.2.10"] if self.running else [], "active": 0, "uploads": self.uploads,
                "since_ts": T0 if self.running else None, "error": None}

    def _view(self) -> Dict[str, Any]:
        return {**dict.fromkeys(tnt_tftp.TFTP_STATUS_KEYS), "available": True, "running": self.running,
                "since_ts": T0 if self.running else None, "adapter": "Ethernet" if self.running else None, "adapters": [],
                "listen": [{"ip": "192.0.2.10", "port": 69}] if self.running else [], "root": "C:/ProgramData/TNT/tftp",
                "uploads": self.uploads, "firewall": {"rule": tnt_tftp.FIREWALL_RULE_NAME, "ok": None, "error": None},
                "transfers": [], "history": [], "counts": dict.fromkeys(tnt_tftp.TFTP_COUNT_KEYS, 0),
                "settings": dict(self.settings)}

    def status(self) -> Dict[str, Any]:
        self.calls.append(("status",))
        return self._view()

    def start(self, adapter: Optional[str] = None, uploads: Any = False) -> Dict[str, Any]:
        self.calls.append(("start", adapter, uploads))
        if self.fail_with is not None:
            raise self.fail_with
        if not isinstance(uploads, bool):
            raise ValueError("uploads must be true or false")
        self.running, self.uploads = True, uploads
        return self._view()

    def stop(self) -> Dict[str, Any]:
        self.calls.append(("stop",))
        self.running = self.uploads = False
        return self._view()

    def set_uploads(self, on: Any) -> Dict[str, Any]:
        self.calls.append(("set_uploads", on))
        if not isinstance(on, bool):
            raise ValueError("on must be true or false")
        self.uploads = on
        return self._view()

    def update_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append(("update_settings", dict(patch)))
        unknown = sorted(str(k) for k in patch if k not in tnt_tftp.TFTP_SETTINGS_KEYS)
        if unknown:
            raise ValueError(f"unknown TFTP setting '{unknown[0]}'")
        self.settings.update(patch)
        return self._view()

    def files(self) -> List[Dict[str, Any]]:
        self.calls.append(("files",))
        return [{"name": "boot/pxelinux.0", "size": 26828, "mtime": T0}]


@pytest.fixture
def network_tools(engine):
    """The fake NAT check, switch port finder, port-forward test, capture manager and TFTP server, set on the engine."""
    tools = {"natcheck": FakeNatChecker(), "switchport": FakeSwitchPort(), "portcheck": FakePortChecker(),
             "capture": FakeCaptureManager(), "tftp": FakeTftpServer()}
    for name, fake in tools.items():
        setattr(engine, name, fake)
    return tools


#: Every network tool route that changes something, plus the capture download (a page of another origin must not make a
#: browser save a capture either).  Not part of QUICK_TOOL_PATHS: those bodies and fakes differ.
NETWORK_TOOL_CHANGES = (
    ("POST", "/api/netcheck/nat", None),
    ("POST", "/api/netcheck/switch", {"adapter": None, "seconds": None}),
    ("DELETE", "/api/netcheck/switch", None),
    ("POST", "/api/netcheck/portforward", {"port": 8000}),
    ("POST", "/api/capture/start", {"adapter": "Ethernet"}),
    ("POST", "/api/capture/stop", None),
    ("POST", "/api/capture/save", None),
    ("POST", "/api/capture/discard", None),
    ("POST", "/api/capture/open", {"name": CAPTURE_NAME}),
    ("DELETE", f"/api/capture/files/{CAPTURE_NAME}", None),
    ("GET", f"/api/capture/files/{CAPTURE_NAME}", None),
    ("POST", "/api/tftp/start", {"adapter": None, "uploads": False}),
    ("POST", "/api/tftp/stop", None),
    ("POST", "/api/tftp/uploads", {"on": True}),
    ("PUT", "/api/tftp/settings", {"max_upload_mb": 512}),
)

#: Every route of the Packet capture page, in the order the module docstring lists them.  All of them are admin-gated,
#: so the same table proves the 503 and the administrator check for the whole page.
CAPTURE_ROUTES = (
    ("GET", "/api/capture", None),
    ("POST", "/api/capture/start", {"adapter": "Ethernet"}),
    ("POST", "/api/capture/stop", None),
    ("POST", "/api/capture/save", None),
    ("POST", "/api/capture/discard", None),
    ("POST", "/api/capture/open", {"name": CAPTURE_NAME}),
    ("GET", "/api/capture/packets", None),
    ("GET", "/api/capture/packets/1", None),
    ("GET", "/api/capture/calls", None),
    ("GET", f"/api/capture/calls/{CAPTURE_CALL_ID}/audio", None),
    ("GET", f"/api/capture/files/{CAPTURE_NAME}", None),
    ("DELETE", f"/api/capture/files/{CAPTURE_NAME}", None),
)


@pytest.mark.parametrize("method,path,body", NETWORK_TOOL_CHANGES)
def test_network_tools_refuse_a_page_of_another_origin(server, network_tools, method, path, body):
    checks: List[Any] = []
    server.wifi_reveal_check = lambda peer, local: checks.append(peer) or "allowed"
    # the server's CSRF guard refuses a cross-site or foreign-Origin POST/PUT/DELETE before routing; the route refuses the
    # rest (same-site: another port on localhost) itself, with its own message
    for headers in ({"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site", "Origin": "http://localhost:8081"},
                    {"Sec-Fetch-Site": "same-site"}):
        status, _headers, payload = call(server, method, path, body, headers=headers)
        assert status == 403 and json.loads(payload)["error"]["code"] == "forbidden", headers
    assert json.loads(payload)["error"]["message"] == api_routes.QUICK_TOOLS_CROSS_ORIGIN_MSG
    assert [name for name, fake in network_tools.items() if fake.calls] == [] and checks == [], \
        "refused before any component runs, the capture admin check included"
    status, _headers, _payload = call(server, method, path, body,
                                      headers={"Sec-Fetch-Site": "same-origin", "Origin": f"http://127.0.0.1:{server.port}"})
    assert status == 200 and [name for name, fake in network_tools.items() if fake.calls]


def test_typed_errors_name_real_exception_classes():
    """The services' typed errors and their answers are exactly the contract's table, and each class exists with its base
    (a RuntimeError one would otherwise be a 500, the LookupError one would escape _tool_call)."""
    import importlib

    expected = {
        ("tnt.pktmon", "PktmonBusy"): (RuntimeError, 409, "conflict"),
        ("tnt.pktmon", "PktmonUnavailable"): (RuntimeError, 409, "unavailable"),
        ("tnt.portcheck", "RateLimited"): (RuntimeError, 429, "rate_limited"),
        ("tnt.portcheck", "NoPublicIp"): (RuntimeError, 409, "no_public_ip"),
        ("tnt.portcheck", "VpnActive"): (RuntimeError, 409, "vpn"),
        ("tnt.tftp", "TftpPortInUse"): (RuntimeError, 409, "tftp_port_in_use"),
        ("tnt.capture", "CaptureFileBusy"): (RuntimeError, 409, "conflict"),
        ("tnt.capture", "CaptureFileMissing"): (LookupError, 404, "not_found"),
        ("tnt.capture", "CaptureBusy"): (RuntimeError, 409, "conflict"),
        ("tnt.capture", "CaptureUnavailable"): (RuntimeError, 409, "unavailable"),
        ("tnt.proav", "ProAvUnavailable"): (RuntimeError, 409, "unavailable"),
        ("tnt.sipflow", "FlowError"): (RuntimeError, 400, "bad_request"),
        ("tnt.sipalg", "AlgUnavailable"): (RuntimeError, 409, "unavailable"),
        ("tnt.sipnat", "NatError"): (RuntimeError, 409, "unavailable"),
    }
    table = {(module, name): answer for module, classes in api_routes.TYPED_ERRORS.items() for name, answer in classes.items()}
    assert table == {key: (status, code) for key, (_base, status, code) in expected.items()}
    for (module, name), (base, _status, _code) in expected.items():
        cls = getattr(importlib.import_module(module), name, None)
        assert isinstance(cls, type) and issubclass(cls, base), (module, name)
    assert tnt_portcheck.RateLimited("Too many tests: wait 4 s", retry_after_s=4).retry_after_s == 4
    owners = [{"pid": 4242, "name": "exampletftpd.exe"}]
    assert tnt_tftp.TftpPortInUse("UDP port 69 is already used by exampletftpd.exe", owners=owners).owners == owners
    assert api_routes.TFTP_PORT_IN_USE_CODE == "tftp_port_in_use" and api_routes._STATUS_CODES[429] == "rate_limited"


def test_netcheck_routes_503_when_components_missing(server, engine):
    engine.natcheck = engine.switchport = engine.portcheck = None
    for method, path, body in (("GET", "/api/netcheck/nat", None), ("POST", "/api/netcheck/nat", None),
                               ("GET", "/api/netcheck/switch", None), ("POST", "/api/netcheck/switch", {"adapter": None}),
                               ("DELETE", "/api/netcheck/switch", None), ("POST", "/api/netcheck/portforward", {"port": 8000})):
        status, data = call_json(server, method, path, body)
        assert status == 503 and data["error"]["code"] == "unavailable", (method, path)


def test_capture_routes_503_when_component_missing(server, engine):
    engine.capture = None
    server.wifi_reveal_check = lambda peer, local: "denied"
    for method, path, body in CAPTURE_ROUTES:              # the administrator check comes first
        status, data = call_json(server, method, path, body)
        assert status == 403 and data["error"]["code"] == "admin_required", (method, path)
    server.wifi_reveal_check = lambda peer, local: "allowed"
    for method, path, body in CAPTURE_ROUTES:
        status, data = call_json(server, method, path, body)
        assert status == 503 and data["error"]["code"] == "unavailable", (method, path)
    status, data = call_json(server, "GET", "/api/status")      # the tile too: null without the component
    assert status == 200 and data["capture"] is None


def test_tftp_routes_503_when_component_missing(server, engine):
    engine.tftp = None
    for method, path, body in (("GET", "/api/tftp/status", None), ("POST", "/api/tftp/start", {"uploads": False}),
                               ("POST", "/api/tftp/stop", None), ("POST", "/api/tftp/uploads", {"on": True}),
                               ("PUT", "/api/tftp/settings", {"max_upload_mb": 512}), ("GET", "/api/tftp/files", None)):
        status, data = call_json(server, method, path, body)
        assert status == 503 and data["error"]["code"] == "unavailable", (method, path)
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["tftp"] is None

    class Broken:
        def summary(self):
            raise RuntimeError("no tftp for you")

    engine.tftp = Broken()
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["tftp"] is None and data["version"] == __version__


def test_nat_check_routes(server, network_tools):
    nat = network_tools["natcheck"]
    status, data = call_json(server, "GET", "/api/netcheck/nat")
    assert status == 200 and data == {"result": None, "running": False}
    status, data = call_json(server, "POST", "/api/netcheck/nat")
    assert status == 200 and data == {"result": NAT_RESULT, "running": False}
    assert list(data["result"]) == list(tnt_natcheck.NAT_RESULT_KEYS)
    nat.busy = True
    status, data = call_json(server, "GET", "/api/netcheck/nat")
    assert status == 200 and data == {"result": NAT_RESULT, "running": True}
    nat.fail_with = RuntimeError(tnt_natcheck.BUSY_TEXT)
    status, data = call_json(server, "POST", "/api/netcheck/nat")
    assert status == 409 and data["error"] == {"code": "conflict", "message": "a NAT check is already running"}
    nat.fail_with = RuntimeError("the check fell over")
    status, data = call_json(server, "POST", "/api/netcheck/nat")
    assert status == 500 and data["error"]["code"] == "internal_error"
    assert [c for c in nat.calls if c == ("run",)] == [("run",)] * 3


def test_switch_port_routes(server, network_tools):
    finder = network_tools["switchport"]
    status, data = call_json(server, "GET", "/api/netcheck/switch")
    assert status == 200 and list(data) == list(tnt_switchport.SWITCH_STATUS_KEYS) and data["job"]["state"] == "idle"
    status, data = call_json(server, "POST", "/api/netcheck/switch", {"adapter": "Ethernet", "seconds": 30})
    assert status == 200 and list(data) == ["job"] and data["job"]["state"] == "listening" and data["job"]["listen_s"] == 30
    status, data = call_json(server, "POST", "/api/netcheck/switch")         # no body: the service picks the adapter, 65 s
    assert status == 200 and data["job"]["listen_s"] == 65
    status, data = call_json(server, "DELETE", "/api/netcheck/switch")
    assert status == 200 and list(data) == ["job"] and data["job"]["state"] == "cancelled"
    assert finder.calls == [("status",), ("start", "Ethernet", 30), ("start", None, None), ("stop",)]
    for exc, expected, code in ((tnt_pktmon.PktmonUnavailable(tnt_pktmon.MISSING_REASON), 409, "unavailable"),
                                (tnt_pktmon.PktmonUnavailable(tnt_switchport.NO_WIRED_TEXT), 409, "unavailable"),
                                (tnt_pktmon.PktmonBusy(tnt_pktmon.LOCK_TEXTS["capture"]), 409, "conflict"),
                                (tnt_pktmon.PktmonBusy(tnt_pktmon.FOREIGN_SESSION_TEXT), 409, "conflict"),
                                (RuntimeError(tnt_switchport.BUSY_TEXT), 409, "conflict"),
                                (ValueError("seconds must be a whole number from 20 to 120"), 400, "bad_request"),
                                (RuntimeError("the search fell over"), 500, "internal_error")):
        finder.fail_with = exc
        status, data = call_json(server, "POST", "/api/netcheck/switch", {"seconds": "soon"})
        assert status == expected and data["error"] == {"code": code, "message": str(exc)}, exc


def test_port_forward_route(server, network_tools):
    checker = network_tools["portcheck"]
    status, data = call_json(server, "POST", "/api/netcheck/portforward", {"port": 8000})
    assert status == 200 and data == PORT_RESULT and list(data) == list(tnt_portcheck.PORTCHECK_RESULT_KEYS)
    # the port reaches the service as it was sent: only the service decides what a port is
    for body in ({"port": "8000"}, {"port": 8000.5}, {"port": True}, {"port": None}, {}):
        status, data = call_json(server, "POST", "/api/netcheck/portforward", body)
        assert status == 400 and data["error"] == {"code": "bad_request", "message": tnt_portcheck.PORTCHECK_PORT_TEXT}, body
    assert checker.calls == [("test", 8000), ("test", "8000"), ("test", 8000.5), ("test", True), ("test", None), ("test", None)]
    for exc, expected, code in ((tnt_portcheck.VpnActive(), 409, "vpn"), (tnt_portcheck.NoPublicIp(), 409, "no_public_ip"),
                                (RuntimeError(tnt_portcheck.PORTCHECK_BUSY_TEXT), 409, "conflict")):
        checker.fail_with = exc
        status, data = call_json(server, "POST", "/api/netcheck/portforward", {"port": 8000})
        assert status == expected and data["error"] == {"code": code, "message": str(exc)}, code
    assert str(tnt_portcheck.VpnActive()) == tnt_portcheck.PORTCHECK_VPN_TEXT
    assert str(tnt_portcheck.NoPublicIp()) == tnt_portcheck.PORTCHECK_NO_IP_TEXT
    checker.fail_with = tnt_portcheck.RateLimited(tnt_portcheck.PORTCHECK_RATE_TEXT.format(seconds=4), retry_after_s=4)
    status, headers, payload = call(server, "POST", "/api/netcheck/portforward", {"port": 8000})
    assert status == 429 and headers["retry-after"] == "4"
    assert json.loads(payload)["error"] == {"code": "rate_limited", "message": "Too many tests: wait 4 s"}


def test_capture_routes_need_an_administrator(server, network_tools, monkeypatch):
    mgr = network_tools["capture"]
    seen: List[Any] = []
    server.wifi_reveal_check = lambda peer, local: seen.append((peer, local)) or "denied"
    for method, path, body in CAPTURE_ROUTES:
        status, data = call_json(server, method, path, body)
        assert status == 403 and data["error"] == {"code": "admin_required", "message": api_routes.CAPTURE_ADMIN_REQUIRED_MSG}, path
    status, _headers, payload = call(server, "HEAD", f"/api/capture/files/{CAPTURE_NAME}")
    assert status == 403 and payload == b""
    peer, local = seen[0]
    assert peer[0].startswith("127.") and int(local[1]) == server.port

    def boom(peer: Any, local: Any) -> str:
        raise RuntimeError("token read exploded")

    for check in (lambda peer, local: "unknown", lambda peer, local: None, boom):
        server.wifi_reveal_check = check
        for method, path, body in CAPTURE_ROUTES:
            status, data = call_json(server, method, path, body)
            assert status == 403 and data["error"] == {"code": "admin_required",
                                                       "message": api_routes.CAPTURE_ADMIN_UNVERIFIED_MSG}, path
    import tnt.peer

    monkeypatch.setattr(tnt.peer, "reveal_allowed", lambda peer, local: "denied")
    server.wifi_reveal_check = None                                  # the production path: tnt.peer decides
    status, data = call_json(server, "GET", "/api/capture")
    assert status == 403 and data["error"]["message"] == api_routes.CAPTURE_ADMIN_REQUIRED_MSG
    assert mgr.calls == [] and mgr.opened == []


def test_capture_routes(server, network_tools):
    """The session's life through the routes: status, start, stop, save, open a saved file, discard, and the file list
    (download, HEAD, delete)."""
    mgr = network_tools["capture"]
    server.wifi_reveal_check = lambda peer, local: "allowed"
    status, data = call_json(server, "GET", "/api/capture")
    assert status == 200 and list(data) == list(tnt_capture.CAPTURE_STATUS_KEYS) and data["session"] is None
    assert list(data["adapters"][0]) == list(tnt_capture.CAPTURE_ADAPTER_KEYS) and data["adapters"] == [CAPTURE_ADAPTER]
    assert list(data["limits"]) == list(tnt_capture.LIMIT_KEYS) and data["limits"] == CAPTURE_LIMITS
    assert list(data["files"][0]) == list(tnt_capture.CAPTURE_FILE_KEYS) and data["files"] == [CAPTURE_FILE]
    start = {"adapter": "Ethernet", "max_seconds": 300, "max_mb": 64, "comment": "not a start key"}
    status, data = call_json(server, "POST", "/api/capture/start", start)
    assert status == 200 and data == {"session": CAPTURE_SESSION} and list(data["session"]) == list(tnt_capture.SESSION_KEYS)
    status, data = call_json(server, "POST", "/api/capture/start", {"adapter": "Ethernet"})   # the rest take the defaults
    assert status == 200
    status, data = call_json(server, "POST", "/api/capture/stop")                             # end it now and keep it
    assert status == 200 and list(data) == ["session"] and data["session"]["state"] == "stopped"
    assert data["session"]["stop_reason"] == "user"
    status, data = call_json(server, "POST", "/api/capture/save")                             # keep it as a saved file
    assert status == 200 and list(data) == ["session", "files"]
    assert data["session"]["saved"] is True and data["session"]["file"] == CAPTURE_NAME
    assert data["files"] == [CAPTURE_FILE] and list(data["files"][0]) == list(tnt_capture.CAPTURE_FILE_KEYS)
    status, data = call_json(server, "POST", "/api/capture/open", {"name": CAPTURE_NAME})     # read a saved one back
    assert status == 200 and list(data) == ["session"] and list(data["session"]) == list(tnt_capture.SESSION_KEYS)
    assert data["session"]["state"] == "loaded" and data["session"]["source"] == "file" and data["session"]["file"] == CAPTURE_NAME
    status, data = call_json(server, "POST", "/api/capture/discard")                          # throw it away
    assert status == 200 and data == {"session": None}
    status, headers, payload = call(server, "GET", f"/api/capture/files/{CAPTURE_NAME}")
    assert status == 200 and payload == CAPTURE_BYTES and headers["content-length"] == str(len(CAPTURE_BYTES))
    assert headers["content-disposition"] == f'attachment; filename="{CAPTURE_NAME}"'
    status, headers, payload = call(server, "HEAD", f"/api/capture/files/{CAPTURE_NAME}")
    assert status == 200 and payload == b"" and headers["content-type"] == "application/octet-stream"
    assert len(mgr.opened) == 2 and all(f.closed for f in mgr.opened), "the download closes its file, HEAD included"
    status, data = call_json(server, "DELETE", f"/api/capture/files/{CAPTURE_NAME}")
    assert status == 200 and data == {"files": []}
    assert mgr.calls == [("status",), ("start", "Ethernet", {"max_seconds": 300, "max_mb": 64}),
                         ("start", "Ethernet", {}), ("stop",), ("save",), ("files",), ("open_file", CAPTURE_NAME),
                         ("discard",), ("file_download", CAPTURE_NAME), ("file_download", CAPTURE_NAME),
                         ("delete_file", CAPTURE_NAME)]


def test_capture_packets_route_hands_the_query_on(server, network_tools):
    """The packet list's filters reach the manager exactly as they arrived (only the service decides what a filter is),
    and ``proto`` is read both ways the page may send it: repeated, and comma separated."""
    mgr = network_tools["capture"]
    server.wifi_reveal_check = lambda peer, local: "allowed"
    status, data = call_json(server, "GET", "/api/capture/packets")
    assert status == 200 and list(data) == list(tnt_capture.PACKETS_KEYS) and data["session"] is None
    assert data["rows"] == [CAPTURE_ROW] and list(data["rows"][0]) == list(tnt_capture.ROW_KEYS)
    assert data["total"] == 12 and data["matched"] == 1 and data["last"] == 1 and data["dropped_before"] is False
    query = "since=120&limit=50&ip=192.0.2.10&mac=02:00:5e:10:00:01&proto=sip&proto=rtp"
    status, data = call_json(server, "GET", "/api/capture/packets?" + query)
    assert status == 200 and list(data) == list(tnt_capture.PACKETS_KEYS)
    status, data = call_json(server, "GET", "/api/capture/packets?proto=sip,rtp&proto=dns")   # the same list, one parameter
    assert status == 200
    status, data = call_json(server, "GET", "/api/capture/packets?proto=&limit=nonsense")     # blanks are dropped, not guessed
    assert status == 200
    assert mgr.calls == [("packets", None, None, None, None, []),
                         ("packets", "120", "50", "192.0.2.10", "02:00:5e:10:00:01", ["sip", "rtp"]),
                         ("packets", None, None, None, None, ["sip", "rtp", "dns"]),
                         ("packets", None, "nonsense", None, None, [])]


def test_capture_packet_detail_route(server, network_tools):
    mgr = network_tools["capture"]
    server.wifi_reveal_check = lambda peer, local: "allowed"
    status, data = call_json(server, "GET", "/api/capture/packets/7")
    assert status == 200 and list(data) == list(tnt_capture.DETAIL_KEYS)
    assert data["row"] == CAPTURE_ROW and data["bytes"] == 74 and data["hex"][0].startswith("0000")
    assert data["layers"][0]["name"] == "ETH"
    assert mgr.calls == [("packet", "7")], "the packet number reaches the manager as it was sent"


def test_capture_calls_and_call_audio_routes(server, network_tools):
    """The SIP calls of the open capture, and one call rebuilt as a WAV file the browser can play."""
    mgr = network_tools["capture"]
    server.wifi_reveal_check = lambda peer, local: "allowed"
    status, data = call_json(server, "GET", "/api/capture/calls")
    assert status == 200 and data == {"calls": [CAPTURE_CALL]}
    status, headers, payload = call(server, "GET", f"/api/capture/calls/{CAPTURE_CALL_ID}/audio")
    assert status == 200 and payload == CAPTURE_WAV and headers["content-length"] == str(len(CAPTURE_WAV))
    assert headers["content-type"] == "audio/wav"
    assert headers["content-disposition"] == f'attachment; filename="TNT-call-{CAPTURE_CALL_ID}.wav"'
    assert mgr.calls == [("calls",), ("call_audio", CAPTURE_CALL_ID)]


def test_capture_errors_reach_their_status(server, network_tools):
    """tnt.capture's four typed errors and a ValueError from start(), each answered with the service's own text."""
    mgr = network_tools["capture"]
    server.wifi_reveal_check = lambda peer, local: "allowed"
    for exc, expected, code in ((ValueError(tnt_capture.ADAPTER_TEXT.format(name="Ethernet 2")), 400, "bad_request"),
                                (ValueError(tnt_capture.SECONDS_TEXT), 400, "bad_request"),
                                (ValueError(tnt_capture.SIZE_TEXT), 400, "bad_request"),
                                (tnt_capture.CaptureBusy(tnt_capture.BUSY_TEXT), 409, "conflict"),
                                (tnt_capture.CaptureUnavailable(tnt_capture.DISK_TEXT.format(mb=1536)), 409, "unavailable"),
                                (RuntimeError("the capture fell over"), 500, "internal_error")):
        mgr.fail_with = exc
        status, data = call_json(server, "POST", "/api/capture/start", {"adapter": "Ethernet"})
        assert status == expected and data["error"] == {"code": code, "message": str(exc)}, code
    mgr.fail_with = tnt_capture.CaptureFileBusy(tnt_capture.FILE_BUSY_TEXT)
    status, data = call_json(server, "DELETE", f"/api/capture/files/{CAPTURE_NAME}")
    assert status == 409 and data["error"] == {"code": "conflict", "message": "The file is being downloaded"}
    mgr.fail_with = tnt_capture.CaptureFileMissing(tnt_capture.FILE_MISSING_TEXT)
    for method, path, body in (("GET", "/api/capture/files/TNT-capture-2026.pcapng", None),
                               ("DELETE", "/api/capture/files/TNT-capture-2026.pcapng", None),
                               ("POST", "/api/capture/open", {"name": "TNT-capture-2026.pcapng"}),
                               ("GET", "/api/capture/packets/9999", None),
                               ("GET", f"/api/capture/calls/{CAPTURE_CALL_ID}/audio", None)):
        status, data = call_json(server, method, path, body)
        assert status == 404 and data["error"] == {"code": "not_found",
                                                   "message": "The capture file was not found"}, (method, path)
    mgr.fail_with = tnt_capture.CaptureUnavailable(f"{CAPTURE_NAME} is not a capture TNT can read")
    status, data = call_json(server, "POST", "/api/capture/open", {"name": CAPTURE_NAME})
    assert status == 409 and data["error"] == {"code": "unavailable", "message": str(mgr.fail_with)}


def test_status_carries_the_capture_tile(server, engine, network_tools):
    """``GET /api/status`` carries TILE_KEYS and nothing else of the capture: counts and the adapter's name, so the
    Packet capture tile needs no administrator (the packets themselves still do)."""
    mgr = network_tools["capture"]
    checks: List[Any] = []
    server.wifi_reveal_check = lambda peer, local: checks.append(peer) or "denied"
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and list(data["capture"]) == list(tnt_capture.TILE_KEYS)
    assert data["capture"] == {"available": True, "reason": None, "running": False, "adapter": None, "packets": 0,
                               "calls": 0, "files": 1}
    mgr.session = dict(CAPTURE_SESSION, packets=412, calls=2)
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["capture"]["running"] is True and data["capture"]["adapter"] == "Ethernet"
    assert data["capture"]["packets"] == 412 and data["capture"]["calls"] == 2
    assert checks == [], "the tile is counts only: it never asks whether the caller is an administrator"

    class Broken:
        def tile(self):
            raise RuntimeError("no capture for you")

    engine.capture = Broken()
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["capture"] is None and data["version"] == __version__
    engine.capture = None
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["capture"] is None


def test_tftp_routes(server, network_tools):
    tftp = network_tools["tftp"]
    status, data = call_json(server, "GET", "/api/tftp/status")
    assert status == 200 and list(data) == list(tnt_tftp.TFTP_STATUS_KEYS) and data["running"] is False
    status, data = call_json(server, "POST", "/api/tftp/start", {"adapter": "Ethernet", "uploads": True})
    assert status == 200 and data["running"] is True and data["uploads"] is True
    status, data = call_json(server, "GET", "/api/status")
    assert status == 200 and data["tftp"] == tftp.summary() and list(data["tftp"]) == list(tnt_tftp.TFTP_SUMMARY_KEYS)
    status, data = call_json(server, "POST", "/api/tftp/stop")
    assert status == 200 and data["running"] is False
    status, data = call_json(server, "POST", "/api/tftp/start")                  # no body: the saved adapter, uploads off
    assert status == 200 and data["running"] is True and data["uploads"] is False
    status, data = call_json(server, "POST", "/api/tftp/uploads", {"on": True})
    assert status == 200 and data["uploads"] is True
    status, data = call_json(server, "PUT", "/api/tftp/settings", {"adapter": "Ethernet", "max_upload_mb": 512})
    assert status == 200 and data["settings"] == {"adapter": "Ethernet", "max_upload_mb": 512}
    status, data = call_json(server, "GET", "/api/tftp/files")
    assert status == 200 and data == {"files": [{"name": "boot/pxelinux.0", "size": 26828, "mtime": T0}]}
    assert tftp.calls == [("status",), ("start", "Ethernet", True), ("stop",), ("start", None, False), ("set_uploads", True),
                          ("update_settings", {"adapter": "Ethernet", "max_upload_mb": 512}), ("files",)]
    for method, path, body, message in (("POST", "/api/tftp/start", {"uploads": None}, "uploads must be true or false"),
                                        ("POST", "/api/tftp/uploads", {}, "on must be true or false"),
                                        ("POST", "/api/tftp/uploads", {"on": "yes"}, "on must be true or false"),
                                        ("PUT", "/api/tftp/settings", {"root": "C:/"}, "unknown TFTP setting 'root'"),
                                        ("PUT", "/api/tftp/settings", [1], "JSON body must be an object")):
        status, data = call_json(server, method, path, body)
        assert status == 400 and data["error"] == {"code": "bad_request", "message": message}, (path, body)
    owners = [{"pid": 4242, "name": "exampletftpd.exe"}, {"pid": 4243, "name": "PID 4243"}]
    tftp.fail_with = tnt_tftp.TftpPortInUse("UDP port 69 is already used by exampletftpd.exe, PID 4243", owners=owners)
    status, data = call_json(server, "POST", "/api/tftp/start", {"adapter": None, "uploads": False})
    assert status == 409 and data == {"error": {"code": "tftp_port_in_use",
                                                "message": "UDP port 69 is already used by exampletftpd.exe, PID 4243"},
                                      "owners": owners}
    tftp.fail_with = tnt_tftp.TftpPortInUse("UDP port 69 is already used by another program")
    status, data = call_json(server, "POST", "/api/tftp/start", {"uploads": False})
    assert status == 409 and data["error"]["code"] == "tftp_port_in_use" and data["owners"] == []
    tftp.fail_with = RuntimeError("UDP port 69 could not be opened (access denied: WinError 10013)")
    status, data = call_json(server, "POST", "/api/tftp/start", {"uploads": False})
    assert status == 500 and data["error"]["code"] == "internal_error"


@pytest.fixture
def capture_folder(server, engine, tmp_path):
    """A real tnt.capture.CaptureManager on a temporary captures folder (only file_download / delete_file / files run,
    so no ETW session is ever created), for an administrator."""
    folder = tmp_path / "captures"
    folder.mkdir()
    engine.capture = tnt_capture.CaptureManager(engine.bus, captures_dir_fn=lambda: folder)
    server.wifi_reveal_check = lambda peer, local: "allowed"
    return folder


def test_capture_download_head_then_delete(server, capture_folder):
    """FileResponse: the headers, the file in chunks, HEAD with no body; neither holds the file, so a delete right after
    succeeds (Windows refuses to delete an open file)."""
    data = b"\x0a\x0d\x0d\x0a" + bytes(range(256)) * 700              # a little under three 64 KiB chunks
    (capture_folder / CAPTURE_NAME).write_bytes(data)
    url = f"/api/capture/files/{CAPTURE_NAME}"
    status, headers, payload = call(server, "GET", url)
    assert status == 200 and payload == data
    assert headers["content-type"] == "application/octet-stream" and headers["content-length"] == str(len(data))
    assert headers["content-disposition"] == f'attachment; filename="{CAPTURE_NAME}"'
    assert headers["cache-control"] == "no-cache" and headers["x-content-type-options"] == "nosniff"
    status, headers, payload = call(server, "HEAD", url)
    assert status == 200 and payload == b"" and headers["content-length"] == str(len(data))
    status, body = call_json(server, "DELETE", url)
    assert status == 200 and body == {"files": []} and not (capture_folder / CAPTURE_NAME).exists()
    for name in (CAPTURE_NAME, "CON", "TNT-capture-2026.pcapng", "..%5C" + CAPTURE_NAME):
        for method in ("GET", "DELETE"):
            status, body = call_json(server, method, f"/api/capture/files/{name}")
            assert status == 404 and body["error"] == {"code": "not_found", "message": tnt_capture.FILE_MISSING_TEXT}, (method, name)


def test_capture_download_the_client_abandons_does_not_hold_the_file(server, capture_folder):
    """While a download runs the file cannot be deleted (409); once the client resets the connection the server closes the
    file, and the delete goes through."""
    path = capture_folder / CAPTURE_NAME
    with open(path, "wb") as fh:
        fh.truncate(64 * 1024 * 1024)                                   # far more than the socket buffers take in
    url = f"/api/capture/files/{CAPTURE_NAME}"
    sock = socket.create_connection(("127.0.0.1", server.port), timeout=10)
    try:
        sock.sendall(f"GET {url} HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n\r\n".encode("ascii"))
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(65536)
            assert chunk, "the server closed the connection"
            head += chunk
        assert head.startswith(b"HTTP/1.1 200 ")
        status, body = call_json(server, "DELETE", url)
        assert status == 409 and body["error"] == {"code": "conflict", "message": tnt_capture.FILE_BUSY_TEXT}
    finally:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH", 1, 0))    # a reset, not a clean close
        sock.close()
    assert _wait_for(lambda: call_json(server, "DELETE", url)[0] == 200, 10.0)
    assert not path.exists()


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


def test_sse_capture_events_go_to_administrators_only(server, engine):
    """``capture.state`` carries the session (the adapter, the file name) and ``capture.sip`` a SIP call (its URIs), which
    every /api/capture route refuses to anyone who is not a Windows administrator: the event stream leaves both out for them
    too (asked once per stream, at the first such event, failing closed) and still forwards everything else."""
    assert api_routes.ADMIN_ONLY_EVENTS == frozenset({tnt_capture.EVENT, tnt_capture.SIP_EVENT})
    state = {"session": CAPTURE_SESSION}
    sip = {"call": CAPTURE_CALL}
    for decision in ("denied", "unknown", "allowed"):
        checks: List[Any] = []
        server.wifi_reveal_check = lambda peer, local, d=decision: checks.append(peer) or d
        frames: List[str] = []
        ready = threading.Event()
        t = threading.Thread(target=_read_sse_frames, args=(server.port, "event: ping.sample", frames, ready), daemon=True)
        t.start()
        assert ready.wait(10), frames
        engine.bus.publish(tnt_capture.EVENT, state, ts=T0)
        engine.bus.publish(tnt_capture.EVENT, state, ts=T0)
        engine.bus.publish(tnt_capture.SIP_EVENT, sip, ts=T0)
        engine.bus.publish("ping.sample", {"target_id": 1, "ok": True, "rtt_ms": 12.5, "light": "green"}, ts=T0)
        t.join(10)
        assert not t.is_alive(), frames
        sessions = [json.loads(f.split("data: ", 1)[1].strip()) for f in frames if f"event: {tnt_capture.EVENT}" in f]
        calls = [json.loads(f.split("data: ", 1)[1].strip()) for f in frames if f"event: {tnt_capture.SIP_EVENT}" in f]
        assert sessions == ([dict(state, ts=T0)] * 2 if decision == "allowed" else []), decision
        assert calls == ([dict(sip, ts=T0)] if decision == "allowed" else []), decision
        assert len(checks) == 1, decision            # once per stream, at the first admin-only event, for both types
        assert any("event: ping.sample" in f for f in frames), decision
        deadline = time.time() + 5
        while server.clients_sse and time.time() < deadline:
            time.sleep(0.05)


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
    eng.networks, eng.reports = Component("networks"), Component("reports")
    eng.natcheck, eng.tftp, eng.switchport = Component("natcheck"), Component("tftp", fail=True), Component("switchport")
    # the port-forward test and packet capture keep nothing that describes the network: never told
    eng.portcheck, eng.capture = Component("portcheck"), Component("capture")
    eng._netinfo_cache, eng._netinfo_cache_ts = {"internet_nic": {"name": "Wi-Fi"}, "adapter_count": 2}, time.time()
    eng._disc_defaults, eng._disc_defaults_ts = {"default_range": "192.168.10.0/24"}, time.time()
    release = threading.Event()
    eng._disc_thread = threading.Thread(target=release.wait, args=(5.0,), daemon=True)
    eng._disc_thread.start()
    try:
        eng._on_net_changed({"generation": 4, "ts": T0, "summary": "Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"})
        assert calls == [("networks", 4), ("ping", 4), ("outages", 4), ("linkmap", 4), ("natcheck", 4), ("lan", 4), ("dhcp", 4),
                         ("tftp", 4), ("switchport", 4), ("reports", 4)], "a failing component never stops the rest"
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


def test_engine_ip_release_renew_pauses_only_what_it_paused(data_dir, monkeypatch):
    from tnt import netinfo, nettools
    from tnt.engine import Engine

    eng = Engine(console=True, port=0, data_dir=data_dir)
    eng.ping = FakePing()
    order: List[Any] = []
    gaps: List[str] = []
    eng.netwatch = SimpleNamespace(poll_soon=lambda: order.append("poll_soon"))
    monkeypatch.setattr(netinfo, "_invalidate_cache", lambda: order.append("netinfo cache"))
    monkeypatch.setattr(eng, "_monitoring_gap", lambda start, end, note: gaps.append(note))

    def fake_release_renew(**kw: Any) -> Dict[str, Any]:
        order.append(("release_renew", getattr(eng.ping, "paused", None)))
        return dict(RENEW_RESULT)

    monkeypatch.setattr(nettools, "release_renew", fake_release_renew)
    eng._netinfo_cache, eng._netinfo_cache_ts = {"internet_nic": {"name": "Wi-Fi"}, "adapter_count": 1}, time.time()
    res = eng.ip_release_renew()
    assert res == dict(RENEW_RESULT, paused_monitoring=True) and list(res) == list(RENEW_RESULT)
    assert order == [("release_renew", True), "netinfo cache", "poll_soon"]
    assert eng.ping.paused is False and gaps == ["monitoring paused"], "the time without an address is a monitoring gap"
    assert eng._netinfo_cache is None and eng._netinfo_cache_ts == 0.0

    eng.ping.set_paused(True)                                                  # paused by the user: left paused
    order.clear()
    gaps.clear()
    res = eng.ip_release_renew()
    assert res["paused_monitoring"] is False and eng.ping.paused is True and gaps == []
    assert order == [("release_renew", True), "netinfo cache", "poll_soon"]

    eng.ping = None                                                            # no ping monitoring: just run
    order.clear()
    assert eng.ip_release_renew()["paused_monitoring"] is False and order[0] == ("release_renew", None)

    eng.ping = FakePing()
    monkeypatch.setattr(nettools, "release_renew", lambda **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    order.clear()
    with pytest.raises(RuntimeError, match="boom"):
        eng.ip_release_renew()
    assert eng.ping.paused is False and order == ["netinfo cache", "poll_soon"], "resumed and refreshed even then"
    monkeypatch.setattr(nettools, "release_renew", fake_release_renew)
    assert eng.ip_release_renew()["ok"] is True, "the lock was released"


def test_engine_ip_release_renew_runs_one_at_a_time(server, engine, data_dir, monkeypatch):
    from tnt import nettools
    from tnt.engine import Engine

    eng = Engine(console=True, port=0, data_dir=data_dir)
    started, finish = threading.Event(), threading.Event()

    def slow(**kw: Any) -> Dict[str, Any]:
        started.set()
        finish.wait(5.0)
        return dict(RENEW_RESULT)

    monkeypatch.setattr(nettools, "release_renew", slow)
    results: List[Dict[str, Any]] = []
    worker = threading.Thread(target=lambda: results.append(eng.ip_release_renew()), daemon=True)
    worker.start()
    try:
        assert started.wait(5.0)
        with pytest.raises(RuntimeError, match="An IP release/renew is already running"):
            eng.ip_release_renew()
        engine.ip_release_renew = eng.ip_release_renew
        server.wifi_reveal_check = lambda peer, local: "allowed"
        status, data = call_body(server, "POST", "/api/tools/ip/renew")
        assert status == 409 and data["error"] == {"code": "conflict", "message": "An IP release/renew is already running"}
    finally:
        finish.set()
        worker.join(5.0)
    assert results == [dict(RENEW_RESULT, paused_monitoring=False)]
    status, data = call_body(server, "POST", "/api/tools/ip/renew")
    assert status == 200 and data["ok"] is True


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
        # the network tools are there from the start and idle (their wiring: test_engine_wires_the_network_tools)
        assert data["tftp"]["running"] is False and not {"natcheck", "portcheck", "switchport", "capture", "tftp"} & set(eng.errors)
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


def test_engine_wires_the_network_tools(data_dir, monkeypatch):
    """Start order: NatChecker and PortChecker after the IP location manager, TftpServer right after the DHCP server (its
    folder secured), SwitchPortFinder and CaptureManager right after the LAN peers (recover() on tnt-capture-recover, not
    waited for), all before the network watcher.  Neither start nor stop runs pktmon or netsh."""
    from tnt import firewall, paths, winacl
    from tnt.engine import Engine

    seed = tnt_db.Database(data_dir / "tnt.db")
    seed.set_meta("defaults_loaded", "1")
    seed.close()
    ran: List[Any] = []

    def no_pktmon(*args: Any, **kwargs: Any) -> Any:
        ran.append(("pktmon", args))
        raise OSError("pktmon is disabled in tests")

    monkeypatch.setattr(tnt_pktmon, "_subprocess_run", no_pktmon)
    monkeypatch.setattr(firewall, "run_netsh", lambda args, *a, **kw: ran.append(("netsh", list(args))) or (1, "disabled in tests"))
    secured: List[Any] = []
    monkeypatch.setattr(winacl, "_set_file_security", lambda path, sddl: secured.append((os.path.normcase(str(path)), sddl)))
    release = threading.Event()
    recovering: List[str] = []

    def slow_recover(self: Any) -> None:
        recovering.append(threading.current_thread().name)
        release.wait(5.0)

    monkeypatch.setattr(tnt_capture.CaptureManager, "recover", slow_recover)
    order: List[str] = []
    steps = ("_start_geoip", "_start_natcheck", "_start_portcheck", "_start_outages", "_start_dhcp", "_start_tftp", "_start_lan",
             "_start_switchport", "_start_capture", "_start_netwatch")
    for step in steps:
        monkeypatch.setattr(Engine, step, lambda self, _real=getattr(Engine, step), _step=step: (order.append(_step), _real(self))[1])

    eng = Engine(console=True, port=0, data_dir=data_dir)
    t0 = time.monotonic()
    eng.start()
    try:
        assert time.monotonic() - t0 < 10.0
        assert order == list(steps)
        assert isinstance(eng.natcheck, tnt_natcheck.NatChecker) and isinstance(eng.portcheck, tnt_portcheck.PortChecker)
        assert isinstance(eng.switchport, tnt_switchport.SwitchPortFinder) and isinstance(eng.capture, tnt_capture.CaptureManager)
        assert isinstance(eng.tftp, tnt_tftp.TftpServer) and eng.tftp.running is False
        assert not {"natcheck", "portcheck", "switchport", "capture", "tftp"} & set(eng.errors)
        # the TFTP folder is created and secured at start; the captures folder only when a capture or search starts
        assert paths.tftp_dir().is_dir() and (os.path.normcase(str(paths.tftp_dir())), winacl.TFTP_SDDL) in secured
        assert not paths.captures_dir().exists() and all(sddl != winacl.CAPTURES_SDDL for _path, sddl in secured)
        assert recovering == ["tnt-capture-recover"], "recover() runs on its own thread"
        assert any(t.name == "tnt-capture-recover" and t.daemon and t.is_alive() for t in threading.enumerate()), \
            "start() did not wait for it"
        assert eng.speed is not None and eng.speed._pinger is eng.pinger, "the latency-under-load probe gets the pinger"
        assert eng.natcheck._refresh_fn == eng.linkmap.refresh_public_ip == eng.portcheck._refresh_fn
        assert eng.natcheck._generation_fn() == eng.netwatch.generation == eng.switchport._generation()
        status, data = call_json(eng.api, "GET", "/api/status")
        assert status == 200 and list(data["tftp"]) == list(tnt_tftp.TFTP_SUMMARY_KEYS) and data["tftp"]["running"] is False
        status, data = call_json(eng.api, "GET", "/api/netcheck/nat")
        assert status == 200 and data == {"result": None, "running": False}
        status, data = call_json(eng.api, "GET", "/api/tftp/files")
        assert status == 200 and data == {"files": []}
    finally:
        release.set()
        t1 = time.monotonic()
        eng.stop()
        assert time.monotonic() - t1 < 8.5
    assert ran == [], "no pktmon or netsh at start or stop"
    assert _wait_for(lambda: not any(t.name == "tnt-pktmon-recover" and t.is_alive() for t in threading.enumerate()))


def test_engine_network_tool_accessors_look_when_they_are_called(data_dir):
    """The public address, the network change time and generation and the NAT verdict are read from the engine when a
    check asks (the network watcher starts after the checks); the refresh is the link map's, when there is one."""
    from tnt.engine import Engine

    eng = Engine(console=True, port=0, data_dir=data_dir)
    view = {"public_ip": {"ip": "203.0.113.5", "ts": T0, "error": None, "checked_ts": T0}}
    refreshed: List[int] = []
    eng.linkmap = SimpleNamespace(view=lambda: view, refresh_public_ip=lambda: refreshed.append(1) or view["public_ip"])
    eng._start_natcheck()
    eng._start_portcheck()
    eng._start_switchport()
    nat, port, finder = eng.natcheck, eng.portcheck, eng.switchport
    assert not {"natcheck", "portcheck", "switchport"} & set(eng.errors)
    for checker in (nat, port):
        assert checker._public_ip_fn() == view["public_ip"] and checker._public_ip_fn() is not view["public_ip"]
        assert checker._changed_ts_fn() is None and checker._generation_fn() == 0
        checker._refresh_fn()
    assert refreshed == [1, 1] and port._nat_verdict_fn() is None and finder._generation() == 0
    eng.netwatch = SimpleNamespace(state=lambda: {"generation": 7, "changed_ts": T0 + 5}, generation=7)   # a property there
    view["public_ip"] = {"ip": "198.51.100.20", "ts": T0 + 9, "error": None, "checked_ts": T0 + 9}
    for checker in (nat, port):
        assert checker._changed_ts_fn() == T0 + 5 and checker._generation_fn() == 7
        assert checker._public_ip_fn()["ip"] == "198.51.100.20"
    assert finder._generation() == 7
    eng.natcheck = SimpleNamespace(last=lambda: dict(NAT_RESULT, verdict="vpn"))
    assert port._nat_verdict_fn() == "vpn"
    eng.natcheck = eng.linkmap = eng.netwatch = None
    assert port._nat_verdict_fn() is None and nat._public_ip_fn() == {} and nat._changed_ts_fn() is None
    assert nat._generation_fn() == 0 and finder._generation() == 0
    eng._start_natcheck()
    assert eng.natcheck._refresh_fn is None, "no link map at start: nothing to refresh"


def test_engine_network_tools_that_cannot_start_are_left_out(data_dir, monkeypatch):
    """A module that does not import leaves its component None with ``errors[name]`` (the routes answer 503); a TFTP folder
    that cannot be prepared never takes the server away."""
    from tnt.engine import Engine

    eng = Engine(console=True, port=0, data_dir=data_dir)
    names = ("natcheck", "portcheck", "tftp", "switchport", "capture")
    with monkeypatch.context() as mp:
        for name in names:
            mp.setitem(sys.modules, f"tnt.{name}", None)
        for name in names:
            getattr(eng, f"_start_{name}")()
    assert [getattr(eng, name) for name in names] == [None] * len(names) and set(names) <= set(eng.errors)
    eng.errors.clear()

    def no_folder(self: Any) -> None:
        raise RuntimeError("the folder exploded")

    monkeypatch.setattr(tnt_tftp.TftpServer, "ensure_root", no_folder)
    eng._start_tftp()
    assert isinstance(eng.tftp, tnt_tftp.TftpServer) and "tftp" not in eng.errors


def test_engine_stop_order_of_the_network_tools(data_dir):
    """The TFTP server stops right after the DHCP server; the capture and then the switch port finder close right after the
    LAN peers, each with a 1 s timeout, and a close that hangs is not waited for."""
    from tnt.engine import Engine

    eng = Engine(console=True, port=0, data_dir=data_dir)
    order: List[Any] = []
    hang = threading.Event()

    class Part:
        def __init__(self, name: str) -> None:
            self.name = name

        def stop(self) -> None:
            order.append(self.name)

        def close(self, timeout: float) -> None:
            order.append((self.name, timeout))
            if self.name == "switchport":
                hang.wait(5.0)

    eng.dhcp, eng.tftp, eng.lan, eng.capture, eng.switchport = (Part(n) for n in ("dhcp", "tftp", "lan", "capture", "switchport"))
    eng._running = True
    try:
        t0 = time.monotonic()
        eng.stop()
        assert time.monotonic() - t0 < 3.0
    finally:
        hang.set()
    assert order == ["dhcp", "tftp", "lan", ("capture", 1.0), ("switchport", 1.0)]


def test_engine_retention_applies_the_capture_retention(data_dir):
    import datetime

    from tnt.engine import Engine

    eng = Engine(console=True, port=0, data_dir=data_dir)
    seen: List[float] = []
    eng.capture = SimpleNamespace(enforce_retention=lambda now: seen.append(now) or 3)
    eng._run_retention(T0, scheduled=False)
    assert seen == [T0]
    sunday = next(T0 + d * 86400 for d in range(7) if datetime.datetime.fromtimestamp(T0 + d * 86400).weekday() == 6)
    vacuums: List[str] = []
    eng.db = SimpleNamespace(retention=lambda days, now: {}, vacuum=lambda: vacuums.append("vacuum"), set_meta=lambda k, v: None)

    def locked(now: float) -> int:
        raise PermissionError(32, "The process cannot access the file because it is being used by another process")

    eng.capture = SimpleNamespace(enforce_retention=locked)
    eng._run_retention(sunday, scheduled=True)          # never raises, and the weekly vacuum still runs
    assert vacuums == ["vacuum"]


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


def test_selfcheck_modules_include_the_network_tools():
    """The network tools are in the self-check list and import with no side effect (no socket, no Packet Monitor,
    no DLL call).

    Where they sit in the list is no longer pinned: it holds every module of the package now, which
    tests/test_packaging.py enforces, and an adjacency assertion on top of that only says how it happens to be
    sorted."""
    import importlib

    from tnt import service

    mods = list(service.SELFCHECK_MODULES)
    for name in ("tnt.winacl", "tnt.natcheck", "tnt.portcheck", "tnt.pcapng", "tnt.lldp", "tnt.pktmon",
                 "tnt.switchport", "tnt.capture", "tnt.tftp", "tnt.speedtest.quality"):
        assert name in mods, name
        importlib.import_module(name)
    assert len(set(mods)) == len(mods), "no module is checked twice"


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
