#!/usr/bin/env python3
"""Mock TNT API server for developing the web UI without the service.

Stdlib only, no ``tnt`` imports.  Serves ``ui/`` and a realistic fake of every
``/api`` route the service exposes with plausible,
evolving data:

* three ping targets (gateway, 1.1.1.1, totalelectronics.com) with traffic lights,
  one ``ping.sample`` SSE event per target per second, occasional misses and a
  periodic "sluggish" phase so the yellow light and red sparkline ticks show up;
* an outage timeline for the last 24 h with a yellow (target) span, a red
  (total internet) span and a grey monitoring gap;
* 7 days of 15-minute speed tests with an evening slowdown and a few failures;
* a discovery scan that progresses over ~4 s after ``POST /api/discovery/scan``;
* a fake DHCP server (Tools view): ``POST /api/dhcp/start`` answers 409 with the
  "other server" payload unless ``force`` is set (or ``STATE.dhcp_force_none``);
  once on, three clients appear over ~8 s with ``dhcp.lease`` events;
* a traceroute (``POST /api/tools/traceroute``) of ~9 hops that arrive ~0.3 s apart
  with ``trace.start`` / ``trace.hop`` / ``trace.done`` events, one silent hop and a
  CGNAT hop included; ``GET /api/tools/traceroute/last`` keeps the last one;
* two LAN peers (``GET /api/tools/lan/peers``, ``lan.peers`` every 10 s) and a ~4 s
  throughput test (``POST /api/tools/lan/throughput``) with progress events and a
  result around 940 / 910 Mbps; 409 while one runs; ``/last`` keeps the result;
  ``PUT /api/tools/lan/settings`` ``{"enabled": false}`` switches discovery off: the
  peer list goes empty with ``listening`` false and ``error`` "disabled", the 10 s
  ``lan.peers`` broadcast stops, a throughput test is refused with 400 and the whole
  peers view is published as ``lan.state``;
* three saved Wi-Fi networks (``GET /api/tools/wifi/profiles``) on one wireless
  interface, two WPA2-PSK with a key and one open network without; ``reveal`` is off by
  default and leaves the keys out but keeps ``key_present``. ``reveal=1`` returns the keys but
  only to an administrator: ``STATE.wifi_admin`` is True by default so the UI works; a test can
  set it False to get the real service's 403 ``admin_required``. Like the service, a browser
  request from a page of another origin gets 403 ``forbidden`` instead;
* settings persisted in memory (``ui.show_ipv6`` included); ``POST /api/export``
  returns a tiny valid PDF; ``status.map.public_ip`` carries a fake WAN address.

SSE framing: ``event: <type>`` / ``data: <json of the event's data>``; the first
event is ``hello``; ``: ping`` comments every 15 s.

Usage::

    python tools/mock_api.py --port 7136
"""
from __future__ import annotations

import argparse
import copy
import json
import logging
import math
import mimetypes
import os
import queue
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

log = logging.getLogger("mock_api")

ROOT = Path(__file__).resolve().parent.parent
UI_DIR = ROOT / "ui"
VERSION = "1.0.0"

DEFAULT_PORTS = [22, 80, 443, 554, 5060, 7001, 8000, 8080, 8443]
DEFAULTS: Dict[str, Any] = {
    "api": {"host": "127.0.0.1", "port": 7130},
    "ping": {"interval_s": 1.0, "timeout_ms": 1000, "loaded": True, "loaded_bytes": 1200,
             "unloaded_bytes": 32, "ttl": 128, "resolve_interval_s": 300},
    "outage": {"miss_threshold": 3, "recover_threshold": 3},
    "thresholds": {"window_s": 60, "local_warn_ms": 30, "internet_warn_ms": 150,
                   "warn_loss_pct": 2.0, "bad_loss_pct": 15.0},
    "speedtest": {"enabled": True, "interval_min": 15, "backend": "auto", "download_mb": 50, "upload_mb": 20,
                  "duration_s": 8, "connections": 4, "timeout_s": 120, "warn_below_pct": 50},
    "discovery": {"ports": list(DEFAULT_PORTS), "ping_timeout_ms": 500, "ping_attempts": 2,
                  "port_timeout_ms": 750, "concurrency": 128, "resolve_hostnames": True, "max_hosts": 4096},
    "retention": {"days": 365},
    "ui": {"theme": "light", "show_ipv6": False},
    "lan": {"enabled": True},
    "targets": {"defaults_extra": ["1.1.1.1", "totalelectronics.com"]},
    "dhcp": {"adapter": "", "pool_start": "", "pool_end": "", "pool_size": 5, "lease_s": 3600,
             "static_ip": "172.16.4.100", "static_prefix": 24, "ping_check": True, "scan_wait_s": 8},
}
#: settings a release removed: PUT /api/settings drops them instead of storing them (same as tnt.config._RETIRED_KEYS)
RETIRED_SETTINGS = ("speedtest.ookla_path", "speedtest.ookla_server_id", "discovery.use_nmap", "discovery.nmap_path")

DHCP_FIREWALL_RULE = "TNT DHCP server (UDP 67 in)"
# up adapters with an IPv4 (candidates for the Tools adapter picker); Ethernet is DHCP-enabled so
# turning the server on "re-addresses" it to the static 172.16.4.100/24 -- and it is also the PC's
# internet connection (is_internet), so the UI shows its loud "this PC goes offline" warning
DHCP_ADAPTERS = [
    {"name": "Ethernet", "index": 12, "mac": "D8:BB:C1:12:34:08", "ip": "10.0.0.112", "prefix": 24, "mask": "255.255.255.0",
     "dhcp_enabled": True, "dhcp_server": "10.0.0.251", "gateway": "10.0.0.251", "is_physical": True, "type_name": "Ethernet", "status": "up",
     "is_internet": True},
    {"name": "vEthernet (Default Switch)", "index": 30, "mac": "00:15:5D:01:02:03", "ip": "172.29.64.1", "prefix": 20, "mask": "255.255.240.0",
     "dhcp_enabled": False, "dhcp_server": None, "gateway": None, "is_physical": False, "type_name": "Ethernet", "status": "up",
     "is_internet": False},
    {"name": "Tailscale", "index": 21, "mac": "", "ip": "100.101.22.7", "prefix": 32, "mask": "255.255.255.255",
     "dhcp_enabled": False, "dhcp_server": None, "gateway": None, "is_physical": False, "type_name": "Tunnel", "status": "up",
     "is_internet": False},
]
DHCP_FAKE_CLIENTS = [
    ("AA:BB:CC:10:20:01", "cam-lobby", "Hangzhou Hikvision Digital Technology Co., Ltd.", 1.4, [80, 554]),
    ("3C:D9:2B:12:34:03", "printer-hp", "Hewlett Packard", 2.1, [80, 443]),
    ("DA:12:34:12:34:0E", None, "Locally administered (randomized)", 11.2, []),
]
PUBLIC_IP = "203.0.113.5"
PC_HOSTNAME = "TEC-DESKTOP"
PC_IP = "10.0.0.112"
# the path to totalelectronics.com: (ip, hostname, kind, label, base rtt ms, probes lost)
# hop 5 never answers; hop 8 drops one of its three probes
TRACE_PATH = [
    ("10.0.0.251", "gateway.lan", "gateway", "Gateway", 0.6, 0),
    ("100.64.0.1", None, "lan", "LAN", 3.1, 0),
    ("198.51.100.1", "core1.anytown.example.net", "public", "Internet", 9.4, 0),
    ("198.51.100.9", "edge2.anytown.example.net", "public", "Internet", 12.2, 0),
    (None, None, "unknown", "No reply", None, 3),
    ("198.51.100.65", "transit1.example.net", "public", "Internet", 24.6, 0),
    ("198.51.100.130", "peer1.example.net", "public", "Internet", 19.3, 0),
    ("203.0.113.254", None, "public", "Internet", 128.0, 1),
    ("203.0.113.80", "totalelectronics.com", "destination", "Destination", 19.1, 0),
]
LAN_PEERS = [
    ("7f3a9c1e", "TEC-LAPTOP-02", "10.0.0.42", VERSION, "Ethernet"),
    ("b21d0e77", "BENCH-PC", "10.0.0.77", "0.9.4", "Ethernet"),
]
#: the only key PUT /api/tools/lan/settings accepts (same as tnt.api.routes.LAN_SETTINGS_KEYS)
LAN_SETTINGS_KEYS = ("enabled",)
#: this PC's wireless interface and the profiles it saved (GET /api/tools/wifi/profiles);
#: (name, ssid, authentication, encryption, key, connection_mode, non_broadcast)
WIFI_INTERFACE = {"guid": "12345678-9abc-4def-8123-456789abcdef",
                  "description": "Intel(R) Wireless-AC 9560 160MHz", "state": "connected"}
WIFI_PROFILES = [
    ("TEC-Office", "TEC-Office", "WPA2PSK", "AES", "example-office-passphrase", "auto", False),
    ("TEC-Guest", "TEC-Guest", "WPA2PSK", "AES", "example-guest-passphrase", "auto", False),
    ("SiteSurvey-5G", "SiteSurvey-5G", "open", "none", None, "manual", True),
]
#: the service's 403 when a non-admin asks for reveal=1 (mirrors tnt.api.routes.WIFI_ADMIN_REQUIRED_MSG)
WIFI_ADMIN_REQUIRED_MSG = "Showing saved Wi-Fi passwords needs a Windows administrator account."
#: ... and when a browser page of another origin asks (mirrors tnt.api.routes.WIFI_CROSS_ORIGIN_MSG)
WIFI_CROSS_ORIGIN_MSG = "Saved Wi-Fi passwords are only shown to the TNT window or a page served by this TNT service."


def cross_origin_browser_request(headers: Any, port: int) -> bool:
    """The service's rule for reveal=1 (tnt.api.routes._cross_origin_browser_request): refused when
    ``Origin`` is not this server or ``Sec-Fetch-Site`` is neither absent, ``same-origin`` nor ``none``."""
    origin = (headers.get("Origin") or "").strip().lower()
    site = (headers.get("Sec-Fetch-Site") or "").strip().lower()
    if origin and origin not in {f"http://{host}:{port}" for host in ("127.0.0.1", "localhost", "[::1]")}:
        return True
    return site not in ("", "same-origin", "none")


def ip2int(ip: str) -> int:
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"{ip!r} is not an IPv4 address")
    out = 0
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            raise ValueError(f"{ip!r} is not an IPv4 address")
        out = (out << 8) | int(p)
    return out


def int2ip(n: int) -> str:
    return ".".join(str((n >> s) & 255) for s in (24, 16, 8, 0))


class DhcpConflict(RuntimeError):
    """Another DHCP server answered the probe: carries the 409 payload for the UI."""

    def __init__(self, servers: List[Dict[str, Any]], scan: Dict[str, Any]) -> None:
        super().__init__("Another DHCP server is active on this network")
        self.servers = servers
        self.scan = scan

    def payload(self) -> Dict[str, Any]:
        return {"error": {"code": "dhcp_server_present", "message": str(self)}, "servers": self.servers, "scan": self.scan}

MIME = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8", ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
    ".ttf": "font/ttf", ".woff2": "font/woff2", ".woff": "font/woff", ".md": "text/markdown; charset=utf-8",
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def changed_keys(old: Dict[str, Any], new: Dict[str, Any], prefix: str = "") -> List[str]:
    keys: List[str] = []
    for k in set(old) | set(new):
        a, b = old.get(k), new.get(k)
        if isinstance(a, dict) and isinstance(b, dict):
            keys += changed_keys(a, b, f"{prefix}{k}.")
        elif a != b:
            keys.append(f"{prefix}{k}")
    return sorted(keys)


def local_hour(ts: float) -> int:
    return time.localtime(ts).tm_hour


def local_weekday(ts: float) -> int:
    return time.localtime(ts).tm_wday


def tiny_pdf(title: str, lines: List[str]) -> bytes:
    """Build a minimal but valid single-page PDF by hand."""
    content_lines = ["BT", "/F1 22 Tf", "72 720 Td", f"({title}) Tj"]
    y = 690
    for ln in lines:
        content_lines += ["/F1 12 Tf", f"1 0 0 1 72 {y} Tm", f"({ln}) Tj"]
        y -= 18
    content_lines.append("ET")
    content = "\n".join(content_lines).encode("latin-1", "replace")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------
class SseHub:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clients: List["queue.Queue[str]"] = []

    def subscribe(self) -> "queue.Queue[str]":
        q: "queue.Queue[str]" = queue.Queue(maxsize=2000)
        with self._lock:
            self._clients.append(q)
        return q

    def unsubscribe(self, q: "queue.Queue[str]") -> None:
        with self._lock:
            if q in self._clients:
                self._clients.remove(q)

    def count(self) -> int:
        with self._lock:
            return len(self._clients)

    def publish(self, event_type: str, data: Dict[str, Any]) -> None:
        frame = f"event: {event_type}\ndata: {json.dumps(data, default=str)}\n\n"
        with self._lock:
            clients = list(self._clients)
        for q in clients:
            try:
                q.put_nowait(frame)
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait(frame)
                except (queue.Empty, queue.Full):
                    pass


class MockState:
    """All fake data lives here; every public method takes the lock."""

    def __init__(self, port: int) -> None:
        self.lock = threading.RLock()
        self.port = port
        self.started_ts = time.time() - 3 * 3600 - 421
        self.hub = SseHub()
        self.settings = copy.deepcopy(DEFAULTS)
        self.settings["api"]["port"] = port
        self.paused = False
        self.next_id = 1
        self.targets: List[Dict[str, Any]] = []
        self.samples: Dict[int, List[tuple]] = {}
        self.outages: List[Dict[str, Any]] = []
        self.speedtests: List[Dict[str, Any]] = []
        self.speed_running = False
        self.speed_progress = {"phase": "idle", "pct": 0.0}
        self.speed_next_ts = time.time() + 7 * 60
        self.disc_runs: List[Dict[str, Any]] = []
        self.disc_running = False
        self.disc_cancel = threading.Event()
        self.disc_progress = {"phase": "done", "done": 0, "total": 0, "found": 0, "elapsed_s": 0.0}
        self.disc_started_ts = 0.0
        self.disc_range: Optional[str] = None       # the running (or last started) scan, as the service reports it
        self.disc_ports: List[int] = []
        # fake DHCP server (Tools view)
        self.dhcp_running = False
        self.dhcp_since: Optional[float] = None
        self.dhcp_error: Optional[str] = None
        self.dhcp_warning: Optional[str] = None
        self.dhcp_changed = False           # we re-addressed the adapter to the static IP
        self.dhcp_clients: List[Dict[str, Any]] = []
        self.dhcp_last_scan: Optional[Dict[str, Any]] = None
        self.dhcp_force_none = False        # True: the probe finds no other server
        self.dhcp_fast = False              # tests: clients appear within a second
        self.dhcp_gen = 0                   # bumps on every start/stop so a stale worker exits
        # Tools: traceroute + LAN throughput (both synchronous, one at a time)
        self.trace_running = False
        self.trace_last: Optional[Dict[str, Any]] = None
        self.trace_fast = False             # tests: hops arrive within a few ms
        self.lan_running = False
        self.lan_last: Optional[Dict[str, Any]] = None
        self.lan_fast = False
        self.lan_peer_ts = time.time()      # the last "announcement" round (lan.peers every 10 s)
        self.lan_enabled = True             # the Tools switch (PUT /api/tools/lan/settings)
        self.wifi_admin = True              # tests: set False to simulate a non-admin caller (403 on reveal=1)
        self.public_ip_ts = time.time() - 4 * 60
        self.log_ring: List[Dict[str, Any]] = []
        self.events_db: List[Dict[str, Any]] = []
        self.rng = random.Random(7)
        self._seed()

    # -- seeding ---------------------------------------------------------
    def _seed(self) -> None:
        now = time.time()
        self._add_target("10.0.0.251", "Gateway", kind="local", ip="10.0.0.251", base=0.6)
        self._add_target("1.1.1.1", None, kind="internet", ip="1.1.1.1", base=12.0)
        self._add_target("totalelectronics.com", None, kind="internet", ip="203.0.113.80", base=38.0)
        # backfill 5 minutes of samples so sparklines are full on first paint
        for t in self.targets:
            for i in range(300, 0, -1):
                self.samples[t["id"]].append(self._make_sample(t, now - i))
        # outages in the last 24 h
        oid = 1

        def add(kind: str, tid: Optional[int], start: float, end: Optional[float], missed: int, note: Optional[str] = None,
                sent: Optional[int] = None) -> None:
            nonlocal oid
            self.outages.append({"id": oid, "kind": kind, "target_id": tid, "start_ts": start, "end_ts": end,
                                 "missed": missed, "sent": sent, "note": note})
            oid += 1

        add("gap", None, now - 20 * 3600, now - 20 * 3600 + 22 * 60, 0, "not monitoring")
        add("target", 1, now - 14 * 3600, now - 14 * 3600 + 95, 95)                            # an older row: estimated
        add("target", 2, now - 6 * 3600 - 260, now - 6 * 3600, 258, sent=260)
        add("target", 2, now - 2 * 3600 - 31 * 60, now - 2 * 3600 - 26 * 60 - 40, 241, sent=260)  # a flaky link: 92.6%
        add("target", 3, now - 2 * 3600 - 30 * 60, now - 2 * 3600 - 27 * 60, 180, sent=180)
        add("total_internet", None, now - 2 * 3600 - 30 * 60, now - 2 * 3600 - 27 * 60, 0)
        add("target", 3, now - 47 * 60, now - 46 * 60 - 20, 40, sent=40)
        # speed history: 7 days every 15 min
        t0 = now - 7 * 86400
        t = t0 - (t0 % 900)
        i = 0
        while t <= now - 900:
            i += 1
            self.speedtests.append(self._make_speed(t, fail=(i % 223 == 0)))
            t += 900
        self.speed_next_ts = now + self.rng.randint(120, 600)
        # two previous discovery runs
        self._add_disc_run(now - 26 * 3600, "10.0.0.0/24", list(DEFAULT_PORTS), 4.2, drop=1)
        self._add_disc_run(now - 3 * 3600 - 700, "10.0.0.0/24", list(DEFAULT_PORTS), 3.9, drop=0)
        # log ring + events
        base = now - 3 * 3600
        msgs = [
            ("INFO", "tnt.engine", "started v%s" % VERSION),
            ("INFO", "tnt.api.server", "listening on 127.0.0.1:%d" % self.port),
            ("INFO", "tnt.pinger", "target 1 10.0.0.251 resolved -> 10.0.0.251 (local)"),
            ("INFO", "tnt.pinger", "target 2 1.1.1.1 resolved -> 1.1.1.1 (internet)"),
            ("INFO", "tnt.pinger", "target 3 totalelectronics.com resolved -> 203.0.113.80 (internet)"),
            ("INFO", "tnt.speedtest.scheduler", "next speed test in 60 s"),
            ("WARNING", "tnt.outages", "target 3 totalelectronics.com: outage started (3 misses)"),
            ("INFO", "tnt.outages", "target 3 totalelectronics.com: recovered after 40 s"),
            ("INFO", "tnt.speedtest.cloudflare", "download 117.4 Mbps upload 30.9 Mbps latency 11.8 ms"),
            ("DEBUG", "tnt.api.server", "GET /api/status 200"),
        ]
        for k, (lvl, name, msg) in enumerate(msgs):
            self.log_ring.append({"ts": base + k * 600, "level": lvl, "logger": name, "message": f"{name}: {msg}"})
        self.events_db = [
            {"id": 1, "ts": base, "level": "info", "category": "service", "message": "started v" + VERSION},
            {"id": 2, "ts": now - 47 * 60, "level": "warning", "category": "outage", "message": "totalelectronics.com down"},
            {"id": 3, "ts": now - 46 * 60, "level": "info", "category": "outage", "message": "totalelectronics.com recovered"},
        ]

    def _add_target(self, host: str, label: Optional[str], kind: str, ip: Optional[str], base: float) -> Dict[str, Any]:
        tid = self.next_id
        self.next_id += 1
        t = {"id": tid, "host": host, "label": label, "kind": kind, "ip": ip, "enabled": True,
             "resolved": ip is not None, "resolve_error": None if ip else "getaddrinfo failed",
             "in_outage": False, "since_ts": time.time(), "base": base, "consecutive_missed": 0,
             "consecutive_ok": 0}
        self.targets.append(t)
        self.samples[tid] = []
        return t

    def _make_sample(self, t: Dict[str, Any], ts: float) -> tuple:
        rng = self.rng
        base = t["base"]
        if not t.get("resolved"):
            return (ts, False, None)
        # sluggish phase: totalelectronics.com every 4 min for 45 s
        slug = t["host"] == "totalelectronics.com" and (int(ts) % 240) < 45
        miss_p = {"10.0.0.251": 0.0, "1.1.1.1": 0.012}.get(t["host"], 0.006)
        if slug:
            miss_p = 0.05
        if rng.random() < miss_p:
            return (ts, False, None)
        rtt = base * (1 + rng.gauss(0, 0.09))
        if slug:
            rtt = 170 + rng.gauss(0, 25)
        if rng.random() < 0.02:
            rtt *= 1 + rng.random() * 2.5
        rtt = max(0.2, rtt)
        return (ts, True, round(rtt, 2))

    def _make_speed(self, ts: float, fail: bool = False) -> Dict[str, Any]:
        rng = self.rng
        hour = local_hour(ts)
        evening = 19 <= hour < 22
        f = 0.6 if evening else 1.0
        if fail:
            return {"id": len(self.speedtests) + 1, "ts": ts, "ok": False, "backend": "cloudflare", "server": None,
                    "isp": None, "external_ip": None, "latency_ms": None, "jitter_ms": None,
                    "download_mbps": None, "upload_mbps": None, "packet_loss_pct": None, "duration_s": 12.1,
                    "error": "HTTP 503 from speed.cloudflare.com"}
        down = 118 * f * (1 + rng.gauss(0, 0.05))
        up = 31 * (0.9 if evening else 1.0) * (1 + rng.gauss(0, 0.05))
        lat = 12 + (7 if evening else 0) + rng.gauss(0, 1.4)
        return {"id": len(self.speedtests) + 1, "ts": ts, "ok": True, "backend": "cloudflare",
                "server": "Cloudflare AMS", "isp": "Example ISP", "external_ip": "203.0.113.5",
                "latency_ms": round(max(3, lat), 1), "jitter_ms": round(1 + abs(rng.gauss(0, 0.8)), 2),
                "download_mbps": round(max(1, down), 1), "upload_mbps": round(max(1, up), 1),
                "packet_loss_pct": 0.0, "duration_s": round(16 + rng.random() * 3, 1), "error": None}

    # (ip, hostname, mac, vendor, rtt_ms, open_ports, device_type) - the device_type values are what
    # tnt.discovery.classify_device would return for these rows (10.0.0.251 is the mock gateway)
    _HOSTS = [
        ("10.0.0.251", "gateway.lan", "24:5A:4C:12:34:01", "Ubiquiti Inc", 0.6, [80, 443], "Router"),
        ("10.0.0.10", "nas.lan", "00:11:32:12:34:02", "Synology Incorporated", 0.9, [80, 443, 8080], None),
        ("10.0.0.21", "printer-hp.lan", "3C:D9:2B:12:34:03", "Hewlett Packard", 2.1, [80, 443], None),
        ("10.0.0.35", None, "C0:56:E3:12:34:04", "Hangzhou Hikvision Digital Technology Co., Ltd.", 1.4, [80, 554], "Camera"),
        ("10.0.0.36", None, "C0:56:E3:12:34:05", "Hangzhou Hikvision Digital Technology Co., Ltd.", 1.5, [80, 554], "Camera"),
        ("10.0.0.62", "yealink-front.lan", "80:5E:C0:12:34:06", "Yealink(Xiamen) Network Technology", 2.6, [80, 5060], "Phone"),
        ("10.0.0.70", "iphone.lan", "DA:12:34:12:34:07", "Locally administered (randomized)", 11.2, [], None),
        ("10.0.0.112", "TEC-DESKTOP.lan", "D8:BB:C1:12:34:08", "Micro-Star INTL CO., LTD.", 0.3, [7001, 8000], "DW Server"),
        ("10.0.0.120", "samsung-tv.lan", "8C:79:F5:12:34:09", "Samsung Electronics Co.,Ltd", 4.8, [8000, 8080], None),
        ("10.0.0.130", "pi4.lan", "DC:A6:32:12:34:0A", "Raspberry Pi Trading Ltd", 0.7, [80, 8443], None),
        ("10.0.0.201", "sonos-kitchen.lan", "94:9F:3E:12:34:0B", "Sonos, Inc.", 3.2, [], None),
        ("10.0.0.240", "ap-warehouse.lan", "24:5A:4C:12:34:0C", "Ubiquiti Networks Inc.", 1.1, [22, 80, 443], "Wifi"),
        ("10.0.0.230", None, None, None, None, [443], None),
    ]

    def _build_hosts(self, drop: int = 0, jitter: bool = True) -> List[Dict[str, Any]]:
        hosts = []
        for k, (ip, hn, mac, vendor, rtt, ports, device_type) in enumerate(self._HOSTS):
            if drop and k == 6:
                continue
            r = None if rtt is None else round(rtt * (1 + (self.rng.gauss(0, 0.15) if jitter else 0)), 2)
            hosts.append({"ip": ip, "hostname": hn, "mac": mac, "vendor": vendor, "ping_ok": rtt is not None,
                          "rtt_ms": r, "open_ports": list(ports), "device_type": device_type})
        return hosts

    def _add_disc_run(self, ts: float, cidr: str, ports: List[int], duration: float, drop: int = 0,
                      hosts: Optional[List[Dict[str, Any]]] = None, cancelled: bool = False) -> Dict[str, Any]:
        rid = len(self.disc_runs) + 1
        hosts = hosts if hosts is not None else self._build_hosts(drop=drop)
        run = {"id": rid, "ts": ts, "cidr": cidr, "ports": list(ports), "method": "native", "duration_s": duration,
               "scanned": 254, "found": len(hosts), "ok": True, "error": "cancelled" if cancelled else None,
               "hosts": [dict(h, run_id=rid) for h in hosts]}
        self.disc_runs.append(run)
        return run

    # -- ping / targets --------------------------------------------------
    def tick(self, ts: float) -> None:
        with self.lock:
            if self.paused:
                return
            out = []
            for t in self.targets:
                s = self._make_sample(t, ts)
                buf = self.samples[t["id"]]
                buf.append(s)
                if len(buf) > 3600:
                    del buf[: len(buf) - 3600]
                if s[1]:
                    t["consecutive_ok"] += 1
                    t["consecutive_missed"] = 0
                else:
                    t["consecutive_missed"] += 1
                    t["consecutive_ok"] = 0
                out.append({"target_id": t["id"], "ts": ts, "ok": s[1], "rtt_ms": s[2], "light": self._light(t)})
        for ev in out:
            self.hub.publish("ping.sample", ev)

    def _stats(self, tid: int, seconds: float) -> Dict[str, Any]:
        now = time.time()
        rows = [s for s in self.samples.get(tid, []) if s[0] >= now - seconds]
        sent = len(rows)
        oks = [s[2] for s in rows if s[1] and s[2] is not None]
        received = len(oks)
        lost = sent - received
        jit = None
        if len(oks) > 1:
            jit = sum(abs(oks[i] - oks[i - 1]) for i in range(1, len(oks))) / (len(oks) - 1)
        return {"seconds": int(seconds), "sent": sent, "received": received, "lost": lost,
                "loss_pct": round(100.0 * lost / sent, 2) if sent else 0.0,
                "avg_ms": round(sum(oks) / received, 2) if received else None,
                "min_ms": round(min(oks), 2) if received else None,
                "max_ms": round(max(oks), 2) if received else None,
                "jitter_ms": round(jit, 2) if jit is not None else None}

    def _light(self, t: Dict[str, Any]) -> str:
        if self.paused or not self.samples.get(t["id"]):
            return "grey"
        th = self.settings["thresholds"]
        w = self._stats(t["id"], th["window_s"])
        if t["in_outage"] or w["loss_pct"] >= th["bad_loss_pct"]:
            return "red"
        warn = th["local_warn_ms"] if t["kind"] == "local" else th["internet_warn_ms"]
        if w["loss_pct"] >= th["warn_loss_pct"] or (w["avg_ms"] is not None and w["avg_ms"] > warn):
            return "yellow"
        return "green"

    def target_view(self, t: Dict[str, Any]) -> Dict[str, Any]:
        buf = self.samples.get(t["id"], [])
        last = buf[-1] if buf else None
        w = self._stats(t["id"], self.settings["thresholds"]["window_s"])
        # a plausible 24 h summary derived from the base RTT
        sent = int(min(86400, time.time() - self.started_ts))
        lost = int(sent * (0.0002 if t["kind"] == "local" else 0.004)) + (258 if t["id"] == 2 else 0)
        day = {"sent": sent, "received": sent - lost, "lost": lost,
               "loss_pct": round(100.0 * lost / sent, 2) if sent else 0.0,
               "avg_ms": round(t["base"] * 1.03, 2), "min_ms": round(t["base"] * 0.7, 2),
               "max_ms": round(t["base"] * 9.1 + 40, 2)}
        return {"id": t["id"], "host": t["host"], "label": t["label"], "kind": t["kind"], "ip": t["ip"],
                "enabled": t["enabled"], "resolved": t["resolved"], "resolve_error": t["resolve_error"],
                "light": self._light(t), "in_outage": t["in_outage"],
                "last": {"ts": last[0], "ok": last[1], "rtt_ms": last[2]} if last else None,
                "consecutive_missed": t["consecutive_missed"], "consecutive_ok": t["consecutive_ok"],
                "window": w, "day": day, "since_ts": t["since_ts"]}

    def targets_view(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [self.target_view(t) for t in self.targets]

    def add_target(self, host: str, label: Optional[str]) -> Dict[str, Any]:
        host = (host or "").strip()
        if not host or " " in host:
            raise ValueError("host is required and must not contain spaces")
        with self.lock:
            for t in self.targets:
                if t["host"].lower() == host.lower():
                    return self.target_view(t)
            is_ip = all(p.isdigit() for p in host.split(".")) and host.count(".") == 3
            kind = "local" if host.startswith(("10.", "192.168.", "172.")) else "internet"
            if host.lower() in ("nonexistent.invalid", "bad.example"):
                t = self._add_target(host, label, "internet", None, 40.0)
            else:
                ip = host if is_ip else "%d.%d.%d.%d" % tuple(self.rng.randint(1, 250) for _ in range(4))
                t = self._add_target(host, label, kind, ip, 1.0 if kind == "local" else 25.0 + self.rng.random() * 40)
            view = self.target_view(t)
            all_views = [self.target_view(x) for x in self.targets]
        self.hub.publish("ping.targets", {"targets": all_views})
        return view

    def remove_target(self, tid: int) -> bool:
        with self.lock:
            before = len(self.targets)
            self.targets = [t for t in self.targets if t["id"] != tid]
            self.samples.pop(tid, None)
            removed = len(self.targets) != before
            all_views = [self.target_view(x) for x in self.targets]
        if removed:
            self.hub.publish("ping.targets", {"targets": all_views})
        return removed

    def load_defaults(self) -> List[Dict[str, Any]]:
        # hard-coded like the real service: gateway, 1.1.1.1, totalelectronics.com; every
        # other tile is removed and the three come first in that order
        wanted = [("gateway", "Gateway", "local", "10.0.0.251", 0.6), ("1.1.1.1", None, "internet", "1.1.1.1", 12.0),
                  ("totalelectronics.com", None, "internet", "203.0.113.80", 30.0)]
        keep = {w[0] for w in wanted} | {"10.0.0.251"}
        with self.lock:
            for t in list(self.targets):
                if t["host"].lower() not in keep:
                    self.targets.remove(t)
                    self.samples.pop(t["id"], None)
            hosts = {t["host"].lower() for t in self.targets}
            for host, label, kind, ip, base in wanted:
                if host.lower() in hosts or (host == "gateway" and "10.0.0.251" in hosts):
                    continue
                self._add_target(host, label, kind, ip, base)
            order = [w[0] for w in wanted]
            key = lambda t: order.index(t["host"].lower()) if t["host"].lower() in order else (0 if t["host"] == "10.0.0.251" else 99)  # noqa: E731
            self.targets.sort(key=key)
            views = [self.target_view(x) for x in self.targets]
        self.hub.publish("ping.targets", {"targets": views})
        return views

    def samples_view(self, tid: int, seconds: int) -> Optional[Dict[str, Any]]:
        with self.lock:
            if tid not in self.samples:
                return None
            now = time.time()
            rows = [[s[0], s[2] if s[1] else None] for s in self.samples[tid] if s[0] >= now - seconds]
            return {"target_id": tid, "samples": rows}

    def history_view(self, tid: int, start: float, end: float) -> Optional[Dict[str, Any]]:
        with self.lock:
            t = next((x for x in self.targets if x["id"] == tid), None)
            if not t:
                return None
            minutes = []
            m = int(start // 60 * 60)
            while m < end:
                rec = 60 - (1 if self.rng.random() < 0.05 else 0)
                minutes.append({"target_id": tid, "minute_ts": m, "sent": 60, "received": rec,
                                "avg_ms": round(t["base"] * (1 + self.rng.gauss(0, 0.05)), 2),
                                "min_ms": round(t["base"] * 0.8, 2), "max_ms": round(t["base"] * 2.2, 2),
                                "jitter_ms": round(t["base"] * 0.05, 2)})
                m += 60
            sent = sum(x["sent"] for x in minutes)
            rec = sum(x["received"] for x in minutes)
            return {"target_id": tid, "minutes": minutes,
                    "summary": {"sent": sent, "received": rec, "lost": sent - rec,
                                "loss_pct": round(100.0 * (sent - rec) / sent, 2) if sent else None,
                                "avg_ms": round(t["base"], 2), "min_ms": round(t["base"] * 0.8, 2),
                                "max_ms": round(t["base"] * 2.2, 2)}}

    # -- outages ---------------------------------------------------------
    @staticmethod
    def _missed_stats(o: Dict[str, Any], duration_s: float) -> Dict[str, Any]:
        """Same rules as tnt.outages.missed_percentage (kept standalone: the mock imports no tnt code)."""
        if o["kind"] != "target":
            return {"sent": None, "missed_pct": None, "sent_estimated": False}
        missed = int(o.get("missed") or 0)
        sent = o.get("sent")
        estimated = not sent
        if estimated:
            sent = max(missed, int(round(max(0.0, duration_s))))
        sent = max(int(sent), missed)
        pct = round(100.0 * missed / sent, 2) if sent else None
        return {"sent": sent or None, "missed_pct": pct, "sent_estimated": estimated}

    def _outage_view(self, o: Dict[str, Any]) -> Dict[str, Any]:
        now = time.time()
        host = None
        if o["target_id"] is not None:
            t = next((x for x in self.targets if x["id"] == o["target_id"]), None)
            host = t["host"] if t else f"target {o['target_id']}"
        end = o["end_ts"] if o["end_ts"] is not None else now
        duration = round(end - o["start_ts"], 1)
        return dict(o, host=host, duration_s=duration, open=o["end_ts"] is None, **self._missed_stats(o, duration))

    def outages_status(self) -> Dict[str, Any]:
        with self.lock:
            now = time.time()
            active = [self._outage_view(o) for o in self.outages if o["end_ts"] is None]
            total_active = next((o for o in active if o["kind"].startswith("total")), None)
            recent = [o for o in self.outages if o["kind"] != "gap" and (o["end_ts"] or now) >= now - 86400]
            last = max(recent, key=lambda o: o["start_ts"]) if recent else None
            return {"active": active, "total_active": total_active, "count_24h": len(recent),
                    "last": self._outage_view(last) if last else None, "monitoring": not self.paused}

    def outages_list(self, start: float, end: float) -> List[Dict[str, Any]]:
        with self.lock:
            rows = [self._outage_view(o) for o in self.outages
                    if o["start_ts"] <= end and (o["end_ts"] is None or o["end_ts"] >= start)]
            rows.sort(key=lambda o: o["start_ts"], reverse=True)
            return rows

    def timeline(self, hours: float) -> Dict[str, Any]:
        with self.lock:
            now = time.time()
            start = now - hours * 3600
            segs, totals, gaps = [], [], []
            for o in self.outages:
                end = o["end_ts"] if o["end_ts"] is not None else now
                if end < start or o["start_ts"] > now:
                    continue
                s = {"id": o["id"], "kind": o["kind"], "target_id": o["target_id"],
                     "host": self._outage_view(o)["host"], "start_ts": max(start, o["start_ts"]),
                     "end_ts": min(now, end), "open": o["end_ts"] is None, "missed": o["missed"],
                     **self._missed_stats(o, end - o["start_ts"])}
                if o["kind"] == "gap":
                    gaps.append({"start_ts": s["start_ts"], "end_ts": s["end_ts"]})
                elif o["kind"].startswith("total"):
                    totals.append(s)
                else:
                    segs.append(s)
            return {"start_ts": start, "end_ts": now, "hours": hours, "segments": segs, "total_segments": totals,
                    "gaps": gaps, "targets": [{"id": t["id"], "host": t["host"], "kind": t["kind"]} for t in self.targets]}

    # -- speed -----------------------------------------------------------
    def speed_status(self) -> Dict[str, Any]:
        with self.lock:
            last = self.speedtests[-1] if self.speedtests else None
            backend = self.settings["speedtest"]["backend"]
            return {"enabled": self.settings["speedtest"]["enabled"], "running": self.speed_running,
                    "next_run_ts": self.speed_next_ts, "last": dict(last, raw={}) if last else None,
                    "backend": "cloudflare" if backend == "auto" else backend,
                    "interval_min": self.settings["speedtest"]["interval_min"], "progress": dict(self.speed_progress)}

    def speed_history(self, start: float, end: float, limit: Optional[int]) -> List[Dict[str, Any]]:
        with self.lock:
            rows = [r for r in self.speedtests if start <= r["ts"] < end]
            rows.sort(key=lambda r: r["ts"], reverse=True)
            return rows[:limit] if limit else rows

    def speed_run(self) -> bool:
        with self.lock:
            if self.speed_running:
                return False
            self.speed_running = True
            self.speed_progress = {"phase": "latency", "pct": 0.0}
        threading.Thread(target=self._speed_worker, name="mock-speed", daemon=True).start()
        return True

    def speed_tick(self) -> None:
        """Run the scheduled test when it falls due (like the real SpeedScheduler)."""
        with self.lock:
            due = (self.settings["speedtest"]["enabled"] and not self.speed_running
                   and time.time() >= self.speed_next_ts)
            if not due:
                if not self.settings["speedtest"]["enabled"] and self.speed_next_ts < time.time():
                    # keep the countdown sane while automatic tests are switched off
                    self.speed_next_ts = time.time() + self.settings["speedtest"]["interval_min"] * 60
                return
        self.speed_run()

    def _speed_worker(self) -> None:
        self.hub.publish("speedtest.start", {"backend": "cloudflare"})
        phases = [("latency", 1.2), ("download", 3.0), ("upload", 2.6)]
        try:
            for phase, dur in phases:
                t0 = time.time()
                while time.time() - t0 < dur:
                    pct = min(1.0, (time.time() - t0) / dur)
                    with self.lock:
                        self.speed_progress = {"phase": phase, "pct": round(pct, 3)}
                    self.hub.publish("speedtest.progress", {"phase": phase, "pct": round(pct, 3)})
                    time.sleep(0.15)
            with self.lock:
                res = self._make_speed(time.time())
                self.speedtests.append(res)
                self.speed_running = False
                self.speed_progress = {"phase": "done", "pct": 1.0}
                self.speed_next_ts = time.time() + self.settings["speedtest"]["interval_min"] * 60
            self.hub.publish("speedtest.done", {"result": dict(res, raw={})})
        except Exception:  # noqa: BLE001
            log.exception("speed worker failed")
            with self.lock:
                self.speed_running = False

    def patterns(self, days: int) -> Dict[str, Any]:
        with self.lock:
            now = time.time()
            rows = [r for r in self.speedtests if r["ts"] >= now - days * 86400]
            ok = [r for r in rows if r["ok"]]
            downs = sorted(r["download_mbps"] for r in ok)
            ups = sorted(r["upload_mbps"] for r in ok)

            def median(xs: List[float]) -> Optional[float]:
                if not xs:
                    return None
                n = len(xs)
                return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2

            md, mu = median(downs), median(ups)
            by_hour = []
            for h in range(24):
                hs = [r for r in ok if local_hour(r["ts"]) == h]
                by_hour.append({"hour": h, "count": len(hs),
                                "avg_down": round(sum(r["download_mbps"] for r in hs) / len(hs), 1) if hs else None,
                                "avg_up": round(sum(r["upload_mbps"] for r in hs) / len(hs), 1) if hs else None,
                                "avg_latency": round(sum(r["latency_ms"] for r in hs) / len(hs), 1) if hs else None})
            by_wd = []
            for wd in range(7):
                ws = [r for r in ok if local_weekday(r["ts"]) == wd]
                by_wd.append({"weekday": wd, "count": len(ws),
                              "avg_down": round(sum(r["download_mbps"] for r in ws) / len(ws), 1) if ws else None})
            warn = self.settings["speedtest"]["warn_below_pct"]
            slow = [{"ts": r["ts"], "download_mbps": r["download_mbps"],
                     "pct_of_median": round(100.0 * r["download_mbps"] / md, 1)}
                    for r in ok if md and r["download_mbps"] < md * warn / 100.0]
            findings = []
            if md:
                ev = [b for b in by_hour if 19 <= b["hour"] < 22 and b["avg_down"]]
                if ev:
                    avg_ev = sum(b["avg_down"] for b in ev) / len(ev)
                    findings.append("Downloads are ~%d%% slower between 19:00 and 22:00" % round(100 * (1 - avg_ev / md)))
            fails = len(rows) - len(ok)
            if fails:
                findings.append("%d test%s failed in the last %d days" % (fails, "" if fails == 1 else "s", days))
            if md and mu and md / mu > 3:
                findings.append("Upload is much slower than download (%.0f vs %.0f Mbps) - typical for cable" % (mu, md))
            if ok:
                lat = sorted(r["latency_ms"] for r in ok)
                if lat[-1] > 3 * median(lat):
                    findings.append("Latency spiked to %.0f ms at least once (median %.0f ms)" % (lat[-1], median(lat)))
            mn = min(ok, key=lambda r: r["download_mbps"]) if ok else None
            mx = max(ok, key=lambda r: r["download_mbps"]) if ok else None
            return {"days": days, "count": len(rows), "ok_count": len(ok), "median_down": md, "median_up": mu,
                    "avg_down": round(sum(downs) / len(downs), 1) if downs else None,
                    "avg_up": round(sum(ups) / len(ups), 1) if ups else None,
                    "min_down": {"value": mn["download_mbps"], "ts": mn["ts"]} if mn else None,
                    "max_down": {"value": mx["download_mbps"], "ts": mx["ts"]} if mx else None,
                    "by_hour": by_hour, "by_weekday": by_wd, "slow_tests": slow[-20:], "findings": findings,
                    "trend_down_pct_per_day": -0.4}

    # -- discovery -------------------------------------------------------
    def _disc_last_summary(self) -> Optional[Dict[str, Any]]:
        """The newest run as the service summarises it (engine._run_summary)."""
        if not self.disc_runs:
            return None
        run = max(self.disc_runs, key=lambda r: r["ts"])
        return {k: run[k] for k in ("id", "ts", "cidr", "found", "duration_s", "ok", "error")}

    def disc_status(self) -> Dict[str, Any]:
        """Same keys as the service's engine.discovery_status()."""
        with self.lock:
            return {"available": True, "running": self.disc_running, "progress": dict(self.disc_progress),
                    "range": self.disc_range, "ports": list(self.disc_ports),
                    "started_ts": self.disc_started_ts if self.disc_running else None,
                    "last_run": self._disc_last_summary(), "default_range": "10.0.0.0/24",
                    "default_ports": list(self.settings["discovery"]["ports"])}

    def disc_start(self, rng_text: Optional[str], ports: Optional[List[int]]) -> Dict[str, Any]:
        rng_text = (rng_text or "").strip() or "10.0.0.0/24"
        if "/" not in rng_text and "-" not in rng_text and rng_text.count(".") != 3:
            raise ValueError("range must be a CIDR (10.0.0.0/24), a range (10.0.0.1-10.0.0.50) or a single IP")
        ports = [int(p) for p in (ports or self.settings["discovery"]["ports"])]
        with self.lock:
            if self.disc_running:
                raise RuntimeError("scan already running")
            self.disc_running = True
            self.disc_cancel.clear()
            self.disc_started_ts = time.time()
            self.disc_range, self.disc_ports = rng_text, list(ports)
            self.disc_progress = {"phase": "ping", "done": 0, "total": 254, "found": 0, "elapsed_s": 0.0}
        threading.Thread(target=self._disc_worker, args=(rng_text, ports), name="mock-disc", daemon=True).start()
        return {"started": True, "range": rng_text, "ports": ports}

    def disc_cancel_scan(self) -> bool:
        self.disc_cancel.set()
        return True

    def _disc_worker(self, cidr: str, ports: List[int]) -> None:
        t0 = time.time()
        total = 254
        hosts = self._build_hosts(drop=self.rng.choice([0, 1]))
        phases = [("ping", 2.0, total), ("ports", 1.4, total * len(ports)), ("arp", 0.2, 1), ("resolve", 0.4, len(hosts))]
        cancelled = False
        try:
            for phase, dur, ptotal in phases:
                p0 = time.time()
                while time.time() - p0 < dur:
                    if self.disc_cancel.is_set():
                        cancelled = True
                        break
                    frac = min(1.0, (time.time() - p0) / dur)
                    found = int(len(hosts) * min(1.0, frac if phase == "ping" else 1.0))
                    prog = {"phase": phase, "done": int(ptotal * frac), "total": ptotal, "found": found,
                            "elapsed_s": round(time.time() - t0, 1)}
                    with self.lock:
                        self.disc_progress = prog
                    self.hub.publish("discovery.progress", prog)
                    time.sleep(0.1)
                if cancelled:
                    break
            with self.lock:
                run = self._add_disc_run(time.time(), cidr, ports, round(time.time() - t0, 1),
                                         hosts=hosts[: (len(hosts) // 2 if cancelled else len(hosts))], cancelled=cancelled)
                self.disc_running = False
                self.disc_progress = {"phase": "done", "done": total, "total": total, "found": run["found"],
                                      "elapsed_s": round(time.time() - t0, 1)}
            self.hub.publish("discovery.progress", self.disc_progress)
            self.hub.publish("discovery.done", {"run_id": run["id"], "cancelled": cancelled, "found": run["found"]})
        except Exception:  # noqa: BLE001
            log.exception("discovery worker failed")
            with self.lock:
                self.disc_running = False

    def disc_runs_view(self, limit: int) -> List[Dict[str, Any]]:
        with self.lock:
            runs = sorted(self.disc_runs, key=lambda r: r["ts"], reverse=True)[:limit]
            return [{k: v for k, v in r.items() if k != "hosts"} for r in runs]

    def disc_run(self, rid: int) -> Optional[Dict[str, Any]]:
        with self.lock:
            r = next((x for x in self.disc_runs if x["id"] == rid), None)
            return copy.deepcopy(r) if r else None

    def disc_last(self) -> Optional[Dict[str, Any]]:
        with self.lock:
            if not self.disc_runs:
                return None
            return copy.deepcopy(max(self.disc_runs, key=lambda r: r["ts"]))

    # -- DHCP server (Tools) ---------------------------------------------
    def _dhcp_adapter(self) -> Optional[Dict[str, Any]]:
        """settings.adapter by name, else auto = the first physical Ethernet."""
        name = self.settings["dhcp"].get("adapter") or ""
        if name:
            for a in DHCP_ADAPTERS:
                if a["name"].lower() == name.lower():
                    return a
        return next((a for a in DHCP_ADAPTERS if a["is_physical"] and a["type_name"] == "Ethernet"), DHCP_ADAPTERS[0])

    def _dhcp_server_ip(self, adapter: Dict[str, Any]) -> tuple:
        """(server_ip, prefix): the static address when the NIC is on DHCP, else its own."""
        cfg = self.settings["dhcp"]
        if adapter["dhcp_enabled"]:
            return cfg["static_ip"], int(cfg["static_prefix"])
        return adapter["ip"], int(adapter["prefix"])

    @staticmethod
    def _dhcp_default_pool(server_ip: str, prefix: int, size: int, exclude: List[str]) -> tuple:
        net = ip2int(server_ip) & (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        bcast = net | ((1 << (32 - prefix)) - 1)
        skip = {ip2int(server_ip), net, bcast} | {ip2int(x) for x in exclude if x}
        after = [n for n in range(ip2int(server_ip) + 1, bcast) if n not in skip][:size]
        if len(after) < size:
            before = [n for n in range(ip2int(server_ip) - 1, net, -1) if n not in skip][: size - len(after)]
            after = sorted(before) + after
        if len(after) < size:
            raise ValueError(f"the subnet /{prefix} cannot hold {size} addresses")
        return int2ip(after[0]), int2ip(after[-1])

    @staticmethod
    def _dhcp_validate_pool(start: str, end: str, server_ip: str, prefix: int, gateway: Optional[str]) -> tuple:
        s, e = ip2int(start), ip2int(end)
        net = ip2int(server_ip) & (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        bcast = net | ((1 << (32 - prefix)) - 1)
        if s > e:
            raise ValueError("pool start must not be after pool end")
        if not (net < s and e < bcast):
            raise ValueError(f"the pool must lie inside {int2ip(net)}/{prefix} (excluding network and broadcast)")
        if e - s + 1 > 250:
            raise ValueError("the pool may hold at most 250 addresses")
        for label, ip in (("the server address", server_ip), ("the gateway", gateway)):
            if ip and s <= ip2int(ip) <= e:
                raise ValueError(f"the pool must not contain {label} {ip}")
        return start, end

    def _dhcp_pool(self, adapter: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.settings["dhcp"]
        server_ip, prefix = self._dhcp_server_ip(adapter)
        if cfg["pool_start"] and cfg["pool_end"]:
            start, end = cfg["pool_start"], cfg["pool_end"]
            return {"start": start, "end": end, "size": ip2int(end) - ip2int(start) + 1, "auto": False}
        start, end = self._dhcp_default_pool(server_ip, prefix, int(cfg["pool_size"]), [adapter.get("gateway") or ""])
        return {"start": start, "end": end, "size": int(cfg["pool_size"]), "auto": True}

    def dhcp_summary(self) -> Dict[str, Any]:
        with self.lock:
            a = self._dhcp_adapter()
            try:
                pool = self._dhcp_pool(a) if a else None
            except ValueError:
                pool = None
            server_ip = self._dhcp_server_ip(a)[0] if a else None
            return {"available": True, "running": self.dhcp_running, "adapter": a["name"] if a else None,
                    "server_ip": server_ip, "pool": {k: pool[k] for k in ("start", "end", "size")} if pool else None,
                    "bound": sum(1 for c in self.dhcp_clients if c["state"] == "bound"),
                    "offered": sum(1 for c in self.dhcp_clients if c["state"] == "offered"),
                    "since_ts": self.dhcp_since, "error": self.dhcp_error}

    def dhcp_status(self) -> Dict[str, Any]:
        with self.lock:
            cfg = self.settings["dhcp"]
            a = self._dhcp_adapter()
            server_ip, prefix = self._dhcp_server_ip(a)
            error = self.dhcp_error
            try:
                pool = self._dhcp_pool(a)
            except ValueError as exc:
                pool, error = {"start": None, "end": None, "size": 0, "auto": True}, str(exc)
            adapter = {k: a[k] for k in ("name", "index", "mac", "ip", "prefix", "mask", "dhcp_enabled", "gateway", "is_physical", "type_name",
                                         "is_internet")}
            adapter.update({"will_change": bool(a["dhcp_enabled"]) and not self.dhcp_changed, "changed": self.dhcp_changed,
                            "static_ip": cfg["static_ip"], "static_prefix": int(cfg["static_prefix"])})
            if self.dhcp_changed:
                adapter["ip"], adapter["prefix"], adapter["mask"] = cfg["static_ip"], int(cfg["static_prefix"]), "255.255.255.0"
            clients = copy.deepcopy(self.dhcp_clients)
            return {"available": True, "running": self.dhcp_running, "since_ts": self.dhcp_since, "error": error,
                    "warning": self.dhcp_warning, "adapter": adapter,
                    "adapters": [{k: x[k] for k in ("name", "index", "ip", "prefix", "dhcp_enabled", "is_physical", "type_name", "status",
                                                    "is_internet")}
                                 for x in DHCP_ADAPTERS],
                    "server_ip": server_ip, "pool": pool, "lease_s": int(cfg["lease_s"]), "gateway": server_ip, "dns": [],
                    "ping_check": bool(cfg["ping_check"]), "clients": clients,
                    "counts": {"bound": sum(1 for c in clients if c["state"] == "bound"),
                               "offered": sum(1 for c in clients if c["state"] == "offered"), "total": len(clients)},
                    "scan": copy.deepcopy(self.dhcp_last_scan),
                    "firewall": {"rule": DHCP_FIREWALL_RULE, "ok": True if self.dhcp_running else None, "error": None},
                    "settings": copy.deepcopy(cfg)}

    def dhcp_leases(self) -> List[Dict[str, Any]]:
        with self.lock:
            return copy.deepcopy(self.dhcp_clients)

    def dhcp_scan(self, wait_s: Optional[float] = None) -> Dict[str, Any]:
        """Relay-style probe on every adapter; the mock waits a shortened time then answers."""
        wait = float(wait_s) if wait_s is not None else float(self.settings["dhcp"]["scan_wait_s"])
        wait = max(0.0, min(30.0, wait))
        t0 = time.time()
        time.sleep(0.05 if self.dhcp_fast else min(wait, 1.5))
        with self.lock:
            servers: List[Dict[str, Any]] = []
            if not self.dhcp_force_none:
                servers.append({"adapter": "Ethernet", "nic_ip": "10.0.0.112", "server_ip": "10.0.0.251", "source_ip": "10.0.0.251",
                                "offered_ip": "10.0.0.191", "lease_s": 86400, "router": "10.0.0.251", "mask": "255.255.255.0",
                                "dns": ["10.0.0.251"], "known": True, "answered": True})
            scan = {"ts": time.time(), "duration_s": round(time.time() - t0, 2), "wait_s": wait, "servers": servers,
                    "probed": [{"adapter": a["name"], "ip": a["ip"]} for a in DHCP_ADAPTERS if a["prefix"] < 32],
                    "errors": [] if self.dhcp_force_none else ["Tailscale: not probed (a /32 tunnel has no broadcast domain)"]}
            self.dhcp_last_scan = scan
        self.hub.publish("dhcp.scan", scan)
        return copy.deepcopy(scan)

    def dhcp_start(self, force: bool = False) -> Dict[str, Any]:
        with self.lock:
            if self.dhcp_running:
                return self.dhcp_status()
        if not force:
            scan = self.dhcp_scan()
            if scan["servers"]:
                raise DhcpConflict(scan["servers"], scan)
        with self.lock:
            a = self._dhcp_adapter()
            self.dhcp_changed = bool(a["dhcp_enabled"])
            self.dhcp_running = True
            self.dhcp_since = time.time()
            self.dhcp_error = None
            self.dhcp_warning = None
            self.dhcp_gen += 1
            gen = self.dhcp_gen
            pool = self._dhcp_pool(a)
            fast = self.dhcp_fast
            st = self.dhcp_status()
        self.hub.publish("dhcp.state", dict(self.dhcp_summary(), running=True))
        threading.Thread(target=self._dhcp_worker, args=(gen, pool, fast), name="mock-dhcp", daemon=True).start()
        return st

    def dhcp_stop(self) -> Dict[str, Any]:
        with self.lock:
            self.dhcp_running = False
            self.dhcp_since = None
            self.dhcp_changed = False
            self.dhcp_gen += 1
            st = self.dhcp_status()
        self.hub.publish("dhcp.state", dict(self.dhcp_summary(), running=False))
        return st

    def _dhcp_worker(self, gen: int, pool: Dict[str, Any], fast: bool) -> None:
        """Three devices ask for an address over ~8 s (offered -> bound), each probed a second later."""
        try:
            delays = [0.15, 0.3, 0.45] if fast else [2.0, 3.0, 3.0]
            probe_delay = 0.15 if fast else 1.0
            lease_s = int(self.settings["dhcp"]["lease_s"])
            base = ip2int(pool["start"])
            for i, (mac, host, vendor, rtt, ports) in enumerate(DHCP_FAKE_CLIENTS):
                time.sleep(delays[i])
                with self.lock:
                    if self.dhcp_gen != gen:
                        return
                    ip = int2ip(base + i)
                    now = time.time()
                    existing = next((c for c in self.dhcp_clients if c["mac"] == mac), None)
                    lease = existing or {"ip": ip, "mac": mac, "hostname": host, "vendor": vendor, "ping_ok": None, "rtt_ms": None,
                                         "open_ports": [], "client_id": "01" + mac.replace(":", "").lower(), "first_ts": now,
                                         "probed_ts": None, "probing": False}
                    lease.update({"ip": ip, "state": "offered", "last_ts": now, "expires_ts": now + 45, "probing": False})
                    if not existing:
                        self.dhcp_clients.append(lease)
                    snap = copy.deepcopy(lease)
                self.hub.publish("dhcp.lease", {"lease": snap})
                time.sleep(0.1 if fast else 0.6)
                with self.lock:
                    if self.dhcp_gen != gen:
                        return
                    now = time.time()
                    lease.update({"state": "bound", "last_ts": now, "expires_ts": now + lease_s, "probing": True})
                    snap = copy.deepcopy(lease)
                self.hub.publish("dhcp.lease", {"lease": snap})
                time.sleep(probe_delay)
                with self.lock:
                    if self.dhcp_gen != gen:
                        return
                    lease.update({"ping_ok": True, "rtt_ms": round(rtt * (1 + self.rng.gauss(0, 0.1)), 2), "open_ports": list(ports),
                                  "probed_ts": time.time(), "probing": False})
                    snap = copy.deepcopy(lease)
                self.hub.publish("dhcp.lease", {"lease": snap})
        except Exception:  # noqa: BLE001
            log.exception("dhcp worker failed")

    def dhcp_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(patch, dict):
            raise ValueError("settings patch must be an object")
        with self.lock:
            cfg = copy.deepcopy(self.settings["dhcp"])
            if "adapter" in patch:
                name = str(patch["adapter"] or "").strip()
                if name and not any(a["name"].lower() == name.lower() for a in DHCP_ADAPTERS):
                    raise ValueError(f"unknown adapter {name!r}")
                cfg["adapter"] = name
            if "pool_size" in patch:
                cfg["pool_size"] = max(1, min(250, int(patch["pool_size"])))
            if "lease_s" in patch:
                lease = int(patch["lease_s"])
                if not 120 <= lease <= 604800:
                    raise ValueError("lease_s must be between 120 and 604800 seconds")
                cfg["lease_s"] = lease
            if "ping_check" in patch:
                cfg["ping_check"] = bool(patch["ping_check"])
            start = str(patch.get("pool_start", cfg["pool_start"]) or "").strip()
            end = str(patch.get("pool_end", cfg["pool_end"]) or "").strip()
            if bool(start) != bool(end):
                raise ValueError("give both pool_start and pool_end, or neither for an automatic pool")
            old = self.settings["dhcp"]
            self.settings["dhcp"] = cfg          # the adapter choice affects the subnet the pool is checked against
            try:
                a = self._dhcp_adapter()
                server_ip, prefix = self._dhcp_server_ip(a)
                if start:
                    self._dhcp_validate_pool(start, end, server_ip, prefix, a.get("gateway"))
                cfg["pool_start"], cfg["pool_end"] = start, end
                self._dhcp_pool(a)               # the automatic pool must fit too
            except ValueError:
                self.settings["dhcp"] = old
                raise
            st = self.dhcp_status()
        self.hub.publish("settings.changed", {"changed": ["dhcp"]})
        if st["running"]:
            self.hub.publish("dhcp.state", dict(self.dhcp_summary(), running=True))
        return st

    def dhcp_forget(self, mac: str) -> bool:
        mac = (mac or "").strip().upper()
        with self.lock:
            before = len(self.dhcp_clients)
            self.dhcp_clients = [c for c in self.dhcp_clients if c["mac"].upper() != mac]
            removed = len(self.dhcp_clients) != before
        if removed:
            # same stub the real server sends: the UI drops the row instead of replacing it
            self.hub.publish("dhcp.lease", {"lease": {"mac": mac, "state": "forgotten"}})
            self.hub.publish("dhcp.state", self.dhcp_summary())
        return removed

    # -- Tools: traceroute -----------------------------------------------
    @staticmethod
    def _hop_stats(rtts: List[Optional[float]]) -> Dict[str, Any]:
        ok = [r for r in rtts if r is not None]
        return {"rtts": rtts, "avg_ms": round(sum(ok) / len(ok), 2) if ok else None,
                "min_ms": round(min(ok), 2) if ok else None, "max_ms": round(max(ok), 2) if ok else None,
                "loss": len(rtts) - len(ok)}

    def _trace_hops(self, host: str, target_ip: str, probes: int, resolve: bool) -> List[Dict[str, Any]]:
        """The fake path: one hop straight to a LAN address, else the 9-hop internet route."""
        rng = self.rng
        if target_ip.startswith("10.0.0."):
            base = 0.6 if target_ip == "10.0.0.251" else 1.2
            rtts = [round(max(0.2, base * (1 + rng.gauss(0, 0.15))), 2) for _ in range(probes)]
            return [dict(ttl=1, ip=target_ip, alt_ips=[], hostname=(host if resolve and host != target_ip else None),
                         responder_status=0, kind="destination", label="Destination", **self._hop_stats(rtts))]
        hops = []
        for i, (ip, hn, kind, label, base, lost) in enumerate(TRACE_PATH, start=1):
            if ip is None:
                rtts: List[Optional[float]] = [None] * probes
            else:
                rtts = [round(max(0.2, base * (1 + rng.gauss(0, 0.08))), 2) for _ in range(probes)]
                for k in range(min(lost, probes)):
                    rtts[(k * 2 + 1) % probes] = None
            if kind == "destination":
                ip, hn = target_ip, (host if host != target_ip else None)
            hops.append(dict(ttl=i, ip=ip, alt_ips=[], hostname=(hn if resolve else None),
                             responder_status=(None if ip is None else 3 if kind == "destination" else 11),
                             kind=kind, label=label, **self._hop_stats(rtts)))
        return hops

    def traceroute(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronous like the service: the hops are published one by one while the request waits."""
        host = str(body.get("host") or "").strip()
        if not host or " " in host:
            raise ValueError("host is required and must not contain spaces")
        try:
            max_hops = max(1, min(64, int(body.get("max_hops") or 30)))
            probes = max(1, min(5, int(body.get("probes") or 3)))
            timeout_ms = max(100, min(10000, int(body.get("timeout_ms") or 1500)))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"bad option: {exc}") from exc
        resolve = bool(body.get("resolve_names", True))
        if host.lower() in ("nonexistent.invalid", "bad.example") or host.endswith(".invalid"):
            raise ValueError(f"could not resolve {host}")
        is_ip = host.count(".") == 3 and all(p.isdigit() for p in host.split("."))
        target_ip = host if is_ip else ("10.0.0.251" if host.lower() == "gateway" else "203.0.113.80")
        with self.lock:
            if self.trace_running:
                raise RuntimeError("a traceroute is already running")
            self.trace_running = True
            fast = self.trace_fast
        t0 = time.time()
        try:
            self.hub.publish("trace.start", {"host": host, "target_ip": target_ip, "max_hops": max_hops, "probes": probes})
            path = self._trace_hops(host, target_ip, probes, resolve)
            hops: List[Dict[str, Any]] = []
            complete = False
            for hop in path:
                if len(hops) >= max_hops:
                    break
                time.sleep(0.01 if fast else (0.3 + (0.4 if hop["ip"] is None else 0.0)))
                hops.append(hop)
                self.hub.publish("trace.hop", {"host": host, "target_ip": target_ip, "hop": copy.deepcopy(hop)})
                if hop["kind"] == "destination":
                    complete = True
            trace = {"host": host, "target_ip": target_ip, "ts": t0, "duration_s": round(time.time() - t0, 2),
                     "max_hops": max_hops, "probes": probes, "timeout_ms": timeout_ms, "complete": complete,
                     "error": None if complete else f"no reply from {host} within {max_hops} hops",
                     "pc": {"ip": PC_IP, "hostname": PC_HOSTNAME}, "gateway": "10.0.0.251", "hops": hops}
            with self.lock:
                self.trace_last = trace
            self.hub.publish("trace.done", {"host": host, "target_ip": target_ip, "hops": len(hops), "complete": complete,
                                            "duration_s": trace["duration_s"]})
            return copy.deepcopy(trace)
        finally:
            with self.lock:
                self.trace_running = False

    def traceroute_last(self) -> Dict[str, Any]:
        with self.lock:
            return {"trace": copy.deepcopy(self.trace_last), "running": self.trace_running}

    # -- Tools: LAN peers + throughput -----------------------------------
    def lan_peers(self) -> Dict[str, Any]:
        """The peers view (same keys as ``tnt.lanpeers.LanPeers.peers_view``).  Switched off:
        no peers, ``listening`` / ``running`` false and ``error`` "disabled"."""
        now = time.time()
        with self.lock:
            on = self.lan_enabled
            peers = []
            if on:
                for k, (pid, hn, ip, ver, adapter) in enumerate(LAN_PEERS):
                    seen = self.lan_peer_ts - k * 2.5
                    peers.append({"id": pid, "hostname": hn, "ip": ip, "version": ver, "last_seen_ts": round(seen, 3),
                                  "age_s": round(max(0.0, now - seen), 1), "adapter": adapter})
            return {"self": {"id": "c0ffee42", "hostname": PC_HOSTNAME, "ip": PC_IP, "version": VERSION, "port": self.port + 3},
                    "peers": peers, "listening": on, "error": None if on else "disabled", "enabled": on, "running": on,
                    "throughput_running": self.lan_running, "beacon_port": self.port + 2, "throughput_port": self.port + 3,
                    "firewall": {"ok": True, "error": None} if on else {"ok": None, "error": None}}

    def lan_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """``{"enabled": true|false}`` -> the peers view, mirroring PUT /api/tools/lan/settings:
        ``enabled`` must be a JSON boolean (a truthy string must never switch discovery off) and
        no other key is accepted.  Publishes ``lan.state`` with the whole view."""
        if not isinstance(patch, dict):
            raise ValueError("settings patch must be an object")
        unknown = sorted(k for k in patch if k not in LAN_SETTINGS_KEYS)
        if unknown:
            raise ValueError(f"unknown LAN setting(s) {', '.join(unknown)}; accepted: {', '.join(LAN_SETTINGS_KEYS)}")
        if "enabled" not in patch:
            raise ValueError(f"nothing to update; accepted keys: {', '.join(LAN_SETTINGS_KEYS)}")
        if not isinstance(patch["enabled"], bool):
            raise ValueError("enabled must be true or false")
        on = patch["enabled"]
        with self.lock:
            self.lan_enabled = on
            self.settings.setdefault("lan", {})["enabled"] = on
            if on:
                self.lan_peer_ts = time.time()      # the peers are heard from again right away
        view = self.lan_peers()
        self.hub.publish("lan.state", copy.deepcopy(view))
        return view

    def lan_tick(self, now: float) -> None:
        """Every 10 s the peers 'announce' again: bump the sighting time and broadcast lan.peers.
        Nothing is announced while the switch is off."""
        with self.lock:
            if not self.lan_enabled or now - self.lan_peer_ts < 10:
                return
            self.lan_peer_ts = now
        self.hub.publish("lan.peers", {"peers": self.lan_peers()["peers"]})

    def lan_throughput(self, body: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            if not self.lan_enabled:
                raise ValueError("LAN discovery is turned off")
        peer_ip = str(body.get("peer") or "").strip()
        peer = next((p for p in LAN_PEERS if p[2] == peer_ip), None)
        if not peer:
            raise ValueError(f"no TNT peer at {peer_ip!r} — pick one from the list")
        try:
            seconds = max(2, min(20, int(body.get("seconds") or 5)))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"bad seconds: {exc}") from exc
        with self.lock:
            if self.lan_running:
                raise RuntimeError("a throughput test is already running")
            self.lan_running = True
            fast = self.lan_fast
        t0 = time.time()
        rng = self.rng
        try:
            up_final = round(940 * (1 + rng.gauss(0, 0.02)), 1)
            down_final = round(910 * (1 + rng.gauss(0, 0.02)), 1)
            phases = [("connect", 0.4, 0.0), ("upload", 1.8, up_final), ("download", 1.8, down_final)]
            for phase, dur, target in phases:
                dur = 0.04 if fast else dur
                p0 = time.time()
                while True:
                    frac = min(1.0, (time.time() - p0) / dur)
                    mbps = round(target * min(1.0, 0.55 + frac * 0.5) * (1 + rng.gauss(0, 0.03)), 1) if target else 0.0
                    self.hub.publish("lan.throughput.progress", {"phase": phase, "pct": round(frac * 100, 1), "mbps": mbps})
                    if frac >= 1.0:
                        break
                    time.sleep(0.02 if fast else 0.15)
            result = {"ts": time.time(), "peer": {"ip": peer[2], "hostname": peer[1]}, "seconds": seconds,
                      "upload_mbps": up_final, "download_mbps": down_final, "latency_ms": round(0.35 + abs(rng.gauss(0, 0.08)), 2),
                      "duration_s": round(time.time() - t0, 2), "error": None}
            with self.lock:
                self.lan_last = result
            self.hub.publish("lan.throughput.done", {"result": copy.deepcopy(result)})
            return copy.deepcopy(result)
        finally:
            with self.lock:
                self.lan_running = False

    def lan_throughput_last(self) -> Dict[str, Any]:
        with self.lock:
            return {"result": copy.deepcopy(self.lan_last), "running": self.lan_running}

    # -- Tools: saved Wi-Fi networks -------------------------------------
    def wifi_profiles(self, reveal: bool = True) -> Dict[str, Any]:
        """Same shape as ``tnt.wifi.list_profiles`` (GET /api/tools/wifi/profiles).
        ``reveal=False`` leaves every key out while ``key_present`` still says whether there
        is one, exactly like the real route's ``?reveal=0``."""
        profiles = []
        for name, ssid, auth, enc, key, mode, hidden in WIFI_PROFILES:
            profiles.append({
                "name": name, "ssid": ssid, "authentication": auth, "encryption": enc,
                "key": key if (reveal and key) else None, "key_present": bool(key),
                "connection_mode": mode, "non_broadcast": bool(hidden),
                "interface": WIFI_INTERFACE["guid"], "error": None,
            })
        return {"available": True, "interfaces": [dict(WIFI_INTERFACE)], "profiles": profiles,
                "error": None, "source": "wlanapi", "ts": time.time()}

    # -- settings / misc -------------------------------------------------
    def update_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(patch, dict):
            raise ValueError("settings patch must be an object")
        with self.lock:
            old = self.settings
            new = deep_merge(old, patch)
            for dotted in RETIRED_SETTINGS:
                section, _, leaf = dotted.rpartition(".")
                if isinstance(new.get(section), dict):
                    new[section].pop(leaf, None)
            sp = new["speedtest"]
            try:
                sp["interval_min"] = max(1, min(1440, int(sp["interval_min"])))
            except (TypeError, ValueError):
                sp["interval_min"] = 15
            if sp["backend"] not in ("auto", "cloudflare", "fastcom"):
                sp["backend"] = "auto"
            if new["ui"]["theme"] not in ("light", "dark"):
                new["ui"]["theme"] = "light"
            new["ui"]["show_ipv6"] = bool(new["ui"].get("show_ipv6", False))
            new.setdefault("lan", {})["enabled"] = bool(new.get("lan", {}).get("enabled", True))
            self.lan_enabled = new["lan"]["enabled"]        # one truth for the Tools switch
            new["ping"]["loaded"] = bool(new["ping"]["loaded"])
            changed = changed_keys(old, new)
            self.settings = new
            snap = copy.deepcopy(new)
        if changed:
            self.hub.publish("settings.changed", {"changed": changed})
        return {"settings": snap, "changed": changed}

    def netinfo(self) -> Dict[str, Any]:
        now = time.time()
        eth = {"index": 12, "name": "Ethernet", "description": "Intel(R) Ethernet Controller I225-V", "mac": "D8:BB:C1:12:34:08",
               "if_type": 6, "type_name": "Ethernet", "status": "up", "speed_bps": 2500000000, "mtu": 1500,
               "dhcp_enabled": True, "dhcp_server": "10.0.0.251", "dns_suffix": "lan",
               "ipv4": [{"address": "10.0.0.112", "prefix": 24, "family": 4, "netmask": "255.255.255.0", "network": "10.0.0.0/24"}],
               "ipv6": [{"address": "fe80::a1b2:c3d4:e5f6:1234", "prefix": 64, "family": 6, "netmask": None, "network": "fe80::/64"}],
               "gateways": ["10.0.0.251"], "dns": ["10.0.0.251", "1.1.1.1"], "metric_v4": 25, "is_physical": True,
               "is_loopback": False,
               "subnets": [{"network": "10.0.0.0/24", "family": 4, "mask": "255.255.255.0", "addresses": ["10.0.0.112"], "gateways": ["10.0.0.251"]},
                           {"network": "fe80::/64", "family": 6, "mask": None, "addresses": ["fe80::a1b2:c3d4:e5f6:1234"], "gateways": []}]}
        wifi = {"index": 7, "name": "Wi-Fi", "description": "Intel(R) Wi-Fi 6E AX211 160MHz", "mac": "A4:6B:B6:12:34:0D",
                "if_type": 71, "type_name": "Wi-Fi", "status": "down", "speed_bps": None, "mtu": 1500,
                "dhcp_enabled": True, "dhcp_server": None, "dns_suffix": "", "ipv4": [], "ipv6": [], "gateways": [],
                "dns": [], "metric_v4": 35, "is_physical": True, "is_loopback": False, "subnets": []}
        ts_ = {"index": 21, "name": "Tailscale", "description": "Tailscale Tunnel", "mac": "", "if_type": 53,
               "type_name": "Tunnel", "status": "up", "speed_bps": None, "mtu": 1280, "dhcp_enabled": False,
               "dhcp_server": None, "dns_suffix": "tail1234.ts.net",
               "ipv4": [{"address": "100.101.22.7", "prefix": 32, "family": 4, "netmask": "255.255.255.255", "network": "100.101.22.7/32"}],
               "ipv6": [], "gateways": [], "dns": ["100.100.100.100"], "metric_v4": 5, "is_physical": False,
               "is_loopback": False,
               "subnets": [{"network": "100.101.22.7/32", "family": 4, "mask": "255.255.255.255", "addresses": ["100.101.22.7"], "gateways": []}]}
        hv = {"index": 30, "name": "vEthernet (Default Switch)", "description": "Hyper-V Virtual Ethernet Adapter", "mac": "00:15:5D:01:02:03",
              "if_type": 6, "type_name": "Ethernet", "status": "up", "speed_bps": 10000000000, "mtu": 1500,
              "dhcp_enabled": False, "dhcp_server": None, "dns_suffix": "",
              "ipv4": [{"address": "172.29.64.1", "prefix": 20, "family": 4, "netmask": "255.255.240.0", "network": "172.29.64.0/20"}],
              "ipv6": [], "gateways": [], "dns": [], "metric_v4": 15, "is_physical": False, "is_loopback": False,
              "subnets": [{"network": "172.29.64.0/20", "family": 4, "mask": "255.255.240.0", "addresses": ["172.29.64.1"], "gateways": []}]}
        return {"ts": now, "adapters": [eth, ts_, hv, wifi], "internet_nic_index": 12, "default_gateway": "10.0.0.251",
                "public_hint": None}

    def status(self) -> Dict[str, Any]:
        with self.lock:
            targets = [self.target_view(t) for t in self.targets]
            lights = [t["light"] for t in targets]
            overall = "grey"
            for c in ("red", "yellow", "green"):
                if c in lights:
                    overall = c
                    break
            last_run = max(self.disc_runs, key=lambda r: r["ts"]) if self.disc_runs else None
            now = time.time()
            return {"version": VERSION, "started_ts": self.started_ts, "uptime_s": round(now - self.started_ts, 1),
                    "mode": "console", "monitoring": not self.paused and bool(self.targets), "paused": self.paused,
                    "overall_light": overall, "targets": targets, "outages": self.outages_status(),
                    "speed": self.speed_status(),
                    "discovery": {"running": self.disc_running, "progress": dict(self.disc_progress),
                                  "last_run": {"id": last_run["id"], "ts": last_run["ts"], "cidr": last_run["cidr"],
                                               "found": last_run["found"], "duration_s": last_run["duration_s"]} if last_run else None},
                    "dhcp": self.dhcp_summary(),
                    "netinfo": {"internet_nic": {"name": "Ethernet", "ipv4": "10.0.0.112/24", "network": "10.0.0.0/24",
                                                 "gateway": "10.0.0.251"}, "adapter_count": 4},
                    "map": {"ts": time.time(), "running": True, "internet_host": "totalelectronics.com",
                            "pc": {"hostname": PC_HOSTNAME, "ip": PC_IP, "adapter": "Ethernet"},
                            # the router's WAN address as seen from the internet, refreshed every 10 min
                            "public_ip": {"ip": PUBLIC_IP, "ts": self.public_ip_ts + ((now - self.public_ip_ts) // 600) * 600, "error": None},
                            "gateway": {"name": "gateway", "host": "gateway", "ip": "10.0.0.251", "resolved": True, "resolve_error": None,
                                        "state": "up", "last": {"ts": time.time(), "ok": True, "rtt_ms": 0.6}, "consecutive_missed": 0,
                                        "sent": 60, "received": 60, "loss_pct": 0.0, "avg_ms": 0.7},
                            "internet": {"name": "internet", "host": "totalelectronics.com", "ip": "203.0.113.80", "resolved": True,
                                         "resolve_error": None, "state": "up", "last": {"ts": time.time(), "ok": True, "rtt_ms": 19.0},
                                         "consecutive_missed": 0, "sent": 60, "received": 59, "loss_pct": 1.7, "avg_ms": 19.4}},
                    "settings": {"theme": self.settings["ui"]["theme"], "loaded": self.settings["ping"]["loaded"]}}

    def diagnostics(self) -> Dict[str, Any]:
        with self.lock:
            now = time.time()
            threads = [{"name": th.name, "alive": th.is_alive(), "daemon": th.daemon} for th in threading.enumerate()]
            return {
                "service": {"name": "TNTService", "version": VERSION, "mode": "console", "pid": os.getpid(),
                            "started_ts": self.started_ts, "uptime_s": round(now - self.started_ts, 1),
                            "python": "3.12.4", "frozen": False, "exe": "C:\\Program Files\\TNT\\TNTService.exe",
                            "data_dir": "C:\\ProgramData\\TNT", "config_path": "C:\\ProgramData\\TNT\\config.json",
                            "log_file": "C:\\ProgramData\\TNT\\logs\\tnt-service.log"},
                "os": {"caption": "Microsoft Windows 11 Pro", "version": "10.0.22631", "build": "22631",
                       "hostname": "TEC-DESKTOP", "user": "SYSTEM", "is_admin": True},
                "api": {"host": "127.0.0.1", "port": self.port, "clients_sse": self.hub.count()},
                "db": {"path": "C:\\ProgramData\\TNT\\tnt.db", "size_bytes": 18_874_368,
                       "counts": {"targets": len(self.targets), "ping_minutes": 12960, "outages": len(self.outages),
                                  "speedtests": len(self.speedtests), "discovery_runs": len(self.disc_runs),
                                  "discovery_hosts": sum(r["found"] for r in self.disc_runs), "events": len(self.events_db)}},
                "logs": {"dir": "C:\\ProgramData\\TNT\\logs", "total_bytes": 4_210_688, "ping_log_files": 9},
                "ping": {"paused": self.paused,
                         "targets": [{"id": t["id"], "host": t["host"], "ip": t["ip"], "kind": t["kind"], "thread_alive": True,
                                      "last_ts": self.samples[t["id"]][-1][0] if self.samples.get(t["id"]) else None,
                                      "light": self._light(t)} for t in self.targets]},
                "outages": {"open": [o for o in self.outages if o["end_ts"] is None], "count_24h": self.outages_status()["count_24h"]},
                "speedtest": {"backends": [{"name": "cloudflare", "available": True, "detail": "https://speed.cloudflare.com"},
                                           {"name": "fastcom", "available": True, "detail": "api.fast.com"}],
                              "selected": "cloudflare", "running": self.speed_running, "next_run_ts": self.speed_next_ts,
                              "last": self.speedtests[-1] if self.speedtests else None},
                # tnt.diagnostics._discovery: last_run only once a run exists
                "discovery": dict({"available": True, "running": self.disc_running, "progress": dict(self.disc_progress),
                                   "last_run_ts": max((r["ts"] for r in self.disc_runs), default=None)},
                                  **({"last_run": self._disc_last_summary()} if self.disc_runs else {})),
                "threads": threads, "memory_mb": 48.6, "cpu_pct": 0.4,
                "recent_log": list(self.log_ring)[-100:], "recent_events": list(reversed(self.events_db))[:50],
                "errors_24h": 0,
            }

    def log_tail(self, lines: int) -> Dict[str, Any]:
        with self.lock:
            out = []
            for r in self.log_ring:
                stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
                out.append(f"{stamp},{int((r['ts'] % 1) * 1000):03d} {r['level']:<7} {r['message']}")
            # pad with plausible periodic lines
            base = time.time() - 60 * len(out)
            for k in range(max(0, lines - len(out))):
                stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(base + k * 37))
                out.append(f"{stamp},{(k * 131) % 1000:03d} DEBUG   tnt.api.server: GET /api/status 200 0.8 ms")
            return {"file": "C:\\ProgramData\\TNT\\logs\\tnt-service.log", "lines": out[-lines:]}


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
STATE: MockState  # set in main()


class Handler(BaseHTTPRequestHandler):
    server_version = "TNT-mock/1.0"
    protocol_version = "HTTP/1.1"

    # -- plumbing --------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
        log.debug("%s " + fmt, self.address_string(), *args)

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, status: int, code: str, message: str) -> None:
        self._json({"error": {"code": code, "message": message}}, status)

    def _consume_body(self) -> None:
        """Read the request body off the socket exactly once, before routing.

        Every request goes through here whether or not its route looks at the body: an
        unread body (say ``POST /api/dhcp/stop`` with ``{}``, which the UI sends) would
        otherwise stay on the keep-alive connection and be parsed as the start of the
        NEXT request line (``{}GET /api/health`` -> 501 "Unsupported method").  The raw
        bytes are cached so ``_body()`` can be called any number of times.
        """
        self._raw_body: bytes = b""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n > 0:
            self._raw_body = self.rfile.read(n)
        elif "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            # not worth decoding for a dev mock: drop the connection after this reply so
            # the leftover chunks can never be mistaken for the next request
            self.close_connection = True

    def _body(self) -> Dict[str, Any]:
        raw = getattr(self, "_raw_body", None)
        if raw is None:                 # a route reached outside _handle(): read it now
            self._consume_body()
            raw = self._raw_body
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"invalid JSON body: {exc}") from exc
        return data if isinstance(data, dict) else {}

    def _static(self, path: str) -> None:
        rel = path.lstrip("/") or "index.html"
        target = (UI_DIR / rel).resolve()
        try:
            target.relative_to(UI_DIR.resolve())
        except ValueError:
            self._error(404, "not_found", "no such file")
            return
        if target.is_dir():
            target = target / "index.html"
        if not target.is_file():
            self._error(404, "not_found", "no such file")
            return
        ctype = MIME.get(target.suffix.lower()) or mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _sse(self) -> None:
        q = STATE.hub.subscribe()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.wfile.write(f"event: hello\ndata: {json.dumps({'version': VERSION, 'ts': time.time()})}\n\n".encode())
            self.wfile.flush()
            while True:
                try:
                    frame = q.get(timeout=15)
                except queue.Empty:
                    frame = ": ping\n\n"
                self.wfile.write(frame.encode("utf-8"))
                self.wfile.flush()
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            STATE.hub.unsubscribe(q)
            self.close_connection = True

    # -- routing ---------------------------------------------------------
    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET", bad_request=False)

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._handle("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle("DELETE")

    def _handle(self, method: str, bad_request: bool = True) -> None:
        """Consume the body, route, and turn exceptions into JSON errors."""
        try:
            self._consume_body()
            self._route(method)
        except ValueError as exc:
            if not bad_request:
                log.exception("%s %s failed", method, self.path)
                self._error(500, "internal", str(exc))
            else:
                self._error(400, "bad_request", str(exc))
        except Exception as exc:  # noqa: BLE001
            log.exception("%s %s failed", method, self.path)
            self._error(500, "internal", str(exc))

    def _route(self, method: str) -> None:  # noqa: C901 - a flat router is easiest to read
        url = urlparse(self.path)
        path = url.path.rstrip("/") or "/"
        qs = {k: v[-1] for k, v in parse_qs(url.query).items()}
        if not path.startswith("/api"):
            if method in ("GET", "HEAD"):
                self._static(path)
            else:
                self._error(405, "method_not_allowed", "static files are read-only")
            return
        p = path[4:] or "/"
        parts = [x for x in p.split("/") if x]
        now = time.time()

        def qf(name: str, default: float) -> float:
            try:
                return float(qs.get(name, default))
            except (TypeError, ValueError):
                return default

        if method == "GET":
            if p == "/health":
                return self._json({"ok": True})
            if p == "/status":
                return self._json(STATE.status())
            if p == "/netinfo":
                return self._json(STATE.netinfo())
            if p == "/targets":
                return self._json(STATE.targets_view())
            if len(parts) == 3 and parts[0] == "targets" and parts[2] == "samples":
                data = STATE.samples_view(int(parts[1]), int(qf("seconds", 300)))
                return self._json(data) if data else self._error(404, "not_found", "no such target")
            if len(parts) == 3 and parts[0] == "targets" and parts[2] == "history":
                data = STATE.history_view(int(parts[1]), qf("from", now - 86400), qf("to", now))
                return self._json(data) if data else self._error(404, "not_found", "no such target")
            if p == "/outages":
                return self._json({"outages": STATE.outages_list(qf("from", now - 86400), qf("to", now)),
                                   "status": STATE.outages_status()})
            if p == "/outages/timeline":
                return self._json(STATE.timeline(qf("hours", 24)))
            if p == "/speedtests":
                lim = int(qf("limit", 0)) or None
                return self._json({"results": STATE.speed_history(qf("from", now - 86400), qf("to", now + 1), lim),
                                   "status": STATE.speed_status()})
            if p == "/speedtests/patterns":
                return self._json(STATE.patterns(int(qf("days", 7))))
            if p == "/discovery/runs":
                return self._json({"runs": STATE.disc_runs_view(int(qf("limit", 50)))})
            if len(parts) == 3 and parts[0] == "discovery" and parts[1] == "runs":
                run = STATE.disc_run(int(parts[2]))
                return self._json(run) if run else self._error(404, "not_found", "no such run")
            if p == "/discovery/last":
                return self._json(STATE.disc_last())
            if p == "/discovery/status":
                return self._json(STATE.disc_status())
            if p == "/dhcp/status":
                return self._json(STATE.dhcp_status())
            if p == "/dhcp/leases":
                return self._json({"leases": STATE.dhcp_leases()})
            if p == "/tools/traceroute/last":
                return self._json(STATE.traceroute_last())
            if p == "/tools/lan/peers":
                return self._json(STATE.lan_peers())
            if p == "/tools/lan/throughput/last":
                return self._json(STATE.lan_throughput_last())
            if p == "/tools/wifi/profiles":
                # reveal defaults OFF, like the real route; reveal=1 needs an administrator
                reveal = str(qs.get("reveal", "0")).strip().lower() in ("1", "true", "yes", "on")
                if reveal and cross_origin_browser_request(self.headers, STATE.port):
                    return self._error(403, "forbidden", WIFI_CROSS_ORIGIN_MSG)
                if reveal and not STATE.wifi_admin:
                    return self._error(403, "admin_required", WIFI_ADMIN_REQUIRED_MSG)
                return self._json(STATE.wifi_profiles(reveal))
            if p == "/settings":
                with STATE.lock:
                    return self._json(copy.deepcopy(STATE.settings))
            if p == "/easter":
                return self._json({"detonated": int(getattr(STATE, "easter_total", 0)), "max_sticks": 100})
            if p == "/diagnostics":
                return self._json(STATE.diagnostics())
            if p == "/diagnostics/log":
                return self._json(STATE.log_tail(int(qf("lines", 200))))
            if p == "/events":
                return self._sse()
            return self._error(404, "not_found", f"no route for GET {path}")

        if method == "POST":
            if p == "/targets":
                body = self._body()
                view = STATE.add_target(str(body.get("host", "")), body.get("label"))
                return self._json(view, 201)
            if p == "/targets/defaults":
                return self._json(STATE.load_defaults())
            if p == "/speedtests/run":
                if not STATE.speed_run():
                    return self._error(409, "conflict", "a speed test is already running")
                return self._json({"started": True})
            if p == "/discovery/scan":
                body = self._body()
                try:
                    return self._json(STATE.disc_start(body.get("range"), body.get("ports")))
                except RuntimeError as exc:
                    return self._error(409, "conflict", str(exc))
            if p == "/discovery/cancel":
                return self._json({"cancelled": STATE.disc_cancel_scan()})
            if p == "/dhcp/scan":
                body = self._body()
                return self._json(STATE.dhcp_scan(body.get("wait_s")))
            if p == "/dhcp/start":
                body = self._body()
                try:
                    return self._json(STATE.dhcp_start(bool(body.get("force"))))
                except DhcpConflict as exc:
                    return self._json(exc.payload(), 409)
            if p == "/dhcp/stop":
                return self._json(STATE.dhcp_stop())
            if p == "/tools/traceroute":
                try:
                    return self._json(STATE.traceroute(self._body()))
                except RuntimeError as exc:
                    return self._error(409, "conflict", str(exc))
            if p == "/tools/lan/throughput":
                try:
                    return self._json(STATE.lan_throughput(self._body()))
                except RuntimeError as exc:
                    return self._error(409, "conflict", str(exc))
            if p == "/easter/detonate":
                body = self._body()
                n = int(body.get("sticks", 1))
                if not 1 <= n <= 100:
                    return self._error(400, "bad_request", "sticks must be between 1 and 100")
                with STATE.lock:
                    STATE.easter_total = int(getattr(STATE, "easter_total", 0)) + n
                    total = STATE.easter_total
                return self._json({"detonated": total, "added": n, "max_sticks": 100})
            if p == "/monitoring/pause":
                with STATE.lock:
                    STATE.paused = True
                STATE.hub.publish("monitoring.paused", {"paused": True})
                return self._json({"paused": True})
            if p == "/monitoring/resume":
                with STATE.lock:
                    STATE.paused = False
                STATE.hub.publish("monitoring.paused", {"paused": False})
                return self._json({"paused": False})
            if p == "/export":
                body = self._body()
                kind = body.get("range", "daily")
                spans = {"daily": 86400, "weekly": 7 * 86400, "monthly": 30 * 86400, "yearly": 365 * 86400}
                if kind == "custom":
                    start = float(body.get("from") or now - 86400)
                    end = float(body.get("to") or now)
                elif kind in spans:
                    start, end = now - spans[kind], now
                else:
                    raise ValueError("range must be daily, weekly, monthly, yearly or custom")
                if end <= start:
                    raise ValueError("'to' must be after 'from'")
                fmt = lambda t: time.strftime("%Y%m%d", time.localtime(t))  # noqa: E731
                name = f"TNT-report-{fmt(start)}-{fmt(end)}.pdf"
                pdf = tiny_pdf("TNT Network Report (mock)", [
                    "Period: %s to %s" % (time.strftime("%Y-%m-%d %H:%M", time.localtime(start)),
                                          time.strftime("%Y-%m-%d %H:%M", time.localtime(end))),
                    "Generated by tools/mock_api.py - not real data.",
                ])
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Length", str(len(pdf)))
                self.send_header("Content-Disposition", f"attachment; filename={name}")
                self.end_headers()
                self.wfile.write(pdf)
                return None
            return self._error(404, "not_found", f"no route for POST {path}")

        if method == "PUT":
            if p == "/settings":
                return self._json(STATE.update_settings(self._body()))
            if p == "/dhcp/settings":
                return self._json(STATE.dhcp_settings(self._body()))
            if p == "/tools/lan/settings":
                return self._json(STATE.lan_settings(self._body()))
            if p == "/targets/order":
                ids = self._body().get("ids")
                if not isinstance(ids, list) or not ids:
                    return self._error(400, "bad_request", "ids must be a non-empty list of target ids")
                with STATE.lock:
                    wanted = []
                    for i in ids:
                        try:
                            ti = int(i)
                        except (TypeError, ValueError):
                            return self._error(400, "bad_request", "ids must be integers")
                        if ti not in wanted:
                            wanted.append(ti)
                    known = {t["id"] for t in STATE.targets}
                    unknown = [i for i in wanted if i not in known]
                    if unknown:
                        return self._error(400, "bad_request", f"unknown target id(s): {unknown}")
                    by_id = {t["id"]: t for t in STATE.targets}
                    STATE.targets = [by_id[i] for i in wanted] + [t for t in STATE.targets if t["id"] not in wanted]
                    views = [STATE.target_view(t) for t in STATE.targets]
                STATE.hub.publish("ping.targets", {"targets": views})
                return self._json(views)
            return self._error(404, "not_found", f"no route for PUT {path}")

        if method == "DELETE":
            if len(parts) == 2 and parts[0] == "targets":
                if STATE.remove_target(int(parts[1])):
                    return self._json({"removed": True})
                return self._error(404, "not_found", "no such target")
            if len(parts) == 3 and parts[0] == "dhcp" and parts[1] == "leases":
                if STATE.dhcp_forget(unquote(parts[2])):
                    return self._json({"ok": True})
                return self._error(404, "not_found", "no such lease")
            return self._error(404, "not_found", f"no route for DELETE {path}")
        return self._error(405, "method_not_allowed", method)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def ticker(stop: threading.Event) -> None:
    nxt = math.floor(time.time()) + 1
    while not stop.is_set():
        delay = nxt - time.time()
        if delay > 0:
            stop.wait(delay)
            if stop.is_set():
                break
        try:
            STATE.tick(float(nxt))
            STATE.speed_tick()
            STATE.lan_tick(float(nxt))
        except Exception:  # noqa: BLE001
            log.exception("tick failed")
            time.sleep(0.5)
        nxt += 1
        if time.time() > nxt + 2:  # fell behind, realign
            nxt = math.floor(time.time()) + 1


def main(argv: Optional[List[str]] = None) -> int:
    global STATE
    ap = argparse.ArgumentParser(description="TNT mock API + UI server (dev only)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT") or 7136))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    STATE = MockState(args.port)
    try:
        httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        log.error("cannot bind %s:%d (%s) - is something else using it? try: netstat -ano | findstr :%d",
                  args.host, args.port, exc, args.port)
        return 2
    httpd.daemon_threads = True
    stop = threading.Event()
    th = threading.Thread(target=ticker, args=(stop,), name="mock-ticker", daemon=True)
    th.start()
    log.info("TNT mock API serving %s on http://%s:%d/  (Ctrl-C to stop)", UI_DIR, args.host, args.port)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        httpd.server_close()
        th.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
