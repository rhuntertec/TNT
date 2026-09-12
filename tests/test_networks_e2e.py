"""End to end: site networks through the real service pieces, from each ping to the saved reports, a comparison and the PDFs.

The owner's rule: only the pings done from a site's own network are fair to judge that site by.  The real pieces run in a
temporary data directory: the SQLite database (a new file: tagged from the first row), the event bus,
:class:`tnt.networks.NetworkTracker`, :class:`tnt.pinger.PingManager` (ticked by the test), :class:`tnt.outages.OutageTracker`,
:class:`tnt.speedtest.SpeedScheduler`, the engine's Discovery runner and its ``_on_net_changed`` fan-out,
:class:`tnt.reports.ReportManager` and the HTTP API on an ephemeral loopback port.  Only the edges are fakes: ICMP (a pinger
that answers from the network the fake PC is on), the adapters and the neighbour / ARP table (the tracker's ``facts_fn`` and
``neighbour_fn``, ``tnt.arp``), the speed-test backend, the Discovery scanner, the adapter snapshot and the Wi-Fi snapshot the
test posts.  One wall clock drives the tracker, the pinger, the outage tracker, the scheduler and the report manager, so the
story below (about seven hours) takes seconds.  No packet leaves the machine.

The story, in minutes after U (when this release started):

* before U: minutes of the gateway and of an internet target disabled since, recorded before data was tagged with networks;
  the "joined this network" marker says this PC joined site A at U-70, and an outage of the disabled target came after that.
* U..U+120 at site A (router MAC a, gateway 192.168.1.1 on 192.168.1.0/24, DHCP from the router): an internet outage, a speed
  test, Full Scan 1 at U+60 (started unnamed, named "Acme Dental" while it runs).
* U+120..U+140 travelling without a network: every echo is missed and the data stays tagged with A.
* U+140 at site B: another router behind the SAME gateway address and subnet (DHCP from a server), reached mid-minute: a
  gateway outage, a speed test, Full Scan 2 at U+200 ("Harbor View").
* U+230..U+250 travelling again (tagged with B).
* U+250 back at A before its router's MAC is in the neighbour table: a provisional network known by gateway, subnet and DHCP
  server, and a gateway outage.  Full Scan 3 starts unnamed on it; the MAC arrives while the scan's speed test runs, the
  provisional network is merged into A (its rows moved, its id deleted), the job follows and suggests "Acme Dental", and the
  report nobody named is saved under that site.

Addresses are RFC 1918 / RFC 5737, MACs locally administered, sites and SSIDs invented.
"""
from __future__ import annotations

import base64
import http.client
import json
import re
import threading
import time
import zlib
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from tnt import arp, networks, reports
from tnt import config as tnt_config
from tnt import db as tnt_db
from tnt import events as tnt_events
from tnt import pinger as pinger_mod
from tnt.api.server import ApiServer
from tnt.speedtest import scheduler as sched_mod
from tnt.speedtest.base import CANCELLED, SpeedResult

WAIT_S = 20.0               # real-time ceiling for anything asynchronous (normally well under a second)
M = 60.0
STEP_S = 10.0               # the fake PC pings each target every 10 s of its clock, at :05, :15, ... :55 of each minute
#: the test service's settings: no scheduled speed test; outages open after 3 misses and close after 3 answers
CONFIG = {"speedtest": {"enabled": False}, "ping": {"interval_s": 10}, "outage": {"miss_threshold": 3, "recover_threshold": 3}}

U = 1_788_998_400.0         # a minute boundary: this release starts and the tracker identifies site A
J0 = U - 70 * M             # the marker an earlier release left: this PC joined site A then
S1 = U + 60 * M + 5         # Full Scan 1, at A
LEAVE_A = U + 120 * M
AT_B = U + 140 * M + 25     # reaches B 25 s into a minute
S2 = U + 200 * M + 5        # Full Scan 2, at B
LEAVE_B = U + 230 * M
BACK = U + 250 * M          # back at A
S3 = BACK + 4 * M + 5       # Full Scan 3, at A (provisional when it starts)

GATEWAY = "192.168.1.1"
SUBNET = "192.168.1.0/24"
INTERNET = "203.0.113.10"
OLD_INTERNET = "198.51.100.20"      # pinged before this release, disabled since
MAC_A = "02:00:5E:10:00:0A"
MAC_B = "02:00:5E:10:00:0B"

#: the two sites: the router, the adapter this PC uses there, the echo times and what Discovery finds
SITES: Dict[str, Dict[str, Any]] = {
    "A": {"mac": MAC_A, "dhcp_server": GATEWAY, "suffix": "acme.example", "nic": "Ethernet", "index": 7, "type": "Ethernet",
          "description": "Example Gigabit Adapter", "pc_mac": "02:00:5E:00:53:07", "pc_ip": "192.168.1.23", "speed_bps": 1_000_000_000,
          "rtt": {GATEWAY: 1.0, INTERNET: 20.0}, "ssid": "Acme-Staff",
          "hosts": [(GATEWAY, MAC_A, "Router", [80, 443]), ("192.168.1.60", "02:00:5E:10:00:3C", "Camera", [554])]},
    "B": {"mac": MAC_B, "dhcp_server": "192.168.1.10", "suffix": "harbor.example", "nic": "Wi-Fi", "index": 9, "type": "Wi-Fi",
          "description": "Example Wi-Fi 6E Adapter", "pc_mac": "02:00:5E:00:53:09", "pc_ip": "192.168.1.45", "speed_bps": 866_000_000,
          "rtt": {GATEWAY: 3.0, INTERNET: 45.0}, "ssid": "Harbor-Office",
          "hosts": [(GATEWAY, MAC_B, "Router", [80, 443]), ("192.168.1.10", "02:00:5E:10:00:0F", None, [53, 67]),
                    ("192.168.1.70", "02:00:5E:10:00:46", "Phone", [5060])]},
}
#: download of each speed test in turn: A's scheduled test, scan 1, B's scheduled test, scan 2, scan 3
DOWNLOADS = [80.0, 94.2, 900.0, 850.0, 120.0]
ROW_KEYS = {"id", "site", "created_ts", "completed_ts", "status", "summary", "network_id"}


# --------------------------------------------------------------------------- the edges
class Clock:
    def __init__(self, t: float) -> None:
        self.t = float(t)

    def __call__(self) -> float:
        return self.t


class World:
    """Where the fake PC is (a site, or None while travelling), its neighbour table and which addresses stay silent."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.site: Optional[str] = "A"
        self.neigh: Dict[str, Tuple[str, str]] = {GATEWAY: (MAC_A, "reachable")}
        self.silent: set = set()

    # the network tracker's adapters and neighbour table (tnt.networks.gateway_facts / tnt.arp.neighbour)
    def facts(self, hint: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with self.lock:
            site = self.site
        if site is None:
            return None
        s = SITES[site]
        return {"gateway_ip": GATEWAY, "subnet": SUBNET, "dhcp_server": s["dhcp_server"], "dns_suffix": s["suffix"], "nic": s["nic"],
                "if_index": s["index"]}

    def neighbour(self, ip: str, if_index: Optional[int] = None) -> Optional[Tuple[str, str]]:
        with self.lock:
            return self.neigh.get(str(ip)) if self.site is not None else None

    def arp_table(self) -> Dict[str, str]:
        """``tnt.arp.get_arp_table`` (the report manager's fallback for the router MAC): never this PC's own table."""
        with self.lock:
            return {ip: mac for ip, (mac, _state) in self.neigh.items()} if self.site is not None else {}

    # ICMP (tnt.icmp.IcmpPinger)
    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> Any:
        with self.lock:
            rtt = SITES[self.site]["rtt"].get(str(ip)) if self.site is not None and str(ip) not in self.silent else None
        return SimpleNamespace(ok=rtt is not None, rtt_ms=rtt)

    def close(self) -> None:
        pass

    # what the report manager and the engine read about the adapters
    def snapshot(self) -> Dict[str, Any]:
        """``netinfo.netinfo_snapshot()``."""
        with self.lock:
            site = self.site
        s = SITES[site or "A"]
        adapter = {"index": s["index"], "name": s["nic"], "description": s["description"], "mac": s["pc_mac"], "type_name": s["type"],
                   "status": "up", "speed_bps": s["speed_bps"], "dhcp_enabled": True, "dhcp_server": s["dhcp_server"] if site else None,
                   "is_physical": True, "primary_ipv4": s["pc_ip"] if site else None,
                   "ipv4": [{"address": s["pc_ip"], "prefix": 24, "family": 4, "netmask": "255.255.255.0", "network": SUBNET}] if site else [],
                   "gateways": [GATEWAY] if site else [], "dns": [s["dhcp_server"]] if site else [], "warnings": []}
        return {"ts": time.time(), "internet_nic_index": s["index"] if site else None, "default_gateway": GATEWAY if site else None,
                "public_hint": None, "adapters": [adapter]}

    def summary(self) -> Dict[str, Any]:
        """``Engine.netinfo_summary()``."""
        with self.lock:
            site = self.site
        if site is None:
            return {"internet_nic": None, "local_nic": None, "adapter_count": 1}
        return {"internet_nic": {"name": SITES[site]["nic"], "network": SUBNET, "gateway": GATEWAY, "warnings": []},
                "local_nic": None, "adapter_count": 1}

    def marker_network(self) -> Tuple[Optional[str], List[str], Optional[str]]:
        """The report manager's ``network_fn``: (default gateway, IPv4 networks, internet adapter)."""
        with self.lock:
            site = self.site
        return (GATEWAY, [SUBNET], SITES[site]["nic"]) if site else (None, [], None)

    def net_changed(self, ts: float, previous: Optional[str]) -> Dict[str, Any]:
        """The ``net.changed`` data the network watcher publishes for the move to where the PC is now."""
        with self.lock:
            site = self.site
        if site is None:
            return {"generation": 0, "ts": ts, "default_gateway": None, "previous_gateway": GATEWAY if previous else None,
                    "internet_nic": None, "gateway_changed": True, "internet_nic_changed": True, "subnets_changed": True,
                    "dns_changed": True, "summary": f"{SITES[previous or 'A']['nic']}: no address · no gateway", "cause": None}
        s = SITES[site]
        return {"generation": 0, "ts": ts, "default_gateway": GATEWAY, "previous_gateway": None,
                "internet_nic": {"index": s["index"], "name": s["nic"], "ipv4": [s["pc_ip"]], "ipv4_prefixes": ["24"],
                                 "networks": [SUBNET], "dns": [s["dhcp_server"]], "dhcp": True},
                "gateway_changed": True, "internet_nic_changed": True, "subnets_changed": True, "dns_changed": True,
                "summary": f"{s['nic']}: {s['pc_ip']}/24 · gateway {GATEWAY}", "cause": None}


class FakeBackend:
    """A speed-test backend: :data:`DOWNLOADS` in turn, held at the gate while it is cleared (until cancelled)."""

    name = "fake"

    def __init__(self) -> None:
        self.results = list(DOWNLOADS)
        self.gate = threading.Event()
        self.gate.set()
        self.calls = 0

    def available(self, config: Any) -> Tuple[bool, str]:
        return True, "fake"

    def run(self, config: Any, progress: Any = None, cancel: Any = None) -> SpeedResult:
        self.calls += 1
        if progress:
            progress("download", 1.0)
            progress("upload", 1.0)
        while not self.gate.is_set() and not (cancel is not None and cancel.is_set()):
            time.sleep(0.01)
        if cancel is not None and cancel.is_set():
            return SpeedResult(ok=False, ts=time.time(), backend="fake", error=CANCELLED, duration_s=0.1)
        return SpeedResult(ok=True, ts=time.time(), backend="fake", server="Example Colo", isp="Example ISP", external_ip="203.0.113.77",
                           download_mbps=self.results.pop(0), upload_mbps=20.0, latency_ms=12.0, jitter_ms=1.0, packet_loss_pct=0.0,
                           duration_s=1.0, raw={"synthetic": True})


class FakeScanner:
    """Stands in for ``tnt.discovery.DiscoveryScanner``: the hosts of the site the fake PC is at."""

    def __init__(self, world: World) -> None:
        self.world = world

    def default_cidr(self) -> str:
        return SUBNET

    def parse_range(self, text: str) -> str:
        return text

    def stop(self) -> None:
        pass

    def scan(self, range_text: str, ports: Any = None, progress: Any = None, cancel: Any = None) -> Any:
        with self.world.lock:
            site = self.world.site or "A"
        hosts = [{"ip": ip, "hostname": None, "mac": mac, "vendor": None, "ping_ok": True, "rtt_ms": 1.0, "open_ports": list(open_ports),
                  "device_type": kind} for ip, mac, kind, open_ports in SITES[site]["hosts"]]
        result = {"ts": time.time(), "cidr": range_text, "ports": list(ports or []), "method": "native", "hosts": hosts, "scanned": 254,
                  "duration_s": 12.0, "ok": True, "error": None, "cancelled": False}
        return SimpleNamespace(to_dict=lambda: dict(result))


# --------------------------------------------------------------------------- helpers
def until(fn: Callable[[], Any], what: str, timeout: float = WAIT_S) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = fn()
        if value:
            return value
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}; last value {value!r}")
        time.sleep(0.02)


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
    """A structurally sound PDF (header, trailer, a cross-reference table whose every offset points at its object, a page tree
    whose count matches its pages); returns the page count."""
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
    return pages


def rows(db: tnt_db.Database, sql: str, *params: Any) -> List[tuple]:
    return [tuple(r) for r in db._conn.execute(sql, params).fetchall()]


def marker(db: tnt_db.Database) -> Dict[str, Any]:
    return reports.parse_marker(db.get_meta(reports.NET_JOINED_META_KEY)) or {}


def marker_threads_done() -> bool:
    return not any(t.name == "tnt-reports-net" and t.is_alive() for t in threading.enumerate())


def seed_legacy(db: tnt_db.Database, gateway_id: int) -> int:
    """What an earlier release left, untagged: minutes of the gateway and of an internet target disabled since (60 before the
    marker's join time, 60 after it), an outage before the join, a network outage of the disabled target only after it, a speed
    test on each side of it, and the marker itself.  Returns the disabled target's id."""
    old = int(db.add_target(OLD_INTERNET, None, kind="internet")["id"])
    db.set_target_enabled(old, False)
    for i in range(60):
        before, after = U - 190 * M + i * M, J0 + i * M
        db.upsert_ping_minute(gateway_id, int(before), 6, 6, 99.0, 98.0, 100.0, 0.5)
        db.upsert_ping_minute(old, int(before), 6, 6, 120.0, 119.0, 121.0, 0.5)
        db.upsert_ping_minute(gateway_id, int(after), 6, 6, 30.0, 29.0, 31.0, 0.5)
        db.upsert_ping_minute(old, int(after), 6, 6, 40.0, 39.0, 41.0, 0.5)
    db.close_outage(db.open_outage("total_local", None, U - 150 * M), U - 145 * M, 0)
    db.close_outage(db.open_outage("total_internet", None, U - 50 * M), U - 45 * M, 0)
    db.close_outage(db.open_outage("target", old, U - 50 * M - 1, host=OLD_INTERNET), U - 45 * M + 1, 30, sent=30)
    for ts, down in ((U - 160 * M, 300.0), (U - 40 * M, 60.0)):
        db.add_speedtest({"ts": ts, "ok": True, "backend": "fake", "server": "Example Colo", "download_mbps": down, "upload_mbps": 20.0,
                          "latency_ms": 12.0, "jitter_ms": 1.0, "packet_loss_pct": 0.0, "duration_s": 9.0})
    db.set_meta(reports.NET_JOINED_META_KEY, json.dumps({"ts": J0, "gateway": GATEWAY, "networks": [SUBNET], "nic": "Ethernet",
                                                         "gateway_mac": MAC_A, "mac_ts": J0, "seen_ts": U - 10 * M}))
    return old


# --------------------------------------------------------------------------- the service
@pytest.fixture
def service(data_dir, monkeypatch):
    """The real pieces on fake edges (see the module docstring), wired the way ``Engine.start`` wires them."""
    from tnt.engine import Engine
    from tnt.outages import OutageTracker
    from tnt.pinger import PingManager

    world = World()
    clock = Clock(U)
    backend = FakeBackend()
    monkeypatch.setattr(sched_mod, "select_backend", lambda config: backend)
    monkeypatch.setattr(pinger_mod, "classify_ip", pinger_mod._fallback_classify)     # never this PC's adapters
    monkeypatch.setattr(arp, "get_arp_table", world.arp_table)
    monkeypatch.setattr(arp, "neighbour", world.neighbour)
    monkeypatch.setattr(Engine, "NET_EVENT_ROW_GAP_S", 0.0)
    (data_dir / "config.json").write_text(json.dumps(CONFIG), encoding="utf-8")

    cfg = tnt_config.Config(data_dir / "config.json").load()
    db = tnt_db.Database(data_dir / "tnt.db")
    bus = tnt_events.EventBus()
    eng = Engine(console=True, port=0, data_dir=data_dir)
    eng.config, eng.db, eng.bus = cfg, db, bus
    eng.netinfo_summary = world.summary
    parts: Dict[str, Any] = {}
    try:
        pm = parts["ping"] = PingManager(db, cfg, bus, pinger=world, raw_log=None, clock=clock, sleep=lambda s: None,
                                         resolver=lambda host: host, network_fn=eng._network_id)
        eng.ping = pm
        gw = int(pm.add_target(GATEWAY, "Gateway")["id"])
        inet = int(pm.add_target(INTERNET)["id"])
        old = seed_legacy(db, gw)
        tracker = parts["networks"] = networks.NetworkTracker(db, clock=clock, facts_fn=world.facts, neighbour_fn=world.neighbour,
                                                              mac_wait_s=30.0, mac_poll_s=0.02, confirm_s=0.1, touch_every_s=0.0)
        tracker.start()
        eng.networks = tracker
        ot = parts["outages"] = OutageTracker(db, cfg, bus, pm, clock=clock, network_fn=eng._network_id)
        ot.start()
        eng.outages = ot
        eng._listen_to_networks(ot.on_network_id_change)
        eng.speed = parts["speed"] = sched_mod.SpeedScheduler(db, cfg, bus, clock=clock, network_fn=eng._network_id)
        eng.discovery = FakeScanner(world)
        mgr = parts["reports"] = reports.ReportManager(db, cfg, bus, eng, clock=clock, netinfo_fn=world.snapshot,
                                                       network_fn=world.marker_network, hostname_fn=lambda: "BENCH-01",
                                                       wifi_wait_s=WAIT_S, discovery_wait_s=10.0, mac_wait_s=0.3)
        eng.reports = mgr
        eng._listen_to_networks(mgr.on_network_id_change)
        mgr.start()
        server = parts["api"] = ApiServer(eng, "127.0.0.1", 0, bus=bus, ui_dir=data_dir)
        server.start()
        eng.api = server
        yield SimpleNamespace(eng=eng, db=db, port=server.port, world=world, clock=clock, backend=backend, pm=pm, tracker=tracker,
                              mgr=mgr, gw=gw, inet=inet, old=old, next_tick=U + 5)
    finally:
        backend.gate.set()
        if "reports" in parts:
            parts["reports"].stop()
            if parts["reports"]._thread is not None:
                parts["reports"]._thread.join(5.0)
        if eng._disc_thread is not None:
            eng._disc_thread.join(5.0)
        for name in ("speed", "outages", "networks", "ping", "api"):
            if name in parts:
                parts[name].stop()
        eng._flush_net_rows()
        db.close()


def ping_until(svc: SimpleNamespace, last: float) -> None:
    """Tick both targets every STEP_S of the fake clock, up to *last* (inclusive)."""
    while svc.next_tick <= last:
        svc.clock.t = svc.next_tick
        for tid in (svc.gw, svc.inet):
            svc.pm.tick(tid)
        svc.next_tick += STEP_S


def silent(svc: SimpleNamespace, ip: str, first: float, last: float) -> None:
    """*ip* misses every echo from the tick at *first* to the one at *last*."""
    ping_until(svc, first - STEP_S)
    with svc.world.lock:
        svc.world.silent.add(ip)
    ping_until(svc, last)
    with svc.world.lock:
        svc.world.silent.discard(ip)


def move(svc: SimpleNamespace, site: Optional[str], ts: float, router: Optional[Tuple[str, str]] = None) -> None:
    """The PC leaves its network (*site* None) or joins *site* at *ts*, with the router's neighbour entry *router* or none yet."""
    previous = svc.world.site
    svc.clock.t = ts
    with svc.world.lock:
        svc.world.site = site
        svc.world.neigh = {GATEWAY: router} if router else {}
    svc.eng._on_net_changed(svc.world.net_changed(ts, previous))
    until(lambda: marker(svc.db).get("seen_ts") == ts, f"the network marker to see the move at {ts}")
    until(marker_threads_done, "the report manager's network check")


def speed_test(svc: SimpleNamespace) -> None:
    assert svc.eng.speed.run_now()
    until(lambda: not svc.eng.speed.running, "the speed test")


def job_when(port: int, pred: Callable[[Dict[str, Any]], bool], what: str) -> Dict[str, Any]:
    return until(lambda: (lambda j: j if j is not None and pred(j) else None)(ok(port, "GET", "/api/reports/scan")["job"]), what)


def post_wifi(svc: SimpleNamespace, job_id: str) -> None:
    """Post the Wi-Fi snapshot once the job waits for it (a TNT window reacting to the job's phase)."""
    job_when(svc.port, lambda j: j["id"] == job_id and j["phase"] == "wifi", "the Wi-Fi phase")
    ssid = SITES[svc.world.site]["ssid"]
    body = {"available": True, "state": "ok", "error": None, "collected_ts": svc.clock.t,
            "interfaces": [{"guid": "{7E57AB1E-0000-4000-8000-0000000000A7}", "description": "Example Wi-Fi 6E Adapter",
                            "state": "connected", "connected_bssid": "02:00:5E:20:00:01", "connected_ssid": ssid}],
            "aps": [{"bssid": "02:00:5E:20:00:01", "ssid": ssid, "hidden": False, "rssi": -50, "band": "5", "channel": 36, "width_mhz": 80,
                     "generation": "Wi-Fi 6", "security": "WPA3-Personal", "connected": True},
                    {"bssid": "02:00:5E:20:00:02", "ssid": ssid, "hidden": False, "rssi": -63, "band": "2.4", "channel": 6, "width_mhz": 20,
                     "generation": "Wi-Fi 6", "security": "WPA3-Personal", "connected": False}]}
    ok(svc.port, "POST", "/api/reports/scan/wifi", body)


def finished(svc: SimpleNamespace, job_id: str) -> Dict[str, Any]:
    return job_when(svc.port, lambda j: j["id"] == job_id and j["status"] != "running", "the scan to finish")


def numbers(ping: Dict[str, Any]) -> Dict[str, Tuple[int, int, float]]:
    """``{host: (samples, lost, average)}`` of a ping section."""
    return {t["host"]: (t["samples"], t["lost"], t["avg_ms"]) for t in ping["targets"]}


# --------------------------------------------------------------------------- the test
def test_site_reports_count_only_the_data_of_their_own_network(service):
    svc = service
    db, port, tracker = svc.db, svc.port, svc.tracker
    until(lambda: marker(db).get("seen_ts") == U and marker_threads_done(), "the report manager's start-up network check")
    assert marker(db)["ts"] == J0 and svc.mgr.joined_ts() == J0, "the same network as the marker: the join time stands"
    assert db.networks_ready
    a = tracker.current_network_id()
    assert (db.get_network(a)["mac"], db.get_network(a)["dhcp_server"]) == (MAC_A, GATEWAY)
    current = ok(port, "GET", "/api/networks/current")["network"]
    assert (current["id"], current["mac"], current["identity"], current["last_report"]) == (a, MAC_A, "mac", None)

    # ---- site A, visit 1: an internet outage, a speed test, Full Scan 1 (named while it runs)
    silent(svc, INTERNET, U + 20 * M + 5, U + 24 * M + 55)
    ping_until(svc, U + 30 * M + 5)
    speed_test(svc)
    ping_until(svc, S1)
    job1 = ok(port, "POST", "/api/reports/scan", {})["job"]
    assert (job1["network_id"], job1["suggested_site"], job1["window_reason"]) == (a, None, "site_network")
    assert ok(port, "PATCH", "/api/reports/scan", {"site": "Acme Dental"})["job"]["site"] == "Acme Dental"
    post_wifi(svc, job1["id"])
    done1 = finished(svc, job1["id"])
    assert (done1["status"], done1["site"], done1["message"]) == ("saved", "Acme Dental", "Saved the report for Acme Dental")
    r1 = done1["report_id"]

    # ---- travelling: no network, every echo missed, still tagged with A
    ping_until(svc, LEAVE_A - 5)
    move(svc, None, LEAVE_A)
    assert tracker.current_network_id() == a and tracker.offline
    ping_until(svc, AT_B - STEP_S)

    # ---- site B: another router behind the same gateway address and subnet
    move(svc, "B", AT_B, router=(MAC_B, "reachable"))
    b = tracker.current_network_id()
    row_b = db.get_network(b)
    assert b != a and (row_b["mac"], row_b["gateway_ip"], row_b["subnet"], row_b["dhcp_server"]) == (MAC_B, GATEWAY, SUBNET, "192.168.1.10")
    until(lambda: marker(db).get("gateway_mac") == MAC_B, "B's router in the marker")
    ping_until(svc, U + 150 * M + 5)
    speed_test(svc)
    silent(svc, GATEWAY, U + 170 * M + 5, U + 172 * M + 55)
    ping_until(svc, S2)
    job2 = ok(port, "POST", "/api/reports/scan", {"site": "Harbor View"})["job"]
    assert (job2["network_id"], job2["suggested_site"], job2["site"]) == (b, None, "Harbor View"), "nothing was scanned on B before"
    post_wifi(svc, job2["id"])
    done2 = finished(svc, job2["id"])
    assert (done2["status"], done2["site"]) == ("saved", "Harbor View")
    r2 = done2["report_id"]

    # ---- travelling again (tagged with B), then back at A before its router's MAC is in the neighbour table
    ping_until(svc, LEAVE_B - 5)
    move(svc, None, LEAVE_B)
    ping_until(svc, BACK - 5)
    move(svc, "A", BACK)
    p = tracker.current_network_id()
    provisional = db.get_network(p)
    assert p not in (a, b) and provisional["mac"] is None
    assert provisional["fingerprint"] == networks.fingerprint(GATEWAY, SUBNET, GATEWAY), "known by gateway, subnet and DHCP server"
    silent(svc, GATEWAY, BACK + 65, BACK + 175)
    ping_until(svc, S3)

    # ---- Full Scan 3, unnamed, starts on the provisional network; the router's MAC arrives while its speed test runs
    svc.backend.gate.clear()
    job3 = ok(port, "POST", "/api/reports/scan", {})["job"]
    assert (job3["network_id"], job3["suggested_site"], job3["site"], job3["window_reason"]) == (p, None, None, "site_network")
    current = ok(port, "GET", "/api/networks/current")["network"]
    assert (current["id"], current["mac"], current["vendor"], current["identity"], current["last_report"]) == (p, None, None, "fingerprint", None)
    until(lambda: svc.backend.calls >= 5, "the scan's own speed test to start (tagged with the provisional network)")
    with svc.world.lock:
        svc.world.neigh[GATEWAY] = (MAC_A, "reachable")
    assert tracker.wait_idle(WAIT_S) and tracker.current_network_id() == a
    followed = job_when(port, lambda j: j["id"] == job3["id"] and j["network_id"] == a and j["suggested_site"], "the job to follow the merge")
    assert followed["suggested_site"] == {"site": "Acme Dental", "report_id": r1, "created_ts": S1}
    assert followed["site"] is None and followed["status"] == "running"
    svc.backend.gate.set()
    post_wifi(svc, job3["id"])
    done3 = finished(svc, job3["id"])
    assert (done3["status"], done3["site"], done3["message"]) == (
        "saved", "Acme Dental", "Saved the report for Acme Dental, the site this network was scanned as before")
    assert done3["suggested_site"]["report_id"] == r1
    r3 = done3["report_id"]

    # ---- what was stored: every row tagged with the network it was collected on, the provisional id merged away
    assert sorted((n["id"], n["mac"]) for n in db.list_networks()) == [(a, MAC_A), (b, MAC_B)] and db.get_network(p) is None
    for table in ("ping_minutes", "outages", "speedtests", "discovery_runs", "reports"):
        assert rows(db, f"SELECT COUNT(*) FROM {table} WHERE network_id=?", p) == [(0,)], table
    assert rows(db, "SELECT network_id, start_ts, end_ts, next_network_id FROM network_offline ORDER BY start_ts") == [
        (a, LEAVE_A, AT_B, b), (b, LEAVE_B, BACK, a)], "two trips, the second one ending on A once the MAC was read"
    # the minute B was reached in is two rows: the misses of the trip (A's) and B's answers
    assert rows(db, "SELECT network_id, sent, received FROM ping_minutes WHERE target_id=? AND minute_ts=? ORDER BY network_id",
                svc.gw, int(U + 140 * M)) == [(a, 2, 0), (b, 4, 4)]
    assert rows(db, "SELECT COUNT(*) FROM ping_minutes WHERE network_id=? AND minute_ts>=? AND minute_ts<?", a, int(BACK), int(BACK + 4 * M)) == \
        [(8,)], "the provisional minutes moved to A"
    assert rows(db, "SELECT network_id, download_mbps FROM speedtests ORDER BY ts, id") == [
        (None, 300.0), (None, 60.0), (a, 80.0), (a, 94.2), (b, 900.0), (b, 850.0), (a, 120.0)]
    assert [r[0] for r in rows(db, "SELECT network_id FROM discovery_runs ORDER BY id")] == [a, b, a]
    assert rows(db, "SELECT id, network_id FROM reports ORDER BY id") == [(r1, a), (r2, b), (r3, a)]
    # the outages of the trips closed when the next network was identified
    trip1 = rows(db, "SELECT kind, network_id, end_ts, note FROM outages WHERE start_ts>=? AND start_ts<? ORDER BY kind, target_id", LEAVE_A, AT_B)
    assert sorted(trip1) == sorted([(k, a, AT_B, "network changed") for k in ("target", "target", "total_internet", "total_local")])
    trip2 = rows(db, "SELECT kind, network_id, end_ts, note FROM outages WHERE start_ts>=? AND start_ts<? ORDER BY kind, target_id", LEAVE_B, BACK)
    assert sorted(trip2) == sorted([(k, b, BACK, "network changed") for k in ("target", "target", "total_internet", "total_local")])

    rep1, rep2, rep3 = (ok(port, "GET", f"/api/reports/{rid}") for rid in (r1, r2, r3))
    for rep in (rep1, rep2, rep3):
        assert set(rep) == ROW_KEYS | {"data"} and rep["summary"] == reports.build_summary(rep["data"])
        history = next(ph for ph in rep["data"]["meta"]["scan_phases"] if ph["key"] == "history")
        assert history["message"].startswith("Pings and outages on this network over the last 7 days"), history
    view_a = {"id": a, "mac": MAC_A, "vendor": networks.router_vendor(MAC_A), "gateway_ip": GATEWAY, "subnet": SUBNET, "dhcp_server": GATEWAY,
              "identity": "mac", "virtual_mac": None, "portable": False}

    # ---- report 1 (A, visit 1): A's minutes and the untagged ones since the old join time (never those before it); the network
    #      outage of the disabled target only is left out and counted
    d1 = rep1["data"]
    assert rep1["network_id"] == a and d1["meta"]["network"] == view_a
    p1 = d1["ping"]
    assert (p1["window_reason"], p1["window_start"], p1["window_end"]) == ("site_network", U - 190 * M, S1)
    assert numbers(p1) == {GATEWAY: (720, 0, 15.5), INTERNET: (360, 30, 20.0)}
    assert p1["note"] == "Left out: 1 removed or disabled target"
    assert p1["visits"] == [{"start": J0, "end": U + 60 * M}] and p1["monitored_s"] == 130 * M
    o1 = d1["outages"]
    assert (o1["count"], o1["network_outages"], o1["target_outages"], o1["network_down_s"]) == (1, 1, 0, 300.0)
    assert o1["by_kind"] == {"target": 1, "total_local": 0, "total_internet": 1, "gap": 0} and o1["monitored_s"] == 130 * M
    assert o1["note"] == "Left out: 1 removed or disabled target (1 network outage)"
    assert [(i["kind"], i["start_ts"], i["end_ts"]) for i in o1["items"]] == [("total_internet", U + 20 * M + 5, U + 25 * M + 5)]
    w1 = d1["speed"]["window"]
    assert (w1["count"], w1["download_min"], w1["download_max"]) == (3, 60.0, 94.2), "the untagged test after the join counts"
    assert rep1["summary"]["window_hours"] == round(130 * M / 3600.0, 1)

    # ---- report 2 (B): only B's minutes, outage and speed tests; nothing of A, of the trip there or from before this release
    d2 = rep2["data"]
    assert rep2["network_id"] == b and d2["meta"]["network"] == dict(view_a, id=b, mac=MAC_B, vendor=networks.router_vendor(MAC_B),
                                                                       dhcp_server="192.168.1.10")
    p2 = d2["ping"]
    assert (p2["window_reason"], p2["window_end"]) == ("site_network", S2)
    assert numbers(p2) == {GATEWAY: (358, 18, 3.0), INTERNET: (358, 0, 45.0)} and p2["note"] is None
    assert p2["visits"] == [{"start": U + 140 * M, "end": U + 200 * M}] and p2["monitored_s"] == 60 * M
    o2 = d2["outages"]
    assert (o2["count"], o2["network_outages"], o2["target_outages"], o2["network_down_s"], o2["note"]) == (1, 1, 0, 180.0, None)
    assert [(i["kind"], i["start_ts"], i["end_ts"]) for i in o2["items"]] == [("total_local", U + 170 * M + 5, U + 173 * M + 5)]
    assert (d2["speed"]["window"]["count"], d2["speed"]["window"]["download_min"], d2["speed"]["window"]["download_max"]) == (2, 850.0, 900.0)
    assert d2["network"]["internet_nic"]["name"] == "Wi-Fi" and d2["discovery"]["host_count"] == 3

    # ---- report 3 (A again): both visits to A (the provisional minutes and outage included), none of B's data, none of either
    #      trip, no untagged data (this PC moved since); saved under the site suggested by report 1
    d3 = rep3["data"]
    assert (rep3["site"], rep3["network_id"], d3["meta"]["site"], d3["meta"]["network"]) == ("Acme Dental", a, "Acme Dental", view_a)
    p3 = d3["ping"]
    assert (p3["window_reason"], p3["window_start"], p3["window_end"]) == ("site_network", U - 190 * M, S3)
    # visit 1 without its last minute (the one before the trip: LEAVE_SLACK_S), and the four minutes back at A
    assert numbers(p3) == {GATEWAY: (123 * 6, 12, 1.0), INTERNET: (123 * 6, 30, 20.0)} and p3["note"] is None
    assert p3["visits"] == [{"start": U, "end": LEAVE_A - M}, {"start": BACK, "end": BACK + 4 * M}] and p3["monitored_s"] == 123 * M
    o3 = d3["outages"]
    assert (o3["count"], o3["network_outages"], o3["target_outages"], o3["network_down_s"], o3["note"]) == (2, 2, 0, 420.0, None)
    assert o3["by_kind"] == {"target": 2, "total_local": 1, "total_internet": 1, "gap": 0} and o3["monitored_s"] == 123 * M
    assert [(i["kind"], i["start_ts"], i["end_ts"]) for i in o3["items"]] == [
        ("total_local", BACK + 65, BACK + 185), ("total_internet", U + 20 * M + 5, U + 25 * M + 5)]
    w3 = d3["speed"]["window"]
    assert (w3["count"], w3["download_min"], w3["download_max"]) == (3, 80.0, 120.0), "A's tests: never B's 900 or the untagged ones"
    assert d3["speed"]["result"]["download_mbps"] == 120.0
    assert rep3["summary"]["window_hours"] == round(123 * M / 3600.0, 1) and rep3["summary"]["outages"] == 2

    # ---- the API: lists, sites and the current network carry the network
    listed = ok(port, "GET", "/api/reports")["reports"]
    assert [(r["id"], r["network_id"]) for r in listed] == [(r3, a), (r2, b), (r1, a)] and all(set(r) == ROW_KEYS for r in listed)
    sites = {s["site"]: s["network_ids"] for s in ok(port, "GET", "/api/reports/sites")["sites"]}
    assert sites == {"Acme Dental": [a], "Harbor View": [b]}
    current = ok(port, "GET", "/api/networks/current")["network"]
    assert (current["id"], current["mac"], current["identity"], current["gateway_ip"], current["subnet"]) == (a, MAC_A, "mac", GATEWAY, SUBNET)
    assert current["last_report"] == {"id": r3, "site": "Acme Dental", "created_ts": S3}

    # ---- comparisons: the same network twice, and A against B
    same = ok(port, "GET", f"/api/reports/compare?a={r3}&b={r1}")
    assert same == reports.compare_reports(rep3, rep1)
    # each side's time on its network once, then that both were scanned on one network
    assert same["notes"] == ["On their networks: A 2h 03m over 2 visits; B 2h 10m over 1 visit", f"A and B were scanned on the same network (router {MAC_A})"]
    notes = {s["key"]: s["rows"][0]["note"] for s in same["sections"] if s["rows"]}
    assert notes["ping"] is None, "the windows of both sides are their time on their networks: the comparison's note"
    assert notes["outages"] == "Too little history for daily rates (a day on each side is needed): the counts of each window", \
        "a side of its site's network has its time in the comparison's note only"
    other = ok(port, "GET", f"/api/reports/compare?a={r3}&b={r2}")
    assert other == reports.compare_reports(rep3, rep2) and other["notes"] == [reports.network_time_note(rep3["data"], rep2["data"])]
    assert other["notes"][0].startswith("On their networks: A 2h 03m over 2 visits; B ")

    # ---- both PDFs
    status, headers, pdf = call(port, "GET", f"/api/reports/{r3}/pdf")
    assert status == 200 and headers["content-type"] == "application/pdf" and 1 <= assert_valid_pdf(pdf) <= 3
    text = pdf_text(pdf)
    for needle in (b"Site report: Acme Dental", b"Router", MAC_A.encode(), b"this site's network only: 2 visits, 2 h 03 min monitored"):
        assert needle in text, needle
    status, headers, pdf = call(port, "GET", f"/api/reports/{r2}/pdf")
    assert status == 200 and 1 <= assert_valid_pdf(pdf) <= 3 and MAC_B.encode() in pdf_text(pdf)
    status, headers, pdf = call(port, "GET", f"/api/reports/compare/pdf?a={r3}&b={r1}")
    assert status == 200 and headers["content-type"] == "application/pdf" and 1 <= assert_valid_pdf(pdf) <= 2
    assert b"A and B were scanned on the same network" in pdf_text(pdf)
