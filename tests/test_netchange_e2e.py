"""End to end: the real service follows this PC from one network to the next (the field report).

TNT kept running on a laptop carried to another building; Windows applied a new address, gateway and DNS servers
and TNT showed none of it.  Here the real :class:`tnt.engine.Engine` (config, database, event bus, PingManager,
LinkMap, OutageTracker, DiscoveryScanner, DhcpServer, LanPeers, NetWatcher and the HTTP API with its SSE stream)
runs in a temporary data directory on an ephemeral loopback port.  Only the edges are fakes:

* ``GetAdaptersAddresses`` and the route lookup (``tnt.netinfo._query_adapters`` / ``_route_source_ip``);
* ICMP (``tnt.icmp.IcmpPinger``), DNS (``tnt.icmp.resolve``), the public-address lookup
  (``tnt.linkmap._fetch_public_ip``), the LAN beacon / throughput sockets and discovery's local-address guess.

A client reads ``GET /api/events`` over HTTP while the fake adapters move from network A to network B (through a
cable-out and DHCP sequence), to a static address without a gateway, to a gateway typed into the wrong subnet and to
a self-assigned address.  Every move must give exactly one ``net.changed`` with the right flags within the 10 s
budget, and the API, the Gateway tile, Load Default Tiles, the link map, LAN peers, the Discovery default range, the
adapter warnings, the outage history and the events table must all describe the new network.

Timing is deterministic without sitting through the real debounce: the watcher is the real class whose monotonic
clock seam advances, before each adapter read, by exactly the delay its own loop would have slept (``network.poll_s``
normally, 1 s while a change settles), while its thread reads every 50 ms of real time.  The budget is measured in
that clock, from the watcher's last read before Windows applied a change (the worst case) to the publication.
Addresses come from the private and documentation ranges, GUIDs are invented and MACs locally administered; no packet
leaves the machine.
"""
from __future__ import annotations

import copy
import http.client
import json
import socket
import threading
import time
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import pytest

from tnt import discovery, icmp, lanpeers, linkmap, netinfo, netwatch
from tnt.icmp import PingResult

WATCH_REAL_POLL_S = 0.05    # real seconds between the watcher thread's adapter reads
BUDGET_S = 10.0             # contract: a change Windows applied reaches the event stream within this (watcher seconds)
WAIT_S = 15.0               # real-time ceiling for anything asynchronous (normally well under a second)
QUIET_READS = 15            # watcher reads (15 s of watcher time at least) after an event that must bring no second one

#: the test service's settings: no speed test, a faster ping schedule so outages open and close quickly
CONFIG = {"speedtest": {"enabled": False}, "ping": {"interval_s": 0.5}, "outage": {"miss_threshold": 2, "recover_threshold": 2}}
#: tnt.diagnostics._network (tests/test_ui.py holds the mock to the same keys)
NETWORK_DIAG_KEYS = {"generation", "changed_ts", "default_gateway", "internet_nic", "summary", "networks", "running", "polls",
                     "failures", "last_error", "pending", "poll_s", "available", "last_change"}
NO_GATEWAY = "this machine has no default gateway right now"

ETH_GUID = "{7E57AB1E-0000-4000-8000-0000000000E1}"
WIFI_GUID = "{7E57AB1E-0000-4000-8000-0000000000A7}"
SWITCH_GUID = "{7E57AB1E-0000-4000-8000-00000000005C}"
ETH_MAC, WIFI_MAC, SWITCH_MAC = "02:00:5E:77:00:0C", "02:00:5E:77:00:07", "02:00:5E:77:00:1E"


# --------------------------------------------------------------------------- what Windows and the world look like
def v4(address: str, prefix: int, origin: int = 3) -> netinfo.IpAddr:
    return netinfo._make_ipaddr(address, 4, prefix, netinfo.IP_DAD_STATE_PREFERRED, 0, origin, origin)


def ethernet(status: str = "up", ipv4: Sequence[netinfo.IpAddr] = (), gateways: Sequence[str] = (), dns: Sequence[str] = (),
             dhcp: bool = True, dhcp_server: Optional[str] = None, suffix: str = "") -> netinfo.Adapter:
    return netinfo.Adapter(index=12, name="Ethernet", description="Example 2.5GbE Ethernet adapter", mac=ETH_MAC, if_type=6,
                           type_name="Ethernet", status=status, speed_bps=2_500_000_000 if status == "up" else None, mtu=1500,
                           dhcp_enabled=dhcp, dhcp_server=dhcp_server, dns_suffix=suffix, ipv4=list(ipv4),
                           gateways=list(gateways), dns=list(dns), metric_v4=25, is_physical=True, guid=ETH_GUID, luid=1012)


def other_adapters() -> List[netinfo.Adapter]:
    """Wi-Fi switched off, and a host-side virtual switch that stays up on every network (it must never be taken for
    the connection, the scan range or the gateway)."""
    wifi = netinfo.Adapter(index=7, name="Wi-Fi", description="Example Wi-Fi 6E adapter", mac=WIFI_MAC, if_type=71,
                           type_name="Wi-Fi", status="down", speed_bps=None, mtu=1500, dhcp_enabled=True, dhcp_server=None,
                           dns_suffix="", metric_v4=35, is_physical=True, guid=WIFI_GUID, luid=1007)
    vswitch = netinfo.Adapter(index=30, name="vEthernet (Example Switch)", description="Example Virtual Ethernet Adapter",
                              mac=SWITCH_MAC, if_type=6, type_name="Ethernet", status="up", speed_bps=10_000_000_000, mtu=1500,
                              dhcp_enabled=False, dhcp_server=None, dns_suffix="", ipv4=[v4("172.29.64.1", 20, origin=1)],
                              metric_v4=15, is_physical=False, guid=SWITCH_GUID, luid=1030)
    return [wifi, vswitch]


def network(name: str) -> Dict[str, Any]:
    """One network: the Ethernet adapter as Windows reports it there, the source address of the default route (None:
    no default route), the router's public address, DNS answers and which addresses answer a ping."""
    if name == "A":                     # building A: DHCP
        eth = ethernet(ipv4=[v4("10.20.0.50", 24)], gateways=["10.20.0.1"], dns=["10.20.0.1"], dhcp_server="10.20.0.1",
                       suffix="site-a.example")
        return dict(name=name, eth=eth, route="10.20.0.50", public="203.0.113.50",
                    names={"totalelectronics.com": "203.0.113.10"}, answering={"10.20.0.1", "1.1.1.1", "203.0.113.10"})
    if name == "B":                     # building B: another DHCP network behind the same wall port
        eth = ethernet(ipv4=[v4("192.168.77.23", 24)], gateways=["192.168.77.1"], dns=["192.168.77.1"],
                       dhcp_server="192.168.77.1", suffix="site-b.example")
        return dict(name=name, eth=eth, route="192.168.77.23", public="198.51.100.77",
                    names={"totalelectronics.com": "198.51.100.10"}, answering={"192.168.77.1", "1.1.1.1", "198.51.100.10"})
    if name == "static":                # a bench address typed in, no gateway: no default route at all
        eth = ethernet(ipv4=[v4("172.16.20.15", 24, origin=1)], dhcp=False)
        return dict(name=name, eth=eth, route=None, public=None, names={}, answering={"172.16.20.1"})
    if name == "static-bad-gateway":    # the same address with the gateway typed into the wrong subnet
        eth = ethernet(ipv4=[v4("172.16.20.15", 24, origin=1)], gateways=["172.16.21.1"], dhcp=False)
        return dict(name=name, eth=eth, route="172.16.20.15", public=None, names={}, answering=set())
    if name == "apipa":                 # DHCP on a network where no DHCP server answers
        eth = ethernet(ipv4=[v4("169.254.23.45", 16, origin=4)])
        return dict(name=name, eth=eth, route=None, public=None, names={}, answering=set())
    if name == "unplugged":
        return dict(name=name, eth=ethernet(status="down"), route=None, public=None, names={}, answering=set())
    if name == "no-lease-yet":          # cable in, DHCP still asking: Windows reports the adapter up without an address
        return dict(name=name, eth=ethernet(), route=None, public=None, names={}, answering=set())
    raise ValueError(name)


class FakeWindows:
    """What Windows reports and what the world answers.

    ``move(name, via)`` applies a new configuration, optionally through intermediate states (a cable pulled, a DHCP
    exchange).  Every component reads the current state through ``query``/``route``; the watcher's own read
    (``watcher_read``) shows each intermediate state to exactly one watcher read before moving on, so a sequence is
    reproducible however the threads are scheduled.
    """

    def __init__(self, name: str) -> None:
        self.cond = threading.Condition()
        self.current = network(name)
        self.steps: List[Dict[str, Any]] = []
        self.advance = False
        self.reads = 0
        self.silent: set = set()                    # addresses that stop answering pings
        self.wan_lookups: List[Tuple[float, str]] = []
        self.pings: List[Tuple[float, str]] = []
        self.beacons: List[Tuple[float, str, str]] = []     # (monotonic, bound address, destination)
        self.watcher: Any = None

    def adapters(self) -> List[netinfo.Adapter]:
        return [copy.deepcopy(self.current["eth"])] + other_adapters()

    def move(self, name: str, via: Sequence[str] = ()) -> float:
        """Apply a configuration; returns the watcher's clock at its last read before it (the budget's start)."""
        with self.cond:
            steps = [network(n) for n in via] + [network(name)]
            self.current = steps.pop(0)
            self.steps = steps
            self.advance = False
            return float(self.watcher.virtual)

    def watcher_read(self) -> List[netinfo.Adapter]:
        with self.cond:
            if self.advance and self.steps:
                self.current = self.steps.pop(0)
            self.advance = True
            self.reads += 1
            self.cond.notify_all()
            return self.adapters()

    def wait_reads(self, n: int) -> None:
        deadline = time.monotonic() + WAIT_S
        with self.cond:
            while self.reads < n:
                left = deadline - time.monotonic()
                assert left > 0, f"the watcher read the adapters {self.reads} times, expected {n}"
                self.cond.wait(left)

    def query(self) -> List[netinfo.Adapter]:
        with self.cond:
            return self.adapters()

    def route(self, probe: Tuple[str, int] = ("1.1.1.1", 53)) -> Optional[str]:
        with self.cond:
            return self.current["route"]

    def resolve(self, host: str, prefer_ipv4: bool = True, timeout_s: float = 3.0) -> Optional[str]:
        try:
            socket.inet_aton(str(host))
            return str(host)
        except OSError:
            with self.cond:
                return self.current["names"].get(str(host).lower())

    def public_ip(self, timeout_s: float = 8.0) -> str:
        with self.cond:
            self.wan_lookups.append((time.monotonic(), self.current["name"]))
            ip = self.current["public"]
        if not ip:
            raise OSError("no route to host")
        return ip

    def answers(self, ip: str) -> bool:
        with self.cond:
            self.pings.append((time.monotonic(), ip))
            return ip in self.current["answering"] and ip not in self.silent


class FakeIcmp:
    """``tnt.icmp.IcmpPinger``: an echo is answered when the current network has that address (instantly either way)."""

    def __init__(self, win: FakeWindows) -> None:
        self.win = win

    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> PingResult:
        ok = self.win.answers(str(ip))
        return PingResult(ok=ok, rtt_ms=0.8 if ok else None, status=0 if ok else 11010, error=None if ok else "timed out",
                          ttl=64, size=size, ip=str(ip))

    def close(self) -> None:
        pass


class FakeSocket:
    """The LAN peers' UDP beacon and TCP throughput sockets: binds and sends are recorded, receives time out."""

    def __init__(self, win: FakeWindows) -> None:
        self.win, self.bound, self.timeout, self.closed = win, ("0.0.0.0", 0), 0.2, False

    def setsockopt(self, *args: Any) -> None:
        pass

    def settimeout(self, timeout: Optional[float]) -> None:
        self.timeout = timeout

    def bind(self, address: Tuple[str, int]) -> None:
        self.bound = (str(address[0]), int(address[1] or 0))

    def listen(self, backlog: int) -> None:
        pass

    def getsockname(self) -> Tuple[str, int]:
        return self.bound

    def sendto(self, data: bytes, destination: Tuple[str, int]) -> int:
        with self.win.cond:
            self.win.beacons.append((time.monotonic(), self.bound[0], str(destination[0])))
        return len(data)

    def _idle(self) -> None:
        if self.closed:
            raise OSError("socket closed")
        time.sleep(min(self.timeout or 0.2, 0.2))
        raise socket.timeout("timed out")

    def recvfrom(self, size: int) -> Tuple[bytes, Tuple[str, int]]:
        self._idle()
        raise AssertionError("unreachable")

    def accept(self) -> Tuple[Any, Tuple[str, int]]:
        self._idle()
        raise AssertionError("unreachable")

    def close(self) -> None:
        self.closed = True


class EventStream:
    """``GET /api/events`` read on a thread: every frame as ``(type, data)``."""

    def __init__(self, port: int) -> None:
        self.frames: List[Tuple[str, Dict[str, Any]]] = []
        self.cond = threading.Condition()
        self.conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
        self.thread = threading.Thread(target=self._read, name="test-sse", daemon=True)
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

    def since(self, mark: int, kind: str) -> List[Dict[str, Any]]:
        with self.cond:
            return [d for t, d in self.frames[mark:] if t == kind]

    def mark(self) -> int:
        with self.cond:
            return len(self.frames)

    def close(self) -> None:
        try:
            self.conn.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- helpers
def until(fn: Callable[[], Any], what: str, timeout: float = WAIT_S) -> Any:
    """``fn()`` once it is truthy (polled every 50 ms); fails with the last value after *timeout*."""
    deadline = time.monotonic() + timeout
    while True:
        value = fn()
        if value:
            return value
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}; last value {value!r}")
        time.sleep(0.05)


def call(port: int, method: str, path: str, body: Any = None) -> Any:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    try:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        conn.request(method, path, body=data, headers={"Content-Type": "application/json"} if data is not None else {})
        resp = conn.getresponse()
        payload = resp.read()
        assert resp.status == 200, (method, path, resp.status, payload[:500])
        return json.loads(payload)
    finally:
        conn.close()


@pytest.fixture
def world(data_dir, monkeypatch):
    """The real Engine on fake adapters (network A at start), its API on an ephemeral port and a live event stream."""
    from tnt.engine import Engine

    win = FakeWindows("A")
    monkeypatch.setattr(netinfo, "_query_adapters", win.query)
    monkeypatch.setattr(netinfo, "_route_source_ip", win.route)
    monkeypatch.setattr(icmp, "IcmpPinger", lambda: FakeIcmp(win))
    monkeypatch.setattr(icmp, "resolve", win.resolve)
    monkeypatch.setattr(linkmap, "_fetch_public_ip", win.public_ip)
    monkeypatch.setattr(discovery, "_local_ipv4_guess", lambda: None)
    # the network tracker never reads this PC's own neighbour table: the fake routers give no MAC (networks by fingerprint)
    monkeypatch.setattr("tnt.arp.neighbour", lambda ip, if_index=None: None)
    real_lan, real_watcher = lanpeers.LanPeers, netwatch.NetWatcher

    class QuietLanPeers(real_lan):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["socket_factory"] = lambda *a, **k: FakeSocket(win)
            super().__init__(*args, **kwargs)

    class SteppedWatcher(real_watcher):
        """The real watcher: its clock advances by the delay its loop would have slept, its thread reads every 50 ms."""

        def __init__(self, config: Any, bus: Any, **kwargs: Any) -> None:
            self.virtual = 1000.0
            super().__init__(config, bus, monotonic=lambda: self.virtual, query=win.watcher_read, **kwargs)

        def poll(self) -> float:
            self.virtual += self._next_delay
            super().poll()
            return WATCH_REAL_POLL_S

    monkeypatch.setattr(lanpeers, "LanPeers", QuietLanPeers)
    monkeypatch.setattr(netwatch, "NetWatcher", SteppedWatcher)
    monkeypatch.setattr(Engine, "NET_EVENT_ROW_GAP_S", 0.0)     # one events row per move: these moves are a second apart
    monkeypatch.setattr(linkmap, "WAN_CHANGE_MIN_GAP_S", 0.5)   # ... and so is every public-address lookup a move asks for
    netinfo._invalidate_cache()
    (data_dir / "config.json").write_text(json.dumps(CONFIG), encoding="utf-8")

    eng = Engine(console=True, port=0, data_dir=data_dir)
    stream: Optional[EventStream] = None
    eng.start()
    try:
        broken = {"db", "config", "api", "icmp", "ping", "linkmap", "outages", "discovery", "dhcp", "lan", "netwatch"} & set(eng.errors)
        assert not broken, eng.errors
        assert isinstance(eng.netwatch, SteppedWatcher) and eng.netwatch.poll_s() == 5.0
        win.watcher = eng.netwatch
        published: List[Tuple[int, float]] = []
        eng.netwatch.add_listener(lambda e: published.append((int(e["generation"]), float(eng.netwatch.virtual))))
        eng.netwatch.poll_soon(0.0)                  # the thread's first sleep would be poll_s of real time
        stream = EventStream(eng.api.port)
        until(lambda: stream.since(0, "hello"), "the event stream's hello")
        yield SimpleNamespace(eng=eng, port=eng.api.port, win=win, stream=stream, published=published, generation=0)
    finally:
        if stream is not None:
            stream.close()
        eng.stop()
        netinfo._invalidate_cache()


def status(w: SimpleNamespace) -> Dict[str, Any]:
    return call(w.port, "GET", "/api/status")


def gateway_target(w: SimpleNamespace) -> Dict[str, Any]:
    return next(t for t in status(w)["targets"] if t["host"] == "gateway")


def ethernet_row(w: SimpleNamespace) -> Dict[str, Any]:
    return next(a for a in call(w.port, "GET", "/api/netinfo")["adapters"] if a["name"] == "Ethernet")


def switch(w: SimpleNamespace, name: str, via: Sequence[str] = ()) -> Tuple[Dict[str, Any], int]:
    """Move to *name*; returns the one ``net.changed`` it caused (and the stream mark before it) once the watcher has
    kept looking for another QUIET_READS reads."""
    gen = w.generation + 1
    mark = w.stream.mark()
    applied = w.win.move(name, via)
    until(lambda: any(g == gen for g, _ in w.published), f"net.changed #{gen} for {name}")
    published_at = next(v for g, v in w.published if g == gen)
    assert published_at - applied <= BUDGET_S, f"{name}: published {published_at - applied:.0f} s after Windows applied it"
    event = until(lambda: next(iter(w.stream.since(mark, "net.changed")), None), f"net.changed #{gen} on the stream")
    w.win.wait_reads(w.win.reads + QUIET_READS)
    time.sleep(0.2)                                     # anything the bus had in hand is on the stream by now
    assert [g for g, _ in w.published] == list(range(1, gen + 1)), f"{name}: exactly one event per move"
    assert [d["generation"] for d in w.stream.since(mark, "net.changed")] == [gen], f"{name}: exactly one event on the stream"
    w.generation = gen
    return event, mark


def assert_pings_stop(w: SimpleNamespace, old_ip: str) -> None:
    """Once the Gateway tile and the link map left *old_ip*, nothing pings it any more."""
    time.sleep(0.3)
    start = time.monotonic()
    time.sleep(1.2)
    with w.win.cond:
        late = [ip for ts, ip in w.win.pings if ts >= start and ip == old_ip]
    assert not late, f"{old_ip} was still pinged {len(late)} time(s) after the move"


def recent_event_messages(w: SimpleNamespace) -> List[str]:
    return [e["message"] for e in call(w.port, "GET", "/api/diagnostics")["recent_events"]]


# --------------------------------------------------------------------------- the test
def test_the_service_follows_this_pc_across_networks(world):
    w = world

    # ---- network A at start: the first-run defaults already ping A's gateway ----------------------------------
    assert status(w)["net"] == {"generation": 0, "changed_ts": None, "default_gateway": "10.20.0.1", "internet_nic": "Ethernet",
                                "summary": "Ethernet: 10.20.0.50/24 · gateway 10.20.0.1", "networks": ["10.20.0.0/24", "172.29.64.0/20"],
                                "network_id": 1}
    assert call(w.port, "GET", "/api/networks/current")["network"]["gateway_ip"] == "10.20.0.1"
    gw = until(lambda: (lambda t: t if t["ip"] == "10.20.0.1" and t["resolved"] else None)(gateway_target(w)), "the gateway tile on A")
    assert gw["kind"] == "local"
    assert until(lambda: next((t for t in status(w)["targets"] if t["host"] == "totalelectronics.com" and t["ip"]), None),
                 "the host name tile")["ip"] == "203.0.113.10"
    ni = call(w.port, "GET", "/api/netinfo")
    assert ni["generation"] == 0 and ni["changed_ts"] is None and ni["default_gateway"] == "10.20.0.1"
    assert all(a["warnings"] == [] for a in ni["adapters"])
    assert call(w.port, "GET", "/api/discovery/status")["default_range"] == "10.20.0.0/24"
    until(lambda: status(w)["map"]["public_ip"]["ip"] == "203.0.113.50", "the public address on A")
    until(lambda: call(w.port, "GET", "/api/tools/lan/peers")["self"]["ip"] == "10.20.0.50", "LAN peers' own address on A")
    # a TNT peer on A's subnet
    w.eng.lan.handle_datagram(lanpeers.encode_beacon("bench-peer-a", "BENCH-A", "1.8.0", 7133, time.time()), ("10.20.0.77", 51000))
    assert [p["adapter"] for p in call(w.port, "GET", "/api/tools/lan/peers")["peers"]] == ["Ethernet"]

    # ---- a cable flap that ends where it started publishes nothing ----------------------------------------------
    w.win.move("A", via=("unplugged",))
    w.win.wait_reads(w.win.reads + QUIET_READS)
    assert w.published == [] and status(w)["net"]["generation"] == 0

    # ---- A -> B: the router of A stops answering (an outage opens), the cable is pulled, plugged in at B, DHCP ----
    w.win.silent.add("10.20.0.1")
    mark = w.stream.mark()
    opened = until(lambda: next((o for o in w.stream.since(mark, "outage.start") if o.get("kind") == "target"), None),
                   "the gateway outage on A")
    assert opened["host"] == "gateway (10.20.0.1)", "the outage names the address that was pinged"
    ev, mark = switch(w, "B", via=("unplugged", "no-lease-yet"))
    assert {k: ev[k] for k in ("default_gateway", "previous_gateway", "gateway_changed", "internet_nic_changed", "subnets_changed",
                               "dns_changed", "summary", "cause")} == {
        "default_gateway": "192.168.77.1", "previous_gateway": "10.20.0.1", "gateway_changed": True, "internet_nic_changed": False,
        "subnets_changed": True, "dns_changed": True, "summary": "Ethernet: 192.168.77.23/24 · gateway 192.168.77.1", "cause": None}
    assert ev["internet_nic"] == {"index": 12, "name": "Ethernet", "ipv4": ["192.168.77.23"], "ipv4_prefixes": ["24"],
                                  "networks": ["192.168.77.0/24"], "dns": ["192.168.77.1"], "dhcp": True}
    assert [(c["adapter"], c["kind"]) for c in ev["changes"]] == [("Ethernet", "ipv4"), ("Ethernet", "gateway"), ("Ethernet", "dns"),
                                                                 ("Ethernet", "dhcp")]
    assert ev["changes"][2]["new"] == {"servers": ["192.168.77.1"], "suffix": "site-b.example"}
    st = status(w)
    assert st["net"] == {"generation": 1, "changed_ts": ev["ts"], "default_gateway": "192.168.77.1", "internet_nic": "Ethernet",
                         "summary": ev["summary"], "networks": ["172.29.64.0/20", "192.168.77.0/24"], "network_id": 2}
    assert (st["netinfo"]["internet_nic"]["ipv4"], st["netinfo"]["internet_nic"]["network"]) == ("192.168.77.23", "192.168.77.0/24")
    ni = call(w.port, "GET", "/api/netinfo")
    assert (ni["generation"], ni["changed_ts"], ni["default_gateway"]) == (1, ev["ts"], "192.168.77.1")
    assert all(a["warnings"] == [] for a in ni["adapters"])
    # the Gateway tile and the host name follow at once; the page hears it through ping.targets
    until(lambda: gateway_target(w)["ip"] == "192.168.77.1", "the gateway tile on B")
    until(lambda: any(t["host"] == "gateway" and t["ip"] == "192.168.77.1" for d in w.stream.since(mark, "ping.targets")
                      for t in d["targets"]), "ping.targets with B's gateway")
    until(lambda: any(t["host"] == "totalelectronics.com" and t["ip"] == "198.51.100.10" for t in status(w)["targets"]),
          "the host name looked up again on B")
    # the outage of A's router ends with the network change, not as a recovery of B's
    closed = until(lambda: next((o for o in w.stream.since(mark, "outage.end") if o.get("kind") == "target"), None),
                   "the gateway outage closing")
    assert closed["note"] == "network changed" and closed["host"] == "gateway (10.20.0.1)"
    # Load Default Tiles carries the current gateway
    defaults = call(w.port, "POST", "/api/targets/defaults")
    assert [t["host"] for t in defaults] == ["gateway", "1.1.1.1", "totalelectronics.com"] and defaults[0]["ip"] == "192.168.77.1"
    # the link map probes B's router and looked the public address up again on B
    until(lambda: status(w)["map"]["gateway"]["ip"] == "192.168.77.1", "the link map's gateway on B")
    until(lambda: status(w)["map"]["public_ip"]["ip"] == "198.51.100.77", "the public address on B")
    assert any(net == "B" for _ts, net in w.win.wan_lookups)
    assert_pings_stop(w, "10.20.0.1")
    # LAN peers: A's peer is gone, beacons leave from B's address to B's broadcast
    until(lambda: any(d["peers"] == [] for d in w.stream.since(mark, "lan.peers")), "lan.peers without A's peer")
    lan = call(w.port, "GET", "/api/tools/lan/peers")
    assert lan["peers"] == [] and lan["self"]["ip"] == "192.168.77.23"
    until(lambda: any(src == "192.168.77.23" and dst == "192.168.77.255" for _ts, src, dst in list(w.win.beacons)), "a beacon on B")
    assert call(w.port, "GET", "/api/discovery/status")["default_range"] == "192.168.77.0/24"
    diag = call(w.port, "GET", "/api/diagnostics")["network"]
    assert set(diag) == NETWORK_DIAG_KEYS and diag["generation"] == 1 and diag["last_change"] == ev and diag["available"] is True
    until(lambda: "network changed: Ethernet: 192.168.77.23/24 · gateway 192.168.77.1" in recent_event_messages(w), "the events row")

    # ---- B -> a static address without a gateway ----------------------------------------------------------------
    ev, mark = switch(w, "static")
    assert (ev["default_gateway"], ev["previous_gateway"], ev["internet_nic"], ev["summary"]) == (
        None, "192.168.77.1", None, "Ethernet: 172.16.20.15/24 · no gateway")
    assert (ev["gateway_changed"], ev["internet_nic_changed"], ev["subnets_changed"], ev["dns_changed"]) == (True, True, True, True)
    assert [(c["adapter"], c["kind"]) for c in ev["changes"]] == [("Ethernet", "ipv4"), ("Ethernet", "gateway"), ("Ethernet", "dns"),
                                                                 ("Ethernet", "dhcp"), ("Ethernet", "internet_nic")]
    assert status(w)["net"] == {"generation": 2, "changed_ts": ev["ts"], "default_gateway": None, "internet_nic": None,
                                "summary": ev["summary"], "networks": ["172.16.20.0/24", "172.29.64.0/20"],
                                "network_id": 2}, "no default gateway: the data stays tagged with the last network"
    assert ethernet_row(w)["warnings"] == [], "a bench address without a gateway is a valid configuration"
    # the Gateway tile stops pinging B's router: no address, not resolved, grey, and Load Default Tiles says the same
    t = until(lambda: (lambda g: g if g["ip"] is None and g["resolved"] is False else None)(gateway_target(w)), "the no-gateway tile")
    assert t["resolve_error"] == NO_GATEWAY
    until(lambda: gateway_target(w)["light"] == "grey", "a grey gateway light")
    defaults = call(w.port, "POST", "/api/targets/defaults")
    assert (defaults[0]["host"], defaults[0]["ip"], defaults[0]["resolved"]) == ("gateway", None, False)
    until(lambda: (lambda m: m["gateway"]["ip"] is None and m["gateway"]["resolve_error"] == NO_GATEWAY)(status(w)["map"]),
          "the link map without a gateway")
    wan = until(lambda: (lambda p: p if p["error"] else None)(status(w)["map"]["public_ip"]), "the failed public-address lookup")
    assert wan["ip"] is None, "B's public address is never shown as this network's"
    assert_pings_stop(w, "192.168.77.1")
    until(lambda: call(w.port, "GET", "/api/tools/lan/peers")["self"]["ip"] == "172.16.20.15", "LAN peers' own bench address")
    until(lambda: any(src == "172.16.20.15" and dst == "172.16.20.255" for _ts, src, dst in list(w.win.beacons)), "a beacon on the bench")
    assert call(w.port, "GET", "/api/discovery/status")["default_range"] == "172.16.20.0/24", "the bench subnet, not the virtual switch"

    # ---- a gateway typed into the wrong subnet ------------------------------------------------------------------
    ev, mark = switch(w, "static-bad-gateway")
    assert (ev["default_gateway"], ev["previous_gateway"], ev["internet_nic"]["name"], ev["summary"]) == (
        "172.16.21.1", None, "Ethernet", "Ethernet: 172.16.20.15/24 · gateway 172.16.21.1")
    assert (ev["gateway_changed"], ev["internet_nic_changed"], ev["subnets_changed"], ev["dns_changed"]) == (True, True, False, False)
    assert [(c["adapter"], c["kind"]) for c in ev["changes"]] == [("Ethernet", "gateway"), ("Ethernet", "internet_nic")]
    warnings = ethernet_row(w)["warnings"]
    assert [x["code"] for x in warnings] == ["gateway_outside_subnet", "no_dns"]
    assert "172.16.21.1" in warnings[0]["message"] and "172.16.20.0/24" in warnings[0]["message"]
    until(lambda: gateway_target(w)["ip"] == "172.16.21.1", "the gateway tile on the mistyped gateway")
    assert call(w.port, "POST", "/api/targets/defaults")[0]["ip"] == "172.16.21.1"
    assert call(w.port, "GET", "/api/discovery/status")["default_range"] == "172.16.20.0/24"

    # ---- no DHCP server answers: a self-assigned address -----------------------------------------------------------
    ev, mark = switch(w, "apipa")
    assert (ev["default_gateway"], ev["previous_gateway"], ev["internet_nic"], ev["summary"]) == (
        None, "172.16.21.1", None, "Ethernet: 169.254.23.45/16 · self-assigned address, no DHCP server answered · no gateway")
    assert (ev["gateway_changed"], ev["internet_nic_changed"], ev["subnets_changed"], ev["dns_changed"]) == (True, True, True, False)
    assert [(c["adapter"], c["kind"]) for c in ev["changes"]] == [("Ethernet", "ipv4"), ("Ethernet", "gateway"), ("Ethernet", "dhcp"),
                                                                 ("Ethernet", "internet_nic")]
    assert [x["code"] for x in ethernet_row(w)["warnings"]] == ["apipa"]
    # no DHCP server answered: a lost lease, not a gateway configured away, so the tile says "no gateway" and keeps pinging
    # the last one (its misses are this PC's local outage)
    until(lambda: (lambda g: g["resolved"] is False and g["resolve_error"] == NO_GATEWAY and g["ip"] == "172.16.21.1")(gateway_target(w)),
          "the no-gateway tile again")
    until(lambda: call(w.port, "GET", "/api/tools/lan/peers")["self"]["ip"] == "169.254.23.45", "LAN peers' self-assigned address")
    assert call(w.port, "GET", "/api/discovery/status")["default_range"] is None, "no scan range: never the virtual switch's"

    # ---- the whole history: one event per move, in order, each in the events table ----------------------------------
    assert [d["generation"] for d in w.stream.since(0, "net.changed")] == [1, 2, 3, 4]
    messages = until(lambda: (lambda m: m if sum("network changed:" in x for x in m) == 4 else None)(recent_event_messages(w)),
                     "four network events rows")
    assert "network changed: Ethernet: 169.254.23.45/16 · self-assigned address, no DHCP server answered · no gateway" in messages
    assert call(w.port, "GET", "/api/diagnostics")["network"]["generation"] == 4
