"""IPv6-only networks and the public-IP lookup.

Two ways TNT misread a working network when IPv4 was not the family that carries the traffic:

* On an IPv6-only host (DHCPv4 unanswered so IPv4 is 169.254.x.x; a global IPv6 address from RA, an
  ``fe80::1`` gateway, DNS64) every host name was resolved A-first, so every name target and the link
  map's internet probe pinged an IPv4 address the host has no route to: a miss every second, a
  ``total_internet`` outage, a red tray and "internet down" on the map while every browser worked.
  ``netinfo.prefers_ipv4()`` now tells the pinger's and the link map's resolvers which family to ask for.
* The public (WAN) address lookup fell back to www.cloudflare.com when 1.1.1.1:443 was blocked, reached
  it over IPv6 and stored this PC's own IPv6 address as "the router's WAN address"; the NAT check and the
  port-forward test then said "no public address yet" forever.  The lookup is now pinned to IPv4.

Nothing here touches the network: getaddrinfo is scripted, ICMP is a fake, and the HTTPS client is
replaced (or only constructed, never connected).  Documentation addresses only.
"""
from __future__ import annotations

import logging
import socket
from types import SimpleNamespace
from typing import Any, List

import pytest

from tnt import icmp, linkmap, natcheck as nc, netinfo
from tnt.config import Config
from tnt.db import Database
from tnt.events import EventBus
from tnt.icmp import PingResult
from tnt.linkmap import LinkMap
from tnt.outages import OutageTracker
from tnt.pinger import PingManager, RawPingLog
from tnt.speedtest import base

AAAA = "2001:db8:aaaa::1"        # the (DNS64-synthesised or native) IPv6 answer
A = "203.0.113.9"                # the A record: unreachable from an IPv6-only host
GW6 = "fe80::1%7"


# ---------------------------------------------------------------------------------------------- adapters
def _v6(addr: str, prefix: int, scope: int = 0, prefix_origin: int = 4, suffix_origin: int = 4,
        dad: int = netinfo.IP_DAD_STATE_PREFERRED) -> netinfo.IpAddr:
    return netinfo._make_ipaddr(addr, 6, prefix, dad, scope, prefix_origin, suffix_origin)


def _v4(addr: str, prefix: int = 24, dad: int = netinfo.IP_DAD_STATE_PREFERRED) -> netinfo.IpAddr:
    return netinfo._make_ipaddr(addr, 4, prefix, dad, 0, 3, 3)


def _adapter(index: int, name: str, ipv4=(), ipv6=(), gateways=(), status: str = "up", if_type: int = 71,
             dns=()) -> netinfo.Adapter:
    return netinfo.Adapter(
        index=index, name=name, description=f"{name} adapter", mac="00:00:5E:00:53:%02X" % index,
        if_type=if_type, type_name="Wi-Fi" if if_type == 71 else "Ethernet", status=status,
        speed_bps=1_000_000_000, mtu=1500, dhcp_enabled=True, dhcp_server=None, dns_suffix="",
        ipv4=list(ipv4), ipv6=list(ipv6), gateways=list(gateways), dns=list(dns), metric_v4=50,
        is_physical=True, is_loopback=False)


def ipv6_only_wifi() -> netinfo.Adapter:
    """Wi-Fi on an IPv6-only network: DHCPv4 never answered (169.254.23.45), SLAAC gave a global
    address, the router advertises itself as fe80::1, DNS64 on 2001:db8:77::53."""
    return _adapter(7, "Wi-Fi", ipv4=[_v4("169.254.23.45", 16)],
                    ipv6=[_v6("fe80::1234:5678:9abc:def0", 64, scope=7, prefix_origin=2),
                          _v6("2001:db8:77::1a2b:3c4d:5e6f:7a8b", 64)],
                    gateways=[GW6], dns=["2001:db8:77::53"])


def dual_stack_wifi() -> netinfo.Adapter:
    return _adapter(7, "Wi-Fi", ipv4=[_v4("192.0.2.23")],
                    ipv6=[_v6("fe80::1234:5678:9abc:def0", 64, scope=7, prefix_origin=2),
                          _v6("2001:db8:77::1a2b:3c4d:5e6f:7a8b", 64)],
                    gateways=["192.0.2.1", GW6], dns=["192.0.2.1"])


def ipv4_only_ethernet() -> netinfo.Adapter:
    return _adapter(12, "Ethernet", ipv4=[_v4("192.0.2.10")], gateways=["192.0.2.1"], if_type=6, dns=["192.0.2.1"])


# ---------------------------------------------------------------------------------------------- prefers_ipv4
def test_prefers_ipv4_is_false_only_on_an_ipv6_only_host():
    assert netinfo.prefers_ipv4([ipv6_only_wifi()]) is False


def test_prefers_ipv4_stays_true_on_dual_stack_and_ipv4_only_hosts():
    assert netinfo.prefers_ipv4([dual_stack_wifi()]) is True
    assert netinfo.prefers_ipv4([ipv4_only_ethernet()]) is True
    # a docked bench: one NIC IPv4-only, the other IPv6-only - IPv4 has a route, so nothing changes
    assert netinfo.prefers_ipv4([ipv4_only_ethernet(), ipv6_only_wifi()]) is True


def test_prefers_ipv4_stays_true_when_nothing_says_ipv6_works():
    assert netinfo.prefers_ipv4([]) is True                                     # no adapters at all
    down = ipv6_only_wifi()
    down.status = "down"
    assert netinfo.prefers_ipv4([down]) is True                                 # the IPv6 route is on a down adapter
    no_gw = ipv6_only_wifi()
    no_gw.gateways = []
    assert netinfo.prefers_ipv4([no_gw]) is True                                # a global address but no IPv6 router
    apipa_only = _adapter(3, "Ethernet", ipv4=[_v4("169.254.9.9", 16)], if_type=6)
    assert netinfo.prefers_ipv4([apipa_only]) is True                           # simply unconfigured: no IPv6 either


def test_prefers_ipv4_ignores_an_ipv4_address_that_is_not_usable():
    # a deprecated (not preferred) IPv4 address with a gateway is no route to count on
    stale = ipv6_only_wifi()
    stale.ipv4 = [_v4("192.0.2.23", dad=netinfo.IP_DAD_STATE_DEPRECATED)]
    stale.gateways = ["192.0.2.1", GW6]
    assert netinfo.prefers_ipv4([stale]) is False
    # a routable IPv4 address with no IPv4 gateway beside a working IPv6 route: IPv6 is the way out
    lonely = ipv6_only_wifi()
    lonely.ipv4 = [_v4("192.0.2.23")]
    assert netinfo.prefers_ipv4([lonely]) is False


def test_prefers_ipv4_reads_the_adapter_cache_and_never_raises(monkeypatch):
    calls: List[Any] = []

    def adapters(include_down=True, include_loopback=False):
        calls.append((include_down, include_loopback))
        return [ipv6_only_wifi()]

    monkeypatch.setattr(netinfo, "get_adapters", adapters)
    monkeypatch.setattr(netinfo, "_route_source_ip", lambda *a, **k: None)     # and no IPv4 route either
    assert netinfo.prefers_ipv4() is False and calls

    def broken(*a, **k):
        raise RuntimeError("GetAdaptersAddresses exploded")

    monkeypatch.setattr(netinfo, "get_adapters", broken)
    assert netinfo.prefers_ipv4() is True
    assert netinfo.prefers_ipv4([object()]) is True                             # garbage in: the old default


def test_prefers_ipv4_counts_a_tentative_ipv4_address_on_a_dual_stack_host_that_just_connected():
    # net.changed fires while DAD is still running on the new IPv4 address; a name target that
    # re-resolves then must keep its A record, not be moved to the AAAA for the next five minutes
    joining = dual_stack_wifi()
    joining.ipv4 = [_v4("192.0.2.23", dad=netinfo.IP_DAD_STATE_TENTATIVE)]
    assert netinfo.prefers_ipv4([joining]) is True
    duplicate = dual_stack_wifi()
    duplicate.ipv4 = [_v4("192.0.2.23", dad=netinfo.IP_DAD_STATE_DUPLICATE)]
    assert netinfo.prefers_ipv4([duplicate]) is False                           # a duplicate never becomes usable


@pytest.mark.parametrize("source", ["192.0.0.2", "198.51.100.77"])
def test_prefers_ipv4_keeps_ipv4_first_when_ipv4_routes_through_an_adapter_with_no_listed_gateway(source):
    # Windows 11 CLAT (192.0.0.x), a PPP/WWAN point-to-point link or a full-tunnel VPN: IPv4 routes,
    # but GetAdaptersAddresses lists no IPv4 gateway.  The route probe (a UDP connect, nothing sent)
    # sees the route, so the host keeps the A-first answer it had before.
    wwan = ipv6_only_wifi()
    wwan.ipv4 = [_v4(source, 32)]
    assert netinfo.prefers_ipv4([wwan], route_probe=lambda: source) is True
    # with no IPv4 route at all it is an IPv6-only host again, and an APIPA source is no route
    assert netinfo.prefers_ipv4([wwan], route_probe=lambda: None) is False
    assert netinfo.prefers_ipv4([ipv6_only_wifi()], route_probe=lambda: "169.254.23.45") is False
    # a probe that blows up is "cannot tell" for the probe only: the adapters still decide
    assert netinfo.prefers_ipv4([ipv6_only_wifi()], route_probe=lambda: 1 / 0) is False


def test_prefers_ipv4_asks_the_live_route_probe_only_for_the_live_adapters(monkeypatch):
    probed: List[Any] = []
    monkeypatch.setattr(netinfo, "_route_source_ip", lambda *a, **k: probed.append(1) or "198.51.100.77")
    # an explicit adapter list describes some host, not this one: this PC's own route must not decide it
    assert netinfo.prefers_ipv4([ipv6_only_wifi()]) is False and not probed
    monkeypatch.setattr(netinfo, "get_adapters", lambda include_down=True, include_loopback=False: [ipv6_only_wifi()])
    assert netinfo.prefers_ipv4() is True and probed
    # an ordinary dual-stack host never needs the probe at all
    probed.clear()
    monkeypatch.setattr(netinfo, "get_adapters", lambda include_down=True, include_loopback=False: [dual_stack_wifi()])
    assert netinfo.prefers_ipv4() is True and not probed


# ---------------------------------------------------------------------------------------------- the resolvers
def windows_sorted_getaddrinfo(host, port=None, family=0, type=0, proto=0, flags=0):
    """What getaddrinfo returns for a dual-stack name: the AAAA and the A (order does not matter to resolve())."""
    return [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (AAAA, 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (A, 0)),
    ]


class V6OnlyPinger:
    """ICMP as the IPv6-only host sees it: IPv6 echoes answer, IPv4 echoes have no route."""

    def __init__(self) -> None:
        self.calls: List[str] = []

    def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
        self.calls.append(ip)
        if ":" in ip:
            return PingResult(True, 2.0, 0, None, None, size, ip, responder=ip)
        return PingResult(False, None, 11002, "Destination network unreachable", None, size, ip)

    def close(self):
        pass


def _host(monkeypatch, adapters):
    """The real netinfo, fed *adapters*; the IPv4 route probe answers as that host's would."""
    monkeypatch.setattr(icmp.socket, "getaddrinfo", windows_sorted_getaddrinfo)
    monkeypatch.setattr(netinfo, "get_adapters", lambda include_down=True, include_loopback=False: list(adapters))
    has_v4 = any(a.ipv4_gateway for a in adapters)
    route = next((a.ipv4[0].address for a in adapters if a.ipv4_gateway), None)
    monkeypatch.setattr(netinfo, "_route_source_ip", lambda *a, **k: route if has_v4 else None)


@pytest.fixture
def v6_host(monkeypatch):
    _host(monkeypatch, [ipv6_only_wifi()])


@pytest.fixture
def dual_host(monkeypatch):
    _host(monkeypatch, [dual_stack_wifi()])


@pytest.fixture
def v4_host(monkeypatch):
    _host(monkeypatch, [ipv4_only_ethernet()])


def test_resolve_keeps_its_ipv4_first_default():
    # the pure function is unchanged: callers that ask nothing still get the A record
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(icmp.socket, "getaddrinfo", windows_sorted_getaddrinfo)
        assert icmp.resolve("example.test") == A
        assert icmp.resolve("example.test", prefer_ipv4=False) == AAAA


def test_a_ping_target_name_resolves_to_its_aaaa_on_an_ipv6_only_host(v6_host, tmp_path):
    db = Database(tmp_path / "t.db")
    try:
        mgr = PingManager(db, Config(tmp_path / "config.json").load(), EventBus(), pinger=V6OnlyPinger(),
                          raw_log=RawPingLog(tmp_path / "pings"), resolver=None)
        assert mgr._do_resolve("example.test") == (AAAA, None)
    finally:
        db.close()


def test_the_link_map_internet_probe_resolves_to_its_aaaa_on_an_ipv6_only_host(v6_host, tmp_path):
    lm = LinkMap(Config(tmp_path / "config.json").load(), EventBus(), pinger=V6OnlyPinger(), sleep=lambda s: None,
                 resolver=None, gateway_lookup=lambda: GW6)
    assert lm._resolve(lm._probes["internet"]) == (AAAA, None)


@pytest.mark.parametrize("host_fixture", ["dual_host", "v4_host"])
def test_dual_stack_and_ipv4_only_hosts_still_resolve_names_to_the_a_record(host_fixture, request, tmp_path):
    request.getfixturevalue(host_fixture)
    db = Database(tmp_path / "t.db")
    try:
        cfg = Config(tmp_path / "config.json").load()
        mgr = PingManager(db, cfg, EventBus(), pinger=V6OnlyPinger(), raw_log=RawPingLog(tmp_path / "pings"), resolver=None)
        assert mgr._do_resolve("example.test") == (A, None)
        lm = LinkMap(cfg, EventBus(), pinger=V6OnlyPinger(), sleep=lambda s: None, resolver=None,
                     gateway_lookup=lambda: "192.0.2.1")
        assert lm._resolve(lm._probes["internet"]) == (A, None)
    finally:
        db.close()


def test_an_injected_resolver_is_still_called_with_the_host_alone(v6_host, tmp_path):
    # tests and the engine may hand in a one-argument resolver: the preference never breaks it
    db = Database(tmp_path / "t.db")
    try:
        seen: List[Any] = []
        mgr = PingManager(db, Config(tmp_path / "config.json").load(), EventBus(), pinger=V6OnlyPinger(),
                          raw_log=RawPingLog(tmp_path / "pings"), resolver=lambda host: seen.append(host) or "198.51.100.9")
        assert mgr._do_resolve("example.test") == ("198.51.100.9", None) and seen == ["example.test"]
    finally:
        db.close()


def test_the_default_tiles_on_an_ipv6_only_host_report_no_internet_outage(v6_host, tmp_path):
    """The whole chain the report walked: default tiles, outage tracker, tray light and the link map.

    The literal 1.1.1.1 stays an IPv4 target and keeps missing: TNT never swaps a typed address for
    another one, and "IPv4 1.1.1.1 does not answer from this PC" is simply true on an IPv6-only network
    (an app that connects to an IPv4 literal fails here too).  What must not happen is a *full*
    internet outage while the name targets answer over IPv6."""
    from tnt.engine import Engine

    now = {"t": 1_800_000_000.0}
    clock = lambda: now["t"]
    db = Database(tmp_path / "t.db")
    cfg = Config(tmp_path / "config.json").load()
    bus = EventBus()
    events: List[Any] = []
    bus.subscribe(events.append)
    pinger = V6OnlyPinger()
    raw = RawPingLog(tmp_path / "pings", clock=clock)
    mgr = PingManager(db, cfg, bus, pinger=pinger, raw_log=raw, clock=clock, sleep=lambda s: None, resolver=None)
    tracker = OutageTracker(db, cfg, bus, mgr, clock=clock, gateway_fn=lambda: GW6)
    tracker.start()
    try:
        tids = [v["id"] for v in mgr.load_defaults()]
        for _ in range(8):                      # 8 s of monitoring at the 1 s schedule
            for tid in tids:
                mgr.tick(tid)
            now["t"] += 1.0
        by_host = {v["host"]: v for v in mgr.targets()}
        assert by_host["gateway"]["ip"] == GW6 and by_host["gateway"]["light"] == "green"
        assert by_host["totalelectronics.com"]["ip"] == AAAA and by_host["totalelectronics.com"]["light"] == "green"
        assert by_host["1.1.1.1"]["ip"] == "1.1.1.1" and by_host["1.1.1.1"]["light"] == "red"
        assert tracker.status()["total_active"] is None
        assert not [e for e in events if e["type"].startswith("outage.") and e["data"].get("kind") == "total_internet"]
        assert Engine.overall_light(SimpleNamespace(ping=mgr, outages=tracker)) == "yellow"   # one target down, not a full outage

        lm = LinkMap(cfg, bus, pinger=pinger, clock=clock, sleep=lambda s: None, resolver=None, gateway_lookup=lambda: GW6)
        for _ in range(4):
            lm.tick("gateway")
            lm.tick("internet")
            now["t"] += 1.0
        view = lm.view()
        assert view["gateway"]["state"] == "up"
        assert view["internet"]["state"] == "up" and view["internet"]["ip"] == AAAA
        assert A not in pinger.calls, "the A record this host cannot route to was never pinged"
    finally:
        tracker.stop()
        mgr.stop()
        raw.close()
        db.close()


# ---------------------------------------------------------------------------------------------- the WAN lookup
V6_WAN = "2001:db8:1234::abcd"
V4_WAN = "203.0.113.5"


def _trace(host: str, ip: str) -> str:
    return f"fl=123abc\nh={host}\nip={ip}\nts=1700000000.000\nvisit_scheme=https\ncolo=AMS\n"


class FakeHttp:
    """Stands in for tnt.speedtest.base.Http.  1.1.1.1 is blocked (a 'block known DoH resolvers' policy);
    www.cloudflare.com answers with whatever address the connection came from: IPv6 unless the client
    pinned the connection to IPv4, which is what a dual-stack Windows PC would do by itself."""

    made: List[dict] = []
    first_blocked = True
    fallback_answers_v6_even_when_pinned = False

    def __init__(self, host: str, port=None, scheme: str = "https", timeout: float = 8.0, **kwargs: Any) -> None:
        self.host = host
        self.kwargs = dict(kwargs)
        FakeHttp.made.append({"host": host, "scheme": scheme, **kwargs})

    def get(self, path: str, max_bytes: int = 0, **_: Any):
        assert path == "/cdn-cgi/trace"
        if self.host == "1.1.1.1":
            if FakeHttp.first_blocked:
                raise ConnectionRefusedError(10061, "1.1.1.1:443 blocked by the firewall")
            body = _trace(self.host, V4_WAN)
        else:
            pinned = self.kwargs.get("source_address") == ("0.0.0.0", 0)
            v6 = FakeHttp.fallback_answers_v6_even_when_pinned or not pinned
            body = _trace(self.host, V6_WAN if v6 else V4_WAN)
        return SimpleNamespace(status=200, headers={}, text=body, body=body.encode())

    def close(self) -> None:
        pass


@pytest.fixture
def fake_http(monkeypatch):
    FakeHttp.made = []
    FakeHttp.first_blocked = True
    FakeHttp.fallback_answers_v6_even_when_pinned = False
    monkeypatch.setattr(base, "Http", FakeHttp)
    return FakeHttp


class _Cfg:
    def get(self, key, default=None):
        return default


class _Bus:
    def publish(self, name, data):
        pass


def _linkmap(**kw) -> LinkMap:
    return LinkMap(_Cfg(), _Bus(), pinger=SimpleNamespace(ping=lambda *a, **k: None),
                   resolver=lambda host: "198.51.100.9", gateway_lookup=lambda: "192.0.2.1", **kw)


def test_the_public_ip_lookup_pins_every_connection_to_ipv4(fake_http):
    assert linkmap._fetch_public_ip() == V4_WAN
    assert [m["host"] for m in fake_http.made] == ["1.1.1.1", "www.cloudflare.com"]
    assert all(m.get("source_address") == ("0.0.0.0", 0) and m["scheme"] == "https" for m in fake_http.made)


def test_the_public_ip_lookup_refuses_an_ipv6_answer(fake_http):
    fake_http.fallback_answers_v6_even_when_pinned = True
    with pytest.raises(Exception) as err:
        linkmap._fetch_public_ip()
    assert "IPv4" in str(err.value)


def test_the_link_map_never_stores_an_ipv6_address_as_the_wan_address(fake_http):
    fake_http.fallback_answers_v6_even_when_pinned = True
    lm = _linkmap()
    w = lm.refresh_public_ip()
    assert w["ip"] is None and w["error"]
    assert lm.view()["public_ip"]["ip"] is None and lm.public_ip() is None


def test_a_blocked_1111_no_longer_stops_the_nat_check_and_the_port_test(fake_http):
    lm = _linkmap()
    lm.refresh_public_ip()
    assert lm.public_ip() == V4_WAN
    calls: List[Any] = []
    checker = nc.NatChecker(adapters_fn=lambda: [ipv4_only_ethernet()], internet_nic_fn=ipv4_only_ethernet,
                            public_ip_fn=lambda: dict(lm.view().get("public_ip") or {}),      # Engine._public_ip_view
                            changed_ts_fn=lambda: None, refresh_fn=lm.refresh_public_ip,
                            generation_fn=lambda: 1, refresh_wait_s=5.0,
                            check=lambda **kw: (calls.append(kw), {"verdict": "single_nat", "generation": 1})[1])
    r = checker.run()
    assert r["verdict"] == "single_nat" and calls[0]["public_ip"] == V4_WAN


def test_a_lookup_with_no_ipv4_path_does_not_read_as_a_dns_failure(monkeypatch):
    # With the connection pinned to IPv4, an AAAA candidate fails at bind() with socket.gaierror
    # ("[Errno 11001] getaddrinfo failed"), and create_connection raises the last candidate's error.
    # When Windows sorts the AAAA last, the WAN chip read like broken DNS on a network whose DNS works.
    class NoV4Path(FakeHttp):
        def get(self, path, max_bytes=0, **_):
            raise socket.gaierror(11001, "getaddrinfo failed")

    FakeHttp.made = []
    monkeypatch.setattr(base, "Http", NoV4Path)
    w = _linkmap().refresh_public_ip()
    assert w["ip"] is None
    assert "getaddrinfo" not in w["error"] and "gaierror" not in w["error"]
    assert "over IPv4" in w["error"] and "www.cloudflare.com" in w["error"]


def test_the_https_client_passes_the_source_address_to_the_connection():
    # constructing the connection opens no socket
    pinned = base.Http("www.cloudflare.com", scheme="https", timeout=1.0, source_address=("0.0.0.0", 0))
    try:
        assert pinned._connection().source_address == ("0.0.0.0", 0)
    finally:
        pinned.close()
    plain = base.Http("www.cloudflare.com", scheme="https", timeout=1.0)
    try:
        assert plain._connection().source_address is None             # everything else is exactly as before
    finally:
        plain.close()
    http_ = base.Http("192.0.2.1", scheme="http", timeout=1.0, source_address=("0.0.0.0", 0))
    try:
        assert http_._connection().source_address == ("0.0.0.0", 0)
    finally:
        http_.close()


def test_binding_an_ipv6_socket_to_the_ipv4_any_address_fails_so_the_aaaa_candidate_is_skipped():
    # socket.create_connection binds each candidate's socket to source_address and moves on when that
    # raises OSError: this is what keeps the pinned lookup off IPv6
    if not socket.has_ipv6:
        pytest.skip("no IPv6 sockets on this machine")
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        with pytest.raises(OSError):
            s.bind(("0.0.0.0", 0))
    finally:
        s.close()


def test_a_new_public_address_is_logged_without_the_address(caplog):
    caplog.set_level(logging.DEBUG, logger="tnt.linkmap")
    wan = {"ip": V4_WAN}
    lm = _linkmap(wan_fetch=lambda: wan["ip"])
    lm.refresh_public_ip()
    wan["ip"] = "198.51.100.44"
    lm.refresh_public_ip()
    records = [r for r in caplog.records if r.name == "tnt.linkmap"]
    changes = [r for r in records if "public" in r.getMessage().lower() and r.levelno >= logging.INFO]
    assert len(changes) == 2
    for r in records:
        msg = r.getMessage()
        assert V4_WAN not in msg and "198.51.100.44" not in msg, msg
