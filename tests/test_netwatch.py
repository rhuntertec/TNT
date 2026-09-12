"""Network-change awareness (tnt/netwatch.py) and the service following a move between networks.

The pure layer (fingerprint, diff, summary, payload, debounce) runs on synthetic adapters; the
watcher is driven poll by poll with fake clocks and a fake ``GetAdaptersAddresses``; one
component-level test moves the PC from network A to network B through the real netinfo,
PingManager, OutageTracker, LinkMap, Engine listener and API routes.  No network access and no
real adapter query: addresses come from the private and documentation ranges (RFC 1918 / 5737 /
3849), GUIDs are invented and every MAC is locally administered.
"""
from __future__ import annotations

import copy
import json
import threading
import time
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from tnt import netinfo, netwatch
from tnt.config import Config
from tnt.events import EventBus
from tnt.icmp import PingResult
from tnt.netwatch import Debouncer, NetWatcher, adapter_key, build_event, build_state, change_flags, diff_states, summarize

T0 = 1_800_000_000.0
WIFI_GUID = "{0D7C1A00-0000-4000-8000-00000000A001}"
ETH_GUID = "{0D7C1A00-0000-4000-8000-00000000B002}"
WIFI_MAC = "02:00:5E:10:00:07"
ETH_MAC = "02:00:5E:10:00:0C"


# --------------------------------------------------------------------------- synthetic adapters
def v4(addr: str, prefix: int, dad: int = 4, origin: int = 3) -> netinfo.IpAddr:
    return netinfo._make_ipaddr(addr, 4, prefix, dad, 0, origin, origin)


def v6(addr: str, prefix: int, *, dad: int = 4, prefix_origin: int = 4, suffix_origin: int = 5, scope: int = 0) -> netinfo.IpAddr:
    return netinfo._make_ipaddr(addr, 6, prefix, dad, scope, prefix_origin, suffix_origin)


def adapter(name: str, index: int, if_type: int, guid: str, mac: str, *, status: str = "up", ipv4=(), ipv6=(),
            gateways=(), dns=(), dhcp: bool = True, dhcp_server=None, suffix: str = "", speed=None, metric: int = 25,
            physical: bool = True) -> netinfo.Adapter:
    return netinfo.Adapter(index=index, name=name, description=f"Example {name} adapter", mac=mac, if_type=if_type,
                           type_name=netinfo.IF_TYPE_NAMES.get(if_type, "Other"), status=status, speed_bps=speed,
                           mtu=1500, dhcp_enabled=dhcp, dhcp_server=dhcp_server, dns_suffix=suffix, ipv4=list(ipv4),
                           ipv6=list(ipv6), gateways=list(gateways), dns=list(dns), metric_v4=metric,
                           is_physical=physical, is_loopback=False, guid=guid, luid=1000 + index)


def wifi_a(**over: Any) -> netinfo.Adapter:
    base: Dict[str, Any] = dict(
        ipv4=[v4("192.168.10.23", 24)],
        ipv6=[v6("fe80::10:23", 64, prefix_origin=2, suffix_origin=4, scope=7),
              v6("2001:db8:10::10:23", 64, suffix_origin=4),            # SLAAC from the router advertisement
              v6("2001:db8:10::a1b2:c3d4", 128)],                       # RFC 4941 temporary: Windows reports /128
        gateways=["192.168.10.1"], dns=["192.168.10.1", "198.51.100.53"], dhcp_server="192.168.10.1",
        suffix="site-a.example", speed=300_000_000, metric=45)
    base.update(over)
    return adapter("Wi-Fi", 7, 71, WIFI_GUID, WIFI_MAC, **base)


def wifi_off() -> netinfo.Adapter:
    return adapter("Wi-Fi", 7, 71, WIFI_GUID, WIFI_MAC, status="down", metric=45)


def eth_b(**over: Any) -> netinfo.Adapter:
    base: Dict[str, Any] = dict(
        ipv4=[v4("10.20.30.45", 24)], ipv6=[v6("fe80::20:45", 64, prefix_origin=2, suffix_origin=4, scope=12)],
        gateways=["10.20.30.1"], dns=["10.20.30.53", "10.20.30.54"], dhcp_server="10.20.30.2",
        suffix="site-b.example", speed=1_000_000_000)
    base.update(over)
    return adapter("Ethernet", 12, 6, ETH_GUID, ETH_MAC, **base)


def eth_off() -> netinfo.Adapter:
    return adapter("Ethernet", 12, 6, ETH_GUID, ETH_MAC, status="down")


def site_a() -> List[netinfo.Adapter]:
    return [wifi_a(), eth_off()]           # building A: on Wi-Fi, Ethernet unplugged


def site_b() -> List[netinfo.Adapter]:
    return [wifi_off(), eth_b()]           # building B: Ethernet plugged in, Wi-Fi out of range


def state(adapters: List[Any], internet: str = None, gateway: str = None) -> netwatch.NetState:
    nic = next((a for a in adapters if a.name == internet), None)
    gw = gateway if gateway is not None else netinfo.default_gateway_for(adapters, nic)
    return build_state(adapters, nic, gw)


def kinds(changes: List[Dict[str, Any]]) -> List[tuple]:
    return [(c["adapter"], c["kind"]) for c in changes]


class FakeWindows:
    """What Windows reports: the adapter list (deep-copied per query), the default-route source
    address, and scripted query failures."""

    def __init__(self, adapters: List[Any], route_ip: str) -> None:
        self.adapters, self.route_ip = adapters, route_ip
        self.fail = 0
        self.queries = 0

    def move(self, adapters: List[Any], route_ip: str) -> None:
        self.adapters, self.route_ip = adapters, route_ip

    def query(self) -> List[Any]:
        self.queries += 1
        if self.fail > 0:
            self.fail -= 1
            raise OSError(31, "simulated GetAdaptersAddresses failure")
        return copy.deepcopy(self.adapters)

    def route(self, probe=("1.1.1.1", 53)):
        return self.route_ip


@pytest.fixture
def windows(monkeypatch):
    win = FakeWindows(site_a(), "192.168.10.23")
    monkeypatch.setattr(netinfo, "_query_adapters", win.query)
    monkeypatch.setattr(netinfo, "_route_source_ip", win.route)
    netinfo._invalidate_cache()
    yield win
    netinfo._invalidate_cache()


class Clock:
    def __init__(self, t: float) -> None:
        self.t = float(t)

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += float(seconds)


def make_watcher(tmp_path, **kw: Any) -> SimpleNamespace:
    cfg = Config(tmp_path / "config.json").load()
    bus = EventBus()
    events: List[Dict[str, Any]] = []
    bus.subscribe(events.append)
    wall, mono = Clock(T0), Clock(1000.0)
    nw = NetWatcher(cfg, bus, clock=wall, monotonic=mono, **kw)

    def step(seconds: float = 1.0) -> float:
        wall.advance(seconds)
        mono.advance(seconds)
        return nw.poll()

    return SimpleNamespace(nw=nw, bus=bus, events=events, wall=wall, mono=mono, cfg=cfg, step=step,
                           changes=lambda: [e["data"] for e in events if e["type"] == "net.changed"])


# --------------------------------------------------------------------------- fingerprint and diff
def test_adapter_key_prefers_guid_then_luid_mac_index_name():
    assert adapter_key(wifi_a()) == "guid:" + WIFI_GUID.lower()
    assert adapter_key(SimpleNamespace(guid="", luid=77, mac=ETH_MAC, index=3)) == "luid:77"
    assert adapter_key(SimpleNamespace(mac="02-00-5e-10-00-0c", index=3)) == "mac:02:00:5E:10:00:0C"
    assert adapter_key(SimpleNamespace(mac="00:00:00:00:00:00", index=3)) == "index:3"
    assert adapter_key(SimpleNamespace(name="Example tunnel")) == "name:Example tunnel"
    # a USB NIC re-plugged into another port gets a new IfIndex but keeps its GUID: no change
    replugged = eth_b()
    replugged.index = 19
    assert diff_states(state([eth_b()], "Ethernet"), state([replugged], "Ethernet")) == []
    # two doubles sharing a MAC (no GUID) stay two adapters
    twins = [SimpleNamespace(name="A", mac=ETH_MAC, index=1, status="up", ipv4=[v4("10.0.0.5", 24)]),
             SimpleNamespace(name="B", mac=ETH_MAC, index=2, status="up", ipv4=[v4("10.0.1.5", 24)])]
    assert len(build_state(twins).adapters) == 2


def test_noise_is_not_a_change():
    base = state(site_a(), "Wi-Fi")
    noisy_wifi = wifi_a(speed=144_000_000, metric=55,
                        dns=["198.51.100.53", "192.168.10.1"],                          # same servers, other order
                        ipv6=[v6("fe80::10:23", 64, prefix_origin=2, suffix_origin=4, scope=7),
                              v6("2001:db8:10::10:23", 64, suffix_origin=4),
                              v6("2001:db8:10::e5f6:789a", 128),                        # the rotated temporary address
                              v6("2001:db8:10::a1b2:c3d4", 128, dad=3)],                # the previous one, deprecated
                        ipv4=[v4("192.168.10.23", 24), v4("169.254.7.7", 16, dad=1, origin=2)])   # a tentative extra
    noisy_wifi.mtu = 1400
    leftovers = eth_off()                                  # a down adapter Windows still lists an address for
    leftovers.ipv4, leftovers.dhcp_enabled = [v4("10.20.30.45", 24, origin=1)], False
    bluetooth = adapter("Bluetooth Network Connection", 21, 6, "{0D7C1A00-0000-4000-8000-00000000C003}",
                        "02:00:5E:10:00:15", status="down")
    noisy = state([noisy_wifi, leftovers, bluetooth], "Wi-Fi")
    assert diff_states(base, noisy) == []
    assert not any(change_flags(base, noisy).values())
    assert noisy.settling, "a tentative address would make a real change wait to settle"
    assert diff_states(noisy, state([noisy_wifi], "Wi-Fi")) == [], "down adapters leaving the list change nothing"


def test_a_move_between_networks_reports_every_side_of_it():
    a, b = state(site_a(), "Wi-Fi"), state(site_b(), "Ethernet")
    changes = diff_states(a, b)
    assert kinds(changes) == [("Wi-Fi", "down"), ("Ethernet", "up"), ("Ethernet", "internet_nic"), ("Ethernet", "gateway")]
    assert (changes[0]["old"], changes[0]["new"]) == ("up", "down")
    assert (changes[2]["old"], changes[2]["new"]) == ("Wi-Fi", "Ethernet")
    assert (changes[3]["old"], changes[3]["new"]) == (["192.168.10.1"], ["10.20.30.1"])
    assert change_flags(a, b) == {"gateway_changed": True, "internet_nic_changed": True, "subnets_changed": True,
                                  "dns_changed": True}


def test_changes_on_one_adapter():
    b = state([eth_b()], "Ethernet")
    # a DHCP renew with other DNS servers: a DNS-only change
    dns = state([eth_b(dns=["10.20.30.54", "198.51.100.53"])], "Ethernet")
    assert kinds(diff_states(b, dns)) == [("Ethernet", "dns")]
    assert diff_states(b, dns)[0]["new"] == {"servers": ["10.20.30.54", "198.51.100.53"], "suffix": "site-b.example"}
    assert change_flags(b, dns) == {"gateway_changed": False, "internet_nic_changed": False, "subnets_changed": False,
                                    "dns_changed": True}
    # a mistyped static address: the gateway stays, the subnet and the DHCP state change
    typo = state([eth_b(ipv4=[v4("10.20.31.45", 24, origin=1)], dhcp=False, dhcp_server=None)], "Ethernet")
    assert kinds(diff_states(b, typo)) == [("Ethernet", "ipv4"), ("Ethernet", "dhcp")]
    assert diff_states(b, typo)[0]["new"] == ["10.20.31.45/24"]
    assert diff_states(b, typo)[1]["new"] == {"enabled": False, "server": None}
    flags = change_flags(b, typo)
    assert flags["subnets_changed"] and not flags["gateway_changed"] and not flags["dns_changed"]
    # a new IPv6 /64 is a real change; a DHCPv6 address counts as itself
    v6net = state([eth_b(ipv6=[v6("2001:db8:30::45", 64, suffix_origin=4)])], "Ethernet")
    assert kinds(diff_states(b, v6net)) == [("Ethernet", "ipv6")] and diff_states(b, v6net)[0]["new"] == ["2001:db8:30::/64"]
    dhcp6 = state([eth_b(ipv6=[v6("2001:db8:30::1:45", 128, prefix_origin=3, suffix_origin=3)])], "Ethernet")
    assert diff_states(b, dhcp6)[0]["new"] == ["2001:db8:30::1:45/128"]
    # the same gateway address at another site: only the DHCP server, DNS and suffix tell them apart
    elsewhere = state([eth_b(dns=["10.20.30.1"], dhcp_server="10.20.30.1", suffix="site-c.example")], "Ethernet")
    assert kinds(diff_states(b, elsewhere)) == [("Ethernet", "dns"), ("Ethernet", "dhcp")]
    assert not change_flags(b, elsewhere)["gateway_changed"]
    # a USB adapter plugged in (up) and pulled out again; one that arrives unplugged is no change
    usb = adapter("Ethernet 3", 31, 6, "{0D7C1A00-0000-4000-8000-00000000D004}", "02:00:5E:10:00:1F",
                  ipv4=[v4("172.16.9.20", 24)])
    plugged = state([eth_b(), usb], "Ethernet")
    assert kinds(diff_states(b, plugged)) == [("Ethernet 3", "added")] and diff_states(b, plugged)[0]["new"] == ["172.16.9.20/24"]
    assert kinds(diff_states(plugged, b)) == [("Ethernet 3", "removed")]
    usb.status, usb.ipv4 = "down", []
    assert diff_states(b, state([eth_b(), usb], "Ethernet")) == []


def test_summary_text():
    assert summarize(state(site_b(), "Ethernet")) == "Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"
    assert summarize(state([wifi_off(), eth_off()])) == "No network connection"
    bench = eth_b(ipv4=[v4("172.16.20.15", 24, origin=1)], gateways=[], dns=[], dhcp=False, dhcp_server=None)
    assert summarize(state([bench])) == "Ethernet: 172.16.20.15/24 · no gateway"
    apipa = eth_b(ipv4=[v4("169.254.23.45", 16, origin=2)], gateways=[], dns=[], dhcp_server=None)
    assert summarize(state([apipa])) == "Ethernet: 169.254.23.45/16 · self-assigned address, no DHCP server answered · no gateway"
    v6only = eth_b(ipv4=[], gateways=["fe80::1%12"], ipv6=[v6("2001:db8:30::45", 64, suffix_origin=4)])
    assert summarize(state([v6only], "Ethernet", gateway="fe80::1%12")) == "Ethernet: IPv6 only · gateway fe80::1%12"
    assert summarize(build_state([], None, "10.20.30.1")) == "Default gateway 10.20.30.1"
    # without an internet adapter a virtual switch or tunnel that stays up is never "the connection"
    vswitch = adapter("vEthernet (Default Switch)", 30, 6, "{0D7C1A00-0000-4000-8000-00000000E005}", "02:00:5E:10:00:1E",
                      ipv4=[v4("172.29.64.1", 20, origin=1)], dhcp=False, physical=False)
    tunnel = adapter("Example VPN", 40, 53, "{0D7C1A00-0000-4000-8000-00000000F006}", "", ipv4=[v4("100.64.22.7", 32, origin=1)],
                     dhcp=False, physical=False)
    assert summarize(state([vswitch, tunnel, apipa])) == \
        "Ethernet: 169.254.23.45/16 · self-assigned address, no DHCP server answered · no gateway"
    assert summarize(state([tunnel, vswitch, bench])) == "Ethernet: 172.16.20.15/24 · no gateway"
    assert summarize(state([vswitch, tunnel, eth_off(), wifi_off()])) == "No network connection"


EVENT_KEYS = {"ts", "generation", "default_gateway", "previous_gateway", "internet_nic", "changes", "gateway_changed",
              "internet_nic_changed", "subnets_changed", "dns_changed", "summary", "cause"}


def test_event_payload_matches_the_contract():
    a, b = state(site_a(), "Wi-Fi"), state(site_b(), "Ethernet")
    ev = build_event(a, b, 3, T0)
    assert set(ev) == EVENT_KEYS and json.loads(json.dumps(ev)) == ev
    assert ev["ts"] == T0 and ev["generation"] == 3 and ev["cause"] is None
    assert ev["default_gateway"] == "10.20.30.1" and ev["previous_gateway"] == "192.168.10.1"
    assert ev["internet_nic"] == {"index": 12, "name": "Ethernet", "ipv4": ["10.20.30.45"], "ipv4_prefixes": ["24"],
                                  "networks": ["10.20.30.0/24"], "dns": ["10.20.30.53", "10.20.30.54"], "dhcp": True}
    assert ev["gateway_changed"] and ev["internet_nic_changed"] and ev["subnets_changed"] and ev["dns_changed"]
    assert ev["summary"] == "Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"
    assert all(c["kind"] in netwatch.KINDS and set(c) == {"adapter", "kind", "old", "new"} for c in ev["changes"])
    assert build_event(b, state([wifi_off(), eth_off()]), 4, T0)["internet_nic"] is None


def test_tnt_own_dhcp_change_is_labelled():
    serving = eth_b(ipv4=[v4("172.16.4.100", 24, origin=1)], gateways=[], dns=[], dhcp=False, dhcp_server=None)
    before, after = state(site_b(), "Ethernet"), state([wifi_off(), serving])
    marker = {"adapter": "Ethernet", "static_ip": "172.16.4.100", "phase": "applying"}
    ev = build_event(before, after, 1, T0, marker)
    assert ev["cause"] == "dhcp" and ev["default_gateway"] is None and ev["gateway_changed"]
    assert ev["summary"] == "DHCP server set Ethernet to 172.16.4.100 · Ethernet: 172.16.4.100/24 · no gateway"
    back = build_event(after, before, 2, T0, dict(marker, phase="restored"))
    assert back["cause"] == "dhcp"
    assert back["summary"] == "DHCP server put Ethernet back on DHCP · Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"
    # something on another adapter at the same time is not TNT's own doing
    assert build_event(before, state([wifi_a(), serving], "Wi-Fi"), 3, T0, marker)["cause"] is None
    assert build_event(before, after, 4, T0, None)["cause"] is None


# --------------------------------------------------------------------------- debounce
def test_debounce_publishes_a_held_change_once():
    d = Debouncer()
    a, b = state(site_a(), "Wi-Fi"), state(site_b(), "Ethernet")
    assert d.observe(a, 0.0) is None and d.published is a          # the first look is the reference
    assert d.observe(b, 5.0) is None and d.pending is b
    assert d.observe(b, 6.0) is None
    assert d.observe(b, 7.0) is b and d.pending is None and d.published is b
    assert d.observe(b, 8.0) is None and d.observe(state(site_b(), "Ethernet"), 60.0) is None


def test_debounce_drops_a_flap_that_ends_where_it_started():
    d = Debouncer()
    a = state(site_a(), "Wi-Fi")
    d.observe(a, 0.0)
    unplugged = state([wifi_off(), eth_off()])
    assert d.observe(unplugged, 5.0) is None and d.pending is unplugged
    assert d.observe(state(site_a(), "Wi-Fi"), 6.0) is None and d.pending is None
    assert d.observe(state(site_a(), "Wi-Fi"), 20.0) is None and d.published is a


def test_debounce_publishes_a_change_that_keeps_moving_after_max_settle():
    d = Debouncer()
    d.observe(state(site_a(), "Wi-Fi"), 0.0)
    moving = [state([wifi_a(ipv4=[v4(f"192.168.10.{30 + i}", 24)])], "Wi-Fi") for i in range(6)]
    published = [d.observe(s, 10.0 + i) for i, s in enumerate(moving)]
    assert published[:4] == [None] * 4 and published[4] is moving[4]      # pending since 10 s: out at 14 s
    assert published[5] is None                                             # a new change starts a new wait


def test_debounce_waits_for_dhcp_to_settle():
    d = Debouncer()
    d.observe(state([wifi_off(), eth_off()]), 0.0)
    linking = state([wifi_off(), eth_b(ipv4=[], gateways=[], dns=[], dhcp_server=None)])   # link up, DHCP still running
    assert linking.settling
    assert d.observe(linking, 5.0) is None
    assert d.observe(linking, 7.0) is None, "held for 2 s but still settling"
    leased = state(site_b(), "Ethernet")
    assert d.observe(leased, 8.0) is None                                   # moved: the 2 s start again ...
    assert d.observe(leased, 9.0) is leased                                 # ... but 4 s pending is the limit


def test_debounce_never_publishes_two_events_within_the_minimum_gap():
    d = Debouncer(stable_s=0.0, max_settle_s=0.0, min_gap_s=2.0)
    a, b = state(site_a(), "Wi-Fi"), state(site_b(), "Ethernet")
    d.observe(a, 0.0)
    assert d.observe(b, 1.0) is b
    assert d.observe(a, 2.0) is None and d.pending is a
    assert d.observe(a, 3.0) is a


# --------------------------------------------------------------------------- the watcher
def test_watcher_publishes_one_event_for_a_move(tmp_path, windows):
    w = make_watcher(tmp_path)
    order: List[tuple] = []
    w.nw.add_listener(lambda ev: order.append(("listener", ev["generation"], list(netinfo._cache[1]))))
    w.bus.subscribe(lambda e: order.append(("bus", e["data"]["generation"])) if e["type"] == "net.changed" else None)
    assert w.nw.poll() == 5.0                                               # the reference: nothing published
    st = w.nw.state()
    assert (st["generation"], st["changed_ts"], st["default_gateway"], st["internet_nic"]) == (0, None, "192.168.10.1", "Wi-Fi")
    assert st["summary"] == "Wi-Fi: 192.168.10.23/24 · gateway 192.168.10.1" and st["polls"] == 1
    assert w.step(5.0) == 5.0 and w.changes() == []
    netinfo.get_adapters()                                                  # netinfo's 1 s cache now holds network A
    windows.move(site_b(), "10.20.30.45")
    assert w.step(5.0) == netwatch.FAST_POLL_S and w.changes() == [] and w.nw.state()["pending"] is True
    assert w.step() == netwatch.FAST_POLL_S and w.changes() == []
    assert w.step() == 5.0                                                  # held for 2 s: published
    changes = w.changes()
    assert len(changes) == 1
    ev = changes[0]
    assert ev["generation"] == 1 and ev["ts"] == w.wall.t
    assert ev["default_gateway"] == "10.20.30.1" and ev["previous_gateway"] == "192.168.10.1"
    assert ev["summary"] == "Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"
    assert order == [("listener", 1, []), ("bus", 1)], "listeners first, on a dropped netinfo cache, then the bus"
    st = w.nw.state()
    assert (st["generation"], st["changed_ts"], st["default_gateway"], st["internet_nic"]) == (1, w.wall.t, "10.20.30.1", "Ethernet")
    assert st["summary"] == ev["summary"] and w.nw.last_event()["generation"] == 1 and st["pending"] is False
    for _ in range(5):
        w.step(5.0)
    assert len(w.changes()) == 1, "nothing more while the new network holds"


def test_a_failed_adapter_query_is_skipped_never_read_as_no_adapters(tmp_path, windows):
    w = make_watcher(tmp_path)
    w.nw.poll()
    windows.fail = 3
    for _ in range(3):
        assert w.step(2.0) == netwatch.FAILURE_RETRY_S
    st = w.nw.state()
    assert st["failures"] == 3 and "simulated" in st["last_error"] and st["generation"] == 0
    assert st["default_gateway"] == "192.168.10.1" and w.changes() == []
    assert w.step(2.0) == 5.0 and w.nw.state()["last_error"] is None and w.changes() == []
    # failing from the very first look: no reference yet and no event; the first answer becomes the reference
    w2 = make_watcher(tmp_path)
    windows.fail = 1
    w2.nw.poll()
    assert w2.nw.state()["default_gateway"] is None and w2.nw.state()["polls"] == 0
    w2.step(2.0)
    assert w2.nw.state()["default_gateway"] == "192.168.10.1" and w2.changes() == []


def test_after_a_sleep_the_old_state_stays_the_reference_and_polling_is_fast(tmp_path, windows):
    w = make_watcher(tmp_path)
    w.nw.poll()
    # an hour asleep at site A; after resume Windows still shows the old lease for a few seconds
    w.wall.advance(3600.0)
    w.mono.advance(5.0)
    assert w.nw.poll() == netwatch.FAST_POLL_S
    for _ in range(3):
        assert w.step() == netwatch.FAST_POLL_S and w.changes() == []
    # the connection drops while the NIC reconnects, then the new lease arrives: one event
    windows.move([wifi_off(), eth_off()], None)
    w.step()
    windows.move(site_b(), "10.20.30.45")
    for _ in range(3):
        w.step()
    changes = w.changes()
    assert len(changes) == 1
    assert changes[0]["previous_gateway"] == "192.168.10.1" and changes[0]["default_gateway"] == "10.20.30.1"
    w.mono.advance(60.0)                                                    # a minute after the resume: back to normal
    assert w.nw.poll() == 5.0


def test_poll_soon_and_the_poll_interval_setting(tmp_path, windows):
    w = make_watcher(tmp_path)
    assert w.nw.poll_s() == 5.0 and w.cfg.get("network.poll_s") == 5
    w.cfg.update({"network": {"poll_s": 1}}, persist=False)
    assert w.cfg.get("network.poll_s") == 2 and w.nw.poll_s() == 2.0
    w.cfg.update({"network": {"poll_s": 600}}, persist=False)
    assert w.nw.poll_s() == 60.0 and w.nw.poll() == 60.0
    w.nw.poll_soon(10.0)
    assert w.step() == netwatch.FAST_POLL_S
    w.mono.advance(10.0)
    assert w.nw.poll() == 60.0
    assert NetWatcher(None, None).poll_s() == netwatch.DEFAULT_POLL_S       # no config at all


def test_watcher_labels_tnt_own_changes(tmp_path, windows):
    marker: Dict[str, Any] = {}
    w = make_watcher(tmp_path, own_change=lambda: dict(marker) or None)
    windows.move(site_b(), "10.20.30.45")
    w.nw.poll()
    marker.update({"adapter": "Ethernet", "static_ip": "172.16.4.100", "phase": "applying"})
    windows.move([wifi_off(), eth_b(ipv4=[v4("172.16.4.100", 24, origin=1)], gateways=[], dns=[], dhcp=False,
                                    dhcp_server=None)], None)
    for _ in range(3):
        w.step()
    assert w.changes()[-1]["cause"] == "dhcp"
    assert w.changes()[-1]["summary"].startswith("DHCP server set Ethernet to 172.16.4.100 · ")
    # the start-time restore of an adapter a previous run left static: TNT's own for a while ...
    marker.clear()
    w.nw.note_own_change({"adapter": "Ethernet", "static_ip": "172.16.4.100", "phase": "restored"}, ttl_s=30.0)
    windows.move(site_b(), "10.20.30.45")
    for _ in range(3):
        w.step()
    assert w.changes()[-1]["summary"].startswith("DHCP server put Ethernet back on DHCP · ")
    # ... and not after that
    w.mono.advance(60.0)
    windows.move([wifi_off(), eth_b(dns=["10.20.30.53"])], "10.20.30.45")
    for _ in range(3):
        w.step()
    assert len(w.changes()) == 3 and w.changes()[-1]["cause"] is None


def test_a_failing_listener_never_holds_the_event_back(tmp_path, windows):
    w = make_watcher(tmp_path)
    w.nw.add_listener(lambda ev: 1 / 0)
    seen: List[Dict[str, Any]] = []
    unsubscribe = w.nw.add_listener(seen.append)
    w.nw.poll()
    windows.move(site_b(), "10.20.30.45")
    for _ in range(3):
        w.step()
    assert len(w.changes()) == 1 and len(seen) == 1
    unsubscribe()
    windows.move(site_a(), "192.168.10.23")
    for _ in range(3):
        w.step()
    assert len(w.changes()) == 2 and len(seen) == 1


def test_thread_start_and_stop(tmp_path, windows):
    cfg = Config(tmp_path / "config.json").load()
    bus = EventBus()
    got = threading.Event()
    bus.subscribe(lambda e: got.set() if e["type"] == "net.changed" else None)
    nw = NetWatcher(cfg, bus, stable_s=0.1, max_settle_s=0.3)
    nw.start()
    try:
        assert nw.running and nw.state()["polls"] == 1 and nw.state()["default_gateway"] == "192.168.10.1"
        assert any(t.name == "tnt-netwatch" and t.is_alive() for t in threading.enumerate())
        nw.start()                                                          # idempotent
        windows.move(site_b(), "10.20.30.45")
        nw.poll_soon(5.0)
        assert got.wait(5.0), "the change reached the bus"
        assert nw.state()["default_gateway"] == "10.20.30.1" and nw.generation == 1
    finally:
        nw.stop()
    assert not nw.running
    assert not any(t.name == "tnt-netwatch" and t.is_alive() for t in threading.enumerate())
    nw.stop()                                                               # idempotent


# --------------------------------------------------------------------------- the whole service
class FakeIcmp:
    def __init__(self) -> None:
        self.alive: set = set()
        self.calls: List[str] = []

    def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
        self.calls.append(str(ip))
        ok = str(ip) in self.alive
        return PingResult(ok=ok, rtt_ms=1.5 if ok else None, status=0 if ok else 11010, error=None, ttl=64, size=size,
                          ip=str(ip))

    def close(self) -> None:
        pass


def test_moving_from_network_a_to_b_updates_every_consumer(tmp_path, windows):
    """The field report: TNT running on a laptop carried to another building.  One net.changed
    event, then the Gateway tile pings the new gateway, host names re-resolve, the link map and
    /api/status show the new network, Load Default Tiles returns the current gateway and the
    change is in the events table."""
    from tnt.api.routes import Request, Response, build_routes
    from tnt.db import Database
    from tnt.engine import Engine
    from tnt.linkmap import LinkMap
    from tnt.outages import OutageTracker
    from tnt.pinger import PingManager, RawPingLog

    wall, mono = Clock(T0), Clock(1000.0)
    cfg = Config(tmp_path / "config.json").load()
    db = Database(tmp_path / "tnt.db")
    bus = EventBus()
    events: List[Dict[str, Any]] = []
    bus.subscribe(events.append)
    icmp = FakeIcmp()
    icmp.alive = {"192.168.10.1", "1.1.1.1", "203.0.113.10"}
    dns = {"totalelectronics.com": "203.0.113.10"}
    public = {"ip": "203.0.113.77"}
    raw = RawPingLog(tmp_path / "pings", clock=wall)
    pm = PingManager(db, cfg, bus, pinger=icmp, raw_log=raw, clock=wall, sleep=lambda s: None, resolver=dns.get)
    tracker = OutageTracker(db, cfg, bus, pm, clock=wall)
    tracker.start()
    lm = LinkMap(cfg, bus, pinger=icmp, clock=wall, sleep=lambda s: None, resolver=dns.get, wan_fetch=lambda: public["ip"])
    eng = Engine()
    eng.config, eng.db, eng.bus, eng.pinger, eng.ping, eng.outages, eng.linkmap = cfg, db, bus, icmp, pm, tracker, lm
    eng.started_ts = wall.t
    nw = NetWatcher(cfg, bus, clock=wall, monotonic=mono)
    nw.add_listener(eng._on_net_changed)
    eng.netwatch = nw
    router = build_routes(eng, SimpleNamespace(port=7130, hub=None))

    def call(method: str, path: str) -> Any:
        handler, params = router.match(method, path)
        res = handler(Request(method=method, path=path, params=params))
        return json.loads(res.body) if isinstance(res, Response) else json.loads(json.dumps(res, default=str))

    def tick(n: int = 1) -> None:
        for _ in range(n):
            for v in pm.targets():
                pm.tick(v["id"])
            lm.tick("gateway")
            lm.tick("internet")
            wall.advance(1.0)
            mono.advance(1.0)

    try:
        nw.poll()
        views = call("POST", "/api/targets/defaults")
        gw_id = next(v["id"] for v in views if v["host"] == "gateway")
        host_id = next(v["id"] for v in views if v["host"] == "totalelectronics.com")
        assert next(v for v in views if v["id"] == gw_id)["ip"] == "192.168.10.1"
        tick(3)
        lm.refresh_public_ip()
        assert call("GET", "/api/status")["net"] == {"generation": 0, "changed_ts": None, "default_gateway": "192.168.10.1",
                                                     "internet_nic": "Wi-Fi", "networks": ["192.168.10.0/24"],
                                                     "summary": "Wi-Fi: 192.168.10.23/24 · gateway 192.168.10.1", "network_id": None}

        # plugged in at building B: another address, gateway, DNS servers and DNS answers
        windows.move(site_b(), "10.20.30.45")
        icmp.alive = {"10.20.30.1", "1.1.1.1", "198.51.100.20"}
        dns["totalelectronics.com"] = "198.51.100.20"
        public["ip"] = "198.51.100.99"
        lm._wan_wake.clear()
        for _ in range(3):
            wall.advance(1.0)
            mono.advance(1.0)
            nw.poll()
        changed = [e["data"] for e in events if e["type"] == "net.changed"]
        assert len(changed) == 1
        data = changed[0]
        assert data["default_gateway"] == "10.20.30.1" and data["previous_gateway"] == "192.168.10.1"
        assert data["gateway_changed"] and data["internet_nic"]["name"] == "Ethernet"
        assert lm._wan_wake.is_set(), "the public address is looked up again"

        before = len(icmp.calls)
        tick(1)
        assert pm.target(gw_id)["ip"] == "10.20.30.1" and "10.20.30.1" in icmp.calls[before:]
        assert "192.168.10.1" not in icmp.calls[before:], "the old router is never pinged again"
        assert pm.target(host_id)["ip"] == "198.51.100.20"
        assert lm.view()["gateway"]["ip"] == "10.20.30.1" and lm.view()["internet"]["ip"] == "198.51.100.20"

        st = call("GET", "/api/status")
        assert st["net"] == {"generation": 1, "changed_ts": data["ts"], "default_gateway": "10.20.30.1", "internet_nic": "Ethernet",
                             "summary": data["summary"], "networks": ["10.20.30.0/24"], "network_id": None}
        assert st["netinfo"]["internet_nic"]["gateway"] == "10.20.30.1" and st["netinfo"]["internet_nic"]["ipv4"] == "10.20.30.45"
        assert st["map"]["gateway"]["ip"] == "10.20.30.1"
        assert next(t for t in st["targets"] if t["id"] == gw_id)["ip"] == "10.20.30.1"
        ni = call("GET", "/api/netinfo")
        assert ni["generation"] == 1 and ni["changed_ts"] == data["ts"] and ni["default_gateway"] == "10.20.30.1"
        assert all(a["warnings"] == [] for a in ni["adapters"])
        assert next(v for v in call("POST", "/api/targets/defaults") if v["host"] == "gateway")["ip"] == "10.20.30.1"
        assert tracker.status()["active"] == [] and eng.overall_light() == "green"
        deadline = time.time() + 3.0
        while time.time() < deadline and not any(e["category"] == "network" for e in db.list_events(20)):
            time.sleep(0.02)
        row = next(e for e in db.list_events(20) if e["category"] == "network")
        assert row["level"] == "info" and row["message"] == "network changed: Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"
    finally:
        tracker.stop()
        pm.stop()
        raw.close()
        db.close()


def test_a_wifi_drop_is_still_a_local_outage_and_a_walk_elsewhere_closes_the_outages_with_the_note(tmp_path, windows, monkeypatch):
    """Outage bookkeeping across network changes, through the real PingManager, OutageTracker, NetWatcher and
    Engine._on_net_changed on fake clocks.  Windows removes the default gateway with the connection, but a minute
    without Wi-Fi on network A is still a gateway, local and internet outage (as before network-change awareness),
    labelled "no network connection".  Carried to building B instead, every outage of the network it left ends with
    "network changed" - 1.1.1.1's too, whose answers on B come before the watcher's event."""
    from tnt.db import Database
    from tnt.engine import Engine
    from tnt.outages import OutageTracker
    from tnt.pinger import PingManager, RawPingLog

    monkeypatch.setattr(netinfo, "_CACHE_TTL_S", 0.0)          # these seconds pass faster than netinfo's one-second cache
    wall, mono = Clock(T0), Clock(1000.0)
    cfg = Config(tmp_path / "config.json").load()
    cfg.update({"outage": {"miss_threshold": 3, "recover_threshold": 3}}, persist=False)
    db = Database(tmp_path / "tnt.db")
    bus = EventBus()
    icmp = FakeIcmp()
    icmp.alive = {"192.168.10.1", "1.1.1.1"}
    raw = RawPingLog(tmp_path / "pings", clock=wall)
    pm = PingManager(db, cfg, bus, pinger=icmp, raw_log=raw, clock=wall, sleep=lambda s: None, resolver=lambda host: None)
    tracker = OutageTracker(db, cfg, bus, pm, clock=wall, gateway_fn=netinfo.get_default_gateway)
    eng = Engine()
    eng.config, eng.db, eng.bus, eng.ping, eng.outages = cfg, db, bus, pm, tracker
    nw = NetWatcher(cfg, bus, clock=wall, monotonic=mono)
    nw.add_listener(eng._on_net_changed)
    ids: List[int] = []

    def run(seconds: int) -> None:
        for _ in range(seconds):
            for tid in ids:
                pm.tick(tid)
            nw.poll()
            wall.advance(1.0)
            mono.advance(1.0)

    def outages_since(t: float) -> List[tuple]:
        return sorted((r["kind"], r["host"], r["start_ts"] - T0, None if r["end_ts"] is None else r["end_ts"] - T0, r["note"])
                      for r in db.list_outages(0, wall.t + 1) if r["kind"] != "gap" and r["start_ts"] - T0 >= t)

    try:
        tracker.start()
        nw.poll()
        ids += [pm.add_target("gateway", "Gateway")["id"], pm.add_target("1.1.1.1")["id"]]
        run(10)
        windows.move([wifi_off(), eth_off()], None)              # Wi-Fi drops for a minute
        icmp.alive = set()
        run(60)
        gw = pm.target(ids[0])
        assert (gw["ip"], gw["resolved"], gw["light"]) == ("192.168.10.1", False, "red"), "the lost gateway is still pinged"
        windows.move(site_a(), "192.168.10.23")
        icmp.alive = {"192.168.10.1", "1.1.1.1"}
        run(20)
        assert outages_since(0) == sorted([
            ("target", "gateway (192.168.10.1)", 10.0, 70.0, "no network connection"),
            ("target", "1.1.1.1", 10.0, 70.0, "no network connection"),
            ("total_local", None, 10.0, 70.0, "no network connection"),
            ("total_internet", None, 10.0, 70.0, "no network connection")])
        # unplugged for half a minute on the way to building B, then plugged in there
        windows.move([wifi_off(), eth_off()], None)
        icmp.alive = set()
        run(30)
        windows.move(site_b(), "10.20.30.45")
        icmp.alive = {"10.20.30.1", "1.1.1.1"}
        run(20)
        walk = outages_since(90)
        assert [(kind, host, start, note) for kind, host, start, _end, note in walk] == sorted([
            ("target", "gateway (192.168.10.1)", 90.0, "network changed"), ("target", "1.1.1.1", 90.0, "network changed"),
            ("total_local", None, 90.0, "network changed"), ("total_internet", None, 90.0, "network changed")])
        assert all(end is not None and 120.0 <= end <= 125.0 for _kind, _host, _start, end, _note in walk), walk
        assert pm.target(ids[0])["ip"] == "10.20.30.1" and tracker.status()["active"] == []
    finally:
        tracker.stop()
        pm.stop()
        raw.close()
        db.close()


# --------------------------------------------------------------------------- labels, summaries, lifecycle
def serving_eth(**over: Any) -> netinfo.Adapter:
    """Ethernet as TNT's DHCP server tool leaves it: static 172.16.4.100/24, no gateway, no DNS."""
    base: Dict[str, Any] = dict(ipv4=[v4("172.16.4.100", 24, origin=1)], gateways=[], dns=[], dhcp=False, dhcp_server=None, suffix="")
    base.update(over)
    return eth_b(**base)


def test_only_what_the_dhcp_server_did_is_labelled_as_its_own():
    serving = state([wifi_off(), serving_eth()])
    marker = {"adapter": "Ethernet", "static_ip": "172.16.4.100", "phase": "serving"}
    # the re-address itself, published while the server already serves
    ev = build_event(state(site_b(), "Ethernet"), serving, 1, T0, marker)
    assert ev["cause"] == "dhcp" and ev["summary"] == "DHCP server set Ethernet to 172.16.4.100 · Ethernet: 172.16.4.100/24 · no gateway"
    # the cable pulled while it serves is not TNT's doing
    pulled = build_event(serving, state([wifi_off(), eth_off()]), 2, T0, marker)
    assert pulled["cause"] is None and pulled["summary"] == "Ethernet disconnected · No network connection"
    # nor an address typed in by hand, nor the USB adapter pulled out
    by_hand = state([wifi_off(), eth_b(ipv4=[v4("192.168.50.23", 24, origin=1)], gateways=["192.168.50.1"], dns=[], dhcp=False,
                                       dhcp_server=None)], "Ethernet")
    ev = build_event(serving, by_hand, 3, T0, marker)
    assert ev["cause"] is None and ev["summary"] == "Ethernet: 192.168.50.23/24 · gateway 192.168.50.1"
    assert build_event(serving, state([wifi_off()]), 4, T0, marker)["cause"] is None
    # restored: the lease coming back is TNT's, a static address typed in within the grace period is not
    restored = dict(marker, phase="restored")
    assert build_event(serving, state(site_b(), "Ethernet"), 5, T0, restored)["cause"] == "dhcp"
    retyped = state([wifi_off(), eth_b(ipv4=[v4("10.20.30.99", 24, origin=1)], dhcp=False, dhcp_server=None)], "Ethernet")
    assert build_event(serving, retyped, 6, T0, restored)["cause"] is None
    # "restoring" while the adapter still has the server address, "applying" before it has it: not what TNT made it
    assert build_event(state(site_b(), "Ethernet"), serving, 7, T0, dict(marker, phase="restoring"))["cause"] is None
    assert build_event(serving, state(site_b(), "Ethernet"), 8, T0, dict(marker, phase="applying"))["cause"] is None
    assert build_event(state(site_b(), "Ethernet"), serving, 9, T0, dict(marker, phase="bogus"))["cause"] is None


def test_a_failure_while_building_the_event_is_retried_on_the_next_poll(tmp_path, windows, monkeypatch):
    w = make_watcher(tmp_path)
    seen: List[Dict[str, Any]] = []
    w.nw.add_listener(seen.append)
    w.nw.poll()
    windows.move(site_b(), "10.20.30.45")
    real = netwatch.build_event
    calls = {"n": 0}

    def flaky(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("synthetic failure while building the payload")
        return real(*args, **kwargs)

    monkeypatch.setattr(netwatch, "build_event", flaky)
    delays = [w.step() for _ in range(3)]                   # held 2 s at the third look: the first try fails
    assert calls["n"] == 1 and delays[-1] == netwatch.FAST_POLL_S
    st = w.nw.state()
    assert w.changes() == [] and seen == [] and st["generation"] == 0 and st["default_gateway"] == "192.168.10.1"
    assert st["pending"] is True and st["last_error"]
    w.step()
    assert calls["n"] == 2 and len(w.changes()) == 1 and len(seen) == 1
    st = w.nw.state()
    assert st["generation"] == 1 and w.changes()[0]["generation"] == 1 and st["default_gateway"] == "10.20.30.1"
    assert st["last_error"] is None and st["pending"] is False


def test_a_quick_restart_never_leaves_two_watchers_polling(tmp_path, windows):
    cfg = Config(tmp_path / "config.json").load()
    bus = EventBus()
    events: List[Dict[str, Any]] = []
    bus.subscribe(lambda e: events.append(e["data"]) if e["type"] == "net.changed" else None)
    nw = NetWatcher(cfg, bus, stable_s=0.1, max_settle_s=0.3)
    entered = threading.Event()
    nw.add_listener(lambda ev: (entered.set(), time.sleep(1.5)))    # longer than stop() waits for the thread
    nw.start()
    try:
        windows.move(site_b(), "10.20.30.45")
        nw.poll_soon(5.0)
        assert entered.wait(5.0)
        old = [t for t in threading.enumerate() if t.name == "tnt-netwatch" and t.is_alive()]
        nw.stop()                                           # returns while that thread still sits in the listener
        nw.start()                                          # its first look waits for that poll to end
        time.sleep(1.0)
        assert old and not any(t.is_alive() for t in old), "the stopped run's thread ended instead of polling on"
        assert len([t for t in threading.enumerate() if t.name == "tnt-netwatch" and t.is_alive()]) == 1
        assert [e["generation"] for e in events] == [1] and nw.state()["default_gateway"] == "10.20.30.1"
    finally:
        nw.stop()


def test_a_renamed_adapter_is_a_change():
    before = state(site_b(), "Ethernet")
    renamed = eth_b()
    renamed.name = "Office LAN"
    after = state([wifi_off(), renamed], "Office LAN")
    changes = diff_states(before, after)
    assert kinds(changes) == [("Office LAN", "renamed")] and (changes[0]["old"], changes[0]["new"]) == ("Ethernet", "Office LAN")
    assert not any(change_flags(before, after).values())
    assert build_event(before, after, 1, T0)["summary"] == "Ethernet renamed to Office LAN · Office LAN: 10.20.30.45/24 · gateway 10.20.30.1"
    assert "renamed" in netwatch.KINDS and netwatch.KINDS[-1] == "internet_nic"
    off = eth_off()
    off.name = "Old Ethernet"                               # an adapter that is down: noise like the rest of it
    assert diff_states(state([eth_off()]), state([off])) == []


def test_an_adapter_that_never_gets_a_lease_holds_no_change_back(tmp_path, windows):
    """The 10 s budget: with the default 5 s poll a change applied just after a look is published 7 s later, even
    while a second DHCP adapter sits up without an address the whole time."""
    never = adapter("Ethernet 2", 31, 6, "{0D7C1A00-0000-4000-8000-00000000D004}", "02:00:5E:10:00:1F")
    windows.move([wifi_a(), eth_off(), never], "192.168.10.23")
    w = make_watcher(tmp_path)
    w.nw.poll()
    windows.move([wifi_off(), eth_b(), never], "10.20.30.45")
    assert w.nw._debouncer.published.settling, "the never-leased adapter settles in the published state too"
    waited, delay = 0.0, w.nw.poll_s()
    while not w.changes() and waited < 30:
        waited += delay
        delay = w.step(delay)
    assert w.changes() and waited == w.nw.poll_s() + netwatch.STABLE_S


def test_summaries_name_a_duplicate_address_and_a_cable_waiting_for_dhcp():
    dup = eth_b(ipv4=[v4("192.168.1.10", 24, dad=2, origin=1), v4("169.254.10.20", 16, origin=4)], gateways=["192.168.1.1"],
                dns=["192.168.1.1"], dhcp=False, dhcp_server=None)
    assert summarize(state([wifi_off(), dup], gateway="192.168.1.1")) == \
        "Ethernet: 192.168.1.10 is already in use on this network · gateway 192.168.1.1"
    assert summarize(state([wifi_off(), dup])) == "Ethernet: 192.168.1.10 is already in use on this network · gateway 192.168.1.1"
    waiting = eth_b(ipv4=[], gateways=[], dns=[], dhcp_server=None)
    assert summarize(state([wifi_off(), waiting])) == "Ethernet: connected, waiting for an address (DHCP)"
    static_empty = eth_b(ipv4=[], gateways=[], dns=[], dhcp=False, dhcp_server=None)
    assert summarize(state([wifi_off(), static_empty])) == "No network connection", "a static adapter waits for nothing"


def test_the_summary_leads_with_what_changed_when_the_connection_did_not():
    both = state([eth_b(), wifi_a()], "Ethernet")
    assert build_event(both, state([eth_b(), wifi_off()], "Ethernet"), 1, T0)["summary"] == \
        "Wi-Fi disconnected · Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"
    b = state([eth_b()], "Ethernet")
    dns = state([eth_b(dns=["10.20.30.54", "198.51.100.53"])], "Ethernet")
    assert build_event(b, dns, 2, T0)["summary"] == \
        "Ethernet: DNS servers 10.20.30.54, 198.51.100.53 · Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"
    prefix = state([eth_b(ipv6=[v6("2001:db8:30::45", 64, suffix_origin=4)])], "Ethernet")
    assert build_event(b, prefix, 3, T0)["summary"] == "Ethernet: IPv6 addresses changed · Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"
    # a new address on the internet adapter already shows in the summary; a move needs no lead either
    renew = state([eth_b(ipv4=[v4("10.20.30.46", 24)])], "Ethernet")
    assert build_event(b, renew, 4, T0)["summary"] == "Ethernet: 10.20.30.46/24 · gateway 10.20.30.1"
    assert build_event(state(site_a(), "Wi-Fi"), state(site_b(), "Ethernet"), 5, T0)["summary"] == \
        "Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"
    busy = state([eth_b(dns=["10.20.30.54"], dhcp_server="10.20.30.3", ipv6=[v6("2001:db8:30::45", 64, suffix_origin=4)])], "Ethernet")
    assert build_event(b, busy, 6, T0)["summary"] == \
        "Ethernet: IPv6 addresses changed · Ethernet: DNS servers 10.20.30.54 (+1 more) · Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"
    toggled = state([eth_b(dhcp=False, dhcp_server=None, suffix="")], "Ethernet")
    assert build_event(b, toggled, 7, T0)["summary"] == \
        "Ethernet: no DNS suffix · Ethernet: DHCP off · Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"


def test_state_lists_the_ipv4_networks_of_the_up_adapters(tmp_path, windows):
    windows.move([wifi_a(), eth_b()], "192.168.10.23")
    w = make_watcher(tmp_path)
    assert w.nw.state()["networks"] == []
    w.nw.poll()
    assert w.nw.state()["networks"] == ["10.20.30.0/24", "192.168.10.0/24"]
