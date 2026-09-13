"""Tests for tnt.discovery. No network access.

* ICMP is replaced by a scripted ``FakePinger`` injected into the scanner.
* TCP probing goes through the module seam ``discovery._tcp_connect``.
* ``tnt.arp`` / ``tnt.oui`` are replaced by fake modules in ``sys.modules`` (the
  scanner imports them lazily through ``importlib``), so the real ctypes / netaddr
  code is never exercised here.
"""
from __future__ import annotations

import ipaddress
import sys
import threading
import time
import types
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

import pytest

from tnt import config as tnt_config
from tnt import discovery


# --------------------------------------------------------------------------- fakes


@dataclass
class FakePingResult:
    ok: bool
    rtt_ms: Optional[float]


class FakePinger:
    """Scripted responders: ``{ip: rtt_ms}``; ``late`` responders only answer on
    their second attempt; ``on_call`` is invoked with the running call count."""

    def __init__(self, responders: Dict[str, float], late: Sequence[str] = (), on_call=None) -> None:
        self.responders = dict(responders)
        self.late = set(late)
        self.on_call = on_call
        self.calls: List[str] = []
        self.kwargs: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self.closed = False

    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> FakePingResult:
        with self._lock:
            self.calls.append(ip)
            self.kwargs.append({"size": size, "timeout_ms": timeout_ms, "ttl": ttl})
            n_for_ip = self.calls.count(ip)
            total = len(self.calls)
        if self.on_call is not None:
            self.on_call(total)
        if ip in self.responders and (ip not in self.late or n_for_ip >= 2):
            return FakePingResult(True, self.responders[ip])
        return FakePingResult(False, None)

    def close(self) -> None:
        self.closed = True

    def count(self, ip: str) -> int:
        with self._lock:
            return self.calls.count(ip)


class RaisingPinger:
    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> FakePingResult:
        raise RuntimeError("icmp exploded")

    def close(self) -> None:
        return None


def make_config(tmp_path, **discovery_overrides: Any) -> tnt_config.Config:
    cfg = tnt_config.Config(path=tmp_path / "config.json")
    patch: Dict[str, Any] = {
        "ports": [80, 443],
        "ping_attempts": 2,
        "ping_timeout_ms": 100,
        "port_timeout_ms": 100,
        "concurrency": 8,
        "resolve_hostnames": False,
        "max_hosts": 4096,
    }
    patch.update(discovery_overrides)
    cfg.update({"discovery": patch}, persist=False)
    return cfg


def fake_module(name: str, **attrs: Any) -> types.ModuleType:
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    return mod


@pytest.fixture
def quiet_env(monkeypatch):
    """Default seams: no TCP ports open, empty ARP table, no vendors, no rDNS."""
    monkeypatch.setattr(discovery, "_tcp_connect", lambda ip, port, timeout: False)
    monkeypatch.setitem(sys.modules, "tnt.arp", fake_module("tnt.arp", get_arp_table=lambda: {}))
    monkeypatch.setitem(sys.modules, "tnt.oui", fake_module("tnt.oui", vendor_for_mac=lambda mac: None))
    # no adapters -> no gateway -> nothing is categorised as "Router" (and no ctypes call)
    monkeypatch.setitem(sys.modules, "tnt.netinfo",
                        fake_module("tnt.netinfo", get_adapters=lambda: [], get_internet_nic=lambda: None))
    monkeypatch.setattr(discovery, "_reverse_lookup", lambda ip: None)
    monkeypatch.setattr(discovery, "RESOLVE_DEADLINE_S", 1.0)
    yield


# --------------------------------------------------------------------------- parse_range


class TestParseRange:
    def test_cidr(self, tmp_path):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        net = s.parse_range("10.0.0.0/24")
        assert isinstance(net, ipaddress.IPv4Network)
        assert str(net) == "10.0.0.0/24"

    def test_cidr_with_host_bits_is_normalised(self, tmp_path):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        assert str(s.parse_range(" 10.0.0.5/24 ")) == "10.0.0.0/24"

    def test_full_range(self, tmp_path):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        addrs = s.parse_range("10.0.0.1-10.0.0.20")
        assert isinstance(addrs, list)
        assert [str(a) for a in addrs[:2]] == ["10.0.0.1", "10.0.0.2"]
        assert str(addrs[-1]) == "10.0.0.20" and len(addrs) == 20

    def test_short_range(self, tmp_path):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        addrs = s.parse_range("10.0.0.1-20")
        assert len(addrs) == 20 and str(addrs[0]) == "10.0.0.1" and str(addrs[-1]) == "10.0.0.20"

    def test_single_ip(self, tmp_path):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        addrs = s.parse_range("10.0.0.5")
        assert addrs == [ipaddress.IPv4Address("10.0.0.5")]

    def test_range_spanning_octets(self, tmp_path):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        addrs = s.parse_range("10.0.0.250-10.0.1.5")
        assert len(addrs) == 12 and str(addrs[6]) == "10.0.1.0"

    @pytest.mark.parametrize("text,needle", [
        ("", "Enter a range"),
        ("   ", "Enter a range"),
        ("hello", "not a valid IPv4 address"),
        ("10.0.0.300", "not a valid IPv4 address"),
        ("1.2.3", "not a valid IPv4 address"),
        ("10.0.0.0/33", "not a valid CIDR"),
        ("10.0.0.1-300", "last octet"),
        ("10.0.0.1-abc", "last octet"),
        ("10.0.0.1-10.0.0.2-3", "not a valid range"),
        ("10.0.0.20-10.0.0.1", "before its start"),
        ("fe80::1/64", "IPv6 is not supported"),
        ("fe80::1", "IPv6 is not supported"),
    ])
    def test_garbage_rejected_with_help(self, tmp_path, text, needle):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        with pytest.raises(ValueError) as ei:
            s.parse_range(text)
        assert needle in str(ei.value)
        # every rejection tells the user what an acceptable range looks like
        assert "10.0.0" in str(ei.value)

    def test_oversize_cidr_rejected(self, tmp_path):
        s = discovery.DiscoveryScanner(make_config(tmp_path))  # default max_hosts 4096
        with pytest.raises(ValueError) as ei:
            s.parse_range("10.0.0.0/8")
        msg = str(ei.value)
        assert "16777214" in msg and "4096" in msg and "max_hosts" in msg and "/20" in msg

    def test_oversize_range_rejected_against_config(self, tmp_path):
        s = discovery.DiscoveryScanner(make_config(tmp_path, max_hosts=10))
        with pytest.raises(ValueError) as ei:
            s.parse_range("10.0.0.1-10.0.0.50")
        assert "50 addresses" in str(ei.value) and "maximum is 10" in str(ei.value)
        assert len(s.parse_range("10.0.0.1-10")) == 10  # exactly max_hosts is fine

    def test_non_string_rejected(self, tmp_path):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        with pytest.raises(ValueError):
            s.parse_range(None)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- default_cidr


class TestDefaultCidr:
    def test_caps_wide_prefix_to_slash24(self, tmp_path, monkeypatch):
        monkeypatch.setattr(discovery, "_internet_ipv4", lambda: ("10.0.5.7", 16))
        assert discovery.DiscoveryScanner(make_config(tmp_path)).default_cidr() == "10.0.5.0/24"

    def test_keeps_prefix_22_and_narrower(self, tmp_path, monkeypatch):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        monkeypatch.setattr(discovery, "_internet_ipv4", lambda: ("10.0.5.7", 22))
        assert s.default_cidr() == "10.0.4.0/22"
        monkeypatch.setattr(discovery, "_internet_ipv4", lambda: ("192.168.1.50", 24))
        assert s.default_cidr() == "192.168.1.0/24"
        monkeypatch.setattr(discovery, "_internet_ipv4", lambda: ("192.168.1.50", 26))
        assert s.default_cidr() == "192.168.1.0/26"

    def test_falls_back_to_another_adapter_then_local_guess_then_none(self, tmp_path, monkeypatch):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        monkeypatch.setattr(discovery, "_internet_ipv4", lambda: None)
        # a static bench address without a gateway: no internet NIC, but that adapter's network
        monkeypatch.setattr(discovery, "_first_up_ipv4", lambda: ("172.16.20.15", 24))
        monkeypatch.setattr(discovery, "_local_ipv4_guess", lambda: "10.9.9.9")
        assert s.default_cidr() == "172.16.20.0/24"
        monkeypatch.setattr(discovery, "_first_up_ipv4", lambda: None)
        monkeypatch.setattr(discovery, "_local_ipv4_guess", lambda: "172.16.9.3")
        assert s.default_cidr() == "172.16.9.0/24"
        # no IPv4 network at all (IPv6 only, nothing connected): no default, never a made-up 192.168.1.0/24
        monkeypatch.setattr(discovery, "_local_ipv4_guess", lambda: None)
        assert s.default_cidr() is None

    def test_a_vpn_tunnel_route_defaults_to_the_lan_adapter(self, tmp_path, monkeypatch):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        monkeypatch.setattr(discovery, "_internet_ipv4", lambda: ("10.8.0.2", 32))      # full-tunnel VPN won the route
        monkeypatch.setattr(discovery, "_first_up_ipv4", lambda: ("192.168.50.23", 24))
        assert s.default_cidr() == "192.168.50.0/24"
        monkeypatch.setattr(discovery, "_first_up_ipv4", lambda: None)                 # nothing better: the tunnel it is
        assert s.default_cidr() == "10.8.0.2/32"

    def test_netinfo_failure_is_tolerated(self, tmp_path, monkeypatch):
        def boom():
            raise RuntimeError("no netinfo")
        monkeypatch.setattr(discovery, "_internet_ipv4", boom)
        monkeypatch.setattr(discovery, "_first_up_ipv4", boom)
        monkeypatch.setattr(discovery, "_local_ipv4_guess", lambda: "10.1.2.3")
        assert discovery.DiscoveryScanner(make_config(tmp_path)).default_cidr() == "10.1.2.0/24"

    def test_first_up_ipv4_skips_link_local_point_to_point_and_down_adapters(self, monkeypatch):
        @dataclass
        class Addr:
            address: str
            prefix: int
            preferred: bool = True

        @dataclass
        class Nic:
            ipv4: list
            is_physical: bool = True
            is_loopback: bool = False

        calls = []

        def get_adapters(include_down=True, include_loopback=False):
            calls.append(include_down)
            return adapters

        adapters = [
            Nic([Addr("100.64.0.9", 32)], is_physical=False),                  # tunnel /32
            Nic([Addr("169.254.23.45", 16)]),                                   # self-assigned
            Nic([Addr("172.16.4.100", 24, preferred=False)]),                   # still tentative
            Nic([Addr("10.30.0.5", 24)], is_physical=False),                    # virtual switch
            Nic([Addr("192.168.50.23", 24)]),                                   # the physical LAN adapter
        ]
        monkeypatch.setitem(sys.modules, "tnt.netinfo", fake_module("tnt.netinfo", get_adapters=get_adapters))
        assert discovery._first_up_ipv4() == ("192.168.50.23", 24) and calls == [False]
        # left with the self-assigned address and a virtual switch (Hyper-V / WSL stay up on every network): no default
        adapters[:] = adapters[:4]
        assert discovery._first_up_ipv4() is None
        adapters[:] = adapters[:3]
        assert discovery._first_up_ipv4() is None


# --------------------------------------------------------------------------- native scan


class TestNativeScan:
    def test_returns_responders_and_port_only_hosts_with_mac_and_vendor(self, tmp_path, quiet_env, monkeypatch):
        pinger = FakePinger({"10.0.0.10": 1.5, "10.0.0.9": 0.4, "10.0.0.100": 12.0}, late=["10.0.0.9"])
        open_ports = {("10.0.0.10", 80), ("10.0.0.10", 443), ("10.0.0.50", 443)}
        seen_timeouts: List[float] = []

        def tcp(ip, port, timeout):
            seen_timeouts.append(timeout)
            return (ip, port) in open_ports

        monkeypatch.setattr(discovery, "_tcp_connect", tcp)
        monkeypatch.setitem(sys.modules, "tnt.arp", fake_module(
            "tnt.arp",
            get_arp_table=lambda: {"10.0.0.10": "c0-56-e3-12-34-56", "10.0.0.50": "AA:BB:CC:DD:EE:FF",
                                   "10.0.0.77": "11:22:33:44:55:66", "10.0.0.9": "00:00:00:00:00:00"}))
        monkeypatch.setitem(sys.modules, "tnt.oui", fake_module(
            "tnt.oui", vendor_for_mac=lambda mac: {"C0:56:E3:12:34:56": "Hangzhou Hikvision"}.get(mac)))

        s = discovery.DiscoveryScanner(make_config(tmp_path), pinger=pinger)
        res = s.scan("10.0.0.0/24", ports=[80, 443, 443, "22", 0, 70000])  # dirty port list is cleaned

        assert res.ok and res.error is None and not res.cancelled
        assert res.method == "native" and res.cidr == "10.0.0.0/24" and res.ports == [80, 443, 22]
        assert res.scanned == 254 and res.duration_s >= 0 and res.ts > 0
        # network and broadcast addresses are never probed
        assert "10.0.0.0" not in pinger.calls and "10.0.0.255" not in pinger.calls
        # sorted numerically by IP (a string sort would give 10, 100, 50, 9)
        assert [h.ip for h in res.hosts] == ["10.0.0.9", "10.0.0.10", "10.0.0.50", "10.0.0.100"]
        by_ip = {h.ip: h for h in res.hosts}
        assert by_ip["10.0.0.10"].ping_ok and by_ip["10.0.0.10"].rtt_ms == 1.5
        assert by_ip["10.0.0.10"].open_ports == [80, 443]
        assert by_ip["10.0.0.10"].mac == "C0:56:E3:12:34:56" and by_ip["10.0.0.10"].vendor == "Hangzhou Hikvision"
        assert by_ip["10.0.0.9"].ping_ok and by_ip["10.0.0.9"].rtt_ms == 0.4 and by_ip["10.0.0.9"].mac is None
        assert not by_ip["10.0.0.50"].ping_ok and by_ip["10.0.0.50"].rtt_ms is None
        assert by_ip["10.0.0.50"].open_ports == [443] and by_ip["10.0.0.50"].mac == "AA:BB:CC:DD:EE:FF"
        assert by_ip["10.0.0.50"].vendor is None
        assert by_ip["10.0.0.100"].open_ports == [] and by_ip["10.0.0.100"].ping_ok
        assert all(h.hostname is None for h in res.hosts)  # resolve_hostnames is off
        # 10.0.0.77 only exists in the ARP cache -> not a host
        assert "10.0.0.77" not in by_ip
        # two-pass sweep: responders of pass 1 are not re-pinged, everything else is
        assert pinger.count("10.0.0.10") == 1 and pinger.count("10.0.0.9") == 2 and pinger.count("10.0.0.3") == 2
        assert len(pinger.calls) == 254 + 252
        assert all(k["timeout_ms"] == 100 for k in pinger.kwargs)
        # every address x every port was probed with port_timeout_ms/1000
        assert len(seen_timeouts) == 254 * 3 and set(seen_timeouts) == {0.1}
        assert not pinger.closed  # injected pingers are not closed by the scanner
        assert not s.running and s.last_run_ts == res.ts

    def test_to_dict_shape(self, tmp_path, quiet_env):
        pinger = FakePinger({"10.0.0.2": 2.0})
        res = discovery.DiscoveryScanner(make_config(tmp_path), pinger=pinger).scan("10.0.0.1-3")
        d = res.to_dict()
        assert set(d) == {"ts", "cidr", "ports", "method", "hosts", "scanned", "duration_s", "ok", "error",
                          "cancelled", "found"}
        assert d["found"] == 1 and d["cidr"] == "10.0.0.1-10.0.0.3" and d["ports"] == [80, 443]
        assert d["hosts"] == [{"ip": "10.0.0.2", "hostname": None, "mac": None, "vendor": None, "ping_ok": True,
                               "rtt_ms": 2.0, "open_ports": [], "device_type": None}]

    def test_scanning_starts_no_process(self, tmp_path, quiet_env, monkeypatch):
        # the scan runs inside the LocalSystem service and is built in: from ping sweep to names it
        # spawns nothing (tnt.arp, whose fallback runs Windows' own arp.exe, is faked here)
        import subprocess

        spawned: List[Any] = []
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: spawned.append(a) or pytest.fail("process started"))
        monkeypatch.setitem(sys.modules, "tnt.arp", fake_module("tnt.arp", get_arp_table=lambda: {"10.0.0.5": "02-00-5e-10-00-05"}))
        monkeypatch.setattr(discovery, "_netbios_name", lambda ip, timeout=1.0: "HOST5" if ip == "10.0.0.5" else None)
        s = discovery.DiscoveryScanner(make_config(tmp_path, resolve_hostnames=True), pinger=FakePinger({"10.0.0.5": 1.0}))
        res = s.scan("10.0.0.1-8")
        assert res.ok and res.method == "native"
        assert [(h.ip, h.mac, h.hostname) for h in res.hosts] == [("10.0.0.5", "02:00:5E:10:00:05", "HOST5")]
        assert spawned == []

    def test_single_ip_and_small_prefixes(self, tmp_path, quiet_env):
        pinger = FakePinger({"10.0.0.5": 1.0, "10.0.0.6": 1.0, "10.0.0.7": 1.0})
        s = discovery.DiscoveryScanner(make_config(tmp_path, ping_attempts=1), pinger=pinger)
        res = s.scan("10.0.0.5")
        assert res.scanned == 1 and [h.ip for h in res.hosts] == ["10.0.0.5"] and res.cidr == "10.0.0.5"
        res = s.scan("10.0.0.6/31")
        assert res.scanned == 2 and [h.ip for h in res.hosts] == ["10.0.0.6", "10.0.0.7"]
        res = s.scan("10.0.0.7/32")
        assert res.scanned == 1 and [h.ip for h in res.hosts] == ["10.0.0.7"]
        res = s.scan("10.0.0.0/29")
        assert res.scanned == 6 and sorted(set(pinger.calls[-6:])) == [f"10.0.0.{i}" for i in range(1, 7)]

    def test_no_ports_means_ping_only(self, tmp_path, quiet_env, monkeypatch):
        calls = []
        monkeypatch.setattr(discovery, "_tcp_connect", lambda ip, port, timeout: calls.append((ip, port)) or True)
        pinger = FakePinger({"10.0.0.1": 1.0})
        res = discovery.DiscoveryScanner(make_config(tmp_path), pinger=pinger).scan("10.0.0.1-4", ports=[])
        assert res.ok and res.ports == [] and calls == [] and [h.ip for h in res.hosts] == ["10.0.0.1"]

    def test_bad_range_and_oversize_are_reported_not_raised(self, tmp_path, quiet_env):
        s = discovery.DiscoveryScanner(make_config(tmp_path, max_hosts=10), pinger=FakePinger({}))
        res = s.scan("garbage")
        assert not res.ok and res.hosts == [] and res.scanned == 0 and "not a valid IPv4" in (res.error or "")
        res = s.scan("10.0.0.0/24")
        assert not res.ok and "maximum is 10" in (res.error or "") and res.scanned == 0
        assert res.cidr == "10.0.0.0/24"

    def test_scan_never_raises(self, tmp_path, quiet_env, monkeypatch):
        # a pinger that blows up on every call is tolerated (no responders, still ok)
        s = discovery.DiscoveryScanner(make_config(tmp_path), pinger=RaisingPinger())
        res = s.scan("10.0.0.1-4")
        assert res.ok and res.hosts == [] and res.scanned == 4
        # a TCP seam that blows up is tolerated too
        def tcp_boom(ip, port, timeout):
            raise OSError("no sockets")
        monkeypatch.setattr(discovery, "_tcp_connect", tcp_boom)
        res = discovery.DiscoveryScanner(make_config(tmp_path), pinger=FakePinger({"10.0.0.2": 1.0})).scan("10.0.0.1-4")
        assert res.ok and [h.ip for h in res.hosts] == ["10.0.0.2"]
        # an unexpected internal failure becomes ok=False, error=..., never an exception
        def explode(self, *a, **k):
            raise RuntimeError("boom")
        monkeypatch.setattr(discovery.DiscoveryScanner, "_scan_native", explode)
        s = discovery.DiscoveryScanner(make_config(tmp_path), pinger=FakePinger({}))
        res = s.scan("10.0.0.1-4")
        assert not res.ok and "boom" in (res.error or "") and not s.running

    def test_arp_and_oui_failures_are_tolerated(self, tmp_path, quiet_env, monkeypatch):
        def arp_boom():
            raise OSError("GetIpNetTable2 failed")
        monkeypatch.setitem(sys.modules, "tnt.arp", fake_module("tnt.arp", get_arp_table=arp_boom))

        def oui_boom(mac):
            raise ValueError("bad mac")
        monkeypatch.setitem(sys.modules, "tnt.oui", fake_module("tnt.oui", vendor_for_mac=oui_boom))
        res = discovery.DiscoveryScanner(make_config(tmp_path), pinger=FakePinger({"10.0.0.2": 1.0})).scan("10.0.0.1-4")
        assert res.ok and [h.ip for h in res.hosts] == ["10.0.0.2"] and res.hosts[0].mac is None

    def test_cancel_stops_early(self, tmp_path, quiet_env):
        cancel = threading.Event()
        pinger = FakePinger({"10.0.0.1": 1.0}, on_call=lambda n: cancel.set() if n >= 10 else None)
        s = discovery.DiscoveryScanner(make_config(tmp_path, concurrency=4), pinger=pinger)
        t0 = time.monotonic()
        res = s.scan("10.0.0.0/24", cancel=cancel)
        assert res.cancelled and res.ok and res.error is None
        assert res.scanned < 254 and len(pinger.calls) < 100
        assert time.monotonic() - t0 < 5
        assert not s.running

    def test_cancel_already_set_returns_immediately(self, tmp_path, quiet_env):
        cancel = threading.Event()
        cancel.set()
        pinger = FakePinger({"10.0.0.1": 1.0})
        res = discovery.DiscoveryScanner(make_config(tmp_path), pinger=pinger).scan("10.0.0.0/24", cancel=cancel)
        assert res.cancelled and res.hosts == [] and res.scanned == 0 and pinger.calls == []

    def test_stop_aborts_running_scan(self, tmp_path, quiet_env):
        gate = threading.Event()

        def slow_call(n: int) -> None:
            # 254 addresses x 2 passes x 10 ms on 2 workers = seconds of work unless aborted
            if n == 5:
                gate.set()
            time.sleep(0.01)
        pinger = FakePinger({}, on_call=slow_call)
        s = discovery.DiscoveryScanner(make_config(tmp_path, concurrency=2), pinger=pinger)
        box: Dict[str, Any] = {}

        def run() -> None:
            box["res"] = s.scan("10.0.0.0/24")
        th = threading.Thread(target=run, daemon=True)
        th.start()
        assert gate.wait(5)
        assert s.running
        s.stop()
        th.join(5)
        assert not th.is_alive()
        assert box["res"].cancelled and not s.running

    def test_progress_phases_in_order_and_contract_keys(self, tmp_path, quiet_env, monkeypatch):
        monkeypatch.setattr(discovery, "_reverse_lookup", lambda ip: f"host-{ip.split('.')[-1]}.lan")
        events: List[Dict[str, Any]] = []
        pinger = FakePinger({"10.0.0.3": 1.0})
        s = discovery.DiscoveryScanner(make_config(tmp_path, resolve_hostnames=True), pinger=pinger)
        res = s.scan("10.0.0.1-8", progress=events.append)
        assert res.ok
        assert events, "progress must be reported"
        for e in events:
            assert set(e) == {"phase", "done", "total", "found", "elapsed_s"}
            assert 0 <= e["done"] <= e["total"] and e["elapsed_s"] >= 0
        phases: List[str] = []
        for e in events:
            if not phases or phases[-1] != e["phase"]:
                phases.append(e["phase"])
        assert phases == ["ping", "ports", "arp", "resolve", "done"]
        last = events[-1]
        assert last["phase"] == "done" and last["done"] == last["total"] and last["found"] == 1
        assert res.hosts[0].hostname == "host-3.lan"
        assert s.progress is not None and s.progress["phase"] == "done"

    def test_progress_callback_errors_are_swallowed(self, tmp_path, quiet_env):
        def bad(_p):
            raise RuntimeError("ui went away")
        res = discovery.DiscoveryScanner(make_config(tmp_path), pinger=FakePinger({"10.0.0.1": 1.0})).scan(
            "10.0.0.1-4", progress=bad)
        assert res.ok and [h.ip for h in res.hosts] == ["10.0.0.1"]

    def test_progress_is_throttled(self):
        calls: List[Dict[str, Any]] = []
        rep = discovery._ProgressReporter(calls.append, time.monotonic(), discovery._ScanState())
        rep.set_phase("ping", 1000)            # forced emit
        for _ in range(500):                   # far faster than 10/s
            rep.advance()
            rep.tick()
        assert len(calls) <= 2
        rep.finish()                           # forced emit
        assert calls[-1]["phase"] == "done" and calls[-1]["done"] == calls[-1]["total"]

    def test_reverse_dns_deadline_does_not_wait_for_stragglers(self, tmp_path, quiet_env, monkeypatch):
        release = threading.Event()

        def lookup(ip: str) -> Optional[str]:
            if ip == "10.0.0.2":
                release.wait(3.0)
                return "slow.lan"
            return "fast.lan"
        monkeypatch.setattr(discovery, "_reverse_lookup", lookup)
        monkeypatch.setattr(discovery, "RESOLVE_DEADLINE_S", 0.3)
        pinger = FakePinger({"10.0.0.1": 1.0, "10.0.0.2": 1.0})
        t0 = time.monotonic()
        try:
            res = discovery.DiscoveryScanner(make_config(tmp_path, resolve_hostnames=True), pinger=pinger).scan("10.0.0.1-2")
            assert time.monotonic() - t0 < 2.5
            by_ip = {h.ip: h for h in res.hosts}
            assert by_ip["10.0.0.1"].hostname == "fast.lan" and by_ip["10.0.0.2"].hostname is None
        finally:
            # let the straggler go so its thread is not still around when a later test counts threads
            release.set()
            deadline = time.monotonic() + 5
            while _pool_threads() and time.monotonic() < deadline:
                time.sleep(0.01)

    def test_tcp_connect_seam_uses_timeout_and_never_raises(self):
        # a closed loopback port answers RST immediately -> False, no exception
        import socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.close()
        assert discovery._tcp_connect("127.0.0.1", port, 0.5) is False
        # an open loopback port -> True
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        try:
            assert discovery._tcp_connect("127.0.0.1", srv.getsockname()[1], 0.5) is True
        finally:
            srv.close()
        # failures that need no DNS and no network: IPv6 literal on an IPv4 socket, port out of range
        assert discovery._tcp_connect("::1", 80, 0.1) is False
        assert discovery._tcp_connect("127.0.0.1", 70000, 0.1) is False


# --------------------------------------------------------------------------- hardening regressions


class CountingPinger:
    """Pinger whose ping() takes *delay* s and tracks how many calls are in progress,
    so a close() that lands while a probe is still running can be detected."""

    def __init__(self, delay: float = 0.15) -> None:
        self.delay = delay
        self.lock = threading.Lock()
        self.in_progress = 0
        self.calls = 0
        self.closed = False
        self.in_progress_at_close: Optional[int] = None

    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> FakePingResult:
        with self.lock:
            self.in_progress += 1
            self.calls += 1
        try:
            time.sleep(self.delay)
            return FakePingResult(False, None)
        finally:
            with self.lock:
                self.in_progress -= 1

    def close(self) -> None:
        with self.lock:
            self.closed = True
            self.in_progress_at_close = self.in_progress


def _pool_threads() -> List[str]:
    return [t.name for t in threading.enumerate() if t.name.startswith("tnt-discovery") and t.is_alive()]


class TestHardening:
    def test_concurrent_scan_on_one_scanner_is_refused(self, tmp_path, quiet_env):
        pinger = CountingPinger(delay=0.05)
        s = discovery.DiscoveryScanner(make_config(tmp_path, concurrency=2, ping_attempts=1), pinger=pinger)
        box: Dict[str, Any] = {}
        th = threading.Thread(target=lambda: box.setdefault("first", s.scan("10.0.0.1-40")), daemon=True)
        th.start()
        deadline = time.monotonic() + 5
        while not s.running and time.monotonic() < deadline:
            time.sleep(0.005)
        assert s.running
        second = s.scan("10.0.0.1-4")
        assert not second.ok and "already running" in (second.error or "") and second.scanned == 0
        assert s.running, "refusing a scan must not clobber the running scan's state"
        th.join(10)
        assert not th.is_alive() and box["first"].ok and not box["first"].cancelled
        assert not s.running

    def test_stop_waits_until_the_scan_has_ended_and_the_pool_is_quiet(self, tmp_path, quiet_env):
        pinger = CountingPinger(delay=0.2)
        s = discovery.DiscoveryScanner(make_config(tmp_path, concurrency=4, ping_timeout_ms=200), pinger=pinger)
        box: Dict[str, Any] = {}
        th = threading.Thread(target=lambda: box.setdefault("res", s.scan("10.0.0.0/24")), daemon=True)
        th.start()
        deadline = time.monotonic() + 5
        while pinger.calls < 4 and time.monotonic() < deadline:
            time.sleep(0.005)
        t0 = time.monotonic()
        assert s.stop(timeout=5.0) is True
        took = time.monotonic() - t0
        # stop() blocks until the scan thread is really done (not just flagged)...
        assert not s.running and took < 4.0
        th.join(2)
        assert not th.is_alive() and box["res"].cancelled
        # ...and no worker thread is left probing behind our back
        assert _pool_threads() == []
        assert not pinger.closed  # injected pinger is never closed

    def test_owned_pinger_is_closed_only_after_inflight_probes_finish(self, tmp_path, quiet_env, monkeypatch):
        pinger = CountingPinger(delay=0.2)
        monkeypatch.setitem(sys.modules, "tnt.icmp", fake_module("tnt.icmp", IcmpPinger=lambda: pinger))
        cancel = threading.Event()
        s = discovery.DiscoveryScanner(make_config(tmp_path, concurrency=4, ping_timeout_ms=200))  # owns its pinger
        box: Dict[str, Any] = {}
        th = threading.Thread(target=lambda: box.setdefault("res", s.scan("10.0.0.0/24", cancel=cancel)), daemon=True)
        th.start()
        deadline = time.monotonic() + 5
        while pinger.calls < 4 and time.monotonic() < deadline:
            time.sleep(0.005)
        assert pinger.in_progress > 0
        cancel.set()
        th.join(5)
        assert not th.is_alive() and box["res"].cancelled
        assert pinger.closed
        assert pinger.in_progress_at_close == 0, "IcmpCloseHandle must never race a live IcmpSendEcho2"

    def test_stop_from_the_scan_thread_does_not_deadlock(self, tmp_path, quiet_env):
        s = discovery.DiscoveryScanner(make_config(tmp_path, concurrency=2), pinger=FakePinger({"10.0.0.1": 1.0}))
        seen: List[bool] = []

        def progress(_p: Dict[str, Any]) -> None:
            if not seen:
                t0 = time.monotonic()
                seen.append(s.stop(timeout=5.0))
                assert time.monotonic() - t0 < 1.0
        res = s.scan("10.0.0.0/24", progress=progress)
        assert seen == [False] and res.cancelled and not s.running
        assert s.stop() is True  # nothing running any more

    def test_clean_ports_accepts_strings_dedupes_and_caps(self, tmp_path, quiet_env, caplog):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        assert s._clean_ports("80, 443;8080 80") == [80, 443, 8080]
        assert s._clean_ports(b"22") == [22]
        assert s._clean_ports(443) == [443]
        assert s._clean_ports([True, "x", None, 0, 65536, 21]) == [21]
        assert s._clean_ports("") == []
        with caplog.at_level("WARNING", logger="tnt.discovery"):
            out = s._clean_ports(range(1, 70000))
        assert out == list(range(1, discovery.MAX_PORTS + 1))
        assert any("truncated" in r.getMessage() for r in caplog.records)

    def test_scan_without_a_range_uses_the_default_cidr(self, tmp_path, quiet_env, monkeypatch):
        monkeypatch.setattr(discovery, "_internet_ipv4", lambda: ("10.9.8.7", 29))
        pinger = FakePinger({"10.9.8.2": 1.0})
        s = discovery.DiscoveryScanner(make_config(tmp_path, ping_attempts=1), pinger=pinger)
        for text in (None, "", "   "):
            res = s.scan(text)  # type: ignore[arg-type]
            assert res.ok and res.cidr == "10.9.8.0/29" and res.scanned == 6
            assert [h.ip for h in res.hosts] == ["10.9.8.2"]
        # parse_range itself still refuses an empty string (the UI relies on that message)
        with pytest.raises(ValueError):
            s.parse_range("")

    def test_internet_ipv4_prefers_route_address_then_preferred_non_apipa(self, monkeypatch):
        @dataclass
        class Addr:
            address: str
            prefix: int
            preferred: bool = True

        class Nic:
            def __init__(self, ipv4):
                self.ipv4 = ipv4
        holder: Dict[str, Any] = {}
        monkeypatch.setitem(sys.modules, "tnt.netinfo",
                            fake_module("tnt.netinfo", get_internet_nic=lambda: holder["nic"]))
        # tentative APIPA listed first must not win over the real lease
        holder["nic"] = Nic([Addr("169.254.7.7", 16, preferred=False), Addr("10.0.0.112", 24)])
        monkeypatch.setattr(discovery, "_local_ipv4_guess", lambda: None)
        assert discovery._internet_ipv4() == ("10.0.0.112", 24)
        # the address the default route uses wins even when listed last
        holder["nic"] = Nic([Addr("192.168.50.2", 24), Addr("10.0.0.112", 22)])
        monkeypatch.setattr(discovery, "_local_ipv4_guess", lambda: "10.0.0.112")
        assert discovery._internet_ipv4() == ("10.0.0.112", 22)
        # garbage entries are skipped, and a self-assigned address never counts: a /24 around it is nothing to scan
        # (the internet adapter of an IPv6-only network has only that one)
        holder["nic"] = Nic([Addr("not-an-ip", 24), Addr("169.254.1.2", 16)])
        monkeypatch.setattr(discovery, "_local_ipv4_guess", lambda: None)
        assert discovery._internet_ipv4() is None
        holder["nic"] = Nic([Addr("169.254.1.2", 16), Addr("192.168.7.20", 24, preferred=False)])
        assert discovery._internet_ipv4() == ("192.168.7.20", 24)
        holder["nic"] = Nic([])
        assert discovery._internet_ipv4() is None

    def test_large_port_list_is_not_materialised_up_front(self, tmp_path, quiet_env, monkeypatch):
        # 6 hosts x 1024 ports go through the pool lazily; every probe still happens exactly once
        probed: List[Any] = []
        lock = threading.Lock()

        def tcp(ip, port, timeout):
            with lock:
                probed.append((ip, port))
            return False
        monkeypatch.setattr(discovery, "_tcp_connect", tcp)
        s = discovery.DiscoveryScanner(make_config(tmp_path, ping_attempts=1, concurrency=16), pinger=FakePinger({}))
        events: List[Dict[str, Any]] = []
        res = s.scan("10.0.0.0/29", ports=list(range(1, 1025)), progress=events.append)
        assert res.ok and len(probed) == 6 * 1024 and len(set(probed)) == 6 * 1024
        ports_events = [e for e in events if e["phase"] == "ports"]
        assert ports_events and ports_events[-1]["total"] == 6 * 1024 and ports_events[-1]["done"] == 6 * 1024

    def test_a_shared_real_icmp_pinger_is_never_used_by_the_pool(self, tmp_path, quiet_env, monkeypatch):
        # The Engine injects the service-wide IcmpPinger. Its per-thread handles can only be
        # released all at once, so sweeping through it from fresh pool threads would leak
        # `concurrency` handles per scan. The scanner must sweep with a private instance instead.
        instances: List[Any] = []

        class IcmpPinger(FakePinger):
            def __init__(self) -> None:
                super().__init__({"10.0.0.2": 1.0})
                instances.append(self)
        monkeypatch.setitem(sys.modules, "tnt.icmp", fake_module("tnt.icmp", IcmpPinger=IcmpPinger))
        shared = IcmpPinger()
        s = discovery.DiscoveryScanner(make_config(tmp_path, ping_attempts=1), pinger=shared)
        res = s.scan("10.0.0.1-4")
        assert res.ok and [h.ip for h in res.hosts] == ["10.0.0.2"]
        assert shared.calls == [] and not shared.closed, "the injected real pinger must be left alone"
        assert len(instances) == 2
        private = instances[1]
        assert sorted(private.calls) == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"] and private.closed
        # ...while an injected test double of any other type is still used as-is
        fake = FakePinger({"10.0.0.3": 1.0})
        res = discovery.DiscoveryScanner(make_config(tmp_path, ping_attempts=1), pinger=fake).scan("10.0.0.1-4")
        assert [h.ip for h in res.hosts] == ["10.0.0.3"] and len(fake.calls) == 4 and not fake.closed
        assert len(instances) == 2

    def test_owned_pinger_is_closed_once_stragglers_finish_after_the_drain_cap(self, tmp_path, quiet_env, monkeypatch):
        # probes that outlive the drain cap must not leak the private pinger's handles:
        # the scan returns promptly and a background closer releases them afterwards
        monkeypatch.setattr(discovery, "DRAIN_CAP_S", 0.2)
        pinger = CountingPinger(delay=1.5)
        monkeypatch.setitem(sys.modules, "tnt.icmp", fake_module("tnt.icmp", IcmpPinger=lambda: pinger))
        cancel = threading.Event()
        s = discovery.DiscoveryScanner(make_config(tmp_path, concurrency=4, ping_timeout_ms=200))
        box: Dict[str, Any] = {}
        th = threading.Thread(target=lambda: box.setdefault("res", s.scan("10.0.0.0/24", cancel=cancel)), daemon=True)
        th.start()
        deadline = time.monotonic() + 5
        while pinger.calls < 4 and time.monotonic() < deadline:
            time.sleep(0.005)
        assert pinger.in_progress > 0
        t0 = time.monotonic()
        cancel.set()
        th.join(5)
        assert not th.is_alive() and box["res"].cancelled and not s.running
        assert time.monotonic() - t0 < 1.0, "the scan must not wait for the stragglers itself"
        assert not pinger.closed, "closing now would race the probes still inside ping()"
        deadline = time.monotonic() + 5
        while not pinger.closed and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pinger.closed, "handles must be released once the stragglers have exited"
        assert pinger.in_progress_at_close == 0, "IcmpCloseHandle must never race a live IcmpSendEcho2"
        deadline = time.monotonic() + 5
        while _pool_threads() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert _pool_threads() == []

    def test_non_string_range_is_reported_not_scanned(self, tmp_path, quiet_env, monkeypatch):
        monkeypatch.setattr(discovery, "_internet_ipv4", lambda: ("10.9.8.7", 29))
        pinger = FakePinger({"10.9.8.2": 1.0})
        s = discovery.DiscoveryScanner(make_config(tmp_path), pinger=pinger)
        for bad in (12345, ["10.0.0.0/24"], {"range": "10.0.0.0/24"}, 3.5):
            res = s.scan(bad)  # type: ignore[arg-type]
            assert not res.ok and "must be text" in (res.error or "") and res.hosts == [] and res.scanned == 0
        assert pinger.calls == [], "garbage must not turn into a scan of the default network"
        assert not s.running

    def test_error_messages_do_not_echo_huge_input(self, tmp_path, quiet_env):
        s = discovery.DiscoveryScanner(make_config(tmp_path))
        for text in ("x" * 5000, "10.0.0.1-" + "9" * 5000, "10.0.0.0/" + "2" * 5000, "1" * 5000 + "::1"):
            with pytest.raises(ValueError) as ei:
                s.parse_range(text)
            assert len(str(ei.value)) < 400 and "..." in str(ei.value) and "10.0.0" in str(ei.value)
        res = s.scan("z" * 5000)
        assert not res.ok and len(res.error or "") < 400


# --------------------------------------------------------------------------- device classification


class FakeAdapter:
    """Just enough of ``netinfo.Adapter`` for ``discovery.gateway_ips``."""

    def __init__(self, gateways: Sequence[str]) -> None:
        self.gateways = list(gateways)


class TestClassifyDevice:
    """The truth table of ``discovery.classify_device`` (pure: no fakes needed)."""

    @pytest.mark.parametrize("ports,vendor,expected", [
        ([5060], None, "Phone"),
        ([80, 5060, 443], "Yealink(Xiamen) Network Technology", "Phone"),
        ([554], None, "Camera"),
        ([80, 554], "Hangzhou Hikvision Digital Technology Co., Ltd.", "Camera"),
        ([7001], None, "DW Server"),
        ([7001, 8000], "Micro-Star INTL CO., LTD.", "DW Server"),
        ([22], "Ubiquiti Inc.", "Ubiquiti"),
        ([22, 80, 443], "Ubiquiti Networks Inc.", "Ubiquiti"),
        ([22, 443], "UBIQUITI INC", "Ubiquiti"),      # the vendor match is case-insensitive
        ([22], "Raspberry Pi Trading Ltd", None),     # a non-Ubiquiti vendor says nothing about the device
        ([22], None, None),                           # no vendor at all
        ([80, 443], "Ubiquiti Inc.", "Ubiquiti"),     # the Ubiquiti MAC alone earns the tag, no port needed
        ([], "Ubiquiti Inc.", "Ubiquiti"),
        ([], None, None),
        ([80, 443, 8080], "Synology Incorporated", None),
    ])
    def test_service_rules(self, ports, vendor, expected):
        assert discovery.classify_device("10.0.0.5", ports, None, vendor) == expected

    def test_gateway_is_the_router(self):
        gws = ("10.0.0.251", "192.168.1.1")
        assert discovery.classify_device("10.0.0.251", [], None, None, None, gws) == "Router"
        assert discovery.classify_device("192.168.1.1", [80], None, None, None, gws) == "Router"
        # a host that is not a gateway falls through to the service rules
        assert discovery.classify_device("10.0.0.5", [554], None, None, None, gws) == "Camera"
        # and without a gateway list nothing is a router
        assert discovery.classify_device("10.0.0.251", [80, 443]) is None

    @pytest.mark.parametrize("ports,vendor", [
        ([7001, 554, 5060, 22], "Ubiquiti Inc."),     # identity beats every service
        ([80, 443], "Ubiquiti Inc."),
        ([7001], None),
    ])
    def test_router_wins_over_every_service(self, ports, vendor):
        assert discovery.classify_device("10.0.0.251", ports, None, vendor, None, ["10.0.0.251"]) == "Router"

    def test_service_priority_is_dw_camera_phone_ubiquiti(self):
        # a box that answers on everything is named by the most specific service
        assert discovery.classify_device("10.0.0.5", [22, 5060, 554, 7001], None, "Ubiquiti Inc.") == "DW Server"
        assert discovery.classify_device("10.0.0.5", [22, 5060, 554], None, "Ubiquiti Inc.") == "Camera"
        assert discovery.classify_device("10.0.0.5", [22, 5060], None, "Ubiquiti Inc.") == "Phone"
        assert discovery.classify_device("10.0.0.5", [22], None, "Ubiquiti Inc.") == "Ubiquiti"

    def test_every_declared_category_is_reachable(self):
        assert discovery.DEVICE_TYPES == ["Router", "DW Server", "Camera", "Phone", "Ubiquiti"]
        produced = {
            discovery.classify_device("10.0.0.251", [], gateways=["10.0.0.251"]),
            discovery.classify_device("10.0.0.1", [7001]),
            discovery.classify_device("10.0.0.2", [554]),
            discovery.classify_device("10.0.0.3", [5060]),
            discovery.classify_device("10.0.0.4", [22], vendor="Ubiquiti Inc."),
        }
        assert produced == set(discovery.DEVICE_TYPES)

    @pytest.mark.parametrize("ports,expected", [
        (["554", 22], "Camera"),      # strings from a sloppy payload still count
        ((5060,), "Phone"),
        (7001, "DW Server"),          # a bare int
        ([None, True, "x", 554], "Camera"),
        (None, None),
        ("nonsense", None),
    ])
    def test_dirty_port_lists_are_tolerated(self, ports, expected):
        assert discovery.classify_device("10.0.0.5", ports) == expected

    def test_odd_inputs_never_raise(self):
        assert discovery.classify_device(None, None) is None
        assert discovery.classify_device("", [], None, None, None, None) is None
        assert discovery.classify_device(" 10.0.0.251 ", [], gateways=[" 10.0.0.251 "]) == "Router"
        assert discovery.classify_device("10.0.0.5", {554: True}) == "Camera"   # a dict iterates its keys

    def test_gateway_ips_reads_every_adapter_ipv4_only(self, monkeypatch):
        adapters = [FakeAdapter(["10.0.0.251", "fe80::1%12"]), FakeAdapter([]), FakeAdapter(["192.168.1.1", "junk"])]
        monkeypatch.setitem(sys.modules, "tnt.netinfo", fake_module("tnt.netinfo", get_adapters=lambda: adapters))
        assert discovery.gateway_ips() == {"10.0.0.251", "192.168.1.1"}

    def test_gateway_ips_never_raises(self, monkeypatch):
        def boom():
            raise OSError("iphlpapi exploded")

        monkeypatch.setitem(sys.modules, "tnt.netinfo", fake_module("tnt.netinfo", get_adapters=boom))
        assert discovery.gateway_ips() == set()
        monkeypatch.setitem(sys.modules, "tnt.netinfo", fake_module("tnt.netinfo"))  # no get_adapters at all
        assert discovery.gateway_ips() == set()


class TestScanDeviceTypes:
    def test_scan_sets_device_type_end_to_end(self, tmp_path, quiet_env, monkeypatch):
        monkeypatch.setitem(sys.modules, "tnt.netinfo",
                            fake_module("tnt.netinfo", get_adapters=lambda: [FakeAdapter(["10.0.0.1"])]))
        open_ports = {("10.0.0.1", 80), ("10.0.0.2", 554), ("10.0.0.3", 5060), ("10.0.0.4", 22),
                      ("10.0.0.5", 7001), ("10.0.0.6", 22)}
        monkeypatch.setattr(discovery, "_tcp_connect", lambda ip, port, timeout: (ip, port) in open_ports)
        monkeypatch.setitem(sys.modules, "tnt.arp", fake_module(
            "tnt.arp", get_arp_table=lambda: {"10.0.0.4": "24:5A:4C:12:34:01", "10.0.0.6": "DC:A6:32:12:34:0A"}))
        monkeypatch.setitem(sys.modules, "tnt.oui", fake_module("tnt.oui", vendor_for_mac=lambda mac: {
            "24:5A:4C:12:34:01": "Ubiquiti Networks Inc.", "DC:A6:32:12:34:0A": "Raspberry Pi Trading Ltd"}.get(mac)))

        s = discovery.DiscoveryScanner(make_config(tmp_path), pinger=FakePinger({"10.0.0.7": 1.0}))
        res = s.scan("10.0.0.1-7", ports=[22, 80, 554, 5060, 7001])

        assert {h.ip: h.device_type for h in res.hosts} == {
            "10.0.0.1": "Router", "10.0.0.2": "Camera", "10.0.0.3": "Phone", "10.0.0.4": "Ubiquiti",
            "10.0.0.5": "DW Server", "10.0.0.6": None, "10.0.0.7": None}
        assert res.to_dict()["hosts"][0]["device_type"] == "Router"   # it reaches the API payload

    def test_cancelled_scan_still_categorises(self, tmp_path, quiet_env, monkeypatch):
        monkeypatch.setitem(sys.modules, "tnt.netinfo",
                            fake_module("tnt.netinfo", get_adapters=lambda: [FakeAdapter(["10.0.0.1"])]))
        cancel = threading.Event()
        pinger = FakePinger({"10.0.0.1": 1.0})
        s = discovery.DiscoveryScanner(make_config(tmp_path, ping_attempts=1), pinger=pinger)
        # cancel once the sweep is over: the partial result still comes back categorised
        res = s.scan("10.0.0.1-4", ports=[80], cancel=cancel,
                     progress=lambda p: cancel.set() if p.get("phase") == "ports" else None)
        assert res.cancelled and [(h.ip, h.device_type) for h in res.hosts] == [("10.0.0.1", "Router")]

    def test_classification_failure_never_breaks_a_scan(self, tmp_path, quiet_env, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("classifier exploded")

        monkeypatch.setattr(discovery, "classify_device", boom)
        res = discovery.DiscoveryScanner(make_config(tmp_path), pinger=FakePinger({"10.0.0.2": 1.0})).scan("10.0.0.1-3")
        assert res.ok and [h.ip for h in res.hosts] == ["10.0.0.2"] and res.hosts[0].device_type is None


class TestFillDeviceTypes:
    def test_fills_only_missing_values(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "tnt.netinfo",
                            fake_module("tnt.netinfo", get_adapters=lambda: [FakeAdapter(["10.0.0.251"])]))
        rows = [
            {"ip": "10.0.0.251", "open_ports": [80], "device_type": None},
            {"ip": "10.0.0.35", "open_ports": [80, 554], "device_type": None},
            {"ip": "10.0.0.36", "open_ports": [80], "device_type": "Camera"},    # a stored value is kept
            {"ip": "10.0.0.40", "open_ports": [22], "vendor": "Ubiquiti Inc."},  # key missing entirely
            {"ip": "10.0.0.41", "open_ports": []},
        ]
        assert discovery.fill_device_types(rows) is rows
        assert [r.get("device_type") for r in rows] == ["Router", "Camera", "Camera", "Ubiquiti", None]

    def test_types_stored_by_older_versions_are_renamed(self, monkeypatch):
        def boom():
            raise AssertionError("renaming a stored type needs no gateways")

        monkeypatch.setitem(sys.modules, "tnt.netinfo", fake_module("tnt.netinfo", get_adapters=boom))
        rows = [{"ip": "10.0.0.40", "open_ports": [22], "vendor": "Ubiquiti Inc.", "device_type": "Wifi"},
                {"ip": "10.0.0.41", "open_ports": [554], "device_type": "Camera"},
                {"ip": "10.0.0.42", "open_ports": [22], "device_type": ["junk"]}]
        assert discovery.fill_device_types(rows) is rows
        assert [r["device_type"] for r in rows] == ["Ubiquiti", "Camera", ["junk"]]
        assert discovery.LEGACY_DEVICE_TYPES == {"Wifi": "Ubiquiti"}

    def test_explicit_gateways_skip_the_lookup(self, monkeypatch):
        def boom():
            raise AssertionError("gateways must not be enumerated when they are given")

        monkeypatch.setitem(sys.modules, "tnt.netinfo", fake_module("tnt.netinfo", get_adapters=boom))
        rows = [{"ip": "10.0.0.9", "open_ports": []}]
        assert discovery.fill_device_types(rows, gateways=["10.0.0.9"])[0]["device_type"] == "Router"
        # nothing missing -> no lookup either
        assert discovery.fill_device_types([{"ip": "10.0.0.9", "device_type": "Phone"}])[0]["device_type"] == "Phone"

    def test_never_raises_on_junk(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "tnt.netinfo", fake_module("tnt.netinfo", get_adapters=lambda: []))
        assert discovery.fill_device_types(None) is None
        assert discovery.fill_device_types([]) == []
        assert discovery.fill_device_types(["nonsense", 3]) == ["nonsense", 3]


class TestDeviceTypePersistence:
    """``discovery_hosts.device_type``: written, read back, migrated and back-filled."""

    @staticmethod
    def _run(hosts):
        run = {"ts": time.time(), "cidr": "10.0.0.0/24", "ports": [22, 554, 5060, 7001], "method": "native",
               "duration_s": 1.0, "scanned": 254, "ok": True, "error": None}
        return run, hosts

    def test_round_trip(self, tmp_path):
        from tnt.db import Database

        db = Database(tmp_path / "tnt.db")
        try:
            hosts = [
                {"ip": "10.0.0.251", "hostname": "gateway.lan", "mac": None, "vendor": "Ubiquiti Inc.",
                 "ping_ok": True, "rtt_ms": 0.6, "open_ports": [80, 443], "device_type": "Router"},
                {"ip": "10.0.0.35", "hostname": None, "mac": None, "vendor": None, "ping_ok": True,
                 "rtt_ms": 1.4, "open_ports": [554], "device_type": "Camera"},
                {"ip": "10.0.0.10", "hostname": "nas.lan", "mac": None, "vendor": None, "ping_ok": True,
                 "rtt_ms": 0.9, "open_ports": [80], "device_type": None},
                # a host dict from an older caller has no device_type key at all
                {"ip": "10.0.0.9", "hostname": None, "mac": None, "vendor": None, "ping_ok": False,
                 "rtt_ms": None, "open_ports": [5060]},
            ]
            run_id = db.add_discovery_run(*self._run(hosts))
            back = db.get_discovery_run(run_id)
            assert {h["ip"]: h["device_type"] for h in back["hosts"]} == {
                "10.0.0.251": "Router", "10.0.0.35": "Camera", "10.0.0.10": None, "10.0.0.9": None}
            assert db.last_discovery_run()["hosts"][0]["ip"] == "10.0.0.9"   # sorted by IP
        finally:
            db.close()

    def test_migrates_a_database_written_before_the_column_existed(self, tmp_path, monkeypatch):
        import sqlite3

        from tnt.db import Database

        path = tmp_path / "old.db"
        conn = sqlite3.connect(str(path))
        conn.executescript(
            "CREATE TABLE discovery_runs ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, cidr TEXT NOT NULL, ports TEXT NOT NULL,"
            " method TEXT NOT NULL, duration_s REAL, scanned INTEGER, found INTEGER,"
            " ok INTEGER NOT NULL DEFAULT 1, error TEXT);"
            "CREATE TABLE discovery_hosts ("
            " run_id INTEGER NOT NULL, ip TEXT NOT NULL, hostname TEXT, mac TEXT, vendor TEXT,"
            " ping_ok INTEGER NOT NULL, rtt_ms REAL, open_ports TEXT NOT NULL, PRIMARY KEY (run_id, ip));"
            "INSERT INTO discovery_runs(id, ts, cidr, ports, method, duration_s, scanned, found, ok, error)"
            " VALUES(1, 1700000000.0, '10.0.0.0/24', '[554, 7001]', 'native', 2.0, 254, 3, 1, NULL);"
            "INSERT INTO discovery_hosts VALUES(1, '10.0.0.251', 'gateway.lan', NULL, 'Ubiquiti Inc.', 1, 0.6, '[80]');"
            "INSERT INTO discovery_hosts VALUES(1, '10.0.0.35', NULL, NULL, NULL, 1, 1.4, '[554]');"
            "INSERT INTO discovery_hosts VALUES(1, '10.0.0.10', 'nas.lan', NULL, NULL, 1, 0.9, '[80]');"
        )
        conn.commit()
        conn.close()

        db = Database(path)
        try:
            cols = {r["name"] for r in db._conn.execute("PRAGMA table_info(discovery_hosts)").fetchall()}
            assert "device_type" in cols
            run = db.get_discovery_run(1)
            assert [h["device_type"] for h in run["hosts"]] == [None, None, None]   # existing rows are NULL
            # ... and the read-side backfill categorises them against today's gateways
            monkeypatch.setitem(sys.modules, "tnt.netinfo",
                                fake_module("tnt.netinfo", get_adapters=lambda: [FakeAdapter(["10.0.0.251"])]))
            discovery.fill_device_types(run["hosts"])
            assert {h["ip"]: h["device_type"] for h in run["hosts"]} == {
                "10.0.0.10": None, "10.0.0.35": "Camera", "10.0.0.251": "Router"}
        finally:
            db.close()
        # re-opening the migrated file is a no-op and new writes carry the column
        db2 = Database(path)
        try:
            rid = db2.add_discovery_run(*self._run([
                {"ip": "10.0.0.9", "hostname": None, "mac": None, "vendor": None, "ping_ok": True,
                 "rtt_ms": 1.0, "open_ports": [5060], "device_type": "Phone"}]))
            assert db2.get_discovery_run(rid)["hosts"][0]["device_type"] == "Phone"
            assert db2.get_discovery_run(1)["hosts"][0]["device_type"] is None
        finally:
            db2.close()

    def test_hosts_stored_as_wifi_are_renamed_when_the_database_opens(self, tmp_path):
        """1.11 and older typed 22 open + a Ubiquiti MAC "Wifi"; the next open renames those rows, and only those."""
        from tnt.db import Database

        path = tmp_path / "tnt.db"
        db = Database(path)
        try:
            rid = db.add_discovery_run(*self._run([
                {"ip": "10.0.0.240", "hostname": None, "mac": None, "vendor": "Ubiquiti Inc.", "ping_ok": True,
                 "rtt_ms": 1.0, "open_ports": [22], "device_type": "Wifi"},
                {"ip": "10.0.0.35", "hostname": None, "mac": None, "vendor": None, "ping_ok": True,
                 "rtt_ms": 1.0, "open_ports": [554], "device_type": "Camera"}]))
        finally:
            db.close()
        for _ in range(2):                          # the second open finds nothing left to rename
            db = Database(path)
            try:
                assert {h["ip"]: h["device_type"] for h in db.get_discovery_run(rid)["hosts"]} == {
                    "10.0.0.240": "Ubiquiti", "10.0.0.35": "Camera"}
            finally:
                db.close()

    def test_runs_recorded_with_a_removed_method_still_load_and_report(self, tmp_path, monkeypatch, caplog):
        """1.6.x could record ``method = "nmap"``; those runs stay readable after the upgrade (the
        method is only a label for the API, the UI badge and the PDF report)."""
        from tnt import export_pdf
        from tnt.db import Database

        db = Database(tmp_path / "tnt.db")
        try:
            run, _ = self._run([])
            run["method"] = "nmap"
            run_id = db.add_discovery_run(run, [
                {"ip": "10.0.0.35", "hostname": "cam35.lan", "mac": "02:00:5E:10:00:35", "vendor": "Example Cameras",
                 "ping_ok": True, "rtt_ms": 1.4, "open_ports": [554]}])
            assert db.list_discovery_runs(10)[0]["method"] == "nmap"
            back = db.get_discovery_run(run_id)
            assert back["method"] == "nmap" and [h["ip"] for h in back["hosts"]] == ["10.0.0.35"]
            monkeypatch.setitem(sys.modules, "tnt.netinfo", fake_module("tnt.netinfo", get_adapters=lambda: []))
            assert discovery.fill_device_types(back["hosts"])[0]["device_type"] == "Camera"
            assert db.last_discovery_run()["method"] == "nmap"
            with caplog.at_level("ERROR", logger="tnt.export_pdf"):
                pdf = export_pdf.build_report(db, time.time() - 86400, time.time(), tz_offset_s=0)
            assert pdf.startswith(b"%PDF") and not [r for r in caplog.records if r.levelname == "ERROR"]
        finally:
            db.close()
