"""Tests for the native Windows layer: ``tnt.icmp``, ``tnt.netinfo``, ``tnt.arp``, ``tnt.oui``.

These run real ``iphlpapi`` calls (no admin needed) but never need the internet: the only
addresses pinged are loopback and 192.0.2.1 (TEST-NET-1, unroutable). Anything that
depends on the machine actually having a network (an internet-facing NIC, ARP entries)
is asserted loosely or skipped so the suite passes on an offline laptop too.
"""
from __future__ import annotations

import ctypes
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import sys
import threading
import time
from ctypes import sizeof

import pytest

from tnt import arp, icmp, netinfo, oui

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows layer")

MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
# Adapters can carry a 2..8 byte physical address (IEEE 1394, some tunnel drivers)
ADAPTER_MAC_RE = re.compile(r"^([0-9A-F]{2}:){1,7}[0-9A-F]{2}$")
X64 = sizeof(ctypes.c_void_p) == 8


# =========================================================================================
# icmp
# =========================================================================================
def test_status_text_table():
    assert icmp.STATUS_TEXT[11010] == "Request timed out"
    assert icmp.STATUS_TEXT[0] == "Success"
    for code in (11001, 11002, 11003, 11005, 11010, 11013, 11050):
        assert isinstance(icmp.STATUS_TEXT[code], str) and icmp.STATUS_TEXT[code]
    assert "unreachable" in icmp.status_text(11003).lower()
    assert icmp.status_text(11010) == "Request timed out"
    assert icmp.status_text(-12345)  # always some text, never raises


def test_payload_is_printable_pattern():
    assert icmp._payload(0) == b""
    data = icmp._payload(1200)
    assert len(data) == 1200
    assert all(32 <= b < 127 for b in data)
    assert icmp._payload(100)[:62] == icmp._payload(200)[:62]  # repeating pattern


@pytest.mark.parametrize("size", [32, 1200, 0])
def test_ping_loopback_ok(size):
    p = icmp.IcmpPinger()
    try:
        r = p.ping("127.0.0.1", size=size, timeout_ms=1000)
    finally:
        p.close()
    assert r.ok is True
    assert r.status == 0 and r.error is None
    assert r.rtt_ms is not None and 0 < r.rtt_ms < 5.0
    assert r.size == size
    assert r.ip == "127.0.0.1"
    assert isinstance(r.ttl, int) and r.ttl > 0
    d = r.to_dict()
    assert d["ok"] is True and d["size"] == size


def test_ping_loopback_ipv6():
    p = icmp.IcmpPinger()
    try:
        r = p.ping("::1", size=64, timeout_ms=1000)
        r2 = p.ping("[::1]", size=8, timeout_ms=1000)
    finally:
        p.close()
    assert r.ok is True and r.rtt_ms is not None and r.rtt_ms < 5.0 and r.size == 64 and r.ip == "::1"
    assert r2.ok is True and r2.ip == "::1"


def test_ping_ipv4_mapped_ipv6_uses_ipv4_path():
    p = icmp.IcmpPinger()
    try:
        r = p.ping("::ffff:127.0.0.1", size=16, timeout_ms=1000)
    finally:
        p.close()
    assert r.ok is True and r.ip == "127.0.0.1" and r.size == 16
    assert isinstance(r.ttl, int) and r.ttl > 0      # came back through the IPv4 reply layout


@pytest.mark.skipif(not X64, reason="x64 layout")
def test_ping_reply_layout_x64():
    """The reply buffer really is laid out as ICMP_ECHO_REPLY with 64-bit pointers: the
    Data pointer must land right after the struct and the echoed payload must be there."""
    dll = icmp._dll()
    handle = dll.IcmpCreateFile()
    assert handle and handle != icmp.INVALID_HANDLE_VALUE
    try:
        size = 32
        req = (ctypes.c_char * size)()
        req.raw = icmp._payload(size)
        opts = icmp.IP_OPTION_INFORMATION(Ttl=128)
        reply_len = sizeof(icmp.ICMP_ECHO_REPLY) + size + 8
        buf = ctypes.create_string_buffer(reply_len)
        dest = int.from_bytes(bytes([127, 0, 0, 1]), "little")
        n = dll.IcmpSendEcho2(handle, None, None, None, dest, req, size, ctypes.byref(opts), buf, reply_len, 1000)
        assert n >= 1
        reply = icmp.ICMP_ECHO_REPLY.from_buffer(buf)
        assert reply.Status == 0 and reply.DataSize == size
        assert reply.Data == ctypes.addressof(buf) + sizeof(icmp.ICMP_ECHO_REPLY)
        assert ctypes.string_at(reply.Data, size) == icmp._payload(size)
        assert reply.Options.Ttl == 128 and reply.Options.OptionsSize == 0
        assert str(ipaddress.IPv4Address(int(reply.Address).to_bytes(4, "little"))) == "127.0.0.1"
    finally:
        dll.IcmpCloseHandle(handle)


def test_ping_zero_reply_with_zero_error_is_os_error(monkeypatch):
    """IcmpSendEcho2 returning 0 while GetLastError() is 0 must not become ok=False, status=0."""

    class FakeDll:
        def IcmpCreateFile(self):
            return 0x1234

        def Icmp6CreateFile(self):
            return 0x5678

        def IcmpCloseHandle(self, h):
            return 1

        def IcmpSendEcho2(self, *args):
            return 0

        def Icmp6SendEcho2(self, *args):
            return 0

    monkeypatch.setattr(icmp, "_dll", lambda: FakeDll())
    monkeypatch.setattr(icmp.ctypes, "get_last_error", lambda: 0)
    p = icmp.IcmpPinger()
    try:
        for ip in ("127.0.0.1", "::1"):
            r = p.ping(ip)
            assert r.ok is False and r.status == -1 and r.rtt_ms is None and r.error and r.ip == ip
        monkeypatch.setattr(icmp.ctypes, "get_last_error", lambda: 11010)
        r = p.ping("127.0.0.1")
        assert r.ok is False and r.status == 11010 and r.error == "Request timed out"
    finally:
        p.close()
    assert p._handles == set()


def test_ping_unroutable_times_out_within_budget():
    timeout_ms = 400
    p = icmp.IcmpPinger()
    try:
        t0 = time.perf_counter()
        r = p.ping("192.0.2.1", size=32, timeout_ms=timeout_ms)
        elapsed_ms = (time.perf_counter() - t0) * 1000
    finally:
        p.close()
    assert r.ok is False
    assert r.rtt_ms is None
    assert r.status in (11010, 11003, 11002), r
    assert r.error and isinstance(r.error, str)
    assert elapsed_ms <= timeout_ms + 200, f"took {elapsed_ms:.0f} ms"
    assert r.size == 32 and r.ip == "192.0.2.1"


def test_ping_invalid_input_never_raises():
    p = icmp.IcmpPinger()
    try:
        for bad in ("not-an-ip", "", None, "999.1.1.1", "1.1.1"):
            r = p.ping(bad)  # type: ignore[arg-type]
            assert r.ok is False and r.status == -1 and r.rtt_ms is None and r.error
        r = p.ping("127.0.0.1", size=-5)
        assert r.ok is True and r.size == 0
    finally:
        p.close()


def test_ping_thread_safe_and_close_idempotent():
    p = icmp.IcmpPinger()
    results = []
    lock = threading.Lock()

    def worker():
        for _ in range(5):
            r = p.ping("127.0.0.1", 32, 1000)
            with lock:
                results.append(r.ok)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert not any(t.is_alive() for t in threads)
    assert len(results) == 20 and all(results)
    assert len(p._handles) >= 1
    p.close()
    assert p._handles == set()
    p.close()  # idempotent
    # a ping after close() transparently gets a fresh handle
    assert p.ping("127.0.0.1").ok is True
    p.close()


def test_ping_after_close_ignores_recycled_handle_value(monkeypatch):
    """Windows hands the value of a just-closed handle to the next Icmp*CreateFile call. A
    thread whose cached IPv4 handle was closed must not adopt the IPv6 handle that now
    carries the same value (IcmpSendEcho2 would fail with error 87 on every ping)."""

    class FakeDll:
        def __init__(self):
            self.v4_handles = iter([0x1000, 0x2000, 0x3000])
            self.sent = []
            self.closed = []

        def IcmpCreateFile(self):
            return next(self.v4_handles)

        def Icmp6CreateFile(self):
            return 0x1000                      # the recycled value of the closed IPv4 handle

        def IcmpCloseHandle(self, h):
            self.closed.append(h)
            return 1

        def IcmpSendEcho2(self, handle, *args):
            self.sent.append(("v4", handle))
            return 0

        def Icmp6SendEcho2(self, handle, *args):
            self.sent.append(("v6", handle))
            return 0

    fake = FakeDll()
    monkeypatch.setattr(icmp, "_dll", lambda: fake)
    monkeypatch.setattr(icmp.ctypes, "get_last_error", lambda: 11010)
    p = icmp.IcmpPinger()
    p.ping("127.0.0.1")
    assert p.ping("127.0.0.1").status == 11010            # the cached handle is reused while valid
    p.close()
    assert fake.closed == [0x1000]
    p.ping("::1")                                          # registers 0x1000 again, as an IPv6 handle
    p.ping("127.0.0.1")                                    # must get a fresh IPv4 handle, not 0x1000
    assert fake.sent == [("v4", 0x1000), ("v4", 0x1000), ("v6", 0x1000), ("v4", 0x2000)]
    p.close()
    assert sorted(fake.closed) == [0x1000, 0x1000, 0x2000]
    assert p._handles == set()
    p.close()
    assert sorted(fake.closed) == [0x1000, 0x1000, 0x2000]  # idempotent


def test_ping_ipv4_after_close_and_ipv6_real_dll():
    """Same scenario against the real iphlpapi, where the recycling actually happens."""
    p = icmp.IcmpPinger()
    try:
        assert p.ping("127.0.0.1").ok is True
        p.close()
        assert p.ping("::1").ok is True
        r = p.ping("127.0.0.1")
        assert r.ok is True, r
    finally:
        p.close()


def test_resolve_basics():
    assert icmp.resolve("localhost") in ("127.0.0.1", "::1")
    assert icmp.resolve("1.1.1.1") == "1.1.1.1"
    assert icmp.resolve(" 8.8.8.8 ") == "8.8.8.8"
    assert icmp.resolve("[::1]") == "::1"
    assert icmp.resolve("2606:4700:4700::1111") == "2606:4700:4700::1111"
    assert icmp.resolve("") is None
    assert icmp.resolve(None) is None  # type: ignore[arg-type]
    assert icmp.resolve("no-such-host-tnt-test.invalid", timeout_s=5.0) is None


def test_resolve_prefers_ipv4_then_ipv6():
    v4 = icmp.resolve("localhost", prefer_ipv4=True)
    v6 = icmp.resolve("localhost", prefer_ipv4=False)
    assert v4 in ("127.0.0.1", "::1") and v6 in ("127.0.0.1", "::1")
    infos = socket.getaddrinfo("localhost", None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    families = {i[0] for i in infos}
    if socket.AF_INET in families:
        assert v4 == "127.0.0.1"
    if socket.AF_INET6 in families:
        assert v6 == "::1"


def test_resolve_tolerates_bad_timeout():
    assert icmp.resolve("1.1.1.1", timeout_s=None) == "1.1.1.1"  # type: ignore[arg-type]
    assert icmp.resolve("localhost", timeout_s="soon") in ("127.0.0.1", "::1")  # type: ignore[arg-type]


def test_resolve_times_out_without_blocking(monkeypatch):
    release = threading.Event()

    def slow_getaddrinfo(*args, **kwargs):
        release.wait(3.0)
        return []

    monkeypatch.setattr(icmp.socket, "getaddrinfo", slow_getaddrinfo)
    t0 = time.perf_counter()
    assert icmp.resolve("hung.example", timeout_s=0.2) is None
    assert time.perf_counter() - t0 < 1.0
    release.set()


def test_resolve_coalesces_inflight_lookups(monkeypatch):
    """The ping manager retries an unresolved host every tick: a hung resolver must cost
    one helper thread per name, not one per call."""
    release = threading.Event()
    calls = []
    real = socket.getaddrinfo

    def slow_getaddrinfo(host, *args, **kwargs):
        calls.append(host)
        release.wait(5.0)
        return real(host, *args, **kwargs)

    monkeypatch.setattr(icmp.socket, "getaddrinfo", slow_getaddrinfo)
    before = threading.active_count()
    for _ in range(5):
        assert icmp.resolve("localhost", timeout_s=0.05) is None
    assert calls == ["localhost"]
    assert threading.active_count() - before <= 1
    assert "localhost" in icmp._inflight
    release.set()
    deadline = time.monotonic() + 3.0
    while "localhost" in icmp._inflight and time.monotonic() < deadline:
        time.sleep(0.01)
    assert "localhost" not in icmp._inflight              # finished lookups are forgotten
    monkeypatch.setattr(icmp.socket, "getaddrinfo", real)
    assert icmp.resolve("localhost") in ("127.0.0.1", "::1")
    assert calls == ["localhost"]


def test_resolve_survives_thread_start_failure(monkeypatch):
    class NoThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("can't start new thread")

    monkeypatch.setattr(icmp.threading, "Thread", NoThread)
    t0 = time.perf_counter()
    assert icmp.resolve("localhost", timeout_s=2.0) is None
    assert time.perf_counter() - t0 < 1.0
    assert "localhost" not in icmp._inflight


# =========================================================================================
# netinfo
# =========================================================================================
@pytest.mark.skipif(not X64, reason="x64 layouts")
def test_netinfo_struct_sizes():
    assert sizeof(netinfo.SOCKET_ADDRESS) == 16
    assert sizeof(netinfo.IP_ADAPTER_UNICAST_ADDRESS) == 64
    assert sizeof(netinfo.IP_ADAPTER_ADDRESSES) == 448
    assert netinfo.IP_ADAPTER_ADDRESSES.FirstGatewayAddress.offset == 208
    assert netinfo.IP_ADAPTER_ADDRESSES.Dhcpv4Server.offset == 232


def _fake_adapter(**over) -> netinfo.Adapter:
    base = dict(
        index=12, name="Ethernet", description="Intel(R) Ethernet Connection", mac="00:00:5E:00:53:10",
        if_type=6, type_name="Ethernet", status="up", speed_bps=1_000_000_000, mtu=1500,
        dhcp_enabled=True, dhcp_server="10.0.0.251", dns_suffix="",
        ipv4=[netinfo.IpAddr("10.0.0.112", 24, 4, "255.255.255.0", "10.0.0.0/24")],
        ipv6=[], gateways=["10.0.0.251"], dns=["10.0.0.251"], metric_v4=25, is_physical=True, is_loopback=False,
    )
    base.update(over)
    return netinfo.Adapter(**base)


def test_get_adapters_real_machine():
    adapters = netinfo.get_adapters()
    assert adapters, "GetAdaptersAddresses returned nothing"
    statuses = {"up", "down", "testing", "unknown", "dormant", "not_present", "lower_layer_down"}
    for a in adapters:
        assert isinstance(a.index, int) and a.index > 0
        assert a.name and a.type_name
        assert a.status in statuses
        assert a.mac == "" or ADAPTER_MAC_RE.match(a.mac), a.mac
        assert not a.is_loopback
        assert a.speed_bps is None or a.speed_bps > 0
        assert a.mtu is None or a.mtu > 0
        for x in a.ipv4:
            assert x.family == 4 and 0 <= x.prefix <= 32 and x.netmask
            assert ipaddress.IPv4Address(x.address) in ipaddress.IPv4Network(x.network)
        for x in a.ipv6:
            assert x.family == 6 and 0 <= x.prefix <= 128 and x.netmask is None
            assert ipaddress.IPv6Address(x.address) in ipaddress.IPv6Network(x.network)
        if a.if_type in (6, 71):
            assert a.mac, f"{a.name} has no MAC"
        if a.if_type == 6 and "virtual" not in a.description.lower():
            assert a.is_physical
    # loopback is hidden by default, present on request
    with_lo = netinfo.get_adapters(include_loopback=True)
    lo = [a for a in with_lo if a.is_loopback]
    assert lo and lo[0].if_type == 24 and any(x.address == "127.0.0.1" for x in lo[0].ipv4)
    assert all(a.status == "up" for a in netinfo.get_adapters(include_down=False))


def _ipconfig_text() -> str:
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "ipconfig.exe")
    proc = subprocess.run([exe], capture_output=True, timeout=15, check=False,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return proc.stdout.decode("utf-8", errors="replace")


def test_internet_nic_gateway_and_subnets_real_machine():
    adapters = netinfo.get_adapters()
    nic = netinfo.get_internet_nic(adapters)
    if nic is None:
        pytest.skip("no internet-facing adapter on this machine")
    assert nic.is_up and nic.ipv4 and nic.gateways
    assert nic.primary_ipv4 is not None
    primary = next(x for x in nic.ipv4 if x.address == nic.primary_ipv4)
    assert 8 <= primary.prefix <= 30, "an internet-facing NIC should sit on a real subnet"
    gw = netinfo.get_default_gateway()
    assert gw is not None and gw in nic.gateways
    assert ipaddress.ip_address(gw) in ipaddress.ip_network(primary.network)
    # the gateway is grouped with the subnet that contains it
    groups = netinfo.subnet_groups(nic)
    group = next(g for g in groups if g["network"] == primary.network)
    assert group["family"] == 4 and group["mask"] == primary.netmask
    assert nic.primary_ipv4 in group["addresses"] and gw in group["gateways"]
    # cross-check with ipconfig (independent oracle)
    text = _ipconfig_text()
    assert nic.primary_ipv4 in text and gw in text
    # the internet NIC must be a physical Ethernet/Wi-Fi adapter on a normal desktop
    assert nic.if_type in (6, 71, 53, 131)


def test_classify_ip_rules():
    for ip in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "172.16.4.4", "::1", "fe80::1", "localhost"):
        assert netinfo.classify_ip(ip) == "local", ip
    for ip in ("1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "not an ip", ""):
        assert netinfo.classify_ip(ip) == "internet", ip
    # documentation / benchmark / reserved ranges are "private" to ipaddress but never on the LAN
    for ip in ("192.0.2.1", "198.51.100.7", "203.0.113.9", "198.18.0.1", "240.0.0.1"):
        assert netinfo.classify_ip(ip) == "internet", ip
    assert netinfo.classify_ip("fd7a:115c:a1e0::1") == "local"  # IPv6 ULA
    # inside a configured (non-private) local network -> local; outside -> internet
    fake = [_fake_adapter(ipv4=[netinfo.IpAddr("100.100.7.7", 16, 4, "255.255.0.0", "100.100.0.0/16")], gateways=[])]
    assert netinfo.classify_ip("100.100.5.5", fake) == "local"
    assert netinfo.classify_ip("100.101.5.5", fake) == "internet"
    assert netinfo.classify_ip("::ffff:10.0.0.1") == "local"
    assert netinfo.classify_ip("::ffff:8.8.8.8") == "internet"


def test_local_networks_excludes_link_local_and_loopback():
    fake = [
        _fake_adapter(),
        _fake_adapter(index=13, name="Wi-Fi", status="down",
                      ipv4=[netinfo.IpAddr("169.254.10.10", 16, 4, "255.255.0.0", "169.254.0.0/16")], gateways=[]),
        _fake_adapter(index=1, name="Loopback", if_type=24, is_loopback=True, is_physical=False,
                      ipv4=[netinfo.IpAddr("127.0.0.1", 8, 4, "255.0.0.0", "127.0.0.0/8")], gateways=[]),
        _fake_adapter(index=18, name="Tailscale", if_type=53,
                      ipv4=[netinfo.IpAddr("100.101.102.103", 32, 4, "255.255.255.255", "100.101.102.103/32")],
                      ipv6=[netinfo.IpAddr("fe80::1", 64, 6, None, "fe80::/64", scope_id=18),
                            netinfo.IpAddr("fd7a:115c:a1e0::1234:5678", 48, 6, None, "fd7a:115c:a1e0::/48")],
                      gateways=[]),
    ]
    nets = [str(n) for n in netinfo.local_networks(fake)]
    assert nets == ["10.0.0.0/24", "100.101.102.103/32", "fd7a:115c:a1e0::/48"]


def test_subnet_groups_fake_adapter():
    a = _fake_adapter(
        ipv4=[
            netinfo.IpAddr("10.0.0.112", 24, 4, "255.255.255.0", "10.0.0.0/24"),
            netinfo.IpAddr("10.0.0.113", 24, 4, "255.255.255.0", "10.0.0.0/24"),
            netinfo.IpAddr("192.168.50.2", 24, 4, "255.255.255.0", "192.168.50.0/24"),
        ],
        ipv6=[netinfo.IpAddr("fe80::1234:5678:9abc:def0", 64, 6, None, "fe80::/64", scope_id=12)],
        gateways=["10.0.0.251", "172.16.0.1", "fe80::fffe%12"],
    )
    groups = netinfo.subnet_groups(a)
    assert groups[0] == {"network": "10.0.0.0/24", "family": 4, "mask": "255.255.255.0",
                         "addresses": ["10.0.0.112", "10.0.0.113"], "gateways": ["10.0.0.251"]}
    assert groups[1] == {"network": "192.168.50.0/24", "family": 4, "mask": "255.255.255.0",
                         "addresses": ["192.168.50.2"], "gateways": []}
    assert groups[2] == {"network": "fe80::/64", "family": 6, "mask": None,
                         "addresses": ["fe80::1234:5678:9abc:def0"], "gateways": ["fe80::fffe%12"]}
    assert groups[3] == {"network": None, "family": 4, "mask": None, "addresses": [], "gateways": ["172.16.0.1"]}
    assert netinfo.subnet_groups(_fake_adapter(ipv4=[], gateways=[])) == []


def test_internet_nic_fallback_by_metric(monkeypatch):
    monkeypatch.setattr(netinfo, "_route_source_ip", lambda *a, **k: None)
    slow = _fake_adapter(index=5, name="Slow", metric_v4=50)
    fast = _fake_adapter(index=7, name="Fast", metric_v4=10,
                         ipv4=[netinfo.IpAddr("192.168.1.10", 24, 4, "255.255.255.0", "192.168.1.0/24")],
                         gateways=["192.168.1.1"])
    down = _fake_adapter(index=9, name="Down", status="down", metric_v4=1)
    nogw = _fake_adapter(index=11, name="NoGw", metric_v4=1, gateways=[])
    assert netinfo.get_internet_nic([slow, fast, down, nogw]).name == "Fast"
    assert netinfo.get_internet_nic([down, nogw]) is None
    # route probe wins when its IP matches an adapter
    monkeypatch.setattr(netinfo, "_route_source_ip", lambda *a, **k: "10.0.0.112")
    assert netinfo.get_internet_nic([slow, fast]).name == "Slow"


def test_adapter_to_dict_and_snapshot_are_json():
    a = _fake_adapter(ipv4=[netinfo.IpAddr("10.0.0.112", 24, 4, "255.255.255.0", "10.0.0.0/24", dad_state=1, preferred=False),
                            netinfo.IpAddr("10.0.0.113", 24, 4, "255.255.255.0", "10.0.0.0/24")])
    d = a.to_dict()
    for key in ("index", "name", "description", "mac", "if_type", "type_name", "status", "speed_bps", "mtu",
                "dhcp_enabled", "dhcp_server", "dns_suffix", "ipv4", "ipv6", "gateways", "dns", "metric_v4",
                "is_physical", "is_loopback", "subnets", "primary_ipv4"):
        assert key in d, key
    assert d["primary_ipv4"] == "10.0.0.113"          # first *preferred* address
    assert d["ipv4"][0]["address"] == "10.0.0.112"    # tentative address still listed
    assert d["subnets"][0]["gateways"] == ["10.0.0.251"]
    json.dumps(d)

    snap = netinfo.netinfo_snapshot()
    assert set(snap) == {"ts", "adapters", "internet_nic_index", "default_gateway", "public_hint"}
    assert snap["public_hint"] is None and isinstance(snap["ts"], float)
    json.dumps(snap)
    if snap["internet_nic_index"] is not None:
        assert snap["adapters"][0]["index"] == snap["internet_nic_index"]
        assert snap["default_gateway"] is not None
    for ad in snap["adapters"]:
        assert "subnets" in ad and not ad["is_loopback"]


def test_preferred_ipv4_listed_first():
    """engine.py reads nic.ipv4[0]: a tentative/duplicate address enumerated before the
    real one must not become the reported IP. Order among equals is Windows' order."""
    tentative = netinfo._make_ipaddr("169.254.10.10", 4, 16, 1, 0)
    dup = netinfo._make_ipaddr("10.0.0.7", 4, 24, 3, 0)
    good = netinfo._make_ipaddr("10.0.0.112", 4, 24, 4, 0)
    good2 = netinfo._make_ipaddr("10.0.0.113", 4, 24, 4, 0)
    ordered = netinfo._preferred_first([tentative, good, dup, good2])
    assert [x.address for x in ordered] == ["10.0.0.112", "10.0.0.113", "169.254.10.10", "10.0.0.7"]
    a = _fake_adapter(ipv4=ordered)
    assert a.ipv4[0].address == a.primary_ipv4 == "10.0.0.112"
    assert netinfo._preferred_first([tentative]) == [tentative]   # nothing preferred: unchanged
    for real in netinfo.get_adapters(include_loopback=True):
        if any(x.preferred for x in real.ipv4):
            assert real.ipv4[0].preferred and real.ipv4[0].address == real.primary_ipv4, real.name


def test_netinfo_never_raises(monkeypatch):
    def boom():
        raise OSError(5, "simulated GetAdaptersAddresses failure")

    netinfo._invalidate_cache()
    monkeypatch.setattr(netinfo, "_query_adapters", boom)
    try:
        assert netinfo.get_adapters() == []
        assert netinfo.get_internet_nic() is None
        assert netinfo.get_default_gateway() is None
        assert netinfo.local_networks() == []
        assert netinfo.classify_ip("10.1.2.3") == "local"
        assert netinfo.classify_ip("9.9.9.9") == "internet"
        snap = netinfo.netinfo_snapshot()
        assert snap["adapters"] == [] and snap["internet_nic_index"] is None and snap["default_gateway"] is None
    finally:
        netinfo._invalidate_cache()


def test_adapter_cache_is_short_lived():
    netinfo._invalidate_cache()
    first = netinfo.get_adapters()
    again = netinfo.get_adapters()
    assert [a.index for a in first] == [a.index for a in again]
    assert first is not again  # callers get their own list
    netinfo._invalidate_cache()
    assert [a.index for a in netinfo.get_adapters()] == [a.index for a in first]


# =========================================================================================
# arp
# =========================================================================================
@pytest.mark.skipif(not X64, reason="x64 layout")
def test_arp_row_layout():
    assert sizeof(arp.SOCKADDR_INET) == 28
    assert sizeof(arp.MIB_IPNET_ROW2) == 88
    assert arp.MIB_IPNET_ROW2.InterfaceIndex.offset == 28
    assert arp.MIB_IPNET_ROW2.InterfaceLuid.offset == 32
    assert arp.MIB_IPNET_ROW2.PhysicalAddress.offset == 40
    assert arp.MIB_IPNET_ROW2.PhysicalAddressLength.offset == 72
    assert arp.MIB_IPNET_ROW2.State.offset == 76
    assert arp._ROWS_OFFSET == 8


def _assert_normalised(table):
    assert isinstance(table, dict)
    for ip, mac in table.items():
        addr = ipaddress.IPv4Address(ip)
        assert not addr.is_multicast and ip != "255.255.255.255"
        assert MAC_RE.match(mac), mac
        assert not int(mac[:2], 16) & 0x01, f"multicast/broadcast MAC kept: {ip} {mac}"


def test_arp_native_matches_arp_command():
    native = arp.get_arp_table_native()
    cmd = arp.get_arp_table_cmd()
    _assert_normalised(native)
    _assert_normalised(cmd)
    common = set(native) & set(cmd)
    for ip in common:
        assert native[ip] == cmd[ip], ip
    # the cache is live, so allow a couple of entries to age in/out between the two calls
    assert len(set(native) ^ set(cmd)) <= 2, (native, cmd)
    if len(cmd) >= 3:
        assert len(native) >= len(cmd) - 2, "native path returned far fewer entries than 'arp -a'"


def test_get_arp_table_public_never_raises(monkeypatch):
    table = arp.get_arp_table()
    _assert_normalised(table)
    calls = []

    def fail_native():
        calls.append("native")
        raise OSError(1, "simulated GetIpNetTable2 failure")

    monkeypatch.setattr(arp, "get_arp_table_native", fail_native)
    fallback = arp.get_arp_table()
    _assert_normalised(fallback)
    assert calls == ["native"]
    assert len(set(fallback) ^ set(table)) <= 2

    def fail_cmd(timeout_s=10.0):
        raise subprocess.TimeoutExpired("arp", timeout_s)

    monkeypatch.setattr(arp, "get_arp_table_cmd", fail_cmd)
    assert arp.get_arp_table() == {}


def test_parse_arp_output_filters_and_normalises():
    text = """
Interface: 10.0.0.112 --- 0x9
  Internet Address      Physical Address      Type
  10.0.0.70             00-00-5e-00-53-ab     dynamic
  10.0.0.251            00-00-5e-00-53-01     dynamic
  10.0.0.255            ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static

Interface: 100.101.102.103 --- 0x12
  Internet Address      Physical Address      Type
  100.100.100.100       00-00-00-00-00-00     static
  10.0.0.70             00:00:5E:00:53:AB     dynamic
"""
    table = arp.parse_arp_output(text)
    assert table == {
        "10.0.0.70": "00:00:5E:00:53:AB",
        "10.0.0.251": "00:00:5E:00:53:01",
    }
    assert "100.100.100.100" not in table          # all-zero placeholder MAC is not a device
    assert arp.parse_arp_output("") == {}
    assert arp.parse_arp_output("No ARP Entries Found.") == {}


def test_parse_arp_output_localised_windows():
    """The type column is localised (and may be mangled by a wrong code page); only the
    IP/MAC columns matter. Lines end in trailing spaces + CRLF on real Windows."""
    text = (
        "\r\nInterfaz: 10.0.0.112 --- 0x9\r\n"
        "  Direcci\u00f3n de Internet     Direcci\u00f3n f\u00edsica      Tipo\r\n"
        "  10.0.0.70             00-00-5e-00-53-ab     din\u00e1mico   \r\n"
        "  10.0.0.71             00-00-5e-00-53-11     din\ufffdmico   \r\n"
        "  10.0.0.72             00-00-5e-00-53-12     \u52a8\u6001\r\n"
        "  10.0.0.73             d6-12-34-56-78-9a     est\u00e1tico\r\n"
        "  10.0.0.74             00-00-5e-00-53-14\r\n"
        "  10.0.0.75             00-00-5e-00-53-1\r\n"
        "  10.0.0.76             00-00-5e-00-53-14-01  din\u00e1mico\r\n"
        "  10.0.0.255            ff-ff-ff-ff-ff-ff     est\u00e1tico\r\n"
    )
    assert arp.parse_arp_output(text) == {
        "10.0.0.70": "00:00:5E:00:53:AB",
        "10.0.0.71": "00:00:5E:00:53:11",
        "10.0.0.72": "00:00:5E:00:53:12",
        "10.0.0.73": "D6:12:34:56:78:9A",   # locally administered (randomized)
        "10.0.0.74": "00:00:5E:00:53:14",   # no type column at all
    }                                        # .75 truncated MAC and .76 seven octets are not matches


def test_get_arp_table_cmd_decodes_oem_code_page(monkeypatch):
    text = (
        "Interfaz: 10.0.0.112 --- 0x9\r\n"
        "  Direcci\u00f3n de Internet     Direcci\u00f3n f\u00edsica      Tipo\r\n"
        "  10.0.0.70             00-00-5e-00-53-ab     din\u00e1mico\r\n"
        "  10.0.0.251            00-00-5e-00-53-01     est\u00e1tico\r\n"
    )
    oem_cp = ctypes.windll.kernel32.GetOEMCP()
    raw = text.encode(f"cp{oem_cp}", errors="replace")
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout=raw, stderr=b"")

    monkeypatch.setattr(arp.subprocess, "run", fake_run)
    assert arp.get_arp_table_cmd(timeout_s=2.5) == {"10.0.0.70": "00:00:5E:00:53:AB",
                                                    "10.0.0.251": "00:00:5E:00:53:01"}
    assert calls and calls[0][0][-1] == "-a" and calls[0][1]["timeout"] == 2.5
    assert arp._decode_console(raw) == text.encode(f"cp{oem_cp}", errors="replace").decode(f"cp{oem_cp}")
    assert arp._decode_console(b"") == ""
    assert arp._decode_console(b"\xff\xfe garbage")          # never raises


def test_arp_usable_filter():
    assert arp._usable("10.0.0.5", "00:00:5E:00:53:AB") is True
    assert arp._usable("10.0.0.5", "00:00:00:00:00:00") is False     # null placeholder
    assert arp._usable("10.0.0.255", "FF:FF:FF:FF:FF:FF") is False   # broadcast
    assert arp._usable("224.0.0.22", "01:00:5E:00:00:16") is False   # multicast
    assert arp._usable("0.0.0.0", "00:00:5E:00:53:AB") is False
    assert arp._usable("255.255.255.255", "00:00:5E:00:53:AB") is False
    assert arp._usable("not-an-ip", "00:00:5E:00:53:AB") is False


def test_arp_native_rejects_implausible_row_count(monkeypatch):
    """A corrupt NumEntries (layout mismatch) must raise so get_arp_table() falls back."""

    class FakeDll:
        freed = False

        def GetIpNetTable2(self, family, out_ptr):
            self.keep = ctypes.create_string_buffer(64)
            ctypes.c_ulong.from_address(ctypes.addressof(self.keep)).value = 0xFFFFFFFF
            out_ptr._obj.value = ctypes.addressof(self.keep)
            return 0

        def FreeMibTable(self, table):
            self.freed = True

    fake = FakeDll()
    monkeypatch.setattr(arp, "_dll", lambda: fake)
    with pytest.raises(OSError):
        arp.get_arp_table_native()
    assert fake.freed is True
    monkeypatch.setattr(arp, "get_arp_table_cmd", lambda timeout_s=10.0: {"10.0.0.1": "00:00:5E:00:53:AB"})
    assert arp.get_arp_table() == {"10.0.0.1": "00:00:5E:00:53:AB"}


def _fake_neighbour_dll(rows):
    """A stand-in for iphlpapi whose GetIpNetTable2 answers IPv4 *rows* of ``(interface index, ip, MAC hex, NL_NEIGHBOR_STATE)``
    and counts FreeMibTable calls."""

    class FakeDll:
        freed = 0

        def GetIpNetTable2(self, family, out_ptr):
            self.keep = ctypes.create_string_buffer(arp._ROWS_OFFSET + ctypes.sizeof(arp.MIB_IPNET_ROW2) * len(rows))
            base = ctypes.addressof(self.keep)
            ctypes.c_ulong.from_address(base).value = len(rows)
            for row, (index, ip, mac, state) in zip((arp.MIB_IPNET_ROW2 * len(rows)).from_address(base + arp._ROWS_OFFSET), rows):
                row.Address.si_family = arp.AF_INET
                row.Address.Ipv4.sin_addr[:] = list(ipaddress.IPv4Address(ip).packed)
                row.InterfaceIndex = index
                row.PhysicalAddress[:6] = list(bytes.fromhex(mac))
                row.PhysicalAddressLength = 6
                row.State = state
            out_ptr._obj.value = base
            return 0

        def FreeMibTable(self, table):
            self.freed += 1

    return FakeDll()


def test_arp_native_leaves_out_the_neighbours_of_an_adapter_that_is_down(monkeypatch):
    """GetIpNetTable2 keeps the last neighbours of an adapter that went down (a Wi-Fi adapter switched off leaves Stale rows);
    ``arp -a`` does not list that interface, and neither does the native table, even where the down adapter's row has the
    better state."""
    from types import SimpleNamespace

    rows = [(13, "192.0.2.10", "02005e100001", 4), (11, "192.0.2.11", "02005e100002", 4), (11, "192.0.2.10", "02005e100003", 5)]
    adapters = [SimpleNamespace(index=11, is_up=False), SimpleNamespace(index=13, is_up=True)]
    monkeypatch.setattr(netinfo, "get_adapters", lambda include_down=True, include_loopback=False: list(adapters))
    assert arp._down_interfaces() == {11}
    fake = _fake_neighbour_dll(rows)
    monkeypatch.setattr(arp, "_dll", lambda: fake)
    assert arp.get_arp_table_native() == {"192.0.2.10": "02:00:5E:10:00:01"} and fake.freed == 1
    # the adapters cannot be listed: nothing is left out (the better state wins as before)
    monkeypatch.setattr(netinfo, "get_adapters", lambda include_down=True, include_loopback=False: 1 / 0)
    assert arp._down_interfaces() == set()
    assert arp.get_arp_table_native() == {"192.0.2.10": "02:00:5E:10:00:03", "192.0.2.11": "02:00:5E:10:00:02"}


def test_neighbour_lookup_leaves_out_the_rows_of_an_adapter_that_is_down(monkeypatch):
    """neighbour(ip) with no interface keeps the best state among the rows for *ip*: a Stale row that an adapter kept after it
    went down must not beat the Delay row of the adapter that is up (it names the router of a network this PC has left)."""
    from types import SimpleNamespace

    rows = [(11, "192.0.2.1", "02005e100001", 4), (13, "192.0.2.1", "02005e100002", 3)]
    adapters = [SimpleNamespace(index=11, is_up=False), SimpleNamespace(index=13, is_up=True)]
    monkeypatch.setattr(netinfo, "get_adapters", lambda include_down=True, include_loopback=False: list(adapters))
    fake = _fake_neighbour_dll(rows)
    monkeypatch.setattr(arp, "_dll", lambda: fake)
    assert arp.neighbour_rows_native(arp.AF_INET) == [("192.0.2.1", 13, "02:00:5E:10:00:02", "delay")] and fake.freed == 1
    assert arp.neighbour("192.0.2.1") == ("02:00:5E:10:00:02", "delay")
    assert arp.neighbour("192.0.2.1", 11) is None and arp.neighbour("192.0.2.1", 13) == ("02:00:5E:10:00:02", "delay")
    # the adapters cannot be listed: nothing is left out, and the better state wins as before
    monkeypatch.setattr(netinfo, "get_adapters", lambda include_down=True, include_loopback=False: 1 / 0)
    assert arp.neighbour("192.0.2.1") == ("02:00:5E:10:00:01", "stale")


# =========================================================================================
# oui
# =========================================================================================
@pytest.mark.parametrize("raw", ["00-00-5e-00-53-ab", "0000.5e00.53ab", "00:00:5E:00:53:AB", "00005e0053ab",
                                 "  00:00:5e:00:53:ab\n", "00 00 5E 00 53 AB"])
def test_normalize_mac_forms(raw):
    assert oui.normalize_mac(raw) == "00:00:5E:00:53:AB"


@pytest.mark.parametrize("bad", ["", "zz", "00:00:5E:00:53", "00:00:5E:00:53:AB:00", "00-00-5e-00-53-ag",
                                 "192.168.1.1", None, 12345])
def test_normalize_mac_rejects_garbage(bad):
    assert oui.normalize_mac(bad) is None  # type: ignore[arg-type]


def test_vendor_lookup_known_oui():
    v = oui.vendor_for_mac("3C:22:FB:00:00:01")
    assert v is not None and "Apple" in v
    assert oui.vendor_for_mac("3c-22-fb-00-00-01") == v
    assert "Apple" in oui.vendor_for_mac("3c22.fb00.0001")


@pytest.mark.parametrize("mac", ["02:12:34:56:78:9A", "D6:12:34:56:78:9A", "0A:12:34:56:78:9A", "0E:12:34:56:78:9A",
                                 "DA:12:34:56:78:9A", "5E:12:34:56:78:9A"])
def test_vendor_randomized_mac(mac):
    assert oui.is_randomized_mac(mac) is True
    if oui._registered_org(oui.normalize_mac(mac)[:13]) is None:
        assert oui.vendor_for_mac(mac) == "Locally administered (randomized)"


def test_vendor_null_mac_is_none():
    # netaddr registers 00-00-00 to Xerox; the all-zero MAC is a placeholder, not a device
    assert oui.vendor_for_mac("00:00:00:00:00:00") is None
    assert oui.vendor_for_mac("00-00-00-00-00-00") is None
    assert oui.vendor_for_mac("00:00:00:00:00:01") == oui._registered_org("00:00:00:00:0")
    assert oui.NULL_MAC == arp.NULL_MAC


def test_vendor_iab_prefix_beats_generic_oui():
    """00-50-C2 (and 70-B3-D5) belong to the IEEE Registration Authority; the 36-bit IAB
    block under it names the real owner and must win over the 24-bit OUI."""
    from netaddr import EUI

    expected = EUI("00:50:C2:00:10:00").iab.registration().org
    assert expected and "IEEE Registration Authority" not in expected
    oui._registered_org.cache_clear()
    assert oui.vendor_for_mac("00:50:C2:00:10:00") == expected
    assert oui.vendor_for_mac("00:50:C2:00:1F:FF") == expected     # same 36-bit block
    # an address in the OUI but outside any IAB block still resolves through the OUI
    assert oui.vendor_for_mac("70:B3:D5:00:10:00") == "IEEE Registration Authority"


def test_vendor_unregistered_lookup_is_quiet(caplog):
    oui._registered_org.cache_clear()
    with caplog.at_level(logging.DEBUG, logger="tnt.oui"):
        assert oui.vendor_for_mac("02:12:34:56:78:9A") == oui.RANDOMIZED_TEXT
        assert oui.vendor_for_mac("00:50:C2:00:10:00")           # IAB range resolves through .iab
    assert not [r for r in caplog.records if "lookup failed" in r.getMessage()]


def test_vendor_broadcast_multicast_and_garbage_are_none():
    assert oui.vendor_for_mac("FF:FF:FF:FF:FF:FF") is None
    assert oui.vendor_for_mac("01:00:5E:00:00:16") is None
    assert oui.vendor_for_mac("garbage") is None
    assert oui.vendor_for_mac("") is None
    assert oui.is_randomized_mac("FF:FF:FF:FF:FF:FF") is False
    assert oui.is_randomized_mac("3C:22:FB:00:00:01") is False


def test_vendor_lookup_is_cached_and_fast():
    oui.vendor_for_mac("3C:22:FB:00:00:02")
    t0 = time.perf_counter()
    for i in range(500):
        oui.vendor_for_mac(f"3C:22:FB:00:{i % 256:02X}:03")
    assert time.perf_counter() - t0 < 1.0


# =========================================================================================
# netinfo: adapter warnings, one enumeration, identity fields (synthetic adapters)
# =========================================================================================
def _v4(addr: str, prefix: int, dad: int = 4) -> "netinfo.IpAddr":
    return netinfo._make_ipaddr(addr, 4, prefix, dad, 0)


def test_adapter_warnings_rules():
    def codes(a, *args):
        return [w["code"] for w in netinfo.adapter_warnings(a, *args)]

    healthy = _fake_adapter()
    assert netinfo.adapter_warnings(healthy) == [] and healthy.to_dict()["warnings"] == []
    apipa = _fake_adapter(ipv4=[_v4("169.254.23.45", 16)], gateways=[], dns=[], dhcp_server=None)
    assert codes(apipa) == ["apipa"] and "169.254.23.45" in netinfo.adapter_warnings(apipa)[0]["message"]
    both = _fake_adapter(ipv4=[_v4("10.0.0.112", 24), _v4("169.254.7.7", 16, dad=1)])    # a tentative extra next to a lease
    assert codes(both) == []
    dup = _fake_adapter(ipv4=[_v4("172.16.20.15", 24, dad=netinfo.IP_DAD_STATE_DUPLICATE)], gateways=["172.16.20.1"])
    assert codes(dup) == ["duplicate_address"] and "172.16.20.15" in netinfo.adapter_warnings(dup)[0]["message"]
    typo = _fake_adapter(ipv4=[_v4("10.20.31.45", 24)], gateways=["10.20.30.1"], dns=["10.20.30.53"])
    w = netinfo.adapter_warnings(typo)
    assert [x["code"] for x in w] == ["gateway_outside_subnet"]
    assert "10.20.30.1" in w[0]["message"] and "10.20.31.0/24" in w[0]["message"]
    assert codes(_fake_adapter(dns=[])) == ["no_dns"]
    assert codes(_fake_adapter(dns=[], gateways=[])) == [], "without a gateway, no DNS server is expected"
    temp = _fake_adapter(ipv6=[netinfo._make_ipaddr("2001:db8:10::a1b2:c3d4", 6, 128, netinfo.IP_DAD_STATE_DEPRECATED, 0, 4, 5)])
    assert codes(temp) == [], "a deprecated IPv6 temporary address is normal, never a duplicate"
    assert codes(_fake_adapter(status="down", dns=[])) == []
    # two default gateways: reported on the internet NIC only, and only while the other adapter is up
    wifi = _fake_adapter(index=7, name="Wi-Fi", mac="02:00:5E:10:00:07", ipv4=[_v4("192.168.10.23", 24)],
                         gateways=["192.168.10.1"], dns=["192.168.10.1"])
    eth = _fake_adapter()
    assert codes(eth, [eth, wifi], 12) == ["multiple_default_gateways"]
    assert "Wi-Fi" in netinfo.adapter_warnings(eth, [eth, wifi], 12)[0]["message"]
    assert codes(wifi, [eth, wifi], 12) == [] and codes(eth) == []
    wifi.status = "down"
    assert codes(eth, [eth, wifi], 12) == []


def test_a_self_assigned_address_is_only_blamed_on_dhcp_when_dhcp_is_to_blame():
    def codes(a):
        return [w["code"] for w in netinfo.adapter_warnings(a)]

    # a static address another device already uses: Windows falls back to 169.254.x.x, but no DHCP server was asked
    dup = _fake_adapter(ipv4=[_v4("192.168.1.10", 24, dad=netinfo.IP_DAD_STATE_DUPLICATE), _v4("169.254.10.20", 16)],
                        gateways=["192.168.1.1"], dns=["192.168.1.1"], dhcp_enabled=False, dhcp_server=None)
    assert codes(dup) == ["duplicate_address"]
    # the same on a DHCP adapter whose lease collided: the duplicate is the problem worth naming
    assert codes(_fake_adapter(ipv4=[_v4("10.0.0.112", 24, dad=netinfo.IP_DAD_STATE_DUPLICATE), _v4("169.254.7.7", 16)],
                               dns=["10.0.0.251"])) == ["duplicate_address"]
    assert codes(_fake_adapter(ipv4=[_v4("169.254.10.20", 16)], gateways=[], dns=[], dhcp_enabled=False, dhcp_server=None)) == []
    # DHCPv4 unanswered next to working IPv6: still no DHCP server, and the message says the network may be IPv6-only
    v6only = _fake_adapter(ipv4=[_v4("169.254.30.40", 16)], gateways=["fe80::1"], dns=["2001:db8:77::53"], dhcp_server=None,
                           ipv6=[netinfo._make_ipaddr("2001:db8:77::1a2b", 6, 64, netinfo.IP_DAD_STATE_PREFERRED, 0, 4, 4)])
    w = netinfo.adapter_warnings(v6only)
    assert [x["code"] for x in w] == ["apipa"] and w[0]["message"].endswith("(IPv6 works: this network may be IPv6-only)")
    plain = netinfo.adapter_warnings(_fake_adapter(ipv4=[_v4("169.254.30.40", 16)], gateways=[], dns=[], dhcp_server=None))
    assert plain[0]["message"] == "Self-assigned address 169.254.30.40: no DHCP server answered"


def test_default_gateway_and_snapshot_come_from_one_enumeration(monkeypatch):
    wifi = _fake_adapter(index=7, name="Wi-Fi", mac="02:00:5E:10:00:07", ipv4=[_v4("192.168.10.23", 24)],
                         gateways=["192.168.10.1"], dns=["192.168.10.1"], metric_v4=45)
    eth = _fake_adapter()
    tunnel = _fake_adapter(index=30, name="Example VPN", mac="", if_type=53, type_name="Tunnel", is_physical=False,
                           ipv4=[_v4("10.8.0.2", 32)], gateways=[], dns=["10.8.0.1"], dhcp_enabled=False, dhcp_server=None)
    assert netinfo.default_gateway_for([wifi, eth], eth) == "10.0.0.251"
    assert netinfo.default_gateway_for([wifi, eth, tunnel], tunnel) == "10.0.0.251", "tunnel without a gateway: the LAN router"
    assert netinfo.default_gateway_for([], None) is None
    v6only = _fake_adapter(ipv4=[], gateways=["fe80::1%12"])
    assert netinfo.default_gateway_for([v6only], v6only) == "fe80::1%12"
    calls = []

    def query():
        calls.append(1)
        if len(calls) > 1:
            raise OSError(31, "simulated failure: a second enumeration would see nothing")
        return [wifi, eth]

    monkeypatch.setattr(netinfo, "_query_adapters", query)
    monkeypatch.setattr(netinfo, "_route_source_ip", lambda probe=("1.1.1.1", 53): "10.0.0.112")
    netinfo._invalidate_cache()
    try:
        snap = netinfo.netinfo_snapshot()
        assert calls == [1] and snap["default_gateway"] == "10.0.0.251" and snap["internet_nic_index"] == 12
        assert [a["name"] for a in snap["adapters"]] == ["Ethernet", "Wi-Fi"]
        assert [x["code"] for x in snap["adapters"][0]["warnings"]] == ["multiple_default_gateways"]
        assert snap["adapters"][1]["warnings"] == []
        assert "guid" not in snap["adapters"][0] and "luid" not in snap["adapters"][0]
        assert not {"prefix_origin", "suffix_origin"} & set(snap["adapters"][0]["ipv4"][0])
        netinfo._invalidate_cache()
        assert netinfo.get_default_gateway([wifi, eth]) == "10.0.0.251" and calls == [1]
    finally:
        netinfo._invalidate_cache()
    temp = netinfo._make_ipaddr("2001:db8:10::a1b2:c3d4", 6, 128, 3, 0, 4, 5)
    assert (temp.prefix_origin, temp.suffix_origin, temp.preferred) == (4, 5, False)
    assert "suffix_origin" not in temp.to_dict()


def test_adapter_identity_fields_real_machine():
    adapters = netinfo.get_adapters()
    assert adapters
    for a in adapters:
        assert a.guid.startswith("{") and a.guid.endswith("}") and a.luid > 0, a.name
