"""Tests for tnt.dhcp (the Tools-page DHCP server) and the dhcp_leases table in tnt.db.

No network beyond 127.0.0.1, never port 67, never a real netsh: sockets and subprocess.run
are always fakes except in the loopback end-to-end test at the bottom (port 0 on 127.0.0.1).
"""
from __future__ import annotations

import json
import queue
import socket
import struct
import subprocess
import threading
import time
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest

from tnt import config as tnt_config
from tnt import db as tnt_db
from tnt import dhcp
from tnt import events as tnt_events
from tnt.icmp import PingResult
from tnt.netinfo import Adapter, IpAddr

T0 = 1_700_000_000.0
MAC_A = "AA:BB:CC:DD:EE:01"
MAC_B = "AA:BB:CC:DD:EE:02"
NIC_MAC = "00:00:5E:00:53:10"


# =========================================================================================
# fakes
# =========================================================================================
class FakeClock:
    def __init__(self, t: float = T0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += max(0.0, float(s))


class FakePinger:
    """``alive`` addresses answer; every call is recorded."""

    def __init__(self, alive: Optional[set] = None) -> None:
        self.alive = set(alive or ())
        self.calls: List[Tuple[str, int]] = []

    def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
        self.calls.append((ip, timeout_ms))
        ok = ip in self.alive
        return PingResult(ok=ok, rtt_ms=1.5 if ok else None, status=0 if ok else 11010, error=None, ttl=64, size=size, ip=ip)

    def close(self):
        pass


#: ``IP_DAD_STATE`` values: 1 = tentative (duplicate-address detection running), 3 = duplicate, 4 = preferred
DAD_TENTATIVE, DAD_DUPLICATE, DAD_PREFERRED = 1, 3, 4


def ipaddr(address: str, prefix: int, dad_state: int = DAD_PREFERRED) -> IpAddr:
    net = f"{address}/{prefix}"
    import ipaddress
    iface = ipaddress.IPv4Interface(net)
    return IpAddr(address=address, prefix=prefix, family=4, netmask=str(iface.network.netmask), network=str(iface.network),
                  dad_state=dad_state, preferred=dad_state == DAD_PREFERRED)


def adapter(name="Ethernet", ip="10.0.0.112", prefix=24, dhcp_enabled=True, dhcp_server="10.0.0.251", gateway="10.0.0.251",
            mac=NIC_MAC, index=12, if_type=6, status="up", is_physical=True) -> Adapter:
    return Adapter(index=index, name=name, description="Intel(R) Ethernet Connection", mac=mac, if_type=if_type,
                   type_name="Ethernet" if if_type == 6 else "Other", status=status, speed_bps=None, mtu=1500,
                   dhcp_enabled=dhcp_enabled, dhcp_server=dhcp_server if dhcp_enabled else None, dns_suffix="",
                   ipv4=[ipaddr(ip, prefix)] if ip else [], ipv6=[], gateways=[gateway] if gateway else [], dns=[],
                   metric_v4=25, is_physical=is_physical, is_loopback=False)


class NicSim:
    """Holds the adapter list and reacts to netsh like Windows would (static/dhcp switch)."""

    def __init__(self, adapters: List[Adapter], firewall_present: Optional[str] = None) -> None:
        self.adapters = adapters
        # keyed by ifindex: Windows renames NICs, the index stays (tests rename adapters)
        self.original: Dict[int, Tuple[List[IpAddr], bool]] = {a.index: (list(a.ipv4), a.dhcp_enabled) for a in adapters}
        self.commands: List[List[str]] = []
        self.kwargs: List[dict] = []
        self.fail_static = False
        self.static_rc = 0                          # non-zero: apply the address but report that code (a netsh timeout)
        self.static_dad = DAD_PREFERRED             # DAD state a freshly set static address starts in
        self.dad_sequence: List[int] = []           # DAD states the static address walks through, one per get_adapters()
        self.static_entry: Optional[IpAddr] = None  # the static address netsh last set (dad_sequence applies to it)
        self.fail_restore = False
        self.restore_noop = False                   # "source=dhcp" exits 0 but leaves the static address in place
        self.firewall_program = firewall_present    # program path of an existing rule (None = no rule)
        self.firewall_ports = "67,68"               # LocalPort of that rule ("67" = an older build's rule)
        self.firewall_added: List[str] = []
        self.firewall_deleted = 0

    def get_adapters(self):
        if self.dad_sequence and self.static_entry is not None:
            # Windows walks a new static address tentative -> preferred (or duplicate) over a
            # few polls; every fresh look advances one step
            state = self.dad_sequence.pop(0)
            self.static_entry.dad_state, self.static_entry.preferred = state, state == DAD_PREFERRED
        return list(self.adapters)

    def find(self, name: str) -> Optional[Adapter]:
        return next((a for a in self.adapters if a.name == name), None)

    def __call__(self, argv, **kwargs):
        self.commands.append(list(argv))
        self.kwargs.append(kwargs)
        args = argv[1:]
        rc, out = 0, b""
        if args[:4] == ["interface", "ipv4", "set", "address"]:
            name = args[4].split("=", 1)[1]
            a = self.find(name)
            if "source=static" in args:
                if self.fail_static or a is None:
                    rc, out = 1, b"The system cannot find the file specified."
                else:
                    ip = next(x.split("=", 1)[1] for x in args if x.startswith("address="))
                    mask = next(x.split("=", 1)[1] for x in args if x.startswith("mask="))
                    import ipaddress
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                    self.static_entry = ipaddr(ip, prefix, self.static_dad)
                    a.ipv4 = [self.static_entry]
                    a.dhcp_enabled = False
                    rc = self.static_rc
            elif "source=dhcp" in args:
                if self.fail_restore or a is None:
                    rc, out = 1, b"Element not found."
                elif self.restore_noop:
                    out = b"DHCP is already enabled on this interface.\r\n"
                else:
                    a.ipv4, a.dhcp_enabled = list(self.original[a.index][0]), self.original[a.index][1]
                    self.static_entry = None
        elif args[:2] == ["advfirewall", "firewall"]:
            if args[2] == "show":
                if self.firewall_program is None:
                    rc, out = 1, b"\r\nNo rules match the specified criteria.\r\n"
                else:
                    out = ("\r\nRule Name: TNT DHCP server (UDP 67 in)\r\n" + "-" * 60 + "\r\nEnabled: Yes\r\nDirection: In\r\n"
                           f"Program: {self.firewall_program}\r\nLocalPort: {self.firewall_ports}\r\nRemotePort: Any\r\n"
                           "Protocol: UDP\r\nAction: Allow\r\nOk.\r\n").encode()
            elif args[2] == "add":
                prog = next(x.split("=", 1)[1] for x in args if x.startswith("program="))
                self.firewall_added.append(prog)
                self.firewall_program = prog
                self.firewall_ports = next(x.split("=", 1)[1] for x in args if x.startswith("localport="))
                out = b"Ok.\r\n"
            elif args[2] == "delete":
                self.firewall_deleted += 1
                self.firewall_program = None
                out = b"Deleted 1 rule(s).\r\nOk.\r\n"
        return SimpleNamespace(returncode=rc, stdout=out, stderr=b"")


class FakeSocket:
    """UDP socket stand-in: records what was sent, delivers what tests inject."""

    def __init__(self, factory: "FakeSocketFactory") -> None:
        self.factory = factory
        self.bound: Optional[Tuple[str, int]] = None
        self.opts: List[tuple] = []
        self.sent: List[Tuple[bytes, Tuple[str, int]]] = []
        self.inbox: "queue.Queue[Tuple[bytes, Tuple[str, int]]]" = queue.Queue()
        self.closed = False
        self.timeout: Optional[float] = None
        self.recv_errors: List[BaseException] = []     # raised (in order) by the next recvfrom calls

    def setsockopt(self, level, opt, value):
        self.opts.append((level, opt, value))

    def bind(self, addr):
        port = addr[1] or 67
        if addr[0] in self.factory.fail_bind or (addr[0], port) in self.factory.fail_bind:
            raise OSError(10048, "Only one usage of each socket address is normally permitted")
        self.bound = (addr[0], port)

    def getsockname(self):
        return self.bound

    def settimeout(self, t):
        self.timeout = t

    def fileno(self):
        return -1

    def sendto(self, data, addr):
        self.sent.append((bytes(data), addr))
        hook = self.factory.on_send
        if hook is not None:
            for raw, src in hook(self, bytes(data), addr) or []:
                self.inbox.put((raw, src))
        return len(data)

    def inject(self, raw: bytes, src: Tuple[str, int]) -> None:
        self.inbox.put((raw, src))

    def readable(self, timeout: float) -> bool:
        if not self.inbox.empty():
            return True
        try:
            item = self.inbox.get(timeout=timeout)
        except queue.Empty:
            return False
        self.inbox.put(item)
        return True

    def recvfrom(self, n):
        if self.recv_errors:
            raise self.recv_errors.pop(0)
        try:
            return self.inbox.get(timeout=self.timeout if self.timeout is not None else 0.05)
        except queue.Empty:
            raise socket.timeout("timed out")

    def close(self):
        self.closed = True


class FakeSocketFactory:
    def __init__(self) -> None:
        self.sockets: List[FakeSocket] = []
        self.fail_bind: set = set()          # IPs (or (ip, port) pairs) whose bind fails with 10048
        self.on_send = None

    def __call__(self, family, kind):
        s = FakeSocket(self)
        self.sockets.append(s)
        return s

    def bound_to(self, ip: str, port: int = 67) -> Optional[FakeSocket]:
        return next((s for s in self.sockets if s.bound == (ip, port)), None)


# =========================================================================================
# packet builders
# =========================================================================================
def tlv(code: int, value: bytes) -> bytes:
    return bytes([code, len(value)]) + value


def build(mtype: int, mac: str = MAC_A, xid: int = 0x11223344, opts: Optional[Dict[int, bytes]] = None, ciaddr: str = "0.0.0.0",
          giaddr: str = "0.0.0.0", flags: int = 0, op: int = 1, yiaddr: str = "0.0.0.0", secs: int = 0,
          client_id: bool = True, hostname: Optional[str] = "cam-12") -> bytes:
    mac6 = bytes.fromhex(mac.replace(":", ""))
    hdr = dhcp.HDR.pack(op, 1, 6, 0, xid, secs, flags, socket.inet_aton(ciaddr), socket.inet_aton(yiaddr), b"\0" * 4,
                        socket.inet_aton(giaddr), mac6 + b"\0" * 10, b"\0" * 64, b"\0" * 128)
    body = tlv(53, bytes([mtype]))
    if client_id:
        body += tlv(61, b"\x01" + mac6)
    if hostname:
        body += tlv(12, hostname.encode())
    for code, value in (opts or {}).items():
        body += tlv(code, value)
    body += tlv(55, bytes([1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]))
    return (hdr + dhcp.MAGIC + body + b"\xff").ljust(300, b"\0")


def ip4(text: str) -> bytes:
    return socket.inet_aton(text)


def u32(n: int) -> bytes:
    return struct.pack("!I", n)


# =========================================================================================
# codec
# =========================================================================================
def test_decode_round_trip_and_helpers():
    raw = build(dhcp.DISCOVER, opts={50: ip4("10.0.0.5"), 51: u32(7200)}, flags=0x8000, secs=3)
    p = dhcp.decode(raw)
    assert p is not None and p.op == 1 and p.xid == 0x11223344 and p.mac == MAC_A and p.secs == 3
    assert p.msg_type == dhcp.DISCOVER and p.broadcast is True
    assert p.ciaddr is None and p.giaddr is None and p.yiaddr is None
    assert p.client_id() == b"\x01" + bytes.fromhex(MAC_A.replace(":", ""))
    assert p.client_id_hex() == "01aabbccddee01"
    assert p.requested_ip() == "10.0.0.5" and p.server_id() is None
    assert p.hostname() == "cam-12" and p.lease_request() == 7200
    assert p.param_list()[:3] == [1, 3, 6]
    assert len(p.chaddr) == 16
    # without option 61 the MAC is the key
    p2 = dhcp.decode(build(dhcp.DISCOVER, client_id=False, hostname=None))
    assert p2.client_id() == bytes.fromhex(MAC_A.replace(":", "")) and p2.client_id_hex() is None and p2.hostname() is None


def test_decode_rejects_garbage_bootp_and_replies():
    assert dhcp.decode(b"") is None
    assert dhcp.decode(b"\x01" * 100) is None
    assert dhcp.decode(None) is None  # type: ignore[arg-type]
    raw = build(dhcp.DISCOVER)
    assert dhcp.decode(raw[:239]) is None                               # too short for the cookie
    assert dhcp.decode(raw[:236] + b"\0\0\0\0" + raw[240:]) is None     # BOOTP: no magic cookie
    assert dhcp.decode(bytearray(raw)) is not None
    # a truncated option keeps what was parsed before it and never raises
    cut = raw[:240] + tlv(53, b"\x01") + bytes([50, 4, 10, 0])
    p = dhcp.decode(cut)
    assert p is not None and p.msg_type == dhcp.DISCOVER and 50 not in p.opts
    # repeated codes concatenate (RFC 3396)
    twice = raw[:240] + tlv(53, b"\x01") + tlv(12, b"ab") + tlv(12, b"cd") + b"\xff"
    assert dhcp.decode(twice).opts[12] == b"abcd"
    # replies are ignored on the server path unless asked for
    reply = build(dhcp.OFFER, op=2)
    assert dhcp.decode(reply) is None
    assert dhcp.decode(reply, allow_reply=True).op == 2
    # unknown message type -> msg_type None; non-Ethernet htype rejected
    assert dhcp.decode(raw[:240] + tlv(53, b"\x63") + b"\xff").msg_type is None
    bad_htype = bytearray(raw)
    bad_htype[1] = 6
    assert dhcp.decode(bytes(bad_htype)) is None


def test_encode_copies_header_fields_and_pads():
    req = dhcp.decode(build(dhcp.DISCOVER, xid=0xCAFEBABE, flags=0x8000, giaddr="10.0.0.9"))
    out = dhcp.encode(req, dhcp.OFFER, "172.16.4.101", [(54, ip4("172.16.4.100")), (51, u32(3600))], "172.16.4.100")
    assert len(out) == 300
    op, htype, hlen, hops, xid, secs, flags, ci, yi, si, gi, chaddr, sname, fname = dhcp.HDR.unpack_from(out)
    assert (op, htype, hlen, hops, xid, secs, flags) == (2, 1, 6, 0, 0xCAFEBABE, 0, 0x8000)
    assert ci == b"\0" * 4 and yi == ip4("172.16.4.101") and si == ip4("172.16.4.100") and gi == ip4("10.0.0.9")
    assert chaddr == req.chaddr and sname == b"\0" * 64 and fname == b"\0" * 128
    assert out[236:240] == dhcp.MAGIC
    rep = dhcp.decode(out, allow_reply=True)
    assert rep.msg_type == dhcp.OFFER and rep.opts[54] == ip4("172.16.4.100") and rep.opts[51] == u32(3600)
    # ACK to a renewing client keeps ciaddr; NAK has neither siaddr nor yiaddr
    renew = dhcp.decode(build(dhcp.REQUEST, ciaddr="172.16.4.101"))
    ack = dhcp.encode(renew, dhcp.ACK, "172.16.4.101", [], "172.16.4.100")
    assert dhcp.HDR.unpack_from(ack)[7] == ip4("172.16.4.101")
    nak = dhcp.encode(renew, dhcp.NAK, None, [(56, b"nope")], "172.16.4.100")
    fields = dhcp.HDR.unpack_from(nak)
    assert fields[7] == b"\0" * 4 and fields[8] == b"\0" * 4 and fields[9] == b"\0" * 4
    # RFC 2131 4.3.2: a NAK to a relayed request MUST carry the BROADCAST flag (the client has
    # no address the relay could unicast to); other replies copy the client's flags verbatim
    relayed = dhcp.decode(build(dhcp.REQUEST, giaddr="172.16.4.9", flags=0, opts={50: ip4("192.168.9.9")}))
    assert dhcp.HDR.unpack_from(dhcp.encode(relayed, dhcp.NAK, None, [(56, b"wrong subnet")], "172.16.4.100"))[6] == 0x8000
    assert dhcp.HDR.unpack_from(dhcp.encode(relayed, dhcp.OFFER, "172.16.4.101", [], "172.16.4.100"))[6] == 0
    assert dhcp.HDR.unpack_from(dhcp.encode(renew, dhcp.NAK, None, [], "172.16.4.100"))[6] == 0         # not relayed


def test_reply_dest_rules():
    src = ("10.0.0.7", 68)
    relayed = dhcp.decode(build(dhcp.DISCOVER, giaddr="10.0.0.1"))
    assert dhcp.reply_dest(relayed, src, dhcp.OFFER) == ("10.0.0.1", 67)
    plain = dhcp.decode(build(dhcp.REQUEST))
    assert dhcp.reply_dest(plain, ("0.0.0.0", 68), dhcp.NAK) == ("255.255.255.255", 68)
    assert dhcp.reply_dest(plain, ("10.0.0.7", 68), dhcp.NAK) == ("255.255.255.255", 68)
    renew = dhcp.decode(build(dhcp.REQUEST, ciaddr="10.0.0.7"))
    assert dhcp.reply_dest(renew, ("10.0.0.7", 68), dhcp.ACK) == ("10.0.0.7", 68)
    assert dhcp.reply_dest(plain, ("127.0.0.1", 51000), dhcp.OFFER) == ("127.0.0.1", 51000)
    assert dhcp.reply_dest(plain, ("0.0.0.0", 68), dhcp.OFFER) == ("255.255.255.255", 68)
    assert dhcp.reply_dest(plain, ("0.0.0.0", 68), dhcp.ACK) == ("255.255.255.255", 68)
    # the BROADCAST flag wins over a non-zero source: a device that fell back to 169.254.x.x
    # sends from that address, and a unicast to it from our static NIC has no route
    apipa = dhcp.decode(build(dhcp.DISCOVER, flags=0x8000))
    assert dhcp.reply_dest(apipa, ("169.254.23.5", 68), dhcp.OFFER) == ("255.255.255.255", 68)
    assert dhcp.reply_dest(apipa, ("169.254.23.5", 68), dhcp.ACK) == ("255.255.255.255", 68)
    assert dhcp.reply_dest(renew, ("10.0.0.7", 68), dhcp.ACK) == ("10.0.0.7", 68)       # ciaddr still comes first


# =========================================================================================
# pool maths
# =========================================================================================
def test_default_pool_cases():
    assert dhcp.default_pool("172.16.4.100", 24, 5) == ("172.16.4.101", "172.16.4.105")
    assert dhcp.default_pool("10.0.0.112", 24, 5, exclude=["10.0.0.251"]) == ("10.0.0.113", "10.0.0.117")
    # gateway right after the server: the window skips it
    assert dhcp.default_pool("10.0.0.112", 24, 3, exclude=["10.0.0.113"]) == ("10.0.0.114", "10.0.0.116")
    # near the top of the subnet the pool sits right before the server
    assert dhcp.default_pool("172.16.4.253", 24, 5, exclude=["172.16.4.254"]) == ("172.16.4.248", "172.16.4.252")
    assert dhcp.default_pool("172.16.4.252", 24, 2) == ("172.16.4.253", "172.16.4.254")
    with pytest.raises(ValueError):
        dhcp.default_pool("10.0.0.1", 30, 5)
    with pytest.raises(ValueError):
        dhcp.default_pool("10.0.0.1", 24, 0)
    with pytest.raises(ValueError):
        dhcp.default_pool("not-an-ip", 24, 5)


def test_validate_pool_rejections():
    ok = dhcp.validate_pool("172.16.4.101", "172.16.4.105", "172.16.4.100", 24, None)
    assert ok == ("172.16.4.101", "172.16.4.105")
    assert dhcp.validate_pool(" 10.0.0.20 ", "10.0.0.30", "10.0.0.112", 24, "10.0.0.251") == ("10.0.0.20", "10.0.0.30")
    with pytest.raises(ValueError, match="subnet"):
        dhcp.validate_pool("10.0.1.5", "10.0.1.9", "10.0.0.112", 24, None)
    with pytest.raises(ValueError, match="before"):
        dhcp.validate_pool("10.0.0.30", "10.0.0.20", "10.0.0.112", 24, None)
    with pytest.raises(ValueError, match="must not contain"):
        dhcp.validate_pool("10.0.0.107", "10.0.0.117", "10.0.0.112", 24, None)          # server inside
    with pytest.raises(ValueError, match="must not contain"):
        dhcp.validate_pool("10.0.0.247", "10.0.0.251", "10.0.0.112", 24, "10.0.0.251")  # gateway = the inclusive pool end
    with pytest.raises(ValueError, match="must not contain"):
        dhcp.validate_pool("10.0.0.0", "10.0.0.5", "10.0.0.112", 24, None)              # network address
    with pytest.raises(ValueError, match="at most"):
        dhcp.validate_pool("10.0.0.1", "10.0.0.255", "10.0.1.1", 16, None)
    with pytest.raises(ValueError, match="pool start"):
        dhcp.validate_pool("x", "10.0.0.5", "10.0.0.112", 24, None)


# =========================================================================================
# lease table
# =========================================================================================
def make_table(db=None, start="172.16.4.101", end="172.16.4.105"):
    t = dhcp.LeaseTable(db, clock=FakeClock())
    t.set_pool(start, end)
    t.set_reserved(["172.16.4.100"])
    return t


def test_pick_address_order_and_ping_quarantine():
    t = make_table()
    alive = FakePinger(alive={"172.16.4.101"})
    key_a, key_b = b"\x01A", b"\x01B"
    # the first pool address answers a ping -> quarantined, the next one is offered
    ip = t.pick_address(key_a, None, T0, ping_fn=lambda ip: alive.ping(ip).ok)
    assert ip == "172.16.4.102" and alive.calls[0][0] == "172.16.4.101"
    assert t.bad["172.16.4.101"] == T0 + dhcp.PING_HOLD_S
    lease = t.offer(key_a, MAC_A, ip, T0, "cam", "0141", 1)
    assert lease.state == "offered" and t.by_ip[ip] == key_a
    # a second client cannot get an address that is offered to the first
    assert t.pick_address(key_b, "172.16.4.102", T0 + 1) == "172.16.4.103"
    # the first client's binding wins over what it asks for, and is not pinged again
    alive.calls.clear()
    assert t.pick_address(key_a, "172.16.4.104", T0 + 1, ping_fn=lambda ip: alive.ping(ip).ok) == "172.16.4.102"
    assert alive.calls == []
    # at most two pings per DISCOVER: everything alive -> give up (the client retries)
    everything = FakePinger(alive={"172.16.4.103", "172.16.4.104", "172.16.4.105"})
    assert t.pick_address(key_b, None, T0 + 2, ping_fn=lambda ip: everything.ping(ip).ok) is None
    assert len(everything.calls) == 2
    # holds expire
    t.expire(T0 + dhcp.PING_HOLD_S + 1)
    assert "172.16.4.101" not in t.bad


def test_offer_expiry_decline_hold_and_returning_mac():
    t = make_table()
    key = b"\x01A"
    t.offer(key, MAC_A, "172.16.4.101", T0, xid=1)
    # an offer nobody takes disappears after OFFER_TTL_S and frees the address
    gone = t.expire(T0 + dhcp.OFFER_TTL_S + 1)
    assert [lz.mac for lz in gone] == [MAC_A] and t.get(key) is None and "172.16.4.101" not in t.by_ip
    # bind, let it expire, and see the returning MAC get the same address back
    t.offer(key, MAC_A, "172.16.4.101", T0 + 100, xid=2)
    lease = t.bind(key, 3600, T0 + 100)
    assert lease.state == "bound" and lease.expires_ts == T0 + 3700
    assert t.pick_address(b"\x01B", "172.16.4.101", T0 + 200) == "172.16.4.102"      # taken while bound
    changed = t.expire(T0 + 3701)
    assert changed[0].state == "expired" and t.get(key).expires_ts is None
    assert t.pick_address(key, None, T0 + 4000) == "172.16.4.101"                     # previous binding first
    # another client can take an expired address; the dead record is then dropped
    assert t.pick_address(b"\x01B", "172.16.4.101", T0 + 4000) == "172.16.4.101"
    t.offer(b"\x01B", MAC_B, "172.16.4.101", T0 + 4000, xid=3)
    assert t.get(key) is None and t.by_ip["172.16.4.101"] == b"\x01B"
    # DECLINE quarantines for DECLINE_HOLD_S and drops the binding
    t.decline(b"\x01B", "172.16.4.101", T0 + 4001)
    assert t.bad["172.16.4.101"] == T0 + 4001 + dhcp.DECLINE_HOLD_S and t.get(b"\x01B").state == "declined"
    assert t.pick_address(b"\x01B", "172.16.4.101", T0 + 4002) == "172.16.4.102"
    assert t.counts()["total"] == 1
    # release keeps the record for reuse
    t.offer(key, MAC_A, "172.16.4.103", T0 + 5000, xid=4)
    t.bind(key, 600, T0 + 5000)
    assert t.release(key, T0 + 5001).state == "released"
    assert t.pick_address(key, None, T0 + 5002) == "172.16.4.103"
    assert t.forget(MAC_A) is True and t.get(key) is None


def test_lease_table_persists_through_database(tmp_path):
    db = tnt_db.Database(tmp_path / "t.db")
    try:
        t = make_table(db)
        key = b"\x01" + bytes.fromhex(MAC_A.replace(":", ""))
        t.offer(key, MAC_A, "172.16.4.101", T0, "cam-12", "01aabbccddee01", 7)
        t.bind(key, 3600, T0 + 1)
        t.update_probe(key, {"hostname": None, "vendor": "Hikvision", "ping_ok": True, "rtt_ms": 1.2, "open_ports": [80, 554]}, T0 + 5)
        t.offer(b"\x01B", MAC_B, "172.16.4.102", T0 + 2, xid=8)   # an offer that never binds
        rows = db.list_dhcp_leases()
        assert {r["mac"]: r["state"] for r in rows} == {MAC_A: "bound", MAC_B: "offered"}
        got = db.get_dhcp_lease(MAC_A)
        assert got["ip"] == "172.16.4.101" and got["hostname"] == "cam-12" and got["vendor"] == "Hikvision"
        assert got["open_ports"] == [80, 554] and got["ping_ok"] is True and got["probed_ts"] == T0 + 5
        assert got["client_id"] == "01aabbccddee01" and got["expires_ts"] == T0 + 3601
        assert db.counts()["dhcp_leases"] == 2
        # reload as after a restart: the bound lease is live, the offer is not carried over
        t2 = dhcp.LeaseTable(db, clock=FakeClock(T0 + 10))
        t2.set_pool("172.16.4.101", "172.16.4.105")
        assert t2.load(db.list_dhcp_leases(), T0 + 10) == 2
        live = t2.get(key)
        assert live.state == "bound" and live.ip == "172.16.4.101" and live.open_ports == [80, 554] and live.hostname == "cam-12"
        assert t2.get_by_mac(MAC_B).state == "expired"        # no option 61 -> keyed by MAC after a reload
        # .101 is still reserved for the bound client; .102 (expired offer of another client)
        # ranks after the never-used .103
        assert t2.pick_address(b"\x01C", "172.16.4.101", T0 + 10) == "172.16.4.103"
        rows = t2.to_rows()
        assert rows[0]["mac"] == MAC_A and set(rows[0]) == {
            "ip", "mac", "hostname", "vendor", "ping_ok", "rtt_ms", "open_ports", "client_id", "state", "first_ts", "last_ts",
            "expires_ts", "probed_ts", "probing"}
        # a lease that ran out while the service was down loads as expired
        t3 = dhcp.LeaseTable(db, clock=FakeClock(T0 + 5000))
        t3.set_pool("172.16.4.101", "172.16.4.105")
        t3.load(db.list_dhcp_leases(), T0 + 5000)
        assert t3.get(key).state == "expired" and db.get_dhcp_lease(MAC_A)["state"] == "expired"   # written through
        # db helpers
        db.upsert_dhcp_lease({"mac": "AA:BB:CC:DD:EE:09", "ip": "172.16.4.109", "state": "bound", "first_ts": T0, "last_ts": T0,
                              "expires_ts": T0 + 60})
        assert db.expire_dhcp_leases(T0 + 5000) == 1 and db.get_dhcp_lease("AA:BB:CC:DD:EE:09")["state"] == "expired"
        assert db.delete_dhcp_lease("AA:BB:CC:DD:EE:09") is True
        db.set_dhcp_lease_state(MAC_A, "released", T0 + 6000)
        assert db.get_dhcp_lease(MAC_A)["state"] == "released" and db.get_dhcp_lease(MAC_A)["last_ts"] == T0 + 6000
        assert db.list_dhcp_leases(include_expired=False) == []
        assert db.list_dhcp_leases(limit=1)[0]["mac"] == MAC_A
        assert db.retention(365, now=T0 + 400 * 86400)["dhcp_leases"] == 2
        assert db.delete_dhcp_lease(MAC_A) is False
        db.upsert_dhcp_lease({"mac": "aa:bb:cc:dd:ee:03", "ip": "172.16.4.103", "state": "bound", "first_ts": T0, "last_ts": T0, "expires_ts": T0 + 60})
        assert db.get_dhcp_lease("AA:BB:CC:DD:EE:03")["ip"] == "172.16.4.103"
        assert db.delete_dhcp_lease("AA:BB:CC:DD:EE:03") is True
        with pytest.raises(ValueError):
            db.upsert_dhcp_lease({"mac": "", "ip": "1.2.3.4"})
        assert db.clear_dhcp_leases() == 0
    finally:
        db.close()


def test_decline_hold_survives_a_restart(tmp_path):
    """A DECLINEd address (somebody squats on it) stays quarantined across stop/start: the
    hold is rebuilt from the row's last_ts, and offered again only once DECLINE_HOLD_S is up."""
    db = tnt_db.Database(tmp_path / "t.db")
    try:
        t = make_table(db)
        key = b"\x01A"
        t.offer(key, MAC_A, "172.16.4.101", T0, xid=1)
        t.bind(key, 3600, T0 + 1)
        t.decline(key, "172.16.4.101", T0 + 2)
        assert db.get_dhcp_lease(MAC_A)["state"] == "declined"
        t2 = make_table(db)
        t2.load(db.list_dhcp_leases(), T0 + 100)
        assert t2.bad == {"172.16.4.101": T0 + 2 + dhcp.DECLINE_HOLD_S}
        assert t2.pick_address(key, None, T0 + 100) == "172.16.4.102"                     # still held after the restart
        assert t2.pick_address(b"\x01B", "172.16.4.101", T0 + 100) == "172.16.4.102"
        t3 = make_table(db)
        t3.load(db.list_dhcp_leases(), T0 + 2 + dhcp.DECLINE_HOLD_S + 1)
        assert t3.bad == {}                                                                 # the hold ran out while down
    finally:
        db.close()


# =========================================================================================
# netsh: NIC control, restore-at-start, firewall
# =========================================================================================
def test_nic_controller_argv_and_record(tmp_path):
    db = tnt_db.Database(tmp_path / "t.db")
    sim = NicSim([adapter()])
    clock = FakeClock()
    nic = dhcp.NicController(runner=sim, adapters_fn=sim.get_adapters, db=db, sleep=clock.sleep, clock=clock)
    seen_before: List[Optional[str]] = []
    real_call = sim.__call__

    def spy(argv, **kw):
        seen_before.append(db.get_meta("dhcp.nic_changed"))
        return real_call(argv, **kw)

    nic._runner = spy
    rec = nic.set_static("Ethernet", "172.16.4.100", 24)
    assert sim.commands[-1][1:] == ["interface", "ipv4", "set", "address", "name=Ethernet", "source=static",
                                    "address=172.16.4.100", "mask=255.255.255.0", "store=active"]
    assert sim.commands[-1][0].lower().endswith("netsh.exe") or sim.commands[-1][0] == "netsh"
    kw = sim.kwargs[-1]
    assert kw["stdin"] is subprocess.DEVNULL and kw["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
    assert kw["timeout"] > 0 and kw["check"] is False and kw["capture_output"] is True
    # the record was in the database before netsh ran, and describes the adapter
    assert seen_before[0] is not None
    stored = json.loads(db.get_meta("dhcp.nic_changed"))
    assert stored["adapter"] == "Ethernet" and stored["index"] == 12 and stored["mac"] == NIC_MAC
    assert stored["static_ip"] == "172.16.4.100" and stored["prefix"] == 24 and stored["ts"] == T0
    assert rec["static_ip"] == "172.16.4.100"
    assert sim.find("Ethernet").ipv4[0].address == "172.16.4.100"
    # restore: set address source=dhcp only -- never "set dnsservers source=dhcp", which would
    # wipe DNS servers the user typed in by hand on a DHCP adapter (the tool never touched
    # DNS); record cleared once the address is gone
    n_before = len(sim.commands)
    assert nic.restore_dhcp("Ethernet", expect_gone="172.16.4.100") is True
    assert [c[1:] for c in sim.commands[n_before:]] == [["interface", "ipv4", "set", "address", "name=Ethernet", "source=dhcp"]]
    assert not any("dnsservers" in c for c in sim.commands)
    assert not db.get_meta("dhcp.nic_changed")
    assert sim.find("Ethernet").dhcp_enabled is True and sim.find("Ethernet").ipv4[0].address == "10.0.0.112"
    # the restore command "succeeds" but the static address stays (persistent store already
    # said DHCP): the record is the only trail left -- kept with attempts + 1, False returned
    nic.set_static("Ethernet", "172.16.4.100", 24)
    sim.restore_noop = True
    clock.t = T0 + 100
    assert nic.restore_dhcp("Ethernet", expect_gone="172.16.4.100") is False
    assert clock.t >= T0 + 100 + dhcp.NIC_SETTLE_S                          # waited the settle window
    stored = json.loads(db.get_meta("dhcp.nic_changed"))
    assert stored["adapter"] == "Ethernet" and stored["static_ip"] == "172.16.4.100" and stored["attempts"] == 1
    assert sim.find("Ethernet").ipv4[0].address == "172.16.4.100" and sim.find("Ethernet").dhcp_enabled is False
    sim.restore_noop = False
    assert nic.restore_dhcp("Ethernet", expect_gone="172.16.4.100") is True and not db.get_meta("dhcp.nic_changed")
    # duplicate-address detection: the address is only "present" once Windows calls it
    # preferred (a bind to a tentative address fails); tentative polls just take time
    sim.dad_sequence = [DAD_TENTATIVE, DAD_TENTATIVE, DAD_PREFERRED]
    clock.t = T0 + 200
    nic.set_static("Ethernet", "172.16.4.100", 24)
    assert sim.dad_sequence == [] and T0 + 200.5 <= clock.t < T0 + 200 + dhcp.NIC_SETTLE_S
    assert sim.find("Ethernet").ipv4[0].preferred is True
    assert nic.restore_dhcp("Ethernet", expect_gone="172.16.4.100") is True
    # ... while a *duplicate* (a bench box already on 172.16.4.100) fails the change and the
    # adapter goes straight back to DHCP, record cleared
    sim.static_dad = DAD_DUPLICATE
    sim.commands.clear()
    with pytest.raises(RuntimeError, match="static address 172.16.4.100 is already used on this network"):
        nic.set_static("Ethernet", "172.16.4.100", 24)
    assert [c[3:6] for c in sim.commands] == [["set", "address", "name=Ethernet"]] * 2
    assert "source=static" in sim.commands[0] and "source=dhcp" in sim.commands[1]
    assert sim.find("Ethernet").dhcp_enabled is True and sim.find("Ethernet").ipv4[0].address == "10.0.0.112"
    assert not db.get_meta("dhcp.nic_changed")
    sim.static_dad = DAD_PREFERRED
    assert nic.address_state("Ethernet", "10.0.0.112") == "preferred" and nic.address_state("Ethernet", "1.2.3.4") == "absent"
    assert nic.address_state("Nope", "10.0.0.112") == "absent"
    # failures: netsh error -> RuntimeError, record kept for the next start
    sim.fail_static = True
    with pytest.raises(RuntimeError, match="static address"):
        nic.set_static("Ethernet", "172.16.4.100", 24)
    assert json.loads(db.get_meta("dhcp.nic_changed"))["adapter"] == "Ethernet"
    assert sim.find("Ethernet").dhcp_enabled is True
    # netsh applied the address but exited non-zero (a timeout while it released the old
    # lease): the adapter is put straight back on DHCP instead of being left static
    sim.fail_static = False
    sim.static_rc = 1460
    sim.commands.clear()
    with pytest.raises(RuntimeError, match="netsh exit 1460"):
        nic.set_static("Ethernet", "172.16.4.100", 24)
    assert [c[3:6] for c in sim.commands] == [["set", "address", "name=Ethernet"]] * 2
    assert "source=static" in sim.commands[0] and "source=dhcp" in sim.commands[1]
    assert sim.find("Ethernet").dhcp_enabled is True and sim.find("Ethernet").ipv4[0].address == "10.0.0.112"
    assert not db.get_meta("dhcp.nic_changed")
    sim.static_rc = 0
    sim.fail_restore = True
    assert nic.restore_dhcp("Ethernet") is False
    with pytest.raises(ValueError):
        nic.set_static("Ethernet", "not-an-ip", 24)
    db.close()


def test_run_netsh_never_raises():
    def boom(argv, **kw):
        raise FileNotFoundError("netsh")

    rc, out = dhcp._run_netsh(["x"], runner=boom)
    assert rc == 9009 and "not found" in out

    def slow(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw.get("timeout"))

    rc, out = dhcp._run_netsh(["x"], runner=slow)
    assert rc == 1460 and "timed out" in out
    rc, out = dhcp._run_netsh(["x"], runner=lambda argv, **kw: SimpleNamespace(returncode=0, stdout=b"Ok.\r\n", stderr=b""))
    assert (rc, out) == (0, "Ok.")


def test_restore_nic_on_start(tmp_path):
    db = tnt_db.Database(tmp_path / "t.db")
    sim = NicSim([adapter()])
    # no record -> nothing happens, no netsh
    assert dhcp.restore_nic_on_start(db, runner=sim, adapters_fn=sim.get_adapters) is None
    assert sim.commands == []
    # a record from a crashed run: restored by name and cleared
    sim.find("Ethernet").ipv4 = [ipaddr("172.16.4.100", 24)]
    sim.find("Ethernet").dhcp_enabled = False
    db.set_meta("dhcp.nic_changed", json.dumps({"adapter": "Ethernet", "index": 12, "mac": NIC_MAC, "static_ip": "172.16.4.100",
                                                "prefix": 24, "ts": T0}))
    done = dhcp.restore_nic_on_start(db, runner=sim, adapters_fn=sim.get_adapters, sleep=lambda s: None)
    assert done == {"adapter": "Ethernet", "restored": True, "static_ip": "172.16.4.100"}
    assert [c[1:] for c in sim.commands] == [["interface", "ipv4", "set", "address", "name=Ethernet", "source=dhcp"]]
    assert not db.get_meta("dhcp.nic_changed") and sim.find("Ethernet").dhcp_enabled is True
    # a stale record on an adapter that is already back on DHCP (a reboot undid the
    # store=active change): nothing is run, the record is dropped
    sim.commands.clear()
    db.set_meta("dhcp.nic_changed", json.dumps({"adapter": "Ethernet", "mac": NIC_MAC, "static_ip": "172.16.4.100", "prefix": 24}))
    r = dhcp.restore_nic_on_start(db, runner=sim, adapters_fn=sim.get_adapters, sleep=lambda s: None)
    assert r == {"adapter": "Ethernet", "restored": False, "already_dhcp": True}
    assert sim.commands == [] and not db.get_meta("dhcp.nic_changed")
    # the tech re-addressed the port by hand in the meantime (static, but not on our address):
    # it is left alone and the record is dropped
    sim.find("Ethernet").ipv4 = [ipaddr("192.168.1.10", 24)]
    sim.find("Ethernet").dhcp_enabled = False
    db.set_meta("dhcp.nic_changed", json.dumps({"adapter": "Ethernet", "mac": NIC_MAC, "static_ip": "172.16.4.100", "prefix": 24}))
    r = dhcp.restore_nic_on_start(db, runner=sim, adapters_fn=sim.get_adapters, sleep=lambda s: None)
    assert r["restored"] is False and r["dropped"] is True and "hand" in r["reason"]
    assert sim.commands == [] and not db.get_meta("dhcp.nic_changed")
    assert sim.find("Ethernet").ipv4[0].address == "192.168.1.10" and sim.find("Ethernet").dhcp_enabled is False
    # renamed adapter, still on our static address: matched by MAC and restored
    sim.find("Ethernet").ipv4 = [ipaddr("172.16.4.100", 24)]
    sim.adapters[0].name = "Ethernet 2"
    db.set_meta("dhcp.nic_changed", json.dumps({"adapter": "Ethernet", "mac": NIC_MAC, "static_ip": "172.16.4.100", "prefix": 24}))
    assert dhcp.restore_nic_on_start(db, runner=sim, adapters_fn=sim.get_adapters, sleep=lambda s: None)["adapter"] == "Ethernet 2"
    assert sim.commands[0][5] == "name=Ethernet 2"
    assert sim.find("Ethernet 2").dhcp_enabled is True and not db.get_meta("dhcp.nic_changed")
    # a failing restore is retried on later starts, then dropped
    sim.find("Ethernet 2").ipv4 = [ipaddr("172.16.4.100", 24)]
    sim.find("Ethernet 2").dhcp_enabled = False
    sim.fail_restore = True
    db.set_meta("dhcp.nic_changed", json.dumps({"adapter": "Ethernet 2", "mac": NIC_MAC, "static_ip": "172.16.4.100", "prefix": 24}))
    for attempt in range(1, dhcp.RESTORE_MAX_ATTEMPTS):
        r = dhcp.restore_nic_on_start(db, runner=sim, adapters_fn=sim.get_adapters, sleep=lambda s: None)
        assert r["restored"] is False and r["attempts"] == attempt
        assert json.loads(db.get_meta("dhcp.nic_changed"))["attempts"] == attempt
    r = dhcp.restore_nic_on_start(db, runner=sim, adapters_fn=sim.get_adapters, sleep=lambda s: None)
    assert r["dropped"] is True and not db.get_meta("dhcp.nic_changed")
    # garbage record and a broken db never raise
    db.set_meta("dhcp.nic_changed", "{not json")
    assert dhcp.restore_nic_on_start(db, runner=sim, adapters_fn=sim.get_adapters) is None
    assert dhcp.restore_nic_on_start(SimpleNamespace(get_meta=lambda k: 1 / 0), runner=sim) is None
    db.close()


def test_ensure_firewall_rule_sequencing():
    exe = r"C:\Program Files\TNT\TNTService.exe"
    # missing -> show, add
    sim = NicSim([])
    assert dhcp.ensure_firewall_rule(exe, runner=sim) == (True, None)
    assert [c[1:5] for c in sim.commands] == [["advfirewall", "firewall", "show", "rule"], ["advfirewall", "firewall", "add", "rule"]]
    add = sim.commands[1][1:]
    # 67 for requests and relay-probe replies, 68 for the client-style probe's broadcast OFFERs
    assert add == ["advfirewall", "firewall", "add", "rule", f"name={dhcp.FIREWALL_RULE_NAME}", "dir=in", "action=allow",
                   f"program={exe}", "protocol=udp", "localport=67,68", "profile=any"]
    assert sim.commands[0][5] == f"name={dhcp.FIREWALL_RULE_NAME}" and sim.firewall_ports == "67,68"
    # present for the same program -> show only (idempotent)
    sim.commands.clear()
    assert dhcp.ensure_firewall_rule(exe.lower(), runner=sim) == (True, None)
    assert len(sim.commands) == 1 and sim.commands[0][3] == "show"
    # present for another program (dev python) -> delete, add
    sim.commands.clear()
    sim.firewall_program = r"C:\Python312\python.exe"
    assert dhcp.ensure_firewall_rule(exe, runner=sim) == (True, None)
    assert [c[3] for c in sim.commands] == ["show", "delete", "add"] and sim.firewall_program == exe
    assert sim.commands[1][1:] == ["advfirewall", "firewall", "delete", "rule", f"name={dhcp.FIREWALL_RULE_NAME}"]
    # an older build's 67-only rule for the right program -> replaced as well
    sim.commands.clear()
    sim.firewall_ports = "67"
    assert dhcp.ensure_firewall_rule(exe, runner=sim) == (True, None)
    assert [c[3] for c in sim.commands] == ["show", "delete", "add"] and sim.firewall_ports == "67,68"
    # add failing -> (False, error), never raises
    failing = lambda argv, **kw: SimpleNamespace(returncode=1, stdout=b"", stderr=b"The requested operation requires elevation.")
    ok, err = dhcp.ensure_firewall_rule(exe, runner=failing)
    assert ok is False and "elevation" in err
    # no explicit path -> the running interpreter (dev runs)
    import sys as _sys
    sim.commands.clear()
    sim.firewall_program = None
    assert dhcp.ensure_firewall_rule(None, runner=sim) == (True, None) and sim.firewall_program == _sys.executable
    # uninstaller helper
    sim.commands.clear()
    assert dhcp.delete_firewall_rule(runner=sim) == (True, None)
    assert sim.commands[0][1:] == ["advfirewall", "firewall", "delete", "rule", f"name={dhcp.FIREWALL_RULE_NAME}"]
    assert dhcp.delete_firewall_rule(runner=failing)[0] is False


# =========================================================================================
# probe_host / scan_for_servers
# =========================================================================================
def test_probe_host_with_fakes():
    pinger = FakePinger(alive={"172.16.4.101"})
    calls: List[Tuple[str, int, float]] = []

    def connect(ip, port, timeout):
        calls.append((ip, port, timeout))
        return port in (80, 554)

    r = dhcp.probe_host("172.16.4.101", [80, 443, 554, "8080", 0, 70000, True], pinger, ping_timeout_ms=300, port_timeout_s=0.2,
                        tcp_connect=connect, resolver=lambda ip: "cam-12", vendor_fn=lambda mac: "Hikvision", mac="aa-bb-cc-dd-ee-01")
    assert set(r) == {"ip", "hostname", "mac", "vendor", "ping_ok", "rtt_ms", "open_ports"}
    assert r["ping_ok"] is True and r["rtt_ms"] == 1.5 and r["open_ports"] == [80, 554]
    assert r["hostname"] == "cam-12" and r["vendor"] == "Hikvision" and r["mac"] == MAC_A
    assert pinger.calls == [("172.16.4.101", 300)] and sorted(p for _ip, p, _t in calls) == [80, 443, 554, 8080]
    # nothing answers, everything raises: still a well-formed result
    def boom(*a):
        raise RuntimeError("no")

    r2 = dhcp.probe_host("172.16.4.102", [80], FakePinger(), tcp_connect=boom, resolver=boom, vendor_fn=boom, mac=MAC_B)
    assert r2["ping_ok"] is False and r2["open_ports"] == [] and r2["hostname"] is None and r2["vendor"] is None
    r3 = dhcp.probe_host("172.16.4.103", [], None, tcp_connect=connect, resolver=None, vendor_fn=None)
    assert r3["ping_ok"] is None and r3["mac"] is None


def offer_for(sent: bytes, server="10.0.0.251", yiaddr="10.0.0.191") -> bytes:
    req = dhcp.decode(sent, allow_reply=True)
    return dhcp.encode(req, dhcp.OFFER, yiaddr, [(54, ip4(server)), (51, u32(86400)), (1, ip4("255.255.255.0")),
                                                (3, ip4(server)), (6, ip4(server) + ip4("1.1.1.1"))], server)


def test_scan_for_servers_with_fake_sockets():
    eth = adapter()                                                                    # DHCP client of 10.0.0.251
    wifi = adapter(name="Wi-Fi", ip="192.168.1.5", dhcp_server="192.168.1.1", gateway="192.168.1.1", mac="AA:AA:AA:AA:AA:AA", index=7, if_type=71)
    usb = adapter(name="USB", ip="169.254.10.5", prefix=16, dhcp_enabled=False, gateway=None, mac="BB:BB:BB:BB:BB:BB", index=9)
    down = adapter(name="Down", ip="10.1.1.1", status="down", index=3)
    factory = FakeSocketFactory()
    factory.fail_bind.add("169.254.10.5")

    def on_send(sock, data, addr):
        if sock.bound[0] != "10.0.0.112":
            return []
        return [
            (data, ("10.0.0.112", 67)),                                                # our own echo (op 1)
            (offer_for(data, server="10.0.0.9"), ("10.0.0.99", 67)),                   # a reply from one of our own IPs
            (offer_for(data), ("10.0.0.251", 67)),
            (offer_for(data), ("10.0.0.251", 67)),                                     # duplicate
            (bytes([2]) + data[1:200], ("10.0.0.251", 67)),                            # truncated garbage
        ]

    factory.on_send = on_send
    res = dhcp.scan_for_servers([eth, wifi, usb, down], 0.4, socket_factory=factory, own_ips={"10.0.0.112", "10.0.0.99"},
                                clock=FakeClock())
    assert res["ts"] == T0 and res["wait_s"] == 0.4 and 0.3 < res["duration_s"] < 3.0
    assert res["probed"] == [{"adapter": "Ethernet", "ip": "10.0.0.112"}, {"adapter": "Wi-Fi", "ip": "192.168.1.5"},
                             {"adapter": "USB", "ip": "169.254.10.5"}]
    assert len(res["errors"]) == 1 and "USB" in res["errors"][0] and "169.254.10.5" in res["errors"][0]
    # the probe packets themselves: relay-style + client-style, each sent twice
    s = factory.bound_to("10.0.0.112")
    assert s.bound == ("10.0.0.112", 67) and (socket.SOL_SOCKET, socket.SO_BROADCAST, 1) in s.opts and s.closed
    assert len(s.sent) == 4 and all(addr == ("255.255.255.255", 67) for _d, addr in s.sent)
    p = dhcp.decode(s.sent[0][0])
    assert p.op == 1 and p.hops == 1 and p.giaddr == "10.0.0.112" and p.mac == NIC_MAC and len(s.sent[0][0]) == 300
    assert p.opts[53] == b"\x01" and p.opts[61] == b"\x01" + bytes.fromhex(NIC_MAC.replace(":", ""))
    assert set(p.opts[55]) >= {1, 3, 6, 51, 54} and p.ciaddr is None and p.flags == 0
    c = dhcp.decode(s.sent[1][0])
    assert c.op == 1 and c.hops == 0 and c.giaddr is None and c.ciaddr is None and c.broadcast is True and c.xid == p.xid
    assert c.mac.startswith("02:54:4E:54:") and c.mac != NIC_MAC and len(s.sent[1][0]) == 300      # locally administered
    assert c.opts[53] == b"\x01" and c.opts[61] == b"\x01" + bytes.fromhex(c.mac.replace(":", "")) and set(c.opts[55]) >= {1, 3, 6, 51, 54}
    assert s.sent[2][0] == s.sent[0][0] and s.sent[3][0] == s.sent[1][0]
    # the broadcast OFFERs of the client-style probe are awaited on :68 -- one wildcard socket
    # plus one per probed NIC, SO_REUSEADDR set, all closed afterwards
    listeners = [x for x in factory.sockets if x.bound and x.bound[1] == 68]
    assert [x.bound for x in listeners] == [("0.0.0.0", 68), ("10.0.0.112", 68), ("192.168.1.5", 68)]
    assert all((socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) in x.opts and x.closed for x in listeners)
    assert factory.bound_to("169.254.10.5", 68) is None                                          # no probe, no listener
    # results: the answering server (also known) + the Wi-Fi one that only the adapter knows about
    by_ip = {(sv["adapter"], sv["server_ip"]): sv for sv in res["servers"]}
    assert set(by_ip) == {("Ethernet", "10.0.0.251"), ("Wi-Fi", "192.168.1.1")}
    eth_sv = by_ip[("Ethernet", "10.0.0.251")]
    assert eth_sv == {"adapter": "Ethernet", "nic_ip": "10.0.0.112", "server_ip": "10.0.0.251", "source_ip": "10.0.0.251",
                      "offered_ip": "10.0.0.191", "lease_s": 86400, "router": "10.0.0.251", "mask": "255.255.255.0",
                      "dns": ["10.0.0.251", "1.1.1.1"], "known": True, "answered": True}
    wifi_sv = by_ip[("Wi-Fi", "192.168.1.1")]
    assert wifi_sv["known"] is True and wifi_sv["answered"] is False and wifi_sv["offered_ip"] is None and wifi_sv["dns"] == []
    # a scan through a running server's socket uses register_probe instead of binding
    calls: Dict[str, Any] = {}

    def register(xid, cb):
        calls["xid"] = xid
        calls["cb"] = cb
        return lambda: calls.__setitem__("unregistered", True)

    def via_server_socket(sock, data, addr):
        # the running server's rx loop would hand the matching OFFER to the registered callback
        calls["cb"](dhcp.decode(offer_for(data, server="10.0.0.250"), allow_reply=True), ("10.0.0.250", 67))
        return []

    factory.on_send = via_server_socket
    existing = FakeSocket(factory)
    existing.bound = ("10.0.0.112", 67)
    n_sockets = len(factory.sockets)
    res2 = dhcp.scan_for_servers([eth], 0.2, socket_factory=factory, existing_socket_for=lambda ip: existing if ip == "10.0.0.112" else None,
                                 register_probe=register)
    assert existing.sent and not existing.closed and calls.get("unregistered") is True
    assert calls["xid"] == dhcp.decode(existing.sent[0][0]).xid == dhcp.decode(existing.sent[1][0]).xid
    assert {sv["server_ip"] for sv in res2["servers"]} == {"10.0.0.250", "10.0.0.251"}
    # no new :67 socket was bound next to the server's; only the :68 listeners were opened
    assert [x.bound for x in factory.sockets[n_sockets:]] == [("0.0.0.0", 68), ("10.0.0.112", 68)]


def test_scan_client_style_probe_finds_a_server_serving_another_subnet():
    """A server whose scope does not cover the NIC's subnet drops the relay probe (dnsmasq: "no
    address range available for DHCP request via <giaddr>") but answers the client-style
    DISCOVER by broadcasting to :68 -- the bench NIC on APIPA or on a static address plugged
    into a customer LAN is exactly that case.  A WSAECONNRESET on the way (a device answering
    the broadcast with ICMP port-unreachable) must not end the listen either."""
    bench = adapter(name="Ethernet", ip="10.0.0.50", dhcp_enabled=False, gateway=None)
    apipa = adapter(name="USB", ip="169.254.10.5", prefix=16, dhcp_enabled=True, dhcp_server=None, gateway=None,
                    mac="BB:BB:BB:BB:BB:BB", index=9)
    factory = FakeSocketFactory()
    seen: List[Tuple[str, Optional[str], bool]] = []

    def dnsmasq(sock, data, addr):
        req = dhcp.decode(data)
        seen.append((sock.bound[0], req.giaddr, req.broadcast))
        if req.giaddr:
            return []                                                # scope 192.168.1.0/24: no range for giaddr
        offer = dhcp.encode(req, dhcp.OFFER, "192.168.1.50", [(54, ip4("192.168.1.1")), (51, u32(86400)), (1, ip4("255.255.255.0")),
                                                              (3, ip4("192.168.1.1"))], "192.168.1.1")
        factory.bound_to("0.0.0.0", 68).inject(offer, ("192.168.1.1", 67))
        # our own server (were it running) answering the client-style probe is not "another server"
        own = dhcp.encode(req, dhcp.OFFER, "10.0.0.51", [(54, ip4("10.0.0.50"))], "10.0.0.50")
        factory.bound_to(sock.bound[0], 68).inject(own, ("10.0.0.50", 67))
        return []

    factory.on_send = dnsmasq
    res = dhcp.scan_for_servers([bench, apipa], 0.4, socket_factory=factory, own_ips={"10.0.0.50", "169.254.10.5"}, clock=FakeClock())
    wild68 = factory.bound_to("0.0.0.0", 68)
    assert wild68 is not None and wild68.closed
    assert set(seen) == {("10.0.0.50", None, True), ("10.0.0.50", "10.0.0.50", False),
                         ("169.254.10.5", None, True), ("169.254.10.5", "169.254.10.5", False)}
    assert res["errors"] == [] and {(sv["adapter"], sv["server_ip"]) for sv in res["servers"]} == {("Ethernet", "192.168.1.1"), ("USB", "192.168.1.1")}
    sv = next(x for x in res["servers"] if x["adapter"] == "Ethernet")
    assert sv == {"adapter": "Ethernet", "nic_ip": "10.0.0.50", "server_ip": "192.168.1.1", "source_ip": "192.168.1.1",
                  "offered_ip": "192.168.1.50", "lease_s": 86400, "router": "192.168.1.1", "mask": "255.255.255.0", "dns": [],
                  "known": False, "answered": True}
    # a port-unreachable reset on the :68 socket before the OFFER arrives: still found
    factory2 = FakeSocketFactory()

    def late(sock, data, addr):
        req = dhcp.decode(data)
        if req.giaddr:
            return []
        w = factory2.bound_to("0.0.0.0", 68)
        w.recv_errors.append(ConnectionResetError(10054, "An existing connection was forcibly closed by the remote host"))
        w.inject(dhcp.encode(req, dhcp.OFFER, "192.168.1.50", [(54, ip4("192.168.1.1"))], "192.168.1.1"), ("192.168.1.1", 67))
        return []

    factory2.on_send = late
    res2 = dhcp.scan_for_servers([bench], 0.4, socket_factory=factory2, own_ips={"10.0.0.50"})
    assert [sv["server_ip"] for sv in res2["servers"]] == ["192.168.1.1"]
    # :68 not bindable at all (something holds it exclusively): the relay probe still runs and
    # the limitation is reported
    factory3 = FakeSocketFactory()
    factory3.fail_bind.update({("0.0.0.0", 68), ("10.0.0.50", 68)})
    factory3.on_send = lambda sock, data, addr: [(offer_for(data, server="10.0.0.1"), ("10.0.0.1", 67))] if dhcp.decode(data).giaddr else []
    res3 = dhcp.scan_for_servers([bench], 0.3, socket_factory=factory3, own_ips={"10.0.0.50"})
    assert [sv["server_ip"] for sv in res3["servers"]] == ["10.0.0.1"] and len(res3["errors"]) == 1 and "UDP 68" in res3["errors"][0]


# =========================================================================================
# DhcpServer with fakes
# =========================================================================================
@pytest.fixture
def fast_scan(monkeypatch):
    """start() honours dhcp.scan_wait_s (>= 2 s); tests do not want to wait that long."""
    real = dhcp.scan_for_servers

    def quick(adapters, wait_s, **kw):
        return real(adapters, 0.3, **kw)

    monkeypatch.setattr(dhcp, "scan_for_servers", quick)
    monkeypatch.setattr(dhcp, "MIN_SCAN_WAIT_S", 0.2)


def make_server(tmp_path, sim: NicSim, factory: Optional[FakeSocketFactory] = None, pinger: Optional[FakePinger] = None,
                clock: Optional[FakeClock] = None, cfg_patch: Optional[dict] = None, **kw):
    cfg = tnt_config.Config(tmp_path / "config.json").load()
    if cfg_patch:
        cfg.update({"dhcp": cfg_patch}, persist=False)
    db = tnt_db.Database(tmp_path / "tnt.db")
    bus = tnt_events.EventBus()
    events: List[dict] = []
    bus.subscribe(lambda e: events.append(e))
    clock = clock or FakeClock()
    factory = factory or FakeSocketFactory()
    srv = dhcp.DhcpServer(db, cfg, bus, pinger=pinger or FakePinger(), clock=clock, socket_factory=factory, runner=sim,
                          adapters_fn=sim.get_adapters, tcp_connect=lambda ip, port, t: port == 80, resolver=lambda ip: None,
                          vendor_fn=lambda mac: "Acme", exe_path=r"C:\Program Files\TNT\TNTService.exe", sleep=clock.sleep, **kw)
    return srv, events, factory, db, cfg, clock


def answering_factory(server="10.0.0.251") -> FakeSocketFactory:
    f = FakeSocketFactory()
    f.on_send = lambda sock, data, addr: [(offer_for(data, server=server), (server, 67))] if addr == ("255.255.255.255", 67) and dhcp.decode(data) else []
    return f


STATUS_KEYS = {"available", "running", "since_ts", "error", "warning", "adapter", "adapters", "server_ip", "pool", "lease_s",
               "gateway", "dns", "ping_check", "clients", "counts", "scan", "firewall", "settings"}
ADAPTER_KEYS = {"name", "index", "mac", "ip", "prefix", "mask", "dhcp_enabled", "gateway", "is_physical", "type_name", "is_internet",
                "will_change", "changed", "static_ip", "static_prefix"}
ADAPTERS_ENTRY_KEYS = {"name", "index", "ip", "prefix", "dhcp_enabled", "is_physical", "type_name", "is_internet", "status"}
SUMMARY_KEYS = {"available", "running", "adapter", "server_ip", "pool", "bound", "offered", "since_ts", "error"}
SETTINGS_KEYS = {"adapter", "pool_start", "pool_end", "pool_size", "lease_s", "static_ip", "static_prefix", "ping_check", "scan_wait_s"}


def test_start_conflict_then_force_readdresses_dhcp_adapter(tmp_path, fast_scan):
    sim = NicSim([adapter()])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim, factory=answering_factory())
    try:
        st = srv.status()
        assert set(st) == STATUS_KEYS and st["running"] is False and st["available"] is True
        assert set(st["adapter"]) == ADAPTER_KEYS and st["adapter"]["will_change"] is True and st["adapter"]["changed"] is False
        assert st["server_ip"] == "172.16.4.100" and st["gateway"] == "172.16.4.100" and st["dns"] == []
        assert st["pool"] == {"start": "172.16.4.101", "end": "172.16.4.105", "size": 5, "auto": True}
        assert st["adapters"][0]["name"] == "Ethernet" and st["adapters"][0]["dhcp_enabled"] is True
        assert set(st["adapters"][0]) == ADAPTERS_ENTRY_KEYS and isinstance(st["adapters"][0]["is_internet"], bool)
        assert isinstance(st["adapter"]["is_internet"], bool)
        assert set(st["settings"]) == SETTINGS_KEYS and st["lease_s"] == 3600 and st["firewall"]["ok"] is None
        assert set(srv.summary()) == SUMMARY_KEYS and srv.summary()["running"] is False
        with pytest.raises(dhcp.DhcpConflict) as ei:
            srv.start()
        assert ei.value.servers[0]["server_ip"] == "10.0.0.251" and ei.value.scan["probed"] == [{"adapter": "Ethernet", "ip": "10.0.0.112"}]
        assert "10.0.0.251" in str(ei.value)
        assert [e["type"] for e in events][-2:] == ["dhcp.scan", "dhcp.state"]
        assert srv.running is False and srv.status()["error"] is None and "10.0.0.251" in srv.status()["warning"]
        assert srv.status()["scan"]["servers"]
        assert not any(c[3:5] == ["set", "address"] for c in sim.commands)     # nothing touched
        # forced: firewall rule, NIC to static, both sockets, threads
        st = srv.start(force=True)
        assert st["running"] is True and st["since_ts"] == T0 and st["error"] is None and st["warning"] is None
        assert sim.firewall_added == [r"C:\Program Files\TNT\TNTService.exe"] and st["firewall"]["ok"] is True
        static_cmd = next(c for c in sim.commands if "source=static" in c)
        assert static_cmd[1:] == ["interface", "ipv4", "set", "address", "name=Ethernet", "source=static", "address=172.16.4.100",
                                  "mask=255.255.255.0", "store=active"]
        assert json.loads(db.get_meta("dhcp.nic_changed"))["static_ip"] == "172.16.4.100"
        assert st["adapter"]["changed"] is True and st["adapter"]["will_change"] is False and st["adapter"]["ip"] == "172.16.4.100"
        assert st["server_ip"] == "172.16.4.100" and st["pool"]["start"] == "172.16.4.101" and st["pool"]["end"] == "172.16.4.105"
        spec, wild = factory.bound_to("172.16.4.100"), factory.bound_to("0.0.0.0")
        assert spec is not None and wild is not None and spec.bound == ("172.16.4.100", 67) and wild.bound == ("0.0.0.0", 67)
        assert (socket.SOL_SOCKET, socket.SO_BROADCAST, 1) in spec.opts and (socket.SOL_SOCKET, socket.SO_BROADCAST, 1) in wild.opts
        names = {t.name for t in threading.enumerate()}
        assert "tnt-dhcp-rx" in names and "tnt-ping-dhcp-probe" in names
        assert srv.start(force=True)["running"] is True          # idempotent
        s = srv.summary()
        assert s["adapter"] == "Ethernet" and s["server_ip"] == "172.16.4.100" and s["pool"] == {"start": "172.16.4.101", "end": "172.16.4.105", "size": 5}
        assert events[-1]["type"] == "dhcp.state" and events[-1]["data"]["running"] is True
        # scanning while running goes through the server's own socket (unicast replies only reach it)
        res = srv.scan(wait_s=0.2)
        assert factory.bound_to("172.16.4.100") is spec and spec.sent and res["probed"] == [{"adapter": "Ethernet", "ip": "172.16.4.100"}]
        assert {sv["server_ip"] for sv in res["servers"]} == {"10.0.0.251"} and srv.status()["scan"] is res
        # stop: threads gone, sockets closed, NIC back on DHCP, record cleared
        st = srv.stop()
        assert st["running"] is False and st["since_ts"] is None and spec.closed and wild.closed
        assert sim.find("Ethernet").dhcp_enabled is True and sim.find("Ethernet").ipv4[0].address == "10.0.0.112"
        assert not db.get_meta("dhcp.nic_changed") and st["adapter"]["changed"] is False and st["adapter"]["will_change"] is True
        assert sim.commands[-1][4:] == ["address", "name=Ethernet", "source=dhcp"] and not any("dnsservers" in c for c in sim.commands)
        time.sleep(0.1)
        assert not {t.name for t in threading.enumerate()} & {"tnt-dhcp-rx", "tnt-ping-dhcp-probe"}
        assert srv.stop()["running"] is False                     # idempotent
    finally:
        srv.stop()
        db.close()


def test_start_static_adapter_keeps_its_address(tmp_path, fast_scan):
    sim = NicSim([adapter(name="Wi-Fi", ip="10.9.0.5", dhcp_enabled=True, dhcp_server="10.9.0.1", gateway="10.9.0.1", if_type=71, index=4),
                  adapter(name="Ethernet", dhcp_enabled=False, gateway="10.0.0.251")])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim)
    try:
        # a DHCP server known to ANY up NIC (here the Wi-Fi one) blocks an unforced start
        with pytest.raises(dhcp.DhcpConflict) as ei:
            srv.start()
        assert ei.value.servers[0] == {"adapter": "Wi-Fi", "nic_ip": "10.9.0.5", "server_ip": "10.9.0.1", "source_ip": None,
                                       "offered_ip": None, "lease_s": None, "router": None, "mask": None, "dns": [],
                                       "known": True, "answered": False}
        sim.adapters[0].dhcp_enabled = False
        sim.adapters[0].dhcp_server = None
        st = srv.start()                        # nobody answers, the Ethernet NIC is static: no conflict, no netsh set
        assert st["running"] is True and st["adapter"]["name"] == "Ethernet" and st["adapter"]["changed"] is False
        assert st["server_ip"] == "10.0.0.112" and st["pool"] == {"start": "10.0.0.113", "end": "10.0.0.117", "size": 5, "auto": True}
        assert not any("set" in c and "address" in c for c in sim.commands)
        assert st["scan"]["servers"] == [] and set(p["adapter"] for p in st["scan"]["probed"]) == {"Wi-Fi", "Ethernet"}
        assert not db.get_meta("dhcp.nic_changed")
        # the Wi-Fi adapter can be chosen explicitly through settings
        srv.stop()
        with pytest.raises(ValueError):
            srv.update_settings({"adapter": "Nope"})
        sim.adapters[0].dhcp_enabled = True
        st = srv.update_settings({"adapter": "Wi-Fi"})
        assert st["adapter"]["name"] == "Wi-Fi" and st["adapter"]["will_change"] is True and cfg.get("dhcp.adapter") == "Wi-Fi"
        assert st["server_ip"] == "172.16.4.100" and st["pool"]["start"] == "172.16.4.101"
    finally:
        srv.stop()
        db.close()


def test_start_bind_failure_restores_nic(tmp_path, fast_scan):
    sim = NicSim([adapter()])
    factory = FakeSocketFactory()
    factory.fail_bind.add("172.16.4.100")
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim, factory=factory)
    try:
        with pytest.raises(RuntimeError, match="already in use"):
            srv.start(force=True)
        assert srv.running is False
        cmds = [c[1:] for c in sim.commands if c[1] == "interface"]
        assert [c[3:6] for c in cmds] == [["address", "name=Ethernet", "source=static"], ["address", "name=Ethernet", "source=dhcp"]]
        assert sim.find("Ethernet").dhcp_enabled is True and not db.get_meta("dhcp.nic_changed")
        assert "already in use" in srv.status()["error"] and srv.status()["adapter"]["changed"] is False
        assert events[-1]["type"] == "dhcp.state"
        # no usable adapter at all -> ValueError, nothing touched
        sim.adapters[0].status = "down"
        with pytest.raises(ValueError, match="no network adapter"):
            srv.start(force=True)
        assert srv.status()["adapter"] is None and srv.status()["server_ip"] is None
        # netsh failing to set the address -> RuntimeError, no sockets opened
        sim.adapters[0].status = "up"
        sim.fail_static = True
        n = len(factory.sockets)
        with pytest.raises(RuntimeError, match="static address"):
            srv.start(force=True)
        assert len(factory.sockets) == n
    finally:
        srv.stop()
        db.close()


def test_clean_scan_clears_a_stale_conflict_warning(tmp_path, fast_scan):
    # a static adapter: no "known" server is merged in, so a silent network is a clean scan
    sim = NicSim([adapter(dhcp_enabled=False)])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim, factory=answering_factory())
    try:
        with pytest.raises(dhcp.DhcpConflict):
            srv.start()
        assert srv.status()["warning"].startswith(dhcp.CONFLICT_WARNING) and "10.0.0.251" in srv.status()["warning"]
        assert srv.scan()["servers"] and "10.0.0.251" in srv.status()["warning"]      # still answering: kept
        factory.on_send = lambda sock, data, addr: []                                   # the other server went away
        assert srv.scan()["servers"] == []
        assert srv.status()["warning"] is None and srv.status()["error"] is None
        assert events[-1]["type"] == "dhcp.scan"
    finally:
        srv.stop()


def test_firewall_failure_is_a_warning(tmp_path, fast_scan):
    sim = NicSim([adapter(dhcp_enabled=False)])
    real = sim.__call__

    def runner(argv, **kw):
        if argv[1] == "advfirewall" and argv[3] == "add":
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"The requested operation requires elevation.")
        return real(argv, **kw)

    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim)
    srv._runner = runner
    srv._nic._runner = runner
    try:
        st = srv.start(force=True)
        assert st["running"] is True and st["firewall"]["ok"] is False and "elevation" in st["firewall"]["error"]
        assert "Firewall" in st["warning"]
    finally:
        srv.stop()
        db.close()


# ---------------------------------------------------------------------------- protocol
@pytest.fixture
def running(tmp_path, fast_scan):
    """A server on a static 172.16.4.100/24 adapter with pool .101-.105, driven via handle()."""
    sim = NicSim([adapter(ip="172.16.4.100", dhcp_enabled=False, gateway=None)])
    pinger = FakePinger()
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim, pinger=pinger)
    srv.start(force=True)
    sock = factory.bound_to("172.16.4.100")
    yield SimpleNamespace(srv=srv, events=events, sock=sock, db=db, cfg=cfg, clock=clock, pinger=pinger)
    srv.stop()
    db.close()


def last_reply(sock: FakeSocket) -> Tuple[dhcp.Packet, Tuple[str, int], bytes]:
    raw, dest = sock.sent[-1]
    return dhcp.decode(raw, allow_reply=True), dest, raw


def test_discover_offer_option_set(running):
    srv, sock = running.srv, running.sock
    assert srv.handle(build(dhcp.DISCOVER, xid=0xABCD0001, flags=0x8000, giaddr="0.0.0.0"), ("0.0.0.0", 68), now=T0) == dhcp.OFFER
    rep, dest, raw = last_reply(sock)
    assert dest == ("255.255.255.255", 68) and len(raw) == 300
    assert rep.op == 2 and rep.xid == 0xABCD0001 and rep.flags == 0x8000 and rep.giaddr is None and rep.yiaddr == "172.16.4.101"
    assert rep.chaddr == dhcp.decode(build(dhcp.DISCOVER)).chaddr and rep.hops == 0 and rep.secs == 0
    assert set(rep.opts) == {53, 54, 51, 58, 59, 1, 3, 28}
    assert 6 not in rep.opts and 50 not in rep.opts and 55 not in rep.opts and 61 not in rep.opts
    assert rep.opts[54] == ip4("172.16.4.100") and rep.opts[3] == ip4("172.16.4.100")
    assert rep.opts[51] == u32(3600) and rep.opts[58] == u32(1800) and rep.opts[59] == u32(3150)
    assert rep.opts[1] == ip4("255.255.255.0") and rep.opts[28] == ip4("172.16.4.255")
    assert rep.siaddr == "172.16.4.100"
    # the same datagram arriving on the second socket within 1.5 s is handled once
    assert srv.handle(build(dhcp.DISCOVER, xid=0xABCD0001, flags=0x8000), ("0.0.0.0", 68), now=T0 + 0.2) is None
    assert len(sock.sent) == 1
    # a retransmission (secs differs) or a later repeat is answered again with the same address
    assert srv.handle(build(dhcp.DISCOVER, xid=0xABCD0001, flags=0x8000, secs=4), ("0.0.0.0", 68), now=T0 + 0.3) == dhcp.OFFER
    assert srv.handle(build(dhcp.DISCOVER, xid=0xABCD0001), ("0.0.0.0", 68), now=T0 + 3) == dhcp.OFFER
    assert last_reply(sock)[0].yiaddr == "172.16.4.101"
    # a relayed DISCOVER is answered to the relay on 67 with giaddr copied
    assert srv.handle(build(dhcp.DISCOVER, mac=MAC_B, xid=5, giaddr="172.16.4.9"), ("172.16.4.9", 67), now=T0 + 4) == dhcp.OFFER
    rep, dest, _ = last_reply(sock)
    assert dest == ("172.16.4.9", 67) and rep.giaddr == "172.16.4.9" and rep.yiaddr == "172.16.4.102"
    # lease time requests are clamped: 600 ok, 60 -> 120, huge -> 3600
    for want, got in ((600, 600), (60, 120), (999999, 3600)):
        srv.handle(build(dhcp.DISCOVER, xid=100 + want, opts={51: u32(want)}), ("0.0.0.0", 68), now=T0 + 10)
        rep = last_reply(sock)[0]
        assert rep.opts[51] == u32(got) and rep.opts[58] == u32(got // 2) and rep.opts[59] == u32(got * 7 // 8)
    # status: offered clients appear at once, with the LEASE DICT keys
    st = srv.status()
    assert st["counts"] == {"bound": 0, "offered": 2, "total": 2}       # MAC_A (re-offered) and MAC_B
    row = next(r for r in st["clients"] if r["mac"] == MAC_A)
    assert row["state"] == "offered" and row["ip"] == "172.16.4.101" and row["hostname"] == "cam-12" and row["client_id"] == "01aabbccddee01"
    assert [e["type"] for e in running.events if e["type"] == "dhcp.lease"]


def test_request_branches(running):
    srv, sock = running.srv, running.sock
    srv.handle(build(dhcp.DISCOVER, xid=1), ("0.0.0.0", 68), now=T0)
    assert last_reply(sock)[0].yiaddr == "172.16.4.101"
    # SELECTING for another server: silence, and our offer is freed
    assert srv.handle(build(dhcp.REQUEST, xid=1, opts={50: ip4("172.16.4.101"), 54: ip4("10.9.9.9")}), ("0.0.0.0", 68), now=T0 + 1) is None
    assert len(sock.sent) == 1 and srv.status()["counts"]["total"] == 0
    assert srv.handle(build(dhcp.DISCOVER, mac=MAC_B, xid=2), ("0.0.0.0", 68), now=T0 + 2) == dhcp.OFFER
    assert last_reply(sock)[0].yiaddr == "172.16.4.101"                                  # .101 was freed
    # SELECTING ours with the wrong address -> NAK (broadcast, 54 + 56 only, no lease options)
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_B, xid=2, opts={50: ip4("172.16.4.105"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 3) == dhcp.NAK
    rep, dest, _ = last_reply(sock)
    assert dest == ("255.255.255.255", 68) and set(rep.opts) == {53, 54, 56} and rep.yiaddr is None and rep.siaddr is None
    # SELECTING ours, right address -> ACK, bound
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_B, xid=2, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 4) == dhcp.ACK
    rep, dest, _ = last_reply(sock)
    assert dest == ("255.255.255.255", 68) and rep.yiaddr == "172.16.4.101" and set(rep.opts) == {53, 54, 51, 58, 59, 1, 3, 28}
    lease = srv.leases()[0]
    assert lease["state"] == "bound" and lease["expires_ts"] == T0 + 4 + 3600 and lease["mac"] == MAC_B
    assert srv.summary()["bound"] == 1 and running.db.get_dhcp_lease(MAC_B)["state"] == "bound"
    # INIT-REBOOT: wrong subnet -> NAK with a message; unknown client -> silence; known -> ACK
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_A, xid=3, opts={50: ip4("192.168.9.9")}), ("0.0.0.0", 68), now=T0 + 5) == dhcp.NAK
    rep = last_reply(sock)[0]
    assert rep.opts[56] == b"wrong subnet" and rep.opts[54] == ip4("172.16.4.100")
    n = len(sock.sent)
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_A, xid=4, opts={50: ip4("172.16.4.104")}), ("0.0.0.0", 68), now=T0 + 6) is None
    assert len(sock.sent) == n
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_B, xid=5, opts={50: ip4("172.16.4.101")}), ("0.0.0.0", 68), now=T0 + 7) == dhcp.ACK
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_B, xid=6, opts={50: ip4("172.16.4.103")}), ("0.0.0.0", 68), now=T0 + 8) == dhcp.NAK
    # RENEWING (unicast, ciaddr): ACK to ciaddr:68 with ciaddr copied; unknown client outside our
    # pool -> silence; unknown client on one of our pool addresses -> NAK; wrong ip -> NAK
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_B, xid=7, ciaddr="172.16.4.101"), ("172.16.4.101", 68), now=T0 + 9) == dhcp.ACK
    rep, dest, raw = last_reply(sock)
    assert dest == ("172.16.4.101", 68) and rep.ciaddr == "172.16.4.101" and rep.yiaddr == "172.16.4.101"
    assert srv.leases()[0]["expires_ts"] == T0 + 9 + 3600
    n = len(sock.sent)
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_A, xid=8, ciaddr="172.16.4.200"), ("172.16.4.200", 68), now=T0 + 10) is None
    assert len(sock.sent) == n
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_A, xid=8, ciaddr="172.16.4.102"), ("172.16.4.102", 68), now=T0 + 10) == dhcp.NAK
    assert last_reply(sock)[0].opts[56] == b"lease not known"
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_B, xid=9, ciaddr="172.16.4.103"), ("172.16.4.103", 68), now=T0 + 11) == dhcp.NAK
    # REBINDING (broadcast with ciaddr) -> ACK
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_B, xid=10, ciaddr="172.16.4.101", flags=0x8000), ("172.16.4.101", 68), now=T0 + 12) == dhcp.ACK
    # a REQUEST with neither 50 nor ciaddr is ignored
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_B, xid=11), ("0.0.0.0", 68), now=T0 + 13) is None
    # an expired lease is not renewable: the address goes to whoever asks first
    running.clock.t = T0 + 12 + 3601
    srv._tick()
    assert srv.leases()[0]["state"] == "expired"
    assert srv.handle(build(dhcp.DISCOVER, mac=MAC_A, xid=12, opts={50: ip4("172.16.4.101")}), ("0.0.0.0", 68), now=T0 + 12 + 3602) == dhcp.OFFER
    assert last_reply(sock)[0].yiaddr == "172.16.4.101"
    assert srv.handle(build(dhcp.REQUEST, mac=MAC_B, xid=13, ciaddr="172.16.4.101"), ("172.16.4.101", 68), now=T0 + 12 + 3603) == dhcp.NAK


def test_decline_release_inform_and_filters(running):
    srv, sock, events = running.srv, running.sock, running.events
    srv.handle(build(dhcp.DISCOVER, xid=1), ("0.0.0.0", 68), now=T0)
    srv.handle(build(dhcp.REQUEST, xid=1, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 1)
    n = len(sock.sent)
    # DECLINE: no reply, address quarantined, next DISCOVER gets another one
    assert srv.handle(build(dhcp.DECLINE, xid=2, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 2) is None
    assert len(sock.sent) == n and srv.leases()[0]["state"] == "declined"
    assert events[-1]["type"] == "dhcp.lease" and events[-1]["data"]["lease"]["state"] == "declined"
    srv.handle(build(dhcp.DISCOVER, xid=3), ("0.0.0.0", 68), now=T0 + 3)
    assert last_reply(sock)[0].yiaddr == "172.16.4.102"
    srv.handle(build(dhcp.REQUEST, xid=3, opts={50: ip4("172.16.4.102"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 4)
    # a DECLINE for another server is ignored
    assert srv.handle(build(dhcp.DECLINE, xid=4, opts={50: ip4("172.16.4.102"), 54: ip4("10.9.9.9")}), ("0.0.0.0", 68), now=T0 + 5) is None
    assert srv.leases()[0]["state"] == "bound"
    # RELEASE: no reply, record kept as released, address reusable by the same client first
    n = len(sock.sent)
    assert srv.handle(build(dhcp.RELEASE, xid=5, ciaddr="172.16.4.102", opts={54: ip4("172.16.4.100")}), ("172.16.4.102", 68), now=T0 + 6) is None
    assert len(sock.sent) == n and srv.leases()[0]["state"] == "released" and srv.leases()[0]["expires_ts"] is None
    assert running.db.get_dhcp_lease(MAC_A)["state"] == "released"
    srv.handle(build(dhcp.DISCOVER, xid=6), ("0.0.0.0", 68), now=T0 + 7)
    assert last_reply(sock)[0].yiaddr == "172.16.4.102"
    # INFORM: ACK unicast to ciaddr with 54/1/3/28 only, no lease, yiaddr 0
    assert srv.handle(build(dhcp.INFORM, xid=7, ciaddr="172.16.4.102"), ("172.16.4.102", 68), now=T0 + 8) == dhcp.ACK
    rep, dest, _ = last_reply(sock)
    assert dest == ("172.16.4.102", 68) and set(rep.opts) == {53, 54, 1, 3, 28} and rep.yiaddr is None and rep.ciaddr == "172.16.4.102"
    # filters: our own echo, our own MAC, replies, garbage, unknown types -> nothing, no crash
    n = len(sock.sent)
    assert srv.handle(build(dhcp.DISCOVER, mac=MAC_B, xid=8), ("172.16.4.100", 67), now=T0 + 9) is None
    assert srv.handle(build(dhcp.DISCOVER, mac=NIC_MAC, xid=9), ("0.0.0.0", 68), now=T0 + 9) is None
    assert srv.handle(build(dhcp.OFFER, mac=MAC_B, xid=10, op=2), ("10.0.0.251", 67), now=T0 + 9) is None
    assert srv.handle(b"\x01\x02garbage", ("0.0.0.0", 68), now=T0 + 9) is None
    assert srv.handle(build(dhcp.DISCOVER, mac=MAC_B, xid=11)[:240] + tlv(53, b"\x09") + b"\xff", ("0.0.0.0", 68), now=T0 + 9) is None
    assert srv.handle(None, ("0.0.0.0", 68)) is None  # type: ignore[arg-type]
    assert len(sock.sent) == n
    # forget a client
    assert srv.forget_lease("aa:bb:cc:dd:ee:01") is True and srv.leases() == [] and running.db.get_dhcp_lease(MAC_A) is None
    assert srv.forget_lease(MAC_A) is False
    with pytest.raises(ValueError):
        srv.forget_lease("nope")


def test_ping_check_before_offer(running):
    srv, sock, pinger = running.srv, running.sock, running.pinger
    pinger.alive.add("172.16.4.101")
    assert srv.handle(build(dhcp.DISCOVER, xid=1), ("0.0.0.0", 68), now=T0) == dhcp.OFFER
    assert last_reply(sock)[0].yiaddr == "172.16.4.102"
    assert pinger.calls == [("172.16.4.101", 500), ("172.16.4.102", 500)]
    # the offered address is not pinged again on the retry
    pinger.calls.clear()
    srv.handle(build(dhcp.DISCOVER, xid=2), ("0.0.0.0", 68), now=T0 + 5)
    assert pinger.calls == []
    # ping_check off: no pings at all
    srv.update_settings({"ping_check": "false"})
    assert running.cfg.get("dhcp.ping_check") is False
    srv.handle(build(dhcp.DISCOVER, mac=MAC_B, xid=3), ("0.0.0.0", 68), now=T0 + 6)
    assert pinger.calls == [] and last_reply(sock)[0].yiaddr == "172.16.4.103"


def test_leases_survive_restart(tmp_path, fast_scan):
    sim = NicSim([adapter(ip="172.16.4.100", dhcp_enabled=False, gateway=None)])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim)
    srv.start(force=True)
    srv.handle(build(dhcp.DISCOVER, xid=1), ("0.0.0.0", 68), now=T0)
    srv.handle(build(dhcp.REQUEST, xid=1, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 1)
    srv.stop()
    assert srv.leases()[0]["state"] == "bound"           # still listed while off (from the table / db)
    # a new server instance (service restart) does not re-offer the live address
    srv2, events2, factory2, db2, cfg2, clock2 = make_server(tmp_path, sim, clock=FakeClock(T0 + 100))
    db.close()
    try:
        assert srv2.leases()[0]["mac"] == MAC_A and srv2.status()["clients"][0]["state"] == "bound"
        srv2.start(force=True)
        assert srv2.summary()["bound"] == 1
        srv2.handle(build(dhcp.DISCOVER, mac=MAC_B, xid=2), ("0.0.0.0", 68), now=T0 + 101)
        assert last_reply(factory2.bound_to("172.16.4.100"))[0].yiaddr == "172.16.4.102"
        # the returning client renews without a new DISCOVER
        assert srv2.handle(build(dhcp.REQUEST, xid=3, ciaddr="172.16.4.101"), ("172.16.4.101", 68), now=T0 + 102) == dhcp.ACK
    finally:
        srv2.stop()
        db2.close()


def test_update_settings_validation_and_live_pool(running):
    srv, cfg = running.srv, running.cfg
    with pytest.raises(ValueError):
        srv.update_settings({"pool_start": "172.16.4.110"})                    # end missing
    with pytest.raises(ValueError):
        srv.update_settings({"pool_start": "10.0.0.1", "pool_end": "10.0.0.5"})   # wrong subnet
    with pytest.raises(ValueError):
        srv.update_settings({"pool_start": "172.16.4.99", "pool_end": "172.16.4.101"})   # contains the server
    with pytest.raises(ValueError):
        srv.update_settings({"pool_size": 0})
    with pytest.raises(ValueError):
        srv.update_settings({"lease_s": 10})
    with pytest.raises(ValueError):
        srv.update_settings({"lease_s": "abc"})
    with pytest.raises(ValueError):
        srv.update_settings("nope")  # type: ignore[arg-type]
    st = srv.update_settings({"pool_start": "172.16.4.110", "pool_end": "172.16.4.112", "lease_s": 900, "pool_size": 3})
    assert cfg.get("dhcp.pool_start") == "172.16.4.110" and cfg.get("dhcp.lease_s") == 900 and cfg.get("dhcp.pool_size") == 3
    assert st["pool"] == {"start": "172.16.4.110", "end": "172.16.4.112", "size": 3, "auto": False} and st["lease_s"] == 900
    assert running.events[-1]["type"] == "dhcp.state"
    srv.handle(build(dhcp.DISCOVER, xid=1), ("0.0.0.0", 68), now=T0)
    rep = last_reply(running.sock)[0]
    assert rep.yiaddr == "172.16.4.110" and rep.opts[51] == u32(900)
    # back to automatic: size 3 right after the server
    st = srv.update_settings({"pool_start": "", "pool_end": ""})
    assert st["pool"] == {"start": "172.16.4.101", "end": "172.16.4.103", "size": 3, "auto": True}


def wait_for(pred, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return bool(pred())


def test_scan_after_stop_listens_for_the_full_window(tmp_path, monkeypatch):
    """stop() used to leave the lifecycle event set, so every later scan() sent its probes and
    listened for 0 s -- a false "no other DHCP server" for the standalone check the tech
    relies on before plugging into a customer LAN.  Only a stop() that arrives *while* a scan
    runs may cut it short."""
    monkeypatch.setattr(dhcp, "MIN_SCAN_WAIT_S", 0.2)
    sim = NicSim([adapter(dhcp_enabled=False)])                      # static: no "known" entry can mask the result
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim, factory=answering_factory())
    try:
        assert [sv["server_ip"] for sv in srv.scan(wait_s=0.3)["servers"]] == ["10.0.0.251"]
        srv.stop()                                                   # while off (the UI's switch, or an idempotent repeat)
        t = time.monotonic()
        res = srv.scan(wait_s=0.3)
        assert [sv["server_ip"] for sv in res["servers"]] == ["10.0.0.251"]
        assert res["duration_s"] >= 0.25 and time.monotonic() - t >= 0.25
        srv.start(force=True)
        srv.stop()                                                   # the common sequence: on, off, later "Check"
        res = srv.scan(wait_s=0.3)
        assert [sv["server_ip"] for sv in res["servers"]] == ["10.0.0.251"] and res["duration_s"] >= 0.25
        assert srv.status()["scan"] is res and events[-1]["type"] == "dhcp.scan"
        # an in-flight scan is still cut short by stop(), and the next one runs in full again
        factory.on_send = lambda sock, data, addr: []
        box: Dict[str, Any] = {}
        th = threading.Thread(target=lambda: box.__setitem__("res", srv.scan(wait_s=5.0)), daemon=True)
        th.start()
        assert wait_for(lambda: srv._scan_cancel is not None)
        t = time.monotonic()
        srv.stop()
        th.join(3.0)
        assert not th.is_alive() and box["res"]["servers"] == [] and box["res"]["duration_s"] < 1.5 and time.monotonic() - t < 1.5
        assert srv._scan_cancel is None
        t = time.monotonic()
        assert srv.scan(wait_s=0.3)["servers"] == [] and time.monotonic() - t >= 0.25
    finally:
        srv.stop()
        db.close()


def test_wildcard_socket_requests_from_other_lans_are_not_served(tmp_path, fast_scan):
    """The 0.0.0.0:67 socket hears every interface's broadcasts, so a laptop on the office Wi-Fi
    while the bench NIC is served would otherwise offer bench addresses to every phone that
    joins the office LAN (and burn the pool), NAK their INIT-REBOOTs and ACK their INFORMs.
    Only the NIC-bound socket knows the bench LAN; the wildcard serves 0.0.0.0-sourced
    requests only until that socket has delivered one, and never a foreign source."""
    wifi = adapter(name="Wi-Fi", ip="192.168.1.20", dhcp_enabled=True, dhcp_server="192.168.1.1", gateway="192.168.1.1",
                   mac="AA:AA:AA:AA:AA:AA", index=7, if_type=71)
    sim = NicSim([adapter(), wifi])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim)
    office = "AA:BB:CC:DD:EE:03"
    try:
        srv.start(force=True)
        spec, wild = factory.bound_to("172.16.4.100"), factory.bound_to("0.0.0.0")
        assert srv.status()["server_ip"] == "172.16.4.100" and spec is not None and wild is not None
        # until the NIC-bound socket has delivered anything the wildcard is the fallback
        assert srv._specific_seen is False
        assert srv.handle(build(dhcp.DISCOVER, mac=MAC_A, xid=1), ("0.0.0.0", 68), now=T0, sock=wild) == dhcp.OFFER
        assert last_reply(spec)[0].yiaddr == "172.16.4.101"
        # a source outside 172.16.4.0/24 is never served on the wildcard, whatever the message
        n = len(spec.sent)
        assert srv.handle(build(dhcp.REQUEST, mac=office, xid=2, ciaddr="192.168.1.77"), ("192.168.1.77", 68), now=T0 + 1, sock=wild) is None
        assert srv.handle(build(dhcp.INFORM, mac=office, xid=3, ciaddr="192.168.1.77"), ("192.168.1.77", 68), now=T0 + 1, sock=wild) is None
        assert srv.handle(build(dhcp.DISCOVER, mac=office, xid=4, giaddr="192.168.1.1"), ("192.168.1.1", 67), now=T0 + 1, sock=wild) is None
        assert srv.handle(build(dhcp.RELEASE, mac=office, xid=5, ciaddr="192.168.1.77", opts={54: ip4("172.16.4.100")}), ("192.168.1.77", 68),
                          now=T0 + 1, sock=wild) is None
        assert len(spec.sent) == n and srv.status()["counts"] == {"bound": 0, "offered": 1, "total": 1}
        # the NIC-bound socket delivers a request: from now on 0.0.0.0-sourced requests on the
        # wildcard are dropped (no OFFER, no pool address held, no ping, no NAK, no row)
        assert srv.handle(build(dhcp.INFORM, mac=office, xid=6, ciaddr="172.16.4.50"), ("172.16.4.50", 68), now=T0 + 2, sock=spec) == dhcp.ACK
        assert srv._specific_seen is True
        n = len(spec.sent)
        pings = len(srv.pinger.calls)
        assert srv.handle(build(dhcp.DISCOVER, mac=office, xid=7, hostname="office-phone"), ("0.0.0.0", 68), now=T0 + 3, sock=wild) is None
        assert srv.handle(build(dhcp.REQUEST, mac=office, xid=8, opts={50: ip4("192.168.1.77")}), ("0.0.0.0", 68), now=T0 + 3, sock=wild) is None
        assert srv.handle(build(dhcp.REQUEST, mac=office, xid=9, opts={50: ip4("192.168.1.77"), 54: ip4("192.168.1.1")}), ("0.0.0.0", 68),
                          now=T0 + 3, sock=wild) is None
        assert len(spec.sent) == n and len(srv.pinger.calls) == pings
        assert [r["mac"] for r in srv.status()["clients"]] == [MAC_A] and db.get_dhcp_lease(office) is None
        # a bench DISCOVER on the NIC-bound socket is served; its copy on the wildcard is deduped
        assert srv.handle(build(dhcp.DISCOVER, mac=MAC_B, xid=10), ("0.0.0.0", 68), now=T0 + 4, sock=spec) == dhcp.OFFER
        assert srv.handle(build(dhcp.DISCOVER, mac=MAC_B, xid=10), ("0.0.0.0", 68), now=T0 + 4.1, sock=wild) is None
        assert last_reply(spec)[0].yiaddr == "172.16.4.102" and len(spec.sent) == n + 1
        # in-subnet unicasts on the wildcard are fine (a bench client renewing)
        srv.handle(build(dhcp.REQUEST, mac=MAC_B, xid=10, opts={50: ip4("172.16.4.102"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 5, sock=spec)
        assert srv.handle(build(dhcp.REQUEST, mac=MAC_B, xid=11, ciaddr="172.16.4.102"), ("172.16.4.102", 68), now=T0 + 6, sock=wild) == dhcp.ACK
        # no socket given (tests, callers) counts as the NIC-bound one
        assert srv.handle(build(dhcp.INFORM, mac=office, xid=12, ciaddr="172.16.4.51"), ("172.16.4.51", 68), now=T0 + 7) == dhcp.ACK
        # through the receive loop the arrival socket is what counts
        n = len(spec.sent)
        wild.inject(build(dhcp.DISCOVER, mac=office, xid=13), ("0.0.0.0", 68))
        spec.inject(build(dhcp.DISCOVER, mac="AA:BB:CC:DD:EE:04", xid=14), ("0.0.0.0", 68))
        xids = lambda: [dhcp.decode(r, allow_reply=True).xid for r, _d in spec.sent[n:]]
        assert wait_for(lambda: 14 in xids(), 3.0) and 13 not in xids()
        # a restart starts over with the fallback
        srv.stop()
        srv.start(force=True)
        assert srv._specific_seen is False
    finally:
        srv.stop()
        db.close()


def test_dropped_records_are_published_as_forgotten(running):
    """A record that leaves the table (an untaken offer, an offer declined by picking another
    server, a dead record whose address moved on) used to be published with a stale state or
    not at all, so the page kept a yellow "offered" row and an "N offered" badge that
    GET /api/dhcp/status contradicted.  Now it is announced as {mac, state: "forgotten"},
    which removes the row; a bound lease that ran out is published as "expired" whichever
    packet noticed it."""
    srv, sock, events, db = running.srv, running.sock, running.events, running.db
    lease_events = lambda: [e["data"]["lease"] for e in events if e["type"] == "dhcp.lease"]
    srv.handle(build(dhcp.DISCOVER, xid=1), ("0.0.0.0", 68), now=T0)
    assert lease_events()[-1]["state"] == "offered" and lease_events()[-1]["expires_ts"] == T0 + dhcp.OFFER_TTL_S
    # an offer nobody takes: after OFFER_TTL_S the table and the db forget it, and so does the page
    running.clock.t = T0 + dhcp.OFFER_TTL_S + 1
    srv._tick()
    assert wait_for(lambda: lease_events()[-1] == {"mac": MAC_A, "state": "forgotten"})
    assert srv.leases() == [] and srv.status()["counts"] == {"bound": 0, "offered": 0, "total": 0} and db.get_dhcp_lease(MAC_A) is None
    # SELECTING for another server frees our offer: the page hears about that too
    t = running.clock.t
    srv.handle(build(dhcp.DISCOVER, xid=2), ("0.0.0.0", 68), now=t)
    assert lease_events()[-1]["state"] == "offered"
    assert srv.handle(build(dhcp.REQUEST, xid=2, opts={50: ip4("172.16.4.101"), 54: ip4("10.9.9.9")}), ("0.0.0.0", 68), now=t + 1) is None
    assert lease_events()[-1] == {"mac": MAC_A, "state": "forgotten"} and srv.leases() == []
    # a bound lease that ran out is published as expired even when another client's packet is
    # what notices it (the record stays: the client's memory)
    srv.handle(build(dhcp.DISCOVER, xid=3), ("0.0.0.0", 68), now=t + 2)
    srv.handle(build(dhcp.REQUEST, xid=3, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=t + 3)
    assert lease_events()[-1]["state"] == "bound"
    later = t + 3 + 3601
    assert srv.handle(build(dhcp.DISCOVER, mac=MAC_B, xid=4), ("0.0.0.0", 68), now=later) == dhcp.OFFER
    assert [(lz["mac"], lz["state"]) for lz in lease_events()[-2:]] == [(MAC_A, "expired"), (MAC_B, "offered")]
    assert last_reply(sock)[0].yiaddr == "172.16.4.102" and db.get_dhcp_lease(MAC_A)["state"] == "expired"
    # the expired record's address goes to a third client: the dead record is dropped and its
    # row removed (never two rows with one address)
    third = "AA:BB:CC:DD:EE:05"
    assert srv.handle(build(dhcp.DISCOVER, mac=third, xid=5, opts={50: ip4("172.16.4.101")}), ("0.0.0.0", 68), now=later + 1) == dhcp.OFFER
    assert last_reply(sock)[0].yiaddr == "172.16.4.101"
    assert [(lz["mac"], lz["state"]) for lz in lease_events()[-2:]] == [(MAC_A, "forgotten"), (third, "offered")]
    assert {r["mac"] for r in srv.leases()} == {MAC_B, third} and db.get_dhcp_lease(MAC_A) is None
    # the page's own delete gets the same stub
    assert srv.forget_lease(MAC_B) is True and lease_events()[-1] == {"mac": MAC_B, "state": "forgotten"}


def test_decline_only_counts_for_the_decliners_own_address(running):
    srv, sock = running.srv, running.sock
    srv.handle(build(dhcp.DISCOVER, xid=1), ("0.0.0.0", 68), now=T0)
    srv.handle(build(dhcp.REQUEST, xid=1, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 1)
    # B declines A's address: ignored -- A stays bound, .101 is not quarantined, A's reboot is ACKed
    assert srv.handle(build(dhcp.DECLINE, mac=MAC_B, xid=2, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 2) is None
    assert srv._table.bad == {} and srv.leases()[0]["state"] == "bound" and srv.leases()[0]["mac"] == MAC_A
    assert srv.handle(build(dhcp.REQUEST, xid=3, opts={50: ip4("172.16.4.101")}), ("0.0.0.0", 68), now=T0 + 3) == dhcp.ACK
    # a DECLINE for a free pool address (the decliner's record already aged out) is honoured;
    # one for an address outside the pool is not our business
    assert srv.handle(build(dhcp.DECLINE, mac=MAC_B, xid=4, opts={50: ip4("172.16.4.103"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 4) is None
    assert srv._table.bad == {"172.16.4.103": T0 + 4 + dhcp.DECLINE_HOLD_S}
    srv.handle(build(dhcp.DECLINE, mac=MAC_B, xid=5, opts={50: ip4("172.16.4.200"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 5)
    assert "172.16.4.200" not in srv._table.bad
    # A's own DECLINE counts, and a REQUEST for the declined address that arrives afterwards (a
    # delayed duplicate, a stack that re-REQUESTs before it re-DISCOVERs) is NAKed instead of
    # re-binding the address the client itself reported as taken
    assert srv.handle(build(dhcp.DECLINE, xid=6, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 6) is None
    assert srv.leases()[0]["state"] == "declined" and srv._table.bad["172.16.4.101"] == T0 + 6 + dhcp.DECLINE_HOLD_S
    assert srv.handle(build(dhcp.REQUEST, xid=7, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 7) == dhcp.NAK
    assert srv.leases()[0]["state"] == "declined" and last_reply(sock)[0].opts[56] == b"address not offered to you"
    srv.handle(build(dhcp.DISCOVER, xid=8), ("0.0.0.0", 68), now=T0 + 8)
    assert last_reply(sock)[0].yiaddr == "172.16.4.102"


def test_stop_restores_the_nic_before_waiting_for_a_busy_worker(tmp_path, fast_scan):
    """The Engine gives dhcp.stop() a 3 s share.  The netsh restore (1-3 s) must not queue
    behind a probe thread that is mid port-scan (up to the 2 s join), or the adapter would be
    restored outside the budget while the database is already closing."""
    sim = NicSim([adapter()])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim)
    try:
        srv.start(force=True)
        assert sim.find("Ethernet").ipv4[0].address == "172.16.4.100"
        busy = threading.Event()

        def slow_probe(key, stop_evt=None):
            busy.set()
            time.sleep(1.2)
            return False

        srv._probe_one = slow_probe
        srv.handle(build(dhcp.DISCOVER, xid=1), ("0.0.0.0", 68), now=T0)
        srv.handle(build(dhcp.REQUEST, xid=1, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 1)
        assert busy.wait(3.0)
        stamps: Dict[str, float] = {}
        real = sim.__call__

        def stamping(argv, **kw):
            if "source=dhcp" in argv and "address" in argv:
                stamps["restore"] = time.monotonic()
            return real(argv, **kw)

        srv._nic._runner = stamping
        t0 = time.monotonic()
        st = srv.stop()
        assert stamps["restore"] - t0 < 0.5 and sim.find("Ethernet").dhcp_enabled is True
        assert st["running"] is False and factory.bound_to("172.16.4.100").closed and not db.get_meta("dhcp.nic_changed")
        assert wait_for(lambda: not {t.name for t in threading.enumerate()} & {"tnt-dhcp-rx", "tnt-ping-dhcp-probe"}, 3.0)
    finally:
        srv.stop()
        db.close()


# =========================================================================================
# review fixes: scan/start safety, NIC restore, DAD, stale workers, moved probes, ageing
# =========================================================================================
def test_scan_keeps_the_known_server_when_the_probe_socket_cannot_bind():
    """F5: a NIC whose (nic_ip, 67) bind fails (another scan holding the port) used to vanish
    from the result together with the DHCP server the adapter itself knows about."""
    eth = adapter()                                                   # DHCP client of 10.0.0.251
    factory = FakeSocketFactory()
    factory.fail_bind.add(("10.0.0.112", 67))
    res = dhcp.scan_for_servers([eth], 0.2, socket_factory=factory, own_ips={"10.0.0.112"}, clock=FakeClock())
    assert res["probed"] == [{"adapter": "Ethernet", "ip": "10.0.0.112"}]
    assert len(res["errors"]) == 1 and res["errors"][0].startswith("Ethernet (10.0.0.112): cannot listen on UDP 67")
    assert [(sv["server_ip"], sv["known"], sv["answered"]) for sv in res["servers"]] == [("10.0.0.251", True, False)]
    # the helper start() uses to decide whether a scan says anything about the chosen NIC
    assert dhcp._scan_problem(res, "Ethernet", "10.0.0.112") == res["errors"][0]
    clean = {"probed": [{"adapter": "Ethernet", "ip": "10.0.0.112"}], "errors": ["Ethernet 2 (10.0.0.5): send failed: x"]}
    assert dhcp._scan_problem(clean, "Ethernet", "10.0.0.112") is None
    assert dhcp._scan_problem(clean, "Ethernet 2", "10.0.0.5") == clean["errors"][0]
    assert "was not probed" in dhcp._scan_problem({"probed": [], "errors": []}, "Ethernet", "10.0.0.112")


def test_start_refuses_when_the_chosen_nic_could_not_be_checked(tmp_path, fast_scan):
    """F14: a pre-start scan whose probe on the chosen adapter failed proves nothing; start()
    used to treat servers == [] as clean and re-address the NIC."""
    sim = NicSim([adapter(dhcp_server=None)])            # a DHCP client that never got a lease: nothing "known"
    factory = FakeSocketFactory()
    factory.fail_bind.add(("10.0.0.112", 67))
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim, factory=factory)
    try:
        with pytest.raises(RuntimeError, match=r"could not check Ethernet for other DHCP servers: Ethernet \(10\.0\.0\.112\): cannot listen on UDP 67"):
            srv.start()
        assert srv.running is False and "could not check Ethernet" in srv.status()["error"]
        assert not any(c[3:5] == ["set", "address"] for c in sim.commands) and not db.get_meta("dhcp.nic_changed")
        assert events[-1]["type"] == "dhcp.state" and srv.status()["scan"]["errors"]
        # the adapter's own server still shows up although its probe socket failed (F5)
        sim.adapters[0].dhcp_server = "10.0.0.251"
        with pytest.raises(dhcp.DhcpConflict) as ei:
            srv.start()
        assert ei.value.servers[0]["server_ip"] == "10.0.0.251" and ei.value.servers[0]["known"] is True and ei.value.scan["errors"]
        # forced: no scan, the server comes up on the static address
        st = srv.start(force=True)
        assert st["running"] is True and st["server_ip"] == "172.16.4.100" and st["error"] is None
    finally:
        srv.stop()
        db.close()


def test_scan_and_start_are_serialised(tmp_path, monkeypatch):
    """F5: a manual check held (nic_ip, 67) while start()'s own scan ran on the same NIC, whose
    bind then failed -- servers == [] and the switch went on.  Both now take the operation
    lock, in either order."""
    monkeypatch.setattr(dhcp, "MIN_SCAN_WAIT_S", 0.2)
    sim = NicSim([adapter(dhcp_enabled=False)])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim)
    box: Dict[str, Any] = {}
    real = dhcp.scan_for_servers

    def timed(adapters, wait_s, **kw):
        res = real(adapters, min(wait_s, 0.8), **kw)
        box["scan_done"] = time.monotonic()
        return res

    monkeypatch.setattr(dhcp, "scan_for_servers", timed)
    try:
        th = threading.Thread(target=lambda: box.__setitem__("res", srv.scan(wait_s=0.8)), daemon=True)
        th.start()
        assert wait_for(lambda: srv._scan_cancel is not None)
        got = srv._op_lock.acquire(blocking=False)
        if got:
            srv._op_lock.release()
        assert not got                                                 # the check holds the operation lock
        t0 = time.monotonic()
        st = srv.start(force=True)                                     # waits for the check to finish
        t1 = time.monotonic()
        assert st["running"] is True and t1 - t0 >= 0.5 and box["scan_done"] <= t1
        th.join(2.0)
        assert box["res"]["servers"] == [] and box["res"]["duration_s"] >= 0.75 and srv.status()["scan"] is box["res"]
        srv.stop()
        # ... and a check that arrives during an (unforced, scanning) start waits for that start
        th = threading.Thread(target=lambda: box.__setitem__("start", srv.start()), daemon=True)
        th.start()
        assert wait_for(lambda: srv._scan_cancel is not None)
        t0 = time.monotonic()
        res = srv.scan(wait_s=0.2)
        elapsed = time.monotonic() - t0
        th.join(2.0)
        assert srv.running is True and elapsed >= 0.5 and box["start"]["running"] is True
        assert res["probed"] == [{"adapter": "Ethernet", "ip": "10.0.0.112"}] and res["servers"] == []
    finally:
        srv.stop()
        db.close()


def test_firewall_rule_is_ensured_before_the_scan_and_by_scan(tmp_path, fast_scan):
    """F6/F17: on the installed service the rule used to be added only after the pre-start
    scan, so the very first scan's unicast OFFERs to :67 were dropped by Windows Firewall."""
    exe = r"C:\Program Files\TNT\TNTService.exe"
    sim = NicSim([adapter(dhcp_enabled=False)])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim, factory=answering_factory())
    fw: List[Tuple[str, int]] = []                                     # (verb, sockets opened so far)
    fail_add = False
    real = sim.__call__

    def runner(argv, **kw):
        if argv[1] == "advfirewall":
            fw.append((argv[3], len(factory.sockets)))
            if argv[3] == "add" and fail_add:
                return SimpleNamespace(returncode=1, stdout=b"", stderr=b"The requested operation requires elevation.")
        return real(argv, **kw)

    srv._runner = runner
    try:
        # a manual check on a fresh service: rule added before any probe socket exists
        assert [sv["server_ip"] for sv in srv.scan(wait_s=0.2)["servers"]] == ["10.0.0.251"]
        assert fw == [("show", 0), ("add", 0)] and sim.firewall_added == [exe]
        assert srv.status()["firewall"] == {"rule": dhcp.FIREWALL_RULE_NAME, "ok": True, "error": None}
        # an unforced start: the (idempotent) show runs before the pre-start scan opens its sockets
        n = len(factory.sockets)
        with pytest.raises(dhcp.DhcpConflict):
            srv.start()
        assert fw[2:] == [("show", n)] and len(factory.sockets) > n and sim.firewall_added == [exe]
        # a rule that cannot be created never stops a check; it is reported in the status
        fail_add = True
        sim.firewall_program = None
        assert [sv["server_ip"] for sv in srv.scan(wait_s=0.2)["servers"]] == ["10.0.0.251"]
        assert fw[-2:][0][0] == "show" and fw[-1][0] == "add" and srv.status()["firewall"]["ok"] is False
        assert "elevation" in srv.status()["firewall"]["error"]
    finally:
        srv.stop()
        db.close()


def test_start_waits_for_dad_and_a_duplicate_static_address_fails_cleanly(tmp_path, fast_scan):
    """F8: netsh lists the new address as *tentative* while Windows checks the wire for a
    duplicate (a bind to it fails with WinError 10049); *duplicate* means a bench box already
    has 172.16.4.100 -- the NIC goes straight back to DHCP and the start fails with a clear
    message."""
    sim = NicSim([adapter()])
    sim.dad_sequence = [DAD_TENTATIVE, DAD_TENTATIVE, DAD_PREFERRED]
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim)
    try:
        st = srv.start(force=True)
        assert st["running"] is True and sim.dad_sequence == [] and clock.t >= T0 + 0.5         # two 0.25 s polls
        assert factory.bound_to("172.16.4.100").bound == ("172.16.4.100", 67) and sim.find("Ethernet").ipv4[0].preferred is True
        srv.stop()
        assert sim.find("Ethernet").dhcp_enabled is True
        sim.static_dad = DAD_DUPLICATE
        n = len(factory.sockets)
        sim.commands.clear()
        with pytest.raises(RuntimeError, match="static address 172.16.4.100 is already used on this network"):
            srv.start(force=True)
        assert srv.running is False and len(factory.sockets) == n                             # never bound
        nic_cmds = [c for c in sim.commands if c[1] == "interface"]
        assert [c[3:6] for c in nic_cmds] == [["set", "address", "name=Ethernet"]] * 2
        assert "source=static" in nic_cmds[0] and "source=dhcp" in nic_cmds[1]
        assert sim.find("Ethernet").dhcp_enabled is True and sim.find("Ethernet").ipv4[0].address == "10.0.0.112"
        assert not db.get_meta("dhcp.nic_changed") and "already used on this network" in srv.status()["error"]
        assert srv.status()["adapter"]["changed"] is False and events[-1]["type"] == "dhcp.state"
    finally:
        srv.stop()
        db.close()


def test_start_after_a_failed_restore_still_restores_on_stop(tmp_path, fast_scan):
    """F9: when stop() could not put the adapter back on DHCP, the next start() saw a "static"
    adapter, planned no change and so never restored it -- stuck on 172.16.4.100 until
    a service restart or reboot."""
    sim = NicSim([adapter()])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim)
    try:
        srv.start(force=True)
        sim.fail_restore = True
        st = srv.stop()
        assert "could not be put back on DHCP" in st["warning"] and st["adapter"]["changed"] is True
        assert sim.find("Ethernet").dhcp_enabled is False and sim.find("Ethernet").ipv4[0].address == "172.16.4.100"
        assert json.loads(db.get_meta("dhcp.nic_changed"))["static_ip"] == "172.16.4.100"
        sim.fail_restore = False
        sim.commands.clear()
        st = srv.start(force=True)
        assert st["running"] is True and st["server_ip"] == "172.16.4.100" and st["adapter"]["ip"] == "172.16.4.100"
        assert st["adapter"]["changed"] is True and st["adapter"]["will_change"] is False and st["warning"] is None
        assert st["pool"] == {"start": "172.16.4.101", "end": "172.16.4.105", "size": 5, "auto": True}
        assert not any(c[1] == "interface" for c in sim.commands)         # no new netsh: the address is ours already
        st = srv.stop()
        assert sim.find("Ethernet").dhcp_enabled is True and sim.find("Ethernet").ipv4[0].address == "10.0.0.112"
        assert not db.get_meta("dhcp.nic_changed") and st["adapter"]["changed"] is False and st["warning"] is None
        # a record for *another* adapter that is still on our static address is restored before
        # serving on this one -- a second record must never overwrite the only trail to it
        wifi = adapter(name="Wi-Fi", ip="10.9.0.5", dhcp_server="10.9.0.1", gateway="10.9.0.1", mac="AA:AA:AA:AA:AA:AA", index=4, if_type=71)
        sim.adapters.append(wifi)
        sim.original[4] = (list(wifi.ipv4), True)
        wifi.ipv4, wifi.dhcp_enabled, wifi.dhcp_server = [ipaddr("172.16.4.100", 24)], False, None
        db.set_meta("dhcp.nic_changed", json.dumps({"adapter": "Wi-Fi", "index": 4, "mac": "AA:AA:AA:AA:AA:AA",
                                                    "static_ip": "172.16.4.100", "prefix": 24}))
        sim.fail_restore = True
        with pytest.raises(RuntimeError, match="'Wi-Fi' is still on 172.16.4.100"):
            srv.start(force=True)
        assert json.loads(db.get_meta("dhcp.nic_changed"))["adapter"] == "Wi-Fi" and sim.find("Ethernet").dhcp_enabled is True
        assert srv.running is False and "Wi-Fi" in srv.status()["error"]
        sim.fail_restore = False
        st = srv.start(force=True)
        assert st["running"] is True and st["adapter"]["name"] == "Ethernet" and sim.find("Wi-Fi").dhcp_enabled is True
        assert json.loads(db.get_meta("dhcp.nic_changed"))["adapter"] == "Ethernet"
    finally:
        srv.stop()
        db.close()


def test_probe_result_for_a_moved_lease_is_discarded_and_the_new_address_probed(tmp_path, fast_scan, monkeypatch):
    """F15: a client that DECLINEs and re-DISCOVERs while its first address is being probed
    used to get the old address's ports written onto the new one -- and the new address was
    never probed because the key still sat in the queued set."""
    monkeypatch.setattr(dhcp, "PROBE_DELAY_S", 0.05)
    sim = NicSim([adapter(ip="172.16.4.100", dhcp_enabled=False, gateway=None)])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim)
    moved = threading.Event()
    probed: List[Tuple[str, int]] = []

    def connect(ip, port, timeout):
        probed.append((ip, port))
        if ip == "172.16.4.101" and not moved.is_set():
            moved.set()
            # the client saw a squatter on .101: DECLINE, then a fresh DISCOVER/REQUEST -> .102
            srv.handle(build(dhcp.DECLINE, xid=1, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 2)
            srv.handle(build(dhcp.DISCOVER, xid=2), ("0.0.0.0", 68), now=T0 + 3)
            srv.handle(build(dhcp.REQUEST, xid=2, opts={50: ip4("172.16.4.102"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 4)
        return port == (80 if ip.endswith(".101") else 443)

    srv._tcp_connect = connect
    try:
        srv.start(force=True)
        assert srv.handle(build(dhcp.DISCOVER, xid=1), ("0.0.0.0", 68), now=T0) == dhcp.OFFER
        assert srv.handle(build(dhcp.REQUEST, xid=1, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=T0 + 1) == dhcp.ACK
        assert wait_for(moved.is_set, 3.0)

        def settled() -> bool:
            rows = srv.leases()
            return bool(rows) and rows[0]["ip"] == "172.16.4.102" and rows[0]["probed_ts"] is not None and not rows[0]["probing"]

        assert wait_for(settled, 5.0)
        row = srv.leases()[0]
        assert row["mac"] == MAC_A and row["state"] == "bound" and row["open_ports"] == [443]     # .102's ports, not .101's
        assert db.get_dhcp_lease(MAC_A)["ip"] == "172.16.4.102" and db.get_dhcp_lease(MAC_A)["open_ports"] == [443]
        assert {ip for ip, _p in probed} == {"172.16.4.101", "172.16.4.102"}
        mine = [e["data"]["lease"] for e in events if e["type"] == "dhcp.lease" and e["data"]["lease"].get("mac") == MAC_A]
        assert mine[-1]["ip"] == "172.16.4.102" and mine[-1]["open_ports"] == [443] and mine[-1]["probing"] is False
        assert srv._queued == set()
        # the table-level rule on its own: a result for another address is ignored
        t = make_table()
        t.offer(b"\x01K", MAC_B, "172.16.4.103", T0)
        t.bind(b"\x01K", 600, T0)
        t.leases[b"\x01K"].probing = True
        assert t.update_probe(b"\x01K", {"open_ports": [22]}, T0 + 5, ip="172.16.4.104") is None
        assert t.leases[b"\x01K"].open_ports == [] and t.leases[b"\x01K"].probing is False and t.leases[b"\x01K"].probed_ts is None
        assert t.update_probe(b"\x01K", {"open_ports": [22]}, T0 + 6, ip="172.16.4.103").open_ports == [22]
    finally:
        srv.stop()
        db.close()


def test_a_worker_that_outlives_stop_never_serves_the_next_run(tmp_path, fast_scan):
    """F16: stop() joins its threads for at most STOP_JOIN_S; a receive thread stuck in a slow
    recvfrom used to wake up under the next start() (the shared Event had been cleared) and
    handle its packet with the new run's sockets and table."""
    sim = NicSim([adapter(ip="172.16.4.100", dhcp_enabled=False, gateway=None)])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim)
    try:
        srv.start(force=True)
        old = factory.bound_to("172.16.4.100")
        old_rx = srv._rx_thread
        entered, woke = threading.Event(), threading.Event()
        real_recv = old.recvfrom

        def slow_recv(n):
            entered.set()
            time.sleep(dhcp.STOP_JOIN_S + 0.6)          # longer than stop() is willing to wait
            woke.set()
            return real_recv(n)

        old.recvfrom = slow_recv
        old.inject(build(dhcp.DISCOVER, xid=0x77), ("0.0.0.0", 68))
        assert entered.wait(3.0)
        t0 = time.monotonic()
        st = srv.stop()
        assert st["running"] is False and time.monotonic() - t0 < dhcp.STOP_JOIN_S + 1.0 and old_rx.is_alive()
        st = srv.start(force=True)
        new = [s for s in factory.sockets if s.bound == ("172.16.4.100", 67)][-1]
        assert st["running"] is True and new is not old and srv._rx_thread is not old_rx
        assert woke.wait(4.0) and wait_for(lambda: not old_rx.is_alive(), 3.0)
        # the stale thread dropped its datagram: nothing offered, no lease, no reply anywhere
        assert new.sent == [] and old.sent == [] and srv.status()["counts"]["total"] == 0 and srv.leases() == []
        assert len([t for t in threading.enumerate() if t.name == "tnt-dhcp-rx"]) == 1
        # the new run itself is fine
        assert srv.handle(build(dhcp.DISCOVER, xid=0x78), ("0.0.0.0", 68), now=T0) == dhcp.OFFER
    finally:
        srv.stop()
        db.close()


def test_leases_are_aged_while_the_server_is_off(tmp_path, fast_scan):
    """F18: with the server off nothing ticked the table, so yesterday's lease came back as
    "bound" from the database while counts/summary said 0."""
    sim = NicSim([adapter(ip="172.16.4.100", dhcp_enabled=False, gateway=None)])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim, clock=FakeClock(T0 + 86400))
    try:
        db.upsert_dhcp_lease({"mac": MAC_A, "ip": "172.16.4.101", "state": "bound", "first_ts": T0, "last_ts": T0, "expires_ts": T0 + 3600,
                              "client_id": "01" + MAC_A.replace(":", "").lower()})
        db.upsert_dhcp_lease({"mac": MAC_B, "ip": "172.16.4.102", "state": "offered", "first_ts": T0, "last_ts": T0 + 1})
        rows = srv.leases()
        assert {r["mac"]: r["state"] for r in rows} == {MAC_A: "expired", MAC_B: "expired"}
        st = srv.status()
        assert [c["state"] for c in st["clients"]] == ["expired", "expired"]
        assert st["counts"] == {"bound": 0, "offered": 0, "total": 2} and srv.summary()["bound"] == 0 and srv.summary()["offered"] == 0
        assert db.get_dhcp_lease(MAC_A)["state"] == "expired" and db.get_dhcp_lease(MAC_A)["expires_ts"] is None
        # a lease that runs out after stop(): the last run's table ages the same way
        srv.start(force=True)
        now = clock.t
        srv.handle(build(dhcp.DISCOVER, xid=1), ("0.0.0.0", 68), now=now)
        srv.handle(build(dhcp.REQUEST, xid=1, opts={50: ip4("172.16.4.101"), 54: ip4("172.16.4.100")}), ("0.0.0.0", 68), now=now + 1)
        srv.stop()
        rows = srv.leases()
        assert [r["state"] for r in rows if r["mac"] == MAC_A] == ["bound"] and srv.status()["counts"]["bound"] == 1
        assert srv.summary()["bound"] == 1
        clock.t = now + 4000
        rows = srv.leases()
        assert [r["state"] for r in rows if r["mac"] == MAC_A] == ["expired"]
        st = srv.status()
        assert st["counts"] == {"bound": 0, "offered": 0, "total": 2} and len(st["clients"]) == 2 and srv.summary()["bound"] == 0
        assert db.get_dhcp_lease(MAC_A)["state"] == "expired"
    finally:
        srv.stop()
        db.close()


def test_status_flags_the_internet_adapter(tmp_path, fast_scan, monkeypatch):
    """``is_internet`` marks the NIC the PC's default route leaves through (the UI warns that
    serving on it takes the PC offline); a lookup failure just means False."""
    from tnt import netinfo

    eth = adapter()
    wifi = adapter(name="Wi-Fi", ip="10.9.0.5", dhcp_server="10.9.0.1", gateway="10.9.0.1", mac="AA:AA:AA:AA:AA:AA", index=4, if_type=71)
    sim = NicSim([eth, wifi])
    srv, events, factory, db, cfg, clock = make_server(tmp_path, sim)
    seen: List[Any] = []

    def internet(adapters=None):
        seen.append(list(adapters or []))
        return wifi

    try:
        monkeypatch.setattr(netinfo, "get_internet_nic", internet)
        st = srv.status()
        assert st["adapter"]["name"] == "Ethernet" and st["adapter"]["is_internet"] is False
        assert {a["name"]: a["is_internet"] for a in st["adapters"]} == {"Ethernet": False, "Wi-Fi": True}
        assert seen and [a.name for a in seen[-1]] == ["Ethernet", "Wi-Fi"]         # looked up among the candidates
        monkeypatch.setattr(netinfo, "get_internet_nic", lambda adapters=None: eth)
        st = srv.status()
        assert st["adapter"]["is_internet"] is True and {a["name"]: a["is_internet"] for a in st["adapters"]} == {"Ethernet": True, "Wi-Fi": False}
        # matched by ifindex when the objects differ (netinfo re-enumerates), by name without one
        monkeypatch.setattr(netinfo, "get_internet_nic", lambda adapters=None: adapter(name="renamed", index=12))
        assert srv.status()["adapter"]["is_internet"] is True
        monkeypatch.setattr(netinfo, "get_internet_nic", lambda adapters=None: adapter(name="Wi-Fi", index=0))
        assert {a["name"]: a["is_internet"] for a in srv.status()["adapters"]} == {"Ethernet": False, "Wi-Fi": True}
        monkeypatch.setattr(netinfo, "get_internet_nic", lambda adapters=None: None)
        assert srv.status()["adapter"]["is_internet"] is False
        monkeypatch.setattr(netinfo, "get_internet_nic", lambda adapters=None: 1 / 0)
        st = srv.status()
        assert st["adapter"]["is_internet"] is False and all(a["is_internet"] is False for a in st["adapters"])
    finally:
        srv.stop()
        db.close()


# =========================================================================================
# loopback end-to-end: real sockets on 127.0.0.1, port 0
# =========================================================================================
def test_loopback_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setattr(dhcp, "PROBE_DELAY_S", 0.1)
    lo = adapter(name="LoopNIC", ip="127.0.0.1", prefix=8, dhcp_enabled=False, gateway=None, mac="AA:BB:CC:00:00:01")
    sim = NicSim([lo])
    cfg = tnt_config.Config(tmp_path / "config.json").load()
    db = tnt_db.Database(tmp_path / "tnt.db")
    bus = tnt_events.EventBus()
    events: List[dict] = []
    bus.subscribe(lambda e: events.append(e))
    pinger = FakePinger(alive={"127.0.0.2"})
    srv = dhcp.DhcpServer(db, cfg, bus, pinger=pinger, adapters_fn=sim.get_adapters, runner=sim,
                          tcp_connect=lambda ip, port, t: port == 80, resolver=lambda ip: "cam-1", vendor_fn=lambda mac: "Acme",
                          port=0, exe_path=r"C:\Program Files\TNT\TNTService.exe")
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        st = srv.start(force=True)
        port = srv._bound_port
        assert st["running"] is True and port > 0 and st["server_ip"] == "127.0.0.1"
        assert st["pool"]["start"] == "127.0.0.2" and st["pool"]["end"] == "127.0.0.6"
        client.bind(("127.0.0.1", 0))
        client.settimeout(3.0)
        client.sendto(build(dhcp.DISCOVER, xid=0x51), ("127.0.0.1", port))
        raw, src = client.recvfrom(2048)
        offer = dhcp.decode(raw, allow_reply=True)
        # the reply came back unicast to the client's source (reply_dest rule 4) from the server port
        assert src == ("127.0.0.1", port) and offer.msg_type == dhcp.OFFER and offer.xid == 0x51
        assert offer.yiaddr == "127.0.0.3" and 6 not in offer.opts and offer.opts[54] == ip4("127.0.0.1")   # .2 answered the ping
        assert offer.opts[3] == ip4("127.0.0.1") and offer.opts[1] == ip4("255.0.0.0") and offer.opts[28] == ip4("127.255.255.255")
        client.sendto(build(dhcp.REQUEST, xid=0x51, opts={50: ip4(offer.yiaddr), 54: ip4("127.0.0.1")}), ("127.0.0.1", port))
        raw, src = client.recvfrom(2048)
        ack = dhcp.decode(raw, allow_reply=True)
        assert ack.msg_type == dhcp.ACK and ack.yiaddr == "127.0.0.3" and ack.opts[51] == u32(3600)
        # exactly one ACK even though the datagram may have reached both sockets
        with pytest.raises((socket.timeout, TimeoutError)):
            client.settimeout(0.5)
            client.recvfrom(2048)
        lease = srv.leases()[0]
        assert lease["state"] == "bound" and lease["ip"] == "127.0.0.3" and lease["mac"] == MAC_A and lease["hostname"] == "cam-12"
        # the probe worker fills ping / vendor / open ports
        deadline = time.monotonic() + 6.0
        while time.monotonic() < deadline:
            lease = srv.leases()[0]
            if lease["probed_ts"] is not None and not lease["probing"]:
                break
            time.sleep(0.05)
        assert lease["open_ports"] == [80] and lease["vendor"] == "Acme" and lease["ping_ok"] is False and lease["probing"] is False
        assert db.get_dhcp_lease(MAC_A)["open_ports"] == [80]
        assert [e["data"]["lease"]["state"] for e in events if e["type"] == "dhcp.lease"][-1] == "bound"
        # a bad datagram does not kill the receive thread (an INIT-REBOOT request is answered
        # to the source; a RENEW would go to ciaddr:68 per RFC 2131 4.1, where nobody listens here)
        client.sendto(b"\xff" * 10, ("127.0.0.1", port))
        client.sendto(build(dhcp.REQUEST, xid=0x52, opts={50: ip4("127.0.0.3")}), ("127.0.0.1", port))
        client.settimeout(3.0)
        raw, _src = client.recvfrom(2048)
        assert dhcp.decode(raw, allow_reply=True).msg_type == dhcp.ACK
        st = srv.stop()
        assert st["running"] is False
        time.sleep(0.2)
        assert not {t.name for t in threading.enumerate()} & {"tnt-dhcp-rx", "tnt-ping-dhcp-probe"}
        assert not sim.commands or all(c[1] == "advfirewall" for c in sim.commands)     # never touched the NIC
    finally:
        client.close()
        srv.stop()
        db.close()
