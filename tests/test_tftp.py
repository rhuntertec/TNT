r"""Tests for tnt.tftp (the Tools-page TFTP server) and the remote scope of tnt.firewall.ensure_rule.

Offline: real sockets only on loopback with port 0 (127.0.0.1 for the server; 127.0.0.2-127.0.0.9 as more client
addresses for the per-client limit and as an outsider) -- tests/conftest.py refuses UDP 67 and 69 for tnt.tftp -- a fake
netsh runner, a recorder in place of the folder DACL, short timers (no test waits a contract timer) and folders in
tmp_path.  curl interop runs %SystemRoot%\System32\curl.exe against the loopback server
and is skipped only when curl or its tftp protocol is missing.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from tnt import firewall, paths, tftp
from tnt.config import Config
from tnt.events import EventBus
from tnt.netinfo import Adapter, IpAddr

RRQ, WRQ, DATA, ACK, ERROR, OACK = 1, 2, 3, 4, 5, 6
FAST = tftp.TftpTimers(0.05, 0.2, 3, 1.0, 0.1, 0.3)      # the retransmit and give-up test
STEADY = tftp.TftpTimers(0.5, 1.0, 3, 5.0, 0.1, 0.3)     # the default: a busy test machine never causes a resend
SLOW = tftp.TftpTimers(1.0, 2.0, 3, 10.0, 0.1, 0.3)      # nothing retransmits while a test looks
EXE = r"C:\Program Files\TNT\TNTService.exe"
TFTP_SDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)"


# =========================================================================================
# fakes and helpers
# =========================================================================================
def ipaddr(ip: str, prefix: int) -> IpAddr:
    net = ipaddress.IPv4Interface(f"{ip}/{prefix}").network
    return IpAddr(address=ip, prefix=prefix, family=4, netmask=str(net.netmask), network=str(net))


def nic(name="Ethernet", ips=(("127.0.0.1", 8),), index=21, mtu=1500, status="up", if_type=6, physical=True,
        mac="02:00:5e:10:00:01") -> Adapter:
    return Adapter(index=index, name=name, description="Example Ethernet", mac=mac, if_type=if_type,
                   type_name="Ethernet" if if_type == 6 else "Wi-Fi", status=status, speed_bps=None, mtu=mtu,
                   dhcp_enabled=False, dhcp_server=None, dns_suffix="", ipv4=[ipaddr(ip, p) for ip, p in ips],
                   gateways=[], is_physical=physical, is_loopback=False)


class Acl:
    """Stands in for tnt.winacl.secure_dir: records ``(path, sddl)`` and creates the folder (no DACL change)."""

    def __init__(self, fail: Optional[BaseException] = None) -> None:
        self.calls: List[tuple] = []
        self.fail = fail

    def __call__(self, path, sddl):
        self.calls.append((str(path), sddl))
        if self.fail is not None:
            raise self.fail
        os.makedirs(path, exist_ok=True)


class FakeDb:
    def __init__(self) -> None:
        self.events: List[tuple] = []

    def add_event(self, level, category, message, ts=None):
        self.events.append((level, category, message))


class FakeNetsh:
    """``netsh advfirewall firewall`` keyed by rule name; ``show`` prints RemoteIP the way Windows does."""

    def __init__(self) -> None:
        self.rules: Dict[str, Dict[str, str]] = {}
        self.commands: List[List[str]] = []

    def __call__(self, argv, **kwargs):
        args = list(argv[1:])
        self.commands.append(args)
        name = next(x.split("=", 1)[1] for x in args if x.startswith("name="))
        verb = args[2]
        if verb == "show":
            rule = self.rules.get(name)
            if rule is None:
                return SimpleNamespace(returncode=1, stdout=b"\r\nNo rules match the specified criteria.\r\n", stderr=b"")
            remote = rule.get("remoteip", "Any")
            remote = "LocalSubnet" if remote.lower() == "localsubnet" else remote
            out = (f"\r\nRule Name: {name}\r\n" + "-" * 40 + "\r\nEnabled: Yes\r\nDirection: In\r\n"
                   f"Profiles: Domain,Private,Public\r\nLocalIP: Any\r\nRemoteIP: {remote}\r\n"
                   f"Protocol: {rule['protocol'].upper()}\r\nLocalPort: {rule['localport']}\r\nRemotePort: Any\r\n"
                   f"Program: {rule['program']}\r\nAction: Allow\r\nOk.\r\n").encode()
            return SimpleNamespace(returncode=0, stdout=out, stderr=b"")
        if verb == "add":
            self.rules[name] = dict(x.split("=", 1) for x in args[4:] if "=" in x)
            return SimpleNamespace(returncode=0, stdout=b"Ok.\r\n", stderr=b"")
        if verb == "delete":
            existed = self.rules.pop(name, None) is not None
            return SimpleNamespace(returncode=0 if existed else 1, stdout=b"Ok.\r\n", stderr=b"")
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"unknown")


class ResetOnce:
    """A real UDP socket whose first ``recvfrom`` raises WinError 10054, as an ICMP port-unreachable leaves it."""

    def __init__(self, family, kind, counter: list) -> None:
        self._sock = socket.socket(family, kind)
        self._counter = counter
        self._resets = 1

    def __getattr__(self, name):
        return getattr(self._sock, name)

    def recvfrom(self, n):
        if self._resets:
            self._resets -= 1
            self._counter.append(1)
            raise ConnectionResetError(10054, "An existing connection was forcibly closed by the remote host")
        return self._sock.recvfrom(n)


def wait_for(pred, timeout: float = 3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = pred()
        if value:
            return value
        time.sleep(0.01)
    return pred()


def opts(payload: bytes) -> Dict[str, str]:
    fields = payload.split(b"\0")[:-1]
    return {fields[i].decode(): fields[i + 1].decode() for i in range(0, len(fields) - 1, 2)}


def text(payload: bytes) -> str:
    return payload.split(b"\0", 1)[0].decode()


class Client:
    """A small TFTP client written for these tests (independent of tnt.tftp's codec)."""

    def __init__(self, ip: str = "127.0.0.1") -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, 0))
        self.sock.settimeout(2.0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self) -> None:
        self.sock.close()

    def request(self, port, op, name, mode="octet", options=()):
        raw = struct.pack("!H", op) + (name if isinstance(name, bytes) else name.encode()) + b"\0" + mode.encode() + b"\0"
        for key, value in options:
            raw += key.encode() + b"\0" + str(value).encode() + b"\0"
        self.sock.sendto(raw, ("127.0.0.1", port))

    def recv(self, timeout: float = 2.0):
        self.sock.settimeout(timeout)
        while True:
            try:
                raw, addr = self.sock.recvfrom(65536)
            except ConnectionResetError:
                continue                  # a closed server port answered an earlier datagram
            op = struct.unpack_from("!H", raw)[0]
            if op == OACK:
                return op, 0, raw[2:], addr        # an OACK has no block number: its options start at byte 2
            return op, struct.unpack_from("!H", raw, 2)[0], raw[4:], addr

    def silent(self, seconds: float) -> bool:
        """True when nothing arrives within *seconds*."""
        try:
            self.recv(seconds)
        except (socket.timeout, TimeoutError):
            return True
        return False

    def ack(self, addr, block):
        self.sock.sendto(struct.pack("!HH", ACK, block & 0xFFFF), addr)

    def data(self, addr, block, payload):
        self.sock.sendto(struct.pack("!HH", DATA, block & 0xFFFF) + payload, addr)

    def get(self, port, name, mode="octet", options=(), record=None):
        self.request(port, RRQ, name, mode, options)
        op, num, rest, addr = self.recv()
        oack: Dict[str, str] = {}
        if op == OACK:
            oack = opts(rest)
            self.ack(addr, 0)
            op, num, rest, second = self.recv()
            assert second == addr
        if op == ERROR:
            return None, SimpleNamespace(error=(num, text(rest)), oack=oack, addr=addr, blocks=0)
        blksize, window, roll = int(oack.get("blksize", 512)), int(oack.get("windowsize", 1)), int(oack.get("rollover", 0))
        def wire(k):
            return k if k <= 0xFFFF else (k & 0xFFFF if roll == 0 else (k - 1) % 0xFFFF + 1)

        out = bytearray()
        n = 1
        while True:
            assert op == DATA, (op, num)
            if num != wire(n):
                # a block of the current window sent again (the server's timer beat a slow ACK): skip it
                assert any(num == wire(n - k) for k in range(1, window + 1) if n - k >= 1), (num, wire(n))
                op, num, rest, _addr = self.recv()
                continue
            if record is not None and 0xFFFE <= n <= 0x10001:
                record.append(num)
            out += rest
            final = len(rest) < blksize
            if final or n % window == 0:
                self.ack(addr, num)
            if final:
                break
            n += 1
            op, num, rest, _addr = self.recv()
        return bytes(out), SimpleNamespace(error=None, oack=oack, addr=addr, blocks=n)

    def put(self, port, name, payload, mode="octet", options=(), wrap=0):
        self.request(port, WRQ, name, mode, options)
        op, num, rest, addr = self.recv()
        if op == ERROR:
            return SimpleNamespace(error=(num, text(rest)), oack={}, addr=addr, final=None)
        oack: Dict[str, str] = {}
        if op == OACK:
            oack = opts(rest)
        else:
            assert (op, num) == (ACK, 0)
        blksize, window = int(oack.get("blksize", 512)), int(oack.get("windowsize", 1))
        blocks = [payload[i:i + blksize] for i in range(0, len(payload), blksize)]
        if len(payload) % blksize == 0:
            blocks.append(b"")

        def wire(n):
            return n if n <= 0xFFFF else (n & 0xFFFF if wrap == 0 else (n - 1) % 0xFFFF + 1)

        done = 0
        while done < len(blocks):
            chunk = blocks[done:done + window]
            for i, block in enumerate(chunk):
                self.data(addr, wire(done + i + 1), block)
            want = wire(done + len(chunk))
            op, num, rest, _addr = self.recv()
            while (op == ACK and num != want and num == wire(done)) or (op == OACK and done == 0):
                op, num, rest, _addr = self.recv()          # an earlier ACK (or the OACK) repeated on a timeout
            if op == ERROR:
                return SimpleNamespace(error=(num, text(rest)), oack=oack, addr=addr, final=None)
            assert (op, num) == (ACK, want), (op, num)
            done += len(chunk)
        return SimpleNamespace(error=None, oack=oack, addr=addr, final=wire(len(blocks)))


@pytest.fixture
def make(tmp_path, monkeypatch):
    """Build (and by default start) a server on a fake adapter holding 127.0.0.1/8, port 0."""
    monkeypatch.setattr(tftp, "_disk_free", lambda path: 1 << 40)
    made: List[tftp.TftpServer] = []

    def factory(adapters=None, timers=STEADY, start=True, uploads=False, **kw):
        adapters = [nic()] if adapters is None else adapters
        root = kw.pop("root", tmp_path / "tftp")
        cfg = Config(tmp_path / "config.json").load()
        bus = EventBus()
        events: List[dict] = []
        bus.subscribe(events.append)
        acl = kw.pop("acl", None) or Acl()
        srv = tftp.TftpServer(kw.pop("db", None), cfg, bus, port=kw.pop("port", 0), adapters_fn=lambda: list(adapters),
                              root=root, acl=acl, udp_owners_fn=kw.pop("udp_owners_fn", lambda port: []), timers=timers,
                              **kw)
        made.append(srv)
        ctx = SimpleNamespace(srv=srv, events=events, cfg=cfg, root=Path(root), acl=acl, adapters=adapters, port=None)
        if start:
            st = srv.start(uploads=uploads)
            ctx.port = st["listen"][0]["port"]
        return ctx

    yield factory
    for srv in made:
        srv.stop()


def history(ctx, state=None, count=1):
    """The history once it holds *count* entries (in *state* when given)."""
    def ready():
        rows = [t for t in ctx.srv.status()["history"] if state is None or t["state"] == state]
        return rows if len(rows) >= count else None
    return wait_for(ready) or []


# =========================================================================================
# the conftest guard, codec, options, names
# =========================================================================================
def test_conftest_guard_refuses_udp_67_and_69(tmp_path):
    seam = tftp._bind_udp
    assert getattr(seam, "__module__", None) == "conftest", "tests/conftest.py must guard tnt.tftp._bind_udp"
    for port in (67, 69):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(OSError, match="disabled in tests"):
                tftp._bind_udp(s, ("127.0.0.1", port))
        finally:
            s.close()
    # a server left on the real port never gets a socket either
    srv = tftp.TftpServer(None, Config(tmp_path / "config.json").load(), EventBus(), adapters_fn=lambda: [nic()],
                          root=tmp_path / "tftp", acl=Acl(), udp_owners_fn=lambda port: [])
    with pytest.raises(RuntimeError, match="disabled in tests"):
        srv.start()
    st = srv.status()
    assert st["running"] is False and "UDP port 69" in st["error"] and st["listen"] == []


def test_codec_bytes_and_request_parser():
    assert tftp.encode_request(1, "pxelinux.0", "octet", [("blksize", 1468), ("tsize", 0)]) == \
        b"\x00\x01pxelinux.0\x00octet\x00blksize\x001468\x00tsize\x000\x00"
    assert tftp.encode_data(5, b"ab") == b"\x00\x03\x00\x05ab"
    assert tftp.encode_ack(7) == b"\x00\x04\x00\x07"
    assert tftp.encode_error(1, "File not found") == b"\x00\x05\x00\x01File not found\x00"
    assert tftp.encode_oack([("blksize", "1468"), ("windowsize", "16")]) == b"\x00\x06blksize\x001468\x00windowsize\x0016\x00"
    r = tftp.parse_request(b"\x00\x02fw/x.bin\x00OcTeT\x00BLKSIZE\x001024\x00blksize\x00512\x00tsize\x00100\x00")
    assert (r.opcode, r.filename, r.mode, r.options) == (2, b"fw/x.bin", "octet", {"blksize": "1024", "tsize": "100"})
    # NUL padding and an incomplete trailing option are ignored
    assert tftp.parse_request(b"\x00\x01a\x00octet\x00\x00\x00\x00").options == {}
    assert tftp.parse_request(b"\x00\x01a\x00octet\x00timeout\x00").options == {}
    assert tftp.parse_request(b"\x00\x01a\x00octet\x00timeout\x005").options == {}
    assert tftp.parse_request(b"\x00\x01a\x00mail\x00").mode == "mail"
    assert tftp.parse_request(b"\x00\x01" + b"n" * 1000 + b"\x00octet\x00").filename == b"n" * 1000   # over 512: still read
    # not a request, or not NUL-terminated: dropped
    for raw in (b"", b"\x00\x01", b"\x00\x01abc", b"\x00\x01abc\x00octet", b"\x00\x04\x00\x01", b"\x00\x07a\x00octet\x00"):
        assert tftp.parse_request(raw) is None, raw


def test_option_negotiation_table():
    neg = tftp.negotiate_options
    assert neg(RRQ, "octet", {}) == []
    assert neg(RRQ, "octet", {"blksize": "7"}) == [] and neg(RRQ, "octet", {"blksize": "big"}) == []
    assert neg(RRQ, "octet", {"blksize": "8"}) == [("blksize", "8")]
    assert neg(RRQ, "octet", {"blksize": "1024"}, blksize_max=1468) == [("blksize", "1024")]
    for big in ("1469", "65464", "65536", "9" * 25):              # a number, however long, is capped, never dropped
        assert neg(RRQ, "octet", {"blksize": big}, blksize_max=1468) == [("blksize", "1468")]
    assert neg(RRQ, "octet", {"blksize": "0" * 30 + "1024"}, blksize_max=1468) == [("blksize", "1024")]
    assert neg(RRQ, "octet", {"blksize": "0007"}) == [] and neg(RRQ, "octet", {"blksize": "-512"}) == []
    assert neg(RRQ, "octet", {"timeout": "005"}) == [("timeout", "5")] and neg(RRQ, "octet", {"windowsize": "9" * 25}) == []
    assert neg(RRQ, "octet", {"timeout": "0"}) == [] and neg(RRQ, "octet", {"timeout": "256"}) == []
    assert neg(RRQ, "octet", {"timeout": "5"}) == [("timeout", "5")]
    assert neg(RRQ, "octet", {"tsize": "0"}, file_size=1234) == [("tsize", "1234")]
    assert neg(RRQ, "netascii", {"tsize": "0"}, file_size=1234) == []
    assert neg(WRQ, "octet", {"tsize": "4096"}) == [("tsize", "4096")] and neg(WRQ, "octet", {"tsize": "x"}) == []
    assert neg(RRQ, "octet", {"windowsize": "0"}) == [] and neg(RRQ, "octet", {"windowsize": "64"}) == [("windowsize", "16")]
    assert neg(RRQ, "octet", {"windowsize": "4"}) == [("windowsize", "4")]
    assert [neg(RRQ, "octet", {"rollover": v}) for v in ("0", "1", "2")] == [[("rollover", "0")], [("rollover", "1")], []]
    assert neg(RRQ, "octet", {"utimeout": "500", "blksize2": "1024", "msftwindow": "31"}) == []
    # request order and case; the first of two duplicates wins
    req = tftp.parse_request(b"\x00\x01f\x00octet\x00WINDOWSIZE\x008\x00Blksize\x001428\x00blksize\x00512\x00")
    assert neg(RRQ, req.mode, req.options, blksize_max=1468, file_size=10) == [("windowsize", "8"), ("blksize", "1428")]


def test_blksize_max_follows_the_mtu_and_wire_block_numbers_wrap():
    assert tftp.blksize_max(None) == 1468 and tftp.blksize_max(1500) == 1468 and tftp.blksize_max(9000) == 1468
    assert tftp.blksize_max(576) == 544 and tftp.blksize_max(500) == 512
    assert [tftp.wire_block(n) for n in (0, 1, 65535, 65536, 65537, 131071, 131072)] == [0, 1, 65535, 0, 1, 65535, 0]
    assert [tftp.wire_block(n, 1) for n in (65535, 65536, 65537, 131070, 131071)] == [65535, 1, 2, 65535, 1]
    t = tftp.TftpTimers()
    assert (t.initial_s, t.cap_s, t.retries, t.idle_s, t.dally_min_s, t.dally_max_s) == (1.0, 5.0, 5, 60.0, 2.0, 10.0)
    assert t.dally_s(None) == 7.5 and t.dally_s(5) == 7.5 and t.dally_s(1) == 2.0 and t.dally_s(30) == 10.0


def test_name_checks():
    good = {"pxelinux.0": "pxelinux.0", "/pxelinux.0": "pxelinux.0", "fw/a/b/x.bin": "fw\\a\\b\\x.bin",
            "boot\\grub.cfg": "boot\\grub.cfg", "SEP0011.cnf.xml": "SEP0011.cnf.xml", ".hidden": ".hidden",
            "console.bin": "console.bin", "COM10.bin": "COM10.bin", b"caf\xc3\xa9.bin": "caf\u00e9.bin"}
    for raw, want in good.items():
        assert tftp.clean_name(raw) == want, raw
    bad = ["", "..", "../x", "a/../x", "a/./x", "./x", "C:x", "C:\\Windows\\win.ini", "\\\\server\\share\\x",
           "//server/share/x", "\\\\?\\C:\\x", "\\\\.\\PhysicalDrive0", "hl.bin:ads", "a<b", "a>b", 'a"b', "a|b", "a?b",
           "a*b", "trail.txt.", "trail ", "dir./x", "CON", "con.txt", "NUL.bin", "fw/COM1/x", "COM0", "lpt9.log",
           "LPT\u00b9", "CONIN$", "conout$.x", "AUX .txt", "a\x01b", "a\x7fb", "a//b", "a/", "x" * 256,
           "a/b/c/d/e.bin", ".x.bin.0badf00d.part", ".X.BIN.0BADF00D.PART", "fw/.x.bin.0badf00d.Part", b"\xff.bin"]
    for raw in bad:
        with pytest.raises(ValueError, match="File name not allowed"):
            tftp.clean_name(raw)


# =========================================================================================
# transfers over loopback
# =========================================================================================
def test_rrq_sizes_without_options(make):
    ctx = make()
    sizes = {"s0.bin": 0, "s1.bin": 1, "s511.bin": 511, "s512.bin": 512, "s513.bin": 513}
    for name, size in sizes.items():
        (ctx.root / name).write_bytes(os.urandom(size))
    with Client() as c:
        for name, size in sizes.items():
            data, info = c.get(ctx.port, name)
            assert data == (ctx.root / name).read_bytes()
            assert info.oack == {} and info.blocks == size // 512 + 1        # 512 bytes: a zero-length final block
            assert info.addr[0] == "127.0.0.1" and info.addr[1] != ctx.port    # a new transfer ID
    rows = history(ctx, "done", 5)
    assert sorted(t["bytes"] for t in rows) == sorted(sizes.values())
    assert all(t["op"] == "read" and t["client"] == "127.0.0.1" and t["mode"] == "octet" for t in rows)
    assert tuple(rows[0]) == tftp.TFTP_TRANSFER_KEYS and rows[0]["ended_ts"] >= rows[0]["started_ts"]
    assert ctx.srv.status()["counts"]["done"] == 5
    kinds = [e["data"]["transfer"]["state"] for e in ctx.events if e["type"] == "tftp.transfer"]
    assert kinds.count("done") == 5 and "sending" in kinds


def test_oack_options_and_a_pxe_style_abort(make):
    ctx = make(adapters=[nic(mtu=576)], timers=SLOW)
    body = os.urandom(5000)
    (ctx.root / "boot.img").write_bytes(body)
    with Client() as c:
        # PXE firmware asks for tsize only, then aborts after the OACK and asks again
        c.request(ctx.port, RRQ, "boot.img", options=[("tsize", 0)])
        op, _num, rest, addr = c.recv()
        assert op == OACK and opts(rest) == {"tsize": "5000"}
        c.sock.sendto(struct.pack("!HH", ERROR, 0) + b"TFTP Aborted\x00", addr)
        first = history(ctx, "cancelled")
        assert "TFTP Aborted" in first[0]["error"]
        # blksize capped by the MTU (576 - 32), windowsize and timeout echoed, an unknown option left out
        data, info = c.get(ctx.port, "boot.img", options=[("tsize", 0), ("blksize", 1468), ("windowsize", 4),
                                                           ("timeout", 3), ("foo", "bar")])
        assert data == body
        assert list(info.oack.items()) == [("tsize", "5000"), ("blksize", "544"), ("windowsize", "4"), ("timeout", "3")]
    done = history(ctx, "done")
    assert (done[0]["blksize"], done[0]["windowsize"], done[0]["size"], done[0]["bytes"]) == (544, 4, 5000, 5000)


def test_rollover_with_blksize_8(make):
    ctx = make()
    size = 65536 * 8 + 3                 # 65,537 blocks: wire 65535, then 0 (or 1), then 1 (or 2)
    body = bytes(range(256)) * (size // 256) + bytes(size % 256)
    (ctx.root / "big.bin").write_bytes(body)
    with Client() as c:
        seen: List[int] = []
        data, info = c.get(ctx.port, "big.bin", options=[("blksize", 8), ("windowsize", 16)], record=seen)
        assert data == body and info.blocks == 65537 and seen == [65534, 65535, 0, 1]
        seen = []
        data, info = c.get(ctx.port, "big.bin", options=[("blksize", 8), ("windowsize", 16), ("rollover", 1)], record=seen)
        assert data == body and info.oack["rollover"] == "1" and seen == [65534, 65535, 1, 2]
    # an upload may wrap to 1 without asking: the server follows the first wrap it sees
    ctx.srv.set_uploads(True)
    with Client() as c:
        res = c.put(ctx.port, "wrapped.bin", body, options=[("blksize", 8), ("windowsize", 16)], wrap=1)
        assert res.error is None
    assert (ctx.root / "wrapped.bin").read_bytes() == body


def test_netascii_conversion_keeps_state_across_blocks():
    enc = tftp._NetasciiEncoder()
    assert enc.feed(b"a\nb\r\nc\rd") == b"a\r\nb\r\nc\r\0d"
    assert enc.feed(b"x\r") == b"x" and enc.feed(b"\ny\r") == b"\r\ny" and enc.feed(b"z") == b"\r\0z"
    assert enc.feed(b"\r") == b"" and enc.finish() == b"\r\0" and enc.finish() == b""
    assert enc.feed(b"\r\r\n\n\r") == b"\r\0\r\n\r\n" and enc.finish() == b"\r\0"
    dec = tftp._NetasciiDecoder()
    assert dec.feed(b"a\r\nb\r\0c") == b"a\r\nb\rc"
    assert dec.feed(b"x\r") == b"x" and dec.feed(b"\0y") == b"\ry"
    assert dec.feed(b"\r") == b"" and dec.feed(b"\n") == b"\r\n"
    assert dec.feed(b"\r") == b"" and dec.finish() == b"\r" and dec.finish() == b""
    # a block source cuts converted output into full blocks, whatever the read chunks were
    r, w = os.pipe()
    os.write(w, b"abcdefg\nhi")
    os.close(w)
    try:
        src = tftp._BlockSource(r, 8, netascii=True)
        assert [src.next_block(), src.next_block(), src.next_block()] == [b"abcdefg\r", b"\nhi", b""]
    finally:
        os.close(r)


def test_netascii_over_the_wire_with_a_cr_on_the_block_boundary(make):
    ctx = make(uploads=True)
    (ctx.root / "cfg.txt").write_bytes(b"abcdefg\nline2\r\nbare\rend")
    with Client() as c:
        # blksize 8: the CR that "\n" becomes is the last byte of block 1, its LF the first of block 2
        data, info = c.get(ctx.port, "cfg.txt", mode="netascii", options=[("blksize", 8), ("tsize", 0)])
        assert data == b"abcdefg\r\nline2\r\nbare\r\0end" and info.oack == {"blksize": "8"}
        # upload: block 1 ends with CR, block 2 starts with its NUL
        up = c.put(ctx.port, "up.txt", b"abcdefg\r\0rest\r\nx", mode="netascii", options=[("blksize", 8)])
        assert up.error is None
    assert (ctx.root / "up.txt").read_bytes() == b"abcdefg\rrest\r\nx"


def test_a_duplicate_ack_never_resends_data_and_a_repeated_request_starts_nothing(make):
    ctx = make(timers=SLOW)
    (ctx.root / "three.bin").write_bytes(b"x" * 1500)            # 512 + 512 + 476
    with Client() as c:
        c.request(ctx.port, RRQ, "three.bin")
        c.request(ctx.port, RRQ, "three.bin")                    # the same request again from the same port
        op, num, _p, addr = c.recv()
        assert (op, num) == (DATA, 1)
        assert c.silent(0.2)                                     # one session only
        c.ack(addr, 1)
        assert c.recv()[:2] == (DATA, 2)
        c.ack(addr, 1)
        c.ack(addr, 1)                                           # duplicates of the previous ACK (Sorcerer's Apprentice)
        assert c.silent(0.3)                                     # no second DATA 2 and no DATA 3
        c.ack(addr, 2)
        op, num, payload, _a = c.recv()
        assert (op, num, len(payload)) == (DATA, 3, 476)
        c.ack(addr, 3)
    assert history(ctx, "done")[0]["bytes"] == 1500 and ctx.srv.status()["counts"]["done"] == 1


def test_a_different_request_from_a_live_port_starts_a_new_transfer(make):
    ctx = make(timers=SLOW)
    (ctx.root / "a.bin").write_bytes(b"a" * 700)
    (ctx.root / "b.bin").write_bytes(b"b" * 10)
    with Client() as c:
        c.request(ctx.port, RRQ, "a.bin")
        op, num, _p, first = c.recv()
        assert (op, num) == (DATA, 1)
        c.request(ctx.port, RRQ, "b.bin")                       # a.bin never acknowledged: asks again from the same port
        op, num, payload, second = c.recv()
        assert (op, num, payload) == (DATA, 1, b"b" * 10) and second != first
        c.ack(second, 1)
    assert history(ctx, "done")[0]["file"] == "b.bin"
    assert [t["file"] for t in ctx.srv.status()["transfers"]] == ["a.bin"]      # still waiting for its ACK


def test_windowsize_loss_and_repeats_are_recovered_in_both_directions(make):
    ctx = make(uploads=True, timers=SLOW)
    body = bytes(range(40))                                      # 5 full blocks of 8, then an empty final block
    (ctx.root / "w.bin").write_bytes(body)
    with Client() as c:
        # read: an ACK for an earlier block of the window restarts from the block after it, once
        c.request(ctx.port, RRQ, "w.bin", options=[("blksize", 8), ("windowsize", 4)])
        op, _num, rest, addr = c.recv()
        assert op == OACK and opts(rest) == {"blksize": "8", "windowsize": "4"}
        c.ack(addr, 0)
        first = [c.recv()[:3] for _ in range(4)]
        assert [(op, num) for op, num, _p in first] == [(DATA, 1), (DATA, 2), (DATA, 3), (DATA, 4)]
        c.ack(addr, 2)                                           # block 3 was "lost"
        c.ack(addr, 2)                                           # the same ACK again changes nothing
        again = [c.recv()[:3] for _ in range(4)]
        assert [(op, num) for op, num, _p in again] == [(DATA, 3), (DATA, 4), (DATA, 5), (DATA, 6)]
        assert again[2][2] == body[32:40] and again[3][2] == b"" and c.silent(0.2)
        c.ack(addr, 6)
        # write: a repeated window is ACKed once; a gap ACKs the last in-order block once and drops what is ahead
        upload = bytes(range(100, 172))                          # 9 full blocks, then an empty final block
        blocks = [upload[i:i + 8] for i in range(0, 72, 8)] + [b""]
        c.request(ctx.port, WRQ, "wu.bin", options=[("blksize", 8), ("windowsize", 4)])
        op, _num, rest, addr = c.recv()
        assert op == OACK and opts(rest) == {"blksize": "8", "windowsize": "4"}
        for n in (1, 2, 3, 4):
            c.data(addr, n, blocks[n - 1])
        assert c.recv()[:2] == (ACK, 4)
        for n in (1, 2, 3, 4):                                   # the window again, as if that ACK was lost
            c.data(addr, n, blocks[n - 1])
        assert c.recv()[:2] == (ACK, 4) and c.silent(0.2)
        for n in (5, 6, 8):                                      # block 7 "lost"
            c.data(addr, n, blocks[n - 1])
        assert c.recv()[:2] == (ACK, 6)
        c.data(addr, 9, blocks[8])
        assert c.silent(0.2)
        for n in (7, 8, 9, 10):
            c.data(addr, n, blocks[n - 1])
        assert c.recv()[:2] == (ACK, 10)
    assert (ctx.root / "wu.bin").read_bytes() == upload
    assert {t["file"]: t["state"] for t in history(ctx, "done", 2)} == {"w.bin": "done", "wu.bin": "done"}


def test_a_timeout_ack_starts_the_upload_window_count_again(make):
    """RFC 7440 upload: when the server's timer repeats the last in-order ACK (the rest of a window was lost), the device
    restarts its window at the block after it, so the server counts that window from there.  Counting on from the blocks
    before the timeout puts every later ACK in the middle of a device window and doubles the DATA the upload costs."""
    ctx = make(uploads=True, timers=tftp.TftpTimers(0.3, 0.6, 5, 5.0, 0.1, 0.3))
    upload = bytes(range(200, 248))                              # 6 full blocks of 8, then an empty final block
    blocks = [upload[i:i + 8] for i in range(0, 48, 8)] + [b""]

    def next_ack(c: Client, stale: int):
        """The next ACK above block *stale* (a repeat of an older ACK or of the OACK is skipped)."""
        while True:
            op, num, _rest, _addr = c.recv()
            if op == OACK or (op == ACK and num <= stale):
                continue
            return op, num

    with Client() as c:
        c.request(ctx.port, WRQ, "tw.bin", options=[("blksize", 8), ("windowsize", 4)])
        op, _num, rest, addr = c.recv()
        assert op == OACK and opts(rest) == {"blksize": "8", "windowsize": "4"}
        for n in (1, 2):                                         # blocks 3 and 4 of the first window "lost"
            c.data(addr, n, blocks[n - 1])
        assert next_ack(c, 1) == (ACK, 2)                        # the timer repeats the last in-order ACK
        for n in (3, 4, 5, 6):                                   # the device's next window starts after it
            c.data(addr, n, blocks[n - 1])
        assert next_ack(c, 2) == (ACK, 6)
        c.data(addr, 7, blocks[6])
        assert next_ack(c, 6) == (ACK, 7)
    assert (ctx.root / "tw.bin").read_bytes() == upload
    assert [t["file"] for t in history(ctx, "done")] == ["tw.bin"]


def test_a_stranger_gets_error_5_and_the_transfer_goes_on(make):
    ctx = make(timers=SLOW)
    (ctx.root / "f.bin").write_bytes(b"y" * 700)
    with Client() as c, Client() as stranger:
        c.request(ctx.port, RRQ, "f.bin")
        op, num, _p, addr = c.recv()
        assert (op, num) == (DATA, 1)
        stranger.ack(addr, 1)
        op, code, msg, src = stranger.recv()
        assert (op, code, src, text(msg)) == (ERROR, 5, addr, "Unknown transfer ID")
        stranger.ack(addr, 1)
        assert stranger.silent(0.2)                              # at most one ERROR 5 a second
        assert c.silent(0.1)                                     # the stranger moved nothing
        c.ack(addr, 1)
        op, num, payload, _a = c.recv()
        assert (op, num, len(payload)) == (DATA, 2, 188)
        c.ack(addr, 2)
    assert history(ctx, "done")[0]["bytes"] == 700


# =========================================================================================
# uploads and limits
# =========================================================================================
def test_uploads_are_create_only_and_every_refusal_has_its_error(make):
    ctx = make()
    (ctx.root / "exists.bin").write_bytes(b"old")
    (ctx.root / "fw").mkdir()
    with Client() as c:
        assert c.put(ctx.port, "new.bin", b"data").error == (2, "Uploads are switched off on this server")
        # switched off comes first: whatever else is wrong with the request, the device learns that uploads are off
        assert c.put(ctx.port, "../x.bin", b"data", mode="mail").error == (2, "Uploads are switched off on this server")
        ctx.srv.set_uploads(True)
        assert c.put(ctx.port, "exists.bin", b"data").error == (6, "File already exists")
        assert c.put(ctx.port, "missing/x.bin", b"data").error == (1, "Folder not found")
        assert c.put(ctx.port, "../x.bin", b"data").error == (2, "File name not allowed")
        assert c.put(ctx.port, "fw", b"data").error == (2, "Access denied")
        assert c.put(ctx.port, "x.bin", b"data", mode="mail").error == (4, "Unsupported transfer mode")
        # the size cap: from tsize before any data, and mid-stream without one
        ctx.srv.update_settings({"max_upload_mb": 1})
        assert c.put(ctx.port, "big.bin", b"", options=[("tsize", 2 * 1024 * 1024)]).error == (3, "File too large")
        res = c.put(ctx.port, "fw/big.bin", os.urandom(1024 * 1024 + 600), options=[("blksize", 1468)])
        assert res.error == (3, "File too large")
        ok = c.put(ctx.port, "fw/ok.bin", b"z" * 3000, options=[("tsize", 3000), ("blksize", 1024)])
        assert ok.error is None and ok.oack == {"tsize": "3000", "blksize": "1024"}
    assert (ctx.root / "exists.bin").read_bytes() == b"old"
    assert (ctx.root / "fw" / "ok.bin").read_bytes() == b"z" * 3000
    assert not (ctx.root / "fw" / "big.bin").exists() and not (ctx.root / "missing").exists()
    assert wait_for(lambda: not [p for p in ctx.root.rglob("*") if p.name.endswith(".part")])
    rows = history(ctx, count=10)
    assert [t["state"] for t in rows].count("failed") == 9 and rows[0]["state"] == "done"
    assert all(t["op"] == "write" for t in rows)


def test_a_name_that_appears_during_the_upload_is_not_overwritten(make):
    ctx = make(uploads=True, timers=SLOW)
    with Client() as c:
        c.request(ctx.port, WRQ, "race.bin")
        op, num, _p, addr = c.recv()
        assert (op, num) == (ACK, 0)
        c.data(addr, 1, b"a" * 512)
        assert c.recv()[:2] == (ACK, 1)
        (ctx.root / "race.bin").write_bytes(b"theirs")
        c.data(addr, 2, b"tail")
        op, code, msg, _a = c.recv()
        assert (op, code, text(msg)) == (ERROR, 6, "File already exists")
    assert (ctx.root / "race.bin").read_bytes() == b"theirs"
    assert wait_for(lambda: sorted(p.name for p in ctx.root.iterdir()) == ["race.bin"])


def test_a_resent_final_data_during_the_dally_is_acked_once_and_stop_ends_the_dally(make):
    ctx = make(uploads=True, timers=tftp.TftpTimers(0.05, 0.2, 3, 1.0, 0.5, 0.8))
    with Client() as c:
        res = c.put(ctx.port, "d.bin", b"q" * 700)
        assert res.error is None and res.final == 2
        assert history(ctx, "done") and ctx.srv.status()["transfers"] == []      # reported, no slot held
        c.data(res.addr, 2, b"CHANGED")
        op, num, _p, src = c.recv()
        assert (op, num, src) == (ACK, 2, res.addr)
        assert c.silent(0.15)
    assert (ctx.root / "d.bin").read_bytes() == b"q" * 700
    # a long dally does not hold stop()
    slow = make(uploads=True, timers=tftp.TftpTimers(0.05, 0.2, 3, 1.0, 5.0, 10.0))
    with Client() as c:
        assert c.put(slow.port, "d2.bin", b"w" * 10).error is None
        t0 = time.monotonic()
        slow.srv.stop()
        assert time.monotonic() - t0 < 1.0
    assert (ctx.root / "d2.bin").read_bytes() == b"w" * 10


def test_limits_4_per_client_and_32_in_total(make):
    ctx = make(timers=SLOW)
    (ctx.root / "f.bin").write_bytes(b"f" * 2000)
    clients: List[Client] = []

    def open_one(ip):
        c = Client(ip)
        clients.append(c)
        c.request(ctx.port, RRQ, "f.bin")
        return c.recv()

    try:
        for _ in range(4):
            assert open_one("127.0.0.1")[:2] == (DATA, 1)
        op, code, msg, src = open_one("127.0.0.1")
        assert (op, code, text(msg)) == (ERROR, 0, "Server busy, try again later") and src[1] != ctx.port
        for i in range(2, 9):
            for _ in range(4):
                assert open_one(f"127.0.0.{i}")[:2] == (DATA, 1)
        assert ctx.srv.summary()["active"] == 32
        assert open_one("127.0.0.9")[:2] == (ERROR, 0)
        st = ctx.srv.status()
        assert st["counts"]["busy"] == 2 and st["counts"]["active"] == 32 and len(st["transfers"]) == 32
        assert st["history"] == []                                  # turned-away requests do not fill the history
    finally:
        for c in clients:
            c.close()


# =========================================================================================
# containment, resets, clients, owners, firewall
# =========================================================================================
@pytest.mark.skipif(sys.platform != "win32", reason="junctions, hard links and final paths are Windows checks here")
def test_junction_and_hardlink_escapes_are_refused_on_the_handle(make, tmp_path, monkeypatch):
    import _winapi

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(b"secret")
    ctx = make(uploads=True)
    junction = ctx.root / "jx"
    _winapi.CreateJunction(str(outside), str(junction))           # a standard user can do this
    os.link(outside / "secret.bin", ctx.root / "hl.bin")          # and this: inside by path, two links
    (ctx.root / "plain.bin").write_bytes(b"plain")
    try:
        with Client() as c:
            assert c.get(ctx.port, "jx/secret.bin")[1].error == (2, "Access denied")
            assert c.get(ctx.port, "hl.bin")[1].error == (2, "Access denied")
            assert c.put(ctx.port, "jx/new.bin", b"x").error == (2, "Access denied")
            assert sorted(p.name for p in outside.iterdir()) == ["secret.bin"]
            # the handle is what counts: a final path outside the root refuses what the path checks let through
            real = tftp._final_path_of_fd
            monkeypatch.setattr(tftp, "_final_path_of_fd", lambda fd: str(outside / "secret.bin"))
            assert c.get(ctx.port, "plain.bin")[1].error == (2, "Access denied")
            assert c.put(ctx.port, "later.bin", b"x").error == (2, "Access denied")
            monkeypatch.setattr(tftp, "_final_path_of_fd", real)
            assert c.get(ctx.port, "plain.bin")[0] == b"plain"
        assert not (ctx.root / "later.bin").exists() and not list(ctx.root.glob(".*.part"))
        assert [f["name"] for f in ctx.srv.files()] == ["hl.bin", "plain.bin"]      # the junction is never walked
    finally:
        os.rmdir(junction)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are a Windows check here")
def test_a_root_that_is_itself_a_link_is_not_secured_served_listed_or_cleaned(make, tmp_path):
    import _winapi

    from tnt import winacl

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "f.bin").write_bytes(b"f")
    (outside / ".c.bin.abcdef01.part").write_bytes(b"not ours")
    root = tmp_path / "linkroot"
    _winapi.CreateJunction(str(outside), str(root))
    seam = winacl._set_file_security
    before = len(seam.calls)
    try:
        ctx = make(root=root, acl=winacl.secure_dir, uploads=True)      # the real refusal; its DACL seam only records
        st = ctx.srv.status()
        assert st["running"] is True and "could not be secured" in st["warning"] and seam.calls[before:] == []
        assert ctx.srv.files() == []
        with Client() as c:
            assert c.get(ctx.port, "f.bin")[1].error == (1, "File not found")
            assert c.put(ctx.port, "new.bin", b"x").error == (1, "Folder not found")
        assert sorted(p.name for p in outside.iterdir()) == [".c.bin.abcdef01.part", "f.bin"]
    finally:
        os.rmdir(root)


def test_connection_resets_do_not_kill_the_listener_or_a_transfer(make):
    resets: List[int] = []
    ctx = make(socket_factory=lambda family, kind: ResetOnce(family, kind, resets))
    (ctx.root / "r.bin").write_bytes(b"r" * 1000)
    for _ in range(2):                                             # a new client port per transfer, as RFC 1350 asks
        with Client() as c:
            assert c.get(ctx.port, "r.bin")[0] == b"r" * 1000
    assert len(resets) >= 3                                        # the listener once, each transfer socket once
    assert ctx.srv.status()["running"] is True and len(history(ctx, "done", 2)) == 2


@pytest.mark.skipif(sys.platform != "win32", reason="WinError 10054 on a UDP socket is Windows behaviour")
def test_a_device_that_goes_away_leaves_a_real_10054_counted_as_a_failed_retry(make, monkeypatch):
    seen: List[int] = []
    counted = tftp._Session.reset_seen

    def spy(session):
        seen.append(session.retries)
        return counted(session)

    monkeypatch.setattr(tftp._Session, "reset_seen", spy)
    ctx = make(timers=FAST)
    (ctx.root / "two.bin").write_bytes(b"2" * 600)
    gone = Client()
    gone.request(ctx.port, RRQ, "two.bin")
    assert gone.recv()[:2] == (DATA, 1)
    gone.close()                    # the next retransmit meets a closed port: ICMP unreachable, then WinError 10054
    row = history(ctx, "failed")
    assert row and row[0]["error"] == "Transfer timed out"          # given up on, never "could not complete"
    assert seen                                                     # a real ConnectionResetError reached the session
    with Client() as c:
        assert c.get(ctx.port, "two.bin")[0] == b"2" * 600


def test_clients_outside_the_adapter_subnets_get_no_answer(make):
    ctx = make(adapters=[nic(ips=(("127.0.0.1", 32),))])
    (ctx.root / "f.bin").write_bytes(b"f")
    with Client("127.0.0.2") as outsider, Client() as insider:
        outsider.request(ctx.port, RRQ, "f.bin")
        outsider.request(ctx.port, RRQ, "missing.bin")
        assert outsider.silent(0.3)
        assert insider.get(ctx.port, "f.bin")[0] == b"f"
        insider.sock.sendto(b"\x00\x04\x00\x01", ("127.0.0.1", ctx.port))      # not a request: no answer either
        assert insider.silent(0.2)
    assert len(ctx.srv.status()["history"]) == 1


def test_udp_owner_table_parser_and_the_real_table():
    rows = (("0.0.0.0", 69, 4321), ("192.0.2.10", 67, 88), ("127.0.0.1", 7130, 99))
    v4 = struct.pack("<I", 3) + b"".join(
        struct.pack("<III", struct.unpack("<I", socket.inet_aton(ip))[0], socket.htons(port), pid) for ip, port, pid in rows)
    assert tftp.parse_udp_table(v4, tftp.AF_INET) == list(rows)
    v6 = struct.pack("<I", 1) + struct.pack("<16sIII", socket.inet_pton(socket.AF_INET6, "2001:db8::5"), 0,
                                            socket.htons(69), 555)
    assert tftp.parse_udp_table(v6, tftp.AF_INET6) == [("2001:db8::5", 69, 555)]
    assert tftp.parse_udp_table(struct.pack("<I", 1000) + v4[4:16], tftp.AF_INET) == [rows[0]]   # count past the buffer
    assert tftp.parse_udp_table(b"\x01\x00", tftp.AF_INET) == []
    assert tftp.udp_port_owners(0) == []
    if sys.platform != "win32":
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    try:
        assert ("127.0.0.1", port, os.getpid()) in tftp.parse_udp_table(tftp._query_udp_table(tftp.AF_INET), tftp.AF_INET)
        assert tftp.udp_port_owners(port) == []                     # this process is never its own conflict
        assert tftp._process_name(os.getpid()).lower().startswith("python")
        assert tftp._process_name(0) == "PID 0"
    finally:
        s.close()


def test_port_in_use_names_the_owners_and_binds_nothing(make):
    asked: List[int] = []
    owners = [{"pid": 4321, "name": "tftpd64.exe"}, {"pid": 4, "name": "PID 4"}]

    def no_sockets(*args):
        raise AssertionError("no socket may be opened when the port has an owner")

    ctx = make(start=False, port=69, socket_factory=no_sockets, udp_owners_fn=lambda port: asked.append(port) or owners)
    with pytest.raises(tftp.TftpPortInUse) as exc:
        ctx.srv.start()
    assert str(exc.value) == "UDP port 69 is already used by tftpd64.exe, PID 4"
    assert exc.value.owners == owners and asked == [69] and isinstance(exc.value, RuntimeError)
    st = ctx.srv.status()
    assert st["conflict"] == {"port": 69, "owners": owners} and st["error"] == str(exc.value) and st["running"] is False
    assert ctx.events[-1]["type"] == "tftp.state"
    # a port taken without a nameable owner (an exclusive socket here) is the same typed error
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    holder.bind(("127.0.0.1", 0))
    try:
        taken = make(start=False, port=holder.getsockname()[1])
        with pytest.raises(tftp.TftpPortInUse, match="already used by another program") as exc:
            taken.srv.start()
        assert exc.value.owners == [] and taken.srv.status()["conflict"]["owners"] == []
        # the next start clears the conflict
        holder.close()
        assert taken.srv.start()["conflict"] is None
    finally:
        holder.close()


def test_firewall_rule_only_with_a_program_path_and_scoped_to_the_local_subnet(make):
    fw = FakeNetsh()
    dev = make(runner=fw)                                          # a console run: exe_path None
    assert fw.commands == []
    assert dev.srv.status()["firewall"] == {"rule": "TNT TFTP server (UDP 69 in)", "ok": None, "error": None}
    dev.srv.stop()
    svc = make(runner=fw, exe_path=EXE)
    assert fw.commands == [
        ["advfirewall", "firewall", "show", "rule", f"name={tftp.FIREWALL_RULE_NAME}", "verbose"],
        ["advfirewall", "firewall", "add", "rule", "name=TNT TFTP server (UDP 69 in)", "dir=in", "action=allow",
         f"program={EXE}", "protocol=udp", "localport=69", "remoteip=localsubnet", "profile=any"],
    ]
    assert svc.srv.status()["firewall"] == {"rule": tftp.FIREWALL_RULE_NAME, "ok": True, "error": None}
    svc.srv.stop()
    fw.commands.clear()
    assert svc.srv.start()["running"] is True and [c[2] for c in fw.commands] == ["show"]      # present and scoped
    svc.srv.stop()
    failing = make(start=False, exe_path=EXE,
                   runner=lambda argv, **kw: SimpleNamespace(returncode=1, stdout=b"", stderr=b"The requested operation requires elevation."))
    st = failing.srv.start()
    assert st["running"] is True and st["firewall"]["ok"] is False and "elevation" in st["warning"]


def test_ensure_rule_remote_ip_argv_and_the_replace_case():
    fw = FakeNetsh()
    exe = r"C:\a\b.exe"
    assert firewall.ensure_rule("X", exe, "udp", 69, runner=fw) == (True, None)
    assert fw.commands[-1] == ["advfirewall", "firewall", "add", "rule", "name=X", "dir=in", "action=allow",
                               f"program={exe}", "protocol=udp", "localport=69", "profile=any"]    # None: as before
    # the same rule without a remote scope is replaced once a scope is wanted
    fw.commands.clear()
    assert firewall.ensure_rule("X", exe, "udp", 69, runner=fw, remote_ip="localsubnet") == (True, None)
    assert [c[2] for c in fw.commands] == ["show", "delete", "add"]
    assert fw.commands[-1][-3:] == ["localport=69", "remoteip=localsubnet", "profile=any"]
    # present with LocalSubnet (any case): nothing to do; None ignores the scope as it always did
    fw.commands.clear()
    assert firewall.ensure_rule("X", r"c:\A\B.exe", "UDP", "69", runner=fw, remote_ip="LocalSubnet") == (True, None)
    assert firewall.ensure_rule("X", exe, "udp", 69, runner=fw) == (True, None)
    assert [c[2] for c in fw.commands] == ["show", "show"]
    # another scope is replaced; a value netsh cannot take never reaches it
    fw.commands.clear()
    assert firewall.ensure_rule("X", exe, "udp", 69, runner=fw, remote_ip="192.0.2.0/24") == (True, None)
    assert [c[2] for c in fw.commands] == ["show", "delete", "add"] and fw.rules["X"]["remoteip"] == "192.0.2.0/24"
    fw.commands.clear()
    assert firewall.ensure_rule("X", exe, "udp", 69, runner=fw, remote_ip="local subnet")[0] is False
    assert fw.commands == []


# =========================================================================================
# timers, stop, network changes
# =========================================================================================
def test_retransmits_back_off_then_fail_or_stay_unconfirmed(make):
    ctx = make(timers=FAST)
    (ctx.root / "two.bin").write_bytes(b"2" * 600)
    (ctx.root / "one.bin").write_bytes(b"1" * 100)                 # a single block, which is the final one
    with Client() as c:
        c.request(ctx.port, RRQ, "two.bin")
        t0 = time.monotonic()
        stamps = []
        for _ in range(4):                                         # DATA 1 and three retransmits
            op, num, _p, _a = c.recv()
            assert (op, num) == (DATA, 1)
            stamps.append(time.monotonic() - t0)
        op, code, msg, _a = c.recv()
        assert (op, code, text(msg)) == (ERROR, 0, "Transfer timed out")
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        assert gaps[2] > gaps[0] * 2                                # 0.05, 0.1, 0.2: doubling up to the cap
        c.request(ctx.port, RRQ, "one.bin")
        assert c.recv()[:2] == (DATA, 1)                            # the final block, never acknowledged
    rows = history(ctx, count=2)
    by_file = {t["file"]: t for t in rows}
    assert by_file["two.bin"]["state"] == "failed" and by_file["two.bin"]["error"] == "Transfer timed out"
    assert wait_for(lambda: {t["file"]: t["state"] for t in ctx.srv.status()["history"]}.get("one.bin") == "unconfirmed")


def test_stop_returns_within_two_seconds_with_transfers_running(make):
    ctx = make(timers=SLOW, uploads=True)
    (ctx.root / "s.bin").write_bytes(b"s" * 5000)
    clients = [Client() for _ in range(4)] + [Client("127.0.0.2") for _ in range(2)]     # 4 per client address
    try:
        for c in clients[:4]:
            c.request(ctx.port, RRQ, "s.bin")
            assert c.recv()[0] == DATA
        for i, c in enumerate(clients[4:]):
            c.request(ctx.port, WRQ, f"up{i}.bin")
            op, num, _p, addr = c.recv()
            assert (op, num) == (ACK, 0)
            c.data(addr, 1, b"u" * 512)
            assert c.recv()[:2] == (ACK, 1)
        assert ctx.srv.summary()["active"] == 6 and len(list(ctx.root.glob(".*.part"))) == 2
        t0 = time.monotonic()
        st = ctx.srv.stop()
        assert time.monotonic() - t0 < 2.0
        assert st["running"] is False and st["uploads"] is False and st["transfers"] == [] and st["listen"] == []
        assert [t["state"] for t in st["history"]] == ["cancelled"] * 6
        op, code, msg, _a = clients[0].recv()
        while op == DATA:                                          # a resend that left before the stop
            op, code, msg, _a = clients[0].recv()
        assert (op, code, text(msg)) == (ERROR, 0, "Server is shutting down")
        assert not [t.name for t in threading.enumerate() if t.name.startswith("tnt-tftp")]
        assert not list(ctx.root.glob(".*.part"))
        t1 = time.monotonic()
        assert ctx.srv.stop()["running"] is False and time.monotonic() - t1 < 0.5          # idle: at once
    finally:
        for c in clients:
            c.close()


def test_network_change_stops_the_server_on_a_helper_thread(make):
    adapters = [nic()]
    ctx = make(adapters=adapters)
    ctx.srv.on_network_change({"generation": 2})                  # nothing changed for this adapter
    assert ctx.srv.summary()["running"] is True
    seen: List[str] = []
    original = ctx.srv._stop_for_network

    def spy(problem):
        seen.append(threading.current_thread().name)
        original(problem)

    ctx.srv._stop_for_network = spy
    adapters[0] = nic(ips=(("127.0.0.2", 8),))                    # the same NIC without the listening address
    t0 = time.monotonic()
    ctx.srv.on_network_change({})
    assert time.monotonic() - t0 < 0.5
    assert wait_for(lambda: not ctx.srv.summary()["running"])
    assert seen == ["tnt-tftp-netstop"]
    assert ctx.srv.status()["error"] == "stopped: Ethernet lost its IPv4 address"
    # a NIC that disappears
    adapters[0] = nic()
    assert ctx.srv.start()["error"] is None
    # the laptop's Wi-Fi stays listed: an enumeration that answers with nothing at all is a failed read, not a removal
    adapters[:] = [nic(name="Wi-Fi", index=22, if_type=71, ips=(("198.51.100.7", 24),), mac="02:00:5e:10:00:02")]
    ctx.srv._stop_for_network = original
    ctx.srv.on_network_change({})
    assert wait_for(lambda: ctx.srv.summary()["error"] == "stopped: Ethernet is no longer present")
    ctx.srv.on_network_change({})                                  # stopped: nothing to do


# =========================================================================================
# the folder, files, status and logs
# =========================================================================================
def test_ensure_root_secures_warns_and_removes_stale_parts(make, tmp_path, data_dir):
    acl = Acl()
    ctx = make(start=False, acl=acl)
    ctx.srv.ensure_root()
    assert acl.calls == [(str(ctx.root), TFTP_SDDL)] and ctx.root.is_dir() and ctx.srv.status()["warning"] is None
    (ctx.root / "fw").mkdir()
    stale = [ctx.root / ".a.bin.0badf00d.part", ctx.root / "fw" / ".b.bin.12345678.part"]
    keep = [ctx.root / "a.bin", ctx.root / ".hidden.part", ctx.root / "x.0badf00d.part"]
    for p in stale + keep:
        p.write_bytes(b"x")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / ".c.bin.abcdef01.part").write_bytes(b"not ours")
    junction = ctx.root / "jx"
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(outside), str(junction))
    try:
        ctx.srv.ensure_root()
        assert not any(p.exists() for p in stale) and all(p.exists() for p in keep)
        assert (outside / ".c.bin.abcdef01.part").exists()           # a junction is never followed
    finally:
        if junction.exists():
            os.rmdir(junction)
    # a failure is only a warning, and the server still starts
    acl.fail = PermissionError("access denied")
    ctx.srv.ensure_root()
    assert ctx.srv.status()["warning"] == "The TFTP folder could not be secured (access denied)"
    st = ctx.srv.start()
    assert st["running"] is True and "could not be secured" in st["warning"] and len(acl.calls) == 4
    ctx.srv.stop()
    # the defaults: paths.tftp_dir() and tnt.winacl.secure_dir with TFTP_SDDL (its DACL seam only records in tests)
    from tnt import winacl

    seam = winacl._set_file_security
    before = len(seam.calls)
    default = tftp.TftpServer(None, ctx.cfg, EventBus(), adapters_fn=lambda: [])
    default.ensure_root()
    assert default.status()["root"] == str(paths.tftp_dir()) and paths.tftp_dir().is_dir()
    assert seam.calls[before:] == [(str(paths.tftp_dir()), winacl.TFTP_SDDL)]


def test_files_lists_relative_names_without_parts_links_or_deep_folders(make, tmp_path):
    ctx = make(start=False)
    ctx.srv.ensure_root()
    r = ctx.root
    (r / "b.bin").write_bytes(b"bb")
    (r / "A.txt").write_bytes(b"a")
    (r / "d1" / "d2" / "d3" / "d4").mkdir(parents=True)
    (r / "d1" / "d2" / "d3" / "deep.bin").write_bytes(b"1234")
    (r / "d1" / "d2" / "d3" / "d4" / "too-deep.bin").write_bytes(b"x")
    (r / ".up.bin.0badf00d.part").write_bytes(b"p")
    files = ctx.srv.files()
    assert [f["name"] for f in files] == ["A.txt", "b.bin", "d1/d2/d3/deep.bin"]
    assert files[1]["size"] == 2 and isinstance(files[1]["mtime"], float) and set(files[1]) == {"name", "size", "mtime"}
    (r / "many").mkdir()
    for i in range(510):
        (r / "many" / f"{i:03}.bin").write_bytes(b"")
    assert len(ctx.srv.files()) == 500
    missing = tftp.TftpServer(None, ctx.cfg, EventBus(), root=tmp_path / "nowhere", adapters_fn=lambda: [])
    assert missing.files() == []


def test_status_summary_settings_uploads_and_db_rows(make):
    db = FakeDb()
    ctx = make(start=False, db=db)
    st = ctx.srv.status()
    assert tuple(st) == tftp.TFTP_STATUS_KEYS
    assert (st["running"], st["listen"], st["uploads"], st["conflict"], st["error"]) == (False, [], False, None, None)
    assert tuple(st["adapter"]) == tftp.TFTP_ADAPTER_KEYS and st["adapter"]["name"] == "Ethernet"
    assert st["adapter"]["ip"] == "127.0.0.1" and st["adapter"]["prefix"] == 8
    assert [a["name"] for a in st["adapters"]] == ["Ethernet"] and tuple(st["counts"]) == tftp.TFTP_COUNT_KEYS
    assert st["settings"] == {"adapter": "", "max_upload_mb": 4096} and st["root"] == str(ctx.root)
    assert tuple(ctx.srv.summary()) == tftp.TFTP_SUMMARY_KEYS and ctx.srv.summary()["adapter"] is None
    # settings: validated and saved; unknown keys refused
    with pytest.raises(ValueError, match="unknown TFTP setting 'root'"):
        ctx.srv.update_settings({"root": "C:\\"})
    with pytest.raises(ValueError, match="is not up or has no IPv4 address"):
        ctx.srv.update_settings({"adapter": "Wi-Fi"})
    for bad in (0, 65537, True, "10", 1.5, float("nan"), float("inf"), None):
        with pytest.raises(ValueError, match="max_upload_mb"):
            ctx.srv.update_settings({"max_upload_mb": bad})
    st = ctx.srv.update_settings({"adapter": "Ethernet", "max_upload_mb": 100.0})
    assert st["settings"] == {"adapter": "Ethernet", "max_upload_mb": 100}
    assert ctx.cfg.section("tftp") == {"adapter": "Ethernet", "max_upload_mb": 100}
    # start arguments are strict
    with pytest.raises(ValueError):
        ctx.srv.start(uploads="yes")
    with pytest.raises(ValueError, match="'Wi-Fi' is not up"):
        ctx.srv.start(adapter="Wi-Fi")
    st = ctx.srv.start(uploads=True)
    assert st["running"] is True and st["uploads"] is True and st["listen"][0]["ip"] == "127.0.0.1"
    assert ctx.srv.summary() == {"available": True, "running": True, "adapter": "Ethernet", "listen_ips": ["127.0.0.1"],
                                 "active": 0, "uploads": True, "since_ts": st["since_ts"], "error": None}
    assert ctx.srv.start()["listen"] == st["listen"]                              # already running: unchanged
    assert ctx.srv.set_uploads(False)["uploads"] is False
    with pytest.raises(ValueError):
        ctx.srv.set_uploads("on")
    ctx.srv.set_uploads(True)
    st = ctx.srv.stop()
    assert st["uploads"] is False and st["running"] is False and st["since_ts"] is None   # uploads never outlive a stop
    states = [e for e in ctx.events if e["type"] == "tftp.state"]
    assert len(states) >= 5 and tuple(states[-1]["data"]) == tftp.TFTP_SUMMARY_KEYS
    assert [m for _level, cat, m in db.events if cat == "tftp"] == [
        "TFTP server started on Ethernet, uploads on", "TFTP uploads switched off", "TFTP uploads switched on",
        "TFTP server stopped"]


def test_info_logs_carry_no_client_address_or_file_name(make, caplog):
    db = FakeDb()
    with caplog.at_level(logging.DEBUG, logger="tnt.tftp"):
        ctx = make(uploads=True, db=db)
        (ctx.root / "secret-name.bin").write_bytes(b"s" * 600)
        with Client() as c:
            assert c.get(ctx.port, "secret-name.bin")[0] == b"s" * 600
            assert c.put(ctx.port, "upload-name.bin", b"u" * 10).error is None
            assert c.get(ctx.port, "missing-name.bin")[1].error == (1, "File not found")
        history(ctx, count=3)
        ctx.srv.stop()
    infos = [r.getMessage() for r in caplog.records if r.levelno >= logging.INFO and r.name == "tnt.tftp"]
    assert any(m.startswith("TFTP server started on 'Ethernet'") for m in infos)
    assert "TFTP read done: 600 bytes in" in " | ".join(infos) and "TFTP write done: 10 bytes in" in " | ".join(infos)
    for message in infos:
        assert "127.0.0.1" not in message and "-name" not in message, message
    for _level, _cat, message in db.events:
        assert "127.0.0.1" not in message and "-name" not in message, message
    assert any("missing-name.bin" in r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG)


# =========================================================================================
# curl interop
# =========================================================================================
CURL = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows", "System32", "curl.exe")


def _curl_has_tftp() -> bool:
    if not os.path.isfile(CURL):
        return False
    try:
        out = subprocess.run([CURL, "-V"], capture_output=True, timeout=10, stdin=subprocess.DEVNULL).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    line = next((ln for ln in out.decode("utf-8", "replace").splitlines() if ln.lower().startswith("protocols:")), "")
    return "tftp" in line.lower().split()


@pytest.mark.skipif(not _curl_has_tftp(), reason="curl.exe with the tftp protocol is not installed")
def test_curl_interop(make, tmp_path):
    ctx = make(uploads=True)
    body = os.urandom(40_000)
    (ctx.root / "fw.bin").write_bytes(body)
    (ctx.root / "cfg.txt").write_bytes(b"line1\nline2\r\n")
    base = f"tftp://127.0.0.1:{ctx.port}"

    def curl(*args):
        return subprocess.run([CURL, "-s", "-S", "--max-time", "20", *args], capture_output=True, timeout=30,
                              stdin=subprocess.DEVNULL)

    for extra, out in (([], "a.bin"), (["--tftp-blksize", "1468"], "b.bin"), (["--tftp-no-options"], "c.bin")):
        r = curl(*extra, "-o", str(tmp_path / out), f"{base}/fw.bin")
        assert r.returncode == 0, r.stderr
        assert (tmp_path / out).read_bytes() == body
    src = tmp_path / "upload.bin"
    src.write_bytes(os.urandom(3000))
    r = curl("-T", str(src), f"{base}/uploaded.bin")
    assert r.returncode == 0, r.stderr
    assert (ctx.root / "uploaded.bin").read_bytes() == src.read_bytes()
    r = curl("-o", str(tmp_path / "cfg.txt"), f"{base}/cfg.txt;mode=netascii")
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "cfg.txt").read_bytes() == b"line1\r\nline2\r\n"                # curl keeps the wire line ends
    r = curl("-o", str(tmp_path / "none.bin"), f"{base}/missing.bin")
    assert r.returncode != 0
    rows = history(ctx, "done", 5)
    assert {t["file"] for t in rows} == {"fw.bin", "uploaded.bin", "cfg.txt"}
