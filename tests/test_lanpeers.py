"""LAN peers (tnt/lanpeers.py) and the shared firewall helper (tnt/firewall.py).

Beacon codec and peer table with fakes; the throughput protocol end to end over real
loopback sockets (two instances on 127.0.0.1 with ephemeral ports).  No test ever sends a
beacon onto the real LAN: every started instance gets ``adapters_fn=lambda: []`` (nothing to
broadcast from) and a fake netsh runner.
"""
import ipaddress
import json
import socket
import threading
import time
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

import tnt
from tnt import firewall, lanpeers
from tnt.config import Config
from tnt.db import Database
from tnt.events import EventBus
from tnt.icmp import PingResult
from tnt.lanpeers import BEACON_FIREWALL_RULE, THROUGHPUT_FIREWALL_RULE, LanPeers
from tnt.netinfo import Adapter, IpAddr

EXE = r"C:\Program Files\TNT\TNTService.exe"


# --- fakes ----------------------------------------------------------------------------------
def ipaddr(ip: str, prefix: int) -> IpAddr:
    net = ipaddress.IPv4Interface(f"{ip}/{prefix}").network
    return IpAddr(address=ip, prefix=prefix, family=4, netmask=str(net.netmask), network=str(net))


def adapter(name: str, ip: str = None, prefix: int = 24, index: int = 1, status: str = "up", gateway: str = None,
            loopback: bool = False) -> Adapter:
    return Adapter(index=index, name=name, description=name, mac=f"00:11:22:33:44:{index:02X}", if_type=6,
                   type_name="ethernet", status=status, speed_bps=None, mtu=1500, dhcp_enabled=True, dhcp_server=None,
                   dns_suffix="", ipv4=[ipaddr(ip, prefix)] if ip else [], gateways=[gateway] if gateway else [],
                   is_physical=True, is_loopback=loopback)


class FakeFirewall:
    """``netsh advfirewall firewall`` stand-in keyed by rule name (show / add / delete)."""

    def __init__(self) -> None:
        self.rules: Dict[str, Dict[str, str]] = {}
        self.commands: List[List[str]] = []
        self.kwargs: List[dict] = []
        self.fail_add = False

    def __call__(self, argv, **kwargs):
        self.commands.append(list(argv))
        self.kwargs.append(kwargs)
        args = argv[1:]
        assert args[:2] == ["advfirewall", "firewall"], args
        name = next(x.split("=", 1)[1] for x in args if x.startswith("name="))
        if args[2] == "show":
            r = self.rules.get(name)
            if r is None:
                return SimpleNamespace(returncode=1, stdout=b"\r\nNo rules match the specified criteria.\r\n", stderr=b"")
            out = (f"\r\nRule Name: {name}\r\n" + "-" * 60 + "\r\nEnabled: Yes\r\nDirection: In\r\n"
                   "Profiles: Domain,Private,Public\r\nGrouping:\r\nLocalIP: Any\r\nRemoteIP: Any\r\n"
                   f"Protocol: {r['protocol'].upper()}\r\nLocalPort: {r['ports']}\r\nRemotePort: Any\r\n"
                   f"Edge traversal: No\r\nProgram: {r['program']}\r\nAction: Allow\r\nOk.\r\n").encode()
            return SimpleNamespace(returncode=0, stdout=out, stderr=b"")
        if args[2] == "add":
            if self.fail_add:
                return SimpleNamespace(returncode=1, stdout=b"",
                                       stderr=b"The requested operation requires elevation (Run as administrator).")

            def get(key: str) -> str:
                return next(x.split("=", 1)[1] for x in args if x.startswith(key + "="))

            self.rules[name] = {"program": get("program"), "protocol": get("protocol"), "ports": get("localport")}
            return SimpleNamespace(returncode=0, stdout=b"Ok.\r\n", stderr=b"")
        if args[2] == "delete":
            existed = self.rules.pop(name, None) is not None
            return SimpleNamespace(returncode=0 if existed else 1,
                                   stdout=b"Deleted 1 rule(s).\r\nOk.\r\n" if existed else b"No rules match the specified criteria.\r\n",
                                   stderr=b"")
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"unknown command")


class FakeSocket:
    def __init__(self, family, type_, *a, **k):
        self.family, self.type = family, type_
        self.opts: List[tuple] = []
        self.bound = None
        self.sent: List[tuple] = []
        self.closed = False
        self.timeout = None
        self.fail_bind = False

    def setsockopt(self, level, opt, val):
        self.opts.append((level, opt, val))

    def settimeout(self, t):
        self.timeout = t

    def bind(self, addr):
        if self.fail_bind:
            raise OSError(10049, "address not available")
        self.bound = addr

    def sendto(self, data, addr):
        self.sent.append((data, addr))
        return len(data)

    def close(self):
        self.closed = True


class FakeSocketFactory:
    def __init__(self, fail_bind_for=()):
        self.sockets: List[FakeSocket] = []
        self.fail_bind_for = set(fail_bind_for)

    def __call__(self, *a, **k):
        s = FakeSocket(*a, **k)
        self.sockets.append(s)
        return s


class FakePinger:
    def __init__(self, rtt: float = 1.5) -> None:
        self.rtt = rtt
        self.calls: List[str] = []

    def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
        self.calls.append(ip)
        return PingResult(ok=True, rtt_ms=self.rtt, status=0, error=None, ttl=64, size=size, ip=ip)


def wait_for(pred, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def lan_threads() -> List[str]:
    return sorted(t.name for t in threading.enumerate() if t.name.startswith("tnt-lan-") and t.is_alive())


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make(tmp_path, *, db=None, adapters=None, runner=None, pinger=None, socket_factory=None, clock=None,
         ports=(0, 0), enabled=True, exe=EXE):
    """A LanPeers on 127.0.0.1 with ephemeral ports, a fake netsh and (by default) no adapters
    to broadcast from, so nothing a test starts ever touches the real LAN."""
    cfg = Config(tmp_path / "config.json").load()
    if not enabled:
        cfg.update({"lan": {"enabled": False}}, persist=False)
    bus = EventBus()
    events: List[Dict[str, Any]] = []
    bus.subscribe(lambda e: events.append(e))
    adapters = [] if adapters is None else adapters
    lp = LanPeers(cfg, bus, db=db, pinger=pinger, clock=clock or time.time, socket_factory=socket_factory,
                  adapters_fn=lambda: adapters, beacon_port=ports[0], throughput_port=ports[1], exe_path=exe,
                  runner=runner or FakeFirewall(), bind_host="127.0.0.1")
    return lp, events, cfg


# =========================================================================================
# beacon codec
# =========================================================================================
def test_beacon_codec_and_rejections():
    raw = lanpeers.encode_beacon("ab12", "TECH-LAPTOP", "1.2.0", 7133, 1_700_000_000.1234)
    assert len(raw) <= lanpeers.BEACON_MAX_BYTES and json.loads(raw)["tnt"] == 1
    assert lanpeers.decode_beacon(raw) == {"id": "ab12", "hostname": "TECH-LAPTOP", "version": "1.2.0", "port": 7133,
                                           "ts": 1_700_000_000.123}
    # hostile text is cleaned (printable only) and capped; a missing ts is tolerated
    nasty = json.dumps({"tnt": 1, "id": "x", "hostname": "ev\x07il\n" + "a" * 100, "version": 7, "port": 1, "ts": "now"}).encode()
    b = lanpeers.decode_beacon(nasty)
    assert b["hostname"] == ("evil" + "a" * 100)[:63] and b["version"] == "" and b["ts"] is None and b["port"] == 1
    # a hostname that would not fit is dropped rather than producing an oversized datagram
    assert len(lanpeers.encode_beacon("a" * 64, "h" * 500, "v" * 100, 65535, 0)) <= lanpeers.BEACON_MAX_BYTES
    bad = [
        b"", b"x", b"garbage", b"{}", b"[]", b"1", b"null", b"\xff\xfe",
        b'{"tnt":1,"id":"x","hostname":"' + b"a" * 600 + b'","version":"1","port":1,"ts":0}',   # oversized
        json.dumps({"tnt": 2, "id": "x", "port": 1}).encode(),                                   # not ours
        json.dumps({"tnt": True, "id": "x", "port": 1}).encode(),
        json.dumps({"tnt": 1, "port": 1}).encode(),                                               # no id
        json.dumps({"tnt": 1, "id": "has space", "port": 1}).encode(),
        json.dumps({"tnt": 1, "id": "a" * 65, "port": 1}).encode(),
        json.dumps({"tnt": 1, "id": 12, "port": 1}).encode(),
        json.dumps({"tnt": 1, "id": "x", "port": 0}).encode(),
        json.dumps({"tnt": 1, "id": "x", "port": 70000}).encode(),
        json.dumps({"tnt": 1, "id": "x", "port": "7133"}).encode(),
        json.dumps({"tnt": 1, "id": "x", "port": True}).encode(),
        json.dumps({"tnt": 1, "id": "x"}).encode(),
        "not bytes",
    ]
    for raw in bad:
        assert lanpeers.decode_beacon(raw) is None, raw
    # framing helpers
    hdr = lanpeers.build_header(lanpeers.MODE_UPLOAD, 5)
    assert len(hdr) == 16 and hdr == b"TNTT\x01U\x05" + b"\x00" * 9
    assert lanpeers.parse_header(hdr) == (b"U", 5) and lanpeers.parse_header(lanpeers.build_header(b"D", 20)) == (b"D", 20)
    for raw in (b"", hdr[:15], hdr + b"x", b"TNTT\x02U\x05" + b"\x00" * 9, b"TNTT\x01X\x05" + b"\x00" * 9,
                b"TNTT\x01U\x00" + b"\x00" * 9, b"TNTT\x01U\x15" + b"\x00" * 9, b"HTTP/1.1 200 OK\r"):
        assert lanpeers.parse_header(raw) is None, raw
    with pytest.raises(ValueError):
        lanpeers.build_header(b"U", 0)
    with pytest.raises(ValueError):
        lanpeers.build_header(b"Z", 1)
    tr = lanpeers.build_trailer(123456789012, 5001)
    assert len(tr) == 16 and tr[:4] == b"TNTR" and lanpeers.parse_trailer(tr) == (123456789012, 5001)
    assert lanpeers.parse_trailer(b"TNTX" + tr[4:]) is None and lanpeers.parse_trailer(tr[:15]) is None


# =========================================================================================
# peer table
# =========================================================================================
def test_peer_table_events_expiry_and_view(tmp_path):
    clock = {"now": 1_700_000_000.0}
    adapters = [adapter("Ethernet", "10.0.0.5", 24, index=12, gateway="10.0.0.1"), adapter("Wi-Fi", "192.168.1.20", 24, index=7)]
    lp, events, _cfg = make(tmp_path, adapters=adapters, clock=lambda: clock["now"], ports=(7132, 7133))
    # our own beacon is ignored
    assert lp.handle_datagram(lp.beacon_bytes(), ("10.0.0.5", 7132)) is None and lp.peers() == []
    other = lanpeers.encode_beacon("peer-a", "OFFICE-PC", "1.2.0", 7133, clock["now"])
    rec = lp.handle_datagram(other, ("10.0.0.7", 51000))
    assert rec["ip"] == "10.0.0.7" and rec["adapter"] == "Ethernet" and rec["hostname"] == "OFFICE-PC"
    assert rec["port"] == 7133 and rec["version"] == "1.2.0" and rec["last_seen_ts"] == clock["now"]
    assert [e["type"] for e in events] == ["lan.peers"] and events[-1]["data"]["peers"][0]["id"] == "peer-a"
    # the same beacon again: refreshed, no event
    clock["now"] += 5
    lp.handle_datagram(other, ("10.0.0.7", 51000))
    assert len(events) == 1 and lp.peers()[0]["last_seen_ts"] == clock["now"] and lp.peers()[0]["age_s"] == 0.0
    # an address change: event, adapter recomputed
    lp.handle_datagram(other, ("192.168.1.30", 51000))
    assert len(events) == 2 and lp.peers()[0]["ip"] == "192.168.1.30" and lp.peers()[0]["adapter"] == "Wi-Fi"
    # a second peer outside every subnet (adapter unknown, empty hostname -> None)
    lp.handle_datagram(lanpeers.encode_beacon("peer-b", "", "1.1.0", 7133, 0), ("172.16.9.9", 1))
    assert len(events) == 3 and {p["id"]: p["adapter"] for p in lp.peers()} == {"peer-a": "Wi-Fi", "peer-b": None}
    assert lp.peer_for_ip("172.16.9.9")["hostname"] is None and lp.peer_for_ip("1.2.3.4") is None
    # malformed datagrams and a bad source never count
    assert lp.handle_datagram(b"nope", ("10.0.0.7", 1)) is None and lp.handle_datagram(other, ("not-an-ip", 1)) is None
    assert lp.handle_datagram(other, None) is None and len(events) == 3
    # the view
    clock["now"] += 3
    v = lp.peers_view()
    assert set(v) >= {"self", "peers", "listening", "error"}
    assert v["self"] == {"id": lp.peer_id, "hostname": lp.hostname, "ip": "10.0.0.5", "version": tnt.__version__, "port": 7133}
    assert v["listening"] is False and v["error"] is None and v["running"] is False and v["throughput_running"] is False
    assert [p["id"] for p in v["peers"]] == ["peer-b", "peer-a"]      # sorted by hostname ("" first), then ip
    assert all(p["age_s"] == 3.0 for p in v["peers"]) and set(v["peers"][0]) == {
        "id", "hostname", "ip", "version", "port", "last_seen_ts", "adapter", "age_s"}
    # expiry: 20 s after the last beacon
    clock["now"] += 16.9
    assert lp.expire_peers() == [] and len(events) == 3
    clock["now"] += 0.2
    assert sorted(lp.expire_peers()) == ["peer-a", "peer-b"] and len(events) == 4 and events[-1]["data"]["peers"] == []
    # a clock stepped backwards drops a "future" peer instead of keeping it forever
    lp.handle_datagram(other, ("10.0.0.7", 1))
    clock["now"] -= 60
    assert lp.expire_peers() == ["peer-a"]


def test_peer_id_persisted_in_db(tmp_path):
    db = Database(tmp_path / "tnt.db")
    try:
        a = make(tmp_path, db=db)[0]
        b = make(tmp_path, db=db)[0]
        assert a.peer_id == b.peer_id == db.get_meta("lan.peer_id") and len(a.peer_id) == 32
        db.set_meta("lan.peer_id", "not a valid id!")
        c = make(tmp_path, db=db)[0]
        assert c.peer_id != a.peer_id and db.get_meta("lan.peer_id") == c.peer_id
    finally:
        db.close()
    c, d = make(tmp_path)[0], make(tmp_path)[0]
    assert c.peer_id != d.peer_id and len(c.peer_id) == 32
    # a broken db never breaks construction
    e = make(tmp_path, db=SimpleNamespace(get_meta=lambda k: 1 / 0, set_meta=lambda k, v: 1 / 0))[0]
    assert len(e.peer_id) == 32


# =========================================================================================
# beacon sending
# =========================================================================================
def test_send_beacon_from_every_usable_adapter(tmp_path):
    adapters = [
        adapter("Ethernet", "10.0.0.5", 24, index=1), adapter("Wi-Fi", "192.168.1.20", 24, index=2),
        adapter("Tailscale", "100.64.0.9", 32, index=3),                    # /32 tunnel: no broadcast domain
        adapter("Ethernet 2", "10.9.9.9", 24, index=4, status="down"),      # down
        adapter("Loopback", "127.0.0.1", 8, index=5, loopback=True),       # loopback
        adapter("Unplugged", None, index=6),                                # no IPv4
    ]
    assert lanpeers.beacon_sources(adapters) == [("10.0.0.5", ["255.255.255.255", "10.0.0.255"]),
                                                 ("192.168.1.20", ["255.255.255.255", "192.168.1.255"])]
    factory = FakeSocketFactory()
    lp, _events, _cfg = make(tmp_path, adapters=adapters, socket_factory=factory, ports=(7132, 7133))
    assert lp.send_beacon() == 4
    assert [s.bound for s in factory.sockets] == [("10.0.0.5", 0), ("192.168.1.20", 0)]
    assert all((socket.SOL_SOCKET, socket.SO_BROADCAST, 1) in s.opts and s.closed for s in factory.sockets)
    assert [a for _d, a in factory.sockets[0].sent] == [("255.255.255.255", 7132), ("10.0.0.255", 7132)]
    assert [a for _d, a in factory.sockets[1].sent] == [("255.255.255.255", 7132), ("192.168.1.255", 7132)]
    b = lanpeers.decode_beacon(factory.sockets[0].sent[0][0])
    assert b["id"] == lp.peer_id and b["port"] == 7133 and b["hostname"] == lp.hostname and b["version"] == tnt.__version__
    # nothing usable from the seam -> nothing sent (no blind default-route send)
    factory2 = FakeSocketFactory()
    lp2 = make(tmp_path, adapters=[], socket_factory=factory2)[0]
    assert lp2.send_beacon() == 0 and factory2.sockets == []
    # a bind failure on one adapter never stops the others
    sockets3: List[FakeSocket] = []

    def flaky(*a, **k):
        s = FakeSocket(*a, **k)
        s.fail_bind = not sockets3            # the first socket (Ethernet) cannot bind
        sockets3.append(s)
        return s

    lp3 = make(tmp_path, adapters=adapters, socket_factory=flaky, ports=(7132, 7133))[0]
    assert lp3.send_beacon() == 2 and sockets3[0].closed and sockets3[1].bound == ("192.168.1.20", 0)


# =========================================================================================
# firewall
# =========================================================================================
def test_firewall_rules_are_not_managed_without_a_program_path(tmp_path):
    """Dev/console runs pass exe_path=None: no netsh at all, reported as 'not managed'."""
    fw = FakeFirewall()
    cfg = Config(tmp_path / "config.json").load()
    lp = LanPeers(cfg, EventBus(), runner=fw, socket_factory=FakeSocketFactory(), exe_path=None)
    assert lp.ensure_firewall() == (True, None)
    assert fw.commands == []
    assert lp.peers_view()["firewall"] == {"ok": None, "error": None}


def test_firewall_rules_exact_names_and_ports(tmp_path):
    fw = FakeFirewall()
    lp, _events, _cfg = make(tmp_path, runner=fw, ports=(7132, 7133), socket_factory=FakeSocketFactory())
    assert lp.ensure_firewall() == (True, None)
    assert fw.rules == {
        "TNT LAN discovery (UDP 7132 in)": {"program": EXE, "protocol": "udp", "ports": "7132"},
        "TNT LAN throughput (TCP 7133 in)": {"program": EXE, "protocol": "tcp", "ports": "7133"},
    }
    assert BEACON_FIREWALL_RULE == "TNT LAN discovery (UDP 7132 in)" and THROUGHPUT_FIREWALL_RULE == "TNT LAN throughput (TCP 7133 in)"
    adds = [c[1:] for c in fw.commands if c[3] == "add"]
    assert adds == [
        ["advfirewall", "firewall", "add", "rule", f"name={BEACON_FIREWALL_RULE}", "dir=in", "action=allow",
         f"program={EXE}", "protocol=udp", "localport=7132", "profile=any"],
        ["advfirewall", "firewall", "add", "rule", f"name={THROUGHPUT_FIREWALL_RULE}", "dir=in", "action=allow",
         f"program={EXE}", "protocol=tcp", "localport=7133", "profile=any"],
    ]
    assert [c[3] for c in fw.commands] == ["show", "add", "show", "add"]
    assert fw.commands[0][0].lower().endswith("netsh.exe") or fw.commands[0][0] == "netsh"
    kw = fw.kwargs[0]
    assert kw["stdin"] is not None and kw["check"] is False and kw["capture_output"] is True and kw["timeout"] > 0
    assert lp.peers_view()["firewall"] == {"ok": True, "error": None} and lp.peers_view()["error"] is None
    # idempotent: show only
    fw.commands.clear()
    assert lp.ensure_firewall() == (True, None) and [c[3] for c in fw.commands] == ["show", "show"]
    # a rule left by a dev run (python.exe) is replaced for the service exe
    fw.rules[THROUGHPUT_FIREWALL_RULE]["program"] = r"C:\Python312\python.exe"
    fw.commands.clear()
    assert lp.ensure_firewall() == (True, None)
    assert [c[3] for c in fw.commands] == ["show", "show", "delete", "add"] and fw.rules[THROUGHPUT_FIREWALL_RULE]["program"] == EXE
    # a failure is a warning, never fatal
    fw.fail_add = True
    fw.rules.clear()
    ok, err = lp.ensure_firewall()
    assert ok is False and "elevation" in err and BEACON_FIREWALL_RULE in err and THROUGHPUT_FIREWALL_RULE in err
    v = lp.peers_view()
    assert v["firewall"]["ok"] is False and "firewall" in v["error"] and "elevation" in v["error"]
    # a broken runner seam
    boom = make(tmp_path, runner=lambda argv, **kw: (_ for _ in ()).throw(RuntimeError("kaboom")), ports=(7132, 7133))[0]
    ok, err = boom.ensure_firewall()
    assert ok is False and "kaboom" in err


def test_firewall_module_generic_rules():
    fw = FakeFirewall()
    assert firewall.ensure_rule("X rule", r"C:\a\b.exe", "tcp", [80, 443], runner=fw) == (True, None)
    assert fw.rules["X rule"] == {"program": r"C:\a\b.exe", "protocol": "tcp", "ports": "80,443"}
    # same program, ports as text, same protocol -> nothing to do (case-insensitive path)
    fw.commands.clear()
    assert firewall.ensure_rule("X rule", r"c:\A\B.EXE", "TCP", "80,443", runner=fw) == (True, None)
    assert [c[3] for c in fw.commands] == ["show"]
    # another protocol -> replaced
    fw.commands.clear()
    assert firewall.ensure_rule("X rule", r"C:\a\b.exe", "udp", "80,443", runner=fw) == (True, None)
    assert [c[3] for c in fw.commands] == ["show", "delete", "add"] and fw.rules["X rule"]["protocol"] == "udp"
    # a superset of the wanted ports is fine; a missing port is not
    fw.rules["X rule"]["ports"] = "80,443,8080"
    fw.commands.clear()
    assert firewall.ensure_rule("X rule", r"C:\a\b.exe", "udp", 80, runner=fw) == (True, None)
    assert [c[3] for c in fw.commands] == ["show"]
    fw.commands.clear()
    assert firewall.ensure_rule("X rule", r"C:\a\b.exe", "udp", [80, 9999], runner=fw) == (True, None)
    assert [c[3] for c in fw.commands] == ["show", "delete", "add"] and fw.rules["X rule"]["ports"] == "80,9999"
    # bad input never reaches netsh
    fw.commands.clear()
    assert firewall.ensure_rule("", "x", "tcp", 1, runner=fw)[0] is False
    assert firewall.ensure_rule("r", "x", "icmp", 1, runner=fw)[0] is False
    assert firewall.ensure_rule("r", "x", "tcp", [], runner=fw)[0] is False
    assert firewall.ensure_rule("r", "x", "tcp", 70000, runner=fw)[0] is False
    assert firewall.ensure_rule("r", "x", "tcp", "a,b", runner=fw)[0] is False
    assert fw.commands == []
    assert firewall.normalize_ports("67, 68,67") == ([67, 68], "67,68") and firewall.normalize_ports(7133) == ([7133], "7133")
    with pytest.raises(ValueError):
        firewall.normalize_ports("a")
    with pytest.raises(ValueError):
        firewall.normalize_ports([0])
    # delete: missing rule reports the netsh failure
    assert firewall.delete_rule("X rule", runner=fw) == (True, None) and "X rule" not in fw.rules
    assert firewall.delete_rule("X rule", runner=fw)[0] is False and firewall.delete_rule("", runner=fw)[0] is False
    # run_netsh never raises
    rc, out = firewall.run_netsh(["x"], runner=lambda argv, **kw: (_ for _ in ()).throw(RuntimeError("x")))
    assert rc != 0 and "x" in out
    rc, out = firewall.run_netsh(["x"], runner=lambda argv, **kw: (_ for _ in ()).throw(FileNotFoundError()))
    assert rc == 9009
    rc, out = firewall.run_netsh(["x"], runner=lambda argv, **kw: SimpleNamespace(returncode=0, stdout=b"Ok.\r\n", stderr=b""))
    assert (rc, out) == (0, "Ok.")


# =========================================================================================
# lifecycle
# =========================================================================================
def test_disabled_config_does_nothing(tmp_path):
    lp, events, _cfg = make(tmp_path, enabled=False, socket_factory=FakeSocketFactory())
    lp.start()
    v = lp.peers_view()
    assert v["listening"] is False and v["error"] == "disabled" and v["running"] is False and lp.running is False
    assert lan_threads() == [] and events == []
    lp.stop()
    assert lp.peers_view()["error"] == "disabled"


def test_start_stop_idempotent_no_lingering_threads(tmp_path):
    fw = FakeFirewall()
    lp, _events, _cfg = make(tmp_path, runner=fw)
    lp.start()
    try:
        assert lp.running and lp.listening
        bport, tport = lp.beacon_port, lp.throughput_port
        assert bport > 0 and tport > 0
        lp.start()                                      # idempotent: same sockets
        assert (lp.beacon_port, lp.throughput_port) == (bport, tport)
        assert lp.wait_firewall(5.0) and set(fw.rules) == {BEACON_FIREWALL_RULE, THROUGHPUT_FIREWALL_RULE}
        assert fw.rules[BEACON_FIREWALL_RULE] == {"program": EXE, "protocol": "udp", "ports": str(bport)}
        assert fw.rules[THROUGHPUT_FIREWALL_RULE] == {"program": EXE, "protocol": "tcp", "ports": str(tport)}
        assert lan_threads() == ["tnt-lan-beacon", "tnt-lan-listen", "tnt-lan-server"]
        v = lp.peers_view()
        assert v["listening"] is True and v["running"] is True and v["error"] is None and v["self"]["port"] == tport
        assert v["beacon_port"] == bport and v["throughput_port"] == tport
    finally:
        lp.stop()
    lp.stop()
    assert wait_for(lambda: lan_threads() == [], 3.0), lan_threads()
    assert lp.running is False and lp.peers_view()["listening"] is False
    # the port is free again and a restart works
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", tport))
    s.close()
    lp.start()
    try:
        assert lp.listening and lp.wait_firewall(5.0)
        assert lan_threads() == ["tnt-lan-beacon", "tnt-lan-listen", "tnt-lan-server"]
    finally:
        lp.stop()
    assert wait_for(lambda: lan_threads() == [], 3.0)


def test_port_in_use_is_reported_not_fatal(tmp_path):
    taken = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    taken.bind(("127.0.0.1", 0))
    taken.listen(1)
    port = taken.getsockname()[1]
    lp, _events, _cfg = make(tmp_path, ports=(0, port))
    try:
        lp.start()
        v = lp.peers_view()
        assert v["running"] is True and v["listening"] is True          # the beacon side still works
        assert f"TCP {port}" in v["error"] and "server" in v["error"]
        assert lp.wait_firewall(5.0) and lan_threads() == ["tnt-lan-beacon", "tnt-lan-listen"]
    finally:
        lp.stop()
        taken.close()
    assert wait_for(lambda: lan_threads() == [], 3.0)


# =========================================================================================
# the on/off switch (set_enabled)
# =========================================================================================
VIEW_KEYS = {"self", "peers", "listening", "error", "enabled", "running", "throughput_running", "beacon_port",
             "throughput_port", "firewall"}
RUNNING_THREADS = ["tnt-lan-beacon", "tnt-lan-listen", "tnt-lan-server"]


def lan_states(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [e["data"] for e in events if e["type"] == "lan.state"]


def settled_threads(lp: LanPeers) -> List[str]:
    """``lan_threads()`` once the short-lived ``tnt-lan-firewall`` worker of a start has finished."""
    assert lp.wait_firewall(5.0)
    return lan_threads()


def saved_enabled(tmp_path) -> Any:
    """``lan.enabled`` as it was written to config.json (not just the in-memory copy)."""
    return json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))["lan"]["enabled"]


def test_set_enabled_off_then_on_persists_stops_and_restarts(tmp_path):
    lp, events, cfg = make(tmp_path)
    lp.start()
    try:
        assert lp.running and lp.listening and settled_threads(lp) == RUNNING_THREADS
        # --- off: persisted, threads gone, the view reports "disabled"
        view = lp.set_enabled(False)
        assert cfg.get("lan.enabled") is False and saved_enabled(tmp_path) is False
        assert wait_for(lambda: lan_threads() == [], 3.0), lan_threads()
        assert view["listening"] is False and view["running"] is False and view["error"] == "disabled"
        assert view["enabled"] is False and view["peers"] == [] and set(view) == VIEW_KEYS
        v = lp.peers_view()
        assert v["listening"] is False and v["running"] is False and v["error"] == "disabled" and v["enabled"] is False
        assert lp.running is False and lp.listening is False
        # the whole peers view goes out as lan.state so every open window follows
        assert lan_states(events) == [view]
        # --- on again: the threads are back and the error is cleared
        view = lp.set_enabled(True)
        assert cfg.get("lan.enabled") is True and saved_enabled(tmp_path) is True
        assert lp.running is True and lp.listening is True
        assert view["listening"] is True and view["running"] is True and view["error"] is None
        assert view["enabled"] is True and set(view) == VIEW_KEYS and view["beacon_port"] > 0 and view["throughput_port"] > 0
        assert settled_threads(lp) == RUNNING_THREADS
        assert len(lan_states(events)) == 2 and lan_states(events)[-1] == view
        assert lp.peers_view()["error"] is None
    finally:
        lp.stop()
    assert wait_for(lambda: lan_threads() == [], 3.0)


def test_set_enabled_is_idempotent(tmp_path):
    lp, events, cfg = make(tmp_path)
    lp.start()
    try:
        first, second = lp.set_enabled(False), lp.set_enabled(False)
        assert wait_for(lambda: lan_threads() == [], 3.0), lan_threads()
        for v in (first, second):
            assert v["listening"] is False and v["running"] is False and v["error"] == "disabled" and v["enabled"] is False
        assert first["self"] == second["self"] and cfg.get("lan.enabled") is False
        assert len(lan_states(events)) == 2          # both calls tell the open windows
        on1 = lp.set_enabled(True)
        threads, ports = settled_threads(lp), (lp.beacon_port, lp.throughput_port)
        on2 = lp.set_enabled(True)                   # the second one must not re-open the sockets
        assert threads == settled_threads(lp) == RUNNING_THREADS
        assert (lp.beacon_port, lp.throughput_port) == ports
        assert (on1["beacon_port"], on1["throughput_port"]) == (on2["beacon_port"], on2["throughput_port"]) == ports
        assert on2["error"] is None and on2["running"] is True and cfg.get("lan.enabled") is True
        assert len(lan_states(events)) == 4
    finally:
        lp.stop()
    assert wait_for(lambda: lan_threads() == [], 3.0)


def test_set_enabled_true_starts_an_instance_whose_config_says_false(tmp_path):
    lp, events, cfg = make(tmp_path, enabled=False)
    lp.start()                                       # a no-op while lan.enabled is false
    assert lp.running is False and lan_threads() == [] and events == []
    assert lp.peers_view()["error"] == "disabled" and lp.peers_view()["listening"] is False
    try:
        view = lp.set_enabled(True)
        assert cfg.get("lan.enabled") is True and saved_enabled(tmp_path) is True
        assert lp.running is True and lp.listening is True and settled_threads(lp) == RUNNING_THREADS
        assert view["listening"] is True and view["running"] is True and view["error"] is None
        assert [e["type"] for e in events] == ["lan.state"] and lan_states(events) == [view]
    finally:
        lp.stop()
    assert wait_for(lambda: lan_threads() == [], 3.0)


def test_set_enabled_coerces_to_a_real_bool(tmp_path):
    lp, events, cfg = make(tmp_path)
    try:
        lp.set_enabled("")                           # falsy -> off, and stored as a real bool
        assert cfg.get("lan.enabled") is False and saved_enabled(tmp_path) is False
        assert lp.peers_view()["error"] == "disabled" and lan_threads() == []
        lp.set_enabled(1)                            # truthy -> on
        assert cfg.get("lan.enabled") is True and saved_enabled(tmp_path) is True
        assert lp.running is True and settled_threads(lp) == RUNNING_THREADS
        assert len(lan_states(events)) == 2
    finally:
        lp.stop()
    assert wait_for(lambda: lan_threads() == [], 3.0)


# =========================================================================================
# throughput over loopback
# =========================================================================================
def test_loopback_throughput_between_two_instances(tmp_path):
    pinger = FakePinger(1.5)
    a, events_a, _ = make(tmp_path, pinger=pinger)
    b, events_b, _ = make(tmp_path)
    a.start()
    b.start()
    try:
        assert a.beacon_port != b.beacon_port and a.throughput_port != b.throughput_port
        # b's beacon reaches a's listener (sent by hand over loopback: tests never broadcast)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(b.beacon_bytes(), ("127.0.0.1", a.beacon_port))
            s.sendto(b"\xff" * 700, ("127.0.0.1", a.beacon_port))              # oversized junk: ignored
            s.sendto(a.beacon_bytes(), ("127.0.0.1", a.beacon_port))           # our own: ignored
        finally:
            s.close()
        assert wait_for(lambda: any(e["type"] == "lan.peers" for e in events_a))
        time.sleep(0.2)
        peers = a.peers_view()["peers"]
        assert len(peers) == 1 and peers[0]["id"] == b.peer_id and peers[0]["ip"] == "127.0.0.1"
        assert peers[0]["port"] == b.throughput_port and peers[0]["hostname"] == b.hostname
        assert sum(1 for e in events_a if e["type"] == "lan.peers") == 1
        # the test itself: a -> b using the port b advertised
        r = a.run_throughput("127.0.0.1", seconds=1)
        assert r["error"] is None, r
        assert r["upload_mbps"] > 50 and r["download_mbps"] > 50, r
        assert r["latency_ms"] == 1.5 and pinger.calls == ["127.0.0.1"]        # the ICMP RTT wins over the connect time
        assert r["peer"] == {"ip": "127.0.0.1", "hostname": b.hostname} and r["seconds"] == 1
        assert 1.5 <= r["duration_s"] < 8 and r["ts"] > 0
        assert set(r) == {"ts", "peer", "seconds", "upload_mbps", "download_mbps", "latency_ms", "duration_s", "error"}
        assert a.last_throughput() == r and a.throughput_running is False
        prog = [e["data"] for e in events_a if e["type"] == "lan.throughput.progress"]
        phases = [p["phase"] for p in prog]
        assert phases[0] == "connect" and "upload" in phases and "download" in phases
        assert phases.index("upload") < phases.index("download") and phases[-1] == "download"
        assert prog[-1]["pct"] == 100 and all(0 <= p["pct"] <= 100 and 0 <= p["phase_pct"] <= 100 for p in prog)
        pcts = [p["pct"] for p in prog]
        assert pcts == sorted(pcts)
        assert any(p["mbps"] for p in prog if p["phase"] == "upload") and any(p["mbps"] for p in prog if p["phase"] == "download")
        assert 3 <= len(prog) <= 40                                             # ~4 per second, not per chunk
        done = [e["data"] for e in events_a if e["type"] == "lan.throughput.done"]
        assert done == [{"result": r}]
        assert not any(e["type"].startswith("lan.throughput") for e in events_b)  # the server side stays quiet
        assert wait_for(lambda: not b._server_busy)
        # the other direction, an unknown peer (no beacon seen): explicit port, connect-time latency
        r2 = b.run_throughput("127.0.0.1", seconds=1, port=a.throughput_port)
        assert r2["error"] is None and r2["latency_ms"] >= 0 and r2["peer"]["hostname"] is None
        assert r2["upload_mbps"] > 50 and r2["download_mbps"] > 50
    finally:
        a.stop()
        b.stop()
    assert wait_for(lambda: lan_threads() == [], 3.0), lan_threads()


def test_busy_bad_refused_and_validation(tmp_path):
    a, _ea, _ = make(tmp_path)
    b, _eb, _ = make(tmp_path)
    a.start()
    b.start()
    try:
        # a non-TNT request is answered with BAD and dropped
        c = socket.create_connection(("127.0.0.1", b.throughput_port), timeout=5)
        c.sendall(b"GET / HTTP/1.0\r\n")
        assert c.recv(8) == b"BAD" and c.recv(8) == b""
        c.close()
        # a client holding the server makes it busy for everyone else
        hold = socket.create_connection(("127.0.0.1", b.throughput_port), timeout=5)
        hold.sendall(lanpeers.build_header(lanpeers.MODE_UPLOAD, 3))
        assert hold.recv(2) == b"OK"
        second = socket.create_connection(("127.0.0.1", b.throughput_port), timeout=5)
        second.sendall(lanpeers.build_header(lanpeers.MODE_DOWNLOAD, 1))
        assert second.recv(4) == b"BUSY"
        second.close()
        r = a.run_throughput("127.0.0.1", seconds=1, port=b.throughput_port)
        assert r["error"] and "busy" in r["error"] and r["upload_mbps"] is None and r["download_mbps"] is None
        assert r["latency_ms"] is not None and r["duration_s"] is not None
        hold.shutdown(socket.SHUT_WR)
        assert lanpeers.parse_trailer(hold.recv(16)) == (0, 0)
        hold.close()
        assert wait_for(lambda: not b._server_busy)
        r = a.run_throughput("127.0.0.1", seconds=1, port=b.throughput_port)
        assert r["error"] is None
        # nobody listening: a RESULT with the error, nothing raised
        r = a.run_throughput("127.0.0.1", seconds=1, port=free_port())
        assert r["error"] and "refused" in r["error"] and r["download_mbps"] is None and r["duration_s"] is not None
        assert a.last_throughput() == r
        # one client-side test at a time
        results: Dict[str, Any] = {}
        t = threading.Thread(target=lambda: results.setdefault("r", a.run_throughput("127.0.0.1", seconds=2, port=b.throughput_port)))
        t.start()
        assert wait_for(lambda: a.throughput_running)
        with pytest.raises(RuntimeError):
            a.run_throughput("127.0.0.1", seconds=1, port=b.throughput_port)
        t.join(20)
        assert results["r"]["error"] is None and a.throughput_running is False
        # validation
        for bad in ("not an ip", "", "10.0.0.256", None):
            with pytest.raises(ValueError):
                a.run_throughput(bad)
        for secs in (0, 21, "x"):
            with pytest.raises(ValueError):
                a.run_throughput("127.0.0.1", seconds=secs)
    finally:
        a.stop()
        b.stop()
    assert wait_for(lambda: lan_threads() == [], 3.0), lan_threads()


# =========================================================================================
# network changes (tnt.netwatch -> LanPeers.on_network_change)
# =========================================================================================
def test_network_change_drops_peers_of_a_left_subnet_and_rematches_the_rest(tmp_path):
    clock = {"now": 1_700_000_000.0}
    adapters = [adapter("Ethernet", "10.0.0.5", 24, index=12, gateway="10.0.0.1"), adapter("Wi-Fi", "192.168.1.20", 24, index=7)]
    lp, events, _cfg = make(tmp_path, adapters=adapters, clock=lambda: clock["now"], ports=(7132, 7133))
    lp.handle_datagram(lanpeers.encode_beacon("peer-a", "BENCH-A", "1.8.0", 7133, clock["now"]), ("10.0.0.7", 51000))
    lp.handle_datagram(lanpeers.encode_beacon("peer-b", "OFFICE-PC", "1.8.0", 7133, clock["now"]), ("192.168.1.30", 51000))
    lp.handle_datagram(lanpeers.encode_beacon("peer-c", "ELSEWHERE", "1.8.0", 7133, clock["now"]), ("172.16.9.9", 51000))
    assert {p["id"]: p["adapter"] for p in lp.peers()} == {"peer-a": "Ethernet", "peer-b": "Wi-Fi", "peer-c": None}
    assert lp.peers_view()["self"]["ip"] == "10.0.0.5"
    # the laptop moves: Ethernet lands on another subnet and a USB adapter joins peer-c's
    adapters[0] = adapter("Ethernet", "10.20.30.45", 24, index=12, gateway="10.20.30.1")
    adapters.append(adapter("USB Ethernet", "172.16.9.20", 24, index=31))
    events.clear()
    lp.on_network_change({"subnets_changed": True})
    assert {p["id"]: p["adapter"] for p in lp.peers()} == {"peer-b": "Wi-Fi", "peer-c": "USB Ethernet"}
    assert [e["type"] for e in events] == ["lan.peers", "lan.state"]
    assert [p["id"] for p in events[0]["data"]["peers"]] == ["peer-c", "peer-b"]
    assert events[1]["data"]["self"]["ip"] == "10.20.30.45", "the cached self address was dropped"
    assert lp._beacon_wake.is_set()
    # nothing left to re-match: only the view goes out
    events.clear()
    lp.on_network_change({})
    assert [e["type"] for e in events] == ["lan.state"]


def test_this_pc_without_an_internet_adapter_is_an_address_the_beacons_leave_from():
    """A bench cable (static or self-assigned addresses, no default route): "This PC" still names an address, a
    physical adapter's before a virtual switch's and a routable one before 169.254.x.x; never a /32 tunnel or a down
    adapter."""
    switch = adapter("vEthernet (Example Switch)", "172.29.64.1", 20, index=30)
    switch.is_physical = False
    tunnel = adapter("Example VPN", "100.64.0.9", 32, index=40)
    down = adapter("Wi-Fi", "192.168.1.20", 24, index=7, status="down")
    apipa = adapter("Ethernet", "169.254.23.45", 16, index=12)
    bench = adapter("Ethernet 2", "172.16.20.15", 24, index=18)
    assert lanpeers._bench_ipv4([switch, tunnel, down, apipa]) == "169.254.23.45"
    assert lanpeers._bench_ipv4([switch, tunnel, down, apipa, bench]) == "172.16.20.15"
    assert lanpeers._bench_ipv4([tunnel, switch]) == "172.29.64.1"
    assert lanpeers._bench_ipv4([tunnel, down]) is None and lanpeers._bench_ipv4([]) is None


def test_network_change_sends_the_next_beacon_at_once(tmp_path):
    lp, _events, _cfg = make(tmp_path)
    sent: List[float] = []
    lp.send_beacon = lambda: sent.append(time.monotonic()) or 0
    lp.start()
    try:
        assert wait_for(lambda: len(sent) == 1)
        time.sleep(0.2)
        assert len(sent) == 1                                   # the next one is BEACON_INTERVAL_S away
        lp.on_network_change({})
        assert wait_for(lambda: len(sent) == 2, 2.0) and sent[1] - sent[0] < 2.0
    finally:
        lp.stop()
    assert wait_for(lambda: lan_threads() == [], 3.0), lan_threads()


def test_a_failed_adapter_read_during_a_network_change_keeps_the_peers_and_is_retried(tmp_path):
    clock = {"now": 1_700_000_000.0}
    adapters = [adapter("Ethernet", "10.20.0.50", 24, index=12, gateway="10.20.0.1")]
    lp, events, _cfg = make(tmp_path, adapters=adapters, clock=lambda: clock["now"], ports=(7132, 7133))
    lp.handle_datagram(lanpeers.encode_beacon("bench-peer-a", "BENCH-A", "1.8.0", 7133, clock["now"]), ("10.20.0.77", 51000))
    assert {p["id"]: p["adapter"] for p in lp.peers()} == {"bench-peer-a": "Ethernet"}
    failures = {"left": 1}

    def flaky() -> List[Any]:
        if failures["left"]:
            failures["left"] -= 1
            raise OSError(31, "simulated GetAdaptersAddresses failure")
        return adapters

    lp._adapters_fn = flaky
    events.clear()
    lp.on_network_change({})
    assert {p["id"]: p["adapter"] for p in lp.peers()} == {"bench-peer-a": "Ethernet"}, "a failed read is not 'no subnets'"
    assert [e["type"] for e in events] == ["lan.state"] and lp._rematch_pending is True
    # the beacon thread matches the peers again before its next beacon; this time the network really changed
    adapters[0] = adapter("Ethernet", "192.168.77.23", 24, index=12, gateway="192.168.77.1")
    stop = threading.Event()
    lp.send_beacon = lambda: (stop.set(), lp._beacon_wake.set(), 0)[-1]
    lp._beacon_loop(stop)
    assert lp.peers() == [] and lp._rematch_pending is False
    assert [e["type"] for e in events][-1] == "lan.peers"
