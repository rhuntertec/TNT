"""The servers and their robustness (review 1.21.2, section 10): the DHCP server's in-use check before an offer, a
firewall rule that exists but is switched off, a failed adapter enumeration during a network change, a LAN peer beacon
flood, and reading a packet back from the second interface of a pcapng.

Nothing here starts a real DHCP or TFTP server, runs netsh or touches the real firewall or an adapter: every server is
driven through its seams with the fakes of tests/test_dhcp.py and tests/test_lanpeers.py (tests/conftest.py also blocks
UDP 67/69).  Addresses are documentation ranges only.
"""
from __future__ import annotations

import io
import json
import logging
import sys
import threading
import types
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest

from tnt import dhcp, firewall, lanpeers, pcapng
from tnt.config import Config
from tnt.events import EventBus
from tnt.icmp import PingResult
from tnt.lanpeers import LanPeers

import test_dhcp as td
from test_pcapng import ETH_FRAME, TS, epb, idb, opt, opts, shb

T0 = td.T0
BENCH_IP = "192.0.2.100"                 # the static bench NIC the server runs on (pool .101-.105)
SILENT_HOST = "192.0.2.101"              # a PC on the Public profile: answers ARP, drops ICMP echo
SILENT_MAC = "00:00:5E:00:53:01"         # IANA documentation MACs
OTHER_MAC = "00:00:5E:00:53:02"
IP_REQ_TIMED_OUT = 11010


# =====================================================================================================================
# 1. the in-use check before an OFFER: a host that answers ARP but drops ICMP echo is in use
# =====================================================================================================================
class SilentPinger(td.FakePinger):
    """Every echo to an address in ``silent`` times out (the host drops ICMP); the others follow FakePinger."""

    def __init__(self, silent=(SILENT_HOST,)) -> None:
        super().__init__()
        self.silent = set(silent)

    def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
        if ip in self.silent:
            self.calls.append((ip, timeout_ms))
            return PingResult(ok=False, rtt_ms=None, status=IP_REQ_TIMED_OUT, error=None, ttl=None, size=size, ip=ip)
        return super().ping(ip, size, timeout_ms, ttl)


class Neighbours:
    """The neighbour-table seam: ``(ip, if_index) -> (MAC, state) | None``; every lookup is recorded."""

    def __init__(self, rows: Optional[Dict[str, Tuple[str, Optional[str]]]] = None, raises: bool = False) -> None:
        self.rows = dict(rows or {})
        self.raises = raises
        self.calls: List[Tuple[str, Any]] = []

    def __call__(self, ip, if_index=None):
        self.calls.append((ip, if_index))
        if self.raises:
            raise OSError(87, "GetIpNetTable2 failed")
        return self.rows.get(ip)


@pytest.fixture
def bench(tmp_path, monkeypatch):
    """A DHCP server on a static 192.0.2.100/24 NIC (index 12) with a silent host on .101, driven via handle()."""
    real = dhcp.scan_for_servers
    monkeypatch.setattr(dhcp, "scan_for_servers", lambda adapters, wait_s, **kw: real(adapters, 0.3, **kw))
    monkeypatch.setattr(dhcp, "MIN_SCAN_WAIT_S", 0.2)
    made: List[Any] = []

    def make(neighbours: Neighbours, pinger: Optional[td.FakePinger] = None) -> SimpleNamespace:
        sim = td.NicSim([td.adapter(ip=BENCH_IP, dhcp_enabled=False, gateway=None, dhcp_server=None)])
        pinger = pinger or SilentPinger()
        srv, events, factory, db, cfg, clock = td.make_server(tmp_path / f"s{len(made)}", sim, pinger=pinger,
                                                              neighbour_fn=neighbours)
        made.append((srv, db))
        srv.start(force=True)
        return SimpleNamespace(srv=srv, sock=factory.bound_to(BENCH_IP), pinger=pinger, neighbours=neighbours, db=db)

    (tmp_path / "s0").mkdir()
    for i in range(1, 4):
        (tmp_path / f"s{i}").mkdir()
    yield make
    for srv, db in made:
        srv.stop()
        db.close()


def _offer(ctx, mac=td.MAC_A, xid=1) -> Optional[str]:
    sent = ctx.srv.handle(td.build(dhcp.DISCOVER, mac=mac, xid=xid), ("0.0.0.0", 68), now=T0)
    return td.last_reply(ctx.sock)[0].yiaddr if sent == dhcp.OFFER else None


def test_a_host_that_answers_arp_but_drops_ping_is_not_offered_its_address(bench):
    ctx = bench(Neighbours({SILENT_HOST: (SILENT_MAC, "reachable")}))
    assert _offer(ctx) == "192.0.2.102"
    assert ctx.srv._table.bad.get(SILENT_HOST, 0) > T0, "the silent host's address is held, like one that answered a ping"
    assert ctx.neighbours.calls[0] == (SILENT_HOST, 12), "the lookup is scoped to the served adapter"


def test_a_permanent_neighbour_entry_also_counts_as_in_use(bench):
    ctx = bench(Neighbours({SILENT_HOST: (SILENT_MAC, "permanent")}))
    assert _offer(ctx) == "192.0.2.102"


@pytest.mark.parametrize("state", ["stale", "delay", "probe", "incomplete", None])
def test_an_unconfirmed_neighbour_entry_is_no_proof_that_the_address_is_in_use(bench, state):
    # a stale/delay row is a host that left minutes ago (or has not answered yet); arp -a's rows have no state at all
    ctx = bench(Neighbours({SILENT_HOST: (SILENT_MAC, state)}))
    assert _offer(ctx) == SILENT_HOST


def test_the_requesting_clients_own_neighbour_entry_never_blocks_its_address(bench):
    # a returning camera whose old row is still in the table is the host "using" the address: it may have it back
    ctx = bench(Neighbours({SILENT_HOST: (td.MAC_A, "reachable")}))
    assert _offer(ctx, mac=td.MAC_A) == SILENT_HOST


def test_no_neighbour_lookup_when_the_ping_already_answered(bench):
    pinger = td.FakePinger(alive={SILENT_HOST})
    ctx = bench(Neighbours({SILENT_HOST: (SILENT_MAC, "reachable")}), pinger=pinger)
    assert _offer(ctx) == "192.0.2.102"
    assert ctx.neighbours.calls == [("192.0.2.102", 12)], "the answered ping needed no second look"


def test_a_neighbour_table_that_cannot_be_read_leaves_the_ping_verdict(bench):
    ctx = bench(Neighbours(raises=True))
    assert _offer(ctx) == SILENT_HOST


def test_the_in_use_check_stays_bounded(bench):
    # every pool address is silent AND held by another host: still at most PING_CHECK_MAX pings and lookups per DISCOVER
    silent = {f"192.0.2.{n}" for n in range(101, 106)}
    ctx = bench(Neighbours({ip: (OTHER_MAC, "reachable") for ip in silent}), pinger=SilentPinger(silent))
    assert _offer(ctx) is None
    assert len(ctx.pinger.calls) == dhcp.PING_CHECK_MAX and len(ctx.neighbours.calls) == dhcp.PING_CHECK_MAX


def test_the_default_neighbour_lookup_is_tnt_arp_imported_lazily(tmp_path, monkeypatch):
    fake = types.ModuleType("tnt.arp")
    seen: List[Tuple[str, Any]] = []
    fake.neighbour = lambda ip, if_index=None: seen.append((ip, if_index)) or (SILENT_MAC, "reachable")
    monkeypatch.setitem(sys.modules, "tnt.arp", fake)
    srv = dhcp.DhcpServer(None, None, None, pinger=SilentPinger())
    srv._adapter = SimpleNamespace(index=12)
    check = srv._ping_fn(td.MAC_A)
    assert check is not None and check(SILENT_HOST) is True and seen == [(SILENT_HOST, 12)]


# =====================================================================================================================
# 2. a firewall rule that is there but switched off or set to Block is not "present"
# =====================================================================================================================
EXE = r"C:\Program Files\TNT\TNTService.exe"
RULE = "TNT DHCP server (UDP 67 in)"
ENGLISH = {"enabled": "Enabled", "action": "Action", "yes": "Yes", "no": "No", "allow": "Allow", "block": "Block"}
GERMAN = {"enabled": "Aktiviert", "action": "Aktion", "yes": "Ja", "no": "Nein", "allow": "Zulassen", "block": "Blockieren"}


class RuleNetsh:
    """``netsh advfirewall firewall`` for one rule that keeps its Enabled/Action state; ``set rule ... new enable=yes
    action=allow`` switches it on, as Windows does.  *words* are the (localised) labels and values ``show`` prints."""

    def __init__(self, enabled: bool = True, allow: bool = True, words: Dict[str, str] = ENGLISH,
                 present: bool = True, fail: Tuple[str, ...] = ()) -> None:
        self.enabled, self.allow, self.words, self.present, self.fail = enabled, allow, words, present, fail
        self.commands: List[List[str]] = []

    @property
    def verbs(self) -> List[str]:
        return [c[2] for c in self.commands]

    def __call__(self, argv, **kwargs):
        args = list(argv[1:])
        self.commands.append(args)
        verb = args[2]
        if verb in self.fail:
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"The requested operation requires elevation.")
        if verb == "show":
            if not self.present:
                return SimpleNamespace(returncode=1, stdout=b"\r\nNo rules match the specified criteria.\r\n", stderr=b"")
            w = self.words
            out = (f"\r\nRule Name:        {RULE}\r\n" + "-" * 60 + "\r\n"
                   f"{w['enabled']}:          {w['yes'] if self.enabled else w['no']}\r\n"
                   "Direction:        In\r\nProfiles:         Domain,Private,Public\r\nLocalIP:          Any\r\n"
                   "RemoteIP:         Any\r\nProtocol:         UDP\r\nLocalPort:        67,68\r\nRemotePort:       Any\r\n"
                   f"Program:          {EXE}\r\n{w['action']}:           {w['allow'] if self.allow else w['block']}\r\n"
                   "Ok.\r\n").encode("cp850")
            return SimpleNamespace(returncode=0, stdout=out, stderr=b"")
        if verb == "set":
            assert args[3:5] == ["rule", f"name={RULE}"] and "new" in args, args
            new = args[args.index("new") + 1:]
            if "enable=yes" in new:
                self.enabled = True
            if "action=allow" in new:
                self.allow = True
            return SimpleNamespace(returncode=0, stdout=b"\r\nUpdated 1 rule(s).\r\nOk.\r\n", stderr=b"")
        if verb == "delete":
            self.present = False
            return SimpleNamespace(returncode=0, stdout=b"Deleted 1 rule(s).\r\nOk.\r\n", stderr=b"")
        if verb == "add":
            self.present, self.enabled, self.allow = True, True, True
            return SimpleNamespace(returncode=0, stdout=b"Ok.\r\n", stderr=b"")
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"unknown")


@pytest.mark.parametrize("enabled,allow", [(False, True), (True, False), (False, False)],
                         ids=["disabled", "block", "disabled-and-block"])
def test_a_rule_that_is_switched_off_or_blocks_is_switched_back_on_and_the_log_says_so(enabled, allow, caplog):
    fw = RuleNetsh(enabled=enabled, allow=allow)
    with caplog.at_level(logging.WARNING, logger="tnt.firewall"):
        assert firewall.ensure_rule(RULE, EXE, "udp", "67,68", runner=fw) == (True, None)
    assert fw.verbs == ["show", "set"]
    set_args = fw.commands[1]
    assert set_args[:5] == ["advfirewall", "firewall", "set", "rule", f"name={RULE}"]
    assert set_args[set_args.index("new") + 1:] == ["enable=yes", "action=allow"]
    assert fw.enabled and fw.allow
    assert any(RULE in r.getMessage() and "switched" in r.getMessage() for r in caplog.records), caplog.text


def test_an_enabled_allow_rule_is_left_alone():
    fw = RuleNetsh()
    assert firewall.ensure_rule(RULE, EXE, "udp", "67,68", runner=fw) == (True, None) and fw.verbs == ["show"]


@pytest.mark.parametrize("enabled,allow", [(True, True), (False, False)], ids=["healthy", "disabled-and-block"])
def test_on_a_localised_windows_the_rule_is_always_forced_on(enabled, allow):
    # the Enabled/Action words are translated (Ja/Nein, Zulassen/Blockieren), so they cannot be read: set them instead
    fw = RuleNetsh(enabled=enabled, allow=allow, words=GERMAN)
    assert firewall.ensure_rule(RULE, EXE, "udp", "67,68", runner=fw) == (True, None)
    assert fw.verbs == ["show", "set"] and fw.enabled and fw.allow


def test_on_a_localised_windows_a_rule_that_cannot_be_set_is_kept_as_it_was(caplog):
    # A caller without elevation (a dev console) cannot 'set' anything, and would fail the delete and add the same
    # way.  Before the fix such a caller got (True, None) for a healthy rule; replacing a rule whose state could not
    # even be read would report a firewall error for a rule that is fine, or delete it and leave none.  An
    # unreadable state is no proof that the rule is off, so it is kept, with a warning naming it.
    fw = RuleNetsh(words=GERMAN, fail=("set", "delete", "add"))
    with caplog.at_level(logging.WARNING, logger="tnt.firewall"):
        assert firewall.ensure_rule(RULE, EXE, "udp", "67,68", runner=fw) == (True, None)
    assert fw.verbs == ["show", "set"] and fw.present
    assert any(RULE in r.getMessage() for r in caplog.records), caplog.text


def test_a_rule_that_cannot_be_switched_on_is_replaced():
    fw = RuleNetsh(enabled=False, fail=("set",))
    assert firewall.ensure_rule(RULE, EXE, "udp", "67,68", runner=fw) == (True, None)
    assert fw.verbs == ["show", "set", "delete", "add"] and fw.enabled and fw.allow


def test_a_rule_that_can_be_neither_switched_on_nor_replaced_is_an_error():
    fw = RuleNetsh(allow=False, fail=("set", "add"))
    ok, error = firewall.ensure_rule(RULE, EXE, "udp", "67,68", runner=fw)
    assert ok is False and error and "netsh exit 1" in error


def test_the_dhcp_server_rule_is_switched_back_on_too():
    fw = RuleNetsh(enabled=False, allow=False)
    assert dhcp.ensure_firewall_rule(EXE, fw) == (True, None)
    assert fw.verbs == ["show", "set"] and fw.enabled and fw.allow


# =====================================================================================================================
# 3. one failed adapter enumeration during net.changed is "no answer", never "the adapter was removed"
# =====================================================================================================================
class FlakyAdapters:
    """The server's adapter seam: the next *fail* calls raise (or, with *empty*, answer an empty list)."""

    def __init__(self, sim: td.NicSim) -> None:
        self.sim = sim
        self.fail = 0
        self.empty = False
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.fail > 0:
            self.fail -= 1
            if self.empty:
                return []
            raise OSError(1228, "GetAdaptersAddresses failed")
        return self.sim.get_adapters()


STATIC_IP = "198.51.100.100"


def office_nic():
    """The laptop's office NIC, a DHCP client the server re-addresses to STATIC_IP while it serves."""
    return td.adapter(ip="192.0.2.112", dhcp_server="192.0.2.251", gateway="192.0.2.251")


def _no_netstop_thread() -> bool:
    return not any(t.name == "tnt-dhcp-netstop" and t.is_alive() for t in threading.enumerate())


@pytest.mark.parametrize("empty", [False, True], ids=["raises", "empty-list"])
def test_one_failed_enumeration_keeps_the_server_and_the_nic_restore_record(tmp_path, monkeypatch, empty):
    real = dhcp.scan_for_servers
    monkeypatch.setattr(dhcp, "scan_for_servers", lambda adapters, wait_s, **kw: real(adapters, 0.3, **kw))
    monkeypatch.setattr(dhcp, "MIN_SCAN_WAIT_S", 0.2)
    sim = td.NicSim([office_nic()])                                # a DHCP-client NIC, re-addressed to the bench IP
    srv, _events, _factory, db, _cfg, _clock = td.make_server(tmp_path, sim, cfg_patch={"static_ip": STATIC_IP})
    flaky = FlakyAdapters(sim)
    srv._adapters_fn = flaky
    try:
        srv.start(force=True)
        eth = sim.find("Ethernet")
        assert eth.dhcp_enabled is False
        flaky.fail, flaky.empty = 1, empty
        srv.on_network_change({"changes": [{"adapter": "Wi-Fi", "kind": "up", "old": "down", "new": "up"}]})
        assert td.wait_for(_no_netstop_thread, 2.0)
        assert flaky.fail == 0, "the failed enumeration was the one the handler used"
        st = srv.status()
        # still serving, the record kept - but the status says the adapters could not be read, so the tile never
        # shows a healthy server on a NIC that may really be gone (a PC whose only adapter was the served one)
        assert srv.running and st["error"] is None and st["warning"] == dhcp.ADAPTERS_UNREAD_WARNING
        assert json.loads(db.get_meta("dhcp.nic_changed"))["static_ip"] == STATIC_IP
        srv.on_network_change({})                                  # the next read answers: the warning goes
        assert srv.status()["warning"] is None
        flaky.fail = 1
        srv.on_network_change({})
        assert srv.status()["warning"] == dhcp.ADAPTERS_UNREAD_WARNING
        srv.stop()
        assert srv.status()["warning"] is None, "the warning spoke of the running server; a stopped one drops it"
        assert eth.dhcp_enabled is True, "stop() put the NIC back on DHCP"
        assert not db.get_meta("dhcp.nic_changed")
    finally:
        srv.stop()
        db.close()


def test_a_removal_is_confirmed_by_a_fresh_enumeration_before_the_record_is_dropped(tmp_path, monkeypatch):
    # the handler saw the NIC missing, but by the time the stop runs a fresh, successful enumeration lists it again:
    # the NIC is restored through netsh as usual, never written off as "removed"
    real = dhcp.scan_for_servers
    monkeypatch.setattr(dhcp, "scan_for_servers", lambda adapters, wait_s, **kw: real(adapters, 0.3, **kw))
    monkeypatch.setattr(dhcp, "MIN_SCAN_WAIT_S", 0.2)
    sim = td.NicSim([office_nic()])
    srv, _events, _factory, db, _cfg, _clock = td.make_server(tmp_path, sim, cfg_patch={"static_ip": STATIC_IP})
    try:
        srv.start(force=True)
        srv._stop_for_network("Ethernet is no longer present", gone=True)
        st = srv.status()
        assert not srv.running and st["error"] == "stopped: Ethernet is no longer present"
        assert st["warning"] != "Ethernet was removed; its temporary address went with it"
        assert any("source=dhcp" in c for c in sim.commands), "the NIC was put back on DHCP"
        assert sim.find("Ethernet").dhcp_enabled is True and not db.get_meta("dhcp.nic_changed")
    finally:
        srv.stop()
        db.close()


def test_a_removal_that_cannot_be_confirmed_keeps_the_record(tmp_path, monkeypatch):
    # the fresh enumeration fails too: restore as usual; if netsh cannot find the NIC the record stays for the next start
    real = dhcp.scan_for_servers
    monkeypatch.setattr(dhcp, "scan_for_servers", lambda adapters, wait_s, **kw: real(adapters, 0.3, **kw))
    monkeypatch.setattr(dhcp, "MIN_SCAN_WAIT_S", 0.2)
    sim = td.NicSim([office_nic()])
    srv, _events, _factory, db, _cfg, _clock = td.make_server(tmp_path, sim, cfg_patch={"static_ip": STATIC_IP})
    flaky = FlakyAdapters(sim)
    try:
        srv.start(force=True)
        srv._adapters_fn = flaky
        flaky.fail = 1
        srv._stop_for_network("Ethernet is no longer present", gone=True)
        assert not srv.running
        assert srv.status()["warning"] != "Ethernet was removed; its temporary address went with it"
        assert any("source=dhcp" in c for c in sim.commands)
    finally:
        srv.stop()
        db.close()


# =====================================================================================================================
# 4. a LAN peer beacon flood: the table is capped and the publishes are bounded
# =====================================================================================================================
def _lan(tmp_path, clock):
    cfg = Config(tmp_path / "config.json").load()
    bus = EventBus()
    rows: List[int] = []
    last: Dict[str, Any] = {}

    def on(e):
        if e["type"] == "lan.peers":
            rows.append(len(e["data"]["peers"]))
            last["peers"] = e["data"]["peers"]

    bus.subscribe(on)
    lp = LanPeers(cfg, bus, db=None, pinger=None, clock=clock, adapters_fn=lambda: [], beacon_port=0,
                  throughput_port=0, exe_path=None, runner=lambda *a, **k: None, bind_host="127.0.0.1")
    return lp, rows, last


def _beacon(pid: str, host: str = "EVIL", ts: float = 0.0) -> bytes:
    return lanpeers.encode_beacon(pid, host, "9.9.9", 7133, ts)


def test_a_flood_of_fresh_ids_from_one_address_holds_only_a_few_rows(tmp_path):
    now = {"t": 1_700_000_000.0}
    lp, rows, _last = _lan(tmp_path, lambda: now["t"])
    lp.handle_datagram(_beacon("real-peer", "BENCH-A"), ("192.0.2.20", 51000))
    for i in range(5000):
        now["t"] += 0.001
        lp.handle_datagram(_beacon(f"flood-{i:05d}"), ("192.0.2.7", 51000))
    ids = [p["id"] for p in lp.peers()]
    assert len(ids) == lanpeers.MAX_PEERS_PER_IP + 1
    assert "real-peer" in ids, "a flood from one host never pushes out a peer on another address"
    assert sorted(i for i in ids if i.startswith("flood-")) == [f"flood-{i:05d}" for i in range(5000 - lanpeers.MAX_PEERS_PER_IP, 5000)], \
        "the stalest ids of the flooding address went first"


def test_the_table_never_grows_past_its_total_cap_and_the_stalest_peer_goes(tmp_path):
    now = {"t": 1_700_000_000.0}
    lp, _rows, _last = _lan(tmp_path, lambda: now["t"])
    for i in range(lanpeers.MAX_PEERS + 50):
        now["t"] += 0.01
        lp.handle_datagram(_beacon(f"p{i}"), (f"198.51.100.{i % 250 + 1}" if i < 250 else f"203.0.113.{i - 249}", 51000))
    ids = {p["id"] for p in lp.peers()}
    assert len(ids) == lanpeers.MAX_PEERS
    assert "p0" not in ids and f"p{lanpeers.MAX_PEERS + 49}" in ids


def test_a_flood_publishes_a_bounded_number_of_events_and_the_last_change_still_goes_out(tmp_path):
    now = {"t": 1_700_000_000.0}
    mono = {"t": 100.0}
    lp, rows, last = _lan(tmp_path, lambda: now["t"])
    lp._publish_clock = lambda: mono["t"]
    for i in range(5000):
        lp.handle_datagram(_beacon(f"flood-{i:05d}"), (f"198.51.100.{i % 200 + 1}", 51000))
    assert len(rows) <= lanpeers.PUBLISH_BURST, "one burst per window, not one table per datagram"
    assert sum(rows) <= lanpeers.PUBLISH_BURST * lanpeers.MAX_PEERS
    # the listener's next tick after the window sends the table as it is now
    mono["t"] += lanpeers.PUBLISH_WINDOW_S
    lp.expire_peers()
    assert len(last["peers"]) == len(lp.peers()) == lanpeers.MAX_PEERS
    # and nothing more once it is out
    n = len(rows)
    mono["t"] += lanpeers.PUBLISH_WINDOW_S
    lp.expire_peers()
    assert len(rows) == n


def test_ordinary_peer_changes_still_publish_at_once(tmp_path):
    now = {"t": 1_700_000_000.0}
    lp, rows, _last = _lan(tmp_path, lambda: now["t"])
    for i in range(4):
        lp.handle_datagram(_beacon(f"peer-{i}", f"PC-{i}"), (f"192.0.2.{20 + i}", 51000))
    assert rows == [1, 2, 3, 4]


# =====================================================================================================================
# 5. read_packet_at reads a packet on any interface of a multi-interface pcapng with that interface's own context
# =====================================================================================================================
LINKTYPE_RAW = 101


def _two_interface_file(frame0: bytes, frame1: bytes, *, linktype1: int = 1, endian: str = "<",
                        options1: bytes = b"") -> bytes:
    """SHB, IDB#0 (Ethernet), IDB#1 (*linktype1*), one EPB on each: a Wireshark 'capture on all interfaces'."""
    return (shb(endian) + idb(1, endian=endian) + idb(linktype1, endian=endian, options=options1)
            + epb(frame0, interface=0, ts=TS, endian=endian) + epb(frame1, interface=1, ts=TS + 1, endian=endian))


def _index(data: bytes):
    return list(pcapng.iter_packets_with_offsets(io.BytesIO(data)))


def test_a_packet_on_the_second_interface_reads_back(tmp_path):
    data = _two_interface_file(ETH_FRAME, ETH_FRAME + b"\x01")
    path = tmp_path / "all-interfaces.pcapng"
    path.write_bytes(data)
    for offset, packet in _index(data):
        back = pcapng.read_packet_at(path, offset)
        assert back == packet, f"interface {packet['interface']} did not read back"
    assert [p["interface"] for _o, p in _index(data)] == [0, 1]


def test_each_packet_reads_back_with_its_own_interfaces_link_type_and_resolution(tmp_path):
    raw_ip = ETH_FRAME[14:]
    data = _two_interface_file(ETH_FRAME, raw_ip, linktype1=LINKTYPE_RAW, options1=opts(opt(9, bytes([9]))))
    path = tmp_path / "mixed.pcapng"
    path.write_bytes(data)
    (o0, p0), (o1, p1) = _index(data)
    # the caller's hint (a single link type for the whole file) does not override the packet's own interface
    back0 = pcapng.read_packet_at(path, o0, linktype=LINKTYPE_RAW)
    back1 = pcapng.read_packet_at(path, o1, linktype=1)
    assert back0["linktype"] == 1 and back0["ts"] == pytest.approx(TS / 1e6)
    assert back1["linktype"] == LINKTYPE_RAW and back1["ts"] == pytest.approx((TS + 1) / 1e9), "nanosecond IDB"
    assert back0 == p0 and back1 == p1


def test_a_big_endian_file_reads_back_without_the_caller_naming_its_byte_order(tmp_path):
    data = _two_interface_file(ETH_FRAME, ETH_FRAME, endian=">")
    path = tmp_path / "be.pcapng"
    path.write_bytes(data)
    assert [pcapng.read_packet_at(path, o) for o, _p in _index(data)] == [p for _o, p in _index(data)]


def test_a_second_section_uses_its_own_interface_table(tmp_path):
    first = shb() + idb(1) + epb(ETH_FRAME, ts=TS)
    second = shb(">") + idb(LINKTYPE_RAW, endian=">") + idb(1, endian=">") + epb(ETH_FRAME, interface=1, ts=TS, endian=">")
    data = first + second
    path = tmp_path / "two-sections.pcapng"
    path.write_bytes(data)
    indexed = _index(data)
    assert [pcapng.read_packet_at(path, o) for o, _p in indexed] == [p for _o, p in indexed]


def test_an_offset_inside_a_block_is_still_no_packet(tmp_path):
    data = _two_interface_file(ETH_FRAME, ETH_FRAME)
    path = tmp_path / "x.pcapng"
    path.write_bytes(data)
    (o0, _p0), (o1, _p1) = _index(data)
    assert pcapng.read_packet_at(path, o0 + 4) is None and pcapng.read_packet_at(path, o1 + 8) is None


def test_a_file_that_grows_reads_back_its_new_packets(tmp_path):
    # the live capture appends to the file it reads back from: a later packet (and a later IDB) must be found
    path = tmp_path / "live.pcapng"
    data = shb() + idb(1) + epb(ETH_FRAME, ts=TS)
    path.write_bytes(data)
    (o0, p0), = _index(data)
    assert pcapng.read_packet_at(path, o0) == p0
    data += idb(LINKTYPE_RAW) + epb(ETH_FRAME[14:], interface=1, ts=TS + 5)
    path.write_bytes(data)
    indexed = _index(data)
    assert [pcapng.read_packet_at(path, o) for o, _p in indexed] == [p for _o, p in indexed]


def test_a_file_replaced_at_the_same_path_is_read_afresh(tmp_path):
    path = tmp_path / "reused.pcapng"
    first = _two_interface_file(ETH_FRAME, ETH_FRAME)
    path.write_bytes(first)
    for o, p in _index(first):
        assert pcapng.read_packet_at(path, o) == p
    second = shb() + idb(LINKTYPE_RAW) + epb(ETH_FRAME[14:], ts=TS)
    path.unlink()
    path.write_bytes(second)
    (o, p), = _index(second)
    assert pcapng.read_packet_at(path, o) == p and p["linktype"] == LINKTYPE_RAW


def test_the_capture_detail_view_reads_a_packet_captured_on_the_second_interface(tmp_path):
    from test_capture import arp_frame, icmp_frame, make

    app = make(tmp_path)
    try:
        path = tmp_path / "Documents" / "all-interfaces.pcapng"
        path.parent.mkdir(parents=True)
        path.write_bytes(_two_interface_file(icmp_frame(), arp_frame()))
        session = app.mgr.open_path(str(path))
        assert session["state"] == "loaded" and session["packets"] == 2
        assert app.mgr.packet(1)["row"]["proto"] == "ICMP"
        assert app.mgr.packet(2)["row"]["proto"] == "ARP"
    finally:
        app.mgr.close(0.5)


@pytest.mark.parametrize("order", ["ethernet-first", "raw-ip-first"])
def test_the_capture_detail_view_dissects_each_packet_with_its_own_interfaces_link_type(tmp_path, order):
    # A Wireshark 'all interfaces' capture on a laptop with a VPN: Ethernet on one interface, raw IP on the other.
    # The capture page used to dissect every packet's detail with the LAST packet's link type, so the Ethernet
    # frame came out as 'Frame, Data' (read as raw IP) - a wrong protocol tree on a tool whose verdicts must be right.
    from test_capture import icmp_frame, make

    frame = icmp_frame()
    raw_ip = frame[14:]
    if order == "ethernet-first":
        data = (shb() + idb(1) + idb(LINKTYPE_RAW)
                + epb(frame, interface=0, ts=TS) + epb(raw_ip, interface=1, ts=TS + 1))
    else:
        data = (shb() + idb(LINKTYPE_RAW) + idb(1)
                + epb(raw_ip, interface=0, ts=TS) + epb(frame, interface=1, ts=TS + 1))
    app = make(tmp_path)
    try:
        path = tmp_path / "Documents" / "vpn-and-ethernet.pcapng"
        path.parent.mkdir(parents=True)
        path.write_bytes(data)
        session = app.mgr.open_path(str(path))
        assert session["state"] == "loaded" and session["packets"] == 2
        for number in (1, 2):
            detail = app.mgr.packet(number)
            names = [str(layer.get("name") or layer.get("title") or "") for layer in detail["layers"]]
            text = " ".join(names)
            assert detail["row"]["proto"] == "ICMP", f"packet {number} row"
            assert "IPv4" in text or "Internet Protocol" in text, f"packet {number} detail layers: {names}"
            assert "ICMP" in text, f"packet {number} detail layers: {names}"
    finally:
        app.mgr.close(0.5)



# =====================================================================================================================
# 3b. the TFTP server reads a failed enumeration the same way: no answer, not "the adapter is gone"
# =====================================================================================================================
@pytest.mark.parametrize("failure", ["raises", "empty-list"])
def test_one_failed_enumeration_does_not_stop_the_tftp_server_with_a_false_reason(tmp_path, monkeypatch, failure):
    # TFTP holds no NIC-restore record, so nothing is stranded; but "Ethernet is no longer present" in the status and
    # the event log would send a technician looking for a NIC that is still plugged in.
    import time as _time

    from tnt import tftp
    from test_tftp import Acl, nic

    monkeypatch.setattr(tftp, "_disk_free", lambda path: 1 << 40)
    adapters = [nic()]
    state = {"fail": False}

    def adapters_fn():
        if state["fail"]:
            if failure == "raises":
                raise OSError(1168, "GetAdaptersAddresses failed")
            return []
        return list(adapters)

    srv = tftp.TftpServer(None, Config(tmp_path / "config.json").load(), EventBus(), port=0, adapters_fn=adapters_fn,
                          root=tmp_path / "tftp", acl=Acl(), udp_owners_fn=lambda port: [])
    try:
        assert srv.start()["error"] is None
        state["fail"] = True
        srv.on_network_change({})
        _time.sleep(0.2)                                           # a stop would run on tnt-tftp-netstop
        assert srv.summary()["running"] is True and srv.status()["error"] is None
        # the next read answers and genuinely lacks the NIC: that is a removal, stopped with the true reason
        state["fail"] = False
        adapters[:] = [nic(name="Wi-Fi", index=22, if_type=71, ips=(("198.51.100.7", 24),), mac="02:00:5e:10:00:02")]
        srv.on_network_change({})
        end = _time.monotonic() + 5
        while srv.summary()["running"] and _time.monotonic() < end:
            _time.sleep(0.01)
        assert srv.status()["error"] == "stopped: Ethernet is no longer present"
    finally:
        srv.stop()
