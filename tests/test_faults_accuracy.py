"""Is the Faults tile right?  Regression tests from the 1.21.2 deep review.

The tile is a fault finder, so a verdict is only worth having if it is true: no false alarm on the
setups a technician actually runs (a docked laptop with Wi-Fi left on, a bench router on one NIC and
the office on the other, an IPv6-only network, a Dante bench), no fault missed because it started
after a long clean run, and no "clean" from a watch that could not read what it claims to have
checked.  Most scenarios here reproduced a wrong verdict before the fix; the rest pin what the fix
must keep (a real duplicate still caught, a VPN still quiet, Discovery's table unchanged).

Everything is driven through the watcher's seams or pure functions; the one native call that is
exercised (``GetIpNetTable2``) goes through a stand-in DLL.  Documentation addresses only.
"""
from __future__ import annotations

import ctypes
import ipaddress
import re
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Sequence

import pytest

from test_ui import _tile_body, browser_page, mock  # noqa: F401  (fixtures)
from tnt import arp, faults, netinfo, throughput
from tnt.engine import Engine

ROOT = Path(__file__).resolve().parent.parent

GW = "192.0.2.1"
M1 = "02:00:5E:10:00:01"
M2 = "02:00:5E:10:00:02"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def counters(luid: int = 1, *, name: str = "Ethernet", rx: int = 0, tx: int = 0, rx_errors: int = 0,
             tx_errors: int = 0, rx_discards: int = 0, tx_discards: int = 0) -> throughput.Counters:
    return throughput.Counters(luid=luid, index=12, name=name, description="Intel(R) I219-V", if_type=6,
                               link_bps=1_000_000_000, rx_bytes=rx * 900, tx_bytes=tx * 200,
                               rx_packets=rx, tx_packets=tx, rx_errors=rx_errors, tx_errors=tx_errors,
                               rx_discards=rx_discards, tx_discards=tx_discards)


class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now


class Bus:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def publish(self, event_type: str, data: Any = None) -> None:
        self.events.append({"type": event_type, "data": data})


class Link:
    """One adapter's running counter totals, and a real FaultWatcher reading them every TICK_S the
    way the service thread does.  ``fail`` makes the next reads raise (an exception) or come back
    with nothing on them (an empty list); ``down`` leaves this adapter off a reading that still lists
    the ``others``, which is how a good reading says an adapter went."""

    def __init__(self, *, adapters: Sequence[Dict[str, Any]] = (), arp_fn: Any = None,
                 gateway: Optional[str] = None, bus: Any = None, others: Sequence[Any] = ()) -> None:
        self.clock = FakeClock()
        self.c: Dict[str, int] = dict(rx=0, tx=0, rx_errors=0, tx_errors=0, rx_discards=0, tx_discards=0)
        self.fail: Any = None
        self.down = False
        self.others = list(others)
        self.w = faults.FaultWatcher(bus, clock=self.clock, reader=self._read,
                                     adapters_fn=lambda: [dict(a) for a in adapters],
                                     arp_fn=arp_fn or (lambda: {}), gateway_fn=lambda: gateway)

    def _read(self) -> List[Any]:
        if isinstance(self.fail, BaseException):
            raise self.fail
        if self.fail is not None:
            return list(self.fail)
        return ([] if self.down else [counters(**self.c)]) + self.others

    def tick(self) -> None:
        self.w.tick()

    def run(self, seconds: float, *, rx_pps: float = 0.0, tx_pps: float = 0.0, error_rate: float = 0.0,
            rx_discards_s: float = 0.0, tx_discard_rate: float = 0.0) -> None:
        for _ in range(int(round(seconds / faults.TICK_S))):
            self.clock.now += faults.TICK_S
            rx, tx = int(rx_pps * faults.TICK_S), int(tx_pps * faults.TICK_S)
            self.c["rx"] += rx
            self.c["tx"] += tx
            self.c["rx_errors"] += int(round(rx * error_rate))
            self.c["rx_discards"] += int(round(rx_discards_s * faults.TICK_S))
            self.c["tx_discards"] += int(round(tx * tx_discard_rate))
            self.w.tick()

    @property
    def level(self) -> str:
        return self.w.view()["level"]

    @property
    def ids(self) -> List[str]:
        return [f["id"] for f in self.w.view()["findings"]]


def v4(address: str, prefix: int, dad: int = netinfo.IP_DAD_STATE_PREFERRED) -> netinfo.IpAddr:
    return netinfo._make_ipaddr(address, 4, prefix, dad, 0)


def v6(address: str, prefix: int = 64, *, scope: int = 0, prefix_origin: int = 4, suffix_origin: int = 4) -> netinfo.IpAddr:
    return netinfo._make_ipaddr(address, 6, prefix, netinfo.IP_DAD_STATE_PREFERRED, scope, prefix_origin, suffix_origin)


def nic(index: int = 12, name: str = "Ethernet", **over: Any) -> netinfo.Adapter:
    """A real netinfo.Adapter; ``is_physical`` is worked out from the type and description the way
    GetAdaptersAddresses parsing does it, unless the test says otherwise."""
    base: Dict[str, Any] = dict(
        index=index, name=name, description="Intel(R) Ethernet Connection I219-LM", mac="00:00:5E:00:53:10",
        if_type=6, type_name="Ethernet", status="up", speed_bps=1_000_000_000, mtu=1500,
        dhcp_enabled=True, dhcp_server=GW, dns_suffix="", ipv4=[v4("192.0.2.40", 24)], ipv6=[],
        gateways=[GW], dns=[GW], metric_v4=25, is_loopback=False)
    base.update(over)
    if "is_physical" not in over:
        base["is_physical"] = netinfo._is_physical(int(base["if_type"]), str(base["description"]))
    base["type_name"] = netinfo.IF_TYPE_NAMES.get(int(base["if_type"]), "Other")
    return netinfo.Adapter(**base)


def snapshot_rows(adapters: List[netinfo.Adapter], internet_index: Optional[int]) -> List[Dict[str, Any]]:
    """The adapter rows exactly as netinfo_snapshot() hands them to the fault watch."""
    rows = []
    for a in adapters:
        row = a.to_dict()
        row["warnings"] = netinfo.adapter_warnings(a, adapters, internet_index)
        rows.append(row)
    return rows


def codes(adapter: netinfo.Adapter, *args: Any) -> List[str]:
    return [w["code"] for w in netinfo.adapter_warnings(adapter, *args)]


# =========================================================================================
# 1. errors and discards are graded on the last few minutes, not on the whole watch
# =========================================================================================
def test_a_fault_that_starts_after_a_clean_day_is_graded_on_its_own_rate():
    """After a clean day (5 M frames) a cable going bad at a 10 % error rate read as 0.01 % of the
    watch, and needed tens of millions more damaged frames to reach "bad".  Graded on the recent
    window, it is a fault within a minute however long TNT has been watching."""
    link = Link()
    link.tick()
    link.run(24 * 3600, rx_pps=60)
    assert link.level == "good" and link.ids == ["fault.clean"]
    link.run(faults.TICK_S, rx_pps=100, error_rate=0.10)
    assert link.level in ("warn", "bad"), "one tick of a 10 % error rate is already worth saying"
    link.run(60, rx_pps=100, error_rate=0.10)
    view = link.w.view()
    assert view["level"] == "bad" and view["findings"][0]["id"] == "fault.errors"
    detail = view["findings"][0]["detail"]
    assert "in the last 5 minutes" in detail
    # the whole watch is still there, as labelled context rather than as the verdict
    assert "Since TNT started watching" in detail and "24 h 01 min" in detail
    row = view["nics"][0]
    assert row["window_s"] == pytest.approx(faults.RATE_WINDOW_S)
    assert row["recent_rx_errors"] == 650 and row["new_rx_errors"] == 650
    assert row["new_rx_packets"] > 5_000_000 > row["recent_rx_packets"]


def test_a_busy_pc_watched_for_days_still_calls_a_bad_link_bad():
    """Two busy days (345 M frames): ten minutes of a 10 % error rate used to be a grey note, and
    ten minutes of a fifth of all outgoing frames discarded was not reported at all."""
    link = Link()
    link.tick()
    link.run(2 * 24 * 3600, rx_pps=2000)
    link.run(600, rx_pps=100, error_rate=0.10)
    tile = link.w.tile()
    assert tile["level"] == "bad" and tile["bad"] == 1 and tile["headline"] == "Ethernet is seeing frame errors"
    link.run(600, rx_pps=100, tx_pps=100, tx_discard_rate=0.20)
    assert "fault.discards" in link.ids


def test_a_fault_that_was_fixed_clears_within_the_window():
    """900 errors in the first three minutes, the cable re-seated, and the tile used to stay yellow
    for hours: a tech could not confirm the fix.  Now it clears one window after the last error."""
    link = Link()
    link.tick()
    link.run(180, rx_pps=556, error_rate=0.009)
    assert link.level == "bad"
    link.run(faults.RATE_WINDOW_S - 60, rx_pps=300)
    assert link.level != "good", "the errors are still inside the window"
    link.run(60 + faults.TICK_S, rx_pps=300)
    assert link.level == "good" and link.ids == ["fault.clean"]
    row = link.w.view()["nics"][0]
    assert row["recent_rx_errors"] == 0 and row["new_rx_errors"] > 800, "the page still says it happened"
    # the tile's "clean for ..." is timed from when it turned clean, not from when the watch began
    tile = link.w.tile()
    assert tile["watched_s"] == pytest.approx(485.0) and tile["clean_s"] < faults.TICK_S + 1
    # and so does the clean result: "no frame errors" is a claim about the window, not the watch
    detail = link.w.view()["findings"][0]["detail"]
    assert detail.startswith("In the last 5 minutes: no frame errors, no frames dropped on the way out")
    assert f"Earlier in the 8 minutes TNT has been watching there were {row['new_rx_errors']:,} frame errors" in detail


def test_errors_too_few_frames_to_judge_are_named_and_never_called_clean():
    """Two errors in the first seventy seconds of an idle link are two out of seventy-odd frames:
    too few to make a ratio of, over the window or the whole watch.  Not judged is not denied - and
    it is not "clean" either: the tile says it is still watching, and the page names the errors.

    (This pinned a green "clean" once.  The second review showed where that goes: a link three parts
    errors on a bench laptop read "clean" for as long as anyone watched.)"""
    link = Link()
    link.tick()
    link.run(65, rx_pps=1)
    link.c["rx_errors"] += 2
    link.run(faults.TICK_S, rx_pps=1)
    view, tile = link.w.view(), link.w.tile()
    assert view["nics"][0]["new_rx_packets"] < faults.MIN_PACKETS
    [found] = view["findings"]
    assert found["id"] == "fault.watching" and found["level"] == "info"
    assert found["title"] == "Frame errors seen, not judged yet"
    assert "2 frame errors on too little traffic to judge yet" in found["detail"]
    assert "no frame errors" not in found["detail"]
    assert tile["level"] == "info" and tile["clean_s"] is None
    # on an adapter that came up a moment ago the reason is the time, not the traffic
    link = Link()
    link.tick()
    link.run(120)
    link.others = [counters(2, name="Wi-Fi", rx=100_000)]                 # Wi-Fi connects
    link.run(faults.TICK_S)
    link.others = [counters(2, name="Wi-Fi", rx=200_000, rx_errors=3)]
    link.run(faults.TICK_S)
    [found] = link.w.view()["findings"]
    assert found["id"] == "fault.watching"
    assert "3 frame errors on an adapter that came up under 60 seconds ago" in found["detail"]


def test_the_errors_of_one_site_do_not_follow_the_tech_to_the_next():
    """A bad patch lead at site A, six hours asleep in the bag, then site B on the same NIC with its
    counters kept: site B's cabling used to be blamed for site A's errors for millions of frames."""
    link = Link()
    link.tick()
    link.run(4 * 3600, rx_pps=10, error_rate=0.02)
    assert link.level == "bad", "site A really is faulty"
    link.clock.now += 6 * 3600                       # asleep: no ticks, nothing counted
    link.run(10 * 60, rx_pps=100)
    assert link.level == "good" and link.ids == ["fault.clean"]
    detail = link.w.view()["findings"][0]["detail"]
    assert "In the last 5 minutes: no frame errors" in detail and "Earlier in the" in detail, "site A is context"


# =========================================================================================
# 2. a read that failed says nothing about the adapters, and must not clear a fault
# =========================================================================================
@pytest.mark.parametrize("failure", [OSError(8, "GetIfTable2 failed"), []], ids=["read-raises", "read-comes-back-empty"])
def test_one_failed_counter_read_keeps_the_fault_and_the_baseline(failure):
    """A failed read (or one with no adapter up on it, as on the first tick after a resume) used to
    delete every baseline: the red tile went green, and the new baseline already held the errors."""
    bus = Bus()
    link = Link(bus=bus)
    link.tick()
    link.run(60, rx_pps=1700, error_rate=0.009)
    assert link.level == "bad"
    link.fail = failure
    link.run(faults.TICK_S)
    view, tile = link.w.view(), link.w.tile()
    assert view["level"] == "bad", "a read that failed cleared nothing"
    assert [n["name"] for n in view["nics"]] == ["Ethernet"], "the baseline and its history are kept"
    assert tile["reason"] and "interface counters" in tile["reason"]
    link.fail = None
    link.run(2 * faults.TICK_S, rx_pps=1700)
    assert link.level == "bad", "the errors are still inside the window, and still counted"
    assert link.w.tile()["reason"] is None
    assert [e["data"]["level"] for e in bus.events] == ["info", "bad"], "never a false all-clear"


def test_an_adapter_that_goes_away_on_a_good_read_is_still_forgotten():
    """A reading that worked and lists the other adapters is what says an adapter went: it is marked
    down at once, and forgotten when its window has nothing left in it."""
    clock = FakeClock()
    rows = {"now": [counters(1, name="Ethernet"), counters(2, name="Wi-Fi")]}
    w = faults.FaultWatcher(None, clock=clock, reader=lambda: list(rows["now"]), adapters_fn=lambda: [],
                            arp_fn=lambda: {}, gateway_fn=lambda: None)
    w.tick()
    rows["now"] = []
    clock.now += faults.TICK_S
    w.tick()
    assert [(n["name"], n["up"]) for n in w.view()["nics"]] == [("Ethernet", True), ("Wi-Fi", True)], \
        "an empty read is not a removal"
    rows["now"] = [counters(1, name="Ethernet")]
    clock.now += faults.TICK_S
    w.tick()
    assert [(n["name"], n["up"]) for n in w.view()["nics"]] == [("Ethernet", True), ("Wi-Fi", False)]
    clock.now += faults.RATE_WINDOW_S
    w.tick()
    assert [n["name"] for n in w.view()["nics"]] == ["Ethernet"]


def test_a_fault_does_not_outlive_the_window_while_the_counters_cannot_be_read():
    """Kept through a failed read is not kept for ever: an hour with nothing up is not "the last five
    minutes" of anything.  The fault goes when its window does, and the tile says it is watching
    and what it could not read, not that the network is clean."""
    link = Link()
    link.tick()
    link.run(120, rx_pps=1700, error_rate=0.009)
    assert link.level == "bad"
    link.fail = []                                     # every adapter down: the laptop is in the bag
    link.run(faults.RATE_WINDOW_S - 30)
    assert link.level == "bad", "still inside the window of the last good reading"
    link.run(60)
    view, tile = link.w.view(), link.w.tile()
    assert [f["id"] for f in view["findings"]] == ["fault.clean"] and view["level"] == "info"
    assert tile["level"] == "info" and "no adapter is up" in tile["reason"]
    assert view["nics"][0]["new_rx_errors"] > 0, "what the watch saw is still on the page"


def test_a_link_that_keeps_dropping_is_still_judged():
    """A bad cable makes a link drop and come back.  Starting the adapter afresh at each return,
    with MIN_WATCH_S applied per adapter, meant a link that dropped every half minute was never old
    enough to be judged at all; it carries on where it left off instead."""
    link = Link(others=[counters(2, name="Wi-Fi")])
    link.tick()
    for _ in range(6):
        link.run(25, rx_pps=400, error_rate=0.02)
        link.down = True
        link.run(faults.TICK_S)
        link.down = False
    link.run(faults.TICK_S, rx_pps=400, error_rate=0.02)
    assert "fault.errors" in link.ids and link.level == "bad"
    [row] = [n for n in link.w.view()["nics"] if n["name"] == "Ethernet"]
    assert row["watched_s"] > faults.MIN_WATCH_S and row["new_rx_errors"] > 1000
    # gone for longer than a window, it is a new adapter when it returns
    link.down = True
    link.run(faults.RATE_WINDOW_S + faults.TICK_S)
    link.down = False
    link.run(faults.TICK_S, rx_pps=400)
    [row] = [n for n in link.w.view()["nics"] if n["name"] == "Ethernet"]
    assert row["watched_s"] == 0 and row["new_rx_errors"] == 0


@pytest.mark.parametrize("blind, claim", [("counters", "no frame errors"),
                                          ("arp", "no address answered by two devices"),
                                          ("adapters", "every adapter addressed properly")])
def test_the_page_never_claims_a_check_it_could_not_make(blind, claim):
    """"No faults found ... and no address answered by two devices" while the ARP table had never
    once been read.  A source that could not be read is named, and its check is not claimed."""
    def boom() -> Any:
        raise OSError("simulated failure")

    clock = FakeClock()
    w = faults.FaultWatcher(
        None, clock=clock,
        reader=boom if blind == "counters" else (lambda: [counters(rx=100_000)]),
        adapters_fn=boom if blind == "adapters" else (lambda: [{"name": "Ethernet", "status": "up", "warnings": []}]),
        arp_fn=boom if blind == "arp" else (lambda: {GW: M1}),
        gateway_fn=lambda: GW)
    w.tick()
    clock.now += 2 * 3600.0
    w.tick()
    view, tile = w.view(), w.tile()
    [finding] = view["findings"]
    assert finding["id"] == "fault.clean"
    assert claim not in finding["detail"] and "could not be read" in finding["detail"]
    assert finding["level"] != "good" and tile["level"] != "good", "a partial look is not a clean bill"
    assert tile["reason"] == view["note"] and "simulated" not in tile["reason"]


# =========================================================================================
# 3. the tile: never "clean" while something could not be read (headless browser, the mock)
# =========================================================================================
def test_the_faults_tile_never_says_clean_while_something_could_not_be_read(browser_page, mock, monkeypatch):
    # a fake site with nothing wrong on it (its bad patch lead and busy uplink taken away), so the
    # only thing between the tile and "clean" is what could not be read
    monkeypatch.setattr(mock.mod, "FAULT_ERROR_NIC", "")
    monkeypatch.setattr(mock.mod, "FAULT_DISCARD_NIC", "")
    mock.state.faults_since = time.time() - 7200
    mock.state.faults_reason = "ARP table: OSError"
    try:
        tile = _tile_body(browser_page(""), "faults")
    finally:
        mock.state.faults_reason = None
    assert "badge green" not in tile and ">clean<" not in tile
    assert '<span class="badge grey">watching</span>' in tile
    assert "ARP table: OSError" in tile
    assert "for 2h" not in tile, "a duration here would be the claim this tile cannot make"


def test_a_tile_that_just_turned_clean_does_not_claim_the_whole_watch(browser_page, mock, monkeypatch):
    """The levels follow the last five minutes, so a tile can be red at noon and clean at 12:06: it
    is clean for six minutes, not for the two hours TNT has been watching."""
    now = time.time()
    monkeypatch.setattr(mock.state, "faults_tile", lambda: {
        "available": True, "reason": None, "level": "good", "bad": 0, "warn": 0, "headline": "No faults found",
        "watched_s": 7200.0, "clean_s": 360.0, "ts": now})
    tile = _tile_body(browser_page(""), "faults")
    assert '<span class="badge green">clean</span> <span class="muted">for 6m 00s</span>' in tile
    assert "for 2h" not in tile


def test_a_fault_on_the_tile_keeps_what_could_not_be_read_in_reach(browser_page, mock):
    mock.state.faults_since = time.time() - 900
    now = time.time()
    for i in range(40):
        mock.state.throughput_tick(now - 39 + i)
    mock.state.faults_reason = "ARP table: OSError"
    try:
        tile = _tile_body(browser_page(""), "faults")
    finally:
        mock.state.faults_reason = None
    assert re.search(r'<span class="badge red">\d+ faults?</span>', tile)
    assert "Ethernet 2 is seeing frame errors" in tile
    assert re.search(r'title="[^"]*ARP table: OSError', tile), "the reason is on the tile, in its tooltip"


def test_the_network_info_tile_shows_no_badge_for_an_informational_warning(browser_page, mock):
    """The mock's office LAN puts multiple_default_gateways on the internet adapter: grey on the
    adapter card, and nothing at all on the tile, whose badge is for something to act on."""
    tile = _tile_body(browser_page(""), "ipinfo")
    assert "internet</span>" in tile
    assert "multiple gateways" not in tile and "badge grey" not in tile and "badge yellow" not in tile


def test_the_network_info_tile_shows_the_address_that_works_on_an_ipv6_only_network(browser_page, mock, monkeypatch):
    """IPv4 self-assigned, IPv6 carrying everything: the tile used to show 169.254.23.45 as the
    internet adapter's address."""
    monkeypatch.setattr(mock.mod, "net_status_nic", lambda prof: {
        "index": 7, "name": "Wi-Fi", "description": "Intel(R) Wi-Fi 6E AX211 160MHz", "type_name": "Wi-Fi",
        "ipv4": "169.254.23.45", "network": "169.254.0.0/16", "ipv6": "2001:db8:77::1a2b:3c4d:5e6f:7a8b",
        "gateway": "fe80::1%7", "mac": "00:00:5E:00:53:07", "warnings": ["apipa_ipv6"]})
    tile = _tile_body(browser_page(""), "ipinfo")
    assert "2001:db8:77::1a2b:3c4d:5e6f:7a8b" in tile and "IPv6</span>" in tile
    assert "169.254.23.45" not in tile
    assert re.search(r'<span class="badge yellow"[^>]*>IPv4 self-assigned</span>', tile)


# =========================================================================================
# 4. a Stale neighbour row read again is not a device answering again
# =========================================================================================
def test_a_stale_row_that_is_read_again_is_not_a_fresh_answer():
    """Windows keeps a Stale row until the next device answers, and TNT reads it every five
    seconds: stamping each read as an answer made every lease change a two-minute duplicate."""
    watch = faults.ArpWatch(window_s=faults.ARP_WINDOW_S)
    t = 1000.0
    watch.observe([("192.0.2.77", 11, M1, "reachable")], t)
    for _ in range(720):                                   # an hour of the same Stale row
        t += faults.TICK_S
        watch.observe([("192.0.2.77", 11, M1, "stale")], t)
    watch.observe([("192.0.2.77", 11, M2, "reachable")], t + faults.TICK_S)
    assert watch.conflicts() == []
    # a plain {ip: mac} reading (no state) is judged the same way: a re-read is not an answer
    plain = faults.ArpWatch(window_s=faults.ARP_WINDOW_S)
    for i in range(720):
        plain.observe({"192.0.2.77": M1}, 1000.0 + faults.TICK_S * i)
    plain.observe({"192.0.2.77": M2}, 1000.0 + faults.TICK_S * 720)
    assert plain.conflicts() == []


def test_a_row_first_seen_stale_is_not_counted_as_an_answer():
    """TNT cannot know when a row it finds Stale last answered, so it does not guess 'just now'."""
    watch = faults.ArpWatch()
    watch.observe([("192.0.2.77", 11, M1, "stale")], 1000.0)
    watch.observe([("192.0.2.77", 11, M2, "reachable")], 1010.0)
    assert watch.conflicts() == []


def test_two_devices_that_really_answer_inside_the_window_are_still_caught():
    watch = faults.ArpWatch()
    watch.observe([("192.0.2.77", 11, M1, "reachable")], 1000.0)
    watch.observe([("192.0.2.77", 11, M2, "reachable")], 1030.0)
    assert watch.conflicts() == [{"ip": "192.0.2.77", "if_index": 11, "macs": [M1, M2], "seen": 2}]
    # the cache flipping to the other MAC is that MAC answering, whatever state the row is in now
    flip = faults.ArpWatch()
    flip.observe([("192.0.2.77", 11, M1, "reachable")], 1000.0)
    flip.observe([("192.0.2.77", 11, M2, "stale")], 1030.0)
    assert [c["macs"] for c in flip.conflicts()] == [[M1, M2]]
    found = faults.arp_findings(watch.conflicts())
    assert found[0]["id"] == "fault.arp" and "answered for 192.0.2.77" in found[0]["detail"]
    assert "within 2 minutes" in found[0]["detail"]


def test_a_router_swap_is_not_reported_as_a_duplicate_gateway():
    """The tech replaces the router: the old one's row sits Stale for an hour, then the new one
    answers.  That used to be a red 'The default gateway has answered from two MAC addresses'."""
    table = {"rows": [(GW, 11, M1, "reachable")]}
    link = Link(arp_fn=lambda: list(table["rows"]), gateway=GW)
    link.tick()
    table["rows"] = [(GW, 11, M1, "stale")]
    link.run(3600, rx_pps=100)
    table["rows"] = [(GW, 11, M2, "reachable")]
    link.run(faults.TICK_S, rx_pps=100)
    view = link.w.view()
    assert view["note"] is None and view["arp"]["tracked"] == 1, "the neighbour rows were read"
    assert link.ids == ["fault.clean"]


# =========================================================================================
# 5. the same address on two interfaces is two networks, not a duplicate
# =========================================================================================
IF_ETH, IF_WIFI = 13, 11
STATE = {"probe": 2, "delay": 3, "stale": 4, "reachable": 5}


def _fake_neighbour_dll(rows):
    """iphlpapi's GetIpNetTable2, answering IPv4 rows of (interface index, ip, MAC hex, state name)."""

    class FakeDll:
        def GetIpNetTable2(self, family, out_ptr):
            self.keep = ctypes.create_string_buffer(arp._ROWS_OFFSET + ctypes.sizeof(arp.MIB_IPNET_ROW2) * len(rows))
            base = ctypes.addressof(self.keep)
            ctypes.c_ulong.from_address(base).value = len(rows)
            for row, (index, ip, mac, state) in zip((arp.MIB_IPNET_ROW2 * len(rows)).from_address(base + arp._ROWS_OFFSET), rows):
                row.Address.si_family = arp.AF_INET
                row.Address.Ipv4.sin_addr[:] = list(ipaddress.IPv4Address(ip).packed)
                row.InterfaceIndex = index
                row.PhysicalAddress[:6] = list(bytes.fromhex(mac.replace(":", "")))
                row.PhysicalAddressLength = 6
                row.State = STATE[state]
            out_ptr._obj.value = base
            return 0

        def FreeMibTable(self, table):
            pass

    return FakeDll()


@pytest.fixture
def two_networks(monkeypatch):
    """Ethernet (13) on a bench router and Wi-Fi (11) on the office network, both up, both numbered
    the same and both with their router at 192.0.2.1.  ``table["rows"]`` is what the DLL answers."""
    adapters = [SimpleNamespace(index=IF_ETH, is_up=True), SimpleNamespace(index=IF_WIFI, is_up=True)]
    monkeypatch.setattr(netinfo, "get_adapters", lambda include_down=True, include_loopback=False: list(adapters))
    table: Dict[str, Any] = {"rows": []}
    monkeypatch.setattr(arp, "_dll", lambda: _fake_neighbour_dll(table["rows"]))
    return table


def _real_arp_watcher() -> "tuple[faults.FaultWatcher, FakeClock]":
    """A watcher whose ARP read is the real one (``arp_fn`` left unset), the rest seamed."""
    clock = FakeClock()
    n = {"rx": 0}

    def reader() -> List[Any]:
        n["rx"] += 500
        return [counters(rx=n["rx"])]

    w = faults.FaultWatcher(None, clock=clock, reader=reader, adapters_fn=lambda: [], gateway_fn=lambda: GW)
    return w, clock


def test_the_same_router_address_on_two_networks_is_not_a_duplicate_gateway(two_networks):
    """get_arp_table_native keeps one MAC per address across every interface, best state winning,
    so as the active row cycled reachable -> stale -> delay -> probe the other network's router
    won now and then, and the tile went red with a duplicate gateway on a healthy bench."""
    w, clock = _real_arp_watcher()
    cycle = ["reachable", "stale", "delay", "probe", "reachable", "stale", "delay", "probe"]
    for i, state in enumerate(cycle * 4):
        two_networks["rows"] = [(IF_ETH, GW, M1, state), (IF_WIFI, GW, M2, "stale" if i else "reachable")]
        w.tick()
        clock.now += faults.TICK_S
    assert w.view()["arp"]["conflicts"] == []
    assert "fault.gateway" not in [f["id"] for f in w.view()["findings"]]


def test_a_second_mac_on_the_same_interface_is_still_a_duplicate_gateway(two_networks):
    w, clock = _real_arp_watcher()
    two_networks["rows"] = [(IF_ETH, GW, M1, "reachable"), (IF_WIFI, GW, M2, "stale")]
    w.tick()
    clock.now += 30.0
    two_networks["rows"] = [(IF_ETH, GW, "02:00:5E:10:00:99", "reachable"), (IF_WIFI, GW, M2, "stale")]
    w.tick()
    found = w.view()["findings"]
    assert found[0]["id"] == "fault.gateway" and found[0]["level"] == "bad"
    assert found[0]["evidence"][0]["if_index"] == IF_ETH


def test_discovery_keeps_its_one_mac_per_address_table(two_networks):
    """Discovery, reports and Pro AV read get_arp_table_native's {ip: mac}; that contract stays."""
    two_networks["rows"] = [(IF_ETH, GW, M1, "stale"), (IF_WIFI, GW, M2, "reachable"),
                            (IF_ETH, "192.0.2.10", "02:00:5E:10:00:0A", "reachable")]
    table = arp.get_arp_table_native()
    assert table == {GW: M2, "192.0.2.10": "02:00:5E:10:00:0A"}


# =========================================================================================
# 6. a docked laptop with Wi-Fi left on is not a fault
# =========================================================================================
def _docked(wifi_ipv4: str = "192.0.2.23", wifi_prefix: int = 24, wifi_gateway: str = GW) -> List[netinfo.Adapter]:
    eth = nic(12, "Ethernet", metric_v4=25)
    wifi = nic(10, "Wi-Fi", if_type=71, description="Intel(R) Wi-Fi 6E AX211 160MHz", mac="00:00:5E:00:53:0A",
               ipv4=[v4(wifi_ipv4, wifi_prefix)], gateways=[wifi_gateway], dns=[wifi_gateway], metric_v4=50)
    return [eth, wifi]


def test_a_docked_laptop_with_wifi_left_on_is_clean():
    """The most common laptop a tech runs TNT on.  The adapter card keeps its grey note; the tile is
    green, because yellow that never goes away teaches the tech to ignore yellow."""
    adapters = _docked()
    rows = snapshot_rows(adapters, 12)
    assert [w["code"] for w in rows[0]["warnings"]] == ["multiple_default_gateways"], "still on the adapter card"
    assert faults.address_findings(rows) == []
    link = Link(adapters=rows)
    link.tick()
    link.run(faults.MIN_WATCH_S + faults.TICK_S, rx_pps=100)
    assert link.ids == ["fault.clean"] and link.w.tile()["level"] == "good"


def test_the_second_gateway_message_says_whether_it_is_the_same_router():
    """netinfo never compared the two gateway addresses: one router reached two ways and a real
    second router read the same.  An address cannot prove two boxes are one (a bench router at its
    factory address beside an office network numbered alike), so the same-router case says so."""
    same = _docked()
    [message] = [w["message"] for w in netinfo.adapter_warnings(same[0], same, 12)]
    assert message == ("Wi-Fi also has a default gateway: the same address on the same subnet (192.0.2.1), "
                       "most likely the same router; Windows sends traffic through the one with the lowest metric")
    other = _docked("198.51.100.20", 24, "198.51.100.1")
    [message] = [w["message"] for w in netinfo.adapter_warnings(other[0], other, 12)]
    assert "a different router (198.51.100.1)" in message
    # the same address on another subnet is not evidence of the same router
    lookalike = _docked("198.51.100.20", 24, GW)
    [message] = [w["message"] for w in netinfo.adapter_warnings(lookalike[0], lookalike, 12)
                 if w["code"] == "multiple_default_gateways"]
    assert "the same address (192.0.2.1) on another subnet, so possibly another router" in message
    assert "same router" not in message


def test_a_real_warning_is_not_hidden_behind_the_docked_laptop():
    """A gateway outside Wi-Fi's subnet used to share its colour and title with the harmless second
    gateway; now it is the only thing the finding is about."""
    adapters = _docked("192.0.2.200", 25, GW)          # 192.0.2.128/25: the gateway is outside it
    found = faults.address_findings(snapshot_rows(adapters, 12))
    assert [(f["id"], f["level"]) for f in found] == [("fault.address", "warn")]
    assert "Gateway 192.0.2.1 is outside" in found[0]["detail"]
    assert "also has a default gateway" not in found[0]["detail"]


# =========================================================================================
# 7. a self-assigned IPv4 address: an IPv6-only network, and a link-local AV bench
# =========================================================================================
def _ipv6_only_wifi() -> netinfo.Adapter:
    """DHCPv4 never answers (by design), SLAAC gave a global address, the router is fe80::1."""
    return nic(7, "Wi-Fi", if_type=71, description="Intel(R) Wi-Fi 6E AX211 160MHz", dhcp_server=None,
               ipv4=[v4("169.254.23.45", 16)],
               ipv6=[v6("fe80::1234:5678:9abc:def0", scope=7, prefix_origin=2),
                     v6("2001:db8:77::1a2b:3c4d:5e6f:7a8b"),
                     v6("2001:db8:77::9f8e:7d6c:5b4a:3928", 128, suffix_origin=5)],      # an RFC 4941 temporary
               gateways=["fe80::1%7"], dns=["2001:db8:77::53"], metric_v4=50)


def test_an_ipv6_only_network_is_not_an_adapter_without_an_address():
    """The same code as a dead DHCP server, graded red 'An adapter has no usable address' while the
    browser, the IPv6 pings and the gateway all worked."""
    wifi = _ipv6_only_wifi()
    warnings = netinfo.adapter_warnings(wifi, [wifi], 7)
    assert [w["code"] for w in warnings] == ["apipa_ipv6"]
    assert "IPv6 works" in warnings[0]["message"] and "169.254.23.45" in warnings[0]["message"]
    rows = snapshot_rows([wifi], 7)
    [found] = faults.address_findings(rows)
    assert found["level"] == "warn" and "no usable address" not in found["title"]
    link = Link(adapters=rows)
    link.tick()
    tile = link.w.tile()
    assert tile["level"] == "warn" and tile["headline"] == "An adapter's address configuration needs a look"
    # a DHCP server that did not answer on a network without IPv6 is still the plain, red case
    plain = nic(12, "Ethernet", ipv4=[v4("169.254.10.20", 16)], gateways=[], dns=[], dhcp_server=None)
    assert codes(plain) == ["apipa"]
    assert faults.address_findings(snapshot_rows([plain], None))[0]["level"] == "bad"


def test_a_link_local_av_bench_is_described_honestly():
    """A laptop plugged into a Dante switch with no DHCP server has a 169.254 address on purpose,
    and it is usable on that link.  The finding says what it is rather than 'no usable address'."""
    wifi = nic(7, "Wi-Fi", if_type=71, description="Intel(R) Wi-Fi 6E AX211 160MHz", ipv4=[v4("192.0.2.23", 24)])
    eth = nic(12, "Ethernet", ipv4=[v4("169.254.77.8", 16)], gateways=[], dns=[], dhcp_server=None)
    [found] = faults.address_findings(snapshot_rows([wifi, eth], 7))
    assert found["title"] == "An adapter has only a self-assigned address"
    assert "no usable address" not in found["title"]
    assert "Dante" in found["advice"] and "169.254" in found["advice"]


def test_the_status_brief_carries_the_global_ipv6_address():
    """status.netinfo.internet_nic: the tile needs the address that works, and it is the stable
    global one, not the link-local one or a temporary that rotates."""
    wifi = _ipv6_only_wifi()
    brief = Engine._nic_brief(netinfo, wifi, [wifi], 7)
    assert brief["ipv4"] == "169.254.23.45" and brief["warnings"] == ["apipa_ipv6"]
    assert brief["ipv6"] == "2001:db8:77::1a2b:3c4d:5e6f:7a8b"
    plain = nic()
    assert Engine._nic_brief(netinfo, plain, [plain], 12)["ipv6"] is None


def test_the_network_info_page_names_the_new_code():
    """ui/js/views/ipinfo.js labels the badge; an unknown code would get a yellow badge named
    'apipa ipv6', which is not a thing a technician should have to decode."""
    src = (ROOT / "ui" / "js" / "views" / "ipinfo.js").read_text(encoding="utf-8")
    assert "apipa_ipv6: ['yellow', 'IPv4 self-assigned']" in src
    pdf = (ROOT / "tnt" / "report_pdf.py").read_text(encoding="utf-8")
    assert '"apipa_ipv6":' in pdf


# =========================================================================================
# 8. a host mask on a real LAN adapter is the typo gateway_outside_subnet exists for
# =========================================================================================
@pytest.mark.parametrize("if_type, description, prefix", [
    (6, "Intel(R) Ethernet Connection I219-LM", 32),
    (6, "Intel(R) Ethernet Connection I219-LM", 31),
    (71, "Intel(R) Wi-Fi 6E AX211 160MHz", 32),
])
def test_a_host_mask_typed_on_a_real_lan_adapter_is_flagged(if_type, description, prefix):
    """255.255.255.255 typed for 255.255.255.0: the PC reaches the router by ARP and half works,
    and nothing else on the LAN answers.  The /31-/32 exemption was meant for tunnels only."""
    a = nic(if_type=if_type, description=description, dhcp_enabled=False, dhcp_server=None,
            ipv4=[v4("192.0.2.50", prefix)])
    assert a.is_physical
    assert codes(a) == ["gateway_outside_subnet"]
    assert f"192.0.2.50/{prefix}" in netinfo.adapter_warnings(a)[0]["message"]


@pytest.mark.parametrize("if_type, description", [
    (53, "Mullvad Tunnel"),
    (131, "Teredo Tunneling Pseudo-Interface"),
    (6, "TAP-Windows Adapter V9"),
    (6, "Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter for Windows x64"),
    (6, "PANGP Virtual Ethernet Adapter Secure"),
    (6, "Fortinet SSL VPN Virtual Ethernet Adapter"),
    (6, "SonicWall NetExtender Adapter"),
    (6, "Zscaler Network Adapter 1.0.2.0"),
    (6, "WireGuard Tunnel"),
    (6, "ZeroTier Virtual Port"),
    (6, "Hyper-V Virtual Ethernet Adapter"),
])
def test_a_vpn_addressed_as_a_host_route_stays_quiet(if_type, description):
    """Many corporate VPN clients present an Ethernet miniport (IfType 6), not a tunnel type, and
    address it /32 with the gateway outside: that must not bring back the 1.21.0 false alarm.  A
    virtual adapter (the Hyper-V one here) keeps the exemption too."""
    a = nic(30, "Ethernet 3", if_type=if_type, description=description, dhcp_enabled=False, dhcp_server=None,
            ipv4=[v4("198.51.100.55", 32)], gateways=["198.51.100.1"], dns=["198.51.100.53"])
    assert codes(a) == []


def test_a_point_to_point_31_with_its_gateway_inside_is_fine():
    a = nic(dhcp_enabled=False, dhcp_server=None, ipv4=[v4("192.0.2.1", 31)], gateways=["192.0.2.0"])
    assert codes(a) == []


def test_an_ethernet_miniport_vpn_holding_the_default_route_is_a_tunnel_too():
    """A full-tunnel VPN takes the default route by design, whatever IfType its driver reports."""
    eth = nic(12, "Ethernet")
    vpn = nic(30, "Ethernet 3", description="Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter for Windows x64",
              dhcp_enabled=False, dhcp_server=None, ipv4=[v4("198.51.100.55", 24)], gateways=["198.51.100.1"],
              dns=["198.51.100.53"], metric_v4=1)
    assert codes(vpn, [eth, vpn], 30) == []
    assert codes(eth, [eth, vpn], 12) == []


# =========================================================================================
# 9. discards: only the ones on the way out mean a full queue
# =========================================================================================
def _row(**kw: Any) -> Dict[str, Any]:
    row = {"name": "Ethernet", "description": "", "index": 12, "link_bps": 1_000_000_000, "watched_s": 600.0,
           "rx_errors": 0, "tx_errors": 0, "rx_discards": 0, "tx_discards": 0,
           "new_rx_errors": 0, "new_tx_errors": 0, "new_rx_discards": 0, "new_tx_discards": 0,
           "new_rx_packets": 0, "new_tx_packets": 0, "error_pct": None, "discard_pct": None}
    row.update(kw)
    return row


def test_inbound_discards_are_not_called_congestion():
    """Windows counts an arriving frame as discarded when nothing on this PC speaks its protocol or a
    filter drops it: this healthy desktop does it 6 to 120 times a second on a link that is never
    full.  On a quiet link that is a large share of what arrives, and it is not a fault."""
    assert faults.discard_findings([_row(new_rx_discards=2_000, new_rx_packets=10_000)]) == []
    link = Link()
    link.tick()
    link.run(3600, rx_pps=20, tx_pps=10, rx_discards_s=6.5)      # a quiet link: a third of arrivals discarded
    assert link.level == "good" and link.ids == ["fault.clean"]


def test_outbound_discards_are_a_full_send_queue():
    """The share is of the frames this PC queued to send.  (This once read "1,000 of the 100,000
    frames": MIB_IF_ROW2 counts only the frames transmitted without errors as OutUcastPkts, so a
    discarded frame is not among them and 1,000 discards beside 99,000 sent is 1,000 of 100,000.)"""
    [found] = faults.discard_findings([_row(new_tx_discards=1_000, new_tx_packets=99_000,
                                            new_rx_discards=50_000, new_rx_packets=100_000)])
    assert found["level"] == "warn"
    assert found["title"] == "Ethernet is dropping frames it could not send"
    assert "1,000 of the 100,000 frames this PC queued to send" in found["detail"]
    assert "send queue" in found["detail"] and "nowhere to put them" not in found["detail"]
    assert "congestion" in found["advice"].lower() and "on the way in" in found["advice"]
    assert found["evidence"] == [{"name": "Ethernet", "tx_discards": 1_000, "tx_packets": 99_000, "pct": 1.0,
                                  "level": "warn"}]
    assert faults.discard_findings([_row(new_tx_discards=6_000, new_tx_packets=94_000)])[0]["level"] == "bad"


def test_this_desktops_measured_counters_stay_clean():
    """Five minutes of this development desktop's real counters (read with read_counters, 5 s apart,
    nothing else kept): inbound discards in bursts of up to 1,735 per tick, none outbound, no errors.
    Replayed as they were, and again as if the link were almost idle - where the same discards would
    be most of what arrives, and grading them would call it "bad" - the tile stays clean."""
    for scale in (1.0, 0.0002):
        link = Link()
        link.tick()
        for rx, tx, rx_disc in MEASURED:
            link.c["rx"] += max(1, int(rx * scale))
            link.c["tx"] += max(1, int(tx * scale))
            link.c["rx_discards"] += rx_disc
            link.clock.now += faults.TICK_S
            link.tick()
        assert link.level == "good" and link.ids == ["fault.clean"], scale


# =========================================================================================
# second review: a link that is mostly errors, a link that keeps dropping, a clock set back
# =========================================================================================
def test_a_damaged_frame_is_a_frame_the_link_carried():
    """Windows counts only the frames received or sent *without errors* in InUcastPkts/OutUcastPkts
    (MIB_IF_ROW2), so a link that is mostly errors looked quiet: 900 damaged frames beside 300 good
    ones was "too little traffic to judge"."""
    [found] = faults.error_findings([_row(new_rx_errors=900, new_rx_packets=300)])
    assert found["level"] == "bad" and found["detail"].startswith("900 arriving damaged out of 1,200 frames")
    assert found["evidence"] == [{"name": "Ethernet", "rx_errors": 900, "tx_errors": 0, "pct": 75.0, "level": "bad"}]


def test_a_quiet_link_whose_errors_outnumber_its_good_frames_is_not_clean():
    """A bench laptop on a bad lead to one device: one good frame a second and three damaged ones.
    The window counted only the good frames, found 300 in five minutes, judged nothing, and the tile
    stayed a green "clean" for as long as anyone watched."""
    link = Link()
    link.tick()
    levels = []
    for _ in range(16 * 12):
        link.run(faults.TICK_S, rx_pps=1, error_rate=3.0)
        levels.append(link.w.tile()["level"])
    assert "good" not in levels
    view = link.w.view()
    assert view["level"] == "bad" and view["findings"][0]["id"] == "fault.errors"
    assert "900 arriving damaged out of 1,200 frames in the last 5 minutes - 75%" in view["findings"][0]["detail"]


def test_a_link_too_quiet_for_its_window_is_judged_on_the_whole_watch():
    """Quieter still - one good frame and two damaged ones every five seconds - and five minutes
    never holds enough frames to make a ratio of.  The errors are there, so the whole watch is the
    span instead, and the finding says so rather than calling it the last five minutes."""
    link = Link()
    link.tick()
    link.run(20 * 60, rx_pps=0.2, error_rate=2.0)
    view = link.w.view()
    assert view["nics"][0]["recent_rx_packets"] + view["nics"][0]["recent_rx_errors"] < faults.MIN_PACKETS
    [found] = view["findings"]
    assert found["id"] == "fault.errors" and found["level"] == "bad"
    assert "480 arriving damaged out of 720 frames in the 20 minutes since TNT started watching" in found["detail"]
    assert "The last 5 minutes alone carried too few frames to judge" in found["detail"]
    # a link that went quiet after a clean, busy spell is judged the same way, and it is a note, not
    # a fault: two damaged frames in 600,000 is nothing to send a tech to the cabling for
    link = Link()
    link.tick()
    link.run(600, rx_pps=1000)
    link.run(600, rx_pps=1)
    link.c["rx_errors"] += 2
    link.run(faults.TICK_S, rx_pps=1)
    [found] = link.w.view()["findings"]
    assert found["id"] == "fault.errors" and found["level"] == "info"
    # once the errors are older than the window there is nothing to judge, and it is clean again
    link.run(faults.RATE_WINDOW_S, rx_pps=1)
    assert link.ids == ["fault.clean"] and link.level == "good"


def test_a_dropping_link_beside_an_up_adapter_keeps_its_verdict():
    """A bad cable on Ethernet that drops one reading in six, with Wi-Fi up beside it: every good
    reading without Ethernet on it moved it out of the findings, so the tile went bad -> clean ->
    bad dozens of times, publishing each one, and read "clean" to a tech who looked during a drop."""
    bus = Bus()
    link = Link(bus=bus, others=[counters(2, name="Wi-Fi", rx=1000)])
    link.tick()
    levels = []
    for i in range(200):
        link.down = i % 6 == 5
        link.run(faults.TICK_S, rx_pps=400, error_rate=0.025)
        levels.append(link.w.tile()["level"])
    first_bad = levels.index("bad")
    assert set(levels[first_bad:]) == {"bad"}
    assert [e["data"]["level"] for e in bus.events] == ["info", "bad"], "one verdict, published once"
    # during a drop the adapter is still on the page, marked down, and still the finding
    link.down = True
    link.run(faults.TICK_S, rx_pps=400, error_rate=0.025)
    view = link.w.view()
    [eth] = [n for n in view["nics"] if n["name"] == "Ethernet"]
    assert eth["up"] is False and eth["recent_rx_errors"] > 0
    assert [n["up"] for n in view["nics"] if n["name"] == "Wi-Fi"] == [True]
    assert view["findings"][0]["id"] == "fault.errors" and view["findings"][0]["title"].startswith("Ethernet")
    assert link.w.tile()["clean_s"] is None


def test_a_link_that_went_down_is_worded_from_when_it_was_last_up():
    """Its errors are still the last few minutes' until they age out, but "in the last 5 minutes"
    would stretch them to now: the span is worded from its last reading."""
    link = Link(others=[counters(2, name="Wi-Fi", rx=1000)])
    link.tick()
    link.run(600, rx_pps=400, error_rate=0.02)
    link.down = True
    link.run(120)
    view = link.w.view()
    [eth] = [n for n in view["nics"] if n["name"] == "Ethernet"]
    assert eth["up"] is False and eth["last_read_s"] == pytest.approx(120.0)
    detail = view["findings"][0]["detail"]
    assert "in the 3 minutes up to 2 minutes ago, when its link was last up" in detail
    assert "in the last 5 minutes" not in detail
    # and when its window has gone by, so has the fault, and the adapter with it
    link.run(faults.RATE_WINDOW_S - 120 + faults.TICK_S)
    assert link.ids == ["fault.clean"] and [n["name"] for n in link.w.view()["nics"]] == ["Wi-Fi"]


def test_counters_that_cannot_be_read_are_worded_from_their_last_reading():
    link = Link()
    link.tick()
    link.run(600, rx_pps=400, error_rate=0.02)
    link.fail = OSError(8, "GetIfTable2 failed")
    link.run(60)
    detail = link.w.view()["findings"][0]["detail"]
    assert "in the 4 minutes up to 60 seconds ago, when its counters were last read" in detail
    [eth] = link.w.view()["nics"]
    assert eth["up"] is True and eth["last_read_s"] == pytest.approx(60.0)


def test_a_clock_set_back_does_not_blind_the_watch():
    """Windows setting its clock back an hour (a time sync on a laptop with a flat RTC battery, the
    moment it reaches a network) made watched_s zero: the tile read "Watching", a real fault went
    unreported for the hour, and the readings piled up because none was ever old enough to drop."""
    table = {"rows": [(GW, 11, M1, "reachable")]}
    link = Link(arp_fn=lambda: list(table["rows"]))
    link.tick()
    link.run(600, rx_pps=400, error_rate=0.05)
    assert link.level == "bad"
    table["rows"] = [("192.0.2.77", 11, M1, "reachable")]
    link.run(faults.TICK_S, rx_pps=400, error_rate=0.05)
    table["rows"] = [("192.0.2.77", 11, M2, "reachable")]
    link.run(faults.TICK_S, rx_pps=400, error_rate=0.05)
    assert "fault.arp" in link.ids
    table["rows"] = [("192.0.2.77", 11, M2, "stale")]
    link.clock.now -= 3600.0
    judged = []
    for _ in range(120):
        link.run(faults.TICK_S, rx_pps=400, error_rate=0.05)
        judged.append("fault.errors" in link.ids)
    assert all(judged), "the errors are reported straight through the step, not an hour later"
    view = link.w.view()
    assert view["watched_s"] >= 600 + 600 and link.level == "bad"
    assert "fault.arp" not in link.ids, "the duplicate aged out two minutes after it was seen"
    assert view["ts"] == link.clock.now, "the page still shows the wall clock"
    assert view["watching_since"] == pytest.approx(link.clock.now - view["watched_s"], abs=0.2)
    [nic_state] = link.w._nics.values()
    assert len(nic_state.history) <= faults.RATE_WINDOW_S / faults.TICK_S + 2


def test_a_look_during_a_slow_tick_is_not_a_clock_step():
    """The tile is polled while a tick is busy reading the adapters: a view that read the clock after
    the tick did is not the clock going backwards, and must not push the watch's time ahead."""
    clock = FakeClock()
    start = clock.now
    w = faults.FaultWatcher(None, clock=clock, reader=lambda: [counters(rx=100)], adapters_fn=lambda: [],
                            arp_fn=lambda: {}, gateway_fn=lambda: None)
    w.tick()
    clock.now = start + 12.0
    w.view()                                    # the page looks while the next tick is still reading
    w.tick(now=start + 5.0)                     # that tick read the clock before the page did
    clock.now = start + 20.0
    view = w.view()
    assert view["watching_since"] == start and view["watched_s"] == 20.0


def test_the_faults_page_tints_a_row_by_its_verdict_not_by_its_past(browser_page, mock, monkeypatch):
    """Errors earlier in the watch tinted the row red while the tile and the findings said clean for
    the last five minutes, and the discard share mixed in the inbound discards nobody grades."""
    now = time.time()

    def row(name: str, index: int, **kw: Any) -> Dict[str, Any]:
        base = dict.fromkeys(faults.NIC_KEYS, 0)
        base.update(name=name, description="", index=index, link_bps=1_000_000_000, watched_s=3600.0,
                    window_s=300.0, error_pct=None, discard_pct=None, up=True, last_read_s=1.0)
        base.update(kw)
        return base

    nics = [row("Ethernet", 12, new_rx_errors=900, rx_errors=900, new_rx_packets=2_000_000, error_pct=0.045,
                new_rx_discards=40_000, rx_discards=40_000, new_tx_packets=400_000, discard_pct=0.0),
            row("Ethernet 2", 14, new_rx_errors=5_000, rx_errors=5_000, recent_rx_errors=400, new_rx_packets=80_000,
                recent_rx_packets=20_000, error_pct=5.9, up=False, last_read_s=40.0),
            row("Wi-Fi", 11, new_tx_discards=60, tx_discards=60, recent_tx_discards=60, new_tx_packets=5_000,
                recent_tx_packets=5_000, discard_pct=1.19)]
    view = {"ts": now, "watching_since": now - 3600, "watched_s": 3600.0, "level": "bad", "note": None,
            "findings": [
                {"id": "fault.errors", "level": "bad", "title": "Ethernet 2 is seeing frame errors", "detail": "",
                 "advice": "", "evidence": [{"name": "Ethernet 2", "rx_errors": 400, "tx_errors": 0, "pct": 1.96,
                                             "level": "bad"}]},
                {"id": "fault.discards", "level": "warn", "title": "Wi-Fi is dropping frames it could not send",
                 "detail": "", "advice": "", "evidence": [{"name": "Wi-Fi", "tx_discards": 60, "tx_packets": 5_000,
                                                           "pct": 1.19, "level": "warn"}]}],
            "nics": nics, "arp": {"tracked": 3, "conflicts": [], "window_s": 120.0, "gateway": GW}}
    monkeypatch.setattr(mock.state, "faults_view", lambda: view)
    dom = browser_page("#faults")
    rows = {name: cls for cls, name in re.findall(r'<tr class="([^"]*)"><td><span class="fa-nic">([^<]+)</span>', dom)}
    assert rows == {"Ethernet": "", "Ethernet 2": "fa-row-bad", "Wi-Fi": "fa-row-warn"}
    assert 'fa-hot' not in re.search(r'<span class="fa-nic">Ethernet</span>.*?</tr>', dom).group(0)
    assert re.search(r'<span class="fa-nic">Ethernet 2</span> <span class="badge grey">link down</span>', dom)
    assert 'title="400 of them in the 5m 00s before it was last read"' in dom
    assert 'title="0 of them in the last 5m 00s"' in dom
    # the discard columns are the outbound ones, graded; the inbound count is there, as context
    eth = re.search(r'<span class="fa-nic">Ethernet</span>.*?</tr>', dom).group(0)
    assert "40,000 in" in eth and ">0%<" in eth


#: (received frames, sent frames, inbound discards) per 5-second tick: the five minutes with the largest inbound
#: discard share (0.36 %) of a 25-minute recording of this desktop's Ethernet, 2026-09-20.  No outbound discard
#: and no error in any of it.
MEASURED: List[tuple] = [
    (117651, 18953, 527), (222050, 36228, 476), (179150, 28343, 982), (171029, 25632, 1200), (125907, 20049, 304),
    (193115, 30411, 309), (260246, 41737, 620), (130694, 20918, 300), (200626, 33337, 391), (210288, 30439, 889),
    (158417, 24895, 567), (179968, 26824, 717), (140550, 20660, 1735), (141954, 20735, 805), (121130, 18171, 789),
    (155449, 23575, 865), (205815, 30708, 1010), (142574, 21281, 262), (170686, 24185, 565), (171840, 26962, 732),
    (189536, 30067, 1016), (202581, 31201, 800), (156525, 23392, 352), (177782, 26218, 1223), (201008, 32534, 513),
    (163332, 26336, 762), (176547, 25912, 1373), (191429, 28829, 588), (195488, 31848, 967), (191266, 29659, 259),
    (172323, 28186, 146), (225258, 86817, 46), (161309, 25929, 420), (172743, 27573, 1581), (150781, 25303, 943),
    (179209, 26840, 1226), (139111, 22739, 234), (165905, 27985, 261), (179628, 30316, 834), (169954, 28016, 270),
    (156681, 24796, 876), (141406, 22782, 546), (160952, 26506, 416), (201889, 32411, 1022), (190708, 31859, 413),
    (174382, 29514, 0), (150514, 25469, 888), (122964, 20383, 0), (130577, 21894, 0), (186430, 31082, 475),
    (139546, 22230, 85), (185093, 30701, 156), (120524, 19655, 0), (154172, 25231, 142), (128418, 21029, 991),
    (186945, 30695, 916), (143177, 22916, 232), (224410, 36159, 407), (172682, 27845, 460), (157851, 25699, 932),
]
