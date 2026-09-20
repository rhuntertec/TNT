"""Tests for the passive fault watch (``tnt.faults``) and the Faults tile.

The watcher is driven through its four seams - the interface counters, the adapters, the ARP table
and the default gateway - so none of this touches a network, and every threshold is exercised as a
pure function first.  The detectors are the interesting part: a tile that cries wolf gets switched
off, and one that stays quiet through a real fault is worse than not having it.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from tnt import faults, netinfo, throughput

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "ui"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def nic(name: str = "Ethernet", *, errors: int = 0, discards: int = 0, packets: int = 100_000,
        watched: float = 600.0, **kw: Any) -> Dict[str, Any]:
    """One row of the shape the detectors take, with the deltas that drive them."""
    row = {"name": name, "description": "Intel(R) I219-V", "index": 12, "link_bps": 1_000_000_000,
           "watched_s": watched,
           "rx_errors": errors + 27, "tx_errors": 0, "rx_discards": discards + 500, "tx_discards": 0,
           "new_rx_errors": errors, "new_tx_errors": 0,
           "new_rx_discards": discards, "new_tx_discards": 0,
           "new_rx_packets": packets, "new_tx_packets": 0,
           "error_pct": None, "discard_pct": None}
    row.update(kw)
    total = int(row["new_rx_packets"]) + int(row["new_tx_packets"])
    if total:
        row["error_pct"] = 100.0 * (row["new_rx_errors"] + row["new_tx_errors"]) / total
        row["discard_pct"] = 100.0 * (row["new_rx_discards"] + row["new_tx_discards"]) / total
    return row


def counters(luid: int = 1, *, name: str = "Ethernet", packets: int = 0, errors: int = 0,
             discards: int = 0, **kw: Any) -> throughput.Counters:
    return throughput.Counters(luid=luid, index=12, name=name, description="Intel(R) I219-V",
                               if_type=6, link_bps=1_000_000_000, rx_bytes=packets * 900,
                               tx_bytes=0, rx_packets=packets, tx_packets=0,
                               rx_errors=errors, tx_errors=0, rx_discards=discards, tx_discards=0,
                               **kw)


def adapter(name: str = "Ethernet", *, status: str = "up", warnings: Any = ()) -> Dict[str, Any]:
    return {"name": name, "status": status, "if_type": 6,
            "warnings": [dict(w) for w in warnings]}


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


def watcher(rows: Optional[List[List[Any]]] = None, *, adapters: Any = (), arp: Any = None,
            gateway: Optional[str] = None, bus: Any = None) -> "tuple[faults.FaultWatcher, FakeClock, list]":
    """A watcher whose four sources the test drives.  ``rows`` is one counter list per tick."""
    clock = FakeClock()
    state = {"i": 0}
    arp_tables = arp if isinstance(arp, list) else [arp or {}]

    def reader() -> List[Any]:
        i = min(state["i"], len(rows or [[]]) - 1)
        return list((rows or [[]])[i])

    def arp_fn() -> Dict[str, str]:
        return dict(arp_tables[min(state["i"], len(arp_tables) - 1)])

    def tick(now: Optional[float] = None) -> Any:
        out = original(now)
        state["i"] += 1
        return out

    w = faults.FaultWatcher(bus, clock=clock, reader=reader, adapters_fn=lambda: list(adapters),
                            arp_fn=arp_fn, gateway_fn=lambda: gateway)
    original = w.tick
    w.tick = tick        # type: ignore[method-assign]
    return w, clock, state


def ids(findings: Any) -> List[str]:
    return [f["id"] for f in findings]


# =========================================================================================
# errors and discards: the two that get confused for each other
# =========================================================================================
def test_an_error_and_a_discard_are_never_reported_as_the_same_thing():
    """The whole reason the counters are kept apart: one sends a tech to the cabling and the other
    to whatever is saturating the link.  A page that said "3,000 problems" would help nobody."""
    rows = [nic(errors=400, discards=4000, packets=100_000)]
    both = faults.error_findings(rows) + faults.discard_findings(rows)
    assert ids(both) == ["fault.errors", "fault.discards"]
    error, discard = both
    assert "damaged" in error["detail"] and "cable" in error["advice"].lower()
    assert "Nothing here is damaged" in discard["detail"] and "congestion" in discard["advice"].lower()


@pytest.mark.parametrize("errors, packets, level", [
    (1, 100_000, "info"),            # 0.001% - real, but not worth shouting about
    (20, 100_000, "warn"),           # 0.02%
    (900, 100_000, "bad"),           # 0.9%
])
def test_the_error_level_follows_the_share_of_frames_not_the_count(errors, packets, level):
    """A thousand errors out of ten million is a different network from a thousand out of two
    thousand, so the ratio decides and the count is reported beside it."""
    found = faults.error_findings([nic(errors=errors, packets=packets)])
    assert found and found[0]["level"] == level


def test_a_quiet_adapter_is_not_judged_on_a_handful_of_frames():
    """One error out of thirty frames is 3%, and means nothing at all."""
    assert faults.error_findings([nic(errors=1, packets=30)]) == []
    assert faults.error_findings([nic(errors=1, packets=faults.MIN_PACKETS + 1)]) != []


def test_a_few_discards_on_a_busy_link_are_what_a_buffer_is_for():
    assert faults.discard_findings([nic(discards=10, packets=100_000)]) == []          # 0.01%
    assert faults.discard_findings([nic(discards=1_000, packets=100_000)])[0]["level"] == "warn"   # 1%
    assert faults.discard_findings([nic(discards=5_000, packets=100_000)])[0]["level"] == "bad"    # 5%, the bar
    assert faults.discard_findings([nic(discards=50_000, packets=100_000)])[0]["level"] == "bad"


def test_the_worst_adapter_leads_and_the_rest_are_counted():
    rows = [nic("Ethernet", errors=5, packets=100_000), nic("Wi-Fi", errors=900, packets=100_000)]
    found = faults.error_findings(rows)[0]
    assert found["title"].startswith("Wi-Fi") and "1 other adapter" in found["title"]
    assert [e["name"] for e in found["evidence"]] == ["Wi-Fi", "Ethernet"]


def test_nothing_is_said_when_nothing_happened():
    assert faults.error_findings([nic()]) == [] and faults.discard_findings([nic()]) == []
    assert faults.error_findings([]) == []


# =========================================================================================
# address configuration
# =========================================================================================
def test_the_adapter_warnings_netinfo_already_knows_are_gathered_where_they_get_read():
    found = faults.address_findings([
        adapter("Ethernet", warnings=[{"code": "no_dns", "message": "No DNS servers"}]),
        adapter("Wi-Fi", warnings=[{"code": "duplicate_address", "message": "10.0.0.5 is already used"}]),
    ])
    assert ids(found) == ["fault.address"]
    assert found[0]["level"] == "bad"           # the worst of the two decides
    assert "Wi-Fi: 10.0.0.5 is already used" in found[0]["detail"]
    assert [e["adapter"] for e in found[0]["evidence"]] == ["Wi-Fi", "Ethernet"]


def test_a_down_adapters_configuration_is_not_a_fault():
    assert faults.address_findings([
        adapter("Wi-Fi", status="down", warnings=[{"code": "apipa", "message": "self-assigned"}])]) == []


def test_every_code_the_levels_table_names_is_one_netinfo_still_emits():
    """An unknown code falls back to "info", which would quietly demote a duplicate address from a
    fault to a note.  This is the test that catches a rename on the other side."""
    emitted = set(re.findall(r'"code": "(\w+)"', (ROOT / "tnt" / "netinfo.py").read_text(encoding="utf-8")))
    assert set(faults._ADDRESS_LEVEL) <= emitted, sorted(set(faults._ADDRESS_LEVEL) - emitted)
    assert emitted <= set(faults._ADDRESS_LEVEL), f"netinfo gained a code nobody graded: {sorted(emitted - set(faults._ADDRESS_LEVEL))}"


def test_a_vpn_tunnel_is_not_a_misconfigured_adapter():
    """A tunnel is addressed as a host route with its gateway outside it, and takes the default
    route while connected.  Both are correct, and warning about either made every machine running
    Tailscale or a corporate VPN look broken - on the adapter card as well as here.
    """
    addr = netinfo.IpAddr("10.2.0.7", 32, 4, "255.255.255.255", "10.2.0.7/32")
    tunnel = netinfo.Adapter(index=32, name="Mullvad", description="Mullvad", mac="", if_type=53,
                             type_name="Tunnel", status="up", speed_bps=None, mtu=1420,
                             dhcp_enabled=False, dhcp_server=None, dns_suffix="",
                             ipv4=[addr], gateways=["10.2.0.1"], dns=["10.2.0.1"])
    assert [w["code"] for w in netinfo.adapter_warnings(tunnel)] == []
    # and a real NIC whose mask really is wrong still says so
    bad = netinfo.Adapter(index=12, name="Ethernet", description="", mac="", if_type=6,
                          type_name="Ethernet", status="up", speed_bps=None, mtu=1500,
                          dhcp_enabled=True, dhcp_server=None, dns_suffix="",
                          ipv4=[netinfo.IpAddr("10.0.0.5", 24, 4, "255.255.255.0", "10.0.0.0/24")],
                          gateways=["192.168.9.1"], dns=["1.1.1.1"])
    assert [w["code"] for w in netinfo.adapter_warnings(bad)] == ["gateway_outside_subnet"]


# =========================================================================================
# the ARP watch
# =========================================================================================
def test_two_macs_answering_for_one_address_inside_the_window_is_a_conflict():
    watch = faults.ArpWatch(window_s=120.0)
    watch.observe({"10.0.0.50": "AA:BB:CC:00:00:01"}, 1000.0)
    assert watch.conflicts() == []
    watch.observe({"10.0.0.50": "AA:BB:CC:00:00:02"}, 1030.0)
    assert watch.conflicts() == [{"ip": "10.0.0.50", "macs": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"],
                                  "seen": 2}]


def test_a_lease_that_changed_hands_hours_ago_is_not_a_conflict():
    """The window is the whole point: DHCP hands addresses around, and that is not a fault."""
    watch = faults.ArpWatch(window_s=120.0)
    watch.observe({"10.0.0.50": "AA:BB:CC:00:00:01"}, 1000.0)
    watch.observe({"10.0.0.50": "AA:BB:CC:00:00:02"}, 1000.0 + 5000.0)
    assert watch.conflicts() == []


def test_the_case_a_mac_is_written_in_does_not_invent_a_conflict():
    watch = faults.ArpWatch()
    watch.observe({"10.0.0.50": "aa:bb:cc:00:00:01"}, 1000.0)
    watch.observe({"10.0.0.50": "AA:BB:CC:00:00:01"}, 1005.0)
    assert watch.conflicts() == []


def test_the_arp_watch_cannot_grow_without_bound():
    """A Discovery sweep of a /16 walks thousands of addresses through the table."""
    watch = faults.ArpWatch(window_s=10_000.0, max_tracked=100)
    for i in range(500):
        watch.observe({f"10.0.{i // 256}.{i % 256}": "AA:BB:CC:00:00:01"}, 1000.0 + i)
    assert watch.tracked() == 100


def test_a_blank_address_or_mac_is_ignored():
    watch = faults.ArpWatch()
    watch.observe({"": "AA:BB:CC:00:00:01", "10.0.0.5": "", "10.0.0.6": "AA:BB:CC:00:00:02"}, 1000.0)
    assert watch.tracked() == 1


def test_the_gateway_answering_from_two_macs_is_reported_as_its_own_thing():
    """A router pair failing over does this legitimately; so does something answering for the
    router.  The finding says both and does not pretend to know which."""
    conflicts = [{"ip": "10.0.0.1", "macs": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"], "seen": 2}]
    found = faults.arp_findings(conflicts, gateway="10.0.0.1")
    assert ids(found) == ["fault.gateway"] and found[0]["level"] == "bad"
    assert "failing over does this legitimately" in found[0]["advice"]
    # the same conflict on any other address is the plain duplicate-IP finding
    plain = faults.arp_findings(conflicts, gateway="192.168.1.1")
    assert ids(plain) == ["fault.arp"] and "10.0.0.1" in plain[0]["title"]


def test_the_gateway_leads_when_several_addresses_are_in_conflict():
    conflicts = [{"ip": "10.0.0.50", "macs": ["A", "B"]}, {"ip": "10.0.0.1", "macs": ["C", "D"]}]
    found = faults.arp_findings(conflicts, gateway="10.0.0.1")
    assert ids(found) == ["fault.gateway"] and "1 other address" in found[0]["detail"]


# =========================================================================================
# the watcher
# =========================================================================================
def test_nothing_is_judged_before_there_is_enough_watched_time():
    """A tile that cried wolf ten seconds after the service started would be switched off."""
    rows = [[counters(packets=0)], [counters(packets=100_000, errors=900)]]
    w, clock, _ = watcher(rows)
    w.tick()
    clock.now += 5.0
    w.tick()
    assert ids(w.view()["findings"]) == ["fault.watching"]
    assert w.tile()["level"] == "info" and w.tile()["bad"] == 0


def test_once_there_is_enough_watched_time_the_fault_is_reported():
    rows = [[counters(packets=0)], [counters(packets=100_000, errors=900)]]
    w, clock, _ = watcher(rows)
    w.tick()
    clock.now += faults.MIN_WATCH_S + 1.0
    w.tick()
    view = w.view()
    assert ids(view["findings"]) == ["fault.errors"] and view["level"] == "bad"
    assert w.tile()["bad"] == 1 and w.tile()["headline"].startswith("Ethernet")


def test_an_address_fault_is_reported_at_once_because_it_needs_no_watching():
    """It is read from the live configuration, not counted over time: waiting a minute to say an
    adapter has no usable address would be a minute wasted."""
    w, clock, _ = watcher([[counters(packets=0)]],
                          adapters=[adapter(warnings=[{"code": "apipa", "message": "self-assigned"}])])
    w.tick()
    assert ids(w.view()["findings"]) == ["fault.address"]
    assert w.view()["level"] == "bad"


def test_the_counters_are_counted_from_when_we_started_not_from_the_top():
    """A month of uptime is not evidence about the network the tech is standing in."""
    rows = [[counters(packets=5_000_000, errors=900_000, discards=400_000)],
            [counters(packets=5_100_000, errors=900_000, discards=400_000)]]
    w, clock, _ = watcher(rows)
    w.tick()
    clock.now += faults.MIN_WATCH_S + 1.0
    w.tick()
    view = w.view()
    assert ids(view["findings"]) == ["fault.clean"], "a lifetime counter is not a fault today"
    row = view["nics"][0]
    assert row["rx_errors"] == 900_000 and row["new_rx_errors"] == 0
    assert row["new_rx_packets"] == 100_000


def test_a_counter_that_went_backwards_restarts_the_baseline():
    """An adapter reset; the delta from the old baseline would be nonsense."""
    rows = [[counters(packets=1_000_000, errors=500)], [counters(packets=20, errors=0)],
            [counters(packets=100_020, errors=0)]]
    w, clock, _ = watcher(rows)
    w.tick()
    clock.now += 10.0
    w.tick()
    clock.now += faults.MIN_WATCH_S + 1.0
    w.tick()
    row = w.view()["nics"][0]
    assert row["new_rx_errors"] == 0 and row["new_rx_packets"] == 100_000


def test_an_adapter_that_goes_away_takes_its_counters_with_it():
    rows = [[counters(1, name="Ethernet"), counters(2, name="Wi-Fi")], [counters(1, name="Ethernet")]]
    w, clock, _ = watcher(rows)
    w.tick()
    clock.now += 5.0
    w.tick()
    assert [n["name"] for n in w.view()["nics"]] == ["Ethernet"]


def test_the_event_is_published_only_when_the_level_changes():
    """A green tile does not need to say so once a second."""
    bus = Bus()
    rows = [[counters(packets=0)], [counters(packets=100_000)], [counters(packets=200_000)],
            [counters(packets=300_000, errors=3_000)]]
    w, clock, _ = watcher(rows, bus=bus)
    w.tick()                                   # info: watching
    clock.now += faults.MIN_WATCH_S + 1.0
    w.tick()                                   # good: clean  -> a change
    clock.now += 5.0
    w.tick()                                   # good again   -> silence
    clock.now += 5.0
    w.tick()                                   # bad          -> a change
    assert [e["type"] for e in bus.events] == ["faults.state", "faults.state", "faults.state"]
    assert [e["data"]["level"] for e in bus.events] == ["info", "good", "bad"]


def test_a_source_that_fails_is_named_and_does_not_stop_the_others():
    def boom() -> Any:
        raise OSError("GetIpNetTable2 failed")

    clock = FakeClock()
    w = faults.FaultWatcher(None, clock=clock, reader=lambda: [counters(packets=100_000)],
                            adapters_fn=lambda: [adapter()], arp_fn=boom, gateway_fn=lambda: None)
    w.tick()
    clock.now += faults.MIN_WATCH_S + 1.0
    w.tick()
    view = w.view()
    assert "ARP table" in (view["note"] or "")
    assert ids(view["findings"]) == ["fault.clean"], "the counters still got read"


def test_when_nothing_at_all_can_be_read_it_says_so_rather_than_all_clear():
    def boom() -> Any:
        raise OSError("nope")

    w = faults.FaultWatcher(None, clock=FakeClock(), reader=boom, adapters_fn=boom, arp_fn=boom,
                            gateway_fn=boom)
    w.tick()
    assert ids(w.view()["findings"]) == ["fault.unavailable"]


def test_the_shapes_are_the_ones_declared():
    rows = [[counters(packets=0)], [counters(packets=100_000, errors=900)]]
    w, clock, _ = watcher(rows, adapters=[adapter()], gateway="10.0.0.1")
    w.tick()
    clock.now += faults.MIN_WATCH_S + 1.0
    w.tick()
    view, tile = w.view(), w.tile()
    assert set(view) == set(faults.VIEW_KEYS)
    assert set(tile) == set(faults.TILE_KEYS)
    assert set(view["nics"][0]) == set(faults.NIC_KEYS)
    for f in view["findings"]:
        assert set(f) == set(faults.FINDING_KEYS)
        assert f["id"] in faults.FINDING_IDS and f["level"] in faults.FINDING_LEVELS
    assert json.dumps(view) and json.dumps(tile)      # everything here crosses the API as JSON


def test_worst_level_picks_the_worst():
    assert faults.worst_level([]) == "good"
    assert faults.worst_level([{"level": "good"}, {"level": "warn"}]) == "warn"
    assert faults.worst_level([{"level": "warn"}, {"level": "bad"}, {"level": "info"}]) == "bad"
    assert faults.worst_level([None, {"level": "nonsense"}]) == "good"


def test_findings_come_back_worst_first():
    rows = [[counters(packets=0)], [counters(packets=100_000, errors=900, discards=5_000)]]
    w, clock, _ = watcher(rows, adapters=[adapter(warnings=[{"code": "no_dns", "message": "no DNS"}])])
    w.tick()
    clock.now += faults.MIN_WATCH_S + 1.0
    w.tick()
    levels = [f["level"] for f in w.view()["findings"]]
    assert levels == sorted(levels, key=lambda l: faults.FINDING_LEVELS.index(l))


# =========================================================================================
# the tile and the page
# =========================================================================================
def test_the_tile_and_the_page_are_loaded_and_placed():
    html = (UI / "index.html").read_text(encoding="utf-8")
    assert '<a class="tile half" data-view="faults" href="#faults" style="--accent: var(--rust)">' in html
    assert '<div class="tile-body" id="tile-faults">' in html
    assert '<script src="js/views/faults.js"></script>' in html
    css = (UI / "css" / "tnt.css").read_text(encoding="utf-8")
    assert "--rust: #" in css and css.count("--rust: #") == 2, "one --rust for each theme"
    view = (UI / "js" / "views" / "faults.js").read_text(encoding="utf-8")
    assert "TNT.views.faults = {" in view and "TNT.api.faults()" in view
    assert "'faults.state'" in view, "the page follows the level-change event"


def test_the_page_never_asks_the_network_anything():
    """The claim on the page is that nothing is sent. Nothing here may start a scan or a probe."""
    view = (UI / "js" / "views" / "faults.js").read_text(encoding="utf-8")
    assert "api.post" not in view and "api.put" not in view and "api.del" not in view
    src = (ROOT / "tnt" / "faults.py").read_text(encoding="utf-8")
    for forbidden in ("socket.", "urlopen", "subprocess", "requests", "sendto", "connect("):
        assert forbidden not in src, forbidden


_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const window = { TNT: { views: {}, util: {}, ui: {}, api: {}, charts: {} } };
const ctx = vm.createContext({ window, console, document: undefined });
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'faults.js' });
const v = window.TNT.views.faults;
const out = {};
out.num = [0, 1, 1234, 321273647, null, NaN].map((n) => v.num(n));
out.pct = [0, 0.0004, 0.0123, 0.56, 1, 12.34, 99.9, null].map((p) => v.pct(p));
out.levels = v.LEVEL_CLASS;
process.stdout.write(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_pages_number_formatting_with_node(tmp_path):
    driver = tmp_path / "driver.js"
    driver.write_text(_DRIVER, encoding="utf-8")
    r = subprocess.run(["node", str(driver), str(UI / "js/views/faults.js")],
                       capture_output=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["num"] == ["0", "1", "1,234", "321,273,647", "—", "—"]
    # a share of frames, at the precision the number deserves - and never a wall of zeros
    assert out["pct"] == ["0%", "<0.001%", "0.012%", "0.56%", "1%", "12.3%", "99.9%", "—"]
    # the level words map onto the badge colours the rest of TNT uses
    assert out["levels"] == {"bad": "red", "warn": "yellow", "info": "grey", "good": "green"}
