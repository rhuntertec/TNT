"""Tests for the realtime throughput monitor (``tnt.throughput``) and its card.

The monitor is driven through its ``reader`` seam with made-up counter readings, so everything
here runs off Windows too; the handful of checks that need the real ``GetIfTable2`` are marked.
The card's own arithmetic (which NICs are shown, where the average rules sit, how a live sample
is merged into the series) is exercised with node when it is installed.
"""
from __future__ import annotations

import ctypes
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from tnt import throughput

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "ui"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def counters(luid: int = 1, *, index: int = 12, name: str = "Ethernet", description: str = "Intel(R) I219-V",
             if_type: int = 6, link_bps: Optional[int] = 1_000_000_000, rx_bytes: int = 0, tx_bytes: int = 0,
             rx_packets: int = 0, tx_packets: int = 0) -> throughput.Counters:
    return throughput.Counters(luid=luid, index=index, name=name, description=description, if_type=if_type,
                               link_bps=link_bps, rx_bytes=rx_bytes, tx_bytes=tx_bytes,
                               rx_packets=rx_packets, tx_packets=tx_packets)


class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now


class Bus:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def publish(self, event_type: str, data: Dict[str, Any] | None = None) -> None:
        self.events.append({"type": event_type, "data": data or {}})


def monitor(rows: List[List[throughput.Counters]], *, bus: Any = None,
            primary: Optional[int] = None) -> "tuple[throughput.ThroughputMonitor, FakeClock, List[int]]":
    """A monitor that hands out *rows* one reading at a time, with a clock the test drives."""
    clock = FakeClock()
    calls = [0]

    def reader() -> List[throughput.Counters]:
        i = min(calls[0], len(rows) - 1)
        calls[0] += 1
        return list(rows[i])

    mon = throughput.ThroughputMonitor(bus, clock=clock, reader=reader, primary_fn=lambda: primary)
    return mon, clock, calls


def ramp(luid: int, steps: List[int], **kw: Any) -> List[throughput.Counters]:
    """Readings where the byte counters advance by *steps* bytes a second, packets by steps//100."""
    out, rx, tx, rxp, txp = [], 0, 0, 0, 0
    for step in steps:
        out.append(counters(luid, rx_bytes=rx, tx_bytes=tx, rx_packets=rxp, tx_packets=txp, **kw))
        rx += step
        tx += step // 4
        rxp += step // 100
        txp += step // 400
    return out


# =========================================================================================
# eligibility: which interfaces belong on the card at all
# =========================================================================================
def test_a_filter_interfaces_copy_of_a_nic_is_not_a_second_nic():
    """Every lightweight filter bound to a NIC gets a row carrying that NIC's counters.

    A machine with Npcap, the QoS scheduler and the WFP filters installed has eight rows for one
    adapter, all claiming the same traffic.  Without the FilterInterface test the card would show
    the same Ethernet eight times, each apparently moving the same 400 GB.
    """
    up, filt = throughput.IF_OPER_STATUS_UP, throughput.FLAG_FILTER
    assert throughput.eligible(6, up, throughput.FLAG_HARDWARE) is True
    assert throughput.eligible(6, up, filt) is False
    assert throughput.eligible(6, up, filt | throughput.FLAG_HARDWARE) is False


def test_hardware_is_not_the_test_because_a_vpn_tunnel_is_not_hardware():
    """Tailscale/WireGuard adapters carry real traffic and set no HardwareInterface bit."""
    assert throughput.eligible(53, throughput.IF_OPER_STATUS_UP, 0) is True


def test_loopback_and_a_down_adapter_are_left_out():
    assert throughput.eligible(throughput.IF_TYPE_SOFTWARE_LOOPBACK, throughput.IF_OPER_STATUS_UP, 0) is False
    for status in (2, 5, 7):      # down, not present, lower-layer down
        assert throughput.eligible(6, status, 0) is False


# =========================================================================================
# windows and bucketing
# =========================================================================================
def test_an_unknown_window_is_the_nearest_one_we_keep_never_an_error():
    """A stale page asking for a window that no longer exists gets the closest answer.

    400ing it would put an error on a card whose only job is to draw a line.
    """
    assert throughput.clamp_window(30) == 30
    assert throughput.clamp_window("60") == 60
    assert throughput.clamp_window(45) == 30         # ties go to the shorter window
    assert throughput.clamp_window(999_999) == 1800
    for bad in (None, "", "soon", float("nan"), [], {}):
        assert throughput.clamp_window(bad) == throughput.DEFAULT_WINDOW_S


def test_only_the_thirty_minute_window_is_bucketed():
    """1800 one-second points is 80 kB of JSON per NIC; every shorter window fits as it is."""
    assert [throughput.step_for(w) for w in throughput.WINDOWS] == [1, 1, 1, 1, 3]
    assert 1800 // throughput.step_for(1800) <= throughput.MAX_POINTS


def test_a_bucket_is_the_mean_of_the_seconds_in_it():
    samples = [(100, 10, 1, 5, 2), (101, 20, 3, 7, 4), (102, 30, 2, 9, 0), (105, 90, 9, 3, 3)]
    assert throughput._bucket(samples, 1) == [[100, 10, 1, 5, 2], [101, 20, 3, 7, 4],
                                              [102, 30, 2, 9, 0], [105, 90, 9, 3, 3]]
    assert throughput._bucket(samples, 3) == [[99, 15, 2, 6, 3], [102, 30, 2, 9, 0], [105, 90, 9, 3, 3]]


def test_a_bucket_nobody_sampled_is_absent_rather_than_zero():
    """An absent bucket is a gap in the line; a zero would be a claim that nothing moved."""
    rows = throughput._bucket([(100, 10, 1, 1, 1), (160, 10, 1, 1, 1)], 3)
    assert [r[0] for r in rows] == [99, 159]


# =========================================================================================
# sampling
# =========================================================================================
def test_the_first_reading_records_nothing_because_a_rate_needs_two():
    mon, clock, _ = monitor([[counters(1, rx_bytes=1000)], [counters(1, rx_bytes=2000)]])
    assert mon.tick() is None
    assert mon.view(30)["nics"] == [] or mon.view(30)["nics"][0]["samples"] == []
    clock.now += 1.0
    assert mon.tick() is not None


def test_a_rate_is_the_difference_over_the_time_between_the_readings_in_bits():
    mon, clock, _ = monitor([[counters(1, rx_bytes=0, tx_bytes=0, rx_packets=0, tx_packets=0)],
                             [counters(1, rx_bytes=125_000, tx_bytes=12_500, rx_packets=100, tx_packets=40)]])
    mon.tick()
    clock.now += 1.0
    event = mon.tick()
    nic = event["nics"][0]
    assert nic["rx_bps"] == 1_000_000 and nic["tx_bps"] == 100_000      # 125 kB/s is 1 Mbps
    assert nic["rx_pps"] == 100 and nic["tx_pps"] == 40


def test_half_a_second_of_traffic_is_reported_as_the_per_second_rate():
    mon, clock, _ = monitor([[counters(1, rx_bytes=0)], [counters(1, rx_bytes=125_000)]])
    mon.tick()
    clock.now += 0.5
    assert mon.tick()["nics"][0]["rx_bps"] == 2_000_000


def test_a_counter_that_went_backwards_reports_nothing_rather_than_a_spike():
    """A driver reload resets the counters.  The traffic between the two readings is unknown, and
    the whole counter as one second's worth would be a spike that never happened."""
    mon, clock, _ = monitor([[counters(1, rx_bytes=5_000_000_000, tx_bytes=9_000)],
                             [counters(1, rx_bytes=4_000, tx_bytes=12_000)]])
    mon.tick()
    clock.now += 1.0
    nic = mon.tick()["nics"][0]
    assert nic["rx_bps"] == 0                 # reset: not measured
    assert nic["tx_bps"] == 24_000            # the other direction still counted normally


def test_a_gap_longer_than_max_span_is_a_gap_not_one_very_long_sample():
    """The machine slept.  A flat line across eight hours would be a claim about time nobody
    measured, so the sample is dropped and the chart shows the hole."""
    mon, clock, _ = monitor([[counters(1, rx_bytes=0)], [counters(1, rx_bytes=10_000_000)],
                             [counters(1, rx_bytes=10_125_000)]])
    mon.tick()
    clock.now += throughput.MAX_SPAN_S + 1.0
    assert mon.tick() is None                 # nothing recorded across the gap
    clock.now += 1.0
    assert mon.tick()["nics"][0]["rx_bps"] == 1_000_000   # and it picks straight back up


def test_the_history_stops_at_half_an_hour():
    mon, clock, _ = monitor([ramp(1, [1000] * 3)[i:i + 1][0:1] or [] for i in range(3)])
    rows = ramp(1, [125_000] * (throughput.HISTORY_S + 50))
    mon, clock, _ = monitor([[r] for r in rows])
    for _ in range(len(rows)):
        mon.tick()
        clock.now += 1.0
    held = mon._nics[1].samples
    assert len(held) == throughput.HISTORY_S


def test_an_adapter_that_goes_away_takes_its_history_with_it():
    """A cable pulled out must not leave the last rate frozen on the chart for half an hour."""
    both = [counters(1, name="Ethernet"), counters(2, index=7, name="Wi-Fi")]
    mon, clock, _ = monitor([both, both, [counters(1, name="Ethernet", rx_bytes=1)]])
    mon.tick()
    clock.now += 1.0
    mon.tick()
    assert set(mon._nics) == {1, 2}
    clock.now += 1.0
    mon.tick()
    assert set(mon._nics) == {1}


def test_a_reader_that_fails_sets_a_note_and_the_next_good_read_clears_it():
    calls = [0]
    clock = FakeClock()

    def reader() -> List[throughput.Counters]:
        calls[0] += 1
        if calls[0] == 2:
            raise OSError(1, "GetIfTable2 failed")
        return [counters(1, rx_bytes=125_000 * calls[0])]

    mon = throughput.ThroughputMonitor(None, clock=clock, reader=reader, primary_fn=lambda: None)
    mon.tick()
    clock.now += 1.0
    assert mon.tick() is None
    assert "GetIfTable2 failed" in (mon.view(30)["note"] or "")
    clock.now += 1.0
    mon.tick()
    assert mon.view(30)["note"] is None


# =========================================================================================
# the event and the view
# =========================================================================================
def test_the_event_carries_every_eligible_nic_including_the_idle_ones():
    """The event is the card's only live feed: a NIC that starts carrying traffic has to be able
    to appear in it, so it cannot be filtered down to what is busy."""
    bus = Bus()
    rows = [[counters(1, name="Ethernet", rx_bytes=0), counters(2, index=30, name="vEthernet", rx_bytes=0)],
            [counters(1, name="Ethernet", rx_bytes=125_000), counters(2, index=30, name="vEthernet", rx_bytes=0)]]
    mon, clock, _ = monitor(rows, bus=bus, primary=1)
    mon.tick()
    clock.now += 1.0
    mon.tick()
    assert [e["type"] for e in bus.events] == ["throughput.sample"]
    names = [n["name"] for n in bus.events[0]["data"]["nics"]]
    assert names == ["Ethernet", "vEthernet"]
    for nic in bus.events[0]["data"]["nics"]:
        assert set(nic) == set(throughput.EVENT_KEYS)


def test_the_view_leaves_out_a_nic_that_moved_nothing_but_never_the_internet_facing_one():
    """A flat line on the NIC carrying the default route is itself the answer; a Hyper-V switch
    that has never moved a byte is just noise on the card."""
    idle = counters(2, index=30, name="vEthernet (Default Switch)", rx_bytes=0, tx_bytes=0)
    rows = [[counters(1, rx_bytes=0), idle], [counters(1, rx_bytes=0), idle]]
    mon, clock, _ = monitor(rows, primary=1)
    mon.tick()
    clock.now += 1.0
    mon.tick()
    assert [n["name"] for n in mon.view(30)["nics"]] == ["Ethernet"]
    assert mon.view(30)["nics"][0]["primary"] is True


def test_when_nothing_is_moving_and_nothing_is_primary_every_nic_is_listed():
    """Better "nothing is moving" than a blank card that looks broken."""
    rows = [[counters(1, rx_bytes=0), counters(2, index=30, name="vEthernet", rx_bytes=0)]] * 2
    mon, clock, _ = monitor(rows, primary=None)
    mon.tick()
    clock.now += 1.0
    mon.tick()
    assert [n["name"] for n in mon.view(30)["nics"]] == ["Ethernet", "vEthernet"]


def test_the_view_carries_the_averages_peaks_and_the_cumulative_counters():
    rows = ramp(1, [125_000, 250_000, 125_000, 375_000])
    mon, clock, _ = monitor([[r] for r in rows], primary=1)
    for _ in rows:
        mon.tick()
        clock.now += 1.0
    nic = mon.view(30)["nics"][0]
    # the deltas that were measured: 125 kB, 250 kB, 125 kB -> 1, 2 and 1 Mbps
    assert [s[1] for s in nic["samples"]] == [1_000_000, 2_000_000, 1_000_000]
    assert nic["avg_rx_bps"] == pytest.approx(1_333_333, abs=2)
    assert nic["peak_rx_bps"] == 2_000_000
    assert nic["rx_bytes"] == 500_000 and nic["rx_packets"] == 5_000    # straight from the counters


def test_the_window_cuts_the_series_but_not_the_running_totals():
    rows = ramp(1, [125_000] * 40)
    mon, clock, _ = monitor([[r] for r in rows], primary=1)
    for _ in rows:
        mon.tick()
        clock.now += 1.0
    short, long = mon.view(10), mon.view(60)
    assert len(short["nics"][0]["samples"]) == 10 and len(long["nics"][0]["samples"]) == 39
    assert short["nics"][0]["rx_bytes"] == long["nics"][0]["rx_bytes"]


def test_the_view_and_the_event_keep_to_their_declared_shapes():
    rows = ramp(1, [125_000] * 3)
    bus = Bus()
    mon, clock, _ = monitor([[r] for r in rows], bus=bus, primary=1)
    for _ in rows:
        mon.tick()
        clock.now += 1.0
    view = mon.view(30)
    assert set(view) == set(throughput.VIEW_KEYS)
    assert set(view["nics"][0]) == set(throughput.NIC_KEYS)
    assert view["windows"] == list(throughput.WINDOWS) and view["history_s"] == throughput.HISTORY_S
    assert all(len(s) == throughput.SAMPLE_WIDTH for s in view["nics"][0]["samples"])
    assert set(bus.events[0]["data"]) == {"ts", "nics"}


def test_the_internet_facing_nic_is_first_then_the_busiest():
    quiet = ramp(2, [12_500] * 3, index=7, name="Wi-Fi")
    busy = ramp(3, [1_250_000] * 3, index=30, name="Ethernet 2")
    primary = ramp(1, [125_000] * 3)
    mon, clock, _ = monitor([[primary[i], quiet[i], busy[i]] for i in range(3)], primary=1)
    for _ in range(3):
        mon.tick()
        clock.now += 1.0
    assert [n["name"] for n in mon.view(30)["nics"]] == ["Ethernet", "Ethernet 2", "Wi-Fi"]


def test_the_view_survives_a_window_nobody_should_have_asked_for():
    rows = ramp(1, [125_000] * 3)
    mon, clock, _ = monitor([[r] for r in rows], primary=1)
    for _ in rows:
        mon.tick()
        clock.now += 1.0
    for bad in (None, "", "half an hour", -5, 0, 10 ** 9):
        assert mon.view(bad)["window_s"] in throughput.WINDOWS


def test_which_nic_is_the_internet_facing_one_is_asked_at_most_every_few_seconds():
    """It is a route lookup; the card only uses it to pick which NIC goes first."""
    asked = [0]

    def primary_fn() -> Optional[int]:
        asked[0] += 1
        return 1

    clock = FakeClock()
    rows = ramp(1, [125_000] * 12)
    calls = [0]

    def reader() -> List[throughput.Counters]:
        i = min(calls[0], len(rows) - 1)
        calls[0] += 1
        return [rows[i]]

    mon = throughput.ThroughputMonitor(None, clock=clock, reader=reader, primary_fn=primary_fn)
    for _ in range(11):
        mon.tick()
        clock.now += 1.0
    assert asked[0] <= 1 + int(10 / throughput.PRIMARY_TTL_S) + 1


def test_a_primary_lookup_that_raises_keeps_the_last_answer_and_never_stops_a_sample():
    boom = [False]

    def primary_fn() -> Optional[int]:
        if boom[0]:
            raise OSError("no route")
        return 1

    clock = FakeClock()
    rows = ramp(1, [125_000] * 6)
    calls = [0]

    def reader() -> List[throughput.Counters]:
        i = min(calls[0], len(rows) - 1)
        calls[0] += 1
        return [rows[i]]

    mon = throughput.ThroughputMonitor(None, clock=clock, reader=reader, primary_fn=primary_fn)
    mon.tick()
    clock.now += 1.0
    assert mon.tick()["nics"][0]["primary"] is True
    boom[0] = True
    clock.now += throughput.PRIMARY_TTL_S + 1.0
    assert mon.tick()["nics"][0]["primary"] is True



# =========================================================================================
# hiding an adapter (throughput.excluded, the checkbox on its Network info card)
# =========================================================================================
class FakeConfig:
    """Just enough of ``tnt.config.Config`` for the monitor: one dotted get."""

    def __init__(self, excluded: Any = ()) -> None:
        self.excluded = excluded
        self.asked = 0

    def get(self, dotted: str, default: Any = None) -> Any:
        assert dotted == "throughput.excluded", dotted
        self.asked += 1
        return self.excluded


def excluding(names: Any, rows: List[List[throughput.Counters]], *, primary: Optional[int] = 1,
              bus: Any = None) -> "tuple[throughput.ThroughputMonitor, FakeClock, FakeConfig]":
    clock = FakeClock()
    calls = [0]
    cfg = FakeConfig(names)

    def reader() -> List[throughput.Counters]:
        i = min(calls[0], len(rows) - 1)
        calls[0] += 1
        return list(rows[i])

    mon = throughput.ThroughputMonitor(bus, config=cfg, clock=clock, reader=reader, primary_fn=lambda: primary)
    return mon, clock, cfg


def three(rx: int) -> List[throughput.Counters]:
    return [counters(1, index=12, name="Ethernet", rx_bytes=rx),
            counters(2, index=18, name="Ethernet 2", rx_bytes=rx),
            counters(3, index=32, name="Tailscale", if_type=53, rx_bytes=rx)]


def names_of(mon: throughput.ThroughputMonitor, event: Any) -> "tuple[list, list]":
    return ([n["name"] for n in (event or {}).get("nics", [])],
            [n["name"] for n in mon.view(30)["nics"]])


def test_an_adapter_on_the_excluded_list_is_left_off_the_card_and_out_of_the_event():
    mon, clock, _ = excluding(["Ethernet 2"], [three(0), three(125_000)])
    mon.tick()
    clock.now += 1.0
    event, view = names_of(mon, mon.tick())
    assert event == ["Ethernet", "Tailscale"] and view == ["Ethernet", "Tailscale"]


def test_the_name_is_matched_the_way_a_person_would_type_it():
    """Case and stray spaces come from a hand-edited config; neither should silently stop working."""
    for spelling in ("Ethernet 2", "  ethernet 2 ", "ETHERNET 2"):
        mon, clock, _ = excluding([spelling], [three(0), three(125_000)])
        mon.tick()
        clock.now += 1.0
        event, view = names_of(mon, mon.tick())
        assert event == ["Ethernet", "Tailscale"], spelling
        assert view == ["Ethernet", "Tailscale"], spelling


def test_the_internet_facing_nic_can_be_hidden_too():
    """view() keeps the primary NIC even when it is flat - but not when it was asked to hide it."""
    mon, clock, _ = excluding(["Ethernet"], [three(0), three(125_000)], primary=1)
    mon.tick()
    clock.now += 1.0
    event, view = names_of(mon, mon.tick())
    assert "Ethernet" not in event and "Ethernet" not in view
    assert view == ["Ethernet 2", "Tailscale"]


def test_hiding_every_adapter_empties_the_card_rather_than_showing_them_all_again():
    """view() lists everything when nothing moved, so the exclusion has to be applied first -
    otherwise hiding the last adapter would bring all of them back."""
    mon, clock, _ = excluding(["Ethernet", "Ethernet 2", "Tailscale"], [three(0), three(125_000)])
    mon.tick()
    clock.now += 1.0
    event, view = names_of(mon, mon.tick())
    assert event == [] and view == []
    assert mon.view(30)["note"] is None, "an empty card is not an error"


def test_a_hidden_adapter_is_still_sampled_so_unticking_the_box_brings_its_history_back():
    rows = ramp(2, [125_000] * 6, index=18, name="Ethernet 2")
    mon, clock, cfg = excluding(["Ethernet 2"], [[r] for r in rows])
    for _ in rows:
        mon.tick()
        clock.now += 1.0
    assert mon.view(30)["nics"] == []
    cfg.excluded = []                                  # the box is unticked
    nics = mon.view(30)["nics"]
    assert [n["name"] for n in nics] == ["Ethernet 2"]
    assert len(nics[0]["samples"]) == 5, "the history it kept while hidden is there"


def test_nothing_is_hidden_without_a_config_or_when_reading_it_fails():
    """A settings read that failed must not blank the card - the counters are the point of it."""
    mon, clock, _ = monitor([three(0), three(125_000)], primary=1)      # no config at all
    mon.tick()
    clock.now += 1.0
    assert len(mon.tick()["nics"]) == 3

    class Boom:
        def get(self, dotted: str, default: Any = None) -> Any:
            raise OSError("settings unreadable")

    clock2 = FakeClock()
    calls = [0]
    rows = [three(0), three(125_000)]

    def reader() -> List[throughput.Counters]:
        i = min(calls[0], len(rows) - 1)
        calls[0] += 1
        return list(rows[i])

    mon2 = throughput.ThroughputMonitor(None, config=Boom(), clock=clock2, reader=reader, primary_fn=lambda: 1)
    mon2.tick()
    clock2.now += 1.0
    assert len(mon2.tick()["nics"]) == 3
    assert mon2._excluded() == frozenset()


def test_a_list_that_is_not_a_list_of_names_hides_nothing():
    for junk in (None, "Ethernet", 7, [None, 3, ""], {}):
        mon, clock, _ = excluding(junk, [three(0), three(125_000)])
        mon.tick()
        clock.now += 1.0
        assert len(mon.tick()["nics"]) == 3, junk


def test_the_setting_is_read_fresh_so_a_box_takes_effect_on_the_next_tick():
    """Not cached: a tick-old answer leaves a hidden NIC on the card for a second after the click."""
    mon, clock, cfg = excluding([], [three(0), three(125_000), three(250_000)])
    mon.tick()
    clock.now += 1.0
    assert len(mon.tick()["nics"]) == 3
    cfg.excluded = ["Tailscale"]
    clock.now += 1.0
    assert [n["name"] for n in mon.tick()["nics"]] == ["Ethernet", "Ethernet 2"]


def test_the_config_keeps_the_excluded_list_tidy():
    from tnt import config

    assert config.DEFAULTS["throughput"] == {"excluded": []}
    assert config.clean_nic_names(["  Ethernet ", "ETHERNET", "Wi-Fi", "", 7, None]) == ["Ethernet", "Wi-Fi"]
    for junk in (None, "Ethernet", 42, {"a": 1}):
        assert config.clean_nic_names(junk) == []
    assert len(config.clean_nic_names([str(i) for i in range(config.MAX_EXCLUDED_NICS + 50)])) \
        == config.MAX_EXCLUDED_NICS
    # it survives a round trip through validate, and a missing section is the default
    assert config.validate({"throughput": {"excluded": ["Ethernet", "ethernet"]}})["throughput"]["excluded"] == ["Ethernet"]
    assert config.validate({})["throughput"] == {"excluded": []}
    assert config.validate({"throughput": {"excluded": "nonsense"}})["throughput"] == {"excluded": []}


# =========================================================================================
# the native layer (real iphlpapi)
# =========================================================================================
@pytest.mark.skipif(sys.platform != "win32", reason="native Windows layer")
def test_the_row_layout_matches_what_windows_expects():
    """``MIB_IF_ROW2`` is 1352 bytes on x64 and the table's rows start at 8, not 4: the row's
    ``NET_LUID`` needs 8-byte alignment, so the count is followed by four bytes of padding."""
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        pytest.skip("x64 offsets")
    assert ctypes.sizeof(throughput.MIB_IF_ROW2) == 1352
    assert throughput.MIB_IF_TABLE2.Table.offset == 8
    for name, offset in (("InterfaceLuid", 0), ("InterfaceIndex", 8), ("Alias", 28), ("Description", 542),
                         ("InterfaceAndOperStatusFlags", 1152), ("OperStatus", 1156),
                         ("InOctets", 1208), ("OutOctets", 1280), ("OutQLen", 1344)):
        assert getattr(throughput.MIB_IF_ROW2, name).offset == offset, name


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows layer")
def test_reading_the_real_counters_gives_one_row_per_adapter_and_no_duplicates():
    rows = throughput.read_counters()
    assert rows, "this machine has no eligible interface at all"
    luids = [r.luid for r in rows]
    assert len(luids) == len(set(luids))
    # the giveaway for a filter row slipping through: two interfaces with identical big counters
    busy = [(r.rx_bytes, r.tx_bytes) for r in rows if r.rx_bytes > 1_000_000]
    assert len(busy) == len(set(busy)), f"filter interfaces are being counted: {[r.name for r in rows]}"
    for r in rows:
        assert r.if_type != throughput.IF_TYPE_SOFTWARE_LOOPBACK
        assert r.rx_bytes >= 0 and r.tx_packets >= 0
        assert r.link_bps is None or r.link_bps > 0


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows layer")
def test_a_monitor_on_the_real_table_measures_this_pc():
    mon = throughput.ThroughputMonitor(None)
    assert mon.tick() is None            # first reading
    import time as _time

    _time.sleep(1.1)
    event = mon.tick()
    assert event and event["nics"]
    view = mon.view(30)
    assert set(view) == set(throughput.VIEW_KEYS) and view["note"] is None
    for nic in view["nics"]:
        assert set(nic) == set(throughput.NIC_KEYS)
        assert nic["rx_bps"] >= 0 and nic["tx_bps"] >= 0
        assert nic["name"]


# =========================================================================================
# the card (ui/js/throughput.js) and the chart (ui/js/charts.js)
# =========================================================================================
_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const window = { TNT: {} };
const ctx = vm.createContext({ window, console, document: undefined });
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'throughput.js' });
const tp = window.TNT.throughput;
const out = {};

out.rate = ['0 bps', 900, 1000, 9950, 224000, 7100000, 26000000, 1230000000, 0, -5, null]
  .map((v) => tp.rateText(typeof v === 'string' ? 0 : v));
out.rateNamed = {
  zero: tp.rateText(0), sub: tp.rateText(900), kb: tp.rateText(224000),
  mb: tp.rateText(7100000), mbWhole: tp.rateText(26000000), gb: tp.rateText(1230000000),
  bad: tp.rateText(null), neg: tp.rateText(-5),
};
out.count = { plain: tp.countText(321273647), zero: tp.countText(0), bad: tp.countText(null), neg: tp.countText(-1) };
out.link = { g: tp.linkText(1e9), g25: tp.linkText(2500000000), m: tp.linkText(866000000), none: tp.linkText(0), nul: tp.linkText(null) };

// which NICs the card shows: primary always, anything that moved inside the window, nothing else
const now = 1000;
const mk = (id, primary, samples) => ({ id, name: id, primary, samples });
out.shown = tp.shown([
  mk('eth', true, [[999, 0, 0, 0, 0]]),                 // primary and flat: kept
  mk('idle', false, [[999, 0, 0, 0, 0]]),               // up but silent: left out
  mk('busy', false, [[999, 40, 0, 1, 0]]),              // moving: kept
  mk('stale', false, [[900, 5000, 5000, 9, 9]]),        // moved, but before the window: left out
  mk('empty', false, []),
], 30, now).map((n) => n.id);

// the average rule is the mean of the points on the chart, not of the whole window
out.avg = {
  three: tp.average([[999, 10, 2, 0, 0], [998, 20, 4, 0, 0], [997, 30, 6, 0, 0]], 1, 30, now),
  tx: tp.average([[999, 10, 2, 0, 0], [998, 20, 4, 0, 0]], 2, 30, now),
  outside: tp.average([[100, 900, 900, 0, 0]], 1, 30, now),
  empty: tp.average([], 1, 30, now),
};

// merging a live sample into the series
let s = [];
tp.push(s, [10, 1, 1, 1, 1]); tp.push(s, [11, 2, 2, 2, 2]); tp.push(s, [11, 9, 9, 9, 9]);
tp.push(s, [9, 5, 5, 5, 5]); tp.push(s, [13, 4, 4, 4, 4]);
out.push = s.map((r) => [r[0], r[1]]);
let cap = [];
for (let i = 0; i < tp.HISTORY_S + 25; i++) tp.push(cap, [i, i, i, i, i]);
out.cap = { len: cap.length, first: cap[0][0], last: cap[cap.length - 1][0] };

out.windows = tp.WINDOWS.map((w) => w[0]);
out.labels = tp.WINDOWS.map((w) => w[2]);
out.spec = { known: tp.windowSpec(300)[1], unknown: tp.windowSpec(7)[0] };
process.stdout.write(JSON.stringify(out));
"""

_CHART_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
// charts.js only touches the DOM inside a chart's constructor; a stub canvas is enough to
// reach the arithmetic (the axis top, the runs a gap is cut into) without a browser.
const listeners = [];
const canvas = {
  addEventListener: () => {}, removeEventListener: () => {}, parentElement: null,
  getBoundingClientRect: () => ({ width: 600, height: 140 }), isConnected: false,
  getContext: () => ({}), width: 600, height: 140,
};
const window = {
  TNT: {}, devicePixelRatio: 1, addEventListener: () => {}, removeEventListener: () => {},
  requestAnimationFrame: () => 0, cancelAnimationFrame: () => {},
  getComputedStyle: () => ({ getPropertyValue: () => '#6FA8FF', fontFamily: 'sans-serif' }),
};
const document = { documentElement: {}, body: {}, createElement: () => ({ style: {} }) };
const ctx = vm.createContext({ window, document, console, ResizeObserver: undefined,
                               requestAnimationFrame: () => 0, cancelAnimationFrame: () => {} });
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'charts.js' });
const C = window.TNT.charts;
const out = {};
out.exports = ['Throughput', 'niceCeil', 'niceStep'].map((k) => typeof C[k]);
out.niceCeil = [0, -3, 1, 1.1, 7, 12, 99, 101, 999, 1234567, 100000].map((v) => C.niceCeil(v));

const chart = new C.Throughput(canvas, { windowS: 30, stepS: 1 });
chart.now = 1000;
// the axis never collapses onto a single stray packet, and it rounds up with headroom
out.topIdle = chart.top();
chart.rx = [[990, 8000000], [995, 9000000]];
chart.tx = [[990, 100000]];
out.topBusy = chart.top();
out.topAbovePeak = chart.top() > 9000000;
// points outside the window do not stretch the axis
chart.rx = [[100, 900000000], [995, 200000]];
out.topIgnoresOld = chart.top();
chart.rx = [[100, 900000000]]; chart.tx = [];
out.topAllOld = chart.top();

// runs: a hole wider than two steps breaks the line instead of drawing across it
chart.stepS = 1;
chart.rx = [[990, 1], [991, 1], [992, 1], [996, 1], [997, 1]];
out.runs = chart.runs(chart.rx).map((r) => r.map((p) => p[0]));
chart.stepS = 3;
out.runsCoarse = chart.runs(chart.rx).map((r) => r.map((p) => p[0]));
chart.stepS = 1;
chart.rx = [[900, 1], [995, 1]];
out.runsWindow = chart.runs(chart.rx).map((r) => r.map((p) => p[0]));
out.minTop = C.Throughput.MIN_TOP_BPS;
process.stdout.write(JSON.stringify(out));
"""


def _node(driver: str, tmp_path: Path, *args: str) -> Any:
    """Run a driver and parse what it printed.

    ``encoding="utf-8"`` rather than ``text=True``: node writes UTF-8 whatever the console is,
    and on a cp1252 machine the default decode turns the em-dash these helpers use for "unknown"
    into three characters.
    """
    path = tmp_path / "driver.js"
    path.write_text(driver, encoding="utf-8")
    r = subprocess.run(["node", str(path), *args], capture_output=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_cards_arithmetic_with_node(tmp_path):
    out = _node(_DRIVER, tmp_path, str(UI / "js/throughput.js"))

    # Task Manager's units: one decimal below ten of the unit, whole above, so the text does not jitter
    assert out["rateNamed"] == {"zero": "0 bps", "sub": "900 bps", "kb": "224 Kbps", "mb": "7.1 Mbps",
                                "mbWhole": "26 Mbps", "gb": "1.2 Gbps", "bad": "0 bps", "neg": "0 bps"}
    assert out["count"] == {"plain": "321,273,647", "zero": "0", "bad": "—", "neg": "—"}
    assert out["link"] == {"g": "1 Gbps", "g25": "2.5 Gbps", "m": "866 Mbps", "none": "", "nul": ""}

    # the card applies the same rule the service does, which is what lets a NIC that wakes up
    # appear without refetching anything
    assert out["shown"] == ["eth", "busy"]

    assert out["avg"] == {"three": 20, "tx": 3, "outside": 0, "empty": 0}

    # merging: in order, a repeat replaces, an out-of-order sample is inserted, and it stops at 30 min
    assert out["push"] == [[9, 5], [10, 1], [11, 9], [13, 4]]
    # 1825 pushed, half an hour kept: the oldest 25 fell off the front and the newest is still there
    assert out["cap"] == {"len": 1800, "first": 25, "last": 1824}

    assert out["windows"] == list(throughput.WINDOWS)
    assert out["labels"] == ["10 seconds", "30 seconds", "60 seconds", "5 minutes", "30 minutes"]
    assert out["spec"] == {"known": "5 min", "unknown": 30}


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_throughput_chart_scales_and_breaks_its_line_with_node(tmp_path):
    out = _node(_CHART_DRIVER, tmp_path, str(UI / "js/charts.js"))
    assert out["exports"] == ["function", "function", "function"]
    assert out["niceCeil"] == [0, 0, 1, 1.5, 8, 15, 100, 150, 1000, 1500000, 100000]

    # an idle adapter's stray packet must not be amplified to a full-height spike
    assert out["topIdle"] == out["minTop"] == 100000
    assert out["topBusy"] >= 9000000 and out["topAbovePeak"] is True
    # a point that has scrolled off the left does not keep the axis stretched: the 900 Mbps
    # reading at ts 100 is outside the 30 s window, so only the 200 kbps one inside it counts
    assert out["topIgnoresOld"] == 250000
    assert out["topAllOld"] == out["minTop"]

    # a hole wider than two steps is a break in the line, not a straight run across it
    assert out["runs"] == [[990, 991, 992], [996, 997]]
    assert out["runsCoarse"] == [[990, 991, 992, 996, 997]]   # at 3 s a 4 s hole is within tolerance
    assert out["runsWindow"] == [[995]]                        # 900 is outside a 30 s window



_HIDE_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
// views/ipinfo.js only touches the DOM inside its functions; the three helpers under test are pure
// apart from reading TNT.state, which the driver sets.
const window = { TNT: { views: {}, util: {}, ui: {}, api: {}, charts: {}, netcheck: {}, throughput: {} } };
const ctx = vm.createContext({ window, console, document: undefined, localStorage: undefined });
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'ipinfo.js' });
const v = window.TNT.views.ipinfo;
const out = {};

const state = (excluded) => ({ settings: { throughput: { excluded } } });
out.read = {
  plain: v.excludedNics(state(['Ethernet 2'])),
  junkEntries: v.excludedNics(state(['Ethernet', 3, null, '  ', 'Wi-Fi'])),
  notAList: v.excludedNics(state('Ethernet')),
  missing: v.excludedNics({ settings: {} }),
  noState: v.excludedNics({}),
};
out.is = {
  exact: v.nicExcluded('Ethernet 2', state(['Ethernet 2'])),
  otherCase: v.nicExcluded('ethernet 2', state(['ETHERNET 2'])),
  spaced: v.nicExcluded(' Ethernet 2 ', state(['Ethernet 2'])),
  no: v.nicExcluded('Ethernet', state(['Ethernet 2'])),
  blank: v.nicExcluded('', state([''])),
  nullName: v.nicExcluded(null, state(['Ethernet'])),
};
out.next = {
  add: v.nextExcluded([], 'Ethernet 2', true),
  addToExisting: v.nextExcluded(['Wi-Fi'], 'Ethernet 2', true),
  noDuplicate: v.nextExcluded(['Ethernet 2'], 'Ethernet 2', true),
  replacesOtherCase: v.nextExcluded(['ETHERNET 2'], 'Ethernet 2', true),
  remove: v.nextExcluded(['Wi-Fi', 'Ethernet 2'], 'Ethernet 2', false),
  removesEveryCase: v.nextExcluded(['ethernet 2', 'Ethernet 2', 'Wi-Fi'], 'ETHERNET 2', false),
  removeMissing: v.nextExcluded(['Wi-Fi'], 'Ethernet 2', false),
  trims: v.nextExcluded([], '  Ethernet 2  ', true),
  blankName: v.nextExcluded(['Wi-Fi'], '', true),
};
process.stdout.write(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_hide_checkboxs_arithmetic_with_node(tmp_path):
    out = _node(_HIDE_DRIVER, tmp_path, str(UI / "js/views/ipinfo.js"))

    assert out["read"] == {"plain": ["Ethernet 2"], "junkEntries": ["Ethernet", "Wi-Fi"],
                           "notAList": [], "missing": [], "noState": []}
    assert out["is"] == {"exact": True, "otherCase": True, "spaced": True,
                         "no": False, "blank": False, "nullName": False}
    # ticking adds the name once however the list already spells it; unticking removes every spelling
    assert out["next"] == {
        "add": ["Ethernet 2"], "addToExisting": ["Wi-Fi", "Ethernet 2"],
        "noDuplicate": ["Ethernet 2"], "replacesOtherCase": ["Ethernet 2"],
        "remove": ["Wi-Fi"], "removesEveryCase": ["Wi-Fi"], "removeMissing": ["Wi-Fi"],
        "trims": ["Ethernet 2"], "blankName": ["Wi-Fi"],
    }


def test_every_adapter_card_ends_with_the_hide_checkbox():
    """The checkbox is the card's last row and writes the same setting the service reads."""
    src = (UI / "js/views/ipinfo.js").read_text(encoding="utf-8")
    start = src.index("    return h('div', { class: 'card adapter'")
    built = src[start:src.index("\n  }", start)]
    assert built.rstrip().endswith("throughputBox(a));"), "the checkbox is not the card's last row"
    assert "TNT.api.updateSettings({ throughput: { excluded:" in src
    assert "'Hide from Realtime throughput'" in src
    # a name is the key on both sides: a card with no name cannot be matched, so its box is dead
    assert "input.disabled = !name;" in src
    css = (UI / "css/tnt.css").read_text(encoding="utf-8")
    assert ".adapter-tp {" in css and ".adapter-tp input {" in css


def test_the_throughput_card_drops_a_nic_the_service_stops_sending():
    """Hiding one has to take it off the chart now, not when its last samples age out - which for
    the 30 minute window would be half an hour later."""
    src = (UI / "js/throughput.js").read_text(encoding="utf-8")
    assert "for (const key of Array.from(nics.keys())) if (!live.has(key)) nics.delete(key);" in src
    assert "if (seenIds.has(n.id)) seed();" in src, "a NIC that comes back asks for its backlog"
    assert "Every adapter is hidden." in src


def test_the_card_and_the_chart_are_loaded_by_the_page():
    html = (UI / "index.html").read_text(encoding="utf-8")
    assert '<script src="js/throughput.js"></script>' in html
    # after charts.js (the card builds a TNT.charts.Throughput) and before the views that use it
    assert html.index("js/charts.js") < html.index("js/throughput.js") < html.index("js/views/ipinfo.js")


def test_the_network_info_view_puts_the_card_between_the_link_map_and_the_nat_card():
    """Every path that lays the grid out draws them in the same order, including the one that runs
    while the adapters are still loading - otherwise the card appears a moment later and shoves the
    page down under the reader."""
    src = (UI / "js/views/ipinfo.js").read_text(encoding="utf-8")
    paths = [m.end() for m in __import__("re").finditer(r"gridEl\.appendChild\(buildMapCard\(\)\);", src)]
    assert len(paths) == 2, "a new render path was added without the two live cards"
    for start in paths:
        body = src[start:start + 400]
        assert body.index("tp.el") < body.index("nc.el"), body
    assert "TNT.throughput.create()" in src and "tp.unmount()" in src


def test_the_windows_the_card_offers_are_the_ones_the_service_keeps():
    src = (UI / "js/throughput.js").read_text(encoding="utf-8")
    listed = [int(m) for m in __import__("re").findall(r"^\s*\[(\d+), '", src, __import__("re").M)]
    assert listed == list(throughput.WINDOWS)
    assert f"const HISTORY_S = {throughput.HISTORY_S};" in src


def test_the_event_is_one_the_page_listens_for():
    src = (UI / "js/api.js").read_text(encoding="utf-8")
    assert "'throughput.sample'" in src and "throughput: (windowS)" in src
