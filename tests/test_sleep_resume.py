"""Sleep, resume and clock steps: what a laptop closed overnight, or a clock set back, does to the numbers.

Four things used to go wrong, each with a technician-visible result:

* **Outages.** An echo request in flight when the lid closed came back after the wake stamped with the
  moment it was *sent*, before the sleep.  When the Engine's maintenance thread had already recorded the
  sleep as a monitoring gap (which resets every miss run), that late miss started a new run and two
  post-wake misses (Wi-Fi re-associating) opened an outage back-dated to before the sleep: an eight-hour
  outage of a target that answered five seconds after the wake.
* **Throughput spikes.** The sampler stamped every reading with the second it was *scheduled* for, not the
  time it was taken, so the rate was divided by the wrong span: a read held up 1.8 s became a 2.8x spike
  and a hole, and the first reading after an eight-hour sleep published the whole sleep's bytes as one
  second (28 Gbps on a 1 Mbps flow) because the ``MAX_SPAN_S`` guard never saw the real span.
* **Throughput freeze.** The sampler scheduled on the wall clock but waited on ``threading.Event``, which
  measures on the monotonic clock, so a clock stepped back an hour put the card to sleep for the hour.
* **Speed test after a resume.** The overdue scheduled test fired on the scheduler thread before the
  maintenance thread's ``monitoring.gap`` could hold it off: "Speed test failed: gaierror" after most
  resumes, and later an "N tests failed" pattern on a network that was fine.

Everything here runs on injected clocks and stand-ins for the waits; nothing sleeps for real longer than
a fraction of a second at a time (the speed scheduler's own thread is given a few of its polls), except
the one check on the real sampler thread (under two seconds, two of its ticks).  Addresses are
documentation ranges only.
"""
from __future__ import annotations

import ipaddress
import logging
import math
import sys
import threading
import time
import types
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from tnt import config as tnt_config
from tnt import db as tnt_db
from tnt import events as tnt_events
from tnt import outages, throughput
from tnt.pinger import PingManager, RawPingLog, Sample
from tnt.speedtest import scheduler as sched_mod
from tnt.speedtest.base import SpeedResult

T0 = 1_800_000_000.0
EIGHT_H = 8 * 3600.0
INTERNET = "203.0.113.10"          # stands for an internet target (TEST-NET-3)


def wait_until(pred: Callable[[], bool], timeout: float = 5.0, step: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return pred()


class FakeClock:
    """A clock the test moves by hand; thread-safe, because the speed scheduler reads it on its own thread."""

    def __init__(self, now: float = T0) -> None:
        self._now = float(now)
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self._now

    @property
    def now(self) -> float:
        return self()

    @now.setter
    def now(self, value: float) -> None:
        with self._lock:
            self._now = float(value)

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._now += float(seconds)


# =========================================================================================
# outages: the echo that was in flight when the lid closed
# =========================================================================================
class FakePingManager:
    """Just enough of PingManager for the OutageTracker: views, the in-outage flag and the sample listeners."""

    def __init__(self) -> None:
        self.views: Dict[int, Dict[str, Any]] = {}
        self._listeners: List[Callable] = []

    def add(self, tid: int, host: str, kind: str = "internet") -> None:
        self.views[tid] = {"id": tid, "host": host, "label": None, "kind": kind, "ip": host, "enabled": True,
                           "resolved": True, "resolve_error": None, "light": "grey", "in_outage": False,
                           "last": None, "consecutive_missed": 0, "consecutive_ok": 0}

    def targets(self) -> List[Dict[str, Any]]:
        return [dict(v) for v in self.views.values()]

    def set_in_outage(self, tid: int, flag: bool) -> None:
        self.views[tid]["in_outage"] = bool(flag)

    def add_sample_listener(self, fn: Callable) -> Callable[[], None]:
        self._listeners.append(fn)
        return lambda: self._listeners.remove(fn)

    def feed(self, tid: int, ts: float, ok: bool) -> None:
        v = self.views[tid]
        v["last"] = {"ts": ts, "ok": ok, "rtt_ms": 20.0 if ok else None}
        for fn in list(self._listeners):
            fn(dict(v), Sample(ts=ts, ok=ok, rtt_ms=20.0 if ok else None))


@pytest.fixture
def tracked(data_dir):
    """A real OutageTracker on a real database, fed by hand: ``feed`` moves the clock with the samples,
    the way a ping worker delivers them."""
    database = tnt_db.Database(data_dir / "sleep.db")
    pm = FakePingManager()
    clock = FakeClock()
    tracker = outages.OutageTracker(database, tnt_config.Config().load(), tnt_events.EventBus(), pm, clock=clock)
    tracker.start()

    def feed(tid: int, ts: float, ok: bool) -> None:
        clock.now = max(clock.now, ts)
        pm.feed(tid, ts, ok)

    def outage_rows() -> List[Tuple[str, float, float, int]]:
        return sorted((r["kind"], r["start_ts"], r["end_ts"], r["missed"])
                      for r in database.list_outages(T0 - 10, T0 + 3 * EIGHT_H) if r["kind"] != "gap")

    yield SimpleNamespace(db=database, pm=pm, clock=clock, tracker=tracker, feed=feed, outage_rows=outage_rows)
    tracker.stop()
    database.close()


def _healthy_then_asleep(t: SimpleNamespace) -> Tuple[float, float, float]:
    """30 s of answers, then the lid closes with an echo in flight.  Returns (t_sleep, last heartbeat, t_wake).

    The Engine dates a sleep gap from its last heartbeat, up to 30 s before the lid closed, so the late echo is
    stamped *inside* the gap, not before it: only the gap's end tells it from a measurement of the network the
    machine woke on."""
    t.pm.add(1, INTERNET)
    for i in range(30):
        t.feed(1, T0 + i, True)
    t_sleep = T0 + 30.0
    return t_sleep, t_sleep - 10.0, t_sleep + EIGHT_H


def test_an_echo_in_flight_across_a_sleep_does_not_back_date_an_outage_when_the_gap_is_recorded_first(tracked):
    """The maintenance thread notices the heartbeat silence four seconds after the wake and records the gap;
    only then does the ping worker hand over its late miss, stamped when it was sent, before the sleep.
    Two post-wake misses while the Wi-Fi re-associates are then not three in a row: nothing opens."""
    t = tracked
    t_sleep, last_hb, t_wake = _healthy_then_asleep(t)
    t.clock.now = t_wake + 4.0
    t.tracker.on_monitoring_gap(last_hb, t.clock.now, "system sleep")
    t.feed(1, t_sleep, False)                       # IcmpSendEcho2 returns after the wake: a "timeout"
    for i in (5, 6):
        t.feed(1, t_wake + i, False)                # re-associating
    for i in range(7, 12):
        t.feed(1, t_wake + i, True)                 # and it answers
    assert t.outage_rows() == [], "an outage back-dated to before the sleep, on a target that answered 7 s after it"
    status = t.tracker.status()
    assert status["count_24h"] == 0 and status["last"] is None and status["active"] == []


def test_the_late_echo_landing_before_the_gap_is_recorded_changes_nothing_either(tracked):
    """The other order of the same race: the gap's reset throws the late miss away."""
    t = tracked
    t_sleep, last_hb, t_wake = _healthy_then_asleep(t)
    t.clock.now = t_wake
    t.feed(1, t_sleep, False)
    t.tracker.on_monitoring_gap(last_hb, t_wake + 4.0, "system sleep")
    for i in (5, 6):
        t.feed(1, t_wake + i, False)
    for i in range(7, 12):
        t.feed(1, t_wake + i, True)
    assert t.outage_rows() == []


def test_a_real_outage_after_the_wake_starts_at_its_own_first_miss_not_before_the_sleep(tracked):
    """The target really is down after the wake: the outage opens, dated from the first post-wake miss.
    Back-dating it to the stale echo would claim the network was down all night."""
    t = tracked
    t_sleep, last_hb, t_wake = _healthy_then_asleep(t)
    t.clock.now = t_wake + 4.0
    t.tracker.on_monitoring_gap(last_hb, t.clock.now, "system sleep")
    t.feed(1, t_sleep, False)
    for i in range(5, 15):
        t.feed(1, t_wake + i, False)
    open_rows = {r["kind"]: r for r in t.db.open_outages()}
    assert set(open_rows) == {"target", "total_internet"}
    assert open_rows["target"]["start_ts"] == t_wake + 5
    assert open_rows["total_internet"]["start_ts"] == t_wake + 5
    assert open_rows["target"]["missed"] == 10, "the stale echo is not one of the misses"


def test_only_the_echo_that_was_in_flight_is_set_aside_so_a_clock_set_back_after_the_wake_blinds_nothing(tracked):
    """Once a target has delivered a sample after the gap, its next ones count whatever they are stamped:
    w32time setting the clock back an hour after the resume must not hide an outage for that hour."""
    t = tracked
    _t_sleep, last_hb, t_wake = _healthy_then_asleep(t)
    t.clock.now = t_wake + 4.0
    t.tracker.on_monitoring_gap(last_hb, t.clock.now, "system sleep")
    t.feed(1, t_wake + 5, True)                     # the first sample after the gap: fresh
    stepped = t_wake + 6 - 3600.0                   # the clock is set back an hour
    t.clock.now = stepped
    for i in range(4):
        t.pm.feed(1, stepped + i, False)            # stamped before the gap ended, yet measured now
    open_rows = {r["kind"]: r for r in t.db.open_outages()}
    assert open_rows["target"]["start_ts"] == stepped


def test_a_target_whose_first_sample_after_the_gap_is_fresh_loses_nothing(tracked):
    t = tracked
    _t_sleep, last_hb, t_wake = _healthy_then_asleep(t)
    t.clock.now = t_wake + 4.0
    t.tracker.on_monitoring_gap(last_hb, t.clock.now, "system sleep")
    for i in range(5, 8):
        t.feed(1, t_wake + i, False)
    assert [r["start_ts"] for r in t.db.open_outages() if r["kind"] == "target"] == [t_wake + 5]


def test_an_outage_open_when_the_lid_closed_is_not_reopened_back_dated_by_the_echo_that_was_in_flight(tracked):
    """The target was really down before the sleep.  The gap closes that outage where monitoring stopped; the late
    echo must not start a new run there, or two misses after the wake reopen it across the whole night."""
    t = tracked
    t.pm.add(1, INTERNET)
    for i in range(10):
        t.feed(1, T0 + i, True)
    for i in range(10, 20):
        t.feed(1, T0 + i, False)                    # down: an outage from T0 + 10
    t_sleep, last_hb = T0 + 20.0, T0 + 15.0
    t_wake = t_sleep + EIGHT_H
    t.clock.now = t_wake + 4.0
    t.tracker.on_monitoring_gap(last_hb, t.clock.now, "system sleep")
    t.feed(1, t_sleep, False)                       # the echo that was out when the lid closed
    for i in (5, 6):
        t.feed(1, t_wake + i, False)
    for i in range(7, 12):
        t.feed(1, t_wake + i, True)
    targets = [r for r in t.outage_rows() if r[0] == "target"]
    assert targets == [("target", T0 + 10, last_hb, 10)], targets
    assert all(end <= last_hb for _k, _s, end, _m in t.outage_rows()), t.outage_rows()


# ----------------------------------------------------------------------------------------- the real PingManager
@dataclass
class FakeResult:
    ok: bool
    rtt_ms: Optional[float]
    status: int = 0
    error: Optional[str] = None
    ttl: Optional[int] = 57
    size: int = 32
    ip: str = ""


class ScriptedPinger:
    """Each item is ``(ok, seconds the call takes)``; the call moves both clocks on, the way IcmpSendEcho2 returning
    after a resume does.  A third item, when given, is how far the *wall* clock moves in that time instead (it was
    set back or forward on the wake).  The last item repeats."""

    def __init__(self, clock: FakeClock, script: List[Tuple[Any, ...]], mono: Optional[FakeClock] = None) -> None:
        self.clock = clock
        self.mono = mono
        self.script = list(script)

    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> FakeResult:
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        ok, takes = item[0], item[1]
        wall_moves = item[2] if len(item) > 2 else takes
        if wall_moves:
            self.clock.advance(wall_moves)
        if takes and self.mono is not None:
            self.mono.advance(takes)
        if ok:
            return FakeResult(True, 20.0, 0, None, 57, size, ip)
        return FakeResult(False, None, 11010, "Request timed out", None, size, ip)

    def close(self) -> None:
        pass


@pytest.fixture
def fake_netinfo(monkeypatch):
    """A stand-in tnt.netinfo: the TEST-NET-2/3 ranges stand for the internet, everything else is local."""
    mod = types.ModuleType("tnt.netinfo")
    internet = (ipaddress.ip_network("198.51.100.0/24"), ipaddress.ip_network("203.0.113.0/24"))

    def classify_ip(ip: str, adapters: Any = None) -> str:
        a = ipaddress.ip_address(ip.split("%")[0])
        return "internet" if any(a in n for n in internet) else "local"

    mod.classify_ip = classify_ip
    mod.get_default_gateway = lambda: "192.0.2.1"
    mod.get_adapters = lambda include_down=True, include_loopback=False: []
    monkeypatch.setitem(sys.modules, "tnt.netinfo", mod)
    return mod


@pytest.fixture
def pinged(tmp_path, data_dir, fake_netinfo):
    """A real PingManager and a real OutageTracker, ticked by hand on fake clocks: ``clock`` stamps the samples,
    ``mono`` is the monotonic clock the manager also times a call on (it counts the time asleep, and only the
    pinger's calls move it here)."""
    database = tnt_db.Database(tmp_path / "p.db")
    cfg = tnt_config.Config(tmp_path / "config.json").load()
    bus = tnt_events.EventBus()
    events: List[Dict[str, Any]] = []
    bus.subscribe(events.append)
    clock = FakeClock()
    mono = FakeClock(10_000.0)
    pinger = ScriptedPinger(clock, [(True, 0.0)], mono=mono)
    raw = RawPingLog(tmp_path / "pings", clock=clock)
    mgr = PingManager(database, cfg, bus, pinger=pinger, raw_log=raw, clock=clock,
                      sleep=lambda s: clock.advance(s), resolver=lambda h: None, monotonic=mono)
    tracker = outages.OutageTracker(database, cfg, bus, mgr, clock=clock)
    ns = SimpleNamespace(db=database, cfg=cfg, clock=clock, mono=mono, pinger=pinger, raw=raw, mgr=mgr,
                         tracker=tracker, events=events)

    def rows(kind: Optional[str] = None) -> List[Dict[str, Any]]:
        return [r for r in database.list_outages(T0 - 10, clock() + 10) if kind is None or r["kind"] == kind]

    ns.rows = rows
    yield ns
    tracker.stop()
    mgr.stop()
    raw.close()
    database.close()


def test_an_echo_whose_call_outlived_a_sleep_is_not_recorded_and_opens_nothing(pinged):
    """End to end on the real PingManager: the maintenance thread is modelled by a sample listener registered
    before the tracker's, which records the gap as soon as a sample shows the heartbeat is 90 s stale (the order
    in which the back-dated outage used to appear).  The echo that spanned the sleep is not a measurement."""
    p = pinged
    heartbeat = {"ts": T0}
    gaps: List[Tuple[float, float]] = []

    def maintenance(view: Dict[str, Any], sample: Sample) -> None:
        now = p.clock()
        if now - heartbeat["ts"] > 90.0:
            p.tracker.on_monitoring_gap(heartbeat["ts"], now, "system sleep")
            gaps.append((heartbeat["ts"], now))
            heartbeat["ts"] = now

    p.mgr.add_sample_listener(maintenance)
    p.tracker.start()
    tid = p.mgr.add_target(INTERNET)["id"]
    for _ in range(30):                              # healthy, a heartbeat every 30 s
        assert p.mgr.tick(tid).ok
        p.clock.advance(1.0)
        if p.clock() - heartbeat["ts"] >= 30.0:
            heartbeat["ts"] = p.clock()
    t_sleep = p.clock()
    p.pinger.script = [(False, EIGHT_H), (False, 0.0), (False, 0.0)] + [(True, 0.0)]
    assert p.mgr.tick(tid) is None, "the echo that spanned the sleep says nothing about the network after it"
    assert not [e for e in p.events if e["type"] == "ping.sample" and e["data"]["ts"] == t_sleep]
    assert all(s.ts != t_sleep for s in p.mgr.samples(tid, 10 ** 6))
    for _ in range(2):                               # re-associating after the wake
        p.clock.advance(1.0)
        assert p.mgr.tick(tid).ok is False
    for _ in range(5):
        p.clock.advance(1.0)
        assert p.mgr.tick(tid).ok
    assert gaps, "the first post-wake sample shows the heartbeat silence"
    assert [r["kind"] for r in p.rows()] == ["gap"], [(r["kind"], r["start_ts"], r["end_ts"]) for r in p.rows()]


def test_a_nap_too_short_for_a_monitoring_gap_does_not_turn_into_an_outage_either(pinged):
    """Sixty seconds with the lid closed is under the Engine's 90 s gap threshold, so nothing resets the miss run:
    the stale echo and two post-wake misses used to open an outage covering the nap."""
    p = pinged
    p.tracker.start()
    tid = p.mgr.add_target(INTERNET)["id"]
    for _ in range(10):
        p.mgr.tick(tid)
        p.clock.advance(1.0)
    p.pinger.script = [(False, 60.0), (False, 0.0), (False, 0.0)] + [(True, 0.0)]
    assert p.mgr.tick(tid) is None
    for _ in range(7):
        p.clock.advance(1.0)
        p.mgr.tick(tid)
    assert p.rows() == []


def test_an_echo_that_merely_timed_out_or_came_back_slowly_is_still_a_miss(pinged):
    """Only a call that outlived its own timeout by far is set aside: an ordinary timeout, and one a busy
    machine returned a few seconds late, are misses like any other."""
    p = pinged
    p.tracker.start()
    tid = p.mgr.add_target(INTERNET)["id"]
    timeout_s = float(p.cfg.get("ping.timeout_ms", 1000)) / 1000.0
    p.pinger.script = [(False, timeout_s), (False, timeout_s + 5.0), (False, 0.0)]
    first = p.mgr.tick(tid)
    second = p.mgr.tick(tid)
    third = p.mgr.tick(tid)
    assert [s.ok for s in (first, second, third)] == [False, False, False]
    assert [r["kind"] for r in p.rows() if r["kind"] == "target"] == ["target"]


def test_an_outage_open_when_the_lid_closed_is_not_extended_by_the_echo_that_was_out_across_the_sleep(pinged):
    """The other order: the late echo comes back before the maintenance thread records the gap, while the target's
    outage from before the sleep is still open.  Counted, it was one more miss of that outage, dated before the
    lid closed and measured after it opened.  The outage keeps the ten misses it really had."""
    p = pinged
    p.tracker.start()
    tid = p.mgr.add_target(INTERNET)["id"]
    p.pinger.script = [(False, 0.0)]
    for _ in range(10):                              # down before the sleep: an outage from the first miss
        p.mgr.tick(tid)
        p.clock.advance(1.0)
    assert [r["start_ts"] for r in p.db.open_outages() if r["kind"] == "target"] == [T0]
    p.pinger.script = [(False, EIGHT_H), (True, 0.0)]
    assert p.mgr.tick(tid) is None, "the echo out across the sleep is not a miss of the outage"
    p.tracker.on_monitoring_gap(T0 + 5.0, p.clock(), "system sleep")
    target = p.rows("target")
    assert len(target) == 1 and target[0]["missed"] == 10 and target[0]["end_ts"] == T0 + 5.0, target
    assert all(s.ts < T0 + 10.0 for s in p.mgr.samples(tid, 10 ** 6)), "a sample dated to the moment the lid closed"


def _raw_rows(p: SimpleNamespace) -> List[List[str]]:
    p.raw.flush()
    path = p.raw.current_path
    if path is None or not path.exists():
        return []
    return [line.split(",") for line in path.read_text(encoding="utf-8").splitlines()[1:]]


def test_an_echo_out_across_a_sleep_is_dropped_even_when_the_clock_is_set_back_on_the_wake(pinged):
    """The call is timed on the monotonic clock as well as the one that stamps the samples.  A twenty-minute nap,
    and w32time sets a clock that ran fast back twenty minutes on the wake: by the wall clock the call took half a
    second, and the late miss went into the card, the minute, the raw log and the listeners dated before the lid
    closed (the outage tracker alone was safe, and only when the gap reached it first)."""
    p = pinged
    p.tracker.start()
    tid = p.mgr.add_target(INTERNET)["id"]
    for _ in range(5):
        assert p.mgr.tick(tid).ok
        p.clock.advance(1.0)
    heard: List[Sample] = []
    p.mgr.add_sample_listener(lambda view, sample: heard.append(sample))
    p.pinger.script = [(False, 1200.0, 0.5), (True, 0.0)]      # 20 min asleep; the wall clock moves 0.5 s
    assert p.mgr.tick(tid) is None, "a call the monotonic clock says outlived its timeout by twenty minutes"
    assert heard == []
    assert all(s.ok for s in p.mgr.samples(tid, 10 ** 6))
    assert all(e["data"]["ok"] for e in p.events if e["type"] == "ping.sample")
    assert p.mgr.target(tid)["consecutive_missed"] == 0
    assert [r[3] for r in _raw_rows(p)] == ["1"] * 5, "a miss in the raw log dated before the sleep"
    p.clock.advance(1.0)
    assert p.mgr.tick(tid).ok, "the next call measures the network the machine woke on"


def test_a_clock_set_forward_while_an_echo_is_out_still_costs_only_that_one_sample(pinged):
    """Either clock showing the overrun drops the call: one set forward an hour mid-call, awake, loses that sample
    and no more."""
    p = pinged
    p.tracker.start()
    tid = p.mgr.add_target(INTERNET)["id"]
    p.pinger.script = [(True, 0.02, 3600.0), (True, 0.02)]
    assert p.mgr.tick(tid) is None
    for _ in range(3):
        p.clock.advance(1.0)
        assert p.mgr.tick(tid).ok


def test_the_echo_of_each_sleep_is_dropped_and_so_is_a_second_when_the_machine_only_woke_for_a_moment(pinged):
    """A sleep catches one echo per target.  A machine that wakes for a moment (a wake timer, a maintenance wake)
    and sleeps again before the worker's next call is back catches a second, straight after the first.  Every
    ordinary call in between starts the count again, so the next night's sleep is dropped the same way."""
    p = pinged
    p.tracker.start()
    tid = p.mgr.add_target(INTERNET)["id"]
    p.pinger.script = [(True, 0.0), (False, EIGHT_H), (False, 600.0)] + [(True, 0.0)] * 5 + [(False, EIGHT_H),
                                                                                              (True, 0.0)]
    got = []
    for _ in range(10):
        s = p.mgr.tick(tid)
        got.append(None if s is None else s.ok)
        p.clock.advance(1.0)
    assert got == [True, None, None, True, True, True, True, True, None, True]
    assert p.rows() == []


def test_a_ping_call_that_is_slow_every_time_is_recorded_again_not_dropped_for_ever(pinged, caplog):
    """A wedged ICMP or filter driver, a VPN client holding IcmpSendEcho2, a starved process: every call outlives its
    timeout by far.  That is not a sleep, which leaves one such call per target (two when the machine woke for a
    moment).  Dropping all of them left the card on its last reading, no outage could ever open, and the log got a
    line a tick.  From the third in a row they are recorded again, each dated when the call came back (never
    before a sleep that may be in it), and the log says so once, then every minute at most."""
    p = pinged
    p.tracker.start()
    tid = p.mgr.add_target(INTERNET)["id"]
    for _ in range(3):
        assert p.mgr.tick(tid).ok
        p.clock.advance(1.0)
    p.pinger.script = [(False, 30.0)]
    got: List[Tuple[float, Optional[Sample]]] = []
    with caplog.at_level(logging.INFO, logger="tnt.pinger"):
        for _ in range(8):
            sent = p.clock()
            got.append((sent, p.mgr.tick(tid)))
    assert [s is None for _t, s in got] == [True, True] + [False] * 6, got
    recorded = [(sent, s) for sent, s in got if s is not None]
    assert all(not s.ok for _t, s in recorded)
    assert [s.ts for _t, s in recorded] == [sent + 30.0 for sent, _s in recorded], "dated when the call came back"
    view = p.mgr.target(tid)
    assert view["consecutive_missed"] == 6 and view["last"]["ok"] is False
    opened = [r for r in p.db.open_outages() if r["kind"] == "target"]
    assert len(opened) == 1 and opened[0]["start_ts"] == recorded[0][1].ts, opened
    messages = [r.getMessage() for r in caplog.records if r.name == "tnt.pinger"]
    assert sum("dropping the echo" in m for m in messages) == 2, messages
    assert sum("keep taking" in m for m in messages) == 1, messages
    p.pinger.script = [(True, 0.0)]                  # the driver recovers: ordinary samples again
    assert p.mgr.tick(tid).ok
    p.pinger.script = [(False, EIGHT_H), (True, 0.0)]
    assert p.mgr.tick(tid) is None, "after an ordinary call, the next sleep's echo is dropped again"


# =========================================================================================
# throughput: stamps, spans and the sampler's waits
# =========================================================================================
class Machine:
    """The clocks a ThroughputMonitor reads and the NIC it measures, moved by hand.

    ``real`` is the time that really passed, which is what the NIC's counters follow (a steady flow, background
    sync going on through a Modern Standby sleep).  ``elapse`` is ordinary time passing: both clocks move.
    ``sleep`` is the machine asleep: the wall clock moves, and the monotonic clock too unless told it stops in
    sleep.  ``step`` is the wall clock being set (w32time, a VM restore, a hand correction): nothing else moves.
    """

    def __init__(self, bytes_per_s: int = 125_000) -> None:          # 1 Mbps
        self.wall = FakeClock(T0)
        self.mono = FakeClock(5_000.0)
        self.real = 0.0
        self.bytes_per_s = bytes_per_s

    def elapse(self, s: float) -> None:
        self.wall.advance(s)
        self.mono.advance(s)
        self.real += s

    def sleep(self, s: float, *, monotonic_counts: bool = True) -> None:
        self.wall.advance(s)
        self.real += s
        if monotonic_counts:
            self.mono.advance(s)

    def step(self, s: float) -> None:
        self.wall.advance(s)

    def counters(self) -> List[throughput.Counters]:
        rx = int(round(self.bytes_per_s * self.real))
        return [throughput.Counters(luid=1, index=12, name="Ethernet", description="Intel(R) I219-V", if_type=6,
                                    link_bps=1_000_000_000, rx_bytes=rx, tx_bytes=rx // 4, rx_packets=rx // 1000,
                                    tx_packets=rx // 4000)]


class Waits:
    """Stands in for the sampler's ``threading.Event``: ``wait`` lets the time pass instead of blocking, records
    how long it was asked to wait, and runs what the test scheduled for that wait (a sleep, a clock step)."""

    def __init__(self, machine: Machine) -> None:
        self.machine = machine
        self.asked: List[float] = []
        self.during: Dict[int, Callable[[], None]] = {}
        self.read_at: List[float] = []          # filled in by sampler(): when each reading was really taken
        self.done = False

    def is_set(self) -> bool:
        return self.done

    def set(self) -> None:
        self.done = True

    def clear(self) -> None:
        self.done = False

    def wait(self, timeout: Optional[float] = None) -> bool:
        self.asked.append(float(timeout or 0.0))
        self.machine.elapse(float(timeout or 0.0))
        also = self.during.get(len(self.asked))
        if also is not None:
            also()
        return self.done


class Bus:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def publish(self, event_type: str, data: Any = None) -> None:
        self.events.append(data)


#: The longest the sampler may wait for its next reading: the whole second after the one a reading taken at the
#: moment of the wait would be stamped with, at most a second and a half away (a clock set back an hour used to
#: be an hour's wait).
LONGEST_WAIT_S = 1.5
#: The shortest time between two of its readings, on the monotonic clock: a span shorter than this would turn a
#: counter the driver updates in steps into a spike.
SHORTEST_SPAN_S = 0.5


def sampler(ticks: int, *, two_clocks: bool = False, stalls: Optional[Dict[int, float]] = None,
            during: Optional[Dict[int, Callable[[Machine], None]]] = None):
    """Drive the real ``ThroughputMonitor._run`` for *ticks* readings.

    *stalls* holds a reading up (reading number -> seconds, the thread did not get to run or the call itself
    stalled); *during* does something to the machine inside a wait (wait number -> fn).  With *two_clocks* the
    monitor gets the monotonic clock as its own seam; without, the one wall clock stands for both, as in a test
    that injects only ``clock``.  ``waits.read_at`` holds the monotonic time each reading was really taken."""
    m = Machine()
    waits = Waits(m)
    for n, fn in (during or {}).items():
        waits.during[n] = (lambda fn=fn: fn(m))
    reads = [0]

    def reader() -> List[throughput.Counters]:
        reads[0] += 1
        held = (stalls or {}).get(reads[0])
        if held:
            m.elapse(held)
        waits.read_at.append(m.mono())
        if reads[0] >= ticks:
            waits.set()
        return m.counters()

    bus = Bus()
    kw: Dict[str, Any] = {"monotonic": m.mono} if two_clocks else {}
    mon = throughput.ThroughputMonitor(bus, clock=m.wall, reader=reader, primary_fn=lambda: None, **kw)
    mon._stop = waits                   # the real _run waits on this
    mon._run()
    return mon, m, waits, bus


def assert_paced(waits: Waits) -> None:
    """No wait longer than a second and a half, and no two readings closer than half a second."""
    assert max(waits.asked) <= LONGEST_WAIT_S, waits.asked
    spans = [b - a for a, b in zip(waits.read_at, waits.read_at[1:])]
    assert min(spans) >= SHORTEST_SPAN_S - 1e-9, spans


def series(mon: throughput.ThroughputMonitor) -> List[Tuple[int, int]]:
    return [(int(s[0] - T0), int(s[1])) for s in mon._nics[1].samples]


def assert_stamps_rise(mon: throughput.ThroughputMonitor) -> None:
    stamps = [s[0] for s in mon._nics[1].samples]
    assert stamps == sorted(set(stamps)), f"a second stamped twice or out of order: {stamps}"


def test_control_a_steady_flow_reads_one_megabit_every_second():
    mon, _m, waits, bus = sampler(7)
    assert series(mon) == [(2, 1_000_000), (3, 1_000_000), (4, 1_000_000), (5, 1_000_000), (6, 1_000_000),
                           (7, 1_000_000)]
    assert [e["ts"] - T0 for e in bus.events] == [2, 3, 4, 5, 6, 7], "the event carries the second of its reading"
    assert waits.asked == [1.0] * 7
    assert_paced(waits)


def test_a_read_held_up_is_divided_by_the_time_it_really_covered():
    """The third reading is 1.8 s late (a busy machine, a speed test in the same process): it covers 2.8 s of
    traffic, and dividing that by one scheduled second drew a 2.8 Mbps spike and then a hole on a 1 Mbps flow."""
    mon, _m, waits, bus = sampler(8, stalls={3: 1.8})
    rates = [r for _s, r in series(mon)]
    assert all(abs(r - 1_000_000) <= 2 for r in rates), series(mon)
    assert all(abs(e["nics"][0]["rx_bps"] - 1_000_000) <= 2 for e in bus.events)
    assert mon.view(30)["nics"][0]["peak_rx_bps"] <= 1_000_002
    assert_stamps_rise(mon)
    # the late reading, taken 4.8 s in, carries the second nearest it rather than the one it was meant for, and
    # the next is taken at the whole second after that
    assert [s for s, _r in series(mon)][:3] == [2, 5, 6]
    assert_paced(waits)


@pytest.mark.parametrize("late_s", [0.4, 0.6, 0.85, 1.45])
def test_a_read_held_up_late_in_its_second_is_never_followed_by_one_a_sliver_later(late_s):
    """Waiting for the next whole second after a read that ran late would read again a tenth of a second on
    (0.85 s late: 0.15 s later).  A counter the driver updates in steps turns a span that short into a tenfold
    spike or a zero, so the loop waits for the second after the one the late reading was stamped with."""
    mon, _m, waits, bus = sampler(8, stalls={3: late_s})
    assert_paced(waits)
    assert all(abs(r - 1_000_000) <= 20 for _s, r in series(mon)), series(mon)
    assert all(abs(e["nics"][0]["rx_bps"] - 1_000_000) <= 20 for e in bus.events)
    assert_stamps_rise(mon)
    assert len(series(mon)) == 7, "every reading after the first is a sample"


def test_the_first_reading_after_an_eight_hour_sleep_is_a_gap_not_a_28_gigabit_spike():
    """Modern Standby: the Wi-Fi stays up and Windows syncs in the background all night.  The wait that straddles
    the sleep returns eight hours later; that reading's span is eight hours, so it is a gap, and nothing carries
    a pre-sleep stamp with the night's bytes in it."""
    mon, m, waits, bus = sampler(7, during={3: lambda m: m.sleep(EIGHT_H)})
    assert max(r for _s, r in series(mon)) <= 1_000_002, series(mon)
    assert all(e["nics"][0]["rx_bps"] <= 1_000_002 for e in bus.events)
    stamps = [s for s, _r in series(mon)]
    assert stamps[0] == 2 and all(s > EIGHT_H for s in stamps[1:]), stamps
    assert len(stamps) == 5, "one reading lost to the sleep, the rest recorded"
    assert_stamps_rise(mon)
    assert max(waits.asked) <= LONGEST_WAIT_S


def test_a_sleep_on_a_monotonic_clock_that_stops_in_sleep_is_a_gap_too():
    """If the monotonic clock did not count the time asleep, the real span would read as one second; the wall
    clock moving eight hours more than it is what gives the sleep away."""
    mon, _m, _waits, bus = sampler(7, two_clocks=True, during={3: lambda m: m.sleep(EIGHT_H, monotonic_counts=False)})
    assert max(r for _s, r in series(mon)) <= 1_000_002, series(mon)
    assert all(e["nics"][0]["rx_bps"] <= 1_000_002 for e in bus.events)
    assert len(series(mon)) == 5
    assert_stamps_rise(mon)


def test_a_five_minute_nap_does_not_poison_the_half_hour_peak_and_average():
    mon, _m, _waits, _bus = sampler(7, during={3: lambda m: m.sleep(300.0)})
    view = mon.view(1800)["nics"][0]
    assert view["peak_rx_bps"] <= 1_000_002 and abs(view["avg_rx_bps"] - 1_000_000) <= 2, view


def test_a_clock_set_back_an_hour_costs_one_reading_not_an_hour_of_them():
    """w32time corrects a fast clock by an hour during the third wait.  No wait may be longer than a second and a
    half (the card froze for the hour), the reading across the step is a gap rather than a rate, and the history
    stamped by the clock as it was is dropped: by the clock as it is now, those seconds have not happened yet, and
    a 30 s window would otherwise count half an hour of them."""
    mon, m, waits, _bus = sampler(9, during={3: lambda m: m.step(-3600.0)})
    assert_paced(waits)
    rows = series(mon)
    assert all(abs(r - 1_000_000) <= 2 for _s, r in rows), rows
    assert all(s <= m.wall() - T0 for s, _r in rows), "a sample stamped in the future of the clock"
    assert len(rows) == 6, "the six readings after the step; the one across it is a gap"
    assert_stamps_rise(mon)
    view = mon.view(30)["nics"][0]
    assert len(view["samples"]) == 6 and abs(view["avg_rx_bps"] - 1_000_000) <= 2


def test_a_clock_set_back_with_a_separate_monotonic_clock_is_handled_the_same_way():
    mon, m, waits, _bus = sampler(9, two_clocks=True, during={3: lambda m: m.step(-3600.0)})
    assert_paced(waits)
    rows = series(mon)
    assert all(abs(r - 1_000_000) <= 2 for _s, r in rows) and len(rows) == 6, rows
    assert all(s <= m.wall() - T0 for s, _r in rows)
    assert_stamps_rise(mon)


def test_a_clock_set_back_an_hour_empties_the_half_hour_history_and_the_next_reading_starts_it_again():
    """The price of never stamping a second twice, pinned on purpose: after w32time sets the clock back an hour
    (a long RTC drift, a VM restored from a snapshot), every sample of the half-hour history is stamped in the new
    clock's future and is dropped, so the 30-minute peak and average start again.  Keeping them would count them
    on top of the new seconds; shifting them by the step would put them out of line with the ping samples, which
    keep the old clock's stamps.  The reading across the step is a gap, and the one after it is a sample."""
    m = Machine()
    mon = throughput.ThroughputMonitor(None, clock=m.wall, monotonic=m.mono, reader=m.counters, primary_fn=lambda: None)
    for _ in range(throughput.HISTORY_S + 5):
        mon.tick()
        m.elapse(1.0)
    assert len(mon._nics[1].samples) == throughput.HISTORY_S
    m.step(-3600.0)
    assert mon.tick() is None, "the reading across the step is a gap"
    assert len(mon._nics[1].samples) == 0, "stamped in the future of the clock as it is now"
    assert mon.view(1800)["nics"][0]["samples"] == []
    m.elapse(1.0)
    event = mon.tick()
    assert event is not None and event["nics"][0]["rx_bps"] == 1_000_000
    view = mon.view(1800)["nics"][0]
    assert len(view["samples"]) == 1 and view["peak_rx_bps"] == 1_000_000 and view["avg_rx_bps"] == 1_000_000


def test_a_clock_set_forward_an_hour_is_a_gap_and_sampling_carries_straight_on():
    mon, m, waits, bus = sampler(9, two_clocks=True, during={3: lambda m: m.step(3600.0)})
    assert_paced(waits)
    rows = series(mon)
    assert all(abs(r - 1_000_000) <= 2 for _s, r in rows), rows
    assert rows[0][0] == 2 and all(s > 3600 for s, _r in rows[1:]) and len(rows) == 7, rows
    assert all(e["nics"][0]["rx_bps"] <= 1_000_002 for e in bus.events)
    assert_stamps_rise(mon)


def test_a_clock_stepped_back_a_few_seconds_never_stamps_a_second_twice():
    mon, m, waits, _bus = sampler(12, two_clocks=True, during={4: lambda m: m.step(-1.5), 7: lambda m: m.step(-3.0)})
    assert_paced(waits)
    assert all(abs(r - 1_000_000) <= 2 for _s, r in series(mon)), series(mon)
    assert_stamps_rise(mon)
    assert all(s <= m.wall() - T0 for s, _r in series(mon))


def test_with_the_real_thread_and_event_a_clock_set_back_still_ticks_within_a_second_and_a_half():
    """The one check on the real ``threading.Event``, whose wait measures on the monotonic clock: a wall clock
    that follows real time is set back 3 s right after the first reading.  The next reading must come at most a
    second and a half later, not four (about two seconds of real time for the whole test)."""
    base, started = T0, time.monotonic()
    offset = [0.0]
    reads: List[float] = []

    def wall() -> float:
        return base + (time.monotonic() - started) + offset[0]

    def reader() -> List[throughput.Counters]:
        reads.append(time.monotonic())
        if len(reads) == 1:
            offset[0] -= 3.0                 # w32time sets the clock back right after the first reading
        return Machine().counters()

    mon = throughput.ThroughputMonitor(None, clock=wall, monotonic=time.perf_counter, reader=reader,
                                       primary_fn=lambda: None)
    mon.start()
    try:
        assert wait_until(lambda: len(reads) >= 2, timeout=3.5), "no reading after the clock was set back"
    finally:
        mon.stop()
    assert reads[1] - reads[0] <= LONGEST_WAIT_S + 0.4, reads


def test_a_reading_is_stamped_after_the_counters_are_read_not_before():
    """``tick()`` on its own: a GetIfTable2 call that took 0.8 s is charged to the span it covered, and the sample
    carries the second nearest the moment the counters were read (1.8 s in), not the moment the call began."""
    m = Machine()
    calls = [0]

    def reader() -> List[throughput.Counters]:
        calls[0] += 1
        if calls[0] == 2:
            m.elapse(0.8)
        return m.counters()

    mon = throughput.ThroughputMonitor(None, clock=m.wall, monotonic=m.mono, reader=reader, primary_fn=lambda: None)
    mon.tick()
    m.elapse(1.0)
    event = mon.tick()
    assert event["nics"][0]["rx_bps"] == 1_000_000
    assert event["ts"] == T0 + 2


# =========================================================================================
# speed test: the scheduler holds itself off after a resume
# =========================================================================================
class ResumeBackend:
    """``ok`` False is the NIC still re-associating: DNS does not answer and the run fails.  ``takes`` moves both
    clocks on inside the run, a slow test on the scheduler's own thread."""

    name = "fake"

    def __init__(self, machine: "SchedMachine") -> None:
        self.machine = machine
        self.calls: List[float] = []
        self.ok = True
        self.takes = 0.0

    def available(self, config: Any) -> Tuple[bool, str]:
        return True, "fake"

    def run(self, config: Any, progress: Any = None, cancel: Any = None) -> SpeedResult:
        self.calls.append(self.machine.wall())
        if self.takes:
            self.machine.elapse(self.takes)
            self.takes = 0.0
        if not self.ok:
            return SpeedResult(ok=False, ts=self.machine.wall(), backend="fake",
                               error="gaierror: [Errno 11001] getaddrinfo failed", duration_s=0.1)
        return SpeedResult(ok=True, ts=self.machine.wall(), backend="fake", server="Fake", download_mbps=100.0,
                           upload_mbps=20.0, latency_ms=10.0, jitter_ms=1.0, duration_s=1.0, raw={})


class SchedMachine:
    """Both clocks the scheduler reads, moved together or apart."""

    def __init__(self) -> None:
        self.wall = FakeClock(T0)
        self.mono = FakeClock(10_000.0)

    def elapse(self, s: float) -> None:
        self.wall.advance(s)
        self.mono.advance(s)


class NappingStop(threading.Event):
    """The scheduler's stop event.  A nap queued with :meth:`nap` happens inside the scheduler's next wait, which is
    where its thread is when a lid closes: both clocks move on (``time.monotonic`` counts the time asleep) and the
    wait returns, as it does on resume."""

    def __init__(self, machine: SchedMachine) -> None:
        super().__init__()
        self.machine = machine
        self._lock = threading.Lock()
        self._nap: Optional[float] = None
        self.napped = threading.Event()

    def nap(self, seconds: float) -> None:
        with self._lock:
            self._nap = float(seconds)
            self.napped.clear()

    def wait(self, timeout: Optional[float] = None) -> bool:
        with self._lock:
            nap, self._nap = self._nap, None
        if nap is not None:
            self.machine.elapse(nap)
            self.napped.set()
            return self.is_set()
        return super().wait(timeout)


@pytest.fixture
def scheduled(tmp_path, monkeypatch):
    """A running SpeedScheduler whose first run is done (at T0 + 60; the next is due at T0 + 60 + 900)."""
    cfg = tnt_config.Config(tmp_path / "config.json")
    cfg.update({"speedtest": {"interval_min": 15}}, persist=False)
    database = tnt_db.Database(tmp_path / "speed.db")
    bus = tnt_events.EventBus()
    events: List[Dict[str, Any]] = []
    bus.subscribe(events.append)
    m = SchedMachine()
    backend = ResumeBackend(m)
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: backend)
    stop = NappingStop(m)
    s = sched_mod.SpeedScheduler(database, cfg, bus, clock=m.wall, poll_s=0.01, monotonic=m.mono)
    s._stop = stop
    s.start()
    m.wall.advance(60.0)                  # the wall clock alone: the first run is due, and runs at once
    assert wait_until(lambda: len(backend.calls) == 1 and not s.running and s.last_result is not None)
    assert backend.calls == [T0 + 60.0] and s.next_run_ts == T0 + 60.0 + 900.0
    ns = SimpleNamespace(s=s, m=m, stop=stop, backend=backend, db=database, bus=bus, events=events, cfg=cfg)
    yield ns
    s.stop()
    database.close()


def test_an_overdue_test_is_held_off_after_a_resume_before_any_monitoring_gap_arrives(scheduled):
    """Two hours asleep, so the next test is long overdue at the wake, and the NIC is still re-associating.  No
    ``monitoring.gap`` is published here at all: the scheduler must see the resume on its own thread."""
    x = scheduled
    x.backend.ok = False
    x.events.clear()
    x.stop.nap(7200.0)
    assert x.stop.napped.wait(2.0)
    woke = x.m.wall()
    time.sleep(0.15)                      # many polls
    assert len(x.backend.calls) == 1, "the overdue test ran straight after the resume"
    assert x.s.next_run_ts == woke + x.s.RESUME_HOLDOFF_S
    assert not [e for e in x.events if e["type"] in ("speedtest.start", "speedtest.done")]
    x.backend.ok = True                   # the link is up a minute later
    x.m.wall.advance(x.s.RESUME_HOLDOFF_S)
    assert wait_until(lambda: len(x.backend.calls) == 2 and not x.s.running)
    assert x.backend.calls[1] == woke + x.s.RESUME_HOLDOFF_S
    rows = x.db.list_speedtests(0, 2e9)
    assert len(rows) == 2 and all(r["ok"] for r in rows)
    assert x.db.list_events(10) == [], "no 'speed test failed' warning"


def test_the_gap_event_arriving_after_the_scheduler_saw_the_resume_only_pushes_the_test_later(scheduled):
    x = scheduled
    x.stop.nap(7200.0)
    assert x.stop.napped.wait(2.0)
    woke = x.m.wall()
    assert wait_until(lambda: x.s.next_run_ts == woke + x.s.RESUME_HOLDOFF_S)
    x.m.wall.advance(4.0)                 # the maintenance thread gets there four seconds later
    x.bus.publish("monitoring.gap", {"start_ts": T0 + 60.0, "end_ts": x.m.wall(), "note": "system sleep"})
    assert x.s.next_run_ts == x.m.wall() + x.s.RESUME_HOLDOFF_S
    time.sleep(0.1)
    assert len(x.backend.calls) == 1


def test_a_clock_set_forward_while_awake_still_runs_the_overdue_test_at_once(scheduled):
    """Only the thread not running is a resume.  A wall clock stepped forward past the next slot is time that
    really is up, as documented: the test runs at once."""
    x = scheduled
    x.m.wall.advance(900.0)
    assert wait_until(lambda: len(x.backend.calls) == 2 and not x.s.running)
    assert x.backend.calls[1] == T0 + 60.0 + 900.0


def test_a_long_test_on_the_scheduler_thread_is_not_mistaken_for_a_sleep(scheduled):
    """The scheduled test runs on the scheduler's own thread, so the poll after it comes round as late as the test
    took.  That is not a resume: with a one-minute interval and a 90 s test, the next one is due at once."""
    x = scheduled
    x.cfg.update({"speedtest": {"interval_min": 1}}, persist=False)
    x.backend.takes = 90.0
    due = x.s.next_run_ts
    x.m.wall.advance(due - x.m.wall())
    assert wait_until(lambda: len(x.backend.calls) >= 3 and not x.s.running)
    assert x.backend.calls[1] == due
    assert x.backend.calls[2] == due + 90.0, "held off as if the machine had slept through its own test"


def test_a_poll_a_few_seconds_late_is_a_busy_machine_not_a_resume(scheduled):
    """The scheduler thread did not get to run for five seconds (a loaded machine), just as the next test fell
    due.  That is under SLEEP_GAP_S: the test runs at once, as it always has."""
    x = scheduled
    due = x.s.next_run_ts
    x.m.wall.advance(due - 2.0 - x.m.wall())          # two seconds before the next test is due
    time.sleep(0.05)
    assert len(x.backend.calls) == 1
    x.stop.nap(5.0)
    assert x.stop.napped.wait(2.0)
    assert wait_until(lambda: len(x.backend.calls) == 2 and not x.s.running)
    assert x.backend.calls[1] == due + 3.0


def test_a_clock_set_back_is_not_a_resume_and_the_next_test_keeps_its_distance(scheduled):
    """w32time sets the clock back an hour while the machine is awake.  The next test moves back with it (it is
    still fifteen minutes away) and nothing is held off: only a wait the monotonic clock says took far longer than
    asked is a resume."""
    x = scheduled
    before = x.s.next_run_ts
    x.m.wall.advance(-3600.0)
    assert wait_until(lambda: x.s.next_run_ts == before - 3600.0), x.s.next_run_ts
    time.sleep(0.05)
    assert x.s.next_run_ts == before - 3600.0 and len(x.backend.calls) == 1


@pytest.mark.skipif(sys.platform != "win32", reason="the service runs on Windows")
def test_the_resume_check_stands_on_a_monotonic_clock_that_counts_the_time_asleep():
    """The scheduler sees a resume as a poll whose wait took far longer than asked on time.monotonic.  That
    works because the monotonic clock keeps counting through a sleep, as GetTickCount64 (Python 3.12 on
    Windows) does.  A Python that moves time.monotonic to another clock has to be checked before this pin is
    changed: on a clock that stops in sleep the scheduler would be back to racing monitoring.gap after every
    resume, and the "Speed test failed: gaierror" toasts would return."""
    info = time.get_clock_info("monotonic")
    assert info.implementation == "GetTickCount64()", info
    assert sched_mod.SpeedScheduler.__init__.__kwdefaults__["monotonic"] is time.monotonic
