"""Tests for tnt.outages.OutageTracker using a fake PingManager."""
from __future__ import annotations

import threading
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional

import pytest

from tnt import config as tnt_config
from tnt import db as tnt_db
from tnt import events as tnt_events
from tnt import outages

try:  # the real Sample if the pinger module already exists
    from tnt.pinger import Sample  # type: ignore
except Exception:  # noqa: BLE001
    @dataclass
    class Sample:  # type: ignore[no-redef]
        ts: float
        ok: bool
        rtt_ms: Optional[float]


T0 = 1_700_000_000.0


class FakeClock:
    def __init__(self, t: float = T0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class FakePingManager:
    """Minimal stand-in exposing the parts of the PingManager contract the tracker uses."""

    def __init__(self) -> None:
        self.views: Dict[int, Dict[str, Any]] = {}
        self.calls: List[tuple] = []
        self.paused = False
        self._sample_listeners: List[Callable] = []
        self._removal_listeners: List[Callable] = []

    def add(self, tid: int, host: str, kind: str = "internet", enabled: bool = True) -> Dict[str, Any]:
        self.views[tid] = {
            "id": tid, "host": host, "label": None, "kind": kind, "ip": host, "enabled": enabled,
            "resolved": True, "resolve_error": None, "light": "grey", "in_outage": False,
            "last": None, "consecutive_missed": 0, "consecutive_ok": 0,
        }
        return self.views[tid]

    def targets(self) -> List[Dict[str, Any]]:
        return [dict(v) for v in self.views.values()]

    def set_in_outage(self, tid: int, flag: bool) -> None:
        self.calls.append((tid, bool(flag)))
        if tid in self.views:
            self.views[tid]["in_outage"] = bool(flag)

    def add_sample_listener(self, fn: Callable) -> Callable[[], None]:
        self._sample_listeners.append(fn)
        return lambda: self._sample_listeners.remove(fn)

    def add_removal_listener(self, fn: Callable) -> Callable[[], None]:
        self._removal_listeners.append(fn)
        return lambda: self._removal_listeners.remove(fn)

    def feed(self, tid: int, ts: float, ok: bool, rtt: float = 20.0) -> None:
        v = self.views[tid]
        v["last"] = {"ts": ts, "ok": ok, "rtt_ms": rtt if ok else None}
        if ok:
            v["consecutive_ok"] += 1
            v["consecutive_missed"] = 0
        else:
            v["consecutive_missed"] += 1
            v["consecutive_ok"] = 0
        sample = Sample(ts=ts, ok=ok, rtt_ms=rtt if ok else None)
        for fn in list(self._sample_listeners):
            fn(dict(v), sample)

    def remove(self, tid: int) -> None:
        self.views.pop(tid, None)
        for fn in list(self._removal_listeners):
            fn(tid)


@pytest.fixture
def env(data_dir):
    database = tnt_db.Database(data_dir / "outages-test.db")
    cfg = tnt_config.Config().load()
    bus = tnt_events.EventBus()
    seen: List[Dict[str, Any]] = []
    bus.subscribe(lambda e: seen.append(e) if e["type"].startswith("outage.") else None)
    pm = FakePingManager()
    clock = FakeClock()
    tracker = outages.OutageTracker(database, cfg, bus, pm, clock=clock)
    tracker.start()

    def feed(tid: int, ts: float, ok: bool) -> None:
        clock.t = max(clock.t, ts)
        pm.feed(tid, ts, ok)

    def run(tid: int, t0: float, pattern: str, step: float = 1.0) -> float:
        """'x' = miss, '.' = ok; returns the ts of the last sample."""
        ts = t0
        for i, ch in enumerate(pattern):
            ts = t0 + i * step
            feed(tid, ts, ch == ".")
        return ts

    def events_of(kind: str) -> List[Dict[str, Any]]:
        return [e for e in seen if e["type"] == kind]

    e = SimpleNamespace(db=database, config=cfg, bus=bus, pm=pm, clock=clock, tracker=tracker,
                        events=seen, feed=feed, run=run, events_of=events_of)
    yield e
    tracker.stop()
    database.close()


# --------------------------------------------------------------------------- per-target rules

def test_two_misses_then_success_no_outage(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xx.")
    assert env.db.open_outages() == []
    assert env.events == []
    assert env.pm.calls == []
    st = env.tracker.status()
    assert st["active"] == [] and st["total_active"] is None and st["count_24h"] == 0


def test_three_misses_open_outage_starting_at_first_miss(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxx")
    rows = env.db.open_outages()
    target_rows = [r for r in rows if r["kind"] == "target"]
    assert len(target_rows) == 1
    row = target_rows[0]
    assert row["target_id"] == 1 and row["start_ts"] == T0 and row["end_ts"] is None
    assert env.pm.calls == [(1, True)]
    starts = env.events_of("outage.start")
    assert starts[0]["data"]["kind"] == "target"
    assert starts[0]["data"]["host"] == "1.1.1.1"
    assert starts[0]["data"]["start_ts"] == T0
    assert starts[0]["data"]["open"] is True
    assert starts[0]["data"]["target_id"] == 1
    # the diagnostics event log gets a line too
    assert any(ev["category"] == "outage" for ev in env.db.list_events(10))
    st = env.tracker.status()
    assert [o["id"] for o in st["active"] if o["kind"] == "target"] == [row["id"]]
    assert st["count_24h"] >= 1 and st["last"] is not None


def test_recovery_needs_three_successes_end_is_first_success(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxxxx")                       # 5 misses, outage opened on the 3rd
    env.feed(1, T0 + 5, True)
    env.feed(1, T0 + 6, True)
    assert [r for r in env.db.open_outages() if r["kind"] == "target"], "two successes must not close"
    env.feed(1, T0 + 7, True)
    assert [r for r in env.db.open_outages() if r["kind"] == "target"] == []
    row = env.db.list_outages(T0 - 10, T0 + 100, kinds=("target",))[0]
    assert row["start_ts"] == T0
    assert row["end_ts"] == T0 + 5          # first success of the recovery run
    assert row["missed"] == 5
    assert env.pm.calls == [(1, True), (1, False)]
    end = env.events_of("outage.end")
    target_end = [e for e in end if e["data"]["kind"] == "target"][0]
    assert target_end["data"]["end_ts"] == T0 + 5
    assert target_end["data"]["duration_s"] == 5.0
    assert target_end["data"]["open"] is False
    assert target_end["data"]["host"] == "1.1.1.1"


def test_miss_during_recovery_resets_counter(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxx")                        # open, start T0
    env.feed(1, T0 + 3, True)
    env.feed(1, T0 + 4, True)
    env.feed(1, T0 + 5, False)                   # recovery reset, missed -> 4
    env.feed(1, T0 + 6, True)
    env.feed(1, T0 + 7, True)
    assert [r for r in env.db.open_outages() if r["kind"] == "target"], "counter must have reset"
    env.feed(1, T0 + 8, True)
    row = env.db.list_outages(T0 - 10, T0 + 100, kinds=("target",))[0]
    assert row["end_ts"] == T0 + 6
    assert row["missed"] == 4
    assert len(env.events_of("outage.start")) == 2 and len(env.events_of("outage.end")) == 2  # target + total


def test_missed_count_persisted_every_10th_and_on_close(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "x" * 3)
    oid = [r for r in env.db.open_outages() if r["kind"] == "target"][0]["id"]
    assert env.db.get_outage(oid)["missed"] == 3
    env.run(1, T0 + 3, "x" * 6)                  # 9 total
    assert env.db.get_outage(oid)["missed"] == 3
    env.feed(1, T0 + 9, False)                   # 10th miss -> persisted
    assert env.db.get_outage(oid)["missed"] == 10
    env.run(1, T0 + 10, "xx")                    # 12
    assert env.db.get_outage(oid)["missed"] == 10
    env.run(1, T0 + 12, "...")
    assert env.db.get_outage(oid)["missed"] == 12
    assert env.db.get_outage(oid)["end_ts"] == T0 + 12


def test_sent_counts_every_ping_and_leaves_out_the_recovery_run(env):
    """Missed % = missed / pings sent while the outage was open. A blip of success inside the
    outage counts as sent; the three successes that close it start at end_ts, so they do not."""
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxx")                        # opens at T0: 3 sent, 3 missed
    oid = [r for r in env.db.open_outages() if r["kind"] == "target"][0]["id"]
    assert env.db.get_outage(oid)["sent"] == 3
    env.run(1, T0 + 3, "x.x")                    # a one-ping blip does not end it: 6 sent, 5 missed
    env.run(1, T0 + 6, "xx")                     # 8 sent, 7 missed
    live = [o for o in env.tracker.status()["active"] if o["id"] == oid][0]
    assert (live["sent"], live["missed"], live["missed_pct"], live["sent_estimated"]) == (8, 7, 87.5, False)
    env.run(1, T0 + 8, "...")                    # recovery run T0+8..T0+10 closes it at T0+8
    row = env.db.get_outage(oid)
    assert (row["end_ts"], row["missed"], row["sent"]) == (T0 + 8, 7, 8)
    listed = [o for o in env.tracker.list(T0 - 10, T0 + 100) if o["id"] == oid][0]
    assert (listed["sent"], listed["missed_pct"], listed["sent_estimated"]) == (8, 87.5, False)
    seg = [s for s in env.tracker.timeline(24, now=T0 + 100)["segments"] if s["id"] == oid][0]
    assert (seg["sent"], seg["missed_pct"]) == (8, 87.5), "the timeline tooltip gets the same numbers"


def test_sent_is_persisted_with_the_missed_counter(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "x" * 3 + "." + "x" * 6)      # 10 sent, 9 missed: not persisted yet
    oid = [r for r in env.db.open_outages() if r["kind"] == "target"][0]["id"]
    env.feed(1, T0 + 10, False)                  # 10th miss -> missed and sent are written
    row = env.db.get_outage(oid)
    assert (row["missed"], row["sent"]) == (10, 11)
    env.tracker.stop()                           # stop persists the live counters too
    assert env.db.get_outage(oid)["sent"] == 11


def test_removed_target_keeps_the_successes_inside_its_window(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxx..")                      # removal (not a recovery) ends it at "now"
    oid = [r for r in env.db.open_outages() if r["kind"] == "target"][0]["id"]
    env.clock.t = T0 + 5
    env.tracker.on_target_removed(1)
    row = env.db.get_outage(oid)
    assert (row["note"], row["missed"], row["sent"]) == ("target removed", 3, 5)


def test_older_rows_get_an_estimated_percentage_and_totals_get_none(env):
    old = env.db.open_outage("target", 9, T0, host="203.0.113.24")
    env.db.close_outage(old, T0 + 2450, 2449, "target removed")      # recorded before `sent` existed
    tot = env.db.open_outage("total_internet", None, T0 + 10)
    env.db.close_outage(tot, T0 + 70, 0)
    gap = env.db.open_outage("gap", None, T0 + 100, note="not monitoring")
    env.db.close_outage(gap, T0 + 200, 0)
    rows = {o["id"]: o for o in env.tracker.list(T0 - 10, T0 + 3000)}
    assert (rows[old]["sent"], rows[old]["missed_pct"], rows[old]["sent_estimated"]) == (2450, 99.96, True)
    for rid in (tot, gap):
        assert (rows[rid]["sent"], rows[rid]["missed_pct"], rows[rid]["sent_estimated"]) == (None, None, False)


def test_missed_percentage_helper():
    mp = outages.missed_percentage
    assert mp("target", 3, 3, 3.0) == (3, 100.0, False)
    assert mp("target", 7, 8, 8.0) == (8, 87.5, False)
    assert mp("target", 2449, None, 2450.0, 1.0) == (2450, 99.96, True)
    assert mp("target", 3, None, 2.9, 1.0) == (3, 100.0, True), "one ping per interval, rounded"
    assert mp("target", 4, None, 4.0, 0.5) == (8, 50.0, True), "a faster ping interval sends more"
    assert mp("target", 5, 2, 10.0) == (5, 100.0, False), "never fewer sent than missed"
    assert mp("target", 0, None, 0.0) == (None, None, True)
    assert mp("target", "x", "y", "z", "q") == (None, None, True), "junk never raises"
    assert mp("total_internet", 0, None, 60.0) == (None, None, False)
    assert mp("gap", 0, None, 60.0) == (None, None, False)


def test_outages_sent_column_is_added_to_an_existing_database(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE outages (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, target_id INTEGER, "
                "start_ts REAL NOT NULL, end_ts REAL, missed INTEGER NOT NULL DEFAULT 0, note TEXT)")
    con.execute("INSERT INTO outages(kind, target_id, start_ts, end_ts, missed) VALUES('target', 1, 1.0, 4.0, 3)")
    con.commit()
    con.close()
    d = tnt_db.Database(path)
    cols = {r["name"] for r in d._conn.execute("PRAGMA table_info(outages)").fetchall()}
    assert {"host", "sent"} <= cols
    row = d.list_outages(0, 10)[0]
    assert row["sent"] is None and row["missed"] == 3, "older rows keep NULL (the percentage is estimated)"
    d.close()


def test_thresholds_are_read_live_from_config(env):
    env.pm.add(1, "1.1.1.1")
    env.config.update({"outage": {"miss_threshold": 5, "recover_threshold": 2}}, persist=False)
    env.run(1, T0, "xxx")
    assert env.db.open_outages() == []
    env.run(1, T0 + 3, "xx")
    assert [r for r in env.db.open_outages() if r["kind"] == "target"]
    env.run(1, T0 + 5, "..")
    assert env.db.open_outages() == []
    row = env.db.list_outages(T0 - 10, T0 + 100, kinds=("target",))[0]
    assert row["start_ts"] == T0 and row["end_ts"] == T0 + 5 and row["missed"] == 5


def test_lowering_threshold_mid_run_takes_effect(env):
    env.pm.add(1, "1.1.1.1")
    env.config.update({"outage": {"miss_threshold": 10}}, persist=False)
    env.run(1, T0, "xxxxx")
    assert env.db.open_outages() == []
    env.config.update({"outage": {"miss_threshold": 3}}, persist=False)
    env.feed(1, T0 + 5, False)                   # 6th consecutive miss >= 3
    rows = [r for r in env.db.open_outages() if r["kind"] == "target"]
    assert len(rows) == 1 and rows[0]["start_ts"] == T0


# --------------------------------------------------------------------------- total outages

def test_total_internet_opens_only_when_all_down_and_starts_at_later_start(env):
    env.pm.add(1, "1.1.1.1")
    env.pm.add(2, "8.8.8.8")
    env.feed(1, T0, True)
    env.feed(2, T0, True)
    for i in (1, 2, 3):                          # target 1 falls, target 2 fine
        env.feed(1, T0 + i, False)
        env.feed(2, T0 + i, True)
    assert env.db.open_outages() and all(r["kind"] == "target" for r in env.db.open_outages())
    assert env.tracker.status()["total_active"] is None
    for i in (5, 6):
        env.feed(1, T0 + i, False)
        env.feed(2, T0 + i, False)
    assert env.tracker.status()["total_active"] is None
    env.feed(1, T0 + 7, False)
    env.feed(2, T0 + 7, False)                   # target 2 opens (start T0+5) -> total
    total = env.tracker.status()["total_active"]
    assert total is not None
    assert total["kind"] == "total_internet"
    assert total["start_ts"] == T0 + 5
    assert total["open"] is True and total["host"] is None and total["target_id"] is None
    kinds = [e["data"]["kind"] for e in env.events_of("outage.start")]
    assert kinds == ["target", "target", "total_internet"]
    st = env.tracker.status()
    assert len(st["active"]) == 3 and st["active"][0]["kind"] == "total_internet"


def test_total_internet_closes_when_one_member_recovers(env):
    env.pm.add(1, "1.1.1.1")
    env.pm.add(2, "8.8.8.8")
    for i in range(4):
        env.feed(1, T0 + i, False)
        env.feed(2, T0 + i, False)
    total_id = env.tracker.status()["total_active"]["id"]
    env.feed(2, T0 + 4, False)
    env.feed(1, T0 + 4, True)                    # first success of target 1's recovery
    env.feed(2, T0 + 5, False)
    env.feed(1, T0 + 5, True)
    assert env.tracker.status()["total_active"] is not None, "needs R successes"
    env.feed(1, T0 + 6, True)                    # target 1 recovered -> total closes
    env.feed(2, T0 + 6, False)
    st = env.tracker.status()
    assert st["total_active"] is None
    assert [o["target_id"] for o in st["active"]] == [2]
    total_row = env.db.get_outage(total_id)
    assert total_row["end_ts"] == T0 + 4
    ends = [e["data"] for e in env.events_of("outage.end")]
    assert [d["kind"] for d in ends] == ["target", "total_internet"]
    assert ends[1]["end_ts"] == T0 + 4
    # target 2 still down alone -> total reopens? Only if all active members are down: yes, target 2
    # is the only member in outage but target 1 is active and fine, so no new total.
    assert [r["kind"] for r in env.db.open_outages()] == ["target"]


def test_single_local_target_down_opens_total_local_only(env):
    env.pm.add(1, "10.0.0.1", kind="local")
    env.pm.add(2, "1.1.1.1", kind="internet")
    env.feed(2, T0, True)
    env.run(1, T0, "xxx")
    open_kinds = sorted(r["kind"] for r in env.db.open_outages())
    assert open_kinds == ["target", "total_local"]
    total = env.tracker.status()["total_active"]
    assert total["kind"] == "total_local" and total["start_ts"] == T0
    env.run(1, T0 + 3, "...")
    assert env.db.open_outages() == []
    rows = {r["kind"]: r for r in env.db.list_outages(T0 - 10, T0 + 100)}
    assert rows["total_local"]["end_ts"] == T0 + 3
    assert rows["target"]["end_ts"] == T0 + 3


def test_both_totals_can_be_open_and_internet_is_preferred(env):
    env.pm.add(1, "10.0.0.1", kind="local")
    env.pm.add(2, "1.1.1.1", kind="internet")
    for i in range(3):
        env.feed(1, T0 + i, False)
        env.feed(2, T0 + i, False)
    st = env.tracker.status()
    assert sorted(o["kind"] for o in st["active"]) == ["target", "target", "total_internet", "total_local"]
    assert st["total_active"]["kind"] == "total_internet"


def test_no_targets_or_samples_nothing_opens(env):
    st = env.tracker.status()
    assert st == {"active": [], "total_active": None, "count_24h": 0, "last": None, "monitoring": False}
    env.pm.add(1, "1.1.1.1")                     # target exists but never pinged
    st = env.tracker.status()
    assert st["monitoring"] is False and st["active"] == []
    tl = env.tracker.timeline(24)
    assert tl["segments"] == [] and tl["total_segments"] == [] and tl["gaps"] == []
    assert tl["targets"] == [{"id": 1, "host": "1.1.1.1", "kind": "internet"}]
    assert env.db.open_outages() == []


def test_inactive_and_disabled_targets_do_not_count_as_members(env):
    env.pm.add(1, "1.1.1.1")
    env.pm.add(2, "8.8.8.8")
    env.pm.add(3, "9.9.9.9", enabled=False)
    env.feed(2, T0, True)                        # last sample of target 2 at T0
    env.feed(3, T0 + 20, True)                   # disabled but fresh
    env.run(1, T0 + 20, "xxx")                   # 20 s later target 2 is stale (>15 s) -> not a member
    total = env.tracker.status()["total_active"]
    assert total is not None and total["kind"] == "total_internet" and total["start_ts"] == T0 + 20


def test_monitoring_flag_reflects_recent_samples_and_pause(env):
    env.pm.add(1, "1.1.1.1")
    env.feed(1, T0, True)
    assert env.tracker.status()["monitoring"] is True
    env.clock.t = T0 + 30
    assert env.tracker.status()["monitoring"] is False
    env.feed(1, T0 + 30, True)
    assert env.tracker.status()["monitoring"] is True
    env.pm.paused = True
    assert env.tracker.status()["monitoring"] is False


# --------------------------------------------------------------------------- startup handling

def test_startup_closes_stale_outages_at_heartbeat_and_inserts_gap(data_dir):
    database = tnt_db.Database(data_dir / "startup.db")
    t = database.add_target("1.1.1.1")
    stale_target = database.open_outage("target", t["id"], T0 - 500)
    database.update_outage_missed(stale_target, 42)
    stale_total = database.open_outage("total_internet", None, T0 - 400)
    database.set_meta("last_heartbeat", str(T0 - 200))
    clock = FakeClock(T0)
    pm = FakePingManager()
    tracker = outages.OutageTracker(database, tnt_config.Config().load(), tnt_events.EventBus(), pm, clock=clock)
    tracker.start()
    assert database.open_outages() == []
    row = database.get_outage(stale_target)
    assert row["end_ts"] == T0 - 200 and row["note"] == "service stopped" and row["missed"] == 42
    assert database.get_outage(stale_total)["end_ts"] == T0 - 200
    gaps = database.list_outages(T0 - 1000, T0, kinds=("gap",))
    assert len(gaps) == 1
    assert gaps[0]["start_ts"] == T0 - 200 and gaps[0]["end_ts"] == T0 and gaps[0]["note"] == "not monitoring"
    assert float(database.get_meta("last_heartbeat")) == T0
    assert tracker.startup_info["closed"] == 2 and tracker.startup_info["gap_id"] == gaps[0]["id"]
    # timeline shows the gap and the closed segments (host looked up from the targets table)
    tl = tracker.timeline(1, now=T0)
    assert tl["gaps"] == [{"start_ts": T0 - 200, "end_ts": T0}]
    assert tl["segments"][0]["host"] == "1.1.1.1" and tl["segments"][0]["open"] is False
    assert tl["total_segments"][0]["kind"] == "total_internet"
    assert {"id": t["id"], "host": "1.1.1.1", "kind": "internet"} in tl["targets"]
    tracker.stop()
    # a second start shortly after (heartbeat now fresh) must not add another gap
    clock.t = T0 + 5
    tracker2 = outages.OutageTracker(database, tnt_config.Config().load(), tnt_events.EventBus(), pm, clock=clock)
    tracker2.start()
    assert len(database.list_outages(T0 - 1000, T0 + 10, kinds=("gap",))) == 1
    tracker2.stop()
    database.close()


def test_startup_no_gap_when_heartbeat_recent_or_unknown(data_dir):
    database = tnt_db.Database(data_dir / "startup2.db")
    oid = database.open_outage("target", 1, T0 - 100)
    database.set_meta("last_heartbeat", str(T0 - 60))      # < 90 s: no gap
    tracker = outages.OutageTracker(database, tnt_config.Config().load(), tnt_events.EventBus(),
                                    FakePingManager(), clock=FakeClock(T0))
    tracker.start()
    assert database.get_outage(oid)["end_ts"] == T0 - 60
    assert database.list_outages(T0 - 1000, T0, kinds=("gap",)) == []
    tracker.stop()
    database.close()

    database = tnt_db.Database(data_dir / "startup3.db")
    oid = database.open_outage("target", 1, T0 - 100)      # no heartbeat at all -> close at now
    tracker = outages.OutageTracker(database, tnt_config.Config().load(), tnt_events.EventBus(),
                                    FakePingManager(), clock=FakeClock(T0))
    tracker.start()
    row = database.get_outage(oid)
    assert row["end_ts"] == T0 and row["note"] == "service stopped"
    assert database.list_outages(T0 - 1000, T0, kinds=("gap",)) == []
    tracker.stop()
    database.close()


def test_startup_end_never_before_start(data_dir):
    database = tnt_db.Database(data_dir / "startup4.db")
    oid = database.open_outage("target", 1, T0 - 50)       # opened after the last heartbeat
    database.set_meta("last_heartbeat", str(T0 - 200))
    tracker = outages.OutageTracker(database, tnt_config.Config().load(), tnt_events.EventBus(),
                                    FakePingManager(), clock=FakeClock(T0))
    tracker.start()
    row = database.get_outage(oid)
    assert row["end_ts"] == T0 - 50
    tracker.stop()
    database.close()


def test_close_stale_outages_is_idempotent_when_engine_ran_it_first(data_dir):
    database = tnt_db.Database(data_dir / "startup5.db")
    database.open_outage("target", 1, T0 - 500)
    database.set_meta("last_heartbeat", str(T0 - 300))
    info = outages.close_stale_outages(database, T0)
    assert info["closed"] == 1 and info["gap_id"] is not None
    # simulate an Engine that did not refresh the heartbeat
    database.set_meta("last_heartbeat", str(T0 - 300))
    info2 = outages.close_stale_outages(database, T0 + 1)
    assert info2["closed"] == 0 and info2["gap_id"] == info["gap_id"]
    assert len(database.list_outages(T0 - 1000, T0 + 10, kinds=("gap",))) == 1
    database.close()


# --------------------------------------------------------------------------- list / timeline

def test_list_decorates_rows(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxxxx...")
    env.clock.t = T0 + 100
    rows = env.tracker.list(T0 - 10, T0 + 100)
    assert len(rows) == 2                        # target + total_internet, newest first
    by_kind = {r["kind"]: r for r in rows}
    t = by_kind["target"]
    assert t["host"] == "1.1.1.1" and t["open"] is False and t["duration_s"] == 5.0 and t["missed"] == 5
    assert by_kind["total_internet"]["host"] is None
    env.run(1, T0 + 100, "xxx")
    open_rows = [r for r in env.tracker.list(T0 - 10, T0 + 200) if r["open"]]
    assert len(open_rows) == 2
    env.clock.t = T0 + 130
    tgt = [r for r in env.tracker.list(T0 - 10, T0 + 200) if r["open"] and r["kind"] == "target"][0]
    assert tgt["duration_s"] == 30.0 and tgt["missed"] == 3


def test_timeline_clips_segments_and_flags_open(env):
    now = T0 + 24 * 3600
    tid = env.db.add_target("1.1.1.1")["id"]
    old = env.db.open_outage("target", tid, now - 30 * 3600)          # entirely before the window
    env.db.close_outage(old, now - 26 * 3600, 3)
    straddle = env.db.open_outage("target", tid, now - 30 * 3600 + 1)  # straddles the window start
    env.db.close_outage(straddle, now - 23 * 3600, 7)
    total = env.db.open_outage("total_internet", None, now - 5 * 3600)
    env.db.close_outage(total, now - 4 * 3600, 0)
    gap = env.db.open_outage("gap", None, now - 10 * 3600, note="not monitoring")
    env.db.close_outage(gap, now - 9 * 3600, 0, "not monitoring")
    env.pm.add(2, "8.8.8.8")
    env.run(2, now - 3600, "xxx")                                        # open outage, starts now-3600
    tl = env.tracker.timeline(24, now=now)
    assert tl["start_ts"] == now - 86400 and tl["end_ts"] == now and tl["hours"] == 24
    assert [s["id"] for s in tl["segments"]] != [] and old not in [s["id"] for s in tl["segments"]]
    seg_straddle = [s for s in tl["segments"] if s["id"] == straddle][0]
    assert seg_straddle["start_ts"] == now - 86400          # clipped
    assert seg_straddle["end_ts"] == now - 23 * 3600
    assert seg_straddle["open"] is False and seg_straddle["missed"] == 7 and seg_straddle["host"] == "1.1.1.1"
    seg_open = [s for s in tl["segments"] if s["target_id"] == 2][0]
    assert seg_open["open"] is True and seg_open["end_ts"] == now and seg_open["start_ts"] == now - 3600
    assert seg_open["host"] == "8.8.8.8" and seg_open["missed"] == 3
    assert [s["kind"] for s in tl["total_segments"]] == ["total_internet", "total_internet"]
    open_total = [s for s in tl["total_segments"] if s["open"]][0]
    assert open_total["end_ts"] == now and open_total["start_ts"] == now - 3600
    assert tl["gaps"] == [{"start_ts": now - 10 * 3600, "end_ts": now - 9 * 3600}]
    ids = {t["id"]: t for t in tl["targets"]}
    assert ids[2]["host"] == "8.8.8.8" and ids[tid]["host"] == "1.1.1.1"   # removed/db-only target included
    # a narrower window clips the open segment start too
    tl2 = env.tracker.timeline(0.5, now=now)
    seg = [s for s in tl2["segments"] if s["target_id"] == 2][0]
    assert seg["start_ts"] == now - 1800 and seg["end_ts"] == now and seg["open"] is True
    assert tl2["gaps"] == [] and len(tl2["total_segments"]) == 1


def test_timeline_bad_hours_falls_back_to_24(env):
    tl = env.tracker.timeline(0, now=T0)
    assert tl["hours"] == 24 and tl["start_ts"] == T0 - 86400
    tl = env.tracker.timeline("abc", now=T0)
    assert tl["hours"] == 24


# --------------------------------------------------------------------------- removal / stop

def test_on_target_removed_closes_with_note_and_closes_total(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxx")
    assert sorted(r["kind"] for r in env.db.open_outages()) == ["target", "total_internet"]
    env.clock.t = T0 + 10
    env.pm.remove(1)                             # fires the removal listener registered by start()
    assert env.db.open_outages() == []
    rows = {r["kind"]: r for r in env.db.list_outages(T0 - 10, T0 + 100)}
    assert rows["target"]["end_ts"] == T0 + 10 and rows["target"]["note"] == "target removed"
    assert rows["target"]["missed"] == 3
    assert rows["total_internet"]["end_ts"] == T0 + 10 and rows["total_internet"]["note"] == "target removed"
    ends = [e["data"] for e in env.events_of("outage.end")]
    assert [d["kind"] for d in ends] == ["target", "total_internet"]
    assert ends[0]["host"] == "1.1.1.1" and ends[0]["note"] == "target removed"
    assert env.pm.calls == [(1, True)]           # no set_in_outage for a removed target
    assert env.tracker.status()["active"] == []
    env.tracker.on_target_removed(99)            # unknown id is harmless
    env.tracker.on_target_removed("nope")        # type: ignore[arg-type]


def test_removing_a_healthy_member_can_complete_a_total_starting_at_removal(env):
    env.pm.add(1, "1.1.1.1")
    env.pm.add(2, "8.8.8.8")
    for i in range(3):
        env.feed(1, T0 + i, False)
        env.feed(2, T0 + i, True)
    assert env.tracker.status()["total_active"] is None
    env.clock.t = T0 + 10
    env.pm.remove(2)
    total = env.tracker.status()["total_active"]
    assert total is not None and total["kind"] == "total_internet"
    # the group was reachable via target 2 until it was removed, so the total must
    # start at the removal moment, not be back-dated to target 1's first miss
    assert total["start_ts"] == T0 + 10
    assert env.events_of("outage.start")[-1]["data"]["start_ts"] == T0 + 10


def test_healthy_target_added_while_total_open_closes_it_at_first_success(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxx")                        # lone internet target down -> total_internet
    assert env.tracker.status()["total_active"]["start_ts"] == T0
    env.pm.add(2, "8.8.8.8")                     # user adds a second, reachable target
    env.feed(1, T0 + 3, False)
    env.feed(2, T0 + 3, True)                    # first sample of the new target succeeds
    st = env.tracker.status()
    assert st["total_active"] is None, "a reachable active member means the group is not all down"
    assert [o["target_id"] for o in st["active"]] == [1]
    total_row = env.db.list_outages(T0 - 10, T0 + 100, kinds=("total_internet",))[0]
    assert total_row["end_ts"] == T0 + 3
    assert env.events_of("outage.end")[-1]["data"]["kind"] == "total_internet"
    # a miss from a target that is not (yet) in outage does not flap the total
    env.pm.add(3, "9.9.9.9")
    env.run(2, T0 + 4, "xxx")                    # target 2 falls too (start T0+4)
    assert env.tracker.status()["total_active"]["start_ts"] == T0 + 4
    env.feed(3, T0 + 7, False)                   # target 3 misses once: total stays open
    assert env.tracker.status()["total_active"] is not None
    assert len(env.db.list_outages(T0 - 10, T0 + 100, kinds=("total_internet",))) == 2


def test_stop_unsubscribes_and_persists_missed(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxxxx")
    oid = [r for r in env.db.open_outages() if r["kind"] == "target"][0]["id"]
    assert env.db.get_outage(oid)["missed"] == 3
    env.tracker.stop()
    assert env.db.get_outage(oid)["missed"] == 5
    assert env.db.get_outage(oid)["end_ts"] is None        # left open for the next start to close
    assert env.pm._sample_listeners == [] and env.pm._removal_listeners == []
    env.pm.feed(1, T0 + 5, True)                           # no listener any more
    env.tracker.on_sample(env.pm.views[1], Sample(T0 + 6, True, 1.0))   # ignored after stop
    assert env.db.get_outage(oid)["end_ts"] is None


def test_start_is_idempotent(env):
    env.tracker.start()
    assert len(env.pm._sample_listeners) == 1


def test_malformed_input_never_raises(env):
    env.tracker.on_sample({"host": "x"}, Sample(T0, False, None))       # no id
    env.tracker.on_sample({"id": 1, "host": "x"}, object())              # no ts/ok
    env.tracker.on_sample({"id": 1, "host": "x"}, {"ts": T0, "ok": False})  # dict sample accepted
    env.tracker.on_sample({"id": 1, "host": "x"}, {"ts": T0 + 1, "ok": False})
    env.tracker.on_sample({"id": 1, "host": "x"}, {"ts": T0 + 2, "ok": False})
    assert [r["kind"] for r in env.db.open_outages()] == ["target"]     # not in pm.targets() -> no total


def test_dead_ping_manager_does_not_break_processing(env):
    env.pm.add(1, "1.1.1.1")

    def boom(*a, **k):
        raise RuntimeError("boom")

    env.pm.targets = boom
    env.pm.set_in_outage = boom
    env.run(1, T0, "xxx")
    assert [r["kind"] for r in env.db.open_outages()] == ["target"]
    assert len(env.events_of("outage.start")) == 1
    assert env.tracker.status()["monitoring"] is False       # targets() failing -> not monitoring
    # timeline still works; the target is listed from its segment, not from the dead pm
    assert env.tracker.timeline(1, now=T0 + 3)["targets"] == [{"id": 1, "host": "1.1.1.1", "kind": "internet"}]


def test_transient_targets_failure_does_not_close_open_total(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxx")
    total_id = env.tracker.status()["total_active"]["id"]
    real_targets = env.pm.targets

    def boom(*a, **k):
        raise RuntimeError("boom")

    env.pm.targets = boom
    env.pm.add(2, "8.8.8.8")
    env.run(2, T0 + 3, "xxx")                    # a change happens while targets() is broken
    assert env.db.get_outage(total_id)["end_ts"] is None, "must not treat a failure as 'no targets'"
    env.pm.targets = real_targets
    env.run(2, T0 + 6, "...")                    # recovery once targets() works again -> closes
    assert env.db.get_outage(total_id)["end_ts"] == T0 + 6


def test_concurrent_samples_from_many_threads(env):
    n = 6
    for i in range(1, n + 1):
        env.pm.add(i, f"10.0.0.{i}", kind="local")
    errors: List[BaseException] = []
    lock = threading.Lock()

    def worker(tid: int) -> None:
        try:
            for k in range(120):
                ok = (k // 10) % 2 == 1            # 10 misses, 10 oks, ...
                sample = Sample(T0 + k, ok, 1.0 if ok else None)
                with lock:
                    v = env.pm.views[tid]
                    v["last"] = {"ts": T0 + k, "ok": ok, "rtt_ms": sample.rtt_ms}
                    view = dict(v)
                env.tracker.on_sample(view, sample)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(1, n + 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert errors == []
    assert not any(t.is_alive() for t in threads)
    rows = env.db.list_outages(T0 - 10, T0 + 1000, kinds=("target",))
    assert len(rows) == n * 6                        # 6 miss runs per target
    assert all(r["end_ts"] is not None and r["missed"] == 10 for r in rows)
    assert env.db.open_outages() == []
    assert env.tracker.status()["active"] == []


# --------------------------------------------------------------------------- hardening regressions

def test_removal_listener_with_garbage_never_raises(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxx")
    for bad in ("nope", None, {"id": "x"}, {"nope": 1}, object()):
        env.tracker._on_removal_event(bad)            # runs on the PingManager's thread: must not raise
    assert sorted(r["kind"] for r in env.db.open_outages()) == ["target", "total_internet"]
    env.tracker._on_removal_event({"id": "1"})        # a stringy id still works
    assert env.db.open_outages() == []


def test_long_ping_interval_widens_active_window(env):
    """With a 20 s interval a healthy target sampled 18 s ago is still a group member."""
    env.pm.add(1, "1.1.1.1")
    env.pm.add(2, "8.8.8.8")
    env.config.update({"ping": {"interval_s": 20}}, persist=False)
    env.feed(2, T0 + 2, True)
    env.feed(1, T0, False)
    env.feed(1, T0 + 20, False)
    env.feed(2, T0 + 22, True)
    env.feed(1, T0 + 40, False)                       # 3rd miss; target 2 last seen 18 s ago and healthy
    assert [r["kind"] for r in env.db.open_outages()] == ["target"]
    assert env.tracker.status()["total_active"] is None
    assert env.tracker.status()["monitoring"] is True
    # once target 2 is silent for longer than two intervals + timeout it stops counting
    env.run(1, T0 + 60, "...")                        # recover (closes target outage at T0+60)
    env.run(1, T0 + 100, "xxx")                       # falls again; target 2 last seen 78 s ago
    assert env.tracker.status()["total_active"]["kind"] == "total_internet"
    # the default window is untouched for the default 1 s interval
    env.config.update({"ping": {"interval_s": 1}}, persist=False)
    assert env.tracker._active_window() == outages.ACTIVE_WINDOW_S


def test_db_failure_on_close_keeps_state_consistent_and_retries(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxx")
    total_id = env.tracker.status()["total_active"]["id"]
    real_close = env.db.close_outage

    def boom(*a, **k):
        raise RuntimeError("disk full")

    env.db.close_outage = boom
    env.run(1, T0 + 3, "...")                         # close attempt fails in the db
    row = env.db.get_outage(1)
    assert row["end_ts"] is None
    assert env.tracker._states[1].outage is not None, "in-memory outage must survive a failed write"
    assert env.pm.calls == [(1, True)], "no set_in_outage(False) for an outage that is still open"
    assert env.db.get_outage(total_id)["end_ts"] is None, "total must not close against inconsistent state"
    assert env.events_of("outage.end") == []
    env.db.close_outage = real_close
    env.feed(1, T0 + 6, True)                         # next success retries: end = first success of the run
    assert env.db.get_outage(1)["end_ts"] == T0 + 3
    assert env.db.get_outage(total_id)["end_ts"] == T0 + 3
    assert env.pm.calls == [(1, True), (1, False)]
    assert [e["data"]["kind"] for e in env.events_of("outage.end")] == ["target", "total_internet"]


def test_db_failure_on_missed_write_does_not_duplicate_open_rows(env):
    env.pm.add(1, "1.1.1.1")

    def boom(*a, **k):
        raise RuntimeError("locked")

    env.db.update_outage_missed = boom
    env.run(1, T0, "xxxxxxxxxxxx")                    # open (missed write fails) + a 10th miss (fails again)
    rows = env.db.open_outages()
    assert [r["kind"] for r in rows] == ["target", "total_internet"]
    assert env.tracker._states[1].outage is not None
    assert env.tracker.status()["active"][-1]["missed"] == 12   # live counter still correct
    env.run(1, T0 + 12, "...")
    assert env.db.get_outage(rows[0]["id"])["missed"] == 12     # persisted on close


def test_broken_paused_property_does_not_break_status(env):
    class BrokenPM(FakePingManager):
        def __init__(self) -> None:
            self.views, self.calls = {}, []
            self._sample_listeners, self._removal_listeners = [], []

        @property
        def paused(self) -> bool:
            raise RuntimeError("dead")

    pm = BrokenPM()
    pm.add(1, "1.1.1.1")
    env.tracker._pm = pm
    pm.feed(1, T0, True)
    st = env.tracker.status()
    assert st["monitoring"] is True and st["active"] == []


def test_list_and_timeline_tolerate_bad_input(env):
    import json
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxx")
    env.clock.t = T0 + 10
    for hours in (float("inf"), float("-inf"), float("nan"), None, True, -5, "24h"):
        tl = env.tracker.timeline(hours, now=T0 + 10)
        assert tl["hours"] == 24 and tl["start_ts"] == T0 + 10 - 86400
        json.dumps(tl, allow_nan=False)
    huge = env.tracker.timeline(1e9, now=T0 + 10)
    assert huge["hours"] == outages.MAX_TIMELINE_HOURS
    json.dumps(huge, allow_nan=False)
    assert env.tracker.timeline(1, now="abc")["end_ts"] == T0 + 10      # bad now -> clock
    assert env.tracker.timeline(1, now=float("nan"))["end_ts"] == T0 + 10
    rows = env.tracker.list(None, None)                                # bad range -> last 24 h
    assert [r["kind"] for r in rows] == ["total_internet", "target"]
    assert env.tracker.list("x", float("nan")) == rows
    assert env.tracker.list(T0 - 1, T0 + 1) == rows
    json.dumps(rows, allow_nan=False)


def test_stop_between_lock_sections_does_not_open_total(env):
    env.pm.add(1, "1.1.1.1")
    real_targets = env.pm.targets

    def targets_then_stop():
        env.tracker.stop()                            # another thread stops the tracker mid-sample
        return real_targets()

    env.pm.targets = targets_then_stop
    env.run(1, T0, "xxx")
    assert [r["kind"] for r in env.db.open_outages()] == ["target"]


def test_new_total_never_starts_before_previous_total_end(env):
    env.pm.add(1, "1.1.1.1")
    env.pm.add(2, "8.8.8.8")
    env.pm.add(3, "9.9.9.9")
    for i in range(3):                                # 1 and 2 fall together -> total A from T0
        env.feed(1, T0 + i, False)
        env.feed(2, T0 + i, False)
    total_a = env.tracker.status()["total_active"]
    assert total_a is not None and total_a["start_ts"] == T0
    env.feed(3, T0 + 3, False)                        # target 3's first sample: a miss (not yet in outage)
    env.config.update({"outage": {"miss_threshold": 22}}, persist=False)
    for i in range(4, 8):                             # target 2 recovers at T0+4 -> total A ends at T0+4
        env.feed(2, T0 + i, True)
        env.feed(3, T0 + i, False)
        env.feed(1, T0 + i, False)
    assert env.db.get_outage(total_a["id"])["end_ts"] == T0 + 4
    assert env.tracker.status()["total_active"] is None
    # target 2 now goes silent (hung worker, last sample T0+7); target 3 reaches its
    # threshold at T0+24, when target 2 has been silent for 17 s and no longer counts
    for i in range(8, 25):
        env.feed(3, T0 + i, False)
        env.feed(1, T0 + i, False)
    total = env.tracker.status()["total_active"]
    assert total is not None and total["kind"] == "total_internet"
    # without the clamp this would be T0+3 (target 3's first miss), overlapping total A (T0..T0+4)
    assert total["start_ts"] == T0 + 4
    totals = env.db.list_outages(T0 - 10, T0 + 100, kinds=("total_internet",))
    assert [(t["start_ts"] - T0, t["end_ts"] and t["end_ts"] - T0) for t in totals] == [(4.0, None), (0.0, 4.0)]


def test_other_group_change_does_not_close_total_with_momentarily_stale_member(env):
    """A total closes only on evidence from its own group.

    total_local is open for the lone local target.  Its worker then goes quiet for
    longer than the active window (e.g. the machine slept) while an internet target
    falls: that internet change must not touch total_local, otherwise it would close
    with nothing to reopen it while the local target keeps missing.
    """
    env.pm.add(1, "10.0.0.1", kind="local")
    env.pm.add(2, "1.1.1.1", kind="internet")
    env.feed(2, T0, True)
    env.run(1, T0, "xxx")                              # total_local from T0
    total_local = env.tracker.status()["total_active"]
    assert total_local is not None and total_local["kind"] == "total_local"
    env.run(2, T0 + 60, "xxx")                         # internet target opens 60 s later; local silent since T0+2
    kinds = sorted(o["kind"] for o in env.tracker.status()["active"])
    assert kinds == ["target", "target", "total_internet", "total_local"]
    assert env.db.get_outage(total_local["id"])["end_ts"] is None
    env.feed(1, T0 + 63, False)                        # local target resumes, still down: nothing flaps
    assert env.db.get_outage(total_local["id"])["end_ts"] is None
    env.run(1, T0 + 64, "...")                         # real recovery closes it at the first success
    assert env.db.get_outage(total_local["id"])["end_ts"] == T0 + 64
    assert env.tracker.status()["total_active"]["kind"] == "total_internet"


def test_non_finite_sample_ts_is_ignored_and_does_not_poison_the_run(env, caplog):
    import logging as _logging
    env.pm.add(1, "1.1.1.1")
    view = env.pm.views[1]
    with caplog.at_level(_logging.WARNING, logger="tnt.outages"):
        env.tracker.on_sample(view, Sample(float("nan"), False, None))
        env.tracker.on_sample(view, Sample(float("inf"), False, None))
        env.tracker.on_sample(view, {"ts": None, "ok": False})
    assert 1 not in env.tracker._states, "a rejected sample must not create state"
    assert sum("malformed sample" in r.getMessage() for r in caplog.records) == 3
    assert not any(r.exc_info for r in caplog.records), "bad data is a warning, not a traceback"
    env.run(1, T0, "xxx")                              # valid misses open normally at their first miss
    rows = [r for r in env.db.open_outages() if r["kind"] == "target"]
    assert len(rows) == 1 and rows[0]["start_ts"] == T0
    assert not any(r.levelno >= _logging.ERROR for r in caplog.records)


def test_timeline_open_segment_reports_live_missed(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "x" * 17)                           # db copy persisted at 3 and 10; live is 17
    seg = env.tracker.timeline(1, now=T0 + 17)["segments"][0]
    assert seg["open"] is True and seg["missed"] == 17
    assert env.tracker.list(T0 - 1, T0 + 20)[-1]["missed"] == 17
    env.run(1, T0 + 17, "...")
    seg = env.tracker.timeline(1, now=T0 + 20)["segments"][0]
    assert seg["open"] is False and seg["missed"] == 17


def test_list_accepts_reversed_bounds(env):
    env.pm.add(1, "1.1.1.1")
    env.run(1, T0, "xxx")
    forward = env.tracker.list(T0 - 10, T0 + 10)
    assert len(forward) == 2
    assert env.tracker.list(T0 + 10, T0 - 10) == forward


def test_target_in_outage_changing_group_reevaluates_both_groups(env):
    """A hostname that starts resolving to the other address class moves its open outage
    to the other group: the old group's total must close and the new one is evaluated."""
    env.pm.add(1, "office.example", kind="internet")
    env.run(1, T0, "xxx")                              # lone internet target down -> total_internet
    total_internet = env.tracker.status()["total_active"]
    assert total_internet["kind"] == "total_internet"
    env.pm.views[1]["kind"] = "local"                  # re-resolved to a LAN address while still down
    env.feed(1, T0 + 3, False)
    st = env.tracker.status()
    assert sorted(o["kind"] for o in st["active"]) == ["target", "total_local"]
    assert env.db.get_outage(total_internet["id"])["end_ts"] == T0 + 3
    assert st["total_active"]["kind"] == "total_local" and st["total_active"]["start_ts"] == T0
    env.run(1, T0 + 4, "...")                          # recovery closes target + total_local
    assert env.db.open_outages() == []


def test_removal_of_never_sampled_target_checks_both_groups(env):
    env.pm.add(1, "1.1.1.1")
    env.pm.add(2, "8.8.8.8")
    env.pm.views[2]["last"] = {"ts": T0 + 2, "ok": True, "rtt_ms": 5.0}   # sampled before the tracker subscribed
    env.run(1, T0, "xxx")
    assert env.tracker.status()["total_active"] is None
    env.clock.t = T0 + 5
    env.pm.remove(2)                                   # tracker never saw a sample from 2: group unknown
    total = env.tracker.status()["total_active"]
    assert total is not None and total["kind"] == "total_internet" and total["start_ts"] == T0 + 5


# --------------------------------------------------------------------------- network changes
def test_network_change_closes_the_outage_about_the_old_address(env):
    env.pm.add(1, "gateway", kind="local")
    env.pm.views[1]["ip"] = "192.168.10.1"
    env.run(1, T0, "xxx")                                  # the old router stopped answering
    st = env.tracker.status()
    target = next(o for o in st["active"] if o["kind"] == "target")
    assert target["host"] == "gateway (192.168.10.1)" and st["total_active"]["kind"] == "total_local"
    assert env.db.get_outage(target["id"])["host"] == "gateway (192.168.10.1)"
    env.clock.t = T0 + 4
    env.pm.views[1]["ip"] = "10.20.30.1"                   # the alias followed the new default gateway
    env.tracker.on_target_ip_changed(env.pm.targets()[0], "192.168.10.1", "10.20.30.1", "network changed")
    assert env.db.open_outages() == []
    row = env.db.get_outage(target["id"])
    assert row["end_ts"] == T0 + 4 and row["note"] == "network changed" and row["missed"] == 3
    total = env.db.get_outage(st["total_active"]["id"])
    assert total["end_ts"] == T0 + 4 and total["note"] == "network changed"
    assert (1, False) in env.pm.calls
    assert [e["type"] for e in env.events][-2:] == ["outage.end", "outage.end"]
    # the next run starts fresh against the new router and is named after it
    env.run(1, T0 + 5, "xxx")
    reopened = next(o for o in env.tracker.status()["active"] if o["kind"] == "target")
    assert reopened["host"] == "gateway (10.20.30.1)" and reopened["start_ts"] == T0 + 5


def test_an_address_change_without_a_network_change_keeps_the_outage(env):
    env.pm.add(1, "cdn.example")
    env.pm.views[1]["ip"] = "203.0.113.10"
    env.run(1, T0, "xxx")
    oid = next(o for o in env.db.open_outages() if o["kind"] == "target")["id"]
    assert env.db.get_outage(oid)["host"] == "cdn.example (203.0.113.10)"
    env.pm.views[1]["ip"] = "203.0.113.11"                 # the periodic lookup rotated to another address
    env.tracker.on_target_ip_changed(env.pm.targets()[0], "203.0.113.10", "203.0.113.11", None)
    assert env.db.get_outage(oid)["end_ts"] is None
    env.tracker.on_target_ip_changed({"id": 99}, "203.0.113.1", "203.0.113.2", "network changed")   # unknown target
    env.tracker.on_target_ip_changed({"nope": 1}, "203.0.113.1", "203.0.113.2", "network changed")  # malformed
    assert env.db.get_outage(oid)["end_ts"] is None
    # an IP target is named by its address alone
    env.pm.add(2, "198.51.100.7")
    env.run(2, T0 + 10, "xxx")
    assert next(o for o in env.db.open_outages() if o["target_id"] == 2)["host"] == "198.51.100.7"


def test_tracker_subscribes_to_address_changes(env):
    registered: List[Callable] = []
    pm = FakePingManager()

    def add_ip_listener(fn):
        registered.append(fn)
        return lambda: registered.remove(fn)

    pm.add_ip_listener = add_ip_listener
    tracker = outages.OutageTracker(env.db, env.config, env.bus, pm, clock=env.clock)
    tracker.start()
    assert registered == [tracker.on_target_ip_changed]
    tracker.stop()
    assert registered == []


def _ended(db, kinds=None) -> Dict[tuple, tuple]:
    return {(r["kind"], r["target_id"], r["start_ts"]): (r["end_ts"], r["note"])
            for r in db.list_outages(T0 - 3600, T0 + 3600, kinds=kinds) if r["end_ts"] is not None}


def test_moving_to_another_network_closes_every_open_outage_with_the_note(env):
    env.pm.add(1, "1.1.1.1")
    env.pm.add(2, "gateway", kind="local")
    env.pm.views[2]["ip"] = "192.168.10.1"
    env.tracker.on_network_change({"ts": T0 - 60, "default_gateway": "192.168.10.1", "previous_gateway": None,
                                   "internet_nic": {"name": "Wi-Fi"}})
    env.run(1, T0, "xxx")
    env.run(2, T0, "xxx")
    assert len(env.db.open_outages()) == 4
    # the cable is pulled on the way to another building: that closes nothing (this PC is still cut off)
    env.tracker.on_network_change({"ts": T0 + 5, "default_gateway": None, "previous_gateway": "192.168.10.1", "internet_nic": None})
    assert len(env.db.open_outages()) == 4
    env.clock.t = T0 + 40
    env.events.clear()
    env.tracker.on_network_change({"ts": T0 + 40, "default_gateway": "10.20.30.1", "previous_gateway": None,
                                   "internet_nic": {"name": "Ethernet"}})
    assert env.db.open_outages() == []
    assert _ended(env.db) == {("target", 1, T0): (T0 + 40, "network changed"), ("target", 2, T0): (T0 + 40, "network changed"),
                              ("total_internet", None, T0): (T0 + 40, "network changed"),
                              ("total_local", None, T0): (T0 + 40, "network changed")}
    assert (1, False) in env.pm.calls and (2, False) in env.pm.calls
    assert [e["type"] for e in env.events] == ["outage.end"] * 4
    # the miss runs start afresh on the new network: two more misses are not an outage yet, a third is
    env.run(1, T0 + 41, "xx")
    assert env.db.open_outages() == []
    env.run(1, T0 + 43, "x")
    # the same network reported again (a DNS change, say) closes nothing
    env.tracker.on_network_change({"ts": T0 + 50, "default_gateway": "10.20.30.1", "previous_gateway": "10.20.30.1",
                                   "internet_nic": {"name": "Ethernet"}})
    assert sorted(o["kind"] for o in env.db.open_outages()) == ["target", "total_internet"]
    for bad in (None, {}, {"ts": "garbage"}, {"ts": float("nan"), "internet_nic": []}):
        env.tracker.on_network_change(bad)                  # never raises


def test_an_outage_while_this_pc_had_no_network_connection_keeps_counting_and_says_so(env):
    """A Wi-Fi drop is still a local outage (the pinger keeps pinging the gateway it lost); the note tells it apart
    from an outage of a network this PC was connected to."""
    env.pm.add(1, "gateway", kind="local")
    env.run(1, T0, "xxx")
    env.tracker.on_network_change({"ts": T0 + 4, "default_gateway": None, "previous_gateway": "192.168.10.1", "internet_nic": None})
    env.run(1, T0 + 4, "xxxx")
    env.run(1, T0 + 60, "...")                              # back on the same network, before or without its event
    rows = sorted(env.db.list_outages(T0 - 1, T0 + 70), key=lambda r: r["kind"])
    assert [(r["kind"], r["start_ts"], r["end_ts"], r["note"], r["missed"]) for r in rows] == [
        ("target", T0, T0 + 60, "no network connection", 7), ("total_local", T0, T0 + 60, "no network connection", 0)]
    env.tracker.on_network_change({"ts": T0 + 64, "default_gateway": "192.168.10.1", "previous_gateway": None,
                                   "internet_nic": {"name": "Wi-Fi"}})
    assert env.db.open_outages() == []
    env.run(1, T0 + 100, "xxx...")                          # connected: an ordinary outage
    env.tracker.on_network_change({"ts": T0 + 200, "default_gateway": None, "previous_gateway": "192.168.10.1", "internet_nic": None})
    env.run(1, T0 + 201, "xxx...")                          # one that begins while cut off is labelled as well
    later = sorted((r for r in env.db.list_outages(T0 + 90, T0 + 300, kinds=("target",))), key=lambda r: r["start_ts"])
    assert [r["note"] for r in later] == [None, "no network connection"]


def test_an_outage_that_recovers_on_another_network_before_the_event_says_so(env):
    live: Dict[str, Optional[str]] = {"gw": "192.168.10.1"}
    pm = FakePingManager()
    tracker = outages.OutageTracker(env.db, env.config, env.bus, pm, clock=env.clock, gateway_fn=lambda: live["gw"])
    tracker.start()

    def run(t0: float, pattern: str) -> None:
        for i, ch in enumerate(pattern):
            env.clock.t = max(env.clock.t, t0 + i)
            pm.feed(1, t0 + i, ch == ".")

    try:
        pm.add(1, "1.1.1.1")
        run(T0, "xxx")
        live["gw"] = "10.20.30.1"                           # plugged in elsewhere: 1.1.1.1 answers before net.changed
        run(T0 + 30, "...")
        run(T0 + 40, "xxx...")                              # an outage of that network, still before the event
        tracker.on_network_change({"ts": T0 + 50, "default_gateway": "10.20.30.1", "previous_gateway": None,
                                   "internet_nic": {"name": "Ethernet"}})
        run(T0 + 60, "xxx...")
        live["gw"] = None                                   # a lookup that finds nothing never invents a note
        run(T0 + 80, "xxx...")
        ended = _ended(env.db)
        assert [ended[("target", 1, T0 + s)][1] for s in (0, 40, 60, 80)] == ["network changed", None, None, None]
        assert [ended[("total_internet", None, T0 + s)][1] for s in (0, 40, 60, 80)] == ["network changed", None, None, None]
        assert ended[("target", 1, T0)][0] == T0 + 30
    finally:
        tracker.stop()


def test_rows_carry_the_network_they_opened_on_and_an_id_change_closes_what_opened_before(env):
    """tnt.networks: target, total and gap rows are tagged with the network current when they opened.  A move the gateway address
    cannot show (two sites behind 192.168.1.1, told apart by the router's MAC) closes the outages of the network left behind at
    the change; a late merge, dated back, leaves what opened since then alone (it is the new network's)."""
    current = {"id": 7}
    pm = FakePingManager()
    tracker = outages.OutageTracker(env.db, env.config, env.bus, pm, clock=env.clock, network_fn=lambda: current["id"])
    tracker.start()

    def run(tid: int, t0: float, pattern: str) -> None:
        for i, ch in enumerate(pattern):
            env.clock.t = max(env.clock.t, t0 + i)
            pm.feed(tid, t0 + i, ch == ".")

    try:
        pm.add(1, "198.51.100.1")
        pm.add(2, "gateway", kind="local")
        pm.views[2]["ip"] = "192.168.1.1"
        run(1, T0, "xxx")
        run(2, T0, "xxx")
        opened = {(r["kind"], r["target_id"]): r["network_id"] for r in env.db.open_outages()}
        assert opened == {("target", 1): 7, ("target", 2): 7, ("total_internet", None): 7, ("total_local", None): 7}
        # an immediate switch at T0+50: everything open began before it and ends then; the miss runs start afresh
        current["id"] = 9
        tracker.on_network_id_change({"old_id": 7, "new_id": 9, "ts": T0 + 50, "late": False, "reason": "network change"})
        assert env.db.open_outages() == []
        assert {(r["end_ts"], r["note"]) for r in env.db.list_outages(T0 - 1, T0 + 60)} == {(T0 + 50, "network changed")}
        run(1, T0 + 100, "xx.")
        assert env.db.open_outages() == []
        # a late merge dated back to T0+200: the outage that opened before closes then, the one that opened after stays open
        run(2, T0 + 150, "xxx")
        run(1, T0 + 210, "xxx")
        tracker.on_network_id_change({"old_id": 9, "new_id": 11, "ts": T0 + 200, "late": True, "reason": "router identified"})
        assert sorted((r["kind"], r["target_id"], r["start_ts"], r["network_id"]) for r in env.db.open_outages()) == [
            ("target", 1, T0 + 210, 9), ("total_internet", None, T0 + 210, 9)]
        closed = {(r["kind"], r["target_id"]): (r["end_ts"], r["note"]) for r in env.db.list_outages(T0 + 140, T0 + 205)
                  if r["end_ts"] is not None and r["start_ts"] >= T0 + 140}
        assert closed == {("target", 2): (T0 + 200, "network changed"), ("total_local", None): (T0 + 200, "network changed")}
        # a monitoring gap is listed under the network it began on (its time is never an outage of that network)
        info = tracker.on_monitoring_gap(T0 + 300, T0 + 900, "system sleep")
        assert env.db.get_outage(info["gap_id"])["network_id"] == 9
        for bad in (None, {}, {"ts": "garbage"}):
            tracker.on_network_id_change(bad)       # never raises
    finally:
        tracker.stop()


def test_without_a_network_function_nothing_is_tagged_and_the_stale_gap_takes_the_previous_network(env, data_dir):
    env.pm.add(1, "198.51.100.1")
    env.run(1, T0, "xxx")
    assert [r["network_id"] for r in env.db.open_outages()] == [None, None]
    database = tnt_db.Database(data_dir / "stale.db")
    try:
        database.set_meta("last_heartbeat", str(T0))
        info = outages.close_stale_outages(database, T0 + 600, network_id=4)
        assert database.get_outage(info["gap_id"])["network_id"] == 4
        assert outages.close_stale_outages(database, T0 + 600, network_id=4)["gap_id"] is None, "the heartbeat was refreshed"
        assert len(database.list_outages(T0 - 1, T0 + 601, kinds=("gap",))) == 1, "idempotent: one gap row"
    finally:
        database.close()
