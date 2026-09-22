"""Clear history (Settings > "Clear history", tnt.history): the service core.

The ranges and the cleared spans (tnt.history), the database deletes, the ping manager and its raw CSV log, the
outage tracker, the speed scheduler, the Discovery scan that runs across a clear, Engine.clear_history's orchestration
and the two routes.  Nothing here touches the real data folder, a real capture, the firewall or an adapter: the suite's
conftest gives every test its own TNT_DATA_DIR, tnt.netinfo is a stand-in, pings and speed tests are fakes, and the
parts the stores part builds in parallel (captures, faults, SIP, Pro AV) are small fakes with the contract's method
names.  Addresses are documentation ranges only.
"""
from __future__ import annotations

import datetime as _dt
import gzip
import http.client
import ipaddress
import json
import sqlite3
import sys
import threading
import time
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from tnt import history, paths
from tnt.api import routes as api_routes
from tnt.api.server import ApiServer
from tnt.config import Config
from tnt.db import Database
from tnt.events import EventBus
from tnt.outages import OutageTracker
from tnt.pinger import PingManager, RawPingLog, Sample
from tnt.speedtest import SpeedScheduler
from tnt.speedtest import scheduler as sched_mod
from tnt.speedtest.base import CANCELLED, SpeedResult, failed_result

ROOT = Path(__file__).resolve().parent.parent

#: noon on 2026-09-20 in local time, plus half a minute: every minute bucket boundary is 30 s away
T0 = _dt.datetime(2026, 9, 20, 12, 0, 30).timestamp()
DAY = 86400.0


def wait_until(pred, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.01)
    return pred()


class Clock:
    def __init__(self, now: float) -> None:
        self.now = float(now)
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self.now

    def advance(self, seconds: float) -> None:
        with self._lock:
            self.now += float(seconds)


class RealClock:
    """The wall clock, for a test that goes through Engine.clear_history (it computes since_ts from time.time())."""

    def __call__(self) -> float:
        return time.time()

    def advance(self, seconds: float) -> None:
        pass


class ScriptPinger:
    """Every echo answers (20 ms) or times out, as ``ok`` says."""

    def __init__(self) -> None:
        self.ok = True

    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> Any:
        return SimpleNamespace(ok=self.ok, rtt_ms=20.0 if self.ok else None)

    def close(self) -> None:
        pass


@pytest.fixture
def fake_netinfo(monkeypatch):
    """A stand-in tnt.netinfo: no adapter is ever enumerated and there is no default gateway."""
    mod = types.ModuleType("tnt.netinfo")

    def classify_ip(ip: str, adapters: Any = None) -> str:
        a = ipaddress.ip_address(ip.split("%")[0])
        return "local" if (a.is_private or a.is_link_local or a.is_loopback) else "internet"

    mod.classify_ip = classify_ip
    mod.get_default_gateway = lambda: None
    mod.get_adapters = lambda include_down=True, include_loopback=False: []
    monkeypatch.setitem(sys.modules, "tnt.netinfo", mod)
    return mod


class PingEnv:
    """A real PingManager (never started: every sample is one ``tick``) on a real database and raw log, with an
    OutageTracker when asked for."""

    def __init__(self, tmp: Path, with_tracker: bool = False, clock: Any = None) -> None:
        self.db = Database(tmp / "t.db")
        self.cfg = Config(tmp / "config.json").load()
        self.bus = EventBus()
        self.events: List[Dict[str, Any]] = []
        self.bus.subscribe(self.events.append)
        self.clock = clock if clock is not None else Clock(T0)
        self.pinger = ScriptPinger()
        self.raw = RawPingLog(tmp / "pings", clock=self.clock, flush_interval_s=3600.0)
        self.pm = PingManager(self.db, self.cfg, self.bus, pinger=self.pinger, raw_log=self.raw, clock=self.clock,
                              sleep=lambda s: None)
        self.tid = int(self.pm.add_target("192.0.2.10")["id"])
        self.tracker: Optional[OutageTracker] = None
        if with_tracker:
            self.tracker = OutageTracker(self.db, self.cfg, self.bus, self.pm, clock=self.clock)
            self.tracker.start()

    def tick(self, n: int = 1, ok: bool = True, step: float = 1.0) -> None:
        self.pinger.ok = ok
        for _ in range(n):
            self.pm.tick(self.tid)
            self.clock.advance(step)

    def minutes(self) -> List[Dict[str, Any]]:
        return self.db._query("SELECT * FROM ping_minutes ORDER BY minute_ts")

    def close(self) -> None:
        try:
            if self.tracker is not None:
                self.tracker.stop()
            self.pm.stop()
        finally:
            self.raw.close()
            self.db.close()


@pytest.fixture
def ping_env(tmp_path, fake_netinfo):
    e = PingEnv(tmp_path)
    yield e
    e.close()


@pytest.fixture
def outage_env(tmp_path, fake_netinfo):
    e = PingEnv(tmp_path, with_tracker=True)
    yield e
    e.close()


# --------------------------------------------------------------------------- tnt.history: ranges and spans
def test_the_eight_ranges_their_seconds_labels_and_since():
    assert list(history.RANGES.items()) == [("5m", 300), ("30m", 1800), ("1h", 3600), ("6h", 21600), ("24h", 86400),
                                            ("7d", 604800), ("30d", 2592000), ("all", None)]
    assert [(r["key"], r["label"]) for r in history.ranges_view()] == [
        ("5m", "Last 5 minutes"), ("30m", "Last 30 minutes"), ("1h", "Last hour"), ("6h", "Last 6 hours"),
        ("24h", "Last 24 hours"), ("7d", "Last 7 days"), ("30d", "Last 30 days"), ("all", "All time")]
    assert history.DEFAULT_RANGE == "1h" and set(history.RANGE_LABELS) == set(history.RANGES)
    # since is computed on the service clock: now - seconds, None for all time
    assert history.since_for("1h", T0) == T0 - 3600 and history.since_for("all", T0) is None
    for bad in ("2h", "", "ALL", None, 3600, ["1h"], {"1h": 1}):
        assert not history.valid_range(bad)
        with pytest.raises(ValueError):
            history.since_for(bad, T0)       # type: ignore[arg-type]
    assert history.empty_counts() == {k: 0 for k in ("ping", "outages", "speed", "discovery", "captures", "faults",
                                                     "sip", "proav")}


def test_cleared_spans_keep_the_newest_fifty_drop_month_old_ones_and_all_time_replaces_them():
    spans: List[Dict[str, Any]] = []
    for i in range(60):
        spans = history.add_span(spans, T0 + i * 10 - 3600, T0 + i * 10, "1h")
    assert len(spans) == history.MAX_SPANS and spans[-1]["at"] == T0 + 590 and spans[0]["at"] == T0 + 100
    # a span that ended more than 30 days before the new clear goes
    later = history.add_span(spans, T0 + 31 * DAY - 300, T0 + 31 * DAY, "5m")
    assert later == [{"since_ts": T0 + 31 * DAY - 300, "at": T0 + 31 * DAY, "range": "5m"}]
    kept = history.add_span(spans, T0 + 29 * DAY, T0 + 29 * DAY + 300, "5m")
    assert len(kept) == history.MAX_SPANS and kept[-1]["range"] == "5m"
    # an all-time clear replaces the whole list with its one entry
    assert history.add_span(spans, None, T0 + 999, "all") == [{"since_ts": None, "at": T0 + 999, "range": "all"}]


def test_cleared_spans_are_clipped_to_the_timeline_merged_and_all_time_starts_at_its_start():
    spans = [{"since_ts": T0 - 3600, "at": T0, "range": "1h"},
             {"since_ts": T0 - 600, "at": T0 + 60, "range": "5m"},          # overlaps the first: one span
             {"since_ts": T0 + 1000, "at": T0 + 1300, "range": "5m"},
             {"since_ts": T0 + 9000, "at": T0 + 9300, "range": "5m"}]       # after the window: left out
    assert history.clip_spans(spans, T0 - 1800, T0 + 5000) == [
        {"start_ts": T0 - 1800, "end_ts": T0 + 60}, {"start_ts": T0 + 1000, "end_ts": T0 + 1300}]
    assert history.clip_spans([{"since_ts": None, "at": T0, "range": "all"}], T0 - 100, T0 + 100) == [
        {"start_ts": T0 - 100, "end_ts": T0}]


def test_an_unreadable_record_of_clears_reads_as_none(tmp_path):
    db = Database(tmp_path / "t.db")
    try:
        for junk in ("not json", "{}", '[{"at": "x"}]', '[{"since_ts": 1, "at": 2, "range": "2h"}]',
                     '[{"since_ts": null, "at": 2, "range": "1h"}]'):
            db.set_meta(history.META_KEY, junk)
            assert history.load_spans(db) == [] and history.last_span(db) is None
        assert history.history_view(None) == {"ranges": history.ranges_view(), "last": None}
        history.record_span(db, T0 - 3600, T0, "1h")
        assert history.history_view(db)["last"] == {"since_ts": T0 - 3600, "at": T0, "range": "1h"}
    finally:
        db.close()


def test_a_capture_left_alone_is_named_for_the_administrator_and_only_counted_for_everyone():
    # the answer to the administrator who asked names the file, in one sentence that reads after the colon
    assert history.capture_skip_reason("TNT-capture-20260920-120000.pcapng", "It is being downloaded.") == \
        "TNT-capture-20260920-120000.pcapng was left alone: it is being downloaded"
    # the history.cleared event every window hears says how many and why, one entry per reason, never a name
    assert history.public_capture_skips(["It is being downloaded", "It is marked read-only", "It is being downloaded"]) == [
        {"what": "captures", "reason": "2 packet captures were left alone, each for this reason: it is being downloaded"},
        {"what": "captures", "reason": "A packet capture was left alone: it is marked read-only"}]
    assert history.public_capture_skips([]) == []
    # every reason is one sentence without its closing period: the page adds one after each
    assert history.reason_text("  Stop it and clear the history again.  ") == "Stop it and clear the history again"


# --------------------------------------------------------------------------- the database deletes
def _outage(db: Database, kind: str, start: float, end: Optional[float], tid: Optional[int] = 1) -> int:
    oid = db.open_outage(kind, tid if kind == "target" else None, start, host="192.0.2.10" if kind == "target" else None)
    if end is not None:
        db.close_outage(oid, end, 3)
    return oid


def test_a_minute_bucket_overlapping_since_goes_whole_and_one_that_ended_before_it_stays(tmp_path):
    db = Database(tmp_path / "t.db")
    try:
        since = T0                                   # 30 s into a minute
        m = int(T0 // 60) * 60                        # the bucket that straddles since
        for minute in (m - 120, m - 60, m, m + 60):
            db.upsert_ping_minute(1, minute, 60, 60, 20.0, 19.0, 21.0, 0.5)
        db.upsert_ping_minute(1, m, 10, 10, 20.0, 19.0, 21.0, 0.5, 7)       # the same minute on another network
        assert db.delete_ping_minutes_since(since) == 3
        # [m-60, m) ended before since: it stays; nothing that overlaps [since, now] is left, on any network
        assert [r["minute_ts"] for r in db._query("SELECT minute_ts FROM ping_minutes ORDER BY minute_ts")] == [m - 120, m - 60]
        assert db.delete_ping_minutes_since(None) == 2
        assert db._query("SELECT * FROM ping_minutes") == []
    finally:
        db.close()


def test_outages_overlapping_since_go_whole_with_their_events_and_older_ones_stay(tmp_path):
    db = Database(tmp_path / "t.db")
    try:
        since = T0
        before = _outage(db, "target", since - 900, since - 600)             # ended before since: stays
        straddling = _outage(db, "target", since - 300, since + 60)           # started before, ended after: goes whole
        open_row = _outage(db, "total_internet", since + 100, None)           # open: goes
        gap = _outage(db, "gap", since - 50, since + 10)                       # a monitoring gap is outage history too
        db.add_event("warning", "outage", "Outage started: 192.0.2.10", ts=since - 900)
        db.add_event("warning", "outage", "Outage started: 192.0.2.10", ts=since + 5)
        db.add_event("info", "network", "network changed: somewhere", ts=since + 5)
        assert db.delete_outages_since(since) == 3
        assert [r["id"] for r in db._query("SELECT id FROM outages")] == [before]
        assert all(db.get_outage(i) is None for i in (straddling, open_row, gap))
        assert [(e["category"], e["ts"]) for e in db.list_events(10)] == [("network", since + 5), ("outage", since - 900)]
        assert db.delete_outages_since(None) == 1
        assert [e["category"] for e in db.list_events(10)] == ["network"]
    finally:
        db.close()


def test_the_database_clear_is_one_transaction_that_rolls_back_on_a_failure(tmp_path):
    db = Database(tmp_path / "t.db")
    try:
        sid = db.add_speedtest({"ts": T0 + 10, "ok": True, "backend": "fake", "download_mbps": 90.0})
        rid = db.add_discovery_run({"ts": T0 + 20, "cidr": "192.0.2.0/24", "ports": [80]},
                                   [{"ip": "192.0.2.5", "ping_ok": True, "open_ports": [80]}])
        db.add_event("warning", "outage", "Outage started: 192.0.2.10", ts=T0 + 30)
        db._conn.execute("CREATE TRIGGER refuse BEFORE DELETE ON discovery_runs BEGIN SELECT RAISE(ABORT, 'disk said no'); END")
        with pytest.raises(sqlite3.DatabaseError):
            db.clear_history(T0)
        # never half applied: the speed test deleted before the failure is back, and so is everything else
        assert [r["id"] for r in db.list_speedtests(0, 2e9)] == [sid]
        assert db.get_discovery_run(rid)["hosts"][0]["ip"] == "192.0.2.5"
        assert [e["category"] for e in db.list_events(10)] == ["outage"]
        db._conn.execute("DROP TRIGGER refuse")
        older = db.add_speedtest({"ts": T0 - 10, "ok": True, "backend": "fake"})
        assert db.clear_history(T0) == {"speedtests": 1, "discovery_runs": 1, "discovery_hosts": 1, "events": 1}
        assert [r["id"] for r in db.list_speedtests(0, 2e9)] == [older]
        assert db._query("SELECT * FROM discovery_hosts") == []
    finally:
        db.close()


def test_the_owners_deletes_report_where_the_earliest_record_they_removed_began(tmp_path):
    # a record that straddles since goes whole, so the cleared time on the Outages timeline starts where it began
    db = Database(tmp_path / "t.db")
    try:
        since = T0
        m = int(T0 // 60) * 60                        # the bucket that straddles since
        info: Dict[str, Any] = {}
        assert db.delete_ping_minutes_since(since, info=info) == 0 and info == {"earliest_ts": None}
        for minute in (m - 60, m, m + 60):
            db.upsert_ping_minute(1, minute, 60, 60, 20.0, 19.0, 21.0, 0.5)
        assert db.delete_ping_minutes_since(since, info=info) == 2 and info["earliest_ts"] == m
        _outage(db, "target", since - 900, since - 600)                      # ended before since: stays, not counted
        _outage(db, "target", since - 300, since + 60)                       # straddles since: goes, from its start
        _outage(db, "gap", since + 10, None)
        assert db.delete_outages_since(since, info=info) == 2 and info["earliest_ts"] == since - 300
        assert db.delete_outages_since(None, info=info) == 1 and info["earliest_ts"] == since - 900
    finally:
        db.close()


def test_the_database_clear_keeps_outage_events_written_after_the_clear_began(tmp_path):
    # The tracker deleted its own events already; the database step repeats that only up to the moment the clear began,
    # so the "Outage started" of a target still down, reopened right after the tracker's clear, is not lost.
    db = Database(tmp_path / "t.db")
    try:
        db.add_event("warning", "outage", "Outage started: 192.0.2.10", ts=T0 + 10)
        db.add_event("warning", "outage", "Outage started: 192.0.2.10", ts=T0 + 100)
        assert db.clear_history(T0, until_ts=T0 + 50)["events"] == 1
        assert [e["ts"] for e in db.list_events(10)] == [T0 + 100]
        assert db.clear_history(None, until_ts=T0 + 50)["events"] == 0
        assert db.clear_history(None)["events"] == 1
    finally:
        db.close()


# --------------------------------------------------------------------------- the raw per-second CSV log
def _csv(path: Path, rows: List[float], gz: bool = False) -> None:
    text = "ts,target_id,host,ok,rtt_ms,bytes\n" + "".join(f"{ts:.3f},1,192.0.2.10,1,20.0,32\n" for ts in rows)
    if gz:
        with gzip.open(path, "wt", encoding="utf-8", newline="") as fh:
            fh.write(text)
    else:
        path.write_text(text, encoding="utf-8", newline="")


def _rows(path: Path) -> List[str]:
    opener = gzip.open if path.name.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", newline="") as fh:   # type: ignore[operator]
        return [line.rstrip("\n") for line in fh]


def test_the_raw_log_keeps_earlier_days_filters_the_day_of_since_and_deletes_later_days_only(tmp_path):
    folder = tmp_path / "pings"
    since = _dt.datetime(2026, 9, 20, 12, 0, 0).timestamp()
    today = since + 2 * DAY
    raw = RawPingLog(folder, clock=Clock(today), flush_interval_s=3600.0)
    try:
        _csv(folder / "2026-09-19.csv.gz", [since - DAY, since - DAY + 1], gz=True)
        _csv(folder / "2026-09-20.csv", [since - 3600, since - 1, since, since + 600])
        _csv(folder / "2026-09-20.csv.gz", [since - 7200, since + 60], gz=True)
        _csv(folder / "2026-09-21.csv.gz", [since + DAY], gz=True)
        # nothing but YYYY-MM-DD.csv(.gz) is ever touched, and a folder that looks like one is not a file
        (folder / "notes.txt").write_text("keep", encoding="utf-8")
        (folder / "2026-09-21.csv.bak").write_text("keep", encoding="utf-8")
        (folder / "x2026-09-21.csv").write_text("keep", encoding="utf-8")
        (folder / "2026-09-23.csv").mkdir()
        # today's file is open with rows still in its buffer
        raw.write(today + 5, 1, "192.0.2.10", True, 20.0, 32)
        assert raw.current_path == folder / "2026-09-22.csv"
        removed = raw.clear_since(since)
        assert removed == 2 + 1 + 2      # two rows of the 20th's csv, one of its gz, two files after it
        names = sorted(p.name for p in folder.iterdir())
        assert names == ["2026-09-19.csv.gz", "2026-09-20.csv", "2026-09-20.csv.gz", "2026-09-21.csv.bak", "2026-09-23.csv",
                         "notes.txt", "x2026-09-21.csv"]
        assert _rows(folder / "2026-09-20.csv") == ["ts,target_id,host,ok,rtt_ms,bytes",
                                                   f"{since - 3600:.3f},1,192.0.2.10,1,20.0,32",
                                                   f"{since - 1:.3f},1,192.0.2.10,1,20.0,32"]
        assert _rows(folder / "2026-09-20.csv.gz")[1:] == [f"{since - 7200:.3f},1,192.0.2.10,1,20.0,32"]
        assert len(_rows(folder / "2026-09-19.csv.gz")) == 3
        assert (folder / "notes.txt").read_text(encoding="utf-8") == "keep" and (folder / "2026-09-23.csv").is_dir()
        # the next row reopens today's file with its header
        raw.write(today + 6, 1, "192.0.2.10", True, 20.0, 32)
        raw.flush()
        assert _rows(folder / "2026-09-22.csv") == ["ts,target_id,host,ok,rtt_ms,bytes", f"{today + 6:.3f},1,192.0.2.10,1,20.0,32"]
        # all time: every daily file goes, nothing else does
        assert raw.clear_since(None) == 4
        assert sorted(p.name for p in folder.iterdir()) == ["2026-09-21.csv.bak", "2026-09-23.csv", "notes.txt",
                                                            "x2026-09-21.csv"]
        assert raw.last_clear_failed == []
    finally:
        raw.close()


def test_the_open_raw_log_keeps_its_buffered_rows_before_since_and_carries_on(tmp_path):
    folder = tmp_path / "pings"
    since = _dt.datetime(2026, 9, 20, 12, 0, 0).timestamp()
    raw = RawPingLog(folder, clock=Clock(since + 30), flush_interval_s=3600.0)
    try:
        for ts in (since - 100, since - 50, since + 10):
            raw.write(ts, 1, "192.0.2.10", True, 20.0, 32)
        path = folder / "2026-09-20.csv"
        assert _rows(path) == [] or len(_rows(path)) < 4, "the rows are still in the write buffer"
        assert raw.clear_since(since) == 1
        raw.write(since + 20, 1, "192.0.2.10", False, None, 32)
        raw.flush()
        assert _rows(path) == ["ts,target_id,host,ok,rtt_ms,bytes", f"{since - 100:.3f},1,192.0.2.10,1,20.0,32",
                               f"{since - 50:.3f},1,192.0.2.10,1,20.0,32", f"{since + 20:.3f},1,192.0.2.10,0,,32"]
    finally:
        raw.close()


def test_the_raw_log_clear_waits_for_a_running_gzip_of_an_earlier_day(tmp_path):
    folder = tmp_path / "pings"
    since = _dt.datetime(2026, 9, 20, 12, 0, 0).timestamp()
    raw = RawPingLog(folder, clock=Clock(since + DAY), flush_interval_s=3600.0)
    try:
        _csv(folder / "2026-09-20.csv", [since - 10, since + 10])
        raw._gz_lock.acquire()                  # a gzip of that day is running
        done = threading.Event()
        worker = threading.Thread(target=lambda: (raw.clear_since(since), done.set()), daemon=True)
        worker.start()
        try:
            assert not done.wait(0.3), "the clear must not rewrite a file that is being compressed"
            assert len(_rows(folder / "2026-09-20.csv")) == 3
        finally:
            raw._gz_lock.release()
        assert done.wait(5)
        assert len(_rows(folder / "2026-09-20.csv")) == 2
    finally:
        raw.close()


def test_the_raw_log_keeps_rows_stamped_after_the_clear_began_on_every_day(tmp_path):
    # PingManager passes the moment its clear began: a row stamped from then on was recorded after the clear (the ring
    # keeps the same samples), so it stays, whichever day's file it is in
    folder = tmp_path / "pings"
    since = _dt.datetime(2026, 9, 20, 12, 0, 0).timestamp()
    until = _dt.datetime(2026, 9, 22, 0, 0, 5).timestamp()        # the clear began five seconds into the 22nd
    raw = RawPingLog(folder, clock=Clock(until + 10), flush_interval_s=3600.0)
    try:
        _csv(folder / "2026-09-20.csv.gz", [since - 10, since + 10], gz=True)
        _csv(folder / "2026-09-21.csv.gz", [since + DAY], gz=True)
        _csv(folder / "2026-09-22.csv", [until - 4, until, until + 3])
        assert raw.clear_since(since, until_ts=until) == 3      # a row of the 20th, the 21st's file, a row of the 22nd
        assert sorted(p.name for p in folder.iterdir()) == ["2026-09-20.csv.gz", "2026-09-22.csv"]
        assert _rows(folder / "2026-09-20.csv.gz")[1:] == [f"{since - 10:.3f},1,192.0.2.10,1,20.0,32"]
        assert _rows(folder / "2026-09-22.csv")[1:] == [f"{until:.3f},1,192.0.2.10,1,20.0,32",
                                                        f"{until + 3:.3f},1,192.0.2.10,1,20.0,32"]
        # all time up to a clear's start: every earlier file and row goes, the later row stays
        assert raw.clear_since(None, until_ts=until + 1) == 2
        assert sorted(p.name for p in folder.iterdir()) == ["2026-09-22.csv"]
        assert _rows(folder / "2026-09-22.csv")[1:] == [f"{until + 3:.3f},1,192.0.2.10,1,20.0,32"]
    finally:
        raw.close()


def test_a_leftover_rewrite_file_is_removed_only_when_it_is_a_regular_file(tmp_path):
    folder = tmp_path / "pings"
    raw = RawPingLog(folder, clock=Clock(T0), flush_interval_s=3600.0)
    try:
        (folder / ".2026-09-20.csv.clearing").write_text("half a rewrite", encoding="utf-8")   # a crash mid-rewrite
        (folder / ".2026-09-19.csv.gz.clearing").mkdir()           # that name, but not a file: left alone
        (folder / ".2026-09-18.csv.bak.clearing").write_text("keep", encoding="utf-8")         # not that name
        raw.clear_since(T0)
        assert sorted(p.name for p in folder.iterdir()) == [".2026-09-18.csv.bak.clearing", ".2026-09-19.csv.gz.clearing"]
        assert raw.last_clear_failed == []
    finally:
        raw.close()


# --------------------------------------------------------------------------- the ping manager: nothing comes back
def test_the_minute_being_built_when_the_history_is_cleared_is_never_written(ping_env):
    e = ping_env
    e.tick(10)                                          # T0 .. T0+9: the minute is still being built
    assert e.pm.clear_history(e.clock() - 300) == 0
    e.tick(20)                                          # T0+10 .. T0+29, after the clear, in the same minute
    e.tick(1)                                           # T0+30 rolls the minute
    rows = e.minutes()
    assert len(rows) == 1 and rows[0]["minute_ts"] == int(T0 // 60) * 60
    assert rows[0]["sent"] == 20, "only the samples recorded after the clear are in that minute"


def test_a_minute_queued_in_the_writer_before_the_clear_is_never_written(ping_env):
    e = ping_env
    e.pm._writer.start()
    gate = threading.Event()
    assert e.pm._writer.submit(gate.wait, 5.0)          # the writer is busy (a database locked by a backup tool)
    e.tick(31)                                          # the 30 samples of the minute, then the roll queues its row
    assert e.pm._writer.pending >= 1
    e.pm.clear_history(None)
    gate.set()
    drained = threading.Event()
    assert e.pm._writer.submit(drained.set) and drained.wait(5.0)
    assert e.minutes() == []


def test_a_minute_a_worker_took_out_of_its_lock_before_the_clear_is_never_written(ping_env):
    e = ping_env
    e.tick(30)
    taken, go = threading.Event(), threading.Event()
    upsert = e.pm._upsert

    def stalled(st: Any, agg: Any) -> None:
        taken.set()                                     # the worker holds the finished minute outside the lock ...
        go.wait(5.0)
        upsert(st, agg)                                 # ... and hands it over after the clear

    e.pm._upsert = stalled                              # type: ignore[method-assign]
    worker = threading.Thread(target=e.pm.tick, args=(e.tid,), daemon=True)
    worker.start()
    assert taken.wait(5.0)
    g0 = e.pm._clear_gen
    clearing = threading.Thread(target=e.pm.clear_history, args=(None,), daemon=True)
    clearing.start()
    assert wait_until(lambda: e.pm._clear_gen != g0)   # the clear has begun (it waits for this sample) ...
    go.set()                                            # ... when the worker hands its minute over
    worker.join(5.0)
    clearing.join(5.0)
    assert not clearing.is_alive() and e.minutes() == []


def test_a_minute_write_that_passed_its_check_lands_before_the_delete_and_goes_with_it(ping_env):
    e = ping_env
    e.tick(30)
    writing, go = threading.Event(), threading.Event()
    upsert = e.db.upsert_ping_minute

    def slow(*args: Any) -> None:
        writing.set()
        go.wait(5.0)
        upsert(*args)

    e.db.upsert_ping_minute = slow                      # type: ignore[method-assign]
    worker = threading.Thread(target=e.pm.tick, args=(e.tid,), daemon=True)
    worker.start()
    assert writing.wait(5.0)
    clearing = threading.Thread(target=e.pm.clear_history, args=(None,), daemon=True)
    clearing.start()
    assert not wait_until(lambda: not clearing.is_alive(), 0.3), "the delete waits for the write already under way"
    go.set()
    worker.join(5.0)
    clearing.join(5.0)
    assert not clearing.is_alive() and e.minutes() == []


def test_clearing_part_of_the_ping_history_keeps_what_came_before(ping_env):
    e = ping_env
    e.tick(600)                                         # T0 .. T0+599: ten minutes
    since = T0 + 300
    before = {r["minute_ts"] for r in e.minutes()}
    deleted = e.pm.clear_history(since)
    after = e.minutes()
    m_since = int(since // 60) * 60                     # the bucket that straddles since goes whole
    assert {r["minute_ts"] for r in after} == {m for m in before if m < m_since}
    assert deleted == len(before) - len(after) and all(r["minute_ts"] + 60 <= since for r in after)
    samples = e.pm.samples(e.tid, 3600)
    assert len(samples) == 300 and max(s.ts for s in samples) == since - 1
    view = e.pm.target(e.tid)
    assert view["last"]["ts"] == since - 1 and view["consecutive_ok"] == 300 and view["consecutive_missed"] == 0
    assert view["day"]["sent"] == sum(r["sent"] for r in after)
    # the raw log kept its rows before since (they were still in the write buffer)
    assert len(_rows(e.raw.directory / "2026-09-20.csv")) == 1 + 300
    # the straddling bucket began before since: the cleared span on the timeline starts there
    assert e.pm.last_clear_info == {"minutes": deleted, "raw_log": 300, "raw_log_failed": [], "earliest_ts": m_since}


def test_clearing_all_ping_history_empties_the_ring_and_greys_the_light(ping_env):
    e = ping_env
    e.tick(120)
    e.pm.clear_history(None)
    view = e.pm.target(e.tid)
    assert e.minutes() == [] and e.pm.samples(e.tid, 3600) == [] and view["last"] is None
    assert view["light"] == "grey" and view["day"]["sent"] == 0 and view["window"]["sent"] == 0
    assert list((e.raw.directory).glob("*.csv*")) == []
    e.tick(1)
    assert e.pm.target(e.tid)["light"] == "green"


def test_a_ping_delete_the_database_refuses_raises_and_leaves_the_samples_alone(ping_env):
    e = ping_env
    e.tick(90)
    rows = e.minutes()

    def locked(since_ts: Optional[float], info: Any = None) -> int:
        raise sqlite3.OperationalError("database is locked")

    e.db.delete_ping_minutes_since = locked            # type: ignore[method-assign]
    with pytest.raises(sqlite3.OperationalError):
        e.pm.clear_history(None)
    # the caller reports it; nothing half done: the stored minutes and the ring are as they were
    assert e.minutes() == rows and len(e.pm.samples(e.tid, 3600)) == 90


def test_a_sample_stamped_inside_the_cleared_span_but_recorded_after_it_is_dropped(ping_env):
    e = ping_env
    e.tick(5)
    at = e.clock()
    e.pm.clear_history(at - 300)
    st = e.pm._state(e.tid)
    e.pm._record(st, Sample(ts=at - 0.5, ok=False, rtt_ms=None), 32)     # its echo was out while the clear ran
    assert e.pm.samples(e.tid, 3600) == []
    e.pm._record(st, Sample(ts=at - 7200, ok=True, rtt_ms=20.0), 32)     # a wall clock set back an hour: kept
    e.pm._record(st, Sample(ts=at, ok=True, rtt_ms=20.0), 32)
    assert [s.ts for s in e.pm.samples(e.tid, 99999)] == [at - 7200, at]


def test_a_sample_checked_just_before_a_clear_lands_goes_nowhere(ping_env):
    # The race a reviewer's probe found: the worker has checked its sample against the clears so far, and a clear lands
    # before it takes the target's lock (here inside _network_id, on the worker's own thread).  The sample, stamped half
    # a second before that clear, must reach neither the ring, its minute, the raw log nor the listeners.
    e = ping_env
    heard: List[float] = []
    e.pm.add_sample_listener(lambda view, s: heard.append(s.ts))
    e.tick(5)
    stamped = e.clock()
    real = e.pm._network_id
    fired: List[bool] = []

    def clear_in_between() -> Optional[int]:
        if not fired:
            fired.append(True)
            e.clock.advance(0.5)
            e.pm.clear_history(e.clock() - 300)
        return real()

    e.pm._network_id = clear_in_between                 # type: ignore[method-assign]
    e.pm.tick(e.tid)
    e.pm._network_id = real                             # type: ignore[method-assign]
    assert fired and e.pm.samples(e.tid, 3600) == [] and stamped not in heard
    e.tick(30)                                          # 12:00:35.5 .. 12:01:04.5: after the clear; the minute rolls
    rows = e.minutes()
    assert [(r["minute_ts"], r["sent"]) for r in rows] == [(int(T0 // 60) * 60, 25)], "only what came after the clear"
    e.raw.flush()
    logged = [line.split(",")[0] for line in _rows(e.raw.directory / "2026-09-20.csv")[1:]]
    assert len(logged) == 30 and f"{stamped:.3f}" not in logged


def test_a_sample_on_its_way_when_the_history_is_cleared_is_waited_for_and_removed_everywhere(outage_env):
    # A later window of the same race: the sample is already in the ring and its minute and is on its way to the raw log
    # and the outage tracker when the clear starts.  The clear waits until it has been recorded everywhere and then
    # removes it from every store; the outage its third miss opened goes with the tracker's clear.
    e = outage_env
    tracker = e.tracker
    assert tracker is not None
    e.tick(2, ok=False)                                 # two misses: the third opens an outage
    stamped = e.clock()
    real_write = e.raw.write
    state: Dict[str, Any] = {}

    def slow_write(ts: float, *args: Any, **kwargs: Any) -> None:
        if ts == stamped and "clearing" not in state:
            e.clock.advance(0.5)
            since = stamped - 300
            g0 = e.pm._clear_gen

            def clear() -> None:
                e.pm.clear_history(since)
                tracker.clear_history(since)            # the Engine's order: ping, then outages

            state["clearing"] = threading.Thread(target=clear, daemon=True)
            state["clearing"].start()
            assert wait_until(lambda: e.pm._clear_gen != g0)
            state["waited"] = not wait_until(lambda: not state["clearing"].is_alive(), 0.3)
        real_write(ts, *args, **kwargs)

    e.raw.write = slow_write                            # type: ignore[method-assign]
    e.pinger.ok = False
    e.pm.tick(e.tid)
    state["clearing"].join(5.0)
    assert not state["clearing"].is_alive()
    assert state["waited"], "the clear waits for the sample already on its way"
    assert e.pm.samples(e.tid, 3600) == [] and e.pm._state(e.tid).minute is None
    path = e.raw.directory / "2026-09-20.csv"
    assert not path.exists() or all(not line.startswith(f"{stamped:.3f},") for line in _rows(path))
    assert e.db.open_outages() == [] and tracker.status()["active"] == []
    assert e.pm.target(e.tid)["in_outage"] is False
    e.tick(2, ok=False)
    assert e.db.open_outages() == [], "the misses before the clear do not count towards a new outage"


def test_a_minute_that_ended_before_the_cleared_span_is_still_written(ping_env):
    # Only a minute that overlaps a cleared span is voided: one that ended before it, still being built by a worker that
    # sat in long timeouts or still queued in a busy writer, is written as always.
    e = ping_env
    e.pm._writer.start()
    gate = threading.Event()
    assert e.pm._writer.submit(gate.wait, 5.0)          # the writer is busy
    e.tick(31)                                          # 12:00:30 .. 12:00:59, then 12:01:00 queues that minute
    assert e.pm._writer.pending >= 1
    e.clock.advance(600)                                # ten minutes without a sample: 12:01's minute is still open
    e.pm.clear_history(e.clock() - 300)                 # the last five minutes: neither minute is in them
    gate.set()
    e.tick(1)                                           # the next sample rolls 12:01's minute
    drained = threading.Event()
    assert e.pm._writer.submit(drained.set) and drained.wait(5.0)
    m0 = int(T0 // 60) * 60
    assert [(r["minute_ts"], r["sent"]) for r in e.minutes()] == [(m0, 30), (m0 + 60, 1)]
    assert e.pm.last_clear_info["minutes"] == 0 and e.pm.last_clear_info["earliest_ts"] is None


# --------------------------------------------------------------------------- the outage tracker
def _outage_writes(db: Database) -> List[int]:
    """Every outage id the tracker closes or updates from now on."""
    ids: List[int] = []
    close, update = db.close_outage, db.update_outage_missed

    def rec_close(oid: int, *a: Any, **k: Any) -> None:
        ids.append(int(oid))
        close(oid, *a, **k)

    def rec_update(oid: int, *a: Any, **k: Any) -> None:
        ids.append(int(oid))
        update(oid, *a, **k)

    db.close_outage = rec_close                         # type: ignore[method-assign]
    db.update_outage_missed = rec_update                # type: ignore[method-assign]
    return ids


def test_an_open_outage_is_deleted_forgotten_and_a_target_still_down_opens_a_fresh_one(outage_env):
    e = outage_env
    tracker = e.tracker
    assert tracker is not None
    e.tick(5, ok=False)                                 # three misses open it at T0, two more
    rows = e.db.open_outages()
    # the only local target is down, so its group is down too: a target outage and a total, both open
    assert sorted(r["kind"] for r in rows) == ["target", "total_local"] and all(r["start_ts"] == T0 for r in rows)
    old = {int(r["id"]) for r in rows}
    assert e.pm.target(e.tid)["in_outage"] is True and e.pm.target(e.tid)["light"] == "red"
    writes = _outage_writes(e.db)
    at = e.clock()
    e.pm.clear_history(at - 3600)                       # the Engine's order: ping, then outages
    assert tracker.clear_history(at - 3600) == 2
    assert all(e.db.get_outage(i) is None for i in old)
    assert [ev for ev in e.db.list_events(20) if ev["category"] == "outage"] == []
    view = e.pm.target(e.tid)
    assert view["in_outage"] is False and view["light"] == "grey"
    status = tracker.status()
    assert status["active"] == [] and status["total_active"] is None and status["count_24h"] == 0
    e.tick(2, ok=False)
    assert e.db.open_outages() == [], "a fresh run of misses starts after the clear"
    e.tick(1, ok=False)
    fresh = e.db.open_outages()
    assert sorted(r["kind"] for r in fresh) == ["target", "total_local"] and all(r["start_ts"] == at for r in fresh)
    assert not old & {int(r["id"]) for r in fresh}
    assert e.pm.target(e.tid)["in_outage"] is True
    e.tick(3, ok=True)
    assert e.db.open_outages() == [] and e.pm.target(e.tid)["in_outage"] is False
    tracker.stop()
    assert writes and not old & set(writes), "no close or update was ever written into a deleted row"


def test_an_outage_effect_computed_before_a_clear_never_turns_the_light_red_after_it(outage_env):
    e = outage_env
    tracker = e.tracker
    assert tracker is not None
    e.tick(3, ok=False)
    published: List[str] = []
    e.bus.subscribe(lambda ev: published.append(ev["type"]))
    stale = [("in_outage", e.tid, True), ("event", "outage.start", {"id": 1}, tracker._clear_gen)]
    tracker.clear_history(None)
    tracker._run_effects(stale)                          # what a worker computed just before the clear
    assert e.pm.target(e.tid)["in_outage"] is False and "outage.start" not in published


def test_the_timeline_carries_the_cleared_spans_clipped_to_its_range(outage_env):
    e = outage_env
    tracker = e.tracker
    assert tracker is not None
    now = e.clock()
    history.record_span(e.db, now - 7200, now - 3600, "1h")
    history.record_span(e.db, now - 600, now - 300, "5m")
    tl = tracker.timeline(1.5, now=now)
    assert tl["cleared"] == [{"start_ts": now - 5400, "end_ts": now - 3600}, {"start_ts": now - 600, "end_ts": now - 300}]
    assert tracker.timeline(0.05, now=now)["cleared"] == []


# --------------------------------------------------------------------------- the speed scheduler
class BlockingBackend:
    """A speed test that runs until it is cancelled, then returns *outcome*: a failed "cancelled" result, or one that
    finished anyway (the cancel landed a moment too late)."""

    name = "fake"

    def __init__(self, outcome: str) -> None:
        self.outcome = outcome
        self.started = threading.Event()

    def available(self, config: Any) -> Any:
        return True, "fake"

    def run(self, config: Any, progress: Any = None, cancel: Any = None) -> SpeedResult:
        self.started.set()
        assert cancel is not None and cancel.wait(5.0)
        if self.outcome == "cancelled":
            return failed_result("fake", time.time(), CANCELLED)
        return SpeedResult(ok=True, ts=time.time(), backend="fake", download_mbps=100.0, upload_mbps=20.0,
                           latency_ms=10.0, duration_s=1.0)


@pytest.mark.parametrize("outcome", ["cancelled", "finished"])
def test_a_running_speed_test_is_cancelled_silently_and_keeps_no_row(tmp_path, monkeypatch, outcome):
    db = Database(tmp_path / "t.db")
    bus = EventBus()
    events: List[Dict[str, Any]] = []
    bus.subscribe(events.append)
    backend = BlockingBackend(outcome)
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: backend)
    now = time.time()
    older = db.add_speedtest({"ts": now - 7200, "ok": True, "backend": "fake", "download_mbps": 50.0})
    newer = db.add_speedtest({"ts": now - 60, "ok": True, "backend": "fake", "download_mbps": 70.0})
    sched = SpeedScheduler(db, Config(tmp_path / "config.json").load(), bus)
    try:
        sched._last_result = sched._load_last()
        assert sched.last_result["id"] == newer
        assert sched.run_now() and backend.started.wait(5.0)
        since = time.time() - 3600
        assert sched.clear_history(since) == {"stopped": True}
        assert sched.last_result["id"] == older, "the newest test before the cleared span"
        db.clear_history(since)
        assert wait_until(lambda: not sched.running)
        assert [r["id"] for r in db.list_speedtests(0, 2e9)] == [older]
        assert sched.last_result["id"] == older
        done = [ev["data"] for ev in events if ev["type"] == "speedtest.done"]
        assert len(done) == 1 and done[0]["silent"] is True and done[0]["cancel_reason"] == "history cleared"
        assert not [ev for ev in db.list_events(20) if ev["category"] == "speedtest"], "no 'speed test failed' row"
        # nothing running: nothing stopped, and an all-time clear leaves no last result
        assert sched.clear_history(None) == {"stopped": False} and sched.last_result is None
    finally:
        sched.stop()
        db.close()


class QuickBackend:
    """A speed test that finishes at once."""

    name = "fake"

    def __init__(self) -> None:
        self.started = threading.Event()

    def available(self, config: Any) -> Any:
        return True, "fake"

    def run(self, config: Any, progress: Any = None, cancel: Any = None) -> SpeedResult:
        self.started.set()
        return SpeedResult(ok=True, ts=time.time(), backend="fake", download_mbps=100.0, upload_mbps=20.0,
                           latency_ms=10.0, duration_s=1.0)


def test_a_speed_test_started_just_after_a_clear_keeps_its_result(tmp_path, monkeypatch):
    # The clear sets the last result from the tests before its span.  A test that starts after the clear's bump is not
    # voided, and it must not see its result overwritten by that older one: it waits to store and adopt it until the
    # clear has set the last result.
    db = Database(tmp_path / "t.db")
    backend = QuickBackend()
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: backend)
    older = db.add_speedtest({"ts": time.time() - 7200, "ok": True, "backend": "fake", "download_mbps": 50.0})
    sched = SpeedScheduler(db, Config(tmp_path / "config.json").load(), EventBus())
    real_list = db.list_speedtests

    def list_during_clear(*args: Any, **kwargs: Any) -> Any:
        # the clear has bumped its generation and reads the last test before its span: a test starts now ...
        assert sched.run_now() and backend.started.wait(5.0)
        time.sleep(0.3)                                 # ... long enough to finish, were nothing holding it back
        return real_list(*args, **kwargs)

    db.list_speedtests = list_during_clear              # type: ignore[method-assign]
    try:
        assert sched.clear_history(time.time() - 3600) == {"stopped": False}
        db.list_speedtests = real_list                  # type: ignore[method-assign]
        assert wait_until(lambda: not sched.running)
        last = sched.last_result
        assert last is not None and last["download_mbps"] == 100.0, "the newer test is the last result, not the older one"
        assert sorted(r["id"] for r in db.list_speedtests(0, 2e9)) == sorted([older, last["id"]])
    finally:
        sched.stop()
        db.close()


# --------------------------------------------------------------------------- Engine.clear_history orchestration
class Part:
    """A component with the contract's clear method; records every call in *calls*."""

    def __init__(self, name: str, calls: List[Any], ret: Any = 0, fail: bool = False, running: bool = False) -> None:
        self.name, self.calls, self.ret, self.fail, self._running = name, calls, ret, fail, running

    def clear_history(self, since_ts: Optional[float], **kwargs: Any) -> Any:
        self.calls.append((self.name, since_ts, kwargs))
        if self.fail:
            raise RuntimeError(f"{self.name} exploded")
        return self.ret

    def running(self) -> bool:
        return self._running


class PingPart(Part):
    last_clear_info = {"minutes": 57, "raw_log": 3, "raw_log_failed": []}

    def publish_targets(self) -> None:
        self.calls.append(("publish_targets", None, {}))


class QualPart:
    def __init__(self, calls: List[Any]) -> None:
        self.calls = calls

    def invalidate(self) -> None:
        self.calls.append(("sipqual", None, {}))


CAPTURE_RESULT = {"deleted": 2, "deleted_names": ["TNT-capture-20260920-120000.pcapng", "TNT-capture-20260920-121500.pcapng"],
                  "skipped": [{"name": "TNT-capture-20260920-113000.pcapng", "reason": "it is being downloaded"}],
                  "recording": True, "discarded_unsaved": True}


def _engine(tmp_path: Path, calls: List[Any], **overrides: Any) -> Any:
    from tnt.engine import Engine

    eng = Engine()
    eng.config = Config(tmp_path / "config.json").load()
    eng.db = Database(tmp_path / "t.db")
    eng.bus = EventBus()
    real_clear = eng.db.clear_history

    def db_clear(since_ts: Optional[float], until_ts: Optional[float] = None) -> Dict[str, int]:
        calls.append(("db", since_ts, {}))
        return real_clear(since_ts, until_ts=until_ts)

    eng.db.clear_history = db_clear                     # type: ignore[method-assign]
    parts = {
        "speed": Part("speed", calls, {"stopped": True}),
        "ping": PingPart("ping", calls, 57),
        "outages": Part("outages", calls, 2),
        "discovery": Part("discovery", calls, 1),
        "capture": Part("capture", calls, dict(CAPTURE_RESULT)),
        "faults": Part("faults", calls, 1),
        "sipalg": Part("sipalg", calls, 1, running=True),
        "sipnat": Part("sipnat", calls, 0),
        "sipflow": Part("sipflow", calls, 2),
        "sipqual": QualPart(calls),
        "proav": Part("proav", calls, {"cleared": 1, "stopped": True}),
        "reports": SimpleNamespace(job=lambda: {"status": "saved"}),
    }
    parts.update(overrides)
    for name, part in parts.items():
        setattr(eng, name, part)
    return eng


def test_the_engine_clears_every_part_in_the_contract_order_and_publishes_its_result(tmp_path, data_dir):
    calls: List[Any] = []
    eng = _engine(tmp_path, calls)
    events: List[Dict[str, Any]] = []
    eng.bus.subscribe(events.append)
    eng.db.add_speedtest({"ts": time.time() - 30, "ok": True, "backend": "fake"})
    try:
        res = eng.clear_history("1h")
        assert list(res) == list(history.RESULT_KEYS)
        assert res["range"] == "1h" and res["label"] == "Last hour" and res["since_ts"] == res["ts"] - 3600
        # the Discovery scanner forgets its last scan with the jobs, before the scan running now is cancelled
        assert [c[0] for c in calls] == ["speed", "discovery", "ping", "outages", "db", "capture", "faults", "sipalg",
                                         "sipnat", "sipflow", "sipqual", "proav", "publish_targets"]
        assert all(c[1] == res["since_ts"] for c in calls if c[0] not in ("sipqual", "publish_targets"))
        folder = paths.captures_dir()
        flow = next(c for c in calls if c[0] == "sipflow")
        assert flow[2] == {"deleted_paths": tuple(str(folder / n) for n in CAPTURE_RESULT["deleted_names"])}
        assert res["cleared"] == {"ping": 57, "outages": 2, "speed": 1, "discovery": 0, "captures": 3, "faults": 1,
                                  "sip": 3, "proav": 1}
        assert res["stopped"] == ["speed test", "SIP check", "Pro AV scan"]
        recording = {"what": "captures", "reason": "A packet capture is recording, so it was left alone. Stop it and "
                                                   "clear the history again to remove it"}
        assert res["skipped"] == [
            {"what": "captures", "reason": "TNT-capture-20260920-113000.pcapng was left alone: it is being downloaded"},
            recording]
        # every window hears the event: the file left alone is counted there, never named (capture names are for an
        # administrator only); the rest is the answer itself
        published = [ev["data"] for ev in events if ev["type"] == "history.cleared"]
        assert published == [dict(res, skipped=[
            {"what": "captures", "reason": "A packet capture was left alone: it is being downloaded"}, recording])]
        assert "TNT-capture" not in json.dumps(published)
        assert history.last_span(eng.db) == {"since_ts": res["since_ts"], "at": res["ts"], "range": "1h"}
        assert [ev for ev in eng.db.list_events(5) if ev["category"] == "history"]
    finally:
        eng.db.close()


def test_a_missing_or_failing_part_is_named_in_skipped_and_the_rest_still_clears(tmp_path, data_dir):
    calls: List[Any] = []
    eng = _engine(tmp_path, calls, faults=Part("faults", calls, fail=True), sipnat=object(), capture=None,
                  proav=Part("proav", calls, fail=True), speed=object())
    def db_boom(since_ts: Optional[float], until_ts: Optional[float] = None) -> Dict[str, int]:
        raise sqlite3.OperationalError("database is locked")

    eng.db.clear_history = db_boom                      # type: ignore[method-assign]
    try:
        res = eng.clear_history("24h")
        whats = [s["what"] for s in res["skipped"]]
        assert whats == ["speed", "speed and discovery", "captures", "faults", "sip", "proav"]
        reasons = {s["what"]: s["reason"] for s in res["skipped"]}
        assert "database is locked" in reasons["speed and discovery"] and "faults exploded" in reasons["faults"]
        assert "cannot clear its history yet" in reasons["sip"] and "not available" in reasons["captures"]
        # everything else still ran and counted
        assert res["cleared"]["ping"] == 57 and res["cleared"]["outages"] == 2 and res["cleared"]["sip"] == 3
        assert {c[0] for c in calls} >= {"ping", "outages", "discovery", "sipalg", "sipflow", "sipqual", "publish_targets"}
        assert history.last_span(eng.db)["range"] == "24h"
    finally:
        eng.db.close()


def test_without_an_administrator_captures_are_left_alone_and_the_rest_clears(tmp_path, data_dir):
    calls: List[Any] = []
    eng = _engine(tmp_path, calls)
    try:
        res = eng.clear_history("all", captures_allowed=False, captures_reason=api_routes.CLEAR_CAPTURES_ADMIN_REQUIRED_MSG)
        assert "capture" not in [c[0] for c in calls] and res["cleared"]["captures"] == 0
        assert {"what": "captures", "reason": api_routes.CLEAR_CAPTURES_ADMIN_REQUIRED_MSG} in res["skipped"]
        assert res["since_ts"] is None and all(c[1] is None for c in calls if c[0] not in ("sipqual", "publish_targets"))
        flow = next(c for c in calls if c[0] == "sipflow")
        assert flow[2] == {"deleted_paths": ()}
    finally:
        eng.db.close()


def test_the_engine_refuses_a_clear_during_a_full_scan_and_a_second_clear(tmp_path, data_dir):
    calls: List[Any] = []
    eng = _engine(tmp_path, calls, reports=SimpleNamespace(job=lambda: {"status": "running", "phase": "speed"}))
    try:
        with pytest.raises(history.ClearConflict) as busy:
            eng.clear_history("1h")
        assert busy.value.code == "full_scan_running" and calls == []
        eng.reports = SimpleNamespace(job=lambda: None)
        with pytest.raises(ValueError):
            eng.clear_history("2h")
        assert eng._clear_lock.acquire(blocking=False)
        try:
            assert eng.clear_running()
            with pytest.raises(history.ClearConflict) as again:
                eng.clear_history("1h")
            assert again.value.code == "clear_running" and calls == []
        finally:
            eng._clear_lock.release()
        assert not eng.clear_running() and eng.clear_history("5m")["range"] == "5m"
    finally:
        eng.db.close()


class BlockingScanner:
    """A Discovery scanner whose scan runs until it is cancelled and then hands back what it found so far."""

    def __init__(self, fail: bool = False) -> None:
        self.started = threading.Event()
        self.cleared: List[Optional[float]] = []
        self.cancel_set_when_cleared: List[bool] = []
        self.cancel: Optional[threading.Event] = None
        self.fail = fail

    def default_cidr(self) -> str:
        return "192.0.2.0/24"

    def parse_range(self, text: str) -> Any:
        return ipaddress.ip_network(text, strict=False)

    def scan(self, range_text: str, ports: Any, progress: Any = None, cancel: Any = None) -> Dict[str, Any]:
        ts = time.time()
        self.cancel = cancel
        self.started.set()
        cancel.wait(5.0)
        if self.fail:
            raise RuntimeError("the scan tripped over its own cancel")
        return {"ts": ts, "cidr": range_text, "ports": list(ports or []), "method": "native", "duration_s": 0.5,
                "scanned": 3, "ok": True, "error": None, "cancelled": True,
                "hosts": [{"ip": "192.0.2.5", "ping_ok": True, "open_ports": [80]}]}

    def clear_history(self, since_ts: Optional[float]) -> int:
        self.cleared.append(since_ts)
        self.cancel_set_when_cleared.append(bool(self.cancel is not None and self.cancel.is_set()))
        return 0


def test_a_discovery_scan_running_across_a_clear_is_cancelled_and_never_stored_or_adopted(tmp_path, data_dir):
    from tnt.engine import Engine

    eng = Engine()
    eng.config = Config(tmp_path / "config.json").load()
    eng.db = Database(tmp_path / "t.db")
    eng.bus = EventBus()
    events: List[Dict[str, Any]] = []
    eng.bus.subscribe(events.append)
    scanner = BlockingScanner()
    eng.discovery = scanner
    older = eng.db.add_discovery_run({"ts": time.time() - 7200, "cidr": "192.0.2.0/24", "ports": [80]},
                                     [{"ip": "192.0.2.9", "ping_ok": True, "open_ports": []}])
    newer = eng.db.add_discovery_run({"ts": time.time() - 60, "cidr": "192.0.2.0/24", "ports": [80]}, [])
    eng._last_discovery = eng._run_summary(eng.db.list_discovery_runs(1)[0])
    try:
        assert eng._last_discovery["id"] == newer
        assert eng.discovery_start("192.0.2.0/24", [80]) and scanner.started.wait(5.0)
        res = eng.clear_history("1h")
        assert "discovery scan" in res["stopped"] and res["cleared"]["discovery"] == 1
        assert wait_until(lambda: not eng.discovery_running())
        assert wait_until(lambda: any(ev["type"] == "discovery.done" for ev in events))
        assert [r["id"] for r in eng.db.list_discovery_runs(10)] == [older]
        assert eng.discovery_status()["last_run"]["id"] == older
        done = next(ev["data"] for ev in events if ev["type"] == "discovery.done")
        assert done["run_id"] is None and done["silent"] is True and done["cancel_reason"] == "history cleared"
        # the scanner forgot its last scan before the scan was cancelled, so it can never record that scan's time
        assert scanner.cleared == [res["since_ts"]] and scanner.cancel_set_when_cleared == [False]
        # a scan started after the clear is stored as always
        scanner.started.clear()
        assert eng.discovery_start("192.0.2.0/24", [80]) and scanner.started.wait(5.0)
        eng.discovery_cancel()
        assert wait_until(lambda: not eng.discovery_running() and len(eng.db.list_discovery_runs(10)) == 2)
    finally:
        eng.discovery_cancel()
        wait_until(lambda: not eng.discovery_running())
        eng.db.close()


def test_the_scanner_forgets_its_last_run_time_and_a_scan_across_the_clear_does_not_set_it(fake_netinfo):
    from tnt.discovery import DiscoveryScanner

    scanner = DiscoveryScanner(SimpleNamespace(get=lambda key, default=None: default))
    scanner._last_run_ts = T0
    assert scanner.clear_history(T0 + 1) == 0 and scanner.last_run_ts == T0
    assert scanner.clear_history(T0 - 1) == 1 and scanner.last_run_ts is None
    scanner._last_run_ts = T0
    assert scanner.clear_history(None) == 1 and scanner.last_run_ts is None


def test_a_discovery_scan_that_fails_across_a_clear_ends_silently_and_is_not_kept(tmp_path, data_dir):
    # A scan the clear stopped may come back with no result at all (it raised): it is still the clear's, so the page
    # shows no failure toast for it and the event log says why it stopped rather than "scan failed".
    from tnt.engine import Engine

    eng = Engine()
    eng.config = Config(tmp_path / "config.json").load()
    eng.db = Database(tmp_path / "t.db")
    eng.bus = EventBus()
    events: List[Dict[str, Any]] = []
    eng.bus.subscribe(events.append)
    scanner = BlockingScanner(fail=True)
    eng.discovery = scanner
    try:
        assert eng.discovery_start("192.0.2.0/24", [80]) and scanner.started.wait(5.0)
        res = eng.clear_history("1h")
        assert "discovery scan" in res["stopped"]
        assert wait_until(lambda: any(ev["type"] == "discovery.done" for ev in events))
        done = next(ev["data"] for ev in events if ev["type"] == "discovery.done")
        assert done["silent"] is True and done["cancel_reason"] == "history cleared"
        assert done["run_id"] is None and done["cancelled"] is True
        assert eng.db.list_discovery_runs(10) == [] and eng.discovery_status()["last_run"] is None
        logged = [ev["message"] for ev in eng.db.list_events(20) if ev["category"] == "discovery"]
        assert any("the history was cleared while it ran" in m for m in logged)
        assert not any(m.startswith("scan failed") for m in logged)
    finally:
        eng.discovery_cancel()
        wait_until(lambda: not eng.discovery_running())
        eng.db.close()


def test_the_speed_tile_never_shows_a_test_the_database_step_deleted(tmp_path, data_dir):
    # A scheduled test that started after the clear cancelled the running one, and finished before the database step,
    # lost its row to that step: the scheduler re-reads its last result afterwards, so the tile does not show it.
    calls: List[Any] = []
    eng = _engine(tmp_path, calls)
    sched = SpeedScheduler(eng.db, eng.config, eng.bus)
    eng.speed = sched
    older = eng.db.add_speedtest({"ts": time.time() - 7200, "ok": True, "backend": "fake", "download_mbps": 50.0})

    class LateTest(PingPart):
        def clear_history(self, since_ts: Optional[float], **kwargs: Any) -> Any:
            eng.db.add_speedtest({"ts": time.time(), "ok": True, "backend": "fake", "download_mbps": 90.0})
            with sched._lock:
                sched._last_result = sched._load_last()
            return super().clear_history(since_ts, **kwargs)

    eng.ping = LateTest("ping", calls, 57)
    try:
        res = eng.clear_history("1h")
        assert res["cleared"]["speed"] == 1
        assert [r["id"] for r in eng.db.list_speedtests(0, 2e9)] == [older]
        assert sched.last_result is not None and sched.last_result["id"] == older
    finally:
        sched.stop()
        eng.db.close()


def test_an_outage_event_written_after_the_tracker_cleared_survives_the_database_step(tmp_path, data_dir):
    calls: List[Any] = []
    eng = _engine(tmp_path, calls)
    eng.db.add_event("warning", "outage", "Outage started: 192.0.2.10", ts=time.time() - 60)     # in the span: goes

    class FreshOutage(Part):
        def clear_history(self, since_ts: Optional[float], **kwargs: Any) -> Any:
            n = super().clear_history(since_ts, **kwargs)
            eng.db.delete_outages_since(since_ts)       # what the real tracker deletes, its events among them
            # the target is still down: a fresh outage opens right after the tracker's clear, before the database step
            eng.db.add_event("warning", "outage", "Outage started: 192.0.2.10", ts=time.time())
            return n

    eng.outages = FreshOutage("outages", calls, 2)
    try:
        res = eng.clear_history("1h")
        kept = [ev for ev in eng.db.list_events(20) if ev["category"] == "outage"]
        assert len(kept) == 1 and kept[0]["ts"] >= res["ts"]
    finally:
        eng.db.close()


def test_the_cleared_span_starts_at_the_earliest_record_the_parts_deleted(tmp_path, data_dir):
    calls: List[Any] = []

    class EarlyPing(PingPart):
        def clear_history(self, since_ts: Optional[float], **kwargs: Any) -> Any:
            # the minute bucket that straddled since went whole
            self.last_clear_info = dict(PingPart.last_clear_info, earliest_ts=None if since_ts is None else since_ts - 30)
            return super().clear_history(since_ts, **kwargs)

    class EarlyOutages(Part):
        def clear_history(self, since_ts: Optional[float], **kwargs: Any) -> Any:
            # an outage that began a quarter of an hour before since and ended inside the span went whole
            self.last_clear_info = {"rows": 2, "earliest_ts": None if since_ts is None else since_ts - 900}
            return super().clear_history(since_ts, **kwargs)

    eng = _engine(tmp_path, calls, ping=EarlyPing("ping", calls, 57), outages=EarlyOutages("outages", calls, 2))
    try:
        res = eng.clear_history("1h")
        assert res["since_ts"] == res["ts"] - 3600, "the answer keeps the cutoff that was asked for"
        assert history.last_span(eng.db) == {"since_ts": res["since_ts"] - 900, "at": res["ts"], "range": "1h"}
        # an all-time clear starts at the beginning, whatever it deleted
        assert eng.clear_history("all")["since_ts"] is None and history.last_span(eng.db)["since_ts"] is None
    finally:
        eng.db.close()


def test_a_clear_and_a_full_scan_start_never_overlap(tmp_path, data_dir):
    calls: List[Any] = []
    job = {"status": "saved"}
    eng = _engine(tmp_path, calls, reports=SimpleNamespace(job=lambda: dict(job)))
    out: Dict[str, Any] = {}

    def start_scan() -> Dict[str, Any]:
        # a clear asked for while a Full Scan starts waits for the start, then finds the scan running
        def clear() -> None:
            try:
                out["result"] = eng.clear_history("1h")
            except history.ClearConflict as exc:
                out["result"] = exc

        out["thread"] = threading.Thread(target=clear, daemon=True)
        out["thread"].start()
        time.sleep(0.2)
        job["status"] = "running"
        return dict(job)

    try:
        assert eng.outside_clear(start_scan)["status"] == "running"
        out["thread"].join(5.0)
        assert isinstance(out["result"], history.ClearConflict) and out["result"].code == "full_scan_running"
        assert calls == []
        # and the other way round: a Full Scan asked for while a clear runs is refused until the clear is done
        job["status"] = "saved"
        refused: List[Any] = []

        class ScanDuringClear(PingPart):
            def clear_history(self, since_ts: Optional[float], **kwargs: Any) -> Any:
                try:
                    eng.outside_clear(lambda: refused.append("started"))
                except history.ClearConflict as exc:
                    refused.append((exc.code, exc.message))
                return super().clear_history(since_ts, **kwargs)

        eng.ping = ScanDuringClear("ping", calls, 57)
        assert eng.clear_history("1h")["range"] == "1h"
        assert refused == [("clear_running", history.SCAN_DURING_CLEAR_MSG)]
        assert eng.outside_clear(lambda: "started") == "started"
    finally:
        eng.db.close()


def _dump(db: Database, table: str) -> List[Dict[str, Any]]:
    return db._query(f"SELECT * FROM {table} ORDER BY 1")


def test_an_all_time_clear_never_touches_reports_exports_networks_targets_offline_spells_leases_or_other_events(
        tmp_path, data_dir, fake_netinfo):
    from tnt.engine import Engine

    env = PingEnv(tmp_path, with_tracker=True)
    eng = Engine()
    eng.config, eng.db, eng.bus, eng.ping, eng.outages, eng.raw_log = env.cfg, env.db, env.bus, env.pm, env.tracker, env.raw
    eng.speed = SpeedScheduler(env.db, env.cfg, env.bus)
    db = env.db
    try:
        # history: ping minutes, an open outage, a speed test, a Discovery run
        env.tick(65, ok=True)
        env.tick(4, ok=False)
        assert db.open_outages()
        db.add_speedtest({"ts": T0, "ok": True, "backend": "fake", "download_mbps": 90.0})
        db.add_discovery_run({"ts": T0, "cidr": "192.0.2.0/24", "ports": [80]}, [{"ip": "192.0.2.5", "ping_ok": True,
                                                                                  "open_ports": []}])
        # never history
        net = db.add_network(T0 - DAY, mac="02:00:5E:00:53:01", gateway_ip="192.0.2.1", subnet="192.0.2.0/24")
        db.add_offline_spell(net["id"], T0 - 3000, T0 - 2000, net["id"])
        db.upsert_dhcp_lease({"mac": "02:00:5E:00:53:22", "ip": "192.0.2.22", "state": "bound", "expires_ts": T0 + 3600})
        report = db.add_report("Example site", "example site", T0 - 600, T0 - 500, "complete", "1.22.0",
                               {"ping": 1}, {"meta": {"site": "Example site"}}, net["id"])
        db.add_event("info", "network", "network changed: 192.0.2.1", ts=T0)
        db.add_event("info", "service", "service started", ts=T0)
        db.set_meta("defaults_loaded", "1")
        exports = paths.exports_dir()
        exports.mkdir(parents=True, exist_ok=True)
        pdf = exports / "TNT-report-20260920-20260920.pdf"
        pdf.write_bytes(b"%PDF-1.4 keep me")
        eng.config.update({"ui": {"theme": "dark"}}, persist=False)
        kept_tables = ("reports", "networks", "targets", "network_offline", "dhcp_leases")
        before = {t: _dump(db, t) for t in kept_tables}
        other_events = [ev for ev in db.list_events(100) if ev["category"] != "outage"]
        outage_rows = db.counts()["outages"]
        assert [r["id"] for r in before["reports"]] == [report] and outage_rows == 2      # the target and its total
        res = eng.clear_history("all")
        counts = db.counts()
        assert counts["ping_minutes"] == 0 and counts["outages"] == 0 and counts["speedtests"] == 0
        assert counts["discovery_runs"] == 0 and counts["discovery_hosts"] == 0
        assert res["cleared"]["ping"] >= 1 and res["cleared"]["outages"] == outage_rows and res["cleared"]["speed"] == 1
        assert res["cleared"]["discovery"] == 1
        assert {t: _dump(db, t) for t in kept_tables} == before
        assert [ev for ev in db.list_events(100) if ev["category"] not in ("outage", "history")] == other_events
        assert not [ev for ev in db.list_events(100) if ev["category"] == "outage"]
        assert db.get_meta("defaults_loaded") == "1" and pdf.read_bytes() == b"%PDF-1.4 keep me"
        assert eng.config.get("ui.theme") == "dark"
        assert env.pm.target(env.tid)["in_outage"] is False and env.tracker.status()["active"] == []
        assert [s["what"] for s in res["skipped"]] == ["captures"]
    finally:
        eng.speed.stop()
        env.close()


# --------------------------------------------------------------------------- the routes
def _call(srv: Any, method: str, path: str, body: Any = None, raw: Optional[bytes] = None,
          headers: Optional[Dict[str, str]] = None) -> Any:
    conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
    try:
        data = raw if raw is not None else (json.dumps(body).encode("utf-8") if body is not None else None)
        hdrs = dict(headers or {})
        if data is not None:
            hdrs.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        return resp.status, (json.loads(payload) if payload else None)
    finally:
        conn.close()


@pytest.fixture
def api_env(tmp_path, data_dir):
    calls: List[Any] = []
    eng = _engine(tmp_path, calls)
    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "index.html").write_text("<!doctype html><title>TNT test UI</title>", encoding="utf-8")
    srv = ApiServer(eng, "127.0.0.1", 0, bus=eng.bus, ui_dir=ui)
    eng.api = srv
    srv.wifi_reveal_check = lambda peer, local: "allowed"
    srv.start()
    events: List[Dict[str, Any]] = []
    eng.bus.subscribe(events.append)
    yield SimpleNamespace(eng=eng, srv=srv, calls=calls, events=events)
    srv.stop()
    eng.db.close()


def test_the_clear_route_refuses_bad_ranges_and_bodies_with_bad_range(api_env):
    srv, calls = api_env.srv, api_env.calls
    for body in ({"range": "2h"}, {"range": 3600}, {"range": ["1h"]}, {}, ["1h"], "1h"):
        status, data = _call(srv, "POST", "/api/history/clear", body)
        assert status == 400 and data["error"] == {"code": "bad_range", "message": history.BAD_RANGE_MSG}, body
    for raw in (b"not json", b"[]", b"null"):
        status, data = _call(srv, "POST", "/api/history/clear", raw=raw)
        assert status == 400 and data["error"]["code"] == "bad_range"
    assert calls == []


def test_the_clear_route_refuses_a_page_of_another_origin_before_anything_runs(api_env):
    srv, calls = api_env.srv, api_env.calls
    checks: List[Any] = []
    srv.wifi_reveal_check = lambda peer, local: checks.append(peer) or "allowed"
    for headers in ({"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site", "Origin": "http://localhost:8081"}):
        status, data = _call(srv, "POST", "/api/history/clear", {"range": "1h"}, headers=headers)
        assert status == 403 and data["error"]["code"] == "forbidden"
    status, data = _call(srv, "POST", "/api/history/clear", {"range": "1h"}, headers={"Sec-Fetch-Site": "same-site"})
    assert status == 403 and data["error"] == {"code": "forbidden", "message": api_routes.QUICK_TOOLS_CROSS_ORIGIN_MSG}
    assert calls == [] and checks == []
    status, _data = _call(srv, "POST", "/api/history/clear", {"range": "1h"},
                          headers={"Sec-Fetch-Site": "same-origin", "Origin": f"http://127.0.0.1:{srv.port}"})
    assert status == 200 and calls


def test_the_clear_route_answers_409_during_a_full_scan_and_a_running_clear(api_env):
    eng, srv, calls = api_env.eng, api_env.srv, api_env.calls
    eng.reports = SimpleNamespace(job=lambda: {"status": "running"})
    status, data = _call(srv, "POST", "/api/history/clear", {"range": "1h"})
    assert status == 409 and data["error"] == {"code": "full_scan_running", "message": history.FULL_SCAN_RUNNING_MSG}
    eng.reports = SimpleNamespace(job=lambda: {"status": "cancelled"})
    assert eng._clear_lock.acquire(blocking=False)
    try:
        status, data = _call(srv, "POST", "/api/history/clear", {"range": "1h"})
        assert status == 409 and data["error"] == {"code": "clear_running", "message": history.CLEAR_RUNNING_MSG}
    finally:
        eng._clear_lock.release()
    assert calls == []


@pytest.mark.parametrize("decision, reason", [("denied", api_routes.CLEAR_CAPTURES_ADMIN_REQUIRED_MSG),
                                              ("unknown", api_routes.CLEAR_CAPTURES_ADMIN_UNVERIFIED_MSG)])
def test_the_clear_route_leaves_captures_alone_for_anyone_but_an_administrator(api_env, decision, reason):
    srv, calls, events = api_env.srv, api_env.calls, api_env.events
    srv.wifi_reveal_check = lambda peer, local: decision
    status, data = _call(srv, "POST", "/api/history/clear", {"range": "6h"})
    assert status == 200 and data["range"] == "6h" and data["label"] == "Last 6 hours"
    assert "capture" not in [c[0] for c in calls] and {"what": "captures", "reason": reason} in data["skipped"]
    assert {c[0] for c in calls} >= {"speed", "ping", "outages", "db", "faults", "proav"}


def test_the_clear_route_names_captures_only_to_the_administrator_and_get_history_shows_the_clear(api_env):
    srv, calls, events = api_env.srv, api_env.calls, api_env.events
    status, data = _call(srv, "GET", "/api/history")
    assert status == 200 and data == {"ranges": history.ranges_view(), "last": None}
    status, data = _call(srv, "POST", "/api/history/clear", {"range": "30m"})
    assert status == 200 and list(data) == list(history.RESULT_KEYS)
    assert list(data["cleared"]) == list(history.CATEGORIES) and data["since_ts"] == pytest.approx(data["ts"] - 1800)
    assert "capture" in [c[0] for c in calls]
    # the administrator who asked is told which capture was left alone ...
    assert {"what": "captures", "reason": "TNT-capture-20260920-113000.pcapng was left alone: it is being downloaded"} \
        in data["skipped"]
    # ... while history.cleared, which every window and every user's tab hears, carries the same answer with that file
    # only counted (capture.state and capture.sip are administrator-only for the same reason)
    published = [ev["data"] for ev in events if ev["type"] == "history.cleared"]
    public_skipped = [s if "TNT-capture" not in s["reason"] else
                      {"what": "captures", "reason": "A packet capture was left alone: it is being downloaded"}
                      for s in data["skipped"]]
    assert published == [dict(data, skipped=public_skipped)] and "TNT-capture" not in json.dumps(published)
    status, view = _call(srv, "GET", "/api/history")
    assert status == 200 and view["last"] == {"since_ts": data["since_ts"], "at": data["ts"], "range": "30m"}


def test_a_full_scan_does_not_start_while_the_history_is_being_cleared(api_env):
    eng, srv = api_env.eng, api_env.srv
    started: List[Any] = []
    eng.reports = SimpleNamespace(job=lambda: None,
                                  start_scan=lambda site=None: started.append(site) or {"status": "running", "site": site})
    eng._clearing = True                                 # a clear is under way
    status, data = _call(srv, "POST", "/api/reports/scan", {})
    assert status == 409 and data["error"] == {"code": "clear_running", "message": history.SCAN_DURING_CLEAR_MSG}
    assert started == []
    eng._clearing = False
    status, data = _call(srv, "POST", "/api/reports/scan", {})
    assert status == 200 and data["job"]["status"] == "running" and started == [None]


def test_the_cleared_span_on_the_outages_timeline_starts_where_the_earliest_deleted_outage_began(
        tmp_path, data_dir, fake_netinfo):
    # End to end: an outage that began a quarter of an hour before the last hour and ended inside it is deleted whole,
    # so the Outages timeline must not paint that quarter of an hour as "fine": its cleared span starts where the
    # outage began, while the clear's answer keeps the cutoff that was asked for.
    from tnt.engine import Engine

    env = PingEnv(tmp_path, with_tracker=True, clock=RealClock())
    eng = Engine()
    eng.config, eng.db, eng.bus, eng.ping, eng.outages, eng.raw_log = env.cfg, env.db, env.bus, env.pm, env.tracker, env.raw
    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "index.html").write_text("<!doctype html><title>TNT test UI</title>", encoding="utf-8")
    srv = ApiServer(eng, "127.0.0.1", 0, bus=eng.bus, ui_dir=ui)
    eng.api = srv
    srv.wifi_reveal_check = lambda peer, local: "allowed"
    srv.start()
    try:
        now = time.time()
        older = _outage(env.db, "target", now - 3 * 3600, now - 2.5 * 3600, env.tid)
        _outage(env.db, "target", now - 4500, now - 3000, env.tid)
        status, res = _call(srv, "POST", "/api/history/clear", {"range": "1h"})
        assert status == 200 and res["since_ts"] == pytest.approx(res["ts"] - 3600) and res["cleared"]["outages"] == 1
        assert [r["id"] for r in env.db._query("SELECT id FROM outages")] == [older]
        status, tl = _call(srv, "GET", "/api/outages/timeline?hours=6")
        assert status == 200 and tl["cleared"] == [{"start_ts": now - 4500, "end_ts": res["ts"]}]
        status, view = _call(srv, "GET", "/api/history")
        assert status == 200 and view["last"] == {"since_ts": now - 4500, "at": res["ts"], "range": "1h"}
    finally:
        srv.stop()
        env.close()


def test_the_architecture_doc_describes_the_clear(tmp_path):
    arch_path = ROOT / "docs" / "ARCHITECTURE.md"
    if not arch_path.exists():
        pytest.skip("docs/ARCHITECTURE.md is not in this tree")
    arch = arch_path.read_text(encoding="utf-8")
    for s in ("POST `/history/clear`", "GET `/history`", "history.cleared", "full_scan_running", "clear_running",
              "bad_range", "delete_ping_minutes_since", "delete_outages_since", "RawPingLog.clear_since",
              '"cleared": [{"start_ts","end_ts"}]', "history_cleared", '"silent": true', "outside_clear", "reload_last",
              "earliest_ts", "_inflight", "until_ts", "counted, never named"):
        assert s in arch, s
