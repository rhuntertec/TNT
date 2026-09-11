"""Tests for tnt.pinger (no network, no real ICMP: everything is driven by fakes)."""
from __future__ import annotations

import gzip
import sys
import threading
import time
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from tnt import pinger as P
from tnt.config import Config
from tnt.db import Database
from tnt.events import EventBus
from tnt.pinger import PingManager, RawPingLog, Sample

T0 = 1_800_000_000.0        # 2027-01-15, an arbitrary anchor; tests that care compute their own


# ---------------------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------------------
@dataclass
class FakeResult:
    """Same fields as tnt.icmp.PingResult without importing the ctypes module."""
    ok: bool
    rtt_ms: Optional[float]
    status: int = 0
    error: Optional[str] = None
    ttl: Optional[int] = 57
    size: int = 32
    ip: str = ""


class FakeClock:
    def __init__(self, now: float = T0) -> None:
        self.now = float(now)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += float(seconds)


class FakePinger:
    """Scripted results: each item is ``(ok, rtt_ms)`` or ``(ok, rtt_ms, cost_s)``.

    ``cost_s`` advances the fake clock to simulate how long the ping call took.
    The last item repeats once the script is exhausted.
    """

    def __init__(self, script: List[Tuple[Any, ...]], clock: Optional[FakeClock] = None) -> None:
        self.script = list(script)
        self.clock = clock
        self.calls: List[Tuple[str, int, int, int]] = []
        self.closed = False

    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> FakeResult:
        self.calls.append((ip, size, timeout_ms, ttl))
        item = self.script.pop(0) if len(self.script) > 1 else (self.script[0] if self.script else (True, 1.0))
        ok, rtt = item[0], item[1]
        cost = item[2] if len(item) > 2 else 0.0
        if cost and self.clock is not None:
            self.clock.advance(cost)
        if ok:
            return FakeResult(True, rtt, 0, None, 57, size, ip)
        return FakeResult(False, None, 11010, "Request timed out", None, size, ip)

    def close(self) -> None:
        self.closed = True


class FakeResolver:
    def __init__(self, table: Optional[Dict[str, Optional[str]]] = None) -> None:
        self.table: Dict[str, Optional[str]] = dict(table or {})
        self.calls: List[str] = []
        self.raise_exc: Optional[Exception] = None

    def __call__(self, host: str) -> Optional[str]:
        self.calls.append(host)
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.table.get(host)


class Env:
    def __init__(self, tmp: Path, fake_netinfo: types.ModuleType) -> None:
        self.tmp = tmp
        self.db = Database(tmp / "t.db")
        self.config = Config(tmp / "config.json").load()
        self.bus = EventBus()
        self.events: List[Dict[str, Any]] = []
        self.bus.subscribe(self.events.append)
        self.clock = FakeClock()
        self.sleeps: List[float] = []
        self.resolver = FakeResolver({"host.test": "93.184.216.34"})
        self.pinger = FakePinger([(True, 20.0)], self.clock)
        self.raw = RawPingLog(tmp / "pings", clock=self.clock)
        self.netinfo = fake_netinfo
        self.mgr = self.make_manager()

    def make_manager(self, sleep: Optional[Callable[[float], None]] = None) -> PingManager:
        def default_sleep(s: float) -> None:
            self.sleeps.append(s)
            self.clock.advance(s)

        return PingManager(self.db, self.config, self.bus, pinger=self.pinger, raw_log=self.raw,
                           clock=self.clock, sleep=sleep or default_sleep, resolver=self.resolver)

    def events_of(self, kind: str) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["type"] == kind]

    def tick_all(self, target_id: int, n: int, step: float = 1.0) -> List[Sample]:
        out = []
        for _ in range(n):
            s = self.mgr.tick(target_id)
            if s is not None:
                out.append(s)
            self.clock.advance(step)
        return out

    def close(self) -> None:
        try:
            self.mgr.stop()
        finally:
            self.raw.close()
            self.db.close()


@pytest.fixture
def fake_netinfo(monkeypatch):
    """A stand-in tnt.netinfo: private/link-local/loopback -> local, gateway 10.0.0.251."""
    import ipaddress

    mod = types.ModuleType("tnt.netinfo")
    mod.gateway = "10.0.0.251"
    mod.classify_calls = []

    def classify_ip(ip: str, adapters=None) -> str:
        mod.classify_calls.append(ip)
        a = ipaddress.ip_address(ip.split("%")[0])
        return "local" if (a.is_private or a.is_link_local or a.is_loopback) else "internet"

    def get_default_gateway() -> Optional[str]:
        return mod.gateway

    mod.classify_ip = classify_ip
    mod.get_default_gateway = get_default_gateway
    monkeypatch.setitem(sys.modules, "tnt.netinfo", mod)
    return mod


@pytest.fixture
def env(tmp_path, fake_netinfo):
    e = Env(tmp_path, fake_netinfo)
    yield e
    e.close()


def _local_midnight(year: int, month: int, day: int) -> float:
    return time.mktime((year, month, day, 0, 0, 0, 0, 0, -1))


# ---------------------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------------------
def test_next_slot_keeps_anchor_and_skips_forward_when_behind():
    start = T0 + 0.123
    n, nxt = P._next_slot(start, 1.0, 0, start + 0.3)           # tick took 0.3 s
    assert (n, nxt) == (1, pytest.approx(start + 1.0))
    n, nxt = P._next_slot(start, 1.0, 1, start + 1.0 + 0.999)   # nearly a full interval late: same slot, no wait
    assert n == 2 and nxt == pytest.approx(start + 2.0)
    n, nxt = P._next_slot(start, 1.0, 2, start + 2.0 + 2.5)     # 2.5 s behind: skip to the next slot ahead
    assert n == 5 and nxt == pytest.approx(start + 5.0)
    n, nxt = P._next_slot(start, 1.0, 5, start + 5.0)           # tick took no time at all
    assert n == 6 and nxt == pytest.approx(start + 6.0)


def test_next_slot_no_float_drift_over_many_slots():
    start = 1_700_000_000.0 + 0.45
    n, now = 0, start
    for i in range(1, 5001):
        n, nxt = P._next_slot(start, 1.0, n, now)
        assert n == i, "slot counter must advance exactly one per tick when on time"
        assert nxt > now
        now = nxt
    assert now == pytest.approx(start + 5000.0, abs=1e-5)


def test_worker_thread_schedule_is_aligned_and_never_drifts(env):
    # ping #0..#1 cost 0.3 s, ping #2 costs 2.5 s (falls behind -> skip), the rest 0.3 s
    env.pinger.script = [(True, 10.0, 0.3), (True, 10.0, 0.3), (True, 10.0, 2.5), (True, 10.0, 0.3)]
    gate = threading.Event()
    sleeps: List[float] = []

    def fake_sleep(s: float) -> None:
        sleeps.append(s)
        env.clock.advance(s)
        time.sleep(0.001)
        if len(sleeps) >= 6:
            gate.wait(5.0)              # park the worker so the test can stop it cleanly

    mgr = env.make_manager(sleep=fake_sleep)
    env.mgr = mgr
    view = mgr.add_target("1.1.1.1")
    tid = view["id"]
    mgr.start()
    deadline = time.time() + 5.0
    while len(mgr.samples(tid, 10 ** 6)) < 6 and time.time() < deadline:
        time.sleep(0.01)
    gate.set()
    t_stop = time.time()
    mgr.stop()
    assert time.time() - t_stop < 3.0, "stop() must be quick"
    samples = mgr.samples(tid, 10 ** 6)
    assert len(samples) >= 6
    start = samples[0].ts
    offsets = [round(s.ts - start, 6) for s in samples[:6]]
    assert offsets == [0.0, 1.0, 2.0, 5.0, 6.0, 7.0]
    assert sleeps[0] == pytest.approx(0.7) and sleeps[1] == pytest.approx(0.7) and sleeps[2] == pytest.approx(0.5)


def test_real_thread_ticks_immediately_and_stops_quickly(env):
    """Default sleep path (stop_event.wait): one tick at start, stop() returns fast, minute flushed."""
    mgr = PingManager(env.db, env.config, env.bus, pinger=env.pinger, raw_log=env.raw, resolver=env.resolver)
    env.mgr = mgr
    tid = mgr.add_target("1.1.1.1")["id"]
    mgr.start()
    deadline = time.time() + 3.0
    while not env.pinger.calls and time.time() < deadline:
        time.sleep(0.01)
    assert env.pinger.calls, "the worker must ping right away"
    t = time.time()
    mgr.stop()
    assert time.time() - t < 2.5
    rows = env.db.ping_minutes(tid, 0, 4_000_000_000)
    assert rows and rows[0]["sent"] >= 1 and rows[0]["received"] == rows[0]["sent"]
    assert not [th for th in threading.enumerate() if th.name == f"tnt-ping-{tid}" and th.is_alive()]


def _worker_threads(tid: int) -> List[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == f"tnt-ping-{tid}" and t.is_alive()]


def test_restart_after_stuck_worker_never_runs_two_workers(env, monkeypatch):
    """A worker parked in a long ping outlives the bounded join in stop(); a later start()
    must give the target a fresh worker and the old one must exit after its ping."""
    monkeypatch.setattr(P, "_STOP_JOIN_S", 0.2)
    monkeypatch.setattr(P, "_STOP_TOTAL_S", 0.6)
    release = threading.Event()
    calls: List[float] = []

    class BlockingPinger:
        def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> FakeResult:
            calls.append(time.time())
            release.wait(5.0)
            return FakeResult(True, 1.0, 0, None, 57, size, ip)

        def close(self) -> None:
            pass

    mgr = PingManager(env.db, env.config, env.bus, pinger=BlockingPinger(), raw_log=env.raw, resolver=env.resolver)
    env.mgr = mgr
    tid = mgr.add_target("1.1.1.1")["id"]
    assert mgr.worker_alive(tid) is False and mgr.worker_alive(999) is None
    mgr.start()
    deadline = time.time() + 3.0
    while not calls and time.time() < deadline:
        time.sleep(0.01)
    assert calls, "the worker must ping right away"
    old = _worker_threads(tid)
    assert len(old) == 1 and mgr.worker_alive(tid) is True
    t0 = time.time()
    mgr.stop()
    assert time.time() - t0 < 1.5
    assert old[0].is_alive(), "the worker is still parked inside ping()"
    mgr.start()                                  # a fresh worker for the same target
    release.set()                                # every parked ping returns now
    old[0].join(3.0)
    assert not old[0].is_alive(), "the superseded worker must exit after its ping"
    alive = _worker_threads(tid)
    assert len(alive) == 1 and mgr.worker_alive(tid) is True
    mgr.stop()
    alive[0].join(3.0)
    assert mgr.worker_alive(tid) is False and _worker_threads(tid) == []


def test_add_target_after_stop_does_not_start_a_worker(env):
    mgr = PingManager(env.db, env.config, env.bus, pinger=env.pinger, raw_log=env.raw, resolver=env.resolver)
    env.mgr = mgr
    mgr.start()
    mgr.stop()
    tid = mgr.add_target("1.1.1.1")["id"]
    time.sleep(0.05)
    assert mgr.worker_alive(tid) is False and _worker_threads(tid) == []
    assert mgr.target(tid)["light"] == "grey"


# ---------------------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------------------
def test_unresolved_hostname_records_miss_then_pings_once_resolved(env):
    env.resolver.table["dns.test"] = None
    tid = env.mgr.add_target("dns.test")["id"]
    env.events.clear()
    s = env.mgr.tick(tid)
    assert s is not None and s.ok is False and s.rtt_ms is None
    assert env.pinger.calls == [], "nothing to ping while unresolved"
    v = env.mgr.target(tid)
    assert v["resolved"] is False and v["ip"] is None and "resolution failed" in v["resolve_error"]
    assert v["consecutive_missed"] == 1 and v["last"] == {"ts": s.ts, "ok": False, "rtt_ms": None}
    # a single miss on a fresh target is "yellow": red needs enough samples and a failing recent run
    assert env.events_of("ping.sample")[-1]["data"] == {"target_id": tid, "ts": s.ts, "ok": False, "rtt_ms": None,
                                                        "light": "yellow"}
    # a failed resolve is retried on every tick while no IP is known
    env.clock.advance(1)
    env.mgr.tick(tid)
    assert env.resolver.calls == ["dns.test", "dns.test"]
    # DNS comes back -> ping happens, kind classified, ping.targets published
    env.resolver.table["dns.test"] = "8.8.8.8"
    env.clock.advance(1)
    n_before = len(env.events_of("ping.targets"))
    s = env.mgr.tick(tid)
    assert s.ok is True and s.rtt_ms == 20.0
    assert env.pinger.calls[-1][0] == "8.8.8.8"
    v = env.mgr.target(tid)
    assert v["resolved"] is True and v["ip"] == "8.8.8.8" and v["resolve_error"] is None and v["kind"] == "internet"
    assert len(env.events_of("ping.targets")) == n_before + 1


def test_resolver_exception_is_a_miss_not_a_crash(env):
    env.resolver.raise_exc = OSError("dns exploded")
    tid = env.mgr.add_target("boom.test")["id"]
    s = env.mgr.tick(tid)
    assert s.ok is False
    assert "dns exploded" in env.mgr.target(tid)["resolve_error"]


def test_reresolve_after_interval_and_failed_reresolve_keeps_last_ip(env):
    env.config.update({"ping": {"resolve_interval_s": 60}}, persist=False)
    tid = env.mgr.add_target("host.test")["id"]
    env.tick_all(tid, 3)
    assert env.resolver.calls == ["host.test"], "resolved once, then cached"
    env.clock.advance(60)
    env.resolver.table["host.test"] = "93.184.216.35"           # address changed
    env.mgr.tick(tid)
    assert env.resolver.calls == ["host.test", "host.test"]
    assert env.pinger.calls[-1][0] == "93.184.216.35"
    env.clock.advance(61)
    env.resolver.table["host.test"] = None                      # DNS hiccup on the periodic refresh
    s = env.mgr.tick(tid)
    assert s.ok is True and env.pinger.calls[-1][0] == "93.184.216.35", "keep pinging the last known IP"
    v = env.mgr.target(tid)
    assert v["resolved"] is False and v["resolve_error"] and v["ip"] == "93.184.216.35"
    # retried after the short retry period, not on every tick
    env.clock.advance(1)
    env.mgr.tick(tid)
    assert len(env.resolver.calls) == 3
    env.clock.advance(5)
    env.mgr.tick(tid)
    assert len(env.resolver.calls) == 4


def test_ip_literal_never_resolves_and_ipv6_brackets_are_stripped(env):
    tid = env.mgr.add_target("[2606:4700:4700::1111]")["id"]
    v = env.mgr.target(tid)
    assert v["host"] == "2606:4700:4700::1111" and v["ip"] == v["host"] and v["resolved"] is True
    env.tick_all(tid, 3)
    assert env.resolver.calls == []
    assert env.pinger.calls[-1][0] == "2606:4700:4700::1111"


# ---------------------------------------------------------------------------------------
# Statistics, light, view
# ---------------------------------------------------------------------------------------
def test_stats_over_window(env):
    env.pinger.script = [(True, 10.0), (True, 20.0), (False, None), (True, 30.0), (True, 40.0)]
    tid = env.mgr.add_target("1.1.1.1")["id"]
    env.tick_all(tid, 5)                    # samples at T0..T0+4, clock now T0+5
    s = env.mgr.stats(tid, 60)
    assert s == {"sent": 5, "received": 4, "lost": 1, "loss_pct": 20.0, "avg_ms": 25.0, "min_ms": 10.0,
                 "max_ms": 40.0, "jitter_ms": 10.0, "last_rtt_ms": 40.0}
    # window of 3 s from T0+5 -> only samples with ts > T0+2 : T0+3 (30) and T0+4 (40)
    s3 = env.mgr.stats(tid, 3)
    assert (s3["sent"], s3["received"], s3["avg_ms"], s3["jitter_ms"]) == (2, 2, 35.0, 10.0)
    assert env.mgr.stats(999, 60)["sent"] == 0 and env.mgr.stats(999, 60)["loss_pct"] is None
    assert [x.rtt_ms for x in env.mgr.samples(tid, 3)] == [30.0, 40.0]
    assert [x.rtt_ms for x in env.mgr.samples(tid, 300)] == [10.0, 20.0, None, 30.0, 40.0]
    v = env.mgr.target(tid)
    assert v["window"]["seconds"] == 60 and v["window"]["sent"] == 5 and "last_rtt_ms" not in v["window"]
    assert v["consecutive_ok"] == 2 and v["consecutive_missed"] == 0


def test_view_shape(env):
    tid = env.mgr.add_target("1.1.1.1", label="CF")["id"]
    env.tick_all(tid, 2)
    v = env.mgr.target(tid)
    assert set(v) == {"id", "host", "label", "kind", "ip", "enabled", "resolved", "resolve_error", "light",
                      "in_outage", "last", "consecutive_missed", "consecutive_ok", "window", "day", "since_ts"}
    assert set(v["window"]) == {"seconds", "sent", "received", "lost", "loss_pct", "avg_ms", "min_ms", "max_ms",
                                "jitter_ms"}
    assert set(v["day"]) == {"sent", "received", "lost", "loss_pct", "avg_ms", "min_ms", "max_ms"}
    assert v["label"] == "CF" and v["enabled"] is True and v["kind"] == "internet" and v["since_ts"] == T0
    assert env.mgr.target(12345) is None
    assert [t["id"] for t in env.mgr.targets()] == [tid]


def test_traffic_light_thresholds(env):
    env.config.update({"thresholds": {"window_s": 60, "local_warn_ms": 30, "internet_warn_ms": 150,
                                      "warn_loss_pct": 2.0, "bad_loss_pct": 15.0}}, persist=False)
    tid = env.mgr.add_target("1.1.1.1")["id"]
    assert env.mgr.light(tid) == "grey" and env.mgr.target(tid)["light"] == "grey"   # no samples yet
    env.pinger.script = [(True, 20.0)]
    env.tick_all(tid, 10)
    assert env.mgr.light(tid) == "green"
    # high latency on an internet target -> yellow
    env.pinger.script = [(True, 500.0)]
    env.tick_all(tid, 10)
    assert env.mgr.light(tid) == "yellow"
    # loss between warn and bad -> yellow (1 miss in 20 = 5 %)
    env.pinger.script = [(False, None)]
    env.tick_all(tid, 1)
    env.pinger.script = [(True, 20.0)]
    assert env.mgr.light(tid) == "yellow"
    # heavy loss -> red
    env.pinger.script = [(False, None)]
    env.tick_all(tid, 10)
    assert env.mgr.stats(tid, 60)["loss_pct"] >= 15.0
    assert env.mgr.light(tid) == "red"
    # samples age out of the window -> grey (no data in the window)
    env.clock.advance(120)
    assert env.mgr.light(tid) == "grey"
    # in_outage forces red even with perfect recent samples
    env.pinger.script = [(True, 20.0)]
    env.tick_all(tid, 5)
    assert env.mgr.light(tid) == "green"
    env.mgr.set_in_outage(tid, True)
    assert env.mgr.light(tid) == "red" and env.mgr.target(tid)["in_outage"] is True
    env.mgr.set_in_outage(tid, False)
    assert env.mgr.light(tid) == "green"
    env.mgr.set_in_outage(999, True)          # unknown id is ignored
    assert env.mgr.light(999) == "grey"


def test_local_kind_uses_local_warn_threshold(env):
    tid = env.mgr.add_target("192.168.1.1")["id"]
    assert env.mgr.target(tid)["kind"] == "local"
    env.pinger.script = [(True, 50.0)]          # fine for internet (150), bad for local (30)
    env.tick_all(tid, 5)
    assert env.mgr.light(tid) == "yellow"
    tid2 = env.mgr.add_target("9.9.9.9")["id"]
    env.tick_all(tid2, 5)
    assert env.mgr.light(tid2) == "green"


def test_kind_forced_by_db_and_fallback_without_netinfo(env, monkeypatch):
    row = env.db.add_target("10.9.9.9", None, kind="internet")
    env.mgr.start()
    assert env.mgr.target(row["id"])["kind"] == "internet", "db kind 'internet' must win over classification"
    env.mgr.stop()
    monkeypatch.setitem(sys.modules, "tnt.netinfo", None)      # import now raises ImportError
    assert P.classify_ip("10.0.0.5") == "local"
    assert P.classify_ip("1.1.1.1") == "internet"
    assert P.classify_ip("fe80::1%12") == "local"
    assert P.classify_ip("not-an-ip") == "internet"
    assert P._default_gateway() is None


# ---------------------------------------------------------------------------------------
# Minute aggregation and day summary
# ---------------------------------------------------------------------------------------
def test_minute_aggregation_upserts_on_rollover_and_on_stop(env):
    m0 = float(int(T0 // 60) * 60) + 57            # three seconds before a minute boundary
    env.clock.now = m0
    env.pinger.script = [(True, 10.0), (True, 20.0), (False, None), (True, 5.0)]
    tid = env.mgr.add_target("1.1.1.1")["id"]
    env.tick_all(tid, 3)                            # m0, m0+1, m0+2 -> all in minute M
    assert env.db.ping_minutes(tid, 0, 4_000_000_000) == [], "nothing persisted before the minute ends"
    env.mgr.tick(tid)                               # m0+3 = next minute -> flush minute M
    rows = env.db.ping_minutes(tid, 0, 4_000_000_000)
    assert len(rows) == 1
    r = rows[0]
    assert r["minute_ts"] == int(m0 // 60) * 60
    assert (r["sent"], r["received"], r["avg_ms"], r["min_ms"], r["max_ms"], r["jitter_ms"]) == (3, 2, 15.0, 10.0, 20.0, 10.0)
    env.mgr.stop()                                  # flushes the partial current minute
    rows = env.db.ping_minutes(tid, 0, 4_000_000_000)
    assert len(rows) == 2 and rows[1]["minute_ts"] == r["minute_ts"] + 60
    assert (rows[1]["sent"], rows[1]["received"], rows[1]["avg_ms"], rows[1]["jitter_ms"]) == (1, 1, 5.0, 0.0)
    # a second stop must not re-flush anything
    env.mgr.stop()
    assert [(x["sent"], x["received"]) for x in env.db.ping_minutes(tid, 0, 4_000_000_000)] == [(3, 2), (1, 1)]
    # a new sample in the same minute after a flush is added on top (upsert accumulates, no double count)
    env.mgr.tick(tid)
    env.mgr.stop()
    assert [(x["sent"], x["received"]) for x in env.db.ping_minutes(tid, 0, 4_000_000_000)] == [(3, 2), (2, 2)]


def test_all_missed_minute_has_null_latency(env):
    env.clock.now = float(int(T0 // 60) * 60)
    env.pinger.script = [(False, None)]
    tid = env.mgr.add_target("1.1.1.1")["id"]
    env.tick_all(tid, 2)
    env.mgr.remove_target(tid)                      # remove flushes too
    rows = env.db.ping_minutes(tid, 0, 4_000_000_000)
    assert len(rows) == 1
    assert (rows[0]["sent"], rows[0]["received"], rows[0]["avg_ms"], rows[0]["min_ms"], rows[0]["jitter_ms"]) == (2, 0, None, None, None)


def test_day_summary_combines_db_and_current_minute(env):
    env.clock.now = float(int(T0 // 60) * 60)
    tid = env.mgr.add_target("1.1.1.1")["id"]
    env.pinger.script = [(True, 10.0), (True, 30.0), (False, None)]
    env.tick_all(tid, 3)
    d = env.mgr.target(tid)["day"]
    assert d == {"sent": 3, "received": 2, "lost": 1, "loss_pct": 33.33, "avg_ms": 20.0, "min_ms": 10.0, "max_ms": 30.0}
    env.clock.advance(60)
    env.pinger.script = [(True, 50.0)]
    env.mgr.tick(tid)                               # rollover: minute 1 in db, minute 2 in memory
    d = env.mgr.target(tid)["day"]
    assert d["sent"] == 4 and d["received"] == 3 and d["avg_ms"] == 30.0 and d["max_ms"] == 50.0 and d["min_ms"] == 10.0
    # the db part is cached for 10 s: extra db rows are not visible immediately, but are after 10 s
    env.db.upsert_ping_minute(tid, int(env.clock.now) - 3600, 60, 60, 20.0, 20.0, 20.0, 0.0)
    assert env.mgr.target(tid)["day"]["sent"] == 4
    env.clock.advance(10)
    assert env.mgr.target(tid)["day"]["sent"] == 64


# ---------------------------------------------------------------------------------------
# RawPingLog
# ---------------------------------------------------------------------------------------
def test_raw_log_header_rows_and_flush(tmp_path):
    clock = FakeClock(_local_midnight(2026, 3, 10) + 3600)
    log = RawPingLog(tmp_path / "pings", clock=clock)
    ts = clock()
    log.write(ts, 1, "1.1.1.1", True, 20.5, 1200)
    log.write(ts + 1, 2, "host.test", False, None, 32)
    path = tmp_path / "pings" / "2026-03-10.csv"
    assert path.exists()
    log.flush()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "ts,target_id,host,ok,rtt_ms,bytes"
    assert lines[1] == f"{ts:.3f},1,1.1.1.1,1,20.5,1200"
    assert lines[2] == f"{ts + 1:.3f},2,host.test,0,,32"
    # buffered: a write 1 s later is not yet on disk, one 2 s later flushes
    clock.advance(1)
    log.write(clock(), 1, "1.1.1.1", True, 1.0, 32)
    assert len(path.read_text(encoding="utf-8").splitlines()) == 3
    clock.advance(1.5)
    log.write(clock(), 1, "1.1.1.1", True, 1.0, 32)
    assert len(path.read_text(encoding="utf-8").splitlines()) == 5
    log.close()
    # reopening appends without a second header
    log2 = RawPingLog(tmp_path / "pings", clock=clock)
    log2.write(clock(), 1, "1.1.1.1", True, 2.0, 32)
    log2.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 6 and lines.count("ts,target_id,host,ok,rtt_ms,bytes") == 1


def test_raw_log_rolls_over_at_local_midnight_and_gzips_previous_day(tmp_path):
    midnight = _local_midnight(2026, 3, 10)
    clock = FakeClock(midnight - 5)
    log = RawPingLog(tmp_path / "pings", clock=clock)
    for i in range(5):
        log.write(clock(), 1, "1.1.1.1", True, 10.0 + i, 32)
        clock.advance(1)
    assert clock() == midnight
    log.write(clock(), 1, "1.1.1.1", True, 99.0, 32)         # first row of the new day
    log.wait_background(5.0)
    d = tmp_path / "pings"
    assert not (d / "2026-03-09.csv").exists()
    gz = d / "2026-03-09.csv.gz"
    assert gz.exists()
    with gzip.open(gz, "rt", encoding="utf-8") as fh:
        old = fh.read().splitlines()
    assert old[0] == "ts,target_id,host,ok,rtt_ms,bytes" and len(old) == 6 and old[-1].endswith(",1,14.0,32")
    log.flush()
    new = (d / "2026-03-10.csv").read_text(encoding="utf-8").splitlines()
    assert new[0] == "ts,target_id,host,ok,rtt_ms,bytes" and len(new) == 2 and new[1].endswith(",1,99.0,32")
    log.close()


def test_raw_log_compresses_stale_files_at_open(tmp_path):
    d = tmp_path / "pings"
    d.mkdir()
    (d / "2026-03-08.csv").write_text("ts,target_id,host,ok,rtt_ms,bytes\n1,1,x,1,1.0,32\n", encoding="utf-8")
    (d / "2026-03-10.csv").write_text("ts,target_id,host,ok,rtt_ms,bytes\n", encoding="utf-8")     # today: untouched
    clock = FakeClock(_local_midnight(2026, 3, 10) + 100)
    log = RawPingLog(d, clock=clock)
    log.wait_background(5.0)
    assert (d / "2026-03-08.csv.gz").exists() and not (d / "2026-03-08.csv").exists()
    assert (d / "2026-03-10.csv").exists()
    log.close()


def test_raw_log_trim_deletes_old_files(tmp_path):
    clock = FakeClock(_local_midnight(2026, 3, 10) + 43200)
    log = RawPingLog(tmp_path / "pings", clock=clock)
    d = tmp_path / "pings"
    for name in ("2025-01-01.csv", "2025-06-01.csv.gz", "2026-02-07.csv.gz", "2026-02-09.csv.gz", "2026-03-09.csv.gz", "notes.txt"):
        (d / name).write_bytes(b"x")
    log.write(clock(), 1, "1.1.1.1", True, 1.0, 32)          # today's file is open
    assert log.trim(30) == 3                                  # cutoff 2026-02-08: 2026-02-07 and older go
    remaining = sorted(p.name for p in d.iterdir())
    assert remaining == ["2026-02-09.csv.gz", "2026-03-09.csv.gz", "2026-03-10.csv", "notes.txt"]
    assert log.trim(0) == 2                                   # everything before today
    assert sorted(p.name for p in d.iterdir()) == ["2026-03-10.csv", "notes.txt"]
    log.close()


# ---------------------------------------------------------------------------------------
# Targets: add / remove / defaults / listeners / pause / config
# ---------------------------------------------------------------------------------------
def test_add_target_validation_and_idempotence(env):
    with pytest.raises(ValueError):
        env.mgr.add_target("")
    with pytest.raises(ValueError):
        env.mgr.add_target("   ")
    with pytest.raises(ValueError):
        env.mgr.add_target("bad host")
    with pytest.raises(ValueError):
        env.mgr.add_target("http://x.test/")
    with pytest.raises(ValueError):
        env.mgr.add_target("-leading.test")
    v = env.mgr.add_target("  Host.Test. ", label=" Web ")
    assert v["host"] == "Host.Test" and v["label"] == "Web"
    again = env.mgr.add_target("host.test")
    assert again["id"] == v["id"] and len(env.mgr.targets()) == 1
    assert env.db.find_target("host.test")["id"] == v["id"]
    assert env.events_of("ping.targets")[-1]["data"]["targets"][0]["id"] == v["id"]


def test_remove_target_stops_worker_flushes_deletes_and_notifies(env):
    gate = threading.Event()

    def parking_sleep(s: float) -> None:      # the worker ticks once, then parks until the test lets it go
        env.clock.advance(s)
        gate.wait(5.0)

    mgr = env.make_manager(sleep=parking_sleep)
    env.mgr = mgr
    removed_ids: List[int] = []
    unsub = mgr.add_removal_listener(removed_ids.append)
    mgr.add_removal_listener(lambda tid: 1 / 0)          # a bad listener must not break removal
    env.clock.now = float(int(T0 // 60) * 60)
    tid = mgr.add_target("1.1.1.1")["id"]
    mgr.start()
    deadline = time.time() + 3.0
    while len(mgr.samples(tid, 10 ** 6)) < 1 and time.time() < deadline:
        time.sleep(0.01)
    assert [th for th in threading.enumerate() if th.name == f"tnt-ping-{tid}" and th.is_alive()]
    env.events.clear()
    gate.set()
    assert mgr.remove_target(tid) is True
    assert removed_ids == [tid]
    assert env.db.get_target(tid) is None
    assert env.mgr.target(tid) is None and env.mgr.targets() == []
    assert env.db.ping_minutes(tid, 0, 4_000_000_000)[0]["sent"] >= 1, "the partial minute was flushed"
    csv_rows = env.raw.current_path.read_text(encoding="utf-8").splitlines()
    assert len(csv_rows) >= 2 and csv_rows[1].split(",")[1] == str(tid), "the raw log was flushed on removal"
    assert env.events_of("ping.targets") and env.events_of("ping.targets")[-1]["data"]["targets"] == []
    assert not [th for th in threading.enumerate() if th.name == f"tnt-ping-{tid}" and th.is_alive()]
    assert env.mgr.remove_target(tid) is False
    assert env.mgr.remove_target("nope") is False
    unsub()
    tid2 = env.mgr.add_target("9.9.9.9")["id"]
    env.mgr.remove_target(tid2)
    assert removed_ids == [tid], "unsubscribed listener is not called"
    env.mgr.stop()


def test_load_defaults_with_fake_gateway(env):
    # config extras are ignored on purpose: the defaults are hard-coded
    env.config.update({"targets": {"defaults_extra": ["8.8.8.8", "host.test", "bad host!"]}}, persist=False)
    extra = env.mgr.add_target("9.9.9.9")["id"]
    env.events.clear()
    views = env.mgr.load_defaults()
    hosts = [v["host"] for v in views]
    # the default gateway tile is the "gateway" alias (follows the current default route),
    # never a frozen IP that turns into a permanent outage after a subnet change; any other
    # tile is removed so the result is exactly the three defaults in order
    assert hosts == ["gateway", "1.1.1.1", "totalelectronics.com"]
    assert env.mgr.target(extra) is None
    gw = views[0]
    assert gw["label"] == "Gateway" and gw["kind"] == "local"
    assert views[1]["kind"] == "internet"
    assert env.events_of("ping.targets"), "ping.targets published"
    assert env.mgr.load_defaults() == env.mgr.targets() and len(env.mgr.targets()) == 3
    # replace=False only prepends the defaults
    env.mgr.add_target("9.9.9.9")
    assert [v["host"] for v in env.mgr.load_defaults(replace=False)] == ["gateway", "1.1.1.1", "totalelectronics.com", "9.9.9.9"]
    # the alias resolves to the machine's gateway on the first tick and re-resolves later
    env.mgr.tick(gw["id"])
    assert env.mgr.target(gw["id"])["ip"] == "10.0.0.251"
    assert env.pinger.calls and env.pinger.calls[-1][0] == "10.0.0.251"
    # gateway changes (new subnet) -> the same tile follows it after the resolve interval
    env.netinfo.gateway = "192.168.50.1"
    env.clock.advance(float(env.config.get("ping.resolve_interval_s")) + 1)
    env.mgr.tick(gw["id"])
    assert env.mgr.target(gw["id"])["ip"] == "192.168.50.1"
    # gateway unavailable -> the alias stays (unresolved, counted as a miss) and the other defaults are added
    env.netinfo.gateway = None
    for v in list(env.mgr.targets()):
        env.mgr.remove_target(v["id"])
    views = env.mgr.load_defaults()
    assert [v["host"] for v in views] == ["gateway", "1.1.1.1", "totalelectronics.com"]
    env.mgr.tick(views[0]["id"])
    v = env.mgr.target(views[0]["id"])
    assert v["resolved"] is False and "no default gateway" in (v["resolve_error"] or "")


def test_start_loads_only_enabled_targets(env):
    a = env.db.add_target("1.1.1.1")
    b = env.db.add_target("8.8.8.8")
    env.db.set_target_enabled(b["id"], False)
    env.mgr.start()
    assert [t["id"] for t in env.mgr.targets()] == [a["id"]]
    assert env.mgr.running is True
    env.mgr.stop()
    assert env.mgr.running is False


def test_sample_listeners_called_after_recording(env):
    seen: List[Tuple[Dict[str, Any], Sample]] = []
    order: List[str] = []

    def listener(view: Dict[str, Any], sample: Sample) -> None:
        order.append("listener")
        seen.append((view, sample))

    env.bus.subscribe(lambda e: order.append("bus") if e["type"] == "ping.sample" else None)
    unsub = env.mgr.add_sample_listener(lambda v, s: 1 / 0)      # bad listener first
    env.mgr.add_sample_listener(listener)
    tid = env.mgr.add_target("1.1.1.1")["id"]
    s = env.mgr.tick(tid)
    assert len(seen) == 1
    view, sample = seen[0]
    assert sample is s and view["id"] == tid and view["kind"] == "internet"
    assert view["last"] == {"ts": s.ts, "ok": True, "rtt_ms": 20.0}
    assert view["window"]["sent"] == 1 and view["consecutive_ok"] == 1 and view["light"] == "green"
    assert order == ["bus", "listener"], "event published, then listeners, both after recording"
    unsub()
    env.clock.advance(1)
    env.mgr.tick(tid)
    assert len(seen) == 2


def test_paused_means_no_pings_and_grey(env):
    tid = env.mgr.add_target("1.1.1.1")["id"]
    env.tick_all(tid, 3)
    assert env.mgr.light(tid) == "green"
    env.events.clear()
    env.mgr.set_paused(True)
    assert env.mgr.paused is True
    assert env.events_of("ping.targets")[-1]["data"]["targets"][0]["light"] == "grey"
    calls = len(env.pinger.calls)
    assert env.tick_all(tid, 3) == []
    assert len(env.pinger.calls) == calls
    assert env.mgr.light(tid) == "grey" and env.mgr.target(tid)["light"] == "grey"
    assert len(env.mgr.samples(tid, 300)) == 3
    env.mgr.set_paused(True)                          # no-op, no extra event
    assert len(env.events_of("ping.targets")) == 1
    env.mgr.set_paused(False)
    assert env.mgr.paused is False
    assert env.mgr.tick(tid) is not None and len(env.pinger.calls) == calls + 1
    assert env.mgr.light(tid) == "green"


def test_loaded_toggle_and_timeout_ttl_are_read_every_tick(env):
    env.config.update({"ping": {"loaded": True, "timeout_ms": 1500, "ttl": 64}}, persist=False)
    tid = env.mgr.add_target("1.1.1.1")["id"]
    env.mgr.tick(tid)
    assert env.pinger.calls[-1] == ("1.1.1.1", 1200, 1500, 64)
    env.config.update({"ping": {"loaded": False}}, persist=False)
    env.clock.advance(1)
    env.mgr.tick(tid)
    assert env.pinger.calls[-1] == ("1.1.1.1", 32, 1500, 64)
    env.config.update({"ping": {"unloaded_bytes": 100, "timeout_ms": 700, "ttl": 32}}, persist=False)
    env.clock.advance(1)
    env.mgr.tick(tid)
    assert env.pinger.calls[-1] == ("1.1.1.1", 100, 700, 32)
    env.raw.flush()
    rows = (env.tmp / "pings" / f"{time.strftime('%Y-%m-%d', time.localtime(T0))}.csv").read_text(encoding="utf-8").splitlines()
    assert [r.split(",")[-1] for r in rows[1:]] == ["1200", "32", "100"]


def test_ping_exception_is_recorded_as_miss(env):
    class Boom:
        def ping(self, *a: Any) -> FakeResult:
            raise RuntimeError("icmp broke")

    mgr = PingManager(env.db, env.config, env.bus, pinger=Boom(), raw_log=env.raw, clock=env.clock,
                      sleep=lambda s: env.clock.advance(s), resolver=env.resolver)
    tid = mgr.add_target("1.1.1.1")["id"]
    s = mgr.tick(tid)
    assert s.ok is False and mgr.target(tid)["consecutive_missed"] == 1
    mgr.stop()


def test_validate_host():
    assert P.validate_host(" 1.1.1.1 ") == "1.1.1.1"
    assert P.validate_host("[::1]") == "::1"
    assert P.validate_host("my_host.local.") == "my_host.local"
    for bad in ("", " ", None, "a b", "x/y", "host:80", "-x", "x-.test", "300.1.1.1", "1.2.3"):
        with pytest.raises(ValueError):
            P.validate_host(bad)


def test_ip_literal_is_canonicalised_so_spellings_do_not_duplicate(env):
    assert P.validate_host("2606:4700:4700:0:0:0:0:1111") == "2606:4700:4700::1111"
    assert P.validate_host("[2606:4700:4700:0000:0000:0000:0000:1111]") == "2606:4700:4700::1111"
    a = env.mgr.add_target("2606:4700:4700:0:0:0:0:1111")
    b = env.mgr.add_target("2606:4700:4700::1111")
    assert a["host"] == "2606:4700:4700::1111" and a["id"] == b["id"] and len(env.mgr.targets()) == 1


# ---------------------------------------------------------------------------------------
# Regression tests
# ---------------------------------------------------------------------------------------
class _BlockingPinger:
    """Every ping parks until ``release`` is set (simulates a long ICMP timeout)."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.inside = threading.Event()
        self.in_ping = False
        self.closed_while_in_ping: List[bool] = []
        self.close_thread: Optional[str] = None

    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> FakeResult:
        self.in_ping = True
        self.inside.set()
        self.release.wait(5.0)
        self.in_ping = False
        return FakeResult(True, 1.0, 0, None, 57, size, ip)

    def close(self) -> None:
        self.closed_while_in_ping.append(self.in_ping)
        self.close_thread = threading.current_thread().name


def test_owned_pinger_is_closed_only_after_the_stuck_worker_exits(env, monkeypatch):
    """stop() must never close the ICMP handles while a worker is inside pinger.ping()."""
    monkeypatch.setattr(P, "_STOP_JOIN_S", 0.2)
    monkeypatch.setattr(P, "_STOP_TOTAL_S", 0.6)
    blocking = _BlockingPinger()
    fake_icmp = types.ModuleType("tnt.icmp")
    fake_icmp.IcmpPinger = lambda: blocking                  # the manager creates (and owns) it lazily
    fake_icmp.resolve = lambda host, prefer_ipv4=True, timeout_s=3.0: None
    monkeypatch.setitem(sys.modules, "tnt.icmp", fake_icmp)
    mgr = PingManager(env.db, env.config, env.bus, pinger=None, raw_log=env.raw, resolver=env.resolver)
    env.mgr = mgr
    tid = mgr.add_target("1.1.1.1")["id"]
    mgr.start()
    assert mgr.pinger is blocking
    assert blocking.inside.wait(3.0), "the worker must ping right away"
    worker = _worker_threads(tid)[0]
    mgr.stop()
    assert worker.is_alive(), "the worker is still parked inside ping()"
    assert blocking.closed_while_in_ping == [], "close() must be deferred while a ping is in flight"
    blocking.release.set()
    worker.join(3.0)
    assert not worker.is_alive()
    assert blocking.closed_while_in_ping == [False], "the last worker out closes the pinger"
    assert blocking.close_thread == worker.name
    mgr.stop()                                               # no worker left: closes again (close() is idempotent)
    assert all(flag is False for flag in blocking.closed_while_in_ping)


def test_owned_pinger_is_closed_immediately_when_workers_stopped_in_time(env, monkeypatch):
    calls: List[str] = []

    class Quick:
        def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> FakeResult:
            return FakeResult(True, 1.0, 0, None, 57, size, ip)

        def close(self) -> None:
            calls.append(threading.current_thread().name)

    fake_icmp = types.ModuleType("tnt.icmp")
    fake_icmp.IcmpPinger = Quick
    monkeypatch.setitem(sys.modules, "tnt.icmp", fake_icmp)
    mgr = PingManager(env.db, env.config, env.bus, pinger=None, raw_log=env.raw, resolver=env.resolver)
    env.mgr = mgr
    tid = mgr.add_target("1.1.1.1")["id"]
    mgr.start()
    deadline = time.time() + 3.0
    while not mgr.samples(tid, 10 ** 6) and time.time() < deadline:
        time.sleep(0.01)
    mgr.stop()
    assert calls == [threading.current_thread().name], "no worker left: stop() closes the pinger itself"
    mgr.start()                                              # restart reuses the pinger, no close
    mgr.stop()
    assert len(calls) == 2


def test_late_sample_after_stop_is_flushed_and_the_raw_log_closed_again(env, monkeypatch):
    """A worker stuck in a long ping outlives stop(); its last sample re-opens the closed raw
    log, so the exiting worker must flush and close it again (no open handle, no lost row)."""
    monkeypatch.setattr(P, "_STOP_JOIN_S", 0.2)
    monkeypatch.setattr(P, "_STOP_TOTAL_S", 0.6)
    blocking = _BlockingPinger()
    mgr = PingManager(env.db, env.config, env.bus, pinger=blocking, raw_log=env.raw, resolver=env.resolver)
    env.mgr = mgr
    tid = mgr.add_target("1.1.1.1")["id"]
    mgr.start()
    assert blocking.inside.wait(3.0)
    worker = _worker_threads(tid)[0]
    mgr.stop()
    assert env.raw._file is None, "stop() closed the raw log"
    blocking.release.set()
    worker.join(3.0)
    assert not worker.is_alive()
    assert env.raw._file is None, "the late write re-opened the log; the worker must close it again"
    path = env.tmp / "pings" / f"{time.strftime('%Y-%m-%d', time.localtime(time.time()))}.csv"
    rows = path.read_text(encoding="utf-8").splitlines()
    assert len(rows) == 2 and rows[1].split(",")[1] == str(tid), "the late row is on disk"
    assert env.db.ping_minutes(tid, 0, 4_000_000_000)[0]["sent"] == 1, "and in the minute table"
    assert blocking.closed_while_in_ping == [], "an injected pinger is never closed by the manager"


def test_clock_stepped_backwards_reanchors_instead_of_sleeping_through_the_jump(env):
    sleeps: List[float] = []
    gate = threading.Event()

    def fake_sleep(s: float) -> None:
        sleeps.append(s)
        env.clock.advance(s)
        if len(sleeps) == 2:
            env.clock.advance(-100.0)           # NTP / manual clock change right after the 2nd tick
        if len(sleeps) >= 4:
            gate.wait(5.0)

    mgr = env.make_manager(sleep=fake_sleep)
    env.mgr = mgr
    tid = mgr.add_target("1.1.1.1")["id"]
    mgr.start()
    deadline = time.time() + 5.0
    while len(sleeps) < 4 and time.time() < deadline:
        time.sleep(0.01)
    gate.set()
    mgr.stop()
    assert [round(s, 6) for s in sleeps[:4]] == [1.0, 1.0, 1.0, 1.0], "never sleep for the whole jump"
    ts = [round(s.ts - T0, 6) for s in mgr.samples(tid, 10 ** 9)]
    assert ts[:4] == [0.0, 1.0, -98.0, -97.0], "one tick per second continues on the new clock"


def test_samples_and_stats_tolerate_junk_window_arguments(env):
    tid = env.mgr.add_target("1.1.1.1")["id"]
    env.tick_all(tid, 3)
    assert len(env.mgr.samples(tid, "abc")) == 3                       # default window
    assert len(env.mgr.samples(tid, None)) == 3
    assert env.mgr.samples(tid, -5) == []
    assert env.mgr.samples(tid, float("inf")) and env.mgr.stats(tid, float("inf"))["sent"] == 3
    assert env.mgr.stats(tid, "nope")["sent"] == 3
    assert env.mgr.stats(tid, float("nan"))["sent"] == 3
    assert env.mgr.stats(tid, -1)["sent"] == 0 and env.mgr.stats(999, None)["sent"] == 0


def test_pause_persists_the_partial_minute(env):
    env.clock.now = float(int(T0 // 60) * 60)
    env.pinger.script = [(True, 10.0)]
    tid = env.mgr.add_target("1.1.1.1")["id"]
    env.tick_all(tid, 3)
    assert env.db.ping_minutes(tid, 0, 4_000_000_000) == []
    env.mgr.set_paused(True)
    rows = env.db.ping_minutes(tid, 0, 4_000_000_000)
    assert len(rows) == 1 and (rows[0]["sent"], rows[0]["received"]) == (3, 3)
    env.mgr.set_paused(False)
    env.tick_all(tid, 2)                                    # same minute: accumulates, no double count
    env.mgr.stop()
    rows = env.db.ping_minutes(tid, 0, 4_000_000_000)
    assert len(rows) == 1 and (rows[0]["sent"], rows[0]["received"], rows[0]["avg_ms"]) == (5, 5, 10.0)
    assert env.mgr.target(tid)["day"]["sent"] == 5


def test_raw_log_recreates_a_deleted_directory(tmp_path):
    import shutil

    clock = FakeClock(_local_midnight(2026, 3, 10) + 3600)
    d = tmp_path / "pings"
    log = RawPingLog(d, clock=clock)
    log.write(clock(), 1, "1.1.1.1", True, 1.0, 32)
    log.close()
    shutil.rmtree(d)
    clock.advance(86400)                                    # next day: rollover opens a new file
    log.write(clock(), 1, "1.1.1.1", True, 2.0, 32)
    log.close()
    assert (d / "2026-03-11.csv").read_text(encoding="utf-8").splitlines() == [
        "ts,target_id,host,ok,rtt_ms,bytes", f"{clock():.3f},1,1.1.1.1,1,2.0,32"]
