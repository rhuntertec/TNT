"""Tests for tnt.speedtest.quality (latency under load, call quality) and its SpeedScheduler wiring.

Offline: every pinger here is a test double, and a real tnt.icmp.IcmpPinger refuses to ping in this module.
"""
from __future__ import annotations

import functools
import inspect
import json
import threading
import time

import pytest

from tnt import icmp
from tnt.config import Config
from tnt.db import Database
from tnt.events import EventBus
from tnt.speedtest import base, quality
from tnt.speedtest import scheduler as sched_mod
from tnt.speedtest.base import SpeedResult


# --------------------------------------------------------------------------- helpers / fixtures

def wait_until(pred, timeout=5.0, step=0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return pred()


class FakeClock:
    def __init__(self, now: float) -> None:
        self.now = float(now)

    def __call__(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def _no_real_icmp(monkeypatch):
    """Guard: no echo leaves the process. A real IcmpPinger refuses to ping during every test in this module."""
    def refuse(self, ip, size=32, timeout_ms=1000, ttl=128):
        raise OSError("ICMP is disabled in tests (tnt.speedtest.quality)")

    monkeypatch.setattr(icmp.IcmpPinger, "ping", refuse)


@pytest.fixture(autouse=True)
def _clear_cooldowns():
    """The rate-limit cooldown registry is module-level: never leak one between tests."""
    base.clear_cooldowns()
    yield
    base.clear_cooldowns()


@pytest.fixture
def cfg(tmp_path):
    c = Config(tmp_path / "config.json")
    c.update({"speedtest": {"download_mb": 1, "upload_mb": 1, "duration_s": 2, "connections": 2}}, persist=False)
    return c


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "t.db")
    yield d
    d.close()


@pytest.fixture
def bus():
    return EventBus()


def _events(bus):
    seen = []
    bus.subscribe(seen.append)
    return seen


def _bloat_threads():
    return [t.name for t in threading.enumerate() if t.name.startswith("tnt-ping-bloat") and t.is_alive()]


class _Reply:
    def __init__(self, ok, rtt_ms):
        self.ok = ok
        self.rtt_ms = rtt_ms if ok else None


class ScriptedPinger:
    """Test double: ``script(seconds since the first echo) -> (sleep_s, ok, rtt_ms)``; records every call."""

    def __init__(self, script=None):
        self.script = script or (lambda elapsed: (0.0, True, 10.0))
        self.calls = []                          # (ip, size, timeout_ms, thread name)
        self.closed = 0
        self.first_call = threading.Event()
        self._lock = threading.Lock()
        self._t0 = None

    def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
        now = time.monotonic()
        with self._lock:
            if self._t0 is None:
                self._t0 = now
            elapsed = now - self._t0
            self.calls.append((ip, size, timeout_ms, threading.current_thread().name))
        self.first_call.set()
        sleep_s, ok, rtt = self.script(elapsed)
        if sleep_s:
            time.sleep(sleep_s)
        return _Reply(ok, rtt)

    def close(self):
        self.closed += 1


#: Phase marks of a synthetic run: a 3 s idle baseline, then 10 s download and upload phases (settle 1 s each).
PHASES = {"baseline": (0.0, 3.0), "connect": (3.0, 3.5), "latency": (3.5, 10.0), "download": (10.0, 20.0),
          "upload": (20.0, 30.0), "done": (30.0, 30.0)}


def _samples(start, values, step=0.1):
    """One sample per value from *start*, *step* s apart: a number is a reply (ms), None a lost echo, "skip" a
    skipped slot."""
    out = []
    for i, value in enumerate(values):
        ts = start + i * step
        if isinstance(value, str):
            out.append((ts, None, None))
        elif value is None:
            out.append((ts, False, None))
        else:
            out.append((ts, True, float(value)))
    return out


def _build(download=None, upload=None, baseline=None, phases=PHASES, target="1.1.1.1"):
    """QUALITY for a synthetic run: 30 idle replies of 10 ms unless *baseline* says otherwise; the *download* and
    *upload* samples start right after their 1 s settle."""
    samples = _samples(0.0, [10.0] * 30 if baseline is None else baseline)
    if download is not None:
        samples += _samples(11.0, download)
    if upload is not None:
        samples += _samples(21.0, upload)
    return quality.build_quality(samples, phases, target=target, interval_ms=100, payload=32)


# --------------------------------------------------------------------------- guard, shapes and texts

def test_real_icmp_is_disabled_in_this_module():
    with pytest.raises(OSError, match="disabled in tests"):
        icmp.IcmpPinger().ping("192.0.2.1")


def test_quality_shapes_keys_and_texts():
    q = _build(download=[20.0] * 20, upload=[20.0] * 20)
    assert list(q) == list(quality.QUALITY_KEYS)
    assert (q["version"], q["available"], q["reason"], q["target"], q["interval_ms"], q["payload_bytes"]) == \
        (1, True, None, "1.1.1.1", 100, 32)
    assert list(q["windows"]) == ["baseline", "download", "upload"]
    assert list(q["windows"]["baseline"]) == list(quality.WINDOW_KEYS)
    for name in ("download", "upload"):
        assert list(q["windows"][name]) == list(quality.WINDOW_KEYS) + list(quality.LOADED_EXTRA_KEYS)
    assert list(q["bufferbloat"]) == list(quality.BUFFERBLOAT_KEYS)
    assert list(q["call"]) == list(quality.CALL_KEYS) and q["call"]["method"] == "estimate (simplified E-model)"
    assert list(q["call"]["idle"]) == list(quality.SCORE_KEYS)
    assert list(q["call"]["loaded"]) == list(quality.SCORE_KEYS) + ["direction"]
    assert [list(c) for c in q["call"]["checks"]] == [list(quality.CHECK_KEYS)] * 2
    assert [c["key"] for c in q["call"]["checks"]] == ["zoom", "teams"]
    assert json.loads(json.dumps(q)) == q
    assert quality.GRADE_TEXT == {
        "A+": "No bufferbloat: latency stays flat while the line is busy",
        "A": "Excellent: calls and games are unaffected by heavy use",
        "B": "Good: small delay spikes while the line is busy",
        "C": "Bufferbloat: calls and games may lag while someone uploads or downloads",
        "D": "Severe bufferbloat: calls will break up while the line is busy",
        "F": "Unusable under load: the connection stalls when it is busy",
    }
    assert tuple(quality.GRADE_TEXT) == quality.GRADES
    assert quality.REASON_NO_REPLIES.format(target="1.1.1.1") == "1.1.1.1 did not answer pings"
    texts = list(quality.GRADE_TEXT.values()) + [quality.REASON_TOO_SHORT, quality.REASON_MOST_LOST,
                                                 quality.REASON_NO_REPLIES, quality.REASON_NO_BASELINE,
                                                 quality.WARNING_SOME_LOST, quality.WARNING_DELAYED]
    assert not any("n't" in text for text in texts)


# --------------------------------------------------------------------------- pure functions

@pytest.mark.parametrize("increase, grade", [
    (0, "A+"), (4.9, "A+"), (5.0, "A"), (29.9, "A"), (30, "B"), (59.9, "B"), (60, "C"), (199.9, "C"),
    (200, "D"), (399.9, "D"), (400, "F"), (5000, "F"),
])
def test_bloat_grade_boundaries_go_to_the_worse_grade(increase, grade):
    assert quality.bloat_grade(increase) == grade


def test_bloat_grade_of_nothing_is_nothing():
    assert quality.bloat_grade(None) is None


@pytest.mark.parametrize("latency, jitter, loss, r, mos, label", [
    (20, 2, 0, 92.35, 4.39, "Excellent"),
    (60, 15, 1, 88.2, 4.29, "Good"),
    (150, 40, 2, 76.2, 3.87, "Fair"),
    (300, 60, 5, 49.7, 2.56, "Unusable"),
    (0, 0, 0, 92.95, 4.40, "Excellent"),
    (1000, 500, 50, 0.0, 1.0, "Unusable"),
    # 0 < R < ~6.5: the cubic term would give 0.99, below the bottom of the MOS scale (and below the 1.0 of R 0)
    (100, 0, 35.5, 1.7, 1.0, "Unusable"),
    (992, 0, 0, 5.0, 1.0, "Unusable"),
])
def test_call_quality_simplified_emodel_vectors(latency, jitter, loss, r, mos, label):
    got = quality.call_quality(latency, jitter, loss)
    assert list(got) == ["r", "mos", "label"]
    assert got["r"] == pytest.approx(r, abs=0.005) and got["mos"] == pytest.approx(mos, abs=0.005)
    assert got["label"] == label


def test_call_quality_labels_and_missing_inputs():
    assert quality.call_quality(None, None, None) == quality.call_quality(0, 0, 0)
    assert quality.call_quality(0, 0, 11.18)["label"] == "Poor"          # R 65.0
    assert quality.call_quality(0, 0, 15)["label"] == "Bad"              # R 55.45
    assert quality.call_quality(None, None, 100.0) == {"r": 0.0, "mos": 1.0, "label": "Unusable"}


def test_window_stats_rounds_ranks_and_uses_dispatch_order():
    samples = _samples(0.0, [10.0, 12.0, 11.0, None, "skip", 30.0, 14.05])
    # the order samples arrive in does not matter: jitter follows dispatch order (unsorted, this order gives 10.8;
    # a plain reversal would not tell, it keeps every consecutive difference)
    w = quality.window_stats([samples[i] for i in (3, 0, 6, 1, 5, 2, 4)])
    assert list(w) == list(quality.WINDOW_KEYS)
    assert w == {"sent": 6, "received": 5, "skipped": 1, "loss_pct": 16.7, "median_ms": 12.0, "mean_ms": 15.4,
                 "p95_ms": 30.0, "max_ms": 30.0, "jitter_ms": 9.5}


def test_window_stats_nearest_rank_and_small_windows():
    w = quality.window_stats(_samples(0.0, list(range(1, 21))))
    assert (w["p95_ms"], w["median_ms"], w["max_ms"], w["jitter_ms"]) == (19.0, 10.5, 20.0, 1.0)
    one = quality.window_stats(_samples(0.0, [None, 7.0]))
    assert (one["received"], one["loss_pct"], one["p95_ms"], one["jitter_ms"]) == (1, 50.0, 7.0, None)
    assert quality.window_stats([]) == dict(dict.fromkeys(quality.WINDOW_KEYS), sent=0, received=0, skipped=0)
    assert quality.window_stats([(0.0, True, None)])["received"] == 0           # a reply without an RTT is lost


# --------------------------------------------------------------------------- grading

def test_grading_pins():
    # 20 sent, 4 replies: most probes lost -> F, with the increase from the replies
    q = _build(download=[30.0] * 4 + [None] * 16)
    d = q["windows"]["download"]
    assert (d["sent"], d["received"], d["loss_pct"]) == (20, 4, 80.0)
    assert (d["grade"], d["reason"], d["increase_ms"]) == ("F", "most probes were lost under load", 20.0)
    assert (q["bufferbloat"]["grade"], q["bufferbloat"]["direction"]) == ("F", "download")
    assert q["bufferbloat"]["text"] == "Unusable under load: the connection stalls when it is busy"

    # 20 sent, no reply: F without an increase; the busy call estimate is Unusable
    q = _build(download=[None] * 20)
    d = q["windows"]["download"]
    assert (d["grade"], d["increase_ms"], d["mean_ms"], d["jitter_ms"]) == ("F", None, None, None)
    assert (q["bufferbloat"]["grade"], q["bufferbloat"]["increase_ms"]) == ("F", None)
    assert q["call"]["loaded"] == {"r": 0.0, "mos": 1.0, "label": "Unusable", "direction": "download"}
    assert q["call"]["checks"] == [
        {"key": "zoom", "ok": False, "detail": "loss 100% is above 2% (while downloading)"},
        {"key": "teams", "ok": False, "detail": "loss 100% is not below 1% (while downloading)"},
    ]

    # 9 sent, 9 replies: too short
    q = _build(download=[20.0] * 9)
    d = q["windows"]["download"]
    assert (d["grade"], d["reason"], d["increase_ms"], d["warning"]) == (None, "phase too short to grade", None, None)
    assert q["bufferbloat"] == {"grade": None, "increase_ms": None, "direction": None, "text": None, "warning": None,
                                "reason": "phase too short to grade"}
    assert q["call"]["loaded"] is None

    # 12 sent, 11 replies, +35 ms: B with the loss warning
    q = _build(download=[45.0] * 11 + [None])
    d = q["windows"]["download"]
    assert (d["loss_pct"], d["increase_ms"], d["grade"], d["reason"]) == (8.3, 35.0, "B", None)
    assert d["warning"] == "some probes were lost under load"
    assert (q["bufferbloat"]["grade"], q["bufferbloat"]["warning"]) == ("B", "some probes were lost under load")


def test_too_few_sent_wins_over_loss_and_too_few_replies_is_not_graded():
    d = _build(download=[None] * 9)["windows"]["download"]
    assert (d["grade"], d["reason"]) == (None, "phase too short to grade")
    d = _build(download=[20.0] * 7 + [None] * 5)["windows"]["download"]          # 41.7 % loss, 7 replies
    assert (d["grade"], d["reason"], d["increase_ms"]) == (None, "phase too short to grade", None)


def test_skipped_slots_are_not_sent_and_warn_when_frequent():
    d = _build(download=[20.0] * 12 + ["skip"] * 2)["windows"]["download"]       # 2 of 14 slots
    assert (d["sent"], d["skipped"], d["loss_pct"], d["grade"]) == (12, 2, 0.0, "A")
    assert d["warning"] == "probes were delayed, so loss may be under-counted"
    assert _build(download=[20.0] * 12 + ["skip"])["windows"]["download"]["warning"] is None      # 1 of 13
    both = _build(download=[45.0] * 11 + [None] + ["skip"] * 2)["windows"]["download"]
    assert both["warning"] == "some probes were lost under load; probes were delayed, so loss may be under-counted"


def test_windows_follow_dispatch_time_and_drop_the_settle():
    samples = _samples(0.0, [10.0] * 30)
    samples += _samples(10.0, [900.0] * 10)       # the first second of the download is its settle
    samples += _samples(11.0, [20.0] * 89)        # 11.0 .. 19.8
    samples.append((19.95, False, None))          # sent just before the download ended; timed out during the upload
    samples += _samples(20.0, [700.0] * 10)       # the upload's settle
    samples += _samples(21.0, [60.0] * 20)
    q = quality.build_quality(samples, PHASES, target="1.1.1.1", interval_ms=100, payload=32)
    d, u = q["windows"]["download"], q["windows"]["upload"]
    assert (d["sent"], d["received"], d["max_ms"], d["loss_pct"]) == (90, 89, 20.0, 1.1)
    assert (u["sent"], u["received"], u["max_ms"]) == (20, 20, 60.0)
    # a short phase drops 25 % of itself: 0.5 s of a 2 s download
    short = dict(PHASES, download=(10.0, 12.0), upload=(12.0, 20.0))
    picked = quality.build_quality([(10.4, True, 500.0), (10.5, True, 20.0), (11.99, True, 20.0), (12.0, True, 500.0)],
                                   short, target="1.1.1.1", interval_ms=100, payload=32)["windows"]
    assert (picked["download"]["sent"], picked["download"]["max_ms"], picked["upload"]["sent"]) == (2, 20.0, 0)
    # a phase that never ran has no window
    assert quality.build_quality([], {"baseline": (0.0, 3.0)}, target="1.1.1.1", interval_ms=100,
                                 payload=32)["windows"]["download"] is None


def test_unanswered_baseline_makes_the_result_unavailable_but_keeps_the_windows():
    q = _build(baseline=[10.0] * 14 + [None] * 16, download=[40.0] * 20, upload=[40.0] * 20)
    assert (q["available"], q["reason"], q["bufferbloat"], q["call"]) == (False, "1.1.1.1 did not answer pings", None,
                                                                           None)
    assert q["windows"]["baseline"]["received"] == 14 and q["windows"]["download"]["sent"] == 20
    assert all(q["windows"]["download"][k] is None for k in quality.LOADED_EXTRA_KEYS)
    assert _build(baseline=[10.0] * 15 + [None] * 15, download=[40.0] * 20)["available"] is True    # exactly half
    assert _build(baseline=[None] * 30, target="192.0.2.53")["reason"] == "192.0.2.53 did not answer pings"
    empty = quality.build_quality([], {}, target="1.1.1.1", interval_ms=100, payload=32)
    assert (empty["available"], empty["reason"]) == (False, "idle latency could not be measured")
    assert empty["windows"] == {"baseline": quality.window_stats([]), "download": None, "upload": None}


def test_the_worse_direction_decides_the_grade_and_the_busy_call_estimate():
    q = _build(download=[30.0] * 20, upload=[100.0] * 33 + [None])
    d, u = q["windows"]["download"], q["windows"]["upload"]
    assert (d["increase_ms"], d["grade"]) == (20.0, "A")
    assert (u["increase_ms"], u["grade"], u["loss_pct"], u["warning"]) == (90.0, "C", 2.9, None)
    assert q["bufferbloat"] == {"grade": "C", "increase_ms": 90.0, "direction": "upload",
                                "text": "Bufferbloat: calls and games may lag while someone uploads or downloads",
                                "warning": None, "reason": None}
    call = q["call"]
    assert call["idle"] == quality.call_quality(10.0, 0.0, 0.0)
    assert call["loaded"] == dict(quality.call_quality(100.0, 0.0, 2.9), direction="upload")
    assert call["checks"] == [
        {"key": "zoom", "ok": False, "detail": "loss 2.9% is above 2% (while uploading)"},
        {"key": "teams", "ok": False, "detail": "latency 100 ms is not below 100 ms; loss 2.9% is not below 1% "
                                                "(while uploading)"},
    ]


def test_checks_fall_back_to_the_idle_baseline():
    q = _build(download=[20.0] * 5)
    assert q["call"]["loaded"] is None
    assert q["call"]["checks"] == [
        {"key": "zoom", "ok": True, "detail": "latency 10 ms, jitter 0 ms, loss 0% (idle)"},
        {"key": "teams", "ok": True, "detail": "latency 10 ms, jitter 0 ms, loss 0% (idle)"},
    ]


def test_equal_grades_and_warnings_of_the_other_direction():
    q = _build(download=[500.0] * 20, upload=[None] * 20)
    assert (q["bufferbloat"]["grade"], q["bufferbloat"]["direction"]) == ("F", "upload")     # a stall is the worst F
    q = _build(download=[90.0] * 20, upload=[80.0] * 20)
    assert (q["bufferbloat"]["grade"], q["bufferbloat"]["direction"], q["bufferbloat"]["increase_ms"]) == \
        ("C", "download", 80.0)
    q = _build(download=[45.0] * 11 + [None], upload=[110.0] * 20)
    assert q["bufferbloat"]["direction"] == "upload"
    assert q["bufferbloat"]["warning"] == "some probes were lost under load"


# --------------------------------------------------------------------------- the probe

def test_pool_sizing_default_and_too_small_pool():
    fake = ScriptedPinger()
    assert quality.LoadLatencyProbe(fake).max_inflight == 11
    assert quality.LoadLatencyProbe(fake, interval_ms=20, timeout_ms=200).max_inflight == 11
    assert quality.LoadLatencyProbe(fake, interval_ms=200, timeout_ms=1000).max_inflight == 6
    assert quality.LoadLatencyProbe(fake, max_inflight=11).max_inflight == 11
    with pytest.raises(ValueError, match="too small"):
        quality.LoadLatencyProbe(fake, max_inflight=10)
    for bad in ({"interval_ms": 0}, {"timeout_ms": -1}, {"max_inflight": True}, {"payload": "x"}):
        with pytest.raises(ValueError):
            quality.LoadLatencyProbe(fake, **bad)


def test_a_phase_reported_again_starts_a_new_attempt_and_keeps_the_baseline():
    now = [0.0]
    probe = quality.LoadLatencyProbe(ScriptedPinger(), clock=lambda: 1000.0, perf=lambda: now[0])

    def at(ts, name, frac):
        now[0] = ts
        probe.set_phase(name, frac)

    at(0.0, "baseline", 0.0)
    at(3.0, "baseline", 1.0)
    at(3.1, "connect", 0.0)
    at(3.2, "connect", 1.0)
    at(4.0, "download", 0.0)
    at(6.0, "download", 1.0)
    at(6.5, "download", 1.0)          # the budget fraction reached 1.0 before the phase really ended
    at(6.6, "upload", 0.0)
    at(9.0, "upload", 1.0)
    assert probe.phases()["download"] == (1004.0, 1006.5)
    assert probe.phases()["upload"] == (1006.6, 1009.0)
    # the fallback backend starts over: the loaded windows of the first attempt are gone
    at(10.0, "connect", 0.0)
    at(10.5, "latency", 0.5)
    at(11.0, "download", 0.0)
    phases = probe.phases()
    assert list(phases) == ["baseline", "connect", "latency", "download"]
    assert phases["baseline"] == (1000.0, 1003.0)
    assert phases["connect"] == (1010.0, 1010.5)          # never reported 1.0: ends where the next phase started
    assert phases["download"] == (1011.0, None)


def test_scaled_time_run_counts_loss_without_skipping_slots():
    """20 ms slots, 200 ms echo timeout: the first 0.4 s every echo is lost after a full timeout. The default pool of
    timeout // interval + 1 workers keeps sending every slot, so loss stays near the true 25 %."""
    pinger = ScriptedPinger(lambda elapsed: (0.2, False, None) if elapsed < 0.4 else (0.001, True, 1.0))
    probe = quality.LoadLatencyProbe(pinger, interval_ms=20, timeout_ms=200)
    assert probe.max_inflight == 11
    probe.start()
    try:
        time.sleep(1.6)
    finally:
        probe.stop(timeout=1.0)
    stats = quality.window_stats(probe.samples())
    assert stats["skipped"] <= 1
    assert stats["sent"] >= 60
    assert abs(stats["loss_pct"] - 25.0) <= 3.0


def test_a_slot_that_finds_the_pool_full_is_skipped_not_sent():
    """3 workers and every echo held: slots keep firing but only 3 echoes go out; the rest are skipped slots, which
    count neither as sent nor as lost once the echoes come back."""
    gate = threading.Event()

    def held(elapsed):
        gate.wait(2)
        return 0.0, True, 5.0

    pinger = ScriptedPinger(held)
    probe = quality.LoadLatencyProbe(pinger, interval_ms=20, timeout_ms=50, max_inflight=3)
    probe.start()
    try:
        assert wait_until(lambda: sum(1 for s in probe.samples() if s[1] is None) >= 3, timeout=2)
        assert len(pinger.calls) == 3                          # the full pool sent nothing more
    finally:
        gate.set()
        probe.stop()
    samples = probe.samples()
    skipped = [s for s in samples if s[1] is None]
    assert all(s[2] is None for s in skipped)
    stats = quality.window_stats(samples)
    assert stats["skipped"] == len(skipped) >= 3
    assert stats["sent"] == len(samples) - len(skipped) >= 3
    assert (stats["received"], stats["loss_pct"]) == (stats["sent"], 0.0)


def test_samples_carry_the_dispatch_time():
    """An echo sent before the download ended and lost during the upload counts in the download window."""
    release = threading.Event()

    def script(elapsed):
        if elapsed < 0.05:                        # the first echo stays out until the upload has started
            release.wait(2)
            return 0.0, False, None
        return 0.0, True, 5.0

    pinger = ScriptedPinger(script)
    probe = quality.LoadLatencyProbe(pinger, interval_ms=200, timeout_ms=300)
    probe.set_phase("download", 0.0)
    time.sleep(0.4)                               # the first echo is sent well after the download's settle
    probe.start()
    try:
        assert pinger.first_call.wait(2)
        probe.set_phase("download", 1.0)          # the first echo is still out ...
        probe.set_phase("upload", 0.0)
        release.set()                             # ... and comes back lost only now, during the upload
        time.sleep(0.5)
        probe.set_phase("upload", 1.0)
    finally:
        release.set()
        probe.stop()
    samples, phases = probe.samples(), probe.phases()
    first = samples[0]
    assert first[1] is False
    assert first[0] < phases["download"][1] <= phases["upload"][0]
    windows = quality.build_quality(samples, phases, target="1.1.1.1", interval_ms=200, payload=32)["windows"]
    assert windows["download"]["sent"] - windows["download"]["received"] == 1      # the lost echo, by dispatch time
    assert windows["upload"]["sent"] >= 1 and windows["upload"]["received"] == windows["upload"]["sent"]


def test_a_real_pinger_is_never_shared_with_the_pool(monkeypatch):
    class CountingPinger:
        """Stands in for tnt.icmp.IcmpPinger."""
        made = []

        def __init__(self):
            self.pings = 0
            self.closed = 0
            self.lock = threading.Lock()
            CountingPinger.made.append(self)

        def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
            with self.lock:
                self.pings += 1
            return _Reply(True, 2.0)

        def close(self):
            self.closed += 1

    monkeypatch.setattr(icmp, "IcmpPinger", CountingPinger)
    shared = CountingPinger()
    for _ in range(3):
        probe = quality.LoadLatencyProbe(shared, interval_ms=20, timeout_ms=50)
        probe.start()
        time.sleep(0.1)
        probe.stop()
        assert probe.samples()
    private = [p for p in CountingPinger.made if p is not shared]
    assert len(private) == 3
    assert all(p.closed == 1 and p.pings >= 1 for p in private)
    assert (shared.pings, shared.closed) == (0, 0)


def test_a_test_double_is_used_as_is_and_never_closed():
    pinger = ScriptedPinger(lambda elapsed: (0.0, True, 3.0))
    probe = quality.LoadLatencyProbe(pinger, interval_ms=20, timeout_ms=100)
    probe.start()
    try:
        assert wait_until(lambda: len(pinger.calls) >= 3)
        assert "tnt-ping-bloat" in {t.name for t in threading.enumerate()}
        with pytest.raises(RuntimeError):
            probe.start()
    finally:
        probe.stop()
    probe.stop()                                          # idempotent
    assert pinger.closed == 0
    assert all(c[0] == "1.1.1.1" and c[1] == 32 and c[2] == 100 for c in pinger.calls)
    assert all(c[3].startswith("tnt-ping-bloat_") for c in pinger.calls)
    assert wait_until(lambda: not _bloat_threads())


def test_echoes_still_out_at_stop_are_lost_and_a_closer_thread_releases_the_pinger(monkeypatch):
    gate = threading.Event()

    class SlowPinger:
        """Stands in for tnt.icmp.IcmpPinger; every echo blocks until the gate opens."""
        made = []

        def __init__(self):
            self.active = 0
            self.active_at_close = None
            self.inside = threading.Event()
            self.closed = threading.Event()
            self.lock = threading.Lock()
            SlowPinger.made.append(self)

        def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
            with self.lock:
                self.active += 1
            self.inside.set()
            gate.wait(5)
            with self.lock:
                self.active -= 1
            return _Reply(False, None)

        def close(self):
            with self.lock:
                self.active_at_close = self.active
            self.closed.set()

    monkeypatch.setattr(icmp, "IcmpPinger", SlowPinger)
    probe = quality.LoadLatencyProbe(SlowPinger(), interval_ms=100, timeout_ms=200)
    try:
        probe.start()
        private = SlowPinger.made[1]
        assert private.inside.wait(2)
        probe.stop(timeout=0.0)
        assert "tnt-ping-bloat-closer" in {t.name for t in threading.enumerate()}
        assert not private.closed.is_set()                # never closed under a live echo
        counted = probe.samples()
        assert [ok for _ts, ok, _rtt in counted if ok is not None] and \
            all(ok is False for _ts, ok, _rtt in counted if ok is not None)
    finally:
        gate.set()
    assert private.closed.wait(3) and private.active_at_close == 0
    assert len(probe.samples()) == len(counted)           # an echo returning after stop() is not counted twice
    assert wait_until(lambda: not _bloat_threads())


# --------------------------------------------------------------------------- scheduler wiring

class PhasedBackend:
    """Reports connect, latency, download and upload over real time; the pinger's RTT follows the load."""

    def __init__(self, load, name="fake", rtts=None, phase_s=None, outcome="ok"):
        self.name = name
        self.load = load
        self.rtts = rtts or {"connect": 10.0, "latency": 10.0, "download": 20.0, "upload": 110.0}
        self.phase_s = phase_s or {"connect": 0.3, "latency": 0.3, "download": 0.5, "upload": 0.5}
        self.outcome = outcome
        self.calls = []

    def available(self, config):
        return True, "fake"

    def run(self, config, progress=None, cancel=None):
        self.calls.append(time.time())
        for phase in ("connect", "latency", "download", "upload"):
            self.load["rtt"] = self.rtts[phase]
            progress(phase, 0.0)
            started = time.monotonic()
            while time.monotonic() - started < self.phase_s[phase]:
                if cancel is not None and cancel.is_set():
                    return base.failed_result(self.name, time.time(), base.CANCELLED, 0.1)
                time.sleep(0.05)
                progress(phase, min(0.99, (time.monotonic() - started) / self.phase_s[phase]))
            progress(phase, 1.0)
        self.load["rtt"] = 10.0
        progress("done", 1.0)
        if self.outcome == "limited":
            return base.rate_limited_result(self.name, time.time(), 429, 3400, "upload phase refused", 1.0)
        if self.outcome == "failed":
            return SpeedResult(ok=False, ts=time.time(), backend=self.name, error="fake failure", duration_s=0.1)
        return SpeedResult(ok=True, ts=time.time(), backend=self.name, server="Fake", download_mbps=100.0,
                           upload_mbps=20.0, latency_ms=10.0, jitter_ms=1.0, duration_s=1.6)


def _fast_probe(monkeypatch):
    """The scheduler builds its probe with the defaults; 20 ms slots give a 0.5 s phase enough echoes to grade."""
    monkeypatch.setattr(sched_mod, "LoadLatencyProbe",
                        functools.partial(quality.LoadLatencyProbe, interval_ms=20, timeout_ms=200))


def _done(events):
    return next(e for e in events if e["type"] == "speedtest.done")["data"]["result"]


def test_public_signatures_and_the_probe_the_scheduler_builds(db, cfg, bus):
    """The interface of contract 6.1/6.4: keyword-only knobs with their defaults, and the scheduler's probe built with
    them toward its quality_target."""
    kw, pos, empty = inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.empty
    probe_params = inspect.signature(quality.LoadLatencyProbe).parameters
    assert [(n, p.kind, p.default) for n, p in probe_params.items()] == [
        ("pinger", pos, empty), ("target", kw, "1.1.1.1"), ("interval_ms", kw, 100), ("payload", kw, 32),
        ("timeout_ms", kw, 1000), ("max_inflight", kw, None), ("clock", kw, time.time), ("perf", kw, time.perf_counter)]
    assert inspect.signature(quality.LoadLatencyProbe.stop).parameters["timeout"].default == 2.0
    assert [(n, p.kind, p.default) for n, p in inspect.signature(quality.build_quality).parameters.items()] == [
        ("samples", pos, empty), ("phases", pos, empty), ("target", kw, empty), ("interval_ms", kw, empty),
        ("payload", kw, empty)]
    sched_params = inspect.signature(sched_mod.SpeedScheduler).parameters
    assert [(n, sched_params[n].kind, sched_params[n].default) for n in ("pinger", "quality_target", "baseline_s")] == [
        ("pinger", kw, None), ("quality_target", kw, "1.1.1.1"), ("baseline_s", kw, 3.0)]

    pinger = ScriptedPinger()
    s = sched_mod.SpeedScheduler(db, cfg, bus, pinger=pinger, quality_target="192.0.2.53")
    probe = s._start_probe()
    try:
        assert (probe.target, probe.interval_ms, probe.payload, probe.timeout_ms, probe.max_inflight) == \
            ("192.0.2.53", 100, 32, 1000, 11)
        assert list(probe.phases()) == ["baseline"]            # opened before the first echo
        assert pinger.first_call.wait(2)
    finally:
        probe.stop()
    assert pinger.calls[0][:3] == ("192.0.2.53", 32, 1000) and pinger.calls[0][3].startswith("tnt-ping-bloat_")
    assert pinger.closed == 0 and wait_until(lambda: not _bloat_threads())
    assert sched_mod.SpeedScheduler(db, cfg, bus)._start_probe() is None       # no pinger: no probe


def test_scheduler_measures_a_baseline_and_stores_quality_in_raw_and_last(db, cfg, bus, monkeypatch):
    load = {"rtt": 10.0}
    pinger = ScriptedPinger(lambda elapsed: (0.0, True, load["rtt"]))
    backend = PhasedBackend(load)
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: backend)
    _fast_probe(monkeypatch)
    events = _events(bus)
    s = sched_mod.SpeedScheduler(db, cfg, bus, clock=FakeClock(0.0), poll_s=0.01, pinger=pinger, baseline_s=0.2)
    try:
        assert s.run_now()
        assert wait_until(lambda: any(e["type"] == "speedtest.done" for e in events), timeout=10)
        assert wait_until(lambda: not s.running)
    finally:
        s.stop()
    progress = [(e["data"]["phase"], e["data"]["pct"]) for e in events if e["type"] == "speedtest.progress"]
    assert progress[0] == ("baseline", 0.0)
    assert progress.index(("baseline", 1.0)) < [p for p, _ in progress].index("connect")
    types = [e["type"] for e in events]
    assert types.index("speedtest.start") < types.index("speedtest.progress")
    result = _done(events)
    q = result["quality"]
    assert q is not None and result["raw"]["quality"] == q
    assert list(q) == list(quality.QUALITY_KEYS) and q["available"] is True
    assert (q["target"], q["interval_ms"], q["payload_bytes"]) == ("1.1.1.1", 20, 32)
    w = q["windows"]
    assert w["baseline"]["received"] >= 5 and w["baseline"]["median_ms"] == 10.0
    assert w["download"]["sent"] >= 10 and w["download"]["grade"] == "A"
    assert w["upload"]["sent"] >= 10 and w["upload"]["grade"] == "C"
    assert (q["bufferbloat"]["grade"], q["bufferbloat"]["direction"]) == ("C", "upload")
    assert q["call"]["loaded"]["direction"] == "upload" and q["call"]["idle"]["label"] == "Excellent"
    # persisted inside raw_json and restored as last["quality"], also after a restart
    assert json.loads(db.last_speedtest()["raw_json"])["quality"] == q
    assert s.status()["last"]["quality"] == q
    restored = sched_mod.SpeedScheduler(db, cfg, bus)._load_last()
    assert restored["quality"] == q and restored["raw"]["quality"] == q
    assert "quality" not in db.list_speedtests(0, 2e9)[0]
    assert pinger.closed == 0 and all(c[0] == "1.1.1.1" and c[1] == 32 for c in pinger.calls)
    assert wait_until(lambda: not _bloat_threads())


def test_scheduler_fallback_retry_reuses_the_baseline_and_restarts_the_loaded_windows(db, cfg, bus, monkeypatch):
    load = {"rtt": 10.0}
    pinger = ScriptedPinger(lambda elapsed: (0.0, True, load["rtt"]))
    limited = PhasedBackend(load, name="cf", outcome="limited", rtts={"connect": 10.0, "latency": 10.0,
                                                                     "download": 900.0, "upload": 900.0},
                            phase_s={"connect": 0.05, "latency": 0.05, "download": 0.3, "upload": 0.3})
    other = PhasedBackend(load)
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: limited)
    monkeypatch.setattr(sched_mod, "alternative_backend", lambda c, exclude=(): other)
    _fast_probe(monkeypatch)
    events = _events(bus)
    s = sched_mod.SpeedScheduler(db, cfg, bus, clock=FakeClock(0.0), poll_s=0.01, pinger=pinger, baseline_s=0.2)
    try:
        assert s.run_now()
        assert wait_until(lambda: any(e["type"] == "speedtest.done" for e in events), timeout=10)
        assert wait_until(lambda: not s.running)
    finally:
        s.stop()
    assert len(limited.calls) == 1 and len(other.calls) == 1
    progress = [(e["data"]["phase"], e["data"]["pct"]) for e in events if e["type"] == "speedtest.progress"]
    assert progress.count(("baseline", 0.0)) == 1 and progress.count(("baseline", 1.0)) == 1
    result = _done(events)
    assert result["ok"] is True and result["backend"] == "fake"
    q = result["quality"]
    assert q["available"] is True and q["windows"]["download"]["max_ms"] < 900.0
    assert (q["windows"]["download"]["grade"], q["windows"]["upload"]["grade"]) == ("A", "C")
    assert result["raw"]["rate_limited_attempts"][0]["backend"] == "cf"


def test_scheduler_cancel_during_the_baseline_runs_no_backend_and_stores_nothing(db, cfg, bus, monkeypatch):
    pinger = ScriptedPinger()
    backend = PhasedBackend({"rtt": 10.0})
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: backend)
    events = _events(bus)
    s = sched_mod.SpeedScheduler(db, cfg, bus, clock=FakeClock(0.0), poll_s=0.01, pinger=pinger, baseline_s=30.0)
    try:
        assert s.run_now()
        assert wait_until(lambda: s.progress["phase"] == "baseline" and pinger.calls)
        t0 = time.perf_counter()
        assert s.cancel_current()
        assert wait_until(lambda: not s.running, timeout=3)
        assert time.perf_counter() - t0 < 2.0
    finally:
        s.stop()
    result = _done(events)
    assert (result["error"], result["quality"], result["raw"]["quality"]) == ("cancelled", None, None)
    assert backend.calls == [] and db.list_speedtests(0, 2e9) == []
    assert wait_until(lambda: not _bloat_threads())


def test_scheduler_stores_no_quality_for_a_failed_run_or_without_a_pinger(db, cfg, bus, monkeypatch):
    quick = {"connect": 0.0, "latency": 0.0, "download": 0.0, "upload": 0.0}
    failing = PhasedBackend({"rtt": 10.0}, phase_s=quick, outcome="failed")
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: failing)
    events = _events(bus)
    s = sched_mod.SpeedScheduler(db, cfg, bus, clock=FakeClock(0.0), poll_s=0.01, pinger=ScriptedPinger(),
                                 baseline_s=0.05)
    try:
        assert s.run_now()
        assert wait_until(lambda: not s.running and s.last_result is not None)
    finally:
        s.stop()
    result = _done(events)
    assert result["ok"] is False and result["quality"] is None and result["raw"]["quality"] is None
    assert s.status()["last"]["quality"] is None
    assert json.loads(db.last_speedtest()["raw_json"]) == {"quality": None}

    # no pinger: no probe, no baseline phase, nothing added to raw (older rows restore quality as None)
    events.clear()
    ok = PhasedBackend({"rtt": 10.0}, phase_s=quick)
    monkeypatch.setattr(sched_mod, "select_backend", lambda c: ok)
    plain = sched_mod.SpeedScheduler(db, cfg, bus, clock=FakeClock(0.0), poll_s=0.01)
    try:
        assert plain.run_now()
        assert wait_until(lambda: not plain.running and plain.last_result is not None and plain.last_result["ok"])
    finally:
        plain.stop()
    progress = [e["data"]["phase"] for e in events if e["type"] == "speedtest.progress"]
    assert progress and "baseline" not in progress
    result = _done(events)
    assert result["quality"] is None and "quality" not in result["raw"]
    assert sched_mod.SpeedScheduler(db, cfg, bus)._load_last()["quality"] is None
