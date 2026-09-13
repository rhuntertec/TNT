"""Latency under load and a call-quality estimate for every speed test (ARCHITECTURE 3.6).

While a speed test runs, :class:`LoadLatencyProbe` sends small ICMP echoes (32 bytes every
100 ms) to one internet host, 1.1.1.1 by default. Echoes to 1.1.1.1 cross both places where a
busy line queues packets (the router's WAN egress and the ISP's shaper) and are answered by a
destination host, so their round-trip time rises when those queues fill; echoes to the default
gateway never cross them. :class:`tnt.speedtest.scheduler.SpeedScheduler` starts the probe,
measures an idle baseline before the backend runs and hands the probe every raw progress call,
so each echo lands in the window it was sent in.

Probe mechanics
---------------
* A real :class:`tnt.icmp.IcmpPinger` is never used from the probe's pool threads: it keeps one
  ICMP handle per thread and releases them only in ``close()``, so the fresh pool threads of
  every test would leak handles into the service's shared pinger (``DiscoveryScanner._get_pinger``
  avoids the same leak). :meth:`LoadLatencyProbe.start` creates a private ``IcmpPinger`` for the
  run and :meth:`LoadLatencyProbe.stop` closes it. Any other injected object (a test double) is
  used as-is and never closed.
* Echoes run on a ``ThreadPoolExecutor`` of ``max_inflight`` workers named ``tnt-ping-bloat_N``
  (the Engine closes its ICMP handle only when no ``tnt-ping-*`` thread is alive).
  ``max_inflight`` defaults to ``timeout_ms // interval_ms + 1`` (11 at 100/1000): an echo that
  times out holds its worker slightly longer than ``timeout_ms``, so one worker fewer would skip
  slots under sustained loss. A pool with ``max_inflight * interval_ms <= timeout_ms`` is refused
  with ValueError.
* The dispatcher thread ``tnt-ping-bloat`` fires on slots aligned to ``interval_ms``. A slot that
  finds every worker busy is recorded as *skipped* and counts neither as sent nor as lost. When
  the dispatcher itself falls a whole interval behind (a stalled process) it skips forward to the
  next aligned slot; the moments it missed are not slots.
* A sample is ``(dispatch_wall_ts, ok, rtt_ms)`` and a skipped slot is ``(slot_wall_ts, None,
  None)``. The timestamp is when the slot fired, not when the echo came back, so an echo sent
  just before the download ended counts in the download window even when it times out during the
  upload. Samples and phase marks share one clock: the wall clock read once when the probe is
  built plus ``perf_counter`` time since then (``time.time()`` moves in 15.6 ms steps on Windows
  before Python 3.13, and a clock step during the test cannot reorder samples and phases).
* :meth:`LoadLatencyProbe.stop` stops the dispatcher, shuts the pool down without waiting (queued
  echoes are cancelled), waits up to *timeout* for the echoes still in flight, records every
  unfinished echo as lost with its dispatch time and closes the private pinger. When echoes are
  still inside ``IcmpSendEcho2`` a daemon thread ``tnt-ping-bloat-closer`` waits for them and
  closes it afterwards: closing a handle under a live call is a use-after-free that ctypes cannot
  catch.

Windows and grading (:func:`build_quality`)
-------------------------------------------
* ``baseline`` is the idle window measured before the backend starts. ``download`` and ``upload``
  run from the phase's first raw progress call (``(phase, 0.0)``) to its last ``(phase, 1.0)``,
  minus a settle of ``min(1.0 s, 25 % of the phase)`` at the start (connection ramp-up, and the
  download draining into the start of the upload). Windows are half-open ``[start, end)``. A
  phase that never reported 1.0 ends where the next phase started. A phase reported again after
  another phase started begins a new attempt (the scheduler's fallback retry): the old entry and
  every phase recorded after it are dropped, so the loaded windows start over and the baseline is
  kept.
* :func:`window_stats`: ``loss_pct`` = lost / sent (skipped slots are neither), ``median_ms``
  (``statistics.median``), ``mean_ms``, ``p95_ms`` (nearest rank) and ``max_ms`` over the replies,
  ``jitter_ms`` = mean absolute difference of consecutive replies in dispatch order (None below 2
  replies). A reply without an RTT counts as lost. ms values and ``loss_pct`` are rounded to 1
  decimal, and grading uses the rounded values (what the page shows).
* Baseline check: when fewer than half of the idle echoes were answered, ICMP to the target is
  blocked or policed, which says nothing about the line: ``available`` is False with reason
  ``"<target> did not answer pings"``, the windows are kept (the loaded ones with every extra key
  None), ``bufferbloat`` and ``call`` are None. An empty baseline (nothing was sent) gives
  :data:`REASON_NO_BASELINE` instead.
* Per loaded direction, in order: fewer than 10 sent: not graded ("phase too short to grade");
  loss >= 50 %: F ("most probes were lost under load"; ``increase_ms`` from the replies when there
  are any); fewer than 8 replies: not graded; otherwise ``increase_ms = max(0, mean_ms - baseline
  median_ms)`` graded by :func:`bloat_grade`, with the warning "some probes were lost under load"
  at 5 % <= loss < 50 %. More than 10 % of a loaded window's slots skipped adds "probes were
  delayed, so loss may be under-counted" (two warnings are joined with "; ").
* ``bufferbloat`` is the worse graded direction (on equal grades the larger increase, an F without
  replies counting as the largest), with its warnings first and the other direction's after.
  ``grade`` is None when neither direction is graded, and ``reason`` then says why.
* ``call``: :func:`call_quality` is a simplified E-model on round-trip time to the target, not on
  a call's media path, so the method says it is an estimate. ``idle`` comes from the baseline and
  ``loaded`` from the worse loaded window (lower R) with at least 10 sent. The ``zoom`` (mean <=
  150 ms, jitter <= 40 ms, loss <= 2 %) and ``teams`` (mean < 100 ms, jitter < 30 ms, loss < 1 %)
  checks use that window, or the baseline when there is none; the detail names the window
  ("idle", "while downloading", "while uploading").

Shapes::

    QUALITY     {"version": 1, "available", "reason", "target", "interval_ms", "payload_bytes",
                 "windows": {"baseline": WINDOW, "download": LOADED | None, "upload": LOADED | None},
                 "bufferbloat": BUFFERBLOAT | None, "call": CALL | None}
    WINDOW      {"sent", "received", "skipped", "loss_pct", "median_ms", "mean_ms", "p95_ms", "max_ms",
                 "jitter_ms"}
    LOADED      WINDOW + {"increase_ms", "grade", "reason", "warning"}
    BUFFERBLOAT {"grade", "increase_ms", "direction", "text", "warning", "reason"}
    CALL        {"method", "idle": SCORE, "loaded": SCORE + {"direction"} | None,
                 "checks": [{"key", "ok", "detail"}]}
    SCORE       {"r", "mos", "label"}
"""
from __future__ import annotations

import importlib
import logging
import math
import statistics
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

log = logging.getLogger(__name__)

__all__ = [
    "BUFFERBLOAT_KEYS", "CALL_KEYS", "CHECK_KEYS", "GRADES", "GRADE_TEXT", "LOADED_EXTRA_KEYS", "QUALITY_KEYS",
    "SCORE_KEYS", "WINDOW_KEYS", "LoadLatencyProbe", "bloat_grade", "build_quality", "call_quality", "window_stats",
]

QUALITY_VERSION = 1
QUALITY_KEYS = ("version", "available", "reason", "target", "interval_ms", "payload_bytes", "windows", "bufferbloat",
                "call")
WINDOW_KEYS = ("sent", "received", "skipped", "loss_pct", "median_ms", "mean_ms", "p95_ms", "max_ms", "jitter_ms")
#: Appended to the "download" and "upload" windows.
LOADED_EXTRA_KEYS = ("increase_ms", "grade", "reason", "warning")
BUFFERBLOAT_KEYS = ("grade", "increase_ms", "direction", "text", "warning", "reason")
CALL_KEYS = ("method", "idle", "loaded", "checks")
SCORE_KEYS = ("r", "mos", "label")
CHECK_KEYS = ("key", "ok", "detail")
BASELINE_PHASE = "baseline"
#: The progress phases whose windows are graded, in the order the backends run them.
LOADED_PHASES = ("download", "upload")

DEFAULT_TARGET = "1.1.1.1"
DEFAULT_INTERVAL_MS = 100
DEFAULT_PAYLOAD = 32
DEFAULT_TIMEOUT_MS = 1000
THREAD_NAME = "tnt-ping-bloat"
CLOSER_THREAD_NAME = "tnt-ping-bloat-closer"

SETTLE_MAX_S = 1.0             # a loaded window drops min(SETTLE_MAX_S, SETTLE_FRACTION x phase) at its start
SETTLE_FRACTION = 0.25
MIN_SENT = 10                  # a loaded window needs this many echoes sent to be graded at all ...
MIN_RECEIVED = 8               # ... and this many replies to be graded on latency
MOST_LOST_PCT = 50.0           # loss at or above this under load is an F
SOME_LOST_PCT = 5.0            # loss at or above this (and below MOST_LOST_PCT) keeps the grade with a warning
SKIPPED_WARN_SHARE = 0.10      # more than this share of a loaded window's slots skipped: loss may be under-counted
BASELINE_MIN_ANSWERED = 0.5    # an idle baseline with a smaller share of answered echoes is not usable

GRADES = ("A+", "A", "B", "C", "D", "F")
#: Exclusive upper bounds of the increase under load (ms): a value on a boundary gets the worse grade.
_GRADE_BOUNDS = ((5.0, "A+"), (30.0, "A"), (60.0, "B"), (200.0, "C"), (400.0, "D"))
GRADE_TEXT: Dict[str, str] = {
    "A+": "No bufferbloat: latency stays flat while the line is busy",
    "A": "Excellent: calls and games are unaffected by heavy use",
    "B": "Good: small delay spikes while the line is busy",
    "C": "Bufferbloat: calls and games may lag while someone uploads or downloads",
    "D": "Severe bufferbloat: calls will break up while the line is busy",
    "F": "Unusable under load: the connection stalls when it is busy",
}

REASON_TOO_SHORT = "phase too short to grade"
REASON_MOST_LOST = "most probes were lost under load"
#: ``REASON_NO_REPLIES.format(target=...)``: "1.1.1.1 did not answer pings" for the default target.
REASON_NO_REPLIES = "{target} did not answer pings"
REASON_NO_BASELINE = "idle latency could not be measured"
WARNING_SOME_LOST = "some probes were lost under load"
WARNING_DELAYED = "probes were delayed, so loss may be under-counted"

CALL_METHOD = "estimate (simplified E-model)"
#: Inclusive lower bounds of R per label; below the last one the label is :data:`CALL_LABEL_WORST`.
_CALL_LABELS = ((90.0, "Excellent"), (80.0, "Good"), (70.0, "Fair"), (60.0, "Poor"), (50.0, "Bad"))
CALL_LABEL_WORST = "Unusable"
#: ``(key, mean ms, jitter ms, loss %, inclusive)``: Zoom publishes "or less" limits, the Teams network
#: targets are "under" limits.
CALL_CHECKS = (("zoom", 150.0, 40.0, 2.0, True), ("teams", 100.0, 30.0, 1.0, False))
_SCOPE = {BASELINE_PHASE: "idle", "download": "while downloading", "upload": "while uploading"}

#: ``(dispatch_wall_ts, ok, rtt_ms)``; ``ok is None`` marks a skipped slot.
Sample = Tuple[float, Optional[bool], Optional[float]]


# --------------------------------------------------------------------------- statistics and grades

def _round1(value: Optional[float]) -> Optional[float]:
    return None if value is None else round(float(value), 1)


def _num(value: float) -> str:
    """``12.0`` -> ``"12"``, ``2.94`` -> ``"2.9"`` (one decimal, no trailing ``.0``)."""
    text = f"{float(value):.1f}"
    return text[:-2] if text.endswith(".0") else text


def window_stats(samples: Sequence[Sample]) -> Dict[str, Any]:
    """WINDOW statistics over *samples* (see module docstring); an empty window has ``sent == 0`` and None values."""
    ordered = sorted(samples, key=lambda s: float(s[0]))
    skipped = sum(1 for s in ordered if s[1] is None)
    sent = len(ordered) - skipped
    rtts = [float(s[2]) for s in ordered if s[1] is not None and s[1] and s[2] is not None]
    received = len(rtts)
    out: Dict[str, Any] = dict.fromkeys(WINDOW_KEYS)
    out.update(sent=sent, received=received, skipped=skipped)
    if sent:
        out["loss_pct"] = _round1(100.0 * (sent - received) / sent)
    if rtts:
        ranked = sorted(rtts)
        rank = (95 * len(ranked) + 99) // 100             # nearest rank: ceil(0.95 * n), in integers
        out.update(median_ms=_round1(statistics.median(rtts)), mean_ms=_round1(statistics.fmean(rtts)),
                   p95_ms=_round1(ranked[rank - 1]), max_ms=_round1(ranked[-1]))
    if received >= 2:
        out["jitter_ms"] = _round1(sum(abs(b - a) for a, b in zip(rtts, rtts[1:])) / (received - 1))
    return out


def bloat_grade(increase_ms: Optional[float]) -> Optional[str]:
    """Bufferbloat grade for the latency increase under load (ms): <5 A+, <30 A, <60 B, <200 C, <400 D, else F.
    None for None."""
    if increase_ms is None:
        return None
    value = float(increase_ms)
    for bound, grade in _GRADE_BOUNDS:
        if value < bound:
            return grade
    return "F"


def _call_label(r: float) -> str:
    for bound, label in _CALL_LABELS:
        if r >= bound:
            return label
    return CALL_LABEL_WORST


def call_quality(mean_ms: Optional[float], jitter_ms: Optional[float], loss_pct: Optional[float]) -> Dict[str, Any]:
    """Simplified E-model: ``{"r", "mos", "label"}`` for a latency, jitter (ms) and loss (%).

    A missing value counts as 0.

    ``Leff = L + 2J + 10``; ``R = 93.2 - Leff/40`` below 160, else ``93.2 - (Leff-120)/10``; minus 2.5 per percent
    of loss, clamped to 0..100; ``MOS = 1 + 0.035R + 7e-6 R(R-60)(100-R)``, never below 1 (the bottom of the MOS
    scale: the cubic term dips to about 0.99 for R between 0 and 6.5). R and MOS are rounded to 2 decimals and the
    label follows the rounded R.
    """
    latency = max(0.0, float(mean_ms or 0.0))
    jitter = max(0.0, float(jitter_ms or 0.0))
    loss = max(0.0, float(loss_pct or 0.0))
    leff = latency + 2.0 * jitter + 10.0
    r = 93.2 - leff / 40.0 if leff < 160.0 else 93.2 - (leff - 120.0) / 10.0
    r = max(0.0, min(100.0, r - 2.5 * loss))
    mos = max(1.0, 1.0 + 0.035 * r + 7e-6 * r * (r - 60.0) * (100.0 - r))
    r = round(r, 2)
    return {"r": r, "mos": round(mos, 2), "label": _call_label(r)}


def _checks(window: Dict[str, Any], scope: str) -> List[Dict[str, Any]]:
    """The Zoom and Teams checks on *window*; a missing mean or jitter counts as 0."""
    mean = float(window.get("mean_ms") or 0.0)
    jitter = float(window.get("jitter_ms") or 0.0)
    loss = float(window.get("loss_pct") or 0.0)
    checks: List[Dict[str, Any]] = []
    for key, max_mean, max_jitter, max_loss, inclusive in CALL_CHECKS:
        verb = "is above" if inclusive else "is not below"
        failures = [f"{what} {_num(value)}{unit} {verb} {_num(limit)}{unit}"
                    for what, value, limit, unit in (("latency", mean, max_mean, " ms"),
                                                     ("jitter", jitter, max_jitter, " ms"),
                                                     ("loss", loss, max_loss, "%"))
                    if (value > limit if inclusive else value >= limit)]
        detail = "; ".join(failures) if failures else \
            f"latency {_num(mean)} ms, jitter {_num(jitter)} ms, loss {_num(loss)}%"
        checks.append({"key": key, "ok": not failures, "detail": f"{detail} ({scope})"})
    return checks


def _grade_loaded(stats: Dict[str, Any], baseline_median: Optional[float]) -> Dict[str, Any]:
    """A loaded WINDOW plus its grade (see the rule order in the module docstring)."""
    window = dict(stats)
    window.update(dict.fromkeys(LOADED_EXTRA_KEYS))
    sent, received, skipped, loss = stats["sent"], stats["received"], stats["skipped"], stats["loss_pct"]
    increase = None
    if stats["mean_ms"] is not None and baseline_median is not None:
        increase = _round1(max(0.0, stats["mean_ms"] - baseline_median))
    warnings: List[str] = []
    if sent < MIN_SENT:
        window["reason"] = REASON_TOO_SHORT
    elif loss is not None and loss >= MOST_LOST_PCT:
        window.update(grade="F", reason=REASON_MOST_LOST, increase_ms=increase)
    elif received < MIN_RECEIVED:
        window["reason"] = REASON_TOO_SHORT
    else:
        window.update(increase_ms=increase, grade=bloat_grade(increase))
        if loss is not None and SOME_LOST_PCT <= loss < MOST_LOST_PCT:
            warnings.append(WARNING_SOME_LOST)
    if skipped and skipped > SKIPPED_WARN_SHARE * (sent + skipped):
        warnings.append(WARNING_DELAYED)
    window["warning"] = "; ".join(warnings) or None
    return window


def _bufferbloat(loaded: Dict[str, Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    """BUFFERBLOAT: the worse graded direction, or no grade with the reason."""
    out: Dict[str, Any] = dict.fromkeys(BUFFERBLOAT_KEYS)
    graded = [(name, w) for name, w in loaded.items() if w is not None and w.get("grade") in GRADES]
    if not graded:
        reasons = [w["reason"] for w in loaded.values() if w is not None and w.get("reason")]
        out["reason"] = reasons[0] if reasons else REASON_TOO_SHORT
        return out

    def severity(item: Tuple[str, Dict[str, Any]]) -> Tuple[int, float]:
        increase = item[1].get("increase_ms")
        return GRADES.index(item[1]["grade"]), math.inf if increase is None else float(increase)

    direction, worst = max(graded, key=severity)          # ties keep the first (download)
    warnings: List[str] = []
    for _name, window in [(direction, worst)] + [g for g in graded if g[0] != direction]:
        for text in str(window.get("warning") or "").split("; "):
            if text and text not in warnings:
                warnings.append(text)
    out.update(grade=worst["grade"], increase_ms=worst.get("increase_ms"), direction=direction,
               text=GRADE_TEXT[worst["grade"]], warning="; ".join(warnings) or None)
    return out


def _call(baseline: Dict[str, Any], loaded: Dict[str, Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    """CALL: idle from the baseline; loaded and the checks from the worse loaded window with enough echoes sent."""
    idle = call_quality(baseline.get("mean_ms"), baseline.get("jitter_ms"), baseline.get("loss_pct"))
    worst: Optional[Tuple[str, Dict[str, Any], Dict[str, Any]]] = None
    for name, window in loaded.items():
        if window is None or int(window.get("sent") or 0) < MIN_SENT:
            continue
        score = call_quality(window.get("mean_ms"), window.get("jitter_ms"), window.get("loss_pct"))
        if worst is None or score["r"] < worst[2]["r"]:
            worst = (name, window, score)
    if worst is None:
        return {"method": CALL_METHOD, "idle": idle, "loaded": None,
                "checks": _checks(baseline, _SCOPE[BASELINE_PHASE])}
    name, window, score = worst
    return {"method": CALL_METHOD, "idle": idle, "loaded": dict(score, direction=name),
            "checks": _checks(window, _SCOPE[name])}


def _span(phases: Any, name: str) -> Optional[Tuple[float, float]]:
    """``(start, end)`` of *name* in *phases* (``{name: (start, end|None)}``); an open end is +inf."""
    entry = phases.get(name) if isinstance(phases, dict) else None
    if not entry or entry[0] is None:
        return None
    end = entry[1] if len(entry) > 1 else None
    return float(entry[0]), (math.inf if end is None else float(end))


def _split_windows(samples: Sequence[Sample], phases: Any) -> Dict[str, Optional[List[Sample]]]:
    """Samples per window by dispatch time: ``{"baseline": [...], "download": [...] | None, "upload": [...] | None}``
    (a loaded window is None when its phase never ran)."""
    spans: Dict[str, Tuple[float, float]] = {}
    baseline = _span(phases, BASELINE_PHASE)
    if baseline is not None:
        spans[BASELINE_PHASE] = baseline
    for name in LOADED_PHASES:
        span = _span(phases, name)
        if span is None:
            continue
        start, end = span
        settle = min(SETTLE_MAX_S, SETTLE_FRACTION * (end - start)) if math.isfinite(end) else SETTLE_MAX_S
        spans[name] = (start + max(0.0, settle), end)
    buckets: Dict[str, List[Sample]] = {name: [] for name in spans}
    for sample in samples:
        ts = float(sample[0])
        for name, (lo, hi) in spans.items():
            if lo <= ts < hi:
                buckets[name].append(sample)
                break
    out: Dict[str, Optional[List[Sample]]] = {BASELINE_PHASE: buckets.get(BASELINE_PHASE, [])}
    for name in LOADED_PHASES:
        out[name] = buckets.get(name)
    return out


def build_quality(samples: Sequence[Sample], phases: Any, *, target: str, interval_ms: int,
                  payload: int) -> Dict[str, Any]:
    """QUALITY from a probe's :meth:`~LoadLatencyProbe.samples` and :meth:`~LoadLatencyProbe.phases`
    (``{name: (start_ts, end_ts|None)}``) and the probe's settings; see the module docstring for the windows and
    the grading."""
    split = _split_windows(samples, phases)
    baseline = window_stats(split[BASELINE_PHASE] or [])
    reason: Optional[str] = None
    if not baseline["sent"]:
        reason = REASON_NO_BASELINE
    elif baseline["received"] < BASELINE_MIN_ANSWERED * baseline["sent"]:
        reason = REASON_NO_REPLIES.format(target=target)
    windows: Dict[str, Optional[Dict[str, Any]]] = {BASELINE_PHASE: baseline}
    for name in LOADED_PHASES:
        chunk = split[name]
        if chunk is None:
            windows[name] = None
        elif reason is None:
            windows[name] = _grade_loaded(window_stats(chunk), baseline["median_ms"])
        else:
            windows[name] = {**window_stats(chunk), **dict.fromkeys(LOADED_EXTRA_KEYS)}
    quality: Dict[str, Any] = dict.fromkeys(QUALITY_KEYS)
    quality.update(version=QUALITY_VERSION, available=reason is None, reason=reason, target=str(target),
                   interval_ms=int(interval_ms), payload_bytes=int(payload), windows=windows)
    if reason is None:
        loaded = {name: windows[name] for name in LOADED_PHASES}
        quality["bufferbloat"] = _bufferbloat(loaded)
        quality["call"] = _call(baseline, loaded)
    return quality


# --------------------------------------------------------------------------- the probe

def _int_at_least(name: str, value: Any, lo: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer of at least {lo}")
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{name} must be an integer of at least {lo}") from None
    if number < lo:
        raise ValueError(f"{name} must be an integer of at least {lo}")
    return number


def _close_pinger(pinger: Any) -> None:
    try:
        pinger.close()
    except Exception:  # noqa: BLE001
        log.debug("pinger close failed", exc_info=True)


def _close_when_quiet(thread: Optional[threading.Thread], executor: ThreadPoolExecutor, pinger: Any) -> None:
    """Closer thread: waits for the dispatcher and every pool worker to finish, then closes the private pinger."""
    try:
        if thread is not None:
            thread.join()
        executor.shutdown(wait=True)          # joins the pool threads (each is bounded by one echo timeout)
    except Exception:  # noqa: BLE001
        log.debug("load latency probe pool shutdown failed", exc_info=True)
    _close_pinger(pinger)
    log.debug("load latency probe: straggling echoes finished; ICMP handles released")


class LoadLatencyProbe:
    """ICMP echoes to one target on aligned slots while a speed test runs (see module docstring).

    One probe measures one run: :meth:`start` once, :meth:`set_phase` for every raw progress call,
    :meth:`stop`, then :meth:`samples` and :meth:`phases` for :func:`build_quality`. ``clock`` (the wall
    clock) is read once, when the probe is built; ``perf`` times the slots and every timestamp after that.
    """

    #: Longest single sleep of the dispatcher, so stop() is noticed quickly.
    WAKE_S = 0.05
    #: How long stop() waits for the dispatcher thread to exit.
    DISPATCHER_JOIN_S = 0.5

    def __init__(self, pinger: Any, *, target: str = DEFAULT_TARGET, interval_ms: int = DEFAULT_INTERVAL_MS,
                 payload: int = DEFAULT_PAYLOAD, timeout_ms: int = DEFAULT_TIMEOUT_MS,
                 max_inflight: Optional[int] = None, clock: Callable[[], float] = time.time,
                 perf: Callable[[], float] = time.perf_counter) -> None:
        interval_ms = _int_at_least("interval_ms", interval_ms, 1)
        timeout_ms = _int_at_least("timeout_ms", timeout_ms, 1)
        inflight = (timeout_ms // interval_ms + 1 if max_inflight is None
                    else _int_at_least("max_inflight", max_inflight, 1))
        if inflight * interval_ms <= timeout_ms:
            raise ValueError(f"max_inflight {inflight} is too small: {inflight} x {interval_ms} ms must be more than "
                             f"the {timeout_ms} ms echo timeout")
        self.target = str(target)
        self.interval_ms = interval_ms
        self.timeout_ms = timeout_ms
        self.payload = _int_at_least("payload", payload, 0)
        self.max_inflight = inflight
        self._injected = pinger
        self._perf = perf
        self._wall0 = float(clock())
        self._perf0 = float(perf())
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._started = False
        self._samples: List[Sample] = []
        self._phases: List[List[Any]] = []       # [name, start_ts, end_ts|None] in the order the phases started
        self._pending: Dict[int, float] = {}     # echo number -> dispatch ts, until its result is recorded
        self._futures: Set[Future] = set()
        self._seq = 0
        self._thread: Optional[threading.Thread] = None
        self._executor: Optional[ThreadPoolExecutor] = None
        self._pinger: Any = None
        self._owned = False

    def _now(self) -> float:
        """Wall-clock timestamp on the probe's one clock (see the class docstring)."""
        return self._wall0 + (float(self._perf()) - self._perf0)

    # -- lifecycle ------------------------------------------------------------
    def start(self) -> None:
        """Start the dispatcher. A probe runs once: a second start, or a start after :meth:`stop`, raises
        RuntimeError. Creating the private pinger may raise too (the run then has no probe)."""
        with self._lock:
            if self._started:
                raise RuntimeError("a load latency probe runs only once")
            self._started = True
        pinger, owned = self._get_pinger()
        executor = ThreadPoolExecutor(max_workers=self.max_inflight, thread_name_prefix=THREAD_NAME)
        thread = threading.Thread(target=self._dispatch, args=(pinger,), name=THREAD_NAME, daemon=True)
        with self._lock:
            self._pinger, self._owned, self._executor, self._thread = pinger, owned, executor, thread
        try:
            thread.start()
        except Exception:
            with self._lock:
                self._pinger, self._owned, self._executor, self._thread = None, False, None, None
            executor.shutdown(wait=False)
            if owned:
                _close_pinger(pinger)
            raise
        log.debug("load latency probe started: %s every %d ms, at most %d echoes in flight",
                  self.target, self.interval_ms, self.max_inflight)

    def _get_pinger(self) -> Tuple[Any, bool]:
        """``(pinger, owned)``: a private ``IcmpPinger`` (owned: stop() closes it) when the injected pinger is a real
        one or None; any other injected object as-is (never closed)."""
        injected = self._injected
        cls: Any = None
        try:
            cls = importlib.import_module("tnt.icmp").IcmpPinger
        except Exception:  # noqa: BLE001
            log.debug("tnt.icmp could not be imported", exc_info=True)
        if injected is not None and not (isinstance(cls, type) and isinstance(injected, cls)):
            return injected, False
        if cls is None:
            raise OSError("ICMP is not available: tnt.icmp could not be imported")
        return cls(), True

    def stop(self, timeout: float = 2.0) -> None:
        """Stop sending, wait up to *timeout* s for the echoes in flight, count the rest as lost and release the
        private pinger (see module docstring). Idempotent; never raises."""
        self._stop.set()
        with self._lock:
            self._started = True
            thread, executor, pinger, owned = self._thread, self._executor, self._pinger, self._owned
            self._thread, self._executor, self._pinger, self._owned = None, None, None, False
        if executor is None:
            return
        try:
            budget = max(0.0, float(timeout))
        except (TypeError, ValueError):
            budget = 2.0
        deadline = time.monotonic() + budget
        if thread is not None and thread is not threading.current_thread():
            thread.join(self.DISPATCHER_JOIN_S)
        dispatcher_done = thread is None or not thread.is_alive()
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except Exception:  # noqa: BLE001
            log.debug("load latency probe pool shutdown failed", exc_info=True)
        with self._lock:
            futures = set(self._futures)
        running = wait(futures, timeout=max(0.0, deadline - time.monotonic())).not_done if futures else set()
        with self._lock:
            unfinished = sorted(self._pending.values())
            self._pending.clear()
            self._samples.extend((ts, False, None) for ts in unfinished)
        if unfinished:
            log.debug("load latency probe stopped with %d echo(es) still out; counted as lost", len(unfinished))
        if not owned:
            return
        if dispatcher_done and not running:
            _close_pinger(pinger)
            return
        if budget > 0:
            log.warning("load latency probe: %d echo(es) still running %.1f s after stop; ICMP handles will be "
                        "released once they finish", len(running), budget)
        closer = threading.Thread(target=_close_when_quiet, args=(thread, executor, pinger),
                                  name=CLOSER_THREAD_NAME, daemon=True)
        try:
            closer.start()
        except Exception:  # noqa: BLE001
            log.warning("load latency probe: no thread to release the ICMP handles; they stay open until exit")

    # -- dispatcher and pool --------------------------------------------------
    def _dispatch(self, pinger: Any) -> None:
        """Dispatcher thread: one echo per aligned slot; a slot with every worker busy is recorded as skipped."""
        interval = self.interval_ms / 1000.0
        anchor = float(self._perf())
        slot = 0
        try:
            while not self._stop.is_set():
                now = float(self._perf())
                due = anchor + slot * interval
                if now < due:
                    time.sleep(min(self.WAKE_S, due - now))
                    continue
                self._fire(pinger)
                slot += 1
                now = float(self._perf())
                if now >= anchor + (slot + 1) * interval:
                    # a whole interval behind (the process stalled): skip forward on the same grid, never drift
                    slot = int((now - anchor) // interval) + 1
        except Exception:  # noqa: BLE001 - never let the thread die with a traceback on stderr
            log.exception("load latency probe dispatcher failed")

    def _fire(self, pinger: Any) -> None:
        ts = self._now()
        with self._lock:
            executor = self._executor
            if executor is None:
                return
            if len(self._pending) >= self.max_inflight:
                self._samples.append((ts, None, None))
                return
            seq = self._seq
            self._seq += 1
            self._pending[seq] = ts
        try:
            future = executor.submit(self._echo, pinger, seq, ts)
        except RuntimeError:                     # the pool is shutting down: stop() is running
            with self._lock:
                self._pending.pop(seq, None)
            return
        with self._lock:
            self._futures.add(future)
        future.add_done_callback(self._forget)

    def _echo(self, pinger: Any, seq: int, ts: float) -> None:
        """Pool worker: one echo; the sample keeps the slot's dispatch time."""
        ok, rtt = False, None
        try:
            reply = pinger.ping(self.target, size=self.payload, timeout_ms=self.timeout_ms)
            value = getattr(reply, "rtt_ms", None)
            if getattr(reply, "ok", False) and value is not None:
                ok, rtt = True, float(value)
        except Exception:  # noqa: BLE001 - a failed echo is a lost probe
            log.debug("load latency echo failed", exc_info=True)
        with self._lock:
            if self._pending.pop(seq, None) is None:
                return                             # stop() already counted it as lost
            self._samples.append((ts, ok, rtt))

    def _forget(self, future: Future) -> None:
        with self._lock:
            self._futures.discard(future)

    # -- phases and results ---------------------------------------------------
    def set_phase(self, name: str, fraction: float) -> None:
        """Record one raw progress call ``(phase, fraction)`` on the probe's clock.

        The first call of a phase opens its window and every call at 1.0 moves its end, so the end is the phase's
        last ``(phase, 1.0)``. A phase reported again after another phase started is a new attempt: its old entry
        and every phase recorded after it are dropped (see module docstring).
        """
        now = self._now()
        try:
            frac = float(fraction)
        except (TypeError, ValueError):
            frac = 0.0
        name = str(name)
        with self._lock:
            current = self._phases[-1] if self._phases else None
            if current is None or current[0] != name:
                earlier = next((i for i, entry in enumerate(self._phases) if entry[0] == name), None)
                if earlier is not None:
                    del self._phases[earlier:]
                current = [name, now, None]
                self._phases.append(current)
            if frac >= 1.0:
                current[2] = now

    def phases(self) -> Dict[str, Tuple[float, Optional[float]]]:
        """``{name: (start_ts, end_ts)}`` in the order the phases started. A phase that never reported 1.0 ends where
        the next one started (None while it is the last one)."""
        with self._lock:
            entries = [tuple(entry) for entry in self._phases]
        out: Dict[str, Tuple[float, Optional[float]]] = {}
        for i, (name, start, end) in enumerate(entries):
            if end is None and i + 1 < len(entries):
                end = entries[i + 1][1]
            out[name] = (start, end)
        return out

    def samples(self) -> List[Sample]:
        """Every recorded sample in dispatch order (an echo still out appears once it returns or stop() counts it)."""
        with self._lock:
            return sorted(self._samples, key=lambda s: s[0])
