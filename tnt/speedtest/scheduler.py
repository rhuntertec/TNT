"""Backend selection, the one-shot runner and the periodic :class:`SpeedScheduler`.

Backend selection (:func:`select_backend`)
------------------------------------------
* ``speedtest.backend == "auto"`` -> the first built-in backend
  (:data:`BACKEND_ORDER`: Cloudflare, then fast.com) that is available - a
  backend on rate-limit cooldown (see :mod:`tnt.speedtest.base`) is not, so
  Cloudflare being limited means fast.com runs. When every backend is cooling
  down the first one is returned anyway so that :func:`run_speedtest` can fail
  with the clear "cooling down until HH:MM" error instead of hitting the server
  again.
* an explicit name -> that backend; if it is unavailable (or unknown) fall
  back to the first available other backend with a warning (so an explicit
  Cloudflare on cooldown runs fast.com once and vice versa). The warning is
  logged once per distinct reason (``status()`` polls call this often). With
  no usable fallback the configured backend (the default one for an unknown
  name) is returned and :func:`run_speedtest` returns the failed result
  described above.
* :func:`alternative_backend` is the scheduler's retry pick: the first
  available backend not in *exclude*, or None.

:func:`run_speedtest` never runs a backend whose ``available()`` is False: a
backend on cooldown yields a failed result whose ``error`` starts with
``"rate limited"`` and whose ``raw`` carries ``rate_limited``/``retry_after_s``
/``cooldown``, and any backend result flagged ``raw["rate_limited"]`` puts that
backend on cooldown if the backend did not do so itself.

Scheduler behaviour
-------------------
* daemon thread; first run 60 s after :meth:`SpeedScheduler.start` (lets the
  pings settle), then every ``speedtest.interval_min`` (re-read on every tick,
  so changes apply at the next tick).
* a tick is skipped (logged + ``speedtest.skipped`` ``{"reason", "next_run_ts"}``
  published, nothing persisted) when ``speedtest.enabled`` is false, when a
  manual run is still in progress, or when all internet ping targets are in
  outage. The latter is learnt from the bus: the OutageTracker publishes
  ``outage.start`` / ``outage.end`` with ``kind == "total_internet"`` and the
  scheduler subscribes on :meth:`SpeedScheduler.start` (no Engine wiring
  needed). An optional ``internet_down`` callable can be passed to the
  constructor as an additional source (either one saying "down" skips).
* rate limiting: when a run comes back rate limited (``raw["rate_limited"]``)
  the scheduler immediately retries **once** with :func:`alternative_backend`
  so the slot still gets a reading; only the final outcome is recorded. A
  successful fallback is persisted as a normal result (its ``raw`` lists the
  refused attempt under ``rate_limited_attempts``). When nothing could run
  the attempt is logged, a ``warning`` event row is written, and
  ``speedtest.skipped`` ``{"reason": "rate limited", "detail", "retry_after_s",
  "next_run_ts"}`` is published (plus ``speedtest.done`` with the un-persisted
  failed result so the UI resets); no ``speedtests`` row is written and
  ``last_result`` keeps the last real measurement.
* adaptive spacing: after two rate-limited outcomes within an hour the
  effective interval doubles (and doubles again on each further one), capped
  at :data:`SpeedScheduler.MAX_EFFECTIVE_INTERVAL_MIN` (60), until the next
  successful run returns it to the configured interval. ``status()`` exposes
  ``effective_interval_min`` and ``interval_reason`` (None when unaffected).
* a backwards jump of the wall clock (NTP correction, manual change) shifts
  ``next_run_ts`` by the same amount instead of postponing the next test by
  the size of the jump; a forward jump simply runs the test at once.
* after a sleep/resume the next test is held off ``RESUME_HOLDOFF_S`` (60 s),
  because the NIC is often still re-associating and DNS does not answer yet.
  The scheduler sees the resume on its own thread: a poll whose wait took more
  than ``SLEEP_GAP_S`` longer than asked on the *monotonic* clock (``monotonic``,
  injectable; ``time.monotonic`` is ``GetTickCount64`` on Windows, which counts
  the time asleep, and a test pins that) means this thread did not run.  The
  stamp is taken after the poll's own work, so a scheduled test run on this
  thread is never taken for a sleep.  The Engine's ``monitoring.gap`` event
  holds the test off too, but it comes from the maintenance thread, which
  waits up to 5 s and writes to the database first: on its own it usually
  arrived after the overdue test had started ("Speed test failed: gaierror"
  after most resumes).  A wall clock set forward while the machine is awake,
  or a poll a few seconds late on a loaded machine, is not a resume and still
  runs the test at once.
* :meth:`run_now` starts a manual run on its own thread and returns True, or
  False when a run (manual or scheduled) is already in progress. Manual runs
  ignore ``enabled``/``internet_down`` (the user asked) and, when finished,
  push the next scheduled run to ``now + interval``.
* every real run publishes ``speedtest.start`` ``{"ts","trigger","backend"}``
  (a fallback retry publishes a second one with ``"attempt": 2``),
  ``speedtest.progress`` ``{"phase","pct"}`` and ``speedtest.done``
  ``{"result": <SpeedResult dict + "id">, "trigger"}``; the result is persisted
  via ``db.add_speedtest`` and a ``warning`` event row is written on failure.
  The one exception is a run cut short by :meth:`SpeedScheduler.stop` or
  :meth:`SpeedScheduler.cancel_current` (error ``"cancelled"``): it is not a
  measurement, so it is neither persisted nor counted as a failure
  (``speedtest.done`` is still published so the UI resets).
* :meth:`cancel_current` cuts only the run in progress short and leaves the
  scheduler running (a cancelled Full Scan stops the test it started itself,
  ``tnt.reports``).
* ``clock`` is injectable; the loop polls the clock every ``poll_s`` (1 s by
  default) so a fake clock can drive tests. The cooldown registry keeps its
  own clock (``base.cooldown_clock``); tests patch both to the same fake.
* networks (ARCHITECTURE 3.20): ``SpeedScheduler(..., network_fn=)`` gives the
  network this PC is on; a run reads it when it starts (with ``ts``) and the
  stored row carries it (``add_speedtest`` ``network_id``). The published
  result dict is unchanged. Without *network_fn* nothing is tagged.
* latency under load (ARCHITECTURE 3.6, :mod:`tnt.speedtest.quality`): with a *pinger* (the
  engine's shared ``IcmpPinger``) every run starts a
  :class:`~tnt.speedtest.quality.LoadLatencyProbe` toward *quality_target* (1.1.1.1) after
  ``speedtest.start`` and measures *baseline_s* (3 s) of idle latency before the backend
  runs, published as progress phase ``"baseline"`` (0 -> 1). A cancel during the baseline
  ends the run at once without running the backend. The probe sees every raw progress call
  of the backend before ``speedtest.progress`` de-duplicates them and is stopped (bounded)
  when the backend returns. The built QUALITY goes into the result dict as ``quality`` and
  ``raw["quality"]``, so ``raw_json`` keeps it and :meth:`SpeedScheduler._row_to_result`
  restores ``quality`` (None for rows without one). It is None for a cancelled, failed or
  rate-limited run. A fallback retry keeps the baseline; its loaded windows start over.
  Without a pinger there is no probe and no baseline, ``quality`` is None and ``raw`` gains
  nothing. ``SpeedResult`` itself is unchanged.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .base import (
    CANCELLED, RATE_LIMITED_PREFIX, ProgressFn, SpeedBackend, SpeedResult, clamp_retry_after, failed_result,
    get_cooldown, is_rate_limited, set_cooldown,
)
from .cloudflare import CloudflareBackend
from .fastcom import FastComBackend
from .patterns import analyse_patterns
from .quality import DEFAULT_TARGET as QUALITY_TARGET, LoadLatencyProbe, build_quality

log = logging.getLogger(__name__)

#: Every backend, in preference order ("auto" and the rate-limit fallback walk this).
BACKEND_ORDER = ("cloudflare", "fastcom")
BACKENDS: Dict[str, SpeedBackend] = {
    "cloudflare": CloudflareBackend(),
    "fastcom": FastComBackend(),
}
DEFAULT_BACKEND = "cloudflare"

_warn_lock = threading.Lock()
_last_fallback_warning: Optional[str] = None


def _warn_once(message: str) -> None:
    """Log *message* as a warning only when it differs from the previous one."""
    global _last_fallback_warning
    with _warn_lock:
        if message == _last_fallback_warning:
            log.debug(message)
            return
        _last_fallback_warning = message
    log.warning(message)


def get_backend(name: str) -> Optional[SpeedBackend]:
    return BACKENDS.get(str(name or "").lower())


def _availability(backend: SpeedBackend, config: Any) -> Tuple[bool, str]:
    """``backend.available(config)`` that never raises."""
    name = str(getattr(backend, "name", "?"))
    try:
        ok, detail = backend.available(config)
        return bool(ok), str(detail)
    except Exception as exc:  # noqa: BLE001
        log.exception("backend %s availability check failed", name)
        return False, f"{type(exc).__name__}: {exc}"


def available_backends(config: Any) -> List[Dict[str, Any]]:
    """``[{"name", "available", "detail", "cooldown_until"}, ...]`` for every known backend.

    ``detail`` of a backend on rate-limit cooldown reads ``"cooling down after HTTP 429
    until HH:MM"``; ``cooldown_until`` is that moment as an epoch timestamp (else None).
    """
    out: List[Dict[str, Any]] = []
    for name in BACKEND_ORDER:
        ok, detail = _availability(BACKENDS[name], config)
        cd = get_cooldown(name)
        out.append({"name": name, "available": ok, "detail": detail,
                    "cooldown_until": cd.until if cd is not None else None})
    return out


def _first_available(config: Any, exclude: Iterable[str] = ()) -> Optional[SpeedBackend]:
    """First backend (in :data:`BACKEND_ORDER`) not in *exclude* whose ``available()`` is True."""
    skip = {str(x).lower() for x in exclude}
    for name in BACKEND_ORDER:
        if name in skip:
            continue
        backend = BACKENDS[name]
        ok, _detail = _availability(backend, config)
        if ok:
            return backend
    return None


def alternative_backend(config: Any, exclude: Iterable[str] = ()) -> Optional[SpeedBackend]:
    """The scheduler's fallback after a rate-limited run: another backend that can run now
    (not in *exclude*, not on cooldown), or None."""
    try:
        return _first_available(config, exclude)
    except Exception:  # noqa: BLE001
        log.exception("alternative backend selection failed")
        return None


def select_backend(config: Any) -> SpeedBackend:
    """Pick the backend for the next run (see module docstring). Never raises."""
    try:
        wanted = str(config.get("speedtest.backend", "auto") or "auto").strip().lower()
    except Exception:  # noqa: BLE001
        log.exception("cannot read speedtest.backend; using %s", DEFAULT_BACKEND)
        wanted = DEFAULT_BACKEND
    default = BACKENDS[DEFAULT_BACKEND]
    if wanted == "auto":
        free = _first_available(config)
        # Everything cooling down: hand back the first so run_speedtest can refuse it with
        # the clear cooldown error rather than hitting the server again.
        return free if free is not None else default
    backend = BACKENDS.get(wanted)
    if backend is None:
        free = _first_available(config)
        _warn_once(f"unknown speedtest backend {wanted!r}; using "
                   f"{free.name if free is not None else DEFAULT_BACKEND}")
        return free if free is not None else default
    ok, detail = _availability(backend, config)
    if ok:
        return backend
    fallback = _first_available(config, exclude=(wanted,))
    if fallback is None:
        # nothing else can run either: return the configured one so that run_speedtest's
        # availability check produces the specific error ("cooling down until ...")
        _warn_once(f"speedtest backend {wanted!r} is unavailable ({detail}) and no fallback can run")
        return backend
    _warn_once(f"speedtest backend {wanted!r} is unavailable ({detail}); falling back to {fallback.name}")
    return fallback


def run_speedtest(config: Any, progress: Optional[ProgressFn] = None,
                  cancel: Optional[threading.Event] = None, backend: Optional[SpeedBackend] = None) -> SpeedResult:
    """Run one test with the selected backend. Never raises (``ok=False`` + ``error``).

    *backend* lets a caller that already selected one (the scheduler, so the
    ``speedtest.start`` event names the backend that actually runs) skip a
    second selection. A backend that is not available is never run: on
    cooldown the result is ``error="rate limited: <name> is cooling down after
    HTTP 429 until HH:MM"`` with ``raw["rate_limited"]``/``retry_after_s``/
    ``cooldown``; otherwise ``error="<name> unavailable: <detail>"``.
    """
    ts = time.time()
    if backend is None:
        try:
            backend = select_backend(config)
        except Exception:  # noqa: BLE001
            log.exception("backend selection failed")
            backend = BACKENDS[DEFAULT_BACKEND]
    name = str(getattr(backend, "name", "unknown"))
    ok, detail = _availability(backend, config)
    if not ok:
        cd = get_cooldown(name)
        if cd is not None:
            remaining = max(1, int(round(cd.remaining())))
            log.warning("speed test not run: %s is %s", name, detail)
            return failed_result(name, ts, f"{RATE_LIMITED_PREFIX}: {name} is {detail}", 0.0,
                                 {"rate_limited": True, "retry_after_s": remaining, "http_status": cd.status,
                                  "cooldown": True, "cooldown_until": cd.until})
        log.warning("speed test not run: %s unavailable: %s", name, detail)
        return failed_result(name, ts, f"{name} unavailable: {detail}", 0.0, {"unavailable": True})
    try:
        result = backend.run(config, progress=progress, cancel=cancel)
    except Exception as exc:  # noqa: BLE001
        log.exception("speedtest backend %s raised", name)
        return failed_result(name, ts, f"{type(exc).__name__}: {exc}", time.time() - ts)
    if not isinstance(result, SpeedResult):
        log.error("speedtest backend %s returned %r instead of a SpeedResult", name, type(result))
        return failed_result(name, ts, "backend returned no result", time.time() - ts)
    if is_rate_limited(result) and get_cooldown(name) is None:
        # a backend that flags the limit but did not register its own cooldown
        raw = result.raw if isinstance(result.raw, dict) else {}
        secs = clamp_retry_after(raw.get("retry_after_s"))   # never beyond MAX_RETRY_AFTER_S
        try:
            status = int(raw.get("http_status") or 429)
        except (TypeError, ValueError):
            status = 429
        set_cooldown(name, secs, status=status)
    return result


def local_tz_offset_s(now: Optional[float] = None) -> int:
    """Local UTC offset in seconds at *now* (DST-aware)."""
    try:
        return int(time.localtime(now if now is not None else time.time()).tm_gmtoff)
    except (AttributeError, OverflowError, OSError, ValueError):
        return int(-time.timezone)


class SpeedScheduler:
    """Periodic speed tests (see module docstring)."""

    FIRST_RUN_DELAY_S = 60.0
    #: Total time stop() may spend joining threads (ARCHITECTURE: ~5 s for shutdown).
    STOP_JOIN_S = 5.0
    #: A clock reading this much earlier than the previous one counts as a clock jump.
    CLOCK_JUMP_S = 60.0
    #: A poll that comes round this much later than its wait, on the monotonic clock, means this thread
    #: did not run: the machine slept or hibernated (``time.monotonic`` is ``GetTickCount64`` on
    #: Windows, which counts the time asleep), or the process was frozen.  The next test is then held
    #: off RESUME_HOLDOFF_S.
    SLEEP_GAP_S = 10.0
    #: Rate-limited outcomes within this window trigger the adaptive spacing ...
    RATE_LIMIT_WINDOW_S = 3600.0
    #: ... which never spaces tests further apart than this (or the configured interval).
    MAX_EFFECTIVE_INTERVAL_MIN = 60
    IDLE_PROGRESS: Dict[str, Any] = {"phase": "idle", "pct": 0.0}
    #: Progress steps of the idle baseline (phase "baseline") measured before the backend runs.
    BASELINE_STEP_S = 0.2
    #: How long the latency-under-load probe may wait for its last echoes once the backend returned.
    QUALITY_STOP_S = 2.0

    def __init__(self, db: Any, config: Any, bus: Any, clock: Callable[[], float] = time.time,
                 internet_down: Optional[Callable[[], bool]] = None, poll_s: float = 1.0,
                 network_fn: Optional[Callable[[], Optional[int]]] = None, *, pinger: Any = None,
                 quality_target: str = QUALITY_TARGET, baseline_s: float = 3.0,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self._db = db
        self._config = config
        self._bus = bus
        self._clock = clock
        self._monotonic = monotonic         # how long a poll's wait really took (a sleep shows here)
        self._internet_down = internet_down
        self._network_fn = network_fn       # the current network id (tnt.networks); None: results are not tagged
        self._pinger = pinger               # the engine's IcmpPinger; None: no latency-under-load probe
        self._quality_target = str(quality_target or QUALITY_TARGET)
        try:
            self._baseline_s = max(0.0, float(baseline_s))
        except (TypeError, ValueError):
            self._baseline_s = 3.0
        self._poll_s = max(0.005, float(poll_s))
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._run_thread: Optional[threading.Thread] = None
        self._running = False
        self._cancel: Optional[threading.Event] = None
        self._next_run_ts: Optional[float] = None
        self._last_seen_now: Optional[float] = None
        self._last_wait: Optional[Tuple[float, float]] = None   # (monotonic time a poll's wait began, its length)
        self._last_result: Optional[Dict[str, Any]] = None
        self._progress: Dict[str, Any] = dict(self.IDLE_PROGRESS)
        self._internet_outage = False      # a total_internet outage is open (from the bus)
        self._unsubscribe: Optional[Callable[[], None]] = None
        self._rate_limited_ts: List[float] = []   # recent rate-limited outcomes (adaptive spacing)
        self._backoff = 1                          # effective interval multiplier

    # -- lifecycle ------------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            now = float(self._clock())
            self._next_run_ts = now + self.FIRST_RUN_DELAY_S
            self._last_seen_now = now
            self._last_wait = None
            if self._last_result is None:
                self._last_result = self._load_last()
            self._subscribe()
            self._thread = threading.Thread(target=self._loop, name="speedtest-scheduler", daemon=True)
            self._thread.start()
            nxt = self._next_run_ts
        log.info("speed scheduler started; first run in %.0f s (interval %d min, backend %s)",
                 self.FIRST_RUN_DELAY_S, self._interval_min(), self._selected_backend_name())
        log.debug("first speed test scheduled at %.0f", nxt)

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            cancel = self._cancel
            threads = [self._thread, self._run_thread]
            unsub, self._unsubscribe = self._unsubscribe, None
        if cancel is not None:
            cancel.set()
        if unsub is not None:
            try:
                unsub()
            except Exception:  # noqa: BLE001
                log.exception("unsubscribing from the event bus failed")
        me = threading.current_thread()
        deadline = time.monotonic() + self.STOP_JOIN_S      # one budget for all threads
        for t in threads:
            if t is not None and t is not me and t.is_alive():
                t.join(max(0.0, deadline - time.monotonic()))
                if t.is_alive():
                    log.warning("speedtest thread %s did not stop within %.0f s", t.name, self.STOP_JOIN_S)
        with self._lock:
            self._thread = None
        log.info("speed scheduler stopped")

    # -- bus: total internet outages ------------------------------------------
    RESUME_HOLDOFF_S = 60.0

    def _subscribe(self) -> None:
        """Follow ``outage.start``/``outage.end`` (kind ``total_internet``) and ``monitoring.gap``.
        Called under the lock."""
        if self._unsubscribe is not None:
            return
        subscribe = getattr(self._bus, "subscribe", None)
        if not callable(subscribe):
            return
        try:
            self._unsubscribe = subscribe(self._on_bus_event)
        except Exception:  # noqa: BLE001
            log.exception("subscribing to the event bus failed; outage skips rely on internet_down only")
            self._unsubscribe = None

    def _on_bus_event(self, event: Dict[str, Any]) -> None:
        """Bus subscriber (runs on the publishing thread; must be quick and never raise)."""
        try:
            etype = event.get("type") if isinstance(event, dict) else None
            if etype == "monitoring.gap":
                # the machine just woke up (or monitoring resumed): the NIC may still be
                # reconnecting, so never fire an overdue test immediately
                with self._lock:
                    now = float(self._clock())
                    if self._next_run_ts is None or self._next_run_ts < now + self.RESUME_HOLDOFF_S:
                        self._next_run_ts = now + self.RESUME_HOLDOFF_S
                        log.info("monitoring gap seen; next speed test held off for %.0f s", self.RESUME_HOLDOFF_S)
                return
            if etype not in ("outage.start", "outage.end"):
                return
            data = event.get("data")
            if not isinstance(data, dict) or data.get("kind") != "total_internet":
                return
            down = etype == "outage.start"
            with self._lock:
                changed = down != self._internet_outage
                self._internet_outage = down
            if changed:
                log.info("speed scheduler: %s", "internet outage started - scheduled tests paused"
                         if down else "internet back - scheduled tests resume")
        except Exception:  # noqa: BLE001
            log.exception("speed scheduler bus handler failed")

    @property
    def internet_outage(self) -> bool:
        """True while a ``total_internet`` outage seen on the bus is open."""
        with self._lock:
            return self._internet_outage

    def _internet_is_down(self) -> bool:
        with self._lock:
            if self._internet_outage:
                return True
        if self._internet_down is None:
            return False
        try:
            return bool(self._internet_down())
        except Exception:  # noqa: BLE001
            log.exception("internet_down check failed; running the test anyway")
            return False

    # -- properties -----------------------------------------------------------
    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    @property
    def next_run_ts(self) -> Optional[float]:
        with self._lock:
            return self._next_run_ts

    @property
    def last_result(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._last_result) if self._last_result is not None else None

    @property
    def progress(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._progress)

    # -- config helpers -------------------------------------------------------
    def _enabled(self) -> bool:
        """Whether automatic tests run.  Switching the Speed tool off in Settings stops them whatever
        ``speedtest.enabled`` says: a tool that is off takes no automated action of its own."""
        try:
            from ..config import tool_on

            if not tool_on(self._config, "speed"):
                return False
        except Exception:  # noqa: BLE001 - an unreadable tools block means the tool is on
            pass
        try:
            return bool(self._config.get("speedtest.enabled", True))
        except Exception:  # noqa: BLE001
            log.exception("cannot read speedtest.enabled")
            return True

    def _interval_min(self) -> int:
        """The configured interval (``speedtest.interval_min``)."""
        try:
            v = int(float(self._config.get("speedtest.interval_min", 15)))
        except Exception:  # noqa: BLE001
            v = 15
        return max(1, v)

    def _effective_interval_min(self) -> int:
        """The configured interval, spaced out while rate limiting persists (see module docstring)."""
        configured = self._interval_min()
        with self._lock:
            backoff = self._backoff
        if backoff <= 1 or configured >= self.MAX_EFFECTIVE_INTERVAL_MIN:
            return configured
        return int(min(self.MAX_EFFECTIVE_INTERVAL_MIN, configured * backoff))

    def _interval_reason(self) -> Optional[str]:
        """Why the effective interval differs from the configured one (None when it does not)."""
        eff = self._effective_interval_min()
        with self._lock:
            if self._backoff <= 1 or eff == self._interval_min():
                return None
            now = float(self._clock())
            n = len([t for t in self._rate_limited_ts if now - t < self.RATE_LIMIT_WINDOW_S])
        return (f"rate limited {n} time{'s' if n != 1 else ''} in the last hour; tests spaced {eff} min apart "
                f"until one succeeds")

    def _interval_s(self) -> float:
        return self._effective_interval_min() * 60.0

    def _selected_backend_name(self) -> str:
        try:
            return str(getattr(select_backend(self._config), "name", DEFAULT_BACKEND))
        except Exception:  # noqa: BLE001
            log.exception("backend selection failed")
            return DEFAULT_BACKEND

    def _publish(self, event_type: str, data: Dict[str, Any]) -> None:
        try:
            self._bus.publish(event_type, data)
        except Exception:  # noqa: BLE001
            log.exception("publishing %s failed", event_type)

    # -- scheduler loop -------------------------------------------------------
    def _loop(self) -> None:
        while not self._stop.is_set():
            wait = self._poll_s
            try:
                with self._lock:
                    now = float(self._clock())
                    prev = self._last_seen_now
                    self._last_seen_now = now
                    if prev is not None and now < prev - self.CLOCK_JUMP_S and self._next_run_ts is not None:
                        # Wall clock went backwards: keep the same *distance* to the next run.
                        shifted = self._next_run_ts - (prev - now)
                        log.warning("clock went back %.0f s; next speed test moved from %.0f to %.0f",
                                    prev - now, self._next_run_ts, shifted)
                        self._next_run_ts = shifted
                    self._hold_off_after_a_sleep(now)
                    nxt = self._next_run_ts
                if nxt is not None and now >= nxt:
                    self._tick(now)
            except Exception:  # noqa: BLE001 - the scheduler must never die
                log.exception("speed scheduler loop error")
                wait = 5.0
            with self._lock:
                # taken after this poll's own work: a scheduled test run on this thread is not a sleep
                self._last_wait = (float(self._monotonic()), wait)
            self._stop.wait(wait)

    def _hold_off_after_a_sleep(self, now: float) -> None:
        """Hold the next test off when the last wait took far longer than asked.  Called under the lock.

        That wait is where this thread was when the machine slept: on resume the next test is often long
        overdue while the NIC is still re-associating and DNS does not answer yet, and running it at once
        is "Speed test failed: gaierror" and, in time, an "N tests failed" pattern on a network that is
        fine.  ``monitoring.gap`` does the same from the Engine's maintenance thread, but that thread waits
        up to 5 s and writes to the database before it publishes, so this one usually woke first and the
        test had already started.  Seen here, on this thread, the resume cannot lose that race.  Only the
        monotonic clock can tell: a wall clock set forward while the machine is awake is time that really
        is up, and the overdue test runs at once as it always has.
        """
        last = self._last_wait
        if last is None or self._next_run_ts is None:
            return
        slept = float(self._monotonic()) - last[0] - last[1]
        if slept <= self.SLEEP_GAP_S:
            return
        held = now + self.RESUME_HOLDOFF_S
        if self._next_run_ts < held:
            self._next_run_ts = held
            log.info("speed scheduler: this thread was stopped for %.0f s (sleep/resume); next speed test held off "
                     "for %.0f s", slept, self.RESUME_HOLDOFF_S)

    def _tick(self, now: float) -> None:
        with self._lock:
            self._next_run_ts = now + self._interval_s()
        if not self._enabled():
            self._skip("disabled")
            return
        if self._internet_is_down():
            self._skip("internet outage")
            return
        if not self._begin():
            self._skip("a test is already running")
            return
        self._execute("scheduled")

    def _skip(self, reason: str, **extra: Any) -> None:
        log.info("speed test skipped: %s%s", reason, f" ({extra['detail']})" if extra.get("detail") else "")
        data: Dict[str, Any] = {"reason": reason, "next_run_ts": self.next_run_ts}
        data.update(extra)
        self._publish("speedtest.skipped", data)

    # -- runs -----------------------------------------------------------------
    def _begin(self, run_thread: Optional[threading.Thread] = None) -> bool:
        """Claim the running flag; registers *run_thread* atomically so stop() can join it."""
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._cancel = threading.Event()
            self._progress = {"phase": "starting", "pct": 0.0}
            if run_thread is not None:
                self._run_thread = run_thread
            return True

    def run_now(self) -> bool:
        """Start a manual run on its own thread. False when one is already running."""
        t = threading.Thread(target=self._execute, args=("manual",), name="speedtest-run", daemon=True)
        if not self._begin(t):
            return False
        try:
            t.start()
        except Exception:
            # The flag was claimed but nothing will ever clear it: release it or every
            # later run_now()/tick would report "already running" forever.
            with self._lock:
                self._running = False
                self._cancel = None
                self._progress = dict(self.IDLE_PROGRESS)
                if self._run_thread is t:
                    self._run_thread = None
            log.exception("could not start the speed test thread")
            raise
        return True

    def cancel_current(self) -> bool:
        """Cut the run in progress short; True when one was running.  Unlike :meth:`stop` the scheduler
        keeps going.  The run ends with error ``"cancelled"``, is not persisted and still publishes
        ``speedtest.done``."""
        with self._lock:
            cancel = self._cancel if self._running else None
        if cancel is None:
            return False
        cancel.set()
        log.info("speed test cancel requested")
        return True

    def _on_progress(self, phase: str, frac: float) -> None:
        try:
            pct = max(0.0, min(1.0, float(frac)))
        except (TypeError, ValueError):
            pct = 0.0
        pct = round(pct, 3)
        with self._lock:
            prev = self._progress
            changed = prev.get("phase") != phase or abs(float(prev.get("pct", 0.0)) - pct) >= 0.01 or pct >= 1.0
            self._progress = {"phase": str(phase), "pct": pct}
        if changed:
            self._publish("speedtest.progress", {"phase": str(phase), "pct": pct})

    def _attempt(self, backend: Optional[SpeedBackend], name: str, cancel: threading.Event, ts: float,
                 progress: Optional[ProgressFn] = None) -> SpeedResult:
        try:
            return run_speedtest(self._config, progress=progress or self._on_progress, cancel=cancel, backend=backend)
        except Exception as exc:  # noqa: BLE001 - run_speedtest never raises, belt and braces
            log.exception("speed test crashed")
            return failed_result(name, ts, f"{type(exc).__name__}: {exc}")

    @staticmethod
    def _refusal(result: SpeedResult) -> Dict[str, Any]:
        raw = result.raw if isinstance(result.raw, dict) else {}
        return {"backend": result.backend, "error": result.error, "retry_after_s": raw.get("retry_after_s"),
                "http_status": raw.get("http_status")}

    def _network_id(self) -> Optional[int]:
        fn = self._network_fn
        if fn is None:
            return None
        try:
            nid = fn()
        except Exception:  # noqa: BLE001
            log.debug("the current network id could not be read", exc_info=True)
            return None
        return nid if isinstance(nid, int) and not isinstance(nid, bool) and nid > 0 else None

    # -- latency under load ---------------------------------------------------
    def _start_probe(self) -> Optional[LoadLatencyProbe]:
        """A started latency-under-load probe; None without a pinger or when it cannot start (the test runs anyway)."""
        if self._pinger is None:
            return None
        try:
            probe = LoadLatencyProbe(self._pinger, target=self._quality_target)
            probe.set_phase("baseline", 0.0)          # before the first echo, so that echo lands in the baseline
            probe.start()
        except Exception:  # noqa: BLE001
            log.exception("latency under load probe could not start; the speed test runs without it")
            return None
        return probe

    def _probe_progress(self, probe: LoadLatencyProbe) -> ProgressFn:
        """Progress callback of a probed run: the probe sees every raw call, then the de-duplicating publisher."""
        def progress(phase: str, frac: float) -> None:
            try:
                probe.set_phase(phase, frac)
            except Exception:  # noqa: BLE001
                log.debug("latency under load probe could not record a phase", exc_info=True)
            self._on_progress(phase, frac)

        return progress

    def _run_baseline(self, progress: ProgressFn, cancel: threading.Event) -> None:
        """Idle latency before the backend runs: *baseline_s* seconds as progress ``("baseline", 0 -> 1)``.
        Returns at once when *cancel* is set (without reaching 1.0)."""
        total = self._baseline_s
        progress("baseline", 0.0)
        started = time.monotonic()
        while not cancel.is_set():
            elapsed = time.monotonic() - started
            if elapsed >= total:
                progress("baseline", 1.0)
                return
            cancel.wait(min(self.BASELINE_STEP_S, total - elapsed))
            elapsed = time.monotonic() - started
            if elapsed < total and not cancel.is_set():
                progress("baseline", elapsed / total)

    def _finish_probe(self, probe: LoadLatencyProbe, result: SpeedResult,
                      cancel: threading.Event) -> Optional[Dict[str, Any]]:
        """Stop the probe (bounded; without waiting when cancelled) and grade the run. None for a cancelled, failed
        or rate-limited run, or when grading fails."""
        cancelled = cancel.is_set()
        try:
            probe.stop(0.0 if cancelled else self.QUALITY_STOP_S)
        except Exception:  # noqa: BLE001
            log.exception("latency under load probe did not stop cleanly")
        if cancelled or not result.ok or is_rate_limited(result):
            return None
        try:
            quality = build_quality(probe.samples(), probe.phases(), target=probe.target,
                                    interval_ms=probe.interval_ms, payload=probe.payload)
        except Exception:  # noqa: BLE001
            log.exception("latency under load could not be graded")
            return None
        self._log_quality(quality)
        return quality

    @staticmethod
    def _log_quality(quality: Dict[str, Any]) -> None:
        """One INFO line with grades, labels and counts (the probe target is an address: DEBUG only)."""
        windows = [w for w in (quality.get("windows") or {}).values() if isinstance(w, dict)]
        sent = sum(int(w.get("sent") or 0) for w in windows)
        received = sum(int(w.get("received") or 0) for w in windows)
        if not quality.get("available"):
            log.info("latency under load not graded: %d of %d probes answered", received, sent)
            log.debug("latency under load not graded: %s", quality.get("reason"))
            return
        bloat = quality.get("bufferbloat") or {}
        call = quality.get("call") or {}
        if bloat.get("grade"):
            increase = bloat.get("increase_ms")
            grade = f"grade {bloat['grade']} ({bloat.get('direction')}" + \
                (f", +{increase:.1f} ms)" if increase is not None else ")")
        else:
            grade = f"not graded ({bloat.get('reason')})"
        log.info("latency under load: %s; call quality %s idle, %s busy; %d of %d probes answered", grade,
                 (call.get("idle") or {}).get("label"), (call.get("loaded") or {}).get("label") or "n/a",
                 received, sent)

    def _execute(self, trigger: str) -> None:
        """Run one test (the running flag must already be claimed via ``_begin``)."""
        ts = float(self._clock())
        network_id = self._network_id()     # the network the test starts on
        with self._lock:
            cancel = self._cancel if self._cancel is not None else threading.Event()
            self._cancel = cancel
        try:
            backend: Optional[SpeedBackend] = select_backend(self._config)
        except Exception:  # noqa: BLE001
            log.exception("backend selection failed")
            backend = None
        backend_name = str(getattr(backend, "name", DEFAULT_BACKEND))
        log.info("speed test starting (%s, backend %s)", trigger, backend_name)
        self._publish("speedtest.start", {"ts": ts, "trigger": trigger, "backend": backend_name})
        probe: Optional[LoadLatencyProbe] = None
        try:
            probe = self._start_probe()
            progress: ProgressFn = self._on_progress
            if probe is not None:
                progress = self._probe_progress(probe)
                self._run_baseline(progress, cancel)
            if probe is not None and cancel.is_set():
                result = failed_result(backend_name, ts, CANCELLED)      # cut short during the baseline
            else:
                result = self._attempt(backend, backend_name, cancel, ts, progress)
            refused: List[Dict[str, Any]] = []
            if is_rate_limited(result) and not cancel.is_set():
                refused.append(self._refusal(result))
                alt = alternative_backend(self._config, exclude=(result.backend, backend_name))
                if alt is not None:
                    alt_name = str(getattr(alt, "name", "?"))
                    log.warning("speed test rate limited by %s (%s); retrying with %s",
                                result.backend, result.error, alt_name)
                    self._publish("speedtest.start", {"ts": ts, "trigger": trigger, "backend": alt_name,
                                                      "attempt": 2, "after": result.backend})
                    # the same probe: its baseline stays, the loaded windows start over with the new phases
                    result = self._attempt(alt, alt_name, cancel, ts, progress)
                    if is_rate_limited(result) and not cancel.is_set():
                        refused.append(self._refusal(result))
                else:
                    log.warning("speed test rate limited by %s (%s); no other backend can run now",
                                result.backend, result.error)
            quality: Optional[Dict[str, Any]] = None
            if probe is not None:
                quality = self._finish_probe(probe, result, cancel)
                probe = None
            d = result.to_dict()
            d["ts"] = ts
            d["trigger"] = trigger
            if not isinstance(d.get("raw"), dict):
                d["raw"] = {}
            if refused:
                d["raw"]["rate_limited_attempts"] = refused
            if self._pinger is not None:
                d["raw"]["quality"] = quality          # kept in raw_json; _row_to_result restores d["quality"]
            d["quality"] = quality
            cancelled = cancel.is_set() and not d.get("ok") and d.get("error") == CANCELLED
            limited = bool(is_rate_limited(result)) and not cancelled
            if cancelled:
                # Cut short by stop(): not a measurement, so no history row, no failure event.
                log.info("speed test cancelled (%s, %s)", trigger, d.get("backend"))
            elif limited:
                self._rate_limited_outcome(trigger, ts, refused or [self._refusal(result)])
            else:
                try:
                    d["id"] = self._db.add_speedtest(d if network_id is None else {**d, "network_id": network_id})
                except Exception:  # noqa: BLE001
                    log.exception("failed to persist speed test result")
            if d.get("ok"):
                log.info("speed test done: down %.1f Mbps, up %s Mbps, latency %s ms (%s, %.1f s)%s",
                         d.get("download_mbps") or 0.0,
                         f"{d['upload_mbps']:.1f}" if d.get("upload_mbps") is not None else "n/a",
                         f"{d['latency_ms']:.1f}" if d.get("latency_ms") is not None else "n/a",
                         d.get("server") or d.get("backend"), d.get("duration_s") or 0.0,
                         f" after {refused[0]['backend']} was rate limited" if refused else "")
                self._successful_outcome(ts)
            elif not cancelled and not limited:
                log.warning("speed test failed (%s): %s", d.get("backend"), d.get("error"))
                try:
                    self._db.add_event("warning", "speedtest", f"speed test failed ({d.get('backend')}): {d.get('error')}", ts=ts)
                except Exception:  # noqa: BLE001
                    log.exception("failed to record speed test failure event")
            with self._lock:
                if not cancelled and not limited:
                    self._last_result = d
                self._progress = {"phase": "done", "pct": 1.0}
            self._publish("speedtest.done", {"result": d, "trigger": trigger})
        except Exception:  # noqa: BLE001
            log.exception("speed test post-processing failed")
        finally:
            if probe is not None:                      # something above raised before the probe was stopped
                try:
                    probe.stop(0.0)
                except Exception:  # noqa: BLE001
                    log.debug("latency under load probe did not stop", exc_info=True)
            with self._lock:
                self._running = False
                self._cancel = None
                self._progress = dict(self.IDLE_PROGRESS)
                if trigger == "manual":
                    self._next_run_ts = float(self._clock()) + self._interval_s()
                if self._run_thread is threading.current_thread():
                    self._run_thread = None

    # -- rate-limit outcomes --------------------------------------------------
    def _successful_outcome(self, ts: float) -> None:
        """Back to the configured interval (the tick that started this run scheduled the next
        one with the spaced-out interval; pull it back in)."""
        with self._lock:
            if self._backoff <= 1:
                return
            self._backoff = 1
            self._rate_limited_ts.clear()
            configured = self._interval_s()
            if self._next_run_ts is not None:
                self._next_run_ts = min(self._next_run_ts, ts + configured)
        log.info("speed test succeeded; interval back to the configured %d min", int(configured // 60))

    def _rate_limited_outcome(self, trigger: str, ts: float, refused: List[Dict[str, Any]]) -> None:
        """Nothing could run this slot: log it, write a warning event, space tests out, publish
        ``speedtest.skipped`` - no ``speedtests`` row."""
        detail = "; ".join(f"{a.get('backend')}: {a.get('error')}" for a in refused) or "rate limited"
        retry_after = max([int(a["retry_after_s"]) for a in refused if a.get("retry_after_s")] or [0]) or None
        log.warning("speed test skipped (%s): rate limited - %s", trigger, detail)
        try:
            self._db.add_event("warning", "speedtest", f"speed test skipped: rate limited ({detail})", ts=ts)
        except Exception:  # noqa: BLE001
            log.exception("failed to record the rate-limit event")
        with self._lock:
            self._rate_limited_ts = [t for t in self._rate_limited_ts if ts - t < self.RATE_LIMIT_WINDOW_S]
            self._rate_limited_ts.append(ts)
            recent = len(self._rate_limited_ts)
            if recent >= 2:
                self._backoff = min(self._backoff * 2, 64)
            eff_s = self._interval_s()
            if self._next_run_ts is not None:
                self._next_run_ts = max(self._next_run_ts, ts + eff_s)
        if recent >= 2:
            log.warning("%d rate-limited speed tests in the last hour; tests now every %d min until one succeeds",
                        recent, int(eff_s // 60))
        self._skip("rate limited", detail=detail, retry_after_s=retry_after)

    # -- queries --------------------------------------------------------------
    def _load_last(self) -> Optional[Dict[str, Any]]:
        try:
            row = self._db.last_speedtest()
        except Exception:  # noqa: BLE001
            log.exception("cannot load last speed test")
            return None
        if not row:
            return None
        return self._row_to_result(row)

    @staticmethod
    def _row_to_result(row: Dict[str, Any]) -> Dict[str, Any]:
        d = dict(row)
        raw_json = d.pop("raw_json", None)
        raw: Dict[str, Any] = {}
        if isinstance(raw_json, str) and raw_json:
            try:
                parsed = json.loads(raw_json)
                if isinstance(parsed, dict):
                    raw = parsed
            except ValueError:
                pass
        d["raw"] = raw
        d["ok"] = bool(d.get("ok"))
        quality = raw.get("quality")
        d["quality"] = quality if isinstance(quality, dict) else None     # latency under load (tnt.speedtest.quality)
        return d

    def status(self) -> Dict[str, Any]:
        with self._lock:
            running = self._running
            nxt = self._next_run_ts
            last = dict(self._last_result) if self._last_result is not None else None
            progress = dict(self._progress)
        return {
            "enabled": self._enabled(),
            "running": running,
            "next_run_ts": nxt,
            "last": last,
            "backend": self._selected_backend_name(),
            "interval_min": self._interval_min(),
            "effective_interval_min": self._effective_interval_min(),
            "interval_reason": self._interval_reason(),
            "progress": progress,
        }

    def history(self, start_ts: float, end_ts: float, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        return self._db.list_speedtests(float(start_ts), float(end_ts), limit=limit)

    def patterns(self, days: int = 7, now: Optional[float] = None) -> Dict[str, Any]:
        now = float(now) if now is not None else float(self._clock())
        days = max(1, int(days))
        rows = self._db.list_speedtests(now - days * 86400.0, now + 1.0)
        try:
            warn = float(self._config.get("speedtest.warn_below_pct", 50))
        except Exception:  # noqa: BLE001
            warn = 50.0
        return analyse_patterns(rows, now, warn, local_tz_offset_s(now), days=days)
