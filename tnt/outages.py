"""Outage state machine and timeline.

The :class:`OutageTracker` is fed one sample per ping by the ``PingManager``
(through ``add_sample_listener``) and turns runs of missed pings into rows of
the ``outages`` table:

* ``kind="target"`` - one target stopped answering.  Opens after
  ``outage.miss_threshold`` consecutive misses with ``start_ts`` = the first
  miss of that run; closes after ``outage.recover_threshold`` consecutive
  successes with ``end_ts`` = the first success of that recovery run.  A miss
  during the recovery run resets the recovery counter.  Both thresholds are
  read live from :class:`~tnt.config.Config` on every sample.
* ``kind="total_local"`` / ``"total_internet"`` - every *active* target of a
  group (enabled, at least one sample in the last 15 s) is in a target outage.
  ``start_ts`` = the latest member start (the moment the last one fell); closes
  when any member recovers, ``end_ts`` = that member's recovery timestamp.
* ``kind="gap"`` - the service was not monitoring.  Inserted at startup when
  the ``last_heartbeat`` meta value (written by the Engine every 30 s) is more
  than 90 s old.  Outages left open by the previous run are closed at that
  heartbeat with note ``"service stopped"``.

Interpretations of the contract (listed as deviations in the module report):

* ``missed`` of a target outage includes the misses that opened it (the outage
  starts at the first miss, so those misses belong to it).  It is persisted on
  every 10th miss, on close and on :meth:`OutageTracker.stop`.
* Thresholds are compared with ``>=`` rather than ``==`` so lowering a
  threshold in the settings while a run is in progress takes effect at once.
* ``status()["active"]`` lists every open outage (target *and* total, newest
  first); ``total_active`` prefers ``total_internet`` when both totals are
  open; ``count_24h`` and ``last`` consider target and total rows, never gaps.
* Startup stale-closing refreshes ``last_heartbeat`` and skips the gap row if
  one for the same period already exists, so the Engine may call
  :func:`close_stale_outages` itself before :meth:`OutageTracker.start` runs
  it again without producing duplicate gap rows.
* ``on_sample`` computes state changes under one RLock but calls
  ``set_in_outage`` and publishes events *after* releasing it, and
  ``ping_manager.targets()`` is fetched outside the lock, so the tracker never
  holds its lock while calling into the PingManager (no lock-order inversion).
* If the PingManager offers ``add_removal_listener`` it is used; the callback
  accepts either a target id or a target view dict.
* Outage start/end are also recorded with ``db.add_event`` (category
  ``"outage"``) so they show up in the diagnostics' recent events.
* A total outage opened because a *healthy* member was removed (leaving only
  down members) starts at the removal moment, never earlier: before the
  removal the group was provably reachable, so back-dating it to the
  remaining member's first miss would paint the timeline red for a period the
  network was up.
* Totals are re-evaluated not only on target open/close but also when a
  successful sample arrives from a target that is *not* in outage while its
  group has an open total (a target added or resuming while everything else
  is down).  The total closes with ``end_ts`` = that sample's timestamp.
  Misses on such a target do not trigger a re-evaluation (it is about to open
  its own outage, and closing/reopening the total would just flap).
* If ``ping_manager.targets()`` raises, total evaluation is skipped for that
  sample instead of being run against an empty list (which would close an
  open total spuriously).
* Only the changed target's group is re-evaluated (both when a target in
  outage moves between groups because its hostname now resolves to the other
  address class, or when a never-sampled target is removed).  The other
  group's all-down status cannot have changed, and re-checking it would let a
  member that is momentarily stale (worker delayed past the active window,
  e.g. right after the machine wakes) close its total spuriously with nothing
  to reopen it while that member keeps missing.
* Samples whose timestamp is missing or not finite are ignored with a warning
  (a NaN ``first_miss_ts`` would fail every later ``start_ts NOT NULL`` insert
  of the run and the outage would never open).
* After :meth:`OutageTracker.on_monitoring_gap` each target's *first* sample is
  dropped when it is stamped before the gap's end: a sample is stamped when its
  echo request is sent, so the one in flight when the machine slept comes back
  after the wake dated before the sleep, after the gap has already reset every
  run.  Counted, it started a new miss run there and two misses while the Wi-Fi
  re-associated opened an outage back-dated across the whole sleep (an 8 h outage
  of a target that answered seconds after the wake).  Only the first sample per
  target is looked at (a worker has one echo out at a time), so a clock set back
  after the wake does not make the tracker ignore anything else.
* The "active" window for total evaluation is 15 s as specified, widened to
  ``2 * ping.interval_s + ping.timeout_ms`` when the configured interval is
  long (up to 60 s is allowed): with a 20 s interval a healthy target would
  otherwise be excluded from its group for most of every cycle and a single
  down target would open a false total.
* A new total never starts before the previous total of the same group ended
  (the group was reachable at that moment through the member that recovered).
* Database writes happen *before* the matching in-memory state change, so a
  failed write (disk full, locked file) leaves the state machine consistent
  and the change is retried on the next sample instead of being lost.
* Network changes: the PingManager's ``add_ip_listener`` reports a target that
  now pings another address because the network changed (the ``gateway``
  alias following a new default gateway or losing it, a host name whose first
  lookup on the new network answered elsewhere).  Its open outage was about
  the old address, so it is closed at that moment with note
  ``"network changed"``, its miss/recovery run starts afresh and its group's
  total is re-evaluated (and closed with the same note when it no longer
  holds).  A host name whose periodic lookup merely rotated keeps its outage.
* ``OutageTracker.on_network_change`` (the Engine, for ``net.changed``): when
  this PC has a default gateway other than the last one it had (a move,
  directly or through a spell without any), every open target and total
  outage is closed at that moment with note ``"network changed"`` and every
  miss/recovery run starts afresh: they were about the network it left.
  Losing the connection changes nothing about what is recorded (a Wi-Fi drop
  is a local and internet outage, as it always was), but an outage that was
  open while this PC had no default gateway and no internet adapter and ends
  without a note of its own gets ``"no network connection"``.  One that ends by
  recovering on another network gets ``"network changed"`` even when its
  answers beat the event: the live default gateway (*gateway_fn*, the Engine's
  netinfo lookup) differs from the one it began on.
* The ``host`` stored on a target outage row (and shown in its events) is what
  was actually pinged: ``"gateway (192.168.10.1)"`` / ``"example.com
  (203.0.113.10)"`` when a name resolved to an address, the plain host for an
  IP target.  An open outage keeps the address it was opened for.
* Networks (ARCHITECTURE 3.20): ``OutageTracker(..., network_fn=)`` gives the
  network this PC is on; every row (target, total and gap) is opened with
  ``network_id`` = that network at that moment (a gap row only lists where
  monitoring stopped: its time is never an outage).  ``close_stale_outages(...,
  network_id=)`` tags the gap of the time the service was stopped with the
  network the previous run was on.  ``on_network_id_change(event)`` (a
  ``tnt.networks`` listener) handles a move the default gateway cannot show (two
  sites behind the same address): every outage that opened before ``event["ts"]``
  closes then with ``"network changed"``, and on an immediate switch every
  miss/recovery run starts afresh.
* Clear history (Settings, :mod:`tnt.history`): ``clear_history(since_ts) -> int``
  deletes the outage rows overlapping ``[since_ts, now]`` (open ones included) and the
  ``outage`` events rows from then on, then forgets every open outage and run (see the
  method).  The PingManager's ``in_outage`` flag is only ever set to what the tracker
  holds at that moment (``_apply_in_outage``), so a flag computed before a clear cannot
  turn a light red again after it.  ``timeline()`` carries ``"cleared": [{"start_ts",
  "end_ts"}]``: the cleared spans (``tnt.history.timeline_spans``) clipped to its range,
  which the Outages view paints like a monitoring gap, never as "fine".
"""
from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterable, List, Optional, Tuple

from . import history as _history

if TYPE_CHECKING:  # pragma: no cover - typing only; tnt.pinger may not exist yet
    from .config import Config
    from .db import Database
    from .events import EventBus
    from .pinger import Sample

log = logging.getLogger(__name__)

#: A target counts as "active" for total-outage evaluation when it is enabled and
#: produced a sample within this many seconds (widened for long ping intervals,
#: see :meth:`OutageTracker._active_window`).
ACTIVE_WINDOW_S = 15.0
#: A ``gap`` row is inserted at startup when ``last_heartbeat`` is older than this.
GAP_THRESHOLD_S = 90.0
#: The ``missed`` counter of an open outage is persisted every N misses.
MISSED_PERSIST_EVERY = 10
#: Upper bound for ``timeline(hours)`` (a year); keeps the payload finite and the query bounded.
MAX_TIMELINE_HOURS = 24.0 * 366

GROUPS: Tuple[str, ...] = ("local", "internet")
TOTAL_KINDS: Tuple[str, ...] = tuple(f"total_{g}" for g in GROUPS)
OUTAGE_KINDS: Tuple[str, ...] = ("target",) + TOTAL_KINDS

# Deferred side effects computed under the lock and executed after releasing it:
# ("in_outage", target_id, flag) or ("event", event_type, data, clear generation).
_Effect = Tuple[Any, ...]

#: Notes of outages that end because of (or across) a network change.
NETWORK_CHANGED_NOTE = "network changed"
NO_NETWORK_NOTE = "no network connection"


def _finite(value: Any) -> Optional[float]:
    """``float(value)`` if it is a finite number (bools excluded), else None."""
    if value is None or isinstance(value, bool):
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _parse_ts(value: Any) -> Optional[float]:
    """Parse a meta value (string) into a finite float timestamp, or None."""
    if value in (None, ""):
        return None
    return _finite(value)


def missed_percentage(kind: Any, missed: Any, sent: Any, duration_s: Any,
                      interval_s: Any = 1.0) -> Tuple[Optional[int], Optional[float], bool]:
    """``(sent, missed_pct, estimated)`` for one outage row.

    Only target outages count pings. ``sent`` is exact for rows recorded since the counter
    exists (every sample while the outage was open, minus the recovery run that closed it,
    which starts at ``end_ts``). Older rows have no count, so it is estimated as one ping per
    ``interval_s`` over the outage's duration (never fewer than the misses) and flagged
    ``estimated``. Total and gap rows give ``(None, None, False)``.
    """
    if kind != "target":
        return None, None, False
    try:
        m = max(0, int(missed or 0))
    except (TypeError, ValueError):
        m = 0
    estimated = False
    try:
        s = int(sent) if sent is not None else None
    except (TypeError, ValueError):
        s = None
    if s is None or s <= 0:
        estimated = True
        try:
            step = float(interval_s)
            if not step > 0:
                step = 1.0
        except (TypeError, ValueError):
            step = 1.0
        d = _finite(duration_s) or 0.0
        s = max(m, int(round(max(0.0, d) / step)))
    s = max(s, m)
    if s <= 0:
        return None, None, estimated
    return s, round(100.0 * m / s, 2), estimated


def _fmt_duration(seconds: float) -> str:
    s = int(max(0.0, seconds))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {sec}s"
    if m:
        return f"{m}m {sec}s"
    return f"{sec}s"


def _sample_fields(sample: Any) -> Tuple[float, bool]:
    """Accept a ``pinger.Sample`` (or anything with ``ts``/``ok``) or a dict.

    Raises ``ValueError`` when the timestamp is missing or not finite: a NaN
    ``ts`` would otherwise become ``first_miss_ts`` and every later miss of the
    run would fail the ``start_ts NOT NULL`` insert (logging a traceback each
    second) without ever opening the outage.
    """
    if isinstance(sample, dict):
        raw_ts, ok = sample["ts"], sample["ok"]
    else:
        raw_ts, ok = sample.ts, sample.ok
    ts = _finite(raw_ts)
    if ts is None:
        raise ValueError(f"sample timestamp {raw_ts!r} is not a finite number")
    return ts, bool(ok)


def _pinged_host(view: Dict[str, Any]) -> Optional[str]:
    """What a target outage is about: ``"host (ip)"`` when a name (or the ``gateway`` alias)
    resolved to an address, else the plain host; ``None`` without a host."""
    host = str(view.get("host") or "").strip()
    if not host:
        return None
    ip = str(view.get("ip") or "").strip()
    return f"{host} ({ip})" if ip and ip.lower() != host.lower() else host


def close_stale_outages(db: "Database", now: Optional[float] = None,
                        keep_ids: Iterable[int] = (), network_id: Optional[int] = None) -> Dict[str, Any]:
    """Startup housekeeping (contract 3.5 "Startup").

    Closes every outage row still open in the database with
    ``end_ts = last_heartbeat`` (or *now* when the heartbeat is unknown), note
    ``"service stopped"``.  When the heartbeat exists and is more than 90 s old
    a ``kind="gap"`` row (note ``"not monitoring"``) is inserted covering
    ``[last_heartbeat, now]`` unless an identical gap row already exists.
    Finally ``last_heartbeat`` is refreshed to *now* so a second call is a
    no-op.  Rows whose ids are in *keep_ids* are left alone (they belong to a
    live tracker).  Returns ``{"closed", "gap_id", "last_heartbeat", "now"}``.
    """
    now = float(now if now is not None else time.time())
    hb = _parse_ts(db.get_meta("last_heartbeat"))
    keep = set(int(i) for i in keep_ids)
    closed = 0
    for row in db.open_outages():
        rid = int(row["id"])
        if rid in keep:
            continue
        start = float(row["start_ts"])
        end = hb if hb is not None else now
        end = min(max(end, start), max(now, start))
        db.close_outage(rid, end, int(row.get("missed") or 0), "service stopped")
        closed += 1
        log.info("closed stale %s outage #%d at %.0f (service stopped)", row.get("kind"), rid, end)
    gap_id: Optional[int] = None
    if hb is not None and now - hb > GAP_THRESHOLD_S:
        existing = [
            r for r in db.list_outages(hb, now, kinds=("gap",), include_open=False)
            if abs(float(r["start_ts"]) - hb) < 1.0
        ]
        if existing:
            gap_id = int(existing[0]["id"])
        elif network_id is not None:
            gap_id = db.open_outage("gap", None, hb, note="not monitoring", network_id=network_id)
            db.close_outage(gap_id, now, 0, "not monitoring")
            log.info("inserted monitoring gap #%d: %s (%.0f -> %.0f)", gap_id, _fmt_duration(now - hb), hb, now)
        else:
            gap_id = db.open_outage("gap", None, hb, note="not monitoring")
            db.close_outage(gap_id, now, 0, "not monitoring")
            log.info("inserted monitoring gap #%d: %s (%.0f -> %.0f)", gap_id, _fmt_duration(now - hb), hb, now)
    db.set_meta("last_heartbeat", repr(now))
    return {"closed": closed, "gap_id": gap_id, "last_heartbeat": hb, "now": now}


@dataclass
class _TargetState:
    """Per-target counters; guarded by :attr:`OutageTracker._lock`."""

    target_id: int
    host: str
    kind: str = "internet"
    consecutive_missed: int = 0
    consecutive_ok: int = 0
    first_miss_ts: Optional[float] = None   # ts of the first miss of the current miss run
    first_ok_ts: Optional[float] = None     # ts of the first success of the current recovery run
    last_sample_ts: Optional[float] = None
    outage: Optional[Dict[str, Any]] = None  # in-memory copy of the open target outage row
    # False from a monitoring gap until this target's first sample after it: that one may be the echo
    # that was in flight while monitoring stopped (see OutageTracker.on_sample)
    sampled_since_gap: bool = False


def backfill_outage_hosts(db: Any, raw_log: Any, hosts: Optional[Dict[int, str]] = None) -> int:
    """Fill ``outages.host`` for target outages recorded before the column existed.

    Sources per target id, in order: the live *hosts* map, the targets table, then the raw
    ping log of the day the outage started (``RawPingLog.host_for``). Returns the number of
    rows updated. Safe to run repeatedly; rows whose host cannot be found are left alone.
    """
    if not hasattr(db, "outages_missing_host"):     # test doubles / very old stores
        return 0
    try:
        rows = db.outages_missing_host()
    except Exception:  # noqa: BLE001
        log.exception("listing outages without a host failed")
        return 0
    if not rows:
        return 0
    cache: Dict[int, Optional[str]] = {int(k): v for k, v in (hosts or {}).items() if v}
    tried: set = set()
    updated = 0
    for r in rows:
        tid = int(r["target_id"])
        host = cache.get(tid)
        if host is None and tid not in cache:
            try:
                t = db.get_target(tid)
                host = t["host"] if t else None
            except Exception:  # noqa: BLE001
                host = None
            cache[tid] = host
        if not host and raw_log is not None:
            key = (tid, _day_key(float(r["start_ts"])))
            if key not in tried:
                tried.add(key)
                try:
                    host = raw_log.host_for(tid, float(r["start_ts"]))
                except Exception:  # noqa: BLE001
                    host = None
                if host:
                    cache[tid] = host
        if host:
            try:
                db.set_outage_host(int(r["id"]), host)
                updated += 1
            except Exception:  # noqa: BLE001
                log.exception("setting the host of outage %s failed", r.get("id"))
    return updated


def _day_key(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


class OutageTracker:
    """Per-target and total outage detection driven by ping samples.

    Thread-safe: ``on_sample`` is called from every ping worker thread and the
    query methods from API threads; one RLock guards all state.
    """

    def __init__(self, db: "Database", config: "Config", bus: "EventBus", ping_manager: Any,
                 clock: Callable[[], float] = time.time,
                 suppress_new: Optional[Callable[[], bool]] = None,
                 gateway_fn: Optional[Callable[[], Optional[str]]] = None,
                 network_fn: Optional[Callable[[], Optional[int]]] = None) -> None:
        self._db = db
        self._config = config
        self._bus = bus
        self._pm = ping_manager
        self._clock = clock
        # The network this PC is on (tnt.networks; None: unknown): every row is opened with it. Without it nothing is tagged.
        self._network_fn = network_fn
        # While this returns True (the Engine passes "a speed test is running") misses do not
        # start a NEW outage: saturating a slow uplink can delay 1200-byte echoes past the
        # timeout and would otherwise log a false outage every 15 minutes. Open outages still
        # recover normally and real failures are detected as soon as the test ends.
        self._suppress_new = suppress_new
        self.suppressed_misses = 0
        # The default gateway right now (the Engine passes a netinfo lookup; None: not known), for
        # the note of an outage that recovers on another network than it began on.
        self._gateway_fn = gateway_fn
        self._net_gateway: Optional[str] = None     # the last default gateway this PC had
        self._offline = False                        # net.changed: no default gateway and no internet adapter
        self._outage_net: Dict[int, Dict[str, Any]] = {}    # open outage id -> {"gateway", "offline"}
        self._lock = threading.RLock()
        self._states: Dict[int, _TargetState] = {}
        self._totals: Dict[str, Dict[str, Any]] = {}   # group -> open total outage row
        self._last_total_end: Dict[str, float] = {}     # group -> end_ts of the last closed total
        self._gap_end_ts: Optional[float] = None        # end of the last monitoring gap (on_sample: stale echoes)
        self._hosts: Dict[int, str] = {}                # target id -> host (kept after removal)
        self._running = False
        self._stopped = False
        self._unsubs: List[Callable[[], None]] = []
        self.startup_info: Dict[str, Any] = {}
        # clear_history: bumped by every clear; an outage.start/end computed before it is not published after it
        self._clear_gen = 0
        self._flag_lock = threading.Lock()              # serialises PingManager.set_in_outage (_apply_in_outage)
        self.last_clear_info: Dict[str, Any] = {}       # what the last clear_history() deleted (rows, earliest_ts)

    def _backfill_hosts(self) -> None:
        try:
            with self._lock:
                known = dict(self._hosts)
            n = backfill_outage_hosts(self._db, getattr(self._pm, "raw_log", None), known)
            if n:
                log.info("backfilled the host of %d older outage rows", n)
        except Exception:  # noqa: BLE001
            log.exception("outage host backfill failed")

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        """Close stale outages / insert a gap row, then subscribe to ping samples."""
        with self._lock:
            if self._running:
                return
            self._stopped = False
            keep = [st.outage["id"] for st in self._states.values() if st.outage]
            keep += [t["id"] for t in self._totals.values()]
            try:
                self.startup_info = close_stale_outages(self._db, self._clock(), keep)
            except Exception:  # noqa: BLE001
                log.exception("closing stale outages failed")
            self._running = True
        if self._gateway_fn is not None:
            gateway = self._live_gateway()
            with self._lock:
                self._net_gateway = self._net_gateway or gateway
        # older outage rows get their host filled in from the targets table / raw ping log;
        # a background job because reading a day's log takes a moment
        threading.Thread(target=self._backfill_hosts, name="tnt-outage-host-backfill", daemon=True).start()
        unsubs: List[Callable[[], None]] = []
        try:
            u = self._pm.add_sample_listener(self.on_sample)
            if callable(u):
                unsubs.append(u)
        except Exception:  # noqa: BLE001
            log.exception("could not register the sample listener")
        add_removal = getattr(self._pm, "add_removal_listener", None)
        if callable(add_removal):
            try:
                u = add_removal(self._on_removal_event)
                if callable(u):
                    unsubs.append(u)
            except Exception:  # noqa: BLE001
                log.exception("could not register the removal listener")
        add_ip = getattr(self._pm, "add_ip_listener", None)
        if callable(add_ip):
            try:
                u = add_ip(self.on_target_ip_changed)
                if callable(u):
                    unsubs.append(u)
            except Exception:  # noqa: BLE001
                log.exception("could not register the address change listener")
        with self._lock:
            self._unsubs.extend(unsubs)
        log.info("outage tracker started (thresholds miss=%d recover=%d)",
                 self._threshold("outage.miss_threshold", 3), self._threshold("outage.recover_threshold", 3))

    def stop(self) -> None:
        """Unsubscribe and persist the missed counters of open outages.

        Open outages are deliberately left open: the next start closes them at
        the Engine's ``last_heartbeat`` with note ``"service stopped"``.
        """
        with self._lock:
            self._running = False
            self._stopped = True
            unsubs, self._unsubs = self._unsubs, []
            for st in self._states.values():
                if st.outage:
                    try:
                        self._db.update_outage_missed(int(st.outage["id"]), int(st.outage["missed"]),
                                                      int(st.outage.get("sent") or 0) or None)
                    except Exception:  # noqa: BLE001
                        log.exception("persisting missed count failed")
        for u in unsubs:
            try:
                u()
            except Exception:  # noqa: BLE001
                log.exception("unsubscribe failed")
        log.info("outage tracker stopped")

    def _suppressed(self) -> bool:
        fn = self._suppress_new
        if fn is None:
            return False
        try:
            return bool(fn())
        except Exception:  # noqa: BLE001
            return False

    def on_monitoring_gap(self, start_ts: float, end_ts: float, note: str = "not monitoring") -> Dict[str, Any]:
        """The service did not sample between *start_ts* and *end_ts* (sleep, hibernate, pause).

        Nothing can be known about that hole, so: every open target/total outage is closed
        at *start_ts* with *note*, all miss/recovery counters are reset (the next samples
        start a fresh run), and a ``kind="gap"`` row covers the hole so the timeline shows
        grey instead of a green bar or a spuriously long yellow/red span.  Each target's first
        sample after the gap is dropped when it is stamped before *end_ts*: it is the echo that
        was in flight while monitoring stopped (see :meth:`on_sample`).
        """
        effects: List[_Effect] = []
        info: Dict[str, Any] = {"closed": 0, "gap_id": None, "start_ts": start_ts, "end_ts": end_ts, "note": note}
        try:
            with self._lock:
                if self._stopped:
                    return info
                self._gap_end_ts = _finite(end_ts)
                for st in self._states.values():
                    if st.outage is not None:
                        self._close_target(st, start_ts, note, effects, notify_pm=True)
                        info["closed"] += 1
                    st.consecutive_missed = 0
                    st.consecutive_ok = 0
                    st.first_miss_ts = None
                    st.first_ok_ts = None
                    st.sampled_since_gap = False
                for group in list(self._totals):
                    self._close_total(group, start_ts, note, effects)
                    info["closed"] += 1
                if end_ts - start_ts >= 1.0:
                    gid = int(self._db.open_outage("gap", None, float(start_ts), note=note, **self._network_kw()))
                    self._db.close_outage(gid, float(end_ts), 0, note)
                    info["gap_id"] = gid
        except Exception:  # noqa: BLE001
            log.exception("monitoring gap handling failed")
        self._run_effects(effects)
        log.info("monitoring gap %.0f s (%s): closed %d outage(s), gap row %s",
                 end_ts - start_ts, note, info["closed"], info["gap_id"])
        return info

    # -- sample processing -------------------------------------------------
    def on_sample(self, target_view: Dict[str, Any], sample: "Sample") -> None:
        """Feed one ping result. Called on the ping worker thread after the sample is recorded."""
        try:
            ts, ok = _sample_fields(sample)
            target_id = int(target_view["id"])
        except Exception as exc:  # noqa: BLE001 - bad data, not a code path worth a traceback
            log.warning("ignoring malformed sample %r for target %r: %s", sample,
                        target_view.get("id") if isinstance(target_view, dict) else target_view, exc)
            return
        effects: List[_Effect] = []
        try:
            with self._lock:
                if self._stopped:
                    return
                prev = self._states.get(target_id)
                prev_kind = prev.kind if prev is not None else None
                st = self._state_for(target_id, target_view)
                if not st.sampled_since_gap:
                    st.sampled_since_gap = True
                    if self._gap_end_ts is not None and ts < self._gap_end_ts:
                        # The echo that was in flight while monitoring stopped: a sample is stamped when
                        # its request is sent, so one that went out before a sleep comes back after the
                        # wake dated before it, after the gap has already reset every run.  Counting it
                        # would start a new miss run there, and two misses while the Wi-Fi re-associates
                        # would open an outage back-dated across the whole sleep.  It says nothing about
                        # the network after the gap.  Only the first sample per target is looked at: a
                        # worker has one echo out at a time, so later ones are fresh whatever the clock
                        # says (w32time setting it back after the wake must not blind the tracker).
                        log.info("ignoring a %s from target %s sent %.0f s before the monitoring gap ended "
                                 "(it was in flight across the gap)", "reply" if ok else "miss", target_id,
                                 self._gap_end_ts - ts)
                        return
                st.last_sample_ts = ts
                if st.outage is not None:
                    # every ping while the outage is open, answered or not: the denominator of
                    # the missed percentage (the recovery run is taken off again on close)
                    st.outage["sent"] = int(st.outage.get("sent") or 0) + 1
                changed = False
                recovered_ts: Optional[float] = None
                recovered_group: Optional[str] = None
                # Only this target's group can flip; evaluating the other group too would let
                # an unrelated change close its total while a member is momentarily stale.
                groups: Tuple[str, ...] = (st.kind,)
                if prev_kind is not None and prev_kind != st.kind and st.outage is not None:
                    # a target in outage moved between groups (hostname now resolves to the
                    # other address class): both groups need a look
                    changed = True
                    groups = (prev_kind, st.kind)
                if ok:
                    if st.consecutive_ok == 0:
                        st.first_ok_ts = ts
                    st.consecutive_ok += 1
                    st.consecutive_missed = 0
                    st.first_miss_ts = None
                    if st.outage is not None and st.consecutive_ok >= self._threshold("outage.recover_threshold", 3):
                        end_ts = st.first_ok_ts if st.first_ok_ts is not None else ts
                        # the recovery run starts at end_ts, so its pings are not part of the outage
                        self._close_target(st, end_ts, None, effects, notify_pm=True,
                                           recovery_samples=st.consecutive_ok)
                        changed = True
                        recovered_ts, recovered_group = end_ts, st.kind
                    elif st.outage is None and st.kind in self._totals:
                        # A healthy target (added or resumed) while its group has an open
                        # total: the group is provably not all down -> re-evaluate now.
                        changed = True
                        recovered_ts, recovered_group = ts, st.kind
                else:
                    if st.outage is None and self._suppressed():
                        # a speed test is saturating the link: do not let these misses
                        # accumulate towards a new outage (see __init__)
                        self.suppressed_misses += 1
                        st.consecutive_missed = 0
                        st.first_miss_ts = None
                        st.consecutive_ok = 0
                        st.first_ok_ts = None
                        return
                    if st.consecutive_missed == 0:
                        st.first_miss_ts = ts
                    st.consecutive_missed += 1
                    st.consecutive_ok = 0
                    st.first_ok_ts = None
                    if st.outage is not None:
                        st.outage["missed"] += 1
                        if st.outage["missed"] % MISSED_PERSIST_EVERY == 0:
                            self._persist_missed(st.outage)
                    elif st.consecutive_missed >= self._threshold("outage.miss_threshold", 3):
                        start_ts = st.first_miss_ts if st.first_miss_ts is not None else ts
                        self._open_target(st, start_ts, effects)
                        changed = True
            if changed:
                views = self._safe_targets()
                if views is not None:
                    with self._lock:
                        if not self._stopped:
                            self._evaluate_totals(views, ts, recovered_ts, recovered_group, None, effects,
                                                  groups=groups)
        except Exception:  # noqa: BLE001
            log.exception("outage processing failed for target %s", target_id)
        self._run_effects(effects)

    def on_target_removed(self, target_id: int) -> None:
        """Close the target's open outage with note ``"target removed"`` and re-evaluate totals."""
        try:
            target_id = int(target_id)
        except (TypeError, ValueError):
            return
        now = float(self._clock())
        effects: List[_Effect] = []
        try:
            with self._lock:
                st = self._states.pop(target_id, None)
                if st is not None and st.outage is not None:
                    self._close_target(st, now, "target removed", effects, notify_pm=False)
                # only the removed target's group can flip; if it was never sampled its
                # group is unknown, so look at both
                groups: Tuple[str, ...] = (st.kind,) if st is not None else GROUPS
            views = self._safe_targets()
            if views is not None:
                views = [v for v in views if _view_id(v) != target_id]
                with self._lock:
                    # A total that only becomes "all down" because a healthy member left
                    # starts at the removal moment (the group was reachable until then).
                    self._evaluate_totals(views, now, None, None, "target removed", effects,
                                          min_start_ts=now, groups=groups)
        except Exception:  # noqa: BLE001
            log.exception("handling removal of target %s failed", target_id)
        self._run_effects(effects)

    def _on_removal_event(self, target: Any) -> None:
        """Adapter for ``PingManager.add_removal_listener`` (id or view dict). Never raises."""
        try:
            tid = target.get("id") if isinstance(target, dict) else target
            if tid is None:
                return
            self.on_target_removed(int(tid))
        except Exception:  # noqa: BLE001 - runs on the PingManager's thread
            log.exception("ignoring malformed target removal %r", target)

    def on_target_ip_changed(self, view: Dict[str, Any], old_ip: Optional[str], new_ip: Optional[str],
                             reason: Optional[str] = None) -> None:
        """A target now pings another address (``PingManager.add_ip_listener``). Never raises.

        Only a switch *caused by a network change* (*reason* set) counts: the open outage was about
        the old address, so it is closed now with *reason* as its note, the target's miss/recovery
        run restarts and its group's total is re-evaluated.  Without a reason (a host name's
        periodic lookup rotated) nothing happens.
        """
        if not reason:
            return
        try:
            tid = int(view["id"])
        except (KeyError, TypeError, ValueError):
            return
        now = float(self._clock())
        effects: List[_Effect] = []
        try:
            with self._lock:
                st = self._states.get(tid)
                if self._stopped or st is None:
                    return
                group = st.kind
                closed = st.outage is not None
                if closed:
                    self._close_target(st, now, reason, effects, notify_pm=True)
                st.consecutive_missed = 0
                st.consecutive_ok = 0
                st.first_miss_ts = None
                st.first_ok_ts = None
                st.host = _pinged_host(view) or st.host
                self._hosts[tid] = st.host
            if closed:
                views = self._safe_targets()
                if views is not None:
                    with self._lock:
                        if not self._stopped:
                            self._evaluate_totals(views, now, now, group, reason, effects, groups=(group,))
            log.info("target %s now pings %s instead of %s (%s)", tid, new_ip or "nothing", old_ip, reason)
        except Exception:  # noqa: BLE001
            log.exception("handling the address change of target %s failed", tid)
        self._run_effects(effects)

    def on_network_change(self, data: Optional[Dict[str, Any]] = None) -> None:
        """``net.changed`` (the Engine, on the network watcher's thread; quick, never raises).

        A default gateway other than the last one this PC had closes every open target and total
        outage at ``data["ts"]`` with note ``"network changed"`` and restarts every miss/recovery
        run (those outages were about the network it left).  No default gateway and no internet
        adapter marks the open outages, and the ones that begin before the connection is back,
        for the note ``"no network connection"`` should they end without one of their own.
        """
        try:
            data = data or {}
            gateway = str(data.get("default_gateway") or "") or None
            offline = gateway is None and not data.get("internet_nic")
            ts = _finite(data.get("ts"))
            ts = float(self._clock()) if ts is None else ts
        except Exception:  # noqa: BLE001 - bad data, not a code path worth a traceback
            log.warning("ignoring a malformed network change %r", data)
            return
        effects: List[_Effect] = []
        closed = 0
        previous: Optional[str] = None
        try:
            with self._lock:
                if self._stopped:
                    return
                previous = self._net_gateway or (str(data.get("previous_gateway") or "") or None)
                if gateway is not None and previous is not None and gateway != previous:
                    for st in self._states.values():
                        if st.outage is not None:
                            self._close_target(st, ts, NETWORK_CHANGED_NOTE, effects, notify_pm=True)
                            closed += 1
                        st.consecutive_missed = 0
                        st.consecutive_ok = 0
                        st.first_miss_ts = None
                        st.first_ok_ts = None
                    for group in list(self._totals):
                        self._close_total(group, ts, NETWORK_CHANGED_NOTE, effects)
                        closed += 1
                if gateway is not None:
                    self._net_gateway = gateway
                self._offline = offline
                if offline:
                    open_ids = [int(st.outage["id"]) for st in self._states.values() if st.outage is not None]
                    open_ids += [int(t["id"]) for t in self._totals.values()]
                    for oid in open_ids:
                        self._outage_net.setdefault(oid, {"gateway": self._net_gateway})["offline"] = True
        except Exception:  # noqa: BLE001
            log.exception("handling a network change in the outage tracker failed")
        self._run_effects(effects)
        if closed:
            log.info("this PC moved from gateway %s to %s: closed %d outage(s) of the network it left",
                     previous, gateway, closed)

    def on_network_id_change(self, event: Dict[str, Any]) -> None:
        """``tnt.networks``: this PC's network is another one since ``event["ts"]`` (also where the default gateway address stayed
        the same: two sites behind 192.168.1.1).  Every open target and total outage that began before that moment was about the
        network left behind and closes then with ``"network changed"``; on an immediate switch (``late`` false) every
        miss/recovery run starts afresh.  A late one (the router's MAC arrived after the switch) leaves the outages that opened
        since the change alone: they are the new network's.  Never raises."""
        try:
            ts = _finite((event or {}).get("ts"))
            ts = float(self._clock()) if ts is None else ts
            late = bool((event or {}).get("late"))
        except Exception:  # noqa: BLE001
            log.warning("ignoring a malformed network id change %r", event)
            return
        effects: List[_Effect] = []
        closed = 0
        try:
            with self._lock:
                if self._stopped:
                    return
                for st in self._states.values():
                    if st.outage is not None and float(st.outage["start_ts"]) < ts:
                        self._close_target(st, ts, NETWORK_CHANGED_NOTE, effects, notify_pm=True)
                        closed += 1
                        st.consecutive_missed = st.consecutive_ok = 0
                        st.first_miss_ts = st.first_ok_ts = None
                    elif not late:
                        st.consecutive_missed = st.consecutive_ok = 0
                        st.first_miss_ts = st.first_ok_ts = None
                for group in list(self._totals):
                    if float(self._totals[group]["start_ts"]) < ts:
                        self._close_total(group, ts, NETWORK_CHANGED_NOTE, effects)
                        closed += 1
        except Exception:  # noqa: BLE001
            log.exception("handling a network id change in the outage tracker failed")
        self._run_effects(effects)
        if closed:
            log.info("this PC is on network %s since %.0f (was %s): closed %d outage(s) of the network it left",
                     (event or {}).get("new_id"), ts, (event or {}).get("old_id"), closed)

    def _network_kw(self) -> Dict[str, Any]:
        """``{"network_id": id}`` for an outage row opened now, or ``{}`` without *network_fn* (the row is not tagged)."""
        fn = self._network_fn
        if fn is None:
            return {}
        try:
            nid = fn()
        except Exception:  # noqa: BLE001
            log.debug("the current network id could not be read", exc_info=True)
            nid = None
        return {"network_id": nid if isinstance(nid, int) and not isinstance(nid, bool) else None}

    def _live_gateway(self) -> Optional[str]:
        fn = self._gateway_fn
        if fn is None:
            return None
        try:
            gateway = fn()
            return str(gateway) if gateway else None
        except Exception:  # noqa: BLE001
            log.debug("default gateway lookup failed", exc_info=True)
            return None

    def _network_note(self, outage_id: int) -> Optional[str]:
        """The note of an outage that ends without one of its own (call with the lock held):
        ``"network changed"`` when this PC's default gateway now is another than when it began,
        ``"no network connection"`` when it was open while this PC had none; else ``None``."""
        mark = self._outage_net.get(int(outage_id))
        if mark is None:
            return None
        now = self._live_gateway()
        if now:
            # something answers again, so this is the network the PC is on: outages that begin from here on are about it
            self._net_gateway = now
        began = mark.get("gateway")
        if began and now and now != began:
            return NETWORK_CHANGED_NOTE
        return NO_NETWORK_NOTE if mark.get("offline") else None

    # -- clear history (Settings; Engine.clear_history) ---------------------
    def clear_history(self, since_ts: Optional[float]) -> int:
        """Forget the outages recorded in ``[since_ts, now]`` (None: all of them).  Returns the outage rows deleted.

        Under the tracker's lock, database first (``Database.delete_outages_since``: every row of every kind that is open
        or ended at or after *since_ts*, and the ``outage`` events rows from *since_ts* on, in one transaction; a failure
        raises and leaves the tracker as it was), then the memory of every open outage: each target's open outage and
        its miss/recovery run, the open totals, the network marks and the last total ends.  An open outage is always in
        the span, so it goes: nothing is closed or updated afterwards (no write into a missing row), the PingManager
        is told the target is no longer in an outage (its light stops being red), and an ``outage.start``/``outage.end``
        computed before the clear is not published after it.  A target still down simply opens a fresh outage after
        ``outage.miss_threshold`` more misses.  ``last_clear_info`` is ``{"rows", "earliest_ts"}``: ``earliest_ts`` is the
        earliest start of an outage it deleted (one that straddles *since_ts* began before it), None when none was."""
        since = None if since_ts is None else float(since_ts)
        info: Dict[str, Any] = {}
        with self._lock:
            affected = [tid for tid, st in self._states.items() if st.outage is not None]
            deleted = int(self._db.delete_outages_since(since, info=info))
            self.last_clear_info = {"rows": deleted, "earliest_ts": info.get("earliest_ts")}
            self._clear_gen += 1
            for st in self._states.values():
                st.outage = None
                st.consecutive_missed = st.consecutive_ok = 0
                st.first_miss_ts = st.first_ok_ts = None
            totals = len(self._totals)
            self._totals.clear()
            self._outage_net.clear()
            self._last_total_end.clear()
        for tid in affected:
            try:
                self._apply_in_outage(tid)
            except Exception:  # noqa: BLE001
                log.exception("turning off the outage flag of target %s failed", tid)
        log.info("outage history cleared %s: %d row(s); %d open target and %d open total outage(s) forgotten",
                 "entirely" if since is None else f"from {since:.0f}", deleted, len(affected), totals)
        return deleted

    # -- queries -----------------------------------------------------------
    def status(self) -> Dict[str, Any]:
        """Summary for the status endpoint / Outages tile."""
        now = float(self._clock())
        with self._lock:
            # snapshot under the lock, decorate (which may touch the db) outside it
            open_rows = [dict(st.outage) for st in self._states.values() if st.outage]
            open_rows += [dict(t) for t in self._totals.values()]
            total = self._totals.get("internet") or self._totals.get("local")
            total_row = dict(total) if total else None
            running = self._running
        hosts: Dict[int, Optional[str]] = {}
        active = [self._decorate(r, now, hosts) for r in open_rows]
        active.sort(key=lambda o: (o["start_ts"], o["id"]), reverse=True)
        total_active = self._decorate(total_row, now, hosts) if total_row else None
        count_24h = 0
        last: Optional[Dict[str, Any]] = None
        try:
            count_24h = len(self._db.list_outages(now - 86400, now, kinds=OUTAGE_KINDS))
            rows = self._db.list_outages(0, now, kinds=OUTAGE_KINDS, limit=1)
            last = self._decorate(rows[0], now, hosts) if rows else None
        except Exception:  # noqa: BLE001
            log.exception("outage status query failed")
        return {
            "active": active,
            "total_active": total_active,
            "count_24h": count_24h,
            "last": last,
            "monitoring": bool(running and self._monitoring_active(now)),
        }

    def list(self, start_ts: float, end_ts: float) -> List[Dict[str, Any]]:  # noqa: A003 - contract name
        """Outage rows overlapping ``[start_ts, end_ts]`` (newest first) + ``host``, ``duration_s``, ``open``.

        Unusable bounds (None, NaN, non-numeric) fall back to the last 24 h.
        """
        now = float(self._clock())
        start = _finite(start_ts)
        end = _finite(end_ts)
        if start is None or end is None:
            log.warning("outages.list: bad range %r..%r, using the last 24 h", start_ts, end_ts)
            start, end = now - 86400.0, now
        if end < start:
            start, end = end, start          # reversed bounds would silently match nothing
        rows = self._db.list_outages(start, end)
        hosts: Dict[int, Optional[str]] = {}
        return [self._decorate(r, now, hosts) for r in rows]

    def timeline(self, hours: float = 24, now: Optional[float] = None) -> Dict[str, Any]:
        """Segments for the timeline canvas, clipped to ``[now - hours*3600, now]``.

        Bad *hours* (non-numeric, non-positive, NaN/inf) fall back to 24; values above
        :data:`MAX_TIMELINE_HOURS` are clamped so the payload is always finite JSON.
        """
        now_f = _finite(now) if now is not None else None
        now = now_f if now_f is not None else float(self._clock())
        hours_f = _finite(hours)
        hours = 24.0 if hours_f is None or hours_f <= 0 else min(hours_f, MAX_TIMELINE_HOURS)
        start = now - hours * 3600.0
        segments: List[Dict[str, Any]] = []
        total_segments: List[Dict[str, Any]] = []
        gaps: List[Dict[str, Any]] = []
        seen_targets: Dict[int, None] = {}
        hosts: Dict[int, Optional[str]] = {}
        rows = sorted(self._db.list_outages(start, now), key=lambda r: (float(r["start_ts"]), int(r["id"])))
        with self._lock:
            # live counters: the db copy of an open outage's `missed` lags by up to 9 misses
            live_missed = {int(st.outage["id"]): int(st.outage["missed"])
                           for st in self._states.values() if st.outage}
            live_sent = {int(st.outage["id"]): st.outage.get("sent")
                         for st in self._states.values() if st.outage}
        interval_s = self._ping_interval()
        for r in rows:
            raw_end = r.get("end_ts")
            seg_start = max(float(r["start_ts"]), start)
            seg_end = min(now if raw_end is None else float(raw_end), now)
            if seg_end < seg_start:
                continue
            kind = r.get("kind")
            if kind == "gap":
                gaps.append({"start_ts": seg_start, "end_ts": seg_end})
                continue
            tid = r.get("target_id")
            tid = int(tid) if tid is not None else None
            rid = int(r["id"])
            seg = {
                "id": rid,
                "kind": kind,
                "target_id": tid,
                "host": r.get("host") or self._host_for(tid, hosts),
                "start_ts": seg_start,
                "end_ts": seg_end,
                "open": raw_end is None,
                "missed": live_missed[rid] if raw_end is None and rid in live_missed else int(r.get("missed") or 0),
            }
            # the percentage covers the whole outage, not just the part inside the window
            full_duration = (now if raw_end is None else float(raw_end)) - float(r["start_ts"])
            seg["sent"], seg["missed_pct"], seg["sent_estimated"] = missed_percentage(
                kind, seg["missed"], live_sent.get(rid) if raw_end is None and rid in live_sent else r.get("sent"),
                full_duration, interval_s)
            if kind == "target":
                segments.append(seg)
                if tid is not None:
                    seen_targets.setdefault(tid, None)
            else:
                total_segments.append(seg)
        targets: List[Dict[str, Any]] = []
        listed: Dict[int, None] = {}
        for v in self._safe_targets() or []:
            tid = _view_id(v)
            if tid is None:
                continue
            listed[tid] = None
            targets.append({"id": tid, "host": v.get("host"), "kind": v.get("kind")})
        for tid in seen_targets:
            if tid not in listed:
                targets.append({"id": tid, "host": self._host_for(tid, hosts), "kind": self._kind_for(tid)})
        try:
            cleared = _history.timeline_spans(self._db, start, now)
        except Exception:  # noqa: BLE001 - never fails the timeline over its bookkeeping
            log.exception("reading the cleared history spans failed")
            cleared = []
        return {
            "start_ts": start,
            "end_ts": now,
            "hours": hours,
            "segments": segments,
            "total_segments": total_segments,
            "gaps": gaps,
            "targets": targets,
            "cleared": cleared,
        }

    # -- internals: state changes (call with the lock held) ----------------
    def _state_for(self, target_id: int, view: Dict[str, Any]) -> _TargetState:
        st = self._states.get(target_id)
        host = _pinged_host(view)
        kind = view.get("kind")
        if st is None:
            st = _TargetState(target_id=target_id, host=str(host or target_id))
            self._states[target_id] = st
        if host and st.outage is None:
            # an open outage stays about the address it was opened for
            st.host = str(host)
        if kind in GROUPS:
            st.kind = kind
        self._hosts[target_id] = st.host
        return st

    def _threshold(self, key: str, default: int) -> int:
        try:
            value = int(self._config.get(key, default))
        except Exception:  # noqa: BLE001
            value = default
        return max(1, value)

    def _persist_missed(self, outage: Dict[str, Any]) -> None:
        """Best-effort write of the live ``missed`` / ``sent`` counters (written again on close)."""
        try:
            self._db.update_outage_missed(int(outage["id"]), int(outage["missed"]),
                                          int(outage.get("sent") or 0) or None)
        except Exception:  # noqa: BLE001
            log.exception("persisting missed count of outage #%s failed", outage.get("id"))

    def _open_target(self, st: _TargetState, start_ts: float, effects: List[_Effect]) -> None:
        # The row insert must succeed before the in-memory outage exists (a failed insert
        # is retried on the next miss); the missed counter write is best-effort so a
        # failure there cannot leave the row open without a matching state.
        oid = int(self._db.open_outage("target", st.target_id, start_ts, host=st.host, **self._network_kw()))
        # the run that opened it was all misses, so sent == missed at this point
        st.outage = {
            "id": oid, "kind": "target", "target_id": st.target_id, "host": st.host, "start_ts": float(start_ts),
            "end_ts": None, "missed": int(st.consecutive_missed), "sent": int(st.consecutive_missed), "note": None,
        }
        self._outage_net[oid] = {"gateway": self._net_gateway, "offline": self._offline}
        if st.outage["missed"]:
            self._persist_missed(st.outage)
        log.warning("outage started: %s (target %d) since %.0f", st.host, st.target_id, start_ts)
        self._db_event("warning", f"Outage started: {st.host}", self._clock())
        effects.append(("in_outage", st.target_id, True))
        effects.append(("event", "outage.start", self._decorate(st.outage, self._clock()), self._clear_gen))

    def _close_target(self, st: _TargetState, end_ts: float, note: Optional[str],
                      effects: List[_Effect], notify_pm: bool, recovery_samples: int = 0) -> None:
        o = st.outage
        if o is None:
            return
        end_ts = max(float(end_ts), float(o["start_ts"]))
        sent = max(int(o["missed"]), int(o.get("sent") or 0) - max(0, int(recovery_samples)))
        if note is None:
            note = self._network_note(int(o["id"]))
        # db first: if the write fails the outage stays open in memory and the close is
        # retried on the next successful sample (consecutive_ok keeps growing, and so does
        # the sent counter, so sent - recovery_samples stays right)
        self._db.close_outage(int(o["id"]), end_ts, int(o["missed"]), note, sent=sent)
        self._outage_net.pop(int(o["id"]), None)
        o["sent"] = sent
        st.outage = None
        o["end_ts"] = end_ts
        o["note"] = note
        dur = _fmt_duration(end_ts - float(o["start_ts"]))
        log.warning("outage ended: %s (target %d) after %s, %d missed%s", st.host, st.target_id, dur,
                    o["missed"], f" ({note})" if note else "")
        self._db_event("info", f"Outage ended: {st.host} after {dur} ({o['missed']} missed)"
                       + (f" - {note}" if note else ""), self._clock())
        if notify_pm:
            effects.append(("in_outage", st.target_id, False))
        effects.append(("event", "outage.end", self._decorate(o, self._clock()), self._clear_gen))

    def _open_total(self, group: str, start_ts: float, effects: List[_Effect]) -> None:
        kind = f"total_{group}"
        oid = int(self._db.open_outage(kind, None, start_ts, **self._network_kw()))
        self._totals[group] = {
            "id": oid, "kind": kind, "target_id": None, "start_ts": float(start_ts),
            "end_ts": None, "missed": 0, "note": None,
        }
        self._outage_net[oid] = {"gateway": self._net_gateway, "offline": self._offline}
        log.warning("%s outage started: all %s targets down since %.0f", kind, group, start_ts)
        self._db_event("warning", f"All {group} targets are down", self._clock())
        effects.append(("event", "outage.start", self._decorate(self._totals[group], self._clock()), self._clear_gen))

    def _close_total(self, group: str, end_ts: float, note: Optional[str], effects: List[_Effect]) -> None:
        o = self._totals.get(group)
        if o is None:
            return
        end_ts = max(float(end_ts), float(o["start_ts"]))
        if note is None:
            note = self._network_note(int(o["id"]))
        self._db.close_outage(int(o["id"]), end_ts, int(o["missed"]), note)   # db first, see _close_target
        self._outage_net.pop(int(o["id"]), None)
        self._totals.pop(group, None)
        self._last_total_end[group] = end_ts
        o["end_ts"] = end_ts
        o["note"] = note
        dur = _fmt_duration(end_ts - float(o["start_ts"]))
        log.warning("%s outage ended after %s%s", o["kind"], dur, f" ({note})" if note else "")
        self._db_event("info", f"{group.capitalize()} connectivity restored after {dur}"
                       + (f" - {note}" if note else ""), self._clock())
        effects.append(("event", "outage.end", self._decorate(o, self._clock()), self._clear_gen))

    def _evaluate_totals(self, views: List[Dict[str, Any]], ref_ts: float, recovered_ts: Optional[float],
                         recovered_group: Optional[str], note: Optional[str], effects: List[_Effect],
                         min_start_ts: Optional[float] = None, groups: Iterable[str] = GROUPS) -> None:
        """Open/close ``total_local`` / ``total_internet`` from the current per-target state.

        *views* is the PingManager's live target list (fetched outside the lock).
        Only *groups* (default: both) are examined - callers pass the group of
        the target whose state changed, because the other group's all-down
        status cannot have changed and re-checking it would let a member that
        is momentarily stale (worker delayed past the active window) close its
        total spuriously.  A total opens with ``start_ts = max(member outage
        starts)``, clamped to *min_start_ts* when given (used for removals) and
        never before the end of the group's previous total (the group was
        reachable at that moment).  It closes with ``end_ts = recovered_ts``
        when the change came from *recovered_group*, else *ref_ts*.
        """
        window = self._active_window()
        for group in groups:
            if group not in GROUPS:
                continue
            members: List[_TargetState] = []
            all_down = True
            for v in views:
                tid = _view_id(v)
                if tid is None or v.get("kind") != group or not v.get("enabled", True):
                    continue
                if not self._is_active(tid, v, ref_ts, window):
                    continue
                st = self._states.get(tid)
                if st is None or st.outage is None:
                    all_down = False
                else:
                    members.append(st)
            all_down = all_down and bool(members)
            current = self._totals.get(group)
            if all_down and current is None:
                start_ts = max(float(st.outage["start_ts"]) for st in members if st.outage)
                if min_start_ts is not None:
                    start_ts = max(start_ts, float(min_start_ts))
                start_ts = max(start_ts, self._last_total_end.get(group, start_ts))
                self._open_total(group, start_ts, effects)
            elif current is not None and not all_down:
                if recovered_ts is not None and recovered_group == group:
                    end_ts = recovered_ts
                else:
                    end_ts = ref_ts
                self._close_total(group, end_ts, note, effects)

    def _active_window(self) -> float:
        """Seconds without a sample after which a target stops counting as a group member.

        15 s per the contract, widened to two ping intervals plus the reply timeout
        when the configured interval is long, so a healthy target that simply has
        not ticked yet is not mistaken for an absent one (which would let a single
        down target open a false total).
        """
        try:
            interval = float(self._config.get("ping.interval_s", 1.0))
            timeout = float(self._config.get("ping.timeout_ms", 1000)) / 1000.0
        except Exception:  # noqa: BLE001
            return ACTIVE_WINDOW_S
        if not (interval > 0 and timeout >= 0):     # also rejects NaN
            return ACTIVE_WINDOW_S
        return max(ACTIVE_WINDOW_S, 2.0 * interval + timeout)

    def _is_active(self, target_id: int, view: Dict[str, Any], ref_ts: float,
                   window: float = ACTIVE_WINDOW_S) -> bool:
        last = view.get("last")
        last_ts = last.get("ts") if isinstance(last, dict) else None
        if last_ts is None:
            st = self._states.get(target_id)
            last_ts = st.last_sample_ts if st else None
        if last_ts is None:
            return False
        try:
            return (ref_ts - float(last_ts)) <= window
        except (TypeError, ValueError):
            return False

    def _monitoring_active(self, now: float) -> bool:
        try:
            if getattr(self._pm, "paused", False):
                return False
        except Exception:  # noqa: BLE001 - a broken property must not break /api/status
            log.exception("reading ping_manager.paused failed")
        window = self._active_window()
        for v in self._safe_targets() or []:
            tid = _view_id(v)
            if tid is None or not v.get("enabled", True):
                continue
            with self._lock:
                if self._is_active(tid, v, now, window):
                    return True
        return False

    # -- internals: helpers ------------------------------------------------
    def _decorate(self, row: Dict[str, Any], now: float,
                  hosts: Optional[Dict[int, Optional[str]]] = None) -> Dict[str, Any]:
        """Copy a db row / in-memory outage and add ``host``, ``duration_s``, ``open``.

        *hosts* is an optional per-call memo so decorating many rows of a removed
        target does not repeat the same db lookup for every row.
        """
        d = dict(row)
        tid = d.get("target_id")
        tid = int(tid) if tid is not None else None
        d["target_id"] = tid
        # the host stored on the row wins (it survives the target being removed)
        d["host"] = d.get("host") or self._host_for(tid, hosts)
        end = d.get("end_ts")
        d["open"] = end is None
        if end is None and tid is not None:
            with self._lock:
                st = self._states.get(tid)
                if st and st.outage and st.outage["id"] == d.get("id"):
                    d["missed"] = st.outage["missed"]
                    d["sent"] = st.outage.get("sent")
        d["missed"] = int(d.get("missed") or 0)
        d["duration_s"] = round(max(0.0, (now if end is None else float(end)) - float(d["start_ts"])), 3)
        d["sent"], d["missed_pct"], d["sent_estimated"] = missed_percentage(
            d.get("kind"), d["missed"], d.get("sent"), d["duration_s"], self._ping_interval())
        return d

    def _ping_interval(self) -> float:
        try:
            v = float(self._config.get("ping.interval_s", 1.0))
            return v if v > 0 else 1.0
        except Exception:  # noqa: BLE001
            return 1.0

    def _host_for(self, target_id: Optional[int],
                  cache: Optional[Dict[int, Optional[str]]] = None) -> Optional[str]:
        if target_id is None:
            return None
        if cache is not None and target_id in cache:
            return cache[target_id]
        with self._lock:
            host = self._hosts.get(target_id)
        if not host:
            try:
                row = self._db.get_target(target_id)
            except Exception:  # noqa: BLE001
                row = None
            host = row["host"] if row else None
        if not host:
            # removed target: fall back to the host recorded on its outages
            try:
                host = self._db.last_outage_host(target_id)
            except Exception:  # noqa: BLE001
                host = None
        if cache is not None:
            cache[target_id] = host
        return host

    def _kind_for(self, target_id: int) -> str:
        with self._lock:
            st = self._states.get(target_id)
            if st is not None:
                return st.kind
        try:
            row = self._db.get_target(target_id)
        except Exception:  # noqa: BLE001
            row = None
        kind = row.get("kind") if row else None
        return kind if kind in GROUPS else "internet"

    def _safe_targets(self) -> Optional[List[Dict[str, Any]]]:
        """Live target views from the PingManager, or ``None`` if the call failed.

        ``None`` (not ``[]``) lets callers skip total evaluation rather than
        treat a transient failure as "no targets" and close an open total.
        """
        try:
            views = self._pm.targets()
            return [v for v in (views or []) if isinstance(v, dict)]
        except Exception:  # noqa: BLE001
            log.exception("ping_manager.targets() failed")
            return None

    def _db_event(self, level: str, message: str, ts: float) -> None:
        try:
            self._db.add_event(level, "outage", message, ts=ts)
        except Exception:  # noqa: BLE001
            log.exception("recording outage event failed")

    def _run_effects(self, effects: List[_Effect]) -> None:
        for effect in effects:
            kind, a, b = effect[0], effect[1], effect[2]
            try:
                if kind == "in_outage":
                    self._apply_in_outage(a)
                elif kind == "event":
                    if len(effect) > 3 and effect[3] != self._clear_gen:
                        continue                # the outage it announces was cleared meanwhile (clear_history)
                    self._bus.publish(a, b, ts=float(self._clock()))
            except Exception:  # noqa: BLE001
                log.exception("outage effect %s failed", kind)

    def _apply_in_outage(self, target_id: Any) -> None:
        """Tell the PingManager whether *target_id* is in an open outage *now* (its red light).  The flag is read and
        handed over under ``_flag_lock``: an effect computed before a clear can never turn the light red again after
        :meth:`clear_history` turned it off.  The tracker's own lock is not held while calling into the PingManager."""
        with self._flag_lock:
            with self._lock:
                st = self._states.get(int(target_id))
                flag = bool(st is not None and st.outage is not None)
            self._pm.set_in_outage(target_id, flag)


def _view_id(view: Dict[str, Any]) -> Optional[int]:
    try:
        return int(view["id"])
    except (KeyError, TypeError, ValueError):
        return None
