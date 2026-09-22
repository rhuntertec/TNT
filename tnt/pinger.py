"""Continuous ping monitoring.

One daemon worker thread per target pings on a fixed, aligned schedule
(``next = start + n * interval``; if a tick falls behind the loop skips forward to the
next slot, so the schedule never drifts). Every tick records a :class:`Sample` into a
per-target ring buffer, updates the consecutive-miss/ok counters, feeds the per-minute
aggregator (flushed to ``db.upsert_ping_minute`` on minute change, stop and remove)
and the daily raw CSV log, then publishes ``ping.sample`` and calls the registered
sample listeners *outside* the target lock.

Payload size (``config.ping_bytes``), ``ping.timeout_ms``, ``ping.ttl``,
``ping.interval_s`` and ``ping.resolve_interval_s`` are read from :class:`Config` on
every tick, so the loaded/unloaded toggle and every other ping setting apply
immediately.

Contract gaps and small additions (documented as required by the contract):

* ``RawPingLog.__init__`` also accepts ``clock`` (used to decide when a flush is due,
  which day is "today" for :meth:`RawPingLog.trim` and which stale files to compress)
  and ``flush_interval_s``; the daily file a row goes to is decided by the row's own
  ``ts``. ``.csv`` files of earlier days still lying around at open (the service was
  stopped over midnight) are gzipped in the background as well. If a ``.csv.gz`` for
  that day already exists the new data is appended as a further gzip member (valid
  multi-member gzip, readable with ``gzip.open``). ``wait_background(timeout)`` joins
  the compression threads (used by tests and ``close``). Flushing happens on the first
  write once ``flush_interval_s`` elapsed, when the buffer holds 200 rows, on rollover,
  when monitoring is paused, when a target is removed and on ``close`` — there is no
  timer thread. The log never
  rolls backwards: a row dated before the currently open day is written to the current
  file (re-opening yesterday's file would race its background gzip). ``close`` accepts
  ``wait_background_s`` so a shutdown can bound the gzip join.
* The worker re-anchors its schedule when the wall clock is stepped backwards (NTP)
  instead of sleeping through the jump, and persists its own partial minute when it
  exits — so a worker that outlives the bounded join in ``stop()``/``remove_target()``
  (it was inside a long ping timeout) loses nothing; a late sample for a target that
  has already been removed is dropped (not published, not persisted). A late sample
  recorded after ``stop()`` re-opens the raw log, so the exiting worker flushes and
  closes it again. When the manager created the ``IcmpPinger`` itself, ``stop()``
  closes it only once the last worker has exited (a stuck worker closes it on its way
  out) — closing ICMP handles under a running ``IcmpSendEcho2`` is never attempted.
* ``set_paused(True)`` also persists every target's partial minute (the history
  endpoint reads the db directly and would otherwise miss the last minute before the
  pause until monitoring resumes); the upsert accumulates, nothing is double counted.
* ``validate_host`` canonicalises IP literals (``2606:4700:4700:0:0:0:0:1111`` →
  ``2606:4700:4700::1111``) so the same address spelled differently is one target.
* ``PingManager.__init__`` accepts an optional ``resolver`` callable
  (``host -> ip | None``) so tests can script DNS; the default is ``tnt.icmp.resolve_routable``
  (IPv4 first, IPv6 first only on an IPv6-only host - ``netinfo.prefers_ipv4()``).
  ``pinger`` and ``raw_log`` are created lazily (``tnt.icmp.IcmpPinger`` /
  ``RawPingLog(paths.ping_logs_dir())``) when not injected. The instances are exposed
  as ``.pinger`` and ``.raw_log`` (the Engine needs ``raw_log.trim`` for retention).
* Additions to the public surface: ``set_in_outage(target_id, flag)`` (used by the
  OutageTracker), ``add_removal_listener(fn(target_id)) -> unsubscribe``,
  ``tick(target_id) -> Sample | None`` (runs one worker iteration synchronously,
  deterministic driving for tests), ``worker_alive(target_id) -> bool | None``
  (used by diagnostics) and the ``running`` property.
* Every worker thread owns the ``threading.Event`` it was started with: a worker
  that outlives the bounded join in ``stop()`` still exits after its current ping even
  if ``start()`` has meanwhile started a fresh worker for the same target, so there is
  never more than one live worker per target for longer than one ping timeout.
* When a *re*-resolve of a hostname fails but an IP is already known, the worker
  keeps pinging the last known IP (the view shows ``resolved=False`` plus
  ``resolve_error``) and retries the lookup every 5 s. A target that has never
  resolved records a miss (``rtt_ms=None``) on every tick and retries the lookup
  every tick, exactly as the contract says.
* ``tnt.netinfo`` is imported lazily through ``importlib`` (it may not exist yet, and
  tests can monkeypatch ``sys.modules``). If it is missing or fails, ``kind`` falls back
  to ``ipaddress`` (private / link-local / loopback -> ``local``, else ``internet``)
  and ``load_defaults`` simply skips the gateway.
* Window/day statistics report ``None`` for ``loss_pct``/``avg_ms``/``min_ms``/
  ``max_ms``/``jitter_ms`` when there is no sample to compute them from (same
  convention as ``db.ping_summary``). Jitter with a single successful sample is 0.0.
* ``minute_ts`` is the sample timestamp floored to the minute in UTC; minute
  boundaries coincide with local-time minute boundaries for every real time zone.
* The traffic light is ``grey`` while paused, when the target has no sample yet, or
  when no sample falls inside the threshold window.
* Network changes (``on_network_change``, called by the Engine for ``net.changed``): every
  hostname target and the ``gateway`` alias re-resolve on their next tick (a lookup the change
  overtook is thrown away and repeated), and ``kind`` is recomputed when the local subnets
  changed. The alias is also looked up at least every ``network.poll_s`` and 2 s after a miss,
  so it follows a new default gateway even before the watcher reports it. Without a default
  gateway ``resolve_error`` says "this machine has no default gateway right now" and what
  happens depends on why it is gone. *Lost* (Wi-Fi dropped, a cable pulled, a router reboot
  that took the link down, a lease lost - the adapter it belonged to is down, gone, without an
  address or on 169.254.x.x): the alias keeps pinging the last gateway, so the misses are
  recorded and a local outage is logged exactly as before network-change awareness.
  *Configured away* (that adapter is still up with a usable address and no gateway: a static
  bench address, the DHCP server tool, a lease without a router) or never had one: the alias
  stops pinging, its IP is cleared, no sample is recorded, its light is grey. While it has no
  gateway it looks again every ``network.poll_s`` (and at once after a network change). When
  the alias moves to another router (or to none) its in-memory samples and counters start
  afresh. ``add_ip_listener(fn(view, old_ip, new_ip, reason))`` reports such a switch
  (``reason`` = ``"network changed"`` for the alias and for a hostname whose first answer
  after a network change is another address - a lookup that failed in between does not use
  that up); the OutageTracker closes that target's open outage with the note.
* ``load_defaults`` looks the default gateway up fresh (netinfo cache invalidated) and applies
  it to the ``gateway`` tile before returning, so the response carries the current gateway IP;
  adding an IP literal compares it with a freshly looked-up alias.
* Networks (ARCHITECTURE 3.20): ``PingManager(..., network_fn=)`` returns the id of the network this
  PC is on (``NetworkTracker.current_network_id``, an attribute read; None: unknown). It is read once
  per sample, and a minute aggregate carries it: when it differs from the aggregate's, the partial
  minute is flushed and a new aggregate starts, so a minute that spans a network change is written as
  two rows (``upsert_ping_minute(..., network_id)``). Without *network_fn* nothing is tagged.
* Clear history (Settings, :mod:`tnt.history`): ``PingManager.clear_history(since_ts) -> int`` forgets what was recorded
  in ``[since_ts, now]`` (None: everything) - the minute rows (``Database.delete_ping_minutes_since``), the in-progress
  minute aggregates, the rings' samples, ``last``, the run counters, the 24 h figure and the raw CSV rows
  (``RawPingLog.clear_since(since_ts, until_ts=None) -> int``).  A clear generation makes every minute begun before the
  clear that overlaps its span a no-op wherever it is (being built, queued in the writer, between a worker and the
  writer); each sample's check is one step with the clear's bump, and the clear waits for the samples already past their
  check to be recorded everywhere before it removes anything, so nothing cleared comes back.  ``publish_targets()``
  publishes ``ping.targets`` afterwards.
"""
from __future__ import annotations

import collections
import csv
import datetime as _dt
import gzip
import importlib
import ipaddress
import logging
import math
import os
import re
import shutil
import stat
import queue
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

__all__ = ["Sample", "RawPingLog", "PingManager", "validate_host", "classify_ip"]

LIGHTS = ("green", "yellow", "red", "grey")
_RESOLVE_RETRY_S = 5.0          # retry a failed re-resolve this often while an IP is still known
_DAY_CACHE_S = 10.0             # recompute the 24 h db summary at most this often per target
_RAW_FLUSH_ROWS = 200           # flush the CSV buffer when this many rows are pending
_STOP_JOIN_S = 2.0              # per-thread join timeout on stop/remove
_STOP_TOTAL_S = 3.5             # overall budget for stop() (joins + flush + raw log close)
_ERR_LOG_EVERY_S = 60.0         # repeated failures of the same kind are logged this often at most
_LABEL_MAX = 80                 # longest target label accepted from the API
_ALIAS_MISS_RECHECK_S = 2.0     # a missed gateway echo makes the alias look the gateway up again this soon
_STALE_ECHO_S = 10.0            # a ping call this far past its timeout was out while the machine slept: dropped
_STALE_ECHO_DROP = 2            # ... this many in a row at most; after that the calls are slow every time: recorded
NETWORK_CHANGED_NOTE = "network changed"
_STALE = object()               # a lookup a network change overtook


class _Throttle:
    """Rate-limit repeated error logging: ``first`` for the first failure, then one warning
    per :data:`_ERR_LOG_EVERY_S`; ``reset`` after a success so the next failure logs again."""

    __slots__ = ("_last", "_count")

    def __init__(self) -> None:
        self._last: Optional[float] = None
        self._count = 0

    def should_log(self) -> bool:
        now = time.monotonic()
        self._count += 1
        if self._last is None or now - self._last >= _ERR_LOG_EVERY_S:
            self._last = now
            return True
        return False

    @property
    def first(self) -> bool:
        return self._count <= 1

    def reset(self) -> None:
        self._last = None
        self._count = 0

_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*"
                      r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})\.csv(\.gz)?$")
_CLEARING_RE = re.compile(r"^\.\d{4}-\d{2}-\d{2}\.csv(\.gz)?\.clearing$")    # RawPingLog.clear_since's temporary file
_NUMERIC_RE = re.compile(r"^[0-9.]+$")
#: after a clear, a sample stamped before it but recorded after it (its echo was out while the history was cleared) is
#: dropped for this long (monotonic): later, an earlier stamp is a wall clock that was set back, and it is kept
_CLEAR_INFLIGHT_S = 60.0
#: a clear waits at most this long (real seconds) for the samples already past their check to be fully recorded before it
#: removes anything (PingManager.clear_history); one that takes longer is still kept out of the ring and the minutes
_CLEAR_DRAIN_S = 5.0
#: the clears PingManager remembers (their generation and span), to judge a minute begun before one of them
_CLEARS_KEPT = 32


def _plain_file(path: Path) -> bool:
    """Whether *path* is a regular file itself: never a symbolic link, a junction or another reparse point."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    return not (getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


# ---------------------------------------------------------------------------------------
# Samples and helpers
# ---------------------------------------------------------------------------------------
@dataclass
class Sample:
    ts: float
    ok: bool
    rtt_ms: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def validate_host(host: Any) -> str:
    """Normalise *host* (strip, drop ``[]`` around IPv6, trailing dot) or raise ValueError."""
    if not isinstance(host, str):
        raise ValueError("host is required")
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    if not text:
        raise ValueError("host is required")
    try:
        return str(ipaddress.ip_address(text))     # canonical form (compressed IPv6, lowercase)
    except ValueError:
        pass
    text = text.rstrip(".")
    if is_gateway_alias(text):
        return "gateway"
    if not text or not _HOST_RE.match(text):
        raise ValueError(f"'{host.strip()}' is not a valid host name or IP address")
    if _NUMERIC_RE.match(text):
        # "300.1.1.1" / "1.2.3" are mistyped IPs, not host names (getaddrinfo would even
        # accept some of them as inet_aton shorthand and ping a surprising address)
        raise ValueError(f"'{host.strip()}' is not a valid IP address")
    return text


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


_FALLBACK_LOCAL_V4 = (
    ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("0.0.0.0/8"),
)
_FALLBACK_LOCAL_V6 = ipaddress.ip_network("fc00::/7")


def _fallback_classify(ip: str) -> str:
    """Mirror of ``netinfo.classify_ip`` without adapter knowledge. Deliberately not
    ``is_private`` (which also covers TEST-NET / benchmark / reserved ranges)."""
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return "internet"
    if isinstance(addr, ipaddress.IPv6Address):
        v4 = addr.ipv4_mapped
        if v4 is not None:
            return _fallback_classify(str(v4))
        local = addr.is_loopback or addr.is_link_local or addr.is_site_local or addr in _FALLBACK_LOCAL_V6
    else:
        local = any(addr in net for net in _FALLBACK_LOCAL_V4)
    return "local" if local else "internet"


def classify_ip(ip: str) -> str:
    """``netinfo.classify_ip`` when available, else an ``ipaddress`` based guess."""
    try:
        netinfo = importlib.import_module("tnt.netinfo")
        kind = netinfo.classify_ip(ip)
        if kind in ("local", "internet"):
            return kind
    except Exception:  # noqa: BLE001 - netinfo missing or broken: fall back below
        log.debug("netinfo.classify_ip(%s) unavailable, using ipaddress fallback", ip, exc_info=True)
    return _fallback_classify(ip)


#: traffic light: samples needed before loss percentages mean anything, and how many of the
#: most recent samples must all succeed for a target to stop being red
_LIGHT_MIN_SAMPLES = 5
_LIGHT_RECENT_N = 5

#: Special host names that follow the machine's *current* default gateway. "Load Default
#: Tiles" adds ``gateway`` instead of a frozen IP so a subnet/NIC change (docking station,
#: Wi-Fi vs Ethernet, new DHCP scope) does not turn the tile into a permanent outage.
GATEWAY_HOSTS = ("gateway", "default-gateway", "default gateway")


#: What "Load Default Tiles" resets the tiles to, in this order (hard-coded on purpose).
DEFAULT_TILES: List[Tuple[str, Optional[str]]] = [("gateway", "Gateway"), ("1.1.1.1", None), ("totalelectronics.com", None)]


def is_gateway_alias(host: Any) -> bool:
    return isinstance(host, str) and host.strip().lower() in GATEWAY_HOSTS


def _default_gateway() -> Optional[str]:
    try:
        netinfo = importlib.import_module("tnt.netinfo")
        gw = netinfo.get_default_gateway()
        return str(gw) if gw else None
    except Exception:  # noqa: BLE001
        log.warning("default gateway lookup failed; skipping it in load_defaults", exc_info=True)
        return None


def _invalidate_netinfo_cache() -> None:
    """Drop netinfo's one-second adapter cache (a stand-in module may not have one)."""
    try:
        fn = getattr(importlib.import_module("tnt.netinfo"), "_invalidate_cache", None)
        if callable(fn):
            fn()
    except Exception:  # noqa: BLE001
        log.debug("netinfo cache invalidation failed", exc_info=True)


_AdapterId = Tuple[str, Optional[int], str]


def _adapter_id(adapter: Any) -> _AdapterId:
    return (str(getattr(adapter, "guid", "") or "").lower(), getattr(adapter, "index", None), str(getattr(adapter, "name", "") or ""))


def _netinfo_adapters() -> Optional[List[Any]]:
    """Every adapter via ``tnt.netinfo.get_adapters`` (its one-second cache); ``None`` when unavailable."""
    try:
        fn = getattr(importlib.import_module("tnt.netinfo"), "get_adapters", None)
        return list(fn(include_down=True, include_loopback=False) or []) if callable(fn) else None
    except Exception:  # noqa: BLE001
        log.debug("adapter lookup failed", exc_info=True)
        return None


def _gateway_owner(gateway: str) -> Optional[_AdapterId]:
    """``(guid, index, name)`` of the adapter *gateway* belongs to (the default gateway lookup just
    filled netinfo's cache); ``None`` when that cannot be told."""
    for a in _netinfo_adapters() or []:
        if gateway in [str(g) for g in (getattr(a, "gateways", None) or [])]:
            return _adapter_id(a)
    return None


def _gateway_left_out(owner: Optional[_AdapterId]) -> bool:
    """Whether a default gateway that disappeared was configured away rather than lost.

    True when the adapter it belonged to (*owner*) is still up with a usable, not self-assigned
    IPv4 address and no IPv4 gateway: a static address typed in without one, the DHCP server tool
    re-addressing it, a lease without a router.  False when that adapter went down or away, lost
    its address or fell back to 169.254.x.x (Wi-Fi dropped, a cable pulled, a lease lost), and
    whenever it cannot be told: then the last gateway is still pinged and its misses still count.
    """
    adapters = _netinfo_adapters() if owner is not None else None
    if not adapters or owner is None:
        return False
    match = next((a for a in adapters if owner[0] and _adapter_id(a)[0] == owner[0]), None)
    if match is None:
        match = next((a for a in adapters if _adapter_id(a)[1:] == owner[1:]), None)
    if match is None or not bool(getattr(match, "is_up", False)):
        return False
    if any(":" not in str(g) for g in (getattr(match, "gateways", None) or [])):
        return False
    for entry in getattr(match, "ipv4", None) or []:
        try:
            addr = ipaddress.IPv4Address(str(getattr(entry, "address", "")))
        except ValueError:
            continue
        if bool(getattr(entry, "preferred", True)) and not addr.is_link_local:
            return True
    return False


def _next_slot(start: float, interval: float, n: int, now: float) -> Tuple[int, float]:
    """Return ``(n, next_ts)`` for the slot after slot *n* on the aligned schedule.

    ``next_ts = start + (n + 1) * interval`` unless that moment is already a whole
    interval in the past, in which case the schedule skips forward to the first slot
    that is still ahead of *now* (never drifting: slots stay anchored at *start*).
    """
    interval = max(0.05, float(interval))
    n += 1
    nxt = start + n * interval
    if now >= nxt + interval:
        n = int(math.floor((now - start) / interval)) + 1
        nxt = start + n * interval
        if nxt <= now:                       # float rounding guard
            n += 1
            nxt = start + n * interval
    return n, nxt


def _local_date(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def _minute_of(ts: float) -> int:
    return int(ts // 60) * 60


def _seconds_arg(value: Any, default: float) -> float:
    """Window length from an API/user value: non-numeric/NaN -> *default*, negative -> 0,
    capped so ``int()`` of it can never overflow."""
    try:
        s = float(value)
    except (TypeError, ValueError):
        return float(default)
    if math.isnan(s):
        return float(default)
    return max(0.0, min(s, 1e9))


# ---------------------------------------------------------------------------------------
# Raw per-second CSV log
# ---------------------------------------------------------------------------------------
class RawPingLog:
    """Daily CSV ``logs/pings/YYYY-MM-DD.csv`` (local date of the row's ``ts``).

    Header ``ts,target_id,host,ok,rtt_ms,bytes``. Buffered writes, flushed at least
    every ``flush_interval_s`` (checked on write) and on :meth:`close`. On the first row
    of a new day the previous file is closed and gzipped to ``.csv.gz`` in a background
    thread. :meth:`trim` deletes ``.csv``/``.csv.gz`` files older than *days*; :meth:`clear_since` removes what was
    logged at or after a moment (Settings > "Clear history").
    """

    HEADER = ["ts", "target_id", "host", "ok", "rtt_ms", "bytes"]

    def __init__(self, directory: Path, clock: Callable[[], float] = time.time,
                 flush_interval_s: float = 2.0) -> None:
        self.directory = Path(directory)
        self._clock = clock
        self._flush_interval = max(0.0, float(flush_interval_s))
        self._lock = threading.RLock()
        self._file: Any = None
        self._writer: Any = None
        self._date: Optional[str] = None
        self._pending = 0
        self._last_flush = float(clock())
        self._bg: List[threading.Thread] = []
        self._gz_lock = threading.Lock()
        self._write_errors = _Throttle()
        self.last_clear_failed: List[str] = []      # the files the last clear_since() could not change
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            log.exception("cannot create ping log directory %s", self.directory)
        self._compress_stale()

    # -- files ---------------------------------------------------------------------------
    def path_for(self, ts: float) -> Path:
        return self.directory / f"{_local_date(ts)}.csv"

    def host_for(self, target_id: int, ts: float) -> Optional[str]:
        """The host a target id was logged as on the local day of *ts*, or None.

        Reads that day's ``.csv`` (flushed first if it is the open file) or ``.csv.gz`` and
        returns the host of the first row for *target_id*. Used to backfill the host of
        outages recorded before it was stored with them. Never raises.
        """
        try:
            date = _local_date(ts)
            with self._lock:
                if self._file is not None and self._date == date:
                    self.flush()
            plain = self.directory / f"{date}.csv"
            gz = self.directory / f"{date}.csv.gz"
            path = plain if plain.exists() else gz if gz.exists() else None
            if path is None:
                return None
            opener = gzip.open if path.suffix == ".gz" else open
            wanted = str(int(target_id))
            with opener(path, "rt", encoding="utf-8", newline="") as fh:   # type: ignore[operator]
                for row in csv.reader(fh):
                    if len(row) >= 3 and row[1] == wanted and row[2]:
                        return row[2]
            return None
        except Exception:  # noqa: BLE001
            log.debug("host lookup for target %s in the raw log failed", target_id, exc_info=True)
            return None

    @property
    def current_path(self) -> Optional[Path]:
        with self._lock:
            return self.directory / f"{self._date}.csv" if self._date else None

    def _open(self, date: str) -> None:
        path = self.directory / f"{date}.csv"
        # the directory may have been cleaned up while the service ran; recreate it
        # (once per day / per open, so this costs nothing on the write path)
        self.directory.mkdir(parents=True, exist_ok=True)
        new_file = not path.exists() or path.stat().st_size == 0
        self._file = open(path, "a", newline="", encoding="utf-8", buffering=64 * 1024)
        self._writer = csv.writer(self._file, lineterminator="\n")
        self._date = date
        if new_file:
            self._writer.writerow(self.HEADER)
            self._pending += 1

    def _close_file(self) -> Optional[Path]:
        if self._file is None:
            return None
        path = self.directory / f"{self._date}.csv"
        try:
            self._file.flush()
        except Exception:  # noqa: BLE001
            log.exception("flushing %s failed", path)
        try:
            self._file.close()
        except Exception:  # noqa: BLE001
            log.exception("closing %s failed", path)
        self._file = None
        self._writer = None
        self._date = None
        self._pending = 0
        return path

    def _rollover(self, new_date: str) -> None:
        old_date = self._date
        old_path = self._close_file()
        if old_path is not None and old_date is not None and old_date < new_date:
            self._start_compress(old_path)
        self._open(new_date)

    # -- writing -------------------------------------------------------------------------
    def write(self, ts: float, target_id: int, host: str, ok: bool, rtt_ms: Optional[float], size: int) -> None:
        """Append one row (never raises).

        The file is chosen by the row's local date, but the log never rolls *backwards*:
        a row dated before the currently open day (a worker whose ping started just
        before midnight and finished after another target already rolled the file) goes
        into the current file. Re-opening the previous day's file would race the
        background gzip of that very file and duplicate its rows.
        """
        try:
            date = _local_date(ts)
            rtt = "" if rtt_ms is None else str(round(float(rtt_ms), 3))
            row = [f"{float(ts):.3f}", int(target_id), host, 1 if ok else 0, rtt, int(size)]
            with self._lock:
                if self._file is None:
                    self._open(date)
                elif date > self._date:
                    self._rollover(date)
                self._writer.writerow(row)
                self._pending += 1
                now = float(self._clock())
                if self._pending >= _RAW_FLUSH_ROWS or now - self._last_flush >= self._flush_interval or now < self._last_flush:
                    self._flush_locked(now)
                self._write_errors.reset()
        except Exception:  # noqa: BLE001
            if self._write_errors.should_log():
                if self._write_errors.first:
                    log.exception("raw ping log write failed (further failures are logged every %.0f s)", _ERR_LOG_EVERY_S)
                else:
                    log.warning("raw ping log write still failing in %s", self.directory, exc_info=True)

    def _flush_locked(self, now: Optional[float] = None) -> None:
        if self._file is not None:
            self._file.flush()
        self._pending = 0
        self._last_flush = float(now if now is not None else self._clock())

    def flush(self) -> None:
        with self._lock:
            try:
                self._flush_locked()
            except Exception:  # noqa: BLE001
                log.exception("raw ping log flush failed")

    def close(self, wait_background_s: float = 3.0) -> None:
        """Flush and close the current file (idempotent; a later write reopens).

        Waits at most *wait_background_s* for a running gzip of the previous day.
        """
        with self._lock:
            self._close_file()
        self.wait_background(wait_background_s)

    # -- compression ---------------------------------------------------------------------
    def _start_compress(self, path: Path) -> None:
        t = threading.Thread(target=self._compress, args=(path,), name=f"tnt-pinglog-gzip-{path.stem}", daemon=True)
        with self._lock:
            self._bg = [x for x in self._bg if x.is_alive()]
            self._bg.append(t)
        t.start()

    def _compress(self, path: Path) -> None:
        gz = path.with_name(path.name + ".gz")
        with self._gz_lock:
            try:
                if not path.exists():
                    return
                with open(path, "rb") as src, gzip.open(gz, "ab") as dst:
                    shutil.copyfileobj(src, dst, 256 * 1024)
                path.unlink()
                log.info("compressed ping log %s", path.name)
            except Exception:  # noqa: BLE001
                log.exception("compressing %s failed", path)

    def _compress_stale(self) -> None:
        """Gzip ``.csv`` files of earlier days left behind by a previous run."""
        try:
            today = _local_date(self._clock())
            for p in sorted(self.directory.glob("*.csv")):
                m = _DATE_RE.match(p.name)
                if m and p.name[:10] < today:
                    self._start_compress(p)
        except Exception:  # noqa: BLE001
            log.exception("scanning for stale ping logs failed")

    def wait_background(self, timeout: float = 5.0) -> None:
        """Join running compression threads (bounded by *timeout* in total)."""
        deadline = time.monotonic() + max(0.0, timeout)
        with self._lock:
            threads = list(self._bg)
        for t in threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            t.join(remaining)
        with self._lock:
            self._bg = [x for x in self._bg if x.is_alive()]
            still = [x.name for x in self._bg]
        if still:
            log.info("ping log compression still running in the background: %s", ", ".join(still))

    # -- clear history (Settings) ---------------------------------------------------------
    def clear_since(self, since_ts: Optional[float], until_ts: Optional[float] = None) -> int:
        """Remove what was logged at or after *since_ts* (None: from the first row), and before *until_ts* when it is
        given (PingManager passes the moment its clear began: a row stamped since then was recorded after the clear);
        None for both removes every daily file.

        Only ``YYYY-MM-DD.csv`` / ``.csv.gz`` names in this directory are touched (regular files: never a link or a
        reparse point), and a ``.YYYY-MM-DD.csv(.gz).clearing`` left by an interrupted rewrite, also only when it is a
        regular file.  A file dated after the local date of *since_ts* (and before that of *until_ts*) is deleted, the file
        of either date is rewritten without its rows in the span (deleted when none is left), earlier days are left alone
        (a row never goes into an earlier day's file).  A gzip of an earlier day that is running is waited for, and none
        starts meanwhile (``_gz_lock``); the open file is flushed and closed first and no row is written meanwhile
        (``_lock``): the next write reopens it, with the header when the file is new.  A file that cannot be rewritten or
        deleted is logged and named in ``last_clear_failed``; the rest are still cleared.  Returns the rows removed from
        rewritten files plus the files deleted."""
        removed = 0
        failed: List[str] = []
        since = None if since_ts is None else float(since_ts)
        until = None if until_ts is None else float(until_ts)
        since_date = None if since is None else _dt.date.fromtimestamp(since)
        until_date = None if until is None else _dt.date.fromtimestamp(until)
        with self._gz_lock:
            with self._lock:
                self._close_file()
                try:
                    names = sorted(os.listdir(self.directory))
                except OSError:
                    log.warning("the ping log folder %s cannot be read; nothing cleared there", self.directory, exc_info=True)
                    names = []
                for name in names:
                    if _CLEARING_RE.match(name):                # a rewrite a crash interrupted
                        if _plain_file(self.directory / name):
                            self._unlink_quietly(self.directory / name)
                        continue
                    m = _DATE_RE.match(name)
                    if not m:
                        continue
                    path = self.directory / name
                    if not _plain_file(path):
                        continue
                    try:
                        fdate = _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                    except ValueError:
                        continue
                    after_since = since_date is None or fdate > since_date
                    before_until = until_date is None or fdate < until_date
                    try:
                        if after_since and before_until:
                            path.unlink()               # every row of it lies in the span
                            removed += 1
                        elif after_since or fdate == since_date:
                            removed += self._filter_file(path, since, until)
                    except Exception:  # noqa: BLE001 - one file must not keep the others
                        log.exception("clearing the ping log %s failed", name)
                        failed.append(name)
        self.last_clear_failed = failed
        log.info("ping logs cleared %s: %d row(s)/file(s) removed%s",
                 "entirely" if since is None else f"from {since:.0f}", removed,
                 f", {len(failed)} could not be changed" if failed else "")
        return removed

    def _filter_file(self, path: Path, since: Optional[float], until: Optional[float] = None) -> int:
        """Rewrite *path* without its rows at or after *since* (None: from the first) and before *until* (None: to the
        last), through a temporary file replaced in one step; delete it when no row is left.  Returns the rows removed,
        plus 1 when the file itself was deleted."""
        gz = path.name.endswith(".gz")
        tmp = path.with_name("." + path.name + ".clearing")
        kept = dropped = 0
        try:
            src_open = gzip.open if gz else open
            with src_open(path, "rt", encoding="utf-8", newline="") as src:   # type: ignore[operator]
                dst = gzip.open(tmp, "wt", encoding="utf-8", newline="") if gz else open(tmp, "w", encoding="utf-8", newline="")
                with dst:
                    writer = csv.writer(dst, lineterminator="\n")
                    for row in csv.reader(src):
                        if not row:
                            continue
                        try:
                            ts = float(row[0])
                        except ValueError:
                            writer.writerow(row)                # the header
                            continue
                        if math.isfinite(ts) and (since is None or ts >= since) and (until is None or ts < until):
                            dropped += 1
                        else:
                            writer.writerow(row)
                            kept += 1
            if not dropped:
                self._unlink_quietly(tmp)
                return 0
            if not kept:
                self._unlink_quietly(tmp)
                path.unlink()
                return dropped + 1
            os.replace(tmp, path)
            return dropped
        except BaseException:
            self._unlink_quietly(tmp)
            raise

    @staticmethod
    def _unlink_quietly(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            log.warning("could not delete %s", path, exc_info=True)

    # -- retention -----------------------------------------------------------------------
    def trim(self, days: int) -> int:
        """Delete ``.csv``/``.csv.gz`` files dated more than *days* days before today."""
        deleted = 0
        try:
            today = _dt.date.fromtimestamp(float(self._clock()))
            cutoff = today - _dt.timedelta(days=max(0, int(days)))
            current = self.current_path
            for p in list(self.directory.iterdir()):
                m = _DATE_RE.match(p.name)
                if not m:
                    continue
                try:
                    fdate = _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                except ValueError:
                    continue
                if fdate >= cutoff or p == current:
                    continue
                try:
                    p.unlink()
                    deleted += 1
                except OSError:
                    log.warning("could not delete old ping log %s", p, exc_info=True)
        except Exception:  # noqa: BLE001
            log.exception("trimming ping logs failed")
        if deleted:
            log.info("trimmed %d old ping log file(s)", deleted)
        return deleted


# ---------------------------------------------------------------------------------------
# Per-target state
# ---------------------------------------------------------------------------------------
class _MinuteAgg:
    __slots__ = ("minute_ts", "network_id", "gen", "sent", "received", "sum", "min", "max", "last_rtt", "jitter_acc",
                 "jitter_n")

    def __init__(self, minute_ts: int, network_id: Optional[int] = None, gen: int = 0) -> None:
        self.minute_ts = minute_ts
        self.network_id = network_id            # the network current for these samples (None: untagged)
        self.gen = gen                          # PingManager._clear_gen when it began: a clear since then voids it
        self.sent = 0
        self.received = 0
        self.sum = 0.0
        self.min: Optional[float] = None
        self.max: Optional[float] = None
        self.last_rtt: Optional[float] = None
        self.jitter_acc = 0.0
        self.jitter_n = 0

    def add(self, sample: Sample) -> None:
        self.sent += 1
        if sample.ok and sample.rtt_ms is not None:
            rtt = float(sample.rtt_ms)
            self.received += 1
            self.sum += rtt
            self.min = rtt if self.min is None else min(self.min, rtt)
            self.max = rtt if self.max is None else max(self.max, rtt)
            if self.last_rtt is not None:
                self.jitter_acc += abs(rtt - self.last_rtt)
                self.jitter_n += 1
            self.last_rtt = rtt

    @property
    def avg(self) -> Optional[float]:
        return self.sum / self.received if self.received else None

    @property
    def jitter(self) -> Optional[float]:
        if self.jitter_n:
            return self.jitter_acc / self.jitter_n
        return 0.0 if self.received else None

    def row(self) -> Tuple[int, int, int, Optional[float], Optional[float], Optional[float], Optional[float]]:
        avg = self.avg
        jit = self.jitter
        return (self.minute_ts, self.sent, self.received,
                round(avg, 3) if avg is not None else None,
                round(self.min, 3) if self.min is not None else None,
                round(self.max, 3) if self.max is not None else None,
                round(jit, 3) if jit is not None else None)


class _TargetState:
    def __init__(self, row: Dict[str, Any], now: float) -> None:
        self.id = int(row["id"])
        self.host = str(row["host"])
        self.label = row.get("label")
        self.name = row.get("name")             # a custom display name the user set (overrides label/host)
        self.kind_db = str(row.get("kind") or "auto")
        self.enabled = bool(row.get("enabled", True))
        self.sort_order = int(row.get("sort_order") or 0)
        self.lock = threading.RLock()
        self.is_literal = _is_ip_literal(self.host)
        self.is_alias = is_gateway_alias(self.host)
        self.ip: Optional[str] = self.host if self.is_literal else None
        self.resolved = self.is_literal
        self.net_epoch = 0              # bumped by on_network_change: a lookup already running is stale
        self.resolved_epoch = 0         # net_epoch of the last lookup that found an address
        self.gateway_owner: Optional[_AdapterId] = None     # the alias: the adapter its gateway belongs to
        self.resolve_error: Optional[str] = None
        self.last_resolve_ts: Optional[float] = now if self.is_literal else None
        self.kind = self.kind_for(self.ip)
        self.samples: Deque[Sample] = collections.deque(maxlen=3600)
        self.last: Optional[Sample] = None
        self.consecutive_missed = 0
        self.consecutive_ok = 0
        self.in_outage = False
        self.stale_calls = 0            # ping() calls in a row that outlived their timeout by far (_STALE_ECHO_S)
        self.stale_log = _Throttle()    # "slow every time" is logged once, then every _ERR_LOG_EVERY_S at most
        self.since_ts = now
        self.minute: Optional[_MinuteAgg] = None
        self.day_cache: Optional[Dict[str, Any]] = None
        self.day_cache_ts = 0.0
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

    def kind_for(self, ip: Optional[str]) -> str:
        """``kind`` for *ip*: the db override wins, else ``classify_ip``.

        May enumerate adapters through ``netinfo`` — call it outside every lock.
        """
        if self.kind_db in ("local", "internet"):
            return self.kind_db
        if ip:
            return classify_ip(ip)
        if is_gateway_alias(self.host):
            return "local"          # the gateway is on-link by definition, even before it resolves
        return "internet"


# ---------------------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------------------
class _DbWriter:
    """Runs the per-minute SQLite upserts on one background thread.

    Workers hand their finished minute to :meth:`submit` and carry on pinging; if the
    database is locked by a backup/antivirus tool (SQLite busy timeout is 30 s) only this
    thread waits, not every ping worker. :meth:`stop` drains what is left (bounded).
    """

    def __init__(self, name: str = "tnt-ping-dbwriter", maxsize: int = 20000) -> None:
        self._q: "queue.Queue[Tuple[Callable[..., Any], Tuple[Any, ...]]]" = queue.Queue(maxsize=maxsize)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._name = name
        self.dropped = 0

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=self._name, daemon=True)
        self._thread.start()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    @property
    def pending(self) -> int:
        return self._q.qsize()

    def submit(self, fn: Callable[..., Any], *args: Any) -> bool:
        """Queue ``fn(*args)``; False when the writer is not running or the queue is full."""
        if not self.running:
            return False
        try:
            self._q.put_nowait((fn, args))
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def _run(self) -> None:
        while not self._stop.is_set() or not self._q.empty():
            try:
                fn, args = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                fn(*args)
            except Exception:  # noqa: BLE001
                log.exception("deferred database write failed")

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the thread and write whatever is still queued synchronously (bounded)."""
        self._stop.set()
        t = self._thread
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(max(0.0, timeout))
        for _ in range(2000):
            try:
                fn, args = self._q.get_nowait()
            except queue.Empty:
                break
            try:
                fn(*args)
            except Exception:  # noqa: BLE001
                log.exception("deferred database write failed during shutdown")


class PingManager:
    """Owns the per-target ping workers and everything derived from their samples."""

    def __init__(self, db: Any, config: Any, bus: Any, pinger: Any = None, raw_log: Optional[RawPingLog] = None,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                 resolver: Optional[Callable[[str], Optional[str]]] = None,
                 network_fn: Optional[Callable[[], Optional[int]]] = None, *,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self._db = db
        self._config = config
        self._bus = bus
        self._clock = clock
        self._monotonic = monotonic             # times a ping() call alongside ``clock`` (it counts the time asleep)
        self._sleep = sleep
        self._resolver = resolver
        self._network_fn = network_fn           # the current network id (tnt.networks); None: minutes are not tagged
        self.pinger = pinger
        self._own_pinger = pinger is None
        self.raw_log = raw_log
        self._own_raw_log = raw_log is None
        self._writer = _DbWriter()
        self._lock = threading.RLock()
        self._targets: Dict[int, _TargetState] = {}
        self._sample_listeners: List[Callable[[Dict[str, Any], Sample], None]] = []
        self._removal_listeners: List[Callable[[int], None]] = []
        self._ip_listeners: List[Callable[[Dict[str, Any], Optional[str], Optional[str], Optional[str]], None]] = []
        self._paused = False
        self._running = False
        self._live_workers = 0                  # worker threads started and not yet exited
        self._close_pinger_pending = False      # stop() found a worker still inside ping()
        # Clear history (clear_history): every minute aggregate carries the generation it began in, and a minute of an
        # older generation that overlaps a span cleared since is never written - whether it is still being built, queued
        # in the writer or on its way there (_voided).  _gen_lock (with _gen_cond) orders a sample's check, and a worker's
        # check-and-queue of a minute, against the bump; _inflight counts the samples past their check, per thread, so the
        # clear can wait for them to be fully recorded before it removes anything; _write_lock serialises every minute
        # write with the clear's delete, so a write that passed its check lands before the delete, and one that did not
        # sees the bump.
        self._clear_gen = 0
        self._gen_lock = threading.Lock()
        self._gen_cond = threading.Condition(self._gen_lock)
        self._inflight: Dict[int, int] = {}     # thread ident -> the generation its sample was checked under
        self._write_lock = threading.RLock()
        # the recent clears, oldest first: (generation after the bump, since_ts, at, monotonic at)
        self._clears: List[Tuple[int, Optional[float], float, float]] = []
        self.last_clear_info: Dict[str, Any] = {}

    # -- lifecycle -----------------------------------------------------------------------
    @property
    def paused(self) -> bool:
        return self._paused

    @property
    def running(self) -> bool:
        return self._running

    def _ensure_helpers(self) -> None:
        if self.pinger is None:
            try:
                icmp = importlib.import_module("tnt.icmp")
                self.pinger = icmp.IcmpPinger()
                self._own_pinger = True
            except Exception:  # noqa: BLE001
                log.exception("could not create the ICMP pinger; every ping will be recorded as a miss")
        if self.raw_log is None:
            try:
                from . import paths
                self.raw_log = RawPingLog(paths.ping_logs_dir(), clock=self._clock)
                self._own_raw_log = True
            except Exception:  # noqa: BLE001
                log.exception("could not open the raw ping log; per-second samples will not be logged")

    def start(self) -> None:
        """Load enabled targets from the db and start one worker per target."""
        self._ensure_helpers()
        self._writer.start()
        now = float(self._clock())
        try:
            rows = self._db.list_targets(enabled_only=True)
        except Exception:  # noqa: BLE001
            log.exception("loading targets from the database failed")
            rows = []
        # build the states outside the lock: classifying an IP may enumerate adapters
        loaded = [_TargetState(row, now) for row in rows]
        with self._lock:
            self._running = True
            self._close_pinger_pending = False      # the pinger is in use again
            for st in loaded:
                self._targets.setdefault(st.id, st)
            states = list(self._targets.values())
        for st in states:
            try:
                self._start_worker(st)
            except Exception:  # noqa: BLE001 - one target must not stop the others
                log.exception("starting the ping worker for %s failed", st.host)
        log.info("ping manager started with %d target(s)", len(states))
        self._publish_targets()

    def stop(self) -> None:
        """Stop all workers (bounded join), flush minute aggregates and the raw log."""
        with self._lock:
            self._running = False
            states = list(self._targets.values())
        for st in states:
            st.stop_event.set()
        deadline = time.monotonic() + _STOP_TOTAL_S
        for st in states:
            t = st.thread
            if t is not None and t.is_alive() and t is not threading.current_thread():
                t.join(max(0.05, min(_STOP_JOIN_S, deadline - time.monotonic())))
                if t.is_alive():
                    # still inside pinger.ping(); it records its sample and flushes its
                    # own minute when it comes out (see _run_worker)
                    log.warning("ping worker for %s did not stop in time", st.host)
            st.thread = None
        for st in states:
            self._flush_minute(st)
        # write the queued minute rows before the process goes away (bounded)
        self._writer.stop(timeout=max(0.5, min(5.0, deadline - time.monotonic())))
        if self.raw_log is not None:
            try:
                self.raw_log.flush()
                self.raw_log.close(wait_background_s=max(0.2, deadline - time.monotonic()))
            except Exception:  # noqa: BLE001
                log.exception("closing the raw ping log failed")
        if self._own_pinger and self.pinger is not None:
            with self._lock:
                idle = self._live_workers == 0
                if not idle:
                    # a worker is still inside pinger.ping(): closing the ICMP handles under
                    # it is not safe; the last worker to exit closes the pinger instead
                    self._close_pinger_pending = True
            if idle:
                self._close_pinger()
            else:
                log.warning("ICMP pinger close deferred until the last ping worker exits")
        log.info("ping manager stopped")

    def _close_pinger(self) -> None:
        p = self.pinger
        if p is None:
            return
        try:
            p.close()
        except Exception:  # noqa: BLE001
            log.exception("closing the ICMP pinger failed")

    def _start_worker(self, st: _TargetState) -> None:
        # the manager lock covers the _running check *and* the thread start, so an
        # add_target() racing with stop() can never leave an orphan worker behind
        # (stop() flips _running and snapshots the states under the same lock)
        with self._lock:
            if not self._running or self._targets.get(st.id) is not st:
                return                              # stopped, or removed while being added
            with st.lock:
                if st.thread is not None and st.thread.is_alive():
                    return
                ev = threading.Event()
                st.stop_event = ev
                st.since_ts = float(self._clock())
                t = threading.Thread(target=self._run_worker, args=(st, ev), name=f"tnt-ping-{st.id}", daemon=True)
                st.thread = t
            self._live_workers += 1                 # balanced by _worker_exited()
            try:
                t.start()
            except BaseException:
                self._live_workers -= 1
                st.thread = None
                raise

    def _stop_worker(self, st: _TargetState, timeout: Optional[float] = None) -> None:
        st.stop_event.set()
        t = st.thread
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(_STOP_JOIN_S if timeout is None else timeout)
            if t.is_alive():
                log.warning("ping worker for %s is still finishing its last ping", st.host)
        st.thread = None

    def worker_alive(self, target_id: int) -> Optional[bool]:
        """Whether the worker thread of *target_id* is alive (None for an unknown id)."""
        st = self._state(target_id)
        if st is None:
            return None
        t = st.thread
        return bool(t is not None and t.is_alive())

    # -- worker loop ---------------------------------------------------------------------
    def _interval(self) -> float:
        try:
            return max(0.5, min(60.0, float(self._config.get("ping.interval_s", 1.0))))
        except Exception:  # noqa: BLE001
            return 1.0

    def _wait(self, stop_event: threading.Event, seconds: float) -> None:
        if seconds <= 0:
            return
        if self._sleep is time.sleep:
            stop_event.wait(seconds)
        else:
            self._sleep(seconds)

    def _run_worker(self, st: _TargetState, stop_event: Optional[threading.Event] = None) -> None:
        # *stop_event* is this thread's own event: start() may hand the target a new
        # worker (and a new event) while this one is still inside a long ping timeout
        ev = stop_event if stop_event is not None else st.stop_event
        start = float(self._clock())
        interval = self._interval()
        n = 0
        try:
            while not ev.is_set():
                try:
                    self._tick(st)
                    cur = self._interval()
                    now = float(self._clock())
                    if cur != interval:                     # interval changed: re-anchor the schedule
                        start, interval, n = now, cur, 0
                    n, nxt = _next_slot(start, interval, n, now)
                    if nxt - now > interval + 1e-3:
                        # the wall clock was stepped backwards (NTP / manual change): the
                        # next slot is now far in the future, re-anchor instead of sleeping
                        # for the whole jump (on a monotone clock nxt - now <= interval)
                        log.warning("clock went backwards by ~%.0f s; re-anchoring the ping schedule for %s",
                                    nxt - now - interval, st.host)
                        start, n = now, 1           # the slot we are about to wait for
                        nxt = now + interval
                    self._wait(ev, nxt - now)
                except Exception:  # noqa: BLE001
                    log.exception("ping worker for %s failed; continuing", st.host)
                    self._wait(ev, 1.0)
        finally:
            self._worker_exited(st)

    def _worker_exited(self, st: _TargetState) -> None:
        """Tail work of a worker thread (runs on that thread, never raises).

        A worker that outlived the bounded join in ``stop()``/``remove_target()`` (it was
        stuck in a long ping timeout) persists what it recorded after the join; for a
        worker that stopped in time the minute flush is a no-op because ``stop()`` flushed
        already. After ``stop()`` its late raw-log row re-opened the closed log, so the
        log is flushed and closed again, and when the manager owns the ``IcmpPinger`` the
        last worker out closes it (``stop()`` deferred that while workers were inside
        ``ping()``).
        """
        try:
            self._flush_minute(st)
        except Exception:  # noqa: BLE001
            log.exception("flushing the last minute of %s failed", st.host)
        with self._lock:
            self._live_workers = max(0, self._live_workers - 1)
            stopped = not self._running
            close_pinger = stopped and self._close_pinger_pending and self._live_workers == 0
            if close_pinger:
                self._close_pinger_pending = False
        if stopped and self.raw_log is not None:
            try:
                self.raw_log.close(wait_background_s=0.0)
            except Exception:  # noqa: BLE001
                log.exception("closing the raw ping log failed")
        if close_pinger:
            self._close_pinger()

    def tick(self, target_id: int) -> Optional[Sample]:
        """Run one worker iteration for *target_id* synchronously (None if paused/unknown, for the
        ``gateway`` alias while this machine has no default gateway, and for an echo that was out
        while the machine slept, see ``_STALE_ECHO_S`` and ``_STALE_ECHO_DROP``)."""
        st = self._state(target_id)
        if st is None:
            return None
        return self._tick(st)

    def _tick(self, st: _TargetState) -> Optional[Sample]:
        if self._paused:
            return None
        now = float(self._clock())
        cfg = self._config
        size = int(cfg.ping_bytes)
        timeout_ms = int(cfg.get("ping.timeout_ms", 1000))
        ttl = int(cfg.get("ping.ttl", 128))
        ip = self._maybe_resolve(st, now)
        if ip is None and st.is_alias:
            # no default gateway and none lost (a static address without one, the DHCP tool took the
            # NIC, never had one): nothing to ping, and nothing to count against the network
            return None
        if ip is None or self.pinger is None:
            sample = Sample(ts=now, ok=False, rtt_ms=None)
        else:
            sent, sent_mono = float(self._clock()), float(self._monotonic())
            try:
                res = self.pinger.ping(ip, size, timeout_ms, ttl)
                ok = bool(getattr(res, "ok", False))
                rtt = getattr(res, "rtt_ms", None)
                if ok and rtt is None:              # a reply without an RTT is still a reply
                    rtt = 0.0
                sample = Sample(ts=now, ok=ok, rtt_ms=float(rtt) if ok else None)
            except Exception:  # noqa: BLE001
                log.exception("ping(%s) raised", ip)
                sample = Sample(ts=now, ok=False, rtt_ms=None)
            returned = float(self._clock())
            # Timed on both clocks, and either one showing the overrun counts: the monotonic clock
            # (GetTickCount64, which counts the time asleep) still sees a sleep across which w32time set the
            # wall clock back, and a wall clock set forward mid-call costs that one sample and no more.
            took = max(returned - sent, float(self._monotonic()) - sent_mono)
            if took <= timeout_ms / 1000.0 + _STALE_ECHO_S:
                if st.stale_calls:
                    st.stale_calls = 0
                    st.stale_log.reset()
            else:
                st.stale_calls += 1
                if st.stale_calls <= _STALE_ECHO_DROP:
                    # The call outlived its own timeout by far: the machine slept (or TNT was frozen) while the
                    # echo was out, and IcmpSendEcho2 returned after the wake.  Its "timed out" is about the
                    # sleep, not the network, and it is stamped with the moment it was sent, before the sleep:
                    # recorded, it would be a miss the ping card and the outage tracker date to before the lid
                    # closed.  Nothing is recorded for it; the next tick measures the network the machine woke on.
                    log.info("dropping the echo to %s: it came back %.0f s after it was sent, past its %d ms timeout "
                             "(the machine slept or the service was frozen while it was out)", st.host, took, timeout_ms)
                    return None
                # More in a row than a sleep leaves (one per target, two when the machine woke only for a
                # moment and slept again): the calls are slow every time - a wedged ICMP or filter driver, a VPN
                # client holding IcmpSendEcho2, a starved process.  Dropping them all would leave the card on its
                # last reading and no outage could ever open, so they are recorded as they came back, dated when
                # the call returned rather than when it was sent, which can never be before a sleep inside it.
                if st.stale_log.should_log():
                    log.warning("ping calls to %s keep taking %.0f s against a %d ms timeout, %d in a row: "
                                "recording them as they come back (logged every %.0f s at most)",
                                st.host, took, timeout_ms, st.stale_calls, _ERR_LOG_EVERY_S)
                sample = Sample(ts=returned, ok=sample.ok, rtt_ms=sample.rtt_ms)
        self._record(st, sample, size)
        return sample

    def _record(self, st: _TargetState, sample: Sample, size: int) -> None:
        with self._lock:
            removed = self._targets.get(st.id) is not st
        if removed:
            # remove_target() gave up joining this worker while it sat in a long ping
            # timeout: the target is gone from the db, don't publish or persist for it
            log.debug("dropping late sample for removed target %s", st.host)
            return
        # Clear history: the check and the count are one step against clear_history's bump (both under _gen_lock).  A
        # sample checked before a clear is fully recorded before that clear removes anything (it waits for _inflight), so
        # the clear removes it from every store; one checked after it is judged against its span.
        me = threading.get_ident()
        with self._gen_cond:
            if self._cleared_span_locked(sample.ts):
                # its echo was out while the history was cleared: stamped inside the cleared span, it must not come back
                log.debug("dropping a sample of %s stamped before the history was cleared", st.host)
                return
            gen = self._clear_gen
            self._inflight[me] = gen
        try:
            self._record_checked(st, sample, size, gen)
        finally:
            with self._gen_cond:
                self._inflight.pop(me, None)
                self._gen_cond.notify_all()

    def _cleared_span_locked(self, ts: float) -> bool:
        """Whether a sample stamped *ts* lies in a span cleared less than ``_CLEAR_INFLIGHT_S`` ago (``_gen_lock`` held,
        or a read of ``_clears``, which is only ever replaced whole)."""
        clears = self._clears
        if not clears:
            return False
        mono = float(self._monotonic())
        return any(mono - m < _CLEAR_INFLIGHT_S and ts < at and (since is None or ts >= since)
                   for _g, since, at, m in clears)

    def _voided(self, gen: int, minute_ts: int) -> bool:
        """Whether a minute begun in generation *gen* was cleared since: a clear after it whose span it overlaps
        (``minute_ts > since_ts - 60``; every minute for an all-time clear).  A minute from before every clear still
        remembered is voided (it cannot be judged)."""
        if gen == self._clear_gen:
            return False
        clears = self._clears
        if not clears or gen < clears[0][0] - 1:
            return True
        return any(g > gen and (since is None or minute_ts > since - 60.0) for g, since, _at, _m in clears)

    def _record_checked(self, st: _TargetState, sample: Sample, size: int, gen: int) -> None:
        minute_ts = _minute_of(sample.ts)
        network_id = self._network_id()         # once per sample, outside every lock
        finished: Optional[_MinuteAgg] = None
        with st.lock:
            if self._clear_gen != gen and self._cleared_span_locked(sample.ts):
                # a clear landed between the check and here (it waits for this sample only so long, or it runs on this
                # very thread): stamped inside its span, the sample goes nowhere
                log.debug("dropping a sample of %s stamped inside a span cleared while it was recorded", st.host)
                return
            if st.minute is not None and self._voided(st.minute.gen, st.minute.minute_ts):
                st.minute = None                # a clear since it began covers it: it is never written
            if st.minute is not None and (st.minute.minute_ts != minute_ts or st.minute.network_id != network_id):
                # a new minute, or the same minute on another network: that part is a row of its own
                finished, st.minute = st.minute, None
        if finished is not None:
            self._upsert(st, finished)          # db write outside the lock, before the view is built
        with st.lock:
            if self._clear_gen != gen and self._cleared_span_locked(sample.ts):
                log.debug("dropping a sample of %s stamped inside a span cleared while it was recorded", st.host)
                return
            if finished is not None:
                st.day_cache = None             # the 24 h db summary just changed
            if st.minute is not None and self._voided(st.minute.gen, st.minute.minute_ts):
                st.minute = None
            st.samples.append(sample)
            st.last = sample
            if sample.ok:
                st.consecutive_ok += 1
                st.consecutive_missed = 0
            else:
                st.consecutive_missed += 1
                st.consecutive_ok = 0
            if st.minute is None:
                st.minute = _MinuteAgg(minute_ts, network_id, self._clear_gen)
            st.minute.add(sample)
            view = self._view_locked(st, sample.ts)
            light = view["light"]
        if self.raw_log is not None:
            try:
                self.raw_log.write(sample.ts, st.id, st.host, sample.ok, sample.rtt_ms, size)
            except Exception:  # noqa: BLE001
                log.exception("raw log write failed for %s", st.host)
        try:
            self._bus.publish("ping.sample", {"target_id": st.id, "ts": sample.ts, "ok": sample.ok,
                                              "rtt_ms": sample.rtt_ms, "light": light}, ts=sample.ts)
        except Exception:  # noqa: BLE001
            log.exception("publishing ping.sample failed")
        with self._lock:
            listeners = list(self._sample_listeners)
        for fn in listeners:
            try:
                fn(view, sample)
            except Exception:  # noqa: BLE001
                log.exception("sample listener failed for %s", st.host)

    # -- resolution ----------------------------------------------------------------------
    def _do_resolve(self, host: str) -> Tuple[Optional[str], Optional[str]]:
        if is_gateway_alias(host):
            gw = _default_gateway()
            return (gw, None) if gw else (None, "this machine has no default gateway right now")
        resolver = self._resolver
        if resolver is None:
            try:
                # the family this host can route: an IPv6-only network gets the AAAA, not an A record
                # it would miss every second (a false "full internet outage")
                resolver = importlib.import_module("tnt.icmp").resolve_routable
            except Exception as exc:  # noqa: BLE001
                return None, f"resolver unavailable: {exc}"
        try:
            ip = resolver(host)
        except Exception as exc:  # noqa: BLE001
            return None, f"resolve failed: {exc}"
        if not ip:
            return None, "name resolution failed"
        return str(ip), None

    def _alias_interval(self) -> float:
        """The ``gateway`` alias is looked up at least this often: every network watcher poll."""
        try:
            value = float(self._config.get("network.poll_s", 5))
        except Exception:  # noqa: BLE001
            return 5.0
        return max(2.0, min(60.0, value)) if value == value else 5.0

    def _maybe_resolve(self, st: _TargetState, now: float) -> Optional[str]:
        """Return the IP to ping (None when unknown), re-resolving hostnames when due.

        The ``gateway`` alias is due at least every ``network.poll_s`` and 2 s after a miss (a
        cheap native lookup), so it follows a new default gateway even before the network
        watcher reports the change; without a gateway it looks every ``network.poll_s``, never
        every tick. A lookup that a network change overtook (``net_epoch`` moved while it ran) is
        thrown away and repeated at once.
        """
        for _attempt in range(2):
            with st.lock:
                if st.is_literal:
                    return st.ip
                try:
                    interval = float(self._config.get("ping.resolve_interval_s", 300))
                except Exception:  # noqa: BLE001
                    interval = 300.0
                last = st.last_resolve_ts
                if last is None or now < last:
                    due = True
                elif st.ip is None:
                    due = not st.is_alias or now - last >= self._alias_interval()
                elif not st.resolved:
                    due = now - last >= (min(_RESOLVE_RETRY_S, self._alias_interval()) if st.is_alias else _RESOLVE_RETRY_S)
                elif st.is_alias:
                    due = (now - last >= min(interval, self._alias_interval())
                           or (st.consecutive_missed > 0 and now - last >= _ALIAS_MISS_RECHECK_S))
                else:
                    due = now - last >= interval
                if not due:
                    return st.ip
                epoch = st.net_epoch
            ip, err = self._do_resolve(st.host)          # outside the lock: may take up to 3 s
            kind = st.kind_for(ip) if ip else None       # outside the lock: may enumerate adapters
            owner, left_out = self._alias_facts(st, ip)  # outside the lock: may enumerate adapters
            current = self._apply_resolution(st, now, ip, kind, err, epoch, owner, left_out)
            if current is not _STALE:
                return current
        with st.lock:
            return st.ip

    @staticmethod
    def _alias_facts(st: _TargetState, ip: Optional[str]) -> Tuple[Optional[_AdapterId], bool]:
        """For the ``gateway`` alias (call outside every lock): ``(the adapter a gateway it found
        belongs to, whether a gateway it no longer finds was configured away)``; ``(None, False)``
        for any other target."""
        if not st.is_alias:
            return None, False
        if ip:
            return _gateway_owner(ip), False
        with st.lock:
            had, owner = st.ip, st.gateway_owner
        return None, bool(had) and _gateway_left_out(owner)

    def _apply_resolution(self, st: _TargetState, now: float, ip: Optional[str], kind: Optional[str],
                          err: Optional[str], epoch: int, owner: Optional[_AdapterId] = None,
                          left_out: bool = False) -> Any:
        """Store one lookup result on *st*; ``_STALE`` when a network change overtook the lookup.

        For the ``gateway`` alias *owner* is the adapter of the gateway found and *left_out* says a
        gateway that is gone was configured away (its IP is cleared) rather than lost (the last one
        is still pinged). Publishes ``ping.targets`` when the IP or the resolved flag changed, and
        tells the IP listeners when the target switched to another address (or the alias's gateway
        was configured away).
        """
        with st.lock:
            if st.net_epoch != epoch:
                return _STALE
            st.last_resolve_ts = now
            after_change = st.resolved_epoch != epoch
            was = (st.ip, st.resolved)
            old_ip = st.ip
            if ip:
                # only an answer uses the "after a network change" mark up: a lookup that failed while the
                # new network's DNS was not ready must not rob the first real answer of its reason
                st.resolved_epoch = epoch
                if ip != st.ip:
                    st.ip = ip
                    st.kind = kind
                if st.is_alias:
                    st.gateway_owner = owner
                st.resolved = True
                st.resolve_error = None
            else:
                st.resolved = False
                st.resolve_error = err
                if st.is_alias and left_out:
                    st.ip = None            # configured without a gateway: never keep pinging the last router
            if st.is_alias and old_ip is not None and st.ip != old_ip:
                # another router (or none at all): the previous one's samples say nothing about it
                st.samples.clear()
                st.last = None
                st.consecutive_missed = 0
                st.consecutive_ok = 0
            changed = was != (st.ip, st.resolved)
            current = st.ip
        if changed:
            if ip:
                log.info("%s resolved to %s (%s)", st.host, ip, st.kind)
            elif st.is_alias and current:
                log.warning("%s: %s; still pinging %s, the gateway it lost, so its misses count", st.host, err, current)
            else:
                log.warning("%s: %s", st.host, err)
            self._publish_targets()
        if old_ip is not None and current != old_ip:
            self._notify_ip_change(st, old_ip, current, NETWORK_CHANGED_NOTE if (st.is_alias or after_change) else None)
        return current

    def _refresh_alias(self, st: _TargetState, now: float) -> None:
        """Look the default gateway up right now for the alias target *st* (a quick native call)."""
        with st.lock:
            epoch = st.net_epoch
        ip, err = self._do_resolve(st.host)
        kind = st.kind_for(ip) if ip else None
        owner, left_out = self._alias_facts(st, ip)
        self._apply_resolution(st, now, ip, kind, err, epoch, owner, left_out)

    def _refresh_aliases(self) -> None:
        now = float(self._clock())
        for st in self._states():
            if st.is_alias:
                try:
                    self._refresh_alias(st, now)
                except Exception:  # noqa: BLE001
                    log.exception("looking up the default gateway for %s failed", st.host)

    # -- minute aggregation --------------------------------------------------------------
    def _network_id(self) -> Optional[int]:
        """The current network id from *network_fn* (None without one, when unknown or when it fails)."""
        fn = self._network_fn
        if fn is None:
            return None
        try:
            nid = fn()
        except Exception:  # noqa: BLE001
            log.debug("the current network id could not be read", exc_info=True)
            return None
        return int(nid) if isinstance(nid, int) and not isinstance(nid, bool) and nid > 0 else None

    def _upsert(self, st: _TargetState, agg: _MinuteAgg) -> None:
        if agg.sent <= 0:
            return
        minute_ts, sent, received, avg, mn, mx, jit = agg.row()
        args: Tuple[Any, ...] = (st.id, minute_ts, sent, received, avg, mn, mx, jit)
        if agg.network_id is not None:
            args += (agg.network_id,)
        # off the ping worker's thread whenever the writer runs (a locked database must
        # stall the writer, never the pings); synchronous fallback otherwise (tests, shutdown)
        with self._gen_lock:
            if self._voided(agg.gen, agg.minute_ts):
                return                          # the history was cleared while it was built: never written
            if self._writer.submit(self._write_minute, agg.gen, args):
                return
        try:
            self._write_minute(agg.gen, args)
        except Exception:  # noqa: BLE001
            log.exception("upsert_ping_minute failed for %s minute %s", st.host, minute_ts)

    def _write_minute(self, gen: int, args: Tuple[Any, ...]) -> None:
        """Write one finished minute unless a clear after it began covers it (on the writer thread, or synchronously).
        ``args[1]`` is its minute_ts."""
        with self._write_lock:
            if self._voided(gen, int(args[1])):
                return
            self._db.upsert_ping_minute(*args)

    def _flush_minute(self, st: _TargetState) -> None:
        with st.lock:
            agg, st.minute = st.minute, None
        if agg is not None:
            self._upsert(st, agg)
            with st.lock:
                st.day_cache = None             # the db part of the 24 h figure just changed

    # -- statistics ----------------------------------------------------------------------
    @staticmethod
    def _stats_of(samples: List[Sample], seconds: int) -> Dict[str, Any]:
        sent = len(samples)
        rtts = [float(s.rtt_ms) for s in samples if s.ok and s.rtt_ms is not None]
        received = len(rtts)
        lost = sent - received
        jitter: Optional[float]
        if len(rtts) >= 2:
            jitter = sum(abs(b - a) for a, b in zip(rtts, rtts[1:])) / (len(rtts) - 1)
        else:
            jitter = 0.0 if rtts else None
        return {
            "seconds": int(seconds),
            "sent": sent,
            "received": received,
            "lost": lost,
            "loss_pct": round(100.0 * lost / sent, 2) if sent else None,
            "avg_ms": round(sum(rtts) / received, 2) if received else None,
            "min_ms": round(min(rtts), 2) if received else None,
            "max_ms": round(max(rtts), 2) if received else None,
            "jitter_ms": round(jitter, 2) if jitter is not None else None,
            "last_rtt_ms": rtts[-1] if rtts else None,
        }

    def _window_locked(self, st: _TargetState, now: float, seconds: int) -> Dict[str, Any]:
        cutoff = now - float(seconds)
        return self._stats_of([s for s in st.samples if s.ts > cutoff], seconds)

    def _thresholds(self) -> Dict[str, Any]:
        try:
            th = self._config.section("thresholds") or {}
        except Exception:  # noqa: BLE001
            th = {}
        return {
            "window_s": int(th.get("window_s", 60) or 60),
            "local_warn_ms": float(th.get("local_warn_ms", 30)),
            "internet_warn_ms": float(th.get("internet_warn_ms", 150)),
            "warn_loss_pct": float(th.get("warn_loss_pct", 2.0)),
            "bad_loss_pct": float(th.get("bad_loss_pct", 15.0)),
        }

    def _light_locked(self, st: _TargetState, now: float, th: Optional[Dict[str, Any]] = None,
                      window: Optional[Dict[str, Any]] = None) -> str:
        if self._paused or not st.samples:
            return "grey"
        if st.is_alias and st.ip is None:
            return "grey"               # no default gateway: nothing is being measured
        th = th or self._thresholds()
        if st.in_outage:
            return "red"
        w = window if window is not None else self._window_locked(st, now, th["window_s"])
        if not w["sent"]:
            return "grey"
        loss = float(w["loss_pct"] or 0.0)
        # A handful of samples (fresh target, just resumed) must not go red on a single miss,
        # and a finished outage must not stay red for the rest of the window: red requires
        # enough samples AND the most recent ones to still be failing.
        recent = list(st.samples)[-_LIGHT_RECENT_N:]
        recent_all_ok = bool(recent) and all(s.ok for s in recent)
        enough = int(w["sent"]) >= _LIGHT_MIN_SAMPLES
        if loss >= th["bad_loss_pct"] and enough and not recent_all_ok:
            return "red"
        warn_ms = th["local_warn_ms"] if st.kind == "local" else th["internet_warn_ms"]
        if (loss >= th["warn_loss_pct"] and enough) or (w["avg_ms"] is not None and w["avg_ms"] > warn_ms):
            return "yellow"
        if loss > 0 and not enough and not recent_all_ok:
            return "yellow"
        return "green"

    def _day_locked(self, st: _TargetState, now: float) -> Dict[str, Any]:
        if st.day_cache is None or now - st.day_cache_ts >= _DAY_CACHE_S or now < st.day_cache_ts:
            try:
                st.day_cache = dict(self._db.ping_summary(st.id, now - 86400, now))
            except Exception:  # noqa: BLE001
                log.exception("ping_summary failed for %s", st.host)
                st.day_cache = {"sent": 0, "received": 0, "lost": 0, "loss_pct": None,
                                "avg_ms": None, "min_ms": None, "max_ms": None}
            st.day_cache_ts = now
        base = st.day_cache
        agg = st.minute
        b_sent, b_recv = int(base.get("sent") or 0), int(base.get("received") or 0)
        sent = b_sent + (agg.sent if agg else 0)
        received = b_recv + (agg.received if agg else 0)
        total = float(base.get("avg_ms") or 0.0) * b_recv + (agg.sum if agg else 0.0)
        mins = [v for v in (base.get("min_ms"), agg.min if agg else None) if v is not None]
        maxs = [v for v in (base.get("max_ms"), agg.max if agg else None) if v is not None]
        return {
            "sent": sent,
            "received": received,
            "lost": sent - received,
            "loss_pct": round(100.0 * (sent - received) / sent, 2) if sent else None,
            "avg_ms": round(total / received, 2) if received else None,
            "min_ms": round(min(mins), 2) if mins else None,
            "max_ms": round(max(maxs), 2) if maxs else None,
        }

    def _view_locked(self, st: _TargetState, now: float) -> Dict[str, Any]:
        th = self._thresholds()
        window = self._window_locked(st, now, th["window_s"])
        window.pop("last_rtt_ms", None)
        last = st.last
        return {
            "id": st.id,
            "host": st.host,
            "label": st.label,
            "name": st.name,
            "kind": st.kind,
            "ip": st.ip,
            "enabled": st.enabled,
            "resolved": st.resolved,
            "resolve_error": st.resolve_error,
            "light": self._light_locked(st, now, th, window),
            "in_outage": st.in_outage,
            "last": {"ts": last.ts, "ok": last.ok, "rtt_ms": last.rtt_ms} if last else None,
            "consecutive_missed": st.consecutive_missed,
            "consecutive_ok": st.consecutive_ok,
            "window": window,
            "day": self._day_locked(st, now),
            "since_ts": st.since_ts,
        }

    def _view(self, st: _TargetState, now: Optional[float] = None) -> Dict[str, Any]:
        with st.lock:
            return self._view_locked(st, float(now if now is not None else self._clock()))

    def _state(self, target_id: Any) -> Optional[_TargetState]:
        try:
            tid = int(target_id)
        except (TypeError, ValueError):
            return None
        with self._lock:
            return self._targets.get(tid)

    def _states(self) -> List[_TargetState]:
        with self._lock:
            return sorted(self._targets.values(), key=lambda s: (s.sort_order, s.id))

    def reorder(self, ids: Any) -> List[Dict[str, Any]]:
        """Reorder the tiles: the given ids come first in that order, the rest keep their
        relative order. Persists to the db and publishes ``ping.targets``. Returns the views."""
        wanted: List[int] = []
        for i in ids or []:
            try:
                ti = int(i)
            except (TypeError, ValueError):
                raise ValueError("ids must be integers") from None
            if ti not in wanted:
                wanted.append(ti)
        with self._lock:
            current = sorted(self._targets.values(), key=lambda s: (s.sort_order, s.id))
            known = {s.id for s in current}
            unknown = [i for i in wanted if i not in known]
            if unknown:
                raise ValueError(f"unknown target id(s): {unknown}")
            order = [i for i in wanted] + [s.id for s in current if s.id not in wanted]
            for pos, tid in enumerate(order, start=1):
                self._targets[tid].sort_order = pos
        try:
            self._db.set_target_order(order)
        except Exception:  # noqa: BLE001
            log.exception("persisting the target order failed")
        log.info("targets reordered: %s", order)
        self._publish_targets()
        return self.targets()

    # -- public queries ------------------------------------------------------------------
    def targets(self) -> List[Dict[str, Any]]:
        now = float(self._clock())
        return [self._view(st, now) for st in self._states()]

    def target(self, target_id: int) -> Optional[Dict[str, Any]]:
        st = self._state(target_id)
        return self._view(st) if st is not None else None

    def samples(self, target_id: int, seconds: int = 300) -> List[Sample]:
        st = self._state(target_id)
        if st is None:
            return []
        cutoff = float(self._clock()) - _seconds_arg(seconds, 300)
        with st.lock:
            return [s for s in st.samples if s.ts > cutoff]

    def stats(self, target_id: int, seconds: int) -> Dict[str, Any]:
        secs = int(_seconds_arg(seconds, 60))
        st = self._state(target_id)
        if st is None:
            out = self._stats_of([], secs)
        else:
            now = float(self._clock())
            with st.lock:
                out = self._window_locked(st, now, secs)
        out.pop("seconds", None)
        return out

    def light(self, target_id: int) -> str:
        st = self._state(target_id)
        if st is None:
            return "grey"
        with st.lock:
            return self._light_locked(st, float(self._clock()))

    # -- mutation ------------------------------------------------------------------------
    def add_target(self, host: str, label: Optional[str] = None) -> Dict[str, Any]:
        """Add (or return the existing) target and start pinging it. ValueError on bad host."""
        return self._add(host, label, publish=True)

    def _add(self, host: str, label: Optional[str], publish: bool) -> Dict[str, Any]:
        clean = validate_host(host)
        # An IP that an existing target already resolves to (typically the 'gateway' alias)
        # is the same device: hand that target back instead of pinging one address twice.
        if _is_ip_literal(clean):
            self._refresh_aliases()     # compare with the gateway of the network this PC is on now
            with self._lock:
                dup = next((s for s in self._targets.values()
                            if s.ip == clean or str(s.host).lower() == clean.lower()), None)
            if dup is not None:
                log.info("target %s already covers %s (id %d); not adding a duplicate", dup.host, clean, dup.id)
                return self._view(dup, float(self._clock()))
        label = (str(label).strip()[:_LABEL_MAX] if label is not None else "") or None
        row = self._db.add_target(clean, label)
        tid = int(row["id"])
        now = float(self._clock())
        created = False
        fresh = _TargetState(row, now)              # outside the lock: classify_ip may enumerate adapters
        with self._lock:
            st = self._targets.get(tid)
            if st is None:
                st = fresh
                self._targets[tid] = st
                created = True
            running = self._running
        if created:
            if not st.enabled:
                try:
                    self._db.set_target_enabled(tid, True)
                except Exception:  # noqa: BLE001
                    log.exception("enabling target %s failed", clean)
                st.enabled = True
            log.info("target added: %s (id %d)", clean, tid)
            if running:
                self._start_worker(st)
            if publish:
                self._publish_targets()
        return self._view(st, now)

    def set_target_name(self, target_id: Any, name: Optional[str]) -> Optional[Dict[str, Any]]:
        """Set (or clear) a target's custom display name. Returns the updated view, or None when the
        target does not exist. An empty name clears it (the UI reverts to the label/host)."""
        st = self._state(target_id)
        if st is None:
            return None
        clean = (str(name).strip()[:_LABEL_MAX] if name is not None else "") or None
        with st.lock:
            if st.name == clean:
                return self._view_locked(st, float(self._clock()))
            st.name = clean
        try:
            self._db.set_target_name(int(st.id), clean)
        except Exception:  # noqa: BLE001
            log.exception("saving the custom name for target %s failed", st.host)
        log.info("target %d custom name %s", st.id, repr(clean) if clean else "cleared")
        self._publish_targets()
        return self._view(st, float(self._clock()))

    def remove_target(self, target_id: int) -> bool:
        """Stop the worker, flush its minute, delete the db row, notify listeners."""
        try:
            tid = int(target_id)
        except (TypeError, ValueError):
            return False
        with self._lock:
            st = self._targets.pop(tid, None)
        if st is not None:
            self._stop_worker(st)
            self._flush_minute(st)
            if self.raw_log is not None:
                # its last rows would otherwise wait for another target's write (or for stop())
                try:
                    self.raw_log.flush()
                except Exception:  # noqa: BLE001
                    log.exception("flushing the raw ping log failed")
        try:
            removed = bool(self._db.remove_target(tid))
        except Exception:  # noqa: BLE001
            log.exception("deleting target %s from the database failed", tid)
            removed = False
        if st is None and not removed:
            return False
        log.info("target removed: %s (id %d)", st.host if st else "?", tid)
        self._publish_targets()
        with self._lock:
            listeners = list(self._removal_listeners)
        for fn in listeners:
            try:
                fn(tid)
            except Exception:  # noqa: BLE001
                log.exception("removal listener failed for target %s", tid)
        return True

    def load_defaults(self, replace: bool = True) -> List[Dict[str, Any]]:
        """Reset the tiles to :data:`DEFAULT_TILES` (gateway, 1.1.1.1, totalelectronics.com).

        With *replace* (the default, what the "Load Default Tiles" button does) every other
        target is removed so the result is exactly the three defaults in that order; with
        ``replace=False`` the defaults are merely added in front of the existing tiles.
        """
        # a fresh look at the adapters: the gateway tile must carry the gateway of the network this
        # PC is on now, not one cached before the laptop moved
        _invalidate_netinfo_cache()
        keep = {h.lower() for h, _ in DEFAULT_TILES}
        if replace:
            for st in self._states():
                if str(st.host).lower() not in keep:
                    try:
                        self.remove_target(st.id)
                    except Exception:  # noqa: BLE001
                        log.exception("removing %s while loading the defaults failed", st.host)
        ids: List[int] = []
        now = float(self._clock())
        for host, label in DEFAULT_TILES:
            try:
                tid = int(self._add(host, label, publish=False)["id"])
                ids.append(tid)
                st = self._state(tid)
                if st is not None and st.is_alias:
                    # the alias follows the current default gateway (see GATEWAY_HOSTS); it is kept
                    # even when there is none right now (a docked laptop gets one later)
                    self._refresh_alias(st, now)
                    if st.ip is None:
                        log.info("no default gateway at the moment; the 'gateway' tile will resolve once one appears")
                elif st is not None and not st.is_literal:
                    with st.lock:
                        st.last_resolve_ts = None       # host names re-resolve on their next tick
            except ValueError as exc:
                log.warning("skipping default target %r: %s", host, exc)
            except Exception:  # noqa: BLE001
                log.exception("adding default target %r failed", host)
        try:
            return self.reorder(ids)          # defaults first, in their order; publishes ping.targets
        except Exception:  # noqa: BLE001
            log.exception("ordering the default tiles failed")
            self._publish_targets()
            return self.targets()

    def set_in_outage(self, target_id: int, in_outage: bool) -> None:
        st = self._state(target_id)
        if st is None:
            return
        with st.lock:
            st.in_outage = bool(in_outage)

    def set_paused(self, paused: bool) -> None:
        paused = bool(paused)
        if paused == self._paused:
            return
        self._paused = paused
        log.info("ping monitoring %s", "paused" if paused else "resumed")
        if paused:
            # no further samples will roll the minute or trigger the periodic raw-log
            # flush: persist the partial minutes and get the last rows on disk now
            for st in self._states():
                self._flush_minute(st)
            if self.raw_log is not None:
                try:
                    self.raw_log.flush()
                except Exception:  # noqa: BLE001
                    log.exception("flushing the raw ping log failed")
        self._publish_targets()

    # -- clear history (Settings; Engine.clear_history) --------------------------------------
    def clear_history(self, since_ts: Optional[float]) -> int:
        """Forget the ping history recorded in ``[since_ts, now]`` (None: all of it).  Returns the minute rows deleted.

        In this order: the clear generation is bumped, so no minute aggregate begun before now that overlaps the span is
        ever written - the one still being built, one queued in the writer, one a worker has just taken out of its
        target's lock (``_upsert`` and ``_write_minute`` check it; a minute that ended before *since_ts* is still written);
        from the bump on, a sample stamped inside the span goes nowhere, and every sample that passed its check just before
        the bump is waited for (up to ``_CLEAR_DRAIN_S``) until it is in the ring, its minute, the raw log and the
        listeners, so what follows removes it from all of them; every in-progress aggregate that overlaps the span is
        dropped; the minute rows overlapping the span go (``Database.delete_ping_minutes_since``, serialised with every
        minute write, so one that passed its check a moment ago lands first and is deleted with the rest); then each
        target's ring loses its samples from *since_ts* on (the ones stamped from this call's start on stay), ``last`` and
        the miss/answer run follow what is left, the 24 h figure is recomputed; and the raw CSV log loses its rows from
        *since_ts* up to this call's start (``RawPingLog.clear_since``).  A sample stamped inside the span that comes back
        after the clear (its echo was out) is dropped for ``_CLEAR_INFLIGHT_S``.  A failing database delete raises (after
        the aggregates were dropped: their data is gone either way) and leaves the rings alone.  ``last_clear_info`` is
        ``{"minutes", "raw_log", "raw_log_failed", "earliest_ts"}``: ``earliest_ts`` is where the earliest minute it removed
        began (a bucket that straddles *since_ts* starts before it), None when it removed none.  The caller publishes
        ``ping.targets`` (:meth:`publish_targets`)."""
        since = None if since_ts is None else float(since_ts)
        at = float(self._clock())
        me = threading.get_ident()
        with self._gen_cond:
            self._clear_gen += 1
            gen = self._clear_gen
            self._clears = (self._clears + [(gen, since, at, float(self._monotonic()))])[-_CLEARS_KEPT:]
            # the samples already past their check finish first (never this thread's own: it would wait for itself)
            deadline = time.monotonic() + _CLEAR_DRAIN_S
            while any(g < gen for ident, g in self._inflight.items() if ident != me):
                left = deadline - time.monotonic()
                if left <= 0:
                    log.warning("clear history: %d ping sample(s) still being recorded after %.0f s; clearing anyway",
                                sum(1 for ident, g in self._inflight.items() if ident != me and g < gen), _CLEAR_DRAIN_S)
                    break
                self._gen_cond.wait(left)
        with self._lock:
            states = list(self._targets.values())
        earliest: List[float] = []
        for st in states:
            with st.lock:
                if st.minute is not None and self._voided(st.minute.gen, st.minute.minute_ts):
                    if st.minute.sent > 0:
                        earliest.append(float(st.minute.minute_ts))
                    st.minute = None
                st.day_cache = None
        info: Dict[str, Any] = {}
        with self._write_lock:
            deleted = int(self._db.delete_ping_minutes_since(since, info=info))
        if info.get("earliest_ts") is not None:
            earliest.append(float(info["earliest_ts"]))
        for st in states:
            with st.lock:
                kept = [s for s in st.samples if (since is not None and s.ts < since) or s.ts >= at]
                if len(kept) != len(st.samples):
                    st.samples.clear()
                    st.samples.extend(kept)
                st.last = kept[-1] if kept else None
                missed = answered = 0
                for s in reversed(kept):
                    if s.ok and not missed:
                        answered += 1
                    elif not s.ok and not answered:
                        missed += 1
                    else:
                        break
                st.consecutive_missed, st.consecutive_ok = missed, answered
                st.day_cache = None
                st.day_cache_ts = 0.0
        raw_removed, raw_failed = 0, []  # type: int, List[str]
        if self.raw_log is not None:
            try:
                # up to this call's start: a row stamped since then was recorded after the clear, as the ring keeps it
                raw_removed = int(self.raw_log.clear_since(since, until_ts=at))
                raw_failed = list(getattr(self.raw_log, "last_clear_failed", []) or [])
            except Exception as exc:  # noqa: BLE001 - the minutes are cleared; the caller reports the log
                log.exception("clearing the raw ping log failed")
                raw_failed = [f"{type(exc).__name__}: {exc}"]
        self.last_clear_info = {"minutes": deleted, "raw_log": raw_removed, "raw_log_failed": raw_failed,
                                "earliest_ts": min(earliest) if earliest else None}
        log.info("ping history cleared %s: %d minute row(s), %d raw log row(s)/file(s)",
                 "entirely" if since is None else f"from {since:.0f}", deleted, raw_removed)
        return deleted

    def publish_targets(self) -> None:
        """Publish ``ping.targets`` with every target's current view (after a clear, the lights and figures)."""
        self._publish_targets()

    # -- listeners -----------------------------------------------------------------------
    def add_sample_listener(self, fn: Callable[[Dict[str, Any], Sample], None]) -> Callable[[], None]:
        with self._lock:
            self._sample_listeners.append(fn)

        def unsubscribe() -> None:
            with self._lock:
                if fn in self._sample_listeners:
                    self._sample_listeners.remove(fn)

        return unsubscribe

    def add_removal_listener(self, fn: Callable[[int], None]) -> Callable[[], None]:
        with self._lock:
            self._removal_listeners.append(fn)

        def unsubscribe() -> None:
            with self._lock:
                if fn in self._removal_listeners:
                    self._removal_listeners.remove(fn)

        return unsubscribe

    def add_ip_listener(self, fn: Callable[[Dict[str, Any], Optional[str], Optional[str], Optional[str]], None]
                        ) -> Callable[[], None]:
        """``fn(view, old_ip, new_ip, reason)`` when a resolved target switches to another address
        (or the ``gateway`` alias's gateway was configured away: *new_ip* ``None``). *reason* is
        ``"network changed"`` when a network change caused it (always for the alias), else
        ``None`` (a host name's periodic lookup answered another address). Called outside every
        lock, on whichever thread did the lookup."""
        with self._lock:
            self._ip_listeners.append(fn)

        def unsubscribe() -> None:
            with self._lock:
                if fn in self._ip_listeners:
                    self._ip_listeners.remove(fn)

        return unsubscribe

    def _notify_ip_change(self, st: _TargetState, old_ip: Optional[str], new_ip: Optional[str],
                          reason: Optional[str]) -> None:
        with self._lock:
            listeners = list(self._ip_listeners)
            removed = self._targets.get(st.id) is not st
        if not listeners or removed:
            return
        view = self._view(st)
        for fn in listeners:
            try:
                fn(view, old_ip, new_ip, reason)
            except Exception:  # noqa: BLE001
                log.exception("IP change listener failed for %s", st.host)

    def on_network_change(self, data: Optional[Dict[str, Any]] = None) -> None:
        """``net.changed`` from the network watcher (on its thread: quick, never raises).

        Every host name target and the ``gateway`` alias re-resolve on their next tick - their own
        worker does the lookup, DNS may take seconds - and a lookup already running is discarded.
        When the local subnets changed, ``kind`` (local/internet) is recomputed for every target
        and ``ping.targets`` published if one moved.
        """
        try:
            data = data or {}
            states = self._states()
            for st in states:
                with st.lock:
                    if st.is_literal:
                        continue
                    st.net_epoch += 1
                    st.last_resolve_ts = None
            if not data.get("subnets_changed", True):
                return
            moved = False
            for st in states:
                with st.lock:
                    ip = st.ip
                if not ip:
                    continue
                kind = st.kind_for(ip)                  # outside the lock: may enumerate adapters
                with st.lock:
                    if st.ip == ip and st.kind != kind:
                        st.kind = kind
                        moved = True
            if moved:
                self._publish_targets()
        except Exception:  # noqa: BLE001
            log.exception("handling a network change in the ping manager failed")

    def _publish_targets(self) -> None:
        try:
            self._bus.publish("ping.targets", {"targets": self.targets()})
        except Exception:  # noqa: BLE001
            log.exception("publishing ping.targets failed")
