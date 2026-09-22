"""Clear history: the time ranges, and the record of what was cleared (Settings > "Clear history").

Like a browser's "clear browsing data", a clear removes what was recorded in the last N: everything in or
overlapping ``[since_ts, now]``, where ``since_ts = now - seconds`` on the *service* clock and the ``all`` range is
``since_ts = None`` (everything).  :data:`RANGES` is the one place the service keeps the eight keys; the UI keeps its
own copy of the same keys and labels (a test compares them).

:meth:`tnt.engine.Engine.clear_history` does the work (ARCHITECTURE 3.11); this module holds what it and the API
share:

* :data:`RANGES` (key -> seconds, ``None`` for ``all``), :data:`RANGE_LABELS`, :func:`since_for`, :func:`ranges_view`.
* :data:`CATEGORIES`: the keys of ``cleared`` in the result (every one always present, see
  :func:`empty_counts`).
* :class:`ClearConflict`: why a clear cannot run now (``full_scan_running``, ``clear_running``), the API's 409.
* The cleared spans, kept in the database's ``meta`` table under :data:`META_KEY` as a JSON list of
  ``{"since_ts": float|null, "at": float, "range": key}``, newest last.  A span's ``since_ts`` is where the cleared time
  begins: the clear's cutoff, or earlier when the clear deleted a record that began before it (an outage or a minute
  bucket that straddles the cutoff goes whole, so the time from its start is cleared too); the clear's own answer keeps
  the requested cutoff.  At most :data:`MAX_SPANS` are kept, a span that
  ended more than :data:`SPAN_MAX_AGE_S` ago is dropped, and an ``all`` clear replaces the list with its one entry
  (:func:`add_span`, :func:`record_span`).  :func:`last_span` is the Settings status line and :func:`timeline_spans`
  the Outages timeline's ``"cleared"`` field: a cleared span is painted like a monitoring gap, never as "fine".

Nothing here raises for a damaged meta value: an unreadable list is an empty one.
"""
from __future__ import annotations

import json
import logging
import math
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Optional

log = logging.getLogger(__name__)

#: range key -> seconds back from now (``None``: all time).  Ordered as the Settings list shows them.
RANGES: "OrderedDict[str, Optional[int]]" = OrderedDict([
    ("5m", 300),
    ("30m", 1800),
    ("1h", 3600),
    ("6h", 21600),
    ("24h", 86400),
    ("7d", 604800),
    ("30d", 2592000),
    ("all", None),
])

#: range key -> what the Settings list and the result call it
RANGE_LABELS: Dict[str, str] = {
    "5m": "Last 5 minutes",
    "30m": "Last 30 minutes",
    "1h": "Last hour",
    "6h": "Last 6 hours",
    "24h": "Last 24 hours",
    "7d": "Last 7 days",
    "30d": "Last 30 days",
    "all": "All time",
}

#: the range Settings selects first
DEFAULT_RANGE = "1h"

#: the keys of ``cleared`` in a clear's result, in this order (Wi-Fi is not here: the page adds its own outcome)
CATEGORIES = ("ping", "outages", "speed", "discovery", "captures", "faults", "sip", "proav")

#: the names ``stopped`` uses for the running jobs a clear stops
STOPPED_SPEED = "speed test"
STOPPED_DISCOVERY = "discovery scan"
STOPPED_PROAV = "Pro AV scan"
STOPPED_SIP = "SIP check"

#: why a cancelled speed test or Discovery scan ended, in its ``speedtest.done`` / ``discovery.done`` event
CANCEL_REASON = "history cleared"

#: the db meta key of the cleared spans
META_KEY = "history_cleared"
#: at most this many spans are kept (the oldest go first)
MAX_SPANS = 50
#: a span that ended longer ago than this is dropped
SPAN_MAX_AGE_S = 30 * 86400.0

#: the keys of one span in the list, and of GET /api/history
SPAN_KEYS = ("since_ts", "at", "range")
HISTORY_KEYS = ("ranges", "last")
#: the keys of POST /api/history/clear and of the ``history.cleared`` event
RESULT_KEYS = ("range", "label", "since_ts", "ts", "cleared", "stopped", "skipped")

#: the API's refusal texts
BAD_RANGE_MSG = "range must be one of " + ", ".join(RANGES)
FULL_SCAN_RUNNING_MSG = ("A Full Scan is running and reads this history as it goes. Wait for it to finish (or cancel it) "
                         "and clear the history then.")
CLEAR_RUNNING_MSG = "History is already being cleared. Wait a moment and try again."
#: POST /api/reports/scan while a clear runs (409 ``clear_running``): the page shows "Could not start the full scan: ..."
SCAN_DURING_CLEAR_MSG = "History is being cleared. Try again in a moment."


def reason_text(text: Any) -> str:
    """A ``skipped`` reason as the page shows it: one plain sentence without its closing period (the page adds it)."""
    s = " ".join(str(text or "").split())
    while s.endswith("."):
        s = s[:-1].rstrip()
    return s


def _clause(text: Any) -> str:
    """*text* to follow a colon: its first letter lower-cased ("It is being downloaded" -> "it is being downloaded")."""
    s = reason_text(text) or "it could not be deleted"
    return s[:1].lower() + s[1:]


def capture_skip_reason(name: str, why: Any) -> str:
    """The ``skipped`` reason for one packet capture file left alone, named - for the administrator's own answer only."""
    return f"{name} was left alone: {_clause(why)}"


def public_capture_skips(whys: Iterable[Any]) -> List[Dict[str, str]]:
    """The same files for the ``history.cleared`` event every window hears: how many were left alone and why, never
    their names (capture file names are for a Windows administrator only, as ``capture.state`` is).  One entry per
    reason, in the order first seen."""
    counts: "OrderedDict[str, int]" = OrderedDict()
    for why in whys:
        clause = _clause(why)
        counts[clause] = counts.get(clause, 0) + 1
    out: List[Dict[str, str]] = []
    for clause, n in counts.items():
        text = (f"A packet capture was left alone: {clause}" if n == 1
                else f"{n} packet captures were left alone, each for this reason: {clause}")
        out.append({"what": "captures", "reason": text})
    return out


class ClearConflict(RuntimeError):
    """A clear that cannot run now: ``code`` is ``full_scan_running`` or ``clear_running`` (the API's 409)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = str(code)
        self.message = str(message)


def valid_range(range_key: Any) -> bool:
    """Whether *range_key* is one of the eight keys (a non-string never is)."""
    return isinstance(range_key, str) and range_key in RANGES


def since_for(range_key: str, now: float) -> Optional[float]:
    """``now - seconds`` of *range_key*, ``None`` for ``all``.  ``ValueError`` for anything but the eight keys."""
    if not valid_range(range_key):
        raise ValueError(BAD_RANGE_MSG)
    seconds = RANGES[range_key]
    return None if seconds is None else float(now) - float(seconds)


def ranges_view() -> List[Dict[str, str]]:
    """``[{"key", "label"}, ...]`` in the Settings order."""
    return [{"key": key, "label": RANGE_LABELS[key]} for key in RANGES]


def empty_counts() -> Dict[str, int]:
    """``cleared`` before anything was cleared: every category, 0."""
    return {key: 0 for key in CATEGORIES}


# --------------------------------------------------------------------------- the cleared spans
def _finite(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _clean_span(item: Any) -> Optional[Dict[str, Any]]:
    """One stored span in its canonical shape, or None when it is not one."""
    if not isinstance(item, dict):
        return None
    at = _finite(item.get("at"))
    key = item.get("range")
    if at is None or not valid_range(key):
        return None
    since = _finite(item.get("since_ts"))
    if since is None and key != "all":
        return None
    return {"since_ts": None if key == "all" else min(since, at), "at": at, "range": key}  # type: ignore[type-var]


def parse_spans(text: Any) -> List[Dict[str, Any]]:
    """The spans in a stored meta value (oldest first); anything unreadable is left out."""
    if not isinstance(text, str) or not text:
        return []
    try:
        raw = json.loads(text)
    except ValueError:
        return []
    if not isinstance(raw, list):
        return []
    return [s for s in (_clean_span(item) for item in raw) if s is not None]


def add_span(spans: Iterable[Dict[str, Any]], since_ts: Optional[float], at: float, range_key: str) -> List[Dict[str, Any]]:
    """*spans* with one more clear at the end: an ``all`` clear replaces them all; spans that ended more than
    SPAN_MAX_AGE_S before *at* are dropped and at most MAX_SPANS are kept (the newest)."""
    entry = _clean_span({"since_ts": since_ts, "at": at, "range": range_key})
    if entry is None:
        raise ValueError("a cleared span needs a range key and finite times")
    if range_key == "all":
        return [entry]
    keep = [s for s in (_clean_span(s) for s in spans) if s is not None and s["at"] >= float(at) - SPAN_MAX_AGE_S]
    keep.append(entry)
    return keep[-MAX_SPANS:]


def load_spans(db: Any) -> List[Dict[str, Any]]:
    """The spans kept in *db* (oldest first); ``[]`` without a database or when it cannot be read."""
    if db is None:
        return []
    try:
        return parse_spans(db.get_meta(META_KEY))
    except Exception:  # noqa: BLE001 - a status line must never fail over its bookkeeping
        log.exception("reading the cleared history spans failed")
        return []


def record_span(db: Any, since_ts: Optional[float], at: float, range_key: str) -> List[Dict[str, Any]]:
    """Add one clear to the spans kept in *db* and return the new list (raises what the database raises)."""
    spans = add_span(load_spans(db), since_ts, at, range_key)
    db.set_meta(META_KEY, json.dumps(spans, separators=(",", ":")))
    return spans


def last_span(db: Any) -> Optional[Dict[str, Any]]:
    """The newest clear (``{"since_ts", "at", "range"}``) or None."""
    spans = load_spans(db)
    return dict(spans[-1]) if spans else None


def clip_spans(spans: Iterable[Dict[str, Any]], start_ts: float, end_ts: float) -> List[Dict[str, float]]:
    """``[{"start_ts", "end_ts"}]``: each span ``[since_ts, at]`` clipped to ``[start_ts, end_ts]`` (``since_ts`` null
    starts at *start_ts*), oldest first, empty ones left out and overlapping ones merged."""
    lo, hi = float(start_ts), float(end_ts)
    out: List[Dict[str, float]] = []
    for s in sorted((c for c in (_clean_span(s) for s in spans) if c is not None),
                    key=lambda c: (c["since_ts"] if c["since_ts"] is not None else -math.inf, c["at"])):
        start = lo if s["since_ts"] is None else max(float(s["since_ts"]), lo)
        end = min(float(s["at"]), hi)
        if end <= start:
            continue
        if out and start <= out[-1]["end_ts"]:
            out[-1]["end_ts"] = max(out[-1]["end_ts"], end)
        else:
            out.append({"start_ts": start, "end_ts": end})
    return out


def timeline_spans(db: Any, start_ts: float, end_ts: float) -> List[Dict[str, float]]:
    """The Outages timeline's ``"cleared"``: the spans kept in *db* clipped to its range."""
    return clip_spans(load_spans(db), start_ts, end_ts)


def history_view(db: Any) -> Dict[str, Any]:
    """GET /api/history: ``{"ranges": [{"key","label"}...], "last": <newest span or null>}``."""
    return {"ranges": ranges_view(), "last": last_span(db)}


__all__ = [
    "RANGES", "RANGE_LABELS", "DEFAULT_RANGE", "CATEGORIES", "CANCEL_REASON", "META_KEY", "MAX_SPANS", "SPAN_MAX_AGE_S",
    "SPAN_KEYS", "HISTORY_KEYS", "RESULT_KEYS", "ClearConflict", "valid_range", "since_for", "ranges_view", "empty_counts",
    "parse_spans", "add_span", "load_spans", "record_span", "last_span", "clip_spans", "timeline_spans", "history_view",
    "STOPPED_SPEED", "STOPPED_DISCOVERY", "STOPPED_PROAV", "STOPPED_SIP", "BAD_RANGE_MSG", "FULL_SCAN_RUNNING_MSG",
    "CLEAR_RUNNING_MSG", "SCAN_DURING_CLEAR_MSG", "reason_text", "capture_skip_reason", "public_capture_skips",
]
