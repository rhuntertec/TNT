"""Pattern analysis over speed-test history (``patterns``).

:func:`analyse_patterns` is a pure function over ``speedtests`` rows (the dicts
``db.list_speedtests`` returns, any order) and never touches the database, so
it is trivially testable with synthetic rows.

Time-of-day buckets use *local* time: ``local = ts + tz_offset_s``; ``hour =
(local % 86400) // 3600``; ``weekday = (local // 86400 + 3) % 7`` (Monday = 0,
1970-01-01 was a Thursday). Only ``ok`` rows with a numeric ``download_mbps``
feed the statistics; failed rows are only counted.

Findings are plain-English strings from simple rules:

* worst 3-hour block (>= 3 tests) whose mean download is >= 15 % below the
  overall median  -> "Downloads are ~40% slower between 19:00 and 22:00"
* failed tests    -> "3 tests failed in the last 7 days"
* ok tests whose upload could not be measured (their note starts with
  ``base.UPLOAD_NOT_MEASURED``: nothing was acknowledged, which is what a dead
  or very slow upstream looks like) -> "The upload could not be measured in 3
  of 20 tests in the last 7 days, while the download worked."  Notes where the
  server refused the upload (``base.UPLOAD_REFUSED``, an HTTP 4xx) are not the
  line's doing and get their own finding -> "The test server refused the upload
  in 2 of 20 tests in the last 7 days: that is the server, not this line."
* ok tests with a stalled phase (note "... stalled: ...") -> "2 tests stalled
  part-way: nothing moved for several seconds."
* weekday (>= 3 tests) >= 20 % below the median -> "... slower on Saturdays"
* upload/download asymmetry (median upload < 10 % of median download)
* latency spikes (latency > max(2 x median, median + 50 ms))
* trend (|trend| >= 0.5 %/day over a span >= 2 days)
* slow tests below ``warn_below_pct`` of the median
* an explanatory line when there is no / too little data.

Deviation from the contract signature: an optional ``days`` keyword is
accepted so the caller can label the window; when omitted it is derived from
the span of the rows (min 1, default 7 for an empty list).
``trend_down_pct_per_day`` is ``0.0`` (not ``None``) when it cannot be
computed (< 3 ok rows or no time spread) so consumers can always format it.
"""
from __future__ import annotations

import logging
import math
from typing import Any, Dict, List, Optional

from .base import UPLOAD_NOT_MEASURED, UPLOAD_REFUSED, median

log = logging.getLogger(__name__)

WEEKDAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

HOUR_BLOCK_LEN = 3
HOUR_BLOCK_MIN_TESTS = 3
HOUR_BLOCK_SLOWER_PCT = 15.0
WEEKDAY_MIN_TESTS = 3
WEEKDAY_SLOWER_PCT = 20.0
ASYMMETRY_RATIO = 0.10
TREND_MIN_PCT_PER_DAY = 0.5
MIN_TESTS_FOR_PATTERNS = 8


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if math.isnan(f) or math.isinf(f):
        return None
    return f


def _mean(values: List[float]) -> Optional[float]:
    return sum(values) / len(values) if values else None


def _r(v: Optional[float], nd: int = 2) -> Optional[float]:
    return round(v, nd) if v is not None else None


def _fmt(v: float) -> str:
    return f"{v:.0f}" if v >= 10 else f"{v:.1f}"


def _hour_label(h: int) -> str:
    return f"{h % 24:02d}:00"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def analyse_patterns(rows: List[Dict[str, Any]], now: float, warn_below_pct: float, tz_offset_s: int,
                     days: Optional[int] = None) -> Dict[str, Any]:
    """Summarise *rows* (speedtests table dicts) into the ``patterns`` dict."""
    clean: List[Dict[str, Any]] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        ts = _num(r.get("ts"))
        if ts is None:
            continue
        clean.append(r)
    clean.sort(key=lambda r: float(r["ts"]))

    count = len(clean)
    ok_rows_all = [r for r in clean if r.get("ok")]
    ok_count = len(ok_rows_all)
    ok_rows = [r for r in ok_rows_all if _num(r.get("download_mbps")) is not None]

    if days is None:
        if clean:
            span = float(now) - float(clean[0]["ts"])
            days = max(1, int(math.ceil(span / 86400.0))) if span > 0 else 1
        else:
            days = 7
    days = max(1, int(days))
    try:
        warn_pct = float(warn_below_pct)
    except (TypeError, ValueError):
        warn_pct = 50.0
    warn_pct = max(1.0, min(100.0, warn_pct))
    tz = int(tz_offset_s or 0)

    downs = [float(_num(r["download_mbps"])) for r in ok_rows]  # type: ignore[arg-type]
    ups = [u for u in (_num(r.get("upload_mbps")) for r in ok_rows) if u is not None]
    lats = [l for l in (_num(r.get("latency_ms")) for r in ok_rows) if l is not None]

    median_down = median(downs)
    median_up = median(ups)
    median_lat = median(lats)
    avg_down = _mean(downs)
    avg_up = _mean(ups)
    avg_lat = _mean(lats)

    min_down: Optional[Dict[str, Any]] = None
    max_down: Optional[Dict[str, Any]] = None
    if ok_rows:
        lo = min(ok_rows, key=lambda r: float(_num(r["download_mbps"])))  # type: ignore[arg-type]
        hi = max(ok_rows, key=lambda r: float(_num(r["download_mbps"])))  # type: ignore[arg-type]
        min_down = {"value": _r(_num(lo["download_mbps"])), "ts": float(lo["ts"])}
        max_down = {"value": _r(_num(hi["download_mbps"])), "ts": float(hi["ts"])}

    # -- buckets --------------------------------------------------------------
    hour_b: List[Dict[str, List[float]]] = [{"down": [], "up": [], "lat": []} for _ in range(24)]
    wday_b: List[Dict[str, List[float]]] = [{"down": [], "up": [], "lat": []} for _ in range(7)]
    for r in ok_rows:
        local = float(r["ts"]) + tz
        hour = int((local % 86400) // 3600) % 24
        wday = (int(local // 86400) + 3) % 7
        d = float(_num(r["download_mbps"]))  # type: ignore[arg-type]
        u = _num(r.get("upload_mbps"))
        l = _num(r.get("latency_ms"))
        for bucket in (hour_b[hour], wday_b[wday]):
            bucket["down"].append(d)
            if u is not None:
                bucket["up"].append(u)
            if l is not None:
                bucket["lat"].append(l)

    by_hour = [{
        "hour": h,
        "avg_down": _r(_mean(b["down"])),
        "avg_up": _r(_mean(b["up"])),
        "avg_latency": _r(_mean(b["lat"])),
        "count": len(b["down"]),
    } for h, b in enumerate(hour_b)]
    by_weekday = [{
        "weekday": w,
        "name": WEEKDAY_NAMES[w],
        "avg_down": _r(_mean(b["down"])),
        "avg_up": _r(_mean(b["up"])),
        "avg_latency": _r(_mean(b["lat"])),
        "count": len(b["down"]),
    } for w, b in enumerate(wday_b)]

    # -- slow tests -------------------------------------------------------------
    slow_tests: List[Dict[str, Any]] = []
    if median_down:
        threshold = median_down * warn_pct / 100.0
        for r in ok_rows:
            d = float(_num(r["download_mbps"]))  # type: ignore[arg-type]
            if d < threshold:
                slow_tests.append({
                    "ts": float(r["ts"]),
                    "download_mbps": _r(d),
                    "pct_of_median": round(100.0 * d / median_down, 1),
                })
        slow_tests.sort(key=lambda s: s["ts"], reverse=True)

    # -- trend (least squares, Mbps per day -> % of median per day) -------------
    trend = 0.0
    if len(downs) >= 3 and median_down:
        xs = [(float(r["ts"]) - float(ok_rows[0]["ts"])) / 86400.0 for r in ok_rows]
        mx = sum(xs) / len(xs)
        my = sum(downs) / len(downs)
        var = sum((x - mx) ** 2 for x in xs)
        if var > 0:
            slope = sum((x - mx) * (y - my) for x, y in zip(xs, downs)) / var
            trend = round(100.0 * slope / median_down, 2)
    span_days = ((float(ok_rows[-1]["ts"]) - float(ok_rows[0]["ts"])) / 86400.0) if len(ok_rows) >= 2 else 0.0

    # -- findings ---------------------------------------------------------------
    findings: List[str] = []
    day_word = _plural(days, "day")

    if count == 0:
        findings.append(f"No speed tests in the last {day_word}.")
    elif ok_count == 0:
        findings.append(f"All {count} speed tests in the last {day_word} failed.")

    # worst 3-hour block
    if median_down and ok_rows:
        worst: Optional[tuple] = None
        for start in range(24):
            hours = [(start + i) % 24 for i in range(HOUR_BLOCK_LEN)]
            vals = [v for h in hours for v in hour_b[h]["down"]]
            if len(vals) < HOUR_BLOCK_MIN_TESTS:
                continue
            m = sum(vals) / len(vals)
            if worst is None or m < worst[1]:
                worst = (start, m)
        if worst is not None:
            slower = (1.0 - worst[1] / median_down) * 100.0
            if slower >= HOUR_BLOCK_SLOWER_PCT:
                findings.append(
                    f"Downloads are ~{slower:.0f}% slower between {_hour_label(worst[0])} and "
                    f"{_hour_label(worst[0] + HOUR_BLOCK_LEN)} (avg {_fmt(worst[1])} Mbps vs a median of "
                    f"{_fmt(median_down)} Mbps)."
                )

    failed = count - ok_count
    if failed > 0:
        findings.append(f"{_plural(failed, 'test')} failed in the last {day_word}.")

    # An ok test's note (its ``error``) names what could not be trusted. A test that never tried the upload has
    # no note, so it is not counted here; one whose upload acknowledged nothing is the only trace of a dead upstream.
    notes = [str(r.get("error") or "") for r in ok_rows_all]
    # A server refusing the upload (an HTTP 4xx: a fast.com cache server that takes no uploads) is counted apart,
    # so the line finding never sends a technician after an upstream that is fine.
    unmeasured_notes = [n for n in notes
                        if n.startswith(UPLOAD_NOT_MEASURED + ":") or ("; " + UPLOAD_NOT_MEASURED + ":") in n]
    refused = sum(1 for n in unmeasured_notes if UPLOAD_REFUSED in n)
    unmeasured = len(unmeasured_notes) - refused
    if unmeasured:
        findings.append(f"The upload could not be measured in {unmeasured} of {_plural(ok_count, 'test')} in the last "
                        f"{day_word}, while the download worked.")
    if refused:
        findings.append(f"The test server refused the upload in {refused} of {_plural(ok_count, 'test')} in the last "
                        f"{day_word}: that is the server, not this line.")
    stalled = sum(1 for n in notes if " stalled: " in n)
    if stalled:
        findings.append(f"{_plural(stalled, 'test')} stalled part-way: nothing moved for several seconds.")

    # weekday effect
    if median_down and ok_rows:
        worst_day: Optional[tuple] = None
        for w, b in enumerate(wday_b):
            if len(b["down"]) < WEEKDAY_MIN_TESTS:
                continue
            m = sum(b["down"]) / len(b["down"])
            if worst_day is None or m < worst_day[1]:
                worst_day = (w, m)
        if worst_day is not None:
            slower = (1.0 - worst_day[1] / median_down) * 100.0
            if slower >= WEEKDAY_SLOWER_PCT:
                findings.append(
                    f"Downloads are ~{slower:.0f}% slower on {WEEKDAY_NAMES[worst_day[0]]}s "
                    f"(avg {_fmt(worst_day[1])} Mbps)."
                )

    # upload/download asymmetry
    if median_down and median_up is not None and median_up < median_down * ASYMMETRY_RATIO:
        findings.append(
            f"Upload (~{_fmt(median_up)} Mbps) is under {ASYMMETRY_RATIO * 100:.0f}% of download "
            f"(~{_fmt(median_down)} Mbps) - typical of an asymmetric connection."
        )

    # latency spikes
    if median_lat is not None and len(lats) >= 3:
        spike_level = max(2.0 * median_lat, median_lat + 50.0)
        spikes = [l for l in lats if l > spike_level]
        if spikes:
            findings.append(
                f"Latency spiked in {_plural(len(spikes), 'test')} of {len(lats)} "
                f"(up to {_fmt(max(spikes))} ms vs a typical {_fmt(median_lat)} ms)."
            )

    # trend
    if abs(trend) >= TREND_MIN_PCT_PER_DAY and span_days >= 2.0:
        direction = "down" if trend < 0 else "up"
        total = trend * span_days
        findings.append(
            f"Download speed is trending {direction} ~{abs(trend):.1f}% per day "
            f"(~{abs(total):.0f}% over {span_days:.0f} days)."
        )

    # slow tests
    if slow_tests and median_down:
        findings.append(
            f"{_plural(len(slow_tests), 'test')} came in below {warn_pct:.0f}% of the median download "
            f"({_fmt(median_down)} Mbps)."
        )

    if count > 0 and ok_count > 0 and ok_count < MIN_TESTS_FOR_PATTERNS and len(findings) == 0:
        findings.append(f"Not enough tests yet to detect patterns ({ok_count} so far).")
    elif ok_count >= MIN_TESTS_FOR_PATTERNS and not findings:
        findings.append("Speeds look consistent across the day and week.")

    return {
        "days": days,
        "count": count,
        "ok_count": ok_count,
        "median_down": _r(median_down),
        "median_up": _r(median_up),
        "median_latency": _r(median_lat),
        "avg_down": _r(avg_down),
        "avg_up": _r(avg_up),
        "avg_latency": _r(avg_lat),
        "min_down": min_down,
        "max_down": max_down,
        "by_hour": by_hour,
        "by_weekday": by_weekday,
        "slow_tests": slow_tests,
        "warn_below_pct": warn_pct,
        "findings": findings,
        "trend_down_pct_per_day": trend,
    }
