r"""The SIP qualifier: would calls work well on this network (SIP page, §3.28)?

A tech arrives at a site and needs an answer before anyone plugs a phone in.  This gives one, out of what TNT has
already been collecting: the ping history for this network, and the last speed test on it.

Nothing here invents a second opinion.  The E-model that scores a call is
:func:`tnt.speedtest.quality.call_quality`, the same one the Speed page uses, fed from ping history instead of a
speed test's load probe; the window statistics are :func:`tnt.reports.ping_stats`, the same ones a site report is
built from.  Two scores that disagreed because two bits of the app measured the same thing differently would be
worse than no score.

What it grades, and why it is split
------------------------------------
Two verdicts, not one, because they send the tech to different places:

* the **LAN leg** - the gateway target.  Bad here is the switch, the cabling or Wi-Fi, and it is in the building.
* the **WAN leg** - the internet targets, and the SIP host if one has been named.  Bad here with a clean LAN is the
  circuit or the provider, and it is a phone call to someone else.

One combined number hides exactly the distinction that decides who fixes it.

How many legs
--------------
A site can have twenty ping targets.  Twenty leg cards would be a list, not an answer, so each kind is capped at
:data:`MAX_LEGS_PER_KIND` - the first few in the order the tech arranged their targets in, which is the order they
put the ones they care about at the top.  A named SIP host is never capped away: it was named on purpose.  When
anything is left out the rating says so in ``note`` rather than quietly grading a subset.

The path that actually carries the calls
-----------------------------------------
The targets TNT monitors by default are the gateway and an internet host - neither of which is the customer's SIP
trunk.  So the qualifier takes an optional ``sip_host``: name the PBX, SBC or registrar and it is graded as its own
leg, and the page can offer to add it as a monitored target so the next visit has history behind it.  Without one
the rating still stands, and says plainly that it is grading the path to a general internet host rather than to the
phone system.

The three numbers
------------------
:func:`headline` is what a call on this network would actually get: a MOS, a mean round trip and a mean jitter,
taken from the **weakest graded leg** rather than summed or averaged across them.

Summing would count the same milliseconds twice - a ping to an internet host already crosses the gateway, so the
internet leg's round trip contains the LAN leg's.  Averaging would hide the bad leg behind the good one, which is
the one thing the split exists to prevent.  The weakest leg is what limits the call, and it is the leg the verdict
and the headline finding already name, so the numbers and the words agree.

Honesty
-------
A window with too little data does not get a grade - :data:`MIN_SAMPLES` is the floor, and below it the leg reports
``unknown`` with the reason, and a rating whose legs are all ungraded has no numbers either rather than a
confident-looking zero.  Every grade says what window it covers, because "the line is fine" and "the line was fine
for the eleven minutes we have looked at" are different claims.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

__all__ = ["QUALIFIER_KEYS", "LEG_KEYS", "HEADLINE_KEYS", "FINDING_KEYS", "GRADES", "LEG_KINDS",
           "FINDING_IDS", "MIN_SAMPLES", "DEFAULT_WINDOW_H", "THRESHOLDS", "MAX_LEGS_PER_KIND",
           "pick_targets", "TILE_KEYS", "TILE_TTL_S", "grade_leg", "headline", "build_qualifier",
           "leg_kind", "leg_label", "SipQualifier"]

QUALIFIER_KEYS = ("ts", "window_h", "network_id", "site", "sip_host", "verdict", "grade", "legs", "headline",
                  "findings", "speedtest_ts", "note")
LEG_KEYS = ("kind", "label", "target", "grade", "mos", "r", "call_label", "avg_ms", "jitter_ms", "loss_pct",
            "p95_ms", "samples", "window_h", "reason")
#: The three numbers a call is judged by, off the weakest graded leg (see the module docstring).
HEADLINE_KEYS = ("leg", "label", "grade", "mos", "r", "call_label", "avg_ms", "jitter_ms", "loss_pct", "samples",
                 "window_h", "reason")
FINDING_KEYS = ("id", "level", "title", "detail", "advice", "evidence")

#: Most targets of one kind that become legs.  Three is enough to tell "the internet is bad" from "that one host
#: is bad" and few enough that the answer is still readable; a named SIP host is extra and never capped away.
MAX_LEGS_PER_KIND = 3

#: Worst to best, so a verdict is the lowest grade of any leg that got one.
GRADES = ("bad", "poor", "fair", "good", "excellent", "unknown")
LEG_KINDS = ("lan", "wan", "sip")

FINDING_IDS: Tuple[str, ...] = (
    "sip.ready", "sip.lan", "sip.wan", "sip.trunk", "sip.jitter", "sip.loss", "sip.latency",
    "sip.nodata", "sip.notarget", "sip.bufferbloat",
)

#: Minute rows needed before a leg is graded at all.
MIN_SAMPLES = 30
DEFAULT_WINDOW_H = 24

#: How long a tile summary stands before the history is read again.  The home page polls status often and a
#: rating that only moves as slowly as ping history does not need recomputing every time.
TILE_TTL_S = 60.0
TILE_KEYS = ("available", "reason", "verdict", "lan", "wan", "sip", "mos", "avg_ms", "jitter_ms",
             "sip_host", "ts")

#: (grade, mean ms at most, jitter ms at most, loss % at most).  ITU-T G.114 puts a one-way mouth-to-ear budget of
#: 150 ms in the "users very satisfied" band and 400 ms at the edge of usable; a round trip is roughly twice the
#: one-way path, so the round-trip numbers here are the doubled equivalents with the codec and jitter buffer's own
#: contribution left room for.
THRESHOLDS: Tuple[Tuple[str, float, float, float], ...] = (
    ("excellent", 60.0, 10.0, 0.1),
    ("good", 120.0, 20.0, 0.5),
    ("fair", 200.0, 40.0, 1.5),
    ("poor", 300.0, 60.0, 3.0),
)


def _num(value: Any) -> Optional[float]:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def grade_leg(stats: Dict[str, Any], *, kind: str, label: str, target: Optional[str] = None,
              window_h: float = DEFAULT_WINDOW_H, min_samples: int = MIN_SAMPLES) -> Dict[str, Any]:
    """One leg graded from its window statistics (:func:`tnt.reports.ping_stats`).

    ``unknown`` with a reason rather than a grade when there is not enough behind it: a rating computed from four
    minutes of data would be read as a rating."""
    samples = int(stats.get("samples") or 0)
    avg, jitter, loss = (_num(stats.get("avg_ms")), _num(stats.get("jitter_ms")), _num(stats.get("loss_pct")))
    row = {"kind": kind, "label": label, "target": target, "grade": "unknown", "mos": None, "r": None,
           "call_label": None, "avg_ms": avg, "jitter_ms": jitter, "loss_pct": loss,
           "p95_ms": _num(stats.get("p95_ms")), "samples": samples, "window_h": window_h, "reason": None}
    if samples < min_samples:
        row["reason"] = (f"only {samples} ping(s) of history on this network - "
                         f"{min_samples} are needed before this is worth grading")
        return row
    if avg is None or loss is None:
        row["reason"] = "the history has no usable round-trip times"
        return row
    score = _call_quality(avg, jitter, loss)
    if score:
        row["mos"], row["r"], row["call_label"] = score.get("mos"), score.get("r"), score.get("label")
    row["grade"] = _grade(avg, jitter if jitter is not None else 0.0, loss)
    return row


def _grade(avg: float, jitter: float, loss: float) -> str:
    for grade, max_avg, max_jitter, max_loss in THRESHOLDS:
        if avg <= max_avg and jitter <= max_jitter and loss <= max_loss:
            return grade
    return "bad"


def _call_quality(avg: float, jitter: Optional[float], loss: float) -> Dict[str, Any]:
    """The same E-model the Speed page scores a call with, fed from ping history."""
    try:
        from .speedtest import quality
        return quality.call_quality(avg, jitter, loss) or {}
    except Exception:                       # noqa: BLE001 - a rating without a MOS is still a rating
        log.debug("the call-quality model could not be used", exc_info=True)
        return {}


def _weakest(leg: Dict[str, Any]) -> Tuple[int, float, float]:
    """Sort key for "the leg that limits the call": worst grade, then lowest MOS, then slowest.

    The grade alone is not enough.  On a healthy site every leg is excellent, and taking the first of them would
    put the gateway's 3 ms on screen as what a call gets - when the call goes out over the internet leg, whose
    round trip is the one that matters and which already contains the gateway's."""
    return (GRADES.index(leg["grade"]),
            leg["mos"] if isinstance(leg.get("mos"), (int, float)) else 5.0,
            -(leg["avg_ms"] if isinstance(leg.get("avg_ms"), (int, float)) else 0.0))


def headline(legs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """The MOS, mean round trip and mean jitter a call on this network would get: the weakest graded leg's.

    Not a sum and not an average.  A ping to an internet host already crosses the gateway, so the internet leg's
    round trip *contains* the LAN leg's and adding them would count the same milliseconds twice; averaging a good
    leg with a bad one hides the bad one, which is the whole reason the legs are split in the first place.  The
    weakest leg is what limits the call, and it is the leg the verdict and the headline finding already name.

    Nothing graded means no numbers, not zeroes: a rating with four minutes of history behind it must not show a
    confident 4.40."""
    graded = [leg for leg in legs if leg.get("grade") in GRADES and leg.get("grade") != "unknown"]
    if not graded:
        reasons = [leg.get("reason") for leg in legs if leg.get("reason")]
        return {"leg": None, "label": None, "grade": "unknown", "mos": None, "r": None, "call_label": None,
                "avg_ms": None, "jitter_ms": None, "loss_pct": None, "samples": 0, "window_h": None,
                "reason": reasons[0] if reasons else "there is no graded leg to take the numbers from"}
    worst = min(graded, key=_weakest)
    return {"leg": worst["kind"], "label": worst["label"], "grade": worst["grade"], "mos": worst["mos"],
            "r": worst["r"], "call_label": worst["call_label"], "avg_ms": worst["avg_ms"],
            "jitter_ms": worst["jitter_ms"], "loss_pct": worst["loss_pct"], "samples": worst["samples"],
            "window_h": worst["window_h"], "reason": None}


# --------------------------------------------------------------------------- findings
def _finding(ident: str, level: str, title: str, detail: Optional[str] = None, advice: Optional[str] = None,
             evidence: Any = None) -> Dict[str, Any]:
    return {"id": ident, "level": level, "title": title, "detail": detail, "advice": advice, "evidence": evidence}


_LEVELS = ("bad", "warn", "info", "good")
_GRADE_LEVEL = {"excellent": "good", "good": "good", "fair": "warn", "poor": "bad", "bad": "bad",
                "unknown": "info"}


def _leg_finding(leg: Dict[str, Any]) -> Dict[str, Any]:
    kind, label, grade = leg["kind"], leg["label"], leg["grade"]
    ident = {"lan": "sip.lan", "wan": "sip.wan", "sip": "sip.trunk"}[kind]
    if grade == "unknown":
        return _finding(ident, "info", f"{label}: not enough history to grade", leg["reason"],
                        "Leave TNT running on this network and come back to it.")
    numbers = (f"{leg['avg_ms']} ms average"
               + (f", {leg['jitter_ms']} ms jitter" if leg["jitter_ms"] is not None else "")
               + f", {leg['loss_pct']} % loss over {leg['samples']} pings")
    advice = {
        "lan": "A bad LAN leg is in the building: the switch, the cabling, or Wi-Fi between the phone and the "
               "gateway. Fix it here before looking outside.",
        "wan": "A bad WAN leg with a clean LAN is the circuit or the provider - that is a call to someone else, "
               "and these numbers are what to tell them.",
        "sip": "This is the path the calls themselves take. Bad here with a clean internet leg points at the route "
               "to the phone system rather than at the line.",
    }[kind]
    return _finding(ident, _GRADE_LEVEL[grade], f"{label}: {grade}",
                    numbers + (f" - {leg['call_label']} (MOS {leg['mos']})" if leg["mos"] else ""),
                    None if grade in ("excellent", "good") else advice,
                    {"avg_ms": leg["avg_ms"], "jitter_ms": leg["jitter_ms"], "loss_pct": leg["loss_pct"]})


def build_qualifier(legs: Sequence[Dict[str, Any]], *, window_h: float,
                    sip_host: Optional[str] = None, site: Optional[str] = None,
                    network_id: Optional[int] = None, speedtest_ts: Optional[float] = None,
                    bufferbloat: Optional[str] = None, ts: Optional[float] = None,
                    left_out: int = 0) -> Dict[str, Any]:
    """The whole rating: the legs, the three headline numbers and the findings, worst first."""
    graded = [leg for leg in legs if leg["grade"] != "unknown"]
    verdict = min((leg["grade"] for leg in graded), key=GRADES.index) if graded else "unknown"
    head = headline(legs)
    findings: List[Dict[str, Any]] = [_leg_finding(leg) for leg in legs]

    if not graded:
        findings.append(_finding(
            "sip.nodata", "info", "Not enough history for a rating yet",
            "None of the legs has enough pings on this network to be worth grading.",
            "Leave TNT running here for a while - even an hour gives the rating something to stand on."))
    else:
        worst = min(graded, key=lambda leg: GRADES.index(leg["grade"]))
        if verdict in ("excellent", "good"):
            findings.insert(0, _finding(
                "sip.ready", "good", f"This network looks {verdict} for SIP",
                f"Every leg measured over the last {_window_text(window_h)} is {verdict} or better"
                + (f" — MOS {head['mos']} at {head['avg_ms']} ms." if head["mos"] is not None else "."),
                None))
        else:
            findings.insert(0, _finding(
                "sip.ready", "bad" if verdict in ("bad", "poor") else "warn",
                f"Calls on this network would be {verdict}",
                f"The {worst['label'].lower()} is the weakest leg over the last {_window_text(window_h)}: "
                + f"{worst['avg_ms']} ms average, {worst['loss_pct']} % loss"
                + (f", {worst['jitter_ms']} ms jitter" if worst["jitter_ms"] is not None else "") + ".",
                "Start with the leg named above - the other legs are not the problem."))

    if sip_host is None:
        findings.append(_finding(
            "sip.notarget", "info", "No SIP host has been named",
            "This rating grades the path to a general internet host. The path the calls actually take - to the "
            "PBX, SBC or registrar - may be a different route entirely.",
            "Name the SIP host and TNT will monitor it like any other target, so the next rating covers the path "
            "that carries the calls."))

    if bufferbloat in ("D", "F"):
        findings.append(_finding(
            "sip.bufferbloat", "bad", f"The line buffers badly under load (grade {bufferbloat})",
            "The last speed test found latency climbing sharply while the line was busy. Calls hold up until "
            "somebody starts a download, and then they break up - which is the complaint that gets reported as "
            "'the phones are random'.",
            "This is the line's queueing, not its speed. Smart queue management on the router fixes it."))
    # The headline is the answer to the question that was asked, so it leads whatever its level - a good network
    # would otherwise bury "this looks good for SIP" under every informational note on the page.
    lead = [f for f in findings if f["id"] == "sip.ready"]
    rest = sorted((f for f in findings if f["id"] != "sip.ready"), key=lambda f: _LEVELS.index(f["level"]))
    findings = lead + rest
    return {"ts": float(ts) if ts is not None else time.time(), "window_h": window_h, "network_id": network_id,
            "site": site, "sip_host": sip_host, "verdict": verdict,
            "grade": verdict, "legs": list(legs), "headline": head, "findings": findings,
            "speedtest_ts": speedtest_ts, "note": _left_out_note(left_out)}


def _left_out_note(left_out: int) -> Optional[str]:
    """What the cap left out, said out loud.  A rating that quietly graded three of a site's twenty targets would
    read as a rating of the site."""
    if not left_out:
        return None
    return (f"{left_out} more monitored target(s) were not graded: the first {MAX_LEGS_PER_KIND} of each kind are, "
            "in the order the targets are listed on the Ping page.")


def _window_text(hours: float) -> str:
    if hours >= 48:
        return f"{int(hours // 24)} days"
    if hours >= 2:
        return f"{int(hours)} hours"
    return f"{int(hours * 60)} minutes"


# --------------------------------------------------------------------------- the engine component
class SipQualifier:
    """Reads the rating out of the database.  The measurement is everything TNT already collects; this only asks.

    The database is injected rather than reached for, so a test can hand it any history it likes."""

    def __init__(self, db: Any = None, *, clock: Any = None) -> None:
        self._db, self._clock = db, clock or time.time
        self._tile_lock = threading.Lock()
        self._tile: Optional[Dict[str, Any]] = None
        self._tile_key: Any = None
        self._tile_ts = 0.0
        self._tile_gen = 0               # bumped by invalidate(): a tile built from reads before it is not kept

    def invalidate(self) -> None:
        """Drop the cached home tile (Settings > Clear history).  The rating is read from ping history and the last
        speed test, which the clear has just removed, so the next tile is built from what is left rather than served
        from a cache up to :data:`TILE_TTL_S` old; one being built right now is answered but not kept."""
        with self._tile_lock:
            self._tile, self._tile_key, self._tile_ts = None, None, 0.0
            self._tile_gen += 1

    def rating(self, *, window_h: float = DEFAULT_WINDOW_H, network_id: Optional[int] = None,
               sip_host: Optional[str] = None, site: Optional[str] = None,
               gateway: Optional[str] = None) -> Dict[str, Any]:
        """The rating for *network_id* over the last *window_h* hours."""
        if self._db is None:
            raise RuntimeError("the qualifier has no database to read")
        from . import reports
        now = float(self._clock())
        start = now - max(0.25, float(window_h)) * 3600.0
        chosen, left_out = pick_targets(self._targets(), sip_host, gateway)
        legs: List[Dict[str, Any]] = []
        for kind, target in chosen:
            rows = self._minute_rows(target, start, now, network_id)
            legs.append(grade_leg(reports.ping_stats(rows), kind=kind, label=leg_label(kind, target),
                                  target=str(target.get("host") or ""), window_h=window_h))
        legs.sort(key=lambda leg: LEG_KINDS.index(leg["kind"]))
        # the speed test is here only for the bufferbloat warning now: a line that buffers badly breaks calls
        # however good the idle numbers are, and that is measured on the Speed page, not from ping history
        speed = self._last_speedtest() or {}
        bloat = (speed.get("quality") or {}).get("bufferbloat") or {}
        return build_qualifier(legs, window_h=window_h, sip_host=sip_host, site=site,
                               network_id=network_id, speedtest_ts=speed.get("ts"),
                               bufferbloat=bloat.get("grade"), ts=now, left_out=left_out)

    def tile(self, *, network_id: Optional[int] = None, sip_host: Optional[str] = None,
             gateway: Optional[str] = None, window_h: float = DEFAULT_WINDOW_H,
             ttl_s: float = TILE_TTL_S) -> Dict[str, Any]:
        """The small dict the home tile shows: the verdict, each leg's grade and the three headline numbers.

        Cached for *ttl_s*, because the home page polls status far more often than ping history moves.  The cache
        is keyed on what would change the answer, so naming a SIP host or moving to another network is reflected
        at once rather than up to a minute later."""
        key = (network_id, (sip_host or "").strip().lower(), gateway, window_h)
        now = float(self._clock())
        with self._tile_lock:
            if self._tile is not None and self._tile_key == key and now - self._tile_ts < ttl_s:
                return dict(self._tile)
            generation = self._tile_gen
        try:
            rating = self.rating(window_h=window_h, network_id=network_id, sip_host=sip_host, gateway=gateway)
        except Exception as exc:            # noqa: BLE001 - the tile is never worth an error on the home page
            log.debug("the SIP tile could not be built", exc_info=True)
            return {"available": False, "reason": str(exc) or "the rating could not be read", "verdict": "unknown",
                    "lan": None, "wan": None, "sip": None, "mos": None, "avg_ms": None, "jitter_ms": None,
                    "sip_host": sip_host, "ts": now}
        grades = {leg["kind"]: leg["grade"] for leg in rating["legs"]}
        head = rating["headline"]
        row = {"available": True, "reason": None, "verdict": rating["verdict"], "lan": grades.get("lan"),
               "wan": grades.get("wan"), "sip": grades.get("sip"), "mos": head["mos"], "avg_ms": head["avg_ms"],
               "jitter_ms": head["jitter_ms"], "sip_host": sip_host, "ts": rating["ts"]}
        with self._tile_lock:
            if self._tile_gen == generation:     # not invalidated while the rating was being read
                self._tile, self._tile_key, self._tile_ts = dict(row), key, now
        return row

    # -- the database, every read survivable: a rating missing one leg beats no rating -------------
    def _targets(self) -> List[Dict[str, Any]]:
        try:
            return [dict(row) for row in (self._db.list_targets(enabled_only=True) or [])]
        except Exception:                   # noqa: BLE001
            log.debug("the targets could not be read", exc_info=True)
            return []

    def _minute_rows(self, target: Dict[str, Any], start: float, end: float,
                     network_id: Optional[int]) -> List[tuple]:
        try:
            return list(self._db.ping_minute_rows(int(target.get("id")), start, end, network_id) or [])
        except Exception:                   # noqa: BLE001
            log.debug("the ping history of target %s could not be read", target.get("id"), exc_info=True)
            return []

    def _last_speedtest(self) -> Optional[Dict[str, Any]]:
        """The last good speed test, with the quality block restored out of ``raw_json``.

        The row-to-result conversion is the speed scheduler's own, so the bufferbloat warning comes from exactly
        the record the Speed page shows.  That warning is all the speed test is used for here: the three headline
        numbers come from ping history."""
        try:
            row = self._db.last_speedtest(ok_only=True)
        except Exception:                   # noqa: BLE001
            log.debug("the last speed test could not be read", exc_info=True)
            return None
        if not row:
            return None
        try:
            from .speedtest.scheduler import SpeedScheduler
            return SpeedScheduler._row_to_result(dict(row))     # noqa: SLF001 - one definition of that conversion
        except Exception:                   # noqa: BLE001
            log.debug("the speed test row could not be read", exc_info=True)
            return dict(row)


def leg_kind(target: Dict[str, Any], sip_host: Optional[str] = None,
             gateway: Optional[str] = None) -> Optional[str]:
    """Which leg a monitored target belongs to, or ``None`` if it belongs to none.

    A named SIP host wins over everything: if the tech is monitoring their PBX it is the trunk leg even though it
    is an ordinary internet target in every other part of the app.  Otherwise the gateway and any other private
    address are inside the building (the LAN leg), and anything routable is outside it."""
    from . import reports
    host = str(target.get("host") or "").strip()
    if sip_host and host.lower() == str(sip_host).strip().lower():
        return "sip"
    role = reports.target_role(host, target.get("ip"), target.get("kind"), gateway)
    if role in ("gateway", "local"):
        return "lan"
    return "wan" if role == "internet" else None


def pick_targets(targets: Sequence[Dict[str, Any]], sip_host: Optional[str] = None,
                 gateway: Optional[str] = None,
                 limit: int = MAX_LEGS_PER_KIND) -> Tuple[List[Tuple[str, Dict[str, Any]]], int]:
    """The targets that become legs, as ``(kind, target)``, and how many were left out.

    Taken in the order the targets arrive - ``Database.list_targets`` orders them by ``sort_order`` then ``id``,
    which is the order the tech arranged them in on the Ping page, so "the first few" means the ones they put at
    the top.  A named SIP host is taken whatever the cap: it was named on purpose, and dropping the one leg the
    user asked for would be the one unforgivable thing this cap could do."""
    chosen: List[Tuple[str, Dict[str, Any]]] = []
    counts: Dict[str, int] = {}
    left_out = 0
    for target in targets or []:
        kind = leg_kind(target, sip_host, gateway)
        if kind is None:
            continue
        if kind == "sip":
            chosen.append((kind, target))
            continue
        if counts.get(kind, 0) >= max(1, int(limit)):
            left_out += 1
            continue
        counts[kind] = counts.get(kind, 0) + 1
        chosen.append((kind, target))
    return chosen, left_out


def leg_label(kind: str, target: Dict[str, Any]) -> str:
    from . import reports
    name = reports.target_name(target.get("name") or target.get("label"), target.get("host")) or "?"
    return {"lan": f"The LAN leg ({name})", "wan": f"The internet leg ({name})",
            "sip": f"The path to {name}"}[kind]
