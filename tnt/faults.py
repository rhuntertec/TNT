"""What is wrong with this network, found without asking the network anything.

The Faults tile. Every other tool in TNT answers a question the tech thought to ask; this one
answers the question they have before they know to ask it - *what is broken here that nobody
mentioned?* - and it answers it by the time they have finished plugging in, because it is watching
from the moment the service starts.

Everything here is **passive and needs no administrator**: three sources the machine already has.

* **The adapter's own error and discard counters** (``GetIfTable2``, read through
  :func:`tnt.throughput.read_counters`).  Errors and discards are kept apart on purpose, because
  they send a tech to different places: an *error* is a frame that arrived or left damaged -
  cabling, a connector, a duplex mismatch - and a *discard* is a frame that was perfectly good and
  was dropped anyway.  Only the discards on the way **out** are judged: a frame this PC queued and
  could not send means the send queue was full, which is congestion.  Windows also counts an
  arriving frame as discarded when nothing on this PC speaks its protocol or a filter driver drops
  it, which a healthy desktop does several times a second on a link that is never full, so the
  inbound figure is shown as context and never graded (see :data:`DISCARD_WARN_PCT`).  Rolling
  errors and discards into one "problem" number would be the least useful thing this module could do.
* **The adapter's live address configuration** (:func:`tnt.netinfo.adapter_warnings`), which already
  knows a self-assigned 169.254 address, a duplicate address, a gateway outside its own subnet, two
  default gateways and an adapter with no DNS servers.  Those were only ever visible on that
  adapter's own card, which is the last place anyone looks.  The informational ones (two default
  gateways) stay there: a docked laptop with Wi-Fi left on is not a fault.
* **The neighbour (ARP) table over time** (:func:`tnt.arp.neighbour_rows_native`).  One address
  answered by two different MACs on the same interface is the classic duplicate IP, and it is
  invisible to everything else in TNT.

Judged on the last few minutes, with the whole watch as context
---------------------------------------------------------------
The counters Windows keeps are cumulative since the adapter came up, which on a desktop that has
been on for a month is a number about last month.  So every level is decided by what the counters
did over the **last** :data:`RATE_WINDOW_S` of readings: a cable that goes bad after a clean day is
graded on its own rate at once, instead of being diluted by millions of clean frames, and a fault
that was fixed clears one window after its last error, so a tech who re-seats a cable can see it
work.  A share is a share of every frame the adapter carried - the damaged and the dropped ones as
well as the good ones, because Windows counts only the good ones as packets - and a window with too
few frames in it (:data:`MIN_PACKETS`) makes no ratio.  A quiet window that nonetheless held damaged
frames is judged on the whole watch instead, which is the only span a link that quiet has enough
frames in; a quiet window without any is not judged at all.  What has happened **since TNT started
watching** is kept beside it and quoted in every finding as clearly labelled context ("142 discards
in the eleven minutes I have been looking" is a fact about the network the tech is standing in), and
the lifetime figure next to that, because a tech who wants it should not have to open Task Manager.

A reading that fails says nothing about the adapters, so it changes nothing: the readings already
kept stay, a fault already found stays found until its errors are older than the window (a finding
about readings that are not the latest says how long ago they were), and the tile is told what could
not be read (the tile's ``reason``) rather than being allowed to call the network clean.  Only a
reading that worked and lists other adapters can say that one went away, and even then the adapter
stays - on the page, marked down, and in the findings - until its window has nothing left in it: a
link that drops and comes straight back, which is what a bad cable does, carries on where it left
off, and a fault on it does not blink green each time it drops.

The watch keeps its own time, from the wall clock (which, unlike a monotonic one, counts the hours a
laptop spends asleep in the bag), except that it never runs backwards: Windows setting the clock back
an hour would otherwise leave the watch "starting" for that hour and blind to what it had seen.

A fault is only raised once there is enough watched time to mean anything (:data:`MIN_WATCH_S`, per
adapter as well as overall); before that the tile says it is still watching rather than that all is
well.

What is deliberately *not* here
-------------------------------
Rogue DHCP servers, spanning-tree churn, broadcast storms and 802.1X failures all need frames off
the wire, which means the ETW capture session - admin rights, and a session :mod:`tnt.capture`
already owns.  Those belong behind a "listen for a minute" button of the kind Pro AV and the switch
port check already use, not in a watcher that is meant to cost nothing and run always.  The
detectors here are written as pure functions over plain data so that adding them later is additive.

Shapes
------
* :meth:`FaultWatcher.view` -> ``GET /api/faults``: the findings, the per-adapter counters behind
  them, and what the ARP watch has seen.
* :meth:`FaultWatcher.tile` -> ``status.faults``: the worst level, how many of each, and one line.
* A ``faults.state`` event is published when the **level changes**, not every tick - a tile that is
  green does not need to say so once a second.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, Iterator, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

__all__ = ["FINDING_LEVELS", "FINDING_IDS", "FINDING_KEYS", "NIC_KEYS", "VIEW_KEYS", "TILE_KEYS",
           "TICK_S", "MIN_WATCH_S", "RATE_WINDOW_S", "FaultWatcher", "error_findings", "address_findings",
           "arp_findings", "worst_level", "ArpWatch"]

#: Worst first, the same order and meaning :mod:`tnt.proav` and :mod:`tnt.sipqual` use.
FINDING_LEVELS: Tuple[str, ...] = ("bad", "warn", "info", "good")
_LEVEL_ORDER = {level: i for i, level in enumerate(FINDING_LEVELS)}

FINDING_IDS: Tuple[str, ...] = (
    "fault.errors", "fault.discards", "fault.address", "fault.arp", "fault.gateway",
    "fault.clean", "fault.watching", "fault.unavailable",
)
FINDING_KEYS: Tuple[str, ...] = ("id", "level", "title", "detail", "advice", "evidence")
NIC_KEYS: Tuple[str, ...] = (
    "name", "description", "index", "link_bps", "watched_s",
    "up", "last_read_s",             # on the last good reading; how long since its counters were read
    "rx_errors", "tx_errors", "rx_discards", "tx_discards",              # cumulative, for context
    "new_rx_errors", "new_tx_errors", "new_rx_discards", "new_tx_discards",   # since we started
    "new_rx_packets", "new_tx_packets", "error_pct", "discard_pct",
    "window_s",                                                              # what the levels judge:
    "recent_rx_errors", "recent_tx_errors", "recent_rx_discards", "recent_tx_discards",   # the last
    "recent_rx_packets", "recent_tx_packets",                                # window_s of readings
)
VIEW_KEYS: Tuple[str, ...] = ("ts", "watching_since", "watched_s", "level", "findings", "nics",
                              "arp", "note")
TILE_KEYS: Tuple[str, ...] = ("available", "reason", "level", "bad", "warn", "headline",
                              "watched_s", "clean_s", "ts")

#: One look every five seconds.  These are counters, not events: a faster tick would cost more and
#: say nothing extra, and a slower one would make the tile feel stale after a cable is re-seated.
TICK_S = 5.0
#: No fault is raised from less watched time than this.  A single error in the first two seconds is
#: noise, and a tile that cried wolf on arrival would be switched off by the end of the week.
MIN_WATCH_S = 60.0
#: Errors and discards are judged on what the counters did over this much of the most recent
#: readings, not over the whole watch: long enough that one burst is not the whole story (sixty
#: readings), short enough that a fault is graded on its own rate the moment it starts and a fixed
#: one clears within five minutes.  The same order of time as the ARP window, for the same reason.
RATE_WINDOW_S = 300.0
#: A window in which an adapter carried fewer frames than this is too quiet to make a ratio of: one
#: error out of thirty frames is a meaningless 3 %.
MIN_PACKETS = 500
#: What the error share is a share of: every frame the adapter received or was asked to send.
#: ``MIB_IF_ROW2`` counts only the frames received or transmitted *without errors* as packets
#: (``InUcastPkts``, ``OutUcastPkts``), and a discarded frame was not delivered or not sent either,
#: so the damaged and the dropped ones are added back.  Counting packets alone, a link that was three
#: parts errors looked quiet and was never judged.
_ALL_FRAMES = ("rx_packets", "rx_errors", "rx_discards", "tx_packets", "tx_errors", "tx_discards")
#: What the outbound discard share is a share of: every frame this PC queued to send.
_SENT_FRAMES = ("tx_packets", "tx_errors", "tx_discards")
#: An adapter whose counters were last read longer ago than this (its link went down, or the reads
#: are failing) has its findings worded from that reading - "in the 3 minutes up to 2 minutes ago" -
#: rather than as "the last 5 minutes".  Two ticks, so one slow read does not change a sentence.
STALE_S = 2 * TICK_S
#: Damaged frames, as a share of frames received and sent.  Anything at all is worth saying on a
#: switched link; these are where it stops being "worth mentioning" and starts being "go and fix it".
ERROR_WARN_PCT = 0.01
ERROR_BAD_PCT = 0.5
#: Frames this PC queued to send and then discarded, as a share of the frames it sent: the send
#: queue was full (or the link went while they waited).  A burst is what a queue is for, so the bar
#: is higher than for errors.
#:
#: Only **outbound** discards are graded, and that split is measured, not assumed.  Windows counts an
#: *arriving* frame as discarded when no protocol on this PC is bound to its EtherType, when a filter
#: driver (a firewall, a VPN client) drops it, or when the NIC sits under a Hyper-V switch and sees
#: frames meant for other hosts - as well as when a receive buffer ran out.  The counter cannot tell
#: those apart.  The development desktop this was written on (linked at 1 Gb/s, healthy, never
#: saturated) was read every 5 s, the way this module reads it, for 25 minutes (2026-09-20: 49.8 M
#: frames in, 8.1 M out, 128,821 inbound discards) and again for 20 minutes (2026-09-21: 42.6 M in,
#: 7.0 M out, 86,325 inbound discards).  Across both: 39 to 123 inbound discards a second in every
#: five-minute window, 0.11-0.36 % of arrivals, in bursts of up to 1,794 per reading - and **no**
#: outbound discard and no error at all; an earlier 20 s look at a quieter time counted about 6.5 a
#: second.  Replayed through this module, as recorded and with the frame counts cut to 1 % and to
#: 0.02 % (the same discards on an almost idle link), both recordings stay clean throughout.
#: Grading the inbound share instead would have sat at 72 % of the warn bar on this busy link,
#: crossed it with a tenth of the traffic (3.6 %), and read "bad" on a quiet link, where those same
#: discards outnumber the frames - on a network where nothing is wrong.  So inbound discards are
#: shown on the page as context and never raise a finding, and these thresholds apply to the
#: outbound share alone.  The cost: a receive buffer that really overflows is not reported here; that
#: mostly happens under a load the Realtime throughput card already shows.
DISCARD_WARN_PCT = 0.5
DISCARD_BAD_PCT = 5.0
#: How long two different MACs answering for one address stay interesting.  A lease changing hands
#: hours apart is not a conflict; the same address flipping inside two minutes is.
ARP_WINDOW_S = 120.0
#: Most addresses the ARP watch remembers, so a /16 sweep cannot grow it without bound.
ARP_MAX_TRACKED = 4096
STOP_JOIN_S = 2.0


def _finding(ident: str, level: str, title: str, detail: Optional[str] = None,
             advice: Optional[str] = None, evidence: Any = None) -> Dict[str, Any]:
    return {"id": ident, "level": level, "title": title, "detail": detail, "advice": advice,
            "evidence": evidence}


def worst_level(findings: Sequence[Dict[str, Any]]) -> str:
    """The worst level in *findings*; ``"good"`` for an empty list."""
    worst = "good"
    for f in findings or []:
        level = str((f or {}).get("level") or "good")
        if _LEVEL_ORDER.get(level, 99) < _LEVEL_ORDER.get(worst, 99):
            worst = level
    return worst


def _plural(n: int, word: str, many: Optional[str] = None) -> str:
    return f"{n:,} {word if n == 1 else (many or word + 's')}"


def _duration(seconds: float) -> str:
    """"3 minutes", "1 h 20 min" - how long we have been watching, in words a sentence can use."""
    s = max(0, int(seconds))
    if s < 90:
        return _plural(s, "second")
    minutes = s // 60
    if minutes < 90:
        return _plural(minutes, "minute")
    return f"{minutes // 60} h {minutes % 60:02d} min"


def _and(items: Any) -> str:
    """"a", "a and b", "a, b, and c"."""
    items = list(items)
    if len(items) < 3:
        return " and ".join(items)
    return ", ".join(items[:-1]) + ", and " + items[-1]


# =========================================================================================
# the detectors - pure functions over plain rows, so every threshold is testable on its own
# =========================================================================================
def _pct(part: int, whole: int) -> Optional[float]:
    return None if whole <= 0 else (100.0 * part) / whole


def _recent(nic: Dict[str, Any], field: str) -> int:
    """What *field* ("rx_errors", "tx_packets", ...) did over the adapter's recent window.  A row
    built without a window (the watch is younger than one, or a caller built the row by hand) has
    only the since-start figure, and then the two are the same thing."""
    value = nic.get("recent_" + field)
    return int((nic.get("new_" + field) if value is None else value) or 0)


def _since(nic: Dict[str, Any], field: str) -> int:
    """What *field* did since TNT started watching this adapter."""
    return int(nic.get("new_" + field) or 0)


def _frames(nic: Dict[str, Any], fields: Sequence[str], value: Callable[[Dict[str, Any], str], int]) -> int:
    """The frames *fields* add up to (:data:`_ALL_FRAMES`, :data:`_SENT_FRAMES`), recent or since-start."""
    return sum(value(nic, f) for f in fields)


def _clean_detail(rows: Sequence[Dict[str, Any]], watched: float, blind: "frozenset[str]") -> str:
    """What a result with no finding can truthfully claim, from what was read.

    Each claim needs its source to have been read on the last look (*blind* names the ones that
    were not).  The counter claims are about the window the levels judge, so they are worded from
    it: a count the window held but could not judge - a quiet link, an adapter that came up a
    moment ago, outbound discards under :data:`DISCARD_WARN_PCT` - is named, not denied, and what
    happened earlier in the watch is said to have happened, because "no frame errors" in a watch
    whose first hour had thousands would be false."""
    claims: List[str] = []
    if "counters" not in blind:
        def errors(r: Dict[str, Any]) -> int:
            return _recent(r, "rx_errors") + _recent(r, "tx_errors")

        quiet = sum(errors(r) for r in rows if float(r.get("watched_s") or 0.0) >= MIN_WATCH_S)
        young = sum(errors(r) for r in rows if float(r.get("watched_s") or 0.0) < MIN_WATCH_S)
        drops = sum(_recent(r, "tx_discards") for r in rows)
        if not quiet and not young:
            claims.append("no frame errors")
        if quiet:
            claims.append(f"{_plural(quiet, 'frame error')} on too little traffic to judge yet")
        if young:
            claims.append(f"{_plural(young, 'frame error')} on an adapter that came up under "
                          f"{_duration(MIN_WATCH_S)} ago")
        claims.append("no frames dropped on the way out" if not drops
                      else f"{_plural(drops, 'frame')} dropped on the way out, too few to call congestion")
    if "adapters" not in blind:
        claims.append("every adapter addressed properly")
    if "arp" not in blind:
        claims.append("no address answered by two devices")
    if not claims:
        return ""
    span = (f"the {_duration(watched)} TNT has been watching" if watched - RATE_WINDOW_S < TICK_S
            else f"the last {_duration(RATE_WINDOW_S)}")
    text = f"In {span}: {_and(claims)}."
    if "counters" not in blind:
        earlier = []
        errors = sum(int(r.get("new_rx_errors") or 0) + int(r.get("new_tx_errors") or 0)
                     - _recent(r, "rx_errors") - _recent(r, "tx_errors") for r in rows)
        drops = sum(int(r.get("new_tx_discards") or 0) - _recent(r, "tx_discards") for r in rows)
        if errors > 0:
            earlier.append(_plural(errors, "frame error"))
        if drops > 0:
            earlier.append(f"{_plural(drops, 'frame')} dropped on the way out")
        if earlier:
            text += (f" Earlier in the {_duration(watched)} TNT has been watching there were "
                     f"{' and '.join(earlier)}; the table below has them by adapter.")
    return text


def _when(nic: Dict[str, Any]) -> Tuple[str, str]:
    """(the span the level was judged on, in words; the start of a since-start sentence, or "").

    "in the last 5 minutes" plus what the whole watch saw; while the watch is not yet longer than
    the window, "in the 3 minutes since TNT started watching" and nothing else to add; and for an
    adapter whose latest reading is not recent (its link went down, or the reads are failing),
    "in the 3 minutes up to 2 minutes ago, when its link was last up" - its window ends at that
    reading, and calling it "the last 5 minutes" would stretch its errors to now."""
    watched = float(nic.get("watched_s") or 0.0)
    window = nic.get("window_s")
    window = watched if window is None else float(window)
    age = max(0.0, float(nic.get("last_read_s") or 0.0))
    # the window reaches back to the start of the watch: then the watch has nothing more to add
    since = "" if watched - age - window < TICK_S else f" Since TNT started watching {_duration(watched)} ago: "
    if age > STALE_S:
        last = "its link was last up" if nic.get("up") is False else "its counters were last read"
        return f"in the {_duration(round(window))} up to {_duration(round(age))} ago, when {last}", since
    if not since:
        return f"in the {_duration(watched)} since TNT started watching", ""
    # from the start of the window to now: a reading a few seconds old is still "the last 5 minutes"
    return f"in the last {_duration(round(window + age))}", since


def error_findings(nics: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Damaged frames over the recent window: cabling, a connector, or a duplex mismatch.

    Receive and transmit are reported together but named separately in the detail, because they
    point at different ends of the same cable: frames arriving damaged is usually the run or the
    far end, frames failing to leave is usually this NIC or its driver.
    """
    rows = []
    for nic in nics:
        rx, tx = _recent(nic, "rx_errors"), _recent(nic, "tx_errors")
        if rx + tx <= 0:
            continue                      # nothing damaged in the window: nothing to judge
        frames, whole = _frames(nic, _ALL_FRAMES, _recent), False
        if frames < MIN_PACKETS:
            # Too quiet a window to make a ratio of, yet it held damaged frames.  On a link that
            # quiet - a bench laptop on a bad lead to one device - the whole watch is the only span
            # with enough frames in it, so that is what is judged.  Dropping the window instead left
            # a link that was three parts errors "clean" for as long as anyone watched.
            rx, tx, whole = _since(nic, "rx_errors"), _since(nic, "tx_errors"), True
            frames = _frames(nic, _ALL_FRAMES, _since)
            if frames < MIN_PACKETS:
                continue                  # not even the whole watch has enough to say anything
        pct = _pct(rx + tx, frames) or 0.0
        level = "bad" if pct >= ERROR_BAD_PCT else "warn" if pct >= ERROR_WARN_PCT else "info"
        rows.append({"pct": pct, "level": level, "nic": nic, "rx": rx, "tx": tx, "frames": frames,
                     "whole": whole})
    if not rows:
        return []
    rows.sort(key=lambda r: -r["pct"])
    lead = rows[0]
    nic = lead["nic"]
    name = nic.get("name") or "an adapter"
    parts = []
    if lead["rx"]:
        parts.append(_plural(lead["rx"], "arriving damaged", "arriving damaged"))
    if lead["tx"]:
        parts.append(_plural(lead["tx"], "failing to send", "failing to send"))
    if lead["whole"]:
        span = f"in the {_duration(float(nic.get('watched_s') or 0.0))} since TNT started watching"
        since = f" The last {_duration(RATE_WINDOW_S)} alone carried too few frames to judge."
    else:
        span, since = _when(nic)
        if since:
            total = _since(nic, "rx_errors") + _since(nic, "tx_errors")
            since += f"{_plural(total, 'error')} in {_plural(_frames(nic, _ALL_FRAMES, _since), 'frame')}."
    more = f" (and {len(rows) - 1} other adapter{'' if len(rows) == 2 else 's'})" if len(rows) > 1 else ""
    return [_finding(
        "fault.errors", lead["level"], f"{name} is seeing frame errors{more}",
        f"{' and '.join(parts)} out of {_plural(lead['frames'], 'frame')} {span} - {lead['pct']:.3g}% of "
        f"them.{since} These are frames the adapter received or sent damaged, not frames dropped "
        "because the link was busy.",
        "On a switched link this should be flat zero. Re-seat both ends of the cable and try a known "
        "good patch lead first; if it stays, suspect the run itself, the socket, or a duplex "
        "mismatch with the switch port (check the port is not forced to half duplex). This clears "
        f"on its own {_duration(RATE_WINDOW_S)} after the last error, so you can watch a fix work.",
        # each adapter with the level its own share earned, so the page can tint its row by it
        [{"name": r["nic"].get("name"), "rx_errors": r["rx"], "tx_errors": r["tx"],
          "pct": round(r["pct"], 4), "level": r["level"]} for r in rows])]


def discard_findings(nics: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Good frames this PC queued to send and then dropped: its send queue was full.

    Only the outbound side is judged (see :data:`DISCARD_WARN_PCT` for the measurement behind that):
    an inbound discard is as often a frame nothing on this PC has a use for as a buffer that ran out.
    A quiet window is never judged here, unlike an error: a link with next to nothing to send is not
    a congested one.
    """
    rows = []
    for nic in nics:
        seen = _recent(nic, "tx_discards")
        queued = _frames(nic, _SENT_FRAMES, _recent)
        if seen <= 0 or queued < MIN_PACKETS:
            continue
        pct = _pct(seen, queued) or 0.0
        if pct < DISCARD_WARN_PCT:
            continue                      # a few discards on a busy link is what a queue is for
        rows.append((pct, "bad" if pct >= DISCARD_BAD_PCT else "warn", nic, seen, queued))
    if not rows:
        return []
    rows.sort(key=lambda r: -r[0])
    pct, level, nic, seen, queued = rows[0]
    name = nic.get("name") or "an adapter"
    span, since = _when(nic)
    if since:
        since += (f"{_plural(_since(nic, 'tx_discards'), 'frame')} discarded of "
                  f"{_plural(_frames(nic, _SENT_FRAMES, _since), 'frame')} queued.")
    return [_finding(
        "fault.discards", level, f"{name} is dropping frames it could not send",
        f"{seen:,} of the {queued:,} frames this PC queued to send {span} were discarded before they "
        f"left - {pct:.3g}%.{since} Nothing here is damaged: the adapter's send queue was full, or "
        "the link went down while they waited in it.",
        "This is congestion on the way out, not a fault in the cable. Check what is saturating the "
        "link on the Realtime throughput card, and whether this adapter has negotiated the speed you "
        "expect. Frames discarded on the way in are left out on purpose: Windows also counts a frame "
        "that way when nothing on this PC speaks its protocol, which a healthy network does all day.",
        [{"name": r[2].get("name"), "tx_discards": r[3], "tx_packets": _recent(r[2], "tx_packets"),
          "pct": round(r[0], 4), "level": r[1]} for r in rows])]


#: Keys are ``tnt.netinfo`` codes; a test asserts they all still exist and that every code netinfo
#: emits is here, because an unknown code would quietly be dropped and a duplicate address would stop
#: being a fault.  "info" codes are notes for the adapter card, never a finding: two default
#: gateways is how every docked laptop with Wi-Fi left on looks, and a tile that can never be green
#: says nothing.  ``apipa_ipv6`` is a self-assigned IPv4 address beside working IPv6: worth a look
#: (IPv4-only devices on that network have nothing), but the adapter plainly has a usable address.
_ADDRESS_LEVEL = {
    "duplicate_address": "bad",
    "apipa": "bad",
    "apipa_ipv6": "warn",
    "gateway_outside_subnet": "warn",
    "multiple_default_gateways": "info",
    "no_dns": "warn",
}
#: The headline when this code leads; anything else gets the level's own.
_ADDRESS_TITLE = {
    "duplicate_address": "Another device is using an adapter's address",
    # not "no usable address": a 169.254 address works on its own link, which is exactly how a
    # Dante or AV network without a DHCP server is meant to run
    "apipa": "An adapter has only a self-assigned address",
}
_ADDRESS_ADVICE = (
    "These come from the live configuration of the adapters, not from a scan. Network info shows "
    "each one on its own adapter card, with the addresses behind it.")
_APIPA_ADVICE = (
    " A self-assigned 169.254 address reaches only devices on the same link that gave themselves "
    "one too: on a Dante or AV network with no DHCP server that is how it is meant to work, and "
    "anywhere else it means no DHCP server answered on that link.")


def address_findings(adapters: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The adapter warnings :mod:`tnt.netinfo` already works out, gathered where they get read.

    They were only ever shown on the adapter's own card on Network info, which is several scrolls
    down a page nobody opens when things are working.  The informational ones stay on the card.
    """
    hits: List[Tuple[str, str, str, str]] = []      # (level, adapter name, message, code)
    for a in adapters or []:
        if str(a.get("status") or "") != "up":
            continue                               # a down adapter's configuration is not a fault
        name = str(a.get("name") or "an adapter")
        for warning in a.get("warnings") or []:
            code = str((warning or {}).get("code") or "")
            message = str((warning or {}).get("message") or "").strip()
            level = _ADDRESS_LEVEL.get(code, "info")
            if not message or level == "info":
                continue                           # a note for the adapter card, not a fault
            hits.append((level, name, message, code))
    if not hits:
        return []
    hits.sort(key=lambda h: _LEVEL_ORDER.get(h[0], 99))
    level, code = hits[0][0], hits[0][3]
    title = _ADDRESS_TITLE.get(code) or ("An adapter has a problem with its address" if level == "bad"
                                         else "An adapter's address configuration needs a look")
    advice = _ADDRESS_ADVICE + (_APIPA_ADVICE if any(h[3] == "apipa" for h in hits) else "")
    return [_finding(
        "fault.address", level, title,
        "; ".join(f"{name}: {message}" for _l, name, message, _c in hits[:4])
        + (f" (and {len(hits) - 4} more)" if len(hits) > 4 else ""),
        advice,
        [{"adapter": name, "level": lvl, "message": message} for lvl, name, message, _c in hits])]


def arp_findings(conflicts: Sequence[Dict[str, Any]], gateway: Optional[str] = None) -> List[Dict[str, Any]]:
    """One address answered by more than one MAC.

    Two devices configured with the same address is the usual cause, and it is miserable to find by
    hand: whichever one answered last wins, so the symptom is a device that works intermittently for
    no visible reason.  The gateway is called out separately - a gateway that changes MAC is either
    a router failover, which is fine, or something answering for a router, which is not, and this
    module does not pretend to know which.
    """
    if not conflicts:
        return []
    rows = sorted(conflicts, key=lambda c: (c.get("ip") != gateway, str(c.get("ip"))))
    first = rows[0]
    is_gateway = gateway is not None and first.get("ip") == gateway
    macs = ", ".join(str(m) for m in (first.get("macs") or [])[:4])
    where = f" on {first['adapter']}" if first.get("adapter") else ""
    more = f" (and {len(rows) - 1} other address{'' if len(rows) == 2 else 'es'})" if len(rows) > 1 else ""
    if is_gateway:
        return [_finding(
            "fault.gateway", "bad", f"The default gateway {first.get('ip')} has answered from two MAC addresses",
            f"Both {macs} answered for {first.get('ip')}{where} within {_duration(ARP_WINDOW_S)}{more}.",
            "A router pair failing over does this legitimately, and so does something answering for "
            "the router that should not be. If the site has no redundant gateway, find the second "
            "device: the MAC's first three bytes name its maker on the Discovery page.",
            list(rows))]
    return [_finding(
        "fault.arp", "bad", f"Two devices are answering for {first.get('ip')}{more}",
        f"{macs} both answered for {first.get('ip')}{where} within {_duration(ARP_WINDOW_S)}. That "
        "address is configured on more than one device, so which one you reach depends on which "
        "answered last.",
        "Find the newer device and change its address, or put it back on DHCP. Whichever device is "
        "not meant to have it will be the one that appeared most recently on the Discovery page.",
        list(rows))]


# =========================================================================================
# the ARP watch
# =========================================================================================
#: Neighbour states that mean the device answered recently (or was configured by hand).  A Stale,
#: Delay or Probe row is the cache remembering an old answer while it waits to ask again.
_FRESH_STATES = frozenset({"reachable", "permanent"})


def _arp_rows(table: Any) -> Iterator[Tuple[Any, str, str, Optional[str]]]:
    """(key, ip, MAC, state) for each row of one reading.

    A reading is either the rows of :func:`tnt.arp.neighbour_rows_native` - ``(ip, interface index,
    MAC, state name)``, keyed by ``(interface index, ip)`` because the same address on two adapters is
    two networks (a bench router and the office one both at the same default address), not a
    duplicate - or a plain ``{ip: mac}`` with no interface and no state, keyed by the address."""
    if isinstance(table, dict):
        for ip, mac in table.items():
            yield str(ip or ""), str(ip or ""), str(mac or ""), None
        return
    for row in table or ():
        try:
            ip, index, mac, state = row
            yield (int(index), str(ip or "")), str(ip or ""), str(mac or ""), str(state or "")
        except (TypeError, ValueError):
            continue                          # one odd row must not cost the rest of the table


class ArpWatch:
    """Remembers which MACs have answered for each address, and when they last did.

    An answer is evidence, not a re-read.  Windows keeps a neighbour row after the device stops
    answering (Stale) until something else answers for that address, and TNT reads the table every
    few seconds; stamping every read would make each lease change, device swap or router swap a
    two-minute "both answered" duplicate that nobody ever saw.  So a MAC is stamped only when its row
    is fresh (reachable, or permanent) or when the table's answer for that address changed to it -
    and a row first met already Stale is not stamped at all, because when it last answered is
    unknown.  A plain ``{ip: mac}`` reading has no states: there a row counts when it first appears
    or changes, never when it is merely read again.

    Kept apart from the watcher so the windowing can be tested against a clock without a network.
    """

    def __init__(self, window_s: float = ARP_WINDOW_S, max_tracked: int = ARP_MAX_TRACKED) -> None:
        self._window = float(window_s)
        self._max = int(max_tracked)
        self._seen: "Dict[Any, Dict[str, float]]" = {}     # key -> {mac: when it last answered}
        self._last: "Dict[Any, str]" = {}                   # key -> the MAC the last reading held

    def observe(self, table: Any, now: float) -> None:
        """Fold one reading in (see :func:`_arp_rows` for the two shapes it takes)."""
        current: "Dict[Any, str]" = {}
        for key, ip, mac, state in _arp_rows(table):
            if not ip or not mac:
                continue
            mac = mac.upper()
            previous = self._last.get(key)
            current[key] = mac
            changed = previous is not None and previous != mac
            fresh = (previous is None) if state is None else (state in _FRESH_STATES)
            if fresh or changed:
                self._seen.setdefault(key, {})[mac] = now
        self._last = current
        self._prune(now)

    def expire(self, now: float) -> None:
        """Let answers age out of the window without a new reading (the table could not be read)."""
        self._prune(now)

    def _prune(self, now: float) -> None:
        for ip in list(self._seen):
            macs = self._seen[ip]
            for mac, ts in list(macs.items()):
                if now - ts > self._window:
                    del macs[mac]
            if not macs:
                del self._seen[ip]
        if len(self._seen) > self._max:
            # keep the most recently seen; a discovery sweep of a /16 must not grow this for ever
            ordered = sorted(self._seen.items(), key=lambda kv: -max(kv[1].values()))
            self._seen = dict(ordered[: self._max])

    def conflicts(self) -> List[Dict[str, Any]]:
        """``[{"ip", "macs": [...], "seen"}]`` for every address that more than one MAC has answered
        for inside the window, with ``"if_index"`` when the reading named the interface."""
        out = []
        for key, macs in self._seen.items():
            if len(macs) > 1:
                row: Dict[str, Any] = {"ip": key[1] if isinstance(key, tuple) else key}
                if isinstance(key, tuple):
                    row["if_index"] = key[0]
                row.update({"macs": sorted(macs), "seen": len(macs)})
                out.append(row)
        out.sort(key=lambda row: (str(row["ip"]), row.get("if_index") or 0))
        return out

    def tracked(self) -> int:
        return len(self._seen)


# =========================================================================================
# the watcher
# =========================================================================================
class _Nic:
    """One adapter's baseline, its recent readings and its latest one."""

    __slots__ = ("first", "latest", "first_ts", "latest_ts", "history")

    def __init__(self, counters: Any, ts: float) -> None:
        self.rebase(counters, ts)

    def rebase(self, counters: Any, ts: float) -> None:
        """A counter went backwards (the adapter reset): start again from here rather than report
        a negative delta or a nonsense one."""
        self.first = counters
        self.first_ts = ts
        self.latest = counters
        self.latest_ts = ts
        self.history: Deque[Tuple[float, Any]] = deque([(ts, counters)])

    def advance(self, counters: Any, ts: float) -> None:
        """A new reading.  The history keeps every reading inside :data:`RATE_WINDOW_S` of it plus the
        newest one at or before the window's start, so the window always spans the whole of it (and,
        across a sleep with no readings, spans the gap: the deltas are still only what happened
        since that last reading)."""
        self.latest, self.latest_ts = counters, ts
        self.history.append((ts, counters))
        while len(self.history) > 1 and self.history[1][0] <= ts - RATE_WINDOW_S:
            self.history.popleft()

    def base(self, now: float) -> Tuple[float, Any]:
        """(when, counters) of the reading the window starts from at *now*: the newest one at or
        before ``now - RATE_WINDOW_S``, or the first kept while the adapter is younger than that.
        Counted from *now*, not from the latest reading, so an adapter that stopped being read (its
        link went down, or the reads fail) has its errors age out on time; once even its latest
        reading is that old, the window is empty and there is nothing recent to judge."""
        cut = now - RATE_WINDOW_S
        if self.latest_ts <= cut:
            return self.latest_ts, self.latest
        chosen = self.history[0]
        for entry in self.history:
            if entry[0] > cut:
                break
            chosen = entry
        return chosen


class FaultWatcher:
    """Watches the cheap signals continuously and turns them into findings.

    ``reader``, ``adapters_fn`` and ``arp_fn`` are the seams the tests drive it through; left alone
    it reads the real interface table, the real adapters and the real ARP table.
    """

    def __init__(self, bus: Any = None, *, clock: Optional[Callable[[], float]] = None,
                 reader: Optional[Callable[[], Sequence[Any]]] = None,
                 adapters_fn: Optional[Callable[[], Sequence[Dict[str, Any]]]] = None,
                 arp_fn: Optional[Callable[[], Any]] = None,
                 gateway_fn: Optional[Callable[[], Optional[str]]] = None) -> None:
        self._bus = bus
        self._clock = clock or time.time
        self._reader = reader
        self._adapters_fn = adapters_fn
        self._arp_fn = arp_fn
        self._gateway_fn = gateway_fn
        self._lock = threading.Lock()
        self._nics: "Dict[int, _Nic]" = {}
        # adapters a good reading no longer listed (their link went down), kept - judged, and on the
        # page marked down - until their window is empty, in case they come straight back
        self._gone: "Dict[int, _Nic]" = {}
        # the watch's own time is the wall clock plus this, so that it never runs backwards
        self._offset = 0.0
        self._last_t: Optional[float] = None
        self._arp = ArpWatch()
        self._started_ts: Optional[float] = None
        self._checked_ts: Optional[float] = None
        self._note: Optional[str] = None
        self._blind: "frozenset[str]" = frozenset()     # which sources the last tick could not read
        self._adapters: List[Dict[str, Any]] = []
        self._gateway: Optional[str] = None
        self._level = "good"
        self._good_since: Optional[float] = None       # when the level last turned "good"
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # -- lifecycle ------------------------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="tnt-faults", daemon=True)
        self._thread.start()
        log.info("fault watch started (every %.0f s, nothing sent)", TICK_S)

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        self._thread = None
        if t is not None and t.is_alive():
            t.join(STOP_JOIN_S)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - one bad read must never end the watch
                log.exception("fault tick failed")
            if self._stop.wait(TICK_S):
                break

    # -- reading --------------------------------------------------------------------------
    def _read_counters(self) -> Sequence[Any]:
        if self._reader is not None:
            return self._reader()
        from . import throughput

        return throughput.read_counters()

    def _read_adapters(self) -> List[Dict[str, Any]]:
        if self._adapters_fn is not None:
            return list(self._adapters_fn())
        from . import netinfo

        snap = netinfo.netinfo_snapshot()
        return list(snap.get("adapters") or []) if isinstance(snap, dict) else []

    def _read_arp(self) -> Any:
        if self._arp_fn is not None:
            table = self._arp_fn()
            return dict(table) if isinstance(table, dict) else list(table or [])
        from . import arp

        # Row by row, with the interface and the neighbour state - not get_arp_table_native's
        # {ip: mac}, which keeps one MAC per address across every interface (the best state wins,
        # and the winner changes as the states cycle), so two networks numbered alike looked like
        # one address answered by two routers.  No "arp -a" fallback either: it has no states.
        return arp.neighbour_rows_native(arp.AF_INET)

    def _read_gateway(self) -> Optional[str]:
        if self._gateway_fn is not None:
            return self._gateway_fn()
        from . import netinfo

        return netinfo.get_default_gateway()

    def _steady_locked(self, wall: float, tick: bool = False) -> float:
        """The watch's time for the wall-clock reading *wall*: the same, except that it never runs
        backwards.

        Not a monotonic clock, because a monotonic clock is not promised to count the time the laptop
        sleeps, and the hours in the bag between two sites are what lets one site's errors age out
        before the next.
        But when Windows sets the clock back (a time sync, often the moment a PC with a flat RTC
        battery reaches a network) every "how long ago" went negative: the watch read as starting
        again, judged nothing until the clock caught up, and aged nothing out.  So a tick that finds
        the clock behind the last one absorbs the step and carries on from where the watch was.

        Only a tick moves the watch's time (*tick*).  The ticks follow one another, so a tick behind
        the last one can only be the clock set back; a page or tile looking in between may have read
        the clock just after a tick read it and just before that tick took the lock, and letting that
        count as a step would push the watch ahead of the wall clock a little every time."""
        t = wall + self._offset
        if self._last_t is not None and t < self._last_t:
            if not tick:
                return self._last_t           # a look between ticks: no earlier than the last tick
            self._offset += self._last_t - t
            t = self._last_t
        if tick:
            self._last_t = t
        return t

    def _wall_locked(self, t: float) -> float:
        """The wall-clock time the watch's time *t* stands for now."""
        return t - self._offset

    def tick(self, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """One pass over all three sources.  Returns the tile when the level changed, else None.
        *now* is a wall-clock reading (the clock's own, when left out)."""
        wall = float(self._clock() if now is None else now)
        problems: List[str] = []
        blind = set()

        try:
            counters = list(self._read_counters())
        except Exception as exc:  # noqa: BLE001
            counters = []
            blind.add("counters")
            problems.append(f"interface counters: {type(exc).__name__}")
            log.debug("reading the interface counters failed", exc_info=True)
        else:
            if not counters:
                # Nothing is up to count - or nothing is up *yet*, as on the first tick after a
                # resume.  Either way this reading says nothing about the adapters already being
                # watched, and "no frame errors" is not a claim it can back.
                blind.add("counters")
                problems.append("interface counters: no adapter is up")
        try:
            adapters: Optional[List[Dict[str, Any]]] = self._read_adapters()
        except Exception as exc:  # noqa: BLE001
            adapters = None                   # keep the last configuration read; say it is old
            blind.add("adapters")
            problems.append(f"adapters: {type(exc).__name__}")
            log.debug("reading the adapters failed", exc_info=True)
        try:
            table = self._read_arp()
        except Exception as exc:  # noqa: BLE001
            table = None
            blind.add("arp")
            problems.append(f"ARP table: {type(exc).__name__}")
            log.debug("reading the ARP table failed", exc_info=True)
        try:
            gateway = self._read_gateway()
        except Exception:  # noqa: BLE001 - which address is the gateway is decoration here
            gateway = self._gateway

        with self._lock:
            now = self._steady_locked(wall, tick=True)
            if self._started_ts is None:
                self._started_ts = now
            self._checked_ts = now
            self._note = "; ".join(problems) or None
            self._blind = frozenset(blind)
            if adapters is not None:
                self._adapters = adapters
            self._gateway = gateway
            for luid in [k for k, n in self._gone.items() if now - n.latest_ts >= RATE_WINDOW_S]:
                del self._gone[luid]          # its window is empty: a new adapter if it returns
            for c in counters:
                nic = self._nics.get(c.luid)
                if nic is None:
                    # An adapter that went down and came back inside a window takes up where it left
                    # off.  A bad cable is exactly what makes a link drop and return; starting it
                    # afresh each time would keep it forever under MIN_WATCH_S, never judged.
                    nic = self._gone.pop(c.luid, None)
                    if nic is None or _went_backwards(c, nic.latest):
                        nic = _Nic(c, now)
                    else:
                        nic.advance(c, now)
                    self._nics[c.luid] = nic
                elif _went_backwards(c, nic.latest):
                    nic.rebase(c, now)
                else:
                    nic.advance(c, now)
            if counters:
                # Only a reading that worked and lists adapters can say one went away.  A failed or
                # empty one leaves every baseline and its history alone: sweeping on it turned a red
                # tile green and forgot the errors, because the next baseline already held them.
                live = {c.luid for c in counters}
                for luid in [k for k in self._nics if k not in live]:
                    # Its link went down.  What it counted before that is still the last few
                    # minutes' until it ages out, so it stays judged (and on the page, marked down):
                    # dropping it at once turned a bad cable's tile green every time the link blinked.
                    self._gone[luid] = self._nics.pop(luid)
            if table is None:
                self._arp.expire(now)         # nothing new was read; old answers still age out
            else:
                self._arp.observe(table, now)
            level_before = self._level
            findings = self._findings_locked(now)
            self._level = worst_level(findings)
            changed = self._level != level_before
            if self._level != "good":
                self._good_since = None
            elif self._good_since is None:
                self._good_since = now

        if changed:
            tile = self.tile()
            if self._bus is not None:
                try:
                    self._bus.publish("faults.state", tile)
                except Exception:  # noqa: BLE001
                    log.exception("publishing faults.state failed")
            log.info("fault watch: %s (%d bad, %d warn)", tile["level"], tile["bad"], tile["warn"])
            return tile
        return None

    # -- findings -------------------------------------------------------------------------
    def _nic_rows_locked(self, now: float) -> List[Dict[str, Any]]:
        rows = []
        # the adapters on the last good reading, then the ones whose link has gone down since, for
        # as long as their window still holds anything
        watched = [(nic, True) for nic in self._nics.values()]
        watched += [(nic, False) for nic in self._gone.values() if now - nic.latest_ts < RATE_WINDOW_S]
        for nic, up in watched:
            first, latest = nic.first, nic.latest
            base_ts, base = nic.base(now)
            row: Dict[str, Any] = {
                "name": latest.name,
                "description": latest.description,
                "index": latest.index,
                "link_bps": latest.link_bps,
                "watched_s": max(0.0, round(now - nic.first_ts, 1)),
                "up": up,
                "last_read_s": max(0.0, round(now - nic.latest_ts, 1)),
                "rx_errors": int(latest.rx_errors), "tx_errors": int(latest.tx_errors),
                "rx_discards": int(latest.rx_discards), "tx_discards": int(latest.tx_discards),
                "error_pct": None,
                "discard_pct": None,
                # the span the levels are judged on: from the reading at the start of the window to
                # the latest one.  Shorter than RATE_WINDOW_S while the adapter is new or has not
                # been read lately, 0 once it has not been read for a window, and longer across a
                # sleep: it reaches back to the last reading before it, so the deltas are still only
                # what the counters did since then.
                "window_s": max(0.0, round(nic.latest_ts - base_ts, 1)),
            }
            for field in ("rx_errors", "tx_errors", "rx_discards", "tx_discards", "rx_packets", "tx_packets"):
                row["new_" + field] = max(0, int(getattr(latest, field)) - int(getattr(first, field)))
                row["recent_" + field] = max(0, int(getattr(latest, field)) - int(getattr(base, field)))
            rows.append(row)
        for row in rows:
            # the shares the findings use, since TNT started watching: errors of every frame carried,
            # and discards of every frame queued to send (the inbound ones are never graded)
            row["error_pct"] = _pct(_since(row, "rx_errors") + _since(row, "tx_errors"),
                                    _frames(row, _ALL_FRAMES, _since))
            row["discard_pct"] = _pct(_since(row, "tx_discards"), _frames(row, _SENT_FRAMES, _since))
        rows.sort(key=lambda r: str(r.get("name") or ""))
        return rows

    def _findings_locked(self, now: float) -> List[Dict[str, Any]]:
        watched = 0.0 if self._started_ts is None else max(0.0, now - self._started_ts)
        if self._note and not self._nics and not self._adapters:
            return [_finding(
                "fault.unavailable", "info", "Nothing could be read to check",
                f"This PC would not answer for its own state ({self._note}).",
                "The service log says which call failed. Everything here is a local read, so this is "
                "a problem with this machine rather than with the network.")]
        # an adapter that came up a moment ago is as new as a watch that started a moment ago
        every_row = self._nic_rows_locked(now)
        rows = [r for r in every_row if r["watched_s"] >= MIN_WATCH_S]
        findings: List[Dict[str, Any]] = []
        findings.extend(address_findings(self._adapters))      # true the moment it is read
        names = {a.get("index"): a.get("name") for a in self._adapters if isinstance(a, dict)}
        conflicts = [dict(c, adapter=names[c["if_index"]]) if names.get(c.get("if_index")) else c
                     for c in self._arp.conflicts()]
        findings.extend(arp_findings(conflicts, self._gateway))
        if watched >= MIN_WATCH_S:
            findings.extend(error_findings(rows))
            findings.extend(discard_findings(rows))
        findings.sort(key=lambda f: _LEVEL_ORDER.get(str(f.get("level")), 99))
        if findings:
            return findings
        if watched < MIN_WATCH_S:
            return [_finding(
                "fault.watching", "info", "Watching",
                f"Nothing wrong so far. The adapter counters need {_duration(MIN_WATCH_S)} of watching "
                f"before they mean anything, and TNT has been here {_duration(watched)}.",
                "Nothing to do. This checks itself, from the moment the service starts.")]
        advice = ("Nothing to do. If something is still wrong, the fault is above the things this can "
                  "see from one port - try the SIP, Pro AV or Packet capture pages for the traffic itself.")
        checked = _clean_detail(every_row, watched, self._blind)
        unread = f"The rest could not be read on the last look ({self._note}), so it was not checked."
        if "counters" not in self._blind and any(
                _recent(r, "rx_errors") + _recent(r, "tx_errors") for r in every_row):
            # Damaged frames the window held but could not judge yet: too few frames on the link to
            # make a share of, even over the whole watch, or an adapter that has only just come up.
            # That is not a clean link - on a switched link the count should be flat zero - so the
            # tile says it is still watching until there is enough to judge them by.
            return [_finding(
                "fault.watching", "info", "Frame errors seen, not judged yet",
                checked + (" " + unread if self._blind else "")
                + f" A share of a handful of frames means nothing, so they are judged once the adapter "
                  f"has carried {MIN_PACKETS:,} frames and been up {_duration(MIN_WATCH_S)}.",
                "Nothing to do yet; this settles on its own within a few minutes. If you are standing "
                "at the cable anyway, re-seat both ends: a switched link should count no errors at all.")]
        if not self._blind:
            return [_finding("fault.clean", "good", "No faults found", checked, advice)]
        # A source could not be read on the last look: say what was checked and what was not, and
        # do not call it clean - a tile that said "clean for 2 h" while the ARP table had never been
        # read would be hiding the one duplicate gateway it exists to catch.
        return [_finding(
            "fault.clean", "info", "No faults found in what could be read",
            (checked + " " if checked else "") + unread,
            "The service log says which call failed. Everything here is a local read, so this is a "
            "problem with this machine rather than with the network; it usually clears on its own.")]

    # -- views ----------------------------------------------------------------------------
    def view(self) -> Dict[str, Any]:
        """``GET /api/faults``: the findings, the counters behind them and the ARP watch."""
        wall = float(self._clock())
        with self._lock:
            now = self._steady_locked(wall)
            findings = self._findings_locked(now)
            rows = self._nic_rows_locked(now)
            watched = 0.0 if self._started_ts is None else max(0.0, now - self._started_ts)
            return {
                "ts": wall,
                "watching_since": None if self._started_ts is None else self._wall_locked(self._started_ts),
                "watched_s": round(watched, 1),
                "level": worst_level(findings),
                "findings": findings,
                "nics": rows,
                "arp": {"tracked": self._arp.tracked(), "conflicts": self._arp.conflicts(),
                        "window_s": ARP_WINDOW_S, "gateway": self._gateway},
                "note": self._note,
            }

    def tile(self) -> Dict[str, Any]:
        """``status.faults``: the worst level, the counts, and the one line the tile shows."""
        wall = float(self._clock())
        with self._lock:
            now = self._steady_locked(wall)
            findings = self._findings_locked(now)
            watched = 0.0 if self._started_ts is None else max(0.0, now - self._started_ts)
            note = self._note
            good_since = self._good_since
        level = worst_level(findings)
        bad = sum(1 for f in findings if f.get("level") == "bad")
        warn = sum(1 for f in findings if f.get("level") == "warn")
        headline = str(findings[0]["title"]) if findings else "No faults found"
        # How long it has been clean, which since the levels follow the last few minutes is not how
        # long TNT has been watching: "clean for 2 h" six minutes after a red tile would be false.
        clean = None
        if level == "good":
            clean = round(max(0.0, now - (now if good_since is None else good_since)), 1)
        return {"available": True, "reason": note, "level": level, "bad": bad, "warn": warn,
                "headline": headline, "watched_s": round(watched, 1), "clean_s": clean, "ts": wall}


def _went_backwards(new: Any, old: Any) -> bool:
    """Whether any counter on this adapter dropped, which only a reset does."""
    for field in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                  "rx_errors", "tx_errors", "rx_discards", "tx_discards"):
        if int(getattr(new, field, 0)) < int(getattr(old, field, 0)):
            return True
    return False
