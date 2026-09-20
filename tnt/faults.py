"""What is wrong with this network, found without asking the network anything.

The Faults tile. Every other tool in TNT answers a question the tech thought to ask; this one
answers the question they have before they know to ask it - *what is broken here that nobody
mentioned?* - and it answers it by the time they have finished plugging in, because it is watching
from the moment the service starts.

Everything here is **passive and needs no administrator**: three sources the machine already has.

* **The adapter's own error and discard counters** (``GetIfTable2``, read through
  :func:`tnt.throughput.read_counters`).  Errors and discards are kept apart on purpose, because
  they send a tech to different places: an *error* is a frame that arrived damaged - cabling, a
  connector, a duplex mismatch - and a *discard* is a frame that was perfectly good and was dropped
  anyway, which is congestion.  Rolling them into one "problem" number would be the least useful
  thing this module could do.
* **The adapter's live address configuration** (:func:`tnt.netinfo.adapter_warnings`), which already
  knows a self-assigned 169.254 address, a duplicate address, a gateway outside its own subnet, two
  default gateways and an adapter with no DNS servers.  Those were only ever visible on that
  adapter's own card, which is the last place anyone looks.
* **The ARP table over time** (:func:`tnt.arp.get_arp_table_native`).  One address answered by two
  different MACs is the classic duplicate IP, and it is invisible to everything else in TNT.

Counting from when we started watching, not from the top
--------------------------------------------------------
The counters Windows keeps are cumulative since the adapter came up, which on a desktop that has
been on for a month is a number about last month.  Every finding here is driven by the change
**since TNT started watching**, and says how long that has been.  "154,426 discards" is a fact about
an uptime nobody remembers; "142 discards in the eleven minutes I have been looking" is a fact about
the network the tech is standing in.  The cumulative figure is still reported beside it as context,
clearly labelled, because a tech who wants it should not have to open Task Manager.

For the same reason a fault is only raised once there is enough watched time to mean anything
(:data:`MIN_WATCH_S`); before that the tile says it is still watching rather than that all is well.

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
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

__all__ = ["FINDING_LEVELS", "FINDING_IDS", "FINDING_KEYS", "NIC_KEYS", "VIEW_KEYS", "TILE_KEYS",
           "TICK_S", "MIN_WATCH_S", "FaultWatcher", "error_findings", "address_findings",
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
    "rx_errors", "tx_errors", "rx_discards", "tx_discards",              # cumulative, for context
    "new_rx_errors", "new_tx_errors", "new_rx_discards", "new_tx_discards",   # since we started
    "new_rx_packets", "new_tx_packets", "error_pct", "discard_pct",
)
VIEW_KEYS: Tuple[str, ...] = ("ts", "watching_since", "watched_s", "level", "findings", "nics",
                              "arp", "note")
TILE_KEYS: Tuple[str, ...] = ("available", "reason", "level", "bad", "warn", "headline",
                              "watched_s", "ts")

#: One look every five seconds.  These are counters, not events: a faster tick would cost more and
#: say nothing extra, and a slower one would make the tile feel stale after a cable is re-seated.
TICK_S = 5.0
#: No fault is raised from less watched time than this.  A single error in the first two seconds is
#: noise, and a tile that cried wolf on arrival would be switched off by the end of the week.
MIN_WATCH_S = 60.0
#: An adapter that has moved fewer packets than this since we started is too quiet to judge: one
#: error out of thirty packets is a meaningless ratio.
MIN_PACKETS = 500
#: Damaged frames, as a share of frames received.  Anything at all is worth saying on a switched
#: link; these are where it stops being "worth mentioning" and starts being "go and fix it".
ERROR_WARN_PCT = 0.01
ERROR_BAD_PCT = 0.5
#: Dropped-for-no-buffer frames.  A burst is normal on a busy link, so the bar is higher than for
#: errors - a discard means the link was full, not that anything is broken.
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


# =========================================================================================
# the detectors - pure functions over plain rows, so every threshold is testable on its own
# =========================================================================================
def _pct(part: int, whole: int) -> Optional[float]:
    return None if whole <= 0 else (100.0 * part) / whole


def error_findings(nics: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Damaged frames since we started watching: cabling, a connector, or a duplex mismatch.

    Receive and transmit are reported together but named separately in the detail, because they
    point at different ends of the same cable: frames arriving damaged is usually the run or the
    far end, frames failing to leave is usually this NIC or its driver.
    """
    rows = []
    for nic in nics:
        seen = int(nic.get("new_rx_errors") or 0) + int(nic.get("new_tx_errors") or 0)
        packets = int(nic.get("new_rx_packets") or 0) + int(nic.get("new_tx_packets") or 0)
        if seen <= 0 or packets < MIN_PACKETS:
            continue
        pct = _pct(seen, packets) or 0.0
        level = "bad" if pct >= ERROR_BAD_PCT else "warn" if pct >= ERROR_WARN_PCT else "info"
        rows.append((pct, level, nic, seen, packets))
    if not rows:
        return []
    rows.sort(key=lambda r: -r[0])
    pct, level, nic, seen, packets = rows[0]
    name = nic.get("name") or "an adapter"
    parts = []
    if int(nic.get("new_rx_errors") or 0):
        parts.append(_plural(int(nic["new_rx_errors"]), "arriving damaged", "arriving damaged"))
    if int(nic.get("new_tx_errors") or 0):
        parts.append(_plural(int(nic["new_tx_errors"]), "failing to send", "failing to send"))
    more = f" (and {len(rows) - 1} other adapter{'' if len(rows) == 2 else 's'})" if len(rows) > 1 else ""
    return [_finding(
        "fault.errors", level, f"{name} is seeing frame errors{more}",
        f"{' and '.join(parts)} out of {_plural(packets, 'frame')} in the "
        f"{_duration(float(nic.get('watched_s') or 0))} since TNT started watching - {pct:.3g}% of them. "
        "These are frames the adapter received or sent damaged, not frames dropped because the link "
        "was busy.",
        "On a switched link this should be flat zero. Re-seat both ends of the cable and try a known "
        "good patch lead first; if it stays, suspect the run itself, the socket, or a duplex "
        "mismatch with the switch port (check the port is not forced to half duplex).",
        [{"name": r[2].get("name"), "rx_errors": r[2].get("new_rx_errors"),
          "tx_errors": r[2].get("new_tx_errors"), "pct": round(r[0], 4)} for r in rows])]


def discard_findings(nics: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Good frames dropped for want of a buffer: the link was full, nothing is damaged."""
    rows = []
    for nic in nics:
        seen = int(nic.get("new_rx_discards") or 0) + int(nic.get("new_tx_discards") or 0)
        packets = int(nic.get("new_rx_packets") or 0) + int(nic.get("new_tx_packets") or 0)
        if seen <= 0 or packets < MIN_PACKETS:
            continue
        pct = _pct(seen, packets) or 0.0
        if pct < DISCARD_WARN_PCT:
            continue                      # a few discards on a busy link is what a buffer is for
        rows.append((pct, "bad" if pct >= DISCARD_BAD_PCT else "warn", nic, seen, packets))
    if not rows:
        return []
    rows.sort(key=lambda r: -r[0])
    pct, level, nic, seen, packets = rows[0]
    name = nic.get("name") or "an adapter"
    return [_finding(
        "fault.discards", level, f"{name} is dropping frames it had no room for",
        f"{_plural(seen, 'frame')} discarded out of {_plural(packets, 'frame')} in the "
        f"{_duration(float(nic.get('watched_s') or 0))} since TNT started watching - {pct:.3g}%. "
        "Nothing here is damaged: these arrived or were queued intact and were dropped because there "
        "was nowhere to put them.",
        "This is congestion, not a fault in the cable. Check what is saturating the link on the "
        "Realtime throughput card, and whether this adapter has negotiated the speed you expect.",
        [{"name": r[2].get("name"), "rx_discards": r[2].get("new_rx_discards"),
          "tx_discards": r[2].get("new_tx_discards"), "pct": round(r[0], 4)} for r in rows])]


#: Keys are ``tnt.netinfo`` codes; a test asserts they all still exist, because an unknown code
#: would quietly fall back to "info" and a duplicate address would stop being a fault.
_ADDRESS_LEVEL = {
    "duplicate_address": "bad",
    "apipa": "bad",
    "gateway_outside_subnet": "warn",
    "multiple_default_gateways": "warn",
    "no_dns": "warn",
}


def address_findings(adapters: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The adapter warnings :mod:`tnt.netinfo` already works out, gathered where they get read.

    They were only ever shown on the adapter's own card on Network info, which is several scrolls
    down a page nobody opens when things are working.
    """
    hits: List[Tuple[str, str, str]] = []           # (level, adapter name, message)
    for a in adapters or []:
        if str(a.get("status") or "") != "up":
            continue                               # a down adapter's configuration is not a fault
        name = str(a.get("name") or "an adapter")
        for warning in a.get("warnings") or []:
            code = str((warning or {}).get("code") or "")
            message = str((warning or {}).get("message") or "").strip()
            if not message:
                continue
            hits.append((_ADDRESS_LEVEL.get(code, "info"), name, message))
    if not hits:
        return []
    hits.sort(key=lambda h: _LEVEL_ORDER.get(h[0], 99))
    level = hits[0][0]
    title = ("An adapter has no usable address" if level == "bad"
             else "An adapter's address configuration needs a look")
    return [_finding(
        "fault.address", level, title,
        "; ".join(f"{name}: {message}" for _l, name, message in hits[:4])
        + (f" (and {len(hits) - 4} more)" if len(hits) > 4 else ""),
        "These come from the live configuration of the adapters, not from a scan. Network info "
        "shows each one on its own adapter card, with the addresses behind it.",
        [{"adapter": name, "level": lvl, "message": message} for lvl, name, message in hits])]


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
    more = f" (and {len(rows) - 1} other address{'' if len(rows) == 2 else 'es'})" if len(rows) > 1 else ""
    if is_gateway:
        return [_finding(
            "fault.gateway", "bad", f"The default gateway {first.get('ip')} has answered from two MAC addresses",
            f"Both {macs} replied for {first.get('ip')} within {_duration(ARP_WINDOW_S)}{more}.",
            "A router pair failing over does this legitimately, and so does something answering for "
            "the router that should not be. If the site has no redundant gateway, find the second "
            "device: the MAC's first three bytes name its maker on the Discovery page.",
            list(rows))]
    return [_finding(
        "fault.arp", "bad", f"Two devices are answering for {first.get('ip')}{more}",
        f"{macs} both replied for {first.get('ip')} within {_duration(ARP_WINDOW_S)}. That address is "
        "configured on more than one device, so which one you reach depends on which answered last.",
        "Find the newer device and change its address, or put it back on DHCP. Whichever device is "
        "not meant to have it will be the one that appeared most recently on the Discovery page.",
        list(rows))]


# =========================================================================================
# the ARP watch
# =========================================================================================
class ArpWatch:
    """Remembers which MACs have answered for each address, and for how long.

    Kept apart from the watcher so the windowing can be tested against a clock without a network.
    """

    def __init__(self, window_s: float = ARP_WINDOW_S, max_tracked: int = ARP_MAX_TRACKED) -> None:
        self._window = float(window_s)
        self._max = int(max_tracked)
        self._seen: "Dict[str, Dict[str, float]]" = {}     # ip -> {mac: last seen ts}

    def observe(self, table: Dict[str, str], now: float) -> None:
        """Fold one ARP table reading in.  *table* is ``{ip: mac}``, as :mod:`tnt.arp` returns it."""
        for ip, mac in (table or {}).items():
            if not ip or not mac:
                continue
            macs = self._seen.setdefault(str(ip), {})
            macs[str(mac).upper()] = now
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
        """``[{"ip", "macs": [...]}]`` for every address that more than one MAC has answered for."""
        out = []
        for ip, macs in self._seen.items():
            if len(macs) > 1:
                out.append({"ip": ip, "macs": sorted(macs), "seen": len(macs)})
        out.sort(key=lambda row: str(row["ip"]))
        return out

    def tracked(self) -> int:
        return len(self._seen)


# =========================================================================================
# the watcher
# =========================================================================================
class _Nic:
    """One adapter's baseline and latest reading."""

    __slots__ = ("first", "latest", "first_ts", "latest_ts")

    def __init__(self, counters: Any, ts: float) -> None:
        self.first = counters
        self.latest = counters
        self.first_ts = ts
        self.latest_ts = ts

    def rebase(self, counters: Any, ts: float) -> None:
        """A counter went backwards (the adapter reset): start again from here rather than report
        a negative delta or a nonsense one."""
        self.first = counters
        self.first_ts = ts
        self.latest = counters
        self.latest_ts = ts


class FaultWatcher:
    """Watches the cheap signals continuously and turns them into findings.

    ``reader``, ``adapters_fn`` and ``arp_fn`` are the seams the tests drive it through; left alone
    it reads the real interface table, the real adapters and the real ARP table.
    """

    def __init__(self, bus: Any = None, *, clock: Optional[Callable[[], float]] = None,
                 reader: Optional[Callable[[], Sequence[Any]]] = None,
                 adapters_fn: Optional[Callable[[], Sequence[Dict[str, Any]]]] = None,
                 arp_fn: Optional[Callable[[], Dict[str, str]]] = None,
                 gateway_fn: Optional[Callable[[], Optional[str]]] = None) -> None:
        self._bus = bus
        self._clock = clock or time.time
        self._reader = reader
        self._adapters_fn = adapters_fn
        self._arp_fn = arp_fn
        self._gateway_fn = gateway_fn
        self._lock = threading.Lock()
        self._nics: "Dict[int, _Nic]" = {}
        self._arp = ArpWatch()
        self._started_ts: Optional[float] = None
        self._checked_ts: Optional[float] = None
        self._note: Optional[str] = None
        self._adapters: List[Dict[str, Any]] = []
        self._gateway: Optional[str] = None
        self._level = "good"
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

    def _read_arp(self) -> Dict[str, str]:
        if self._arp_fn is not None:
            return dict(self._arp_fn())
        from . import arp

        return dict(arp.get_arp_table_native())

    def _read_gateway(self) -> Optional[str]:
        if self._gateway_fn is not None:
            return self._gateway_fn()
        from . import netinfo

        return netinfo.get_default_gateway()

    def tick(self, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """One pass over all three sources.  Returns the tile when the level changed, else None."""
        now = float(self._clock() if now is None else now)
        problems: List[str] = []

        try:
            counters = list(self._read_counters())
        except Exception as exc:  # noqa: BLE001
            counters = []
            problems.append(f"interface counters: {type(exc).__name__}")
            log.debug("reading the interface counters failed", exc_info=True)
        try:
            adapters = self._read_adapters()
        except Exception as exc:  # noqa: BLE001
            adapters = []
            problems.append(f"adapters: {type(exc).__name__}")
            log.debug("reading the adapters failed", exc_info=True)
        try:
            table = self._read_arp()
        except Exception as exc:  # noqa: BLE001
            table = {}
            problems.append(f"ARP table: {type(exc).__name__}")
            log.debug("reading the ARP table failed", exc_info=True)
        try:
            gateway = self._read_gateway()
        except Exception:  # noqa: BLE001 - which address is the gateway is decoration here
            gateway = self._gateway

        with self._lock:
            if self._started_ts is None:
                self._started_ts = now
            self._checked_ts = now
            self._note = "; ".join(problems) or None
            self._adapters = adapters
            self._gateway = gateway
            for c in counters:
                nic = self._nics.get(c.luid)
                if nic is None:
                    self._nics[c.luid] = _Nic(c, now)
                    continue
                if _went_backwards(c, nic.latest):
                    nic.rebase(c, now)
                else:
                    nic.latest, nic.latest_ts = c, now
            live = {c.luid for c in counters}
            for luid in [k for k in self._nics if k not in live]:
                del self._nics[luid]      # the adapter went: its counters say nothing about now
            self._arp.observe(table, now)
            level_before = self._level
            findings = self._findings_locked(now)
            self._level = worst_level(findings)
            changed = self._level != level_before

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
        for nic in self._nics.values():
            first, latest = nic.first, nic.latest
            rows.append({
                "name": latest.name,
                "description": latest.description,
                "index": latest.index,
                "link_bps": latest.link_bps,
                "watched_s": max(0.0, round(now - nic.first_ts, 1)),
                "rx_errors": int(latest.rx_errors), "tx_errors": int(latest.tx_errors),
                "rx_discards": int(latest.rx_discards), "tx_discards": int(latest.tx_discards),
                "new_rx_errors": max(0, int(latest.rx_errors) - int(first.rx_errors)),
                "new_tx_errors": max(0, int(latest.tx_errors) - int(first.tx_errors)),
                "new_rx_discards": max(0, int(latest.rx_discards) - int(first.rx_discards)),
                "new_tx_discards": max(0, int(latest.tx_discards) - int(first.tx_discards)),
                "new_rx_packets": max(0, int(latest.rx_packets) - int(first.rx_packets)),
                "new_tx_packets": max(0, int(latest.tx_packets) - int(first.tx_packets)),
                "error_pct": None,
                "discard_pct": None,
            })
        for row in rows:
            packets = row["new_rx_packets"] + row["new_tx_packets"]
            row["error_pct"] = _pct(row["new_rx_errors"] + row["new_tx_errors"], packets)
            row["discard_pct"] = _pct(row["new_rx_discards"] + row["new_tx_discards"], packets)
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
        rows = self._nic_rows_locked(now)
        findings: List[Dict[str, Any]] = []
        findings.extend(address_findings(self._adapters))      # true the moment it is read
        findings.extend(arp_findings(self._arp.conflicts(), self._gateway))
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
        return [_finding(
            "fault.clean", "good", "No faults found",
            f"In the {_duration(watched)} TNT has been watching: no frame errors, no congestion "
            "drops, every adapter addressed properly, and no address answered by two devices.",
            "Nothing to do. If something is still wrong, the fault is above the things this can see "
            "from one port - try the SIP, Pro AV or Packet capture pages for the traffic itself.")]

    # -- views ----------------------------------------------------------------------------
    def view(self) -> Dict[str, Any]:
        """``GET /api/faults``: the findings, the counters behind them and the ARP watch."""
        now = float(self._clock())
        with self._lock:
            findings = self._findings_locked(now)
            rows = self._nic_rows_locked(now)
            watched = 0.0 if self._started_ts is None else max(0.0, now - self._started_ts)
            return {
                "ts": now,
                "watching_since": self._started_ts,
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
        now = float(self._clock())
        with self._lock:
            findings = self._findings_locked(now)
            watched = 0.0 if self._started_ts is None else max(0.0, now - self._started_ts)
            note = self._note
        level = worst_level(findings)
        bad = sum(1 for f in findings if f.get("level") == "bad")
        warn = sum(1 for f in findings if f.get("level") == "warn")
        headline = str(findings[0]["title"]) if findings else "No faults found"
        return {"available": True, "reason": note, "level": level, "bad": bad, "warn": warn,
                "headline": headline, "watched_s": round(watched, 1), "ts": now}


def _went_backwards(new: Any, old: Any) -> bool:
    """Whether any counter on this adapter dropped, which only a reset does."""
    for field in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                  "rx_errors", "tx_errors", "rx_discards", "tx_discards"):
        if int(getattr(new, field, 0)) < int(getattr(old, field, 0)):
            return True
    return False
