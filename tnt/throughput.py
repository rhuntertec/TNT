"""Live per-adapter throughput: what each NIC is actually moving, sampled once a second.

Drives the "Realtime throughput" card of the Network info page (between the live link map and
the NAT & switch port card).  One ``GetIfTable2`` call a second reads every interface's 64-bit
byte and packet counters; the difference between two readings, over the time between them, is
the rate.  Nothing is sent and no admin rights are needed - these are the same counters Task
Manager and the Control Panel status dialog read.

Why ``GetIfTable2`` and not ``GetIfTable``: the older table carries 32-bit octet counters, which
wrap every 34 seconds on a gigabit link.  A wrap is indistinguishable from a reset, so a busy NIC
would show a spike or a hole once a minute.  ``MIB_IF_ROW2`` is 64-bit throughout.

What is counted, and what is not
--------------------------------
Windows reports one row per *interface*, which includes a copy of every physical NIC as seen
through each installed lightweight filter (QoS Packet Scheduler, WFP, Npcap, NDIS capture).
Those copies carry the **same counters** as the NIC they sit on, so a machine with Npcap
installed would show the same adapter eight times, each apparently moving the same traffic.
``MIB_IF_ROW2.InterfaceAndOperStatusFlags`` bit 1 (``FilterInterface``) marks them and they are
dropped; bit 0 (``HardwareInterface``) is *not* the test, because a VPN tunnel that really is
carrying traffic is not hardware either.  Software loopback (``IF_TYPE_SOFTWARE_LOOPBACK``) is
dropped too: it is this PC talking to itself.

A tunnel's traffic is counted twice on purpose - once on the tunnel and once on the NIC that
carries it - because that is what is really on each interface, and it is what Task Manager shows.

An adapter the site never wants to look at is left out by name: ``throughput.excluded`` in the
settings holds Windows connection names ("Ethernet 2", "vEthernet (Default Switch)"), set from a
checkbox at the foot of that adapter's card on Network info.  Names, not indexes, because an index
moves when a USB NIC is re-plugged and a name is what the person ticking the box is reading.  An
excluded adapter is still *sampled* - the table read costs the same either way - so unticking the
box brings its history back rather than starting it from nothing.

Rates and gaps
--------------
A rate needs two readings, so the first tick after start records nothing.  A counter that goes
*backwards* (an adapter reset, a driver reload) contributes 0 rather than a fabricated spike.
A gap longer than :data:`MAX_SPAN_S` - the machine slept, or the service was stopped - is left as
a gap in the series instead of being drawn as one long low-rate sample, because a flat line
across eight hours of sleep would be a claim about time nobody measured.

Shapes
------
* :func:`read_counters` -> ``[Counters, ...]``, the eligible interfaces and their raw totals.
* :meth:`ThroughputMonitor.view` -> the card's payload (``GET /api/throughput``): NICs with a
  bucketed series for the asked-for window, the window average and peak, and the cumulative
  byte/packet totals the Control Panel shows.
* :meth:`ThroughputMonitor.latest` -> the per-second ``throughput.sample`` event: the same NIC
  rows without the series, so an open card follows without asking for anything.

Rates are **bits per second** everywhere (``*_bps``), because that is the unit a link speed is
quoted in and what Task Manager shows; packets are per second (``*_pps``).  Cumulative
``rx_bytes`` / ``rx_packets`` are bytes and packets, straight from the counters, and count from
whenever the adapter came up - not from when TNT started.
"""
from __future__ import annotations

import collections
import ctypes
import logging
import math
import sys
import threading
import time
from ctypes import POINTER, Structure, byref, c_ubyte, c_ulong, c_ulonglong, c_ushort, c_void_p, c_wchar
from typing import Any, Callable, Deque, Dict, List, NamedTuple, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

__all__ = [
    "WINDOWS", "DEFAULT_WINDOW_S", "HISTORY_S", "MAX_POINTS", "MAX_SPAN_S",
    "NIC_KEYS", "VIEW_KEYS", "EVENT_KEYS", "SAMPLE_WIDTH",
    "Counters", "ThroughputMonitor", "read_counters", "clamp_window", "step_for",
]

#: The windows the card offers, in seconds.  30 s is the default because it is long enough to
#: show the shape of a transfer and short enough that a one-second sample is still a pixel wide.
WINDOWS: Tuple[int, ...] = (10, 30, 60, 300, 1800)
DEFAULT_WINDOW_S = 30
#: How much history is kept per NIC: the longest window, so switching to it is instant.
HISTORY_S = 1800
#: Most points sent for one NIC in one view.  1800 one-second samples is 80 kB of JSON per NIC;
#: bucketing to this keeps the longest window near 25 kB and still gives 2 points per pixel.
MAX_POINTS = 600
#: A reading further than this from the one before it is a gap (sleep, a stopped service), not a
#: sample.  Generous next to the one-second tick so a loaded machine does not punch holes.
MAX_SPAN_S = 10.0
#: How long the internet-facing NIC is remembered before it is looked up again.
PRIMARY_TTL_S = 5.0
STOP_JOIN_S = 2.0

#: One row of :meth:`ThroughputMonitor.view`'s ``nics``.
NIC_KEYS: Tuple[str, ...] = (
    "id", "index", "name", "description", "type", "primary", "link_bps",
    "rx_bps", "tx_bps", "rx_pps", "tx_pps", "avg_rx_bps", "avg_tx_bps", "peak_rx_bps", "peak_tx_bps",
    "rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "samples",
)
VIEW_KEYS: Tuple[str, ...] = ("ts", "window_s", "step_s", "history_s", "windows", "nics", "note")
#: The ``throughput.sample`` event: every NIC row except the series and the window figures.
EVENT_KEYS: Tuple[str, ...] = tuple(
    k for k in NIC_KEYS if k not in ("samples", "avg_rx_bps", "avg_tx_bps", "peak_rx_bps", "peak_tx_bps")
)
#: ``[ts, rx_bps, tx_bps, rx_pps, tx_pps]`` - an array, not an object, because there are hundreds.
SAMPLE_WIDTH = 5

IF_OPER_STATUS_UP = 1
IF_TYPE_SOFTWARE_LOOPBACK = 24
FLAG_HARDWARE = 0x01
FLAG_FILTER = 0x02
#: Windows' "speed unknown" sentinel, the same one :mod:`tnt.netinfo` folds to None.
SPEED_UNKNOWN = 0xFFFFFFFFFFFFFFFF
IF_MAX_STRING_SIZE = 256
IF_MAX_PHYS_ADDRESS_LENGTH = 32


class Counters(NamedTuple):
    """One interface's totals at one instant.  Every count is cumulative, since the adapter came up.

    The error and discard counts are what :mod:`tnt.faults` reads.  They are two different things and
    are kept apart on purpose: an **error** is a frame that arrived damaged (a bad FCS - cabling, a
    connector, a duplex mismatch), a **discard** is a frame that was fine and got dropped anyway
    (no buffer - congestion).  Rolling them together would send a tech to the wrong place.
    """

    luid: int
    index: int
    name: str
    description: str
    if_type: int
    link_bps: Optional[int]
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errors: int = 0
    tx_errors: int = 0
    rx_discards: int = 0
    tx_discards: int = 0


# =========================================================================================
# native
# =========================================================================================
class _GUID(Structure):
    _fields_ = [("Data1", c_ulong), ("Data2", c_ushort), ("Data3", c_ushort), ("Data4", c_ubyte * 8)]


class MIB_IF_ROW2(Structure):
    """``MIB_IF_ROW2`` (netioapi.h).  1352 bytes on x64; ``tests/test_native.py`` pins that.

    ``InterfaceAndOperStatusFlags`` is a byte of bit flags in C; declaring it ``c_ubyte`` and
    letting ctypes align the ``c_ulong`` after it reproduces the three bytes of padding MSVC
    puts there.
    """

    _fields_ = [
        ("InterfaceLuid", c_ulonglong),
        ("InterfaceIndex", c_ulong),
        ("InterfaceGuid", _GUID),
        ("Alias", c_wchar * (IF_MAX_STRING_SIZE + 1)),
        ("Description", c_wchar * (IF_MAX_STRING_SIZE + 1)),
        ("PhysicalAddressLength", c_ulong),
        ("PhysicalAddress", c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("PermanentPhysicalAddress", c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("Mtu", c_ulong),
        ("Type", c_ulong),
        ("TunnelType", c_ulong),
        ("MediaType", c_ulong),
        ("PhysicalMediumType", c_ulong),
        ("AccessType", c_ulong),
        ("DirectionType", c_ulong),
        ("InterfaceAndOperStatusFlags", c_ubyte),
        ("OperStatus", c_ulong),
        ("AdminStatus", c_ulong),
        ("MediaConnectState", c_ulong),
        ("NetworkGuid", _GUID),
        ("ConnectionType", c_ulong),
        ("TransmitLinkSpeed", c_ulonglong),
        ("ReceiveLinkSpeed", c_ulonglong),
        ("InOctets", c_ulonglong),
        ("InUcastPkts", c_ulonglong),
        ("InNUcastPkts", c_ulonglong),
        ("InDiscards", c_ulonglong),
        ("InErrors", c_ulonglong),
        ("InUnknownProtos", c_ulonglong),
        ("InUcastOctets", c_ulonglong),
        ("InMulticastOctets", c_ulonglong),
        ("InBroadcastOctets", c_ulonglong),
        ("OutOctets", c_ulonglong),
        ("OutUcastPkts", c_ulonglong),
        ("OutNUcastPkts", c_ulonglong),
        ("OutDiscards", c_ulonglong),
        ("OutErrors", c_ulonglong),
        ("OutUcastOctets", c_ulonglong),
        ("OutMulticastOctets", c_ulonglong),
        ("OutBroadcastOctets", c_ulonglong),
        ("OutQLen", c_ulonglong),
    ]


class MIB_IF_TABLE2(Structure):
    """``MIB_IF_TABLE2``: a count, then the rows.  The rows start at offset 8, not 4 - the row's
    ``NET_LUID`` needs 8-byte alignment."""

    _fields_ = [("NumEntries", c_ulong), ("Table", MIB_IF_ROW2 * 1)]


_dll: Any = None
_dll_lock = threading.Lock()


def _iphlpapi() -> Any:
    """Load ``iphlpapi`` once with the two prototypes declared (64-bit safe)."""
    global _dll
    with _dll_lock:
        if _dll is None:
            dll = ctypes.WinDLL("iphlpapi", use_last_error=True)
            dll.GetIfTable2.argtypes = [POINTER(POINTER(MIB_IF_TABLE2))]
            dll.GetIfTable2.restype = c_ulong
            dll.FreeMibTable.argtypes = [c_void_p]
            dll.FreeMibTable.restype = None
            _dll = dll
        return _dll


def eligible(if_type: int, oper_status: int, flags: int) -> bool:
    """Whether an interface belongs on the card: up, real, and not a filter's copy of a NIC.

    The filter test is the one that matters.  Every lightweight filter bound to a NIC gets its
    own row carrying that NIC's counters, so without it one adapter appears many times moving
    the same bytes.
    """
    if oper_status != IF_OPER_STATUS_UP:
        return False
    if flags & FLAG_FILTER:
        return False
    return if_type != IF_TYPE_SOFTWARE_LOOPBACK


def read_counters() -> List[Counters]:
    """Every eligible interface's totals, now.  Raises ``OSError`` if the call fails."""
    if sys.platform != "win32":
        raise OSError("interface counters need Windows")
    dll = _iphlpapi()
    ptr = POINTER(MIB_IF_TABLE2)()
    rc = int(dll.GetIfTable2(byref(ptr)))
    if rc != 0:
        raise OSError(rc, f"GetIfTable2 failed: {ctypes.FormatError(rc).strip()} ({rc})")
    out: List[Counters] = []
    try:
        table = ptr.contents
        base = ctypes.addressof(table) + MIB_IF_TABLE2.Table.offset
        width = ctypes.sizeof(MIB_IF_ROW2)
        for i in range(int(table.NumEntries)):
            row = MIB_IF_ROW2.from_address(base + i * width)
            if not eligible(int(row.Type), int(row.OperStatus), int(row.InterfaceAndOperStatusFlags)):
                continue
            speed = int(row.ReceiveLinkSpeed)
            out.append(Counters(
                luid=int(row.InterfaceLuid),
                index=int(row.InterfaceIndex),
                name=str(row.Alias or "").strip(),
                description=str(row.Description or "").strip(),
                if_type=int(row.Type),
                link_bps=None if speed in (0, SPEED_UNKNOWN) else speed,
                rx_bytes=int(row.InOctets),
                tx_bytes=int(row.OutOctets),
                rx_packets=int(row.InUcastPkts) + int(row.InNUcastPkts),
                tx_packets=int(row.OutUcastPkts) + int(row.OutNUcastPkts),
                rx_errors=int(row.InErrors),
                tx_errors=int(row.OutErrors),
                rx_discards=int(row.InDiscards),
                tx_discards=int(row.OutDiscards),
            ))
    finally:
        dll.FreeMibTable(ptr)
    return out


# =========================================================================================
# helpers
# =========================================================================================
def clamp_window(value: Any, default: int = DEFAULT_WINDOW_S) -> int:
    """The nearest window we actually keep.  Anything unreadable is the default."""
    try:
        want = int(float(value))
    except (TypeError, ValueError):
        return default
    if want in WINDOWS:
        return want
    if want <= 0:
        return default
    return min(WINDOWS, key=lambda w: (abs(w - want), w))


def step_for(window_s: int, max_points: int = MAX_POINTS) -> int:
    """Seconds per bucket so a window fits in *max_points*.  1 for everything but 30 minutes."""
    window_s = max(1, int(window_s))
    return max(1, int(math.ceil(window_s / float(max(1, max_points)))))


def _type_name(if_type: int) -> str:
    try:
        from .netinfo import IF_TYPE_NAMES

        return IF_TYPE_NAMES.get(if_type, f"Other ({if_type})")
    except Exception:  # noqa: BLE001 - a name is decoration; never let it sink a sample
        return f"Other ({if_type})"


def _bucket(samples: Sequence[Sequence[float]], step_s: int) -> List[List[int]]:
    """Average the per-second samples into *step_s* buckets, oldest first.

    Each sample already covers one second, so a plain mean over the bucket is the bucket's rate;
    a bucket nobody sampled is simply absent, which the chart draws as a gap.
    """
    if step_s <= 1:
        return [[int(s[0]), int(s[1]), int(s[2]), int(s[3]), int(s[4])] for s in samples]
    buckets: "collections.OrderedDict[int, List[float]]" = collections.OrderedDict()
    for s in samples:
        key = int(s[0]) // step_s * step_s
        acc = buckets.get(key)
        if acc is None:
            buckets[key] = acc = [0.0, 0.0, 0.0, 0.0, 0.0]
        acc[0] += float(s[1])
        acc[1] += float(s[2])
        acc[2] += float(s[3])
        acc[3] += float(s[4])
        acc[4] += 1.0
    out: List[List[int]] = []
    for key, acc in buckets.items():
        n = acc[4] or 1.0
        out.append([key, int(round(acc[0] / n)), int(round(acc[1] / n)),
                    int(round(acc[2] / n)), int(round(acc[3] / n))])
    out.sort(key=lambda row: row[0])
    return out


class _Nic:
    """One interface's history and the last raw reading taken from it."""

    __slots__ = ("luid", "index", "name", "description", "if_type", "link_bps", "last", "last_ts",
                 "samples", "seen_ts")

    def __init__(self, c: Counters, ts: float) -> None:
        self.luid = c.luid
        self.index = c.index
        self.name = c.name
        self.description = c.description
        self.if_type = c.if_type
        self.link_bps = c.link_bps
        self.last: Counters = c
        self.last_ts: float = ts
        self.seen_ts: float = ts
        self.samples: Deque[Tuple[int, int, int, int, int]] = collections.deque(maxlen=HISTORY_S)


# =========================================================================================
# monitor
# =========================================================================================
class ThroughputMonitor:
    """Samples every eligible NIC once a second and keeps 30 minutes of it in memory.

    Nothing is written to the database: this is a live view, and a rate that is half an hour old
    is of no interest once it has scrolled off the chart.

    ``reader`` and ``primary_fn`` are the seams the tests drive it through; left alone it reads
    the real interface table and asks :mod:`tnt.netinfo` which NIC carries the default route.
    """

    def __init__(self, bus: Any = None, *, config: Any = None,
                 clock: Optional[Callable[[], float]] = None,
                 reader: Optional[Callable[[], List[Counters]]] = None,
                 primary_fn: Optional[Callable[[], Optional[int]]] = None) -> None:
        self._bus = bus
        self._config = config
        self._clock = clock or time.time
        self._reader = reader or read_counters
        self._primary_fn = primary_fn
        self._lock = threading.Lock()
        self._nics: "collections.OrderedDict[int, _Nic]" = collections.OrderedDict()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._note: Optional[str] = None
        self._primary_lock = threading.Lock()   # its own: _lock is held while the samples are read
        self._primary: Optional[int] = None
        self._primary_ts: float = 0.0

    # -- lifecycle ------------------------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="tnt-throughput", daemon=True)
        self._thread.start()
        log.info("throughput monitor started (%d s of history, %s s windows)", HISTORY_S,
                 "/".join(str(w) for w in WINDOWS))

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        self._thread = None
        if t is not None and t.is_alive():
            t.join(STOP_JOIN_S)

    def _run(self) -> None:
        """One tick a second, aligned to the second so the samples line up with the ping tiles."""
        nxt = math.floor(self._clock()) + 1.0
        while not self._stop.is_set():
            delay = nxt - self._clock()
            if delay > 0:
                if self._stop.wait(delay):
                    break
            try:
                self.tick(nxt)
            except Exception:  # noqa: BLE001 - one bad read must not end the thread
                log.exception("throughput tick failed")
            nxt += 1.0
            if self._clock() > nxt + 2.0:       # fell behind (a busy machine, a resume): realign
                nxt = math.floor(self._clock()) + 1.0

    # -- sampling -------------------------------------------------------------------------
    def tick(self, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Read the counters once and record a sample per NIC.  Returns the event it published.

        None when there is nothing to say: the very first read (no previous reading to subtract)
        or a read that failed.
        """
        now = float(self._clock() if now is None else now)
        try:
            rows = list(self._reader())
            note = None
        except Exception as exc:  # noqa: BLE001
            note = f"{type(exc).__name__}: {exc}"[:200]
            log.debug("reading the interface counters failed", exc_info=True)
            with self._lock:
                self._note = note
            return None
        published = False
        with self._lock:
            self._note = None
            seen = set()
            for c in rows:
                seen.add(c.luid)
                nic = self._nics.get(c.luid)
                if nic is None:
                    # a rate needs two readings: remember this one and start measuring next tick
                    self._nics[c.luid] = _Nic(c, now)
                    continue
                span = now - nic.last_ts
                nic.seen_ts = now
                nic.index, nic.name, nic.description, nic.link_bps = c.index, c.name, c.description, c.link_bps
                if 0 < span <= MAX_SPAN_S:
                    nic.samples.append((
                        int(now),
                        _rate(c.rx_bytes, nic.last.rx_bytes, span, bits=True),
                        _rate(c.tx_bytes, nic.last.tx_bytes, span, bits=True),
                        _rate(c.rx_packets, nic.last.rx_packets, span),
                        _rate(c.tx_packets, nic.last.tx_packets, span),
                    ))
                    published = True
                nic.last, nic.last_ts = c, now
            for luid in [k for k in self._nics if k not in seen]:
                # the adapter went down or away: its history goes with it, so a cable pulled out
                # does not leave a frozen line on the chart
                del self._nics[luid]
        if not published:
            return None
        event = self.latest(now)
        if self._bus is not None:
            try:
                self._bus.publish("throughput.sample", event)
            except Exception:  # noqa: BLE001
                log.exception("publishing throughput.sample failed")
        return event

    # -- views ----------------------------------------------------------------------------
    def latest(self, now: Optional[float] = None) -> Dict[str, Any]:
        """The per-second event: every NIC's current rate and running totals, no series.

        Every eligible NIC is in it, idle ones included - unlike :meth:`view`, which shows only
        what is moving.  The event is the card's *only* live feed, so a NIC that starts carrying
        traffic has to be able to appear in it; letting the card apply the same rule to what
        arrives keeps the decision in one place instead of splitting it across a filter here and
        a refetch there.
        """
        now = float(self._clock() if now is None else now)
        primary = self._primary_luid(now)
        excluded = self._excluded()
        with self._lock:
            nics = [self._row(nic, primary) for nic in self._nics.values()
                    if nic.samples and nic.name.strip().casefold() not in excluded]
        nics.sort(key=_order)
        return {"ts": now, "nics": nics}

    def view(self, window_s: Any = DEFAULT_WINDOW_S) -> Dict[str, Any]:
        """The card's payload: the series for *window_s* plus what it takes to label the chart.

        A NIC is in it when it moved something inside the window, or when it is the one carrying
        the default route - that one is worth a flat line, because a flat line on the internet
        NIC is itself the answer.  If neither applies to anything, every eligible NIC is listed
        rather than none, so the card says "nothing is moving" instead of going blank.
        """
        window_s = clamp_window(window_s)
        step_s = step_for(window_s)
        now = float(self._clock())
        floor_ts = now - window_s
        primary = self._primary_luid(now)
        excluded = self._excluded()
        with self._lock:
            note = self._note
            rows = []
            for nic in self._nics.values():
                if nic.name.strip().casefold() in excluded:
                    continue        # before anything else, so the "nothing moved" fallback cannot bring it back
                window = [s for s in nic.samples if s[0] >= floor_ts]
                rows.append((nic, window, self._row(nic, primary)))
        every: List[Dict[str, Any]] = []
        keep: List[Dict[str, Any]] = []
        for _nic, window, row in rows:
            row["samples"] = _bucket(window, step_s)
            row["avg_rx_bps"] = _mean(window, 1)
            row["avg_tx_bps"] = _mean(window, 2)
            row["peak_rx_bps"] = max((int(s[1]) for s in window), default=0)
            row["peak_tx_bps"] = max((int(s[2]) for s in window), default=0)
            every.append(row)
            if row["primary"] or any(s[1] or s[2] for s in window):
                keep.append(row)
        if not keep:
            keep = every
        keep.sort(key=_order)
        return {"ts": now, "window_s": window_s, "step_s": step_s, "history_s": HISTORY_S,
                "windows": list(WINDOWS), "nics": keep, "note": note}

    # -- internals ------------------------------------------------------------------------
    def _row(self, nic: _Nic, primary: Optional[int]) -> Dict[str, Any]:
        last = nic.samples[-1] if nic.samples else (0, 0, 0, 0, 0)
        return {
            "id": str(nic.luid),
            "index": nic.index,
            "name": nic.name,
            "description": nic.description,
            "type": _type_name(nic.if_type),
            "primary": primary is not None and nic.luid == primary,
            "link_bps": nic.link_bps,
            "rx_bps": int(last[1]),
            "tx_bps": int(last[2]),
            "rx_pps": int(last[3]),
            "tx_pps": int(last[4]),
            "rx_bytes": int(nic.last.rx_bytes),
            "tx_bytes": int(nic.last.tx_bytes),
            "rx_packets": int(nic.last.rx_packets),
            "tx_packets": int(nic.last.tx_packets),
        }

    def _excluded(self) -> "frozenset[str]":
        """The adapter names ``throughput.excluded`` says to leave out, case-folded for comparison.

        Read every time rather than cached: it is a short list behind one lock, and a tick-old
        answer would leave a NIC on the card for a second after its box was unticked.  Anything
        unreadable means **exclude nothing** - a settings read that failed must not blank the card.
        """
        if self._config is None:
            return frozenset()
        try:
            names = self._config.get("throughput.excluded")
        except Exception:  # noqa: BLE001
            log.debug("reading throughput.excluded failed", exc_info=True)
            return frozenset()
        if not isinstance(names, (list, tuple)):
            # a hand-edited config can hold anything here; iterating a bare string would hide every
            # adapter whose name is one letter long, and a number would raise
            return frozenset()
        return frozenset(n.strip().casefold() for n in names if isinstance(n, str) and n.strip())

    def _primary_luid(self, now: float) -> Optional[int]:
        """The LUID of the NIC carrying the default route, remembered for PRIMARY_TTL_S."""
        with self._primary_lock:
            if self._primary_ts and 0 <= now - self._primary_ts < PRIMARY_TTL_S:
                return self._primary
            previous = self._primary
        luid: Optional[int] = None
        try:
            if self._primary_fn is not None:
                luid = self._primary_fn()
            else:
                from . import netinfo

                nic = netinfo.get_internet_nic()
                luid = (int(getattr(nic, "luid", 0)) or None) if nic is not None else None
        except Exception:  # noqa: BLE001 - which NIC is "the" one is decoration, never a failure
            log.debug("looking the internet-facing NIC up failed", exc_info=True)
            luid = previous
        with self._primary_lock:
            self._primary, self._primary_ts = luid, now
        return luid


def _rate(new: int, old: int, span: float, bits: bool = False) -> int:
    """Per-second rate between two counter readings.  A counter that went backwards gives 0.

    Backwards means the adapter reset (a driver reload, a disable/enable).  The traffic between
    the two readings is unknown, and 0 says "nothing measured" rather than inventing a spike out
    of the whole counter.
    """
    delta = int(new) - int(old)
    if delta <= 0 or span <= 0:
        return 0
    if bits:
        delta *= 8
    return int(round(delta / span))


def _mean(samples: Sequence[Sequence[float]], column: int) -> int:
    if not samples:
        return 0
    return int(round(sum(float(s[column]) for s in samples) / len(samples)))


def _order(row: Dict[str, Any]) -> Tuple[int, int, str]:
    """Internet-facing NIC first, then the busiest, then by name - a stable order for the card."""
    busy = int(row.get("rx_bps") or 0) + int(row.get("tx_bps") or 0)
    return (0 if row.get("primary") else 1, -busy, str(row.get("name") or ""))
