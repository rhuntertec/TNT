r"""IEEE 1588 Precision Time Protocol: the clock a pro-audio network runs on (ProAV page, ARCHITECTURE §3.27).

Original code written from IEEE 1588-2008 (PTPv2: the common header of clause 13.3, the Announce, Sync, Follow_Up,
Delay_Req and Delay_Resp bodies of clause 13, the ``clockClass`` / ``clockAccuracy`` / ``timeSource`` enumerations of
clause 7.6 and the EUI-64 ``clockIdentity`` of clause 7.5.2.2), IEEE 1588-2002 (PTPv1: the 40-byte header and the Sync
/ Delay_Req body, which is what classic Dante clocks with) and IEEE 802.1AS (gPTP, the same v2 wire format over
Ethernet).  Every offset below is from those published layouts; nothing is taken from any other implementation.

Why this is the most useful thing on an AV network
--------------------------------------------------
Dante, AES67, SMPTE ST 2110, AVB and Q-LAN all slave their audio clock to PTP, and PTP announces itself continuously
to a multicast group.  Listening to it - joining a group and reading, no probing - answers most of what an integrator
wants to know before touching anything:

* **who the grandmaster is** and what it is locked to (GPS, an atomic clock, or nothing at all);
* **how far away it is**: ``steps_removed`` counts the boundary clocks between it and this PC;
* **whether a switch is doing PTP work**: a non-zero ``correctionField`` means a *transparent* clock timestamped the
  packet in flight, and a parent clock identity that is not the grandmaster's means a *boundary* clock re-served it;
* **whether the clock is stable**: a grandmaster that changes mid-listen is a live election, which is audible;
* **who is following it**: in the usual multicast end-to-end mode every follower's ``Delay_Req`` goes to the same
  group, so simply listening enumerates the clock's participants - gear that answers no mDNS query at all;
* **whether there are two clock trees**: two domains, or PTPv1 and PTPv2 together, is the classic "half the room is
  on the wrong clock" fault.

Nothing here opens a socket, reads a file, logs or looks at the time of day: :func:`parse` is pure, and
:class:`ClockTracker` is fed messages with the timestamp the caller read them at.  :mod:`tnt.proav` does the
listening.

Parsing (:func:`parse`)
-----------------------
``parse(payload)`` takes the PTP message itself (the UDP payload, or the bytes after the 0x88F7 ethertype) and returns
a MESSAGE dict or None.  The version is read from the wire, not guessed: a v2 message has ``versionPTP`` 2 in the low
nibble of octet 1, a v1 message has ``versionPTP`` 1 in the u16 at octet 0.  A message shorter than its body needs, or
of an unknown type, is None.  Reserved and unknown enumeration values keep their number and get no text, never a
guess.

MESSAGE dict (keys in this order, :data:`MESSAGE_KEYS`)::

    {"version": 1|2, "type": str, "domain": int, "domain_text": str, "source": str, "source_mac": str|None,
     "port": int, "sequence": int, "correction_ns": float, "two_step": bool, "unicast": bool,
     "interval_s": float|None, "announce": ANNOUNCE|None, "requesting": str|None, "length": int}

``type`` is one of :data:`MESSAGE_TYPES` ("Sync", "Delay_Req", "Follow_Up", "Delay_Resp", "Announce", "Signaling",
"Management", "Pdelay_Req", "Pdelay_Resp", "Pdelay_Resp_Follow_Up").  ``source`` is the sending port's clock identity
as ``AA:BB:CC:FF:FE:DD:EE:FF`` (v2) or its 6-byte UUID as a MAC (v1); ``source_mac`` is the MAC inside it when the
identity is an EUI-64 built from one (:func:`identity_mac`), which is what lets the vendor be looked up.
``correction_ns`` is the v2 correction field in nanoseconds (it is carried as nanoseconds x 2**16).  ``interval_s`` is
the announced log interval as seconds (2 ** logMessageInterval), None when the message carries none.  ``requesting``
is the requesting port identity of a Delay_Resp, which is what pairs a reply to the follower that asked, and
``parent`` the parent clock a PTPv1 Sync names (None on every other message: PTPv2 puts the same fact in the sending
port identity of the Announce).

ANNOUNCE dict (keys in this order, :data:`ANNOUNCE_KEYS`)::

    {"grandmaster": str, "grandmaster_mac": str|None, "priority1": int, "priority2": int, "clock_class": int,
     "clock_class_text": str|None, "accuracy": int, "accuracy_text": str|None, "variance": int,
     "steps_removed": int, "time_source": int, "time_source_text": str|None, "utc_offset": int|None,
     "leap61": bool, "leap59": bool, "time_traceable": bool, "frequency_traceable": bool, "locked": bool|None}

``locked`` is True for a grandmaster locked to a reference (clock class 6 or 13), False for one that is free-running
or in holdover (7, 14, 52, 58, 187, 193, 248) and None for a class this module has no rule for.  A v1 Sync carries the
same facts in a different shape and is reported through the same dict: ``clock_class`` is the v1 stratum mapped onto
the nearest v2 class, ``time_source`` comes from the four-character grandmaster clock identifier ("GPS ", "ATOM",
"NTP ", "HAND", "DFLT", "INIT") and ``priority2``/``variance``/``accuracy`` are the v1 fields that match.

Tracking (:class:`ClockTracker`)
--------------------------------
:meth:`ClockTracker.add` takes one message's bytes with the timestamp and (optionally) source address it arrived with
and folds it into per-domain state; :meth:`ClockTracker.view` renders that state.  A "domain" here is the pair
(version, domainNumber) - PTPv1's subdomain name and PTPv2's domain number are different things, and seeing both at
once is exactly the fault worth reporting.  The tracker keeps at most :data:`MAX_MASTERS` masters and
:data:`MAX_FOLLOWERS` followers per domain and at most :data:`MAX_DOMAINS` domains; past those, new identities are
counted into ``dropped`` and ignored, so a hostile or broken network cannot grow it without bound.

Intervals and jitter are measured, not read from the announcement: ``sync_s`` is the median gap between Sync messages
from the active master and ``sync_jitter_ms`` the largest deviation from it over the listen (the packet delay
variation a follower has to absorb).  Both are None until :data:`MIN_INTERVAL_SAMPLES` gaps have been seen.

``view()`` shape (keys in this order, :data:`CLOCK_KEYS`, :data:`DOMAIN_KEYS`, :data:`MASTER_KEYS`,
:data:`FOLLOWER_KEYS`)::

    CLOCK   = {"heard", "messages", "dropped", "versions": [1|2], "domains": [DOMAIN], "best": DOMAIN|None,
               "transparent": bool, "first_ts", "last_ts"}
    DOMAIN  = {"version", "domain", "label", "master": MASTER|None, "masters": [MASTER], "followers": [FOLLOWER],
               "messages", "announce_s", "sync_s", "sync_jitter_ms", "correction_ns", "transparent", "changes",
               "first_ts", "last_ts"}
    MASTER  = {"identity", "mac", "vendor", "ip", "priority1", "priority2", "clock_class", "clock_class_text",
               "accuracy", "accuracy_text", "variance", "steps_removed", "time_source", "time_source_text",
               "utc_offset", "leap61", "leap59", "time_traceable", "frequency_traceable", "locked", "two_step",
               "parent", "parent_mac", "parent_vendor", "announce_s", "count", "first_ts", "last_ts"}
    FOLLOWER = {"identity", "mac", "vendor", "ip", "asking": bool, "count", "first_ts", "last_ts"}

``best`` is the domain with the most messages (the one the room is actually running on), and the domains are sorted
that way.  A follower's ``asking`` is True while its Delay_Req is being answered by the master (a Delay_Resp naming it
was seen), which separates a device that is really in the clock tree from one that is only shouting at it.

Module-level seams that tests (and only tests) monkeypatch: ``_vendor_for_mac``.  :mod:`tnt.oui` is imported lazily so
that a stripped install still parses.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["MESSAGE_KEYS", "ANNOUNCE_KEYS", "CLOCK_KEYS", "DOMAIN_KEYS", "MASTER_KEYS", "FOLLOWER_KEYS",
           "MESSAGE_TYPES", "EVENT_PORT", "GENERAL_PORT", "GROUP_V4", "GROUP_V6", "PDELAY_GROUP_V4", "ETHERTYPE",
           "SENDER_KEYS", "CLOCK_CLASS_TEXT", "ACCURACY_TEXT", "TIME_SOURCE_TEXT", "MAX_DOMAINS", "MAX_MASTERS", "MAX_FOLLOWERS",
           "identity_mac", "identity_text", "parse", "ClockTracker"]

MESSAGE_KEYS = ("version", "type", "domain", "domain_text", "source", "source_mac", "port", "sequence",
                "correction_ns", "two_step", "unicast", "interval_s", "announce", "requesting", "parent", "length")
ANNOUNCE_KEYS = ("grandmaster", "grandmaster_mac", "priority1", "priority2", "clock_class", "clock_class_text",
                 "accuracy", "accuracy_text", "variance", "steps_removed", "time_source", "time_source_text",
                 "utc_offset", "leap61", "leap59", "time_traceable", "frequency_traceable", "locked")
CLOCK_KEYS = ("heard", "messages", "dropped", "versions", "domains", "best", "transparent", "first_ts", "last_ts")
DOMAIN_KEYS = ("version", "domain", "label", "master", "masters", "senders", "followers", "messages", "announce_s",
               "sync_s", "sync_jitter_ms", "correction_ns", "transparent", "changes", "first_ts", "last_ts")
MASTER_KEYS = ("identity", "mac", "vendor", "ip", "priority1", "priority2", "clock_class", "clock_class_text",
               "accuracy", "accuracy_text", "variance", "steps_removed", "time_source", "time_source_text",
               "utc_offset", "leap61", "leap59", "time_traceable", "frequency_traceable", "locked", "two_step",
               "parent", "parent_mac", "parent_vendor", "announce_s", "count", "first_ts", "last_ts")
SENDER_KEYS = ("identity", "mac", "vendor", "ip", "role", "count", "first_ts", "last_ts")
FOLLOWER_KEYS = ("identity", "mac", "vendor", "ip", "asking", "count", "first_ts", "last_ts")

#: Where PTP lives.  Event messages (Sync, Delay_Req) go to :data:`EVENT_PORT`, everything else to
#: :data:`GENERAL_PORT`; both to :data:`GROUP_V4` except peer-delay, which uses its own link-local group.
EVENT_PORT = 319
GENERAL_PORT = 320
GROUP_V4 = "224.0.1.129"
GROUP_V6 = "ff0e::181"
PDELAY_GROUP_V4 = "224.0.0.107"
ETHERTYPE = 0x88F7                      # PTP over Ethernet (802.1AS / the L2 mapping of Annex F)

#: PTPv2 message types by the low nibble of octet 0 (IEEE 1588-2008 table 19).
MESSAGE_TYPES: Dict[int, str] = {
    0x0: "Sync", 0x1: "Delay_Req", 0x2: "Pdelay_Req", 0x3: "Pdelay_Resp",
    0x8: "Follow_Up", 0x9: "Delay_Resp", 0xA: "Pdelay_Resp_Follow_Up", 0xB: "Announce",
    0xC: "Signaling", 0xD: "Management",
}
_ANNOUNCE, _SYNC, _DELAY_REQ, _DELAY_RESP, _FOLLOW_UP = "Announce", "Sync", "Delay_Req", "Delay_Resp", "Follow_Up"

#: ``clockClass`` (IEEE 1588-2008 table 5).  A class with no entry keeps its number and gets no text.
CLOCK_CLASS_TEXT: Dict[int, str] = {
    6: "locked to a primary reference (GPS or equivalent)",
    7: "holdover, was locked to a primary reference",
    13: "locked to an application-specific reference",
    14: "holdover, was locked to an application-specific reference",
    52: "holdover out of specification (would not be chosen)",
    58: "holdover out of specification, application-specific",
    187: "holdover out of specification (alternate profile)",
    193: "holdover out of specification, application-specific (alternate profile)",
    248: "free-running: not locked to any reference",
    255: "follower only: never a grandmaster",
}
#: Classes that mean the grandmaster really is locked to something.
LOCKED_CLASSES = (6, 13)
#: ... and the ones that mean it is not (holdover or free-running).  Anything else gives ``locked`` None.
UNLOCKED_CLASSES = (7, 14, 52, 58, 187, 193, 248)

#: ``clockAccuracy`` (IEEE 1588-2008 table 6): how close to the reference the grandmaster claims to be.
ACCURACY_TEXT: Dict[int, str] = {
    0x20: "25 ns", 0x21: "100 ns", 0x22: "250 ns", 0x23: "1 us", 0x24: "2.5 us", 0x25: "10 us", 0x26: "25 us",
    0x27: "100 us", 0x28: "250 us", 0x29: "1 ms", 0x2A: "2.5 ms", 0x2B: "10 ms", 0x2C: "25 ms", 0x2D: "100 ms",
    0x2E: "250 ms", 0x2F: "1 s", 0x30: "10 s", 0x31: "more than 10 s", 0xFE: "unknown",
}
#: ``timeSource`` (IEEE 1588-2008 table 7): what the grandmaster is disciplined by.
TIME_SOURCE_TEXT: Dict[int, str] = {
    0x10: "atomic clock", 0x20: "GPS", 0x30: "terrestrial radio", 0x40: "PTP", 0x50: "NTP", 0x60: "hand set",
    0x90: "other", 0xA0: "internal oscillator",
}
#: The four-character grandmaster clock identifier of a PTPv1 Sync, mapped onto the v2 ``timeSource`` it means.
_V1_IDENTIFIER_SOURCE: Dict[str, int] = {"ATOM": 0x10, "GPS": 0x20, "NTP": 0x50, "HAND": 0x60, "INIT": 0xA0,
                                         "DFLT": 0xA0}
#: PTPv1 clock stratum mapped onto the nearest v2 ``clockClass`` (1588-2002 clause 6.2.3: 1 primary, 2 secondary,
#: 3 a boundary clock's own, 4 the default free-running one).
_V1_STRATUM_CLASS: Dict[int, int] = {0: 6, 1: 6, 2: 7, 3: 13, 4: 248}

# ---------------------------------------------------------------- v2 layout
_V2_HEADER = 34
_V2_ANNOUNCE_BODY = 30                  # originTimestamp(10) .. timeSource(1)
_V2_TIMESTAMP_BODY = 10
_V2_DELAY_RESP_BODY = 20                # receiveTimestamp(10) + requestingPortIdentity(10)
_FLAG_TWO_STEP, _FLAG_UNICAST = 0x02, 0x04                      # flagField octet 0
_FLAG_LEAP61, _FLAG_LEAP59, _FLAG_UTC_VALID = 0x01, 0x02, 0x04  # flagField octet 1
_FLAG_TIME_TRACEABLE, _FLAG_FREQ_TRACEABLE = 0x10, 0x20
_CORRECTION_SCALE = 65536.0             # the correction field is nanoseconds x 2**16
_NO_INTERVAL = 0x7F                     # logMessageInterval of a message that announces none

# ---------------------------------------------------------------- v1 layout
_V1_HEADER = 40
_V1_SYNC_BODY = 84                      # through parentLastSyncSequenceNumber; the fields read below end well before
_V1_CONTROL = {0: _SYNC, 1: _DELAY_REQ, 2: _FOLLOW_UP, 3: _DELAY_RESP, 4: "Management", 5: "Signaling"}
_V1_GM_UUID, _V1_GM_STRATUM, _V1_GM_IDENTIFIER = 54, 67, 68
_V1_GM_VARIANCE, _V1_GM_PRIORITY, _V1_GM_BOUNDARY = 74, 77, 79
_V1_SYNC_INTERVAL, _V1_STEPS_REMOVED, _V1_PARENT_UUID = 83, 90, 102
_V1_UTC_OFFSET = 50

#: Bounds on what one tracker holds, so a broken or hostile network cannot grow it without end.
MAX_DOMAINS = 8
MAX_MASTERS = 16
MAX_FOLLOWERS = 512
MAX_GAPS = 256                          # inter-arrival gaps kept per domain for the interval and jitter figures
MIN_INTERVAL_SAMPLES = 3                # gaps needed before an interval or a jitter figure is reported


def _u16(data: bytes, at: int) -> int:
    return struct.unpack_from(">H", data, at)[0]


def _i16(data: bytes, at: int) -> int:
    return struct.unpack_from(">h", data, at)[0]


def _u32(data: bytes, at: int) -> int:
    return struct.unpack_from(">I", data, at)[0]


def _i64(data: bytes, at: int) -> int:
    return struct.unpack_from(">q", data, at)[0]


def _mac_text(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw)


def identity_text(raw: bytes) -> str:
    """An 8-byte PTPv2 clock identity as ``AA:BB:CC:FF:FE:DD:EE:FF`` (uppercase, the spelling Wireshark uses)."""
    return ":".join(f"{b:02X}" for b in raw)


def identity_mac(identity: bytes) -> Optional[str]:
    """The MAC inside an EUI-64 clock identity, or None when it was not built from one.

    IEEE 1588-2008 clause 7.5.2.2 builds a clock identity from a 48-bit MAC by inserting ``FF FE`` (the EUI-64
    encapsulation) or ``FF FF`` (the older EUI-48 one) in the middle.  Anything else is a clock identity the device
    made up, and there is no MAC to report."""
    if len(identity) != 8 or identity[3:5] not in (b"\xff\xfe", b"\xff\xff"):
        return None
    return _mac_text(identity[0:3] + identity[5:8])


def _vendor_for_mac(mac: Optional[str]) -> Optional[str]:
    """The OUI vendor of a MAC, or None.  A seam: imported lazily so a stripped install still parses PTP."""
    if not mac:
        return None
    try:
        from . import oui
    except Exception:       # noqa: BLE001 - vendor text is an extra, never a reason to lose the clock reading
        return None
    try:
        return oui.vendor_for_mac(mac)
    except Exception:       # noqa: BLE001
        return None


def _interval_s(raw: int) -> Optional[float]:
    """``logMessageInterval`` (a signed power of two) as seconds, or None when the message announces none."""
    if raw == _NO_INTERVAL:
        return None
    value = raw - 256 if raw > 127 else raw
    if not -8 <= value <= 8:            # outside this a device is announcing nonsense; report nothing rather than 0.0
        return None
    return float(2 ** value) if value >= 0 else 1.0 / float(2 ** -value)


def _clock_class_fields(clock_class: int) -> Tuple[Optional[str], Optional[bool]]:
    text = CLOCK_CLASS_TEXT.get(clock_class)
    if clock_class in LOCKED_CLASSES:
        return text, True
    if clock_class in UNLOCKED_CLASSES:
        return text, False
    return text, None


def _announce_dict(grandmaster: bytes, priority1: int, priority2: int, clock_class: int, accuracy: int,
                   variance: int, steps_removed: int, time_source: int, utc_offset: Optional[int],
                   flags: int) -> Dict[str, Any]:
    class_text, locked = _clock_class_fields(clock_class)
    return {
        "grandmaster": identity_text(grandmaster),
        "grandmaster_mac": identity_mac(grandmaster),
        "priority1": priority1,
        "priority2": priority2,
        "clock_class": clock_class,
        "clock_class_text": class_text,
        "accuracy": accuracy,
        "accuracy_text": ACCURACY_TEXT.get(accuracy),
        "variance": variance,
        "steps_removed": steps_removed,
        "time_source": time_source,
        "time_source_text": TIME_SOURCE_TEXT.get(time_source),
        "utc_offset": utc_offset,
        "leap61": bool(flags & _FLAG_LEAP61),
        "leap59": bool(flags & _FLAG_LEAP59),
        "time_traceable": bool(flags & _FLAG_TIME_TRACEABLE),
        "frequency_traceable": bool(flags & _FLAG_FREQ_TRACEABLE),
        "locked": locked,
    }


def _parse_v2(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < _V2_HEADER:
        return None
    kind = MESSAGE_TYPES.get(data[0] & 0x0F)
    if kind is None:
        return None
    flags_hi, flags_lo = data[6], data[7]
    source = data[20:28]
    message: Dict[str, Any] = {
        "version": 2,
        "type": kind,
        "domain": data[4],
        "domain_text": f"domain {data[4]}",
        "source": identity_text(source),
        "source_mac": identity_mac(source),
        "port": _u16(data, 28),
        "sequence": _u16(data, 30),
        "correction_ns": _i64(data, 8) / _CORRECTION_SCALE,
        "two_step": bool(flags_hi & _FLAG_TWO_STEP),
        "unicast": bool(flags_hi & _FLAG_UNICAST),
        "interval_s": _interval_s(data[33]),
        "announce": None,
        "requesting": None,
        "parent": None,
        "length": len(data),
    }
    if kind == _ANNOUNCE:
        if len(data) < _V2_HEADER + _V2_ANNOUNCE_BODY:
            return None
        at = _V2_HEADER
        utc_offset = _i16(data, at + 10) if flags_lo & _FLAG_UTC_VALID else None
        message["announce"] = _announce_dict(
            grandmaster=data[at + 19:at + 27], priority1=data[at + 13], priority2=data[at + 18],
            clock_class=data[at + 14], accuracy=data[at + 15], variance=_u16(data, at + 16),
            steps_removed=_u16(data, at + 27), time_source=data[at + 29], utc_offset=utc_offset, flags=flags_lo)
    elif kind == _DELAY_RESP:
        if len(data) < _V2_HEADER + _V2_DELAY_RESP_BODY:
            return None
        message["requesting"] = identity_text(data[_V2_HEADER + 10:_V2_HEADER + 18])
    elif kind in (_SYNC, _DELAY_REQ, _FOLLOW_UP) and len(data) < _V2_HEADER + _V2_TIMESTAMP_BODY:
        return None
    return message


def _v1_text(raw: bytes) -> str:
    """A fixed-width PTPv1 character field as text: NULs and trailing blanks removed, non-ASCII dropped."""
    return "".join(chr(b) for b in raw if 32 <= b < 127).strip()


def _parse_v1(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < _V1_HEADER:
        return None
    kind = _V1_CONTROL.get(data[32])
    if kind is None:
        return None
    subdomain = _v1_text(data[4:20])
    source = data[22:28]
    flags = _u16(data, 34)
    message: Dict[str, Any] = {
        "version": 1,
        "type": kind,
        "domain": 0,                                # v1 names its subdomain instead of numbering it
        "domain_text": f"subdomain {subdomain}" if subdomain else "subdomain (unnamed)",
        "source": _mac_text(source),
        "source_mac": _mac_text(source),
        "port": _u16(data, 28),
        "sequence": _u16(data, 30),
        "correction_ns": 0.0,                       # PTPv1 has no correction field: there are no transparent clocks
        "two_step": True,                           # v1 is always two-step (Sync is followed by a Follow_Up)
        "unicast": False,
        "interval_s": None,
        "announce": None,
        "requesting": None,
        "parent": None,
        "length": len(data),
    }
    if kind == _SYNC and len(data) >= _V1_SYNC_BODY:
        stratum = data[_V1_GM_STRATUM]
        identifier = _v1_text(data[_V1_GM_IDENTIFIER:_V1_GM_IDENTIFIER + 4])
        interval = data[_V1_SYNC_INTERVAL]
        message["interval_s"] = _interval_s(interval)
        gm_mac = data[_V1_GM_UUID:_V1_GM_UUID + 6]
        announce = _announce_dict(
            grandmaster=gm_mac, priority1=data[_V1_GM_PRIORITY], priority2=data[_V1_GM_BOUNDARY],
            clock_class=_V1_STRATUM_CLASS.get(stratum, 248), accuracy=0xFE,
            variance=_u16(data, _V1_GM_VARIANCE), steps_removed=_u16(data, _V1_STEPS_REMOVED),
            time_source=_V1_IDENTIFIER_SOURCE.get(identifier, 0xA0), utc_offset=_i16(data, _V1_UTC_OFFSET),
            flags=0)
        # a v1 grandmaster is named by a 6-byte UUID, which is a MAC: report it as one rather than as an EUI-64
        announce["grandmaster"] = _mac_text(gm_mac)
        announce["grandmaster_mac"] = _mac_text(gm_mac)
        message["announce"] = announce
        message["parent"] = _mac_text(data[_V1_PARENT_UUID:_V1_PARENT_UUID + 6])
    return message


def parse(payload: bytes) -> Optional[Dict[str, Any]]:
    """One PTP message (the UDP payload, or the bytes after the 0x88F7 ethertype) as a MESSAGE dict, or None.

    None means "this is not a PTP message this module reads": too short, a version other than 1 or 2, an unknown
    message type, or a body shorter than the type needs.  Never raises."""
    data = bytes(payload)
    if len(data) < 2:
        return None
    try:
        if data[1] & 0x0F == 2:
            return _parse_v2(data)
        if _u16(data, 0) == 1:
            return _parse_v1(data)
    except (struct.error, IndexError, ValueError):
        return None
    return None


def _median(values: List[float]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


class _Domain:
    """One (version, domainNumber) clock tree's running state."""

    def __init__(self, version: int, domain: int, label: str, ts: float) -> None:
        self.version, self.domain, self.label = version, domain, label
        self.messages = 0
        self.changes = 0                            # times the active grandmaster identity changed
        self.first_ts = self.last_ts = ts
        self.masters: Dict[str, Dict[str, Any]] = {}      # grandmasters, keyed by the identity an Announce named
        self.senders: Dict[str, Dict[str, Any]] = {}      # the ports that sent them: the GM itself, or a boundary clock
        self.followers: Dict[str, Dict[str, Any]] = {}
        self.active: Optional[str] = None           # the identity of the master whose Sync is arriving
        self.correction_ns = 0.0                    # the largest correction seen: a transparent clock's residence time
        self.transparent = False
        self._sync_gaps: List[float] = []
        self._announce_gaps: List[float] = []
        self._last_sync_ts: Optional[float] = None
        self._last_announce_ts: Optional[float] = None
        self.dropped = 0

    # -------------------------------------------------------- folding messages in
    def master(self, identity: str, ts: float) -> Optional[Dict[str, Any]]:
        row = self.masters.get(identity)
        if row is None:
            if len(self.masters) >= MAX_MASTERS:
                self.dropped += 1
                return None
            mac = None
            row = {"identity": identity, "mac": mac, "vendor": None, "ip": None, "priority1": None, "priority2": None,
                   "clock_class": None, "clock_class_text": None, "accuracy": None, "accuracy_text": None,
                   "variance": None, "steps_removed": None, "time_source": None, "time_source_text": None,
                   "utc_offset": None, "leap61": False, "leap59": False, "time_traceable": False,
                   "frequency_traceable": False, "locked": None, "two_step": None, "parent": None,
                   "parent_mac": None, "parent_vendor": None, "announce_s": None, "count": 0,
                   "first_ts": ts, "last_ts": ts}
            self.masters[identity] = row
        return row

    def sender(self, identity: str, mac: Optional[str], ts: float, ip: Optional[str] = None,
               role: str = "master") -> Optional[Dict[str, Any]]:
        """The port a Sync or Announce came *from*, which is the grandmaster only when it is one hop away."""
        row = self.senders.get(identity)
        if row is None:
            if len(self.senders) >= MAX_MASTERS:
                self.dropped += 1
                return None
            row = {"identity": identity, "mac": mac, "vendor": _vendor_for_mac(mac), "ip": ip, "role": role,
                   "count": 0, "first_ts": ts, "last_ts": ts}
            self.senders[identity] = row
        row["count"] += 1
        row["last_ts"] = ts
        if ip and not row["ip"]:
            row["ip"] = ip
        if mac and not row["mac"]:
            row["mac"] = mac
            row["vendor"] = _vendor_for_mac(mac)
        if role == "boundary":
            row["role"] = role
        return row

    def follower(self, identity: str, ts: float) -> Optional[Dict[str, Any]]:
        row = self.followers.get(identity)
        if row is None:
            if len(self.followers) >= MAX_FOLLOWERS:
                self.dropped += 1
                return None
            row = {"identity": identity, "mac": None, "vendor": None, "ip": None, "asking": False, "count": 0,
                   "first_ts": ts, "last_ts": ts}
            self.followers[identity] = row
        return row

    def note_sync(self, ts: float) -> None:
        if self._last_sync_ts is not None:
            gap = ts - self._last_sync_ts
            if 0.0 < gap < 60.0:
                self._sync_gaps.append(gap)
                if len(self._sync_gaps) > MAX_GAPS:
                    del self._sync_gaps[0]
        self._last_sync_ts = ts

    def note_announce(self, ts: float) -> None:
        if self._last_announce_ts is not None:
            gap = ts - self._last_announce_ts
            if 0.0 < gap < 120.0:
                self._announce_gaps.append(gap)
                if len(self._announce_gaps) > MAX_GAPS:
                    del self._announce_gaps[0]
        self._last_announce_ts = ts

    def set_active(self, identity: str) -> None:
        if self.active is not None and self.active != identity:
            self.changes += 1
        self.active = identity

    # -------------------------------------------------------- rendering
    def sync_s(self) -> Optional[float]:
        return _median(self._sync_gaps) if len(self._sync_gaps) >= MIN_INTERVAL_SAMPLES else None

    def announce_s(self) -> Optional[float]:
        return _median(self._announce_gaps) if len(self._announce_gaps) >= MIN_INTERVAL_SAMPLES else None

    def sync_jitter_ms(self) -> Optional[float]:
        nominal = self.sync_s()
        if nominal is None or nominal <= 0:
            return None
        return round(max(abs(gap - nominal) for gap in self._sync_gaps) * 1000.0, 3)

    def view(self) -> Dict[str, Any]:
        masters = sorted(self.masters.values(), key=lambda m: (-m["count"], m["identity"]))
        followers = sorted(self.followers.values(), key=lambda f: (not f["asking"], -f["count"], f["identity"]))
        active = self.masters.get(self.active or "")
        if active is None and masters:
            active = masters[0]
        senders = sorted(self.senders.values(), key=lambda s: (-s["count"], s["identity"]))
        for row in senders:     # a sender is the grandmaster itself only when it is the one being announced
            row["role"] = "grandmaster" if row["identity"] == (self.active or "") else "boundary"
        return {
            "version": self.version,
            "domain": self.domain,
            "label": self.label,
            "master": active,
            "masters": masters,
            "senders": senders,
            "followers": followers,
            "messages": self.messages,
            "announce_s": self.announce_s(),
            "sync_s": self.sync_s(),
            "sync_jitter_ms": self.sync_jitter_ms(),
            "correction_ns": round(self.correction_ns, 3) if self.transparent else None,
            "transparent": self.transparent,
            "changes": self.changes,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
        }


class ClockTracker:
    """Folds PTP messages into per-domain clock state.  Pure: every timestamp is the caller's."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._domains: Dict[Tuple[int, int], _Domain] = {}
        self.messages = 0
        self.dropped = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None

    @property
    def heard(self) -> bool:
        return self.messages > 0

    def add(self, payload: bytes, ts: float, *, src_ip: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Fold one message in and return it as a MESSAGE dict (None when it is not PTP this module reads)."""
        message = parse(payload)
        if message is None:
            return None
        key = (message["version"], message["domain"])
        domain = self._domains.get(key)
        if domain is None:
            if len(self._domains) >= MAX_DOMAINS:
                self.dropped += 1
                return message
            domain = _Domain(message["version"], message["domain"], message["domain_text"], ts)
            self._domains[key] = domain
        self.messages += 1
        domain.messages += 1
        domain.last_ts = ts
        self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        correction = abs(float(message["correction_ns"]))
        if correction > 0.0:
            domain.transparent = True
            domain.correction_ns = max(domain.correction_ns, correction)
        kind = message["type"]
        if kind == _ANNOUNCE:
            self._add_announce(domain, message, ts, src_ip)
        elif kind == _SYNC:
            self._add_sync(domain, message, ts, src_ip)
        elif kind in (_DELAY_REQ, "Pdelay_Req"):
            self._add_follower(domain, message["source"], message["source_mac"], ts, src_ip)
        elif kind == _DELAY_RESP:
            self._add_delay_resp(domain, message, ts)
        elif kind == _FOLLOW_UP:
            row = domain.master(message["source"], ts)
            if row is not None:
                row["last_ts"] = ts
        return message

    def _add_announce(self, domain: "_Domain", message: Dict[str, Any], ts: float, src_ip: Optional[str]) -> None:
        """An Announce names a *grandmaster*, which may be several hops away; the packet came from whatever port
        last served the domain.  Those are two different devices whenever a boundary clock is in the path, so the
        grandmaster's row never takes the sender's address."""
        announce = message["announce"]
        if not announce:
            return
        identity = announce["grandmaster"]
        row = domain.master(identity, ts)
        if row is None:
            return
        domain.set_active(identity)
        domain.note_announce(ts)
        row["count"] += 1
        row["last_ts"] = ts
        row["mac"] = announce["grandmaster_mac"]
        row["vendor"] = _vendor_for_mac(row["mac"])
        row["two_step"] = message["two_step"]
        row["announce_s"] = message["interval_s"] or domain.announce_s()
        for key in ("priority1", "priority2", "clock_class", "clock_class_text", "accuracy", "accuracy_text",
                    "variance", "steps_removed", "time_source", "time_source_text", "utc_offset", "leap61",
                    "leap59", "time_traceable", "frequency_traceable", "locked"):
            row[key] = announce[key]
        sender = message["source"]
        domain.sender(sender, message["source_mac"], ts, src_ip)
        if sender == identity:
            if src_ip:
                row["ip"] = src_ip          # the grandmaster is one hop away: this really is its address
        else:
            row["parent"] = sender
            row["parent_mac"] = message["source_mac"]
            row["parent_vendor"] = _vendor_for_mac(message["source_mac"])

    def _add_sync(self, domain: "_Domain", message: Dict[str, Any], ts: float, src_ip: Optional[str]) -> None:
        domain.note_sync(ts)
        identity = message["source"]
        announce = message.get("announce")
        if announce and message["version"] == 1:
            # PTPv1 has no Announce: the Sync carries the grandmaster's facts as well as the clock tick
            domain.note_announce(ts)
            domain.sender(identity, message["source_mac"], ts, src_ip)
            gm = announce["grandmaster"]
            gm_row = domain.master(gm, ts)
            if gm_row is None:
                return
            domain.set_active(gm)
            gm_row["count"] += 1
            gm_row["last_ts"] = ts
            gm_row["mac"] = announce["grandmaster_mac"]
            gm_row["vendor"] = _vendor_for_mac(gm_row["mac"])
            gm_row["announce_s"] = message["interval_s"]
            gm_row["two_step"] = message["two_step"]
            for key in ("priority1", "priority2", "clock_class", "clock_class_text", "accuracy", "accuracy_text",
                        "variance", "steps_removed", "time_source", "time_source_text", "utc_offset", "leap61",
                        "leap59", "time_traceable", "frequency_traceable", "locked"):
                gm_row[key] = announce[key]
            if gm == identity:
                if src_ip:
                    gm_row["ip"] = src_ip
            else:
                parent = message.get("parent") or identity
                gm_row["parent"] = parent
                gm_row["parent_mac"] = parent if parent == identity else None
                gm_row["parent_vendor"] = _vendor_for_mac(gm_row["parent_mac"])
            return
        domain.sender(identity, message["source_mac"], ts, src_ip)

    def _add_follower(self, domain: "_Domain", identity: str, mac: Optional[str], ts: float,
                      src_ip: Optional[str]) -> None:
        if identity in domain.masters or identity in domain.senders:
            return                              # a master asking its own upstream is not a follower of this tree
        row = domain.follower(identity, ts)
        if row is None:
            return
        row["count"] += 1
        row["last_ts"] = ts
        if mac and not row["mac"]:
            row["mac"] = mac
            row["vendor"] = _vendor_for_mac(mac)
        if src_ip and not row["ip"]:
            row["ip"] = src_ip

    def _add_delay_resp(self, domain: "_Domain", message: Dict[str, Any], ts: float) -> None:
        asked = message["requesting"]
        if not asked:
            return
        row = domain.followers.get(asked)
        if row is None:
            row = domain.follower(asked, ts)
            if row is None:
                return
            row["mac"] = identity_mac(bytes.fromhex(asked.replace(":", ""))) if len(asked) == 23 else None
            row["vendor"] = _vendor_for_mac(row["mac"])
        row["asking"] = True                    # the master is answering it: it really is in this clock tree
        row["last_ts"] = ts

    def view(self) -> Dict[str, Any]:
        """The CLOCK dict: every domain heard, richest first."""
        domains = sorted((d.view() for d in self._domains.values()),
                         key=lambda d: (-d["messages"], d["version"], d["domain"]))
        versions = sorted({d["version"] for d in domains})
        dropped = self.dropped + sum(d.dropped for d in self._domains.values())
        return {
            "heard": self.messages > 0,
            "messages": self.messages,
            "dropped": dropped,
            "versions": versions,
            "domains": domains,
            "best": domains[0] if domains else None,
            "transparent": any(d["transparent"] for d in domains),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
        }
