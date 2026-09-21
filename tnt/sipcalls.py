r"""SIP call reconstruction and RTP audio rebuilding for the Packet Capture screen's "SIP Flows" (ARCHITECTURE §3.24).

Original code written from RFC 3261 (SIP), RFC 3264 and RFC 4566 (SDP, the offer/answer media description), RFC 3550
(RTP and RTCP) and RFC 3551 (the RTP/AVP profile and its static payload types), with the two G.711 companding laws
taken from ITU-T G.711 (A-law and mu-law, clause 2 and its segment/interval encoding) and the RIFF/WAVE container from
the Microsoft Multimedia Programming Interface (WAVE_FORMAT_PCM). Every function is pure: nothing here opens a socket,
runs a program, reads or writes a file, or sleeps. Untrusted bytes reach every parser, so no parser raises: a malformed
message, packet or body is None or a partial result, and every length read out of a packet is bounds-checked and
capped.

SIP (:func:`parse_sip`, :func:`is_sip`)
---------------------------------------
:func:`is_sip` is the cheap sniff a capture loop can afford on every UDP payload: the first 16 bytes start either with
``SIP/2.0 `` or with one of :data:`SIP_METHODS` followed by a space. :func:`parse_sip` then parses a whole datagram of
at most :data:`MAX_MESSAGE` bytes: a start line, folded headers (a line starting with a space or a tab continues the
one before it), a blank line and a body. Header names are case-insensitive and the compact forms ``i f t m v c l s k
o`` are accepted as Call-ID, From, To, Contact, Via, Content-Type, Content-Length, Subject, Supported and Event. A
request needs a known method, a request URI and ``SIP/2.0``; a response needs a three-digit status of 100..699. Only
the first of each header is read.

SIP dict (keys in this order, :data:`SIP_KEYS`)::

    {"kind": "request"|"response", "method": str|None, "status": int|None, "reason": str|None, "uri": str|None,
     "call_id": str|None, "from_uri": str|None, "from_tag": str|None, "to_uri": str|None, "to_tag": str|None,
     "cseq": int|None, "cseq_method": str|None, "via_branch": str|None, "contact": str|None,
     "user_agent": str|None, "content_type": str|None, "sdp": SDP|None}

``method``, ``uri`` are a request's; ``status``, ``reason`` a response's. A URI is what stands between ``<`` and ``>``,
else the value up to the first ``;``; ``from_tag`` / ``to_tag`` are the ``tag`` parameter after it. ``via_branch`` is
the ``branch`` parameter of the first Via. ``sdp`` is :func:`parse_sdp` of the body when Content-Type is
``application/sdp`` (or when there is no Content-Type and the body starts with ``v=``), else None. Text is decoded as
UTF-8 with ``errors="replace"`` and capped at :data:`MAX_TEXT` characters.

SDP (:func:`parse_sdp`)
-----------------------
``<letter>=<value>`` lines, CRLF or LF, at most :data:`MAX_SDP_LINES` of them. A body without a ``v=`` line is not SDP
(None)::

    {"session": str|None, "connection": str|None, "media": [MEDIA, ...]}          :data:`SDP_KEYS`
    {"type": str, "port": int, "proto": str, "formats": [int, ...], "rtpmap": {int: str},
     "direction": str, "connection": str|None}                                    :data:`MEDIA_KEYS`

``session`` is the ``s=`` name and ``connection`` the session-level ``c=`` address (the third token, a multicast
``/ttl/count`` suffix removed). A ``m=<type> <port> <proto> <fmt> ...`` line starts a media section, at most
:data:`MAX_MEDIA` of them; an ``m=`` line of fewer than three tokens starts a section this module cannot read, and
every line after it is dropped with that section rather than read as the section before it (RFC 4566 §5.14 puts
everything after an ``m=`` line at media level). ``port`` is the number before an optional ``/count`` when it is
0..65535 else 0, ``formats`` the numeric payload types (at most :data:`MAX_FORMATS`), ``rtpmap`` the section's
``a=rtpmap:<pt> <name>`` entries as ``{0: "PCMU/8000"}``, ``direction`` its ``a=sendrecv|sendonly|recvonly|inactive``
(else the session-level one, else ``"sendrecv"``) and ``connection`` its own ``c=`` address, else the session's.

RTP (:func:`parse_rtp`, :func:`looks_like_rtp`)
-----------------------------------------------
:func:`looks_like_rtp` checks only that 12 bytes are there, that the version is 2, that the CSRC list fits and that the
payload type is outside 64..95 (where RTCP's packet types sit on a shared port). :func:`parse_rtp` validates the whole
fixed header, the ``csrc_count`` 32-bit CSRCs, an extension header (``profile``, a 16-bit word count, then that many
words) and the padding count in the last byte, and returns None when any of them runs past the packet::

    {"version": 2, "padding": bool, "extension": bool, "csrc_count": int, "marker": bool, "payload_type": int,
     "seq": int, "ts": int, "ssrc": int, "payload": bytes}                        :data:`RTP_KEYS`

``payload`` is what is left between the header (CSRCs and extension included) and the padding.

Codecs (:func:`ulaw_to_pcm16`, :func:`alaw_to_pcm16`, :func:`decodable`)
------------------------------------------------------------------------
:data:`PAYLOAD_TYPES` maps an RFC 3551 static payload type to ``(name, clock rate, channels)`` for the audio types
(0..18); the dynamic types (96..127) are named by an SDP ``rtpmap`` instead. :data:`DECODABLE` is what this module can
actually turn into audio: ``(0, 8)``, G.711 mu-law (PCMU) and A-law (PCMA). Both decoders are table driven: a 256-entry
table is built once at import from the G.711 definition (sign, 3-bit segment, 4-bit interval; mu-law bytes are stored
inverted and A-law bytes with every other bit inverted, ``^ 0x55``), and each byte becomes one 16-bit little-endian
sample. The sample count therefore equals the payload length, which is what the rebuilder counts in.

WAV (:func:`build_wav`)
-----------------------
A canonical 44-byte RIFF/WAVE header (``fmt `` chunk of 16 bytes, format 1, 16 bits) followed by the samples, which a
browser ``<audio>`` plays as it stands. The data is trimmed to whole sample frames and to :data:`MAX_WAV_DATA` bytes.
A *rate* outside 1..192000 or *channels* outside 1..2 raises ``ValueError("a WAV needs a rate of 1..192000 Hz and 1 or
2 channels")`` - the only error any function here raises for the data it is given.

Tracking (:class:`CallTracker`)
-------------------------------
Feed every SIP message (:meth:`~CallTracker.add_sip`) and every RTP packet (:meth:`~CallTracker.add_rtp`) of a capture
in arrival order, with the IP addresses and ports of the packet that carried it. Calls are keyed by Call-ID and start
at an INVITE; :meth:`~CallTracker.add_sip` returns the call's ``id`` when the message created the call or changed its
state (so the caller can raise its "call found" notification once), else None::

    {"id": str, "call_id": str, "from_uri": str|None, "to_uri": str|None, "state": str, "start_ts": float,
     "answer_ts": float|None, "end_ts": float|None, "duration_s": float, "status": int|None,
     "messages": [MESSAGE, ...], "streams": [STREAM, ...], "note": str|None}      :data:`CALL_KEYS`
    {"ts": float, "kind": str|None, "method": str|None, "status": int|None, "reason": str|None, "src": str,
     "dst": str, "cseq": int|None, "cseq_method": str|None, "via_branch": str|None, "contact": str|None,
     "user_agent": str|None, "has_sdp": bool, "sdp_c": str|None, "where": Any,
     "side": Any}                                                                 :data:`MESSAGE_KEYS`
    {"id": str, "src": str, "sport": int, "dst": str, "dport": int, "ssrc": int, "payload_type": int, "codec": str,
     "packets": int, "lost": int, "out_of_order": int, "first_ts": float, "last_ts": float, "duration_s": float,
     "bytes": int, "jitter_ms": float|None, "decodable": bool}                    :data:`STREAM_KEYS`
    {"calls": int, "streams": int, "sip_messages": int, "rtp_packets": int, "dropped": int}  :data:`STATS_KEYS`

``state`` is one of :data:`CALL_STATES`: an INVITE opens a call ``"calling"``, a 180 or 183 to it makes it
``"ringing"``, a 2xx ``"answered"`` (with ``answer_ts``), a BYE ``"ended"``, a CANCEL ``"cancelled"`` and a 4xx/5xx/6xx
final response ``"failed"``, all with ``end_ts``. ``status`` is the last response of 200 or more to the INVITE, so a
cancelled call keeps its state and still records the 487. A newer INVITE (a higher CSeq on the same Call-ID from
the same sender) on a ``"failed"`` call that was never answered reopens it ``"calling"``, with ``end_ts`` and
``status`` cleared: that is the retry with credentials RFC 3261 22.2 sends after a 401 or 407, the normal start of a
call through an authenticating PBX or trunk. A response to an INVITE older than the newest one from the end it was
sent to is ignored, so a late copy of the challenge cannot fail the retry; the CSeq is kept per sender because each
end numbers its own requests, and a callee's re-INVITE must not make the caller's look old. A challenge nobody
retried leaves the call ``"failed"`` with its 401 or 407. ``duration_s`` runs from ``answer_ts`` (else ``start_ts``)
to ``end_ts`` (else the last message or RTP packet seen) and is rounded to milliseconds. ``id`` is a URL-safe slug of
the Call-ID: everything outside ``A-Za-z0-9-_`` becomes ``-``, runs of ``-`` collapse, the result is capped at
:data:`MAX_ID_TEXT` characters and a short SHA-256 of the Call-ID is appended, so it can never hold ``/``, ``\`` or
``..`` and two Call-IDs never share one. ``note`` says why a call has no audio (no RTP seen, or a codec that cannot be
rebuilt), else None.

:meth:`~CallTracker.expected_rtp` is the set of ``(ip, port)`` pairs learned from every SDP offer and answer (the
media-level ``c=``, else the session's, else the address the message came from when it is missing or a wildcard), so a
capture loop can decide with one set lookup that a UDP packet is worth parsing. A stream belongs to a call when either
of its ends is one of that call's pairs.

Audio (:meth:`~CallTracker.audio`, :meth:`~CallTracker.call_audio`)
--------------------------------------------------------------------
A stream is rebuilt in RTP timestamp order, not arrival order: each packet's timestamp is unwrapped by adding the
signed 32-bit difference from the packet before it (RFC 3550's comparison), which survives the 32-bit wrap, and the
packets are then sorted by that position. A repeated ``(position, sequence)`` is a duplicate and is dropped. Where the
position runs ahead of what has been written, the hole is filled with silence, at most :data:`MAX_GAP_SECONDS` of it
per hole so that one bad timestamp cannot allocate hundreds of megabytes; where it runs behind, the overlapping
samples at the front of the payload are dropped instead. The total is capped at ``max_seconds`` (itself capped at
:data:`MAX_SECONDS`). :meth:`~CallTracker.call_audio` mixes a call's streams (at most :data:`MAX_MIXED_STREAMS`, and
only those sharing one clock rate) into one mono WAV by adding them sample for sample with clipping at ±32767, each
offset by its own first arrival time relative to the earliest.

Memory
------
``max_stream_packets`` payloads are kept per stream and ``max_messages`` messages per call; past that, and past
:data:`MAX_STORED_BYTES` over all streams, nothing more is stored and the item counts into ``dropped`` (which counts
what was refused, never what was parsed). A kept frame is charged its payload plus :data:`FRAME_OVERHEAD`, what the
tuple, the ``bytes`` object, the two timestamps and the list slot around that payload cost on top of it, so the cap
bounds the memory the tracker really holds and not merely the payload inside it. A new stream past ``max_streams`` is
refused the same way. A new call past ``max_calls`` makes room by forgetting the oldest call, which does not count as
a drop and which also drops the streams that were only that call's, giving their stored bytes back. ``packets``,
``lost``, ``out_of_order`` and ``bytes`` keep counting after a stream is full.

Contract gaps filled here (documented as required):

* ``lost`` is RFC 3550's expected minus received: each forward sequence gap of at most :data:`MAX_SEQ_GAP` packets
  counts the packets it skipped (a larger jump reads as a restarted stream, not as loss), and a late packet that fills
  one of those holes takes its count back off, the 16-bit sequence wrap included. ``out_of_order`` counts those late
  arrivals. A duplicate (a sequence already received) is neither, and neither is a packet older than the first one
  the stream saw; a duplicate is dropped only when the audio is rebuilt.
* ``jitter_ms`` needs the RTP clock rate: :data:`PAYLOAD_TYPES` for a static type, else the rate the SDP ``rtpmap``
  of either end gives the dynamic one (``opus/48000/2`` is 48 kHz), capped at :data:`MAX_CLOCK_RATE`. Without either
  it is None - a dynamic number means nothing on its own, and a guess could report jitter in the wrong scale. It is
  None as well when the rate arrived late and the estimator saw fewer than :data:`MIN_JITTER_STEPS` steps of a
  longer stream: a few steps from zero read as smooth whatever the audio did.
* Streams are keyed by ``(src, sport, dst, dport, ssrc)``, so the two directions of a call are two streams. A stream's
  ``payload_type`` is the first one seen on that SSRC and only packets carrying it are rebuilt, which keeps
  ``telephone-event`` (RFC 4733) and comfort noise out of the audio without losing the packet counts.
* ``codec`` is the :data:`PAYLOAD_TYPES` name, else the name from the SDP ``rtpmap`` of either end, else ``"PT <n>"``.
* A stream whose ends match no call's media is still tracked and still reachable through :meth:`~CallTracker.stream`;
  it simply appears in no call. A call lists at most :data:`MAX_STREAMS_PER_CALL` streams, oldest first.
* A 3xx redirect to the INVITE records its ``status`` and leaves the state alone: the call carries on at the contact
  the redirect names, under a new Call-ID this tracker sees as a call of its own.
* :meth:`~CallTracker.call` and :meth:`~CallTracker.call_audio` take either the Call-ID or the ``id`` slug.
* ``max_calls``, ``max_streams``, ``max_stream_packets`` and ``max_messages`` are clamped to at least 1.
* A message without a Call-ID, a message that is not an INVITE for a call that does not exist yet, an RTP dict without
  the fields it needs and a timestamp that is not a finite number (a bool, a NaN, an infinity and a number too large
  for a float are none of them) are all ignored (still counted into ``sip_messages`` / ``rtp_packets`` when the
  argument was a dict).
"""
from __future__ import annotations

import hashlib
import math
import operator
import struct
import sys
from array import array
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

__all__ = ["SIP_KEYS", "SDP_KEYS", "MEDIA_KEYS", "RTP_KEYS", "STREAM_KEYS", "CALL_KEYS", "MESSAGE_KEYS", "STATS_KEYS", "clock_rate", "sip_headers", "HEADER_VIEW_KEYS",
           "CALL_STATES", "SIP_METHODS", "PAYLOAD_TYPES", "DECODABLE", "MAX_TEXT", "MAX_MESSAGE", "MAX_SECONDS",
           "MAX_GAP_SECONDS", "MAX_STORED_BYTES", "parse_sip", "is_sip", "parse_sdp", "parse_rtp", "looks_like_rtp",
           "ulaw_to_pcm16", "alaw_to_pcm16", "decodable", "build_wav", "CallTracker"]

SIP_KEYS = ("kind", "method", "status", "reason", "uri", "call_id", "from_uri", "from_tag", "to_uri", "to_tag",
            "cseq", "cseq_method", "via_branch", "contact", "user_agent", "content_type", "sdp")
SDP_KEYS = ("session", "connection", "media")
MEDIA_KEYS = ("type", "port", "proto", "formats", "rtpmap", "direction", "connection")
RTP_KEYS = ("version", "padding", "extension", "csrc_count", "marker", "payload_type", "seq", "ts", "ssrc", "payload")
STREAM_KEYS = ("id", "src", "sport", "dst", "dport", "ssrc", "payload_type", "codec", "packets", "lost",
               "out_of_order", "first_ts", "last_ts", "duration_s", "bytes", "jitter_ms", "decodable")
CALL_KEYS = ("id", "call_id", "from_uri", "to_uri", "state", "start_ts", "answer_ts", "end_ts", "duration_s",
             "status", "messages", "streams", "note")
MESSAGE_KEYS = ("ts", "kind", "method", "status", "reason", "src", "dst", "cseq", "cseq_method", "via_branch",
                "contact", "user_agent", "has_sdp", "sdp_c", "where", "side")
STATS_KEYS = ("calls", "streams", "sip_messages", "rtp_packets", "dropped")
CALL_STATES = ("calling", "ringing", "answered", "ended", "failed", "cancelled")

#: The request methods this module knows (RFC 3261 and the extensions a phone system uses in practice).
SIP_METHODS = ("INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH",
               "INFO", "REFER", "MESSAGE", "UPDATE")
#: RFC 3551 static payload types, audio only: ``payload type -> (name, clock rate in Hz, channels)``.
PAYLOAD_TYPES: Dict[int, Tuple[str, int, int]] = {
    0: ("PCMU", 8000, 1), 3: ("GSM", 8000, 1), 4: ("G723", 8000, 1), 5: ("DVI4", 8000, 1), 6: ("DVI4", 16000, 1),
    7: ("LPC", 8000, 1), 8: ("PCMA", 8000, 1), 9: ("G722", 8000, 1), 10: ("L16", 44100, 2), 11: ("L16", 44100, 1),
    12: ("QCELP", 8000, 1), 13: ("CN", 8000, 1), 14: ("MPA", 90000, 1), 15: ("G728", 8000, 1),
    16: ("DVI4", 11025, 1), 17: ("DVI4", 22050, 1), 18: ("G729", 8000, 1),
}
#: The payload types :class:`CallTracker` can rebuild as audio: G.711 mu-law and A-law.
DECODABLE = (0, 8)

MAX_TEXT = 200                       # characters kept of any header value that reaches a dict
MAX_MESSAGE = 65536                  # a SIP datagram never exceeds this
MAX_HEADERS = 200                    # header lines read of one message
MAX_HEADER_VALUE = 1000              # characters kept of a folded header line
MAX_SDP_LINES = 400
MAX_MEDIA = 8                        # m= sections of one SDP body
MAX_FORMATS = 32                     # payload types of one m= line, and rtpmap entries of one section
MAX_ID_TEXT = 40                     # characters of a Call-ID kept in a call's id slug
MAX_EXPECTED = 512                   # (ip, port) pairs learned from SDP
MAX_STREAMS_PER_CALL = 8
MAX_MIXED_STREAMS = 4                # streams mixed into one call recording
MAX_SEQ_GAP = 4096                   # a larger forward sequence jump is a restart, not loss
MAX_SECONDS = 3600.0                 # hard cap on a rebuilt recording
MAX_GAP_SECONDS = 3.0                # silence inserted for one timestamp hole
MAX_STORED_BYTES = 256 * 1024 * 1024  # RTP frames held by one tracker, per-frame overhead included
#: What one kept frame costs on top of its payload: the 4-tuple (72 B), the bytes header (33 B), the two timestamps
#: that are too large to be cached ints (28 B each) and the list slot (8 B). Charging it keeps
#: :data:`MAX_STORED_BYTES` a bound on memory rather than on payload: 160-byte G.711 frames cost twice their payload.
FRAME_OVERHEAD = 170
MAX_WAV_DATA = 200 * 1024 * 1024     # sample bytes a WAV file carries
MAX_WAV_RATE = 192000
MAX_CLOCK_RATE = 1_000_000           # an rtpmap clock rate past this is not one (video runs at 90 kHz)
MAX_INVITE_SENDERS = 8               # addresses whose INVITE CSeq one call remembers (a caller, a callee, proxies)
MIN_JITTER_STEPS = 16                # packet-to-packet steps the jitter estimator must see before it is a figure
MAX_WAV_CHANNELS = 2

PT_PCMU, PT_PCMA = 0, 8
RTP_VERSION = 2
RTP_HEADER = 12
_RTCP_TYPES = range(64, 96)          # RFC 3550 §11: RTCP packet types, kept clear of the RTP profile
_WILDCARD_ADDRESSES = ("0.0.0.0", "::", "")
_SIP_VERSION = "SIP/2.0"
_MIN_SIP = len("BYE / SIP/2.0")
_SNIFF = 16                          # bytes is_sip() looks at
_DIRECTIONS = ("sendrecv", "sendonly", "recvonly", "inactive")
_METHOD_BYTES = frozenset(method.encode("ascii") for method in SIP_METHODS)
#: RFC 3261 (and RFC 3265) compact header forms.
_COMPACT_HEADERS = {"i": "call-id", "f": "from", "t": "to", "m": "contact", "v": "via", "c": "content-type",
                    "l": "content-length", "s": "subject", "k": "supported", "o": "event"}
_ID_SAFE = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
_NATIVE_BIG_ENDIAN = sys.byteorder == "big"
_CLIP = 32767
_FLOOR = -_CLIP - 1                  # -32768: the one 16-bit sample the ±32767 clip catches with nothing under it


# --------------------------------------------------------------------------- small helpers
def _shaped(keys: Sequence[str], fields: Dict[str, Any]) -> Dict[str, Any]:
    """A dict with exactly *keys*, in that order, filled from *fields* (anything missing is None)."""
    shaped: Dict[str, Any] = dict.fromkeys(keys)
    shaped.update(fields)
    return shaped


def _text(value: str, limit: int = MAX_TEXT) -> Optional[str]:
    """A header value, stripped and capped at *limit* (:data:`MAX_TEXT` by default); None when nothing is left.

    The header *view* asks for a longer limit than a call's own fields do: a Via stack grows one entry per hop and a
    rewritten Contact is the thing being looked at, so cutting either at 200 characters would hide the answer."""
    return value.strip()[:limit].strip() or None


def _digits(value: str) -> bool:
    """Is *value* ASCII digits only, so that :func:`int` cannot raise on it?

    ``str.isdigit()`` on its own is not that guard: it is true for every Unicode Numeric_Type=Digit character, a
    strict superset of what ``int()`` reads, so superscripts (``²``) and circled digits (``①``) pass it and then
    raise. Bytes off the wire are decoded with ``errors="replace"``, which carries those characters through intact."""
    return value.isascii() and value.isdigit()


def _int(value: str) -> Optional[int]:
    return int(value) if _digits(value) and len(value) <= 20 else None


def _seq_diff(a: int, b: int) -> int:
    """``a - b`` as a signed 16-bit difference (RFC 3550's sequence comparison)."""
    return ((a - b + 0x8000) & 0xFFFF) - 0x8000


def _ts_diff(a: int, b: int) -> int:
    """``a - b`` as a signed 32-bit difference, so an RTP timestamp wrap reads as a small step."""
    return ((a - b + 0x80000000) & 0xFFFFFFFF) - 0x80000000


def _endpoint(ip: Any, port: Any) -> str:
    """``ip:port`` for a message dict, with an IPv6 literal in brackets."""
    text = str(ip)
    return f"[{text}]:{port}" if ":" in text else f"{text}:{port}"


def _slug(call_id: str) -> str:
    """A URL-safe id for a Call-ID: safe characters only, then a short digest so two Call-IDs never share one.

    It can hold neither a path separator nor ``..``, whatever the Call-ID was."""
    kept: List[str] = []
    for char in call_id[:MAX_ID_TEXT * 4]:
        if char in _ID_SAFE:
            kept.append(char)
        elif kept and kept[-1] != "-":
            kept.append("-")
    text = "".join(kept)[:MAX_ID_TEXT].strip("-")
    digest = hashlib.sha256(call_id.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"{text}-{digest}" if text else digest


# --------------------------------------------------------------------------- SIP
def is_sip(payload: bytes) -> bool:
    """A cheap sniff: does *payload* start with a known method and a space, or with ``SIP/2.0 ``?"""
    head = bytes(payload[:_SNIFF])
    if head.startswith(b"SIP/2.0 "):
        return True
    method, space, _rest = head.partition(b" ")
    return bool(space) and method in _METHOD_BYTES


def _split_body(data: bytes) -> Tuple[bytes, bytes]:
    """The header block and the body, split at the first blank line (CRLF or LF)."""
    best = -1
    length = 0
    for separator in (b"\r\n\r\n", b"\n\n"):
        found = data.find(separator)
        if found >= 0 and (best < 0 or found < best):
            best, length = found, len(separator)
    return (data, b"") if best < 0 else (data[:best], data[best + length:])


def _start_line(line: str) -> Optional[Tuple[str, Optional[str], Optional[int], Optional[str], Optional[str]]]:
    """``(kind, method, status, reason, uri)`` of a start line, or None when it is neither a request nor a response."""
    parts = line.split(None, 2)
    if line.startswith(_SIP_VERSION):
        if len(parts) < 2 or len(parts[1]) != 3 or not _digits(parts[1]):
            return None
        status = int(parts[1])
        if not 100 <= status <= 699:
            return None
        return "response", None, status, (_text(parts[2]) if len(parts) > 2 else None), None
    if len(parts) != 3 or parts[0] not in SIP_METHODS or parts[2].strip().upper() != _SIP_VERSION:
        return None
    return "request", parts[0], None, None, _text(parts[1])


def _headers(text: str) -> List[Tuple[str, str]]:
    """``(lower-case name, value)`` per header line, continuation lines folded into the line before them."""
    found: List[Tuple[str, str]] = []
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if not line:
            continue
        if line[0] in " \t":
            if found:
                name, value = found[-1]
                found[-1] = (name, (value + " " + line.strip())[:MAX_HEADER_VALUE])
            continue
        name, colon, value = line.partition(":")
        if not colon:
            continue
        key = name.strip().lower()
        found.append((_COMPACT_HEADERS.get(key, key), value.strip()[:MAX_HEADER_VALUE]))
        if len(found) >= MAX_HEADERS:
            break
    return found


def _first(headers: Iterable[Tuple[str, str]], name: str) -> Optional[str]:
    for key, value in headers:
        if key == name:
            return value
    return None


def _parameters(text: str) -> Dict[str, str]:
    """``;name=value`` parameters of a header value, lower-case names, at most :data:`MAX_FORMATS` of them."""
    found: Dict[str, str] = {}
    for item in text.split(";")[1:MAX_FORMATS + 1]:
        name, equals, value = item.partition("=")
        if equals:
            found.setdefault(name.strip().lower(), value.strip())
    return found


def _uri_and_tag(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """The URI of a From/To/Contact header and its ``tag`` parameter."""
    if value is None:
        return None, None
    start = value.find("<")
    if start >= 0:
        end = value.find(">", start + 1)
        if end < 0:
            return _text(value[start + 1:]), None
        return _text(value[start + 1:end]), _text(_parameters(";" + value[end + 1:]).get("tag", ""))
    head, semicolon, rest = value.partition(";")
    return _text(head), (_text(_parameters(";" + rest).get("tag", "")) if semicolon else None)


def _cseq(value: Optional[str]) -> Tuple[Optional[int], Optional[str]]:
    if not value:
        return None, None
    parts = value.split()
    number = _int(parts[0]) if parts else None
    method = parts[1].upper()[:MAX_TEXT] if len(parts) > 1 else None
    return number, method


def parse_sip(payload: bytes) -> Optional[Dict[str, Any]]:
    """The :data:`SIP_KEYS` dict of a SIP request or response, or None when *payload* is neither. Never raises."""
    data = bytes(payload)
    if not _MIN_SIP <= len(data) <= MAX_MESSAGE:
        return None
    head, body = _split_body(data)
    text = head.decode("utf-8", errors="replace")
    first, _newline, rest = text.partition("\n")
    start = _start_line(first.rstrip("\r"))
    if start is None:
        return None
    kind, method, status, reason, uri = start
    headers = _headers(rest)
    from_uri, from_tag = _uri_and_tag(_first(headers, "from"))
    to_uri, to_tag = _uri_and_tag(_first(headers, "to"))
    contact, _contact_tag = _uri_and_tag(_first(headers, "contact"))
    cseq, cseq_method = _cseq(_first(headers, "cseq"))
    via = _first(headers, "via")
    content_type = _text(_first(headers, "content-type") or "")
    return _shaped(SIP_KEYS, {
        "kind": kind, "method": method, "status": status, "reason": reason, "uri": uri,
        "call_id": _text(_first(headers, "call-id") or ""), "from_uri": from_uri, "from_tag": from_tag,
        "to_uri": to_uri, "to_tag": to_tag, "cseq": cseq, "cseq_method": cseq_method,
        "via_branch": _text(_parameters(via).get("branch", "")) if via else None, "contact": contact,
        "user_agent": _text(_first(headers, "user-agent") or ""), "content_type": content_type,
        "sdp": parse_sdp(body) if _is_sdp(content_type, body) else None})


def sip_headers(payload: bytes) -> Optional[Dict[str, Any]]:
    """Every header of one SIP message, in the order it was sent, for the detail view behind a ladder row.

    :func:`parse_sip` keeps the dozen fields a call needs and the *first* value of each; this keeps all of them and
    every repeat. That matters: the Via stack is a list, one entry per hop, and reading it top to bottom is how a
    routing problem is diagnosed. So is Record-Route, and so is a Contact an ALG has rewritten. Returns
    ``{"start", "kind", "method", "status", "reason", "uri", "headers": [{"name", "value"}], "body", "is_sdp"}``
    or None when *payload* is not SIP. Never raises."""
    data = bytes(payload)
    if not _MIN_SIP <= len(data) <= MAX_MESSAGE:
        return None
    head, body = _split_body(data)
    text = head.decode("utf-8", errors="replace")
    first, _newline, rest = text.partition("\n")
    start = first.rstrip("\r")
    parsed = _start_line(start)
    if parsed is None:
        return None
    kind, method, status, reason, uri = parsed
    content_type = None
    out: List[Dict[str, Any]] = []
    for name, value in _headers(rest):
        if name == "content-type" and content_type is None:
            content_type = value
        out.append({"name": name, "value": _text(value, MAX_HEADER_VALUE)})
    body_text = body.decode("utf-8", errors="replace")[:MAX_HEADER_VALUE * 4]
    # a Content-Length that does not match the body is the classic mark of a middlebox that rewrote the body and
    # did not re-count it; None when the message did not carry one to check
    declared = _first(_headers(rest), "content-length")
    length_ok: Optional[bool] = None
    if declared is not None and declared.strip().isdigit():
        length_ok = int(declared.strip()) == len(body)
    return {"start": _text(start, MAX_HEADER_VALUE), "kind": kind, "method": method, "status": status,
            "reason": reason, "uri": uri, "headers": out, "body": body_text or None,
            "is_sdp": _is_sdp(content_type, body), "length_ok": length_ok}


HEADER_VIEW_KEYS = ("start", "kind", "method", "status", "reason", "uri", "headers", "body", "is_sdp",
                    "length_ok")


def _is_sdp(content_type: Optional[str], body: bytes) -> bool:
    if content_type is not None:
        return content_type.split(";")[0].strip().lower() == "application/sdp"
    return body[:2] == b"v="


# --------------------------------------------------------------------------- SDP
def _connection_address(value: str) -> Optional[str]:
    """The address of a ``c=IN IP4 192.0.2.10`` line, a multicast ``/ttl/count`` suffix removed."""
    parts = value.split()
    return _text(parts[2].split("/")[0]) if len(parts) >= 3 else None


def _media_line(value: str) -> Optional[Dict[str, Any]]:
    parts = value.split()
    if len(parts) < 3:
        return None
    port = _int(parts[1].split("/")[0])
    formats = [number for number in (_int(item) for item in parts[3:MAX_FORMATS + 3]) if number is not None]
    return _shaped(MEDIA_KEYS, {"type": parts[0].lower()[:MAX_TEXT], "proto": parts[2][:MAX_TEXT],
                                "port": port if port is not None and port <= 65535 else 0, "formats": formats,
                                "rtpmap": {}, "direction": None, "connection": None})


def parse_sdp(body: bytes | str) -> Optional[Dict[str, Any]]:
    """The :data:`SDP_KEYS` dict of an SDP body, or None when it carries no ``v=`` line. Never raises."""
    text = body.decode("utf-8", errors="replace") if isinstance(body, (bytes, bytearray, memoryview)) else str(body)
    session: Optional[str] = None
    connection: Optional[str] = None
    direction: Optional[str] = None
    media: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    skipping = False
    version = False
    for raw in text.replace("\r\n", "\n").split("\n")[:MAX_SDP_LINES]:
        line = raw.strip()
        if len(line) < 2 or line[1] != "=":
            continue
        field, value = line[0], line[2:].strip()
        if field == "m":
            if len(media) >= MAX_MEDIA:
                break
            current = _media_line(value)
            skipping = current is None
            if current is not None:
                media.append(current)
            continue
        # RFC 4566 §5.14: everything after an m= line is that section's. When the m= line could not be read, its
        # lines go with it - they are not the section before it, and must not rewrite that section's address.
        if skipping:
            continue
        if field == "v":
            version = True
        elif field == "s" and current is None:
            session = _text(value)
        elif field == "c":
            address = _connection_address(value)
            if current is None:
                connection = address
            else:
                current["connection"] = address
        elif field == "a":
            lowered = value.lower()
            if lowered in _DIRECTIONS:
                if current is None:
                    direction = lowered
                else:
                    current["direction"] = lowered
            elif current is not None:
                _rtpmap_entry(value, current)
    if not version:
        return None
    for entry in media:
        if entry["direction"] is None:
            entry["direction"] = direction or _DIRECTIONS[0]
        if entry["connection"] is None:
            entry["connection"] = connection
    return _shaped(SDP_KEYS, {"session": session, "connection": connection, "media": media})


def _rtpmap_entry(value: str, media: Dict[str, Any]) -> None:
    """An ``a=rtpmap:<pt> <name>/<rate>`` line, added to the media section it sits in."""
    name, colon, rest = value.partition(":")
    if not colon or name.strip().lower() != "rtpmap":
        return
    parts = rest.split()
    payload_type = _int(parts[0]) if parts else None
    if payload_type is None or len(parts) < 2 or len(media["rtpmap"]) >= MAX_FORMATS:
        return
    media["rtpmap"].setdefault(payload_type, parts[1][:MAX_TEXT])


# --------------------------------------------------------------------------- RTP
def looks_like_rtp(payload: bytes) -> bool:
    """A cheap sniff: 12 bytes, version 2, a CSRC list that fits and a payload type outside RTCP's 64..95."""
    if len(payload) < RTP_HEADER:
        return False
    first, second = payload[0], payload[1]
    if first >> 6 != RTP_VERSION or (second & 0x7F) in _RTCP_TYPES:
        return False
    return len(payload) >= RTP_HEADER + 4 * (first & 0x0F)


def parse_rtp(payload: bytes) -> Optional[Dict[str, Any]]:
    """The :data:`RTP_KEYS` dict of an RTP packet, or None when the header, its CSRCs, its extension or its padding
    does not fit the bytes given. Never raises."""
    data = bytes(payload)
    size = len(data)
    if size < RTP_HEADER or data[0] >> 6 != RTP_VERSION:
        return None
    csrc_count = data[0] & 0x0F
    start = RTP_HEADER + 4 * csrc_count
    if start > size:
        return None
    extension = bool(data[0] & 0x10)
    if extension:
        if start + 4 > size:
            return None
        (words,) = struct.unpack_from(">H", data, start + 2)
        start += 4 + 4 * words
        if start > size:
            return None
    end = size
    if data[0] & 0x20:                       # padding: the last byte counts itself and the bytes before it
        pad = data[size - 1]
        if pad < 1 or start + pad > size:
            return None
        end = size - pad
    seq = struct.unpack_from(">H", data, 2)[0]
    timestamp, ssrc = struct.unpack_from(">II", data, 4)
    return _shaped(RTP_KEYS, {"version": RTP_VERSION, "padding": bool(data[0] & 0x20), "extension": extension,
                              "csrc_count": csrc_count, "marker": bool(data[1] & 0x80),
                              "payload_type": data[1] & 0x7F, "seq": seq, "ts": timestamp, "ssrc": ssrc,
                              "payload": data[start:end]})


# --------------------------------------------------------------------------- G.711
def _ulaw_table() -> Tuple[int, ...]:
    """The 256 mu-law codes as 16-bit samples (ITU-T G.711): the byte is stored inverted, then bit 7 is the sign, bits
    6-4 the segment and bits 3-0 the interval, and the decoded 14-bit magnitude is scaled by 4 to fill 16 bits."""
    values: List[int] = []
    for code in range(256):
        stored = ~code & 0xFF
        magnitude = 4 * (((2 * (stored & 0x0F) + 33) << ((stored >> 4) & 0x07)) - 33)
        values.append(-magnitude if stored & 0x80 else magnitude)
    return tuple(values)


def _alaw_table() -> Tuple[int, ...]:
    """The 256 A-law codes as 16-bit samples (ITU-T G.711): every other bit of the byte is inverted on the line, and
    the decoded 13-bit magnitude (segment 0 is linear) is scaled by 8 to fill 16 bits."""
    values: List[int] = []
    for code in range(256):
        stored = code ^ 0x55
        segment, interval = (stored >> 4) & 0x07, stored & 0x0F
        magnitude = 8 * ((2 * interval + 1) if segment == 0 else ((2 * interval + 33) << (segment - 1)))
        values.append(magnitude if stored & 0x80 else -magnitude)
    return tuple(values)


_ULAW = _ulaw_table()
_ALAW = _alaw_table()


def _pcm16(data: bytes, table: Tuple[int, ...]) -> bytes:
    samples = array("h", map(table.__getitem__, data))
    if _NATIVE_BIG_ENDIAN:
        samples.byteswap()
    return samples.tobytes()


def ulaw_to_pcm16(data: bytes) -> bytes:
    """G.711 mu-law (payload type 0) as 16-bit little-endian PCM: one sample per byte."""
    return _pcm16(bytes(data), _ULAW)


def alaw_to_pcm16(data: bytes) -> bytes:
    """G.711 A-law (payload type 8) as 16-bit little-endian PCM: one sample per byte."""
    return _pcm16(bytes(data), _ALAW)


def decodable(payload_type: int) -> bool:
    """Can this module turn that payload type into audio?"""
    return payload_type in DECODABLE


def clock_rate(payload_type: Any) -> Optional[int]:
    """The RTP clock rate of a static payload type, or None for one this module does not know.

    Jitter is measured in these units, so a stream whose rate is unknown reports no jitter rather than a number in
    the wrong scale. A dynamic payload type is not here: :class:`CallTracker` takes its rate from the SDP rtpmap."""
    entry = PAYLOAD_TYPES.get(payload_type) if isinstance(payload_type, int) else None
    return entry[1] if entry else None


# --------------------------------------------------------------------------- WAV
def build_wav(pcm: bytes, *, rate: int = 8000, channels: int = 1) -> bytes:
    """*pcm* (16-bit little-endian samples) as a RIFF/WAVE file with the canonical 44-byte header.

    The data is trimmed to whole sample frames and to :data:`MAX_WAV_DATA` bytes. A *rate* outside 1..192000 or
    *channels* outside 1..2 raises ValueError."""
    if not isinstance(rate, int) or not isinstance(channels, int) or isinstance(rate, bool) \
            or isinstance(channels, bool) or not 1 <= rate <= MAX_WAV_RATE or not 1 <= channels <= MAX_WAV_CHANNELS:
        raise ValueError("a WAV needs a rate of 1..192000 Hz and 1 or 2 channels")
    block = 2 * channels
    body = bytes(pcm)[:MAX_WAV_DATA]
    body = body[:len(body) - len(body) % block]
    return b"".join((b"RIFF", struct.pack("<I", 36 + len(body)), b"WAVE",
                     b"fmt ", struct.pack("<IHHIIHH", 16, 1, channels, rate, rate * block, block, 16),
                     b"data", struct.pack("<I", len(body)), body))


# --------------------------------------------------------------------------- streams and calls
class _Stream:
    """One RTP stream: its counters, and the payloads kept for rebuilding it."""

    __slots__ = ("id", "src", "sport", "dst", "dport", "ssrc", "payload_type", "codec", "packets", "lost",
                 "out_of_order", "first_ts", "last_ts", "bytes", "highest_seq", "frames", "full", "stored",
                 "rate", "jitter", "jitter_steps", "_last_arrival", "_last_stamp", "_missing")

    def __init__(self, stream_id: str, src: str, sport: int, dst: str, dport: int, ssrc: int, payload_type: int,
                 codec: str, ts: float) -> None:
        self.id = stream_id
        self.src, self.sport, self.dst, self.dport = src, sport, dst, dport
        self.ssrc, self.payload_type, self.codec = ssrc, payload_type, codec
        self.packets = self.lost = self.out_of_order = self.bytes = self.stored = 0
        self.first_ts = self.last_ts = ts
        self.highest_seq: Optional[int] = None
        self.frames: List[Tuple[int, int, int, bytes]] = []
        self.full = False
        self.rate = clock_rate(payload_type)
        self.jitter = 0.0                    # RFC 3550 interarrival jitter, in RTP timestamp units
        self.jitter_steps = 0                # packet-to-packet steps that went into it
        self._last_arrival: Optional[float] = None
        self._last_stamp: Optional[int] = None
        # One bit per 16-bit sequence number, set while that packet is counted as lost and has not turned up. It is
        # only allocated at the first gap (8 KiB), so a stream that never loses anything never pays for it.
        self._missing: Optional[bytearray] = None

    def count(self, seq: int, ts: float, size: int, stamp: Optional[int] = None) -> None:
        self.packets += 1
        self.bytes += size
        if ts > self.last_ts:
            self.last_ts = ts
        # RFC 3550 clause 6.4.1: D is how much the gap between two packets' arrivals differs from the gap their own
        # timestamps claim, and the jitter estimate follows it with a gain of 1/16. This is the number a phone's own
        # jitter buffer is sized against, and it cannot be recovered later: it needs the arrival time of every packet.
        if self.rate and stamp is not None:
            arrival = ts * self.rate
            if self._last_arrival is not None and self._last_stamp is not None:
                # the signed 32-bit step, as everywhere else in this module: the raw difference across the wrap of
                # the timestamp field is four billion units, which the estimator turned into hours of "jitter"
                delta = (arrival - self._last_arrival) - float(_ts_diff(stamp, self._last_stamp))
                self.jitter += (abs(delta) - self.jitter) / 16.0
                self.jitter_steps += 1
            self._last_arrival, self._last_stamp = arrival, stamp
        if self.highest_seq is None:
            self.highest_seq = seq
            return
        # Loss is RFC 3550 appendix A.3's "expected minus received": a forward gap counts the packets it skipped,
        # and a late packet that fills one of those holes gives its count back, so a path that reorders but loses
        # nothing reports no loss. Counting the gaps alone read every reordered packet as a lost one, and 1 %
        # reordering on a multi-link WAN then raised "Audio packets were lost" on a stream that was complete. A
        # late packet whose number is not an open hole is a duplicate (or older than the first packet seen) and
        # is neither lost nor out of order.
        step = _seq_diff(seq, self.highest_seq)
        if step > 0:
            if step <= MAX_SEQ_GAP:
                if step > 1:
                    self.lost += step - 1
                    if self._missing is None:
                        self._missing = bytearray(0x2000)
                self._open_holes(self.highest_seq, step)
            else:
                self._missing = None             # a restarted stream: nothing from before it will be matched now
            self.highest_seq = seq
        elif step < 0 and self._missing is not None:
            index = seq & 0xFFFF
            mask = 1 << (index & 7)
            if self._missing[index >> 3] & mask:
                self._missing[index >> 3] &= ~mask & 0xFF
                self.lost -= 1
                self.out_of_order += 1

    def _open_holes(self, highest: int, step: int) -> None:
        """Mark the *step* - 1 numbers after *highest* missing and clear the one that just arrived.

        Every number the stream moves past is written, set or cleared, so a bit left over from the same number one
        16-bit cycle earlier can never be taken for a hole now."""
        missing = self._missing
        if missing is None:
            return
        for offset in range(1, step + 1):
            index = (highest + offset) & 0xFFFF
            mask = 1 << (index & 7)
            if offset < step:
                missing[index >> 3] |= mask
            else:
                missing[index >> 3] &= ~mask & 0xFF


class _Call:
    """One call, keyed by its SIP Call-ID."""

    __slots__ = ("id", "call_id", "from_uri", "to_uri", "state", "start_ts", "answer_ts", "end_ts", "last_ts",
                 "status", "messages", "media", "order", "invite_cseq")

    def __init__(self, call_id: str, msg: Dict[str, Any], ts: float, order: int) -> None:
        self.id = _slug(call_id)
        self.call_id = call_id
        self.from_uri = msg.get("from_uri")
        self.to_uri = msg.get("to_uri") or msg.get("uri")
        self.state = CALL_STATES[0]
        self.start_ts = self.last_ts = ts
        self.answer_ts: Optional[float] = None
        self.end_ts: Optional[float] = None
        self.status: Optional[int] = None
        self.messages: List[Dict[str, Any]] = []
        self.media: Set[Tuple[str, int]] = set()
        self.order = order
        # the CSeq of the newest INVITE from each sender on this Call-ID: each end numbers its own requests
        # (RFC 3261 8.1.1.5), so the caller's and a callee's re-INVITE numbers do not compare
        self.invite_cseq: Dict[str, int] = {}


def _in_timestamp_order(frames: Sequence[Tuple[int, int, int, bytes]],
                        payload_type: int) -> List[Tuple[int, int, bytes]]:
    """``(unwrapped timestamp, sequence, payload)`` for the frames carrying *payload_type*, in timestamp order.

    The timestamps are unwrapped by adding each packet's signed 32-bit step from the packet before it in arrival
    order, so the running total is the real distance from the first packet however often the 32-bit field wrapped."""
    unwrapped: List[Tuple[int, int, bytes]] = []
    position = 0
    previous: Optional[int] = None
    for timestamp, seq, pt, payload in frames:
        if previous is not None:
            position += _ts_diff(timestamp, previous)
        previous = timestamp
        if pt == payload_type and payload:
            unwrapped.append((position, seq, payload))
    unwrapped.sort(key=lambda frame: (frame[0], frame[1]))
    return unwrapped


def _rebuild(stream: _Stream, max_seconds: float) -> Optional[Tuple[bytes, int]]:
    """``(16-bit little-endian PCM, clock rate)`` rebuilt from a stream, or None when there is nothing to play."""
    entry = PAYLOAD_TYPES.get(stream.payload_type)
    if entry is None or not decodable(stream.payload_type) or not stream.frames:
        return None
    rate = entry[1]
    decode = ulaw_to_pcm16 if stream.payload_type == PT_PCMU else alaw_to_pcm16
    try:
        limit = int(max(0.0, min(float(max_seconds), MAX_SECONDS)) * rate)
    except (TypeError, ValueError):
        return None
    ordered = _in_timestamp_order(stream.frames, stream.payload_type)
    if limit <= 0 or not ordered:
        return None
    max_gap = int(MAX_GAP_SECONDS * rate)
    start = ordered[0][0]
    chunks: List[bytes] = []
    position = 0
    previous: Optional[Tuple[int, int]] = None
    for timestamp, seq, payload in ordered:
        if (timestamp, seq) == previous:                     # the same packet again
            continue
        previous = (timestamp, seq)
        want = timestamp - start                             # G.711: one timestamp unit is one sample
        if want > position:
            gap = min(want - position, max_gap, limit - position)
            if gap > 0:
                chunks.append(bytes(2 * gap))
                position += gap
        elif want < position:                                # overlapping samples: keep what is new
            payload = payload[min(position - want, len(payload)):]
        if len(payload) > limit - position:
            payload = payload[:limit - position]
        if not payload:
            if position >= limit:
                break
            continue
        chunks.append(decode(payload))
        position += len(payload)
        if position >= limit:
            break
    pcm = b"".join(chunks)
    return (pcm, rate) if pcm else None


def _clipped(value: int) -> int:
    return _CLIP if value > _CLIP else (-_CLIP if value < -_CLIP else value)


def _mix(parts: Sequence[Tuple[int, bytes]], total: int) -> bytes:
    """*parts* (``(offset in samples, PCM)``) added together with clipping at ±32767, as *total* samples.

    The addition runs over whole slices - ``map`` at C speed, one slice assignment per part - and not sample by
    sample, because :data:`MAX_SECONDS` of audio is 29 million samples per direction and this runs inside a request.
    A part landing where nothing has been written yet is copied straight in, which is what adding it to silence is -
    except that ``-32768`` still has to be clipped to ``-32767`` on its own, so a part carrying one is passed through
    the clip anyway (a G.711 sample never reaches it, but ``_mix`` is not to depend on who is calling it)."""
    mixed = array("h", bytes(2 * total))
    for offset, pcm in parts:
        samples = array("h")
        samples.frombytes(pcm)
        if _NATIVE_BIG_ENDIAN:
            samples.byteswap()
        start = max(0, offset)
        end = min(start + len(samples), total)
        if end <= start:
            continue
        del samples[end - start:]
        under = mixed[start:end]
        if any(under):
            samples = array("h", map(_clipped, map(operator.add, under, samples)))
        elif _FLOOR in samples:
            samples = array("h", map(_clipped, samples))
        mixed[start:end] = samples
    if _NATIVE_BIG_ENDIAN:
        mixed.byteswap()
    return mixed.tobytes()


class CallTracker:
    """Feed it every SIP and RTP packet of a capture, in arrival order; ask it for the calls."""

    __slots__ = ("_max_calls", "_max_streams", "_max_stream_packets", "_max_messages", "_calls", "_slugs", "_streams",
                 "_endpoints", "_rtpmap", "_sip_messages", "_rtp_packets", "_dropped", "_stored_bytes", "_order")

    def __init__(self, *, max_calls: int = 64, max_streams: int = 256, max_stream_packets: int = 200_000,
                 max_messages: int = 400) -> None:
        self._max_calls = max(1, int(max_calls))
        self._max_streams = max(1, int(max_streams))
        self._max_stream_packets = max(1, int(max_stream_packets))
        self._max_messages = max(1, int(max_messages))
        self._calls: Dict[str, _Call] = {}
        self._slugs: Dict[str, str] = {}
        self._streams: Dict[str, _Stream] = {}
        self._endpoints: Dict[Tuple[str, int], str] = {}
        self._rtpmap: Dict[Tuple[str, int], Dict[int, str]] = {}
        self._sip_messages = self._rtp_packets = self._dropped = self._stored_bytes = self._order = 0

    # ----------------------------------------------------------------- feeding
    def add_sip(self, msg: Dict[str, Any], ts: float, src: str, sport: int, dst: str, dport: int,
                where: Any = None, side: Any = None) -> Optional[str]:
        """Take one parsed SIP message; return the call's ``id`` when it created a call or changed its state.

        ``where`` is an opaque locator the caller can use to find the packet again - a capture row number, or the
        byte offset of its pcapng block. It is stored, never interpreted: keeping a few bytes per message and
        re-reading the packet on demand costs about a thousandth of what holding every message's text would, and
        the raw bytes are what a header view wants anyway. ``side`` is the caller's own label for which capture a
        message came from, which is what lets a merged two-sided view say where each one was seen."""
        if not isinstance(msg, dict):
            return None
        self._sip_messages += 1
        call_id = msg.get("call_id")
        when = _number(ts)
        if not isinstance(call_id, str) or not call_id or when is None:
            return None
        call = self._calls.get(call_id)
        changed = False
        if call is None:
            if msg.get("kind") != "request" or msg.get("method") != "INVITE":
                return None
            call = self._start(call_id, msg, when)
            changed = True
        changed = self._advance(call, msg, when, str(src), str(dst)) or changed
        if call.from_uri is None:
            call.from_uri = msg.get("from_uri")
        if call.to_uri is None:
            call.to_uri = msg.get("to_uri")
        if when > call.last_ts:
            call.last_ts = when
        sdp = msg.get("sdp")
        if isinstance(sdp, dict):
            self._learn_media(call, sdp, src)
        if len(call.messages) < self._max_messages:
            call.messages.append(_shaped(MESSAGE_KEYS, {
                "ts": when, "kind": msg.get("kind"), "method": msg.get("method"), "status": msg.get("status"),
                "reason": msg.get("reason"), "src": _endpoint(src, sport), "dst": _endpoint(dst, dport),
                "cseq": msg.get("cseq"), "cseq_method": msg.get("cseq_method"),
                "via_branch": msg.get("via_branch"), "contact": msg.get("contact"),
                "user_agent": msg.get("user_agent"), "has_sdp": isinstance(msg.get("sdp"), dict),
                # the address the sender told the far end to send audio to: what an ALG rewrites to strand it
                "sdp_c": (msg.get("sdp") or {}).get("connection") if isinstance(msg.get("sdp"), dict) else None,
                "where": where, "side": side}))
        else:
            self._dropped += 1
        return call.id if changed else None

    def add_rtp(self, rtp: Dict[str, Any], ts: float, src: str, sport: int, dst: str, dport: int) -> None:
        """Take one parsed RTP packet: count it, and keep its payload while there is room for it."""
        if not isinstance(rtp, dict):
            return
        self._rtp_packets += 1
        when = _number(ts)
        payload = rtp.get("payload")
        fields = [rtp.get(name) for name in ("ssrc", "seq", "ts", "payload_type")]
        if when is None or not isinstance(payload, (bytes, bytearray, memoryview)):
            return
        if any(not isinstance(field, int) or isinstance(field, bool) for field in fields):
            return
        ssrc, seq, timestamp, payload_type = fields
        source, destination = (str(src), _port(sport)), (str(dst), _port(dport))
        stream_id = _stream_id(source, destination, ssrc)
        stream = self._streams.get(stream_id)
        if stream is None:
            if len(self._streams) >= self._max_streams:
                self._dropped += 1
                return
            stream = _Stream(stream_id, source[0], source[1], destination[0], destination[1], ssrc, payload_type,
                             self._codec(payload_type, destination, source), when)
            self._streams[stream_id] = stream
        if stream.rate is None:
            # A dynamic payload type (Opus, iLBC, AMR, speex) has no clock rate of its own: the SDP's rtpmap names
            # it. Looked up again while it is unknown, because the SDP can arrive after the first packets (early
            # media, a capture started mid-call). Without the SDP the rate stays unknown and jitter_ms stays None:
            # a dynamic number means nothing on its own - 111 is Opus on one phone and something else on the next -
            # so guessing from it could report a number in the wrong scale, which is worse than none.
            stream.rate = self._rtpmap_rate(stream.payload_type, destination, source)
            if stream.rate is not None and stream.codec == f"PT {stream.payload_type}":
                stream.codec = self._codec(stream.payload_type, destination, source)
        stream.count(seq, when, len(payload), timestamp)
        cost = len(payload) + FRAME_OVERHEAD          # what the frame really costs, not just the bytes in it
        if stream.full or len(stream.frames) >= self._max_stream_packets \
                or self._stored_bytes + cost > MAX_STORED_BYTES:
            stream.full = True
            self._dropped += 1
            return
        stream.frames.append((timestamp, seq, payload_type, bytes(payload)))
        stream.stored += cost
        self._stored_bytes += cost

    def expected_rtp(self) -> Set[Tuple[str, int]]:
        """The ``(ip, port)`` pairs learned from SDP, so a capture loop can sniff cheaply for the media."""
        return set(self._endpoints)

    # ----------------------------------------------------------------- reading
    def calls(self) -> List[Dict[str, Any]]:
        """Every call as a :data:`CALL_KEYS` dict, newest first."""
        ordered = sorted(self._calls.values(), key=lambda call: (call.start_ts, call.order), reverse=True)
        return [self._call_dict(call) for call in ordered]

    def call(self, call_id: str) -> Optional[Dict[str, Any]]:
        """One call by its Call-ID or by its ``id`` slug, or None."""
        found = self._find(call_id)
        return None if found is None else self._call_dict(found)

    def stream(self, stream_id: str) -> Optional[Dict[str, Any]]:
        """One RTP stream as a :data:`STREAM_KEYS` dict, or None."""
        found = self._streams.get(stream_id)
        return None if found is None else _stream_dict(found)

    def audio(self, stream_id: str, *, max_seconds: float = 600.0) -> Optional[bytes]:
        """One stream rebuilt as a WAV file, or None when its codec cannot be rebuilt or nothing was kept."""
        stream = self._streams.get(stream_id)
        rebuilt = None if stream is None else _rebuild(stream, max_seconds)
        return None if rebuilt is None else build_wav(rebuilt[0], rate=rebuilt[1])

    def call_audio(self, call_id: str, *, max_seconds: float = 600.0) -> Optional[bytes]:
        """Both directions of a call mixed into one mono WAV, each offset by its own first arrival time."""
        call = self._find(call_id)
        if call is None:
            return None
        rate: Optional[int] = None
        rebuilt: List[Tuple[float, bytes]] = []
        for stream in self._call_streams(call):
            parts = _rebuild(stream, max_seconds)
            if parts is None or (rate is not None and parts[1] != rate):
                continue
            rate = parts[1]
            rebuilt.append((stream.first_ts, parts[0]))
            if len(rebuilt) >= MAX_MIXED_STREAMS:
                break
        if not rebuilt or rate is None:
            return None
        if len(rebuilt) == 1:
            return build_wav(rebuilt[0][1], rate=rate)
        limit = int(max(0.0, min(float(max_seconds), MAX_SECONDS)) * rate)
        earliest = min(first for first, _pcm in rebuilt)
        placed: List[Tuple[int, bytes]] = []
        total = 0
        for first, pcm in rebuilt:
            offset = min(max(0, int(round((first - earliest) * rate))), limit)
            count = max(0, min(len(pcm) // 2, limit - offset))
            placed.append((offset, pcm[:2 * count]))
            total = max(total, offset + count)
        return build_wav(_mix(placed, total), rate=rate) if total else None

    def stats(self) -> Dict[str, Any]:
        """``{"calls", "streams", "sip_messages", "rtp_packets", "dropped"}`` (:data:`STATS_KEYS`)."""
        return _shaped(STATS_KEYS, {"calls": len(self._calls), "streams": len(self._streams),
                                    "sip_messages": self._sip_messages, "rtp_packets": self._rtp_packets,
                                    "dropped": self._dropped})

    # ----------------------------------------------------------------- inside
    def _start(self, call_id: str, msg: Dict[str, Any], ts: float) -> _Call:
        """A new call, making room by forgetting the oldest one when ``max_calls`` is reached."""
        while len(self._calls) >= self._max_calls:
            self._forget(min(self._calls.values(), key=lambda call: call.order))
        self._order += 1
        call = _Call(call_id, msg, ts, self._order)
        self._calls[call_id] = call
        self._slugs[call.id] = call_id
        return call

    def _forget(self, call: _Call) -> None:
        """Drop a call, the endpoints it owns and the streams that were only its, giving their stored bytes back.

        Without the last part a call rolled out by ``max_calls`` frees nothing: its frames stay in ``_streams`` for
        the life of the tracker and ``_stored_bytes`` only ever climbs towards :data:`MAX_STORED_BYTES`."""
        self._calls.pop(call.call_id, None)
        self._slugs.pop(call.id, None)
        released: Set[Tuple[str, int]] = set()
        for endpoint in call.media:
            if self._endpoints.get(endpoint) == call.call_id:
                self._endpoints.pop(endpoint, None)
                self._rtpmap.pop(endpoint, None)
                released.add(endpoint)
        if not released:
            return
        for stream_id, stream in list(self._streams.items()):
            ends = ((stream.src, stream.sport), (stream.dst, stream.dport))
            if any(end in released for end in ends) and not any(end in self._endpoints for end in ends):
                del self._streams[stream_id]
                self._stored_bytes -= stream.stored

    @staticmethod
    def _advance(call: _Call, msg: Dict[str, Any], ts: float, src: str = "", dst: str = "") -> bool:
        """Apply the call state rules to one message; True when the state changed.

        *src* and *dst* are the addresses it travelled between: an INVITE's CSeq is kept per sender, and a response
        is matched with the INVITEs of the end it was sent to."""
        kind, status, cseq = msg.get("kind"), msg.get("status"), msg.get("cseq")
        if not isinstance(cseq, int) or isinstance(cseq, bool):
            cseq = None
        if kind == "request":
            method = msg.get("method")
            if method == "INVITE":
                previous = call.invite_cseq.get(src)
                if cseq is None or (previous is not None and cseq <= previous):
                    return False             # a retransmission of an INVITE already seen
                if previous is None and len(call.invite_cseq) >= MAX_INVITE_SENDERS:
                    return False             # a flood of senders on one Call-ID: keep what is already known
                call.invite_cseq[src] = cseq
                if previous is not None and call.state == "failed" and call.answer_ts is None:
                    # RFC 3261 22.2: a 401 or 407 is answered by sending the INVITE again, same Call-ID, next CSeq,
                    # with credentials. That is how nearly every call through Asterisk, FreePBX, 3CX or an
                    # authenticating trunk starts, so the challenge was a step in the call, not its end. Any other
                    # refusal a caller retries the same way (a 422 or a 491) reopens the call just the same.
                    call.state, call.end_ts, call.status = "calling", None, None
                    return True
                return False
            if method == "BYE" and call.state != "ended":
                call.state, call.end_ts = "ended", ts
                return True
            if method == "CANCEL" and call.state in ("calling", "ringing"):
                call.state, call.end_ts = "cancelled", ts
                return True
            return False
        if kind != "response" or msg.get("cseq_method") != "INVITE" or not isinstance(status, int):
            return False
        # The newest INVITE of the end this response went to; a response to an address that sent no INVITE here
        # (a capture that missed it) is held against the newest INVITE of any sender, the best evidence there is.
        newest = call.invite_cseq.get(dst)
        if newest is None and call.invite_cseq:
            newest = max(call.invite_cseq.values())
        if cseq is not None and newest is not None and cseq < newest:
            return False                     # a late or repeated answer to an INVITE a newer one has replaced
        if status >= 200:
            call.status = status
        if status in (180, 183) and call.state == "calling":
            call.state = "ringing"
            return True
        if call.state not in ("calling", "ringing"):
            return False
        if 200 <= status < 300:
            call.state, call.answer_ts = "answered", ts
            return True
        if status >= 400:
            call.state, call.end_ts = "failed", ts
            return True
        return False

    def _learn_media(self, call: _Call, sdp: Dict[str, Any], src: Any) -> None:
        """Record the ``(ip, port)`` pairs an SDP offer or answer names, so RTP can be matched to this call."""
        session = sdp.get("connection")
        media = sdp.get("media")
        for entry in media if isinstance(media, list) else ():
            if not isinstance(entry, dict):
                continue
            port, address = entry.get("port"), entry.get("connection") or session
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                continue
            if not isinstance(address, str) or address in _WILDCARD_ADDRESSES:
                address = str(src)
            endpoint = (address, port)
            if endpoint not in self._endpoints and len(self._endpoints) >= MAX_EXPECTED:
                continue
            self._endpoints[endpoint] = call.call_id
            call.media.add(endpoint)
            names = entry.get("rtpmap")
            if isinstance(names, dict) and names:
                self._rtpmap[endpoint] = dict(list(names.items())[:MAX_FORMATS])

    def _codec(self, payload_type: int, *endpoints: Tuple[str, int]) -> str:
        entry = PAYLOAD_TYPES.get(payload_type)
        if entry is not None:
            return entry[0]
        for endpoint in endpoints:
            name = (self._rtpmap.get(endpoint) or {}).get(payload_type)
            if name:
                return name.split("/")[0][:MAX_TEXT]
        return f"PT {payload_type}"

    def _rtpmap_rate(self, payload_type: int, *endpoints: Tuple[str, int]) -> Optional[int]:
        """The RTP clock rate an SDP rtpmap gives a payload type: ``opus/48000/2`` -> 48000 (RFC 4566 section 6: the
        field after the encoding name is the RTP timestamp clock rate), else None."""
        for endpoint in endpoints:
            name = (self._rtpmap.get(endpoint) or {}).get(payload_type)
            if not isinstance(name, str):
                continue
            parts = name.split("/")
            rate = _int(parts[1].strip()) if len(parts) > 1 else None
            if rate is not None and 1 <= rate <= MAX_CLOCK_RATE:
                return rate
        return None

    def _find(self, call_id: Any) -> Optional[_Call]:
        if not isinstance(call_id, str) or not call_id:
            return None
        found = self._calls.get(call_id)
        return found if found is not None else self._calls.get(self._slugs.get(call_id, ""))

    def _call_streams(self, call: _Call) -> List[_Stream]:
        """The call's RTP streams, oldest first: either end of the stream is one of the call's media addresses."""
        found = [stream for stream in self._streams.values()
                 if (stream.dst, stream.dport) in call.media or (stream.src, stream.sport) in call.media]
        found.sort(key=lambda stream: (stream.first_ts, stream.id))
        return found[:MAX_STREAMS_PER_CALL]

    def _call_dict(self, call: _Call) -> Dict[str, Any]:
        streams = self._call_streams(call)
        last = max([call.last_ts] + [stream.last_ts for stream in streams])
        end = call.end_ts if call.end_ts is not None else last
        start = call.answer_ts if call.answer_ts is not None else call.start_ts
        return _shaped(CALL_KEYS, {
            "id": call.id, "call_id": call.call_id, "from_uri": call.from_uri, "to_uri": call.to_uri,
            "state": call.state, "start_ts": call.start_ts, "answer_ts": call.answer_ts, "end_ts": call.end_ts,
            "duration_s": round(max(0.0, end - start), 3), "status": call.status, "messages": list(call.messages),
            "streams": [_stream_dict(stream) for stream in streams], "note": _note(streams)})


def _note(streams: Sequence[_Stream]) -> Optional[str]:
    """Why a call has no audio to play, or None when it has."""
    if not streams:
        return "no RTP was seen for this call"
    if any(decodable(stream.payload_type) for stream in streams):
        return None
    codecs = sorted({stream.codec for stream in streams})
    return f"the audio is {', '.join(codecs)} and cannot be rebuilt here"


def _jitter_measured(stream: _Stream) -> bool:
    """True when the jitter estimate stands for the stream: every step of a short one, or :data:`MIN_JITTER_STEPS`.

    A dynamic payload type's clock rate can arrive late (an rtpmap first seen in a re-INVITE near the end), and the
    estimator then ran over only the last few packets. It starts at zero and moves a sixteenth of the way per step,
    so a handful of steps reads as a smooth stream whatever the audio did, and the call would be called clean."""
    if not stream.rate or stream.jitter_steps < 1:
        return False
    return stream.jitter_steps >= min(MIN_JITTER_STEPS, stream.packets - 1)


def _stream_dict(stream: _Stream) -> Dict[str, Any]:
    return _shaped(STREAM_KEYS, {
        "id": stream.id, "src": stream.src, "sport": stream.sport, "dst": stream.dst, "dport": stream.dport,
        "ssrc": stream.ssrc, "payload_type": stream.payload_type, "codec": stream.codec, "packets": stream.packets,
        "lost": stream.lost, "out_of_order": stream.out_of_order, "first_ts": stream.first_ts,
        "last_ts": stream.last_ts, "duration_s": round(max(0.0, stream.last_ts - stream.first_ts), 3),
        "bytes": stream.bytes,
        "jitter_ms": round(stream.jitter / stream.rate * 1000.0, 3) if _jitter_measured(stream) else None,
        "decodable": decodable(stream.payload_type)})


def _stream_id(source: Tuple[str, int], destination: Tuple[str, int], ssrc: int) -> str:
    """A URL-safe id for one direction of one SSRC: the SSRC in hex and a short digest of the two ends."""
    raw = f"{source[0]}:{source[1]}>{destination[0]}:{destination[1]}#{ssrc}".encode("utf-8", errors="replace")
    return f"{ssrc & 0xFFFFFFFF:08x}-{hashlib.sha256(raw).hexdigest()[:10]}"


def _number(value: Any) -> Optional[float]:
    """*value* as a float when it is a finite number, else None.

    A NaN or an infinity is a float and would pass an ``isinstance`` guard, but it poisons every timestamp it
    reaches: ``int(round(nan))`` raises ValueError and ``int(round(inf))`` OverflowError where a recording is placed,
    and both serialise to invalid JSON. A capture file read off disk is untrusted, so they are turned away here."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):      # an int too large for a float
        return None
    return number if math.isfinite(number) else None


def _port(value: Any) -> int:
    return value & 0xFFFF if isinstance(value, int) and not isinstance(value, bool) else 0
