r"""Multicast DNS and DNS-based service discovery: what a device says it is (ProAV page, ARCHITECTURE §3.27).

Original code written from RFC 1035 (the DNS message format, name compression and the A / PTR / TXT record types),
RFC 2782 (SRV), RFC 3596 (AAAA), RFC 6762 (multicast DNS: the group, the port, the cache-flush and unicast-response
bits, the ``.local`` namespace) and RFC 6763 (DNS-SD: the ``_service._proto.domain`` shape, the PTR -> SRV -> TXT ->
A chain, the ``key=value`` TXT convention and the ``_services._dns-sd._udp`` meta-query).  Nothing is taken from any
other implementation.

Why a tool that wants to find pro-audio gear starts here
--------------------------------------------------------
Dante, Q-SYS, Ravenna, NMOS and most AV control surfaces publish themselves over mDNS, so one multicast question
answers "what is on this network" for gear that answers no ping and has every TCP port shut.  The honest way to ask
is the DNS-SD **meta-query** (:data:`META_QUERY`): instead of guessing at service names, it asks the link to list the
service types it has, and :mod:`tnt.proav` classifies whatever comes back.  A short list of well-known types
(:data:`SEED_QUERIES`) is asked directly as well, because some devices answer a direct question and ignore the
meta-query.

Nothing here opens a socket, resolves a name or logs: :func:`build_query` returns bytes to send and :func:`parse`
turns bytes received into records.  :mod:`tnt.proav` does the listening.

Building a question (:func:`build_query`)
-----------------------------------------
``build_query(["_services._dns-sd._udp.local", "_netaudio-arc._udp.local"])`` is one standard query (id 0, no flags)
with one PTR question per name, in the order given, asked over multicast (the QU bit is left clear, so replies go to
the group and every listener - this tool included - sees them).  Names are capped at :data:`MAX_NAMES` and a name
with a label longer than 63 octets, or over 255 octets in total, is left out rather than truncated.  No compression
is used in a question: it costs nothing here and some embedded responders handle it badly.

Reading an answer (:func:`parse`)
---------------------------------
``parse(payload)`` returns a MESSAGE dict or None (too short, or a message this module cannot read).  Both questions
and records are returned; a response and a request are told apart by ``response``.  All four record sections are read
into one ``records`` list, because mDNS puts the SRV/TXT/A of an answer in the additional section as often as not and
nothing downstream cares which section a fact arrived in.

MESSAGE dict (keys in this order, :data:`MESSAGE_KEYS`)::

    {"id": int, "response": bool, "questions": [QUESTION], "records": [RECORD], "truncated": bool}
    QUESTION = {"name": str, "type": str, "unicast": bool}
    RECORD   = {"name": str, "type": str, "ttl": int, "flush": bool, "value": Any}

``type`` is the text of :data:`RECORD_TYPES` ("A", "PTR", "TXT", "SRV", "AAAA", "NSEC") or ``"type <n>"`` for one this
module does not read.  ``value`` depends on the type:

===========  ==============================================================================================
type         value
===========  ==============================================================================================
``A``        dotted IPv4 text
``AAAA``     IPv6 text (compressed, lowercase)
``PTR``      the pointed-to name
``SRV``      ``{"priority", "weight", "port", "target"}``
``TXT``      ``{key: value|None}`` - a key with no ``=`` is None; the first spelling of a repeated key wins
other        None (the record is reported but its data is not decoded)
===========  ==============================================================================================

Names are decompressed (RFC 1035 clause 4.1.4).  A pointer that goes forward or sideways rather than strictly
backwards, a chain longer than :data:`MAX_POINTERS`, or a name over 255 octets ends that name: the message is still
returned with the records read so far.  Text is decoded as UTF-8 with ``errors="replace"``, and trailing dots are
kept off (``"Mixer._netaudio-arc._udp.local"``, not ``"...local."``), which is what every other name in TNT looks
like.  A message is capped at :data:`MAX_RECORDS` records and :data:`MAX_QUESTIONS` questions.

Service names (:func:`split_service`, :func:`instance_name`)
-------------------------------------------------------------
``split_service("Mixer 1._netaudio-arc._udp.local")`` is ``("Mixer 1", "_netaudio-arc._udp.local")``; a name that is
a bare service type gives ``(None, name)``.  DNS-SD escapes ``.`` and ``\`` inside an instance label, and
:func:`instance_name` unescapes them, so a device called ``Rack 2.1`` reads back as it was meant to.
"""

from __future__ import annotations

import ipaddress
import struct
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["MESSAGE_KEYS", "QUESTION_KEYS", "RECORD_KEYS", "RECORD_TYPES", "GROUP_V4", "GROUP_V6", "PORT",
           "META_QUERY", "SEED_QUERIES", "MAX_NAMES", "MAX_RECORDS", "MAX_QUESTIONS", "MAX_POINTERS",
           "build_query", "parse", "split_service", "instance_name", "service_proto"]

MESSAGE_KEYS = ("id", "response", "questions", "records", "truncated")
QUESTION_KEYS = ("name", "type", "unicast")
RECORD_KEYS = ("name", "type", "ttl", "flush", "value")

GROUP_V4 = "224.0.0.251"
GROUP_V6 = "ff02::fb"
PORT = 5353

#: The DNS-SD service-type enumeration: "list the service types you have" (RFC 6763 clause 9).
META_QUERY = "_services._dns-sd._udp.local"

#: Asked directly as well as through the meta-query, because some responders answer only a direct question.  These
#: are the types most likely to matter on an AV network; the meta-query is what actually finds the rest, and
#: ``tnt.proav.FAMILIES`` classifies whatever comes back rather than relying on this list being complete.
SEED_QUERIES: Tuple[str, ...] = (
    META_QUERY,
    "_netaudio-arc._udp.local",       # Dante: the device's own control service (Audinate Routing Control)
    "_netaudio-cmc._udp.local",       # Dante: connection management
    "_netaudio-chan._udp.local",      # Dante: channel names
    "_netaudio-dbc._udp.local",       # Dante: device brokered control
    "_nmos-node._tcp.local",          # AMWA NMOS IS-04 (SMPTE ST 2110 estates)
    "_nmos-register._tcp.local",
    "_nmos-query._tcp.local",
    "_ravenna._tcp.local",            # Ravenna / AES67
    "_rtsp._tcp.local",               # Ravenna session description, and cameras
    "_qsys._tcp.local",               # QSC Q-SYS
    "_axia-livewire._tcp.local",      # Telos/Axia Livewire (broadcast radio)
    "_http._tcp.local",               # the device web UI most AV gear has
    "_workstation._tcp.local",        # control PCs on the segment
)

#: Record types this module decodes.  Anything else is reported as ``"type <n>"`` with a ``value`` of None.
RECORD_TYPES: Dict[int, str] = {1: "A", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV", 47: "NSEC", 255: "ANY"}
_TYPE_A, _TYPE_PTR, _TYPE_TXT, _TYPE_AAAA, _TYPE_SRV = 1, 12, 16, 28, 33
_QTYPE_PTR = 12
_CLASS_IN = 1
_FLUSH_BIT = 0x8000                 # the cache-flush bit of a record's class (RFC 6762 clause 10.2)
_UNICAST_BIT = 0x8000               # the QU bit of a question's class (RFC 6762 clause 5.4)
_HEADER = 12
_POINTER = 0xC0
_FLAG_RESPONSE = 0x8000
_FLAG_TRUNCATED = 0x0200

MAX_NAMES = 32                      # questions one query may carry
MAX_RECORDS = 512                   # records read from one message
MAX_QUESTIONS = 64
MAX_POINTERS = 16                   # compression-pointer hops followed before a name is given up on
MAX_NAME_OCTETS = 255
MAX_LABEL = 63
MAX_TXT_KEYS = 64
MAX_TEXT = 255


def _split_labels(name: str) -> List[str]:
    r"""A presentation-format name split on its *unescaped* dots, so ``"Rack 2\.1._http._tcp.local"`` is four
    labels and not five.  The labels keep their escapes; :func:`instance_name` is what takes them off."""
    labels: List[str] = []
    current: List[str] = []
    i = 0
    clean = name.rstrip(".")
    while i < len(clean):
        ch = clean[i]
        if ch == "\\" and i + 1 < len(clean):
            current.append(ch)
            current.append(clean[i + 1])
            i += 2
            continue
        if ch == ".":
            labels.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    labels.append("".join(current))
    return labels


def _escape_label(text: str) -> str:
    r"""One wire label as presentation text: ``\`` and ``.`` are escaped, so a label is always one dotted part."""
    return text.replace("\\", "\\\\").replace(".", "\\.")


def _encode_name(name: str) -> Optional[bytes]:
    """A dotted name as DNS wire labels, or None when it does not fit the format."""
    out = bytearray()
    total = 1
    for label in _split_labels(name):
        raw = instance_name(label).encode("utf-8", "replace")
        if not raw or len(raw) > MAX_LABEL:
            return None
        total += 1 + len(raw)
        if total > MAX_NAME_OCTETS:
            return None
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def build_query(names: Any, *, unicast: bool = False, ident: int = 0) -> bytes:
    """One mDNS query asking for the PTR of each name, in order.

    ``unicast`` sets the QU bit, which asks responders to reply straight back to this socket instead of to the group.
    The default is off: a multicast reply is what the rest of the link expects and it lets this tool hear the answers
    other devices' questions produce as well.  Names that do not fit the DNS format are left out; at most
    :data:`MAX_NAMES` are asked."""
    wanted = [n for n in list(names)[:MAX_NAMES] if isinstance(n, str) and n]
    encoded = [raw for raw in (_encode_name(n) for n in wanted) if raw is not None]
    qclass = _CLASS_IN | (_UNICAST_BIT if unicast else 0)
    out = bytearray(struct.pack(">HHHHHH", ident & 0xFFFF, 0, len(encoded), 0, 0, 0))
    for raw in encoded:
        out += raw
        out += struct.pack(">HH", _QTYPE_PTR, qclass)
    return bytes(out)


def _read_name(data: bytes, at: int) -> Tuple[Optional[str], int]:
    """The name at ``at`` and the offset just past it in the record stream.

    A compression pointer is followed (strictly backwards only, at most :data:`MAX_POINTERS` hops) but never advances
    the returned offset past the first pointer, which is what RFC 1035 clause 4.1.4 asks for."""
    labels: List[str] = []
    end = -1
    hops = 0
    octets = 0
    here = at
    size = len(data)
    while True:
        if here >= size:
            return None, size
        length = data[here]
        if length == 0:
            here += 1
            break
        if length & _POINTER == _POINTER:
            if here + 1 >= size:
                return None, size
            target = ((length & 0x3F) << 8) | data[here + 1]
            if end < 0:
                end = here + 2
            hops += 1
            if hops > MAX_POINTERS or target >= here:       # forwards or sideways: a loop, or a malformed message
                return None, end
            here = target
            continue
        if length > MAX_LABEL:
            return None, end if end >= 0 else here + 1
        start = here + 1
        if start + length > size:
            return None, size
        octets += 1 + length
        if octets > MAX_NAME_OCTETS:
            return None, end if end >= 0 else start + length
        labels.append(_escape_label(data[start:start + length].decode("utf-8", "replace")))
        here = start + length
    return ".".join(labels), (end if end >= 0 else here)


def _txt_value(raw: bytes) -> Dict[str, Optional[str]]:
    """A TXT record's ``key=value`` strings as a dict (RFC 6763 clause 6).  The first spelling of a key wins."""
    out: Dict[str, Optional[str]] = {}
    at = 0
    while at < len(raw) and len(out) < MAX_TXT_KEYS:
        length = raw[at]
        at += 1
        if length == 0 or at + length > len(raw):
            at += length
            continue
        item = raw[at:at + length]
        at += length
        split = item.find(b"=")
        if split < 0:
            key, value = item.decode("utf-8", "replace"), None
        else:
            key = item[:split].decode("utf-8", "replace")
            value = item[split + 1:].decode("utf-8", "replace")[:MAX_TEXT]
        key = key.strip()
        if key and key not in out:
            out[key] = value
    return out


def _record_value(kind: int, data: bytes, at: int, length: int) -> Any:
    raw = data[at:at + length]
    if kind == _TYPE_A and length == 4:
        return ".".join(str(b) for b in raw)
    if kind == _TYPE_AAAA and length == 16:
        try:
            return str(ipaddress.IPv6Address(raw))
        except ValueError:
            return None
    if kind == _TYPE_PTR:
        name, _ = _read_name(data, at)
        return name
    if kind == _TYPE_TXT:
        return _txt_value(raw)
    if kind == _TYPE_SRV and length >= 7:
        priority, weight, port = struct.unpack_from(">HHH", data, at)
        target, _ = _read_name(data, at + 6)
        return {"priority": priority, "weight": weight, "port": port, "target": target}
    return None


def parse(payload: bytes) -> Optional[Dict[str, Any]]:
    """One mDNS message as a MESSAGE dict, or None when it cannot be read at all.  Never raises."""
    data = bytes(payload)
    if len(data) < _HEADER:
        return None
    try:
        ident, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(">HHHHHH", data, 0)
    except struct.error:
        return None
    questions: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []
    at = _HEADER
    try:
        for _ in range(min(qdcount, MAX_QUESTIONS)):
            name, at = _read_name(data, at)
            if name is None or at + 4 > len(data):
                at = len(data)
                break
            qtype, qclass = struct.unpack_from(">HH", data, at)
            at += 4
            questions.append({"name": name, "type": RECORD_TYPES.get(qtype, f"type {qtype}"),
                              "unicast": bool(qclass & _UNICAST_BIT)})
        wanted = min(ancount + nscount + arcount, MAX_RECORDS)
        for _ in range(wanted):
            name, at = _read_name(data, at)
            if name is None or at + 10 > len(data):
                break
            kind, klass, ttl, length = struct.unpack_from(">HHIH", data, at)
            at += 10
            if at + length > len(data):
                break
            records.append({"name": name, "type": RECORD_TYPES.get(kind, f"type {kind}"), "ttl": ttl,
                            "flush": bool(klass & _FLUSH_BIT), "value": _record_value(kind, data, at, length)})
            at += length
    except (struct.error, IndexError, ValueError):
        pass                                    # keep what was read: a malformed tail never loses the good records
    return {"id": ident, "response": bool(flags & _FLAG_RESPONSE), "questions": questions, "records": records,
            "truncated": bool(flags & _FLAG_TRUNCATED)}


def service_proto(name: str) -> Optional[str]:
    """The ``_service._proto`` part of a DNS-SD name, or None when it has none.

    ``"Mixer._netaudio-arc._udp.local"`` and ``"_netaudio-arc._udp.local"`` both give ``"_netaudio-arc._udp"``."""
    labels = _split_labels(name)
    for i in range(len(labels) - 1):
        if labels[i].startswith("_") and labels[i + 1] in ("_tcp", "_udp"):
            return labels[i] + "." + labels[i + 1]
    return None


def instance_name(label: str) -> str:
    r"""A DNS-SD instance label with its escapes undone (``"Rack 2\.1"`` -> ``"Rack 2.1"``)."""
    out: List[str] = []
    i = 0
    while i < len(label):
        ch = label[i]
        if ch == "\\" and i + 1 < len(label):
            nxt = label[i + 1]
            if nxt.isdigit() and label[i + 1:i + 4].isdigit() and len(label[i + 1:i + 4]) == 3:
                try:
                    out.append(chr(int(label[i + 1:i + 4])))
                    i += 4
                    continue
                except ValueError:
                    pass
            out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def split_service(name: str) -> Tuple[Optional[str], str]:
    """``(instance, service type)`` of a DNS-SD name; ``instance`` is None for a bare service type.

    The instance label is unescaped (:func:`instance_name`); the service type keeps its domain
    (``"_netaudio-arc._udp.local"``)."""
    clean = name.rstrip(".")
    labels = _split_labels(clean)
    for i in range(len(labels) - 1):
        if labels[i].startswith("_") and labels[i + 1] in ("_tcp", "_udp"):
            if i == 0:
                return None, clean
            return instance_name(".".join(labels[:i])), ".".join(labels[i:])
    return None, clean
