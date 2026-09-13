"""Quick network tools: the Tools page's DNS lookup and the top bar's IP Release/Renew and Flush DNS.

Three commands a technician types by hand -- ``nslookup <name> [<server>]``, ``ipconfig /flushdns`` and
``ipconfig /release`` + ``ipconfig /renew`` -- done the way TNT does the rest: natively, because the console
tools print localised text.

* :func:`dns_lookup` is a small stdlib DNS client.  Like nslookup it asks a DNS server directly (never the hosts
  file or the Windows cache): the server given (an IP literal as is, a host name resolved first with
  ``getaddrinfo``), else this PC's own -- the internet adapter's first DNS server from :mod:`tnt.netinfo` (IPv4
  first), else the first DNS server of any up adapter.  Without a record type (Auto) a name gets an ``A`` and an
  ``AAAA`` query (the CNAME chain in the answers is followed) and an IP literal a ``PTR`` query (``in-addr.arpa`` /
  ``ip6.arpa``).  A record type from :data:`DNS_TYPES` (``nslookup -type=MX``) is one query of that type, the
  CNAME chain followed the same way; an IP literal takes only ``PTR`` (:data:`IP_TYPE_TEXT`).  The pseudo-type
  ``"ALL"`` (``nslookup`` has no equal) fans out one query per type in :data:`ALL_TYPES` and merges the answers into
  one result (an IP literal is still a ``PTR`` lookup, as with Auto); the result ``type`` is ``"ALL"``.  UDP with a
  :data:`DNS_TIMEOUT_S` timeout and one retry, the same query over TCP when the reply is truncated; a random query
  id the reply must carry (any other datagram is ignored).  The resolver's own name is a PTR lookup of its address
  on the same server with a short timeout (null when that fails).
* :func:`flush_dns` calls ``DnsFlushResolverCache()`` in ``dnsapi.dll``.
* :func:`release_renew` reads ``GetInterfaceInfo`` and calls ``IpReleaseAddress`` for every up, DHCP-enabled IPv4
  adapter (decided with :mod:`tnt.netinfo`), then ``IpRenewAddress`` for each of them: the adapters
  ``ipconfig /release`` and ``/renew`` act on.  Each native call runs on a helper thread bounded by
  :data:`RELEASE_TIMEOUT_S` / :data:`RENEW_TIMEOUT_S`, so a stuck DHCP client cannot hold the API request, the
  engine's lock and paused monitoring for ever.

Only when ``dnsapi.dll`` / ``iphlpapi.dll`` cannot be loaded (:class:`NativeUnavailable`) do the last two run
``%SystemRoot%\\System32\\ipconfig.exe`` instead, with the conventions of :mod:`tnt.firewall`: never PATH, an
argv list, no shell, ``CREATE_NO_WINDOW``, ``stdin=DEVNULL``, a timeout and OEM decoding through
``tnt.arp._decode_console``.

Shapes (keys in this order; :data:`DNS_RESULT_KEYS`, :data:`FLUSH_RESULT_KEYS`, :data:`RENEW_RESULT_KEYS`)::

    DNS_RESULT   = {"name", "type": null|one of DNS_TYPES|"ALL", "server", "resolver": {"name", "address"},
                    "answer_name", "addresses", "aliases", "records": [{"type": one of DNS_TYPES, "name", "value", "ttl"}],
                    "authoritative", "ok", "error", "duration_ms", "ts"}
    FLUSH_RESULT = {"ok", "method": "native"|"ipconfig", "error", "duration_ms", "ts"}
    RENEW_RESULT = {"ok", "address", "adapter", "adapters": [{"name", "released", "renewed", "error"}],
                    "warnings", "paused_monitoring", "method": "native"|"ipconfig", "error", "duration_ms", "ts"}

Record values, with their fields in the order dig prints them and names without the trailing dot (a name inside
the data may be compressed; the root is ``.``): A and AAAA the address; CNAME, NS and PTR the name; MX
``preference exchange``; TXT the strings joined with nothing between them, unquoted; SOA ``mname rname serial
refresh retry expire minimum``; SRV ``priority weight port target``; CAA ``flags tag "value"``; NAPTR ``order
preference "flags" "services" "regexp" replacement``.  TXT text, the CAA value and the NAPTR strings get ``\\`` ->
``\\\\`` and ``"`` -> ``\\"`` on the raw bytes first and are then decoded as UTF-8 with ``backslashreplace``
(escaping first keeps a backslash in the text apart from ``\\xNN``, a byte that is not UTF-8).  Duplicate records
are listed once; TXT, CAA and NAPTR values keep their case when compared, names and the other values do not.

Contract gaps filled here: a reverse lookup without a PTR record says :data:`NO_PTR_TEXT`; RCODEs other than the
named ones are "Format error", "Not implemented" or "DNS error code N"; when the A and AAAA queries fail
differently the most specific reason wins (NXDOMAIN, SERVFAIL, REFUSED, another RCODE, an empty answer, an
unreadable reply, no reply).  The AAAA query is skipped after an A query that got no reply or NXDOMAIN, and the
resolver-name lookup when the server never answered.  Known limits: the authority section is not read, so an SOA
or NS lookup of a name below its zone says :data:`NO_RECORDS_TEXT` where nslookup shows the zone's SOA; a
truncated reply that TCP cannot fetch again is used as it is (a large TXT set may then say NO_RECORDS_TEXT too).
``RENEW_RESULT["error"]`` is the first renew failure (``"<adapter>: <text>"``) when the internet adapter still has
an address but no adapter renewed; with the ipconfig fallback ``adapters`` is empty and ``warnings`` are the
output lines that report an error.

Nothing here raises except ``ValueError`` from the validators (and the lookup that calls them).  Seams (keyword
arguments): ``clock`` (wall time for ``ts``), ``runner`` (a ``subprocess.run`` stand-in for ipconfig), ``api``
(:class:`NetApi`: ``flush_cache() / interfaces() / release(index, name) / renew(index, name)``), ``adapters_fn``
and ``address_fn`` (the :mod:`tnt.netinfo` reads), and for the DNS client ``port``, ``timeout_s``, ``sockets``
(anything with the ``socket`` module's ``socket()`` and ``getaddrinfo()``) and ``system_server``.  Logging: one
INFO line per action (outcome and duration, no names or addresses); details at DEBUG.
"""
from __future__ import annotations

import ctypes
import importlib
import ipaddress
import logging
import os
import re
import secrets
import socket
import struct
import subprocess
import threading
import time
from ctypes import POINTER, Structure, byref, c_long, c_ulong, c_void_p, c_wchar
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

log = logging.getLogger(__name__)

__all__ = [
    "validate_name", "validate_server", "validate_type", "validate_lookup", "dns_lookup", "flush_dns", "release_renew",
    "default_dns_server", "build_query", "parse_message", "encode_name", "reverse_name", "read_interface_info",
    "ipconfig_exe", "NetApi", "NativeUnavailable", "DnsFormatError", "IP_ADAPTER_INDEX_MAP", "IP_INTERFACE_INFO",
    "DNS_TYPES", "ALL_TYPES", "DNS_RESULT_KEYS", "DNS_RECORD_KEYS", "FLUSH_RESULT_KEYS", "RENEW_RESULT_KEYS", "RENEW_ADAPTER_KEYS",
    "DNS_PORT", "DNS_TIMEOUT_S", "DNS_TRIES", "RESOLVER_NAME_TIMEOUT_S", "RELEASE_TIMEOUT_S", "RENEW_TIMEOUT_S",
    "FLUSH_TIMEOUT_S",
]

DNS_PORT = 53
#: Seconds one UDP attempt waits for the reply; :data:`DNS_TRIES` attempts (one retry).
DNS_TIMEOUT_S = 2.0
DNS_TRIES = 2
#: The PTR lookup of the resolver's own address gets one attempt of at most this long.
RESOLVER_NAME_TIMEOUT_S = 1.0
RELEASE_TIMEOUT_S = 60.0
RENEW_TIMEOUT_S = 120.0
FLUSH_TIMEOUT_S = 30.0
NAME_MAX = 253
#: How much of a rejected name the ValueError text repeats.
SHOWN_MAX = 80
WARNINGS_MAX = 10
WARNING_CHARS = 200

#: The record types a lookup can ask for, in the order the Tools page lists them (none is Auto: A + AAAA, or PTR).
DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "PTR", "NAPTR")
#: The pseudo-type ``"ALL"`` fans these out (one query each, in this order; PTR is left out, it is only for addresses).
ALL_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "NAPTR")
DNS_RESULT_KEYS = ("name", "type", "server", "resolver", "answer_name", "addresses", "aliases", "records",
                   "authoritative", "ok", "error", "duration_ms", "ts")
DNS_RECORD_KEYS = ("type", "name", "value", "ttl")
FLUSH_RESULT_KEYS = ("ok", "method", "error", "duration_ms", "ts")
RENEW_RESULT_KEYS = ("ok", "address", "adapter", "adapters", "warnings", "paused_monitoring", "method", "error",
                     "duration_ms", "ts")
RENEW_ADAPTER_KEYS = ("name", "released", "renewed", "error")

EMPTY_NAME_TEXT = "Type a DNS name or IP address to look up"
NO_SERVER_TEXT = "No DNS server is configured on this PC"
TIMEOUT_TEXT = "No response from the DNS server (timed out)"
NO_ADDRESSES_TEXT = "No addresses found for this name"
NO_PTR_TEXT = "No name found for this address"
#: A typed lookup that found no record of its type: ``NO_RECORDS_TEXT.format("MX")``.
NO_RECORDS_TEXT = "No {} records found for this name"
#: An IP literal with a record type other than PTR.
IP_TYPE_TEXT = "An IP address is looked up as PTR: type a DNS name to ask for other record types"
#: A record type that is not in :data:`DNS_TYPES`: ``BAD_TYPE_TEXT.format(<the value trimmed, at most 80 characters>)``.
BAD_TYPE_TEXT = '"{}" is not a DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR or NAPTR)'
UNREADABLE_TEXT = "The DNS server's answer could not be read"
FLUSH_FAILED_TEXT = "Windows did not flush the DNS cache"
NO_DHCP_ADAPTER_TEXT = "No adapter gets its address from DHCP"
NO_ADDRESS_TEXT = "No IPv4 address after renewing: the DHCP server did not answer"
IPCONFIG_MISSING_TEXT = "ipconfig is not available"
RCODE_TEXT: Dict[int, str] = {1: "Format error", 2: "Server failed", 3: "Non-existent domain", 4: "Not implemented",
                              5: "Query refused"}

TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_SOA, TYPE_PTR, TYPE_MX, TYPE_TXT = 1, 2, 5, 6, 12, 15, 16
TYPE_AAAA, TYPE_SRV, TYPE_NAPTR, TYPE_CAA = 28, 33, 35, 257
CLASS_IN = 1
#: The record types that are read; :func:`parse_message` skips every other answer.
TYPE_NAMES: Dict[int, str] = {TYPE_A: "A", TYPE_AAAA: "AAAA", TYPE_CNAME: "CNAME", TYPE_MX: "MX", TYPE_TXT: "TXT",
                              TYPE_NS: "NS", TYPE_SOA: "SOA", TYPE_SRV: "SRV", TYPE_CAA: "CAA", TYPE_PTR: "PTR",
                              TYPE_NAPTR: "NAPTR"}
TYPE_CODES: Dict[str, int] = {name: code for code, name in TYPE_NAMES.items()}
#: Values that keep their case when duplicate records are dropped: text, where names ignore case.
_CASE_KEPT = ("TXT", "CAA", "NAPTR")
#: RFC 8659: a CAA tag is 1-15 octets.
_CAA_TAG_MAX = 15
RCODE_NOERROR, RCODE_SERVFAIL, RCODE_NXDOMAIN, RCODE_REFUSED = 0, 2, 3, 5
_MAX_POINTERS = 64
_MAX_CHAIN = 16
_CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)
#: A host-name label: letters, digits, ``_`` and ``-``, 1-63 characters, not starting or ending with ``-``.
_LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")

Outcome = Tuple[str, Optional[Dict[str, Any]]]     # ("reply", message) | ("unreadable", None) | ("timeout", None)


# --- validation ---------------------------------------------------------------------------------
def _validate(text: Any, what: str) -> Optional[str]:
    """The shared name rules; ``None`` for an empty value (the callers decide what that means)."""
    if text is None:
        return None
    if not isinstance(text, str):
        raise ValueError(f'"{str(text)[:SHOWN_MAX]}" is not {what}')
    s = text.strip()
    if not s:
        return None
    invalid = ValueError(f'"{s[:SHOWN_MAX]}" is not {what}')
    body = s[:-1] if s.endswith(".") else s
    try:
        return str(ipaddress.ip_address(body))
    except ValueError:
        pass
    if not body.isascii():
        try:
            body = body.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            raise invalid from None
    # a leading "-" would be an option to a console tool: never a name here either
    if not body or len(body) > NAME_MAX or body.startswith("-") \
            or not all(_LABEL_RE.fullmatch(label) for label in body.split(".")):
        raise invalid
    return body


def validate_name(text: Any) -> str:
    """The name to look up: an IPv4/IPv6 literal (a reverse lookup) or a host name (one trailing dot allowed,
    non-ASCII converted with the ``idna`` codec).  ``ValueError`` with the text the UI shows."""
    name = _validate(text, "a DNS name or IP address")
    if name is None:
        raise ValueError(EMPTY_NAME_TEXT)
    return name


def validate_server(text: Any) -> Optional[str]:
    """The DNS server to ask, or ``None`` (empty: this PC's own).  Same rules as :func:`validate_name`."""
    return _validate(text, "a DNS server name or IP address")


def validate_type(text: Any) -> Optional[str]:
    """The record type to ask for: its upper-case name from :data:`DNS_TYPES`, or ``"ALL"`` (all record types at once)
    for ``"all"`` (any case), all trimmed; or ``None`` for Auto (``None``, empty or whitespace).  ``ValueError``
    :data:`BAD_TYPE_TEXT` for anything else, a non-string included."""
    if text is None:
        return None
    if isinstance(text, str):
        shown = text.strip()
        if not shown:
            return None
        if shown.upper() in DNS_TYPES or shown.upper() == "ALL":
            return shown.upper()
    else:
        shown = str(text).strip()
    raise ValueError(BAD_TYPE_TEXT.format(shown[:SHOWN_MAX]))


def validate_lookup(name: Any, server: Any = None, record_type: Any = None) -> Tuple[str, Optional[str], Optional[str]]:
    """``(name, server, type)`` of a lookup, checked in this order: :func:`validate_name`, :func:`validate_server`,
    :func:`validate_type`, then an IP literal with a type other than PTR (``ValueError`` :data:`IP_TYPE_TEXT`)."""
    qname = validate_name(name)
    srv = validate_server(server)
    rtype = validate_type(record_type)
    if rtype not in (None, "PTR", "ALL") and _is_ip(qname):
        raise ValueError(IP_TYPE_TEXT)
    return qname, srv, rtype


def _is_ip(text: Any) -> bool:
    try:
        ipaddress.ip_address(str(text))
        return True
    except ValueError:
        return False


# --- DNS messages -------------------------------------------------------------------------------
class DnsFormatError(ValueError):
    """A DNS message that cannot be read."""


def encode_name(name: str) -> bytes:
    """``example.com`` -> ``b"\\x07example\\x03com\\x00"`` (ASCII labels of 1-63 octets)."""
    out = bytearray()
    for label in str(name).rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 1 <= len(raw) <= 63:
            raise ValueError(f"invalid DNS label in {name!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def build_query(qid: int, name: str, qtype: int) -> bytes:
    """A standard query for *name* / *qtype* (class IN) with recursion desired, as nslookup sends it."""
    return struct.pack("!HHHHHH", int(qid) & 0xFFFF, 0x0100, 1, 0, 0, 0) + encode_name(name) \
        + struct.pack("!HH", int(qtype), CLASS_IN)


def reverse_name(address: str) -> str:
    """``8.8.8.8`` -> ``8.8.8.8.in-addr.arpa``; IPv6 -> the ``ip6.arpa`` nibble name (a zone is ignored)."""
    return ipaddress.ip_address(str(address).split("%", 1)[0]).reverse_pointer


def _read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """``(name, offset after it)``.  A compression pointer must point before itself, which also rules out loops."""
    labels: List[str] = []
    pos, end, jumps, octets = offset, None, 0, 0
    while True:
        if pos >= len(data):
            raise DnsFormatError("a name runs past the end of the message")
        length = data[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DnsFormatError("a compression pointer is cut off")
            target = ((length & 0x3F) << 8) | data[pos + 1]
            if target >= pos or jumps >= _MAX_POINTERS:
                raise DnsFormatError("a compression pointer does not point back")
            if end is None:
                end = pos + 2
            pos, jumps = target, jumps + 1
            continue
        if length & 0xC0:
            raise DnsFormatError("unsupported label type")
        pos += 1
        if length == 0:
            break
        if pos + length > len(data):
            raise DnsFormatError("a label runs past the end of the message")
        octets += length + 1
        if octets > 255:
            raise DnsFormatError("a name is longer than 255 octets")
        labels.append(data[pos:pos + length].decode("ascii", "backslashreplace"))
        pos += length
    return ".".join(labels), (end if end is not None else pos)


def _rdata_name(data: bytes, pos: int, rdata_end: int, exact: bool = False) -> Tuple[str, int]:
    """``(name, offset after it)`` of a name inside record data: compression is followed and the root shows as
    ``"."``.  ``DnsFormatError`` when it runs past the record (with *exact*, when it ends anywhere but there)."""
    name, end = _read_name(data, pos)
    if end > rdata_end:
        raise DnsFormatError("a name runs past its record")
    if exact and end != rdata_end:
        raise DnsFormatError("a name ends before its record does")
    return (name or "."), end


def _escape_text(raw: bytes) -> str:
    """Record text as shown: ``\\`` -> ``\\\\`` and ``"`` -> ``\\"`` on the raw bytes, then UTF-8 with
    ``backslashreplace`` (escaping first keeps a real backslash apart from a byte that is not UTF-8)."""
    return bytes(raw).replace(b"\\", b"\\\\").replace(b'"', b'\\"').decode("utf-8", "backslashreplace")


def _character_string(data: bytes, pos: int, rdata_end: int) -> Tuple[bytes, int]:
    """``(octets, offset after it)`` of a <character-string> (a length octet, then the octets) inside record data."""
    if pos >= rdata_end or pos + 1 + data[pos] > rdata_end:
        raise DnsFormatError("a string runs past its record")
    end = pos + 1 + data[pos]
    return data[pos + 1:end], end


def _rdata(data: bytes, rtype: int, pos: int, rdata_end: int) -> str:
    """The value of one record, in the formats of the module docstring; ``DnsFormatError`` when its data cannot be
    read."""
    size = rdata_end - pos
    if rtype in (TYPE_A, TYPE_AAAA):
        if size != (4 if rtype == TYPE_A else 16):
            raise DnsFormatError(f"an {TYPE_NAMES[rtype]} record of {size} octets")
        raw = data[pos:rdata_end]
        return str(ipaddress.IPv4Address(raw) if rtype == TYPE_A else ipaddress.IPv6Address(raw))
    if rtype in (TYPE_CNAME, TYPE_NS, TYPE_PTR):
        return _rdata_name(data, pos, rdata_end)[0]
    if rtype == TYPE_MX:        # PREFERENCE EXCHANGE (RFC 1035 3.3.9)
        if size < 3:
            raise DnsFormatError(f"an MX record of {size} octets")
        return f"{struct.unpack_from('!H', data, pos)[0]} {_rdata_name(data, pos + 2, rdata_end)[0]}"
    if rtype == TYPE_TXT:       # one or more <character-string>s (RFC 1035 3.3.14)
        parts: List[bytes] = []
        while pos < rdata_end:
            part, pos = _character_string(data, pos, rdata_end)
            parts.append(part)
        return _escape_text(b"".join(parts))        # joined first: a UTF-8 character may span two strings
    if rtype == TYPE_SOA:       # MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM (RFC 1035 3.3.13)
        mname, at = _rdata_name(data, pos, rdata_end)
        rname, at = _rdata_name(data, at, rdata_end)
        if rdata_end - at != 20:
            raise DnsFormatError(f"an SOA record with {rdata_end - at} octets after its names")
        return " ".join([mname, rname, *(str(n) for n in struct.unpack_from("!IIIII", data, at))])
    if rtype == TYPE_SRV:       # PRIORITY WEIGHT PORT TARGET (RFC 2782)
        if size < 7:
            raise DnsFormatError(f"an SRV record of {size} octets")
        priority, weight, port = struct.unpack_from("!HHH", data, pos)
        return f"{priority} {weight} {port} {_rdata_name(data, pos + 6, rdata_end)[0]}"
    if rtype == TYPE_CAA:       # FLAGS, TAG LENGTH, TAG, VALUE (RFC 8659 4.1)
        tag_len = data[pos + 1] if size >= 2 else 0
        if not 1 <= tag_len <= _CAA_TAG_MAX or pos + 2 + tag_len > rdata_end:
            raise DnsFormatError(f"a CAA record of {size} octets with a tag of {tag_len}")
        tag = data[pos + 2:pos + 2 + tag_len].decode("ascii", "backslashreplace")
        return f'{data[pos]} {tag} "{_escape_text(data[pos + 2 + tag_len:rdata_end])}"'
    if rtype == TYPE_NAPTR:     # ORDER PREFERENCE FLAGS SERVICES REGEXP REPLACEMENT (RFC 3403 4.1)
        if size < 8:
            raise DnsFormatError(f"a NAPTR record of {size} octets")
        order, preference = struct.unpack_from("!HH", data, pos)
        at, strings = pos + 4, [str(order), str(preference)]
        for _ in range(3):
            raw, at = _character_string(data, at, rdata_end)
            strings.append(f'"{_escape_text(raw)}"')
        return " ".join([*strings, _rdata_name(data, at, rdata_end, exact=True)[0]])
    raise DnsFormatError(f"records of type {rtype} are not read")


def parse_message(data: bytes) -> Dict[str, Any]:
    """``{"id", "qr", "aa", "tc", "rcode", "questions": [(name, qtype)], "answers": [RECORD]}`` of a DNS message.

    Only answers of class IN with a type in :data:`DNS_TYPES` are kept, each value read by :func:`_rdata` (the rest
    are skipped unread); the authority and additional sections are not read.  ``DnsFormatError`` when the message
    cannot be read."""
    data = bytes(data)
    if len(data) < 12:
        raise DnsFormatError("shorter than a DNS header")
    qid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack_from("!HHHHHH", data, 0)
    pos = 12
    questions: List[Tuple[str, int]] = []
    for _ in range(qdcount):
        qname, pos = _read_name(data, pos)
        if pos + 4 > len(data):
            raise DnsFormatError("a question is cut off")
        qtype, _qclass = struct.unpack_from("!HH", data, pos)
        pos += 4
        questions.append((qname, qtype))
    answers: List[Dict[str, Any]] = []
    for _ in range(ancount):
        rname, pos = _read_name(data, pos)
        if pos + 10 > len(data):
            raise DnsFormatError("a record is cut off")
        rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, pos)
        pos += 10
        rdata_end = pos + rdlength
        if rdata_end > len(data):
            raise DnsFormatError("record data runs past the end of the message")
        if rclass == CLASS_IN and rtype in TYPE_NAMES:
            answers.append({"type": TYPE_NAMES[rtype], "name": rname, "value": _rdata(data, rtype, pos, rdata_end),
                            "ttl": int(ttl)})
        pos = rdata_end
    return {"id": qid, "qr": bool(flags & 0x8000), "aa": bool(flags & 0x0400), "tc": bool(flags & 0x0200),
            "rcode": flags & 0x000F, "questions": questions, "answers": answers}


# --- DNS transport ------------------------------------------------------------------------------
def _match(data: bytes, qid: int, qname: str, qtype: int) -> Tuple[str, Optional[Dict[str, Any]]]:
    """``("reply", message)``; ``("unreadable", None)`` for a reply to this query that cannot be read; ``("stray",
    None)`` for a datagram that answers something else (another id, not a response, another question)."""
    if len(data) < 2 or struct.unpack_from("!H", data, 0)[0] != qid:
        return "stray", None
    try:
        msg = parse_message(data)
    except DnsFormatError:
        return "unreadable", None
    if not msg["qr"]:
        return "stray", None
    if msg["questions"] and not any(n.lower() == qname.lower() and t == qtype for n, t in msg["questions"]):
        return "stray", None
    return "reply", msg


def _close(sock: Any) -> None:
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass


def _udp_exchange(target: Tuple[Any, int, tuple], query: bytes, qname: str, qtype: int, timeout_s: float,
                  tries: int) -> Outcome:
    sockets, family, sockaddr = target
    qid = struct.unpack_from("!H", query, 0)[0]
    sock = None
    try:
        sock = sockets.socket(family, socket.SOCK_DGRAM)
        sock.connect(sockaddr)          # a connected socket only takes datagrams from the server
        for _attempt in range(max(1, int(tries))):
            try:
                sock.send(query)
            except OSError as exc:
                log.debug("sending the DNS query failed: %s", exc)
                continue
            deadline = time.monotonic() + float(timeout_s)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    sock.settimeout(remaining)
                    data = sock.recv(65535)
                except OSError:         # timed out, or "port unreachable" (ConnectionResetError on Windows)
                    break
                status, msg = _match(data, qid, qname, qtype)
                if status != "stray":
                    return status, msg
        return "timeout", None
    except OSError as exc:
        log.debug("DNS over UDP failed: %s", exc)
        return "timeout", None
    finally:
        _close(sock)


def _recv_exact(sock: Any, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise OSError("the DNS server closed the connection")
        buf += chunk
    return bytes(buf)


def _tcp_exchange(target: Tuple[Any, int, tuple], query: bytes, qname: str, qtype: int,
                  timeout_s: float) -> Optional[Outcome]:
    """The query again over TCP (the UDP reply was truncated); ``None`` when TCP gets nowhere."""
    sockets, family, sockaddr = target
    qid = struct.unpack_from("!H", query, 0)[0]
    sock = None
    try:
        sock = sockets.socket(family, socket.SOCK_STREAM)
        sock.settimeout(float(timeout_s))
        sock.connect(sockaddr)
        sock.sendall(struct.pack("!H", len(query)) + query)
        size = struct.unpack("!H", _recv_exact(sock, 2))[0]
        data = _recv_exact(sock, size)
    except OSError as exc:
        log.debug("DNS over TCP failed: %s", exc)
        return None
    finally:
        _close(sock)
    status, msg = _match(data, qid, qname, qtype)
    return ("unreadable", None) if status == "stray" else (status, msg)


def _exchange(target: Tuple[Any, int, tuple], qname: str, qtype: int, timeout_s: float, tries: int) -> Outcome:
    query = build_query(secrets.randbelow(0x10000), qname, qtype)
    status, msg = _udp_exchange(target, query, qname, qtype, timeout_s, tries)
    if status == "reply" and msg is not None and msg["tc"]:
        over_tcp = _tcp_exchange(target, query, qname, qtype, timeout_s)
        if over_tcp is not None:
            return over_tcp
    return status, msg


# --- DNS lookup ---------------------------------------------------------------------------------
def default_dns_server(adapters: Sequence[Any], internet_nic: Any) -> Optional[str]:
    """The DNS server a lookup without a server asks: the internet adapter's first one (IPv4 first), else the
    first one of any up adapter (IPv4 first); ``None`` when no adapter has one."""
    def first(adapter: Any) -> Optional[str]:
        servers = [str(s) for s in (getattr(adapter, "dns", None) or []) if _is_ip(s)]
        return next((s for s in servers if ":" not in s), None) or (servers[0] if servers else None)

    if internet_nic is not None:
        found = first(internet_nic)
        if found:
            return found
    for adapter in adapters or []:
        if getattr(adapter, "is_up", False) and not getattr(adapter, "is_loopback", False):
            found = first(adapter)
            if found:
                return found
    return None


def _system_dns_server() -> Optional[str]:
    try:
        netinfo = importlib.import_module("tnt.netinfo")
        adapters = netinfo.get_adapters(include_down=False)
        return default_dns_server(adapters, netinfo.get_internet_nic(adapters))
    except Exception:  # noqa: BLE001 - no adapters readable: no server
        log.debug("reading this PC's DNS servers failed", exc_info=True)
        return None


def _resolve_server(server: Optional[str], port: int, sockets: Any,
                    system_server: Optional[Callable[[], Optional[str]]]) -> Tuple[Optional[str], Optional[str]]:
    """``(address, None)`` of the DNS server to ask, or ``(None, error text)``."""
    if server is None:
        try:
            address = (system_server or _system_dns_server)()
        except Exception:  # noqa: BLE001
            log.debug("the system DNS server seam failed", exc_info=True)
            address = None
        return (str(address), None) if address and _is_ip(address) else (None, NO_SERVER_TEXT)
    if _is_ip(server):
        return server, None
    not_found = f'Could not find the DNS server "{server}"'
    try:
        infos = sockets.getaddrinfo(server, int(port), 0, socket.SOCK_DGRAM)
    except (OSError, UnicodeError, ValueError) as exc:
        log.debug("the DNS server name did not resolve: %s", exc)
        return None, not_found
    found: List[Tuple[int, str]] = []
    for info in infos or []:
        family, sockaddr = info[0], info[4]
        host = str(sockaddr[0])
        if family == socket.AF_INET6 and len(sockaddr) >= 4 and sockaddr[3] and "%" not in host:
            host = f"{host}%{sockaddr[3]}"
        if family in (socket.AF_INET, socket.AF_INET6) and _is_ip(host):
            found.append((0 if family == socket.AF_INET else 1, host))
    found.sort(key=lambda item: item[0])
    return (found[0][1], None) if found else (None, not_found)


def _target(address: str, port: int) -> Tuple[int, tuple]:
    """``(family, sockaddr)`` for an IP literal (an IPv6 zone becomes the scope id)."""
    addr = ipaddress.ip_address(address)
    host = str(addr).split("%", 1)[0]
    if addr.version == 4:
        return socket.AF_INET, (host, port)
    scope = str(getattr(addr, "scope_id", None) or "")
    try:
        scope_id = int(scope) if scope else 0
    except ValueError:
        try:
            scope_id = socket.if_nametoindex(scope)
        except (OSError, AttributeError):
            scope_id = 0
    return socket.AF_INET6, (host, port, 0, scope_id)


def _chain(answers: List[Dict[str, Any]], qname: str) -> Tuple[str, List[str], Set[str]]:
    """``(the name at the end of the CNAME chain, the owner names that pointed onwards, every name on the chain
    in lower case)``."""
    current, aliases, names = qname, [], {qname.lower()}
    for _ in range(_MAX_CHAIN):
        hop = next((r for r in answers if r["type"] == "CNAME" and r["name"].lower() == current.lower()), None)
        if hop is None or hop["value"].lower() in names:
            break
        aliases.append(hop["name"])
        current = hop["value"]
        names.add(current.lower())
    return current, aliases, names


def _add_records(records: List[Dict[str, Any]], seen: Set[Tuple[str, str, str]], answers: List[Dict[str, Any]]) -> None:
    for r in answers:
        value = r["value"] if r["type"] in _CASE_KEPT else r["value"].lower()     # text keeps its case; names do not
        key = (r["type"], r["name"].lower(), value)
        if key not in seen:
            seen.add(key)
            records.append({k: r[k] for k in DNS_RECORD_KEYS})


def _failure_text(outcomes: List[Outcome], empty_text: str) -> str:
    """The most specific reason a lookup found nothing (see the module docstring)."""
    replies = [msg for status, msg in outcomes if status == "reply" and msg is not None]
    codes = [int(m["rcode"]) for m in replies]
    for code in (RCODE_NXDOMAIN, RCODE_SERVFAIL, RCODE_REFUSED):
        if code in codes:
            return RCODE_TEXT[code]
    other = next((c for c in codes if c != RCODE_NOERROR), None)
    if other is not None:
        return RCODE_TEXT.get(other, f"DNS error code {other}")
    if replies:
        return empty_text
    if any(status == "unreadable" for status, _msg in outcomes):
        return UNREADABLE_TEXT
    return TIMEOUT_TEXT


def _forward_lookup(target: Tuple[Any, int, tuple], qname: str, timeout_s: float, result: Dict[str, Any]) -> List[Outcome]:
    outcomes = [_exchange(target, qname, TYPE_A, timeout_s, DNS_TRIES)]
    status, msg = outcomes[0]
    if not (status == "timeout" or (status == "reply" and msg is not None and msg["rcode"] == RCODE_NXDOMAIN)):
        outcomes.append(_exchange(target, qname, TYPE_AAAA, timeout_s, DNS_TRIES))
    records: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str]] = set()
    addresses: List[str] = []
    aliases: List[str] = []
    for (status, msg), rtype in zip(outcomes, ("A", "AAAA")):
        if status != "reply" or msg is None:
            continue
        answers = msg["answers"]
        _add_records(records, seen, answers)
        end, hops, names = _chain(answers, qname)
        found = [r["value"] for r in answers if r["type"] == rtype and r["name"].lower() in names]
        aliases.extend(a for a in hops if a not in aliases)
        if (found or hops) and result["answer_name"] is None:
            result["answer_name"] = end
        if found and result["authoritative"] is None:
            result["authoritative"] = bool(msg["aa"])
        addresses.extend(a for a in found if a not in addresses)
    result.update(addresses=addresses, aliases=aliases, records=records, ok=bool(addresses))
    if not addresses:
        result["error"] = _failure_text(outcomes, NO_ADDRESSES_TEXT)
    return outcomes


def _all_lookup(target: Tuple[Any, int, tuple], qname: str, timeout_s: float, result: Dict[str, Any]) -> List[Outcome]:
    """One query per type in :data:`ALL_TYPES`, merged into one result (``type`` ``"ALL"``): every type's records are
    concatenated and deduped, ``addresses``/``aliases`` filled from the A/AAAA/CNAME answers.  A type whose query fails
    is skipped; the lookup fails only when no type found any record."""
    records: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str]] = set()
    addresses: List[str] = []
    aliases: List[str] = []
    outcomes: List[Outcome] = []
    for rtype in ALL_TYPES:
        status, msg = _exchange(target, qname, TYPE_CODES[rtype], timeout_s, DNS_TRIES)
        outcomes.append((status, msg))
        if status != "reply" or msg is None:
            continue
        answers = msg["answers"]
        _add_records(records, seen, answers)
        end, hops, names = _chain(answers, qname)
        found = [r["value"] for r in answers if r["type"] == rtype and r["name"].lower() in names]
        aliases.extend(a for a in hops if a not in aliases)
        if (found or hops) and result["answer_name"] is None:
            result["answer_name"] = end
        if found and result["authoritative"] is None:
            result["authoritative"] = bool(msg["aa"])
        if rtype in ("A", "AAAA"):
            addresses.extend(a for a in found if a not in addresses)
    result.update(addresses=addresses, aliases=aliases, records=records, ok=bool(records))
    if not records:
        result["error"] = _failure_text(outcomes, NO_ADDRESSES_TEXT)
    return outcomes


def _reverse_lookup(target: Tuple[Any, int, tuple], address: str, timeout_s: float, result: Dict[str, Any]) -> List[Outcome]:
    ptr_name = reverse_name(address)
    status, msg = _exchange(target, ptr_name, TYPE_PTR, timeout_s, DNS_TRIES)
    if status == "reply" and msg is not None:
        records: List[Dict[str, Any]] = []
        _add_records(records, set(), msg["answers"])
        _end, aliases, names = _chain(msg["answers"], ptr_name)
        ptrs = [r["value"] for r in msg["answers"] if r["type"] == "PTR" and r["name"].lower() in names]
        result.update(records=records, aliases=aliases)
        if ptrs:
            plain = str(ipaddress.ip_address(address.split("%", 1)[0]))
            result.update(answer_name=ptrs[0], addresses=[plain], authoritative=bool(msg["aa"]), ok=True)
    if not result["ok"]:
        result["error"] = _failure_text([(status, msg)], NO_PTR_TEXT)
    return [(status, msg)]


def _typed_lookup(target: Tuple[Any, int, tuple], qname: str, rtype: str, timeout_s: float,
                  result: Dict[str, Any]) -> List[Outcome]:
    """One query of *rtype* (``nslookup -type=<rtype>``).  Every answer is listed; what was found is the records of
    that type on the CNAME chain (for CNAME, the chain's own records).  ``addresses`` only for A and AAAA."""
    status, msg = _exchange(target, qname, TYPE_CODES[rtype], timeout_s, DNS_TRIES)
    if status == "reply" and msg is not None:
        answers = msg["answers"]
        records: List[Dict[str, Any]] = []
        _add_records(records, set(), answers)
        end, hops, names = _chain(answers, qname)
        found = [r["value"] for r in answers if r["type"] == rtype and r["name"].lower() in names]
        result.update(records=records, aliases=hops)
        if found or hops:
            result["answer_name"] = found[0] if rtype == "PTR" and found else end
        if found:
            result.update(authoritative=bool(msg["aa"]), ok=True)
            if rtype in ("A", "AAAA"):
                result["addresses"] = list(dict.fromkeys(found))
    if not result["ok"]:
        result["error"] = _failure_text([(status, msg)], NO_RECORDS_TEXT.format(rtype))
    return [(status, msg)]


def _server_name(target: Tuple[Any, int, tuple], address: str, timeout_s: float) -> Optional[str]:
    """The resolver's own name: a PTR lookup of its address on itself, one short attempt; ``None`` on failure."""
    try:
        ptr_name = reverse_name(address)
        status, msg = _exchange(target, ptr_name, TYPE_PTR, timeout_s, 1)
        if status != "reply" or msg is None:
            return None
        _end, _aliases, names = _chain(msg["answers"], ptr_name)
        return next((r["value"] for r in msg["answers"] if r["type"] == "PTR" and r["name"].lower() in names), None)
    except Exception:  # noqa: BLE001
        log.debug("the resolver name lookup failed", exc_info=True)
        return None


_DNS_REASONS = {TIMEOUT_TEXT: "no response", NO_ADDRESSES_TEXT: "no addresses", NO_PTR_TEXT: "no name",
                UNREADABLE_TEXT: "unreadable answer", NO_SERVER_TEXT: "no DNS server",
                **{NO_RECORDS_TEXT.format(t): "no records" for t in DNS_TYPES},
                **{text: text.lower() for text in RCODE_TEXT.values()}}


def dns_lookup(name: Any, server: Any = None, record_type: Any = None, *, port: int = DNS_PORT,
               timeout_s: float = DNS_TIMEOUT_S, sockets: Any = socket,
               system_server: Optional[Callable[[], Optional[str]]] = None,
               clock: Callable[[], float] = time.time) -> Dict[str, Any]:
    """What ``nslookup [-type=<record_type>] <name> [<server>]`` answers, as DNS_RESULT (see the module docstring).

    ``ValueError`` with the validators' text for a bad name, server or record type, or for an IP literal with a type
    other than PTR (:func:`validate_lookup`); every other failure is ``ok: False`` with ``error``.  *port*,
    *timeout_s* (per UDP attempt), *sockets* and *system_server* are test seams."""
    qname, srv, rtype = validate_lookup(name, server, record_type)
    t0 = time.monotonic()
    result: Dict[str, Any] = {
        "name": qname, "type": rtype, "server": srv, "resolver": {"name": None, "address": None}, "answer_name": None,
        "addresses": [], "aliases": [], "records": [], "authoritative": None, "ok": False, "error": None,
        "duration_ms": 0, "ts": float(clock()),
    }
    reverse = _is_ip(qname)         # an IP literal comes through validate_lookup only as Auto, PTR or ALL (a PTR lookup)
    try:
        address, error = _resolve_server(srv, port, sockets, system_server)
        if address is None:
            result["error"] = error
        else:
            result["resolver"]["address"] = address
            family, sockaddr = _target(address, int(port))
            target = (sockets, family, sockaddr)
            if reverse:
                outcomes = _reverse_lookup(target, qname, float(timeout_s), result)
            elif rtype is None:
                outcomes = _forward_lookup(target, qname, float(timeout_s), result)
            elif rtype == "ALL":
                outcomes = _all_lookup(target, qname, float(timeout_s), result)
            else:
                outcomes = _typed_lookup(target, qname, rtype, float(timeout_s), result)
            if any(status != "timeout" for status, _msg in outcomes):
                result["resolver"]["name"] = _server_name(target, address, min(RESOLVER_NAME_TIMEOUT_S, float(timeout_s)))
    except Exception as exc:  # noqa: BLE001 - nothing past validation may raise
        log.exception("DNS lookup failed")
        result.update(ok=False, addresses=[], error=f"The DNS lookup failed: {exc}")
    result["duration_ms"] = max(0, int(round((time.monotonic() - t0) * 1000)))
    outcome = "ok" if result["ok"] else _DNS_REASONS.get(result["error"] or "", "failed")
    log.info("DNS lookup (%s): %s in %d ms", "reverse" if reverse else (rtype or "forward"), outcome,
             result["duration_ms"])
    log.debug("DNS lookup of %s via %s: %s", qname, result["resolver"]["address"],
              result["addresses"] or [r["value"] for r in result["records"]] or result["error"])
    return result


# --- native Windows calls -----------------------------------------------------------------------
NO_ERROR = 0
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_DATA = 232
MAX_ADAPTER_NAME = 128
#: A GetInterfaceInfo table claiming more rows than this is corrupt, not real.
_MAX_INTERFACES = 1024


class IP_ADAPTER_INDEX_MAP(Structure):
    _fields_ = [
        ("Index", c_ulong),                         # 0  the IPv4 interface index
        ("Name", c_wchar * MAX_ADAPTER_NAME),       # 4  "\DEVICE\TCPIP_{GUID}"
    ]                                               # sizeof == 260 (WCHAR is 2 bytes on Windows)


class IP_INTERFACE_INFO(Structure):
    _fields_ = [
        ("NumAdapters", c_long),
        ("Adapter", IP_ADAPTER_INDEX_MAP * 1),      # ANY_SIZE; rows start at offset 4
    ]


#: The Windows layout, spelled out so :func:`read_interface_info` parses the same bytes on any platform.
_INDEX_MAP_SIZE = 4 + 2 * MAX_ADAPTER_NAME
_ROWS_OFFSET = 4


class NativeUnavailable(OSError):
    """``dnsapi.dll`` / ``iphlpapi.dll`` (or the function) cannot be loaded: the ipconfig fallback is used."""


_fn_lock = threading.Lock()
_functions: Dict[Tuple[str, str], Any] = {}


def _function(dll_name: str, func_name: str, argtypes: List[Any], restype: Any) -> Any:
    """A prototyped function of a system DLL, loaded once; :class:`NativeUnavailable` when it cannot be (import-safe
    off Windows: nothing is loaded before the first call)."""
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise NativeUnavailable(0, f"{dll_name}.dll exists on Windows only")
    key = (dll_name, func_name)
    with _fn_lock:
        fn = _functions.get(key)
        if fn is None:
            try:
                fn = getattr(loader(dll_name, use_last_error=True), func_name)
            except (OSError, AttributeError) as exc:
                raise NativeUnavailable(0, f"{dll_name}.{func_name} cannot be loaded: {exc}") from exc
            fn.argtypes = argtypes
            fn.restype = restype
            _functions[key] = fn
    return fn


def win_error_text(rc: int) -> str:
    """The FormatMessage text of a Win32 error code ("Windows error N" when there is none)."""
    try:
        text = str(ctypes.FormatError(int(rc))).strip()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - not Windows
        text = ""
    return text if text and not text.startswith("<") else f"Windows error {rc}"


def _exc_text(exc: BaseException) -> str:
    return str(getattr(exc, "strerror", None) or exc or type(exc).__name__)


def read_interface_info(raw: bytes) -> List[Tuple[int, str]]:
    """``[(index, name)]`` from a ``GetInterfaceInfo`` buffer; ``OSError`` for a row count the buffer cannot hold."""
    raw = bytes(raw)
    if len(raw) < _ROWS_OFFSET:
        return []
    count = struct.unpack_from("<i", raw, 0)[0]
    if not 0 <= count <= _MAX_INTERFACES or _ROWS_OFFSET + count * _INDEX_MAP_SIZE > len(raw):
        raise OSError(0, f"GetInterfaceInfo returned an implausible table of {count} rows")
    out: List[Tuple[int, str]] = []
    for i in range(count):
        at = _ROWS_OFFSET + i * _INDEX_MAP_SIZE
        index = struct.unpack_from("<I", raw, at)[0]
        name = raw[at + 4:at + _INDEX_MAP_SIZE].decode("utf-16-le", "replace").split("\x00", 1)[0]
        out.append((int(index), name))
    return out


def _index_map(index: int, name: str) -> IP_ADAPTER_INDEX_MAP:
    entry = IP_ADAPTER_INDEX_MAP()
    entry.Index = int(index) & 0xFFFFFFFF
    entry.Name = str(name)[:MAX_ADAPTER_NAME - 1]
    return entry


class NetApi:
    """The native calls behind four small methods (the ``api`` seam of :func:`flush_dns` / :func:`release_renew`).

    Every method raises :class:`NativeUnavailable` when its DLL function cannot be loaded.  ``interfaces()`` loads
    ``IpReleaseAddress`` and ``IpRenewAddress`` too (so a missing one falls back before anything is released) and
    raises ``OSError`` with the Win32 code when the call fails; ``release`` / ``renew`` return the Win32 code."""

    def flush_cache(self) -> bool:
        return bool(_function("dnsapi", "DnsFlushResolverCache", [], ctypes.c_int)())

    @staticmethod
    def _step(func_name: str) -> Any:
        return _function("iphlpapi", func_name, [POINTER(IP_ADAPTER_INDEX_MAP)], c_ulong)

    def interfaces(self) -> List[Tuple[int, str]]:
        fn = _function("iphlpapi", "GetInterfaceInfo", [c_void_p, POINTER(c_ulong)], c_ulong)
        self._step("IpReleaseAddress")
        self._step("IpRenewAddress")
        size = c_ulong(0)
        for _ in range(4):
            buf = ctypes.create_string_buffer(max(int(size.value), ctypes.sizeof(IP_INTERFACE_INFO)))
            size = c_ulong(len(buf))
            rc = int(fn(buf, byref(size)))
            if rc == ERROR_INSUFFICIENT_BUFFER:
                continue                        # size now holds what it needs
            if rc == ERROR_NO_DATA:
                return []
            if rc != NO_ERROR:
                raise OSError(rc, win_error_text(rc))
            return read_interface_info(buf.raw)
        raise OSError(ERROR_INSUFFICIENT_BUFFER, "GetInterfaceInfo kept asking for a larger buffer")

    def release(self, index: int, name: str) -> int:
        return int(self._step("IpReleaseAddress")(byref(_index_map(index, name))))

    def renew(self, index: int, name: str) -> int:
        return int(self._step("IpRenewAddress")(byref(_index_map(index, name))))


# --- the ipconfig fallback ----------------------------------------------------------------------
def ipconfig_exe() -> str:
    """``ipconfig.exe`` from ``%SystemRoot%\\System32``; the bare name only when that file is missing (a non-Windows
    test box), never a path from PATH or a setting."""
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    cand = os.path.join(root, "System32", "ipconfig.exe")
    return cand if os.path.isfile(cand) else "ipconfig"


def _decode_console(raw: Any) -> str:
    """ipconfig writes the OEM code page like arp; reuse the tolerant decoder (lazily imported)."""
    if isinstance(raw, str):
        return raw
    if not raw:
        return ""
    try:
        return importlib.import_module("tnt.arp")._decode_console(bytes(raw))
    except Exception:  # noqa: BLE001
        return bytes(raw).decode("utf-8", errors="replace")


def _run_ipconfig(args: Sequence[str], runner: Callable[..., Any], timeout_s: float) -> Dict[str, Any]:
    """``{"rc", "error", "output"}`` of ``ipconfig <args>``; ``error`` only when it did not start or finish (a
    non-zero exit code alone is not one)."""
    argv = [ipconfig_exe(), *[str(a) for a in args]]
    command = " ".join(["ipconfig", *[str(a) for a in args]])
    log.debug("running %s", subprocess.list2cmdline(argv))
    try:
        proc = runner(argv, capture_output=True, timeout=timeout_s, check=False, stdin=subprocess.DEVNULL,
                      creationflags=_CREATE_NO_WINDOW)
    except FileNotFoundError:
        return {"rc": None, "error": IPCONFIG_MISSING_TEXT, "output": ""}
    except subprocess.TimeoutExpired:
        return {"rc": None, "error": f"{command} did not finish within {timeout_s:g} s", "output": ""}
    except Exception as exc:  # noqa: BLE001 - OSError, or a broken runner seam
        return {"rc": None, "error": f"could not run {command}: {exc}", "output": ""}
    output = (_decode_console(getattr(proc, "stdout", b"")) + _decode_console(getattr(proc, "stderr", b""))).strip()
    try:
        rc = int(getattr(proc, "returncode", 1))
    except (TypeError, ValueError):
        rc = 1
    return {"rc": rc, "error": None, "output": output}


def _last_line(text: str) -> Optional[str]:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1][:WARNING_CHARS] if lines else None


def _add_warning(warnings: List[str], text: str) -> None:
    text = " ".join(str(text).split())[:WARNING_CHARS]
    if text and text not in warnings and len(warnings) < WARNINGS_MAX:
        warnings.append(text)


def _ipconfig_warnings(output: str) -> List[str]:
    """ipconfig's lines about an error while releasing or renewing an interface (English Windows)."""
    warnings: List[str] = []
    for line in (output or "").splitlines():
        low = line.lower()
        if "error" in low and ("releas" in low or "renew" in low):
            _add_warning(warnings, line)
    return warnings


# --- flush DNS ----------------------------------------------------------------------------------
def flush_dns(*, runner: Callable[..., Any] = subprocess.run, clock: Callable[[], float] = time.time,
              api: Any = None) -> Dict[str, Any]:
    """``ipconfig /flushdns``: ``DnsFlushResolverCache()``, or ipconfig when ``dnsapi.dll`` cannot be loaded.
    FLUSH_RESULT; never raises."""
    t0 = time.monotonic()
    result: Dict[str, Any] = {"ok": False, "method": "native", "error": None, "duration_ms": 0, "ts": float(clock())}
    try:
        flushed = bool((api if api is not None else NetApi()).flush_cache())
        result.update(ok=flushed, error=None if flushed else FLUSH_FAILED_TEXT)
    except NativeUnavailable as exc:
        log.info("DnsFlushResolverCache is not available (%s); running ipconfig /flushdns", exc)
        step = _run_ipconfig(["/flushdns"], runner, FLUSH_TIMEOUT_S)
        ok = step["error"] is None and step["rc"] == 0
        error = None if ok else (step["error"] or _last_line(step["output"])
                                 or f"ipconfig /flushdns ended with exit code {step['rc']}")
        result.update(method="ipconfig", ok=ok, error=error)
        log.debug("ipconfig /flushdns (exit code %s): %s", step["rc"], step["output"])
    except Exception as exc:  # noqa: BLE001
        log.exception("flushing the DNS cache failed")
        result.update(ok=False, error=f"Flushing the DNS cache failed: {_exc_text(exc)}")
    result["duration_ms"] = max(0, int(round((time.monotonic() - t0) * 1000)))
    log.info("Flush DNS (%s): %s in %d ms", result["method"], "ok" if result["ok"] else f"failed ({result['error']})",
             result["duration_ms"])
    return result


# --- IP release / renew -------------------------------------------------------------------------
def _bounded(fn: Callable[[], Any], timeout_s: float, name: str) -> Tuple[bool, Any, Optional[BaseException]]:
    """``(finished, value, exception)`` of *fn* run on a helper thread for at most *timeout_s*.  A native call cannot
    be cancelled: one that does not finish is left running on its daemon thread."""
    box: Dict[str, Any] = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - handed to the caller
            box["exc"] = exc

    thread = threading.Thread(target=run, name=name, daemon=True)
    thread.start()
    thread.join(max(0.0, float(timeout_s)))
    if thread.is_alive():
        return False, None, None
    return True, box.get("value"), box.get("exc")


def _native_step(fn: Callable[[int, str], Any], index: int, name: str, timeout_s: float, what: str) -> Optional[str]:
    """``None`` when ``fn(index, name)`` returned NO_ERROR, else the error text."""
    finished, value, exc = _bounded(lambda: fn(index, name), timeout_s, f"tnt-ip-{what}")
    if not finished:
        return f"the {what} did not finish within {timeout_s:g} s"
    if exc is not None:
        return _exc_text(exc)
    try:
        rc = int(value)
    except (TypeError, ValueError):
        return f"the {what} returned {value!r}"
    if rc != NO_ERROR:
        log.debug("%s of interface %s: Win32 error %d", what, index, rc)
        return win_error_text(rc)
    return None


def _netinfo_adapters() -> List[Any]:
    netinfo = importlib.import_module("tnt.netinfo")
    netinfo._invalidate_cache()
    return list(netinfo.get_adapters(include_down=True) or [])


def _internet_address() -> Tuple[Optional[str], Optional[str]]:
    """``(adapter name, IPv4)`` of the internet adapter, read afresh (tnt.netinfo's cache dropped first)."""
    netinfo = importlib.import_module("tnt.netinfo")
    netinfo._invalidate_cache()
    nic = netinfo.get_internet_nic()
    if nic is None:
        return None, None
    return getattr(nic, "name", None), getattr(nic, "primary_ipv4", None)


def _read_address(address_fn: Optional[Callable[[], Tuple[Optional[str], Optional[str]]]]) -> Tuple[Optional[str], Optional[str]]:
    try:
        adapter, address = (address_fn or _internet_address)()
    except Exception:  # noqa: BLE001 - never raises
        log.debug("reading the internet adapter's address failed", exc_info=True)
        return None, None
    return (str(adapter) if adapter else None), (str(address) if address else None)


def _usable_ipv4(address: Optional[str]) -> bool:
    """An IPv4 address that is neither self-assigned (169.254.x.x) nor 0.0.0.0."""
    try:
        addr = ipaddress.IPv4Address(str(address or ""))
    except ValueError:
        return False
    return not (addr.is_link_local or addr.is_unspecified)


def _guid_of(name: str) -> str:
    m = re.search(r"\{[0-9A-Fa-f-]+\}", str(name or ""))
    return m.group(0).lower() if m else ""


def _dhcp_targets(interfaces: Sequence[Tuple[int, str]], adapters: Sequence[Any]) -> List[Tuple[int, str, str]]:
    """``(index, interface name, adapter name)`` of every listed interface whose tnt.netinfo adapter (matched by GUID,
    else by index) is up and gets its IPv4 address from DHCP, in GetInterfaceInfo order."""
    by_guid = {str(getattr(a, "guid", "") or "").lower(): a for a in adapters if getattr(a, "guid", "")}
    by_index: Dict[int, Any] = {}
    for a in adapters:
        try:
            by_index.setdefault(int(getattr(a, "index")), a)
        except (TypeError, ValueError, AttributeError):
            continue
    out: List[Tuple[int, str, str]] = []
    for index, name in interfaces:
        adapter = by_guid.get(_guid_of(name)) or by_index.get(int(index))
        if adapter is None or not getattr(adapter, "is_up", False) or not getattr(adapter, "dhcp_enabled", False) \
                or getattr(adapter, "is_loopback", False):
            log.debug("release/renew leaves interface %s alone (%s)", index,
                      "no such adapter" if adapter is None else "down or not on DHCP")
            continue
        out.append((int(index), str(name), str(getattr(adapter, "name", "") or name)))
    return out


def _release_renew_native(result: Dict[str, Any], api: Any, adapters_fn: Optional[Callable[[], Sequence[Any]]],
                          address_fn: Optional[Callable[[], Tuple[Optional[str], Optional[str]]]]) -> None:
    interfaces = list(api.interfaces())     # NativeUnavailable -> the ipconfig fallback, nothing touched yet
    targets = _dhcp_targets(interfaces, list((adapters_fn or _netinfo_adapters)() or []))
    rows = [{"name": label, "released": False, "renewed": False, "error": None} for _index, _name, label in targets]
    result["adapters"] = rows
    if not targets:
        result["error"] = NO_DHCP_ADAPTER_TEXT
        result["adapter"], result["address"] = _read_address(address_fn)
        return
    warnings = result["warnings"]
    for (index, name, label), row in zip(targets, rows):          # every release first, like ipconfig /release
        error = _native_step(api.release, index, name, RELEASE_TIMEOUT_S, "release")
        row["released"] = error is None
        if error:
            row["error"] = error
            _add_warning(warnings, f"{label}: {error}")
    renew_errors: List[str] = []
    for (index, name, label), row in zip(targets, rows):          # then every renew, even after a failed release
        error = _native_step(api.renew, index, name, RENEW_TIMEOUT_S, "renew")
        row["renewed"] = error is None
        if error:
            row["error"] = error
            _add_warning(warnings, f"{label}: {error}")
            renew_errors.append(f"{label}: {error}"[:WARNING_CHARS])
    result["adapter"], result["address"] = _read_address(address_fn)
    has_address = _usable_ipv4(result["address"])
    result["ok"] = any(row["renewed"] for row in rows) and has_address
    if not result["ok"]:
        result["error"] = renew_errors[0] if has_address and renew_errors else NO_ADDRESS_TEXT


def _release_renew_ipconfig(result: Dict[str, Any], runner: Callable[..., Any],
                            address_fn: Optional[Callable[[], Tuple[Optional[str], Optional[str]]]]) -> None:
    result["method"] = "ipconfig"
    release = _run_ipconfig(["/release"], runner, RELEASE_TIMEOUT_S)
    renew = _run_ipconfig(["/renew"], runner, RENEW_TIMEOUT_S)     # always, even when the release failed
    warnings = result["warnings"]
    if release["error"] and release["error"] != renew["error"]:
        _add_warning(warnings, release["error"])
    for line in _ipconfig_warnings(release["output"] + "\n" + renew["output"]):
        _add_warning(warnings, line)
    log.debug("ipconfig /release (exit code %s): %s", release["rc"], release["output"])
    log.debug("ipconfig /renew (exit code %s): %s", renew["rc"], renew["output"])
    result["adapter"], result["address"] = _read_address(address_fn)
    result["ok"] = renew["error"] is None and _usable_ipv4(result["address"])
    if not result["ok"]:
        result["error"] = renew["error"] or NO_ADDRESS_TEXT


def release_renew(*, runner: Callable[..., Any] = subprocess.run, clock: Callable[[], float] = time.time,
                  address_fn: Optional[Callable[[], Tuple[Optional[str], Optional[str]]]] = None, api: Any = None,
                  adapters_fn: Optional[Callable[[], Sequence[Any]]] = None) -> Dict[str, Any]:
    """``ipconfig /release`` then ``ipconfig /renew``, natively (see the module docstring).  RENEW_RESULT with
    ``paused_monitoring`` False (the engine sets it); never raises.

    *address_fn* ``() -> (adapter name, IPv4)`` reads the internet adapter afterwards (default: tnt.netinfo with its
    cache dropped); *adapters_fn* ``() -> [Adapter]`` decides which adapters are up and on DHCP (default:
    ``tnt.netinfo.get_adapters``)."""
    t0 = time.monotonic()
    result: Dict[str, Any] = {"ok": False, "address": None, "adapter": None, "adapters": [], "warnings": [],
                              "paused_monitoring": False, "method": "native", "error": None, "duration_ms": 0,
                              "ts": float(clock())}
    try:
        _release_renew_native(result, api if api is not None else NetApi(), adapters_fn, address_fn)
    except NativeUnavailable as exc:
        log.info("the IP helper API is not available (%s); running ipconfig /release and /renew", exc)
        _release_renew_ipconfig(result, runner, address_fn)
    except Exception as exc:  # noqa: BLE001
        log.exception("IP release/renew failed")
        result.update(ok=False, error=_exc_text(exc))
    result["duration_ms"] = max(0, int(round((time.monotonic() - t0) * 1000)))
    renewed = sum(1 for row in result["adapters"] if row["renewed"])
    log.info("IP release/renew (%s): %s, %d of %d adapter(s) renewed, %d warning(s), in %d ms", result["method"],
             "ok" if result["ok"] else "failed", renewed, len(result["adapters"]), len(result["warnings"]),
             result["duration_ms"])
    log.debug("IP release/renew: adapter %s address %s error %s warnings %s", result["adapter"], result["address"],
              result["error"], result["warnings"])
    return result
