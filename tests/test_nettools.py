"""Tests for tnt.nettools: the DNS lookup client, Flush DNS and IP release/renew.

Offline: the DNS client talks to a fake DNS server on 127.0.0.1 (UDP and TCP on one ephemeral port); the native
calls (``DnsFlushResolverCache``, ``GetInterfaceInfo``, ``IpReleaseAddress``, ``IpRenewAddress``) and ipconfig are
fakes behind the ``api`` / ``runner`` seams, so nothing here touches this PC's DNS cache or adapters.  Addresses
are documentation ranges (RFC 5737, RFC 3849) and names example.com / example.net.
"""
from __future__ import annotations

import ctypes
import logging
import os
import random
import socket
import struct
import subprocess
import threading
import time
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from tnt import nettools as nt

T0 = 1_700_000_000.0


# =========================================================================== validation
@pytest.mark.parametrize("text,expected", [
    ("example.com", "example.com"),
    ("  www.example.com.  ", "www.example.com"),
    ("_dmarc.example.com", "_dmarc.example.com"),
    ("a-b.example.net", "a-b.example.net"),
    ("localhost", "localhost"),
    ("192.0.2.10", "192.0.2.10"),
    ("198.51.100.7.", "198.51.100.7"),
    ("2001:DB8::1", "2001:db8::1"),
    ("bücher.example", "xn--bcher-kva.example"),
    ("a" * 63 + ".example.com", "a" * 63 + ".example.com"),
    (".".join(["a" * 49] * 5) + "ab", ".".join(["a" * 49] * 5) + "ab"),     # 251 characters
])
def test_validate_name_accepts(text, expected):
    assert nt.validate_name(text) == expected


@pytest.mark.parametrize("text", [
    "with space.example.com", "-type=any", "-x", "a..b", "example.com..", ".", "a" * 64 + ".example.com",
    "ab\n.example.com", "www\n.example.com",                       # a label ending in a newline is not a label
    ".".join(["a" * 50] * 5), "bad-.example.com", "-bad.example.com", "exa$mple.com", "example.com;calc",
    "ü" * 64 + ".example", "example.com", "x" * 300,
])
def test_validate_name_rejects(text):
    with pytest.raises(ValueError) as err:
        nt.validate_name(text)
    assert str(err.value) == f'"{text.strip()[:80]}" is not a DNS name or IP address'


@pytest.mark.parametrize("text", [None, "", "   "])
def test_validate_name_empty(text):
    with pytest.raises(ValueError) as err:
        nt.validate_name(text)
    assert str(err.value) == "Type a DNS name or IP address to look up"


def test_validate_server():
    assert nt.validate_server(None) is None and nt.validate_server("") is None and nt.validate_server("  ") is None
    assert nt.validate_server(" 1.1.1.1 ") == "1.1.1.1" and nt.validate_server("dns.example.net.") == "dns.example.net"
    assert nt.validate_server("2001:db8::53") == "2001:db8::53"
    for bad in ("-x", "a..b", "dns example"):
        with pytest.raises(ValueError) as err:
            nt.validate_server(bad)
        assert str(err.value) == f'"{bad}" is not a DNS server name or IP address'
    with pytest.raises(ValueError) as err:
        nt.validate_name(5)
    assert str(err.value) == '"5" is not a DNS name or IP address'


TYPE_TEXT = '"{}" is not a DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR or NAPTR)'
IP_TYPE_TEXT = "An IP address is looked up as PTR: type a DNS name to ask for other record types"


def test_record_types_and_texts():
    assert nt.DNS_TYPES == ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "PTR", "NAPTR")
    assert nt.ALL_TYPES == ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "NAPTR")   # PTR left out
    assert nt.DNS_RESULT_KEYS == ("name", "type", "server", "resolver", "answer_name", "addresses", "aliases", "records",
                                  "authoritative", "ok", "error", "duration_ms", "ts")
    assert nt.TYPE_CODES == {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "TXT": 16, "NS": 2, "SOA": 6, "SRV": 33, "CAA": 257,
                             "PTR": 12, "NAPTR": 35}
    assert set(nt.TYPE_NAMES.values()) == set(nt.DNS_TYPES)
    assert nt.BAD_TYPE_TEXT == TYPE_TEXT and nt.IP_TYPE_TEXT == IP_TYPE_TEXT
    assert nt.NO_RECORDS_TEXT == "No {} records found for this name"
    assert TYPE_TEXT.format("x").endswith("(" + ", ".join(nt.DNS_TYPES[:-1]) + " or " + nt.DNS_TYPES[-1] + ")")


@pytest.mark.parametrize("text,expected", [
    (None, None), ("", None), ("   ", None), ("A", "A"), ("aaaa", "AAAA"), (" mx ", "MX"), ("Txt", "TXT"), ("NS", "NS"),
    ("soa", "SOA"), ("SRV", "SRV"), ("caa", "CAA"), ("PTR", "PTR"), ("CNAME", "CNAME"), ("naptr", "NAPTR"), ("\tNaPtR\n", "NAPTR"),
    ("all", "ALL"), ("ALL", "ALL"), (" All ", "ALL"),
])
def test_validate_type_accepts(text, expected):
    assert nt.validate_type(text) == expected


@pytest.mark.parametrize("text", ["ANY", "HINFO", "DNSKEY", "-type=mx", "M X", "MX.", "x" * 100, "  " + "y" * 90 + "  ", 5, 15.0,
                                  True, ["MX"]])
def test_validate_type_rejects(text):
    with pytest.raises(ValueError) as err:
        nt.validate_type(text)
    assert str(err.value) == TYPE_TEXT.format(str(text).strip()[:80])


def test_validate_type_rejects_with_the_exact_text():
    with pytest.raises(ValueError) as err:
        nt.validate_type(" any ")
    assert str(err.value) == '"any" is not a DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR or NAPTR)'


def test_validate_lookup_checks_name_server_type_then_the_address():
    assert nt.validate_lookup(" example.com. ", " 192.0.2.53 ", " mx ") == ("example.com", "192.0.2.53", "MX")
    assert nt.validate_lookup("www.example.com") == ("www.example.com", None, None)
    assert nt.validate_lookup("192.0.2.10", "", "") == ("192.0.2.10", None, None)
    assert nt.validate_lookup("2001:DB8::1", None, "ptr") == ("2001:db8::1", None, "PTR")
    assert nt.validate_lookup("10.113.0.203.in-addr.arpa", None, "PTR") == ("10.113.0.203.in-addr.arpa", None, "PTR")
    assert nt.validate_lookup("example.com", None, "all") == ("example.com", None, "ALL")
    assert nt.validate_lookup("192.0.2.10", None, "ALL") == ("192.0.2.10", None, "ALL")   # ALL on an IP is allowed (a PTR lookup)
    # a refused lookup never picks or resolves a server and opens no socket, so even a broken check sends no packet
    never = SimpleNamespace(socket=lambda *a, **kw: pytest.fail("a refused lookup opened a socket"),
                            getaddrinfo=lambda *a, **kw: pytest.fail("a refused lookup resolved a server"))
    for args, text in ((("", "-x", "ANY"), "Type a DNS name or IP address to look up"),
                       (("example.com", "-x", "ANY"), '"-x" is not a DNS server name or IP address'),
                       (("192.0.2.10", None, "ANY"), TYPE_TEXT.format("ANY")),
                       (("192.0.2.10", None, "MX"), IP_TYPE_TEXT),
                       (("2001:db8::1", "192.0.2.53", "aaaa"), IP_TYPE_TEXT),
                       (("198.51.100.7.", None, "NAPTR"), IP_TYPE_TEXT)):
        with pytest.raises(ValueError) as err:
            nt.validate_lookup(*args)
        assert str(err.value) == text, args
        with pytest.raises(ValueError) as err:
            nt.dns_lookup(*args, sockets=never, system_server=lambda: pytest.fail("a refused lookup picked a server"))
        assert str(err.value) == text, args


# =========================================================================== DNS messages
def ptr_to(offset: int) -> bytes:
    return struct.pack("!H", 0xC000 | offset)


class Reply:
    """A reply to *query* built record by record, so a test can point compressed names at earlier offsets."""

    def __init__(self, query: bytes, rcode: int = 0, aa: bool = False, tc: bool = False, qid: Optional[int] = None) -> None:
        self.qid = struct.unpack_from("!H", query, 0)[0] if qid is None else qid
        self.flags = 0x8000 | 0x0100 | 0x0080 | (0x0400 if aa else 0) | (0x0200 if tc else 0) | rcode
        self.body = bytearray(query[12:])        # the question, at offset 12
        self.count = 0

    def add(self, owner: bytes, rtype: int, rdata: bytes, ttl: int = 300) -> int:
        """Append a record; returns the offset of its data."""
        self.body += owner + struct.pack("!HHIH", rtype, 1, ttl, len(rdata))
        at = 12 + len(self.body)
        self.body += rdata
        self.count += 1
        return at

    def bytes(self) -> bytes:
        return struct.pack("!HHHHHH", self.qid, self.flags, 1, self.count, 0, 0) + bytes(self.body)


def a(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET, ip)


def aaaa(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, ip)


def test_build_query_and_names():
    q = nt.build_query(0x1234, "www.example.com", nt.TYPE_AAAA)
    assert q[:12] == struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    assert q[12:] == b"\x03www\x07example\x03com\x00" + struct.pack("!HH", 28, 1)
    assert nt.reverse_name("192.0.2.1") == "1.2.0.192.in-addr.arpa"
    assert nt.reverse_name("2001:db8::1") == "1.0.0.0." + "0." * 20 + "8.b.d.0.1.0.0.2.ip6.arpa"
    msg = nt.parse_message(q)
    assert msg["id"] == 0x1234 and msg["qr"] is False and msg["questions"] == [("www.example.com", 28)]


def test_parse_message_rejects_malformed_messages():
    q = nt.build_query(7, "example.com", nt.TYPE_A)
    with pytest.raises(nt.DnsFormatError):
        nt.parse_message(q[:11])
    with pytest.raises(nt.DnsFormatError):
        nt.parse_message(q[:-3])                                      # question cut off
    loop = Reply(q)
    loop.body = bytearray(b"\xc0\x0c" + struct.pack("!HH", 1, 1))    # a question name pointing at itself
    with pytest.raises(nt.DnsFormatError):
        nt.parse_message(loop.bytes())
    forward = Reply(q)
    forward.add(ptr_to(200), nt.TYPE_A, a("192.0.2.1"))              # a pointer past the record
    with pytest.raises(nt.DnsFormatError):
        nt.parse_message(forward.bytes())
    short_a = Reply(q)
    short_a.add(ptr_to(12), nt.TYPE_A, b"\xc0\x00\x02")
    with pytest.raises(nt.DnsFormatError):
        nt.parse_message(short_a.bytes())
    other = Reply(q)
    other.add(ptr_to(12), 13, b"\x01x\x01y")                           # HINFO: skipped, not an error
    other.add(ptr_to(12), 46, b"\xff")                                 # RRSIG, even unreadable: skipped
    other.add(ptr_to(12), nt.TYPE_A, a("192.0.2.9"))
    assert [r["value"] for r in nt.parse_message(other.bytes())["answers"]] == ["192.0.2.9"]


def mx_rdata(preference: int, exchange: bytes) -> bytes:
    return struct.pack("!H", preference) + exchange


def txt_rdata(*parts: bytes) -> bytes:
    """<character-string>s: a length octet, then the octets."""
    return b"".join(bytes([len(p)]) + p for p in parts)


def soa_rdata(mname: bytes, rname: bytes, *numbers: int) -> bytes:
    return mname + rname + struct.pack("!IIIII", *numbers)


def srv_rdata(priority: int, weight: int, port: int, target: bytes) -> bytes:
    return struct.pack("!HHH", priority, weight, port) + target


def caa_rdata(flags: int, tag: bytes, value: bytes) -> bytes:
    return bytes([flags, len(tag)]) + tag + value


def naptr_rdata(order: int, preference: int, flags: bytes, services: bytes, regexp: bytes, replacement: bytes) -> bytes:
    return struct.pack("!HH", order, preference) + txt_rdata(flags, services, regexp) + replacement


def test_parse_message_decodes_record_types():
    q = nt.build_query(9, "example.com", nt.TYPE_TXT)                  # the question's "example.com" is at offset 12
    r = Reply(q, aa=True)
    ns = r.add(ptr_to(12), nt.TYPE_NS, nt.encode_name("ns1.example.net"), ttl=86400)
    # the SOA's mname is "ns2" + a pointer to the "example.net" inside the NS data; its rname points at the question
    r.add(ptr_to(12), nt.TYPE_SOA, soa_rdata(b"\x03ns2" + ptr_to(ns + 4), b"\x0ahostmaster" + ptr_to(12),
                                             2026091301, 7200, 3600, 1209600, 300))
    r.add(ptr_to(12), nt.TYPE_SOA, soa_rdata(b"\x00", b"\x00", 1, 2, 3, 4, 5))
    r.add(ptr_to(12), nt.TYPE_MX, mx_rdata(10, b"\x04mail" + ptr_to(12)))
    r.add(ptr_to(12), nt.TYPE_MX, mx_rdata(0, b"\x00"))                 # null MX (RFC 7505), 3 octets
    r.add(ptr_to(12), nt.TYPE_TXT, txt_rdata(b"v=spf1 ip4:203.0.113.0/24", b" -all"))
    # a quote, a backslash and a byte that is not UTF-8 are escaped first; an "é" split over two strings is joined
    r.add(ptr_to(12), nt.TYPE_TXT, txt_rdata(b'say "hi" \\ \xff', "é".encode()[:1], "é".encode()[1:]))
    r.add(ptr_to(12), nt.TYPE_TXT, b"")
    r.add(ptr_to(12), nt.TYPE_SRV, srv_rdata(10, 60, 5060, nt.encode_name("sip.example.com")))
    r.add(ptr_to(12), nt.TYPE_SRV, srv_rdata(0, 0, 0, b"\x00"))         # the service is not offered, 7 octets
    r.add(ptr_to(12), nt.TYPE_CAA, caa_rdata(0, b"issue", b"letsencrypt.org"))
    r.add(ptr_to(12), nt.TYPE_CAA, caa_rdata(128, b"iodef", b'mailto:"x"\\'))
    r.add(ptr_to(12), nt.TYPE_CAA, caa_rdata(0, b"issuewild", b""))
    r.add(ptr_to(12), nt.TYPE_NAPTR, naptr_rdata(100, 10, b"S", b"SIP+D2U", b"", nt.encode_name("_sip._udp.example.com")))
    r.add(ptr_to(12), nt.TYPE_NAPTR, naptr_rdata(100, 50, b"U", b"E2U+sip", b"!^.*$!sip:\\1@example.com!", b"\x00"))
    r.add(ptr_to(12), nt.TYPE_NAPTR, naptr_rdata(10, 20, b"s", b"SIPS+D2T", b"", b"\x05_sips\x04_tcp" + ptr_to(12)))
    r.add(ptr_to(12), nt.TYPE_NAPTR, naptr_rdata(1, 2, b'a"b', b"\xff\\", b"", b"\x00"))    # escaped first, then decoded
    r.add(ptr_to(12), nt.TYPE_NAPTR, naptr_rdata(100, 10, b"", b"", b"", b"\x00"))    # 8 octets, the least there is
    r.add(ptr_to(12), nt.TYPE_PTR, b"\x00")
    r.add(ptr_to(12), 46, b"\x00" * 20)                                # RRSIG: skipped
    assert [(x["type"], x["value"]) for x in nt.parse_message(r.bytes())["answers"]] == [
        ("NS", "ns1.example.net"),
        ("SOA", "ns2.example.net hostmaster.example.com 2026091301 7200 3600 1209600 300"), ("SOA", ". . 1 2 3 4 5"),
        ("MX", "10 mail.example.com"), ("MX", "0 ."),
        ("TXT", "v=spf1 ip4:203.0.113.0/24 -all"), ("TXT", 'say \\"hi\\" \\\\ \\xffé'), ("TXT", ""),
        ("SRV", "10 60 5060 sip.example.com"), ("SRV", "0 0 0 ."),
        ("CAA", '0 issue "letsencrypt.org"'), ("CAA", '128 iodef "mailto:\\"x\\"\\\\"'), ("CAA", '0 issuewild ""'),
        ("NAPTR", '100 10 "S" "SIP+D2U" "" _sip._udp.example.com'),
        ("NAPTR", '100 50 "U" "E2U+sip" "!^.*$!sip:\\\\1@example.com!" .'),
        ("NAPTR", '10 20 "s" "SIPS+D2T" "" _sips._tcp.example.com'),
        ("NAPTR", '1 2 "a\\"b" "\\xff\\\\" "" .'),
        ("NAPTR", '100 10 "" "" "" .'),
        ("PTR", "."),
    ]


@pytest.mark.parametrize("rtype,rdata", [
    (nt.TYPE_A, b"\x00" * 5), (nt.TYPE_AAAA, b"\x00" * 4),
    (nt.TYPE_NS, b"\x03ns1"),                                          # a name running on into the next record
    (nt.TYPE_CNAME, ptr_to(400)),                                      # a pointer that does not point back
    (nt.TYPE_MX, b"\x00\x0a"),                                         # MX of 2 octets
    (nt.TYPE_MX, b"\x00\x0a\x04mail"),                                 # its exchange runs past the record
    (nt.TYPE_TXT, b"\x05hi"),                                          # a string length past the data
    (nt.TYPE_TXT, b"\x02hi\x03a"),
    (nt.TYPE_SOA, b"\x00\x00" + b"\x00" * 19),                         # the fixed tail one octet short
    (nt.TYPE_SOA, b"\x00\x00" + b"\x00" * 21),                         # and one octet long
    (nt.TYPE_SOA, b"\x00"),                                            # no rname
    (nt.TYPE_SRV, b"\x00" * 6),                                        # SRV of 6 octets
    (nt.TYPE_SRV, b"\x00" * 6 + b"\x03sip"),
    (nt.TYPE_CAA, b"\x00"),                                            # no tag length
    (nt.TYPE_CAA, b"\x00\x09issue"),                                   # a tag length past the data
    (nt.TYPE_CAA, b"\x00\x00letsencrypt.org"),                         # an empty tag
    (nt.TYPE_CAA, b"\x00\x10" + b"a" * 16 + b"x"),                     # a 16-octet tag
    (nt.TYPE_NAPTR, b"\x00" * 7),                                      # NAPTR of 7 octets
    (nt.TYPE_NAPTR, struct.pack("!HH", 100, 10) + b"\x01S\x07SIP"),     # a string past the data
    (nt.TYPE_NAPTR, struct.pack("!HH", 100, 10) + b"\x00\x00\x03abc"),  # no octet left for the replacement
    (nt.TYPE_NAPTR, struct.pack("!HH", 100, 10) + b"\x00" * 5),         # the replacement ends before the data does
    (nt.TYPE_NAPTR, struct.pack("!HH", 100, 10) + b"\x00\x00\x00\x03sip"),  # the replacement runs past the data
])
def test_parse_message_rejects_malformed_rdata(rtype, rdata):
    q = nt.build_query(7, "example.com", rtype)
    bad = Reply(q)
    bad.add(ptr_to(12), rtype, rdata)
    bad.add(ptr_to(12), nt.TYPE_A, a("192.0.2.9"))                     # a record after it, for a name to run into
    with pytest.raises(nt.DnsFormatError):
        nt.parse_message(bad.bytes())


def test_parse_message_reads_random_record_data_or_raises_a_format_error():
    """Whatever the record data, a message is read or raises DnsFormatError (which a lookup reports as an answer that
    could not be read): no IndexError or struct.error gets out."""
    rng = random.Random(115)
    q = nt.build_query(7, "example.com", nt.TYPE_TXT)
    for rtype in nt.TYPE_NAMES:
        for size in range(40):
            for _ in range(6):
                msg = Reply(q)
                msg.add(ptr_to(12), rtype, bytes(rng.choice((0, 1, 3, 12, 0xC0, rng.randrange(256))) for _ in range(size)))
                if rng.random() < 0.5:
                    msg.add(ptr_to(12), nt.TYPE_A, a("192.0.2.9"))
                try:
                    nt.parse_message(msg.bytes())
                except nt.DnsFormatError:
                    pass


# =========================================================================== fake DNS server
Handler = Callable[[bytes, str, int, str], Optional[List[bytes]]]


class FakeDns:
    """A DNS server on 127.0.0.1, UDP and TCP on the same ephemeral port.  ``handler(query, qname, qtype,
    transport)`` returns the messages to send back (none: stay silent)."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.queries: List[Tuple[str, int, str]] = []
        for _ in range(50):
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(("127.0.0.1", 0))
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                tcp.bind(("127.0.0.1", udp.getsockname()[1]))
                break
            except OSError:
                udp.close()
                tcp.close()
        else:
            pytest.skip("no free port for a UDP+TCP fake DNS server")
        tcp.listen(4)
        udp.settimeout(0.05)
        tcp.settimeout(0.05)
        self.udp, self.tcp, self.port = udp, tcp, udp.getsockname()[1]
        self._stop = threading.Event()
        self._threads = [threading.Thread(target=self._serve_udp, daemon=True),
                         threading.Thread(target=self._serve_tcp, daemon=True)]
        for t in self._threads:
            t.start()

    def _answer(self, data: bytes, transport: str) -> List[bytes]:
        qname, qtype = nt.parse_message(data)["questions"][0]
        self.queries.append((qname, qtype, transport))
        return list(self.handler(data, qname, qtype, transport) or [])

    def _serve_udp(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self.udp.recvfrom(4096)
            except OSError:          # timeout, or a reset from a client that already left
                continue
            for out in self._answer(data, "udp"):
                try:
                    self.udp.sendto(out, peer)
                except OSError:
                    pass

    def _serve_tcp(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _peer = self.tcp.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(2.0)
                try:
                    size = struct.unpack("!H", conn.recv(2))[0]
                    data = b""
                    while len(data) < size:
                        data += conn.recv(size - len(data))
                    for out in self._answer(data, "tcp"):
                        conn.sendall(struct.pack("!H", len(out)) + out)
                except OSError:
                    pass

    def types(self, transport: str = "udp") -> List[int]:
        return [t for _n, t, tr in self.queries if tr == transport]

    def close(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(1.0)
        self.udp.close()
        self.tcp.close()


@pytest.fixture
def dns():
    servers: List[FakeDns] = []

    def start(handler: Handler) -> FakeDns:
        srv = FakeDns(handler)
        servers.append(srv)
        return srv

    yield start
    for srv in servers:
        srv.close()


RESOLVER_PTR = "1.0.0.127.in-addr.arpa"


def with_resolver(handler: Handler) -> Handler:
    """*handler*, plus the PTR of 127.0.0.1 (the resolver's own name) answered as dns.example.net."""
    def wrapped(query: bytes, qname: str, qtype: int, transport: str) -> Optional[List[bytes]]:
        if qname == RESOLVER_PTR and qtype == nt.TYPE_PTR:
            r = Reply(query, aa=True)
            r.add(ptr_to(12), nt.TYPE_PTR, nt.encode_name("dns.example.net"))
            return [r.bytes()]
        return handler(query, qname, qtype, transport)
    return wrapped


def lookup(srv: FakeDns, name: str, **kw: Any) -> Dict[str, Any]:
    kw.setdefault("timeout_s", 0.3)
    return nt.dns_lookup(name, "127.0.0.1", port=srv.port, **kw)


def test_lookup_a_and_aaaa(dns, caplog):
    def handler(query, qname, qtype, transport):
        r = Reply(query)
        if qtype == nt.TYPE_A:
            r.add(ptr_to(12), nt.TYPE_A, a("192.0.2.10"), ttl=120)
            r.add(ptr_to(12), nt.TYPE_A, a("192.0.2.11"), ttl=120)
        elif qtype == nt.TYPE_AAAA:
            r.add(ptr_to(12), nt.TYPE_AAAA, aaaa("2001:db8::10"), ttl=60)
            r.add(ptr_to(12), nt.TYPE_AAAA, aaaa("2001:db8::10"), ttl=60)       # a duplicate is listed once
        return [r.bytes()]

    srv = dns(with_resolver(handler))
    caplog.set_level(logging.INFO, logger="tnt.nettools")
    res = lookup(srv, "www.example.com", clock=lambda: T0)
    assert tuple(res) == nt.DNS_RESULT_KEYS
    assert res == {**res, "name": "www.example.com", "type": None, "server": "127.0.0.1", "answer_name": "www.example.com",
                   "addresses": ["192.0.2.10", "192.0.2.11", "2001:db8::10"], "aliases": [], "authoritative": False,
                   "ok": True, "error": None, "ts": T0}
    assert res["resolver"] == {"name": "dns.example.net", "address": "127.0.0.1"}
    assert res["records"] == [{"type": "A", "name": "www.example.com", "value": "192.0.2.10", "ttl": 120},
                              {"type": "A", "name": "www.example.com", "value": "192.0.2.11", "ttl": 120},
                              {"type": "AAAA", "name": "www.example.com", "value": "2001:db8::10", "ttl": 60}]
    assert all(tuple(r) == nt.DNS_RECORD_KEYS for r in res["records"])
    assert isinstance(res["duration_ms"], int) and res["duration_ms"] >= 0
    assert srv.types() == [nt.TYPE_A, nt.TYPE_AAAA, nt.TYPE_PTR]
    info = " ".join(r.getMessage() for r in caplog.records if r.levelno >= logging.INFO)
    assert "DNS lookup" in info and "example.com" not in info and "192.0.2" not in info and "127.0.0.1" not in info


def test_lookup_follows_a_compressed_cname_chain(dns):
    def handler(query, qname, qtype, transport):
        r = Reply(query, aa=True)
        edge = r.add(ptr_to(12), nt.TYPE_CNAME, nt.encode_name("edge.example.net"), ttl=30)
        # "e1.cdn" + a pointer to the "example.net" inside the first CNAME's data
        cdn = r.add(ptr_to(edge), nt.TYPE_CNAME, b"\x02e1\x03cdn" + ptr_to(edge + 5), ttl=30)
        if qtype == nt.TYPE_A:
            r.add(ptr_to(cdn), nt.TYPE_A, a("192.0.2.20"))
        else:
            r.add(ptr_to(cdn), nt.TYPE_AAAA, aaaa("2001:db8::20"))
        return [r.bytes()]

    res = lookup(dns(with_resolver(handler)), "www.example.com")
    assert res["ok"] is True and res["error"] is None and res["authoritative"] is True
    assert res["aliases"] == ["www.example.com", "edge.example.net"]
    assert res["answer_name"] == "e1.cdn.example.net"
    assert res["addresses"] == ["192.0.2.20", "2001:db8::20"]
    assert [(r["type"], r["name"], r["value"]) for r in res["records"]] == [
        ("CNAME", "www.example.com", "edge.example.net"), ("CNAME", "edge.example.net", "e1.cdn.example.net"),
        ("A", "e1.cdn.example.net", "192.0.2.20"), ("AAAA", "e1.cdn.example.net", "2001:db8::20")]


@pytest.mark.parametrize("rcode,text", [(3, "Non-existent domain"), (2, "Server failed"), (5, "Query refused"),
                                        (4, "Not implemented"), (9, "DNS error code 9")])
def test_lookup_error_codes(dns, rcode, text):
    srv = dns(with_resolver(lambda query, qname, qtype, transport: [Reply(query, rcode=rcode).bytes()]))
    res = lookup(srv, "missing.example.com")
    assert res == {**res, "ok": False, "error": text, "addresses": [], "answer_name": None, "authoritative": None,
                   "records": [], "aliases": []}
    assert res["resolver"] == {"name": "dns.example.net", "address": "127.0.0.1"}
    if rcode == 3:
        assert srv.types() == [nt.TYPE_A, nt.TYPE_PTR], "no AAAA query after NXDOMAIN"
    else:
        assert srv.types() == [nt.TYPE_A, nt.TYPE_AAAA, nt.TYPE_PTR]


def test_lookup_without_addresses(dns):
    srv = dns(with_resolver(lambda query, qname, qtype, transport: [Reply(query).bytes()]))
    res = lookup(srv, "_dmarc.example.com")
    assert res["ok"] is False and res["error"] == "No addresses found for this name" and res["answer_name"] is None


def test_lookup_truncated_reply_goes_to_tcp(dns):
    def handler(query, qname, qtype, transport):
        if transport == "udp":
            return [Reply(query, tc=True).bytes()]
        r = Reply(query)
        for i in range(3):
            if qtype == nt.TYPE_A:
                r.add(ptr_to(12), nt.TYPE_A, a(f"198.51.100.{i + 1}"))
        return [r.bytes()]

    srv = dns(with_resolver(handler))
    res = lookup(srv, "big.example.com")
    assert res["ok"] is True and res["addresses"] == ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    assert srv.types("tcp") == [nt.TYPE_A, nt.TYPE_AAAA]


def test_lookup_ignores_a_reply_with_another_id(dns):
    def handler(query, qname, qtype, transport):
        qid = struct.unpack_from("!H", query, 0)[0]
        spoof = Reply(query, qid=(qid + 1) & 0xFFFF)
        good = Reply(query)
        if qtype == nt.TYPE_A:
            spoof.add(ptr_to(12), nt.TYPE_A, a("203.0.113.66"))
            good.add(ptr_to(12), nt.TYPE_A, a("192.0.2.30"))
        return [spoof.bytes(), good.bytes()]

    res = lookup(dns(with_resolver(handler)), "www.example.com")
    assert res["ok"] is True and res["addresses"] == ["192.0.2.30"]


def test_lookup_timeout_retries_once_then_gives_up(dns):
    srv = dns(lambda query, qname, qtype, transport: None)
    started = time.monotonic()
    res = lookup(srv, "www.example.com", timeout_s=0.2)
    assert res == {**res, "ok": False, "error": "No response from the DNS server (timed out)", "addresses": []}
    assert res["resolver"] == {"name": None, "address": "127.0.0.1"}
    assert srv.types() == [nt.TYPE_A, nt.TYPE_A], "one retry, no AAAA query and no resolver-name query"
    assert time.monotonic() - started >= 0.35 and res["duration_ms"] >= 350


def test_lookup_garbage_reply(dns):
    srv = dns(lambda query, qname, qtype, transport: [query[:2] + b"\xff\xff\xff"])
    res = lookup(srv, "www.example.com")
    assert res["ok"] is False and res["error"] == "The DNS server's answer could not be read"
    assert res["resolver"]["name"] is None


def test_reverse_lookup(dns):
    def handler(query, qname, qtype, transport):
        r = Reply(query, aa=True)
        if qname == "53.2.0.192.in-addr.arpa":
            r.add(ptr_to(12), nt.TYPE_PTR, nt.encode_name("host.example.com"), ttl=3600)
            return [r.bytes()]
        if qname == "54.2.0.192.in-addr.arpa":
            return [r.bytes()]                                   # NOERROR, no PTR record
        return [Reply(query, rcode=3).bytes()]

    srv = dns(with_resolver(handler))
    res = lookup(srv, "192.0.2.53")
    assert res == {**res, "name": "192.0.2.53", "ok": True, "error": None, "answer_name": "host.example.com",
                   "addresses": ["192.0.2.53"], "aliases": [], "authoritative": True}
    assert res["records"] == [{"type": "PTR", "name": "53.2.0.192.in-addr.arpa", "value": "host.example.com", "ttl": 3600}]
    assert srv.types()[0] == nt.TYPE_PTR
    assert lookup(srv, "192.0.2.54")["error"] == "No name found for this address"
    missing = lookup(srv, "2001:db8::99")
    assert missing["ok"] is False and missing["error"] == "Non-existent domain" and missing["addresses"] == []


def test_lookup_server_by_name_and_system_server(dns):
    srv = dns(with_resolver(lambda query, qname, qtype, transport: [Reply(query).bytes()]))

    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        if host != "dns.example.net":
            raise socket.gaierror(11001, "host not found")
        return [(socket.AF_INET6, socket.SOCK_DGRAM, 0, "", ("::1", port, 0, 0)),
                (socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("127.0.0.1", port))]

    sockets = SimpleNamespace(socket=socket.socket, getaddrinfo=fake_getaddrinfo)
    by_name = nt.dns_lookup("www.example.com", "dns.example.net", port=srv.port, timeout_s=0.3, sockets=sockets)
    assert by_name["server"] == "dns.example.net" and by_name["resolver"]["address"] == "127.0.0.1", "IPv4 first"
    unknown = nt.dns_lookup("www.example.com", "nowhere.example.net", port=srv.port, sockets=sockets)
    assert unknown == {**unknown, "ok": False, "error": 'Could not find the DNS server "nowhere.example.net"',
                       "resolver": {"name": None, "address": None}}
    system = nt.dns_lookup("www.example.com", None, port=srv.port, timeout_s=0.3, system_server=lambda: "127.0.0.1")
    assert system["server"] is None and system["resolver"]["address"] == "127.0.0.1"
    none = nt.dns_lookup("www.example.com", "", system_server=lambda: None)
    assert none == {**none, "ok": False, "error": "No DNS server is configured on this PC"}
    with pytest.raises(ValueError):
        nt.dns_lookup("www.example.com", "-x")
    with pytest.raises(ValueError):
        nt.dns_lookup("", None)


def test_default_dns_server_prefers_the_internet_adapter_and_ipv4():
    nic = SimpleNamespace(dns=["2001:db8::53", "192.0.2.53"], is_up=True)
    other = SimpleNamespace(dns=["198.51.100.53"], is_up=True)
    down = SimpleNamespace(dns=["203.0.113.53"], is_up=False)
    assert nt.default_dns_server([down, other, nic], nic) == "192.0.2.53"
    assert nt.default_dns_server([down, other], SimpleNamespace(dns=[], is_up=True)) == "198.51.100.53"
    assert nt.default_dns_server([down, SimpleNamespace(dns=["2001:db8::1"], is_up=True)], None) == "2001:db8::1"
    assert nt.default_dns_server([down], None) is None


# =========================================================================== typed lookups
def info_lines(caplog) -> List[str]:
    return [r.getMessage() for r in caplog.records if r.name == "tnt.nettools" and r.levelno >= logging.INFO]


def test_lookup_mx_follows_the_cname_chain(dns, caplog):
    def handler(query, qname, qtype, transport):
        r = Reply(query, aa=True)
        if qname == "www.example.com" and qtype == nt.TYPE_MX:         # "example.com" of the question is at offset 16
            r.add(ptr_to(12), nt.TYPE_CNAME, ptr_to(16), ttl=3600)
            r.add(ptr_to(16), nt.TYPE_MX, mx_rdata(10, b"\x04mail" + ptr_to(16)), ttl=3600)
            r.add(ptr_to(16), nt.TYPE_MX, mx_rdata(10, nt.encode_name("MAIL.example.com")), ttl=3600)   # a name: listed once
            r.add(ptr_to(16), nt.TYPE_MX, mx_rdata(20, nt.encode_name("backup.example.net")), ttl=3600)
            r.add(nt.encode_name("other.example.org"), nt.TYPE_MX, mx_rdata(5, b"\x00"))    # listed, but not on the chain
        elif qname == "other.example.com":                              # only an MX record of another name
            r.add(nt.encode_name("other.example.org"), nt.TYPE_MX, mx_rdata(5, b"\x00"))
        return [r.bytes()]

    srv = dns(with_resolver(handler))
    caplog.set_level(logging.INFO, logger="tnt.nettools")
    res = lookup(srv, "www.example.com", record_type="mx", clock=lambda: T0)
    assert tuple(res) == nt.DNS_RESULT_KEYS
    assert res == {**res, "name": "www.example.com", "type": "MX", "server": "127.0.0.1", "answer_name": "example.com",
                   "addresses": [], "aliases": ["www.example.com"], "authoritative": True, "ok": True, "error": None, "ts": T0}
    assert res["resolver"] == {"name": "dns.example.net", "address": "127.0.0.1"}
    assert [(r["type"], r["name"], r["value"], r["ttl"]) for r in res["records"]] == [
        ("CNAME", "www.example.com", "example.com", 3600), ("MX", "example.com", "10 mail.example.com", 3600),
        ("MX", "example.com", "20 backup.example.net", 3600), ("MX", "other.example.org", "5 .", 300)]
    assert srv.types() == [nt.TYPE_MX, nt.TYPE_PTR], "one query of the type, then the resolver's name"
    info = " ".join(info_lines(caplog))
    assert "DNS lookup (MX): ok in" in info and "example" not in info and "127.0.0.1" not in info
    stray = lookup(srv, "other.example.com", record_type="MX")          # only the record off the chain
    assert stray == {**stray, "ok": False, "error": "No MX records found for this name", "authoritative": None, "addresses": [],
                     "answer_name": None, "aliases": []}
    assert [(r["name"], r["value"]) for r in stray["records"]] == [("other.example.org", "5 .")], "listed, but not found"


def test_typed_lookup_failures(dns, caplog):
    def handler(query, qname, qtype, transport):
        if qname == "missing.example.com":
            return [Reply(query, rcode=3).bytes()]
        if qname == "garbage.example.com":
            return [query[:2] + b"\xff\xff\xff"]
        if qname == "silent.example.com":
            return None
        r = Reply(query, aa=True)
        if qname == "hinfo.example.com":                                   # answers of other types only
            r.add(ptr_to(12), 13, b"\x01x\x01y")                           # HINFO: skipped
            r.add(ptr_to(12), nt.TYPE_TXT, txt_rdata(b"v=spf1 -all"))      # TXT: listed, but not a CAA record
        elif qname == "alias.example.com":                                 # a CNAME to a name without the type
            r.add(ptr_to(12), nt.TYPE_CNAME, nt.encode_name("edge.example.net"))
        return [r.bytes()]

    srv = dns(with_resolver(handler))
    caplog.set_level(logging.INFO, logger="tnt.nettools")
    empty = lookup(srv, "_dmarc.example.com", record_type="TXT")
    assert empty == {**empty, "type": "TXT", "ok": False, "error": "No TXT records found for this name", "answer_name": None,
                     "authoritative": None, "addresses": [], "aliases": [], "records": []}
    assert empty["resolver"]["name"] == "dns.example.net"
    assert info_lines(caplog)[-1].startswith("DNS lookup (TXT): no records in")
    other = lookup(srv, "hinfo.example.com", record_type="CAA")
    assert other == {**other, "ok": False, "error": "No CAA records found for this name", "authoritative": None, "answer_name": None}
    assert [(r["type"], r["value"]) for r in other["records"]] == [("TXT", "v=spf1 -all")]
    # a hop and nothing of the type: the chain's end is the answer name, but nothing was found
    hop = lookup(srv, "alias.example.com", record_type="SRV")
    assert hop == {**hop, "type": "SRV", "ok": False, "error": "No SRV records found for this name", "answer_name": "edge.example.net",
                   "aliases": ["alias.example.com"], "authoritative": None, "addresses": []}
    assert [r["type"] for r in hop["records"]] == ["CNAME"]
    assert info_lines(caplog)[-1].startswith("DNS lookup (SRV): no records in")
    nx = lookup(srv, "missing.example.com", record_type="ns")
    assert nx == {**nx, "type": "NS", "ok": False, "error": "Non-existent domain", "records": []}
    assert info_lines(caplog)[-1].startswith("DNS lookup (NS): non-existent domain in")
    unreadable = lookup(srv, "garbage.example.com", record_type="SRV")
    assert unreadable["ok"] is False and unreadable["error"] == "The DNS server's answer could not be read"
    srv.queries.clear()
    slow = lookup(srv, "silent.example.com", record_type="SOA", timeout_s=0.1)
    assert slow == {**slow, "type": "SOA", "ok": False, "error": "No response from the DNS server (timed out)",
                    "resolver": {"name": None, "address": "127.0.0.1"}}
    assert srv.types() == [nt.TYPE_SOA, nt.TYPE_SOA], "one retry, and no resolver-name query"


def test_lookup_a_or_aaaa_alone(dns):
    def handler(query, qname, qtype, transport):
        r = Reply(query)
        if qtype == nt.TYPE_A:
            r.add(ptr_to(12), nt.TYPE_A, a("192.0.2.10"))
            r.add(ptr_to(12), nt.TYPE_A, a("192.0.2.10"))                  # listed once
        elif qtype == nt.TYPE_AAAA:
            r.add(ptr_to(12), nt.TYPE_AAAA, aaaa("2001:db8::10"))
        return [r.bytes()]

    srv = dns(with_resolver(handler))
    v4 = lookup(srv, "www.example.com", record_type="A")
    assert v4 == {**v4, "type": "A", "ok": True, "addresses": ["192.0.2.10"], "answer_name": "www.example.com",
                  "authoritative": False, "error": None}
    assert [r["type"] for r in v4["records"]] == ["A"] and srv.types() == [nt.TYPE_A, nt.TYPE_PTR]
    v6 = lookup(srv, "www.example.com", record_type=" aaaa ")
    assert v6 == {**v6, "type": "AAAA", "ok": True, "addresses": ["2001:db8::10"]}
    assert srv.types()[2:] == [nt.TYPE_AAAA, nt.TYPE_PTR]


def test_lookup_cname_lists_the_chain(dns):
    def handler(query, qname, qtype, transport):
        r = Reply(query, aa=True)
        if qname == "www.example.com":
            edge = r.add(ptr_to(12), nt.TYPE_CNAME, nt.encode_name("edge.example.net"))
            r.add(ptr_to(edge), nt.TYPE_CNAME, nt.encode_name("e1.cdn.example.net"))
        return [r.bytes()]

    srv = dns(with_resolver(handler))
    res = lookup(srv, "www.example.com", record_type="CNAME")
    assert res == {**res, "type": "CNAME", "ok": True, "answer_name": "e1.cdn.example.net", "addresses": [],
                   "aliases": ["www.example.com", "edge.example.net"], "authoritative": True}
    assert [r["value"] for r in res["records"]] == ["edge.example.net", "e1.cdn.example.net"]
    plain = lookup(srv, "example.com", record_type="CNAME")
    assert plain["ok"] is False and plain["error"] == "No CNAME records found for this name" and plain["answer_name"] is None


def test_lookup_ptr_by_name_and_an_address_with_ptr(dns, caplog):
    def handler(query, qname, qtype, transport):
        r = Reply(query, aa=True)
        if qname == "10.113.0.203.in-addr.arpa":                           # RFC 2317: the PTR sits behind a CNAME
            hop = r.add(ptr_to(12), nt.TYPE_CNAME, nt.encode_name("10.0-25.113.0.203.in-addr.arpa"))
            r.add(ptr_to(hop), nt.TYPE_PTR, nt.encode_name("host.example.com"), ttl=3600)
        elif qname == "53.2.0.192.in-addr.arpa":
            r.add(ptr_to(12), nt.TYPE_PTR, nt.encode_name("ns.example.com"), ttl=3600)
        return [r.bytes()]

    srv = dns(with_resolver(handler))
    caplog.set_level(logging.INFO, logger="tnt.nettools")
    by_name = lookup(srv, "10.113.0.203.in-addr.arpa", record_type="PTR")
    assert by_name == {**by_name, "type": "PTR", "ok": True, "error": None, "answer_name": "host.example.com",
                       "addresses": [], "aliases": ["10.113.0.203.in-addr.arpa"], "authoritative": True}
    assert srv.types() == [nt.TYPE_PTR, nt.TYPE_PTR]
    auto = lookup(srv, "192.0.2.53", clock=lambda: T0)
    typed = lookup(srv, "192.0.2.53", record_type="ptr", clock=lambda: T0)
    assert auto["type"] is None and typed["type"] == "PTR" and typed["addresses"] == ["192.0.2.53"]
    assert {**typed, "type": None, "duration_ms": 0} == {**auto, "duration_ms": 0}, "an address with PTR is the reverse lookup"
    assert [line.split(":")[0] for line in info_lines(caplog)] == ["DNS lookup (PTR)", "DNS lookup (reverse)", "DNS lookup (reverse)"]
    before = list(srv.queries)
    with pytest.raises(ValueError) as err:
        lookup(srv, "192.0.2.53", record_type="MX")
    assert str(err.value) == IP_TYPE_TEXT and srv.queries == before, "refused before any query"


def test_lookup_all_record_types(dns, caplog):
    def handler(query, qname, qtype, transport):
        r = Reply(query, aa=True)
        if qname == "broken.example.com":
            return [Reply(query, rcode=2).bytes()]                          # every type fails: SERVFAIL
        if qname == "example.com":
            if qtype == nt.TYPE_A:
                r.add(ptr_to(12), nt.TYPE_A, a("203.0.113.10"))
            elif qtype == nt.TYPE_AAAA:
                r.add(ptr_to(12), nt.TYPE_AAAA, aaaa("2001:db8::10"))
            elif qtype == nt.TYPE_MX:
                r.add(ptr_to(12), nt.TYPE_MX, mx_rdata(10, nt.encode_name("mail.example.com")), ttl=3600)
            elif qtype == nt.TYPE_TXT:
                return [Reply(query, rcode=2).bytes()]                      # one type fails: skipped, the rest stand
            # every other type: NOERROR with no records
        elif qname == "53.2.0.192.in-addr.arpa":
            r.add(ptr_to(12), nt.TYPE_PTR, nt.encode_name("ns.example.com"), ttl=3600)
        return [r.bytes()]

    srv = dns(with_resolver(handler))
    caplog.set_level(logging.INFO, logger="tnt.nettools")
    res = lookup(srv, "example.com", record_type="all", clock=lambda: T0)
    assert tuple(res) == nt.DNS_RESULT_KEYS
    assert res == {**res, "name": "example.com", "type": "ALL", "server": "127.0.0.1", "answer_name": "example.com",
                   "addresses": ["203.0.113.10", "2001:db8::10"], "aliases": [], "authoritative": True, "ok": True,
                   "error": None, "ts": T0}
    assert [(r["type"], r["value"]) for r in res["records"]] == [
        ("A", "203.0.113.10"), ("AAAA", "2001:db8::10"), ("MX", "10 mail.example.com")]           # TXT (SERVFAIL) is skipped
    assert srv.types() == [nt.TYPE_A, nt.TYPE_AAAA, nt.TYPE_CNAME, nt.TYPE_MX, nt.TYPE_TXT, nt.TYPE_NS, nt.TYPE_SOA,
                           nt.TYPE_SRV, nt.TYPE_CAA, nt.TYPE_NAPTR, nt.TYPE_PTR], "one query per type, then the resolver's name"
    assert info_lines(caplog)[-1].startswith("DNS lookup (ALL): ok in")
    # an IP with ALL is a reverse (PTR) lookup, exactly as Auto is
    srv.queries.clear()
    ip = lookup(srv, "192.0.2.53", record_type="ALL", clock=lambda: T0)
    assert ip == {**ip, "type": "ALL", "ok": True, "answer_name": "ns.example.com", "addresses": ["192.0.2.53"],
                  "aliases": [], "authoritative": True}
    assert srv.types() == [nt.TYPE_PTR, nt.TYPE_PTR], "one PTR lookup, then the resolver's name"
    # every type fails: the whole lookup fails, with the single-lookup reason
    fail = lookup(srv, "broken.example.com", record_type="all")
    assert fail == {**fail, "type": "ALL", "ok": False, "error": "Server failed", "records": [], "addresses": [],
                    "answer_name": None, "aliases": []}


def test_lookup_large_txt_over_tcp_keeps_the_case_of_text(dns):
    long_parts = [bytes([0x61 + i]) * 255 for i in range(4)]

    def handler(query, qname, qtype, transport):
        if transport == "udp":
            return [Reply(query, tc=True).bytes()]
        r = Reply(query)
        r.add(ptr_to(12), nt.TYPE_TXT, txt_rdata(*long_parts))
        r.add(ptr_to(12), nt.TYPE_TXT, txt_rdata(b"Hello"))
        r.add(ptr_to(12), nt.TYPE_TXT, txt_rdata(b"hello"))                   # text keeps its case: both listed
        r.add(ptr_to(12), nt.TYPE_TXT, txt_rdata(b"Hel", b"lo"))              # the same text again: listed once
        return [r.bytes()]

    srv = dns(with_resolver(handler))
    res = lookup(srv, "big.example.com", record_type="TXT")
    assert res["ok"] is True and srv.types("tcp") == [nt.TYPE_TXT]
    assert [r["value"] for r in res["records"]] == [b"".join(long_parts).decode("ascii"), "Hello", "hello"]


def test_lookup_keeps_the_case_of_caa_and_naptr_text(dns):
    regexp = b"!^.*$!sip:info@example.com!"

    def handler(query, qname, qtype, transport):
        r = Reply(query)
        if qtype == nt.TYPE_CAA:
            r.add(ptr_to(12), nt.TYPE_CAA, caa_rdata(0, b"issue", b"ca.example.net"))
            r.add(ptr_to(12), nt.TYPE_CAA, caa_rdata(0, b"issue", b"CA.example.net"))
        elif qtype == nt.TYPE_NAPTR:
            for value in (regexp, regexp.replace(b"info", b"INFO"), regexp):
                r.add(ptr_to(12), nt.TYPE_NAPTR, naptr_rdata(100, 10, b"U", b"E2U+sip", value, b"\x00"))
        return [r.bytes()]

    srv = dns(with_resolver(handler))
    caa = lookup(srv, "example.com", record_type="CAA")
    assert caa["ok"] is True and [r["value"] for r in caa["records"]] == ['0 issue "ca.example.net"', '0 issue "CA.example.net"']
    naptr = lookup(srv, "example.com", record_type="NAPTR")
    assert naptr == {**naptr, "type": "NAPTR", "ok": True, "answer_name": "example.com", "addresses": []}
    assert [r["value"] for r in naptr["records"]] == ['100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .',
                                                      '100 10 "U" "E2U+sip" "!^.*$!sip:INFO@example.com!" .']


# =========================================================================== native seams
class FakeApi:
    """The ``api`` seam: records every call; per-index return codes (an exception is raised, a callable run)."""

    def __init__(self, interfaces: Any = (), release: Optional[Dict[int, Any]] = None,
                 renew: Optional[Dict[int, Any]] = None, flushed: Any = True, unavailable: bool = False) -> None:
        self._interfaces, self.flushed, self.unavailable = interfaces, flushed, unavailable
        self._release, self._renew = dict(release or {}), dict(renew or {})
        self.calls: List[Tuple[Any, ...]] = []

    @staticmethod
    def _answer(value: Any) -> Any:
        if isinstance(value, BaseException):
            raise value
        return value() if callable(value) else value

    def flush_cache(self) -> bool:
        self.calls.append(("flush",))
        if self.unavailable:
            raise nt.NativeUnavailable(0, "dnsapi cannot be loaded")
        return self._answer(self.flushed)

    def interfaces(self) -> List[Tuple[int, str]]:
        self.calls.append(("interfaces",))
        if self.unavailable:
            raise nt.NativeUnavailable(0, "iphlpapi cannot be loaded")
        return list(self._answer(self._interfaces))

    def release(self, index: int, name: str) -> int:
        self.calls.append(("release", index))
        return self._answer(self._release.get(index, 0))

    def renew(self, index: int, name: str) -> int:
        self.calls.append(("renew", index))
        return self._answer(self._renew.get(index, 0))


class FakeRunner:
    """A ``subprocess.run`` stand-in: records ``(argv, kwargs)``; answers per ipconfig switch."""

    def __init__(self, answers: Optional[Dict[str, Any]] = None) -> None:
        self.answers = dict(answers or {})
        self.calls: List[Tuple[List[str], Dict[str, Any]]] = []

    def __call__(self, argv: List[str], **kwargs: Any) -> Any:
        self.calls.append((list(argv), dict(kwargs)))
        answer = self.answers.get(argv[-1], (0, ""))
        if isinstance(answer, BaseException):
            raise answer
        rc, out = answer
        return SimpleNamespace(returncode=rc, stdout=out.encode("ascii"), stderr=b"")


def guid_name(n: int) -> str:
    return "\\DEVICE\\TCPIP_{%08X-0000-4000-8000-%012X}" % (n, n)


def adapter(n: int, name: str, up: bool = True, dhcp: bool = True) -> SimpleNamespace:
    return SimpleNamespace(index=n, guid=guid_name(n)[len("\\DEVICE\\TCPIP_"):], name=name, is_up=up, dhcp_enabled=dhcp,
                           is_loopback=False)


INTERFACES = [(11, guid_name(11)), (12, guid_name(12)), (13, guid_name(13)), (14, guid_name(14))]
ADAPTERS = [adapter(11, "Ethernet"), adapter(12, "Wi-Fi"), adapter(13, "Ethernet 2", up=False),
            adapter(14, "Tunnel", dhcp=False)]
GOOD_ADDRESS = ("Ethernet", "192.0.2.44")


def renew(api: FakeApi, address: Tuple[Optional[str], Optional[str]] = GOOD_ADDRESS, **kw: Any) -> Dict[str, Any]:
    kw.setdefault("adapters_fn", lambda: ADAPTERS)
    kw.setdefault("runner", FakeRunner())
    return nt.release_renew(api=api, address_fn=lambda: address, clock=lambda: T0, **kw)


def test_ctypes_layouts():
    if ctypes.sizeof(ctypes.c_wchar) != 2:
        pytest.skip("the IP helper structures are laid out for Windows (WCHAR = 2 bytes)")
    assert ctypes.sizeof(nt.IP_ADAPTER_INDEX_MAP) == 260 == nt._INDEX_MAP_SIZE
    assert nt.IP_ADAPTER_INDEX_MAP.Index.offset == 0 and nt.IP_ADAPTER_INDEX_MAP.Name.offset == 4
    assert nt.IP_INTERFACE_INFO.Adapter.offset == 4 == nt._ROWS_OFFSET and ctypes.sizeof(nt.IP_INTERFACE_INFO) == 264


def test_read_interface_info():
    def row(index: int, name: str) -> bytes:
        return struct.pack("<I", index) + name.encode("utf-16-le").ljust(256, b"\x00")

    raw = struct.pack("<i", 2) + row(11, guid_name(11)) + row(12, guid_name(12))
    assert nt.read_interface_info(raw) == [(11, guid_name(11)), (12, guid_name(12))]
    assert nt.read_interface_info(b"") == [] and nt.read_interface_info(struct.pack("<i", 0)) == []
    for bad in (struct.pack("<i", 3) + row(1, "x"), struct.pack("<i", -1)):
        with pytest.raises(OSError):
            nt.read_interface_info(bad)


def test_native_api_is_unavailable_without_windll(monkeypatch):
    """Off Windows (no ctypes.WinDLL) nothing is loaded or called: every method says the API is unavailable."""
    monkeypatch.delattr(ctypes, "WinDLL", raising=False)
    monkeypatch.setattr(nt, "_functions", {})
    api = nt.NetApi()
    for call in (api.flush_cache, api.interfaces, lambda: api.release(1, "x"), lambda: api.renew(1, "x")):
        with pytest.raises(nt.NativeUnavailable):
            call()


def test_ipconfig_exe_comes_from_system32(monkeypatch, tmp_path):
    (tmp_path / "System32").mkdir()
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    assert nt.ipconfig_exe() == "ipconfig"                   # never PATH: the bare name only when the file is missing
    (tmp_path / "System32" / "ipconfig.exe").write_bytes(b"")
    assert nt.ipconfig_exe() == os.path.join(str(tmp_path), "System32", "ipconfig.exe")


# =========================================================================== flush DNS
def test_flush_native():
    api, runner = FakeApi(), FakeRunner()
    res = nt.flush_dns(api=api, runner=runner, clock=lambda: T0)
    assert tuple(res) == nt.FLUSH_RESULT_KEYS
    assert res == {**res, "ok": True, "method": "native", "error": None, "ts": T0}
    assert api.calls == [("flush",)] and runner.calls == []
    failed = nt.flush_dns(api=FakeApi(flushed=False), runner=runner)
    assert failed == {**failed, "ok": False, "method": "native", "error": "Windows did not flush the DNS cache"}
    broken = nt.flush_dns(api=FakeApi(flushed=OSError(5, "Access is denied.")), runner=runner)
    assert broken["ok"] is False and broken["error"] == "Flushing the DNS cache failed: Access is denied."
    assert runner.calls == []


def test_flush_falls_back_to_ipconfig():
    runner = FakeRunner({"/flushdns": (0, "\r\nWindows IP Configuration\r\n\r\nSuccessfully flushed the DNS Resolver Cache.\r\n")})
    res = nt.flush_dns(api=FakeApi(unavailable=True), runner=runner)
    assert res == {**res, "ok": True, "method": "ipconfig", "error": None}
    (argv, kwargs), = runner.calls
    assert argv == [nt.ipconfig_exe(), "/flushdns"]
    if os.environ.get("SystemRoot") and os.path.isfile(os.path.join(os.environ["SystemRoot"], "System32", "ipconfig.exe")):
        assert argv[0].lower() == os.path.join(os.environ["SystemRoot"], "System32", "ipconfig.exe").lower()
    assert kwargs["timeout"] == nt.FLUSH_TIMEOUT_S and kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0) and not kwargs.get("shell")
    fail = nt.flush_dns(api=FakeApi(unavailable=True), runner=FakeRunner(
        {"/flushdns": (1, "Windows IP Configuration\r\n\r\nCould not flush the DNS Resolver Cache: Function failed during execution.\r\n")}))
    assert fail == {**fail, "ok": False, "method": "ipconfig",
                    "error": "Could not flush the DNS Resolver Cache: Function failed during execution."}
    slow = nt.flush_dns(api=FakeApi(unavailable=True),
                        runner=FakeRunner({"/flushdns": subprocess.TimeoutExpired(["ipconfig"], 30)}))
    assert slow["ok"] is False and slow["error"] == "ipconfig /flushdns did not finish within 30 s"
    missing = nt.flush_dns(api=FakeApi(unavailable=True), runner=FakeRunner({"/flushdns": FileNotFoundError()}))
    assert missing["ok"] is False and missing["error"] == "ipconfig is not available"


# =========================================================================== release / renew
def test_release_renew_releases_every_dhcp_adapter_then_renews_them(caplog):
    api = FakeApi(INTERFACES)
    caplog.set_level(logging.INFO, logger="tnt.nettools")
    res = renew(api)
    assert tuple(res) == nt.RENEW_RESULT_KEYS
    assert api.calls == [("interfaces",), ("release", 11), ("release", 12), ("renew", 11), ("renew", 12)]
    assert res == {**res, "ok": True, "address": "192.0.2.44", "adapter": "Ethernet", "warnings": [],
                   "paused_monitoring": False, "method": "native", "error": None, "ts": T0}
    assert res["adapters"] == [{"name": "Ethernet", "released": True, "renewed": True, "error": None},
                               {"name": "Wi-Fi", "released": True, "renewed": True, "error": None}]
    assert all(tuple(row) == nt.RENEW_ADAPTER_KEYS for row in res["adapters"])
    info = " ".join(r.getMessage() for r in caplog.records if r.levelno >= logging.INFO)
    assert "2 of 2 adapter(s) renewed" in info and "Ethernet" not in info and "192.0.2.44" not in info


def test_release_renew_renews_after_a_failed_release():
    res = renew(FakeApi(INTERFACES, release={11: 5}))
    text = nt.win_error_text(5)
    assert res["ok"] is True and res["error"] is None
    assert res["adapters"][0] == {"name": "Ethernet", "released": False, "renewed": True, "error": text}
    assert res["warnings"] == [f"Ethernet: {text}"]


def test_release_renew_without_an_address_afterwards():
    api = FakeApi(INTERFACES, renew={11: 1460, 12: 1460})
    res = renew(api, address=("Wi-Fi", "169.254.10.20"))
    assert res == {**res, "ok": False, "address": "169.254.10.20", "adapter": "Wi-Fi",
                   "error": "No IPv4 address after renewing: the DHCP server did not answer"}
    assert [row["renewed"] for row in res["adapters"]] == [False, False] and len(res["warnings"]) == 2
    apipa = renew(FakeApi(INTERFACES), address=("Ethernet", "169.254.1.1"))
    assert apipa["ok"] is False and apipa["error"] == "No IPv4 address after renewing: the DHCP server did not answer"
    gone = renew(FakeApi(INTERFACES), address=(None, None))
    assert gone["ok"] is False and gone["address"] is None and gone["adapter"] is None


def test_release_renew_names_the_renew_failure_when_the_address_stayed():
    res = renew(FakeApi(INTERFACES, release={11: 5, 12: 5}, renew={11: 5, 12: 5}))
    assert res["ok"] is False and res["error"] == f"Ethernet: {nt.win_error_text(5)}"
    assert res["warnings"] == [f"Ethernet: {nt.win_error_text(5)}", f"Wi-Fi: {nt.win_error_text(5)}"]


def test_release_renew_without_dhcp_adapters_touches_nothing():
    api = FakeApi(INTERFACES)
    res = renew(api, adapters_fn=lambda: [adapter(11, "Ethernet", dhcp=False), adapter(12, "Wi-Fi", up=False)])
    assert res == {**res, "ok": False, "adapters": [], "error": "No adapter gets its address from DHCP"}
    assert api.calls == [("interfaces",)]
    listed_none = renew(FakeApi([]))
    assert listed_none["error"] == "No adapter gets its address from DHCP"


def test_release_renew_interface_list_failure():
    api = FakeApi(OSError(1231, "The network location cannot be reached."))
    res = renew(api)
    assert res == {**res, "ok": False, "method": "native", "error": "The network location cannot be reached."}
    assert api.calls == [("interfaces",)]


def test_release_renew_bounds_a_stuck_native_call(monkeypatch):
    monkeypatch.setattr(nt, "RENEW_TIMEOUT_S", 0.05)
    stuck = threading.Event()
    try:
        res = renew(FakeApi(INTERFACES[:1], renew={11: lambda: stuck.wait(5.0) and 0}))
        assert res["adapters"] == [{"name": "Ethernet", "released": True, "renewed": False,
                                    "error": "the renew did not finish within 0.05 s"}]
        assert res["ok"] is False and res["error"] == "Ethernet: the renew did not finish within 0.05 s"
    finally:
        stuck.set()


def test_release_renew_caps_warnings():
    many = [(n, guid_name(n)) for n in range(1, 13)]
    long_error = OSError(0, "x" * 500)
    res = renew(FakeApi(many, release={n: long_error for n in range(1, 13)}),
                adapters_fn=lambda: [adapter(n, f"Adapter {n}") for n in range(1, 13)])
    assert res["ok"] is True and len(res["warnings"]) == 10 and all(len(w) <= 200 for w in res["warnings"])
    assert res["warnings"][0].startswith("Adapter 1: xxx")


def test_release_renew_falls_back_to_ipconfig():
    runner = FakeRunner({
        "/release": (1, "Windows IP Configuration\r\n\r\nAn error occurred while releasing interface Wi-Fi : "
                        "The media is disconnected.\r\n"),
        "/renew": (0, "Windows IP Configuration\r\n\r\nEthernet adapter Ethernet:\r\n\r\n   IPv4 Address. . . : 192.0.2.44\r\n"),
    })
    res = renew(FakeApi(unavailable=True), runner=runner)
    assert tuple(res) == nt.RENEW_RESULT_KEYS
    assert res == {**res, "ok": True, "method": "ipconfig", "adapters": [], "error": None, "address": "192.0.2.44",
                   "warnings": ["An error occurred while releasing interface Wi-Fi : The media is disconnected."]}
    assert [argv[1:] for argv, _kw in runner.calls] == [["/release"], ["/renew"]]
    assert [kw["timeout"] for _argv, kw in runner.calls] == [nt.RELEASE_TIMEOUT_S, nt.RENEW_TIMEOUT_S]
    assert all(kw["stdin"] is subprocess.DEVNULL and not kw.get("shell") for _argv, kw in runner.calls)


def test_ipconfig_fallback_failures():
    slow_release = FakeRunner({"/release": subprocess.TimeoutExpired(["ipconfig"], 60)})
    res = renew(FakeApi(unavailable=True), runner=slow_release)
    assert [argv[1:] for argv, _kw in slow_release.calls] == [["/release"], ["/renew"]], "renew runs after a failed release"
    assert res["ok"] is True and res["warnings"] == ["ipconfig /release did not finish within 60 s"]
    slow_renew = renew(FakeApi(unavailable=True), runner=FakeRunner({"/renew": subprocess.TimeoutExpired(["ipconfig"], 120)}))
    assert slow_renew["ok"] is False and slow_renew["error"] == "ipconfig /renew did not finish within 120 s"
    missing = renew(FakeApi(unavailable=True), runner=FakeRunner({"/release": FileNotFoundError(), "/renew": FileNotFoundError()}))
    assert missing["ok"] is False and missing["error"] == "ipconfig is not available" and missing["warnings"] == []
    no_lease = renew(FakeApi(unavailable=True), runner=FakeRunner(), address=("Ethernet", "169.254.3.3"))
    assert no_lease["ok"] is False and no_lease["error"] == "No IPv4 address after renewing: the DHCP server did not answer"


def test_release_renew_reads_netinfo_by_default(monkeypatch):
    import tnt.netinfo as netinfo

    dropped: List[str] = []
    monkeypatch.setattr(netinfo, "_invalidate_cache", lambda: dropped.append("drop"))
    monkeypatch.setattr(netinfo, "get_adapters", lambda include_down=True, include_loopback=False: ADAPTERS)
    monkeypatch.setattr(netinfo, "get_internet_nic", lambda adapters=None: SimpleNamespace(name="Wi-Fi", primary_ipv4="192.0.2.45"))
    api = FakeApi(INTERFACES)
    res = nt.release_renew(api=api, runner=FakeRunner())
    assert res["ok"] is True and (res["adapter"], res["address"]) == ("Wi-Fi", "192.0.2.45")
    assert len(dropped) >= 2, "the adapter list and the address are both read afresh"
    monkeypatch.setattr(netinfo, "get_internet_nic", lambda adapters=None: (_ for _ in ()).throw(RuntimeError("boom")))
    broken = nt.release_renew(api=FakeApi(INTERFACES), runner=FakeRunner())
    assert broken["ok"] is False and broken["address"] is None
