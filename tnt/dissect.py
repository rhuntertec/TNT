r"""Frame dissection for the Packet Capture screen: one-line list rows and a Wireshark-style detail tree
(ARCHITECTURE §3.24).

Original code written from IEEE 802.3 and DIX (Ethernet II, LLC), IEEE 802.1Q and 802.1ad (VLAN tags), IEEE 802.1D
(spanning tree BPDUs), IEEE 802.1X (EAPOL), RFC 1042 (SNAP), RFC 826 (ARP), RFC 791 (IPv4), RFC 8200 (IPv6 and its
extension headers), RFC 2516 (PPPoE), RFC 792 (ICMP), RFC 4443 and RFC 4861 (ICMPv6 and neighbour discovery),
RFC 2236 and RFC 3376 (IGMP), RFC 9293 (TCP), RFC 768 (UDP), RFC 1035 (DNS, with RFC 6762 mDNS and RFC 4795 LLMNR),
RFC 1002 (NetBIOS name service), RFC 2131 (DHCP), RFC 8415 (DHCPv6), RFC 9112 (HTTP/1.1 message framing), RFC 8446
and RFC 6066 (the TLS record layer and the server name extension), RFC 3261 (SIP), RFC 3550 (RTP and RTCP), RFC 5905
(NTP), RFC 1350 (TFTP), RFC 7826 (RTSP), RFC 9000 (the QUIC long header), RFC 5424 (syslog) and RFC 3416 (the SNMP
message wrapper). LLDP and CDP are not re-implemented here: :mod:`tnt.lldp` decodes them.

Every function is pure: nothing here opens a socket, runs a program, reads a file or sleeps. Every function survives a
0-byte frame, a 1-byte frame and a frame cut in the middle of any header; no helper raises on malformed bytes.

Rows (:func:`summarize`)
------------------------
One dict per captured frame, exactly :data:`SUMMARY_KEYS` in that order::

    {"ts": float|None, "src": str, "dst": str, "src_mac": str, "dst_mac": str, "proto": str, "sport": int|None,
     "dport": int|None, "length": int, "info": str, "layers": [str, ...], "payload": bytes}

* ``ts`` is passed straight through, never re-read or rounded.
* ``src`` / ``dst`` are the most meaningful addresses as text: the IPv4 or IPv6 addresses when the frame has them, the
  ARP sender and target protocol addresses for ARP, else the MACs, else ``""``.
* ``src_mac`` / ``dst_mac`` are ``"aa:bb:cc:dd:ee:ff"`` (lower case), ``""`` when the link layer has no addresses.
* ``proto`` is the top-most protocol TNT names, one of :data:`PROTOCOLS`; ``"UNKNOWN"`` when even the link layer could
  not be read.
* ``sport`` / ``dport`` come from TCP or UDP only.
* ``length`` is *origlen* when given (the length on the wire), else ``len(frame)``.
* ``info`` is a short summary in Wireshark's spirit, capped at :data:`MAX_INFO` characters, control characters removed:
  ``"49851 > 554 [SYN] Seq=0 Win=64240 Len=0"``, ``"Echo (ping) request id=0x0001 seq=5"``,
  ``"Standard query 0x1a2b A example.com"``, ``"INVITE sip:bob@example.com"``, ``"Application Data"``,
  ``"Who has 192.0.2.5? Tell 192.0.2.1"``. An empty frame gives ``"Empty frame"``; a header cut short gives
  ``"Truncated <label>"``; a header that cannot be one gives ``"Malformed <label>"``.
* ``layers`` is the protocol stack, outermost first, e.g. ``["ETH", "IPv4", "TCP", "HTTP"]``. It names the protocols
  TNT filters on: the ``Frame`` and ``Data`` pseudo-layers, the LLC/SNAP header and IPv6 extension headers appear in
  :func:`detail` only.
* ``payload`` is the bytes after the transport header (``b""`` when the frame has no transport payload, and never a
  copy of the whole frame). It is there so a caller that already has the row does not have to walk the headers again:
  the packet capture hands the payload of a SIP or RTP packet to :mod:`tnt.sipcalls`. It is not part of a row that
  goes to the UI.

Detail tree (:func:`detail`)
----------------------------
One dict per layer, outermost first, exactly :data:`DETAIL_KEYS`, each holding :data:`FIELD_KEYS` dicts::

    {"name": str, "summary": str, "start": int, "length": int,
     "fields": [{"name": str, "value": str, "start": int, "length": int}, ...]}

``name`` is the same token as in ``layers`` (plus ``"Frame"``, ``"Data"``, ``"LLC"`` and the IPv6 extension headers),
``summary`` the line the UI shows when the layer is collapsed and ``value`` is always text. ``start`` and ``length``
are byte offsets into *frame* so the UI can highlight a selected field, both clamped into the frame; a field that is
not a single run of bytes (an arrival time, a value taken from a parsed record) has length 0. The first layer is
always ``Frame``: arrival time (UTC, or "not recorded"), epoch time, captured length, length on the wire and link type.

Link types
----------
1 Ethernet (the normal case), 101 raw IP (the first nibble picks IPv4 or IPv6), 228 raw IPv4 and 229 raw IPv6. Any
other link type gives one ``Data`` layer, ``proto`` ``"UNKNOWN"`` and the info ``"Link type <n> is not dissected"``,
as does a link type 101 frame whose first nibble is neither 4 nor 6 (``"Raw IP version <n> is not dissected"``).

Heuristics
----------
Ports decide first: :data:`PORTS` maps ``"tcp"`` and ``"udp"`` port numbers to a protocol name, destination port
before source port. When neither port is known the payload is sniffed: a request line whose version token is
``SIP/2.0``, ``RTSP/1.0`` or ``HTTP/1.x`` (or a status line starting with one) names SIP, RTSP or HTTP, so a SIP call
on an odd port is still found; a TLS record header (content type 20-23, version 3.x, sane length) names TLS; and on
UDP a version-2 RTP header on an even port above 1023 with a sane payload type names RTP, while a version-2 header
whose packet type is 200-207 names RTCP, whatever the ports (the four fixed bytes of a receiver report are enough).
An application handler that does not recognise its own payload falls back to the transport row and a ``Data`` layer.

Filters
-------
:data:`PROTO_FILTERS` maps a quick-filter button key to the ``proto`` / ``layers`` values it matches, in the order the
buttons are meant to appear. :func:`matches_proto` uses it (an unlisted key matches a layer of the same name, ignoring
case). :func:`matches_ip` accepts a bare IPv4 or IPv6 literal, optionally in brackets or with white space around it,
and compares the parsed address with ``src`` and ``dst``. :func:`matches_mac` accepts ``:``, ``-``, ``.`` or no
separators in any case. All three return False for text that is not an address, and never raise.

Caps (untrusted bytes drive every one of these)
-----------------------------------------------
:data:`MAX_VLAN_TAGS` 2 stacked VLAN tags, :data:`MAX_EXTENSION_HEADERS` 8 IPv6 extension headers,
:data:`MAX_TCP_OPTION_BYTES` 40 bytes of TCP options, :data:`MAX_DHCP_OPTIONS` 128 DHCP options,
:data:`MAX_TLS_EXTENSIONS` 32 TLS extensions, :data:`MAX_DNS_LABELS` 128 labels and :data:`MAX_DNS_NAME` 255
characters per DNS name with at most :data:`MAX_DNS_POINTERS` compression pointers, each of which must point strictly
backwards: before the pointer itself and before the one before it. :data:`MAX_INFO` caps the row text and
:data:`MAX_FIELD_TEXT` a field's value, including the hex of an ARP address that is not Ethernet over IPv4.

Contract gaps filled here
-------------------------
* The frame is dissected as far as it parses and no further: the first header that is cut short or cannot be one adds
  its layer with the summary ``"<label>: truncated after <n> bytes"`` or ``"<label>: malformed header"``, and the
  bytes left over become the ``Data`` layer. Nothing is reassembled, no checksum is verified and no stream is tracked,
  so TCP sequence numbers are the absolute ones from the frame, not Wireshark's relative ones.
* An IPv4 total length or UDP length that is longer than the captured bytes is clamped to them; one shorter than its
  own header is ignored. A fragment with a non-zero offset stops the walk: ``info`` says so and the payload is data.
* An IPv6 extension header that is cut short stops the walk with ``"Truncated <label>"``; only a real next header 59
  gives ``"No next header"``.
* An IGMPv3 membership report (type 0x22) has group records, not a group address: the row names the group of a lone
  record, else how many records there are.
* LLDP and CDP layers are built from the NEIGHBOR dict of :func:`tnt.lldp.parse_lldp` / :func:`tnt.lldp.parse_cdp`,
  which carries no offsets, so their fields have length 0. A frame those return None for still gets its layer, with
  the info ``"LLDP advertisement"`` / ``"CDP advertisement"``.
* SIP is named and its first line is read here; call reconstruction lives in :mod:`tnt.sipcalls`.
* SNMP gives the version and the length of the community string, never the community itself.
* :func:`hex_dump` clamps *width* into 1..:data:`MAX_DUMP_WIDTH` rather than raising, and returns ``[]`` for no data.
"""
from __future__ import annotations

import datetime
import ipaddress
import struct
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import lldp

__all__ = ["SUMMARY_KEYS", "DETAIL_KEYS", "FIELD_KEYS", "PROTOCOLS", "PROTO_FILTERS", "PORTS", "MAX_INFO",
           "MAX_FIELD_TEXT", "MAX_VLAN_TAGS", "MAX_EXTENSION_HEADERS", "MAX_TCP_OPTION_BYTES", "MAX_DHCP_OPTIONS",
           "MAX_TLS_EXTENSIONS", "MAX_DNS_LABELS", "MAX_DNS_NAME", "MAX_DNS_POINTERS", "MAX_DUMP_WIDTH",
           "summarize", "detail", "hex_dump", "mac_text", "matches_mac", "matches_ip", "matches_proto"]

SUMMARY_KEYS = ("ts", "src", "dst", "src_mac", "dst_mac", "proto", "sport", "dport", "length", "info", "layers",
                "payload")
DETAIL_KEYS = ("name", "summary", "start", "length", "fields")
FIELD_KEYS = ("name", "value", "start", "length")

#: Every value ``summarize()`` may put in ``proto`` (and, but for the pseudo-layers, in ``layers``).
PROTOCOLS = ("ETH", "802.1Q", "ARP", "IPv4", "IPv6", "PPPoE", "IPX", "EAPOL", "STP", "LLDP", "CDP", "WOL", "ICMP",
             "ICMPv6", "IGMP", "TCP", "UDP", "DNS", "MDNS", "LLMNR", "NBNS", "DHCP", "DHCPv6", "HTTP", "TLS", "SIP",
             "RTP", "RTCP", "NTP", "SSDP", "SNMP", "SMB", "TFTP", "RTSP", "QUIC", "SYSLOG", "UNKNOWN")

MAX_INFO = 160                     # characters of row text
MAX_FIELD_TEXT = 200               # characters of a field value taken from the frame
MAX_VLAN_TAGS = 2
MAX_EXTENSION_HEADERS = 8
MAX_TCP_OPTION_BYTES = 40
MAX_DHCP_OPTIONS = 128
MAX_TLS_EXTENSIONS = 32
MAX_DNS_LABELS = 128
MAX_DNS_NAME = 255
MAX_DNS_POINTERS = 16
MAX_DUMP_WIDTH = 64

#: Quick-filter button key -> the ``proto`` / ``layers`` values it matches, in button order.
PROTO_FILTERS: Dict[str, Tuple[str, ...]] = {
    "icmp": ("ICMP", "ICMPv6"),
    "arp": ("ARP",),
    "dns": ("DNS", "MDNS", "LLMNR", "NBNS"),
    "dhcp": ("DHCP", "DHCPv6"),
    "http": ("HTTP",),
    "https": ("TLS", "QUIC"),
    "tls": ("TLS",),
    "sip": ("SIP",),
    "rtp": ("RTP", "RTCP"),
    "rtsp": ("RTSP",),
    "tcp": ("TCP",),
    "udp": ("UDP",),
    "ipv4": ("IPv4",),
    "ipv6": ("IPv6",),
    "vlan": ("802.1Q",),
    "ntp": ("NTP",),
    "snmp": ("SNMP",),
    "smb": ("SMB",),
    "tftp": ("TFTP",),
    "quic": ("QUIC",),
    "ssdp": ("SSDP",),
    "syslog": ("SYSLOG",),
    "igmp": ("IGMP",),
    "discovery": ("LLDP", "CDP"),
    "stp": ("STP",),
    "eapol": ("EAPOL",),
    "wol": ("WOL",),
}

#: Well-known ports, by transport. The destination port is looked up before the source port.
PORTS: Dict[str, Dict[int, str]] = {
    "tcp": {53: "DNS", 80: "HTTP", 88: "HTTP", 139: "SMB", 443: "TLS", 445: "SMB", 465: "TLS", 514: "SYSLOG",
            554: "RTSP", 993: "TLS", 995: "TLS", 1900: "SSDP", 5060: "SIP", 5061: "TLS", 5222: "TLS", 5353: "MDNS",
            5355: "LLMNR", 8000: "HTTP", 8008: "HTTP", 8080: "HTTP", 8443: "TLS", 8554: "RTSP"},
    "udp": {7: "WOL", 9: "WOL", 53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP", 137: "NBNS", 161: "SNMP",
            162: "SNMP", 443: "QUIC", 514: "SYSLOG", 546: "DHCPv6", 547: "DHCPv6", 554: "RTSP", 1900: "SSDP",
            5060: "SIP", 5353: "MDNS", 5355: "LLMNR"},
}

_ETHERNET_HEADER = 14
_MAX_8023_LENGTH = 1500
_VLAN_TYPES = (0x8100, 0x88A8, 0x9100)
_ETHERTYPE_IPV4, _ETHERTYPE_ARP, _ETHERTYPE_WOL = 0x0800, 0x0806, 0x0842
_ETHERTYPE_RARP, _ETHERTYPE_IPX, _ETHERTYPE_IPV6 = 0x8035, 0x8137, 0x86DD
_ETHERTYPE_PPPOE_DISCOVERY, _ETHERTYPE_PPPOE_SESSION = 0x8863, 0x8864
_ETHERTYPE_EAPOL, _ETHERTYPE_LLDP = 0x888E, 0x88CC

_ETHERTYPE_TEXT = {0x0800: "IPv4", 0x0806: "ARP", 0x0842: "Wake-on-LAN", 0x8035: "RARP", 0x8100: "802.1Q",
                   0x8137: "IPX", 0x86DD: "IPv6", 0x8863: "PPPoE Discovery", 0x8864: "PPPoE Session",
                   0x888E: "EAPOL", 0x88A8: "802.1ad", 0x88CC: "LLDP", 0x88E5: "MACsec", 0x8892: "PROFINET",
                   0x9100: "802.1Q QinQ", 0x22F0: "AVTP"}

_IP_ICMP, _IP_IGMP, _IP_IPV4, _IP_TCP, _IP_UDP, _IP_IPV6, _IP_ICMPV6 = 1, 2, 4, 6, 17, 41, 58
_IP_HOPOPT, _IP_ROUTING, _IP_FRAGMENT, _IP_AH, _IP_NONE, _IP_DSTOPTS = 0, 43, 44, 51, 59, 60
_IP_PROTO_TEXT = {0: "Hop-by-hop options", 1: "ICMP", 2: "IGMP", 4: "IPv4", 6: "TCP", 17: "UDP", 41: "IPv6",
                  43: "Routing header", 44: "Fragment header", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
                  59: "No next header", 60: "Destination options", 89: "OSPF", 103: "PIM", 112: "VRRP",
                  132: "SCTP", 135: "Mobility header"}
_IPV6_EXTENSIONS = {_IP_HOPOPT: "IPv6 Hop-by-Hop Options", _IP_ROUTING: "IPv6 Routing", _IP_FRAGMENT: "IPv6 Fragment",
                    _IP_AH: "IPv6 Authentication", _IP_DSTOPTS: "IPv6 Destination Options", 135: "IPv6 Mobility"}
_IP_STOP = -1                                         # not a protocol number: an extension header walk that stopped

_LINKTYPE_ETHERNET, _LINKTYPE_RAW, _LINKTYPE_IPV4, _LINKTYPE_IPV6 = 1, 101, 228, 229
_LINKTYPE_TEXT = {1: "Ethernet", 101: "Raw IP", 228: "Raw IPv4", 229: "Raw IPv6"}

_ARP_OPCODES = {1: "request", 2: "reply", 3: "RARP request", 4: "RARP reply", 8: "InARP request", 9: "InARP reply"}

_TCP_FLAG_BITS = ((0x001, "FIN"), (0x002, "SYN"), (0x004, "RST"), (0x008, "PSH"), (0x010, "ACK"), (0x020, "URG"),
                  (0x040, "ECE"), (0x080, "CWR"), (0x100, "NS"))
_TCP_FLAG_ORDER = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS")

_ICMP_TYPE_TEXT = {0: "Echo (ping) reply", 3: "Destination unreachable", 4: "Source quench", 5: "Redirect",
                   8: "Echo (ping) request", 9: "Router advertisement", 10: "Router solicitation",
                   11: "Time-to-live exceeded", 12: "Parameter problem", 13: "Timestamp request",
                   14: "Timestamp reply", 17: "Address mask request", 18: "Address mask reply"}
_ICMP_UNREACHABLE = {0: "Network unreachable", 1: "Host unreachable", 2: "Protocol unreachable",
                     3: "Port unreachable", 4: "Fragmentation needed", 5: "Source route failed",
                     9: "Network administratively prohibited", 10: "Host administratively prohibited",
                     13: "Communication administratively filtered"}
_ICMP_EXCEEDED = {0: "Time to live exceeded in transit", 1: "Fragment reassembly time exceeded"}
_ICMP_REDIRECT = {0: "Redirect for network", 1: "Redirect for host", 2: "Redirect for service and network",
                  3: "Redirect for service and host"}
_ICMP_ECHO_TYPES = (0, 8)

_ICMPV6_TYPE_TEXT = {1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded", 4: "Parameter problem",
                     128: "Echo (ping) request", 129: "Echo (ping) reply", 130: "Multicast listener query",
                     131: "Multicast listener report", 132: "Multicast listener done",
                     133: "Router solicitation", 134: "Router advertisement", 135: "Neighbour solicitation",
                     136: "Neighbour advertisement", 137: "Redirect", 143: "Multicast listener report v2"}
_ICMPV6_UNREACHABLE = {0: "No route to destination", 1: "Administratively prohibited", 2: "Beyond scope",
                       3: "Address unreachable", 4: "Port unreachable"}
_ICMPV6_ECHO_TYPES = (128, 129)
_ICMPV6_TARGET_TYPES = (135, 136)                     # neighbour solicitation and advertisement carry a target

_IGMP_TYPE_TEXT = {0x11: "Membership query", 0x12: "Membership report v1", 0x16: "Membership report v2",
                   0x17: "Leave group", 0x22: "Membership report v3"}
_IGMP_REPORT_V3 = 0x22                                # RFC 3376 §4.2: group records, not a group address
_IGMP_RECORD_FIXED = 8                                # a group record up to and including its multicast address

_DNS_OPCODES = {0: "Standard query", 1: "Inverse query", 2: "Server status request", 4: "Notify", 5: "Update"}
_DNS_RCODES = {0: "", 1: "Format error", 2: "Server failure", 3: "No such name", 4: "Not implemented", 5: "Refused",
               9: "Not authoritative", 10: "Name not in zone"}
_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT", 28: "AAAA",
              33: "SRV", 35: "NAPTR", 41: "OPT", 47: "NSEC", 64: "SVCB", 65: "HTTPS", 251: "IXFR", 252: "AXFR",
              255: "ANY"}

_DHCP_MESSAGE_TEXT = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release",
                      8: "Inform"}
_DHCP_MAGIC = b"\x63\x82\x53\x63"
_DHCP_FIXED = 240                                     # BOOTP header plus the magic cookie
_DHCPV6_MESSAGE_TEXT = {1: "Solicit", 2: "Advertise", 3: "Request", 4: "Confirm", 5: "Renew", 6: "Rebind",
                        7: "Reply", 8: "Release", 9: "Decline", 10: "Reconfigure", 11: "Information request",
                        12: "Relay forward", 13: "Relay reply"}

_TLS_CONTENT_TEXT = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data",
                     24: "Heartbeat"}
_TLS_HANDSHAKE_TEXT = {1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket", 8: "Encrypted Extensions",
                       11: "Certificate", 12: "Server Key Exchange", 13: "Certificate Request",
                       14: "Server Hello Done", 15: "Certificate Verify", 16: "Client Key Exchange",
                       20: "Finished"}
_TLS_VERSION_TEXT = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
_TLS_SERVER_NAME = 0

_RTP_PAYLOAD_TEXT = {0: "PCMU", 3: "GSM", 4: "G.723", 8: "PCMA", 9: "G.722", 10: "L16", 18: "G.729", 26: "JPEG",
                     31: "H.261", 32: "MPV", 34: "H.263"}
_RTCP_PACKET_TEXT = {200: "Sender Report", 201: "Receiver Report", 202: "Source Description", 203: "Goodbye",
                     204: "Application defined", 205: "Transport feedback", 206: "Payload feedback"}
_NTP_MODE_TEXT = {0: "reserved", 1: "symmetric active", 2: "symmetric passive", 3: "client", 4: "server",
                  5: "broadcast", 6: "control message", 7: "private"}
_TFTP_OPCODE_TEXT = {1: "Read request", 2: "Write request", 3: "Data", 4: "Acknowledgement", 5: "Error",
                     6: "Option acknowledgement"}
_SMB2_COMMAND_TEXT = {0: "Negotiate", 1: "Session Setup", 2: "Logoff", 3: "Tree Connect", 4: "Tree Disconnect",
                      5: "Create", 6: "Close", 7: "Flush", 8: "Read", 9: "Write", 10: "Lock", 11: "Ioctl",
                      12: "Cancel", 13: "Echo", 14: "Query Directory", 15: "Change Notify", 16: "Query Info",
                      17: "Set Info", 18: "Oplock Break"}
_QUIC_LONG_TYPE_TEXT = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
_SYSLOG_FACILITY_TEXT = {0: "kernel", 1: "user", 2: "mail", 3: "system", 4: "security", 5: "syslog", 6: "printer",
                         7: "news", 8: "uucp", 9: "clock", 10: "authorisation", 11: "ftp", 12: "ntp", 13: "audit",
                         14: "alert", 15: "clock", 16: "local0", 17: "local1", 18: "local2", 19: "local3",
                         20: "local4", 21: "local5", 22: "local6", 23: "local7"}
_SYSLOG_SEVERITY_TEXT = {0: "emergency", 1: "alert", 2: "critical", 3: "error", 4: "warning", 5: "notice",
                         6: "informational", 7: "debug"}
_EAPOL_TYPE_TEXT = {0: "EAP packet", 1: "Start", 2: "Logoff", 3: "Key", 4: "Encapsulated ASF alert"}
_EAP_CODE_TEXT = {1: "Request", 2: "Response", 3: "Success", 4: "Failure"}
_PPPOE_CODE_TEXT = {0x00: "Session data", 0x09: "PADI", 0x07: "PADO", 0x19: "PADR", 0x65: "PADS", 0xA7: "PADT"}
_PPP_PROTOCOL_TEXT = {0x0021: "IPv4", 0x0057: "IPv6", 0xC021: "LCP", 0xC023: "PAP", 0xC223: "CHAP",
                      0x8021: "IPCP", 0x8057: "IPv6CP"}
_STP_BPDU_TEXT = {0x00: "Configuration", 0x02: "Rapid or multiple spanning tree", 0x80: "Topology change notice"}

_SNAP_OUI_ENCAPSULATED = b"\x00\x00\x00"
_SNAP_OUI_CISCO = b"\x00\x00\x0c"
_CDP_PROTOCOL_ID = 0x2000
_LLC_SNAP, _LLC_STP, _LLC_IPX, _LLC_CONTROL_UI = 0xAA, 0x42, 0xE0, 0x03

_SIP_METHODS = ("INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH",
                "INFO", "REFER", "MESSAGE", "UPDATE")
#: The version token of a request or status line names the protocol, so a method TNT has never heard of still lands in
#: the right dissector (OPTIONS, NOTIFY and SUBSCRIBE are a method of more than one of these).
_VERSION_PROTOCOLS = ((b"SIP/2.0", "SIP"), (b"RTSP/1.0", "RTSP"), (b"HTTP/1.0", "HTTP"), (b"HTTP/1.1", "HTTP"))
_MAX_LINE = 1024                                      # bytes of payload searched for the end of the first line

_RTP_VERSION = 2
_RTP_HEADER = 12
_RTCP_MINIMUM = 4                                     # RFC 3550 §6.4.2: the fixed part of any RTCP packet
_RTCP_TYPES = range(200, 208)
_RTP_DYNAMIC = range(96, 128)
_WOL_PREFIX = b"\xff" * 6
_WOL_REPEATS = 4                                      # repetitions of the MAC that must be there to call it a magic


# --------------------------------------------------------------------------- small readers
def _u16(data: bytes, pos: int) -> int:
    return struct.unpack_from(">H", data, pos)[0]


def _u32(data: bytes, pos: int) -> int:
    return struct.unpack_from(">I", data, pos)[0]


def _field(name: str, value: str, start: int, length: int) -> Dict[str, Any]:
    return {"name": name, "value": value, "start": start, "length": length}


def _clean(text: str, limit: int) -> str:
    """Printable characters only, stripped and capped (control and format characters are dropped, not replaced)."""
    return "".join(ch for ch in text if ch.isprintable()).strip()[:limit]


def _text_of(raw: bytes, limit: int = MAX_FIELD_TEXT) -> str:
    """Bytes from a frame as display text: UTF-8 with replacement, printable characters only, capped."""
    return _clean(bytes(raw).decode("utf-8", errors="replace"), limit)


def _ipv4_text(raw: bytes) -> str:
    return str(ipaddress.IPv4Address(bytes(raw))) if len(raw) == 4 else ""


def _ipv6_text(raw: bytes) -> str:
    return str(ipaddress.IPv6Address(bytes(raw))) if len(raw) == 16 else ""


def _ethertype_text(ethertype: int) -> str:
    name = _ETHERTYPE_TEXT.get(ethertype)
    return f"{name} (0x{ethertype:04x})" if name else f"0x{ethertype:04x}"


def _ip_protocol_text(protocol: int) -> str:
    name = _IP_PROTO_TEXT.get(protocol)
    return f"{name} ({protocol})" if name else f"Protocol {protocol}"


def _linktype_text(linktype: int) -> str:
    name = _LINKTYPE_TEXT.get(linktype)
    return f"{name} ({linktype})" if name else f"Link type {linktype}"


def _time_text(ts: Optional[float]) -> str:
    """*ts* as ``"2023-11-14 22:13:20.123456 UTC"``, or "not recorded"; anything unusable comes back as its number."""
    if ts is None:
        return "not recorded"
    try:
        moment = datetime.datetime.fromtimestamp(float(ts), tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError, TypeError):
        return str(ts)
    return moment.strftime("%Y-%m-%d %H:%M:%S.%f") + " UTC"


def _wire_length(captured: int, origlen: Optional[int]) -> int:
    if isinstance(origlen, bool) or not isinstance(origlen, int) or origlen < 0:
        return captured
    return origlen


def _mac_key(text: str) -> str:
    """A MAC as 12 lower-case hex characters, whatever separators it came with; "" when it is not a MAC."""
    if not isinstance(text, str):
        return ""
    stripped = text.strip().replace(":", "").replace("-", "").replace(".", "").replace(" ", "").lower()
    if len(stripped) != 12:
        return ""
    return stripped if all(ch in "0123456789abcdef" for ch in stripped) else ""


def _as_ip(text: str) -> Optional[Any]:
    """*text* as an :mod:`ipaddress` address, or None; brackets and white space around it are allowed."""
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        stripped = stripped[1:-1].strip()
    if not stripped:
        return None
    try:
        return ipaddress.ip_address(stripped)
    except ValueError:
        return None


def _first_line(payload: bytes) -> bytes:
    """The bytes before the first CR or LF in the first :data:`_MAX_LINE` bytes of *payload*."""
    head = bytes(payload[:_MAX_LINE])
    for ending in (b"\r\n", b"\n", b"\r"):
        cut = head.find(ending)
        if cut >= 0:
            return head[:cut]
    return head


def _line_protocol(payload: bytes) -> Tuple[Optional[str], bytes]:
    """``(protocol name, first line)`` for a text request or status line: the version token names SIP, RTSP or HTTP."""
    line = _first_line(payload)
    if not line:
        return None, line
    for token, name in _VERSION_PROTOCOLS:
        if line.startswith(token + b" "):
            return name, line
    parts = line.split(b" ")
    if len(parts) >= 3:
        for token, name in _VERSION_PROTOCOLS:
            if parts[-1] == token:
                return name, line
    return None, line


# --------------------------------------------------------------------------- the walk
class _Walk:
    """The state of one dissection: the frame, the layers built so far and the row values they fill in."""

    __slots__ = ("frame", "size", "layers", "names", "src", "dst", "src_mac", "dst_mac", "proto", "sport", "dport",
                 "info", "payload")

    def __init__(self, frame: bytes) -> None:
        self.frame = frame
        self.size = len(frame)
        self.layers: List[Dict[str, Any]] = []
        self.names: List[str] = []
        self.src = self.dst = self.src_mac = self.dst_mac = ""
        self.proto = "UNKNOWN"
        self.sport: Optional[int] = None
        self.dport: Optional[int] = None
        self.info = ""
        self.payload = b""              # the bytes after the transport header (tnt.sipcalls reads SIP and RTP here)

    def add(self, name: str, summary: str, start: int, length: int, fields: List[Dict[str, Any]], *,
            named: bool = True) -> None:
        """Append one layer, clamping its own and its fields' offsets into the frame."""
        start = max(0, min(start, self.size))
        for item in fields:
            item["start"] = max(0, min(item["start"], self.size))
            item["length"] = max(0, min(item["length"], self.size - item["start"]))
        if named:
            self.names.append(name)
            self.proto = name
        self.layers.append({"name": name, "summary": _clean(summary, MAX_INFO), "start": start,
                            "length": max(0, min(length, self.size - start)), "fields": fields})

    def say(self, info: str) -> None:
        self.info = _clean(info, MAX_INFO)

    def data(self, start: int, end: int) -> None:
        """The bytes left over after the last layer TNT understands."""
        left = min(end, self.size) - start
        if left > 0:
            self.add("Data", f"Data: {left} bytes", start, left, [_field("Data", f"{left} bytes", start, left)],
                     named=False)

    def truncated(self, name: str, label: str, start: int, *, named: bool = True) -> None:
        left = max(0, self.size - start)
        self.add(name, f"{label}: truncated after {left} bytes", start, left,
                 [_field("Truncated", f"{left} bytes of the {label} header", start, left)], named=named)
        self.say(f"Truncated {label}")

    def malformed(self, name: str, label: str, start: int, end: int) -> None:
        left = max(0, min(end, self.size) - start)
        self.add(name, f"{label}: malformed header", start, left,
                 [_field("Malformed", f"{left} bytes that are not a {label} header", start, left)])
        self.say(f"Malformed {label}")


# --------------------------------------------------------------------------- link layer
def _ethernet(w: _Walk, start: int) -> None:
    if w.size - start < _ETHERNET_HEADER:
        w.truncated("ETH", "Ethernet", start)
        return
    w.dst_mac = mac_text(w.frame[start:start + 6])
    w.src_mac = mac_text(w.frame[start + 6:start + 12])
    w.src, w.dst = w.src_mac, w.dst_mac
    ethertype = _u16(w.frame, start + 12)
    fields = [_field("Destination", w.dst_mac, start, 6), _field("Source", w.src_mac, start + 6, 6)]
    payload = start + _ETHERNET_HEADER
    if ethertype <= _MAX_8023_LENGTH:
        fields.append(_field("Length", str(ethertype), start + 12, 2))
        w.add("ETH", f"Ethernet 802.3, {w.src_mac} > {w.dst_mac}, length {ethertype}", start, _ETHERNET_HEADER, fields)
        w.say(f"{w.src_mac} > {w.dst_mac}, 802.3 length {ethertype}")
        _llc(w, payload, min(w.size, payload + ethertype))
        return
    fields.append(_field("Type", _ethertype_text(ethertype), start + 12, 2))
    w.add("ETH", f"Ethernet II, {w.src_mac} > {w.dst_mac}, type {_ethertype_text(ethertype)}", start,
          _ETHERNET_HEADER, fields)
    w.say(f"{w.src_mac} > {w.dst_mac}, type {_ethertype_text(ethertype)}")
    _after_ethertype(w, ethertype, payload, w.size)


def _after_ethertype(w: _Walk, ethertype: int, pos: int, end: int) -> None:
    """VLAN tags (at most :data:`MAX_VLAN_TAGS`) and then the network layer the ethertype names."""
    tags = 0
    while ethertype in _VLAN_TYPES and tags < MAX_VLAN_TAGS:
        if end - pos < 4:
            w.truncated("802.1Q", "VLAN tag", pos)
            return
        tci = _u16(w.frame, pos)
        inner = _u16(w.frame, pos + 2)
        vid, pcp, dei = tci & 0x0FFF, tci >> 13, (tci >> 12) & 1
        kind = "802.1ad service tag" if ethertype in (0x88A8, 0x9100) else "802.1Q tag"
        w.add("802.1Q", f"VLAN {vid}, priority {pcp} ({kind})", pos, 4,
              [_field("Priority", str(pcp), pos, 2), _field("Drop eligible", "1" if dei else "0", pos, 2),
               _field("VLAN ID", str(vid), pos, 2), _field("Type", _ethertype_text(inner), pos + 2, 2)])
        w.say(f"VLAN {vid}, priority {pcp}, type {_ethertype_text(inner)}")
        ethertype, pos, tags = inner, pos + 4, tags + 1
    if ethertype == _ETHERTYPE_IPV4:
        _ipv4(w, pos, end)
    elif ethertype == _ETHERTYPE_IPV6:
        _ipv6(w, pos, end)
    elif ethertype in (_ETHERTYPE_ARP, _ETHERTYPE_RARP):
        _arp(w, pos, end)
    elif ethertype == _ETHERTYPE_LLDP:
        _lldp_layer(w, pos, end)
    elif ethertype == _ETHERTYPE_EAPOL:
        _eapol(w, pos, end)
    elif ethertype in (_ETHERTYPE_PPPOE_DISCOVERY, _ETHERTYPE_PPPOE_SESSION):
        _pppoe(w, pos, end, ethertype == _ETHERTYPE_PPPOE_SESSION)
    elif ethertype == _ETHERTYPE_IPX:
        _ipx(w, pos, end)
    elif ethertype == _ETHERTYPE_WOL:
        if not _wol(w, pos, end, "WOL"):
            w.data(pos, end)
    else:
        w.data(pos, end)


def _llc(w: _Walk, start: int, end: int) -> None:
    """An IEEE 802.2 LLC header, with SNAP folded into it; the layer is not named, so it never becomes ``proto``."""
    if end - start >= 2 and w.frame[start:start + 2] == b"\xff\xff":
        _ipx(w, start, end)                              # Novell raw 802.3
        return
    if end - start < 3:
        w.truncated("LLC", "LLC", start, named=False)
        return
    dsap, ssap, control = w.frame[start], w.frame[start + 1], w.frame[start + 2]
    fields = [_field("DSAP", f"0x{dsap:02x}", start, 1), _field("SSAP", f"0x{ssap:02x}", start + 1, 1),
              _field("Control", f"0x{control:02x}", start + 2, 1)]
    if dsap == _LLC_SNAP and ssap == _LLC_SNAP and control == _LLC_CONTROL_UI and end - start >= 8:
        oui, protocol_id = w.frame[start + 3:start + 6], _u16(w.frame, start + 6)
        fields.append(_field("Organisation code", oui.hex(":"), start + 3, 3))
        fields.append(_field("Protocol ID", f"0x{protocol_id:04x}", start + 6, 2))
        w.add("LLC", f"LLC with SNAP, protocol 0x{protocol_id:04x}", start, 8, fields, named=False)
        if oui == _SNAP_OUI_ENCAPSULATED:
            _after_ethertype(w, protocol_id, start + 8, end)
        elif oui == _SNAP_OUI_CISCO and protocol_id == _CDP_PROTOCOL_ID:
            _cdp_layer(w, start + 8, end)
        else:
            w.data(start + 8, end)
        return
    w.add("LLC", f"LLC, DSAP 0x{dsap:02x}, SSAP 0x{ssap:02x}", start, 3, fields, named=False)
    if dsap == _LLC_STP:
        _stp(w, start + 3, end)
    elif dsap == _LLC_IPX:
        _ipx(w, start + 3, end)
    else:
        w.data(start + 3, end)


def _stp(w: _Walk, start: int, end: int) -> None:
    if end - start < 4:
        w.truncated("STP", "STP", start)
        return
    protocol_id, version, bpdu_type = _u16(w.frame, start), w.frame[start + 2], w.frame[start + 3]
    kind = _STP_BPDU_TEXT.get(bpdu_type, f"type 0x{bpdu_type:02x}")
    fields = [_field("Protocol identifier", f"0x{protocol_id:04x}", start, 2),
              _field("Version", str(version), start + 2, 1), _field("BPDU type", kind, start + 3, 1)]
    length = 4
    if bpdu_type != 0x80 and end - start >= 35:
        # 802.1D-2004 §9.3.1: root identifier 5-12, root path cost 13-16, bridge identifier 17-24, port identifier
        # 25-26, then the four timers
        root = f"{_u16(w.frame, start + 5)}/{mac_text(w.frame[start + 7:start + 13])}"
        bridge = f"{_u16(w.frame, start + 17)}/{mac_text(w.frame[start + 19:start + 25])}"
        fields += [_field("Flags", f"0x{w.frame[start + 4]:02x}", start + 4, 1),
                   _field("Root bridge", root, start + 5, 8),
                   _field("Root path cost", str(_u32(w.frame, start + 13)), start + 13, 4),
                   _field("Bridge", bridge, start + 17, 8),
                   _field("Port", f"0x{_u16(w.frame, start + 25):04x}", start + 25, 2)]
        length = 35
        w.add("STP", f"Spanning tree, {kind} BPDU, root {root}", start, length, fields)
        w.say(f"{kind} BPDU, root {root}, cost {_u32(w.frame, start + 13)}")
    else:
        w.add("STP", f"Spanning tree, {kind} BPDU", start, min(length, end - start), fields)
        w.say(f"{kind} BPDU")
    w.data(start + length, end)


def _lldp_layer(w: _Walk, start: int, end: int) -> None:
    neighbour = lldp.parse_lldp(w.frame[start:min(end, w.size)])
    _neighbour_layer(w, "LLDP", "LLDP", neighbour, start, end)


def _cdp_layer(w: _Walk, start: int, end: int) -> None:
    neighbour = lldp.parse_cdp(w.frame[start:min(end, w.size)])
    _neighbour_layer(w, "CDP", "CDP", neighbour, start, end)


def _neighbour_layer(w: _Walk, name: str, label: str, neighbour: Optional[Dict[str, Any]], start: int,
                     end: int) -> None:
    """One LLDP or CDP layer from a :mod:`tnt.lldp` NEIGHBOR dict (which carries no offsets: every field is length 0)."""
    length = max(0, min(end, w.size) - start)
    if neighbour is None:
        w.add(name, f"{label}: no usable advertisement", start, length, [])
        w.say(f"{label} advertisement")
        return
    fields = []
    for key, title in (("chassis_id", "Chassis ID"), ("port_id", "Port ID"), ("switch_name", "System name"),
                       ("switch_description", "System description"), ("port_description", "Port description"),
                       ("vlan", "VLAN"), ("voice_vlan", "Voice VLAN"), ("ttl_s", "Time to live")):
        value = neighbour.get(key)
        if value is not None:
            fields.append(_field(title, _clean(str(value), MAX_FIELD_TEXT), start, 0))
    for ip in neighbour.get("management_ips") or []:
        fields.append(_field("Management address", str(ip), start, 0))
    who = neighbour.get("switch_name") or neighbour.get("chassis_id")
    port = neighbour.get("port_id")
    if who and port:
        summary = f"{who}, port {port}"
    else:
        summary = str(who or port or f"{label} advertisement")
    w.add(name, f"{label}: {summary}", start, length, fields)
    w.say(summary)


def _eapol(w: _Walk, start: int, end: int) -> None:
    if end - start < 4:
        w.truncated("EAPOL", "EAPOL", start)
        return
    version, kind, body = w.frame[start], w.frame[start + 1], _u16(w.frame, start + 2)
    text = _EAPOL_TYPE_TEXT.get(kind, f"type {kind}")
    fields = [_field("Version", str(version), start, 1), _field("Type", text, start + 1, 1),
              _field("Body length", str(body), start + 2, 2)]
    if kind == 0 and end - start >= 5:
        code = w.frame[start + 4]
        text = f"EAP {_EAP_CODE_TEXT.get(code, f'code {code}')}"
        fields.append(_field("EAP code", text, start + 4, 1))
    w.add("EAPOL", f"EAPOL, {text}", start, min(4, end - start), fields)
    w.say(f"EAPOL {text}")
    w.data(start + 4, end)


def _pppoe(w: _Walk, start: int, end: int, session: bool) -> None:
    if end - start < 6:
        w.truncated("PPPoE", "PPPoE", start)
        return
    version_type, code, session_id, length = w.frame[start], w.frame[start + 1], _u16(w.frame, start + 2), \
        _u16(w.frame, start + 4)
    text = _PPPOE_CODE_TEXT.get(code, f"code 0x{code:02x}")
    fields = [_field("Version", str(version_type >> 4), start, 1), _field("Type", str(version_type & 0x0F), start, 1),
              _field("Code", text, start + 1, 1), _field("Session ID", f"0x{session_id:04x}", start + 2, 2),
              _field("Payload length", str(length), start + 4, 2)]
    payload = start + 6
    body_end = min(end, payload + length) if length else end
    protocol = None
    if session and code == 0x00 and body_end - payload >= 2:
        protocol = _u16(w.frame, payload)
        fields.append(_field("PPP protocol", _PPP_PROTOCOL_TEXT.get(protocol, f"0x{protocol:04x}"), payload, 2))
    w.add("PPPoE", f"PPPoE {'session' if session else 'discovery'}, {text}, session 0x{session_id:04x}", start, 6,
          fields)
    w.say(f"PPPoE {text}, session 0x{session_id:04x}")
    if protocol == 0x0021:
        _ipv4(w, payload + 2, body_end)
    elif protocol == 0x0057:
        _ipv6(w, payload + 2, body_end)
    else:
        w.data(payload + (2 if protocol is not None else 0), body_end)


def _ipx(w: _Walk, start: int, end: int) -> None:
    length = max(0, min(end, w.size) - start)
    w.add("IPX", f"IPX, {length} bytes", start, length, [])
    w.say(f"IPX, {length} bytes")


def _wol(w: _Walk, start: int, end: int, name: str) -> bool:
    """A Wake-on-LAN magic packet: six 0xFF bytes and the target MAC over and over. False when it is not one."""
    stop = min(end, w.size)
    if stop - start < 6 + 6 * _WOL_REPEATS or w.frame[start:start + 6] != _WOL_PREFIX:
        return False
    target = w.frame[start + 6:start + 12]
    if target == bytes(6):                                         # padding, not a target
        return False
    for index in range(1, _WOL_REPEATS):
        at = start + 6 + index * 6
        if w.frame[at:at + 6] != target:
            return False
    text = mac_text(target)
    w.add(name, f"Wake-on-LAN, magic packet for {text}", start, min(6 + 16 * 6, stop - start),
          [_field("Synchronisation", "ff:ff:ff:ff:ff:ff", start, 6), _field("Target", text, start + 6, 6)])
    w.say(f"Magic packet for {text}")
    return True


# --------------------------------------------------------------------------- network layer
def _arp(w: _Walk, start: int, end: int) -> None:
    if end - start < 8:
        w.truncated("ARP", "ARP", start)
        return
    hardware, protocol, hlen, plen, opcode = struct.unpack_from(">HHBBH", w.frame, start)
    need = 8 + 2 * hlen + 2 * plen
    if end - start < need:
        w.truncated("ARP", "ARP", start)
        return
    sha = w.frame[start + 8:start + 8 + hlen]
    spa = w.frame[start + 8 + hlen:start + 8 + hlen + plen]
    tha = w.frame[start + 8 + hlen + plen:start + 8 + 2 * hlen + plen]
    tpa = w.frame[start + 8 + 2 * hlen + plen:start + need]
    ethernet_ip = hardware == 1 and protocol == _ETHERTYPE_IPV4 and hlen == 6 and plen == 4
    # hlen and plen come from the frame, so the hex of an address it claims is capped like every other field value
    sender_mac = mac_text(sha) if ethernet_ip else _clean(sha.hex(), MAX_FIELD_TEXT)
    target_mac = mac_text(tha) if ethernet_ip else _clean(tha.hex(), MAX_FIELD_TEXT)
    sender_ip = _ipv4_text(spa) if ethernet_ip else _clean(spa.hex(), MAX_FIELD_TEXT)
    target_ip = _ipv4_text(tpa) if ethernet_ip else _clean(tpa.hex(), MAX_FIELD_TEXT)
    if ethernet_ip:
        w.src, w.dst = sender_ip, target_ip
    kind = _ARP_OPCODES.get(opcode, f"opcode {opcode}")
    fields = [_field("Hardware type", str(hardware), start, 2),
              _field("Protocol type", _ethertype_text(protocol), start + 2, 2),
              _field("Hardware size", str(hlen), start + 4, 1), _field("Protocol size", str(plen), start + 5, 1),
              _field("Opcode", kind, start + 6, 2),
              _field("Sender MAC", sender_mac, start + 8, hlen),
              _field("Sender address", sender_ip, start + 8 + hlen, plen),
              _field("Target MAC", target_mac, start + 8 + hlen + plen, hlen),
              _field("Target address", target_ip, start + 8 + 2 * hlen + plen, plen)]
    w.add("ARP", f"ARP {kind}", start, need, fields)
    if not ethernet_ip:
        w.say(f"ARP {kind}")
    elif opcode == 1:
        w.say(f"Who has {target_ip}? Tell {sender_ip}")
    elif opcode == 2:
        w.say(f"{sender_ip} is at {sender_mac}")
    elif opcode == 3:
        w.say(f"Who is {target_mac}? Tell {sender_mac}")
    elif opcode == 4:
        w.say(f"{target_mac} is at {target_ip}")
    else:
        w.say(f"ARP {kind}")
    w.data(start + need, end)


def _ipv4(w: _Walk, start: int, end: int) -> None:
    if end - start < 20:
        w.truncated("IPv4", "IPv4", start)
        return
    version_ihl = w.frame[start]
    header = (version_ihl & 0x0F) * 4
    if version_ihl >> 4 != 4 or header < 20:
        w.malformed("IPv4", "IPv4", start, end)
        w.data(start, end)
        return
    if end - start < header:
        w.truncated("IPv4", "IPv4", start)
        return
    total = _u16(w.frame, start + 2)
    identification = _u16(w.frame, start + 4)
    flags_offset = _u16(w.frame, start + 6)
    offset = (flags_offset & 0x1FFF) * 8
    ttl, protocol = w.frame[start + 8], w.frame[start + 9]
    w.src, w.dst = _ipv4_text(w.frame[start + 12:start + 16]), _ipv4_text(w.frame[start + 16:start + 20])
    flags = [name for bit, name in ((0x4000, "do not fragment"), (0x2000, "more fragments")) if flags_offset & bit]
    fields = [_field("Version", "4", start, 1), _field("Header length", f"{header} bytes", start, 1),
              _field("Differentiated services", f"0x{w.frame[start + 1]:02x}", start + 1, 1),
              _field("Total length", str(total), start + 2, 2),
              _field("Identification", f"0x{identification:04x}", start + 4, 2),
              _field("Flags", ", ".join(flags) or "none", start + 6, 2),
              _field("Fragment offset", str(offset), start + 6, 2), _field("Time to live", str(ttl), start + 8, 1),
              _field("Protocol", _ip_protocol_text(protocol), start + 9, 1),
              _field("Header checksum", f"0x{_u16(w.frame, start + 10):04x}", start + 10, 2),
              _field("Source", w.src, start + 12, 4), _field("Destination", w.dst, start + 16, 4)]
    if header > 20:
        fields.append(_field("Options", f"{header - 20} bytes", start + 20, header - 20))
    w.add("IPv4", f"IPv4, {w.src} > {w.dst}", start, header, fields)
    w.say(_ip_protocol_text(protocol))
    payload = start + header
    payload_end = min(end, start + total) if header <= total <= end - start else end
    if offset:
        w.say(f"Fragmented {_ip_protocol_text(protocol)}, offset {offset}")
        w.data(payload, payload_end)
        return
    _network_payload(w, protocol, payload, payload_end, version=4)


def _ipv6(w: _Walk, start: int, end: int) -> None:
    if end - start < 40:
        w.truncated("IPv6", "IPv6", start)
        return
    first = _u32(w.frame, start)
    if first >> 28 != 6:
        w.malformed("IPv6", "IPv6", start, end)
        w.data(start, end)
        return
    payload_length, next_header, hop_limit = _u16(w.frame, start + 4), w.frame[start + 6], w.frame[start + 7]
    w.src, w.dst = _ipv6_text(w.frame[start + 8:start + 24]), _ipv6_text(w.frame[start + 24:start + 40])
    fields = [_field("Version", "6", start, 1),
              _field("Traffic class", f"0x{(first >> 20) & 0xFF:02x}", start, 2),
              _field("Flow label", f"0x{first & 0xFFFFF:05x}", start + 1, 3),
              _field("Payload length", str(payload_length), start + 4, 2),
              _field("Next header", _ip_protocol_text(next_header), start + 6, 1),
              _field("Hop limit", str(hop_limit), start + 7, 1), _field("Source", w.src, start + 8, 16),
              _field("Destination", w.dst, start + 24, 16)]
    w.add("IPv6", f"IPv6, {w.src} > {w.dst}", start, 40, fields)
    w.say(_ip_protocol_text(next_header))
    payload_end = min(end, start + 40 + payload_length) if payload_length else end
    next_header, pos, fragmented = _ipv6_extensions(w, next_header, start + 40, payload_end)
    if next_header == _IP_STOP:                    # an extension header was cut short: its layer says so already
        return
    if fragmented:
        w.say(f"Fragmented {_ip_protocol_text(next_header)}")
        w.data(pos, payload_end)
        return
    _network_payload(w, next_header, pos, payload_end, version=6)


def _ipv6_extensions(w: _Walk, next_header: int, pos: int, end: int) -> Tuple[int, int, bool]:
    """Walk at most :data:`MAX_EXTENSION_HEADERS` extension headers; ``(next header, offset, fragmented)``.

    A header cut short adds its own truncated layer and comes back as :data:`_IP_STOP`, which is not a protocol
    number, so the caller stops rather than reading the sentinel as "no next header"."""
    for _ in range(MAX_EXTENSION_HEADERS):
        label = _IPV6_EXTENSIONS.get(next_header)
        if label is None:
            break
        if end - pos < 8:
            w.truncated(label, label, pos, named=False)
            return _IP_STOP, pos, False
        following = w.frame[pos]
        fields = [_field("Next header", _ip_protocol_text(following), pos, 1)]
        if next_header == _IP_FRAGMENT:
            length = 8
            control = _u16(w.frame, pos + 2)
            offset = (control >> 3) * 8
            fields += [_field("Fragment offset", str(offset), pos + 2, 2),
                       _field("More fragments", "1" if control & 1 else "0", pos + 2, 2),
                       _field("Identification", f"0x{_u32(w.frame, pos + 4):08x}", pos + 4, 4)]
            w.add(label, f"{label}, offset {offset}", pos, length, fields, named=False)
            if offset:
                return following, pos + length, True
        else:
            length = (w.frame[pos + 1] + 2) * 4 if next_header == _IP_AH else (w.frame[pos + 1] + 1) * 8
            if end - pos < length:
                w.truncated(label, label, pos, named=False)
                return _IP_STOP, pos, False
            fields.append(_field("Length", f"{length} bytes", pos + 1, 1))
            w.add(label, f"{label}, {length} bytes", pos, length, fields, named=False)
        next_header, pos = following, pos + length
    return next_header, pos, False


def _network_payload(w: _Walk, protocol: int, start: int, end: int, *, version: int) -> None:
    if protocol == _IP_TCP:
        _tcp(w, start, end)
    elif protocol == _IP_UDP:
        _udp(w, start, end)
    elif protocol == _IP_ICMP:
        _icmp(w, start, end)
    elif protocol == _IP_ICMPV6:
        _icmpv6(w, start, end)
    elif protocol == _IP_IGMP:
        _igmp(w, start, end)
    elif protocol == _IP_IPV4:
        _ipv4(w, start, end)
    elif protocol == _IP_IPV6:
        _ipv6(w, start, end)
    else:
        if version == 6 and protocol == _IP_NONE:
            w.say("No next header")
        w.data(start, end)


# --------------------------------------------------------------------------- transport layer
def _icmp(w: _Walk, start: int, end: int) -> None:
    if end - start < 4:
        w.truncated("ICMP", "ICMP", start)
        return
    kind, code = w.frame[start], w.frame[start + 1]
    text = _ICMP_TYPE_TEXT.get(kind, f"Type {kind}")
    fields = [_field("Type", f"{text} ({kind})", start, 1), _field("Code", str(code), start + 1, 1),
              _field("Checksum", f"0x{_u16(w.frame, start + 2):04x}", start + 2, 2)]
    length = 4
    info = text
    if kind in _ICMP_ECHO_TYPES and end - start >= 8:
        identifier, sequence = _u16(w.frame, start + 4), _u16(w.frame, start + 6)
        fields += [_field("Identifier", f"0x{identifier:04x}", start + 4, 2),
                   _field("Sequence number", str(sequence), start + 6, 2)]
        length = 8
        info = f"{text} id=0x{identifier:04x} seq={sequence}"
    elif kind == 3:
        info = f"{text} ({_ICMP_UNREACHABLE.get(code, f'code {code}')})"
    elif kind == 11:
        info = f"{text} ({_ICMP_EXCEEDED.get(code, f'code {code}')})"
    elif kind == 5:
        info = _ICMP_REDIRECT.get(code, f"{text} code {code}")
    w.add("ICMP", f"ICMP, {text}", start, length, fields)
    w.say(info)
    w.data(start + length, end)


def _icmpv6(w: _Walk, start: int, end: int) -> None:
    if end - start < 4:
        w.truncated("ICMPv6", "ICMPv6", start)
        return
    kind, code = w.frame[start], w.frame[start + 1]
    text = _ICMPV6_TYPE_TEXT.get(kind, f"Type {kind}")
    fields = [_field("Type", f"{text} ({kind})", start, 1), _field("Code", str(code), start + 1, 1),
              _field("Checksum", f"0x{_u16(w.frame, start + 2):04x}", start + 2, 2)]
    length = 4
    info = text
    if kind in _ICMPV6_ECHO_TYPES and end - start >= 8:
        identifier, sequence = _u16(w.frame, start + 4), _u16(w.frame, start + 6)
        fields += [_field("Identifier", f"0x{identifier:04x}", start + 4, 2),
                   _field("Sequence number", str(sequence), start + 6, 2)]
        length = 8
        info = f"{text} id=0x{identifier:04x} seq={sequence}"
    elif kind in _ICMPV6_TARGET_TYPES and end - start >= 24:
        target = _ipv6_text(w.frame[start + 8:start + 24])
        fields.append(_field("Target address", target, start + 8, 16))
        length = 24
        info = f"{text} for {target}"
    elif kind == 1:
        info = f"{text} ({_ICMPV6_UNREACHABLE.get(code, f'code {code}')})"
    w.add("ICMPv6", f"ICMPv6, {text}", start, length, fields)
    w.say(info)
    w.data(start + length, end)


def _igmp(w: _Walk, start: int, end: int) -> None:
    if end - start < 8:
        w.truncated("IGMP", "IGMP", start)
        return
    kind = w.frame[start]
    text = _IGMP_TYPE_TEXT.get(kind, f"Type 0x{kind:02x}")
    fields = [_field("Type", f"{text} (0x{kind:02x})", start, 1)]
    if kind == _IGMP_REPORT_V3:
        # RFC 3376 §4.2: reserved, checksum, reserved, the number of group records, then the records themselves;
        # there is no group address in the header and byte 1 is not a max response time
        records = _u16(w.frame, start + 6)
        fields += [_field("Checksum", f"0x{_u16(w.frame, start + 2):04x}", start + 2, 2),
                   _field("Group records", str(records), start + 6, 2)]
        length = 8
        group = ""
        if records and end - start >= _IGMP_RECORD_FIXED + 8:
            # the first group record: record type, auxiliary data length, source count, then the multicast address
            group = _ipv4_text(w.frame[start + 12:start + 16])
            fields.append(_field("Multicast address", group, start + 12, 4))
            length = 8 + _IGMP_RECORD_FIXED
        counted = f"{records} group record" + ("" if records == 1 else "s")
        info = f"{text} for {group}" if group and records == 1 else f"{text}, {counted}"
    else:
        length = 8
        group = _ipv4_text(w.frame[start + 4:start + 8])
        fields += [_field("Max response time", str(w.frame[start + 1]), start + 1, 1),
                   _field("Checksum", f"0x{_u16(w.frame, start + 2):04x}", start + 2, 2),
                   _field("Group address", group, start + 4, 4)]
        info = f"{text} for {group}" if group and group != "0.0.0.0" else text
    w.add("IGMP", f"IGMP, {text}", start, length, fields)
    w.say(info)
    w.data(start + length, end)


def _tcp_options(data: bytes, start: int) -> List[Dict[str, Any]]:
    """The TCP option list as fields; the walk stops at the end of the list, at a bad length or after 40 bytes."""
    fields: List[Dict[str, Any]] = []
    pos = 0
    limit = min(len(data), MAX_TCP_OPTION_BYTES)
    while pos < limit:
        kind = data[pos]
        if kind == 0:
            fields.append(_field("Option", "End of option list", start + pos, 1))
            break
        if kind == 1:
            fields.append(_field("Option", "No operation", start + pos, 1))
            pos += 1
            continue
        if pos + 2 > limit:
            break
        size = data[pos + 1]
        if size < 2 or pos + size > limit:
            break
        body = data[pos + 2:pos + size]
        if kind == 2 and size == 4:
            text = f"Maximum segment size: {int.from_bytes(body, 'big')}"
        elif kind == 3 and size == 3:
            text = f"Window scale: {body[0]}"
        elif kind == 4 and size == 2:
            text = "SACK permitted"
        elif kind == 5:
            text = f"SACK, {size - 2} bytes"
        elif kind == 8 and size == 10:
            text = f"Timestamps: value {int.from_bytes(body[:4], 'big')}, echo {int.from_bytes(body[4:], 'big')}"
        else:
            text = f"Option {kind}, {size} bytes"
        fields.append(_field("Option", text, start + pos, size))
        pos += size
    return fields


def _tcp(w: _Walk, start: int, end: int) -> None:
    if end - start < 20:
        w.truncated("TCP", "TCP", start)
        return
    sport, dport, sequence, acknowledgement = struct.unpack_from(">HHII", w.frame, start)
    offset_flags = _u16(w.frame, start + 12)
    header = (offset_flags >> 12) * 4
    flags = offset_flags & 0x01FF
    window = _u16(w.frame, start + 14)
    if header < 20:
        w.malformed("TCP", "TCP", start, end)
        w.data(start, end)
        return
    if end - start < header:
        w.truncated("TCP", "TCP", start)
        return
    w.sport, w.dport = sport, dport
    named = [name for bit, name in _TCP_FLAG_BITS if flags & bit]
    ordered = [name for name in _TCP_FLAG_ORDER if name in named]
    payload, payload_end = start + header, end
    length = max(0, payload_end - payload)
    fields = [_field("Source port", str(sport), start, 2), _field("Destination port", str(dport), start + 2, 2),
              _field("Sequence number", str(sequence), start + 4, 4),
              _field("Acknowledgement number", str(acknowledgement), start + 8, 4),
              _field("Header length", f"{header} bytes", start + 12, 1),
              _field("Flags", ", ".join(ordered) or "none", start + 12, 2),
              _field("Window", str(window), start + 14, 2),
              _field("Checksum", f"0x{_u16(w.frame, start + 16):04x}", start + 16, 2),
              _field("Urgent pointer", str(_u16(w.frame, start + 18)), start + 18, 2),
              _field("Payload length", f"{length} bytes", payload, length)]
    fields += _tcp_options(w.frame[start + 20:start + header], start + 20)
    w.add("TCP", f"TCP, {sport} > {dport}, {', '.join(ordered) or 'no flags'}, length {length}", start, header, fields)
    acked = f" Ack={acknowledgement}" if "ACK" in ordered else ""
    w.say(f"{sport} > {dport} [{', '.join(ordered)}] Seq={sequence}{acked} Win={window} Len={length}")
    if length > 0:
        _application(w, payload, payload_end, "tcp", sport, dport)


def _udp(w: _Walk, start: int, end: int) -> None:
    if end - start < 8:
        w.truncated("UDP", "UDP", start)
        return
    sport, dport, length, checksum = struct.unpack_from(">HHHH", w.frame, start)
    w.sport, w.dport = sport, dport
    payload = start + 8
    payload_end = min(end, start + length) if 8 <= length <= end - start else end
    size = max(0, payload_end - payload)
    fields = [_field("Source port", str(sport), start, 2), _field("Destination port", str(dport), start + 2, 2),
              _field("Length", str(length), start + 4, 2), _field("Checksum", f"0x{checksum:04x}", start + 6, 2),
              _field("Payload length", f"{size} bytes", payload, size)]
    w.add("UDP", f"UDP, {sport} > {dport}, length {size}", start, 8, fields)
    w.say(f"{sport} > {dport} Len={size}")
    if size > 0:
        _application(w, payload, payload_end, "udp", sport, dport)
    else:
        w.data(payload, payload_end)


# --------------------------------------------------------------------------- application layer
def _application(w: _Walk, start: int, end: int, transport: str, sport: int, dport: int) -> None:
    """Name the payload from the port table, else from its own bytes; anything unrecognised stays a Data layer."""
    table = PORTS[transport]
    w.payload = w.frame[max(0, start):max(0, min(end, w.size))]
    name = table.get(dport) or table.get(sport) or _sniff(w.payload, transport, sport, dport)
    handler = _APP_HANDLERS.get(name) if name else None
    if handler is None or not handler(w, start, end, name):
        w.data(start, end)


def _sniff(payload: bytes, transport: str, sport: int, dport: int) -> Optional[str]:
    name, _line = _line_protocol(payload)
    if name is not None:
        return name
    if transport == "tcp":
        return "TLS" if _looks_like_tls(payload) else None
    return _sniff_rtp(payload, sport, dport)


def _looks_like_tls(payload: bytes) -> bool:
    if len(payload) < 5 or payload[0] not in _TLS_CONTENT_TEXT or payload[1] != 3 or payload[2] > 4:
        return False
    return 0 < _u16(payload, 3) <= 0x4100


def _sniff_rtp(payload: bytes, sport: int, dport: int) -> Optional[str]:
    """RFC 3550 has no magic number: version 2 with a sane payload type on a high port is as close as it gets."""
    if len(payload) < _RTCP_MINIMUM or payload[0] >> 6 != _RTP_VERSION:
        return None
    if payload[1] in _RTCP_TYPES:      # an RTCP packet type fills the octet; a receiver report with no blocks is 8
        return "RTCP"
    if len(payload) < _RTP_HEADER:
        return None
    if min(sport, dport) < 1024 or (sport % 2 and dport % 2):      # RTP rides the even port of its pair
        return None
    kind = payload[1] & 0x7F
    if kind <= 34 or kind in _RTP_DYNAMIC:
        return "RTP"
    return None


def _dns(w: _Walk, start: int, end: int, name: str) -> bool:
    if end - start < 12:
        w.truncated(name, name, start)
        return True
    identifier, flags = _u16(w.frame, start), _u16(w.frame, start + 2)
    counts = [_u16(w.frame, start + 4 + 2 * n) for n in range(4)]
    response = bool(flags & 0x8000)
    opcode, rcode = (flags >> 11) & 0x0F, flags & 0x0F
    kind = _DNS_OPCODES.get(opcode, f"Opcode {opcode}")
    fields = [_field("Transaction ID", f"0x{identifier:04x}", start, 2),
              _field("Type", "response" if response else "query", start + 2, 2),
              _field("Opcode", kind, start + 2, 2),
              _field("Flags", f"0x{flags:04x}", start + 2, 2),
              _field("Questions", str(counts[0]), start + 4, 2),
              _field("Answer records", str(counts[1]), start + 6, 2),
              _field("Authority records", str(counts[2]), start + 8, 2),
              _field("Additional records", str(counts[3]), start + 10, 2)]
    if response:
        fields.append(_field("Reply code", _DNS_RCODES.get(rcode, f"code {rcode}") or "no error", start + 2, 2))
    question = ""
    if counts[0] and name != "NBNS":
        label, after = _dns_name(w.frame, start, start + 12, min(end, w.size))
        if label is not None and after + 4 <= min(end, w.size):
            qtype, qclass = _u16(w.frame, after), _u16(w.frame, after + 2)
            type_text = _DNS_TYPES.get(qtype, f"type {qtype}")
            question = f"{type_text} {label}"
            fields += [_field("Question name", label, start + 12, max(0, after - start - 12)),
                       _field("Question type", type_text, after, 2),
                       _field("Question class", f"0x{qclass:04x}", after + 2, 2)]
    parts = [kind + (" response" if response else "")]
    if response and rcode:
        parts.append(_DNS_RCODES.get(rcode, f"reply code {rcode}"))
    parts.append(f"0x{identifier:04x}")
    if question:
        parts.append(question)
    info = " ".join(parts)
    if name == "NBNS":
        info = f"NetBIOS name {'response' if response else 'query'} 0x{identifier:04x}"
    w.add(name, f"{name}: {info}", start, max(0, min(end, w.size) - start), fields)
    w.say(info)
    return True


def _dns_name(data: bytes, message: int, pos: int, end: int) -> Tuple[Optional[str], int]:
    """``(name, offset after it)`` from *pos*, or ``(None, pos)``: labels and length are capped and a compression
    pointer must point strictly backwards, before itself and before the pointer before it (RFC 1035 §4.1.4)."""
    labels: List[str] = []
    after: Optional[int] = None
    bound = end
    hops = total = 0
    while pos < end and len(labels) < MAX_DNS_LABELS:
        size = data[pos]
        if size & 0xC0 == 0xC0:
            if pos + 2 > end:
                return None, pos
            target = message + (((size & 0x3F) << 8) | data[pos + 1])
            if after is None:
                after = pos + 2
            hops += 1
            bound = min(bound, pos)                  # a prior occurrence of the name: never itself, never forward
            if target >= bound or target < message or hops > MAX_DNS_POINTERS:
                return None, pos
            bound, pos = target, target
            continue
        if size & 0xC0:
            return None, pos
        pos += 1
        if size == 0:
            name = ".".join(labels) if labels else "<root>"
            return name, after if after is not None else pos
        if pos + size > end:
            return None, pos
        total += size + 1
        if total > MAX_DNS_NAME:
            return None, pos
        labels.append(_text_of(data[pos:pos + size], 63))
        pos += size
    return None, pos


def _dhcp(w: _Walk, start: int, end: int, name: str) -> bool:
    if end - start < 44:
        w.truncated(name, name, start)
        return True
    op, htype, hlen = w.frame[start], w.frame[start + 1], w.frame[start + 2]
    xid = _u32(w.frame, start + 4)
    client = mac_text(w.frame[start + 28:start + 34]) if hlen == 6 else w.frame[start + 28:start + 28 + hlen].hex()
    fields = [_field("Message op code", "request" if op == 1 else "reply" if op == 2 else str(op), start, 1),
              _field("Hardware type", str(htype), start + 1, 1),
              _field("Transaction ID", f"0x{xid:08x}", start + 4, 4),
              _field("Seconds elapsed", str(_u16(w.frame, start + 8)), start + 8, 2),
              _field("Client address", _ipv4_text(w.frame[start + 12:start + 16]), start + 12, 4),
              _field("Your address", _ipv4_text(w.frame[start + 16:start + 20]), start + 16, 4),
              _field("Server address", _ipv4_text(w.frame[start + 20:start + 24]), start + 20, 4),
              _field("Relay address", _ipv4_text(w.frame[start + 24:start + 28]), start + 24, 4),
              _field("Client MAC", client, start + 28, max(1, hlen))]
    message = None
    stop = min(end, w.size)
    if stop - start >= _DHCP_FIXED and w.frame[start + 236:start + 240] == _DHCP_MAGIC:
        message = _dhcp_message_type(w.frame, start + _DHCP_FIXED, stop, fields)
    text = _DHCP_MESSAGE_TEXT.get(message, f"message type {message}") if message is not None else \
        ("BOOTP request" if op == 1 else "BOOTP reply")
    info = f"{text}, transaction 0x{xid:08x}"
    w.add(name, f"{name}: {info}", start, stop - start, fields)
    w.say(info)
    return True


def _dhcp_message_type(data: bytes, pos: int, end: int, fields: List[Dict[str, Any]]) -> Optional[int]:
    """Option 53 from a DHCP option list (at most :data:`MAX_DHCP_OPTIONS` options); None when it is not there."""
    message = None
    for _ in range(MAX_DHCP_OPTIONS):
        if pos >= end:
            break
        code = data[pos]
        if code == 255:
            break
        if code == 0:
            pos += 1
            continue
        if pos + 2 > end:
            break
        size = data[pos + 1]
        if pos + 2 + size > end:
            break
        if code == 53 and size >= 1 and message is None:
            message = data[pos + 2]
            text = _DHCP_MESSAGE_TEXT.get(message, f"type {message}")
            fields.append(_field("Message type", f"{text} ({message})", pos + 2, 1))
        pos += 2 + size
    return message


def _dhcpv6(w: _Walk, start: int, end: int, name: str) -> bool:
    if end - start < 4:
        w.truncated(name, name, start)
        return True
    kind = w.frame[start]
    text = _DHCPV6_MESSAGE_TEXT.get(kind, f"message type {kind}")
    transaction = int.from_bytes(w.frame[start + 1:start + 4], "big")
    fields = [_field("Message type", f"{text} ({kind})", start, 1),
              _field("Transaction ID", f"0x{transaction:06x}", start + 1, 3)]
    info = f"{text}, transaction 0x{transaction:06x}"
    w.add(name, f"{name}: {info}", start, max(0, min(end, w.size) - start), fields)
    w.say(info)
    return True


def _http(w: _Walk, start: int, end: int, name: str) -> bool:
    """HTTP, SSDP and RTSP: the first line only, never a reassembled message."""
    payload = w.frame[start:min(end, w.size)]
    found, raw = _line_protocol(payload)
    if raw == b"" or (found is None and name != "SSDP"):
        return False
    line = _text_of(raw, MAX_INFO)
    parts = raw.split(b" ")
    fields: List[Dict[str, Any]] = []
    if any(raw.startswith(token + b" ") for token, _name in _VERSION_PROTOCOLS) and len(parts) >= 2:
        # every offset is the field's own bytes: the version opens the line, the code follows the space after it
        fields = [_field("Version", _text_of(parts[0], 16), start, len(parts[0])),
                  _field("Status code", _text_of(parts[1], 8), start + len(parts[0]) + 1, len(parts[1]))]
        if len(parts) > 2:
            fields.append(_field("Reason", _text_of(b" ".join(parts[2:]), MAX_FIELD_TEXT), start, 0))
    elif len(parts) >= 3:
        uri = b" ".join(parts[1:-1])
        fields = [_field("Method", _text_of(parts[0], 24), start, len(parts[0])),
                  _field("Request URI", _text_of(uri, MAX_FIELD_TEXT), start + len(parts[0]) + 1, len(uri)),
                  _field("Version", _text_of(parts[-1], 16), start + len(raw) - len(parts[-1]), len(parts[-1]))]
    else:
        return False
    fields.append(_field("First line", line, start, len(raw)))
    w.add(name, f"{name}: {line}", start, max(0, min(end, w.size) - start), fields)
    w.say(line)
    return True


def _sip(w: _Walk, start: int, end: int, name: str) -> bool:
    """SIP is named and its first line read here; call reconstruction lives in :mod:`tnt.sipcalls`."""
    payload = w.frame[start:min(end, w.size)]
    raw = _first_line(payload)
    parts = raw.split(b" ")
    fields: List[Dict[str, Any]] = []
    if raw.startswith(b"SIP/2.0 ") and len(parts) >= 2:
        code, reason = _text_of(parts[1], 8), _text_of(b" ".join(parts[2:]), MAX_FIELD_TEXT)
        info = f"{code} {reason}".strip()
        fields = [_field("Version", "SIP/2.0", start, 7), _field("Status code", code, start + 8, len(parts[1])),
                  _field("Reason", reason, start, 0)]
    elif len(parts) >= 3 and parts[-1] == b"SIP/2.0" and _text_of(parts[0], 24) in _SIP_METHODS:
        method, uri = _text_of(parts[0], 24), _text_of(b" ".join(parts[1:-1]), MAX_FIELD_TEXT)
        info = f"{method} {uri}".strip()
        fields = [_field("Method", method, start, len(parts[0])),
                  _field("Request URI", uri, start + len(parts[0]) + 1, max(0, len(raw) - len(parts[0]) - 9)),
                  _field("Version", "SIP/2.0", start + max(0, len(raw) - 7), 7)]
    else:
        return False
    w.add(name, f"SIP: {info}", start, max(0, min(end, w.size) - start), fields)
    w.say(info)
    return True


def _tls(w: _Walk, start: int, end: int, name: str) -> bool:
    stop = min(end, w.size)
    if stop - start < 5:
        return False
    content, version, length = w.frame[start], _u16(w.frame, start + 1), _u16(w.frame, start + 3)
    if content not in _TLS_CONTENT_TEXT or version >> 8 != 3:
        return False
    text = _TLS_CONTENT_TEXT[content]
    version_text = _TLS_VERSION_TEXT.get(version, f"0x{version:04x}")
    fields = [_field("Content type", f"{text} ({content})", start, 1),
              _field("Version", version_text, start + 1, 2), _field("Length", str(length), start + 3, 2)]
    info = text
    record_end = min(stop, start + 5 + length)
    if content == 22 and record_end - start >= 9:
        handshake = w.frame[start + 5]
        handshake_text = _TLS_HANDSHAKE_TEXT.get(handshake, f"Handshake type {handshake}")
        fields.append(_field("Handshake type", f"{handshake_text} ({handshake})", start + 5, 1))
        info = handshake_text
        if handshake == 1:
            server_name = _tls_server_name(w.frame, start + 9, record_end)
            if server_name:
                fields.append(_field("Server name", server_name, start + 9, 0))
                info = f"{handshake_text} (SNI={server_name})"
    w.add(name, f"TLS: {info}", start, max(0, stop - start), fields)
    w.say(info)
    return True


def _tls_server_name(data: bytes, pos: int, end: int) -> str:
    """The SNI host of a ClientHello body (from ``legacy_version``), or "" when it is not there."""
    pos += 34                                                    # legacy version and the 32-byte random
    if pos >= end:
        return ""
    pos += 1 + data[pos]                                         # legacy session id
    if pos + 2 > end:
        return ""
    pos += 2 + _u16(data, pos)                                   # cipher suites
    if pos + 1 > end:
        return ""
    pos += 1 + data[pos]                                         # compression methods
    if pos + 2 > end:
        return ""
    extensions_end = min(end, pos + 2 + _u16(data, pos))
    pos += 2
    for _ in range(MAX_TLS_EXTENSIONS):
        if pos + 4 > extensions_end:
            return ""
        kind, size = _u16(data, pos), _u16(data, pos + 2)
        if pos + 4 + size > extensions_end:
            return ""
        if kind == _TLS_SERVER_NAME and size >= 5 and data[pos + 6] == 0:
            name_length = _u16(data, pos + 7)
            if pos + 9 + name_length <= extensions_end:
                return _text_of(data[pos + 9:pos + 9 + name_length], MAX_FIELD_TEXT)
            return ""
        pos += 4 + size
    return ""


def _rtp(w: _Walk, start: int, end: int, name: str) -> bool:
    stop = min(end, w.size)
    if stop - start < _RTP_HEADER or w.frame[start] >> 6 != _RTP_VERSION:
        return False
    marker, kind = w.frame[start + 1] >> 7, w.frame[start + 1] & 0x7F
    sequence, timestamp, ssrc = _u16(w.frame, start + 2), _u32(w.frame, start + 4), _u32(w.frame, start + 8)
    payload_text = _RTP_PAYLOAD_TEXT.get(kind, "dynamic" if kind in _RTP_DYNAMIC else f"type {kind}")
    fields = [_field("Version", "2", start, 1), _field("Padding", str((w.frame[start] >> 5) & 1), start, 1),
              _field("Contributing sources", str(w.frame[start] & 0x0F), start, 1),
              _field("Marker", str(marker), start + 1, 1),
              _field("Payload type", f"{payload_text} ({kind})", start + 1, 1),
              _field("Sequence number", str(sequence), start + 2, 2),
              _field("Timestamp", str(timestamp), start + 4, 4),
              _field("Synchronisation source", f"0x{ssrc:08x}", start + 8, 4)]
    info = f"PT={payload_text} SSRC=0x{ssrc:08x} Seq={sequence} Time={timestamp}"
    w.add(name, f"RTP: {info}", start, _RTP_HEADER, fields)
    w.say(info)
    w.data(start + _RTP_HEADER, end)
    return True


def _rtcp(w: _Walk, start: int, end: int, name: str) -> bool:
    stop = min(end, w.size)
    if stop - start < 4 or w.frame[start] >> 6 != _RTP_VERSION:
        return False
    kind, length = w.frame[start + 1], _u16(w.frame, start + 2)
    text = _RTCP_PACKET_TEXT.get(kind, f"packet type {kind}")
    fields = [_field("Version", "2", start, 1), _field("Reception reports", str(w.frame[start] & 0x1F), start, 1),
              _field("Packet type", f"{text} ({kind})", start + 1, 1),
              _field("Length", f"{(length + 1) * 4} bytes", start + 2, 2)]
    if stop - start >= 8:
        fields.append(_field("Synchronisation source", f"0x{_u32(w.frame, start + 4):08x}", start + 4, 4))
    w.add(name, f"RTCP: {text}", start, max(0, stop - start), fields)
    w.say(text)
    return True


def _ntp(w: _Walk, start: int, end: int, name: str) -> bool:
    stop = min(end, w.size)
    if stop - start < 4:
        return False
    first = w.frame[start]
    version, mode = (first >> 3) & 0x07, first & 0x07
    mode_text = _NTP_MODE_TEXT.get(mode, f"mode {mode}")
    fields = [_field("Leap indicator", str(first >> 6), start, 1), _field("Version", str(version), start, 1),
              _field("Mode", f"{mode_text} ({mode})", start, 1),
              _field("Stratum", str(w.frame[start + 1]), start + 1, 1),
              _field("Poll interval", str(w.frame[start + 2]), start + 2, 1),
              _field("Precision", str(w.frame[start + 3] - 256 if w.frame[start + 3] > 127 else w.frame[start + 3]),
                     start + 3, 1)]
    info = f"NTP version {version}, {mode_text}"
    w.add(name, f"NTP: {info}", start, max(0, stop - start), fields)
    w.say(info)
    return True


def _snmp(w: _Walk, start: int, end: int, name: str) -> bool:
    """The BER wrapper only: the version and the length of the community string, never the community itself."""
    stop = min(end, w.size)
    if stop - start < 8 or w.frame[start] != 0x30:
        return False
    pos = start + 1
    size = w.frame[pos]
    pos += 1 + (size & 0x7F if size & 0x80 else 0)
    if pos + 3 > stop or w.frame[pos] != 0x02 or w.frame[pos + 1] != 1:
        return False
    version = w.frame[pos + 2]
    version_text = {0: "v1", 1: "v2c", 3: "v3"}.get(version, f"version {version}")
    fields = [_field("Version", f"{version_text} ({version})", pos + 2, 1)]
    pos += 3
    community = None
    if pos + 2 <= stop and w.frame[pos] == 0x04:
        community = w.frame[pos + 1] & 0x7F if not w.frame[pos + 1] & 0x80 else None
        if community is not None:
            fields.append(_field("Community length", f"{community} bytes", pos + 1, 1))
    info = f"SNMP {version_text}" + (f", community {community} bytes" if community is not None else "")
    w.add(name, f"SNMP: {info}", start, max(0, stop - start), fields)
    w.say(info)
    return True


def _tftp(w: _Walk, start: int, end: int, name: str) -> bool:
    stop = min(end, w.size)
    if stop - start < 4:
        return False
    opcode = _u16(w.frame, start)
    text = _TFTP_OPCODE_TEXT.get(opcode)
    if text is None:
        return False
    fields = [_field("Opcode", f"{text} ({opcode})", start, 2)]
    info = text
    if opcode in (3, 4):
        block = _u16(w.frame, start + 2)
        fields.append(_field("Block number", str(block), start + 2, 2))
        info = f"{text}, block {block}"
    w.add(name, f"TFTP: {info}", start, max(0, stop - start), fields)
    w.say(info)
    return True


def _smb(w: _Walk, start: int, end: int, name: str) -> bool:
    stop = min(end, w.size)
    pos = start
    if stop - pos >= 8 and w.frame[pos] == 0x00:
        pos += 4                                          # NetBIOS session service header
    if stop - pos < 8:
        return False
    magic = w.frame[pos:pos + 4]
    if magic == b"\xfeSMB":
        # the SMB2 header is little-endian: command sits 12 bytes in, after the structure size, credits and status
        command = struct.unpack_from("<H", w.frame, pos + 12)[0] if stop - pos >= 14 else None
        text = _SMB2_COMMAND_TEXT.get(command, f"command {command}") if command is not None else "header"
        fields = [_field("Protocol", "SMB2", pos, 4), _field("Command", text, pos + 12, 2)]
        info = f"SMB2 {text}"
    elif magic == b"\xffSMB":
        command = w.frame[pos + 4]
        fields = [_field("Protocol", "SMB1", pos, 4), _field("Command", f"0x{command:02x}", pos + 4, 1)]
        info = f"SMB1 command 0x{command:02x}"
    else:
        return False
    w.add(name, f"SMB: {info}", start, max(0, stop - start), fields)
    w.say(info)
    return True


def _quic(w: _Walk, start: int, end: int, name: str) -> bool:
    stop = min(end, w.size)
    if stop - start < 1:
        return False
    first = w.frame[start]
    if not first & 0x80:
        w.add(name, "QUIC: short header, protected payload", start, max(0, stop - start),
              [_field("Header form", "short", start, 1)])
        w.say("Protected payload")
        return True
    if stop - start < 5:
        return False
    version = _u32(w.frame, start + 1)
    kind = _QUIC_LONG_TYPE_TEXT.get((first >> 4) & 0x03, "long header")
    text = "Version negotiation" if version == 0 else kind
    fields = [_field("Header form", "long", start, 1), _field("Packet type", text, start, 1),
              _field("Version", f"0x{version:08x}", start + 1, 4)]
    info = f"{text}, version 0x{version:08x}"
    w.add(name, f"QUIC: {info}", start, max(0, stop - start), fields)
    w.say(info)
    return True


def _syslog(w: _Walk, start: int, end: int, name: str) -> bool:
    stop = min(end, w.size)
    if stop - start < 3 or w.frame[start] != 0x3C:                 # "<"
        return False
    digits = ""
    for offset in range(start + 1, min(start + 5, stop)):
        byte = w.frame[offset]
        if byte == 0x3E:                                           # ">"
            break
        if not 0x30 <= byte <= 0x39:        # ASCII digits only: str.isdigit() also takes "²", which int() refuses
            return False
        digits += chr(byte)
    if not digits or start + 1 + len(digits) >= stop or w.frame[start + 1 + len(digits)] != 0x3E:
        return False
    priority = int(digits)
    facility, severity = priority >> 3, priority & 0x07
    facility_text = _SYSLOG_FACILITY_TEXT.get(facility, f"facility {facility}")
    severity_text = _SYSLOG_SEVERITY_TEXT.get(severity, f"severity {severity}")
    fields = [_field("Priority", str(priority), start, len(digits) + 2),
              _field("Facility", f"{facility_text} ({facility})", start, len(digits) + 2),
              _field("Severity", f"{severity_text} ({severity})", start, len(digits) + 2)]
    info = f"{facility_text}.{severity_text}"
    w.add(name, f"Syslog: {info}", start, max(0, stop - start), fields)
    w.say(info)
    return True


#: Application handlers by the protocol name the port table or the sniffer gives; each returns False when the payload
#: is not what the port promised, and the caller falls back to a Data layer.
_APP_HANDLERS: Dict[str, Callable[[_Walk, int, int, str], bool]] = {
    "DNS": _dns, "MDNS": _dns, "LLMNR": _dns, "NBNS": _dns, "DHCP": _dhcp, "DHCPv6": _dhcpv6, "HTTP": _http,
    "SSDP": _http, "RTSP": _http, "SIP": _sip, "TLS": _tls, "RTP": _rtp, "RTCP": _rtcp, "NTP": _ntp, "SNMP": _snmp,
    "TFTP": _tftp, "SMB": _smb, "QUIC": _quic, "SYSLOG": _syslog, "WOL": _wol,
}


# --------------------------------------------------------------------------- the whole frame
def _frame_layer(w: _Walk, linktype: int, ts: Optional[float], origlen: Optional[int]) -> None:
    wire = _wire_length(w.size, origlen)
    fields = [_field("Arrival time", _time_text(ts), 0, 0),
              _field("Epoch time", "not recorded" if ts is None else f"{ts}", 0, 0),
              _field("Captured length", f"{w.size} bytes", 0, 0), _field("Frame length", f"{wire} bytes", 0, 0),
              _field("Link type", _linktype_text(linktype), 0, 0)]
    w.add("Frame", f"Frame: {wire} bytes on the wire, {w.size} bytes captured", 0, w.size, fields, named=False)


def _dissect(frame: bytes, linktype: int, ts: Optional[float], origlen: Optional[int]) -> _Walk:
    w = _Walk(frame)
    _frame_layer(w, linktype, ts, origlen)
    if not w.size:
        w.say("Empty frame")
        return w
    if linktype == _LINKTYPE_ETHERNET:
        _ethernet(w, 0)
    elif linktype == _LINKTYPE_RAW:
        version = frame[0] >> 4
        if version == 4:
            _ipv4(w, 0, w.size)
        elif version == 6:
            _ipv6(w, 0, w.size)
        else:
            w.say(f"Raw IP version {version} is not dissected")
            w.data(0, w.size)
    elif linktype == _LINKTYPE_IPV4:
        _ipv4(w, 0, w.size)
    elif linktype == _LINKTYPE_IPV6:
        _ipv6(w, 0, w.size)
    else:
        w.say(f"Link type {linktype} is not dissected")
        w.data(0, w.size)
    return w


def summarize(frame: bytes, *, linktype: int = 1, ts: Optional[float] = None,
              origlen: Optional[int] = None) -> Dict[str, Any]:
    """One packet-list row for a captured frame: exactly :data:`SUMMARY_KEYS`, in that order.

    *linktype* is the pcapng link type of the interface, *ts* the arrival time (passed straight through) and *origlen*
    the frame's length on the wire when the capture cut it short."""
    w = _dissect(bytes(frame), linktype, ts, origlen)
    return {"ts": ts, "src": w.src, "dst": w.dst, "src_mac": w.src_mac, "dst_mac": w.dst_mac, "proto": w.proto,
            "sport": w.sport, "dport": w.dport, "length": _wire_length(w.size, origlen), "info": w.info,
            "layers": list(w.names), "payload": w.payload}


def detail(frame: bytes, *, linktype: int = 1, ts: Optional[float] = None,
           origlen: Optional[int] = None) -> List[Dict[str, Any]]:
    """The expandable detail tree of a captured frame: one :data:`DETAIL_KEYS` dict per layer, outermost first, the
    first of them the ``Frame`` pseudo-layer. Offsets point into *frame* so the UI can highlight the selected bytes."""
    return _dissect(bytes(frame), linktype, ts, origlen).layers


def hex_dump(data: bytes, *, width: int = 16) -> List[str]:
    """Classic offset / hex / ASCII lines, e.g. ``"0000  45 00 00 3c ...   E..<............"``; ``[]`` for no data.

    *width* is the bytes per line, clamped into 1..:data:`MAX_DUMP_WIDTH`."""
    raw = bytes(data)
    size = width if isinstance(width, int) and not isinstance(width, bool) else 16
    size = max(1, min(size, MAX_DUMP_WIDTH))
    lines = []
    for offset in range(0, len(raw), size):
        chunk = raw[offset:offset + size]
        hexed = " ".join(f"{byte:02x}" for byte in chunk).ljust(size * 3 - 1)
        text = "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in chunk)
        lines.append(f"{offset:04x}  {hexed}   {text}")
    return lines


def mac_text(raw: bytes) -> str:
    """Six bytes as ``"aa:bb:cc:dd:ee:ff"`` (lower case); ``""`` for anything that is not six bytes."""
    data = bytes(raw)
    return ":".join(f"{byte:02x}" for byte in data) if len(data) == 6 else ""


def matches_mac(summary: Dict[str, Any], mac: str) -> bool:
    """True when the row's source or destination MAC is *mac*, whatever case or separators it was typed with."""
    wanted = _mac_key(mac)
    if not wanted:
        return False
    return wanted in (_mac_key(summary.get("src_mac") or ""), _mac_key(summary.get("dst_mac") or ""))


def matches_ip(summary: Dict[str, Any], text: str) -> bool:
    """True when the row's source or destination address is the IP literal *text* (``2001:0db8::1`` finds
    ``2001:db8::1``). Text that is not an address matches nothing."""
    wanted = _as_ip(text)
    if wanted is None:
        return False
    return any(_as_ip(summary.get(key) or "") == wanted for key in ("src", "dst"))


def matches_proto(summary: Dict[str, Any], key: str) -> bool:
    """True when the row's protocol or any of its layers is one the quick filter *key* names.

    *key* is a :data:`PROTO_FILTERS` key (case does not matter); a key that is not in the table matches a layer of
    exactly that name instead, so a protocol without a button of its own can still be filtered."""
    if not isinstance(key, str) or not key.strip():
        return False
    wanted = PROTO_FILTERS.get(key.strip().lower())
    layers = summary.get("layers") or []
    names = [str(name) for name in layers] + [str(summary.get("proto") or "")]
    if wanted is None:
        return any(name.lower() == key.strip().lower() for name in names)
    return any(name in wanted for name in names)
