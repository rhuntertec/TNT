"""tnt.dissect: packet-list rows, the detail tree, the hex dump and the quick filters.

Every frame is built here with struct.pack from the Ethernet, ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, DHCP, TLS, SIP and
RTP field layouts, with MACs 02:00:5e:10:00:0x and addresses from 192.0.2.0/24 and 2001:db8::/32. Nothing here touches
a network, runs a program or reads a file.
"""
from __future__ import annotations

import ast
import random
import struct
from pathlib import Path

import pytest

from tnt import dissect
from tnt.dissect import (DETAIL_KEYS, FIELD_KEYS, MAX_DNS_LABELS, MAX_VLAN_TAGS, PORTS, PROTO_FILTERS, PROTOCOLS,
                         SUMMARY_KEYS, detail, hex_dump, mac_text, matches_ip, matches_mac, matches_proto, summarize)

PC = bytes.fromhex("02005e100001")          # this PC
GATEWAY = bytes.fromhex("02005e100002")     # the router
PHONE = bytes.fromhex("02005e100003")
BROADCAST = b"\xff" * 6
PC_IP = bytes([192, 0, 2, 10])
GATEWAY_IP = bytes([192, 0, 2, 1])
SERVER_IP = bytes([192, 0, 2, 5])
PC_V6 = bytes.fromhex("20010db8000000000000000000000010")
SERVER_V6 = bytes.fromhex("20010db8000000000000000000000002")
PC_TEXT, GATEWAY_TEXT, SERVER_TEXT = "192.0.2.10", "192.0.2.1", "192.0.2.5"
PC_V6_TEXT, SERVER_V6_TEXT = "2001:db8::10", "2001:db8::2"
PC_MAC, GATEWAY_MAC = "02:00:5e:10:00:01", "02:00:5e:10:00:02"


# --------------------------------------------------------------------------- builders
def eth(payload, *, ethertype=0x0800, src=PC, dst=GATEWAY):
    return dst + src + struct.pack(">H", ethertype) + payload


def vlan(vid, *, tpid=0x8100, priority=0):
    """A VLAN tag as it sits in a frame: the TPID where the ethertype was, then the TCI."""
    return struct.pack(">HH", tpid, (priority << 13) | vid)


def ipv4(payload, *, protocol=6, src=PC_IP, dst=SERVER_IP, flags=0x4000, options=b"", total=None):
    ihl = 5 + len(options) // 4
    length = 4 * ihl + len(payload) if total is None else total
    return (struct.pack(">BBHHHBBH", 0x40 | ihl, 0, length, 1, flags, 64, protocol, 0) + src + dst + options
            + payload)


def ipv6(payload, *, next_header=6, src=PC_V6, dst=SERVER_V6, payload_length=None):
    length = len(payload) if payload_length is None else payload_length
    return struct.pack(">IHBB", 6 << 28, length, next_header, 64) + src + dst + payload


def tcp(payload=b"", *, sport=49851, dport=554, seq=0, ack=0, flags=0x02, window=64240, options=b""):
    header = 20 + len(options)
    return (struct.pack(">HHIIHHHH", sport, dport, seq, ack, ((header // 4) << 12) | flags, window, 0, 0)
            + options + payload)


def udp(payload, *, sport=50000, dport=53, length=None):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload) if length is None else length, 0) + payload


def icmp_echo(kind=8, *, identifier=1, sequence=5, body=b"abcdefgh"):
    return struct.pack(">BBHHH", kind, 0, 0, identifier, sequence) + body


def dns_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def dns(name="example.com", *, identifier=0x1A2B, flags=0x0100, qtype=1, questions=1, tail=b""):
    body = dns_name(name) + struct.pack(">HH", qtype, 1) if questions else b""
    return struct.pack(">HHHHHH", identifier, flags, questions, 0, 0, 0) + body + tail


def dhcp_discover(*, xid=0x00003D1D, message=1):
    header = struct.pack(">BBBBIHH", 1, 1, 6, 0, xid, 0, 0x8000) + bytes(16) + PC + bytes(10)
    return (header + bytes(192) + b"\x63\x82\x53\x63" + bytes([53, 1, message]) + bytes([12, 3]) + b"pc1"
            + b"\xff")


def tls_record(content, body, *, version=0x0303):
    return struct.pack(">BHH", content, version, len(body)) + body


def client_hello(host="example.com"):
    """A ClientHello whose only extension is the server name (RFC 6066)."""
    name = host.encode()
    server_name = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack(">HH", 0, len(server_name)) + server_name
    body = (struct.pack(">H", 0x0303) + bytes(32) + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack(">H", len(extensions)) + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return tls_record(22, handshake, version=0x0301)


def rtp(*, payload_type=0, sequence=1000, timestamp=160, ssrc=0x12345678, body=b"\x00" * 20):
    return struct.pack(">BBHII", 0x80, payload_type, sequence, timestamp, ssrc) + body


def arp(*, opcode=1, sender_mac=PC, sender_ip=GATEWAY_IP, target_mac=bytes(6), target_ip=SERVER_IP):
    return struct.pack(">HHBBH", 1, 0x0800, 6, 4, opcode) + sender_mac + sender_ip + target_mac + target_ip


def fields_of(layer):
    return {field["name"]: field["value"] for field in layer["fields"]}


def layer_named(frame, name, **kwargs):
    return next(layer for layer in detail(frame, **kwargs) if layer["name"] == name)


DNS_QUERY = eth(ipv4(udp(dns(), sport=50000, dport=53), protocol=17, dst=GATEWAY_IP))
HTTP_GET = eth(ipv4(tcp(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", dport=80, flags=0x18, seq=1,
                        ack=1), protocol=6))


# --------------------------------------------------------------------------- shapes
def test_summarize_returns_every_key_in_order():
    row = summarize(eth(ipv4(tcp())), ts=1700000000.5, origlen=1514)
    assert tuple(row) == SUMMARY_KEYS
    assert row == {"ts": 1700000000.5, "src": PC_TEXT, "dst": SERVER_TEXT, "src_mac": PC_MAC, "dst_mac": GATEWAY_MAC,
                   "proto": "TCP", "sport": 49851, "dport": 554, "length": 1514,
                   "info": "49851 > 554 [SYN] Seq=0 Win=64240 Len=0", "layers": ["ETH", "IPv4", "TCP"], "payload": b""}
    assert summarize(eth(ipv4(tcp())))["length"] == 54            # no origlen: the captured length


def test_detail_returns_layers_and_fields_in_key_order():
    frame = eth(ipv4(icmp_echo(), protocol=1))
    layers = detail(frame, ts=1700000000.123456)
    assert [tuple(layer) for layer in layers] == [DETAIL_KEYS] * len(layers)
    assert [layer["name"] for layer in layers] == ["Frame", "ETH", "IPv4", "ICMP", "Data"]
    for layer in layers:
        assert all(tuple(field) == FIELD_KEYS for field in layer["fields"])
        assert 0 <= layer["start"] <= len(frame) and layer["start"] + layer["length"] <= len(frame)
        for field in layer["fields"]:
            assert 0 <= field["start"] <= len(frame) and field["start"] + field["length"] <= len(frame)
    frame_layer = layers[0]
    assert frame_layer["summary"] == f"Frame: {len(frame)} bytes on the wire, {len(frame)} bytes captured"
    assert fields_of(frame_layer)["Arrival time"] == "2023-11-14 22:13:20.123456 UTC"
    assert fields_of(frame_layer)["Link type"] == "Ethernet (1)"
    assert fields_of(detail(frame)[0])["Arrival time"] == "not recorded"


def test_detail_offsets_point_at_the_bytes_of_the_field():
    frame = eth(ipv4(tcp()))
    source = next(f for f in layer_named(frame, "IPv4")["fields"] if f["name"] == "Source")
    assert frame[source["start"]:source["start"] + source["length"]] == PC_IP
    destination = next(f for f in layer_named(frame, "ETH")["fields"] if f["name"] == "Destination")
    assert frame[destination["start"]:destination["start"] + destination["length"]] == GATEWAY


def test_every_protocol_name_is_one_the_contract_lists():
    frames = [eth(ipv4(tcp())), eth(arp(), ethertype=0x0806), DNS_QUERY, HTTP_GET, b"", b"\x00" * 3,
              eth(ipv6(tcp()), ethertype=0x86DD), eth(ipv4(icmp_echo(), protocol=1))]
    for frame in frames:
        row = summarize(frame)
        assert row["proto"] in PROTOCOLS
        assert all(name in PROTOCOLS for name in row["layers"])


# --------------------------------------------------------------------------- ARP
def test_arp_request_and_reply():
    request = summarize(eth(arp(), ethertype=0x0806, dst=BROADCAST))
    assert (request["proto"], request["layers"]) == ("ARP", ["ETH", "ARP"])
    assert (request["src"], request["dst"]) == (GATEWAY_TEXT, SERVER_TEXT)
    assert (request["src_mac"], request["dst_mac"]) == (PC_MAC, "ff:ff:ff:ff:ff:ff")
    assert request["info"] == "Who has 192.0.2.5? Tell 192.0.2.1"
    reply = summarize(eth(arp(opcode=2, sender_mac=GATEWAY, sender_ip=SERVER_IP, target_mac=PC,
                              target_ip=GATEWAY_IP), ethertype=0x0806))
    assert reply["info"] == "192.0.2.5 is at 02:00:5e:10:00:02"
    assert fields_of(layer_named(eth(arp(), ethertype=0x0806), "ARP"))["Opcode"] == "request"


def test_arp_that_is_not_ethernet_over_ipv4_is_named_but_not_read_as_addresses():
    body = struct.pack(">HHBBH", 6, 0x0800, 2, 4, 1) + b"\x01\x02" + PC_IP + b"\x03\x04" + SERVER_IP
    row = summarize(eth(body, ethertype=0x0806))
    assert (row["proto"], row["info"]) == ("ARP", "ARP request")
    assert (row["src"], row["dst"]) == (PC_MAC, GATEWAY_MAC)          # no protocol addresses: the MACs stand in


def test_an_arp_address_the_frame_claims_is_long_is_capped_like_every_other_field():
    """hlen and plen come from the frame: 255-byte addresses must not put 510 characters in the detail pane."""
    body = struct.pack(">HHBBH", 1, 0x0800, 255, 255, 1) + bytes(255) * 4
    frame = eth(body, ethertype=0x0806)
    row = summarize(frame)
    assert (row["proto"], row["info"]) == ("ARP", "ARP request")
    assert all(len(field["value"]) <= dissect.MAX_FIELD_TEXT for field in layer_named(frame, "ARP")["fields"])


# --------------------------------------------------------------------------- IPv4, ICMP, TCP, UDP
@pytest.mark.parametrize("kind, text", [(8, "Echo (ping) request id=0x0001 seq=5"),
                                        (0, "Echo (ping) reply id=0x0001 seq=5")])
def test_icmp_echo(kind, text):
    row = summarize(eth(ipv4(icmp_echo(kind), protocol=1)))
    assert (row["proto"], row["layers"], row["info"]) == ("ICMP", ["ETH", "IPv4", "ICMP"], text)
    assert (row["sport"], row["dport"]) == (None, None)


def test_icmp_destination_unreachable_names_its_code():
    body = struct.pack(">BBHI", 3, 3, 0, 0) + ipv4(udp(b"", sport=50000, dport=53), protocol=17)
    assert summarize(eth(ipv4(body, protocol=1)))["info"] == "Destination unreachable (Port unreachable)"
    exceeded = struct.pack(">BBHI", 11, 0, 0, 0) + bytes(28)
    assert summarize(eth(ipv4(exceeded, protocol=1)))["info"] == \
        "Time-to-live exceeded (Time to live exceeded in transit)"


def test_tcp_handshake_and_a_data_segment():
    syn = summarize(eth(ipv4(tcp(options=b"\x02\x04\x05\xb4\x01\x03\x03\x08"))))
    assert syn["info"] == "49851 > 554 [SYN] Seq=0 Win=64240 Len=0"
    options = [f["value"] for f in layer_named(eth(ipv4(tcp(options=b"\x02\x04\x05\xb4\x01\x03\x03\x08"))),
                                               "TCP")["fields"] if f["name"] == "Option"]
    assert options == ["Maximum segment size: 1460", "No operation", "Window scale: 8"]
    ack = summarize(eth(ipv4(tcp(sport=554, dport=49851, ack=1, flags=0x12, window=65535), src=SERVER_IP,
                             dst=PC_IP), src=GATEWAY, dst=PC))
    assert ack["info"] == "554 > 49851 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0"
    push = summarize(eth(ipv4(tcp(b"\x00\x01\x02\x03", sport=49851, dport=49852, seq=1, ack=1, flags=0x18))))
    assert push["info"] == "49851 > 49852 [PSH, ACK] Seq=1 Ack=1 Win=64240 Len=4"
    assert push["layers"] == ["ETH", "IPv4", "TCP"]


def test_tcp_option_walk_stops_at_a_bad_length_and_never_runs_past_forty_bytes():
    bad = summarize(eth(ipv4(tcp(options=b"\x02\x00\x00\x00"))))                 # an option that claims length 0
    assert bad["proto"] == "TCP"
    long_options = b"\x01" * 40
    assert summarize(eth(ipv4(tcp(options=long_options))))["info"].endswith("Len=0")


def test_ipv4_fragment_after_the_first_is_not_dissected_as_a_transport():
    row = summarize(eth(ipv4(b"\x00" * 24, protocol=6, flags=0x2000 | (185 // 8))))
    assert (row["proto"], row["layers"]) == ("IPv4", ["ETH", "IPv4"])
    assert row["info"] == "Fragmented TCP (6), offset 184"
    first = summarize(eth(ipv4(tcp(), flags=0x2000)))
    assert first["proto"] == "TCP"


def test_ipv4_total_length_longer_than_the_capture_is_clamped():
    row = summarize(eth(ipv4(tcp(), total=1500)))
    assert row["info"] == "49851 > 554 [SYN] Seq=0 Win=64240 Len=0"


def test_an_unknown_ip_protocol_keeps_the_ip_row():
    row = summarize(eth(ipv4(b"\x00" * 8, protocol=47)))
    assert (row["proto"], row["info"], row["layers"]) == ("IPv4", "GRE (47)", ["ETH", "IPv4"])
    assert detail(eth(ipv4(b"\x00" * 8, protocol=47)))[-1]["name"] == "Data"


def test_udp_without_a_known_port_keeps_the_ports_and_length():
    row = summarize(eth(ipv4(udp(b"\x00" * 10, sport=40000, dport=40001), protocol=17)))
    assert (row["proto"], row["sport"], row["dport"], row["info"]) == ("UDP", 40000, 40001, "40000 > 40001 Len=10")


# --------------------------------------------------------------------------- IGMP
def test_igmp_v2_query_and_leave_read_the_group_address():
    query = struct.pack(">BBH", 0x11, 100, 0) + bytes([239, 1, 1, 1])
    row = summarize(eth(ipv4(query, protocol=2, dst=bytes([239, 1, 1, 1]))))
    assert (row["proto"], row["layers"]) == ("IGMP", ["ETH", "IPv4", "IGMP"])
    assert row["info"] == "Membership query for 239.1.1.1"
    assert fields_of(layer_named(eth(ipv4(query, protocol=2)), "IGMP"))["Max response time"] == "100"
    general = struct.pack(">BBH", 0x11, 100, 0) + bytes(4)               # every group: no address of its own
    assert summarize(eth(ipv4(general, protocol=2)))["info"] == "Membership query"


def test_igmp_v3_membership_report_reads_its_group_records_not_a_group_address():
    """RFC 3376 §4.2: a v3 report has reserved bytes and a record count where v1 and v2 have a group address."""
    record = struct.pack(">BBH", 4, 0, 0) + bytes([239, 1, 1, 1])        # change to exclude, no sources
    frame = eth(ipv4(struct.pack(">BBHHH", 0x22, 0, 0, 0, 1) + record, protocol=2, dst=bytes([224, 0, 0, 22])))
    row = summarize(frame)
    assert (row["proto"], row["layers"]) == ("IGMP", ["ETH", "IPv4", "IGMP"])
    assert row["info"] == "Membership report v3 for 239.1.1.1"
    fields = fields_of(layer_named(frame, "IGMP"))
    assert (fields["Group records"], fields["Multicast address"]) == ("1", "239.1.1.1")
    assert "Group address" not in fields and "Max response time" not in fields
    address = next(f for f in layer_named(frame, "IGMP")["fields"] if f["name"] == "Multicast address")
    assert frame[address["start"]:address["start"] + address["length"]] == bytes([239, 1, 1, 1])
    two = struct.pack(">BBHHH", 0x22, 0, 0, 0, 2) + record + struct.pack(">BBH", 4, 0, 0) + bytes([239, 1, 1, 2])
    assert summarize(eth(ipv4(two, protocol=2)))["info"] == "Membership report v3, 2 group records"


# --------------------------------------------------------------------------- IPv6
def test_ipv6_with_tcp():
    row = summarize(eth(ipv6(tcp(dport=443)), ethertype=0x86DD))
    assert (row["proto"], row["layers"]) == ("TCP", ["ETH", "IPv6", "TCP"])
    assert (row["src"], row["dst"], row["dport"]) == (PC_V6_TEXT, SERVER_V6_TEXT, 443)
    assert fields_of(layer_named(eth(ipv6(tcp()), ethertype=0x86DD), "IPv6"))["Hop limit"] == "64"


def test_ipv6_neighbour_solicitation():
    body = struct.pack(">BBHI", 135, 0, 0, 0) + SERVER_V6 + b"\x01\x01" + PC
    row = summarize(eth(ipv6(body, next_header=58), ethertype=0x86DD))
    assert (row["proto"], row["layers"]) == ("ICMPv6", ["ETH", "IPv6", "ICMPv6"])
    assert row["info"] == "Neighbour solicitation for 2001:db8::2"
    echo = struct.pack(">BBHHH", 128, 0, 0, 1, 5)
    assert summarize(eth(ipv6(echo, next_header=58), ethertype=0x86DD))["info"] == \
        "Echo (ping) request id=0x0001 seq=5"


def test_ipv6_extension_headers_are_walked_and_capped():
    hop_by_hop = bytes([17, 0]) + bytes(6)                       # next header UDP, one 8-byte block
    frame = eth(ipv6(hop_by_hop + udp(dns(), sport=50000, dport=53), next_header=0), ethertype=0x86DD)
    row = summarize(frame)
    assert (row["proto"], row["layers"]) == ("DNS", ["ETH", "IPv6", "UDP", "DNS"])
    assert [layer["name"] for layer in detail(frame)][:4] == ["Frame", "ETH", "IPv6", "IPv6 Hop-by-Hop Options"]
    chain = bytes([0, 0]) + bytes(6)
    deep = eth(ipv6(chain * 12 + tcp(), next_header=0), ethertype=0x86DD)       # more headers than the cap
    assert summarize(deep)["proto"] == "IPv6"                    # the walk stopped, nothing was dissected past it


def test_an_ipv6_extension_header_cut_short_says_truncated_not_no_next_header():
    """A header cut short must name itself; only a real next header 59 gives "No next header"."""
    over_long = eth(ipv6(bytes([17, 3]) + bytes(6), next_header=0), ethertype=0x86DD)   # claims 32 bytes, 8 are there
    assert summarize(over_long)["info"] == "Truncated IPv6 Hop-by-Hop Options"
    assert [layer["name"] for layer in detail(over_long)][-1] == "IPv6 Hop-by-Hop Options"
    short = eth(ipv6(bytes([17, 3]) + bytes(4), next_header=0), ethertype=0x86DD)       # shorter than the minimum
    assert summarize(short)["info"] == "Truncated IPv6 Hop-by-Hop Options"
    routing = eth(ipv6(bytes([6, 1]) + bytes(4), next_header=43), ethertype=0x86DD)
    assert summarize(routing)["info"] == "Truncated IPv6 Routing"
    assert summarize(eth(ipv6(bytes(4), next_header=59), ethertype=0x86DD))["info"] == "No next header"


def test_ipv6_fragment_after_the_first_is_not_dissected():
    fragment = struct.pack(">BBHI", 6, 0, (185 // 8) << 3, 1) + b"\x00" * 8
    row = summarize(eth(ipv6(fragment, next_header=44), ethertype=0x86DD))
    assert (row["proto"], row["info"]) == ("IPv6", "Fragmented TCP (6)")


# --------------------------------------------------------------------------- VLAN tags
def test_a_vlan_tagged_frame_names_the_tag_and_keeps_going():
    frame = GATEWAY + PC + vlan(10) + struct.pack(">H", 0x0800) + ipv4(icmp_echo(), protocol=1)
    row = summarize(frame)
    assert row["layers"] == ["ETH", "802.1Q", "IPv4", "ICMP"]
    assert (row["proto"], row["info"]) == ("ICMP", "Echo (ping) request id=0x0001 seq=5")
    assert fields_of(layer_named(frame, "802.1Q"))["VLAN ID"] == "10"


def test_a_double_tagged_frame_reads_both_tags():
    frame = (GATEWAY + PC + vlan(100, tpid=0x88A8) + struct.pack(">H", 0x8100) + struct.pack(">H", 10)
             + struct.pack(">H", 0x0800) + ipv4(tcp()))
    row = summarize(frame)
    assert row["layers"] == ["ETH", "802.1Q", "802.1Q", "IPv4", "TCP"]
    tags = [layer for layer in detail(frame) if layer["name"] == "802.1Q"]
    assert [fields_of(tag)["VLAN ID"] for tag in tags] == ["100", "10"]
    assert MAX_VLAN_TAGS == 2
    stacked = GATEWAY + PC + vlan(1) + b"\x81\x00" + struct.pack(">H", 2) + b"\x81\x00" + struct.pack(">H", 3) \
        + struct.pack(">H", 0x0800) + ipv4(tcp())
    assert summarize(stacked)["layers"] == ["ETH", "802.1Q", "802.1Q"]          # the third tag is not followed


# --------------------------------------------------------------------------- DNS and DHCP
def test_dns_query_and_response():
    query = summarize(DNS_QUERY)
    assert (query["proto"], query["layers"]) == ("DNS", ["ETH", "IPv4", "UDP", "DNS"])
    assert (query["sport"], query["dport"]) == (50000, 53)
    assert query["info"] == "Standard query 0x1a2b A example.com"
    answer = dns_name("example.com") + struct.pack(">HHIH", 1, 1, 60, 4) + SERVER_IP
    body = dns(flags=0x8180, tail=answer)
    body = body[:6] + struct.pack(">H", 1) + body[8:]                   # one answer record
    response = summarize(eth(ipv4(udp(body, sport=53, dport=50000), protocol=17)))
    assert response["info"] == "Standard query response 0x1a2b A example.com"
    missing = summarize(eth(ipv4(udp(dns(flags=0x8183), sport=53, dport=50000), protocol=17)))
    assert missing["info"] == "Standard query response No such name 0x1a2b A example.com"


def test_dns_over_mdns_and_llmnr_keep_their_own_names():
    row = summarize(eth(ipv4(udp(dns("printer.local"), sport=5353, dport=5353), protocol=17)))
    assert (row["proto"], row["layers"][-1]) == ("MDNS", "MDNS")
    assert row["info"] == "Standard query 0x1a2b A printer.local"
    assert summarize(eth(ipv4(udp(dns("pc1"), sport=60000, dport=5355), protocol=17)))["proto"] == "LLMNR"


def test_dns_name_compression_must_point_backwards():
    forward = dns()[:12] + b"\xc0\x20" + struct.pack(">HH", 1, 1)       # a pointer past itself
    row = summarize(eth(ipv4(udp(forward, sport=50000, dport=53), protocol=17)))
    assert row["info"] == "Standard query 0x1a2b"                        # no question name was read
    backwards = dns() + b"\xc0\x0c" + struct.pack(">HH", 1, 1)
    assert summarize(eth(ipv4(udp(backwards, sport=50000, dport=53), protocol=17)))["proto"] == "DNS"
    loop = dns()[:12] + b"\xc0\x0c" + struct.pack(">HH", 1, 1)           # a pointer at itself
    assert summarize(eth(ipv4(udp(loop, sport=50000, dport=53), protocol=17)))["info"] == "Standard query 0x1a2b"


def test_a_dns_pointer_that_points_forward_inside_the_message_is_refused():
    """RFC 1035 §4.1.4: a pointer names a prior occurrence of the name, so one that points past itself is not one,
    even when its target is inside the message and holds a perfectly good name."""
    forward = (dns()[:12] + b"\xc0\x12" + struct.pack(">HH", 1, 1) + dns_name("forward.com"))
    assert forward[18:19] == b"\x07"                                     # offset 18 really is that name
    row = summarize(eth(ipv4(udp(forward, sport=50000, dport=53), protocol=17)))
    assert (row["proto"], row["info"]) == ("DNS", "Standard query 0x1a2b")


def test_a_dns_name_of_many_labels_is_capped():
    name = ".".join(["a"] * (MAX_DNS_LABELS + 20))
    row = summarize(eth(ipv4(udp(dns(name), sport=50000, dport=53), protocol=17)))
    assert row["proto"] == "DNS" and row["info"] == "Standard query 0x1a2b"


def test_dhcp_discover():
    row = summarize(eth(ipv4(udp(dhcp_discover(), sport=68, dport=67), protocol=17, src=bytes(4),
                             dst=bytes([255, 255, 255, 255])), dst=BROADCAST))
    assert (row["proto"], row["layers"]) == ("DHCP", ["ETH", "IPv4", "UDP", "DHCP"])
    assert row["info"] == "Discover, transaction 0x00003d1d"
    assert fields_of(layer_named(eth(ipv4(udp(dhcp_discover(message=5), sport=67, dport=68), protocol=17)),
                                 "DHCP"))["Message type"] == "ACK (5)"


def test_dhcpv6_names_its_message_type():
    body = bytes([1]) + b"\x0a\x0b\x0c" + bytes(8)
    row = summarize(eth(ipv6(udp(body, sport=546, dport=547), next_header=17), ethertype=0x86DD))
    assert (row["proto"], row["info"]) == ("DHCPv6", "Solicit, transaction 0x0a0b0c")


# --------------------------------------------------------------------------- HTTP, TLS, SIP, RTP
def test_http_request_and_status_line():
    row = summarize(HTTP_GET)
    assert (row["proto"], row["layers"]) == ("HTTP", ["ETH", "IPv4", "TCP", "HTTP"])
    assert row["info"] == "GET /index.html HTTP/1.1"
    assert fields_of(layer_named(HTTP_GET, "HTTP"))["Method"] == "GET"
    status = eth(ipv4(tcp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", sport=80, dport=49851, flags=0x18)))
    assert summarize(status)["info"] == "HTTP/1.1 200 OK"
    assert fields_of(layer_named(status, "HTTP"))["Status code"] == "200"


def test_http_first_line_fields_point_at_their_own_bytes():
    """The status code is not at the start of the line, and neither is the version of a request line."""
    status = eth(ipv4(tcp(b"HTTP/1.1 404 Not Found\r\n\r\n", sport=80, dport=49851, flags=0x18)))
    found = {field["name"]: field for field in layer_named(status, "HTTP")["fields"]}
    for name, raw in (("Version", b"HTTP/1.1"), ("Status code", b"404"), ("First line", b"HTTP/1.1 404 Not Found")):
        field = found[name]
        assert status[field["start"]:field["start"] + field["length"]] == raw
    request = {field["name"]: field for field in layer_named(HTTP_GET, "HTTP")["fields"]}
    for name, raw in (("Method", b"GET"), ("Request URI", b"/index.html"), ("Version", b"HTTP/1.1")):
        field = request[name]
        assert HTTP_GET[field["start"]:field["start"] + field["length"]] == raw


def test_http_on_a_port_that_is_not_http_falls_back_to_tcp():
    row = summarize(eth(ipv4(tcp(b"\x00\x01\x02\x03binary", dport=80, flags=0x18))))
    assert (row["proto"], row["layers"]) == ("TCP", ["ETH", "IPv4", "TCP"])
    assert detail(eth(ipv4(tcp(b"\x00\x01binary", dport=80, flags=0x18))))[-1]["name"] == "Data"


def test_tls_client_hello_carries_the_server_name():
    frame = eth(ipv4(tcp(client_hello(), dport=443, flags=0x18)))
    row = summarize(frame)
    assert (row["proto"], row["layers"]) == ("TLS", ["ETH", "IPv4", "TCP", "TLS"])
    assert row["info"] == "Client Hello (SNI=example.com)"
    assert fields_of(layer_named(frame, "TLS"))["Server name"] == "example.com"
    application = eth(ipv4(tcp(tls_record(23, b"\x00" * 40), dport=443, flags=0x18)))
    assert summarize(application)["info"] == "Application Data"
    assert fields_of(layer_named(application, "TLS"))["Version"] == "TLS 1.2"


def test_tls_on_an_unknown_port_is_still_found():
    row = summarize(eth(ipv4(tcp(tls_record(23, b"\x00" * 40), dport=44300, flags=0x18))))
    assert row["proto"] == "TLS"


def test_sip_invite_over_udp_5060_and_on_an_odd_port():
    invite = b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.10\r\n\r\n"
    frame = eth(ipv4(udp(invite, sport=5060, dport=5060), protocol=17), dst=PHONE)
    row = summarize(frame)
    assert (row["proto"], row["layers"]) == ("SIP", ["ETH", "IPv4", "UDP", "SIP"])
    assert row["info"] == "INVITE sip:bob@example.com"
    assert fields_of(layer_named(frame, "SIP"))["Request URI"] == "sip:bob@example.com"
    odd = summarize(eth(ipv4(udp(invite, sport=5062, dport=15060), protocol=17)))
    assert odd["proto"] == "SIP"                                   # content sniffing, not the port
    ringing = b"SIP/2.0 180 Ringing\r\nVia: SIP/2.0/UDP 192.0.2.10\r\n\r\n"
    assert summarize(eth(ipv4(udp(ringing, sport=5060, dport=5060), protocol=17)))["info"] == "180 Ringing"


def test_rtp_on_an_even_port_and_rtcp_on_the_odd_one():
    row = summarize(eth(ipv4(udp(rtp(), sport=16400, dport=16402), protocol=17)))
    assert (row["proto"], row["layers"]) == ("RTP", ["ETH", "IPv4", "UDP", "RTP"])
    assert row["info"] == "PT=PCMU SSRC=0x12345678 Seq=1000 Time=160"
    report = struct.pack(">BBHI", 0x80, 200, 6, 0x12345678) + bytes(20)
    assert summarize(eth(ipv4(udp(report, sport=16401, dport=16403), protocol=17)))["proto"] == "RTCP"
    assert summarize(eth(ipv4(udp(rtp(), sport=16401, dport=16403), protocol=17)))["proto"] == "UDP"


def test_a_receiver_report_with_no_reception_blocks_is_still_rtcp():
    """RFC 3550 §6.4.2: eight bytes is a whole receiver report, four short of an RTP header."""
    report = struct.pack(">BBH", 0x80, 201, 1) + struct.pack(">I", 0x12345678)
    row = summarize(eth(ipv4(udp(report, sport=16401, dport=16403), protocol=17)))
    assert (row["proto"], row["info"]) == ("RTCP", "Receiver Report")
    assert row["layers"] == ["ETH", "IPv4", "UDP", "RTCP"]


def test_a_syslog_priority_of_digits_that_are_not_ascii_is_not_one():
    """"²" passes str.isdigit() but int() refuses it: the frame falls back to UDP instead of raising."""
    row = summarize(eth(ipv4(udp(b"<\xb2>hello", sport=50000, dport=514), protocol=17)))
    assert (row["proto"], row["info"]) == ("UDP", "50000 > 514 Len=8")
    for payload in (b"<\xb9\xb2>x", b"<1\xb2>x", b"<\xb3>x", b"<>message", b"<abc>x"):
        assert summarize(eth(ipv4(udp(payload, sport=50000, dport=514), protocol=17)))["proto"] == "UDP"


@pytest.mark.parametrize("payload, sport, dport, proto, info", [
    (b"\x23" + b"\x00" * 47, 123, 123, "NTP", "NTP version 4, client"),                       # LI 0, version 4, mode 3
    (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n", 50000, 1900, "SSDP",
     "M-SEARCH * HTTP/1.1"),
    (struct.pack(">H", 1) + b"boot.bin\x00octet\x00", 50000, 69, "TFTP", "Read request"),
    (struct.pack(">H", 3) + struct.pack(">H", 7) + b"\x00" * 512, 50000, 69, "TFTP", "Data, block 7"),
    (b"\x30\x1a\x02\x01\x01\x04\x06public" + b"\x00" * 8, 50000, 161, "SNMP", "SNMP v2c, community 6 bytes"),
    (b"<13>Sep 17 10:00:00 pc1 message", 50000, 514, "SYSLOG", "user.notice"),
    (b"\xc0" + struct.pack(">I", 1) + b"\x00" * 20, 50000, 443, "QUIC", "Initial, version 0x00000001"),
], ids=["ntp", "ssdp", "tftp_read", "tftp_data", "snmp", "syslog", "quic"])
def test_the_rest_of_the_udp_port_table(payload, sport, dport, proto, info):
    row = summarize(eth(ipv4(udp(payload, sport=sport, dport=dport), protocol=17)))
    assert (row["proto"], row["info"]) == (proto, info)
    assert row["layers"] == ["ETH", "IPv4", "UDP", proto]


def test_smb_and_rtsp_over_tcp():
    smb = b"\x00\x00\x00\x40" + b"\xfeSMB" + bytes(8) + struct.pack("<H", 5) + bytes(50)
    row = summarize(eth(ipv4(tcp(smb, dport=445, flags=0x18))))
    assert (row["proto"], row["info"]) == ("SMB", "SMB2 Create")
    rtsp = b"DESCRIBE rtsp://192.0.2.5/stream RTSP/1.0\r\nCSeq: 2\r\n\r\n"
    row = summarize(eth(ipv4(tcp(rtsp, dport=554, flags=0x18))))
    assert (row["proto"], row["info"]) == ("RTSP", "DESCRIBE rtsp://192.0.2.5/stream RTSP/1.0")


def test_an_snmp_community_string_is_never_read_into_the_row():
    payload = b"\x30\x1a\x02\x01\x00\x04\x08secret12" + b"\x00" * 8
    frame = eth(ipv4(udp(payload, sport=50000, dport=161), protocol=17))
    row = summarize(frame)
    assert row["info"] == "SNMP v1, community 8 bytes"
    assert "secret12" not in row["info"]
    assert not any("secret" in field["value"] for field in layer_named(frame, "SNMP")["fields"])


# --------------------------------------------------------------------------- link-layer neighbours and oddities
def test_lldp_and_cdp_are_decoded_by_tnt_lldp():
    lldpdu = (struct.pack(">H", (1 << 9) | 7) + b"\x04" + GATEWAY + struct.pack(">H", (2 << 9) | 7) + b"\x05Port 7"
              + struct.pack(">H", (3 << 9) | 2) + struct.pack(">H", 120)
              + struct.pack(">H", (5 << 9) | 9) + b"LAB-SW-01" + struct.pack(">H", 0))
    row = summarize(eth(lldpdu, ethertype=0x88CC, src=GATEWAY, dst=bytes.fromhex("0180c200000e")))
    assert (row["proto"], row["layers"], row["info"]) == ("LLDP", ["ETH", "LLDP"], "LAB-SW-01, port Port 7")
    packet = bytes([2, 180]) + b"\x12\x34" + struct.pack(">HH", 1, 13) + b"LAB-SW-01"
    llc = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + packet
    frame = bytes.fromhex("01000ccccccc") + GATEWAY + struct.pack(">H", len(llc)) + llc
    cdp = summarize(frame)
    assert (cdp["proto"], cdp["layers"], cdp["info"]) == ("CDP", ["ETH", "CDP"], "LAB-SW-01")
    assert [layer["name"] for layer in detail(frame)] == ["Frame", "ETH", "LLC", "CDP"]


def test_a_spanning_tree_bpdu_over_llc():
    bpdu = struct.pack(">HBB", 0, 0, 0) + b"\x00" + struct.pack(">H", 32768) + GATEWAY + struct.pack(">I", 0) \
        + struct.pack(">H", 32768) + GATEWAY + struct.pack(">H", 0x8001) + bytes(8)
    llc = b"\x42\x42\x03" + bpdu
    frame = bytes.fromhex("0180c2000000") + GATEWAY + struct.pack(">H", len(llc)) + llc
    row = summarize(frame)
    assert (row["proto"], row["layers"]) == ("STP", ["ETH", "STP"])
    assert row["info"].startswith("Configuration BPDU, root 32768/02:00:5e:10:00:02")


def test_a_spanning_tree_bpdu_reads_the_bridge_and_the_port_identifier():
    """802.1D-2004 §9.3.1: root identifier 5-12, root path cost 13-16, bridge identifier 17-24, port 25-26."""
    bridge_mac = bytes.fromhex("0a0b0c0d0e0f")                   # a bridge that is not the root, so the two differ
    bpdu = struct.pack(">HBB", 0, 0, 0) + b"\x00" + struct.pack(">H", 32768) + GATEWAY + struct.pack(">I", 4) \
        + struct.pack(">H", 4096) + bridge_mac + struct.pack(">H", 0x8001) + bytes(8)
    llc = b"\x42\x42\x03" + bpdu
    frame = bytes.fromhex("0180c2000000") + GATEWAY + struct.pack(">H", len(llc)) + llc
    found = fields_of(layer_named(frame, "STP"))
    assert found["Root bridge"] == "32768/02:00:5e:10:00:02"
    assert found["Root path cost"] == "4"
    assert found["Bridge"] == "4096/0a:0b:0c:0d:0e:0f"
    assert found["Port"] == "0x8001"
    bridge = next(f for f in layer_named(frame, "STP")["fields"] if f["name"] == "Bridge")
    assert frame[bridge["start"]:bridge["start"] + bridge["length"]] == struct.pack(">H", 4096) + bridge_mac


def test_an_unknown_ethertype_stays_an_ethernet_row():
    row = summarize(eth(b"\x00" * 20, ethertype=0x9999))
    assert (row["proto"], row["layers"]) == ("ETH", ["ETH"])
    assert row["info"] == "02:00:5e:10:00:01 > 02:00:5e:10:00:02, type 0x9999"
    assert (row["src"], row["dst"]) == (PC_MAC, GATEWAY_MAC)


def test_wake_on_lan_over_its_own_ethertype():
    magic = b"\xff" * 6 + PHONE * 16
    row = summarize(eth(magic, ethertype=0x0842, dst=BROADCAST))
    assert (row["proto"], row["info"]) == ("WOL", "Magic packet for 02:00:5e:10:00:03")
    assert summarize(eth(b"\xff" * 6 + b"\x00" * 60, ethertype=0x0842))["proto"] == "ETH"


@pytest.mark.parametrize("linktype, frame, proto", [
    (101, ipv4(tcp()), "TCP"),
    (101, ipv6(tcp()), "TCP"),
    (228, ipv4(icmp_echo(), protocol=1), "ICMP"),
    (229, ipv6(tcp()), "TCP"),
    (101, b"\x00" * 20, "UNKNOWN"),
    (99, b"\x00" * 20, "UNKNOWN"),
])
def test_other_link_types(linktype, frame, proto):
    row = summarize(frame, linktype=linktype)
    assert row["proto"] == proto
    assert (row["src_mac"], row["dst_mac"]) == ("", "")
    assert detail(frame, linktype=linktype)[0]["name"] == "Frame"


# --------------------------------------------------------------------------- truncation and garbage
def test_an_empty_frame():
    row = summarize(b"")
    assert row == {"ts": None, "src": "", "dst": "", "src_mac": "", "dst_mac": "", "proto": "UNKNOWN",
                   "sport": None, "dport": None, "length": 0, "info": "Empty frame", "layers": [], "payload": b""}
    layers = detail(b"")
    assert [layer["name"] for layer in layers] == ["Frame"]
    assert layers[0]["summary"] == "Frame: 0 bytes on the wire, 0 bytes captured"


@pytest.mark.parametrize("frame", [
    eth(ipv4(udp(dns(), sport=50000, dport=53), protocol=17)),
    eth(ipv4(tcp(client_hello(), dport=443, flags=0x18))),
    eth(ipv6(struct.pack(">BBHI", 135, 0, 0, 0) + SERVER_V6, next_header=58), ethertype=0x86DD),
    eth(arp(), ethertype=0x0806),
    GATEWAY + PC + vlan(10) + struct.pack(">H", 0x0800) + ipv4(icmp_echo(), protocol=1),
], ids=["dns", "tls", "icmpv6", "arp", "vlan"])
def test_a_frame_cut_at_every_byte_still_gives_a_row_and_a_tree(frame):
    for size in range(len(frame) + 1):
        cut = frame[:size]
        row = summarize(cut, ts=1.0, origlen=len(frame))
        assert tuple(row) == SUMMARY_KEYS
        assert row["proto"] in PROTOCOLS and row["info"]
        assert row["length"] == len(frame)
        layers = detail(cut)
        assert layers and layers[0]["name"] == "Frame"
        for layer in layers:
            assert layer["start"] + layer["length"] <= size
            for field in layer["fields"]:
                assert field["start"] + field["length"] <= size


@pytest.mark.parametrize("frame, proto, info", [
    (eth(b"")[:13], "ETH", "Truncated Ethernet"),
    (eth(ipv4(tcp())[:10]), "IPv4", "Truncated IPv4"),
    (eth(ipv4(tcp()[:12])), "TCP", "Truncated TCP"),
    (eth(ipv4(udp(b"")[:5], protocol=17)), "UDP", "Truncated UDP"),
    (eth(ipv4(b"\x08\x00", protocol=1)), "ICMP", "Truncated ICMP"),
    (eth(ipv6(b"")[:30], ethertype=0x86DD), "IPv6", "Truncated IPv6"),
    (eth(arp()[:6], ethertype=0x0806), "ARP", "Truncated ARP"),
    (GATEWAY + PC + b"\x81\x00\x00", "802.1Q", "Truncated VLAN tag"),
])
def test_every_header_cut_short_says_so(frame, proto, info):
    row = summarize(frame)
    assert (row["proto"], row["info"]) == (proto, info)
    assert detail(frame)[-1]["summary"].endswith(f"truncated after {len(frame) - detail(frame)[-1]['start']} bytes")


@pytest.mark.parametrize("frame, proto, info", [
    (eth(b"\x65" + b"\x00" * 30), "IPv4", "Malformed IPv4"),                     # version 6 behind ethertype IPv4
    (eth(b"\x45" + b"\x00" * 39, ethertype=0x86DD), "IPv6", "Malformed IPv6"),
    (eth(ipv4(struct.pack(">HHIIHHHH", 1, 2, 0, 0, 0x0002, 0, 0, 0))), "TCP", "Malformed TCP"),
])
def test_a_header_that_cannot_be_one_says_so(frame, proto, info):
    row = summarize(frame)
    assert (row["proto"], row["info"]) == (proto, info)


@pytest.mark.parametrize("frame", [b"", b"\x00", b"\xff" * 14, bytes(range(60)), b"\xff" * 1500,
                                   bytes([0x45]) * 40, b"\x00" * 64])
def test_garbage_never_raises(frame):
    for linktype in (1, 101, 228, 229, 47):
        row = summarize(frame, linktype=linktype, ts=None, origlen=len(frame) + 4)
        assert tuple(row) == SUMMARY_KEYS and row["proto"] in PROTOCOLS
        assert all(tuple(layer) == DETAIL_KEYS for layer in detail(frame, linktype=linktype))


def test_mutated_frames_never_raise_and_never_point_outside_the_frame():
    """A seeded fuzz over the frames above: a byte or two changed, and often the tail cut off."""
    seeds = [DNS_QUERY, HTTP_GET, eth(ipv4(tcp(client_hello(), dport=443, flags=0x18))),
             eth(ipv4(udp(dhcp_discover(), sport=68, dport=67), protocol=17)),
             eth(ipv6(udp(bytes(20), sport=546, dport=547), next_header=17), ethertype=0x86DD),
             eth(ipv4(udp(rtp(), sport=16400, dport=16402), protocol=17)),
             eth(ipv4(icmp_echo(), protocol=1)),
             GATEWAY + PC + vlan(10) + struct.pack(">H", 0x0800) + ipv4(tcp())]
    rng = random.Random(20260917)
    for _ in range(4000):
        frame = bytearray(rng.choice(seeds))
        for _flip in range(rng.randrange(1, 5)):
            frame[rng.randrange(len(frame))] = rng.randrange(256)
        if rng.random() < 0.4:
            frame = frame[:rng.randrange(len(frame) + 1)]
        frame = bytes(frame)
        row = summarize(frame, ts=1.0)
        assert tuple(row) == SUMMARY_KEYS and row["proto"] in PROTOCOLS
        for layer in detail(frame):
            assert layer["start"] + layer["length"] <= len(frame)
            for field in layer["fields"]:
                assert field["start"] + field["length"] <= len(frame)


def test_a_strange_timestamp_or_wire_length_never_raises():
    assert summarize(eth(ipv4(tcp())), ts=-1e18)["ts"] == -1e18
    assert "Arrival time" in fields_of(detail(eth(ipv4(tcp())), ts=1e18)[0])
    assert summarize(eth(ipv4(tcp())), origlen=-5)["length"] == 54
    assert summarize(eth(ipv4(tcp())), origlen=True)["length"] == 54


# --------------------------------------------------------------------------- helpers and filters
def test_hex_dump():
    assert hex_dump(b"") == []
    lines = hex_dump(bytes.fromhex("450000 3c") + b"hello world" + bytes(4))
    assert lines[0] == "0000  45 00 00 3c 68 65 6c 6c 6f 20 77 6f 72 6c 64 00   E..<hello world."
    assert lines[1] == "0010  00 00 00                                          ..."
    assert hex_dump(b"12345", width=4) == ["0000  31 32 33 34   1234", "0004  35            5"]
    assert len(hex_dump(bytes(300))) == 19
    assert hex_dump(b"\x00\x01", width=0) == hex_dump(b"\x00\x01", width=1)
    assert hex_dump(b"\x00", width=10_000) == hex_dump(b"\x00", width=dissect.MAX_DUMP_WIDTH)


@pytest.mark.parametrize("raw, expected", [
    (PC, "02:00:5e:10:00:01"), (b"\xff" * 6, "ff:ff:ff:ff:ff:ff"), (b"", ""), (b"\x01" * 5, ""), (b"\x01" * 7, ""),
])
def test_mac_text(raw, expected):
    assert mac_text(raw) == expected


@pytest.mark.parametrize("mac, expected", [
    ("02:00:5e:10:00:01", True), ("02-00-5E-10-00-01", True), ("02005E100001", True), ("0200.5e10.0001", True),
    ("  02:00:5e:10:00:01  ", True), ("02:00:5e:10:00:02", True), ("02:00:5e:10:00:03", False),
    ("", False), ("not a mac", False), ("02:00:5e:10:00", False),
])
def test_matches_mac(mac, expected):
    assert matches_mac(summarize(eth(ipv4(tcp()))), mac) is expected
    assert matches_mac(summarize(b""), mac) is False


@pytest.mark.parametrize("text, expected", [
    ("192.0.2.10", True), (" 192.0.2.5 ", True), ("192.0.2.1", False), ("", False), ("example.com", False),
    ("192.0.2", False),
])
def test_matches_ip(text, expected):
    assert matches_ip(summarize(eth(ipv4(tcp()))), text) is expected


def test_matches_ip_compares_parsed_addresses():
    row = summarize(eth(ipv6(tcp()), ethertype=0x86DD))
    assert matches_ip(row, "2001:0db8:0000:0000:0000:0000:0000:0010") is True
    assert matches_ip(row, "[2001:db8::2]") is True
    assert matches_ip(row, "2001:db8::3") is False
    assert matches_ip(summarize(eth(arp(), ethertype=0x0806)), "192.0.2.5") is True
    assert matches_ip(summarize(eth(b"\x00" * 20, ethertype=0x9999)), "192.0.2.5") is False


def test_proto_filters_name_only_protocols_the_contract_lists():
    for key, names in PROTO_FILTERS.items():
        assert key == key.lower() and names
        assert all(name in PROTOCOLS for name in names)
    assert set(PROTO_FILTERS) >= {"icmp", "sip", "http", "https", "dns", "dhcp", "arp", "tcp", "udp", "rtp", "tls",
                                  "rtsp"}


@pytest.mark.parametrize("key, expected", [
    ("http", True), ("tcp", True), ("HTTP", True), (" http ", True), ("https", False), ("udp", False),
    ("icmp", False), ("ipv4", True), ("eth", True), ("nonsense", False), ("", False),
])
def test_matches_proto(key, expected):
    assert matches_proto(summarize(HTTP_GET), key) is expected


def test_matches_proto_groups_related_protocols():
    icmpv6 = summarize(eth(ipv6(struct.pack(">BBHI", 135, 0, 0, 0) + SERVER_V6, next_header=58), ethertype=0x86DD))
    assert matches_proto(icmpv6, "icmp") is True
    assert matches_proto(summarize(eth(ipv4(icmp_echo(), protocol=1))), "icmp") is True
    mdns = summarize(eth(ipv4(udp(dns(), sport=5353, dport=5353), protocol=17)))
    assert (matches_proto(mdns, "dns"), matches_proto(mdns, "udp")) == (True, True)
    tls = summarize(eth(ipv4(tcp(client_hello(), dport=443, flags=0x18))))
    assert (matches_proto(tls, "https"), matches_proto(tls, "tls"), matches_proto(tls, "http")) == (True, True, False)


def test_ports_table_names_handlers_that_exist():
    for transport, table in PORTS.items():
        assert transport in ("tcp", "udp")
        for port, name in table.items():
            assert 0 < port < 65536 and name in PROTOCOLS


def test_module_opens_no_socket_and_runs_no_program():
    """tnt.dissect has no I/O seam for tests/conftest.py to guard: it only decodes the bytes it is given."""
    tree = ast.parse(Path(dissect.__file__).read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {(node.module or "").split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not imported & {"socket", "subprocess", "ctypes", "http", "urllib", "ssl", "asyncio", "multiprocessing",
                           "os", "pathlib", "time"}


# --------------------------------------------------------------------------- the transport payload
def test_the_payload_is_the_bytes_after_the_transport_header():
    """``payload`` is what the packet capture hands to tnt.sipcalls; it is never a copy of the whole frame."""
    body = b"hello there"
    row = summarize(eth(ipv4(udp(payload=body), protocol=17)))
    assert row["payload"] == body
    assert summarize(eth(ipv4(tcp())))["payload"] == b""       # a TCP header with nothing after it
    assert summarize(eth(ipv4(icmp_echo(), protocol=1)))["payload"] == b""   # ICMP is not a transport TNT slices
    assert summarize(b"")["payload"] == b""
    assert summarize(b"\x01\x02\x03")["payload"] == b""
