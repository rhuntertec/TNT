"""tnt.lldp: LLDP / CDP frame selection and TLV decoding for the switch-port lookup.

Every frame is built here from the IEEE 802.1AB, IEEE 802.3 clause 79, ANSI/TIA-1057 and CDP field layouts, with the
stand-in switch (LAB-SW-01, "Example Switch 8P", Port 7), MACs 02:00:5e:10:00:0x and addresses from 192.0.2.0/24 and
2001:db8::/32. Nothing here touches a network or runs a program.
"""
from __future__ import annotations

import ast
import ipaddress
import struct
from pathlib import Path

import pytest

from tnt import lldp, pcapng
from tnt.lldp import (MAU_TEXT, MAX_MANAGEMENT_IPS, MAX_TEXT, NEIGHBOR_KEYS, classify_frame, neighbors_from_packets,
                      parse_cdp, parse_lldp)

ADAPTER_MAC = "02:00:5e:10:00:01"            # this PC's wired adapter, as netinfo would name it (any case)
ADAPTER = bytes.fromhex("02005e100001")
SWITCH = bytes.fromhex("02005e100002")       # the switch's chassis MAC
SWITCH_PORT = bytes.fromhex("02005e100003")  # the switch port's own MAC (LLDP source address)
OTHER_SWITCH = bytes.fromhex("02005e100004")
LLDP_DST = bytes.fromhex("0180c200000e")
CDP_DST = bytes.fromhex("01000ccccccc")
MGMT_V4 = ipaddress.IPv4Address("192.0.2.2")
MGMT_V6 = ipaddress.IPv6Address("2001:db8::2")
QTAG = struct.pack(">HH", 0x8100, 10)
STAG = struct.pack(">HH", 0x88A8, 100)


# --------------------------------------------------------------------------- builders
def tlv(tlv_type, value=b""):
    """An LLDP TLV: 7-bit type and 9-bit length in a big-endian u16, then the value."""
    return struct.pack(">H", (tlv_type << 9) | len(value)) + value


def org(oui, subtype, info=b""):
    return tlv(127, bytes.fromhex(oui) + bytes([subtype]) + info)


CHASSIS = tlv(1, b"\x04" + SWITCH)               # subtype 4: MAC address
PORT = tlv(2, b"\x05Port 7")                     # subtype 5: interface name


def lldpdu(*extra, chassis=CHASSIS, port=PORT, ttl=120):
    return chassis + port + tlv(3, struct.pack(">H", ttl)) + b"".join(extra) + tlv(0)


def capabilities(system, enabled):
    return tlv(7, struct.pack(">HH", system, enabled))


def mgmt(family, address, if_number=7):
    """Management address TLV: address string length, IANA family, address, ifIndex subtype and number, empty OID."""
    return tlv(8, bytes([1 + len(address), family]) + address + b"\x02" + struct.pack(">I", if_number) + b"\x00")


def pvid(vid):
    return org("0080c2", 1, struct.pack(">H", vid))


def network_policy(vid, *, app=1, unknown=False, tagged=True, priority=5, dscp=46):
    bits = (0x800000 if unknown else 0) | (0x400000 if tagged else 0) | (vid << 9) | (priority << 6) | dscp
    return org("0012bb", 2, bytes([app]) + bits.to_bytes(3, "big"))


def mac_phy(mau, status=0x03, advertised=0x6C01):
    return org("00120f", 1, bytes([status]) + struct.pack(">HH", advertised, mau))


def power_via_mdi(class_octet, allocated=None):
    """IEEE 802.3 Power via MDI: support, pair, class; with *allocated* also type/source/priority, requested and
    allocated power (0.1 W), making a 12-octet value."""
    info = bytes([0x0F, 0x01, class_octet])
    if allocated is not None:
        info += bytes([0x51]) + struct.pack(">HH", allocated, allocated)
    return org("00120f", 2, info)


def med_power(tenths):
    return org("0012bb", 4, bytes([0x51]) + struct.pack(">H", tenths))


def ethernet(payload, *, src=SWITCH_PORT, dst=LLDP_DST, ethertype=0x88CC, tags=b""):
    return dst + src + tags + struct.pack(">H", ethertype) + payload


def cdp_tlv(tlv_type, value):
    return struct.pack(">HH", tlv_type, len(value) + 4) + value


def cdp_packet(*tlvs, ttl=180):
    return bytes([2, ttl]) + b"\x12\x34" + b"".join(tlvs)


def cdp_address(proto_type, proto, address):
    return bytes([proto_type, len(proto)]) + proto + struct.pack(">H", len(address)) + address


def cdp_addresses(*entries):
    return struct.pack(">I", len(entries)) + b"".join(entries)


V4_ENTRY = cdp_address(1, b"\xcc", MGMT_V4.packed)
V6_ENTRY = cdp_address(2, bytes.fromhex("aaaa0300000086dd"), MGMT_V6.packed)


def cdp_frame(packet, *, src=SWITCH_PORT, dst=CDP_DST, pid=0x2000, tags=b"", trailer=b""):
    """An 802.3 frame: length, LLC AA AA 03, Cisco OUI, protocol id, packet; *trailer* sits after the 802.3 length."""
    llc = bytes.fromhex("aaaa0300000c") + struct.pack(">H", pid) + packet
    return dst + src + tags + struct.pack(">H", len(llc)) + llc + trailer


def pcapng_file(*frames):
    """A little-endian pcapng file: SHB, one Ethernet IDB and one EPB per frame."""
    def block(block_type, body):
        length = len(body) + 12
        return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)

    data = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + block(1, struct.pack("<HHI", 1, 0, 0))
    for index, frame in enumerate(frames):
        fixed = struct.pack("<IIIII", 0, 0, index, len(frame), len(frame))
        data += block(6, fixed + frame + bytes(-len(frame) % 4))
    return data


# --------------------------------------------------------------------------- LLDP
def test_full_lldpdu_decodes_every_field_in_key_order():
    payload = lldpdu(
        tlv(4, b"Uplink to office"), tlv(5, b"LAB-SW-01"), tlv(6, b"Example Switch 8P"),
        capabilities(0x0014, 0x0004), mgmt(1, MGMT_V4.packed), pvid(10), network_policy(20),
        mac_phy(30), power_via_mdi(5, allocated=0x00F0))
    neighbor = parse_lldp(payload)
    assert tuple(neighbor) == NEIGHBOR_KEYS
    assert neighbor == {
        "protocol": "lldp", "switch_name": "LAB-SW-01", "switch_description": "Example Switch 8P", "vendor": None,
        "chassis_id": "02:00:5E:10:00:02", "port_id": "Port 7", "port_description": "Uplink to office",
        "vlan": 10, "voice_vlan": 20, "management_ips": ["192.0.2.2"], "capabilities": ["bridge"],
        "poe": {"class": 4, "allocated_w": 24.0}, "link": {"autoneg": True, "mau": 30, "text": "1000BASE-T full"},
        "ttl_s": 120}
    assert [neighbor] == neighbors_from_packets([ethernet(payload)])


def test_minimal_lldpdu_uses_the_chassis_id_as_the_switch_name():
    assert parse_lldp(lldpdu()) == {
        "protocol": "lldp", "switch_name": "02:00:5E:10:00:02", "switch_description": None, "vendor": None,
        "chassis_id": "02:00:5E:10:00:02", "port_id": "Port 7", "port_description": None, "vlan": None,
        "voice_vlan": None, "management_ips": [], "capabilities": [], "poe": None, "link": None, "ttl_s": 120}


@pytest.mark.parametrize("value, expected", [
    (b"\x04" + SWITCH, "02:00:5E:10:00:02"),
    (b"\x05\x01" + MGMT_V4.packed, "192.0.2.2"),
    (b"\x05\x02" + MGMT_V6.packed, "2001:db8::2"),
    (b"\x07LAB-SW-01", "LAB-SW-01"),                     # locally assigned: text
    (b"\x01\x00\x01\xff\x10", "0001ff10"),               # chassis component that is not printable: hex
    (b"\x04" + SWITCH[:5], "02005e1000"),                # a "MAC" of 5 bytes: hex
    (b"\x05\x03" + bytes(4), "0300000000"),              # an unknown address family: hex
], ids=["mac", "ipv4", "ipv6", "text", "not_printable", "short_mac", "unknown_family"])
def test_chassis_id_subtypes(value, expected):
    neighbor = parse_lldp(lldpdu(chassis=tlv(1, value)))
    assert neighbor["chassis_id"] == expected
    assert neighbor["switch_name"] == expected


@pytest.mark.parametrize("value, expected", [
    (b"\x03" + SWITCH_PORT, "02:00:5E:10:00:03"),
    (b"\x04\x01" + ipaddress.IPv4Address("192.0.2.3").packed, "192.0.2.3"),
    (b"\x04\x02" + MGMT_V6.packed, "2001:db8::2"),
    (b"\x05Port 7", "Port 7"),
    (b"\x07" + b"7", "7"),
    (b"\x01Port 7\x00", "Port 7"),
], ids=["mac", "ipv4", "ipv6", "interface_name", "locally_assigned", "alias_with_nul"])
def test_port_id_subtypes(value, expected):
    assert parse_lldp(lldpdu(port=tlv(2, value)))["port_id"] == expected


def test_strings_drop_control_characters_replace_bad_utf8_and_are_capped():
    neighbor = parse_lldp(lldpdu(
        tlv(4, b"\x00Uplink\r\n"), tlv(5, b"LAB-\xffSW\x07-01"),
        tlv(6, ("Example " + chr(0x202E) + "Switch 8P").encode())))      # a right-to-left override
    assert neighbor["port_description"] == "Uplink"
    assert neighbor["switch_name"] == "LAB-" + chr(0xFFFD) + "SW-01"  # bad byte replaced, BEL removed
    assert neighbor["switch_description"] == "Example Switch 8P"
    assert parse_lldp(lldpdu(tlv(5, b"x" * 300)))["switch_name"] == "x" * MAX_TEXT
    assert parse_lldp(lldpdu(tlv(5, b"\x00\x00")))["switch_name"] == "02:00:5E:10:00:02"


@pytest.mark.parametrize("payload", [
    b"",
    CHASSIS + PORT + tlv(0),                                     # no TTL
    PORT + CHASSIS + tlv(3, b"\x00\x78") + tlv(0),               # mandatory TLVs out of order
    tlv(1, b"\x04") + PORT + tlv(3, b"\x00\x78") + tlv(0),       # a chassis id TLV without an id
    CHASSIS + PORT + tlv(3, b"\x78") + tlv(0),                   # a one-byte TTL
    lldpdu(tlv(5, b"LAB-SW-01"), ttl=0),                         # shutdown LLDPDU
], ids=["empty", "no_ttl", "out_of_order", "empty_chassis_id", "short_ttl", "ttl_0"])
def test_lldpdu_without_valid_mandatory_tlvs_or_with_ttl_0_is_ignored(payload):
    assert parse_lldp(payload) is None
    assert neighbors_from_packets([ethernet(payload)]) == []


def test_a_tlv_running_past_the_data_ends_the_walk():
    payload = lldpdu()[:-2] + tlv(5, b"LAB-SW-01") + struct.pack(">H", (6 << 9) | 100) + b"short"
    neighbor = parse_lldp(payload)
    assert neighbor["switch_name"] == "LAB-SW-01"
    assert neighbor["switch_description"] is None


@pytest.mark.parametrize("system, enabled, expected", [
    (0x0014, 0x0004, ["bridge"]),
    (0x0014, 0x0014, ["bridge", "router"]),
    (0x00A4, 0x0000, ["bridge", "phone", "station"]),        # nothing enabled: the system bits
    (0x00BE, 0x00BE, ["repeater", "bridge", "wlan-ap", "router", "phone", "station"]),
    (0x0741, 0x0741, []),                                     # other, DOCSIS, C-VLAN, S-VLAN, TPMR: no names
])
def test_system_capabilities(system, enabled, expected):
    assert parse_lldp(lldpdu(capabilities(system, enabled)))["capabilities"] == expected


def test_management_addresses_are_ipv4_or_ipv6_and_at_most_four():
    extra = [mgmt(1, MGMT_V4.packed), mgmt(6, SWITCH), mgmt(2, MGMT_V6.packed), mgmt(1, MGMT_V4.packed)]
    extra += [mgmt(1, ipaddress.IPv4Address(f"192.0.2.{n}").packed) for n in (3, 4, 5, 6)]
    neighbor = parse_lldp(lldpdu(*extra))
    assert MAX_MANAGEMENT_IPS == 4
    assert neighbor["management_ips"] == ["192.0.2.2", "2001:db8::2", "192.0.2.3", "192.0.2.4"]


@pytest.mark.parametrize("vid, expected", [(10, 10), (1, 1), (0, None)], ids=["pvid_10", "pvid_1", "pvid_0"])
def test_port_vlan_id(vid, expected):
    assert parse_lldp(lldpdu(pvid(vid)))["vlan"] == expected


@pytest.mark.parametrize("policy, expected", [
    (network_policy(20), 20),
    (network_policy(1), 1),
    (network_policy(4094), 4094),
    (network_policy(20, tagged=False), None),       # untagged: the phone stays on the port VLAN
    (network_policy(20, unknown=True), None),       # the switch does not know the policy
    (network_policy(0), None),
    (network_policy(4095), None),
    (network_policy(30, app=2), None),              # voice signalling, not voice
], ids=["tagged_20", "vid_1", "vid_4094", "untagged", "unknown", "vid_0", "vid_4095", "voice_signalling"])
def test_med_network_policy_voice_vlan(policy, expected):
    assert parse_lldp(lldpdu(policy))["voice_vlan"] == expected


def test_voice_vlan_comes_from_the_voice_application_policy():
    assert parse_lldp(lldpdu(network_policy(30, app=2), network_policy(20)))["voice_vlan"] == 20


@pytest.mark.parametrize("status, mau, expected", [
    (0x03, 16, {"autoneg": True, "mau": 16, "text": "100BASE-TX full"}),
    (0x03, 30, {"autoneg": True, "mau": 30, "text": "1000BASE-T full"}),
    (0x01, 30, {"autoneg": False, "mau": 30, "text": "1000BASE-T full"}),     # supported, not enabled
    (0x02, 0, {"autoneg": True, "mau": 0, "text": None}),                     # MAU type 0: unknown
    (0x00, 999, {"autoneg": False, "mau": 999, "text": None}),
], ids=["100base_tx", "1000base_t", "autoneg_off", "mau_unknown", "mau_unlisted"])
def test_mac_phy_link(status, mau, expected):
    assert parse_lldp(lldpdu(mac_phy(mau, status=status)))["link"] == expected


def test_mau_text_names_confirmed_types_only():
    assert MAU_TEXT[16] == "100BASE-TX full"
    assert MAU_TEXT[30] == "1000BASE-T full"
    assert 0 not in MAU_TEXT


@pytest.mark.parametrize("tlvs, expected", [
    ([power_via_mdi(5)], {"class": 4, "allocated_w": None}),
    ([power_via_mdi(1)], {"class": 0, "allocated_w": None}),
    ([power_via_mdi(0)], None),
    ([power_via_mdi(6)], None),
    ([power_via_mdi(5, allocated=0x00F0)], {"class": 4, "allocated_w": 24.0}),
    ([power_via_mdi(0, allocated=0x00F0)], {"class": None, "allocated_w": 24.0}),
    ([med_power(0x00F0)], {"class": None, "allocated_w": 24.0}),
    ([power_via_mdi(4), med_power(130)], {"class": 3, "allocated_w": 13.0}),
    ([med_power(130), power_via_mdi(5, allocated=0x00F0)], {"class": 4, "allocated_w": 24.0}),
    ([], None),
], ids=["class_4", "class_0", "octet_0", "octet_6", "allocated_24w", "allocated_without_class", "med_only",
        "med_fallback", "dot3_before_med", "no_power_tlvs"])
def test_poe_class_and_allocated_power(tlvs, expected):
    assert parse_lldp(lldpdu(*tlvs))["poe"] == expected


# --------------------------------------------------------------------------- CDP
def test_cdp_tlvs():
    packet = cdp_packet(
        cdp_tlv(0x0001, b"LAB-SW-01"),
        cdp_tlv(0x0002, cdp_addresses(V4_ENTRY)),
        cdp_tlv(0x0003, b"Port 7"),
        cdp_tlv(0x0004, struct.pack(">I", 0x28)),            # switch + IGMP (no name)
        cdp_tlv(0x0005, b"ExampleOS 1.0"),                   # software version: not used
        cdp_tlv(0x0006, b"Example Switch 8P"),
        cdp_tlv(0x000A, struct.pack(">H", 10)),
        cdp_tlv(0x000E, b"\x01" + struct.pack(">H", 20)),
        cdp_tlv(0x0010, struct.pack(">H", 6300)),            # the sender's own power draw: ignored
        cdp_tlv(0x0016, cdp_addresses(V4_ENTRY, V6_ENTRY)),
        cdp_tlv(0x001A, struct.pack(">HHII", 1, 1, 15400, 30000)))
    neighbor = parse_cdp(packet)
    assert tuple(neighbor) == NEIGHBOR_KEYS
    assert neighbor == {
        "protocol": "cdp", "switch_name": "LAB-SW-01", "switch_description": "Example Switch 8P", "vendor": None,
        "chassis_id": "LAB-SW-01", "port_id": "Port 7", "port_description": None, "vlan": 10, "voice_vlan": 20,
        "management_ips": ["192.0.2.2", "2001:db8::2"], "capabilities": ["switch"],
        "poe": {"class": None, "allocated_w": 15.4}, "link": None, "ttl_s": 180}
    assert classify_frame(cdp_frame(packet)) == "cdp"
    assert neighbors_from_packets([cdp_frame(packet)]) == [neighbor]


def test_cdp_power_tlv_0x0010_alone_gives_no_poe():
    assert parse_cdp(cdp_packet(cdp_tlv(1, b"LAB-SW-01"), cdp_tlv(0x0010, struct.pack(">H", 6300))))["poe"] is None


@pytest.mark.parametrize("bits, expected", [
    (0x01, ["router"]), (0x02, ["bridge"]), (0x04, ["bridge"]), (0x06, ["bridge"]), (0x08, ["switch"]),
    (0x10, ["host"]), (0x40, ["repeater"]), (0x80, ["phone"]), (0x120, []),
    (0xDF, ["router", "bridge", "switch", "host", "repeater", "phone"]),
])
def test_cdp_capability_bits(bits, expected):
    packet = cdp_packet(cdp_tlv(1, b"LAB-SW-01"), cdp_tlv(4, struct.pack(">I", bits)))
    assert parse_cdp(packet)["capabilities"] == expected


def test_cdp_vlan_0_is_none():
    packet = cdp_packet(cdp_tlv(1, b"LAB-SW-01"), cdp_tlv(0x000A, b"\x00\x00"), cdp_tlv(0x000E, b"\x01\x00\x00"))
    neighbor = parse_cdp(packet)
    assert (neighbor["vlan"], neighbor["voice_vlan"]) == (None, None)


def test_cdp_needs_a_header_and_a_device_or_port():
    assert parse_cdp(b"\x02\xb4\x00") is None
    assert parse_cdp(cdp_packet(cdp_tlv(6, b"Example Switch 8P"))) is None
    neighbor = parse_cdp(cdp_packet(cdp_tlv(3, b"Port 7")))
    assert (neighbor["switch_name"], neighbor["chassis_id"], neighbor["port_id"]) == (None, None, "Port 7")
    # a TLV that runs past the data ends the walk; the TLVs before it still count
    neighbor = parse_cdp(cdp_packet(cdp_tlv(1, b"LAB-SW-01")) + struct.pack(">HH", 3, 50) + b"Port")
    assert (neighbor["switch_name"], neighbor["port_id"]) == ("LAB-SW-01", None)


def test_cdp_ignores_bytes_after_the_802_3_length():
    frame = cdp_frame(cdp_packet(cdp_tlv(3, b"Port 7")), trailer=cdp_tlv(1, b"padding"))
    [neighbor] = neighbors_from_packets([frame])
    assert (neighbor["switch_name"], neighbor["port_id"]) == (None, "Port 7")


# --------------------------------------------------------------------------- frames and packets
@pytest.mark.parametrize("frame, expected", [
    (ethernet(lldpdu()), "lldp"),
    (ethernet(lldpdu(), tags=QTAG), "lldp"),
    (ethernet(lldpdu(), tags=STAG + QTAG), "lldp"),
    (cdp_frame(cdp_packet(cdp_tlv(1, b"LAB-SW-01"))), "cdp"),
    (cdp_frame(cdp_packet(cdp_tlv(1, b"LAB-SW-01")), tags=QTAG), "cdp"),
    (cdp_frame(bytes(40), pid=0x2003), None),                                 # VTP
    (cdp_frame(bytes(40), pid=0x2004), None),                                 # DTP
    (cdp_frame(bytes(40), pid=0x0104), None),                                 # PAgP
    (cdp_frame(bytes(40), pid=0x0111), None),                                 # UDLD
    (cdp_frame(cdp_packet(cdp_tlv(1, b"LAB-SW-01")), dst=LLDP_DST), None),    # not the CDP address
    (ethernet(bytes.fromhex("aaaa0300000c2000") + cdp_packet(), dst=CDP_DST, ethertype=0x0800), None),
    (ethernet(bytes(46), dst=ADAPTER, ethertype=0x0800), None),
    (ethernet(lldpdu())[:13], None),
], ids=["lldp", "lldp_vlan_tag", "lldp_qinq", "cdp", "cdp_vlan_tag", "vtp", "dtp", "pagp", "udld", "cdp_wrong_dst",
        "ethernet_ii_to_cdp_address", "ipv4", "short"])
def test_classify_frame(frame, expected):
    assert classify_frame(frame) == expected


@pytest.mark.parametrize("own_mac", ["02:00:5e:10:00:01", "02-00-5E-10-00-01", "02:00:5E:10:00:01"])
def test_classify_frame_ignores_frames_sent_by_this_adapter(own_mac):
    assert classify_frame(ethernet(lldpdu(), src=ADAPTER), own_mac=own_mac) is None
    assert classify_frame(cdp_frame(cdp_packet(cdp_tlv(1, b"PC-01")), src=ADAPTER), own_mac=own_mac) is None
    assert classify_frame(ethernet(lldpdu(), src=SWITCH_PORT), own_mac=own_mac) == "lldp"


def test_classify_frame_without_a_usable_own_mac_filters_nothing():
    frame = ethernet(lldpdu(), src=ADAPTER)
    assert classify_frame(frame, own_mac=None) == "lldp"
    assert classify_frame(frame, own_mac="") == "lldp"
    assert classify_frame(frame, own_mac="not a mac") == "lldp"


def test_own_lldp_frame_in_a_capture_is_not_a_neighbor():
    # Windows' LLDP agent advertises the adapter itself; Packet Monitor captures it with the switch's frames
    own = ethernet(lldpdu(tlv(5, b"PC-01"), chassis=tlv(1, b"\x04" + ADAPTER), port=tlv(2, b"\x03" + ADAPTER)),
                   src=ADAPTER)                                    # from 02:00:5e:10:00:01, the adapter
    switch_payload = lldpdu(tlv(5, b"LAB-SW-01"))
    switch = ethernet(switch_payload, src=SWITCH)                  # then one from 02:00:5e:10:00:02
    packets = pcapng.read_packets(pcapng_file(own, switch))
    neighbors = neighbors_from_packets(packets, own_mac=ADAPTER_MAC)
    assert neighbors == [parse_lldp(switch_payload)]               # exactly one neighbour: the second
    assert (neighbors[0]["switch_name"], neighbors[0]["port_id"]) == ("LAB-SW-01", "Port 7")
    assert neighbors_from_packets(packets, own_mac="02-00-5E-10-00-01") == neighbors
    assert len(neighbors_from_packets(packets)) == 2


def test_neighbors_are_deduplicated_in_first_heard_order_with_the_latest_values():
    first = ethernet(lldpdu(tlv(5, b"LAB-SW-01"), ttl=120))
    other = ethernet(lldpdu(tlv(5, b"LAB-SW-02"), chassis=tlv(1, b"\x04" + OTHER_SWITCH)), src=OTHER_SWITCH)
    again = ethernet(lldpdu(tlv(5, b"LAB-SW-01"), tlv(4, b"Uplink"), ttl=110))
    other_port = ethernet(lldpdu(tlv(5, b"LAB-SW-01"), port=tlv(2, b"\x05Port 8")))
    cdp = cdp_frame(cdp_packet(cdp_tlv(1, b"LAB-SW-01"), cdp_tlv(3, b"Port 7")))
    result = neighbors_from_packets([first, other, again, other_port, cdp])
    assert [(n["protocol"], n["switch_name"], n["port_id"], n["ttl_s"]) for n in result] == [
        ("lldp", "LAB-SW-01", "Port 7", 110), ("lldp", "LAB-SW-02", "Port 7", 120),
        ("lldp", "LAB-SW-01", "Port 8", 120), ("cdp", "LAB-SW-01", "Port 7", 180)]
    assert result[0]["port_description"] == "Uplink"


def test_neighbors_skip_other_link_types_and_things_that_are_not_frames():
    frame = ethernet(lldpdu(tlv(5, b"LAB-SW-01")))
    packets = [{"linktype": 105, "data": frame}, {"linktype": 1, "data": None}, "not a frame", 42,
               {"linktype": 1, "data": ethernet(b"\x00\x00")}, bytearray(frame)]
    assert [n["switch_name"] for n in neighbors_from_packets(packets)] == ["LAB-SW-01"]


def test_module_opens_no_socket_and_runs_no_program():
    """tnt.lldp has no I/O seam for tests/conftest.py to guard: it only decodes the bytes it is given."""
    tree = ast.parse(Path(lldp.__file__).read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {(node.module or "").split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not imported & {"socket", "subprocess", "ctypes", "http", "urllib", "ssl", "asyncio", "multiprocessing"}
