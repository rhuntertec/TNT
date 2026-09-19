"""tnt.pcapng: block validation, packet reading and counting, and the Wi-Fi rewrite (802.11 data frames -> Ethernet II).

Every file and frame is built here from the pcapng and IEEE 802.11 field layouts, with MACs 02:00:5e:10:00:0x and
addresses from 192.0.2.0/24. Nothing here touches a network or runs a program.
"""
from __future__ import annotations

import ast
import io
import struct
from pathlib import Path

import pytest

from tnt import pcapng
from tnt.pcapng import (KNOWN_ETHERTYPES, MAX_BLOCK, MAX_IN_MEMORY, PACKET_KEYS, REWRITE_KEYS, PcapngError,
                        count_packets, dot11_to_ethernet, iter_blocks, iter_packets, read_packets,
                        rewrite_dot11_to_ethernet)

STA = bytes.fromhex("02005e100001")        # this PC (the Wi-Fi station)
AP = bytes.fromhex("02005e100002")         # the access point (BSSID)
HOST = bytes.fromhex("02005e100003")       # a wired host behind the access point
PEER = bytes.fromhex("02005e100004")       # Address 4 of a WDS frame
SNAP = b"\xaa\xaa\x03\x00\x00\x00"
BRIDGE_TUNNEL = b"\xaa\xaa\x03\x00\x00\xf8"
ETH_IPV4 = b"\x08\x00"
ETH_ARP = b"\x08\x06"
# an IPv4 + UDP header, 192.0.2.10 -> 192.0.2.1 (nothing here checks checksums)
IP_PACKET = (bytes([0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 10, 192, 0, 2, 1])
             + struct.pack(">HHHH", 50000, 53, 8, 0))
ARP_BODY = (struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + STA + bytes([192, 0, 2, 10]) + bytes(6)
            + bytes([192, 0, 2, 1]))
PAYLOAD = SNAP + ETH_IPV4 + IP_PACKET      # an 802.11 data frame body: SNAP, ethertype, IPv4
ETHERNET_BODY = ETH_IPV4 + IP_PACKET
ETH_FRAME = AP + STA + ETHERNET_BODY       # an Ethernet II frame (no FCS)
TS = 1_700_000_000_123_456                 # microseconds since 1970


# --------------------------------------------------------------------------- builders
def dot11(body=b"", *, to_ds=False, from_ds=False, subtype=0, order=False, qos=0, a1=AP, a2=STA, a3=HOST, a4=PEER,
          frame_type=2, version=0):
    """An 802.11 frame: frame control (Protected bit set, as Packet Monitor delivers them), duration, Address 1-3,
    sequence control, Address 4 (ToDS + FromDS), QoS Control (QoS data) and HT Control (QoS + Order)."""
    fc0 = (subtype << 4) | (frame_type << 2) | version
    fc1 = (0x01 if to_ds else 0) | (0x02 if from_ds else 0) | 0x40 | (0x80 if order else 0)
    header = bytes([fc0, fc1]) + b"\x00\x00" + a1 + a2 + a3 + b"\x10\x00"
    if to_ds and from_ds:
        header += a4
    if frame_type == 2 and subtype & 0x08:
        header += struct.pack("<H", qos)
        if order:
            header += b"\x00\x00\x00\x00"
    return header + body


def subframe(da, sa, msdu, *, pad=True):
    """One A-MSDU subframe: DA, SA, big-endian length, MSDU, padded to 4 bytes unless it is the last."""
    sub = da + sa + struct.pack(">H", len(msdu)) + msdu
    return sub + bytes(-len(sub) % 4 if pad else 0)


def block(block_type, body, endian="<"):
    length = len(body) + 12
    return struct.pack(endian + "II", block_type, length) + body + struct.pack(endian + "I", length)


def opt(code, value, endian="<"):
    return struct.pack(endian + "HH", code, len(value)) + value + bytes(-len(value) % 4)


def opts(*items, endian="<"):
    return b"".join(items) + struct.pack(endian + "HH", 0, 0)


def shb(endian="<", options=b"", magic=0x1A2B3C4D):
    return block(0x0A0D0D0A, struct.pack(endian + "IHHq", magic, 1, 0, -1) + options, endian)


def idb(linktype=1, snaplen=0, endian="<", options=b""):
    return block(1, struct.pack(endian + "HHI", linktype, 0, snaplen) + options, endian)


def epb(data, interface=0, ts=0, origlen=None, endian="<", options=b""):
    fixed = struct.pack(endian + "IIIII", interface, ts >> 32, ts & 0xFFFFFFFF, len(data),
                        len(data) if origlen is None else origlen)
    return block(6, fixed + data + bytes(-len(data) % 4) + options, endian)


def spb(data, origlen=None, endian="<"):
    fixed = struct.pack(endian + "I", len(data) if origlen is None else origlen)
    return block(3, fixed + data + bytes(-len(data) % 4), endian)


def pb(data, interface=0, ts=0, endian="<"):
    fixed = struct.pack(endian + "HHIIII", interface, 0, ts >> 32, ts & 0xFFFFFFFF, len(data), len(data))
    return block(2, fixed + data + bytes(-len(data) % 4), endian)


def nrb(endian="<"):
    record = struct.pack(endian + "HH", 1, 7) + bytes([192, 0, 2, 1]) + b"gw\x00" + b"\x00"
    return block(4, record + struct.pack(endian + "HH", 0, 0), endian)


def isb(endian="<"):
    return block(5, struct.pack(endian + "III", 0, 0, 0), endian)


def _pad4(size):
    return (size + 3) & ~3


# --------------------------------------------------------------------------- dot11_to_ethernet
@pytest.mark.parametrize("to_ds, from_ds, addresses, da, sa", [
    (False, False, (HOST, STA, AP), HOST, STA),        # DA a1, SA a2
    (True, False, (AP, STA, HOST), HOST, STA),         # DA a3, SA a2
    (False, True, (STA, AP, HOST), STA, HOST),         # DA a1, SA a3
    (True, True, (AP, STA, HOST), HOST, PEER),         # WDS: DA a3, SA a4
], ids=["plain", "to_ds", "from_ds", "wds"])
def test_data_frame_addresses_follow_the_ds_bits(to_ds, from_ds, addresses, da, sa):
    a1, a2, a3 = addresses
    frame = dot11(PAYLOAD, to_ds=to_ds, from_ds=from_ds, a1=a1, a2=a2, a3=a3)
    assert len(frame) == (30 if to_ds and from_ds else 24) + len(PAYLOAD)
    converted, origlen = dot11_to_ethernet(frame, len(frame))
    assert converted == da + sa + ETHERNET_BODY
    assert origlen == len(converted) == 12 + len(ETHERNET_BODY)


@pytest.mark.parametrize("subtype, order, header_len", [
    (8, False, 26),        # QoS data: + QoS Control
    (8, True, 30),         # QoS data with the Order bit: + HT Control
    (0, True, 24),         # the Order bit on a non-QoS frame adds nothing
], ids=["qos", "qos_htc", "order_without_qos"])
def test_qos_control_and_ht_control_lengthen_the_header(subtype, order, header_len):
    frame = dot11(PAYLOAD, from_ds=True, subtype=subtype, order=order, qos=0x0005, a1=STA, a2=AP, a3=HOST)
    assert len(frame) == header_len + len(PAYLOAD)
    converted, origlen = dot11_to_ethernet(frame, len(frame))
    assert converted == STA + HOST + ETHERNET_BODY
    assert origlen == len(converted)


def test_plain_frame_origlen_counts_the_bytes_that_were_not_captured():
    frame = dot11(PAYLOAD, from_ds=True, subtype=8, a1=STA, a2=AP, a3=HOST)       # header 26, SNAP ends at 32
    on_air = len(frame) + 100
    converted, origlen = dot11_to_ethernet(frame[:40], on_air)
    assert converted == STA + HOST + frame[32:40]
    assert origlen == on_air - 32 + 12
    converted, origlen = dot11_to_ethernet(frame, 10)       # a nonsense origlen never goes under the frame length
    assert origlen == len(converted)


def test_bridge_tunnel_snap_converts():
    frame = dot11(BRIDGE_TUNNEL + ETH_ARP + ARP_BODY, to_ds=True, a1=AP, a2=STA, a3=HOST)
    converted, origlen = dot11_to_ethernet(frame, len(frame))
    assert converted == HOST + STA + ETH_ARP + ARP_BODY
    assert origlen == len(converted)


def test_amsdu_bit_with_snap_at_the_header_end_converts_as_a_plain_frame():
    # drivers keep the A-MSDU bit on frames they have already de-aggregated: that is no reason to drop them
    frame = dot11(PAYLOAD, from_ds=True, subtype=8, qos=0x0080, a1=STA, a2=AP, a3=HOST)
    converted, origlen = dot11_to_ethernet(frame, len(frame))
    assert converted == STA + HOST + ETHERNET_BODY
    assert origlen == len(converted)


def test_two_subframe_amsdu_keeps_only_the_first_subframe():
    first = SNAP + ETH_IPV4 + IP_PACKET                     # n = 36, padded
    second = SNAP + ETH_ARP + ARP_BODY + bytes(12)          # n = 48
    body = subframe(STA, HOST, first) + subframe(STA, PEER, second, pad=False)
    frame = dot11(body, from_ds=True, subtype=8, qos=0x0080, a1=STA, a2=AP, a3=AP)
    converted, origlen = dot11_to_ethernet(frame, len(frame))
    assert converted == STA + HOST + ETH_IPV4 + IP_PACKET
    assert len(converted) == origlen == len(first) + 6


def test_amsdu_origlen_when_the_capture_or_the_frame_is_short():
    first = SNAP + ETH_IPV4 + IP_PACKET
    body = subframe(STA, HOST, first) + subframe(STA, PEER, SNAP + ETH_ARP + ARP_BODY, pad=False)
    frame = dot11(body, from_ds=True, subtype=8, qos=0x0080, a1=STA, a2=AP, a3=AP)
    hl = 26
    # part of the first subframe captured, the whole A-MSDU on the air: the subframe's own Ethernet length
    converted, origlen = dot11_to_ethernet(frame[:hl + 30], len(frame))
    assert converted == STA + HOST + frame[hl + 20:hl + 30]
    assert origlen == len(first) + 6
    # the frame on the air ended inside the first subframe: what followed the subframe header, plus DA and SA
    short = hl + 40
    converted, origlen = dot11_to_ethernet(frame[:short], short)
    assert converted == STA + HOST + frame[hl + 20:short]
    assert origlen == short - (hl + 20) + 12 == len(converted)


def test_amsdu_conversion_fails_without_a_usable_first_subframe():
    too_short = STA + HOST + struct.pack(">H", 7) + SNAP + ETH_IPV4 + IP_PACKET
    frame = dot11(too_short, from_ds=True, subtype=8, qos=0x0080, a1=STA, a2=AP, a3=HOST)
    assert dot11_to_ethernet(frame, len(frame)) is None
    no_snap = STA + HOST + struct.pack(">H", 36) + bytes(36)
    frame = dot11(no_snap, from_ds=True, subtype=8, qos=0x0080, a1=STA, a2=AP, a3=HOST)
    assert dot11_to_ethernet(frame, len(frame)) is None
    without_the_bit = dot11(subframe(STA, HOST, PAYLOAD), from_ds=True, subtype=8, qos=0x0000, a1=STA, a2=AP, a3=HOST)
    assert dot11_to_ethernet(without_the_bit, len(without_the_bit)) is None


@pytest.mark.parametrize("subtype", [4, 12], ids=["null_function", "qos_null"])
def test_frames_without_a_payload_are_not_converted(subtype):
    frame = dot11(PAYLOAD, to_ds=True, subtype=subtype)
    assert dot11_to_ethernet(frame, len(frame)) is None


def test_non_data_and_unknown_version_frames_are_not_converted():
    beacon = dot11(PAYLOAD, frame_type=0, subtype=8)
    assert dot11_to_ethernet(beacon, len(beacon)) is None
    version_1 = dot11(PAYLOAD, to_ds=True, version=1)
    assert dot11_to_ethernet(version_1, len(version_1)) is None


def test_truncated_frames_are_not_converted():
    frame = dot11(PAYLOAD, to_ds=True)
    assert dot11_to_ethernet(frame[:16], len(frame)) is None
    assert dot11_to_ethernet(dot11(SNAP + b"\x08", to_ds=True), 64) is None      # SNAP without an ethertype
    assert dot11_to_ethernet(dot11(PAYLOAD, subtype=8, qos=0x0080)[:25], 64) is None


def test_an_ethernet_frame_is_not_an_802_11_frame():
    assert dot11_to_ethernet(ETH_FRAME, len(ETH_FRAME)) is None


def test_802_11_frame_whose_address_2_reads_as_an_ethertype_is_converted_not_kept(tmp_path):
    a2 = bytes.fromhex("020008000002")        # locally administered; octets 2-3 are 08 00 on purpose
    frame = dot11(PAYLOAD, to_ds=True, a1=AP, a2=a2, a3=HOST)
    assert struct.unpack(">H", frame[12:14])[0] in KNOWN_ETHERTYPES
    converted, _ = dot11_to_ethernet(frame, len(frame))
    assert converted == HOST + a2 + ETHERNET_BODY
    src, dst = tmp_path / "raw.pcapng", tmp_path / "wifi.pcapng"
    src.write_bytes(shb() + idb() + epb(frame))
    assert rewrite_dot11_to_ethernet(src, dst) == {"converted": 1, "kept_ethernet": 0, "dropped": 0}
    assert [p["data"] for p in read_packets(dst.read_bytes())] == [converted]


# --------------------------------------------------------------------------- rewrite_dot11_to_ethernet
def test_rewrite_converts_keeps_drops_and_copies_every_other_block(tmp_path):
    data_frame = dot11(PAYLOAD, from_ds=True, subtype=8, a1=STA, a2=AP, a3=HOST)
    beacon = dot11(bytes(12), frame_type=0, subtype=8)          # bytes 12-13 are 5e 10: not an ethertype
    null = dot11(b"", to_ds=True, subtype=4)
    head = shb(options=opts(opt(4, b"TNT test"))) + idb(options=opts(opt(2, b"Wi-Fi"))) + nrb()
    tail = spb(ETH_FRAME) + isb()
    src, dst = tmp_path / "raw.pcapng", tmp_path / "wifi.pcapng"
    src.write_bytes(head + epb(data_frame, ts=TS) + epb(ETH_FRAME, ts=TS + 1) + epb(beacon) + epb(null) + tail)
    dst.write_bytes(b"an older file")

    stats = rewrite_dot11_to_ethernet(src, dst)

    assert stats == {"converted": 1, "kept_ethernet": 1, "dropped": 2}
    assert tuple(stats) == REWRITE_KEYS
    assert not Path(str(dst) + ".part").exists()
    out = dst.read_bytes()
    assert out.startswith(head) and out.endswith(tail)
    assert out[len(head):len(out) - len(tail)] == epb(STA + HOST + ETHERNET_BODY, ts=TS) + epb(ETH_FRAME, ts=TS + 1)
    packets = read_packets(out)
    assert [p["data"] for p in packets] == [STA + HOST + ETHERNET_BODY, ETH_FRAME, ETH_FRAME]
    assert packets[0]["ts"] == pytest.approx(TS / 1e6, abs=1e-6)
    assert count_packets(dst) == 3


@pytest.mark.parametrize("endian", ["<", ">"], ids=["little_endian", "big_endian"])
def test_rewrite_keeps_epb_options_and_recomputes_caplen_padding_and_lengths(tmp_path, endian):
    frame = dot11(PAYLOAD + b"\x01", to_ds=True, subtype=8, order=True, a1=AP, a2=STA, a3=HOST)    # header 30
    options = opts(opt(1, b"first frame", endian), opt(2, struct.pack(endian + "I", 1), endian), endian=endian)
    src, dst = tmp_path / "raw.pcapng", tmp_path / "wifi.pcapng"
    src.write_bytes(shb(endian) + idb(endian=endian)
                    + epb(frame, ts=TS, origlen=len(frame) + 4, endian=endian, options=options))

    assert rewrite_dot11_to_ethernet(src, dst)["converted"] == 1

    with open(dst, "rb") as f:
        blocks = list(iter_blocks(f))              # iter_blocks checks both block lengths
    assert [(e, t) for e, t, _ in blocks] == [(endian, 0x0A0D0D0A), (endian, 1), (endian, 6)]
    body = blocks[2][2]
    interface, ts_high, ts_low, caplen, origlen = struct.unpack_from(endian + "IIIII", body, 0)
    expected = HOST + STA + ETHERNET_BODY + b"\x01"
    assert (interface, (ts_high << 32) | ts_low, caplen) == (0, TS, len(expected))
    assert origlen == len(frame) + 4 - (30 + 6) + 12
    assert body[20:20 + caplen] == expected
    assert body[20 + caplen:20 + _pad4(caplen)] == bytes(_pad4(caplen) - caplen)
    assert body[20 + _pad4(caplen):] == options


def test_rewrite_failure_removes_the_part_file_and_leaves_the_destination(tmp_path):
    src, dst = tmp_path / "raw.pcapng", tmp_path / "wifi.pcapng"
    src.write_bytes(shb() + idb() + epb(dot11(PAYLOAD, to_ds=True)) + epb(ETH_FRAME)[:-8])
    dst.write_bytes(b"an older file")
    with pytest.raises(PcapngError, match="past the end"):
        rewrite_dot11_to_ethernet(src, dst)
    assert dst.read_bytes() == b"an older file"
    assert not Path(str(dst) + ".part").exists()


def test_rewrite_keeps_ethernet_frames_with_a_listed_ethertype_and_drops_the_rest(tmp_path):
    # the 802.3 passthrough: a frame that is not an 802.11 data frame stays only when bytes 12-13 are one of these
    listed = (0x0800, 0x86DD, 0x0806, 0x888E, 0x8100, 0x88A8, 0x88CC, 0x8892, 0x22F0)
    assert KNOWN_ETHERTYPES == frozenset(listed)
    kept = [AP + STA + struct.pack(">H", ethertype) + bytes(46) for ethertype in listed]
    others = [AP + STA + struct.pack(">H", 0x88B5) + bytes(46),                 # a local experimental ethertype
              AP + STA + struct.pack(">H", 38) + b"\x42\x42\x03" + bytes(35)]   # an 802.3 length and LLC (STP)
    assert all(dot11_to_ethernet(frame, len(frame)) is None for frame in kept + others)
    src, dst = tmp_path / "raw.pcapng", tmp_path / "wired.pcapng"
    src.write_bytes(shb() + idb() + b"".join(epb(frame) for frame in others[:1] + kept + others[1:]))
    assert rewrite_dot11_to_ethernet(src, dst) == {"converted": 0, "kept_ethernet": len(listed), "dropped": 2}
    assert [p["data"] for p in read_packets(dst.read_bytes())] == kept


# --------------------------------------------------------------------------- reading
@pytest.mark.parametrize("endian", ["<", ">"], ids=["little_endian", "big_endian"])
def test_reads_packets_in_either_byte_order(tmp_path, endian):
    data = shb(endian) + idb(endian=endian, snaplen=65535) + epb(ETH_FRAME, ts=TS, origlen=60, endian=endian)
    assert data[8:12] == (b"\x4d\x3c\x2b\x1a" if endian == "<" else b"\x1a\x2b\x3c\x4d")
    [packet] = read_packets(data)
    assert tuple(packet) == PACKET_KEYS
    assert (packet["interface"], packet["linktype"], packet["caplen"], packet["origlen"]) == (0, 1, len(ETH_FRAME), 60)
    assert packet["data"] == ETH_FRAME
    assert packet["ts"] == pytest.approx(1_700_000_000.123456, abs=1e-6)
    path = tmp_path / "one.pcapng"
    path.write_bytes(data)
    assert count_packets(path) == 1


def test_iter_blocks_yields_the_body_between_the_two_lengths():
    data = shb(">") + idb(endian=">") + epb(ETH_FRAME, endian=">")
    blocks = list(iter_blocks(io.BytesIO(data)))
    assert [(e, t) for e, t, _ in blocks] == [(">", 0x0A0D0D0A), (">", 1), (">", 6)]
    assert blocks[0][2][:4] == b"\x1a\x2b\x3c\x4d"
    assert blocks[2][2] == epb(ETH_FRAME, endian=">")[8:-4]


def test_each_section_has_its_own_byte_order_and_interface_table(tmp_path):
    first = shb("<") + idb(1) + idb(105) + epb(ETH_FRAME, interface=1)
    second = shb(">") + idb(1, endian=">") + epb(ETH_FRAME, interface=0, endian=">")
    assert [(p["interface"], p["linktype"]) for p in read_packets(first + second)] == [(1, 105), (0, 1)]
    path = tmp_path / "two.pcapng"
    path.write_bytes(first + second)
    assert count_packets(path) == 2
    # interface 1 was described only in the first section
    _all_readers_raise(tmp_path, first + shb(">") + idb(1, endian=">") + epb(ETH_FRAME, interface=1, endian=">"),
                       "interface 1")


def _all_readers_raise(tmp_path, data, match):
    with pytest.raises(PcapngError, match=match):
        read_packets(data)
    with pytest.raises(PcapngError, match=match):
        list(iter_packets(io.BytesIO(data)))
    path, out = tmp_path / "bad.pcapng", tmp_path / "bad-out.pcapng"
    path.write_bytes(data)
    with pytest.raises(PcapngError, match=match):
        count_packets(path)
    with pytest.raises(PcapngError, match=match):
        rewrite_dot11_to_ethernet(path, out)
    assert not out.exists() and not Path(str(out) + ".part").exists()


def _epb_claiming(caplen):
    body = struct.pack("<IIIII", 0, 0, 0, caplen, caplen) + ETH_FRAME + bytes(-len(ETH_FRAME) % 4)
    return block(6, body)


@pytest.mark.parametrize("data, match", [
    (shb() + idb() + epb(ETH_FRAME, interface=2), "interface 2"),
    (shb() + epb(ETH_FRAME), "interface 0"),
    (shb() + spb(ETH_FRAME), "interface 0"),
    (shb() + idb() + pb(ETH_FRAME, interface=1), "interface 1"),
], ids=["epb_interface_2", "epb_without_idb", "spb_without_idb", "pb_interface_1"])
def test_unknown_interface_id_raises(tmp_path, data, match):
    _all_readers_raise(tmp_path, data, match)


def test_trailing_length_mismatch_raises(tmp_path):
    bad = bytearray(epb(ETH_FRAME))
    bad[-4:] = struct.pack("<I", len(bad) + 4)
    _all_readers_raise(tmp_path, shb() + idb() + bytes(bad), "ends with length")
    bad_idb = bytearray(idb())
    bad_idb[-4:] = struct.pack("<I", 24)
    _all_readers_raise(tmp_path, shb() + bytes(bad_idb) + epb(ETH_FRAME), "ends with length")


def test_truncated_blocks_raise(tmp_path):
    _all_readers_raise(tmp_path, shb() + idb() + epb(ETH_FRAME)[:-8], "past the end of the file")
    _all_readers_raise(tmp_path, shb() + idb() + epb(ETH_FRAME) + b"\x06\x00\x00", "truncated block header")


@pytest.mark.parametrize("data, match", [
    (b"", "empty"),
    (idb() + epb(ETH_FRAME), "does not start with a section header"),
    (shb(magic=0x1A2B3C4E) + idb(), "byte-order magic"),
    (shb() + idb() + struct.pack("<II", 0x0BAD, 8), "bad block length 8"),
    (shb() + idb() + struct.pack("<II", 0x0BAD, 30) + bytes(22), "bad block length 30"),
    (shb() + idb() + struct.pack("<II", 0x0BAD, MAX_BLOCK + 4), "bad block length"),
    (shb() + idb() + block(6, bytes(16)), "under its 32 byte minimum"),
    (shb() + block(1, bytes(4)), "under its 20 byte minimum"),
    (block(0x0A0D0D0A, struct.pack("<I", 0x1A2B3C4D) + bytes(8)), "under its 28 byte minimum"),
    (shb() + idb() + _epb_claiming(100), "claims 100 captured bytes"),
], ids=["empty", "no_section_header", "bad_magic", "length_8", "length_not_multiple_of_4", "length_over_max_block",
        "epb_under_32", "idb_under_20", "shb_under_28", "caplen_past_block"])
def test_malformed_files_raise(tmp_path, data, match):
    _all_readers_raise(tmp_path, data, match)


def test_simple_packet_block_uses_interface_0_and_the_caplen_rule():
    [packet] = read_packets(shb() + idb(105) + idb(1) + spb(ETH_FRAME, origlen=1500))
    # min(origlen 1500, block length - 16 = 44 (the padded data), snaplen 0 = unlimited)
    assert packet == {"interface": 0, "linktype": 105, "ts": None, "caplen": 44, "origlen": 1500,
                      "data": ETH_FRAME + b"\x00\x00"}
    [packet] = read_packets(shb() + idb() + spb(ETH_FRAME))
    assert (packet["caplen"], packet["data"]) == (len(ETH_FRAME), ETH_FRAME)
    [packet] = read_packets(shb() + idb(snaplen=20) + spb(ETH_FRAME, origlen=1500))
    assert (packet["caplen"], packet["data"]) == (20, ETH_FRAME[:20])


def test_obsolete_packet_block_is_read_and_counted(tmp_path):
    data = shb() + idb() + idb(105) + pb(ETH_FRAME, interface=1, ts=TS)
    [packet] = read_packets(data)
    assert (packet["interface"], packet["linktype"], packet["data"]) == (1, 105, ETH_FRAME)
    assert packet["ts"] == pytest.approx(TS / 1e6, abs=1e-6)
    path = tmp_path / "pb.pcapng"
    path.write_bytes(data)
    assert count_packets(path) == 1


@pytest.mark.parametrize("endian", ["<", ">"], ids=["little_endian", "big_endian"])
@pytest.mark.parametrize("tsresol, divisor", [
    (None, 10 ** 6),       # no option: microseconds
    (3, 10 ** 3),          # 10^-3
    (9, 10 ** 9),          # 10^-9
    (0x8A, 1 << 10),       # bit 7 set: 2^-10
], ids=["default", "milliseconds", "nanoseconds", "power_of_two"])
def test_if_tsresol_sets_the_timestamp_unit(endian, tsresol, divisor):
    items = [opt(2, b"eth0", endian)]
    if tsresol is not None:
        items.append(opt(9, bytes([tsresol]), endian))
    raw = 1_700_000_000 * divisor + divisor // 2
    data = shb(endian) + idb(endian=endian, options=opts(*items, endian=endian)) + epb(ETH_FRAME, ts=raw, endian=endian)
    [packet] = read_packets(data)
    assert packet["ts"] == pytest.approx(1_700_000_000.5, abs=1e-6)


def test_a_malformed_idb_option_list_keeps_the_default_resolution():
    broken = struct.pack("<HH", 9, 40) + b"\x03\x00\x00\x00"        # if_tsresol claiming 40 bytes
    [packet] = read_packets(shb() + idb(options=broken) + epb(ETH_FRAME, ts=TS))
    assert packet["ts"] == pytest.approx(TS / 1e6, abs=1e-6)


def test_count_packets_streams_a_file_with_12000_packets(tmp_path):
    path = tmp_path / "big.pcapng"
    path.write_bytes(shb() + idb() + nrb() + epb(ETH_FRAME, ts=TS) * 11_998 + spb(ETH_FRAME) + pb(ETH_FRAME) + isb())
    assert count_packets(path) == 12_000
    with open(path, "rb") as f:
        assert sum(1 for _ in iter_packets(f)) == 12_000
    data = path.read_bytes()
    assert len(read_packets(data)) == 10_000                       # read_packets' default cap
    assert len(read_packets(data, max_packets=None)) == 12_000


class _CountingReader:
    """A binary file that adds up the bytes its read() calls return."""

    def __init__(self, path):
        self._file = io.open(path, "rb")
        self.bytes_read = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._file.close()

    def read(self, size=-1):
        chunk = self._file.read(size)
        self.bytes_read += len(chunk)
        return chunk

    def seek(self, *args):
        return self._file.seek(*args)

    def fileno(self):
        return self._file.fileno()


def test_count_packets_reads_block_headers_and_seeks_past_the_bodies(tmp_path, monkeypatch):
    frame = AP + STA + ETH_IPV4 + bytes(1486)                      # a full-size 1500-byte frame
    path = tmp_path / "wide.pcapng"
    path.write_bytes(shb() + idb() + epb(frame, ts=TS) * 200 + spb(frame) * 50 + pb(frame) * 50)
    readers = []

    def counting_open(file, mode="r", *args, **kwargs):
        assert mode == "rb"
        readers.append(_CountingReader(file))
        return readers[-1]

    monkeypatch.setattr(pcapng, "open", counting_open, raising=False)
    assert count_packets(path) == 300
    [reader] = readers
    assert reader.bytes_read < path.stat().st_size // 20          # block headers and trailers, never the frames


def test_read_packets_refuses_a_buffer_over_64_mib():
    with pytest.raises(PcapngError, match="limit"):
        read_packets(bytes(MAX_IN_MEMORY + 1))


def test_max_packets_stops_before_the_blocks_after_it():
    data = shb() + idb() + epb(ETH_FRAME) + epb(ETH_FRAME) + b"\x06\x00\x00\x00junk"
    assert len(read_packets(data, max_packets=2)) == 2
    assert list(iter_packets(io.BytesIO(data), max_packets=0)) == []
    with pytest.raises(PcapngError, match="bad block length"):
        read_packets(data, max_packets=3)
    with pytest.raises(ValueError):
        iter_packets(io.BytesIO(data), max_packets=-1)
    with pytest.raises(TypeError):
        read_packets(data, max_packets=2.5)


def test_module_opens_no_socket_and_runs_no_program():
    """tnt.pcapng has no I/O seam for tests/conftest.py to guard: it only reads and writes the files it is given."""
    tree = ast.parse(Path(pcapng.__file__).read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {(node.module or "").split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not imported & {"socket", "subprocess", "ctypes", "http", "urllib", "ssl", "asyncio", "multiprocessing"}


# --------------------------------------------------------------------------- Writer and the offset readers
def test_writer_writes_a_file_every_reader_here_takes(tmp_path):
    out = io.BytesIO()
    writer = pcapng.Writer(out, linktype=1, if_name="Ethernet")
    header_bytes = writer.offset
    first = writer.write_packet(1_700_000_000.123456, ETH_FRAME, 74)
    second = writer.write_packet(1_700_000_001.5, ETH_FRAME[:20])
    data = out.getvalue()
    assert (first, second) == (header_bytes, header_bytes + 32 + len(ETH_FRAME) + (-len(ETH_FRAME) % 4))
    assert writer.packets == 2 and writer.offset == len(data)
    packets = read_packets(data)
    assert [p["caplen"] for p in packets] == [len(ETH_FRAME), 20]
    assert [p["origlen"] for p in packets] == [74, 20]
    assert packets[0]["ts"] == pytest.approx(1_700_000_000.123456)
    assert packets[0]["linktype"] == 1 and packets[0]["data"] == ETH_FRAME
    path = tmp_path / "written.pcapng"
    path.write_bytes(data)
    assert count_packets(path) == 2


def test_writer_offsets_come_back_through_read_packet_at(tmp_path):
    out = io.BytesIO()
    writer = pcapng.Writer(out)
    offsets = [writer.write_packet(1_700_000_000.0 + i, ETH_FRAME + bytes([i])) for i in range(4)]
    path = tmp_path / "x.pcapng"
    path.write_bytes(out.getvalue())
    for i, offset in enumerate(offsets):
        packet = pcapng.read_packet_at(path, offset)
        assert packet is not None and packet["data"][-1] == i
        assert tuple(packet) == PACKET_KEYS
    assert [o for o, _p in pcapng.iter_packets_with_offsets(io.BytesIO(out.getvalue()))] == offsets


@pytest.mark.parametrize("offset", [0, 12, -1, 10 ** 9])
def test_read_packet_at_is_none_anywhere_that_is_not_a_packet(tmp_path, offset):
    out = io.BytesIO()
    pcapng.Writer(out).write_packet(1.0, ETH_FRAME)
    path = tmp_path / "x.pcapng"
    path.write_bytes(out.getvalue())
    assert pcapng.read_packet_at(path, offset) is None


def test_read_packet_at_is_none_for_a_file_that_is_not_there(tmp_path):
    assert pcapng.read_packet_at(tmp_path / "nope.pcapng", 0) is None


def test_writer_clamps_a_timestamp_it_cannot_write():
    out = io.BytesIO()
    writer = pcapng.Writer(out)
    writer.write_packet(None, ETH_FRAME)
    writer.write_packet(-5.0, ETH_FRAME)
    assert [p["ts"] for p in read_packets(out.getvalue())] == [0.0, 0.0]


def test_writer_refuses_a_packet_over_the_block_limit():
    out = io.BytesIO()
    writer = pcapng.Writer(out)
    with pytest.raises(PcapngError, match="over the"):
        writer.write_packet(1.0, bytes(pcapng.Writer.MAX_PACKET + 1))
    assert writer.packets == 0


def test_writer_pads_an_odd_length_packet_and_stays_readable():
    out = io.BytesIO()
    writer = pcapng.Writer(out)
    for size in (1, 2, 3, 5, 15):
        writer.write_packet(1.0, bytes(range(size)))
    assert [p["caplen"] for p in read_packets(out.getvalue())] == [1, 2, 3, 5, 15]
    assert len(out.getvalue()) % 4 == 0


def test_iter_packets_with_offsets_stops_at_max_packets():
    out = io.BytesIO()
    writer = pcapng.Writer(out)
    for i in range(5):
        writer.write_packet(float(i), ETH_FRAME)
    assert len(list(pcapng.iter_packets_with_offsets(io.BytesIO(out.getvalue()), max_packets=2))) == 2
