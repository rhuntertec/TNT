"""MaxMind DB reader (tnt/mmdb.py): synthetic databases, hand-encoded golden vectors, malformed files, budgets.

Every database here is built in tmp_path by tests/mmdb_writer.py or by hand; the real DB-IP Lite files are read only
by the env-gated smoke test (TNT_TEST_DBIP_DIR).  Addresses are documentation ranges.
"""
import glob
import gzip
import ipaddress
import os
import struct
import sys
import threading
import time

import pytest

from mmdb_writer import (ASN_FIXTURE, CITY_FIXTURE, MARKER, Typed, assemble, build_mmdb, control, encode_value,
                         fixture_pair, gzip_bytes, month_epoch, pointer, write_mmdb)
from tnt import mmdb
from tnt.mmdb import MmdbError, Reader

EPOCH_2026_09 = 1788226681
EMPTY_NODE = bytes.fromhex("000001000001")       # node_count 1, record_size 24: both records "no data"


@pytest.fixture
def open_db(tmp_path):
    """open_db(file_bytes, **reader_kw) -> an open Reader on a fresh file in tmp_path (closed at teardown)."""
    readers = []

    def _open(data, **kw):
        path = tmp_path / f"db{len(readers)}-{time.monotonic_ns()}.mmdb"
        path.write_bytes(data)
        reader = Reader(path, **kw)
        readers.append(reader)
        return reader

    yield _open
    for reader in readers:
        reader.close()


_META_TYPES = {"binary_format_major_version": "uint16", "binary_format_minor_version": "uint16",
               "build_epoch": "uint64", "ip_version": "uint16", "node_count": "uint32", "record_size": "uint16"}


def _meta(**changes):
    """Hand-typed metadata for hand-built files (node_count 1, record_size 24, IPv4).  A plain int change gets the
    spec's type for that key, any other value (Typed, bool, str, ...) is written as given, and None removes the key."""
    meta = {"binary_format_major_version": 2, "binary_format_minor_version": 0, "build_epoch": 0,
            "database_type": "TNT-Test", "ip_version": 4, "languages": [], "node_count": 1, "record_size": 24}
    meta.update(changes)
    return {key: Typed(_META_TYPES[key], value) if key in _META_TYPES and type(value) is int else value
            for key, value in meta.items() if value is not None}


def _node24(left, right):
    return left.to_bytes(3, "big") + right.to_bytes(3, "big")


def _data_db(section, offset=0):
    """A one-node IPv4 tree: 0.0.0.0/1 -> the value at data offset `offset`, 128.0.0.0/1 -> no data."""
    return assemble(_node24(1 + 16 + offset, 1), section, _meta())


def _hand_str(text):
    raw = text.encode("utf-8")
    assert len(raw) < 29
    return bytes([0x40 | len(raw)]) + raw


def _pad(n):
    """Exactly n data-section bytes of bytes values, hand-encoded from the spec (type 4, size forms 29/30/31)."""
    out = bytearray()
    while n > 0:
        if n <= 29:
            length, head = n - 1, bytes([0x80 | (n - 1)])
        elif n in (30, 287, 65824):                  # not reachable with one value: take a 1-byte empty value first
            length, head = 0, b"\x80"
        elif n <= 286:
            length = n - 2
            head = bytes([0x9D, length - 29])
        elif n <= 65823:
            length = n - 3
            head = b"\x9e" + (length - 285).to_bytes(2, "big")
        else:
            length = min(n - 4, 65821 + 0xFFFFFF)
            head = b"\x9f" + (length - 65821).to_bytes(3, "big")
        out += head + bytes(length)
        n -= len(head) + length
    return bytes(out)


def _record28(buf, node, bit):
    o = node * 7
    if bit:
        return ((buf[o + 3] & 0x0F) << 24) | int.from_bytes(buf[o + 4:o + 7], "big")
    return ((buf[o + 3] >> 4) << 24) | int.from_bytes(buf[o:o + 3], "big")


def _set_record28(buf, node, bit, value):
    o = node * 7
    if bit:
        buf[o + 3] = (buf[o + 3] & 0xF0) | (value >> 24)
        buf[o + 4:o + 7] = (value & 0xFFFFFF).to_bytes(3, "big")
    else:
        buf[o + 3] = (buf[o + 3] & 0x0F) | ((value >> 24) << 4)
        buf[o:o + 3] = (value & 0xFFFFFF).to_bytes(3, "big")


# ---------------------------------------------------------------------------------------------- lookups
@pytest.mark.parametrize("record_size", [24, 28, 32])
def test_open_metadata_and_lookup_record_sizes(tmp_path, record_size):
    path = write_mmdb(tmp_path / "city.mmdb", CITY_FIXTURE, record_size=record_size, build_epoch=EPOCH_2026_09)
    with Reader(path) as r:
        assert r.path == str(path)
        assert r.size == path.stat().st_size
        assert r.record_size == record_size
        assert r.ip_version == 6
        assert r.database_type == "DBIP-City-Lite"
        assert r.build_epoch == EPOCH_2026_09 == month_epoch("2026-09")
        assert r.node_count == r.metadata["node_count"] > 128
        assert r.metadata["binary_format_major_version"] == 2
        assert r.metadata["languages"] == ["en"]
        r.metadata["languages"].append("xx")         # a copy each time
        assert r.metadata["languages"] == ["en"]
        assert not r.closed

        anytown = r.get("203.0.113.9")
        assert anytown == CITY_FIXTURE[0][1]
        assert anytown["city"]["names"]["en"] == "Anytown"
        assert anytown["subdivisions"][0]["names"]["en"] == "Texas"
        assert anytown["country"]["iso_code"] == "US"
        dallas = r.get("203.0.113.200")
        assert dallas["city"]["names"]["en"] == "Dallas" and dallas["location"]["latitude"] == 32.78
        assert r.get("198.51.100.7")["city"]["names"]["en"] == "Richardson (Canyon Creek)"
        montreal = r.get("192.0.2.10")
        assert montreal["city"]["names"]["en"] == "Montreal" and montreal["country"]["iso_code"] == "CA"
        london = r.get("2001:db8::1")
        assert london["country"]["iso_code"] == "GB" and london["continent"]["code"] == "EU"
        assert r.get("::ffff:203.0.113.9") == anytown
        assert r.get("10.0.0.1") is None
        assert r.get("198.18.0.1") is None

        assert r.get_with_prefix_len("203.0.113.9") == (anytown, 25)
        assert r.get_with_prefix_len("198.51.100.7")[1] == 24
        assert r.get_with_prefix_len("2001:db8::1")[1] == 32
    assert r.closed

    city, asn = fixture_pair(city_record_size=record_size, asn_record_size=record_size)
    assert city == path.read_bytes()
    (tmp_path / "asn.mmdb").write_bytes(asn)
    with Reader(tmp_path / "asn.mmdb") as a:
        assert a.database_type == "DBIP-ASN-Lite (compat=GeoLite2-ASN)"
        assert a.get("203.0.113.9") == {"autonomous_system_number": 64500,
                                        "autonomous_system_organization": "Example Broadband "}
        assert a.get("203.0.113.200")["autonomous_system_number"] == 64500
        assert a.get("198.51.100.7") == ASN_FIXTURE[1][1]
        assert a.get("2001:db8::1")["autonomous_system_organization"] == "Example Hosting LLC"
        assert a.get("192.0.2.10") is None
        assert a.get("10.0.0.1") is None


def test_ipv4_only_tree(open_db):
    v4 = [(cidr, record) for cidr, record in CITY_FIXTURE if ":" not in cidr]
    r = open_db(build_mmdb(v4, ip_version=4, record_size=24))
    assert r.ip_version == 4
    assert r.get("203.0.113.9")["city"]["names"]["en"] == "Anytown"
    assert r.get_with_prefix_len("203.0.113.200")[1] == 25
    assert r.get_with_prefix_len("192.0.2.10")[1] == 24
    assert r.get("::ffff:198.51.100.7") == r.get("198.51.100.7") is not None
    assert r.get("10.0.0.1") is None
    assert r.get_with_prefix_len("2001:db8::1") == (None, 0)
    assert r.get_with_prefix_len("::203.0.113.9") == (None, 0)
    r.self_check(64)
    with pytest.raises(ValueError):
        build_mmdb([("2001:db8::/32", {"x": 1})], ip_version=4)


def test_ipv4_mapped_and_alias_paths(open_db):
    r = open_db(fixture_pair()[0])
    want = r.get("203.0.113.9")
    assert want is not None
    assert r.get("::ffff:203.0.113.9") == want
    assert r.get("::203.0.113.9") == want
    assert r.get(ipaddress.IPv6Address("::ffff:203.0.113.9")) == want
    assert r.get_with_prefix_len("::ffff:203.0.113.9") == (want, 25)      # looked up as IPv4
    assert r.get_with_prefix_len("::203.0.113.9") == (want, 96 + 25)     # walked as IPv6 through ::/96

    # The ::ffff:0:0/96 alias in the tree itself leads back to the IPv4 subtree (the reader maps such addresses to
    # IPv4 before walking, so walk the 128 bits directly).
    mapped = int(ipaddress.IPv6Address("::ffff:203.0.113.9"))
    record, depth = r._walk(mapped, 128, 0)
    assert depth == 96 + 25
    assert r._resolve(record) == want

    plain = open_db(build_mmdb(CITY_FIXTURE, ipv4_alias=False))
    record, _ = plain._walk(mapped, 128, 0)
    assert plain._resolve(record) is None
    assert plain.get("::ffff:203.0.113.9") == want                        # still found through IPv4


def test_all_data_types_round_trip(open_db):
    section = bytearray()

    def put(blob):
        offset = len(section)
        section.extend(blob)
        return offset

    key_off = put(encode_value("shared key"))
    near = {"nested": {"deeper": [1, "two", 3.0]}}
    near_off = put(encode_value(near))
    put(_pad(4000 - len(section)))
    mid_off = put(encode_value("two-byte pointer target"))
    put(_pad(600000 - len(section)))
    far = ["three-byte", "pointer", "target"]
    far_off = put(encode_value(far))
    assert near_off < 2048 <= mid_off < 526336 <= far_off
    assert [len(pointer(o)) for o in (near_off, mid_off, far_off)] == [2, 3, 4]

    entries = [   # (key as str or pre-encoded bytes, value to encode, expected decoded value)
        ("utf8", "héllo", "héllo"),
        ("double", -2.5, -2.5),
        ("bytes", b"\x00\x01\xfe\xff", b"\x00\x01\xfe\xff"),
        ("empty bytes", Typed("bytes", b""), b""),
        ("uint16", Typed("uint16", 65535), 65535),
        ("uint16 zero", Typed("uint16", 0), 0),
        ("uint32", 4294967295, 4294967295),
        ("int32 min", Typed("int32", -2 ** 31), -2 ** 31),
        ("int32 -1", Typed("int32", -1), -1),
        ("int32 max", Typed("int32", 2 ** 31 - 1), 2 ** 31 - 1),
        ("int32 short", Typed("int32", 200), 200),
        ("uint64", Typed("uint64", 2 ** 64 - 1), 2 ** 64 - 1),
        ("uint128", Typed("uint128", 2 ** 128 - 1), 2 ** 128 - 1),
        ("array", [1, "a", False], [1, "a", False]),
        ("true", True, True),
        ("false", False, False),
        ("float", Typed("float", -0.375), -0.375),
        ("nested", {"a": {"b": {"c": [], "d": {}}}}, {"a": {"b": {"c": [], "d": {}}}}),
        ("size 29", "z" * 29, "z" * 29),
        ("size 30", "z" * 300, "z" * 300),
        ("size 31", "y" * 70000, "y" * 70000),
        ("array size 29", list(range(40)), list(range(40))),
        ("map size 29", {f"k{i:02d}": i for i in range(30)}, {f"k{i:02d}": i for i in range(30)}),
        (pointer(key_off), "value under a pointer key", "value under a pointer key"),
        ("pointer 2 bytes", Typed("pointer", near_off), near),
        ("pointer 3 bytes", Typed("pointer", mid_off), "two-byte pointer target"),
        ("pointer 4 bytes", Typed("pointer", far_off), far),
        ("pointer 5 bytes", Typed("pointer", (near_off, 4)), near),
        ("pointer in array", [Typed("pointer", mid_off), 7], ["two-byte pointer target", 7]),
    ]
    blob = control(7, len(entries))
    expected = {}
    for key, value, want in entries:
        blob += (key if isinstance(key, bytes) else encode_value(key)) + encode_value(value)
        expected["shared key" if isinstance(key, bytes) else key] = want
    record_off = put(blob)

    tree = struct.pack(">II", 1 + 16 + record_off, 1)
    r = open_db(assemble(tree, bytes(section), _meta(record_size=32)))
    got = r.get("0.0.0.1")
    assert got == expected
    for key, want in expected.items():
        assert type(got[key]) is type(want), key
    assert r.get("128.0.0.1") is None
    assert r.get("0.0.0.1") == expected            # again, through the pointer cache


def test_writer_shares_repeated_values_through_pointers(open_db):
    records = [("203.0.113.0/25", CITY_FIXTURE[0][1]),
               ("203.0.113.128/25", {"again": CITY_FIXTURE[0][1], "names": {"en": "Texas"}}),
               ("198.51.100.0/24", CITY_FIXTURE[0][1])]
    shared = build_mmdb(records, share=True)
    plain = build_mmdb(records, share=False)
    assert len(shared) < len(plain)
    for data in (shared, plain):
        r = open_db(data)
        assert r.get("203.0.113.9") == records[0][1]
        assert r.get("203.0.113.200") == records[1][1]
        assert r.get("198.51.100.7") == records[0][1]
        r.self_check(32)


def test_writer_rejects_overlapping_networks():
    with pytest.raises(ValueError):
        build_mmdb([("203.0.113.0/24", {"a": 1}), ("203.0.113.128/25", {"b": 1})])
    with pytest.raises(ValueError):
        build_mmdb([("203.0.113.128/25", {"b": 1}), ("203.0.113.0/24", {"a": 1})])
    with pytest.raises(ValueError):
        build_mmdb([("::ffff:203.0.113.0/120", {"a": 1})])            # inside the alias subtree
    build_mmdb([("::ffff:203.0.113.0/120", {"a": 1})], ipv4_alias=False)
    assert month_epoch("2026-09") == EPOCH_2026_09
    assert gzip.decompress(gzip_bytes(b"abc")) == b"abc"
    assert gzip_bytes(b"abc") == gzip_bytes(b"abc")


def test_28_bit_records_use_the_high_nibbles(open_db):
    near = encode_value({"side": "near"})
    section = near + _pad((1 << 24) + 10)
    far_off = len(section)
    section += encode_value({"side": "far"})
    far_record, near_record = 1 + 16 + far_off, 1 + 16
    assert far_record >> 24 == 1 and near_record >> 24 == 0

    def node28(left, right):                         # spec: left = (b3 >> 4) << 24 | b0..2, right = (b3 & 15) << 24 | b4..6
        return (left & 0xFFFFFF).to_bytes(3, "big") + bytes([(left >> 24) << 4 | right >> 24]) + \
            (right & 0xFFFFFF).to_bytes(3, "big")

    assert node28(0x1ABCDEF, 0x0123456) == bytes.fromhex("abcdef10123456")
    assert node28(0x0123456, 0x1ABCDEF) == bytes.fromhex("12345601abcdef")
    for left, right in ((far_record, near_record), (near_record, far_record)):
        for size, tree in ((28, node28(left, right)), (32, struct.pack(">II", left, right))):
            r = open_db(assemble(tree, section, _meta(record_size=size)))
            want_low = {"side": "far" if left == far_record else "near"}
            want_high = {"side": "far" if right == far_record else "near"}
            assert (r.get("0.0.0.1"), r.get("128.0.0.1")) == (want_low, want_high)
            r.close()


def test_concurrent_gets_share_one_reader(open_db):
    r = open_db(fixture_pair()[0], cache_size=8)
    addrs = ["203.0.113.9", "203.0.113.200", "198.51.100.7", "192.0.2.10", "2001:db8::1", "10.0.0.1"]
    want = {a: r.get(a) for a in addrs}
    errors = []

    def worker():
        try:
            for _ in range(200):
                for a in addrs:
                    assert r.get(a) == want[a]
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, name=f"mmdb-test-{i}") for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors


# ---------------------------------------------------------------------------------------------- golden vectors
GOLDEN_ANCHORS = [(5, _hand_str("at5")), (42, _hand_str("at42")), (2047, _hand_str("")), (2048, _hand_str("at2048")),
                  (526335, _hand_str("")), (526336, _hand_str("at526336"))]
GOLDEN_ROWS = [   # (hand-encoded bytes, decoded value): contract section 2.3
    (bytes.fromhex("43414243"), "ABC"),
    (bytes.fromhex("5d00") + b"x" * 29, "x" * 29),
    (bytes.fromhex("5e0001") + b"x" * 286, "x" * 286),
    (bytes.fromhex("5f000001") + b"x" * 65822, "x" * 65822),
    (bytes.fromhex("a2012c"), 300),
    (bytes.fromhex("c4ffffffff"), 4294967295),
    (bytes.fromhex("0401ffffffff"), -1),
    (bytes.fromhex("02020100"), 256),
    (bytes.fromhex("010305"), 5),
    (bytes.fromhex("0007"), False),
    (bytes.fromhex("0107"), True),
    (bytes.fromhex("04083fc00000"), 1.5),
    (bytes.fromhex("683ff8000000000000"), 1.5),
    (bytes.fromhex("8200ff"), b"\x00\xff"),
    (bytes.fromhex("e14161c107"), {"a": 7}),
    (bytes.fromhex("1d0400") + b"\xa0" * 29, [0] * 29),
    (bytes.fromhex("2005"), "at5"),
    (bytes.fromhex("27ff"), ""),                    # 2047
    (bytes.fromhex("280000"), "at2048"),
    (bytes.fromhex("2fffff"), ""),                  # 526335
    (bytes.fromhex("30000000"), "at526336"),
    (bytes.fromhex("380000002a"), "at42"),
    (bytes.fromhex("3f0000002a"), "at42"),
    (bytes.fromhex("02042005a2012c"), ["at5", 300]),
]


def test_golden_vectors(open_db):
    section = bytearray()
    for offset, blob in GOLDEN_ANCHORS:
        section += _pad(offset - len(section)) + blob
    rows_at = []
    section += _pad(530000 - len(section))
    for blob, _ in GOLDEN_ROWS:
        rows_at.append(len(section))
        section += blob
    r = open_db(assemble(EMPTY_NODE, bytes(section), _meta()))
    for offset, blob in GOLDEN_ANCHORS:
        assert r._decode_data(offset) == blob[1:].decode()
    for offset, (blob, want) in zip(rows_at, GOLDEN_ROWS):
        got = r._decode_data(offset)
        assert got == want and type(got) is type(want), blob[:8].hex()
    with pytest.raises(MmdbError):                  # inside zero padding: where a decoder that dropped VVV would land
        r._decode_data(255)

    # The writer's encoders produce the same bytes for the same inputs.
    assert control(2, 3) + b"ABC" == encode_value("ABC") == GOLDEN_ROWS[0][0]
    assert control(2, 29) == bytes.fromhex("5d00")
    assert control(2, 286) == bytes.fromhex("5e0001")
    assert control(2, 65822) == bytes.fromhex("5f000001")
    assert encode_value(Typed("uint16", 300)) == bytes.fromhex("a2012c")
    assert encode_value(4294967295) == bytes.fromhex("c4ffffffff")
    assert encode_value(Typed("int32", -1)) == bytes.fromhex("0401ffffffff")
    assert encode_value(Typed("uint64", 256)) == bytes.fromhex("02020100")
    assert encode_value(Typed("uint128", 5)) == bytes.fromhex("010305")
    assert encode_value(False) == bytes.fromhex("0007") and encode_value(True) == bytes.fromhex("0107")
    assert encode_value(Typed("float", 1.5)) == bytes.fromhex("04083fc00000")
    assert encode_value(1.5) == bytes.fromhex("683ff8000000000000")
    assert encode_value(b"\x00\xff") == bytes.fromhex("8200ff")
    assert encode_value({"a": 7}) == bytes.fromhex("e14161c107")
    assert encode_value([Typed("uint16", 0)] * 29) == GOLDEN_ROWS[15][0]
    assert pointer(5) == bytes.fromhex("2005")
    assert pointer(2047) == bytes.fromhex("27ff")
    assert pointer(2048) == bytes.fromhex("280000")
    assert pointer(526335) == bytes.fromhex("2fffff")
    assert pointer(526336) == bytes.fromhex("30000000")
    assert pointer(42, 4) == bytes.fromhex("380000002a")
    assert control(8, 4) + b"\xff" * 4 == GOLDEN_ROWS[6][0]


def test_results_are_independent_copies(open_db):
    for cache_size in (mmdb.POINTER_CACHE_MAX, 1, 0):
        r = open_db(fixture_pair()[0], cache_size=cache_size)
        first = r.get("203.0.113.9")
        first["city"]["names"]["en"] = "Changed"
        first["subdivisions"].append({"x": 1})
        first["country"].clear()
        second = r.get("203.0.113.9")
        assert second == CITY_FIXTURE[0][1]
        third = r.get("203.0.113.9")
        assert third["continent"] is not second["continent"]
        assert third["continent"]["names"] is not second["continent"]["names"]
        a, b = r.get("203.0.113.9"), r.get("198.51.100.7")     # records sharing sub-maps through pointers
        assert a["country"] == b["country"] and a["country"] is not b["country"]
        a["country"]["names"]["en"] = "Elsewhere"
        assert r.get("198.51.100.7")["country"]["names"]["en"] == "United States"
        meta = r.metadata
        meta["languages"].clear()
        assert r.metadata["languages"] == ["en"]


def test_self_check_passes_on_fixtures(open_db):
    for size in (24, 28, 32):
        city, asn = fixture_pair(city_record_size=size, asn_record_size=size)
        for data in (city, asn):
            r = open_db(data)
            r.self_check()
            r.self_check(0)
            r.self_check(256)
    v4 = [(cidr, record) for cidr, record in CITY_FIXTURE if ":" not in cidr]
    open_db(build_mmdb(v4, ip_version=4)).self_check(64)
    open_db(mmdb.SELFCHECK_MMDB).self_check(64)
    open_db(assemble(EMPTY_NODE, b"", _meta())).self_check(8)          # nothing at all in it is fine


def test_self_check_samples_the_ipv4_subtree(open_db):
    data = bytearray(build_mmdb([("0.0.0.0/1", {"half": "low"}), ("128.0.0.0/1", {"half": "high"})],
                                ip_version=6, record_size=28))
    good = open_db(bytes(data))
    good.self_check(16)
    node_count = good.node_count
    node = 0
    for _ in range(96):                             # the IPv4 start node, found independently of the reader
        node = _record28(data, node, 0)
    assert node < node_count
    assert _record28(data, node, 1) > node_count + 16
    _set_record28(data, node, 1, node_count + 5)    # a reserved record
    bad = open_db(bytes(data))
    assert bad.get("0.0.0.1") == {"half": "low"}
    with pytest.raises(MmdbError):
        bad.get("128.0.0.1")
    with pytest.raises(MmdbError):
        bad.self_check(16)


# ---------------------------------------------------------------------------------------------- malformed files
def test_rejects_missing_marker(open_db):
    with pytest.raises(MmdbError, match="metadata marker not found"):
        open_db(bytes(4096))
    good = fixture_pair()[1]
    open_db(good)
    with pytest.raises(MmdbError, match="metadata marker not found"):
        open_db(good + bytes(mmdb.METADATA_WINDOW))             # the marker is further back than the window


BAD_METADATA = {
    "format major 1": {"binary_format_major_version": Typed("uint16", 1)},
    "record_size 20": {"record_size": Typed("uint16", 20)},
    "ip_version 5": {"ip_version": Typed("uint16", 5)},
    "node_count 0": {"node_count": Typed("uint32", 0)},
    "node_count True": {"node_count": True},
    "missing database_type": {"database_type": None},
    "missing node_count": {"node_count": None},
    "database_type not a string": {"database_type": Typed("uint16", 1)},
    "record_size a string": {"record_size": "24"},
    "ip_version True": {"ip_version": True},
    "build_epoch negative": {"build_epoch": Typed("int32", -1)},
    "languages not a list": {"languages": "en"},
    "description not a map": {"description": ["en"]},
}


@pytest.mark.parametrize("case", ["not a map"] + list(BAD_METADATA))
def test_rejects_bad_metadata(open_db, case):
    assert open_db(assemble(EMPTY_NODE, b"", _meta())).node_count == 1
    if case == "not a map":
        data = EMPTY_NODE + bytes(16) + MARKER + encode_value(["not", "a", "map"])
    else:
        data = assemble(EMPTY_NODE, b"", _meta(**BAD_METADATA[case]))
    with pytest.raises(MmdbError):
        open_db(data)


def test_rejects_tree_overlapping_metadata(open_db):
    with pytest.raises(MmdbError, match="overlaps"):
        open_db(assemble(EMPTY_NODE, b"", _meta(node_count=100)))
    open_db(assemble(EMPTY_NODE * 100, b"", _meta(node_count=100)))


def test_rejects_nonzero_separator(open_db):
    with pytest.raises(MmdbError, match="separator"):
        open_db(assemble(EMPTY_NODE, b"", _meta(), separator=bytes(15) + b"\x01"))
    with pytest.raises(MmdbError, match="separator"):
        open_db(assemble(EMPTY_NODE, b"", _meta(), separator=b"\x01" + bytes(15)))


def test_rejects_pointer_out_of_bounds(open_db):
    r = open_db(_data_db(pointer(500) + encode_value("x")))
    with pytest.raises(MmdbError, match="pointer"):
        r.get("0.0.0.1")
    with pytest.raises(MmdbError, match="pointer"):
        r._decode_data(0)
    assert r._decode_data(2) == "x"
    with pytest.raises(MmdbError):
        open_db(_data_db(b"\x28\x00")).get("0.0.0.1")                  # a 2-byte pointer cut short
    with pytest.raises(MmdbError):
        open_db(_data_db(pointer(3))).get("0.0.0.1")                   # exactly one past the end
    with pytest.raises(MmdbError):                                      # the metadata resolves its own pointers
        open_db(EMPTY_NODE + bytes(16) + MARKER + control(7, 1) + pointer(1000) + encode_value("v"))


def test_rejects_pointer_to_pointer(open_db):
    r = open_db(_data_db(pointer(2) + pointer(4) + encode_value("x")))
    with pytest.raises(MmdbError, match="pointer to a pointer"):
        r.get("0.0.0.1")
    assert r._decode_data(2) == "x"


def test_rejects_nesting_deeper_than_limit(open_db):
    def nested(levels):
        return control(11, 1) * levels + encode_value("x")

    value = open_db(_data_db(nested(mmdb.MAX_DEPTH))).get("0.0.0.1")
    for _ in range(mmdb.MAX_DEPTH):
        value = value[0]
    assert value == "x"
    with pytest.raises(MmdbError, match="nesting too deep"):
        open_db(_data_db(nested(mmdb.MAX_DEPTH + 1))).get("0.0.0.1")

    def chain(levels):                              # each level: [pointer to the next level]; two depth steps each
        section = bytearray()
        for i in range(levels):
            section += control(11, 1) + pointer(4 * (i + 1))
        return bytes(section + encode_value("x"))

    for cache_size in (mmdb.POINTER_CACHE_MAX, 0):
        ok = open_db(_data_db(chain(mmdb.MAX_DEPTH // 2)), cache_size=cache_size)
        assert ok.get("0.0.0.1") == ok.get("0.0.0.1")
        deep = open_db(_data_db(chain(mmdb.MAX_DEPTH // 2 + 1)), cache_size=cache_size)
        deep._decode_data(4)                        # fills the cache from a shallower start
        for _ in range(2):
            with pytest.raises(MmdbError, match="nesting too deep"):
                deep.get("0.0.0.1")


@pytest.mark.parametrize("cache_size", [mmdb.POINTER_CACHE_MAX, 0])
def test_rejects_fanout_bomb(open_db, cache_size):
    keys = [encode_value(f"k{i:02d}") for i in range(64)]
    leaf = {f"k{i:02d}": i for i in range(64)}
    section = bytearray(encode_value(leaf))
    level2 = len(section)
    section += control(7, 64) + b"".join(key + pointer(0) for key in keys)
    level1 = len(section)
    section += control(7, 64) + b"".join(key + pointer(level2) for key in keys)
    r = open_db(_data_db(bytes(section), offset=level1), cache_size=cache_size)
    started = time.monotonic()
    with pytest.raises(MmdbError, match="record too large"):
        r.get("0.0.0.1")
    with pytest.raises(MmdbError, match="record too large"):
        r._decode_data(level2)
    assert time.monotonic() - started < 2.0
    assert r._decode_data(0) == leaf                # every top-level decode starts a fresh budget
    assert r._decode_data(0) == leaf


@pytest.mark.parametrize("cache_size", [mmdb.POINTER_CACHE_MAX, 0])
def test_rejects_string_byte_bomb(open_db, cache_size):
    section = bytearray(encode_value("s" * 60000))

    def bomb(count):
        top = len(section)
        return top, control(7, count) + b"".join(encode_value(f"key{i:02d}") + pointer(0) for i in range(count))

    top20, blob20 = bomb(20)
    r = open_db(_data_db(bytes(section + blob20), offset=top20), cache_size=cache_size)
    with pytest.raises(MmdbError, match="record too large"):
        r.get("0.0.0.1")
    assert r._decode_data(0) == "s" * 60000
    top17, blob17 = bomb(17)                        # 1,020,000 bytes: still inside MAX_RECORD_BYTES
    assert len(open_db(_data_db(bytes(section + blob17), offset=top17), cache_size=cache_size).get("0.0.0.1")) == 17


def test_pointer_cache_keeps_only_small_targets(open_db):
    limit = mmdb.POINTER_CACHE_ITEMS_MAX
    assert 78 < limit < mmdb.MAX_ITEMS_PER_RECORD       # above the largest real DB-IP target (78 items)
    section = bytearray(encode_value({"k": "v"}))       # offset 0: a 3-item target
    edge = len(section)                                 # exactly `limit` items: an array of limit - 1 empty maps
    section += control(11, limit - 1) + b"\xe0" * (limit - 1)
    over = len(section)                                 # one item more
    section += control(11, limit) + b"\xe0" * limit
    nested = len(section)                               # 1 + 300 * 3 items, built from the cached 3-item target
    section += control(11, 300) + pointer(0) * 300
    bigs = []
    for _ in range(32):                                 # many distinct 3001-item targets, 1 byte per empty map
        bigs.append(len(section))
        section += control(11, 3000) + b"\xe0" * 3000
    records = []
    for target in [edge, over, nested] + bigs:          # each record: {"x": pointer -> target}
        records.append(len(section))
        section += control(7, 1) + encode_value("x") + pointer(target)
    twice = len(section)                                # two expansions of one uncached big target: 6005 items
    section += control(7, 2) + encode_value("a") + pointer(bigs[0]) + encode_value("b") + pointer(bigs[0])
    r = open_db(_data_db(bytes(section), offset=records[0]))
    cached = lambda offset: len(_node24(0, 0)) + 16 + offset in r._cache    # noqa: E731 (keys are file offsets)
    for _ in range(2):
        assert r._decode_data(records[0]) == {"x": [{}] * (limit - 1)}
        assert r._decode_data(records[1]) == {"x": [{}] * limit}
        value = r._decode_data(records[2])
        assert value == {"x": [{"k": "v"}] * 300} and value["x"][0] is not value["x"][1]
        for record in records[3:]:
            assert len(r._decode_data(record)["x"]) == 3000
        with pytest.raises(MmdbError, match="record too large"):   # an uncached target is still budgeted in full
            r._decode_data(twice)
        assert cached(0) and cached(edge)
        assert not cached(over) and not cached(nested) and not any(cached(big) for big in bigs)
        assert max(items for _, items, _, _ in r._cache.values()) <= limit


BAD_SIZES = {
    "double size 4": control(3, 4) + bytes(4),
    "float size 8": control(15, 8) + bytes(8),
    "uint16 size 3": control(5, 3) + bytes(3),
    "uint32 size 5": control(6, 5) + bytes(5),
    "int32 size 5": control(8, 5) + bytes(5),
    "uint64 size 9": control(9, 9) + bytes(9),
    "uint128 size 17": control(10, 17) + bytes(17),
    "boolean size 2": control(14, 2),
    "map size beyond section": control(7, 28) + encode_value("k"),
    "array size beyond section": control(11, 20) + encode_value(1),
    "string beyond section": control(2, 10) + b"abc",
    "size bytes beyond section": b"\x5f\x00",
    "extended type 20": bytes([0x00, 20 - 7]),
    "extended type 7": bytes([0x00, 0x00]),
    "extended type byte missing": bytes([0x00]),
    "cache container type 12": control(12, 0),
    "end marker type 13": control(13, 0),
    "map key not a string": control(7, 1) + encode_value(5) + encode_value("v"),
}


@pytest.mark.parametrize("case", list(BAD_SIZES))
def test_rejects_bad_sizes(open_db, case):
    r = open_db(_data_db(BAD_SIZES[case]))
    with pytest.raises(MmdbError):
        r.get("0.0.0.1")
    assert r.get("128.0.0.1") is None


def test_rejects_record_in_reserved_range(open_db):
    section = encode_value({"a": 1})
    assert open_db(assemble(_node24(1 + 16, 1), section, _meta())).get("0.0.0.1") == {"a": 1}
    for record in (1 + 1, 1 + 15):
        r = open_db(assemble(_node24(record, 1), section, _meta()))
        with pytest.raises(MmdbError):
            r.get("0.0.0.1")
        assert r.get("128.0.0.1") is None
        with pytest.raises(MmdbError):
            r.self_check(64)


def test_rejects_record_past_data_end(open_db):
    section = encode_value({"a": 1})
    r = open_db(assemble(_node24(1 + 16 + len(section), 1 + 16), section, _meta()))
    with pytest.raises(MmdbError):
        r.get("0.0.0.1")
    assert r.get("128.0.0.1") == {"a": 1}
    with pytest.raises(MmdbError):
        r.self_check(64)
    with pytest.raises(MmdbError):
        r._decode_data(len(section))


def test_empty_and_truncated_files(tmp_path, open_db):
    empty = tmp_path / "empty.mmdb"
    empty.write_bytes(b"")
    with pytest.raises(MmdbError, match="empty file"):
        Reader(empty)
    os.remove(empty)                                # the failed open left nothing open
    with pytest.raises(OSError):
        Reader(tmp_path / "missing.mmdb")

    good = fixture_pair()[0]
    open_db(good).self_check()
    cuts = sorted({1, 13, 64, len(good) // 3, len(good) // 2, len(good) - 300, *range(len(good) - 80, len(good))})
    for cut in cuts:
        with pytest.raises(MmdbError):
            open_db(good[:cut])
    truncated = tmp_path / "truncated.mmdb"
    truncated.write_bytes(good[:-1])
    with pytest.raises(MmdbError):
        Reader(truncated)
    os.remove(truncated)                            # the map was closed before raising
    tree_cut = good[:40] + good[-400:]              # the metadata survives, the tree does not
    with pytest.raises(MmdbError):
        open_db(tree_cut)


def test_close_is_idempotent_and_releases_the_file(tmp_path):
    path = tmp_path / "city.mmdb"
    path.write_bytes(fixture_pair()[0])
    r = Reader(path)
    assert r.get("203.0.113.9") is not None
    if sys.platform == "win32":
        with pytest.raises(PermissionError):
            os.remove(path)                         # the map keeps the file locked until close()
    r.close()
    r.close()
    assert r.closed
    for call in (lambda: r.get("203.0.113.9"), lambda: r.get_with_prefix_len("2001:db8::1"), r.self_check,
                 lambda: r._decode_data(0)):
        with pytest.raises(MmdbError, match="reader is closed"):
            call()
    os.remove(path)
    assert not path.exists()

    path.write_bytes(fixture_pair()[1])
    with Reader(path) as r2:
        assert r2.get("198.51.100.7")["autonomous_system_number"] == 64510
    assert r2.closed
    os.remove(path)


def test_bad_address_raises_value_error(open_db):
    r = open_db(fixture_pair()[0])
    for bad in ("", "   ", "not an ip", "203.0.113.999", "203.0.113", "2001:db8::g", "[203.0.113.9", "203.0.113.9/24"):
        with pytest.raises(ValueError) as info:
            r.get(bad)
        assert not isinstance(info.value, MmdbError), bad
    for wrong in (None, 3405803785, b"203.0.113.9", ("203.0.113.9",), ipaddress.ip_network("203.0.113.0/24")):
        with pytest.raises(TypeError):
            r.get(wrong)
    want = r.get("203.0.113.9")
    assert r.get(" 203.0.113.9\n") == want
    assert r.get(ipaddress.IPv4Address("203.0.113.9")) == want
    london = r.get("2001:db8::1")
    assert london is not None
    assert r.get("[2001:db8::1]") == london
    assert r.get("2001:db8::1%12") == london
    assert r.get("[2001:db8::1%eth0]") == london


def test_selfcheck_database_constant(tmp_path):
    built = build_mmdb([("203.0.113.0/24", {"tnt": "selfcheck"})], ip_version=4, record_size=24,
                       database_type="TNT-Selfcheck", build_epoch=0, languages=(), share=False)
    assert mmdb.SELFCHECK_MMDB == built
    assert len(mmdb.SELFCHECK_MMDB) < 1024
    assert mmdb.SELFCHECK_RECORD == {"tnt": "selfcheck"} and mmdb.SELFCHECK_IP == "203.0.113.9"
    path = tmp_path / "selfcheck.mmdb"
    path.write_bytes(mmdb.SELFCHECK_MMDB)
    with Reader(path) as r:
        assert r.get(mmdb.SELFCHECK_IP) == mmdb.SELFCHECK_RECORD
        assert r.database_type == "TNT-Selfcheck" and r.ip_version == 4 and r.build_epoch == 0
        r.self_check(64)
    assert set(mmdb.__all__) == {"Reader", "MmdbError", "METADATA_MARKER", "SELFCHECK_MMDB", "SELFCHECK_IP",
                                 "SELFCHECK_RECORD"}
    assert mmdb.METADATA_MARKER == MARKER
    assert issubclass(MmdbError, ValueError)


# ---------------------------------------------------------------------------------------------- real DB-IP files
@pytest.mark.skipif(not os.environ.get("TNT_TEST_DBIP_DIR"), reason="set TNT_TEST_DBIP_DIR to a folder with DB-IP Lite files")
def test_real_dbip_files_smoke():
    folder = os.environ["TNT_TEST_DBIP_DIR"]

    def newest(kind):
        names = sorted(glob.glob(os.path.join(folder, f"dbip-{kind}-lite-*.mmdb")))
        assert names, f"no dbip-{kind}-lite-*.mmdb in TNT_TEST_DBIP_DIR"
        return names[-1]

    with Reader(newest("city")) as city, Reader(newest("asn")) as asn:
        assert "City" in city.database_type and "ASN" in asn.database_type
        assert city.ip_version == asn.ip_version == 6
        city.self_check(256)
        asn.self_check(256)
        assert asn.get("1.1.1.1")["autonomous_system_number"] == 13335
        assert asn.get("8.8.8.8")["autonomous_system_number"] == 15169
        assert city.get("8.8.8.8")["country"]["iso_code"] == "US"
        assert city.get("10.0.0.1") is None
        assert asn.get("10.0.0.1") is None
        assert asn.get("2001:4860:4860::8888")["autonomous_system_number"] == 15169
        assert city.get("::ffff:8.8.8.8") == city.get("8.8.8.8")

        # A deterministic spread of real records all decode inside MAX_ITEMS_PER_RECORD / MAX_RECORD_BYTES.
        state, found = 20260912, 0
        for i in range(1500):
            state = (state * 6364136223846793005 + 1442695040888963407) % 2 ** 64
            addrs = [ipaddress.IPv4Address(state >> 32)]
            if i % 3 == 0:
                addrs.append(ipaddress.IPv6Address((1 << 125) | ((state * 0x9E3779B97F4A7C15) % (1 << 125))))
            for addr in addrs:
                for reader in (city, asn):
                    found += reader.get(addr) is not None
        assert found > 500
        assert city._cache and asn._cache           # real pointer targets are small enough to stay cached,
        assert max(items for _, items, _, _ in city._cache.values()) > 1   # shared city sub-maps included (29 items)
