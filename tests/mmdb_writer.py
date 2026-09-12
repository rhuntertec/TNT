"""Synthetic MaxMind DB writer for the tests (a helper module, not collected by pytest).

Builds small, valid ``.mmdb`` files in memory - the search tree, the 16-byte separator, the data
section and the metadata - so the reader (``tnt/mmdb.py``) and the IP location manager can be
tested without a real DB-IP file.  Pure stdlib; test data uses documentation ranges only.

The encoders follow the MaxMind DB spec: ``control()`` writes a control byte (extended types and
the 29/30/31 size forms included), ``pointer()`` a 1-4 payload-byte pointer and ``encode_value()``
a whole value, sharing repeated strings and maps through pointers when asked to.  ``Typed``
forces one encoding; the two extra kinds ``"pointer"`` and ``"raw"`` let malformed-file tests
place a pointer or pre-encoded bytes anywhere inside a value.
"""
from __future__ import annotations

import calendar
import gzip
import ipaddress
import os
import struct
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

MARKER = b"\xab\xcd\xefMaxMind.com"

T_POINTER, T_UTF8, T_DOUBLE, T_BYTES, T_UINT16, T_UINT32, T_MAP = 1, 2, 3, 4, 5, 6, 7
T_INT32, T_UINT64, T_UINT128, T_ARRAY, T_CACHE, T_END, T_BOOLEAN, T_FLOAT = 8, 9, 10, 11, 12, 13, 14, 15

_UINT_KINDS = {"uint16": (T_UINT16, 16), "uint32": (T_UINT32, 32), "uint64": (T_UINT64, 64),
               "uint128": (T_UINT128, 128)}
_KINDS = ("utf8", "double", "float", "bytes", "uint16", "uint32", "uint64", "uint128", "int32", "boolean",
          "pointer", "raw")


class Typed:
    """Force an encoding: Typed("uint16", 5), Typed("int32", -3), Typed("float", 1.5), Typed("bytes", b"\\x00").

    Two test-only kinds: Typed("pointer", offset) or Typed("pointer", (offset, payload_bytes)) writes a pointer,
    and Typed("raw", b"...") inserts already-encoded bytes verbatim.
    """

    __slots__ = ("kind", "value")

    def __init__(self, kind: str, value: Any) -> None:
        if kind not in _KINDS:
            raise ValueError(f"unknown kind {kind!r}")
        self.kind = kind
        self.value = value

    def __repr__(self) -> str:
        return f"Typed({self.kind!r}, {self.value!r})"


def control(type_id: int, size: int) -> bytes:
    """The control byte(s) for a value of ``type_id`` (2..262, pointers excluded) and ``size``."""
    if type_id == T_POINTER or not 2 <= type_id <= 7 + 255:
        raise ValueError(f"control() does not write type {type_id}")
    if size < 0:
        raise ValueError("negative size")
    if size < 29:
        bits, ext = size, b""
    elif size < 285:
        bits, ext = 29, bytes([size - 29])
    elif size < 65821:
        bits, ext = 30, (size - 285).to_bytes(2, "big")
    elif size < 65821 + (1 << 24):
        bits, ext = 31, (size - 65821).to_bytes(3, "big")
    else:
        raise ValueError(f"size {size} is too large")
    if type_id <= 7:
        return bytes([(type_id << 5) | bits]) + ext
    return bytes([bits, type_id - 7]) + ext          # extended: the type byte comes before the size bytes


def pointer(offset: int, size_bytes: Optional[int] = None) -> bytes:
    """A pointer to ``offset`` with 1..4 payload bytes (the smallest that fits when ``size_bytes`` is None)."""
    if offset < 0:
        raise ValueError("negative pointer offset")
    spans = ((1, 0, 1 << 11), (2, 2048, 1 << 19), (3, 526336, 1 << 27), (4, 0, 1 << 32))
    for n, bias, limit in spans:
        if size_bytes is not None and n != size_bytes:
            continue
        value = offset - bias
        if not 0 <= value < limit:
            if size_bytes is not None:
                raise ValueError(f"offset {offset} does not fit a {n}-byte pointer")
            continue
        if n == 4:
            return bytes([0x38]) + value.to_bytes(4, "big")
        payload = value & ((1 << (8 * n)) - 1)
        return bytes([0x20 | ((n - 1) << 3) | (value >> (8 * n))]) + payload.to_bytes(n, "big")
    raise ValueError(f"cannot write a pointer to {offset} with {size_bytes} payload bytes")


def _uint_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _encode_typed(out: bytearray, typed: Typed) -> None:
    kind, value = typed.kind, typed.value
    if kind == "utf8":
        raw = str(value).encode("utf-8")
        out += control(T_UTF8, len(raw)) + raw
    elif kind == "double":
        out += control(T_DOUBLE, 8) + struct.pack(">d", float(value))
    elif kind == "float":
        out += control(T_FLOAT, 4) + struct.pack(">f", float(value))
    elif kind == "bytes":
        raw = bytes(value)
        out += control(T_BYTES, len(raw)) + raw
    elif kind in _UINT_KINDS:
        type_id, bits = _UINT_KINDS[kind]
        if type(value) is not int or not 0 <= value < (1 << bits):
            raise ValueError(f"{value!r} is not a {kind}")
        raw = _uint_bytes(value)
        out += control(type_id, len(raw)) + raw
    elif kind == "int32":
        if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
            raise ValueError(f"{value!r} is not an int32")
        raw = (value & 0xFFFFFFFF).to_bytes(4, "big") if value < 0 else _uint_bytes(value)
        out += control(T_INT32, len(raw)) + raw
    elif kind == "boolean":
        out += control(T_BOOLEAN, 1 if value else 0)
    elif kind == "pointer":
        offset, size_bytes = value if isinstance(value, tuple) else (value, None)
        out += pointer(offset, size_bytes)
    else:                                            # raw
        out += bytes(value)


def _shareable(value: Any) -> bool:
    return isinstance(value, (str, dict, list, tuple))


def _encode_into(out: bytearray, value: Any, share: Optional[Dict[bytes, int]], base: int) -> None:
    if share is not None and _shareable(value):
        canonical = encode_value(value)
        known = share.get(canonical)
        if known is not None:
            ref = pointer(known)
            if len(ref) < len(canonical):
                out += ref
                return
        else:
            share[canonical] = base + len(out)       # registered before the children, which never equal the parent
    if isinstance(value, Typed):
        _encode_typed(out, value)
    elif isinstance(value, bool):
        out += control(T_BOOLEAN, 1 if value else 0)
    elif isinstance(value, str):
        raw = value.encode("utf-8")
        out += control(T_UTF8, len(raw)) + raw
    elif isinstance(value, (bytes, bytearray)):
        out += control(T_BYTES, len(value)) + bytes(value)
    elif isinstance(value, float):
        out += control(T_DOUBLE, 8) + struct.pack(">d", value)
    elif isinstance(value, int):
        if 0 <= value < (1 << 32):
            _encode_typed(out, Typed("uint32", value))
        elif 0 <= value < (1 << 64):
            _encode_typed(out, Typed("uint64", value))
        elif 0 <= value < (1 << 128):
            _encode_typed(out, Typed("uint128", value))
        else:
            _encode_typed(out, Typed("int32", value))   # negative (or too large: ValueError)
    elif isinstance(value, dict):
        out += control(T_MAP, len(value))
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"map key {key!r} is not a string")
            _encode_into(out, key, share, base)
            _encode_into(out, item, share, base)
    elif isinstance(value, (list, tuple)):
        out += control(T_ARRAY, len(value))
        for item in value:
            _encode_into(out, item, share, base)
    else:
        raise ValueError(f"cannot encode {type(value).__name__}")


def encode_value(value: Any, *, share: Optional[Dict[bytes, int]] = None, base: int = 0) -> bytes:
    """Encode ``value`` as it will sit at data-section offset ``base``.

    str->utf8, dict->map, list/tuple->array, bool->boolean, float->double, bytes->bytes, int: 0..2**32-1 uint32,
    <2**64 uint64, <2**128 uint128, negative int32; ``Typed`` forces an encoding.  With ``share`` (canonical bytes ->
    offset, updated in place) repeated strings, map keys and sub-maps are written once and referenced by pointers
    wherever the pointer is shorter.
    """
    out = bytearray()
    _encode_into(out, value, share, base)
    return bytes(out)


def assemble(tree: bytes, data: bytes, metadata: Dict[str, Any], *, separator: bytes = bytes(16)) -> bytes:
    """tree + separator + data + marker + encoded metadata (no validation, so tests can build broken files)."""
    return bytes(tree) + bytes(separator) + bytes(data) + MARKER + encode_value(metadata)


def _network_bits(cidr: str, ip_version: int) -> Tuple[int, int]:
    """(address as an int in the tree's bit width, prefix length in that width)."""
    net = ipaddress.ip_network(cidr)
    if net.version == 4:
        if ip_version == 4:
            return int(net.network_address), net.prefixlen
        return int(net.network_address), 96 + net.prefixlen        # IPv4 goes under ::/96 in a v6 tree
    if ip_version == 4:
        raise ValueError(f"{cidr} is IPv6 but the tree is IPv4")
    return int(net.network_address), net.prefixlen


def _descend(root: List[Any], value: int, nbits: int, depth: int) -> List[Any]:
    """The node reached after ``depth`` bits of ``value``, creating nodes; ValueError when a leaf is in the way."""
    node = root
    for i in range(depth):
        bit = (value >> (nbits - 1 - i)) & 1
        child = node[bit]
        if child is None:
            child = node[bit] = [None, None]
        elif not isinstance(child, list):
            raise ValueError("overlapping networks")
        node = child
    return node


def build_mmdb(networks: Union[Mapping[str, Any], Iterable[Tuple[str, Any]]], *, ip_version: int = 6,
               record_size: int = 28, database_type: str = "DBIP-City-Lite", build_epoch: int = 1788226681,
               languages: Sequence[str] = ("en",), description: Optional[Dict[str, str]] = None,
               binary_format: Tuple[int, int] = (2, 0), ipv4_alias: bool = True, share: bool = True,
               extra_metadata: Optional[Dict[str, Any]] = None) -> bytes:
    """A complete .mmdb file.

    ``networks``: CIDR -> value, non-overlapping (else ValueError).  IPv4 CIDRs go under ::/96 in a v6 tree; with
    ``ipv4_alias`` the ::ffff:0:0/96 subtree points back to the IPv4 start node (a backward reference, like DB-IP).
    The first record written is at data offset 0; identical records are written once when ``share``.
    ``extra_metadata`` entries are applied last; a None value removes that key.
    """
    if ip_version not in (4, 6):
        raise ValueError("ip_version must be 4 or 6")
    if record_size not in (24, 28, 32):
        raise ValueError("record_size must be 24, 28 or 32")
    items = list(networks.items()) if isinstance(networks, Mapping) else list(networks)
    nbits = 32 if ip_version == 4 else 128
    data = bytearray()
    shared: Optional[Dict[bytes, int]] = {} if share else None
    root: List[Any] = [None, None]
    for cidr, value in items:
        offset = shared.get(encode_value(value)) if shared is not None else None
        if offset is None:
            offset = len(data)
            data += encode_value(value, share=shared, base=offset)
        addr, prefix = _network_bits(cidr, ip_version)
        if prefix == 0:
            raise ValueError("a /0 network is not supported")
        parent = _descend(root, addr, nbits, prefix - 1)
        bit = (addr >> (nbits - prefix)) & 1
        if parent[bit] is not None:
            raise ValueError(f"overlapping networks at {cidr}")
        parent[bit] = ("data", offset)
    if ip_version == 6 and ipv4_alias:
        ipv4_start = _descend(root, 0, 128, 96)
        mapped = int(ipaddress.IPv6Address("::ffff:0:0"))
        parent = _descend(root, mapped, 128, 95)
        if parent[1] is not None:
            raise ValueError("a network overlaps ::ffff:0:0/96")
        parent[1] = ("alias", ipv4_start)

    order: List[List[Any]] = []                      # depth-first, left before right: the alias points backwards
    index: Dict[int, int] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        index[id(node)] = len(order)
        order.append(node)
        for kid in (node[1], node[0]):
            if isinstance(kid, list):
                stack.append(kid)
    node_count = len(order)

    def record(kid: Any) -> int:
        if kid is None:
            value = node_count
        elif isinstance(kid, list):
            value = index[id(kid)]
        elif kid[0] == "data":
            value = node_count + 16 + kid[1]
        else:
            value = index[id(kid[1])]
        if value >= (1 << record_size):
            raise ValueError(f"record {value} does not fit {record_size} bits")
        return value

    tree = bytearray()
    for node in order:
        left, right = record(node[0]), record(node[1])
        if record_size == 24:
            tree += left.to_bytes(3, "big") + right.to_bytes(3, "big")
        elif record_size == 28:
            tree += (left & 0xFFFFFF).to_bytes(3, "big") + bytes([(left >> 24) << 4 | (right >> 24)])
            tree += (right & 0xFFFFFF).to_bytes(3, "big")
        else:
            tree += struct.pack(">II", left, right)

    metadata: Dict[str, Any] = {
        "binary_format_major_version": Typed("uint16", binary_format[0]),
        "binary_format_minor_version": Typed("uint16", binary_format[1]),
        "build_epoch": Typed("uint64", build_epoch),
        "database_type": database_type,
        "ip_version": Typed("uint16", ip_version),
        "languages": list(languages),
        "node_count": Typed("uint32", node_count),
        "record_size": Typed("uint16", record_size),
    }
    if description is not None:
        metadata["description"] = dict(description)
    for key, value in (extra_metadata or {}).items():
        if value is None:
            metadata.pop(key, None)
        else:
            metadata[key] = value
    return assemble(bytes(tree), bytes(data), metadata)


def write_mmdb(path: Union[str, os.PathLike], networks: Union[Mapping[str, Any], Iterable[Tuple[str, Any]]],
               **kw: Any) -> Path:
    """build_mmdb(networks, **kw) written to ``path``."""
    target = Path(path)
    target.write_bytes(build_mmdb(networks, **kw))
    return target


def gzip_bytes(data: bytes, mtime: int = 0) -> bytes:
    """Deterministic gzip of ``data`` (no file name, fixed mtime)."""
    return gzip.compress(data, mtime=mtime)


_CONTINENTS = {"AF": (6255146, "Africa"), "AN": (6255152, "Antarctica"), "AS": (6255147, "Asia"),
               "EU": (6255148, "Europe"), "NA": (6255149, "North America"), "OC": (6255151, "Oceania"),
               "SA": (6255150, "South America")}
_COUNTRY_IDS = {"CA": 6251999, "GB": 2635167, "US": 6252001}


def city_record(city: Optional[str], region: Optional[str], country_code: str, country: str,
                lat: float, lon: float, continent: str = "NA") -> Dict[str, Any]:
    """A record in the DB-IP City Lite shape; ``city``/``subdivisions`` are left out when None."""
    continent_id, continent_name = _CONTINENTS.get(continent, (0, continent))
    record: Dict[str, Any] = {}
    if city is not None:
        record["city"] = {"names": {"en": city}}
    record["continent"] = {"code": continent, "geoname_id": continent_id, "names": {"en": continent_name}}
    record["country"] = {"geoname_id": _COUNTRY_IDS.get(country_code, 0), "is_in_european_union": False,
                         "iso_code": country_code, "names": {"en": country}}
    record["location"] = {"latitude": float(lat), "longitude": float(lon)}
    if region is not None:
        record["subdivisions"] = [{"names": {"en": region}}]
    return record


def asn_record(asn: int, org: str) -> Dict[str, Any]:
    """A record in the DB-IP ASN Lite shape."""
    return {"autonomous_system_number": asn, "autonomous_system_organization": org}


def month_epoch(month: str) -> int:
    """01:38:01 UTC on the 1st of "YYYY-MM" (DB-IP's usual build time)."""
    year, mon = (int(part) for part in month.split("-"))
    return calendar.timegm((year, mon, 1, 1, 38, 1, 0, 0, 0))


CITY_FIXTURE = [
    ("203.0.113.0/25", city_record("Anytown", "Texas", "US", "United States", 32.95, -96.73)),
    ("203.0.113.128/25", city_record("Dallas", "Texas", "US", "United States", 32.78, -96.80)),
    ("198.51.100.0/24", city_record("Richardson (Canyon Creek)", "Texas", "US", "United States", 32.95, -96.73)),
    ("192.0.2.0/24", city_record("Montreal", "Quebec", "CA", "Canada", 45.50, -73.57)),
    ("2001:db8::/32", city_record("London", "England", "GB", "United Kingdom", 51.51, -0.13, continent="EU")),
]
ASN_FIXTURE = [
    ("203.0.113.0/24", asn_record(64500, "Example Broadband ")),      # trailing space: isp_text strips it
    ("198.51.100.0/24", asn_record(64510, "Example Transit, Inc.")),
    ("2001:db8::/32", asn_record(64511, "Example Hosting LLC")),
]
VERIFY_PROBES_FIXTURE = {
    "city": {"present": ("203.0.113.9", "198.51.100.7"), "absent": ("10.0.0.1",)},
    "asn": {"present": ("203.0.113.9", "198.51.100.7"), "absent": ("10.0.0.1",)},
}


def fixture_pair(month: str = "2026-09", *, city_record_size: int = 28,
                 asn_record_size: int = 24) -> Tuple[bytes, bytes]:
    """(city .mmdb bytes "DBIP-City-Lite", asn .mmdb bytes "DBIP-ASN-Lite (compat=GeoLite2-ASN)") built for ``month``."""
    epoch = month_epoch(month)
    city = build_mmdb(CITY_FIXTURE, record_size=city_record_size, database_type="DBIP-City-Lite", build_epoch=epoch)
    asn = build_mmdb(ASN_FIXTURE, record_size=asn_record_size, database_type="DBIP-ASN-Lite (compat=GeoLite2-ASN)",
                     build_epoch=epoch)
    return city, asn
