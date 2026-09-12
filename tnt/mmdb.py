"""Pure-stdlib MaxMind DB (``.mmdb``) reader for the DB-IP Lite city and ASN files.

The file is memory-mapped read-only (``mmap``), so a lookup touches only the pages it needs and the
~130 MB city file costs no Python memory.  The map keeps the file locked on Windows until
:meth:`Reader.close`; no memoryview of the map is ever kept, so closing never raises ``BufferError``.

Layout of a MaxMind DB file (spec: https://maxmind.github.io/MaxMind-DB/):

* a binary search tree of ``node_count`` nodes, two records of ``record_size`` bits each;
* 16 zero bytes, then the data section, whose values the tree's terminal records point into;
* ``\\xab\\xcd\\xefMaxMind.com`` and the metadata map, found near the end of the file.

Everything read from the file is bounds-checked, and a decode is limited in nesting depth and in
the items and bytes it may produce (pointer expansions included), so a corrupt or hostile file
raises :class:`MmdbError` instead of looping, recursing away or exhausting memory.  Small decoded
pointer targets are cached per reader; results are always fresh copies, so callers may mutate them.

``SELFCHECK_MMDB`` is a tiny valid IPv4 database (one /24 of the documentation range) that the
frozen build's ``--selfcheck`` writes to a temporary file to exercise mmap and the decoder offline.
"""
from __future__ import annotations

import ipaddress
import mmap
import os
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"
METADATA_WINDOW = 128 * 1024          # the marker is searched for in the last 128 KiB only
DATA_SECTION_SEPARATOR = 16           # zero bytes between the search tree and the data section
MAX_DEPTH = 32                        # nesting limit, pointer hops included
POINTER_CACHE_MAX = 4096              # decoded pointer targets kept per Reader (cleared when full)
POINTER_CACHE_ITEMS_MAX = 256         # a target decoding to more items is not kept (real DB-IP targets are <= 78 items)
MAX_ITEMS_PER_RECORD = 4096           # decoded values per top-level decode (map keys included), pointer expansions included
MAX_RECORD_BYTES = 1024 * 1024        # utf8 + bytes payload bytes per top-level decode, pointer expansions included
RECORD_SIZES = (24, 28, 32)
SELFCHECK_IP = "203.0.113.9"
SELFCHECK_RECORD = {"tnt": "selfcheck"}
#: build_mmdb([("203.0.113.0/24", {"tnt": "selfcheck"})], ip_version=4, record_size=24, database_type="TNT-Selfcheck",
#: build_epoch=0, languages=(), share=False) from tests/mmdb_writer.py (tests/test_mmdb.py checks it still matches)
SELFCHECK_MMDB = (
    b"\x00\x00\x18\x00\x00\x01\x00\x00\x18\x00\x00\x02\x00\x00\x03\x00\x00\x18\x00\x00\x04\x00\x00\x18"
    b"\x00\x00\x18\x00\x00\x05\x00\x00\x06\x00\x00\x18\x00\x00\x18\x00\x00\x07\x00\x00\x18\x00\x00\x08"
    b"\x00\x00\x09\x00\x00\x18\x00\x00\x0a\x00\x00\x18\x00\x00\x0b\x00\x00\x18\x00\x00\x0c\x00\x00\x18"
    b"\x00\x00\x0d\x00\x00\x18\x00\x00\x0e\x00\x00\x18\x00\x00\x0f\x00\x00\x18\x00\x00\x10\x00\x00\x18"
    b"\x00\x00\x11\x00\x00\x18\x00\x00\x18\x00\x00\x12\x00\x00\x18\x00\x00\x13\x00\x00\x18\x00\x00\x14"
    b"\x00\x00\x15\x00\x00\x18\x00\x00\x16\x00\x00\x18\x00\x00\x17\x00\x00\x18\x00\x00\x18\x00\x00\x28"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe1\x43\x74\x6e\x74\x49\x73\x65"
    b"\x6c\x66\x63\x68\x65\x63\x6b\xab\xcd\xef\x4d\x61\x78\x4d\x69\x6e\x64\x2e\x63\x6f\x6d\xe8\x5b\x62"
    b"\x69\x6e\x61\x72\x79\x5f\x66\x6f\x72\x6d\x61\x74\x5f\x6d\x61\x6a\x6f\x72\x5f\x76\x65\x72\x73\x69"
    b"\x6f\x6e\xa1\x02\x5b\x62\x69\x6e\x61\x72\x79\x5f\x66\x6f\x72\x6d\x61\x74\x5f\x6d\x69\x6e\x6f\x72"
    b"\x5f\x76\x65\x72\x73\x69\x6f\x6e\xa0\x4b\x62\x75\x69\x6c\x64\x5f\x65\x70\x6f\x63\x68\x00\x02\x4d"
    b"\x64\x61\x74\x61\x62\x61\x73\x65\x5f\x74\x79\x70\x65\x4d\x54\x4e\x54\x2d\x53\x65\x6c\x66\x63\x68"
    b"\x65\x63\x6b\x4a\x69\x70\x5f\x76\x65\x72\x73\x69\x6f\x6e\xa1\x04\x49\x6c\x61\x6e\x67\x75\x61\x67"
    b"\x65\x73\x00\x04\x4a\x6e\x6f\x64\x65\x5f\x63\x6f\x75\x6e\x74\xc1\x18\x4b\x72\x65\x63\x6f\x72\x64"
    b"\x5f\x73\x69\x7a\x65\xa1\x18"
)
__all__ = ["Reader", "MmdbError", "METADATA_MARKER", "SELFCHECK_MMDB", "SELFCHECK_IP", "SELFCHECK_RECORD"]

_POINTER, _UTF8, _DOUBLE, _BYTES, _UINT16, _UINT32, _MAP = 1, 2, 3, 4, 5, 6, 7
_INT32, _UINT64, _UINT128, _ARRAY, _BOOLEAN, _FLOAT = 8, 9, 10, 11, 14, 15
_UINT_MAX_SIZE = {_UINT16: 2, _UINT32: 4, _UINT64: 8, _UINT128: 16}
_SIZE_BASE = (29, 285, 65821)         # sizes 29/30/31 add 1/2/3 big-endian bytes to these
_LCG_MUL = 6364136223846793005        # self_check's deterministic bit paths (never the random module)
_LCG_INC = 1442695040888963407
_MASK64 = (1 << 64) - 1

Address = Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]


class MmdbError(ValueError):
    """The file is not a valid/supported MaxMind DB, or a lookup met corrupt data."""


def _copy(value: Any) -> Any:
    """A recursive copy of the containers in a decoded value (scalars are immutable and shared)."""
    kind = type(value)
    if kind is dict:
        return {key: _copy(item) for key, item in value.items()}
    if kind is list:
        return [_copy(item) for item in value]
    return value


def _parse_address(ip: Address) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
    if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return ip
    if not isinstance(ip, str):
        raise TypeError(f"expected an IP address string, not {type(ip).__name__}")
    text = ip.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return ipaddress.ip_address(text.split("%", 1)[0])       # ValueError for anything unparsable


def _lcg_bits(seed: int, nbits: int) -> int:
    state = (seed * 0x9E3779B97F4A7C15 + 0x2545F4914F6CDD1D) & _MASK64
    value = have = 0
    while have < nbits:
        state = (state * _LCG_MUL + _LCG_INC) & _MASK64
        value = (value << 32) | (state >> 32)
        have += 32
    return value >> (have - nbits)


def _meta_int(meta: Dict[str, Any], key: str) -> int:
    value = meta.get(key)
    if type(value) is not int:                               # a boolean is not an integer here
        raise MmdbError(f"metadata {key} is missing or not an integer")
    return value


class Reader:
    """A read-only, memory-mapped MaxMind DB.  ``get()`` may be called from several threads; ``close()`` must not
    race a ``get()`` (the caller serialises them)."""

    def __init__(self, path: Union[str, os.PathLike], *, cache_size: int = POINTER_CACHE_MAX) -> None:
        self._path = os.fsdecode(os.fspath(path))
        self._cache_size = max(0, int(cache_size))
        self._cache: Dict[int, Tuple[Any, int, int, int]] = {}   # target offset -> (value, items, bytes, height)
        self._closed = True
        with open(self._path, "rb") as f:
            if os.fstat(f.fileno()).st_size == 0:
                raise MmdbError("empty file")               # mmap of size 0 fails on Windows
            self._buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            self._open()
        except BaseException:
            self._buf.close()
            raise
        self._closed = False

    def _open(self) -> None:
        buf = self._buf
        size = self._size = len(buf)
        idx = buf.rfind(METADATA_MARKER, max(0, size - METADATA_WINDOW))
        if idx < 0:
            raise MmdbError("not a MaxMind DB file: metadata marker not found")
        meta_start = idx + len(METADATA_MARKER)
        meta = self._decode_top(meta_start, meta_start, size, False)
        if not isinstance(meta, dict):
            raise MmdbError("metadata is not a map")
        major = _meta_int(meta, "binary_format_major_version")
        if major != 2:
            raise MmdbError(f"unsupported binary format version {major}")
        node_count = _meta_int(meta, "node_count")
        if not 1 <= node_count < 2 ** 32:
            raise MmdbError("metadata node_count is out of range")
        record_size = _meta_int(meta, "record_size")
        if record_size not in RECORD_SIZES:
            raise MmdbError(f"unsupported record size {record_size}")
        ip_version = _meta_int(meta, "ip_version")
        if ip_version not in (4, 6):
            raise MmdbError(f"unsupported ip_version {ip_version}")
        database_type = meta.get("database_type")
        if type(database_type) is not str:
            raise MmdbError("metadata database_type is missing or not a string")
        build_epoch = _meta_int(meta, "build_epoch")
        if build_epoch < 0:
            raise MmdbError("metadata build_epoch is negative")
        if "languages" in meta and not isinstance(meta["languages"], list):
            raise MmdbError("metadata languages is not a list")
        if "description" in meta and not isinstance(meta["description"], dict):
            raise MmdbError("metadata description is not a map")

        node_bytes = record_size * 2 // 8
        tree_size = node_count * node_bytes
        data_start = tree_size + DATA_SECTION_SEPARATOR
        if data_start > idx:
            raise MmdbError("search tree overlaps the metadata")
        if buf[tree_size:data_start] != bytes(DATA_SECTION_SEPARATOR):
            raise MmdbError("the data section separator is not zero")
        self._metadata = meta
        self._node_count = node_count
        self._record_size = record_size
        self._node_bytes = node_bytes
        self._ip_version = ip_version
        self._database_type = database_type
        self._build_epoch = build_epoch
        self._data_start = data_start
        self._data_end = idx
        node = 0
        if ip_version == 6:                                  # IPv4 lives under ::/96: walk 96 zero bits once
            for _ in range(96):
                if node >= node_count:
                    break
                node = self._read_record(node, 0)
        self._ipv4_start = node

    # ------------------------------------------------------------------ properties
    @property
    def path(self) -> str:
        return self._path

    @property
    def size(self) -> int:
        return self._size

    @property
    def metadata(self) -> Dict[str, Any]:
        return _copy(self._metadata)

    @property
    def node_count(self) -> int:
        return self._node_count

    @property
    def record_size(self) -> int:
        return self._record_size

    @property
    def ip_version(self) -> int:
        return self._ip_version

    @property
    def database_type(self) -> str:
        return self._database_type

    @property
    def build_epoch(self) -> int:
        return self._build_epoch

    @property
    def closed(self) -> bool:
        return self._closed

    # ------------------------------------------------------------------ lookups
    def get(self, ip: Address) -> Optional[Any]:
        """The record for ``ip``, or None when the database has none."""
        return self.get_with_prefix_len(ip)[0]

    def get_with_prefix_len(self, ip: Address) -> Tuple[Optional[Any], int]:
        """(record or None, prefix length of the network it belongs to, in ``ip``'s own family)."""
        self._check_open()
        addr = _parse_address(ip)
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        if addr.version == 4:
            record, prefix = self._walk(int(addr), 32, self._ipv4_start)
        elif self._ip_version == 4:
            return None, 0
        else:
            record, prefix = self._walk(int(addr), 128, 0)
        return self._resolve(record), prefix

    def _check_open(self) -> None:
        if self._closed:
            raise MmdbError("reader is closed")

    def _read_record(self, node: int, bit: int) -> int:
        buf, offset = self._buf, node * self._node_bytes
        if self._record_size == 24:
            offset += 3 * bit
            return int.from_bytes(buf[offset:offset + 3], "big")
        if self._record_size == 32:
            offset += 4 * bit
            return int.from_bytes(buf[offset:offset + 4], "big")
        b = buf[offset:offset + 7]
        if bit:
            return ((b[3] & 0x0F) << 24) | (b[4] << 16) | (b[5] << 8) | b[6]
        return ((b[3] >> 4) << 24) | (b[0] << 16) | (b[1] << 8) | b[2]

    def _walk(self, value: int, bits: int, node: int) -> Tuple[int, int]:
        """Follow ``bits`` bits of ``value`` (MSB first) from ``node``: (terminal record, bits consumed)."""
        node_count = self._node_count
        if node >= node_count:
            return node, 0
        read = self._read_record
        for depth in range(bits):
            node = read(node, (value >> (bits - 1 - depth)) & 1)
            if node >= node_count:
                return node, depth + 1
        raise MmdbError("invalid search tree")

    def _resolve(self, record: int) -> Optional[Any]:
        node_count = self._node_count
        if record == node_count:
            return None
        if record < node_count + 16:
            raise MmdbError("invalid search tree record")
        offset = self._data_start + (record - node_count - 16)
        if offset >= self._data_end:
            raise MmdbError("search tree record points past the data section")
        return self._decode_top(offset, self._data_start, self._data_end, True)

    # ------------------------------------------------------------------ data section decoder
    def _decode_data(self, offset: int) -> Any:
        """Test seam: decode one value at a data-section offset with a fresh budget."""
        self._check_open()
        if not 0 <= offset < self._data_end - self._data_start:
            raise MmdbError("data offset out of range")
        return self._decode_top(self._data_start + offset, self._data_start, self._data_end, True)

    def _decode_top(self, offset: int, start: int, end: int, cache: bool) -> Any:
        budget = [0, 0, 0]                                   # items, payload bytes, deepest level reached
        try:
            value, _ = self._decode(offset, start, end, 0, budget, cache and self._cache_size > 0)
        except (IndexError, struct.error) as exc:            # belt and braces: every read is bounds-checked
            raise MmdbError(f"corrupt data: {exc}") from None
        return value

    def _decode(self, off: int, start: int, end: int, depth: int, budget: List[int], cache: bool) -> Tuple[Any, int]:
        if depth > MAX_DEPTH:
            raise MmdbError("nesting too deep")
        if depth > budget[2]:
            budget[2] = depth
        if not start <= off < end:
            raise MmdbError("data offset out of bounds")
        buf = self._buf
        ctrl = buf[off]
        off += 1
        kind = ctrl >> 5
        if kind == _POINTER:
            return self._decode_pointer(ctrl, off, start, end, depth, budget, cache)
        if kind == 0:                                        # extended: the next byte holds type - 7
            if off >= end:
                raise MmdbError("value runs past the section")
            kind = 7 + buf[off]
            off += 1
            if not 8 <= kind <= 15:
                raise MmdbError(f"invalid extended type {kind}")
        size = ctrl & 0x1F
        if size >= 29:
            n = size - 28
            if off + n > end:
                raise MmdbError("value runs past the section")
            size = _SIZE_BASE[n - 1] + int.from_bytes(buf[off:off + n], "big")
            off += n
        budget[0] += 1
        if budget[0] > MAX_ITEMS_PER_RECORD:
            raise MmdbError("record too large")
        remaining = end - off

        if kind == _MAP:
            if size > remaining:
                raise MmdbError("map size runs past the section")
            result: Dict[str, Any] = {}
            child = depth + 1
            for _ in range(size):
                key, off = self._decode(off, start, end, child, budget, cache)
                if type(key) is not str:
                    raise MmdbError("map key is not a string")
                value, off = self._decode(off, start, end, child, budget, cache)
                result[key] = value
            return result, off
        if kind == _UTF8 or kind == _BYTES:
            if size > remaining:
                raise MmdbError("value runs past the section")
            budget[1] += size
            if budget[1] > MAX_RECORD_BYTES:
                raise MmdbError("record too large")
            raw = buf[off:off + size]
            return (raw.decode("utf-8", errors="replace") if kind == _UTF8 else bytes(raw)), off + size
        if kind in _UINT_MAX_SIZE:
            if size > _UINT_MAX_SIZE[kind]:
                raise MmdbError(f"invalid size {size} for an unsigned integer")
            if size > remaining:
                raise MmdbError("value runs past the section")
            return int.from_bytes(buf[off:off + size], "big"), off + size
        if kind == _ARRAY:
            if size > remaining:
                raise MmdbError("array size runs past the section")
            items: List[Any] = []
            child = depth + 1
            for _ in range(size):
                value, off = self._decode(off, start, end, child, budget, cache)
                items.append(value)
            return items, off
        if kind == _DOUBLE or kind == _FLOAT:
            width = 8 if kind == _DOUBLE else 4
            if size != width:
                raise MmdbError(f"invalid size {size} for a {'double' if width == 8 else 'float'}")
            if size > remaining:
                raise MmdbError("value runs past the section")
            return struct.unpack(">d" if width == 8 else ">f", buf[off:off + size])[0], off + size
        if kind == _BOOLEAN:
            if size > 1:
                raise MmdbError(f"invalid size {size} for a boolean")
            return size == 1, off
        if kind == _INT32:
            if size > 4:
                raise MmdbError(f"invalid size {size} for an int32")
            if size > remaining:
                raise MmdbError("value runs past the section")
            value = int.from_bytes(buf[off:off + size], "big")
            if size == 4 and value & 0x80000000:
                value -= 1 << 32
            return value, off + size
        raise MmdbError(f"unsupported data type {kind}")      # 12 data cache container, 13 end marker

    def _decode_pointer(self, ctrl: int, off: int, start: int, end: int, depth: int, budget: List[int],
                        cache: bool) -> Tuple[Any, int]:
        ss = (ctrl >> 3) & 0x3
        n = ss + 1
        if off + n > end:
            raise MmdbError("pointer runs past the section")
        b = self._buf[off:off + n]
        vvv = ctrl & 0x7
        if ss == 0:
            value = (vvv << 8) | b[0]
        elif ss == 1:
            value = ((vvv << 16) | (b[0] << 8) | b[1]) + 2048
        elif ss == 2:
            value = ((vvv << 24) | (b[0] << 16) | (b[1] << 8) | b[2]) + 526336
        else:
            value = int.from_bytes(b, "big")                 # VVV is ignored for 4-byte pointers
        after = off + n                                      # decoding resumes here, never after the target
        target = start + value
        if target >= end:
            raise MmdbError("pointer out of bounds")
        if self._buf[target] >> 5 == _POINTER:
            raise MmdbError("pointer to a pointer")
        child = depth + 1
        if cache:
            hit = self._cache.get(target)
            if hit is not None:
                result, items, nbytes, height = hit
                if child + height > MAX_DEPTH:
                    raise MmdbError("nesting too deep")
                budget[0] += items
                budget[1] += nbytes
                if budget[0] > MAX_ITEMS_PER_RECORD or budget[1] > MAX_RECORD_BYTES:
                    raise MmdbError("record too large")
                if child + height > budget[2]:
                    budget[2] = child + height
                return _copy(result), after
        items0, bytes0, deepest = budget
        budget[2] = child
        result, _ = self._decode(target, start, end, child, budget, cache)
        height = budget[2] - child
        if deepest > budget[2]:
            budget[2] = deepest
        items = budget[0] - items0                           # nested pointer expansions included
        if cache and items <= POINTER_CACHE_ITEMS_MAX:       # bounds what the cache holds, not just its entry count
            if len(self._cache) >= self._cache_size:
                self._cache.clear()
            self._cache[target] = (result, items, budget[1] - bytes0, height)
            result = _copy(result)
        return result, after

    # ------------------------------------------------------------------ verification and lifecycle
    def self_check(self, samples: int = 64) -> None:
        """Walk ``samples`` deterministic pseudo-random tree paths and decode what they reach; MmdbError on the first
        failure.  In an IPv6 tree even samples walk the IPv4 subtree and odd samples 2000::/3, the parts lookups use."""
        self._check_open()
        if self._data_start < self._data_end:
            self._decode_data(0)
        node_count = self._node_count
        ipv4_start = self._ipv4_start
        for i in range(max(0, samples)):
            if self._ip_version == 4:
                record, _ = self._walk(_lcg_bits(i, 32), 32, 0)
            elif i % 2 == 0:
                if ipv4_start >= node_count:
                    continue
                record, _ = self._walk(_lcg_bits(i, 32), 32, ipv4_start)
            else:
                path = (_lcg_bits(i, 128) & ((1 << 125) - 1)) | (1 << 125)   # first three bits 001
                record, _ = self._walk(path, 128, 0)
            self._check_terminal(record)
        if ipv4_start >= node_count:
            self._check_terminal(ipv4_start)

    def _check_terminal(self, record: int) -> None:
        if record != self._node_count and not isinstance(self._resolve(record), dict):
            raise MmdbError("a search tree record does not point to a map")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._cache.clear()
        self._buf.close()

    def __enter__(self) -> "Reader":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self._closed else getattr(self, "_database_type", "?")
        return f"<mmdb.Reader {os.path.basename(self._path)} {state}>"
