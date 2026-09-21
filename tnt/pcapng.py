"""Pure-stdlib pcapng reader and Wi-Fi rewriter for the switch-port lookup and packet capture (ARCHITECTURE §3.24).

Original code written from the pcapng specification (IETF draft-ietf-opsawg-pcapng, the PCAP Next Generation capture
file format), IEEE 802.11 (the MAC data frame format and A-MSDU subframes), and RFC 1042 and IEEE 802.1H (SNAP
encapsulation). Nothing here opens a socket or runs a program, and files are read one block at a time.

Blocks
------
Every block is ``u32 type, u32 total length, body, u32 total length`` in its section's byte order. The types read here
are the Section Header Block (SHB, 0x0A0D0D0A), Interface Description Block (IDB, 1), the obsolete Packet Block (PB,
2), the Simple Packet Block (SPB, 3) and the Enhanced Packet Block (EPB, 6). Every other block (name resolution,
interface statistics, ...) is framed and validated like the rest, then passed over or copied unchanged.

Validation (every reader)
-------------------------
* The first block is an SHB, and every SHB's byte-order magic reads 0x1A2B3C4D in one of the two byte orders. Each SHB
  starts a new section with its own byte order and its own interface (IDB) table.
* Every block length is at least 12 (and at least the fixed part of its type: SHB 28, IDB 20, SPB 16, EPB/PB 32), a
  multiple of 4, at most :data:`MAX_BLOCK`, inside the file, and equal to the trailing copy.
* EPB (and PB, whose interface id is a u16): ``28 + pad4(caplen) + 4 <= block length``, and the interface id indexes
  the current section's IDB table.
* SPB: belongs to IDB 0 of its section; ``caplen = min(origlen, block length - 16, snaplen or unlimited)``.

Anything else raises :class:`PcapngError` (a ValueError). IDB options are read for ``if_tsresol`` (option 9) only; a
malformed option list keeps the default resolution.

Timestamps
----------
``ts`` is float seconds since 1970: the 64-bit EPB/PB timestamp divided by the interface's resolution. ``if_tsresol``
with bit 7 set means ``2^-(v & 0x7F)`` s, otherwise ``10^-v`` s; the default is 10^-6. An SPB carries no timestamp
(``ts`` None).

PACKET dict (keys in this order, :data:`PACKET_KEYS`)::

    {"interface": int, "linktype": int, "ts": float|None, "caplen": int, "origlen": int, "data": bytes}

Readers
-------
* :func:`iter_blocks` yields ``(endian "<"|">", block_type, body)`` per block, holding one block in memory.
* :func:`iter_packets` yields PACKET dicts for every EPB, SPB and PB (optionally at most ``max_packets``).
* :func:`read_packets` does the same for an in-memory buffer of at most :data:`MAX_IN_MEMORY` bytes (the switch-port
  lookup's small LLDP/CDP capture).
* :func:`count_packets` counts EPB + SPB + PB in a file of any size: it reads block headers (and the 20 fixed bytes of
  each EPB/PB) and seeks past the bodies, so memory stays constant (the packet capture file list).
* :func:`iter_packets_with_offsets` yields ``(block offset, PACKET)``, which is how the live capture indexes a file it
  opened, and :func:`read_packet_at` reads one packet back from such an offset (None for anything that is not a packet
  block there, never an error). A file may hold several interfaces (Wireshark's "all interfaces", a mergecap) and
  several sections, so the packet is read with the byte order, link type and timestamp resolution of *its own*
  section and interface: the block headers before it are walked once (bodies skipped, IDBs read) and that interface
  table is remembered per file, resuming where it stopped for a file that grows. Only a file whose blocks before the
  packet cannot be walked falls back to the caller's byte order / link type / resolution for interface 0.

Writing
-------
:class:`Writer` writes a one-interface file: a little-endian SHB (``shb_userappl``) and IDB (``if_name`` and
``if_tsresol`` 10^-6 s), then an EPB per :meth:`Writer.write_packet`, which returns the block's offset for the index
above. The live capture writes every frame it receives through it, so the file on disk is the capture and only a
summary per packet stays in memory. A packet over ``Writer.MAX_PACKET`` raises :class:`PcapngError` before anything is
written.

Wi-Fi rewrite
-------------
Packet Monitor labels a Wi-Fi adapter's capture as Ethernet (link type 1) although the frames are 802.11 data frames
(payload already decrypted). :func:`rewrite_dot11_to_ethernet` streams a file block by block into ``<dst>.part`` and
then moves it over ``dst``. For each EPB, in this order: :func:`dot11_to_ethernet` converts the frame; only when that
fails, a frame whose bytes 12-13 are a known ethertype (:data:`KNOWN_ETHERTYPES`) is kept as it is; anything else is
dropped and counted. EPB options are copied, while caplen, padding and both block lengths are recomputed. SHB, IDB, NRB
and every other block are copied unchanged. The result is ``{"converted", "kept_ethernet", "dropped"}``
(:data:`REWRITE_KEYS`).

:func:`dot11_to_ethernet` accepts data frames only (protocol version 0, type 2) and skips the subtypes without a payload
(``subtype & 4``: null function, QoS null, ...). The MAC header is 24 bytes, +6 when both ToDS and FromDS are set
(Address 4), +2 for QoS data (``subtype & 8``) and +4 more when a QoS frame has the Order bit (HT Control). The
Ethernet addresses come from the DS bits:

    ======  ========  ====  ============
    ToDS    FromDS    DA    SA
    ======  ========  ====  ============
    0       0         a1    a2
    1       0         a3    a2
    0       1         a1    a3
    1       1         a3    a4
    ======  ========  ====  ============

An RFC 1042 (``AA AA 03 00 00 00``) or bridge-tunnel (``AA AA 03 00 00 F8``) SNAP header right after the MAC header
gives ``DA SA ethertype payload`` with ``origlen' = max(len, origlen - (hl + 6) + 12)``. The QoS A-MSDU bit alone is no
reason to drop a frame: some drivers leave it set on frames they have already de-aggregated, and those carry SNAP
right after the header. Only when SNAP is not there and the A-MSDU bit is set is the first subframe read
(``DA' SA' length n``, then SNAP at ``hl + 14``): the frame becomes ``DA' SA' + p[hl+20 : min(hl+14+n, caplen)]`` with
``origlen' = n + 6`` when the whole subframe was on the wire inside ``origlen``, else ``origlen - (hl + 20) + 12``.
A subframe length under 8 or a missing SNAP fails the conversion; later subframes are never emitted.
"""
from __future__ import annotations

import bisect
import io
import os
import struct
import threading
from collections import OrderedDict
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Tuple, Union

__all__ = ["PcapngError", "MAX_BLOCK", "MAX_IN_MEMORY", "PACKET_KEYS", "REWRITE_KEYS", "KNOWN_ETHERTYPES",
           "iter_blocks", "iter_packets", "read_packets", "count_packets", "dot11_to_ethernet",
           "rewrite_dot11_to_ethernet", "Writer", "iter_packets_with_offsets", "read_packet_at"]

MAX_BLOCK = 16 * 1024 * 1024              # one block of any type
MAX_IN_MEMORY = 64 * 1024 * 1024          # read_packets() refuses a larger buffer
PACKET_KEYS = ("interface", "linktype", "ts", "caplen", "origlen", "data")
REWRITE_KEYS = ("converted", "kept_ethernet", "dropped")

BLOCK_SHB = 0x0A0D0D0A
BLOCK_IDB = 1
BLOCK_PB = 2                              # obsolete Packet Block: like an EPB with a u16 interface id and u16 drops
BLOCK_SPB = 3
BLOCK_EPB = 6
PACKET_BLOCKS = (BLOCK_EPB, BLOCK_SPB, BLOCK_PB)
OPT_END = 0
OPT_IF_TSRESOL = 9
DEFAULT_TS_DIVISOR = 10 ** 6              # no if_tsresol option: microseconds
LINKTYPE_ETHERNET = 1

#: Ethertypes a frame may carry at bytes 12-13 to be kept as Ethernet when the 802.11 conversion fails: IPv4, IPv6,
#: ARP, EAPOL (802.1X), 802.1Q, 802.1ad, LLDP, PROFINET and AVTP.
KNOWN_ETHERTYPES = frozenset((0x0800, 0x86DD, 0x0806, 0x888E, 0x8100, 0x88A8, 0x88CC, 0x8892, 0x22F0))
SNAP_HEADERS = (b"\xaa\xaa\x03\x00\x00\x00",   # RFC 1042
                b"\xaa\xaa\x03\x00\x00\xf8")   # IEEE 802.1H bridge-tunnel

_SHB_TYPE = b"\x0a\x0d\x0d\x0a"           # reads the same in both byte orders
_BYTE_ORDER = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}
_MIN_LENGTH = {BLOCK_SHB: 28, BLOCK_IDB: 20, BLOCK_PB: 32, BLOCK_SPB: 16, BLOCK_EPB: 32}
_PACKET_FIXED = 20                        # EPB/PB fields between the block header and the packet data

PathLike = Union[str, "os.PathLike[str]"]


class PcapngError(ValueError):
    """The data is not a valid pcapng file, or a block in it is malformed."""


def _pad4(size: int) -> int:
    return (size + 3) & ~3


def _read_exact(fileobj: BinaryIO, size: int) -> bytes:
    """*size* bytes, or fewer only at the end of the file."""
    data = fileobj.read(size)
    if len(data) >= size or not data:
        return data
    chunks = [data]
    left = size - len(data)
    while left > 0:
        chunk = fileobj.read(left)
        if not chunk:
            break
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def _read_header(fileobj: BinaryIO, endian: Optional[str], offset: int) -> Optional[Tuple[str, int, int, bytes]]:
    """``(endian, block_type, block_length, magic)`` for the block at *offset*, or None at a clean end of file.

    An SHB's byte-order magic is read with its header (it decides how the length reads) and returned as *magic*, so
    the caller knows 12 bytes were consumed instead of 8."""
    head = _read_exact(fileobj, 8)
    if not head:
        if endian is None:
            raise PcapngError("not a pcapng file: it is empty")
        return None
    if len(head) < 8:
        raise PcapngError(f"truncated block header at offset {offset}")
    magic = b""
    if head[:4] == _SHB_TYPE:
        magic = _read_exact(fileobj, 4)
        if len(magic) < 4:
            raise PcapngError(f"truncated section header at offset {offset}")
        endian = _BYTE_ORDER.get(magic)
        if endian is None:
            raise PcapngError(f"the section header at offset {offset} has no valid byte-order magic")
    elif endian is None:
        raise PcapngError("not a pcapng file: it does not start with a section header")
    block_type, length = struct.unpack(endian + "II", head)
    if length < 12 or length % 4 or length > MAX_BLOCK:
        raise PcapngError(f"bad block length {length} at offset {offset}")
    minimum = _MIN_LENGTH.get(block_type, 12)
    if length < minimum:
        raise PcapngError(f"block type {block_type} at offset {offset} is {length} bytes, under its {minimum} byte "
                          "minimum")
    return endian, block_type, length, magic


def _check_trailer(endian: str, trailer: bytes, length: int, offset: int) -> None:
    if len(trailer) < 4:
        raise PcapngError(f"the block at offset {offset} runs past the end of the file")
    (copy,) = struct.unpack(endian + "I", trailer)
    if copy != length:
        raise PcapngError(f"the block at offset {offset} ends with length {copy}, not {length}")


def _packet_fields(endian: str, block_type: int, fixed: bytes, length: int,
                   offset: int) -> Tuple[int, int, int, int, int]:
    """``(interface_id, ts_high, ts_low, caplen, origlen)`` from the 20 fixed bytes of an EPB or PB, with the caplen
    checked against the block length."""
    if len(fixed) < _PACKET_FIXED:
        raise PcapngError(f"the block at offset {offset} runs past the end of the file")
    if block_type == BLOCK_EPB:
        interface_id, ts_high, ts_low, caplen, origlen = struct.unpack_from(endian + "IIIII", fixed, 0)
    else:
        interface_id, _drops, ts_high, ts_low, caplen, origlen = struct.unpack_from(endian + "HHIIII", fixed, 0)
    if 28 + _pad4(caplen) + 4 > length:
        raise PcapngError(f"the packet at offset {offset} claims {caplen} captured bytes, more than its "
                          f"{length} byte block holds")
    return interface_id, ts_high, ts_low, caplen, origlen


def _check_interface(interface_id: int, known: int, offset: int) -> None:
    if interface_id >= known:
        raise PcapngError(f"the packet at offset {offset} names interface {interface_id}, which its section does not "
                          "describe")


def _ts_divisor(options: bytes, endian: str) -> int:
    """Timestamp units per second from an IDB's option list (``if_tsresol``), else :data:`DEFAULT_TS_DIVISOR`."""
    pos = 0
    while pos + 4 <= len(options):
        code, size = struct.unpack_from(endian + "HH", options, pos)
        if code == OPT_END or pos + 4 + size > len(options):
            break
        if code == OPT_IF_TSRESOL and size >= 1:
            value = options[pos + 4]
            return 1 << (value & 0x7F) if value & 0x80 else 10 ** value
        pos += 4 + _pad4(size)
    return DEFAULT_TS_DIVISOR


class _Section:
    """One section: its byte order and interface table ``[(linktype, snaplen, ts_divisor), ...]``."""

    __slots__ = ("endian", "interfaces")

    def __init__(self, endian: str) -> None:
        self.endian = endian
        self.interfaces: List[Tuple[int, int, int]] = []

    def add_interface(self, body: bytes) -> None:
        linktype, _reserved, snaplen = struct.unpack_from(self.endian + "HHI", body, 0)
        self.interfaces.append((linktype, snaplen, _ts_divisor(body[8:], self.endian)))

    def interface(self, interface_id: int, offset: int) -> Tuple[int, int, int]:
        _check_interface(interface_id, len(self.interfaces), offset)
        return self.interfaces[interface_id]

    def packet(self, block_type: int, body: bytes, offset: int) -> Dict[str, Any]:
        """The PACKET dict of an EPB, SPB or PB body (validated)."""
        length = len(body) + 12
        if block_type == BLOCK_SPB:
            (origlen,) = struct.unpack_from(self.endian + "I", body, 0)
            linktype, snaplen, _divisor = self.interface(0, offset)
            caplen = min(origlen, length - 16, snaplen or origlen)      # snaplen 0 = unlimited
            return {"interface": 0, "linktype": linktype, "ts": None, "caplen": caplen, "origlen": origlen,
                    "data": body[4:4 + caplen]}
        interface_id, ts_high, ts_low, caplen, origlen = _packet_fields(self.endian, block_type, body, length, offset)
        linktype, _snaplen, divisor = self.interface(interface_id, offset)
        return {"interface": interface_id, "linktype": linktype, "ts": ((ts_high << 32) | ts_low) / divisor,
                "caplen": caplen, "origlen": origlen, "data": body[_PACKET_FIXED:_PACKET_FIXED + caplen]}


def iter_blocks(fileobj: BinaryIO) -> Iterator[Tuple[str, int, bytes]]:
    """``(endian "<"|">", block_type, body)`` for every block of a binary file object, one block in memory at a time.

    *body* is the block between its 8-byte header and its trailing length (an SHB body starts with the byte-order
    magic). Raises :class:`PcapngError` as the module docstring describes; blocks before the bad one have already
    been yielded."""
    endian: Optional[str] = None
    offset = 0
    while True:
        header = _read_header(fileobj, endian, offset)
        if header is None:
            return
        endian, block_type, length, magic = header
        want = length - 8 - len(magic)
        rest = _read_exact(fileobj, want)
        if len(rest) < want:
            raise PcapngError(f"the block at offset {offset} runs past the end of the file")
        _check_trailer(endian, rest[-4:], length, offset)
        yield endian, block_type, magic + rest[:-4]
        offset += length


def _limit(max_packets: Optional[int]) -> Optional[int]:
    if max_packets is None:
        return None
    if isinstance(max_packets, bool) or not isinstance(max_packets, int):
        raise TypeError("max_packets must be a whole number or None")
    if max_packets < 0:
        raise ValueError("max_packets must not be negative")
    return max_packets


def _iter_packets(fileobj: BinaryIO, limit: Optional[int]) -> Iterator[Dict[str, Any]]:
    if limit == 0:
        return
    section: Optional[_Section] = None
    offset = count = 0
    for endian, block_type, body in iter_blocks(fileobj):
        if block_type == BLOCK_SHB:
            section = _Section(endian)
        elif block_type == BLOCK_IDB:
            section.add_interface(body)                     # iter_blocks guarantees an SHB came first
        elif block_type in PACKET_BLOCKS:
            yield section.packet(block_type, body, offset)
            count += 1
            if limit is not None and count >= limit:
                return
        offset += len(body) + 12


def iter_packets(fileobj: BinaryIO, *, max_packets: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    """PACKET dicts for every EPB, SPB and PB in a binary file object, read one block at a time (no total size cap).

    Stops after *max_packets* packets when given (the blocks after them are not read)."""
    return _iter_packets(fileobj, _limit(max_packets))


def read_packets(data: Union[bytes, bytearray, memoryview], *,
                 max_packets: Optional[int] = 10000) -> List[Dict[str, Any]]:
    """The PACKET dicts of an in-memory pcapng file, at most *max_packets* of them.

    A buffer larger than :data:`MAX_IN_MEMORY` raises :class:`PcapngError` before anything is parsed: large files go
    through :func:`iter_packets` or :func:`count_packets` instead."""
    if len(data) > MAX_IN_MEMORY:
        raise PcapngError(f"a {len(data)} byte pcapng buffer is over the {MAX_IN_MEMORY} byte in-memory limit")
    limit = _limit(max_packets)
    return list(_iter_packets(io.BytesIO(bytes(data)), limit))


def count_packets(path: PathLike) -> int:
    """The number of EPB + SPB + PB blocks in the pcapng file at *path*.

    Reads each block header (plus the 20 fixed bytes of an EPB/PB) and seeks past the body to check the trailing
    length, so memory use does not grow with the file. The validation matches the other readers."""
    count = 0
    with open(path, "rb") as fileobj:
        size = os.fstat(fileobj.fileno()).st_size
        endian: Optional[str] = None
        interfaces = offset = 0
        while True:
            header = _read_header(fileobj, endian, offset)
            if header is None:
                return count
            endian, block_type, length, _magic = header
            if offset + length > size:
                raise PcapngError(f"the block at offset {offset} runs past the end of the file")
            if block_type == BLOCK_SHB:
                interfaces = 0
            elif block_type == BLOCK_IDB:
                interfaces += 1
            elif block_type in (BLOCK_EPB, BLOCK_PB):
                fixed = _read_exact(fileobj, _PACKET_FIXED)
                interface_id = _packet_fields(endian, block_type, fixed, length, offset)[0]
                _check_interface(interface_id, interfaces, offset)
                count += 1
            elif block_type == BLOCK_SPB:
                _check_interface(0, interfaces, offset)
                count += 1
            fileobj.seek(offset + length - 4)
            _check_trailer(endian, _read_exact(fileobj, 4), length, offset)
            offset += length


_OPT_END = struct.pack("<HH", OPT_END, 0)


def _option(code: int, value: Union[bytes, str]) -> bytes:
    """One little-endian option (code, length, value, padding) for a block :class:`Writer` writes."""
    raw = value.encode("utf-8", "replace") if isinstance(value, str) else bytes(value)
    raw = raw[:0xFFFF]
    return struct.pack("<HH", code, len(raw)) + raw + bytes(_pad4(len(raw)) - len(raw))


def iter_packets_with_offsets(fileobj: BinaryIO, *, max_packets: Optional[int] = None) -> Iterator[Tuple[int, Dict[str, Any]]]:
    """``(block offset, PACKET)`` for every EPB, SPB and PB, so a caller can index a file and come back to one packet.

    The offset is the packet block's own start in the file, which :func:`read_packet_at` takes."""
    limit = _limit(max_packets)
    if limit == 0:
        return
    section: Optional[_Section] = None
    offset = count = 0
    for endian, block_type, body in iter_blocks(fileobj):
        if block_type == BLOCK_SHB:
            section = _Section(endian)
        elif block_type == BLOCK_IDB:
            section.add_interface(body)                     # iter_blocks guarantees an SHB came first
        elif block_type in PACKET_BLOCKS:
            yield offset, section.packet(block_type, body, offset)
            count += 1
            if limit is not None and count >= limit:
                return
        offset += len(body) + 12


class _FileSections:
    """What :func:`read_packet_at` learnt walking one file: its sections ``[(start offset, _Section)]`` in file order
    and the offset of the first block it has not walked yet, so a later packet (a file that grows) resumes there."""

    __slots__ = ("ident", "starts", "sections", "next_offset")

    def __init__(self, ident: Tuple[Any, ...]) -> None:
        self.ident = ident
        self.starts: List[int] = []
        self.sections: List[_Section] = []
        self.next_offset = 0

    def walk_to(self, fileobj: BinaryIO, offset: int) -> None:
        """Walk the block headers from :attr:`next_offset` through the block that starts at or before *offset*: an SHB
        opens a section, an IDB extends its interface table, every other body is skipped.  Raises PcapngError."""
        pos = self.next_offset
        endian = self.sections[-1].endian if self.sections else None
        fileobj.seek(pos)
        while pos <= offset:
            header = _read_header(fileobj, endian, pos)
            if header is None:
                return
            endian, block_type, length, magic = header
            if block_type == BLOCK_SHB:
                self.starts.append(pos)
                self.sections.append(_Section(endian))
                fileobj.seek(pos + length)
            elif block_type == BLOCK_IDB:
                rest = _read_exact(fileobj, length - 8)
                if len(rest) < length - 8:
                    return                  # a block still being written: walked no further
                _check_trailer(endian, rest[-4:], length, pos)
                self.sections[-1].add_interface(rest[:-4])
            else:
                fileobj.seek(pos + length)
            pos += length
            self.next_offset = pos

    def section_at(self, offset: int) -> Optional[_Section]:
        i = bisect.bisect_right(self.starts, offset) - 1
        return self.sections[i] if i >= 0 else None


#: The walked files, most recent last (a handful: the capture page reads from one file at a time).
_SECTIONS: "OrderedDict[str, _FileSections]" = OrderedDict()
_SECTIONS_MAX = 8
_SECTIONS_LOCK = threading.Lock()
_WALK_BUFFER = 1 << 16


def _file_ident(st: os.stat_result) -> Tuple[Any, ...]:
    """A file's identity: another file written to the same path is walked afresh."""
    born = getattr(st, "st_birthtime_ns", None) or st.st_ctime_ns
    return (st.st_dev, st.st_ino, born)


def _section_for(path: PathLike, offset: int) -> Optional[_Section]:
    """The section (byte order + interface table) that holds the block at *offset*, or None when the blocks before it
    cannot be walked (not a pcapng, a damaged block)."""
    try:
        key = os.path.normcase(os.path.abspath(os.fspath(path)))
        st = os.stat(key)
    except (OSError, TypeError, ValueError):
        return None
    ident = _file_ident(st)
    with _SECTIONS_LOCK:
        known = _SECTIONS.get(key)
        if known is None or known.ident != ident or st.st_size < known.next_offset:
            known = _FileSections(ident)
            _SECTIONS[key] = known
        _SECTIONS.move_to_end(key)
        while len(_SECTIONS) > _SECTIONS_MAX:
            _SECTIONS.popitem(last=False)
        if known.next_offset <= offset:
            try:
                with open(key, "rb", buffering=_WALK_BUFFER) as fileobj:
                    known.walk_to(fileobj, offset)
            except (OSError, PcapngError, struct.error):
                _SECTIONS.pop(key, None)
                return None
        return known.section_at(offset)


def read_packet_at(path: PathLike, offset: int, *, endian: str = "<", linktype: int = LINKTYPE_ETHERNET,
                   ts_divisor: int = DEFAULT_TS_DIVISOR) -> Optional[Dict[str, Any]]:
    """The PACKET at *offset* of a pcapng file, or None when there is no packet block there.

    The packet is read with its own section's byte order and its own interface's link type and timestamp resolution
    (the file's SHBs and IDBs, walked once and remembered: see the module docstring), so a packet on the second
    interface of an "all interfaces" capture, in a big-endian file or in a nanosecond one reads back exactly as
    :func:`iter_packets_with_offsets` indexed it.  *endian*, *linktype* and *ts_divisor* are used only when the blocks
    before the packet cannot be walked, and then for interface 0.  A block that is not an EPB, SPB or PB, or one that
    does not read back, gives None rather than an error."""
    if offset < 0:
        return None
    section = _section_for(path, offset)
    if section is None:
        section = _Section(endian)
        section.interfaces.append((linktype, 0, ts_divisor))
    try:
        with open(path, "rb") as fileobj:
            fileobj.seek(offset)
            head = _read_exact(fileobj, 8)
            if len(head) < 8:
                return None
            block_type, length = struct.unpack(section.endian + "II", head)
            if block_type not in PACKET_BLOCKS or length < _MIN_LENGTH.get(block_type, 12) or length > MAX_BLOCK:
                return None
            rest = _read_exact(fileobj, length - 8)
            if len(rest) < length - 8:
                return None
    except OSError:
        return None
    try:
        _check_trailer(section.endian, rest[-4:], length, offset)
        return section.packet(block_type, rest[:-4], offset)
    except (PcapngError, struct.error):
        return None


class Writer:
    """Writes a pcapng file of one interface: the SHB and IDB up front, then an EPB per packet.

    Used by the live packet capture, which writes every frame it receives straight to disk and keeps only a summary in
    memory.  :meth:`write_packet` returns the block's offset, which is what the packet list stores so a detail view can
    read that one packet back with :func:`read_packet_at`.  The byte order is always little-endian and the timestamp
    resolution microseconds, so a reader needs no options to follow it.  Nothing here closes *fileobj*: the caller owns
    it.  Timestamps before 1970 or past the 64-bit range are clamped, and a packet larger than :data:`MAX_BLOCK` minus
    its header is refused with :class:`PcapngError` (never a partial block)."""

    __slots__ = ("_out", "_linktype", "_snaplen", "offset", "packets")

    #: what a caller may not exceed with one packet (the block header, the fixed fields and the trailing length)
    MAX_PACKET = MAX_BLOCK - 32

    def __init__(self, fileobj: BinaryIO, *, linktype: int = LINKTYPE_ETHERNET, snaplen: int = 0,
                 app_name: str = "TNT", if_name: Optional[str] = None) -> None:
        self._out = fileobj
        self._linktype = int(linktype)
        self._snaplen = max(0, int(snaplen))
        self.offset = 0                                  # bytes written so far: the next block's offset
        self.packets = 0
        self._write(_block("<", BLOCK_SHB, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _option(4, app_name) + _OPT_END))
        options = _option(9, bytes((6,)))                # if_tsresol: 10^-6 s
        if if_name:
            options = _option(2, if_name) + options
        self._write(_block("<", BLOCK_IDB, struct.pack("<HHI", self._linktype, 0, self._snaplen) + options + _OPT_END))

    def _write(self, data: bytes) -> None:
        self._out.write(data)
        self.offset += len(data)

    def write_packet(self, ts: Optional[float], data: bytes, origlen: Optional[int] = None) -> int:
        """Append one packet; the offset of the block that was written.

        *ts* is float seconds since 1970 (None means 0) and *origlen* the frame's length on the wire (None means the
        length of *data*)."""
        frame = bytes(data)
        if len(frame) > self.MAX_PACKET:
            raise PcapngError(f"a {len(frame)} byte packet is over the {self.MAX_PACKET} byte block limit")
        micros = 0 if ts is None else int(max(0.0, float(ts)) * DEFAULT_TS_DIVISOR)
        micros = min(micros, 0xFFFFFFFFFFFFFFFF)
        wire = len(frame) if origlen is None else max(len(frame), int(origlen))
        padded = _pad4(len(frame))
        at = self.offset
        length = 32 + padded
        self._write(b"".join((struct.pack("<IIIIIII", BLOCK_EPB, length, 0, micros >> 32, micros & 0xFFFFFFFF,
                                          len(frame), wire),
                              frame, bytes(padded - len(frame)), struct.pack("<I", length))))
        self.packets += 1
        return at

    def flush(self) -> None:
        """Push what is buffered to the file; never raises for a file object without ``flush``."""
        try:
            self._out.flush()
        except (AttributeError, OSError, ValueError):
            pass


def dot11_to_ethernet(frame: bytes, origlen: int) -> Optional[Tuple[bytes, int]]:
    """``(ethernet_frame, new_origlen)`` for an 802.11 data frame carrying SNAP, or None when *frame* is not one.

    *frame* holds the captured bytes (caplen) and *origlen* the frame's length on the wire. The rules are in the module
    docstring."""
    p = bytes(frame)
    size = len(p)
    if size < 24:
        return None
    fc0, fc1 = p[0], p[1]
    if fc0 & 0x03 or (fc0 >> 2) & 0x03 != 2:          # protocol version 0, type 2 (data)
        return None
    subtype = fc0 >> 4
    if subtype & 0x04:                                   # null function, QoS null, ...: no payload
        return None
    to_ds, from_ds = fc1 & 0x01, fc1 & 0x02
    hl = 30 if to_ds and from_ds else 24
    amsdu = False
    if subtype & 0x08:                                   # QoS data: 2-byte QoS Control after the addresses
        if size < hl + 2:
            return None
        amsdu = bool(p[hl] & 0x80)
        hl += 2
        if fc1 & 0x80:                                   # Order bit on a QoS frame: 4-byte HT Control follows
            hl += 4
    a1, a2, a3 = p[4:10], p[10:16], p[16:22]
    if to_ds and from_ds:
        da, sa = a3, p[24:30]                            # WDS: Address 4 is the source
    elif to_ds:
        da, sa = a3, a2
    elif from_ds:
        da, sa = a1, a3
    else:
        da, sa = a1, a2
    if size >= hl + 8 and p[hl:hl + 6] in SNAP_HEADERS:
        converted = da + sa + p[hl + 6:]
        return converted, max(len(converted), origlen - (hl + 6) + 12)
    if amsdu and size >= hl + 22 and p[hl + 14:hl + 20] in SNAP_HEADERS:
        (subframe_len,) = struct.unpack_from(">H", p, hl + 12)
        if subframe_len < 8:                             # shorter than SNAP + ethertype
            return None
        converted = p[hl:hl + 12] + p[hl + 20:min(hl + 14 + subframe_len, size)]
        if hl + 14 + subframe_len <= origlen:
            new_origlen = subframe_len + 6
        else:
            new_origlen = origlen - (hl + 20) + 12
        return converted, max(len(converted), new_origlen)
    return None


def _block(endian: str, block_type: int, body: bytes) -> bytes:
    length = len(body) + 12
    return struct.pack(endian + "II", block_type, length) + body + struct.pack(endian + "I", length)


def _rewrite_epb(section: _Section, body: bytes, offset: int, stats: Dict[str, int]) -> bytes:
    """The rewritten EPB (converted or kept), or ``b""`` when the frame is dropped."""
    endian = section.endian
    interface_id, ts_high, ts_low, caplen, origlen = _packet_fields(endian, BLOCK_EPB, body, len(body) + 12, offset)
    section.interface(interface_id, offset)
    data = body[_PACKET_FIXED:_PACKET_FIXED + caplen]
    options = body[_PACKET_FIXED + _pad4(caplen):]
    converted = dot11_to_ethernet(data, origlen)
    if converted is not None:
        frame, new_origlen = converted
        stats["converted"] += 1
    elif len(data) >= 14 and struct.unpack_from(">H", data, 12)[0] in KNOWN_ETHERTYPES:
        frame, new_origlen = data, origlen
        stats["kept_ethernet"] += 1
    else:
        stats["dropped"] += 1
        return b""
    padded = _pad4(len(frame))
    length = 28 + padded + len(options) + 4
    return b"".join((struct.pack(endian + "IIIIIII", BLOCK_EPB, length, interface_id, ts_high, ts_low, len(frame),
                                 new_origlen),
                     frame, bytes(padded - len(frame)), options, struct.pack(endian + "I", length)))


def rewrite_dot11_to_ethernet(src_path: PathLike, dst_path: PathLike) -> Dict[str, int]:
    """Rewrite a Wi-Fi capture's 802.11 data frames as Ethernet II, streaming *src_path* into *dst_path*.

    Writes ``<dst_path>.part`` and moves it over *dst_path* only when the whole file was read; on any error the part
    file is removed and the error is raised (a :class:`PcapngError` for a malformed file). Returns
    ``{"converted", "kept_ethernet", "dropped"}`` frame counts."""
    stats = dict.fromkeys(REWRITE_KEYS, 0)
    part = os.fspath(dst_path) + ".part"
    try:
        with open(src_path, "rb") as src, open(part, "wb") as out:
            section: Optional[_Section] = None
            offset = 0
            for endian, block_type, body in iter_blocks(src):
                if block_type == BLOCK_EPB:
                    out.write(_rewrite_epb(section, body, offset, stats))
                else:
                    if block_type == BLOCK_SHB:
                        section = _Section(endian)
                    elif block_type == BLOCK_IDB:
                        section.add_interface(body)
                    elif block_type in (BLOCK_SPB, BLOCK_PB):
                        section.packet(block_type, body, offset)      # validated like every reader, copied as is
                    out.write(_block(endian, block_type, body))
                offset += len(body) + 12
        os.replace(part, dst_path)
    except BaseException:
        try:
            os.remove(part)
        except OSError:
            pass
        raise
    return stats
