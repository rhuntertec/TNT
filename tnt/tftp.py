r"""TFTP server (Tools page): hand files to the devices on one adapter that ask for them.

Why this exists
---------------
Phones, switches, access points and bootloaders fetch firmware and configuration over TFTP.  A
technician on a bench needs a server for a few minutes, on the adapter the device is cabled to, without
installing a third-party server or a Windows role.  This module is that server, run by the LocalSystem
service: RFC 1350 (TFTP revision 2) over IPv4 with the RFC 2347 option extension, ``blksize``
(RFC 2348), ``timeout`` and ``tsize`` (RFC 2349), ``windowsize`` (RFC 7440) and the de-facto
``rollover`` option, in ``octet`` and ``netascii`` modes, with the timer and Sorcerer's Apprentice rules
of RFC 1123 §4.2.3.  It is original code written from those documents.

Safety first (an unauthenticated UDP service that reads and writes files as SYSTEM):

* **One adapter.**  A listener is bound to each IPv4 address of the chosen adapter (never 0.0.0.0) and
  only clients inside that adapter's IPv4 subnets are answered; anyone else is dropped silently, so the
  server can never be used to reflect traffic.  Each transfer socket binds ``(listen_ip, 0)``: replies
  leave from the address the device asked (curl and U-Boot drop data from any other address).
* **One folder.**  Files come only from :func:`tnt.paths.tftp_dir` (there is no root setting), secured by
  :meth:`TftpServer.ensure_root` with ``tnt.winacl.TFTP_SDDL`` (Users may drop files there).  Every name
  goes through :func:`clean_name` (no ``..``, drives, UNC, ``:`` streams, device names, trailing dots or
  spaces, control characters, more than :data:`MAX_DEPTH` folders).  The check that counts is made on
  the **open handle**: ``GetFinalPathNameByHandleW`` must lie under the root's own final path, and the
  file must be a regular file with one link that is not a reparse point.  A standard user can create a
  junction or a hard link inside the root; both give themselves away there and are refused.
* **Uploads** are off after every service start and every stop.  While on they are create-only: data goes
  into ``.<name>.<8 hex>.part`` opened ``O_EXCL`` (in a folder that already exists and whose own handle is
  checked the same way) and is renamed at the end, so an existing name is never overwritten; the size is
  capped by ``tftp.max_upload_mb`` and a :data:`FREE_SPACE_RESERVE` of free disk.
* **Limits:** :data:`MAX_TRANSFERS` transfers, :data:`MAX_PER_CLIENT` per client address; retransmits back
  off; a duplicate ACK never makes the server send data again; ERROR 5 goes to a stranger at most once a
  second per transfer.
* **Port owners** are looked up (``GetExtendedUdpTable``) before binding, because a successful exclusive
  bind does not prove that nobody else serves UDP 69 (a wildcard socket of another account):
  :class:`TftpPortInUse` names them.
* **Firewall:** the installed service adds :data:`FIREWALL_RULE_NAME` for its own exe, scoped to
  ``LocalSubnet``; a console or dev run (no ``exe_path``) never touches the firewall.

Windows socket facts this code relies on (measured on Windows 11):

* ``recvfrom`` on an unconnected UDP socket raises ``ConnectionResetError`` (WinError 10054) after an ICMP
  port-unreachable for an earlier send, and the socket keeps working.  ``SIO_UDP_CONNRESET`` cannot be set
  from Python, so every receive loop here catches it.
* ``SO_EXCLUSIVEADDRUSE`` stops another socket from taking the port over with ``SO_REUSEADDR``.
* Without ``IP_PKTINFO`` a request sent to the subnet broadcast cannot be told from a unicast one, so the
  RFC 1123 rule against answering broadcast requests is not enforced.
* A transfer socket always sends first (OACK, DATA 1, ACK 0 or ERROR), so only inbound UDP 69 needs a
  firewall rule: the device's replies belong to a flow the server opened.

Shapes (keys in this order)::

    STATUS   = {"available", "running", "since_ts", "error", "warning", "adapter": ADAPTER|None,
                "adapters": [ADAPTER], "listen": [{"ip", "port"}], "root": str, "uploads": bool,
                "firewall": {"rule", "ok": bool|None, "error"}, "conflict": {"port", "owners": [OWNER]}|None,
                "transfers": [TRANSFER] (active, oldest first), "history": [TRANSFER] (finished, newest first, 50),
                "counts": {"active", "done", "unconfirmed", "failed", "cancelled", "busy"},
                "settings": {"adapter", "max_upload_mb"}}
    SUMMARY  = {"available", "running", "adapter": name|None, "listen_ips": [str], "active": int,
                "uploads": bool, "since_ts", "error"}
    TRANSFER = {"id": int, "client": ip, "op": "read"|"write", "file": str (as the device sent it), "mode",
                "blksize": int, "windowsize": int, "size": int|None, "bytes": int, "state", "error": str|None,
                "started_ts", "ended_ts"}
    ADAPTER  = {"name", "index", "ip", "prefix", "type_name", "is_physical", "is_internet", "status"}
    OWNER    = {"pid": int, "name": str}

Transfer ``state``: ``negotiating`` (the request is being checked, or an OACK waits for its answer), then
``sending`` / ``receiving``, and finally ``done``, ``unconfirmed`` (the last block went out but its ACK
never came), ``failed`` (including requests refused with an ERROR) or ``cancelled`` (the device ended it
during option negotiation, or the server stopped).  ``size`` is the file size for an octet read, the
``tsize`` a device announced for a write, else None; ``bytes`` counts the bytes delivered: file bytes, except for a
``netascii`` read, where it counts the converted bytes on the wire (so it may pass the file size).  ``counts["busy"]``
counts requests turned away by the limits (they do not enter the history).

Events (``bus.publish``): ``tftp.state`` (SUMMARY) on start, stop, uploads and settings changes and when a
transfer starts or ends; ``tftp.transfer`` ``{"transfer": TRANSFER}`` at most 4 times a second per transfer
plus every state change.  Database ``events`` rows (category ``tftp``; skipped when the db is None): start,
stop, uploads switched, and each finished upload (bytes and outcome only).

Logging: INFO names the adapter, uploads on/off, the firewall result and one line per finished transfer
(operation, outcome, bytes, seconds); client addresses and file names are DEBUG only.

Injectable seams (keyword arguments): ``socket_factory``, ``runner`` (netsh), ``adapters_fn``,
``udp_owners_fn``, ``acl`` (default :func:`tnt.winacl.secure_dir`), ``timers`` (:class:`TftpTimers`),
``clock`` and ``monotonic``.  Every bind goes through the module seam :func:`_bind_udp` (tests/conftest.py
refuses UDP 67 and 69 there).
"""
from __future__ import annotations

import ctypes
import errno
import importlib
import ipaddress
import logging
import ntpath
import os
import re
import secrets
import select
import shutil
import socket
import stat
import struct
import sys
import threading
import time
from collections import deque
from ctypes import POINTER, byref, c_int, c_ulong, c_void_p, c_wchar_p
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Any, Callable, Deque, Dict, Iterator, List, NoReturn, Optional, Sequence, Set, Tuple

from . import dhcp as _dhcp
from . import firewall as _firewall
from . import paths
from . import winacl as _winacl

log = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_PORT", "FIREWALL_RULE_NAME", "MAX_TRANSFERS", "MAX_PER_CLIENT", "HISTORY_KEEP", "MAX_DEPTH",
    "TFTP_STATUS_KEYS", "TFTP_SUMMARY_KEYS", "TFTP_TRANSFER_KEYS", "TFTP_ADAPTER_KEYS", "TFTP_COUNT_KEYS",
    "TFTP_SETTINGS_KEYS", "TRANSFER_STATES", "TftpTimers", "TftpPortInUse", "TftpServer", "Request",
    "blksize_max", "clean_name", "encode_request", "encode_data", "encode_ack", "encode_error", "encode_oack",
    "parse_request", "negotiate_options", "wire_block", "parse_udp_table", "udp_port_owners",
]

# --- protocol constants (RFC 1350, RFC 2347-2349, RFC 7440) ------------------------------
OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR, OP_OACK = 1, 2, 3, 4, 5, 6
#: ERROR codes (RFC 1350 §5; 8 is RFC 2347's "terminate the transfer because of option negotiation").
ERR_UNDEFINED, ERR_NOT_FOUND, ERR_ACCESS, ERR_DISK_FULL, ERR_ILLEGAL, ERR_UNKNOWN_TID, ERR_EXISTS = range(7)
ERR_OPTIONS = 8
MODES = ("netascii", "octet")
DEFAULT_BLKSIZE = 512
MIN_BLKSIZE = 8                        # RFC 2348: 8..65464
BLKSIZE_CAP = 1468                     # an MTU of 1500 minus 20 (IPv4), 8 (UDP) and 4 (TFTP header)
BLKSIZE_FLOOR = 512                    # never offer less than RFC 1350's own block size
WINDOWSIZE_MAX = 16                    # RFC 7440 allows 1..65535
TIMEOUT_OPTION_MIN, TIMEOUT_OPTION_MAX = 1, 255
DALLY_TIMEOUT_FALLBACK_S = 5.0         # curl and U-Boot negotiate 5 s; the dally assumes it when nothing was

# --- policy -------------------------------------------------------------------------------
DEFAULT_PORT = 69
FIREWALL_RULE_NAME = "TNT TFTP server (UDP 69 in)"
FIREWALL_REMOTE_IP = "localsubnet"
MAX_TRANSFERS = 32
MAX_PER_CLIENT = 4
HISTORY_KEEP = 50
MAX_DEPTH = 3                          # folders below the root a name may go down: a/b/c/file.bin
MAX_NAME_CHARS = 255
MAX_FILES = 500                        # files() lists at most this many
WALK_MAX_ENTRIES = 20000               # folder entries one walk of the root looks at
FREE_SPACE_RESERVE = 1 << 30           # an upload never leaves less than 1 GB free
FREE_SPACE_CHECK_BYTES = 16 << 20      # free space is checked again after every 16 MB written
DEFAULT_MAX_UPLOAD_MB = 4096
MAX_UPLOAD_MB_MIN, MAX_UPLOAD_MB_MAX = 1, 65536
ERROR5_INTERVAL_S = 1.0
TRANSFER_EVENT_INTERVAL_S = 0.25       # tftp.transfer at most 4 times a second per transfer
LISTEN_TICK_S = 0.25
TRANSFER_TICK_S = 0.1                  # how quickly a transfer notices stop()
STOP_JOIN_S = 1.5                      # stop() joins within this (the engine gives it 2 s)
RECV_BUFFER = 65536
READ_CHUNK = 65536
WRITE_FLUSH_BYTES = 256 << 10
DEVICE_TEXT_LIMIT = 120

TFTP_STATUS_KEYS = ("available", "running", "since_ts", "error", "warning", "adapter", "adapters", "listen", "root",
                    "uploads", "firewall", "conflict", "transfers", "history", "counts", "settings")
TFTP_SUMMARY_KEYS = ("available", "running", "adapter", "listen_ips", "active", "uploads", "since_ts", "error")
TFTP_TRANSFER_KEYS = ("id", "client", "op", "file", "mode", "blksize", "windowsize", "size", "bytes", "state", "error",
                      "started_ts", "ended_ts")
TFTP_ADAPTER_KEYS = ("name", "index", "ip", "prefix", "type_name", "is_physical", "is_internet", "status")
TFTP_COUNT_KEYS = ("active", "done", "unconfirmed", "failed", "cancelled", "busy")
TFTP_SETTINGS_KEYS = ("adapter", "max_upload_mb")
TRANSFER_STATES = ("negotiating", "sending", "receiving", "done", "unconfirmed", "failed", "cancelled")

# --- texts (ERROR messages to devices and TRANSFER["error"]) -----------------------------
MSG_BUSY = "Server busy, try again later"
MSG_CANCELLED = "Transfer cancelled"
MSG_SHUTDOWN = "Server is shutting down"
MSG_TIMED_OUT = "Transfer timed out"
MSG_NOT_FOUND = "File not found"
MSG_FOLDER_NOT_FOUND = "Folder not found"
MSG_UPLOADS_OFF = "Uploads are switched off on this server"
MSG_NAME_NOT_ALLOWED = "File name not allowed"
MSG_ACCESS_DENIED = "Access denied"
MSG_TOO_LARGE = "File too large"
MSG_DISK_FULL = "Disk full"
MSG_MODE = "Unsupported transfer mode"
MSG_OVERSIZE = "Data block larger than the negotiated block size"
MSG_UNKNOWN_TID = "Unknown transfer ID"
MSG_EXISTS = "File already exists"
MSG_UNCONFIRMED = "The device did not confirm the last block"
MSG_READ_FAILED = "Could not read the file"
MSG_WRITE_FAILED = "Could not write the file"
MSG_INTERNAL = "The server could not complete the transfer"
MAX_UPLOAD_MB_MSG = f"max_upload_mb must be a whole number from {MAX_UPLOAD_MB_MIN} to {MAX_UPLOAD_MB_MAX}"

_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NOINHERIT = getattr(os, "O_NOINHERIT", 0)
_PART_RE = re.compile(r"^\..+\.[0-9a-f]{8}\.part$")                      # the exact shape uploads create
# the same shape in any letter case: NTFS names are case-insensitive, so a request must not reach an upload in progress
_PART_NAME_RE = re.compile(r"^\..+\.[0-9a-f]{8}\.part$", re.IGNORECASE | re.ASCII)
_DECIMAL_CAP = 10 ** 20                # a decimal option value with more significant digits than this reads as this
_RESERVED_STEMS = frozenset({"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
                            | {f"{p}{d}" for p in ("COM", "LPT") for d in "0123456789\u00b9\u00b2\u00b3"})
_FORBIDDEN_CHARS = frozenset('<>:"|?*')


@dataclass(frozen=True)
class TftpTimers:
    """Timing knobs (never settings; the engine uses the defaults).

    ``initial_s`` is the first retransmit timeout (a negotiated ``timeout`` replaces it); it doubles after each
    retransmit up to ``cap_s`` and a transfer gives up after ``retries`` retransmits, or when nothing moved for
    ``idle_s``.  After the final ACK of an upload the server dallies ``1.5 x`` the negotiated timeout (5 s when
    none was), kept between ``dally_min_s`` and ``dally_max_s``."""

    initial_s: float = 1.0
    cap_s: float = 5.0
    retries: int = 5
    idle_s: float = 60.0
    dally_min_s: float = 2.0
    dally_max_s: float = 10.0

    def dally_s(self, negotiated_timeout: Optional[float]) -> float:
        base = float(negotiated_timeout) if negotiated_timeout else DALLY_TIMEOUT_FALLBACK_S
        return min(float(self.dally_max_s), max(float(self.dally_min_s), 1.5 * base))


class TftpPortInUse(RuntimeError):
    """Another program holds the TFTP port.  ``owners`` is ``[{"pid", "name"}]``; it is empty when the bind
    itself failed and no owner could be named.  The route answers 409 ``tftp_port_in_use`` with the owners."""

    def __init__(self, message: str, owners: Optional[Sequence[Dict[str, Any]]] = None) -> None:
        super().__init__(message)
        self.owners: List[Dict[str, Any]] = [dict(o) for o in owners or []]


def _bind_udp(sock: Any, address: Tuple[str, int]) -> None:
    """Bind *sock* to *address*.  The module seam every bind goes through (tests/conftest.py refuses UDP 67 and
    69 here for the whole session), so callers look it up as a module global at call time."""
    sock.bind(address)


# --- wire format ------------------------------------------------------------------------
def _z(value: Any) -> bytes:
    raw = value if isinstance(value, (bytes, bytearray)) else str(value).encode("utf-8")
    return bytes(raw) + b"\0"


def _pairs(options: Any) -> List[Tuple[Any, Any]]:
    if not options:
        return []
    if isinstance(options, dict):
        return list(options.items())
    return list(options)


def encode_request(opcode: int, filename: Any, mode: str = "octet", options: Any = None) -> bytes:
    """RRQ (1) / WRQ (2): opcode, filename NUL, mode NUL, then (option NUL value NUL) pairs."""
    body = struct.pack("!H", opcode) + _z(filename) + _z(mode)
    for name, value in _pairs(options):
        body += _z(name) + _z(value)
    return body


def encode_data(block: int, payload: bytes = b"") -> bytes:
    """DATA (3): opcode, 16-bit block number (the wire number: pass it already wrapped), payload."""
    return struct.pack("!HH", OP_DATA, int(block) & 0xFFFF) + bytes(payload)


def encode_ack(block: int) -> bytes:
    return struct.pack("!HH", OP_ACK, int(block) & 0xFFFF)


def encode_error(code: int, message: str) -> bytes:
    return struct.pack("!HH", OP_ERROR, int(code) & 0xFFFF) + str(message).encode("ascii", "replace")[:255] + b"\0"


def encode_oack(options: Any) -> bytes:
    """OACK (6): the accepted options, in the order given."""
    body = struct.pack("!H", OP_OACK)
    for name, value in _pairs(options):
        body += _z(name) + _z(value)
    return body


@dataclass
class Request:
    """A parsed RRQ or WRQ.  ``filename`` stays bytes (:func:`clean_name` decodes it); ``mode`` is lower case;
    ``options`` maps lower-case option names to their text in request order, the first occurrence winning."""

    opcode: int
    filename: bytes
    mode: str
    options: Dict[str, str]


def parse_request(raw: bytes) -> Optional[Request]:
    """An RRQ or WRQ, else None (anything else sent to the listening port gets no answer at all).

    Lenient about size (RFC 2347 caps requests at 512 octets; any datagram size is read): NUL padding after
    the last option and an incomplete trailing option are ignored.  A request whose filename or mode is not
    NUL-terminated is dropped."""
    if len(raw) < 4:
        return None
    opcode = struct.unpack_from("!H", raw)[0]
    if opcode not in (OP_RRQ, OP_WRQ):
        return None
    fields = bytes(raw[2:]).split(b"\0")
    if len(fields) < 3:
        return None
    try:
        mode = fields[1].decode("ascii").lower()
    except UnicodeDecodeError:
        mode = ""
    options: Dict[str, str] = {}
    complete = fields[2:-1]                      # the last field is whatever followed the final NUL
    for i in range(0, len(complete) - 1, 2):
        name_raw, value_raw = complete[i], complete[i + 1]
        if not name_raw:
            break                                # NUL padding
        try:
            name, value = name_raw.decode("ascii").lower(), value_raw.decode("ascii")
        except UnicodeDecodeError:
            continue
        options.setdefault(name, value)
    return Request(opcode, fields[0], mode, options)


def _parse_packet(raw: bytes) -> Tuple[Optional[int], int, bytes]:
    """``(opcode, block number or error code, rest)``; opcode None for a runt."""
    if len(raw) < 4:
        return None, 0, b""
    op, num = struct.unpack_from("!HH", raw)
    return op, num, bytes(raw[4:])


def _device_text(raw: bytes) -> str:
    """An ERROR message from a device: printable, at most :data:`DEVICE_TEXT_LIMIT` characters."""
    text = bytes(raw).split(b"\0", 1)[0].decode("utf-8", "replace")
    return "".join(ch for ch in text if ch.isprintable())[:DEVICE_TEXT_LIMIT]


def _decimal(value: Any) -> Optional[int]:
    """An option value written as ASCII decimal digits (leading zeros allowed), else None.  More than 20
    significant digits read as :data:`_DECIMAL_CAP`, above every limit here, so a long number is still a
    number (``blksize`` is then capped, not dropped) and no huge string is ever converted."""
    text = str(value)
    if not text or not (text.isascii() and text.isdigit()):
        return None
    digits = text.lstrip("0") or "0"
    return int(digits) if len(digits) <= 20 else _DECIMAL_CAP


def blksize_max(mtu: Optional[int]) -> int:
    """The largest block size offered on an adapter with *mtu*: 1468 when the MTU is unknown (None), else
    ``max(512, min(1468, mtu - 32))`` so one block fits one IPv4 packet (U-Boot does not reassemble)."""
    if mtu is None or isinstance(mtu, bool):
        return BLKSIZE_CAP
    try:
        value = int(mtu)
    except (TypeError, ValueError):
        return BLKSIZE_CAP
    return max(BLKSIZE_FLOOR, min(BLKSIZE_CAP, value - 32))


def negotiate_options(opcode: int, mode: str, options: Dict[str, str], *, blksize_max: int = BLKSIZE_CAP,
                      file_size: Optional[int] = None) -> List[Tuple[str, str]]:
    """The options to put in an OACK, in the device's order; an empty list means no OACK (DATA 1 / ACK 0).

    Only requested options appear (RFC 2347) and an unusable one is left out, never answered with an ERROR:
    ``blksize`` below 8 or not a number is omitted, else ``min(requested, blksize_max)``; ``timeout`` 1-255 is
    echoed; ``tsize`` becomes the file size on an octet read (omitted in netascii, whose wire size is not known)
    and is echoed on a write; ``windowsize`` 1-65535 becomes ``min(requested, 16)``; ``rollover`` ``0``/``1``
    is echoed.  Anything else (``blksize2``, ``utimeout``, ``msftwindow``...) is omitted."""
    accepted: List[Tuple[str, str]] = []
    for name, value in options.items():
        if name == "blksize":
            n = _decimal(value)
            if n is not None and n >= MIN_BLKSIZE:
                accepted.append((name, str(min(n, int(blksize_max)))))
        elif name == "timeout":
            n = _decimal(value)
            if n is not None and TIMEOUT_OPTION_MIN <= n <= TIMEOUT_OPTION_MAX:
                accepted.append((name, str(n)))
        elif name == "tsize":
            if opcode == OP_RRQ:
                if mode == "octet" and file_size is not None:
                    accepted.append((name, str(int(file_size))))
            else:
                n = _decimal(value)
                if n is not None:
                    accepted.append((name, str(n)))
        elif name == "windowsize":
            n = _decimal(value)
            if n is not None and 1 <= n <= 65535:
                accepted.append((name, str(min(n, WINDOWSIZE_MAX))))
        elif name == "rollover":
            if value in ("0", "1"):
                accepted.append((name, value))
    return accepted


def wire_block(n: int, rollover: int = 0) -> int:
    """The 16-bit wire number of absolute block *n* (block 1 is the first; 0 is the ACK of a WRQ or an OACK).
    Past 65535 the counter wraps to 0 (the common default) or, with ``rollover=1``, to 1."""
    if n <= 0xFFFF:
        return n
    if rollover == 1:
        return (n - 1) % 0xFFFF + 1
    return n & 0xFFFF


# --- names --------------------------------------------------------------------------------
def clean_name(raw: Any) -> str:
    """The ``\\``-separated relative path a request names, or ``ValueError(MSG_NAME_NOT_ALLOWED)``.

    In order: strict UTF-8, no control characters, at most 255 characters; ``/`` becomes ``\\`` and one leading
    separator is dropped (devices ask for ``/pxelinux.0``); no drive, UNC or device-namespace prefix
    (``C:x``, ``\\\\server\\share``, ``\\\\?\\``, ``\\\\.\\``); no ``:`` (it would name an alternate data stream)
    and none of ``<>"|?*``; no empty, ``.`` or ``..`` component; no component ending in a dot or a space
    (Windows would silently drop it); no reserved device name as the part before the first dot (CON, PRN, AUX,
    NUL, CONIN$, CONOUT$, COM0-9, LPT0-9 and the superscript COM/LPT digits), in any component; at most
    :data:`MAX_DEPTH` folders; and never a name shaped like this server's own ``.part`` upload files."""
    if isinstance(raw, (bytes, bytearray)):
        try:
            name = bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(MSG_NAME_NOT_ALLOWED) from None
    else:
        name = str(raw)
    if not name or len(name) > MAX_NAME_CHARS or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        raise ValueError(MSG_NAME_NOT_ALLOWED)
    mapped = name.replace("/", "\\")
    if mapped.startswith("\\\\") or PureWindowsPath(mapped).drive:
        raise ValueError(MSG_NAME_NOT_ALLOWED)
    if mapped.startswith("\\"):
        mapped = mapped[1:]
    if any(ch in _FORBIDDEN_CHARS for ch in mapped):
        raise ValueError(MSG_NAME_NOT_ALLOWED)
    parts = mapped.split("\\")
    if len(parts) - 1 > MAX_DEPTH:
        raise ValueError(MSG_NAME_NOT_ALLOWED)
    for part in parts:
        if part in ("", ".", "..") or part[-1] in ". ":
            raise ValueError(MSG_NAME_NOT_ALLOWED)
        if part.split(".", 1)[0].rstrip(" ").upper() in _RESERVED_STEMS:
            raise ValueError(MSG_NAME_NOT_ALLOWED)
    if _PART_NAME_RE.match(parts[-1]):
        raise ValueError(MSG_NAME_NOT_ALLOWED)
    return "\\".join(parts)


def _display_name(raw: bytes) -> str:
    return bytes(raw).decode("utf-8", "backslashreplace")[:MAX_NAME_CHARS]


# --- netascii (RFC 764 line ends as TFTP uses them) --------------------------------------
class _NetasciiEncoder:
    """Local bytes to netascii for a read: a bare LF becomes CR LF, a bare CR becomes CR NUL and CR LF passes
    unchanged.  A CR at the end of one chunk waits for the next (the byte after it decides)."""

    def __init__(self) -> None:
        self._cr = False

    def feed(self, data: bytes) -> bytes:
        data = bytes(data)
        head = b""
        if self._cr and data:
            self._cr = False
            if data[:1] == b"\n":
                head, data = b"\r\n", data[1:]
            else:
                head = b"\r\0"
        if data.endswith(b"\r"):
            self._cr, data = True, data[:-1]
        return head + data.replace(b"\r\n", b"\n").replace(b"\r", b"\r\0").replace(b"\n", b"\r\n")

    def finish(self) -> bytes:
        if self._cr:
            self._cr = False
            return b"\r\0"
        return b""


class _NetasciiDecoder:
    """Netascii to local bytes for a write: CR NUL becomes CR and CR LF stays (the Windows line end).  A CR at
    the end of one block waits for the next."""

    def __init__(self) -> None:
        self._cr = False

    def feed(self, data: bytes) -> bytes:
        data = bytes(data)
        head = b""
        if self._cr and data:
            self._cr = False
            if data[:1] == b"\0":
                head, data = b"\r", data[1:]
            elif data[:1] == b"\n":
                head, data = b"\r\n", data[1:]
            else:
                head = b"\r"
        if data.endswith(b"\r"):
            self._cr, data = True, data[:-1]
        return head + data.replace(b"\r\0", b"\r")

    def finish(self) -> bytes:
        if self._cr:
            self._cr = False
            return b"\r"
        return b""


class _BlockSource:
    """The blocks of an open file, one :meth:`next_block` at a time (netascii converted on the way).  A block
    shorter than ``blksize`` is the last one; a file that is an exact multiple ends with an empty block."""

    def __init__(self, fd: int, blksize: int, netascii: bool) -> None:
        self._fd = fd
        self._blksize = int(blksize)
        self._encoder = _NetasciiEncoder() if netascii else None
        self._buf = b""
        self._pos = 0
        self._eof = False

    def next_block(self) -> bytes:
        parts: List[bytes] = []
        need = self._blksize
        while need > 0:
            if self._pos >= len(self._buf):
                if self._eof:
                    break
                chunk = os.read(self._fd, READ_CHUNK)
                if not chunk:
                    self._eof = True
                    self._buf, self._pos = (self._encoder.finish() if self._encoder else b""), 0
                    continue
                self._buf, self._pos = (self._encoder.feed(chunk) if self._encoder else chunk), 0
                continue
            piece = self._buf[self._pos:self._pos + need]
            self._pos += len(piece)
            need -= len(piece)
            parts.append(piece)
        return b"".join(parts)


class _Writer:
    """Buffered writes to an upload's ``.part`` file descriptor."""

    def __init__(self, fd: int) -> None:
        self.fd: Optional[int] = fd
        self._buf = bytearray()

    def write(self, data: bytes) -> None:
        self._buf += data
        if len(self._buf) >= WRITE_FLUSH_BYTES:
            self.flush()

    def flush(self) -> None:
        if self.fd is None or not self._buf:
            return
        data, self._buf = bytes(self._buf), bytearray()
        view = memoryview(data)
        while view:
            written = os.write(self.fd, view)
            view = view[written:]

    def close(self) -> None:
        """Flush and close (raises ``OSError`` when the flush fails; the descriptor is closed either way)."""
        if self.fd is None:
            return
        fd = self.fd
        try:
            self.flush()
        finally:
            self.fd = None
            os.close(fd)

    def discard(self) -> None:
        self._buf = bytearray()
        if self.fd is not None:
            fd, self.fd = self.fd, None
            try:
                os.close(fd)
            except OSError:
                pass


# --- Windows: final paths, UDP owners -----------------------------------------------------
FILE_READ_ATTRIBUTES = 0x0080
FILE_SHARE_ALL = 0x0007
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000     # needed to open a folder
INVALID_HANDLE_VALUE = c_void_p(-1).value
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
UDP_TABLE_OWNER_PID = 1
AF_INET, AF_INET6 = 2, 23                   # the Win32 values (socket.AF_INET6 is 23 on Windows too)
NO_ERROR = 0
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_DISK_FULL = 112
_MAX_ROWS = 1_000_000
_V4_ROW = struct.Struct("<III")              # MIB_UDPROW_OWNER_PID: dwLocalAddr, dwLocalPort, dwOwningPid
_V6_ROW = struct.Struct("<16sIII")           # MIB_UDP6ROW_OWNER_PID: ucLocalAddr, dwLocalScopeId, dwLocalPort, dwOwningPid

_dll_lock = threading.Lock()
_kernel32: Any = None
_iphlpapi: Any = None


def _dll() -> Tuple[Any, Any]:
    """Load ``kernel32`` / ``iphlpapi`` lazily with every prototype declared (import-safe off Windows)."""
    global _kernel32, _iphlpapi
    with _dll_lock:
        if _kernel32 is None:
            k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.CreateFileW.argtypes = [c_wchar_p, c_ulong, c_ulong, c_void_p, c_ulong, c_ulong, c_void_p]
            k.CreateFileW.restype = c_void_p
            k.GetFinalPathNameByHandleW.argtypes = [c_void_p, c_wchar_p, c_ulong, c_ulong]
            k.GetFinalPathNameByHandleW.restype = c_ulong
            k.CloseHandle.argtypes = [c_void_p]
            k.CloseHandle.restype = c_int
            k.OpenProcess.argtypes = [c_ulong, c_int, c_ulong]
            k.OpenProcess.restype = c_void_p
            k.QueryFullProcessImageNameW.argtypes = [c_void_p, c_ulong, c_wchar_p, POINTER(c_ulong)]
            k.QueryFullProcessImageNameW.restype = c_int
            ip = ctypes.WinDLL("iphlpapi", use_last_error=True)
            ip.GetExtendedUdpTable.argtypes = [c_void_p, POINTER(c_ulong), c_int, c_ulong, c_int, c_ulong]
            ip.GetExtendedUdpTable.restype = c_ulong
            _kernel32, _iphlpapi = k, ip
        return _kernel32, _iphlpapi


def _strip_final(path: str) -> str:
    """``\\\\?\\C:\\x`` -> ``C:\\x``; ``\\\\?\\UNC\\srv\\share`` -> ``\\\\srv\\share``."""
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def _handle_final_path(handle: Any) -> str:
    kernel, _ip = _dll()
    size = 32768
    buf = ctypes.create_unicode_buffer(size)
    n = kernel.GetFinalPathNameByHandleW(handle, buf, size, 0)      # FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
    if not n or n >= size:
        raise ctypes.WinError(ctypes.get_last_error())
    return _strip_final(buf.value)


def _final_path_of_fd(fd: int) -> str:
    """Where the open file *fd* really is (junctions and symbolic links resolved).  Raises ``OSError``."""
    if sys.platform != "win32":
        raise OSError("checking where an open file really is needs Windows")
    import msvcrt

    return _handle_final_path(msvcrt.get_osfhandle(fd))


def _final_path_of_dir(path: str) -> str:
    """Where the folder *path* really is, from a handle opened on it.  Raises ``OSError``."""
    if sys.platform != "win32":
        raise OSError("checking where a folder really is needs Windows")
    kernel, _ip = _dll()
    handle = kernel.CreateFileW(str(path), FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, None, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS, None)
    if handle is None or handle == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return _handle_final_path(handle)
    finally:
        kernel.CloseHandle(handle)


def _inside(path: str, root: str, allow_root: bool = False) -> bool:
    """True when *path* lies under *root* (both final paths; compared case-insensitively)."""
    p = os.path.normcase(_strip_final(str(path))).rstrip("\\/")
    r = os.path.normcase(_strip_final(str(root))).rstrip("\\/")
    return bool(r) and ((allow_root and p == r) or p.startswith(r + "\\") or p.startswith(r + "/"))


def _disk_free(path: str) -> Optional[int]:
    """Free bytes on the volume of *path*, None when unknown (the module seam tests replace)."""
    try:
        return int(shutil.disk_usage(path).free)
    except OSError:
        return None


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _query_udp_table(family: int) -> bytes:
    """The raw ``MIB_UDP(6)TABLE_OWNER_PID`` for *family* (grow-and-retry).  Raises ``OSError``."""
    _k, ip = _dll()
    size = c_ulong(0)
    ip.GetExtendedUdpTable(None, byref(size), False, family, UDP_TABLE_OWNER_PID, 0)
    for _ in range(8):
        buf = ctypes.create_string_buffer(max(size.value, 4))
        rc = int(ip.GetExtendedUdpTable(buf, byref(size), False, family, UDP_TABLE_OWNER_PID, 0))
        if rc == ERROR_INSUFFICIENT_BUFFER:
            continue                          # the table grew between the two calls
        if rc != NO_ERROR:
            raise OSError(rc, f"GetExtendedUdpTable(af={family}) failed: {rc}")
        return bytes(buf.raw[:size.value])
    raise OSError(ERROR_INSUFFICIENT_BUFFER, "GetExtendedUdpTable kept growing")


def parse_udp_table(raw: bytes, family: int = AF_INET) -> List[Tuple[str, int, int]]:
    """``[(local address, local port, owning pid)]`` from a ``GetExtendedUdpTable(UDP_TABLE_OWNER_PID)`` buffer:
    a ``DWORD`` count, then 12-byte ``<III`` rows for ``AF_INET`` or 28-byte ``<16sIII`` rows for ``AF_INET6``.
    The port is ``ntohs(dwLocalPort & 0xFFFF)``.  A count larger than the buffer yields the rows that fit."""
    if len(raw) < 4:
        return []
    row = _V6_ROW if family == AF_INET6 else _V4_ROW
    count = min(struct.unpack_from("<I", raw, 0)[0], (len(raw) - 4) // row.size, _MAX_ROWS)
    out: List[Tuple[str, int, int]] = []
    for i in range(count):
        fields = row.unpack_from(raw, 4 + i * row.size)
        if family == AF_INET6:
            addr, _scope, dw_port, pid = fields
            ip = socket.inet_ntop(socket.AF_INET6, addr)
        else:
            dw_addr, dw_port, pid = fields
            ip = socket.inet_ntoa(struct.pack("<I", dw_addr))
        out.append((ip, socket.ntohs(dw_port & 0xFFFF), int(pid)))
    return out


def _process_name(pid: int) -> str:
    """The image file name of *pid* (``tftpd64.exe``), else ``"PID <n>"``.  Never raises."""
    fallback = f"PID {pid}"
    if sys.platform != "win32" or int(pid) <= 0:
        return fallback
    try:
        kernel, _ip = _dll()
        handle = kernel.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return fallback
        try:
            size = c_ulong(32768)
            buf = ctypes.create_unicode_buffer(size.value)
            if not kernel.QueryFullProcessImageNameW(handle, 0, buf, byref(size)):
                return fallback
            return ntpath.basename(buf.value) or fallback
        finally:
            kernel.CloseHandle(handle)
    except Exception:  # noqa: BLE001 - a name is a nicety
        return fallback


def udp_port_owners(port: int) -> List[Dict[str, Any]]:
    """Processes other than this one holding UDP *port* on IPv4 or IPv6: ``[{"pid", "name"}]`` by pid.  Empty off
    Windows, for port 0, or when the table cannot be read (the exclusive bind still guards the port)."""
    if sys.platform != "win32" or not port:
        return []
    own = os.getpid()
    pids: List[int] = []
    for family in (AF_INET, AF_INET6):
        try:
            rows = parse_udp_table(_query_udp_table(family), family)
        except OSError:
            log.debug("could not read the UDP table (af=%s)", family, exc_info=True)
            continue
        for _ip, local_port, pid in rows:
            if local_port == int(port) and pid != own and pid not in pids:
                pids.append(pid)
    return [{"pid": pid, "name": _process_name(pid)} for pid in sorted(pids)]


# --- adapters ---------------------------------------------------------------------------------
def _candidates(adapters_fn: Optional[Callable[[], Sequence[Any]]] = None) -> List[Any]:
    """Up, non-loopback adapters that carry an IPv4 address (the DHCP server's rule)."""
    out = []
    for a in _dhcp._get_adapters(adapters_fn):
        if getattr(a, "is_loopback", False) or not getattr(a, "is_up", True):
            continue
        ip, _prefix = _dhcp._adapter_primary(a)
        if ip:
            out.append(a)
    return out


def _pick_adapter(wanted: str, candidates: List[Any]) -> Any:
    """The configured name, else the first physical Ethernet adapter, else the internet NIC, else the first
    candidate.  ``ValueError`` when nothing is usable."""
    if wanted:
        for a in candidates:
            if str(getattr(a, "name", "")) == wanted:
                return a
        raise ValueError(f"adapter '{wanted}' is not up or has no IPv4 address")
    for a in candidates:
        if int(getattr(a, "if_type", 0) or 0) == 6 and getattr(a, "is_physical", False):
            return a
    try:
        netinfo = importlib.import_module("tnt.netinfo")
        inet = netinfo.get_internet_nic(candidates)
        if inet is not None and inet in candidates:
            return inet
    except Exception:  # noqa: BLE001
        pass
    if candidates:
        return candidates[0]
    raise ValueError("no network adapter is up with an IPv4 address")


def _internet_nic(candidates: List[Any]) -> Any:
    try:
        netinfo = importlib.import_module("tnt.netinfo")
        return netinfo.get_internet_nic(candidates)
    except Exception:  # noqa: BLE001
        log.debug("get_internet_nic failed", exc_info=True)
        return None


def _adapter_dict(adapter: Any, internet: Any) -> Dict[str, Any]:
    ip, prefix = _dhcp._adapter_primary(adapter)
    return {
        "name": str(getattr(adapter, "name", "") or ""), "index": getattr(adapter, "index", None), "ip": ip,
        "prefix": prefix, "type_name": str(getattr(adapter, "type_name", "") or ""),
        "is_physical": bool(getattr(adapter, "is_physical", False)),
        "is_internet": _dhcp.DhcpServer._same_adapter(adapter, internet),
        "status": str(getattr(adapter, "status", "up") or "up"),
    }


def _serving_problem(adapter: Any, listen_ips: Sequence[str], pool: Sequence[Any]) -> Optional[str]:
    """Why the server can no longer serve from *adapter* (plain text naming the adapter only), else None."""
    name = str(getattr(adapter, "name", "") or "") or "the adapter"
    current = _dhcp.DhcpServer._same_nic(adapter, pool)
    if current is None:
        return f"{name} is no longer present"
    if not bool(getattr(current, "is_up", True)):
        return f"{name} went down"
    have = {ip for ip, _p in _dhcp._adapter_ipv4s(current)}
    if any(ip not in have for ip in listen_ips):
        return f"{name} lost its IPv4 address"
    return None


# --- the root folder --------------------------------------------------------------------------
def _entry_is_link(entry: "os.DirEntry[str]") -> bool:
    """A junction, symbolic link or any other reparse point (``is_dir(follow_symlinks=False)`` is True for a
    junction, so the attribute is what tells)."""
    try:
        if entry.is_symlink() or getattr(entry, "is_junction", lambda: False)():
            return True
        return bool(getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
                    & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return True


def _walk_files(root: str, max_depth: int = MAX_DEPTH, limit: int = WALK_MAX_ENTRIES) -> Iterator[Tuple[str, Any]]:
    """Files under *root* as ``(relative name with "\\", DirEntry)``, folder by folder (names sorted), at most
    *max_depth* folders down.  Never enters a reparse point (a root that is one yields nothing, as nothing is served
    from it) and stops after *limit* entries."""
    try:
        if _winacl._is_reparse_point(root):
            return
    except OSError:
        return
    pending: List[Tuple[str, str, int]] = [(root, "", 0)]
    seen = 0
    while pending:
        folder, prefix, depth = pending.pop(0)
        try:
            with os.scandir(folder) as it:
                entries = sorted(it, key=lambda e: e.name.casefold())
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > limit:
                return
            if _entry_is_link(entry):
                continue
            rel = prefix + entry.name
            try:
                if entry.is_dir(follow_symlinks=False):
                    if depth < max_depth:
                        pending.append((entry.path, rel + "\\", depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    yield rel, entry
            except OSError:
                continue


class _Refusal(Exception):
    """A request answered with an ERROR before any data moves."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


def _open_for_read(root: str, root_final: str, rel: str) -> Tuple[int, int]:
    """``(fd, size)`` of *rel* under *root*, or :class:`_Refusal`.  A ``realpath`` pre-check, then the checks that
    count, on the open handle: its final path lies under *root_final*, it is a regular file with one link and
    not a reparse point.  Data is read only through that descriptor."""
    path = os.path.join(root, rel)
    try:
        real = os.path.realpath(path, strict=True)
    except OSError:
        raise _Refusal(ERR_NOT_FOUND, MSG_NOT_FOUND) from None
    if not _inside(real, root_final):
        raise _Refusal(ERR_ACCESS, MSG_ACCESS_DENIED)
    if os.path.isdir(real):
        raise _Refusal(ERR_NOT_FOUND, MSG_NOT_FOUND)
    try:
        fd = os.open(path, os.O_RDONLY | _O_BINARY | _O_NOINHERIT)
    except FileNotFoundError:
        raise _Refusal(ERR_NOT_FOUND, MSG_NOT_FOUND) from None
    except OSError:
        raise _Refusal(ERR_ACCESS, MSG_ACCESS_DENIED) from None
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
                or not _inside(_final_path_of_fd(fd), root_final)):
            raise _Refusal(ERR_ACCESS, MSG_ACCESS_DENIED)
    except _Refusal:
        os.close(fd)
        raise
    except OSError:
        os.close(fd)
        raise _Refusal(ERR_ACCESS, MSG_ACCESS_DENIED) from None
    return fd, int(st.st_size)


def _create_part(root: str, root_final: str, rel: str, tsize: Optional[int], cap_bytes: int) -> Tuple[int, str, str]:
    """``(fd, part path, target path)`` for an upload of *rel*, or :class:`_Refusal`.  The parent folder must
    exist (none is ever created) and its handle must lie under *root_final*; the target must not exist in any
    form; *tsize* must fit the cap and the free space above :data:`FREE_SPACE_RESERVE`; the ``.part`` file is
    created ``O_EXCL`` and its own handle checked before a byte is written."""
    target = os.path.join(root, rel)
    parent = os.path.dirname(target)
    if not os.path.isdir(parent):
        raise _Refusal(ERR_NOT_FOUND, MSG_FOLDER_NOT_FOUND)
    try:
        parent_final = _final_path_of_dir(parent)
    except OSError:
        raise _Refusal(ERR_NOT_FOUND, MSG_FOLDER_NOT_FOUND) from None
    if not _inside(parent_final, root_final, allow_root=True):
        raise _Refusal(ERR_ACCESS, MSG_ACCESS_DENIED)
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        st = None
    except OSError:
        raise _Refusal(ERR_ACCESS, MSG_ACCESS_DENIED) from None
    if st is not None:
        plain = (stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                 and not getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        raise _Refusal(ERR_EXISTS, MSG_EXISTS) if plain else _Refusal(ERR_ACCESS, MSG_ACCESS_DENIED)
    if tsize is not None and tsize > cap_bytes:
        raise _Refusal(ERR_DISK_FULL, MSG_TOO_LARGE)
    free = _disk_free(parent)
    if free is not None and free - FREE_SPACE_RESERVE < (tsize or 0):
        raise _Refusal(ERR_DISK_FULL, MSG_DISK_FULL)
    part = os.path.join(parent, f".{os.path.basename(target)}.{secrets.token_hex(4)}.part")
    try:
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_NOINHERIT)
    except OSError:
        raise _Refusal(ERR_ACCESS, MSG_ACCESS_DENIED) from None
    try:
        if not _inside(_final_path_of_fd(fd), root_final):
            raise _Refusal(ERR_ACCESS, MSG_ACCESS_DENIED)
    except BaseException as exc:
        os.close(fd)
        _remove_quietly(part)
        if isinstance(exc, OSError):
            raise _Refusal(ERR_ACCESS, MSG_ACCESS_DENIED) from None
        raise
    return fd, part, target


# --- transfers --------------------------------------------------------------------------------
class _Transfer:
    """One request's bookkeeping (TRANSFER in the module notes)."""

    def __init__(self, tid: int, client: str, client_port: int, listen_ip: str, op: str, file: str, mode: str,
                 started_ts: float, started_mono: float) -> None:
        self.id = tid
        self.client = client
        self.client_port = client_port
        self.listen_ip = listen_ip
        self.op = op
        self.file = file
        self.mode = mode
        self.blksize = DEFAULT_BLKSIZE
        self.windowsize = 1
        self.size: Optional[int] = None
        self.bytes = 0
        self.state = "negotiating"
        self.error: Optional[str] = None
        self.started_ts = started_ts
        self.ended_ts: Optional[float] = None
        self.started_mono = started_mono
        self.holds_slot = True               # counts toward the limits until it finishes (a dally holds none)
        self.began = False                   # got past the checks (announced with tftp.state)
        self.last_event: Optional[float] = None
        self.cancel = threading.Event()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "client": self.client, "op": self.op, "file": self.file, "mode": self.mode,
            "blksize": self.blksize, "windowsize": self.windowsize, "size": self.size, "bytes": self.bytes,
            "state": self.state, "error": self.error, "started_ts": self.started_ts, "ended_ts": self.ended_ts,
        }


class _Session:
    """One transfer on its own socket, run on its own thread (``tnt-tftp-xfer``)."""

    def __init__(self, server: "TftpServer", tr: _Transfer, sock: Any, stop_evt: threading.Event) -> None:
        self.srv = server
        self.tr = tr
        self.sock = sock
        self.peer = (tr.client, tr.client_port)
        self.stop_evt = stop_evt
        self.timers = server._timers
        self.mono = server._mono
        self.rto_start = float(self.timers.initial_s)
        self.rto = self.rto_start
        self.retries = 0
        self.last_progress = self.mono()
        self.last_err5: Optional[float] = None
        self.negotiated_timeout: Optional[int] = None
        self.rollover: Optional[int] = None

    # -- plumbing ---------------------------------------------------------------------------
    def send(self, packet: bytes) -> None:
        try:
            self.sock.sendto(packet, self.peer)
        except OSError:
            log.debug("TFTP send failed", exc_info=True)

    def stopping(self) -> bool:
        return self.stop_evt.is_set() or self.tr.cancel.is_set()

    def wait(self, deadline: float) -> Tuple[str, bytes]:
        """The next datagram from the peer before *deadline*: ``("packet", raw)``, ``("timeout", b"")``,
        ``("reset", b"")`` (WinError 10054) or ``("stop", b"")``.  A datagram from any other address or port gets
        ERROR 5 (at most once a second, only inside the served subnets) and changes nothing."""
        while True:
            if self.stopping():
                return "stop", b""
            remaining = deadline - self.mono()
            if remaining <= 0:
                return "timeout", b""
            try:
                ready = select.select([self.sock], [], [], min(remaining, TRANSFER_TICK_S))[0]
            except (OSError, ValueError):
                return "stop", b""
            if not ready:
                continue
            try:
                raw, src = self.sock.recvfrom(RECV_BUFFER)
            except ConnectionResetError:
                return "reset", b""
            except (BlockingIOError, InterruptedError, socket.timeout):
                continue
            except OSError:
                if self.stopping():
                    return "stop", b""
                log.debug("TFTP receive failed", exc_info=True)
                return "reset", b""
            try:
                source = (str(src[0]), int(src[1]))
            except (TypeError, ValueError, IndexError):
                continue
            if source != self.peer:
                self.unknown_tid(source)
                continue
            return "packet", raw

    def unknown_tid(self, source: Tuple[str, int]) -> None:
        if not self.srv._client_allowed(*source):
            return
        now = self.mono()
        if self.last_err5 is not None and now - self.last_err5 < ERROR5_INTERVAL_S:
            return
        self.last_err5 = now
        log.debug("TFTP datagram from an unknown transfer ID %s:%s", *source)
        try:
            self.sock.sendto(encode_error(ERR_UNKNOWN_TID, MSG_UNKNOWN_TID), source)
        except OSError:
            pass

    def backoff(self) -> bool:
        """A retransmit is due: count it and double the timeout (up to the cap, never below a negotiated one).
        False when the retries are used up or nothing moved for ``idle_s``."""
        self.retries += 1
        if self.retries > int(self.timers.retries) or self.mono() - self.last_progress >= float(self.timers.idle_s):
            return False
        self.rto = min(self.rto * 2.0, max(float(self.timers.cap_s), self.rto_start))
        return True

    def reset_seen(self) -> bool:
        """A 10054 (the device's port answered ICMP unreachable) counts as a failed retry."""
        self.retries += 1
        return self.retries <= int(self.timers.retries)

    def progress(self) -> None:
        self.last_progress = self.mono()
        self.retries = 0
        self.rto = self.rto_start
        self.srv._publish_transfer(self.tr)

    def apply_options(self, accepted: Sequence[Tuple[str, str]]) -> None:
        opts = dict(accepted)
        if "blksize" in opts:
            self.tr.blksize = int(opts["blksize"])
        if "windowsize" in opts:
            self.tr.windowsize = int(opts["windowsize"])
        if "rollover" in opts:
            self.rollover = int(opts["rollover"])
        if "timeout" in opts:
            self.negotiated_timeout = int(opts["timeout"])
            self.rto_start = self.rto = float(self.negotiated_timeout)

    # A last packet goes out only after the transfer is finished, so a device that reacts at once (asks again
    # from the same port) never meets its own ended session.
    def refuse(self, code: int, message: str) -> None:
        self.srv._finish(self.tr, "failed", message, refused=True)
        self.send(encode_error(code, message))

    def abort(self, code: int, message: str) -> None:
        self.srv._finish(self.tr, "failed", message)
        self.send(encode_error(code, message))

    def cancelled(self) -> None:
        self.srv._finish(self.tr, "cancelled", MSG_CANCELLED)
        self.send(encode_error(ERR_UNDEFINED, MSG_SHUTDOWN))

    def device_error(self, code: int, rest: bytes, before_data: bool) -> None:
        """The device sent ERROR: the transfer ends at once (never answered).  During option negotiation that is
        routine (PXE firmware asks for ``tsize`` only, aborts, then asks again), so it reads as cancelled."""
        text = _device_text(rest)
        detail = f"The device ended the transfer (error {code}: {text})" if text else \
            f"The device ended the transfer (error {code})"
        self.srv._finish(self.tr, "cancelled" if before_data else "failed", detail)

    def give_up(self, final_sent: bool) -> None:
        if final_sent:
            self.srv._finish(self.tr, "unconfirmed", MSG_UNCONFIRMED)
        else:
            self.abort(ERR_UNDEFINED, MSG_TIMED_OUT)

    def wire(self, n: int) -> int:
        return wire_block(n, self.rollover or 0)

    # -- RRQ --------------------------------------------------------------------------------
    def run_read(self, req: Request) -> None:
        tr, srv = self.tr, self.srv
        if req.mode not in MODES:
            return self.refuse(ERR_ILLEGAL, MSG_MODE)
        try:
            rel = clean_name(req.filename)
        except ValueError:
            return self.refuse(ERR_ACCESS, MSG_NAME_NOT_ALLOWED)
        root, root_final = srv._root_for_request()
        if root_final is None:
            return self.refuse(ERR_NOT_FOUND, MSG_NOT_FOUND)
        try:
            fd, size = _open_for_read(root, root_final, rel)
        except _Refusal as refusal:
            return self.refuse(refusal.code, refusal.message)
        try:
            netascii = req.mode == "netascii"
            tr.size = None if netascii else size
            accepted = negotiate_options(OP_RRQ, req.mode, req.options, blksize_max=srv._blksize_max, file_size=size)
            self.apply_options(accepted)
            source = _BlockSource(fd, tr.blksize, netascii)
            if accepted and not self.negotiate_read(encode_oack(accepted)):
                return None
            self.send_blocks(source)
        finally:
            os.close(fd)
        return None

    def negotiate_read(self, oack: bytes) -> bool:
        """OACK until the device confirms it with ACK 0 (resent on timeout)."""
        self.srv._began(self.tr)
        self.send(oack)
        deadline = self.mono() + self.rto
        while True:
            kind, raw = self.wait(deadline)
            if kind == "stop":
                self.cancelled()
                return False
            if kind == "reset":
                if not self.reset_seen():
                    self.give_up(False)
                    return False
                continue
            if kind == "timeout":
                if not self.backoff():
                    self.give_up(False)
                    return False
                self.send(oack)
                deadline = self.mono() + self.rto
                continue
            op, num, rest = _parse_packet(raw)
            if op == OP_ACK and num == 0:
                self.progress()
                return True
            if op == OP_ERROR:
                self.device_error(num, rest, before_data=True)
                return False

    def send_blocks(self, source: _BlockSource) -> None:
        """Send the file a window at a time.  An ACK for the window's last block moves on; an ACK for an earlier
        block of the window restarts from the block after it; a duplicate or stale ACK is ignored (RFC 1123
        §4.2.3.1: never resend on a duplicate ACK); a timeout resends the unacknowledged blocks."""
        tr, srv = self.tr, self.srv
        window, blksize = max(1, int(tr.windowsize)), int(tr.blksize)
        srv._set_state(tr, "sending")
        pending: List[Tuple[int, bytes]] = []          # (absolute block, payload) sent, not yet acknowledged
        next_n = 1
        final_n: Optional[int] = None

        def fill() -> bool:
            nonlocal next_n, final_n
            while final_n is None and len(pending) < window:
                try:
                    payload = source.next_block()
                except OSError:
                    log.debug("TFTP read of %r failed", tr.file, exc_info=True)
                    self.abort(ERR_UNDEFINED, MSG_READ_FAILED)
                    return False
                pending.append((next_n, payload))
                if len(payload) < blksize:
                    final_n = next_n
                next_n += 1
            return True

        def send_pending() -> None:
            for n, payload in pending:
                self.send(encode_data(self.wire(n), payload))

        if not fill():
            return
        send_pending()
        deadline = self.mono() + self.rto
        while True:
            kind, raw = self.wait(deadline)
            if kind == "stop":
                return self.cancelled()
            if kind == "reset":
                if not self.reset_seen():
                    return self.give_up(final_n is not None)
                continue
            if kind == "timeout":
                if not self.backoff():
                    return self.give_up(final_n is not None)
                send_pending()
                deadline = self.mono() + self.rto
                continue
            op, num, rest = _parse_packet(raw)
            if op == OP_ERROR:
                return self.device_error(num, rest, before_data=False)
            if op != OP_ACK:
                continue
            hit = next((i for i, (n, _p) in enumerate(pending) if self.wire(n) == num), None)
            if hit is None:
                continue
            acked_n = pending[hit][0]
            tr.bytes += sum(len(p) for _n, p in pending[:hit + 1])
            del pending[:hit + 1]
            self.progress()
            if acked_n == final_n:
                return srv._finish(tr, "done")
            if not fill():
                return None
            send_pending()
            deadline = self.mono() + self.rto

    # -- WRQ --------------------------------------------------------------------------------
    def run_write(self, req: Request) -> None:
        tr, srv = self.tr, self.srv
        if not srv.uploads:                          # first: nothing else about the request matters while this is off
            return self.refuse(ERR_ACCESS, MSG_UPLOADS_OFF)
        if req.mode not in MODES:
            return self.refuse(ERR_ILLEGAL, MSG_MODE)
        try:
            rel = clean_name(req.filename)
        except ValueError:
            return self.refuse(ERR_ACCESS, MSG_NAME_NOT_ALLOWED)
        root, root_final = srv._root_for_request()
        if root_final is None:
            return self.refuse(ERR_NOT_FOUND, MSG_FOLDER_NOT_FOUND)
        accepted = negotiate_options(OP_WRQ, req.mode, req.options, blksize_max=srv._blksize_max)
        tsize = _decimal(dict(accepted)["tsize"]) if "tsize" in dict(accepted) else None
        tr.size = tsize
        cap = srv._max_upload_bytes()
        try:
            fd, part, target = _create_part(root, root_final, rel, tsize, cap)
        except _Refusal as refusal:
            return self.refuse(refusal.code, refusal.message)
        srv._track_part(part, True)
        writer = _Writer(fd)
        committed = False
        try:
            self.apply_options(accepted)
            committed = self.receive_blocks(writer, part, target, cap, encode_oack(accepted) if accepted else None)
        finally:
            if not committed:
                writer.discard()
                _remove_quietly(part)
            srv._track_part(part, False)
        return None

    def wires_for(self, n: int) -> Tuple[int, ...]:
        """Wire numbers accepted for absolute block *n*: after 65535 a device may wrap to 0 or to 1; the first one
        seen is kept for the rest of the upload."""
        if n == 0x10000 and self.rollover is None:
            return (0, 1)
        return (self.wire(n),)

    def receive_blocks(self, writer: _Writer, part: str, target: str, cap: int, oack: Optional[bytes]) -> bool:
        """Receive the upload; True once it is committed (renamed into place before the final ACK goes out).

        With a window of W the server ACKs after W in-order blocks or the final one.  A block from the future
        (a gap) is dropped and the last in-order block ACKed once; an old block repeats that ACK (every time with
        W = 1, once per burst otherwise).  A timeout repeats it too (or the OACK / ACK 0 before any data) and counts
        the window from there again: the device restarts its window at the block after that ACK (RFC 7440)."""
        tr, srv = self.tr, self.srv
        window, blksize = max(1, int(tr.windowsize)), int(tr.blksize)
        decoder = _NetasciiDecoder() if tr.mode == "netascii" else None
        srv._began(tr)
        if oack is None:
            srv._set_state(tr, "receiving")
        reply = oack if oack is not None else encode_ack(0)
        self.send(reply)
        expected, in_window, repeated = 1, 0, False
        next_free_check = FREE_SPACE_CHECK_BYTES
        deadline = self.mono() + self.rto
        while True:
            kind, raw = self.wait(deadline)
            if kind == "stop":
                self.cancelled()
                return False
            if kind == "reset":
                if not self.reset_seen():
                    self.abort(ERR_UNDEFINED, MSG_TIMED_OUT)
                    return False
                continue
            if kind == "timeout":
                if not self.backoff():
                    self.abort(ERR_UNDEFINED, MSG_TIMED_OUT)
                    return False
                self.send(reply)
                in_window = 0
                deadline = self.mono() + self.rto
                continue
            op, num, payload = _parse_packet(raw)
            if op == OP_ERROR:
                self.device_error(num, payload, before_data=expected == 1)
                return False
            if op != OP_DATA:
                continue
            if num not in self.wires_for(expected):
                behind = any(num == self.wire(expected - k) for k in range(1, window + 1) if expected - k >= 1)
                ahead = not behind and any(num == self.wire(expected + k) for k in range(1, window + 1))
                if behind and (window == 1 or not repeated):
                    self.send(reply)
                    repeated = True
                elif ahead and not repeated:
                    self.send(reply)
                    repeated, in_window = True, 0
                continue
            if expected == 0x10000 and self.rollover is None:
                self.rollover = num
            if len(payload) > blksize:
                self.abort(ERR_ILLEGAL, MSG_OVERSIZE)
                return False
            final = len(payload) < blksize
            data = decoder.feed(payload) if decoder else payload
            if final and decoder:
                data += decoder.finish()
            if tr.bytes + len(data) > cap:
                self.abort(ERR_DISK_FULL, MSG_TOO_LARGE)
                return False
            try:
                writer.write(data)
            except OSError as exc:
                self.write_failed(exc)
                return False
            tr.bytes += len(data)
            if tr.bytes >= next_free_check:
                next_free_check += FREE_SPACE_CHECK_BYTES
                free = _disk_free(os.path.dirname(part))
                if free is not None and free < FREE_SPACE_RESERVE:
                    self.abort(ERR_DISK_FULL, MSG_DISK_FULL)
                    return False
            if tr.state != "receiving":
                srv._set_state(tr, "receiving")
            reply = encode_ack(num)
            expected, in_window, repeated = expected + 1, in_window + 1, False
            self.progress()
            if final:
                try:
                    writer.close()
                    os.rename(part, target)          # create-only: FileExistsError if the name appeared meanwhile
                except FileExistsError:
                    self.abort(ERR_EXISTS, MSG_EXISTS)
                    return False
                except OSError as exc:
                    self.write_failed(exc)
                    return False
                srv._finish(tr, "done")
                self.send(reply)
                self.dally(num, reply)
                return True
            if in_window >= window:
                self.send(reply)
                in_window = 0
            deadline = self.mono() + self.rto

    def write_failed(self, exc: OSError) -> None:
        log.debug("TFTP write of %r failed", self.tr.file, exc_info=True)
        if getattr(exc, "winerror", None) == ERROR_DISK_FULL or getattr(exc, "errno", None) == errno.ENOSPC:
            self.abort(ERR_DISK_FULL, MSG_DISK_FULL)
        else:
            self.abort(ERR_UNDEFINED, MSG_WRITE_FAILED)

    def dally(self, final_wire: int, ack: bytes) -> None:
        """After the final ACK of an upload: a resent final DATA (its ACK was lost) is ACKed again, and the
        committed file is never touched.  The upload is already reported done and holds no limit slot; stop()
        ends the dally at once."""
        deadline = self.mono() + self.timers.dally_s(self.negotiated_timeout)
        while True:
            kind, raw = self.wait(deadline)
            if kind in ("stop", "timeout"):
                return
            if kind == "reset":
                continue
            op, num, _rest = _parse_packet(raw)
            if op == OP_DATA and num == final_wire:
                self.send(ack)


# --- the component --------------------------------------------------------------------------
class TftpServer:
    """The TFTP server component (one instance per Engine; ``engine.tftp``).

    Off after every service start.  :meth:`start` picks the adapter, secures the root, checks the port's
    owners, adds the firewall rule (installed service only) and binds one listener per adapter IPv4 address,
    served by the thread ``tnt-tftp-listen``; each request runs on its own ``tnt-tftp-xfer`` thread.
    :meth:`stop` ends everything within :data:`STOP_JOIN_S`.  Works without a database."""

    def __init__(self, db: Any, config: Any, bus: Any, clock: Callable[[], float] = time.time, *,
                 socket_factory: Optional[Callable[..., Any]] = None, runner: Optional[Callable[..., Any]] = None,
                 adapters_fn: Optional[Callable[[], Sequence[Any]]] = None, port: int = DEFAULT_PORT,
                 exe_path: Optional[str] = None, root: Any = None,
                 udp_owners_fn: Optional[Callable[[int], List[Dict[str, Any]]]] = None,
                 acl: Optional[Callable[[str, str], None]] = None, timers: Optional[TftpTimers] = None,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self._db = db
        self._config = config
        self._bus = bus
        self._clock = clock
        self._mono = monotonic
        self._socket_factory = socket_factory or socket.socket
        self._runner = runner
        self._adapters_fn = adapters_fn
        self._port = int(port)
        # None = never manage a firewall rule (console / dev runs and tests; the installed service passes its exe)
        self._exe_path = exe_path or None
        self._root = root
        self._udp_owners_fn = udp_owners_fn
        self._acl = acl
        self._timers = timers or TftpTimers()
        self._lock = threading.RLock()           # state
        self._op_lock = threading.RLock()        # start / stop are serialised
        self._stop_evt = threading.Event()
        self._running = False
        self._since_ts: Optional[float] = None
        self._error: Optional[str] = None
        self._warning: Optional[str] = None
        self._root_warning: Optional[str] = None
        self._adapter: Any = None
        self._listen: List[Tuple[str, int]] = []
        self._listen_socks: List[Any] = []
        self._listen_thread: Optional[threading.Thread] = None
        self._nets: List[ipaddress.IPv4Network] = []
        self._uploads = False
        self._firewall: Dict[str, Any] = {"rule": FIREWALL_RULE_NAME, "ok": None, "error": None}
        self._conflict: Optional[Dict[str, Any]] = None
        self._root_final: Optional[str] = None
        self._blksize_max = BLKSIZE_CAP
        self._transfers: Dict[int, _Transfer] = {}
        self._by_key: Dict[Tuple[str, int], Tuple[_Transfer, bytes]] = {}     # client (ip, port) -> (live transfer, request)
        self._threads: Set[threading.Thread] = set()
        self._parts: Set[str] = set()
        self._history: Deque[_Transfer] = deque(maxlen=HISTORY_KEEP)
        self._counts: Dict[str, int] = {k: 0 for k in TFTP_COUNT_KEYS if k != "active"}
        self._next_id = 1

    # -- small helpers ----------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._running

    @property
    def uploads(self) -> bool:
        return self._uploads

    def _cfg(self, key: str, default: Any) -> Any:
        try:
            value = self._config.get(f"tftp.{key}", default)
            return default if value is None else value
        except Exception:  # noqa: BLE001
            return default

    def _settings(self) -> Dict[str, Any]:
        """The tftp settings with local defaults."""
        mb = self._cfg("max_upload_mb", DEFAULT_MAX_UPLOAD_MB)
        try:
            mb = DEFAULT_MAX_UPLOAD_MB if isinstance(mb, bool) else max(MAX_UPLOAD_MB_MIN, min(MAX_UPLOAD_MB_MAX, int(float(mb))))
        except (TypeError, ValueError, OverflowError):
            mb = DEFAULT_MAX_UPLOAD_MB
        return {"adapter": str(self._cfg("adapter", "") or "").strip(), "max_upload_mb": mb}

    def _max_upload_bytes(self) -> int:
        return int(self._settings()["max_upload_mb"]) * 1024 * 1024

    def _root_path(self) -> str:
        return os.fspath(self._root) if self._root is not None else str(paths.tftp_dir())

    def _publish(self, event_type: str, data: Dict[str, Any]) -> None:
        try:
            self._bus.publish(event_type, data)
        except Exception:  # noqa: BLE001
            log.exception("publish %s failed", event_type)

    def _publish_state(self) -> None:
        self._publish("tftp.state", self.summary())

    def _publish_transfer(self, tr: _Transfer, force: bool = False) -> None:
        now = self._mono()
        if not force and tr.last_event is not None and now - tr.last_event < TRANSFER_EVENT_INTERVAL_S:
            return
        tr.last_event = now
        self._publish("tftp.transfer", {"transfer": tr.to_dict()})

    def _db_event(self, level: str, message: str) -> None:
        if self._db is None:
            return
        try:
            self._db.add_event(level, "tftp", message)
        except Exception:  # noqa: BLE001
            log.debug("db event failed", exc_info=True)

    def _client_allowed(self, ip: str, port: int) -> bool:
        """A sane unicast source inside one of the served IPv4 subnets (not its network or broadcast address)."""
        try:
            if not 0 < int(port) <= 65535:
                return False
            addr = ipaddress.IPv4Address(str(ip))
        except (TypeError, ValueError):
            return False
        if addr.is_multicast or addr.is_reserved or int(addr) >> 24 == 0:
            return False
        with self._lock:
            nets = list(self._nets)
        for net in nets:
            if addr in net:
                return net.prefixlen >= 31 or addr not in (net.network_address, net.broadcast_address)
        return False

    def _track_part(self, part: str, busy: bool) -> None:
        with self._lock:
            if busy:
                self._parts.add(os.path.normcase(part))
            else:
                self._parts.discard(os.path.normcase(part))

    def _resolve_root_final(self) -> Optional[str]:
        """The root's own final path, None when it is missing or is itself a link (then nothing is served)."""
        root = self._root_path()
        try:
            if _winacl._is_reparse_point(root):
                log.warning("the TFTP folder is a link; nothing is served from it")
                return None
            if not os.path.isdir(root):
                return None
            return _final_path_of_dir(root)
        except OSError:
            log.debug("could not resolve the TFTP folder", exc_info=True)
            return None

    def _root_for_request(self) -> Tuple[str, Optional[str]]:
        with self._lock:
            final = self._root_final
        if final is None:
            final = self._resolve_root_final()
            with self._lock:
                if self._running:
                    self._root_final = final
        return self._root_path(), final

    # -- folder -------------------------------------------------------------------------------
    def ensure_root(self) -> None:
        """Create and secure the root folder (``acl(root, TFTP_SDDL)``, default :func:`tnt.winacl.secure_dir`) and
        delete ``.part`` files an interrupted upload left behind.  Never raises: a failure only sets the status
        warning."""
        try:
            acl = self._acl or _winacl.secure_dir
            acl(self._root_path(), _winacl.TFTP_SDDL)
            warning = None
        except Exception as exc:  # noqa: BLE001
            warning = f"The TFTP folder could not be secured ({exc})"
            log.warning("the TFTP folder could not be secured: %s", exc)
        with self._lock:
            self._root_warning = warning
        try:
            self._remove_stale_parts(self._root_path())
        except Exception:  # noqa: BLE001
            log.exception("could not clean up the TFTP folder")

    def _remove_stale_parts(self, root: str) -> None:
        removed = 0
        for _rel, entry in _walk_files(root):
            if not _PART_RE.match(entry.name):
                continue
            with self._lock:
                busy = os.path.normcase(entry.path) in self._parts
            if busy:
                continue
            try:
                os.remove(entry.path)
                removed += 1
            except OSError:
                log.debug("could not remove an unfinished upload", exc_info=True)
        if removed:
            log.info("removed %d unfinished TFTP upload(s)", removed)

    def files(self) -> List[Dict[str, Any]]:
        """The files devices can ask for: ``[{"name", "size", "mtime"}]`` with ``/`` separators, sorted by name,
        at most :data:`MAX_DEPTH` folders down and :data:`MAX_FILES` entries.  Unfinished uploads, links and names a
        request could not use are left out."""
        out: List[Dict[str, Any]] = []
        for rel, entry in _walk_files(self._root_path()):
            if _PART_RE.match(entry.name):
                continue
            try:
                clean_name(rel)
                st = entry.stat(follow_symlinks=False)
            except (ValueError, OSError):
                continue
            out.append({"name": rel.replace("\\", "/"), "size": int(st.st_size), "mtime": float(st.st_mtime)})
            if len(out) >= MAX_FILES:
                break
        out.sort(key=lambda f: f["name"].casefold())
        return out

    # -- lifecycle ------------------------------------------------------------------------------
    def _port_owners(self) -> List[Dict[str, Any]]:
        fn = self._udp_owners_fn or udp_port_owners
        try:
            owners = list(fn(self._port) or [])
        except Exception:  # noqa: BLE001 - an unreadable table does not block a start (the bind is exclusive)
            log.debug("could not look up the owners of the TFTP port", exc_info=True)
            return []
        return [{"pid": int(o.get("pid") or 0), "name": str(o.get("name") or f"PID {o.get('pid')}")}
                for o in owners if isinstance(o, dict)]

    def _ensure_firewall(self) -> Tuple[Optional[bool], Optional[str]]:
        """The inbound rule for our exe, scoped to the local subnet; ``(None, None)`` (not managed) without an
        ``exe_path``.  Mirrored into ``status()["firewall"]``."""
        if not self._exe_path:
            result: Tuple[Optional[bool], Optional[str]] = (None, None)
        else:
            result = _firewall.ensure_rule(FIREWALL_RULE_NAME, self._exe_path, "udp", self._port or DEFAULT_PORT,
                                           self._runner, remote_ip=FIREWALL_REMOTE_IP)
        with self._lock:
            self._firewall = {"rule": FIREWALL_RULE_NAME, "ok": result[0], "error": result[1]}
        return result

    def _open_listeners(self, ips: Sequence[str]) -> List[Tuple[str, int, Any]]:
        """One exclusive socket per address on the server port: ``[(ip, bound port, socket)]``.
        :class:`TftpPortInUse` when the port is taken, ``RuntimeError`` when it cannot be opened otherwise."""
        opened: List[Tuple[str, int, Any]] = []
        sock: Any = None
        try:
            for ip in ips:
                sock = self._socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
                exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
                if exclusive is not None:
                    sock.setsockopt(socket.SOL_SOCKET, exclusive, 1)
                _bind_udp(sock, (ip, self._port))
                try:
                    bound = int(sock.getsockname()[1]) or self._port
                except Exception:  # noqa: BLE001 - a fake may not implement getsockname
                    bound = self._port
                opened.append((ip, bound, sock))
                sock = None
        except OSError as exc:
            for s in [sock] + [s for _ip, _p, s in opened]:
                if s is not None:
                    try:
                        s.close()
                    except Exception:  # noqa: BLE001
                        pass
            code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
            if code in (10048, 98, 48):
                raise TftpPortInUse(f"UDP port {self._port} is already used by another program") from exc
            if code in (10013, 13):
                raise RuntimeError(f"UDP port {self._port} could not be opened (access denied: another program may "
                                   f"hold it exclusively, or Windows reserves the port)") from exc
            if code in (10049, 99, 49):
                raise RuntimeError(f"UDP port {self._port} could not be opened: the adapter address is not ready "
                                   f"yet") from exc
            raise RuntimeError(f"UDP port {self._port} could not be opened: {exc}") from exc
        return opened

    def _fail_start(self, exc: Exception) -> NoReturn:
        with self._lock:
            self._error = str(exc)
            if isinstance(exc, TftpPortInUse):
                self._conflict = {"port": self._port, "owners": [dict(o) for o in exc.owners]}
        self._publish_state()
        raise exc

    def start(self, adapter: Optional[str] = None, uploads: bool = False) -> Dict[str, Any]:
        """Serve on *adapter* (None: the ``tftp.adapter`` setting, else the automatic pick) with uploads on or off.

        ``ValueError`` for a bad argument or no usable adapter; :class:`TftpPortInUse` when another program holds
        the port; ``RuntimeError`` when the port cannot be opened.  A folder that could not be secured and a
        firewall rule that could not be added are warnings.  Already running: the status, unchanged."""
        if not isinstance(uploads, bool):
            raise ValueError("uploads must be true or false")
        if adapter is not None and not isinstance(adapter, str):
            raise ValueError("adapter must be a name or null")
        with self._op_lock:
            if self._running:
                return self.status()
            # a fresh lifecycle event per run: a thread of the previous run that outlived stop()'s join keeps its
            # own (set) event and can never serve under this start
            stop_evt = threading.Event()
            self._stop_evt = stop_evt
            with self._lock:
                self._error = None
                self._warning = None
                self._conflict = None
            settings = self._settings()
            wanted = settings["adapter"] if adapter is None else adapter.strip()
            chosen = _pick_adapter(wanted, _candidates(self._adapters_fn))
            name = str(getattr(chosen, "name", "") or "")
            addrs = _dhcp._adapter_ipv4s(chosen)
            if not addrs:
                raise ValueError(f"adapter '{name}' is not up or has no IPv4 address")
            self.ensure_root()
            root_final = self._resolve_root_final()
            owners = self._port_owners()
            if owners:
                names = ", ".join(o["name"] for o in owners)
                self._fail_start(TftpPortInUse(f"UDP port {self._port} is already used by {names}", owners))
            ok, err = self._ensure_firewall()
            warning = None
            if ok is False:
                warning = f"Windows Firewall rule could not be created ({err}); devices may not reach the server"
                log.warning("the TFTP firewall rule could not be created: %s", err)
            try:
                listeners = self._open_listeners([ip for ip, _prefix in addrs])
            except RuntimeError as exc:
                self._fail_start(exc)
            if stop_evt.is_set():
                for _ip, _p, s in listeners:
                    try:
                        s.close()
                    except Exception:  # noqa: BLE001
                        pass
                raise RuntimeError("start cancelled")
            nets: List[ipaddress.IPv4Network] = []
            for ip, prefix in addrs:
                try:
                    nets.append(ipaddress.IPv4Interface(f"{ip}/{prefix}").network)
                except ValueError:
                    continue
            with self._lock:
                self._running = True
                self._since_ts = self._clock()
                self._adapter = chosen
                self._listen = [(ip, port) for ip, port, _s in listeners]
                self._listen_socks = [s for _ip, _port, s in listeners]
                self._nets = nets
                self._uploads = uploads
                self._warning = warning
                self._root_final = root_final
                self._blksize_max = blksize_max(getattr(chosen, "mtu", None))
                self._listen_thread = threading.Thread(target=self._listen_loop, args=(stop_evt, listeners),
                                                       name="tnt-tftp-listen", daemon=True)
                self._listen_thread.start()
            firewall_text = "not managed" if ok is None else ("ok" if ok else "failed")
            log.info("TFTP server started on '%s' (%d address(es)), uploads %s, firewall %s", name, len(listeners),
                     "on" if uploads else "off", firewall_text)
            self._db_event("info", f"TFTP server started on {name}, uploads {'on' if uploads else 'off'}")
            self._publish_state()
            return self.status()

    def stop(self) -> Dict[str, Any]:
        """Stop serving: close the listeners, end every transfer (the device gets ERROR 0 "Server is shutting down")
        and join the threads within :data:`STOP_JOIN_S`.  Uploads switch off.  Idempotent; at once when idle."""
        self._stop_evt.set()          # also aborts a start that is still binding
        with self._op_lock:
            with self._lock:
                was_running = self._running
                self._running = False
                socks, self._listen_socks = self._listen_socks, []
                listen_thread, self._listen_thread = self._listen_thread, None
                threads = list(self._threads)
                for tr in self._transfers.values():
                    tr.cancel.set()
                self._uploads = False
            if not was_running and not threads:
                return self.status()
            for s in socks:
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass
            deadline = time.monotonic() + STOP_JOIN_S
            if listen_thread is not None and listen_thread.is_alive() and listen_thread is not threading.current_thread():
                listen_thread.join(max(0.01, deadline - time.monotonic()))
            with self._lock:
                # again, now the listener is gone: a request it took just before the stop may have started a transfer
                threads = list(self._threads)
                for tr in self._transfers.values():
                    tr.cancel.set()
            for t in threads:
                if t.is_alive() and t is not threading.current_thread():
                    t.join(max(0.01, deadline - time.monotonic()))
            with self._lock:
                self._since_ts = None
                self._listen = []
                self._nets = []
                self._adapter = None
                self._root_final = None
            if was_running:
                log.info("TFTP server stopped")
                self._db_event("info", "TFTP server stopped")
                self._publish_state()
            return self.status()

    def set_uploads(self, on: bool) -> Dict[str, Any]:
        """Switch uploads on or off (never saved: off after every start of the service and every stop)."""
        if not isinstance(on, bool):
            raise ValueError("on must be true or false")
        with self._lock:
            changed = self._uploads != on
            self._uploads = on
        if changed:
            log.info("TFTP uploads switched %s", "on" if on else "off")
            self._db_event("info", f"TFTP uploads switched {'on' if on else 'off'}")
            self._publish_state()
        return self.status()

    def update_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and save ``tftp.adapter`` / ``tftp.max_upload_mb``; any other key is a ``ValueError``.  The
        adapter is used at the next start; the upload cap applies to the next upload."""
        if not isinstance(patch, dict):
            raise ValueError("settings patch must be an object")
        unknown = sorted(str(k) for k in patch if k not in TFTP_SETTINGS_KEYS)
        if unknown:
            raise ValueError(f"unknown TFTP setting '{unknown[0][:40]}'")
        new: Dict[str, Any] = {}
        if "adapter" in patch:
            value = patch.get("adapter")
            if value is not None and not isinstance(value, str):
                raise ValueError("adapter must be a name or empty")
            name = (value or "").strip()
            if name and name not in [str(getattr(a, "name", "")) for a in _candidates(self._adapters_fn)]:
                raise ValueError(f"adapter '{name[:40]}' is not up or has no IPv4 address")
            new["adapter"] = name
        if "max_upload_mb" in patch:
            value = patch.get("max_upload_mb")
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(MAX_UPLOAD_MB_MSG)
            try:
                mb = int(value)
            except (ValueError, OverflowError):
                raise ValueError(MAX_UPLOAD_MB_MSG) from None
            if mb != value or not MAX_UPLOAD_MB_MIN <= mb <= MAX_UPLOAD_MB_MAX:
                raise ValueError(MAX_UPLOAD_MB_MSG)
            new["max_upload_mb"] = mb
        if new:
            try:
                self._config.update({"tftp": new})
            except ValueError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError(f"settings could not be saved: {exc}") from exc
            self._publish_state()
        return self.status()

    # -- network changes ------------------------------------------------------------------------
    def on_network_change(self, data: Optional[Dict[str, Any]] = None) -> None:
        """``net.changed`` (network watcher thread; quick, never raises).  While serving, check that the adapter is
        still present, up and holding every address the server listens on; when it is not, stop on the helper
        thread ``tnt-tftp-netstop`` with the reason in ``status()["error"]`` ("stopped: Ethernet went down")."""
        try:
            with self._lock:
                running, adapter, ips = self._running, self._adapter, [ip for ip, _p in self._listen]
            if not running or adapter is None:
                return
            problem = _serving_problem(adapter, ips, _dhcp._get_adapters(self._adapters_fn))
            if problem is None:
                return
            log.info("TFTP server is stopping: %s", problem)
            threading.Thread(target=self._stop_for_network, args=(problem,), name="tnt-tftp-netstop",
                             daemon=True).start()
        except Exception:  # noqa: BLE001
            log.exception("handling a network change in the TFTP server failed")

    def _stop_for_network(self, problem: str) -> None:
        with self._lock:
            if not self._running:
                return
            self._error = f"stopped: {problem}"
        self._db_event("warning", f"TFTP server stopped: {problem}")
        try:
            self.stop()
        except Exception:  # noqa: BLE001
            log.exception("stopping the TFTP server after a network change failed")

    # -- the listener ---------------------------------------------------------------------------
    def _listen_loop(self, stop_evt: threading.Event, listeners: List[Tuple[str, int, Any]]) -> None:
        """The listening thread: every datagram to the server port.  It never dies (10054 included)."""
        socks = [s for _ip, _port, s in listeners]
        listen_ip = {id(s): ip for ip, _port, s in listeners}
        while not stop_evt.is_set():
            try:
                try:
                    ready = select.select(socks, [], [], LISTEN_TICK_S)[0]
                except (OSError, ValueError):
                    if stop_evt.is_set():
                        break
                    stop_evt.wait(0.1)
                    continue
                for s in ready:
                    try:
                        raw, src = s.recvfrom(RECV_BUFFER)
                    except ConnectionResetError:
                        continue                  # WinError 10054: harmless on a UDP socket
                    except (BlockingIOError, InterruptedError, socket.timeout):
                        continue
                    except OSError:
                        if stop_evt.is_set():
                            break
                        log.debug("TFTP listener receive failed", exc_info=True)
                        continue
                    if stop_evt.is_set():
                        break
                    self._on_request(raw, src, listen_ip[id(s)], stop_evt)
            except Exception:  # noqa: BLE001 - the listener must never die
                log.exception("TFTP listener error")
                stop_evt.wait(0.1)

    def _on_request(self, raw: bytes, src: Any, listen_ip: str, stop_evt: threading.Event) -> None:
        try:
            ip, port = str(src[0]), int(src[1])
        except (TypeError, ValueError, IndexError):
            return
        if not self._client_allowed(ip, port):
            return                                # outside the served subnets: no answer at all
        req = parse_request(raw)
        if req is None:
            return
        key = (ip, port)
        with self._lock:
            if not self._running or stop_evt.is_set():
                return
            live = self._by_key.get(key)
            if live is not None and live[1] == bytes(raw):
                # the same request again while its session lives: that session's timers answer it.  A different
                # request from the same port is a new transfer (PXE firmware aborts, then asks again from its port).
                return
            slots = [t for t in self._transfers.values() if t.holds_slot]
            busy = len(slots) >= MAX_TRANSFERS or sum(1 for t in slots if t.client == ip) >= MAX_PER_CLIENT
            if busy:
                self._counts["busy"] += 1
            else:
                tr = _Transfer(self._next_id, ip, port, listen_ip, "read" if req.opcode == OP_RRQ else "write",
                               _display_name(req.filename), req.mode[:16], self._clock(), self._mono())
                self._next_id += 1
                self._transfers[tr.id] = tr
                self._by_key[key] = (tr, bytes(raw))
        if busy:
            log.debug("TFTP request from %s turned away: server busy", ip)
            self._send_from(listen_ip, key, encode_error(ERR_UNDEFINED, MSG_BUSY))
            return
        thread = threading.Thread(target=self._run_transfer, args=(tr, req, stop_evt), name="tnt-tftp-xfer",
                                  daemon=True)
        with self._lock:
            self._threads.add(thread)
        try:
            thread.start()
        except RuntimeError:
            log.exception("could not start a TFTP transfer thread")
            with self._lock:
                self._threads.discard(thread)
            self._finish(tr, "failed", MSG_BUSY, refused=True)
            self._release(tr)

    def _send_from(self, listen_ip: str, dest: Tuple[str, int], packet: bytes) -> None:
        """One datagram from a fresh port on *listen_ip* (a request is never answered from the listening port)."""
        sock = None
        try:
            sock = self._socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
            _bind_udp(sock, (listen_ip, 0))
            sock.sendto(packet, dest)
        except OSError:
            log.debug("TFTP send failed", exc_info=True)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:  # noqa: BLE001
                    pass

    def _run_transfer(self, tr: _Transfer, req: Request, stop_evt: threading.Event) -> None:
        sock = None
        try:
            if stop_evt.is_set():                 # accepted just before a stop: end it without a socket or a packet
                self._finish(tr, "cancelled", MSG_CANCELLED)
                return
            sock = self._socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
            _bind_udp(sock, (tr.listen_ip, 0))
            session = _Session(self, tr, sock, stop_evt)
            if req.opcode == OP_RRQ:
                session.run_read(req)
            else:
                session.run_write(req)
        except Exception:  # noqa: BLE001 - one broken transfer never takes the server down
            log.exception("TFTP transfer failed")
        finally:
            if tr.ended_ts is None:
                self._finish(tr, "failed", MSG_INTERNAL)
            if sock is not None:
                try:
                    sock.close()
                except Exception:  # noqa: BLE001
                    pass
            self._release(tr)

    def _release(self, tr: _Transfer) -> None:
        with self._lock:
            key = (tr.client, tr.client_port)
            if (self._by_key.get(key) or (None,))[0] is tr:
                del self._by_key[key]
            self._threads.discard(threading.current_thread())

    def _began(self, tr: _Transfer) -> None:
        """The request passed its checks: from here on it is a transfer the UI shows."""
        if tr.began:
            return
        tr.began = True
        self._publish_transfer(tr, force=True)
        self._publish_state()

    def _set_state(self, tr: _Transfer, state: str) -> None:
        with self._lock:
            if tr.ended_ts is not None or tr.state == state:
                return
            tr.state = state
        if tr.began:
            self._publish_transfer(tr, force=True)
        else:
            self._began(tr)

    def _finish(self, tr: _Transfer, state: str, error: Optional[str] = None, refused: bool = False) -> None:
        with self._lock:
            if tr.ended_ts is not None:
                return
            tr.state, tr.error, tr.ended_ts = state, error, self._clock()
            tr.holds_slot = False
            self._transfers.pop(tr.id, None)
            key = (tr.client, tr.client_port)
            if (self._by_key.get(key) or (None,))[0] is tr:
                del self._by_key[key]        # finished: the same request from that port is a new transfer
            self._history.appendleft(tr)
            if state in self._counts:
                self._counts[state] += 1
        seconds = max(0.0, self._mono() - tr.started_mono)
        if refused:
            log.debug("TFTP %s of %r for %s refused: %s", tr.op, tr.file, tr.client, error)
        else:
            log.info("TFTP %s %s: %d bytes in %.2f s", tr.op, state, tr.bytes, seconds)
            log.debug("TFTP %s of %r for %s ended %s: %s", tr.op, tr.file, tr.client, state, error)
            if tr.op == "write":
                self._db_event("info" if state == "done" else "warning",
                               f"TFTP upload {state}: {tr.bytes} bytes in {seconds:.1f} s")
        self._publish_transfer(tr, force=True)
        if tr.began:
            self._publish_state()

    # -- views ----------------------------------------------------------------------------------
    def status(self) -> Dict[str, Any]:
        settings = self._settings()
        candidates = _candidates(self._adapters_fn)
        internet = _internet_nic(candidates)
        with self._lock:
            running = self._running
            adapter = self._adapter if running else None
            listen = [{"ip": ip, "port": port} for ip, port in self._listen] if running else []
            error, since, uploads = self._error, self._since_ts, self._uploads
            warnings = [w for w in (self._root_warning, self._warning) if w]
            firewall = dict(self._firewall)
            conflict = {"port": self._conflict["port"], "owners": [dict(o) for o in self._conflict["owners"]]} \
                if self._conflict else None
            transfers = [t.to_dict() for _tid, t in sorted(self._transfers.items())]
            history = [t.to_dict() for t in self._history]
            counts = {"active": len(self._transfers), **self._counts}
        if adapter is None:
            try:
                adapter = _pick_adapter(settings["adapter"], candidates)
            except ValueError as exc:
                adapter = None
                if not running:
                    warnings.append(str(exc))
        return {
            "available": True, "running": running, "since_ts": since, "error": error,
            "warning": "; ".join(warnings) if warnings else None,
            "adapter": _adapter_dict(adapter, internet) if adapter is not None else None,
            "adapters": [_adapter_dict(a, internet) for a in candidates],
            "listen": listen, "root": self._root_path(), "uploads": uploads, "firewall": firewall,
            "conflict": conflict, "transfers": transfers, "history": history,
            "counts": {k: int(counts.get(k, 0)) for k in TFTP_COUNT_KEYS}, "settings": settings,
        }

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            running = self._running
            return {
                "available": True, "running": running,
                "adapter": str(getattr(self._adapter, "name", "") or "") if running and self._adapter is not None else None,
                "listen_ips": [ip for ip, _p in self._listen] if running else [],
                "active": len(self._transfers), "uploads": self._uploads, "since_ts": self._since_ts,
                "error": self._error,
            }
