"""IPv4 neighbour (ARP) table.

:func:`get_arp_table` returns ``{"10.0.0.70": "00:00:5E:00:53:AB", ...}`` for every
usable IPv4 neighbour. The primary source is ``GetIpNetTable2(AF_INET)`` from
``iphlpapi.dll`` (no admin needed); if that fails for any reason the output of
``arp -a`` is parsed instead. Both paths return MACs normalised through
:func:`tnt.oui.normalize_mac` so callers never see the ``00-00-5e-...`` form.

Filtering (both paths): entries without a 6-byte physical address, entries in the
``NlnsUnreachable`` state, IPv4 multicast (224/4), the unspecified address, the
limited broadcast (255.255.255.255) and every multicast/broadcast MAC (I/G bit set,
which also drops directed-broadcast rows such as ``10.0.0.255 ff-ff-...``) are
skipped. When the same IP appears on several interfaces the entry with the "best"
neighbour state (Permanent > Reachable > Stale > Delay > Probe > Incomplete) wins.

Contract gaps filled here: ``GetIpNetTable2`` returning ``ERROR_NOT_FOUND`` (1168)
is treated as an empty table rather than a failure; physical addresses that are not
exactly 6 bytes (e.g. tunnel pseudo-addresses) are skipped so both paths agree; the
all-zero placeholder MAC (``00:00:00:00:00:00``, e.g. Tailscale's static
``100.100.100.100`` row) is dropped because it is not a device address (and the OUI
registry would attribute it to Xerox). ``arp -a`` output is decoded with the OEM code
page and only the IP/MAC columns are matched, so localised Windows builds work too.

Layout note (``InterfaceLuid`` is easily assumed to come before
``InterfaceIndex``): the real ``netioapi.h`` order is ``Address`` (28), ``InterfaceIndex``
(4, offset 28), ``InterfaceLuid`` (8, offset 32), ``PhysicalAddress[32]`` (offset 40),
``PhysicalAddressLength`` (72), ``State`` (76), ``Flags`` (80), ``ReachabilityTime`` (84);
``sizeof == 88``. The reversed order produced a 96-byte stride and garbage rows; the
88-byte layout was verified row-by-row against ``arp -a`` on Windows 11 x64.
"""
from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import re
import subprocess
import sys
import threading
from ctypes import POINTER, Structure, Union, byref, c_char, c_ubyte, c_ulong, c_ulonglong, c_ushort, c_void_p
from typing import Dict, List, Optional, Tuple

from .oui import normalize_mac

log = logging.getLogger(__name__)

__all__ = ["get_arp_table", "get_arp_table_native", "get_arp_table_cmd", "parse_arp_output", "neighbour",
           "neighbour_rows_native"]

AF_UNSPEC = 0
AF_INET = 2
AF_INET6 = 23
NO_ERROR = 0
ERROR_NOT_FOUND = 1168
NLNS_UNREACHABLE = 0
NL_STATE_NAMES = {0: "unreachable", 1: "incomplete", 2: "probe", 3: "delay", 4: "stale", 5: "reachable", 6: "permanent"}


# --- native structures (x64 layout verified on Windows 11: MIB_IPNET_ROW2 is 88 bytes) --
class SOCKADDR_IN(Structure):
    _fields_ = [
        ("sin_family", c_ushort),
        ("sin_port", c_ushort),
        ("sin_addr", c_ubyte * 4),
        ("sin_zero", c_char * 8),
    ]


class SOCKADDR_IN6(Structure):
    _fields_ = [
        ("sin6_family", c_ushort),
        ("sin6_port", c_ushort),
        ("sin6_flowinfo", c_ulong),
        ("sin6_addr", c_ubyte * 16),
        ("sin6_scope_id", c_ulong),
    ]


class SOCKADDR_INET(Union):
    _fields_ = [
        ("Ipv4", SOCKADDR_IN),
        ("Ipv6", SOCKADDR_IN6),
        ("si_family", c_ushort),
    ]


class MIB_IPNET_ROW2(Structure):
    _fields_ = [
        ("Address", SOCKADDR_INET),           # 0   28 bytes (union, 4-aligned)
        ("InterfaceIndex", c_ulong),          # 28  NET_IFINDEX
        ("InterfaceLuid", c_ulonglong),       # 32  NET_LUID (8-aligned)
        ("PhysicalAddress", c_ubyte * 32),    # 40
        ("PhysicalAddressLength", c_ulong),   # 72
        ("State", c_ulong),                   # 76  NL_NEIGHBOR_STATE
        ("Flags", c_ubyte),                   # 80  union { UCHAR Flags; IsRouter:1; IsUnreachable:1 }
        ("ReachabilityTime", c_ulong),        # 84  union { LastReachable; LastUnreachable }
    ]                                         # sizeof == 88


class MIB_IPNET_TABLE2(Structure):
    _fields_ = [
        ("NumEntries", c_ulong),
        ("Table", MIB_IPNET_ROW2 * 1),        # ANY_SIZE; rows start at offset 8
    ]


_ROWS_OFFSET = MIB_IPNET_TABLE2.Table.offset

_dll_lock = threading.Lock()
_iphlpapi = None
# A neighbour table with more rows than this is corrupt (a layout mismatch), not real;
# refuse it so the ``arp -a`` fallback is used instead of allocating gigabytes.
_MAX_ROWS = 1_000_000
NULL_MAC = "00:00:00:00:00:00"


def _dll():
    """Load iphlpapi lazily (so importing this module never fails off-Windows)."""
    global _iphlpapi
    with _dll_lock:
        if _iphlpapi is None:
            dll = ctypes.WinDLL("iphlpapi", use_last_error=True)
            dll.GetIpNetTable2.argtypes = [c_ushort, POINTER(c_void_p)]
            dll.GetIpNetTable2.restype = c_ulong
            dll.FreeMibTable.argtypes = [c_void_p]
            dll.FreeMibTable.restype = None
            _iphlpapi = dll
        return _iphlpapi


def _usable(ip: str, mac: str) -> bool:
    """Shared filter so the native and ``arp -a`` paths agree exactly."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified or addr == ipaddress.IPv4Address("255.255.255.255"):
        return False
    if mac == NULL_MAC:  # placeholder (e.g. Tailscale's 100.100.100.100 static entry), not a device
        return False
    first_octet = int(mac[:2], 16)
    if first_octet & 0x01:  # I/G bit: multicast or broadcast MAC
        return False
    return True


def get_arp_table_native() -> Dict[str, str]:
    """``GetIpNetTable2(AF_INET)`` → ``{ip: MAC}``. Raises ``OSError`` on API failure."""
    dll = _dll()
    table = c_void_p()
    rc = dll.GetIpNetTable2(AF_INET, byref(table))
    if rc == ERROR_NOT_FOUND:
        if table.value:
            dll.FreeMibTable(table)
        return {}
    if rc != NO_ERROR:
        raise OSError(rc, f"GetIpNetTable2 failed: {ctypes.FormatError(rc)} ({rc})")
    if not table.value:
        return {}
    best: Dict[str, tuple[int, str]] = {}
    try:
        count = c_ulong.from_address(table.value).value
        if count > _MAX_ROWS:
            raise OSError(0, f"GetIpNetTable2 reported an implausible {count} rows")
        rows = (MIB_IPNET_ROW2 * count).from_address(table.value + _ROWS_OFFSET)
        for row in rows:
            if row.Address.si_family != AF_INET:
                continue
            if row.PhysicalAddressLength != 6 or row.State == NLNS_UNREACHABLE:
                continue
            raw = bytes(row.PhysicalAddress[:6])
            mac = normalize_mac(raw.hex())
            if mac is None:
                continue
            ip = str(ipaddress.IPv4Address(bytes(row.Address.Ipv4.sin_addr)))
            if not _usable(ip, mac):
                continue
            state = int(row.State)
            prev = best.get(ip)
            if prev is None or state > prev[0]:
                best[ip] = (state, mac)
    finally:
        dll.FreeMibTable(table)
    return {ip: mac for ip, (_state, mac) in best.items()}


# Only the IP and MAC columns are matched: the third column ("dynamic"/"static") is
# localised and may contain non-ASCII (Spanish "dinámico", Chinese "动态"...) or
# replacement characters when the console code page was guessed wrong.
_ARP_LINE_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})(?=\s|$)",
    re.MULTILINE,
)


def parse_arp_output(text: str) -> Dict[str, str]:
    """Parse ``arp -a`` output (any locale: only the IP/MAC columns are matched)."""
    out: Dict[str, str] = {}
    for m in _ARP_LINE_RE.finditer(text or ""):
        ip, raw_mac = m.group(1), m.group(2)
        mac = normalize_mac(raw_mac)
        if mac is None or not _usable(ip, mac):
            continue
        out.setdefault(ip, mac)
    return out


def _arp_exe() -> str:
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    cand = os.path.join(root, "System32", "arp.exe")
    return cand if os.path.isfile(cand) else "arp"


def get_arp_table_cmd(timeout_s: float = 10.0) -> Dict[str, str]:
    """Fallback: run ``arp -a`` (hidden window, bounded by *timeout_s*) and parse it."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    proc = subprocess.run(
        [_arp_exe(), "-a"],
        capture_output=True,
        timeout=timeout_s,
        creationflags=flags,
        check=False,
    )
    return parse_arp_output(_decode_console(proc.stdout))


def _decode_console(raw: bytes) -> str:
    """Decode console-tool output: the OEM code page on Windows (``arp.exe`` writes
    cp437/cp850/cp936... not UTF-8), UTF-8 elsewhere; never raises."""
    if not raw:
        return ""
    if sys.platform == "win32":
        try:
            return raw.decode("oem", errors="replace")
        except LookupError:
            pass
    return raw.decode("utf-8", errors="replace")


def get_arp_table() -> Dict[str, str]:
    """``{"10.0.0.70": "00:00:5E:00:53:AB", ...}`` for IPv4 neighbours. Never raises."""
    try:
        return get_arp_table_native()
    except Exception as exc:  # noqa: BLE001 - fall back, never break discovery
        log.warning("GetIpNetTable2 failed (%s); falling back to 'arp -a'", exc)
    try:
        return get_arp_table_cmd()
    except Exception:  # noqa: BLE001
        log.exception("'arp -a' fallback failed")
        return {}


def neighbour_state_name(state: int) -> Optional[str]:
    """Human name of an ``NL_NEIGHBOR_STATE`` value (diagnostics helper)."""
    return NL_STATE_NAMES.get(int(state))


def _plain_ip(ip: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(str(ip).strip().split("%", 1)[0])
    except ValueError:
        return None


def neighbour_rows_native(family: int = AF_UNSPEC) -> List[Tuple[str, int, str, str]]:
    """``(ip, interface index, MAC, state name)`` of every neighbour row with a unicast 6-byte address that is not
    unreachable, IPv4 and IPv6 (``GetIpNetTable2``; a router of an IPv6-only network is an NDP entry).  Raises ``OSError``."""
    dll = _dll()
    table = c_void_p()
    rc = dll.GetIpNetTable2(int(family), byref(table))
    if rc == ERROR_NOT_FOUND:
        if table.value:
            dll.FreeMibTable(table)
        return []
    if rc != NO_ERROR:
        raise OSError(rc, f"GetIpNetTable2 failed: {ctypes.FormatError(rc)} ({rc})")
    if not table.value:
        return []
    out: List[Tuple[str, int, str, str]] = []
    try:
        count = c_ulong.from_address(table.value).value
        if count > _MAX_ROWS:
            raise OSError(0, f"GetIpNetTable2 reported an implausible {count} rows")
        rows = (MIB_IPNET_ROW2 * count).from_address(table.value + _ROWS_OFFSET)
        for row in rows:
            fam = row.Address.si_family
            if fam not in (AF_INET, AF_INET6) or row.PhysicalAddressLength != 6 or row.State == NLNS_UNREACHABLE:
                continue
            mac = normalize_mac(bytes(row.PhysicalAddress[:6]).hex())
            if mac is None or mac == NULL_MAC or int(mac[:2], 16) & 0x01:
                continue
            if fam == AF_INET:
                addr: ipaddress._BaseAddress = ipaddress.IPv4Address(bytes(row.Address.Ipv4.sin_addr))
            else:
                addr = ipaddress.IPv6Address(bytes(row.Address.Ipv6.sin6_addr))
            if addr.is_multicast or addr.is_unspecified:
                continue
            out.append((str(addr), int(row.InterfaceIndex), mac, NL_STATE_NAMES.get(int(row.State), "unknown")))
    finally:
        dll.FreeMibTable(table)
    return out


_STATE_RANK = {name: rank for rank, name in NL_STATE_NAMES.items()}


def neighbour(ip: str, if_index: Optional[int] = None) -> Optional[Tuple[str, Optional[str]]]:
    """``(MAC, state)`` of the neighbour *ip* (an IPv6 zone is ignored) on the interface *if_index* (any interface when None;
    of several rows the best state wins), ``None`` when there is none.  State names: ``permanent``, ``reachable``, ``stale``,
    ``delay``, ``probe``.  When the native table cannot be read the ``arp -a`` fallback answers for IPv4 with state None
    (it has none: a caller treats it as unconfirmed).  Never raises."""
    target = _plain_ip(ip)
    if target is None:
        return None
    try:
        rows = neighbour_rows_native(AF_INET if target.version == 4 else AF_INET6)
    except Exception as exc:  # noqa: BLE001 - fall back, never break the caller
        log.debug("GetIpNetTable2 failed (%s); looking the neighbour up with 'arp -a'", exc)
        if target.version != 4:
            return None
        try:
            mac = get_arp_table_cmd().get(str(target))
        except Exception:  # noqa: BLE001
            log.debug("'arp -a' fallback failed", exc_info=True)
            return None
        return (mac, None) if mac else None
    best: Optional[Tuple[str, Optional[str]]] = None
    for row_ip, index, mac, state in rows:
        if _plain_ip(row_ip) != target or (if_index is not None and index != int(if_index)):
            continue
        if best is None or _STATE_RANK.get(state, 0) > _STATE_RANK.get(best[1] or "", 0):
            best = (mac, state)
    return best
