"""Who owns the client end of a loopback connection, and is that process a Windows
administrator?

Why this exists
---------------
The saved Wi-Fi keys (:mod:`tnt.wifi`) are handed back in the clear only when the caller
asks with ``reveal=1``.  Windows keeps plaintext keys from standard users, but the TNT
service runs as LocalSystem and answers *any* local process on the loopback API.  So before
the service reveals a key it asks: **does the process on the other end of this HTTP
connection run under a Windows administrator account?**  Elevated or not (see
:func:`token_is_admin`): that is TNT's rule, a little more permissive than Windows' own
plaintext-key access, and it never admits a standard user.

The chain
---------
1. The API server binds to loopback and knows both ends of the accepted socket: the
   request's peer address/port (the client's *local* endpoint) and the server socket's own
   address/port (the client's *remote* endpoint).
2. :func:`_owner_pid` calls ``GetExtendedTcpTable`` (iphlpapi, ``TCP_TABLE_OWNER_PID_CONNECTIONS``)
   for ``AF_INET`` and ``AF_INET6`` and finds the row whose local endpoint is the client's
   and whose remote endpoint is the server's -- that row carries the owning PID.
3. :func:`_token_sids` opens that process (``PROCESS_QUERY_LIMITED_INFORMATION``), opens its
   token (``TOKEN_QUERY``) and reads ``TokenUser`` + ``TokenGroups`` via ``GetTokenInformation``,
   turning each SID into its string form with ``ConvertSidToStringSidW``.  Every handle is
   closed.
4. :func:`token_is_admin` -- a **pure** function of ``(user_sid, [(sid, attributes)])`` so it
   is unit-testable without a real token -- decides.  Allowed: the token's user is LocalSystem
   (``S-1-5-18``), or its groups contain ``BUILTIN\\Administrators`` (``S-1-5-32-544``) either
   enabled (an elevated token) or present with ``SE_GROUP_USE_FOR_DENY_ONLY`` (the UAC-filtered
   token of an administrator account, which is how the normal non-elevated TNT window runs for
   a technician on an admin account).  Refused: a standard user (no Administrators SID at all).
   UAC is not the boundary here -- the standard-user / administrator boundary is.

:func:`reveal_allowed` glues those together and **never raises**: it returns
:data:`ALLOWED`, :data:`DENIED`, or :data:`UNKNOWN`.  It **fails closed** -- if the owner
cannot be found or the token cannot be read (or this is not Windows) it returns
:data:`UNKNOWN`, which the route treats as a refusal.

Every Win32 function is wrapped with ``argtypes``/``restype`` (this repo learned the hard
way -- see :mod:`tnt.arp` -- that ctypes without prototypes crashes on x64).  The module is
import-safe off Windows: the ``WinDLL`` loads lazily inside :func:`_dll`.
"""
from __future__ import annotations

import ctypes
import ipaddress
import logging
import socket
import struct
import sys
import threading
from ctypes import POINTER, Structure, byref, c_int, c_ubyte, c_ulong, c_void_p, c_wchar_p
from typing import Any, Iterable, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

__all__ = [
    "reveal_allowed", "token_is_admin", "ALLOWED", "DENIED", "UNKNOWN",
    "LOCAL_SYSTEM_SID", "ADMINISTRATORS_SID",
    "SE_GROUP_ENABLED", "SE_GROUP_USE_FOR_DENY_ONLY",
]

#: The three outcomes of :func:`reveal_allowed`.
ALLOWED = "allowed"     #: the owning process is LocalSystem or an administrator
DENIED = "denied"       #: the owning process is a standard user
UNKNOWN = "unknown"     #: the owner or its token could not be determined -> fail closed

#: Well-known SIDs (string form, as ``ConvertSidToStringSidW`` returns them).
LOCAL_SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"

#: ``SID_AND_ATTRIBUTES.Attributes`` flags we care about (winnt.h).
SE_GROUP_ENABLED = 0x00000004
SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010

# -- Win32 constants -------------------------------------------------------------------------
AF_INET = 2
AF_INET6 = 23
NO_ERROR = 0
ERROR_INSUFFICIENT_BUFFER = 122
#: ``TCP_TABLE_CLASS``: connections (not listeners) with their owning PID.
TCP_TABLE_OWNER_PID_CONNECTIONS = 4
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
#: ``TOKEN_INFORMATION_CLASS``.
TOKEN_USER_CLASS = 1
TOKEN_GROUPS_CLASS = 2

#: Sanity caps against a corrupt count from a layout mismatch (see tnt.arp's ``_MAX_ROWS``).
_MAX_ROWS = 1_000_000
_MAX_GROUPS = 4096
_MAX_TOKEN_INFO = 1024 * 1024


# --- native structures (x64 layout per tcpmib.h / winnt.h) ----------------------------------
class MIB_TCPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwState", c_ulong),
        ("dwLocalAddr", c_ulong),     # IPv4 in network byte order
        ("dwLocalPort", c_ulong),     # port in network byte order in the low 16 bits
        ("dwRemoteAddr", c_ulong),
        ("dwRemotePort", c_ulong),
        ("dwOwningPid", c_ulong),
    ]                                 # sizeof == 24


class MIB_TCPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", c_ulong),
        ("table", MIB_TCPROW_OWNER_PID * 1),   # ANY_SIZE; rows start at offset 4
    ]


class MIB_TCP6ROW_OWNER_PID(Structure):
    _fields_ = [
        ("ucLocalAddr", c_ubyte * 16),         # IPv6 in network byte order
        ("dwLocalScopeId", c_ulong),
        ("dwLocalPort", c_ulong),
        ("ucRemoteAddr", c_ubyte * 16),
        ("dwRemoteScopeId", c_ulong),
        ("dwRemotePort", c_ulong),
        ("dwState", c_ulong),
        ("dwOwningPid", c_ulong),
    ]                                          # sizeof == 56


class MIB_TCP6TABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", c_ulong),
        ("table", MIB_TCP6ROW_OWNER_PID * 1),  # ANY_SIZE; rows start at offset 4
    ]


class SID_AND_ATTRIBUTES(Structure):
    _fields_ = [("Sid", c_void_p), ("Attributes", c_ulong)]   # 8-aligned -> sizeof 16


class TOKEN_USER(Structure):
    _fields_ = [("User", SID_AND_ATTRIBUTES)]


class TOKEN_GROUPS(Structure):
    _fields_ = [
        ("GroupCount", c_ulong),
        ("Groups", SID_AND_ATTRIBUTES * 1),    # ANY_SIZE; rows start at offset 8 (pointer align)
    ]


_V4_ROWS_OFFSET = MIB_TCPTABLE_OWNER_PID.table.offset
_V6_ROWS_OFFSET = MIB_TCP6TABLE_OWNER_PID.table.offset
_GROUPS_OFFSET = TOKEN_GROUPS.Groups.offset

_dll_lock = threading.Lock()
_iphlpapi: Any = None
_kernel32: Any = None
_advapi32: Any = None


def _dll() -> Tuple[Any, Any, Any]:
    """Load ``iphlpapi`` / ``kernel32`` / ``advapi32`` lazily with every prototype declared
    (so importing this module never fails off Windows, and no call is made without
    ``argtypes`` on x64)."""
    global _iphlpapi, _kernel32, _advapi32
    with _dll_lock:
        if _iphlpapi is None:
            ip = ctypes.WinDLL("iphlpapi", use_last_error=True)
            ip.GetExtendedTcpTable.argtypes = [c_void_p, POINTER(c_ulong), c_int, c_ulong, c_int, c_ulong]
            ip.GetExtendedTcpTable.restype = c_ulong
            k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.OpenProcess.argtypes = [c_ulong, c_int, c_ulong]
            k.OpenProcess.restype = c_void_p
            k.CloseHandle.argtypes = [c_void_p]
            k.CloseHandle.restype = c_int
            k.LocalFree.argtypes = [c_void_p]
            k.LocalFree.restype = c_void_p
            a = ctypes.WinDLL("advapi32", use_last_error=True)
            a.OpenProcessToken.argtypes = [c_void_p, c_ulong, POINTER(c_void_p)]
            a.OpenProcessToken.restype = c_int
            a.GetTokenInformation.argtypes = [c_void_p, c_int, c_void_p, c_ulong, POINTER(c_ulong)]
            a.GetTokenInformation.restype = c_int
            a.ConvertSidToStringSidW.argtypes = [c_void_p, POINTER(c_wchar_p)]
            a.ConvertSidToStringSidW.restype = c_int
            _iphlpapi, _kernel32, _advapi32 = ip, k, a
        return _iphlpapi, _kernel32, _advapi32


# --- the pure decision (unit-testable without a real token) ---------------------------------
def _norm_sid(sid: Any) -> str:
    return str(sid or "").strip().upper()


def token_is_admin(user_sid: Any, groups: Optional[Iterable[Tuple[Any, Any]]]) -> bool:
    """Decide, from a token's user SID and its groups, whether it belongs to LocalSystem or a
    member of ``BUILTIN\\Administrators``.

    *groups* is any iterable of ``(sid, attributes)`` pairs (attributes an int bitmask).  A
    token is admin when the user SID is :data:`LOCAL_SYSTEM_SID`, or the Administrators SID
    appears among the groups either enabled (:data:`SE_GROUP_ENABLED`, an elevated token) or
    marked deny-only (:data:`SE_GROUP_USE_FOR_DENY_ONLY`, the UAC-filtered token of an admin
    account).  Never raises: garbage in is simply not admin.
    """
    if _norm_sid(user_sid) == LOCAL_SYSTEM_SID:
        return True
    admin = ADMINISTRATORS_SID
    mask = SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY
    for pair in groups or ():
        try:
            sid, attrs = pair
        except (TypeError, ValueError):
            continue
        if _norm_sid(sid) != admin:
            continue
        try:
            attrs_i = int(attrs)
        except (TypeError, ValueError):
            attrs_i = 0
        if attrs_i & mask:
            return True
    return False


# --- owner PID via GetExtendedTcpTable ------------------------------------------------------
def _port(dw: int) -> int:
    """The port from a ``dwLocalPort`` / ``dwRemotePort`` field (network order, low 16 bits)."""
    return socket.ntohs(int(dw) & 0xFFFF)


def _v4_bytes(dw: int) -> bytes:
    """The 4 network-order bytes of a ``dwLocalAddr`` / ``dwRemoteAddr`` field."""
    return struct.pack("<I", int(dw) & 0xFFFFFFFF)


def _query_tcp_table(dll: Any, family: int) -> bytearray:
    """The raw ``MIB_*TCPTABLE_OWNER_PID`` bytes for *family* (grow-and-retry).  Raises
    ``OSError`` on failure."""
    size = c_ulong(0)
    dll.GetExtendedTcpTable(None, byref(size), False, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
    for _ in range(8):
        n = size.value
        buf = ctypes.create_string_buffer(n if n > 0 else 4)
        rc = int(dll.GetExtendedTcpTable(buf, byref(size), False, family,
                                         TCP_TABLE_OWNER_PID_CONNECTIONS, 0))
        if rc == ERROR_INSUFFICIENT_BUFFER:
            continue                          # the table grew between the two calls
        if rc != NO_ERROR:
            raise OSError(rc, f"GetExtendedTcpTable(af={family}) failed: {rc}")
        return bytearray(buf.raw[:size.value])
    raise OSError(ERROR_INSUFFICIENT_BUFFER, "GetExtendedTcpTable kept growing")


def _owner_pid(peer: Sequence[Any], local: Sequence[Any]) -> Optional[int]:
    """The PID owning the client end of the loopback TCP connection whose *local* endpoint is
    ``peer`` (ip, port) and whose *remote* endpoint is ``local`` (ip, port).  ``None`` when it
    cannot be found.  Never raises."""
    try:
        pip = ipaddress.ip_address(str(peer[0]).split("%", 1)[0])
        lip = ipaddress.ip_address(str(local[0]).split("%", 1)[0])
        pport = int(peer[1])
        lport = int(local[1])
    except (TypeError, ValueError, IndexError, KeyError):
        return None
    # a dual-stack socket reports an IPv4 client as ::ffff:a.b.c.d -> match the AF_INET table
    if pip.version == 6 and pip.ipv4_mapped is not None:
        pip = pip.ipv4_mapped
    if lip.version == 6 and lip.ipv4_mapped is not None:
        lip = lip.ipv4_mapped
    if pip.version != lip.version:
        return None
    try:
        dll, _k, _a = _dll()
        if pip.version == 4:
            return _find_v4(dll, pip.packed, pport, lip.packed, lport)
        return _find_v6(dll, pip.packed, pport, lip.packed, lport)
    except OSError:
        log.debug("owner PID lookup failed", exc_info=True)
        return None
    except Exception:  # noqa: BLE001 - a layout surprise must not crash the request
        log.exception("owner PID lookup crashed")
        return None


def _find_v4(dll: Any, want_local: bytes, pport: int, want_remote: bytes, lport: int) -> Optional[int]:
    raw = _query_tcp_table(dll, AF_INET)
    count = int.from_bytes(raw[:4], "little")
    if count > _MAX_ROWS:
        raise OSError(0, f"GetExtendedTcpTable reported an implausible {count} rows")
    rows = (MIB_TCPROW_OWNER_PID * count).from_buffer(raw, _V4_ROWS_OFFSET)
    for row in rows:
        if _v4_bytes(row.dwLocalAddr) != want_local or _port(row.dwLocalPort) != pport:
            continue
        if _v4_bytes(row.dwRemoteAddr) != want_remote or _port(row.dwRemotePort) != lport:
            continue
        return int(row.dwOwningPid)
    return None


def _find_v6(dll: Any, want_local: bytes, pport: int, want_remote: bytes, lport: int) -> Optional[int]:
    raw = _query_tcp_table(dll, AF_INET6)
    count = int.from_bytes(raw[:4], "little")
    if count > _MAX_ROWS:
        raise OSError(0, f"GetExtendedTcpTable reported an implausible {count} rows")
    rows = (MIB_TCP6ROW_OWNER_PID * count).from_buffer(raw, _V6_ROWS_OFFSET)
    for row in rows:
        if bytes(row.ucLocalAddr) != want_local or _port(row.dwLocalPort) != pport:
            continue
        if bytes(row.ucRemoteAddr) != want_remote or _port(row.dwRemotePort) != lport:
            continue
        return int(row.dwOwningPid)
    return None


# --- the process token ----------------------------------------------------------------------
def _sid_to_str(advapi: Any, kernel: Any, psid: Any) -> Optional[str]:
    """``ConvertSidToStringSidW`` -> ``"S-1-5-..."`` (the ``LocalAlloc`` buffer is freed)."""
    if not psid:
        return None
    out = c_wchar_p()
    if not advapi.ConvertSidToStringSidW(psid, byref(out)):
        return None
    try:
        return out.value
    finally:
        kernel.LocalFree(ctypes.cast(out, c_void_p))


def _get_token_info(advapi: Any, htoken: Any, info_class: int) -> Optional[ctypes.Array]:
    """The raw buffer for a ``GetTokenInformation`` class (two-call size probe).  ``None`` on
    failure."""
    size = c_ulong(0)
    advapi.GetTokenInformation(htoken, info_class, None, 0, byref(size))
    if size.value == 0 or size.value > _MAX_TOKEN_INFO:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if not advapi.GetTokenInformation(htoken, info_class, buf, size.value, byref(size)):
        return None
    return buf


def _token_user(advapi: Any, kernel: Any, htoken: Any) -> Optional[str]:
    buf = _get_token_info(advapi, htoken, TOKEN_USER_CLASS)
    if buf is None:
        return None
    tu = ctypes.cast(buf, POINTER(TOKEN_USER)).contents
    return _sid_to_str(advapi, kernel, tu.User.Sid)


def _token_groups(advapi: Any, kernel: Any, htoken: Any) -> List[Tuple[str, int]]:
    buf = _get_token_info(advapi, htoken, TOKEN_GROUPS_CLASS)
    if buf is None:
        return []
    count = int.from_bytes(buf.raw[:4], "little")
    if count <= 0 or count > _MAX_GROUPS:
        return []
    rows = (SID_AND_ATTRIBUTES * count).from_address(ctypes.addressof(buf) + _GROUPS_OFFSET)
    out: List[Tuple[str, int]] = []
    for row in rows:
        sid = _sid_to_str(advapi, kernel, row.Sid)
        if sid:
            out.append((sid, int(row.Attributes)))
    return out


def _token_sids(pid: int) -> Optional[Tuple[str, List[Tuple[str, int]]]]:
    """``(user_sid, [(group_sid, attributes), ...])`` for the token of *pid*, or ``None`` on any
    failure.  Every handle is closed."""
    if not pid or int(pid) <= 0:
        return None
    _ip, kernel, advapi = _dll()
    hproc = kernel.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not hproc:
        return None
    htoken = c_void_p()
    try:
        if not advapi.OpenProcessToken(hproc, TOKEN_QUERY, byref(htoken)):
            return None
        user = _token_user(advapi, kernel, htoken)
        if user is None:
            return None
        groups = _token_groups(advapi, kernel, htoken)
        return user, groups
    finally:
        if htoken.value:
            kernel.CloseHandle(htoken)
        kernel.CloseHandle(hproc)


# --- the public entry point -----------------------------------------------------------------
def reveal_allowed(peer: Optional[Sequence[Any]], local: Optional[Sequence[Any]]) -> str:
    """Is the process that owns the client end of this loopback connection allowed to see
    plaintext Wi-Fi keys?

    Returns :data:`ALLOWED`, :data:`DENIED` or :data:`UNKNOWN`.  Never raises and **fails
    closed**: off Windows, or when the owner or its token cannot be read, the answer is
    :data:`UNKNOWN` (which the route refuses).  *peer* is the request's peer address/port,
    *local* the server socket's own address/port.
    """
    if sys.platform != "win32":
        return UNKNOWN
    if not peer or not local:
        return UNKNOWN
    try:
        pid = _owner_pid(peer, local)
        if not pid:
            log.info("Wi-Fi key reveal: no owning process for connection %s -> %s", tuple(peer), tuple(local))
            return UNKNOWN
        sids = _token_sids(pid)
        if sids is None:
            log.info("Wi-Fi key reveal: could not read the token of PID %s", pid)
            return UNKNOWN
        return ALLOWED if token_is_admin(*sids) else DENIED
    except Exception:  # noqa: BLE001 - the reveal check must never take the request down
        log.exception("Wi-Fi key reveal check failed")
        return UNKNOWN
