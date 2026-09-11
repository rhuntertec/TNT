"""Native ICMP echo via ``IcmpSendEcho2`` / ``Icmp6SendEcho2``.

Everything goes through ``iphlpapi.dll`` with ctypes. No raw sockets and no admin
rights are required. Every function has ``argtypes``/``restype`` declared: on 64-bit
Windows the ``HANDLE`` returned by ``IcmpCreateFile`` is a pointer and truncating it
to a C ``int`` (the ctypes default) causes an access violation inside the DLL.

Rules implemented (from the contract):

* The payload is a repeating pattern of printable bytes; ``size`` is clamped to
  ``0..65500``.
* ``rtt_ms`` is the API's integer ``RoundTripTime`` when it is >= 1, otherwise the
  wall-clock ``perf_counter`` duration of the call capped at 0.99 ms (LAN replies
  therefore show sub-millisecond values instead of 0).
* ``IcmpSendEcho2`` returning 0 → ``ok=False`` with ``status=GetLastError()`` (11010 for
  a timeout). A reply carrying a non-zero ``Status`` (e.g. 11003 destination host
  unreachable from the gateway) → ``ok=False`` with that status.
* Any ctypes/OS error → ``ok=False, status=-1, error=str(exc)``. ``ping`` never raises.

Contract gaps filled here (documented as required):

* ICMP handles are per thread (``threading.local``) *and* tracked in a registry so
  ``close()`` can release handles created by other (already stopped) threads. After
  ``close()`` a further ``ping`` transparently creates a new handle; ``close()`` is
  idempotent. Call ``close()`` only after the worker threads using the pinger stopped.
  A thread's cached handle is tagged with a *generation* that ``close()`` bumps, because
  Windows recycles handle values immediately: the ``Icmp6CreateFile`` call that follows a
  ``close()`` typically returns the very value the IPv4 handle had, and a plain "is it
  still registered" check would then send IPv4 echoes over an IPv6 handle (error 87).
* ``resolve`` shares one helper thread between concurrent callers asking for the same
  name, so a hung resolver never grows the thread count beyond one thread per distinct
  hostname (the ping manager retries an unresolved host every tick).
* IPv6 replies do not carry a hop limit, so ``ttl`` is ``None`` for IPv6 targets.
* IPv4-mapped IPv6 literals (``::ffff:10.0.0.1``) are pinged as the IPv4 host they name
  (``Icmp6SendEcho2`` rejects them); ``PingResult.ip`` is then the IPv4 literal.
* ``IcmpSendEcho2`` returning 0 with ``GetLastError() == 0`` is reported as ``status=-1``
  (never ``ok=False, status=0``, which would read as a success code).
* ``resolve`` strips surrounding whitespace and ``[]`` brackets and keeps an IPv6 scope
  id (``fe80::1%12``) returned by ``getaddrinfo``.
"""
from __future__ import annotations

import ctypes
import functools
import ipaddress
import logging
import socket
import string
import threading
import time
from ctypes import POINTER, Structure, byref, c_char, c_int, c_ubyte, c_uint, c_ulong, c_ushort, c_void_p, sizeof
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

__all__ = ["PingResult", "IcmpPinger", "resolve", "STATUS_TEXT", "status_text"]

AF_INET = 2
AF_INET6 = 23
MAX_PAYLOAD = 65500
INVALID_HANDLE_VALUE = 2**64 - 1 if sizeof(c_void_p) == 8 else 2**32 - 1

# IP_STATUS codes (ipexport.h). 0 = success, everything else is IP_STATUS_BASE (11000) + n.
STATUS_TEXT: Dict[int, str] = {
    0: "Success",
    11001: "Buffer too small",
    11002: "Destination network unreachable",
    11003: "Destination host unreachable",
    11004: "Destination protocol unreachable",
    11005: "Destination port unreachable",
    11006: "No resources",
    11007: "Bad option",
    11008: "Hardware error",
    11009: "Packet too big",
    11010: "Request timed out",
    11011: "Bad request",
    11012: "Bad route",
    11013: "TTL expired in transit",
    11014: "TTL expired during reassembly",
    11015: "Parameter problem",
    11016: "Source quench",
    11017: "Option too big",
    11018: "Bad destination",
    11019: "Address deleted",
    11020: "Specified MTU changed",
    11021: "MTU changed",
    11022: "Unload",
    11023: "Address added",
    11024: "Media connect",
    11025: "Media disconnect",
    11026: "Bind adapter",
    11027: "Unbind adapter",
    11028: "Device does not exist",
    11029: "Duplicate address",
    11030: "Interface metric change",
    11031: "Reconfiguring secondary",
    11032: "Negotiating IPsec",
    11033: "Interface WOL capability change",
    11034: "Duplicate IP address",
    11040: "Destination unreachable",
    11041: "Time exceeded",
    11042: "Bad header",
    11043: "Unrecognized next header",
    11044: "ICMP error",
    11045: "Destination scope mismatch",
    11050: "General failure",
}

# Win32 errors IcmpSendEcho2 commonly reports through GetLastError() when it returns 0.
_WIN32_TEXT: Dict[int, str] = {
    5: "Access denied",
    6: "Invalid handle",
    8: "Not enough memory",
    87: "Invalid parameter",
    122: "Reply buffer too small",
    997: "Operation pending",
    1231: "Network unreachable",
    1232: "Host unreachable",
    1233: "Protocol unreachable",
    1234: "Port unreachable",
    10013: "Permission denied (WSAEACCES)",
    10051: "Network unreachable (WSAENETUNREACH)",
    10065: "Host unreachable (WSAEHOSTUNREACH)",
}


def status_text(status: int) -> str:
    """Human text for an IP_STATUS / Win32 code (falls back to ``FormatError``)."""
    if status in STATUS_TEXT:
        return STATUS_TEXT[status]
    if status in _WIN32_TEXT:
        return _WIN32_TEXT[status]
    try:
        text = ctypes.FormatError(int(status)).strip()
    except Exception:  # noqa: BLE001
        text = ""
    return text or f"Error {status}"


@dataclass
class PingResult:
    ok: bool
    rtt_ms: Optional[float]      # None when not ok
    status: int                  # IP_STATUS code (0 success, 11010 timed out, ...); -1 = OS/ctypes error
    error: Optional[str]         # human text for status when not ok
    ttl: Optional[int]
    size: int                    # payload bytes sent
    ip: str                      # address actually pinged
    responder: Optional[str] = None   # who answered: the target on success, the hop router on "TTL expired" (traceroute)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --- native structures -----------------------------------------------------------------
class IP_OPTION_INFORMATION(Structure):
    _fields_ = [
        ("Ttl", c_ubyte),
        ("Tos", c_ubyte),
        ("Flags", c_ubyte),
        ("OptionsSize", c_ubyte),
        ("OptionsData", c_void_p),
    ]


class ICMP_ECHO_REPLY(Structure):
    _fields_ = [
        ("Address", c_ulong),          # IPAddr, network byte order
        ("Status", c_ulong),
        ("RoundTripTime", c_ulong),
        ("DataSize", c_ushort),
        ("Reserved", c_ushort),
        ("Data", c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]


class IPV6_ADDRESS_EX(Structure):
    _pack_ = 1                          # declared inside pshpack1.h in ipexport.h
    _fields_ = [
        ("sin6_port", c_ushort),
        ("sin6_flowinfo", c_ulong),
        ("sin6_addr", c_ushort * 8),
        ("sin6_scope_id", c_ulong),
    ]


class ICMPV6_ECHO_REPLY(Structure):
    _fields_ = [
        ("Address", IPV6_ADDRESS_EX),
        ("Status", c_ulong),
        ("RoundTripTime", c_uint),
    ]


class SOCKADDR_IN6(Structure):
    _fields_ = [
        ("sin6_family", c_ushort),
        ("sin6_port", c_ushort),
        ("sin6_flowinfo", c_ulong),
        ("sin6_addr", c_ubyte * 16),
        ("sin6_scope_id", c_ulong),
    ]


_dll_lock = threading.Lock()
_iphlpapi: Any = None


def _dll() -> Any:
    """Load ``iphlpapi`` once, with every prototype declared (64-bit safe)."""
    global _iphlpapi
    with _dll_lock:
        if _iphlpapi is not None:
            return _iphlpapi
        dll = ctypes.WinDLL("iphlpapi", use_last_error=True)
        dll.IcmpCreateFile.argtypes = []
        dll.IcmpCreateFile.restype = c_void_p          # HANDLE — essential on x64
        dll.Icmp6CreateFile.argtypes = []
        dll.Icmp6CreateFile.restype = c_void_p
        dll.IcmpCloseHandle.argtypes = [c_void_p]
        dll.IcmpCloseHandle.restype = c_int
        dll.IcmpSendEcho2.argtypes = [
            c_void_p,                      # IcmpHandle
            c_void_p,                      # Event
            c_void_p,                      # ApcRoutine
            c_void_p,                      # ApcContext
            c_ulong,                       # DestinationAddress (IPAddr, network order)
            c_void_p,                      # RequestData
            c_ushort,                      # RequestSize
            POINTER(IP_OPTION_INFORMATION),
            c_void_p,                      # ReplyBuffer
            c_ulong,                       # ReplySize
            c_ulong,                       # Timeout (ms)
        ]
        dll.IcmpSendEcho2.restype = c_ulong
        dll.Icmp6SendEcho2.argtypes = [
            c_void_p,                      # IcmpHandle
            c_void_p,                      # Event
            c_void_p,                      # ApcRoutine
            c_void_p,                      # ApcContext
            POINTER(SOCKADDR_IN6),         # SourceAddress
            POINTER(SOCKADDR_IN6),         # DestinationAddress
            c_void_p,                      # RequestData
            c_ushort,                      # RequestSize
            POINTER(IP_OPTION_INFORMATION),
            c_void_p,                      # ReplyBuffer
            c_ulong,                       # ReplySize
            c_ulong,                       # Timeout (ms)
        ]
        dll.Icmp6SendEcho2.restype = c_ulong
        _iphlpapi = dll
        return dll


_PATTERN = (string.ascii_lowercase + string.digits + string.ascii_uppercase).encode("ascii")


@functools.lru_cache(maxsize=16)
def _payload(size: int) -> bytes:
    """Repeating printable pattern of exactly *size* bytes."""
    if size <= 0:
        return b""
    reps = size // len(_PATTERN) + 1
    return (_PATTERN * reps)[:size]


def _clamp(value: Any, lo: int, hi: int, default: int) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def _no_reply(err: int, size: int, ip_text: str) -> PingResult:
    """Result for ``Icmp*SendEcho2`` returning 0: *err* is ``GetLastError()`` (11010 for a
    timeout). An error of 0 cannot be reported as ``status=0`` (that means success), so it
    becomes the generic ``-1`` OS-error status."""
    if err == 0:
        return PingResult(False, None, -1, "IcmpSendEcho2 returned no reply (GetLastError 0)", None, size, ip_text)
    return PingResult(False, None, int(err), status_text(err), None, size, ip_text)


class IcmpPinger:
    """Thread-safe wrapper over ``IcmpSendEcho2`` / ``Icmp6SendEcho2``.

    Handles are created lazily per thread (``threading.local``) and all released by
    :meth:`close`.
    """

    def __init__(self) -> None:
        self._local = threading.local()
        self._lock = threading.Lock()
        self._handles: set = set()          # every live handle, any thread
        self._generation = 0                # bumped by close(); stale thread-local handles are ignored

    # -- handles --------------------------------------------------------------------
    def _handle(self, ipv6: bool) -> int:
        attr = "h6" if ipv6 else "h4"
        cached = getattr(self._local, attr, None)      # (handle, generation) or None
        with self._lock:
            generation = self._generation
        if cached is not None and cached[1] == generation:
            return cached[0]
        dll = _dll()
        handle = dll.Icmp6CreateFile() if ipv6 else dll.IcmpCreateFile()
        if not handle or handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            raise OSError(err, f"{'Icmp6CreateFile' if ipv6 else 'IcmpCreateFile'} failed: {status_text(err)} ({err})")
        with self._lock:
            # If close() ran meanwhile the handle is still open and registered here, so the
            # next close() releases it; tagging it with the *current* generation keeps it usable.
            self._handles.add(handle)
            generation = self._generation
        setattr(self._local, attr, (handle, generation))
        return handle

    def close(self) -> None:
        """Close every ICMP handle created so far (idempotent, never raises)."""
        with self._lock:
            handles = list(self._handles)
            self._handles.clear()
            self._generation += 1
        if not handles:
            return
        try:
            dll = _dll()
        except Exception:  # noqa: BLE001
            return
        for h in handles:
            try:
                dll.IcmpCloseHandle(h)
            except Exception:  # noqa: BLE001
                log.debug("IcmpCloseHandle failed", exc_info=True)

    # -- pinging --------------------------------------------------------------------
    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> PingResult:
        """Send one echo request. Never raises; failures come back as ``ok=False``."""
        size = _clamp(size, 0, MAX_PAYLOAD, 32)
        timeout_ms = _clamp(timeout_ms, 1, 60_000, 1000)
        ttl = _clamp(ttl, 1, 255, 128)
        text = str(ip).strip() if ip is not None else ""
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            return PingResult(False, None, -1, f"invalid IP address: {ip!r}", None, size, text)
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped           # "::ffff:10.0.0.1" is an IPv4 host: Icmp6SendEcho2 rejects it
        try:
            if addr.version == 4:
                return self._ping4(addr, size, timeout_ms, ttl)
            return self._ping6(addr, size, timeout_ms, ttl)
        except Exception as exc:  # noqa: BLE001 - contract: never raise from ping
            log.debug("ping %s failed: %s", text, exc, exc_info=True)
            return PingResult(False, None, -1, str(exc) or exc.__class__.__name__, None, size, str(addr))

    def _ping4(self, addr: ipaddress.IPv4Address, size: int, timeout_ms: int, ttl: int) -> PingResult:
        dll = _dll()
        handle = self._handle(ipv6=False)
        dest = int.from_bytes(addr.packed, "little")   # IPAddr is the 4 bytes in network order
        data = _payload(size)
        request = (c_char * max(size, 1))()
        if size:
            request.raw = data
        opts = IP_OPTION_INFORMATION(Ttl=ttl, Tos=0, Flags=0, OptionsSize=0, OptionsData=None)
        reply_len = sizeof(ICMP_ECHO_REPLY) + size + 8
        reply_buf = ctypes.create_string_buffer(reply_len)
        ip_text = str(addr)
        t0 = time.perf_counter()
        count = dll.IcmpSendEcho2(handle, None, None, None, dest, request, size, byref(opts),
                                  reply_buf, reply_len, timeout_ms)
        wall_ms = (time.perf_counter() - t0) * 1000.0
        if count == 0:
            return _no_reply(ctypes.get_last_error(), size, ip_text)
        reply = ICMP_ECHO_REPLY.from_buffer(reply_buf)
        status = int(reply.Status)
        if status != 0:
            responder = str(ipaddress.IPv4Address(int(reply.Address).to_bytes(4, "little")))
            text = status_text(status)
            if responder not in (ip_text, "0.0.0.0"):
                text = f"{text} (reply from {responder})"
            return PingResult(False, None, status, text, None, size, ip_text,
                              responder=None if responder == "0.0.0.0" else responder)
        rtt = float(reply.RoundTripTime) if reply.RoundTripTime >= 1 else min(wall_ms, 0.99)
        return PingResult(True, rtt, 0, None, int(reply.Options.Ttl), size, ip_text, responder=ip_text)

    def _ping6(self, addr: ipaddress.IPv6Address, size: int, timeout_ms: int, ttl: int) -> PingResult:
        dll = _dll()
        handle = self._handle(ipv6=True)
        src = SOCKADDR_IN6(sin6_family=AF_INET6)                 # all zeros = any source
        dst = SOCKADDR_IN6(sin6_family=AF_INET6)
        dst.sin6_addr = (c_ubyte * 16)(*addr.packed)
        scope = getattr(addr, "scope_id", None)
        if scope:
            try:
                dst.sin6_scope_id = int(scope)
            except ValueError:
                pass
        data = _payload(size)
        request = (c_char * max(size, 1))()
        if size:
            request.raw = data
        opts = IP_OPTION_INFORMATION(Ttl=ttl, Tos=0, Flags=0, OptionsSize=0, OptionsData=None)
        reply_len = sizeof(ICMPV6_ECHO_REPLY) + size + 8
        reply_buf = ctypes.create_string_buffer(reply_len)
        ip_text = str(addr)
        t0 = time.perf_counter()
        count = dll.Icmp6SendEcho2(handle, None, None, None, byref(src), byref(dst), request, size,
                                   byref(opts), reply_buf, reply_len, timeout_ms)
        wall_ms = (time.perf_counter() - t0) * 1000.0
        if count == 0:
            return _no_reply(ctypes.get_last_error(), size, ip_text)
        reply = ICMPV6_ECHO_REPLY.from_buffer(reply_buf)
        status = int(reply.Status)
        if status != 0:
            raw = b"".join(int(w).to_bytes(2, "little") for w in reply.Address.sin6_addr)
            responder = str(ipaddress.IPv6Address(raw))
            text = status_text(status)
            if responder not in (ip_text, "::"):
                text = f"{text} (reply from {responder})"
            return PingResult(False, None, status, text, None, size, ip_text,
                              responder=None if responder == "::" else responder)
        rtt = float(reply.RoundTripTime) if reply.RoundTripTime >= 1 else min(wall_ms, 0.99)
        return PingResult(True, rtt, 0, None, None, size, ip_text, responder=ip_text)


# --- name resolution ----------------------------------------------------------------------
class _Lookup:
    """One in-flight ``getaddrinfo`` shared by every caller asking for the same name."""

    __slots__ = ("done", "result")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.result: Any = None            # getaddrinfo() list, or the exception it raised


_resolve_lock = threading.Lock()
_inflight: Dict[str, _Lookup] = {}


def _lookup(text: str, wait_s: float) -> Any:
    """``getaddrinfo(text)`` on a daemon thread, bounded by *wait_s*.

    Returns the address list, the exception the resolver raised, or ``None`` on timeout.
    Concurrent/overlapping calls for the same name wait on the same thread instead of
    starting another one, so a hung resolver costs at most one lingering thread per name.
    """
    with _resolve_lock:
        job = _inflight.get(text)
        start = job is None
        if job is None:
            job = _Lookup()
            _inflight[text] = job
    if start:
        def worker(job: _Lookup = job) -> None:
            try:
                job.result = socket.getaddrinfo(text, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except Exception as exc:  # noqa: BLE001 - reported to the caller as None
                job.result = exc
            finally:
                with _resolve_lock:
                    if _inflight.get(text) is job:
                        del _inflight[text]
                job.done.set()

        t = threading.Thread(target=worker, name=f"tnt-resolve-{text[:32]}", daemon=True)
        try:
            t.start()
        except Exception as exc:  # noqa: BLE001 - "can't start new thread": fail this lookup, not the caller
            with _resolve_lock:
                if _inflight.get(text) is job:
                    del _inflight[text]
            job.result = exc
            job.done.set()
    if not job.done.wait(wait_s):
        return None
    return job.result


def resolve(host: str, prefer_ipv4: bool = True, timeout_s: float = 3.0) -> Optional[str]:
    """Resolve *host* to an IP string (IPv4 preferred).

    Returns the input unchanged if it is already an IP literal. Returns ``None`` on
    failure or timeout: ``getaddrinfo`` runs in a daemon helper thread so a hung DNS
    resolver never blocks the caller for longer than *timeout_s*.
    """
    if not isinstance(host, str):
        return None
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if not text:
        return None
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        pass

    try:
        wait_s = max(0.0, float(timeout_s))
    except (TypeError, ValueError):
        wait_s = 3.0
    answer = _lookup(text, wait_s)
    if answer is None:
        log.debug("resolve(%s) timed out after %.1fs", text, wait_s)
        return None
    if isinstance(answer, Exception):
        log.debug("resolve(%s) failed: %s", text, answer)
        return None
    v4: List[str] = []
    v6: List[str] = []
    for family, _type, _proto, _canon, sockaddr in answer:
        if family == socket.AF_INET:
            v4.append(sockaddr[0])
        elif family == socket.AF_INET6:
            ip6 = sockaddr[0]
            scope = sockaddr[3] if len(sockaddr) > 3 else 0
            if scope and "%" not in ip6:
                ip6 = f"{ip6}%{scope}"
            v6.append(ip6)
    for candidates in ((v4, v6) if prefer_ipv4 else (v6, v4)):
        if candidates:
            return candidates[0]
    return None
