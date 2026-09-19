r"""Real-time Event Tracing for Windows (ETW) consumer: live frames from the built-in NDIS packet-capture provider
(the engine under the live Packet Capture screen, ARCHITECTURE §3.24).

Original code written from the published Windows Event Tracing interface: the ``EVENT_TRACE_PROPERTIES`` /
``WNODE_HEADER`` layouts of wmistr.h and evntrace.h, the ``EVENT_RECORD`` / ``EVENT_HEADER`` / ``EVENT_DESCRIPTOR``
layouts of evntcons.h, the documented behaviour of ``StartTraceW``, ``ControlTraceW``, ``EnableTraceEx2``,
``OpenTraceW``, ``ProcessTrace`` and ``CloseTrace``, and the x64 structure packing and calling convention those
headers imply.  Every structure below is declared from that published layout with ctypes; nothing is taken from any
other implementation.  The module drives advapi32 only: no driver is installed and no program is run.

Why a session of our own
------------------------
TNT's service runs as LocalSystem, so it may create ETW sessions.  :class:`TraceSession` starts a real-time session,
enables ``Microsoft-Windows-NDIS-PacketCapture`` (:data:`NDIS_PACKET_CAPTURE_GUID`) on it and consumes the events as
they arrive, so a live capture needs no third-party capture driver and no file on disk.

Is it usable (:func:`available`)
--------------------------------
``{"ok": bool, "reason": str|None}`` (:data:`AVAILABILITY_KEYS`): Windows (:data:`NOT_WINDOWS_REASON`), an advapi32
that loads with every tracing function this module calls (:data:`NO_API_REASON`), and administrator rights
(:data:`NOT_ADMIN_REASON`, which LocalSystem has).  Never raises.

Session names (:func:`session_name`)
------------------------------------
``session_name()`` is :data:`SESSION_PREFIX`; ``session_name("eth0")`` is ``"TNT-Capture-eth0"``.  Everything outside
``A-Z a-z 0-9 - _`` is dropped from the suffix and what is left is cut to :data:`MAX_SUFFIX` characters; a suffix that
leaves nothing behind gives the bare prefix.

EVENT dict (keys in this order, :data:`EVENT_KEYS`)::

    {"provider": str, "event_id": int, "ts": float, "data": bytes}

``provider`` is the canonical uppercase GUID text without braces, ``ts`` float seconds since 1970 (UTC) and ``data``
the event's user data.  ETW hands the consumer ``EVENT_HEADER.TimeStamp`` as a FILETIME-style 100 ns count since
1601-01-01 *because* this module never sets :data:`PROCESS_TRACE_MODE_RAW_TIMESTAMP` in
``EVENT_TRACE_LOGFILEW.ProcessTraceMode`` - that, and not the session's clock type, is what decides the format.  So
``ts = TimeStamp / 10_000_000 - 11_644_473_600``, and a timestamp that converts to a negative time gives ``ts`` 0.0.
(The session's ``Wnode.ClientContext`` is 1, QPC, which would pick the *raw* clock and would have to be converted by
hand if a maintainer ever turned ``PROCESS_TRACE_MODE_RAW_TIMESTAMP`` on.)

FRAME dict (keys in this order, :data:`FRAME_KEYS`)::

    {"ts": float, "if_index": int, "lower_if": int, "data": bytes, "origlen": int}

:class:`TraceSession`
---------------------
``TraceSession(name, *, providers=(), buffer_kb=64, min_buffers=16, max_buffers=256, flush_timer_s=1, api=None)``.
*providers* is a sequence of ``(guid, level, keywords)``; *api* is the injectable seam (None means the real advapi32
wrapper, built on the first call that needs it).  The buffer numbers are clamped to the ranges in :data:`LIMITS`, and
an empty *name*, a name over :data:`MAX_NAME` characters or a provider GUID that does not parse raises ``ValueError``.

* ``start()`` runs ``StartTraceW``; on ``ERROR_ALREADY_EXISTS`` (183) it stops the session of that name and tries once
  more, so a session a crash left behind never blocks a capture.  Then ``EnableTraceEx2`` for every provider.  A
  failure raises :class:`EtwError` with a plain-English reason: :data:`ACCESS_DENIED_TEXT` for ``ERROR_ACCESS_DENIED``
  (5), else :data:`START_FAILED_TEXT` or :data:`PROVIDER_FAILED_TEXT` with the Windows error number.  Starting twice
  raises :data:`ALREADY_STARTED_TEXT`.
* ``consume(callback)`` opens the trace and runs ``ProcessTrace`` on a daemon thread named
  :data:`CONSUMER_THREAD_NAME`.  *callback* gets EVENT dicts on that thread and must never raise: every call is
  wrapped, a raise is counted into ``stats()["callback_errors"]`` and logged at DEBUG, and one bad callback never ends
  the capture.  Without a start it raises :data:`NOT_STARTED_TEXT`, a second time :data:`ALREADY_CONSUMING_TEXT`, and a
  failed open :data:`ACCESS_DENIED_TEXT` for ``ERROR_ACCESS_DENIED`` (5), else :data:`OPEN_FAILED_TEXT` with the
  Windows error number - the same two-way answer ``start()`` gives.
* ``stop(timeout=5.0)`` closes the trace, joins the thread and stops the session.  Idempotent and never raises.
  ``CloseTrace`` on a real-time consumer answers ``ERROR_CTX_CLOSE_PENDING``: ``ProcessTrace`` goes on delivering what
  is already in the buffers, so the consumer thread may outlive *timeout*.  That is safe - the seam holds every
  callback and structure ETW can still reach until ``ProcessTrace`` returns - and the thread is a daemon, so a stop
  never waits for a busy adapter to drain.
* ``running`` is True between a start and a stop; ``stats()`` is ``{"events", "lost_events", "callback_errors",
  "buffers_read", "started_ts"}`` (:data:`STATS_KEYS`), with ``started_ts`` None before the first start.

:func:`stop_stale_sessions` stops the sessions a crash left behind: for the bare *prefix* and ``<prefix>-1`` ..
``<prefix>-<MAX_STALE_NAMES - 1>`` (the names TNT itself creates) it calls ``ControlTraceW(STOP)`` by name and counts
the ones that really stopped.  ``ERROR_WMI_INSTANCE_NOT_FOUND`` (4201) means there was nothing to stop.  Never raises.

:func:`decode_ndis_frame` turns an EVENT dict from the NDIS provider into a FRAME dict.  The payload is three
little-endian ``uint32`` - MiniportIfIndex, LowerIfIndex, FragmentSize - and then FragmentSize bytes of the frame.
That layout was verified on one PC, so every part of it is checked again here: an event from another provider or with
an id outside :data:`PACKET_EVENT_IDS` is not a packet event (None), a payload that ends at or before the end of its
:data:`HEADER_LEN` byte header is None, a FragmentSize over :data:`MAX_FRAME` is refused (None) and a FragmentSize
longer than the payload is clamped to what was really there.  ``origlen`` is the FragmentSize the event claimed and
``data`` the bytes that were there.  A ``ts`` that is not a number, a NaN, or a whole number too big for a float,
reads as 0.0: this answers None or a FRAME dict and never raises.

The injectable seam
-------------------
:class:`_Advapi` holds the bound ctypes functions and speaks plain Python: it builds and owns every structure, and
:class:`TraceSession` never touches ctypes itself.  Any object with these methods can stand in for it, which is the
only way this module can be tested - no test may create a real ETW session, and the test suite does not run as an
administrator::

    start_trace(name, *, buffer_kb, min_buffers, max_buffers, flush_timer_s) -> (rc, session_handle)
    enable_trace(handle, guid, level, keywords)                              -> rc
    control_trace(handle, name, code)                                        -> (rc, CONTROL_STATS dict)
    open_trace(name, on_event, on_buffer)                                    -> (rc, trace_handle)
    process_trace(trace_handle)                                              -> rc   (blocks until the trace closes)
    close_trace(trace_handle)                                                -> rc

``on_event`` gets EVENT dicts, ``on_buffer`` a ``{"buffers_read", "events_lost"}`` dict and returns False when the
consumer should stop.  ``control_trace`` returns ``{"events_lost", "buffers_written", "real_time_buffers_lost"}``
(:data:`CONTROL_STATS_KEYS`).  Whatever ``open_trace`` builds for a handle stays alive until the ``process_trace`` of
that handle returns; ``close_trace`` only asks ETW to stop, it frees nothing a running ``ProcessTrace`` still reads.

Contract gaps filled here
-------------------------
* :func:`stop_stale_sessions` takes an ``api`` keyword as well.  Without it a test would have to call ``ControlTraceW``
  for real, which could stop a capture the installed TNT is running on the same PC.
* ``StartTraceW`` gets ``LogFileNameOffset`` 0: this session logs to no file, and a non-zero offset with an empty name
  there is what makes ``StartTraceW`` fail with ``ERROR_BAD_PATHNAME``.  The buffer still carries room for both names
  (``sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024`` bytes), because ``ControlTraceW`` writes both back into it and needs
  both offsets set.
* A FragmentSize of 0, and a payload that carries the header and nothing behind it, are not packets either (None):
  clamping would leave a frame of no bytes, which is nothing a capture can show.
* An EVENT dict whose ``provider`` is missing or None is decoded; only a *different* provider is refused, so a caller
  that already filters by provider does not have to fill the field in.
* ``consume()`` runs once per session.  Call ``stop()`` and build another :class:`TraceSession` to capture again.
* ``stop()`` folds the counters ``ControlTraceW`` writes back into ``stats()``, so ``lost_events`` is the larger of
  what the buffer callback saw and what the session reported when it stopped.
* ``buffer_kb`` is kilobytes, as ``EVENT_TRACE_PROPERTIES.BufferSize`` counts them.
* A buffer number of ``inf`` clamps to the end of its range and a ``NaN`` falls back to the default, rather than
  raising out of the constructor: ``json.loads`` reads both of those bare literals, so either can reach it.

Logging: INFO carries counts and a stale session being cleared; handles, GUIDs and Windows error numbers are DEBUG.
"""
from __future__ import annotations

import ctypes
import logging
import struct
import sys
import threading
import time
import uuid
from ctypes import Structure, c_int64, c_long, c_ubyte, c_uint64, c_ulong, c_ushort, c_void_p, c_wchar, c_wchar_p
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

__all__ = [
    "EtwError", "NDIS_PACKET_CAPTURE_GUID", "SESSION_PREFIX", "EVENT_KEYS", "FRAME_KEYS", "STATS_KEYS",
    "CONTROL_STATS_KEYS", "AVAILABILITY_KEYS", "DEFAULT_BUFFER_KB", "DEFAULT_MIN_BUFFERS", "DEFAULT_MAX_BUFFERS",
    "FLUSH_TIMER_S", "MAX_FRAME", "HEADER_LEN", "PACKET_EVENT_IDS", "MAX_SUFFIX", "MAX_NAME", "MAX_STALE_NAMES",
    "LIMITS", "CONSUMER_THREAD_NAME", "NOT_WINDOWS_REASON", "NO_API_REASON", "NOT_ADMIN_REASON", "ACCESS_DENIED_TEXT",
    "START_FAILED_TEXT", "PROVIDER_FAILED_TEXT", "OPEN_FAILED_TEXT", "ALREADY_STARTED_TEXT", "NOT_STARTED_TEXT",
    "ALREADY_CONSUMING_TEXT", "STRUCT_SIZES", "available", "session_name", "TraceSession", "stop_stale_sessions",
    "decode_ndis_frame",
]

#: Microsoft-Windows-NDIS-PacketCapture: the in-box provider that carries every frame an adapter sends or receives.
NDIS_PACKET_CAPTURE_GUID = "2ED6006E-4729-4609-B423-3EE7BCD678EF"
SESSION_PREFIX = "TNT-Capture"
EVENT_KEYS = ("provider", "event_id", "ts", "data")          # ts is float seconds since 1970 (UTC)
FRAME_KEYS = ("ts", "if_index", "lower_if", "data", "origlen")
STATS_KEYS = ("events", "lost_events", "callback_errors", "buffers_read", "started_ts")
CONTROL_STATS_KEYS = ("events_lost", "buffers_written", "real_time_buffers_lost")
AVAILABILITY_KEYS = ("ok", "reason")

DEFAULT_BUFFER_KB = 64
DEFAULT_MIN_BUFFERS = 16
DEFAULT_MAX_BUFFERS = 256
FLUSH_TIMER_S = 1

MAX_FRAME = 65536                          # a FragmentSize over this is refused, never allocated
HEADER_LEN = 12                            # MiniportIfIndex, LowerIfIndex, FragmentSize: three little-endian uint32
#: The NDIS provider's packet-fragment events: 1001 is the one this PC emits, 1002 and 1003 carry the same header.
PACKET_EVENT_IDS = (1001, 1002, 1003)
MAX_SUFFIX = 32
MAX_NAME = 200                             # ETW allows more; a name a person may have to read does not need it
MAX_STALE_NAMES = 8                        # the prefix itself and <prefix>-1 .. <prefix>-7
#: ``field: (smallest, largest)`` the constructor clamps the session's buffer numbers to.
LIMITS = {"buffer_kb": (4, 1024), "min_buffers": (2, 1024), "max_buffers": (2, 1024), "flush_timer_s": (1, 60)}
CONSUMER_THREAD_NAME = "tnt-etw"

NOT_WINDOWS_REASON = "Live packet capture needs Windows"
NO_API_REASON = "This PC has no Event Tracing API (advapi32)"
NOT_ADMIN_REASON = "Live packet capture needs a Windows administrator account"
ACCESS_DENIED_TEXT = "access denied: TNT must run as a service to capture packets"
START_FAILED_TEXT = "the capture session could not start (error {rc})"
PROVIDER_FAILED_TEXT = "the packet capture provider could not be enabled (error {rc})"
OPEN_FAILED_TEXT = "the capture session could not be opened for reading (error {rc})"
ALREADY_STARTED_TEXT = "this capture session was already started"
NOT_STARTED_TEXT = "the capture session is not running"
ALREADY_CONSUMING_TEXT = "this capture session is already delivering events"

# -- evntrace.h / evntcons.h / winerror.h -----------------------------------------------------------
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
#: Deliberately never set: with it, ``EVENT_HEADER.TimeStamp`` arrives as a raw clock reading (QPC ticks for this
#: session's ``ClientContext``) instead of 100 ns since 1601, and :func:`_unix_ts` would put every frame in 1601.
PROCESS_TRACE_MODE_RAW_TIMESTAMP = 0x00001000
WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
EVENT_TRACE_CONTROL_QUERY = 0
EVENT_TRACE_CONTROL_STOP = 1
ERROR_SUCCESS = 0
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_ALREADY_EXISTS = 183
ERROR_WMI_INSTANCE_NOT_FOUND = 4201
#: What ``CloseTrace`` answers for a real-time consumer: ``ProcessTrace`` is still draining the buffers it has.
ERROR_CTX_CLOSE_PENDING = 7007
INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF
TRACE_NAME_BYTES = 1024                    # room after the structure for the logger name, then the log file name
FILETIME_EPOCH_S = 11_644_473_600          # seconds between 1601-01-01 and 1970-01-01
FILETIME_PER_S = 10_000_000                # 100 ns units in a second


class EtwError(RuntimeError):
    """An ETW session could not be started, enabled, opened or read.  The text is meant for a person to read."""


# --- native structures (x64 layout per wmistr.h, evntrace.h and evntcons.h) -------------------------
class GUID(Structure):
    _fields_ = [
        ("Data1", c_ulong),
        ("Data2", c_ushort),
        ("Data3", c_ushort),
        ("Data4", c_ubyte * 8),
    ]                                      # sizeof == 16


class WNODE_HEADER(Structure):
    _fields_ = [
        ("BufferSize", c_ulong),
        ("ProviderId", c_ulong),
        ("HistoricalContext", c_uint64),   # union with Version + Linkage
        ("TimeStamp", c_uint64),           # union with CountLost and KernelHandle
        ("Guid", GUID),
        ("ClientContext", c_ulong),        # 1 = QPC: the session's raw clock, which a consumer sees only with
                                           # PROCESS_TRACE_MODE_RAW_TIMESTAMP (this module never sets it)
        ("Flags", c_ulong),
    ]                                      # sizeof == 48


class EVENT_TRACE_PROPERTIES(Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", c_ulong),           # kilobytes
        ("MinimumBuffers", c_ulong),
        ("MaximumBuffers", c_ulong),
        ("MaximumFileSize", c_ulong),
        ("LogFileMode", c_ulong),
        ("FlushTimer", c_ulong),           # seconds
        ("EnableFlags", c_ulong),
        ("AgeLimit", c_long),              # union with FlushThreshold
        ("NumberOfBuffers", c_ulong),
        ("FreeBuffers", c_ulong),
        ("EventsLost", c_ulong),
        ("BuffersWritten", c_ulong),
        ("LogBuffersLost", c_ulong),
        ("RealTimeBuffersLost", c_ulong),
        ("LoggerThreadId", c_void_p),      # HANDLE: 8 bytes on x64, and it aligns the two offsets behind it
        ("LogFileNameOffset", c_ulong),
        ("LoggerNameOffset", c_ulong),
    ]                                      # sizeof == 120 on x64 (104 bytes of fields, then the aligned HANDLE)


class EVENT_TRACE_HEADER(Structure):
    _fields_ = [
        ("Size", c_ushort),
        ("FieldTypeFlags", c_ushort),      # union with HeaderType + MarkerFlags
        ("Version", c_ulong),              # union with Class (Type, Level, Version)
        ("ThreadId", c_ulong),
        ("ProcessId", c_ulong),
        ("TimeStamp", c_int64),
        ("Guid", GUID),                    # union with GuidPtr
        ("ProcessorTime", c_uint64),       # union with ClientContext + Flags and KernelTime + UserTime
    ]                                      # sizeof == 48


class ETW_BUFFER_CONTEXT(Structure):
    _fields_ = [
        ("ProcessorIndex", c_ushort),      # union with ProcessorNumber + Alignment
        ("LoggerId", c_ushort),
    ]                                      # sizeof == 4


class EVENT_TRACE(Structure):
    _fields_ = [
        ("Header", EVENT_TRACE_HEADER),
        ("InstanceId", c_ulong),
        ("ParentInstanceId", c_ulong),
        ("ParentGuid", GUID),
        ("MofData", c_void_p),
        ("MofLength", c_ulong),
        ("BufferContext", ETW_BUFFER_CONTEXT),   # union with ClientContext
    ]                                      # sizeof == 88 on x64 (MofData is aligned to 72)


class SYSTEMTIME(Structure):
    _fields_ = [(name, c_ushort) for name in ("wYear", "wMonth", "wDayOfWeek", "wDay", "wHour", "wMinute", "wSecond",
                                              "wMilliseconds")]
    # sizeof == 16


class TIME_ZONE_INFORMATION(Structure):
    _fields_ = [
        ("Bias", c_long),
        ("StandardName", c_wchar * 32),
        ("StandardDate", SYSTEMTIME),
        ("StandardBias", c_long),
        ("DaylightName", c_wchar * 32),
        ("DaylightDate", SYSTEMTIME),
        ("DaylightBias", c_long),
    ]                                      # sizeof == 172


class TRACE_LOGFILE_HEADER(Structure):
    _fields_ = [
        ("BufferSize", c_ulong),
        ("Version", c_ulong),              # union with VersionDetail (four bytes)
        ("ProviderVersion", c_ulong),
        ("NumberOfProcessors", c_ulong),
        ("EndTime", c_int64),
        ("TimerResolution", c_ulong),
        ("MaximumFileSize", c_ulong),
        ("LogFileMode", c_ulong),
        ("BuffersWritten", c_ulong),
        ("LogInstanceGuid", GUID),         # union with StartBuffers, PointerSize, EventsLost, CpuSpeedInMHz
        ("LoggerName", c_wchar_p),
        ("LogFileName", c_wchar_p),
        ("TimeZone", TIME_ZONE_INFORMATION),
        ("BootTime", c_int64),             # the 172-byte time zone ends at 244: this is padded to 248
        ("PerfFreq", c_int64),
        ("StartTime", c_int64),
        ("ReservedFlags", c_ulong),
        ("BuffersLost", c_ulong),
    ]                                      # sizeof == 280 on x64


class EVENT_DESCRIPTOR(Structure):
    _fields_ = [
        ("Id", c_ushort),
        ("Version", c_ubyte),
        ("Channel", c_ubyte),
        ("Level", c_ubyte),
        ("Opcode", c_ubyte),
        ("Task", c_ushort),
        ("Keyword", c_uint64),
    ]                                      # sizeof == 16


class EVENT_HEADER(Structure):
    _fields_ = [
        ("Size", c_ushort),
        ("HeaderType", c_ushort),
        ("Flags", c_ushort),
        ("EventProperty", c_ushort),
        ("ThreadId", c_ulong),
        ("ProcessId", c_ulong),
        ("TimeStamp", c_int64),            # 100 ns since 1601-01-01: ETW converts it unless the consumer asks for
                                           # PROCESS_TRACE_MODE_RAW_TIMESTAMP, which open_trace() below never does
        ("ProviderId", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("ProcessorTime", c_uint64),       # union with KernelTime + UserTime
        ("ActivityId", GUID),
    ]                                      # sizeof == 80 on x64


class EVENT_RECORD(Structure):
    _fields_ = [
        ("EventHeader", EVENT_HEADER),
        ("BufferContext", ETW_BUFFER_CONTEXT),
        ("ExtendedDataCount", c_ushort),
        ("UserDataLength", c_ushort),
        ("ExtendedData", c_void_p),
        ("UserData", c_void_p),
        ("UserContext", c_void_p),
    ]                                      # sizeof == 112 on x64 (ExtendedData is aligned to 88)


#: ``WINFUNCTYPE`` only exists on Windows; ``CFUNCTYPE`` keeps the module importable elsewhere, where nothing calls it.
_FUNCTYPE = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
#: ``PEVENT_RECORD_CALLBACK``.  The buffer callback takes ``PEVENT_TRACE_LOGFILEW``, which is declared below it, so it
#: is taken as a plain address and cast inside: that keeps the two declarations from referring to each other.
EVENT_RECORD_CALLBACK = _FUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))
BUFFER_CALLBACK = _FUNCTYPE(c_ulong, c_void_p)


class EVENT_TRACE_LOGFILEW(Structure):
    _fields_ = [
        ("LogFileName", c_wchar_p),
        ("LoggerName", c_wchar_p),
        ("CurrentTime", c_int64),
        ("BuffersRead", c_ulong),
        ("ProcessTraceMode", c_ulong),     # union with LogFileMode
        ("CurrentEvent", EVENT_TRACE),
        ("LogfileHeader", TRACE_LOGFILE_HEADER),
        ("BufferCallback", BUFFER_CALLBACK),
        ("BufferSize", c_ulong),
        ("Filled", c_ulong),
        ("EventsLost", c_ulong),
        ("EventRecordCallback", EVENT_RECORD_CALLBACK),   # union with EventCallback; aligned to 424
        ("IsKernelTrace", c_ulong),
        ("Context", c_void_p),             # aligned to 440
    ]                                      # sizeof == 448 on x64


class ENABLE_TRACE_PARAMETERS(Structure):
    _fields_ = [
        ("Version", c_ulong),
        ("EnableProperty", c_ulong),
        ("ControlFlags", c_ulong),
        ("SourceId", GUID),
        ("EnableFilterDesc", c_void_p),    # the 16-byte GUID ends at 28: this is padded to 32
        ("FilterDescCount", c_ulong),
    ]                                      # sizeof == 48 on x64


#: The documented x64 size of every structure above.  A mis-declared field is caught here, not by corrupted memory.
STRUCT_SIZES = {
    "GUID": 16, "WNODE_HEADER": 48, "EVENT_TRACE_PROPERTIES": 120, "EVENT_TRACE_HEADER": 48, "ETW_BUFFER_CONTEXT": 4,
    "EVENT_TRACE": 88, "SYSTEMTIME": 16, "TIME_ZONE_INFORMATION": 172, "TRACE_LOGFILE_HEADER": 280,
    "EVENT_DESCRIPTOR": 16, "EVENT_HEADER": 80, "EVENT_RECORD": 112, "EVENT_TRACE_LOGFILEW": 448,
    "ENABLE_TRACE_PARAMETERS": 48,
}


# --- small helpers ---------------------------------------------------------------------------------
def _clamp(value: Any, field: str, default: int) -> int:
    """*value* as a whole number inside ``LIMITS[field]``; *default* when it is not a number at all.

    A NaN is not a number at all either, so it gives *default*; an infinity is a number with no whole part, so it
    clamps to the end of the range it points at.  ``int()`` refuses both, and this never raises out of the
    constructor: ``json.loads`` accepts the bare literals ``Infinity`` and ``NaN``, so either can reach here."""
    low, high = LIMITS[field]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    if value != value:                                   # NaN: it is not anywhere on the range
        return default
    try:
        whole = int(value)
    except (OverflowError, ValueError):                  # an infinity: as far along the range as it goes
        return high if value > 0 else low
    return max(low, min(high, whole))


def _guid_struct(text: Any) -> Optional[GUID]:
    """A :class:`GUID` from ``"2ED6006E-..."`` (braces optional), or None when the text is not a GUID.

    ``UUID.bytes_le`` is exactly the little-endian memory layout of a Windows GUID, so no field is swapped by hand."""
    try:
        return GUID.from_buffer_copy(uuid.UUID(str(text)).bytes_le)
    except (AttributeError, TypeError, ValueError):
        return None


def _guid_text(guid: Any) -> Optional[str]:
    """A :class:`GUID` structure as canonical uppercase text without braces, or None when it cannot be read."""
    try:
        return str(uuid.UUID(bytes_le=bytes(guid))).upper()
    except (AttributeError, TypeError, ValueError):
        return None


def _normalized_guid(text: Any) -> Optional[str]:
    """GUID text in the one form this module compares, or None when it is not a GUID."""
    try:
        return str(uuid.UUID(str(text))).upper()
    except (AttributeError, TypeError, ValueError):
        return None


def _unix_ts(filetime: Any) -> float:
    """A FILETIME-style 100 ns count since 1601-01-01 as float seconds since 1970; 0.0 for anything before that."""
    try:
        seconds = int(filetime) / FILETIME_PER_S - FILETIME_EPOCH_S
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return seconds if seconds > 0 else 0.0


def _frame_ts(value: Any) -> float:
    """An event's ``ts`` as a float; 0.0 for anything that is not a number, including one too big for a float.

    A ``bool`` is an ``int`` to Python but never a time here, a NaN is not a time either, and an integer of more than
    308 digits - which is a ``json.loads`` away from a caller - makes ``float()`` raise ``OverflowError``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        return 0.0
    try:
        return float(value)
    except (OverflowError, ValueError):
        return 0.0


def _is_admin() -> Optional[bool]:
    """Does this process have administrator rights?  None when that cannot be told (the service is LocalSystem)."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        log.debug("the administrator check failed", exc_info=True)
        return None


def _load_advapi32() -> Any:
    """``advapi32`` with every tracing function this module calls declared.  Raises when it cannot be loaded."""
    dll = ctypes.WinDLL("advapi32", use_last_error=True)
    dll.StartTraceW.argtypes = [ctypes.POINTER(c_uint64), c_wchar_p, c_void_p]
    dll.StartTraceW.restype = c_ulong
    dll.ControlTraceW.argtypes = [c_uint64, c_wchar_p, c_void_p, c_ulong]
    dll.ControlTraceW.restype = c_ulong
    dll.EnableTraceEx2.argtypes = [c_uint64, ctypes.POINTER(GUID), c_ulong, c_ubyte, c_uint64, c_uint64, c_ulong,
                                   c_void_p]
    dll.EnableTraceEx2.restype = c_ulong
    dll.OpenTraceW.argtypes = [c_void_p]
    dll.OpenTraceW.restype = c_uint64
    dll.ProcessTrace.argtypes = [ctypes.POINTER(c_uint64), c_ulong, c_void_p, c_void_p]
    dll.ProcessTrace.restype = c_ulong
    dll.CloseTrace.argtypes = [c_uint64]
    dll.CloseTrace.restype = c_ulong
    return dll


def _api_available() -> bool:
    """Can advapi32 be loaded with every tracing function?  (the seam :func:`available` asks; never raises)"""
    try:
        _load_advapi32()
    except Exception:  # noqa: BLE001
        log.debug("advapi32 could not be loaded for tracing", exc_info=True)
        return False
    return True


# --- the real advapi32 seam ------------------------------------------------------------------------
class _Advapi:
    """The bound ctypes functions behind :class:`TraceSession`: plain Python in, plain Python out.

    Every callback object and log file structure :meth:`open_trace` builds is kept in a Python attribute until the
    ``ProcessTrace`` of that handle returns.  ETW calls those callbacks and writes into that structure from its own
    thread for as long as that call runs - past ``CloseTrace``, which only asks it to stop - so a garbage collector
    that freed one any earlier would corrupt memory under it.  The ``StartTraceW`` properties buffer is *not* kept:
    ``StartTraceW`` copies it into the kernel and never looks at the caller's copy again, and ``ControlTraceW`` fills
    in whatever buffer it is handed at the time of the call, which :meth:`control_trace` allocates fresh."""

    def __init__(self) -> None:
        self._dll = _load_advapi32()
        #: trace handle -> ``{"objects": (logfile, name buffer, the two callbacks), "processing": bool}``
        self._open: Dict[int, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    # -- buffers ---------------------------------------------------------------------------------
    @staticmethod
    def _properties_buffer() -> Any:
        """A zeroed ``EVENT_TRACE_PROPERTIES`` with room for the logger name and the log file name behind it."""
        size = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        return (c_ubyte * (size + 2 * TRACE_NAME_BYTES))()

    @staticmethod
    def _init_properties(buf: Any) -> Any:
        """The ``EVENT_TRACE_PROPERTIES`` view of *buf*, with the fields every call has to fill in already set."""
        props = EVENT_TRACE_PROPERTIES.from_buffer(buf)
        props.Wnode.BufferSize = ctypes.sizeof(buf)
        props.Wnode.ClientContext = 1                    # QPC: the session's own clock (see the module docstring)
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        return props

    # -- the session -----------------------------------------------------------------------------
    def start_trace(self, name: str, *, buffer_kb: int, min_buffers: int, max_buffers: int,
                    flush_timer_s: int) -> Tuple[int, int]:
        """``StartTraceW`` for a real-time session; ``(rc, session handle)``."""
        buf = self._properties_buffer()
        props = self._init_properties(buf)
        props.BufferSize = buffer_kb
        props.MinimumBuffers = min_buffers
        props.MaximumBuffers = max_buffers
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        props.FlushTimer = flush_timer_s
        props.LogFileNameOffset = 0                      # no log file: an empty name behind a real offset would fail
        handle = c_uint64(0)
        rc = int(self._dll.StartTraceW(ctypes.byref(handle), name, ctypes.addressof(buf)))
        return rc, int(handle.value)                     # StartTraceW copied the buffer: nothing to keep here

    def enable_trace(self, handle: int, guid: str, level: int, keywords: int) -> int:
        """``EnableTraceEx2`` with ``EVENT_CONTROL_CODE_ENABLE_PROVIDER``; the Windows error code."""
        provider = _guid_struct(guid)
        if provider is None:
            raise ValueError(f"{guid!r} is not a provider GUID")
        return int(self._dll.EnableTraceEx2(c_uint64(handle), ctypes.byref(provider),
                                            EVENT_CONTROL_CODE_ENABLE_PROVIDER, c_ubyte(level & 0xFF),
                                            c_uint64(keywords & 0xFFFFFFFFFFFFFFFF), c_uint64(0), c_ulong(0), None))

    def control_trace(self, handle: int, name: Optional[str], code: int) -> Tuple[int, Dict[str, int]]:
        """``ControlTraceW`` (stop or query) by handle or by name; ``(rc, CONTROL_STATS dict)``.

        Both name offsets are set here: ``ControlTraceW`` writes the logger name and the log file name back into the
        buffer, and refuses the call when it has nowhere to put them."""
        buf = self._properties_buffer()
        props = self._init_properties(buf)
        props.LogFileNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + TRACE_NAME_BYTES
        rc = int(self._dll.ControlTraceW(c_uint64(handle or 0), name, ctypes.addressof(buf), c_ulong(code)))
        stats = {"events_lost": int(props.EventsLost), "buffers_written": int(props.BuffersWritten),
                 "real_time_buffers_lost": int(props.RealTimeBuffersLost)}
        return rc, stats

    # -- consuming -------------------------------------------------------------------------------
    @staticmethod
    def _event_callback(on_event: Callable[[Dict[str, Any]], None]) -> Any:
        """An ``EVENT_RECORD_CALLBACK`` that turns a record into an EVENT dict.  It runs on the kernel's own thread, so
        it swallows everything: an exception escaping a ctypes callback has nowhere to go."""
        def handler(record: Any) -> None:
            try:
                rec = record.contents
                header = rec.EventHeader
                length = int(rec.UserDataLength)
                address = rec.UserData
                data = ctypes.string_at(address, length) if address and length > 0 else b""
                event = {"provider": _guid_text(header.ProviderId), "event_id": int(header.EventDescriptor.Id),
                         "ts": _unix_ts(header.TimeStamp), "data": data}
            except Exception:  # noqa: BLE001
                log.debug("an ETW record could not be read", exc_info=True)
                return
            try:
                on_event(event)
            except Exception:  # noqa: BLE001
                log.debug("the ETW event handler raised", exc_info=True)

        return EVENT_RECORD_CALLBACK(handler)

    @staticmethod
    def _buffer_callback(on_buffer: Callable[[Dict[str, int]], Any]) -> Any:
        """A ``BUFFER_CALLBACK`` reporting the running counters; 0 (False) tells ``ProcessTrace`` to stop."""
        def handler(address: Any) -> int:
            try:
                logfile = ctypes.cast(address, ctypes.POINTER(EVENT_TRACE_LOGFILEW)).contents
                info = {"buffers_read": int(logfile.BuffersRead), "events_lost": int(logfile.EventsLost)}
            except Exception:  # noqa: BLE001
                log.debug("an ETW buffer could not be read", exc_info=True)
                return 1
            try:
                return 1 if on_buffer(info) else 0
            except Exception:  # noqa: BLE001
                log.debug("the ETW buffer handler raised", exc_info=True)
                return 1

        return BUFFER_CALLBACK(handler)

    def open_trace(self, name: str, on_event: Callable[[Dict[str, Any]], None],
                   on_buffer: Callable[[Dict[str, int]], Any]) -> Tuple[int, int]:
        """``OpenTraceW`` for the real-time session *name*; ``(rc, trace handle)``, rc 0 only for a usable handle."""
        logfile = EVENT_TRACE_LOGFILEW()
        name_buf = ctypes.create_unicode_buffer(str(name))
        logfile.LoggerName = ctypes.cast(name_buf, c_wchar_p)
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        event_cb = self._event_callback(on_event)
        buffer_cb = self._buffer_callback(on_buffer)
        logfile.EventRecordCallback = event_cb
        logfile.BufferCallback = buffer_cb
        handle = int(self._dll.OpenTraceW(ctypes.addressof(logfile)))
        if handle == INVALID_PROCESSTRACE_HANDLE:
            return int(ctypes.get_last_error() or 1), 0
        with self._lock:                                 # alive until this handle's ProcessTrace returns
            self._open[handle] = {"objects": (logfile, name_buf, event_cb, buffer_cb), "processing": False}
        return ERROR_SUCCESS, handle

    def _release(self, handle: int) -> None:
        """Let go of the callbacks and the log file structure of *handle*, once ETW can no longer reach them."""
        with self._lock:
            self._open.pop(int(handle), None)

    def process_trace(self, handle: int) -> int:
        """``ProcessTrace``: it blocks on the calling thread until the trace is closed *and* drained.

        This is the one place the objects :meth:`open_trace` built are let go, in the ``finally``: until this call
        returns, ETW is still calling those callbacks and still writing into that log file structure.  A handle whose
        objects are already gone - :meth:`close_trace` ran before this thread ever got here - is not processed at
        all, because the callbacks it would need no longer exist."""
        key = int(handle)
        with self._lock:
            entry = self._open.get(key)
            if entry is None:
                log.debug("ProcessTrace skipped: the trace handle was closed before it could be read")
                return ERROR_INVALID_HANDLE
            entry["processing"] = True
        handles = (c_uint64 * 1)(key)
        try:
            return int(self._dll.ProcessTrace(handles, c_ulong(1), None, None))
        finally:
            self._release(key)

    def close_trace(self, handle: int) -> int:
        """``CloseTrace``, which is what makes a blocked ``ProcessTrace`` return.

        For a real-time consumer it answers ``ERROR_CTX_CLOSE_PENDING`` and ``ProcessTrace`` goes on delivering the
        events already in the buffers, so this frees nothing while a ``ProcessTrace`` is running: that call frees the
        callbacks itself when it returns.  A handle nobody is processing is released here instead, so a trace that
        was opened and then closed without ever being read leaves nothing behind."""
        key = int(handle)
        try:
            return int(self._dll.CloseTrace(c_uint64(key)))
        finally:
            with self._lock:                             # one step, so it cannot race a ProcessTrace starting
                entry = self._open.get(key)
                if entry is not None and not entry["processing"]:
                    self._open.pop(key, None)


# --- public helpers --------------------------------------------------------------------------------
def available() -> Dict[str, Any]:
    """``{"ok", "reason"}``: can this PC run a live ETW capture?  Never raises, and starts nothing."""
    if sys.platform != "win32":
        return {"ok": False, "reason": NOT_WINDOWS_REASON}
    if not _api_available():
        return {"ok": False, "reason": NO_API_REASON}
    if _is_admin() is False:
        return {"ok": False, "reason": NOT_ADMIN_REASON}
    return {"ok": True, "reason": None}


def session_name(suffix: str = "") -> str:
    """The ETW session name for a capture: :data:`SESSION_PREFIX`, with ``-<suffix>`` when one is left after the
    characters outside ``A-Z a-z 0-9 - _`` are dropped and the rest is cut to :data:`MAX_SUFFIX`."""
    kept = "".join(ch for ch in str(suffix or "") if ch.isascii() and (ch.isalnum() or ch in "-_"))[:MAX_SUFFIX]
    return f"{SESSION_PREFIX}-{kept}" if kept else SESSION_PREFIX


# --- one real-time session -------------------------------------------------------------------------
class TraceSession:
    """One real-time ETW session and its consumer thread."""

    def __init__(self, name: str, *, providers: Sequence[Tuple[str, int, int]] = (),
                 buffer_kb: int = DEFAULT_BUFFER_KB, min_buffers: int = DEFAULT_MIN_BUFFERS,
                 max_buffers: int = DEFAULT_MAX_BUFFERS, flush_timer_s: int = FLUSH_TIMER_S,
                 api: Any = None) -> None:
        text = str(name or "").strip()
        if not text or len(text) > MAX_NAME:
            raise ValueError(f"a session name must be 1 to {MAX_NAME} characters")
        self.name = text
        self.providers: List[Tuple[str, int, int]] = []
        for entry in providers or ():
            guid, level, keywords = entry
            if _normalized_guid(guid) is None:
                raise ValueError(f"{guid!r} is not a provider GUID")
            self.providers.append((str(guid), int(level), int(keywords)))
        self.buffer_kb = _clamp(buffer_kb, "buffer_kb", DEFAULT_BUFFER_KB)
        self.min_buffers = _clamp(min_buffers, "min_buffers", DEFAULT_MIN_BUFFERS)
        self.max_buffers = max(self.min_buffers, _clamp(max_buffers, "max_buffers", DEFAULT_MAX_BUFFERS))
        self.flush_timer_s = _clamp(flush_timer_s, "flush_timer_s", FLUSH_TIMER_S)
        self._api = api
        self._lock = threading.Lock()
        self._handle: int = 0
        self._trace_handle: Optional[int] = None
        self._thread: Optional[threading.Thread] = None
        self._started = False
        self._start_attempted = False
        self._stopping = False
        self._events = 0
        self._lost_events = 0
        self._callback_errors = 0
        self._buffers_read = 0
        self._started_ts: Optional[float] = None

    # -- state ------------------------------------------------------------------------------------
    @property
    def running(self) -> bool:
        """True from a successful :meth:`start` until :meth:`stop`."""
        with self._lock:
            return self._started

    def stats(self) -> Dict[str, Any]:
        """``{"events", "lost_events", "callback_errors", "buffers_read", "started_ts"}`` (:data:`STATS_KEYS`)."""
        with self._lock:
            return {"events": self._events, "lost_events": self._lost_events,
                    "callback_errors": self._callback_errors, "buffers_read": self._buffers_read,
                    "started_ts": self._started_ts}

    def _advapi(self) -> Any:
        """The seam: the one that was injected, else the real advapi32 wrapper, built once."""
        with self._lock:
            if self._api is not None:
                return self._api
        try:
            api = _Advapi()
        except Exception as exc:  # noqa: BLE001
            log.debug("advapi32 could not be loaded", exc_info=True)
            raise EtwError(NO_API_REASON) from exc
        with self._lock:
            if self._api is None:
                self._api = api
            return self._api

    # -- starting ---------------------------------------------------------------------------------
    @staticmethod
    def _failure(template: str, rc: int) -> EtwError:
        """The plain-English reason for a Windows error code."""
        if rc == ERROR_ACCESS_DENIED:
            return EtwError(ACCESS_DENIED_TEXT)
        return EtwError(template.format(rc=rc))

    def start(self) -> None:
        """Start the session and enable every provider on it.

        A session of the same name that a crash left behind (``ERROR_ALREADY_EXISTS``) is stopped and the start tried
        once more.  Raises :class:`EtwError` with a reason a person can read; leaves nothing running on failure."""
        with self._lock:
            if self._start_attempted:
                raise EtwError(ALREADY_STARTED_TEXT)
            self._start_attempted = True
        api = self._advapi()
        rc, handle = api.start_trace(self.name, buffer_kb=self.buffer_kb, min_buffers=self.min_buffers,
                                     max_buffers=self.max_buffers, flush_timer_s=self.flush_timer_s)
        if rc == ERROR_ALREADY_EXISTS:
            log.info("a capture session was left behind by an earlier run: stopping it")
            self._control(api, 0, EVENT_TRACE_CONTROL_STOP)
            rc, handle = api.start_trace(self.name, buffer_kb=self.buffer_kb, min_buffers=self.min_buffers,
                                         max_buffers=self.max_buffers, flush_timer_s=self.flush_timer_s)
        if rc != ERROR_SUCCESS:
            log.debug("StartTraceW for %s returned %d", self.name, rc)
            raise self._failure(START_FAILED_TEXT, rc)
        with self._lock:
            self._handle = int(handle or 0)
            self._started = True
            self._started_ts = time.time()
        for guid, level, keywords in self.providers:
            try:
                enable_rc = int(api.enable_trace(self._handle, guid, level, keywords))
            except Exception as exc:  # noqa: BLE001 - a broken seam must not leave the session running
                log.debug("EnableTraceEx2 for %s raised", guid, exc_info=True)
                self.stop()
                raise EtwError(PROVIDER_FAILED_TEXT.format(rc=1)) from exc
            if enable_rc != ERROR_SUCCESS:
                log.debug("EnableTraceEx2 for %s returned %d", guid, enable_rc)
                error = self._failure(PROVIDER_FAILED_TEXT, enable_rc)
                self.stop()
                raise error

    # -- consuming --------------------------------------------------------------------------------
    def _wrap(self, callback: Callable[[Dict[str, Any]], None]) -> Callable[[Dict[str, Any]], None]:
        """The callback the consumer thread really calls: it counts every event and swallows every raise."""
        def deliver(event: Dict[str, Any]) -> None:
            with self._lock:
                self._events += 1
            try:
                callback(event)
            except Exception:  # noqa: BLE001 - one bad callback must never end a capture
                with self._lock:
                    self._callback_errors += 1
                log.debug("a packet capture callback raised", exc_info=True)

        return deliver

    def _on_buffer(self, info: Dict[str, int]) -> bool:
        """The buffer callback: keep the counters and say whether the consumer should carry on."""
        try:
            read, lost = int(info.get("buffers_read") or 0), int(info.get("events_lost") or 0)
        except (AttributeError, TypeError, ValueError):
            read = lost = 0
        with self._lock:
            self._buffers_read = max(self._buffers_read, read)
            self._lost_events = max(self._lost_events, lost)
            return not self._stopping

    def _run(self, api: Any, trace_handle: int) -> None:
        """The consumer thread.  *api* is an argument, not ``self._api``, on purpose: this frame is what keeps the
        seam - and so every callback ETW still holds - alive even if the session is dropped while it drains."""
        try:
            rc = int(api.process_trace(trace_handle))
        except Exception:  # noqa: BLE001 - the thread must end quietly, whatever the seam did
            log.debug("ProcessTrace raised", exc_info=True)
            return
        if rc != ERROR_SUCCESS:
            log.debug("ProcessTrace returned %d", rc)

    def consume(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Open the trace and deliver EVENT dicts to *callback* on a daemon thread named :data:`CONSUMER_THREAD_NAME`.

        *callback* runs on that thread and may raise: every raise is counted into ``stats()["callback_errors"]`` and
        the capture carries on.  Raises :class:`EtwError` when the session is not running (:data:`NOT_STARTED_TEXT`),
        when it is already consuming (:data:`ALREADY_CONSUMING_TEXT`), or when the trace cannot be opened -
        :data:`ACCESS_DENIED_TEXT` for ``ERROR_ACCESS_DENIED``, else :data:`OPEN_FAILED_TEXT` with the error
        number."""
        with self._lock:
            if not self._started:
                raise EtwError(NOT_STARTED_TEXT)
            if self._thread is not None:
                raise EtwError(ALREADY_CONSUMING_TEXT)
        api = self._advapi()
        rc, trace_handle = api.open_trace(self.name, self._wrap(callback), self._on_buffer)
        rc = int(rc)
        handle = int(trace_handle or 0)
        if rc != ERROR_SUCCESS or handle in (0, INVALID_PROCESSTRACE_HANDLE):
            log.debug("OpenTraceW for %s returned %d", self.name, rc)
            raise self._failure(OPEN_FAILED_TEXT, rc or 1)
        thread = threading.Thread(target=self._run, args=(api, handle), name=CONSUMER_THREAD_NAME, daemon=True)
        with self._lock:
            self._trace_handle = handle
            self._thread = thread
        thread.start()

    # -- stopping ---------------------------------------------------------------------------------
    def _control(self, api: Any, handle: int, code: int) -> Optional[Dict[str, int]]:
        """``ControlTraceW`` by name on this session; the counters it wrote back, or None when it failed."""
        try:
            rc, stats = api.control_trace(handle, self.name, code)
        except Exception:  # noqa: BLE001
            log.debug("ControlTraceW raised for %s", self.name, exc_info=True)
            return None
        if int(rc) != ERROR_SUCCESS:
            log.debug("ControlTraceW(%d) for %s returned %d", code, self.name, int(rc))
            return None
        return stats if isinstance(stats, dict) else None

    def stop(self, timeout: float = 5.0) -> None:
        """Close the trace, join the consumer thread and stop the session.  Idempotent, and never raises.

        ``CloseTrace`` only asks the consumer to stop: on a busy adapter ``ProcessTrace`` keeps draining the buffers
        it already holds, so the join can time out and this still returns.  Nothing is freed underneath it - the seam
        holds every callback and structure ETW can still reach until that ``ProcessTrace`` returns - and the thread
        is a daemon, so a slow drain never holds a capture, a restart or a shutdown up."""
        with self._lock:
            api, thread, trace_handle, handle = self._api, self._thread, self._trace_handle, self._handle
            was_started, self._stopping = self._started, True
            self._thread = self._trace_handle = None
            self._started = False
        if api is None:
            return
        if trace_handle is not None:
            try:
                api.close_trace(trace_handle)
            except Exception:  # noqa: BLE001
                log.debug("CloseTrace raised", exc_info=True)
        if thread is not None and thread is not threading.current_thread():
            try:
                thread.join(max(0.0, float(timeout)))
            except Exception:  # noqa: BLE001
                log.debug("the consumer thread could not be joined", exc_info=True)
            if thread.is_alive():
                log.info("the capture consumer is still draining its buffers; it ends when ProcessTrace returns")
        if was_started:
            stats = self._control(api, handle, EVENT_TRACE_CONTROL_STOP)
            if stats is not None:
                with self._lock:
                    self._lost_events = max(self._lost_events, int(stats.get("events_lost") or 0))
        with self._lock:
            self._handle = 0                             # _stopping stays True: a session is stopped only once


def stop_stale_sessions(prefix: str = SESSION_PREFIX, *, api: Any = None) -> int:
    """Stop the capture sessions of *prefix* that a crash left behind; how many really stopped.

    Tries the bare prefix and ``<prefix>-1`` .. ``<prefix>-<MAX_STALE_NAMES - 1>``, the names TNT itself creates, so
    nothing has to be enumerated.  *api* is the injectable seam (None means the real advapi32 wrapper).  Never
    raises: a session that is not there (``ERROR_WMI_INSTANCE_NOT_FOUND``) and one that cannot be stopped both count
    0."""
    base = str(prefix or SESSION_PREFIX).strip()
    if not base:
        return 0
    if api is None:
        try:
            api = _Advapi()
        except Exception:  # noqa: BLE001
            log.debug("advapi32 could not be loaded to clear stale sessions", exc_info=True)
            return 0
    stopped = 0
    for name in [base] + [f"{base}-{n}" for n in range(1, MAX_STALE_NAMES)]:
        try:
            rc, _stats = api.control_trace(0, name, EVENT_TRACE_CONTROL_STOP)
        except Exception:  # noqa: BLE001
            log.debug("ControlTraceW raised while clearing %s", name, exc_info=True)
            continue
        if int(rc) == ERROR_SUCCESS:
            stopped += 1
        elif int(rc) != ERROR_WMI_INSTANCE_NOT_FOUND:
            log.debug("ControlTraceW(STOP) for %s returned %d", name, int(rc))
    if stopped:
        log.info("stopped %d capture session(s) left behind by an earlier run", stopped)
    return stopped


# --- the NDIS payload ------------------------------------------------------------------------------
def decode_ndis_frame(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The FRAME dict of an NDIS packet-capture EVENT dict, or None when it is not a packet event.

    The payload is MiniportIfIndex, LowerIfIndex and FragmentSize as little-endian ``uint32``, then the frame.  None
    of that is trusted: a payload with under :data:`HEADER_LEN` + 1 bytes, a FragmentSize of 0 or one over
    :data:`MAX_FRAME` gives None, and a FragmentSize longer than the payload is clamped to the bytes that were really
    there while ``origlen`` keeps the length the event claimed.  A ``ts`` that is not a number, or a whole number no
    float can hold, reads as 0.0: this returns None or a FRAME dict, and never raises."""
    if not isinstance(event, dict):
        return None
    provider = event.get("provider")
    if provider is not None and _normalized_guid(provider) != _normalized_guid(NDIS_PACKET_CAPTURE_GUID):
        return None
    event_id = event.get("event_id")
    if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id not in PACKET_EVENT_IDS:
        return None
    payload = event.get("data")
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        return None
    payload = bytes(payload)
    if len(payload) <= HEADER_LEN:                       # a header with no frame behind it is nothing to show
        return None
    if_index, lower_if, fragment_size = struct.unpack_from("<III", payload, 0)
    if fragment_size == 0 or fragment_size > MAX_FRAME:
        return None
    return {"ts": _frame_ts(event.get("ts")),
            "if_index": int(if_index), "lower_if": int(lower_if),
            "data": payload[HEADER_LEN:HEADER_LEN + fragment_size], "origlen": int(fragment_size)}
