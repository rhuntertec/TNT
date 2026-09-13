r"""Packet Monitor (``pktmon.exe``) plumbing for the switch-port lookup and the packet capture tool (ARCHITECTURE §3.24).

Windows 10 version 2004 (build 19041) and later ship Packet Monitor in ``%SystemRoot%\System32``.  TNT drives it through
its documented command line only:

* ``pktmon filter list``, ``pktmon filter add <name> <args...>`` and ``pktmon filter remove`` (filters are global to the
  driver: AND inside one filter, OR across filters);
* ``pktmon list --all`` (one section per adapter, read for the component id that matches the adapter's ifIndex);
* ``pktmon start --capture --comp <id> --pkt-size <n> -f <absolute .etl> -s <MB>``;
* ``pktmon counters --json`` (packets that passed the filters, per component);
* ``pktmon stop``;
* ``pktmon etl2pcap <etl> --out <pcapng> [--component-id <id>]``.

Never ``pktmon unload`` (it wipes every other user's counters and filters), and never a capture without ``-f``: Packet
Monitor would pre-size a 512 MB ``PktMon.etl`` in the working directory, which is System32 for the service.  ``-s`` is at
least :data:`MIN_FILE_MB`: a 16 MB file holds no packet events at all.

Conventions (as :func:`tnt.firewall.run_netsh`)
-----------------------------------------------
* The program is always ``%SystemRoot%\System32\PktMon.exe`` (:func:`pktmon_exe`), never PATH or a setting.
* :func:`run_pktmon` passes an argv list with ``CREATE_NO_WINDOW``, ``stdin=DEVNULL`` and a timeout, decodes the output
  in the OEM code page (``tnt.arp._decode_console``) and never raises: it returns ``(rc, output)``.
* Console text is localised, so nothing here reads a label: :func:`filters_present` counts lines, :func:`list_components`
  reads the ``pktmon list --all`` layout by its shape, :func:`counters_inbound` reads the JSON.  Exit codes are not
  documented either, so a failed ``stop`` counts as done when the session is gone and a conversion counts only when
  its output file exists.
* Every failure a user sees reads ``"Packet Monitor could not <start|stop|convert> (exit N)"``
  (:func:`failure_text`); Packet Monitor's own output is logged at DEBUG only.

Is it usable (:func:`capability`)
---------------------------------
``{"ok", "reason"}`` (:data:`CAPABILITY_KEYS`): ok only when the Windows build is at least :data:`PKTMON_MIN_BUILD`,
``PktMon.exe`` exists and its first :data:`EXE_READ_LIMIT` bytes contain every :data:`REQUIRED_EXE_STRINGS` entry
encoded UTF-16LE (the option table is not localised; an older Packet Monitor spells its options differently).  The
probe of the program file is cached per process.

Is somebody else capturing (:func:`session_running`)
----------------------------------------------------
``ControlTraceW(0, "PktMon", properties, EVENT_TRACE_CONTROL_QUERY)`` asks for the ETW logger session Packet Monitor
runs while it captures: 0 means it runs (True), ERROR_WMI_INSTANCE_NOT_FOUND (4201) that it does not (False), anything
else is unknown (None).  The properties buffer is ``sizeof(EVENT_TRACE_PROPERTIES)`` (120 bytes on x64) plus 2048 bytes
for the two names, with ``Wnode.BufferSize`` set, ``LoggerNameOffset`` right after the structure and
``LogFileNameOffset`` 1024 bytes further.

One capture at a time (:data:`LOCK`)
------------------------------------
Packet Monitor runs one session for the whole PC, so the switch-port lookup and the packet capture share
:class:`PktmonLock`.  ``acquire(holder)`` raises :class:`PktmonBusy` with the holder's text (:data:`LOCK_TEXTS`).
:class:`PktmonSession` refuses to start when a session is already running (:data:`FOREIGN_SESSION_TEXT`) or another
program set filters (:data:`FOREIGN_FILTERS_TEXT`), so TNT does not stop or clear a capture that was already running.
One race remains: a capture another program starts in the same second, between that check and ``pktmon start``, makes
TNT's start fail, and the clean-up after it (which stops a session that runs or might, :meth:`PktmonSession.cleanup`)
can end that capture.

Crash marker
------------
Before a session starts, :func:`write_marker` puts :data:`MARKER_NAME` (JSON: ``purpose``, ``files``, ``started_ts``)
into the captures folder; :func:`clear_marker` removes it after the clean-up.  After a crash, :func:`recover` (run on a
helper thread when the service starts) holds :data:`LOCK` as ``"capture"``, runs ``pktmon stop`` unless no session runs
and then always ``pktmon filter remove`` (10 s each), deletes the files the marker lists when they resolve inside the
folder, and clears the marker.

Test seam
---------
:data:`_subprocess_run` is the ``subprocess.run`` alias the default runner looks up at call time; tests/conftest.py makes
it fail for the whole test session, so no test can run the real Packet Monitor.  Every function that runs a command
takes a ``runner`` (a ``subprocess.run`` stand-in receiving the same keyword arguments).

Contract gaps filled here
-------------------------
* :func:`pktmon_exe` always names the System32 file, even when it is missing (the run then fails with 9009, as
  ``run_netsh`` reports a missing program); it never falls back to a bare name a PATH search could resolve.
* ``etl2pcap`` gets :data:`CONVERT_TIMEOUT_S` (a 1 GB capture takes a while); every other command the 30 s default.
* A ``PktMon.exe`` that exists but cannot be read counts as missing and is not cached.
* :func:`counters_inbound` accepts the JSON after any text, skips counter entries without an ``Inbound`` packet count,
  and is None only when no group carries a ``Components`` list; a component that is not listed counts 0.
* :func:`list_components` needs a non-empty name after the colon of a section line; an unindented line of any other
  shape (a table header) ends the current section.
* :class:`PktmonSession` is single-use.  A failed ``filter add`` fails the start like a failed ``start`` (clean-up,
  then the start text); the clean-up runs ``filter remove`` only when no filter was set before the start, or when one
  of TNT's filters was added (or timed out), so an inconclusive ``filter list`` never costs another program its
  filters.  For the same reason ``stop()`` and ``cleanup()`` skip ``filter remove`` for a session that added no
  filter (a capture with no criteria).  ``stop()`` raises the stop text only when ``pktmon stop`` failed and the
  session still (or maybe) runs; a failed ``filter remove`` is logged and retried by ``cleanup()``.  ``convert()`` deletes an old output
  file first, so an earlier file can never pass for a conversion.  ``active`` tells whether TNT's session may still
  run; ``last_error`` keeps the latest failure text.
* :func:`recover` skips (False) when the lock is held, and it clears an unreadable marker as well.

Logging: INFO carries counts only; command lines, Packet Monitor's output and file names are DEBUG.
"""
from __future__ import annotations

import ctypes
import importlib
import json
import logging
import os
import re
import subprocess
import sys
import threading
from ctypes import Structure, c_long, c_ubyte, c_uint64, c_ulong, c_void_p, c_wchar_p
from pathlib import PureWindowsPath
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

log = logging.getLogger(__name__)

__all__ = [
    "PKTMON_MIN_BUILD", "MIN_FILE_MB", "REQUIRED_EXE_STRINGS", "EXE_READ_LIMIT", "PKTMON_TIMEOUT_S",
    "CONVERT_TIMEOUT_S", "RECOVER_TIMEOUT_S", "CAPABILITY_KEYS", "COMPONENT_KEYS", "MARKER_NAME", "HOLDERS",
    "OLD_WINDOWS_REASON", "MISSING_REASON", "TOO_OLD_REASON", "FOREIGN_SESSION_TEXT", "FOREIGN_FILTERS_TEXT",
    "LOCK_TEXTS", "FOLDER_NOT_SECURED_TEXT", "NOT_LISTED_TEXT", "PktmonBusy", "PktmonUnavailable", "pktmon_exe",
    "run_pktmon", "failure_text", "capability", "session_running", "filters_present", "list_components",
    "parse_components", "component_for", "counters_inbound", "PktmonLock", "LOCK", "PktmonSession", "write_marker",
    "clear_marker", "recover",
]

PKTMON_MIN_BUILD = 19041                  # Windows 10 version 2004: real-time mode and pcapng conversion
MIN_FILE_MB = 64                          # -s 16 gives an ETL with no packet events; 32 and up work
REQUIRED_EXE_STRINGS = ("etl2pcap", "--capture", "--pkt-size", "--comp")
EXE_READ_LIMIT = 4 * 1024 * 1024          # the capability probe reads at most this much of PktMon.exe
PKTMON_TIMEOUT_S = 30.0
CONVERT_TIMEOUT_S = 600.0
RECOVER_TIMEOUT_S = 10.0
CAPABILITY_KEYS = ("ok", "reason")
COMPONENT_KEYS = ("id", "if_index", "name")
MARKER_NAME = "TNT-pktmon-session.json"
HOLDERS = ("switchport", "capture")

OLD_WINDOWS_REASON = "Needs Windows 10 version 2004 (build 19041) or later"
MISSING_REASON = "Packet Monitor (pktmon.exe) is missing from this PC"
TOO_OLD_REASON = "Packet Monitor on this PC is too old for this: update Windows"
FOREIGN_SESSION_TEXT = "Packet Monitor is already capturing for another program"
FOREIGN_FILTERS_TEXT = "Packet Monitor has filters set by another program"
LOCK_TEXTS: Dict[str, str] = {
    "switchport": "TNT is finding the switch port: try again when it finishes",
    "capture": "A packet capture is running: stop it first",
}
#: Shared by the switch-port lookup and the packet capture (both fail closed on these).
FOLDER_NOT_SECURED_TEXT = "The capture folder could not be secured"
NOT_LISTED_TEXT = "Packet Monitor does not list this adapter"

# -- ETW (evntrace.h / winerror.h) --------------------------------------------------------------
PKTMON_LOGGER_NAME = "PktMon"
EVENT_TRACE_CONTROL_QUERY = 0
ERROR_SUCCESS = 0
ERROR_WMI_INSTANCE_NOT_FOUND = 4201
TRACE_NAMES_BYTES = 2048                  # room for the logger name and the log file name after the structure

_CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)
TIMEOUT_RC = 1460                         # run_pktmon's exit code for a command that timed out (ERROR_TIMEOUT)

#: The ``subprocess.run`` alias :func:`run_pktmon` calls when no runner is given (tests/conftest.py replaces it).
_subprocess_run = subprocess.run

PathLike = Union[str, "os.PathLike[str]"]


class PktmonBusy(RuntimeError):
    """Packet Monitor is in use: by TNT's other tool (:data:`LOCK_TEXTS`) or by another program (HTTP 409 conflict)."""


class PktmonUnavailable(RuntimeError):
    """Packet Monitor cannot be used for this, or it failed (HTTP 409 unavailable)."""


# --- native structures (x64 layout per wmistr.h / evntrace.h) -----------------------------------
class WNODE_HEADER(Structure):
    _fields_ = [
        ("BufferSize", c_ulong),
        ("ProviderId", c_ulong),
        ("HistoricalContext", c_uint64),
        ("TimeStamp", c_uint64),          # union with KernelHandle
        ("Guid", c_ubyte * 16),
        ("ClientContext", c_ulong),
        ("Flags", c_ulong),
    ]                                     # sizeof == 48


class EVENT_TRACE_PROPERTIES(Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", c_ulong),
        ("MinimumBuffers", c_ulong),
        ("MaximumBuffers", c_ulong),
        ("MaximumFileSize", c_ulong),
        ("LogFileMode", c_ulong),
        ("FlushTimer", c_ulong),
        ("EnableFlags", c_ulong),
        ("AgeLimit", c_long),             # union with FlushThreshold
        ("NumberOfBuffers", c_ulong),
        ("FreeBuffers", c_ulong),
        ("EventsLost", c_ulong),
        ("BuffersWritten", c_ulong),
        ("LogBuffersLost", c_ulong),
        ("RealTimeBuffersLost", c_ulong),
        ("LoggerThreadId", c_void_p),     # HANDLE
        ("LogFileNameOffset", c_ulong),
        ("LoggerNameOffset", c_ulong),
    ]                                     # sizeof == 120 on x64


_dll_lock = threading.Lock()
_advapi32: Any = None
_probe_lock = threading.Lock()
_probe_cache: Dict[str, bool] = {}        # normalised PktMon.exe path -> it has every required option string


def _advapi() -> Any:
    """``advapi32`` loaded lazily with ``ControlTraceW`` declared."""
    global _advapi32
    with _dll_lock:
        if _advapi32 is None:
            a = ctypes.WinDLL("advapi32", use_last_error=True)
            a.ControlTraceW.argtypes = [c_uint64, c_wchar_p, c_void_p, c_ulong]
            a.ControlTraceW.restype = c_ulong
            _advapi32 = a
        return _advapi32


def _short(text: Any, limit: int = 300) -> str:
    s = str(text).strip().replace("\r", " ").replace("\n", " ")
    return s if len(s) <= limit else s[:limit] + "..."


# --- running pktmon ---------------------------------------------------------------------------
def pktmon_exe() -> str:
    """``PktMon.exe`` in ``%SystemRoot%\\System32`` (never PATH or a setting)."""
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return os.path.join(root, "System32", "PktMon.exe")


def _decode_console(raw: Any) -> str:
    """Packet Monitor writes the OEM code page like arp and netsh; reuse the tolerant decoder (lazily imported so a
    fake ``tnt.arp`` in ``sys.modules`` is honoured)."""
    if isinstance(raw, str):
        return raw
    if not raw:
        return ""
    try:
        arp = importlib.import_module("tnt.arp")
        return arp._decode_console(bytes(raw))
    except Exception:  # noqa: BLE001
        return bytes(raw).decode("utf-8", errors="replace")


def run_pktmon(args: Sequence[Any], runner: Optional[Callable[..., Any]] = None,
               timeout_s: float = PKTMON_TIMEOUT_S) -> Tuple[int, str]:
    """Run ``pktmon <args>`` hidden; ``(returncode, combined output)``.  Never raises: a missing program is 9009, a
    timeout 1460 and any other launch failure 1, each with the reason as the output."""
    argv = [pktmon_exe(), *[str(a) for a in args]]
    run = runner if runner is not None else _subprocess_run      # looked up now: the conftest guard must see it
    log.debug("running %s", subprocess.list2cmdline(argv))
    try:
        proc = run(argv, capture_output=True, timeout=timeout_s, check=False, stdin=subprocess.DEVNULL,
                   creationflags=_CREATE_NO_WINDOW)
    except FileNotFoundError:
        return 9009, "PktMon.exe was not found"
    except subprocess.TimeoutExpired:
        return TIMEOUT_RC, f"pktmon timed out after {timeout_s:.0f} s"
    except OSError as exc:
        return 1, f"could not run pktmon: {exc}"
    except Exception as exc:  # noqa: BLE001 - a broken runner seam must not escape
        return 1, f"pktmon failed: {exc}"
    out = _decode_console(getattr(proc, "stdout", b"")) + _decode_console(getattr(proc, "stderr", b""))
    try:
        rc = int(getattr(proc, "returncode", 1))
    except (TypeError, ValueError):
        rc = 1
    return rc, out.strip()


def failure_text(verb: str, rc: int) -> str:
    """``"Packet Monitor could not <verb> (exit N)"``: the only failure text a user sees."""
    return f"Packet Monitor could not {verb} (exit {rc})"


# --- capability ---------------------------------------------------------------------------------
def _windows_build() -> int:
    """``CurrentBuild`` from the registry (``tnt.diagnostics``), 0 when unknown or not Windows."""
    try:
        info = importlib.import_module("tnt.diagnostics")._windows_version()
        return int(info.get("build") or 0)
    except Exception:  # noqa: BLE001
        log.debug("Windows build lookup failed", exc_info=True)
        return 0


def _read_exe_head(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(EXE_READ_LIMIT)


def _has_option_strings(data: bytes) -> bool:
    head = bytes(data[:EXE_READ_LIMIT])
    return all(text.encode("utf-16-le") in head for text in REQUIRED_EXE_STRINGS)


def capability(*, build_fn: Optional[Callable[[], Any]] = None, exe_path: Optional[PathLike] = None,
               read_fn: Optional[Callable[[str], bytes]] = None) -> Dict[str, Any]:
    """``{"ok", "reason"}``: can this PC run the switch-port lookup and the packet capture?

    *build_fn* returns the Windows build (default: the registry), *exe_path* names the program (default
    :func:`pktmon_exe`) and *read_fn(path)* returns its first bytes (default: at most :data:`EXE_READ_LIMIT` bytes,
    cached per process).  Never raises."""
    try:
        build = int((build_fn or _windows_build)() or 0)
    except Exception:  # noqa: BLE001
        build = 0
    if build < PKTMON_MIN_BUILD:
        return {"ok": False, "reason": OLD_WINDOWS_REASON}
    exe = os.fspath(exe_path) if exe_path is not None else pktmon_exe()
    if not os.path.isfile(exe):
        return {"ok": False, "reason": MISSING_REASON}
    key = os.path.normcase(os.path.abspath(exe))
    found: Optional[bool] = None
    if read_fn is None:
        with _probe_lock:
            found = _probe_cache.get(key)
    if found is None:
        try:
            found = _has_option_strings((read_fn or _read_exe_head)(exe))
        except Exception:  # noqa: BLE001 - unreadable: not usable, and asked again next time
            log.debug("could not read %s", exe, exc_info=True)
            return {"ok": False, "reason": MISSING_REASON}
        if read_fn is None:
            with _probe_lock:
                _probe_cache[key] = found
    if not found:
        return {"ok": False, "reason": TOO_OLD_REASON}
    return {"ok": True, "reason": None}


# --- session and filter state ---------------------------------------------------------------------
def session_running() -> Optional[bool]:
    """Is Packet Monitor's ETW logger session running?  True / False, or None when that cannot be told (not Windows,
    access denied, any other ``ControlTraceW`` answer).  Never raises; runs no program."""
    if sys.platform != "win32":
        return None
    try:
        advapi = _advapi()
        size = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        buf = (ctypes.c_ubyte * (size + TRACE_NAMES_BYTES))()
        props = EVENT_TRACE_PROPERTIES.from_buffer(buf)
        props.Wnode.BufferSize = ctypes.sizeof(buf)
        props.LoggerNameOffset = size
        props.LogFileNameOffset = size + TRACE_NAMES_BYTES // 2
        rc = int(advapi.ControlTraceW(0, PKTMON_LOGGER_NAME, ctypes.addressof(buf), EVENT_TRACE_CONTROL_QUERY))
    except Exception:  # noqa: BLE001
        log.debug("ControlTraceW query failed", exc_info=True)
        return None
    if rc == ERROR_SUCCESS:
        return True
    if rc == ERROR_WMI_INSTANCE_NOT_FOUND:
        return False
    log.debug("ControlTraceW query for the Packet Monitor session returned %d", rc)
    return None


def filters_present(runner: Optional[Callable[..., Any]] = None) -> Optional[bool]:
    """Does Packet Monitor hold any filter?  ``pktmon filter list`` prints exactly two non-empty lines (a heading and
    "none", localised) when it holds none: more lines is True, a failed command None."""
    rc, out = run_pktmon(["filter", "list"], runner)
    if rc != 0:
        log.debug("pktmon filter list exited %d: %s", rc, _short(out))
        return None
    return len([line for line in out.splitlines() if line.strip()]) > 2


# --- components -------------------------------------------------------------------------------
_SECTION_RE = re.compile(r"^(\S[^:]*):\s*(\S.*?)\s*$")
_NUMBER_RE = re.compile(r"^\s+[^:]+:\s*(\d+)\s*$", re.ASCII)


def parse_components(output: str) -> List[Dict[str, Any]]:
    """``[{"id", "if_index", "name"}]`` from ``pktmon list --all`` output, read by shape (the labels are localised).

    An unindented ``<label>: <name>`` line opens a section; inside it, the first indented ``<label>: <digits>`` line is
    the component id and the second the adapter's ifIndex.  Sections without two such lines are skipped."""
    components: List[Dict[str, Any]] = []
    name: Optional[str] = None
    numbers: List[int] = []

    def close() -> None:
        if name is not None and len(numbers) >= 2:
            components.append({"id": numbers[0], "if_index": numbers[1], "name": name})

    for line in str(output or "").splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            close()
            match = _SECTION_RE.match(line)
            name, numbers = (match.group(2), []) if match else (None, [])
            continue
        if name is not None and len(numbers) < 2:
            match = _NUMBER_RE.match(line)
            if match:
                numbers.append(int(match.group(1)))
    close()
    return components


def list_components(runner: Optional[Callable[..., Any]] = None) -> List[Dict[str, Any]]:
    """The adapters Packet Monitor can capture on (:func:`parse_components`); ``[]`` when the command fails.  Component
    ids change across reboots and driver restarts, so this is read right before every start."""
    rc, out = run_pktmon(["list", "--all"], runner)
    if rc != 0:
        log.debug("pktmon list --all exited %d: %s", rc, _short(out))
        return []
    return parse_components(out)


def _field(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


def component_for(adapter: Any, components: Iterable[Dict[str, Any]]) -> Optional[int]:
    """The component id whose ifIndex is the adapter's ``index`` (an Adapter or a dict), else None.  By ifIndex only:
    names are localised and a virtual switch can clone a physical adapter's MAC."""
    index = _field(adapter, "index")
    if isinstance(index, bool) or not isinstance(index, int) or index <= 0:
        return None
    for comp in components or []:
        if isinstance(comp, dict) and comp.get("if_index") == index and isinstance(comp.get("id"), int):
            return int(comp["id"])
    return None


def _count(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def counters_inbound(output: Any, comp_id: int) -> Optional[int]:
    """Inbound packets of component *comp_id* in ``pktmon counters --json`` output: the sum of ``Inbound.Packets`` over
    every counter of every listed component with ``Id == comp_id`` (0 when it is not listed), or None when the output
    is not that JSON.  Text before the JSON is skipped."""
    text = _decode_console(output)
    decoder = json.JSONDecoder()
    groups: Optional[List[List[Any]]] = None
    pos = text.find("[")
    while pos >= 0 and groups is None:
        try:
            data, _end = decoder.raw_decode(text, pos)
        except ValueError:
            data = None
        if isinstance(data, list):
            # a bracketed word in the text before the JSON can parse too: only groups with components count
            groups = [g["Components"] for g in data if isinstance(g, dict) and isinstance(g.get("Components"), list)]
            groups = groups or None
        pos = text.find("[", pos + 1)
    if groups is None:
        return None
    total = 0
    for comps in groups:
        for comp in comps:
            if not isinstance(comp, dict) or _count(comp.get("Id")) != comp_id:
                continue
            for counter in comp.get("Counters") or []:
                inbound = counter.get("Inbound") if isinstance(counter, dict) else None
                packets = _count(inbound.get("Packets")) if isinstance(inbound, dict) else None
                if packets is not None:
                    total += packets
    return total


# --- the shared lock ------------------------------------------------------------------------------
class PktmonLock:
    """One Packet Monitor user inside TNT at a time; the holder names who (``"switchport"`` or ``"capture"``)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._holder: Optional[str] = None

    def acquire(self, holder: str) -> None:
        """Take the lock for *holder*, or raise :class:`PktmonBusy` with the current holder's text."""
        if holder not in HOLDERS:
            raise ValueError(f"unknown Packet Monitor user {holder!r}")
        with self._lock:
            if self._holder is not None:
                raise PktmonBusy(LOCK_TEXTS[self._holder])
            self._holder = holder

    def release(self) -> None:
        with self._lock:
            self._holder = None

    def holder(self) -> Optional[str]:
        with self._lock:
            return self._holder


LOCK = PktmonLock()


# --- one capture session ------------------------------------------------------------------------------
def _is_absolute(path: str) -> bool:
    try:
        return PureWindowsPath(path).is_absolute()
    except (TypeError, ValueError):
        return False


def _whole(value: Any, minimum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


class PktmonSession:
    """One Packet Monitor capture: filters, start, counters, stop, conversion and clean-up.  Single-use."""

    def __init__(self, *, comp_id: int, filters: Iterable[Sequence[Any]], etl_path: PathLike, size_mb: int,
                 pkt_size: int, runner: Optional[Callable[..., Any]] = None,
                 session_running_fn: Optional[Callable[[], Optional[bool]]] = None,
                 filters_present_fn: Optional[Callable[[], Optional[bool]]] = None) -> None:
        self.comp_id = comp_id
        self.filters: List[List[str]] = [[str(part) for part in f] for f in (filters or [])]
        self.etl_path = os.fspath(etl_path)
        self.size_mb = size_mb
        self.pkt_size = pkt_size
        self.last_error: Optional[str] = None
        self._runner = runner
        self._session_running_fn = session_running_fn
        self._filters_present_fn = filters_present_fn
        self._start_attempted = False
        self._stopped = False
        self._filters_added = False

    @property
    def active(self) -> bool:
        """True from the moment ``pktmon start`` was run until the session is known to be stopped."""
        return self._start_attempted and not self._stopped

    # -- helpers -------------------------------------------------------------------------------------
    def _run(self, args: Sequence[Any], timeout_s: float = PKTMON_TIMEOUT_S) -> Tuple[int, str]:
        return run_pktmon(args, self._runner, timeout_s)

    def _session_running(self) -> Optional[bool]:
        try:
            fn = self._session_running_fn or session_running
            return fn()
        except Exception:  # noqa: BLE001
            log.debug("session check failed", exc_info=True)
            return None

    def _filters_present(self) -> Optional[bool]:
        try:
            if self._filters_present_fn is not None:
                return self._filters_present_fn()
            return filters_present(self._runner)
        except Exception:  # noqa: BLE001
            log.debug("filter check failed", exc_info=True)
            return None

    def _fail(self, verb: str, rc: int, out: str) -> PktmonUnavailable:
        self.last_error = failure_text(verb, rc)
        log.debug("pktmon %s exited %d: %s", verb, rc, _short(out))
        return PktmonUnavailable(self.last_error)

    def _remove_filters(self) -> bool:
        if not self._filters_added:
            return True
        rc, out = self._run(["filter", "remove"])
        if rc != 0:
            log.warning("Packet Monitor could not remove TNT's filters (exit %d)", rc)
            log.debug("pktmon filter remove output: %s", _short(out))
            return False
        self._filters_added = False
        return True

    # -- the session -----------------------------------------------------------------------------------
    def start(self) -> None:
        """Validate, refuse a busy Packet Monitor, add the filters and start the capture.

        ``ValueError`` unless ``etl_path`` is absolute and ``size_mb >= MIN_FILE_MB``; :class:`PktmonBusy` when another
        session runs or another program set filters; :class:`PktmonUnavailable` ("could not start (exit N)") after
        a clean-up when a command fails."""
        if not _is_absolute(self.etl_path):
            raise ValueError("etl_path must be an absolute path")
        if not _whole(self.size_mb, MIN_FILE_MB):
            raise ValueError(f"size_mb must be a whole number of at least {MIN_FILE_MB}")
        if not _whole(self.pkt_size, 0):
            raise ValueError("pkt_size must be a whole number of at least 0")
        if not _whole(self.comp_id, 0):
            raise ValueError("comp_id must be a whole number")
        if self._start_attempted or self._filters_added:
            raise RuntimeError("this Packet Monitor session was already started")
        if self._session_running() is True:
            raise PktmonBusy(FOREIGN_SESSION_TEXT)
        present = self._filters_present()
        if present is True:
            raise PktmonBusy(FOREIGN_FILTERS_TEXT)
        for spec in self.filters:
            if present is False:
                self._filters_added = True     # none were set before: `filter remove` can only remove TNT's
            rc, out = self._run(["filter", "add", *spec])
            if rc in (0, TIMEOUT_RC):
                self._filters_added = True     # added (or maybe, after a timeout): a half-added set is removed
            if rc != 0:
                error = self._fail("start", rc, out)
                self.cleanup()
                raise error
        self._start_attempted = True
        rc, out = self._run(["start", "--capture", "--comp", self.comp_id, "--pkt-size", self.pkt_size,
                             "-f", self.etl_path, "-s", self.size_mb])
        if rc != 0:
            error = self._fail("start", rc, out)
            self.cleanup()
            raise error

    def inbound(self) -> Optional[int]:
        """Inbound packets that passed the filters on this component so far, or None when the counters cannot be
        read."""
        rc, out = self._run(["counters", "--json"])
        if rc != 0:
            log.debug("pktmon counters exited %d: %s", rc, _short(out))
            return None
        return counters_inbound(out, self.comp_id)

    def stop(self) -> None:
        """``pktmon stop``, then ``pktmon filter remove``.  :class:`PktmonUnavailable` ("could not stop (exit N)")
        when the stop failed and the session is not known to be gone."""
        error: Optional[PktmonUnavailable] = None
        if self._start_attempted and not self._stopped:
            rc, out = self._run(["stop"])
            if rc == 0 or self._session_running() is False:
                self._stopped = True
            else:
                error = self._fail("stop", rc, out)
        self._remove_filters()
        if error is not None:
            raise error

    def convert(self, pcapng_path: PathLike, component_id: Optional[int] = None) -> bool:
        """``pktmon etl2pcap <etl> --out <pcapng> [--component-id <id>]``; True only when it exited 0 and the output
        file exists (``last_error`` holds the text otherwise)."""
        out_path = os.fspath(pcapng_path)
        try:
            os.remove(out_path)
        except FileNotFoundError:
            pass
        except OSError:
            log.debug("could not remove an old conversion output", exc_info=True)
            self.last_error = failure_text("convert", 0)
            return False
        args: List[Any] = ["etl2pcap", self.etl_path, "--out", out_path]
        if component_id is not None:
            args += ["--component-id", component_id]
        rc, out = self._run(args, CONVERT_TIMEOUT_S)
        if rc != 0 or not os.path.isfile(out_path):
            self._fail("convert", rc, out)
            return False
        return True

    def cleanup(self) -> None:
        """Stop the session when it runs (or might) and remove the filters this session added.  Never ``pktmon
        unload``; never raises."""
        try:
            if self._start_attempted and not self._stopped:
                if self._session_running() is False:
                    self._stopped = True
                else:
                    rc, out = self._run(["stop"])
                    if rc == 0:
                        self._stopped = True
                    else:
                        log.warning("Packet Monitor could not stop TNT's session (exit %d)", rc)
                        log.debug("pktmon stop output: %s", _short(out))
            self._remove_filters()
        except Exception:  # noqa: BLE001
            log.exception("cleaning up the Packet Monitor session failed")


# --- crash marker -------------------------------------------------------------------------------
def _marker_path(folder: PathLike) -> str:
    return os.path.join(os.fspath(folder), MARKER_NAME)


def write_marker(dir: PathLike, info: Dict[str, Any]) -> None:  # noqa: A002 - the contract's name
    """Record a session about to start (``purpose``, ``files`` inside *dir*, ``started_ts``).  Raises ``OSError``."""
    path = _marker_path(dir)
    part = path + ".part"
    with open(part, "w", encoding="utf-8") as fh:
        json.dump(dict(info), fh, sort_keys=True)
    os.replace(part, path)


def clear_marker(dir: PathLike) -> None:  # noqa: A002 - the contract's name
    """Remove the marker (and a half-written one).  Never raises."""
    path = _marker_path(dir)
    for target in (path, path + ".part"):
        try:
            os.remove(target)
        except FileNotFoundError:
            pass
        except OSError:
            log.warning("could not remove the Packet Monitor session marker")
            log.debug("removing %s failed", target, exc_info=True)


def _inside(folder: str, name: Any) -> Optional[str]:
    """The real path of *name* when it resolves to something inside *folder* (never *folder* itself), else None."""
    if not isinstance(name, str) or not name.strip():
        return None
    try:
        root = os.path.normcase(os.path.realpath(folder))
        path = os.path.realpath(os.path.join(folder, name))
        if os.path.commonpath([root, os.path.normcase(path)]) != root or os.path.normcase(path) == root:
            return None
    except (OSError, ValueError):
        return None
    return path


def recover(dir: PathLike, *, runner: Optional[Callable[..., Any]] = None,  # noqa: A002 - the contract's name
            session_running_fn: Optional[Callable[[], Optional[bool]]] = None) -> bool:
    """Clean up after a session a crash left behind (see the module docstring).  True when a marker was found and
    handled; False for a missing folder or marker, or while TNT is using Packet Monitor.  Never raises."""
    directory = os.fspath(dir)
    marker = _marker_path(directory)
    if not os.path.isdir(directory) or not os.path.isfile(marker):
        return False
    try:
        LOCK.acquire("capture")
    except PktmonBusy:
        log.info("Packet Monitor clean-up skipped: TNT is using Packet Monitor")
        return False
    try:
        info: Dict[str, Any] = {}
        try:
            with open(marker, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            info = loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            log.debug("the Packet Monitor session marker could not be read", exc_info=True)
        try:
            running = (session_running_fn or session_running)()
        except Exception:  # noqa: BLE001
            running = None
        if running is not False:
            rc, out = run_pktmon(["stop"], runner, RECOVER_TIMEOUT_S)
            if rc != 0:
                log.debug("pktmon stop exited %d: %s", rc, _short(out))
        rc, out = run_pktmon(["filter", "remove"], runner, RECOVER_TIMEOUT_S)
        if rc != 0:
            log.debug("pktmon filter remove exited %d: %s", rc, _short(out))
        deleted = 0
        files = info.get("files")
        for name in files if isinstance(files, list) else []:
            path = _inside(directory, name)
            if path is None or not os.path.isfile(path):
                continue
            try:
                os.remove(path)
                deleted += 1
            except OSError:
                log.debug("could not delete %s", path, exc_info=True)
        clear_marker(directory)
        log.info("Packet Monitor clean-up after an interrupted session: %d file(s) deleted", deleted)
        return True
    except Exception:  # noqa: BLE001
        log.exception("Packet Monitor clean-up failed")
        return False
    finally:
        LOCK.release()
