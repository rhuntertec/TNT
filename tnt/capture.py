r"""Packet capture for the Tools page: a timed Packet Monitor capture of one adapter, saved as pcapng (ARCHITECTURE §3.24).

:class:`CaptureManager` is the engine component behind ``/api/tools/capture`` (admin-gated routes).  One capture runs at a
time, and never together with the switch-port lookup (:data:`tnt.pktmon.LOCK`).  Files live only in the captures folder
(:func:`tnt.paths.captures_dir`), which every start secures again with ``tnt.winacl.CAPTURES_SDDL`` (SYSTEM and
Administrators only; the start fails closed when that does not work).

Start (:meth:`CaptureManager.start`)
------------------------------------
The request is validated first (``ValueError``, texts below), then: Packet Monitor capability (:class:`PktmonUnavailable`
with its reason); the shared lock (:class:`PktmonBusy`); the job appears as ``starting``; the folder is secured;
retention runs; free disk space must be at least ``size_mb * 2 MiB + 1 GiB``; the adapter's Packet Monitor component;
the filters; the crash marker; ``pktmon start`` with ``--pkt-size 0`` (full packets) or ``128``, ``-s size_mb`` and
``TNT-capture-<YYYYmmdd-HHMMSS>.etl`` (local time); the job turns ``capturing`` and the worker thread ``tnt-capture``
takes over.  A failure on the way ends the job in ``error`` (partial files deleted, lock released) and is raised.

Filters (one AND-combined filter, :func:`capture_filters`): ``TNT-CAP`` with ``-i <host>``, ``-p <port>`` and
``-t TCP|UDP`` as given; ICMP is ``-t ICMP`` with an IPv4 host and ``-t ICMPv6`` with an IPv6 host; ICMP without a host
adds two filters, ``TNT-CAP4 -t ICMP`` and ``TNT-CAP6 -t ICMPv6`` (Packet Monitor ORs filters); no criteria, no filter.

=============  ====================================  ================================================
Field          Rule                                  ``ValueError`` text
=============  ====================================  ================================================
seconds        whole number, 5..1800                 seconds must be a whole number from 5 to 1800
size_mb        one of :data:`CAPTURE_SIZES_MB`       size_mb must be one of 64, 128, 256, 512 or 1024
host           IPv4 or IPv6 literal, or null         host must be an IP address
port           whole number 1..65535, or null        port must be a whole number from 1 to 65535
protocol       tcp, udp, icmp or null                protocol must be tcp, udp, icmp or null
port + icmp    not allowed                           port cannot be combined with protocol icmp
adapter        one of :meth:`CaptureManager.adapters` adapter '<x>' is not up
full_packets   true or false                         full_packets must be true or false
=============  ====================================  ================================================

Running and finishing
---------------------
While capturing, every ``tick_s`` the job gets ``elapsed_s`` and ``bytes`` (the ETL size) and ``capture.state``
``{"capture": JOB}`` is published.  At ``seconds``, or when :meth:`CaptureManager.stop` asks (the capture is KEPT):
``converting``; ``pktmon stop``; ``etl2pcap`` into ``<name>.raw.pcapng`` for the one component; a Wi-Fi adapter
(if_type 71) has its 802.11 data frames rewritten as Ethernet (:func:`tnt.pcapng.rewrite_dot11_to_ethernet`, with the
note :func:`wifi_note` when frames were left out), anything else is renamed; the packets are counted into the cache;
the ETL is deleted and the marker cleared; ``done`` with ``file``.  ``cancelled`` (partial files deleted) only when
``stop()`` arrives while the job is still ``starting``, or :meth:`CaptureManager.close` runs at engine stop.

Files and retention
-------------------
:meth:`CaptureManager.files` lists the names matching :data:`FILE_RE`, newest first, with ``packets`` from a cache keyed
by ``(name, size, mtime)`` (None until counted, and for a file that is not valid pcapng).  :meth:`CaptureManager.recover`
(engine start, helper thread) cleans up after a crash (:func:`tnt.pktmon.recover`) and starts ``tnt-capture-count``, which
counts the files not in the cache.  :meth:`CaptureManager.open_file` and :meth:`CaptureManager.delete_file` take a
name that matches :data:`FILE_RE` exactly and resolves to a regular file (not a reparse point) directly inside the
folder, else :class:`CaptureFileMissing`; deleting a file a download holds open is :class:`CaptureFileBusy`.
:meth:`CaptureManager.enforce_retention` keeps at most :data:`MAX_FILES` files, :data:`MAX_TOTAL_BYTES` in total and
nothing older than :data:`MAX_AGE_S`, skipping a file it cannot delete (tried again next time); it runs before each
capture and from the engine's daily retention.

Shapes (keys in this order: :data:`CAPTURE_JOB_KEYS`, :data:`CAPTURE_FILE_KEYS`, :data:`CAPTURE_STATUS_KEYS`,
:data:`CAPTURE_ADAPTER_KEYS`)::

    JOB     = {"id": int, "state": "starting"|"capturing"|"converting"|"done"|"error"|"cancelled",
               "adapter": ADAPTER, "filters": {"host", "port", "protocol"}, "full_packets", "seconds", "size_mb",
               "started_ts", "elapsed_s", "bytes": int|None, "file": str|None, "error": str|None,
               "note": str|None, "ts"}
    FILE    = {"name", "size", "created_ts", "packets": int|None}
    STATUS  = {"available", "reason", "adapters": [ADAPTER], "capture": JOB|None, "files": [FILE]}
    ADAPTER = {"name", "index", "mac", "type_name", "wifi": bool}     # up, not loopback, physical

Injectable knobs (keyword-only; None means the ``tnt.netinfo`` / ``tnt.pktmon`` / ``tnt.paths`` / ``tnt.winacl`` /
``shutil`` default): ``adapters_fn``, ``runner``, ``clock``, ``monotonic``, ``wait(seconds) -> bool`` (default an Event
wait that ``stop()`` and ``close()`` wake), ``session_running_fn``, ``filters_present_fn``, ``components_fn``,
``capability_fn``, ``captures_dir_fn``, ``acl``, ``disk_free_fn(path) -> bytes``, and ``tick_s``, ``min_seconds``,
``max_seconds``.  The engine uses the defaults.

Contract gaps filled here:

* ``id`` counts up from 1 per service run.  The job's ``adapter`` is the ADAPTER row it was started on.  ``started_ts``
  is when the job appeared; ``elapsed_s`` counts from ``capturing`` and stays the capture's real length after it;
  ``bytes`` is the saved file's size once ``done``.
* A float with no fraction counts as a whole number; an empty host or protocol counts as null; a host with a zone or a
  prefix is refused.  A crash marker that cannot be written fails the start like an unsecured folder.
* A name already taken in the folder (a clock set back) moves the file name on by a second.
* ``stop()`` while capturing waits up to :data:`STOP_WAIT_S` for the worker to take the job to ``converting``.  Once the
  final file exists, a cancellation no longer deletes it.  An unreadable Wi-Fi capture ends in ``error`` with
  :data:`REWRITE_ERROR_TEXT`; an unexpected failure with :data:`FAILED_TEXT`.
* The note reads "1 Wi-Fi frame that was not a data frame was left out" for a single frame.
* The counting thread publishes ``capture.state`` ``{"capture": JOB, "files": [FILE]}`` when it counted something, so a
  page can refresh the list.  ``files()`` lists nothing when the folder is a reparse point.
* ``enforce_retention(None)`` uses ``clock``.  Too-old files never take one of the kept slots; once a file does not fit
  the count or the size budget, it and every older file are deleted.

Logging: INFO carries adapter names, durations, sizes and counts; hosts, ports and file names are DEBUG.
"""
from __future__ import annotations

import copy
import importlib
import ipaddress
import logging
import os
import re
import shutil
import stat
import threading
import time
from typing import Any, BinaryIO, Callable, Dict, List, Optional, Sequence, Tuple

from . import paths, pcapng, pktmon, winacl
from .pktmon import PktmonBusy, PktmonUnavailable

log = logging.getLogger(__name__)

__all__ = [
    "CaptureManager", "CaptureFileBusy", "CaptureFileMissing", "capture_filters", "wifi_note", "CAPTURE_JOB_KEYS",
    "CAPTURE_FILE_KEYS", "CAPTURE_STATUS_KEYS", "CAPTURE_ADAPTER_KEYS", "FILTER_KEYS", "CAPTURE_STATES",
    "RUNNING_STATES", "CAPTURE_SECONDS", "CAPTURE_SIZES_MB", "PROTOCOLS", "FILE_RE", "HEADERS_PKT_SIZE", "MAX_FILES",
    "MAX_TOTAL_BYTES", "MAX_AGE_S", "STOP_WAIT_S", "EVENT", "THREAD_NAME", "COUNT_THREAD_NAME", "SECONDS_TEXT",
    "SIZE_TEXT", "HOST_TEXT", "PORT_TEXT", "PROTOCOL_TEXT", "PORT_ICMP_TEXT", "ADAPTER_TEXT", "FULL_PACKETS_TEXT",
    "DISK_TEXT", "FILE_BUSY_TEXT", "FILE_MISSING_TEXT", "REWRITE_ERROR_TEXT", "FAILED_TEXT",
]

CAPTURE_JOB_KEYS = ("id", "state", "adapter", "filters", "full_packets", "seconds", "size_mb", "started_ts",
                    "elapsed_s", "bytes", "file", "error", "note", "ts")
CAPTURE_FILE_KEYS = ("name", "size", "created_ts", "packets")      # packets None until counted
CAPTURE_STATUS_KEYS = ("available", "reason", "adapters", "capture", "files")
CAPTURE_ADAPTER_KEYS = ("name", "index", "mac", "type_name", "wifi")
FILTER_KEYS = ("host", "port", "protocol")
CAPTURE_STATES = ("starting", "capturing", "converting", "done", "error", "cancelled")
RUNNING_STATES = ("starting", "capturing", "converting")
CAPTURE_SECONDS = (10, 30, 60, 300, 900)       # UI choices; the API accepts 5..1800
CAPTURE_SIZES_MB = (64, 128, 256, 512, 1024)
PROTOCOLS = ("tcp", "udp", "icmp")
FILE_RE = r"^TNT-capture-\d{8}-\d{6}\.pcapng$"
FILE_PREFIX = "TNT-capture-"
HEADERS_PKT_SIZE = 128                     # "First 128 bytes"
MAX_FILES = 10
MAX_TOTAL_BYTES = 2 * 1024 ** 3
MAX_AGE_S = 7 * 86400
STOP_WAIT_S = 1.0
IF_TYPE_WIFI = 71
EVENT = "capture.state"
THREAD_NAME = "tnt-capture"
COUNT_THREAD_NAME = "tnt-capture-count"
_MIB = 1024 ** 2
_GIB = 1024 ** 3
_FILE_PATTERN = re.compile(FILE_RE, re.ASCII)

SECONDS_TEXT = "seconds must be a whole number from {lo} to {hi}"
SIZE_TEXT = "size_mb must be one of 64, 128, 256, 512 or 1024"
HOST_TEXT = "host must be an IP address"
PORT_TEXT = "port must be a whole number from 1 to 65535"
PROTOCOL_TEXT = "protocol must be tcp, udp, icmp or null"
PORT_ICMP_TEXT = "port cannot be combined with protocol icmp"
ADAPTER_TEXT = "adapter '{name}' is not up"
FULL_PACKETS_TEXT = "full_packets must be true or false"
DISK_TEXT = "Not enough free disk space for this capture (needs {mb} MB)"
FILE_BUSY_TEXT = "The file is being downloaded"
FILE_MISSING_TEXT = "The capture file was not found"
REWRITE_ERROR_TEXT = "The Wi-Fi capture could not be converted"
FAILED_TEXT = "The capture could not be saved"
WIFI_NOTE_TEXT = "{n} Wi-Fi frames that were not data frames were left out"
WIFI_NOTE_ONE_TEXT = "1 Wi-Fi frame that was not a data frame was left out"


class CaptureFileBusy(RuntimeError):
    """The capture file is in use (a download holds it open): HTTP 409 conflict."""


class CaptureFileMissing(LookupError):
    """No such capture file, or the name is not one TNT gives its files: HTTP 404 not_found."""


class _Failure(RuntimeError):
    """A failure whose text is shown on the job as it is."""


class _Cancelled(Exception):
    """The capture was cancelled (engine stop)."""


# --- helpers -------------------------------------------------------------------------------------
def _field(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


def _whole(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _check_size(size_mb: Any) -> int:
    value = _whole(size_mb)
    if value not in CAPTURE_SIZES_MB:
        raise ValueError(SIZE_TEXT)
    return value


def _check_host(host: Any) -> Optional[str]:
    if host is None:
        return None
    if not isinstance(host, str):
        raise ValueError(HOST_TEXT)
    text = host.strip()
    if not text:
        return None
    if "%" in text or "/" in text:
        raise ValueError(HOST_TEXT)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise ValueError(HOST_TEXT) from None


def _check_port(port: Any) -> Optional[int]:
    if port is None:
        return None
    value = _whole(port)
    if value is None or not 1 <= value <= 65535:
        raise ValueError(PORT_TEXT)
    return value


def _check_protocol(protocol: Any) -> Optional[str]:
    if protocol is None:
        return None
    if not isinstance(protocol, str):
        raise ValueError(PROTOCOL_TEXT)
    text = protocol.strip().lower()
    if not text:
        return None
    if text not in PROTOCOLS:
        raise ValueError(PROTOCOL_TEXT)
    return text


def capture_filters(host: Optional[str], port: Optional[int], protocol: Optional[str]) -> List[List[str]]:
    """The Packet Monitor filters (``[name, args...]`` each) for validated criteria (see the module docstring)."""
    if protocol == "icmp" and not host:
        return [["TNT-CAP4", "-t", "ICMP"], ["TNT-CAP6", "-t", "ICMPv6"]]
    args: List[str] = []
    if host:
        args += ["-i", host]
    if port is not None:
        args += ["-p", str(port)]
    if protocol == "tcp":
        args += ["-t", "TCP"]
    elif protocol == "udp":
        args += ["-t", "UDP"]
    elif protocol == "icmp":
        args += ["-t", "ICMPv6" if ipaddress.ip_address(str(host)).version == 6 else "ICMP"]
    return [["TNT-CAP", *args]] if args else []


def wifi_note(dropped: int) -> Optional[str]:
    """The job note for Wi-Fi frames the rewrite left out, None when none were."""
    if dropped <= 0:
        return None
    return WIFI_NOTE_ONE_TEXT if dropped == 1 else WIFI_NOTE_TEXT.format(n=dropped)


def _is_capture_name(name: Any) -> bool:
    return isinstance(name, str) and _FILE_PATTERN.fullmatch(name) is not None


def _is_link(st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _size(path: str) -> Optional[int]:
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError:
        log.debug("could not delete %s", path, exc_info=True)


def _disk_free(path: str) -> int:
    return shutil.disk_usage(path).free


def _error_text(exc: BaseException) -> str:
    if isinstance(exc, (PktmonBusy, PktmonUnavailable, _Failure, ValueError)):
        return str(exc)
    return FAILED_TEXT


class _Capture:
    """One capture: what the worker needs and the job dict it updates."""

    __slots__ = ("job", "adapter", "comp_id", "seconds", "folder", "etl", "raw", "final", "part", "marker",
                 "session", "started_mono")

    def __init__(self, job: Dict[str, Any], adapter: Dict[str, Any], comp_id: int, seconds: int, folder: str,
                 stem: str) -> None:
        self.job = job
        self.adapter = adapter
        self.comp_id = comp_id
        self.seconds = seconds
        self.folder = folder
        self.etl = os.path.join(folder, stem + ".etl")
        self.raw = os.path.join(folder, stem + ".raw.pcapng")
        self.final = os.path.join(folder, stem + ".pcapng")
        self.part = self.final + ".part"                 # the Wi-Fi rewrite's work file
        self.marker = False
        self.session: Optional[pktmon.PktmonSession] = None
        self.started_mono = 0.0

    @property
    def names(self) -> List[str]:
        """The files a crash could leave behind (never the finished capture)."""
        return [os.path.basename(p) for p in (self.etl, self.raw, self.part)]


class CaptureManager:
    """The engine component behind ``/api/tools/capture`` (see the module docstring)."""

    def __init__(self, bus: Any, *, adapters_fn: Optional[Callable[[], Sequence[Any]]] = None,
                 runner: Optional[Callable[..., Any]] = None, clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic, wait: Optional[Callable[[float], bool]] = None,
                 session_running_fn: Optional[Callable[[], Optional[bool]]] = None,
                 filters_present_fn: Optional[Callable[[], Optional[bool]]] = None,
                 components_fn: Optional[Callable[[], List[Dict[str, Any]]]] = None,
                 capability_fn: Optional[Callable[[], Dict[str, Any]]] = None,
                 captures_dir_fn: Optional[Callable[[], Any]] = None,
                 acl: Optional[Callable[[str, str], None]] = None,
                 disk_free_fn: Optional[Callable[[str], int]] = None, tick_s: float = 2.0, min_seconds: int = 5,
                 max_seconds: int = 1800) -> None:
        self._bus = bus
        self._adapters_fn = adapters_fn
        self._runner = runner
        self._clock = clock
        self._monotonic = monotonic
        self._session_running_fn = session_running_fn
        self._filters_present_fn = filters_present_fn
        self._components_fn = components_fn
        self._capability_fn = capability_fn
        self._captures_dir_fn = captures_dir_fn
        self._acl = acl
        self._disk_free_fn = disk_free_fn
        self._tick_s = float(tick_s)
        self._min_seconds = int(min_seconds)
        self._max_seconds = int(max_seconds)
        self._lock = threading.Lock()                     # job, session, thread, count cache
        self._changed = threading.Condition(self._lock)   # a job update (stop() waits on it)
        self._pub_lock = threading.Lock()                 # a snapshot and its publish go out together
        self._wake = threading.Event()
        self._wait = wait if wait is not None else self._wake.wait
        self._stop_evt = threading.Event()                # finish early and keep the capture
        self._cancel_evt = threading.Event()              # discard it (stop while starting, engine stop)
        self._job: Optional[Dict[str, Any]] = None
        self._next_id = 1
        self._session: Optional[pktmon.PktmonSession] = None
        self._thread: Optional[threading.Thread] = None
        self._count_thread: Optional[threading.Thread] = None
        self._counts: Dict[Tuple[str, int, float], Optional[int]] = {}

    # -- collaborators ---------------------------------------------------------------------------------
    def _adapter_list(self) -> List[Any]:
        try:
            if self._adapters_fn is not None:
                return list(self._adapters_fn() or [])
            return list(importlib.import_module("tnt.netinfo").get_adapters())
        except Exception:  # noqa: BLE001
            log.debug("adapter enumeration failed", exc_info=True)
            return []

    def _capability(self) -> Dict[str, Any]:
        cap = (self._capability_fn or pktmon.capability)() or {}
        return {"ok": bool(cap.get("ok")), "reason": cap.get("reason")}

    def _components(self) -> List[Dict[str, Any]]:
        if self._components_fn is not None:
            return list(self._components_fn() or [])
        return pktmon.list_components(self._runner)

    def _folder(self) -> str:
        return os.fspath(self._captures_dir_fn() if self._captures_dir_fn is not None else paths.captures_dir())

    def _publish(self, files: bool = False) -> None:
        if self._bus is None:
            return
        with self._pub_lock:
            try:
                data: Dict[str, Any] = {"capture": self.job()}
                if files:
                    data["files"] = self.files()
                self._bus.publish(EVENT, data)
            except Exception:  # noqa: BLE001
                log.exception("publishing %s failed", EVENT)

    def _set(self, job: Dict[str, Any], only_state: Optional[str] = None, **fields: Any) -> bool:
        """Update *job* (when it is still the current job, and in *only_state* when given); True when it changed."""
        now = float(self._clock())
        with self._changed:
            if self._job is not job or (only_state is not None and job.get("state") != only_state):
                return False
            job.update(fields)
            job["ts"] = now
            self._changed.notify_all()
            return True

    # -- views -----------------------------------------------------------------------------------------
    def job(self) -> Optional[Dict[str, Any]]:
        """The current (or last) JOB as a copy, None before the first capture."""
        with self._lock:
            return copy.deepcopy(self._job) if self._job is not None else None

    def adapters(self) -> List[Dict[str, Any]]:
        """Adapters a capture can run on: up, not loopback, physical."""
        out: List[Dict[str, Any]] = []
        for a in self._adapter_list():
            if _field(a, "status") != "up" or _field(a, "is_loopback") or not _field(a, "is_physical"):
                continue
            out.append({"name": str(_field(a, "name") or ""), "index": _field(a, "index"),
                        "mac": str(_field(a, "mac") or ""), "type_name": str(_field(a, "type_name") or ""),
                        "wifi": _field(a, "if_type") == IF_TYPE_WIFI})
        return out

    def status(self) -> Dict[str, Any]:
        cap = self._capability()
        return {"available": cap["ok"], "reason": None if cap["ok"] else cap["reason"], "adapters": self.adapters(),
                "capture": self.job(), "files": self.files()}

    # -- starting --------------------------------------------------------------------------------------
    def _check_seconds(self, seconds: Any) -> int:
        value = _whole(seconds)
        if value is None or not self._min_seconds <= value <= self._max_seconds:
            raise ValueError(SECONDS_TEXT.format(lo=self._min_seconds, hi=self._max_seconds))
        return value

    def _check_adapter(self, adapter: Any) -> Dict[str, Any]:
        name = adapter if isinstance(adapter, str) else ("" if adapter is None else str(adapter))
        name = name.strip()
        for row in self.adapters() if name else []:
            if row["name"] == name:
                return row
        raise ValueError(ADAPTER_TEXT.format(name=name[:40]))

    def _check_disk(self, folder: str, size_mb: int) -> None:
        need = size_mb * 2 * _MIB + _GIB
        try:
            free = int((self._disk_free_fn or _disk_free)(folder))
        except Exception:  # noqa: BLE001 - unknown: let Packet Monitor try
            log.debug("free disk space unknown", exc_info=True)
            return
        if free < need:
            raise PktmonUnavailable(DISK_TEXT.format(mb=need // _MIB))

    def _free_stem(self, folder: str, now: float) -> str:
        stem = ""
        for step in range(60):
            stem = FILE_PREFIX + time.strftime("%Y%m%d-%H%M%S", time.localtime(now + step))
            taken = (stem + ".pcapng", stem + ".etl", stem + ".raw.pcapng", stem + ".pcapng.part")
            if not any(os.path.lexists(os.path.join(folder, n)) for n in taken):
                return stem
        raise _Failure(FAILED_TEXT)

    def start(self, *, adapter: Any, seconds: Any = 60, size_mb: Any = 128, full_packets: Any = True,
              host: Any = None, port: Any = None, protocol: Any = None) -> Dict[str, Any]:
        """Validate, start a capture and return its JOB (``capturing``, or ``cancelled`` when ``stop()`` came while it
        started); see the module docstring for the order of the checks and their errors."""
        seconds = self._check_seconds(seconds)
        size_mb = _check_size(size_mb)
        host = _check_host(host)
        port = _check_port(port)
        protocol = _check_protocol(protocol)
        if port is not None and protocol == "icmp":
            raise ValueError(PORT_ICMP_TEXT)
        chosen = self._check_adapter(adapter)
        if not isinstance(full_packets, bool):
            raise ValueError(FULL_PACKETS_TEXT)
        cap = self._capability()
        if not cap["ok"]:
            raise PktmonUnavailable(cap["reason"] or pktmon.TOO_OLD_REASON)
        pktmon.LOCK.acquire("capture")
        now = float(self._clock())
        with self._lock:
            job: Dict[str, Any] = {
                "id": self._next_id, "state": "starting", "adapter": dict(chosen),
                "filters": {"host": host, "port": port, "protocol": protocol}, "full_packets": full_packets,
                "seconds": seconds, "size_mb": size_mb, "started_ts": now, "elapsed_s": 0.0, "bytes": None,
                "file": None, "error": None, "note": None, "ts": now,
            }
            self._next_id += 1
            self._job = job
            self._session = None
            self._stop_evt.clear()
            self._cancel_evt.clear()
            self._wake.clear()
        self._publish()
        ctx: Optional[_Capture] = None
        handed_off = False
        try:
            folder = self._folder()
            try:
                (self._acl or winacl.secure_dir)(folder, winacl.CAPTURES_SDDL)
            except Exception as exc:  # noqa: BLE001 - fail closed on any failure
                log.warning("packet capture refused: the capture folder could not be secured (%s)", type(exc).__name__)
                log.debug("securing %s failed", folder, exc_info=True)
                raise PktmonUnavailable(pktmon.FOLDER_NOT_SECURED_TEXT) from exc
            self.enforce_retention(now)
            self._check_disk(folder, size_mb)
            comp_id = pktmon.component_for(chosen, self._components())
            if comp_id is None:
                raise PktmonUnavailable(pktmon.NOT_LISTED_TEXT)
            filters = capture_filters(host, port, protocol)
            ctx = _Capture(job, dict(chosen), comp_id, seconds, folder, self._free_stem(folder, now))
            if self._cancel_evt.is_set():
                self._set(job, state="cancelled")
                log.info("packet capture cancelled while it started")
                return self.job()                          # the finally releases the lock and publishes
            try:
                pktmon.write_marker(folder, {"purpose": "capture", "files": ctx.names, "started_ts": now})
                ctx.marker = True
            except OSError as exc:
                log.debug("writing the Packet Monitor session marker failed", exc_info=True)
                raise PktmonUnavailable(pktmon.FOLDER_NOT_SECURED_TEXT) from exc
            session = pktmon.PktmonSession(comp_id=comp_id, filters=filters, etl_path=ctx.etl, size_mb=size_mb,
                                           pkt_size=0 if full_packets else HEADERS_PKT_SIZE, runner=self._runner,
                                           session_running_fn=self._session_running_fn,
                                           filters_present_fn=self._filters_present_fn)
            ctx.session = session
            with self._lock:
                self._session = session
            log.debug("packet capture filters: %s", filters)
            session.start()
            if self._cancel_evt.is_set():
                self._discard(ctx)
                self._set(job, state="cancelled")
                log.info("packet capture cancelled while it started")
                return self.job()
            ctx.started_mono = float(self._monotonic())
            thread = threading.Thread(target=self._worker, args=(ctx,), name=THREAD_NAME, daemon=True)
            with self._lock:
                self._thread = thread
            self._set(job, state="capturing", bytes=_size(ctx.etl))
            started = self.job()                           # the answer is the capture as it began
            thread.start()
            handed_off = True
            log.info("packet capture started on '%s': %d s, %d MB, %s, %d filter(s)", chosen["name"], seconds, size_mb,
                     "full packets" if full_packets else "first 128 bytes", len(filters))
            return started
        except BaseException as exc:
            if ctx is not None:
                self._discard(ctx)
            self._set(job, state="error", error=_error_text(exc))
            log.warning("packet capture could not start (%s)", type(exc).__name__)
            raise
        finally:
            if not handed_off:
                with self._lock:
                    self._session = None
                pktmon.LOCK.release()
            self._publish()

    # -- running and finishing ----------------------------------------------------------------------
    def _elapsed(self, ctx: _Capture) -> float:
        return round(max(0.0, float(self._monotonic()) - ctx.started_mono), 1)

    def _discard(self, ctx: _Capture) -> None:
        """Clean-up of a capture that is not kept: the session, the partial files, the marker.  Never raises."""
        try:
            if ctx.session is not None:
                ctx.session.cleanup()
            for path in (ctx.etl, ctx.raw, ctx.part):
                _remove(path)
            if ctx.marker:
                pktmon.clear_marker(ctx.folder)
        except Exception:  # noqa: BLE001
            log.exception("cleaning up after the packet capture failed")

    def _capture_loop(self, ctx: _Capture) -> None:
        while True:
            if self._cancel_evt.is_set():
                raise _Cancelled()
            left = ctx.seconds - (float(self._monotonic()) - ctx.started_mono)
            if self._stop_evt.is_set() or left <= 0:
                return
            self._wait(min(self._tick_s, left))
            if self._cancel_evt.is_set():
                raise _Cancelled()
            if self._stop_evt.is_set():
                return
            if self._set(ctx.job, only_state="capturing", elapsed_s=self._elapsed(ctx), bytes=_size(ctx.etl)):
                self._publish()

    def _finish(self, ctx: _Capture) -> None:
        job = ctx.job
        session = ctx.session
        assert session is not None
        self._set(job, state="converting", elapsed_s=self._elapsed(ctx), bytes=_size(ctx.etl))
        self._publish()
        session.stop()
        if self._cancel_evt.is_set():
            raise _Cancelled()
        if not session.convert(ctx.raw, component_id=ctx.comp_id):
            raise _Failure(session.last_error or pktmon.failure_text("convert", 0))
        if self._cancel_evt.is_set():
            raise _Cancelled()
        note = None
        if ctx.adapter.get("wifi"):
            try:
                result = pcapng.rewrite_dot11_to_ethernet(ctx.raw, ctx.final)
            except (OSError, pcapng.PcapngError) as exc:
                log.warning("the Wi-Fi capture could not be converted (%s)", type(exc).__name__)
                log.debug("rewriting %s failed", ctx.raw, exc_info=True)
                raise _Failure(REWRITE_ERROR_TEXT) from exc
            _remove(ctx.raw)
            note = wifi_note(int(result.get("dropped") or 0))
        else:
            os.replace(ctx.raw, ctx.final)
        packets = self._count_file(ctx.final)
        _remove(ctx.etl)
        pktmon.clear_marker(ctx.folder)
        size = _size(ctx.final)
        self._set(job, state="done", file=os.path.basename(ctx.final), note=note, bytes=size)
        log.info("packet capture saved: %s packet(s), %.0f s, %s bytes", packets, job.get("elapsed_s") or 0.0, size)
        log.debug("packet capture file: %s", os.path.basename(ctx.final))

    def _worker(self, ctx: _Capture) -> None:
        job = ctx.job
        try:
            self._capture_loop(ctx)
            self._finish(ctx)
        except _Cancelled:
            self._discard(ctx)
            self._set(job, state="cancelled")
            log.info("packet capture cancelled")
        except Exception as exc:  # noqa: BLE001
            cancelled = self._cancel_evt.is_set()
            self._discard(ctx)
            if cancelled:
                self._set(job, state="cancelled")
                log.info("packet capture cancelled")
            else:
                self._set(job, state="error", error=_error_text(exc))
                log.warning("packet capture failed (%s)", type(exc).__name__)
                log.debug("packet capture failure", exc_info=True)
        finally:
            with self._lock:
                if self._session is ctx.session:
                    self._session = None
            pktmon.LOCK.release()
            self._publish()

    def stop(self) -> Optional[Dict[str, Any]]:
        """End the capture early and KEEP it (``capturing`` → ``converting`` → ``done``); while it is still
        ``starting`` it is cancelled instead.  Returns the JOB; at once when nothing runs."""
        with self._changed:
            job = self._job
            state = job.get("state") if job is not None else None
            if state == "starting":
                self._cancel_evt.set()
                self._wake.set()
            elif state == "capturing":
                self._stop_evt.set()
                self._wake.set()
                self._changed.wait_for(lambda: job.get("state") != "capturing", timeout=STOP_WAIT_S)
        return self.job()

    def close(self, timeout: float) -> None:
        """Engine stop: cancel a running capture and, when TNT's Packet Monitor session is active, run ``pktmon
        stop`` with *timeout*.  At once, with no pktmon command, when idle."""
        with self._lock:
            job, session = self._job, self._session
            running = job is not None and job.get("state") in RUNNING_STATES
        if not running and session is None:
            return
        self._cancel_evt.set()
        self._wake.set()
        if session is not None and session.active:
            rc, out = pktmon.run_pktmon(["stop"], self._runner, timeout_s=max(0.1, float(timeout)))
            if rc != 0:
                log.debug("pktmon stop at close exited %d: %s", rc, out)

    # -- files -----------------------------------------------------------------------------------------
    def _forget(self, name: str) -> None:
        with self._lock:
            for key in [k for k in self._counts if k[0] == name]:
                del self._counts[key]

    def _count_file(self, path: str) -> Optional[int]:
        """Packets in a saved capture, from the cache or counted into it (None for a file that is not pcapng)."""
        try:
            st = os.stat(path)
        except OSError:
            return None
        key = (os.path.basename(path), st.st_size, st.st_mtime)
        with self._lock:
            if key in self._counts:
                return self._counts[key]
        try:
            packets: Optional[int] = pcapng.count_packets(path)
        except pcapng.PcapngError:
            log.debug("%s is not valid pcapng", path, exc_info=True)
            packets = None
        except OSError:
            log.debug("could not count %s", path, exc_info=True)
            return None
        with self._lock:
            self._counts[key] = packets
        return packets

    def files(self) -> List[Dict[str, Any]]:
        """The saved captures (FILE dicts), newest first."""
        folder = self._folder()
        try:
            if winacl._is_reparse_point(folder):
                return []
            names = os.listdir(folder)
        except OSError:
            return []
        with self._lock:
            counts = dict(self._counts)
        rows: List[Dict[str, Any]] = []
        for name in names:
            if not _is_capture_name(name):
                continue
            try:
                st = os.lstat(os.path.join(folder, name))
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or _is_link(st):
                continue
            rows.append({"name": name, "size": st.st_size, "created_ts": st.st_mtime,
                         "packets": counts.get((name, st.st_size, st.st_mtime))})
        rows.sort(key=lambda r: (r["created_ts"], r["name"]), reverse=True)
        return rows

    def _resolve(self, name: Any) -> Tuple[str, os.stat_result]:
        """The path and ``lstat`` of a saved capture called *name*, else :class:`CaptureFileMissing`."""
        if not _is_capture_name(name) or os.path.basename(name) != name:
            raise CaptureFileMissing(FILE_MISSING_TEXT)
        folder = self._folder()
        path = os.path.join(folder, name)
        try:
            if winacl._is_reparse_point(folder) or not os.path.isdir(folder):
                raise CaptureFileMissing(FILE_MISSING_TEXT)
            st = os.lstat(path)
            root = os.path.normcase(os.path.realpath(folder))
            real = os.path.normcase(os.path.realpath(path))
        except (OSError, ValueError):
            raise CaptureFileMissing(FILE_MISSING_TEXT) from None
        if not stat.S_ISREG(st.st_mode) or _is_link(st) or os.path.dirname(real) != root:
            raise CaptureFileMissing(FILE_MISSING_TEXT)
        return path, st

    def open_file(self, name: Any) -> Tuple[BinaryIO, int]:
        """``(binary file object, size)`` of a saved capture for a download; the caller closes it."""
        path, st = self._resolve(name)
        try:
            fh = open(path, "rb")
        except FileNotFoundError:
            raise CaptureFileMissing(FILE_MISSING_TEXT) from None
        try:
            opened = os.fstat(fh.fileno())
            if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(st, opened):
                raise CaptureFileMissing(FILE_MISSING_TEXT)
        except BaseException:
            fh.close()
            raise
        log.debug("capture file opened for download: %s", name)
        return fh, opened.st_size

    def delete_file(self, name: Any) -> List[Dict[str, Any]]:
        """Delete a saved capture and return the remaining FILE list."""
        path, _st = self._resolve(name)
        try:
            os.remove(path)
        except PermissionError:
            raise CaptureFileBusy(FILE_BUSY_TEXT) from None
        except FileNotFoundError:
            raise CaptureFileMissing(FILE_MISSING_TEXT) from None
        self._forget(name)
        log.info("packet capture file deleted")
        log.debug("deleted capture file %s", name)
        return self.files()

    def enforce_retention(self, now: Optional[float]) -> int:
        """Delete saved captures past the retention limits; the number deleted.  Never raises for a file it cannot
        delete (it is tried again next time) or a missing folder."""
        folder = self._folder()
        if not os.path.isdir(folder):
            return 0
        reference = float(self._clock() if now is None else now)
        deleted = kept = total = 0
        over = False
        for row in self.files():
            old = reference - float(row["created_ts"]) > MAX_AGE_S
            if not old and not over and (kept >= MAX_FILES or total + int(row["size"]) > MAX_TOTAL_BYTES):
                over = True
            if old or over:
                try:
                    os.remove(os.path.join(folder, row["name"]))
                except FileNotFoundError:
                    continue
                except OSError:
                    log.debug("kept %s for now: it could not be deleted", row["name"], exc_info=True)
                    continue
                deleted += 1
                self._forget(row["name"])
                continue
            kept += 1
            total += int(row["size"])
        if deleted:
            log.info("packet capture retention deleted %d file(s)", deleted)
        return deleted

    def recover(self) -> None:
        """Engine start (helper thread): clean up a Packet Monitor session a crash left behind, then count the saved
        captures that have no count yet on ``tnt-capture-count``.  Never raises."""
        try:
            pktmon.recover(self._folder(), runner=self._runner, session_running_fn=self._session_running_fn)
        except Exception:  # noqa: BLE001
            log.exception("packet capture recovery failed")
        try:
            with self._lock:
                if self._count_thread is not None and self._count_thread.is_alive():
                    return
                thread = threading.Thread(target=self._count_missing, name=COUNT_THREAD_NAME, daemon=True)
                self._count_thread = thread
            thread.start()
        except Exception:  # noqa: BLE001
            log.exception("could not start counting the saved captures")

    def _count_missing(self) -> None:
        try:
            folder = self._folder()
            counted = 0
            rows = self.files()
            for row in rows:
                with self._lock:
                    known = (row["name"], row["size"], row["created_ts"]) in self._counts
                if not known:
                    self._count_file(os.path.join(folder, row["name"]))
                    counted += 1
            present = {(r["name"], r["size"], r["created_ts"]) for r in rows}
            with self._lock:
                for key in [k for k in self._counts if k not in present]:
                    del self._counts[key]
            if counted:
                log.info("packet capture files counted: %d", counted)
                self._publish(files=True)
        except Exception:  # noqa: BLE001
            log.exception("counting the packets of saved captures failed")
