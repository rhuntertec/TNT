r"""Live packet capture for the Packet capture page: one adapter's frames, in real time, as a pcapng file plus an
in-memory packet list (ARCHITECTURE §3.24).

:class:`CaptureManager` is the engine component behind ``/api/capture`` (admin-gated routes).  It is a stripped-down
network analyser: pick an adapter that is up, start, watch the packets arrive, filter them, click one for its detail
tree, and save the capture to disk (or throw it away).  A capture that finds a SIP call says so, and the call's RTP can
be rebuilt as audio (:mod:`tnt.sipcalls`).

Where the frames come from
--------------------------
TNT starts its own real-time ETW session (:mod:`tnt.etw`) on Windows' built-in NDIS packet-capture provider and
consumes it live.  Nothing is installed and no third-party driver is needed; the service already runs as LocalSystem,
which is what creating an ETW session takes.  This is a different mechanism from ``pktmon.exe`` (which the switch-port
lookup still uses): the two do not share :data:`tnt.pktmon.LOCK`, so a capture and a switch-port lookup can run
together.

Every frame the session delivers is handed to a bounded queue, and the worker thread :data:`THREAD_NAME` does the work:
the frame goes straight into the pcapng file (:class:`tnt.pcapng.Writer`), one summary row goes into a ring of at most
:data:`MAX_ROWS` rows (:func:`tnt.dissect.summarize`), and SIP and RTP go to the :class:`tnt.sipcalls.CallTracker`.
A frame that arrives while the queue is full is counted into ``dropped`` and thrown away - the capture never grows
without bound and never blocks the kernel's delivery thread.  A Wi-Fi adapter's 802.11 data frames are rewritten as
Ethernet on the way in (:func:`tnt.pcapng.dot11_to_ethernet`), as the old pktmon capture did at the end.

Memory and disk
---------------
Three limits end a capture by themselves, whichever comes first: ``max_seconds`` (:data:`CAPTURE_SECONDS`, 15 minutes
by default), ``max_mb`` (:data:`CAPTURE_SIZES_MB`, 256 MB by default) and :data:`MAX_PACKETS`.  So does the adapter
going away (``stop_reason`` ``adapter``): every :data:`ADAPTER_CHECK_S` a running capture checks its adapter is still
up, and an enumeration that fails never ends one.  The packet list keeps
at most :data:`MAX_ROWS` rows: past that the oldest row falls off the front (the file still holds every packet, and the
session says ``truncated``).  A start needs ``max_mb * 2 MiB + 1 GiB`` of free disk.  Saved captures keep the old
retention: at most :data:`MAX_FILES` files, :data:`MAX_TOTAL_BYTES` in total, nothing older than :data:`MAX_AGE_S`.

Files
-----
While it runs, a capture writes ``TNT-live-<YYYYmmdd-HHMMSS>.pcapng`` in the captures folder
(:func:`tnt.paths.captures_dir`), which every start secures again with ``tnt.winacl.CAPTURES_SDDL`` (SYSTEM and
Administrators only; the start fails closed when that does not work).  :meth:`CaptureManager.save` renames it to
``TNT-capture-<YYYYmmdd-HHMMSS>.pcapng`` (:data:`FILE_RE`, the listed and downloadable name) and
:meth:`CaptureManager.discard` deletes it.  A working file a crash left behind is cleaned up by
:meth:`CaptureManager.recover`.

Opening a capture that is already on disk
-----------------------------------------
:meth:`CaptureManager.open_file` reads one of TNT's own saved captures back into the packet list.
:meth:`CaptureManager.open_path` reads ANY capture file on this PC by its full path - one from Wireshark, a switch or
a colleague - so the page is not limited to what TNT captured itself.  The file is only ever read: it is never moved,
written or deleted, ``save()`` does nothing for it and ``discard()`` leaves it where it is.  The path must be absolute
and local (no relative path and no UNC share), must resolve to a regular file that is not a reparse point, and must be
at most :data:`MAX_OPEN_BYTES`; everything else is :data:`PATH_TEXT` / :data:`PATH_BIG_TEXT` (``ValueError``) or
:class:`CaptureFileMissing`.  Both routes are admin-gated like the rest, so this reads nothing an administrator could
not already read.

Shapes (keys in this order: :data:`CAPTURE_STATUS_KEYS`, :data:`SESSION_KEYS`, :data:`ROW_KEYS`,
:data:`CAPTURE_FILE_KEYS`, :data:`CAPTURE_ADAPTER_KEYS`, :data:`LIMIT_KEYS`)::

    STATUS  = {"available", "reason", "adapters": [ADAPTER], "session": SESSION|None, "files": [FILE],
               "limits": LIMITS}
    SESSION = {"id", "state": "capturing"|"stopped"|"loaded"|"error", "source": "live"|"file", "adapter": ADAPTER|None,
               "file": str|None, "saved": bool, "started_ts", "first_ts", "elapsed_s", "packets", "shown", "bytes",
               "dropped", "truncated", "calls", "stop_reason": str|None, "error": str|None, "ts"}
    ROW     = {"no", "ts", "rel", "src", "dst", "src_mac", "dst_mac", "proto", "sport", "dport", "length", "info"}
    FILE    = {"name", "size", "created_ts", "packets": int|None}
    ADAPTER = {"name", "index", "mac", "type_name", "wifi"}     # up, not loopback, physical
    LIMITS  = {"max_rows", "max_packets", "seconds", "sizes_mb", "default_seconds", "default_mb"}

Validation (``ValueError``, texts below)

=============  =========================================  ===============================================
Field          Rule                                       text
=============  =========================================  ===============================================
adapter        one of :meth:`CaptureManager.adapters`     adapter '<x>' is not up
max_seconds    one of :data:`CAPTURE_SECONDS`             max_seconds must be one of 60, 300, 900, 1800 or 3600
max_mb         one of :data:`CAPTURE_SIZES_MB`            max_mb must be one of 64, 128, 256, 512 or 1024
path           absolute, local, a regular file            path must be the full path of a file on this PC
path (size)    at most :data:`MAX_OPEN_BYTES`             That file is larger than 4096 MB, which is more than TNT opens
=============  =========================================  ===============================================

Reading the list
----------------
:meth:`CaptureManager.packets` answers ``{"rows", "total", "shown", "matched", "last", "dropped_before", "session"}``.
Without ``since`` it returns the newest ``limit`` matching rows (a fresh page, or a filter the user just changed); with
``since`` it returns the matching rows numbered after it, oldest first, so the page can tail a running capture.
``dropped_before`` is true when the ring has already rolled past ``since``, which tells the page its tail has a hole.
The filters are an IP address, a MAC address and any number of protocol keys (:data:`tnt.dissect.PROTO_FILTERS`), all
ANDed, and the protocol keys ORed among themselves.  :meth:`CaptureManager.packet` reads one packet back out of the
file by its offset and returns ``{"row", "layers", "hex", "bytes"}`` - the detail tree and the hex dump.

Events
------
``capture.state`` ``{"session": SESSION}`` every :data:`TICK_S` while a capture runs and on every state change;
``capture.sip`` ``{"call": CALL}`` once per new SIP call.  Both are admin-only on the event stream.

Injectable knobs (keyword-only; None means the module default): ``adapters_fn``, ``clock``, ``monotonic``,
``captures_dir_fn``, ``acl``, ``disk_free_fn``, ``etw``, ``dissect``, ``sipcalls``, ``tick_s``, ``queue_size``,
``max_rows``.  The engine uses the defaults.

Logging: INFO carries adapter names, counts and sizes; addresses, ports and file names are DEBUG.  Packet contents are
never logged.
"""
from __future__ import annotations

import copy
import importlib
import ipaddress
import logging
import os
import queue
import re
import shutil
import stat
import threading
import time
from typing import Any, BinaryIO, Callable, Dict, List, Optional, Sequence, Tuple

from . import paths, pcapng, winacl

log = logging.getLogger(__name__)

__all__ = [
    "CaptureManager", "CaptureFileBusy", "CaptureFileMissing", "CaptureUnavailable", "CaptureBusy",
    "CAPTURE_STATUS_KEYS", "SESSION_KEYS", "ROW_KEYS", "CAPTURE_FILE_KEYS", "CAPTURE_ADAPTER_KEYS", "LIMIT_KEYS",
    "DETAIL_KEYS", "PACKETS_KEYS", "TILE_KEYS", "SESSION_STATES", "CAPTURE_SECONDS", "CAPTURE_SIZES_MB", "DEFAULT_SECONDS", "DEFAULT_MB",
    "MAX_ROWS", "MAX_PACKETS", "MAX_FILES", "MAX_TOTAL_BYTES", "MAX_AGE_S", "FILE_RE", "WORK_RE", "TICK_S",
    "QUEUE_SIZE", "ADAPTER_CHECK_S", "EVENT", "SIP_EVENT", "THREAD_NAME", "ADAPTER_TEXT", "SECONDS_TEXT", "SIZE_TEXT", "DISK_TEXT",
    "FILE_BUSY_TEXT", "FILE_MISSING_TEXT", "BUSY_TEXT", "NOTHING_TEXT", "FAILED_TEXT", "STOP_REASONS",
    "PATH_TEXT", "PATH_BIG_TEXT", "MAX_OPEN_BYTES", "MAX_PATH_LEN",
]

CAPTURE_STATUS_KEYS = ("available", "reason", "adapters", "session", "files", "limits")
SESSION_KEYS = ("id", "state", "source", "adapter", "file", "saved", "started_ts", "first_ts", "elapsed_s", "packets",
                "shown", "bytes", "dropped", "truncated", "calls", "stop_reason", "error", "ts")
ROW_KEYS = ("no", "ts", "rel", "src", "dst", "src_mac", "dst_mac", "proto", "sport", "dport", "length", "info")
CAPTURE_FILE_KEYS = ("name", "size", "created_ts", "packets")      # packets None until counted
CAPTURE_ADAPTER_KEYS = ("name", "index", "mac", "type_name", "wifi")
LIMIT_KEYS = ("max_rows", "max_packets", "seconds", "sizes_mb", "default_seconds", "default_mb")
DETAIL_KEYS = ("row", "layers", "hex", "bytes")
PACKETS_KEYS = ("rows", "total", "shown", "matched", "last", "dropped_before", "session")
TILE_KEYS = ("available", "reason", "running", "adapter", "packets", "calls", "files")

SESSION_STATES = ("capturing", "stopped", "loaded", "error")
STOP_REASONS = ("user", "seconds", "size", "packets", "adapter", "service")
CAPTURE_SECONDS = (60, 300, 900, 1800, 3600)       # UI choices, and what the API accepts
CAPTURE_SIZES_MB = (64, 128, 256, 512, 1024)
DEFAULT_SECONDS = 900
DEFAULT_MB = 256
MAX_ROWS = 50_000                          # packet list rows held in memory (the file keeps every packet)
MAX_PACKETS = 5_000_000                    # a hard stop, whatever the size and time limits allow
MAX_FILES = 10
MAX_TOTAL_BYTES = 2 * 1024 ** 3
MAX_AGE_S = 7 * 86400
FILE_RE = r"^TNT-capture-\d{8}-\d{6}\.pcapng$"
WORK_RE = r"^TNT-live-\d{8}-\d{6}\.pcapng$"
FILE_PREFIX = "TNT-capture-"
WORK_PREFIX = "TNT-live-"
TICK_S = 1.0
CAPABILITY_TTL_S = 30.0                    # how long "can this PC capture?" and the file count are reused
ADAPTER_CHECK_S = 5.0                      # how often a running capture checks its adapter is still up
MAX_OPEN_BYTES = 4 * 1024 ** 3             # the largest file open_path() will read
MAX_PATH_LEN = 4096
QUEUE_SIZE = 20_000                        # frames waiting for the worker; past this a frame is dropped and counted
STOP_JOIN_S = 5.0
IF_TYPE_WIFI = 71
EVENT = "capture.state"
SIP_EVENT = "capture.sip"
THREAD_NAME = "tnt-capture"
COUNT_THREAD_NAME = "tnt-capture-count"
DEFAULT_ROW_LIMIT = 500
MAX_ROW_LIMIT = 2000
_MIB = 1024 ** 2
_GIB = 1024 ** 3
_FILE_PATTERN = re.compile(FILE_RE, re.ASCII)
_WORK_PATTERN = re.compile(WORK_RE, re.ASCII)

ADAPTER_TEXT = "adapter '{name}' is not up"
SECONDS_TEXT = "max_seconds must be one of 60, 300, 900, 1800 or 3600"
SIZE_TEXT = "max_mb must be one of 64, 128, 256, 512 or 1024"
DISK_TEXT = "Not enough free disk space for this capture (needs {mb} MB)"
FILE_BUSY_TEXT = "The file is being downloaded"
FILE_MISSING_TEXT = "The capture file was not found"
BUSY_TEXT = "A capture is already running: stop it first"
NOTHING_TEXT = "No capture is open"
FAILED_TEXT = "The capture could not be started"
FOLDER_TEXT = "The capture folder could not be secured"
UNSAVED_TEXT = "The capture has not been saved yet"
PATH_TEXT = "path must be the full path of a file on this PC"
PATH_BIG_TEXT = "That file is larger than {mb} MB, which is more than TNT opens"


class CaptureFileBusy(RuntimeError):
    """The capture file is in use (a download holds it open): HTTP 409 conflict."""


class CaptureFileMissing(LookupError):
    """No such capture file, or the name is not one TNT gives its files: HTTP 404 not_found."""


class CaptureUnavailable(RuntimeError):
    """Capturing cannot be done here, or it failed: HTTP 409 unavailable."""


class CaptureBusy(RuntimeError):
    """A capture is already running: HTTP 409 conflict."""


# --- helpers -------------------------------------------------------------------------------------
def _field(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


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


def _norm_mac(text: Any) -> str:
    """A MAC filter as twelve lower-case hex digits, or '' when it is not one (any separator, or none)."""
    raw = "".join(c for c in str(text or "").lower() if c in "0123456789abcdef")
    return raw if len(raw) == 12 else ""


def _norm_ip(text: Any) -> str:
    """An IP filter as its canonical text, or '' when it is not an address."""
    value = str(text or "").strip()
    if not value or "/" in value or "%" in value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _whole(value: Any, default: int, lo: int, hi: int) -> int:
    """A whole number inside [lo, hi]; *default* for anything else (list paging never fails a request)."""
    if isinstance(value, bool) or value is None:
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, number))


class _Ring:
    """The packet list: at most *limit* summary rows, the oldest falling off the front.

    Rows are kept as they will be sent (ROW dicts) plus the two things only the manager needs: the packet's offset in
    the file and its protocol layers, which the protocol filters match on."""

    __slots__ = ("limit", "rows", "offsets", "layers", "first_no", "total", "truncated")

    def __init__(self, limit: int) -> None:
        self.limit = max(1, int(limit))
        self.rows: List[Dict[str, Any]] = []
        self.offsets: List[int] = []
        self.layers: List[Tuple[str, ...]] = []
        self.first_no = 1                     # the "no" of rows[0]
        self.total = 0                        # every packet ever added, whether it is still held or not
        self.truncated = False

    def clear(self) -> None:
        self.rows = []
        self.offsets = []
        self.layers = []
        self.first_no = 1
        self.total = 0
        self.truncated = False

    def add(self, row: Dict[str, Any], offset: int, layers: Sequence[str]) -> None:
        self.rows.append(row)
        self.offsets.append(int(offset))
        self.layers.append(tuple(str(x) for x in layers or ()))
        self.total += 1
        over = len(self.rows) - self.limit
        if over > 0:
            del self.rows[:over]
            del self.offsets[:over]
            del self.layers[:over]
            self.first_no += over
            self.truncated = True

    def index_of(self, no: int) -> Optional[int]:
        pos = int(no) - self.first_no
        return pos if 0 <= pos < len(self.rows) else None


class _Filter:
    """One validated packet filter: an IP, a MAC and a set of protocol keys, all ANDed."""

    __slots__ = ("ip", "mac", "protos")

    def __init__(self, ip: str = "", mac: str = "", protos: Sequence[str] = ()) -> None:
        self.ip = ip
        self.mac = mac
        self.protos = tuple(protos)

    @property
    def empty(self) -> bool:
        return not (self.ip or self.mac or self.protos)


class CaptureManager:
    """The engine component behind ``/api/capture`` (see the module docstring)."""

    def __init__(self, bus: Any, *, adapters_fn: Optional[Callable[[], Sequence[Any]]] = None,
                 clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic,
                 captures_dir_fn: Optional[Callable[[], Any]] = None,
                 acl: Optional[Callable[[str, str], None]] = None,
                 disk_free_fn: Optional[Callable[[str], int]] = None, etw: Any = None, dissect: Any = None,
                 sipcalls: Any = None, tick_s: float = TICK_S, queue_size: int = QUEUE_SIZE,
                 max_rows: int = MAX_ROWS) -> None:
        self._bus = bus
        self._adapters_fn = adapters_fn
        self._clock = clock
        self._monotonic = monotonic
        self._captures_dir_fn = captures_dir_fn
        self._acl = acl
        self._disk_free_fn = disk_free_fn
        self._etw_mod = etw
        self._dissect_mod = dissect
        self._sipcalls_mod = sipcalls
        self._tick_s = max(0.05, float(tick_s))
        self._queue_size = max(16, int(queue_size))
        self._lock = threading.RLock()
        self._pub_lock = threading.Lock()
        # its own lock: the ETW consumer thread must never wait behind a packet being written to disk
        self._drop_lock = threading.Lock()
        self._stop_evt = threading.Event()
        self._session: Optional[Dict[str, Any]] = None
        self._next_id = 1
        self._ring = _Ring(max_rows)
        self._tracker: Any = None
        self._queue: Optional["queue.Queue[Any]"] = None
        self._thread: Optional[threading.Thread] = None
        self._count_thread: Optional[threading.Thread] = None
        self._trace: Any = None
        self._writer: Optional[pcapng.Writer] = None
        self._fh: Optional[BinaryIO] = None
        self._work_path: Optional[str] = None
        self._read_path: Optional[str] = None      # the file rows were indexed from (live or opened)
        self._read_linktype = 1
        self._wifi = False
        self._if_index: Optional[int] = None
        self._limit_seconds = DEFAULT_SECONDS
        self._limit_bytes = DEFAULT_MB * _MIB
        self._started_mono = 0.0
        self._adapter_checked = 0.0
        self._dropped = 0
        self._counts: Dict[Tuple[str, int, float], Optional[int]] = {}
        self._capability_cache: Optional[Dict[str, Any]] = None
        self._capability_ts = 0.0
        self._file_count = 0                 # what tile() reports, refreshed at most every CAPABILITY_TTL_S
        self._file_count_ts = 0.0

    # -- collaborators ---------------------------------------------------------------------------------
    def _etw(self) -> Any:
        return self._etw_mod if self._etw_mod is not None else importlib.import_module("tnt.etw")

    def _dissect(self) -> Any:
        return self._dissect_mod if self._dissect_mod is not None else importlib.import_module("tnt.dissect")

    def _sip(self) -> Any:
        return self._sipcalls_mod if self._sipcalls_mod is not None else importlib.import_module("tnt.sipcalls")

    def _adapter_list(self) -> List[Any]:
        try:
            if self._adapters_fn is not None:
                return list(self._adapters_fn() or [])
            return list(importlib.import_module("tnt.netinfo").get_adapters())
        except Exception:  # noqa: BLE001
            log.debug("adapter enumeration failed", exc_info=True)
            return []

    def _folder(self) -> str:
        return os.fspath(self._captures_dir_fn() if self._captures_dir_fn is not None else paths.captures_dir())

    def _capability(self) -> Dict[str, Any]:
        """Can this PC capture? Cached for :data:`CAPABILITY_TTL_S`: the answer is the platform and the process's own
        rights, neither of which changes, and ``/api/status`` asks for it every few seconds."""
        now = float(self._clock())
        with self._lock:
            if self._capability_cache is not None and now - self._capability_ts < CAPABILITY_TTL_S:
                return dict(self._capability_cache)
        try:
            cap = self._etw().available() or {}
            answer = {"ok": bool(cap.get("ok")), "reason": cap.get("reason")}
        except Exception as exc:  # noqa: BLE001
            log.debug("the capture capability probe failed", exc_info=True)
            answer = {"ok": False, "reason": f"Packet capture is not available here ({type(exc).__name__})"}
        with self._lock:
            self._capability_cache = dict(answer)
            self._capability_ts = now
        return answer

    # -- publishing ------------------------------------------------------------------------------------
    def _publish(self) -> None:
        if self._bus is None:
            return
        with self._pub_lock:
            try:
                self._bus.publish(EVENT, {"session": self.session()})
            except Exception:  # noqa: BLE001
                log.exception("publishing %s failed", EVENT)

    def _publish_call(self, call: Dict[str, Any]) -> None:
        if self._bus is None:
            return
        try:
            self._bus.publish(SIP_EVENT, {"call": call})
        except Exception:  # noqa: BLE001
            log.exception("publishing %s failed", SIP_EVENT)

    def _set(self, **fields: Any) -> None:
        with self._lock:
            if self._session is None:
                return
            self._session.update(fields)
            self._session["ts"] = float(self._clock())

    # -- views -----------------------------------------------------------------------------------------
    def session(self) -> Optional[Dict[str, Any]]:
        """The open SESSION as a copy, None when nothing is open."""
        with self._lock:
            if self._session is None:
                return None
            out = copy.deepcopy(self._session)
            out["packets"] = self._ring.total
            out["shown"] = len(self._ring.rows)
            out["truncated"] = self._ring.truncated
            out["dropped"] = self._dropped
            out["calls"] = self._call_count()
            if out["state"] == "capturing":
                out["elapsed_s"] = round(max(0.0, float(self._monotonic()) - self._started_mono), 1)
                out["bytes"] = self._writer.offset if self._writer is not None else out["bytes"]
            return out

    def _call_count(self) -> int:
        tracker = self._tracker
        if tracker is None:
            return 0
        try:
            return int(tracker.stats().get("calls") or 0)
        except Exception:  # noqa: BLE001
            return 0

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

    def limits(self) -> Dict[str, Any]:
        return {"max_rows": self._ring.limit, "max_packets": MAX_PACKETS, "seconds": list(CAPTURE_SECONDS),
                "sizes_mb": list(CAPTURE_SIZES_MB), "default_seconds": DEFAULT_SECONDS, "default_mb": DEFAULT_MB}

    def status(self) -> Dict[str, Any]:
        cap = self._capability()
        return {"available": cap["ok"], "reason": None if cap["ok"] else cap["reason"], "adapters": self.adapters(),
                "session": self.session(), "files": self.files(), "limits": self.limits()}

    def tile(self) -> Dict[str, Any]:
        """The small block ``/api/status`` carries for the Packet capture tile (never any packet contents)."""
        session = self.session() or {}
        cap = self._capability()
        adapter = session.get("adapter") or {}
        return {"available": cap["ok"], "reason": None if cap["ok"] else cap["reason"],
                "running": session.get("state") == "capturing", "adapter": adapter.get("name"),
                "packets": int(session.get("packets") or 0), "calls": int(session.get("calls") or 0),
                "files": self._saved_count()}

    def _saved_count(self) -> int:
        """How many captures are saved, from a cache with the same short life as the capability: ``/api/status``
        carries it every few seconds and it must not list the folder every time."""
        now = float(self._clock())
        with self._lock:
            if now - self._file_count_ts < CAPABILITY_TTL_S:
                return self._file_count
        count = len(self.files())
        with self._lock:
            self._file_count = count
            self._file_count_ts = now
        return count

    # -- starting --------------------------------------------------------------------------------------
    def _check_adapter(self, adapter: Any) -> Dict[str, Any]:
        name = adapter if isinstance(adapter, str) else ("" if adapter is None else str(adapter))
        name = name.strip()
        for row in self.adapters() if name else []:
            if row["name"] == name:
                return row
        raise ValueError(ADAPTER_TEXT.format(name=name[:40]))

    def _check_disk(self, folder: str, max_mb: int) -> None:
        need = max_mb * 2 * _MIB + _GIB
        try:
            free = int((self._disk_free_fn or _disk_free)(folder))
        except Exception:  # noqa: BLE001 - unknown: let the capture try
            log.debug("free disk space unknown", exc_info=True)
            return
        if free < need:
            raise CaptureUnavailable(DISK_TEXT.format(mb=need // _MIB))

    def _free_path(self, folder: str, prefix: str, now: float) -> str:
        for step in range(60):
            name = prefix + time.strftime("%Y%m%d-%H%M%S", time.localtime(now + step)) + ".pcapng"
            path = os.path.join(folder, name)
            if not os.path.lexists(path):
                return path
        raise CaptureUnavailable(FAILED_TEXT)

    def start(self, *, adapter: Any, max_seconds: Any = DEFAULT_SECONDS, max_mb: Any = DEFAULT_MB) -> Dict[str, Any]:
        """Validate, start capturing on *adapter* and return the SESSION.

        An open session that is not capturing is replaced (its working file is discarded unless it was saved); a
        capture that is still running raises :class:`CaptureBusy`."""
        chosen = self._check_adapter(adapter)
        seconds = max_seconds if max_seconds in CAPTURE_SECONDS else None
        if seconds is None:
            raise ValueError(SECONDS_TEXT)
        size_mb = max_mb if max_mb in CAPTURE_SIZES_MB else None
        if size_mb is None:
            raise ValueError(SIZE_TEXT)
        cap = self._capability()
        if not cap["ok"]:
            raise CaptureUnavailable(cap["reason"] or FAILED_TEXT)
        with self._lock:
            if self._session is not None and self._session["state"] == "capturing":
                raise CaptureBusy(BUSY_TEXT)
        self._teardown(discard=True)

        folder = self._folder()
        try:
            (self._acl or winacl.secure_dir)(folder, winacl.CAPTURES_SDDL)
        except Exception as exc:  # noqa: BLE001 - fail closed on any failure
            log.warning("packet capture refused: the capture folder could not be secured (%s)", type(exc).__name__)
            log.debug("securing %s failed", folder, exc_info=True)
            raise CaptureUnavailable(FOLDER_TEXT) from exc
        self.enforce_retention(None)
        self._check_disk(folder, size_mb)

        now = float(self._clock())
        path = self._free_path(folder, WORK_PREFIX, now)
        etw = self._etw()
        trace = None
        try:
            fh = open(path, "wb")
        except OSError as exc:
            log.debug("could not open %s", path, exc_info=True)
            raise CaptureUnavailable(FOLDER_TEXT) from exc
        try:
            writer = pcapng.Writer(fh, linktype=1, if_name=chosen["name"])
            trace = etw.TraceSession(etw.session_name(),
                                     providers=((etw.NDIS_PACKET_CAPTURE_GUID, 5, 0xFFFFFFFFFFFFFFFF),))
            trace.start()
        except Exception as exc:  # noqa: BLE001
            try:
                fh.close()
            finally:
                _remove(path)
            if trace is not None:
                try:
                    trace.stop()
                except Exception:  # noqa: BLE001
                    pass
            log.warning("packet capture could not start (%s)", type(exc).__name__)
            log.debug("capture start failed", exc_info=True)
            raise CaptureUnavailable(str(exc) or FAILED_TEXT) from exc

        with self._lock:
            self._ring.clear()
            self._dropped = 0
            self._tracker = self._sip().CallTracker()
            self._queue = queue.Queue(self._queue_size)
            self._fh = fh
            self._writer = writer
            self._work_path = path
            self._read_path = path
            self._read_linktype = 1
            self._trace = trace
            self._wifi = bool(chosen.get("wifi"))
            self._if_index = chosen.get("index") if isinstance(chosen.get("index"), int) else None
            self._limit_seconds = int(seconds)
            self._limit_bytes = int(size_mb) * _MIB
            self._started_mono = float(self._monotonic())
            self._adapter_checked = self._started_mono
            self._stop_evt.clear()
            self._session = {
                "id": self._next_id, "state": "capturing", "source": "live", "adapter": dict(chosen),
                "file": None, "saved": False, "started_ts": now, "first_ts": None, "elapsed_s": 0.0, "packets": 0,
                "shown": 0, "bytes": writer.offset, "dropped": 0, "truncated": False, "calls": 0,
                "stop_reason": None, "error": None, "ts": now,
            }
            self._next_id += 1
            thread = threading.Thread(target=self._worker, name=THREAD_NAME, daemon=True)
            self._thread = thread
        thread.start()
        try:
            trace.consume(self._on_event)
        except Exception as exc:  # noqa: BLE001
            self._fail(str(exc) or FAILED_TEXT)
            raise CaptureUnavailable(str(exc) or FAILED_TEXT) from exc
        log.info("packet capture started on '%s': up to %d s, %d MB", chosen["name"], seconds, size_mb)
        self._publish()
        return self.session()

    # -- receiving -------------------------------------------------------------------------------------
    def _on_event(self, event: Dict[str, Any]) -> None:
        """The ETW consumer thread: decode the frame and hand it over. Never blocks, never raises."""
        try:
            frame = self._etw().decode_ndis_frame(event)
            if frame is None:
                return
            if self._if_index is not None and frame["if_index"] != self._if_index:
                return
            q = self._queue
            if q is None:
                return
            try:
                q.put_nowait((frame["ts"], frame["data"], frame["origlen"]))
            except queue.Full:
                self._drop()
        except Exception:  # noqa: BLE001 - a bad frame must never break the consumer
            self._drop()

    def _drop(self) -> None:
        with self._drop_lock:
            self._dropped += 1

    def _worker(self) -> None:
        """Writes every frame to the file, summarises it and feeds the SIP tracker; ends the capture at its limits."""
        dissect = self._dissect()
        sip = self._sip()
        last_tick = 0.0
        try:
            while not self._stop_evt.is_set():
                q = self._queue
                if q is None:
                    break
                try:
                    item = q.get(timeout=self._tick_s)
                except queue.Empty:
                    item = None
                now = float(self._monotonic())
                if item is not None:
                    self._ingest(item, dissect, sip)
                    # the size and packet limits are checked per packet, so a fast link stops on the byte it reaches
                    # the cap rather than up to a tick later
                    reason = self._limit_reached(now)
                    if reason:
                        self._finish(reason)
                        return
                if now - last_tick >= self._tick_s:
                    last_tick = now
                    reason = self._limit_reached(now) or self._adapter_gone(now)
                    if reason:
                        self._finish(reason)
                        return
                    self._publish()
        except Exception as exc:  # noqa: BLE001
            log.exception("the packet capture worker failed")
            self._fail(str(exc) or FAILED_TEXT)

    def _adapter_gone(self, now: float) -> Optional[str]:
        """``"adapter"`` once the adapter a capture runs on is no longer up (unplugged, disabled, a VPN taken down).

        Enumerating adapters is a Win32 call, so it happens every :data:`ADAPTER_CHECK_S`, not every tick.  An
        enumeration that fails tells us nothing and never ends a capture."""
        if now - self._adapter_checked < ADAPTER_CHECK_S:
            return None
        self._adapter_checked = now
        with self._lock:
            session = self._session
            wanted = (session.get("adapter") or {}).get("name") if session else None
        if not wanted:
            return None
        rows = self.adapters()
        if not rows:                                  # the enumeration failed, or nothing is up at this instant
            return None
        return None if any(row["name"] == wanted for row in rows) else "adapter"

    def _limit_reached(self, now: float) -> Optional[str]:
        if now - self._started_mono >= self._limit_seconds:
            return "seconds"
        writer = self._writer
        if writer is not None and writer.offset >= self._limit_bytes:
            return "size"
        if self._ring.total >= MAX_PACKETS:
            return "packets"
        return None

    def _ingest(self, item: Tuple[float, bytes, int], dissect: Any, sip: Any) -> None:
        ts, data, origlen = item
        if self._wifi:
            converted = pcapng.dot11_to_ethernet(data, origlen)
            if converted is not None:
                data, origlen = converted
        with self._lock:
            writer = self._writer
            if writer is None:
                return
            try:
                offset = writer.write_packet(ts, data, origlen)
            except (pcapng.PcapngError, OSError, ValueError):
                self._drop()
                return
            try:
                row = dissect.summarize(data, linktype=1, ts=ts, origlen=origlen)
            except Exception:  # noqa: BLE001 - an undissectable frame is still a row
                log.debug("dissecting a frame failed", exc_info=True)
                row = {"ts": ts, "src": "", "dst": "", "src_mac": "", "dst_mac": "", "proto": "UNKNOWN",
                       "sport": None, "dport": None, "length": origlen, "info": "", "layers": []}
            if self._session is not None and self._session["first_ts"] is None:
                self._session["first_ts"] = ts
            first = self._session["first_ts"] if self._session is not None else ts
            no = self._ring.total + 1
            self._ring.add(self._row(no, row, first), offset, row.get("layers") or ())
        self._track(row, ts, sip)

    def _row(self, no: int, summary: Dict[str, Any], first_ts: Optional[float]) -> Dict[str, Any]:
        ts = summary.get("ts")
        rel = 0.0 if ts is None or first_ts is None else round(max(0.0, float(ts) - float(first_ts)), 6)
        return {"no": no, "ts": ts, "rel": rel, "src": summary.get("src") or "", "dst": summary.get("dst") or "",
                "src_mac": summary.get("src_mac") or "", "dst_mac": summary.get("dst_mac") or "",
                "proto": summary.get("proto") or "UNKNOWN", "sport": summary.get("sport"),
                "dport": summary.get("dport"), "length": int(summary.get("length") or 0),
                "info": str(summary.get("info") or "")}

    def _track(self, summary: Dict[str, Any], ts: float, sip: Any) -> None:
        """SIP and RTP of one packet into the call tracker; a new call is published once. Never raises."""
        tracker = self._tracker
        if tracker is None:
            return
        layers = tuple(summary.get("layers") or ())
        if "SIP" not in layers and "RTP" not in layers:
            return
        try:
            payload = summary.get("payload")
            if payload is None:
                return
            src, dst = str(summary.get("src") or ""), str(summary.get("dst") or "")
            sport = int(summary.get("sport") or 0)
            dport = int(summary.get("dport") or 0)
            if "SIP" in layers:
                msg = sip.parse_sip(payload)
                if msg is not None:
                    found = tracker.add_sip(msg, ts, src, sport, dst, dport)
                    if found:
                        call = tracker.call(found)
                        if call is not None:
                            log.info("packet capture found a SIP call")
                            self._publish_call(call)
            else:
                rtp = sip.parse_rtp(payload)
                if rtp is not None:
                    tracker.add_rtp(rtp, ts, src, sport, dst, dport)
        except Exception:  # noqa: BLE001
            log.debug("SIP tracking failed for a packet", exc_info=True)

    # -- stopping --------------------------------------------------------------------------------------
    def _teardown(self, *, discard: bool) -> None:
        """Stop the ETW session and close the file; delete the working file when *discard* and it was not saved."""
        self._stop_evt.set()
        with self._lock:
            trace, thread = self._trace, self._thread
            fh, writer, path = self._fh, self._writer, self._work_path
            saved = bool(self._session and self._session.get("saved"))
            self._trace = None
            self._thread = None
            self._fh = None
            self._writer = None
        if trace is not None:
            try:
                trace.stop(STOP_JOIN_S)
            except Exception:  # noqa: BLE001
                log.debug("stopping the ETW session failed", exc_info=True)
        if thread is not None and thread is not threading.current_thread():
            thread.join(STOP_JOIN_S)
        if writer is not None:
            writer.flush()
        if fh is not None:
            try:
                fh.close()
            except OSError:
                log.debug("closing the capture file failed", exc_info=True)
        if discard and path and not saved:
            _remove(path)
            with self._lock:
                self._work_path = None
                if self._read_path == path:
                    self._read_path = None

    def _finish(self, reason: str) -> None:
        """End a running capture and keep what it captured (the file is still unsaved)."""
        self._teardown(discard=False)
        with self._lock:
            if self._session is not None and self._session["state"] == "capturing":
                self._session["state"] = "stopped"
                self._session["stop_reason"] = reason
                self._session["elapsed_s"] = round(max(0.0, float(self._monotonic()) - self._started_mono), 1)
                self._session["bytes"] = _size(self._work_path or "") or self._session["bytes"]
                self._session["ts"] = float(self._clock())
            total, dropped = self._ring.total, self._dropped
        log.info("packet capture stopped (%s): %d packet(s), %d dropped", reason, total, dropped)
        self._publish()

    def _fail(self, message: str) -> None:
        self._teardown(discard=True)
        with self._lock:
            if self._session is not None:
                self._session["state"] = "error"
                self._session["error"] = message
                self._session["ts"] = float(self._clock())
        self._publish()

    def stop(self) -> Optional[Dict[str, Any]]:
        """End the capture now and keep it (state ``stopped``); at once when nothing runs."""
        with self._lock:
            running = self._session is not None and self._session["state"] == "capturing"
        if running:
            self._finish("user")
        return self.session()

    def save(self) -> Dict[str, Any]:
        """Keep the open capture: rename its working file to a listed ``TNT-capture-...`` name.

        A capture that still runs is stopped first.  Saving one that was already saved, or one that was opened from a
        file, answers without doing anything."""
        with self._lock:
            if self._session is None:
                raise CaptureFileMissing(NOTHING_TEXT)
            if self._session["state"] == "capturing":
                running = True
            else:
                running = False
        if running:
            self._finish("user")
        with self._lock:
            session = self._session
            if session is None:
                raise CaptureFileMissing(NOTHING_TEXT)
            if session["source"] == "file" or session.get("saved"):
                return self.session()
            path = self._work_path
        if not path or not os.path.exists(path):
            raise CaptureFileMissing(FILE_MISSING_TEXT)
        folder = self._folder()
        final = self._free_path(folder, FILE_PREFIX, float(self._clock()))
        try:
            os.replace(path, final)
        except OSError as exc:
            log.warning("the capture could not be saved (%s)", type(exc).__name__)
            log.debug("renaming %s failed", path, exc_info=True)
            raise CaptureUnavailable(FAILED_TEXT) from exc
        with self._lock:
            self._work_path = final
            if self._read_path == path:
                self._read_path = final
            if self._session is not None:
                self._session["saved"] = True
                self._session["file"] = os.path.basename(final)
                self._session["ts"] = float(self._clock())
        self._files_changed()
        log.info("packet capture saved: %s bytes", _size(final))
        log.debug("capture saved as %s", os.path.basename(final))
        self.enforce_retention(None)
        self._publish()
        return self.session()

    def discard(self) -> None:
        """Throw the open capture away: its working file is deleted unless it was saved."""
        self._teardown(discard=True)
        with self._lock:
            self._session = None
            self._ring.clear()
            self._tracker = None
            self._dropped = 0
            self._read_path = None
            self._work_path = None
        self._publish()

    def close(self, timeout: float = STOP_JOIN_S) -> None:
        """Engine stop: end a running capture and let go of the ETW session. The working file is kept (recover()
        cleans it up next time). Never raises."""
        try:
            with self._lock:
                running = self._session is not None and self._session["state"] == "capturing"
            if running:
                self._finish("service")
            else:
                self._teardown(discard=False)
        except Exception:  # noqa: BLE001
            log.exception("closing the packet capture failed")

    # -- reading the list ------------------------------------------------------------------------------
    def _make_filter(self, ip: Any = None, mac: Any = None, protos: Any = None) -> _Filter:
        keys = ()
        if protos:
            known = getattr(self._dissect(), "PROTO_FILTERS", {})
            wanted = protos if isinstance(protos, (list, tuple, set)) else str(protos).split(",")
            keys = tuple(sorted({str(p).strip().lower() for p in wanted if str(p).strip().lower() in known}))
        return _Filter(_norm_ip(ip), _norm_mac(mac), keys)

    def _matches(self, index: int, flt: _Filter, table: Dict[str, Sequence[str]]) -> bool:
        row = self._ring.rows[index]
        if flt.ip and flt.ip != row["src"] and flt.ip != row["dst"]:
            return False
        if flt.mac and flt.mac != _norm_mac(row["src_mac"]) and flt.mac != _norm_mac(row["dst_mac"]):
            return False
        if flt.protos:
            layers = self._ring.layers[index]
            for key in flt.protos:
                names = table.get(key) or ()
                if row["proto"] in names or any(name in layers for name in names):
                    return True
            return False
        return True

    def packets(self, *, since: Any = None, limit: Any = DEFAULT_ROW_LIMIT, ip: Any = None, mac: Any = None,
                protos: Any = None) -> Dict[str, Any]:
        """The packet list (see the module docstring); never raises for a filter it cannot read (it is ignored)."""
        count = _whole(limit, DEFAULT_ROW_LIMIT, 1, MAX_ROW_LIMIT)
        flt = self._make_filter(ip, mac, protos)
        table = dict(getattr(self._dissect(), "PROTO_FILTERS", {}) or {})
        with self._lock:
            ring = self._ring
            dropped_before = False
            if since is None:
                start = 0
            else:
                after = _whole(since, 0, 0, 1 << 62)
                dropped_before = after + 1 < ring.first_no and ring.total > 0
                pos = after + 1 - ring.first_no
                start = max(0, pos)
            picked: List[Dict[str, Any]] = []
            matched = 0
            for index in range(start, len(ring.rows)):
                if not flt.empty and not self._matches(index, flt, table):
                    continue
                matched += 1
                picked.append(ring.rows[index])
            if since is None and len(picked) > count:
                picked = picked[-count:]
            elif len(picked) > count:
                picked = picked[:count]
            rows = [dict(r) for r in picked]
            last = rows[-1]["no"] if rows else (ring.first_no + len(ring.rows) - 1 if ring.rows else 0)
            return {"rows": rows, "total": ring.total, "shown": len(ring.rows), "matched": matched, "last": last,
                    "dropped_before": dropped_before, "session": self.session()}

    def packet(self, no: Any) -> Dict[str, Any]:
        """One packet's detail: ``{"row", "layers", "hex", "bytes"}``; :class:`CaptureFileMissing` when it is gone."""
        number = _whole(no, 0, 0, 1 << 62)
        with self._lock:
            index = self._ring.index_of(number)
            if index is None:
                raise CaptureFileMissing("That packet is no longer in the list")
            row = dict(self._ring.rows[index])
            offset = self._ring.offsets[index]
            path, linktype = self._read_path, self._read_linktype
            writer = self._writer
        if writer is not None:
            writer.flush()
        if not path:
            raise CaptureFileMissing(FILE_MISSING_TEXT)
        packet = pcapng.read_packet_at(path, offset, linktype=linktype)
        if packet is None:
            raise CaptureFileMissing("That packet could not be read back")
        data = packet["data"]
        dissect = self._dissect()
        try:
            layers = dissect.detail(data, linktype=linktype, ts=packet.get("ts"), origlen=packet.get("origlen"))
        except Exception:  # noqa: BLE001
            log.debug("dissecting a packet in detail failed", exc_info=True)
            layers = []
        try:
            dump = dissect.hex_dump(data)
        except Exception:  # noqa: BLE001
            dump = []
        return {"row": row, "layers": layers, "hex": dump, "bytes": len(data)}

    # -- SIP -------------------------------------------------------------------------------------------
    def calls(self) -> List[Dict[str, Any]]:
        """The SIP calls found so far, newest first; empty without a tracker."""
        tracker = self._tracker
        if tracker is None:
            return []
        try:
            return list(tracker.calls())
        except Exception:  # noqa: BLE001
            log.debug("listing the SIP calls failed", exc_info=True)
            return []

    def call_audio(self, call_id: Any) -> bytes:
        """One call's reconstructed audio as a WAV file; :class:`CaptureFileMissing` when there is none."""
        tracker = self._tracker
        if tracker is None:
            raise CaptureFileMissing(NOTHING_TEXT)
        try:
            wav = tracker.call_audio(str(call_id or ""))
        except Exception as exc:  # noqa: BLE001
            log.debug("rebuilding a call's audio failed", exc_info=True)
            raise CaptureFileMissing("That call's audio could not be rebuilt") from exc
        if not wav:
            raise CaptureFileMissing("That call has no audio TNT can play")
        return wav

    # -- files -----------------------------------------------------------------------------------------
    def _forget(self, name: str) -> None:
        with self._lock:
            for key in [k for k in self._counts if k[0] == name]:
                del self._counts[key]
            self._file_count_ts = 0.0

    def _files_changed(self) -> None:
        """A capture was saved or deleted: the next tile() counts the folder again instead of reusing its cache."""
        with self._lock:
            self._file_count_ts = 0.0

    def _count_file(self, path: str) -> Optional[int]:
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

    def open_file(self, name: Any) -> Dict[str, Any]:
        """Read one of TNT's own saved captures into the packet list and return the SESSION (source ``file``)."""
        path, st = self._resolve(name)
        return self._open(path, st, owned=True)

    def open_path(self, path: Any) -> Dict[str, Any]:
        """Read ANY capture file on this PC into the packet list: a capture from Wireshark, a switch, a colleague.

        *path* is an absolute local path (:func:`_check_open_path` for the rules and their texts).  The file is only
        ever read, never written or moved, and TNT does not take it over: :meth:`save` and :meth:`discard` leave a
        file opened this way exactly where it is."""
        resolved, st = self._check_open_path(path)
        return self._open(resolved, st, owned=False)

    def _check_open_path(self, path: Any) -> Tuple[str, os.stat_result]:
        """An absolute local path to a regular file TNT may read, and its ``lstat``; else :class:`ValueError` (a bad
        path) or :class:`CaptureFileMissing` (nothing readable there)."""
        text = path if isinstance(path, str) else ("" if path is None else str(path))
        text = text.strip().strip('"')
        if not text:
            raise ValueError(PATH_TEXT)
        if "\x00" in text or len(text) > MAX_PATH_LEN:
            raise ValueError(PATH_TEXT)
        if not os.path.isabs(text) or text.startswith("\\\\"):     # no relative path, and no UNC share
            raise ValueError(PATH_TEXT)
        try:
            resolved = os.path.realpath(text)
            st = os.lstat(resolved)
        except (OSError, ValueError):
            raise CaptureFileMissing(FILE_MISSING_TEXT) from None
        if not stat.S_ISREG(st.st_mode) or _is_link(st):
            raise CaptureFileMissing(FILE_MISSING_TEXT)
        if st.st_size > MAX_OPEN_BYTES:
            raise ValueError(PATH_BIG_TEXT.format(mb=MAX_OPEN_BYTES // _MIB))
        return resolved, st

    def _open(self, path: str, st: os.stat_result, *, owned: bool) -> Dict[str, Any]:
        """Index *path* into the packet list (the FIRST :data:`MAX_ROWS` packets; a file that holds more leaves the
        session ``truncated``).  *owned* is whether the file is one of TNT's own saved captures, which is what decides
        whether :meth:`discard` may delete it.  A capture that is still running is refused (:class:`CaptureBusy`)."""
        with self._lock:
            if self._session is not None and self._session["state"] == "capturing":
                raise CaptureBusy(BUSY_TEXT)
        self._teardown(discard=True)
        sip = self._sip()
        dissect = self._dissect()
        tracker = sip.CallTracker()
        ring = _Ring(self._ring.limit)
        first_ts: Optional[float] = None
        linktype = 1
        try:
            with open(path, "rb") as fileobj:
                for offset, packet in pcapng.iter_packets_with_offsets(fileobj, max_packets=ring.limit):
                    linktype = int(packet.get("linktype") or 1)
                    ts = packet.get("ts")
                    if first_ts is None and ts is not None:
                        first_ts = ts
                    try:
                        summary = dissect.summarize(packet["data"], linktype=linktype, ts=ts,
                                                    origlen=packet.get("origlen"))
                    except Exception:  # noqa: BLE001
                        continue
                    ring.add(self._row(ring.total + 1, summary, first_ts), offset, summary.get("layers") or ())
                    self._track_into(tracker, summary, ts, sip)
        except pcapng.PcapngError as exc:
            raise CaptureUnavailable(f"{os.path.basename(path)} is not a capture TNT can read") from exc
        except OSError as exc:
            raise CaptureFileMissing(FILE_MISSING_TEXT) from exc
        # the list holds the FIRST max_rows packets of the file; say so when the file has more, so "opened N packets"
        # is never read as "that is the whole capture" (counting is constant memory, whatever the file's size)
        if ring.total >= ring.limit:
            try:
                ring.truncated = pcapng.count_packets(path) > ring.total
            except (pcapng.PcapngError, OSError):
                log.debug("could not count %s after opening it", path, exc_info=True)
        now = float(self._clock())
        with self._lock:
            self._ring = ring
            self._tracker = tracker
            self._dropped = 0
            self._read_path = path
            self._read_linktype = linktype
            # only a capture of TNT's own may be deleted by discard(): a file the user pointed at is left alone
            self._work_path = path if owned else None
            self._session = {
                "id": self._next_id, "state": "loaded", "source": "file", "adapter": None,
                "file": os.path.basename(path), "saved": True, "started_ts": first_ts if first_ts is not None else now,
                "first_ts": first_ts, "elapsed_s": 0.0, "packets": ring.total, "shown": len(ring.rows),
                "bytes": st.st_size, "dropped": 0, "truncated": ring.truncated, "calls": 0, "stop_reason": None,
                "error": None, "ts": now,
            }
            self._next_id += 1
        log.info("opened a capture file: %d packet(s)", ring.total)
        log.debug("opened capture file %s", os.path.basename(path))
        self._publish()
        return self.session()

    def _track_into(self, tracker: Any, summary: Dict[str, Any], ts: Any, sip: Any) -> None:
        layers = tuple(summary.get("layers") or ())
        payload = summary.get("payload")
        if payload is None or ("SIP" not in layers and "RTP" not in layers):
            return
        try:
            src, dst = str(summary.get("src") or ""), str(summary.get("dst") or "")
            sport, dport = int(summary.get("sport") or 0), int(summary.get("dport") or 0)
            when = float(ts) if ts is not None else 0.0
            if "SIP" in layers:
                msg = sip.parse_sip(payload)
                if msg is not None:
                    tracker.add_sip(msg, when, src, sport, dst, dport)
            else:
                rtp = sip.parse_rtp(payload)
                if rtp is not None:
                    tracker.add_rtp(rtp, when, src, sport, dst, dport)
        except Exception:  # noqa: BLE001
            log.debug("SIP tracking failed for a packet of a saved capture", exc_info=True)

    def file_download(self, name: Any) -> Tuple[BinaryIO, int]:
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
        with self._lock:
            open_now = self._read_path and os.path.normcase(self._read_path) == os.path.normcase(path)
        if open_now:
            self.discard()
        try:
            os.remove(path)
        except PermissionError:
            raise CaptureFileBusy(FILE_BUSY_TEXT) from None
        except FileNotFoundError:
            raise CaptureFileMissing(FILE_MISSING_TEXT) from None
        self._forget(os.path.basename(path))
        log.info("packet capture file deleted")
        log.debug("deleted capture file %s", name)
        return self.files()

    def enforce_retention(self, now: Optional[float]) -> int:
        """Delete saved captures past the retention limits; the number deleted. Never raises for a file it cannot
        delete (it is tried again next time) or a missing folder. The capture that is open is never deleted."""
        folder = self._folder()
        if not os.path.isdir(folder):
            return 0
        reference = float(self._clock() if now is None else now)
        with self._lock:
            keep_open = os.path.normcase(self._read_path) if self._read_path else ""
        deleted = kept = total = 0
        over = False
        for row in self.files():
            path = os.path.join(folder, row["name"])
            if keep_open and os.path.normcase(path) == keep_open:
                kept += 1
                total += int(row["size"])
                continue
            old = reference - float(row["created_ts"]) > MAX_AGE_S
            if not old and not over and (kept >= MAX_FILES or total + int(row["size"]) > MAX_TOTAL_BYTES):
                over = True
            if old or over:
                try:
                    os.remove(path)
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
        """Engine start (helper thread): stop an ETW session a crash left behind, delete the working files it left,
        then count the saved captures that have no count yet. Never raises."""
        try:
            self._etw().stop_stale_sessions()
        except Exception:  # noqa: BLE001
            log.debug("stopping a stale ETW session failed", exc_info=True)
        try:
            folder = self._folder()
            left = 0
            for name in os.listdir(folder) if os.path.isdir(folder) else []:
                if _WORK_PATTERN.fullmatch(name):
                    _remove(os.path.join(folder, name))
                    left += 1
            if left:
                log.info("packet capture recovery deleted %d unsaved capture(s)", left)
        except OSError:
            log.debug("packet capture recovery could not list the folder", exc_info=True)
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
                self._publish()
        except Exception:  # noqa: BLE001
            log.exception("counting the packets of saved captures failed")
