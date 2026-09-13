r"""Which switch port am I on?  The switch's LLDP or CDP announcement, heard through Packet Monitor (ARCHITECTURE §3.24).

Windows keeps no LLDP neighbour table (its own LLDP agent only sends), so :class:`SwitchPortFinder` captures the
announcements itself on one wired adapter and decodes them with :mod:`tnt.pcapng` and :mod:`tnt.lldp`:

1. Packet Monitor filters ``TNT-LLDP -d 35020`` (ethertype 0x88CC) and ``TNT-CDP -m 01-00-0C-CC-CC-CC``
   (:data:`FILTERS`), a capture of that adapter's component with ``--pkt-size 0`` and ``-s 64`` into
   ``TNT-switchport-<YYYYmmdd-HHMMSS>.etl`` in the (secured) captures folder;
2. every ``poll_s`` the inbound counters: once a filtered frame came in, ``settle_s`` more, then stop, ``etl2pcap``
   and read the pcapng (in memory up to :data:`tnt.pcapng.MAX_IN_MEMORY`, else streamed);
3. neighbours come from :func:`tnt.lldp.neighbors_from_packets` with the adapter's own MAC left out (Windows' own
   LLDPDU is captured too), each one's ``vendor`` filled in from the chassis MAC's OUI (:func:`tnt.oui.vendor_for_mac`).
   Found: ``done``.  Heard only frames that name no neighbour: the capture starts again for
   the time left.  Counters that cannot be read: listen for the whole window and convert once.  Time up with nothing:
   ``done`` with no neighbours and :data:`NO_NEIGHBOR_TEXT`.

The ETL and pcapng are always deleted, the crash marker cleared and :data:`tnt.pktmon.LOCK` released when a listen
ends, however it ends.

Starting (:meth:`SwitchPortFinder.start`), in this order: Packet Monitor capability (:class:`PktmonUnavailable` with its
reason); the adapter (the named one, else the internet adapter when it is wired, else the first wired adapter: if_type 6,
physical, up); ``seconds`` (a whole number, clamped to ``min_seconds..max_seconds``); a listen already running
(``RuntimeError`` :data:`BUSY_TEXT`); the shared lock (:class:`PktmonBusy`); the captures folder secured with
``tnt.winacl.CAPTURES_SDDL`` (fails closed); the adapter's Packet Monitor component; the crash marker; then the worker
thread ``tnt-switchport`` runs the capture (a foreign Packet Monitor session or foreign filters end the job in ``error``).

Shapes (keys in this order, :data:`SWITCH_JOB_KEYS`, :data:`SWITCH_STATUS_KEYS`, :data:`WIRED_ADAPTER_KEYS`)::

    JOB    = {"state": "idle"|"listening"|"done"|"error"|"cancelled", "adapter": {"name", "index", "mac"}|None,
              "started_ts", "listen_s", "elapsed_s", "neighbors": [NEIGHBOR, ...], "error": str|None,
              "reason": str|None, "generation": int, "ts"}
    STATUS = {"job": JOB, "adapters": [{"name", "index", "mac", "is_internet"}], "available": bool,
              "reason": str|None}

``NEIGHBOR`` is :data:`tnt.lldp.NEIGHBOR_KEYS`.  ``reason`` is set on a ``done`` job that heard nobody; ``error`` on an
``error`` job.  Events: ``netcheck.switch`` ``{"job": JOB}`` on every state change and every ``poll_s`` while listening.

Kept results: the last finished (``done`` or ``error``) job per adapter MAC.  :meth:`SwitchPortFinder.job` is the
latest job, else the newest kept one, else an ``idle`` job.  :meth:`SwitchPortFinder.on_network_change` (network watcher
thread; quick, never raises) drops the kept results of another generation and the ones for adapters that are no longer
wired and up, and publishes; when the adapter being listened on is no longer up it cancels on the helper thread
``tnt-switchport-netstop``.  A generation change alone never cancels a listen.

Injectable knobs (keyword-only; None means the ``tnt.pktmon`` / ``tnt.netinfo`` / ``tnt.paths`` / ``tnt.winacl``
default): ``adapters_fn``, ``internet_nic_fn``, ``generation_fn`` (None: generation 0), ``runner``, ``clock``,
``monotonic``, ``wait(seconds) -> bool`` (True when cancelled; default an Event wait), ``session_running_fn``,
``filters_present_fn``, ``components_fn``, ``capability_fn``, ``work_dir_fn``, ``acl``, and the timers ``poll_s``,
``settle_s``, ``min_seconds``, ``max_seconds``.  The engine uses the defaults.

Contract gaps filled here:

* ``seconds`` None means :data:`DEFAULT_SECONDS`; a float with no fraction counts as whole.  An adapter name that is
  not a string gets the unknown-adapter ``ValueError``.
* A crash marker that cannot be written fails the start like an unsecured folder (no capture runs without one).
* :meth:`SwitchPortFinder.stop` cancels and waits up to :data:`STOP_WAIT_S` for the worker; a job still listening then
  is marked ``cancelled`` at once (the worker finishes the clean-up and keeps the lock until it is done).
* A restarted capture counts as "heard" only when the inbound counter passes the value that ended the previous round,
  so counters that are not reset by ``pktmon start`` cannot loop.
* A finished job carries the generation current when it ended.  A listen that was cancelled (or failed because of the
  cancellation) ends ``cancelled``; an unreadable capture ends ``error`` with :data:`READ_ERROR_TEXT`, anything
  unexpected with :data:`FAILED_TEXT`.
* A cancellation wins: a stop during the conversion ends ``cancelled`` although the conversion finishes, and a job
  :meth:`SwitchPortFinder.stop` already answered ``cancelled`` stays so (nothing is kept).  The
  ``tnt-switchport-netstop`` helper cancels only the listen it was started for, and a network change whose adapters
  cannot be enumerated drops and cancels nothing for being down.

Logging: INFO carries adapter names, states, counts and durations; file names and neighbour details are DEBUG.
"""
from __future__ import annotations

import copy
import importlib
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import lldp, oui, paths, pcapng, pktmon, winacl
from .pktmon import PktmonBusy, PktmonUnavailable

log = logging.getLogger(__name__)

__all__ = [
    "SwitchPortFinder", "SWITCH_JOB_KEYS", "SWITCH_STATUS_KEYS", "JOB_ADAPTER_KEYS", "WIRED_ADAPTER_KEYS",
    "JOB_STATES", "DEFAULT_SECONDS", "FILTERS", "FILE_SIZE_MB", "PKT_SIZE", "STOP_WAIT_S", "EVENT", "THREAD_NAME",
    "NETSTOP_THREAD_NAME", "NO_WIRED_TEXT", "BUSY_TEXT", "NO_NEIGHBOR_TEXT", "READ_ERROR_TEXT", "FAILED_TEXT",
]

SWITCH_JOB_KEYS = ("state", "adapter", "started_ts", "listen_s", "elapsed_s", "neighbors", "error", "reason",
                   "generation", "ts")
SWITCH_STATUS_KEYS = ("job", "adapters", "available", "reason")
JOB_ADAPTER_KEYS = ("name", "index", "mac")
WIRED_ADAPTER_KEYS = ("name", "index", "mac", "is_internet")
JOB_STATES = ("idle", "listening", "done", "error", "cancelled")

DEFAULT_SECONDS = 65                      # LLDP every 30 s, CDP every 60 s
FILTERS = (("TNT-LLDP", "-d", "35020"), ("TNT-CDP", "-m", "01-00-0C-CC-CC-CC"))
FILE_SIZE_MB = 64
PKT_SIZE = 0                              # whole frames
STOP_WAIT_S = 3.0                         # stop() waits this long for the worker's clean-up
IF_TYPE_ETHERNET = 6
FILE_PREFIX = "TNT-switchport-"
EVENT = "netcheck.switch"
THREAD_NAME = "tnt-switchport"
NETSTOP_THREAD_NAME = "tnt-switchport-netstop"

NO_WIRED_TEXT = "Needs a wired (Ethernet) connection"
BUSY_TEXT = "a switch port search is already running"
NO_NEIGHBOR_TEXT = ("No LLDP or CDP heard in {seconds} s. The switch may not send them (unmanaged switches never do), "
                    "or LLDP is turned off on its port.")
READ_ERROR_TEXT = "The capture could not be read"
FAILED_TEXT = "The switch port search failed"


class _Failure(RuntimeError):
    """A failure whose text is shown on the job as it is."""


def _field(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


def _is_wired_up(adapter: Any) -> bool:
    return (_field(adapter, "if_type") == IF_TYPE_ETHERNET and bool(_field(adapter, "is_physical"))
            and _field(adapter, "status") == "up")


def _same_mac(a: Any, b: Any) -> bool:
    ma = oui.normalize_mac(str(a or ""))
    return ma is not None and ma == oui.normalize_mac(str(b or ""))


class _Listen:
    """One listen: what the worker needs and the job dict it updates."""

    __slots__ = ("job", "adapter", "comp_id", "listen_s", "work_dir", "etl", "pcapng", "started_mono", "session")

    def __init__(self, job: Dict[str, Any], adapter: Dict[str, Any], comp_id: int, listen_s: int, work_dir: str,
                 stem: str, started_mono: float) -> None:
        self.job = job
        self.adapter = adapter
        self.comp_id = comp_id
        self.listen_s = listen_s
        self.work_dir = work_dir
        self.etl = os.path.join(work_dir, stem + ".etl")
        self.pcapng = os.path.join(work_dir, stem + ".pcapng")
        self.started_mono = started_mono
        self.session: Optional[pktmon.PktmonSession] = None


class SwitchPortFinder:
    """The engine component behind ``GET``/``POST``/``DELETE /api/netcheck/switch`` (see the module docstring)."""

    def __init__(self, bus: Any, *, adapters_fn: Optional[Callable[[], Sequence[Any]]] = None,
                 internet_nic_fn: Optional[Callable[[], Any]] = None,
                 generation_fn: Optional[Callable[[], int]] = None, runner: Optional[Callable[..., Any]] = None,
                 clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic,
                 wait: Optional[Callable[[float], bool]] = None,
                 session_running_fn: Optional[Callable[[], Optional[bool]]] = None,
                 filters_present_fn: Optional[Callable[[], Optional[bool]]] = None,
                 components_fn: Optional[Callable[[], List[Dict[str, Any]]]] = None,
                 capability_fn: Optional[Callable[[], Dict[str, Any]]] = None,
                 work_dir_fn: Optional[Callable[[], Any]] = None, acl: Optional[Callable[[str, str], None]] = None,
                 poll_s: float = 2.0, settle_s: float = 1.0, min_seconds: int = 20, max_seconds: int = 120) -> None:
        self._bus = bus
        self._adapters_fn = adapters_fn
        self._internet_nic_fn = internet_nic_fn
        self._generation_fn = generation_fn
        self._runner = runner
        self._clock = clock
        self._monotonic = monotonic
        self._session_running_fn = session_running_fn
        self._filters_present_fn = filters_present_fn
        self._components_fn = components_fn
        self._capability_fn = capability_fn
        self._work_dir_fn = work_dir_fn
        self._acl = acl
        self._poll_s = float(poll_s)
        self._settle_s = float(settle_s)
        self._min_seconds = int(min_seconds)
        self._max_seconds = int(max_seconds)
        self._lock = threading.Lock()             # job state
        self._pub_lock = threading.Lock()         # a snapshot and its publish go out together
        self._cancel = threading.Event()
        self._wait = wait if wait is not None else self._cancel.wait
        self._current: Optional[Dict[str, Any]] = None
        self._kept: Dict[str, Dict[str, Any]] = {}  # normalised adapter MAC -> last finished job
        self._thread: Optional[threading.Thread] = None

    # -- collaborators ---------------------------------------------------------------------------------
    def _adapters(self) -> List[Any]:
        return self._adapter_pool() or []

    def _adapter_pool(self) -> Optional[List[Any]]:
        """Every adapter, or None when they cannot be enumerated."""
        try:
            if self._adapters_fn is not None:
                return list(self._adapters_fn() or [])
            return list(importlib.import_module("tnt.netinfo").get_adapters())
        except Exception:  # noqa: BLE001
            log.debug("adapter enumeration failed", exc_info=True)
            return None

    def _internet_nic(self) -> Any:
        try:
            if self._internet_nic_fn is not None:
                return self._internet_nic_fn()
            return importlib.import_module("tnt.netinfo").get_internet_nic()
        except Exception:  # noqa: BLE001
            log.debug("internet adapter lookup failed", exc_info=True)
            return None

    def _generation(self) -> int:
        try:
            value = self._generation_fn() if self._generation_fn is not None else 0
            return int(value or 0)
        except Exception:  # noqa: BLE001
            return 0

    def _capability(self) -> Dict[str, Any]:
        cap = (self._capability_fn or pktmon.capability)() or {}
        return {"ok": bool(cap.get("ok")), "reason": cap.get("reason")}

    def _components(self) -> List[Dict[str, Any]]:
        if self._components_fn is not None:
            return list(self._components_fn() or [])
        return pktmon.list_components(self._runner)

    def _work_dir(self) -> str:
        return os.fspath(self._work_dir_fn() if self._work_dir_fn is not None else paths.captures_dir())

    def _publish(self) -> None:
        if self._bus is None:
            return
        with self._pub_lock:
            try:
                self._bus.publish(EVENT, {"job": self.job()})
            except Exception:  # noqa: BLE001
                log.exception("publishing %s failed", EVENT)

    # -- views -----------------------------------------------------------------------------------------
    def _idle_job(self) -> Dict[str, Any]:
        job: Dict[str, Any] = dict.fromkeys(SWITCH_JOB_KEYS)
        job.update(state="idle", neighbors=[], generation=self._generation())
        return job

    def job(self) -> Dict[str, Any]:
        """The latest job, else the newest kept one, else an ``idle`` job (a copy)."""
        with self._lock:
            if self._current is not None:
                return copy.deepcopy(self._current)
            if self._kept:
                return copy.deepcopy(max(self._kept.values(), key=lambda j: j.get("ts") or 0.0))
        return self._idle_job()

    def wired_adapters(self) -> List[Dict[str, Any]]:
        """Adapters a switch port can be looked up on: Ethernet (if_type 6), physical, up."""
        pool = [a for a in self._adapters() if _is_wired_up(a)]
        if not pool:
            return []
        nic = self._internet_nic()
        nic_index = _field(nic, "index") if nic is not None else None
        return [{"name": str(_field(a, "name") or ""), "index": _field(a, "index"), "mac": str(_field(a, "mac") or ""),
                 "is_internet": nic_index is not None and _field(a, "index") == nic_index} for a in pool]

    def status(self) -> Dict[str, Any]:
        cap = self._capability()
        return {"job": self.job(), "adapters": self.wired_adapters(), "available": cap["ok"],
                "reason": None if cap["ok"] else cap["reason"]}

    # -- starting --------------------------------------------------------------------------------------
    def _pick_adapter(self, adapter: Any, wired: List[Dict[str, Any]]) -> Dict[str, Any]:
        if adapter is not None and not isinstance(adapter, str):
            raise ValueError(f"adapter '{str(adapter)[:40]}' is not a wired adapter that is up")
        name = (adapter or "").strip()
        if name:
            for a in wired:
                if a["name"] == name:
                    return a
            raise ValueError(f"adapter '{name[:40]}' is not a wired adapter that is up")
        if not wired:
            raise PktmonUnavailable(NO_WIRED_TEXT)
        return next((a for a in wired if a["is_internet"]), wired[0])

    def _listen_seconds(self, seconds: Any) -> int:
        if seconds is None:
            seconds = DEFAULT_SECONDS
        whole = isinstance(seconds, int) and not isinstance(seconds, bool)
        if isinstance(seconds, float) and seconds.is_integer():
            whole = True
        if not whole:
            raise ValueError(f"seconds must be a whole number from {self._min_seconds} to {self._max_seconds}")
        return max(self._min_seconds, min(self._max_seconds, int(seconds)))

    def start(self, adapter: Optional[str] = None, seconds: Any = DEFAULT_SECONDS) -> Dict[str, Any]:
        """Start listening for the switch on a wired adapter and return the ``listening`` JOB (see the module
        docstring for the order of the checks and their errors)."""
        cap = self._capability()
        if not cap["ok"]:
            raise PktmonUnavailable(cap["reason"] or pktmon.TOO_OLD_REASON)
        chosen = self._pick_adapter(adapter, self.wired_adapters())
        listen_s = self._listen_seconds(seconds)
        with self._lock:
            if self._current is not None and self._current.get("state") == "listening":
                raise RuntimeError(BUSY_TEXT)
        pktmon.LOCK.acquire("switchport")
        work_dir: Optional[str] = None
        marker = handed_off = False
        try:
            work_dir = self._work_dir()
            try:
                (self._acl or winacl.secure_dir)(work_dir, winacl.CAPTURES_SDDL)
            except Exception as exc:  # noqa: BLE001 - fail closed on any failure
                log.warning("switch port search refused: the capture folder could not be secured (%s)",
                            type(exc).__name__)
                log.debug("securing %s failed", work_dir, exc_info=True)
                raise PktmonUnavailable(pktmon.FOLDER_NOT_SECURED_TEXT) from exc
            comp_id = pktmon.component_for(chosen, self._components())
            if comp_id is None:
                raise PktmonUnavailable(pktmon.NOT_LISTED_TEXT)
            now = float(self._clock())
            stem = FILE_PREFIX + time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
            try:
                pktmon.write_marker(work_dir, {"purpose": "switchport", "files": [stem + ".etl", stem + ".pcapng"],
                                               "started_ts": now})
                marker = True
            except OSError as exc:
                log.debug("writing the Packet Monitor session marker failed", exc_info=True)
                raise PktmonUnavailable(pktmon.FOLDER_NOT_SECURED_TEXT) from exc
            job: Dict[str, Any] = {
                "state": "listening",
                "adapter": {k: chosen[k] for k in JOB_ADAPTER_KEYS},
                "started_ts": now,
                "listen_s": listen_s,
                "elapsed_s": 0.0,
                "neighbors": [],
                "error": None,
                "reason": None,
                "generation": self._generation(),
                "ts": now,
            }
            ctx = _Listen(job, dict(chosen), comp_id, listen_s, work_dir, stem, float(self._monotonic()))
            thread = threading.Thread(target=self._worker, args=(ctx,), name=THREAD_NAME, daemon=True)
            with self._lock:
                self._cancel.clear()
                self._current = job
                self._thread = thread
                started = copy.deepcopy(job)               # the answer is the listen as it began
            try:
                thread.start()
            except BaseException:
                with self._lock:
                    job.update(state="error", error=FAILED_TEXT)
                raise
            handed_off = True
        finally:
            if not handed_off:
                if marker and work_dir is not None:
                    pktmon.clear_marker(work_dir)
                pktmon.LOCK.release()
        log.info("switch port search started on '%s' for %d s", chosen["name"], listen_s)
        self._publish()
        return started

    # -- the listen ------------------------------------------------------------------------------------
    def _sleep(self, seconds: float) -> bool:
        """Wait; True when the listen was cancelled."""
        return bool(self._wait(max(0.0, seconds))) or self._cancel.is_set()

    def _progress(self, ctx: _Listen) -> None:
        elapsed = round(max(0.0, float(self._monotonic()) - ctx.started_mono), 1)
        now = float(self._clock())
        with self._lock:
            if ctx.job.get("state") != "listening":
                return
            ctx.job.update(elapsed_s=elapsed, ts=now)
        self._publish()

    def _remove_files(self, ctx: _Listen) -> None:
        for path in (ctx.etl, ctx.pcapng):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            except OSError:
                log.debug("could not delete %s", path, exc_info=True)

    @staticmethod
    def _add_vendors(neighbors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fill each neighbour's ``vendor`` from the chassis MAC's OUI (None when the chassis id is not a MAC)."""
        for neighbor in neighbors:
            chassis = neighbor.get("chassis_id")
            neighbor["vendor"] = oui.vendor_for_mac(chassis) if oui.normalize_mac(str(chassis or "")) else None
        return neighbors

    def _read_neighbors(self, ctx: _Listen) -> List[Dict[str, Any]]:
        mac = ctx.adapter.get("mac") or None
        try:
            if os.path.getsize(ctx.pcapng) <= pcapng.MAX_IN_MEMORY:
                with open(ctx.pcapng, "rb") as fh:
                    packets = pcapng.read_packets(fh.read())
                return self._add_vendors(lldp.neighbors_from_packets(packets, own_mac=mac))
            with open(ctx.pcapng, "rb") as fh:
                return self._add_vendors(lldp.neighbors_from_packets(pcapng.iter_packets(fh), own_mac=mac))
        except (OSError, pcapng.PcapngError) as exc:
            log.warning("the switch port capture could not be read (%s)", type(exc).__name__)
            log.debug("reading %s failed", ctx.pcapng, exc_info=True)
            raise _Failure(READ_ERROR_TEXT) from exc

    def _listen(self, ctx: _Listen) -> Tuple[str, List[Dict[str, Any]], Optional[str]]:
        """``(state, neighbors, reason)`` of one listen; raises on a failure."""
        deadline = ctx.started_mono + ctx.listen_s
        baseline = 0
        while True:
            if self._cancel.is_set():
                return "cancelled", [], None
            session = pktmon.PktmonSession(comp_id=ctx.comp_id, filters=FILTERS, etl_path=ctx.etl,
                                           size_mb=FILE_SIZE_MB, pkt_size=PKT_SIZE, runner=self._runner,
                                           session_running_fn=self._session_running_fn,
                                           filters_present_fn=self._filters_present_fn)
            ctx.session = session
            session.start()
            heard = False
            counters = True
            while True:
                left = deadline - float(self._monotonic())
                if left <= 0:
                    break
                if self._sleep(min(self._poll_s, left)):
                    return "cancelled", [], None
                self._progress(ctx)
                if not counters:
                    continue
                count = session.inbound()
                if self._cancel.is_set():
                    return "cancelled", [], None
                if count is None:
                    counters = False
                    log.debug("Packet Monitor counters could not be read: listening for the whole window")
                elif count > baseline:
                    heard, baseline = True, count
                    break
            if heard and self._sleep(self._settle_s):
                return "cancelled", [], None
            session.stop()
            if self._cancel.is_set():
                return "cancelled", [], None
            converted = session.convert(ctx.pcapng, component_id=ctx.comp_id)
            if self._cancel.is_set():
                return "cancelled", [], None            # a stop() during the conversion wins over its result
            if not converted:
                raise _Failure(session.last_error or pktmon.failure_text("convert", 0))
            neighbors = self._read_neighbors(ctx)
            self._remove_files(ctx)
            if neighbors:
                return "done", neighbors, None
            if not heard or float(self._monotonic()) >= deadline:
                return "done", [], NO_NEIGHBOR_TEXT.format(seconds=ctx.listen_s)
            log.debug("the frames heard named no neighbour: listening again for the time left")

    def _worker(self, ctx: _Listen) -> None:
        state, neighbors, error, reason = "error", [], None, None
        try:
            state, neighbors, reason = self._listen(ctx)
        except (PktmonBusy, PktmonUnavailable, _Failure) as exc:
            error = str(exc)
        except Exception as exc:  # noqa: BLE001
            log.error("switch port search failed (%s)", type(exc).__name__)
            log.debug("switch port search failure", exc_info=True)
            error = FAILED_TEXT
        finally:
            try:
                if ctx.session is not None:
                    ctx.session.cleanup()
                self._remove_files(ctx)
                pktmon.clear_marker(ctx.work_dir)
            except Exception:  # noqa: BLE001
                log.exception("cleaning up after the switch port search failed")
            if state == "error" and self._cancel.is_set():
                state, error = "cancelled", None
            elapsed = round(max(0.0, float(self._monotonic()) - ctx.started_mono), 1)
            generation = self._generation()
            now = float(self._clock())
            with self._lock:
                if ctx.job.get("state") == "cancelled":        # stop() already answered "cancelled": it stays so
                    state, neighbors, error, reason = "cancelled", [], None, None
                ctx.job.update(state=state, neighbors=neighbors, error=error, reason=reason, elapsed_s=elapsed,
                               generation=generation, ts=now)
                mac = oui.normalize_mac(str(ctx.adapter.get("mac") or "")) or str(ctx.adapter.get("name"))
                if state in ("done", "error"):
                    self._kept[mac] = copy.deepcopy(ctx.job)
            pktmon.LOCK.release()
            log.info("switch port search on '%s' ended %s: %d neighbour(s) in %.0f s", ctx.adapter.get("name"), state,
                     len(neighbors), elapsed)
            self._publish()

    # -- stopping --------------------------------------------------------------------------------------
    def stop(self) -> Dict[str, Any]:
        """Cancel a listen (nothing is kept) and return the JOB.  At once when nothing listens."""
        return self._cancel_listen(None)

    def _cancel_listen(self, only: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """:meth:`stop`; with *only* (a job dict), cancel that listen and never a later one."""
        with self._lock:
            job, thread = self._current, self._thread
            listening = job is not None and job.get("state") == "listening" and (only is None or job is only)
        if not listening:
            return self.job()
        self._cancel.set()
        if thread is not None and thread is not threading.current_thread() and thread.is_alive():
            thread.join(STOP_WAIT_S)
        changed = False
        now = float(self._clock())
        with self._lock:
            if job.get("state") == "listening":
                job.update(state="cancelled", ts=now)
                changed = True
        if changed:
            self._publish()
        return self.job()

    def on_network_change(self, data: Any = None) -> None:
        """``net.changed`` (network watcher thread; quick, never raises): see the module docstring."""
        try:
            gen = data.get("generation") if isinstance(data, dict) else None
            if isinstance(gen, bool) or not isinstance(gen, int):
                gen = self._generation()
            with self._lock:
                cur = self._current
                listening = cur if cur is not None and cur.get("state") == "listening" else None
                check = listening is not None or bool(self._kept) or cur is not None
            found = self._adapter_pool() if check else []
            pool = None if found is None else [a for a in found if _is_wired_up(a)]

            def up(adapter: Optional[Dict[str, Any]]) -> bool:
                if pool is None:
                    return True            # adapters unknown: nothing is dropped or cancelled for being down
                if not adapter:
                    return False
                if adapter.get("mac") and oui.normalize_mac(str(adapter["mac"])):
                    return any(_same_mac(_field(a, "mac"), adapter["mac"]) for a in pool)
                return any(_field(a, "index") == adapter.get("index") for a in pool)

            changed = False
            with self._lock:
                for mac, kept in list(self._kept.items()):
                    if kept.get("generation") != gen or not up(kept.get("adapter")):
                        del self._kept[mac]
                        changed = True
                cur = self._current
                if cur is not None and cur.get("state") != "listening" and (
                        cur.get("generation") != gen or not up(cur.get("adapter"))):
                    self._current = None
                    changed = True
            if listening is not None and not up(listening.get("adapter")):
                log.info("switch port search stopping: '%s' is no longer up",
                         (listening.get("adapter") or {}).get("name"))
                threading.Thread(target=self._stop_for_network, args=(listening,), name=NETSTOP_THREAD_NAME,
                                 daemon=True).start()
            if changed:
                self._publish()
        except Exception:  # noqa: BLE001
            log.exception("handling a network change in the switch port finder failed")

    def _stop_for_network(self, job: Dict[str, Any]) -> None:
        """``tnt-switchport-netstop``: cancel the listen whose adapter went down (not one started since)."""
        try:
            self._cancel_listen(job)
        except Exception:  # noqa: BLE001
            log.exception("stopping the switch port search after a network change failed")

    def close(self, timeout: float) -> None:
        """Engine stop: cancel a listen and wait up to *timeout* for its clean-up.  At once when idle (no pktmon
        command runs)."""
        with self._lock:
            thread = self._thread
        if thread is None or not thread.is_alive():
            return
        self._cancel.set()
        if thread is not threading.current_thread():
            thread.join(max(0.0, float(timeout)))
