"""The service engine: owns and supervises every component.

Start order: ``ensure_dirs -> logging -> config -> db -> bus -> close stale outages /
gap row -> dhcp-restore (undo a NIC re-address left behind by a previous run) ->
IcmpPinger -> PingManager -> LinkMap -> GeoIpManager (IP location data: loads the installed
data, its thread downloads) -> NatChecker -> PortChecker -> OutageTracker -> SpeedScheduler ->
DiscoveryScanner -> DhcpServer (constructed, never started by itself) -> TftpServer
(constructed, its folder secured) -> LanPeers (beacon + throughput server, started) ->
SwitchPortFinder -> CaptureManager (an ETW session and an unsaved capture a crash left behind cleaned up
on a thread) ->
NetWatcher (network-change watcher, started) -> ReportManager (Full Scan site reports) ->
ApiServer -> maintenance thread (heartbeat + retention)``.

Every sibling module is imported lazily inside :meth:`Engine.start` and wrapped in
``try/except``: a missing or broken module disables *that* feature (the attribute
stays ``None`` and the API answers ``503 unavailable`` for its routes) instead of
killing the service.  Failures are recorded in :attr:`Engine.errors` for the
diagnostics view.

Contract gaps resolved here (documented deviations):

* ``Engine(port=...)`` is used directly for the API bind and is **never** written
  into ``config`` (not even in memory): ``Config.update`` persists the whole
  in-memory config on the next ``PUT /api/settings``, so a console run on 7135
  against the service's data dir would otherwise silently re-point the installed
  service at the dev port.  ``config.api.port`` therefore keeps describing the
  service; the live port is ``engine.api.port`` (also shown by diagnostics).  This
  also lets tests use port ``0`` (ephemeral), which the config clamp forbids.
* ``Engine(data_dir=...)`` sets ``TNT_DATA_DIR`` before any path is resolved.
* On the very first run (no targets in the DB and no ``defaults_loaded`` meta key)
  the default targets are loaded through ``PingManager.load_defaults()`` so a fresh
  install monitors something from boot without anyone opening the UI.
* Retention runs on the maintenance thread right after start (so ``start()`` stays
  fast) and then daily at 03:15 local; ``db.vacuum()`` runs on the scheduled run
  when the local weekday is Sunday.
* ``OutageTracker`` is skipped (``None``) when the ping manager is unavailable
  since it cannot work without samples.
* :meth:`Engine.stop` runs each component's ``stop()`` (and the final database
  writes + ``close()``) on a helper thread joined with the remaining share of the
  8 s budget, so one misbehaving component - or a VACUUM holding the db lock -
  cannot hold the service shutdown.
* :meth:`Engine.discovery_cancel` sets the scan's cancel event and calls the
  scanner's own ``stop()`` on a helper thread with a 1 s bounded wait: that
  method waits up to 5 s for the scan to finish, which neither an API request nor
  ``stop()`` may hang on.  ``discovery.done`` reports the actual end of the scan.
* The maintenance thread re-anchors its heartbeat / 03:15 schedule when the wall
  clock is stepped backwards (otherwise it would go silent for the length of the
  jump and the next start would record a spurious monitoring gap).
* Extra events: ``discovery.start`` ``{range, ports}`` and ``monitoring.paused``
  ``{paused}`` are published in addition to the contract's events.
* The DHCP server tool (``tnt.dhcp.DhcpServer``, ``engine.dhcp``) is only *constructed*
  at start; it listens only after ``POST /api/dhcp/start`` and is therefore off after
  every service start.  ``dhcp-restore`` runs before the pinger so that an adapter the
  previous run switched to a static address (recorded in db meta ``dhcp.nic_changed``)
  is back on DHCP before anything resolves the gateway.  The program path handed to the
  firewall rule is the frozen ``TNTService.exe`` or, in dev, the *base* interpreter
  (``sys._base_executable``): the venv ``python.exe`` is only a launcher and Windows
  Firewall matches the process image that really runs.
* The LAN peer service (``tnt.lanpeers.LanPeers``, ``engine.lan``) *is* started at start
  (unless ``lan.enabled`` is off): it announces this install on UDP 7132 and runs the
  throughput server on TCP 7133, ensuring its two firewall rules with the same program
  path as the DHCP tool.  It does not need the database (its peer id then lives in memory
  only), so it is not part of the db retry.  ``stop()`` stops it right after the DHCP
  server, before the pinger goes (a latency ping may be in flight).
* The network watcher (``tnt.netwatch.NetWatcher``, ``engine.netwatch``) starts after every
  component it notifies and after dhcp-restore, so its reference state already includes an
  adapter that step put back on DHCP (the lease returning for it is labelled as TNT's own).
  For each ``net.changed``, :meth:`Engine._on_net_changed` runs on the watcher thread *before*
  the bus gets the event: it drops the 10 s status netinfo cache and the 30 s discovery
  default-range cache, calls ``on_network_change(data)`` on the ping manager, outage tracker,
  link map, LAN peers and DHCP server, marks a running discovery scan (``network_changed`` in
  ``discovery.done``) and writes an ``info``/``network`` events row "network changed:
  <summary>" stamped with the event's ``ts`` on a helper thread (a locked database never holds
  the event back).  A network that keeps flapping writes at most one row per
  :data:`Engine.NET_EVENT_ROW_GAP_S` (60 s): the changes in between become one row "network
  changed N more times, now: <summary>" at the end of that minute.  The outage tracker gets a
  live default-gateway lookup (``gateway_fn``) for the notes of outages that cross a change.  A
  ``system sleep`` monitoring gap makes the watcher look at once and every second for a
  minute.  ``stop()`` stops the watcher first, before anything it notifies.  It needs no
  database; a failure to start is ``errors["netwatch"]`` and ``/api/status`` then reports
  generation 0.
* The site reports manager (``tnt.reports.ReportManager``, ``engine.reports``) starts after the
  network watcher (it compares the network with the "joined this network" marker it keeps in db
  meta ``net.joined``) and before the API.  It needs the database: without one it is
  ``errors["reports"] = "database unavailable"`` and the db retry loop brings it up.  It gets
  ``net.changed`` after the other consumers, drives ``engine.speed`` and :meth:`discovery_start`
  for a Full Scan (:meth:`discovery_running` tells it whether a scan it waits for still runs) and
  is stopped first in ``stop()`` (a running Full Scan is cancelled and saves nothing).
* The network tracker (``tnt.networks.NetworkTracker``, ``engine.networks``, ARCHITECTURE 3.20) starts right after the bus,
  before the stale-outage housekeeping and every writer: it identifies the network synchronously, so the first ping minute is
  tagged.  The gap of the time the service was stopped is tagged with the network the previous run was on
  (``NetworkTracker.previous_id``); a start on another network records that time as a spell of the previous network ending on
  the new one (travel), so the gap is left out of the previous site's report.  ``PingManager``, ``OutageTracker`` and ``SpeedScheduler`` get ``network_fn`` (an
  attribute read of the current id); :meth:`discovery_start` captures it for the run; the outage tracker and the report
  manager listen for id changes.  ``_on_net_changed`` tells the tracker first, before any other consumer; the heartbeat calls
  ``touch()``; ``stop()`` stops it after the network watcher.  Without a database (or when the networks migration did not
  run) nothing is tagged: ``errors["networks"]`` / the tracker idles, and the db retry loop starts it.
* The IP location manager (``tnt.geoip.GeoIpManager``, ``engine.geoip``) starts right after the link map.  It needs no
  database, is not part of the db retry, and its ``start()`` only starts the ``tnt-geoip`` thread (the first download
  check waits ``FIRST_CHECK_DELAY_S``).  ``stop()`` stops it right after the link map.  A failure leaves ``engine.geoip``
  None with ``errors["geoip"]``; ``status.geoip`` is then null and ``/api/geoip`` answers 503.
* :meth:`Engine.ip_release_renew` (the top bar's IP Release/Renew, ``tnt.nettools.release_renew``) runs one at a time
  (a second call is ``RuntimeError`` "already running", the API's 409).  It pauses monitoring for the seconds without
  an address when it is not paused already, so that time is a monitoring gap and not an outage, and resumes only what
  it paused; afterwards it drops the netinfo caches and makes the network watcher look at once.  The change is not
  labelled with ``NetWatcher.note_own_change``: that marker is the DHCP server tool's (``cause`` ``dhcp`` makes the
  network tracker count the offline spell as travel, and its summary names the DHCP server).
* The network tools (ARCHITECTURE 3.23-3.25) are constructed at start and work only on request: the NAT check
  (``tnt.natcheck.NatChecker``, ``engine.natcheck``) and the port-forward test (``tnt.portcheck.PortChecker``,
  ``engine.portcheck``) right after the IP location manager; the TFTP server (``tnt.tftp.TftpServer``, ``engine.tftp``)
  right after the DHCP server, off after every start, with its folder created and secured at once (``ensure_root()``;
  a failure there is only the server's status warning); the switch port finder (``tnt.switchport.SwitchPortFinder``,
  ``engine.switchport``) and packet capture (``tnt.capture.CaptureManager``, ``engine.capture``) right after the LAN
  peers.  Constructing them runs no network, Packet Monitor, ETW or netsh work; ``_start_capture`` starts the daemon
  thread ``tnt-capture-recover`` (``CaptureManager.recover()`` stops an ETW session a crash left behind, deletes the
  unsaved capture files it left and counts the saved ones) and ``start()`` never waits for it.  The NAT check and the port-forward test read the network through accessors that look
  when they are called: the link map's ``public_ip``, the watcher's ``changed_ts`` and generation,
  ``LinkMap.refresh_public_ip`` and, for the port-forward test, the NAT check's last verdict.  None of them needs the
  database (TFTP without one skips its events rows), so none is part of the db retry.  ``_on_net_changed`` tells the
  NAT check after the link map and the TFTP server and switch port finder after the DHCP server (both stop on their
  own helper threads); ``stop()`` stops the TFTP server right after the DHCP server and closes the capture (a running
  one ends with stop reason ``service`` and its file is kept for ``recover()`` to clean up), then the switch port
  finder, right after the LAN peers (idle, each returns at once and runs no pktmon command);
  ``_run_retention`` also applies the capture retention.  The speed scheduler gets the pinger for its latency-under-load
  probe (which makes a private one per run).
* Settings > "Clear history" (:mod:`tnt.history`) is :meth:`Engine.clear_history`: one at a time (``_clear_lock``,
  ``ClearConflict("clear_running")``), never while a Full Scan runs (``ClearConflict("full_scan_running")``), each
  component cleared through its own ``clear_history`` in a fixed order and each step guarded (a part that is missing or
  fails is named in ``skipped``; the rest still clears).  A Discovery scan running across a clear is cancelled and neither
  stored nor adopted (``_disc_clear_gen``, checked under ``_disc_persist_lock`` before ``add_discovery_run``); its
  ``discovery.done`` carries ``"silent": true, "cancel_reason": "history cleared"``.  The result is published as
  ``history.cleared`` (the packet capture files it left alone counted there, named only in the answer to the
  administrator who asked) and an ``info``/``history`` events row records what went.  A Full Scan start goes through
  :meth:`Engine.outside_clear`, so none starts while a clear runs.
"""
from __future__ import annotations

import copy
import datetime as _dt
import logging
import math
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import DEFAULT_PORT, __version__, paths

log = logging.getLogger(__name__)

HEARTBEAT_INTERVAL_S = 30.0
API_RETRY_INTERVAL_S = 30.0
RETENTION_HOUR = 3
RETENTION_MINUTE = 15
STOP_BUDGET_S = 8.0
NETINFO_CACHE_S = 10.0
DISCOVERY_DEFAULTS_CACHE_S = 30.0
DISCOVERY_CANCEL_WAIT_S = 1.0   # longest discovery_cancel() waits for the scanner's own stop()
LIGHT_RANK = {"grey": 0, "green": 1, "yellow": 2, "red": 3}
_RANK_LIGHT = {v: k for k, v in LIGHT_RANK.items()}


def _next_retention_ts(now: float, hour: int = RETENTION_HOUR, minute: int = RETENTION_MINUTE) -> float:
    """Epoch seconds of the next local ``hour:minute`` strictly after *now*."""
    local = _dt.datetime.fromtimestamp(now)
    candidate = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= local:
        candidate += _dt.timedelta(days=1)
    return candidate.timestamp()


def _parse_ts(value: Any) -> Optional[float]:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _clock_jumped(next_ts: float, now: float, max_ahead_s: float) -> bool:
    """True when a scheduled wall-clock instant is further away than it can legitimately
    be - the clock was stepped backwards (NTP / manual change) after it was computed."""
    return next_ts - now > max_ahead_s


def _clean_ports(ports: Optional[List[int]]) -> List[int]:
    out: List[int] = []
    for p in ports or []:
        try:
            pi = int(p)
        except (TypeError, ValueError):
            raise ValueError(f"invalid port {p!r}") from None
        if not 1 <= pi <= 65535:
            raise ValueError(f"port {pi} out of range 1-65535")
        if pi not in out:
            out.append(pi)
    return out


class Engine:
    """Owns config, db, bus and every worker; see the module docstring."""

    def __init__(self, console: bool = False, port: Optional[int] = None,
                 data_dir: Optional[str | Path] = None) -> None:
        if data_dir:
            os.environ["TNT_DATA_DIR"] = str(Path(data_dir))
        self.console = bool(console)
        self.version = __version__
        self.port_override: Optional[int] = int(port) if port is not None else None

        self.config: Any = None
        self.db: Any = None
        self.bus: Any = None
        self.pinger: Any = None
        self.linkmap: Any = None
        self.throughput: Any = None
        self.faults: Any = None
        self.geoip: Any = None
        self.update: Any = None
        self.raw_log: Any = None
        self.ping: Any = None
        self.outages: Any = None
        self.speed: Any = None
        self.discovery: Any = None
        self.dhcp: Any = None
        self.lan: Any = None
        self.netwatch: Any = None
        self.reports: Any = None
        self.networks: Any = None
        # the network tools (see the module docstring)
        self.natcheck = self.portcheck = self.switchport = self.capture = self.tftp = self.proav = None
        self.sipqual = self.sipalg = self.sipnat = self.sipflow = None
        self.api: Any = None

        self.started_ts: Optional[float] = None
        self.stopped_ts: Optional[float] = None
        self.log_file: Optional[Path] = None
        self.api_error: Optional[str] = None
        self.errors: Dict[str, str] = {}

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._running = False
        self._maint_thread: Optional[threading.Thread] = None
        self._api_retry_thread: Optional[threading.Thread] = None

        # discovery state (guarded by _lock)
        self._disc_thread: Optional[threading.Thread] = None
        self._disc_cancel: Optional[threading.Event] = None
        self._disc_range: Optional[str] = None
        self._disc_ports: List[int] = []
        self._disc_started_ts: Optional[float] = None
        self._disc_progress: Optional[Dict[str, Any]] = None
        self._last_discovery: Optional[Dict[str, Any]] = None
        self._disc_defaults: Dict[str, Any] = {}
        self._disc_defaults_ts = 0.0
        self._disc_net_changed = False          # the network changed while the running scan ran
        self._disc_network_id: Optional[int] = None   # the network the running scan started on (tnt.networks)
        # clear history: a scan running across a clear is neither stored nor adopted.  _disc_clear_gen is bumped by the
        # clear, _disc_gen is its value when the running scan started; _disc_persist_lock orders the scan's check and its
        # row against the clear's bump (a row stored a moment before the bump is in the database when the clear deletes).
        self._disc_clear_gen = 0
        self._disc_gen = 0
        self._disc_persist_lock = threading.Lock()

        # Settings > "Clear history": one clear at a time (clear_history).  _clear_gate orders the clear's "no Full Scan
        # runs" check against a Full Scan start (outside_clear): whichever comes second is refused.
        self._clear_lock = threading.Lock()
        self._clear_gate = threading.Lock()
        self._clearing = False

        # the adapter dhcp-restore put back on DHCP at start (its returning lease is TNT's own change)
        self._restored_nic: Optional[Dict[str, Any]] = None
        # "network changed" events rows: when the last one was written (monotonic), the changes held
        # back since then (count, newest payload) and the timer that writes them
        self._net_row_lock = threading.Lock()
        self._net_row_last: Optional[float] = None
        self._net_row_pending: Optional[tuple] = None
        self._net_row_timer: Optional[threading.Timer] = None

        # monitoring-gap bookkeeping (sleep detection, pause spans) and the db retry thread
        self._last_hb_ts: Optional[float] = None
        self._pause_started: Optional[float] = None
        self._db_retry_thread: Optional[threading.Thread] = None

        # netinfo summary cache
        self._netinfo_lock = threading.Lock()
        self._netinfo_cache: Optional[Dict[str, Any]] = None
        self._netinfo_cache_ts = 0.0

        # one IP release/renew at a time
        self._renew_lock = threading.Lock()

    # ------------------------------------------------------------------ props
    @property
    def mode(self) -> str:
        return "console" if self.console else "service"

    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    @property
    def uptime_s(self) -> float:
        return round(time.time() - self.started_ts, 1) if self.started_ts else 0.0

    # -------------------------------------------------------------- lifecycle
    def start(self) -> None:
        """Bring every component up; never raises for a single failed component."""
        with self._lock:
            if self._running:
                return
            self._stop.clear()
            self._running = True
        self.started_ts = time.time()
        self.stopped_ts = None
        self.errors = {}

        self._step("dirs", paths.ensure_dirs)
        self._setup_logging()
        log.info("TNT engine v%s starting (%s mode, data dir %s)", self.version, self.mode, paths.data_dir())
        self._start_config()
        self._start_db()
        self._start_bus()
        self._start_networks()
        self._close_stale_outages()
        self._step("dhcp-restore", self._restore_dhcp_nic)
        self._start_pinger()
        self._start_ping_manager()
        self._start_linkmap()
        self._start_throughput()
        self._start_faults()
        self._start_geoip()
        self._start_update()
        self._start_natcheck()
        self._start_portcheck()
        self._start_outages()
        self._start_speed()
        self._start_discovery()
        self._start_dhcp()
        self._start_tftp()
        self._start_lan()
        self._start_switchport()
        self._start_capture()
        self._start_proav()
        self._start_sip()
        self._start_netwatch()
        self._start_reports()
        self._start_api()
        self._start_maintenance()
        self._db_event("info", "service", f"started v{self.version} ({self.mode} mode)")
        if self.errors:
            log.warning("engine started with degraded components: %s", ", ".join(sorted(self.errors)))
        else:
            log.info("engine started")

    def stop(self) -> None:
        """Reverse-order shutdown bounded to roughly :data:`STOP_BUDGET_S` seconds."""
        with self._lock:
            if not self._running:
                return
            self._running = False
        t0 = time.monotonic()
        deadline = t0 + STOP_BUDGET_S
        self._stop.set()
        log.info("engine stopping")
        if getattr(self, "reports", None) is not None:
            # a running Full Scan is cancelled (its own speed test and discovery scan with it)
            self._bounded("reports", self.reports.stop, deadline, 1.5)
        try:
            self.discovery_cancel()
        except Exception:  # noqa: BLE001
            log.exception("discovery cancel failed")
        self._join(self._api_retry_thread, deadline, 1.0)
        self._join(self._maint_thread, deadline, 2.0)
        if getattr(self, "netwatch", None) is not None:
            # first: nothing may be told about a network change while it is being torn down
            self._bounded("netwatch", self.netwatch.stop, deadline, 1.0)
        if getattr(self, "networks", None) is not None:
            self._bounded("networks", self.networks.stop, deadline, 1.0)     # a router MAC still being looked for
        self._bounded("net-rows", self._flush_net_rows, deadline, 1.0)     # a held-back "network changed" row
        if self.api is not None:
            self._bounded("api", lambda: self.api.stop(timeout=min(3.0, max(0.5, deadline - time.monotonic()))), deadline, 3.5)
        if self.dhcp is not None:
            # after the API (no request can reach it mid-teardown) and before the pinger
            # goes away; stop() also puts a re-addressed adapter back on DHCP
            self._bounded("dhcp", self.dhcp.stop, deadline, 3.0)
        if getattr(self, "tftp", None) is not None:
            # closes the listeners and ends every transfer (the device is told the server is shutting down)
            self._bounded("tftp", self.tftp.stop, deadline, 2.0)
        if self.lan is not None:
            # closes the beacon listener and the throughput server (a test in flight is cut)
            self._bounded("lan", self.lan.stop, deadline, 2.0)
        if getattr(self, "capture", None) is not None:
            # a running capture is ended and its ETW session let go; the unsaved file is left for recover()
            self._bounded("capture", lambda: self.capture.close(1.0), deadline, 1.5)
        if getattr(self, "switchport", None) is not None:
            self._bounded("switchport", lambda: self.switchport.close(1.0), deadline, 1.5)
        if getattr(self, "proav", None) is not None:
            # a running Pro AV listen is ended: its sockets are closed and its groups left
            self._bounded("proav", lambda: self.proav.close(1.0), deadline, 1.5)
        self._join(self._disc_thread, deadline, 2.0)
        if self.speed is not None:
            self._bounded("speedtest", self.speed.stop, deadline, 3.0)
        if self.outages is not None:
            self._bounded("outages", self.outages.stop, deadline, 2.0)
        if getattr(self, "linkmap", None) is not None:
            self._bounded("linkmap", self.linkmap.stop, deadline, 2.0)
        if getattr(self, "throughput", None) is not None:
            self._bounded("throughput", self.throughput.stop, deadline, 1.0)
        if getattr(self, "faults", None) is not None:
            self._bounded("faults", self.faults.stop, deadline, 1.0)
        if getattr(self, "geoip", None) is not None:
            self._bounded("geoip", self.geoip.stop, deadline, 1.0)
        if getattr(self, "update", None) is not None:
            self._bounded("update", self.update.stop, deadline, 1.0)
        if self.ping is not None:
            self._bounded("ping", self.ping.stop, deadline, 4.0)
        if self.raw_log is not None:
            self._bounded("raw_log", self.raw_log.close, deadline, 1.0)
        if self.pinger is not None:
            # never pull the ICMP handle out from under a worker that is still inside
            # IcmpSendEcho2 (a stuck timeout can outlive the bounded join); process exit
            # releases the handle anyway
            busy = [t.name for t in threading.enumerate() if t.name.startswith("tnt-ping-") and t.is_alive()]
            if busy:
                log.warning("ICMP handle close skipped: %d ping worker(s) still finishing (%s)",
                            len(busy), ", ".join(busy[:4]))
            else:
                self._bounded("pinger", self.pinger.close, deadline, 1.0)
        now = time.time()
        self.stopped_ts = now
        if self.db is not None:
            # bounded too: a VACUUM still running on the maintenance thread holds the
            # database lock, and close() would otherwise wait for it indefinitely
            self._bounded("db", lambda: self._final_db_writes(now), deadline, 2.0)
        log.info("engine stopped in %.1f s", time.monotonic() - t0)

    def _final_db_writes(self, now: float) -> None:
        db = self.db
        if db is None:
            return
        try:
            db.add_event("info", "service", f"stopped after {round(now - (self.started_ts or now))} s")
            db.set_meta("last_heartbeat", str(now))
        except Exception:  # noqa: BLE001
            log.exception("final db writes failed")
        try:
            db.close()
        except Exception:  # noqa: BLE001
            log.exception("db close failed")

    def run_forever(self, stop_event: threading.Event) -> None:
        """Block until *stop_event* (or the engine's own stop) is set."""
        while not stop_event.is_set() and not self._stop.is_set():
            stop_event.wait(1.0)

    # ------------------------------------------------------------ start steps
    def _step(self, name: str, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            self._fail(name, exc)
            return None

    def _fail(self, name: str, exc: BaseException) -> None:
        self.errors[name] = f"{type(exc).__name__}: {exc}"
        try:
            log.exception("component %s failed to start: %s", name, exc)
        except Exception:  # noqa: BLE001 - logging must never break startup
            pass

    def _setup_logging(self) -> None:
        try:
            from . import logging_setup

            self.log_file = logging_setup.setup_logging(console=self.console)
        except Exception as exc:  # noqa: BLE001
            self.errors["logging"] = f"{type(exc).__name__}: {exc}"

    def _start_config(self) -> None:
        from .config import Config

        cfg = Config()
        try:
            cfg.load()
        except Exception as exc:  # noqa: BLE001
            self._fail("config", exc)
        # port_override is deliberately NOT pushed into cfg (see the module docstring)
        self.config = cfg

    def _start_db(self) -> None:
        try:
            from .db import Database

            self.db = Database(paths.db_path())
        except Exception as exc:  # noqa: BLE001
            self.db = None
            self._fail("db", exc)
            self._start_db_retry()

    DB_RETRY_S = 30.0
    MONITORING_GAP_S = 90.0
    #: At most one "network changed" events row this often; the changes in between are summed up in one row.
    NET_EVENT_ROW_GAP_S = 60.0

    def _start_db_retry(self) -> None:
        """The database could not be opened (locked by a backup tool, disk full, permissions).

        Instead of running as a zombie service with no monitoring, keep retrying in the
        background and bring the DB-dependent components up as soon as it opens. The API
        (already running) shows the error in Diagnostics meanwhile.
        """
        t = getattr(self, "_db_retry_thread", None)
        if t is not None and t.is_alive():
            return
        self._db_retry_thread = threading.Thread(target=self._db_retry_loop, name="tnt-db-retry", daemon=True)
        self._db_retry_thread.start()

    def _db_retry_loop(self) -> None:
        from .db import Database

        while not self._stop.wait(self.DB_RETRY_S):
            if self.db is not None:
                return
            try:
                self.db = Database(paths.db_path())
            except Exception as exc:  # noqa: BLE001
                self.errors["db"] = f"{type(exc).__name__}: {exc}"
                log.warning("database still unavailable: %s", exc)
                continue
            log.info("database opened after retry; starting the monitoring components")
            self.errors.pop("db", None)
            for name in ("networks", "ping", "outages", "speedtest", "dhcp", "dhcp-restore", "reports", "sipqual"):
                self.errors.pop(name, None)
            try:
                if getattr(self, "networks", None) is None:
                    self._start_networks()
                self._close_stale_outages()
                if self.dhcp is None:
                    self._step("dhcp-restore", self._restore_dhcp_nic)
                if self.ping is None:
                    self._start_ping_manager()
                if self.outages is None:
                    self._start_outages()
                if self.speed is None:
                    self._start_speed()
                if self.dhcp is None:
                    self._start_dhcp()
                if getattr(self, "reports", None) is None:
                    self._start_reports()
                if getattr(self, "sipqual", None) is None:
                    from .sipqual import SipQualifier          # the only SIP part that reads the database

                    self.sipqual = SipQualifier(self.db)
                self._db_event("warning", "service", "database became available after a failed start; monitoring resumed")
            except Exception:  # noqa: BLE001
                log.exception("starting components after the database retry failed")
            return

    def _speedtest_running(self) -> bool:
        sp = self.speed
        try:
            return bool(sp is not None and getattr(sp, "running", False))
        except Exception:  # noqa: BLE001
            return False

    def _monitoring_gap(self, start_ts: float, end_ts: float, note: str) -> None:
        """Record a hole in monitoring (sleep/hibernate detected by heartbeat silence, or a pause)."""
        if end_ts - start_ts < 1.0:
            return
        info: Dict[str, Any] = {}
        try:
            if self.outages is not None and hasattr(self.outages, "on_monitoring_gap"):
                info = self.outages.on_monitoring_gap(start_ts, end_ts, note) or {}
            elif self.db is not None:
                closed = self.db.close_all_open(start_ts, note)
                gid = self.db.open_outage("gap", None, start_ts, note=note)
                self.db.close_outage(gid, end_ts, 0, note)
                info = {"closed": closed, "gap_id": gid}
        except Exception:  # noqa: BLE001
            log.exception("recording the monitoring gap failed")
        if note == "system sleep" and getattr(self, "netwatch", None) is not None:
            try:
                self.netwatch.poll_soon()       # the machine may have woken up on another network
            except Exception:  # noqa: BLE001
                log.exception("waking the network watcher failed")
        log.warning("monitoring gap: %s for %.0f s (%s)", note, end_ts - start_ts, info)
        self._db_event("warning", "monitoring", f"{note}: not monitoring for {end_ts - start_ts:.0f} s")
        self._publish("monitoring.gap", {"start_ts": start_ts, "end_ts": end_ts, "note": note, **info})

    def _start_bus(self) -> None:
        from .events import EventBus

        self.bus = EventBus()

    def _close_stale_outages(self) -> None:
        """Close outages left open by a previous run and record a monitoring gap."""
        if self.db is None:
            return
        now = time.time()
        try:
            try:
                from .outages import close_stale_outages  # type: ignore
            except Exception:  # noqa: BLE001 - module missing/broken: minimal fallback
                close_stale_outages = None
            if close_stale_outages is not None:
                # the time the service was stopped belongs to the network the previous run was on
                info = close_stale_outages(self.db, now, network_id=getattr(getattr(self, "networks", None), "previous_id", None))
                if info.get("closed") or info.get("gap_id"):
                    log.info("startup housekeeping: %s", info)
                return
            hb = _parse_ts(self.db.get_meta("last_heartbeat"))
            end = hb if hb is not None else now
            closed = self.db.close_all_open(min(end, now), "service stopped")
            if closed:
                log.info("closed %d stale outage(s) at %.0f", closed, end)
            if hb is not None and now - hb > 90:
                gap = self.db.open_outage("gap", None, hb, note="not monitoring")
                self.db.close_outage(gap, now, 0, "not monitoring")
                log.info("recorded monitoring gap #%d (%.0f s)", gap, now - hb)
            self.db.set_meta("last_heartbeat", str(now))
        except Exception:  # noqa: BLE001
            log.exception("startup outage housekeeping failed")

    def _start_pinger(self) -> None:
        try:
            from .icmp import IcmpPinger

            self.pinger = IcmpPinger()
        except Exception as exc:  # noqa: BLE001
            self.pinger = None
            self._fail("icmp", exc)

    def _start_ping_manager(self) -> None:
        if self.db is None:
            self.errors["ping"] = "database unavailable"
            return
        try:
            from .pinger import PingManager, RawPingLog
        except Exception as exc:  # noqa: BLE001
            self._fail("ping", exc)
            return
        try:
            self.raw_log = RawPingLog(paths.ping_logs_dir())
        except Exception as exc:  # noqa: BLE001
            self.raw_log = None
            self._fail("raw_log", exc)
        try:
            pm = PingManager(self.db, self.config, self.bus, pinger=self.pinger, raw_log=self.raw_log, network_fn=self._network_id)
            pm.start()
            self.ping = pm
        except Exception as exc:  # noqa: BLE001
            self.ping = None
            self._fail("ping", exc)
            return
        self._load_first_run_defaults()

    def _load_first_run_defaults(self) -> None:
        try:
            if self.db.list_targets() or self.db.get_meta("defaults_loaded"):
                return
            views = self.ping.load_defaults()
            self.db.set_meta("defaults_loaded", str(time.time()))
            log.info("first run: loaded %d default target(s)", len(views or []))
            self._db_event("info", "targets", f"loaded {len(views or [])} default target(s)")
        except Exception:  # noqa: BLE001
            log.exception("loading default targets failed")

    def _start_linkmap(self) -> None:
        """Always-on gateway/internet probes for the Network info link map."""
        try:
            from .linkmap import LinkMap

            lm = LinkMap(self.config, self.bus, pinger=self.pinger, geo_lookup=self._geo_lookup)
            lm.start()
            self.linkmap = lm
        except Exception as exc:  # noqa: BLE001
            self.linkmap = None
            self._fail("linkmap", exc)

    def _start_throughput(self) -> None:
        """Per-second NIC byte/packet counters for the Network info throughput card."""
        try:
            from .throughput import ThroughputMonitor

            tm = ThroughputMonitor(self.bus, config=self.config)
            tm.start()
            self.throughput = tm
        except Exception as exc:  # noqa: BLE001
            self.throughput = None
            self._fail("throughput", exc)

    def _start_faults(self) -> None:
        """The always-on passive watch behind the Faults tile: counters, addresses, the ARP table."""
        try:
            from .faults import FaultWatcher

            fw = FaultWatcher(self.bus)
            fw.start()
            self.faults = fw
        except Exception as exc:  # noqa: BLE001
            self.faults = None
            self._fail("faults", exc)

    def _start_geoip(self) -> None:
        """IP location + ISP data (DB-IP Lite): loads what is installed, downloads on its own thread."""
        try:
            from .geoip import GeoIpManager

            gm = GeoIpManager(self.config, self.bus, public_ip_fn=self._public_ip)
            gm.start()
            self.geoip = gm
        except Exception as exc:  # noqa: BLE001
            self.geoip = None
            self._fail("geoip", exc)

    def _start_update(self) -> None:
        """Auto-update: checks the GitHub releases page on its own thread and, on request, downloads,
        verifies (SHA-256) and launches the installer."""
        try:
            from .updater import UpdateManager

            um = UpdateManager(self.config, self.bus, current_version=self.version)
            um.start()
            self.update = um
        except Exception as exc:  # noqa: BLE001
            self.update = None
            self._fail("update", exc)

    def _public_ip(self) -> Optional[str]:
        lm = getattr(self, "linkmap", None)
        try:
            return lm.public_ip() if lm is not None else None
        except Exception:  # noqa: BLE001
            return None

    def _geo_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        gm = getattr(self, "geoip", None)
        return gm.lookup(ip) if gm is not None else None

    # ------------------------------------------------------------ NAT check + port-forward test
    def _public_ip_view(self) -> Dict[str, Any]:
        """The link map's public address ``{"ip", "ts", "error", "checked_ts"}`` (a copy; ``{}`` without a link map)."""
        lm = getattr(self, "linkmap", None)
        return dict(((lm.view() if lm is not None else None) or {}).get("public_ip") or {})

    def _net_changed_ts(self) -> Optional[float]:
        """When the network watcher last saw the network change (None without a watcher)."""
        nw = getattr(self, "netwatch", None)
        return (nw.state() or {}).get("changed_ts") if nw is not None else None

    def _net_generation(self) -> int:
        """The network watcher's generation (0 without a watcher; ``NetWatcher.generation`` is a property)."""
        nw = getattr(self, "netwatch", None)
        return nw.generation if nw is not None else 0

    def _nat_verdict(self) -> Optional[str]:
        """The verdict of the NAT check's last kept result (None without one)."""
        nat = getattr(self, "natcheck", None)
        return (nat.last() or {}).get("verdict") if nat is not None else None

    def _start_natcheck(self) -> None:
        """The NAT check (``tnt.natcheck.NatChecker``, ``engine.natcheck``): constructed only, it runs on request.  The
        accessors look at the link map and the network watcher when they are called (the watcher starts later)."""
        try:
            from . import netinfo  # lazy: optional at runtime
            from .natcheck import NatChecker

            lm = getattr(self, "linkmap", None)
            self.natcheck = NatChecker(adapters_fn=netinfo.get_adapters, internet_nic_fn=lambda: netinfo.get_internet_nic(),
                                       public_ip_fn=self._public_ip_view, changed_ts_fn=self._net_changed_ts,
                                       refresh_fn=lm.refresh_public_ip if lm is not None else None,
                                       generation_fn=self._net_generation)
        except Exception as exc:  # noqa: BLE001
            self.natcheck = None
            self._fail("natcheck", exc)

    def _start_portcheck(self) -> None:
        """The port-forward test (``tnt.portcheck.PortChecker``, ``engine.portcheck``): constructed only, it runs on
        request; it refuses while the NAT check's last verdict is ``vpn``."""
        try:
            from .portcheck import PortChecker

            lm = getattr(self, "linkmap", None)
            self.portcheck = PortChecker(public_ip_fn=self._public_ip_view, changed_ts_fn=self._net_changed_ts,
                                         refresh_fn=lm.refresh_public_ip if lm is not None else None,
                                         generation_fn=self._net_generation, nat_verdict_fn=self._nat_verdict)
        except Exception as exc:  # noqa: BLE001
            self.portcheck = None
            self._fail("portcheck", exc)

    def _start_outages(self) -> None:
        if self.ping is None:
            self.errors.setdefault("outages", "ping manager unavailable")
            log.error("outage tracker skipped: ping manager unavailable")
            return
        try:
            from .outages import OutageTracker

            tracker = OutageTracker(self.db, self.config, self.bus, self.ping,
                                    suppress_new=self._speedtest_running, gateway_fn=self._live_gateway,
                                    network_fn=self._network_id)
            tracker.start()
            self.outages = tracker
            self._listen_to_networks(getattr(tracker, "on_network_id_change", None))
        except Exception as exc:  # noqa: BLE001
            self.outages = None
            self._fail("outages", exc)

    def _start_speed(self) -> None:
        if self.db is None:
            self.errors["speedtest"] = "database unavailable"
            return
        try:
            from .speedtest import SpeedScheduler

            sched = SpeedScheduler(self.db, self.config, self.bus, network_fn=self._network_id, pinger=self.pinger)
            sched.start()
            self.speed = sched
        except Exception as exc:  # noqa: BLE001
            self.speed = None
            self._fail("speedtest", exc)

    def _start_discovery(self) -> None:
        try:
            from .discovery import DiscoveryScanner

            self.discovery = DiscoveryScanner(self.config, self.pinger)
        except Exception as exc:  # noqa: BLE001
            self.discovery = None
            self._fail("discovery", exc)
        if self.db is not None:
            try:
                runs = self.db.list_discovery_runs(1)
                if runs:
                    self._last_discovery = self._run_summary(runs[0])
            except Exception:  # noqa: BLE001
                log.exception("reading the last discovery run failed")

    # ------------------------------------------------------------ DHCP tool
    @staticmethod
    def _dhcp_exe_path() -> str:
        """Program path for the inbound UDP 67 firewall rule: the process image Windows sees.

        Frozen: ``TNTService.exe``.  Dev: the venv ``python.exe`` is a launcher that runs
        the base interpreter, and Windows Firewall matches *that* image, so prefer
        ``sys._base_executable`` when it exists.
        """
        exe = str(sys.executable or "")
        if paths.is_frozen():
            return exe
        base = str(getattr(sys, "_base_executable", "") or "")
        try:
            if base and base.lower() != exe.lower() and os.path.isfile(base):
                return base
        except OSError:
            pass
        return exe

    def _restore_dhcp_nic(self) -> Optional[Dict[str, Any]]:
        """Put an adapter back on DHCP if a previous run left it on the static address.

        The record lives in db meta ``dhcp.nic_changed`` (written before the adapter is
        touched, cleared after a successful restore).  Runs before the pinger so nothing
        downstream caches the temporary address.  A missing ``tnt.dhcp`` module is not an
        error here (``_start_dhcp`` reports it once).
        """
        if self.db is None:
            return None
        try:
            from .dhcp import restore_nic_on_start
        except ImportError as exc:
            log.debug("dhcp restore step skipped: %s", exc)
            return None
        info = restore_nic_on_start(self.db)
        if info:
            log.warning("startup: restored adapter %s to DHCP after a previous DHCP server run (%s)",
                        info.get("adapter"), info)
            self._db_event("warning", "dhcp", f"restored adapter {info.get('adapter')} to DHCP at start")
            if info.get("restored") and info.get("adapter"):
                self._restored_nic = {"adapter": info.get("adapter"), "static_ip": info.get("static_ip"),
                                      "phase": "restored"}
        return info

    def _start_dhcp(self) -> None:
        """Construct the DHCP server tool (it only listens after POST /api/dhcp/start)."""
        if self.db is None:
            self.errors["dhcp"] = "database unavailable"
            return
        try:
            from .dhcp import DhcpServer

            self.dhcp = DhcpServer(self.db, self.config, self.bus, pinger=self.pinger, exe_path=self._dhcp_exe_path())
        except Exception as exc:  # noqa: BLE001
            self.dhcp = None
            self._fail("dhcp", exc)

    def _start_tftp(self) -> None:
        """The TFTP server (``tnt.tftp.TftpServer``, ``engine.tftp``): constructed and its folder created and secured; it
        listens only after ``POST /api/tftp/start``.  Works without the database (not part of the db retry); its
        firewall rule is managed for the installed service only, like the LAN peers' rules."""
        try:
            from .tftp import TftpServer

            self.tftp = TftpServer(self.db, self.config, self.bus,
                                   exe_path=self._dhcp_exe_path() if paths.is_frozen() else None)
        except Exception as exc:  # noqa: BLE001
            self.tftp = None
            self._fail("tftp", exc)
            return
        try:
            self.tftp.ensure_root()         # never raises: a folder that cannot be secured is the server's warning
        except Exception:  # noqa: BLE001
            log.exception("preparing the TFTP folder failed")

    # ------------------------------------------------------------ LAN peers
    def _start_lan(self) -> None:
        """LAN peer discovery + throughput server (``tnt.lanpeers.LanPeers``, ``engine.lan``).

        Started right away (it is what makes this install visible to the other TNT boxes on
        the LAN); ``lan.enabled`` false makes ``start()`` a no-op.  The firewall rules use the
        same program path as the DHCP tool.  Works without the database.
        """
        try:
            from .lanpeers import LanPeers

            # firewall rules are only managed for the installed service (TNTService.exe); a dev
            # console run must not leave python.exe rules behind on every start
            lan = LanPeers(self.config, self.bus, db=self.db, pinger=self.pinger,
                           exe_path=self._dhcp_exe_path() if paths.is_frozen() else None)
            lan.start()
            self.lan = lan
        except Exception as exc:  # noqa: BLE001
            self.lan = None
            self._fail("lan", exc)

    # ------------------------------------------------------------ switch port + packet capture
    def _start_switchport(self) -> None:
        """The switch port finder (``tnt.switchport.SwitchPortFinder``, ``engine.switchport``): constructed only; Packet
        Monitor runs only while a search does."""
        try:
            from .switchport import SwitchPortFinder

            self.switchport = SwitchPortFinder(self.bus, generation_fn=self._net_generation)
        except Exception as exc:  # noqa: BLE001
            self.switchport = None
            self._fail("switchport", exc)

    def _start_capture(self) -> None:
        """Packet capture (``tnt.capture.CaptureManager``, ``engine.capture``): constructed, then ``recover()`` runs on
        the daemon thread ``tnt-capture-recover`` (an ETW session and an unsaved capture a crash left behind are cleaned
        up and the saved captures are counted).  ``start()`` never waits for it."""
        try:
            from .capture import CaptureManager

            self.capture = CaptureManager(self.bus)
        except Exception as exc:  # noqa: BLE001
            self.capture = None
            self._fail("capture", exc)
            return
        try:
            threading.Thread(target=self.capture.recover, name="tnt-capture-recover", daemon=True).start()
        except Exception:  # noqa: BLE001 - capture still works; a leftover session is cleaned up at the next start
            log.exception("starting the packet capture clean-up failed")

    def _start_proav(self) -> None:
        """The Pro AV scanner (``tnt.proav.ProAvScanner``, ``engine.proav``): constructed only.  No socket is opened
        and no group joined until a scan runs.  It is given the switch-port finder's last neighbour so a scan can
        report the switch this PC is plugged into alongside what it heard."""
        try:
            from .proav import ProAvScanner

            self.proav = ProAvScanner(self.bus, switch_fn=self._switch_neighbour)
        except Exception as exc:  # noqa: BLE001
            self.proav = None
            self._fail("proav", exc)

    def _start_sip(self) -> None:
        """The SIP page's four parts, constructed only: the qualifier (``tnt.sipqual.SipQualifier``,
        ``engine.sipqual``), the ALG check (``tnt.sipalg.AlgChecker``, ``engine.sipalg``), the STUN test
        (``tnt.sipnat.StunChecker``, ``engine.sipnat``) and the call-flow reader (``tnt.sipflow.FlowReader``,
        ``engine.sipflow``).  No socket is opened and no file read until a request asks for one.

        The qualifier is the only one that needs the database - it reads the ping history and the last speed test
        and measures nothing itself - so it is the only one the db retry has to rebuild.  A failure in any one of
        them costs that part of the page and nothing else, which is why they are four attributes and not one."""
        try:
            from .sipqual import SipQualifier

            self.sipqual = SipQualifier(self.db) if self.db is not None else None
            if self.db is None:
                self.errors.setdefault("sipqual", "database unavailable")
        except Exception as exc:  # noqa: BLE001
            self.sipqual = None
            self._fail("sipqual", exc)
        for name, module, cls in (("sipalg", ".sipalg", "AlgChecker"), ("sipnat", ".sipnat", "StunChecker"),
                                  ("sipflow", ".sipflow", "FlowReader")):
            try:
                import importlib

                setattr(self, name, getattr(importlib.import_module(module, __package__), cls)())
            except Exception as exc:  # noqa: BLE001
                setattr(self, name, None)
                self._fail(name, exc)

    def _switch_neighbour(self) -> Any:
        """The LLDP/CDP neighbour of the last switch-port lookup, or None.  Read, never started: a Pro AV scan does
        not run Packet Monitor of its own."""
        finder = getattr(self, "switchport", None)
        if finder is None:
            return None
        job = finder.job() if hasattr(finder, "job") else None
        neighbours = (job or {}).get("neighbors") or []
        return neighbours[0] if neighbours else None

    # ------------------------------------------------------------ network changes
    def _start_netwatch(self) -> None:
        """The network-change watcher (``tnt.netwatch.NetWatcher``, ``engine.netwatch``); see the
        module docstring.  Started after the components it notifies; works without the database."""
        try:
            from .netwatch import NetWatcher

            nw = NetWatcher(self.config, self.bus, own_change=self._dhcp_own_change)
            nw.add_listener(self._on_net_changed)
            if self._restored_nic:
                nw.note_own_change(self._restored_nic)
            nw.start()
            self.netwatch = nw
        except Exception as exc:  # noqa: BLE001
            self.netwatch = None
            self._fail("netwatch", exc)

    def _start_reports(self) -> None:
        """Full Scan site reports (``tnt.reports.ReportManager``, ``engine.reports``); see the module docstring."""
        if self.db is None:
            self.errors["reports"] = "database unavailable"
            return
        try:
            from .reports import ReportManager

            mgr = ReportManager(self.db, self.config, self.bus, self)
            mgr.start()
            self.reports = mgr
            self._listen_to_networks(getattr(mgr, "on_network_id_change", None))
        except Exception as exc:  # noqa: BLE001
            self.reports = None
            self._fail("reports", exc)

    # ------------------------------------------------------------ networks
    def _start_networks(self) -> None:
        """The network tracker (``tnt.networks.NetworkTracker``, ``engine.networks``); see the module docstring."""
        if getattr(self, "networks", None) is not None:
            return
        if self.db is None:
            self.errors["networks"] = "database unavailable"
            return
        try:
            from .networks import NetworkTracker

            tracker = NetworkTracker(self.db)
            tracker.start()
            self.networks = tracker
        except Exception as exc:  # noqa: BLE001
            self.networks = None
            self._fail("networks", exc)

    def _network_id(self) -> Optional[int]:
        """The id of the network this PC is on (None: unknown, or no tracker): what every writer tags its rows with."""
        tracker = getattr(self, "networks", None)
        if tracker is None:
            return None
        try:
            return tracker.current_network_id()
        except Exception:  # noqa: BLE001
            return None

    def _listen_to_networks(self, fn: Any) -> None:
        tracker = getattr(self, "networks", None)
        if tracker is None or not callable(fn):
            return
        try:
            tracker.add_listener(fn)
        except Exception:  # noqa: BLE001
            log.exception("listening to network id changes failed")

    def _dhcp_own_change(self) -> Optional[Dict[str, Any]]:
        fn = getattr(self.dhcp, "own_change", None)
        return fn() if callable(fn) else None

    @staticmethod
    def _live_gateway() -> Optional[str]:
        """This PC's default gateway right now (netinfo's one-second adapter cache), for the outage tracker."""
        from . import netinfo  # lazy: optional at runtime

        return netinfo.get_default_gateway()

    def _on_net_changed(self, data: Dict[str, Any]) -> None:
        """``net.changed`` listener (watcher thread, before the bus): drop the caches that describe
        the old network, let every consumer react, record the change in the events table."""
        with self._netinfo_lock:
            self._netinfo_cache = None
            self._netinfo_cache_ts = 0.0
        with self._lock:
            self._disc_defaults = {}
            self._disc_defaults_ts = 0.0
            if self._disc_thread is not None and self._disc_thread.is_alive():
                self._disc_net_changed = True
        for name in ("networks", "ping", "outages", "linkmap", "natcheck", "lan", "dhcp", "tftp", "switchport",
                     "sipalg", "sipnat", "reports"):
            # networks first: the samples, outages and reports that follow are tagged with the network identified now
            fn = getattr(getattr(self, name, None), "on_network_change", None)
            if not callable(fn):
                continue
            try:
                fn(data)
            except Exception:  # noqa: BLE001
                log.exception("%s: handling the network change failed", name)
        self._record_net_change(data)

    def _record_net_change(self, data: Dict[str, Any]) -> None:
        """The "network changed" events row: written at once (on a helper thread: a database locked by a
        backup tool must not hold the event back) unless one went in less than NET_EVENT_ROW_GAP_S ago; then
        this change is held back and a timer writes one row for everything held back when that time is up."""
        if self.db is None:
            return
        now = time.monotonic()
        with self._net_row_lock:
            last, gap = self._net_row_last, float(self.NET_EVENT_ROW_GAP_S)
            if last is not None and 0.0 <= now - last < gap:
                count = (self._net_row_pending[0] if self._net_row_pending else 0) + 1
                self._net_row_pending = (count, data)
                if self._net_row_timer is None:
                    timer = threading.Timer(max(0.0, last + gap - now), self._flush_net_rows)
                    timer.name, timer.daemon = "tnt-net-rows", True
                    self._net_row_timer = timer
                    timer.start()
                return
            self._net_row_last = now
        threading.Thread(target=self._write_net_row, args=(data, 1), name="tnt-net-event", daemon=True).start()

    def _flush_net_rows(self) -> None:
        """Write the row for the changes held back (the timer, or stop()); nothing when there are none."""
        with self._net_row_lock:
            pending, self._net_row_pending = self._net_row_pending, None
            timer, self._net_row_timer = self._net_row_timer, None
            if pending is not None:
                self._net_row_last = time.monotonic()
        if timer is not None and timer is not threading.current_thread():
            timer.cancel()
        if pending is not None:
            self._write_net_row(pending[1], pending[0])

    def _write_net_row(self, data: Dict[str, Any], count: int) -> None:
        summary = str(data.get("summary") or "")
        message = f"network changed: {summary}" if count <= 1 else f"network changed {count} more times, now: {summary}"
        ts = data.get("ts")
        try:
            self.db.add_event("info", "network", message.strip(), ts=float(ts) if isinstance(ts, (int, float)) else None)
        except Exception:  # noqa: BLE001
            log.exception("db event write failed")

    def _api_address(self) -> tuple[str, int]:
        host = "127.0.0.1"
        port = DEFAULT_PORT
        if self.config is not None:
            host = str(self.config.get("api.host") or host)
            try:
                port = int(self.config.get("api.port") or port)
            except (TypeError, ValueError):
                pass
        if self.port_override is not None:
            port = self.port_override
        return host, port

    def _start_api(self) -> None:
        try:
            from .api.server import ApiServer

            host, port = self._api_address()
            self.api = ApiServer(self, host, port, bus=self.bus)
        except Exception as exc:  # noqa: BLE001
            self.api = None
            self._fail("api", exc)
            return
        try:
            self.api.start()
            self.api_error = None
        except Exception as exc:  # noqa: BLE001
            self.api_error = str(exc)
            log.error("API not started (%s); retrying every %g s in the background", exc, API_RETRY_INTERVAL_S)
            self._db_event("error", "api", f"bind failed: {exc}")
            self._api_retry_thread = threading.Thread(target=self._api_retry_loop, name="tnt-api-retry", daemon=True)
            self._api_retry_thread.start()

    def _api_retry_loop(self) -> None:
        while not self._stop.wait(API_RETRY_INTERVAL_S):
            try:
                host, port = self._api_address()
                self.api.host, self.api.port = host, port
                self.api.start()
                if self._stop.is_set():
                    # stop() ran while we were binding and has already stopped the
                    # (then not running) server: do not leave a listener behind
                    self.api.stop(timeout=1.0)
                    return
                self.api_error = None
                log.info("API bind retry succeeded: %s", self.api.url)
                self._db_event("info", "api", f"listening on {self.api.url}")
                return
            except Exception as exc:  # noqa: BLE001
                self.api_error = str(exc)
                log.warning("API bind retry failed: %s", exc)

    def _start_maintenance(self) -> None:
        self._maint_thread = threading.Thread(target=self._maint_loop, name="tnt-maint", daemon=True)
        self._maint_thread.start()

    # ------------------------------------------------------------ maintenance
    def _maint_loop(self) -> None:
        next_hb = 0.0
        next_ret = 0.0  # 0 => run retention right after start
        while not self._stop.is_set():
            wait = 1.0
            try:
                now = time.time()
                # This loop wakes at least every 5 s. A much longer silence means the machine
                # slept / hibernated (or the process was frozen): no pings ran through that
                # hole, so record it as a monitoring gap instead of letting open outages
                # absorb the sleep time and the timeline paint it green.
                last_hb = self._last_hb_ts
                if last_hb is not None and now - last_hb > self.MONITORING_GAP_S:
                    self._monitoring_gap(last_hb, now, "system sleep")
                    self._last_hb_ts = now
                    next_hb = now
                # wall-clock schedule: if the clock was stepped backwards the next
                # instants are suddenly far away - re-anchor instead of going silent
                # (a missing heartbeat is read as a monitoring gap at the next start)
                if _clock_jumped(next_hb, now, 2 * HEARTBEAT_INTERVAL_S):
                    log.warning("clock went backwards; re-anchoring the heartbeat schedule")
                    next_hb = now
                if next_ret > 0.0 and _clock_jumped(next_ret, now, 86400.0 + 3600.0):
                    next_ret = _next_retention_ts(now)
                if now >= next_hb:
                    self._heartbeat(now)
                    next_hb = now + HEARTBEAT_INTERVAL_S
                if now >= next_ret:
                    scheduled = next_ret > 0.0
                    next_ret = _next_retention_ts(now)
                    self._run_retention(now, scheduled)
                wait = max(0.2, min(next_hb, next_ret) - time.time())
            except Exception:  # noqa: BLE001
                log.exception("maintenance loop error")
                wait = 5.0
            self._stop.wait(min(wait, 5.0))

    def _heartbeat(self, now: float) -> None:
        self._last_hb_ts = now
        if self.db is None:
            return
        try:
            self.db.set_meta("last_heartbeat", str(now))
        except Exception:  # noqa: BLE001
            log.exception("heartbeat write failed")
        tracker = getattr(self, "networks", None)
        if tracker is not None:
            try:
                tracker.touch(now)          # last_seen (once a minute) and a router swapped behind the same address
            except Exception:  # noqa: BLE001
                log.exception("network tracker heartbeat failed")

    def _run_retention(self, now: float, scheduled: bool) -> None:
        days = 365
        try:
            days = int(self.config.get("retention.days", 365)) if self.config is not None else 365
        except (TypeError, ValueError):
            pass
        if self.db is not None:
            try:
                removed = self.db.retention(days, now)
                log.info("retention (%d days): %s", days, removed)
            except Exception:  # noqa: BLE001
                log.exception("db retention failed")
        if self.raw_log is not None:
            try:
                n = self.raw_log.trim(days)
                if n:
                    log.info("raw ping log trim removed %d file(s)", n)
            except Exception:  # noqa: BLE001
                log.exception("raw log trim failed")
        capture = getattr(self, "capture", None)
        if capture is not None:
            try:
                capture.enforce_retention(now)      # the newest 10 captures, at most 2 GB and 7 days
            except Exception:  # noqa: BLE001
                log.exception("packet capture retention failed")
        if scheduled and self.db is not None and _dt.datetime.fromtimestamp(now).weekday() == 6:
            try:
                t0 = time.monotonic()
                self.db.vacuum()
                self.db.set_meta("last_vacuum", str(now))
                log.info("weekly vacuum done in %.1f s", time.monotonic() - t0)
            except Exception:  # noqa: BLE001
                log.exception("vacuum failed")

    # --------------------------------------------------------------- helpers
    def _db_event(self, level: str, category: str, message: str) -> None:
        if self.db is None:
            return
        try:
            self.db.add_event(level, category, message)
        except Exception:  # noqa: BLE001
            log.exception("db event write failed")

    def _publish(self, event_type: str, data: Dict[str, Any]) -> None:
        if self.bus is None:
            return
        try:
            self.bus.publish(event_type, data)
        except Exception:  # noqa: BLE001
            log.exception("publish %s failed", event_type)

    @staticmethod
    def _join(thread: Optional[threading.Thread], deadline: float, share: float) -> None:
        if thread is None or not thread.is_alive():
            return
        thread.join(max(0.05, min(share, deadline - time.monotonic())))
        if thread.is_alive():
            log.warning("thread %s did not stop in time", thread.name)

    @staticmethod
    def _bounded(name: str, fn: Callable[[], Any], deadline: float, share: float) -> None:
        """Run ``fn()`` on a helper thread and wait at most its share of the budget."""
        t = threading.Thread(target=lambda: Engine._guarded(name, fn), name=f"tnt-stop-{name}", daemon=True)
        t.start()
        t.join(max(0.05, min(share, deadline - time.monotonic())))
        if t.is_alive():
            log.warning("%s is taking too long to stop; not waiting for it", name)

    @staticmethod
    def _guarded(name: str, fn: Callable[[], Any]) -> None:
        try:
            fn()
        except Exception:  # noqa: BLE001
            log.exception("stopping %s failed", name)

    # ------------------------------------------------------------ monitoring
    def overall_light(self) -> str:
        """Machine-wide light for the tray dot and the header pill.

        Red is reserved for a *full* outage (all local or all internet targets down at
        once); any individual target that is down or sluggish only makes it yellow.
        Green when every target is fine, grey when there is nothing to judge.
        """
        pm = self.ping
        if pm is None:
            return "grey"
        try:
            if self.outages is not None and (self.outages.status() or {}).get("total_active"):
                return "red"
        except Exception:  # noqa: BLE001
            log.exception("outage status failed")
        try:
            views = pm.targets()
        except Exception:  # noqa: BLE001
            log.exception("targets() failed")
            return "grey"
        worst = 0
        for v in views or []:
            worst = max(worst, LIGHT_RANK.get(str(v.get("light") or "grey"), 0))
        return "yellow" if _RANK_LIGHT[worst] == "red" else _RANK_LIGHT[worst]

    def set_paused(self, paused: bool) -> bool:
        """Pause/resume monitoring; returns the new paused state."""
        pm = self.ping
        if pm is None:
            raise RuntimeError("ping monitoring is not available")
        was = bool(getattr(pm, "paused", False))
        pm.set_paused(bool(paused))
        state = bool(getattr(pm, "paused", paused))
        now = time.time()
        if state and not was:
            self._pause_started = now
        elif was and not state:
            started = getattr(self, "_pause_started", None)
            self._pause_started = None
            if started is not None:
                # a pause is a monitoring hole: close whatever was open, show grey on the timeline
                self._monitoring_gap(started, now, "monitoring paused")
        self._publish("monitoring.paused", {"paused": state})
        self._db_event("info", "monitoring", "paused" if state else "resumed")
        return state

    def ip_release_renew(self) -> Dict[str, Any]:
        """The top bar's IP Release/Renew: ``tnt.nettools.release_renew()`` with monitoring paused around it (see the
        module docstring).  RENEW_RESULT with ``paused_monitoring``; ``RuntimeError`` while one is running."""
        if not self._renew_lock.acquire(blocking=False):
            raise RuntimeError("An IP release/renew is already running")
        try:
            from . import nettools

            paused_here = False
            if self.ping is not None and not bool(getattr(self.ping, "paused", False)):
                try:
                    # the seconds without an address are a monitoring gap, not an outage
                    paused_here = bool(self.set_paused(True))
                except Exception:  # noqa: BLE001 - never a reason not to renew
                    log.exception("pausing monitoring for the IP release/renew failed")
            try:
                result = nettools.release_renew()
            finally:
                if paused_here:
                    try:
                        self.set_paused(False)
                    except Exception:  # noqa: BLE001
                        log.exception("resuming monitoring after the IP release/renew failed")
                self._addresses_changed()
            result["paused_monitoring"] = paused_here
            return result
        finally:
            self._renew_lock.release()

    def _addresses_changed(self) -> None:
        """This PC's addresses were just changed on purpose: drop both netinfo caches and make the network watcher
        look at once, so Network info follows without waiting for the next poll."""
        with self._netinfo_lock:
            self._netinfo_cache = None
            self._netinfo_cache_ts = 0.0
        try:
            from . import netinfo  # lazy: optional at runtime

            netinfo._invalidate_cache()
        except Exception:  # noqa: BLE001
            log.exception("dropping the netinfo cache failed")
        if getattr(self, "netwatch", None) is not None:
            try:
                self.netwatch.poll_soon()
            except Exception:  # noqa: BLE001
                log.exception("waking the network watcher failed")

    def add_target(self, host: str, label: Optional[str] = None) -> Dict[str, Any]:
        pm = self.ping
        if pm is None:
            raise RuntimeError("ping monitoring is not available")
        view = pm.add_target(host, label)
        self._db_event("info", "targets", f"added {host}")
        return view

    def remove_target(self, target_id: int) -> bool:
        pm = self.ping
        if pm is None:
            raise RuntimeError("ping monitoring is not available")
        ok = bool(pm.remove_target(int(target_id)))
        if ok:
            # OutageTracker hooks PingManager.add_removal_listener when the manager has it;
            # otherwise tell it directly so the open outage is closed.
            if self.outages is not None and not hasattr(pm, "add_removal_listener"):
                try:
                    self.outages.on_target_removed(int(target_id))
                except Exception:  # noqa: BLE001
                    log.exception("outage cleanup for target %s failed", target_id)
            self._db_event("info", "targets", f"removed target {target_id}")
        return ok

    def netinfo_summary(self) -> Dict[str, Any]:
        """``{"internet_nic": {...}|None, "local_nic": {...}|None, "adapter_count": int}`` for /api/status
        (cached 10 s).  Both adapter dicts carry ``warnings`` (the codes of ``netinfo.adapter_warnings``);
        ``local_nic`` is the adapter the dashboard shows when none faces the internet: the first up
        physical one with an IPv4 address, a real address before a self-assigned one (a bench cable, the
        DHCP server tool, no DHCP server answering)."""
        now = time.time()
        with self._netinfo_lock:
            if self._netinfo_cache is not None and now - self._netinfo_cache_ts < NETINFO_CACHE_S:
                return dict(self._netinfo_cache)
        summary: Dict[str, Any] = {"internet_nic": None, "local_nic": None, "adapter_count": 0}
        try:
            from . import netinfo  # lazy: optional at runtime

            adapters = netinfo.get_adapters() or []
            summary["adapter_count"] = len(adapters)
            nic = netinfo.get_internet_nic(adapters)
            if nic is not None:
                summary["internet_nic"] = self._nic_brief(netinfo, nic, adapters, getattr(nic, "index", None))
            else:
                bench = [a for a in adapters if getattr(a, "is_up", False) and getattr(a, "is_physical", False)
                         and getattr(a, "primary_ipv4", None)]
                bench.sort(key=lambda a: 1 if str(a.primary_ipv4).startswith("169.254.") else 0)
                if bench:
                    summary["local_nic"] = self._nic_brief(netinfo, bench[0], adapters, None)
        except Exception as exc:  # noqa: BLE001
            log.debug("netinfo summary unavailable: %s", exc)
            summary["error"] = f"{type(exc).__name__}: {exc}"
        with self._netinfo_lock:
            self._netinfo_cache = dict(summary)
            self._netinfo_cache_ts = now
        return summary

    @staticmethod
    def _nic_brief(netinfo: Any, nic: Any, adapters: List[Any], internet_index: Optional[int]) -> Dict[str, Any]:
        """One adapter for status.netinfo: its primary IPv4 address with the network, the gateway and the
        codes of ``netinfo.adapter_warnings`` (*internet_index* adds the one that compares adapters)."""
        v4 = list(getattr(nic, "ipv4", None) or [])
        # prefer the preferred (non-tentative, non-APIPA) address the NIC reports as primary
        primary = getattr(nic, "primary_ipv4", None)
        first = next((a for a in v4 if getattr(a, "address", None) == primary), None) or (v4[0] if v4 else None)
        gws = [g for g in (getattr(nic, "gateways", None) or []) if ":" not in str(g)] or list(getattr(nic, "gateways", None) or [])
        v4gw = getattr(nic, "ipv4_gateway", None)
        if v4gw:
            gws = [v4gw] + [g for g in gws if g != v4gw]
        warn = getattr(netinfo, "adapter_warnings", None)
        found = warn(nic, adapters, internet_index) if callable(warn) else []
        return {
            "index": getattr(nic, "index", None),
            "name": getattr(nic, "name", None),
            "description": getattr(nic, "description", None),
            "type_name": getattr(nic, "type_name", None),
            "ipv4": getattr(first, "address", None) if first is not None else None,
            "network": getattr(first, "network", None) if first is not None else None,
            # the tile shows this instead when IPv4 is self-assigned while IPv6 carries the traffic
            # (an IPv6-only network): 169.254.x.x is not the address anything reaches the PC on
            "ipv6": getattr(nic, "global_ipv6", None),
            "gateway": gws[0] if gws else None,
            "mac": getattr(nic, "mac", None),
            "warnings": [str(w["code"]) for w in found or [] if isinstance(w, dict) and w.get("code")],
        }

    # ------------------------------------------------------------- discovery
    @staticmethod
    def _run_summary(run: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": run.get("id"),
            "ts": run.get("ts"),
            "cidr": run.get("cidr"),
            "found": run.get("found"),
            "duration_s": run.get("duration_s"),
            "ok": run.get("ok", True),
            "error": run.get("error"),
        }

    def _discovery_defaults(self) -> Dict[str, Any]:
        """Default range, cached for a while (it touches the adapters)."""
        now = time.time()
        with self._lock:
            if self._disc_defaults and now - self._disc_defaults_ts < DISCOVERY_DEFAULTS_CACHE_S:
                return dict(self._disc_defaults)
        out: Dict[str, Any] = {"default_range": None}
        disc = self.discovery
        if disc is not None:
            try:
                out["default_range"] = disc.default_cidr()
            except Exception as exc:  # noqa: BLE001
                log.debug("default_cidr failed: %s", exc)
        with self._lock:
            self._disc_defaults = dict(out)
            self._disc_defaults_ts = now
        return out

    def discovery_start(self, range_text: Optional[str], ports: Optional[List[int]]) -> bool:
        """Start a scan in a background thread. False if one is already running.

        Raises ``ValueError`` for an invalid range (or when no default range can be
        determined) and ``RuntimeError`` when discovery is unavailable.
        """
        disc = self.discovery
        if disc is None:
            raise RuntimeError("network discovery is not available")
        with self._lock:
            if self._disc_thread is not None and self._disc_thread.is_alive():
                return False
            rt = (range_text or "").strip() if isinstance(range_text, str) else ""
            if not rt:
                try:
                    rt = str(disc.default_cidr() or "").strip()
                except Exception as exc:  # noqa: BLE001
                    raise ValueError(f"cannot determine the default scan range: {exc}") from exc
                if not rt:
                    raise ValueError("no range given and no default network could be determined")
            disc.parse_range(rt)  # ValueError with a helpful message on bad input
            if ports:
                ps = _clean_ports(ports)  # ValueError on a bad port
            else:
                ps = [int(p) for p in (self.config.get("discovery.ports") if self.config is not None else None) or []]
            cancel = threading.Event()
            self._disc_cancel = cancel
            self._disc_range = rt
            self._disc_ports = ps
            self._disc_started_ts = time.time()
            self._disc_progress = None
            self._disc_net_changed = False
            self._disc_network_id = self._network_id()      # the run is stored with the network it started on
            self._disc_gen = self._disc_clear_gen
            t = threading.Thread(target=self._discovery_run, args=(disc, rt, ps, cancel), name="tnt-discovery", daemon=True)
            self._disc_thread = t
            # announce before the worker runs so discovery.start always precedes discovery.progress
            log.info("discovery scan started: %s ports=%s", rt, ps)
            self._db_event("info", "discovery", f"scan started: {rt} ports {ps}")
            self._publish("discovery.start", {"range": rt, "ports": ps})
            t.start()
        return True

    def _on_discovery_progress(self, progress: Dict[str, Any]) -> None:
        snap = dict(progress or {})
        with self._lock:
            self._disc_progress = snap
            rt = self._disc_range
        payload = dict(snap)
        payload["range"] = rt
        self._publish("discovery.progress", payload)

    def _discovery_run(self, disc: Any, range_text: str, ports: List[int], cancel: threading.Event) -> None:
        result: Any = None
        run_id: Optional[int] = None
        voided = False
        with self._lock:
            gen = self._disc_gen
        summary: Dict[str, Any] = {"run_id": None, "ok": False, "error": None, "cancelled": False,
                                   "found": 0, "cidr": range_text, "duration_s": None}
        try:
            result = disc.scan(range_text, ports, progress=self._on_discovery_progress, cancel=cancel)
        except Exception as exc:  # noqa: BLE001 - scan() should never raise, but be safe
            log.exception("discovery scan crashed")
            summary["error"] = f"{type(exc).__name__}: {exc}"
        if result is not None:
            try:
                d = result.to_dict() if hasattr(result, "to_dict") else dict(result)
                hosts = [h if isinstance(h, dict) else h.to_dict() for h in (d.get("hosts") or [])]
                run = {k: d.get(k) for k in ("ts", "cidr", "ports", "method", "duration_s", "scanned", "ok", "error")}
                run["cidr"] = run.get("cidr") or range_text
                run["ports"] = run.get("ports") or ports
                if run.get("ts") is None:
                    run["ts"] = time.time()
                with self._lock:
                    network_id = self._disc_network_id
                if network_id is not None:
                    run["network_id"] = network_id
                with self._disc_persist_lock:
                    with self._lock:
                        voided = gen != self._disc_clear_gen    # the history was cleared while it ran (clear_history)
                    if self.db is not None and not voided:
                        run_id = int(self.db.add_discovery_run(run, hosts))
                summary.update({
                    "run_id": run_id,
                    "ok": bool(run.get("ok", True)),
                    "error": run.get("error"),
                    "cancelled": bool(d.get("cancelled", False)),
                    "found": len(hosts),
                    "cidr": run["cidr"],
                    "duration_s": run.get("duration_s"),
                    "method": run.get("method"),
                    "scanned": run.get("scanned"),
                })
                with self._lock:
                    voided = voided or gen != self._disc_clear_gen
                    if not voided:
                        self._last_discovery = {
                            "id": run_id, "ts": run["ts"], "cidr": run["cidr"], "found": len(hosts),
                            "duration_s": run.get("duration_s"), "ok": summary["ok"], "error": summary["error"],
                        }
            except Exception:  # noqa: BLE001
                log.exception("persisting the discovery run failed")
        with self._lock:
            # whatever the scan returned (a result, None, or it raised): a clear since it started voids it
            voided = voided or gen != self._disc_clear_gen
        if voided:
            # neither stored nor the last run: the page resets without a "Scan cancelled" or failure toast
            summary.update(run_id=None, cancelled=True, silent=True, cancel_reason="history cleared")
        with self._lock:
            self._disc_cancel = None
            # a scan that ran across a network change swept (part of) the network this PC left
            summary["network_changed"] = bool(self._disc_net_changed)
            self._disc_net_changed = False
        state = "cancelled" if summary["cancelled"] else ("finished" if summary["ok"] else "failed")
        log.info("discovery scan %s: %s found=%s run_id=%s error=%s%s", state, summary["cidr"], summary["found"], run_id,
                 summary["error"], " (the history was cleared: not kept)" if voided else "")
        if voided:
            self._db_event("info", "discovery", f"scan stopped: {summary['cidr']} - the history was cleared while it ran, "
                                                "so it was not kept")
        else:
            self._db_event("info" if summary["ok"] else "warning", "discovery",
                           f"scan {state}: {summary['cidr']} found {summary['found']}" + (f" ({summary['error']})" if summary["error"] else "")
                           + (" - the network changed during the scan" if summary["network_changed"] else ""))
        self._publish("discovery.done", summary)

    def discovery_running(self) -> bool:
        """True while a scan thread is alive (unlike :meth:`discovery_status`, no adapter or config access)."""
        with self._lock:
            return self._disc_thread is not None and self._disc_thread.is_alive()

    def discovery_cancel(self) -> bool:
        """Cancel the running scan; True if one was running."""
        with self._lock:
            running = self._disc_thread is not None and self._disc_thread.is_alive()
            cancel = self._disc_cancel
        if cancel is not None:
            cancel.set()
        disc = self.discovery
        if running and disc is not None:
            stop = getattr(disc, "stop", None)
            if callable(stop):
                # DiscoveryScanner.stop() also *waits* (up to 5 s) for the scan to end;
                # neither an API request nor Engine.stop() may hang on that, so run it
                # on a helper thread and give it a short bounded wait.  The cancel event
                # above is what actually aborts the scan; discovery.done reports the end.
                self._bounded("discovery-stop", stop, time.monotonic() + DISCOVERY_CANCEL_WAIT_S,
                              DISCOVERY_CANCEL_WAIT_S)
        if running:
            log.info("discovery scan cancel requested")
        return running

    def discovery_status(self) -> Dict[str, Any]:
        defaults = self._discovery_defaults()
        with self._lock:
            running = self._disc_thread is not None and self._disc_thread.is_alive()
            progress = dict(self._disc_progress) if self._disc_progress else None
            out = {
                "available": self.discovery is not None,
                "running": running,
                "progress": progress,
                "range": self._disc_range,
                "ports": list(self._disc_ports),
                "started_ts": self._disc_started_ts if running else None,
                "last_run": dict(self._last_discovery) if self._last_discovery else None,
            }
        default_ports: List[int] = []
        if self.config is not None:
            try:
                default_ports = [int(p) for p in (self.config.get("discovery.ports") or [])]
            except Exception:  # noqa: BLE001
                default_ports = []
        out["default_range"] = defaults.get("default_range")
        out["default_ports"] = default_ports
        return out

    # ------------------------------------------------------------- clear history
    def full_scan_running(self) -> bool:
        """Whether a Full Scan runs now (it reads the history as it goes, so a clear waits for it)."""
        mgr = getattr(self, "reports", None)
        job_fn = getattr(mgr, "job", None)
        if not callable(job_fn):
            return False
        try:
            job = job_fn()
        except Exception:  # noqa: BLE001
            log.exception("reading the Full Scan job failed")
            return False
        return isinstance(job, dict) and job.get("status") == "running"

    def clear_running(self) -> bool:
        """Whether a history clear runs now."""
        return self._clear_lock.locked()

    def outside_clear(self, fn: Callable[[], Any]) -> Any:
        """Run *fn* (a Full Scan start, ``POST /api/reports/scan``) unless a history clear runs:
        ``tnt.history.ClearConflict("clear_running")`` then.  Under ``_clear_gate``, which the clear holds while it checks
        that no Full Scan runs, so a scan that starts here is running when a clear looks, and a clear that looked first
        keeps any scan from starting until it is done."""
        from . import history

        with self._clear_gate:
            if self._clearing:
                raise history.ClearConflict("clear_running", history.SCAN_DURING_CLEAR_MSG)
            return fn()

    def clear_history(self, range_key: str, captures_allowed: bool = True,
                      captures_reason: Optional[str] = None) -> Dict[str, Any]:
        """Settings > "Clear history": remove what was recorded in the last *range_key* (``tnt.history.RANGES``; ``all`` is
        everything) and return the result, which is also published as ``history.cleared``.

        ``ValueError`` for another key; ``tnt.history.ClearConflict`` (``clear_running``) while another clear runs and
        (``full_scan_running``) while a Full Scan runs (checked under ``_clear_gate``, so no Full Scan starts until the
        clear is done: :meth:`outside_clear`).  ``since_ts`` is ``now - seconds`` on this clock.  In this order: the
        running jobs are stopped (the speed test through ``SpeedScheduler.clear_history``, which also reloads the last
        result from the tests before the span, so it goes before the database rows it must not race; the Discovery
        scanner's own ``clear_history`` first, so the scan running now cannot record its time, then the scan by bumping
        its generation and cancelling it) -> ``PingManager.clear_history`` -> ``OutageTracker.clear_history`` ->
        ``Database.clear_history(since, until_ts=now)`` (one transaction) -> ``SpeedScheduler.reload_last()`` (a test that
        started after the cancel and ended before the delete lost its row) -> the last Discovery run re-derived ->
        ``CaptureManager.clear_history`` (only when *captures_allowed*: the caller is a Windows administrator; else
        captures are skipped with *captures_reason*) -> ``FaultWatcher.clear_history`` -> ``AlgChecker`` /
        ``StunChecker`` / ``FlowReader.clear_history`` and ``SipQualifier.invalidate()`` -> ``ProAvScanner.clear_history``
        -> the cleared span recorded (``tnt.history.record_span``, from the earliest start of an outage or minute bucket
        it deleted when that is before ``since_ts``) -> ``ping.targets`` and ``history.cleared`` published.  Every step is
        guarded: a component that is missing, lacks its method or fails is logged and named in ``skipped`` and the rest
        still clears.  Components that keep nothing but memory (faults, SIP, Pro AV) and are not running have nothing to
        clear.  The answer names each packet capture left alone (for the administrator who asked); the published
        ``history.cleared``, which every window hears, only says how many and why.  Never deleted or changed: the
        reports table, the exports folder, networks, targets, network_offline, dhcp_leases, settings, LAN peers,
        speed-test cooldowns and events rows other than category ``outage`` (the clear adds one ``history`` row of its
        own)."""
        from . import history

        if not history.valid_range(range_key):
            raise ValueError(history.BAD_RANGE_MSG)
        if not self._clear_lock.acquire(blocking=False):
            raise history.ClearConflict("clear_running", history.CLEAR_RUNNING_MSG)
        try:
            with self._clear_gate:
                if self.full_scan_running():
                    raise history.ClearConflict("full_scan_running", history.FULL_SCAN_RUNNING_MSG)
                self._clearing = True
            try:
                return self._clear_history_locked(range_key, captures_allowed, captures_reason)
            finally:
                with self._clear_gate:
                    self._clearing = False
        finally:
            self._clear_lock.release()

    def _clear_history_locked(self, range_key: str, captures_allowed: bool,
                              captures_reason: Optional[str]) -> Dict[str, Any]:
        from . import history

        now = time.time()
        since = history.since_for(range_key, now)
        label = history.RANGE_LABELS[range_key]
        log.warning("clearing history: %s (since %s)", label, "the beginning" if since is None else f"{since:.0f}")
        job = _HistoryClear(since, now)
        self._clear_stop_jobs(job)
        self._clear_ping(job)
        self._clear_outages(job)
        self._clear_database(job)
        self._clear_rederive_discovery(job)
        self._clear_captures(job, captures_allowed, captures_reason)
        self._clear_faults(job)
        self._clear_sip(job)
        self._clear_proav(job)
        if self.db is not None:
            # a record that straddled since_ts went whole: the cleared time on the timeline starts where it began
            span_since = since if since is None else min([since] + job.earliest)
            job.step("timeline", lambda: history.record_span(self.db, span_since, now, range_key),
                     "the cleared time could not be marked on the Outages timeline")
        result: Dict[str, Any] = {
            "range": range_key, "label": label, "since_ts": since, "ts": now,
            "cleared": job.cleared, "stopped": job.stopped, "skipped": job.skipped,
        }
        counts = ", ".join(f"{k} {v}" for k, v in job.cleared.items() if v)
        self._db_event("info", "history", f"history cleared ({label}): {counts or 'nothing was recorded'}"
                       + (f"; left alone: {', '.join(s['what'] for s in job.skipped)}" if job.skipped else ""))
        pm = self.ping
        if pm is not None and callable(getattr(pm, "publish_targets", None)):
            job.step("ping", pm.publish_targets, "the ping tiles could not be refreshed")
        # every window hears the event: the capture files left alone are counted there, never named
        self._publish("history.cleared", dict(copy.deepcopy(result), skipped=job.public_skipped()))
        log.warning("history cleared (%s): %s; stopped %s; skipped %s", label, job.cleared, job.stopped or "nothing",
                    job.skipped or "nothing")
        return result

    def _clear_stop_jobs(self, job: "_HistoryClear") -> None:
        """Stop what is running and would store history after the clear: the speed test and the Discovery scan."""
        from . import history

        sched = self.speed
        if sched is not None:
            res = job.method("speed", sched, "clear_history", (job.since,), "the running speed test could not be stopped "
                             "and the Speed tile may show the last test until the next one")
            if isinstance(res, dict) and res.get("stopped"):
                job.stopped.append(history.STOPPED_SPEED)
        disc = self.discovery
        if disc is not None:
            # before the scan is cancelled: a scan running now must not record its time as the last scan when it ends
            job.method("discovery", disc, "clear_history", (job.since,), "the Discovery scanner kept its last scan time")
        with self._disc_persist_lock:
            with self._lock:
                self._disc_clear_gen += 1
                running = self._disc_thread is not None and self._disc_thread.is_alive()
        if running:
            job.step("discovery", self.discovery_cancel, "the running Discovery scan could not be stopped")
            job.stopped.append(history.STOPPED_DISCOVERY)

    def _clear_ping(self, job: "_HistoryClear") -> None:
        pm = self.ping
        if pm is not None:
            n = job.method("ping", pm, "clear_history", (job.since,), "the ping history could not be cleared")
            if n is not None:
                job.cleared["ping"] = int(n)
                info = getattr(pm, "last_clear_info", None) or {}
                job.note_earliest(info.get("earliest_ts"))
                failed = info.get("raw_log_failed") or []
                if failed:
                    job.skip("ping logs", "Some raw ping log files could not be changed: " + ", ".join(str(f) for f in failed))
            return
        # monitoring is not running: nothing is in memory, the stored history still goes
        if self.db is None:
            job.skip("ping", "The database is not available, so the ping history was left alone")
        else:
            info: Dict[str, Any] = {}
            n = job.step("ping", lambda: self.db.delete_ping_minutes_since(job.since, info=info),
                         "the ping history could not be cleared")
            if n is not None:
                job.cleared["ping"] = int(n)
                job.note_earliest(info.get("earliest_ts"))
        raw = self.raw_log
        if raw is not None and callable(getattr(raw, "clear_since", None)):
            job.step("ping logs", lambda: raw.clear_since(job.since, until_ts=job.now), "the raw ping logs could not be cleared")

    def _clear_outages(self, job: "_HistoryClear") -> None:
        tracker = self.outages
        if tracker is not None:
            n = job.method("outages", tracker, "clear_history", (job.since,), "the outage history could not be cleared")
            if n is not None:
                job.note_earliest((getattr(tracker, "last_clear_info", None) or {}).get("earliest_ts"))
        elif self.db is not None:
            info: Dict[str, Any] = {}
            n = job.step("outages", lambda: self.db.delete_outages_since(job.since, info=info),
                         "the outage history could not be cleared")
            if n is not None:
                job.note_earliest(info.get("earliest_ts"))
        else:
            job.skip("outages", "The database is not available, so the outages were left alone")
            n = None
        if n is not None:
            job.cleared["outages"] = int(n)

    def _clear_database(self, job: "_HistoryClear") -> None:
        """Speed tests, Discovery scans (and ``outage`` events up to the clear's start) in one transaction: all of them or
        none.  Then the speed scheduler re-reads its last result from what is left."""
        if self.db is None:
            job.skip("speed and discovery", "The database is not available, so the speed tests and Discovery scans were left alone")
            return
        res = job.step("speed and discovery", lambda: self.db.clear_history(job.since, until_ts=job.now),
                       "the speed tests and Discovery scans could not be deleted, so none of them was")
        if isinstance(res, dict):
            job.cleared["speed"] = int(res.get("speedtests") or 0)
            job.cleared["discovery"] = int(res.get("discovery_runs") or 0)
        sched = self.speed
        reload_last = getattr(sched, "reload_last", None) if sched is not None else None
        if callable(reload_last):
            # a test that started after the cancel and ended before the delete lost its row: the tile must not show it
            job.step("speed", reload_last, "the Speed tile may show a deleted speed test until the next one")

    def _clear_rederive_discovery(self, job: "_HistoryClear") -> None:
        """The Discovery tile's last run: the newest run left (or none).  (The scanner's own last-run time was forgotten
        when the jobs were stopped.)"""
        if self.db is not None:
            runs = job.step("discovery", lambda: self.db.list_discovery_runs(1),
                            "the Discovery tile could not re-read its last scan")
            if runs is not None:
                with self._lock:
                    self._last_discovery = self._run_summary(runs[0]) if runs else None
        else:
            with self._lock:
                last = self._last_discovery
                if last is not None and (job.since is None or float(last.get("ts") or 0.0) >= job.since):
                    self._last_discovery = None

    def _clear_captures(self, job: "_HistoryClear", allowed: bool, reason: Optional[str]) -> None:
        if not allowed:
            job.skip("captures", reason or "Packet captures need a Windows administrator account, so they were left alone")
            return
        cap = self.capture
        if cap is None:
            job.skip("captures", "Packet capture is not available, so its files were left alone")
            return
        res = job.method("captures", cap, "clear_history", (job.since,), "the packet captures could not be cleared")
        if not isinstance(res, dict):
            return
        job.cleared["captures"] = int(res.get("deleted") or 0) + (1 if res.get("discarded_unsaved") else 0)
        folder: Optional[Path] = None
        try:
            folder = paths.captures_dir()
        except Exception:  # noqa: BLE001
            log.exception("the captures folder could not be named")
        if folder is not None:
            job.deleted_paths = [str(folder / str(name)) for name in res.get("deleted_names") or [] if name]
        for item in res.get("skipped") or []:
            if isinstance(item, dict):
                name, why = str(item.get("name") or "a capture"), str(item.get("reason") or "it could not be deleted")
                job.skip_capture_file(name, why)
        if res.get("recording"):
            job.skip("captures", "A packet capture is recording, so it was left alone. "
                                 "Stop it and clear the history again to remove it")

    def _clear_faults(self, job: "_HistoryClear") -> None:
        fw = self.faults
        if fw is not None:
            n = job.method("faults", fw, "clear_history", (job.since,), "the fault watch could not start over")
            if n is not None:
                job.cleared["faults"] = int(n)

    def _clear_sip(self, job: "_HistoryClear") -> None:
        from . import history

        total, stopped = 0, False
        for name, what in (("sipalg", "the SIP ALG check result"), ("sipnat", "the SIP NAT (STUN) result")):
            comp = getattr(self, name, None)
            if comp is None:
                continue
            running_fn = getattr(comp, "running", None)
            try:
                was_running = bool(running_fn()) if callable(running_fn) else False
            except Exception:  # noqa: BLE001
                was_running = False
            n = job.method("sip", comp, "clear_history", (job.since,), f"{what} could not be cleared")
            if n is not None:
                total += int(n)
                stopped = stopped or was_running
        flow = getattr(self, "sipflow", None)
        if flow is not None:
            n = job.method("sip", flow, "clear_history", (job.since,), "the SIP call flows could not be closed",
                           {"deleted_paths": tuple(job.deleted_paths)})
            if n is not None:
                total += int(n)
        qual = getattr(self, "sipqual", None)
        if qual is not None:
            job.method("sip", qual, "invalidate", (), "the SIP tile may show its old verdict for up to a minute")
        job.cleared["sip"] = total
        if stopped:
            job.stopped.append(history.STOPPED_SIP)

    def _clear_proav(self, job: "_HistoryClear") -> None:
        from . import history

        scanner = getattr(self, "proav", None)
        if scanner is None:
            return
        res = job.method("proav", scanner, "clear_history", (job.since,), "the Pro AV result could not be cleared")
        if isinstance(res, dict):
            job.cleared["proav"] = int(res.get("cleared") or 0)
            if res.get("stopped"):
                job.stopped.append(history.STOPPED_PROAV)


class _HistoryClear:
    """What one :meth:`Engine.clear_history` has done so far: ``cleared`` (every category, 0 until counted), ``stopped``,
    ``skipped``, the capture files it deleted (for the SIP call-flow reader) and the earliest start of a record it deleted
    (``earliest``: where the cleared span begins when that is before ``since``).  :meth:`step` and :meth:`method` run one
    guarded step: a failure is logged and named in ``skipped``, and None comes back.  Every reason is one plain sentence
    without its closing period (the page adds one)."""

    def __init__(self, since: Optional[float], now: float) -> None:
        from . import history

        self.since = since
        self.now = float(now)
        self.cleared: Dict[str, int] = history.empty_counts()
        self.stopped: List[str] = []
        self.skipped: List[Dict[str, str]] = []
        self.deleted_paths: List[str] = []
        self.earliest: List[float] = []
        self._capture_files: Dict[int, str] = {}       # id() of a skipped entry naming a capture file -> its reason

    def skip(self, what: str, reason: str) -> None:
        from . import history

        self.skipped.append({"what": what, "reason": history.reason_text(reason)})

    def skip_capture_file(self, name: str, why: str) -> None:
        """One packet capture file left alone: named in the answer, only counted in the published event."""
        from . import history

        entry = {"what": "captures", "reason": history.capture_skip_reason(name, why)}
        self.skipped.append(entry)
        self._capture_files[id(entry)] = why

    def public_skipped(self) -> List[Dict[str, str]]:
        """``skipped`` for the ``history.cleared`` event: the capture files left alone become one "N packet captures were
        left alone" entry per reason, where the first of them was, without their names."""
        from . import history

        out: List[Dict[str, str]] = []
        summary_done = False
        for entry in self.skipped:
            if id(entry) in self._capture_files:
                if not summary_done:
                    out.extend(history.public_capture_skips(self._capture_files.values()))
                    summary_done = True
                continue
            out.append(dict(entry))
        return out

    def note_earliest(self, ts: Any) -> None:
        """A record deleted by the clear began at *ts* (None: none was)."""
        if isinstance(ts, (int, float)) and not isinstance(ts, bool) and math.isfinite(float(ts)):
            self.earliest.append(float(ts))

    def step(self, what: str, fn: Callable[[], Any], reason: str) -> Any:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - one part must never stop the rest of the clear
            log.exception("clear history: %s failed", what)
            detail = str(exc).strip() or type(exc).__name__
            self.skip(what, f"{reason[:1].upper()}{reason[1:]} ({detail[:200]})")
            return None

    def method(self, what: str, component: Any, name: str, args: tuple, reason: str,
               kwargs: Optional[Dict[str, Any]] = None) -> Any:
        """``component.<name>(*args, **kwargs)`` when it has that method; a component without it (an older part) is
        named in ``skipped``."""
        fn = getattr(component, name, None)
        if not callable(fn):
            log.warning("clear history: %s has no %s()", type(component).__name__, name)
            self.skip(what, f"{reason[:1].upper()}{reason[1:]}: this part of TNT cannot clear its history yet")
            return None
        return self.step(what, lambda: fn(*args, **(kwargs or {})), reason)


__all__ = ["Engine", "HEARTBEAT_INTERVAL_S", "API_RETRY_INTERVAL_S", "STOP_BUDGET_S"]
