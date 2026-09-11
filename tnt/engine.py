"""The service engine: owns and supervises every component.

Start order: ``ensure_dirs -> logging -> config -> db -> bus -> close stale outages /
gap row -> dhcp-restore (undo a NIC re-address left behind by a previous run) ->
IcmpPinger -> PingManager -> OutageTracker -> SpeedScheduler -> DiscoveryScanner ->
DhcpServer (constructed, never started by itself) -> LanPeers (beacon + throughput server,
started) -> ApiServer -> maintenance thread (heartbeat + retention)``.

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
"""
from __future__ import annotations

import datetime as _dt
import logging
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
        self.raw_log: Any = None
        self.ping: Any = None
        self.outages: Any = None
        self.speed: Any = None
        self.discovery: Any = None
        self.dhcp: Any = None
        self.lan: Any = None
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

        # monitoring-gap bookkeeping (sleep detection, pause spans) and the db retry thread
        self._last_hb_ts: Optional[float] = None
        self._pause_started: Optional[float] = None
        self._db_retry_thread: Optional[threading.Thread] = None

        # netinfo summary cache
        self._netinfo_lock = threading.Lock()
        self._netinfo_cache: Optional[Dict[str, Any]] = None
        self._netinfo_cache_ts = 0.0

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
        self._close_stale_outages()
        self._step("dhcp-restore", self._restore_dhcp_nic)
        self._start_pinger()
        self._start_ping_manager()
        self._start_linkmap()
        self._start_outages()
        self._start_speed()
        self._start_discovery()
        self._start_dhcp()
        self._start_lan()
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
        try:
            self.discovery_cancel()
        except Exception:  # noqa: BLE001
            log.exception("discovery cancel failed")
        self._join(self._api_retry_thread, deadline, 1.0)
        self._join(self._maint_thread, deadline, 2.0)
        if self.api is not None:
            self._bounded("api", lambda: self.api.stop(timeout=min(3.0, max(0.5, deadline - time.monotonic()))), deadline, 3.5)
        if self.dhcp is not None:
            # after the API (no request can reach it mid-teardown) and before the pinger
            # goes away; stop() also puts a re-addressed adapter back on DHCP
            self._bounded("dhcp", self.dhcp.stop, deadline, 3.0)
        if self.lan is not None:
            # closes the beacon listener and the throughput server (a test in flight is cut)
            self._bounded("lan", self.lan.stop, deadline, 2.0)
        self._join(self._disc_thread, deadline, 2.0)
        if self.speed is not None:
            self._bounded("speedtest", self.speed.stop, deadline, 3.0)
        if self.outages is not None:
            self._bounded("outages", self.outages.stop, deadline, 2.0)
        if getattr(self, "linkmap", None) is not None:
            self._bounded("linkmap", self.linkmap.stop, deadline, 2.0)
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
            for name in ("ping", "outages", "speedtest", "dhcp", "dhcp-restore"):
                self.errors.pop(name, None)
            try:
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
                info = close_stale_outages(self.db, now)
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
            pm = PingManager(self.db, self.config, self.bus, pinger=self.pinger, raw_log=self.raw_log)
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

            lm = LinkMap(self.config, self.bus, pinger=self.pinger)
            lm.start()
            self.linkmap = lm
        except Exception as exc:  # noqa: BLE001
            self.linkmap = None
            self._fail("linkmap", exc)

    def _start_outages(self) -> None:
        if self.ping is None:
            self.errors.setdefault("outages", "ping manager unavailable")
            log.error("outage tracker skipped: ping manager unavailable")
            return
        try:
            from .outages import OutageTracker

            tracker = OutageTracker(self.db, self.config, self.bus, self.ping,
                                    suppress_new=self._speedtest_running)
            tracker.start()
            self.outages = tracker
        except Exception as exc:  # noqa: BLE001
            self.outages = None
            self._fail("outages", exc)

    def _start_speed(self) -> None:
        if self.db is None:
            self.errors["speedtest"] = "database unavailable"
            return
        try:
            from .speedtest import SpeedScheduler

            sched = SpeedScheduler(self.db, self.config, self.bus)
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
        """``{"internet_nic": {...}|None, "adapter_count": int}`` for /api/status (cached 10 s)."""
        now = time.time()
        with self._netinfo_lock:
            if self._netinfo_cache is not None and now - self._netinfo_cache_ts < NETINFO_CACHE_S:
                return dict(self._netinfo_cache)
        summary: Dict[str, Any] = {"internet_nic": None, "adapter_count": 0}
        try:
            from . import netinfo  # lazy: optional at runtime

            adapters = netinfo.get_adapters() or []
            summary["adapter_count"] = len(adapters)
            nic = netinfo.get_internet_nic(adapters)
            if nic is not None:
                v4 = list(getattr(nic, "ipv4", None) or [])
                # prefer the preferred (non-tentative, non-APIPA) address the NIC reports as primary
                primary = getattr(nic, "primary_ipv4", None)
                first = next((a for a in v4 if getattr(a, "address", None) == primary), None) or (v4[0] if v4 else None)
                gws = [g for g in (getattr(nic, "gateways", None) or []) if ":" not in str(g)] or list(getattr(nic, "gateways", None) or [])
                v4gw = getattr(nic, "ipv4_gateway", None)
                if v4gw:
                    gws = [v4gw] + [g for g in gws if g != v4gw]
                summary["internet_nic"] = {
                    "index": getattr(nic, "index", None),
                    "name": getattr(nic, "name", None),
                    "description": getattr(nic, "description", None),
                    "type_name": getattr(nic, "type_name", None),
                    "ipv4": getattr(first, "address", None) if first is not None else None,
                    "network": getattr(first, "network", None) if first is not None else None,
                    "gateway": gws[0] if gws else None,
                    "mac": getattr(nic, "mac", None),
                }
        except Exception as exc:  # noqa: BLE001
            log.debug("netinfo summary unavailable: %s", exc)
            summary["error"] = f"{type(exc).__name__}: {exc}"
        with self._netinfo_lock:
            self._netinfo_cache = dict(summary)
            self._netinfo_cache_ts = now
        return summary

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
                if self.db is not None:
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
                    self._last_discovery = {
                        "id": run_id, "ts": run["ts"], "cidr": run["cidr"], "found": len(hosts),
                        "duration_s": run.get("duration_s"), "ok": summary["ok"], "error": summary["error"],
                    }
            except Exception:  # noqa: BLE001
                log.exception("persisting the discovery run failed")
        with self._lock:
            self._disc_cancel = None
        state = "cancelled" if summary["cancelled"] else ("finished" if summary["ok"] else "failed")
        log.info("discovery scan %s: %s found=%s run_id=%s error=%s", state, summary["cidr"], summary["found"], run_id, summary["error"])
        self._db_event("info" if summary["ok"] else "warning", "discovery",
                       f"scan {state}: {summary['cidr']} found {summary['found']}" + (f" ({summary['error']})" if summary["error"] else ""))
        self._publish("discovery.done", summary)

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


__all__ = ["Engine", "HEARTBEAT_INTERVAL_S", "API_RETRY_INTERVAL_S", "STOP_BUDGET_S"]
