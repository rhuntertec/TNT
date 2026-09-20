"""Windows service wrapper and command-line entry point.

``python -m tnt`` / ``TNTService.exe`` delegate to :func:`main`:

* no arguments - frozen: host the service (``servicemanager.Initialize`` +
  ``PrepareToHostSingle`` + ``StartServiceCtrlDispatcher``); not frozen:
  pywin32's ``HandleCommandLine`` (prints its usage).
* ``install`` / ``remove`` / ``start`` / ``stop`` / ``restart`` / ``status`` -
  frozen: shell out to ``sc.exe`` (``create`` with a quoted ``binPath=``,
  ``start= auto``, ``DisplayName=``; ``sc config`` with the same values when the
  service already exists so a re-install re-points it at this exe;
  ``sc description``; ``sc failure ... actions= restart/5000/restart/10000/restart/30000``);
  not frozen: pywin32's ``HandleCommandLine`` so ``python -m tnt install`` works
  for development.
* ``--console [--port N] [--data-dir D]`` - run the engine in the foreground
  until Ctrl-C, exit code 0.  This is the one place ``print()`` is used (the URL
  being served and the shutdown notice); everything else logs.
* ``--version`` / ``--help``.

Contract gaps resolved here (documented deviations):

* ``--console`` without ``--port`` (and without a ``PORT``/``TNT_PORT`` env
  override) uses **7135**, TNT's dev/console port, so a console run
  never collides with an installed service on 7130.
* ``sc create`` passes the binPath pre-quoted (``"\"C:\\...\\TNTService.exe\""``)
  so the registry ImagePath is quoted even when the path has spaces.
* When pythonservice.exe (dev-mode install) imports this file as a top-level
  module, the package root is added to ``sys.path`` and ``__package__`` set so the
  relative imports keep working.
* CLI helpers print to stdout/stderr - they only ever run interactively - but
  tolerate the streams being ``None`` (frozen service process, pythonw).
"""
from __future__ import annotations

import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

if __package__ in (None, ""):  # pragma: no cover - only under pythonservice.exe dev installs
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "tnt"  # noqa: A001

from . import (  # noqa: E402
    APP_LONG_NAME,
    SERVICE_DESCRIPTION,
    SERVICE_DISPLAY_NAME,
    SERVICE_NAME,
    __version__,
    paths,
)

log = logging.getLogger(__name__)

try:  # pywin32 is only present on Windows; keep the module importable elsewhere
    import servicemanager  # type: ignore
    import win32event  # type: ignore  # noqa: F401
    import win32service  # type: ignore
    import win32serviceutil  # type: ignore

    HAVE_PYWIN32 = True
except ImportError:  # pragma: no cover - non-Windows
    servicemanager = win32event = win32service = win32serviceutil = None  # type: ignore[assignment]
    HAVE_PYWIN32 = False

CONSOLE_DEFAULT_PORT = 7135
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SC_COMMANDS = ("install", "remove", "start", "stop", "restart", "status")
SC_FAILURE_ACTIONS = "restart/5000/restart/10000/restart/30000"
SC_FAILURE_RESET_S = 86400
SC_TIMEOUT_S = 60
SC_WAIT_S = 30.0
SC_ERROR_HINTS: Dict[int, str] = {
    5: "access denied - run this from an elevated (Administrator) command prompt",
    1056: "the service is already running",
    1060: "the service is not installed",
    1062: "the service is not running",
    1072: "the service is marked for deletion - close services.msc and retry",
    1073: "the service already exists",
}
_STATE_RE = re.compile(r"STATE\s*:\s*(\d+)\s+([A-Z_]+)")

Runner = Callable[[List[str]], Tuple[int, str]]


# ---------------------------------------------------------------------------
# output helpers (interactive CLI only)
# ---------------------------------------------------------------------------
def _print(stream: Any, text: str) -> None:
    # In a frozen service process (or under pythonw) the standard streams are None
    # or already closed; a CLI notice must never turn into an AttributeError/OSError.
    if stream is None:
        return
    try:
        print(text, file=stream, flush=True)
    except (OSError, ValueError, AttributeError):
        pass


def _out(text: str) -> None:
    _print(sys.stdout, text)


def _err(text: str) -> None:
    _print(sys.stderr, text)


def usage() -> str:
    exe = "TNTService.exe" if paths.is_frozen() else "python -m tnt"
    return (
        f"{APP_LONG_NAME} service v{__version__}\n"
        f"\n"
        f"Usage:\n"
        f"  {exe}                       run as a Windows service (started by the Service Control Manager)\n"
        f"  {exe} install               install the {SERVICE_NAME} service (auto start, restart on failure)\n"
        f"  {exe} remove                stop and remove the service\n"
        f"  {exe} start | stop | restart | status\n"
        f"  {exe} --console [--port N] [--data-dir DIR]\n"
        f"                              run in the foreground (default port {CONSOLE_DEFAULT_PORT}); Ctrl-C stops\n"
        f"  {exe} --version\n"
        f"\n"
        f"Data directory: {paths.data_dir()} (override with TNT_DATA_DIR or --data-dir)\n"
    )


# ---------------------------------------------------------------------------
# the service class
# ---------------------------------------------------------------------------
if HAVE_PYWIN32:

    class TNTService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        """pywin32 service: runs :class:`tnt.engine.Engine` until the SCM says stop."""

        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args: Any) -> None:
            super().__init__(args)
            self.stop_event = threading.Event()
            self.engine: Any = None

        # -- SCM callbacks -------------------------------------------------
        def SvcStop(self) -> None:  # noqa: N802 - pywin32 API
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=15000)
            self.stop_event.set()

        def SvcShutdown(self) -> None:  # noqa: N802 - pywin32 API
            self.SvcStop()

        def SvcDoRun(self) -> None:  # noqa: N802 - pywin32 API
            self._event_log(servicemanager.PYS_SERVICE_STARTED)
            # tells tnt.config to ignore the generic PORT/HOST environment variables
            # (a machine-wide PORT must not re-point the installed service)
            os.environ["TNT_SERVICE_MODE"] = "1"
            try:
                from .engine import Engine

                self.engine = Engine(console=False)
                self.engine.start()
                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
                self.engine.run_forever(self.stop_event)
            except Exception as exc:  # noqa: BLE001
                log.exception("service run failed")
                try:
                    servicemanager.LogErrorMsg(f"{SERVICE_NAME} failed: {exc!r}")
                except Exception:  # noqa: BLE001
                    pass
            finally:
                engine, self.engine = self.engine, None
                if engine is not None:
                    try:
                        engine.stop()
                    except Exception:  # noqa: BLE001
                        log.exception("engine stop failed")
                self._event_log(servicemanager.PYS_SERVICE_STOPPED)

        def _event_log(self, msg_id: int) -> None:
            try:
                servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, msg_id, (self._svc_name_, ""))
            except Exception:  # noqa: BLE001
                pass

else:  # pragma: no cover - non-Windows placeholder so imports never fail

    class TNTService:  # type: ignore[no-redef]
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args: Any) -> None:
            raise RuntimeError("pywin32 is required to run TNT as a Windows service")


# ---------------------------------------------------------------------------
# service hosting / pywin32 command line
# ---------------------------------------------------------------------------
def run_dispatcher() -> int:
    """Host the service in this (frozen) process. Returns an exit code."""
    if not HAVE_PYWIN32:
        _err("pywin32 is not available; cannot run as a Windows service.")
        return 1
    try:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(TNTService)
        servicemanager.StartServiceCtrlDispatcher()
        return 0
    except Exception as exc:  # noqa: BLE001 - typically error 1063 when run interactively
        _err(
            f"{SERVICE_NAME}: could not connect to the Service Control Manager ({exc}).\n"
            f"This program is a Windows service. Install it with `{Path(sys.executable).name} install` and start it with\n"
            f"`{Path(sys.executable).name} start`, or run it interactively with `--console`.\n"
        )
        _err(usage())
        return 1


def handle_command_line(args: Sequence[str]) -> int:
    """Delegate to pywin32's ``HandleCommandLine`` (dev mode). Returns an exit code."""
    if not HAVE_PYWIN32:
        _err("pywin32 is not available; service commands need Windows + pywin32.")
        return 1
    argv = [sys.argv[0] if sys.argv and sys.argv[0] else "tnt"] + list(args)
    try:
        rc = win32serviceutil.HandleCommandLine(TNTService, argv=argv)
    except SystemExit as exc:  # HandleCommandLine's usage() calls sys.exit
        code = exc.code
        return code if isinstance(code, int) else (0 if code is None else 1)
    except Exception as exc:  # noqa: BLE001
        _err(f"service command failed: {exc}")
        return 1
    return int(rc or 0)


# ---------------------------------------------------------------------------
# sc.exe based management (frozen builds)
# ---------------------------------------------------------------------------
def service_exe_path() -> str:
    """Path of the service executable registered as binPath."""
    return str(Path(sys.executable).resolve())


def sc_exe() -> str:
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    cand = Path(root) / "System32" / "sc.exe"
    return str(cand) if cand.is_file() else "sc.exe"


def _sc_argv(args: Sequence[str]) -> List[str]:
    return [sc_exe(), *args]


def _run_sc(args: List[str]) -> Tuple[int, str]:
    """Run ``sc.exe`` with *args*; returns ``(returncode, combined output)``."""
    argv = _sc_argv(args)
    log.debug("running %s", subprocess.list2cmdline(argv))
    try:
        # sc.exe prints in the OEM code page: decode leniently (a stray byte must not
        # crash the installer), and never pop a console when the caller has none.
        proc = subprocess.run(argv, capture_output=True, text=True, errors="replace", stdin=subprocess.DEVNULL,
                              timeout=SC_TIMEOUT_S, check=False, creationflags=_CREATE_NO_WINDOW)
    except FileNotFoundError:
        return 9009, "sc.exe was not found"
    except subprocess.TimeoutExpired:
        return 1460, f"sc.exe {args[0]} timed out after {SC_TIMEOUT_S} s"
    except OSError as exc:
        return 1, f"could not run sc.exe: {exc}"
    output = (proc.stdout or "") + (proc.stderr or "")
    return int(proc.returncode), output.strip()


def _report(rc: int, output: str, what: str) -> None:
    hint = SC_ERROR_HINTS.get(rc)
    if rc == 0:
        _out(f"{what}: OK" + (f"\n{output}" if output else ""))
    else:
        _err(f"{what}: failed (sc.exe returned {rc}{' - ' + hint if hint else ''})" + (f"\n{output}" if output else ""))


def sc_state(runner: Optional[Runner] = None) -> Optional[str]:
    """``RUNNING`` / ``STOPPED`` / ``START_PENDING`` ... or None when not installed."""
    run = runner or _run_sc
    rc, output = run(["query", SERVICE_NAME])
    if rc != 0:
        return None
    m = _STATE_RE.search(output)
    return m.group(2) if m else None


def _wait_state(target: str, runner: Optional[Runner], timeout_s: float = SC_WAIT_S) -> Optional[str]:
    """Poll ``sc query`` until the service reaches *target* (or is gone), up to *timeout_s*.

    Waiting for ``RUNNING`` gives up early once the service has settled back to
    ``STOPPED`` (it crashed during start) instead of burning the whole timeout.
    """
    deadline = time.monotonic() + timeout_s
    state = sc_state(runner)
    polls = 0
    while state not in (target, None) and time.monotonic() < deadline:
        if target == "RUNNING" and state == "STOPPED" and polls >= 2:
            break
        time.sleep(0.5)
        state = sc_state(runner)
        polls += 1
    return state


def sc_install(runner: Optional[Runner] = None, exe: Optional[str] = None) -> int:
    """``sc create`` + ``sc description`` + ``sc failure``."""
    run = runner or _run_sc
    exe = exe or service_exe_path()
    quoted = f'"{exe}"'  # pre-quoted so the registry ImagePath is quoted
    rc, output = run(["create", SERVICE_NAME, "binPath=", quoted, "start=", "auto", "DisplayName=", SERVICE_DISPLAY_NAME])
    _report(rc, output, f"create {SERVICE_NAME}")
    if rc == 1073:
        # already installed (upgrade / re-run): re-point it at this exe so an install
        # into a different folder does not leave the SCM starting the old binary
        rc, output = run(["config", SERVICE_NAME, "binPath=", quoted, "start=", "auto", "DisplayName=", SERVICE_DISPLAY_NAME])
        _report(rc, output, f"update {SERVICE_NAME}")
    if rc != 0:
        return rc
    rc2, output2 = run(["description", SERVICE_NAME, SERVICE_DESCRIPTION])
    _report(rc2, output2, "set description")
    rc3, output3 = run(["failure", SERVICE_NAME, "reset=", str(SC_FAILURE_RESET_S), "actions=", SC_FAILURE_ACTIONS])
    _report(rc3, output3, "set failure actions")
    _out(f"{SERVICE_DISPLAY_NAME} installed ({exe}). Start it with: {Path(exe).name} start")
    return 0 if rc3 == 0 and rc2 == 0 else (rc3 or rc2)


def sc_start(runner: Optional[Runner] = None) -> int:
    run = runner or _run_sc
    rc, output = run(["start", SERVICE_NAME])
    if rc == 1056:
        _out(f"{SERVICE_NAME} is already running")
        return 0
    _report(rc, output, f"start {SERVICE_NAME}")
    if rc != 0:
        return rc
    state = _wait_state("RUNNING", runner)
    _out(f"{SERVICE_NAME} state: {state or 'unknown'}")
    return 0 if state == "RUNNING" else 1


def sc_stop(runner: Optional[Runner] = None, quiet_if_stopped: bool = False) -> int:
    run = runner or _run_sc
    rc, output = run(["stop", SERVICE_NAME])
    if rc == 1062:
        if not quiet_if_stopped:
            _out(f"{SERVICE_NAME} is not running")
        return 0
    if rc == 1060 and quiet_if_stopped:
        return 0
    _report(rc, output, f"stop {SERVICE_NAME}")
    if rc != 0:
        return rc
    state = _wait_state("STOPPED", runner)
    _out(f"{SERVICE_NAME} state: {state or 'unknown'}")
    return 0 if state in ("STOPPED", None) else 1


def sc_restart(runner: Optional[Runner] = None) -> int:
    rc = sc_stop(runner, quiet_if_stopped=True)
    if rc != 0:
        return rc
    return sc_start(runner)


def sc_remove(runner: Optional[Runner] = None) -> int:
    run = runner or _run_sc
    sc_stop(runner, quiet_if_stopped=True)
    rc, output = run(["delete", SERVICE_NAME])
    if rc == 1060:
        _out(f"{SERVICE_NAME} is not installed")
        return 0
    _report(rc, output, f"delete {SERVICE_NAME}")
    return rc


def sc_status(runner: Optional[Runner] = None) -> int:
    state = sc_state(runner)
    if state is None:
        _out(f"{SERVICE_NAME}: not installed")
        return 1
    _out(f"{SERVICE_NAME}: {state}")
    return 0


SC_HANDLERS: Dict[str, Callable[..., int]] = {
    "install": sc_install,
    "remove": sc_remove,
    "start": sc_start,
    "stop": sc_stop,
    "restart": sc_restart,
    "status": sc_status,
}


# ---------------------------------------------------------------------------
# console mode
# ---------------------------------------------------------------------------
def parse_console_args(args: Sequence[str]) -> Dict[str, Any]:
    """``--port N`` / ``--port=N`` and ``--data-dir D`` / ``--data-dir=D``."""
    opts: Dict[str, Any] = {"port": None, "data_dir": None}
    items = list(args)
    i = 0
    while i < len(items):
        arg = items[i]
        key, eq, inline = arg.partition("=")
        if key in ("--port", "-p"):
            value = inline if eq else (items[i + 1] if i + 1 < len(items) else None)
            if value is None:
                raise ValueError("--port needs a number")
            try:
                opts["port"] = int(value)
            except ValueError:
                raise ValueError(f"invalid port {value!r}") from None
            if not 0 <= opts["port"] <= 65535:
                raise ValueError(f"port {opts['port']} is out of range 0-65535")
            i += 1 if eq else 2
        elif key in ("--data-dir", "-d"):
            value = inline if eq else (items[i + 1] if i + 1 < len(items) else None)
            if not value:
                raise ValueError("--data-dir needs a directory")
            opts["data_dir"] = value
            i += 1 if eq else 2
        else:
            raise ValueError(f"unknown option {arg!r}")
    return opts


def _install_signal_handlers(stop: threading.Event) -> None:
    if threading.current_thread() is not threading.main_thread():
        return

    def _handler(signum: int, _frame: Any) -> None:
        log.info("signal %s received; stopping", signum)
        stop.set()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):  # not the main thread / unsupported
            pass


def _service_answering(timeout: float = 1.0) -> bool:
    """True when something answers /api/health on the installed service's port."""
    import http.client
    import json as _json

    from . import DEFAULT_PORT

    try:
        conn = http.client.HTTPConnection("127.0.0.1", DEFAULT_PORT, timeout=timeout)
        conn.request("GET", "/api/health", headers={"Host": f"127.0.0.1:{DEFAULT_PORT}"})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status == 200 and bool(_json.loads(body or b"{}").get("ok"))
    except Exception:  # noqa: BLE001
        return False


def run_console(port: Optional[int] = None, data_dir: Optional[str] = None,
                stop_event: Optional[threading.Event] = None) -> int:
    """Run the engine in the foreground until Ctrl-C (or *stop_event*). Returns 0 on a clean exit."""
    from . import logging_setup
    from .engine import Engine

    if data_dir:
        os.environ["TNT_DATA_DIR"] = str(data_dir)
    if port is None and not (os.environ.get("TNT_PORT") or os.environ.get("PORT")):
        port = CONSOLE_DEFAULT_PORT
    if not data_dir and not os.environ.get("TNT_DATA_DIR") and _service_answering():
        from . import DEFAULT_PORT

        _err(f"error: the installed TNT service is running on 127.0.0.1:{DEFAULT_PORT}; a console run without\n"
             f"       --data-dir would open the same live database ({paths.db_path()}).\n"
             f"       Use --data-dir <folder> (or TNT_DATA_DIR) for a separate data set, or stop the service first.")
        return 2
    try:
        paths.ensure_dirs()
        logging_setup.setup_logging(console=True)
    except Exception as exc:  # noqa: BLE001
        _err(f"warning: logging setup failed: {exc}")
    stop = stop_event if stop_event is not None else threading.Event()
    _install_signal_handlers(stop)
    engine = Engine(console=True, port=port, data_dir=data_dir)
    rc = 0
    try:
        engine.start()
        if engine.api is not None and engine.api.running:
            _out(f"{APP_LONG_NAME} v{__version__} - console mode - serving {engine.api.url}  (Ctrl-C to stop)")
        else:
            _out(f"{APP_LONG_NAME} v{__version__} - console mode - API NOT listening: {engine.api_error}\n"
                 f"(retrying every 30 s; Ctrl-C to stop)")
        _out(f"data dir: {paths.data_dir()}   log: {engine.log_file}")
        if engine.errors:
            _out("degraded components: " + ", ".join(f"{k} ({v})" for k, v in sorted(engine.errors.items())))
        try:
            engine.run_forever(stop)
        except KeyboardInterrupt:
            pass
    except KeyboardInterrupt:
        pass
    except Exception as exc:  # noqa: BLE001
        log.exception("console run failed")
        _err(f"error: {exc}")
        rc = 1
    finally:
        _out("stopping...")
        try:
            engine.stop()
        except Exception as exc:  # noqa: BLE001
            log.exception("engine stop failed")
            _err(f"error while stopping: {exc}")
            rc = rc or 1
        _out("stopped")
    return rc


# ---------------------------------------------------------------------------
# frozen-build self check (run by installer/build.ps1 right after PyInstaller)
# ---------------------------------------------------------------------------
SELFCHECK_MODULES = (
    # stdlib C extensions whose DLLs a conda-based build can silently miss
    "ctypes", "sqlite3", "ssl", "hashlib", "zlib", "bz2", "lzma", "gzip", "xml.etree.ElementTree",
    "socket", "select", "json", "http.server", "mmap",
    # every module of the tnt package. A frozen build that cannot import one of these is broken in exactly the
    # way this check exists to catch, and the list is every module rather than a chosen few because the chosen few
    # drifted: tests/test_packaging.py fails when a new module is not here.
    "tnt.api", "tnt.api.routes", "tnt.api.server", "tnt.api.sse",
    "tnt.arp", "tnt.capture", "tnt.config", "tnt.db", "tnt.dhcp", "tnt.diagnostics", "tnt.discovery",
    "tnt.dissect", "tnt.etw", "tnt.events", "tnt.export_pdf", "tnt.firewall", "tnt.geohints",
    "tnt.geohints_data", "tnt.geoip", "tnt.icmp", "tnt.lanpeers", "tnt.linkmap", "tnt.lldp",
    "tnt.logging_setup", "tnt.faults", "tnt.mdns", "tnt.mmdb", "tnt.natcheck", "tnt.netinfo", "tnt.nettools",
    "tnt.networks", "tnt.netwatch", "tnt.outages",
    "tnt.oui", "tnt.paths", "tnt.pcapng", "tnt.peer", "tnt.pinger", "tnt.pktmon", "tnt.portcheck",
    "tnt.proav", "tnt.ptp", "tnt.report_pdf", "tnt.reports", "tnt.service", "tnt.sipalg", "tnt.sipcalls",
    "tnt.sipflow", "tnt.sipnat", "tnt.sipqual", "tnt.speedtest", "tnt.speedtest.base",
    "tnt.speedtest.cloudflare", "tnt.speedtest.fastcom", "tnt.speedtest.patterns", "tnt.speedtest.quality",
    "tnt.speedtest.scheduler", "tnt.switchport", "tnt.throughput", "tnt.tftp", "tnt.traceroute",
    "tnt.updater", "tnt.wifi",
    "tnt.winacl", "tnt.engine",
    # third-party packages the service depends on
    "netaddr", "reportlab", "psutil",
)


def _geoip_selfchecks() -> List[Tuple[str, bool, str]]:
    """IP location pieces a broken frozen bundle would break, checked without the network."""
    import gzip
    import shutil
    import ssl
    import tempfile
    import zlib

    out: List[Tuple[str, bool, str]] = []
    try:
        from tnt import geohints

        # an invented router name: no real carrier name sits in service code
        hint = geohints.location_hint("ae3.rtr1.dllstx01.example.net")
        out.append(("geohints data", hint is not None, str(hint.get("code")) if isinstance(hint, dict) else "no hint"))
    except Exception as exc:  # noqa: BLE001
        out.append(("geohints data", False, f"{type(exc).__name__}: {exc}"))
    try:
        from tnt import mmdb

        tmp = Path(tempfile.mkdtemp(prefix="tnt-selfcheck-"))
        try:
            path = tmp / "selfcheck.mmdb"
            path.write_bytes(mmdb.SELFCHECK_MMDB)
            reader = mmdb.Reader(path)
            try:
                ok = reader.get(mmdb.SELFCHECK_IP) == mmdb.SELFCHECK_RECORD
            finally:
                reader.close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        out.append(("MMDB reader (mmap)", ok, f"{len(mmdb.SELFCHECK_MMDB)} bytes"))
    except Exception as exc:  # noqa: BLE001
        out.append(("MMDB reader (mmap)", False, f"{type(exc).__name__}: {exc}"))
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        ok = d.decompress(gzip.compress(b"tnt" * 1000)) == b"tnt" * 1000 and d.eof
        out.append(("gzip stream", bool(ok), ""))
    except Exception as exc:  # noqa: BLE001
        out.append(("gzip stream", False, f"{type(exc).__name__}: {exc}"))
    try:
        n = int(ssl.create_default_context().cert_store_stats()["x509_ca"])
        out.append(("Windows certificate store", n > 0, f"{n} CA certificates"))
    except Exception as exc:  # noqa: BLE001
        out.append(("Windows certificate store", False, f"{type(exc).__name__}: {exc}"))
    return out


def selfcheck() -> int:
    """Import every module the service needs and exercise ICMP, SQLite and the OUI DB.

    Prints one line per check; exit code 0 only when everything passed. Meant for the
    frozen exe (``TNTService.exe --selfcheck``) so a broken bundle fails the build
    instead of an installed service.
    """
    import importlib
    import sqlite3
    import time as _time

    failures = 0

    def report(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        if not ok:
            failures += 1
        _out(f"{'ok  ' if ok else 'FAIL'} {name}{(' - ' + detail) if detail else ''}")

    for mod in SELFCHECK_MODULES:
        try:
            importlib.import_module(mod)
            report(f"import {mod}", True)
        except Exception as exc:  # noqa: BLE001
            report(f"import {mod}", False, f"{type(exc).__name__}: {exc}")
    try:
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE t(x)")
        con.execute("INSERT INTO t VALUES (1)")
        n = con.execute("SELECT COUNT(*) FROM t").fetchone()[0]
        con.close()
        report("sqlite3 in-memory database", n == 1, f"sqlite {sqlite3.sqlite_version}")
    except Exception as exc:  # noqa: BLE001
        report("sqlite3 in-memory database", False, f"{type(exc).__name__}: {exc}")
    try:
        from tnt.icmp import IcmpPinger

        p = IcmpPinger()
        r = p.ping("127.0.0.1", size=1200, timeout_ms=1000)
        p.close()
        report("ICMP echo 127.0.0.1 (1200 B)", bool(r.ok), f"rtt {r.rtt_ms} ms status {r.status}")
    except Exception as exc:  # noqa: BLE001
        report("ICMP echo 127.0.0.1 (1200 B)", False, f"{type(exc).__name__}: {exc}")
    try:
        from tnt.oui import vendor_for_mac

        v = vendor_for_mac("3C:22:FB:00:00:01")
        report("OUI vendor database", bool(v and "Apple" in v), str(v))
    except Exception as exc:  # noqa: BLE001
        report("OUI vendor database", False, f"{type(exc).__name__}: {exc}")
    try:
        from tnt import netinfo

        adapters = netinfo.get_adapters()
        report("GetAdaptersAddresses", isinstance(adapters, list), f"{len(adapters)} adapter(s)")
    except Exception as exc:  # noqa: BLE001
        report("GetAdaptersAddresses", False, f"{type(exc).__name__}: {exc}")
    try:
        ui = paths.ui_dir()
        ok = (ui / "index.html").is_file() and (ui / "css" / "tnt.css").is_file()
        report("bundled UI", ok, str(ui))
    except Exception as exc:  # noqa: BLE001
        report("bundled UI", False, f"{type(exc).__name__}: {exc}")
    try:
        from tnt.export_pdf import build_report
        from tnt.db import Database
        import tempfile
        import os as _os

        tmp = Path(tempfile.mkdtemp(prefix="tnt-selfcheck-"))
        db = Database(tmp / "t.db")
        pdf = build_report(db, _time.time() - 3600, _time.time())
        db.close()
        for f in tmp.glob("*"):
            try:
                _os.remove(f)
            except OSError:
                pass
        report("PDF report generation", pdf[:4] == b"%PDF", f"{len(pdf)} bytes")
    except Exception as exc:  # noqa: BLE001
        report("PDF report generation", False, f"{type(exc).__name__}: {exc}")
    for name, ok, detail in _geoip_selfchecks():
        report(name, ok, detail)
    _out(f"selfcheck: {'PASSED' if failures == 0 else f'{failures} FAILURE(S)'} (frozen={paths.is_frozen()}, exe={sys.executable})")
    return 0 if failures == 0 else 1


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command-line entry point; returns the process exit code."""
    args = list(sys.argv[1:] if argv is None else argv)
    frozen = paths.is_frozen()
    if not args:
        return run_dispatcher() if frozen else handle_command_line([])
    cmd = args[0].strip().lower()
    if cmd in ("--version", "-v", "version"):
        _out(f"{APP_LONG_NAME} {__version__}")
        return 0
    if cmd in ("-h", "--help", "help", "/?"):
        _out(usage())
        return 0
    if cmd == "--selfcheck":
        return selfcheck()
    if cmd == "--console":
        try:
            opts = parse_console_args(args[1:])
        except ValueError as exc:
            _err(f"error: {exc}\n")
            _err(usage())
            return 2
        return run_console(port=opts["port"], data_dir=opts["data_dir"])
    if cmd in SC_COMMANDS:
        if frozen:
            return SC_HANDLERS[cmd]()
        if cmd == "status":
            return sc_status()
        return handle_command_line(args)
    if not frozen:
        return handle_command_line(args)
    _err(f"error: unknown command {args[0]!r}\n")
    _err(usage())
    return 2


__all__ = [
    "CONSOLE_DEFAULT_PORT",
    "HAVE_PYWIN32",
    "SC_FAILURE_ACTIONS",
    "TNTService",
    "handle_command_line",
    "main",
    "parse_console_args",
    "run_console",
    "run_dispatcher",
    "sc_install",
    "sc_remove",
    "sc_restart",
    "sc_start",
    "sc_state",
    "sc_status",
    "sc_stop",
    "service_exe_path",
    "usage",
]
