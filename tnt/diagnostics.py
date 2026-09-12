"""Diagnostics snapshot for the Diagnostics panel.

:func:`collect` builds one JSON-able dict from the live :class:`tnt.engine.Engine`
(or any object exposing the same attributes, e.g. the test fake).  Every top-level
key is produced by its own collector wrapped in ``try/except`` so a failure in one
area yields ``{"error": "..."}`` for that key only and never hides the rest.

:func:`tail_log` returns the last *lines* of the rotating service log for
``GET /api/diagnostics/log``.

Contract notes / small gaps resolved here:

* ``ping.targets[].thread_alive`` - the PingManager contract has no thread
  introspection.  The value is taken from the live view when it carries a
  ``thread_alive`` key, else from ``PingManager.worker_alive(id)`` when such a
  method exists, else guessed from the names of live threads (``...-<id>`` or the
  host in the name); ``None`` means unknown.
* ``logs.ping_log_files`` is the number of files in ``logs/pings``.
* ``cpu_pct`` is the process CPU percentage since the previous call (psutil
  semantics); the first call after import measures since import time.
* ``network`` - ``engine.netwatch.state()`` (generation, changed_ts, default
  gateway, internet NIC, summary, poll interval, poll/failure counters) plus
  ``last_change`` (the last ``net.changed`` payload) and ``available``;
  ``{"available": false}`` without a watcher.
* ``geoip`` - ``{"available", "status", "files"}`` (``tnt.geoip.DIAG_KEYS``): the IP location manager's
  ``status()`` and ``files()``; ``{"available": false, "status": null, "files": []}`` without one.
"""
from __future__ import annotations

import ctypes
import logging
import os
import platform
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import SERVICE_NAME, __version__, logging_setup, paths

log = logging.getLogger(__name__)

LOG_FILE_NAME = "tnt-service.log"
MAX_TAIL_LINES = 5000
MAX_TAIL_BYTES = 4 * 1024 * 1024
ERROR_LEVELS = ("ERROR", "CRITICAL")

try:  # psutil is a declared dependency but diagnostics must degrade without it
    import psutil  # type: ignore

    _PROC: Any = psutil.Process()
    try:
        _PROC.cpu_percent(None)  # prime the per-process counter
    except Exception:  # noqa: BLE001
        pass
except Exception:  # noqa: BLE001
    psutil = None  # type: ignore[assignment]
    _PROC = None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _safe(fn: Callable[[], Any]) -> Any:
    """Run *fn*; on any exception return ``{"error": "..."}`` instead of raising."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        log.debug("diagnostics collector %s failed", getattr(fn, "__name__", fn), exc_info=True)
        return {"error": f"{type(exc).__name__}: {exc}"}


def _float(value: Any) -> Optional[float]:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _is_admin() -> Optional[bool]:
    if sys.platform != "win32":
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return None
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return None


def _windows_version() -> Dict[str, Any]:
    """Product name / display version / build from the registry (Windows only)."""
    info: Dict[str, Any] = {}
    if sys.platform != "win32":
        return info
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            for name, out in (("ProductName", "product"), ("DisplayVersion", "display_version"),
                              ("CurrentBuild", "build"), ("UBR", "ubr"), ("EditionID", "edition")):
                try:
                    info[out] = winreg.QueryValueEx(key, name)[0]
                except OSError:
                    pass
    except Exception:  # noqa: BLE001
        log.debug("registry version lookup failed", exc_info=True)
    try:
        build = int(info.get("build") or 0)
    except (TypeError, ValueError):
        build = 0
    product = str(info.get("product") or "")
    if build >= 22000 and product.startswith("Windows 10"):
        # The registry still says "Windows 10" on Windows 11; fix the caption.
        product = "Windows 11" + product[len("Windows 10"):]
    if product:
        info["product"] = product
    return info


def _thread_alive(pm: Any, view: Dict[str, Any]) -> Optional[bool]:
    if "thread_alive" in view:
        return bool(view["thread_alive"]) if view["thread_alive"] is not None else None
    tid = view.get("id")
    fn = getattr(pm, "worker_alive", None)
    if callable(fn) and tid is not None:
        try:
            return bool(fn(tid))
        except Exception:  # noqa: BLE001
            return None
    host = str(view.get("host") or "")
    ping_threads = [t for t in threading.enumerate() if "ping" in t.name.lower()]
    if not ping_threads:
        return None
    for t in ping_threads:
        if (tid is not None and t.name.endswith(f"-{tid}")) or (host and host in t.name):
            return bool(t.is_alive())
    return False


# ---------------------------------------------------------------------------
# collectors
# ---------------------------------------------------------------------------
def _service(engine: Any) -> Dict[str, Any]:
    now = time.time()
    started = _float(getattr(engine, "started_ts", None))
    config = getattr(engine, "config", None)
    cfg_path = getattr(config, "path", None) if config is not None else None
    log_file = getattr(engine, "log_file", None) or (paths.logs_dir() / LOG_FILE_NAME)
    return {
        "name": SERVICE_NAME,
        "version": getattr(engine, "version", None) or __version__,
        "mode": "console" if getattr(engine, "console", False) else "service",
        "pid": os.getpid(),
        "started_ts": started,
        "uptime_s": round(now - started, 1) if started else None,
        "python": platform.python_version(),
        "frozen": paths.is_frozen(),
        "exe": sys.executable,
        "argv": list(sys.argv),
        "data_dir": str(paths.data_dir()),
        "config_path": str(cfg_path or paths.config_path()),
        "log_file": str(log_file),
        "component_errors": dict(getattr(engine, "errors", {}) or {}),
    }


def _os() -> Dict[str, Any]:
    win = _windows_version()
    build = win.get("build")
    caption = win.get("product") or f"{platform.system()} {platform.release()}"
    if win.get("display_version"):
        caption += f" {win['display_version']}"
    version = platform.version()
    if build and win.get("ubr") is not None:
        version = f"{version} (build {build}.{win['ubr']})"
    user: Optional[str] = os.environ.get("USERNAME") or os.environ.get("USER")
    if not user:
        try:
            import getpass

            user = getpass.getuser()
        except Exception:  # noqa: BLE001
            user = None
    return {
        "caption": caption,
        "version": version,
        "build": str(build) if build else platform.release(),
        "edition": win.get("edition"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "hostname": socket.gethostname(),
        "user": user,
        "is_admin": _is_admin(),
    }


def _api(engine: Any) -> Dict[str, Any]:
    api = getattr(engine, "api", None)
    config = getattr(engine, "config", None)
    if api is None:
        return {
            "running": False,
            "host": config.get("api.host") if config is not None else None,
            "port": config.get("api.port") if config is not None else None,
            "clients_sse": 0,
            "last_error": getattr(engine, "api_error", None),
        }
    return {
        "running": bool(getattr(api, "running", False)),
        "host": getattr(api, "host", None),
        "port": getattr(api, "port", None),
        "url": getattr(api, "url", None),
        "started_ts": getattr(api, "started_ts", None),
        "clients_sse": int(getattr(api, "clients_sse", 0) or 0),
        "last_error": getattr(api, "last_error", None) or getattr(engine, "api_error", None),
    }


def _db(engine: Any) -> Dict[str, Any]:
    db = getattr(engine, "db", None)
    if db is None:
        return {"available": False, "path": str(paths.db_path()), "size_bytes": None, "counts": {}}
    return {
        "available": True,
        "path": str(getattr(db, "path", paths.db_path())),
        "size_bytes": int(db.size_bytes()),
        "counts": db.counts(),
        "last_heartbeat": _float(db.get_meta("last_heartbeat")),
        "schema_version": db.get_meta("schema_version"),
    }


def _logs(engine: Any) -> Dict[str, Any]:
    root = paths.logs_dir()
    total = 0
    files: List[Dict[str, Any]] = []
    if root.is_dir():
        for p in root.rglob("*"):
            if p.is_file():
                try:
                    size = p.stat().st_size
                except OSError:
                    continue
                total += size
                if p.parent == root:
                    files.append({"name": p.name, "bytes": size})
    ping_dir = paths.ping_logs_dir()
    ping_files = [p for p in ping_dir.iterdir() if p.is_file()] if ping_dir.is_dir() else []
    ping_bytes = 0
    for p in ping_files:
        try:
            ping_bytes += p.stat().st_size
        except OSError:
            pass
    log_file = getattr(engine, "log_file", None) or (root / LOG_FILE_NAME)
    return {
        "dir": str(root),
        "file": str(log_file),
        "total_bytes": total,
        "files": sorted(files, key=lambda f: f["name"]),
        "ping_log_dir": str(ping_dir),
        "ping_log_files": len(ping_files),
        "ping_log_bytes": ping_bytes,
    }


def _ping(engine: Any) -> Dict[str, Any]:
    pm = getattr(engine, "ping", None)
    if pm is None:
        return {"available": False, "paused": None, "targets": []}
    out: List[Dict[str, Any]] = []
    for v in pm.targets():
        last = v.get("last") or {}
        out.append({
            "id": v.get("id"),
            "host": v.get("host"),
            "ip": v.get("ip"),
            "kind": v.get("kind"),
            "enabled": v.get("enabled"),
            "resolved": v.get("resolved"),
            "resolve_error": v.get("resolve_error"),
            "thread_alive": _thread_alive(pm, v),
            "last_ts": last.get("ts") if isinstance(last, dict) else None,
            "last_ok": last.get("ok") if isinstance(last, dict) else None,
            "light": v.get("light"),
            "in_outage": v.get("in_outage"),
            "consecutive_missed": v.get("consecutive_missed"),
        })
    return {"available": True, "paused": bool(getattr(pm, "paused", False)), "targets": out}


def _outages(engine: Any) -> Dict[str, Any]:
    tracker = getattr(engine, "outages", None)
    if tracker is None:
        return {"available": False, "open": [], "count_24h": None}
    st = tracker.status()
    return {
        "available": True,
        "open": st.get("active", []),
        "total_active": st.get("total_active"),
        "count_24h": st.get("count_24h"),
        "last": st.get("last"),
        "monitoring": st.get("monitoring"),
    }


def _speedtest(engine: Any) -> Dict[str, Any]:
    sched = getattr(engine, "speed", None)
    config = getattr(engine, "config", None)
    out: Dict[str, Any] = {"available": sched is not None}
    try:
        from .speedtest import available_backends  # lazy: the module may be missing/broken

        out["backends"] = available_backends(config)
    except Exception as exc:  # noqa: BLE001
        out["backends"] = {"error": f"{type(exc).__name__}: {exc}"}
    if sched is None:
        out.update({"selected": None, "running": False, "next_run_ts": None, "last": None})
        return out
    st = sched.status()
    out.update({
        "selected": st.get("backend"),
        "enabled": st.get("enabled"),
        "interval_min": st.get("interval_min"),
        "running": bool(st.get("running")),
        "next_run_ts": st.get("next_run_ts"),
        "progress": st.get("progress"),
        "last": st.get("last"),
    })
    return out


def _discovery(engine: Any) -> Dict[str, Any]:
    scanner = getattr(engine, "discovery", None)
    out: Dict[str, Any] = {"available": scanner is not None, "running": False, "last_run_ts": None}
    if scanner is not None:
        out["running"] = bool(getattr(scanner, "running", False))
        out["last_run_ts"] = getattr(scanner, "last_run_ts", None)
    status_fn = getattr(engine, "discovery_status", None)
    if callable(status_fn):
        try:
            st = status_fn() or {}
            out["running"] = bool(st.get("running", out["running"]))
            out["progress"] = st.get("progress")
            last = st.get("last_run") or {}
            if isinstance(last, dict) and last.get("ts") is not None:
                out["last_run_ts"] = last.get("ts")
                out["last_run"] = last
        except Exception as exc:  # noqa: BLE001
            out["status_error"] = str(exc)
    return out


def _threads() -> List[Dict[str, Any]]:
    rows = []
    for t in threading.enumerate():
        rows.append({
            "name": t.name,
            "alive": t.is_alive(),
            "daemon": t.daemon,
            "ident": t.ident,
            "native_id": getattr(t, "native_id", None),
        })
    rows.sort(key=lambda r: r["name"])
    return rows


def _memory_mb() -> float:
    if _PROC is None:
        raise RuntimeError("psutil is not available")
    return round(_PROC.memory_info().rss / (1024.0 * 1024.0), 1)


def _cpu_pct() -> float:
    if _PROC is None:
        raise RuntimeError("psutil is not available")
    return float(_PROC.cpu_percent(None))


def _network(engine: Any) -> Dict[str, Any]:
    """The network watcher's state plus the last ``net.changed`` it published."""
    watch = getattr(engine, "netwatch", None)
    if watch is None:
        return {"available": False}
    out = dict(watch.state())
    out["available"] = True
    last = getattr(watch, "last_event", None)
    out["last_change"] = last() if callable(last) else None
    return out


def _geoip(engine: Any) -> Dict[str, Any]:
    comp = getattr(engine, "geoip", None)
    if comp is None:
        return {"available": False, "status": None, "files": []}
    return {"available": True, "status": comp.status(), "files": comp.files()}


def _recent_events(engine: Any) -> List[Dict[str, Any]]:
    db = getattr(engine, "db", None)
    if db is None:
        return []
    return db.list_events(50)


def _errors_24h() -> int:
    cutoff = time.time() - 86400
    return sum(1 for r in logging_setup.recent_records(600, "ERROR")
               if str(r.get("level")) in ERROR_LEVELS and float(r.get("ts") or 0) >= cutoff)


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def collect(engine: Any) -> Dict[str, Any]:
    """Full diagnostics snapshot. Never raises; failed sections carry ``{"error": ...}``."""
    return {
        "ts": time.time(),
        "service": _safe(lambda: _service(engine)),
        "os": _safe(_os),
        "api": _safe(lambda: _api(engine)),
        "db": _safe(lambda: _db(engine)),
        "logs": _safe(lambda: _logs(engine)),
        "ping": _safe(lambda: _ping(engine)),
        "outages": _safe(lambda: _outages(engine)),
        "speedtest": _safe(lambda: _speedtest(engine)),
        "discovery": _safe(lambda: _discovery(engine)),
        "network": _safe(lambda: _network(engine)),
        "geoip": _safe(lambda: _geoip(engine)),
        "threads": _safe(_threads),
        "memory_mb": _safe(_memory_mb),
        "cpu_pct": _safe(_cpu_pct),
        "recent_log": _safe(lambda: logging_setup.recent_records(100)),
        "recent_events": _safe(lambda: _recent_events(engine)),
        "errors_24h": _safe(_errors_24h),
    }


def _read_tail(path: Path, lines: int, max_bytes: int = MAX_TAIL_BYTES) -> List[str]:
    """Last *lines* lines of *path* reading only the tail of the file."""
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        chunk = 64 * 1024
        pos = size
        data = b""
        while pos > 0 and data.count(b"\n") <= lines and len(data) < max_bytes:
            step = min(chunk, pos)
            pos -= step
            fh.seek(pos)
            data = fh.read(step) + data
            chunk = min(chunk * 2, 1024 * 1024)
    text = data.decode("utf-8", errors="replace")
    out = text.splitlines()
    if pos > 0 and out:
        out = out[1:]  # first line is probably partial
    return out[-lines:]


def tail_log(lines: int = 200, path: Optional[Path] = None) -> Dict[str, Any]:
    """``{"file", "lines", "exists", "size_bytes"}`` for the service log tail."""
    try:
        lines = max(1, min(MAX_TAIL_LINES, int(lines)))
    except (TypeError, ValueError):
        lines = 200
    p = Path(path) if path else paths.logs_dir() / LOG_FILE_NAME
    out: Dict[str, Any] = {"file": str(p), "lines": [], "exists": p.is_file(), "size_bytes": 0}
    if not out["exists"]:
        return out
    try:
        out["size_bytes"] = p.stat().st_size
        out["lines"] = _read_tail(p, lines)
    except Exception as exc:  # noqa: BLE001
        log.debug("tail_log failed", exc_info=True)
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


__all__ = ["collect", "tail_log"]
