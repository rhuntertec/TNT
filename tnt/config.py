"""Settings: defaults, validation, persistence and change notification.

The config file is ``%ProgramData%\\TNT\\config.json``. Unknown keys are kept
(forward compatibility) but every known key is clamped to a sane range so a
hand-edited file can never crash the service. Settings a release removed
(``_RETIRED_KEYS``) are the exception: they are dropped, never stored.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

from . import DEFAULT_PORT
from . import paths

log = logging.getLogger(__name__)

#: 5060 (SIP) is in here so Discovery can categorise desk phones; 554 = RTSP cameras,
#: 7001 = Digital Watchdog Spectrum media servers, 22 + a Ubiquiti MAC = Ubiquiti gear.
DEFAULT_PORTS: List[int] = [22, 80, 443, 554, 5060, 7001, 8000, 8080, 8443]
DEFAULT_EXTRA_TARGETS: List[str] = ["1.1.1.1", "totalelectronics.com"]
#: Earlier default port lists. A saved config that still holds one of these verbatim was never
#: edited by the user, so it is upgraded to DEFAULT_PORTS on load (that is how 22, and later
#: 5060, reach machines whose config.json predates them). Any other list is the user's and is
#: left alone.
_LEGACY_PORT_LISTS: List[List[int]] = [
    [80, 443, 554, 7001, 8000, 8080, 8443],
    [22, 80, 443, 554, 7001, 8000, 8080, 8443],
]
#: Settings removed in 1.7.0 together with the external speed-test and scanner programs they
#: configured. A config.json saved by 1.6.x still carries them; they are dropped wherever a
#: config comes from (the file on load, PUT /api/settings from an older client) so they are
#: never written back. Every other key of such a file is kept.
_RETIRED_KEYS: List[str] = [
    "speedtest.ookla_path",
    "speedtest.ookla_server_id",
    "discovery.use_nmap",
    "discovery.nmap_path",
]
#: Values of a kept setting that no longer exist, and what they become.
_RETIRED_VALUES: Dict[str, Dict[str, Any]] = {
    "speedtest.backend": {"ookla": "auto"},   # "auto" now chooses among the built-in backends
}


def _drop_retired(data: Dict[str, Any]) -> List[str]:
    """Remove retired settings from *data* in place; returns the dotted keys it touched."""
    touched: List[str] = []
    for dotted in _RETIRED_KEYS:
        section_path, _, leaf = dotted.rpartition(".")
        section = _get_path(data, section_path)
        if isinstance(section, dict) and leaf in section:
            del section[leaf]
            touched.append(dotted)
    for dotted, replacements in _RETIRED_VALUES.items():
        value = _get_path(data, dotted)
        if isinstance(value, str) and value in replacements:
            _set_path(data, dotted, replacements[value])
            touched.append(dotted)
    return touched


def _migrate_legacy(data: Dict[str, Any]) -> bool:
    """Upgrade values that only differ from today's defaults because they were saved earlier."""
    changed = False
    ports = _get_path(data, "discovery.ports")
    if isinstance(ports, list) and ports != list(DEFAULT_PORTS) and ports in _LEGACY_PORT_LISTS:
        _set_path(data, "discovery.ports", list(DEFAULT_PORTS))
        log.info("config migration: discovery.ports upgraded to the current defaults (%s)", DEFAULT_PORTS)
        changed = True
    return changed

DEFAULTS: Dict[str, Any] = {
    "api": {"host": "127.0.0.1", "port": DEFAULT_PORT},
    "ping": {
        "interval_s": 1.0,          # seconds between pings per target
        "timeout_ms": 1000,         # reply timeout; a miss is recorded after this
        "loaded": True,             # loaded (1200 B) vs unloaded (32 B) payload
        "loaded_bytes": 1200,
        "unloaded_bytes": 32,
        "ttl": 128,
        "resolve_interval_s": 300,  # re-resolve hostnames this often
    },
    "outage": {"miss_threshold": 3, "recover_threshold": 3},
    "thresholds": {                 # traffic-light rules, evaluated over window_s
        "window_s": 60,
        "local_warn_ms": 30,
        "internet_warn_ms": 150,
        "warn_loss_pct": 2.0,
        "bad_loss_pct": 15.0,
    },
    "speedtest": {
        "enabled": True,
        "interval_min": 15,
        "backend": "auto",          # auto | cloudflare | fastcom
        "download_mb": 50,          # byte budget per run
        "upload_mb": 20,
        "duration_s": 8,            # time budget per direction
        "connections": 4,
        "timeout_s": 120,
        "warn_below_pct": 50,       # flag results below this % of the 7-day median
    },
    "discovery": {
        "ports": list(DEFAULT_PORTS),
        "ping_timeout_ms": 500,
        "ping_attempts": 2,
        "port_timeout_ms": 750,
        "concurrency": 128,
        "resolve_hostnames": True,
        "max_hosts": 4096,
    },
    "retention": {"days": 365},
    "network": {"poll_s": 5},       # tnt.netwatch: read the adapters' IP configuration this often
    "map": {"internet_host": "totalelectronics.com"},   # second hop of the live link map (Network info)
    "ui": {"theme": "light", "show_ipv6": False},   # Network info hides IPv6 addresses unless asked
    "lan": {"enabled": True},       # Tools > LAN throughput: beacon on UDP 7132, throughput server on TCP 7133
    "geoip": {"enabled": True},     # IP location + ISP (Network info, Traceroute) from DB-IP Lite: the service downloads ~65 MB a month
    "targets": {"defaults_extra": list(DEFAULT_EXTRA_TARGETS)},
    "dhcp": {                       # Tools > DHCP server (the on/off state is NOT persisted: off after every start)
        "adapter": "",              # adapter name to serve on; "" = auto (first physical Ethernet, else the internet NIC)
        "pool_start": "",           # "" = automatic: pool_size addresses right after the server's own IP
        "pool_end": "",
        "pool_size": 5,
        "lease_s": 3600,
        "static_ip": "172.16.4.100",    # address given to a DHCP-enabled adapter while the server runs
        "static_prefix": 24,
        "ping_check": True,         # ping a candidate address before offering it
        "scan_wait_s": 8,           # how long the "other DHCP server" probe waits for offers
    },
}

# (path, min, max) clamps for numeric settings
_CLAMPS = {
    "api.port": (1024, 65535),
    "ping.interval_s": (0.5, 60.0),
    "ping.timeout_ms": (100, 10000),
    "ping.loaded_bytes": (0, 65500),
    "ping.unloaded_bytes": (0, 65500),
    "ping.ttl": (1, 255),
    "ping.resolve_interval_s": (30, 86400),
    "outage.miss_threshold": (1, 100),
    "outage.recover_threshold": (1, 100),
    "thresholds.window_s": (10, 3600),
    "thresholds.local_warn_ms": (1, 10000),
    "thresholds.internet_warn_ms": (1, 10000),
    "thresholds.warn_loss_pct": (0.0, 100.0),
    "thresholds.bad_loss_pct": (0.0, 100.0),
    "speedtest.interval_min": (1, 1440),
    "speedtest.download_mb": (1, 2000),
    "speedtest.upload_mb": (1, 2000),
    "speedtest.duration_s": (2, 60),
    "speedtest.connections": (1, 16),
    "speedtest.timeout_s": (10, 600),
    "speedtest.warn_below_pct": (1, 100),
    "discovery.ping_timeout_ms": (50, 10000),
    "discovery.ping_attempts": (1, 5),
    "discovery.port_timeout_ms": (50, 10000),
    "discovery.concurrency": (1, 512),
    "discovery.max_hosts": (1, 65536),
    "retention.days": (7, 3650),
    "network.poll_s": (2, 60),
    "dhcp.pool_size": (1, 250),
    "dhcp.lease_s": (120, 604800),
    "dhcp.static_prefix": (8, 30),
    "dhcp.scan_wait_s": (2, 30),
}
_ENUMS = {
    "speedtest.backend": {"auto", "cloudflare", "fastcom"},
    "ui.theme": {"light", "dark"},
}

Listener = Callable[[Dict[str, Any], Set[str]], None]


def _deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _get_path(d: Dict[str, Any], dotted: str, default: Any = None) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _set_path(d: Dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = d
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def _changed_keys(old: Dict[str, Any], new: Dict[str, Any], prefix: str = "") -> Set[str]:
    keys: Set[str] = set()
    for k in set(old) | set(new):
        p = f"{prefix}{k}"
        a, b = old.get(k), new.get(k)
        if isinstance(a, dict) and isinstance(b, dict):
            keys |= _changed_keys(a, b, p + ".")
        elif a != b:
            keys.add(p)
    return keys


def _is_loopback_host(host: Any) -> bool:
    text = str(host or "").strip().strip("[]").lower()
    if text in ("localhost", ""):
        return text == "localhost"
    try:
        import ipaddress

        return ipaddress.ip_address(text.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _ipv4_text(value: Any) -> str:
    """*value* as a dotted IPv4 string, or ``""`` when it is not one (blank, None, garbage, IPv6)."""
    text = str(value).strip() if value is not None else ""
    if not text:
        return ""
    try:
        import ipaddress

        return str(ipaddress.IPv4Address(text))
    except (ValueError, TypeError):
        return ""


def validate(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return a cleaned copy of *cfg*: defaults filled in, numbers clamped, enums checked,
    retired settings dropped."""
    out = _deep_merge(DEFAULTS, cfg if isinstance(cfg, dict) else {})
    # a hand-edited section that is not an object ("speedtest": null) would break every rule below
    # and with it the whole file; only that section falls back to its defaults
    for name, section in DEFAULTS.items():
        if isinstance(section, dict) and not isinstance(out.get(name), dict):
            log.warning("config section %r is not an object (%s); using its defaults", name, type(out.get(name)).__name__)
            out[name] = copy.deepcopy(section)
    _drop_retired(out)
    for dotted, (lo, hi) in _CLAMPS.items():
        v = _get_path(out, dotted)
        dflt = _get_path(DEFAULTS, dotted)
        try:
            if isinstance(v, bool):
                raise TypeError("bool is not a number")
            f = float(v)
            if f != f or f in (float("inf"), float("-inf")):
                raise ValueError("non-finite")
            num = f if isinstance(dflt, float) else int(f)
        except (TypeError, ValueError, OverflowError):
            num = dflt
        num = max(lo, min(hi, num))
        _set_path(out, dotted, num)
    for dotted, allowed in _ENUMS.items():
        v = _get_path(out, dotted)
        if v not in allowed:
            _set_path(out, dotted, _get_path(DEFAULTS, dotted))
    # booleans
    for dotted in ("ping.loaded", "speedtest.enabled", "discovery.resolve_hostnames", "dhcp.ping_check", "ui.show_ipv6", "lan.enabled",
                   "geoip.enabled"):
        _set_path(out, dotted, bool(_get_path(out, dotted)))
    # ports list
    ports = _get_path(out, "discovery.ports")
    clean_ports: List[int] = []
    if isinstance(ports, (list, tuple)):
        for p in ports:
            try:
                if isinstance(p, bool):
                    continue
                pf = float(p)
                if pf != pf or pf in (float("inf"), float("-inf")):
                    continue
                pi = int(pf)
            except (TypeError, ValueError, OverflowError):
                continue
            if 1 <= pi <= 65535 and pi not in clean_ports:
                clean_ports.append(pi)
    _set_path(out, "discovery.ports", clean_ports or list(DEFAULT_PORTS))
    # strings
    for dotted in ("api.host", "map.internet_host", "dhcp.adapter", "dhcp.pool_start", "dhcp.pool_end",
                   "dhcp.static_ip"):
        v = _get_path(out, dotted)
        _set_path(out, dotted, str(v).strip() if v is not None else "")
    if not _get_path(out, "map.internet_host"):
        _set_path(out, "map.internet_host", DEFAULTS["map"]["internet_host"])
    # DHCP addresses: a pool bound that is not an IPv4 address means "automatic" (""); the
    # static fallback address always has to be one, so garbage goes back to the default
    for dotted in ("dhcp.pool_start", "dhcp.pool_end"):
        _set_path(out, dotted, _ipv4_text(_get_path(out, dotted)))
    static_ip = _ipv4_text(_get_path(out, "dhcp.static_ip"))
    if not static_ip:
        raw = _get_path(out, "dhcp.static_ip")
        if raw not in ("", None):
            log.warning("dhcp.static_ip %r is not an IPv4 address; using %s", raw, DEFAULTS["dhcp"]["static_ip"])
        static_ip = DEFAULTS["dhcp"]["static_ip"]
    _set_path(out, "dhcp.static_ip", static_ip)
    # The API is loopback-only by design: the service runs as LocalSystem and the API can
    # change settings and start scans, so it must never be reachable from the LAN.
    if not _is_loopback_host(_get_path(out, "api.host")):
        log.warning("api.host %r is not a loopback address; using %s", _get_path(out, "api.host"), DEFAULTS["api"]["host"])
        _set_path(out, "api.host", DEFAULTS["api"]["host"])
    extra = _get_path(out, "targets.defaults_extra")
    if not isinstance(extra, list) or not all(isinstance(x, str) for x in extra):
        _set_path(out, "targets.defaults_extra", list(DEFAULT_EXTRA_TARGETS))
    return out


class Config:
    """Thread-safe settings holder backed by a JSON file."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else paths.config_path()
        self._lock = threading.RLock()
        self._data: Dict[str, Any] = validate({})
        self._listeners: List[Listener] = []

    # -- persistence -------------------------------------------------------
    def load(self) -> "Config":
        with self._lock:
            raw: Dict[str, Any] = {}
            if self.path.exists():
                try:
                    # utf-8-sig: a file saved "UTF-8 with BOM" (Notepad on older Windows 10,
                    # PowerShell 5.1's Set-Content/Out-File -Encoding utf8) is still valid
                    # JSON to a technician; reading it as plain utf-8 fails, which used to
                    # rename it to .corrupt and silently reset every setting to the defaults
                    raw = json.loads(self.path.read_text(encoding="utf-8-sig"))
                except Exception:  # noqa: BLE001
                    log.exception("config file %s is unreadable; using defaults", self.path)
                    try:
                        self.path.replace(self.path.with_suffix(".json.corrupt"))
                    except OSError:
                        pass
            # validate() would drop retired settings silently; looking at the file first says so
            # once in the log and rewrites config.json without them
            retired = _drop_retired(raw) if isinstance(raw, dict) else []
            if retired:
                log.info("config migration: removed settings dropped from %s (%s)", self.path.name, ", ".join(retired))
            self._data = validate(raw)
            migrated = _migrate_legacy(self._data) or bool(retired)
            self._apply_env_overrides()
            if not self.path.exists():
                self.save()
            elif migrated:
                # best effort: the migrated settings apply in memory either way, and a file that
                # cannot be rewritten (read-only config.json) is simply migrated again next start
                try:
                    self.save()
                except OSError as exc:
                    log.warning("config migration: could not rewrite %s (%s); the migrated settings apply until the next start",
                                self.path, exc)
        return self

    def _apply_env_overrides(self) -> None:
        """Environment overrides are applied in memory only and never written to config.json.

        ``TNT_PORT`` / ``TNT_HOST`` always apply. The generic ``PORT`` / ``HOST`` (port-policy
        convenience for dev runs) are ignored when running as the Windows service
        (``TNT_SERVICE_MODE=1``, set by ``tnt.service``) so a machine-wide ``PORT`` variable
        cannot re-point the installed service.
        """
        self._file_values: Dict[str, Any] = {}
        generic_ok = os.environ.get("TNT_SERVICE_MODE") != "1"
        port = os.environ.get("TNT_PORT") or (os.environ.get("PORT") if generic_ok else None)
        if port:
            try:
                self._file_values["api.port"] = self._data["api"]["port"]
                self._data["api"]["port"] = max(1024, min(65535, int(port)))
            except ValueError:
                self._file_values.pop("api.port", None)
                log.warning("ignoring invalid PORT env value %r", port)
        host = os.environ.get("TNT_HOST") or (os.environ.get("HOST") if generic_ok else None)
        if host:
            if _is_loopback_host(host):
                self._file_values["api.host"] = self._data["api"]["host"]
                self._data["api"]["host"] = host.strip()
            else:
                log.warning("ignoring HOST env value %r: the API only binds loopback addresses", host)

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data = copy.deepcopy(self._data)
            for dotted, original in getattr(self, "_file_values", {}).items():
                _set_path(data, dotted, original)  # keep env overrides out of the file
            tmp = self.path.with_suffix(".json.tmp")
            try:
                tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
                os.replace(tmp, self.path)
            except OSError:
                try:
                    tmp.unlink()        # never leave config.json.tmp behind
                except OSError:
                    pass
                raise

    # -- access ------------------------------------------------------------
    def get(self, dotted: str, default: Any = None) -> Any:
        with self._lock:
            return copy.deepcopy(_get_path(self._data, dotted, default))

    def section(self, name: str) -> Dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data.get(name, {}))

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data)

    def update(self, patch: Dict[str, Any], persist: bool = True) -> Set[str]:
        """Deep-merge *patch*, validate, save and notify listeners. Returns changed dotted keys."""
        if not isinstance(patch, dict):
            raise ValueError("settings patch must be an object")
        for name, value in patch.items():
            if isinstance(DEFAULTS.get(name), dict) and not isinstance(value, dict):
                raise ValueError(f"settings section {name!r} must be an object")
        with self._lock:
            old = self._data
            new = validate(_deep_merge(old, patch))
            changed = _changed_keys(old, new)
            self._data = new
            if persist and changed:
                self.save()
            listeners = list(self._listeners)
            snap = copy.deepcopy(new)
        if changed:
            for fn in listeners:
                try:
                    fn(snap, changed)
                except Exception:  # noqa: BLE001
                    log.exception("config listener failed")
        return changed

    def add_listener(self, fn: Listener) -> Callable[[], None]:
        with self._lock:
            self._listeners.append(fn)

        def remove() -> None:
            with self._lock:
                if fn in self._listeners:
                    self._listeners.remove(fn)

        return remove

    # -- convenience -------------------------------------------------------
    @property
    def ping_bytes(self) -> int:
        with self._lock:
            p = self._data["ping"]
            return int(p["loaded_bytes"] if p["loaded"] else p["unloaded_bytes"])


def any_changed(changed: Iterable[str], prefixes: Iterable[str]) -> bool:
    pre = tuple(prefixes)
    return any(k.startswith(pre) for k in changed)
