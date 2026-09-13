"""HTTP routing and the ``/api`` route table.

The :class:`Router` is a tiny method + path matcher supporting ``{name}`` path
parameters.  :func:`build_routes` registers every contract route against an
*engine* object.  Routes only ever touch the engine through this surface (the
real :class:`tnt.engine.Engine` implements it; tests use a fake):

``engine.version, started_ts, console, config, db, bus, pinger, ping, outages, speed,
discovery, dhcp, lan, api, overall_light(), discovery_start(range_text, ports) -> bool,
discovery_cancel() -> bool, discovery_status() -> dict, set_paused(bool) -> bool,
add_target(host, label) -> dict, remove_target(id) -> bool, netinfo_summary() -> dict``
and, optionally, ``netwatch`` (a ``tnt.netwatch.NetWatcher``: ``state() -> dict``) and
``reports`` (a ``tnt.reports.ReportManager``; missing or ``None`` makes every ``/api/reports``
route 503) and ``geoip`` (a ``tnt.geoip.GeoIpManager``: ``status() / lookup(ip) / check_now() /
locate_hop(...) / origin()``; missing or ``None`` makes every ``/api/geoip`` route 503) and ``update``
(a ``tnt.updater.UpdateManager``: ``status() / check_now() / request_install()``; missing or ``None`` makes
every ``/api/update`` route 503) and
``ip_release_renew() -> dict`` (missing makes ``POST /api/tools/ip/renew`` 503) and ``natcheck``, ``portcheck``,
``switchport``, ``capture`` and ``tftp`` (the network tools below; missing or ``None`` makes their routes 503).

Site reports (``/api/reports*``, ARCHITECTURE 3.19): the literal paths (``sites``, ``scan``,
``scan/wifi``, ``compare``, ``compare/pdf``) are registered before ``{id}`` and ``{id}/pdf``
because the router takes the first pattern that matches.  Report ids (path and ``?a=&b=``) must be
1-15 decimal digits (400 otherwise; ``query_int`` would clamp).  ``POST /api/reports/scan`` while a
scan runs is 409 ``{"error":{"code":"busy"},"job":...}``; ``PATCH /api/reports/scan`` renames the
report the last scan saved when it is no longer running (409 ``no_scan``/``not_running`` when there
is nothing to name); ``DELETE /api/reports/scan`` is idempotent (200 with the job as it is when it is
not running); ``POST /api/reports/scan/wifi`` is 409 ``not_waiting`` unless a scan waits for Wi-Fi
and may be 2 MB (``tnt.api.server.BODY_LIMITS``).  PDFs are built on request (``tnt.report_pdf``,
lazily imported: a broken import is a 503) and, unlike ``/api/export``, not copied to the exports
folder: the report itself is stored.  Their ``Content-Disposition`` file name is ASCII letters,
digits and ``-`` only (``tnt.reports.pdf_filename``).  ``GET /api/status`` carries ``"reports"``
(``ReportManager.status()``: counts, the newest report and the job) for the Reports tile.

The DHCP server tool (``engine.dhcp``, a ``tnt.dhcp.DhcpServer``) is driven through
``status() / summary() / leases() / scan(wait_s) / start(force) / stop() /
update_settings(patch) / forget_lease(mac)``.  ``start()`` raising a ``RuntimeError``
that carries a ``servers`` attribute (``tnt.dhcp.DhcpConflict``) is answered with HTTP
409 ``{"error":{"code":"dhcp_server_present"},"servers":[...],"scan":{...}}`` so the UI
can show the danger screen; the check is by attribute, not by class, so this module
imports even when ``tnt.dhcp`` is missing and tests can use a stand-in.

The Tools page routes: ``/api/tools/traceroute`` runs a :class:`tnt.traceroute.Tracer`
that is created lazily from ``engine.pinger`` + ``engine.bus`` on first use and kept as
``engine.tracer`` (the Engine has no slot for it; 503 without a pinger).
``/api/tools/lan/*`` drive ``engine.lan`` (a ``tnt.lanpeers.LanPeers``: ``peers_view() /
run_throughput(peer_ip, seconds) / last_throughput() / throughput_running``).  For both,
a ``ValueError`` is 400, a ``RuntimeError`` whose message says "already running" is 409
``conflict`` and any other ``RuntimeError`` 500 (``_tool_call``).
``GET /api/tools/wifi/profiles`` reads this PC's saved WLAN profiles through ``tnt.wifi``
(lazily imported, so a missing module is a 503).  ``reveal`` defaults to False (keys omitted,
open to any local caller); ``reveal=1`` returns the plaintext keys but only to a process running
under a Windows administrator account, elevated or not -- the owning process of the connection
is identified and its token checked (``tnt.peer``), and a standard or unverifiable caller gets
403 ``admin_required``.  A browser page of another origin is refused before that check (403
``forbidden``), so no web page can make an administrator's browser fetch the keys.  The keys
never leave this loopback API.
The quick tools (``tnt.nettools``, lazily imported, so a broken import is a 503): ``POST /api/tools/dns/lookup``
``{"name", "server"?, "type"?}`` is DNS_RESULT (``type`` null or empty is Auto; a bad name, server or record type, and an
IP address asked for any type but PTR, are 400 with the validator's text), ``POST
/api/tools/dns/flush`` is FLUSH_RESULT and ``POST /api/tools/ip/renew`` is RENEW_RESULT from
``engine.ip_release_renew()`` (503 when the engine has none, 409 while one runs).  All three refuse a browser page of
another origin first (403 ``forbidden``, :data:`QUICK_TOOLS_CROSS_ORIGIN_MSG`); the renew then needs a Windows
administrator, checked like the Wi-Fi keys (403 ``admin_required``, failing closed).
The network tools (ARCHITECTURE 3.23-3.25) drive ``engine.natcheck`` (``tnt.natcheck.NatChecker``: ``last() / running() /
run()``), ``engine.portcheck`` (``tnt.portcheck.PortChecker.test(port)``), ``engine.switchport``
(``tnt.switchport.SwitchPortFinder``: ``status() / start(adapter, seconds) / stop()``), ``engine.capture``
(``tnt.capture.CaptureManager``: ``status() / start(**body) / stop() / open_file(name) / delete_file(name)``) and
``engine.tftp`` (``tnt.tftp.TftpServer``: ``status() / summary() / start(adapter, uploads) / stop() / set_uploads(on) /
update_settings(patch) / files()``).  ``GET /api/netcheck/nat`` is ``{"result": NAT_RESULT|null, "running"}`` and ``POST``
(no body) runs a check, ``{"result", "running": false}``.  ``GET /api/netcheck/switch`` is SWITCH_STATUS, ``POST``
``{"adapter", "seconds"}`` starts listening and ``DELETE`` cancels (both ``{"job"}``).  ``POST /api/netcheck/portforward``
``{"port"}`` is PORTCHECK_RESULT.  ``GET /api/tools/capture`` is CAPTURE_STATUS, ``POST`` the start body (a key left out
takes the service default) and ``DELETE`` stops and keeps the capture (both ``{"capture": JOB}``); ``GET
/api/tools/capture/files/{name}`` is the file as a :class:`FileResponse` download and ``DELETE`` on it ``{"files"}``.
``GET /api/tftp/status``, ``POST /api/tftp/start`` ``{"adapter", "uploads"}``, ``/api/tftp/stop``, ``/api/tftp/uploads``
``{"on"}`` and ``PUT /api/tftp/settings`` ``{"adapter", "max_upload_mb"}`` answer the TFTP STATUS; ``GET /api/tftp/files`` is
``{"files": [...]}`` and ``GET /api/status`` carries ``"tftp"`` (``TftpServer.summary()``, null without the component).
Every POST/PUT/DELETE among them, and the capture download, refuses a browser page of another origin first (403
``forbidden``, :data:`QUICK_TOOLS_CROSS_ORIGIN_MSG`).  Every capture route then needs a Windows administrator, checked
like the Wi-Fi keys (403 ``admin_required``, :data:`CAPTURE_ADMIN_REQUIRED_MSG` / :data:`CAPTURE_ADMIN_UNVERIFIED_MSG`,
failing closed), before the 503 for a missing component; ``GET /api/events`` leaves out :data:`ADMIN_ONLY_EVENTS`
(``capture.state``, the capture job) for anyone else, with the same check asked once per stream.  The services' typed
errors are answered before
:func:`_tool_call` (:data:`TYPED_ERRORS`, :func:`_typed_call`): ``PktmonBusy`` 409 ``conflict``, ``PktmonUnavailable``
409 ``unavailable``, ``RateLimited`` 429 ``rate_limited`` with ``Retry-After``, ``NoPublicIp`` 409 ``no_public_ip``,
``VpnActive`` 409 ``vpn``, ``CaptureFileBusy`` 409 ``conflict``, ``CaptureFileMissing`` 404 ``not_found`` and
``TftpPortInUse`` 409 ``{"error": {"code": "tftp_port_in_use", "message"}, "owners": [{"pid", "name"}]}``; a busy text
("already running") stays 409 ``conflict``.
``GET /api/oui?prefix=AA:BB:CC&prefix=...`` (1-256 prefixes, repeated and/or comma separated;
``:``, ``-`` or no separator) names the vendors of 24-bit OUIs through ``tnt.oui.vendor_for_oui``
for the WiFi tile. The Wi-Fi survey itself runs in ``TNT.exe`` (Windows gives BSSID lists only to
a user with location access) and reaches the UI through the pywebview bridge, not this API; only
OUIs come here.  ``Request.query_all`` reads a repeated query parameter (``Request.query`` keeps
the last value).

A sub-component that failed to start is ``None`` on the engine; every route
that needs it answers ``503 {"error":{"code":"unavailable"}}``.  Modules that
are only needed on demand (``tnt.netinfo``, ``tnt.export_pdf``,
``tnt.diagnostics``) are imported lazily so an import failure degrades that
route to 503 instead of taking the server down.

Contract gaps resolved here (documented deviations):

* ``/api/status.monitoring`` is ``True`` when the ping manager is available,
  not paused and has at least one target.
* ``POST /api/export`` also accepts ``from``/``to`` as ``YYYY-MM-DD`` strings
  (local dates) in addition to epoch seconds, and ``GET /api/export?range=..``
  is accepted as well so the UI can use a plain download link.  A copy of every
  report is written to ``paths.exports_dir()`` (best effort) and its path is
  returned in the ``X-TNT-Export-Path`` header.
* ``PATCH /api/settings`` is an alias of ``PUT``.
* ``GET /api/discovery/runs/{id}`` and ``/api/discovery/last`` return hosts whose
  ``device_type`` is filled in even when the stored row predates that column
  (``tnt.discovery.fill_device_types``, best effort - see ``_categorised``).
* Networks (ARCHITECTURE 3.20): ``GET /api/networks/current`` is ``{"network": {"id","mac","vendor",
  "gateway_ip","subnet","dhcp_server","identity","virtual_mac","portable","first_seen","last_seen",
  "offline","last_report":{"id","site","created_ts"}|null}|null}`` from ``engine.networks`` (a
  ``tnt.networks.NetworkTracker``; ``null`` without one or while the network is unknown; ``last_report``
  the newest report under a site name) and ``status.net`` carries ``"network_id"``.  ``PATCH
  /api/networks/{id}`` ``{"portable": bool}`` marks a network carried from site to site (a hotspot) or not
  (``ReportManager.set_network_portable``): ``{"network": view}``, 400 for a bad id or body, 404 unknown,
  503 without the report manager or a tracker.
* ``GET /api/status`` carries ``"net": {"generation", "changed_ts", "default_gateway",
  "internet_nic", "summary", "networks", "network_id"}`` from ``engine.netwatch.state()`` (no native call):
  ``summary`` is the text of the last ``net.changed`` (what a page that missed the event shows),
  ``networks`` the IPv4 subnets of the up adapters.  ``GET /api/netinfo`` adds ``"generation"``
  and ``"changed_ts"`` to the snapshot.  Without a watcher (``engine.netwatch`` missing or
  ``None``) generation is 0, ``changed_ts`` and ``summary`` null, ``networks`` empty and the
  gateway / adapter name come from ``netinfo_summary()``.
* IP location (DB-IP Lite, ``engine.geoip``): ``GET /api/status`` carries ``"geoip"`` (STATUS from
  ``GeoIpManager.status()``, null without the component) and ``map.public_geo`` (GEO of ``map.public_ip.ip``
  or null, from the link map).  ``GET /api/geoip`` is STATUS; ``GET /api/geoip/lookup?ip=`` is
  ``{"ip", "result": GEO|null}`` (a local lookup; ``[brackets]`` and a ``%scope`` are accepted, 400 for anything
  that is not an IPv4/IPv6 address); ``POST /api/geoip/check`` (Retry now, no body) is STATUS, or 409 ``conflict``
  when the setting is off.  All three are 503 without the component.  The lazily built tracer gets the manager
  as its ``geo`` provider, so every traceroute HOP carries ``"location"`` (LOCATION or null).
"""
from __future__ import annotations

import importlib
import ipaddress
import json
import logging
import threading
import math
import re
import time
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl

log = logging.getLogger(__name__)

Handler = Callable[["Request"], Any]

# Epoch-second inputs (``from``/``to`` and export dates) must fall in this range:
# anything else is a typo or an overflow attempt (SQLite binds 64-bit ints, and
# ``time.localtime`` raises for out-of-range values on Windows).
EASTER_META_KEY = "easter_detonated"   # db meta key: sticks of TNT the easter egg has blown up
EASTER_MAX_STICKS = 100
MIN_EPOCH_S = 0.0
MAX_EPOCH_S = 4_102_444_800.0  # 2100-01-01T00:00:00Z

_STATUS_CODES = {
    400: "bad_request",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    429: "rate_limited",
    500: "internal_error",
    503: "unavailable",
}


class ApiError(Exception):
    """Raised by routes; rendered as ``{"error":{"code","message"}}`` with *status*."""

    def __init__(self, status: int, code: Optional[str] = None, message: str = "", headers: Optional[Dict[str, str]] = None) -> None:
        self.status = int(status)
        self.code = code or _STATUS_CODES.get(self.status, "error")
        self.message = message or self.code.replace("_", " ")
        self.headers = dict(headers or {})
        super().__init__(f"{self.status} {self.code}: {self.message}")

    def to_dict(self) -> Dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message}}


@dataclass
class Request:
    method: str
    path: str
    query: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    client: str = ""
    #: the accepted socket's two ends, ``(ip, port)`` each, or ``None`` when unknown: ``peer``
    #: is the client (remote) address as this server sees it, ``local`` the server socket's own
    #: address.  Used only to identify the calling process for the Wi-Fi key admin check.
    peer: Optional[Tuple[str, int]] = None
    local: Optional[Tuple[str, int]] = None
    #: the raw query string (``prefix=a&prefix=b``): ``query`` keeps only the last value of a
    #: repeated parameter, :meth:`query_all` reads every one
    raw_query: str = ""

    # -- body ----------------------------------------------------------------
    def json(self) -> Any:
        """Parsed JSON body (``{}`` when empty). 400 on malformed JSON."""
        if not self.body or not self.body.strip():
            return {}
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ApiError(400, "bad_request", f"invalid JSON body: {exc}") from exc
        except RecursionError:
            raise ApiError(400, "bad_request", "invalid JSON body: nesting too deep") from None

    def json_object(self) -> Dict[str, Any]:
        data = self.json()
        if not isinstance(data, dict):
            raise ApiError(400, "bad_request", "JSON body must be an object")
        return data

    # -- params / query ------------------------------------------------------
    def query_all(self, name: str) -> List[str]:
        """Every value of a (possibly repeated) query parameter, in order."""
        if self.raw_query:
            return [v for k, v in parse_qsl(self.raw_query, keep_blank_values=True) if k == name]
        return [self.query[name]] if name in self.query else []

    def int_param(self, name: str) -> int:
        raw = self.params.get(name, "")
        try:
            return int(raw)
        except (TypeError, ValueError):
            raise ApiError(400, "bad_request", f"{name} must be an integer, got {raw!r}") from None

    def query_int(self, name: str, default: int, lo: Optional[int] = None, hi: Optional[int] = None) -> int:
        raw = self.query.get(name)
        if raw is None or raw == "":
            return default
        try:
            val = int(float(raw))
        except (TypeError, ValueError, OverflowError):  # OverflowError: int(inf)
            raise ApiError(400, "bad_request", f"query parameter {name} must be a number, got {raw!r}") from None
        if lo is not None:
            val = max(lo, val)
        if hi is not None:
            val = min(hi, val)
        return val

    def query_float(self, name: str, default: Optional[float]) -> Optional[float]:
        """A finite float (``nan``/``inf`` are rejected: they poison comparisons and SQL)."""
        raw = self.query.get(name)
        if raw is None or raw == "":
            return default
        try:
            val = float(raw)
        except (TypeError, ValueError):
            raise ApiError(400, "bad_request", f"query parameter {name} must be a number, got {raw!r}") from None
        if not math.isfinite(val):
            raise ApiError(400, "bad_request", f"query parameter {name} must be a finite number, got {raw!r}")
        return val

    def time_range(self, default_span_s: float = 86400.0, now: Optional[float] = None) -> Tuple[float, float]:
        """``?from=&to=`` (epoch seconds) defaulting to the last *default_span_s*."""
        now = time.time() if now is None else now
        end = self.query_float("to", None)
        start = self.query_float("from", None)
        for label, val in (("to", end), ("from", start)):
            if val is not None and not MIN_EPOCH_S <= val <= MAX_EPOCH_S:
                raise ApiError(400, "bad_request", f"'{label}' must be epoch seconds between {int(MIN_EPOCH_S)} and {int(MAX_EPOCH_S)}")
        if end is None:
            end = now if start is None else start + default_span_s
        if start is None:
            start = end - default_span_s
        if start > end:
            raise ApiError(400, "bad_request", "'from' must not be after 'to'")
        return float(start), float(end)


@dataclass
class Response:
    """A fully-formed HTTP response (bytes) returned by a route."""

    status: int = 200
    body: bytes = b""
    content_type: str = "application/json; charset=utf-8"
    headers: Dict[str, str] = field(default_factory=dict)


class StreamResponse:
    """Marker returned by streaming routes; the handler runs ``serve(handler)``."""

    def __init__(self, serve: Callable[[Any], None]) -> None:
        self.serve = serve


class FileResponse:
    """A download returned by a route: ``tnt.api.server`` sends *size* bytes of the open binary *fileobj* as an attachment
    called *filename* and closes it on every path (a HEAD request, a client that went away, an error).  The name is kept
    to letters, digits, ``.``, ``_`` and ``-`` so it cannot break the ``Content-Disposition`` header."""

    def __init__(self, fileobj: Any, size: int, filename: str, content_type: str = "application/octet-stream") -> None:
        self.fileobj = fileobj
        self.size = max(0, int(size))
        self.filename = re.sub(r"[^A-Za-z0-9._-]", "_", str(filename or ""))[:200] or "download"
        self.content_type = content_type


def json_response(payload: Any, status: int = 200, headers: Optional[Dict[str, str]] = None) -> Response:
    body = json.dumps(payload, default=str).encode("utf-8")
    return Response(status=status, body=body, headers=dict(headers or {}))


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
_PARAM_RE = re.compile(r"\{(\w+)\}")


def _compile(pattern: str) -> "re.Pattern[str]":
    out: List[str] = []
    pos = 0
    for m in _PARAM_RE.finditer(pattern):
        out.append(re.escape(pattern[pos:m.start()]))
        out.append(f"(?P<{m.group(1)}>[^/]+)")
        pos = m.end()
    out.append(re.escape(pattern[pos:]))
    return re.compile("^" + "".join(out) + "$")


class Router:
    """Method + path matcher with ``{name}`` parameters and 404/405 semantics."""

    def __init__(self) -> None:
        self._routes: List[Tuple[str, "re.Pattern[str]", Dict[str, Handler]]] = []

    def add(self, method: str, pattern: str, handler: Handler) -> None:
        method = method.upper()
        for pat, _regex, methods in self._routes:
            if pat == pattern:
                methods[method] = handler
                return
        self._routes.append((pattern, _compile(pattern), {method: handler}))

    def route(self, method: str, pattern: str) -> Callable[[Handler], Handler]:
        def deco(fn: Handler) -> Handler:
            self.add(method, pattern, fn)
            return fn
        return deco

    def get(self, pattern: str) -> Callable[[Handler], Handler]:
        return self.route("GET", pattern)

    def post(self, pattern: str) -> Callable[[Handler], Handler]:
        return self.route("POST", pattern)

    def put(self, pattern: str) -> Callable[[Handler], Handler]:
        return self.route("PUT", pattern)

    def delete(self, pattern: str) -> Callable[[Handler], Handler]:
        return self.route("DELETE", pattern)

    def match(self, method: str, path: str) -> Tuple[Handler, Dict[str, str]]:
        """Return ``(handler, params)``; raise ApiError 404 or 405."""
        method = method.upper()
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/") or "/"
        allowed: set[str] = set()
        for _pat, regex, methods in self._routes:
            m = regex.match(path)
            if not m:
                continue
            if method in methods:
                return methods[method], {k: v for k, v in m.groupdict().items()}
            allowed |= set(methods)
        if allowed:
            allow = ", ".join(sorted(allowed))
            raise ApiError(405, "method_not_allowed", f"{method} is not allowed on {path} (allowed: {allow})", {"Allow": allow})
        raise ApiError(404, "not_found", f"no route for {method} {path}")

    def patterns(self) -> List[Tuple[str, List[str]]]:
        return [(pat, sorted(methods)) for pat, _r, methods in self._routes]


# ---------------------------------------------------------------------------
# helpers used by the route table
# ---------------------------------------------------------------------------
def _need(engine: Any, name: str, what: Optional[str] = None) -> Any:
    comp = getattr(engine, name, None)
    if comp is None:
        raise ApiError(503, "unavailable", f"{what or name} is not available (component failed to start; see the service log)")
    return comp


def _lazy(module: str, what: Optional[str] = None) -> ModuleType:
    try:
        return importlib.import_module(module)
    except Exception as exc:  # noqa: BLE001 - ImportError or a broken module
        log.error("lazy import of %s failed: %s", module, exc)
        raise ApiError(503, "unavailable", f"{what or module} is not available: {exc}") from exc


def _safe_call(what: str, fn: Callable[[], Any], default: Any = None) -> Any:
    """Call *fn*; on failure log and return *default* (for aggregate views such as /status)."""
    try:
        return fn()
    except Exception:  # noqa: BLE001
        log.exception("%s failed", what)
        return default


def _current_network_id(engine: Any) -> Optional[int]:
    """``engine.networks.current_network_id()``, or ``None`` without a tracker (or when it failed)."""
    fn = getattr(getattr(engine, "networks", None), "current_network_id", None)
    return _safe_call("networks.current_network_id()", fn, None) if callable(fn) else None


def _net_state(engine: Any) -> Optional[Dict[str, Any]]:
    """``engine.netwatch.state()``, or ``None`` without a watcher (or when it failed)."""
    watch = getattr(engine, "netwatch", None)
    if watch is None:
        return None
    state = _safe_call("netwatch.state()", watch.state, None)
    return state if isinstance(state, dict) else None


def _as_dict(obj: Any) -> Any:
    if obj is None or isinstance(obj, (dict, list, str, int, float, bool)):
        return obj
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    if hasattr(obj, "__dataclass_fields__"):
        return {k: getattr(obj, k) for k in obj.__dataclass_fields__}  # type: ignore[attr-defined]
    return obj


def _sample_pair(sample: Any) -> List[Any]:
    if isinstance(sample, dict):
        return [sample.get("ts"), sample.get("rtt_ms")]
    if isinstance(sample, (list, tuple)) and len(sample) >= 2:
        return [sample[0], sample[1]]
    return [getattr(sample, "ts", None), getattr(sample, "rtt_ms", None)]


def _parse_when(value: Any, end_of_day: bool = False) -> Optional[float]:
    """Epoch seconds from a number or a local ``YYYY-MM-DD`` string."""
    if value is None or value == "":
        return None
    bad = ApiError(400, "bad_request", f"invalid date {value!r}; use epoch seconds or YYYY-MM-DD")
    num: Optional[float] = None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        num = float(value)
    else:
        text = str(value).strip()
        try:
            num = float(text)
        except ValueError:
            try:
                st = time.strptime(text[:10], "%Y-%m-%d")
                base = time.mktime(st)  # OverflowError/OSError for dates outside the platform's range
            except (ValueError, OverflowError, OSError):
                raise bad from None
            num = base + 86399.0 if end_of_day else base
    if num is None or not math.isfinite(num) or not MIN_EPOCH_S <= num <= MAX_EPOCH_S:
        raise bad
    return num


def _clean_ports(ports: Any) -> Optional[List[int]]:
    if ports in (None, "", []):
        return None
    if isinstance(ports, str):
        ports = [p for p in re.split(r"[,\s]+", ports) if p]
    if not isinstance(ports, (list, tuple)):
        raise ApiError(400, "bad_request", "ports must be a list of integers")
    out: List[int] = []
    for p in ports:
        try:
            pi = int(p)
        except (TypeError, ValueError):
            raise ApiError(400, "bad_request", f"invalid port {p!r}") from None
        if not 1 <= pi <= 65535:
            raise ApiError(400, "bad_request", f"port {pi} out of range 1-65535")
        if pi not in out:
            out.append(pi)
    return out or None


def _categorised(run: Any) -> Any:
    """A stored discovery run with every host's ``device_type`` filled in.

    Runs saved before ``discovery_hosts.device_type`` existed carry NULLs; they are
    categorised here (``tnt.discovery.classify_device`` rules, current gateways) so old runs
    read like fresh ones. Best effort: a failure here never fails the request.
    """
    try:
        if isinstance(run, dict) and run.get("hosts"):
            importlib.import_module("tnt.discovery").fill_device_types(run["hosts"])
    except Exception:  # noqa: BLE001
        log.debug("device-type backfill failed", exc_info=True)
    return run


def _local_tz_offset_s() -> int:
    lt = time.localtime()
    return int(lt.tm_gmtoff) if hasattr(lt, "tm_gmtoff") else -int(time.timezone)


DHCP_CONFLICT_CODE = "dhcp_server_present"
DHCP_CONFLICT_MESSAGE = "Another DHCP server is active on this network"
DHCP_SETTINGS_KEYS = ("adapter", "pool_start", "pool_end", "pool_size", "lease_s", "ping_check")
LAN_SETTINGS_KEYS = ("enabled",)
#: ``POST /api/tools/capture``: the body keys handed to ``CaptureManager.start`` (a key left out takes its default).
CAPTURE_START_KEYS = ("adapter", "seconds", "size_mb", "full_packets", "host", "port", "protocol")


def _dhcp_conflict(exc: BaseException) -> Optional[Tuple[int, Dict[str, Any]]]:
    """``(409, payload)`` for a ``DhcpConflict``-shaped error (a RuntimeError with ``servers``)."""
    servers = getattr(exc, "servers", None)
    if not isinstance(exc, RuntimeError) or servers is None:
        return None
    scan = getattr(exc, "scan", None)
    return 409, {
        "error": {"code": DHCP_CONFLICT_CODE, "message": DHCP_CONFLICT_MESSAGE},
        "servers": list(servers) if isinstance(servers, (list, tuple)) else [],
        "scan": scan if isinstance(scan, dict) else None,
    }


def _dhcp_call(what: str, fn: Callable[[], Any]) -> Any:
    """Run a DhcpServer method: ValueError -> 400, DhcpConflict -> (409, payload), RuntimeError -> 500."""
    try:
        return fn()
    except ApiError:
        raise
    except ValueError as exc:
        raise ApiError(400, "bad_request", str(exc)) from exc
    except RuntimeError as exc:
        conflict = _dhcp_conflict(exc)
        if conflict is not None:
            return conflict
        log.error("%s failed: %s", what, exc)
        raise ApiError(500, "internal_error", str(exc) or f"{what} failed") from exc


def _dhcp_wait_s(body: Dict[str, Any]) -> Optional[float]:
    raw = body.get("wait_s")
    if raw is None or raw == "":
        return None
    if isinstance(raw, bool):
        raise ApiError(400, "bad_request", "wait_s must be a number of seconds")
    try:
        val = float(raw)
    except (TypeError, ValueError):
        raise ApiError(400, "bad_request", "wait_s must be a number of seconds") from None
    if not math.isfinite(val):
        raise ApiError(400, "bad_request", "wait_s must be a finite number of seconds")
    return max(2.0, min(30.0, val))


def _dhcp_mac(raw: str) -> str:
    """The ``{mac}`` path parameter normalised to ``AA:BB:CC:DD:EE:FF`` (400 when it is not a MAC)."""
    try:
        from .. import oui

        mac = oui.normalize_mac(str(raw or ""))
    except Exception:  # noqa: BLE001 - the OUI module is optional at runtime
        log.debug("tnt.oui unavailable for MAC normalisation", exc_info=True)
        digits = re.sub(r"[^0-9A-Fa-f]", "", str(raw or ""))
        mac = ":".join(digits[i:i + 2] for i in range(0, 12, 2)).upper() if len(digits) == 12 else None
    if not mac:
        raise ApiError(400, "bad_request", f"{raw!r} is not a MAC address")
    return mac


# -- Tools page (traceroute, LAN peers) helpers -------------------------------
TRACE_HOST_MAX = 253
TRACE_MAX_HOPS = (1, 64)
TRACE_PROBES = (1, 5)
TRACE_TIMEOUT_MS = (200, 5000)
LAN_THROUGHPUT_SECONDS = (2, 20)
_TRACE_HOST_RE = re.compile(r"^[A-Za-z0-9_.:\-]+$")


def _tool_call(what: str, fn: Callable[[], Any]) -> Any:
    """Run a Tools-page component method: ValueError -> 400, "already running" -> 409, RuntimeError -> 500."""
    try:
        return fn()
    except ApiError:
        raise
    except ValueError as exc:
        raise ApiError(400, "bad_request", str(exc) or f"{what}: invalid input") from exc
    except RuntimeError as exc:
        if "already running" in str(exc).lower():
            raise ApiError(409, "conflict", str(exc)) from exc
        log.error("%s failed: %s", what, exc)
        raise ApiError(500, "internal_error", str(exc) or f"{what} failed") from exc


TFTP_PORT_IN_USE_CODE = "tftp_port_in_use"
#: The network tools' typed errors, by module and class name: ``(HTTP status, error code)``.  Most are RuntimeErrors
#: that :func:`_tool_call` would answer with 500, so :func:`_typed_call` answers them first.
TYPED_ERRORS: Dict[str, Dict[str, Tuple[int, str]]] = {
    "tnt.pktmon": {"PktmonBusy": (409, "conflict"), "PktmonUnavailable": (409, "unavailable")},
    "tnt.portcheck": {"RateLimited": (429, "rate_limited"), "NoPublicIp": (409, "no_public_ip"), "VpnActive": (409, "vpn")},
    "tnt.tftp": {"TftpPortInUse": (409, TFTP_PORT_IN_USE_CODE)},
    "tnt.capture": {"CaptureFileBusy": (409, "conflict"), "CaptureFileMissing": (404, "not_found")},
}


def _typed_call(what: str, fn: Callable[[], Any], *modules: str) -> Any:
    """:func:`_tool_call` with the :data:`TYPED_ERRORS` of *modules* (imported lazily, 503 when one cannot be) answered
    first: ``ApiError(status, code, str(exc))``, with ``Retry-After: <retry_after_s>`` for a 429.  ``TftpPortInUse`` is
    ``(409, {"error": {"code", "message"}, "owners": [...]})``, like :func:`_dhcp_conflict`."""
    typed: List[Tuple[type, int, str]] = []
    for name in modules:
        mod = _lazy(name)
        for cls_name, (status, code) in TYPED_ERRORS[name].items():
            cls = getattr(mod, cls_name, None)
            if isinstance(cls, type) and issubclass(cls, BaseException):
                typed.append((cls, status, code))

    def run() -> Any:
        try:
            return fn()
        except tuple(cls for cls, _status, _code in typed) as exc:
            _cls, status, code = next(entry for entry in typed if isinstance(exc, entry[0]))
            if code == TFTP_PORT_IN_USE_CODE:
                owners = getattr(exc, "owners", None)
                return status, {"error": {"code": code, "message": str(exc)},
                                "owners": [dict(o) for o in owners if isinstance(o, dict)] if isinstance(owners, (list, tuple)) else []}
            headers = {"Retry-After": str(int(getattr(exc, "retry_after_s", 1)))} if status == 429 else None
            raise ApiError(status, code, str(exc), headers) from exc

    return _tool_call(what, run)


#: Query values that mean "no" (anything else, the empty string included, keeps the default).
_FALSE_QUERY = {"0", "false", "no", "off"}


def _query_flag(req: "Request", name: str, default: bool = True) -> bool:
    """An optional ``?name=0|false|no|off`` switch (never 400: an unreadable value is the default)."""
    raw = req.query.get(name)
    if raw is None or raw == "":
        return default
    text = str(raw).strip().lower()
    if text in _FALSE_QUERY:
        return False
    if text in ("1", "true", "yes", "on"):
        return True
    return default


def _body_int(body: Dict[str, Any], key: str, default: int, lo: int, hi: int) -> int:
    """An optional integer body field within ``lo..hi`` (400 otherwise; JSON true/false never count)."""
    raw = body.get(key, default)
    if raw is None or raw == "":
        return default
    bad = ApiError(400, "bad_request", f"{key} must be an integer between {lo} and {hi}")
    if isinstance(raw, bool):
        raise bad
    try:
        val = int(raw) if isinstance(raw, int) else int(float(raw))
    except (TypeError, ValueError, OverflowError):
        raise bad from None
    if not lo <= val <= hi:
        raise bad
    return val


def _trace_host(body: Dict[str, Any]) -> str:
    """The traceroute ``host`` (validated like a ping target: letters, digits, ``. - : _``, max 253)."""
    raw = body.get("host")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raise ApiError(400, "bad_request", "host is required")
    if not isinstance(raw, str):
        raise ApiError(400, "bad_request", "host must be a host name or IP address")
    text = raw.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    if not text or len(text) > TRACE_HOST_MAX or not _TRACE_HOST_RE.match(text):
        raise ApiError(400, "bad_request",
                       f"host must be a host name or IP address (letters, digits, '.', '-', ':'; at most {TRACE_HOST_MAX} characters)")
    return text


def _ipv4_body(body: Dict[str, Any], key: str) -> str:
    raw = body.get(key)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raise ApiError(400, "bad_request", f"{key} is required")
    if not isinstance(raw, str):
        raise ApiError(400, "bad_request", f"{key} must be an IPv4 address")
    try:
        return str(ipaddress.IPv4Address(raw.strip()))
    except (ipaddress.AddressValueError, ValueError):
        raise ApiError(400, "bad_request", f"{key} must be an IPv4 address, got {raw.strip()!r}") from None


#: ``/api/reports*``: a report id is 1-15 decimal digits; search strings are at most this long.
_REPORT_ID_RE = re.compile(r"^[0-9]{1,15}$")
REPORT_QUERY_MAX = 200

#: ``GET /api/oui`` takes 1..OUI_MAX_PREFIXES 24-bit prefixes per request.
OUI_MAX_PREFIXES = 256
_OUI_PREFIX_RE = re.compile(r"^([0-9A-Fa-f]{2})([:-]?)([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})$")


def _oui_prefixes(req: "Request") -> List[str]:
    """The ``prefix`` query values (repeated and/or comma separated) as unique ``AA:BB:CC`` keys in
    request order. 400 for none, more than OUI_MAX_PREFIXES, or one that is not three hex pairs
    joined by a single separator style (``:``, ``-`` or none)."""
    raw = [part.strip() for value in req.query_all("prefix") for part in value.split(",")]
    raw = [part for part in raw if part]
    if not raw:
        raise ApiError(400, "bad_request", "prefix is required, e.g. ?prefix=AA:BB:CC")
    if len(raw) > OUI_MAX_PREFIXES:
        raise ApiError(400, "bad_request", f"at most {OUI_MAX_PREFIXES} prefixes per request, got {len(raw)}")
    keys: List[str] = []
    for part in raw:
        m = _OUI_PREFIX_RE.match(part)
        if m is None:
            raise ApiError(400, "bad_request", f"{part[:40]!r} is not a 24-bit OUI prefix (use AA:BB:CC)")
        key = f"{m.group(1)}:{m.group(3)}:{m.group(4)}".upper()
        if key not in keys:
            keys.append(key)
    return keys


#: 403 message when the caller is a standard user (not an administrator).
WIFI_ADMIN_REQUIRED_MSG = "Showing saved Wi-Fi passwords needs a Windows administrator account."
#: 403 message when the caller could not be verified as an administrator (fail closed).
WIFI_ADMIN_UNVERIFIED_MSG = ("Showing saved Wi-Fi passwords needs a Windows administrator account; "
                             "this request could not be verified as one.")
#: 403 message when a browser asks for the keys from a page that is not served by this API.
WIFI_CROSS_ORIGIN_MSG = "Saved Wi-Fi passwords are only shown to the TNT window or a page served by this TNT service."
#: 403 message of the quick tools (DNS lookup, Flush DNS, IP release/renew) and the network tools (NAT check, switch port,
#: port-forward test, packet capture, TFTP server) for a browser page of another origin.
QUICK_TOOLS_CROSS_ORIGIN_MSG = "This tool only answers the TNT window or a page served by this TNT service."
#: 403 messages of IP release/renew for a standard user and for a caller that could not be verified.
IP_RENEW_ADMIN_REQUIRED_MSG = "Releasing and renewing IP addresses needs a Windows administrator account."
IP_RENEW_ADMIN_UNVERIFIED_MSG = ("Releasing and renewing IP addresses needs a Windows administrator account; "
                                 "this request could not be verified as one.")
#: 403 messages of the update install for a standard user and for a caller that could not be verified.
UPDATE_ADMIN_REQUIRED_MSG = "Installing an update needs a Windows administrator account."
UPDATE_ADMIN_UNVERIFIED_MSG = ("Installing an update needs a Windows administrator account; "
                               "this request could not be verified as one.")
#: 403 messages of every packet capture route for a standard user and for a caller that could not be verified.
CAPTURE_ADMIN_REQUIRED_MSG = "Packet capture needs a Windows administrator account."
CAPTURE_ADMIN_UNVERIFIED_MSG = ("Packet capture needs a Windows administrator account; "
                                "this request could not be verified as one.")
#: Event types GET /api/events sends only to a Windows administrator, as every packet capture route answers only one:
#: ``capture.state`` carries the capture job (adapter, host / port / protocol filters, file name) and the saved files.
ADMIN_ONLY_EVENTS = frozenset({"capture.state"})


def _cross_origin_browser_request(req: Request, api: Any) -> bool:
    """True when a browser sent *req* from a page of another origin.

    Browsers send ``Sec-Fetch-Site`` with every request and ``Origin`` with a cross-origin
    fetch. Allowed: no such header (curl, PowerShell, the tray client's own HTTP calls),
    ``same-origin`` (the TNT window or a tab on this server) and ``none`` (an address typed into
    the browser). Refused: ``same-site`` (another port on localhost is a different origin) and
    ``cross-site``, or an ``Origin`` that is not this server. The process-token check still runs
    for every request this lets through; this only keeps a hostile page open in an
    administrator's browser from making the service serialise the keys to that browser."""
    from .server import origin_allowed    # deferred: tnt.api.server imports this module

    origin = (req.headers.get("origin") or "").strip()
    site = (req.headers.get("sec-fetch-site") or "").strip().lower()
    if origin and not origin_allowed(origin, getattr(api, "port", None)):
        return True
    return site not in ("", "same-origin", "none")


def _wifi_reveal_check(api: Any) -> Optional[Callable[[Any, Any], str]]:
    """The admin check the Wi-Fi route uses before revealing keys: ``api.wifi_reveal_check``
    when a test injected one, else the real :func:`tnt.peer.reveal_allowed` (the mock API does
    not use this: it emulates the answer with ``STATE.wifi_admin``). ``None`` when even that
    cannot be imported (the route then fails closed)."""
    injected = getattr(api, "wifi_reveal_check", None)
    if injected is not None:
        return injected
    try:
        from ..peer import reveal_allowed
    except Exception:  # noqa: BLE001 - never let an import problem reveal a key
        log.warning("tnt.peer could not be imported; refusing to reveal Wi-Fi keys", exc_info=True)
        return None
    return reveal_allowed


def _admin_decision(req: Request, api: Any, what: str) -> str:
    """``"allowed"``, ``"denied"`` or ``"unknown"`` for the caller of *req*, from :func:`_wifi_reveal_check` (the
    Wi-Fi keys, IP release/renew and packet capture).  No check, or one that raises, is ``"unknown"``: the callers fail
    closed."""
    check = _wifi_reveal_check(api)
    if check is None:
        return "unknown"
    try:
        return str(check(req.peer, req.local))
    except Exception:  # noqa: BLE001 - a failing check refuses, never 500s
        log.exception("%s check raised", what)
        return "unknown"


# ---------------------------------------------------------------------------
# route table
# ---------------------------------------------------------------------------
def build_routes(engine: Any, api: Any) -> Router:
    """Register every ``/api`` route from the contract on a new Router."""
    r = Router()

    # -- basics -------------------------------------------------------------
    @r.get("/api/health")
    def health(req: Request) -> Any:
        return {"ok": True}

    @r.get("/api/status")
    def status(req: Request) -> Any:
        now = time.time()
        ping = getattr(engine, "ping", None)
        outages = getattr(engine, "outages", None)
        speed = getattr(engine, "speed", None)
        config = getattr(engine, "config", None)
        # one broken component must not blank the whole status (the tray polls it)
        targets = _safe_call("ping.targets()", ping.targets, []) if ping is not None else []
        targets = targets if isinstance(targets, list) else []
        paused = bool(getattr(ping, "paused", False)) if ping is not None else False
        started = getattr(engine, "started_ts", None)
        disc = _safe_call("discovery_status()", engine.discovery_status, {}) or {}
        net = _safe_call("netinfo_summary()", engine.netinfo_summary, None) or {"internet_nic": None, "adapter_count": 0}
        linkmap = getattr(engine, "linkmap", None)
        dhcp = getattr(engine, "dhcp", None)
        reports = getattr(engine, "reports", None)
        geoip = getattr(engine, "geoip", None)
        updater = getattr(engine, "update", None)
        tftp = getattr(engine, "tftp", None)
        watch = _net_state(engine)
        nic = (net.get("internet_nic") if isinstance(net, dict) else None) or {}
        return {
            "map": _safe_call("linkmap.view()", linkmap.view, None) if linkmap is not None else None,
            "dhcp": _safe_call("dhcp.summary()", dhcp.summary, None) if dhcp is not None else None,
            "reports": _safe_call("reports.status()", reports.status, None) if reports is not None else None,
            "geoip": _safe_call("geoip.status()", geoip.status, None) if geoip is not None else None,
            "update": _safe_call("update.status()", updater.status, None) if updater is not None else None,
            "tftp": _safe_call("tftp.summary()", tftp.summary, None) if tftp is not None else None,
            "version": getattr(engine, "version", ""),
            "started_ts": started,
            "uptime_s": round(now - started, 1) if started else 0.0,
            "mode": "console" if getattr(engine, "console", False) else "service",
            "monitoring": ping is not None and not paused and len(targets) > 0,
            "paused": paused,
            "overall_light": _safe_call("overall_light()", engine.overall_light, "grey"),
            "targets": targets,
            "outages": _safe_call("outages.status()", outages.status) if outages is not None else None,
            "speed": _safe_call("speed.status()", speed.status) if speed is not None else None,
            "discovery": {
                "running": bool(disc.get("running", False)),
                "progress": disc.get("progress"),
                "last_run": disc.get("last_run"),
            },
            "netinfo": net,
            "net": {
                "generation": int((watch or {}).get("generation") or 0),
                "changed_ts": (watch or {}).get("changed_ts"),
                "default_gateway": watch.get("default_gateway") if watch is not None else nic.get("gateway"),
                "internet_nic": watch.get("internet_nic") if watch is not None else nic.get("name"),
                "summary": watch.get("summary") if watch is not None else None,
                "networks": [str(n) for n in (watch.get("networks") or [])] if watch is not None else [],
                "network_id": _current_network_id(engine),
            },
            "settings": {
                "theme": config.get("ui.theme", "light") if config is not None else "light",
                "loaded": bool(config.get("ping.loaded", True)) if config is not None else True,
            },
        }

    @r.get("/api/netinfo")
    def netinfo(req: Request) -> Any:
        mod = _lazy("tnt.netinfo", "network information")
        snap = mod.netinfo_snapshot()
        if isinstance(snap, dict):
            watch = _net_state(engine) or {}
            snap["generation"] = int(watch.get("generation") or 0)
            snap["changed_ts"] = watch.get("changed_ts")
        return snap

    # -- IP location (DB-IP Lite) --------------------------------------------
    @r.get("/api/geoip")
    def geoip_status(req: Request) -> Any:
        return _need(engine, "geoip", "IP location").status()

    @r.get("/api/geoip/lookup")
    def geoip_lookup(req: Request) -> Any:
        gm = _need(engine, "geoip", "IP location")
        text = str(req.query.get("ip") or "").strip()
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        text = text.split("%", 1)[0]
        try:
            if not text or len(text) > 64:
                raise ValueError
            addr = ipaddress.ip_address(text)
        except ValueError:
            raise ApiError(400, "bad_request", "ip must be an IPv4 or IPv6 address") from None
        return {"ip": str(addr), "result": _safe_call("geoip.lookup()", lambda: gm.lookup(str(addr)), None)}

    @r.post("/api/geoip/check")
    def geoip_check(req: Request) -> Any:
        """Retry now: clears the month budget and backoff and wakes the IP location thread (no body)."""
        gm = _need(engine, "geoip", "IP location")
        if not gm.check_now():
            raise ApiError(409, "conflict", "IP location is switched off")
        return gm.status()

    # -- auto-update (GitHub releases) ---------------------------------------
    @r.get("/api/update")
    def update_status(req: Request) -> Any:
        return _need(engine, "update", "Automatic updates").status()

    @r.post("/api/update/check")
    def update_check(req: Request) -> Any:
        """Check GitHub now (no body); 409 when updates are switched off."""
        um = _need(engine, "update", "Automatic updates")
        if not um.check_now():
            raise ApiError(409, "conflict", "Automatic updates are switched off")
        return um.status()

    @r.post("/api/update/install")
    def update_install(req: Request) -> Any:
        """Download, verify (SHA-256) and launch the installer for the available update (no body). Only for
        a Windows administrator (the Wi-Fi key check, failing closed); 409 when none is available or one is
        already installing."""
        _quick_tool_origin(req, "Install update")
        decision = _admin_decision(req, api, "Install update")
        if decision != "allowed":
            log.info("update install refused for %s (%s)", req.client or "?", decision)
            raise ApiError(403, "admin_required",
                           UPDATE_ADMIN_REQUIRED_MSG if decision == "denied" else UPDATE_ADMIN_UNVERIFIED_MSG)
        um = _need(engine, "update", "Automatic updates")
        try:
            um.request_install()
        except RuntimeError as exc:
            raise ApiError(409, "conflict", str(exc)) from None
        return um.status()

    # -- targets ------------------------------------------------------------
    @r.get("/api/targets")
    def targets(req: Request) -> Any:
        return _need(engine, "ping", "ping monitoring").targets()

    @r.post("/api/targets")
    def add_target(req: Request) -> Any:
        _need(engine, "ping", "ping monitoring")
        body = req.json_object()
        host = str(body.get("host") or "").strip()
        label = body.get("label")
        label = str(label).strip() or None if label is not None else None
        if not host:
            raise ApiError(400, "bad_request", "host is required")
        try:
            adder = getattr(engine, "add_target", None)
            view = adder(host, label) if callable(adder) else engine.ping.add_target(host, label)
        except ValueError as exc:
            raise ApiError(400, "bad_request", str(exc)) from exc
        return json_response(view, 201)

    @r.post("/api/targets/defaults")
    def load_defaults(req: Request) -> Any:
        return _need(engine, "ping", "ping monitoring").load_defaults()

    @r.put("/api/targets/order")
    def reorder_targets(req: Request) -> Any:
        ping = _need(engine, "ping", "ping monitoring")
        body = req.json_object()
        ids = body.get("ids")
        if not isinstance(ids, list) or not ids or len(ids) > 500:
            raise ApiError(400, "bad_request", "ids must be a non-empty list of target ids")
        try:
            return ping.reorder(ids)
        except ValueError as exc:
            raise ApiError(400, "bad_request", str(exc)) from exc

    @r.delete("/api/targets/{id}")
    def remove_target(req: Request) -> Any:
        _need(engine, "ping", "ping monitoring")
        tid = req.int_param("id")
        remover = getattr(engine, "remove_target", None)
        ok = remover(tid) if callable(remover) else engine.ping.remove_target(tid)
        if not ok:
            raise ApiError(404, "not_found", f"target {tid} not found")
        return {"removed": True}

    @r.get("/api/targets/{id}/samples")
    def samples(req: Request) -> Any:
        ping = _need(engine, "ping", "ping monitoring")
        tid = req.int_param("id")
        seconds = req.query_int("seconds", 300, lo=1, hi=86400)
        if ping.target(tid) is None:
            raise ApiError(404, "not_found", f"target {tid} not found")
        return {"target_id": tid, "seconds": seconds, "samples": [_sample_pair(s) for s in ping.samples(tid, seconds)]}

    @r.get("/api/targets/{id}/history")
    def history(req: Request) -> Any:
        db = _need(engine, "db", "database")
        tid = req.int_param("id")
        start, end = req.time_range(86400.0)
        if db.get_target(tid) is None:
            raise ApiError(404, "not_found", f"target {tid} not found")
        return {
            "target_id": tid,
            "from": start,
            "to": end,
            "minutes": db.ping_minutes(tid, start, end),
            "summary": db.ping_summary(tid, start, end),
        }

    # -- outages ------------------------------------------------------------
    @r.get("/api/outages")
    def outages(req: Request) -> Any:
        tracker = _need(engine, "outages", "outage tracking")
        start, end = req.time_range(86400.0)
        return {"from": start, "to": end, "outages": tracker.list(start, end), "status": tracker.status()}

    @r.get("/api/outages/timeline")
    def timeline(req: Request) -> Any:
        tracker = _need(engine, "outages", "outage tracking")
        hours = req.query_float("hours", 24.0) or 24.0
        hours = max(0.25, min(24.0 * 366, float(hours)))
        return tracker.timeline(hours)

    # -- speed tests --------------------------------------------------------
    @r.get("/api/speedtests")
    def speedtests(req: Request) -> Any:
        sched = _need(engine, "speed", "speed tests")
        start, end = req.time_range(86400.0)
        limit = req.query_int("limit", 0, lo=0, hi=100000) or None
        return {"from": start, "to": end, "results": sched.history(start, end, limit), "status": sched.status()}

    @r.post("/api/speedtests/run")
    def speedtest_run(req: Request) -> Any:
        sched = _need(engine, "speed", "speed tests")
        if not sched.run_now():
            raise ApiError(409, "conflict", "a speed test is already running")
        return {"started": True}

    @r.get("/api/speedtests/patterns")
    def speedtest_patterns(req: Request) -> Any:
        sched = _need(engine, "speed", "speed tests")
        days = req.query_int("days", 7, lo=1, hi=365)
        return sched.patterns(days)

    # -- discovery ----------------------------------------------------------
    @r.get("/api/discovery/runs")
    def discovery_runs(req: Request) -> Any:
        db = _need(engine, "db", "database")
        limit = req.query_int("limit", 50, lo=1, hi=1000)
        return {"runs": db.list_discovery_runs(limit)}

    @r.get("/api/discovery/runs/{id}")
    def discovery_run(req: Request) -> Any:
        db = _need(engine, "db", "database")
        rid = req.int_param("id")
        run = db.get_discovery_run(rid)
        if run is None:
            raise ApiError(404, "not_found", f"discovery run {rid} not found")
        return _categorised(run)

    @r.get("/api/discovery/last")
    def discovery_last(req: Request) -> Any:
        return _categorised(_need(engine, "db", "database").last_discovery_run())

    @r.post("/api/discovery/scan")
    def discovery_scan(req: Request) -> Any:
        _need(engine, "discovery", "network discovery")
        body = req.json_object()
        range_text = body.get("range")
        range_text = str(range_text).strip() or None if range_text is not None else None
        ports = _clean_ports(body.get("ports"))
        try:
            started = engine.discovery_start(range_text, ports)
        except ValueError as exc:
            raise ApiError(400, "bad_request", str(exc)) from exc
        if not started:
            raise ApiError(409, "conflict", "a discovery scan is already running")
        st = engine.discovery_status()
        return {"started": True, "range": st.get("range", range_text), "ports": st.get("ports", ports)}

    @r.post("/api/discovery/cancel")
    def discovery_cancel(req: Request) -> Any:
        _need(engine, "discovery", "network discovery")
        engine.discovery_cancel()
        return {"cancelled": True}

    @r.get("/api/discovery/status")
    def discovery_status(req: Request) -> Any:
        st = dict(engine.discovery_status())
        st.setdefault("running", False)
        st.setdefault("progress", None)
        st.setdefault("default_range", None)
        st.setdefault("default_ports", [])
        return st

    # -- DHCP server tool ---------------------------------------------------
    @r.get("/api/dhcp/status")
    def dhcp_status(req: Request) -> Any:
        dhcp = _need(engine, "dhcp", "the DHCP server")
        return _dhcp_call("dhcp.status()", dhcp.status)

    @r.get("/api/dhcp/leases")
    def dhcp_leases(req: Request) -> Any:
        dhcp = _need(engine, "dhcp", "the DHCP server")
        leases = _dhcp_call("dhcp.leases()", dhcp.leases)
        return {"leases": list(leases or [])}

    @r.post("/api/dhcp/scan")
    def dhcp_scan(req: Request) -> Any:
        dhcp = _need(engine, "dhcp", "the DHCP server")
        body = req.json_object() if req.body and req.body.strip() else {}
        wait_s = _dhcp_wait_s(body)
        if wait_s is None:
            return _dhcp_call("dhcp.scan()", dhcp.scan)
        return _dhcp_call("dhcp.scan()", lambda: dhcp.scan(wait_s=wait_s))

    @r.post("/api/dhcp/start")
    def dhcp_start(req: Request) -> Any:
        dhcp = _need(engine, "dhcp", "the DHCP server")
        body = req.json_object() if req.body and req.body.strip() else {}
        force = body.get("force", False)
        if not isinstance(force, bool):
            # only JSON true skips the second-server safety scan: "yes", 1 or {} must not
            raise ApiError(400, "bad_request", "force must be true or false")
        return _dhcp_call("dhcp.start()", lambda: dhcp.start(force=force))

    @r.post("/api/dhcp/stop")
    def dhcp_stop(req: Request) -> Any:
        dhcp = _need(engine, "dhcp", "the DHCP server")
        return _dhcp_call("dhcp.stop()", dhcp.stop)

    @r.put("/api/dhcp/settings")
    def dhcp_settings(req: Request) -> Any:
        dhcp = _need(engine, "dhcp", "the DHCP server")
        body = req.json_object()
        unknown = sorted(k for k in body if k not in DHCP_SETTINGS_KEYS)
        if unknown:
            raise ApiError(400, "bad_request",
                           f"unknown DHCP setting(s) {', '.join(unknown)}; accepted: {', '.join(DHCP_SETTINGS_KEYS)}")
        patch = {k: body[k] for k in DHCP_SETTINGS_KEYS if k in body}
        if not patch:
            raise ApiError(400, "bad_request", f"nothing to update; accepted keys: {', '.join(DHCP_SETTINGS_KEYS)}")
        return _dhcp_call("dhcp.update_settings()", lambda: dhcp.update_settings(patch))

    @r.delete("/api/dhcp/leases/{mac}")
    def dhcp_forget(req: Request) -> Any:
        dhcp = _need(engine, "dhcp", "the DHCP server")
        mac = _dhcp_mac(req.params.get("mac", ""))
        ok = _dhcp_call("dhcp.forget_lease()", lambda: dhcp.forget_lease(mac))
        if isinstance(ok, tuple):
            return ok
        if not ok:
            raise ApiError(404, "not_found", f"no lease for {mac}")
        return {"ok": True}

    # -- Tools page: traceroute + LAN peers ---------------------------------
    tracer_lock = threading.Lock()

    def _tracer(create: bool) -> Any:
        """``engine.tracer``; built from the shared pinger on first use when *create* (503 without one)."""
        tracer = getattr(engine, "tracer", None)
        if tracer is not None or not create:
            return tracer
        with tracer_lock:
            tracer = getattr(engine, "tracer", None)
            if tracer is None:
                pinger = _need(engine, "pinger", "the ICMP engine")
                mod = _lazy("tnt.traceroute", "traceroute")
                tracer = mod.Tracer(pinger, getattr(engine, "bus", None), geo=lambda: getattr(engine, "geoip", None))
                setattr(engine, "tracer", tracer)
        return tracer

    @r.post("/api/tools/traceroute")
    def traceroute(req: Request) -> Any:
        body = req.json_object()
        host = _trace_host(body)
        kwargs: Dict[str, Any] = {
            "max_hops": _body_int(body, "max_hops", 30, *TRACE_MAX_HOPS),
            "probes": _body_int(body, "probes", 3, *TRACE_PROBES),
            "timeout_ms": _body_int(body, "timeout_ms", 1500, *TRACE_TIMEOUT_MS),
        }
        resolve_names = body.get("resolve_names", True)
        if resolve_names is None:
            resolve_names = True
        if not isinstance(resolve_names, bool):
            raise ApiError(400, "bad_request", "resolve_names must be true or false")
        kwargs["resolve_names"] = resolve_names
        tracer = _tracer(create=True)
        return _tool_call("traceroute", lambda: tracer.trace(host, **kwargs))

    @r.get("/api/tools/traceroute/last")
    def traceroute_last(req: Request) -> Any:
        tracer = _tracer(create=False)
        if tracer is None:
            return {"trace": None, "running": False}
        return {"trace": getattr(tracer, "last", None), "running": bool(getattr(tracer, "running", False))}

    @r.get("/api/tools/lan/peers")
    def lan_peers(req: Request) -> Any:
        lan = _need(engine, "lan", "LAN peer discovery")
        return _tool_call("lan.peers_view()", lan.peers_view)

    @r.post("/api/tools/lan/throughput")
    def lan_throughput(req: Request) -> Any:
        lan = _need(engine, "lan", "LAN peer discovery")
        body = req.json_object()
        peer = _ipv4_body(body, "peer")
        seconds = _body_int(body, "seconds", 5, *LAN_THROUGHPUT_SECONDS)
        return _tool_call("lan.run_throughput()", lambda: lan.run_throughput(peer, seconds))

    @r.get("/api/tools/lan/throughput/last")
    def lan_throughput_last(req: Request) -> Any:
        lan = _need(engine, "lan", "LAN peer discovery")
        result = _tool_call("lan.last_throughput()", lan.last_throughput)
        return {"result": result, "running": bool(getattr(lan, "throughput_running", False))}

    @r.put("/api/tools/lan/settings")
    def lan_settings(req: Request) -> Any:
        """``{"enabled": true|false}`` -> the peers view. Off stops announcing and listening."""
        lan = _need(engine, "lan", "LAN peer discovery")
        body = req.json_object()
        unknown = sorted(k for k in body if k not in LAN_SETTINGS_KEYS)
        if unknown:
            raise ApiError(400, "bad_request",
                           f"unknown LAN setting(s) {', '.join(unknown)}; accepted: {', '.join(LAN_SETTINGS_KEYS)}")
        if "enabled" not in body:
            raise ApiError(400, "bad_request", f"nothing to update; accepted keys: {', '.join(LAN_SETTINGS_KEYS)}")
        # strict bool: a truthy string ("no", "0") must never silently switch discovery off
        if not isinstance(body["enabled"], bool):
            raise ApiError(400, "bad_request", "enabled must be true or false")
        return _tool_call("lan.set_enabled()", lambda: lan.set_enabled(body["enabled"]))

    @r.get("/api/tools/wifi/profiles")
    def wifi_profiles(req: Request) -> Any:
        """Every Wi-Fi profile this PC has stored.  ``reveal`` defaults to **False**: without it
        the keys are left out (``key_present`` still says whether there is one) and any local
        caller may read the list.  ``reveal=1`` returns the plaintext keys, but only to a
        process running under a Windows administrator account (elevated or not): the service
        identifies the process that owns the client end of this connection (:mod:`tnt.peer`)
        and checks its token.  A standard user -- or a caller that cannot be verified -- gets
        403 ``admin_required`` and no keys.  A browser request from a page of another origin is
        refused first (403 ``forbidden``, see :func:`_cross_origin_browser_request`).  The keys
        never leave this loopback API.  ``tnt.wifi`` is imported lazily so a broken import is a
        503."""
        mod = _lazy("tnt.wifi", "saved Wi-Fi networks")
        reveal = _query_flag(req, "reveal", False)
        if reveal:
            if _cross_origin_browser_request(req, api):
                log.info("saved Wi-Fi passwords not revealed to %s (cross-origin browser request)", req.client or "?")
                raise ApiError(403, "forbidden", WIFI_CROSS_ORIGIN_MSG)
            decision = _admin_decision(req, api, "Wi-Fi reveal")
            if decision != "allowed":
                log.info("saved Wi-Fi passwords not revealed to %s (%s)", req.client or "?", decision)
                msg = WIFI_ADMIN_REQUIRED_MSG if decision == "denied" else WIFI_ADMIN_UNVERIFIED_MSG
                raise ApiError(403, "admin_required", msg)
        return _tool_call("wifi.list_profiles()", lambda: mod.list_profiles(reveal=reveal))

    # -- quick tools: DNS lookup (Tools page), Flush DNS and IP release/renew (top bar) ----------
    def _quick_tool_origin(req: Request, what: str) -> None:
        if _cross_origin_browser_request(req, api):
            log.info("%s refused for %s (cross-origin browser request)", what, req.client or "?")
            raise ApiError(403, "forbidden", QUICK_TOOLS_CROSS_ORIGIN_MSG)

    @r.post("/api/tools/dns/lookup")
    def tools_dns_lookup(req: Request) -> Any:
        """``{"name": str, "server": str|null, "type": str|null}`` -> DNS_RESULT: ``tnt.nettools.dns_lookup`` asks
        the DNS server directly, like nslookup (``ok`` false with ``error`` when it finds nothing).  ``type`` null,
        absent or empty is Auto (A + AAAA for a name, PTR for an address); a bad name, server or type, or an address
        with a type other than PTR, is a 400 with the validator's text."""
        _quick_tool_origin(req, "DNS lookup")
        body = req.json_object()
        name, server, record_type = body.get("name"), body.get("server"), body.get("type")
        if name is not None and not isinstance(name, str):
            raise ApiError(400, "bad_request", "name must be text")
        if server is not None and not isinstance(server, str):
            raise ApiError(400, "bad_request", "server must be text or null")
        if record_type is not None and not isinstance(record_type, str):
            raise ApiError(400, "bad_request", "type must be text or null")
        mod = _lazy("tnt.nettools", "DNS lookup")
        return _tool_call("nettools.dns_lookup()",
                          lambda: mod.dns_lookup(name or "", server, record_type=record_type))

    @r.post("/api/tools/dns/flush")
    def tools_dns_flush(req: Request) -> Any:
        """No body -> FLUSH_RESULT (``ok`` may be false; the reason is in ``error``)."""
        _quick_tool_origin(req, "Flush DNS")
        mod = _lazy("tnt.nettools", "Flush DNS")
        return _tool_call("nettools.flush_dns()", mod.flush_dns)

    @r.post("/api/tools/ip/renew")
    def tools_ip_renew(req: Request) -> Any:
        """No body -> RENEW_RESULT from ``engine.ip_release_renew()``.  Only for a Windows administrator (the Wi-Fi
        key check, failing closed); 409 while one runs."""
        _quick_tool_origin(req, "IP release/renew")
        decision = _admin_decision(req, api, "IP release/renew")
        if decision != "allowed":
            log.info("IP release/renew refused for %s (%s)", req.client or "?", decision)
            raise ApiError(403, "admin_required",
                           IP_RENEW_ADMIN_REQUIRED_MSG if decision == "denied" else IP_RENEW_ADMIN_UNVERIFIED_MSG)
        renew = getattr(engine, "ip_release_renew", None)
        if not callable(renew):
            raise ApiError(503, "unavailable", "IP release/renew is not available")
        return _tool_call("engine.ip_release_renew()", renew)

    # -- network checks (Network info): NAT check, switch port, port-forward test -------------------
    @r.get("/api/netcheck/nat")
    def netcheck_nat(req: Request) -> Any:
        nat = _need(engine, "natcheck", "the NAT check")
        return {"result": nat.last(), "running": bool(nat.running())}

    @r.post("/api/netcheck/nat")
    def netcheck_nat_run(req: Request) -> Any:
        """No body -> ``{"result": NAT_RESULT, "running": false}``; synchronous, 409 while another check runs."""
        _quick_tool_origin(req, "NAT check")
        nat = _need(engine, "natcheck", "the NAT check")
        return {"result": _tool_call("natcheck.run()", nat.run), "running": False}

    @r.get("/api/netcheck/switch")
    def netcheck_switch(req: Request) -> Any:
        finder = _need(engine, "switchport", "the switch port finder")
        return _tool_call("switchport.status()", finder.status)

    @r.post("/api/netcheck/switch")
    def netcheck_switch_start(req: Request) -> Any:
        """``{"adapter": str|null, "seconds": int|null}`` -> ``{"job": JOB}`` (listening); null or absent means the internet
        adapter when it is wired, else the first wired one, and 65 s."""
        _quick_tool_origin(req, "Switch port search")
        finder = _need(engine, "switchport", "the switch port finder")
        body = req.json_object()                    # an empty body is {}
        job =_typed_call("switchport.start()", lambda: finder.start(adapter=body.get("adapter"), seconds=body.get("seconds")),
                          "tnt.pktmon")
        return {"job": job}

    @r.delete("/api/netcheck/switch")
    def netcheck_switch_stop(req: Request) -> Any:
        """Cancel a search (nothing is kept) -> ``{"job": JOB}``."""
        _quick_tool_origin(req, "Switch port search")
        finder = _need(engine, "switchport", "the switch port finder")
        return {"job": _typed_call("switchport.stop()", finder.stop, "tnt.pktmon")}

    @r.post("/api/netcheck/portforward")
    def netcheck_portforward(req: Request) -> Any:
        """``{"port": int}`` -> PORTCHECK_RESULT (the port goes to the service as sent; it blocks for up to about 47 s)."""
        _quick_tool_origin(req, "Port-forward test")
        checker = _need(engine, "portcheck", "the port-forward test")
        body = req.json_object()
        return _typed_call("portcheck.test()", lambda: checker.test(body.get("port")), "tnt.portcheck")

    # -- packet capture (Tools page) ------------------------------------------------------------------
    def _capture(req: Request) -> Any:
        """The capture manager for *req*: a browser page of another origin is refused on every route but the status
        read, then anyone who is not a Windows administrator (failing closed), then 503 without the component."""
        if req.method != "GET" or req.params.get("name") is not None:
            # the download too: a page of another origin must not make a browser save a capture
            _quick_tool_origin(req, "Packet capture")
        decision = _admin_decision(req, api, "Packet capture")
        if decision != "allowed":
            log.info("packet capture refused (%s)", decision)
            raise ApiError(403, "admin_required",
                           CAPTURE_ADMIN_REQUIRED_MSG if decision == "denied" else CAPTURE_ADMIN_UNVERIFIED_MSG)
        return _need(engine, "capture", "packet capture")

    @r.get("/api/tools/capture")
    def capture_status(req: Request) -> Any:
        mgr = _capture(req)
        return _tool_call("capture.status()", mgr.status)

    @r.post("/api/tools/capture")
    def capture_start(req: Request) -> Any:
        """``{"adapter", "seconds"?, "size_mb"?, "full_packets"?, "host"?, "port"?, "protocol"?}`` -> ``{"capture": JOB}``.
        A key left out takes the service default; a null that is sent is checked like any other value."""
        mgr = _capture(req)
        body = req.json_object()
        kwargs = {k: body[k] for k in CAPTURE_START_KEYS if k in body}
        kwargs["adapter"] = body.get("adapter")
        return {"capture": _typed_call("capture.start()", lambda: mgr.start(**kwargs), "tnt.pktmon", "tnt.capture")}

    @r.delete("/api/tools/capture")
    def capture_stop(req: Request) -> Any:
        """End the capture early and keep it -> ``{"capture": JOB|null}``."""
        mgr = _capture(req)
        return {"capture": _typed_call("capture.stop()", mgr.stop, "tnt.pktmon", "tnt.capture")}

    @r.get("/api/tools/capture/files/{name}")
    def capture_file(req: Request) -> Any:
        """A saved capture as a download (:class:`FileResponse`, HEAD included); 404 for a name that is not one."""
        mgr = _capture(req)
        name = req.params.get("name", "")
        fh, size = _typed_call("capture.open_file()", lambda: mgr.open_file(name), "tnt.capture")
        try:
            return FileResponse(fh, size, name)
        except Exception:  # noqa: BLE001 - never leave the file open (it could not be deleted)
            fh.close()
            raise

    @r.delete("/api/tools/capture/files/{name}")
    def capture_file_delete(req: Request) -> Any:
        """Delete a saved capture -> ``{"files": [FILE]}``; 409 while it is being downloaded."""
        mgr = _capture(req)
        name = req.params.get("name", "")
        return {"files": _typed_call("capture.delete_file()", lambda: mgr.delete_file(name), "tnt.capture")}

    # -- TFTP server (Tools page) ---------------------------------------------------------------------
    @r.get("/api/tftp/status")
    def tftp_status(req: Request) -> Any:
        tftp = _need(engine, "tftp", "the TFTP server")
        return _tool_call("tftp.status()", tftp.status)

    @r.post("/api/tftp/start")
    def tftp_start(req: Request) -> Any:
        """``{"adapter": str|null, "uploads": bool}`` -> STATUS (the adapter for this run only; uploads off when absent).
        Another program on UDP 69 is 409 ``tftp_port_in_use`` with its ``owners``."""
        _quick_tool_origin(req, "TFTP server")
        tftp = _need(engine, "tftp", "the TFTP server")
        body = req.json_object()                    # an empty body is {}
        return _typed_call("tftp.start()", lambda: tftp.start(adapter=body.get("adapter"), uploads=body.get("uploads", False)),
                           "tnt.tftp")

    @r.post("/api/tftp/stop")
    def tftp_stop(req: Request) -> Any:
        _quick_tool_origin(req, "TFTP server")
        tftp = _need(engine, "tftp", "the TFTP server")
        return _tool_call("tftp.stop()", tftp.stop)

    @r.post("/api/tftp/uploads")
    def tftp_uploads(req: Request) -> Any:
        """``{"on": bool}`` -> STATUS (never saved: uploads are off after every service start)."""
        _quick_tool_origin(req, "TFTP server")
        tftp = _need(engine, "tftp", "the TFTP server")
        body = req.json_object()
        return _tool_call("tftp.set_uploads()", lambda: tftp.set_uploads(body.get("on")))

    @r.put("/api/tftp/settings")
    def tftp_settings(req: Request) -> Any:
        """``{"adapter", "max_upload_mb"}`` (either or both) -> STATUS; the service refuses any other key (400)."""
        _quick_tool_origin(req, "TFTP server")
        tftp = _need(engine, "tftp", "the TFTP server")
        patch = req.json_object()
        return _tool_call("tftp.update_settings()", lambda: tftp.update_settings(patch))

    @r.get("/api/tftp/files")
    def tftp_files(req: Request) -> Any:
        tftp = _need(engine, "tftp", "the TFTP server")
        return {"files": list(_tool_call("tftp.files()", tftp.files) or [])}

    # -- vendors for the WiFi tile ------------------------------------------
    @r.get("/api/oui")
    def oui_vendors(req: Request) -> Any:
        """``?prefix=AA:BB:CC&prefix=11-22-33`` (or ``prefix=a,b``) -> ``{"vendors": {"AA:BB:CC": name|null}}``.
        Only 24-bit OUIs ever reach the service (the Wi-Fi survey itself runs in TNT.exe, whose bundle
        has no vendor database), so no BSSID is sent to or logged by this API."""
        keys = _oui_prefixes(req)
        mod = _lazy("tnt.oui", "vendor lookup")
        vendors: Dict[str, Optional[str]] = {}
        for key in keys:
            vendors[key] = _safe_call("oui.vendor_for_oui()", lambda k=key: mod.vendor_for_oui(k))
        return {"vendors": vendors}

    # -- networks -----------------------------------------------------------
    @r.get("/api/networks/current")
    def networks_current(req: Request) -> Any:
        tracker = getattr(engine, "networks", None)
        view = _safe_call("networks.current()", tracker.current, None) if tracker is not None else None
        if not isinstance(view, dict):
            return {"network": None}
        db = getattr(engine, "db", None)
        newest = getattr(db, "newest_report_on_network", None)
        # an "Unnamed site" report names no site
        unnamed = _safe_call("reports.site_key()", lambda: _reports_mod().site_key(_reports_mod().UNNAMED_SITE), None)
        row = _safe_call("db.newest_report_on_network()", lambda: newest(view.get("id"), unnamed), None) if callable(newest) else None
        view["last_report"] = ({"id": row.get("id"), "site": row.get("site"), "created_ts": row.get("created_ts")}
                               if isinstance(row, dict) else None)
        return {"network": view}

    def network_update(req: Request) -> Any:
        """``PATCH /api/networks/{id}`` ``{"portable": bool}``: a network carried from site to site (a hotspot), or not."""
        text = str(req.params.get("id") or "").strip()
        if not _REPORT_ID_RE.match(text) or int(text) < 1:
            raise ApiError(400, "bad_request", f"a network id is 1-15 digits, got {text[:20]!r}")
        nid = int(text)
        mgr = _reports()
        body = req.json_object()
        if not isinstance(body.get("portable"), bool):
            raise ApiError(400, "bad_request", "portable (true or false) is required")
        try:
            view = mgr.set_network_portable(nid, body["portable"])
        except RuntimeError as exc:
            raise ApiError(503, "unavailable", str(exc)) from exc
        if view is None:
            raise ApiError(404, "not_found", f"network {nid} not found")
        return {"network": view}

    r.add("PATCH", "/api/networks/{id}", network_update)

    # -- site reports: Full Scan, saved reports, comparisons ----------------
    def _reports() -> Any:
        return _need(engine, "reports", "site reports")

    def _reports_mod() -> ModuleType:
        return _lazy("tnt.reports", "site reports")

    def _site_field(body: Dict[str, Any], required: bool) -> Optional[str]:
        raw = body.get("site")
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            if required:
                raise ApiError(400, "bad_request", "site is required")
            return None
        if not isinstance(raw, str):
            raise ApiError(400, "bad_request", "site must be text")
        try:
            return _reports_mod().normalize_site(raw)
        except ValueError as exc:
            raise ApiError(400, "bad_request", str(exc)) from exc

    def _query_text(req: Request, name: str) -> Optional[str]:
        raw = req.query.get(name)
        if raw is None or not raw.strip():
            return None
        if len(raw) > REPORT_QUERY_MAX:
            raise ApiError(400, "bad_request", f"{name} is longer than {REPORT_QUERY_MAX} characters")
        return raw

    def _report_id(raw: Any, name: str) -> int:
        text = str(raw or "").strip()
        if not text:
            raise ApiError(400, "bad_request", f"{name} is required (a report id)")
        if not _REPORT_ID_RE.match(text) or int(text) < 1:
            raise ApiError(400, "bad_request", f"{name} must be a report id, got {text[:20]!r}")
        return int(text)

    def _scan_conflict(exc: BaseException) -> Tuple[int, Dict[str, Any]]:
        return 409, {"error": {"code": getattr(exc, "code", "conflict"), "message": str(exc)},
                     "job": getattr(exc, "job", None)}

    def _pdf(pdf: Any, filename: str) -> Response:
        if not isinstance(pdf, (bytes, bytearray)):
            raise ApiError(500, "internal_error", "PDF builder returned no data")
        return Response(200, bytes(pdf), "application/pdf", {"Content-Disposition": f'attachment; filename="{filename}"'})

    @r.get("/api/reports")
    def reports_list(req: Request) -> Any:
        mgr = _reports()
        return mgr.list_reports(_query_text(req, "site_key"), _query_text(req, "q"),
                                req.query_int("limit", 50, lo=1, hi=500), req.query_int("offset", 0, lo=0, hi=10_000_000))

    @r.get("/api/reports/sites")
    def reports_sites(req: Request) -> Any:
        mgr = _reports()
        return mgr.sites(_query_text(req, "q"), req.query_int("limit", 20, lo=1, hi=500))

    def scan_get(req: Request) -> Any:
        return {"job": _reports().job()}

    def scan_start(req: Request) -> Any:
        mgr = _reports()
        mod = _reports_mod()
        body = req.json_object() if req.body and req.body.strip() else {}
        site = _site_field(body, required=False)
        try:
            return {"job": mgr.start_scan(site)}
        except mod.ScanBusy as exc:
            return _scan_conflict(exc)
        except mod.ScanConflict as exc:
            raise ApiError(503, "unavailable", str(exc)) from exc

    def scan_name(req: Request) -> Any:
        mgr = _reports()
        mod = _reports_mod()
        site = _site_field(req.json_object(), required=True)
        try:
            return {"job": mgr.set_site(site)}
        except mod.ScanConflict as exc:
            return _scan_conflict(exc)

    def scan_cancel(req: Request) -> Any:
        return {"job": _reports().cancel()}

    r.add("GET", "/api/reports/scan", scan_get)
    r.add("POST", "/api/reports/scan", scan_start)
    r.add("PATCH", "/api/reports/scan", scan_name)
    r.add("DELETE", "/api/reports/scan", scan_cancel)

    @r.post("/api/reports/scan/wifi")
    def scan_wifi(req: Request) -> Any:
        mgr = _reports()
        mod = _reports_mod()
        body = req.json_object()
        try:
            return {"job": mgr.post_wifi(body)}
        except ValueError as exc:
            raise ApiError(400, "bad_request", str(exc)) from exc
        except mod.ScanConflict as exc:
            return _scan_conflict(exc)

    def _compare(req: Request) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        mgr = _reports()
        a_id, b_id = _report_id(req.query.get("a"), "a"), _report_id(req.query.get("b"), "b")
        try:
            return mgr.compare(a_id, b_id)
        except KeyError as exc:
            raise ApiError(404, "not_found", f"report {exc.args[0]} not found") from exc

    @r.get("/api/reports/compare")
    def reports_compare(req: Request) -> Any:
        return _compare(req)[2]

    @r.get("/api/reports/compare/pdf")
    def reports_compare_pdf(req: Request) -> Any:
        a, b, comparison = _compare(req)
        pdfmod = _lazy("tnt.report_pdf", "report PDFs")
        return _pdf(pdfmod.build_compare_report(a, b, comparison), _reports_mod().compare_filename(a.get("site"), b.get("site")))

    def _stored(req: Request) -> Tuple[Any, int, Dict[str, Any]]:
        mgr = _reports()
        rid = _report_id(req.params.get("id"), "report id")
        report = mgr.get(rid)
        if report is None:
            raise ApiError(404, "not_found", f"report {rid} not found")
        return mgr, rid, report

    @r.get("/api/reports/{id}")
    def report_get(req: Request) -> Any:
        _mgr, _rid, report = _stored(req)
        return {k: report.get(k) for k in ("id", "site", "created_ts", "completed_ts", "status", "network_id", "summary", "data")}

    def report_rename(req: Request) -> Any:
        mgr = _reports()
        rid = _report_id(req.params.get("id"), "report id")
        site = _site_field(req.json_object(), required=True)
        row = mgr.rename(rid, site)
        if row is None:
            raise ApiError(404, "not_found", f"report {rid} not found")
        return row

    r.add("PATCH", "/api/reports/{id}", report_rename)

    @r.delete("/api/reports/{id}")
    def report_delete(req: Request) -> Any:
        mgr = _reports()
        rid = _report_id(req.params.get("id"), "report id")
        if not mgr.delete(rid):
            raise ApiError(404, "not_found", f"report {rid} not found")
        return {"ok": True}

    @r.get("/api/reports/{id}/pdf")
    def report_pdf(req: Request) -> Any:
        _mgr, _rid, report = _stored(req)
        pdfmod = _lazy("tnt.report_pdf", "report PDFs")
        return _pdf(pdfmod.build_site_report(report), _reports_mod().pdf_filename(report.get("site"), report.get("created_ts")))

    # -- settings -----------------------------------------------------------
    @r.get("/api/settings")
    def settings(req: Request) -> Any:
        return _need(engine, "config", "settings").snapshot()

    def settings_update(req: Request) -> Any:
        config = _need(engine, "config", "settings")
        patch = req.json_object()
        try:
            changed = config.update(patch)
        except ValueError as exc:
            raise ApiError(400, "bad_request", str(exc)) from exc
        snapshot = config.snapshot()
        if changed:
            bus = getattr(engine, "bus", None)
            if bus is not None:
                try:
                    bus.publish("settings.changed", {"settings": snapshot, "keys": sorted(changed)})
                except Exception:  # noqa: BLE001
                    log.exception("settings.changed publish failed")
        return {"settings": snapshot, "changed": sorted(changed)}

    r.add("PUT", "/api/settings", settings_update)
    r.add("PATCH", "/api/settings", settings_update)

    # -- easter egg: sticks of TNT detonated on this machine (db meta table) ---------
    easter_lock = threading.Lock()

    def _easter_total(db: Any) -> int:
        try:
            return max(0, int(db.get_meta(EASTER_META_KEY, "0") or 0))
        except (TypeError, ValueError):
            return 0

    @r.get("/api/easter")
    def easter(req: Request) -> Any:
        db = _need(engine, "db", "database")
        return {"detonated": _easter_total(db), "max_sticks": EASTER_MAX_STICKS}

    @r.post("/api/easter/detonate")
    def easter_detonate(req: Request) -> Any:
        db = _need(engine, "db", "database")
        body = req.json_object() if req.body and req.body.strip() else {}
        raw = body.get("sticks", 1)
        try:
            if isinstance(raw, bool):
                raise TypeError("bool")
            n = int(raw)
        except (TypeError, ValueError, OverflowError):
            raise ApiError(400, "bad_request", "sticks must be an integer") from None
        if not 1 <= n <= EASTER_MAX_STICKS:
            raise ApiError(400, "bad_request", f"sticks must be between 1 and {EASTER_MAX_STICKS}")
        with easter_lock:
            total = _easter_total(db) + n
            db.set_meta(EASTER_META_KEY, str(total))
        log.info("easter egg: %d stick(s) of TNT detonated (%d so far on this machine)", n, total)
        return {"detonated": total, "added": n, "max_sticks": EASTER_MAX_STICKS}

    # -- monitoring ---------------------------------------------------------
    @r.post("/api/monitoring/pause")
    def pause(req: Request) -> Any:
        _need(engine, "ping", "ping monitoring")
        return {"paused": bool(engine.set_paused(True))}

    @r.post("/api/monitoring/resume")
    def resume(req: Request) -> Any:
        _need(engine, "ping", "ping monitoring")
        return {"paused": bool(engine.set_paused(False))}

    # -- diagnostics --------------------------------------------------------
    @r.get("/api/diagnostics")
    def diagnostics(req: Request) -> Any:
        mod = _lazy("tnt.diagnostics", "diagnostics")
        return mod.collect(engine)

    @r.get("/api/diagnostics/log")
    def diagnostics_log(req: Request) -> Any:
        mod = _lazy("tnt.diagnostics", "diagnostics")
        lines = req.query_int("lines", 200, lo=1, hi=5000)
        return mod.tail_log(lines)

    # -- export -------------------------------------------------------------
    def export(req: Request) -> Any:
        db = _need(engine, "db", "database")
        body = req.json_object() if req.method == "POST" else dict(req.query)
        kind = str(body.get("range") or "daily").strip().lower()
        if kind not in ("daily", "weekly", "monthly", "yearly", "custom"):
            raise ApiError(400, "bad_request", "range must be one of daily, weekly, monthly, yearly, custom")
        now = time.time()
        c_from = _parse_when(body.get("from"))
        c_to = _parse_when(body.get("to"), end_of_day=True)
        if kind == "custom":
            if c_from is None or c_to is None:
                raise ApiError(400, "bad_request", "custom range needs 'from' and 'to'")
            if c_from > c_to:
                raise ApiError(400, "bad_request", "'from' must not be after 'to'")
        mod = _lazy("tnt.export_pdf", "PDF export")
        start, end = mod.range_bounds(kind, now, c_from, c_to)
        ping = getattr(engine, "ping", None)
        targets_view = None
        if ping is not None:
            try:
                targets_view = ping.targets()
            except Exception:  # noqa: BLE001
                log.debug("targets() failed for export", exc_info=True)
        net = None
        try:
            net = importlib.import_module("tnt.netinfo").netinfo_snapshot()
        except Exception:  # noqa: BLE001
            log.debug("netinfo snapshot unavailable for export", exc_info=True)
        pdf = mod.build_report(db, start, end, targets=targets_view, netinfo=net, tz_offset_s=_local_tz_offset_s())
        if not isinstance(pdf, (bytes, bytearray)):
            raise ApiError(500, "internal_error", "PDF builder returned no data")
        fname = "TNT-report-%s-%s.pdf" % (
            time.strftime("%Y%m%d", time.localtime(start)),
            time.strftime("%Y%m%d", time.localtime(end)),
        )
        headers = {"Content-Disposition": f"attachment; filename={fname}"}
        try:
            from .. import paths
            out_dir = paths.exports_dir()
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / fname
            out_path.write_bytes(bytes(pdf))
            headers["X-TNT-Export-Path"] = str(out_path)
        except Exception:  # noqa: BLE001
            log.debug("could not save export copy", exc_info=True)
        return Response(200, bytes(pdf), "application/pdf", headers)

    r.add("POST", "/api/export", export)
    r.add("GET", "/api/export", export)

    # -- SSE ----------------------------------------------------------------
    @r.get("/api/events")
    def events(req: Request) -> Any:
        # ADMIN_ONLY_EVENTS go to a Windows administrator only: the packet capture routes' check, asked once per stream when
        # the first such event comes (failing closed)
        return StreamResponse(lambda handler: handler.serve_sse(
            ADMIN_ONLY_EVENTS, lambda: _admin_decision(req, api, "Packet capture") == "allowed"))

    return r
