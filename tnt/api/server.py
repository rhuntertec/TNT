"""Local HTTP server: static UI + JSON API + SSE.

* stdlib ``ThreadingHTTPServer`` (``daemon_threads=True``) bound to
  ``api.host:api.port`` (127.0.0.1:7130 by default).  ``SO_REUSEADDR`` is
  deliberately disabled: on Windows it would let us bind *next to* another
  listener on the same port, hiding a port collision instead of reporting it.
  :func:`preflight_port` produces the operator-friendly error message (owner PID,
  ``netstat -ano | findstr :PORT``, how to move TNT to another port) and raises
  ``RuntimeError`` so the Engine can retry every 30 s instead of crashing the
  service.
* Only loopback clients are accepted (``127.0.0.0/8``, ``::1``,
  ``::ffff:127.x``); anyone else gets ``403 {"error":{"code":"forbidden"}}``.
* Static files come from ``paths.ui_dir()`` with proper MIME types and
  ``Cache-Control: no-cache``; ``/`` -> ``index.html``; ``..`` segments,
  backslashes and anything resolving outside the UI directory are rejected.
* JSON bodies are capped at 1 MB (413).  Requests are logged at DEBUG only.
  Every response carries ``Server: TNT/<version>``.  Errors raised by the stdlib
  request parser itself (bad request line, 414, 431, 501, 505) are rendered in
  the same JSON error shape as route errors.
* ``server_bind`` skips ``socket.getfqdn()`` (a reverse-DNS lookup the stdlib
  ``HTTPServer`` performs at bind time) so the API comes up instantly even when
  DNS is unreachable - which is exactly when TNT is needed.
* Shutdown: ``ApiServer.stop()`` wakes SSE clients through the hub, stops the
  accept loop and joins the server thread with a timeout.  Handler threads are
  daemons and are never joined (``block_on_close=False``).
"""
from __future__ import annotations

import ipaddress
import logging
import mimetypes
import queue
import select
import socket
import socketserver
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

from .. import DEFAULT_PORT, __version__
from .routes import ApiError, Request, Response, Router, StreamResponse, build_routes, json_response
from .sse import HEARTBEAT_S, STOP, SseHub, event_payload, format_comment, format_event

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 1024 * 1024
SSE_POLL_S = 1.0  # how often an idle SSE handler checks whether its client is still there
SERVER_HEADER = f"TNT/{__version__}"
#: How to move the API off a busy port (the overrides are applied by tnt.config; a plain PORT
#: is ignored by the installed service, TNT_PORT is not).
PORT_OVERRIDE_HINT = ("To run TNT on another port, set the TNT_PORT environment variable (PORT also works "
                      "for a console run) or api.port in config.json.")

_MIME: Dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".webmanifest": "application/manifest+json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".pdf": "application/pdf",
    ".wasm": "application/wasm",
}

_FALLBACK_INDEX = """<!doctype html><html><head><meta charset="utf-8"><title>TNT</title>
<style>body{font-family:system-ui,sans-serif;margin:3rem;color:#2B2438}code{background:#eee;padding:.1em .3em;border-radius:4px}</style>
</head><body><h1>TNT service is running</h1>
<p>The web UI files were not found in <code>{ui_dir}</code>.</p>
<p>The API is available: <a href="/api/status">/api/status</a>, <a href="/api/health">/api/health</a>,
<a href="/api/diagnostics">/api/diagnostics</a>.</p></body></html>"""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
_LOCAL_HOSTNAMES = ("127.0.0.1", "localhost", "[::1]", "::1")


def host_allowed(host_header: str, port: "int | None") -> bool:
    """Accept only loopback names for the Host header (any port when *port* is unknown)."""
    text = host_header.strip().lower()
    if not text:
        return True
    if text.startswith("["):  # [::1]:port
        end = text.find("]")
        if end < 0:
            return False
        name, rest = text[: end + 1], text[end + 1:]
        port_part = rest[1:] if rest.startswith(":") else ("" if not rest else None)
    else:
        name, _, port_part = text.partition(":")
    if port_part is None:
        return False
    if name not in _LOCAL_HOSTNAMES:
        try:  # any other name must be a literal loopback IP (127.x.x.x), never a DNS name
            if not ipaddress.ip_address(name).is_loopback:
                return False
        except ValueError:
            return False
    if port_part:
        if not port_part.isdigit():
            return False
        if port is not None and int(port_part) != int(port):
            return False
    return True


def origin_allowed(origin: str, port: "int | None") -> bool:
    """Same-origin check for state-changing requests coming from a browser context."""
    text = origin.strip().lower()
    if text in ("", "null"):
        return text == ""
    if not text.startswith("http://"):
        return False
    return host_allowed(text[len("http://"):], port)


def is_loopback(ip: str) -> bool:
    """True for 127.0.0.0/8, ::1 and IPv4-mapped loopback (zone ids stripped)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return bool(addr.is_loopback)


def mime_for(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in _MIME:
        return _MIME[ext]
    guess, _enc = mimetypes.guess_type(str(path))
    if guess and guess.startswith("text/"):
        return f"{guess}; charset=utf-8"
    return guess or "application/octet-stream"


def describe_port_owner(port: int) -> Optional[str]:
    """``'PID 1234 (python.exe)'`` for the listener on *port*, or None. Never raises."""
    try:
        import psutil  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != psutil.CONN_LISTEN or not conn.laddr or conn.laddr.port != port:
                continue
            pid = conn.pid
            if not pid:
                return "an unknown process"
            try:
                name = psutil.Process(pid).name()
            except Exception:  # noqa: BLE001
                name = "?"
            return f"PID {pid} ({name})"
    except Exception:  # noqa: BLE001
        log.debug("could not inspect port owner", exc_info=True)
    return None


def port_busy_message(host: str, port: int, error: Optional[BaseException] = None) -> str:
    owner = describe_port_owner(port)
    owner_txt = f" - owned by {owner}" if owner else ""
    pid_hint = ""
    if owner and owner.startswith("PID "):
        pid_hint = f' (then: tasklist /FI "PID eq {owner.split()[1]}")'
    err_txt = f" [{error}]" if error is not None else ""
    return (
        f"TNT API cannot listen on {host}:{port}: port {port} is already in use{owner_txt}{err_txt}. "
        f"Find the owner with:  netstat -ano | findstr :{port}{pid_hint}. "
        f"Stop that program or move TNT: {PORT_OVERRIDE_HINT} "
        f"The service keeps running and retries the bind every 30 s."
    )


def preflight_port(host: str, port: int) -> None:
    """Raise ``RuntimeError`` with an operator-friendly message if *port* cannot be bound."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(2.0)
        # no SO_REUSEADDR here on purpose (Windows would happily "share" the port)
        sock.bind((host, int(port)))
    except OSError as exc:
        if getattr(exc, "errno", None) in (98, 10048, 48) or getattr(exc, "winerror", None) == 10048:
            msg = port_busy_message(host, port, exc)
        elif getattr(exc, "winerror", None) == 10013 or getattr(exc, "errno", None) == 13:
            msg = (f"TNT API cannot listen on {host}:{port}: access denied (Windows reserved the port or a "
                   f"firewall policy blocks it) [{exc}]. Check `netsh interface ipv4 show excludedportrange "
                   f"protocol=tcp` and `netstat -ano | findstr :{port}`. {PORT_OVERRIDE_HINT}")
        else:
            msg = (f"TNT API cannot listen on {host}:{port}: {exc}. Check `netstat -ano | findstr :{port}`. "
                   f"{PORT_OVERRIDE_HINT}")
        log.error(msg)
        raise RuntimeError(msg) from exc
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# server + handler
# ---------------------------------------------------------------------------
class ApiHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = False
    allow_reuse_port = False
    request_queue_size = 64

    def __init__(self, address: Tuple[str, int], handler: type, api: "ApiServer") -> None:
        self.api = api
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, handler)

    def server_bind(self) -> None:  # noqa: D401 - override
        # HTTPServer.server_bind() calls socket.getfqdn(host), a reverse-DNS lookup
        # that can block for seconds when DNS is unreachable - i.e. exactly while the
        # internet is down, which is when TNT must come up quickly.  We only need the
        # literal host/port, so bind at the TCPServer level and skip the lookup.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)

    def handle_error(self, request: Any, client_address: Any) -> None:  # noqa: D401 - override
        exc = sys.exception()
        if isinstance(exc, (ConnectionError, TimeoutError, socket.timeout)):
            log.debug("connection from %s ended: %s", client_address, exc)
        else:
            log.warning("unhandled error serving %s", client_address, exc_info=True)


class ApiHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60  # idle keep-alive / stalled client socket timeout
    server: ApiHTTPServer  # type: ignore[assignment]

    # -- logging -------------------------------------------------------------
    def version_string(self) -> str:  # noqa: D401 - override
        return SERVER_HEADER

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401 - override
        log.debug("%s %s", self.client_address[0], fmt % args)

    def log_error(self, fmt: str, *args: Any) -> None:  # noqa: D401 - override
        log.debug("%s %s", self.client_address[0], fmt % args)

    def send_error(self, code: int, message: Optional[str] = None, explain: Optional[str] = None) -> None:  # noqa: D401
        """Errors raised by the stdlib request parser (bad request line, 414, 431,
        unsupported HTTP version) are rendered as the contract's JSON error shape
        instead of the default HTML page."""
        try:
            phrase = HTTPStatus(int(code)).phrase
        except ValueError:
            phrase = "error"
        text = message or explain or phrase
        self.log_error("code %d, message %s", code, text)
        self.close_connection = True
        try:
            exc = ApiError(int(code), None, str(text))
            resp = json_response(exc.to_dict(), exc.status)
            self.send_response(resp.status, phrase)
            self.send_header("Content-Type", resp.content_type)
            self.send_header("Content-Length", str(len(resp.body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if getattr(self, "command", None) != "HEAD" and int(code) >= 200 and int(code) not in (204, 304):
                self.wfile.write(resp.body)
            self.wfile.flush()
        except (OSError, ValueError):
            pass

    # -- entry points ----------------------------------------------------------
    def do_GET(self) -> None:
        self._dispatch("GET", send_body=True)

    def do_HEAD(self) -> None:
        self._dispatch("GET", send_body=False)

    def do_POST(self) -> None:
        self._dispatch("POST", send_body=True)

    def do_PUT(self) -> None:
        self._dispatch("PUT", send_body=True)

    def do_PATCH(self) -> None:
        self._dispatch("PATCH", send_body=True)

    def do_DELETE(self) -> None:
        self._dispatch("DELETE", send_body=True)

    def do_OPTIONS(self) -> None:
        self._dispatch("OPTIONS", send_body=True)

    # -- core ------------------------------------------------------------------
    def _dispatch(self, method: str, send_body: bool) -> None:
        api = self.server.api
        started = time.perf_counter()
        status = 500
        try:
            client_ip = self.client_address[0] if self.client_address else ""
            if not is_loopback(client_ip):
                self.close_connection = True
                status = self._send_error(ApiError(403, "forbidden", "only local (loopback) clients are accepted"), send_body)
                return
            if api.stopping:
                self.close_connection = True
                status = self._send_error(ApiError(503, "unavailable", "server is shutting down"), send_body)
                return
            # DNS rebinding: a hostile web page can point its own hostname at 127.0.0.1 and
            # reach this server from a browser; the Host header then names that hostname.
            host_hdr = (self.headers.get("Host") or "").strip()
            if host_hdr and not host_allowed(host_hdr, getattr(api, "port", None)):
                self.close_connection = True
                status = self._send_error(ApiError(403, "forbidden", f"unexpected Host header {host_hdr!r}"), send_body)
                return
            # CSRF: browsers attach Origin / Sec-Fetch-Site to cross-site requests; only same-origin
            # (the TNT window / a tab on this server) may change state. Non-browser clients send neither.
            if method in ("POST", "PUT", "PATCH", "DELETE"):
                origin = (self.headers.get("Origin") or "").strip()
                fetch_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
                if (origin and not origin_allowed(origin, getattr(api, "port", None))) or fetch_site == "cross-site":
                    self.close_connection = True
                    status = self._send_error(ApiError(403, "forbidden", "cross-origin requests are not allowed"), send_body)
                    return
            parts = urlsplit(self.path)
            path = unquote(parts.path or "/")
            query = {k: v for k, v in parse_qsl(parts.query, keep_blank_values=True)}
            body = self._read_body()
            if path == "/api" or path.startswith("/api/"):
                handler, params = api.router.match(method, path)
                peer_addr = local_addr = None
                try:  # the two ends of the accepted socket, for the Wi-Fi key admin check only
                    ca = self.client_address
                    if ca:
                        peer_addr = (ca[0], int(ca[1]))
                    sn = self.connection.getsockname()
                    local_addr = (sn[0], int(sn[1]))
                except Exception:  # noqa: BLE001 - a socket without a name just means "unknown"
                    pass
                req = Request(method=method, path=path, query=query, params=params,
                              headers={k.lower(): v for k, v in self.headers.items()}, body=body,
                              client=client_ip, peer=peer_addr, local=local_addr)
                result = handler(req)
                if isinstance(result, StreamResponse):
                    status = 200
                    if not send_body:  # HEAD: describe the stream, do not start it
                        self._write(Response(200, b"", "text/event-stream; charset=utf-8"), False)
                        return
                    result.serve(self)
                    return
                status = self._send_result(result, send_body)
            else:
                if method != "GET":
                    raise ApiError(405, "method_not_allowed", f"{method} is not allowed on static paths", {"Allow": "GET, HEAD"})
                status = self._serve_static(path, send_body)
        except ApiError as exc:
            status = self._send_error(exc, send_body)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, TimeoutError) as exc:
            log.debug("client %s went away: %s", self.client_address, exc)
            self.close_connection = True
            status = 0
        except Exception as exc:  # noqa: BLE001
            log.exception("unhandled error in %s %s", method, self.path)
            try:
                status = self._send_error(ApiError(500, "internal_error", f"{type(exc).__name__}: {exc}"), send_body)
            except Exception:  # noqa: BLE001
                self.close_connection = True
        finally:
            log.debug("%s %s %s -> %s in %.1f ms", self.client_address[0] if self.client_address else "?",
                      self.command, self.path, status, (time.perf_counter() - started) * 1000.0)

    def _read_body(self) -> bytes:
        raw_len = self.headers.get("Content-Length")
        if not raw_len:
            if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                self.close_connection = True
                raise ApiError(411, "length_required", "chunked request bodies are not supported; send Content-Length")
            return b""
        try:
            length = int(raw_len)
        except ValueError:
            raise ApiError(400, "bad_request", "invalid Content-Length") from None
        if length < 0:
            raise ApiError(400, "bad_request", "invalid Content-Length")
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            raise ApiError(413, "payload_too_large", f"request body exceeds {MAX_BODY_BYTES} bytes")
        if length == 0:
            return b""
        data = self.rfile.read(length)
        if len(data) != length:
            self.close_connection = True
            raise ApiError(400, "bad_request", "incomplete request body")
        return data

    # -- responses -------------------------------------------------------------
    def _send_result(self, result: Any, send_body: bool) -> int:
        if isinstance(result, Response):
            resp = result
        elif isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], int):
            resp = json_response(result[1], result[0])
        else:
            resp = json_response(result)
        self._write(resp, send_body)
        return resp.status

    def _send_error(self, exc: ApiError, send_body: bool) -> int:
        resp = json_response(exc.to_dict(), exc.status, exc.headers)
        self._write(resp, send_body)
        return exc.status

    def _write(self, resp: Response, send_body: bool) -> None:
        self.send_response(resp.status)
        self.send_header("Content-Type", resp.content_type)
        self.send_header("Content-Length", str(len(resp.body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in resp.headers.items():
            self.send_header(k, v)
        self.end_headers()
        if send_body and resp.body:
            self.wfile.write(resp.body)
        self.wfile.flush()

    # -- static files ----------------------------------------------------------
    def _serve_static(self, path: str, send_body: bool) -> int:
        api = self.server.api
        root = api.static_root()
        if "\\" in path or "\x00" in path:
            raise ApiError(400, "bad_request", "invalid path")
        segments = [s for s in path.split("/") if s]
        if any(s in ("..", ".") for s in segments):
            raise ApiError(400, "bad_request", "invalid path")
        if not segments:
            segments = ["index.html"]
        try:
            root_resolved = root.resolve()
            target = root_resolved.joinpath(*segments).resolve()
            target.relative_to(root_resolved)
        except (OSError, ValueError, RuntimeError):
            raise ApiError(404, "not_found", "file not found") from None
        if target.is_dir():
            target = target / "index.html"
        if not target.is_file():
            if segments == ["index.html"]:
                body = _FALLBACK_INDEX.replace("{ui_dir}", str(root)).encode("utf-8")
                self._write(Response(200, body, "text/html; charset=utf-8"), send_body)
                return 200
            raise ApiError(404, "not_found", f"file not found: /{'/'.join(segments)}")
        try:
            data = target.read_bytes()
        except OSError as exc:
            raise ApiError(404, "not_found", f"cannot read file: {exc}") from exc
        self._write(Response(200, data, mime_for(target)), send_body)
        return 200

    # -- SSE -------------------------------------------------------------------
    def serve_sse(self) -> None:
        """Stream bus events until the client disconnects or the server stops."""
        api = self.server.api
        hub = api.hub
        q = hub.subscribe()
        self.close_connection = True
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.wfile.write(b"retry: 3000\n")
            self.wfile.write(format_event("hello", {"version": __version__, "ts": time.time()}))
            self.wfile.flush()
            last_write = time.monotonic()
            while not api.stopping:
                try:
                    ev = q.get(timeout=SSE_POLL_S)
                except queue.Empty:
                    # A silent client is only noticed on a write, so peek at the socket
                    # every poll interval to release the thread (and the client count) promptly.
                    if self._peer_closed():
                        break
                    if time.monotonic() - last_write >= HEARTBEAT_S:
                        self.wfile.write(format_comment("ping"))
                        self.wfile.flush()
                        last_write = time.monotonic()
                    continue
                if ev is STOP:
                    break
                if not isinstance(ev, dict):
                    continue
                self.wfile.write(format_event(str(ev.get("type", "event")), event_payload(ev)))
                self.wfile.flush()
                last_write = time.monotonic()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, TimeoutError, OSError) as exc:
            log.debug("SSE client %s disconnected: %s", self.client_address, exc)
        except Exception:  # noqa: BLE001
            log.exception("SSE stream failed for %s", self.client_address)
        finally:
            hub.unsubscribe(q)

    def _peer_closed(self) -> bool:
        """True when the client socket is readable and yields EOF (client went away)."""
        sock = self.connection
        try:
            readable, _w, _x = select.select([sock], [], [], 0)
            if not readable:
                return False
            return sock.recv(1, socket.MSG_PEEK) == b""
        except (OSError, ValueError):
            return True


# ---------------------------------------------------------------------------
# ApiServer
# ---------------------------------------------------------------------------
class ApiServer:
    """Owns the HTTP server thread, the router and the SSE hub."""

    def __init__(self, engine: Any, host: str = "127.0.0.1", port: int = DEFAULT_PORT, bus: Any | None = None,
                 ui_dir: Optional[Path] = None, hub: Optional[SseHub] = None) -> None:
        self.engine = engine
        self.host = host or "127.0.0.1"
        self.port = int(port)
        self.bus = bus
        self.ui_dir = Path(ui_dir) if ui_dir else None
        self.hub = hub or SseHub(bus)
        self.router: Router = build_routes(engine, self)
        self.httpd: Optional[ApiHTTPServer] = None
        self.stopping = False
        self.started_ts: Optional[float] = None
        self.last_error: Optional[str] = None
        # Injectable seam for the Wi-Fi key reveal check (tests / mock set it): a callable
        # (peer, local) -> "allowed" | "denied" | "unknown". None means "use tnt.peer".
        self.wifi_reveal_check: Optional[Any] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

    # -- properties --------------------------------------------------------
    @property
    def running(self) -> bool:
        with self._lock:
            return self.httpd is not None and self._thread is not None and self._thread.is_alive()

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}/"

    @property
    def clients_sse(self) -> int:
        return self.hub.client_count()

    def static_root(self) -> Path:
        if self.ui_dir is not None:
            return self.ui_dir
        from .. import paths
        return paths.ui_dir()

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        """Bind and serve in a daemon thread. Raises RuntimeError when the port is busy."""
        with self._lock:
            if self.running:
                return
            stale, self.httpd = self.httpd, None
            if stale is not None:
                # the accept loop died (its thread is gone) but the listening socket is
                # still bound: release it or the rebind below fails against ourselves
                try:
                    stale.server_close()
                except Exception:  # noqa: BLE001
                    log.debug("closing the stale server failed", exc_info=True)
            self.stopping = False
            if self.bus is not None and not self.hub.attached:
                self.hub.attach(self.bus)
            try:
                preflight_port(self.host, self.port)
            except RuntimeError as exc:
                self.last_error = str(exc)
                raise
            try:
                httpd = ApiHTTPServer((self.host, self.port), ApiHandler, self)
            except OSError as exc:
                self.last_error = port_busy_message(self.host, self.port, exc)
                log.error(self.last_error)
                raise RuntimeError(self.last_error) from exc
            self.httpd = httpd
            self.port = int(httpd.server_address[1])
            self.started_ts = time.time()
            self.last_error = None
            self._thread = threading.Thread(target=self._serve, args=(httpd,), name="tnt-api", daemon=True)
            self._thread.start()
        log.info("API listening on %s (ui: %s)", self.url, self.static_root())

    def _serve(self, httpd: ApiHTTPServer) -> None:
        # httpd is passed in (not read from self) so a stop() that lands before this
        # thread runs can never make shutdown() wait on a loop that never started.
        try:
            httpd.serve_forever(poll_interval=0.5)
        except Exception:  # noqa: BLE001
            log.exception("API server loop died")
        finally:
            log.debug("API server loop exited")

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            self.stopping = True
            httpd, self.httpd = self.httpd, None
            thread, self._thread = self._thread, None
        try:
            self.hub.close()
        except Exception:  # noqa: BLE001
            log.debug("hub close failed", exc_info=True)
        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception:  # noqa: BLE001
                log.debug("httpd shutdown failed", exc_info=True)
            try:
                httpd.server_close()
            except Exception:  # noqa: BLE001
                log.debug("httpd close failed", exc_info=True)
        if thread is not None and thread.is_alive():
            thread.join(timeout)
        log.info("API server stopped")


__all__ = [
    "ApiHandler",
    "ApiHTTPServer",
    "ApiServer",
    "MAX_BODY_BYTES",
    "describe_port_owner",
    "is_loopback",
    "mime_for",
    "port_busy_message",
    "preflight_port",
]
