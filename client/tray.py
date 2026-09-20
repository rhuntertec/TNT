r"""TNT tray icon + WebView2 window client (``TNT.exe``).

Run from source::

    python client/tray.py [--minimized] [--port 7130] [--url http://127.0.0.1:7130] [--debug]
                          [--remote-debugging-port N]

What it does
------------
* Single instance through the named mutex ``Local\TNT.Client``. A second copy
  finds the existing window (``FindWindowW`` by title), restores + foregrounds it,
  signals the named event ``Local\TNT.Client.Activate`` (so the running copy can
  ``show()`` its window through pywebview even when it was hidden to the tray) and
  exits with code 0.
* Waits for the service: ``GET /api/health`` is polled for up to 45 s. While
  waiting, the window shows an inline "TNT is starting..." page; when the service
  answers the window navigates to the service URL. If it never answers, an inline
  error page explains what to check (services.msc / TNTService, the port, the log
  paths). The page has a *Retry* button and the client keeps probing every 5 s so
  it recovers by itself once the service is up.
* One pywebview window (``edgechromium``, ``private_mode=False`` so the UI's
  ``localStorage`` survives). Closing the window hides it; the app lives in the
  tray until *Quit TNT*.
* pystray icon (dynamite stick from :mod:`client.icons`) in a daemon thread with
  the menu **Open TNT** (default / double-click), **Run speed test now**,
  **Pause/Resume monitoring**, **Diagnostics**, **Quit TNT**. ``/api/status`` is
  polled every 10 s; the icon's status dot and the tooltip
  (``TNT — 3 targets · all green``) follow ``overall_light``.
* JS bridge (``window.pywebview.api``): ``save_file(suggested_name, b64)``,
  ``pick_capture_file()`` (the Packet capture page's "Browse…": an open dialog that answers a path
  and reads nothing - the service opens the file), ``open_path(path)``, ``client_info()``,
  ``set_theme(theme)`` and the small extra ``retry()`` used by the error page. The public :class:`JsBridge` methods are registered one by
  one with ``window.expose`` (:func:`bridge_functions`), never as ``js_api``: pywebview resolves a
  ``js_api`` call name as a dotted attribute path, so a page could have reached
  ``_app.wifi.survey`` or ``_app.quit`` past every method's own check. The window is also a
  single-origin shell: a ``NavigationStarting`` hook cancels every navigation that is not the
  service origin or TNT's own inline page (:func:`navigation_allowed`); a user's click on a link
  to another http(s) site opens the default browser instead.
* Wi-Fi survey (the WiFi tile, :mod:`client.wifi_survey`): runs here, as the signed-in user,
  because Windows 11 24H2 gives BSSID lists only to a user who granted location access, and
  reaches the UI only through the bridge: ``wifi_survey(options)``, ``wifi_scan_now()``,
  ``wifi_clear()``, ``wifi_set_enabled(on)`` (``wifi_survey_enabled`` in client.json, default
  off) and ``open_location_settings()``. They answer only while the window shows the TNT service
  origin (:meth:`ClientApp.showing_service_page`). The session starts the first time the window
  is actually shown (not while TNT.exe waits minimised in the tray), or on a ``wifi_survey``
  call while the window is visible or the WiFi page is active; the scanner thread stops on quit.
* Everything is wrapped in try/except and logged to ``%LOCALAPPDATA%\TNT\client.log``.
* Self-healing window. When Windows signs out, restarts or shuts down, closing the window
  quits the client instead of hiding it (``SM_SHUTTINGDOWN`` in the close handler, plus a
  WinForms ``FormClosing`` hook that sees ``CloseReason.WindowsShutDown``), so TNT never
  holds up a restart. The WebView2 ``ProcessFailed`` event reloads the page after a renderer
  crash and relaunches ``TNT.exe`` when the browser process itself is gone; a watchdog in the
  status loop and in ``show_window`` catches a browser that died without the event (the case
  of a restart that was started and then abandoned): the recorded browser PID is no longer
  running, or the control dropped its ``CoreWebView2``. Relaunches are capped at 3 per 10 min;
  once the cap stops one, the watchdog stays quiet until the oldest relaunch ages out, and
  opening the window from the tray (or a second ``TNT.exe``) relaunches regardless of the cap.
* Window that fits the screen. pywebview takes width/height/min_size/x/y in logical (96-DPI)
  pixels, so the primary monitor's work area is read with plain Win32 calls
  (``SPI_GETWORKAREA`` + the system DPI) before pywebview loads, and :func:`fit_window` sizes the
  window to at most 92 % of it with a minimum size that never exceeds it (1024x700 shrinking to
  800x560, or the whole work area on smaller screens); the window is centred on the work area.
  ``show_window`` moves a window whose monitor went away, or that is larger than the monitor it is
  now on, back into a work area (:func:`keep_on_screen`).
* A .NET runtime that cannot be loaded (pythonnet / clr_loader raising while pywebview imports
  its WinForms backend) gets a plain-language dialog naming .NET Framework 4.7.2 and exit code 4
  (:func:`is_dotnet_load_error`); a missing WebView2 runtime keeps exit code 3.
* WebView2 health: the runtime version (``CoreWebView2.Environment.BrowserVersionString``, else the
  Evergreen registry ``pv``) is logged, and a runtime older than ``MIN_WEBVIEW2_MAJOR`` (the UI's
  CSS needs Chromium 111+) gets one tray notification per version (remembered in client.json). A
  WebView2 that has not initialised 45 s after the GUI started is logged with the likely causes and
  gets one tray notification; the client never relaunches for it.
* ``--remote-debugging-port N`` (diagnostics only, off by default) passes
  ``--remote-debugging-port=N`` to WebView2 through pywebview's ``REMOTE_DEBUGGING_PORT`` setting
  (DevTools protocol on 127.0.0.1) and survives a self-relaunch. Every local program, a standard
  user's included, can drive the window through that port with the signed-in user's rights (on an
  administrator account that includes the saved Wi-Fi passwords the service reveals to the window),
  so the client logs a warning and shows a tray notification each time it starts with it.

Small decisions not spelled out in the contract (documented deviations)
-----------------------------------------------------------------------
* The "starting" page is shown *inside* the main window (there is only one
  window); the window is created immediately and navigates from a background
  thread. pywebview needs the window to exist before anything can be displayed.
* After the 45 s error page the client keeps polling every 5 s and self-heals.
* ``set_theme`` also remembers the theme in ``%LOCALAPPDATA%\TNT\client.json`` so
  the next launch paints the right background before the UI has loaded.
* ``open_path`` returns ``True``/``False``; the bridge has an extra ``retry()``.
* The tooltip carries a second line saying that *Quit* only closes the client
  (the service keeps monitoring) and is capped at 127 characters (Windows limit).
* The WebView2 user-data folder is ``%LOCALAPPDATA%\TNT\webview``.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import html
import json
import logging
import logging.handlers
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

# Allow ``python client/tray.py`` from a source checkout (client + tnt importable).
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if not getattr(sys, "frozen", False) and (_ROOT / "client").is_dir() and str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from client import icons  # noqa: E402
from client import wifi_survey  # noqa: E402

try:  # the client bundles tnt/__init__.py only for the version string
    from tnt import __version__ as CLIENT_VERSION  # noqa: E402
except Exception:  # noqa: BLE001
    CLIENT_VERSION = "1.0.0"

log = logging.getLogger(__name__)

TITLE = "TNT — TEC Network Tool"
MUTEX_NAME = "Local\\TNT.Client"
ACTIVATE_EVENT_NAME = "Local\\TNT.Client.Activate"
DEFAULT_PORT = 7130
HEALTH_WAIT_S = 45.0
STATUS_POLL_S = 10.0
RETRY_AFTER_ERROR_S = 5.0
TOOLTIP_MAX = 127
THEME_BG = {"light": "#FFF7E8", "dark": "#1E1B2E"}
TRAY_ICON_PX = 64
#: Windows truncates balloon text at 255 characters (NOTIFYICONDATAW.szInfo).
NOTIFY_MAX = 255
#: client.json key of the Wi-Fi survey switch (default off).
WIFI_ENABLED_KEY = "wifi_survey_enabled"
#: The Settings page where location access (which the Wi-Fi survey needs) is granted.
LOCATION_SETTINGS_URI = "ms-settings:privacy-location"
#: What the Wi-Fi bridge methods answer to any page that is not the TNT service's own.
WIFI_BRIDGE_REFUSED = "The Wi-Fi survey only answers the TNT dashboard."
WIFI_BRIDGE_FAILED = "The Wi-Fi survey failed; details are in the TNT client log."

# Process exit codes
EXIT_OK = 0
EXIT_FATAL = 1
EXIT_WEBVIEW2_MISSING = 3
EXIT_DOTNET_MISSING = 4

# Win32 constants
ERROR_ALREADY_EXISTS = 183
SW_RESTORE = 9
MB_ICONERROR = 0x10
WAIT_OBJECT_0 = 0


# --------------------------------------------------------------------------- paths & logging
def client_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "TNT"


def client_log_path() -> Path:
    return client_dir() / "client.log"


def client_state_path() -> Path:
    return client_dir() / "client.json"


_logging_configured = False


def setup_client_logging(level: int = logging.INFO) -> Path:
    """Rotating file log in %LOCALAPPDATA%\\TNT\\client.log (idempotent)."""
    global _logging_configured
    path = client_log_path()
    root = logging.getLogger()
    if _logging_configured:
        return path
    root.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(path, maxBytes=1024 * 1024, backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except Exception:  # noqa: BLE001 - no writable log dir: keep going with stderr only
        pass
    if sys.stderr is not None and not getattr(sys, "frozen", False):
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        root.addHandler(sh)
    _logging_configured = True
    return path


def load_state() -> Dict[str, Any]:
    try:
        p = client_state_path()
        if p.exists():
            # utf-8-sig: tolerate a byte-order mark from a hand edit (the relaunch history lives here)
            data = json.loads(p.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict):
                return data
    except Exception:  # noqa: BLE001
        log.exception("could not read client state")
    return {}


def save_state(patch: Dict[str, Any]) -> None:
    try:
        state = load_state()
        state.update(patch)
        p = client_state_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        os.replace(tmp, p)
    except Exception:  # noqa: BLE001
        log.exception("could not save client state")


# --------------------------------------------------------------------------- args
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="TNT", description="TNT - TEC Network Tool client (tray + window)")
    ap.add_argument("--minimized", action="store_true", help="start hidden in the tray")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="service port (default 7130)")
    ap.add_argument("--url", default=None, help="override the service URL (default http://127.0.0.1:PORT)")
    ap.add_argument("--debug", action="store_true", help="enable the WebView2 dev tools and debug logging")
    ap.add_argument("--remote-debugging-port", type=int, default=None, metavar="N",
                    help="diagnostics only: open the WebView2 DevTools protocol on 127.0.0.1:N (1024-65535). "
                         "Any program on this PC can then control the TNT window with your rights, "
                         "including showing saved Wi-Fi passwords; do not leave it on")
    args = ap.parse_args(list(argv) if argv is not None else None)
    if not (1 <= args.port <= 65535):
        ap.error("--port must be 1..65535")
    if args.remote_debugging_port is not None and not (1024 <= args.remote_debugging_port <= 65535):
        ap.error("--remote-debugging-port must be 1024..65535")
    return args


def service_url(args: argparse.Namespace) -> str:
    if args.url:
        return str(args.url).strip().rstrip("/")
    return f"http://127.0.0.1:{args.port}"


def same_origin(url: Any, base: Any) -> bool:
    """True when *url* is an http(s) URL with the scheme, host and port of *base* (the service URL).
    None, the inline pages (pywebview reports no URL for them), other ports and user-info tricks such
    as ``http://127.0.0.1:7130@example.com/`` are all False. Never raises."""
    if not isinstance(url, str) or not isinstance(base, str) or not url or not base:
        return False
    try:
        u, b = urllib.parse.urlsplit(url.strip()), urllib.parse.urlsplit(base.strip())
        scheme = u.scheme.lower()
        if scheme not in ("http", "https") or scheme != b.scheme.lower():
            return False
        if not u.hostname or u.hostname.lower() != (b.hostname or "").lower():
            return False
        default = 443 if scheme == "https" else 80
        return (u.port or default) == (b.port or default)
    except ValueError:              # an out-of-range or malformed port
        return False


def navigation_allowed(uri: Any, base: Any) -> bool:
    """May the TNT window navigate its top frame to *uri*? Pages of the service origin (*base*), a blob: URL
    of that origin, ``about:blank`` and ``data:`` (what WebView2 reports for ``NavigateToString``, the inline
    starting and error pages; Chromium never lets a page itself navigate its top frame to a data: URL).
    Every other page would run with the bridge (this user's files, the Wi-Fi survey) injected. Never raises."""
    if not isinstance(uri, str):
        return False
    text = uri.strip()
    low = text.lower()
    if low == "about:blank" or low.startswith("data:"):
        return True
    if low.startswith("blob:"):
        text = text[5:]
    return same_origin(text, base)


def wifi_enabled_setting(state: Dict[str, Any]) -> bool:
    """The Wi-Fi survey switch from client.json: a JSON boolean, anything else means off. The default is off —
    Wi-Fi scanning stays off until the user turns it on (remembered in client.json)."""
    value = state.get(WIFI_ENABLED_KEY, False) if isinstance(state, dict) else False
    return value if isinstance(value, bool) else False


# --------------------------------------------------------------------------- HTTP client
class ServiceClient:
    """Tiny urllib wrapper; every call has a timeout and never raises."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None,
                timeout: float = 5.0) -> Tuple[int, Any]:
        """Return ``(http_status, parsed_json_or_None)``; status 0 = unreachable."""
        url = self.base_url + path
        data = None
        headers = {"Accept": "application/json", "User-Agent": f"TNT-client/{CLIENT_VERSION}"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - loopback only
                raw = resp.read()
                return resp.status, _parse_json(raw)
        except urllib.error.HTTPError as e:
            try:
                raw = e.read()
            except Exception:  # noqa: BLE001
                raw = b""
            return e.code, _parse_json(raw)
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError, ValueError) as e:
            log.debug("%s %s failed: %s", method, path, e)
            return 0, None
        except Exception:  # noqa: BLE001
            log.exception("%s %s failed unexpectedly", method, path)
            return 0, None

    def get(self, path: str, timeout: float = 5.0) -> Tuple[int, Any]:
        return self.request("GET", path, timeout=timeout)

    def post(self, path: str, body: Optional[Dict[str, Any]] = None, timeout: float = 10.0) -> Tuple[int, Any]:
        return self.request("POST", path, body=body if body is not None else {}, timeout=timeout)

    def health(self, timeout: float = 2.0) -> bool:
        code, data = self.get("/api/health", timeout=timeout)
        return code == 200 and (not isinstance(data, dict) or data.get("ok", True) is not False)

    def status(self, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        code, data = self.get("/api/status", timeout=timeout)
        return data if code == 200 and isinstance(data, dict) else None


def _parse_json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- status text
def light_summary(status: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """Return ``(light, short text)`` for the tooltip, e.g. ``("green", "all green")``."""
    if not isinstance(status, dict):
        return "grey", "service unreachable"
    targets = status.get("targets") or []
    n = len(targets) if isinstance(targets, list) else 0
    light = str(status.get("overall_light") or "grey").lower()
    if light not in icons.LIGHT_COLOURS:
        light = "grey"
    if status.get("paused"):
        return "grey", "monitoring paused"
    if n == 0:
        return "grey", "no targets"
    if light == "green":
        return light, "all green"
    if light == "red":
        total = (status.get("outages") or {}).get("total_active") if isinstance(status.get("outages"), dict) else None
        if isinstance(total, dict):
            if total.get("kind") == "total_internet":
                return light, "internet outage"
            if total.get("kind") == "total_local":
                return light, "local network outage"
        reds = sum(1 for t in targets if isinstance(t, dict) and t.get("light") == "red")
        return light, f"{reds or 1} target{'s' if (reds or 1) != 1 else ''} down"
    if light == "yellow":
        ys = sum(1 for t in targets if isinstance(t, dict) and t.get("light") == "yellow")
        return light, f"{ys or 1} target{'s' if (ys or 1) != 1 else ''} degraded"
    return "grey", "no data yet"


def tooltip_text(status: Optional[Dict[str, Any]]) -> str:
    targets = status.get("targets") if isinstance(status, dict) else None
    n = len(targets) if isinstance(targets, list) else 0
    _, text = light_summary(status)
    if status is None:
        first = f"TNT — {text}"
    else:
        first = f"TNT — {n} target{'s' if n != 1 else ''} · {text}"
    tip = first + "\nQuit only closes this window; monitoring keeps running."
    return tip[:TOOLTIP_MAX]


# --------------------------------------------------------------------------- inline pages
_PAGE_CSS = """
:root{--bg:#FFF7E8;--paper:#FFFFFF;--paper-2:#FFF1D6;--ink:#2B2438;--ink-soft:#6B6480;--red:#FF5C5C;
--yellow:#FFD166;--green:#6BCB77;--blue:#6FA8FF;--orange:#FFA45C;--shadow:#2B2438;
--font:"Nunito","Segoe UI Variable Display","Segoe UI",system-ui,sans-serif}
[data-theme="dark"]{--bg:#1E1B2E;--paper:#2A2640;--paper-2:#332E4D;--ink:#F3EEFF;--ink-soft:#B8B0CC;
--red:#FF6B6B;--green:#7ED987;--blue:#7DB2FF;--orange:#FFB070;--shadow:#0F0D1A}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--ink);font-family:var(--font);font-size:16px;line-height:1.4;
display:flex;align-items:center;justify-content:center;padding:24px;user-select:text}
.card{background:var(--paper);border:3px solid var(--ink);border-radius:22px;box-shadow:6px 6px 0 var(--shadow);
padding:32px 36px;max-width:640px;width:100%}
h1{font-size:28px;font-weight:800;letter-spacing:-0.01em;margin:0 0 8px;display:flex;align-items:center;gap:12px}
p{margin:8px 0}
.soft{color:var(--ink-soft)}
code{background:var(--paper-2);border:2px solid var(--ink);border-radius:8px;padding:2px 8px;font-size:14px;
font-family:Consolas,"Cascadia Mono",monospace;user-select:text}
ul{padding-left:22px;margin:10px 0}
li{margin:6px 0}
.badge{display:inline-block;border:2px solid var(--ink);border-radius:999px;padding:2px 12px;font-size:12px;
font-weight:800;letter-spacing:.08em;text-transform:uppercase;background:var(--paper-2)}
.badge.red{background:var(--red)}
.fuse{position:relative;height:16px;border:3px solid var(--ink);border-radius:999px;background:var(--paper-2);
overflow:hidden;margin:20px 0 8px}
.fuse::after{content:"";position:absolute;top:0;bottom:0;left:-40%;width:40%;background:var(--orange);
border-radius:999px;animation:burn 1.6s linear infinite}
@keyframes burn{from{left:-40%}to{left:100%}}
.spark{color:var(--orange);font-size:22px;animation:blink 2s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
button{font:inherit;font-weight:800;height:44px;padding:0 22px;border:3px solid var(--ink);border-radius:999px;
background:var(--orange);color:#2B2438;box-shadow:4px 4px 0 var(--shadow);cursor:pointer;margin-top:16px}
button:active{transform:translate(2px,2px);box-shadow:1px 1px 0 var(--shadow)}
@media (prefers-reduced-motion:reduce){.fuse::after,.spark{animation:none}}
"""


def ssh_prompt_script(host: str) -> str:
    """PowerShell for the ssh window: ask for a user name, then run ``ssh [user@]host``.

    Single quotes only (the host is validated to letters, digits and ``.:-_[]`` before it
    gets here) so nothing in it can break out of the string or be expanded.
    """
    return (
        f"$h = '{host}'; "
        "Write-Host ('TNT: ssh to ' + $h) -ForegroundColor Green; "
        "$u = Read-Host 'User name (leave blank for the default)'; "
        "if ($u) { $u = $u.Trim() }; "
        "if ($u) { Write-Host ('ssh ' + $u + '@' + $h) -ForegroundColor DarkGray; ssh ($u + '@' + $h) } "
        "else { Write-Host ('ssh ' + $h) -ForegroundColor DarkGray; ssh $h }"
    )


def _logo_svg(size: int = 40) -> str:
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 64 64" aria-hidden="true">'
            '<g transform="rotate(-22 32 32)">'
            '<path d="M30 20 C 26 12, 34 8, 42 10" fill="none" stroke="#2B2438" stroke-width="4" stroke-linecap="round"/>'
            '<rect x="19" y="18" width="22" height="40" rx="5" fill="#FF5C5C" stroke="#2B2438" stroke-width="3.5"/>'
            '<rect x="17" y="32" width="26" height="12" rx="2" fill="#FFF7E8" stroke="#2B2438" stroke-width="3"/>'
            '<path d="M44 4 L46.5 9.5 L52 12 L46.5 14.5 L44 20 L41.5 14.5 L36 12 L41.5 9.5 Z" fill="#FFA45C" '
            'stroke="#2B2438" stroke-width="2"/></g></svg>')


def starting_html(url: str, theme: str = "light") -> str:
    """Inline 'TNT is starting...' page shown while /api/health is polled."""
    theme = theme if theme in THEME_BG else "light"
    return f"""<!doctype html><html lang="en" data-theme="{theme}"><head><meta charset="utf-8">
<title>TNT is starting…</title><style>{_PAGE_CSS}</style></head><body>
<div class="card">
<h1>{_logo_svg()} TNT is starting… <span class="spark">✦</span></h1>
<p class="soft">Waiting for the <strong>TNTService</strong> background service to answer at
<code>{html.escape(url)}</code>. This normally takes a few seconds after boot.</p>
<div class="fuse"></div>
<p class="soft" style="font-size:14px">The window will switch to the TNT dashboard automatically.</p>
</div></body></html>"""


def error_html(url: str, client_log: Path, theme: str = "light") -> str:
    """Inline page shown when the service never answered within HEALTH_WAIT_S."""
    theme = theme if theme in THEME_BG else "light"
    port = url.rsplit(":", 1)[-1].split("/")[0] if ":" in url else "7130"
    service_log = r"%ProgramData%\TNT\logs\tnt-service.log"
    return f"""<!doctype html><html lang="en" data-theme="{theme}"><head><meta charset="utf-8">
<title>Cannot reach the TNT service</title><style>{_PAGE_CSS}</style></head><body>
<div class="card">
<h1>{_logo_svg()} Can't reach the TNT service</h1>
<p><span class="badge red">service unreachable</span></p>
<p>Nothing answered at <code>{html.escape(url)}</code>. The dashboard is served by the
<strong>TNTService</strong> Windows service, which appears to be stopped or is listening on a different port.</p>
<p><strong>Things to check</strong></p>
<ul>
<li>Open <code>services.msc</code> and make sure <strong>TNT — TEC Network Tool Service</strong>
(<code>TNTService</code>) is <em>Running</em> (Startup type <em>Automatic</em>). Start it if it is stopped.</li>
<li>The service must listen on port <code>{html.escape(port)}</code>. If another program uses that port, the service log
says so: <code>{service_log}</code>.</li>
<li>Client log: <code>{html.escape(str(client_log))}</code>.</li>
<li>Reinstalling TNT re-registers the service.</li>
</ul>
<p class="soft" style="font-size:14px">This page checks again automatically every {int(RETRY_AFTER_ERROR_S)} seconds.</p>
<button onclick="if(window.pywebview&&window.pywebview.api){{window.pywebview.api.retry()}}">Retry now</button>
</div></body></html>"""


# --------------------------------------------------------------------------- Win32 helpers
def _kernel32() -> Any:
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _user32() -> Any:
    return ctypes.WinDLL("user32", use_last_error=True)


_mutex_handle: Optional[int] = None
_activate_event_handle: Optional[int] = None


def acquire_single_instance(name: str = MUTEX_NAME) -> bool:
    """Create the named mutex; False if another client already owns it."""
    global _mutex_handle
    if os.name != "nt":
        return True
    try:
        k = _kernel32()
        k.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        k.CreateMutexW.restype = ctypes.c_void_p
        handle = k.CreateMutexW(None, 0, name)
        err = ctypes.get_last_error()
        if not handle:
            log.warning("CreateMutexW failed (error %s); continuing without single-instance guard", err)
            return True
        _mutex_handle = handle
        if err == ERROR_ALREADY_EXISTS:
            return False
        return True
    except Exception:  # noqa: BLE001
        log.exception("single-instance check failed; continuing")
        return True


def release_single_instance() -> None:
    global _mutex_handle, _activate_event_handle
    try:
        k = _kernel32()
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        for h in (_mutex_handle, _activate_event_handle):
            if h:
                k.CloseHandle(h)
    except Exception:  # noqa: BLE001
        pass
    _mutex_handle = None
    _activate_event_handle = None


def _create_activate_event() -> Optional[int]:
    """Named auto-reset event the *primary* instance waits on."""
    global _activate_event_handle
    try:
        k = _kernel32()
        k.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
        k.CreateEventW.restype = ctypes.c_void_p
        h = k.CreateEventW(None, 0, 0, ACTIVATE_EVENT_NAME)
        _activate_event_handle = h or None
        return _activate_event_handle
    except Exception:  # noqa: BLE001
        log.exception("CreateEventW failed")
        return None


def _signal_activate_event() -> bool:
    try:
        k = _kernel32()
        k.OpenEventW.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_wchar_p]
        k.OpenEventW.restype = ctypes.c_void_p
        k.SetEvent.argtypes = [ctypes.c_void_p]
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        EVENT_MODIFY_STATE = 0x0002
        h = k.OpenEventW(EVENT_MODIFY_STATE, 0, ACTIVATE_EVENT_NAME)
        if not h:
            return False
        try:
            return bool(k.SetEvent(h))
        finally:
            k.CloseHandle(h)
    except Exception:  # noqa: BLE001
        log.exception("could not signal the running client")
        return False


def find_window(title: str = TITLE) -> int:
    try:
        u = _user32()
        u.FindWindowW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
        u.FindWindowW.restype = ctypes.c_void_p
        return int(u.FindWindowW(None, title) or 0)
    except Exception:  # noqa: BLE001
        log.exception("FindWindowW failed")
        return 0


def activate_existing_window(title: str = TITLE) -> bool:
    """Restore + foreground the window of an already running client."""
    try:
        hwnd = find_window(title)
        if not hwnd:
            return False
        u = _user32()
        u.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
        u.SetForegroundWindow.argtypes = [ctypes.c_void_p]
        u.ShowWindow(hwnd, SW_RESTORE)
        u.SetForegroundWindow(hwnd)
        return True
    except Exception:  # noqa: BLE001
        log.exception("could not activate the existing window")
        return False


def _is_iconic(hwnd: int) -> bool:
    try:
        u = _user32()
        u.IsIconic.argtypes = [ctypes.c_void_p]
        return bool(u.IsIconic(hwnd))
    except Exception:  # noqa: BLE001
        return False


def _fatal_dialog(message: str) -> None:
    try:
        u = _user32()
        u.MessageBoxW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        u.MessageBoxW(None, message, TITLE, MB_ICONERROR)
    except Exception:  # noqa: BLE001
        pass


_WEBVIEW2_CLIENT_ID = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
#: The UI's CSS uses color-mix(), which Chromium supports from version 111. A WebView2 runtime older
#: than this (an offline PC that never updated) draws the dashboard with colours missing.
MIN_WEBVIEW2_MAJOR = 111


def _webview2_registry_keys(winreg: Any) -> Tuple[Tuple[Any, str], ...]:
    return (
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_CLIENT_ID}"),
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_CLIENT_ID}"),
        (winreg.HKEY_CURRENT_USER, rf"Software\Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_CLIENT_ID}"),
    )


def webview2_major(version_text: Any) -> Optional[int]:
    """Major version of a WebView2 runtime version string: ``"152.0.4191.66"`` -> 152, also with a
    channel suffix (``"120.0.2210.91 beta"``). None for a missing or unparsable version and for
    ``0.0.0.0``, which the Evergreen registry uses for "not installed"."""
    if not isinstance(version_text, str):
        return None
    m = re.match(r"\s*(\d{1,6})(?:\.\d+)*(?:\s|$)", version_text)
    if not m:
        return None
    major = int(m.group(1))
    return major if major > 0 else None


def needs_webview2_update(version_text: Any, minimum: Any = MIN_WEBVIEW2_MAJOR) -> bool:
    """True only when the runtime version is known and its major version is below *minimum*
    (an unknown version never triggers the warning)."""
    major = webview2_major(version_text)
    try:
        return major is not None and major < int(minimum)
    except (TypeError, ValueError):
        return False


def webview2_outdated_message(version: str) -> str:
    return (f"The Microsoft Edge WebView2 Runtime on this PC is out of date (version {version}). "
            "TNT may display incorrectly until Windows updates it or you install the latest runtime.")


#: Tray text when the WebView2 never initialised (kept under NOTIFY_MAX).
WEBVIEW_INIT_FAILED_MESSAGE = ("The TNT window could not start its web view. Reinstall the Microsoft Edge "
                               "WebView2 Runtime from Microsoft's website, then restart TNT. Monitoring keeps "
                               "running in the TNT service.")
#: Tray notification while --remote-debugging-port is on (shown at every start with it).
REMOTE_DEBUGGING_WARNING = ("Remote debugging is on (port {port}): any program on this PC can control the TNT "
                            "window, including showing saved Wi-Fi passwords. Quit TNT and start it without "
                            "--remote-debugging-port when you are done.")


def webview2_registry_version() -> Optional[str]:
    """Version of the Evergreen WebView2 runtime from the registry (the highest ``pv``), or None."""
    try:
        import winreg
    except ImportError:
        return None
    best: Optional[str] = None
    best_major = 0
    for root, sub in _webview2_registry_keys(winreg):
        try:
            with winreg.OpenKey(root, sub) as k:
                pv, _ = winreg.QueryValueEx(k, "pv")
        except OSError:
            continue
        text = str(pv).strip()
        major = webview2_major(text)
        if major is not None and major > best_major:
            best, best_major = text, major
    return best


#: Phrases pythonnet 3.1 (``pythonnet/__init__.py``) and clr_loader 0.3 (``__init__.py``,
#: ``ffi/__init__.py``, ``util/find.py``) put in the exception when no .NET runtime can be loaded,
#: matched case-insensitively with whitespace collapsed (their messages span several lines). When
#: both runtimes fail, pywebview's ``import clr`` retry raises
#: ``RuntimeError('Failed to create a .NET runtime (coreclr) using the parameters {}.')`` caused by
#: ``RuntimeError('Can not determine dotnet root')`` in the context of
#: ``RuntimeError('Failed to create a default .NET runtime, which would have been "netfx" ...')``.
DOTNET_LOAD_ERROR_PHRASES = (
    "failed to create a default .net runtime",
    "failed to create a .net runtime",
    "failed to resolve python.runtime.loader",
    "failed to initialize python.runtime.dll",
    "no valid runtime selected",
    "could not find a suitable hostfxr library",
    "can not determine dotnet root",
    "clrloader.dll",
    "built by a runtime newer than the currently loaded runtime",
)


def is_dotnet_load_error(exc: Any) -> bool:
    """True when *exc* (or an exception in its ``__cause__`` / ``__context__`` chain) says the .NET
    runtime could not be loaded: a clr_loader ``ClrError`` (hosting API HRESULT) or one of
    :data:`DOTNET_LOAD_ERROR_PHRASES`. Never raises."""
    pending = [exc]
    seen: set = set()
    while pending and len(seen) < 32:
        e = pending.pop(0)
        if not isinstance(e, BaseException) or id(e) in seen:
            continue
        seen.add(id(e))
        cls = type(e)
        if cls.__name__ == "ClrError" and str(getattr(cls, "__module__", "")).startswith("clr_loader"):
            return True
        try:
            text = " ".join(str(e).split()).lower()
        except Exception:  # noqa: BLE001 - a hostile __str__
            text = ""
        if any(phrase in text for phrase in DOTNET_LOAD_ERROR_PHRASES):
            return True
        pending.extend(x for x in (e.__cause__, e.__context__) if x is not None)
    return False


def dotnet_missing_message(log_path: Any) -> str:
    """Dialog text when the .NET runtime cannot be loaded (plain language, no traceback)."""
    return ("TNT could not open its window because Microsoft .NET Framework could not be loaded on this PC.\n\n"
            "The TNT window needs .NET Framework 4.7.2 or later, which is built into Windows 10 version 1809 "
            "and later. Install the latest Windows updates, then start TNT again. If .NET Framework is already "
            "installed, security software may be blocking TNT from using it.\n\n"
            "Monitoring keeps running in the TNT service.\n\n"
            f"Details are in the log: {log_path}")


def webview2_installed() -> bool:
    """True when the Evergreen WebView2 runtime (or a fixed-version one) is registered.

    Same registry keys the installer checks; a missing/unreadable registry is treated as
    "installed" so an odd machine can still try (pywebview then reports its own error).
    """
    try:
        import winreg
    except ImportError:
        return True
    keys = _webview2_registry_keys(winreg)
    seen_any = False
    for root, sub in keys:
        try:
            with winreg.OpenKey(root, sub) as k:
                seen_any = True
                pv, _ = winreg.QueryValueEx(k, "pv")
                if str(pv).strip() not in ("", "0.0.0.0"):
                    return True
        except OSError:
            continue
    if not seen_any and os.environ.get("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER"):
        return True  # fixed-version distribution
    return False


def icon_file() -> Path:
    """Path of tnt.ico: bundled next to the exe, the repo's assets/, or generated."""
    candidates = []
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        candidates += [base / "assets" / "tnt.ico", Path(sys.executable).parent / "assets" / "tnt.ico"]
    candidates.append(_ROOT / "assets" / "tnt.ico")
    for c in candidates:
        if c.is_file():
            return c
    gen = client_dir() / "tnt.ico"
    try:
        if not gen.is_file():
            icons.make_ico(gen)
    except Exception:  # noqa: BLE001
        log.exception("could not generate %s", gen)
    return gen


# --------------------------------------------------------------------------- window geometry
# pywebview 6.2.1's WinForms backend takes width/height/min_size/x/y in logical (96-DPI) pixels: the
# BrowserForm multiplies them by GetDpiForWindow(hwnd) / 96 (platforms/winforms.py:208-227) after
# create_window() made the process system-DPI aware with SetProcessDPIAware() (winforms.py:820). A
# minimum size larger than the screen is applied as is (WM_GETMINMAXINFO), so the window hangs off the
# screen and cannot be shrunk. Without x/y the form is not centred either: its handle is created
# (winforms.py:204) before StartPosition=CenterScreen is set (winforms.py:229), and WinForms only
# centres at handle creation, so Windows' default position is used. So the client reads the primary
# monitor's work area in logical pixels before creating the window, fits the size to it and centres it.

#: Design geometry in logical px (the window's outer size, frame included).
WINDOW_SIZE = (1280, 860)
WINDOW_MIN_SIZE = (1024, 700)
#: The smallest minimum size the UI stays usable at; below it the minimum is the work area itself.
WINDOW_FLOOR = (800, 560)
#: The window starts at most this fraction of the work area in each direction.
WINDOW_MARGIN = 0.92
SPI_GETWORKAREA = 0x0030
LOGPIXELSY = 90
DPI_AWARENESS_CONTEXT_SYSTEM_AWARE = -2
#: keep_on_screen: a window may be this much (logical px) larger than its work area without being
#: resized; snapped windows include Windows' invisible 7-8 px resize borders.
SCREEN_TOLERANCE = 16
#: keep_on_screen: at least this much of the top CAPTION_PX band must lie on a work area.
CAPTION_PX = 32
CAPTION_VISIBLE_PX = 100


class _RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long), ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


def _as_int(value: Any) -> Optional[int]:
    """``int(value)`` for a real number; None for bools, NaN, infinity and anything else."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return int(value)
    except (ValueError, OverflowError):
        return None


def _valid_rect(rect: Any) -> Optional[Tuple[int, int, int, int]]:
    """``(left, top, width, height)`` as ints with a positive size, else None."""
    try:
        vals = [_as_int(v) for v in rect]
    except TypeError:
        return None
    if len(vals) != 4 or any(v is None for v in vals) or vals[2] <= 0 or vals[3] <= 0:
        return None
    return vals[0], vals[1], vals[2], vals[3]


def _fit_axis(work: int, want: int, minimum: int, floor: int, margin: float) -> Tuple[int, int]:
    floor = max(1, min(floor, minimum))
    cap = max(1, int(work * margin))
    least = work if work <= floor else max(floor, min(minimum, cap))
    return max(least, min(want, cap)), least


def fit_window(work_w: Any, work_h: Any, want: Sequence[int] = WINDOW_SIZE, minimum: Sequence[int] = WINDOW_MIN_SIZE,
               margin: float = WINDOW_MARGIN, floor: Sequence[int] = WINDOW_FLOOR) -> Tuple[int, int, int, int]:
    """Window size and minimum size ``(w, h, min_w, min_h)`` for a work area of *work_w* x *work_h*.

    Per direction: the window starts at *want* but never larger than *margin* x the work area; the
    minimum size is *minimum* while that fits in the same share of the work area, otherwise it
    shrinks with the work area down to *floor*, and on a work area smaller than *floor* it is the
    work area itself; the size is never below the minimum. When the floor exceeds the margin the
    floor wins, so the window never exceeds the work area and can always be shrunk to fit it. A
    missing or degenerate work area (0, negative, not a number) returns *want* and *minimum*."""
    fallback = (int(want[0]), int(want[1]), int(minimum[0]), int(minimum[1]))
    ww, wh = _as_int(work_w), _as_int(work_h)
    if ww is None or wh is None or ww <= 0 or wh <= 0:
        return fallback
    try:
        m = float(margin)
    except (TypeError, ValueError):
        m = WINDOW_MARGIN
    if not 0.0 < m <= 1.0:      # also NaN
        m = WINDOW_MARGIN
    w, min_w = _fit_axis(ww, int(want[0]), int(minimum[0]), int(floor[0]), m)
    h, min_h = _fit_axis(wh, int(want[1]), int(minimum[1]), int(floor[1]), m)
    return w, h, min_w, min_h


def center_in(work: Sequence[int], w: int, h: int) -> Tuple[int, int]:
    """Top-left ``(x, y)`` that centres a *w* x *h* window on *work* ``(left, top, width, height)``
    (never left of / above the work area)."""
    left, top, ww, wh = (int(v) for v in work)
    return left + max(0, (ww - int(w)) // 2), top + max(0, (wh - int(h)) // 2)


def window_geometry(work: Any) -> Dict[str, Any]:
    """``webview.create_window`` geometry for the primary work area ``(left, top, width, height)`` in
    logical px: fitted ``width``/``height``/``min_size`` and a centred ``x``/``y``. Without a usable
    work area: the design size and no ``x``/``y`` (Windows places the window, as before)."""
    rect = _valid_rect(work) if work is not None else None
    if rect is None:
        return {"width": WINDOW_SIZE[0], "height": WINDOW_SIZE[1], "min_size": WINDOW_MIN_SIZE}
    w, h, min_w, min_h = fit_window(rect[2], rect[3])
    x, y = center_in(rect, w, h)
    return {"width": w, "height": h, "min_size": (min_w, min_h), "x": x, "y": y}


def logical_rect(left: Any, top: Any, right: Any, bottom: Any, dpi: Any) -> Optional[Tuple[int, int, int, int]]:
    """A device rectangle (edges, as ``SystemParametersInfo`` returns it) -> ``(left, top, width,
    height)`` in logical px for *dpi* (96 = 100 %; implausible values count as 96). Sizes round down
    so pywebview's ``int(size * scale)`` never exceeds the device size. None for an empty rectangle."""
    vals = [_as_int(v) for v in (left, top, right, bottom)]
    if any(v is None for v in vals):
        return None
    l, t, r, b = vals  # noqa: E741
    d = _as_int(dpi)
    scale = d / 96.0 if d is not None and 48 <= d <= 960 else 1.0
    if r - l <= 0 or b - t <= 0:
        return None
    return int(round(l / scale)), int(round(t / scale)), int((r - l) / scale), int((b - t) / scale)


def system_dpi() -> int:
    """DPI the calling thread sees for the system (96 when it cannot be read).

    Before pywebview makes the process DPI aware this is 96 and ``SPI_GETWORKAREA`` is already
    scaled to logical px; once the process is system aware it is the real system DPI and the work
    area is in device px. So work area / (dpi / 96) is logical px either way, in the unit pywebview
    uses (GetDpiForWindow of a system-aware process is the system DPI)."""
    if os.name != "nt":
        return 96
    try:
        u = _user32()
        fn = getattr(u, "GetDpiForSystem", None)      # Windows 10 1607+
        if fn is not None:
            fn.restype = ctypes.c_uint
            dpi = int(fn())
            if dpi > 0:
                return dpi
        g = ctypes.WinDLL("gdi32")
        u.GetDC.argtypes = [ctypes.c_void_p]
        u.GetDC.restype = ctypes.c_void_p
        u.ReleaseDC.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        g.GetDeviceCaps.argtypes = [ctypes.c_void_p, ctypes.c_int]
        g.GetDeviceCaps.restype = ctypes.c_int
        hdc = u.GetDC(None)
        if hdc:
            try:
                dpi = int(g.GetDeviceCaps(hdc, LOGPIXELSY))
                if dpi > 0:
                    return dpi
            finally:
                u.ReleaseDC(None, hdc)
    except Exception:  # noqa: BLE001
        log.debug("could not read the system DPI", exc_info=True)
    return 96


def primary_work_area() -> Optional[Tuple[int, int, int, int]]:
    """The primary monitor's work area (screen minus taskbar) as ``(left, top, width, height)`` in
    logical px, read with plain Win32 calls so nothing .NET loads before pywebview. None (and the
    design geometry) when it cannot be read.

    The calling thread is switched to the system-DPI-aware context for the read (and back), the
    mode pywebview's SetProcessDPIAware() puts the process in, so the device rectangle and the DPI
    are not virtualised and device px / (DPI / 96) is exactly pywebview's logical unit. Without
    SetThreadDpiAwarenessContext (before Windows 10 1607) the pair is read as is, which is
    consistent too (see :func:`system_dpi`)."""
    if os.name != "nt":
        return None
    set_context: Any = None
    previous = None
    try:
        u = _user32()
        set_context = getattr(u, "SetThreadDpiAwarenessContext", None)
        if set_context is not None:
            set_context.argtypes = [ctypes.c_void_p]
            set_context.restype = ctypes.c_void_p
            previous = set_context(ctypes.c_void_p(DPI_AWARENESS_CONTEXT_SYSTEM_AWARE))
        u.SystemParametersInfoW.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]
        u.SystemParametersInfoW.restype = ctypes.c_int
        rect = _RECT()
        if not u.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(rect), 0):
            log.warning("SystemParametersInfoW(SPI_GETWORKAREA) failed (error %s)", ctypes.get_last_error())
            return None
        dpi = system_dpi()
        area = logical_rect(rect.left, rect.top, rect.right, rect.bottom, dpi)
        log.info("primary work area (%d,%d)-(%d,%d) at %d DPI (thread DPI context %s) -> %s logical px",
                 rect.left, rect.top, rect.right, rect.bottom, dpi,
                 "system aware" if previous else "unchanged", area)
        return area
    except Exception:  # noqa: BLE001
        log.exception("could not read the primary work area")
        return None
    finally:
        if previous:
            try:
                set_context(ctypes.c_void_p(previous))
            except Exception:  # noqa: BLE001
                log.exception("could not restore the thread DPI awareness context")


def _overlap(a0: int, a1: int, b0: int, b1: int) -> int:
    return max(0, min(a1, b1) - max(a0, b0))


def keep_on_screen(bounds: Any, work_areas: Any, min_size: Any, tolerance: int = SCREEN_TOLERANCE,
                   caption: int = CAPTION_PX, visible: int = CAPTION_VISIBLE_PX
                   ) -> Optional[Tuple[Tuple[int, int, int, int], Tuple[int, int]]]:
    """Where to put a window that is shown again after the monitor setup may have changed.

    *bounds* ``(x, y, w, h)``, *work_areas* ``[(left, top, width, height), ...]`` and *min_size*
    share one unit (logical px). Returns ``((x, y, w, h), (min_w, min_h))`` when the window has to
    change, else None. It changes when it is larger than the work area it is mostly on (by more than
    *tolerance*) or when less than *visible* px of its title-bar band lies on any work area (it
    could not be dragged back). It is then shrunk to that work area as :func:`fit_window` would
    (the minimum size shrinking with it) and moved the shortest distance into it."""
    b = _valid_rect(bounds)
    areas = [r for r in (_valid_rect(a) for a in (work_areas or ())) if r is not None]
    if b is None or not areas:
        return None
    try:
        min_w0, min_h0 = max(1, int(min_size[0])), max(1, int(min_size[1]))
    except (TypeError, ValueError, IndexError):
        min_w0, min_h0 = 1, 1
    x, y, w, h = b

    def shared(a: Tuple[int, int, int, int]) -> int:
        return _overlap(x, x + w, a[0], a[0] + a[2]) * _overlap(y, y + h, a[1], a[1] + a[3])

    target = max(areas, key=shared)
    if shared(target) == 0:     # entirely off every work area: the nearest one
        cx, cy = x + w / 2.0, y + h / 2.0
        target = min(areas, key=lambda a: (a[0] + a[2] / 2.0 - cx) ** 2 + (a[1] + a[3] / 2.0 - cy) ** 2)
    left, top, aw, ah = target
    band = min(caption, h)
    title_visible = sum(_overlap(x, x + w, a[0], a[0] + a[2]) for a in areas
                        if _overlap(y, y + band, a[1], a[1] + a[3]) > 0)
    too_wide, too_tall = w > aw + tolerance, h > ah + tolerance
    if not (too_wide or too_tall) and title_visible >= min(visible, w):
        return None
    fit_w, fit_h, fit_min_w, fit_min_h = fit_window(aw, ah, want=(w, h), minimum=(min_w0, min_h0))
    nw, new_min_w = (fit_w, fit_min_w) if too_wide else (w, min_w0)
    nh, new_min_h = (fit_h, fit_min_h) if too_tall else (h, min_h0)
    nx = min(max(x, left), left + aw - nw) if nw <= aw else left + (aw - nw) // 2
    ny = min(max(y, top), top + ah - nh) if nh <= ah else top
    if (nx, ny, nw, nh) == (x, y, w, h) and (new_min_w, new_min_h) == (min_w0, min_h0):
        return None
    return (nx, ny, nw, nh), (new_min_w, new_min_h)


def dir_writable(path: Any) -> bool:
    """True when a file can be created in *path* (created if missing). Never raises."""
    try:
        p = Path(path)
        p.mkdir(parents=True, exist_ok=True)
        probe = p / f".tnt-write-test-{os.getpid()}"
        probe.write_bytes(b"ok")
        probe.unlink()
        return True
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- self-healing window
# Windows can tear the embedded browser down underneath a TNT.exe that keeps running: a
# restart or sign-out that is started and then abandoned ends the WebView2 child processes,
# a display-driver reset can take the browser process with it, and an Evergreen WebView2
# update replaces the runtime. Each time the WinForms host survives and shows a blank white
# window, and every later "Open TNT" just brings that dead window to the front. So the
# client (1) quits instead of hiding to the tray when Windows ends the session, which also
# stops it from holding up a restart, and (2) watches its WebView2: a crashed renderer is
# reloaded, and a dead browser process makes TNT.exe start a fresh copy of itself and exit.

SM_SHUTTINGDOWN = 0x2000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_ACCESS_DENIED = 5
STILL_ACTIVE = 259
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
#: A detached console program gets a console window of its own; this is the flag that gives it
#: none at all, which is what a background helper wants.
CREATE_NO_WINDOW = 0x08000000
#: At most RELAUNCH_MAX self-relaunches per RELAUNCH_WINDOW_S (kept in client.json across
#: the relaunched processes), so a browser that dies on every start cannot loop forever.
RELAUNCH_WINDOW_S = 600.0
RELAUNCH_MAX = 3
WEBVIEW_CHECK_TIMEOUT_S = 5.0
#: If tearing down the dead WebView2 control hangs WinForms, the old process exits anyway.
EXIT_FALLBACK_S = 8.0
#: A WebView2 that has not initialised this long after the GUI loop started gets logged and one tray
#: notification (it normally takes well under a second).
WEBVIEW_INIT_TIMEOUT_S = 45.0

#: CoreWebView2ProcessFailedKind values -> readable names for the log.
PROCESS_FAILED_KINDS = {
    0: "browser process exited", 1: "render process exited", 2: "render process unresponsive",
    3: "frame render process exited", 4: "utility process exited", 5: "sandbox helper process exited",
    6: "GPU process exited", 7: "PPAPI plugin process exited", 8: "PPAPI broker process exited",
    9: "unknown process exited",
}


def session_ending() -> bool:
    """True while Windows is signing out, restarting or shutting down this session."""
    if os.name != "nt":
        return False
    try:
        u = _user32()
        u.GetSystemMetrics.argtypes = [ctypes.c_int]
        u.GetSystemMetrics.restype = ctypes.c_int
        return u.GetSystemMetrics(SM_SHUTTINGDOWN) != 0
    except Exception:  # noqa: BLE001
        return False


def process_alive(pid: Any) -> bool:
    """True when process *pid* is still running (a process we may not query counts as alive)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    try:
        k = _kernel32()
        k.OpenProcess.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]
        k.OpenProcess.restype = ctypes.c_void_p
        k.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
        k.GetExitCodeProcess.restype = ctypes.c_int
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
        if not h:
            return ctypes.get_last_error() == ERROR_ACCESS_DENIED
        try:
            code = ctypes.c_uint(0)
            if not k.GetExitCodeProcess(h, ctypes.byref(code)):
                return True
            return code.value == STILL_ACTIVE
        finally:
            k.CloseHandle(h)
    except Exception:  # noqa: BLE001
        return True      # cannot tell: never relaunch on a guess


def failure_action(kind: Any) -> str:
    """What a CoreWebView2 ``ProcessFailed`` event calls for: ``relaunch``, ``reload`` or ``ignore``.

    The browser process is the whole WebView2 instance, so the control cannot recover and the
    client restarts itself. A renderer that died or hung takes only the page: reload it. GPU,
    utility and helper processes are restarted by WebView2 on its own."""
    try:
        k = int(kind)
    except (TypeError, ValueError):
        return "ignore"
    if k == 0:
        return "relaunch"
    if k in (1, 2, 3):
        return "reload"
    return "ignore"


def relaunch_allowed(history: Sequence[Any], now: float, window_s: float = RELAUNCH_WINDOW_S,
                     max_count: int = RELAUNCH_MAX) -> bool:
    """True when fewer than *max_count* relaunches happened in the last *window_s* seconds."""
    recent = [t for t in history if isinstance(t, (int, float)) and not isinstance(t, bool) and 0 <= now - t < window_s]
    return len(recent) < max_count


def relaunch_history(state: Optional[Dict[str, Any]] = None) -> list:
    """The relaunch timestamps kept in client.json (junk dropped)."""
    raw = (load_state() if state is None else state).get("relaunches")
    if not isinstance(raw, list):
        return []
    return [t for t in raw if isinstance(t, (int, float)) and not isinstance(t, bool)]


def relaunch_argv(args: argparse.Namespace, show: bool, executable: Optional[str] = None,
                  frozen: Optional[bool] = None, script: Optional[str] = None) -> list:
    """Command line for a fresh copy of this client with the same service settings."""
    frozen = bool(getattr(sys, "frozen", False)) if frozen is None else bool(frozen)
    exe = executable or sys.executable
    argv = [exe] if frozen else [exe, script or str(Path(__file__).resolve())]
    if getattr(args, "url", None):
        argv += ["--url", str(args.url)]
    elif int(getattr(args, "port", DEFAULT_PORT) or DEFAULT_PORT) != DEFAULT_PORT:
        argv += ["--port", str(int(args.port))]
    if getattr(args, "debug", False):
        argv.append("--debug")
    rdp = getattr(args, "remote_debugging_port", None)
    if rdp:
        argv += ["--remote-debugging-port", str(int(rdp))]
    if not show:
        argv.append("--minimized")
    return argv


def _window_visible(title: str = TITLE) -> bool:
    try:
        hwnd = find_window(title)
        if not hwnd:
            return False
        u = _user32()
        u.IsWindowVisible.argtypes = [ctypes.c_void_p]
        return bool(u.IsWindowVisible(hwnd))
    except Exception:  # noqa: BLE001
        return False


def _safe(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator: never let a callback raise (log it instead)."""
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except Exception:  # noqa: BLE001
            log.exception("callback %s failed", getattr(fn, "__name__", fn))
            return None
    wrapper.__name__ = getattr(fn, "__name__", "callback")
    return wrapper


# --------------------------------------------------------------------------- JS bridge
_BAD_NAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def _clean_filename(name: str, default: str = "TNT-export.bin") -> str:
    name = os.path.basename(str(name or "")).strip()
    name = _BAD_NAME_CHARS.sub("_", name)
    return name or default


def _decode_b64(b64: str) -> bytes:
    s = str(b64 or "")
    if s.startswith("data:") and "," in s:
        s = s.split(",", 1)[1]
    s = re.sub(r"\s+", "", s)
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _downloads_dir() -> str:
    for cand in (Path.home() / "Downloads", Path.home()):
        if cand.is_dir():
            return str(cand)
    return ""


def bridge_functions(bridge: Any) -> list:
    """The bound public methods of *bridge*, for ``window.expose``. pywebview looks an exposed function up
    by its exact name, whereas a ``js_api`` object is searched as a dotted attribute path (``_app.quit``
    included), so only these functions are ever callable from a page."""
    cls = type(bridge)
    return [getattr(bridge, name) for name in sorted(vars(cls))
            if not name.startswith("_") and callable(getattr(cls, name))]


class JsBridge:
    """Exposed to the page as ``window.pywebview.api`` (each public method through ``window.expose``, see
    :func:`bridge_functions`). Every method is exception-safe."""

    def __init__(self, app: "ClientApp") -> None:
        self._app = app

    def save_file(self, suggested_name: str, b64: str) -> Optional[str]:
        """Save dialog -> write the base64 payload -> return the path (None if cancelled)."""
        try:
            import webview  # local import: keep the module importable without a GUI
            name = _clean_filename(suggested_name)
            data = _decode_b64(b64)
            ext = Path(name).suffix.lower().lstrip(".")
            if ext:
                types = (f"{ext.upper()} file (*.{ext})", "All files (*.*)")
            else:
                types = ("All files (*.*)",)
            window = self._app.window
            if window is None:
                return None
            # pywebview >= 5 exposes FileDialog.SAVE; SAVE_DIALOG is the deprecated alias.
            dialog = getattr(getattr(webview, "FileDialog", None), "SAVE", None)
            if dialog is None:
                dialog = webview.SAVE_DIALOG
            result = window.create_file_dialog(dialog, directory=_downloads_dir(),
                                               save_filename=name, file_types=types)
            if not result:
                return None
            path = result[0] if isinstance(result, (list, tuple)) else result
            path = str(path)
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(data)
            log.info("saved %d bytes to %s", len(data), path)
            return path
        except Exception:  # noqa: BLE001
            log.exception("save_file failed")
            return None

    def pick_capture_file(self) -> Optional[str]:
        """Open dialog for a capture file -> its path, or None when it is cancelled (or there is no window).

        The Packet capture page's "Browse…" uses this so a capture taken anywhere on this PC can be opened, not only
        the ones TNT saved; the SIP page's call flows use the same one for each of their two slots.  Nothing is read
        here: the path goes to the service, which is what opens the file."""
        try:
            import webview  # local import: keep the module importable without a GUI
            window = self._app.window
            if window is None:
                return None
            # pywebview >= 5 exposes FileDialog.OPEN; OPEN_DIALOG is the deprecated alias.
            dialog = getattr(getattr(webview, "FileDialog", None), "OPEN", None)
            if dialog is None:
                dialog = webview.OPEN_DIALOG
            result = window.create_file_dialog(
                dialog, allow_multiple=False,
                file_types=("Packet captures (*.pcapng;*.pcap;*.cap)", "All files (*.*)"))
            if not result:
                return None
            path = result[0] if isinstance(result, (list, tuple)) else result
            log.info("a capture file was picked for the packet capture page")
            return str(path)
        except Exception:  # noqa: BLE001
            log.exception("pick_capture_file failed")
            return None

    def open_path(self, path: str) -> bool:
        """Open a file/folder with its associated app (Explorer for folders)."""
        try:
            p = Path(str(path or "")).expanduser()
            if not p.exists():
                log.warning("open_path: %s does not exist", p)
                return False
            os.startfile(str(p))  # noqa: S606 - user-requested open of a local path
            return True
        except Exception:  # noqa: BLE001
            log.exception("open_path failed")
            return False

    def open_url(self, url: str) -> bool:
        """Open an http(s) URL in the user's default browser (discovery port links etc.)."""
        try:
            text = str(url or "").strip()
            if not re.match(r"^https?://[^\s\"'<>]+$", text):
                log.warning("open_url refused non-http(s) url %r", text[:120])
                return False
            import webbrowser

            return bool(webbrowser.open(text, new=2))
        except Exception:  # noqa: BLE001
            log.exception("open_url failed")
            return False

    def open_ssh(self, host: str) -> bool:
        """Open a new PowerShell window that asks for a user name, then runs ``ssh user@host``.

        Windows' built-in OpenSSH client defaults to the local Windows account name, which is
        rarely the right login for a camera or switch, so the window prompts first (blank
        keeps the ssh default).
        """
        try:
            text = str(host or "").strip()
            if not re.match(r"^[A-Za-z0-9._:\-\[\]]{1,253}$", text):
                log.warning("open_ssh refused host %r", text[:120])
                return False
            import shutil
            import subprocess

            ps = shutil.which("powershell.exe") or os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                                                  "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
            subprocess.Popen([ps, "-NoExit", "-NoLogo", "-Command", ssh_prompt_script(text)],
                             creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
            return True
        except Exception:  # noqa: BLE001
            log.exception("open_ssh failed")
            return False

    def client_info(self) -> Dict[str, Any]:
        return {"version": CLIENT_VERSION, "pid": os.getpid()}

    def set_theme(self, theme: str) -> bool:
        """Remember the theme and repaint the window background (avoids white flashes)."""
        try:
            theme = str(theme or "light").lower()
            if theme not in THEME_BG:
                return False
            self._app.set_theme(theme)
            return True
        except Exception:  # noqa: BLE001
            log.exception("set_theme failed")
            return False

    def retry(self) -> bool:
        """Error page button: probe the service again right now."""
        try:
            self._app.wake_navigator()
            return True
        except Exception:  # noqa: BLE001
            log.exception("retry failed")
            return False

    def arm_relaunch(self) -> bool:
        """Before an update install: start a detached helper that waits for the installer to replace
        this exe and then opens it again.  The installer runs ``/VERYSILENT``, and the ``[Run]`` entry
        that would reopen TNT is ``skipifsilent``, so during an update this is the *only* thing that
        brings the window back.

        The command comes from :func:`tnt.updater.relaunch_command` - one definition, shared - and is
        spawned with ``CREATE_NO_WINDOW``.  It used to use ``DETACHED_PROCESS``, which for a console
        program makes Windows hand it a console of its own: that was the black window full of pings
        people saw during an update.  A no-op unless this is the frozen client."""
        try:
            if not getattr(sys, "frozen", False):
                return False
            exe = sys.executable
            if not exe or not os.path.isfile(exe):
                return False
            import subprocess

            from tnt.updater import relaunch_command

            cmd = relaunch_command(exe)
            flags = (CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP) if os.name == "nt" else 0
            subprocess.Popen(cmd, close_fds=True, creationflags=flags,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log.info("update: armed a client relaunch to follow the installer")
            return True
        except Exception:  # noqa: BLE001
            log.exception("arm_relaunch failed")
            return False

    # -- Wi-Fi survey (client/wifi_survey.py) --------------------------------------------------
    # The BSSID list is location data, so these answer only the TNT dashboard itself: any other page
    # the window might end up on gets a refusal. None of them blocks: the WLAN calls run on the
    # survey's own thread and these only copy its store.
    def _wifi_on_service_page(self) -> bool:
        try:
            return bool(self._app.showing_service_page())
        except Exception:  # noqa: BLE001
            log.exception("could not tell which page the window shows")
            return False

    def _wifi_enabled(self) -> bool:
        try:
            return bool(self._app.wifi.enabled)
        except Exception:  # noqa: BLE001
            return False

    def wifi_survey(self, options: Any = None) -> Dict[str, Any]:
        """The survey dict; ``options`` = ``{"active": bool, "history_s": number|null}`` (``active`` = the
        WiFi page is on screen, renewing the 30 s active-scan lease)."""
        try:
            if not self._wifi_on_service_page():
                return wifi_survey.blank_view("error", WIFI_BRIDGE_REFUSED)
            return self._app.wifi.survey(options, visible=self._app.window_visible)
        except Exception:  # noqa: BLE001
            log.exception("wifi_survey failed")
            return wifi_survey.blank_view("error", WIFI_BRIDGE_FAILED, enabled=self._wifi_enabled())

    def wifi_scan_now(self) -> Dict[str, Any]:
        """Request an immediate active scan (one per 5 s); ``{"ok": bool, "error": str|null}``."""
        try:
            if not self._wifi_on_service_page():
                return {"ok": False, "error": WIFI_BRIDGE_REFUSED}
            return self._app.wifi.scan_now()
        except Exception:  # noqa: BLE001
            log.exception("wifi_scan_now failed")
            return {"ok": False, "error": WIFI_BRIDGE_FAILED}

    def wifi_clear(self) -> Dict[str, Any]:
        """Forget every access point and all history; the survey session restarts now."""
        try:
            if not self._wifi_on_service_page():
                return {"ok": False, "error": WIFI_BRIDGE_REFUSED}
            return self._app.wifi.clear()
        except Exception:  # noqa: BLE001
            log.exception("wifi_clear failed")
            return {"ok": False, "error": WIFI_BRIDGE_FAILED}

    def wifi_set_enabled(self, on: Any) -> Dict[str, Any]:
        """Switch the survey on/off (a JSON boolean only), remembered in client.json."""
        try:
            if not self._wifi_on_service_page():
                return {"ok": False, "enabled": self._wifi_enabled(), "error": WIFI_BRIDGE_REFUSED}
            if not isinstance(on, bool):
                return {"ok": False, "enabled": self._wifi_enabled(), "error": "on must be true or false"}
            return self._app.wifi.set_enabled(on)
        except Exception:  # noqa: BLE001
            log.exception("wifi_set_enabled failed")
            return {"ok": False, "enabled": self._wifi_enabled(), "error": WIFI_BRIDGE_FAILED}

    def open_location_settings(self) -> Dict[str, Any]:
        """Open Settings > Privacy & security > Location (where the survey's location access is granted)."""
        try:
            if not self._wifi_on_service_page():
                return {"ok": False, "error": WIFI_BRIDGE_REFUSED}
            os.startfile(LOCATION_SETTINGS_URI)  # noqa: S606 - a fixed ms-settings: URI
            return {"ok": True}
        except Exception:  # noqa: BLE001
            log.exception("open_location_settings failed")
            return {"ok": False, "error": "Windows could not open the location settings."}


# --------------------------------------------------------------------------- tray icon
class TrayIcon:
    """pystray icon running in a daemon thread; thread-safe ``set_state``."""

    def __init__(self, app: "ClientApp") -> None:
        self._app = app
        self._lock = threading.RLock()
        self._icon: Any = None
        self._thread: Optional[threading.Thread] = None
        self._light = "grey"
        self._paused = False
        self._images: Dict[str, Any] = {}
        self._ready = threading.Event()

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        import pystray

        def item(text: Any, fn: Callable[[], Any], **kw: Any) -> Any:
            return pystray.MenuItem(text, lambda icon, it: _safe(fn)(), **kw)

        menu = pystray.Menu(
            item("Open TNT", self._app.show_window, default=True),
            item("Run speed test now", self._app.run_speedtest),
            item(lambda it: "Resume monitoring" if self._paused else "Pause monitoring", self._app.toggle_pause),
            item("Diagnostics", self._app.open_diagnostics),
            pystray.Menu.SEPARATOR,
            item("Quit TNT", self._app.quit),
        )
        with self._lock:
            self._icon = pystray.Icon("TNT", icon=self._image("grey"), title=tooltip_text(None), menu=menu)
        self._thread = threading.Thread(target=self._run, name="tray", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            def setup(icon: Any) -> None:
                icon.visible = True
                self._ready.set()
            self._icon.run(setup=setup)
        except Exception:  # noqa: BLE001
            log.exception("tray icon loop crashed")
        finally:
            self._ready.set()
            log.info("tray icon loop ended")

    def stop(self) -> None:
        with self._lock:
            icon = self._icon
        try:
            if icon is not None:
                icon.visible = False
                icon.stop()
        except Exception:  # noqa: BLE001
            log.exception("tray stop failed")
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout=3.0)

    # -- state -------------------------------------------------------------
    def _image(self, light: str) -> Any:
        if light not in self._images:
            self._images[light] = icons.make_icon(TRAY_ICON_PX, light)
        return self._images[light]

    @property
    def paused(self) -> bool:
        return self._paused

    def set_state(self, light: str, tooltip: str, paused: bool) -> None:
        light = light if light in icons.LIGHT_COLOURS else "grey"
        with self._lock:
            icon = self._icon
            light_changed = light != self._light
            paused_changed = paused != self._paused
            self._light, self._paused = light, paused
        if icon is None or not self._ready.is_set():
            return
        try:
            if light_changed:
                icon.icon = self._image(light)
            icon.title = tooltip[:TOOLTIP_MAX]
            if paused_changed:
                icon.update_menu()
        except Exception:  # noqa: BLE001
            log.exception("tray update failed")

    def wait_ready(self, timeout: float) -> bool:
        """Wait up to *timeout* s for the icon to be shown; True when it is running."""
        with self._lock:
            started = self._icon is not None
        return started and self._ready.wait(timeout) and self._icon is not None

    def notify(self, message: str, title: str = "TNT") -> bool:
        """Show a balloon; True when it was handed to Windows."""
        with self._lock:
            icon = self._icon
        if icon is None or not self._ready.is_set():
            return False
        try:
            if getattr(icon, "HAS_NOTIFICATION", False):
                icon.notify(str(message)[:NOTIFY_MAX], str(title)[:63])
                return True
        except Exception:  # noqa: BLE001
            log.exception("notify failed")
        return False


# --------------------------------------------------------------------------- application
class ClientApp:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.url = service_url(args)
        self.client = ServiceClient(self.url)
        self.bridge = JsBridge(self)
        self.tray = TrayIcon(self)
        self.window: Any = None
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._quitting = False
        self._on_service_page = False
        self._pending_hash: Optional[str] = None
        self._last_status: Optional[Dict[str, Any]] = None
        self._threads: list[threading.Thread] = []
        self._relaunching = False
        self._relaunch_refused = False         # the relaunch cap stopped one (logged once per process)
        self._hooks_installed = False          # FormClosing + ProcessFailed are attached
        self._hooks: list = []                 # keep the .NET event handlers referenced
        self._hooked_core: Any = None          # the CoreWebView2 whose ProcessFailed is attached
        self._browser_pid: Optional[int] = None   # its browser process
        self._webview_ready = threading.Event()   # a CoreWebView2 was initialised and hooked
        self._version_checked = False
        self._init_warned = False
        self._hard_exit: Callable[[int], Any] = os._exit   # replaced in tests
        state = load_state()
        self.theme = state.get("theme") if state.get("theme") in THEME_BG else "light"
        # no WLAN call and no thread until the session starts (first time the window is shown)
        self.wifi = wifi_survey.WifiSurvey(enabled=wifi_enabled_setting(state),
                                           persist=lambda on: save_state({WIFI_ENABLED_KEY: bool(on)}))

    # -- main entry --------------------------------------------------------
    def run(self) -> int:
        import webview

        try:
            webview.settings["ALLOW_DOWNLOADS"] = True
            webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
        except Exception:  # noqa: BLE001
            pass
        rdp = getattr(self.args, "remote_debugging_port", None)
        if rdp:
            try:
                # pywebview appends --remote-debugging-port=N to the WebView2 AdditionalBrowserArguments
                # (platforms/edgechromium.py); the WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS variable is
                # ignored because pywebview sets those arguments explicitly
                webview.settings["REMOTE_DEBUGGING_PORT"] = int(rdp)
                log.warning("WebView2 remote debugging enabled on 127.0.0.1:%d - diagnostics only: any local program "
                            "can drive the window with this user's rights (saved Wi-Fi passwords included)", int(rdp))
            except Exception:  # noqa: BLE001
                log.exception("could not enable WebView2 remote debugging")

        reachable = self.client.health(timeout=1.5)
        log.info("service %s reachable=%s", self.url, reachable)
        geometry = window_geometry(primary_work_area())
        log.info("window geometry: %s", geometry)
        # no js_api: the bridge methods are exposed by name only (bridge_functions)
        kwargs: Dict[str, Any] = dict(
            title=TITLE, background_color=THEME_BG[self.theme],
            hidden=bool(self.args.minimized), text_select=True, **geometry,
        )
        if reachable:
            self.window = webview.create_window(url=self.url, **kwargs)
            self._on_service_page = True
        else:
            self.window = webview.create_window(html=starting_html(self.url, self.theme), **kwargs)
        self.window.expose(*bridge_functions(self.bridge))
        self.window.events.closing += self._on_closing
        self.window.events.shown += self._on_shown
        self.window.events.loaded += self._on_loaded

        storage = client_dir() / "webview"
        try:
            storage.mkdir(parents=True, exist_ok=True)
        except Exception:  # noqa: BLE001
            log.exception("could not create %s", storage)
        if not webview2_installed():
            # pywebview would silently fall back to the legacy MSHTML (IE) engine, which
            # cannot render the dashboard; say what is missing instead
            log.error("Microsoft Edge WebView2 Runtime not found in the registry")
            _fatal_dialog("TNT needs the Microsoft Edge WebView2 Runtime, which is not installed on this PC.\n\n"
                          "Install it from https://developer.microsoft.com/microsoft-edge/webview2/ "
                          "(Evergreen Bootstrapper) or run the TNT installer again while online, "
                          "then start TNT again.\n\nMonitoring itself keeps running in the TNT service.")
            return EXIT_WEBVIEW2_MISSING
        ico = icon_file()
        log.info("starting GUI loop (edgechromium), minimized=%s icon=%s", self.args.minimized, ico)
        try:
            webview.start(func=self._after_gui_started, gui="edgechromium", private_mode=False,
                          storage_path=str(storage), icon=str(ico) if ico.is_file() else None,
                          debug=bool(self.args.debug))
        finally:
            self._shutdown()
        log.info("GUI loop ended")
        return EXIT_OK

    def _after_gui_started(self) -> None:
        """Runs on a helper thread once the GUI loop is up (webview.start(func=...))."""
        try:
            _create_activate_event()
            self.tray.start()
            targets = [("status-poll", self._status_loop), ("navigator", self._navigator),
                       ("activate-watch", self._activate_loop), ("webview-hooks", self.install_webview_hooks),
                       ("webview-init-watch", self.webview_init_watchdog)]
            if getattr(self.args, "remote_debugging_port", None):
                targets.append(("remote-debugging-warning", self.warn_remote_debugging))
            for name, target in targets:
                t = threading.Thread(target=target, name=name, daemon=True)
                t.start()
                self._threads.append(t)
            log.info("background threads started")
        except Exception:  # noqa: BLE001
            log.exception("background start failed")
        if not self.args.minimized:
            self.wifi.window_shown()        # the window opened visible: the Wi-Fi survey session starts now

    def stop_wifi_survey(self) -> None:
        """Stop the Wi-Fi survey's scanner thread (idempotent; waits at most a second)."""
        try:
            self.wifi.stop(timeout=1.0)
        except Exception:  # noqa: BLE001
            log.exception("Wi-Fi survey stop failed")

    def _shutdown(self) -> None:
        with self._lock:
            self._quitting = True
        self._stop.set()
        self._wake.set()
        self.stop_wifi_survey()
        try:
            self.tray.stop()
        except Exception:  # noqa: BLE001
            log.exception("tray shutdown failed")
        for t in self._threads:
            try:
                t.join(timeout=2.0)
            except Exception:  # noqa: BLE001
                pass
        release_single_instance()

    # -- window events -----------------------------------------------------
    def _on_closing(self) -> Optional[bool]:
        """Close button -> hide to tray (return False cancels the close).

        When Windows is ending the session the close is allowed and the client quits: hiding
        would hold up the restart, and Windows ends the WebView2 processes regardless, so a
        restart that is then abandoned would leave a white window behind."""
        try:
            with self._lock:
                quitting = self._quitting
            if quitting:
                return None
            if session_ending():
                log.info("Windows is signing out or restarting -> quitting instead of hiding to the tray")
                self._begin_exit()
                return None
            log.info("window close requested -> hiding to tray")
            threading.Thread(target=self._hide_window, name="hide", daemon=True).start()
            return False
        except Exception:  # noqa: BLE001
            log.exception("closing handler failed")
            return False

    def _hide_window(self) -> None:
        try:
            with self._lock:
                if self._quitting:
                    return
            if self.window is not None:
                self.window.hide()
        except Exception:  # noqa: BLE001
            log.exception("hide failed")

    def _begin_exit(self) -> None:
        """Windows is ending the session: quit the client for real (tray icon, threads, window).

        WM_QUERYENDSESSION only *asks* whether the session may end; WinForms answers it without
        destroying the form. So the window is destroyed here as well: if the restart is then
        abandoned, TNT is simply not running and opens fresh next time, rather than lingering
        with no tray icon or without its browser. Runs off the UI thread (``quit`` stops pystray,
        which waits for its thread, and destroys the window, which invokes onto the UI thread)."""
        with self._lock:
            if self._quitting:
                return
        threading.Thread(target=self.quit, name="session-end-quit", daemon=True).start()

    # -- self-healing webview ----------------------------------------------
    def _form(self) -> Any:
        return getattr(self.window, "native", None) if self.window is not None else None

    def _on_ui(self, fn: Callable[[], Any], timeout: float = WEBVIEW_CHECK_TIMEOUT_S) -> Tuple[str, Any]:
        """Run *fn* on the WinForms UI thread -> ``("ok", value)``, ``("error", exc)``,
        ``("timeout", None)`` or ``("no-form", None)``."""
        form = self._form()
        if form is None:
            return "no-form", None
        box: Dict[str, Any] = {}
        done = threading.Event()

        def run() -> None:
            try:
                box["value"] = fn()
            except Exception as exc:  # noqa: BLE001
                box["error"] = exc
            finally:
                done.set()

        try:
            if bool(getattr(form, "IsDisposed", False)) or not bool(getattr(form, "IsHandleCreated", True)):
                return "no-form", None
            if not form.InvokeRequired:          # already on the UI thread
                run()
            else:
                from System import Action  # type: ignore  # pythonnet, available in the GUI process

                form.BeginInvoke(Action(run))
        except Exception as exc:  # noqa: BLE001
            return "no-form", exc
        if not done.wait(timeout):
            return "timeout", None
        if "error" in box:
            return "error", box["error"]
        return "ok", box.get("value")

    def webview_state(self) -> str:
        """``alive``, ``dead`` (the WebView2 browser process is gone), ``hung`` (the UI thread
        did not answer) or ``unknown`` (no window, or WebView2 not initialised yet).

        Once a CoreWebView2 was hooked, a recorded browser PID that no longer runs is ``dead``
        without asking the UI thread, and so is a control that dropped its CoreWebView2 (the
        WinForms control clears it when the browser process exits, so reading the PID from the
        control alone never sees the dead browser)."""
        with self._lock:
            hooked = self._hooks_installed
            recorded = self._browser_pid
        if hooked and recorded and not process_alive(recorded):
            return "dead"

        def read_pid() -> Tuple[str, Any]:
            form = self._form()
            wv = getattr(getattr(form, "browser", None), "webview", None)
            if wv is None:
                return "none", None
            try:
                core = wv.CoreWebView2
                if core is None:
                    return "none", None
                return "pid", int(core.BrowserProcessId)
            except Exception as exc:  # noqa: BLE001 - a dead CoreWebView2 throws on every member
                return "dead", str(exc)

        status, value = self._on_ui(read_pid)
        if status == "timeout":
            return "hung"
        if status != "ok" or not value:
            return "unknown"
        kind, detail = value
        if kind == "dead":
            log.warning("WebView2 is not usable: %s", detail)
            return "dead"
        if kind == "none":
            return "dead" if hooked else "unknown"
        if kind == "pid":
            return "alive" if process_alive(detail) else "dead"
        return "unknown"

    def _core_initialised_on_ui(self) -> bool:
        wv = getattr(getattr(self._form(), "browser", None), "webview", None)
        return wv is not None and wv.CoreWebView2 is not None

    def webview_init_watchdog(self, timeout: float = WEBVIEW_INIT_TIMEOUT_S) -> bool:
        """From the GUI start: when no CoreWebView2 was initialised within *timeout* s, log the likely
        causes and show one tray notification (never relaunch: a new copy would fail the same way).
        Returns True when it warned. Never raises."""
        try:
            return self._webview_init_watchdog(timeout)
        except Exception:  # noqa: BLE001
            log.exception("WebView2 start-up watchdog failed")
            return False

    def _webview_init_watchdog(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while not self._stop.is_set() and not self._webview_ready.is_set():
            left = deadline - time.monotonic()
            if left <= 0:
                break
            self._webview_ready.wait(min(left, 0.5))
        if self._stop.is_set() or self._webview_ready.is_set():
            return False
        # the hooks may have missed the event: ask the control itself before warning
        status, value = self._on_ui(self._core_initialised_on_ui, timeout=WEBVIEW_CHECK_TIMEOUT_S)
        if status == "ok" and value:
            log.info("WebView2 is initialised (its ready event was not seen)")
            return False
        with self._lock:
            if self._init_warned or self._quitting:
                return False
            self._init_warned = True
        detail = {"ok": "it never finished initialising", "timeout": "the window's UI thread is not responding",
                  "no-form": "the window was not created"}.get(status, f"{status}: {value}")
        folder = client_dir() / "webview"
        log.error("the TNT window's WebView2 did not initialise within %.0f s of the GUI starting (%s). Likely causes: "
                  "the Microsoft Edge WebView2 Runtime is missing or corrupt (reinstall it); security software is "
                  "blocking msedgewebview2.exe; the WebView2 user-data folder %s is not writable (writable now: %s). "
                  "The window stays blank until this is fixed; monitoring keeps running in the TNT service.",
                  timeout, detail, folder, dir_writable(folder))
        if self.tray.wait_ready(15.0) and self.tray.notify(WEBVIEW_INIT_FAILED_MESSAGE):
            log.info("told the user to reinstall the WebView2 runtime")
        return True

    def warn_remote_debugging(self) -> bool:
        """With ``--remote-debugging-port``, tell the user in a tray notification that every local
        program can now drive the window. Returns True when the notification was shown."""
        rdp = getattr(self.args, "remote_debugging_port", None)
        if not rdp:
            return False
        try:
            return bool(self.tray.wait_ready(20.0) and self.tray.notify(REMOTE_DEBUGGING_WARNING.format(port=int(rdp))))
        except Exception:  # noqa: BLE001
            log.exception("remote debugging warning failed")
            return False

    def check_webview2_version(self, version: Optional[str] = None) -> bool:
        """Log the WebView2 runtime version and, when it is older than MIN_WEBVIEW2_MAJOR, show one
        tray notification per version (remembered in client.json). Returns True when it notified."""
        try:
            if not version:
                version = webview2_registry_version()
            log.info("WebView2 runtime version %s", version or "unknown")
            if not version or not needs_webview2_update(version, MIN_WEBVIEW2_MAJOR):
                return False
            log.warning("the WebView2 runtime %s is older than %d; the TNT UI needs Chromium %d or later and may "
                        "display incorrectly until Windows updates it or the latest runtime is installed",
                        version, MIN_WEBVIEW2_MAJOR, MIN_WEBVIEW2_MAJOR)
            if load_state().get("webview2_outdated_notified") == version:
                return False
            if not self.tray.wait_ready(20.0) or not self.tray.notify(webview2_outdated_message(version)):
                return False
            save_state({"webview2_outdated_notified": version})
            return True
        except Exception:  # noqa: BLE001
            log.exception("WebView2 version check failed")
            return False

    def _start_version_check(self, core: Any) -> None:
        """Once per process, on the UI thread: read the runtime version in use, check it off-thread."""
        with self._lock:
            if self._version_checked:
                return
            self._version_checked = True
        version = None
        try:
            version = str(core.Environment.BrowserVersionString or "").strip() or None
        except Exception:  # noqa: BLE001 - an old runtime may not implement CoreWebView2.Environment
            log.debug("could not read CoreWebView2.Environment.BrowserVersionString", exc_info=True)
        if version is None:
            try:
                from Microsoft.Web.WebView2.Core import CoreWebView2Environment  # type: ignore

                version = str(CoreWebView2Environment.GetAvailableBrowserVersionString(None) or "").strip() or None
            except Exception:  # noqa: BLE001 - check_webview2_version falls back to the registry
                log.debug("GetAvailableBrowserVersionString failed", exc_info=True)
        threading.Thread(target=self.check_webview2_version, args=(version,), name="webview2-version",
                         daemon=True).start()

    def install_webview_hooks(self) -> None:
        """Wait for the form and its WebView2 control, then attach the FormClosing and
        ProcessFailed handlers on the UI thread."""
        deadline = time.monotonic() + 60.0
        while not self._stop.is_set():
            form = self._form()
            if form is not None and getattr(getattr(form, "browser", None), "webview", None) is not None:
                break
            if time.monotonic() >= deadline:
                log.warning("WebView2 control did not appear within 60 s; crash recovery is not active")
                return
            self._stop.wait(0.25)
        if self._stop.is_set():
            return
        status, value = self._on_ui(self._hook_on_ui, timeout=10.0)
        if status != "ok":
            log.warning("could not attach the window hooks (%s): %s", status, value)

    def _hook_on_ui(self) -> None:
        form = self._form()
        wv = form.browser.webview

        def on_form_closing(sender: Any, args: Any) -> None:
            # pywebview's own FormClosing handler ran first and cancelled the close on our
            # behalf (hide to tray); the close reason is only visible here
            try:
                if str(args.CloseReason) == "WindowsShutDown":
                    log.info("Windows is ending the session -> quitting instead of hiding to the tray")
                    args.Cancel = False
                    self._begin_exit()
            except Exception:  # noqa: BLE001
                log.exception("FormClosing hook failed")

        form.FormClosing += on_form_closing
        self._hooks.append(on_form_closing)

        def hook_core(core: Any) -> None:
            try:
                if self._hooked_core is not None and bool(self._hooked_core.Equals(core)):
                    return           # this CoreWebView2 is already watched
            except Exception:  # noqa: BLE001
                pass
            core.ProcessFailed += self._on_process_failed
            self._hooks.append(self._on_process_failed)
            try:
                core.NavigationStarting += self._on_navigation_starting
                self._hooks.append(self._on_navigation_starting)
            except Exception:  # noqa: BLE001 - the bridge methods still check the page themselves
                log.exception("could not attach the navigation guard")
            pid = int(core.BrowserProcessId)
            with self._lock:
                self._hooked_core = core
                self._browser_pid = pid
                self._hooks_installed = True
            self._webview_ready.set()
            log.info("watching the WebView2 browser (pid %s)", pid)
            self._start_version_check(core)

        def on_ready(sender: Any, args: Any) -> None:
            try:
                if args.IsSuccess and sender.CoreWebView2 is not None:
                    hook_core(sender.CoreWebView2)
                elif not args.IsSuccess:
                    log.error("WebView2 initialisation failed: %s", args.InitializationException)
            except Exception:  # noqa: BLE001
                log.exception("attaching ProcessFailed failed")

        # attached even when CoreWebView2 already exists, so a later re-initialisation is watched too
        # (and its browser PID recorded)
        wv.CoreWebView2InitializationCompleted += on_ready
        self._hooks.append(on_ready)
        if wv.CoreWebView2 is not None:
            hook_core(wv.CoreWebView2)

    def _on_navigation_starting(self, sender: Any, args: Any) -> None:
        """CoreWebView2.NavigationStarting (raised on the UI thread): keep the window on the TNT service origin
        and TNT's own inline pages (:func:`navigation_allowed`). Any other page would get the bridge, which
        reaches this user's files and the Wi-Fi survey's location data. A link to another http(s) site the
        user clicked opens in the default browser instead; anything else is just cancelled."""
        try:
            uri = str(args.Uri or "")
            if navigation_allowed(uri, self.url):
                return
            args.Cancel = True
            try:
                parts = urllib.parse.urlsplit(uri[:2048])
                where = f"{parts.scheme}://{parts.hostname or ''}"      # the origin only, never the path
                web = parts.scheme.lower() in ("http", "https") and bool(parts.hostname)
            except ValueError:
                where, web = "a malformed URL", False
            if web and bool(getattr(args, "IsUserInitiated", False)) and re.match(r"^https?://[^\s\"'<>]+$", uri, re.I):
                log.info("a link to %s opens in the default browser, not in the TNT window", where)
                import webbrowser

                threading.Thread(target=webbrowser.open, args=(uri,), kwargs={"new": 2}, name="open-link",
                                 daemon=True).start()
            else:
                log.warning("blocked the TNT window from navigating to %s", where)
        except Exception:  # noqa: BLE001
            log.exception("NavigationStarting handler failed")

    def _on_process_failed(self, sender: Any, args: Any) -> None:
        """CoreWebView2.ProcessFailed (raised on the UI thread)."""
        try:
            try:
                kind = int(args.ProcessFailedKind)
            except Exception:  # noqa: BLE001
                kind = -1
            name = PROCESS_FAILED_KINDS.get(kind, f"process failure kind {kind}")
            action = failure_action(kind)
            log.warning("WebView2 %s -> %s", name, action)
            if action == "reload":
                try:
                    sender.Reload()
                    return
                except Exception:  # noqa: BLE001
                    log.exception("reload after '%s' failed; relaunching instead", name)
                    action = "relaunch"
            if action == "relaunch":
                threading.Thread(target=self.relaunch, kwargs={"reason": "WebView2 " + name},
                                 name="relaunch", daemon=True).start()
        except Exception:  # noqa: BLE001
            log.exception("ProcessFailed handler failed")

    def relaunch(self, show: Optional[bool] = None, reason: str = "", user_initiated: bool = False) -> bool:
        """Start a fresh copy of the client and end this one (its embedded browser is gone).

        Automatic relaunches are capped (:func:`relaunch_allowed`); a refused one is logged once per
        process. *user_initiated* (the user opened the window) ignores the cap, and the relaunch is
        still recorded."""
        with self._lock:
            if self._quitting or self._relaunching:
                return False
            self._relaunching = True
        now = time.time()
        history = relaunch_history()
        recent = [t for t in history if 0 <= now - t < RELAUNCH_WINDOW_S]
        allowed = relaunch_allowed(history, now)
        if not allowed and not user_initiated:
            with self._lock:
                first = not self._relaunch_refused
                self._relaunch_refused = True
                self._relaunching = False
            if first:
                log.error("the TNT window keeps losing its browser (%d relaunches in %.0f min); not relaunching "
                          "automatically until the oldest is %.0f min old - opening TNT from the tray still "
                          "restarts it (%s)", len(recent), RELAUNCH_WINDOW_S / 60, RELAUNCH_WINDOW_S / 60, reason)
            return False
        if not allowed:
            log.warning("relaunch limit reached, but the user opened the window -> relaunching anyway")
        save_state({"relaunches": recent + [now]})
        if show is None:
            show = _window_visible()
        argv = relaunch_argv(self.args, show=bool(show))
        log.warning("relaunching the TNT window (%s): %s", reason or "WebView2 not usable", " ".join(argv))
        with self._lock:
            self._quitting = True
        self._stop.set()
        self._wake.set()
        # the new copy must become the primary instance: give up the mutex before it starts
        release_single_instance()
        try:
            import subprocess

            subprocess.Popen(argv, close_fds=True, cwd=str(Path(argv[0]).parent),
                             creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
        except Exception:  # noqa: BLE001
            log.exception("could not start a new TNT window")
        fallback = threading.Timer(EXIT_FALLBACK_S, lambda: self._hard_exit(0))
        fallback.daemon = True
        fallback.start()
        try:
            self.tray.stop()
        except Exception:  # noqa: BLE001
            log.exception("tray stop failed")
        try:
            if self.window is not None:
                self.window.destroy()
        except Exception:  # noqa: BLE001
            log.exception("window destroy failed")
        return True

    def _on_shown(self) -> None:
        # WinForms raises Shown for a window created hidden too (pywebview shows it at opacity 0 and
        # hides it again), so this is not where the Wi-Fi survey starts: see _after_gui_started and
        # show_window
        log.debug("window shown")

    def _on_loaded(self) -> None:
        log.debug("page loaded")

    def page_url(self) -> Optional[str]:
        """The URL the window shows now; None for the inline starting/error pages, before the first
        navigation, or when it cannot be read. Reads pywebview's record of the last navigation
        (``gui.get_current_url``, a plain attribute in the WinForms backend) instead of
        ``window.get_current_url()``, which waits up to 20 s for the page's loaded event."""
        window = self.window
        if window is None:
            return None
        try:
            getter = getattr(getattr(window, "gui", None), "get_current_url", None)
            if getter is None:
                return None
            url = getter(getattr(window, "uid", None))
            return str(url) if url else None
        except Exception:  # noqa: BLE001
            log.debug("could not read the window's URL", exc_info=True)
            return None

    def showing_service_page(self) -> bool:
        """True while the window shows a page of the TNT service origin (the Wi-Fi bridge guard)."""
        return same_origin(self.page_url(), self.url)

    def window_visible(self) -> bool:
        """True while the TNT window is on screen (not hidden to the tray). Plain Win32, never blocks."""
        return _window_visible()

    # -- navigation --------------------------------------------------------
    def wake_navigator(self) -> None:
        self._wake.set()

    def _navigator(self) -> None:
        """Wait for /api/health, then navigate; error page after HEALTH_WAIT_S; keep retrying."""
        deadline = time.monotonic() + HEALTH_WAIT_S
        error_shown = False
        while not self._stop.is_set():
            try:
                with self._lock:
                    on_page = self._on_service_page
                if on_page:
                    return
                if self.client.health(timeout=2.0):
                    self._navigate_to_service()
                    return
                if not error_shown and time.monotonic() >= deadline:
                    error_shown = True
                    log.warning("service did not answer within %.0f s; showing the error page", HEALTH_WAIT_S)
                    self.window.load_html(error_html(self.url, client_log_path(), self.theme))
            except Exception:  # noqa: BLE001
                log.exception("navigator loop error")
                self._stop.wait(2.0)
            self._wake.wait(RETRY_AFTER_ERROR_S if error_shown else 1.0)
            self._wake.clear()

    def _navigate_to_service(self) -> None:
        with self._lock:
            target = self.url + (self._pending_hash or "")
            self._pending_hash = None
        log.info("service is up -> navigating to %s", target)
        self.window.load_url(target)
        with self._lock:
            self._on_service_page = True

    # -- status polling ----------------------------------------------------
    def _status_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.refresh_status()
            except Exception:  # noqa: BLE001
                log.exception("status poll failed")
            try:
                self.watchdog_tick()
            except Exception:  # noqa: BLE001
                log.exception("webview watchdog failed")
            self._stop.wait(STATUS_POLL_S)

    def watchdog_tick(self) -> None:
        """One pass of the dead-browser watchdog, for the case where ProcessFailed never fired (the
        browser was ended as part of a sign-out or restart). Only once a WebView2 was seen working.
        After the relaunch cap refused a relaunch it stays quiet (no probe, no relaunch, no log)
        until :func:`relaunch_allowed` passes again - the oldest relaunch aged out or the history in
        client.json was cleared - and then relaunches on the next tick."""
        with self._lock:
            watching = self._hooks_installed and not self._quitting
            refused = self._relaunch_refused
        if not watching:
            return
        if refused and not relaunch_allowed(relaunch_history(), time.time()):
            return
        if self.webview_state() == "dead":
            self.relaunch(reason="WebView2 browser process is gone")

    def refresh_status(self) -> Optional[Dict[str, Any]]:
        status = self.client.status(timeout=5.0)
        with self._lock:
            self._last_status = status
        light, _ = light_summary(status)
        self.tray.set_state(light, tooltip_text(status), bool(status and status.get("paused")))
        return status

    # -- actions (tray menu / bridge) --------------------------------------
    def show_window(self) -> None:
        try:
            if self.window is None:
                return
            # bringing a window whose browser died to the front only shows a white page:
            # start a fresh copy instead, which opens straight onto the dashboard
            with self._lock:
                watching = self._hooks_installed
            if watching and self.webview_state() == "dead":
                # the user asked for the window: relaunch even when the automatic cap is reached
                self.relaunch(show=True, reason="the window was opened but its WebView2 browser is gone",
                              user_initiated=True)
                return
            self.keep_window_on_screen()
            self.window.show()
            self.wifi.window_shown()                 # first time on screen: the Wi-Fi survey session starts
            hwnd = find_window()
            if hwnd:
                u = _user32()
                if _is_iconic(hwnd):
                    u.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
                    u.ShowWindow(hwnd, SW_RESTORE)
                    self.keep_window_on_screen()     # a minimised window restores to its old place
                u.SetForegroundWindow.argtypes = [ctypes.c_void_p]
                u.SetForegroundWindow(hwnd)
        except Exception:  # noqa: BLE001
            log.exception("show_window failed")

    def _keep_on_screen_on_ui(self) -> Any:
        """UI thread: move/shrink a normal (not minimised or maximised) window into a work area when
        :func:`keep_on_screen` says so. Works in logical px like pywebview (form bounds and screen
        work areas are device px of this system-DPI-aware process)."""
        form = self._form()
        if form is None or str(form.WindowState) != "Normal":
            return None
        from System.Drawing import Size  # type: ignore  # pythonnet, available in the GUI process
        from System.Windows.Forms import Screen  # type: ignore

        try:
            scale = float(form._scale) or 1.0          # pywebview: GetDpiForWindow / 96
        except Exception:  # noqa: BLE001
            scale = 1.0

        def lg(v: Any) -> int:
            return int(round(int(v) / scale))

        b = form.Bounds
        bounds = (lg(b.X), lg(b.Y), lg(b.Width), lg(b.Height))
        areas = [(lg(s.WorkingArea.X), lg(s.WorkingArea.Y), lg(s.WorkingArea.Width), lg(s.WorkingArea.Height))
                 for s in Screen.AllScreens]
        minimum = (lg(form.MinimumSize.Width), lg(form.MinimumSize.Height))
        plan = keep_on_screen(bounds, areas, minimum)
        if plan is None:
            return None
        (x, y, w, h), (min_w, min_h) = plan
        if (min_w, min_h) != minimum:
            form.MinimumSize = Size(int(min_w * scale), int(min_h * scale))
        form.SetBounds(int(round(x * scale)), int(round(y * scale)), int(w * scale), int(h * scale))
        return bounds, areas, plan

    def keep_window_on_screen(self) -> None:
        """Bring a window whose monitor went away, or that is larger than the monitor it is on now,
        back into a work area before it is shown. Never raises."""
        try:
            status, value = self._on_ui(self._keep_on_screen_on_ui, timeout=3.0)
            if status == "ok" and value:
                bounds, areas, plan = value
                log.info("window %s did not fit the work areas %s -> moved/resized to %s (minimum %s)",
                         bounds, areas, plan[0], plan[1])
            elif status in ("error", "timeout"):
                log.warning("could not check that the window is on screen (%s): %s", status, value)
        except Exception:  # noqa: BLE001
            log.exception("keep_window_on_screen failed")

    def run_speedtest(self) -> None:
        code, data = self.client.post("/api/speedtests/run", timeout=10.0)
        if code == 200 and isinstance(data, dict) and data.get("started", True):
            self.tray.notify("Speed test started. Results appear in the Speed tile in a minute or so.")
        elif code == 409:
            self.tray.notify("A speed test is already running.")
        elif code == 0:
            self.tray.notify("Could not reach the TNT service.")
        else:
            msg = ""
            if isinstance(data, dict):
                msg = str((data.get("error") or {}).get("message", "")) if isinstance(data.get("error"), dict) else ""
            self.tray.notify(f"Speed test could not start (HTTP {code}). {msg}".strip())
        log.info("run speed test -> %s %s", code, data)

    def toggle_pause(self) -> None:
        with self._lock:
            paused = bool(self._last_status and self._last_status.get("paused"))
        path = "/api/monitoring/resume" if paused else "/api/monitoring/pause"
        code, data = self.client.post(path, timeout=10.0)
        log.info("%s -> %s %s", path, code, data)
        if code == 0:
            self.tray.notify("Could not reach the TNT service.")
        elif code == 200 and isinstance(data, dict):
            self.tray.notify("Monitoring paused." if data.get("paused") else "Monitoring resumed.")
        self.refresh_status()

    def open_diagnostics(self) -> None:
        self.show_window()
        with self._lock:
            on_page = self._on_service_page
        if not on_page:
            with self._lock:
                self._pending_hash = "#diagnostics"
            self.wake_navigator()
            return
        try:
            self.window.evaluate_js("location.hash = '#diagnostics'; void 0;")
        except Exception:  # noqa: BLE001
            log.warning("evaluate_js failed; falling back to load_url", exc_info=True)
            try:
                self.window.load_url(self.url + "#diagnostics")
            except Exception:  # noqa: BLE001
                log.exception("could not open diagnostics")

    def set_theme(self, theme: str) -> None:
        self.theme = theme
        save_state({"theme": theme})
        colour = THEME_BG[theme]
        try:
            form = getattr(self.window, "native", None)
            if form is not None:
                from System import Action  # type: ignore  # pythonnet, available in the GUI process
                from System.Drawing import ColorTranslator  # type: ignore

                def _apply() -> None:
                    form.BackColor = ColorTranslator.FromHtml(colour)

                if form.InvokeRequired:
                    form.Invoke(Action(_apply))
                else:
                    _apply()
        except Exception:  # noqa: BLE001
            log.warning("could not repaint the window background", exc_info=True)

    def quit(self) -> None:
        log.info("quit requested (the TNTService service keeps running)")
        with self._lock:
            self._quitting = True
        self._stop.set()
        self._wake.set()
        self.stop_wifi_survey()
        try:
            self.tray.stop()
        except Exception:  # noqa: BLE001
            log.exception("tray stop failed")
        try:
            if self.window is not None:
                self.window.destroy()
        except Exception:  # noqa: BLE001
            log.exception("window destroy failed")

    # -- second-instance activation ----------------------------------------
    def _activate_loop(self) -> None:
        h = _activate_event_handle
        if not h:
            return
        k = _kernel32()
        k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        k.WaitForSingleObject.restype = ctypes.c_uint
        while not self._stop.is_set():
            try:
                if k.WaitForSingleObject(h, 1000) == WAIT_OBJECT_0:
                    log.info("another TNT.exe asked us to come to the front")
                    self.show_window()
            except Exception:  # noqa: BLE001
                log.exception("activate watcher error")
                self._stop.wait(2.0)


# --------------------------------------------------------------------------- main
def client_selfcheck() -> int:
    """Frozen-build self check (``TNT.exe --selfcheck``), run by installer/build.ps1.

    The exe is windowed (no console), so results go to ``%LOCALAPPDATA%\\TNT\\selfcheck.log``
    and the exit code (0 = everything importable and the icon renders). No window, no
    tray icon, no network is touched.
    """
    import importlib

    lines: list[str] = []
    failures = 0

    def report(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        if not ok:
            failures += 1
        lines.append(f"{'ok  ' if ok else 'FAIL'} {name}{(' - ' + detail) if detail else ''}")

    for mod in ("ctypes", "ssl", "json", "PIL.Image", "PIL.ImageDraw", "pystray", "pystray._win32",
                "clr_loader", "clr", "webview", "webview.platforms.winforms", "webview.platforms.edgechromium",
                "client.icons", "client.wifi_ies", "client.wifi_survey"):
        try:
            importlib.import_module(mod)
            report(f"import {mod}", True)
        except Exception as exc:  # noqa: BLE001
            report(f"import {mod}", False, f"{type(exc).__name__}: {exc}")
    try:  # no WLAN call: the structure layout and the element parser on a synthetic entry
        from client import wifi_ies

        parsed, detail = wifi_ies.self_test()
        report("Wi-Fi survey structures + parser", wifi_survey.layout_ok() and parsed,
               f"{detail}; WLAN_BSS_ENTRY {ctypes.sizeof(wifi_survey.WLAN_BSS_ENTRY)} bytes")
    except Exception as exc:  # noqa: BLE001
        report("Wi-Fi survey structures + parser", False, f"{type(exc).__name__}: {exc}")
    try:
        img = icons.make_icon(TRAY_ICON_PX, "green")
        report("tray icon render", img.size == (TRAY_ICON_PX, TRAY_ICON_PX), f"{img.size} {img.mode}")
    except Exception as exc:  # noqa: BLE001
        report("tray icon render", False, f"{type(exc).__name__}: {exc}")
    try:
        ico = icon_file()
        report("bundled tnt.ico", ico is not None and Path(ico).is_file(), str(ico))
    except Exception as exc:  # noqa: BLE001
        report("bundled tnt.ico", False, f"{type(exc).__name__}: {exc}")
    try:
        import webview as _wv  # noqa: F401
        from webview.platforms import edgechromium as _ec  # noqa: F401

        report("WebView2 backend module", True)
    except Exception as exc:  # noqa: BLE001
        report("WebView2 backend module", False, f"{type(exc).__name__}: {exc}")
    lines.append(f"selfcheck: {'PASSED' if failures == 0 else f'{failures} FAILURE(S)'} "
                 f"(frozen={bool(getattr(sys, 'frozen', False))}, exe={sys.executable})")
    try:
        client_dir().mkdir(parents=True, exist_ok=True)
        (client_dir() / "selfcheck.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    if sys.stdout is not None:
        try:
            print("\n".join(lines), flush=True)
        except (OSError, ValueError):
            pass
    return 0 if failures == 0 else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if "--selfcheck" in raw:
        return client_selfcheck()
    args = parse_args(argv)
    log_path = setup_client_logging(logging.DEBUG if args.debug else logging.INFO)
    log.info("TNT client %s starting pid=%s frozen=%s url=%s minimized=%s log=%s",
             CLIENT_VERSION, os.getpid(), bool(getattr(sys, "frozen", False)), service_url(args),
             args.minimized, log_path)
    if not acquire_single_instance():
        log.info("another TNT client is already running; bringing it to the front")
        if args.remote_debugging_port:
            log.warning("--remote-debugging-port %d has no effect: TNT is already running (quit it from the tray "
                        "first)", args.remote_debugging_port)
        activated = activate_existing_window()
        signalled = _signal_activate_event()
        log.info("activate existing: window=%s event=%s", activated, signalled)
        release_single_instance()
        return EXIT_OK
    try:
        return ClientApp(args).run()
    except Exception as exc:  # noqa: BLE001
        if is_dotnet_load_error(exc):
            # pythonnet could load neither .NET Framework nor .NET: no traceback for the user
            log.error("the .NET runtime could not be loaded, so the TNT window cannot start", exc_info=True)
            _fatal_dialog(dotnet_missing_message(log_path))
            return EXIT_DOTNET_MISSING
        log.exception("fatal client error")
        _fatal_dialog(f"TNT could not start its window.\n\n{exc}\n\nSee {log_path}")
        return EXIT_FATAL
    finally:
        release_single_instance()


if __name__ == "__main__":
    sys.exit(main())
