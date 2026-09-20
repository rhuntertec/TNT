"""Auto-update from the GitHub releases page.

:class:`UpdateManager` (``engine.update``) checks the project's GitHub releases on its own daemon
thread (``tnt-update``), tells the UI when a newer release exists, and — on the user's confirm, or
automatically when ``update.auto_install`` is on — downloads the installer, verifies it against the
release's SHA-256 checksum and launches it silently. The service runs as LocalSystem, so the installer
starts with no UAC prompt; the installer itself stops the service and client, replaces the files and
restarts the service (installer/tnt.iss).

Trust
-----
Only HTTPS to ``api.github.com`` and the asset CDN (redirects are https-only, a fresh default TLS
context per request). The downloaded installer is **never run** unless its SHA-256 matches the checksum
published in the release (a ``<setup>.exe.sha256`` asset, or a ``SHA256SUMS`` list). There is no
code-signing certificate yet, so this checksum is the only integrity guarantee and it is mandatory —
a missing or mismatched checksum aborts the install. The ``verify`` step is the seam where a detached
signature check would later slot in. The repository is a module constant, never a setting, so a
hand-edited config can never point the updater at another host.

Schedule
--------
The first check runs ``FIRST_CHECK_DELAY_S`` after start, then every ``update.check_interval_h`` hours
(+ jitter), with a 1 min .. 6 h backoff after failures. Turning ``update.enabled`` off idles the thread;
turning it on schedules a check straight away.

Seams (keyword arguments): ``current_version`` (defaults to ``tnt.__version__``), ``urlopen`` (an
``http_open`` stand-in), ``installer_launch`` (a ``subprocess.Popen`` stand-in), ``temp_dir_fn`` (where
the installer is staged; default ``tnt.paths.update_dir``), ``clock`` and ``monotonic``. Setting
``TNT_UPDATE_OFFLINE`` refuses every non-loopback host (tests).

STATUS (exactly :data:`STATUS_KEYS`): ``{"enabled", "state", "current_version", "latest_version",
"latest_ts", "notes_url", "asset": {"name","bytes"}|None, "checked_ts", "next_check_ts",
"download": {"received","total","phase"}|None, "error", "auto_install"}``.
"""
from __future__ import annotations

import http.client
import base64
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import threading
import time
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin, urlsplit

from . import __version__

log = logging.getLogger(__name__)

MiB = 1024 * 1024
REPO = "rhuntertec/TNT"                    # owner/repo — a constant, never a setting (no SSRF via config)
GITHUB_API = "https://api.github.com"
LATEST_URL = f"{GITHUB_API}/repos/{REPO}/releases/latest"
RELEASES_URL = f"{GITHUB_API}/repos/{REPO}/releases?per_page=20"
USER_AGENT = f"TNT/{__version__} (+https://github.com/{REPO})"
INSTALLER_ARGS = ("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART")
#: The installer writes its log beside itself in the staging folder.  Without this a silent
#: install that failed left no record anywhere of why, which is no way to support a field tool.
INSTALL_LOG_NAME = "install.log"

SETUP_ASSET_RE = re.compile(r"^TNT-Setup-.*\.exe$", re.IGNORECASE)
CHECKSUM_NAMES = ("sha256sums", "sha256sums.txt")   # a shared checksum list (fallback to "<setup>.sha256")
_HEX64_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")
#: A release tag.  The optional ``TNT`` prefix is this project's own convention - its releases are
#: tagged ``TNT1.20.1``, not ``v1.20.1`` - and leaving it out here meant every release from 1.16.0
#: onward parsed as None, so no client ever found an update.  Both forms are accepted now.
_VER_RE = re.compile(r"^(?:[Tt][Nn][Tt])?[vV]?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.\-]+))?"
                     r"(?:\+[0-9A-Za-z.\-]+)?$")
#: What :func:`display_version` strips off the front, longest first.
_VER_PREFIXES = ("tntv", "tnt", "v")

MAX_SETUP_BYTES = 300 * MiB
MAX_JSON_BYTES = 4 * MiB
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
SOCKET_TIMEOUT_S = 30.0
STALL_WINDOW_S = 300.0
STALL_MIN_BYTES = 1 * MiB
READ_CHUNK = 256 * 1024
MAX_REDIRECTS = 5
FIRST_CHECK_DELAY_S = 30.0
CHECK_JITTER_S = 900.0                     # up to 15 min added to each scheduled check
RETRY_BACKOFF_S = (60.0, 300.0, 900.0, 3600.0, 21600.0)
MIN_CHECK_INTERVAL_S = 60.0
MAX_WAIT_S = 3600.0
PROGRESS_EVENT_S = 1.0
STOP_JOIN_S = 0.8
THREAD_NAME = "tnt-update"
OFFLINE_ENV = "TNT_UPDATE_OFFLINE"
_MAX_TEXT = 200

STATES = ("disabled", "idle", "checking", "up_to_date", "available", "downloading", "verifying",
          "ready", "installing", "error")
STATUS_KEYS = ("enabled", "state", "current_version", "latest_version", "latest_ts", "notes_url",
               "asset", "checked_ts", "next_check_ts", "download", "error", "auto_install")


class UpdateError(Exception):
    """Base; str(exc) is the user-facing status text (<= 200 chars)."""


class DownloadError(UpdateError):
    """A download failed (HTTP status, size cap, stall, cut short, disk, redirect)."""


class VerifyError(UpdateError):
    """The downloaded installer did not match the published SHA-256 (or none was published)."""


# --------------------------------------------------------------------------- pure helpers
def _cut(text: str, limit: int = _MAX_TEXT) -> str:
    return text if len(text) <= limit else text[:limit]


def parse_version(tag: object) -> Optional[Tuple[int, int, int, int, Tuple[Tuple[int, Any], ...]]]:
    """A comparable key for a version tag, or None. ``"v1.16.0"`` -> ``(1,16,0,1,())``;
    ``"1.16.0-rc.1"`` -> ``(1,16,0,0,((0,1) after 'rc'...))``. A release (rank 1) outranks a
    pre-release (rank 0) of the same MAJOR.MINOR.PATCH; numeric pre-release parts rank below
    alphanumeric ones, and more parts outrank fewer (semver precedence)."""
    if not isinstance(tag, str):
        return None
    m = _VER_RE.match(tag.strip())
    if m is None:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    pre = m.group(4)
    if not pre:
        return (major, minor, patch, 1, ())
    pieces: List[Tuple[int, Any]] = []
    for part in pre.split("."):
        if part.isdigit():
            pieces.append((0, int(part)))     # numeric identifiers rank below alphanumeric
        else:
            pieces.append((1, part))
    return (major, minor, patch, 0, tuple(pieces))


def is_newer(candidate: object, current: object) -> bool:
    """True when version *candidate* is strictly newer than *current* (both must parse)."""
    a, b = parse_version(candidate), parse_version(current)
    return a is not None and b is not None and a > b


def display_version(tag: object) -> str:
    """A tag as a version for display: ``"v1.16.0"`` and ``"TNT1.20.1"`` -> ``"1.16.0"`` / ``"1.20.1"``.

    "" for a non-string, and a tag that is not one of ours comes back untouched rather than chopped.
    """
    text = tag.strip() if isinstance(tag, str) else ""
    lowered = text.lower()
    for prefix in _VER_PREFIXES:
        if lowered.startswith(prefix) and len(text) > len(prefix) and text[len(prefix)].isdigit():
            return text[len(prefix):]
    return text


def _release_ok(rel: Any, channel: str) -> bool:
    if not isinstance(rel, dict) or rel.get("draft"):
        return False
    if channel != "prerelease" and rel.get("prerelease"):
        return False
    return parse_version(rel.get("tag_name")) is not None


def select_release(releases: Any, channel: str, current: object) -> Optional[Dict[str, Any]]:
    """The newest eligible release strictly newer than *current*, or None. Drafts are never eligible;
    pre-releases only on the ``prerelease`` channel."""
    best: Optional[Dict[str, Any]] = None
    best_key: Any = parse_version(current)
    if best_key is None:
        best_key = (0, 0, 0, 0, ())
    for rel in releases if isinstance(releases, list) else []:
        if not _release_ok(rel, channel):
            continue
        key = parse_version(rel.get("tag_name"))
        if key is not None and key > best_key:
            best, best_key = rel, key
    return best


def pick_setup_asset(assets: Any) -> Optional[Dict[str, Any]]:
    """The ``TNT-Setup-*.exe`` asset dict, or None."""
    for a in assets if isinstance(assets, list) else []:
        name = a.get("name") if isinstance(a, dict) else None
        if isinstance(name, str) and SETUP_ASSET_RE.match(name):
            return a
    return None


def pick_checksum_asset(assets: Any, setup_name: str) -> Optional[Dict[str, Any]]:
    """The checksum asset for *setup_name*: ``<setup>.sha256`` first, else a shared SHA256SUMS list."""
    want = (setup_name + ".sha256").lower()
    shared: Optional[Dict[str, Any]] = None
    for a in assets if isinstance(assets, list) else []:
        name = a.get("name") if isinstance(a, dict) else None
        if not isinstance(name, str):
            continue
        low = name.lower()
        if low == want:
            return a
        if shared is None and low in CHECKSUM_NAMES:
            shared = a
    return shared


def parse_checksum(text: object, setup_name: str) -> Optional[str]:
    """The 64-hex SHA-256 for *setup_name* from a ``.sha256`` file or a SHA256SUMS list, else None.
    Accepts ``"<hex>  <name>"`` / ``"<hex> *<name>"`` lines and a bare ``<hex>`` file."""
    if not isinstance(text, str):
        return None
    want = setup_name.lower()
    bare: Optional[str] = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _HEX64_RE.search(line)
        if m is None:
            continue
        digest = m.group(1).lower()
        rest = (line[:m.start()] + line[m.end():]).strip().lstrip("*").strip()
        if rest.lower().lstrip("*").strip() == want or os.path.basename(rest).lower() == want:
            return digest
        if bare is None and not rest:
            bare = digest
    return bare


#: The post-install waiter's limits.  The timeout is generous because it has to cover the whole
#: download as well as the install: on a site connection a 32 MB installer is minutes, not seconds.
RELAUNCH_TIMEOUT_S = 300
RELAUNCH_POLL_S = 2
#: A breath after the installer lets go of the exe, before opening it.
RELAUNCH_SETTLE_S = 2

#: The waiter, as PowerShell.  It watches the client exe's timestamp rather than sleeping a fixed
#: time: that is the one signal that says the installer has actually replaced it.  Everything the
#: caller varies is substituted in, then the whole thing is base64'd into -EncodedCommand, which
#: sidesteps every quoting rule between here and the shell.
#:
#: It reads the *baseline* timestamp itself rather than being handed one.  A tick count computed
#: here from ``st_mtime`` and one read there from ``LastWriteTimeUtc`` are two different stacks'
#: answers to the same question, and a float second cannot hold 100 ns precision - the two would
#: disagree on some files, the waiter would decide the exe had already been replaced, and it would
#: fire on its first poll.  Reading it in one place makes that impossible.  Nothing can have
#: replaced the exe in the moment between arming and this line: the download has not started.
_RELAUNCH_PS = """
$e = @EXE@
$was = @WAS@
if (-not $was) { try { $was = (Get-Item -LiteralPath $e).LastWriteTimeUtc.Ticks.ToString() } catch { } }
$deadline = (Get-Date).AddSeconds(@TIMEOUT@)
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds @POLL@
  $now = $null
  try { $now = (Get-Item -LiteralPath $e).LastWriteTimeUtc.Ticks.ToString() } catch { }
  if ($was -and $now -and $now -ne $was -and -not (Get-Process -Name 'TNT-Setup*' -ErrorAction SilentlyContinue)) { break }
}
Start-Sleep -Seconds @SETTLE@
if (-not (Get-Process -Name 'TNT' -ErrorAction SilentlyContinue)) {
  if (Test-Path -LiteralPath $e) { Start-Process -FilePath $e }
}
"""


def _ps_literal(text: str) -> str:
    """*text* as a single-quoted PowerShell string (the only escape inside one is a doubled quote)."""
    return "'" + str(text).replace("'", "''") + "'"


def relaunch_command(exe: str, stamp: str = "", timeout_s: int = RELAUNCH_TIMEOUT_S) -> List[str]:
    """The detached helper the client arms before an update: wait for the installer, then reopen TNT.

    **Not** ``TNT.exe``, because the installer's ``taskkill /IM TNT.exe`` in ``PrepareToInstall``
    would kill the waiter along with the window it is meant to bring back.

    It used to be ``ping -n 31 127.0.0.1`` - a thirty-second sleep - which is only long enough when
    the download is fast.  On a slower connection the sleep ran out during the download, the waiter
    started the client, opened TNT, and then the installer killed it with nothing left to try again:
    the update succeeded and the application disappeared.  So this waits on the thing that actually
    matters, the client exe being replaced, and keeps a timeout only so that an update which fails
    outright still gives the user their window back.

    *stamp* is the baseline timestamp to watch for a change from; "" (the default, and what the
    client passes) means the waiter reads it on its own first line.  The tests hand one in.
    """
    script = (_RELAUNCH_PS
              .replace("@EXE@", _ps_literal(exe))
              .replace("@WAS@", _ps_literal(stamp))      # "" -> the script reads it itself
              .replace("@TIMEOUT@", str(max(10, int(timeout_s))))
              .replace("@POLL@", str(RELAUNCH_POLL_S))
              .replace("@SETTLE@", str(RELAUNCH_SETTLE_S)))
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
            "-EncodedCommand", encoded]


def friendly_error(exc: BaseException, host: str) -> str:
    if isinstance(exc, UpdateError):
        text = str(exc)
    elif isinstance(exc, socket.gaierror):
        text = f"could not look up {host} (no DNS or no internet)"
    elif isinstance(exc, ssl.SSLCertVerificationError):
        text = f"the certificate of {host} could not be verified (TLS inspection or a missing root certificate)"
    elif isinstance(exc, TimeoutError):
        text = f"{host} did not answer in time (a proxy may be required)"
    elif isinstance(exc, (ConnectionError, OSError)):
        text = f"could not reach {host} (a firewall or proxy may be blocking it)"
    else:
        text = f"{type(exc).__name__}: {exc}"
    return _cut(text)


def _host_text(host: object) -> str:
    return str(host).strip().strip("[]").lower() or "the update server"


# --------------------------------------------------------------------------- HTTP seam
class HttpResponse:
    """One GET response; ``read_all`` reads a bounded body, ``readinto`` streams it, ``abort`` shuts it."""

    def __init__(self, conn: Any, resp: Any, sock: Any, url: str, host: str) -> None:
        self._conn = conn
        self._resp = resp
        self._sock = sock
        self._closed = False
        self.status: int = resp.status
        self.headers: Dict[str, str] = {str(k).lower(): v for k, v in resp.getheaders()}
        self.url = url
        self.host = host

    def read_all(self, cap: int) -> bytes:
        return self._resp.read(cap + 1)

    def readinto(self, buf: Union[bytearray, memoryview]) -> int:
        data = self._resp.read1(len(buf))
        n = len(data)
        buf[:n] = data
        return n

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for closer in (self._resp.close, self._conn.close):
            try:
                closer()
            except Exception:  # noqa: BLE001
                pass

    def abort(self) -> None:
        sock, self._sock = self._sock, None
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:  # noqa: BLE001
            pass
        try:
            fd = socket.socket.detach(sock)
            if fd >= 0:
                socket.close(fd)
        except Exception:  # noqa: BLE001
            pass


def http_open(url: str, *, timeout: float = SOCKET_TIMEOUT_S, headers: Optional[Dict[str, str]] = None,
              max_redirects: int = MAX_REDIRECTS) -> HttpResponse:
    """GET *url* over HTTPS (http only on loopback), following https redirects; final status unread."""
    parts = urlsplit(url)
    scheme, host = (parts.scheme or "").lower(), (parts.hostname or "").lower()
    if not (host and (scheme == "https" or (scheme == "http" and host in LOOPBACK_HOSTS))):
        raise ValueError(f"only https downloads are allowed (not {scheme or 'no scheme'})")
    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity",
                       "Connection": "close"}
    request_headers.update(headers or {})
    current, redirects = url, 0
    while True:
        if os.environ.get(OFFLINE_ENV) and host not in LOOPBACK_HOSTS:
            raise OSError("network access is disabled (TNT_UPDATE_OFFLINE)")
        if scheme == "https":
            conn: Any = http.client.HTTPSConnection(host, parts.port or 443, timeout=timeout,
                                                    context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(host, parts.port or 80, timeout=timeout)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        try:
            conn.request("GET", path, headers=request_headers)
            sock = conn.sock
            resp = conn.getresponse()
        except BaseException:
            conn.close()
            raise
        if resp.status not in (301, 302, 303, 307, 308):
            return HttpResponse(conn, resp, sock, current, _host_text(host))
        try:
            resp.read(64 * 1024)
        except Exception:  # noqa: BLE001
            pass
        location = resp.getheader("Location")
        resp.close()
        conn.close()
        if not location:
            raise DownloadError(f"HTTP {resp.status} from {_host_text(host)}")
        target = urljoin(current, location.strip())
        tparts = urlsplit(target)
        tscheme, thost = (tparts.scheme or "").lower(), (tparts.hostname or "").lower()
        if not (tscheme == "https" and thost):
            raise DownloadError(f"refused a redirect to {_host_text(thost)}")
        redirects += 1
        if redirects > max_redirects:
            raise DownloadError(f"too many redirects from {_host_text(host)}")
        current, parts, scheme, host = target, tparts, tscheme, thost


_urlopen = http_open      # THE SEAM: replaced by tests, or overridden per instance via urlopen=


def _abort_response(resp: Any) -> None:
    abort = getattr(resp, "abort", None)
    if callable(abort):
        try:
            abort()
        except Exception:  # noqa: BLE001
            pass


def installer_args(exe: str) -> List[str]:
    """The silent-install switches, plus a log written next to the staged installer."""
    folder = os.path.dirname(exe) or "."
    return [*INSTALLER_ARGS, "/LOG=" + os.path.join(folder, INSTALL_LOG_NAME)]


def _default_installer_launch(exe: str) -> None:
    """Launch the installer detached so it outlives the service it is about to stop."""
    flags = 0
    if os.name == "nt":
        flags = (getattr(subprocess, "DETACHED_PROCESS", 0)
                 | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    subprocess.Popen([exe, *installer_args(exe)], cwd=os.path.dirname(exe) or None, close_fds=True,
                     creationflags=flags, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)


def _default_temp_dir() -> Path:
    from . import paths
    return paths.update_dir()


# --------------------------------------------------------------------------- manager
class UpdateManager:
    """Checks GitHub releases and, on request, downloads + verifies + launches the installer (§ module)."""

    def __init__(self, config: Any, bus: Any = None, *, current_version: str = __version__,
                 urlopen: Optional[Callable[..., Any]] = None,
                 installer_launch: Optional[Callable[[str], None]] = None,
                 temp_dir_fn: Optional[Callable[[], Union[str, os.PathLike]]] = None,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 first_check_delay_s: float = FIRST_CHECK_DELAY_S,
                 jitter_s: Optional[float] = None) -> None:
        self.config = config
        self.bus = bus
        self._current = str(current_version)
        self._injected_urlopen = urlopen
        self._installer_launch = installer_launch if installer_launch is not None else _default_installer_launch
        self._temp_dir_fn = temp_dir_fn if temp_dir_fn is not None else _default_temp_dir
        self._clock = clock
        self._monotonic = monotonic
        self._first_check_delay_s = float(first_check_delay_s)
        self._jitter_s = float(jitter_s) if jitter_s is not None else CHECK_JITTER_S

        self._lock = threading.RLock()
        self._state = "idle" if self.enabled() else "disabled"
        self._error: Optional[str] = None
        self._latest_version: Optional[str] = None
        self._latest_ts: Optional[float] = None
        self._notes_url: Optional[str] = None
        self._asset: Optional[Dict[str, Any]] = None       # {name, size, browser_download_url}
        self._release: Optional[Dict[str, Any]] = None
        self._checked_ts: Optional[float] = None
        self._next_check_ts: Optional[float] = None
        self._download: Optional[Dict[str, Any]] = None
        self._failures = 0
        self._install_requested = False
        self._resp: Any = None

        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._remove_listener: Optional[Callable[[], None]] = None
        self._progress_at = 0.0

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        thread = self._thread
        if thread is not None and thread.is_alive():
            return
        self._stop.clear()
        with self._lock:
            self._next_check_ts = self._clock() + self._first_check_delay_s
            self._state = "idle" if self.enabled() else "disabled"
        add_listener = getattr(self.config, "add_listener", None)
        if callable(add_listener) and self._remove_listener is None:
            try:
                self._remove_listener = add_listener(self._on_config)
            except Exception:  # noqa: BLE001
                self._remove_listener = None
        self._thread = threading.Thread(target=self._run, name=THREAD_NAME, daemon=True)
        self._thread.start()
        log.info("auto-update started (current v%s, %s)", self._current,
                 "enabled" if self.enabled() else "disabled")

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            resp = self._resp
        self._wake.set()
        _abort_response(resp)
        remove, self._remove_listener = self._remove_listener, None
        if remove is not None:
            try:
                remove()
            except Exception:  # noqa: BLE001
                pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(STOP_JOIN_S)
        log.info("auto-update stopped")

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    # ------------------------------------------------------------------ state
    def enabled(self) -> bool:
        try:
            return bool(self.config.get("update.enabled", True))
        except Exception:  # noqa: BLE001
            return True

    def auto_install(self) -> bool:
        try:
            return bool(self.config.get("update.auto_install", False))
        except Exception:  # noqa: BLE001
            return False

    def _channel(self) -> str:
        try:
            return "prerelease" if str(self.config.get("update.channel", "stable")) == "prerelease" else "stable"
        except Exception:  # noqa: BLE001
            return "stable"

    def _interval_s(self) -> float:
        try:
            hours = float(self.config.get("update.check_interval_h", 24))
        except Exception:  # noqa: BLE001
            hours = 24.0
        return max(1.0, hours) * 3600.0

    def status(self) -> Dict[str, Any]:
        """STATUS (exactly STATUS_KEYS): cheap, no I/O, never raises."""
        try:
            en = self.enabled()
            with self._lock:
                return {"enabled": en,
                        "state": self._state if en else "disabled",
                        "current_version": self._current,
                        "latest_version": self._latest_version,
                        "latest_ts": self._latest_ts,
                        "notes_url": self._notes_url,
                        "asset": ({"name": self._asset.get("name"), "bytes": self._asset.get("size")}
                                  if self._asset else None),
                        "checked_ts": self._checked_ts,
                        "next_check_ts": self._next_check_ts,
                        "download": dict(self._download) if self._download is not None else None,
                        "error": self._error,
                        "auto_install": self.auto_install()}
        except Exception:  # noqa: BLE001
            out = dict.fromkeys(STATUS_KEYS)
            out.update({"enabled": True, "state": "error", "current_version": self._current,
                        "error": "status unavailable", "auto_install": False})
            return out

    def _publish(self) -> None:
        bus = self.bus
        if bus is None:
            return
        try:
            bus.publish("update.state", self.status())
        except Exception:  # noqa: BLE001
            log.debug("update.state publish failed", exc_info=True)

    def _set_state(self, state: str) -> None:
        with self._lock:
            self._state = state

    def check_now(self) -> bool:
        """Schedule a check right now (Retry / Check now); False when updates are switched off."""
        if not self.enabled():
            return False
        with self._lock:
            self._failures = 0
            self._next_check_ts = self._clock()
        self._wake.set()
        return True

    def request_install(self) -> None:
        """Begin download + verify + launch of the known available update. Raises RuntimeError when
        updates are off, none is available, or one is already installing."""
        if not self.enabled():
            raise RuntimeError("Automatic updates are switched off")
        with self._lock:
            if self._state in ("downloading", "verifying", "installing"):
                raise RuntimeError("An update is already installing")
            if self._asset is None or self._latest_version is None:
                raise RuntimeError("No update is available to install")
            self._install_requested = True
        self._wake.set()

    # ------------------------------------------------------------------ config
    def _on_config(self, snapshot: Any, changed: Any) -> None:
        try:
            if any(str(k) == "update" or str(k).startswith("update.") for k in changed):
                self._wake.set()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ thread
    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.clear()
            try:
                if not self.enabled():
                    if self._state != "disabled":
                        self._set_state("disabled")
                        self._publish()
                    self._wake.wait(MAX_WAIT_S)
                    continue
                if self._state == "disabled":
                    self._set_state("idle")
                with self._lock:
                    install = self._install_requested
                    self._install_requested = False
                    nxt = self._next_check_ts
                if install:
                    self._do_install()
                    continue
                now = self._clock()
                if nxt is None or nxt - now > 40 * 86400.0:
                    with self._lock:
                        self._next_check_ts = now + self._interval_s()
                    continue
                if now >= nxt:
                    self._do_check()
                    continue
                self._wake.wait(min(nxt - now, MAX_WAIT_S))
            except Exception:  # noqa: BLE001
                log.exception("auto-update thread error")
                self._wake.wait(MIN_CHECK_INTERVAL_S)

    def _opener(self) -> Callable[..., Any]:
        return self._injected_urlopen if self._injected_urlopen is not None else _urlopen

    def _schedule_next(self, now: float, ok: bool) -> None:
        with self._lock:
            if ok:
                self._failures = 0
                wait = self._interval_s() + (self._jitter_s * 0.5)
            else:
                self._failures += 1
                wait = RETRY_BACKOFF_S[min(self._failures, len(RETRY_BACKOFF_S)) - 1]
            self._next_check_ts = now + max(MIN_CHECK_INTERVAL_S, wait)

    # ------------------------------------------------------------------ check
    def _fetch_json(self, url: str) -> Any:
        resp = self._opener()(url, timeout=SOCKET_TIMEOUT_S, headers={"Accept": "application/vnd.github+json"})
        try:
            status = int(resp.status)
            host = getattr(resp, "host", None) or _host_text(urlsplit(url).hostname)
            if status == 404:
                return None
            if status == 403:
                raise DownloadError(f"{host} refused the request (HTTP 403): the rate limit may be reached")
            if status != 200:
                raise DownloadError(f"HTTP {status} from {host}")
            raw = resp.read_all(MAX_JSON_BYTES)
            if len(raw) > MAX_JSON_BYTES:
                raise DownloadError("the release list is larger than expected")
            return json.loads(raw.decode("utf-8", "replace"))
        finally:
            try:
                resp.close()
            except Exception:  # noqa: BLE001
                pass

    def _releases(self) -> List[Dict[str, Any]]:
        if self._channel() == "prerelease":
            data = self._fetch_json(RELEASES_URL)
            return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
        data = self._fetch_json(LATEST_URL)          # already excludes drafts + pre-releases
        return [data] if isinstance(data, dict) else []

    def _do_check(self) -> str:
        if not self.enabled():
            return "disabled"
        self._set_state("checking")
        self._publish()
        now = self._clock()
        try:
            rel = select_release(self._releases(), self._channel(), self._current)
        except Exception as exc:  # noqa: BLE001
            host = _host_text(urlsplit(GITHUB_API).hostname)
            text = friendly_error(exc, host)
            log.warning("update check failed: %s", text)
            with self._lock:
                self._error = text
                self._state = "available" if self._asset else "error"
            self._schedule_next(now, ok=False)
            self._publish()
            return "error"
        with self._lock:
            self._checked_ts = now
            self._error = None
        if rel is None:
            with self._lock:
                self._latest_version = None
                self._latest_ts = None
                self._notes_url = None
                self._asset = None
                self._release = None
                self._state = "up_to_date"
            self._schedule_next(now, ok=True)
            log.info("update check: TNT is up to date (v%s)", self._current)
            self._publish()
            return "up_to_date"
        asset = pick_setup_asset(rel.get("assets"))
        with self._lock:
            self._latest_version = display_version(rel.get("tag_name"))
            self._latest_ts = _parse_iso(rel.get("published_at"))
            self._notes_url = rel.get("html_url") if isinstance(rel.get("html_url"), str) else None
            self._asset = asset
            self._release = rel
            self._state = "available"
            if asset is None:
                self._error = "the release has no installer to download"
        self._schedule_next(now, ok=True)
        log.info("update available: v%s (installer %s)", self._latest_version,
                 "found" if asset else "missing")
        self._publish()
        if asset is not None and self.auto_install():
            with self._lock:
                self._install_requested = True
            self._wake.set()
        return "available"

    # ------------------------------------------------------------------ install
    def _do_install(self) -> str:
        with self._lock:
            asset = dict(self._asset) if self._asset else None
            rel = self._release
        if not self.enabled():
            return "disabled"
        if asset is None or not asset.get("browser_download_url"):
            self._fail_install("no installer to download")
            return "error"
        setup_name = str(asset.get("name") or "TNT-Setup.exe")
        folder = Path(self._temp_dir_fn())
        try:
            folder.mkdir(parents=True, exist_ok=True)
            target = folder / setup_name
            self._set_state("downloading")
            with self._lock:
                self._download = {"received": 0, "total": asset.get("size"), "phase": "download"}
                self._error = None
            self._publish()
            digest = self._download_asset(str(asset["browser_download_url"]), target)
            self._set_state("verifying")
            with self._lock:
                if self._download is not None:
                    self._download["phase"] = "verify"
            self._publish()
            expected = self._fetch_expected_checksum(rel, setup_name)
            if not expected:
                raise VerifyError("the release did not publish a SHA-256 checksum; refusing to install")
            if digest.lower() != expected.lower():
                raise VerifyError("the downloaded installer did not match the published SHA-256 checksum")
            self._set_state("installing")
            with self._lock:
                self._download = None
            self._publish()
            log.info("update verified (v%s); launching the installer", self._latest_version)
            self._installer_launch(str(target))
            return "installing"
        except Exception as exc:  # noqa: BLE001
            try:
                (folder / setup_name).unlink()
            except OSError:
                pass
            host = _host_text(getattr(exc, "host", None) or urlsplit(str(asset.get("browser_download_url") or "")).hostname)
            self._fail_install(friendly_error(exc, host))
            return "error"

    def _fail_install(self, text: str) -> None:
        with self._lock:
            self._error = text
            self._download = None
            self._state = "available" if self._asset else "error"
        log.warning("update install failed: %s", text)
        self._publish()

    def _fetch_expected_checksum(self, rel: Any, setup_name: str) -> Optional[str]:
        asset = pick_checksum_asset(rel.get("assets") if isinstance(rel, dict) else None, setup_name)
        if asset is None or not asset.get("browser_download_url"):
            return None
        resp = self._opener()(str(asset["browser_download_url"]), timeout=SOCKET_TIMEOUT_S)
        try:
            if int(resp.status) != 200:
                return None
            raw = resp.read_all(64 * 1024)
        finally:
            try:
                resp.close()
            except Exception:  # noqa: BLE001
                pass
        return parse_checksum(raw.decode("utf-8", "replace"), setup_name)

    def _download_asset(self, url: str, target: Path) -> str:
        resp = self._opener()(url, timeout=SOCKET_TIMEOUT_S)
        with self._lock:
            self._resp = resp
        h = sha256()
        received = 0
        buf = bytearray(READ_CHUNK)
        win_start, win_bytes = self._monotonic(), 0
        try:
            status = int(resp.status)
            host = getattr(resp, "host", None) or _host_text(urlsplit(url).hostname)
            if status != 200:
                raise DownloadError(f"HTTP {status} from {host}")
            total = None
            try:
                total = int(str({k.lower(): v for k, v in (resp.headers or {}).items()}.get("content-length", "")).strip())
                total = total if total >= 0 else None
            except (ValueError, AttributeError):
                total = None
            if total is not None and total > MAX_SETUP_BYTES:
                raise DownloadError("the installer is larger than expected")
            with open(target, "wb") as f:
                while True:
                    n = resp.readinto(buf)
                    if self._stop.is_set():
                        raise DownloadError("cancelled")
                    if not n:
                        break
                    received += n
                    if received > MAX_SETUP_BYTES:
                        raise DownloadError("the installer is larger than expected")
                    win_bytes += n
                    tnow = self._monotonic()
                    if tnow - win_start >= STALL_WINDOW_S:
                        if win_bytes < STALL_MIN_BYTES:
                            raise DownloadError("the download stalled (less than 1 MB in 5 min)")
                        win_start, win_bytes = tnow, 0
                    h.update(memoryview(buf)[:n])
                    f.write(memoryview(buf)[:n])
                    with self._lock:
                        if self._download is not None:
                            self._download["received"] = received
                    tick = time.monotonic()
                    if tick - self._progress_at >= PROGRESS_EVENT_S:
                        self._progress_at = tick
                        self._publish()
                f.flush()
                os.fsync(f.fileno())
            if total is not None and total != received:
                raise DownloadError("the download was cut short")
            return h.hexdigest()
        finally:
            try:
                resp.close()
            except Exception:  # noqa: BLE001
                pass
            with self._lock:
                self._resp = None


def _parse_iso(value: object) -> Optional[float]:
    """A GitHub ISO-8601 UTC timestamp ("2026-09-13T12:00:00Z") -> epoch seconds, or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        import datetime
        return datetime.datetime.fromisoformat(text).timestamp()
    except (ValueError, OverflowError, OSError):
        return None
