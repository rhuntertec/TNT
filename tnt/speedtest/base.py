"""Shared types and HTTP transfer machinery for the speed-test backends.

This module holds everything the built-in HTTP backends (Cloudflare, fast.com)
have in common so each backend is only a thin description of *which* URLs to
hit:

* :class:`SpeedResult` - the result record every backend returns (and the
  scheduler persists via ``db.add_speedtest``).
* :class:`SpeedBackend` - the protocol a backend implements.
* :class:`Http` - a tiny keep-alive wrapper over ``http.client`` with a socket
  timeout, streaming download (``readinto`` into a reusable buffer) and
  streaming upload (``send`` in blocks) so the byte counters advance while
  the transfer is in flight and a phase can be aborted mid-request.
* :class:`TransferPhase` - accounting for one multi-connection phase
  (download or upload): byte budget, time budget, cancel event, progress
  callbacks and the final Mbps figure. Mbps = bytes * 8 / wall seconds of
  the phase, where the wall clock runs from the phase start to the moment
  the last byte was counted (ramp-up included, trailing straggler time
  excluded).

  Downloads count bytes as they are read from the socket (they have
  provably arrived). Uploads must not: ``send()`` returns as soon as the
  kernel has buffered the data and Windows' dynamic send buffering absorbs
  megabytes per connection, so a 20 MB budget can be "sent" before half of
  it is on the wire (measured here: 364 Mbps counted vs 217 Mbps actually
  acknowledged). Upload phases therefore run in *acked* mode: bytes only
  count once the server's response to the request has arrived
  (:meth:`TransferPhase.ack`), the byte budget stops *new* requests but lets
  in-flight ones finish within a short tail (:data:`TAIL_GRACE_S`), and
  requests are sized adaptively (:func:`next_request_size`) so slow links
  still complete requests inside the time budget.
* :class:`RunGuard` - the cancel event plus the ``speedtest.timeout_s``
  deadline of one run, quacking like an ``Event`` so every step can be
  handed the same abort flag. A hung server therefore cannot hold the
  scheduler beyond ``timeout_s`` plus the one blocking call in progress
  (a recv/send bounded by the socket timeout; a connect may try each
  resolved address in turn, and ``getaddrinfo`` itself is bounded only by
  the OS resolver). Transfer workers are daemon threads that the phase
  abandons rather than waits for, so a stuck socket never blocks the run.
* :func:`measure_latency` - N small GETs on one keep-alive connection;
  latency = median, jitter = mean absolute difference between consecutive
  samples. One un-counted warm-up request establishes the connection first
  so the TLS handshake does not pollute the samples.
* Rate limiting (HTTP 429, and 403 which Cloudflare uses for bot blocks):
  :func:`parse_retry_after` / :func:`retry_after_s` read a ``Retry-After``
  header (delta-seconds or HTTP-date; default :data:`DEFAULT_RETRY_AFTER_S`,
  clamped to :data:`MIN_RETRY_AFTER_S`..:data:`MAX_RETRY_AFTER_S`);
  :func:`rate_limited_result` builds the failed result every backend returns
  when it is being refused (``error`` starts with ``"rate limited"``, ``raw``
  carries ``rate_limited``/``retry_after_s``/``http_status``) and puts the
  backend on **cooldown**. The cooldown registry (:func:`set_cooldown`,
  :func:`get_cooldown`, :func:`clear_cooldowns`) is module-level and
  thread-safe so every backend and the scheduler share one view: a backend on
  cooldown reports ``available() == (False, "cooling down after HTTP 429
  until HH:MM")`` and ``select_backend`` picks the other backend.
  ``cooldown_clock`` is the wall clock the registry uses (patched by tests).

Everything here is thread-based, every blocking call has a timeout, and no
function in this module ever calls ``print``.
"""
from __future__ import annotations

import email.utils
import http.client
import logging
import os
import ssl
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import timezone
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple, runtime_checkable

log = logging.getLogger(__name__)

#: A browser-like User-Agent. speed.cloudflare.com answers 403 to the default
#: Python UA; identifying the tool at the end of a real browser UA works fine.
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 TNT/1.0"
)

#: Socket timeout (seconds) applied to connect and to every recv/send.
SOCKET_TIMEOUT_S = 10.0
#: Size of the read buffer used for streaming downloads.
READ_CHUNK = 256 * 1024
#: Size of the blocks written during streaming uploads.
SEND_CHUNK = 64 * 1024
#: How long in-flight requests of an *acked* phase may still complete after
#: the byte/time budget was reached before they are abandoned (uncounted).
TAIL_GRACE_S = 1.0
#: Error string of a result whose run was cancelled (service stopping).
CANCELLED = "cancelled"
#: HTTP statuses that mean "this IP is being refused": 429 Too Many Requests and the
#: 403 speed.cloudflare.com answers to clients it classifies as bots.
RATE_LIMIT_STATUSES = (429, 403)
#: Cooldown applied when a rate-limit response carries no usable ``Retry-After``.
DEFAULT_RETRY_AFTER_S = 900
#: Bounds for the cooldown derived from ``Retry-After`` (a server asking for "0" still
#: gets a minute of quiet; nothing is ever honoured beyond an hour).
MIN_RETRY_AFTER_S = 60
MAX_RETRY_AFTER_S = 3600
#: Error prefix of a rate-limited result (the scheduler keys off ``raw["rate_limited"]``).
RATE_LIMITED_PREFIX = "rate limited"

ProgressFn = Callable[[str, float], None]


class Cancelled(Exception):
    """Raised inside a backend when the cancel event is set."""


class RunGuard:
    """Abort flag of one run: the caller's cancel event *or* the run deadline.

    Only the ``is_set()`` half of ``threading.Event`` is implemented, which is
    all :class:`TransferPhase` and :func:`check_cancel` use, so one guard can be
    threaded through every step of a run.
    """

    def __init__(self, cancel: Optional[threading.Event], timeout_s: float,
                 clock: Callable[[], float] = time.perf_counter) -> None:
        self.cancel = cancel if cancel is not None else threading.Event()
        self.timeout_s = max(1.0, float(timeout_s))
        self._clock = clock
        self._deadline = clock() + self.timeout_s

    def is_set(self) -> bool:
        return self.cancel.is_set() or self._clock() >= self._deadline

    @property
    def cancelled(self) -> bool:
        return self.cancel.is_set()

    @property
    def timed_out(self) -> bool:
        return not self.cancel.is_set() and self._clock() >= self._deadline

    def remaining(self) -> float:
        return max(0.0, self._deadline - self._clock())

    def socket_timeout(self) -> float:
        """Per-socket timeout for new connections: never past the run deadline."""
        return max(1.0, min(SOCKET_TIMEOUT_S, self.remaining()))

    @staticmethod
    def timeout_for(cancel: Any) -> float:
        """Socket timeout to use with *cancel* (a guard, a plain Event or None)."""
        fn = getattr(cancel, "socket_timeout", None)
        try:
            return float(fn()) if callable(fn) else SOCKET_TIMEOUT_S
        except Exception:  # noqa: BLE001
            return SOCKET_TIMEOUT_S

    def reason(self) -> str:
        """Error text for a run that ended because of this guard."""
        if self.cancel.is_set():
            return CANCELLED
        return f"timed out after {self.timeout_s:g} s (speedtest.timeout_s)"


class HttpError(Exception):
    """A non-success HTTP status (with the response headers, for ``Retry-After``)."""

    def __init__(self, status: int, path: str, detail: str = "", headers: Optional[Dict[str, str]] = None) -> None:
        super().__init__(f"HTTP {status} for {path}{(': ' + detail) if detail else ''}")
        self.status = status
        self.path = path
        self.detail = detail
        self.headers: Dict[str, str] = dict(headers or {})

    @property
    def rate_limited(self) -> bool:
        return self.status in RATE_LIMIT_STATUSES

    @property
    def retry_after(self) -> Optional[int]:
        """Seconds from the response's ``Retry-After`` header, or None when it has none."""
        return parse_retry_after(self.headers.get("retry-after"))


# --------------------------------------------------------------------------- rate limiting

def parse_retry_after(value: Optional[str], now: Optional[float] = None) -> Optional[int]:
    """``Retry-After`` header value -> whole seconds, or None when absent/unparseable.

    Accepts delta-seconds (``"3400"``, ``"12.5"``) and an HTTP-date (RFC 7231
    IMF-fixdate or the obsolete RFC 850 / asctime forms), which is converted to
    the seconds remaining from *now* (never negative).
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        secs = float(text)
    except ValueError:
        secs = None
    if secs is not None:
        if secs != secs or secs in (float("inf"), float("-inf")):   # NaN / inf
            return None
        return max(0, int(secs))
    try:
        when = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    try:
        target = when.timestamp()
    except (OverflowError, OSError, ValueError):
        return None
    base_now = float(now) if now is not None else time.time()
    return max(0, int(target - base_now))


def clamp_retry_after(seconds: Optional[float]) -> int:
    """Cooldown seconds to honour: *seconds* (or the default when None) clamped to
    ``MIN_RETRY_AFTER_S``..``MAX_RETRY_AFTER_S``."""
    secs = DEFAULT_RETRY_AFTER_S if seconds is None else seconds
    try:
        secs = float(secs)
    except (TypeError, ValueError):
        secs = float(DEFAULT_RETRY_AFTER_S)
    if secs != secs:   # NaN
        secs = float(DEFAULT_RETRY_AFTER_S)
    return int(max(MIN_RETRY_AFTER_S, min(MAX_RETRY_AFTER_S, secs)))


def retry_after_s(value: Optional[str], now: Optional[float] = None) -> int:
    """Cooldown seconds for a rate-limit response: the parsed ``Retry-After`` header
    (or the default when absent/unparseable) clamped by :func:`clamp_retry_after`."""
    return clamp_retry_after(parse_retry_after(value, now))


#: Wall clock of the cooldown registry (module attribute so tests can patch it).
cooldown_clock: Callable[[], float] = time.time
_cooldown_lock = threading.Lock()
_cooldowns: Dict[str, "Cooldown"] = {}


@dataclass(frozen=True)
class Cooldown:
    """One backend's cooldown: refused with *status* at *since*, quiet until *until* (epoch s)."""

    backend: str
    since: float
    until: float
    status: int

    def remaining(self, now: Optional[float] = None) -> float:
        base_now = float(now) if now is not None else float(cooldown_clock())
        return max(0.0, self.until - base_now)

    def describe(self) -> str:
        """``"cooling down after HTTP 429 until 14:05"`` (local time)."""
        return f"cooling down after HTTP {self.status} until {format_local_hhmm(self.until)}"


def format_local_hhmm(ts: float) -> str:
    try:
        return time.strftime("%H:%M", time.localtime(float(ts)))
    except (OverflowError, OSError, ValueError):
        return "?"


def set_cooldown(backend: str, seconds: float, status: int = 429, now: Optional[float] = None) -> Cooldown:
    """Put *backend* on cooldown for *seconds* (extends an existing one, never shortens it)."""
    name = str(backend or "").lower()
    base_now = float(now) if now is not None else float(cooldown_clock())
    until = base_now + max(0.0, float(seconds))
    with _cooldown_lock:
        cur = _cooldowns.get(name)
        if cur is not None and cur.until >= until and cur.until > base_now:
            return cur
        cd = Cooldown(backend=name, since=base_now, until=until, status=int(status))
        _cooldowns[name] = cd
    log.warning("speedtest backend %s on cooldown for %.0f s (HTTP %d) - until %s",
                name, until - base_now, cd.status, format_local_hhmm(until))
    return cd


def get_cooldown(backend: str, now: Optional[float] = None) -> Optional[Cooldown]:
    """The active cooldown of *backend*, or None (expired entries are dropped)."""
    name = str(backend or "").lower()
    base_now = float(now) if now is not None else float(cooldown_clock())
    with _cooldown_lock:
        cd = _cooldowns.get(name)
        if cd is None:
            return None
        if cd.until <= base_now:
            del _cooldowns[name]
            return None
        return cd


def all_cooldowns(now: Optional[float] = None) -> Dict[str, Cooldown]:
    """``{backend: Cooldown}`` for every backend currently cooling down."""
    base_now = float(now) if now is not None else float(cooldown_clock())
    with _cooldown_lock:
        expired = [k for k, v in _cooldowns.items() if v.until <= base_now]
        for k in expired:
            del _cooldowns[k]
        return dict(_cooldowns)


def clear_cooldowns(backend: Optional[str] = None) -> None:
    with _cooldown_lock:
        if backend is None:
            _cooldowns.clear()
        else:
            _cooldowns.pop(str(backend).lower(), None)


def is_rate_limited(result: Any) -> bool:
    """True for a :class:`SpeedResult` (or its dict) flagged ``raw["rate_limited"]``."""
    raw = getattr(result, "raw", None)
    if raw is None and isinstance(result, dict):
        raw = result.get("raw")
    return bool(isinstance(raw, dict) and raw.get("rate_limited"))


# --------------------------------------------------------------------------- results

@dataclass
class SpeedResult:
    """One speed-test run. All rates are Mbps (decimal megabits), times in ms."""

    ok: bool
    ts: float
    backend: str
    server: Optional[str] = None
    isp: Optional[str] = None
    external_ip: Optional[str] = None
    latency_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    download_mbps: Optional[float] = None
    upload_mbps: Optional[float] = None
    packet_loss_pct: Optional[float] = None
    duration_s: float = 0.0
    error: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Plain JSON-able dict (also the shape ``db.add_speedtest`` accepts)."""
        d = asdict(self)
        if not isinstance(d.get("raw"), dict):
            d["raw"] = {}
        return d


def failed_result(backend: str, ts: float, error: str, duration_s: float = 0.0,
                  raw: Optional[Dict[str, Any]] = None, **fields: Any) -> SpeedResult:
    """Convenience constructor for an ``ok=False`` result."""
    return SpeedResult(ok=False, ts=ts, backend=backend, error=error, duration_s=round(duration_s, 3),
                       raw=raw or {}, **fields)


def rate_limited_result(backend: str, ts: float, status: int, retry_after: Optional[int], detail: str = "",
                        duration_s: float = 0.0, raw: Optional[Dict[str, Any]] = None,
                        cooldown: bool = True, **fields: Any) -> SpeedResult:
    """The failed result of a run the server refused (HTTP 429/403).

    ``error`` starts with ``"rate limited"`` and names the status and the cooldown;
    ``raw`` gains ``rate_limited=True``, ``retry_after_s`` (clamped, see
    :func:`retry_after_s`) and ``http_status``. Unless *cooldown* is False the
    backend is put on cooldown for ``retry_after_s`` at the same time, so
    ``available()`` reports it and the scheduler picks another backend.
    """
    secs = clamp_retry_after(retry_after)
    what = f"HTTP {int(status)}" + (" forbidden" if int(status) == 403 else "")
    text = f"{RATE_LIMITED_PREFIX} ({what}, retry after {secs} s)"
    if detail:
        text += f": {str(detail).strip()[:160]}"
    out = dict(raw or {})
    out.update({"rate_limited": True, "retry_after_s": secs, "http_status": int(status)})
    if cooldown:
        set_cooldown(backend, secs, status=int(status))
    return failed_result(backend, ts, text, duration_s, out, **fields)


@runtime_checkable
class SpeedBackend(Protocol):
    """What the scheduler needs from a backend."""

    name: str

    def available(self, config: Any) -> Tuple[bool, str]:
        """``(ok, reason/details)`` - cheap; may be called from status polls."""
        ...

    def run(self, config: Any, progress: Optional[ProgressFn] = None,
            cancel: Optional[threading.Event] = None) -> SpeedResult:
        """Run a full test. Never raises; returns ``ok=False`` with ``error`` instead."""
        ...


# --------------------------------------------------------------------------- maths

def median(values: List[float]) -> Optional[float]:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def mean_abs_delta(values: List[float]) -> Optional[float]:
    """Jitter: mean absolute difference between consecutive samples."""
    if len(values) < 2:
        return 0.0 if values else None
    return sum(abs(b - a) for a, b in zip(values, values[1:])) / (len(values) - 1)


def mbps(nbytes: int, seconds: float) -> Optional[float]:
    """Decimal megabits per second, or None when nothing was measured."""
    if nbytes <= 0 or seconds <= 0:
        return None
    return nbytes * 8.0 / seconds / 1e6


def next_request_size(sent: int, elapsed_s: float, target_s: float, lo: int, hi: int) -> int:
    """Size of the next upload body so that it takes about *target_s* at the rate just seen."""
    lo, hi = int(lo), max(int(lo), int(hi))
    if sent <= 0 or elapsed_s <= 0:
        return lo
    want = int(float(sent) / float(elapsed_s) * float(target_s))
    return max(lo, min(hi, want))


def check_cancel(cancel: Any) -> None:
    """Raise :class:`Cancelled` when *cancel* (an Event or :class:`RunGuard`) is set."""
    if cancel is not None and cancel.is_set():
        raise Cancelled(CANCELLED)


# --------------------------------------------------------------------------- HTTP

_ssl_lock = threading.Lock()
_ssl_ctx: Optional[ssl.SSLContext] = None
_upload_block: Optional[bytes] = None


def ssl_context() -> ssl.SSLContext:
    """One verified default context shared by all connections (thread-safe)."""
    global _ssl_ctx
    with _ssl_lock:
        if _ssl_ctx is None:
            _ssl_ctx = ssl.create_default_context()
        return _ssl_ctx


def upload_block() -> bytes:
    """A block of incompressible bytes reused for every upload send()."""
    global _upload_block
    with _ssl_lock:
        if _upload_block is None:
            _upload_block = os.urandom(SEND_CHUNK)
        return _upload_block


@dataclass
class HttpReply:
    status: int
    headers: Dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class Http:
    """Keep-alive ``http.client`` connection with a socket timeout.

    One instance per thread; it is not thread-safe. Any error leaves the
    connection closed; the next call reconnects transparently.
    """

    def __init__(self, host: str, port: Optional[int] = None, scheme: str = "https",
                 timeout: float = SOCKET_TIMEOUT_S, user_agent: str = BROWSER_UA) -> None:
        self.host = host
        self.scheme = scheme
        self.port = port if port is not None else (443 if scheme == "https" else 80)
        self.timeout = float(timeout)
        self.user_agent = user_agent
        self._conn: Optional[http.client.HTTPConnection] = None

    # -- connection management --------------------------------------------
    def _connection(self) -> http.client.HTTPConnection:
        if self._conn is None:
            if self.scheme == "https":
                self._conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=ssl_context())
            else:
                self._conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        return self._conn

    def close(self) -> None:
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {"User-Agent": self.user_agent, "Accept": "*/*", "Connection": "keep-alive",
             "Cache-Control": "no-cache"}
        if extra:
            h.update(extra)
        return h

    @staticmethod
    def _header_dict(resp: http.client.HTTPResponse) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for k, v in resp.getheaders():
            k = k.lower()
            out[k] = (out[k] + ", " + v) if k in out else v
        return out

    # -- small requests ---------------------------------------------------
    def get(self, path: str, max_bytes: int = 4 * 1024 * 1024, check: bool = True,
            headers: Optional[Dict[str, str]] = None) -> HttpReply:
        """GET a small resource. Raises :class:`HttpError` on status >= 400 when *check*."""
        try:
            conn = self._connection()
            conn.request("GET", path, headers=self._headers(headers))
            resp = conn.getresponse()
            chunks: List[bytes] = []
            total = 0
            while True:
                chunk = resp.read(min(READ_CHUNK, max_bytes - total + 1))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    self.close()
                    raise HttpError(resp.status, path, "response too large")
            reply = HttpReply(resp.status, self._header_dict(resp), b"".join(chunks))
        except Exception:
            self.close()
            raise
        if check and reply.status >= 400:
            self.close()
            raise HttpError(reply.status, path, reply.text[:120].strip(), headers=reply.headers)
        return reply

    # -- streaming --------------------------------------------------------
    def download(self, path: str, on_bytes: Callable[[int], bool],
                 headers: Optional[Dict[str, str]] = None) -> Tuple[int, int, bool]:
        """Stream a GET body, calling ``on_bytes(n)`` per chunk.

        ``on_bytes`` returns False to abort (the connection is then closed so it
        cannot be reused). Returns ``(status, bytes_received, aborted)``.
        Raises :class:`HttpError` for a non-200 status.
        """
        buf = bytearray(READ_CHUNK)
        view = memoryview(buf)
        received = 0
        try:
            conn = self._connection()
            conn.request("GET", path, headers=self._headers(headers))
            resp = conn.getresponse()
            if resp.status not in (200, 206):
                headers = self._header_dict(resp)
                try:
                    detail = resp.read(200).decode("utf-8", errors="replace").strip()
                finally:
                    self.close()
                raise HttpError(resp.status, path, detail, headers=headers)
            while True:
                n = resp.readinto(view)
                if not n:
                    break
                received += n
                if not on_bytes(n):
                    self.close()
                    return resp.status, received, True
            return resp.status, received, False
        except Exception:
            self.close()
            raise

    def upload(self, path: str, size: int, on_bytes: Callable[[int], bool],
               headers: Optional[Dict[str, str]] = None) -> Tuple[Optional[int], int, bool]:
        """Stream a POST body of *size* bytes, calling ``on_bytes(n)`` per block.

        Returns ``(status or None if aborted, bytes_sent, aborted)``.
        Raises :class:`HttpError` for a non-2xx status.
        """
        block = upload_block()
        sent = 0
        try:
            conn = self._connection()
            conn.putrequest("POST", path)
            for k, v in self._headers(headers).items():
                conn.putheader(k, v)
            conn.putheader("Content-Type", "application/octet-stream")
            conn.putheader("Content-Length", str(int(size)))
            conn.endheaders()
            remaining = int(size)
            while remaining > 0:
                n = min(len(block), remaining)
                conn.send(block if n == len(block) else block[:n])
                remaining -= n
                sent += n
                if not on_bytes(n):
                    self.close()
                    return None, sent, True
            resp = conn.getresponse()
            body = resp.read(4096)
            while resp.read(READ_CHUNK):
                pass
            if resp.status >= 300:
                self.close()
                raise HttpError(resp.status, path, body[:120].decode("utf-8", errors="replace"),
                                headers=self._header_dict(resp))
            return resp.status, sent, False
        except Exception:
            self.close()
            raise


# --------------------------------------------------------------------------- phases

@dataclass
class PhaseStats:
    name: str
    bytes: int
    seconds: float
    requests: int
    errors: int
    aborted: bool
    mbps: Optional[float]
    acked_bytes: int = 0
    mbps_full: Optional[float] = None   # whole-phase figure incl. ramp-up (mbps excludes it when possible)
    rate_limit_hits: int = 0            # HTTP 429/403 responses seen (incl. ones a smaller chunk got around)
    rate_limited: int = 0               # workers that gave up because the server kept refusing them
    retry_after_s: Optional[int] = None  # largest Retry-After seen (parsed seconds), if any
    rate_limit_status: Optional[int] = None  # the refusing status (429 or 403), if any

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["seconds"] = round(self.seconds, 3)
        d["mbps"] = round(self.mbps, 3) if self.mbps is not None else None
        d["mbps_full"] = round(self.mbps_full, 3) if self.mbps_full is not None else None
        return d

    def rate_limited_phase(self, connections: int) -> bool:
        """True when the server refused the phase as a whole: every worker gave up on
        429/403, or at least one did and nothing was counted at all."""
        if self.rate_limited <= 0:
            return False
        return self.rate_limited >= max(1, int(connections)) or self.mbps is None


class TransferPhase:
    """Shared accounting for one multi-connection transfer phase.

    Workers call :meth:`should_stop` before starting a request and
    :meth:`on_bytes` for every chunk moved; the latter returns False when the
    current request must be aborted. :meth:`run` starts the worker threads,
    emits throttled progress and returns the phase statistics.

    Two modes:

    * received (default, downloads): every counted byte has arrived, so the
      byte/time budget aborts in-flight requests at once and Mbps = bytes /
      (last byte - start).
    * acked (``acked=True``, uploads): bytes only count once the worker calls
      :meth:`ack` after the server's response arrived. The byte budget stops
      new requests but in-flight ones may complete for ``tail_s`` more seconds
      (the time budget likewise), after which they are abandoned and *not*
      counted; acks arriving after the phase closed are ignored. Mbps =
      acked bytes / (last ack - start).
    """

    #: A phase keeps transferring for at least this long even when the byte budget is
    #: already reached (a fast link empties 20 MB inside TCP slow start; the reading would
    #: swing 3x between runs) - bounded by ``max_bytes_factor`` x the budget.
    MIN_DURATION_S = 1.5
    MAX_BYTES_FACTOR = 3.0
    #: Mbps is computed over the steady part of the phase: the first quarter (connection
    #: ramp-up / slow start) is excluded when the phase is long enough to allow it.
    RAMP_FRACTION = 0.25
    STEADY_MIN_S = 0.3

    def __init__(self, name: str, duration_s: float, byte_budget: int,
                 cancel: Any = None, progress: Optional[ProgressFn] = None,
                 clock: Callable[[], float] = time.perf_counter, grace_s: float = SOCKET_TIMEOUT_S + 3.0,
                 acked: bool = False, tail_s: float = TAIL_GRACE_S,
                 min_duration_s: Optional[float] = None, max_bytes_factor: Optional[float] = None) -> None:
        self.name = name
        self.duration_s = max(0.5, float(duration_s))
        self.byte_budget = max(1, int(byte_budget))
        self.min_duration_s = min(self.duration_s, float(self.MIN_DURATION_S if min_duration_s is None else min_duration_s))
        self.max_bytes_factor = max(1.0, float(self.MAX_BYTES_FACTOR if max_bytes_factor is None else max_bytes_factor))
        self._trace: List[Tuple[float, int]] = []   # (ts, cumulative counted bytes) for the steady-state figure
        self._last_trace_ts = -1.0
        self.cancel = cancel if cancel is not None else threading.Event()
        self.grace_s = float(grace_s)
        self.acked = bool(acked)
        self.tail_s = max(0.0, float(tail_s)) if self.acked else 0.0
        self._progress = progress
        self._clock = clock
        self._lock = threading.Lock()
        self._bytes = 0
        self._acked_bytes = 0
        self._requests = 0
        self._errors = 0
        self._rate_limit_hits = 0
        self._rate_limited = 0
        self._retry_after: Optional[int] = None
        self._rate_limit_status: Optional[int] = None
        self._start: Optional[float] = None
        self._last_byte_ts: Optional[float] = None
        self._last_ack_ts: Optional[float] = None
        self._ended_at: Optional[float] = None    # budget reached: no new requests
        self._stop = threading.Event()            # phase closed: abort everything
        self._last_emit = 0.0

    # -- worker side --------------------------------------------------------
    @property
    def bytes(self) -> int:
        with self._lock:
            return self._bytes

    @property
    def acked_bytes(self) -> int:
        with self._lock:
            return self._acked_bytes

    def remaining_bytes(self, hard: bool = False) -> int:
        """Bytes still to move before the budget - or, with *hard*, before the phase's
        absolute cap (``max_bytes_factor`` x budget).

        Size requests against the *hard* figure: the phase keeps transferring after the
        budget until ``min_duration_s`` has elapsed, and sizing against the soft budget
        shrinks every request in that stretch to the worker's minimum (that alone made a
        gigabit run issue ~50 downloads and ~130 uploads; per-request rate limits punish
        exactly that).
        """
        with self._lock:
            cap = int(self.byte_budget * self.max_bytes_factor) if hard else self.byte_budget
            return max(0, cap - self._bytes)

    def note_rate_limit(self, retry_after: Optional[int] = None, gave_up: bool = False,
                        status: int = 429) -> None:
        """Record a 429/403 response; *gave_up* when the worker stops because of it."""
        with self._lock:
            self._rate_limit_hits += 1
            self._rate_limit_status = int(status)
            if gave_up:
                self._rate_limited += 1
            if retry_after is not None:
                ra = int(retry_after)
                self._retry_after = ra if self._retry_after is None else max(self._retry_after, ra)

    def _ended(self, now: float) -> Optional[float]:
        """Time the budget was reached (checking the time budget too). Call under the lock."""
        if self._ended_at is None and self._start is not None and now - self._start >= self.duration_s:
            self._ended_at = now
        return self._ended_at

    def _closed(self, now: float) -> bool:
        """True when in-flight requests must be aborted. Call under the lock."""
        if self._stop.is_set():
            return True
        ended = self._ended(now)
        if ended is None:
            return False
        if now - ended >= self.tail_s:
            self._stop.set()
            return True
        return False

    def _budget_reached(self, now: float) -> bool:
        """Byte budget semantics (call under the lock): reached once the budget is moved AND
        the phase ran for ``min_duration_s``, or when ``max_bytes_factor`` x budget is moved."""
        moved = self._bytes   # bytes handed to the network (acked mode: acks are counted for Mbps only)
        if moved >= self.byte_budget * self.max_bytes_factor:
            return True
        if moved < self.byte_budget:
            return False
        return self._start is None or now - self._start >= self.min_duration_s

    def _trace_point(self, now: float, counted: int) -> None:
        if now - self._last_trace_ts >= 0.02:
            self._trace.append((now, counted))
            self._last_trace_ts = now

    def add_bytes(self, n: int) -> None:
        now = self._clock()
        with self._lock:
            self._bytes += int(n)
            self._last_byte_ts = now
            if not self.acked:
                self._trace_point(now, self._bytes)
            if self._ended_at is None and self._budget_reached(now):
                self._ended_at = now

    def ack(self, n: int) -> bool:
        """Count *n* server-acknowledged bytes. False (not counted) once the phase closed."""
        now = self._clock()
        with self._lock:
            if self._closed(now):
                return False
            self._acked_bytes += int(n)
            self._last_ack_ts = now
            self._trace_point(now, self._acked_bytes)
            return True

    def _steady_mbps(self, start: float, end: float, total: int) -> Optional[float]:
        """Throughput over the phase minus its ramp-up quarter (None when too short to tell)."""
        elapsed = end - start
        if elapsed <= 0 or self.RAMP_FRACTION <= 0:
            return None
        cutoff = start + self.RAMP_FRACTION * elapsed
        for ts, counted in self._trace:
            if ts >= cutoff:
                if end - ts < self.STEADY_MIN_S or total <= counted:
                    return None
                return mbps(total - counted, end - ts)
        return None

    def add_request(self) -> None:
        with self._lock:
            self._requests += 1

    def add_error(self) -> None:
        with self._lock:
            self._errors += 1

    def should_stop(self) -> bool:
        """True when no new request should be started."""
        if self._stop.is_set() or self.cancel.is_set():
            return True
        now = self._clock()
        with self._lock:
            if self._ended(now) is None:
                return False
            self._closed(now)
            return True

    def on_bytes(self, n: int) -> bool:
        """Count *n* bytes; returns False when the current request must be aborted."""
        self.add_bytes(n)
        if self.cancel.is_set():
            return False
        with self._lock:
            return not self._closed(self._clock())

    def wait(self, seconds: float) -> None:
        """Sleep that wakes early when the phase is over."""
        self._stop.wait(seconds)

    def fraction(self) -> float:
        with self._lock:
            start = self._start
            nbytes = self._bytes
        if start is None:
            return 0.0
        f_time = (self._clock() - start) / self.duration_s
        f_bytes = nbytes / float(self.byte_budget)
        return max(0.0, min(1.0, max(f_time, f_bytes)))

    # -- controller side ----------------------------------------------------
    def _emit(self, value: Optional[float] = None) -> None:
        if self._progress is None:
            return
        now = time.monotonic()
        if value is None and now - self._last_emit < 0.2:
            return
        self._last_emit = now
        try:
            self._progress(self.name, self.fraction() if value is None else float(value))
        except Exception:  # noqa: BLE001
            log.exception("speedtest progress callback failed")

    def _guard(self, worker: Callable[["TransferPhase", int], None], idx: int) -> None:
        try:
            worker(self, idx)
        except Exception:  # noqa: BLE001
            self.add_error()
            log.exception("speedtest %s worker %d crashed", self.name, idx)

    def run(self, worker: Callable[["TransferPhase", int], None], connections: int) -> PhaseStats:
        connections = max(1, int(connections))
        with self._lock:
            self._start = self._clock()
        self._emit(0.0)
        threads: List[threading.Thread] = []
        for i in range(connections):
            t = threading.Thread(target=self._guard, args=(worker, i), name=f"speedtest-{self.name}-{i}", daemon=True)
            threads.append(t)
            t.start()
        hard_deadline = (self._start or 0.0) + self.duration_s + self.tail_s + self.grace_s
        while True:
            alive = [t for t in threads if t.is_alive()]
            if not alive:
                break
            if self.cancel.is_set():
                # A worker blocked in recv()/send() only notices the cancel when data
                # flows or its socket times out (SOCKET_TIMEOUT_S); the caller (the
                # scheduler's stop()) must not wait for that, so abandon the workers.
                log.debug("speedtest %s cancelled with %d worker(s) still busy", self.name, len(alive))
                break
            now = self._clock()
            with self._lock:
                closed = self._closed(now)
            if closed:
                # Budget (+ tail) reached: workers abort at their next chunk; a
                # worker blocked waiting for a straggling response is abandoned
                # below and its late ack is ignored by ack().
                break
            if now >= hard_deadline:
                log.warning("speedtest %s: %d worker(s) still busy after the hard deadline; abandoning them",
                            self.name, len(alive))
                break
            alive[0].join(0.1)
            self._emit()
        self._stop.set()
        # Bounded wind-down: at most ~1 s in total whatever the connection count.
        join_deadline = time.monotonic() + 1.0
        for t in threads:
            if t.is_alive():
                t.join(max(0.0, join_deadline - time.monotonic()))
        with self._lock:
            start = self._start or self._clock()
            if self.acked:
                nbytes = self._acked_bytes
                last = self._last_ack_ts
            else:
                nbytes = self._bytes
                last = self._last_byte_ts
            end = last if last is not None else self._clock()
            elapsed = max(0.0, end - start)
            full = mbps(nbytes, elapsed)
            steady = self._steady_mbps(start, end, nbytes) if full is not None else None
            stats = PhaseStats(name=self.name, bytes=self._bytes, seconds=elapsed, requests=self._requests,
                               errors=self._errors, aborted=self.cancel.is_set(),
                               mbps=steady if steady is not None else full,
                               acked_bytes=self._acked_bytes, mbps_full=full,
                               rate_limit_hits=self._rate_limit_hits, rate_limited=self._rate_limited,
                               retry_after_s=self._retry_after, rate_limit_status=self._rate_limit_status)
        self._emit(1.0)
        return stats


# --------------------------------------------------------------------------- latency

def measure_latency(http_: Http, path: str, count: int = 8,
                    server_time: Optional[Callable[[Dict[str, str]], float]] = None,
                    cancel: Any = None, progress: Optional[ProgressFn] = None,
                    phase: str = "latency", clock: Callable[[], float] = time.perf_counter
                    ) -> Tuple[Optional[float], Optional[float], List[float]]:
    """*count* small GETs over one keep-alive connection.

    Returns ``(median_ms, jitter_ms, samples)``. When *server_time* is given it
    receives the response headers and returns the server-side processing time
    (ms) to subtract from each wall-clock sample. Raises :class:`Cancelled`,
    :class:`HttpError` or an ``OSError`` after repeated failures.
    """
    check_cancel(cancel)
    # Warm-up: establishes TCP/TLS so the handshake is not part of any sample.
    try:
        http_.get(path)
    except (OSError, http.client.HTTPException):
        http_.close()
        http_.get(path)
    samples: List[float] = []
    failures = 0
    while len(samples) < count:
        check_cancel(cancel)
        t0 = clock()
        try:
            reply = http_.get(path)
        except (OSError, http.client.HTTPException) as exc:
            failures += 1
            http_.close()
            log.debug("latency probe failed (%d): %s", failures, exc)
            if failures > 2:
                raise
            continue
        dt = (clock() - t0) * 1000.0
        if server_time is not None:
            try:
                dt -= float(server_time(reply.headers) or 0.0)
            except Exception:  # noqa: BLE001
                log.debug("server-timing parse failed", exc_info=True)
        samples.append(max(0.0, dt))
        if progress is not None:
            try:
                progress(phase, len(samples) / float(count))
            except Exception:  # noqa: BLE001
                log.exception("speedtest progress callback failed")
    med = median(samples)
    jit = mean_abs_delta(samples)
    return (round(med, 2) if med is not None else None, round(jit, 2) if jit is not None else None, samples)


def budgets(config: Any) -> Dict[str, Any]:
    """Read the shared byte/time budgets from ``config`` with safe fallbacks."""
    try:
        sec = config.section("speedtest") or {}
    except Exception:  # noqa: BLE001
        sec = {}

    def _num(key: str, default: float, lo: float, hi: float) -> float:
        try:
            v = float(sec.get(key, default))
        except (TypeError, ValueError):
            v = default
        return max(lo, min(hi, v))

    return {
        "download_bytes": int(_num("download_mb", 50, 1, 2000) * 1_000_000),
        "upload_bytes": int(_num("upload_mb", 20, 1, 2000) * 1_000_000),
        "duration_s": _num("duration_s", 8, 2, 60),
        "connections": int(_num("connections", 4, 1, 16)),
        "timeout_s": _num("timeout_s", 120, 10, 600),
    }
