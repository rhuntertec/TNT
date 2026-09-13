"""Port-forward test for the Network info card (``POST /api/netcheck/portforward``; ARCHITECTURE §3.23).

A technician who has just forwarded a port to a camera or an NVR wants to know whether it answers from the internet.
Testing this network's own public address from inside the LAN proves nothing (many routers do not hairpin, others
answer with their own admin page), so :class:`PortChecker` asks a checker outside.  TCP only, one port per test, and
the target is ONLY this site's fresh public IPv4 address as the link map knows it: no other host, no port ranges, no
TNT listener.  The checker sees that address and the port; nothing else about the site leaves the PC.

Before anything is sent
-----------------------
:meth:`PortChecker.test` refuses, in this order:

1. a port that is not an ``int`` from 1 to 65535 (``bool`` is not one): ``ValueError`` :data:`PORTCHECK_PORT_TEXT`;
2. a NAT check verdict of ``vpn`` (the test would check the VPN's address): :class:`VpnActive`;
3. no fresh public IPv4 address (as in §2.3: an IPv4 literal whose ``ts`` is not older than the last network change).
   A stale one is looked up again once, through ``refresh_fn`` on a daemon helper thread (``tnt-portcheck-refresh``;
   a lookup still running from an earlier test is waited for instead of starting another) waited for at most
   ``refresh_wait_s``, then read again; still not fresh: :class:`NoPublicIp`;
4. a test already running: ``RuntimeError`` :data:`PORTCHECK_BUSY_TEXT`;
5. a test started less than ``min_gap_s`` ago, or ``per_hour`` tests started in the last 3600 s: :class:`RateLimited`
   "Too many tests: wait N s" with ``retry_after_s`` N (whole seconds, at least 1).  Only tests that got this far
   count, measured on ``monotonic``; a knob of 0 switches its limit off.

Providers
---------
One deadline of ``deadline_s`` covers both; each request's timeout is ``min(10 s, time left)``.

* **portchecker.io**: ``POST https://portchecker.io/api/query`` with ``{"host": ip, "ports": [port]}``.  A 200 whose
  ``error`` is false and whose ``check[0].port`` is the port gives ``check[0].status``.  Its checker makes one
  connect with a 1 s timeout, so a ``false`` is asked once more after ``retry_delay_s``: true is
  :data:`PORTCHECKER_OPEN_DETAIL`, false twice :data:`PORTCHECKER_CLOSED_DETAIL`.
* **Globalping**, only when portchecker.io errors (a network error, any status but 200 including 429, an unreadable
  body, ``error`` true, or a retry that errors): ``POST https://api.globalping.io/v1/measurements`` with a 3-packet
  TCP ping from one probe.  The 202 carries the measurement id, read back with ``GET /v1/measurements/<id>`` every
  ``poll_s`` until its ``status`` is ``finished`` or ``poll_max_s`` has passed.  The first probe result
  ``finished`` with ``stats.rcv`` > 0 is reachable and with 0 is not (:data:`GLOBALPING_DETAIL`); ``failed`` or
  ``offline`` is an error.

When both fail, ``reachable`` is None and ``error`` is :data:`PORTCHECK_FAILED_TEXT` with one short reason per
provider tried, e.g. "portchecker.io answered HTTP 429, Globalping did not answer in time".  Reasons are fixed phrases
(``REASON_*``), never an exception's or a server's own text, which could carry the address.

Shape (keys in this order; :data:`PORTCHECK_RESULT_KEYS`)::

    PORTCHECK_RESULT = {"ts", "generation", "port", "protocol": "tcp", "public_ip", "reachable": bool|None,
                        "provider": "portchecker.io"|"globalping", "detail": str|None, "nat_verdict": str|None,
                        "error": str|None, "duration_ms"}

``ts`` is the wall clock when the test was let through step 5 and ``duration_ms`` runs from then; ``generation`` is
the network generation read right before the address (the card ignores an answer for an older network),
``nat_verdict`` the NAT check's verdict at step 2 and ``provider`` the last provider asked.

Seams and knobs
---------------
``request`` stands in for the module seam :func:`_https_request` ``(method, host, path, body, timeout, headers) ->
(status, body)``.  Without it the seam is looked up as a module global when a test runs, so the tests/conftest.py
guard, which replaces it for the whole session, cannot be slipped past.  The real one, :func:`https_request`, is
stdlib ``http.client.HTTPSConnection`` to port 443 with a fresh default SSL context (certificate and host name
checked), no proxy and no redirects followed; the whole answer must arrive within the timeout and be at most
256 KiB, and ``User-Agent`` is ``TNT/<version>``.  ``clock``, ``monotonic``, ``sleep`` and the timer knobs are keyword
arguments (never settings; the engine uses the defaults), so tests run without waiting.

Logging: one INFO line per test run (``"Port-forward test: %s via %s in %d ms"``: reachable, provider, duration).
The address, the port, refusals and provider failures go to DEBUG only.
"""
from __future__ import annotations

import collections
import http.client
import ipaddress
import json
import logging
import math
import re
import socket
import ssl
import threading
import time
from typing import Any, Callable, Deque, Dict, NamedTuple, Optional, Tuple

from . import __version__

log = logging.getLogger(__name__)

__all__ = [
    "PortChecker", "RateLimited", "NoPublicIp", "VpnActive", "ResponseTooLarge", "Outcome", "https_request",
    "validate_port", "fresh_public_ip", "failure_reason", "parse_portchecker", "parse_globalping_created",
    "parse_globalping_measurement", "PORTCHECK_RESULT_KEYS", "PORTCHECK_PROTOCOL", "PROVIDERS",
    "PORTCHECK_PORT_TEXT", "PORTCHECK_VPN_TEXT", "PORTCHECK_NO_IP_TEXT", "PORTCHECK_BUSY_TEXT",
    "PORTCHECK_RATE_TEXT", "PORTCHECKER_OPEN_DETAIL", "PORTCHECKER_CLOSED_DETAIL", "GLOBALPING_DETAIL",
    "PORTCHECK_FAILED_TEXT", "USER_AGENT",
]

PORTCHECK_RESULT_KEYS = ("ts", "generation", "port", "protocol", "public_ip", "reachable", "provider", "detail",
                         "nat_verdict", "error", "duration_ms")
PORTCHECK_PROTOCOL = "tcp"
PROVIDER_PORTCHECKER = "portchecker.io"
PROVIDER_GLOBALPING = "globalping"
PROVIDERS = (PROVIDER_PORTCHECKER, PROVIDER_GLOBALPING)
#: How each provider is named in :data:`PORTCHECK_FAILED_TEXT`.
PROVIDER_NAMES: Dict[str, str] = {PROVIDER_PORTCHECKER: "portchecker.io", PROVIDER_GLOBALPING: "Globalping"}

# -- timer knobs (PortChecker keyword arguments; never settings) -------------------------------------------------------
DEADLINE_S = 35.0             # one deadline for both providers
RETRY_DELAY_S = 1.0           # before portchecker.io is asked again after a false
POLL_S = 1.0                  # before each Globalping read
POLL_MAX_S = 20.0             # Globalping reads stop this long after the measurement was created
MIN_GAP_S = 5.0               # between the starts of two tests
PER_HOUR = 30                 # tests started in any RATE_WINDOW_S
REFRESH_WAIT_S = 12.0         # the longest wait for the link map's public address lookup (its own timeout is 8 s)
RATE_WINDOW_S = 3600.0
#: Each request's timeout is ``min(REQUEST_TIMEOUT_S, time left before the deadline)``.
REQUEST_TIMEOUT_S = 10.0

# -- requests ----------------------------------------------------------------------------------------------------------
USER_AGENT = f"TNT/{__version__}"
HTTPS_PORT = 443
BODY_MAX = 256 * 1024         # the largest answer body read
READ_CHUNK = 64 * 1024
PORTCHECKER_HOST = "portchecker.io"
PORTCHECKER_PATH = "/api/query"
GLOBALPING_HOST = "api.globalping.io"
GLOBALPING_PATH = "/v1/measurements"
GLOBALPING_PACKETS = 3
REFRESH_THREAD_NAME = "tnt-portcheck-refresh"
#: A measurement id goes into a request path, so only these characters are accepted.
_MEASUREMENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")

# -- texts (the API answers them verbatim; the mock mirrors them) ------------------------------------------------------
PORTCHECK_PORT_TEXT = "port must be a whole number from 1 to 65535"
PORTCHECK_VPN_TEXT = ("This PC's internet goes through a VPN, so the test would check the VPN's address, not this "
                      "site's: disconnect the VPN first")
PORTCHECK_NO_IP_TEXT = ("This network's public IPv4 address is not known yet (or it has none): wait for the WAN "
                        "address on the link map, then test again")
PORTCHECK_BUSY_TEXT = "a port-forward test is already running"
PORTCHECK_RATE_TEXT = "Too many tests: wait {seconds} s"
PORTCHECKER_OPEN_DETAIL = "portchecker.io connected to the port"
PORTCHECKER_CLOSED_DETAIL = "portchecker.io could not connect (tried twice)"
GLOBALPING_DETAIL = "{answered} of {sent} connections answered (Globalping)"
#: ``reason`` is "<provider name> <REASON_*>" for each provider tried, joined with ", ".
PORTCHECK_FAILED_TEXT = "The port checkers could not be reached: {reason}"
REASON_TIMEOUT = "did not answer in time"
REASON_DNS = "could not be looked up (no DNS)"
REASON_CERTIFICATE = "has a certificate this PC does not trust"
REASON_TLS = "could not set up a secure connection"
REASON_CONNECT = "could not connect"
REASON_HTTP = "answered HTTP {status}"
REASON_UNREADABLE = "gave an unreadable answer"
REASON_REPORTED_ERROR = "reported an error"
REASON_PROBE_FAILED = "reported that its probe failed"
REASON_PROBE_OFFLINE = "reported that its probe was offline"
REASON_NO_RESULT = "had no result in time"
REASON_NOT_TRIED = "was not tried (no time left)"


class RateLimited(RuntimeError):
    """Too many tests in a short time (HTTP 429 ``rate_limited`` with ``Retry-After: <retry_after_s>``)."""

    def __init__(self, message: str, retry_after_s: int) -> None:
        super().__init__(message)
        self.retry_after_s = int(retry_after_s)


class NoPublicIp(RuntimeError):
    """No fresh public IPv4 address to test (HTTP 409 ``no_public_ip``)."""

    def __init__(self, message: str = PORTCHECK_NO_IP_TEXT) -> None:
        super().__init__(message)


class VpnActive(RuntimeError):
    """The NAT check found this PC's internet going through a VPN (HTTP 409 ``vpn``)."""

    def __init__(self, message: str = PORTCHECK_VPN_TEXT) -> None:
        super().__init__(message)


class ResponseTooLarge(ValueError):
    """An answer body over :data:`BODY_MAX` (a reason of :data:`REASON_UNREADABLE`)."""


class Outcome(NamedTuple):
    """What one provider found: ``reachable`` and ``detail``, or ``reason`` when it failed."""

    reachable: Optional[bool]
    detail: Optional[str]
    reason: Optional[str]


# --------------------------------------------------------------------------- pure helpers
def validate_port(port: Any) -> int:
    """*port* when it is an ``int`` from 1 to 65535 (not a ``bool``); ``ValueError`` otherwise."""
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(PORTCHECK_PORT_TEXT)
    return int(port)


def _seconds(value: Any) -> Optional[float]:
    """*value* as a time in seconds when it is a finite ``int`` or ``float`` (not a ``bool``), else None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        seconds = float(value)
    except OverflowError:
        return None
    return seconds if math.isfinite(seconds) else None


def fresh_public_ip(pip: Any, changed_ts: Any) -> Optional[str]:
    """The address in a link map ``public_ip`` dict (``{ip, ts, error, checked_ts}``) when it is fresh: an IPv4 literal
    with a ``ts``, and ``changed_ts`` (the last network change) None or not after that ``ts``.  None otherwise, which
    includes a ``ts`` or ``changed_ts`` that is not a time (such as :data:`_FAILED`, from a ``changed_ts_fn`` that
    raised)."""
    if not isinstance(pip, dict) or not isinstance(pip.get("ip"), str):
        return None
    try:
        ip = str(ipaddress.IPv4Address(pip["ip"]))
    except ValueError:
        return None
    ts = _seconds(pip.get("ts"))
    if ts is None:
        return None
    if changed_ts is None:
        return ip
    changed = _seconds(changed_ts)
    return ip if changed is not None and ts >= changed else None


def failure_reason(exc: BaseException) -> str:
    """The short reason for an exception a request raised; never the exception's own text."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return REASON_CERTIFICATE
    if isinstance(exc, ssl.SSLError):
        return REASON_TLS
    if isinstance(exc, socket.gaierror):
        return REASON_DNS
    if isinstance(exc, TimeoutError):
        return REASON_TIMEOUT
    if isinstance(exc, ConnectionError):
        return REASON_CONNECT
    if isinstance(exc, (ResponseTooLarge, http.client.HTTPException)):
        return REASON_UNREADABLE
    return REASON_CONNECT


def _json_object(body: Any) -> Optional[Dict[str, Any]]:
    """The JSON object in an answer body (bytes or str, at most :data:`BODY_MAX`), or None."""
    if isinstance(body, (bytes, bytearray)):
        if len(body) > BODY_MAX:
            return None
        try:
            text = bytes(body).decode("utf-8")
        except UnicodeDecodeError:
            return None
    elif isinstance(body, str) and len(body) <= BODY_MAX:
        text = body
    else:
        return None
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return doc if isinstance(doc, dict) else None


def _count(value: Any) -> bool:
    return type(value) is int and value >= 0


def parse_portchecker(status: Any, body: Any, port: int) -> Tuple[Optional[bool], Optional[str]]:
    """``(True|False, None)`` for a portchecker.io answer that gives *port*'s status, else ``(None, reason)``."""
    if status != 200:
        return None, REASON_HTTP.format(status=status)
    doc = _json_object(body)
    if doc is None:
        return None, REASON_UNREADABLE
    if doc.get("error") is True:
        return None, REASON_REPORTED_ERROR
    if doc.get("error") is not False:
        return None, REASON_UNREADABLE
    check = doc.get("check")
    first = check[0] if isinstance(check, list) and check else None
    if not isinstance(first, dict) or type(first.get("port")) is not int or first["port"] != port \
            or not isinstance(first.get("status"), bool):
        return None, REASON_UNREADABLE
    return first["status"], None


def parse_globalping_created(status: Any, body: Any) -> Tuple[Optional[str], Optional[str]]:
    """``(measurement id, None)`` for Globalping's 202 answer to the POST, else ``(None, reason)``."""
    if status != 202:
        return None, REASON_HTTP.format(status=status)
    doc = _json_object(body)
    measurement = doc.get("id") if doc is not None else None
    if not isinstance(measurement, str) or not _MEASUREMENT_ID_RE.fullmatch(measurement):
        return None, REASON_UNREADABLE
    return measurement, None


def parse_globalping_measurement(status: Any, body: Any) -> Optional[Outcome]:
    """None while the measurement is ``in-progress``; otherwise the Outcome of its first probe result."""
    if status != 200:
        return Outcome(None, None, REASON_HTTP.format(status=status))
    doc = _json_object(body)
    if doc is None:
        return Outcome(None, None, REASON_UNREADABLE)
    if doc.get("status") == "in-progress":
        return None
    if doc.get("status") != "finished":
        return Outcome(None, None, REASON_UNREADABLE)
    results = doc.get("results")
    first = results[0] if isinstance(results, list) and results else None
    result = first.get("result") if isinstance(first, dict) else None
    if not isinstance(result, dict):
        return Outcome(None, None, REASON_UNREADABLE)
    if result.get("status") == "failed":
        return Outcome(None, None, REASON_PROBE_FAILED)
    if result.get("status") == "offline":
        return Outcome(None, None, REASON_PROBE_OFFLINE)
    stats = result.get("stats") if isinstance(result.get("stats"), dict) else {}
    answered = stats.get("rcv")
    if result.get("status") != "finished" or not _count(answered):
        return Outcome(None, None, REASON_UNREADABLE)
    sent = stats.get("total")
    if not _count(sent) or sent < answered:
        drop = stats.get("drop")
        sent = answered + drop if _count(drop) else max(answered, GLOBALPING_PACKETS)
    return Outcome(answered > 0, GLOBALPING_DETAIL.format(answered=answered, sent=sent), None)


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def _headers(with_body: bool) -> Dict[str, str]:
    """``Content-Type`` (only with a body), ``Accept`` and ``User-Agent``."""
    headers = {"Content-Type": "application/json"} if with_body else {}
    headers["Accept"] = "application/json"
    headers["User-Agent"] = USER_AGENT
    return headers


#: What :func:`_call` gives for a ``changed_ts_fn`` that raised: not a time, so no address counts as fresh (§2.3).
_FAILED = object()


def _call(fn: Optional[Callable[[], Any]], failed: Any = None) -> Any:
    """``fn()``; None when there is no *fn*, *failed* when it raised (by default None: the value is "not known")."""
    if fn is None:
        return None
    try:
        return fn()
    except Exception:  # noqa: BLE001
        log.debug("Port-forward test: an accessor failed", exc_info=True)
        return failed


# --------------------------------------------------------------------------- HTTPS seam
def _bound(sock: Any, end: float, monotonic: Callable[[], float]) -> None:
    """Give *sock* the time left before *end*; ``TimeoutError`` when none is left."""
    left = end - monotonic()
    if left <= 0:
        raise TimeoutError("the answer did not arrive in time")
    if sock is not None:
        sock.settimeout(left)


def https_request(method: str, host: str, path: str, body: Optional[bytes], timeout: float,
                  headers: Optional[Dict[str, str]], *, connection_factory: Optional[Callable[..., Any]] = None,
                  monotonic: Callable[[], float] = time.monotonic) -> Tuple[int, bytes]:
    """One HTTPS request to *host* port 443: ``(status, body)``.

    stdlib ``http.client.HTTPSConnection`` (or *connection_factory*, for tests) with a fresh default SSL context, so
    the certificate and the host name are always checked; no proxy, and a 3xx is only a status (never followed).
    *timeout* bounds the connect and the TLS handshake, and the request and the whole answer must be done within it
    (a server that drips bytes is cut off with ``TimeoutError``).  A body over :data:`BODY_MAX` raises
    :class:`ResponseTooLarge`; network failures raise ``OSError``.  ``User-Agent`` defaults to :data:`USER_AGENT`."""
    limit = max(0.001, float(timeout))      # a socket timeout of 0 would mean non-blocking
    end = monotonic() + limit
    send = dict(headers or {})
    send.setdefault("User-Agent", USER_AGENT)
    factory = connection_factory if connection_factory is not None else http.client.HTTPSConnection
    conn = factory(host, HTTPS_PORT, timeout=limit, context=ssl.create_default_context())
    resp: Any = None
    try:
        conn.connect()
        sock = conn.sock                    # getresponse() may drop conn.sock; the response keeps reading from it
        _bound(sock, end, monotonic)
        conn.request(method, path, body=body, headers=send)
        _bound(sock, end, monotonic)
        resp = conn.getresponse()
        status = int(resp.status)
        try:
            length: Optional[int] = int(str(resp.getheader("Content-Length", "")).strip())
        except ValueError:
            length = None
        if length is not None and length > BODY_MAX:
            raise ResponseTooLarge(f"the answer is larger than {BODY_MAX // 1024} KiB")
        chunks = []
        size = 0
        while True:
            _bound(sock, end, monotonic)
            chunk = resp.read1(READ_CHUNK)
            if not chunk:
                return status, b"".join(chunks)
            size += len(chunk)
            if size > BODY_MAX:
                raise ResponseTooLarge(f"the answer is larger than {BODY_MAX // 1024} KiB")
            chunks.append(chunk)
    finally:
        for closer in ((resp.close if resp is not None else None), conn.close):
            if closer is None:
                continue
            try:
                closer()
            except Exception:  # noqa: BLE001
                pass


_https_request = https_request   # THE SEAM: PortChecker calls it through a module-global lookup at call time unless
                                 # a `request` was injected; tests/conftest.py replaces it for the whole session (§1.2)


# --------------------------------------------------------------------------- checker
class PortChecker:
    """Runs one port-forward test at a time against this network's public IPv4 address (see the module docstring)."""

    def __init__(self, *, public_ip_fn: Optional[Callable[[], Any]], changed_ts_fn: Optional[Callable[[], Any]],
                 refresh_fn: Optional[Callable[[], Any]], generation_fn: Optional[Callable[[], Any]],
                 nat_verdict_fn: Optional[Callable[[], Any]], clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 request: Optional[Callable[..., Tuple[int, bytes]]] = None, deadline_s: float = DEADLINE_S,
                 retry_delay_s: float = RETRY_DELAY_S, poll_s: float = POLL_S, poll_max_s: float = POLL_MAX_S,
                 min_gap_s: float = MIN_GAP_S, per_hour: int = PER_HOUR,
                 refresh_wait_s: float = REFRESH_WAIT_S) -> None:
        self._public_ip_fn = public_ip_fn
        self._changed_ts_fn = changed_ts_fn
        self._refresh_fn = refresh_fn
        self._generation_fn = generation_fn
        self._nat_verdict_fn = nat_verdict_fn
        self._clock = clock
        self._monotonic = monotonic
        self._sleep = sleep
        self._request = request
        self._deadline_s = float(deadline_s)
        self._retry_delay_s = float(retry_delay_s)
        self._poll_s = float(poll_s)
        self._poll_max_s = float(poll_max_s)
        self._min_gap_s = float(min_gap_s)
        self._per_hour = int(per_hour)
        self._refresh_wait_s = float(refresh_wait_s)
        # _lock: the running flag, the refresh helper and the rate-limit bookkeeping (monotonic start times of the
        # tests let through)
        self._lock = threading.Lock()
        self._running = False
        self._refresh_thread: Optional[threading.Thread] = None
        self._last_start: Optional[float] = None
        self._starts: Deque[float] = collections.deque()

    # -- public API --------------------------------------------------------------------
    def test(self, port: Any) -> Dict[str, Any]:
        """Test TCP *port* on this network's public IPv4 address and return PORTCHECK_RESULT.

        Raises ``ValueError``, :class:`VpnActive`, :class:`NoPublicIp`, ``RuntimeError`` (a test is already running)
        or :class:`RateLimited`, checked in that order before anything is sent.  Blocks for at most ``deadline_s``,
        plus up to ``refresh_wait_s`` when the public address has to be looked up again first."""
        port = validate_port(port)
        verdict = _call(self._nat_verdict_fn)
        if verdict == "vpn":
            log.debug("Port-forward test refused: the NAT check found a VPN")
            raise VpnActive(PORTCHECK_VPN_TEXT)
        generation, ip = self._public_address()
        if ip is None:
            log.debug("Port-forward test refused: no fresh public IPv4 address")
            raise NoPublicIp(PORTCHECK_NO_IP_TEXT)
        start = self._admit()
        try:
            return self._run(port, ip, generation, verdict, start)
        finally:
            with self._lock:
                self._running = False

    # -- before anything is sent -------------------------------------------------------
    def _public_address(self) -> Tuple[Any, Optional[str]]:
        """``(generation, fresh IPv4 or None)``, after one refresh when the first read is not fresh."""
        generation, ip = self._read_address()
        if ip is not None or self._refresh_fn is None:
            return generation, ip
        self._refresh()
        return self._read_address()

    def _read_address(self) -> Tuple[Any, Optional[str]]:
        """``(generation, fresh IPv4 or None)`` read now.  The generation is read first, so a network change between
        the reads leaves an older generation (an answer the card ignores), never an old address under a new one."""
        generation = _call(self._generation_fn)
        return generation, fresh_public_ip(_call(self._public_ip_fn), _call(self._changed_ts_fn, _FAILED))

    def _refresh(self) -> None:
        """Run ``refresh_fn`` on a daemon helper thread and wait for it at most ``refresh_wait_s``.  A lookup still
        running from an earlier test is waited for instead, so repeated clicks never pile up lookups."""
        with self._lock:
            helper = self._refresh_thread
            if helper is None or not helper.is_alive():
                helper = threading.Thread(target=self._run_refresh, name=REFRESH_THREAD_NAME, daemon=True)
                self._refresh_thread = helper
                helper.start()
        helper.join(max(0.0, self._refresh_wait_s))
        if helper.is_alive():
            log.debug("Port-forward test: the public address lookup is still running after %.1f s",
                      self._refresh_wait_s)

    def _run_refresh(self) -> None:
        refresh = self._refresh_fn
        try:
            if refresh is not None:
                refresh()
        except Exception:  # noqa: BLE001 - the read after the wait decides
            log.debug("Port-forward test: the public address lookup failed", exc_info=True)

    def _admit(self) -> float:
        """Steps 4 and 5: mark the test running and return its monotonic start, or raise."""
        with self._lock:
            if self._running:
                log.debug("Port-forward test refused: one is already running")
                raise RuntimeError(PORTCHECK_BUSY_TEXT)
            now = self._monotonic()
            wait = self._rate_wait(now)
            if wait > 0:
                seconds = max(1, math.ceil(round(wait, 6)))
                log.debug("Port-forward test refused: rate limited for %d s", seconds)
                raise RateLimited(PORTCHECK_RATE_TEXT.format(seconds=seconds), retry_after_s=seconds)
            self._running = True
            self._last_start = now
            self._starts.append(now)
            return now

    def _rate_wait(self, now: float) -> float:
        """Seconds until another test may start (0.0: now).  The caller holds ``_lock``."""
        starts = self._starts
        while starts and now - starts[0] >= RATE_WINDOW_S:
            starts.popleft()
        wait = 0.0
        last = self._last_start
        if self._min_gap_s > 0 and last is not None and now - last < self._min_gap_s:
            wait = self._min_gap_s - (now - last)
        if self._per_hour > 0 and len(starts) >= self._per_hour:
            wait = max(wait, starts[len(starts) - self._per_hour] + RATE_WINDOW_S - now)
        return wait

    # -- the test ----------------------------------------------------------------------
    def _run(self, port: int, ip: str, generation: Any, verdict: Any, start: float) -> Dict[str, Any]:
        request = self._request if self._request is not None else _https_request   # looked up now: the test guard
        ts = float(self._clock())
        deadline = start + max(0.0, self._deadline_s)
        provider = PROVIDER_PORTCHECKER
        outcome = self._portchecker(request, ip, port, deadline)
        reasons = []
        if outcome.reason is not None:
            reasons.append(f"{PROVIDER_NAMES[PROVIDER_PORTCHECKER]} {outcome.reason}")
            if deadline - self._monotonic() > 0:
                provider = PROVIDER_GLOBALPING
                outcome = self._globalping(request, ip, port, deadline)
            else:
                outcome = Outcome(None, None, REASON_NOT_TRIED)
            if outcome.reason is not None:
                reasons.append(f"{PROVIDER_NAMES[PROVIDER_GLOBALPING]} {outcome.reason}")
        error = PORTCHECK_FAILED_TEXT.format(reason=", ".join(reasons)) if outcome.reason is not None else None
        duration_ms = max(0, int(round((self._monotonic() - start) * 1000)))
        log.info("Port-forward test: %s via %s in %d ms", outcome.reachable, provider, duration_ms)
        log.debug("Port-forward test of %s TCP %d: %s", ip, port, outcome.detail or error)
        return {"ts": ts, "generation": generation, "port": port, "protocol": PORTCHECK_PROTOCOL, "public_ip": ip,
                "reachable": outcome.reachable, "provider": provider, "detail": outcome.detail,
                "nat_verdict": verdict, "error": error, "duration_ms": duration_ms}

    def _pause(self, seconds: float, deadline: float) -> None:
        """``sleep(seconds)``, cut to the time left before *deadline* (no call when none is)."""
        wait = min(seconds, deadline - self._monotonic())
        if wait > 0:
            self._sleep(wait)

    def _ask(self, request: Callable[..., Any], method: str, host: str, path: str, body: Optional[bytes],
             deadline: float) -> Tuple[Any, Any, Optional[str]]:
        """One request with ``min(REQUEST_TIMEOUT_S, time left)``.

        ``(status, body, None)``, or ``(None, None, reason)`` when no time was left or the request failed."""
        left = deadline - self._monotonic()
        if left <= 0:
            return None, None, REASON_TIMEOUT
        try:
            status, data = request(method, host, path, body, min(REQUEST_TIMEOUT_S, left), _headers(body is not None))
        except Exception as exc:  # noqa: BLE001 - every failure becomes a short reason
            log.debug("Port-forward test: %s https://%s%s failed: %r", method, host, path, exc)
            return None, None, failure_reason(exc)
        return status, data, None

    def _portchecker(self, request: Callable[..., Any], ip: str, port: int, deadline: float) -> Outcome:
        body = _json_bytes({"host": ip, "ports": [port]})
        for attempt in (1, 2):
            if attempt == 2:
                self._pause(self._retry_delay_s, deadline)
            status, data, reason = self._ask(request, "POST", PORTCHECKER_HOST, PORTCHECKER_PATH, body, deadline)
            reachable: Optional[bool] = None
            if reason is None:
                reachable, reason = parse_portchecker(status, data, port)
            if reason is not None:
                log.debug("Port-forward test: portchecker.io %s", reason)
                return Outcome(None, None, reason)
            if reachable:
                return Outcome(True, PORTCHECKER_OPEN_DETAIL, None)
        return Outcome(False, PORTCHECKER_CLOSED_DETAIL, None)

    def _globalping(self, request: Callable[..., Any], ip: str, port: int, deadline: float) -> Outcome:
        body = _json_bytes({"type": "ping", "target": ip, "limit": 1,
                            "measurementOptions": {"packets": GLOBALPING_PACKETS, "protocol": "TCP", "port": port}})
        status, data, reason = self._ask(request, "POST", GLOBALPING_HOST, GLOBALPING_PATH, body, deadline)
        measurement: Optional[str] = None
        if reason is None:
            measurement, reason = parse_globalping_created(status, data)
        if measurement is None:
            log.debug("Port-forward test: Globalping %s", reason)
            return Outcome(None, None, reason)
        path = f"{GLOBALPING_PATH}/{measurement}"
        polls_end = self._monotonic() + max(0.0, self._poll_max_s)
        # a bound on the reads as well as on the time, so a clock that stands still cannot spin this loop
        max_polls = int(self._poll_max_s / self._poll_s) + 1 if self._poll_s > 0 else 1
        for _ in range(max_polls):
            now = self._monotonic()
            if now >= deadline:
                return Outcome(None, None, REASON_TIMEOUT)
            if now >= polls_end:
                break
            self._pause(self._poll_s, deadline)
            status, data, reason = self._ask(request, "GET", GLOBALPING_HOST, path, None, deadline)
            if reason is not None:
                return Outcome(None, None, reason)
            outcome = parse_globalping_measurement(status, data)
            if outcome is not None:
                if outcome.reason is not None:
                    log.debug("Port-forward test: Globalping %s", outcome.reason)
                return outcome
        if self._monotonic() >= deadline:
            return Outcome(None, None, REASON_TIMEOUT)
        return Outcome(None, None, REASON_NO_RESULT)
