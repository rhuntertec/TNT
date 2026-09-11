"""Cloudflare speed-test backend (default; no licence restrictions).

Endpoints on ``speed.cloudflare.com``:

* ``GET /cdn-cgi/trace``           -> ``ip=...`` / ``colo=AMS`` / ``loc=NL`` lines
* ``GET /__down?bytes=N``          -> N bytes; ``server-timing`` header carries
  ``cfSpeedWorker;dur=<ms>`` (server-side processing time)
* ``POST /__up``                   -> accepts any body

A browser-like ``User-Agent`` is mandatory (the default Python UA gets 403).

Measurement:

* latency  - one warm-up GET, then 8 x ``GET /__down?bytes=0``; each sample is
  wall time minus the ``cfSpeedWorker`` duration (falls back to
  ``cfRequestDuration``); latency = median, jitter = mean |consecutive delta|.
* download - ``connections`` threads fetching :data:`DOWNLOAD_CHUNK_BYTES`
  (5 MB) chunks over keep-alive connections until the ``duration_s`` or
  ``download_mb`` budget is reached. Requests are sized against the phase's
  *hard* cap (``TransferPhase.remaining_bytes(hard=True)``) so they stay 5 MB
  while the phase runs on for its minimum duration instead of collapsing to
  1 MB once the soft budget is met.
* upload   - ``connections`` threads POSTing to ``/__up`` against the
  ``upload_mb`` budget. Only bytes the server has acknowledged (its response
  arrived) count, because ``send()`` returns as soon as the kernel buffered
  the data - see :mod:`tnt.speedtest.base`. Bodies start at
  :data:`UPLOAD_FIRST_BYTES` (128 kB, a cheap rate probe) and are resized so
  each request takes about :data:`UPLOAD_TARGET_S` (2 s), capped at
  :data:`UPLOAD_BODY_BYTES` (4 MB); requests in flight when the budget is
  reached get :data:`UPLOAD_TAIL_S` to complete and be counted.

Mbps = bytes * 8 / wall seconds of the phase, ramp-up (TCP/TLS handshakes and
slow start of every connection) *included* as the contract asks. With the
default 50 MB / 20 MB budgets a fast link finishes a phase in well under a
second, so the figure is a conservative "brief" reading rather than a peak;
raise ``download_mb``/``upload_mb`` (or ``duration_s``) for a steadier number.
The result's ``server`` is ``"Cloudflare <colo>"`` and ``external_ip`` comes
from the trace. The edge-measured TCP RTT (``cfL4`` ``min_rtt``) is kept in
``raw`` for diagnostics.

Requests per run and rate limiting
----------------------------------
speed.cloudflare.com rate-limits per source IP. With frequent scheduled tests
from one address, ``/__down?bytes=10000000`` can answer HTTP 429
(``Retry-After`` ~3400 s) while 5 MB chunks keep working; the number of
requests is the most likely trigger, so a run makes as few as the byte budgets
allow. With the defaults (50 MB down, 20 MB up, ``duration_s`` 8,
4 connections; each phase runs for at least 1.5 s and stops at 3 x its budget,
see :class:`~tnt.speedtest.base.TransferPhase`) a run is roughly:

=============  =====================================  ==================  ==================
link           download (5 MB chunks)                 upload (<= 4 MB)    total per run
=============  =====================================  ==================  ==================
fixed          11 small GETs (trace, warm-up + 8 latency probes, edge TCP info)
10 Mbps        4 (cut off by the 8 s time budget)     ~10                 ~25, ~20 MB (est.)
100 Mbps       ~12 (50 MB reached after ~4 s)         ~12 (~32 MB)        ~35, ~85 MB (est.)
1 Gbps         29 (138 MB: 1.5 s / the 150 MB cap)    21 (the 60 MB cap)  61, ~200 MB (measured)
=============  =====================================  ==================  ==================

The gigabit row was measured on a near-gigabit link; before
requests were sized against the hard cap the same run issued 57 downloads and
158 uploads (the tail of each phase ran on 1 MB / 64 kB requests). Bytes per
run are unchanged - they are set by the budgets - so ``download_mb`` /
``upload_mb`` / ``interval_min`` remain the knobs for metered or heavily
tested links.

When a request is refused:

* the download worker halves its chunk on 429 (5 -> 2.5 -> 1.25 -> 1 MB,
  :data:`DOWNLOAD_MIN_BYTES`) and only gives up when the minimum is refused
  too; the upload worker gives up on the first 429/403.
* when every worker of a phase gave up (or nothing was transferred and one
  did), or the trace / latency probes are refused, the run fails with a
  result whose ``error`` starts with ``"rate limited"``; ``raw`` carries
  ``rate_limited=True``, ``retry_after_s`` (the ``Retry-After`` header parsed
  as seconds or HTTP-date, default 900 s, capped at 3600 s) and
  ``http_status``. The backend is put on cooldown for that long
  (:func:`tnt.speedtest.base.set_cooldown`): :meth:`CloudflareBackend.available`
  reports ``"cooling down after HTTP 429 until HH:MM"`` and the scheduler
  falls back to fast.com meanwhile. HTTP 403 (Cloudflare's bot block) is
  treated the same way. Any 429 that a smaller chunk got around is only
  counted in ``raw["download"]["rate_limit_hits"]``.

The whole run is bounded by ``speedtest.timeout_s`` (plus at most one socket
timeout) through :class:`~tnt.speedtest.base.RunGuard`; a run that hits it
fails with ``"timed out after N s"``.

The module-level ``HOST``/``PORT``/``SCHEME`` exist so tests can point the
backend at a local fake server.
"""
from __future__ import annotations

import http.client
import logging
import threading
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs

from dataclasses import replace

from .base import (
    Cancelled, Http, HttpError, PhaseStats, ProgressFn, RunGuard, SpeedResult, TransferPhase, budgets,
    check_cancel, failed_result, get_cooldown, measure_latency, next_request_size, rate_limited_result,
    SOCKET_TIMEOUT_S,
)

log = logging.getLogger(__name__)

HOST = "speed.cloudflare.com"
PORT: Optional[int] = None
SCHEME = "https"

LATENCY_COUNT = 8
# Cloudflare rate-limits large __down requests per source IP (HTTP 429 with a Retry-After of
# ~1 h was observed for >= 10 MB chunks after a day of heavy testing) while 5 MB chunks kept
# working, so requests start at 5 MB and the worker halves the size on 429 (down to
# DOWNLOAD_MIN_BYTES) before giving up.
DOWNLOAD_CHUNK_BYTES = 5_000_000
DOWNLOAD_MIN_BYTES = 1_000_000
RATE_LIMIT_STATUS = 429
UPLOAD_BODY_BYTES = 4_000_000       # largest POST body
UPLOAD_FIRST_BYTES = 128_000        # first request per connection (cheap rate probe)
UPLOAD_MIN_BYTES = 64_000
UPLOAD_TARGET_S = 2.0               # aim for one request per ~2 s per connection (fewer, larger requests)
UPLOAD_TAIL_S = 2.0                 # in-flight uploads may complete this long after the budget is reached


# --------------------------------------------------------------------------- parsing helpers

def parse_trace(text: str) -> Dict[str, str]:
    """``/cdn-cgi/trace`` body (``key=value`` lines) -> dict."""
    out: Dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def _split_outside_quotes(text: str, sep: str) -> list:
    parts = []
    cur = []
    quoted = False
    for ch in text:
        if ch == '"':
            quoted = not quoted
        if ch == sep and not quoted:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def parse_server_timing(header: Optional[str]) -> Dict[str, Dict[str, Any]]:
    """Parse a ``Server-Timing`` header.

    ``"cfSpeedEdge;dur=5, cfSpeedWorker;dur=325, cfL4;desc=\"?rtt=20156\""`` ->
    ``{"cfSpeedEdge": {"dur": 5.0}, "cfSpeedWorker": {"dur": 325.0}, "cfL4": {"desc": "?rtt=20156"}}``
    """
    out: Dict[str, Dict[str, Any]] = {}
    if not header:
        return out
    for entry in _split_outside_quotes(header, ","):
        entry = entry.strip()
        if not entry:
            continue
        pieces = _split_outside_quotes(entry, ";")
        name = pieces[0].strip()
        if not name:
            continue
        params: Dict[str, Any] = {}
        for p in pieces[1:]:
            p = p.strip()
            if not p:
                continue
            k, _, v = p.partition("=")
            k = k.strip().lower()
            v = v.strip()
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                v = v[1:-1]
            if k == "dur":
                try:
                    params["dur"] = float(v)
                except ValueError:
                    continue
            else:
                params[k] = v
        out[name] = params
    return out


def server_time_ms(headers: Dict[str, str]) -> float:
    """Server-side processing time (ms) to subtract from a wall-clock sample."""
    timing = parse_server_timing(headers.get("server-timing"))
    for key in ("cfSpeedWorker", "cfRequestDuration"):
        entry = timing.get(key)
        if entry and "dur" in entry:
            return float(entry["dur"])
    return 0.0


def edge_tcp_info(headers: Dict[str, str]) -> Dict[str, Any]:
    """Cloudflare's ``cfL4`` edge TCP stats (rtt in microseconds) -> ms values."""
    timing = parse_server_timing(headers.get("server-timing"))
    desc = (timing.get("cfL4") or {}).get("desc")
    if not desc:
        return {}
    q = parse_qs(desc.lstrip("?"))
    out: Dict[str, Any] = {}
    for key, name in (("rtt", "tcp_rtt_ms"), ("min_rtt", "tcp_min_rtt_ms"), ("rtt_var", "tcp_rtt_var_ms")):
        vals = q.get(key)
        if vals:
            try:
                out[name] = round(float(vals[0]) / 1000.0, 3)
            except ValueError:
                pass
    for key in ("lost", "retrans"):
        vals = q.get(key)
        if vals:
            try:
                out["tcp_" + key] = int(vals[0])
            except ValueError:
                pass
    return out


# --------------------------------------------------------------------------- backend

class CloudflareBackend:
    name = "cloudflare"

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None, scheme: Optional[str] = None) -> None:
        # Resolved lazily so monkeypatching the module constants in tests works.
        self._host = host
        self._port = port
        self._scheme = scheme

    def _endpoint(self) -> Tuple[str, Optional[int], str]:
        return (self._host or HOST, self._port if self._port is not None else PORT, self._scheme or SCHEME)

    def _http(self, timeout: float = SOCKET_TIMEOUT_S) -> Http:
        host, port, scheme = self._endpoint()
        return Http(host, port, scheme=scheme, timeout=timeout)

    def available(self, config: Any) -> Tuple[bool, str]:
        cd = get_cooldown(self.name)
        if cd is not None:
            return False, cd.describe()
        return True, "built-in (speed.cloudflare.com)"

    # -- workers ------------------------------------------------------------
    def _download_worker(self, phase: TransferPhase, idx: int) -> None:
        http_ = self._http(RunGuard.timeout_for(phase.cancel))
        failures = 0
        chunk = DOWNLOAD_CHUNK_BYTES
        try:
            while not phase.should_stop():
                n = max(DOWNLOAD_MIN_BYTES, min(chunk, phase.remaining_bytes(hard=True)))
                try:
                    http_.download(f"/__down?bytes={n}", phase.on_bytes)
                    phase.add_request()
                    failures = 0
                except HttpError as exc:
                    if exc.rate_limited:
                        if exc.status == RATE_LIMIT_STATUS and n > DOWNLOAD_MIN_BYTES:
                            # per-IP rate limit on big chunks: ask for smaller ones instead of failing
                            # (halve the size that was refused, not the nominal chunk - near the
                            # hard cap the two differ and re-asking for the same size wastes hits)
                            chunk = max(DOWNLOAD_MIN_BYTES, n // 2)
                            phase.note_rate_limit(exc.retry_after, status=exc.status)
                            log.info("cloudflare download worker %d: HTTP 429, retrying with %d-byte chunks", idx, chunk)
                            phase.wait(0.2)
                            continue
                        # refused even at the minimum size (or blocked outright): this worker is done
                        phase.note_rate_limit(exc.retry_after, gave_up=True, status=exc.status)
                        phase.add_error()
                        log.info("cloudflare download worker %d: %s at %d-byte chunks; giving up", idx, exc, n)
                        break
                    phase.add_error()
                    failures += 1
                    log.debug("cloudflare download worker %d error: %s", idx, exc)
                    if failures >= 3:
                        break
                    phase.wait(0.25)
                except (OSError, http.client.HTTPException) as exc:
                    phase.add_error()
                    failures += 1
                    log.debug("cloudflare download worker %d error: %s", idx, exc)
                    if failures >= 3:
                        break
                    phase.wait(0.25)
        finally:
            http_.close()

    def _upload_worker(self, phase: TransferPhase, idx: int) -> None:
        http_ = self._http(RunGuard.timeout_for(phase.cancel))
        failures = 0
        size = UPLOAD_FIRST_BYTES
        try:
            while not phase.should_stop():
                n = max(UPLOAD_MIN_BYTES, min(size, phase.remaining_bytes(hard=True)))
                t0 = time.perf_counter()
                try:
                    _status, sent, aborted = http_.upload("/__up", n, phase.on_bytes)
                except HttpError as exc:
                    phase.add_error()
                    if exc.rate_limited:
                        phase.note_rate_limit(exc.retry_after, gave_up=True, status=exc.status)
                        log.info("cloudflare upload worker %d: %s; giving up", idx, exc)
                        break
                    failures += 1
                    log.debug("cloudflare upload worker %d error: %s", idx, exc)
                    if failures >= 3:
                        break
                    phase.wait(0.25)
                    continue
                except (OSError, http.client.HTTPException) as exc:
                    phase.add_error()
                    failures += 1
                    log.debug("cloudflare upload worker %d error: %s", idx, exc)
                    if failures >= 3:
                        break
                    phase.wait(0.25)
                    continue
                if aborted:
                    break
                # The response is in: the server has every byte of this request.
                if phase.ack(sent):
                    phase.add_request()
                failures = 0
                size = next_request_size(sent, time.perf_counter() - t0, UPLOAD_TARGET_S,
                                         UPLOAD_MIN_BYTES, UPLOAD_BODY_BYTES)
        finally:
            http_.close()

    # -- run ----------------------------------------------------------------
    def _refused(self, stats: PhaseStats, connections: int, ts: float, t0: float, raw: Dict[str, Any],
                 **fields: Any) -> SpeedResult:
        """The rate-limited result for a phase the server refused as a whole."""
        status = stats.rate_limit_status or RATE_LIMIT_STATUS
        detail = (f"{stats.name} phase refused: {stats.rate_limited} of {connections} worker(s) gave up "
                  f"after {stats.rate_limit_hits} HTTP {status} response(s)")
        log.warning("cloudflare speed test rate limited: %s", detail)
        return rate_limited_result(self.name, ts, status, stats.retry_after_s, detail,
                                   time.perf_counter() - t0, raw, **fields)

    def run(self, config: Any, progress: Optional[ProgressFn] = None,
            cancel: Optional[threading.Event] = None) -> SpeedResult:
        ts = time.time()
        t0 = time.perf_counter()

        def report(phase: str, frac: float) -> None:
            if progress is None:
                return
            try:
                progress(phase, frac)
            except Exception:  # noqa: BLE001
                log.exception("speedtest progress callback failed")

        b = budgets(config)
        guard = RunGuard(cancel, b["timeout_s"])
        raw: Dict[str, Any] = {"host": self._endpoint()[0], "budgets": b}
        http_ = self._http(guard.socket_timeout())
        try:
            report("connect", 0.0)
            check_cancel(guard)
            trace = parse_trace(http_.get("/cdn-cgi/trace", max_bytes=65536).text)
            raw["trace"] = {k: trace[k] for k in ("ip", "colo", "loc", "http", "tls", "warp") if k in trace}
            colo = trace.get("colo")
            server = f"Cloudflare {colo}" if colo else "Cloudflare"
            external_ip = trace.get("ip") or None
            report("connect", 1.0)

            check_cancel(guard)
            latency, jitter, samples = measure_latency(
                http_, "/__down?bytes=0", count=LATENCY_COUNT, server_time=server_time_ms,
                cancel=guard, progress=report,
            )
            raw["latency_samples_ms"] = [round(s, 2) for s in samples]
            try:
                raw.update(edge_tcp_info(http_.get("/__down?bytes=0").headers))
            except Exception:  # noqa: BLE001 - purely informational
                log.debug("cloudflare edge tcp info unavailable", exc_info=True)
            http_.close()
            known = {"server": server, "external_ip": external_ip, "latency_ms": latency, "jitter_ms": jitter}

            check_cancel(guard)
            dl = TransferPhase("download", b["duration_s"], b["download_bytes"], cancel=guard, progress=report)
            dl_stats = dl.run(self._download_worker, b["connections"])
            raw["download"] = dl_stats.to_dict()
            check_cancel(guard)
            if dl_stats.rate_limited_phase(b["connections"]):
                return self._refused(dl_stats, b["connections"], ts, t0, raw, **known)
            if dl_stats.mbps is None:
                return failed_result(self.name, ts, f"download failed ({dl_stats.errors} errors, no data received)",
                                     time.perf_counter() - t0, raw, **known)
            if dl_stats.errors and dl_stats.bytes < 0.25 * b["download_bytes"]:
                # mostly failed requests: the wall clock includes time spent failing, so the
                # figure would be a meaningless underestimate recorded as a real reading
                return failed_result(self.name, ts, f"download unreliable: {dl_stats.errors} request error(s), "
                                     f"only {dl_stats.bytes} bytes received", time.perf_counter() - t0, raw, **known)

            ul = TransferPhase("upload", b["duration_s"], b["upload_bytes"], cancel=guard, progress=report,
                               acked=True, tail_s=UPLOAD_TAIL_S)
            ul_stats = ul.run(self._upload_worker, b["connections"])
            raw["upload"] = ul_stats.to_dict()
            check_cancel(guard)
            if ul_stats.rate_limited_phase(b["connections"]):
                return self._refused(ul_stats, b["connections"], ts, t0, raw, **known)
            if ul_stats.mbps is None:
                log.warning("cloudflare upload phase: no request was acknowledged in time (%d errors, %d bytes "
                            "sent); recording upload as unknown", ul_stats.errors, ul_stats.bytes)
                raw["upload"]["error"] = "no upload request completed within the budget"
            elif ul_stats.errors and ul_stats.acked_bytes < 0.25 * b["upload_bytes"]:
                log.warning("cloudflare upload phase unreliable: %d request error(s), only %d bytes acknowledged; "
                            "recording upload as unknown", ul_stats.errors, ul_stats.acked_bytes)
                raw["upload"]["error"] = f"{ul_stats.errors} request error(s); too little data acknowledged"
                ul_stats = replace(ul_stats, mbps=None)

            report("done", 1.0)
            return SpeedResult(
                ok=True, ts=ts, backend=self.name, server=server, isp=None, external_ip=external_ip,
                latency_ms=latency, jitter_ms=jitter,
                download_mbps=round(dl_stats.mbps, 2),
                upload_mbps=round(ul_stats.mbps, 2) if ul_stats.mbps is not None else None,
                packet_loss_pct=None, duration_s=round(time.perf_counter() - t0, 3), error=None, raw=raw,
            )
        except Cancelled:
            reason = guard.reason()
            log.log(logging.INFO if guard.cancelled else logging.WARNING, "cloudflare speed test %s", reason)
            return failed_result(self.name, ts, reason, time.perf_counter() - t0, raw)
        except HttpError as exc:
            if exc.rate_limited:
                # the trace or the latency probes were refused: nothing else will get through
                log.warning("cloudflare speed test rate limited: %s", exc)
                return rate_limited_result(self.name, ts, exc.status, exc.retry_after,
                                           f"{exc.path}: {exc.detail}" if exc.detail else exc.path,
                                           time.perf_counter() - t0, raw)
            log.warning("cloudflare speed test failed: %s", exc)
            return failed_result(self.name, ts, f"{type(exc).__name__}: {exc}", time.perf_counter() - t0, raw)
        except Exception as exc:  # noqa: BLE001 - never raise out of run()
            log.warning("cloudflare speed test failed: %s: %s", type(exc).__name__, exc)
            return failed_result(self.name, ts, f"{type(exc).__name__}: {exc}", time.perf_counter() - t0, raw)
        finally:
            http_.close()
