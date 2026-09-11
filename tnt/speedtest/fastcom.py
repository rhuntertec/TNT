"""fast.com (Netflix) speed-test backend.

``GET https://api.fast.com/netflix/speedtest/v2?https=true&token=<token>&urlCount=5``
returns::

    {"client": {"ip": "...", "asn": "64500", "location": {"city": "...", "country": "US"}},
     "targets": [{"name": "...", "url": "https://ipv4-c001-any001-ix.1.oca.example.net/speedtest?c=us&...",
                  "location": {"city": "Anytown", "country": "US"}}, ...]}

Each target serves a 25 MB body; a bounded range is requested by inserting
``/range/<start>-<end>`` (inclusive) before the query string, e.g.
``/speedtest/range/0-1048575?c=us&...`` (fast-cli convention).

Measurement:

* latency  - warm-up, then 8 x ``GET .../range/0-0`` on the first target
  (no server-timing header exists, so the sample is the plain wall time);
  median / mean |consecutive delta|.
* download - ``connections`` threads, worker *i* pinned to target
  ``i % len(targets)`` with its own keep-alive connection, requesting ranges of
  up to 25 MB until the ``duration_s`` / ``download_mb`` budget is reached.
  Ranges are sized against the phase's hard cap (see
  ``TransferPhase.remaining_bytes``) so they stay large while the phase runs on
  for its minimum duration.
* upload   - POST bodies to the same range URLs (Netflix OCAs accept them).
  As with Cloudflare only server-acknowledged bytes count (see
  :mod:`tnt.speedtest.base`) and bodies are sized adaptively (128 kB first,
  ~2 s per request, 4 MB max). If no upload request completes ``upload_mbps``
  is ``None`` and the result stays ``ok`` (the contract asks for this).

Requests per run: 1 API call + 9 latency GETs, then with the default budgets
(50 MB / 20 MB, 8 s, 4 connections) a handful of download ranges (25 MB each,
capped by 3 x ``download_mb``) and up to ~21 uploads (4 MB bodies against the
60 MB cap). A run measured on a near-gigabit link made 7 downloads
(151 MB) + 21 uploads (62 MB) = 38 requests, ~215 MB; a 100 Mbps link needs
about 4 downloads + ~12 uploads (~25 requests, ~85 MB), a 10 Mbps one ~20.

Rate limiting: a 429 (or a 403 on the API, the latency probes or the
download ranges) is handled like the Cloudflare backend - the worker halves
its range on 429 before giving up, and when every worker of a phase gave up
(or the API / probes were refused) the run fails with an error starting with
``"rate limited"`` (``raw["rate_limited"]``, ``raw["retry_after_s"]`` from
``Retry-After`` or 900 s, capped at 3600 s) and the backend goes on cooldown
(:func:`tnt.speedtest.base.set_cooldown`) so :meth:`FastComBackend.available`
reports it and the scheduler uses Cloudflare meanwhile. A 403 on the *upload*
POSTs alone is *not* a rate limit: it is an OCA that does not accept uploads,
so the upload is recorded as unknown and the download reading is kept.

The whole run is bounded by ``speedtest.timeout_s`` via
:class:`~tnt.speedtest.base.RunGuard`.

``server`` is ``"fast.com <oca-label> (<city>, <country>)"`` built from the
first target; ``external_ip`` is ``client.ip``; ``isp`` is ``"AS<asn>"`` (the
API only exposes the ASN, not the ISP name).

The module-level ``API_HOST``/``API_PORT``/``API_SCHEME`` exist so tests can
point the backend at a local fake server (target URLs then carry that server's
``http://`` origin).
"""
from __future__ import annotations

import http.client
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .base import (
    Cancelled, Http, HttpError, PhaseStats, ProgressFn, RunGuard, SpeedResult, TransferPhase, budgets,
    check_cancel, failed_result, get_cooldown, measure_latency, next_request_size, rate_limited_result,
    SOCKET_TIMEOUT_S,
)

log = logging.getLogger(__name__)

API_HOST = "api.fast.com"
API_PORT: Optional[int] = None
API_SCHEME = "https"
API_TOKEN = "YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm"
API_PATH = f"/netflix/speedtest/v2?https=true&token={API_TOKEN}&urlCount=5"

LATENCY_COUNT = 8
DOWNLOAD_CHUNK_BYTES = 25 * 1024 * 1024
DOWNLOAD_MIN_BYTES = 1_000_000
RATE_LIMIT_STATUS = 429
UPLOAD_BODY_BYTES = 4_000_000
UPLOAD_FIRST_BYTES = 128_000
UPLOAD_MIN_BYTES = 64_000
UPLOAD_TARGET_S = 2.0
UPLOAD_TAIL_S = 2.0


# --------------------------------------------------------------------------- parsing helpers

def range_path(url: str, start: int, end: int) -> str:
    """Path+query for an inclusive byte range of a target URL.

    ``https://h/speedtest?c=us`` + (0, 1048575) -> ``/speedtest/range/0-1048575?c=us``
    """
    parts = urlsplit(url)
    path = parts.path.rstrip("/") or "/speedtest"
    out = f"{path}/range/{int(start)}-{int(end)}"
    if parts.query:
        out += "?" + parts.query
    return out


def parse_targets(data: Any) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """API JSON -> ``(client, targets)``.

    Each target: ``{"url", "scheme", "host", "port", "label", "city", "country"}``.
    Raises ``ValueError`` when no usable target is present.
    """
    if isinstance(data, (str, bytes)):
        data = json.loads(data)
    if not isinstance(data, dict):
        raise ValueError("fast.com API returned no object")
    client = data.get("client") if isinstance(data.get("client"), dict) else {}
    targets: List[Dict[str, Any]] = []
    for t in data.get("targets") or []:
        if not isinstance(t, dict):
            continue
        url = t.get("url") or t.get("name")
        if not isinstance(url, str) or "://" not in url:
            continue
        try:
            parts = urlsplit(url)
            host, port = parts.hostname, parts.port     # .port raises on a malformed port
        except ValueError:
            continue
        if not host:
            continue
        loc = t.get("location") if isinstance(t.get("location"), dict) else {}
        label = host.split(".")[0]
        targets.append({
            "url": url,
            "scheme": parts.scheme or "https",
            "host": host,
            "port": port,
            "label": label,
            "city": loc.get("city"),
            "country": loc.get("country"),
        })
    if not targets:
        raise ValueError("fast.com API returned no targets")
    return client, targets


def describe_server(target: Dict[str, Any]) -> str:
    where = ", ".join(str(x) for x in (target.get("city"), target.get("country")) if x)
    label = target.get("label") or target.get("host") or "server"
    return f"fast.com {label}" + (f" ({where})" if where else "")


# --------------------------------------------------------------------------- backend

class FastComBackend:
    name = "fastcom"

    def available(self, config: Any) -> Tuple[bool, str]:
        cd = get_cooldown(self.name)
        if cd is not None:
            return False, cd.describe()
        return True, "built-in (fast.com)"

    def _api_endpoint(self) -> Tuple[str, Optional[int], str]:
        return API_HOST, API_PORT, API_SCHEME

    @staticmethod
    def _http_for(target: Dict[str, Any], timeout: float = SOCKET_TIMEOUT_S) -> Http:
        return Http(target["host"], target.get("port"), scheme=target.get("scheme", "https"), timeout=timeout)

    def fetch_targets(self, timeout: float = SOCKET_TIMEOUT_S) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        host, port, scheme = self._api_endpoint()
        http_ = Http(host, port, scheme=scheme, timeout=timeout)
        try:
            reply = http_.get(API_PATH, max_bytes=1024 * 1024)
        finally:
            http_.close()
        return parse_targets(reply.body)

    # -- workers ------------------------------------------------------------
    def _make_download_worker(self, targets: List[Dict[str, Any]]):
        def worker(phase: TransferPhase, idx: int) -> None:
            target = targets[idx % len(targets)]
            http_ = self._http_for(target, RunGuard.timeout_for(phase.cancel))
            failures = 0
            chunk = DOWNLOAD_CHUNK_BYTES
            try:
                while not phase.should_stop():
                    n = max(DOWNLOAD_MIN_BYTES, min(chunk, phase.remaining_bytes(hard=True)))
                    try:
                        http_.download(range_path(target["url"], 0, n - 1), phase.on_bytes)
                        phase.add_request()
                        failures = 0
                    except HttpError as exc:
                        if exc.rate_limited:
                            if exc.status == RATE_LIMIT_STATUS and n > DOWNLOAD_MIN_BYTES:
                                chunk = max(DOWNLOAD_MIN_BYTES, n // 2)   # halve what was refused
                                phase.note_rate_limit(exc.retry_after, status=exc.status)
                                log.info("fast.com download worker %d (%s): HTTP 429, retrying with %d-byte ranges",
                                         idx, target["host"], chunk)
                                phase.wait(0.2)
                                continue
                            phase.note_rate_limit(exc.retry_after, gave_up=True, status=exc.status)
                            phase.add_error()
                            log.info("fast.com download worker %d (%s): %s; giving up", idx, target["host"], exc)
                            break
                        phase.add_error()
                        failures += 1
                        log.debug("fast.com download worker %d (%s) error: %s", idx, target["host"], exc)
                        if failures >= 3:
                            break
                        phase.wait(0.25)
                    except (OSError, http.client.HTTPException) as exc:
                        phase.add_error()
                        failures += 1
                        log.debug("fast.com download worker %d (%s) error: %s", idx, target["host"], exc)
                        if failures >= 3:
                            break
                        phase.wait(0.25)
            finally:
                http_.close()
        return worker

    def _make_upload_worker(self, targets: List[Dict[str, Any]]):
        def worker(phase: TransferPhase, idx: int) -> None:
            target = targets[idx % len(targets)]
            http_ = self._http_for(target, RunGuard.timeout_for(phase.cancel))
            failures = 0
            size = UPLOAD_FIRST_BYTES
            try:
                while not phase.should_stop():
                    n = max(UPLOAD_MIN_BYTES, min(size, phase.remaining_bytes(hard=True)))
                    t0 = time.perf_counter()
                    try:
                        _status, sent, aborted = http_.upload(range_path(target["url"], 0, n - 1), n, phase.on_bytes)
                    except HttpError as exc:
                        phase.add_error()
                        if exc.status == RATE_LIMIT_STATUS:
                            # a 403 here is an OCA refusing uploads (upload -> unknown), not a rate limit
                            phase.note_rate_limit(exc.retry_after, gave_up=True, status=exc.status)
                            log.info("fast.com upload worker %d (%s): %s; giving up", idx, target["host"], exc)
                            break
                        failures += 1
                        log.debug("fast.com upload worker %d (%s) error: %s", idx, target["host"], exc)
                        if failures >= 3:
                            break
                        phase.wait(0.25)
                        continue
                    except (OSError, http.client.HTTPException) as exc:
                        phase.add_error()
                        failures += 1
                        log.debug("fast.com upload worker %d (%s) error: %s", idx, target["host"], exc)
                        if failures >= 3:
                            break
                        phase.wait(0.25)
                        continue
                    if aborted:
                        break
                    if phase.ack(sent):
                        phase.add_request()
                    failures = 0
                    size = next_request_size(sent, time.perf_counter() - t0, UPLOAD_TARGET_S,
                                             UPLOAD_MIN_BYTES, UPLOAD_BODY_BYTES)
            finally:
                http_.close()
        return worker

    # -- run ----------------------------------------------------------------
    def _refused(self, stats: PhaseStats, connections: int, ts: float, t0: float, raw: Dict[str, Any],
                 **fields: Any) -> SpeedResult:
        status = stats.rate_limit_status or RATE_LIMIT_STATUS
        detail = (f"{stats.name} phase refused: {stats.rate_limited} of {connections} worker(s) gave up "
                  f"after {stats.rate_limit_hits} HTTP {status} response(s)")
        log.warning("fast.com speed test rate limited: %s", detail)
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
        raw: Dict[str, Any] = {"budgets": b}
        try:
            report("connect", 0.0)
            check_cancel(guard)
            client, targets = self.fetch_targets(guard.socket_timeout())
            raw["client"] = client
            raw["targets"] = [{"host": t["host"], "city": t.get("city"), "country": t.get("country")} for t in targets]
            first = targets[0]
            server = describe_server(first)
            external_ip = client.get("ip") or None
            asn = client.get("asn")
            isp = f"AS{asn}" if asn else None
            report("connect", 1.0)

            check_cancel(guard)
            http_ = self._http_for(first, guard.socket_timeout())
            try:
                latency, jitter, samples = measure_latency(
                    http_, range_path(first["url"], 0, 0), count=LATENCY_COUNT, cancel=guard, progress=report,
                )
            finally:
                http_.close()
            raw["latency_samples_ms"] = [round(s, 2) for s in samples]
            known = {"server": server, "isp": isp, "external_ip": external_ip, "latency_ms": latency,
                     "jitter_ms": jitter}

            check_cancel(guard)
            dl = TransferPhase("download", b["duration_s"], b["download_bytes"], cancel=guard, progress=report)
            dl_stats = dl.run(self._make_download_worker(targets), b["connections"])
            raw["download"] = dl_stats.to_dict()
            check_cancel(guard)
            if dl_stats.rate_limited_phase(b["connections"]):
                return self._refused(dl_stats, b["connections"], ts, t0, raw, **known)
            if dl_stats.mbps is None:
                return failed_result(self.name, ts, f"download failed ({dl_stats.errors} errors, no data received)",
                                     time.perf_counter() - t0, raw, **known)

            upload_mbps: Optional[float] = None
            try:
                ul = TransferPhase("upload", b["duration_s"], b["upload_bytes"], cancel=guard, progress=report,
                                   acked=True, tail_s=UPLOAD_TAIL_S)
                ul_stats = ul.run(self._make_upload_worker(targets), b["connections"])
                raw["upload"] = ul_stats.to_dict()
                if ul_stats.rate_limited_phase(b["connections"]):
                    return self._refused(ul_stats, b["connections"], ts, t0, raw, **known)
                # Only acknowledged requests feed the figure, so bytes pushed on requests
                # that then errored out (an OCA closing the connection - the "not
                # supported" signature) can never become a number.
                if ul_stats.mbps is not None:
                    upload_mbps = round(ul_stats.mbps, 2)
                else:
                    raw["upload"]["error"] = "upload not supported or no request completed within the budget"
                    log.info("fast.com upload unavailable (%d errors, %d bytes sent); recording upload as unknown",
                             ul_stats.errors, ul_stats.bytes)
            except Cancelled:
                raise
            except Exception as exc:  # noqa: BLE001 - upload is best effort
                log.info("fast.com upload phase failed: %s", exc)
                raw["upload"] = {"error": f"{type(exc).__name__}: {exc}"}
            check_cancel(guard)

            report("done", 1.0)
            return SpeedResult(
                ok=True, ts=ts, backend=self.name, server=server, isp=isp, external_ip=external_ip,
                latency_ms=latency, jitter_ms=jitter, download_mbps=round(dl_stats.mbps, 2),
                upload_mbps=upload_mbps, packet_loss_pct=None,
                duration_s=round(time.perf_counter() - t0, 3), error=None, raw=raw,
            )
        except Cancelled:
            reason = guard.reason()
            log.log(logging.INFO if guard.cancelled else logging.WARNING, "fast.com speed test %s", reason)
            return failed_result(self.name, ts, reason, time.perf_counter() - t0, raw)
        except HttpError as exc:
            if exc.rate_limited:
                # the API or the latency probes were refused: nothing else will get through
                log.warning("fast.com speed test rate limited: %s", exc)
                return rate_limited_result(self.name, ts, exc.status, exc.retry_after,
                                           f"{exc.path.split('?', 1)[0]}: {exc.detail}" if exc.detail
                                           else exc.path.split("?", 1)[0],
                                           time.perf_counter() - t0, raw)
            log.warning("fast.com speed test failed: %s", exc)
            return failed_result(self.name, ts, f"{type(exc).__name__}: {exc}", time.perf_counter() - t0, raw)
        except Exception as exc:  # noqa: BLE001 - never raise out of run()
            log.warning("fast.com speed test failed: %s: %s", type(exc).__name__, exc)
            return failed_result(self.name, ts, f"{type(exc).__name__}: {exc}", time.perf_counter() - t0, raw)
