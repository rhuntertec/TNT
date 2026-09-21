"""Classic ICMP traceroute for the Tools page (``POST /api/tools/traceroute``).

For TTL 1, 2, 3, ... the :class:`Tracer` sends *probes* echo requests to the target with
that TTL through the shared :class:`tnt.icmp.IcmpPinger`.  A router that drops the packet
answers "TTL expired in transit" (status 11013) and ``PingResult.responder`` is its
address; the destination itself answers with ``ok`` and ``responder == target``.  The trace
ends at the hop where the destination answered (``complete``), after a router reported
the destination unreachable, at ``max_hops`` or when ``cancel`` is set.

Silent hops do not end it: many cores and cloud edges never send "TTL expired", and the
destination can answer several hops beyond them, so like Windows ``tracert`` the trace goes
on to ``max_hops``.  (It used to give up after five silent hops and report "no reply after
hop 3" for a destination that answered at hop 10.)  To keep the time bounded, once
:data:`SILENT_HOPS_LIMIT` hops in a row have been silent each further hop is sent one probe,
and the rest of its probes only if that one is answered; at the defaults a trace in which
nothing answers takes 5 x 3 + 25 x 1 probes x 1.5 s = 60 s.  When the trace ends in such a
silent run the error still says so: ``"no reply after hop N"`` (N the last hop that
answered) or ``"no reply from any of the M hops"``.  The accepted cost: a hop that loses only its
one probe there is recorded as silent, so a destination that drops that echo is found one hop
later (still ``complete``), as tracert shows it when every probe of a hop is lost.

The probing as a whole also has a time limit, :data:`TRACE_PROBE_BUDGET_S`: the Tools page
waits 120 s for its answer, and slower settings it accepts (64 hops at a 2 s timeout, silent
after hop 1) would otherwise probe for about 150 s, so the page would report a timeout while
the service carried on.  No probe is started that could not finish inside the limit; a trace
that reaches it ends with ``"no reply after hop N; stopped at hop T, the 100 s time limit for
a trace"`` (or ``"no reply from any of the T hops tried; ..."`` / ``"destination not reached
by hop T; ..."``).

Every answered hop is classified (``kind`` / ``label``): ``gateway`` (the machine's default
gateway), ``lan`` (RFC 1918, link-local, loopback or CGNAT 100.64/10 and not the
gateway), ``public``, ``destination`` (the last hop of a complete trace) and ``unknown``
(no reply).  Hop routers are reverse-resolved in the background with an overall
:data:`REVERSE_DNS_DEADLINE_S` cap; the names are filled into the final result (a
``trace.hop`` event carries the name only when the lookup had already come back).

The ICMP calls run on a daemon thread named ``tnt-ping-trace`` (the Engine only closes
the ICMP handle when no ``tnt-ping-*`` thread is alive); :meth:`Tracer.trace` runs in the
caller's thread and waits for it, bounded by ``max_hops * probes * timeout`` plus a grace
period.  Only one trace runs at a time: a second call raises ``RuntimeError("a traceroute
is already running")`` (HTTP 409 on the route).

Events (``bus.publish``): ``trace.start`` ``{host, target_ip, max_hops, probes}``,
``trace.hop`` ``{hop: HOP}`` after every hop, ``trace.done`` ``{host, target_ip, hops,
complete, error, duration_s}``.

Result (TRACE) dict::

    {"host", "target_ip", "ts", "duration_s", "max_hops", "probes", "timeout_ms",
     "complete": bool, "error": None|str,
     "pc": {"ip": <internet NIC IPv4>|None, "hostname": str|None}, "gateway": ip|None,
     "hops": [HOP, ...]}

HOP dict::

    {"ttl": int, "ip": str|None, "alt_ips": [str], "hostname": str|None,
     "rtts": [float|None per probe], "avg_ms", "min_ms", "max_ms" (None when nothing
     answered), "loss": int, "responder_status": int|None, "kind", "label",
     "location": LOCATION|None}

``location`` (``tnt.geoip`` LOCATION: ``{"text", "source", "hint", "db_text", "asn", "as_org"}``) comes from
the ``geo`` provider (the engine's IP location manager, asked once per trace).  It is filled at hop completion
from the database, plus the router name if the reverse lookup had already come back, and refined for every
named hop after the final hostname fill, before ``last`` is set and ``trace.done`` is published.  It is None
for unanswered and LAN/CGNAT/link-local/loopback hops, and when IP location is off or unavailable.
"""
from __future__ import annotations

import importlib
import ipaddress
import logging
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

__all__ = ["Tracer", "classify_hop", "is_lan_address", "KIND_LABELS"]

DEFAULT_MAX_HOPS = 30
DEFAULT_PROBES = 3
DEFAULT_TIMEOUT_MS = 1500
MAX_HOPS_LIMIT = 64
PROBES_LIMIT = 5
TIMEOUT_MS_MIN = 100
TIMEOUT_MS_MAX = 10_000
PROBE_SIZE = 32
SILENT_HOPS_LIMIT = 5          # after this many unanswered hops in a row, one probe per hop until one answers
REVERSE_DNS_DEADLINE_S = 4.0   # overall cap on the hop-name lookups at the end of a trace
TRACE_PROBE_BUDGET_S = 100.0  # probing time limit: with the DNS cap and grace it stays inside the client's 120 s
WAIT_GRACE_S = 10.0            # added to the worst-case probe time when waiting for the worker
THREAD_NAME = "tnt-ping-trace"
STATUS_OK = 0
STATUS_TTL_EXPIRED = 11013

KIND_LABELS: Dict[str, str] = {
    "gateway": "Gateway",
    "lan": "LAN",
    "public": "Internet",
    "destination": "Destination",
    "unknown": "No reply",
}

# Deliberately not ipaddress.is_private: that also covers the documentation ranges
# (192.0.2/24, 198.51.100/24, 203.0.113/24), which are never on a LAN.
_LAN_V4 = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "169.254.0.0/16",                                   # link-local / APIPA
    "100.64.0.0/10",                                    # CGNAT (RFC 6598): the ISP side of a shared NAT
    "127.0.0.0/8",                                      # loopback
))
_LAN_V6 = tuple(ipaddress.ip_network(n) for n in ("fc00::/7", "fe80::/10", "::1/128"))


def is_lan_address(ip: Any) -> bool:
    """True for RFC 1918 / link-local / loopback / CGNAT addresses (IPv4 and IPv6). Never raises."""
    text = str(ip or "").strip()
    try:
        addr = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        v4 = addr.ipv4_mapped
        if v4 is not None:
            return any(v4 in net for net in _LAN_V4)
        return any(addr in net for net in _LAN_V6)
    return any(addr in net for net in _LAN_V4)


def classify_hop(ip: Optional[str], gateway: Optional[str], reached: bool = False) -> Tuple[str, str]:
    """``(kind, label)`` for a hop: the router *ip* (None = nobody answered), the machine's
    default *gateway* and whether the destination answered at this hop."""
    if not ip:
        kind = "unknown"
    elif reached:
        kind = "destination"
    elif gateway and ip == gateway:
        kind = "gateway"
    elif is_lan_address(ip):
        kind = "lan"
    else:
        kind = "public"
    return kind, KIND_LABELS[kind]


def _int_arg(name: str, value: Any, lo: int, hi: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer between {lo} and {hi}")
    try:
        val = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{name} must be an integer between {lo} and {hi}") from None
    if not lo <= val <= hi:
        raise ValueError(f"{name} must be between {lo} and {hi}")
    return val


def _round(value: Optional[float]) -> Optional[float]:
    return None if value is None else round(float(value), 2)


class _Lookup:
    """One background reverse-DNS lookup; ``name`` is valid once ``done`` is set."""

    def __init__(self, ip: str, fn: Callable[[str], Optional[str]]) -> None:
        self.ip = ip
        self.name: Optional[str] = None
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._run, args=(fn,), name=f"tnt-trace-rdns-{ip}", daemon=True)

    def start(self) -> None:
        try:
            self.thread.start()
        except Exception:  # noqa: BLE001 - thread limit: treat as "no name"
            log.debug("could not start the reverse lookup for %s", self.ip, exc_info=True)
            self.done.set()

    def _run(self, fn: Callable[[str], Optional[str]]) -> None:
        try:
            name = fn(self.ip)
            self.name = str(name).strip() or None if name else None
        except Exception:  # noqa: BLE001
            self.name = None
        finally:
            self.done.set()


class _Job:
    """State shared between :meth:`Tracer.trace` (the caller) and the worker thread."""

    def __init__(self, host: str, target_ip: str, max_hops: int, probes: int, timeout_ms: int,
                 resolve_names: bool, cancel: Optional[threading.Event]) -> None:
        self.host = host
        self.target_ip = target_ip
        self.max_hops = max_hops
        self.probes = probes
        self.timeout_ms = timeout_ms
        self.resolve_names = resolve_names
        self.cancel = cancel
        self.abandon = threading.Event()   # the caller stopped waiting
        self.lock = threading.Lock()
        self.result: Optional[Dict[str, Any]] = None
        self.partial: Optional[Dict[str, Any]] = None   # header + hops while running
        self.exc: Optional[BaseException] = None
        self.probe_deadline: Optional[float] = None     # monotonic time the probing must end by (TRACE_PROBE_BUDGET_S)

    def stop_requested(self) -> bool:
        return self.abandon.is_set() or (self.cancel is not None and self.cancel.is_set())

    def snapshot(self, error: str) -> Dict[str, Any]:
        with self.lock:
            base = dict(self.partial or {})
            hops = [dict(h) for h in base.get("hops", [])]
        base.update({"hops": hops, "complete": False, "error": error})
        base.setdefault("host", self.host)
        base.setdefault("target_ip", self.target_ip)
        return base


class Tracer:
    def __init__(self, pinger: Any, bus: Any = None, clock: Callable[[], float] = time.time,
                 resolver: Optional[Callable[[str], Optional[str]]] = None,
                 reverse: Optional[Callable[[str], Optional[str]]] = None,
                 gateway_fn: Optional[Callable[[], Optional[str]]] = None,
                 local_fn: Optional[Callable[[], Optional[str]]] = None,
                 geo: Optional[Callable[[], Any]] = None,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self.pinger = pinger
        self._monotonic = monotonic  # times the probing against TRACE_PROBE_BUDGET_S (a test passes a fake)
        self._bus = bus
        self._clock = clock
        self._resolver = resolver
        self._reverse = reverse
        self._gateway_fn = gateway_fn
        self._local_fn = local_fn
        self._geo_provider = geo     # called once per trace: an object with locate_hop() and origin(), or None
        self._lock = threading.Lock()
        self._running = False
        self._last: Optional[Dict[str, Any]] = None

    # -- state -------------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._running

    @property
    def last(self) -> Optional[Dict[str, Any]]:
        return self._last

    # -- collaborators (injectable; lazily imported so this module has no heavy imports) --
    def _resolve(self, host: str) -> Optional[str]:
        resolver = self._resolver
        if resolver is None:
            resolver = importlib.import_module("tnt.icmp").resolve
        try:
            ip = resolver(host)
        except Exception:  # noqa: BLE001
            log.debug("resolve(%s) raised", host, exc_info=True)
            return None
        return str(ip) if ip else None

    def _reverse_fn(self) -> Callable[[str], Optional[str]]:
        if self._reverse is not None:
            return self._reverse
        try:
            return importlib.import_module("tnt.discovery")._reverse_lookup
        except Exception:  # noqa: BLE001
            log.debug("tnt.discovery unavailable; falling back to gethostbyaddr", exc_info=True)

            def fallback(ip: str) -> Optional[str]:
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except (OSError, UnicodeError):
                    return None
                name = (name or "").strip().rstrip(".")
                return name if name and name != ip else None

            return fallback

    def _gateway(self) -> Optional[str]:
        try:
            fn = self._gateway_fn
            if fn is None:
                fn = importlib.import_module("tnt.pinger")._default_gateway
            gw = fn()
            return str(gw) if gw else None
        except Exception:  # noqa: BLE001
            log.debug("default gateway lookup failed", exc_info=True)
            return None

    def _local_ip(self) -> Optional[str]:
        try:
            fn = self._local_fn
            if fn is None:
                nic = importlib.import_module("tnt.netinfo").get_internet_nic()
                ip = getattr(nic, "primary_ipv4", None) if nic is not None else None
            else:
                ip = fn()
            return str(ip) if ip else None
        except Exception:  # noqa: BLE001
            log.debug("internet NIC lookup failed", exc_info=True)
            return None

    def _pc_info(self) -> Dict[str, Any]:
        hostname: Optional[str] = None
        try:
            hostname = socket.gethostname() or None
        except Exception:  # noqa: BLE001
            pass
        return {"ip": self._local_ip(), "hostname": hostname}

    def _geo(self) -> Any:
        try:
            return self._geo_provider() if self._geo_provider is not None else None
        except Exception:  # noqa: BLE001
            log.debug("geo provider failed", exc_info=True)
            return None

    @staticmethod
    def _locate(geo: Any, hop: Dict[str, Any], origin: Any) -> Optional[Dict[str, Any]]:
        if geo is None or not hop.get("ip") or is_lan_address(hop["ip"]):
            return None
        try:
            loc = geo.locate_hop(hop["ip"], hop.get("hostname"), hop.get("min_ms"), origin, kind=hop.get("kind"))
        except Exception:  # noqa: BLE001
            log.debug("hop location failed", exc_info=True)
            return None
        return dict(loc) if isinstance(loc, dict) else None

    def _publish(self, event_type: str, data: Dict[str, Any]) -> None:
        if self._bus is None:
            return
        try:
            self._bus.publish(event_type, data)
        except Exception:  # noqa: BLE001
            log.exception("publishing %s failed", event_type)

    # -- public API --------------------------------------------------------------------
    def trace(self, host: str, max_hops: int = DEFAULT_MAX_HOPS, probes: int = DEFAULT_PROBES,
              timeout_ms: int = DEFAULT_TIMEOUT_MS, resolve_names: bool = True,
              cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
        """Run a traceroute to *host* and return the TRACE dict (see the module docstring).

        ``ValueError`` for a bad argument or a host that does not resolve,
        ``RuntimeError`` when a trace is already running.  Blocks the caller for the
        duration of the trace (worst case ``max_hops * probes * timeout_ms``, capped at
        :data:`TRACE_PROBE_BUDGET_S`, plus the reverse-DNS cap).
        """
        text = str(host or "").strip()
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1].strip()
        if not text:
            raise ValueError("host is required")
        max_hops = _int_arg("max_hops", max_hops, 1, MAX_HOPS_LIMIT)
        probes = _int_arg("probes", probes, 1, PROBES_LIMIT)
        timeout_ms = _int_arg("timeout_ms", timeout_ms, TIMEOUT_MS_MIN, TIMEOUT_MS_MAX)
        if self.pinger is None:
            raise RuntimeError("the ICMP engine is not available")

        with self._lock:
            if self._running:
                raise RuntimeError("a traceroute is already running")
            self._running = True
        try:
            target_ip = self._resolve(text)
            if not target_ip:
                raise ValueError(f"could not resolve {text}")
            job = _Job(text, target_ip, max_hops, probes, timeout_ms, bool(resolve_names), cancel)
            worker = threading.Thread(target=self._worker, args=(job,), name=THREAD_NAME, daemon=True)
            worker.start()
        except BaseException:
            with self._lock:
                self._running = False
            raise

        budget = (min(max_hops * probes * timeout_ms / 1000.0, TRACE_PROBE_BUDGET_S)
                  + REVERSE_DNS_DEADLINE_S + WAIT_GRACE_S)
        worker.join(budget)
        if worker.is_alive():
            job.abandon.set()
            log.warning("traceroute to %s did not finish within %.0f s; returning what was collected", text, budget)
            snap = job.snapshot(f"traceroute did not finish within {budget:.0f} s")
            self._last = snap
            return snap
        if job.exc is not None:
            raise job.exc
        assert job.result is not None
        return job.result

    # -- worker ------------------------------------------------------------------------
    def _worker(self, job: _Job) -> None:
        try:
            job.result = self._run(job)
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller's thread
            job.exc = exc
        finally:
            with self._lock:
                self._running = False

    def _run(self, job: _Job) -> Dict[str, Any]:
        started = float(self._clock())
        hops: List[Dict[str, Any]] = []
        result: Dict[str, Any] = {
            "host": job.host,
            "target_ip": job.target_ip,
            "ts": started,
            "duration_s": 0.0,
            "max_hops": job.max_hops,
            "probes": job.probes,
            "timeout_ms": job.timeout_ms,
            "complete": False,
            "error": None,
            "pc": self._pc_info(),
            "gateway": self._gateway(),
            "hops": hops,
        }
        with job.lock:
            job.partial = result
        geo = self._geo()
        origin = None
        if geo is not None:
            try:
                origin = geo.origin()
            except Exception:  # noqa: BLE001
                origin = None
        self._publish("trace.start", {"host": job.host, "target_ip": job.target_ip,
                                      "max_hops": job.max_hops, "probes": job.probes})
        lookups: Dict[str, _Lookup] = {}
        reverse = self._reverse_fn() if job.resolve_names else None

        def start_lookup(ip: str) -> None:
            if reverse is None or ip in lookups:
                return
            lk = _Lookup(ip, reverse)
            lookups[ip] = lk
            lk.start()

        complete = False
        error: Optional[str] = None
        silent = 0
        last_answered_ttl = 0
        job.probe_deadline = self._monotonic() + TRACE_PROBE_BUDGET_S
        try:
            for ttl in range(1, job.max_hops + 1):
                if job.stop_requested():
                    error = "cancelled"
                    break
                if not self._probe_fits(job):
                    # out of time: say where replies stopped, and that the limit (not the network) ended it
                    tried = ttl - 1
                    limit = f"the {TRACE_PROBE_BUDGET_S:.0f} s time limit for a trace"
                    if not last_answered_ttl:
                        error = f"no reply from any of the {tried} hops tried; stopped at {limit}"
                    elif silent:
                        error = f"no reply after hop {last_answered_ttl}; stopped at hop {tried}, {limit}"
                    else:
                        error = f"destination not reached by hop {tried}; stopped at {limit}"
                    break
                hop, reached, reply_error = self._probe_hop(job, ttl, start_lookup,
                                                            quiet=silent >= SILENT_HOPS_LIMIT)
                hop["kind"], hop["label"] = classify_hop(hop["ip"], result["gateway"], reached)
                lk = lookups.get(hop["ip"]) if hop["ip"] else None
                if lk is not None and lk.done.is_set():
                    hop["hostname"] = lk.name
                hop["location"] = self._locate(geo, hop, origin)
                with job.lock:
                    hops.append(hop)
                self._publish("trace.hop", {"hop": dict(hop)})
                if reached:
                    complete = True
                    break
                if hop["ip"] is None:
                    # no break: the destination may still answer beyond a core that sends no "TTL expired"
                    silent += 1
                    continue
                silent = 0
                last_answered_ttl = ttl
                if reply_error:
                    # a router said the destination is unreachable: going further is pointless
                    error = reply_error
                    break
                if job.stop_requested():
                    error = "cancelled"
                    break
            else:
                if silent >= SILENT_HOPS_LIMIT:
                    # the tail really is silent: say where the replies stopped
                    error = (f"no reply after hop {last_answered_ttl}" if last_answered_ttl
                             else f"no reply from any of the {job.max_hops} hops")
                else:
                    error = f"destination not reached within {job.max_hops} hops"
        except Exception as exc:  # noqa: BLE001 - never lose the hops collected so far
            log.exception("traceroute to %s failed", job.host)
            error = f"traceroute failed: {exc}"

        # gather the hop names that came back (overall cap, daemon threads are abandoned)
        if lookups:
            deadline = time.monotonic() + REVERSE_DNS_DEADLINE_S
            for lk in lookups.values():
                lk.done.wait(max(0.0, deadline - time.monotonic()))
            with job.lock:
                for hop in hops:
                    lk = lookups.get(hop["ip"]) if hop["ip"] else None
                    if lk is not None and lk.done.is_set():
                        hop["hostname"] = lk.name
        # router names are in now: locate the named hops again (a new dict: published hops are shallow copies)
        if geo is not None:
            refined = [(hop, self._locate(geo, hop, origin)) for hop in hops if hop["ip"] and hop["hostname"]]
            with job.lock:
                for hop, loc in refined:
                    hop["location"] = loc

        finished = float(self._clock())
        result["complete"] = complete
        result["error"] = error
        result["duration_s"] = round(max(0.0, finished - started), 3)
        self._last = result
        self._publish("trace.done", {"host": job.host, "target_ip": job.target_ip, "hops": len(hops),
                                     "complete": complete, "error": error, "duration_s": result["duration_s"]})
        log.info("traceroute %s (%s): %d hop(s), %s%s", job.host, job.target_ip, len(hops),
                 "complete" if complete else "incomplete", f" - {error}" if error else "")
        return result

    def _probe_fits(self, job: _Job) -> bool:
        """Whether one more probe, waited out to its full timeout, still ends inside the probing time limit."""
        return job.probe_deadline is None or self._monotonic() + job.timeout_ms / 1000.0 <= job.probe_deadline

    def _probe_hop(self, job: _Job, ttl: int, on_responder: Callable[[str], None],
                   quiet: bool = False) -> Tuple[Dict[str, Any], bool, Optional[str]]:
        """Send the probes for one TTL. Returns ``(hop, destination_reached, reply_error)``.

        *quiet* (deep in a silent run): stop after the first probe when it was not answered, so a
        long silent tail costs one timeout per hop; a hop that answers still gets all its probes.
        """
        rtts: List[Optional[float]] = []
        responders: List[str] = []
        first_ip: Optional[str] = None
        first_status: Optional[int] = None
        reached = False
        reply_error: Optional[str] = None
        for i in range(job.probes):
            if i and job.stop_requested():
                break
            if i and quiet and not responders:
                break
            if i and not self._probe_fits(job):
                break          # the hop keeps the probes it was sent; the trace loop then ends on the time limit
            t0 = time.perf_counter()
            try:
                r = self.pinger.ping(job.target_ip, size=PROBE_SIZE, timeout_ms=job.timeout_ms, ttl=ttl)
            except Exception:  # noqa: BLE001 - IcmpPinger.ping never raises; a stand-in might
                log.exception("traceroute probe ttl=%d failed", ttl)
                r = None
            wall_ms = (time.perf_counter() - t0) * 1000.0
            ok = bool(getattr(r, "ok", False))
            responder = getattr(r, "responder", None)
            if responder is None and ok:
                responder = job.target_ip        # a pinger without the responder field
            responder = str(responder) if responder else None
            if not responder:
                rtts.append(None)
                continue
            rtt = getattr(r, "rtt_ms", None)
            rtt_val = float(rtt) if rtt is not None else wall_ms   # TTL-expired replies carry no rtt
            rtts.append(round(rtt_val, 2))
            status = getattr(r, "status", None)
            try:
                status = int(status) if status is not None else None
            except (TypeError, ValueError):
                status = None
            if first_ip is None:
                first_ip = responder
                first_status = status
                on_responder(responder)
            responders.append(responder)
            if ok and responder == job.target_ip:
                reached = True
            elif status not in (STATUS_OK, STATUS_TTL_EXPIRED, None) and reply_error is None:
                text = getattr(r, "error", None) or f"ICMP status {status}"
                reply_error = f"{text} (from {responder})" if "reply from" not in str(text) else str(text)
        if reached:
            reply_error = None
        answered = [x for x in rtts if x is not None]
        alt_ips: List[str] = []
        for ip in responders:
            if ip != first_ip and ip not in alt_ips:
                alt_ips.append(ip)
        hop: Dict[str, Any] = {
            "ttl": ttl,
            "ip": first_ip,
            "alt_ips": alt_ips,
            "hostname": None,
            "rtts": rtts,
            "avg_ms": _round(sum(answered) / len(answered)) if answered else None,
            "min_ms": _round(min(answered)) if answered else None,
            "max_ms": _round(max(answered)) if answered else None,
            "loss": len(rtts) - len(answered),
            "responder_status": first_status,
            "kind": "unknown",
            "label": KIND_LABELS["unknown"],
            "location": None,
        }
        return hop, reached, reply_error
