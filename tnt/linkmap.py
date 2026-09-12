"""Live link map: this PC -> gateway -> internet, probed continuously.

Two always-on ICMP probes drive the map card at the top of the Network info page: the
machine's *current* default gateway (the same ``gateway`` alias the Ping tiles use) and one
internet host (``map.internet_host``, default totalelectronics.com). They reuse the same ICMP engine, payload size (loaded/unloaded
toggle), timeout and one-per-second aligned schedule as the Ping tiles, but they are
independent of them: they run even when neither host is a ping target, keep a short
in-memory history only and never write to the database.

Link states (``view()``):

* ``up``       - the last echo came back
* ``degraded`` - the last echo was missed but fewer than ``outage.miss_threshold`` in a
                 row (the last-minute loss percentage is reported alongside)
* ``down``     - ``outage.miss_threshold`` consecutive misses, or nothing to ping (no
                 default gateway / DNS failure)
* ``unknown``  - no sample yet

Every sample is published on the event bus as ``map.sample``
``{"probe": "gateway"|"internet", "ts", "ok", "rtt_ms", "ip", "state"}``.

The router's public (WAN) address is looked up separately (Cloudflare's trace endpoint,
thread ``tnt-linkmap-wan``, every 10 minutes, whenever the internet probe comes back up and
after a network change - at once, but never sooner than 30 s after the last lookup a network change
asked for, so a flapping network costs one lookup per half minute) and reported as ``view()["public_ip"]`` /
``view()["gateway"]["public_ip"]`` so the map can show it next to the gateway's LAN address.
``view()["public_geo"]`` is the IP location + ISP of that address (``geo_lookup``, the engine's
``tnt.geoip.GeoIpManager.lookup``: a local database read, computed at view time from the stored address;
None when the feature is off, no data is loaded, there is no address or no record).  It is logged at DEBUG only.

Network changes (:meth:`LinkMap.on_network_change`, called by the Engine for ``net.changed``):
both probes look their address up again on their next tick (a lookup the change overtook is
repeated), the PC node's cached address is dropped and the public address is checked again at
once (retried every 10 s for a minute while the new network is not ready; while that lookup fails the
previous network's address is dropped rather than shown as current).  The gateway is also
looked up at least every ``network.poll_s`` and 2 s after a miss.  A gateway probe that moves to
another router, or finds none (its IP is cleared: state ``down`` with the ``resolve_error``),
starts its samples and counters afresh, so the old router's loss and average never show up on
the new one.
"""
from __future__ import annotations

import collections
import importlib
import logging
import socket
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

PROBES: Tuple[str, ...] = ("gateway", "internet")
SAMPLES_KEEP = 180
RESOLVE_INTERVAL_S = 300.0
RESOLVE_RETRY_S = 10.0
GATEWAY_MISS_RECHECK_S = 2.0    # a missed gateway echo makes the probe look the gateway up again this soon
STOP_JOIN_S = 2.0
PC_INFO_CACHE_S = 5.0
DEFAULT_INTERNET_HOST = "totalelectronics.com"
#: The router's public (WAN) address is looked up through Cloudflare's trace endpoint - the
#: same service the speed test already talks to - every WAN_REFRESH_S, sooner after a
#: failure, and again whenever the internet probe comes back up (a new lease or a failover
#: usually means a new public address).
WAN_REFRESH_S = 600.0
WAN_RETRY_S = 60.0
WAN_CHANGE_RETRY_S = 10.0       # a failed lookup within WAN_CHANGE_WINDOW_S of a network change retries this soon
WAN_CHANGE_WINDOW_S = 60.0
WAN_CHANGE_MIN_GAP_S = 30.0     # lookups network changes ask for are at least this far apart
WAN_HOSTS: Tuple[str, ...] = ("1.1.1.1", "www.cloudflare.com")
WAN_TIMEOUT_S = 8.0


def _fetch_public_ip(timeout_s: float = WAN_TIMEOUT_S) -> Optional[str]:
    """``GET https://1.1.1.1/cdn-cgi/trace`` -> the ``ip=`` line, validated; None when unavailable."""
    import ipaddress

    base = importlib.import_module("tnt.speedtest.base")
    cloudflare = importlib.import_module("tnt.speedtest.cloudflare")
    last_error: Optional[Exception] = None
    for host in WAN_HOSTS:
        try:
            http_ = base.Http(host, scheme="https", timeout=timeout_s)
            try:
                reply = http_.get("/cdn-cgi/trace", max_bytes=65536)
            finally:
                try:
                    http_.close()
                except Exception:  # noqa: BLE001
                    pass
            ip = cloudflare.parse_trace(getattr(reply, "text", "") or "").get("ip", "").strip()
            if ip:
                return str(ipaddress.ip_address(ip))
        except Exception as exc:  # noqa: BLE001 - try the next host
            last_error = exc
    if last_error is not None:
        raise last_error
    return None


class _Probe:
    def __init__(self, name: str, host: str) -> None:
        self.name = name
        self.host = host
        self.ip: Optional[str] = None
        self.resolved = False
        self.resolve_error: Optional[str] = None
        self.last_resolve_ts: Optional[float] = None
        self.force = False              # look the address up on the next tick (a network change)
        self.epoch = 0                  # bumped by a network change: a lookup already running is stale
        self.samples: Deque[Tuple[float, bool, Optional[float]]] = collections.deque(maxlen=SAMPLES_KEEP)
        self.consecutive_missed = 0
        self.consecutive_ok = 0
        self.last: Optional[Dict[str, Any]] = None
        self.thread: Optional[threading.Thread] = None
        self.lock = threading.RLock()


class LinkMap:
    def __init__(self, config: Any, bus: Any, pinger: Any = None, clock: Callable[[], float] = time.time,
                 sleep: Optional[Callable[[float], None]] = None, resolver: Optional[Callable[[str], Optional[str]]] = None,
                 gateway_lookup: Optional[Callable[[], Optional[str]]] = None,
                 wan_fetch: Optional[Callable[[], Optional[str]]] = None,
                 geo_lookup: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None) -> None:
        self._config = config
        self._bus = bus
        self.pinger = pinger
        self._own_pinger = pinger is None
        self._clock = clock
        self._sleep = sleep
        self._resolver = resolver
        self._gateway_lookup = gateway_lookup
        self._wan_fetch = wan_fetch
        self._geo_lookup = geo_lookup
        self._geo_logged: Optional[Tuple[Any, ...]] = None
        self._wan: Dict[str, Any] = {"ip": None, "ts": None, "error": None, "checked_ts": None}
        self._wan_wake = threading.Event()
        self._wan_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._running = False
        self._lock = threading.RLock()
        self._probes: Dict[str, _Probe] = {
            "gateway": _Probe("gateway", "gateway"),
            "internet": _Probe("internet", self.internet_host()),
        }
        self._pc_cache: Tuple[float, Dict[str, Any]] = (0.0, {})
        self._wan_changed_ts: Optional[float] = None
        self._wan_due_ts: Optional[float] = None            # a network change asked for a lookup at this time
        self._wan_change_lookup_ts: Optional[float] = None  # when the last lookup a network change asked for ran

    # -- configuration -----------------------------------------------------------------
    def internet_host(self) -> str:
        try:
            host = str(self._config.get("map.internet_host", DEFAULT_INTERNET_HOST) or "").strip()
        except Exception:  # noqa: BLE001
            host = ""
        return host or DEFAULT_INTERNET_HOST

    def _cfg(self, key: str, default: Any) -> Any:
        try:
            v = self._config.get(key, default)
            return default if v is None else v
        except Exception:  # noqa: BLE001
            return default

    def _poll_s(self) -> float:
        """The gateway is looked up at least this often: every network watcher poll."""
        try:
            value = float(self._cfg("network.poll_s", 5))
        except (TypeError, ValueError):
            return 5.0
        return max(2.0, min(60.0, value)) if value == value else 5.0

    # -- lifecycle ---------------------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._stop.clear()
            self._running = True
            if self.pinger is None:
                from .icmp import IcmpPinger

                self.pinger = IcmpPinger()
                self._own_pinger = True
            for p in self._probes.values():
                # named like the ping workers so the Engine's "close the ICMP handle only when
                # no tnt-ping-* thread is alive" rule covers these too
                t = threading.Thread(target=self._run, args=(p,), name=f"tnt-ping-map-{p.name}", daemon=True)
                p.thread = t
                t.start()
            self._wan_wake.clear()
            self._wan_thread = threading.Thread(target=self._wan_loop, name="tnt-linkmap-wan", daemon=True)
            self._wan_thread.start()
        log.info("link map started: gateway + %s", self._probes["internet"].host)

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
        self._stop.set()
        self._wan_wake.set()
        deadline = time.monotonic() + STOP_JOIN_S
        for p in self._probes.values():
            t = p.thread
            if t is not None and t.is_alive() and t is not threading.current_thread():
                t.join(max(0.05, deadline - time.monotonic()))
        wt = self._wan_thread
        if wt is not None and wt.is_alive() and wt is not threading.current_thread():
            wt.join(max(0.05, deadline - time.monotonic()))
        alive = [p.name for p in self._probes.values() if p.thread is not None and p.thread.is_alive()]
        if self._own_pinger and self.pinger is not None and not alive:
            try:
                self.pinger.close()
            except Exception:  # noqa: BLE001
                log.exception("closing the link-map pinger failed")
        log.info("link map stopped%s", (" (probes still finishing: %s)" % ", ".join(alive)) if alive else "")

    @property
    def running(self) -> bool:
        return self._running

    # -- probing -----------------------------------------------------------------------
    def _wait(self, seconds: float) -> None:
        if seconds <= 0:
            return
        if self._sleep is not None:
            self._sleep(seconds)
        else:
            self._stop.wait(seconds)

    def _resolve(self, p: _Probe) -> Tuple[Optional[str], Optional[str]]:
        try:
            if p.name == "gateway":
                lookup = self._gateway_lookup
                if lookup is None:
                    lookup = importlib.import_module("tnt.pinger")._default_gateway
                gw = lookup()
                return (str(gw), None) if gw else (None, "this machine has no default gateway right now")
            host = self.internet_host()
            p.host = host
            resolver = self._resolver
            if resolver is None:
                resolver = importlib.import_module("tnt.icmp").resolve
            ip = resolver(host)
            return (str(ip), None) if ip else (None, "name resolution failed")
        except Exception as exc:  # noqa: BLE001
            return None, f"resolve failed: {exc}"

    def _maybe_resolve(self, p: _Probe, now: float) -> Optional[str]:
        for _attempt in range(2):
            with p.lock:
                last = p.last_resolve_ts
                if p.force or last is None or now < last:
                    due = True
                elif p.ip is None or not p.resolved:
                    due = now - last >= RESOLVE_RETRY_S
                elif p.name == "gateway":
                    due = (now - last >= min(RESOLVE_INTERVAL_S, self._poll_s())
                           or (p.consecutive_missed > 0 and now - last >= GATEWAY_MISS_RECHECK_S))
                else:
                    due = now - last >= RESOLVE_INTERVAL_S
                if not due:
                    return p.ip
                p.force = False
                epoch = p.epoch
            ip, err = self._resolve(p)
            with p.lock:
                if p.epoch != epoch:
                    continue                    # a network change overtook this lookup: look again
                p.last_resolve_ts = now
                old = p.ip
                if ip:
                    if ip != old:
                        log.info("link map %s -> %s", p.name, ip)
                    p.ip = ip
                    p.resolved = True
                    p.resolve_error = None
                else:
                    p.resolved = False
                    p.resolve_error = err
                    if p.name == "gateway":
                        p.ip = None             # no default gateway: never keep pinging the old router
                if p.name == "gateway" and old is not None and p.ip != old:
                    # another router (or none): the old one's loss and average say nothing about it
                    p.samples.clear()
                    p.consecutive_missed = 0
                    p.consecutive_ok = 0
                    p.last = None
                return p.ip
        with p.lock:
            return p.ip

    def tick(self, name: str, now: Optional[float] = None) -> Dict[str, Any]:
        """One probe cycle (resolve if due, ping once, record). Returns the sample event data."""
        p = self._probes[name]
        now = float(self._clock() if now is None else now)
        ip = self._maybe_resolve(p, now)
        ok, rtt = False, None
        if ip and self.pinger is not None:
            try:
                size = int(getattr(self._config, "ping_bytes", 32))
            except Exception:  # noqa: BLE001
                size = 32
            timeout_ms = int(self._cfg("ping.timeout_ms", 1000))
            ttl = int(self._cfg("ping.ttl", 128))
            try:
                r = self.pinger.ping(ip, size=size, timeout_ms=timeout_ms, ttl=ttl)
                ok = bool(getattr(r, "ok", False))
                rtt = getattr(r, "rtt_ms", None) if ok else None
            except Exception:  # noqa: BLE001
                log.exception("link map ping to %s failed", ip)
        with p.lock:
            was_up = bool(p.samples) and self._state_locked(p, now) == "up"
            p.samples.append((now, ok, rtt))
            if ok:
                p.consecutive_ok += 1
                p.consecutive_missed = 0
            else:
                p.consecutive_missed += 1
                p.consecutive_ok = 0
            p.last = {"ts": now, "ok": ok, "rtt_ms": rtt}
            data = {"probe": name, "ts": now, "ok": ok, "rtt_ms": rtt, "ip": p.ip, "state": self._state_locked(p, now)}
        if name == "internet" and ok and not was_up:
            self._wan_wake.set()      # the internet just came (back) up: re-check the public address soon
        try:
            self._bus.publish("map.sample", data)
        except Exception:  # noqa: BLE001
            log.exception("publishing map.sample failed")
        return data

    # -- public (WAN) address ------------------------------------------------------------
    def refresh_public_ip(self) -> Dict[str, Any]:
        """Look the router's public address up now; keeps the last known one on failure."""
        now = float(self._clock())
        error: Optional[str] = None
        ip: Optional[str] = None
        try:
            ip = self._wan_fetch() if self._wan_fetch is not None else _fetch_public_ip()
            if not ip:
                error = "no address in the reply"
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"[:200]
        with self._lock:
            if ip:
                if ip != self._wan.get("ip"):
                    log.info("public IP: %s", ip)
                self._wan = {"ip": ip, "ts": now, "error": None, "checked_ts": now}
            else:
                wan = dict(self._wan, error=error, checked_ts=now)
                changed = self._wan_changed_ts
                if changed is not None and wan.get("ip") and float(wan.get("ts") or 0.0) < changed:
                    # the last known address was looked up on the network this PC has left: never show it as current
                    wan["ip"] = None
                self._wan = wan
            return dict(self._wan)

    def public_ip(self) -> Optional[str]:
        """The last known public (WAN) address, or None."""
        with self._lock:
            return self._wan.get("ip")

    def _public_geo(self, ip: Optional[str]) -> Optional[Dict[str, Any]]:
        """IP location + ISP of the public address (a local lookup), or None; never raises."""
        if not ip or self._geo_lookup is None:
            return None
        try:
            geo = self._geo_lookup(ip)
        except Exception:  # noqa: BLE001
            log.debug("public IP location lookup failed", exc_info=True)
            return None
        if not isinstance(geo, dict):
            return None
        key = (ip, geo.get("place"), geo.get("isp"))
        if key != self._geo_logged:
            log.debug("public IP location: %s · %s", geo.get("place"), geo.get("isp"))
            self._geo_logged = key
        return dict(geo)

    def on_network_change(self, data: Optional[Dict[str, Any]] = None) -> None:
        """``net.changed`` (network watcher thread; quick, never raises): both probes look their
        address up on their next tick, the PC node is refreshed and the public address looked up
        at once, or :data:`WAN_CHANGE_MIN_GAP_S` after the last lookup a network change asked for."""
        try:
            for p in self._probes.values():
                with p.lock:
                    p.epoch += 1
                    p.force = True
            self._pc_cache = (0.0, {})
            now = float(self._clock())
            with self._lock:
                self._wan_changed_ts = now
                last = self._wan_change_lookup_ts
                spaced = last is None or now < last or now - last >= WAN_CHANGE_MIN_GAP_S
                self._wan_due_ts = now if spaced else last + WAN_CHANGE_MIN_GAP_S
            self._wan_wake.set()
        except Exception:  # noqa: BLE001
            log.exception("handling a network change in the link map failed")

    def _wan_loop(self) -> None:
        while not self._stop.is_set():
            # cleared before the lookup, so a network change reported while it runs wakes the next one
            self._wan_wake.clear()
            with self._lock:
                due = self._wan_due_ts
            now = float(self._clock())
            if due is not None and now < due:
                # a network change asked again within WAN_CHANGE_MIN_GAP_S: one lookup when that is up
                self._wan_wake.wait(min(due - now, WAN_CHANGE_MIN_GAP_S))
                continue
            if due is not None:
                with self._lock:
                    if self._wan_due_ts == due:
                        self._wan_due_ts = None
                    self._wan_change_lookup_ts = now
            try:
                result = self.refresh_public_ip()
            except Exception:  # noqa: BLE001
                log.exception("public IP lookup failed")
                result = {"ip": None}
            ok = bool(result.get("ip")) and not result.get("error")
            delay = WAN_REFRESH_S if ok else WAN_RETRY_S
            with self._lock:
                changed = self._wan_changed_ts
            if not ok and changed is not None and 0.0 <= float(self._clock()) - changed < WAN_CHANGE_WINDOW_S:
                delay = WAN_CHANGE_RETRY_S      # the new network may need a few seconds before it reaches out
            self._wan_wake.wait(delay)      # an early wake: the internet came back up, the network changed, or stop

    def _run(self, p: _Probe) -> None:
        interval = 1.0
        next_t = float(self._clock())
        while not self._stop.is_set():
            try:
                interval = max(0.5, float(self._cfg("ping.interval_s", 1.0)))
            except Exception:  # noqa: BLE001
                interval = 1.0
            now = float(self._clock())
            if now < next_t:
                self._wait(min(next_t - now, 1.0))
                continue
            try:
                self.tick(p.name, now)
            except Exception:  # noqa: BLE001
                log.exception("link map probe %s failed", p.name)
                self._wait(1.0)
            next_t += interval
            if next_t < now - 2 * interval or next_t > now + 2 * interval:
                next_t = now + interval     # fell behind (sleep/hibernate) or clock jump: re-anchor

    # -- state -------------------------------------------------------------------------
    def _threshold(self) -> int:
        try:
            return max(1, int(self._cfg("outage.miss_threshold", 3)))
        except (TypeError, ValueError):
            return 3

    def _state_locked(self, p: _Probe, now: float) -> str:
        if p.ip is None:
            return "down" if p.last_resolve_ts is not None else "unknown"
        if not p.samples:
            return "unknown"
        if p.consecutive_missed >= self._threshold():
            return "down"
        return "up" if p.samples[-1][1] else "degraded"

    def _probe_view(self, p: _Probe, now: float) -> Dict[str, Any]:
        with p.lock:
            recent = [s for s in p.samples if s[0] >= now - 60]
            sent = len(recent)
            received = sum(1 for s in recent if s[1])
            rtts = [s[2] for s in recent if s[1] and s[2] is not None]
            return {
                "name": p.name,
                "host": p.host,
                "ip": p.ip,
                "resolved": p.resolved,
                "resolve_error": p.resolve_error,
                "state": self._state_locked(p, now),
                "last": dict(p.last) if p.last else None,
                "consecutive_missed": p.consecutive_missed,
                "sent": sent,
                "received": received,
                "loss_pct": round(100.0 * (sent - received) / sent, 1) if sent else None,
                "avg_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
            }

    def _pc_info(self, now: float) -> Dict[str, Any]:
        ts, cached = self._pc_cache
        if cached and now - ts < PC_INFO_CACHE_S:
            return cached
        info: Dict[str, Any] = {"hostname": None, "ip": None, "adapter": None}
        try:
            info["hostname"] = socket.gethostname()
        except Exception:  # noqa: BLE001
            pass
        try:
            netinfo = importlib.import_module("tnt.netinfo")
            nic = netinfo.get_internet_nic()
            if nic is not None:
                info["ip"] = getattr(nic, "primary_ipv4", None)
                info["adapter"] = getattr(nic, "name", None)
        except Exception:  # noqa: BLE001
            log.debug("link map: internet NIC lookup failed", exc_info=True)
        self._pc_cache = (now, info)
        return info

    def view(self) -> Dict[str, Any]:
        now = float(self._clock())
        with self._lock:
            wan = dict(self._wan)
        gateway = self._probe_view(self._probes["gateway"], now)
        gateway["public_ip"] = wan.get("ip")
        return {
            "ts": now,
            "running": self._running,
            "internet_host": self.internet_host(),
            "pc": self._pc_info(now),
            "gateway": gateway,
            "internet": self._probe_view(self._probes["internet"], now),
            "public_ip": wan,
            "public_geo": self._public_geo(wan.get("ip")),
        }
