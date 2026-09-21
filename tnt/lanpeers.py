"""LAN peers (Tools page): find other TNT installs on the local network and measure the
TCP throughput between two of them.

Why this exists
---------------
A speed test to the internet says nothing about the office LAN.  Two technicians (or a
tech and the office server) both running TNT can measure the *local* link between their
machines: this module makes every TNT install announce itself and run a tiny, safe
throughput server, and lets the UI pick a peer and run an upload + download test to it.

Two services, both LAN-reachable (the only ones TNT exposes beyond 127.0.0.1):

* **Beacon / discovery (UDP 7132).**  Every :data:`BEACON_INTERVAL_S` a JSON datagram
  ``{"tnt": 1, "id", "hostname", "version", "port", "ts"}`` (<= 512 bytes) goes to
  ``255.255.255.255:7132`` *and* to each up IPv4 adapter's subnet-directed broadcast,
  from a socket bound to that adapter's own address (``SO_BROADCAST``).  Windows facts
  (measured for :mod:`tnt.dhcp`): a ``0.0.0.0``-bound sender follows the default route
  only, so a beacon must leave from every NIC separately; binding to the NIC address pins
  the egress NIC; ``/32`` tunnels and loopback have no broadcast domain and are skipped.
  A listener on ``0.0.0.0:7132`` (``SO_REUSEADDR``: the dev console on 7135 and the
  installed service may run at once) records every peer by its stable id; peers not heard
  from for :data:`PEER_TTL_S` expire.  ``lan.peers`` is published only when the set of
  peers or a peer's address/name/port changes, never per beacon.  Ids are free text, so a
  host sending beacons with fresh ids (a fuzzer, a hostile box) must not grow the table or
  flood every window: one source address holds at most :data:`MAX_PEERS_PER_IP` ids and the
  table at most :data:`MAX_PEERS` (the stalest id goes first), and at most
  :data:`PUBLISH_BURST` ``lan.peers`` go out per :data:`PUBLISH_WINDOW_S`; a change beyond
  that is sent with the table as it then is at the listener's next tick.
* **Throughput server (TCP 7133).**  One test at a time; a second connection while busy
  gets ``BUSY`` and is closed.  The protocol is deliberately tiny and never runs anything:
  the client sends a 16-byte header ``b"TNTT"`` + version ``1`` + mode (``b"U"`` client
  uploads / ``b"D"`` server sends) + seconds (1..20) + 9 reserved zero bytes; the server
  answers ``OK``, ``BUSY`` or ``BAD``.  Mode U: the client streams 64 KiB chunks for
  *seconds* then half-closes; the server counts bytes and the time from the first byte to
  EOF and replies with the 16-byte trailer ``b"TNTR"`` + byte count (8 bytes, big-endian)
  + elapsed ms (4 bytes, big-endian).  Mode D: the server streams for *seconds* and
  closes; the client counts.  Every socket has a 10 s timeout and every loop is bounded by
  the requested seconds + 5.  Mbps = bytes * 8 / elapsed / 1e6, always measured by the
  *receiving* side (what really arrived).

Windows Firewall blocks both inbound ports for the installed service, so ``start()``
ensures the program rules :data:`BEACON_FIREWALL_RULE` and :data:`THROUGHPUT_FIREWALL_RULE`
through :mod:`tnt.firewall` (on a helper thread: netsh must never delay the service start;
a failure is a warning in ``peers_view()["error"]``, not fatal).  The uninstaller deletes
both rules.

``lan.enabled`` (config, default on) switches the whole feature off: ``start()`` then does
nothing and ``peers_view()`` reports ``listening: false`` with ``error: "disabled"``.

Network changes (:meth:`LanPeers.on_network_change`, called by the Engine for ``net.changed``):
the adapter and self-address caches are dropped, the next beacon leaves at once from the new
addresses, every peer is matched to the current adapters again and a peer that sat on a subnet
this PC has left is dropped straight away instead of 20 s later (a peer that never matched a
subnet, heard through the limited broadcast, stays); ``lan.peers`` follows when the table
changed and ``lan.state`` carries the new ``self`` address.

Every worker thread is wrapped so a malformed datagram, a hostile client or a dead socket
can never kill a thread or the service.  Injectable seams (keyword arguments, defaulting
to the real thing): ``socket_factory``, ``adapters_fn``, ``runner`` (netsh), ``clock``,
``sleep``, ``bind_host`` and the two ports (``0`` = ephemeral, for tests).  ``tnt.netinfo``
is imported lazily through ``importlib`` so a fake in ``sys.modules`` is honoured.
"""
from __future__ import annotations

import importlib
import ipaddress
import json
import logging
import os
import socket
import struct
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from . import __version__
from . import firewall as _firewall

log = logging.getLogger(__name__)

__all__ = [
    "BEACON_PORT", "THROUGHPUT_PORT", "BEACON_INTERVAL_S", "PEER_TTL_S", "BEACON_MAX_BYTES", "PEER_ID_META",
    "BEACON_FIREWALL_RULE", "THROUGHPUT_FIREWALL_RULE", "MAGIC_REQUEST", "MAGIC_REPLY", "PROTO_VERSION",
    "MODE_UPLOAD", "MODE_DOWNLOAD", "HEADER_LEN", "TRAILER_LEN", "MIN_SECONDS", "MAX_SECONDS", "DEFAULT_SECONDS",
    "CHUNK", "SOCKET_TIMEOUT_S", "MAX_PEERS", "MAX_PEERS_PER_IP", "PUBLISH_BURST", "PUBLISH_WINDOW_S",
    "encode_beacon", "decode_beacon", "build_header", "parse_header", "build_trailer", "parse_trailer",
    "beacon_sources", "ThroughputError", "LanPeers",
]

# --- ports / timing -------------------------------------------------------------------------
#: Next to the API on 7130: 7132 = beacon (UDP), 7133 = throughput server (TCP).
BEACON_PORT = 7132
THROUGHPUT_PORT = 7133
BEACON_INTERVAL_S = 5.0
#: A peer whose last beacon is older than this is dropped (4 missed beacons).
PEER_TTL_S = 20.0
#: The peer table's hard size, and how many ids one source address may hold (the service and a dev console on one PC
#: are two).  A new id beyond either limit pushes out the stalest id (of that address, or of the whole table).
MAX_PEERS = 256
MAX_PEERS_PER_IP = 4
#: At most this many ``lan.peers`` events per window; a change beyond that goes out at the listener's next tick
#: after the window, with the table as it is then (a beacon flood cannot make every window rebuild the table).
PUBLISH_BURST = 8
PUBLISH_WINDOW_S = 1.0
BEACON_MAX_BYTES = 512
PEER_ID_META = "lan.peer_id"
BEACON_FIREWALL_RULE = "TNT LAN discovery (UDP 7132 in)"
THROUGHPUT_FIREWALL_RULE = "TNT LAN throughput (TCP 7133 in)"
BROADCAST_IP = "255.255.255.255"

# --- throughput protocol --------------------------------------------------------------------
MAGIC_REQUEST = b"TNTT"
MAGIC_REPLY = b"TNTR"
PROTO_VERSION = 1
MODE_UPLOAD = b"U"
MODE_DOWNLOAD = b"D"
HEADER_LEN = 16
TRAILER_LEN = 16
REPLY_OK, REPLY_BUSY, REPLY_BAD = b"OK", b"BUSY", b"BAD"
MIN_SECONDS, MAX_SECONDS, DEFAULT_SECONDS = 1, 20, 5
CHUNK = 64 * 1024
SOCKET_TIMEOUT_S = 10.0
#: Every server/client loop ends at most this long after the requested seconds.
LOOP_GRACE_S = 5.0
PROGRESS_INTERVAL_S = 0.25
CONNECT_TIMEOUT_S = 10.0
LISTEN_BACKLOG = 4

RX_TICK_S = 0.5
STOP_JOIN_S = 2.0
ADAPTER_CACHE_S = 5.0
SELF_INFO_CACHE_S = 5.0
HOSTNAME_MAX = 63
VERSION_MAX = 32
ID_MAX = 64

#: The bytes a throughput stream carries: random once, so no link-layer compression (PPP,
#: some VPN tunnels) can make a 64 KiB chunk of zeros look faster than the wire.
_PAYLOAD = os.urandom(CHUNK)
_TRAILER = struct.Struct("!4sQI")


class ThroughputError(RuntimeError):
    """A throughput test could not run to the end (refused, busy, protocol error, timeout)."""


# --- small helpers ------------------------------------------------------------------------
def _clean_text(value: Any, limit: int) -> str:
    """Printable characters only, stripped, at most *limit* long (this lands in the UI)."""
    if not isinstance(value, str):
        return ""
    text = "".join(ch for ch in value if ch.isprintable()).strip()
    return text[:limit]


def _valid_id(value: Any) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= ID_MAX:
        return False
    return all(ch.isalnum() or ch in "-_" for ch in value)


def _parse_ipv4(text: Any, what: str = "address") -> str:
    try:
        return str(ipaddress.IPv4Address(str(text).strip()))
    except (ValueError, TypeError, AttributeError):
        raise ValueError(f"{what} is not a valid IPv4 address: {str(text)[:40]!r}") from None


def _close(sock: Any) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except Exception:  # noqa: BLE001
        pass


def _oserror_text(exc: BaseException) -> str:
    code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
    if code in (10061, 111, 61):
        return "connection refused (is TNT running on the peer and its firewall rule in place?)"
    if code in (10060, 110, 60) or isinstance(exc, (socket.timeout, TimeoutError)):
        return "timed out (the peer did not answer; a firewall may be blocking TCP %d)" % THROUGHPUT_PORT
    if code in (10065, 113, 65):
        return "no route to the peer"
    return str(exc) or type(exc).__name__


# --- beacon codec ---------------------------------------------------------------------------
def encode_beacon(peer_id: str, hostname: str, version: str, port: int, ts: float) -> bytes:
    """The JSON datagram (compact, <= :data:`BEACON_MAX_BYTES` by construction)."""
    body = {
        "tnt": 1,
        "id": str(peer_id)[:ID_MAX],
        "hostname": _clean_text(hostname, HOSTNAME_MAX),
        "version": _clean_text(version, VERSION_MAX),
        "port": int(port),
        "ts": round(float(ts), 3),
    }
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    if len(raw) > BEACON_MAX_BYTES:                       # cannot happen with the caps above; be safe
        body["hostname"] = ""
        raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    return raw


def decode_beacon(raw: Any) -> Optional[Dict[str, Any]]:
    """Parse a datagram; ``None`` for anything that is not a well-formed beacon (wrong size,
    not JSON, not ours, bad id/port).  Never raises."""
    try:
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            return None
        raw = bytes(raw)
        if not 2 <= len(raw) <= BEACON_MAX_BYTES:
            return None
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            return None
        tag = data.get("tnt")
        if isinstance(tag, bool) or tag != 1:
            return None
        pid = data.get("id")
        if not _valid_id(pid):
            return None
        port = data.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return None
        ts = data.get("ts")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            ts = None
        return {
            "id": pid,
            "hostname": _clean_text(data.get("hostname"), HOSTNAME_MAX),
            "version": _clean_text(data.get("version"), VERSION_MAX),
            "port": port,
            "ts": float(ts) if ts is not None else None,
        }
    except Exception:  # noqa: BLE001 - a hostile datagram must never escape as an exception
        return None


# --- throughput framing -------------------------------------------------------------------
def build_header(mode: bytes, seconds: int) -> bytes:
    """``b"TNTT"`` + version + mode + seconds + 9 reserved zero bytes (16 bytes)."""
    if mode not in (MODE_UPLOAD, MODE_DOWNLOAD):
        raise ValueError("mode must be U or D")
    seconds = int(seconds)
    if not MIN_SECONDS <= seconds <= MAX_SECONDS:
        raise ValueError(f"seconds must be between {MIN_SECONDS} and {MAX_SECONDS}")
    return MAGIC_REQUEST + bytes([PROTO_VERSION]) + mode + bytes([seconds]) + b"\x00" * 9


def parse_header(raw: Any) -> Optional[Tuple[bytes, int]]:
    """``(mode, seconds)`` or ``None`` for anything that is not a valid v1 request.  The nine
    reserved bytes are ignored (a later version may use them)."""
    try:
        raw = bytes(raw)
        if len(raw) != HEADER_LEN or raw[:4] != MAGIC_REQUEST or raw[4] != PROTO_VERSION:
            return None
        mode = raw[5:6]
        if mode not in (MODE_UPLOAD, MODE_DOWNLOAD):
            return None
        seconds = raw[6]
        if not MIN_SECONDS <= seconds <= MAX_SECONDS:
            return None
        return mode, seconds
    except Exception:  # noqa: BLE001
        return None


def build_trailer(count: int, elapsed_ms: int) -> bytes:
    return _TRAILER.pack(MAGIC_REPLY, max(0, int(count)), max(0, min(0xFFFFFFFF, int(elapsed_ms))))


def parse_trailer(raw: Any) -> Optional[Tuple[int, int]]:
    """``(byte_count, elapsed_ms)`` or ``None``."""
    try:
        raw = bytes(raw)
        if len(raw) != TRAILER_LEN:
            return None
        magic, count, ms = _TRAILER.unpack(raw)
        if magic != MAGIC_REPLY:
            return None
        return int(count), int(ms)
    except Exception:  # noqa: BLE001
        return None


def _mbps(nbytes: int, elapsed_s: float) -> Optional[float]:
    if elapsed_s <= 0 or nbytes <= 0:
        return None
    return round(nbytes * 8 / elapsed_s / 1e6, 2)


# --- adapters -------------------------------------------------------------------------------
def _adapter_ipv4s(adapter: Any) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    for a in getattr(adapter, "ipv4", None) or []:
        addr = getattr(a, "address", None)
        prefix = getattr(a, "prefix", None)
        if addr and prefix is not None:
            try:
                out.append((str(addr), int(prefix)))
            except (TypeError, ValueError):
                continue
    return out


def _bench_ipv4(adapters: Sequence[Any]) -> Optional[str]:
    """The address "This PC" shows without an internet-facing adapter (a bench cable with static or self-assigned
    addresses, no default route): the first up adapter's address the beacons go out from, a physical adapter's
    before a virtual one and a routable address before a 169.254.x.x one; ``/32`` tunnel endpoints never."""
    ranked = []
    for pos, a in enumerate(adapters or []):
        if not _adapter_up(a):
            continue
        for ip, prefix in _adapter_ipv4s(a):
            if 1 <= prefix < 32 and not ip.startswith("127."):
                ranked.append((0 if getattr(a, "is_physical", False) else 1, 1 if ip.startswith("169.254.") else 0, pos, ip))
    return min(ranked)[3] if ranked else None


def _adapter_up(adapter: Any) -> bool:
    try:
        return bool(getattr(adapter, "is_up", True)) and not bool(getattr(adapter, "is_loopback", False))
    except Exception:  # noqa: BLE001
        return False


def beacon_sources(adapters: Sequence[Any]) -> List[Tuple[str, List[str]]]:
    """``[(bind_ip, [destinations...]), ...]``: one entry per usable IPv4 address of every up,
    non-loopback adapter; destinations are the limited broadcast plus the address's
    subnet-directed broadcast.  ``/32`` addresses (VPN / tunnel endpoints) and loopback
    have no broadcast domain and are skipped."""
    out: List[Tuple[str, List[str]]] = []
    seen: Set[str] = set()
    for a in adapters or []:
        if not _adapter_up(a):
            continue
        for ip, prefix in _adapter_ipv4s(a):
            if ip in seen or prefix >= 32 or prefix < 1:
                continue
            try:
                addr = ipaddress.IPv4Address(ip)
                if addr.is_loopback or addr.is_unspecified:
                    continue
                net = ipaddress.IPv4Interface(f"{ip}/{prefix}").network
            except ValueError:
                continue
            seen.add(ip)
            dests = [BROADCAST_IP]
            directed = str(net.broadcast_address)
            if directed not in dests:
                dests.append(directed)
            out.append((ip, dests))
    return out


# --- the component ------------------------------------------------------------------------
class LanPeers:
    """Beacon + peer table + throughput server/client (one instance per Engine; ``engine.lan``).

    Threads (all daemon): ``tnt-lan-beacon`` (send every 5 s), ``tnt-lan-listen`` (receive
    beacons, expire peers), ``tnt-lan-server`` (accept), ``tnt-lan-conn`` (one per accepted
    connection, bounded) and the short-lived ``tnt-lan-firewall``.  ``run_throughput`` runs
    on the caller's thread.
    """

    def __init__(self, config: Any, bus: Any, db: Any = None, pinger: Any = None,
                 clock: Callable[[], float] = time.time, *,
                 socket_factory: Optional[Callable[..., Any]] = None,
                 adapters_fn: Optional[Callable[[], Sequence[Any]]] = None,
                 beacon_port: int = BEACON_PORT, throughput_port: int = THROUGHPUT_PORT,
                 exe_path: Optional[str] = None, runner: Optional[Callable[..., Any]] = None,
                 sleep: Optional[Callable[[float], None]] = None, bind_host: str = "0.0.0.0") -> None:
        self._config = config
        self._bus = bus
        self._db = db
        self.pinger = pinger
        self._clock = clock
        self._socket_factory = socket_factory or socket.socket
        self._adapters_fn = adapters_fn
        self._beacon_port = int(beacon_port)
        self._throughput_port = int(throughput_port)
        # None = do not manage Windows Firewall rules at all (dev/console runs and tests; the
        # installed service passes TNTService.exe). Rules for a developer's python.exe would
        # otherwise pile up on every test run.
        self._exe_path = exe_path or None
        self._runner = runner
        self._sleep = sleep
        self._bind_host = str(bind_host or "0.0.0.0")

        self._lock = threading.RLock()          # peers, status, sockets
        self._op_lock = threading.RLock()       # start / stop serialised
        self._tp_lock = threading.Lock()        # one client-side throughput test at a time
        self._stop_evt = threading.Event()
        self._beacon_wake = threading.Event()   # set to send the next beacon now (network change, stop)
        self._rematch_pending = False           # a network change could not read the adapters: re-match at the next beacon
        self._running = False
        self._listening = False
        self._errors: Dict[str, str] = {}       # component -> problem (listener, server, firewall)
        self._peers: Dict[str, Dict[str, Any]] = {}
        self._publish_clock: Callable[[], float] = time.monotonic   # the lan.peers rate limit's clock (a test seam)
        self._publish_times: List[float] = []   # when the recent lan.peers went out (at most PUBLISH_BURST)
        self._peers_dirty = False               # a change is waiting for the rate limit
        self._listen_sock: Any = None
        self._server_sock: Any = None
        self._beacon_bound_port = self._beacon_port
        self._throughput_bound_port = self._throughput_port
        self._threads: List[threading.Thread] = []
        self._firewall_thread: Optional[threading.Thread] = None
        self._firewall: Dict[str, Any] = {"ok": None, "error": None}
        self._server_busy = False
        self._server_conns: Set[Any] = set()
        self._tp_running = False
        self._last_tp: Optional[Dict[str, Any]] = None
        self._adapter_cache: Tuple[float, List[Any]] = (0.0, [])
        self._self_cache: Tuple[float, Optional[str]] = (0.0, None)
        self._last_progress = 0.0

        try:
            self._hostname = _clean_text(socket.gethostname(), HOSTNAME_MAX) or "unknown"
        except Exception:  # noqa: BLE001
            self._hostname = "unknown"
        self._version = _clean_text(str(__version__), VERSION_MAX)
        self._peer_id = self._load_peer_id()

    # -- identity -----------------------------------------------------------------------
    def _load_peer_id(self) -> str:
        """A random id created once and kept in db meta ``lan.peer_id`` (memory only without
        a db) so a peer keeps its identity across restarts and address changes."""
        pid: Any = None
        if self._db is not None:
            try:
                pid = self._db.get_meta(PEER_ID_META)
            except Exception:  # noqa: BLE001
                log.exception("could not read %s", PEER_ID_META)
        if _valid_id(pid):
            return str(pid)
        pid = uuid.uuid4().hex
        if self._db is not None:
            try:
                self._db.set_meta(PEER_ID_META, pid)
            except Exception:  # noqa: BLE001
                log.exception("could not store %s", PEER_ID_META)
        return pid

    @property
    def peer_id(self) -> str:
        return self._peer_id

    @property
    def hostname(self) -> str:
        return self._hostname

    @property
    def running(self) -> bool:
        return self._running

    @property
    def listening(self) -> bool:
        return self._listening

    @property
    def beacon_port(self) -> int:
        """The beacon listener's port (the bound one once listening)."""
        return self._beacon_bound_port

    @property
    def throughput_port(self) -> int:
        """The throughput server's port (the bound one once listening) -- what the beacon
        advertises."""
        return self._throughput_bound_port

    @property
    def throughput_running(self) -> bool:
        return self._tp_running

    def enabled(self) -> bool:
        try:
            return bool(self._config.get("lan.enabled", True))
        except Exception:  # noqa: BLE001
            return True

    def set_enabled(self, on: Any) -> Dict[str, Any]:
        """Turn LAN discovery on or off, persist it and apply it right away.

        Off closes the beacon listener and the throughput server, so this machine stops
        announcing itself, stops hearing peers and refuses throughput connections (a test in
        flight is cut).  Publishes ``lan.state`` with the new :meth:`peers_view` so every
        open window follows.  Idempotent."""
        on = bool(on)
        try:
            self._config.update({"lan": {"enabled": on}})
        except Exception as exc:  # noqa: BLE001
            log.exception("could not save lan.enabled")
            raise RuntimeError(f"could not save the setting: {exc}") from exc
        if on:
            self.start()
        else:
            self.stop()
        log.info("LAN discovery %s", "enabled" if on else "disabled")
        view = self.peers_view()
        self._publish("lan.state", view)
        return view

    # -- adapters -----------------------------------------------------------------------
    def _adapters(self, fresh: bool = False) -> List[Any]:
        """Up, non-loopback adapters via the seam or ``tnt.netinfo`` (cached 5 s); never raises."""
        now = time.monotonic()
        ts, cached = self._adapter_cache
        if not fresh and cached is not None and now - ts < ADAPTER_CACHE_S and ts > 0:
            return cached
        out: List[Any] = []
        try:
            if self._adapters_fn is not None:
                out = [a for a in (self._adapters_fn() or []) if _adapter_up(a)]
            else:
                netinfo = importlib.import_module("tnt.netinfo")
                out = list(netinfo.get_adapters(include_down=False, include_loopback=False) or [])
        except Exception:  # noqa: BLE001
            log.exception("adapter enumeration failed")
            out = []
        self._adapter_cache = (now, out)
        return out

    def _adapter_for(self, ip: str, adapters: Optional[Sequence[Any]] = None) -> Optional[str]:
        """Name of the up adapter (of *adapters*, default the cached list) whose subnet contains
        *ip* (``None`` when none does)."""
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return None
        for a in (self._adapters() if adapters is None else adapters):
            for own, prefix in _adapter_ipv4s(a):
                try:
                    if addr in ipaddress.IPv4Interface(f"{own}/{prefix}").network:
                        return str(getattr(a, "name", "") or "") or None
                except ValueError:
                    continue
        return None

    def _self_ip(self) -> Optional[str]:
        """Primary IPv4 of the internet-facing NIC, else :func:`_bench_ipv4` (cached 5 s); ``None`` when unknown."""
        now = time.monotonic()
        ts, cached = self._self_cache
        if ts > 0 and now - ts < SELF_INFO_CACHE_S:
            return cached
        ip: Optional[str] = None
        try:
            adapters = self._adapters()
            nic: Any = None
            if self._adapters_fn is None:
                netinfo = importlib.import_module("tnt.netinfo")
                nic = netinfo.get_internet_nic(adapters)
            else:
                with_gw = [a for a in adapters if getattr(a, "gateways", None)]
                nic = (with_gw or adapters or [None])[0]
            if nic is not None:
                ip = getattr(nic, "primary_ipv4", None)
                if not ip:
                    ips = _adapter_ipv4s(nic)
                    ip = ips[0][0] if ips else None
            if not ip:
                ip = _bench_ipv4(adapters)
        except Exception:  # noqa: BLE001
            log.debug("internet NIC lookup failed", exc_info=True)
        self._self_cache = (now, ip)
        return ip

    # -- events --------------------------------------------------------------------------
    def _publish(self, event_type: str, data: Dict[str, Any]) -> None:
        try:
            self._bus.publish(event_type, data)
        except Exception:  # noqa: BLE001
            log.exception("publish %s failed", event_type)

    def _publish_peers(self) -> None:
        """``lan.peers`` with the whole table, unless :data:`PUBLISH_BURST` went out in the last
        :data:`PUBLISH_WINDOW_S`: then the change waits for :meth:`_flush_peers` (the listener's next tick)."""
        now = float(self._publish_clock())
        with self._lock:
            recent = [t for t in self._publish_times if 0.0 <= now - t < PUBLISH_WINDOW_S]
            if len(recent) >= PUBLISH_BURST:
                self._publish_times = recent
                self._peers_dirty = True
                return
            recent.append(now)
            self._publish_times = recent
            self._peers_dirty = False
        self._publish("lan.peers", {"peers": self._peer_rows()})

    def _flush_peers(self) -> None:
        """Send a change the rate limit held back, once the window allows it."""
        if self._peers_dirty:
            self._publish_peers()

    # -- beacon --------------------------------------------------------------------------
    def beacon_bytes(self, ts: Optional[float] = None) -> bytes:
        return encode_beacon(self._peer_id, self._hostname, self._version, self._throughput_bound_port,
                             self._clock() if ts is None else ts)

    def send_beacon(self) -> int:
        """One beacon from every usable adapter address to the limited and the subnet-directed
        broadcast (:func:`beacon_sources`).  Without any usable adapter *and* without an
        injected ``adapters_fn`` (enumeration failed) a single unbound send follows the
        default route.  Returns the number of datagrams sent; never raises."""
        raw = self.beacon_bytes()
        sources = beacon_sources(self._adapters(fresh=True))
        if not sources and self._adapters_fn is None:
            sources = [("0.0.0.0", [BROADCAST_IP])]
        sent = 0
        for bind_ip, dests in sources:
            s = None
            try:
                s = self._socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.settimeout(1.0)
                s.bind((bind_ip, 0))
                for dest in dests:
                    try:
                        s.sendto(raw, (dest, self._beacon_bound_port))
                        sent += 1
                    except OSError as exc:
                        log.debug("beacon %s -> %s failed: %s", bind_ip, dest, exc)
            except OSError as exc:
                log.debug("beacon socket on %s failed: %s", bind_ip, exc)
            except Exception:  # noqa: BLE001
                log.exception("beacon send from %s failed", bind_ip)
            finally:
                _close(s)
        return sent

    def _wait(self, seconds: float, stop_evt: threading.Event) -> None:
        if seconds <= 0:
            return
        if self._sleep is not None:
            self._sleep(seconds)
        else:
            stop_evt.wait(seconds)

    def _beacon_loop(self, stop_evt: threading.Event) -> None:
        while not stop_evt.is_set():
            self._beacon_wake.clear()
            try:
                if self._rematch_pending:
                    self.refresh_peer_adapters()
                self._flush_peers()             # a held-back lan.peers, should the listener not be running
                self.send_beacon()
            except Exception:  # noqa: BLE001 - the beacon thread must never die
                log.exception("beacon loop error")
            if self._sleep is not None:
                self._wait(BEACON_INTERVAL_S, stop_evt)
            else:
                # an early wake: the network changed (announce the new addresses now) or stop()
                self._beacon_wake.wait(BEACON_INTERVAL_S)

    # -- peer table ----------------------------------------------------------------------
    def handle_datagram(self, raw: Any, src: Any) -> Optional[Dict[str, Any]]:
        """Record the peer behind one received datagram; ``None`` when it was not a beacon,
        our own, or came from an unusable source.  Publishes ``lan.peers`` on a change."""
        beacon = decode_beacon(raw)
        if beacon is None or beacon["id"] == self._peer_id:
            return None
        try:
            ip = _parse_ipv4(src[0])
        except (ValueError, TypeError, IndexError):
            return None
        now = float(self._clock())
        rec = {
            "id": beacon["id"], "hostname": beacon["hostname"] or None, "ip": ip, "version": beacon["version"] or None,
            "port": beacon["port"], "last_seen_ts": now, "adapter": self._adapter_for(ip),
        }
        evicted: List[str] = []
        with self._lock:
            old = self._peers.get(rec["id"])
            if old is None:
                evicted = self._make_room(ip)
            self._peers[rec["id"]] = rec
            changed = old is None or any(old.get(k) != rec[k] for k in ("ip", "hostname", "port", "version"))
        if evicted:
            log.debug("LAN peers: room for %s from %s made by dropping %s", rec["id"], ip, ", ".join(evicted))
        if changed:
            log.info("LAN peer %s %s (%s) %s", rec["hostname"] or rec["id"], ip, rec["version"], "found" if old is None else "changed")
            self._publish_peers()
        return dict(rec)

    def _make_room(self, ip: str) -> List[str]:
        """Before a new id is added (under the lock): drop the stalest ids of *ip* beyond
        :data:`MAX_PEERS_PER_IP` - 1, then the stalest of the table beyond :data:`MAX_PEERS` - 1.
        Returns the dropped ids."""
        def stalest(recs: List[Tuple[str, Dict[str, Any]]], keep: int) -> List[str]:
            if len(recs) <= keep:
                return []
            recs.sort(key=lambda item: float(item[1].get("last_seen_ts") or 0.0))
            return [pid for pid, _r in recs[:len(recs) - keep]]

        dropped = stalest([(pid, r) for pid, r in self._peers.items() if r.get("ip") == ip], MAX_PEERS_PER_IP - 1)
        for pid in dropped:
            self._peers.pop(pid, None)
        if len(self._peers) >= MAX_PEERS:
            more = stalest(list(self._peers.items()), MAX_PEERS - 1)
            for pid in more:
                self._peers.pop(pid, None)
            dropped += more
        return dropped

    def expire_peers(self, now: Optional[float] = None) -> List[str]:
        """Drop peers not heard from for :data:`PEER_TTL_S` (or seen in the future after a
        clock step).  Returns the dropped ids; publishes ``lan.peers`` when any went, or when a
        change is still waiting for the rate limit (:meth:`_publish_peers`)."""
        now = float(self._clock() if now is None else now)
        gone: List[str] = []
        with self._lock:
            for pid, rec in list(self._peers.items()):
                seen = float(rec.get("last_seen_ts") or 0.0)
                if now - seen >= PEER_TTL_S or seen - now > PEER_TTL_S:
                    self._peers.pop(pid, None)
                    gone.append(pid)
        if gone:
            log.info("LAN peer(s) expired: %s", ", ".join(gone))
            self._publish_peers()
        else:
            self._flush_peers()
        return gone

    def _read_adapters(self) -> Optional[List[Any]]:
        """Up, non-loopback adapters read afresh (the seam, else ``netinfo._query_adapters``); ``None``
        when the enumeration failed, which :meth:`_adapters` cannot tell apart from no adapters."""
        try:
            if self._adapters_fn is not None:
                return [a for a in (self._adapters_fn() or []) if _adapter_up(a)]
            netinfo = importlib.import_module("tnt.netinfo")
            query = getattr(netinfo, "_query_adapters", None)
            if not callable(query):
                return list(netinfo.get_adapters(include_down=False, include_loopback=False) or [])
            return [a for a in (query() or []) if _adapter_up(a)]
        except Exception:  # noqa: BLE001
            log.warning("LAN peers: reading the adapters failed; the peers are matched again at the next beacon", exc_info=True)
            return None

    def refresh_peer_adapters(self) -> List[str]:
        """Match every peer to the current adapters again (after a network change).  A peer that
        sat on one of this PC's subnets and no longer does is dropped at once; one that never
        matched a subnet (heard through the limited broadcast) is kept.  Publishes ``lan.peers``
        when the table changed; returns the dropped ids.  When the adapters cannot be read nothing
        is dropped (a failed enumeration is not "no subnets") and the beacon thread tries again."""
        adapters = self._read_adapters()
        if adapters is None:
            self._rematch_pending = True
            return []
        self._rematch_pending = False
        self._adapter_cache = (time.monotonic(), adapters)
        with self._lock:
            recs = [(pid, rec.get("ip"), rec.get("adapter")) for pid, rec in self._peers.items()]
        verdicts = [(pid, ip, old, self._adapter_for(str(ip or ""), adapters)) for pid, ip, old in recs]
        gone: List[str] = []
        changed = False
        with self._lock:
            for pid, ip, old, new in verdicts:
                rec = self._peers.get(pid)
                if rec is None or rec.get("ip") != ip:
                    continue                    # a beacon moved it meanwhile: that one is current
                if old and new is None:
                    self._peers.pop(pid, None)
                    gone.append(pid)
                    changed = True
                elif new != old:
                    rec["adapter"] = new
                    changed = True
        if gone:
            log.info("LAN peer(s) no longer on a local subnet: %s", ", ".join(gone))
        if changed:
            self._publish_peers()
        return gone

    def on_network_change(self, data: Optional[Dict[str, Any]] = None) -> None:
        """``net.changed`` (network watcher thread; quick, never raises): fresh adapters and self
        address, the next beacon from the new addresses right away, peers re-matched
        (:meth:`refresh_peer_adapters`) and ``lan.state`` with the new view."""
        try:
            self._adapter_cache = (0.0, [])
            self._self_cache = (0.0, None)
            self._beacon_wake.set()
            self.refresh_peer_adapters()
            self._publish("lan.state", self.peers_view())
        except Exception:  # noqa: BLE001
            log.exception("handling a network change in LAN peers failed")

    def _peer_rows(self, now: Optional[float] = None) -> List[Dict[str, Any]]:
        now = float(self._clock() if now is None else now)
        with self._lock:
            rows = [dict(r) for r in self._peers.values()]
        for r in rows:
            r["age_s"] = round(max(0.0, now - float(r.get("last_seen_ts") or now)), 1)
        rows.sort(key=lambda r: ((r.get("hostname") or "").lower(), r.get("ip") or ""))
        return rows

    def peers(self) -> List[Dict[str, Any]]:
        return self._peer_rows()

    def peer_for_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for rec in self._peers.values():
                if rec.get("ip") == ip:
                    return dict(rec)
        return None

    def _listen_loop(self, stop_evt: threading.Event, sock: Any) -> None:
        while not stop_evt.is_set():
            try:
                try:
                    raw, src = sock.recvfrom(2048)
                except (socket.timeout, TimeoutError, BlockingIOError, InterruptedError):
                    raw, src = None, None
                except OSError:
                    if stop_evt.is_set():
                        break
                    # WSAECONNRESET on a UDP socket (ICMP port-unreachable for one of our own
                    # broadcasts) is harmless; anything else is logged and we go on
                    log.debug("beacon recvfrom failed", exc_info=True)
                    stop_evt.wait(0.05)
                    raw, src = None, None
                if stop_evt.is_set():
                    break
                if raw is not None:
                    self.handle_datagram(raw, src)
                self.expire_peers()
            except Exception:  # noqa: BLE001 - the listen thread must never die
                log.exception("beacon listen loop error")
                stop_evt.wait(0.1)

    # -- views ---------------------------------------------------------------------------
    def _error_text(self) -> Optional[str]:
        with self._lock:
            parts = [f"{k}: {v}" for k, v in self._errors.items() if v]
            fw = self._firewall
        if fw.get("ok") is False and fw.get("error"):
            parts.append(f"firewall: {fw['error']}")
        return "; ".join(parts) if parts else None

    def peers_view(self) -> Dict[str, Any]:
        """``{"self": {id, hostname, ip, version, port}, "peers": [peer + age_s], "listening",
        "error"}`` plus ``running``, ``throughput_running``, ``beacon_port``, ``throughput_port``
        and ``firewall`` ``{ok, error}`` for the diagnostics/Tools page."""
        if not self._running and not self.enabled():
            error: Optional[str] = "disabled"
        else:
            error = self._error_text()
        with self._lock:
            fw = dict(self._firewall)
        return {
            "self": {
                "id": self._peer_id, "hostname": self._hostname, "ip": self._self_ip(),
                "version": self._version, "port": self._throughput_bound_port,
            },
            "peers": self._peer_rows(),
            "listening": bool(self._listening),
            "error": error,
            "enabled": self.enabled(),      # the Tools switch: off = not announcing, not listening
            "running": bool(self._running),
            "throughput_running": bool(self._tp_running),
            "beacon_port": self._beacon_bound_port,
            "throughput_port": self._throughput_bound_port,
            "firewall": fw,
        }

    def last_throughput(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._last_tp) if self._last_tp else None

    # -- firewall ------------------------------------------------------------------------
    def ensure_firewall(self) -> Tuple[bool, Optional[str]]:
        """Both inbound program rules for our exe (idempotent).  ``(ok, error)``; the result
        is mirrored into ``peers_view()["firewall"]`` / ``["error"]``."""
        if not self._exe_path:
            with self._lock:
                self._firewall = {"ok": None, "error": None}     # not managed (no program path)
            return True, None
        rules = ((BEACON_FIREWALL_RULE, "udp", self._beacon_port or self._beacon_bound_port),
                 (THROUGHPUT_FIREWALL_RULE, "tcp", self._throughput_port or self._throughput_bound_port))
        problems: List[str] = []
        for name, proto, port in rules:
            if not port:
                continue
            ok, err = _firewall.ensure_rule(name, self._exe_path, proto, port, self._runner)
            if not ok:
                problems.append(f"{name}: {err}")
        result = (not problems, "; ".join(problems) if problems else None)
        with self._lock:
            self._firewall = {"ok": result[0], "error": result[1]}
        if problems:
            log.warning("Windows Firewall rule(s) could not be created: %s", result[1])
        return result

    def _firewall_worker(self) -> None:
        try:
            self.ensure_firewall()
        except Exception:  # noqa: BLE001
            log.exception("firewall setup failed")

    def wait_firewall(self, timeout: float = 5.0) -> bool:
        """Block until the start-time firewall step finished (tests / diagnostics)."""
        t = self._firewall_thread
        if t is None:
            return True
        t.join(timeout)
        return not t.is_alive()

    # -- lifecycle -----------------------------------------------------------------------
    def _open_listener(self) -> Any:
        s = self._socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind((self._bind_host, self._beacon_port))
            s.settimeout(RX_TICK_S)
        except OSError:
            _close(s)
            raise
        return s

    def _open_server(self) -> Any:
        s = self._socket_factory(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((self._bind_host, self._throughput_port))
            s.listen(LISTEN_BACKLOG)
            s.settimeout(RX_TICK_S)
        except OSError:
            _close(s)
            raise
        return s

    @staticmethod
    def _bound_port(sock: Any, fallback: int) -> int:
        try:
            return int(sock.getsockname()[1]) or fallback
        except Exception:  # noqa: BLE001 - fakes may not implement getsockname
            return fallback

    def start(self) -> None:
        """Open the beacon listener and the throughput server, start the threads and ensure
        the firewall rules in the background.  Does nothing when ``lan.enabled`` is false.
        A port that cannot be bound is reported in ``peers_view()["error"]``; the other
        half keeps working.  Idempotent."""
        with self._op_lock:
            if self._running:
                return
            if not self.enabled():
                with self._lock:
                    self._listening = False
                log.info("LAN peers disabled by lan.enabled")
                return
            stop_evt = threading.Event()
            self._stop_evt = stop_evt
            errors: Dict[str, str] = {}
            listen_sock = server_sock = None
            try:
                listen_sock = self._open_listener()
                self._beacon_bound_port = self._bound_port(listen_sock, self._beacon_port)
            except OSError as exc:
                errors["listener"] = f"UDP {self._beacon_port} could not be opened: {exc}"
                log.error("LAN beacon listener: %s", errors["listener"])
            try:
                server_sock = self._open_server()
                self._throughput_bound_port = self._bound_port(server_sock, self._throughput_port)
            except OSError as exc:
                errors["server"] = f"TCP {self._throughput_port} could not be opened: {exc}"
                log.error("LAN throughput server: %s", errors["server"])
            threads: List[threading.Thread] = []
            with self._lock:
                self._errors = errors
                self._listen_sock = listen_sock
                self._server_sock = server_sock
                self._listening = listen_sock is not None
                self._peers = {}
                self._server_busy = False
                self._server_conns = set()
                self._firewall = {"ok": None, "error": None}
                self._running = True
                threads.append(threading.Thread(target=self._beacon_loop, args=(stop_evt,), name="tnt-lan-beacon", daemon=True))
                if listen_sock is not None:
                    threads.append(threading.Thread(target=self._listen_loop, args=(stop_evt, listen_sock), name="tnt-lan-listen", daemon=True))
                if server_sock is not None:
                    threads.append(threading.Thread(target=self._server_loop, args=(stop_evt, server_sock), name="tnt-lan-server", daemon=True))
                self._threads = threads
                self._firewall_thread = threading.Thread(target=self._firewall_worker, name="tnt-lan-firewall", daemon=True)
            self._firewall_thread.start()
            for t in threads:
                t.start()
        log.info("LAN peers started: beacon UDP %d, throughput TCP %d (id %s)",
                 self._beacon_bound_port, self._throughput_bound_port, self._peer_id[:8])

    def stop(self) -> None:
        """Stop the threads (joined for at most :data:`STOP_JOIN_S` in total), close every
        socket (a test in flight is cut).  Idempotent."""
        with self._op_lock:
            if not self._running:
                return
            self._running = False
            self._stop_evt.set()
            self._beacon_wake.set()
            with self._lock:
                socks = [self._listen_sock, self._server_sock] + list(self._server_conns)
                self._listen_sock = self._server_sock = None
                self._server_conns = set()
                self._listening = False
                threads = list(self._threads)
                fw = self._firewall_thread
                self._peers = {}
            for s in socks:
                _close(s)
            deadline = time.monotonic() + STOP_JOIN_S
            for t in threads + ([fw] if fw is not None else []):
                if t.is_alive() and t is not threading.current_thread():
                    t.join(max(0.05, deadline - time.monotonic()))
            alive = [t.name for t in threads if t.is_alive()]
            with self._lock:
                self._threads = []
            self._beacon_bound_port = self._beacon_port
            self._throughput_bound_port = self._throughput_port
        log.info("LAN peers stopped%s", (" (still finishing: %s)" % ", ".join(alive)) if alive else "")

    # -- throughput server ---------------------------------------------------------------
    def _server_loop(self, stop_evt: threading.Event, lsock: Any) -> None:
        while not stop_evt.is_set():
            try:
                try:
                    conn, addr = lsock.accept()
                except (socket.timeout, TimeoutError, BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    if stop_evt.is_set():
                        break
                    log.debug("accept failed", exc_info=True)
                    stop_evt.wait(0.1)
                    continue
                if stop_evt.is_set():
                    _close(conn)
                    break
                with self._lock:
                    self._server_conns.add(conn)
                t = threading.Thread(target=self._serve_connection, args=(conn, addr, stop_evt), name="tnt-lan-conn", daemon=True)
                t.start()
            except Exception:  # noqa: BLE001 - the accept thread must never die
                log.exception("throughput server loop error")
                stop_evt.wait(0.1)

    def _serve_connection(self, conn: Any, addr: Any, stop_evt: threading.Event) -> None:
        """One client: read the header, answer OK/BUSY/BAD, run the requested mode.  Bounded
        by the socket timeout and the requested seconds + grace; never raises."""
        acquired = False
        peer = "%s:%s" % (addr[0], addr[1]) if isinstance(addr, tuple) and len(addr) >= 2 else str(addr)
        try:
            conn.settimeout(SOCKET_TIMEOUT_S)
            header = self._recv_exact(conn, HEADER_LEN, time.monotonic() + SOCKET_TIMEOUT_S)
            parsed = parse_header(header) if header is not None else None
            if parsed is None:
                log.debug("throughput: bad request from %s", peer)
                conn.sendall(REPLY_BAD)
                return
            mode, seconds = parsed
            with self._lock:
                if not self._server_busy:
                    self._server_busy = True
                    acquired = True
            if not acquired:
                log.info("throughput: %s refused, a test is already running", peer)
                conn.sendall(REPLY_BUSY)
                return
            conn.sendall(REPLY_OK)
            log.info("throughput: %s test from %s for %d s", "upload" if mode == MODE_UPLOAD else "download", peer, seconds)
            if mode == MODE_UPLOAD:
                self._serve_upload(conn, seconds, stop_evt)
            else:
                self._serve_download(conn, seconds, stop_evt)
        except (OSError, ValueError) as exc:
            log.debug("throughput connection %s ended: %s", peer, exc)
        except Exception:  # noqa: BLE001
            log.exception("throughput connection %s failed", peer)
        finally:
            with self._lock:
                if acquired:
                    self._server_busy = False
                self._server_conns.discard(conn)
            _close(conn)

    def _serve_upload(self, conn: Any, seconds: int, stop_evt: threading.Event) -> None:
        """Mode U (the client sends): count until EOF, reply with the trailer."""
        deadline = time.monotonic() + seconds + LOOP_GRACE_S
        total = 0
        t0: Optional[float] = None
        t_end: Optional[float] = None
        while not stop_evt.is_set() and time.monotonic() < deadline:
            try:
                data = conn.recv(CHUNK)
            except (socket.timeout, TimeoutError):
                break
            now = time.monotonic()
            if not data:
                t_end = now
                break
            if t0 is None:
                t0 = now
            t_end = now
            total += len(data)
        elapsed_ms = int(round((t_end - t0) * 1000)) if t0 is not None and t_end is not None else 0
        conn.sendall(build_trailer(total, elapsed_ms))
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def _serve_download(self, conn: Any, seconds: int, stop_evt: threading.Event) -> None:
        """Mode D (we send): stream for *seconds*, then half-close so the client sees EOF."""
        deadline = time.monotonic() + seconds
        while not stop_evt.is_set() and time.monotonic() < deadline:
            conn.sendall(_PAYLOAD)
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        # wait (briefly) for the client's EOF so the data is flushed before the close
        try:
            conn.settimeout(2.0)
            while conn.recv(4096):
                pass
        except OSError:
            pass

    @staticmethod
    def _recv_exact(conn: Any, n: int, deadline: float) -> Optional[bytes]:
        """Exactly *n* bytes, or ``None`` on EOF / deadline."""
        buf = b""
        while len(buf) < n:
            if time.monotonic() > deadline:
                return None
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # -- throughput client ---------------------------------------------------------------
    def _progress(self, phase: str, phase_pct: float, mbps: Optional[float], force: bool = False) -> None:
        """``lan.throughput.progress`` at most ~4 times a second (phase starts always).
        ``pct`` is the whole test's progress (connect 0, upload 0-50, download 50-100);
        ``phase_pct`` the current phase's."""
        now = time.monotonic()
        if not force and now - self._last_progress < PROGRESS_INTERVAL_S:
            return
        self._last_progress = now
        phase_pct = max(0.0, min(100.0, float(phase_pct)))
        base = {"connect": 0.0, "upload": 0.0, "download": 50.0}.get(phase, 0.0)
        span = 0.0 if phase == "connect" else 50.0
        pct = round(base + span * phase_pct / 100.0, 1)
        self._publish("lan.throughput.progress", {"phase": phase, "pct": pct, "phase_pct": round(phase_pct, 1), "mbps": mbps})

    def _connect(self, ip: str, port: int) -> Tuple[Any, float]:
        """A connected TCP socket and the connect time in ms."""
        s = self._socket_factory(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(CONNECT_TIMEOUT_S)
            t0 = time.monotonic()
            s.connect((ip, port))
            ms = (time.monotonic() - t0) * 1000.0
            s.settimeout(SOCKET_TIMEOUT_S)
        except OSError:
            _close(s)
            raise
        return s, ms

    def _handshake(self, conn: Any, mode: bytes, seconds: int) -> None:
        conn.sendall(build_header(mode, seconds))
        reply = self._recv_exact(conn, 2, time.monotonic() + SOCKET_TIMEOUT_S)
        if reply == REPLY_OK:
            return
        if reply == REPLY_BUSY[:2]:
            raise ThroughputError("the peer is busy with another throughput test; try again in a moment")
        if reply == REPLY_BAD[:2]:
            raise ThroughputError("the peer rejected the request (incompatible TNT version?)")
        if reply is None:
            raise ThroughputError("the peer closed the connection without answering (not a TNT throughput server?)")
        raise ThroughputError(f"unexpected reply from the peer: {reply!r}")

    def _client_upload(self, conn: Any, seconds: int) -> Optional[float]:
        self._handshake(conn, MODE_UPLOAD, seconds)
        t0 = time.monotonic()
        t_end = t0 + seconds
        sent = 0
        self._progress("upload", 0.0, None, force=True)
        while True:
            now = time.monotonic()
            if now >= t_end:
                break
            conn.sendall(_PAYLOAD)
            sent += CHUNK
            now = time.monotonic()
            self._progress("upload", (now - t0) / seconds * 100.0, _mbps(sent, now - t0))
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        trailer = self._recv_exact(conn, TRAILER_LEN, time.monotonic() + SOCKET_TIMEOUT_S)
        parsed = parse_trailer(trailer) if trailer is not None else None
        if parsed is None:
            raise ThroughputError("the peer did not report the upload result")
        count, ms = parsed
        self._progress("upload", 100.0, _mbps(count, ms / 1000.0), force=True)
        return _mbps(count, ms / 1000.0)

    def _client_download(self, conn: Any, seconds: int) -> Optional[float]:
        self._handshake(conn, MODE_DOWNLOAD, seconds)
        deadline = time.monotonic() + seconds + LOOP_GRACE_S
        total = 0
        t0: Optional[float] = None
        t_end: Optional[float] = None
        self._progress("download", 0.0, None, force=True)
        while time.monotonic() < deadline:
            try:
                data = conn.recv(CHUNK)
            except (socket.timeout, TimeoutError):
                break
            now = time.monotonic()
            if not data:
                t_end = now
                break
            if t0 is None:
                t0 = now
            t_end = now
            total += len(data)
            self._progress("download", (now - t0) / seconds * 100.0, _mbps(total, now - t0))
        if t0 is None:
            raise ThroughputError("the peer sent no data")
        elapsed = (t_end - t0) if t_end is not None else 0.0
        result = _mbps(total, elapsed)
        self._progress("download", 100.0, result, force=True)
        return result

    def run_throughput(self, peer_ip: str, seconds: int = DEFAULT_SECONDS, port: Optional[int] = None) -> Dict[str, Any]:
        """Upload then download test against ``peer_ip`` (its advertised port from the peer
        table, else *port*, else the default).  Returns the RESULT DICT (``error`` set when it
        could not run: refused, busy, timeout -- nothing is raised for those).  Raises
        ``ValueError`` for a bad address/seconds and ``RuntimeError`` when a test is already
        running on this side."""
        ip = _parse_ipv4(peer_ip, "peer address")
        try:
            seconds = int(seconds)
        except (TypeError, ValueError):
            raise ValueError("seconds must be a whole number") from None
        if not MIN_SECONDS <= seconds <= MAX_SECONDS:
            raise ValueError(f"seconds must be between {MIN_SECONDS} and {MAX_SECONDS}")
        if not self._tp_lock.acquire(blocking=False):
            raise RuntimeError("a throughput test is already running")
        try:
            self._tp_running = True
            result = self._run_throughput(ip, seconds, port)
        finally:
            self._tp_running = False
            self._tp_lock.release()
        with self._lock:
            self._last_tp = dict(result)
        self._publish("lan.throughput.done", {"result": dict(result)})
        return result

    def _run_throughput(self, ip: str, seconds: int, port: Optional[int]) -> Dict[str, Any]:
        peer = self.peer_for_ip(ip)
        if port is None:
            port = int(peer["port"]) if peer and peer.get("port") else (self._throughput_port or THROUGHPUT_PORT)
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} out of range 1-65535")
        result: Dict[str, Any] = {
            "ts": float(self._clock()),
            "peer": {"ip": ip, "hostname": (peer or {}).get("hostname")},
            "seconds": seconds, "upload_mbps": None, "download_mbps": None, "latency_ms": None,
            "duration_s": None, "error": None,
        }
        t_start = time.monotonic()
        conn: Any = None
        log.info("throughput test to %s:%d for %d s", ip, port, seconds)
        self._progress("connect", 0.0, None, force=True)
        try:
            conn, connect_ms = self._connect(ip, port)
            latency = connect_ms
            if self.pinger is not None:
                try:
                    r = self.pinger.ping(ip, size=32, timeout_ms=1000, ttl=128)
                    if getattr(r, "ok", False) and getattr(r, "rtt_ms", None) is not None:
                        latency = float(r.rtt_ms)
                except Exception:  # noqa: BLE001
                    log.debug("latency ping to %s failed", ip, exc_info=True)
            result["latency_ms"] = round(float(latency), 2)
            result["upload_mbps"] = self._client_upload(conn, seconds)
            _close(conn)
            conn, _ms = self._connect(ip, port)
            result["download_mbps"] = self._client_download(conn, seconds)
        except ThroughputError as exc:
            result["error"] = str(exc)
        except (OSError, socket.timeout, TimeoutError) as exc:
            result["error"] = f"{ip}:{port}: {_oserror_text(exc)}"
        except Exception as exc:  # noqa: BLE001
            log.exception("throughput test to %s failed", ip)
            result["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            _close(conn)
        result["duration_s"] = round(time.monotonic() - t_start, 2)
        if result["error"]:
            log.warning("throughput test to %s failed: %s", ip, result["error"])
        else:
            log.info("throughput to %s: up %s Mbps, down %s Mbps, latency %s ms",
                     ip, result["upload_mbps"], result["download_mbps"], result["latency_ms"])
        return result
