"""Networks: which network this PC is on, identified by its router (ARCHITECTURE 3.20).

TNT is carried from customer network to customer network, and only the pings done from a site's own network are fair to
judge that site by.  Every ping minute, outage, speed test, Discovery run and report is therefore tagged with the network
current when it was collected (``network_id``, a row of table ``networks``), and a site report reads its own network's data.

Identity
--------
A network is its **router**: the MAC of the default gateway, read on the adapter that owns that gateway
(:func:`gateway_facts`).  The site is the network of the physical adapter the traffic leaves by (:func:`site_gateway`: a
full-tunnel VPN adapter, with or without a gateway of its own, is not the site).  Most small networks are 192.168.0.1 or
192.168.1.1/24 behind a consumer router, so the MAC is what tells two sites apart.  When the MAC cannot be read (an IPv6
router without a neighbour entry, no entry yet) the network is known by a **fingerprint**: a hash of the gateway address, the
owner adapter's subnet and the DHCP server (:func:`fingerprint`).  Virtual router MACs (VRRP, HSRP, GLBP, HA firewall
clusters: :func:`is_virtual_router_mac`) are the same at unrelated sites, so such a network is known by a fingerprint that
includes the MAC (kept in ``virtual_mac``), and has no ``mac`` of its own.  A network first seen behind a phone hotspot's
gateway and subnet (:data:`HOTSPOT_NETWORKS`) is **portable**, carried from site to site: no site is suggested for it and its
report reads only the current connection to it; :meth:`NetworkTracker.set_portable` marks any network so, or not.

:class:`NetworkTracker` (``engine.networks``)
-------------------------------------------
* ``start()`` (the Engine, right after the database and before any writer): identifies the network synchronously from the
  adapters and one neighbour-table read.  Without a network the id the previous run left (db meta ``networks.current``) stays
  and an offline spell starts at the previous run's last heartbeat; started on another network than the previous run's, the
  time since that heartbeat is a closed spell of the previous network that ended on the new one (travel).
* ``on_network_change(data)`` (the Engine, the first ``net.changed`` consumer): with a default gateway the network is
  identified at once; with none this PC is offline, **the id stays on the last network** (an outage at the site still counts
  for it) and an offline spell is recorded (table ``network_offline``), closed with the network identified next: when that is
  another network the spell was travel, which a report of the earlier network leaves out (``tnt.reports``).  A spell during
  which a physical adapter got onto another network without a gateway (a camera LAN; TNT's DHCP server re-addressing one,
  ``cause`` ``dhcp``) is marked ``lan``: travel even when the same network comes back.
* Identification: a MAC read in state reachable or permanent names the network at once (its row, else a new one), unless the
  event continues a connection whose network is not settled yet (a second event of it; the link back within ``flap_s`` after a
  drop inside its MAC wait): that MAC then resolves the connection from its change, as a poll would.  Otherwise the current
  network is kept until its router says otherwise when its fingerprint matches, or its gateway address is the same and the
  neighbour table names its router in any state, or has no entry yet while connected (an adapter switch, a dock); else the
  MAC-less row with that fingerprint (else a new row) is provisional.  A helper thread looks for the MAC every ``mac_poll_s``
  for up to ``mac_wait_s``.  A MAC in another state (stale, delay, probe) or from the ``arp -a`` fallback counts once seen
  twice ``confirm_s`` apart without another MAC in between; the MAC the current network already has never does (a stale entry
  of the router before, behind the same address, proves nothing).  When the router is read (``_resolve``): the network was
  right; or a provisional row this change created takes the MAC when no other row owns it; or, when another row owns it, what
  was tagged since the change moves there (``Database.retag_network``; all rows of a row this change created, which is then
  deleted); or, when the current row existed before (a fingerprint-only network of earlier visits, the MAC row this PC saw last
  behind the same address), a new row gets the data since the change, so earlier visits are never merged into another site.
* ``touch(now)`` (the maintenance heartbeat) and ``confirm()`` (a Full Scan's start): ``last_seen`` at most once per
  ``touch_every_s``, and a look at the router.  A network not settled since its change is resolved from that change (a MAC
  that arrives after the MAC wait; another router answering for a network kept by its address, within ``late_router_s``); a
  settled one whose router answers from another reachable MAC (a router replaced with no link loss) is another network from
  then on.  ``confirm()`` returns None while offline: the writers stay on the last network, a scan is on none.
* ``current_network_id()`` is a plain attribute read (the pinger calls it for every sample).  ``add_listener(fn)``:
  ``fn({"old_id","new_id","ts","late","reason"})`` when the id changes; ``late`` is a merge after the switch, dated back to the
  change (the OutageTracker closes what was open before ``ts``; the ReportManager follows a running Full Scan's network).
"""
from __future__ import annotations

import hashlib
import importlib
import ipaddress
import json
import logging
import math
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

__all__ = ["NetworkTracker", "fingerprint", "gateway_facts", "gatewayless_networks", "is_locally_administered", "is_virtual_router_mac",
           "looks_like_hotspot", "network_view", "router_vendor", "site_gateway", "unknown_network", "CURRENT_META_KEY", "FLAP_S",
           "HOTSPOT_NETWORKS", "IDENTITIES", "LATE_ROUTER_S", "MAC_WAIT_S", "MAC_POLL_S", "MAC_CONFIRM_S"]

#: how long a change looks for the router's MAC, how often, and how far apart two sightings of an unconfirmed MAC must be
MAC_WAIT_S = 15.0
MAC_POLL_S = 1.0
MAC_CONFIRM_S = 2.0
#: ``last_seen`` and the same-address router check at most this often (the maintenance heartbeat runs every 30 s)
TOUCH_EVERY_S = 60.0
#: a link that drops inside the MAC wait of a network not confirmed yet and comes back to the same gateway this soon is the same
#: connection (a flap): the router read then names the network from that connection's change
FLAP_S = 120.0
#: another router answering for a network kept by its address, whose own router was not confirmed since, moves the data since
#: that change when it answers within this long; later it is a router swapped from then on
LATE_ROUTER_S = 1800.0
#: db meta key of the current network (``{"id","ts"}``): the id stays on it across a restart without a network
CURRENT_META_KEY = "networks.current"
IDENTITIES: Tuple[str, ...] = ("mac", "fingerprint", "unknown")
#: neighbour states that name a router at once (others must be seen twice)
CONFIRMED_STATES = frozenset(("reachable", "permanent"))
#: virtual router MACs, identical at unrelated sites: VRRP (IPv4, IPv6), HSRP v1, HSRP v2, GLBP, and the cluster MACs of HA firewall
#: pairs, derived from a group id that is usually left at its default: FortiGate FGCP (FortiOS 5 / 6), Palo Alto HA, Juniper SRX
#: chassis cluster (prefixes from vendor documentation, not checked against hardware)
_VIRTUAL_MAC_PREFIXES = ("00:00:5E:00:01:", "00:00:5E:00:02:", "00:00:0C:07:AC:", "00:00:0C:9F:F", "00:07:B4:00:",
                         "00:09:0F:09:", "00:1B:17:00:", "00:10:DB:FF:")
#: ``(gateway, subnet)`` of phone hotspots, carried from site to site: iOS Personal Hotspot, Android's classic tethering network.
#: A network first seen behind one is portable (no site is suggested for it, a report reads only the current connection)
HOTSPOT_NETWORKS: Tuple[Tuple[str, str], ...] = (("172.20.10.1", "172.20.10.0/28"), ("192.168.43.1", "192.168.43.0/24"))
_FACT_COLUMNS = ("gateway_ip", "subnet", "dhcp_server", "dns_suffix", "nic")

Facts = Dict[str, Any]
Listener = Callable[[Dict[str, Any]], None]


# --------------------------------------------------------------------------------------------- pure helpers
def _finite(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _mac(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        from .oui import normalize_mac

        return normalize_mac(value)
    except Exception:  # noqa: BLE001 - no OUI module: no MAC
        return None


def _ip(text: Any) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(str(text).strip().split("%", 1)[0])
    except ValueError:
        return None


def is_virtual_router_mac(mac: Any) -> bool:
    """A VRRP / HSRP / GLBP or HA firewall cluster virtual MAC (the same group number gives the same MAC at unrelated sites)."""
    norm = _mac(mac)
    return bool(norm) and norm.startswith(_VIRTUAL_MAC_PREFIXES)  # type: ignore[union-attr]


def is_locally_administered(mac: Any) -> bool:
    """A MAC with the locally-administered bit set (randomised, a phone hotspot's, a virtual interface's): its OUI names no vendor."""
    norm = _mac(mac)
    return bool(norm) and bool(int(norm[:2], 16) & 0x02)  # type: ignore[index]


def looks_like_hotspot(facts: Optional[Facts]) -> bool:
    """Whether gateway facts are those of a phone hotspot (:data:`HOTSPOT_NETWORKS`)."""
    if not isinstance(facts, dict):
        return False
    gw = _ip(facts.get("gateway_ip"))
    try:
        subnet = ipaddress.ip_network(str(facts.get("subnet") or ""), strict=False)
    except ValueError:
        return False
    return any(gw == _ip(g) and subnet == ipaddress.ip_network(s) for g, s in HOTSPOT_NETWORKS)


def _adapter_up(a: Any) -> bool:
    up = getattr(a, "is_up", None)
    return (getattr(a, "status", "up") == "up") if up is None else bool(up)


def _ipv4_gateway(a: Any) -> Optional[str]:
    return next((str(g) for g in getattr(a, "gateways", None) or [] if _ip(g) is not None and _ip(g).version == 4), None)  # type: ignore[union-attr]


def site_gateway(adapters: Sequence[Any], nic: Any) -> Tuple[Optional[str], Optional[int]]:
    """``(gateway, adapter index)`` that identify the site: the internet adapter's gateway when it is a physical adapter; else the
    lowest-metric up physical adapter with an IPv4 gateway (a full-tunnel VPN whose adapter has a gateway of its own carries the
    route, but the site is the network the tunnel runs over); else the internet adapter's, else any up adapter's IPv4 gateway."""
    def any_gateway(a: Any) -> Optional[str]:
        gws = getattr(a, "gateways", None) or []
        return _ipv4_gateway(a) or (str(gws[0]) if gws else None)

    def rank(a: Any) -> Tuple[int, int]:
        return int(getattr(a, "metric_v4", 0) or 0), int(getattr(a, "index", 0) or 0)

    if nic is not None and bool(getattr(nic, "is_physical", False)) and any_gateway(nic):
        return any_gateway(nic), getattr(nic, "index", None)
    usable = [a for a in adapters or [] if _adapter_up(a) and not getattr(a, "is_loopback", False) and _ipv4_gateway(a)]
    physical = [a for a in usable if getattr(a, "is_physical", False)]
    if physical:
        best = min(physical, key=rank)
        return _ipv4_gateway(best), getattr(best, "index", None)
    if nic is not None and any_gateway(nic):
        return any_gateway(nic), getattr(nic, "index", None)
    if usable:
        best = min(usable, key=rank)
        return _ipv4_gateway(best), getattr(best, "index", None)
    return None, getattr(nic, "index", None) if nic is not None else None


def gatewayless_networks(adapters: Sequence[Any]) -> List[str]:
    """The IPv4 networks of the up physical adapters without a gateway (not APIPA, not loopback), sorted: a camera LAN, the
    network TNT's DHCP server serves.  Virtual adapters (Hyper-V, VirtualBox) are left out: they come and go with no move."""
    out: set = set()
    for a in adapters or []:
        if not _adapter_up(a) or not getattr(a, "is_physical", False) or getattr(a, "is_loopback", False) or _ipv4_gateway(a):
            continue
        for entry in getattr(a, "ipv4", None) or []:
            try:
                net = ipaddress.ip_network(str(getattr(entry, "network", "")), strict=False)
            except ValueError:
                continue
            if net.version == 4 and not net.is_link_local and not net.is_loopback:
                out.add(str(net))
    return sorted(out)


def fingerprint(gateway_ip: Any, subnet: Any, dhcp_server: Any, extra: Any = None) -> str:
    """A stable hash of ``gateway_ip|subnet|dhcp_server`` (plus *extra*, a virtual router MAC), lower-cased, 32 hex digits."""
    parts = [str(v or "").strip().lower() for v in (gateway_ip, subnet, dhcp_server)]
    if extra:
        parts.append(str(extra).strip().lower())
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]


def gateway_facts(adapters: Sequence[Any], gateway: Any, internet_index: Optional[int] = None) -> Optional[Facts]:
    """``{"gateway_ip","subnet","dhcp_server","dns_suffix","nic","if_index"}`` of the network behind *gateway*, from the adapter
    that owns it (an up one first, the internet adapter first, then the lowest metric): the gateway without an IPv6 zone, the
    owner's IPv4 network holding the gateway (else its first), for an IPv6 gateway its first network that is not link-local.
    None without a gateway; the adapter fields are None when no adapter lists it."""
    gw = _ip(gateway) if gateway else None
    if gw is None:
        return None
    owners = [a for a in adapters or [] if gw in [_ip(g) for g in (getattr(a, "gateways", None) or [])]]

    def rank(a: Any) -> Tuple[int, int, int, int]:
        up = getattr(a, "is_up", None)
        up = (getattr(a, "status", "up") == "up") if up is None else bool(up)
        return (0 if up else 1, 0 if internet_index is not None and getattr(a, "index", None) == internet_index else 1,
                int(getattr(a, "metric_v4", 0) or 0), int(getattr(a, "index", 0) or 0))

    owner = min(owners, key=rank) if owners else None
    subnet: Optional[str] = None
    if owner is not None:
        nets: List[Tuple[Any, bool]] = []
        for entry in getattr(owner, "ipv4" if gw.version == 4 else "ipv6", None) or []:
            try:
                net = ipaddress.ip_network(str(getattr(entry, "network", "")), strict=False)
            except ValueError:
                continue
            if net.version == 6 and net.is_link_local:
                continue
            nets.append((net, bool(getattr(entry, "preferred", True))))
        holding = [n for n, _p in nets if gw in n]
        preferred = [n for n, p in nets if p]
        pick = holding or preferred or [n for n, _p in nets]
        subnet = str(pick[0]) if pick else None
    return {"gateway_ip": str(gw), "subnet": subnet,
            "dhcp_server": (getattr(owner, "dhcp_server", None) or None) if owner is not None else None,
            "dns_suffix": (getattr(owner, "dns_suffix", None) or None) if owner is not None else None,
            "nic": (getattr(owner, "name", None) or None) if owner is not None else None,
            "if_index": getattr(owner, "index", None) if owner is not None else None}


def router_vendor(mac: Any) -> Optional[str]:
    """The registered vendor of a router MAC: of its OUI, or of the OUI with the locally-administered bit cleared when that bit
    is set (the rule the report uses for BSSIDs); None when unknown."""
    norm = _mac(mac)
    if norm is None:
        return None
    first = int(norm[:2], 16)
    prefix = f"{first & ~0x02 & 0xFF:02X}{norm[2:8]}" if first & 0x02 else norm[:8]
    try:
        from .oui import vendor_for_oui

        return vendor_for_oui(prefix)
    except Exception:  # noqa: BLE001 - netaddr missing: no vendor names
        return None


def network_view(row: Optional[Dict[str, Any]], with_times: bool = True) -> Optional[Dict[str, Any]]:
    """A ``networks`` row as the API and a report show it: ``{"id","mac","vendor","gateway_ip","subnet","dhcp_server","identity",
    "virtual_mac","portable"}`` (plus ``first_seen`` / ``last_seen`` *with_times*); ``identity`` is ``mac`` or ``fingerprint``
    (``virtual_mac``: the redundant gateway's MAC a fingerprint network includes).  None for no row."""
    if not row:
        return None
    mac = row.get("mac") or None
    out: Dict[str, Any] = {"id": int(row["id"]), "mac": mac, "vendor": router_vendor(mac) if mac else None,
                           "gateway_ip": row.get("gateway_ip"), "subnet": row.get("subnet"), "dhcp_server": row.get("dhcp_server"),
                           "identity": "mac" if mac else "fingerprint", "virtual_mac": None if mac else (row.get("virtual_mac") or None),
                           "portable": bool(row.get("portable"))}
    if with_times:
        out.update(first_seen=row.get("first_seen"), last_seen=row.get("last_seen"))
    return out


def unknown_network() -> Dict[str, Any]:
    """The report's ``meta.network`` when the network was not identified when the Full Scan started."""
    return {"id": None, "mac": None, "vendor": None, "gateway_ip": None, "subnet": None, "dhcp_server": None, "identity": "unknown",
            "virtual_mac": None, "portable": False}


# --------------------------------------------------------------------------------------------- the tracker
class NetworkTracker:
    """``engine.networks``: the current network id and its identification (see the module docstring)."""

    def __init__(self, db: Any, *, clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic,
                 facts_fn: Optional[Callable[[Optional[str]], Optional[Facts]]] = None,
                 neighbour_fn: Optional[Callable[[str, Optional[int]], Any]] = None,
                 lans_fn: Optional[Callable[[], Optional[Sequence[str]]]] = None,
                 mac_wait_s: float = MAC_WAIT_S, mac_poll_s: float = MAC_POLL_S, confirm_s: float = MAC_CONFIRM_S,
                 touch_every_s: float = TOUCH_EVERY_S, flap_s: float = FLAP_S, late_router_s: float = LATE_ROUTER_S) -> None:
        self._db = db
        self._clock = clock
        self._mono = monotonic
        self._facts_fn = facts_fn
        self._neighbour_fn = neighbour_fn
        self._lans_fn = lans_fn
        self.mac_wait_s = float(mac_wait_s)
        self.mac_poll_s = float(mac_poll_s)
        self.confirm_s = float(confirm_s)
        self.touch_every_s = float(touch_every_s)
        self.flap_s = float(flap_s)
        self.late_router_s = float(late_router_s)
        self._lock = threading.RLock()          # the fields below
        self._op_lock = threading.RLock()       # identifications, merges and spells take turns (database sequences)
        self._row: Optional[Dict[str, Any]] = None
        self._id: Optional[int] = None          # what writers read, without a lock
        self._facts: Optional[Facts] = None     # the gateway facts of the current connection
        self._change_ts: Optional[float] = None  # when the identification became uncertain: a merge re-tags from here
        self._created = False                   # the current row was created by that change (MAC-less): all its rows are this connection's
        self._confirmed = False                 # the network's router answered (reachable / permanent) since that change
        self._wait_until: Optional[float] = None  # monotonic end of the MAC wait of the last identification
        self._connected_ts: Optional[float] = None  # when this PC joined, or came back to, the current network
        self._offline = False
        self._offline_mono: Optional[float] = None  # monotonic start of the offline spell
        self._flap_ok = False                   # the spell began in the MAC wait of an unconfirmed network: a quick return continues it
        self._lan_base: Optional[set] = None    # the gateway-less networks this PC had when it went offline (None: unknown)
        self._lan_marked = False                # the open spell is marked as spent on another network without a gateway
        self._seq = 0                           # identifications, in order: a MAC poll of an older one gives up
        self._stopped = False                   # live until stop(): start() only identifies the network at once
        self._stop_evt = threading.Event()
        self._touched: Optional[float] = None
        self._listeners: List[Listener] = []
        self._threads: List[threading.Thread] = []
        #: the id the previous run left (the network the stale outage gap of this start belongs to)
        self.previous_id = self._load()

    # -- lifecycle -----------------------------------------------------------------------------
    @property
    def ready(self) -> bool:
        return bool(getattr(self._db, "networks_ready", False))

    def _load(self) -> Optional[int]:
        if not self.ready:
            return None
        try:
            raw = json.loads(self._db.get_meta(CURRENT_META_KEY) or "null")
            row = self._db.get_network(raw.get("id")) if isinstance(raw, dict) else None
        except (ValueError, TypeError, sqlite3.Error):
            log.exception("networks: reading the current network failed")
            row = None
        if row is not None:
            self._row, self._id = row, int(row["id"])
        return self._id

    def start(self) -> None:
        """Identify the network now (see the module docstring); quick, never raises."""
        self._stop_evt.clear()
        with self._lock:
            self._stopped = False
        if not self.ready:
            log.warning("networks: the database is not tagged with networks (its migration did not run); reports use the time rule")
            return
        try:
            now = float(self._clock())
            stopped_at = self._last_heartbeat(now)          # when the previous run stopped monitoring
            facts = self._facts_now(None)
            with self._op_lock:
                if facts is None:
                    # offline since the service stopped, as far as anyone knows: the spell starts then
                    self._go_offline(stopped_at if stopped_at is not None else now, self._lans())
                    log.info("networks: no network at start; data stays tagged with network %s", self._id)
                    return
                previous = self._id
                had_spell = self._db.open_offline_spell_row() is not None
                self._identify(facts, now, "start", fresh=True)
                if previous is not None and self._id is not None and self._id != previous and stopped_at is not None and not had_spell:
                    # stopped on one network, started on another: the time in between was not the earlier network's (travel)
                    self._db.add_offline_spell(previous, stopped_at, now, self._id)
        except Exception:  # noqa: BLE001
            log.exception("networks: identifying the network at start failed")

    def _last_heartbeat(self, now: float) -> Optional[float]:
        """The previous run's last heartbeat (db meta ``last_heartbeat``: read before the engine's housekeeping moves it), or None."""
        try:
            hb = _finite(self._db.get_meta("last_heartbeat"))
        except Exception:  # noqa: BLE001
            return None
        return hb if hb is not None and hb < now else None

    def stop(self) -> None:
        with self._lock:
            self._stopped = True
            self._seq += 1
            threads = list(self._threads)
        self._stop_evt.set()
        for t in threads:
            if t.is_alive() and t is not threading.current_thread():
                t.join(0.5)

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """Wait for the MAC polls that are running (tests); True when none is left."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                alive = [t for t in self._threads if t.is_alive()]
                self._threads = alive
            if not alive:
                return True
            if time.monotonic() >= deadline:
                return False
            alive[0].join(max(0.01, min(0.2, deadline - time.monotonic())))

    def add_listener(self, fn: Listener) -> Callable[[], None]:
        with self._lock:
            self._listeners.append(fn)

        def unsubscribe() -> None:
            with self._lock:
                if fn in self._listeners:
                    self._listeners.remove(fn)

        return unsubscribe

    # -- reads ---------------------------------------------------------------------------------
    def current_network_id(self) -> Optional[int]:
        """The id data collected now is tagged with (None: unknown); a plain attribute read."""
        return self._id

    @property
    def offline(self) -> bool:
        return self._offline

    def current(self) -> Optional[Dict[str, Any]]:
        """The current network as :func:`network_view` shows it (with ``first_seen`` / ``last_seen``) plus ``offline`` (this PC has no
        network with a gateway now: the network is the last one, which the data stays tagged with), or None."""
        with self._lock:
            row = dict(self._row) if self._row else None
            offline = self._offline
        view = network_view(row)
        if view is not None:
            view["offline"] = offline
        return view

    def connected_since(self, network_id: Any) -> Optional[float]:
        """When this PC joined, or came back to, *network_id* when that is the network it is on now; None otherwise or offline."""
        with self._lock:
            nid, offline, since = self._id, self._offline, self._connected_ts
        try:
            same = nid is not None and network_id is not None and int(network_id) == nid
        except (TypeError, ValueError):
            same = False
        return since if same and not offline else None

    def set_portable(self, network_id: Any, portable: bool) -> Optional[Dict[str, Any]]:
        """Mark *network_id* (as it stands after a merge) carried from site to site, or not; its :func:`network_view` without
        times, None when there is no such network (or data is not tagged)."""
        if not self.ready:
            return None
        nid = self._db.map_network_id(network_id)
        row = self._db.get_network(nid) if nid is not None else None
        if row is None:
            return None
        self._db.update_network(int(row["id"]), portable=1 if portable else 0)
        fresh = self._db.get_network(int(row["id"])) or row
        with self._lock:
            if self._id == int(fresh["id"]):
                self._row = fresh
        log.info("networks: network %d is %s", int(fresh["id"]), "portable (a hotspot or travel router)" if portable else "a site's network")
        return network_view(fresh, with_times=False)

    def describe(self, network_id: Any, with_times: bool = False) -> Optional[Dict[str, Any]]:
        """:func:`network_view` of the network *network_id* stands for now (after a merge), or None."""
        try:
            nid = self._db.map_network_id(network_id)
            return network_view(self._db.get_network(nid), with_times) if nid is not None else None
        except Exception:  # noqa: BLE001
            log.exception("networks: reading network %s failed", network_id)
            return None

    def gateway_mac(self, gateway: Any) -> Optional[str]:
        """The router MAC of the current network when *gateway* is its gateway (the report's network marker asks)."""
        with self._lock:
            facts, row = self._facts, self._row
        if not facts or not row or not gateway or _ip(gateway) != _ip(facts.get("gateway_ip")):
            return None
        return row.get("mac") or None

    # -- events --------------------------------------------------------------------------------
    def on_network_change(self, data: Dict[str, Any]) -> None:
        """``net.changed`` (the Engine, on the watcher thread, before the other consumers).  Never raises."""
        if not isinstance(data, dict) or not self.ready:
            return
        try:
            gateway = str(data.get("default_gateway") or "") or None
            ts = _finite(data.get("ts"))
            ts = float(self._clock()) if ts is None else ts
            facts = self._facts_now(gateway) if gateway else None
            if facts is None:
                self._go_offline(ts, self._lans(), data.get("cause"))
                return
            self._identify(facts, ts, "network change")
        except Exception:  # noqa: BLE001
            log.exception("networks: handling the network change failed")

    def touch(self, now: Optional[float] = None) -> None:
        """The maintenance heartbeat: ``last_seen`` and the same-address router check, at most every ``touch_every_s``."""
        if not self.ready:
            return
        mono = float(self._mono())
        with self._lock:
            if self._touched is not None and 0.0 <= mono - self._touched < self.touch_every_s:
                return
            self._touched = mono
            nid, offline = self._id, self._offline
        if nid is None or offline:
            return
        when = float(self._clock()) if now is None else float(now)
        try:
            self._db.touch_network(nid, when)
        except Exception:  # noqa: BLE001
            log.exception("networks: refreshing last_seen failed")
        self._check_router(when)

    def confirm(self) -> Optional[int]:
        """A quick look at the router before a Full Scan reads its network: a MAC that arrived late, or another router behind
        the same address; returns the current id, None while offline (the writers stay on the last network, but a scan started
        without a network with a gateway is on no site's network)."""
        if not self.ready:
            return None
        if not self._offline:
            self._check_router(float(self._clock()))
        return None if self._offline else self._id

    # -- internals -----------------------------------------------------------------------------
    def _facts_now(self, gateway_hint: Optional[str]) -> Optional[Facts]:
        if self._facts_fn is not None:
            return self._facts_fn(gateway_hint)
        netinfo = importlib.import_module("tnt.netinfo")
        adapters = netinfo.get_adapters(include_down=True, include_loopback=False)
        nic = netinfo.get_internet_nic(adapters)
        gateway, index = site_gateway(adapters, nic)
        if gateway is None:
            gateway, index = gateway_hint, getattr(nic, "index", None)
        return gateway_facts(adapters, gateway, index)

    def _lans(self) -> Optional[List[str]]:
        """The gateway-less networks this PC has now (:func:`gatewayless_networks`), or None when they cannot be read."""
        try:
            if self._lans_fn is not None:
                got = self._lans_fn()
            else:
                netinfo = importlib.import_module("tnt.netinfo")
                got = gatewayless_networks(netinfo.get_adapters(include_down=False, include_loopback=False))
        except Exception:  # noqa: BLE001
            log.debug("networks: the adapters' networks could not be read", exc_info=True)
            return None
        return None if got is None else sorted({str(n) for n in got if n})

    def _read_mac(self, facts: Facts) -> Optional[Tuple[str, Optional[str]]]:
        """``(MAC, neighbour state)`` of the gateway on its adapter, or None."""
        try:
            fn = self._neighbour_fn
            if fn is None:
                from .arp import neighbour as fn  # type: ignore[no-redef]
            got = fn(str(facts.get("gateway_ip")), facts.get("if_index"))
        except Exception:  # noqa: BLE001
            log.debug("networks: the gateway's neighbour entry could not be read", exc_info=True)
            return None
        if not got:
            return None
        mac = _mac(got[0])
        return (mac, got[1] if len(got) > 1 else None) if mac else None

    def _facts_fingerprint(self, facts: Facts, extra: Any = None) -> str:
        return fingerprint(facts.get("gateway_ip"), facts.get("subnet"), facts.get("dhcp_server"), extra)

    def _store(self) -> None:
        try:
            self._db.set_meta(CURRENT_META_KEY, json.dumps({"id": self._id, "ts": float(self._clock())}, separators=(",", ":")))
        except Exception:  # noqa: BLE001
            log.exception("networks: storing the current network failed")

    def _emit(self, events: Sequence[Dict[str, Any]]) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for event in events:
            for fn in listeners:
                try:
                    fn(dict(event))
                except Exception:  # noqa: BLE001
                    log.exception("networks: a network change listener failed")

    def _go_offline(self, ts: float, lans: Optional[Sequence[str]] = None, cause: Any = None) -> None:
        """No default gateway at *ts*: the id stays, a spell opens.  *lans* (the gateway-less networks now) and *cause* tell
        whether this PC is on another network without a gateway (a camera LAN, TNT's DHCP server re-addressing an adapter): the
        spell is then marked ``lan``, travel whatever network comes next."""
        with self._op_lock:
            mono = float(self._mono())
            with self._lock:
                already = self._offline
                nid, row = self._id, self._row
                if not already:
                    self._offline, self._offline_mono, self._lan_marked = True, mono, False
                    # dropped inside the MAC wait of a network not confirmed yet: coming straight back continues that connection
                    self._flap_ok = bool(nid is not None and not self._confirmed and self._wait_until is not None and mono < self._wait_until)
                    self._lan_base = set(lans) if lans is not None else None
                self._seq += 1                  # a MAC poll still running is about the network left
                base, marked = self._lan_base, self._lan_marked
            if not already and nid is not None:
                try:
                    self._db.open_offline_spell(nid, ts)
                except Exception:  # noqa: BLE001
                    log.exception("networks: recording the offline spell failed")
            own = str((row or {}).get("subnet") or "")
            new_lans = [n for n in lans or [] if base is not None and n not in base and n != own]
            if nid is None or marked or not (cause == "dhcp" or new_lans):
                return
            with self._lock:
                self._flap_ok, self._lan_marked = False, True
            try:
                self._db.mark_offline_spell("lan")
                log.info("networks: this PC is on a network without a gateway (%s): the time until the next network counts for no site",
                         ", ".join(new_lans) or "TNT's DHCP server")
            except Exception:  # noqa: BLE001
                log.exception("networks: marking the offline spell failed")

    def _identify(self, facts: Facts, ts: float, reason: str, fresh: bool = False) -> None:
        """Identify the network behind *facts* at *ts* (the module docstring).  *fresh*: the service's start (like a return from
        an offline spell, the connection before is over)."""
        with self._lock:
            self._seq += 1
            seq = self._seq
        got = self._read_mac(facts)
        fp = self._facts_fingerprint(facts)
        events: List[Dict[str, Any]] = []
        poll: Optional[List[Tuple[str, float]]] = None
        with self._op_lock:
            mono = float(self._mono())
            with self._lock:
                cur, cur_facts, offline, confirmed, created = self._row, self._facts, self._offline, self._confirmed, self._created
                change_ts = self._change_ts
                flap = bool(offline and self._flap_ok and self._offline_mono is not None and 0.0 <= mono - self._offline_mono <= self.flap_s)
            gw = _ip(facts.get("gateway_ip"))
            same_gw = cur is not None and gw is not None and gw == _ip((cur_facts or {}).get("gateway_ip") or cur.get("gateway_ip"))
            ongoing = same_gw and ((not offline and not fresh) or flap)       # this event continues the current connection
            mac = got[0] if got is not None and got[1] in CONFIRMED_STATES else None
            seen = got[0] if got is not None else None
            if cur is not None and mac is not None and ongoing and not confirmed:
                # the router of a connection whose network is not settled (a provisional network, a network kept by its address;
                # a second event of that connection, or the link back after a flap): resolved as a MAC poll would, from its change
                events += self._switch(cur, facts, change_ts if change_ts is not None else ts, created, False, reason, spell_ts=ts)
                events += self._resolve(mac)
            elif mac is not None:
                row = self._row_for_mac(mac, facts, ts)
                events += self._switch(row, facts, ts, False, True, reason, note_fp=True)
            elif cur is not None and (cur.get("fingerprint") == fp or bool(
                    cur.get("mac") and same_gw and (seen == cur.get("mac") or (seen is None and not offline and not fresh)))):
                # kept until its router says otherwise: the same gateway, subnet and DHCP server as then; or the same gateway
                # address with its router's MAC in the neighbour table in any state, or (while connected) with no entry yet: an
                # adapter switch (a dock), a DHCP server change on renewal
                nothing_changed = cur_facts is not None and self._facts_fingerprint(cur_facts) == fp and \
                    cur_facts.get("if_index") == facts.get("if_index")
                if ongoing and (flap or (created and not cur.get("mac"))):
                    keep = (change_ts, created, False)                  # the connection's change stays (all its rows move)
                elif ongoing and nothing_changed:
                    keep = (change_ts, created, confirmed)              # nothing that names a network changed (a DNS change)
                else:
                    keep = (ts, False, False)
                events += self._switch(cur, facts, keep[0] if keep[0] is not None else ts, keep[1], keep[2], reason, spell_ts=ts)
                if not keep[2]:
                    poll = [(seen, mono)] if seen is not None and seen != cur.get("mac") else []
            else:
                row = self._db.network_by_fingerprint(fp)
                new = row is None
                if row is None:
                    row = self._add_network(ts, facts, fingerprint=fp)
                events += self._switch(row, facts, ts, new, False, reason)
                poll = [(seen, mono)] if seen is not None else []
        self._emit(events)
        if poll is not None:
            self._start_poll(seq, dict(facts), poll)

    def _add_network(self, ts: float, facts: Facts, **extra: Any) -> Dict[str, Any]:
        """A new networks row with *facts* (portable when they look like a phone hotspot); a router MAC row backfills the untagged
        reports made behind it."""
        cols: Dict[str, Any] = {k: facts.get(k) for k in _FACT_COLUMNS}
        cols.update({k: v for k, v in extra.items() if v is not None})
        row = self._db.add_network(ts, portable=1 if looks_like_hotspot(facts) else 0, **cols)
        if row.get("portable"):
            log.info("networks: network %d (gateway %s) looks like a phone hotspot: portable, no site is suggested for it",
                     int(row["id"]), facts.get("gateway_ip"))
        if row.get("mac"):
            self._backfill(row)
        return row

    def _backfill(self, row: Dict[str, Any]) -> None:
        try:
            tagged = self._db.backfill_report_networks(int(row["id"]), row.get("mac"), row.get("gateway_ip"))
            if tagged:
                log.info("networks: %d report(s) saved before networks were identified were made behind router %s (network %d)",
                         tagged, row.get("mac"), int(row["id"]))
        except Exception:  # noqa: BLE001
            log.exception("networks: tagging the earlier reports of network %s failed", row.get("id"))

    def _row_for_mac(self, mac: str, facts: Facts, ts: float) -> Dict[str, Any]:
        if is_virtual_router_mac(mac):
            key = self._facts_fingerprint(facts, mac)
            return self._db.network_by_fingerprint(key) or self._add_network(ts, facts, fingerprint=key, virtual_mac=mac)
        return self._db.network_by_mac(mac) or self._add_network(ts, facts, mac=mac, fingerprint=self._facts_fingerprint(facts))

    def _refresh_row(self, row: Dict[str, Any], facts: Facts, ts: float, note_fp: bool = False) -> Dict[str, Any]:
        """The row with the facts of now and ``last_seen``; *note_fp*: its router was confirmed on these facts, so a MAC row notes
        how its network looks now (never on a keep or a merge: a docked adapter's address must not become the network's look)."""
        nid = int(row["id"])
        fields: Dict[str, Any] = {k: facts.get(k) for k in _FACT_COLUMNS}
        if note_fp and row.get("mac"):
            fields["fingerprint"] = self._facts_fingerprint(facts)
        self._db.update_network(nid, **fields)
        self._db.touch_network(nid, ts)
        return self._db.get_network(nid) or row

    def _switch(self, row: Dict[str, Any], facts: Facts, change_ts: float, created: bool, confirmed: bool, reason: str,
                spell_ts: Optional[float] = None, note_fp: bool = False) -> List[Dict[str, Any]]:
        """Make *row* the current network (call with the op lock held); returns the listener event when the id changed."""
        new_id = int(row["id"])
        mono = float(self._mono())
        ts = float(change_ts if spell_ts is None else spell_ts)
        with self._lock:
            old_id, was_offline = self._id, self._offline
            self._row, self._id, self._facts = row, new_id, dict(facts)
            self._change_ts = float(change_ts)
            self._created, self._confirmed = bool(created), bool(confirmed)
            self._wait_until = mono + self.mac_wait_s + 1.0
            self._offline, self._flap_ok, self._lan_base, self._lan_marked = False, False, None, False
            if old_id != new_id or was_offline or self._connected_ts is None:
                self._connected_ts = ts
        self._db.end_network_aliases(new_id, ts)
        refreshed = self._refresh_row(row, facts, ts, note_fp)
        with self._lock:
            if self._id == new_id:
                self._row = refreshed
        self._db.close_offline_spells(ts, new_id)
        self._store()
        if old_id == new_id:
            return []
        log.info("networks: this PC is on network %d (%s, gateway %s%s)", new_id,
                 "router " + str(refreshed.get("mac")) if refreshed.get("mac") else "provisional" if created else "no router MAC",
                 facts.get("gateway_ip"), f", {reason}" if reason else "")
        return [{"old_id": old_id, "new_id": new_id, "ts": ts, "late": False, "reason": reason}]

    def _merge(self, from_id: int, to_row: Dict[str, Any], facts: Facts, since: float, delete_from: bool,
               reason: str) -> List[Dict[str, Any]]:
        """Move what was tagged *from_id* since *since* to *to_row* and make it current (call with the op lock held)."""
        to_id = int(to_row["id"])
        with self._lock:
            self._row, self._id, self._offline = to_row, to_id, False
            self._created, self._confirmed = False, True
        moved = self._db.retag_network(from_id, to_id, since, delete_from=delete_from)
        self._db.end_network_aliases(to_id, since)
        refreshed = self._refresh_row(to_row, facts, float(self._clock()))
        with self._lock:
            if self._id == to_id:
                self._row = refreshed
        self._store()
        log.info("networks: network %d is network %d (router %s) since %.0f: moved %s%s", from_id, to_id, refreshed.get("mac"),
                 since, {k: v for k, v in moved.items() if v and k != "deleted"}, " and deleted it" if moved.get("deleted") else "")
        return [{"old_id": from_id, "new_id": to_id, "ts": since, "late": True, "reason": reason}]

    def _mac_arrived(self, seq: int, mac: str) -> None:
        with self._op_lock:
            with self._lock:
                if seq != self._seq or self._stopped:
                    return
            events = self._resolve(mac)
        self._emit(events)

    def _resolve(self, mac: str) -> List[Dict[str, Any]]:
        """The router *mac* answered for the current connection, whose network was not settled (call with the op lock held):
        the network was right; or a row this change created takes the MAC (no other row owns it); or what was tagged since the
        change moves to the row that owns it (all of a row this change created, which is then deleted); or a new row gets the
        data since the change (the current row existed before: earlier visits are never merged into another site).  A network
        kept by its address whose own router was not confirmed for ``late_router_s`` is another router from now on instead."""
        with self._lock:
            cur, cur_id, facts, since, created = self._row, self._id, self._facts, self._change_ts, self._created
        if cur is None or cur_id is None or facts is None or since is None:
            return []
        virtual = is_virtual_router_mac(mac)
        key = self._facts_fingerprint(facts, mac) if virtual else None
        if (virtual and not cur.get("mac") and cur.get("fingerprint") == key) or (not virtual and cur.get("mac") == mac):
            with self._lock:
                self._confirmed = True
            return []                                   # the network was right
        now = float(self._clock())
        if cur.get("mac") and now - since > self.late_router_s:
            log.info("networks: the router behind %s answers from %s now, not %s", facts.get("gateway_ip"), mac, cur.get("mac"))
            return self._switch(self._row_for_mac(mac, facts, now), facts, now, False, True, "router changed", note_fp=True)
        target = self._db.network_by_fingerprint(key) if virtual else self._db.network_by_mac(mac)
        provisional = not cur.get("mac")
        if target is not None and int(target["id"]) != cur_id:
            return self._merge(cur_id, target, facts, since, created and provisional, "router identified")
        if target is None and created and provisional:
            try:
                self._db.update_network(cur_id, **({"fingerprint": key, "virtual_mac": mac} if virtual else {"mac": mac}))
            except sqlite3.IntegrityError:
                log.warning("networks: router %s is another network's already; network %d keeps its fingerprint", mac, cur_id)
                return []
            fresh = self._db.get_network(cur_id) or cur
            with self._lock:
                self._row, self._confirmed = fresh, True
            self._store()
            log.info("networks: network %d identified by its router %s", cur_id, mac)
            if not virtual:
                self._backfill(fresh)
            return []
        if target is None:
            new = self._add_network(since, facts, mac=None if virtual else mac, fingerprint=key or self._facts_fingerprint(facts),
                                    virtual_mac=mac if virtual else None)
            return self._merge(cur_id, new, facts, since, False, "router identified")
        return []

    def _start_poll(self, seq: int, facts: Facts, sightings: List[Tuple[str, float]]) -> None:
        t = threading.Thread(target=self._poll, args=(seq, facts, sightings), name="tnt-networks-mac", daemon=True)
        with self._lock:
            self._threads = [x for x in self._threads if x.is_alive()] + [t]
        t.start()

    def _poll(self, seq: int, facts: Facts, sightings: List[Tuple[str, float]]) -> None:
        try:
            deadline = float(self._mono()) + self.mac_wait_s
            first = True
            while True:
                with self._lock:
                    if seq != self._seq or self._stopped:
                        return
                    own = (self._row or {}).get("mac") or None
                now = float(self._mono())
                got = None if first and sightings else self._read_mac(facts)
                first = False
                if got is not None:
                    mac, state = got
                    if state in CONFIRMED_STATES:
                        self._mac_arrived(seq, mac)
                        return
                    if mac != own:
                        # an unconfirmed entry of the router the network already has proves nothing (a stale entry of the site
                        # before, behind the same address): it never ends the wait; another MAC counts once seen twice
                        if any(m != mac for m, _t in sightings):
                            sightings = []              # another MAC in between: start over
                        sightings.append((mac, now))
                if sightings and sightings[-1][1] - sightings[0][1] >= self.confirm_s and len(sightings) >= 2:
                    self._mac_arrived(seq, sightings[-1][0])
                    return
                if now >= deadline:
                    log.info("networks: no router MAC for gateway %s within %.0f s; the network is known by its gateway and subnet",
                             facts.get("gateway_ip"), self.mac_wait_s)
                    return
                self._stop_evt.wait(max(0.01, min(self.mac_poll_s, deadline - now)))
        except Exception:  # noqa: BLE001
            log.exception("networks: looking for the router's MAC failed")

    def _check_router(self, now: float) -> None:
        """The heartbeat's (and a Full Scan's) look at the router.  A network not settled since its change (a MAC that arrives
        after the MAC wait, a network kept by its address whose own router never answered) is resolved from that change; a
        settled one whose router now answers from another reachable MAC (a router replaced with no link loss) is another network
        from now on."""
        with self._lock:
            cur, facts, offline, seq, confirmed = self._row, self._facts, self._offline, self._seq, self._confirmed
        if offline or cur is None or facts is None:
            return
        got = self._read_mac(facts)
        if got is None or got[1] not in CONFIRMED_STATES:
            return
        mac = got[0]
        try:
            if cur.get("mac") and is_virtual_router_mac(mac):
                return
            if cur.get("mac") and mac != cur.get("mac") and confirmed:
                log.info("networks: the router behind %s answers from %s now, not %s", facts.get("gateway_ip"), mac, cur.get("mac"))
                fresh = self._facts_now(str(facts.get("gateway_ip"))) or facts
                self._identify(fresh, now, "router changed")
            elif not (confirmed and cur.get("mac") == mac):
                self._mac_arrived(seq, mac)
        except Exception:  # noqa: BLE001
            log.exception("networks: checking the router failed")
