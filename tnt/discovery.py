"""On-demand network discovery.

A :class:`DiscoveryScanner` sweeps an IPv4 range and returns every host that
answered a ping **or** has at least one of the requested TCP ports open, enriched
with MAC (ARP cache), vendor (OUI) and reverse-DNS name.

The scan is built in and pure Python (``DiscoveryResult.method`` is ``"native"``): ICMP
sweep through ``tnt.icmp.IcmpPinger`` in a ``ThreadPoolExecutor``
(``discovery.ping_attempts`` passes, later passes only re-ping non-responders), then
``connect_ex`` probes against **every** address in the range for every port (same
executor, ``discovery.concurrency`` workers), then ARP (MAC) / OUI (vendor) / reverse DNS
with a NetBIOS fallback (hostname). No third-party scanner is involved and this module starts
no process (only ``tnt.arp`` may fall back to Windows' own ``arp -a``). Runs stored by a
release before 1.7.0 may carry another ``method`` value; they load and display as recorded.

Contract gaps / decisions taken here (the smallest sensible behaviour):

* ``parse_range`` returns a one-element ``list[IPv4Address]`` for a single IP
  (the contract allows ``IPv4Network | list[IPv4Address]``; a list keeps the
  "explicit addresses" semantics and needs no /32 special-casing downstream).
  CIDR text is parsed with ``strict=False`` so ``10.0.0.5/24`` means ``10.0.0.0/24``.
  Ranges are IPv4 only; IPv6 text is rejected with a clear message.
* Oversize ranges are rejected by ``parse_range`` (``ValueError`` naming
  ``discovery.max_hosts``), so ``scan`` reports them as ``ok=False``.
* A cancelled scan returns the hosts found so far with ``ok=True``,
  ``cancelled=True`` and no ARP/DNS enrichment (it stops as fast as possible).
* If ``tnt.icmp`` cannot be imported the sweep degrades to TCP-only (every
  ping counts as a miss); this is logged as an error but the scan still runs.
* Reverse DNS runs on plain daemon threads (not a ``ThreadPoolExecutor``) so
  that stragglers blocked inside ``gethostbyaddr`` can never delay service
  shutdown; results arriving after the 3 s cap are discarded.
* ``default_cidr`` is the internet-facing NIC's IPv4 network.  Without one (a static
  address without a gateway, a self-assigned 169.254.x.x adapter next to a real one) or
  when that NIC is a /31-/32 tunnel (a full-tunnel VPN), it is the first up physical adapter's
  preferred, non-link-local IPv4 network (``_first_up_ipv4``; never a Hyper-V / WSL switch),
  then a UDP-connect local-address guess (``/24``), and ``None`` when this PC is on no
  IPv4 network at all: the old ``192.168.1.0/24`` guess scanned a network it is not on.
* Extras for the Engine / diagnostics: ``running``, ``progress``, ``last_run_ts``
  properties and ``stop(timeout)`` (aborts a running scan and waits, bounded, for
  it to finish; used at service shutdown).
* One scanner runs one scan at a time: a second concurrent ``scan()`` call is
  refused with ``ok=False, error="a discovery scan is already running"`` instead
  of racing the first one.
* ``scan(None)`` / ``scan("")`` scans :meth:`DiscoveryScanner.default_cidr`
  (``parse_range`` itself still rejects an empty string with a helpful message).
* The port list is capped at ``MAX_PORTS`` entries (logged) and may be given as
  a comma/space separated string.
* A real ``tnt.icmp.IcmpPinger`` is never shared with the sweep pool, even when
  one is injected: it keeps one ICMP handle per thread and can only release them
  all in ``close()``, so pool threads (fresh on every scan) would leak
  ``concurrency`` handles into the service's pinger per scan. The scanner sweeps
  with a private pinger it closes afterwards; an injected object of any other
  type (a test double) is used as-is and never closed.
* On cancel the in-flight probe tasks are drained (bounded by one probe timeout,
  at most ``DRAIN_CAP_S``) before the scanner-owned ``IcmpPinger`` is closed, so a
  handle is never closed while another thread is still inside ``IcmpSendEcho2``.
  If stragglers outlive the drain cap, a daemon thread closes the pinger once
  they have exited (nothing blocks the scan's return or service shutdown).
* ``scan()`` reports a non-string, non-``None`` range as ``ok=False`` rather than
  scanning the default network; user text in error messages is bounded to 80 chars.
* ``DiscoveryResult.to_dict()`` adds ``"found"`` (host count) next to the dataclass
  fields; the dict is directly usable with ``Database.add_discovery_run``.
* Every host is categorised by :func:`classify_device` (``device_type``: Router / DW Server /
  Camera / Phone / Ubiquiti or ``None``) on the way out of ``scan()``, whatever the outcome. The
  rule set is pure and lives in one place; the UI only renders what the payload carries and
  :func:`fill_device_types` categorises rows stored before the column existed. The router is
  recognised by address, so the machine's own gateways are collected once per scan through
  :func:`gateway_ips` (``tnt.netinfo``, IPv4 only, failures = no Router) when the scan starts:
  a scan that the laptop carries onto another network still types the routers of the one it swept.

Module-level seams that tests (and only tests) monkeypatch: ``_tcp_connect``,
``_reverse_lookup``, ``_internet_ipv4``, ``_first_up_ipv4``, ``_local_ipv4_guess``,
``RESOLVE_DEADLINE_S``, ``MAX_PORTS`` and ``DRAIN_CAP_S``. ``tnt.icmp`` / ``tnt.arp`` /
``tnt.oui`` / ``tnt.netinfo`` are imported lazily through ``importlib`` so a fake
in ``sys.modules`` is honoured.
"""
from __future__ import annotations

import importlib
import ipaddress
import logging
import re
import socket
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

log = logging.getLogger(__name__)

__all__ = [
    "HostResult",
    "DiscoveryResult",
    "DiscoveryScanner",
    "ScanCancelled",
    "classify_device",
    "fill_device_types",
    "gateway_ips",
    "DEVICE_TYPES",
    "RESOLVE_DEADLINE_S",
]

#: Overall cap for the reverse-DNS phase (seconds). Patched down in tests.
RESOLVE_DEADLINE_S: float = 6.0   # reverse DNS (slow without PTR records on Windows) + NetBIOS fallback
#: Minimum interval between two progress callbacks (~10/s).
PROGRESS_INTERVAL_S: float = 0.1
#: ICMP payload used for the sweep (small: we only care about reachability).
SWEEP_PAYLOAD_BYTES: int = 32
SWEEP_TTL: int = 128
#: Upper bound on parallel reverse-DNS lookups.
RESOLVE_WORKERS: int = 64
#: Upper bound on the number of TCP ports probed per scan (input validation).
MAX_PORTS: int = 1024
#: Longest we wait for in-flight probe tasks after a cancel before giving up on them.
DRAIN_CAP_S: float = 5.0

#: Device categories :func:`classify_device` can return, in the order it tries them.
DEVICE_TYPES: List[str] = ["Router", "DW Server", "Camera", "Phone", "Ubiquiti"]
DW_SERVER_PORT: int = 7001      # Digital Watchdog Spectrum media server (its web/client port)
CAMERA_PORT: int = 554          # RTSP
PHONE_PORT: int = 5060          # SIP
UBIQUITI_VENDOR_MATCH: str = "ubiquiti"   # the OUI registry says "Ubiquiti Inc." / "Ubiquiti Networks Inc."
#: Device types earlier versions stored, and what they are called now (1.11 and older said "Wifi").
LEGACY_DEVICE_TYPES: Dict[str, str] = {"Wifi": "Ubiquiti"}

_RANGE_HELP = "e.g. 10.0.0.0/24, 10.0.0.1-10.0.0.50, 10.0.0.1-50 or a single IP such as 10.0.0.5"

ProgressFn = Callable[[Dict[str, Any]], None]
RangeType = Union[ipaddress.IPv4Network, List[ipaddress.IPv4Address]]


class ScanCancelled(Exception):
    """Raised internally when the cancel event (or ``stop()``) fires mid-scan.

    ``drained`` is False when probe tasks were still running in the pool when the
    raiser gave up waiting for them (the owner must then not close shared handles).
    """

    def __init__(self, drained: bool = True) -> None:
        super().__init__("scan cancelled")
        self.drained = drained


# --------------------------------------------------------------------------- results


@dataclass
class HostResult:
    ip: str
    hostname: Optional[str]
    mac: Optional[str]
    vendor: Optional[str]
    ping_ok: bool
    rtt_ms: Optional[float]
    open_ports: List[int] = field(default_factory=list)
    #: one of :data:`DEVICE_TYPES` or ``None`` (see :func:`classify_device`)
    device_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveryResult:
    ts: float
    cidr: str
    ports: List[int]
    method: str
    hosts: List[HostResult]
    scanned: int
    duration_s: float
    ok: bool
    error: Optional[str]
    cancelled: bool

    def to_dict(self) -> Dict[str, Any]:
        """JSON-able dict; ``hosts`` are dicts, plus ``found`` = number of hosts."""
        d = asdict(self)
        d["hosts"] = [h.to_dict() for h in self.hosts]
        d["found"] = len(self.hosts)
        return d


# --------------------------------------------------------------------------- helpers


def _short(text: Any, limit: int = 80) -> str:
    """User text as it should appear in an error message: stripped and bounded
    (a huge POST body must not be echoed verbatim into the log and the API error)."""
    s = str(text).strip()
    return s if len(s) <= limit else s[:limit] + "..."


def _ip_key(ip: str) -> Tuple[int, Any]:
    try:
        return (0, int(ipaddress.IPv4Address(ip)))
    except ValueError:
        return (1, ip)


def _normalize_mac(mac: Any) -> Optional[str]:
    """``"00-00-5e-00-53-ab"`` -> ``"00:00:5E:00:53:AB"``; ``None`` when not a MAC."""
    if not isinstance(mac, str):
        return None
    hexdigits = "".join(ch for ch in mac if ch not in ":-. ")
    if len(hexdigits) != 12:
        return None
    try:
        int(hexdigits, 16)
    except ValueError:
        return None
    hexdigits = hexdigits.upper()
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2))


def _usable_mac(mac: Optional[str]) -> Optional[str]:
    """Drop placeholder entries the ARP cache keeps for incomplete/broadcast rows."""
    if mac in (None, "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return None
    return mac


def _tcp_connect(ip: str, port: int, timeout: float) -> bool:
    """True when a TCP connection to ``ip:port`` completes within ``timeout`` seconds."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        return s.connect_ex((ip, int(port))) == 0
    except (OSError, OverflowError, ValueError, TypeError):
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def _reverse_lookup(ip: str) -> Optional[str]:
    """Reverse DNS for ``ip``; ``None`` on failure. May block (called from daemon threads)."""
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
    name = (name or "").strip().rstrip(".")
    if not name or name == ip:
        return None
    return name


# NetBIOS node-status request (NBSTAT, RFC 1002 4.2.17): a "*" name encoded in the
# first-level format, type NBSTAT (0x21), class IN. Windows PCs, printers and NAS boxes on
# the LAN answer it in ~10 ms even when the DNS server has no PTR record for them.
_NBSTAT_REQUEST = (b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                   b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00" + b"\x00\x21\x00\x01")


def _netbios_name(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Workstation name via a NetBIOS node-status query (UDP 137); ``None`` when nothing answers."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(_NBSTAT_REQUEST, (ip, 137))
        data, _ = s.recvfrom(4096)
    except (OSError, ValueError):
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
    # header (12) + RR name (34) + type/class/ttl/rdlength (10) -> number of names, then 18-byte entries
    if len(data) < 57:
        return None
    count = data[56]
    fallback = None
    for i in range(count):
        entry = data[57 + 18 * i: 57 + 18 * i + 18]
        if len(entry) < 18:
            break
        raw_name, suffix, flags = entry[:15], entry[15], int.from_bytes(entry[16:18], "big")
        if flags & 0x8000:  # group name (workgroup/domain), not a host
            continue
        name = raw_name.decode("latin-1").rstrip(" \x00").strip()
        if not name or name.startswith("\x01\x02"):
            continue
        if suffix == 0x00:      # workstation service = the computer name
            return name
        if suffix == 0x20 and fallback is None:  # file server service carries the same name
            fallback = name
    return fallback


def _resolve_name(ip: str) -> Optional[str]:
    """Reverse DNS first, NetBIOS second (LAN hosts rarely have PTR records)."""
    return _reverse_lookup(ip) or _netbios_name(ip)


def _internet_ipv4() -> Optional[Tuple[str, int]]:
    """``(address, prefix)`` of the internet-facing NIC via ``tnt.netinfo``; ``None`` if unknown.

    An adapter can carry several IPv4 addresses (a tentative APIPA 169.254.x.x next
    to the real DHCP lease, a secondary static address...). Prefer the address the
    default route actually uses, then a *preferred* (DAD state) one, then anything
    that parses. A self-assigned 169.254.x.x address never counts: a /24 around it is
    not a network anyone can scan (an IPv6-only network, where the internet adapter's
    only IPv4 address is self-assigned, gets the other adapters' networks or no default).
    """
    netinfo = importlib.import_module("tnt.netinfo")
    nic = netinfo.get_internet_nic()
    if nic is None:
        return None
    cands: List[Tuple[str, int, bool]] = []
    for a in getattr(nic, "ipv4", None) or []:
        addr = getattr(a, "address", None)
        prefix = getattr(a, "prefix", None)
        if not addr or prefix is None:
            continue
        try:
            if ipaddress.IPv4Address(addr).is_link_local:
                continue
            cands.append((str(addr), int(prefix), bool(getattr(a, "preferred", True))))
        except (ValueError, TypeError):
            continue
    if not cands:
        return None
    try:
        route_ip = _local_ipv4_guess()
    except Exception:  # noqa: BLE001
        route_ip = None

    def rank(c: Tuple[str, int, bool]) -> Tuple[int, int]:
        addr, _prefix, preferred = c
        return (0 if addr == route_ip else 1, 0 if preferred else 1)

    best = min(cands, key=rank)
    return best[0], best[1]


def _local_ipv4_guess() -> Optional[str]:
    """Local IPv4 chosen for the default route (UDP connect sends no packets)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(1.0)
        s.connect(("1.1.1.1", 53))
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass
    if not ip or ip.startswith("127.") or ip == "0.0.0.0":
        return None
    return ip


def _first_up_ipv4() -> Optional[Tuple[str, int]]:
    """``(address, prefix)`` of the first up *physical* adapter's preferred IPv4 address that is
    neither link-local (169.254.x.x) nor a /31-/32 point-to-point one.  For a PC without an
    internet-facing adapter (a static bench address without a gateway) or whose default route goes
    into a VPN tunnel.  A virtual adapter (a Hyper-V or WSL switch that stays up on every network, a
    VPN) is never the network a person means to scan, so a laptop on a network where no DHCP server
    answered gets no default rather than the virtual switch's."""
    netinfo = importlib.import_module("tnt.netinfo")
    best: Optional[Tuple[int, int, str, int]] = None
    for pos, adapter in enumerate(netinfo.get_adapters(include_down=False) or []):
        if getattr(adapter, "is_loopback", False) or not getattr(adapter, "is_physical", False):
            continue
        for entry in getattr(adapter, "ipv4", None) or []:
            if not bool(getattr(entry, "preferred", True)):
                continue
            try:
                addr = ipaddress.IPv4Address(str(getattr(entry, "address", "")))
                prefix = int(getattr(entry, "prefix", 32))
            except (TypeError, ValueError):
                continue
            if addr.is_link_local or addr.is_loopback or prefix >= 31:
                continue
            rank = (0 if getattr(adapter, "is_physical", False) else 1, pos, str(addr), prefix)
            if best is None or rank < best:
                best = rank
    return (best[2], best[3]) if best is not None else None


def _arp_table() -> Dict[str, str]:
    """``tnt.arp.get_arp_table()`` with every failure tolerated (empty dict)."""
    try:
        arp = importlib.import_module("tnt.arp")
        table = arp.get_arp_table() or {}
    except Exception as exc:  # noqa: BLE001 - optional enrichment
        log.warning("ARP table unavailable for discovery: %s", exc)
        return {}
    out: Dict[str, str] = {}
    try:
        for k, v in dict(table).items():
            out[str(k)] = str(v)
    except Exception:  # noqa: BLE001
        log.exception("unexpected ARP table shape")
    return out


def _vendor_lookup() -> Optional[Callable[[str], Optional[str]]]:
    """``tnt.oui.vendor_for_mac`` or ``None`` when the module is unavailable."""
    try:
        oui = importlib.import_module("tnt.oui")
        fn = getattr(oui, "vendor_for_mac")
    except Exception as exc:  # noqa: BLE001
        log.warning("OUI vendor lookup unavailable for discovery: %s", exc)
        return None
    return fn


# ----------------------------------------------------------------- device classification


def gateway_ips() -> Set[str]:
    """Every IPv4 default gateway of the machine's adapters (``set()`` when unknown).

    Used to spot the router in a scan. Enumeration failures are never fatal: an empty set
    just means no host is categorised as "Router".
    """
    out: Set[str] = set()
    try:
        netinfo = importlib.import_module("tnt.netinfo")
        adapters = netinfo.get_adapters() or []
    except Exception as exc:  # noqa: BLE001 - optional enrichment
        log.debug("netinfo unavailable for device classification: %s", exc)
        return out
    try:
        for adapter in adapters:
            for gw in getattr(adapter, "gateways", None) or []:
                try:
                    out.add(str(ipaddress.IPv4Address(str(gw).strip())))
                except (ValueError, TypeError):
                    continue          # IPv6 gateways (and junk) are not scan targets
    except Exception:  # noqa: BLE001
        log.debug("unexpected adapter shape while collecting gateways", exc_info=True)
    return out


def _port_set(open_ports: Any) -> Set[int]:
    ports: Set[int] = set()
    try:
        items = [open_ports] if isinstance(open_ports, (int, float)) and not isinstance(open_ports, bool) else (open_ports or [])
        for p in items:
            if isinstance(p, bool):
                continue
            try:
                ports.add(int(p))
            except (TypeError, ValueError):
                continue
    except TypeError:
        return ports
    return ports


def classify_device(ip: Any, open_ports: Any, mac: Optional[str] = None, vendor: Optional[str] = None,
                    hostname: Optional[str] = None, gateways: Iterable[str] = ()) -> Optional[str]:
    """Best guess at what a discovered host *is*; ``None`` when nothing matches.

    Pure (no I/O) so the UI can mirror it and tests can drive it directly. Identity first,
    then the most specific service, so a device that matches two rules gets the stronger one:

    1. ``Router``    -- *ip* is one of this machine's default gateways (*gateways*).
    2. ``DW Server`` -- TCP 7001 open (Digital Watchdog Spectrum media server).
    3. ``Camera``    -- TCP 554 open (RTSP).
    4. ``Phone``     -- TCP 5060 open (SIP).
    5. ``Ubiquiti``  -- the MAC vendor names Ubiquiti (an access point, a switch or a gateway); the
       branding alone is enough, whatever ports are open. A device that also matches a more specific
       service above keeps that stronger label (a Ubiquiti camera stays ``Camera``).

    *mac* and *hostname* are accepted for future rules and to keep the call site uniform.
    """
    ip_text = str(ip).strip() if ip is not None else ""
    if ip_text:
        for gw in gateways or ():
            if ip_text == str(gw).strip():
                return "Router"
    ports = _port_set(open_ports)
    if DW_SERVER_PORT in ports:
        return "DW Server"
    if CAMERA_PORT in ports:
        return "Camera"
    if PHONE_PORT in ports:
        return "Phone"
    if UBIQUITI_VENDOR_MATCH in str(vendor or "").lower():
        return "Ubiquiti"
    return None


def _classify_host(host: HostResult, gateways: Iterable[str]) -> Optional[str]:
    return classify_device(host.ip, host.open_ports, host.mac, host.vendor, host.hostname, gateways)


def apply_device_types(hosts: List[HostResult], gateways: Optional[Iterable[str]] = None) -> List[HostResult]:
    """Set ``device_type`` on every :class:`HostResult` (in place). Never raises."""
    try:
        gws = set(gateways) if gateways is not None else gateway_ips()
    except Exception:  # noqa: BLE001
        gws = set()
    for h in hosts or []:
        try:
            h.device_type = _classify_host(h, gws)
        except Exception:  # noqa: BLE001 - a classification must never break a scan
            log.debug("device classification failed for %r", getattr(h, "ip", None), exc_info=True)
            h.device_type = None
    return hosts


def fill_device_types(hosts: Any, gateways: Optional[Iterable[str]] = None) -> Any:
    """Categorise stored host **dicts** that carry no ``device_type`` (rows written before the
    ``discovery_hosts.device_type`` column existed), in place, and rename the types older versions
    stored (:data:`LEGACY_DEVICE_TYPES`). Never raises; rows that already have a current type are left
    untouched, and the gateways are only enumerated when something needs them.
    """
    try:
        for h in hosts or []:
            old = h.get("device_type") if isinstance(h, dict) else None
            if isinstance(old, str) and old in LEGACY_DEVICE_TYPES:
                h["device_type"] = LEGACY_DEVICE_TYPES[old]
        todo = [h for h in (hosts or []) if isinstance(h, dict) and not h.get("device_type")]
        if not todo:
            return hosts
        gws = set(gateways) if gateways is not None else gateway_ips()
        for h in todo:
            h["device_type"] = classify_device(h.get("ip"), h.get("open_ports"), h.get("mac"),
                                               h.get("vendor"), h.get("hostname"), gws)
    except Exception:  # noqa: BLE001 - never fail a request over this
        log.debug("device-type backfill failed", exc_info=True)
    return hosts


# --------------------------------------------------------------------------- internals


class _NullPinger:
    """Stand-in when ``tnt.icmp`` is unavailable: every ping is a miss."""

    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> Any:
        return _NullResult()

    def close(self) -> None:
        return None


class _NullResult:
    ok = False
    rtt_ms = None


class _ScanState:
    """Accumulates findings; written by the scan thread only (task threads return values)."""

    def __init__(self) -> None:
        self.responders: Dict[str, Optional[float]] = {}
        self.open_ports: Dict[str, List[int]] = {}
        self.pinged: Set[str] = set()
        self.macs: Dict[str, str] = {}
        self.vendors: Dict[str, str] = {}
        self.names: Dict[str, str] = {}

    def found_ips(self) -> List[str]:
        ips = set(self.responders) | {ip for ip, ps in self.open_ports.items() if ps}
        return sorted(ips, key=_ip_key)

    def found_count(self) -> int:
        return len(set(self.responders) | {ip for ip, ps in self.open_ports.items() if ps})

    def hosts(self) -> List[HostResult]:
        out: List[HostResult] = []
        for ip in self.found_ips():
            out.append(HostResult(
                ip=ip,
                hostname=self.names.get(ip),
                mac=self.macs.get(ip),
                vendor=self.vendors.get(ip),
                ping_ok=ip in self.responders,
                rtt_ms=self.responders.get(ip),
                open_ports=sorted(set(self.open_ports.get(ip, []))),
            ))
        return out


class _ProgressReporter:
    """Builds the contract progress dict and throttles callbacks to ~10/s."""

    def __init__(self, callback: Optional[ProgressFn], t0: float, state: _ScanState,
                 sink: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self._cb = callback
        self._sink = sink
        self._t0 = t0
        self._state = state
        self._last = 0.0
        self._warned = False
        self.phase = "ping"
        self.done = 0
        self.total = 0

    def snapshot(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "done": int(self.done),
            "total": int(self.total),
            "found": self._state.found_count(),
            "elapsed_s": round(time.monotonic() - self._t0, 2),
        }

    def set_phase(self, phase: str, total: int) -> None:
        self.phase = phase
        self.done = 0
        self.total = max(0, int(total))
        self.emit(force=True)

    def advance(self, n: int = 1) -> None:
        self.done += n

    def tick(self) -> None:
        self.emit(force=False)

    def emit(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last < PROGRESS_INTERVAL_S:
            return
        self._last = now
        snap = self.snapshot()
        if self._sink is not None:
            try:
                self._sink(snap)
            except Exception:  # noqa: BLE001
                pass
        if self._cb is None:
            return
        try:
            self._cb(dict(snap))
        except Exception:  # noqa: BLE001
            if not self._warned:
                self._warned = True
                log.exception("discovery progress callback failed (further failures suppressed)")

    def finish(self) -> None:
        self.phase = "done"
        if self.total <= 0:
            self.total = max(self.done, 1)
        self.done = self.total
        self.emit(force=True)


# --------------------------------------------------------------------------- scanner


class DiscoveryScanner:
    """On-demand IPv4 host discovery (ping + TCP ports + ARP + OUI + rDNS).

    ``config`` is a :class:`tnt.config.Config` (only ``get`` is used). A ``pinger``
    may be injected (tests use a fake); when ``None`` a private
    ``tnt.icmp.IcmpPinger`` is created per scan and closed afterwards so the
    per-thread ICMP handles of the pool threads are released.
    """

    def __init__(self, config: Any, pinger: Any = None) -> None:
        self._config = config
        self._pinger = pinger
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._idle = threading.Event()          # set whenever no scan is running
        self._idle.set()
        self._scan_thread: Optional[threading.Thread] = None
        self._running = False
        self._progress: Optional[Dict[str, Any]] = None
        self._last_run_ts: Optional[float] = None

    # -- state for Engine / diagnostics ----------------------------------------
    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    @property
    def progress(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._progress) if self._progress else None

    @property
    def last_run_ts(self) -> Optional[float]:
        with self._lock:
            return self._last_run_ts

    def stop(self, timeout: float = 5.0) -> bool:
        """Abort the running scan (if any) and wait up to *timeout* s for it to end.

        Returns True when no scan is running on return. Safe to call repeatedly;
        scans started later are not affected. Called from the scan thread itself
        (e.g. inside a progress callback) it only flags the cancel and returns False.
        """
        with self._lock:
            self._stop.set()
            running = self._running
            scan_thread = self._scan_thread
        if not running:
            return True
        if scan_thread is threading.current_thread():
            return False
        return self._idle.wait(max(0.0, float(timeout)))

    # -- config access ---------------------------------------------------------
    def _cfg(self, key: str, default: Any) -> Any:
        try:
            v = self._config.get(f"discovery.{key}", default)
        except Exception:  # noqa: BLE001
            return default
        return default if v is None else v

    def _max_hosts(self) -> int:
        try:
            return max(1, int(self._cfg("max_hosts", 4096)))
        except (TypeError, ValueError):
            return 4096

    def _clean_ports(self, ports: Optional[Iterable[Any]]) -> List[int]:
        src: Any = self._cfg("ports", []) if ports is None else ports
        if isinstance(src, bytes):
            src = src.decode("ascii", "replace")
        if isinstance(src, str):
            src = [p for p in re.split(r"[,;\s]+", src) if p]
        elif isinstance(src, (int, float)):
            src = [src]
        out: List[int] = []
        try:
            for p in src or []:
                if isinstance(p, bool):
                    continue
                try:
                    pi = int(p)
                except (TypeError, ValueError):
                    continue
                if 1 <= pi <= 65535 and pi not in out:
                    out.append(pi)
        except TypeError:
            return []
        if len(out) > MAX_PORTS:
            log.warning("discovery port list truncated from %d to %d entries", len(out), MAX_PORTS)
            out = out[:MAX_PORTS]
        return out

    # -- range handling --------------------------------------------------------
    def default_cidr(self) -> Optional[str]:
        """Internet-facing NIC's IPv4 network; a /24 around the IP when the prefix is < 22.

        Fallbacks (module notes): another up adapter's network, the route guess, then ``None``
        when this PC is on no IPv4 network at all.
        """
        addr: Optional[str] = None
        prefix: Optional[int] = None
        try:
            found = _internet_ipv4()
            if found:
                addr, prefix = found
        except Exception as exc:  # noqa: BLE001 - netinfo missing or failing
            log.debug("netinfo unavailable for default_cidr: %s", exc)
        if addr is None or (prefix is not None and int(prefix) >= 31):
            try:
                other = _first_up_ipv4()
            except Exception as exc:  # noqa: BLE001
                log.debug("adapter list unavailable for default_cidr: %s", exc)
                other = None
            if other:
                addr, prefix = other
        if addr is None:
            try:
                addr = _local_ipv4_guess()
            except Exception:  # noqa: BLE001
                addr = None
            prefix = 24
        if addr is None:
            return None
        try:
            p = int(prefix) if prefix is not None else 24
            if p < 22 or p > 32:
                p = 24
            return str(ipaddress.ip_network(f"{addr}/{p}", strict=False))
        except ValueError:
            return None

    @staticmethod
    def _host_count(net: ipaddress.IPv4Network) -> int:
        return net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses

    def _oversize(self, what: str, count: int, prefix_hint: Optional[int] = None) -> ValueError:
        max_hosts = self._max_hosts()
        msg = f"{what} contains {count} addresses; the maximum is {max_hosts} (setting discovery.max_hosts)"
        if prefix_hint is not None:
            for p in range(max(prefix_hint, 0), 33):
                n = 2 ** (32 - p)
                if (n - 2 if p < 31 else n) <= max_hosts:
                    msg += f" - try a /{p} or smaller"
                    break
        return ValueError(msg)

    @staticmethod
    def _parse_ipv4(part: str, raw: str) -> ipaddress.IPv4Address:
        if ":" in part:
            raise ValueError(f"{_short(raw)!r}: IPv6 is not supported; enter an IPv4 range, {_RANGE_HELP}")
        try:
            return ipaddress.IPv4Address(part)
        except ValueError:
            raise ValueError(f"{_short(part)!r} is not a valid IPv4 address; {_RANGE_HELP}") from None

    def parse_range(self, text: str) -> RangeType:
        """Parse ``10.0.0.0/24`` | ``10.0.0.1-10.0.0.20`` | ``10.0.0.1-20`` | ``10.0.0.5``.

        Returns an ``IPv4Network`` for CIDR text, otherwise a list of addresses.
        Raises ``ValueError`` with a helpful message for garbage or oversize ranges.
        """
        raw = text if isinstance(text, str) else ""
        s = "".join(raw.split())
        if not s:
            raise ValueError(f"Enter a range to scan, {_RANGE_HELP}")
        max_hosts = self._max_hosts()
        if "/" in s:
            if ":" in s:
                raise ValueError(f"{_short(raw)!r}: IPv6 is not supported; enter an IPv4 range, {_RANGE_HELP}")
            try:
                net = ipaddress.ip_network(s, strict=False)
            except ValueError:
                raise ValueError(f"{_short(raw)!r} is not a valid CIDR network; {_RANGE_HELP}") from None
            if not isinstance(net, ipaddress.IPv4Network):
                raise ValueError(f"{_short(raw)!r}: IPv6 is not supported; enter an IPv4 range, {_RANGE_HELP}")
            count = self._host_count(net)
            if count > max_hosts:
                raise self._oversize(str(net), count, net.prefixlen)
            return net
        if "-" in s:
            if s.count("-") != 1:
                raise ValueError(f"{_short(raw)!r} is not a valid range; {_RANGE_HELP}")
            a, b = s.split("-", 1)
            start = self._parse_ipv4(a, raw)
            if "." in b or ":" in b:
                end = self._parse_ipv4(b, raw)
            else:
                # len check first: int() of thousands of digits raises Python's own
                # "Exceeds the limit (4300 digits)" ValueError, which is not a range message
                if not b.isdigit() or not b.isascii() or len(b) > 3 or int(b) > 255:
                    raise ValueError(
                        f"{_short(raw)!r}: the part after '-' must be a last octet (0-255) or a full IPv4 address; {_RANGE_HELP}")
                octets = str(start).split(".")
                octets[3] = str(int(b))
                end = ipaddress.IPv4Address(".".join(octets))
            if end < start:
                raise ValueError(f"{_short(raw)!r}: the range end {end} is before its start {start}")
            count = int(end) - int(start) + 1
            if count > max_hosts:
                raise self._oversize(f"{start}-{end}", count)
            return [ipaddress.IPv4Address(i) for i in range(int(start), int(end) + 1)]
        return [self._parse_ipv4(s, raw)]

    @staticmethod
    def _expand(target: RangeType) -> List[str]:
        if isinstance(target, ipaddress.IPv4Network):
            if target.prefixlen < 31:
                first, last = int(target.network_address) + 1, int(target.broadcast_address) - 1
            else:
                first, last = int(target.network_address), int(target.broadcast_address)
            return [str(ipaddress.IPv4Address(i)) for i in range(first, last + 1)]
        return [str(a) for a in target]

    @staticmethod
    def _label(target: RangeType) -> str:
        if isinstance(target, ipaddress.IPv4Network):
            return str(target)
        if not target:
            return ""
        return str(target[0]) if len(target) == 1 else f"{target[0]}-{target[-1]}"

    # -- native ----------------------------------------------------------------
    def _get_pinger(self) -> Tuple[Any, bool]:
        """(pinger, owned) - *owned* means we created it and must close it.

        A real ``tnt.icmp.IcmpPinger`` keeps one ICMP handle per *thread* and can
        only release them all at once in ``close()``. Sweeping through a shared
        (injected) instance from the short-lived pool threads would therefore leak
        ``concurrency`` handles into it on every scan for the life of the service.
        Real pingers are never shared: a private one is created per scan and closed
        once the pool is quiet. Any other injected object (a test double) is used
        as-is and never closed.
        """
        injected = self._pinger
        try:
            icmp = importlib.import_module("tnt.icmp")
            cls = icmp.IcmpPinger
        except Exception:  # noqa: BLE001
            if injected is not None:
                return injected, False
            log.exception("ICMP pinger unavailable; discovery falls back to TCP-port probing only")
            return _NullPinger(), False
        if injected is not None and not (isinstance(cls, type) and isinstance(injected, cls)):
            return injected, False
        try:
            return cls(), True
        except Exception:  # noqa: BLE001
            if injected is not None:
                log.exception("could not create a private IcmpPinger; sweeping through the shared one")
                return injected, False
            log.exception("ICMP pinger unavailable; discovery falls back to TCP-port probing only")
            return _NullPinger(), False

    def _cancelled(self, cancel: Optional[threading.Event]) -> bool:
        return self._stop.is_set() or (cancel is not None and cancel.is_set())

    @staticmethod
    def _drain(futures: Set[Future], timeout_s: float) -> bool:
        """Cancel pending futures and wait (bounded) for the running ones to finish.

        Returns True when nothing is left running in the pool. Needed because closing
        an ``IcmpPinger`` while a pool thread is still inside ``IcmpSendEcho2`` on one
        of its handles is a use-after-free that ctypes cannot catch.
        """
        if not futures:
            return True
        for f in futures:
            f.cancel()
        not_done = wait(futures, timeout=max(0.0, timeout_s)).not_done
        if not_done:
            log.warning("discovery cancel: %d probe task(s) still running after %.1f s", len(not_done), timeout_s)
            return False
        return True

    def _run_tasks(self, executor: ThreadPoolExecutor, window: int, items: Iterable[Any],
                   fn: Callable[[Any], Any], on_result: Callable[[Any], None],
                   reporter: _ProgressReporter, cancel: Optional[threading.Event],
                   drain_s: float = DRAIN_CAP_S) -> None:
        """Feed *items* through *executor* keeping at most *window* futures in flight.

        Checks cancellation every ~0.2 s, throttles progress, never lets one bad task
        abort the phase. Raises :class:`ScanCancelled` (after draining the in-flight
        tasks for up to *drain_s* seconds).
        """
        it = iter(items)
        in_flight: Set[Future] = set()
        exhausted = False
        while True:
            if self._cancelled(cancel):
                raise ScanCancelled(drained=self._drain(in_flight, drain_s))
            while not exhausted and len(in_flight) < window:
                try:
                    item = next(it)
                except StopIteration:
                    exhausted = True
                    break
                in_flight.add(executor.submit(fn, item))
            if not in_flight:
                break
            done, in_flight = wait(in_flight, timeout=0.2, return_when=FIRST_COMPLETED)
            for f in done:
                reporter.advance()
                try:
                    res = f.result()
                except Exception:  # noqa: BLE001
                    log.exception("discovery task failed")
                    continue
                try:
                    on_result(res)
                except Exception:  # noqa: BLE001
                    log.exception("discovery result handler failed")
            reporter.tick()

    def _scan_native(self, addrs: List[str], ports: List[int], state: _ScanState,
                     reporter: _ProgressReporter, cancel: Optional[threading.Event]) -> None:
        try:
            concurrency = max(1, min(512, int(self._cfg("concurrency", 128))))
        except (TypeError, ValueError):
            concurrency = 128
        try:
            attempts = max(1, min(5, int(self._cfg("ping_attempts", 2))))
        except (TypeError, ValueError):
            attempts = 2
        try:
            ping_timeout_ms = max(50, int(self._cfg("ping_timeout_ms", 500)))
        except (TypeError, ValueError):
            ping_timeout_ms = 500
        try:
            port_timeout_s = max(0.05, float(self._cfg("port_timeout_ms", 750)) / 1000.0)
        except (TypeError, ValueError):
            port_timeout_s = 0.75
        window = concurrency * 2
        # a probe task can outlive a cancel by at most its own timeout; wait that long
        # (plus slack, capped) for the pool to go quiet before touching shared handles
        drain_s = min(DRAIN_CAP_S, max(ping_timeout_ms / 1000.0, port_timeout_s) + 1.0)

        pinger, owned = self._get_pinger()
        executor = ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="tnt-discovery")
        completed = False
        drained = False
        try:
            # (1) ping sweep: `attempts` passes, later passes only for non-responders
            reporter.set_phase("ping", len(addrs) * attempts)
            remaining = list(addrs)

            def ping_one(ip: str) -> Tuple[str, bool, Optional[float]]:
                try:
                    r = pinger.ping(ip, size=SWEEP_PAYLOAD_BYTES, timeout_ms=ping_timeout_ms, ttl=SWEEP_TTL)
                except Exception as exc:  # noqa: BLE001
                    log.debug("ping %s failed: %s", ip, exc)
                    return ip, False, None
                ok = bool(getattr(r, "ok", False))
                rtt = getattr(r, "rtt_ms", None) if ok else None
                return ip, ok, (float(rtt) if rtt is not None else None)

            def on_ping(res: Tuple[str, bool, Optional[float]]) -> None:
                ip, ok, rtt = res
                state.pinged.add(ip)
                if ok:
                    state.responders[ip] = rtt

            for attempt in range(attempts):
                if not remaining:
                    break
                if attempt:
                    reporter.total = reporter.done + len(remaining) * (attempts - attempt)
                self._run_tasks(executor, window, remaining, ping_one, on_ping, reporter, cancel, drain_s)
                remaining = [ip for ip in remaining if ip not in state.responders]
            reporter.done = reporter.total
            reporter.emit(force=True)

            # (2) TCP connect probes against every address for every port (lazy: a
            # /16 x 1024 ports would otherwise materialise 67M tuples up front)
            n_tasks = len(addrs) * len(ports)
            tasks = ((ip, p) for ip in addrs for p in ports)
            reporter.set_phase("ports", n_tasks)

            def port_one(task: Tuple[str, int]) -> Tuple[str, int, bool]:
                ip, port = task
                try:
                    return ip, port, bool(_tcp_connect(ip, port, port_timeout_s))
                except Exception as exc:  # noqa: BLE001
                    log.debug("tcp %s:%s failed: %s", ip, port, exc)
                    return ip, port, False

            def on_port(res: Tuple[str, int, bool]) -> None:
                ip, port, is_open = res
                if is_open:
                    state.open_ports.setdefault(ip, []).append(port)

            if n_tasks:
                self._run_tasks(executor, window, tasks, port_one, on_port, reporter, cancel, drain_s)
            reporter.done = reporter.total
            reporter.emit(force=True)
            completed = True
        except ScanCancelled as exc:
            drained = exc.drained
            raise
        finally:
            quiet = completed or drained
            try:
                # quiet: every task finished -> join the (idle) threads immediately;
                # otherwise leave the stragglers to exit on their own (never block here)
                executor.shutdown(wait=quiet, cancel_futures=True)
            except Exception:  # noqa: BLE001
                log.exception("executor shutdown failed")
            if owned:
                if quiet:
                    self._close_pinger(pinger)
                else:
                    # Never close under a live IcmpSendEcho2 call: hand the handles to a
                    # daemon thread that closes them once the last straggler has exited.
                    log.warning("discovery: probe tasks still running after cancel; ICMP handles "
                                "will be released once they finish")
                    threading.Thread(target=self._close_when_quiet, args=(executor, pinger),
                                     name="tnt-discovery-closer", daemon=True).start()

    @staticmethod
    def _close_pinger(pinger: Any) -> None:
        try:
            pinger.close()
        except Exception:  # noqa: BLE001
            log.debug("pinger close failed", exc_info=True)

    @classmethod
    def _close_when_quiet(cls, executor: ThreadPoolExecutor, pinger: Any) -> None:
        try:
            executor.shutdown(wait=True)      # joins the pool threads (bounded by one probe timeout)
        except Exception:  # noqa: BLE001
            log.debug("executor shutdown failed", exc_info=True)
        cls._close_pinger(pinger)
        log.info("discovery: straggling probe tasks finished; ICMP handles released")

    # -- enrichment ------------------------------------------------------------
    def _enrich_arp(self, ips: List[str], state: _ScanState, reporter: _ProgressReporter) -> None:
        reporter.set_phase("arp", len(ips))
        table = _arp_table() if ips else {}
        norm: Dict[str, str] = {}
        for k, v in table.items():
            m = _usable_mac(_normalize_mac(v))
            if m:
                norm[k] = m
        vendor_fn = _vendor_lookup() if ips else None
        for ip in ips:
            if ip not in state.macs and ip in norm:
                state.macs[ip] = norm[ip]
            mac = state.macs.get(ip)
            if mac and ip not in state.vendors and vendor_fn is not None:
                try:
                    v = vendor_fn(mac)
                except Exception as exc:  # noqa: BLE001
                    log.debug("vendor lookup failed for %s: %s", mac, exc)
                    v = None
                if v:
                    state.vendors[ip] = str(v)
            reporter.advance()
            reporter.tick()
        reporter.emit(force=True)

    def _enrich_names(self, ips: List[str], state: _ScanState, reporter: _ProgressReporter,
                      cancel: Optional[threading.Event]) -> None:
        todo = [ip for ip in ips if ip not in state.names]
        reporter.set_phase("resolve", len(todo))
        if not todo:
            return
        n = len(todo)
        pending: List[str] = list(todo)
        lock = threading.Lock()
        results: Dict[str, str] = {}
        remaining = [n]
        done_evt = threading.Event()
        abandoned = threading.Event()

        def worker() -> None:
            while not abandoned.is_set():
                with lock:
                    if not pending:
                        return
                    ip = pending.pop()
                try:
                    name = _resolve_name(ip)
                except Exception:  # noqa: BLE001
                    name = None
                with lock:
                    if abandoned.is_set():
                        return
                    if name:
                        results[ip] = name
                    remaining[0] -= 1
                    if remaining[0] <= 0:
                        done_evt.set()

        for i in range(min(n, RESOLVE_WORKERS)):
            threading.Thread(target=worker, name=f"tnt-discovery-rdns-{i}", daemon=True).start()

        deadline = time.monotonic() + float(RESOLVE_DEADLINE_S)
        while not done_evt.is_set():
            if self._cancelled(cancel) or time.monotonic() >= deadline:
                break
            done_evt.wait(0.05)
            with lock:
                reporter.done = n - remaining[0]
            reporter.tick()
        with lock:
            abandoned.set()
            state.names.update(results)
            reporter.done = n - remaining[0]
        if not done_evt.is_set():
            log.info("reverse DNS capped at %.1f s: %d of %d lookups finished", RESOLVE_DEADLINE_S,
                     reporter.done, n)
        reporter.emit(force=True)

    # -- public entry point ----------------------------------------------------
    def scan(self, range_text: str, ports: Optional[List[int]] = None,
             progress: Optional[ProgressFn] = None,
             cancel: Optional[threading.Event] = None) -> DiscoveryResult:
        """Discover hosts in *range_text*. Never raises; see :class:`DiscoveryResult`."""
        t0 = time.monotonic()
        ts = time.time()
        state = _ScanState()
        label = (range_text or "").strip() if isinstance(range_text, str) else ""
        clean_ports: List[int] = []

        scan_gateways: List[Optional[Set[str]]] = [None]   # the routers of the network the scan started on

        def finish(*, ok: bool, error: Optional[str], cancelled: bool, scanned: int,
                   hosts: Optional[List[HostResult]] = None) -> DiscoveryResult:
            hosts = hosts if hosts is not None else []
            if hosts:
                # every exit (finished, cancelled, crashed) hands back categorised hosts, typed
                # with the gateways read when the scan started (never letting the scan fail)
                apply_device_types(hosts, scan_gateways[0])
            hosts.sort(key=lambda h: _ip_key(h.ip))
            return DiscoveryResult(
                ts=ts, cidr=label, ports=list(clean_ports), method="native", hosts=hosts,
                scanned=int(scanned), duration_s=round(time.monotonic() - t0, 3),
                ok=ok, error=error, cancelled=cancelled,
            )

        def sink(snap: Dict[str, Any]) -> None:
            with self._lock:
                self._progress = snap

        # Claim the scanner atomically: one scan at a time, and a stop() that lands
        # after this point is seen by this scan (it is only cleared under the lock).
        with self._lock:
            if self._running:
                log.warning("discovery scan refused: another scan is still running")
                return finish(ok=False, error="a discovery scan is already running", cancelled=False, scanned=0)
            self._running = True
            self._scan_thread = threading.current_thread()
            self._progress = None
            self._stop.clear()
            self._idle.clear()
        reporter = _ProgressReporter(progress, t0, state, sink)
        scan_gateways[0] = gateway_ips()

        try:
            try:
                clean_ports = self._clean_ports(ports)
            except Exception:  # noqa: BLE001
                log.exception("invalid ports for discovery; using none")
                clean_ports = []
            if range_text is not None and not isinstance(range_text, str):
                # a number / list from a sloppy API body must not silently become "scan my LAN"
                return finish(ok=False, error=f"the scan range must be text, {_RANGE_HELP}", cancelled=False,
                              scanned=0)
            if not label:
                # "both optional -> defaults" (API contract): no range means the local network
                try:
                    range_text = label = self.default_cidr() or ""
                except Exception:  # noqa: BLE001
                    log.exception("default_cidr failed")
            try:
                target = self.parse_range(range_text)
            except ValueError as exc:
                log.warning("discovery range rejected: %s", exc)
                return finish(ok=False, error=str(exc), cancelled=False, scanned=0)
            addrs = self._expand(target)
            label = self._label(target)
            if len(addrs) > self._max_hosts():
                return finish(ok=False, error=str(self._oversize(label, len(addrs))), cancelled=False, scanned=0)
            if not addrs:
                return finish(ok=False, error=f"{label!r} contains no scannable addresses", cancelled=False, scanned=0)
            log.info("discovery scan starting: %s (%d addresses, ports %s)", label, len(addrs), clean_ports)

            try:
                self._scan_native(addrs, clean_ports, state, reporter, cancel)
            except ScanCancelled:
                log.info("discovery cancelled after %d/%d addresses", len(state.pinged), len(addrs))
                return finish(ok=True, error=None, cancelled=True, scanned=len(state.pinged),
                              hosts=state.hosts())

            found = state.found_ips()
            try:
                self._enrich_arp(found, state, reporter)
            except Exception:  # noqa: BLE001
                log.exception("ARP/vendor enrichment failed; continuing without it")
            try:
                if bool(self._cfg("resolve_hostnames", True)):
                    self._enrich_names(found, state, reporter, cancel)
                else:
                    reporter.set_phase("resolve", 0)
            except Exception:  # noqa: BLE001
                log.exception("reverse DNS enrichment failed; continuing without it")
            hosts = state.hosts()
            reporter.finish()
            log.info("discovery scan finished: %s -> %d hosts in %.1f s", label, len(hosts),
                     time.monotonic() - t0)
            return finish(ok=True, error=None, cancelled=self._cancelled(cancel), scanned=len(addrs), hosts=hosts)
        except Exception as exc:  # noqa: BLE001 - scan must never raise
            log.exception("discovery scan failed")
            try:
                partial = state.hosts()
            except Exception:  # noqa: BLE001
                partial = []
            return finish(ok=False, error=f"{type(exc).__name__}: {exc}", cancelled=False,
                          scanned=len(state.pinged), hosts=partial)
        finally:
            with self._lock:
                self._running = False
                self._scan_thread = None
                self._last_run_ts = ts
                self._idle.set()
