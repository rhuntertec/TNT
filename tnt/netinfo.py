"""Network adapters, gateways and address classification.

Everything comes from ``GetAdaptersAddresses`` in ``iphlpapi.dll`` through ctypes
(``AF_UNSPEC`` with ``INCLUDE_PREFIX | INCLUDE_GATEWAYS | SKIP_ANYCAST | SKIP_MULTICAST``,
retrying on ``ERROR_BUFFER_OVERFLOW``). No admin rights are needed and no packets are sent:
:func:`get_internet_nic` only does a UDP ``connect()`` (a route lookup) to find the local
address the default route uses.

Public API (see the contract for the dict shapes):

* :class:`IpAddr`, :class:`Adapter` dataclasses; ``Adapter.to_dict()`` adds ``"subnets"``.
* :func:`get_adapters`, :func:`get_internet_nic`, :func:`get_default_gateway`,
  :func:`local_networks`, :func:`classify_ip`, :func:`subnet_groups`,
  :func:`netinfo_snapshot`.

Contract gaps filled here (documented as required):

* ``IpAddr`` carries three extra fields beyond the contract -- ``dad_state`` (raw
  ``IP_DAD_STATE``, 4 = preferred), ``preferred`` (``dad_state == 4``) and ``scope_id`` (IPv6
  zone, 0 for IPv4) -- so callers can pick the "primary" address without a second lookup.
  ``Adapter.primary_ipv4`` is the first *preferred* IPv4 address (falls back to the first
  IPv4 address of any DAD state); ``to_dict()`` includes it as ``"primary_ipv4"``.
  ``IpAddr.family`` is the IP version (4 / 6), matching ``subnet_groups()``'s ``"family"``.
* ``speed_bps`` is ``None`` when Windows reports the unknown sentinel
  (``0xFFFFFFFFFFFFFFFF``) *or* 0 (disconnected adapters report 0); ``mtu`` is ``None`` when
  it is 0 or ``0xFFFFFFFF``.
* IPv6 link-local gateways are returned as ``"fe80::1%12"`` (with the zone) because that is
  the form ``ping``/``ipaddress`` need; addresses keep the zone in ``scope_id`` instead.
* ``get_default_gateway()`` prefers the IPv4 gateway of the internet-facing NIC; if that NIC
  has no gateway (e.g. a VPN tunnel won the route lookup) it falls back to the lowest-metric
  "up" adapter that has one.
* ``classify_ip()`` accepts anything: an unparsable string (a hostname) is ``"internet"``
  except ``"localhost"``, which is ``"local"``; it never raises and never does DNS.
* Adapter enumeration is cached for one second (``_CACHE_TTL_S``) so an API burst
  (``/status`` + ``/netinfo`` + several ``classify_ip`` calls) costs one native call.
* Adapters whose ``IfIndex`` is 0 (IPv6-only bindings) use ``Ipv6IfIndex`` as ``index``.
* ``Adapter.ipv4`` lists *preferred* (DAD state 4) addresses first, in the order Windows
  reported them, so ``ipv4[0]`` is the usable address even when a tentative/duplicate one
  was enumerated earlier; ``primary_ipv4`` and ``ipv4[0]`` therefore always agree whenever
  a preferred address exists.
* The deprecated site-local placeholders ``fec0:0:0:ffff::1-3`` that Windows reports as DNS
  servers on unconfigured adapters are dropped from ``dns`` (``ipconfig`` hides them too).
* Identity and origin fields for :mod:`tnt.netwatch` (not part of ``to_dict()``, so the API
  shape is unchanged): ``Adapter.guid`` (``AdapterName``, e.g. ``"{4D36E972-...}"``) and
  ``Adapter.luid`` stay the same when a USB NIC is re-plugged into another port (``IfIndex``
  may not); ``IpAddr.prefix_origin`` / ``suffix_origin`` are the raw ``IP_PREFIX_ORIGIN`` /
  ``IP_SUFFIX_ORIGIN`` values, which tell a manual or DHCPv6 IPv6 address from the RFC 4941
  temporary ones Windows rotates.
* ``DadState`` values follow ``NL_DAD_STATE``: 1 tentative, 2 duplicate, 3 deprecated (every
  expired IPv6 temporary address), 4 preferred.
* ``get_default_gateway(adapters)`` and :func:`default_gateway_for` compute the gateway from
  one enumeration, so a caller that already holds the adapter list (``netinfo_snapshot``, the
  network watcher) never mixes two enumerations that straddle a change.
* :func:`adapter_warnings` flags what is visibly wrong with an adapter's live state (a
  self-assigned 169.254 address, a duplicate address, a gateway outside the subnet, no DNS
  servers, two default gateways); ``to_dict()`` carries them as ``"warnings"`` and
  ``netinfo_snapshot()`` adds the one that needs the other adapters.
"""
from __future__ import annotations

import ctypes
import ipaddress
import logging
import socket
import threading
import time
from ctypes import POINTER, Structure, c_int, c_ubyte, c_ulong, c_ulonglong, c_ushort, c_void_p
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

log = logging.getLogger(__name__)

__all__ = [
    "IpAddr", "Adapter", "get_adapters", "get_internet_nic", "get_default_gateway", "default_gateway_for",
    "local_networks", "classify_ip", "subnet_groups", "adapter_warnings", "netinfo_snapshot",
    "IF_TYPE_NAMES", "OPER_STATUS_NAMES",
]

AF_UNSPEC = 0
AF_INET = 2
AF_INET6 = 23

GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_INCLUDE_PREFIX = 0x0010
GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
GAA_FLAGS = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST

NO_ERROR = 0
ERROR_BUFFER_OVERFLOW = 111
ERROR_NO_DATA = 232
ERROR_ADDRESS_NOT_ASSOCIATED = 1228

IP_ADAPTER_DHCP_ENABLED = 0x0004          # Flags bit: Dhcpv4Enabled
IP_DAD_STATE_TENTATIVE = 1                # NL_DAD_STATE
IP_DAD_STATE_DUPLICATE = 2
IP_DAD_STATE_DEPRECATED = 3
IP_DAD_STATE_PREFERRED = 4
IP_SUFFIX_ORIGIN_MANUAL = 1               # IP_SUFFIX_ORIGIN: a fixed address somebody typed in ...
IP_SUFFIX_ORIGIN_DHCP = 3                 # ... or one a DHCP(v6) server assigned
SPEED_UNKNOWN = 0xFFFFFFFFFFFFFFFF
MTU_UNKNOWN = 0xFFFFFFFF
MAX_ADAPTER_ADDRESS_LENGTH = 8
MAX_DHCPV6_DUID_LENGTH = 130

#: Adapter types that are a tunnel rather than a link to a network: a VPN client, Tailscale,
#: WireGuard.  They are addressed as host routes with a gateway outside them and they take the
#: default route while connected, both of which are correct and neither of which is a warning.
TUNNEL_IF_TYPES: Tuple[int, ...] = (53, 131)

IF_TYPE_NAMES: Dict[int, str] = {
    1: "Other",
    6: "Ethernet",
    9: "Token Ring",
    15: "FDDI",
    23: "PPP",
    24: "Loopback",
    37: "ATM",
    53: "Tunnel",          # IF_TYPE_PROP_VIRTUAL: Tailscale/WireGuard/VPN adapters show up here
    71: "Wi-Fi",
    131: "Tunnel",
    144: "IEEE 1394",
    237: "WWAN",
    243: "WWAN",
    244: "WWAN",
}

OPER_STATUS_NAMES: Dict[int, str] = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "not_present",
    7: "lower_layer_down",
}

_VIRTUAL_MARKERS = ("virtual", "hyper-v", "vmware", "virtualbox", "loopback")
_CACHE_TTL_S = 1.0
# Windows lists these deprecated site-local addresses as DNS servers on every adapter that
# has none configured; ipconfig hides them and so do we.
_PLACEHOLDER_DNS = ipaddress.IPv6Network("fec0:0:0:ffff::/64")
_APIPA = ipaddress.IPv4Network("169.254.0.0/16")
#: Fields that exist for tnt.netwatch only and stay out of the API dicts.
_INTERNAL_ADAPTER_FIELDS = ("guid", "luid")
_INTERNAL_ADDR_FIELDS = ("prefix_origin", "suffix_origin")

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


# --- dataclasses ---------------------------------------------------------------------------
@dataclass
class IpAddr:
    address: str                     # "10.0.0.112" / "fe80::1234:5678:9abc:def0" (no zone)
    prefix: int                      # on-link prefix length, e.g. 24
    family: int                      # IP version: 4 or 6
    netmask: Optional[str]           # dotted mask for IPv4, None for IPv6
    network: str                     # "10.0.0.0/24"
    dad_state: int = IP_DAD_STATE_PREFERRED
    preferred: bool = True
    scope_id: int = 0
    prefix_origin: int = 0           # raw IP_PREFIX_ORIGIN (internal, not in to_dict)
    suffix_origin: int = 0           # raw IP_SUFFIX_ORIGIN (internal, not in to_dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for k in _INTERNAL_ADDR_FIELDS:
            d.pop(k, None)
        return d


@dataclass
class Adapter:
    index: int
    name: str
    description: str
    mac: str
    if_type: int
    type_name: str
    status: str                      # up | down | testing | unknown | dormant | not_present | lower_layer_down
    speed_bps: Optional[int]
    mtu: Optional[int]
    dhcp_enabled: bool
    dhcp_server: Optional[str]
    dns_suffix: str
    ipv4: List[IpAddr] = field(default_factory=list)
    ipv6: List[IpAddr] = field(default_factory=list)
    gateways: List[str] = field(default_factory=list)
    dns: List[str] = field(default_factory=list)
    metric_v4: int = 0
    is_physical: bool = False
    is_loopback: bool = False
    guid: str = ""                   # AdapterName (internal, not in to_dict)
    luid: int = 0                    # interface LUID (internal, not in to_dict)

    @property
    def is_up(self) -> bool:
        return self.status == "up"

    @property
    def primary_ipv4(self) -> Optional[str]:
        """First *preferred* IPv4 address, else the first IPv4 address, else ``None``."""
        for a in self.ipv4:
            if a.preferred:
                return a.address
        return self.ipv4[0].address if self.ipv4 else None

    @property
    def ipv4_gateway(self) -> Optional[str]:
        for gw in self.gateways:
            if _version(gw) == 4:
                return gw
        return None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for k in _INTERNAL_ADAPTER_FIELDS:
            d.pop(k, None)
        for family in ("ipv4", "ipv6"):
            for entry in d.get(family) or []:
                for k in _INTERNAL_ADDR_FIELDS:
                    entry.pop(k, None)
        d["primary_ipv4"] = self.primary_ipv4
        d["subnets"] = subnet_groups(self)
        d["warnings"] = adapter_warnings(self)
        return d


# --- native structures (x64 layouts; sizes checked in tests) --------------------------------
class SOCKET_ADDRESS(Structure):
    _fields_ = [
        ("lpSockaddr", c_void_p),
        ("iSockaddrLength", c_int),
    ]


class IP_ADAPTER_ADDRESS_NODE(Structure):
    """Common prefix of the *_ADDRESS list nodes (unicast, dns, wins, gateway, prefix)."""
    _fields_ = [
        ("Length", c_ulong),
        ("Flags", c_ulong),
        ("Next", c_void_p),
        ("Address", SOCKET_ADDRESS),
    ]


class IP_ADAPTER_UNICAST_ADDRESS(Structure):
    _fields_ = [
        ("Length", c_ulong),
        ("Flags", c_ulong),
        ("Next", c_void_p),
        ("Address", SOCKET_ADDRESS),
        ("PrefixOrigin", c_int),
        ("SuffixOrigin", c_int),
        ("DadState", c_int),
        ("ValidLifetime", c_ulong),
        ("PreferredLifetime", c_ulong),
        ("LeaseLifetime", c_ulong),
        ("OnLinkPrefixLength", c_ubyte),
    ]


class GUID(Structure):
    _fields_ = [
        ("Data1", c_ulong),
        ("Data2", c_ushort),
        ("Data3", c_ushort),
        ("Data4", c_ubyte * 8),
    ]


class IP_ADAPTER_ADDRESSES(Structure):
    """``IP_ADAPTER_ADDRESSES_LH`` (Vista+), 448 bytes on x64."""
    _fields_ = [
        ("Length", c_ulong),
        ("IfIndex", c_ulong),
        ("Next", c_void_p),
        ("AdapterName", c_void_p),                 # PCHAR (GUID string)
        ("FirstUnicastAddress", c_void_p),
        ("FirstAnycastAddress", c_void_p),
        ("FirstMulticastAddress", c_void_p),
        ("FirstDnsServerAddress", c_void_p),
        ("DnsSuffix", c_void_p),                   # PWCHAR
        ("Description", c_void_p),                 # PWCHAR
        ("FriendlyName", c_void_p),                # PWCHAR
        ("PhysicalAddress", c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
        ("PhysicalAddressLength", c_ulong),
        ("Flags", c_ulong),
        ("Mtu", c_ulong),
        ("IfType", c_ulong),
        ("OperStatus", c_int),
        ("Ipv6IfIndex", c_ulong),
        ("ZoneIndices", c_ulong * 16),
        ("FirstPrefix", c_void_p),
        ("TransmitLinkSpeed", c_ulonglong),
        ("ReceiveLinkSpeed", c_ulonglong),
        ("FirstWinsServerAddress", c_void_p),
        ("FirstGatewayAddress", c_void_p),
        ("Ipv4Metric", c_ulong),
        ("Ipv6Metric", c_ulong),
        ("Luid", c_ulonglong),
        ("Dhcpv4Server", SOCKET_ADDRESS),
        ("CompartmentId", c_ulong),
        ("NetworkGuid", GUID),
        ("ConnectionType", c_int),
        ("TunnelType", c_int),
        ("Dhcpv6Server", SOCKET_ADDRESS),
        ("Dhcpv6ClientDuid", c_ubyte * MAX_DHCPV6_DUID_LENGTH),
        ("Dhcpv6ClientDuidLength", c_ulong),
        ("Dhcpv6Iaid", c_ulong),
        ("FirstDnsSuffix", c_void_p),
    ]


_dll_lock = threading.Lock()
_iphlpapi: Any = None


def _dll() -> Any:
    """Load ``iphlpapi`` once with the prototype declared (64-bit safe)."""
    global _iphlpapi
    with _dll_lock:
        if _iphlpapi is None:
            dll = ctypes.WinDLL("iphlpapi", use_last_error=True)
            dll.GetAdaptersAddresses.argtypes = [c_ulong, c_ulong, c_void_p, c_void_p, POINTER(c_ulong)]
            dll.GetAdaptersAddresses.restype = c_ulong
            _iphlpapi = dll
        return _iphlpapi


# --- low-level helpers ---------------------------------------------------------------------
def _wstr(ptr: Optional[int]) -> str:
    if not ptr:
        return ""
    try:
        return ctypes.wstring_at(ptr)
    except Exception:  # noqa: BLE001
        return ""


def _sockaddr(ptr: Optional[int], length: int) -> Optional[Tuple[str, int, int]]:
    """``(address, version, scope_id)`` for a ``sockaddr`` pointer, or ``None``."""
    if not ptr or length < 2:
        return None
    family = c_ushort.from_address(ptr).value
    if family == AF_INET and length >= 8:
        raw = ctypes.string_at(ptr + 4, 4)
        return str(ipaddress.IPv4Address(raw)), 4, 0
    if family == AF_INET6 and length >= 24:
        raw = ctypes.string_at(ptr + 8, 16)
        scope = c_ulong.from_address(ptr + 24).value if length >= 28 else 0
        return str(ipaddress.IPv6Address(raw)), 6, int(scope)
    return None


def _walk(first: Optional[int], node_type: type = IP_ADAPTER_ADDRESS_NODE, limit: int = 1024):
    """Yield structures of *node_type* following ``Next`` pointers (bounded, cycle-safe)."""
    ptr = first
    seen = 0
    while ptr and seen < limit:
        node = node_type.from_address(ptr)
        yield node
        nxt = node.Next
        if nxt == ptr:
            break
        ptr = nxt
        seen += 1


def _version(ip: str) -> Optional[int]:
    try:
        return ipaddress.ip_address(ip.split("%", 1)[0]).version
    except ValueError:
        return None


def _make_ipaddr(address: str, version: int, prefix: int, dad_state: int, scope_id: int,
                 prefix_origin: int = 0, suffix_origin: int = 0) -> IpAddr:
    max_prefix = 32 if version == 4 else 128
    prefix = max(0, min(max_prefix, int(prefix)))
    try:
        net = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        network = str(net)
        netmask = str(net.netmask) if version == 4 else None
    except ValueError:
        network = f"{address}/{prefix}"
        netmask = None
    return IpAddr(
        address=address,
        prefix=prefix,
        family=version,
        netmask=netmask,
        network=network,
        dad_state=int(dad_state),
        preferred=int(dad_state) == IP_DAD_STATE_PREFERRED,
        scope_id=int(scope_id),
        prefix_origin=int(prefix_origin),
        suffix_origin=int(suffix_origin),
    )


def _preferred_first(entries: List[IpAddr]) -> List[IpAddr]:
    """Stable reorder: preferred (DAD state 4) addresses first, Windows' order otherwise."""
    return sorted(entries, key=lambda e: 0 if e.preferred else 1)


def _is_physical(if_type: int, description: str) -> bool:
    if if_type not in (6, 71):
        return False
    text = (description or "").lower()
    return not any(marker in text for marker in _VIRTUAL_MARKERS)


def _parse_adapter(a: IP_ADAPTER_ADDRESSES) -> Adapter:
    description = _wstr(a.Description)
    name = _wstr(a.FriendlyName) or description
    mac_len = int(a.PhysicalAddressLength)
    mac = ""
    if 0 < mac_len <= MAX_ADAPTER_ADDRESS_LENGTH:
        mac = ":".join(f"{b:02X}" for b in bytes(a.PhysicalAddress[:mac_len]))
    if_type = int(a.IfType)
    index = int(a.IfIndex) or int(a.Ipv6IfIndex)

    ipv4: List[IpAddr] = []
    ipv6: List[IpAddr] = []
    for u in _walk(a.FirstUnicastAddress, IP_ADAPTER_UNICAST_ADDRESS):
        sa = _sockaddr(u.Address.lpSockaddr, int(u.Address.iSockaddrLength))
        if sa is None:
            continue
        address, version, scope = sa
        entry = _make_ipaddr(address, version, int(u.OnLinkPrefixLength), int(u.DadState), scope,
                             int(u.PrefixOrigin), int(u.SuffixOrigin))
        (ipv4 if version == 4 else ipv6).append(entry)
    ipv4 = _preferred_first(ipv4)

    gateways: List[str] = []
    for g in _walk(a.FirstGatewayAddress):
        sa = _sockaddr(g.Address.lpSockaddr, int(g.Address.iSockaddrLength))
        if sa is None:
            continue
        address, version, scope = sa
        if address in ("0.0.0.0", "::"):
            continue                       # some tunnel drivers report an unspecified gateway
        if version == 6 and scope and address.lower().startswith("fe80:"):
            address = f"{address}%{scope}"
        if address not in gateways:
            gateways.append(address)

    dns: List[str] = []
    for d in _walk(a.FirstDnsServerAddress):
        sa = _sockaddr(d.Address.lpSockaddr, int(d.Address.iSockaddrLength))
        if sa is None:
            continue
        address, version, scope = sa
        if version == 6 and ipaddress.IPv6Address(address) in _PLACEHOLDER_DNS:
            continue
        if version == 6 and scope and address.lower().startswith("fe80:"):
            address = f"{address}%{scope}"
        if address not in dns:
            dns.append(address)

    dhcp_server: Optional[str] = None
    if a.Dhcpv4Server.lpSockaddr and a.Dhcpv4Server.iSockaddrLength > 0:
        sa = _sockaddr(a.Dhcpv4Server.lpSockaddr, int(a.Dhcpv4Server.iSockaddrLength))
        if sa is not None and sa[0] != "0.0.0.0":
            dhcp_server = sa[0]

    speed = int(a.TransmitLinkSpeed)
    mtu = int(a.Mtu)
    guid = ""
    if a.AdapterName:
        try:
            guid = ctypes.string_at(a.AdapterName).decode("ascii", "replace").strip()
        except Exception:  # noqa: BLE001
            guid = ""
    return Adapter(
        index=index,
        name=name,
        description=description,
        mac=mac,
        if_type=if_type,
        type_name=IF_TYPE_NAMES.get(if_type, f"Other ({if_type})"),
        status=OPER_STATUS_NAMES.get(int(a.OperStatus), "unknown"),
        speed_bps=None if speed in (0, SPEED_UNKNOWN) else speed,
        mtu=None if mtu in (0, MTU_UNKNOWN) else mtu,
        dhcp_enabled=bool(int(a.Flags) & IP_ADAPTER_DHCP_ENABLED),
        dhcp_server=dhcp_server,
        dns_suffix=_wstr(a.DnsSuffix),
        ipv4=ipv4,
        ipv6=ipv6,
        gateways=gateways,
        dns=dns,
        metric_v4=int(a.Ipv4Metric),
        is_physical=_is_physical(if_type, description),
        is_loopback=if_type == 24,
        guid=guid,
        luid=int(a.Luid),
    )


def _query_adapters() -> List[Adapter]:
    """One ``GetAdaptersAddresses`` call (with buffer-overflow retries). Raises on failure."""
    dll = _dll()
    size = c_ulong(16 * 1024)
    rc = ERROR_BUFFER_OVERFLOW
    buf = None
    for _attempt in range(6):
        buf = ctypes.create_string_buffer(int(size.value))
        rc = dll.GetAdaptersAddresses(AF_UNSPEC, GAA_FLAGS, None, buf, ctypes.byref(size))
        if rc != ERROR_BUFFER_OVERFLOW:
            break
    if rc in (ERROR_NO_DATA, ERROR_ADDRESS_NOT_ASSOCIATED):
        return []
    if rc != NO_ERROR or buf is None:
        raise OSError(rc, f"GetAdaptersAddresses failed: {ctypes.FormatError(int(rc)).strip()} ({rc})")
    adapters: List[Adapter] = []
    for node in _walk(ctypes.addressof(buf), IP_ADAPTER_ADDRESSES):
        try:
            adapters.append(_parse_adapter(node))
        except Exception:  # noqa: BLE001 - one odd adapter must not hide the others
            log.exception("failed to parse an adapter entry")
    return adapters


_cache_lock = threading.Lock()
_cache: Tuple[float, List[Adapter]] = (0.0, [])


def _all_adapters() -> List[Adapter]:
    """Every adapter (cached for ``_CACHE_TTL_S``). Never raises: ``[]`` on failure."""
    global _cache
    now = time.monotonic()
    with _cache_lock:
        ts, cached = _cache
        if cached and now - ts < _CACHE_TTL_S:
            return list(cached)
    try:
        adapters = _query_adapters()
    except Exception:  # noqa: BLE001 - contract: never raise
        log.exception("GetAdaptersAddresses failed")
        return []
    with _cache_lock:
        _cache = (time.monotonic(), list(adapters))
    return adapters


def _invalidate_cache() -> None:
    global _cache
    with _cache_lock:
        _cache = (0.0, [])


# --- public API ----------------------------------------------------------------------------
def get_adapters(include_down: bool = True, include_loopback: bool = False) -> List[Adapter]:
    """Adapters from ``GetAdaptersAddresses``. Never raises (``[]`` on failure)."""
    out: List[Adapter] = []
    for a in _all_adapters():
        if not include_loopback and a.is_loopback:
            continue
        if not include_down and not a.is_up:
            continue
        out.append(a)
    return out


def _route_source_ip(probe: Tuple[str, int] = ("1.1.1.1", 53)) -> Optional[str]:
    """Local IPv4 the default route would use (UDP ``connect`` sends nothing)."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect(probe)
        ip = s.getsockname()[0]
    except OSError as exc:
        log.debug("route probe failed: %s", exc)
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
    if not ip or ip == "0.0.0.0" or ip.startswith("127."):
        return None
    return ip


def get_internet_nic(adapters: Optional[Sequence[Adapter]] = None) -> Optional[Adapter]:
    """Adapter carrying the default route: UDP-connect local IP → adapter; else the "up"
    adapter that has a gateway and the lowest ``metric_v4``. ``None`` if nothing qualifies."""
    try:
        pool = list(adapters) if adapters is not None else get_adapters(include_down=True, include_loopback=False)
        ip = _route_source_ip()
        if ip:
            for a in pool:
                if any(x.address == ip for x in a.ipv4):
                    return a
        candidates = [a for a in pool if a.is_up and a.gateways and not a.is_loopback]
        if not candidates:
            return None
        candidates.sort(key=lambda a: (0 if a.ipv4_gateway else 1, a.metric_v4, 0 if a.is_physical else 1, a.index))
        return candidates[0]
    except Exception:  # noqa: BLE001
        log.exception("get_internet_nic failed")
        return None


def default_gateway_for(adapters: Sequence[Adapter], nic: Optional[Adapter]) -> Optional[str]:
    """The default gateway given an adapter list and its internet NIC (no native call).

    The NIC's IPv4 gateway, else its first (IPv6) gateway, else the lowest-metric up adapter
    that has an IPv4 gateway (a VPN tunnel that won the route lookup usually has none)."""
    if nic is not None:
        gw = nic.ipv4_gateway or (nic.gateways[0] if nic.gateways else None)
        if gw:
            return gw
    fallback = [a for a in adapters if a.is_up and not a.is_loopback and a.ipv4_gateway]
    fallback.sort(key=lambda a: (a.metric_v4, a.index))
    return fallback[0].ipv4_gateway if fallback else None


def get_default_gateway(adapters: Optional[Sequence[Adapter]] = None) -> Optional[str]:
    """IPv4 (preferably) gateway of :func:`get_internet_nic`; ``None`` if unknown.

    *adapters* reuses an enumeration the caller already holds (one consistent view)."""
    try:
        pool = list(adapters) if adapters is not None else get_adapters(include_down=True, include_loopback=False)
        return default_gateway_for(pool, get_internet_nic(pool))
    except Exception:  # noqa: BLE001
        log.exception("get_default_gateway failed")
        return None


def local_networks(adapters: Optional[Sequence[Adapter]] = None) -> List[IPNetwork]:
    """Networks of every adapter address, excluding link-local and loopback (de-duplicated)."""
    pool = list(adapters) if adapters is not None else get_adapters(include_down=True, include_loopback=False)
    out: List[IPNetwork] = []
    seen: set = set()
    for a in pool:
        if a.is_loopback:
            continue
        for entry in list(a.ipv4) + list(a.ipv6):
            try:
                net = ipaddress.ip_network(entry.network, strict=False)
            except ValueError:
                continue
            if net.is_link_local or net.is_loopback or net.network_address.is_link_local:
                continue
            if net.network_address.is_unspecified:
                continue
            key = str(net)
            if key in seen:
                continue
            seen.add(key)
            out.append(net)
    return out


_IPV4_LOCAL_RANGES = (
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / APIPA
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),        # "this network"
)
_IPV6_ULA = ipaddress.ip_network("fc00::/7")


def classify_ip(ip: str, adapters: Optional[Sequence[Adapter]] = None) -> str:
    """``"local"`` for private / link-local / loopback addresses or anything inside a local
    network, else ``"internet"``. Never raises."""
    text = str(ip or "").strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        addr = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return "local" if text.lower() in ("localhost", "localhost.") else "internet"
    if isinstance(addr, ipaddress.IPv6Address):
        v4 = addr.ipv4_mapped
        if v4 is not None:
            return classify_ip(str(v4), adapters)
        if addr.is_loopback or addr.is_link_local or addr.is_site_local or addr in _IPV6_ULA:
            return "local"
    else:
        # Deliberately NOT ipaddress.is_private: that also covers the documentation /
        # benchmark / reserved ranges (192.0.2.0/24, 198.18.0.0/15, 240.0.0.0/4, ...),
        # which are never on the LAN and must count as "internet" for total-outage logic.
        if any(addr in net for net in _IPV4_LOCAL_RANGES):
            return "local"
    try:
        for net in local_networks(adapters):
            if addr.version == net.version and addr in net:
                return "local"
    except Exception:  # noqa: BLE001
        log.exception("classify_ip(%s) could not read local networks", text)
    return "internet"


def subnet_groups(adapter: Adapter) -> List[Dict[str, Any]]:
    """Group the adapter's addresses by on-link network and attach the gateways they contain.

    ``[{"network": "10.0.0.0/24", "family": 4, "mask": "255.255.255.0",
       "addresses": ["10.0.0.112"], "gateways": ["10.0.0.251"]}]`` -- IPv4 groups first, then
    IPv6; gateways that fit no subnet end up in a trailing group with ``network=None``.
    """
    groups: List[Dict[str, Any]] = []
    by_network: Dict[str, Dict[str, Any]] = {}
    for entry in list(adapter.ipv4) + list(adapter.ipv6):
        g = by_network.get(entry.network)
        if g is None:
            g = {
                "network": entry.network,
                "family": entry.family,
                "mask": entry.netmask,
                "addresses": [],
                "gateways": [],
            }
            by_network[entry.network] = g
            groups.append(g)
        if entry.address not in g["addresses"]:
            g["addresses"].append(entry.address)

    leftovers: List[str] = []
    for gw in adapter.gateways:
        placed = False
        try:
            gw_addr = ipaddress.ip_address(gw.split("%", 1)[0])
        except ValueError:
            leftovers.append(gw)
            continue
        for g in groups:
            if g["family"] != gw_addr.version:
                continue
            try:
                net = ipaddress.ip_network(g["network"], strict=False)
            except ValueError:
                continue
            if gw_addr in net:
                if gw not in g["gateways"]:
                    g["gateways"].append(gw)
                placed = True
                break
        if not placed:
            leftovers.append(gw)

    groups.sort(key=lambda g: (g["family"], g["network"]))
    if leftovers:
        groups.append({
            "network": None,
            "family": _version(leftovers[0]) or 4,
            "mask": None,
            "addresses": [],
            "gateways": leftovers,
        })
    return groups


def _is_apipa(address: str) -> bool:
    try:
        return ipaddress.IPv4Address(address) in _APIPA
    except ValueError:
        return False


def _has_ipv6_route(adapter: Adapter) -> bool:
    """A preferred global (or unique-local) IPv6 address and an IPv6 gateway on *adapter*."""
    if not any(_version(g) == 6 for g in adapter.gateways):
        return False
    for x in adapter.ipv6:
        try:
            addr = ipaddress.IPv6Address(str(x.address).split("%", 1)[0])
        except ValueError:
            continue
        if x.preferred and not (addr.is_link_local or addr.is_loopback or addr.is_multicast or addr.is_unspecified):
            return True
    return False


def adapter_warnings(adapter: Adapter, adapters: Optional[Sequence[Adapter]] = None,
                     internet_index: Optional[int] = None) -> List[Dict[str, str]]:
    """Plain-language problems visible in an adapter's live state; ``[]`` when there are none.

    ``[{"code", "message"}]``, only for an adapter that is up:

    * ``apipa`` - every usable IPv4 address is self-assigned (169.254.x.x): no DHCP server answered.
      Only on a DHCP adapter without a duplicate IPv4 address: a static or duplicate address that
      Windows replaced with 169.254.x.x is the ``duplicate_address`` problem, not a DHCP one.  When
      the adapter has a global IPv6 address and an IPv6 gateway the message says that the network
      may be IPv6-only
    * ``duplicate_address`` - duplicate-address detection found another device on an address
    * ``gateway_outside_subnet`` - an IPv4 gateway lies in none of the adapter's IPv4 subnets
      (typical of a mistyped static address or mask; Windows accepts it)
    * ``no_dns`` - a usable IPv4 address and a gateway but no DNS server
    * ``multiple_default_gateways`` - informational, needs *adapters* and only on the internet
      NIC (*internet_index*): another up adapter has an IPv4 default gateway as well

    Pure (no native call); never raises.
    """
    out: List[Dict[str, str]] = []
    try:
        if not adapter.is_up or adapter.is_loopback:
            return out
        usable = [x for x in adapter.ipv4 if x.preferred]
        duplicate_v4 = any(int(x.dad_state) == IP_DAD_STATE_DUPLICATE for x in adapter.ipv4)
        if usable and all(_is_apipa(x.address) for x in usable) and adapter.dhcp_enabled and not duplicate_v4:
            message = f"Self-assigned address {usable[0].address}: no DHCP server answered"
            if _has_ipv6_route(adapter):
                message += " (IPv6 works: this network may be IPv6-only)"
            out.append({"code": "apipa", "message": message})
        seen: set = set()
        for x in list(adapter.ipv4) + list(adapter.ipv6):
            if int(x.dad_state) == IP_DAD_STATE_DUPLICATE and x.address not in seen:
                seen.add(x.address)
                out.append({"code": "duplicate_address",
                            "message": f"{x.address} is already used by another device on this network"})
        nets: List[ipaddress.IPv4Network] = []
        for x in adapter.ipv4:
            try:
                net = ipaddress.IPv4Network(x.network, strict=False)
            except ValueError:
                continue
            # A /31 or /32 is a host route: there is no subnet for a gateway to be inside, which is
            # exactly how a VPN tunnel is addressed (Mullvad, Tailscale, WireGuard all do it).  Asking
            # whether its gateway is "outside its subnet" is a question with no sensible answer, and
            # answering it yellow made every VPN user's adapter card look misconfigured.
            if net.prefixlen < 31:
                nets.append(net)
        if nets:
            for gw in adapter.gateways:
                if _version(gw) != 4:
                    continue
                if not any(ipaddress.IPv4Address(gw) in net for net in nets):
                    out.append({"code": "gateway_outside_subnet",
                                "message": f"Gateway {gw} is outside this adapter's subnet {nets[0]}: "
                                           "check the IP address and subnet mask"})
        if usable and adapter.ipv4_gateway and not adapter.dns:
            out.append({"code": "no_dns", "message": "No DNS servers: host names will not resolve"})
        if adapters is not None and internet_index is not None and adapter.index == internet_index \
                and adapter.ipv4_gateway and adapter.if_type not in TUNNEL_IF_TYPES:
            # tunnels excluded on both sides: a connected VPN takes the default route by design, and
            # flagging that would mean every machine with Tailscale or a corporate VPN is "wrong"
            others = [a for a in adapters if a is not adapter and a.index != adapter.index and a.is_up
                      and not a.is_loopback and a.ipv4_gateway and a.if_type not in TUNNEL_IF_TYPES]
            if others:
                other = others[0]
                out.append({"code": "multiple_default_gateways",
                            "message": f"{other.name} also has a default gateway ({other.ipv4_gateway}); "
                                       "Windows sends traffic through the one with the lowest metric"})
    except Exception:  # noqa: BLE001
        log.exception("adapter warnings for %s failed", getattr(adapter, "name", "?"))
    return out


def _snapshot_rank(a: Adapter, internet_index: Optional[int]) -> Tuple[int, int, int]:
    if internet_index is not None and a.index == internet_index:
        rank = 0
    elif a.is_up and a.is_physical:
        rank = 1
    elif a.is_up:
        rank = 2
    else:
        rank = 3
    return rank, 0 if a.is_physical else 1, a.index


def netinfo_snapshot() -> Dict[str, Any]:
    """Everything the IP Info view needs, JSON-ready. Never raises."""
    ts = time.time()
    try:
        adapters = get_adapters(include_down=True, include_loopback=False)
        nic = get_internet_nic(adapters)
        internet_index = nic.index if nic is not None else None
        # the gateway comes from the same enumeration: a second one could straddle a network
        # change and pair the new gateway with the old adapter list
        gateway = default_gateway_for(adapters, nic)
        ordered = sorted(adapters, key=lambda a: _snapshot_rank(a, internet_index))
        rows: List[Dict[str, Any]] = []
        for a in ordered:
            row = a.to_dict()
            row["warnings"] = adapter_warnings(a, adapters, internet_index)
            rows.append(row)
        return {
            "ts": ts,
            "adapters": rows,
            "internet_nic_index": internet_index,
            "default_gateway": gateway,
            "public_hint": None,
        }
    except Exception:  # noqa: BLE001
        log.exception("netinfo_snapshot failed")
        return {"ts": ts, "adapters": [], "internet_nic_index": None, "default_gateway": None, "public_hint": None}
