"""Network-change awareness: notice when this PC's IP configuration changes.

Why this exists
---------------
A laptop carried to another building gets a new address, gateway and DNS servers from Windows
within seconds, but TNT used to notice none of it: every component read the adapters on its own
slow timer (the ping tiles' ``gateway`` alias every 5 minutes, the WAN address every 10) and the
Network info page only when it was opened.  :class:`NetWatcher` (``engine.netwatch``) reads
``GetAdaptersAddresses`` every ``network.poll_s`` seconds (default 5, clamped 2..60), reduces the
answer to a normalised fingerprint and publishes **one** ``net.changed`` event when that really
changed.

Layers
------
* Pure and unit-testable without Windows: :func:`adapter_key`, :func:`build_state` (fingerprint
  plus what summaries show), :func:`diff_states` (the ``changes`` list), :func:`change_flags`,
  :func:`summarize`, :func:`build_event` and the :class:`Debouncer`.
* A thin polling thread, :class:`NetWatcher`, with seams for both clocks, the adapter query and
  the DHCP server's own-change marker.  :meth:`NetWatcher.poll` runs one iteration synchronously.

What counts as a change
-----------------------
Per adapter, keyed by the ``AdapterName`` GUID (else LUID, MAC, index, name) so a USB NIC
re-plugged into another port is still the same adapter: whether it is up, its name (a rename in
Network Connections is change kind ``renamed``), its preferred IPv4 addresses with prefixes, its
IPv6 networks (the /64 of every router-advertised address, the address itself when it was typed
in or came from DHCPv6), IPv4 and IPv6 gateways, DNS servers, the connection-specific DNS suffix,
DHCP enabled and the DHCP server; plus which adapter faces the internet and the default gateway
(exactly what the Gateway tile pings, :func:`tnt.netinfo.default_gateway_for`).  Lists are
sorted, so a reordering is no change.

Noise that never counts: link speed and the automatic metric that follows it, MTU, lifetimes,
RFC 4941 temporary IPv6 addresses (Windows reports them as /128 and rotates them; only their /64
is kept), link-local IPv6, addresses still in duplicate-address detection (an address counts once
it is *preferred*), and anything about an adapter that is not up (Windows may or may not keep
listing a disconnected static adapter's addresses; a down adapter appearing in or leaving the
list changes nothing).

Debounce
--------
A new state must hold for :data:`STABLE_S` (2 s) before it is published, or is published anyway
once it has been pending for :data:`MAX_SETTLE_S` (4 s) while it keeps moving or is still settling
(an up DHCP adapter without an address yet, a tentative address - only on an adapter that is part
of the change: a second NIC that never gets a lease holds nothing back); two events are never closer
than :data:`MIN_EVENT_GAP_S`.  While a change is pending the watcher polls every :data:`FAST_POLL_S`.
A cable flap or a DHCP sequence therefore settles into at most one event per ~2 s, a flap that ends
where it started publishes nothing, and a change reaches the bus within ``network.poll_s`` + 4 s of
Windows applying it: ~9 s with the default 5 s poll, so the 10 s promise holds up to a 6 s poll.
Slower settings (the clamp allows 60 s) trade that for fewer adapter reads.

Failures, sleep
---------------
The watcher calls ``netinfo._query_adapters()`` itself: a failed query (driver reload, resume) is
skipped and the last state kept, so a transient failure can never read as "every adapter removed".
When the wall clock jumped past the poll interval (the machine slept) or the Engine reports a
monitoring gap (:meth:`NetWatcher.poll_soon`), the pre-sleep state stays the reference and the
watcher polls every second for a minute, so the lease Windows applies a few seconds after resume
is published as soon as it settles.

Publishing
----------
The netinfo adapter cache is invalidated, then ``net.changed`` goes to the listeners registered
with :meth:`NetWatcher.add_listener` (the Engine: its caches, the pinger, link map, LAN peers, DHCP
server; they must be quick and hand slow work to their own threads) and only then onto the bus, so
an SSE client refreshing on the event already reads fresh data.  Payload::

    {"ts", "generation", "default_gateway", "previous_gateway",
     "internet_nic": {"index", "name", "ipv4": [...], "ipv4_prefixes": ["24", ...], "networks": [...],
                      "dns": [...], "dhcp"} | None,
     "changes": [{"adapter", "kind", "old", "new"}, ...],
     "gateway_changed", "internet_nic_changed", "subnets_changed", "dns_changed",
     "summary", "cause": "dhcp" | None}

``generation`` is 0 when the service starts and counts published changes.  ``cause`` is
``"dhcp"`` when every adapter-level change is an address, gateway, DNS or DHCP change of the
adapter TNT's own DHCP server is re-addressing or putting back on DHCP (``DhcpServer.own_change()``,
or the start-time restore via :meth:`NetWatcher.note_own_change`) *and* that adapter now looks the
way TNT left it: up with the server address and DHCP off while applying or serving, back on DHCP
without it while restoring or restored.  A cable pulled or an address typed in by hand meanwhile is
somebody else's change.  TNT's own changes are still published (the Gateway tile and the map must
follow them) with a summary that says what TNT did.  When neither the default gateway nor the
internet adapter changed, the summary starts with what did ("Wi-Fi disconnected", "Ethernet: DNS
servers 10.20.30.54") because the rest of it reads as before.

Nothing is committed before the payload is built: a failure there leaves the change pending, so the
next poll publishes it (``poll()`` never raises).  Polls are serialised, and the thread of a stopped
run never polls again, so a quick ``stop()``/``start()`` cannot publish from two threads.
"""
from __future__ import annotations

import importlib
import ipaddress
import logging
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

__all__ = [
    "EVENT", "KINDS", "DEFAULT_POLL_S", "MIN_POLL_S", "MAX_POLL_S", "FAST_POLL_S", "STABLE_S", "MAX_SETTLE_S",
    "MIN_EVENT_GAP_S", "NetState", "Debouncer", "NetWatcher", "adapter_key", "build_state", "diff_states",
    "change_flags", "summarize", "internet_nic_brief", "build_event",
]

EVENT = "net.changed"
DEFAULT_POLL_S = 5.0
MIN_POLL_S = 2.0
MAX_POLL_S = 60.0
#: Poll interval while a change settles and for a while after a resume.
FAST_POLL_S = 1.0
#: A new state must hold this long before it is published ...
STABLE_S = 2.0
#: ... unless it keeps moving (or is still settling): then it is published after this long.
MAX_SETTLE_S = 4.0
MIN_EVENT_GAP_S = 2.0
#: Fast polling after a sleep/resume or a clock jump.
RESUME_FAST_S = 60.0
#: Wall-clock silence beyond ``poll_s`` plus this means the machine slept (or the clock was set).
RESUME_JUMP_S = 20.0
FAILURE_RETRY_S = 2.0
#: How long the start-time DHCP restore still labels changes as TNT's own.
OWN_CHANGE_GRACE_S = 30.0
STOP_JOIN_S = 1.0
_ERR_LOG_EVERY_S = 60.0

#: ``changes[].kind`` values.
KINDS: Tuple[str, ...] = ("added", "removed", "up", "down", "ipv4", "ipv6", "gateway", "dns", "dhcp", "renamed",
                          "internet_nic")
_ADAPTER_KINDS = frozenset(KINDS[:-1])
#: The kinds TNT's own DHCP server causes when it re-addresses an adapter or puts it back on DHCP.
_OWN_KINDS = frozenset(("ipv4", "ipv6", "gateway", "dns", "dhcp"))
_OWN_SERVING_PHASES = ("applying", "serving")
_OWN_RESTORE_PHASES = ("restoring", "restored")
#: Separator inside ``summary``: "Ethernet: 10.0.0.112/24 · gateway 10.0.0.251".
SEP = " · "

_PREFIX_ORIGIN_MANUAL = 1           # IP_PREFIX_ORIGIN
_PREFIX_ORIGIN_DHCP = 3
_PREFIX_ORIGIN_RA = 4               # stateless autoconfiguration from a router advertisement
_SUFFIX_ORIGIN_MANUAL = 1           # IP_SUFFIX_ORIGIN
_SUFFIX_ORIGIN_DHCP = 3
_DAD_TENTATIVE = 1
_DAD_DUPLICATE = 2
_APIPA = ipaddress.IPv4Network("169.254.0.0/16")


# --------------------------------------------------------------------------- pure helpers
def _text(value: Any) -> str:
    return str(value or "").strip()


def _norm_mac(mac: Any) -> str:
    digits = "".join(ch for ch in str(mac or "") if ch.isalnum()).upper()
    if len(digits) != 12 or set(digits) == {"0"}:
        return ""
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _version(ip: Any) -> Optional[int]:
    try:
        return ipaddress.ip_address(str(ip).split("%", 1)[0]).version
    except ValueError:
        return None


def _is_apipa(address: Any) -> bool:
    try:
        return ipaddress.IPv4Address(str(address)) in _APIPA
    except ValueError:
        return False


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _adapter_up(adapter: Any) -> bool:
    up = getattr(adapter, "is_up", None)
    if up is None:
        return str(getattr(adapter, "status", "") or "") == "up"
    return bool(up)


def adapter_key(adapter: Any) -> str:
    """Identity of an adapter across polls: the ``AdapterName`` GUID, else the LUID, else the MAC,
    else the interface index, else the name (the last three only matter for test doubles)."""
    guid = _text(getattr(adapter, "guid", "")).lower()
    if guid:
        return "guid:" + guid
    luid = _int(getattr(adapter, "luid", 0))
    if luid:
        return f"luid:{luid}"
    mac = _norm_mac(getattr(adapter, "mac", ""))
    if mac:
        return "mac:" + mac
    index = _int(getattr(adapter, "index", 0))
    if index:
        return f"index:{index}"
    return "name:" + _text(getattr(adapter, "name", ""))


def _ipv4_entries(adapter: Any) -> Tuple[List[Tuple[str, int]], bool, List[str]]:
    """``([(address, prefix)] of preferred IPv4 addresses in Windows' order, any tentative?, the
    addresses duplicate-address detection found in use by another device)``."""
    out: List[Tuple[str, int]] = []
    tentative = False
    duplicates: List[str] = []
    for e in getattr(adapter, "ipv4", None) or []:
        address = _text(getattr(e, "address", ""))
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            continue
        dad = _int(getattr(e, "dad_state", 4), 4)
        if dad == _DAD_TENTATIVE:
            tentative = True
        elif dad == _DAD_DUPLICATE and address not in duplicates:
            duplicates.append(address)
        if not bool(getattr(e, "preferred", True)):
            continue
        out.append((address, _int(getattr(e, "prefix", 32), 32)))
    return out, tentative, duplicates


def _ipv6_identity(entries: Iterable[Any]) -> List[str]:
    """The IPv6 networks an adapter is on, rotation-proof: the /64 of every router-advertised
    address (EUI-64, stable-privacy and the RFC 4941 temporary ones Windows reports as /128 and
    rotates), the address itself when a person or a DHCPv6 server assigned it, the on-link
    network otherwise.  Only preferred global/ULA addresses count."""
    out = set()
    for e in entries or []:
        if not bool(getattr(e, "preferred", True)):
            continue
        try:
            addr = ipaddress.IPv6Address(_text(getattr(e, "address", "")).split("%", 1)[0])
        except ValueError:
            continue
        if addr.is_link_local or addr.is_loopback or addr.is_unspecified or addr.is_multicast:
            continue
        prefix = max(0, min(128, _int(getattr(e, "prefix", 128), 128)))
        prefix_origin = _int(getattr(e, "prefix_origin", 0))
        suffix_origin = _int(getattr(e, "suffix_origin", 0))
        if prefix_origin == _PREFIX_ORIGIN_RA:
            out.add(str(ipaddress.IPv6Network(f"{addr}/64", strict=False)))
        elif suffix_origin in (_SUFFIX_ORIGIN_MANUAL, _SUFFIX_ORIGIN_DHCP) or \
                prefix_origin in (_PREFIX_ORIGIN_MANUAL, _PREFIX_ORIGIN_DHCP):
            out.add(f"{addr}/{prefix}")
        else:
            out.add(str(ipaddress.IPv6Network(f"{addr}/{prefix}", strict=False)))
    return sorted(out)


class NetState:
    """One observation of the network: ``fp`` is what is compared, ``info`` what summaries and
    payloads show, ``order`` the adapters in Windows' order, ``settling_keys`` the adapters still
    settling (an up DHCP adapter without an address, a tentative address)."""

    __slots__ = ("fp", "info", "order", "settling_keys")

    def __init__(self, fp: Dict[str, Any], info: Dict[str, Dict[str, Any]], order: List[str],
                 settling_keys: Iterable[str] = ()) -> None:
        self.fp = fp
        self.info = info
        self.order = order
        self.settling_keys = frozenset(settling_keys)

    @property
    def settling(self) -> bool:
        return bool(self.settling_keys)

    @property
    def adapters(self) -> Dict[str, Dict[str, Any]]:
        return self.fp["adapters"]

    @property
    def internet_key(self) -> Optional[str]:
        return self.fp["internet_nic"]

    @property
    def default_gateway(self) -> Optional[str]:
        return self.fp["default_gateway"]

    def name(self, key: Optional[str]) -> Optional[str]:
        if key is None:
            return None
        return str((self.info.get(key) or {}).get("name") or key)

    def internet_nic_name(self) -> Optional[str]:
        return self.name(self.internet_key) if self.internet_key in self.info else None

    def networks(self) -> List[str]:
        """Every IPv4 subnet and IPv6 network of the up adapters, sorted."""
        out = set()
        for fp in self.adapters.values():
            if not fp["up"]:
                continue
            for cidr in list(fp["ipv4"]) + list(fp["ipv6"]):
                try:
                    out.add(str(ipaddress.ip_interface(cidr).network))
                except ValueError:
                    continue
        return sorted(out)

    def ipv4_networks(self) -> List[str]:
        """The IPv4 subnets of the up adapters, sorted numerically (``/api/status`` ``net.networks``)."""
        nets = set()
        for fp in self.adapters.values():
            if not fp["up"]:
                continue
            for cidr in fp["ipv4"]:
                try:
                    nets.add(ipaddress.IPv4Interface(cidr).network)
                except ValueError:
                    continue
        return [str(n) for n in sorted(nets)]

    def dns_view(self) -> Dict[str, Tuple[Tuple[str, ...], str]]:
        return {k: (tuple(fp["dns"]), fp["suffix"]) for k, fp in self.adapters.items()
                if fp["up"] and (fp["dns"] or fp["suffix"])}


def build_state(adapters: Sequence[Any], internet_nic: Any = None, default_gateway: Optional[str] = None) -> NetState:
    """Normalise one adapter enumeration (``netinfo.Adapter`` or anything shaped like it)."""
    fp_adapters: Dict[str, Dict[str, Any]] = {}
    info: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    internet_key: Optional[str] = None
    settling: List[str] = []
    for a in adapters or []:
        if getattr(a, "is_loopback", False):
            continue
        base = adapter_key(a)
        key, n = base, 2
        while key in fp_adapters:                # two doubles sharing a MAC: keep both apart
            key = f"{base}#{n}"
            n += 1
        up = _adapter_up(a)
        v4, tentative, dup4 = _ipv4_entries(a) if up else ([], False, [])
        gateways = [_text(g) for g in (getattr(a, "gateways", None) or []) if _text(g)] if up else []
        dns = [_text(d) for d in (getattr(a, "dns", None) or []) if _text(d)] if up else []
        dhcp = bool(getattr(a, "dhcp_enabled", False))
        name = _text(getattr(a, "name", ""))
        fp_adapters[key] = {
            "up": up,
            "name": name if up else "",
            "ipv4": sorted(f"{addr}/{prefix}" for addr, prefix in v4),
            "ipv6": _ipv6_identity(getattr(a, "ipv6", None) or []) if up else [],
            "gw4": sorted(g for g in gateways if _version(g) == 4),
            "gw6": sorted(g for g in gateways if _version(g) == 6),
            "dns": sorted(set(dns)),
            "suffix": _text(getattr(a, "dns_suffix", "")).lower() if up else "",
            "dhcp": dhcp if up else None,
            "dhcp_server": (_text(getattr(a, "dhcp_server", "")) or None) if up else None,
        }
        info[key] = {
            "name": name or key,
            "index": getattr(a, "index", None),
            "mac": _norm_mac(getattr(a, "mac", "")),
            "status": _text(getattr(a, "status", "")) or ("up" if up else "unknown"),
            "physical": bool(getattr(a, "is_physical", False)),
            "ipv4": [addr for addr, _p in v4],
            "prefixes": [p for _a, p in v4],
            "dup4": dup4,
            "gateway4": next((g for g in gateways if _version(g) == 4), None),
            "dns": dns,
            "dhcp": dhcp,
        }
        order.append(key)
        if up and (tentative or (dhcp and not v4)):
            settling.append(key)                 # DHCP or duplicate-address detection still running
        if internet_nic is not None and a is internet_nic:
            internet_key = key
    if internet_nic is not None and internet_key is None:
        k = adapter_key(internet_nic)
        internet_key = k if k in fp_adapters else None
    fp = {"adapters": fp_adapters, "internet_nic": internet_key,
          "default_gateway": _text(default_gateway) or None}
    return NetState(fp, info, order, settling)


def _change(adapter: Optional[str], kind: str, old: Any, new: Any) -> Dict[str, Any]:
    return {"adapter": adapter or "", "kind": kind, "old": old, "new": new}


def diff_states(old: NetState, new: NetState) -> List[Dict[str, Any]]:
    """What changed from *old* to *new*, as ``[{"adapter", "kind", "old", "new"}]``; ``[]`` = nothing
    that matters.  Kinds and values: ``added``/``removed`` (IPv4 ``["a.b.c.d/p"]``), ``up``/``down``
    (status strings; an adapter whose up state flipped reports nothing else), ``renamed`` (the old
    and the new name of an up adapter), ``ipv4`` / ``ipv6`` (sorted lists), ``gateway`` (IPv4 then
    IPv6), ``dns`` (``{"servers", "suffix"}``), ``dhcp`` (``{"enabled", "server"}``),
    ``internet_nic`` (adapter names).  A default gateway that moved without any adapter's gateway
    list changing is reported as a ``gateway`` change too."""
    changes: List[Dict[str, Any]] = []
    keys = list(new.order) + [k for k in old.order if k not in new.adapters]
    for key in keys:
        o, n = old.adapters.get(key), new.adapters.get(key)
        if o is None and n is None:
            continue
        if o is None:
            if n["up"]:
                changes.append(_change(new.name(key), "added", None, list(n["ipv4"])))
            continue
        if n is None:
            if o["up"]:
                changes.append(_change(old.name(key), "removed", list(o["ipv4"]), None))
            continue
        name = new.name(key)
        if o["up"] != n["up"]:
            changes.append(_change(name, "up" if n["up"] else "down", old.info[key]["status"], new.info[key]["status"]))
            continue
        if not n["up"]:
            continue
        if o.get("name", "") != n.get("name", ""):
            changes.append(_change(name, "renamed", old.name(key), name))
        if o["ipv4"] != n["ipv4"]:
            changes.append(_change(name, "ipv4", list(o["ipv4"]), list(n["ipv4"])))
        if o["ipv6"] != n["ipv6"]:
            changes.append(_change(name, "ipv6", list(o["ipv6"]), list(n["ipv6"])))
        if o["gw4"] != n["gw4"] or o["gw6"] != n["gw6"]:
            changes.append(_change(name, "gateway", o["gw4"] + o["gw6"], n["gw4"] + n["gw6"]))
        if o["dns"] != n["dns"] or o["suffix"] != n["suffix"]:
            changes.append(_change(name, "dns", {"servers": list(o["dns"]), "suffix": o["suffix"]},
                                   {"servers": list(n["dns"]), "suffix": n["suffix"]}))
        if o["dhcp"] != n["dhcp"] or o["dhcp_server"] != n["dhcp_server"]:
            changes.append(_change(name, "dhcp", {"enabled": o["dhcp"], "server": o["dhcp_server"]},
                                   {"enabled": n["dhcp"], "server": n["dhcp_server"]}))
    old_nic, new_nic = old.internet_nic_name(), new.internet_nic_name()
    if old.internet_key != new.internet_key:
        changes.append(_change(new_nic or old_nic, "internet_nic", old_nic, new_nic))
    if old.default_gateway != new.default_gateway and not any(c["kind"] == "gateway" for c in changes):
        changes.append(_change(new_nic or old_nic, "gateway",
                               [old.default_gateway] if old.default_gateway else [],
                               [new.default_gateway] if new.default_gateway else []))
    return changes


def change_flags(old: NetState, new: NetState) -> Dict[str, bool]:
    return {
        "gateway_changed": old.default_gateway != new.default_gateway,
        "internet_nic_changed": old.internet_key != new.internet_key,
        "subnets_changed": old.networks() != new.networks(),
        "dns_changed": old.dns_view() != new.dns_view(),
    }


def summarize(state: NetState) -> str:
    """Plain text for a toast: ``"Ethernet: 10.20.30.45/24 · gateway 10.20.30.1"``,
    ``"Ethernet: 172.16.20.15/24 · no gateway"``, ``"No network connection"``...

    Without an internet-facing adapter it describes the first up *physical* adapter with an IPv4
    address (a real or duplicate address before a self-assigned one): a Hyper-V switch or a VPN
    tunnel that is still up is not what a person means by the network connection.  An address
    another device already uses is named as the problem (Windows falls back to 169.254.x.x, but
    no DHCP server is to blame), and a cable that is in while DHCP is still asking says so."""
    key = state.internet_key if state.internet_key in state.info else None
    gateway = state.default_gateway
    if key is None:
        ups = [k for k in state.order if state.adapters[k]["up"] and state.info[k]["physical"]]
        candidates = [k for k in ups if state.info[k]["ipv4"] or state.info[k]["dup4"]]
        candidates.sort(key=lambda k: (0 if state.info[k]["dup4"] or not _is_apipa(state.info[k]["ipv4"][0]) else 1,
                                       state.order.index(k)))
        key = candidates[0] if candidates else None
        if key is not None:
            gateway = gateway or state.info[key]["gateway4"]
        elif not gateway:
            waiting = [k for k in ups if state.info[k]["dhcp"] and not state.adapters[k]["ipv6"]]
            if waiting:
                return f"{state.info[waiting[0]]['name']}: connected, waiting for an address (DHCP)"
    if key is None:
        return f"Default gateway {gateway}" if gateway else "No network connection"
    i = state.info[key]
    parts: List[str] = []
    if i["dup4"]:
        parts.append(f"{i['name']}: {i['dup4'][0]} is already in use on this network")
    elif i["ipv4"]:
        parts.append(f"{i['name']}: {i['ipv4'][0]}/{i['prefixes'][0]}")
        if _is_apipa(i["ipv4"][0]):
            parts.append("self-assigned address, no DHCP server answered")
    elif state.adapters[key]["ipv6"]:
        parts.append(f"{i['name']}: IPv6 only")
    else:
        parts.append(f"{i['name']}: no IP address")
    parts.append(f"gateway {gateway}" if gateway else "no gateway")
    return SEP.join(parts)


def _change_phrase(change: Dict[str, Any]) -> Optional[str]:
    """One change as a few plain words for the front of a summary; ``None`` for ``internet_nic``."""
    adapter, kind, new = change["adapter"] or "An adapter", change["kind"], change["new"]
    if kind in ("down", "removed"):
        return f"{adapter} {'disconnected' if kind == 'down' else 'removed'}"
    if kind in ("up", "added"):
        return f"{adapter} connected"
    if kind == "renamed":
        return f"{change['old']} renamed to {new}"
    if kind == "ipv4":
        return f"{adapter}: " + (", ".join(new) if new else "no IPv4 address")
    if kind == "ipv6":
        return f"{adapter}: IPv6 addresses changed"
    if kind == "gateway":
        return f"{adapter}: " + (f"gateway {', '.join(new)}" if new else "no gateway")
    if kind == "dns":
        servers, suffix = (new or {}).get("servers") or [], (new or {}).get("suffix") or ""
        if servers != ((change["old"] or {}).get("servers") or []):
            return f"{adapter}: " + (f"DNS servers {', '.join(servers)}" if servers else "no DNS servers")
        return f"{adapter}: " + (f"DNS suffix {suffix}" if suffix else "no DNS suffix")
    if kind == "dhcp":
        enabled, server = (new or {}).get("enabled"), (new or {}).get("server")
        if enabled != (change["old"] or {}).get("enabled"):
            return f"{adapter}: DHCP {'on' if enabled else 'off'}"
        return f"{adapter}: DHCP server {server}" if server else f"{adapter}: DHCP server changed"
    return None


def _change_lead(changes: List[Dict[str, Any]], old: NetState, new: NetState, flags: Dict[str, bool]) -> Optional[str]:
    """What changed, for the front of the summary, when the summary itself would read as before: the
    default gateway and the internet adapter are the same (an internet adapter's new address already
    shows in the summary).  At most two phrases; ``None`` when there is nothing to add."""
    if flags["gateway_changed"] or flags["internet_nic_changed"]:
        return None
    inet = new.internet_nic_name()
    phrases: List[str] = []
    for c in changes:
        if c["kind"] == "ipv4" and inet is not None and c["adapter"] == inet:
            continue
        phrase = _change_phrase(c)
        if phrase and phrase not in phrases:
            phrases.append(phrase)
    if not phrases:
        return None
    more = len(phrases) - 2
    return SEP.join(phrases[:2]) + (f" (+{more} more)" if more > 0 else "")


def internet_nic_brief(state: NetState) -> Optional[Dict[str, Any]]:
    key = state.internet_key
    if key is None or key not in state.info:
        return None
    i = state.info[key]
    networks: List[str] = []
    for addr, prefix in zip(i["ipv4"], i["prefixes"]):
        try:
            net = str(ipaddress.IPv4Interface(f"{addr}/{prefix}").network)
        except ValueError:
            continue
        if net not in networks:
            networks.append(net)
    return {"index": i["index"], "name": i["name"], "ipv4": list(i["ipv4"]),
            "ipv4_prefixes": [str(p) for p in i["prefixes"]], "networks": networks,
            "dns": list(i["dns"]), "dhcp": bool(i["dhcp"])}


def _own_text(own: Dict[str, Any]) -> str:
    adapter = _text(own.get("adapter")) or "the adapter"
    if _text(own.get("phase")) in ("restoring", "restored"):
        return f"DHCP server put {adapter} back on DHCP"
    ip = _text(own.get("static_ip"))
    return f"DHCP server set {adapter} to {ip}" if ip else f"DHCP server re-addressed {adapter}"


def _caused_by(changes: List[Dict[str, Any]], own: Optional[Dict[str, Any]], new: NetState) -> bool:
    """True when TNT's own DHCP server made this change: every adapter-level change is an address,
    gateway, DNS or DHCP change of the adapter the marker names (the ``internet_nic`` entry follows
    from those and is not looked at), and that adapter is now what TNT made it - up, holding the
    server address with DHCP off while ``applying``/``serving``; back on DHCP without the server
    address while ``restoring``/``restored``.  A cable pulled, an adapter removed or an address
    typed in by hand on that adapter is never TNT's doing, whatever phase the server is in."""
    own = own or {}
    adapter = _text(own.get("adapter"))
    per_adapter = [c for c in changes if c["kind"] in _ADAPTER_KINDS]
    if not adapter or not per_adapter or any(c["adapter"] != adapter or c["kind"] not in _OWN_KINDS for c in per_adapter):
        return False
    key = next((k for k in new.order if new.info[k]["name"] == adapter), None)
    if key is None or not new.adapters[key]["up"]:
        return False
    phase, static_ip = _text(own.get("phase")), _text(own.get("static_ip"))
    has_static = bool(static_ip) and static_ip in new.info[key]["ipv4"]
    dhcp = bool(new.info[key]["dhcp"])
    if phase in _OWN_SERVING_PHASES:
        return has_static and not dhcp
    if phase in _OWN_RESTORE_PHASES:
        return dhcp and not has_static
    return False


def build_event(old: NetState, new: NetState, generation: int, ts: float,
                own: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The ``net.changed`` payload for the change *old* -> *new* (see the module docstring)."""
    changes = diff_states(old, new)
    flags = change_flags(old, new)
    summary = summarize(new)
    cause: Optional[str] = None
    if _caused_by(changes, own, new):
        cause = "dhcp"
        summary = _own_text(own or {}) + SEP + summary
    else:
        lead = _change_lead(changes, old, new, flags)
        if lead:
            summary = lead + SEP + summary
    event: Dict[str, Any] = {
        "ts": float(ts),
        "generation": int(generation),
        "default_gateway": new.default_gateway,
        "previous_gateway": old.default_gateway,
        "internet_nic": internet_nic_brief(new),
        "changes": changes,
    }
    event.update(flags)
    event["summary"] = summary
    event["cause"] = cause
    return event


class Debouncer:
    """Turns a stream of observations into published changes (pure: the caller passes the time).

    The first observation is the reference.  One that differs from the published state
    (:func:`diff_states` not empty) becomes *pending*; it is published once it has not moved for
    *stable_s* and none of the adapters taking part in the change is settling, or once it has been
    pending for *max_settle_s*, and never sooner than *min_gap_s* after the previous publication.
    A pending change that returns to the published state (a flap) is dropped without an event.
    """

    def __init__(self, stable_s: float = STABLE_S, max_settle_s: float = MAX_SETTLE_S,
                 min_gap_s: float = MIN_EVENT_GAP_S) -> None:
        self.stable_s = float(stable_s)
        self.max_settle_s = float(max_settle_s)
        self.min_gap_s = float(min_gap_s)
        self.published: Optional[NetState] = None
        self.pending: Optional[NetState] = None
        self.pending_since: Optional[float] = None
        self.pending_moved_at: Optional[float] = None
        self.last_publish_at: Optional[float] = None

    def observe(self, state: NetState, now: float) -> Optional[NetState]:
        """Feed one observation; returns the state to publish now, else ``None``."""
        if self.published is None:
            self.published = state
            return None
        if not diff_states(self.published, state):
            self.pending = self.pending_since = self.pending_moved_at = None
            return None
        if self.pending is None or self.pending_since is None or self.pending_moved_at is None:
            self.pending_since = self.pending_moved_at = now
        elif diff_states(self.pending, state):
            self.pending_moved_at = now
        self.pending = state
        held = now - self.pending_moved_at >= self.stable_s and not self._settling(state)
        overdue = now - self.pending_since >= self.max_settle_s
        spaced = self.last_publish_at is None or now - self.last_publish_at >= self.min_gap_s
        if not ((held or overdue) and spaced):
            return None
        self.published = state
        self.pending = self.pending_since = self.pending_moved_at = None
        self.last_publish_at = now
        return state

    def _settling(self, state: NetState) -> bool:
        """Whether an adapter that is part of the change is still settling (one that settles in
        the published state just the same, like a second NIC that never gets a lease, is not)."""
        base = self.published
        return any(base is None or base.adapters.get(k) != state.adapters.get(k) for k in state.settling_keys)

    def save(self) -> Tuple[Any, ...]:
        """Everything :meth:`observe` may change, for :meth:`restore`."""
        return (self.published, self.pending, self.pending_since, self.pending_moved_at, self.last_publish_at)

    def restore(self, saved: Tuple[Any, ...]) -> None:
        """Undo the observations since :meth:`save` (a publication that failed is tried again)."""
        (self.published, self.pending, self.pending_since, self.pending_moved_at, self.last_publish_at) = saved


# --------------------------------------------------------------------------- the watcher
def _invalidate_netinfo_cache() -> None:
    try:
        fn = getattr(importlib.import_module("tnt.netinfo"), "_invalidate_cache", None)
        if callable(fn):
            fn()
    except Exception:  # noqa: BLE001
        log.debug("netinfo cache invalidation failed", exc_info=True)


Listener = Callable[[Dict[str, Any]], None]


class NetWatcher:
    """Polls the adapters and publishes ``net.changed`` (``engine.netwatch``); see the module docstring.

    Seams (keyword arguments): *clock* (wall time: ``ts``, ``changed_ts``, sleep detection),
    *monotonic* (debounce timing), *query* (``() -> [Adapter]``; default
    ``tnt.netinfo._query_adapters``, raising means "no answer this time"), *own_change*
    (``() -> marker | None``, normally ``DhcpServer.own_change``).  The internet NIC and the
    default gateway are derived with ``tnt.netinfo`` from the same enumeration.
    """

    def __init__(self, config: Any, bus: Any, *, clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 query: Optional[Callable[[], Sequence[Any]]] = None,
                 own_change: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
                 stable_s: float = STABLE_S, max_settle_s: float = MAX_SETTLE_S) -> None:
        self._config = config
        self._bus = bus
        self._clock = clock
        self._mono = monotonic
        self._query_fn = query
        self._own_change_fn = own_change
        self._lock = threading.RLock()
        self._poll_lock = threading.Lock()      # one poll at a time (start(), the thread, a stopped run's thread)
        self._thread_run = threading.local()    # .stop: the stop event of the run a watcher thread belongs to
        self._debouncer = Debouncer(stable_s, max_settle_s, MIN_EVENT_GAP_S)
        self._listeners: List[Listener] = []
        self._generation = 0
        self._changed_ts: Optional[float] = None
        self._last_event: Optional[Dict[str, Any]] = None
        self._polls = 0
        self._failures = 0
        self._last_error: Optional[str] = None
        self._err_logged_at: Optional[float] = None
        self._last_poll_wall: Optional[float] = None
        self._fast_until = 0.0
        self._next_delay = DEFAULT_POLL_S
        self._own_note: Optional[Tuple[Dict[str, Any], float]] = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._unsub_config: Optional[Callable[[], None]] = None

    # -- configuration / listeners ---------------------------------------------------
    def poll_s(self) -> float:
        try:
            value = float(self._config.get("network.poll_s", DEFAULT_POLL_S))
        except Exception:  # noqa: BLE001 - no config (tests) or a broken value
            value = DEFAULT_POLL_S
        if value != value:
            value = DEFAULT_POLL_S
        return max(MIN_POLL_S, min(MAX_POLL_S, value))

    def add_listener(self, fn: Listener) -> Callable[[], None]:
        """``fn(event)`` for every published change, before the bus gets it (watcher thread;
        must be quick, exceptions are logged)."""
        with self._lock:
            self._listeners.append(fn)

        def unsubscribe() -> None:
            with self._lock:
                if fn in self._listeners:
                    self._listeners.remove(fn)

        return unsubscribe

    def note_own_change(self, marker: Optional[Dict[str, Any]], ttl_s: float = OWN_CHANGE_GRACE_S) -> None:
        """Label changes on ``marker["adapter"]`` as TNT's own for *ttl_s* (the start-time restore
        of an adapter a previous DHCP server run left static)."""
        with self._lock:
            self._own_note = (dict(marker), float(self._mono()) + float(ttl_s)) if marker else None

    def _own_marker(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            note = self._own_note
        if note is not None and float(self._mono()) < note[1]:
            return dict(note[0])
        fn = self._own_change_fn
        if fn is None:
            return None
        try:
            marker = fn()
            return dict(marker) if marker else None
        except Exception:  # noqa: BLE001
            log.debug("own-change marker unavailable", exc_info=True)
            return None

    # -- lifecycle ---------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._running

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def start(self) -> None:
        """Take the reference state now (one native call) and start ``tnt-netwatch``. Idempotent."""
        with self._lock:
            if self._running:
                return
            self._running = True
            stop_evt = threading.Event()
            self._stop = stop_evt
            self._wake.clear()
        self.poll()
        add = getattr(self._config, "add_listener", None)
        if callable(add):
            try:
                unsub = add(self._on_config)
                with self._lock:
                    self._unsub_config = unsub if callable(unsub) else None
            except Exception:  # noqa: BLE001
                log.exception("could not watch network.poll_s")
        t = threading.Thread(target=self._run, args=(stop_evt,), name="tnt-netwatch", daemon=True)
        with self._lock:
            self._thread = t
        t.start()
        log.info("network watcher started (every %g s): %s", self.poll_s(), self.state().get("summary"))

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
            stop_evt, t, unsub = self._stop, self._thread, self._unsub_config
            self._thread = None
            self._unsub_config = None
        stop_evt.set()
        self._wake.set()
        if unsub is not None:
            try:
                unsub()
            except Exception:  # noqa: BLE001
                pass
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(STOP_JOIN_S)
        log.info("network watcher stopped")

    def poll_soon(self, fast_for_s: float = RESUME_FAST_S) -> None:
        """Poll now and every :data:`FAST_POLL_S` for *fast_for_s* (the machine just woke up)."""
        with self._lock:
            self._fast_until = max(self._fast_until, float(self._mono()) + float(fast_for_s))
        self._wake.set()

    def _on_config(self, _snapshot: Dict[str, Any], changed: Iterable[str]) -> None:
        if any(str(k).startswith("network.") for k in changed or ()):
            self._wake.set()

    def _run(self, stop_evt: threading.Event) -> None:
        self._thread_run.stop = stop_evt        # poll() on this thread belongs to this run
        delay = self._next_delay
        while not stop_evt.is_set():
            self._wake.wait(max(0.05, delay))
            self._wake.clear()
            if stop_evt.is_set():
                break
            try:
                delay = self.poll()
            except Exception:  # noqa: BLE001 - poll() never raises; the thread must never die
                log.exception("network watcher poll failed")
                delay = FAILURE_RETRY_S

    # -- polling -----------------------------------------------------------------------
    def _observe(self) -> NetState:
        netinfo = importlib.import_module("tnt.netinfo")
        raw = self._query_fn() if self._query_fn is not None else netinfo._query_adapters()
        adapters = [a for a in (raw or []) if not getattr(a, "is_loopback", False)]
        nic = netinfo.get_internet_nic(adapters)
        return build_state(adapters, nic, netinfo.default_gateway_for(adapters, nic))

    def poll(self) -> float:
        """One observation (never raises); returns the seconds until the next poll.  Polls are
        serialised; on the thread of a run that was stopped (a newer ``start()`` owns the watcher)
        this does nothing."""
        with self._poll_lock:
            run = getattr(self._thread_run, "stop", None)
            if run is not None and run.is_set():
                return self._next_delay
            return self._poll_locked()

    def _poll_locked(self) -> float:
        poll_s = self.poll_s()
        mono = float(self._mono())
        wall = float(self._clock())
        last = self._last_poll_wall
        if last is not None and (wall - last > poll_s + RESUME_JUMP_S or last - wall > RESUME_JUMP_S):
            log.info("network watcher: %.0f s since the last look (sleep/resume or a clock change); "
                     "checking every %g s for a while", wall - last, FAST_POLL_S)
            with self._lock:
                self._fast_until = max(self._fast_until, mono + RESUME_FAST_S)
        self._last_poll_wall = wall
        try:
            state = self._observe()
        except Exception as exc:  # noqa: BLE001 - a failed query is "no answer", never "no adapters"
            with self._lock:
                self._failures += 1
                self._last_error = f"{type(exc).__name__}: {exc}"[:200]
            if self._err_logged_at is None or mono - self._err_logged_at >= _ERR_LOG_EVERY_S:
                self._err_logged_at = mono
                log.warning("network watcher: reading the adapters failed (%s); keeping the last known state", exc)
            self._next_delay = min(poll_s, FAILURE_RETRY_S)
            return self._next_delay
        change: Optional[Tuple[NetState, NetState]] = None
        with self._lock:
            self._polls += 1
            self._last_error = None
            saved = self._debouncer.save()
            before = self._debouncer.published
            after = self._debouncer.observe(state, mono)
            if after is not None and before is not None:
                change = (before, after)
            fast = self._debouncer.pending is not None or mono < self._fast_until
        if change is not None:
            try:
                self._publish(change[0], change[1], wall)
            except Exception:  # noqa: BLE001 - nothing was committed: the change stays pending for the next poll
                with self._lock:
                    self._debouncer.restore(saved)
                    self._last_error = "publishing the change failed"
                if self._err_logged_at is None or mono - self._err_logged_at >= _ERR_LOG_EVERY_S:
                    self._err_logged_at = mono
                    log.exception("network watcher: publishing a change failed; trying again")
                self._next_delay = FAST_POLL_S
                return self._next_delay
        self._err_logged_at = None
        self._next_delay = FAST_POLL_S if fast else poll_s
        return self._next_delay

    def _publish(self, old: NetState, new: NetState, wall: float) -> None:
        own = self._own_marker()
        with self._lock:
            generation = self._generation + 1
        # built before anything is committed: if this raises, the generation, the published state
        # and the listeners are untouched and the next poll tries again
        event = build_event(old, new, generation, wall, own)
        with self._lock:
            self._generation = generation
            self._changed_ts = wall
            self._last_event = event
            listeners = list(self._listeners)
        _invalidate_netinfo_cache()
        log.info("network changed (#%d): %s", generation, event["summary"])
        log.debug("network changes: %s", event["changes"])
        for fn in listeners:
            try:
                fn(event)
            except Exception:  # noqa: BLE001
                log.exception("net.changed listener failed")
        if self._bus is not None:
            try:
                self._bus.publish(EVENT, event, ts=wall)
            except Exception:  # noqa: BLE001
                log.exception("publishing net.changed failed")

    # -- views -------------------------------------------------------------------------
    def state(self) -> Dict[str, Any]:
        """``{"generation", "changed_ts", "default_gateway", "internet_nic", "summary", "networks",
        "running", "poll_s", "polls", "failures", "last_error", "pending"}`` - the published state
        (what ``generation`` describes), no native call.  ``networks`` are the IPv4 subnets of the
        up adapters."""
        with self._lock:
            published = self._debouncer.published
            event = self._last_event
            out = {
                "generation": self._generation,
                "changed_ts": self._changed_ts,
                "default_gateway": published.default_gateway if published is not None else None,
                "internet_nic": published.internet_nic_name() if published is not None else None,
                "summary": event["summary"] if event else (summarize(published) if published is not None else None),
                "networks": published.ipv4_networks() if published is not None else [],
                "running": self._running,
                "polls": self._polls,
                "failures": self._failures,
                "last_error": self._last_error,
                "pending": self._debouncer.pending is not None,
            }
        out["poll_s"] = self.poll_s()
        return out

    def last_event(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._last_event) if self._last_event else None
