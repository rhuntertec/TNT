"""Field DHCP server (Tools page): hand out a handful of addresses on one NIC.

Why this exists
---------------
A technician on a bench or in a rack often has a box (camera, NVR, switch) that boots
into "waiting for DHCP" and nothing on the wire answers. Instead of installing a full
DHCP role, this module turns the PC into a tiny RFC 2131 server for *one* adapter, with
a pool of a few addresses, and lists every device that took one (like the Discovery
table: IP, MAC, vendor, open ports).

Safety first (the things that can bite when a second DHCP server appears on a LAN):

* Before serving we **probe every up NIC for an existing DHCP server** using the relay
  trick (RFC 2131 §4.1: a DISCOVER whose ``giaddr`` is set makes every server unicast its
  OFFER to ``giaddr:67`` -- which we can bind) *and* a plain client-style DISCOVER whose
  broadcast OFFER is caught on :68 (a server whose scope does not cover the NIC's current
  subnet ignores the relay probe but answers that one).  Any answer, or an adapter that
  already got its address from DHCP (``Adapter.dhcp_server``), raises
  :class:`DhcpConflict`; the UI shows a big warning and the user has to force it.
* If the chosen adapter is itself a DHCP client we **re-address it to a static
  172.16.4.100/24** (``netsh ... store=active`` so a reboot alone undoes it), remember
  that in the database (meta key ``dhcp.nic_changed``, written *before* touching the
  NIC) and put it back to DHCP on stop -- and at service start if a previous run died
  (:func:`restore_nic_on_start`).  The NIC is never left static by accident, the record
  is only cleared once the static address has really left the adapter, and the adapter's
  DNS settings are never touched (only the address source is switched).  The static
  address is used only once Windows' duplicate-address detection calls it *preferred*;
  a *duplicate* (someone on the bench already has 172.16.4.100) fails the start and
  restores the NIC.
* We hand out **gateway = our own IP and no DNS** (option 6 is never emitted): the point
  is to reach the device from this PC, not to route it to the internet.
* Every worker thread is wrapped so a malformed packet, a dead socket or a broken
  netsh can never kill the server thread or the service.
* The serving NIC is watched: a network change (``on_network_change``, called by the Engine
  for ``net.changed``) that took that adapter down, removed it or took the server address off
  it stops the server on a helper thread (netsh and the joins take seconds; never on the
  watcher's thread) and says why in ``status()["error"]`` ("stopped: Ethernet went down");
  ``stop()`` restores the NIC as usual.  While the server re-addresses the NIC itself,
  :meth:`DhcpServer.own_change` names the adapter, the static address and the phase
  (``applying`` / ``serving`` / ``restoring``, then ``restored`` for 30 s while the lease comes
  back) so the network watcher labels that change as TNT's own rather than a foreign one.

Windows socket facts this code relies on (measured on Windows 11):

* UDP 67 is free on a Windows 11 PC; the DHCP *client* service only opens 68 briefly.
* A socket bound to the NIC's own IPv4 receives that NIC's broadcasts and its unicast;
  a wildcard ``0.0.0.0`` socket also receives broadcasts.  Unicast goes **only** to the
  most specific socket.  We therefore bind *both* (they coexist without SO_REUSEADDR),
  dedupe datagrams that arrive twice, and always *send* through the specific socket so
  the reply leaves the right NIC.  ``SO_BROADCAST`` is required to send to
  255.255.255.255 (WinError 10013 otherwise).
* A socket that broadcasts to :67 receives its own datagram back; own-IP / own-MAC
  packets are dropped.
* ``recvmsg``/``IP_PKTINFO`` are unavailable in this Python build, so the receiving
  socket (one per NIC) is how the NIC is identified.
* Windows Firewall blocks inbound UDP 67 for the installed service, hence the program
  rule managed by :func:`ensure_firewall_rule` (the netsh conventions live in
  :mod:`tnt.firewall`, shared with the LAN peer service).

Protocol summary (RFC 2131 / 2132): DISCOVER -> OFFER; REQUEST classified as SELECTING
(has 54 + 50), INIT-REBOOT (50 only), RENEWING/REBINDING (ciaddr only) -> ACK / NAK /
silence exactly per §4.3.2 Table 4; DECLINE quarantines the address; RELEASE frees it;
INFORM gets an ACK without a lease.  Replies carry options 53, 54, 51, 58, 59, 1, 3, 28
and nothing else (NAK: 54 + 56).  Reply addressing follows §4.1 (:func:`reply_dest`).

Injectable seams (all keyword arguments, defaulting to the real thing): ``socket_factory``,
``runner`` (a ``subprocess.run`` stand-in), ``adapters_fn``, ``clock``, ``sleep``,
``tcp_connect``, ``resolver``, ``vendor_fn``, ``neighbour_fn`` and ``pinger``.  ``tnt.netinfo``,
``tnt.discovery``, ``tnt.oui`` and ``tnt.arp`` are imported lazily through ``importlib``
so a fake in ``sys.modules`` is honoured.
"""
from __future__ import annotations

import importlib
import ipaddress
import json
import logging
import queue
import random
import select
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import firewall as _firewall

log = logging.getLogger(__name__)

__all__ = [
    "MAGIC", "HDR", "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NAK", "RELEASE", "INFORM",
    "FIREWALL_RULE_NAME", "OFFER_TTL_S", "DECLINE_HOLD_S", "PING_HOLD_S", "DEFAULT_STATIC_IP",
    "DEFAULT_STATIC_PREFIX", "DEFAULT_POOL_SIZE", "DEFAULT_LEASE_S", "MIN_LEASE_S", "MAX_LEASE_S", "SCAN_WAIT_S",
    "Packet", "decode", "encode", "reply_dest", "Lease", "LeaseTable", "default_pool", "validate_pool",
    "NicController", "DuplicateAddress", "restore_nic_on_start", "ensure_firewall_rule", "delete_firewall_rule",
    "scan_for_servers", "probe_host", "DhcpConflict", "DhcpServer",
]

# --- protocol constants ---------------------------------------------------------------------
#: RFC 2132 §2 magic cookie that turns a BOOTP packet into DHCP.
MAGIC = b"\x63\x82\x53\x63"
#: The fixed 236-byte BOOTP header (RFC 2131 §2 Table 1); options follow the cookie at 240.
HDR = struct.Struct("!BBBBIHH4s4s4s4s16s64s128s")
assert HDR.size == 236

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = 1, 2, 3, 4, 5, 6, 7, 8
MSG_NAMES = {DISCOVER: "DISCOVER", OFFER: "OFFER", REQUEST: "REQUEST", DECLINE: "DECLINE", ACK: "ACK",
             NAK: "NAK", RELEASE: "RELEASE", INFORM: "INFORM"}

BOOTREQUEST, BOOTREPLY = 1, 2
FLAG_BROADCAST = 0x8000
#: BOOTP (RFC 951) minimum datagram: shorter replies are dropped by some clients/relays.
MIN_PACKET = 300
BROADCAST_IP = "255.255.255.255"
SERVER_PORT, CLIENT_PORT = 67, 68

# --- policy constants -----------------------------------------------------------------------
FIREWALL_RULE_NAME = "TNT DHCP server (UDP 67 in)"
#: The rule opens both DHCP ports: 67 for requests / relay-probe replies, 68 for the broadcast
#: OFFERs that answer the client-style scan probe.  The name is kept (the uninstaller and
#: earlier installs refer to it); an old 67-only rule is replaced.
FIREWALL_PORTS = frozenset({SERVER_PORT, CLIENT_PORT})
FIREWALL_PORTS_TEXT = f"{SERVER_PORT},{CLIENT_PORT}"
#: An OFFER the client never REQUESTs is forgotten after this (Open DHCP uses 20 s, MS 60 s).
OFFER_TTL_S = 45
#: A DECLINEd address (client saw it in use) is not offered again for this long.
DECLINE_HOLD_S = 1800
#: An address that answered our pre-offer ping is skipped for this long.
PING_HOLD_S = 600
DEFAULT_STATIC_IP = "172.16.4.100"
DEFAULT_STATIC_PREFIX = 24
DEFAULT_POOL_SIZE = 5
DEFAULT_LEASE_S = 3600
MIN_LEASE_S = 120
MAX_LEASE_S = 604800
MAX_POOL = 250
#: How long the "is there another DHCP server?" probe listens (first OFFERs took 3.7 s here).
SCAN_WAIT_S = 8.0
MIN_SCAN_WAIT_S = 1.0
#: Pre-offer ping: short timeout and at most this many candidates so a DISCOVER is answered
#: in ~1 s even when the first pick is taken.
PING_CHECK_TIMEOUT_MS = 500
PING_CHECK_MAX = 2
#: Neighbour-table states that prove a host answered ARP (or was set by hand) just now.  A Windows PC on the Public
#: firewall profile, or a camera with "ping" switched off, drops the echo but still answers the ARP request that went
#: before it, so after an unanswered ping the entry is ``reachable``.  ``stale``/``delay``/``probe`` rows are a host
#: that may have left minutes ago (or has not answered yet), so they never count.
IN_USE_NEIGHBOUR_STATES = ("reachable", "permanent")
#: Identical datagrams seen on both sockets within this window are handled once.
DEDUPE_WINDOW_S = 1.5
RX_TICK_S = 0.5
STOP_JOIN_S = 2.0
#: Wait for the device to finish configuring itself before probing its ports.
PROBE_DELAY_S = 2.0
#: A renewed lease is re-probed only when the last probe is older than this.
REPROBE_AFTER_S = 600.0
NIC_SETTLE_S = 6.0
NETSH_TIMEOUT_S = 20.0
#: How long after putting a NIC back on DHCP its changes (the returning lease) still count as TNT's own.
OWN_CHANGE_GRACE_S = 30.0
#: ``IP_DAD_STATE`` values (``tnt.netinfo.IpAddr.dad_state``): a freshly set address is
#: *tentative* while Windows runs duplicate-address detection, then *preferred* -- or
#: *duplicate* when another host already answers for it.  Only a preferred address can be bound.
IP_DAD_STATE_DUPLICATE = 2      # NL_DAD_STATE: 1 tentative, 2 duplicate, 3 deprecated, 4 preferred
IP_DAD_STATE_PREFERRED = 4
#: How many service starts may fail to restore a re-addressed NIC before the record is dropped
#: (the adapter was removed from the machine, typically a USB NIC).
RESTORE_MAX_ATTEMPTS = 3
NIC_CHANGED_META = "dhcp.nic_changed"
#: ``status()["warning"]`` prefix after a start was refused because of another server; a later
#: clean scan clears it again (see ``DhcpServer._do_scan``).
CONFLICT_WARNING = "another DHCP server is active"
#: ``status()["warning"]`` while a net.changed enumeration failed or answered with nothing: the server keeps
#: running (it may be fine), but the tile must not claim a healthy server on a NIC that may be gone.  The next
#: enumeration that answers clears it.
ADAPTERS_UNREAD_WARNING = "the network adapters could not be read after a network change; the serving adapter may be gone"

_Z4 = b"\x00" * 4
_Z64 = b"\x00" * 64
_Z128 = b"\x00" * 128


# --- small helpers ------------------------------------------------------------------------
def _ip4(raw: bytes) -> Optional[str]:
    """4 raw bytes -> dotted text; ``None`` for 0.0.0.0 / short input."""
    if not raw or len(raw) < 4 or raw[:4] == _Z4:
        return None
    return socket.inet_ntoa(bytes(raw[:4]))


def _packed(ip: Optional[str]) -> bytes:
    if not ip:
        return _Z4
    try:
        return socket.inet_aton(ip)
    except OSError:
        return _Z4


def _u32(n: int) -> bytes:
    return struct.pack("!I", max(0, min(0xFFFFFFFF, int(n))))


def _mac_text(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in bytes(raw[:6]).ljust(6, b"\x00"))


def _mac_bytes(text: Optional[str]) -> Optional[bytes]:
    """``"AA:BB:CC:DD:EE:FF"`` (any separators) -> 6 bytes; ``None`` when not a MAC."""
    if not isinstance(text, str):
        return None
    digits = "".join(ch for ch in text if ch not in ":-. ")
    if len(digits) != 12:
        return None
    try:
        return bytes.fromhex(digits)
    except ValueError:
        return None


def _normalize_mac(text: Optional[str]) -> Optional[str]:
    raw = _mac_bytes(text)
    return _mac_text(raw) if raw is not None else None


def _parse_ipv4(text: Any, what: str = "address") -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(str(text).strip())
    except (ValueError, TypeError, AttributeError):
        raise ValueError(f"{what} is not a valid IPv4 address: {str(text)[:40]!r}") from None


def _mask_text(prefix: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{int(prefix)}").netmask)


def _short(text: Any, limit: int = 120) -> str:
    s = str(text).strip().replace("\r", " ").replace("\n", " ")
    return s if len(s) <= limit else s[:limit] + "..."


# --- packet codec ---------------------------------------------------------------------------
@dataclass
class Packet:
    """A decoded DHCP message (request or reply).

    ``ciaddr``/``yiaddr``/``siaddr``/``giaddr`` are dotted strings or ``None`` when the
    field is 0.0.0.0, so ``if req.giaddr:`` reads like the RFC.  ``mac`` is the first
    ``hlen`` bytes of ``chaddr`` as ``AA:BB:CC:DD:EE:FF``; ``chaddr`` is the raw 16 bytes
    so a reply can copy it verbatim (RFC 2131 Table 3).
    """
    op: int
    xid: int
    flags: int
    ciaddr: Optional[str]
    yiaddr: Optional[str]
    siaddr: Optional[str]
    giaddr: Optional[str]
    mac: str
    chaddr: bytes
    secs: int
    opts: Dict[int, bytes] = field(default_factory=dict)
    msg_type: Optional[int] = None
    htype: int = 1
    hlen: int = 6
    hops: int = 0

    @property
    def broadcast(self) -> bool:
        return bool(self.flags & FLAG_BROADCAST)

    def client_id(self) -> bytes:
        """Lease key: option 61 (type byte included) when present, else the MAC bytes.

        RFC 2131 §4.2: servers "utilize this value to index their address binding
        database"; Windows sends ``01`` + MAC so both forms agree for it."""
        cid = self.opts.get(61)
        if cid:
            return bytes(cid)
        return self.chaddr[:6]

    def client_id_hex(self) -> Optional[str]:
        cid = self.opts.get(61)
        return bytes(cid).hex() if cid else None

    def requested_ip(self) -> Optional[str]:
        return _ip4(self.opts.get(50, b""))

    def server_id(self) -> Optional[str]:
        return _ip4(self.opts.get(54, b""))

    def hostname(self) -> Optional[str]:
        raw = self.opts.get(12)
        if not raw:
            return None
        text = bytes(raw).split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
        # keep it printable and short: this lands in the UI and the database
        text = "".join(ch for ch in text if ch.isprintable())[:63]
        return text or None

    def lease_request(self) -> Optional[int]:
        raw = self.opts.get(51)
        if raw and len(raw) >= 4:
            return struct.unpack("!I", bytes(raw[:4]))[0]
        return None

    def param_list(self) -> List[int]:
        return list(self.opts.get(55, b""))


def decode(raw: bytes, allow_reply: bool = False) -> Optional[Packet]:
    """Parse a datagram; ``None`` for anything that is not a well-formed DHCP message.

    Rejects plain BOOTP (no magic cookie), non-Ethernet ``htype``/``hlen`` and, unless
    ``allow_reply`` is set, anything but BOOTREQUEST.  Options are bounds-checked TLV by
    TLV; a truncated option ends parsing (what was read so far is kept); repeated codes
    are concatenated (RFC 3396).  Never raises.
    """
    try:
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            return None
        raw = bytes(raw)
        if len(raw) < HDR.size + 4 or raw[HDR.size:HDR.size + 4] != MAGIC:
            return None
        op, htype, hlen, hops, xid, secs, flags, ci, yi, si, gi, chaddr, _sname, _file = HDR.unpack_from(raw)
        if op not in ((BOOTREQUEST, BOOTREPLY) if allow_reply else (BOOTREQUEST,)):
            return None
        if htype != 1 or hlen != 6:
            return None
        opts: Dict[int, bytes] = {}
        i = HDR.size + 4
        n = len(raw)
        while i < n:
            code = raw[i]
            if code == 0:            # pad: no length byte
                i += 1
                continue
            if code == 255:          # end
                break
            if i + 1 >= n:
                break
            ln = raw[i + 1]
            val = raw[i + 2:i + 2 + ln]
            if len(val) < ln:        # truncated option
                break
            opts[code] = opts.get(code, b"") + val
            i += 2 + ln
        mt = opts.get(53)
        msg_type = mt[0] if mt else None
        if msg_type is not None and msg_type not in MSG_NAMES:
            msg_type = None
        return Packet(
            op=op, xid=xid, flags=flags, ciaddr=_ip4(ci), yiaddr=_ip4(yi), siaddr=_ip4(si), giaddr=_ip4(gi),
            mac=_mac_text(chaddr), chaddr=bytes(chaddr), secs=secs, opts=opts, msg_type=msg_type,
            htype=htype, hlen=hlen, hops=hops,
        )
    except Exception:  # noqa: BLE001 - a hostile datagram must never escape as an exception
        log.debug("undecodable DHCP datagram", exc_info=True)
        return None


def _tlv(code: int, value: bytes) -> bytes:
    value = bytes(value)
    if len(value) > 255:
        value = value[:255]
    return bytes([code & 0xFF, len(value)]) + value


def encode(req: Packet, mtype: int, yiaddr: Optional[str], opts: List[Tuple[int, bytes]], server_ip: str) -> bytes:
    """Build a BOOTREPLY for *req* (RFC 2131 Table 3), padded to :data:`MIN_PACKET`.

    ``xid``/``flags``/``giaddr``/``chaddr``/``htype``/``hlen`` are copied from the request,
    ``hops``/``secs`` are 0, ``ciaddr`` is copied only into an ACK for a client that had
    one (RENEW/REBIND/INFORM), ``siaddr`` is our address in OFFER/ACK (like dnsmasq; a PXE
    client uses it as "next server") and 0 in a NAK.  Option 53 goes first, 255 ends the
    list; the caller never passes 53 or 255 in *opts*.
    """
    ci = _packed(req.ciaddr) if (mtype == ACK and req.ciaddr) else _Z4
    yi = _packed(yiaddr) if yiaddr else _Z4
    si = _packed(server_ip) if mtype in (OFFER, ACK) else _Z4
    flags = req.flags & 0xFFFF
    if mtype == NAK and req.giaddr:
        # RFC 2131 §4.3.2: "the server MUST set the broadcast bit in the DHCPNAK, so that the
        # relay agent will broadcast the DHCPNAK to the client" (it has no usable address yet)
        flags |= FLAG_BROADCAST
    hdr = HDR.pack(BOOTREPLY, req.htype or 1, req.hlen or 6, 0, req.xid & 0xFFFFFFFF, 0, flags,
                   ci, yi, si, _packed(req.giaddr), bytes(req.chaddr).ljust(16, b"\x00")[:16], _Z64, _Z128)
    body = _tlv(53, bytes([mtype]))
    for code, value in opts:
        if code in (0, 53, 255):
            continue
        body += _tlv(code, value)
    body += b"\xff"
    return (hdr + MAGIC + body).ljust(MIN_PACKET, b"\x00")


def reply_dest(req: Packet, src: Tuple[str, int], mtype: int) -> Tuple[str, int]:
    """Where a reply to *req* (received from *src*) goes -- RFC 2131 §4.1 in order:

    1. relayed (``giaddr`` set) -> ``giaddr:67``;
    2. NAK -> limited broadcast (the client may have no usable address at all);
    3. client already has an address (``ciaddr``: RENEW / REBIND / INFORM) -> ``ciaddr:68``;
    4. the client set the BROADCAST flag -> 255.255.255.255:68 (§4.1: it cannot receive a
       unicast yet; a device that fell back to 169.254.x.x sends from that address, and a
       unicast to it from our static NIC has no route);
    5. a unicast source that is not 0.0.0.0 -> back to the source (loopback tests, clients
       on another port);
    6. otherwise broadcast to 255.255.255.255:68.  The RFC's "unicast to yiaddr" needs a raw
       frame (the client cannot answer ARP yet); Windows accepts the broadcast regardless of
       its BROADCAST flag, so we always broadcast here.
    """
    if req.giaddr:
        return (req.giaddr, SERVER_PORT)
    if mtype == NAK:
        return (BROADCAST_IP, CLIENT_PORT)
    if req.ciaddr:
        return (req.ciaddr, CLIENT_PORT)
    if req.broadcast:
        return (BROADCAST_IP, CLIENT_PORT)
    try:
        src_ip, src_port = str(src[0]), int(src[1])
    except (TypeError, ValueError, IndexError):
        src_ip, src_port = "0.0.0.0", CLIENT_PORT
    if src_ip and src_ip != "0.0.0.0" and src_port > 0:
        return (src_ip, src_port)
    return (BROADCAST_IP, CLIENT_PORT)


# --- leases ---------------------------------------------------------------------------------
LEASE_STATES = ("offered", "bound", "released", "expired", "declined")


@dataclass
class Lease:
    key: bytes                       # client id (option 61) or MAC bytes
    mac: str
    ip: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    client_id: Optional[str] = None  # hex of option 61
    state: str = "offered"
    first_ts: float = 0.0
    last_ts: float = 0.0
    expires_ts: Optional[float] = None       # bound leases only
    offer_expires_ts: Optional[float] = None  # offered leases only
    xid: int = 0
    ping_ok: Optional[bool] = None
    rtt_ms: Optional[float] = None
    open_ports: List[int] = field(default_factory=list)
    probed_ts: Optional[float] = None
    probing: bool = False

    def active(self, now: float) -> bool:
        """True while the address is spoken for (unexpired offer or bound lease)."""
        if self.state == "offered":
            return self.offer_expires_ts is not None and self.offer_expires_ts > now
        if self.state == "bound":
            return self.expires_ts is not None and self.expires_ts > now
        return False

    def to_dict(self) -> Dict[str, Any]:
        """The LEASE DICT the UI table renders (Discovery host keys + lease fields).

        ``expires_ts`` is the lease end for a bound lease and the *offer* end for an offered
        one (the page shows "offer expires in 40 s" and can age the row out itself)."""
        expires = self.expires_ts if self.state != "offered" else self.offer_expires_ts
        return {
            "ip": self.ip, "mac": self.mac, "hostname": self.hostname, "vendor": self.vendor,
            "ping_ok": self.ping_ok, "rtt_ms": self.rtt_ms, "open_ports": list(self.open_ports),
            "client_id": self.client_id, "state": self.state, "first_ts": self.first_ts, "last_ts": self.last_ts,
            "expires_ts": expires, "probed_ts": self.probed_ts, "probing": bool(self.probing),
        }


class LeaseTable:
    """In-memory address bindings with write-through persistence.

    Keyed by the client key (option 61 or MAC); ``by_ip`` maps an address to the key that
    last held it.  ``bad`` holds addresses we must not offer for a while (a DECLINE, or a
    ping or ARP answer before offering).  Every mutation goes through :meth:`_persist` so a
    service restart (:meth:`load`) never re-offers a live address.  Records that leave the
    table (an untaken offer, a dead record whose address moved to another client) are
    collected in ``dropped`` until :meth:`drain_dropped` so the server can tell the UI to
    remove their rows.  Not thread-safe by itself: :class:`DhcpServer` serialises access
    under its lock.
    """

    def __init__(self, db: Any = None, clock: Callable[[], float] = time.time) -> None:
        self._db = db
        self._clock = clock
        self.leases: Dict[bytes, Lease] = {}
        self.by_ip: Dict[str, bytes] = {}
        self.bad: Dict[str, float] = {}
        self.dropped: List[Lease] = []
        self._pool: List[str] = []
        self._pool_set: Set[str] = set()
        self._reserved: Set[str] = set()

    # -- configuration ----------------------------------------------------------------
    def set_pool(self, start: str, end: str) -> None:
        lo, hi = int(_parse_ipv4(start, "pool start")), int(_parse_ipv4(end, "pool end"))
        if hi < lo:
            raise ValueError("pool end is before pool start")
        if hi - lo + 1 > MAX_POOL:
            raise ValueError(f"the pool may hold at most {MAX_POOL} addresses")
        self._pool = [str(ipaddress.IPv4Address(n)) for n in range(lo, hi + 1)]
        self._pool_set = set(self._pool)

    def set_reserved(self, ips: Iterable[str]) -> None:
        self._reserved = {str(ip) for ip in ips if ip}

    @property
    def pool(self) -> List[str]:
        return list(self._pool)

    # -- lookups ----------------------------------------------------------------------
    def get(self, key: bytes) -> Optional[Lease]:
        return self.leases.get(key)

    def get_by_mac(self, mac: str) -> Optional[Lease]:
        norm = _normalize_mac(mac) or mac
        for lease in self.leases.values():
            if lease.mac == norm:
                return lease
        return None

    def get_by_ip(self, ip: str) -> Optional[Lease]:
        key = self.by_ip.get(ip)
        return self.leases.get(key) if key is not None else None

    def _holder_blocks(self, ip: str, key: bytes, now: float) -> bool:
        """True when *ip* is spoken for by a client other than *key*."""
        owner = self.by_ip.get(ip)
        if owner is None or owner == key:
            return False
        lease = self.leases.get(owner)
        return lease is not None and lease.active(now)

    def _usable(self, ip: str, key: bytes, now: float) -> bool:
        if ip not in self._pool_set or ip in self._reserved:
            return False
        if self.bad.get(ip, 0.0) > now:
            return False
        return not self._holder_blocks(ip, key, now)

    def pick_address(self, key: bytes, requested: Optional[str], now: float,
                     ping_fn: Optional[Callable[[str], bool]] = None, max_pings: int = PING_CHECK_MAX) -> Optional[str]:
        """Choose the address to offer *key* (RFC 2131 §4.3.1 order).

        1. the client's current/previous binding, 2. the address it asks for (option 50),
        3. never-used pool addresses, 4. addresses whose previous holder's lease ended.
        *ping_fn(ip)* returning True means "somebody answered" -> the address is held for
        :data:`PING_HOLD_S` and the next candidate is tried; at most *max_pings* pings per
        call keep DISCOVER handling fast.  Addresses still offered/bound to this key are
        not pinged (the client is the one answering).
        """
        current = self.leases.get(key)
        cands: List[str] = []
        if current is not None:
            cands.append(current.ip)
        if requested and requested not in cands:
            cands.append(requested)
        used_ips = set(self.by_ip)
        fresh = [ip for ip in self._pool if ip not in used_ips and ip not in cands]
        stale = [ip for ip in self._pool if ip in used_ips and ip not in cands]
        cands.extend(fresh)
        cands.extend(stale)
        pings = 0
        for ip in cands:
            if not self._usable(ip, key, now):
                continue
            ours = current is not None and current.ip == ip and current.state in ("offered", "bound")
            if ping_fn is not None and not ours:
                if pings >= max_pings:
                    return None            # do not stall the client; it will retry
                pings += 1
                try:
                    in_use = bool(ping_fn(ip))
                except Exception:  # noqa: BLE001 - a broken pinger must not stop the server
                    log.debug("ping check failed for %s", ip, exc_info=True)
                    in_use = False
                if in_use:
                    log.warning("DHCP: %s is in use (it answered the check before it was offered); holding it for %d s",
                                ip, PING_HOLD_S)
                    self.bad[ip] = now + PING_HOLD_S
                    continue
            return ip
        return None

    # -- mutations --------------------------------------------------------------------
    def _drop_stale_holders(self, ip: str, key: bytes) -> None:
        """When *ip* moves to *key*, forget dead records of other clients that pointed at it
        (their memory is worthless now and would show two rows with one IP in the UI)."""
        owner = self.by_ip.get(ip)
        if owner is not None and owner != key:
            old = self.leases.pop(owner, None)
            if old is not None:
                self._delete_row(old.mac)
                self.dropped.append(old)

    def offer(self, key: bytes, mac: str, ip: str, now: float, hostname: Optional[str] = None,
              client_id: Optional[str] = None, xid: int = 0) -> Lease:
        self._drop_stale_holders(ip, key)
        lease = self.leases.get(key)
        if lease is None:
            lease = Lease(key=key, mac=mac, ip=ip, first_ts=now)
            self.leases[key] = lease
        elif lease.ip != ip:
            if self.by_ip.get(lease.ip) == key:
                self.by_ip.pop(lease.ip, None)
            lease.ip = ip
            lease.probed_ts = None
            lease.open_ports = []
            lease.ping_ok = None
            lease.rtt_ms = None
        lease.mac = mac
        lease.state = "offered"
        lease.last_ts = now
        lease.offer_expires_ts = now + OFFER_TTL_S
        lease.expires_ts = None
        lease.xid = xid
        if hostname:
            lease.hostname = hostname
        if client_id:
            lease.client_id = client_id
        self.by_ip[ip] = key
        self._persist(lease)
        return lease

    def bind(self, key: bytes, lease_s: int, now: float, hostname: Optional[str] = None,
             client_id: Optional[str] = None) -> Optional[Lease]:
        lease = self.leases.get(key)
        if lease is None:
            return None
        lease.state = "bound"
        lease.last_ts = now
        lease.expires_ts = now + int(lease_s)
        lease.offer_expires_ts = None
        if hostname:
            lease.hostname = hostname
        if client_id:
            lease.client_id = client_id
        self.by_ip[lease.ip] = key
        self._persist(lease)
        return lease

    def release(self, key: bytes, now: float) -> Optional[Lease]:
        lease = self.leases.get(key)
        if lease is None:
            return None
        lease.state = "released"
        lease.last_ts = now
        lease.expires_ts = None
        lease.offer_expires_ts = None
        self._persist(lease)
        return lease

    def decline(self, key: bytes, ip: str, now: float) -> Optional[Lease]:
        """RFC 2131 §4.3.3: the address is in use by someone else -- quarantine it and drop
        the binding so the next DISCOVER gets another one."""
        self.bad[ip] = now + DECLINE_HOLD_S
        lease = self.leases.get(key)
        if lease is not None and lease.ip == ip:
            lease.state = "declined"
            lease.last_ts = now
            lease.expires_ts = None
            lease.offer_expires_ts = None
            self._persist(lease)
        return lease

    def drop_offer(self, key: bytes) -> Optional[Lease]:
        """A SELECTING REQUEST named another server: our offer was declined by silence.
        Returns the dropped record (state ``expired``, no longer in the table) or ``None``."""
        lease = self.leases.get(key)
        if lease is None or lease.state != "offered":
            return None
        self.leases.pop(key, None)
        if self.by_ip.get(lease.ip) == key:
            self.by_ip.pop(lease.ip, None)
        self._delete_row(lease.mac)
        lease.state = "expired"
        lease.offer_expires_ts = None
        return lease

    def drain_dropped(self) -> List[Lease]:
        """Records removed from the table since the last call (their UI rows must go)."""
        out, self.dropped = self.dropped, []
        return out

    def forget(self, mac: str) -> bool:
        norm = _normalize_mac(mac) or mac
        gone = False
        for key, lease in list(self.leases.items()):
            if lease.mac == norm:
                self.leases.pop(key, None)
                if self.by_ip.get(lease.ip) == key:
                    self.by_ip.pop(lease.ip, None)
                gone = True
        if self._db is not None:
            try:
                gone = bool(self._db.delete_dhcp_lease(norm)) or gone
            except Exception:  # noqa: BLE001
                log.exception("could not delete DHCP lease %s", norm)
        return gone

    def update_probe(self, key: bytes, result: Dict[str, Any], now: float, ip: Optional[str] = None) -> Optional[Lease]:
        """Store a :func:`probe_host` result on the lease behind *key*.  *ip* is the address
        that was probed: when the lease has moved to another address meanwhile the result is
        ignored (``None`` is returned and ``probing`` is cleared) instead of being written onto
        the new address."""
        lease = self.leases.get(key)
        if lease is None:
            return None
        if ip is not None and lease.ip != ip:
            lease.probing = False
            return None
        if result.get("hostname") and not lease.hostname:
            lease.hostname = result["hostname"]
        if result.get("vendor"):
            lease.vendor = result["vendor"]
        lease.ping_ok = result.get("ping_ok")
        lease.rtt_ms = result.get("rtt_ms")
        lease.open_ports = [int(p) for p in (result.get("open_ports") or [])]
        lease.probed_ts = now
        lease.probing = False
        self._persist(lease)
        return lease

    def expire(self, now: float) -> List[Lease]:
        """Forget offers nobody took and mark bound leases whose time ran out; returns the
        leases that changed (a forgotten offer comes back with state ``expired`` and is no
        longer in the table).  Also drops old quarantine entries."""
        changed: List[Lease] = []
        for key, lease in list(self.leases.items()):
            if lease.state == "offered" and (lease.offer_expires_ts is None or lease.offer_expires_ts <= now):
                self.leases.pop(key, None)
                if self.by_ip.get(lease.ip) == key:
                    self.by_ip.pop(lease.ip, None)
                self._delete_row(lease.mac)
                lease.state = "expired"
                lease.offer_expires_ts = None
                changed.append(lease)
            elif lease.state == "bound" and (lease.expires_ts is None or lease.expires_ts <= now):
                lease.state = "expired"
                lease.expires_ts = None
                self._persist(lease)
                changed.append(lease)
        for ip, until in list(self.bad.items()):
            if until <= now:
                self.bad.pop(ip, None)
        return changed

    def counts(self, now: Optional[float] = None) -> Dict[str, int]:
        now = self._clock() if now is None else now
        bound = sum(1 for lz in self.leases.values() if lz.state == "bound")
        offered = sum(1 for lz in self.leases.values() if lz.state == "offered")
        return {"bound": bound, "offered": offered, "total": len(self.leases)}

    # -- persistence ------------------------------------------------------------------
    def to_rows(self) -> List[Dict[str, Any]]:
        rows = [lease.to_dict() for lease in self.leases.values()]
        rows.sort(key=lambda r: (0 if r["state"] in ("bound", "offered") else 1, _ip_sort_key(r["ip"])))
        return rows

    def load(self, rows: Iterable[Dict[str, Any]], now: Optional[float] = None) -> int:
        """Rebuild from database rows (only offered/bound rows still in time reserve their
        address; dead rows are kept as the client's memory).  Returns the number loaded."""
        now = self._clock() if now is None else now
        n = 0
        for r in rows or []:
            try:
                mac = _normalize_mac(r.get("mac"))
                ip = str(r.get("ip") or "")
                if not mac or not ip:
                    continue
                cid = r.get("client_id") or None
                key = bytes.fromhex(cid) if cid else (_mac_bytes(mac) or b"")
                state = str(r.get("state") or "expired")
                expires = r.get("expires_ts")
                lease = Lease(
                    key=key, mac=mac, ip=ip, hostname=r.get("hostname"), vendor=r.get("vendor"), client_id=cid,
                    state=state, first_ts=float(r.get("first_ts") or now), last_ts=float(r.get("last_ts") or now),
                    expires_ts=float(expires) if expires is not None else None,
                    ping_ok=r.get("ping_ok"), rtt_ms=r.get("rtt_ms"),
                    open_ports=[int(p) for p in (r.get("open_ports") or [])], probed_ts=r.get("probed_ts"),
                )
                if state == "offered":
                    # an offer does not survive a restart: the client re-DISCOVERs anyway
                    lease.state = "expired"
                elif state == "bound" and (lease.expires_ts is None or lease.expires_ts <= now):
                    lease.state = "expired"
                    lease.expires_ts = None
                if state not in LEASE_STATES:
                    lease.state = "expired"
                elif state == "declined":
                    # the quarantine survives a restart: the squatter is most likely still there
                    until = lease.last_ts + DECLINE_HOLD_S
                    if until > now:
                        self.bad[ip] = max(self.bad.get(ip, 0.0), until)
                self.leases[key] = lease
                if lease.state != state:
                    self._persist(lease)      # the database mirrors what we decided
                # a live lease always wins the ip index; a dead one only if nobody else has it
                if lease.active(now) or ip not in self.by_ip:
                    self.by_ip[ip] = key
                n += 1
            except Exception:  # noqa: BLE001 - one bad row must not block the start
                log.exception("skipping unreadable DHCP lease row %r", r)
        return n

    def _persist(self, lease: Lease) -> None:
        if self._db is None:
            return
        try:
            self._db.upsert_dhcp_lease(lease.to_dict())
        except Exception:  # noqa: BLE001 - the server keeps serving from memory
            log.exception("could not persist DHCP lease %s", lease.mac)

    def _delete_row(self, mac: str) -> None:
        if self._db is None:
            return
        try:
            self._db.delete_dhcp_lease(mac)
        except Exception:  # noqa: BLE001
            log.exception("could not delete DHCP lease %s", mac)


def _ip_sort_key(ip: str) -> Tuple[int, Any]:
    try:
        return (0, int(ipaddress.IPv4Address(ip)))
    except ValueError:
        return (1, ip)


# --- pool maths -----------------------------------------------------------------------------
def _reserved_for(server_ip: str, prefix: int, exclude: Iterable[str] = ()) -> Tuple[ipaddress.IPv4Network, Set[int]]:
    iface = ipaddress.IPv4Interface(f"{_parse_ipv4(server_ip, 'server address')}/{int(prefix)}")
    net = iface.network
    reserved = {int(net.network_address), int(net.broadcast_address), int(iface.ip)}
    for x in exclude or ():
        try:
            reserved.add(int(ipaddress.IPv4Address(str(x))))
        except (ValueError, TypeError):
            continue
    return net, reserved


def default_pool(server_ip: str, prefix: int, size: int = DEFAULT_POOL_SIZE, exclude: Iterable[str] = ()) -> Tuple[str, str]:
    """The *size* addresses right after *server_ip* in its subnet, skipping network,
    broadcast, the server, the gateway and our other addresses (*exclude*); when that
    does not fit, the *size* addresses right before it.  ``ValueError`` when the subnet
    cannot hold *size* free consecutive addresses.

    172.16.4.100/24 -> 172.16.4.101..105; 10.0.0.112/24 -> 10.0.0.113..117.
    """
    size = int(size)
    if size < 1 or size > MAX_POOL:
        raise ValueError(f"pool size must be between 1 and {MAX_POOL}")
    net, reserved = _reserved_for(server_ip, prefix, exclude)
    me = int(ipaddress.IPv4Address(str(server_ip).strip()))
    lo, hi = int(net.network_address), int(net.broadcast_address)

    def window(start: int, step: int) -> Optional[Tuple[int, int]]:
        """First run of *size* consecutive non-reserved addresses walking from *start*."""
        run: List[int] = []
        n = start
        while lo <= n <= hi:
            if n in reserved:
                run = []
            else:
                run.append(n)
                if len(run) == size:
                    return (min(run), max(run))
            n += step
        return None

    found = window(me + 1, +1) or window(me - 1, -1)
    if found is None:
        raise ValueError(f"the subnet {net.with_prefixlen} cannot hold a pool of {size} addresses next to {server_ip}")
    return str(ipaddress.IPv4Address(found[0])), str(ipaddress.IPv4Address(found[1]))


def validate_pool(start: Any, end: Any, server_ip: str, prefix: int, gateway: Optional[str] = None,
                  exclude: Iterable[str] = ()) -> Tuple[str, str]:
    """Check a user-supplied range: inside the server's subnet, ordered, at most
    :data:`MAX_POOL` addresses and free of the server, gateway, network and broadcast
    addresses.  Returns the normalised ``(start, end)`` or raises ``ValueError``."""
    a = _parse_ipv4(start, "pool start")
    b = _parse_ipv4(end, "pool end")
    net, reserved = _reserved_for(server_ip, prefix, list(exclude or ()) + ([gateway] if gateway else []))
    if a not in net or b not in net:
        raise ValueError(f"the pool must lie inside the server's subnet {net.with_prefixlen}")
    if int(b) < int(a):
        raise ValueError("pool end is before pool start")
    if int(b) - int(a) + 1 > MAX_POOL:
        raise ValueError(f"the pool may hold at most {MAX_POOL} addresses")
    for n in range(int(a), int(b) + 1):
        if n in reserved:
            raise ValueError(f"the pool must not contain {ipaddress.IPv4Address(n)} (server, gateway, network or broadcast address)")
    return str(a), str(b)


# --- netsh plumbing -------------------------------------------------------------------------
def _run_netsh(args: Sequence[str], runner: Optional[Callable[..., Any]] = None,
               timeout_s: float = NETSH_TIMEOUT_S) -> Tuple[int, str]:
    """Run ``netsh <args>`` hidden; ``(returncode, combined output)``.  The conventions (exe
    from ``%SystemRoot%\\System32``, argv list, no window, DEVNULL stdin, OEM decoding) live
    in :mod:`tnt.firewall`; never raises."""
    return _firewall.run_netsh(args, runner, timeout_s)


def _get_adapters(adapters_fn: Optional[Callable[[], Sequence[Any]]] = None, include_down: bool = True) -> List[Any]:
    """Adapters via the seam or ``tnt.netinfo.get_adapters``; never raises."""
    try:
        if adapters_fn is not None:
            return list(adapters_fn() or [])
        netinfo = importlib.import_module("tnt.netinfo")
        return list(netinfo.get_adapters(include_down=include_down, include_loopback=False) or [])
    except Exception:  # noqa: BLE001
        log.exception("adapter enumeration failed")
        return []


def _invalidate_adapter_cache() -> None:
    try:
        netinfo = importlib.import_module("tnt.netinfo")
        fn = getattr(netinfo, "_invalidate_cache", None)
        if fn is not None:
            fn()
    except Exception:  # noqa: BLE001
        pass


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


def _adapter_primary(adapter: Any) -> Tuple[Optional[str], Optional[int]]:
    """``(ip, prefix)`` of the adapter's preferred IPv4 (netinfo puts it first)."""
    primary = getattr(adapter, "primary_ipv4", None)
    for ip, prefix in _adapter_ipv4s(adapter):
        if primary is None or ip == primary:
            return ip, prefix
    ips = _adapter_ipv4s(adapter)
    return ips[0] if ips else (None, None)


class DuplicateAddress(RuntimeError):
    """Windows' duplicate-address detection found the static address in use on the wire."""

    def __init__(self, ip: str) -> None:
        super().__init__(f"static address {ip} is already used on this network")
        self.ip = ip


class NicController:
    """Switch one adapter between DHCP and a static address with ``netsh``.

    The change is recorded in the database (meta ``dhcp.nic_changed``) *before* netsh
    runs, so a crash between the two still leaves a note for :func:`restore_nic_on_start`.
    ``store=active`` keeps the static address out of the persistent store: a reboot alone
    puts the adapter back on DHCP even if everything else fails.
    """

    def __init__(self, runner: Optional[Callable[..., Any]] = None, adapters_fn: Optional[Callable[[], Sequence[Any]]] = None,
                 db: Any = None, sleep: Optional[Callable[[float], None]] = None,
                 clock: Callable[[], float] = time.time, settle_s: float = NIC_SETTLE_S) -> None:
        self._runner = runner
        self._adapters_fn = adapters_fn
        self._db = db
        self._sleep = sleep or time.sleep
        self._clock = clock
        self._settle_s = settle_s
        self.commands: List[List[str]] = []      # what ran, for diagnostics/tests

    # -- adapters ---------------------------------------------------------------------
    def adapters(self) -> List[Any]:
        return _get_adapters(self._adapters_fn)

    def find(self, name: Optional[str] = None, mac: Optional[str] = None) -> Optional[Any]:
        """Adapter by friendly name, else by MAC (Windows renames NICs; MACs stay)."""
        pool = self.adapters()
        if name:
            for a in pool:
                if str(getattr(a, "name", "")) == name:
                    return a
        norm = _normalize_mac(mac) if mac else None
        if norm:
            for a in pool:
                if _normalize_mac(getattr(a, "mac", None)) == norm:
                    return a
        return None

    def _run(self, args: Sequence[str]) -> Tuple[int, str]:
        self.commands.append([str(a) for a in args])
        return _run_netsh(args, self._runner)

    def has_address(self, name: str, ip: str) -> bool:
        """Fresh look (cache invalidated): does adapter *name* list *ip* right now (in any
        DAD state)?"""
        return self.address_state(name, ip) != "absent"

    def address_state(self, name: str, ip: str) -> str:
        """Fresh look at *ip* on adapter *name*: ``"absent"`` (not listed, or no such adapter),
        ``"preferred"`` (usable), ``"duplicate"`` (another host answered for it) or
        ``"tentative"`` (duplicate-address detection still running, or any other state)."""
        _invalidate_adapter_cache()
        a = self.find(name)
        if a is None:
            return "absent"
        for entry in getattr(a, "ipv4", None) or []:
            if str(getattr(entry, "address", "")) != ip:
                continue
            state = getattr(entry, "dad_state", None)
            try:
                state = None if state is None else int(state)
            except (TypeError, ValueError):
                state = None
            if state == IP_DAD_STATE_DUPLICATE:
                return "duplicate"
            if state == IP_DAD_STATE_PREFERRED or (state is None and bool(getattr(entry, "preferred", True))):
                return "preferred"
            return "tentative"
        return "absent"

    def _wait_for(self, name: str, ip: str, present: bool) -> bool:
        """Poll ``get_adapters`` (cache invalidated) until *ip* is **preferred** on *name*
        (``present``) or gone from it.  A freshly set static address is *tentative* while
        Windows checks the wire for a duplicate (a bind to it fails with WinError 10049), so
        merely being listed is not enough.  Raises :class:`DuplicateAddress` when Windows
        reports the address as *duplicate* while waiting for it."""
        deadline = self._clock() + self._settle_s
        while True:
            state = self.address_state(name, ip)
            if present:
                if state == "preferred":
                    return True
                if state == "duplicate":
                    raise DuplicateAddress(ip)
            elif state == "absent":
                return True
            if self._clock() >= deadline:
                return False
            self._sleep(0.25)

    # -- record ------------------------------------------------------------------------
    def record(self) -> Optional[Dict[str, Any]]:
        if self._db is None:
            return None
        try:
            raw = self._db.get_meta(NIC_CHANGED_META)
        except Exception:  # noqa: BLE001
            log.exception("could not read %s", NIC_CHANGED_META)
            return None
        if not raw:
            return None
        try:
            rec = json.loads(raw)
            return rec if isinstance(rec, dict) else None
        except (TypeError, ValueError):
            log.warning("ignoring unreadable %s record", NIC_CHANGED_META)
            return None

    def _write_record(self, rec: Optional[Dict[str, Any]]) -> None:
        if self._db is None:
            return
        self._db.set_meta(NIC_CHANGED_META, json.dumps(rec) if rec else "")

    def clear_record(self) -> None:
        try:
            self._write_record(None)
        except Exception:  # noqa: BLE001
            log.exception("could not clear %s", NIC_CHANGED_META)

    # -- changes ----------------------------------------------------------------------
    def set_static(self, name: str, ip: str, prefix: int) -> Dict[str, Any]:
        """``netsh interface ipv4 set address name=<name> source=static address=<ip> mask=<mask> store=active``.

        Returns the record that was written.  Raises ``RuntimeError`` when netsh fails or
        the address does not show up within the settle time (the record is kept so the
        next service start still tries to restore DHCP)."""
        ip = str(_parse_ipv4(ip, "static address"))
        prefix = int(prefix)
        if not 8 <= prefix <= 30:
            raise ValueError("static prefix must be between 8 and 30")
        adapter = self.find(name)
        rec = {
            "adapter": name,
            "index": int(getattr(adapter, "index", 0) or 0) if adapter is not None else None,
            "mac": _normalize_mac(getattr(adapter, "mac", None)) if adapter is not None else None,
            "static_ip": ip, "prefix": prefix, "ts": self._clock(), "attempts": 0,
        }
        # the note goes in first: if the process dies right after netsh ran, the next start
        # still knows what to undo
        self._write_record(rec)
        rc, out = self._run(["interface", "ipv4", "set", "address", f"name={name}", "source=static",
                             f"address={ip}", f"mask={_mask_text(prefix)}", "store=active"])
        if rc != 0:
            # netsh can apply the address and still exit non-zero (a timeout while it releases
            # the old lease, a partial failure): never leave the adapter static in that case
            if self.has_address(name, ip):
                log.warning("netsh exit %s but %s is on '%s'; putting it back on DHCP", rc, ip, name)
                try:
                    self.restore_dhcp(name, expect_gone=ip)
                except Exception:  # noqa: BLE001
                    log.exception("could not undo the half-applied static address on '%s'", name)
            raise RuntimeError(f"could not set a static address on '{name}': netsh exit {rc}: {_short(out) or 'no output'}")
        try:
            settled = self._wait_for(name, ip, present=True)
        except DuplicateAddress as dup:
            # somebody on the bench already answers for the static address: never serve from
            # it (and never leave the adapter on it) -- back to DHCP, then tell the user
            log.error("static address %s is already used on the network of '%s'; putting it back on DHCP", ip, name)
            try:
                self.restore_dhcp(name, expect_gone=ip)
            except Exception:  # noqa: BLE001
                log.exception("could not undo the duplicate static address on '%s'", name)
            raise RuntimeError(f"{dup}; '{name}' was put back on DHCP") from dup
        if not settled:
            log.warning("static address %s did not become usable on '%s' within %.0f s", ip, name, self._settle_s)
        log.info("adapter '%s' switched to static %s/%d (was DHCP)", name, ip, prefix)
        return rec

    def _bump_attempts(self) -> None:
        """One more failed restore on the record (``restore_nic_on_start`` gives up after
        :data:`RESTORE_MAX_ATTEMPTS`)."""
        rec = self.record()
        if not rec:
            return
        rec["attempts"] = int(rec.get("attempts") or 0) + 1
        try:
            self._write_record(rec)
        except Exception:  # noqa: BLE001
            log.exception("could not update %s", NIC_CHANGED_META)

    def restore_dhcp(self, name: str, expect_gone: Optional[str] = None) -> bool:
        """``set address name=<name> source=dhcp``; clears the record once *expect_gone* has
        actually left the adapter (or the adapter is gone).  Returns True on success.

        DNS is deliberately left alone: ``set address source=static`` does not touch the DNS
        source, so there is nothing to undo -- and ``set dnsservers source=dhcp`` would wipe
        DNS servers the user configured by hand on a DHCP adapter.  When the address command
        exits 0 but the static address is still listed after the settle time the record is
        kept (attempts + 1) and False is returned, so ``stop()`` warns and the next service
        start tries again instead of the only crash-proof trail being erased."""
        rc, out = self._run(["interface", "ipv4", "set", "address", f"name={name}", "source=dhcp"])
        if rc != 0:
            log.error("could not put '%s' back on DHCP: netsh exit %s: %s", name, rc, _short(out))
            return False
        if expect_gone:
            if not self._wait_for(name, expect_gone, present=False):
                log.warning("adapter '%s' still carries %s after the DHCP restore; keeping the %s record",
                            name, expect_gone, NIC_CHANGED_META)
                self._bump_attempts()
                return False
        else:
            _invalidate_adapter_cache()
        self.clear_record()
        log.info("adapter '%s' restored to DHCP", name)
        return True


def restore_nic_on_start(db: Any, runner: Optional[Callable[..., Any]] = None,
                         adapters_fn: Optional[Callable[[], Sequence[Any]]] = None,
                         sleep: Optional[Callable[[float], None]] = None) -> Optional[Dict[str, Any]]:
    """Undo a NIC change a previous run left behind (called by the Engine before the pinger).

    Reads ``dhcp.nic_changed``; when present, restores that adapter (by name, then by
    MAC) to DHCP and clears the record.  A failed restore is retried on the next start up
    to :data:`RESTORE_MAX_ATTEMPTS` times, then the record is dropped (the adapter is
    gone).  Never raises; returns a small dict describing what happened, or ``None`` when
    there was nothing to do.
    """
    try:
        nic = NicController(runner, adapters_fn, db, sleep)
        rec = nic.record()
        if not rec:
            return None
        name = str(rec.get("adapter") or "")
        adapter = nic.find(name, rec.get("mac"))
        target = str(getattr(adapter, "name", "")) if adapter is not None else name
        if not target:
            log.warning("dropping %s record without an adapter name: %r", NIC_CHANGED_META, rec)
            nic.clear_record()
            return {"adapter": None, "restored": False, "dropped": True}
        if adapter is None:
            log.warning("adapter '%s' from a previous DHCP run is not present; trying to restore it anyway", name)
        else:
            # only undo what we did: an adapter that is already back on DHCP (a reboot reverted
            # the store=active change) needs nothing, and one somebody re-addressed by hand in
            # the meantime must not be flipped under them
            static_ip = str(rec.get("static_ip") or "")
            addrs = [ip for ip, _p in _adapter_ipv4s(adapter)]
            if bool(getattr(adapter, "dhcp_enabled", False)):
                log.info("adapter '%s' is already on DHCP; clearing the stale %s record", target, NIC_CHANGED_META)
                nic.clear_record()
                return {"adapter": target, "restored": False, "already_dhcp": True}
            if addrs and static_ip and static_ip not in addrs:
                log.warning("adapter '%s' is static on %s, not on the %s a previous DHCP run set; leaving it alone",
                            target, ", ".join(addrs), static_ip)
                nic.clear_record()
                return {"adapter": target, "restored": False, "dropped": True, "reason": "re-addressed by hand"}
        ok = nic.restore_dhcp(target, expect_gone=rec.get("static_ip") if adapter is not None else None)
        if ok:
            log.warning("restored adapter '%s' to DHCP (a previous DHCP server run had set %s/%s)",
                        target, rec.get("static_ip"), rec.get("prefix"))
            return {"adapter": target, "restored": True, "static_ip": rec.get("static_ip")}
        attempts = int(rec.get("attempts") or 0) + 1
        if attempts >= RESTORE_MAX_ATTEMPTS:
            log.error("giving up restoring adapter '%s' after %d attempts; dropping the record", target, attempts)
            nic.clear_record()
            return {"adapter": target, "restored": False, "dropped": True}
        rec["attempts"] = attempts
        try:
            nic._write_record(rec)
        except Exception:  # noqa: BLE001
            log.exception("could not update %s", NIC_CHANGED_META)
        return {"adapter": target, "restored": False, "attempts": attempts}
    except Exception:  # noqa: BLE001 - never block the service start
        log.exception("restore_nic_on_start failed")
        return None


# --- Windows Firewall -----------------------------------------------------------------------
def ensure_firewall_rule(exe_path: Optional[str], runner: Optional[Callable[..., Any]] = None) -> Tuple[bool, Optional[str]]:
    """Make sure the inbound UDP 67+68 *program* rule :data:`FIREWALL_RULE_NAME` exists for
    *exe_path* -- a thin wrapper over :func:`tnt.firewall.ensure_rule`.

    67 receives client requests and the unicast OFFERs of the relay-style scan probe; 68
    receives the broadcast OFFERs of the client-style probe (Windows Firewall only lets a
    unicast answer to a broadcast in for 3 s, shorter than the 3.7 s a first OFFER took).
    Present for another program (dev python vs. the installed service exe) or without port
    68 (an older build) -> replaced.  Idempotent.  Returns ``(ok, error)``; never raises.
    """
    return _firewall.ensure_rule(FIREWALL_RULE_NAME, exe_path, "udp", FIREWALL_PORTS_TEXT, runner)


def delete_firewall_rule(runner: Optional[Callable[..., Any]] = None) -> Tuple[bool, Optional[str]]:
    """Remove the rule (uninstaller helper).  Missing rule counts as success."""
    return _firewall.delete_rule(FIREWALL_RULE_NAME, runner)


# --- detecting other DHCP servers -----------------------------------------------------------
def _probe_packet(xid: int, nic_ip: str, mac6: bytes) -> bytes:
    """A relay-style DISCOVER: ``giaddr`` = the NIC's address and ``hops`` = 1 make every
    server on that segment unicast its OFFER to ``nic_ip:67`` (RFC 2131 §4.1) -- a port
    we can bind on a client PC, unlike 68.  The NIC's real MAC is used so MAC-filtering
    servers answer too; nothing changes for them because we never REQUEST."""
    hdr = HDR.pack(BOOTREQUEST, 1, 6, 1, xid & 0xFFFFFFFF, 0, 0, _Z4, _Z4, _Z4, _packed(nic_ip),
                   mac6.ljust(16, b"\x00")[:16], _Z64, _Z128)
    body = _tlv(53, bytes([DISCOVER])) + _tlv(61, b"\x01" + mac6) + _tlv(55, bytes([1, 3, 6, 51, 54])) + b"\xff"
    return (hdr + MAGIC + body).ljust(MIN_PACKET, b"\x00")


def _client_probe_packet(xid: int, mac6: bytes) -> bytes:
    """A client-style DISCOVER: ``giaddr`` 0, ``hops`` 0, BROADCAST flag -- what a device with no
    address sends.  A server only answers the relay probe when it has a scope for ``giaddr``'s
    subnet (dnsmasq: "no address range available for DHCP request via <giaddr>"; ISC: "unknown
    network segment"), so a server serving a *different* subnet on the same wire -- the bench
    NIC still on 169.254.x.x, or static on 10.0.0.x while the customer's router serves
    192.168.1.0/24 -- stays invisible to it.  It does answer this packet, by broadcasting its
    OFFER to :68, where the scan listens.  *mac6* is a random locally-administered MAC so the
    Windows DHCP client never sees an OFFER for its own hardware address."""
    hdr = HDR.pack(BOOTREQUEST, 1, 6, 0, xid & 0xFFFFFFFF, 0, FLAG_BROADCAST, _Z4, _Z4, _Z4, _Z4,
                   mac6.ljust(16, b"\x00")[:16], _Z64, _Z128)
    body = _tlv(53, bytes([DISCOVER])) + _tlv(61, b"\x01" + mac6) + _tlv(55, bytes([1, 3, 6, 51, 54])) + b"\xff"
    return (hdr + MAGIC + body).ljust(MIN_PACKET, b"\x00")


def _random_mac() -> bytes:
    """A locally administered MAC (``02:54:4E:54`` = "TNT"), never a real vendor prefix."""
    return bytes([0x02, 0x54, 0x4E, 0x54, random.randrange(256), random.randrange(256)])


def _dns_list(raw: Optional[bytes]) -> List[str]:
    out: List[str] = []
    raw = bytes(raw or b"")
    for i in range(0, len(raw) - 3, 4):
        ip = _ip4(raw[i:i + 4])
        if ip:
            out.append(ip)
    return out


def _server_dict(adapter_name: str, nic_ip: str, sid: str, src_ip: Optional[str], pkt: Optional[Packet],
                 known: bool, answered: bool) -> Dict[str, Any]:
    opts = pkt.opts if pkt is not None else {}
    return {
        "adapter": adapter_name, "nic_ip": nic_ip, "server_ip": sid, "source_ip": src_ip,
        "offered_ip": pkt.yiaddr if pkt is not None else None,
        "lease_s": pkt.lease_request() if pkt is not None else None,
        "router": _ip4(opts.get(3, b"")), "mask": _ip4(opts.get(1, b"")), "dns": _dns_list(opts.get(6)),
        "known": bool(known), "answered": bool(answered),
    }


class _Probe:
    """One NIC's DISCOVER probes (relay-style + client-style, one xid) and the :67 socket they
    leave through (our own, or the running server's)."""

    def __init__(self, adapter: Any, nic_ip: str, xid: int, packet: bytes, client_packet: bytes) -> None:
        self.adapter = adapter
        self.name = str(getattr(adapter, "name", "") or nic_ip)
        self.nic_ip = nic_ip
        self.xid = xid
        self.packet = packet
        self.client_packet = client_packet
        self.sock: Any = None
        self.own_socket = False
        self.unregister: Optional[Callable[[], None]] = None


def scan_for_servers(adapters: Sequence[Any], wait_s: float = SCAN_WAIT_S, socket_factory: Optional[Callable[..., Any]] = None,
                     own_ips: Iterable[str] = (), clock: Callable[[], float] = time.time,
                     existing_socket_for: Optional[Callable[[str], Any]] = None,
                     register_probe: Optional[Callable[[int, Callable[[Packet, Tuple[str, int]], None]], Callable[[], None]]] = None,
                     cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Look for DHCP servers on every up IPv4 adapter (loopback excluded, APIPA included: an
    isolated NIC on 169.254.x.x is exactly where a rogue server matters).

    Per adapter a socket is bound to ``(nic_ip, 67)`` with ``SO_BROADCAST`` and two DISCOVERs
    leave through it (twice: at 0 and at ``wait_s/2``, since a server that ping-checks answers
    late):

    * a **relay-style** one (``giaddr`` = the NIC's address, the NIC's real MAC): every server
      with a scope for that subnet unicasts its OFFER to ``nic_ip:67`` -- MAC-filtering servers
      included;
    * a **client-style** one (``giaddr`` 0, BROADCAST flag, a random locally-administered MAC):
      a server whose scope does *not* cover the NIC's current subnet ignores the relay probe
      but answers this one by broadcasting to :68, so it is caught on sockets bound to
      ``(0.0.0.0, 68)`` and ``(nic_ip, 68)`` (``SO_REUSEADDR``: the Windows DHCP client opens 68
      now and then).

    OFFERs (op 2, matching xid, option 53 == 2) are collected for *wait_s* seconds, keyed by
    option 54 (falling back to the source IP).  Our own echo (op 1, a source in *own_ips*, or a
    server id in *own_ips* -- our own server answering the client-style probe) is ignored.
    Adapters that already know their server (``Adapter.dhcp_server`` while ``dhcp_enabled``)
    contribute ``known`` entries even when that server stayed silent -- and even when that
    NIC's probe socket could not be bound.  A bind failure on one NIC is reported in
    ``errors`` (an entry starting with ``"<adapter> (<nic ip>): "``) and the others are still
    probed.

    When our own server holds ``(nic_ip, 67)`` (Windows delivers unicast only to the most
    specific socket, so a second socket would never see the reply) *existing_socket_for(nic_ip)*
    returns that socket and *register_probe(xid, callback)* makes the server's receive loop
    hand matching replies to us; it returns an unregister callable.  *cancel* ends the listen
    early (the server's ``stop()`` sets it for an in-flight scan).
    """
    started = time.monotonic()
    wait_s = max(0.1, float(wait_s))
    own = {str(ip) for ip in own_ips or ()}
    factory = socket_factory or socket.socket
    result: Dict[str, Any] = {"ts": clock(), "duration_s": 0.0, "wait_s": wait_s, "servers": [], "probed": [], "errors": []}
    servers: Dict[Tuple[str, str], Dict[str, Any]] = {}
    lock = threading.Lock()
    probes: List[_Probe] = []
    attempted: List[_Probe] = []                   # every NIC we tried, bound or not (the "known" merge)
    by_xid: Dict[int, _Probe] = {}
    listeners: List[Tuple[Any, str]] = []          # (socket, label): the :68 OFFER listeners
    threads: List[threading.Thread] = []
    stop = threading.Event()

    def cancelled() -> bool:
        return stop.is_set() or (cancel is not None and cancel.is_set())

    def collect(pkt: Optional[Packet], src: Tuple[str, int]) -> None:
        if pkt is None or pkt.op != BOOTREPLY or pkt.msg_type != OFFER:
            return
        probe = by_xid.get(pkt.xid)
        if probe is None:
            return
        src_ip = str(src[0]) if src else None
        if src_ip in own:
            return
        sid = pkt.server_id() or src_ip or "?"
        if sid in own:
            return
        with lock:
            entry = servers.get((probe.name, sid))
            if entry is None:
                servers[(probe.name, sid)] = _server_dict(probe.name, probe.nic_ip, sid, src_ip, pkt, False, True)
            else:
                entry["answered"] = True
                if entry.get("offered_ip") is None:
                    entry.update(_server_dict(probe.name, probe.nic_ip, sid, src_ip, pkt, entry.get("known", False), True))

    def rx_loop(sock: Any, label: str, deadline: float) -> None:
        while time.monotonic() < deadline and not cancelled():
            try:
                raw, src = sock.recvfrom(2048)
            except (socket.timeout, TimeoutError, BlockingIOError, InterruptedError):
                continue
            except ConnectionResetError:
                # Windows reports an ICMP port-unreachable for an earlier send as WSAECONNRESET
                # on the next recvfrom (a device that rejects the broadcast); the socket is fine
                continue
            except OSError:
                break
            except Exception:  # noqa: BLE001
                log.debug("scan receive failed on %s", label, exc_info=True)
                break
            try:
                collect(decode(raw, allow_reply=True), src)
            except Exception:  # noqa: BLE001
                log.debug("scan reply handling failed", exc_info=True)

    def open_udp(addr: str, port: int, reuse: bool) -> Any:
        s = factory(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if reuse:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind((addr, port))
            s.settimeout(0.25)
        except OSError:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
            raise
        return s

    def send(probe: _Probe) -> bool:
        for data in (probe.packet, probe.client_packet):
            try:
                probe.sock.sendto(data, (BROADCAST_IP, SERVER_PORT))
            except Exception as exc:  # noqa: BLE001 - OSError, or a broken fake
                result["errors"].append(f"{probe.name} ({probe.nic_ip}): send failed: {exc}")
                return False
        return True

    # -- set up one probe per adapter -------------------------------------------------
    for adapter in adapters or []:
        try:
            if getattr(adapter, "is_loopback", False) or not getattr(adapter, "is_up", True):
                continue
            nic_ip, _prefix = _adapter_primary(adapter)
            if not nic_ip or nic_ip.startswith("127."):
                continue
            mac6 = _mac_bytes(getattr(adapter, "mac", None)) or _random_mac()
            xid = random.getrandbits(32) or 1
            while xid in by_xid:
                xid = random.getrandbits(32) or 1
            probe = _Probe(adapter, nic_ip, xid, _probe_packet(xid, nic_ip, mac6), _client_probe_packet(xid, _random_mac()))
            result["probed"].append({"adapter": probe.name, "ip": nic_ip})
            attempted.append(probe)
            existing = existing_socket_for(nic_ip) if existing_socket_for is not None else None
            if existing is not None and register_probe is not None:
                probe.sock = existing
                probe.unregister = register_probe(xid, collect)
            else:
                try:
                    probe.sock = open_udp(nic_ip, SERVER_PORT, reuse=False)
                except OSError as exc:
                    result["errors"].append(f"{probe.name} ({nic_ip}): cannot listen on UDP {SERVER_PORT}: {exc}")
                    continue
                probe.own_socket = True
            probes.append(probe)
            by_xid[xid] = probe
        except Exception as exc:  # noqa: BLE001 - one odd adapter must not stop the scan
            log.exception("scan setup failed for %r", getattr(adapter, "name", adapter))
            result["errors"].append(f"{getattr(adapter, 'name', '?')}: {exc}")

    # -- the :68 listeners for the client-style probe's broadcast OFFERs ----------------
    # One wildcard socket (the path measured on Windows 11: a flags=0x8000 OFFER landed on
    # 0.0.0.0:68) plus one per NIC (a NIC-bound socket receives that NIC's broadcasts); the xid
    # says which probe an OFFER belongs to, whichever socket it arrives on.
    if probes:
        seen_addrs: Set[str] = set()
        for addr in ["0.0.0.0"] + [p.nic_ip for p in probes]:
            if addr in seen_addrs:
                continue
            seen_addrs.add(addr)
            try:
                listeners.append((open_udp(addr, CLIENT_PORT, reuse=True), f"{addr}:{CLIENT_PORT}"))
            except OSError as exc:
                log.debug("scan: cannot listen on %s:%d: %s", addr, CLIENT_PORT, exc)
        if not listeners:
            result["errors"].append(f"cannot listen on UDP {CLIENT_PORT}: only servers with a scope for the NIC's own subnet can answer")

    # -- listen, then send (the listeners must be up before the first OFFER can arrive) ----
    deadline = time.monotonic() + wait_s
    for i, probe in enumerate(probes):
        if probe.own_socket:
            t = threading.Thread(target=rx_loop, args=(probe.sock, probe.name, deadline), name=f"tnt-dhcp-scan-{i}", daemon=True)
            threads.append(t)
            t.start()
    for i, (s, label) in enumerate(listeners):
        t = threading.Thread(target=rx_loop, args=(s, label, deadline), name=f"tnt-dhcp-scan-68-{i}", daemon=True)
        threads.append(t)
        t.start()
    try:
        for probe in probes:
            send(probe)
        resent = not probes
        while time.monotonic() < deadline:
            if cancelled():
                break
            if not resent and time.monotonic() >= deadline - wait_s / 2:
                resent = True
                for probe in probes:
                    send(probe)
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    finally:
        stop.set()
        for probe in probes:
            if probe.unregister:
                try:
                    probe.unregister()
                except Exception:  # noqa: BLE001
                    pass
            if probe.own_socket:
                try:
                    probe.sock.close()
                except Exception:  # noqa: BLE001
                    pass
        for s, _label in listeners:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
        for t in threads:
            t.join(1.0)

    # -- merge what the adapters already know -------------------------------------------
    # over every NIC we *tried*: a probe socket that could not bind (another scan holding
    # the port) must not make the adapter's own DHCP server disappear from the result
    for probe in attempted:
        a = probe.adapter
        known_server = getattr(a, "dhcp_server", None) if getattr(a, "dhcp_enabled", False) else None
        if known_server and known_server not in own:
            key = (probe.name, str(known_server))
            with lock:
                if key in servers:
                    servers[key]["known"] = True
                else:
                    servers[key] = _server_dict(probe.name, probe.nic_ip, str(known_server), None, None, True, False)
    with lock:
        result["servers"] = list(servers.values())
    result["duration_s"] = round(time.monotonic() - started, 3)
    return result


# --- probing a client that took a lease ------------------------------------------------------
PROBE_MAX_PORTS = 64
PROBE_RESOLVE_CAP_S = 3.0


def _clean_ports(ports: Any) -> List[int]:
    out: List[int] = []
    if isinstance(ports, (str, bytes)):
        ports = str(ports).replace(",", " ").split()
    if isinstance(ports, int) and not isinstance(ports, bool):
        ports = [ports]
    for p in ports or []:
        try:
            if isinstance(p, bool):
                continue
            n = int(float(p))
        except (TypeError, ValueError, OverflowError):
            continue
        if 1 <= n <= 65535 and n not in out:
            out.append(n)
        if len(out) >= PROBE_MAX_PORTS:
            break
    return out


def probe_host(ip: str, ports: Iterable[int], pinger: Any, ping_timeout_ms: int = 1000, port_timeout_s: float = 0.6,
               tcp_connect: Optional[Callable[[str, int, float], bool]] = None,
               resolver: Optional[Callable[[str], Optional[str]]] = None,
               vendor_fn: Optional[Callable[[str], Optional[str]]] = None, mac: Optional[str] = None) -> Dict[str, Any]:
    """Ping + TCP port sweep + name/vendor for one address, the way Discovery does it for a
    whole subnet.  Same keys as ``HostResult.to_dict()``.  Never raises and is bounded to a
    few seconds: the port sweep runs on a small pool with an overall deadline, and the name
    lookup (reverse DNS / NetBIOS, which can block) runs on a daemon thread capped at
    :data:`PROBE_RESOLVE_CAP_S`.
    """
    out: Dict[str, Any] = {"ip": str(ip), "hostname": None, "mac": _normalize_mac(mac) if mac else None,
                           "vendor": None, "ping_ok": None, "rtt_ms": None, "open_ports": []}
    try:
        disc = importlib.import_module("tnt.discovery")
    except Exception:  # noqa: BLE001
        disc = None
    # -- name lookup in the background while we ping/scan ------------------------------
    name_box: Dict[str, Any] = {}
    resolve = resolver or (getattr(disc, "_resolve_name", None) if disc is not None else None)
    resolver_thread: Optional[threading.Thread] = None
    if resolve is not None:
        def _resolve() -> None:
            try:
                name_box["name"] = resolve(str(ip))
            except Exception:  # noqa: BLE001
                name_box["name"] = None

        resolver_thread = threading.Thread(target=_resolve, name="tnt-dhcp-resolve", daemon=True)
        resolver_thread.start()
    # -- ping ---------------------------------------------------------------------------
    if pinger is not None:
        try:
            r = pinger.ping(str(ip), size=32, timeout_ms=int(ping_timeout_ms), ttl=128)
            out["ping_ok"] = bool(getattr(r, "ok", False))
            rtt = getattr(r, "rtt_ms", None)
            out["rtt_ms"] = round(float(rtt), 2) if out["ping_ok"] and rtt is not None else None
        except Exception:  # noqa: BLE001
            log.debug("probe ping failed for %s", ip, exc_info=True)
            out["ping_ok"] = False
    # -- ports --------------------------------------------------------------------------
    port_list = _clean_ports(ports)
    connect = tcp_connect or (getattr(disc, "_tcp_connect", None) if disc is not None else None)
    if port_list and connect is not None:
        from concurrent.futures import ThreadPoolExecutor, wait as _wait
        timeout = max(0.05, float(port_timeout_s))
        pool = ThreadPoolExecutor(max_workers=min(8, len(port_list)), thread_name_prefix="tnt-dhcp-port")
        try:
            futs = {pool.submit(connect, str(ip), p, timeout): p for p in port_list}
            done, _pending = _wait(list(futs), timeout=timeout * 2 + 1.0)
            for f in done:
                try:
                    if f.result():
                        out["open_ports"].append(futs[f])
                except Exception:  # noqa: BLE001
                    continue
            out["open_ports"].sort()
        finally:
            pool.shutdown(wait=False)
    # -- vendor / name ------------------------------------------------------------------
    if out["mac"]:
        fn = vendor_fn
        if fn is None and disc is not None:
            try:
                fn = disc._vendor_lookup()
            except Exception:  # noqa: BLE001
                fn = None
        if fn is not None:
            try:
                out["vendor"] = fn(out["mac"])
            except Exception:  # noqa: BLE001
                out["vendor"] = None
    if resolver_thread is not None:
        resolver_thread.join(PROBE_RESOLVE_CAP_S)
        name = name_box.get("name")
        out["hostname"] = str(name).strip() or None if name else None
    return out


class DhcpConflict(RuntimeError):
    """Another DHCP server answered (or is known) on a probed NIC; ``servers`` lists them."""

    def __init__(self, servers: List[Dict[str, Any]], scan: Dict[str, Any]) -> None:
        names = ", ".join(sorted({str(s.get("server_ip")) for s in servers}))
        super().__init__(f"Another DHCP server is active on this network ({names})")
        self.servers = list(servers)
        self.scan = scan


def _scan_problem(scan: Dict[str, Any], name: str, nic_ip: Optional[str]) -> Optional[str]:
    """Why a :func:`scan_for_servers` result says nothing about adapter *name* / *nic_ip*:
    the error entry that names it (``"<name> (<ip>): ..."`` / ``"<name>: ..."``), or a note
    that it was never probed.  ``None`` when the NIC was probed cleanly."""
    for err in scan.get("errors") or []:
        text = str(err)
        if text.startswith(f"{name} (") or text.startswith(f"{name}: ") or (nic_ip and f"({nic_ip})" in text):
            return text
    probed = scan.get("probed") or []
    if any(str(p.get("adapter")) == name or (nic_ip and str(p.get("ip")) == nic_ip) for p in probed):
        return None
    return f"{name} ({nic_ip or 'no IPv4 address'}) was not probed"


# --- the server -----------------------------------------------------------------------------
SETTING_DEFAULTS: Dict[str, Any] = {
    "adapter": "", "pool_start": "", "pool_end": "", "pool_size": DEFAULT_POOL_SIZE, "lease_s": DEFAULT_LEASE_S,
    "static_ip": DEFAULT_STATIC_IP, "static_prefix": DEFAULT_STATIC_PREFIX, "ping_check": True, "scan_wait_s": int(SCAN_WAIT_S),
}


class DhcpServer:
    """The DHCP server component (one instance per Engine; ``engine.dhcp``).

    Off after every service start.  ``start()`` picks the adapter, scans for other servers
    (unless forced), re-addresses a DHCP-client adapter, binds the sockets and starts two
    threads: ``tnt-dhcp-rx`` (receive + protocol) and ``tnt-ping-dhcp-probe`` (pings and
    port-scans each new client; named ``tnt-ping-*`` so the Engine never closes the shared
    ICMP handle under it).  ``stop()`` undoes everything, including the NIC change.
    """

    def __init__(self, db: Any, config: Any, bus: Any, pinger: Any = None, clock: Callable[[], float] = time.time, *,
                 socket_factory: Optional[Callable[..., Any]] = None, runner: Optional[Callable[..., Any]] = None,
                 adapters_fn: Optional[Callable[[], Sequence[Any]]] = None,
                 tcp_connect: Optional[Callable[[str, int, float], bool]] = None,
                 resolver: Optional[Callable[[str], Optional[str]]] = None,
                 vendor_fn: Optional[Callable[[str], Optional[str]]] = None, port: int = SERVER_PORT,
                 exe_path: Optional[str] = None, sleep: Optional[Callable[[float], None]] = None,
                 neighbour_fn: Optional[Callable[..., Optional[Tuple[str, Optional[str]]]]] = None) -> None:
        self._db = db
        self._config = config
        self._bus = bus
        self.pinger = pinger
        self._clock = clock
        self._sleep = sleep or time.sleep
        self._socket_factory = socket_factory or socket.socket
        self._runner = runner
        self._adapters_fn = adapters_fn
        self._tcp_connect = tcp_connect
        self._resolver = resolver
        self._vendor_fn = vendor_fn
        self._neighbour_fn = neighbour_fn
        self._port = int(port)
        self._exe_path = exe_path or sys.executable
        self._lock = threading.RLock()          # state
        self._op_lock = threading.RLock()       # start / stop / scan are serialised
        self._stop_evt = threading.Event()
        self._running = False
        self._since_ts: Optional[float] = None
        self._error: Optional[str] = None
        self._warning: Optional[str] = None
        self._adapter: Any = None
        self._server_ip: Optional[str] = None
        self._prefix: Optional[int] = None
        self._nic_changed = False
        self._nic = NicController(runner, adapters_fn, db, sleep, clock)
        self._pool: Optional[Tuple[str, str]] = None
        self._pool_auto = True
        self._table = LeaseTable(db, clock)
        self._sock_specific: Any = None
        self._sock_wild: Any = None
        self._bound_port = self._port
        self._rx_thread: Optional[threading.Thread] = None
        self._probe_thread: Optional[threading.Thread] = None
        self._probe_q: "queue.Queue[bytes]" = queue.Queue()
        self._queued: Set[bytes] = set()
        self._probes: Dict[int, Callable[[Packet, Tuple[str, int]], None]] = {}
        self._recent: Dict[Tuple[int, str, int, int], float] = {}
        self._last_scan: Optional[Dict[str, Any]] = None
        self._scan_cancel: Optional[threading.Event] = None     # the in-flight scan's cancel event
        self._firewall: Dict[str, Any] = {"rule": FIREWALL_RULE_NAME, "ok": None, "error": None}
        self._own_ips: Set[str] = set()
        self._own_macs: Set[str] = set()
        # set once the NIC-bound socket has delivered a request: from then on the wildcard
        # socket is only a safety net (see _wildcard_accepts)
        self._specific_seen = False
        # what this server is doing to a NIC right now (own_change), and until when "restored" lasts
        self._own_change: Optional[Dict[str, Any]] = None
        self._own_change_until: Optional[float] = None

    # -- small helpers ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._running

    def own_change(self) -> Optional[Dict[str, Any]]:
        """What this server is doing to a NIC right now, for the network watcher:
        ``{"adapter", "index", "mac", "guid", "static_ip", "phase"}`` with phase ``applying`` (netsh
        is switching it to the static address), ``serving``, ``restoring`` (going back to DHCP) or
        ``restored`` (for :data:`OWN_CHANGE_GRACE_S` afterwards, while the lease returns); ``None``
        when it touches no NIC."""
        with self._lock:
            marker, until = self._own_change, self._own_change_until
        if marker is None or (until is not None and float(self._clock()) > until):
            return None
        return dict(marker)

    def _set_own_change(self, adapter: Any, static_ip: Optional[str], phase: Optional[str]) -> None:
        with self._lock:
            if adapter is None or not phase:
                self._own_change, self._own_change_until = None, None
                return
            self._own_change = {
                "adapter": str(getattr(adapter, "name", "") or ""), "index": getattr(adapter, "index", None),
                "mac": _normalize_mac(getattr(adapter, "mac", None)), "guid": str(getattr(adapter, "guid", "") or ""),
                "static_ip": static_ip, "phase": phase,
            }
            self._own_change_until = float(self._clock()) + OWN_CHANGE_GRACE_S if phase == "restored" else None

    def _cfg(self, key: str, default: Any) -> Any:
        try:
            v = self._config.get(f"dhcp.{key}", default)
            return default if v is None else v
        except Exception:  # noqa: BLE001
            return default

    def _settings(self) -> Dict[str, Any]:
        """The dhcp settings with local defaults (works before config.py knows the section)."""
        s: Dict[str, Any] = {}
        for k, d in SETTING_DEFAULTS.items():
            s[k] = self._cfg(k, d)
        for k in ("adapter", "pool_start", "pool_end", "static_ip"):
            s[k] = str(s[k] or "").strip()
        for k, lo, hi in (("pool_size", 1, MAX_POOL), ("lease_s", MIN_LEASE_S, MAX_LEASE_S),
                          ("static_prefix", 8, 30), ("scan_wait_s", 2, 30)):
            try:
                s[k] = max(lo, min(hi, int(float(s[k]))))
            except (TypeError, ValueError, OverflowError):
                s[k] = SETTING_DEFAULTS[k]
        s["ping_check"] = bool(s["ping_check"])
        try:
            ipaddress.IPv4Address(s["static_ip"])
        except ValueError:
            s["static_ip"] = DEFAULT_STATIC_IP
        return s

    def _publish(self, event_type: str, data: Dict[str, Any]) -> None:
        try:
            self._bus.publish(event_type, data)
        except Exception:  # noqa: BLE001
            log.exception("publish %s failed", event_type)

    def _publish_state(self) -> None:
        d = self.summary()
        d["running"] = self._running
        self._publish("dhcp.state", d)

    def _publish_lease(self, lease: Optional[Lease]) -> None:
        """One ``dhcp.lease`` event for *lease*.  A record that has left the table (an untaken
        offer, an offer the client declined by picking another server, a dead record whose
        address moved to another client) is announced as ``{"mac", "state": "forgotten"}`` so
        the page removes the row instead of showing a state that ``status()`` no longer has."""
        if lease is None:
            return
        with self._lock:
            live = self._table.leases.get(lease.key) is lease
        if live:
            self._publish("dhcp.lease", {"lease": lease.to_dict()})
        else:
            self._publish("dhcp.lease", {"lease": {"mac": lease.mac, "state": "forgotten"}})

    def _publish_leases(self, leases: Iterable[Lease]) -> None:
        for lease in leases:
            self._publish_lease(lease)

    def _db_event(self, level: str, message: str) -> None:
        if self._db is None:
            return
        try:
            self._db.add_event(level, "dhcp", message)
        except Exception:  # noqa: BLE001
            log.debug("db event failed", exc_info=True)

    # -- adapters -----------------------------------------------------------------------
    def _candidates(self) -> List[Any]:
        """Up, non-loopback adapters that carry an IPv4 address."""
        out = []
        for a in _get_adapters(self._adapters_fn):
            if getattr(a, "is_loopback", False) or not getattr(a, "is_up", True):
                continue
            ip, _prefix = _adapter_primary(a)
            if ip:
                out.append(a)
        return out

    def _pick_adapter(self, wanted: str, candidates: List[Any]) -> Any:
        """Configured name, else the first up physical Ethernet, else the internet NIC, else
        the first candidate.  ``ValueError`` when nothing is usable."""
        if wanted:
            for a in candidates:
                if str(getattr(a, "name", "")) == wanted:
                    return a
            raise ValueError(f"adapter '{wanted}' is not up or has no IPv4 address")
        for a in candidates:
            if int(getattr(a, "if_type", 0) or 0) == 6 and getattr(a, "is_physical", False):
                return a
        try:
            netinfo = importlib.import_module("tnt.netinfo")
            inet = netinfo.get_internet_nic(candidates)
            if inet is not None and inet in candidates:
                return inet
        except Exception:  # noqa: BLE001
            pass
        if candidates:
            return candidates[0]
        raise ValueError("no network adapter is up with an IPv4 address")

    def _plan(self, adapter: Any, settings: Dict[str, Any]) -> Tuple[str, int, bool]:
        """``(server_ip, prefix, will_change)`` for *adapter*: a DHCP client gets the static
        address, a static adapter keeps its own."""
        if bool(getattr(adapter, "dhcp_enabled", False)):
            return settings["static_ip"], int(settings["static_prefix"]), True
        ip, prefix = _adapter_primary(adapter)
        return str(ip), int(prefix if prefix is not None else 24), False

    def _stuck_record(self, adapter: Any) -> Optional[Tuple[str, int, bool]]:
        """``(server_ip, prefix, False)`` when *adapter* still carries the static address of
        an un-cleared ``dhcp.nic_changed`` record (a previous ``stop()`` could not put it back
        on DHCP): the address is ours, so the run must be treated as *changed* without a new
        netsh call.  ``None`` otherwise, including when a record exists for another adapter --
        that one is restored first (``RuntimeError`` when it cannot be), so a new record never
        overwrites the only trail to a stuck NIC."""
        rec = self._nic.record()
        if not rec:
            return None
        static_ip = str(rec.get("static_ip") or "")
        name = str(getattr(adapter, "name", ""))
        mac = _normalize_mac(getattr(adapter, "mac", None))
        rec_mac = _normalize_mac(rec.get("mac"))
        ours = str(rec.get("adapter") or "") == name or bool(mac and rec_mac and mac == rec_mac)
        if not ours:
            other = self._nic.find(str(rec.get("adapter") or ""), rec.get("mac"))
            other_name = str(getattr(other, "name", "") or rec.get("adapter") or "")
            if other is not None and static_ip and static_ip in [ip for ip, _p in _adapter_ipv4s(other)] \
                    and not bool(getattr(other, "dhcp_enabled", False)):
                log.warning("adapter '%s' is still on %s from an earlier run; restoring it before serving on '%s'",
                            other_name, static_ip, name)
                if not self._nic.restore_dhcp(other_name, expect_gone=static_ip):
                    raise RuntimeError(f"adapter '{other_name}' is still on {static_ip} from an earlier run and could not "
                                       "be put back on DHCP; restart the service (it retries at start) or fix it with netsh")
            return None
        if bool(getattr(adapter, "dhcp_enabled", False)) or not static_ip:
            return None                  # back on DHCP (a reboot undid store=active): a plain start
        if static_ip not in [ip for ip, _p in _adapter_ipv4s(adapter)]:
            return None                  # re-addressed by hand meanwhile: not ours any more
        try:
            prefix = int(rec.get("prefix") or DEFAULT_STATIC_PREFIX)
        except (TypeError, ValueError):
            prefix = DEFAULT_STATIC_PREFIX
        log.warning("adapter '%s' is still on our static %s/%d from an earlier run; serving from it and restoring on stop",
                    name, static_ip, prefix)
        return static_ip, prefix, False

    def _ensure_firewall(self) -> Tuple[bool, Optional[str]]:
        """:func:`ensure_firewall_rule` for our program path, mirrored into ``status()["firewall"]``."""
        ok, err = ensure_firewall_rule(self._exe_path, self._runner)
        with self._lock:
            self._firewall = {"rule": FIREWALL_RULE_NAME, "ok": ok, "error": err}
        return ok, err

    def _own_addresses(self) -> Tuple[Set[str], Set[str]]:
        ips: Set[str] = set()
        macs: Set[str] = set()
        for a in _get_adapters(self._adapters_fn):
            for ip, _p in _adapter_ipv4s(a):
                ips.add(ip)
            m = _normalize_mac(getattr(a, "mac", None))
            if m:
                macs.add(m)
        return ips, macs

    def _resolve_pool(self, adapter: Any, server_ip: str, prefix: int, settings: Dict[str, Any]) -> Tuple[Tuple[str, str], bool]:
        gateway = getattr(adapter, "ipv4_gateway", None)
        exclude = [ip for ip, _p in _adapter_ipv4s(adapter)] + ([gateway] if gateway else [])
        if settings["pool_start"] and settings["pool_end"]:
            return validate_pool(settings["pool_start"], settings["pool_end"], server_ip, prefix, gateway, exclude), False
        return default_pool(server_ip, prefix, int(settings["pool_size"]), exclude), True

    # -- sockets ------------------------------------------------------------------------
    def _open_sockets(self, server_ip: str) -> None:
        """Specific + wildcard sockets on the server port (see the module notes on why both).
        Raises ``RuntimeError`` with a clear message when the port is taken."""
        spec = wild = None
        try:
            spec = self._socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
            spec.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            spec.bind((server_ip, self._port))
            try:
                self._bound_port = int(spec.getsockname()[1]) or self._port
            except Exception:  # noqa: BLE001 - fakes may not implement getsockname
                self._bound_port = self._port
            wild = self._socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
            wild.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            wild.bind(("0.0.0.0", self._bound_port))
        except OSError as exc:
            for s in (spec, wild):
                if s is not None:
                    try:
                        s.close()
                    except Exception:  # noqa: BLE001
                        pass
            errno = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
            if errno in (10048, 98, 48):
                raise RuntimeError(f"UDP port {self._port} is already in use (another DHCP server on this PC?)") from exc
            if errno in (10013, 13):
                raise RuntimeError(f"UDP port {self._port} could not be opened (access denied - is another DHCP server holding it exclusively?)") from exc
            raise RuntimeError(f"could not open UDP port {self._port} on {server_ip}: {exc}") from exc
        self._sock_specific, self._sock_wild = spec, wild

    def _close_sockets(self) -> None:
        for attr in ("_sock_specific", "_sock_wild"):
            s = getattr(self, attr)
            setattr(self, attr, None)
            if s is not None:
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass

    def existing_socket_for(self, nic_ip: str) -> Any:
        """The running server's specific socket when it is bound to *nic_ip* (scan helper)."""
        with self._lock:
            if self._running and self._server_ip == nic_ip and self._bound_port == SERVER_PORT:
                return self._sock_specific
        return None

    def register_probe(self, xid: int, callback: Callable[[Packet, Tuple[str, int]], None]) -> Callable[[], None]:
        """Route replies with *xid* from the receive loop to *callback*; returns unregister."""
        with self._lock:
            self._probes[int(xid)] = callback

        def unregister() -> None:
            with self._lock:
                self._probes.pop(int(xid), None)

        return unregister

    # -- lifecycle ----------------------------------------------------------------------
    def start(self, force: bool = False) -> Dict[str, Any]:
        """Bring the server up.  ``DhcpConflict`` when another server is found and *force* is
        false; ``ValueError`` for bad settings / no adapter; ``RuntimeError`` when the chosen
        NIC could not be checked for other servers (unless forced), when the static address
        turned out to be in use, or when the NIC or the socket could not be set up
        (everything already changed is undone first)."""
        with self._op_lock:
            if self._running:
                return self.status()
            # a fresh lifecycle event per run: a worker of the previous run that outlived
            # stop()'s join keeps its own (set) event and can never resume under this start
            stop_evt = threading.Event()
            self._stop_evt = stop_evt
            with self._lock:
                self._error = None
                self._warning = None
            settings = self._settings()
            candidates = self._candidates()
            adapter = self._pick_adapter(settings["adapter"], candidates)
            name = str(getattr(adapter, "name", ""))
            nic_ip, _nic_prefix = _adapter_primary(adapter)
            server_ip, prefix, will_change = self._plan(adapter, settings)
            # an adapter a previous stop() could not put back on DHCP reads as "static" now,
            # but the static address is ours: keep treating it as changed so stop() restores it
            try:
                stuck = self._stuck_record(adapter)
            except RuntimeError as exc:
                with self._lock:
                    self._error = str(exc)
                self._publish_state()
                raise
            if stuck is not None:
                server_ip, prefix, will_change = stuck
            # the pool is validated before anything is touched so a bad range fails fast
            pool, auto = self._resolve_pool(adapter, server_ip, prefix, settings)
            own_ips, own_macs = self._own_addresses()
            # the firewall rule goes in *before* the scan: on the installed service the very
            # first scan's unicast OFFERs to :67 would otherwise be dropped by Windows Firewall
            ok, err = self._ensure_firewall()
            warning = None if ok else f"Windows Firewall rule could not be created ({err}); clients may not reach the server"
            if warning:
                log.warning(warning)
            if not force:
                scan = self._do_scan(candidates, float(settings["scan_wait_s"]), own_ips)
                if stop_evt.is_set():
                    raise RuntimeError("start cancelled")
                if scan["servers"]:
                    # a warning, not an error: the user may simply cancel and nothing is broken
                    with self._lock:
                        self._warning = f"{CONFLICT_WARNING} ({', '.join(sorted({str(s['server_ip']) for s in scan['servers']}))})"
                    self._publish_state()
                    raise DhcpConflict(scan["servers"], scan)
                problem = _scan_problem(scan, name, nic_ip)
                if problem is not None:
                    # a scan that could not probe *this* NIC (its :67 taken by another scan, a
                    # send failure) proves nothing: refuse rather than start blind
                    msg = f"could not check {name} for other DHCP servers: {problem}"
                    with self._lock:
                        self._error = msg
                    self._publish_state()
                    raise RuntimeError(msg)
            changed = False
            try:
                if will_change:
                    # the network watcher sees this re-address as TNT's own (own_change)
                    self._set_own_change(adapter, server_ip, "applying")
                    self._nic.set_static(name, server_ip, prefix)
                    changed = True
                    own_ips.add(server_ip)
                elif stuck is not None:
                    changed = True                # still our address from the earlier run
                    own_ips.add(server_ip)
                self._open_sockets(server_ip)
                with self._lock:
                    self._table = LeaseTable(self._db, self._clock)
                    self._table.set_pool(*pool)
                    self._table.set_reserved([server_ip] + [ip for ip, _p in _adapter_ipv4s(adapter)]
                                             + ([getattr(adapter, "ipv4_gateway", None)] if getattr(adapter, "ipv4_gateway", None) else []))
                    self._load_leases()
                    if stop_evt.is_set():
                        raise RuntimeError("start cancelled")
                    self._adapter = adapter
                    self._server_ip = server_ip
                    self._prefix = prefix
                    self._nic_changed = changed
                    self._pool = pool
                    self._pool_auto = auto
                    self._own_ips = own_ips
                    self._own_macs = own_macs
                    self._firewall = {"rule": FIREWALL_RULE_NAME, "ok": ok, "error": err}
                    self._warning = warning
                    self._recent = {}
                    self._specific_seen = False
                    self._queued = set()
                    self._probe_q = queue.Queue()
                    self._running = True
                    self._since_ts = self._clock()
                    if changed:
                        self._set_own_change(adapter, server_ip, "serving")
                    self._rx_thread = threading.Thread(target=self._rx_loop, args=(stop_evt,), name="tnt-dhcp-rx", daemon=True)
                    self._probe_thread = threading.Thread(target=self._probe_loop, args=(stop_evt,), name="tnt-ping-dhcp-probe", daemon=True)
                    self._rx_thread.start()
                    self._probe_thread.start()
            except Exception as exc:
                # transactional: nothing we changed survives a failed start
                self._close_sockets()
                with self._lock:
                    self._running = False
                if changed:
                    self._set_own_change(adapter, server_ip, "restoring")
                    try:
                        self._nic.restore_dhcp(name, expect_gone=server_ip)
                    except Exception:  # noqa: BLE001
                        log.exception("could not restore '%s' after a failed start", name)
                if changed or will_change:
                    self._set_own_change(adapter, server_ip, "restored")   # set_static may have undone it itself
                with self._lock:
                    self._error = str(exc)
                self._publish_state()
                if isinstance(exc, (RuntimeError, ValueError)):
                    raise
                raise RuntimeError(str(exc)) from exc
            log.info("DHCP server started on '%s' %s/%d, pool %s-%s, lease %ss%s", name, server_ip, prefix, pool[0], pool[1],
                     settings["lease_s"], " (adapter re-addressed from DHCP)" if changed else "")
            self._db_event("info", f"DHCP server started on {name} ({server_ip}), pool {pool[0]}-{pool[1]}")
            self._publish_state()
            return self.status()

    def stop(self, restore_nic: bool = True) -> Dict[str, Any]:
        """Stop serving, close the sockets and put the adapter back on DHCP if we changed it.
        Idempotent and safe from any thread."""
        self._stop_evt.set()          # aborts an in-flight start too
        with self._lock:
            scan_cancel = self._scan_cancel
        if scan_cancel is not None:
            scan_cancel.set()         # and an in-flight scan (its own event: a later scan() is unaffected)
        with self._op_lock:
            with self._lock:
                was_running = self._running
                self._running = False
                rx, pb = self._rx_thread, self._probe_thread
                self._rx_thread = self._probe_thread = None
                adapter = self._adapter
                name = str(getattr(self._adapter, "name", "")) if self._adapter is not None else ""
                changed = self._nic_changed
                server_ip = self._server_ip
                if self._warning == ADAPTERS_UNREAD_WARNING:
                    self._warning = None          # it spoke of the running server only
            if not was_running and not changed:
                return self.status()
            # Sockets first (the receive thread wakes up on the closed socket and exits), then
            # the NIC restore -- netsh takes 1-3 s and must not queue behind a probe thread that
            # is mid port-scan, or it would fall outside the Engine's bounded stop budget and
            # race the database close -- and only then the thread joins.
            self._close_sockets()
            if changed and restore_nic:
                self._set_own_change(adapter, server_ip, "restoring")
                try:
                    if self._nic.restore_dhcp(name, expect_gone=server_ip):
                        with self._lock:
                            self._nic_changed = False
                    else:
                        with self._lock:
                            self._warning = f"adapter '{name}' could not be put back on DHCP; it will be restored at the next service start"
                except Exception:  # noqa: BLE001
                    log.exception("restore of '%s' failed", name)
                self._set_own_change(adapter, server_ip, "restored")
            else:
                self._set_own_change(None, None, None)
            deadline = time.monotonic() + STOP_JOIN_S
            for t in (rx, pb):
                if t is not None and t.is_alive() and t is not threading.current_thread():
                    t.join(max(0.05, deadline - time.monotonic()))
            with self._lock:
                self._since_ts = None
                self._probes = {}
                self._recent = {}
            if was_running:
                log.info("DHCP server stopped")
                self._db_event("info", "DHCP server stopped")
            self._publish_state()
            return self.status()

    # -- network changes ----------------------------------------------------------------
    def on_network_change(self, data: Optional[Dict[str, Any]] = None) -> None:
        """``net.changed`` (network watcher thread; quick, never raises).  While serving, check that
        the serving NIC is still present, up and holding the server address; when it is not, stop
        on a helper thread with the reason in ``status()["error"]``.  Otherwise addresses another
        NIC gained join the own-address filter."""
        try:
            with self._lock:
                running, adapter, server_ip = self._running, self._adapter, self._server_ip
            if not running or adapter is None or not server_ip:
                return
            pool = _get_adapters(self._adapters_fn)
            if not pool:
                # a failed enumeration (netinfo answers [] for one) is "no answer", never "every adapter was
                # removed": reading it as a removal would drop the NIC-restore record while the NIC still has
                # the static bench address.  It can also be a PC whose only adapter was the served one, so the
                # status says the adapters could not be read rather than showing a healthy server; the next
                # net.changed looks again.
                log.warning("DHCP server: the adapters could not be read during a network change; keeping the server as it is")
                with self._lock:
                    flag = self._running and self._warning is None
                    if flag:
                        self._warning = ADAPTERS_UNREAD_WARNING
                if flag:
                    self._publish_state()
                return
            with self._lock:
                cleared = self._warning == ADAPTERS_UNREAD_WARNING
                if cleared:
                    self._warning = None
            if cleared:
                self._publish_state()
            problem = self._serving_problem(adapter, server_ip, pool)
            if problem is None:
                ips = {ip for a in pool for ip, _p in _adapter_ipv4s(a)}
                macs = {m for m in (_normalize_mac(getattr(a, "mac", None)) for a in pool) if m}
                with self._lock:
                    if self._running:
                        self._own_ips = self._own_ips | ips
                        self._own_macs = self._own_macs | macs
                return
            log.warning("DHCP server is stopping: %s", problem)
            gone = self._same_nic(adapter, pool) is None
            threading.Thread(target=self._stop_for_network, args=(problem, gone), name="tnt-dhcp-netstop",
                             daemon=True).start()
        except Exception:  # noqa: BLE001
            log.exception("handling a network change in the DHCP server failed")

    @staticmethod
    def _same_nic(adapter: Any, pool: Sequence[Any]) -> Any:
        """*adapter* in a fresh enumeration: by GUID, then index and name together, then MAC and
        name, then name, MAC or index alone (a USB NIC re-plugged elsewhere keeps its MAC but may
        get a new index; a virtual switch can clone a physical NIC's MAC)."""
        guid = str(getattr(adapter, "guid", "") or "").lower()
        mac = _normalize_mac(getattr(adapter, "mac", None))
        index = getattr(adapter, "index", None)
        name = str(getattr(adapter, "name", "") or "")

        def same_name(a: Any) -> bool:
            return bool(name) and str(getattr(a, "name", "") or "") == name

        def same_mac(a: Any) -> bool:
            return bool(mac) and _normalize_mac(getattr(a, "mac", None)) == mac

        def same_index(a: Any) -> bool:
            return bool(index) and getattr(a, "index", None) == index

        rules = (
            lambda a: bool(guid) and str(getattr(a, "guid", "") or "").lower() == guid,
            lambda a: same_index(a) and same_name(a),
            lambda a: same_mac(a) and same_name(a),
            same_name, same_mac, same_index,
        )
        for rule in rules:
            for a in pool:
                if rule(a):
                    return a
        return None

    @classmethod
    def _serving_problem(cls, adapter: Any, server_ip: str, pool: Sequence[Any]) -> Optional[str]:
        """Why the server can no longer serve from *adapter* / *server_ip* (plain text), else ``None``."""
        name = str(getattr(adapter, "name", "") or "") or "the adapter"
        current = cls._same_nic(adapter, pool)
        if current is None:
            return f"{name} is no longer present"
        if not bool(getattr(current, "is_up", True)):
            return f"{name} went down"
        if server_ip not in [ip for ip, _p in _adapter_ipv4s(current)]:
            return f"{name} no longer has {server_ip}"
        return None

    def _stop_for_network(self, problem: str, gone: bool = False) -> None:
        """Stop because of *problem*.  An adapter that is *gone* (a USB NIC pulled out) is not put
        back on DHCP: its temporary address was set with ``store=active``, which went away with the
        interface, so there is nothing to restore (netsh would only fail) and no start-time restore
        is left behind for it.  "Gone" is confirmed first by a fresh enumeration that succeeds and
        lacks the adapter; when that enumeration fails, or lists the adapter again, the NIC is
        restored as usual (and when netsh cannot reach it the record stays for the next start)."""
        with self._lock:
            if not self._running:
                return
            self._error = f"stopped: {problem}"
            adapter = self._adapter
            name = str(getattr(adapter, "name", "") or "") or "The adapter"
            changed = self._nic_changed
        if gone and changed:
            _invalidate_adapter_cache()
            fresh = _get_adapters(self._adapters_fn)
            if not fresh or self._same_nic(adapter, fresh) is not None:
                log.warning("DHCP server: %s is listed again (or the adapters could not be read); restoring it as usual", name)
                gone = False
        self._db_event("warning", f"DHCP server stopped: {problem}")
        try:
            self.stop(restore_nic=not gone)
            if gone and changed:
                try:
                    self._nic.clear_record()
                except Exception:  # noqa: BLE001
                    log.exception("could not clear %s", NIC_CHANGED_META)
                with self._lock:
                    self._nic_changed = False
                    self._warning = f"{name} was removed; its temporary address went with it"
                self._publish_state()
        except Exception:  # noqa: BLE001
            log.exception("stopping the DHCP server after a network change failed")

    def _load_leases(self) -> None:
        if self._db is None:
            return
        try:
            rows = self._db.list_dhcp_leases(include_expired=True)
        except Exception:  # noqa: BLE001
            log.exception("could not load DHCP leases")
            return
        n = self._table.load(rows, self._clock())
        if n:
            log.info("loaded %d DHCP lease record(s)", n)

    # -- scanning -----------------------------------------------------------------------
    def _do_scan(self, candidates: List[Any], wait_s: float, own_ips: Set[str]) -> Dict[str, Any]:
        # a per-scan cancel event: stop() sets it to abort an in-flight scan, but a scan that
        # starts *after* a stop() must listen for the full window (the lifecycle event stays set
        # while the server is off)
        cancel = threading.Event()
        with self._lock:
            self._scan_cancel = cancel
        try:
            scan = scan_for_servers(candidates, wait_s, socket_factory=self._socket_factory, own_ips=own_ips,
                                    clock=self._clock, existing_socket_for=self.existing_socket_for,
                                    register_probe=self.register_probe, cancel=cancel)
        finally:
            with self._lock:
                if self._scan_cancel is cancel:
                    self._scan_cancel = None
        with self._lock:
            self._last_scan = scan
            # a refused start leaves a conflict warning behind; a clean scan while off retires it
            if not self._running and not scan["servers"] and (self._warning or "").startswith(CONFLICT_WARNING):
                self._warning = None
        self._publish("dhcp.scan", scan)
        if scan["servers"]:
            log.warning("DHCP scan found %d other server(s): %s", len(scan["servers"]),
                        ", ".join(f"{s['server_ip']} on {s['adapter']}" for s in scan["servers"]))
        return scan

    def scan(self, wait_s: Optional[float] = None) -> Dict[str, Any]:
        """Probe every up adapter for other DHCP servers (works whether running or not).

        Serialised with ``start()``/``stop()`` on the operation lock: a manual check that
        arrives while a start is running waits for it (two scans on one NIC would fight over
        ``(nic_ip, 67)`` and the start's own scan would come back blind).  The firewall rule
        is ensured first (idempotent: a ``show rule`` when it already exists) so the OFFERs
        the probes provoke can reach us on the installed service."""
        wait = float(wait_s) if wait_s is not None else float(self._settings()["scan_wait_s"])
        wait = max(MIN_SCAN_WAIT_S, min(30.0, wait))
        with self._op_lock:
            ok, err = self._ensure_firewall()
            if not ok:
                log.warning("Windows Firewall rule could not be created (%s); the scan may miss other servers", err)
            own_ips, own_macs = self._own_addresses()
            with self._lock:
                if self._running:
                    # a NIC that appeared after start (a USB adapter) is probed too, and its probe
                    # echoes back into our wildcard socket: it must be recognised as our own
                    self._own_ips = self._own_ips | own_ips
                    self._own_macs = self._own_macs | own_macs
                    own_ips = set(self._own_ips)
            return self._do_scan(self._candidates(), wait, own_ips)

    # -- receive loop -------------------------------------------------------------------
    def _wait_readable(self, socks: List[Any], timeout: float, stop_evt: Optional[threading.Event] = None) -> List[Any]:
        """``select()`` for real sockets; fakes may offer ``readable(timeout) -> bool``."""
        if socks and all(hasattr(s, "readable") for s in socks):
            per = max(0.01, timeout / len(socks))
            return [s for s in socks if s.readable(per)]
        try:
            ready, _w, _x = select.select(socks, [], [], timeout)
            return list(ready)
        except (OSError, ValueError, TypeError):
            (stop_evt or self._stop_evt).wait(min(timeout, 0.2))
            return []

    def _rx_loop(self, stop_evt: Optional[threading.Event] = None) -> None:
        """The receive thread.  *stop_evt* is the lifecycle event of the run that started it:
        a thread that outlives ``stop()``'s join keeps seeing its own (set) event even after
        the next ``start()`` made a new one, so it can never serve the new run."""
        stop_evt = stop_evt or self._stop_evt
        log.debug("dhcp rx loop running on port %d", self._bound_port)
        while not stop_evt.is_set():
            try:
                with self._lock:
                    socks = [s for s in (self._sock_specific, self._sock_wild) if s is not None]
                if not socks:
                    break
                for s in self._wait_readable(socks, RX_TICK_S, stop_evt):
                    try:
                        raw, src = s.recvfrom(2048)
                    except (socket.timeout, TimeoutError, BlockingIOError, InterruptedError):
                        continue
                    except OSError:
                        if stop_evt.is_set():
                            break
                        # WSAECONNRESET on a UDP socket (an ICMP port-unreachable for an
                        # earlier send) is harmless; anything else is logged and we go on
                        log.debug("recvfrom failed", exc_info=True)
                        continue
                    if stop_evt.is_set():
                        break                 # woke up after stop(): this run is over
                    self.handle(raw, src, sock=s)
                if stop_evt.is_set():
                    break
                self._tick()
            except Exception:  # noqa: BLE001 - the receive thread must never die
                log.exception("dhcp rx loop error")
                stop_evt.wait(0.1)

    def _tick(self) -> None:
        now = self._clock()
        with self._lock:
            changed = self._table.expire(now) + self._table.drain_dropped()
            for k, ts in list(self._recent.items()):
                if now - ts > DEDUPE_WINDOW_S * 4:
                    self._recent.pop(k, None)
        self._publish_leases(changed)

    # -- protocol -----------------------------------------------------------------------
    def _lease_time(self, req: Packet) -> int:
        limit = int(self._settings()["lease_s"])
        want = req.lease_request()
        if want is None:
            return limit
        return max(MIN_LEASE_S, min(limit, int(want)))

    def _net(self) -> Optional[ipaddress.IPv4Network]:
        if not self._server_ip or self._prefix is None:
            return None
        return ipaddress.IPv4Interface(f"{self._server_ip}/{self._prefix}").network

    def _full_opts(self, lease_s: int) -> List[Tuple[int, bytes]]:
        """OFFER/ACK options: 54, 51, 58 (T1 = 1/2), 59 (T2 = 7/8), 1, 3 (= us), 28. No 6, ever."""
        sid = _packed(self._server_ip)
        net = self._net()
        mask = net.netmask.packed if net is not None else _packed("255.255.255.0")
        bcast = net.broadcast_address.packed if net is not None else _packed(BROADCAST_IP)
        return [(54, sid), (51, _u32(lease_s)), (58, _u32(lease_s // 2)), (59, _u32(lease_s * 7 // 8)),
                (1, mask), (3, sid), (28, bcast)]

    def _send(self, req: Packet, src: Tuple[str, int], mtype: int, yiaddr: Optional[str], opts: List[Tuple[int, bytes]]) -> bool:
        sock = self._sock_specific or self._sock_wild
        if sock is None or not self._server_ip:
            return False
        data = encode(req, mtype, yiaddr, opts, self._server_ip)
        dest = reply_dest(req, src, mtype)
        try:
            sock.sendto(data, dest)
            log.debug("dhcp %s -> %s:%d (%s, xid %08x)", MSG_NAMES.get(mtype, mtype), dest[0], dest[1], yiaddr, req.xid)
            return True
        except OSError as exc:
            log.warning("dhcp %s to %s failed: %s", MSG_NAMES.get(mtype, mtype), dest, exc)
            return False

    def _nak(self, req: Packet, src: Tuple[str, int], why: str) -> None:
        self._send(req, src, NAK, None, [(54, _packed(self._server_ip)), (56, why.encode("ascii", "replace")[:255])])

    def _neighbour(self, ip: str, if_index: Any) -> Optional[Tuple[str, Optional[str]]]:
        """``(MAC, state)`` of *ip* in this PC's neighbour table on the served adapter (the seam, else
        ``tnt.arp.neighbour``, imported lazily); ``None`` when there is no row or the table cannot be read."""
        try:
            fn = self._neighbour_fn
            if fn is None:
                fn = importlib.import_module("tnt.arp").neighbour
            return fn(ip, if_index)
        except Exception:  # noqa: BLE001 - a table that cannot be read leaves the ping's verdict
            log.debug("neighbour lookup for %s failed", ip, exc_info=True)
            return None

    def _ping_fn(self, client_mac: Optional[str] = None) -> Optional[Callable[[str], bool]]:
        """The in-use check :meth:`LeaseTable.pick_address` runs before an offer: a ping, and when the echo is not
        answered, the neighbour table of the served adapter.  Windows resolves the address with ARP before it sends the
        echo, so a host that drops ICMP but answers ARP (a PC on the Public firewall profile) is left behind as a
        ``reachable`` row; that counts as "in use" unless the row is the requesting client's own MAC (a returning
        client may have its old address back).  The lookup is a table read, so the check still takes one ping timeout
        at most per candidate."""
        if not self._settings()["ping_check"] or self.pinger is None:
            return None
        if_index = getattr(self._adapter, "index", None)
        own = _normalize_mac(client_mac)

        def check(ip: str) -> bool:
            r = self.pinger.ping(ip, size=32, timeout_ms=PING_CHECK_TIMEOUT_MS, ttl=128)
            if getattr(r, "ok", False):
                return True
            row = self._neighbour(ip, if_index)
            if not row or row[1] not in IN_USE_NEIGHBOUR_STATES:
                return False
            mac = _normalize_mac(row[0])
            if mac is None or mac == own:
                return False
            log.info("DHCP: %s did not answer the ping but %s answered ARP for it", ip, mac)
            return True

        return check

    def handle(self, raw: bytes, src: Tuple[str, int], now: Optional[float] = None, sock: Any = None) -> Optional[int]:
        """Process one datagram (RFC 2131 §4.3).  Returns the reply type sent (or ``None``).

        Pure enough to drive from tests with bytes + a source address.  *sock* is the socket
        the datagram arrived on: a request that came in on the wildcard socket is served only
        when it can belong to the served LAN (:meth:`_wildcard_accepts`); ``None`` (tests)
        counts as the NIC-bound socket.  Replies always leave through the specific socket.
        Never raises.
        """
        try:
            return self._handle(raw, src, self._clock() if now is None else float(now), sock)
        except Exception:  # noqa: BLE001
            log.exception("dhcp packet handling failed")
            return None

    def _wildcard_accepts(self, src_ip: str, specific_seen: bool) -> bool:
        """May a BOOTREQUEST that arrived on the ``0.0.0.0:67`` socket be served?

        That socket receives broadcasts from *every* interface, so a request from a client on
        another NIC's LAN (the office Wi-Fi while the bench NIC is served) looks exactly like a
        bench client.  A source outside the served subnet is never ours (RENEW/REBIND/INFORM/
        RELEASE carry the client's address).  A 0.0.0.0 source (DISCOVER, SELECTING,
        INIT-REBOOT) cannot be placed, so it is served only until the NIC-bound socket has
        proven that it delivers this LAN's broadcasts (on Windows 11 it does); from then on
        the wildcard socket is only a safety net and such requests are dropped.
        """
        if src_ip and src_ip != "0.0.0.0":
            net = self._net()
            if net is None:
                return True
            try:
                return ipaddress.IPv4Address(src_ip) in net
            except ValueError:
                return False
        return not specific_seen

    def _handle(self, raw: bytes, src: Tuple[str, int], now: float, sock: Any = None) -> Optional[int]:
        pkt = decode(raw, allow_reply=True)
        if pkt is None:
            return None
        src_ip = str(src[0]) if src else "0.0.0.0"
        src_port = int(src[1]) if src and len(src) > 1 else 0
        if pkt.op == BOOTREPLY:
            # OFFERs for a registered scan probe are handed to the scanner; other replies
            # (another server answering a client) are none of our business
            with self._lock:
                cb = self._probes.get(pkt.xid)
            if cb is not None and pkt.msg_type == OFFER:
                try:
                    cb(pkt, (src_ip, src_port))
                except Exception:  # noqa: BLE001
                    log.debug("probe callback failed", exc_info=True)
            return None
        if pkt.msg_type is None:
            return None
        with self._lock:
            on_wildcard = sock is not None and self._sock_wild is not None and sock is self._sock_wild
            if sock is not None and self._sock_specific is not None and sock is self._sock_specific:
                self._specific_seen = True
            specific_seen = self._specific_seen
            own_probe = pkt.xid in self._probes
        # our own broadcasts echo back to us (src = our IP:67), our own scan DISCOVERs carry
        # our MAC or a registered probe xid (a NIC that appeared after start): never answer
        # ourselves
        if (src_ip in self._own_ips and src_port == self._bound_port) or pkt.mac in self._own_macs or own_probe:
            return None
        if on_wildcard and not self._wildcard_accepts(src_ip, specific_seen):
            log.debug("dhcp: ignoring %s from %s on the wildcard socket (not the served LAN)", MSG_NAMES.get(pkt.msg_type), src_ip)
            return None
        with self._lock:
            if not self._running and self._server_ip is None:
                return None
            # the same datagram delivered to both sockets: byte-identical, so a hash of the
            # payload joins the key (a retransmission differs at least in ``secs``)
            key = (pkt.xid, pkt.mac, pkt.msg_type, hash(bytes(raw)))
            seen = self._recent.get(key)
            if seen is not None and now - seen < DEDUPE_WINDOW_S and now >= seen:
                return None
            self._recent[key] = now
            changed = self._table.expire(now)
            handler = {DISCOVER: self._on_discover, REQUEST: self._on_request, DECLINE: self._on_decline,
                       RELEASE: self._on_release, INFORM: self._on_inform}.get(pkt.msg_type)
            if handler is None:
                sent, lease = None, None
            else:
                sent, lease = handler(pkt, (src_ip, src_port), now)
            changed += self._table.drain_dropped()
        # what expired or was dropped on the way first, then the record this packet touched
        self._publish_leases(changed)
        if lease is not None:
            self._publish_lease(lease)
        return sent

    def _on_discover(self, pkt: Packet, src: Tuple[str, int], now: float) -> Tuple[Optional[int], Optional[Lease]]:
        key = pkt.client_id()
        ip = self._table.pick_address(key, pkt.requested_ip(), now, self._ping_fn(pkt.mac))
        if ip is None:
            log.warning("DHCP: no free address for %s (pool %s-%s)", pkt.mac, *(self._pool or ("?", "?")))
            return None, None
        lease = self._table.offer(key, pkt.mac, ip, now, pkt.hostname(), pkt.client_id_hex(), pkt.xid)
        self._send(pkt, src, OFFER, ip, self._full_opts(self._lease_time(pkt)))
        log.info("DHCP OFFER %s to %s%s", ip, pkt.mac, f" ({lease.hostname})" if lease.hostname else "")
        return OFFER, lease

    def _on_request(self, pkt: Packet, src: Tuple[str, int], now: float) -> Tuple[Optional[int], Optional[Lease]]:
        key = pkt.client_id()
        sid, rip, ci = pkt.server_id(), pkt.requested_ip(), pkt.ciaddr
        lease = self._table.get(key)
        net = self._net()
        if sid:                                   # SELECTING
            if sid != self._server_ip:
                # the client picked another server: free our offer, stay silent (§4.3.2); the
                # dropped record is returned so the page removes its row
                return None, self._table.drop_offer(key)
            # like INIT-REBOOT, never re-bind an address under quarantine: a REQUEST that
            # arrives after the client's own DECLINE (a delayed duplicate, a stack that
            # re-REQUESTs before it re-DISCOVERs) gets a NAK and starts over
            ok = (lease is not None and rip is not None and rip == lease.ip and lease.state != "declined"
                  and self._table.bad.get(rip, 0.0) <= now and not self._table._holder_blocks(rip, key, now))
            if not ok:
                self._nak(pkt, src, "address not offered to you")
                return NAK, None
        elif rip:                                 # INIT-REBOOT
            if net is not None and ipaddress.IPv4Address(rip) not in net:
                self._nak(pkt, src, "wrong subnet")
                return NAK, None
            if lease is None:
                return None, None                 # "MUST remain silent" (another server's client)
            ok = rip == lease.ip and not self._table._holder_blocks(rip, key, now) and self._table.bad.get(rip, 0.0) <= now
            if not ok:
                self._nak(pkt, src, "address not yours")
                return NAK, None
        elif ci:                                  # RENEWING (unicast) / REBINDING (broadcast)
            if lease is None:
                # no record: silence for addresses we do not manage; for one of *our* pool
                # addresses be authoritative (RFC 2131 4.3.2 allows either) so a stale client
                # cannot keep an address we may have handed to someone else
                if ci in self._table._pool_set:
                    self._nak(pkt, src, "lease not known")
                    return NAK, None
                return None, None
            ok = ci == lease.ip and not self._table._holder_blocks(ci, key, now)
            if not ok:
                self._nak(pkt, src, "lease not valid")
                return NAK, None
        else:
            return None, None
        lease_s = self._lease_time(pkt)
        was_bound = lease is not None and lease.state == "bound"
        lease = self._table.bind(key, lease_s, now, pkt.hostname(), pkt.client_id_hex())
        if lease is None:
            return None, None
        self._send(pkt, src, ACK, lease.ip, self._full_opts(lease_s))
        if not was_bound:
            log.info("DHCP ACK %s to %s%s (lease %ss)", lease.ip, pkt.mac, f" ({lease.hostname})" if lease.hostname else "", lease_s)
            self._db_event("info", f"DHCP lease {lease.ip} -> {pkt.mac}" + (f" ({lease.hostname})" if lease.hostname else ""))
        self._schedule_probe(lease, now, force=not was_bound)
        return ACK, lease

    def _on_decline(self, pkt: Packet, src: Tuple[str, int], now: float) -> Tuple[Optional[int], Optional[Lease]]:
        rip = pkt.requested_ip()
        if pkt.server_id() != self._server_ip or not rip:
            return None, None
        key = pkt.client_id()
        lease = self._table.get(key)
        ours = lease is not None and lease.ip == rip
        if not ours and (rip not in self._table._pool_set or self._table._holder_blocks(rip, key, now)):
            # RFC 2131 §4.3.3 / ISC: a DECLINE counts only for the address this client was given.
            # A stray one (a misbehaving device, another server's client on a shared wire) must
            # not quarantine an address that is bound to somebody else -- its holder would be
            # NAKed "address not yours" at its next reboot.
            log.info("DHCP DECLINE for %s by %s ignored: not that client's address", rip, pkt.mac)
            return None, None
        lease = self._table.decline(key, rip, now)
        log.warning("DHCP DECLINE: %s says %s is already in use; holding it for %d s", pkt.mac, rip, DECLINE_HOLD_S)
        self._db_event("warning", f"DHCP: {pkt.mac} declined {rip} (address already in use on the network)")
        return None, lease

    def _on_release(self, pkt: Packet, src: Tuple[str, int], now: float) -> Tuple[Optional[int], Optional[Lease]]:
        if pkt.server_id() not in (None, self._server_ip):
            return None, None
        lease = self._table.get(pkt.client_id())
        if lease is None or not pkt.ciaddr or lease.ip != pkt.ciaddr:
            return None, None
        lease = self._table.release(pkt.client_id(), now)
        log.info("DHCP RELEASE %s by %s", pkt.ciaddr, pkt.mac)
        return None, lease

    def _on_inform(self, pkt: Packet, src: Tuple[str, int], now: float) -> Tuple[Optional[int], Optional[Lease]]:
        if not pkt.ciaddr:
            return None, None
        net = self._net()
        sid = _packed(self._server_ip)
        mask = net.netmask.packed if net is not None else _packed("255.255.255.0")
        bcast = net.broadcast_address.packed if net is not None else _packed(BROADCAST_IP)
        self._send(pkt, src, ACK, None, [(54, sid), (1, mask), (3, sid), (28, bcast)])
        return ACK, None

    # -- client probing -----------------------------------------------------------------
    def _schedule_probe(self, lease: Lease, now: float, force: bool = False) -> None:
        if lease.key in self._queued:
            return
        if not force and lease.probed_ts is not None and now - lease.probed_ts < REPROBE_AFTER_S:
            return
        self._queued.add(lease.key)
        self._probe_q.put(lease.key)

    def _probe_loop(self, stop_evt: Optional[threading.Event] = None) -> None:
        """The client-probe thread (see :meth:`_rx_loop` for *stop_evt*)."""
        stop_evt = stop_evt or self._stop_evt
        probe_q = self._probe_q
        while not stop_evt.is_set():
            try:
                key = probe_q.get(timeout=0.5)
            except queue.Empty:
                continue
            again = False
            try:
                again = bool(self._probe_one(key, stop_evt))
            except Exception:  # noqa: BLE001 - the probe thread must never die
                log.exception("dhcp client probe failed")
            finally:
                with self._lock:
                    self._queued.discard(key)
            if again and not stop_evt.is_set():
                # the address moved while we were probing the old one: probe the new one
                with self._lock:
                    lease = self._table.get(key)
                    if lease is not None and lease.state == "bound":
                        self._schedule_probe(lease, self._clock(), force=True)

    def _probe_one(self, key: bytes, stop_evt: Optional[threading.Event] = None) -> bool:
        """Probe the client behind *key*.  Returns True when the lease's address changed while
        the probe ran (the result was discarded and the caller should queue it again)."""
        stop_evt = stop_evt or self._stop_evt
        # give the device a moment to bring its stack up before knocking on its ports
        if stop_evt.wait(PROBE_DELAY_S):
            return False
        with self._lock:
            lease = self._table.get(key)
            if lease is None or lease.state != "bound":
                return False
            lease.probing = True
            ip, mac = lease.ip, lease.mac
        self._publish_lease(lease)
        try:
            ports = self._config.get("discovery.ports", None)
        except Exception:  # noqa: BLE001
            ports = None
        if not ports:
            ports = [22, 80, 443, 554, 5060, 7001, 8000, 8080, 8443]
        try:
            timeout_ms = int(self._config.get("discovery.ping_timeout_ms", 1000) or 1000)
        except Exception:  # noqa: BLE001
            timeout_ms = 1000
        result = probe_host(ip, ports, self.pinger, ping_timeout_ms=timeout_ms, port_timeout_s=0.6,
                            tcp_connect=self._tcp_connect, resolver=self._resolver, vendor_fn=self._vendor_fn, mac=mac)
        if stop_evt.is_set():
            return False
        with self._lock:
            # the result belongs to *ip*: a lease that moved meanwhile (DECLINE + re-DISCOVER
            # during the sweep) must not wear the old address's ports; it is probed again
            lease = self._table.update_probe(key, result, self._clock(), ip=ip)
            moved = lease is None and self._table.get(key) is not None
            if moved:
                lease = self._table.get(key)
        if lease is None:
            return False
        if moved:
            log.info("DHCP client %s moved from %s to %s during its probe; probing again", mac, ip, lease.ip)
            self._publish_lease(lease)
            return True
        log.info("DHCP client %s (%s) probed: ping %s, open ports %s", ip, mac,
                 "ok" if result.get("ping_ok") else "no reply", result.get("open_ports") or "none")
        self._publish_lease(lease)
        return False

    # -- views --------------------------------------------------------------------------
    @staticmethod
    def _count_rows(rows: Iterable[Dict[str, Any]]) -> Dict[str, int]:
        """``counts`` for a list of LEASE DICTs (the off-line twin of ``LeaseTable.counts``)."""
        rows = list(rows)
        return {"bound": sum(1 for r in rows if r.get("state") == "bound"),
                "offered": sum(1 for r in rows if r.get("state") == "offered"), "total": len(rows)}

    def leases(self) -> List[Dict[str, Any]]:
        """The LEASE DICT rows.  While the server is off nothing ticks the table, so leases
        are aged here first: a bound lease whose time ran out (yesterday's camera after a
        reboot) shows as ``expired``, and never disagrees with ``counts``."""
        now = self._clock()
        with self._lock:
            if self._running:
                return self._table.to_rows()
            if self._table.leases:
                # the last run's table is still here (stop() keeps it): age it the way the
                # receive loop's tick would have
                self._table.expire(now)
                self._table.drain_dropped()
                return self._table.to_rows()
        if self._db is None:
            return []
        try:
            self._db.expire_dhcp_leases(now)
            rows = self._db.list_dhcp_leases(include_expired=True)
        except Exception:  # noqa: BLE001
            log.debug("could not list DHCP leases", exc_info=True)
            return []
        out = []
        for r in rows:
            out.append({"ip": r.get("ip"), "mac": r.get("mac"), "hostname": r.get("hostname"), "vendor": r.get("vendor"),
                        "ping_ok": r.get("ping_ok"), "rtt_ms": r.get("rtt_ms"), "open_ports": list(r.get("open_ports") or []),
                        "client_id": r.get("client_id"), "state": "expired" if r.get("state") == "offered" else r.get("state"),
                        "first_ts": r.get("first_ts"), "last_ts": r.get("last_ts"), "expires_ts": r.get("expires_ts"),
                        "probed_ts": r.get("probed_ts"), "probing": False})
        return out

    def forget_lease(self, mac: str) -> bool:
        norm = _normalize_mac(mac)
        if not norm:
            raise ValueError("not a MAC address")
        with self._lock:
            gone = self._table.forget(norm)
        if not gone and self._db is not None:
            try:
                gone = bool(self._db.delete_dhcp_lease(norm))
            except Exception:  # noqa: BLE001
                gone = False
        if gone:
            self._publish("dhcp.lease", {"lease": {"mac": norm, "state": "forgotten"}})
        return gone

    @staticmethod
    def _internet_nic(candidates: List[Any]) -> Any:
        """The adapter the PC's default route leaves through (``tnt.netinfo.get_internet_nic``
        over *candidates*), or ``None`` when unknown.  Never raises."""
        try:
            netinfo = importlib.import_module("tnt.netinfo")
            return netinfo.get_internet_nic(candidates)
        except Exception:  # noqa: BLE001
            log.debug("get_internet_nic failed", exc_info=True)
            return None

    @staticmethod
    def _same_adapter(a: Any, b: Any) -> bool:
        """Same NIC by ifindex (when both have one), else by name."""
        if a is None or b is None:
            return False
        if a is b:
            return True
        ia, ib = getattr(a, "index", None), getattr(b, "index", None)
        if ia and ib:
            try:
                return int(ia) == int(ib)
            except (TypeError, ValueError):
                pass
        na, nb = str(getattr(a, "name", "") or ""), str(getattr(b, "name", "") or "")
        return bool(na) and na == nb

    def _adapter_dict(self, adapter: Any, settings: Dict[str, Any], internet: Any = None) -> Dict[str, Any]:
        ip, prefix = _adapter_primary(adapter)
        with self._lock:
            changed = self._nic_changed and self._adapter is not None and getattr(self._adapter, "name", None) == getattr(adapter, "name", None)
            if changed and self._server_ip:
                ip, prefix = self._server_ip, self._prefix
        return {
            "name": str(getattr(adapter, "name", "")), "index": getattr(adapter, "index", None),
            "mac": _normalize_mac(getattr(adapter, "mac", None)), "ip": ip, "prefix": prefix,
            "mask": _mask_text(prefix) if prefix is not None else None,
            "dhcp_enabled": bool(getattr(adapter, "dhcp_enabled", False)), "gateway": getattr(adapter, "ipv4_gateway", None),
            "is_physical": bool(getattr(adapter, "is_physical", False)), "type_name": str(getattr(adapter, "type_name", "") or ""),
            "is_internet": self._same_adapter(adapter, internet),
            "will_change": bool(getattr(adapter, "dhcp_enabled", False)) and not changed, "changed": changed,
            "static_ip": settings["static_ip"], "static_prefix": int(settings["static_prefix"]),
        }

    def status(self) -> Dict[str, Any]:
        settings = self._settings()
        candidates = self._candidates()
        internet = self._internet_nic(candidates)
        with self._lock:
            running = self._running
            adapter = self._adapter if running else None
            server_ip, prefix = (self._server_ip, self._prefix) if running else (None, None)
            pool, auto = (self._pool, self._pool_auto) if running else (None, True)
            error, warning, since = self._error, self._warning, self._since_ts
            scan, firewall = self._last_scan, dict(self._firewall)
            clients = self._table.to_rows() if running else None
            counts = self._table.counts() if running else None
        if adapter is None:
            try:
                adapter = self._pick_adapter(settings["adapter"], candidates)
            except ValueError as exc:
                adapter = None
                if error is None and not running:
                    error = None
                    warning = warning or str(exc)
        if adapter is not None and server_ip is None:
            try:
                server_ip, prefix, _wc = self._plan(adapter, settings)
                pool, auto = self._resolve_pool(adapter, server_ip, prefix, settings)
            except ValueError as exc:
                pool, auto = None, not (settings["pool_start"] and settings["pool_end"])
                warning = warning or f"pool: {exc}"
        if clients is None:
            clients = self.leases()
            counts = self._count_rows(clients)
        return {
            "available": True, "running": running, "since_ts": since, "error": error, "warning": warning,
            "adapter": self._adapter_dict(adapter, settings, internet) if adapter is not None else None,
            "adapters": [
                {"name": str(getattr(a, "name", "")), "index": getattr(a, "index", None), "ip": _adapter_primary(a)[0],
                 "prefix": _adapter_primary(a)[1], "dhcp_enabled": bool(getattr(a, "dhcp_enabled", False)),
                 "is_physical": bool(getattr(a, "is_physical", False)), "type_name": str(getattr(a, "type_name", "") or ""),
                 "is_internet": self._same_adapter(a, internet), "status": str(getattr(a, "status", "up") or "up")}
                for a in candidates
            ],
            "server_ip": server_ip,
            "pool": {"start": pool[0] if pool else None, "end": pool[1] if pool else None,
                     "size": (int(ipaddress.IPv4Address(pool[1])) - int(ipaddress.IPv4Address(pool[0])) + 1) if pool else int(settings["pool_size"]),
                     "auto": bool(auto)},
            "lease_s": int(settings["lease_s"]), "gateway": server_ip, "dns": [], "ping_check": bool(settings["ping_check"]),
            "clients": clients, "counts": counts, "scan": scan, "firewall": firewall,
            "settings": settings,
        }

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            running = self._running
            adapter = str(getattr(self._adapter, "name", "")) if (running and self._adapter is not None) else None
            server_ip = self._server_ip if running else None
            pool = self._pool if running else None
            counts = self._table.counts() if running else None
            since, error = self._since_ts, self._error
        if counts is None:
            counts = self._count_rows(self.leases())        # aged first: see leases()
        return {
            "available": True, "running": running, "adapter": adapter, "server_ip": server_ip,
            "pool": {"start": pool[0], "end": pool[1],
                     "size": int(ipaddress.IPv4Address(pool[1])) - int(ipaddress.IPv4Address(pool[0])) + 1} if pool else None,
            "bound": counts["bound"], "offered": counts["offered"], "since_ts": since, "error": error,
        }

    def update_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and persist ``dhcp.*`` settings (adapter, pool_start, pool_end, pool_size,
        lease_s, ping_check); a pool change is applied live.  ``ValueError`` on bad input."""
        if not isinstance(patch, dict):
            raise ValueError("settings patch must be an object")
        settings = self._settings()
        new: Dict[str, Any] = {}
        if "adapter" in patch:
            name = str(patch.get("adapter") or "").strip()
            if name and name not in [str(getattr(a, "name", "")) for a in self._candidates()]:
                raise ValueError(f"adapter '{_short(name, 40)}' is not up or has no IPv4 address")
            new["adapter"] = name
        if "pool_size" in patch:
            try:
                size = int(float(patch.get("pool_size")))
            except (TypeError, ValueError, OverflowError):
                raise ValueError("pool_size must be a number") from None
            if not 1 <= size <= MAX_POOL:
                raise ValueError(f"pool_size must be between 1 and {MAX_POOL}")
            new["pool_size"] = size
        if "lease_s" in patch:
            try:
                lease_s = int(float(patch.get("lease_s")))
            except (TypeError, ValueError, OverflowError):
                raise ValueError("lease_s must be a number") from None
            if not MIN_LEASE_S <= lease_s <= MAX_LEASE_S:
                raise ValueError(f"lease_s must be between {MIN_LEASE_S} and {MAX_LEASE_S} seconds")
            new["lease_s"] = lease_s
        if "ping_check" in patch:
            v = patch.get("ping_check")
            if isinstance(v, str):
                v = v.strip().lower() in ("1", "true", "yes", "on")
            new["ping_check"] = bool(v)
        if "pool_start" in patch or "pool_end" in patch:
            start = str(patch.get("pool_start", settings["pool_start"]) or "").strip()
            end = str(patch.get("pool_end", settings["pool_end"]) or "").strip()
            if bool(start) != bool(end):
                raise ValueError("give both pool_start and pool_end, or neither for an automatic pool")
            if start:
                merged = dict(settings, **new)
                adapter = self._pick_adapter(merged["adapter"], self._candidates())
                server_ip, prefix, _wc = self._plan(adapter, merged)
                gateway = getattr(adapter, "ipv4_gateway", None)
                start, end = validate_pool(start, end, server_ip, prefix, gateway, [ip for ip, _p in _adapter_ipv4s(adapter)])
            new["pool_start"], new["pool_end"] = start, end
        if new:
            try:
                self._config.update({"dhcp": new})
            except ValueError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError(f"settings could not be saved: {exc}") from exc
            with self._lock:
                if self._running and self._adapter is not None and self._server_ip and self._prefix is not None:
                    try:
                        pool, auto = self._resolve_pool(self._adapter, self._server_ip, self._prefix, self._settings())
                        if pool != self._pool:
                            self._table.set_pool(*pool)
                            self._pool, self._pool_auto = pool, auto
                            log.info("DHCP pool changed live to %s-%s", *pool)
                    except ValueError as exc:
                        self._warning = f"pool: {exc}"
            self._publish_state()
        return self.status()
