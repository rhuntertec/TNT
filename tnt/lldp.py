"""LLDP and CDP neighbour decoding for the switch-port lookup ("which switch port am I on", ARCHITECTURE §3.24).

Original code written from IEEE 802.1AB (LLDP and the IEEE 802.1 organisationally specific TLVs), IEEE 802.3 clause 79
(the IEEE 802.3 TLVs: MAC/PHY configuration/status and Power via MDI), ANSI/TIA-1057 (LLDP-MED network policy and
extended power via MDI) and RFC 4836 / IANA-MAU-MIB (MAU type names). CDP has no published standard; the frame and TLV
layouts used below are protocol facts. Every function is pure: nothing here opens a socket, reads a file or logs.

Frames (:func:`classify_frame`)
-------------------------------
A frame (Ethernet, no FCS) whose source MAC (bytes 6-11) equals ``own_mac`` is never a neighbour: Windows' own LLDP
agent sends from the adapter, and Packet Monitor filters match both directions. Up to two 802.1Q / 802.1ad tags
(0x8100 / 0x88A8) are skipped. Ethertype 0x88CC is LLDP. CDP goes to ``01:00:0C:CC:CC:CC`` as an 802.3 frame (a length
of at most 1500 where the ethertype would be) with LLC ``AA AA 03``, OUI ``00 00 0C`` and protocol id 0x2000; the other
Cisco protocols on that address (VTP, DTP, PAgP, UDLD, ...) use other ids and are ignored.

Strings
-------
Device text is decoded as UTF-8 with ``errors="replace"``, control and format characters (Unicode categories Cc and
Cf) are removed, surrounding white space is stripped and the result is capped at :data:`MAX_TEXT` characters; empty
text is None. MACs are ``AA:BB:CC:DD:EE:FF`` (uppercase, as :func:`tnt.oui.normalize_mac` writes them).

LLDP (:func:`parse_lldp`, the LLDPDU after the ethertype)
--------------------------------------------------------
TLV header: a big-endian u16 with the type in the top 7 bits and the value length in the low 9. The LLDPDU must start
with Chassis ID (1), Port ID (2) and TTL (3), in that order, else it is ignored (None). Decoding stops at End (0) or at
a TLV that runs past the data.

* Chassis ID: subtype 4 with 6 bytes is a MAC; subtype 5 is a network address (IANA family 1 + 4 bytes: dotted IPv4,
  family 2 + 16 bytes: IPv6 text); any other subtype (or a malformed one) is text, or lowercase hex when the bytes are
  not printable UTF-8.
* Port ID: subtype 3 is a MAC and subtype 4 a network address, as above; other subtypes are text.
* Port description (4), system name (5), system description (6): text.
* TTL: 0 is a shutdown LLDPDU, so :func:`parse_lldp` returns None.
* System capabilities (7): the enabled bits, or the system (supported) bits when none are enabled: 0x02 repeater,
  0x04 bridge, 0x08 wlan-ap, 0x10 router, 0x20 phone, 0x80 station.
* Management address (8): IPv4 and IPv6 only, at most :data:`MAX_MANAGEMENT_IPS`.
* IEEE 802.1 (00-80-C2) subtype 1, Port VLAN ID: ``vlan``; PVID 0 means none.
* LLDP-MED (00-12-BB) subtype 2, network policy for application type 1 (voice): on the 24-bit field after the
  application type, ``voice_vlan = (x & 0x1FFE00) >> 9`` only when the Unknown bit (0x800000) is 0, the Tagged bit
  (0x400000) is 1 and the VLAN id is 1..4094; otherwise None.
* IEEE 802.3 (00-12-0F) subtype 1, MAC/PHY: ``link = {"autoneg": bool(status & 0x02), "mau": u16, "text":
  MAU_TEXT.get(mau)}``.
* IEEE 802.3 subtype 2, Power via MDI: ``class = octet 6 - 1`` when that octet (offsets count from the start of the
  TLV value, OUI included) is 1..5, else None; ``allocated_w = u16 at offset 10 / 10`` when the value is at least 12
  octets.
* LLDP-MED subtype 4, extended power via MDI: ``allocated_w = u16 at offset 5 / 10``, used only when the IEEE 802.3
  TLV gave no allocation.

``switch_name`` is the system name, else ``chassis_id``. ``poe`` is None when both class and allocation are None.

CDP (:func:`parse_cdp`, from the 4-byte header: version, TTL, checksum)
----------------------------------------------------------------------
TLVs are a u16 type and a u16 length that includes the 4-byte TLV header. 0x0001 Device ID: ``switch_name`` (and
``chassis_id``, the device's identity for de-duplication). 0x0003 Port ID: ``port_id``. 0x0004 capabilities (u32):
0x01 router, 0x02 / 0x04 bridge, 0x08 switch, 0x10 host, 0x40 repeater, 0x80 phone. 0x0006 platform:
``switch_description``. 0x0002 / 0x0016 addresses: a u32 count, then entries of protocol type (u8), protocol length
(u8), protocol bytes, address length (u16) and address; NLPID 0xCC with 4 bytes is IPv4 and the 802.2 SNAP protocol
``AA AA 03 00 00 00 86 DD`` with 16 bytes is IPv6. 0x000a native VLAN (u16): ``vlan``. 0x000e voice VLAN reply
(u8 data + u16 VLAN): ``voice_vlan``. 0x001a power available: ``allocated_w = u32 at value offset 4 / 1000`` (mW),
class None; 0x0010 (the sender's own power draw) is ignored. VLAN 0 means none. ``ttl_s`` is the header TTL.

NEIGHBOR dict (keys in this order, :data:`NEIGHBOR_KEYS`)::

    {"protocol": "lldp"|"cdp", "switch_name": str|None, "switch_description": str|None, "vendor": str|None,
     "chassis_id": str|None, "port_id": str|None, "port_description": str|None, "vlan": int|None,
     "voice_vlan": int|None, "management_ips": [str, ...], "capabilities": [str, ...],
     "poe": {"class": int|None, "allocated_w": float|None}|None,
     "link": {"autoneg": bool, "mau": int, "text": str|None}|None, "ttl_s": int}

``vendor`` (the switch manufacturer) is left None by these pure parsers; :mod:`tnt.switchport` fills it in from the
chassis MAC's OUI.  :func:`neighbors_from_packets` runs the above over pcapng PACKET dicts (link type 1 only) or raw
frames and keeps one neighbour per ``(protocol, chassis_id, port_id)``, in first-heard order with the latest frame's
values.
"""
from __future__ import annotations

import ipaddress
import struct
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import oui

__all__ = ["NEIGHBOR_KEYS", "POE_KEYS", "LINK_KEYS", "MAU_TEXT", "MAX_TEXT", "MAX_MANAGEMENT_IPS", "classify_frame",
           "parse_lldp", "parse_cdp", "neighbors_from_packets"]

NEIGHBOR_KEYS = ("protocol", "switch_name", "switch_description", "vendor", "chassis_id", "port_id",
                 "port_description", "vlan", "voice_vlan", "management_ips", "capabilities", "poe", "link", "ttl_s")
POE_KEYS = ("class", "allocated_w")
LINK_KEYS = ("autoneg", "mau", "text")
MAX_TEXT = 200
MAX_MANAGEMENT_IPS = 4

ETHERTYPE_LLDP = 0x88CC
VLAN_TAG_TYPES = (0x8100, 0x88A8)
MAX_VLAN_TAGS = 2
MAX_8023_LENGTH = 1500
CDP_DESTINATION = b"\x01\x00\x0c\xcc\xcc\xcc"
CDP_SNAP = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"     # LLC DSAP, SSAP, control; Cisco OUI; protocol id 0x2000
LINKTYPE_ETHERNET = 1

# LLDP TLV types (IEEE 802.1AB)
_TLV_END, _TLV_CHASSIS_ID, _TLV_PORT_ID, _TLV_TTL = 0, 1, 2, 3
_TLV_PORT_DESCRIPTION, _TLV_SYSTEM_NAME, _TLV_SYSTEM_DESCRIPTION = 4, 5, 6
_TLV_CAPABILITIES, _TLV_MANAGEMENT_ADDRESS, _TLV_ORG_SPECIFIC = 7, 8, 127
_CHASSIS_MAC, _CHASSIS_NETWORK = 4, 5
_PORT_MAC, _PORT_NETWORK = 3, 4
_FAMILY_IPV4, _FAMILY_IPV6 = 1, 2                   # IANA address family numbers
_OUI_IEEE_8021 = b"\x00\x80\xc2"
_OUI_IEEE_8023 = b"\x00\x12\x0f"
_OUI_TIA_MED = b"\x00\x12\xbb"
_MED_APP_VOICE = 1

# CDP TLV types
_CDP_DEVICE_ID, _CDP_ADDRESSES, _CDP_PORT_ID, _CDP_CAPABILITIES = 0x0001, 0x0002, 0x0003, 0x0004
_CDP_PLATFORM, _CDP_NATIVE_VLAN, _CDP_VOICE_VLAN_REPLY = 0x0006, 0x000A, 0x000E
_CDP_MANAGEMENT_ADDRESSES, _CDP_POWER_AVAILABLE = 0x0016, 0x001A
_CDP_NLPID, _CDP_8022 = 1, 2
_CDP_PROTO_IPV4 = b"\xcc"
_CDP_PROTO_IPV6 = b"\xaa\xaa\x03\x00\x00\x00\x86\xdd"

LLDP_CAPABILITY_BITS = ((0x02, "repeater"), (0x04, "bridge"), (0x08, "wlan-ap"), (0x10, "router"), (0x20, "phone"),
                        (0x80, "station"))
CDP_CAPABILITY_BITS = ((0x01, "router"), (0x02, "bridge"), (0x04, "bridge"), (0x08, "switch"), (0x10, "host"),
                       (0x40, "repeater"), (0x80, "phone"))

#: Operational MAU types (IEEE 802.3 MAC/PHY TLV) by their RFC 4836 / IANA-MAU-MIB dot3MauType number. The duplex
#: word is given only where the MIB names it. Unlisted types (0 = unknown included) have no text.
MAU_TEXT: Dict[int, str] = {
    5: "10BASE-T", 10: "10BASE-T half", 11: "10BASE-T full",
    14: "100BASE-T4", 15: "100BASE-TX half", 16: "100BASE-TX full", 17: "100BASE-FX half", 18: "100BASE-FX full",
    21: "1000BASE-X half", 22: "1000BASE-X full", 23: "1000BASE-LX half", 24: "1000BASE-LX full",
    25: "1000BASE-SX half", 26: "1000BASE-SX full", 27: "1000BASE-CX half", 28: "1000BASE-CX full",
    29: "1000BASE-T half", 30: "1000BASE-T full",
    31: "10GBASE-X", 33: "10GBASE-R", 34: "10GBASE-ER", 35: "10GBASE-LR", 36: "10GBASE-SR", 41: "10GBASE-CX4",
    54: "10GBASE-T full", 55: "10GBASE-LRM",
    103: "2.5GBASE-T", 104: "5GBASE-T",
}

_DROPPED_CATEGORIES = ("Cc", "Cf")                  # control and format characters (bidi overrides included)


# --------------------------------------------------------------------------- small decoders
def _u16(data: bytes, pos: int = 0) -> int:
    return struct.unpack_from(">H", data, pos)[0]


def _text(raw: bytes) -> Optional[str]:
    """Device text: UTF-8 with replacement, control/format characters removed, stripped, capped; None when empty."""
    decoded = bytes(raw).decode("utf-8", errors="replace")
    cleaned = "".join(ch for ch in decoded if unicodedata.category(ch) not in _DROPPED_CATEGORIES).strip()
    return cleaned[:MAX_TEXT].rstrip() or None


def _text_or_hex(raw: bytes) -> Optional[str]:
    """Text when *raw* is printable UTF-8, else lowercase hex (capped like text)."""
    if not raw:
        return None
    try:
        decoded = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        decoded = None
    if decoded is not None and decoded.isprintable():
        return _text(raw)
    return bytes(raw).hex()[:MAX_TEXT]


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw)


def _network_address(raw: bytes) -> Optional[str]:
    """An IANA-family-prefixed address (``01`` + 4 bytes or ``02`` + 16 bytes) as text, else None."""
    if len(raw) == 5 and raw[0] == _FAMILY_IPV4:
        return str(ipaddress.IPv4Address(bytes(raw[1:])))
    if len(raw) == 17 and raw[0] == _FAMILY_IPV6:
        return str(ipaddress.IPv6Address(bytes(raw[1:])))
    return None


def _vlan_id(value: int) -> Optional[int]:
    return value or None


def _capabilities(bits: int, table: Tuple[Tuple[int, str], ...]) -> List[str]:
    names: List[str] = []
    for mask, name in table:
        if bits & mask and name not in names:
            names.append(name)
    return names


def _add_ip(ips: List[str], ip: Optional[str]) -> None:
    if ip is not None and ip not in ips and len(ips) < MAX_MANAGEMENT_IPS:
        ips.append(ip)


def _neighbor(protocol: str, **fields: Any) -> Dict[str, Any]:
    neighbor: Dict[str, Any] = dict.fromkeys(NEIGHBOR_KEYS)
    neighbor.update(protocol=protocol, management_ips=[], capabilities=[])
    neighbor.update(fields)
    return neighbor


# --------------------------------------------------------------------------- frames
def _own_mac_bytes(own_mac: Optional[str]) -> Optional[bytes]:
    """*own_mac* (``:`` or ``-`` separated, any case) as 6 bytes; None when it is missing or not a MAC."""
    if not own_mac:
        return None
    normalized = oui.normalize_mac(own_mac)
    return bytes.fromhex(normalized.replace(":", "")) if normalized else None


def _locate(frame: bytes, own: Optional[bytes]) -> Tuple[Optional[str], int, int]:
    """``(kind, payload_start, payload_end)`` of an LLDP or CDP frame, or ``(None, 0, 0)``."""
    size = len(frame)
    if size < 14 or (own is not None and frame[6:12] == own):
        return None, 0, 0
    pos = 12
    ethertype = _u16(frame, pos)
    tags = 0
    while ethertype in VLAN_TAG_TYPES and tags < MAX_VLAN_TAGS and size >= pos + 8:
        pos += 4
        tags += 1
        ethertype = _u16(frame, pos)
    if ethertype == ETHERTYPE_LLDP:
        return "lldp", pos + 2, size
    if (ethertype <= MAX_8023_LENGTH and frame[:6] == CDP_DESTINATION
            and frame[pos + 2:pos + 2 + len(CDP_SNAP)] == CDP_SNAP):
        # the 802.3 length covers LLC + SNAP + CDP; anything after it is Ethernet padding
        return "cdp", pos + 2 + len(CDP_SNAP), min(size, pos + 2 + ethertype)
    return None, 0, 0


def classify_frame(frame: bytes, *, own_mac: Optional[str] = None) -> Optional[str]:
    """``"lldp"``, ``"cdp"`` or None for an Ethernet frame; None also when it was sent from *own_mac*."""
    return _locate(bytes(frame), _own_mac_bytes(own_mac))[0]


# --------------------------------------------------------------------------- LLDP
def _lldp_tlvs(data: bytes) -> Iterable[Tuple[int, bytes]]:
    pos = 0
    while pos + 2 <= len(data):
        header = _u16(data, pos)
        tlv_type, length = header >> 9, header & 0x1FF
        if tlv_type == _TLV_END:
            return
        end = pos + 2 + length
        if end > len(data):
            return
        yield tlv_type, data[pos + 2:end]
        pos = end


def _chassis_id(value: bytes) -> Optional[str]:
    subtype, ident = value[0], value[1:]
    if subtype == _CHASSIS_MAC and len(ident) == 6:
        return _mac(ident)
    if subtype == _CHASSIS_NETWORK:
        address = _network_address(ident)
        if address is not None:
            return address
    return _text_or_hex(ident)


def _port_id(value: bytes) -> Optional[str]:
    subtype, ident = value[0], value[1:]
    if subtype == _PORT_MAC:
        return _mac(ident) if len(ident) == 6 else _text_or_hex(ident)
    if subtype == _PORT_NETWORK:
        address = _network_address(ident)
        return address if address is not None else _text_or_hex(ident)
    return _text(ident)


def _management_ip(value: bytes) -> Optional[str]:
    if len(value) < 3:
        return None
    address_len = value[0]                          # the family byte plus the address
    if 1 + address_len > len(value):
        return None
    return _network_address(value[1:1 + address_len])


def parse_lldp(payload: bytes) -> Optional[Dict[str, Any]]:
    """The NEIGHBOR dict of an LLDPDU (the bytes after the 0x88CC ethertype), or None (malformed or TTL 0)."""
    tlvs = list(_lldp_tlvs(bytes(payload)))
    if len(tlvs) < 3 or tuple(t for t, _ in tlvs[:3]) != (_TLV_CHASSIS_ID, _TLV_PORT_ID, _TLV_TTL):
        return None
    chassis_value, port_value, ttl_value = tlvs[0][1], tlvs[1][1], tlvs[2][1]
    if len(chassis_value) < 2 or len(port_value) < 2 or len(ttl_value) < 2:
        return None
    ttl = _u16(ttl_value)
    if ttl == 0:
        return None
    fields: Dict[str, Any] = {"chassis_id": _chassis_id(chassis_value), "port_id": _port_id(port_value), "ttl_s": ttl}
    system_name = None
    ips: List[str] = []
    capabilities: Optional[List[str]] = None
    pvid_seen = voice_seen = False
    poe_class = dot3_allocated = med_allocated = None
    for tlv_type, value in tlvs[3:]:
        if tlv_type == _TLV_PORT_DESCRIPTION and fields.get("port_description") is None:
            fields["port_description"] = _text(value)
        elif tlv_type == _TLV_SYSTEM_NAME and system_name is None:
            system_name = _text(value)
        elif tlv_type == _TLV_SYSTEM_DESCRIPTION and fields.get("switch_description") is None:
            fields["switch_description"] = _text(value)
        elif tlv_type == _TLV_CAPABILITIES and capabilities is None and len(value) >= 4:
            system_bits, enabled_bits = _u16(value, 0), _u16(value, 2)
            capabilities = _capabilities(enabled_bits or system_bits, LLDP_CAPABILITY_BITS)
        elif tlv_type == _TLV_MANAGEMENT_ADDRESS:
            _add_ip(ips, _management_ip(value))
        elif tlv_type == _TLV_ORG_SPECIFIC and len(value) >= 4:
            org, subtype = value[:3], value[3]
            if org == _OUI_IEEE_8021 and subtype == 1 and len(value) >= 6 and not pvid_seen:
                pvid_seen = True
                fields["vlan"] = _vlan_id(_u16(value, 4))
            elif org == _OUI_TIA_MED and subtype == 2 and len(value) >= 8 and value[4] == _MED_APP_VOICE \
                    and not voice_seen:
                voice_seen = True
                policy = int.from_bytes(value[5:8], "big")
                vid = (policy & 0x1FFE00) >> 9
                if not policy & 0x800000 and policy & 0x400000 and 1 <= vid <= 4094:
                    fields["voice_vlan"] = vid
            elif org == _OUI_IEEE_8023 and subtype == 1 and len(value) >= 9 and fields.get("link") is None:
                mau = _u16(value, 7)
                fields["link"] = {"autoneg": bool(value[4] & 0x02), "mau": mau, "text": MAU_TEXT.get(mau)}
            elif org == _OUI_IEEE_8023 and subtype == 2 and len(value) >= 7:
                if poe_class is None and 1 <= value[6] <= 5:
                    poe_class = value[6] - 1
                if dot3_allocated is None and len(value) >= 12:
                    dot3_allocated = _u16(value, 10) / 10
            elif org == _OUI_TIA_MED and subtype == 4 and len(value) >= 7 and med_allocated is None:
                med_allocated = _u16(value, 5) / 10
    allocated = dot3_allocated if dot3_allocated is not None else med_allocated
    fields["switch_name"] = system_name if system_name is not None else fields["chassis_id"]
    fields["management_ips"] = ips
    fields["capabilities"] = capabilities or []
    if poe_class is not None or allocated is not None:
        fields["poe"] = {"class": poe_class, "allocated_w": allocated}
    return _neighbor("lldp", **fields)


# --------------------------------------------------------------------------- CDP
def _cdp_addresses(value: bytes, ips: List[str]) -> None:
    if len(value) < 4:
        return
    count = struct.unpack_from(">I", value, 0)[0]
    pos = 4
    seen = 0
    while seen < count and pos + 2 <= len(value):
        seen += 1
        proto_type, proto_len = value[pos], value[pos + 1]
        proto = value[pos + 2:pos + 2 + proto_len]
        pos += 2 + proto_len
        if pos + 2 > len(value):
            return
        address_len = _u16(value, pos)
        address = value[pos + 2:pos + 2 + address_len]
        pos += 2 + address_len
        if pos > len(value):
            return
        if proto_type == _CDP_NLPID and proto == _CDP_PROTO_IPV4 and address_len == 4:
            _add_ip(ips, str(ipaddress.IPv4Address(address)))
        elif proto_type == _CDP_8022 and proto == _CDP_PROTO_IPV6 and address_len == 16:
            _add_ip(ips, str(ipaddress.IPv6Address(address)))


def parse_cdp(payload: bytes) -> Optional[Dict[str, Any]]:
    """The NEIGHBOR dict of a CDP packet (from its version byte), or None when it is too short or names neither a
    device nor a port."""
    data = bytes(payload)
    if len(data) < 4:
        return None
    fields: Dict[str, Any] = {"ttl_s": data[1]}
    ips: List[str] = []
    capabilities: Optional[List[str]] = None
    pos = 4
    while pos + 4 <= len(data):
        tlv_type, length = struct.unpack_from(">HH", data, pos)
        if length < 4 or pos + length > len(data):
            break
        value = data[pos + 4:pos + length]
        pos += length
        if tlv_type == _CDP_DEVICE_ID and fields.get("switch_name") is None:
            fields["switch_name"] = _text(value)
        elif tlv_type == _CDP_PORT_ID and fields.get("port_id") is None:
            fields["port_id"] = _text(value)
        elif tlv_type == _CDP_CAPABILITIES and capabilities is None and len(value) >= 4:
            capabilities = _capabilities(struct.unpack_from(">I", value, 0)[0], CDP_CAPABILITY_BITS)
        elif tlv_type == _CDP_PLATFORM and fields.get("switch_description") is None:
            fields["switch_description"] = _text(value)
        elif tlv_type in (_CDP_ADDRESSES, _CDP_MANAGEMENT_ADDRESSES):
            _cdp_addresses(value, ips)
        elif tlv_type == _CDP_NATIVE_VLAN and "vlan" not in fields and len(value) >= 2:
            fields["vlan"] = _vlan_id(_u16(value, 0))
        elif tlv_type == _CDP_VOICE_VLAN_REPLY and "voice_vlan" not in fields and len(value) >= 3:
            fields["voice_vlan"] = _vlan_id(_u16(value, 1))
        elif tlv_type == _CDP_POWER_AVAILABLE and fields.get("poe") is None and len(value) >= 8:
            fields["poe"] = {"class": None, "allocated_w": struct.unpack_from(">I", value, 4)[0] / 1000}
    if fields.get("switch_name") is None and fields.get("port_id") is None:
        return None
    fields["chassis_id"] = fields.get("switch_name")
    fields["management_ips"] = ips
    fields["capabilities"] = capabilities or []
    return _neighbor("cdp", **fields)


# --------------------------------------------------------------------------- packets
def neighbors_from_packets(packets: Iterable[Any], *, own_mac: Optional[str] = None) -> List[Dict[str, Any]]:
    """NEIGHBOR dicts from pcapng PACKET dicts (``tnt.pcapng``; link type 1 only) or raw Ethernet frames.

    Frames sent from *own_mac* are skipped. One neighbour is kept per ``(protocol, chassis_id, port_id)``: listed in
    the order first heard, with the values of the latest frame."""
    own = _own_mac_bytes(own_mac)
    found: Dict[Tuple[str, Optional[str], Optional[str]], Dict[str, Any]] = {}
    for packet in packets:
        if isinstance(packet, dict):
            if packet.get("linktype", LINKTYPE_ETHERNET) != LINKTYPE_ETHERNET:
                continue
            frame = packet.get("data")
        else:
            frame = packet
        if not isinstance(frame, (bytes, bytearray, memoryview)):
            continue
        frame = bytes(frame)
        kind, start, end = _locate(frame, own)
        if kind is None:
            continue
        neighbor = parse_lldp(frame[start:end]) if kind == "lldp" else parse_cdp(frame[start:end])
        if neighbor is None:
            continue
        found[(neighbor["protocol"], neighbor["chassis_id"], neighbor["port_id"])] = neighbor
    return list(found.values())
