r"""Pro AV: what a broadcast-audio network says about itself (ProAV page, ARCHITECTURE §3.27).

Dante, AES67, Ravenna, SMPTE ST 2110, Q-LAN and AVB all discover and clock themselves over multicast, so a PC that
does nothing but *listen* on one of their networks can answer most of what an integrator wants to know before
touching a cable: what gear is here, what is streaming, which clock everything is following, and which of the usual
five faults is present.  This module is the analysis half of that - :mod:`tnt.ptp` reads the clock, :mod:`tnt.mdns`
reads the service announcements, and what is here turns all of it into devices, streams, findings and a diagram.

Original code written from RFC 2974 (the Session Announcement Protocol header), RFC 8866 (SDP: the ``v=/o=/s=/c=/m=``
lines and the ``a=`` attributes), RFC 7273 (``a=ts-refclk`` and ``a=mediaclk``: how a stream names its PTP
grandmaster), AES67-2018 (the SAP group and port, L16/L24 over RTP, the 1 ms packet time) and SMPTE ST 2110-10
(the same reference-clock lines for video estates).  Nothing is taken from any other implementation.

What is honest to report, and what is not
------------------------------------------
This runs on one PC, on one port, with no switch credentials.  That bounds what can be *known*:

* **Yes**: who announces what (mDNS), what streams are advertised and with what format and clock (SAP/SDP), the whole
  PTP clock tree including boundary and transparent clocks, and which devices are following it (:mod:`tnt.ptp`).
* **Yes, by inference**: that a switch is doing PTP work, that the audio clock and the announced reference clock
  disagree, that two clock trees are running at once.
* **No**: which port of which switch every device is plugged into.  One host hears LLDP from its *own* switch and
  nothing about anyone else's port, and a switch's MAC table needs SNMP or a login.  So :func:`build_graph` draws the
  two graphs that *are* derivable - the **clock tree** and the **stream flow map** - and never a physical topology.
  ``GRAPH["note"]`` says so on the page, rather than letting a drawing imply more than was measured.

Everything in this module is pure: no socket is opened, no file read, no clock consulted and nothing logged.  The
caller passes the timestamps.  :class:`tnt.proav.ProAvScanner` (below) does the listening.

SAP and SDP (:func:`parse_sap`, :func:`parse_sdp`)
---------------------------------------------------
``parse_sap(payload)`` reads the RFC 2974 header off a packet from the SAP group and returns
``{"version", "deletion", "source", "hash", "content_type", "body"}`` or None.  ``body`` is the SDP text.
``parse_sdp(text, ...)`` turns that into a STREAM dict.  The fields that matter on an AV network:

======================  ======================================================================================
line                    what it gives
======================  ======================================================================================
``s=``                  the stream name as the operator sees it in their controller
``o=``                  the originating device's address, and the session id/version that mark a re-announce
``c=IN IP4 g/ttl``      the multicast group the audio is actually on, and its scope
``m=audio p RTP/AVP f`` the destination port and payload type
``a=rtpmap:f L24/48000/8``  encoding, sample rate and channel count - which is the bandwidth
``a=ptime:1``           the packet time, which with the above is the packet rate and size
``a=ts-refclk:ptp=IEEE1588-2008:<gmid>:<domain>``  **the grandmaster this stream expects**, and its domain
``a=mediaclk:direct=0`` the media clock offset
``a=recvonly``/``sendonly``  which way it goes
======================  ======================================================================================

``bitrate_mbps`` is computed, not announced: ``rate x channels x depth`` for the payload, plus
:data:`PACKET_OVERHEAD_BYTES` of RTP/UDP/IP/Ethernet per packet at ``1000 / ptime_ms`` packets a second.  It is what
the stream costs on the wire, which is the number that decides whether a 1 Gb link is about to run out.

Classification (:func:`classify_service`, :func:`classify_vendor`)
------------------------------------------------------------------
A device's family comes from what it announces first (:data:`SERVICE_FAMILIES`, matched on the ``_service._proto``
part and then on :data:`FAMILY_HINTS` substrings) and from who made it second (:func:`classify_vendor`, matched
against the OUI registry's vendor text with :data:`AV_VENDORS` / :data:`NETWORK_VENDORS`).  Matching the *vendor
name* rather than a hard-coded OUI list is deliberate: :mod:`tnt.oui` already ships the registry, and a table of
manufacturer names ages far better than a table of prefixes.  A device that matches nothing keeps family ``"other"``
and is still listed - an unknown box on an AV VLAN is itself worth seeing.

Devices (:func:`build_devices`)
-------------------------------
One row per real device, merged from every source that saw it, keyed by MAC where one is known and by IP otherwise
(:func:`device_id`).  mDNS gives the name, model, firmware and services; PTP gives the clock role and often a device
that answers no mDNS at all; SAP gives what it sends; ARP gives the MAC that ties an IP to a vendor.  ``sources``
lists which of those saw it, so the page can say why a row is there.

Findings (:func:`build_findings`)
----------------------------------
The checks a competent integrator runs by hand, in one list, worst first.  Each is a FINDING dict with a stable
``id`` (so the UI can link to an explanation and a report can be diffed run to run), a ``level`` of
:data:`FINDING_LEVELS` (``"bad"``, ``"warn"``, ``"info"``, ``"good"``), a one-line ``title``, a ``detail`` that
quotes the measurement it came from, and ``advice`` saying what to do about it.  :data:`FINDING_IDS` is every id this
module can emit; the mock and the tests use it to stay in step.

A Layer 2 listen that could not keep up says so (``net.lost``) rather than letting the numbers it did collect stand
as if they were complete: the flooding rate becomes a lower bound, and "no IGMP querier" drops from a fault to
something to check again, because a general query is one packet every couple of minutes and is exactly the kind of
thing a dropped buffer loses.

Nothing is invented: a check that has no data to work with is not reported at all rather than reported as passing,
and ``build_findings(..., l2=None)`` (no Layer 2 listen) leaves out every check that needs one.

Graph (:func:`build_graph`)
----------------------------
Two node/edge graphs the UI draws.  ``clock`` is the PTP tree: the grandmaster at the root, any boundary clock
between it and this PC in the middle, the followers as leaves, and this PC marked.  ``flow`` is the stream map:
talkers on the left, one node per announced multicast stream, listeners on the right where an IGMP membership report
named them (a Layer 2 listen) and a note saying they are unknown where it did not.

Shapes (keys in this order)::

    STREAM  = tnt.proav.STREAM_KEYS
    DEVICE  = tnt.proav.DEVICE_KEYS
    SERVICE = tnt.proav.SERVICE_KEYS
    FINDING = tnt.proav.FINDING_KEYS
    GRAPH   = {"clock": PLOT, "flow": PLOT}; PLOT = {"nodes": [NODE], "edges": [EDGE], "note": str|None}
    NODE    = tnt.proav.NODE_KEYS; EDGE = tnt.proav.EDGE_KEYS
"""

from __future__ import annotations

import importlib
import ipaddress
import logging
import math
import os
import re
import select
import socket
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import mdns as _mdns

__all__ = ["STREAM_KEYS", "DEVICE_KEYS", "SERVICE_KEYS", "FINDING_KEYS", "NODE_KEYS", "EDGE_KEYS", "PLOT_KEYS",
           "FAMILIES", "FAMILY_TEXT", "SERVICE_FAMILIES", "FAMILY_HINTS", "AV_VENDORS", "NETWORK_VENDORS",
           "FINDING_LEVELS", "FINDING_IDS", "SAP_GROUP_V4", "SAP_GROUP_ADMIN", "SAP_PORT", "PACKET_OVERHEAD_BYTES",
           "parse_sap", "parse_sdp", "classify_service", "classify_vendor", "device_id", "build_devices",
           "build_findings", "build_graph", "stream_id", "SCAN_STATUS_KEYS", "JOB_KEYS", "RESULT_KEYS",
           "SCAN_ADAPTER_KEYS", "LISTENER_KEYS", "COUNTS_KEYS", "L2_KEYS", "TILE_KEYS", "SCAN_STATES",
           "SCAN_SECONDS", "DEFAULT_SECONDS", "EVENT", "PROGRESS_EVENT", "ProAvUnavailable", "ProAvScanner"]

STREAM_KEYS = ("id", "name", "info", "group", "port", "source", "origin", "family", "codec", "rate", "channels",
               "depth", "ptime_ms", "packet_bytes", "bitrate_mbps", "refclk", "refclk_domain", "refclk_kind",
               "mediaclk", "direction", "scope", "count", "first_ts", "last_ts", "deleted")
DEVICE_KEYS = ("id", "name", "ip", "ips", "mac", "vendor", "vendor_kind", "family", "family_text", "model",
               "firmware", "hostname", "services", "roles", "clock_role", "clock_identity", "streams_out",
               "sources", "first_ts", "last_ts")
SERVICE_KEYS = ("type", "label", "instance", "host", "port", "txt")
FINDING_KEYS = ("id", "level", "title", "detail", "advice", "evidence")
NODE_KEYS = ("id", "kind", "label", "sub", "family", "level", "detail")
EDGE_KEYS = ("source", "target", "kind", "label")
PLOT_KEYS = ("nodes", "edges", "note")

#: Where AES67 / ST 2110 session announcements live (AES67-2018 clause 8, RFC 2974 clause 3).  The administratively
#: scoped group is what AES67 specifies; the original SAP group is listened to as well because older gear uses it.
SAP_GROUP_V4 = "239.255.255.255"
SAP_GROUP_ADMIN = "224.2.127.254"
SAP_PORT = 9875

#: RTP(12) + UDP(8) + IPv4(20) + Ethernet header, preamble, FCS and inter-frame gap(38): what one audio packet really
#: costs on a link, which is what ``bitrate_mbps`` reports.
PACKET_OVERHEAD_BYTES = 78

#: The protocol families this page knows about.  ``"other"`` is a device that announced something but matched none.
FAMILIES = ("dante", "aes67", "ravenna", "st2110", "avb", "qsys", "crestron", "livewire", "cobranet", "av", "other")
#: The families that really do need a shared PTP clock.  ``"av"`` (AirPlay, Chromecast, an RTSP camera) does not,
#: so finding no clock on a network of those is not a fault worth flagging.
PRO_FAMILIES = ("dante", "aes67", "ravenna", "st2110", "avb", "qsys", "livewire", "cobranet")
FAMILY_TEXT: Dict[str, str] = {
    "dante": "Dante", "aes67": "AES67", "ravenna": "Ravenna", "st2110": "SMPTE ST 2110", "avb": "AVB / Milan",
    "qsys": "Q-SYS", "crestron": "Crestron", "livewire": "Livewire", "cobranet": "CobraNet",
    "av": "AV device", "other": "Other",
}

#: ``_service._proto`` -> (family, what to call it).  The DNS-SD meta-query is what finds service types; this table
#: is only what they *mean*, so a type that is not here still shows up as an unclassified service on its device.
SERVICE_FAMILIES: Dict[str, Tuple[str, str]] = {
    "_netaudio-arc._udp": ("dante", "Dante control"),
    "_netaudio-cmc._udp": ("dante", "Dante connection management"),
    "_netaudio-chan._udp": ("dante", "Dante channels"),
    "_netaudio-dbc._udp": ("dante", "Dante brokered control"),
    "_netaudio-audinate._udp": ("dante", "Dante"),
    "_nmos-node._tcp": ("st2110", "NMOS node"),
    "_nmos-register._tcp": ("st2110", "NMOS registry"),
    "_nmos-registration._tcp": ("st2110", "NMOS registration"),
    "_nmos-query._tcp": ("st2110", "NMOS query"),
    "_ravenna._tcp": ("ravenna", "Ravenna"),
    "_ravenna_session._tcp": ("ravenna", "Ravenna session"),
    "_qsys._tcp": ("qsys", "Q-SYS"),
    "_qsys-disco._udp": ("qsys", "Q-SYS discovery"),
    "_axia-livewire._tcp": ("livewire", "Livewire"),
    "_livewire._tcp": ("livewire", "Livewire"),
    "_crestron._tcp": ("crestron", "Crestron"),
    "_crestron-cip._tcp": ("crestron", "Crestron CIP"),
    "_rtsp._tcp": ("av", "RTSP"),
    "_shure._tcp": ("av", "Shure"),
    "_biamp._tcp": ("av", "Biamp"),
    "_symetrix._tcp": ("av", "Symetrix"),
    "_powersoft._tcp": ("av", "Powersoft"),
    "_http._tcp": ("", "Web interface"),
    "_https._tcp": ("", "Web interface (TLS)"),
    "_ssh._tcp": ("", "SSH"),
    "_telnet._tcp": ("", "Telnet"),
    "_workstation._tcp": ("", "Workstation"),
    "_sftp-ssh._tcp": ("", "SFTP"),
    "_printer._tcp": ("", "Printer"),
    "_ipp._tcp": ("", "Printer (IPP)"),
    "_airplay._tcp": ("av", "AirPlay"),
    "_raop._tcp": ("av", "AirPlay audio"),
    "_googlecast._tcp": ("av", "Chromecast"),
}

#: Substrings matched against a service type that :data:`SERVICE_FAMILIES` does not list, so a vendor that ships a
#: new ``_netaudio-something._udp`` is still recognised.  Checked in order; the first hit wins.
FAMILY_HINTS: Tuple[Tuple[str, str], ...] = (
    ("netaudio", "dante"), ("dante", "dante"), ("nmos", "st2110"), ("ravenna", "ravenna"), ("aes67", "aes67"),
    ("qsys", "qsys"), ("qlan", "qsys"), ("crestron", "crestron"), ("livewire", "livewire"), ("avdecc", "avb"),
    ("milan", "avb"), ("cobranet", "cobranet"),
)

#: Vendor-name substrings (lowercase) that mark a pro-audio / AV manufacturer, matched against the OUI registry's
#: text.  ``dante`` is listed apart because an Audinate MAC *is* a Dante device; the rest only say "AV".
AV_VENDORS: Tuple[Tuple[str, str], ...] = (
    ("audinate", "dante"),
    ("qsc", "qsys"), ("q-sys", "qsys"),
    ("crestron", "crestron"),
    ("telos", "livewire"), ("axia", "livewire"), ("wheatstone", "livewire"),
    ("shure", "av"), ("sennheiser", "av"), ("biamp", "av"), ("symetrix", "av"), ("extron", "av"),
    ("bose", "av"), ("yamaha", "av"), ("roland", "av"), ("behringer", "av"), ("music group", "av"),
    ("midas", "av"), ("klark", "av"), ("digico", "av"), ("allen & heath", "av"), ("allen and heath", "av"),
    ("soundcraft", "av"), ("harman", "av"), ("akg", "av"), ("jbl", "av"), ("crown", "av"), ("bss", "av"),
    ("lexicon", "av"), ("dbx", "av"), ("martin audio", "av"), ("meyer sound", "av"), ("d&b audio", "av"),
    ("powersoft", "av"), ("lab.gruppen", "av"), ("lab gruppen", "av"), ("rcf ", "av"), ("genelec", "av"),
    ("neumann", "av"), ("focusrite", "av"), ("rme", "av"), ("motu", "av"), ("merging", "av"),
    ("directout", "av"), ("ferrofish", "av"), ("appsys", "av"), ("archwave", "av"), ("digigram", "av"),
    ("luminex", "av"), ("attero", "av"), ("xilica", "av"), ("ashly", "av"), ("barix", "av"),
    ("electro-voice", "av"), ("dynacord", "av"), ("bosch", "av"), ("tascam", "av"), ("teac", "av"),
    ("solid state logic", "av"), ("calrec", "av"), ("studer", "av"), ("lawo", "av"), ("riedel", "av"),
    ("stagetec", "av"), ("avid ", "av"), ("audio-technica", "av"), ("audio technica", "av"),
    ("blackmagic", "av"), ("aja ", "av"), ("ross video", "av"), ("evertz", "av"), ("grass valley", "av"),
    ("barco", "av"), ("christie", "av"), ("analog way", "av"), ("kramer", "av"), ("atlona", "av"),
    ("amx ", "av"), ("netgear av", "av"), ("visionary", "av"), ("zeevee", "av"), ("bolin", "av"),
)

#: ... and the ones that mark network infrastructure, which is worth telling apart from an endpoint on the diagram.
NETWORK_VENDORS: Tuple[str, ...] = (
    "cisco", "ubiquiti", "netgear", "aruba", "hewlett", "hp ", "juniper", "extreme networks", "arista",
    "d-link", "tp-link", "zyxel", "mikrotik", "ruckus", "meraki", "fortinet", "sonicwall", "brocade",
    "allied telesis", "huawei", "alcatel", "avaya", "enterasys", "edge-core", "fs.com",
)
# Deliberately not here: Dell and bare "HP". Both make switches, but far more of their addresses are on PCs, and
# calling every laptop on the AV VLAN "network infrastructure" would hide it from the "not AV gear" finding.

FINDING_LEVELS = ("bad", "warn", "info", "good")
_LEVEL_ORDER = {level: i for i, level in enumerate(FINDING_LEVELS)}

#: Every finding this module can emit.  A stable id per check: the UI keys its explanation off it and a report can be
#: compared run to run.  Ids that need a Layer 2 listen are marked in the comment beside them.
FINDING_IDS: Tuple[str, ...] = (
    "clock.none", "clock.locked", "clock.free", "clock.holdover", "clock.domains", "clock.versions",
    "clock.contention", "clock.changed", "clock.jitter", "clock.boundary", "clock.transparent", "clock.leap",
    "clock.followers", "clock.announce",
    "stream.none", "stream.refclk", "stream.domain", "stream.bandwidth", "stream.ptime", "stream.unicast",
    "stream.scope", "stream.found",
    "device.none", "device.found", "device.mixed", "device.unmanaged",
    "net.querier", "net.flood", "net.dscp", "net.lost", "net.l2",   # these five need the Layer 2 listen
    "net.switch", "net.vlan",                                       # ... these two do not: they are LLDP
)

#: Sync packet-delay-variation thresholds.  A follower has to absorb this; past a millisecond a clock is being
#: starved by the network rather than by its own oscillator.
JITTER_WARN_MS = 1.0
JITTER_BAD_MS = 10.0
#: Announced multicast bandwidth as a share of the link, past which the link is the next thing to break.
BANDWIDTH_WARN_PCT = 40.0
BANDWIDTH_BAD_PCT = 70.0
#: Bounds, so a hostile or broken network cannot grow a scan without end.
MAX_STREAMS = 512
MAX_DEVICES = 1024
MAX_SERVICES_PER_DEVICE = 32
MAX_TEXT = 200

_SDP_LINE_RE = re.compile(r"^([a-z])=(.*)$")
_RTPMAP_RE = re.compile(r"^(\d+)\s+([A-Za-z0-9_\-/.]+)")
# the identity is matched as whole octets (a 6-byte UUID through an 8-byte EUI-64) so that the ``:<domain>`` after
# it is not swallowed by the address: "ptp=IEEE1588-2008:00-1D-C1-FF-FE-11-22-33:0" is an identity *and* domain 0
_REFCLK_RE = re.compile(r"ptp=(IEEE1588-\d{4}|IEEE802\.1AS-\d{4})"
                        r"(?::((?:[0-9A-Fa-f]{2}[:\-]){5,7}[0-9A-Fa-f]{2}))?(?::(\d+))?")
_DEPTHS = {"L8": 8, "L16": 16, "L20": 20, "L24": 24, "L32": 32, "AM824": 32, "PCMU": 8, "PCMA": 8}


def _text(value: Any, limit: int = MAX_TEXT) -> Optional[str]:
    """Trimmed display text, control characters removed, or None when nothing is left."""
    if value is None:
        return None
    raw = value if isinstance(value, str) else str(value)
    clean = "".join(ch for ch in raw if ch >= " " or ch == "\t").strip()
    return clean[:limit] or None


def _address_rank(ip: str) -> int:
    """How useful an address is on a page: IPv4 (0), routable IPv6 (1), link-local or unique-local IPv6 (2)."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return 3
    if address.version == 4:
        return 0
    return 2 if (address.is_link_local or address.is_private) else 1


def _is_multicast(ip: Optional[str]) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False


# ============================================================== SAP and SDP

def parse_sap(payload: bytes) -> Optional[Dict[str, Any]]:
    """One packet from the SAP group as ``{"version", "deletion", "source", "hash", "content_type", "body"}``.

    None when it is not SAP this module reads: shorter than the header, a version other than 1, encrypted or
    compressed (nothing on an AV network sends either, and guessing at the payload would be worse than saying no)."""
    data = bytes(payload)
    if len(data) < 8:
        return None
    flags = data[0]
    version = (flags >> 5) & 0x07
    if version != 1:
        return None
    ipv6 = bool(flags & 0x10)
    deletion = bool(flags & 0x04)
    encrypted = bool(flags & 0x02)
    compressed = bool(flags & 0x01)
    if encrypted or compressed:
        return None
    auth_words = data[1]
    address_len = 16 if ipv6 else 4
    at = 4 + address_len
    if len(data) < at:
        return None
    try:
        source = str(ipaddress.ip_address(data[4:at]))
    except ValueError:
        source = None
    at += auth_words * 4
    if at >= len(data):
        return None
    content_type = None
    # an optional NUL-terminated MIME type sits before the payload; "v=0" first means it was left out (RFC 2974 §6)
    if not data[at:].startswith(b"v=0"):
        end = data.find(b"\x00", at)
        if 0 <= end < len(data):
            content_type = _text(data[at:end].decode("utf-8", "replace"), 64)
            at = end + 1
    body = data[at:].decode("utf-8", "replace")
    return {"version": version, "deletion": deletion, "source": source, "hash": int.from_bytes(data[2:4], "big"),
            "content_type": content_type, "body": body}


def _sdp_lines(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        match = _SDP_LINE_RE.match(raw.strip())
        if match:
            out.append((match.group(1), match.group(2).strip()))
    return out


def _connection(value: str) -> Tuple[Optional[str], Optional[int]]:
    """``c=`` as (address, TTL).  ``IN IP4 239.69.0.1/32`` is the group and its multicast scope."""
    parts = value.split()
    if len(parts) < 3:
        return None, None
    address = parts[2]
    ttl: Optional[int] = None
    if "/" in address:
        address, _, tail = address.partition("/")
        head, _, _ = tail.partition("/")
        if head.isdigit():
            ttl = int(head)
    return address or None, ttl


def _refclk(value: str) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """``a=ts-refclk:`` as (grandmaster identity, domain, kind).

    ``ptp=IEEE1588-2008:00-1D-C1-FF-FE-11-22-33:0`` is the usual AES67 spelling: the grandmaster's clock identity
    and the PTP domain the stream expects.  ``localmac=`` means the sender is its own clock (RFC 7273 clause 4.8),
    which on an AV network means it is not on the shared clock at all."""
    match = _REFCLK_RE.search(value)
    if match:
        identity = match.group(2)
        domain = int(match.group(3)) if match.group(3) is not None and match.group(3).isdigit() else None
        if identity:
            identity = identity.replace("-", ":").upper()
        return identity, domain, match.group(1)
    if "localmac=" in value:
        _, _, mac = value.partition("localmac=")
        return _text(mac.replace("-", ":").upper(), 32), None, "localmac"
    return None, None, _text(value.split(":")[0], 32)


def stream_id(group: Optional[str], port: Optional[int], name: Optional[str]) -> str:
    """A stable id for a stream: its destination if it has one, else its name."""
    if group and port:
        return f"{group}:{port}"
    if group:
        return str(group)
    return "sdp:" + (name or "stream")


def parse_sdp(text: str, *, source: Optional[str] = None, ts: float = 0.0,
              deleted: bool = False) -> Optional[Dict[str, Any]]:
    """One SDP session description as a STREAM dict, or None when it carries no media line at all.

    Session-level ``c=`` is used when the media level has none, which is how most AV gear writes it.  Only the first
    media line is described: an AES67 or ST 2110 announcement carries one stream, and a multi-media SDP is reported
    by its first (the rest stay in ``sdp`` on the session for anyone who wants them)."""
    lines = _sdp_lines(text or "")
    if not lines:
        return None
    name = info = origin = None
    session_group: Optional[str] = None
    session_ttl: Optional[int] = None
    media_group: Optional[str] = None
    media_ttl: Optional[int] = None
    port: Optional[int] = None
    payload_type: Optional[str] = None
    codec = rate = channels = None
    ptime: Optional[float] = None
    refclk = refclk_domain = refclk_kind = None
    mediaclk = None
    direction = None
    seen_media = False
    for key, value in lines:
        if key == "s":
            name = _text(value)
        elif key == "i" and not seen_media:
            info = _text(value)
        elif key == "o":
            parts = value.split()
            if len(parts) >= 6:
                origin = _text(parts[5], 64)
        elif key == "c":
            address, ttl = _connection(value)
            if seen_media:
                media_group, media_ttl = address, ttl
            else:
                session_group, session_ttl = address, ttl
        elif key == "m":
            if seen_media:
                continue                        # only the first media line is described
            seen_media = True
            parts = value.split()
            if len(parts) >= 4:
                if parts[1].split("/")[0].isdigit():
                    port = int(parts[1].split("/")[0])
                payload_type = parts[3]
        elif key == "a":
            lowered = value.lower()
            if lowered.startswith("rtpmap:"):
                match = _RTPMAP_RE.match(value[7:].strip())
                if match and (payload_type is None or match.group(1) == payload_type):
                    bits = match.group(2).split("/")
                    codec = _text(bits[0], 32)
                    if len(bits) > 1 and bits[1].isdigit():
                        rate = int(bits[1])
                    channels = int(bits[2]) if len(bits) > 2 and bits[2].isdigit() else 1
            elif lowered.startswith("ptime:"):
                try:
                    ptime = float(value[6:].strip())
                except ValueError:
                    ptime = None
            elif lowered.startswith("ts-refclk:"):
                refclk, refclk_domain, refclk_kind = _refclk(value[10:].strip())
            elif lowered.startswith("mediaclk:"):
                mediaclk = _text(value[9:].strip(), 64)
            elif lowered in ("recvonly", "sendonly", "sendrecv", "inactive"):
                direction = lowered
    if not seen_media:
        return None
    group = media_group or session_group
    scope = media_ttl if media_ttl is not None else session_ttl
    depth = _DEPTHS.get((codec or "").upper())
    packet_bytes = bitrate = None
    if rate and channels and depth and ptime and ptime > 0:
        samples = rate * (ptime / 1000.0)
        packet_bytes = int(round(samples * channels * depth / 8.0))
        packets_per_s = 1000.0 / ptime
        bitrate = round(packets_per_s * (packet_bytes + PACKET_OVERHEAD_BYTES) * 8 / 1_000_000.0, 3)
    return {
        "id": stream_id(group, port, name),
        "name": name or "(unnamed stream)",
        "info": info,
        "group": group,
        "port": port,
        "source": source,
        "origin": origin,
        "family": "aes67" if refclk_kind and refclk_kind.startswith("IEEE1588") else "av",
        "codec": codec,
        "rate": rate,
        "channels": channels,
        "depth": depth,
        "ptime_ms": ptime,
        "packet_bytes": packet_bytes,
        "bitrate_mbps": bitrate,
        "refclk": refclk,
        "refclk_domain": refclk_domain,
        "refclk_kind": refclk_kind,
        "mediaclk": mediaclk,
        "direction": direction,
        "scope": scope,
        "count": 1,
        "first_ts": ts,
        "last_ts": ts,
        "deleted": deleted,
    }


# ============================================================== classification

def classify_service(service_type: Optional[str]) -> Tuple[str, Optional[str]]:
    """``(family, label)`` for a DNS-SD service type.  ``family`` is ``""`` for a service that says nothing about
    the family (a web UI, SSH) and ``"other"`` for one that is not recognised at all."""
    if not service_type:
        return "other", None
    proto = _mdns.service_proto(service_type) or service_type
    known = SERVICE_FAMILIES.get(proto)
    if known is not None:
        return known[0], known[1]
    lowered = proto.lower()
    for needle, family in FAMILY_HINTS:
        if needle in lowered:
            return family, None
    return "other", None


def classify_vendor(vendor: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """``(family, kind)`` from an OUI vendor name: ``kind`` is ``"av"``, ``"network"`` or None.

    An Audinate address really is a Dante device, so that one sets the family; the rest only mark the row as AV gear
    or as network infrastructure, which is what the diagram needs to draw them differently."""
    if not vendor:
        return None, None
    lowered = vendor.lower()
    for needle, family in AV_VENDORS:
        if needle in lowered:
            return (family if family != "av" else None), "av"
    for needle in NETWORK_VENDORS:
        if needle in lowered:
            return None, "network"
    return None, None


def _best_family(candidates: Iterable[Optional[str]]) -> str:
    """The most specific family among those seen: a named ecosystem beats ``"av"``, which beats ``"other"``."""
    seen = [c for c in candidates if c]
    for family in FAMILIES:
        if family in ("av", "other"):
            continue
        if family in seen:
            return family
    if "av" in seen:
        return "av"
    return "other"


# ============================================================== devices

def device_id(mac: Optional[str], ip: Optional[str], name: Optional[str]) -> str:
    """A stable device key: the MAC where one is known, else the IP, else the announced name."""
    if mac:
        return "mac:" + mac.upper()
    if ip:
        return "ip:" + ip
    return "name:" + (name or "?")


class _DeviceBuilder:
    """Accumulates one device row from every source that saw it."""

    def __init__(self, key: str, ts: float) -> None:
        self.key = key
        self.row: Dict[str, Any] = {
            "id": key, "name": None, "ip": None, "ips": [], "mac": None, "vendor": None, "vendor_kind": None,
            "family": "other", "family_text": FAMILY_TEXT["other"], "model": None, "firmware": None,
            "hostname": None, "services": [], "roles": [], "clock_role": None, "clock_identity": None,
            "streams_out": 0, "sources": [], "first_ts": ts, "last_ts": ts,
        }
        self._families: List[Optional[str]] = []

    def touch(self, ts: float, source: str) -> None:
        self.row["first_ts"] = min(self.row["first_ts"], ts)
        self.row["last_ts"] = max(self.row["last_ts"], ts)
        if source not in self.row["sources"]:
            self.row["sources"].append(source)

    def add_ip(self, ip: Optional[str]) -> None:
        """Collect an address, and keep ``ip`` as the most useful one: IPv4 first, then a routable IPv6, and a
        link-local address only when there is nothing else.  mDNS answers with every address a device has, and a
        fe80:: one is no use to anybody reading the page."""
        if not ip or ip in self.row["ips"]:
            return
        self.row["ips"].append(ip)
        if self.row["ip"] is None or _address_rank(ip) < _address_rank(self.row["ip"]):
            self.row["ip"] = ip

    def add_role(self, role: Optional[str]) -> None:
        if role and role not in self.row["roles"]:
            self.row["roles"].append(role)

    def finish(self, vendor_lookup: Any) -> Dict[str, Any]:
        row = self.row
        if row["mac"] and not row["vendor"]:
            row["vendor"] = vendor_lookup(row["mac"])
        vendor_family, kind = classify_vendor(row["vendor"])
        row["vendor_kind"] = kind
        row["family"] = _best_family(self._families + [vendor_family, "av" if kind == "av" else None])
        row["family_text"] = FAMILY_TEXT.get(row["family"], FAMILY_TEXT["other"])
        if not row["name"]:
            # nothing announced a name: "Audinate Pty L 11:22:33" reads better than a bare MAC, and the last three
            # octets keep two boxes from the same maker apart
            if row["vendor"] and row["mac"]:
                row["name"] = f"{row['vendor']} {row['mac'][9:]}"
            else:
                row["name"] = row["hostname"] or row["ip"] or row["mac"] or "(unnamed)"
        row["services"] = row["services"][:MAX_SERVICES_PER_DEVICE]
        return row

    def note_family(self, family: Optional[str]) -> None:
        if family:
            self._families.append(family)


def _txt_fact(txt: Any, *names: str) -> Optional[str]:
    """The first of ``names`` present in a TXT dict, matched without case."""
    if not isinstance(txt, dict):
        return None
    lowered = {str(k).lower(): v for k, v in txt.items()}
    for name in names:
        value = lowered.get(name)
        if value:
            return _text(value, 64)
    return None


def build_devices(services: Any, clock: Any, streams: Any, *, arp: Any = None,
                  vendor_lookup: Any = None) -> List[Dict[str, Any]]:
    """One DEVICE row per device, merged from the mDNS services, the PTP clock view and the announced streams.

    ``services`` is a list of ``{"instance", "type", "host", "port", "txt", "ips", "ts"}`` as the scanner collects
    them; ``clock`` a :meth:`tnt.ptp.ClockTracker.view` dict; ``streams`` the STREAM list.  ``arp`` maps IP to MAC
    (``tnt.arp.get_arp_table()``) and ``vendor_lookup`` MAC to vendor text (``tnt.oui.vendor_for_mac``); both are
    optional, and without them a row simply has no MAC or no vendor.  Rows are sorted AV gear first, then by name."""
    arp_map = {str(k): str(v) for k, v in (arp or {}).items()}
    lookup = vendor_lookup or (lambda _mac: None)
    builders: Dict[str, _DeviceBuilder] = {}
    by_ip: Dict[str, str] = {}
    by_mac: Dict[str, str] = {}
    by_host: Dict[str, str] = {}
    by_name: Dict[str, str] = {}
    by_identity: Dict[str, str] = {}

    def builder(mac: Optional[str], ips: Any, name: Optional[str], ts: float, source: str,
                host: Optional[str] = None) -> Optional[_DeviceBuilder]:
        """The row for one device, found again however it names itself this time.

        The same box arrives as a MAC from ARP or PTP, as one or more addresses from mDNS, and as a hostname on
        every service it publishes - and a device with several service instances answers under all of them.  So a
        row is looked up by MAC, then by any address already seen, then by hostname, and only a device that matches
        none of those is a new row."""
        addresses = [a for a in (ips if isinstance(ips, (list, tuple)) else [ips]) if a]
        mac = mac.upper() if mac else next((arp_map[a] for a in addresses if a in arp_map), None)
        host_key = (host or "").rstrip(".").lower() or None
        name_key = (name or "").strip().lower() or None
        key = None
        if mac:
            key = by_mac.get(mac)
        if key is None:
            key = next((by_ip[a] for a in addresses if a in by_ip), None)
        if key is None and host_key:
            key = by_host.get(host_key)
        if key is None and name_key:
            candidate = by_name.get(name_key)
            # one device publishes several services under one friendly name, and only some of them carry an
            # address. Merging on the name is right for those, and wrong only if two devices really are called the
            # same thing *and* both have addresses - so that case is left alone.
            if candidate is not None:
                other = builders[candidate].row["ips"]
                if not addresses or not other or set(addresses) & set(other):
                    key = candidate
        if key is None:
            key = device_id(mac, addresses[0] if addresses else None, name)
        if key not in builders:
            if len(builders) >= MAX_DEVICES:
                return None
            builders[key] = _DeviceBuilder(key, ts)
        row = builders[key]
        if mac and not row.row["mac"]:
            row.row["mac"] = mac
        if mac:
            by_mac.setdefault(mac, key)
        for address in addresses:
            row.add_ip(address)
            by_ip.setdefault(address, key)
        if host_key:
            by_host.setdefault(host_key, key)
        if name_key:
            by_name.setdefault(name_key, key)
        row.touch(ts, source)
        return row

    # ---- mDNS: names, models, firmware and what each device offers
    for entry in (services or []):
        ts = float(entry.get("ts") or 0.0)
        row = builder(entry.get("mac"), entry.get("ips") or [], entry.get("instance"), ts, "mdns",
                      host=entry.get("host"))
        if row is None:
            continue
        family, label = classify_service(entry.get("type"))
        row.note_family(family or None)
        service = {"type": entry.get("type"), "label": label, "instance": entry.get("instance"),
                   "host": entry.get("host"), "port": entry.get("port"), "txt": entry.get("txt") or {}}
        if service not in row.row["services"]:
            row.row["services"].append(service)
        if entry.get("instance") and not row.row["name"]:
            row.row["name"] = _text(entry.get("instance"))
        if entry.get("host") and not row.row["hostname"]:
            row.row["hostname"] = _text(str(entry["host"]).rstrip("."))
        txt = entry.get("txt")
        row.row["model"] = row.row["model"] or _txt_fact(txt, "model", "md", "mdl", "product", "ty")
        row.row["firmware"] = row.row["firmware"] or _txt_fact(txt, "fw", "firmware", "version", "vers", "sw",
                                                               "arcp_vers", "rev")
        if label:
            row.add_role(label)

    # ---- PTP: the clock role, and gear that answers no mDNS at all
    for domain in ((clock or {}).get("domains") or []):
        master = domain.get("master")
        for entry in (domain.get("masters") or []):
            # a grandmaster is named by its clock identity, and has an address only when it is one hop away: the
            # packets may have been re-served by a boundary clock, which is a different device entirely
            row = builder(entry.get("mac"), entry.get("ip"), entry.get("identity"),
                          float(entry.get("last_ts") or 0.0), "ptp")
            if row is None:
                continue
            is_active = bool(master and master.get("identity") == entry.get("identity"))
            row.row["clock_role"] = "grandmaster" if is_active else (row.row["clock_role"] or "master")
            row.row["clock_identity"] = entry.get("identity")
            row.add_role("PTP grandmaster" if is_active else "PTP master")
            if entry.get("identity"):
                by_identity[entry["identity"]] = row.key
        for entry in (domain.get("senders") or []):
            # the port the announcements actually came from: the grandmaster itself, or the switch that re-served it
            row = builder(entry.get("mac"), entry.get("ip"), entry.get("identity"),
                          float(entry.get("last_ts") or 0.0), "ptp")
            if row is None:
                continue
            if entry.get("role") == "boundary":
                row.row["clock_role"] = "boundary"
                row.add_role("PTP boundary clock")
            row.row["clock_identity"] = row.row["clock_identity"] or entry.get("identity")
            if entry.get("identity"):
                by_identity.setdefault(entry["identity"], row.key)
        for entry in (domain.get("followers") or []):
            row = builder(entry.get("mac"), entry.get("ip"), entry.get("identity"),
                          float(entry.get("last_ts") or 0.0), "ptp")
            if row is None:
                continue
            if not row.row["clock_role"]:
                row.row["clock_role"] = "follower"
                row.add_role("PTP follower")
            row.row["clock_identity"] = row.row["clock_identity"] or entry.get("identity")
            if entry.get("identity"):
                by_identity.setdefault(entry["identity"], row.key)

    # ---- SAP: who is sending audio
    for stream in (streams or []):
        ip = stream.get("origin") or stream.get("source")
        if not ip or _is_multicast(ip):
            continue
        row = builder(None, ip, stream.get("name"), float(stream.get("last_ts") or 0.0), "sap")
        if row is None:
            continue
        row.row["streams_out"] += 1
        row.note_family(stream.get("family"))
        row.add_role("Stream source")

    rows = [b.finish(lookup) for b in builders.values()]
    rows.sort(key=lambda r: (r["family"] in ("other",), r["vendor_kind"] != "av", (r["name"] or "").lower()))
    return rows


# ============================================================== findings

def _finding(ident: str, level: str, title: str, detail: Optional[str] = None, advice: Optional[str] = None,
             evidence: Any = None) -> Dict[str, Any]:
    return {"id": ident, "level": level, "title": title, "detail": detail, "advice": advice, "evidence": evidence}


def _domain_name(domain: Dict[str, Any]) -> str:
    return f"PTPv{domain.get('version')} {domain.get('label') or ''}".strip()


def _clock_findings(clock: Dict[str, Any], devices: List[Dict[str, Any]], out: List[Dict[str, Any]]) -> None:
    domains = clock.get("domains") or []
    if not clock.get("heard"):
        av = [d for d in devices if d.get("family") in PRO_FAMILIES]
        if av:
            out.append(_finding(
                "clock.none", "warn", "No PTP clock was heard",
                f"{len(av)} AV device(s) answered, but nothing arrived on the PTP group "
                f"({_ptp_group_text()}) during the listen.",
                "Either nothing is streaming, or IGMP snooping on this switch is not forwarding the clock group to "
                "this port. Check that the VLAN has an IGMP querier and that this port is in the AV VLAN."))
        else:
            out.append(_finding(
                "clock.none", "info", "No PTP clock was heard",
                "Nothing arrived on the PTP group during the listen.",
                "This is normal on a network with no AES67, Dante or ST 2110 gear on it."))
        return

    if len(domains) > 1:
        names = ", ".join(_domain_name(d) for d in domains)
        out.append(_finding(
            "clock.domains", "bad", f"{len(domains)} PTP clock trees are running at once",
            f"Announcements arrived for {names}. Devices on different domains do not share a clock, however good "
            "each clock is on its own.",
            "Put every device on one domain. If half the room is on Dante's own clock and half on AES67, set the "
            "Dante devices to AES67 mode (or the AES67 devices to the Dante domain) so there is one tree.",
            [{"version": d.get("version"), "domain": d.get("domain"), "messages": d.get("messages")}
             for d in domains]))
    versions = clock.get("versions") or []
    if len(versions) > 1:
        out.append(_finding(
            "clock.versions", "warn", "PTPv1 and PTPv2 are both on this network",
            "PTPv1 is what Dante clocks with natively; PTPv2 is what AES67, Q-LAN and ST 2110 use. Hearing both "
            "means two ecosystems are clocking separately.",
            "That is expected while Dante is in its own mode and something else runs AES67 alongside. It is a fault "
            "only if those devices are meant to pass audio to each other."))

    best = clock.get("best") or (domains[0] if domains else None)
    if not best:
        return
    master = best.get("master")
    if len(best.get("masters") or []) > 1:
        out.append(_finding(
            "clock.contention", "warn",
            f"{len(best['masters'])} devices are announcing as master on {_domain_name(best)}",
            "More than one clock is claiming the domain. The best-master algorithm should settle it, but while it "
            "does, followers can step.",
            "Set priority1 deliberately on the device you want as grandmaster, and leave the others higher "
            "(a lower number wins).",
            [{"identity": m.get("identity"), "vendor": m.get("vendor"), "priority1": m.get("priority1"),
              "clock_class": m.get("clock_class")} for m in best["masters"][:8]]))
    if best.get("changes"):
        out.append(_finding(
            "clock.changed", "bad", "The grandmaster changed during this listen",
            f"The active grandmaster changed {best['changes']} time(s) in {_span_text(best)}. Every change is a "
            "step in the audio clock, which is usually audible.",
            "Find out why the current grandmaster keeps losing the election: a flapping link, a device being "
            "rebooted, or two devices with the same priority fighting over it."))
    if master:
        locked = master.get("locked")
        clock_class = master.get("clock_class")
        source = master.get("time_source_text") or "an unnamed source"
        if locked is True:
            out.append(_finding(
                "clock.locked", "good", f"The grandmaster is locked to {source}",
                f"{_master_text(master)} - clock class {clock_class} "
                f"({master.get('clock_class_text') or 'no text'}), accuracy {master.get('accuracy_text') or '?'}.",
                None))
        elif clock_class == 248:
            out.append(_finding(
                "clock.free", "warn", "The grandmaster is free-running",
                f"{_master_text(master)} announces clock class 248: its own oscillator, locked to nothing. "
                "Audio will stay in sync with itself but will drift against anything outside this network.",
                "That is fine for a self-contained system. It is not, if this network has to stay in step with "
                "video, timecode or another site - give the grandmaster a GPS or PTP reference."))
        elif locked is False:
            out.append(_finding(
                "clock.holdover", "bad", "The grandmaster has lost its reference",
                f"{_master_text(master)} announces clock class {clock_class} "
                f"({master.get('clock_class_text') or 'holdover'}). It is coasting on its last known rate.",
                "Check the grandmaster's reference input - a GPS antenna that has lost its fix is the usual "
                "cause. The longer it stays in holdover the further the whole network drifts."))
        steps = master.get("steps_removed")
        if isinstance(steps, int) and steps > 0:
            parent = master.get("parent_vendor") or master.get("parent")
            out.append(_finding(
                "clock.boundary", "info",
                f"{steps} boundary clock(s) sit between this PC and the grandmaster",
                f"The announcement arrived with stepsRemoved {steps}"
                + (f", re-served by {parent}." if parent else ".")
                + " A switch acting as a PTP boundary clock terminates the domain and serves it again, which is "
                  "what an AV switch's PTP support does.",
                "Nothing to do: this is what a boundary clock looks like from a follower. It is worth knowing "
                "because it means the switch, not the grandmaster, is what this PC is timing against."))
        if master.get("leap61") or master.get("leap59"):
            out.append(_finding(
                "clock.leap", "info", "A leap second is announced",
                "The grandmaster has the leap61 or leap59 flag set for the end of the current UTC day.",
                "Nothing to do; some gear mutes briefly at the leap."))
    if best.get("transparent"):
        out.append(_finding(
            "clock.transparent", "info", "A transparent clock is in the path",
            f"Sync messages arrive with a correction field of up to {best.get('correction_ns')} ns, which only a "
            "switch that timestamps packets in transit can write.",
            "Nothing to do: this is a switch correcting for its own delay, which is what you want on an AV "
            "network. It is proof the switch's PTP support is doing something."))
    jitter = best.get("sync_jitter_ms")
    if isinstance(jitter, (int, float)):
        if jitter >= JITTER_BAD_MS:
            out.append(_finding(
                "clock.jitter", "bad", "Sync messages arrive very unevenly",
                f"Sync arrives every {best.get('sync_s')} s on average, but varies by up to {jitter} ms. "
                "A follower has to absorb that; past a few milliseconds most cannot.",
                "This is congestion or a queue, not a clock fault. Check that PTP is in a priority queue on every "
                "switch in the path, and that this port is not sharing a queue with a bulk transfer."))
        elif jitter >= JITTER_WARN_MS:
            out.append(_finding(
                "clock.jitter", "warn", "Sync messages arrive unevenly",
                f"Sync arrives every {best.get('sync_s')} s on average, varying by up to {jitter} ms.",
                "Worth watching. If it grows, look at QoS on the path: clock packets should be in the highest "
                "priority queue."))
    followers = best.get("followers") or []
    answered = [f for f in followers if f.get("asking")]
    if followers:
        out.append(_finding(
            "clock.followers", "info",
            f"{len(followers)} device(s) are following this clock",
            f"{len(answered)} of them are having their delay requests answered by the grandmaster, which is what a "
            "device that is really in the clock tree looks like."
            + ("" if len(answered) == len(followers) else
               f" The other {len(followers) - len(answered)} were heard asking but no reply to them was seen."),
            None,
            [{"identity": f.get("identity"), "vendor": f.get("vendor"), "ip": f.get("ip"),
              "asking": f.get("asking")} for f in followers[:16]]))


def _master_text(master: Dict[str, Any]) -> str:
    who = master.get("vendor") or "an unknown vendor"
    mac = master.get("mac") or master.get("identity") or "?"
    return f"{who} ({mac})"


def _span_text(domain: Dict[str, Any]) -> str:
    first, last = domain.get("first_ts"), domain.get("last_ts")
    if isinstance(first, (int, float)) and isinstance(last, (int, float)) and last > first:
        return f"{round(last - first, 1)} s"
    return "the listen"


def _ptp_group_text() -> str:
    from . import ptp
    return f"{ptp.GROUP_V4}:{ptp.EVENT_PORT}/{ptp.GENERAL_PORT}"


def _stream_findings(streams: List[Dict[str, Any]], clock: Dict[str, Any], devices: List[Dict[str, Any]],
                     link_mbps: Optional[float], out: List[Dict[str, Any]]) -> None:
    live = [s for s in streams if not s.get("deleted")]
    if not live:
        av = [d for d in devices if d.get("vendor_kind") == "av" or d.get("family") not in ("other",)]
        out.append(_finding(
            "stream.none", "info", "No streams were announced",
            "Nothing arrived on the SAP group during the listen."
            + (f" {len(av)} AV device(s) did answer, so there is gear here that is not announcing." if av else ""),
            "Dante does not use SAP unless its devices are in AES67 mode, so an all-Dante network is expected to "
            "be quiet here. On AES67, Ravenna or ST 2110, silence usually means the SAP group is not reaching this "
            "port." if av else None))
        return
    total = round(sum(s.get("bitrate_mbps") or 0.0 for s in live), 2)
    out.append(_finding(
        "stream.found", "good", f"{len(live)} stream(s) are being announced",
        f"Together they are {total} Mb/s on the wire"
        + (f", {round(total / link_mbps * 100.0, 1)} % of this {int(link_mbps)} Mb/s link." if link_mbps else ".")
        + " Channel counts, sample rates and packet times are in the table.",
        None,
        [{"name": s.get("name"), "group": s.get("group"), "port": s.get("port"),
          "bitrate_mbps": s.get("bitrate_mbps")} for s in live[:16]]))
    if link_mbps:
        share = total / link_mbps * 100.0
        if share >= BANDWIDTH_BAD_PCT:
            out.append(_finding(
                "stream.bandwidth", "bad", "The announced audio nearly fills this link",
                f"{total} Mb/s of announced streams against a {int(link_mbps)} Mb/s link ({round(share, 1)} %).",
                "Not every stream necessarily reaches this port, but if it does there is no headroom left for "
                "bursts, control traffic or a re-transmit. Move to a faster uplink or split the streams."))
        elif share >= BANDWIDTH_WARN_PCT:
            out.append(_finding(
                "stream.bandwidth", "warn", "The announced audio is a large share of this link",
                f"{total} Mb/s of announced streams against a {int(link_mbps)} Mb/s link ({round(share, 1)} %).",
                "Worth keeping an eye on as channel counts grow."))
    # the reference clock every stream names, against the clock actually heard
    heard = set()
    domains_by_gm: Dict[str, Any] = {}
    for domain in (clock.get("domains") or []):
        for master in (domain.get("masters") or []):
            if master.get("identity"):
                heard.add(str(master["identity"]).upper())
                domains_by_gm[str(master["identity"]).upper()] = domain
            if master.get("mac"):
                heard.add(str(master["mac"]).upper())
    wrong = [s for s in live if s.get("refclk") and heard and str(s["refclk"]).upper() not in heard]
    if wrong:
        out.append(_finding(
            "stream.refclk", "bad",
            f"{len(wrong)} stream(s) expect a grandmaster that is not the one on this network",
            "Each of these names a reference clock in its SDP that no announcement here matches. A receiver that "
            "trusts the SDP will not lock, or will lock to the wrong tree.",
            "Re-announce the streams from a device that is on the current grandmaster, or find out why the "
            "grandmaster changed after the streams were set up.",
            [{"name": s.get("name"), "group": s.get("group"), "refclk": s.get("refclk"),
              "expected": sorted(heard)[:4]} for s in wrong[:8]]))
    local = [s for s in live if s.get("refclk_kind") == "localmac"]
    if local:
        out.append(_finding(
            "stream.domain", "warn", f"{len(local)} stream(s) are their own clock",
            "Their SDP says ts-refclk:localmac, which means the sender is not following a shared PTP clock at all.",
            "Anything receiving these has to resample. Put the sender on the network's PTP clock if it can be.",
            [{"name": s.get("name"), "group": s.get("group")} for s in local[:8]]))
    not_multicast = [s for s in live if s.get("group") and not _is_multicast(s["group"])]
    if not_multicast:
        out.append(_finding(
            "stream.unicast", "info", f"{len(not_multicast)} stream(s) are announced to a unicast address",
            "A SAP announcement normally carries a multicast group. These name a single address, so they are "
            "point-to-point.",
            None,
            [{"name": s.get("name"), "group": s.get("group")} for s in not_multicast[:8]]))
    low_scope = [s for s in live if isinstance(s.get("scope"), int) and s["scope"] <= 1]
    if low_scope:
        out.append(_finding(
            "stream.scope", "warn", f"{len(low_scope)} stream(s) have a multicast TTL of 1",
            "They cannot cross a router, only a switch.",
            "Fine on a flat AV VLAN. If any receiver is on another subnet, it will never hear these.",
            [{"name": s.get("name"), "group": s.get("group"), "scope": s.get("scope")} for s in low_scope[:8]]))
    times = sorted({s["ptime_ms"] for s in live if s.get("ptime_ms")})
    if len(times) > 1:
        out.append(_finding(
            "stream.ptime", "info", "Streams use more than one packet time",
            f"Packet times in use: {', '.join(str(t) + ' ms' for t in times)}. Mixed packet times are legal but "
            "each one costs a different amount of latency and bandwidth.",
            "Standardise on one (1 ms is the AES67 default) unless a device cannot do it."))


def _device_findings(devices: List[Dict[str, Any]], out: List[Dict[str, Any]]) -> None:
    av = [d for d in devices if d.get("vendor_kind") == "av" or d.get("family") not in ("other",)]
    if not devices:
        out.append(_finding(
            "device.none", "info", "No devices answered",
            "Nothing answered the mDNS question and nothing announced itself during the listen.",
            "If you expected AV gear here, check this PC is in the right VLAN and that mDNS is not being filtered "
            "between it and the devices."))
        return
    families: Dict[str, int] = {}
    for device in av:
        family = device.get("family") or "other"
        if family not in ("other", "av"):
            families[family] = families.get(family, 0) + 1
    if av:
        named = ", ".join(f"{FAMILY_TEXT.get(f, f)} x{n}" for f, n in sorted(families.items(), key=lambda kv: -kv[1]))
        out.append(_finding(
            "device.found", "good", f"{len(av)} AV device(s) found",
            (named or "They were recognised by their manufacturer rather than by an AV service they announced.")
            + f" {len(devices)} device(s) answered in total.",
            None))
    if len(families) > 1:
        out.append(_finding(
            "device.mixed", "info", f"{len(families)} AV ecosystems share this network",
            ", ".join(f"{FAMILY_TEXT.get(f, f)} ({n})" for f, n in sorted(families.items(), key=lambda kv: -kv[1]))
            + ". That is common and usually fine, but they only pass audio to each other through a gateway or "
              "through AES67.",
            None))
    unmanaged = [d for d in devices if d.get("vendor_kind") is None and d.get("family") == "other"]
    if unmanaged and av:
        out.append(_finding(
            "device.unmanaged", "info", f"{len(unmanaged)} device(s) here are not AV gear",
            "They answered but match no AV manufacturer or service. On a dedicated AV VLAN, anything that is not "
            "AV gear is worth knowing about.",
            "If this is meant to be a dedicated AV network, check why these are on it.",
            [{"name": d.get("name"), "ip": d.get("ip"), "vendor": d.get("vendor")} for d in unmanaged[:12]]))


def _l2_findings(l2: Dict[str, Any], streams: List[Dict[str, Any]], out: List[Dict[str, Any]],
                 av_present: bool) -> None:
    """The three checks a UDP socket cannot make.  ``av_present`` decides how loudly to say it: no querier on a
    network that is carrying multicast audio is a fault, on a network with no AV gear on it is a note."""
    lost = int(l2.get("lost") or 0)
    if lost:
        out.append(_finding(
            "net.lost", "warn", "The Layer 2 listen could not keep up",
            f"{lost} frame(s) were dropped by the capture session out of {l2.get('frames') or 0} read. That happens "
            "when a port is carrying more than this PC can read in real time - which on an AV network usually means "
            "a lot of multicast is reaching it.",
            "Treat the flooding rates below as a lower bound. If a check here matters, scan again for longer, or "
            "from a port that is not being flooded."))
    querier = l2.get("querier")
    if l2.get("igmp_seen") is not None:
        if querier:
            out.append(_finding(
                "net.querier", "good", "An IGMP querier is on this VLAN",
                f"General queries arrive from {querier.get('ip')}"
                + (f" every {querier.get('interval_s')} s." if querier.get("interval_s") else ".")
                + " That is what keeps IGMP snooping tables alive, and what multicast audio needs.",
                None))
        elif av_present:
            out.append(_finding(
                "net.querier", "warn" if lost else "bad",
                "No IGMP querier was heard on this VLAN",
                "No general query arrived during the listen, and there is multicast audio on this network. With "
                "snooping on and no querier, group memberships age out and the audio stops - usually a minute or "
                "two after everything looked fine."
                + (" The listen also dropped frames, so a query every couple of minutes could have been one of "
                   "them: scan again before acting on this." if lost else ""),
                "Enable the IGMP snooping querier on the switch that owns this VLAN (exactly one per VLAN), or "
                "give the VLAN a router interface that queries."))
        else:
            out.append(_finding(
                "net.querier", "info", "No IGMP querier is running on this VLAN",
                "No general query arrived during the listen. Nothing here needs one yet, because no multicast "
                "audio was found - but anything you add later will.",
                "Turn the IGMP snooping querier on before this network carries Dante or AES67."))
    flooded = l2.get("flooded") or []
    if flooded:
        heavy = [g for g in flooded if (g.get("mbps") or 0.0) >= FLOOD_WARN_MBPS]
        total = round(sum(g.get("mbps") or 0.0 for g in flooded), 2)
        out.append(_finding(
            "net.flood", "warn" if heavy else "info",
            f"{len(flooded)} multicast group(s) are reaching this port unasked",
            f"Traffic arrived for groups this PC never joined, {'at least ' if lost else ''}{total} Mb/s in total"
            + (f", including {len(heavy)} carrying media rates." if heavy else ", all of it at control rates.")
            + " Either IGMP snooping is off on this switch, or this port is being treated as a multicast router "
              "port.",
            "On an AV network this wastes the port's bandwidth and can swamp a slow device. Turn snooping on for "
            "this VLAN." if heavy else
            "Low-rate groups leaking to every port is common and mostly harmless, but it is the same mechanism "
            "that would flood audio here once there is any.",
            flooded[:12]))
    dscp = l2.get("dscp") or {}
    clock_dscp = dscp.get("ptp")
    audio_dscp = dscp.get("audio")
    # without AV traffic the "audio" bucket is whatever multicast this network happens to carry, and saying it is
    # badly marked would be reading a fault into a network that has nothing to mark
    if av_present and (clock_dscp is not None or audio_dscp is not None):
        bad_marks = []
        if clock_dscp is not None and clock_dscp == 0:
            bad_marks.append("clock packets arrive with DSCP 0")
        if audio_dscp is not None and audio_dscp == 0:
            bad_marks.append("audio packets arrive with DSCP 0")
        if bad_marks:
            sentence = " and ".join(bad_marks)
            out.append(_finding(
                "net.dscp", "warn", "AV traffic is arriving unmarked",
                sentence[:1].upper() + sentence[1:] + ". Something in the path has cleared the marking, or the "
                "sender never set it. Unmarked traffic falls into the default queue with everything else.",
                "Check that the switches trust DSCP on these ports rather than re-marking. Dante marks its clock "
                "56 and its audio 46; AES67 normally marks audio 46."))
        else:
            out.append(_finding(
                "net.dscp", "good", "AV traffic arrives correctly marked",
                f"Clock packets arrive with DSCP {clock_dscp}, audio with DSCP {audio_dscp}." if
                (clock_dscp is not None and audio_dscp is not None) else
                f"Observed DSCP: {clock_dscp if clock_dscp is not None else audio_dscp}.",
                None))

def _switch_findings(switch: Any, streams: List[Dict[str, Any]], out: List[Dict[str, Any]]) -> None:
    """Which switch and port this PC is on.  This comes from the switch-port lookup's LLDP neighbour and has
    nothing to do with the Layer 2 listen, so it is reported whether or not one ran."""
    if not isinstance(switch, dict) or not switch:
        return
    out.append(_finding(
        "net.switch", "info", f"This PC is on {switch.get('switch_name') or 'a switch'}",
        _switch_text(switch), None, switch))
    vlan = switch.get("vlan")
    if vlan is not None and streams:
        out.append(_finding(
            "net.vlan", "info", f"This port's untagged VLAN is {vlan}",
            "Audio announced here is what this port can see. If a stream you expected is missing, it is "
            "probably on a VLAN this port is not in.",
            None))


def _switch_text(switch: Dict[str, Any]) -> str:
    bits = []
    if switch.get("switch_description"):
        bits.append(str(switch["switch_description"]))
    if switch.get("port_id"):
        bits.append("port " + str(switch["port_id"]))
    if switch.get("vlan") is not None:
        bits.append("untagged VLAN " + str(switch["vlan"]))
    link = switch.get("link") or {}
    if link.get("text"):
        bits.append(str(link["text"]))
    poe = switch.get("poe") or {}
    if poe.get("allocated_w"):
        bits.append(f"{poe['allocated_w']} W of PoE allocated")
    return ", ".join(bits) if bits else "Heard through LLDP on this port."


def build_findings(clock: Any, streams: Any, devices: Any, *, l2: Any = None, switch: Any = None,
                   link_mbps: Optional[float] = None) -> List[Dict[str, Any]]:
    """Every check this module can make, worst first.

    ``l2`` is the Layer 2 listen's result (``{"igmp_seen", "querier", "flooded", "dscp", "lost"}``) or None; the four
    checks that need one are left out entirely when it is None, rather than reported as passing.  ``switch`` is the
    switch-port lookup's LLDP neighbour, which is a fact about this port rather than about the listen and is
    reported either way.  ``link_mbps`` is this adapter's link speed, used to turn announced bandwidth into a share
    of the link."""
    out: List[Dict[str, Any]] = []
    clock_view = clock if isinstance(clock, dict) else {}
    stream_list = [s for s in (streams or []) if isinstance(s, dict)]
    device_list = [d for d in (devices or []) if isinstance(d, dict)]
    _device_findings(device_list, out)
    _clock_findings(clock_view, device_list, out)
    _switch_findings(switch, stream_list, out)
    _stream_findings(stream_list, clock_view, device_list, link_mbps, out)
    if isinstance(l2, dict):
        av_present = bool(clock_view.get("heard") or stream_list
                          or any(d.get("vendor_kind") == "av" or d.get("family") not in ("other", "av")
                                 for d in device_list))
        _l2_findings(l2, stream_list, out, av_present)
    else:
        out.append(_finding(
            "net.l2", "info", "Multicast hygiene was not checked",
            "The Layer 2 listen was not run, so this scan cannot say whether there is an IGMP querier, whether "
            "groups are being flooded to this port, or how the traffic is marked.",
            "Run the scan with the Layer 2 listen turned on (it needs Windows administrator rights) to add those "
            "three checks."))
    out.sort(key=lambda f: _LEVEL_ORDER.get(f["level"], 9))
    return out


# ============================================================== graph

def _node(ident: str, kind: str, label: str, sub: Optional[str] = None, family: Optional[str] = None,
          level: Optional[str] = None, detail: Optional[str] = None) -> Dict[str, Any]:
    return {"id": ident, "kind": kind, "label": label, "sub": sub, "family": family, "level": level,
            "detail": detail}


def _edge(source: str, target: str, kind: str, label: Optional[str] = None) -> Dict[str, Any]:
    return {"source": source, "target": target, "kind": kind, "label": label}


CLOCK_NOTE = ("The clock tree is measured, not guessed: every line is something this PC heard. A switch appears only "
              "when it announced itself as a boundary clock.")
FLOW_NOTE = ("Talkers and streams come from the SAP announcements. Which devices are listening cannot be seen from "
             "one port without reading the switch's IGMP snooping table, so receivers are only shown where one was "
             "heard joining the group.")
NO_PHYSICAL_NOTE = ("This is not a wiring diagram. One PC hears LLDP from its own switch port and nothing about "
                    "anyone else's, so which device is in which port cannot be known from here.")


def build_graph(clock: Any, streams: Any, devices: Any, *, l2: Any = None,
                self_label: str = "This PC") -> Dict[str, Any]:
    """The two graphs the ProAV page draws: ``clock`` (the PTP tree) and ``flow`` (talkers, streams, listeners).

    Both are ``{"nodes", "edges", "note"}``.  Nodes carry a ``kind`` the UI styles on
    (``grandmaster``/``boundary``/``follower``/``self``/``talker``/``stream``/``listener``) and a ``level`` that
    colours a problem.  Deliberately not drawn: a physical topology - see :data:`NO_PHYSICAL_NOTE`."""
    clock_view = clock if isinstance(clock, dict) else {}
    stream_list = [s for s in (streams or []) if isinstance(s, dict) and not s.get("deleted")]
    device_list = [d for d in (devices or []) if isinstance(d, dict)]
    by_identity = {d.get("clock_identity"): d for d in device_list if d.get("clock_identity")}
    by_ip = {ip: d for d in device_list for ip in (d.get("ips") or [])}

    # ---------------- the clock tree
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    for index, domain in enumerate(clock_view.get("domains") or []):
        master = domain.get("master")
        domain_id = f"d{index}"
        if not master:
            continue
        gm_id = f"{domain_id}:gm"
        gm_device = by_identity.get(master.get("identity"))
        level = "good" if master.get("locked") is True else ("warn" if master.get("clock_class") == 248 else
                                                             ("bad" if master.get("locked") is False else None))
        nodes.append(_node(
            gm_id, "grandmaster",
            (gm_device or {}).get("name") or master.get("vendor") or master.get("mac") or master.get("identity"),
            f"Grandmaster - {master.get('time_source_text') or 'no named source'}",
            (gm_device or {}).get("family"), level,
            f"{_domain_name(domain)}, clock class {master.get('clock_class')}, "
            f"priority1 {master.get('priority1')}"))
        parent_id = gm_id
        steps = master.get("steps_removed") or 0
        if master.get("parent") and master.get("parent") != master.get("identity"):
            boundary_id = f"{domain_id}:bc"
            sender = next((s for s in (domain.get("senders") or [])
                           if s.get("identity") == master.get("parent")), {})
            bc_device = by_identity.get(master.get("parent"))
            nodes.append(_node(
                boundary_id, "boundary",
                (bc_device or {}).get("name") or sender.get("vendor") or master.get("parent_vendor")
                or master.get("parent_mac") or master.get("parent"),
                sender.get("ip") or f"Boundary clock - {steps} step(s) from the grandmaster", None, None,
                "This switch terminated the domain and served it again; it is what this PC times against."))
            edges.append(_edge(gm_id, boundary_id, "clock", f"{steps} step(s)"))
            parent_id = boundary_id
        elif steps > 0:
            boundary_id = f"{domain_id}:bc"
            nodes.append(_node(
                boundary_id, "boundary", f"{steps} boundary clock(s)",
                "Between the grandmaster and this PC", None, None,
                "The announcement's stepsRemoved says they are there; none of them named itself."))
            edges.append(_edge(gm_id, boundary_id, "clock", None))
            parent_id = boundary_id
        if domain.get("transparent"):
            nodes.append(_node(
                f"{domain_id}:tc", "transparent", "Transparent clock",
                f"correction up to {domain.get('correction_ns')} ns", None, None,
                "A switch timestamped these packets in transit."))
            edges.append(_edge(parent_id, f"{domain_id}:tc", "clock", None))
            parent_id = f"{domain_id}:tc"
        for follower in (domain.get("followers") or [])[:48]:
            device = by_identity.get(follower.get("identity"))
            follower_id = f"{domain_id}:f:{follower.get('identity')}"
            nodes.append(_node(
                follower_id, "follower",
                (device or {}).get("name") or follower.get("vendor") or follower.get("ip")
                or follower.get("identity"),
                follower.get("ip"), (device or {}).get("family"),
                None if follower.get("asking") else "warn",
                "Its delay requests are being answered" if follower.get("asking")
                else "Heard asking, but no reply to it was seen"))
            edges.append(_edge(parent_id, follower_id, "clock", None))
        self_id = f"{domain_id}:self"
        nodes.append(_node(self_id, "self", self_label, "Listening here", None, None, None))
        edges.append(_edge(parent_id, self_id, "clock", None))
    clock_plot = {"nodes": nodes, "edges": edges,
                  "note": CLOCK_NOTE if nodes else "No PTP clock was heard, so there is no tree to draw."}

    # ---------------- the flow map
    nodes = []
    edges = []
    listeners: Dict[str, List[str]] = {}
    for entry in ((l2 or {}).get("memberships") or []):
        group = entry.get("group")
        who = entry.get("ip")
        if group and who:
            listeners.setdefault(group, [])
            if who not in listeners[group]:
                listeners[group].append(who)
    for stream in stream_list[:MAX_STREAMS]:
        stream_key = f"s:{stream.get('id')}"
        rate = stream.get("bitrate_mbps")
        nodes.append(_node(
            stream_key, "stream", stream.get("name") or stream.get("id"),
            f"{stream.get('group')}:{stream.get('port')}", stream.get("family"), None,
            _stream_detail(stream)))
        talker_ip = stream.get("origin") or stream.get("source")
        if talker_ip:
            talker_key = f"t:{talker_ip}"
            device = by_ip.get(talker_ip)
            if not any(n["id"] == talker_key for n in nodes):
                nodes.append(_node(talker_key, "talker", (device or {}).get("name") or talker_ip, talker_ip,
                                   (device or {}).get("family"), None, (device or {}).get("vendor")))
            edges.append(_edge(talker_key, stream_key, "flow",
                               f"{rate} Mb/s" if rate else None))
        for who in listeners.get(stream.get("group") or "", []):
            listener_key = f"l:{who}"
            device = by_ip.get(who)
            if not any(n["id"] == listener_key for n in nodes):
                nodes.append(_node(listener_key, "listener", (device or {}).get("name") or who, who,
                                   (device or {}).get("family"), None, "Heard joining this group"))
            edges.append(_edge(stream_key, listener_key, "flow", None))
    flow_note = FLOW_NOTE if nodes else "No streams were announced, so there is no flow to draw."
    flow_plot = {"nodes": nodes, "edges": edges, "note": flow_note}
    return {"clock": clock_plot, "flow": flow_plot}


def _stream_detail(stream: Dict[str, Any]) -> Optional[str]:
    bits = []
    if stream.get("codec"):
        bits.append(str(stream["codec"]))
    if stream.get("rate"):
        bits.append(f"{int(stream['rate']) // 1000} kHz")
    if stream.get("channels"):
        bits.append(f"{stream['channels']} ch")
    if stream.get("ptime_ms"):
        bits.append(f"{stream['ptime_ms']} ms")
    if stream.get("bitrate_mbps"):
        bits.append(f"{stream['bitrate_mbps']} Mb/s")
    return ", ".join(bits) or None


# ============================================================== the scan

log = logging.getLogger(__name__)

SCAN_STATUS_KEYS = ("available", "reason", "adapters", "job", "last_run_ts", "limits")
JOB_KEYS = ("state", "adapter", "seconds", "deep", "started_ts", "elapsed_s", "phase", "pct", "counts",
            "listeners", "error", "reason", "generation", "ts")
RESULT_KEYS = ("ts", "seconds", "adapter", "link_mbps", "counts", "listeners", "clock", "streams", "services",
               "devices", "findings", "graph", "l2", "switch", "cancelled")
SCAN_ADAPTER_KEYS = ("name", "index", "mac", "ip", "type_name", "speed_mbps", "wifi", "is_internet")
LISTENER_KEYS = ("key", "label", "group", "port", "ok", "reason", "packets")
COUNTS_KEYS = ("mdns", "sap", "ptp", "frames", "devices", "streams")
L2_KEYS = ("ok", "reason", "frames", "lost", "igmp_seen", "querier", "memberships", "flooded", "dscp")
TILE_KEYS = ("available", "reason", "running", "pct", "devices", "streams", "clock", "worst", "last_run_ts")

SCAN_STATES = ("idle", "scanning", "done", "error", "cancelled")
#: Listen lengths the UI offers and the API accepts.  Thirty seconds is enough for two Announce intervals on every
#: profile in common use, and for a slow mDNS responder to answer twice.
SCAN_SECONDS = (10, 20, 30, 60, 120, 300)
DEFAULT_SECONDS = 30
MIN_SECONDS, MAX_SECONDS = 5, 600

EVENT = "proav.state"
PROGRESS_EVENT = "proav.progress"
THREAD_NAME = "tnt-proav"
L2_THREAD_NAME = "tnt-proav-l2"
SESSION_SUFFIX = "ProAV"

#: How often the worker wakes to check the clock and the cancel flag while nothing is arriving.
TICK_S = 0.25
#: Progress is published at most this often (the UI redraws on it).
PROGRESS_MIN_S = 0.4
#: When the mDNS questions go out, as a fraction of the listen.  Early ones catch fast responders, the later two
#: ask again for the service types the meta-query turned up.
QUERY_AT = (0.0, 0.04, 0.12, 0.40, 0.72)
#: Groups that are link-local by definition: traffic for these reaches every port on the VLAN by design, so it is
#: never reported as "flooded" (RFC 5771 clause 4: the Local Network Control Block is never snooped).
LINK_LOCAL_BLOCK = "224.0.0."
MAX_FLOODED = 64
#: Multicast groups that reach every port by design and say nothing about a switch's snooping: SSDP/UPnP discovery
#: and mDNS-over-IPv4's own alternates.  Flooding of *these* is not a finding; flooding of an audio group is.
EXPECTED_FLOOD_GROUPS = ("239.255.255.250", "239.255.255.253")
#: A flooded group carrying more than this is media, not a control protocol, and is worth a warning of its own.
FLOOD_WARN_MBPS = 1.0
MAX_MEMBERSHIPS = 512
MAX_QUERY_TYPES = 24

NOT_WINDOWS_REASON = "Pro AV scanning needs Windows"
NO_ADAPTER_REASON = "this PC has no network adapter that is up with an IPv4 address"
BUSY_TEXT = "a Pro AV scan is already running"
NO_LISTENER_TEXT = "none of the Pro AV multicast groups could be listened to on this adapter"
SECONDS_TEXT = f"seconds must be a whole number from {MIN_SECONDS} to {MAX_SECONDS}"
ADAPTER_TEXT = "that adapter is not available for a scan"


class ProAvUnavailable(RuntimeError):
    """A scan cannot start on this PC right now; the message says why."""


def _now_text(value: Any) -> Optional[str]:
    return _text(value, 120)


_SINCE_TEXT = "since_ts must be a time in seconds, or None for everything"


def _clear_since(value: Any) -> Optional[float]:
    """*value* as the start of a history clear: None (everything) or a finite time in seconds, else ``ValueError``.
    A NaN compares false with every time, so taken as it is a clear would silently keep everything."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(_SINCE_TEXT)
    try:
        since = float(value)
    except OverflowError:
        raise ValueError(_SINCE_TEXT) from None
    if not math.isfinite(since):
        raise ValueError(_SINCE_TEXT)
    return since


def _cleared_by(ts: Any, since_ts: Optional[float]) -> bool:
    """Whether something recorded at *ts* falls in a history clear from *since_ts* on (None: everything goes).  A
    time that cannot be read goes too: a result nobody can place is not one to keep."""
    if since_ts is None or isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return True
    return float(ts) >= float(since_ts)


def _socket_reason(exc: BaseException) -> str:
    """A plain-language reason a listener could not open."""
    name = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
    text = str(exc).strip() or type(exc).__name__
    return f"{text}" if name is None else f"{text} (error {name})"


class _Listener:
    """One joined multicast group: the socket, what it is for, and how much arrived on it."""

    def __init__(self, key: str, label: str, group: Optional[str], port: int) -> None:
        self.key, self.label, self.group, self.port = key, label, group, port
        self.sock: Optional[Any] = None
        self.ok = False
        self.reason: Optional[str] = None
        self.packets = 0

    def view(self) -> Dict[str, Any]:
        return {"key": self.key, "label": self.label, "group": self.group, "port": self.port, "ok": self.ok,
                "reason": self.reason, "packets": self.packets}

    def close(self) -> None:
        sock, self.sock = self.sock, None
        if sock is not None:
            try:
                sock.close()
            except Exception:       # noqa: BLE001 - closing a socket must never break a scan's clean-up
                pass


class _MdnsCollector:
    """Folds mDNS records into service instances: PTR names them, SRV places them, TXT describes them, A/AAAA
    addresses them.  A record can arrive in any order and in any section, so everything is merged by name."""

    def __init__(self) -> None:
        self.types: List[str] = []
        self.instances: Dict[str, Dict[str, Any]] = {}
        self.hosts: Dict[str, List[str]] = {}
        self.messages = 0

    def add(self, message: Dict[str, Any], src: Optional[str], ts: float) -> None:
        self.messages += 1
        for record in message.get("records") or []:
            kind, name, value = record.get("type"), record.get("name") or "", record.get("value")
            if kind == "PTR" and isinstance(value, str) and value:
                if name.rstrip(".") == _mdns.META_QUERY:
                    self._note_type(value.rstrip("."))
                else:
                    self._instance(value.rstrip("."), ts).setdefault("src", src)
                    self._note_type(name.rstrip("."))
            elif kind == "SRV" and isinstance(value, dict):
                entry = self._instance(name, ts)
                entry["host"] = (value.get("target") or "").rstrip(".") or None
                entry["port"] = value.get("port")
                entry.setdefault("src", src)
            elif kind == "TXT" and isinstance(value, dict):
                entry = self._instance(name, ts)
                for key, item in value.items():
                    entry["txt"].setdefault(key, item)
                entry.setdefault("src", src)
            elif kind in ("A", "AAAA") and isinstance(value, str):
                host = (name or "").rstrip(".")
                if host:
                    addresses = self.hosts.setdefault(host, [])
                    if value not in addresses:
                        addresses.append(value)

    def _note_type(self, service_type: str) -> None:
        if service_type and service_type not in self.types and len(self.types) < 256:
            self.types.append(service_type)

    def _instance(self, name: str, ts: float) -> Dict[str, Any]:
        key = name.rstrip(".")
        entry = self.instances.get(key)
        if entry is None:
            if len(self.instances) >= MAX_DEVICES:
                return {"txt": {}}          # a throwaway: past the cap nothing more is kept
            instance, service_type = _mdns.split_service(key)
            entry = {"instance": instance or key, "type": service_type, "host": None, "port": None, "txt": {},
                     "src": None, "ts": ts}
            self.instances[key] = entry
            self._note_type(service_type)
        entry["ts"] = ts
        return entry

    def unasked(self, asked: Iterable[str]) -> List[str]:
        """Service types the meta-query turned up that have not been asked about yet."""
        seen = {a.rstrip(".") for a in asked}
        return [t for t in self.types if t not in seen and t != _mdns.META_QUERY][:MAX_QUERY_TYPES]

    def services(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for entry in self.instances.values():
            if not entry.get("type"):
                continue
            ips = list(self.hosts.get(entry.get("host") or "", []))
            if entry.get("src") and entry["src"] not in ips:
                ips.append(entry["src"])
            out.append({"instance": entry.get("instance"), "type": entry.get("type"), "host": entry.get("host"),
                        "port": entry.get("port"), "txt": dict(entry.get("txt") or {}), "ips": ips,
                        "ts": float(entry.get("ts") or 0.0)})
        out.sort(key=lambda s: ((s["instance"] or "").lower(), s["type"] or ""))
        return out


def _group_mbps(group: Dict[str, Any]) -> Optional[float]:
    """A flooded group's rate over the span it was heard, or None when it was heard only once."""
    span = float(group.get("last_ts") or 0.0) - float(group.get("first_ts") or 0.0)
    if span <= 0.0:
        return None
    return round(float(group.get("bytes") or 0) * 8 / span / 1_000_000.0, 3)


class _L2Listener:
    """A bounded Layer 2 listen, for the three checks a UDP socket cannot make: is there an IGMP querier, is
    multicast being flooded to this port, and is the traffic marked.

    It runs its own real-time ETW session on the NDIS packet-capture provider, exactly as the packet capture does but
    under its own name, so the two can run together.  Without administrator rights (the service has them; a developer
    running the module by hand may not) :meth:`start` fails and the scan simply reports that these checks did not
    run - never that they passed."""

    def __init__(self, if_index: Optional[int], joined: Iterable[str]) -> None:
        self.if_index = if_index
        self.joined = {str(g) for g in joined}
        self.ok = False
        self.reason: Optional[str] = None
        self.frames = 0
        self.lost = 0                   # frames the capture session dropped because this PC could not keep up
        self.igmp_seen = 0
        self._trace: Optional[Any] = None
        self._lock = threading.Lock()
        self._querier: Optional[Dict[str, Any]] = None
        self._query_times: List[float] = []
        self._memberships: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._groups: Dict[str, Dict[str, Any]] = {}
        self._dscp: Dict[str, Dict[int, int]] = {"ptp": {}, "audio": {}}

    # -- lifecycle ---------------------------------------------------------------------------------
    def start(self) -> bool:
        try:
            etw = importlib.import_module("tnt.etw")
        except Exception as exc:        # noqa: BLE001
            self.reason = f"the capture engine could not be loaded ({type(exc).__name__})"
            return False
        available = {}
        try:
            available = etw.available() or {}
        except Exception:               # noqa: BLE001
            available = {}
        if not available.get("ok"):
            self.reason = available.get("reason") or "this PC cannot run a Layer 2 listen"
            return False
        try:
            trace = etw.TraceSession(etw.session_name(SESSION_SUFFIX),
                                     providers=((etw.NDIS_PACKET_CAPTURE_GUID, 5, 0xFFFFFFFFFFFFFFFF),))
            trace.start()
            trace.consume(self._on_event)
        except Exception as exc:        # noqa: BLE001 - the rest of the scan is worth having without this
            self.reason = str(exc) or "the Layer 2 listen could not start"
            log.debug("ProAV Layer 2 listen could not start", exc_info=True)
            try:
                if self._trace is not None:
                    self._trace.stop()
            except Exception:           # noqa: BLE001
                pass
            return False
        self._trace = trace
        self.ok = True
        return True

    def stop(self) -> None:
        trace, self._trace = self._trace, None
        if trace is None:
            return
        try:                            # what the session dropped, while it is still there to ask
            self.lost = int((trace.stats() or {}).get("lost_events") or 0)
        except Exception:               # noqa: BLE001 - a count is an extra, never a reason to leave a session up
            log.debug("the ProAV Layer 2 listen's statistics could not be read", exc_info=True)
        try:
            trace.stop(2.0)
        except Exception:               # noqa: BLE001
            log.debug("stopping the ProAV Layer 2 listen failed", exc_info=True)

    # -- frames ------------------------------------------------------------------------------------
    def _on_event(self, event: Dict[str, Any]) -> None:
        """The ETW consumer thread.  Never blocks and never raises: a bad frame must not end the listen."""
        try:
            etw = importlib.import_module("tnt.etw")
            frame = etw.decode_ndis_frame(event)
            if frame is None:
                return
            if self.if_index is not None and frame["if_index"] != self.if_index:
                return
            self.frames += 1
            self._ip_frame(frame["data"], float(frame["ts"]))
        except Exception:               # noqa: BLE001
            pass

    def _ip_frame(self, data: bytes, ts: float) -> None:
        if len(data) < 14:
            return
        at = 12
        ethertype = int.from_bytes(data[at:at + 2], "big")
        for _ in range(2):              # up to two VLAN tags, as tnt.lldp does
            if ethertype in (0x8100, 0x88A8) and len(data) >= at + 8:
                at += 4
                ethertype = int.from_bytes(data[at:at + 2], "big")
            else:
                break
        at += 2
        if ethertype != 0x0800 or len(data) < at + 20:
            return
        ihl = (data[at] & 0x0F) * 4
        if ihl < 20 or len(data) < at + ihl:
            return
        dscp = data[at + 1] >> 2
        protocol = data[at + 9]
        source = ".".join(str(b) for b in data[at + 12:at + 16])
        destination = ".".join(str(b) for b in data[at + 16:at + 20])
        body = at + ihl
        if protocol == 2:
            self._igmp(source, destination, data, body, ts)
            return
        if protocol != 17 or len(data) < body + 8:
            return
        destination_port = int.from_bytes(data[body + 2:body + 4], "big")
        if not destination.startswith(("2", "3")) or not _is_multicast(destination):
            return
        with self._lock:
            if destination_port in (319, 320):
                self._dscp["ptp"][dscp] = self._dscp["ptp"].get(dscp, 0) + 1
            elif destination_port not in (5353, 9875, 5355, 1900, 137, 138):
                self._dscp["audio"][dscp] = self._dscp["audio"].get(dscp, 0) + 1
            if (destination in self.joined or destination.startswith(LINK_LOCAL_BLOCK)
                    or destination in EXPECTED_FLOOD_GROUPS):
                return                  # asked for, link-local, or flooded by design: not a finding
            row = self._groups.get(destination)
            if row is None:
                if len(self._groups) >= MAX_FLOODED:
                    return
                row = {"group": destination, "port": destination_port, "source": source, "packets": 0,
                       "bytes": 0, "mbps": None, "first_ts": ts, "last_ts": ts}
                self._groups[destination] = row
            row["packets"] += 1
            row["bytes"] += len(data)
            row["last_ts"] = ts

    def _igmp(self, source: str, destination: str, data: bytes, at: int, ts: float) -> None:
        if len(data) < at + 8:
            return
        kind = data[at]
        with self._lock:
            self.igmp_seen += 1
            if kind == 0x11:            # a membership query; to 224.0.0.1 it is the general one a querier sends
                group = ".".join(str(b) for b in data[at + 4:at + 8])
                if group == "0.0.0.0" or destination == "224.0.0.1":
                    self._query_times.append(ts)
                    interval = None
                    if len(self._query_times) > 1:
                        gaps = [b - a for a, b in zip(self._query_times, self._query_times[1:]) if b > a]
                        interval = round(sum(gaps) / len(gaps), 1) if gaps else None
                    self._querier = {"ip": source, "interval_s": interval, "queries": len(self._query_times)}
            elif kind in (0x16, 0x12):  # a v1/v2 membership report: the group is in the header
                self._membership(source, ".".join(str(b) for b in data[at + 4:at + 8]), ts)
            elif kind == 0x22:          # a v3 report: one or more group records follow the header
                count = int.from_bytes(data[at + 6:at + 8], "big")
                offset = at + 8
                for _ in range(min(count, 32)):
                    if len(data) < offset + 8:
                        break
                    sources = int.from_bytes(data[offset + 2:offset + 4], "big")
                    self._membership(source, ".".join(str(b) for b in data[offset + 4:offset + 8]), ts)
                    offset += 8 + sources * 4 + data[offset + 1] * 4

    def _membership(self, who: str, group: str, ts: float) -> None:
        if not _is_multicast(group) or group.startswith(LINK_LOCAL_BLOCK):
            return
        key = (who, group)
        row = self._memberships.get(key)
        if row is None:
            if len(self._memberships) >= MAX_MEMBERSHIPS:
                return
            row = {"ip": who, "group": group, "reports": 0, "last_ts": ts}
            self._memberships[key] = row
        row["reports"] += 1
        row["last_ts"] = ts

    # -- result ------------------------------------------------------------------------------------
    def view(self) -> Dict[str, Any]:
        with self._lock:
            def common(name: str) -> Optional[int]:
                counts = self._dscp.get(name) or {}
                return max(counts, key=lambda k: counts[k]) if counts else None
            return {
                "ok": self.ok,
                "reason": self.reason,
                "frames": self.frames,
                "lost": self.lost,
                "igmp_seen": self.igmp_seen if self.ok else None,
                "querier": dict(self._querier) if self._querier else None,
                "memberships": sorted(self._memberships.values(), key=lambda m: (m["group"], m["ip"]))[:256],
                "flooded": sorted((dict(g, mbps=_group_mbps(g)) for g in self._groups.values()),
                                  key=lambda g: (-(g["mbps"] or 0.0), -g["packets"])),
                "dscp": {"ptp": common("ptp"), "audio": common("audio")},
            }


class ProAvScanner:
    r"""The engine component behind ``/api/proav``: one timed listen on the AV multicast groups, and the analysis of
    what arrived.

    A scan joins four groups on one adapter and reads for ``seconds``:

    ======================  ========  =================================================================
    group                   port      what it gives
    ======================  ========  =================================================================
    224.0.0.251             5353      mDNS / DNS-SD: every device that publishes a service
    239.255.255.255         9875      SAP: the AES67 / ST 2110 stream announcements
    224.2.127.254           9875      the original SAP group, for older gear
    224.0.1.129             319, 320  PTP: the whole clock tree, and everyone following it
    ======================  ========  =================================================================

    Only mDNS is asked a question; the other three are pure listening.  The question is the DNS-SD meta-query plus
    :data:`tnt.mdns.SEED_QUERIES`, repeated at :data:`QUERY_AT` through the listen, and once the meta-query has named
    the service types that are really here, those are asked about too.  Nothing is scanned, probed or connected to:
    a device that is never spoken to cannot be disturbed by this, which matters on a network carrying a live show.

    A listener that cannot open (its port already bound, multicast refused on the adapter) is recorded with the
    reason and the scan carries on with the others; a scan fails only when *no* listener opened.  With administrator
    rights a :class:`_L2Listener` also runs, which adds the IGMP querier, multicast-flooding and DSCP checks; without
    them the scan says those were not checked rather than that they passed.

    Shapes (keys in this order, :data:`SCAN_STATUS_KEYS`, :data:`JOB_KEYS`, :data:`RESULT_KEYS`,
    :data:`SCAN_ADAPTER_KEYS`, :data:`LISTENER_KEYS`, :data:`COUNTS_KEYS`, :data:`L2_KEYS`)::

        STATUS = {"available", "reason", "adapters": [ADAPTER], "job": JOB, "last_run_ts", "limits"}
        JOB    = {"state": "idle"|"scanning"|"done"|"error"|"cancelled", "adapter": ADAPTER|None, "seconds",
                  "deep", "started_ts", "elapsed_s", "phase", "pct", "counts": COUNTS, "listeners": [LISTENER],
                  "error", "reason", "generation", "ts"}
        RESULT = {"ts", "seconds", "adapter", "link_mbps", "counts", "listeners", "clock", "streams", "services",
                  "devices", "findings", "graph", "l2", "cancelled"}

    One scan runs at a time; a second :meth:`start` is refused with :data:`BUSY_TEXT`.  :meth:`cancel` ends the
    listen early and keeps what was heard (``RESULT["cancelled"]`` is True), which is what the Stop button does.
    :meth:`clear_history` (Settings > Clear history) forgets the result, and stops a running listen and throws away
    what it heard.

    Module-level seams that tests (and only tests) monkeypatch: ``_open_socket``, ``_adapter_list``, ``_arp_table``,
    ``_vendor_for_mac`` (in :mod:`tnt.ptp`) and ``_L2Listener``.  ``tnt.netinfo`` / ``tnt.arp`` / ``tnt.oui`` /
    ``tnt.etw`` are imported lazily, so the module loads and the pure half is usable without any of them."""

    def __init__(self, bus: Any = None, *, clock: Any = None, switch_fn: Any = None) -> None:
        self._bus = bus
        self._clock = clock or time.time
        self._switch_fn = switch_fn                 # optional: the LLDP neighbour of tnt.switchport, for the findings
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._generation = 0
        # the generation of a scan that was listening when the history was cleared: its result is thrown away
        self._discard_generation: Optional[int] = None
        self._last: Optional[Dict[str, Any]] = None
        self._last_run_ts: Optional[float] = None
        self._job: Dict[str, Any] = self._idle_job()
        self._progress_ts = 0.0

    # -- state -------------------------------------------------------------------------------------
    def _idle_job(self) -> Dict[str, Any]:
        return {"state": "idle", "adapter": None, "seconds": DEFAULT_SECONDS, "deep": True, "started_ts": None,
                "elapsed_s": 0.0, "phase": None, "pct": 0.0, "counts": self._zero_counts(), "listeners": [],
                "error": None, "reason": None, "generation": self._generation, "ts": float(self._clock())}

    @staticmethod
    def _zero_counts() -> Dict[str, Any]:
        return {"mdns": 0, "sap": 0, "ptp": 0, "frames": 0, "devices": 0, "streams": 0}

    @property
    def running(self) -> bool:
        with self._lock:
            return self._job.get("state") == "scanning"

    def job(self) -> Dict[str, Any]:
        with self._lock:
            job = dict(self._job)
        job["listeners"] = [dict(entry) for entry in job.get("listeners") or []]
        job["counts"] = dict(job.get("counts") or {})
        return job

    def last(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._last

    def limits(self) -> Dict[str, Any]:
        return {"seconds": list(SCAN_SECONDS), "default_seconds": DEFAULT_SECONDS, "min_seconds": MIN_SECONDS,
                "max_seconds": MAX_SECONDS}

    def status(self) -> Dict[str, Any]:
        adapters = self.adapters()
        reason = None
        if os.name != "nt":
            reason = NOT_WINDOWS_REASON
        elif not adapters:
            reason = NO_ADAPTER_REASON
        with self._lock:
            last_run = self._last_run_ts
        return {"available": reason is None, "reason": reason, "adapters": adapters, "job": self.job(),
                "last_run_ts": last_run, "limits": self.limits()}

    def tile(self) -> Dict[str, Any]:
        """The small dict the home tile shows, without the whole result behind it."""
        status = self.status()
        job = status["job"]
        last = self.last() or {}
        findings = last.get("findings") or []
        worst = None
        for level in FINDING_LEVELS:
            if any(f.get("level") == level for f in findings):
                worst = level
                break
        clock = ((last.get("clock") or {}).get("best") or {}).get("master") or {}
        return {"available": status["available"], "reason": status["reason"],
                "running": job["state"] == "scanning", "pct": job["pct"],
                "devices": len(last.get("devices") or []), "streams": len(last.get("streams") or []),
                "clock": clock.get("vendor") or clock.get("mac"), "worst": worst,
                "last_run_ts": status["last_run_ts"]}

    # -- adapters ----------------------------------------------------------------------------------
    def _adapter_list(self) -> List[Any]:
        try:
            return list(importlib.import_module("tnt.netinfo").get_adapters())
        except Exception:               # noqa: BLE001
            log.debug("adapter enumeration failed", exc_info=True)
            return []

    def _internet_index(self, adapters: List[Any]) -> Optional[int]:
        try:
            nic = importlib.import_module("tnt.netinfo").get_internet_nic(adapters)
            return getattr(nic, "index", None) if nic is not None else None
        except Exception:               # noqa: BLE001
            return None

    def adapters(self) -> List[Dict[str, Any]]:
        """Adapters a scan can listen on: up, physical, not loopback, and with an IPv4 address to join a group on."""
        adapters = self._adapter_list()
        internet = self._internet_index(adapters)
        out: List[Dict[str, Any]] = []
        for a in adapters:
            if getattr(a, "status", None) != "up" or getattr(a, "is_loopback", False):
                continue
            if not getattr(a, "is_physical", False):
                continue
            ip = getattr(a, "primary_ipv4", None)
            if not ip:
                continue
            speed = getattr(a, "speed_bps", None)
            out.append({"name": str(getattr(a, "name", "") or ""), "index": getattr(a, "index", None),
                        "mac": str(getattr(a, "mac", "") or ""), "ip": ip,
                        "type_name": str(getattr(a, "type_name", "") or ""),
                        "speed_mbps": int(speed / 1_000_000) if isinstance(speed, int) and speed > 0 else None,
                        "wifi": getattr(a, "if_type", None) == 71,
                        "is_internet": getattr(a, "index", None) == internet if internet is not None else False})
        out.sort(key=lambda a: (not a["is_internet"], a["wifi"], a["name"].lower()))
        return out

    def _pick_adapter(self, wanted: Any) -> Dict[str, Any]:
        adapters = self.adapters()
        if not adapters:
            raise ProAvUnavailable(NO_ADAPTER_REASON)
        if wanted in (None, ""):
            return adapters[0]
        text = str(wanted).strip().lower()
        for adapter in adapters:
            if adapter["name"].lower() == text or str(adapter["index"]) == text:
                return adapter
        raise ValueError(ADAPTER_TEXT)

    # -- publishing --------------------------------------------------------------------------------
    def _publish(self, event: str = EVENT) -> None:
        if self._bus is None:
            return
        try:
            self._bus.publish(event, {"job": self.job()})
        except Exception:               # noqa: BLE001
            log.exception("publishing %s failed", event)

    def _set(self, **fields: Any) -> None:
        with self._lock:
            self._job.update(fields)
            self._job["ts"] = float(self._clock())

    def _progress(self, phase: str, pct: float, *, force: bool = False) -> None:
        now = float(self._clock())
        self._set(phase=phase, pct=round(max(0.0, min(1.0, pct)), 4))
        if not force and now - self._progress_ts < PROGRESS_MIN_S:
            return
        self._progress_ts = now
        self._publish(PROGRESS_EVENT)

    # -- starting ----------------------------------------------------------------------------------
    def start(self, *, seconds: Any = None, adapter: Any = None, deep: Any = True) -> Dict[str, Any]:
        """Start a listen and return the JOB it created.  Raises ``ValueError`` for bad input,
        :class:`ProAvUnavailable` when this PC cannot scan, and ``RuntimeError`` when one is already running."""
        if os.name != "nt":
            raise ProAvUnavailable(NOT_WINDOWS_REASON)
        listen_s = DEFAULT_SECONDS if seconds in (None, "") else seconds
        if isinstance(listen_s, bool) or not isinstance(listen_s, (int, float)) or float(listen_s) != int(listen_s):
            raise ValueError(SECONDS_TEXT)
        listen_s = int(listen_s)
        if not MIN_SECONDS <= listen_s <= MAX_SECONDS:
            raise ValueError(SECONDS_TEXT)
        chosen = self._pick_adapter(adapter)
        with self._lock:
            if self._job.get("state") == "scanning":
                raise RuntimeError(BUSY_TEXT)
            self._generation += 1
            self._job = {"state": "scanning", "adapter": dict(chosen), "seconds": listen_s, "deep": bool(deep),
                         "started_ts": float(self._clock()), "elapsed_s": 0.0, "phase": "starting", "pct": 0.0,
                         "counts": self._zero_counts(), "listeners": [], "error": None, "reason": None,
                         "generation": self._generation, "ts": float(self._clock())}
            self._stop = threading.Event()
            stop = self._stop
            thread = threading.Thread(target=self._worker, name=THREAD_NAME,
                                      args=(dict(chosen), listen_s, bool(deep), stop, self._generation),
                                      daemon=True)
            self._thread = thread
        thread.start()
        log.info("Pro AV scan started on '%s' for %d s", chosen["name"], listen_s)
        self._publish()
        return self.job()

    def cancel(self) -> bool:
        """Ask a running listen to finish now and keep what it heard.  False when nothing was running."""
        with self._lock:
            if self._job.get("state") != "scanning":
                return False
            stop = self._stop
        stop.set()
        return True

    def close(self, timeout: float = 3.0) -> None:
        """Service shutdown: end a running listen and wait, bounded, for the worker to leave."""
        with self._lock:
            thread, stop = self._thread, self._stop
        stop.set()
        if thread is not None and thread.is_alive():
            thread.join(max(0.0, float(timeout)))

    def clear_history(self, since_ts: Optional[float]) -> Dict[str, Any]:
        """Settings > Clear history: ``{"cleared": int, "stopped": bool}``.

        The kept result goes when it was recorded (``RESULT["ts"]``, when the scan ended) at or after *since_ts*, or
        always when *since_ts* is None; a finished, failed or cancelled job that belongs to the cleared time goes back
        to idle with it.  A scan that is listening is stopped (``stopped``) and what it heard is thrown away when its
        worker finishes, by its generation, so it can never land after the clear; until then the job says it is still
        scanning, which it is.  ``proav.state`` is published, so the page and the tile read the change.  A *since_ts*
        that is neither None nor a finite time is refused with ``ValueError`` before anything changes."""
        since = _clear_since(since_ts)
        stop: Optional[threading.Event] = None
        with self._lock:
            state = self._job.get("state")
            cleared = 0
            if self._last is not None and _cleared_by(self._last.get("ts"), since):
                self._last = None
                self._last_run_ts = None
                cleared = 1
            if state == "scanning":
                self._discard_generation = self._job.get("generation")
                stop = self._stop
            elif state != "idle" and (cleared or _cleared_by(self._job.get("started_ts"), since)):
                self._job = self._idle_job()
        if stop is not None:
            stop.set()
        log.info("Pro AV: history cleared (%d result(s)%s)", cleared, ", a running scan stopped" if stop else "")
        self._publish()
        return {"cleared": cleared, "stopped": stop is not None}

    # -- listeners ---------------------------------------------------------------------------------
    def _open_socket(self, port: int, groups: Iterable[str], local_ip: str) -> Any:
        """A UDP socket bound to ``port`` with every group joined on ``local_ip``.

        ``SO_REUSEADDR`` is set before the bind because the ports here are shared by definition: Windows' own mDNS
        responder holds 5353, and more than one listener on a multicast port is the normal case.  Loopback of this
        socket's own sends is turned off so a query does not come back as an answer."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", int(port)))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            for group in groups:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                socket.inet_aton(group) + socket.inet_aton(local_ip))
            sock.setblocking(False)
        except Exception:
            try:
                sock.close()
            finally:
                pass
            raise
        return sock

    def _build_listeners(self, local_ip: str) -> List["_Listener"]:
        from . import ptp as _ptp
        wanted = [
            ("mdns", "Service discovery (mDNS)", [_mdns.GROUP_V4], _mdns.PORT),
            ("sap", "Stream announcements (SAP)", [SAP_GROUP_V4, SAP_GROUP_ADMIN], SAP_PORT),
            ("ptp-event", "Clock, event messages (PTP)", [_ptp.GROUP_V4, _ptp.PDELAY_GROUP_V4], _ptp.EVENT_PORT),
            ("ptp-general", "Clock, announcements (PTP)", [_ptp.GROUP_V4], _ptp.GENERAL_PORT),
        ]
        out: List[_Listener] = []
        for key, label, groups, port in wanted:
            listener = _Listener(key, label, groups[0], port)
            try:
                listener.sock = self._open_socket(port, groups, local_ip)
                listener.ok = True
            except Exception as exc:    # noqa: BLE001 - one group that will not open never ends the scan
                listener.reason = _socket_reason(exc)
                log.debug("ProAV listener %s could not open", key, exc_info=True)
            out.append(listener)
        return out

    # -- the listen --------------------------------------------------------------------------------
    def _worker(self, adapter: Dict[str, Any], seconds: int, deep: bool, stop: threading.Event,
                generation: int) -> None:
        started = float(self._clock())
        local_ip = adapter.get("ip") or "0.0.0.0"
        listeners = self._build_listeners(local_ip)
        collector = _MdnsCollector()
        tracker = None
        streams: Dict[str, Dict[str, Any]] = {}
        l2: Optional[_L2Listener] = None
        cancelled = False
        try:
            from . import ptp as _ptp
            tracker = _ptp.ClockTracker()
            self._set(listeners=[entry.view() for entry in listeners])
            if not any(entry.ok for entry in listeners):
                self._finish_error(generation, NO_LISTENER_TEXT,
                                   [entry.view() for entry in listeners])
                return
            if deep:
                joined = [g for entry in listeners if entry.ok for g in (entry.group,) if g]
                l2 = _L2Listener(adapter.get("index"), joined + [SAP_GROUP_ADMIN, _ptp.PDELAY_GROUP_V4])
                l2.start()
            self._progress("listening", 0.02, force=True)
            cancelled = self._listen(listeners, collector, tracker, streams, seconds, started, stop, local_ip)
            self._progress("building", 0.92, force=True)
        except Exception as exc:        # noqa: BLE001 - a scan must fail with a message, never with a traceback
            log.exception("the Pro AV scan failed")
            for entry in listeners:
                entry.close()
            if l2 is not None:
                l2.stop()
            self._finish_error(generation, str(exc) or "the scan failed",
                               [entry.view() for entry in listeners])
            return
        for entry in listeners:
            entry.close()
        if l2 is not None:
            l2.stop()
        try:
            result = self._build_result(adapter, seconds, started, listeners, collector, tracker, streams, l2,
                                        cancelled)
        except Exception as exc:        # noqa: BLE001
            log.exception("building the Pro AV result failed")
            self._finish_error(generation, str(exc) or "the scan result could not be built",
                               [entry.view() for entry in listeners])
            return
        with self._lock:
            if self._job.get("generation") != generation:
                return                  # a newer scan started while this one was finishing: its state wins
            discarded = self._discarded_locked(generation)
            if not discarded:
                self._last = result
                self._last_run_ts = result["ts"]
                self._job.update({"state": "cancelled" if cancelled else "done", "phase": "done", "pct": 1.0,
                                  "elapsed_s": round(float(self._clock()) - started, 2),
                                  "counts": dict(result["counts"]), "listeners": list(result["listeners"]),
                                  "ts": float(self._clock())})
        if discarded:
            log.info("Pro AV scan stopped and thrown away: the history was cleared while it listened")
        else:
            log.info("Pro AV scan finished: %d device(s), %d stream(s), %d finding(s)",
                     len(result["devices"]), len(result["streams"]), len(result["findings"]))
        self._publish()

    def _discarded_locked(self, generation: int) -> bool:
        """Whether the scan of *generation* was listening when the history was cleared; if so the job goes back to
        idle and nothing it heard is kept (the caller holds the lock and has checked the generation is current)."""
        if self._discard_generation != generation:
            return False
        self._discard_generation = None
        self._job = self._idle_job()
        return True

    def _finish_error(self, generation: int, message: str, listeners: List[Dict[str, Any]]) -> None:
        with self._lock:
            if self._job.get("generation") != generation:
                return
            if not self._discarded_locked(generation):
                self._job.update({"state": "error", "phase": "error", "error": _now_text(message),
                                  "listeners": listeners, "ts": float(self._clock())})
        self._publish()

    def _listen(self, listeners: List["_Listener"], collector: "_MdnsCollector", tracker: Any,
                streams: Dict[str, Dict[str, Any]], seconds: int, started: float, stop: threading.Event,
                local_ip: str) -> bool:
        """The read loop.  True when it ended because :meth:`cancel` was called."""
        by_socket = {entry.sock: entry for entry in listeners if entry.ok and entry.sock is not None}
        mdns_listener = next((entry for entry in listeners if entry.key == "mdns" and entry.ok), None)
        asked: List[str] = []
        sent = 0
        counts = self._zero_counts()
        while True:
            now = float(self._clock())
            elapsed = now - started
            if stop.is_set():
                return True
            if elapsed >= seconds:
                return False
            # the questions go out on a schedule through the listen; the later ones ask about what the meta-query found
            while sent < len(QUERY_AT) and elapsed >= QUERY_AT[sent] * seconds:
                names = list(_mdns.SEED_QUERIES) if sent < 2 else collector.unasked(asked)
                self._ask(mdns_listener, names, local_ip)
                asked.extend(names)
                sent += 1
            ready: List[Any] = []
            if by_socket:
                try:
                    ready, _, _ = select.select(list(by_socket), [], [], TICK_S)
                except (OSError, ValueError):
                    ready = []
            else:
                stop.wait(TICK_S)
            for sock in ready:
                entry = by_socket.get(sock)
                if entry is None:
                    continue
                for _ in range(64):     # drain what is queued before going back to select
                    try:
                        payload, address = sock.recvfrom(9000)
                    except (BlockingIOError, InterruptedError):
                        break
                    except OSError:
                        break
                    entry.packets += 1
                    self._handle(entry.key, payload, address[0] if address else None, float(self._clock()),
                                 collector, tracker, streams, counts)
            counts["mdns"] = collector.messages
            counts["ptp"] = getattr(tracker, "messages", 0)
            counts["streams"] = len(streams)
            self._set(elapsed_s=round(elapsed, 2), counts=dict(counts),
                      listeners=[entry.view() for entry in listeners])
            self._progress("listening", 0.02 + 0.88 * (elapsed / max(1, seconds)))

    def _ask(self, listener: Optional["_Listener"], names: List[str], local_ip: str) -> None:
        if listener is None or listener.sock is None or not names:
            return
        try:
            listener.sock.sendto(_mdns.build_query(names), (_mdns.GROUP_V4, _mdns.PORT))
        except OSError:
            log.debug("the mDNS question could not be sent", exc_info=True)

    def _handle(self, key: str, payload: bytes, src: Optional[str], ts: float, collector: "_MdnsCollector",
                tracker: Any, streams: Dict[str, Dict[str, Any]], counts: Dict[str, Any]) -> None:
        try:
            if key == "mdns":
                message = _mdns.parse(payload)
                if message is not None and message.get("records"):
                    collector.add(message, src, ts)
            elif key == "sap":
                self._handle_sap(payload, src, ts, streams, counts)
            else:
                tracker.add(payload, ts, src_ip=src)
        except Exception:               # noqa: BLE001 - one malformed packet never ends a listen
            log.debug("a %s packet could not be read", key, exc_info=True)

    def _handle_sap(self, payload: bytes, src: Optional[str], ts: float, streams: Dict[str, Dict[str, Any]],
                    counts: Dict[str, Any]) -> None:
        header = parse_sap(payload)
        if header is None:
            return
        counts["sap"] = counts.get("sap", 0) + 1
        stream = parse_sdp(header["body"], source=header.get("source") or src, ts=ts,
                           deleted=bool(header.get("deletion")))
        if stream is None:
            return
        existing = streams.get(stream["id"])
        if existing is None:
            if len(streams) >= MAX_STREAMS:
                return
            streams[stream["id"]] = stream
            return
        existing["count"] += 1
        existing["last_ts"] = ts
        existing["deleted"] = bool(header.get("deletion"))
        for field in ("name", "codec", "rate", "channels", "depth", "ptime_ms", "refclk", "refclk_domain",
                      "packet_bytes", "bitrate_mbps", "origin", "scope", "direction", "mediaclk"):
            if stream.get(field) is not None:
                existing[field] = stream[field]

    # -- the result --------------------------------------------------------------------------------
    def _arp_table(self) -> Dict[str, str]:
        try:
            return dict(importlib.import_module("tnt.arp").get_arp_table())
        except Exception:               # noqa: BLE001
            log.debug("the ARP table could not be read", exc_info=True)
            return {}

    def _vendor_lookup(self) -> Any:
        try:
            return importlib.import_module("tnt.oui").vendor_for_mac
        except Exception:               # noqa: BLE001
            return lambda _mac: None

    def _switch(self) -> Any:
        if self._switch_fn is None:
            return None
        try:
            return self._switch_fn()
        except Exception:               # noqa: BLE001
            log.debug("the switch-port neighbour could not be read", exc_info=True)
            return None

    def _build_result(self, adapter: Dict[str, Any], seconds: int, started: float, listeners: List["_Listener"],
                      collector: "_MdnsCollector", tracker: Any, streams: Dict[str, Dict[str, Any]],
                      l2: Optional["_L2Listener"], cancelled: bool) -> Dict[str, Any]:
        clock = tracker.view()
        stream_list = sorted(streams.values(), key=lambda s: (s.get("deleted"), (s.get("name") or "").lower()))
        services = collector.services()
        devices = build_devices(services, clock, stream_list, arp=self._arp_table(),
                                vendor_lookup=self._vendor_lookup())
        l2_view = l2.view() if (l2 is not None and l2.ok) else None
        switch = self._switch()
        link_mbps = adapter.get("speed_mbps")
        findings = build_findings(clock, stream_list, devices, l2=l2_view, switch=switch,
                                  link_mbps=float(link_mbps) if link_mbps else None)
        graph = build_graph(clock, stream_list, devices, l2=l2_view,
                            self_label=adapter.get("name") or "This PC")
        counts = {"mdns": collector.messages, "sap": sum(1 for _ in stream_list),
                  "ptp": int(clock.get("messages") or 0), "frames": (l2.frames if l2 is not None else 0),
                  "devices": len(devices), "streams": len(stream_list)}
        return {
            "ts": float(self._clock()),
            "seconds": seconds,
            "adapter": dict(adapter),
            "link_mbps": link_mbps,
            "counts": counts,
            "listeners": [entry.view() for entry in listeners],
            "clock": clock,
            "streams": stream_list,
            "services": services,
            "devices": devices,
            "findings": findings,
            "graph": graph,
            "l2": l2_view if l2_view is not None else ({"ok": False, "reason": l2.reason, "frames": 0, "lost": 0,
                                                        "igmp_seen": None, "querier": None, "memberships": [],
                                                        "flooded": [], "dscp": {"ptp": None, "audio": None}}
                                                       if l2 is not None else None),
            "switch": switch,
            "cancelled": cancelled,
        }
