r"""NAT check for the Network info page: is this site behind no NAT, one NAT, a double NAT or a carrier-grade NAT?

Read-only toward the router, always.  The only traffic is:

* NAT-PMP opcode 0, "external address" (RFC 6886 §3.2), UDP to the gateway's port 5351;
* one SSDP ``M-SEARCH`` for ``InternetGatewayDevice:1`` (UPnP Device Architecture 1.1 §1.3.2), unicast to the gateway
  first and then to 239.255.255.250 with multicast TTL 2, from an ephemeral port bound to the internet adapter;
* the UPnP description GET (UDA 1.1 §2) and SOAP ``GetStatusInfo``, ``GetExternalIPAddress`` and
  ``GetGenericPortMappingEntry`` (UDA 1.1 §3; UPnP IGD WANIPConnection:1/:2 and WANPPPConnection:1 service
  templates), only ever to the gateway's own address;
* ICMP echo toward this site's own public address with TTL 1-6 (time exceeded, RFC 792), only when the router
  reported no usable WAN address.

Never PCP, MAP, AddPortMapping, DeletePortMapping, SUBSCRIBE or STUN (:data:`SOAP_ACTIONS` is the whole list).

:func:`check_nat` runs the probes and decides; :class:`NatChecker` is the engine component behind
``GET``/``POST /api/netcheck/nat``: one run at a time, a fresh public address first, a short throttle, the last
result per network.

Shapes (keys in this order; :data:`NAT_RESULT_KEYS`, :data:`ROUTER_KEYS`, :data:`NATPMP_KEYS`, :data:`UPNP_KEYS`,
:data:`TRACE_KEYS`, :data:`HOP_KEYS`, :data:`PORT_MAPPINGS_KEYS`, :data:`MAPPING_KEYS`)::

    NAT_RESULT    = {"ts", "generation", "duration_ms", "verdict": NAT_VERDICTS,
                     "confidence": "high"|"medium"|"low"|None,
                     "title", "explanation", "router": ROUTER, "public_ip": str|None, "trace": TRACE|None,
                     "port_mappings": PORT_MAPPINGS|None, "error": str|None}
    ROUTER        = {"gateway": IPv4|None, "wan_ip": IPv4|None, "wan_source": "upnp"|"natpmp"|None,
                     "natpmp": {"answered", "result": int|None, "external_ip": IPv4|None},
                     "upnp": {"found", "server", "model", "service", "status", "external_ip", "error"}}
    TRACE         = {"reached_ttl": int|None, "hops": [{"ttl", "ip", "rtt_ms", "range"}]}
    PORT_MAPPINGS = {"entries": [{"protocol", "external_port", "internal_client", "internal_port", "enabled",
                                  "description", "lease_s"}], "truncated", "error"}

``confidence`` is None for ``offline`` and ``unknown``; ``range`` is :func:`range_of` (``"private"``, ``"shared"``,
``"reserved"``, ``"public"`` or None); ``trace`` is None when the trace did not run.  Device text is capped:
``server`` 120, ``model`` 80, mapping descriptions 80 characters.  ``title``/``explanation`` are :data:`NAT_TEXT`.

Address ranges (:data:`NAT_RANGES`, checked in this order, never ``ipaddress.is_private``/``is_global``): private
RFC 1918; shared RFC 6598 100.64/10 plus the DS-Lite 192.0.0.0/29 (RFC 6333); reserved 0/8, 127/8, 169.254/16,
192.0.0.0/24, 198.18/15, 224/4, 240/4 (RFC 6890); public is everything else, the RFC 5737 documentation ranges
included.

Safety toward the router (it is untrusted: any LAN device can answer a search, and this runs as LocalSystem):

* an SSDP reply counts only from the gateway's address, as ``HTTP/1.1 200``, with a LOCATION of at most 512
  characters that is ``http://<the gateway's own IPv4 literal>[:port]/...``;
* every HTTP request (description and SOAP) goes through :func:`_http_connection` to ``(gateway, port)`` with only
  the path and query; the resolved control URL must pass the same check (``URLBase`` and absolute control URLs
  included), and the 404 host-root retry too; a 3xx is a failure and never followed; the whole reply -- status
  line, headers and body -- is read under a wall-clock deadline (``min(http_timeout_s, time left)``), a body
  over 256 KiB is abandoned, and a body with ``<!DOCTYPE``/``<!ENTITY`` is refused before ElementTree sees it.

Seams: :func:`_udp_socket` (NAT-PMP and SSDP) and :func:`_http_connection` are looked up as module globals at call
time; tests/conftest.py makes both fail for the whole test session.  Timing knobs are keyword-only arguments that
default to the contract values (``budget_s`` ... ``trace_timeout_ms``; ``refresh_wait_s``/``throttle_s``), with
``clock`` (wall time) and ``monotonic`` injectable; the engine uses the defaults.

Contract gaps filled here:

* An internet adapter without an IPv4 address of its own skips SSDP (there is nothing to bind the search to).
* ``upnp.found`` means the gateway answered the SSDP search; ``upnp.error`` stays None for failures the contract
  names no text for (the description or a SOAP call failing), which are logged at DEBUG.  ``port_mappings`` is None
  whenever no connection service was chosen, so the UI never reads "none listed" for a walk that could not run.
* SSDP reads at least the MX (2 s) even when ``ssdp_read_s`` is smaller, but never past the check's deadline; a
  ``ConnectionResetError`` (an ICMP port unreachable after the unicast search) or an oversized datagram does not
  end the read, since some routers answer only the multicast search.
* A LOCATION or control URL with user info, or with a control character or space in its path, is refused; a body
  containing a NUL byte (UTF-16 or UTF-32 would slip past the ``<!DOCTYPE`` byte check) is refused like a DOCTYPE.
* Requests also send ``Connection: close``.  The once-per-run 404 retry is spent only when a host-root request is
  actually sent (a control URL already in host-root form has nothing to retry); that service keeps the host-root
  form for its later calls unless the retry failed too.  A WWAN adapter (if_type 237/243/244) is never a VPN, even
  when its description carries a VPN word.  "Faults 606, HTTP 401/403 or 501" take 501 as either the UPnP errorCode or the HTTP status.  A walk
  counts as truncated when it stops on its cap or when its deadline ran out (a call that timed out with no walk time
  left); another failure just ends it.  Two entries repeat when every field (``NewRemoteHost`` included) matches.
* :class:`NatChecker` keeps a result only when no :meth:`NatChecker.on_network_change` came in during the run and
  the generation still matches; the throttle compares the kept result's ``ts`` with ``clock``.  A refresh helper
  thread that is still running from an earlier run is waited on again instead of starting a second one.

Logging: INFO carries verdicts, confidences, durations and counts only; addresses, the public IP and device names are
logged at DEBUG.
"""
from __future__ import annotations

import copy
import http.client
import importlib
import io
import ipaddress
import logging
import socket
import struct
import threading
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlsplit
from xml.sax.saxutils import escape

from . import __version__

log = logging.getLogger(__name__)

__all__ = [
    "check_nat", "NatChecker", "range_of", "evaluate_verdict", "ssdp_request", "soap_envelope", "parse_natpmp_reply",
    "NAT_VERDICTS", "NAT_RESULT_KEYS", "ROUTER_KEYS", "NATPMP_KEYS", "UPNP_KEYS", "TRACE_KEYS", "HOP_KEYS",
    "PORT_MAPPINGS_KEYS", "MAPPING_KEYS", "CONFIDENCES", "NAT_TEXT", "NAT_RANGES", "SERVICE_TYPES", "SOAP_ACTIONS",
    "NO_INTERNET_ERROR", "NO_PUBLIC_IP_ERROR", "NO_GATEWAY_ERROR", "CONTROL_NOT_ROUTER_ERROR",
    "MAPPINGS_NOT_SHARED_ERROR", "BUSY_TEXT", "DEFAULT_USER_AGENT", "NATPMP_REQUEST",
]

# --- shapes -------------------------------------------------------------------------------------
NAT_VERDICTS = ("no_nat", "single_nat", "double_nat", "cgnat", "upstream_nat", "nat_unclear_private_wan",
                "vpn", "offline", "unknown")
NAT_RESULT_KEYS = ("ts", "generation", "duration_ms", "verdict", "confidence", "title", "explanation", "router",
                   "public_ip", "trace", "port_mappings", "error")
ROUTER_KEYS = ("gateway", "wan_ip", "wan_source", "natpmp", "upnp")   # wan_source "upnp"|"natpmp"|None
NATPMP_KEYS = ("answered", "result", "external_ip")
UPNP_KEYS = ("found", "server", "model", "service", "status", "external_ip", "error")
TRACE_KEYS = ("reached_ttl", "hops")                                  # trace is None when the trace did not run
HOP_KEYS = ("ttl", "ip", "rtt_ms", "range")          # range "private"|"shared"|"reserved"|"public"|None
PORT_MAPPINGS_KEYS = ("entries", "truncated", "error")               # port_mappings is None when UPnP was not found
MAPPING_KEYS = ("protocol", "external_port", "internal_client", "internal_port", "enabled", "description", "lease_s")
CONFIDENCES = ("high", "medium", "low")                               # confidence None for offline/unknown

#: ``NAT_TEXT[verdict] = (title, explanation)``: the UI shows these verbatim and the mock mirrors them.
NAT_TEXT: Dict[str, Tuple[str, str]] = {
    "no_nat": ("No NAT", "This PC has the public address itself. Nothing to forward: Windows Firewall decides what "
                         "gets in."),
    "single_nat": ("Single NAT", "One router holds the public address. Port forwards on it work, unless the ISP "
                                 "blocks the port."),
    "double_nat": ("Double NAT", "Another NAT sits between this network's router and the internet (usually the ISP "
                                 "modem or gateway, sometimes the ISP itself). Forward ports on both, or put the ISP "
                                 "box in bridge / IP-passthrough mode."),
    "cgnat": ("Carrier-grade NAT (CGNAT)", "The ISP shares one public address between customers, so port forwarding "
                                           "from the internet cannot work on IPv4. Ask the ISP for a public or "
                                           "static IP, or use the device's cloud/P2P service or a VPN."),
    "upstream_nat": ("NAT beyond the router", "Websites see an address the router does not have, so something beyond "
                                              "it translates again (ISP NAT, an upstream firewall, a second line or "
                                              "a VPN)."),
    "nat_unclear_private_wan": ("Probably behind another NAT", "The router reports no usable public address although "
                                                               "the internet works. That usually means it sits "
                                                               "behind another NAT."),
    "vpn": ("Traffic leaves through a VPN", "This PC's internet traffic goes through a VPN, so a check would describe "
                                            "the VPN, not this site's router. Disconnect it and check again."),
    "offline": ("Could not check", "No internet connection (or no public address yet), so NAT cannot be checked."),
    "unknown": ("Could not tell", "The router does not answer UPnP or NAT-PMP and the path gave no clear sign."),
}

NO_INTERNET_ERROR = "no internet connection"
NO_PUBLIC_IP_ERROR = "no public address yet"
NO_GATEWAY_ERROR = "no IPv4 gateway"
CONTROL_NOT_ROUTER_ERROR = "the router's control address is not the router"
MAPPINGS_NOT_SHARED_ERROR = "the router does not share its port forwards"
BUSY_TEXT = "a NAT check is already running"

#: Explicit networks per range, checked in this order; anything else is ``"public"``.  ``ui/js/netcheck.js``
#: ``rangeOf`` mirrors them.
NAT_RANGES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("private", ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),                        # RFC 1918
    ("shared", ("100.64.0.0/10", "192.0.0.0/29")),                                         # RFC 6598, RFC 6333 DS-Lite
    ("reserved", ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "198.18.0.0/15", "224.0.0.0/4",
                  "240.0.0.0/4")),                                                         # RFC 6890
)
_RANGE_NETWORKS = tuple((name, tuple(ipaddress.IPv4Network(n) for n in nets)) for name, nets in NAT_RANGES)

# --- protocol constants ---------------------------------------------------------------------------
NATPMP_PORT = 5351
#: Version 0, opcode 0 (external address request), RFC 6886 §3.2.
NATPMP_REQUEST = b"\x00\x00"
NATPMP_READ_MAX = 1100
SSDP_PORT = 1900
SSDP_MULTICAST = "239.255.255.250"
SSDP_MX = 2
SSDP_TTL = 2
SSDP_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
SSDP_DATAGRAM_MAX = 2048
#: Stray socket errors (ICMP port unreachable, an oversized datagram) one SSDP read tolerates before giving up.
SSDP_STRAY_ERRORS_MAX = 16
_WSAEMSGSIZE = 10040
#: Connection services in order of preference (IGD:2 first); the exact URNs are the only ones ever put in a SOAP call.
SERVICE_TYPES = ("urn:schemas-upnp-org:service:WANIPConnection:2", "urn:schemas-upnp-org:service:WANIPConnection:1",
                 "urn:schemas-upnp-org:service:WANPPPConnection:1")
#: The only SOAP actions this module can build: all of them read, none changes the router.
SOAP_ACTIONS = ("GetStatusInfo", "GetExternalIPAddress", "GetGenericPortMappingEntry")
MAX_SERVICES = 4
CONNECTED_STATES = ("Connected", "Up")
URL_MAX = 512
HTTP_BODY_MAX = 256 * 1024
HTTP_CHUNK = 16 * 1024
SERVER_MAX = 120
MODEL_MAX = 80
DESCRIPTION_MAX = 80
STATUS_MAX = 32
EXTERNAL_IP_MAX = 45
CLIENT_MAX = 64
#: A step (NAT-PMP, SSDP, an HTTP call, the walk) is skipped when less than this much of the budget is left.
MIN_STEP_S = 0.25
#: The trace sends TTL n only while ``trace_timeout_ms/1000 + TRACE_MARGIN_S`` is left.
TRACE_MARGIN_S = 0.1
TRACE_SIZE = 32
DEFAULT_USER_AGENT = f"Windows/10.0 UPnP/1.1 TNT/{__version__}"
_SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
_SOAP_ENCODING = "http://schemas.xmlsoap.org/soap/encoding/"
_VPN_IF_TYPES = (23, 53, 131)          # PPP (Windows' own VPN client), the two tunnel types
_WWAN_IF_TYPES = (237, 243, 244)       # WiMAX and mobile broadband: never a VPN, whatever the description says
_VPN_MARKERS =("vpn", "tap-windows", "wintun", "wireguard", "openvpn", "anyconnect", "pangp", "fortinet", "juniper",
                "pulse secure", "ivanti", "zscaler", "virtual")
_HYPERVISOR_MARKERS = ("hyper-v", "vmware", "virtualbox")
_RAISE = {"low": "medium", "medium": "high", "high": "high"}


# --- module seams -----------------------------------------------------------------------------------
def _udp_socket(family: int, type: int) -> socket.socket:  # noqa: A002 - the socket module's own parameter name
    """Every UDP socket (NAT-PMP and SSDP).  The module seam: tests/conftest.py makes it fail."""
    return socket.socket(family, type)


def _http_connection(host: str, port: int, timeout: float) -> http.client.HTTPConnection:
    """Every HTTP connection to the router: ``http.client`` (which never uses a proxy or follows a redirect), whose
    reply :func:`check_nat` reads under a deadline.  The module seam: tests/conftest.py makes it fail."""
    return _RouterConnection(host, port, timeout)


# --- small helpers ------------------------------------------------------------------------------------
def _ipv4(value: Any) -> Optional[str]:
    """*value* when it is an IPv4 literal in dotted-quad form, else None.  Never raises."""
    if not isinstance(value, str):
        return None
    try:
        text = str(ipaddress.IPv4Address(value))
    except ValueError:
        return None
    return text if text == value else None


def range_of(ip: Any) -> Optional[str]:
    """``"private"``, ``"shared"``, ``"reserved"`` or ``"public"`` for an IPv4 literal (:data:`NAT_RANGES`), None for
    anything else (None, IPv6, text).  Never raises."""
    text = _ipv4(ip)
    if text is None:
        return None
    addr = ipaddress.IPv4Address(text)
    for name, networks in _RANGE_NETWORKS:
        if any(addr in net for net in networks):
            return name
    return "public"


def _clean(value: Any, cap: int) -> Optional[str]:
    """Device text: control characters become spaces, stripped, at most *cap* characters; None when empty."""
    if value is None:
        return None
    text = "".join(ch if ch.isprintable() else " " for ch in str(value)).strip()[:cap].strip()
    return text or None


def _close(sock: Any) -> None:
    if sock is not None:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass


def _local(tag: Any) -> str:
    """The local name of an ElementTree tag (``{namespace}name`` -> ``name``)."""
    return str(tag).rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _child_text(element: Optional[ET.Element], name: str) -> str:
    """Stripped text of the first direct child of *element* with local name *name*, else ``""``."""
    if element is None:
        return ""
    for child in element:
        if _local(child.tag) == name:
            return (child.text or "").strip()
    return ""


def _find_text(root: Optional[ET.Element], name: str) -> Optional[str]:
    """Stripped text of the first element anywhere under *root* with local name *name*; None when there is none."""
    if root is None:
        return None
    for element in root.iter():
        if _local(element.tag) == name:
            return (element.text or "").strip()
    return None


def _int(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _bool(value: Any) -> Optional[bool]:
    text = str(value or "").strip().lower()
    if text in ("1", "true", "yes"):
        return True
    if text in ("0", "false", "no"):
        return False
    return None


# --- NAT-PMP (RFC 6886) ---------------------------------------------------------------------------------
def parse_natpmp_reply(data: Any) -> Optional[Dict[str, Any]]:
    """NATPMP dict for an external-address response: exactly 12 bytes, version 0, opcode ``0x80``; ``result`` is the
    u16 at offset 2 and ``external_ip`` the address in bytes 8-12 when the result is 0.  None for anything else."""
    if not isinstance(data, (bytes, bytearray)) or len(data) != 12 or data[0] != 0 or data[1] != 0x80:
        return None
    result = struct.unpack_from("!H", data, 2)[0]
    external = str(ipaddress.IPv4Address(bytes(data[8:12]))) if result == 0 else None
    return {"answered": True, "result": result, "external_ip": external}


# --- SSDP (UDA 1.1 §1.3) ----------------------------------------------------------------------------------
def ssdp_request(host: str, *, multicast: bool, user_agent: str = DEFAULT_USER_AGENT) -> bytes:
    """The ``M-SEARCH`` for an Internet Gateway Device: unicast to ``<gateway>:1900`` without MX, multicast to
    239.255.255.250:1900 with ``MX: 2``."""
    lines = ["M-SEARCH * HTTP/1.1", f"HOST: {host}:{SSDP_PORT}", 'MAN: "ssdp:discover"']
    if multicast:
        lines.append(f"MX: {SSDP_MX}")
    lines += [f"ST: {SSDP_ST}", f"USER-AGENT: {user_agent}"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii", "replace")


def _router_url(url: Any, gateway: str) -> Optional[Tuple[int, str]]:
    """``(port, path?query)`` when *url* is ``http://<gateway>[:port]/...`` with *gateway*'s own IPv4 literal as the
    host and a port of 1-65535 (80 when absent); None otherwise (another host, a name, https, user info, a path with
    spaces or control characters, longer than :data:`URL_MAX`)."""
    text = str(url or "").strip() if isinstance(url, str) else ""
    if not text or len(text) > URL_MAX:
        return None
    try:
        parts = urlsplit(text)
        port = parts.port
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme != "http" or parts.username is not None or parts.password is not None:
        return None
    if host is None or host != gateway or _ipv4(host) != gateway:
        return None
    port = 80 if port is None else port
    if not 1 <= port <= 65535:
        return None
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if not target.startswith("/") or any(ord(ch) <= 32 or ord(ch) == 127 for ch in target):
        return None
    return port, target


def _accept_ssdp(data: Any, source: Any, gateway: str) -> Optional[Tuple[str, Optional[str]]]:
    """``(location, server)`` for an SSDP response this check accepts: from the gateway's address, ``HTTP/1.1 200``,
    a LOCATION of at most 512 characters on the gateway (:func:`_router_url`).  None for anything else."""
    if not isinstance(source, tuple) or not source or source[0] != gateway:
        return None
    if not isinstance(data, (bytes, bytearray)):
        return None
    text = bytes(data).decode("latin-1")
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    status = lines[0].split()
    if len(status) < 2 or status[0] != "HTTP/1.1" or status[1] != "200":
        return None
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break
        name, sep, value = line.partition(":")
        if sep:
            headers.setdefault(name.strip().upper(), value.strip())
    location = headers.get("LOCATION")
    if not location or len(location) > URL_MAX or _router_url(location, gateway) is None:
        return None
    return location, _clean(headers.get("SERVER"), SERVER_MAX)


# --- SOAP (UDA 1.1 §3) ------------------------------------------------------------------------------------
def soap_envelope(service_type: str, action: str, args: Iterable[Tuple[str, Any]] = ()) -> bytes:
    """The SOAP body for one read-only *action* on a connection service.  ``ValueError`` for an action outside
    :data:`SOAP_ACTIONS` or a service type outside :data:`SERVICE_TYPES`."""
    if action not in SOAP_ACTIONS:
        raise ValueError(f"not a read-only UPnP action: {action!r}")
    if service_type not in SERVICE_TYPES:
        raise ValueError(f"not a WAN connection service: {service_type!r}")
    inner = "".join(f"<{name}>{escape(str(value))}</{name}>" for name, value in args)
    return (f'<?xml version="1.0"?><s:Envelope xmlns:s="{_SOAP_ENV}" s:encodingStyle="{_SOAP_ENCODING}">'
            f'<s:Body><u:{action} xmlns:u="{service_type}">{inner}</u:{action}></s:Body></s:Envelope>').encode("utf-8")


# --- HTTP to the router -------------------------------------------------------------------------------------
class _DeadlineReader(io.RawIOBase):
    """The raw stream ``http.client`` reads a router's reply from: every socket read waits at most until the
    deadline, so a router that drips its status line or headers cannot hold the check (a socket timeout alone only
    bounds one read)."""

    def __init__(self, sock: Any, left: Callable[[], float]) -> None:
        super().__init__()
        self._sock = sock
        self._raw = sock.makefile("rb", buffering=0)   # like http.client's own: keeps the socket open until closed
        self._left = left

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> Optional[int]:
        left = self._left()
        if left <= 0:
            raise TimeoutError("the router did not finish its reply in time")
        self._sock.settimeout(left)
        return self._raw.readinto(buffer)

    def close(self) -> None:
        if not self.closed:
            try:
                self._raw.close()
            finally:
                super().close()


class _DeadlineSocket:
    """What an ``http.client.HTTPResponse`` is built on instead of the socket: it only calls ``makefile``."""

    def __init__(self, sock: Any, left: Callable[[], float]) -> None:
        self._sock = sock
        self._left = left

    def makefile(self, mode: str = "rb", *args: Any, **kwargs: Any) -> io.BufferedReader:
        return io.BufferedReader(_DeadlineReader(self._sock, self._left))


class _RouterConnection(http.client.HTTPConnection):
    """``http.client.HTTPConnection`` whose reply is read under ``deadline``, a ``(monotonic, at)`` pair that
    :func:`check_nat` sets before the request."""

    def __init__(self, host: str, port: int, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self.deadline: Optional[Tuple[Callable[[], float], float]] = None
        self.response_class = self._response        # type: ignore[assignment] - called as (sock, ..., method=)

    def _response(self, sock: Any, *args: Any, **kwargs: Any) -> http.client.HTTPResponse:
        deadline = self.deadline
        if deadline is not None:
            monotonic, at = deadline
            sock = _DeadlineSocket(sock, lambda: at - monotonic())
        return http.client.HTTPResponse(sock, *args, **kwargs)


class _HttpFailure(Exception):
    """One HTTP exchange with the router failed.  ``kind``: ``skipped`` (no time left), ``timeout``, ``redirect``,
    ``too_large``, ``unsafe`` (DOCTYPE, ENTITY or NUL), ``unreadable`` (not XML) or ``transport``."""

    def __init__(self, kind: str, status: Optional[int] = None) -> None:
        super().__init__(kind)
        self.kind = kind
        self.status = status


class _Check:
    """The knobs, the deadline and the per-run state of one :func:`check_nat`."""

    def __init__(self, *, monotonic: Callable[[], float], budget_s: float, natpmp_waits_ms: Sequence[float],
                 ssdp_read_s: float, http_timeout_s: float, walk_s: float, walk_max: int, trace_ttls: int,
                 trace_timeout_ms: float, user_agent: Optional[str]) -> None:
        self.monotonic = monotonic
        self.started = monotonic()
        self.deadline = self.started + float(budget_s)
        self.natpmp_waits_ms = tuple(natpmp_waits_ms or ())
        self.ssdp_read_s = float(ssdp_read_s)
        self.http_timeout_s = float(http_timeout_s)
        self.walk_s = float(walk_s)
        self.walk_max = int(walk_max)
        self.trace_ttls = int(trace_ttls)
        self.trace_timeout_ms = float(trace_timeout_ms)
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self.gateway = ""
        self.retried_404 = False        # the host-root retry is tried once per run

    def left(self) -> float:
        return self.deadline - self.monotonic()

    def headers(self, port: int, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {"Host": f"{self.gateway}:{port}", "User-Agent": self.user_agent, "Connection": "close"}
        headers.update(extra or {})
        return headers


def _read_body(resp: Any, at: float, monotonic: Callable[[], float]) -> bytes:
    """The whole body in chunks, abandoned past :data:`HTTP_BODY_MAX` or once ``monotonic()`` reaches *at*."""
    read = getattr(resp, "read1", None) or resp.read
    body = bytearray()
    while True:
        chunk = read(HTTP_CHUNK)
        if not chunk:
            return bytes(body)
        body += chunk
        if len(body) > HTTP_BODY_MAX:
            raise _HttpFailure("too_large")
        if monotonic() >= at:
            raise _HttpFailure("timeout")


def _exchange(ctx: _Check, port: int, method: str, target: str, headers: Dict[str, str],
              body: Optional[bytes] = None, until: Optional[float] = None) -> Tuple[int, Optional[ET.Element]]:
    """One request to the gateway.  ``(status, root)``: a 200 always comes with its parsed body, a 500 (a SOAP
    fault) with its body when it parses; no body is read for any other status.  Raises :class:`_HttpFailure`."""
    budget = min(ctx.http_timeout_s, ctx.left())
    if until is not None:
        budget = min(budget, until - ctx.monotonic())
    if budget < MIN_STEP_S:
        raise _HttpFailure("skipped")
    at = ctx.monotonic() + budget
    conn = resp = None
    try:
        conn = _http_connection(ctx.gateway, port, budget)
        if isinstance(conn, _RouterConnection):
            conn.deadline = (ctx.monotonic, at)
        conn.request(method, target, body=body, headers=headers)
        resp = conn.getresponse()
        status = int(resp.status)
        if 300 <= status < 400:
            raise _HttpFailure("redirect", status)      # never followed
        if status not in (200, 500):
            return status, None
        data = _read_body(resp, at, ctx.monotonic)
    except _HttpFailure:
        raise
    except TimeoutError:
        raise _HttpFailure("timeout") from None
    except (OSError, http.client.HTTPException, ValueError) as exc:
        log.debug("NAT check: HTTP %s %s to the router failed: %s", method, target, exc)
        raise _HttpFailure("transport") from None
    finally:
        _close(resp)                # http.client hands a closing connection's socket to the response
        _close(conn)
    lowered = data.lower()
    if b"\x00" in data or b"<!doctype" in lowered or b"<!entity" in lowered:
        raise _HttpFailure("unsafe", status)
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError):
        if status == 200:
            raise _HttpFailure("unreadable", status) from None
        root = None
    return status, root


# --- NAT-PMP and SSDP steps -----------------------------------------------------------------------------------
def _natpmp(ctx: _Check) -> Dict[str, Any]:
    """Step 5: opcode 0 to the gateway, one try per wait in ``natpmp_waits_ms``.  Any socket error other than a
    read timeout (``ConnectionResetError``: nothing listens on 5351) ends the step at once."""
    out: Dict[str, Any] = {"answered": False, "result": None, "external_ip": None}
    if ctx.left() < MIN_STEP_S:
        return out
    sock = None
    try:
        sock = _udp_socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((ctx.gateway, NATPMP_PORT))    # a connected socket only takes datagrams from gateway:5351
        for wait_ms in ctx.natpmp_waits_ms:
            left = ctx.left()
            if left < MIN_STEP_S:
                break
            sock.send(NATPMP_REQUEST)
            end = ctx.monotonic() + min(float(wait_ms) / 1000.0, left)
            while True:
                remaining = end - ctx.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    data = sock.recv(NATPMP_READ_MAX)
                except TimeoutError:
                    break
                reply = parse_natpmp_reply(data)
                if reply is not None:
                    log.debug("NAT check: NAT-PMP result %s, external address %s", reply["result"],
                              reply["external_ip"])
                    return reply
    except OSError as exc:
        log.debug("NAT check: no NAT-PMP (%s)", exc)
    finally:
        _close(sock)
    return out


def _ssdp_search(ctx: _Check, local_ip: str) -> Optional[Tuple[str, Optional[str]]]:
    """Step 6a: the unicast search, then the multicast one, from one socket bound to the internet adapter; reads
    until the first accepted reply (:func:`_accept_ssdp`) or the read window ends."""
    left = ctx.left()
    if left < MIN_STEP_S:
        return None
    window = min(max(ctx.ssdp_read_s, float(SSDP_MX)), left)
    sock = None
    try:
        sock = _udp_socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((local_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, SSDP_TTL)
        sent = 0
        for host in (ctx.gateway, SSDP_MULTICAST):
            try:
                sock.sendto(ssdp_request(host, multicast=host == SSDP_MULTICAST, user_agent=ctx.user_agent),
                            (host, SSDP_PORT))
                sent += 1
            except OSError as exc:
                log.debug("NAT check: sending the SSDP search to %s failed: %s", host, exc)
        if not sent:
            return None
        end = ctx.monotonic() + window
        strays = 0
        while True:
            remaining = end - ctx.monotonic()
            if remaining <= 0:
                return None
            try:
                sock.settimeout(remaining)
                data, source = sock.recvfrom(SSDP_DATAGRAM_MAX)
            except TimeoutError:
                return None
            except OSError as exc:
                if isinstance(exc, ConnectionResetError) or getattr(exc, "winerror", None) == _WSAEMSGSIZE:
                    strays += 1
                    if strays <= SSDP_STRAY_ERRORS_MAX:
                        continue
                raise
            accepted = _accept_ssdp(data, source, ctx.gateway)
            if accepted is not None:
                log.debug("NAT check: UPnP answer from %s (%s)", ctx.gateway, accepted[1])
                return accepted
    except OSError as exc:
        log.debug("NAT check: SSDP search failed: %s", exc)
        return None
    finally:
        _close(sock)


# --- UPnP IGD ------------------------------------------------------------------------------------------------
class _Service:
    """A WAN connection service whose control URL passed :func:`_router_url`."""

    __slots__ = ("service_type", "control", "port", "target")

    def __init__(self, service_type: str, control: str, port: int, target: str) -> None:
        self.service_type = service_type
        self.control = control          # the controlURL text from the description
        self.port = port
        self.target = target            # path?query sent to gateway:port


class _SoapOutcome:
    __slots__ = ("root", "fault", "status", "timed_out")

    def __init__(self, root: Optional[ET.Element], fault: Optional[int], status: Optional[int], timed_out: bool):
        self.root = root
        self.fault = fault
        self.status = status
        self.timed_out = timed_out

    @property
    def ok(self) -> bool:
        return self.status == 200 and self.root is not None


def _describe(ctx: _Check, location: str) -> Optional[ET.Element]:
    """The description document at LOCATION, or None."""
    checked = _router_url(location, ctx.gateway)
    if checked is None:
        return None
    port, target = checked
    try:
        status, root = _exchange(ctx, port, "GET", target, ctx.headers(port))
    except _HttpFailure as exc:
        log.debug("NAT check: the UPnP description failed (%s)", exc.kind)
        return None
    if status != 200 or root is None:
        log.debug("NAT check: the UPnP description answered HTTP %s", status)
        return None
    return root


def _services(root: ET.Element, location: str, gateway: str) -> Tuple[List[_Service], bool]:
    """``(services, any_candidates)``: the WAN connection services anywhere in the device tree, by preference then
    document order, at most :data:`MAX_SERVICES`, keeping only those whose control URL is on the gateway."""
    base = _child_text(root, "URLBase") or location
    found: List[Tuple[int, int, str, str]] = []
    for position, element in enumerate(e for e in root.iter() if _local(e.tag) == "service"):
        service_type = _child_text(element, "serviceType")
        control = _child_text(element, "controlURL")
        if service_type in SERVICE_TYPES and control:
            found.append((SERVICE_TYPES.index(service_type), position, service_type, control))
    found.sort(key=lambda item: (item[0], item[1]))
    services: List[_Service] = []
    for _preference, _position, service_type, control in found[:MAX_SERVICES]:
        try:
            url = urljoin(base, control)
        except ValueError:
            url = ""
        checked = _router_url(url, gateway)
        if checked is None:
            log.debug("NAT check: the control URL of %s is not on the router; skipped", service_type)
            continue
        services.append(_Service(service_type, control, checked[0], checked[1]))
    return services, bool(found)


def _host_root(service: _Service, gateway: str) -> Optional[str]:
    """The host-root form of a control URL (``"/" + path.lstrip("/")`` on ``http://<gateway>:<port>/``), checked."""
    try:
        parts = urlsplit(service.control)
        url = urljoin(f"http://{gateway}:{service.port}/", "/" + (parts.path or "").lstrip("/"))
    except ValueError:
        return None
    if parts.query:
        url += f"?{parts.query}"
    checked = _router_url(url, gateway)
    if checked is None or checked[0] != service.port:
        return None
    return checked[1]


def _soap(ctx: _Check, service: _Service, action: str, args: Iterable[Tuple[str, Any]] = (),
          until: Optional[float] = None) -> _SoapOutcome:
    """One SOAP call; an HTTP 404 is retried once per run with the host-root form of the control URL, which the
    service keeps for its later calls unless that retry failed too (another 404 or no answer)."""
    body = soap_envelope(service.service_type, action, args)
    headers = ctx.headers(service.port, {"Content-Type": 'text/xml; charset="utf-8"',
                                         "SOAPACTION": f'"{service.service_type}#{action}"'})
    retry_from: Optional[str] = None
    while True:
        try:
            status, root = _exchange(ctx, service.port, "POST", service.target, headers, body, until)
        except _HttpFailure as exc:
            if retry_from is not None:
                service.target = retry_from  # the host-root form did not answer either
            log.debug("NAT check: UPnP %s failed (%s)", action, exc.kind)
            return _SoapOutcome(None, None, exc.status, exc.kind in ("skipped", "timeout"))
        if status == 404 and retry_from is None and not ctx.retried_404:
            retry = _host_root(service, ctx.gateway)
            if retry is not None and retry != service.target:
                ctx.retried_404 = True       # spent only by a retry that is actually sent
                retry_from, service.target = service.target, retry
                continue
        if status == 404 and retry_from is not None:
            service.target = retry_from      # the host-root form did not help either
        if status == 200 and root is not None:
            return _SoapOutcome(root, None, status, False)
        fault = _int(_find_text(root, "errorCode")) if status == 500 else None
        log.debug("NAT check: UPnP %s answered HTTP %s (fault %s)", action, status, fault)
        return _SoapOutcome(None, fault, status, False)


def _external_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return "".join(ch for ch in value if ch.isprintable())[:EXTERNAL_IP_MAX].strip()


def _choose_service(ctx: _Check, services: List[_Service]) -> Tuple[_Service, Optional[str], Optional[str]]:
    """``(service, status, external_ip)``: GetStatusInfo on each service in order (GetExternalIPAddress too when it
    is Connected), stopping at the first Connected one with a public address; then the choice rules of §2.4."""
    seen: List[Tuple[_Service, Optional[str], Optional[str]]] = []
    for service in services:
        if ctx.left() < MIN_STEP_S:
            break
        info = _soap(ctx, service, "GetStatusInfo")
        status = _find_text(info.root, "NewConnectionStatus") if info.ok else None
        external: Optional[str] = None
        if status in CONNECTED_STATES:
            reply = _soap(ctx, service, "GetExternalIPAddress")
            if reply.ok:
                external = _external_text(_find_text(reply.root, "NewExternalIPAddress"))
        seen.append((service, status, external))
        if status in CONNECTED_STATES and range_of(external) == "public":
            break
    connected = [item for item in seen if item[1] in CONNECTED_STATES]
    for item in connected:
        if range_of(item[2]) == "public":
            return item
    for item in connected:
        if item[2] and item[2] != "0.0.0.0":
            return item
    if connected:
        return connected[0]
    return seen[0] if seen else (services[0], None, None)


def _empty_upnp(error: Optional[str] = None) -> Dict[str, Any]:
    return {"found": False, "server": None, "model": None, "service": None, "status": None, "external_ip": None,
            "error": error}


def _upnp(ctx: _Check, local_ip: Optional[str]) -> Tuple[Dict[str, Any], Optional[_Service], bool]:
    """Step 6: ``(UPNP, chosen service or None, chosen service is Connected)``."""
    upnp = _empty_upnp()
    if local_ip is None:
        log.debug("NAT check: the internet adapter has no IPv4 address to search from")
        return upnp, None, False
    accepted = _ssdp_search(ctx, local_ip)
    if accepted is None:
        return upnp, None, False
    location, server = accepted
    upnp["found"] = True
    upnp["server"] = server
    root = _describe(ctx, location)
    if root is None:
        return upnp, None, False
    device = next((child for child in root if _local(child.tag) == "device"), None)
    upnp["model"] = _clean(f"{_child_text(device, 'manufacturer')} {_child_text(device, 'modelName')}", MODEL_MAX)
    services, had_candidates = _services(root, location, ctx.gateway)
    if not services:
        if had_candidates:
            upnp["error"] = CONTROL_NOT_ROUTER_ERROR
        return upnp, None, False
    service, status, external = _choose_service(ctx, services)
    connected = status in CONNECTED_STATES
    upnp["service"] = service.service_type
    upnp["status"] = _clean(status, STATUS_MAX)
    upnp["external_ip"] = external if connected else None
    return upnp, service, connected


def _mapping(root: Optional[ET.Element]) -> Tuple[Dict[str, Any], Tuple[Any, ...]]:
    """``(MAPPING, key)`` from a GetGenericPortMappingEntry response; *key* also covers ``NewRemoteHost``."""
    protocol = _clean(_find_text(root, "NewProtocol"), 8)
    entry = {
        "protocol": protocol.upper() if protocol else None,
        "external_port": _int(_find_text(root, "NewExternalPort")),
        "internal_client": _clean(_find_text(root, "NewInternalClient"), CLIENT_MAX),
        "internal_port": _int(_find_text(root, "NewInternalPort")),
        "enabled": _bool(_find_text(root, "NewEnabled")),
        "description": _clean(_find_text(root, "NewPortMappingDescription"), DESCRIPTION_MAX),
        "lease_s": _int(_find_text(root, "NewLeaseDuration")),
    }
    key = (_clean(_find_text(root, "NewRemoteHost"), CLIENT_MAX),) + tuple(entry[k] for k in MAPPING_KEYS)
    return entry, key


def _walk(ctx: _Check, service: _Service) -> Dict[str, Any]:
    """Step 9: GetGenericPortMappingEntry for index 0, 1, ... until a fault or failure, a repeated entry,
    ``walk_max`` entries or ``min(walk_s, time left)``."""
    entries: List[Dict[str, Any]] = []
    seen: set = set()
    truncated = False
    error: Optional[str] = None
    end = min(ctx.monotonic() + ctx.walk_s, ctx.deadline)
    index = 0
    while True:
        if len(entries) >= ctx.walk_max:
            truncated = True
            break
        if end - ctx.monotonic() < MIN_STEP_S:
            truncated = True
            break
        outcome = _soap(ctx, service, "GetGenericPortMappingEntry", (("NewPortMappingIndex", index),), until=end)
        if not outcome.ok:
            if outcome.timed_out and end - ctx.monotonic() < MIN_STEP_S:
                truncated = True
            elif index == 0 and (outcome.fault in (606, 501) or outcome.status in (401, 403, 501)):
                error = MAPPINGS_NOT_SHARED_ERROR
            break
        entry, key = _mapping(outcome.root)
        if key in seen:
            break
        seen.add(key)
        entries.append(entry)
        index += 1
    return {"entries": entries, "truncated": truncated, "error": error}


# --- self-traceroute ------------------------------------------------------------------------------------------
def _hop(ttl: int, reply: Any, wall_ms: float, public_ip: str) -> Tuple[Dict[str, Any], bool]:
    """``(HOP, ok)``: the responder is the hop (a "TTL expired" reply carries no rtt, so the call's own time is used),
    ``public_ip`` only for an ok reply without one; ``ip`` None when nothing answered or the ping raised."""
    ok = reply is not None and bool(getattr(reply, "ok", False))
    responder = getattr(reply, "responder", None) if reply is not None else None
    if not responder and ok:
        responder = public_ip
    ip = str(responder) if responder else None
    rtt: Optional[float] = None
    if ip is not None:
        rtt = round(wall_ms, 2)
        if ok:
            try:
                rtt = round(float(getattr(reply, "rtt_ms")), 2)
            except (TypeError, ValueError, AttributeError):
                pass
    return {"ttl": ttl, "ip": ip, "rtt_ms": rtt, "range": range_of(ip)}, ok


def _trace(ctx: _Check, public_ip: str, pinger_factory: Optional[Callable[[], Any]]) -> Optional[Dict[str, Any]]:
    """Step 8: echo requests to this site's own public address with TTL 1, 2, ... through a private pinger (created
    only when the trace runs, closed in finally); stops where the public address itself answers."""
    need_s = ctx.trace_timeout_ms / 1000.0 + TRACE_MARGIN_S
    if ctx.trace_ttls < 1 or ctx.left() < need_s:
        return None
    try:
        factory = pinger_factory if pinger_factory is not None else importlib.import_module("tnt.icmp").IcmpPinger
        pinger = factory()
    except Exception as exc:  # noqa: BLE001 - no trace, the verdict still comes out
        log.warning("NAT check: no ICMP pinger for the trace (%s)", type(exc).__name__)
        log.debug("NAT check: creating the pinger failed", exc_info=True)
        return None
    hops: List[Dict[str, Any]] = []
    reached: Optional[int] = None
    try:
        for ttl in range(1, ctx.trace_ttls + 1):
            left = ctx.left()
            if left < need_s:
                break
            timeout_ms = int(min(ctx.trace_timeout_ms, left * 1000.0))
            t0 = time.perf_counter()
            try:
                reply = pinger.ping(public_ip, size=TRACE_SIZE, timeout_ms=timeout_ms, ttl=ttl)
            except Exception:  # noqa: BLE001 - IcmpPinger.ping never raises; a stand-in might
                log.debug("NAT check: trace ping ttl=%d raised", ttl, exc_info=True)
                reply = None
            hop, ok = _hop(ttl, reply, (time.perf_counter() - t0) * 1000.0, public_ip)
            hops.append(hop)
            if ok and hop["ip"] == public_ip:
                reached = ttl
                break
    finally:
        try:
            pinger.close()
        except Exception:  # noqa: BLE001
            log.debug("NAT check: closing the trace pinger failed", exc_info=True)
    log.debug("NAT check: trace reached ttl %s: %s", reached, [(h["ttl"], h["ip"]) for h in hops])
    return {"reached_ttl": reached, "hops": hops}


# --- verdict ------------------------------------------------------------------------------------------------
def evaluate_verdict(*, wan_ip: Optional[str], public_ip: Optional[str], trace: Optional[Dict[str, Any]],
                     unclear: bool, natpmp_answered: bool = False,
                     upnp_found: bool = False) -> Tuple[str, Optional[str]]:
    """``(verdict, confidence)`` from rows 5-14 of the verdict table (first match wins), for a check that got past
    the no-probe rows: *wan_ip* is the usable router WAN address or None, *unclear* the unclear signal (NAT-PMP
    result 3, or a Connected UPnP service with an empty, 0.0.0.0 or reserved address)."""
    wan_range = range_of(wan_ip)
    if wan_range == "shared":
        return "cgnat", "high"
    if wan_range == "private":
        return "double_nat", "medium"
    if wan_range == "public":
        return ("single_nat", "high") if wan_ip == public_ip else ("upstream_nat", "low")
    hops = [h for h in ((trace or {}).get("hops") or []) if isinstance(h, dict) and isinstance(h.get("ttl"), int)]
    reached = (trace or {}).get("reached_ttl")
    reached = reached if isinstance(reached, int) else None
    if reached == 1:
        return "single_nat", "medium"
    for hop in hops:
        if hop.get("range") == "shared" and (hop["ttl"] < reached if reached is not None else hop["ttl"] in (2, 3)):
            return "cgnat", "high" if unclear else "medium"
    if reached == 2:
        confidence = "medium" if (natpmp_answered or upnp_found) else "low"
        return "double_nat", _RAISE[confidence] if unclear else confidence
    if reached is not None and reached >= 3:
        before = next((h for h in hops if h["ttl"] == reached - 1), None)
        if before is not None and before.get("range") == "private":
            return "double_nat", "medium" if unclear else "low"
    if unclear:
        return "nat_unclear_private_wan", "low"
    return "unknown", None


def _result(ts: float, generation: Any) -> Dict[str, Any]:
    """An empty NAT_RESULT (keys in :data:`NAT_RESULT_KEYS` order)."""
    return {
        "ts": ts, "generation": generation, "duration_ms": 0, "verdict": "unknown", "confidence": None,
        "title": NAT_TEXT["unknown"][0], "explanation": NAT_TEXT["unknown"][1],
        "router": {"gateway": None, "wan_ip": None, "wan_source": None,
                   "natpmp": {"answered": False, "result": None, "external_ip": None}, "upnp": _empty_upnp()},
        "public_ip": None, "trace": None, "port_mappings": None, "error": None,
    }


def _set_verdict(result: Dict[str, Any], verdict: str, confidence: Optional[str],
                 error: Optional[str] = None) -> Dict[str, Any]:
    result["verdict"] = verdict
    result["confidence"] = confidence
    result["title"], result["explanation"] = NAT_TEXT[verdict]
    result["error"] = error
    return result


def _finish(result: Dict[str, Any], ctx: _Check, verdict: str, confidence: Optional[str],
            error: Optional[str] = None) -> Dict[str, Any]:
    result["duration_ms"] = max(0, int(round((ctx.monotonic() - ctx.started) * 1000.0)))
    return _set_verdict(result, verdict, confidence, error)


def _offline(error: str, generation: Any, clock: Callable[[], float]) -> Dict[str, Any]:
    return _set_verdict(_result(float(clock()), generation), "offline", None, error)


def _pc_ipv4s(adapters: Any, nic: Any) -> set:
    """Every IPv4 address of every adapter (the internet adapter included)."""
    out: set = set()
    for adapter in list(adapters or []) + [nic]:
        for entry in getattr(adapter, "ipv4", None) or []:
            text = _ipv4(getattr(entry, "address", entry))
            if text:
                out.add(text)
    return out


def _is_vpn(nic: Any) -> bool:
    """A tunnel (if_type 53/131), PPP (23), or a VPN client's adapter by description; WWAN (237/243/244) and
    hypervisor adapters are not VPNs."""
    try:
        if_type = int(getattr(nic, "if_type", 0) or 0)
    except (TypeError, ValueError):
        if_type = 0
    if if_type in _VPN_IF_TYPES:
        return True
    if if_type in _WWAN_IF_TYPES:
        return False
    description = str(getattr(nic, "description", "") or "").lower()
    return any(m in description for m in _VPN_MARKERS) and not any(m in description for m in _HYPERVISOR_MARKERS)


def _usable_wan(value: Any) -> bool:
    """An IPv4 literal that is not 0.0.0.0 and not in the reserved range."""
    return _ipv4(value) is not None and value != "0.0.0.0" and range_of(value) != "reserved"


def _guarded(step: str, default: Any, fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - one broken step never loses the verdict
        log.warning("NAT check: the %s step failed (%s)", step, type(exc).__name__)
        log.debug("NAT check: the %s step failed", step, exc_info=True)
        return default


def check_nat(*, nic: Any, adapters: Any, public_ip: Any, pinger_factory: Optional[Callable[[], Any]] = None,
              generation: Any = None, clock: Callable[[], float] = time.time,
              monotonic: Callable[[], float] = time.monotonic, budget_s: float = 20.0,
              natpmp_waits_ms: Sequence[float] = (250, 500, 1000), ssdp_read_s: float = 2.5,
              http_timeout_s: float = 2.0, walk_s: float = 5.0, walk_max: int = 64, trace_ttls: int = 6,
              trace_timeout_ms: float = 800, user_agent: Optional[str] = None) -> Dict[str, Any]:
    """Run the NAT check for the internet adapter *nic* (a :class:`tnt.netinfo.Adapter`), this PC's *adapters* and
    the site's fresh *public_ip*, and return a NAT_RESULT.  Every step shares one deadline of *budget_s* seconds on
    *monotonic*.  Never raises."""
    ctx = _Check(monotonic=monotonic, budget_s=budget_s, natpmp_waits_ms=natpmp_waits_ms, ssdp_read_s=ssdp_read_s,
                 http_timeout_s=http_timeout_s, walk_s=walk_s, walk_max=walk_max, trace_ttls=trace_ttls,
                 trace_timeout_ms=trace_timeout_ms, user_agent=user_agent)
    result = _result(float(clock()), generation)
    if nic is None:
        return _finish(result, ctx, "offline", None, NO_INTERNET_ERROR)
    public = _ipv4(public_ip)
    if public is None:
        return _finish(result, ctx, "offline", None, NO_PUBLIC_IP_ERROR)
    result["public_ip"] = public
    router = result["router"]
    gateway = _ipv4(getattr(nic, "ipv4_gateway", None))   # an IPv6 or scoped gateway never reaches a socket
    router["gateway"] = gateway
    # 1-3: decided without a single probe
    if public in _pc_ipv4s(adapters, nic):
        return _finish(result, ctx, "no_nat", "high")
    if _is_vpn(nic):
        return _finish(result, ctx, "vpn", "medium")
    local_ip = _ipv4(getattr(nic, "primary_ipv4", None))
    if range_of(local_ip) == "shared":
        return _finish(result, ctx, "cgnat", "high")
    # 4-6: the router
    service: Optional[_Service] = None
    connected = False
    if gateway is None:
        router["upnp"] = _empty_upnp(NO_GATEWAY_ERROR)
    else:
        ctx.gateway = gateway
        router["natpmp"] = _guarded("NAT-PMP", router["natpmp"], lambda: _natpmp(ctx))
        router["upnp"], service, connected = _guarded("UPnP", (_empty_upnp(), None, False),
                                                      lambda: _upnp(ctx, local_ip))
    natpmp, upnp = router["natpmp"], router["upnp"]
    # 7: the router's own WAN address (UPnP wins)
    candidates = []
    if connected:
        candidates.append(("upnp", upnp["external_ip"]))
    if natpmp["result"] == 0:
        candidates.append(("natpmp", natpmp["external_ip"]))
    for source, value in candidates:
        if _usable_wan(value):
            router["wan_ip"], router["wan_source"] = value, source
            break
    upnp_ip = upnp["external_ip"]
    unclear = natpmp["result"] == 3 or (
        connected and upnp_ip is not None and (upnp_ip in ("", "0.0.0.0") or range_of(upnp_ip) == "reserved"))
    # 8-9: the path, then the router's port forwards
    if router["wan_ip"] is None:
        result["trace"] = _guarded("trace", None, lambda: _trace(ctx, public, pinger_factory))
    if service is not None:
        chosen = service
        result["port_mappings"] = _guarded("port-mapping", None, lambda: _walk(ctx, chosen))
    verdict, confidence = evaluate_verdict(wan_ip=router["wan_ip"], public_ip=public, trace=result["trace"],
                                           unclear=unclear, natpmp_answered=bool(natpmp["answered"]),
                                           upnp_found=bool(upnp["found"]))
    return _finish(result, ctx, verdict, confidence)


# --- the engine component -----------------------------------------------------------------------------------
class NatChecker:
    """The engine's NAT check behind ``GET``/``POST /api/netcheck/nat``.

    Every accessor is called when it is needed: ``adapters_fn()`` (this PC's adapters), ``internet_nic_fn()`` (the
    internet adapter or None), ``public_ip_fn()`` (the link map's ``{"ip", "ts", "error", "checked_ts"}``),
    ``changed_ts_fn()`` (when the network last changed, or None), ``refresh_fn`` (looks the public address up now;
    None without a link map) and ``generation_fn()`` (the network generation).  ``check`` is :func:`check_nat`.
    """

    def __init__(self, *, adapters_fn: Callable[[], Any], internet_nic_fn: Callable[[], Any],
                 public_ip_fn: Callable[[], Any], changed_ts_fn: Callable[[], Any],
                 refresh_fn: Optional[Callable[[], Any]], generation_fn: Callable[[], Any],
                 pinger_factory: Optional[Callable[[], Any]] = None, clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic, refresh_wait_s: float = 12.0,
                 throttle_s: float = 15.0, check: Callable[..., Dict[str, Any]] = check_nat) -> None:
        self._adapters_fn = adapters_fn
        self._internet_nic_fn = internet_nic_fn
        self._public_ip_fn = public_ip_fn
        self._changed_ts_fn = changed_ts_fn
        self._refresh_fn = refresh_fn
        self._generation_fn = generation_fn
        self._pinger_factory = pinger_factory
        self._clock = clock
        self._monotonic = monotonic
        self._refresh_wait_s = float(refresh_wait_s)
        self._throttle_s = float(throttle_s)
        self._check = check
        self._lock = threading.Lock()
        self._running = False
        self._last: Optional[Dict[str, Any]] = None
        self._epoch = 0                     # bumped by on_network_change: a run that overlapped one is not kept
        self._refresh_thread: Optional[threading.Thread] = None

    # -- state -----------------------------------------------------------------------------------------
    def last(self) -> Optional[Dict[str, Any]]:
        """The last kept NAT_RESULT for this network (a copy), or None."""
        with self._lock:
            return copy.deepcopy(self._last)

    def running(self) -> bool:
        return self._running

    def on_network_change(self, data: Any = None) -> None:
        """``net.changed`` (network watcher thread; quick, never raises): the kept result described the old network."""
        try:
            with self._lock:
                self._last = None
                self._epoch += 1
        except Exception:  # noqa: BLE001
            log.exception("handling a network change in the NAT check failed")

    # -- running -----------------------------------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        """Check now and return the NAT_RESULT (synchronous).  ``RuntimeError(BUSY_TEXT)`` while a run is going."""
        with self._lock:
            if self._running:
                raise RuntimeError(BUSY_TEXT)
            self._running = True
            epoch = self._epoch
        try:
            return self._run(epoch)
        finally:
            with self._lock:
                self._running = False

    def _run(self, epoch: int) -> Dict[str, Any]:
        generation = self._call(self._generation_fn, "network generation", None)
        with self._lock:
            last = self._last
        if last is not None and last.get("generation") == generation:
            try:
                age = float(self._clock()) - float(last.get("ts"))
            except (TypeError, ValueError):
                age = -1.0
            if 0.0 <= age < self._throttle_s:
                log.debug("NAT check: the result from %.1f s ago still stands", age)
                return copy.deepcopy(last)
        nic = self._call(self._internet_nic_fn, "internet adapter", None)
        if nic is None:
            log.info("NAT check: offline (%s)", NO_INTERNET_ERROR)
            return _offline(NO_INTERNET_ERROR, generation, self._clock)
        public = self._public_ip()
        if not self._fresh(public) and self._refresh_fn is not None:
            self._refresh()
            public = self._public_ip()
        if not self._fresh(public):
            log.info("NAT check: offline (%s)", NO_PUBLIC_IP_ERROR)
            return _offline(NO_PUBLIC_IP_ERROR, generation, self._clock)
        adapters = self._call(self._adapters_fn, "adapters", None) or []
        result = self._check(nic=nic, adapters=adapters, public_ip=public.get("ip"),
                             pinger_factory=self._pinger_factory, generation=generation, clock=self._clock,
                             monotonic=self._monotonic)
        current = self._call(self._generation_fn, "network generation", None)
        with self._lock:
            if result.get("generation") == current and self._epoch == epoch:
                self._last = copy.deepcopy(result)
        log.info("NAT check: %s (%s) in %d ms", result.get("verdict"), result.get("confidence"),
                 int(result.get("duration_ms") or 0))
        return result

    # -- inputs ------------------------------------------------------------------------------------------
    @staticmethod
    def _call(fn: Optional[Callable[[], Any]], what: str, default: Any) -> Any:
        if fn is None:
            return default
        try:
            return fn()
        except Exception:  # noqa: BLE001
            log.debug("NAT check: reading the %s failed", what, exc_info=True)
            return default

    def _public_ip(self) -> Dict[str, Any]:
        value = self._call(self._public_ip_fn, "public address", None)
        return dict(value) if isinstance(value, dict) else {}

    def _fresh(self, public: Dict[str, Any]) -> bool:
        """An IPv4 public address looked up after the last network change."""
        if _ipv4(public.get("ip")) is None or public.get("ts") is None:
            return False
        changed = self._call(self._changed_ts_fn, "network change time", None)
        if changed is None:
            return True
        try:
            return float(public["ts"]) >= float(changed)
        except (TypeError, ValueError):
            return False

    def _refresh(self) -> None:
        """``refresh_fn()`` on a daemon helper thread, waited on for at most ``refresh_wait_s``."""
        with self._lock:
            thread = self._refresh_thread
            start = thread is None or not thread.is_alive()
            if start:
                thread = threading.Thread(target=self._refresh_worker, name="tnt-natcheck-refresh", daemon=True)
                self._refresh_thread = thread
        assert thread is not None
        if start:
            try:
                thread.start()
            except Exception:  # noqa: BLE001 - "can't start new thread": no refresh this time
                log.warning("NAT check: could not start the public address lookup")
                return
        thread.join(max(0.0, self._refresh_wait_s))

    def _refresh_worker(self) -> None:
        try:
            if self._refresh_fn is not None:
                self._refresh_fn()
        except Exception:  # noqa: BLE001
            log.debug("NAT check: looking the public address up failed", exc_info=True)
