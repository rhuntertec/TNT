"""Tests for tnt.natcheck: the NAT check (NAT-PMP, SSDP, UPnP IGD, the self-traceroute and the verdict table).

Offline and fake-only: the UDP sockets (``tnt.natcheck._udp_socket``), the HTTP connections to the router
(``tnt.natcheck._http_connection``) and the ICMP pinger are stand-ins driven by a fake clock, so no packet leaves this
PC and no test waits a contract timer.  Addresses are documentation ranges (RFC 5737) plus the private and shared
addresses the contract's vectors use; the router is "Example Router XR-1".
"""
from __future__ import annotations

import http.client
import ipaddress
import logging
import re
import socket
import struct
import threading
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional
from xml.sax.saxutils import escape

import pytest

import tnt
from tnt import natcheck as nc
from tnt.netinfo import Adapter, IpAddr

GATEWAY = "192.0.2.1"
PC_IP = "192.0.2.10"
PUBLIC = "203.0.113.5"
OTHER_PUBLIC = "198.51.100.7"
T0 = 1_700_000_000.0
LOCATION = f"http://{GATEWAY}:5000/rootDesc.xml"
SERVER = "ExampleOS/1.0 UPnP/1.1 MiniUPnPd/2.2.0"
IP1 = "urn:schemas-upnp-org:service:WANIPConnection:1"
IP2 = "urn:schemas-upnp-org:service:WANIPConnection:2"
PPP1 = "urn:schemas-upnp-org:service:WANPPPConnection:1"
SOAP_ENV = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>')


# =========================================================================== fakes
class Clock:
    """Fake wall and monotonic time; fake sockets, HTTP replies and pings advance it."""

    def __init__(self) -> None:
        self.t = 1000.0

    def monotonic(self) -> float:
        return self.t

    def time(self) -> float:
        return T0 + self.t

    def advance(self, seconds: Optional[float]) -> None:
        self.t += max(0.0, float(seconds or 0.0))


def adapter(name: str = "Ethernet", *, ip: Optional[str] = PC_IP, gateways=(GATEWAY,), if_type: int = 6,
            description: str = "Example Gigabit Network Connection", index: int = 21, extra_ips=()) -> Adapter:
    ipv4 = [IpAddr(address=a, prefix=24, family=4, netmask="255.255.255.0",
                   network=str(ipaddress.ip_network(f"{a}/24", strict=False)))
            for a in ((ip,) if ip else ()) + tuple(extra_ips)]
    return Adapter(index=index, name=name, description=description, mac="02:00:5e:10:00:01", if_type=if_type,
                   type_name="Ethernet", status="up", speed_bps=1_000_000_000, mtu=1500, dhcp_enabled=True,
                   dhcp_server=None, dns_suffix="", ipv4=ipv4, gateways=list(gateways), is_physical=True)


class FakeUdp:
    """One UDP socket: records every call; a read with nothing queued advances the clock by the socket timeout and
    times out.  Queued items are datagrams (NAT-PMP), ``(datagram, source)`` pairs (SSDP) or exceptions to raise."""

    def __init__(self, net: "FakeNet", family: int, kind: int) -> None:
        self.net, self.family, self.kind = net, family, kind
        self.connected: Any = None
        self.bound: Any = None
        self.options: List[tuple] = []
        self.sent: List[tuple] = []
        self.queue: List[Any] = []
        self.timeout: Optional[float] = None
        self.timeouts: List[float] = []
        self.read_sizes: List[int] = []
        self.reads = 0
        self.closed = False

    def connect(self, address) -> None:
        self.connected = address

    def bind(self, address) -> None:
        self.bound = address

    def setsockopt(self, level, option, value) -> None:
        self.options.append((level, option, value))

    def settimeout(self, value) -> None:
        self.timeout = value
        self.timeouts.append(value)

    def send(self, data) -> None:
        self.sent.append((bytes(data), self.connected))
        self.net.on_send(self, self.connected)

    def sendto(self, data, address) -> None:
        self.sent.append((bytes(data), address))
        self.net.on_send(self, address)

    def _next(self) -> Any:
        self.reads += 1
        if self.queue:
            item = self.queue.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        self.net.clock.advance(self.timeout)
        raise socket.timeout("timed out")

    def recv(self, size) -> Any:
        self.read_sizes.append(size)
        return self._next()

    def recvfrom(self, size) -> Any:
        self.read_sizes.append(size)
        return self._next()

    def close(self) -> None:
        self.closed = True


class FakeNet:
    """``natpmp``: one list of queued items per NAT-PMP send; ``ssdp``: items queued once the first search is sent."""

    def __init__(self, clock: Clock, natpmp=None, ssdp=None) -> None:
        self.clock = clock
        self.natpmp = [list(x) for x in (natpmp or [])]
        self.ssdp = list(ssdp or [])
        self.sockets: List[FakeUdp] = []

    def socket(self, family, kind) -> FakeUdp:
        sock = FakeUdp(self, family, kind)
        self.sockets.append(sock)
        return sock

    def on_send(self, sock: FakeUdp, address) -> None:
        if address and address[1] == nc.NATPMP_PORT:
            sock.queue.extend(self.natpmp.pop(0) if self.natpmp else [])
        elif address and address[1] == nc.SSDP_PORT and len(sock.sent) == 1:
            sock.queue.extend(self.ssdp)

    def natpmp_socket(self) -> Optional[FakeUdp]:
        return next((s for s in self.sockets if s.connected and s.connected[1] == nc.NATPMP_PORT), None)

    def ssdp_socket(self) -> Optional[FakeUdp]:
        return next((s for s in self.sockets if s.bound is not None), None)


class Reply:
    def __init__(self, status: int = 200, body: bytes = b"", chunk: Optional[int] = None, delay: float = 0.0) -> None:
        self.status, self.body, self.chunk, self.delay = status, body, chunk, delay


class FakeResponse:
    def __init__(self, reply: Reply, clock: Clock) -> None:
        self.status = reply.status
        self._reply, self._clock, self._pos = reply, clock, 0
        self.reads = 0
        self.closed = False

    def read1(self, size: int = -1) -> bytes:
        self.reads += 1
        body = self._reply.body
        if self._pos >= len(body):
            return b""
        take = size if size and size > 0 else len(body)
        if self._reply.chunk:
            take = min(take, self._reply.chunk)
        chunk = body[self._pos:self._pos + take]
        self._pos += len(chunk)
        self._clock.advance(self._reply.delay)
        return chunk

    def close(self) -> None:
        self.closed = True


class FakeConn:
    def __init__(self, router: "FakeRouter", host: str, port: int, timeout: float) -> None:
        self.router, self.host, self.port, self.timeout = router, host, port, timeout
        self.request_seen: Any = None
        self.closed = False

    def request(self, method, target, body=None, headers=None) -> None:
        self.request_seen = SimpleNamespace(host=self.host, port=self.port, method=method, target=target, body=body,
                                            headers=dict(headers or {}))
        self.router.requests.append(self.request_seen)

    def getresponse(self) -> FakeResponse:
        response = FakeResponse(self.router.respond(self.request_seen), self.router.clock)
        self.router.responses.append(response)
        return response

    def close(self) -> None:
        self.closed = True


def soap_ok(service_type: str, action: str, **values: Any) -> Reply:
    inner = "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in values.items())
    return Reply(200, (f'{SOAP_ENV}<u:{action}Response xmlns:u="{service_type}">{inner}</u:{action}Response>'
                       "</s:Body></s:Envelope>").encode())


def soap_fault(code: int) -> Reply:
    return Reply(500, (f"{SOAP_ENV}<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>"
                       f'<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>{code}</errorCode>'
                       "<errorDescription>Error</errorDescription></UPnPError></detail></s:Fault></s:Body>"
                       "</s:Envelope>").encode())


def mapping(port: int, client: str = "10.0.0.60", internal: Optional[int] = None, protocol: str = "TCP",
            description: str = "Camera", lease: int = 0, remote: str = "") -> Dict[str, Any]:
    return {"NewRemoteHost": remote, "NewExternalPort": port, "NewProtocol": protocol,
            "NewInternalPort": internal or port, "NewInternalClient": client, "NewEnabled": 1,
            "NewPortMappingDescription": description, "NewLeaseDuration": lease}


class Svc:
    """A connection service on the fake router.  ``control`` is the description's controlURL text, ``path`` the
    request target it resolves to."""

    def __init__(self, service_type: str = IP1, control: str = "/ctl/IPConn", *, path: Optional[str] = None,
                 status: str = "Connected", external: str = PUBLIC, mappings=(),
                 entry: Optional[Callable[[int], Reply]] = None) -> None:
        self.service_type, self.control = service_type, control
        self.path = path if path is not None else control
        self.status, self.external = status, external
        self.mappings = list(mappings)
        self.entry = entry

    def handle(self, action: Optional[str], body: bytes) -> Reply:
        if action == "GetStatusInfo":
            return soap_ok(self.service_type, action, NewConnectionStatus=self.status,
                           NewLastConnectionError="ERROR_NONE", NewUptime=3600)
        if action == "GetExternalIPAddress":
            return soap_ok(self.service_type, action, NewExternalIPAddress=self.external)
        if action == "GetGenericPortMappingEntry":
            index = int(re.search(rb"<NewPortMappingIndex>(\d+)</NewPortMappingIndex>", body).group(1))
            if self.entry is not None:
                return self.entry(index)
            if index < len(self.mappings):
                return soap_ok(self.service_type, action, **self.mappings[index])
            return soap_fault(713)
        return soap_fault(401)


def describe(services, *, urlbase: Optional[str] = None, manufacturer: str = "Example",
             model: str = "Router XR-1") -> bytes:
    """An IGD description: connection services under InternetGatewayDevice > WANDevice > WANConnectionDevice."""
    items = "".join(f"<service><serviceType>{escape(s.service_type)}</serviceType>"
                    f"<serviceId>urn:upnp-org:serviceId:WANConn{i}</serviceId>"
                    f"<controlURL>{escape(s.control)}</controlURL><eventSubURL>/evt/{i}</eventSubURL>"
                    f"<SCPDURL>/scpd/{i}.xml</SCPDURL></service>" for i, s in enumerate(services))
    base = f"<URLBase>{escape(urlbase)}</URLBase>" if urlbase else ""
    return ('<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0">'
            f"<specVersion><major>1</major><minor>1</minor></specVersion>{base}<device>"
            "<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>"
            f"<friendlyName>Example Router</friendlyName><manufacturer>{manufacturer}</manufacturer>"
            f"<modelName>{model}</modelName><serviceList><service>"
            "<serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>"
            "<controlURL>/ctl/L3F</controlURL></service></serviceList><deviceList><device>"
            "<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><serviceList><service>"
            "<serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>"
            "<controlURL>/ctl/CmnIfCfg</controlURL></service></serviceList><deviceList><device>"
            "<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>"
            f"<serviceList>{items}</serviceList></device></deviceList></device></deviceList></device></root>").encode()


class FakeRouter:
    """The router's HTTP side.  ``overrides`` maps ``(method, target, action)`` or ``(method, target)`` to a Reply or
    to ``callable(request) -> Reply``."""

    def __init__(self, clock: Clock, services=(), *, description: Optional[bytes] = None,
                 desc_path: str = "/rootDesc.xml", urlbase: Optional[str] = None) -> None:
        self.clock = clock
        self.services = list(services)
        self.description = description if description is not None else describe(self.services, urlbase=urlbase)
        self.desc_path = desc_path
        self.overrides: Dict[tuple, Any] = {}
        self.connections: List[tuple] = []
        self.requests: List[SimpleNamespace] = []
        self.responses: List[FakeResponse] = []

    def connection(self, host, port, timeout) -> FakeConn:
        self.connections.append((host, port, timeout))
        return FakeConn(self, host, port, timeout)

    def respond(self, request) -> Reply:
        action = request.headers.get("SOAPACTION", "").strip('"').rpartition("#")[2] or None
        for key in ((request.method, request.target, action), (request.method, request.target)):
            if key in self.overrides:
                value = self.overrides[key]
                return value(request) if callable(value) else value
        if request.method == "GET" and request.target == self.desc_path:
            return Reply(200, self.description)
        if request.method == "POST":
            for svc in self.services:
                if svc.path == request.target:
                    return svc.handle(action, request.body or b"")
        return Reply(404, b"not found")

    def actions(self) -> List[str]:
        return [r.headers["SOAPACTION"].strip('"').rpartition("#")[2] for r in self.requests if r.method == "POST"]


class FakePinger:
    """``hops`` maps a TTL to the address that answers it (the target itself answers as a real echo reply), to a
    ready reply object, or to an exception; an unlisted TTL times out."""

    def __init__(self, hops: Dict[int, Any], clock: Optional[Clock] = None, per_call_s: float = 0.0) -> None:
        self.hops, self.clock, self.per_call_s = hops, clock, per_call_s
        self.calls: List[tuple] = []
        self.closed = False

    def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
        self.calls.append((ip, size, timeout_ms, ttl))
        if self.clock is not None:
            self.clock.advance(self.per_call_s)
        value = self.hops.get(ttl)
        if isinstance(value, BaseException):
            raise value
        if value is None:
            return SimpleNamespace(ok=False, rtt_ms=None, status=11010, responder=None)
        if isinstance(value, str):
            if value == ip:
                return SimpleNamespace(ok=True, rtt_ms=7.254, status=0, responder=ip)
            return SimpleNamespace(ok=False, rtt_ms=None, status=11013, responder=value)
        return value

    def close(self) -> None:
        self.closed = True


class PingerFactory:
    def __init__(self, hops: Dict[int, Any], clock: Optional[Clock] = None, per_call_s: float = 0.0) -> None:
        self.hops, self.clock, self.per_call_s = hops, clock, per_call_s
        self.made: List[FakePinger] = []

    def __call__(self) -> FakePinger:
        pinger = FakePinger(self.hops, self.clock, self.per_call_s)
        self.made.append(pinger)
        return pinger


def ssdp_reply(location: Optional[str] = LOCATION, *, status: str = "HTTP/1.1 200 OK", server: str = SERVER) -> bytes:
    lines = [status, "CACHE-CONTROL: max-age=120", f"ST: {nc.SSDP_ST}", "EXT:", f"SERVER: {server}",
             f"USN: uuid:00000000-0000-4000-8000-000000000001::{nc.SSDP_ST}"]
    if location is not None:
        lines.append(f"LOCATION: {location}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def natpmp_reply(result: int, ip: str = "0.0.0.0") -> bytes:
    return struct.pack("!BBHI", 0, 0x80, result, 12345) + socket.inet_aton(ip)


UPNP_ANSWER = [(ssdp_reply(), (GATEWAY, 1900))]


class Harness:
    """One check_nat run against fake sockets, a fake router and a fake pinger (all on one fake clock)."""

    def __init__(self, monkeypatch, *, natpmp=None, ssdp=None, services=(), hops=None, urlbase=None,
                 description: Optional[bytes] = None, per_ping_s: float = 0.0) -> None:
        self.clock = Clock()
        self.net = FakeNet(self.clock, natpmp, ssdp)
        self.router = FakeRouter(self.clock, services, urlbase=urlbase, description=description)
        self.pingers = PingerFactory(hops or {}, self.clock, per_ping_s)
        monkeypatch.setattr(nc, "_udp_socket", self.net.socket)
        monkeypatch.setattr(nc, "_http_connection", self.router.connection)

    def run(self, nic: Optional[Adapter] = None, adapters=None, public_ip: Any = PUBLIC, **knobs) -> Dict[str, Any]:
        nic = nic if nic is not None else adapter()
        self.started = self.clock.t
        return nc.check_nat(nic=nic, adapters=[nic] if adapters is None else adapters, public_ip=public_ip,
                            pinger_factory=self.pingers, generation=7, clock=self.clock.time,
                            monotonic=self.clock.monotonic, **knobs)

    @property
    def elapsed(self) -> float:
        return self.clock.t - self.started


# =========================================================================== guard, constants, shapes
def test_conftest_guard_blocks_router_traffic():
    with pytest.raises(OSError, match=r"network access is disabled in tests \(tnt\.natcheck\)"):
        nc._udp_socket(socket.AF_INET, socket.SOCK_DGRAM)
    with pytest.raises(OSError, match=r"network access is disabled in tests \(tnt\.natcheck\)"):
        nc._http_connection(GATEWAY, 80, 1.0)


def test_a_check_without_fakes_fails_closed_at_the_guard():
    clock = Clock()
    pingers = PingerFactory({1: PUBLIC})
    result = nc.check_nat(nic=adapter(), adapters=[], public_ip=PUBLIC, pinger_factory=pingers, generation=3,
                          clock=clock.time, monotonic=clock.monotonic)
    assert result["router"]["natpmp"] == {"answered": False, "result": None, "external_ip": None}
    assert result["router"]["upnp"]["found"] is False and result["port_mappings"] is None
    assert (result["verdict"], result["confidence"]) == ("single_nat", "medium")
    assert pingers.made[0].closed


def test_shapes_and_texts_are_pinned():
    assert nc.NAT_VERDICTS == ("no_nat", "single_nat", "double_nat", "cgnat", "upstream_nat",
                               "nat_unclear_private_wan", "vpn", "offline", "unknown")
    assert nc.NAT_RESULT_KEYS == ("ts", "generation", "duration_ms", "verdict", "confidence", "title", "explanation",
                                  "router", "public_ip", "trace", "port_mappings", "error")
    assert nc.ROUTER_KEYS == ("gateway", "wan_ip", "wan_source", "natpmp", "upnp")
    assert nc.NATPMP_KEYS == ("answered", "result", "external_ip")
    assert nc.UPNP_KEYS == ("found", "server", "model", "service", "status", "external_ip", "error")
    assert nc.TRACE_KEYS == ("reached_ttl", "hops")
    assert nc.HOP_KEYS == ("ttl", "ip", "rtt_ms", "range")
    assert nc.PORT_MAPPINGS_KEYS == ("entries", "truncated", "error")
    assert nc.MAPPING_KEYS == ("protocol", "external_port", "internal_client", "internal_port", "enabled",
                               "description", "lease_s")
    assert nc.CONFIDENCES == ("high", "medium", "low")
    assert nc.NAT_TEXT == {
        "no_nat": ("No NAT", "This PC has the public address itself. Nothing to forward: Windows Firewall decides "
                             "what gets in."),
        "single_nat": ("Single NAT", "One router holds the public address. Port forwards on it work, unless the ISP "
                                     "blocks the port."),
        "double_nat": ("Double NAT", "Another NAT sits between this network's router and the internet (usually the "
                                     "ISP modem or gateway, sometimes the ISP itself). Forward ports on both, or put "
                                     "the ISP box in bridge / IP-passthrough mode."),
        "cgnat": ("Carrier-grade NAT (CGNAT)", "The ISP shares one public address between customers, so port "
                                               "forwarding from the internet cannot work on IPv4. Ask the ISP for a "
                                               "public or static IP, or use the device's cloud/P2P service or a VPN."),
        "upstream_nat": ("NAT beyond the router", "Websites see an address the router does not have, so something "
                                                  "beyond it translates again (ISP NAT, an upstream firewall, a second "
                                                  "line or a VPN)."),
        "nat_unclear_private_wan": ("Probably behind another NAT", "The router reports no usable public address "
                                                                   "although the internet works. That usually means "
                                                                   "it sits behind another NAT."),
        "vpn": ("Traffic leaves through a VPN", "This PC's internet traffic goes through a VPN, so a check would "
                                                "describe the VPN, not this site's router. Disconnect it and check "
                                                "again."),
        "offline": ("Could not check", "No internet connection (or no public address yet), so NAT cannot be "
                                       "checked."),
        "unknown": ("Could not tell", "The router does not answer UPnP or NAT-PMP and the path gave no clear sign."),
    }
    texts = [t for pair in nc.NAT_TEXT.values() for t in pair] + [
        nc.NO_INTERNET_ERROR, nc.NO_PUBLIC_IP_ERROR, nc.NO_GATEWAY_ERROR, nc.CONTROL_NOT_ROUTER_ERROR,
        nc.MAPPINGS_NOT_SHARED_ERROR, nc.BUSY_TEXT]
    assert not [t for t in texts if "n't" in t or not t.isascii()]
    assert (nc.NO_INTERNET_ERROR, nc.NO_PUBLIC_IP_ERROR, nc.NO_GATEWAY_ERROR) == (
        "no internet connection", "no public address yet", "no IPv4 gateway")
    assert nc.CONTROL_NOT_ROUTER_ERROR == "the router's control address is not the router"
    assert nc.MAPPINGS_NOT_SHARED_ERROR == "the router does not share its port forwards"
    assert nc.BUSY_TEXT == "a NAT check is already running"


def test_result_shape_follows_the_key_order(monkeypatch):
    h = Harness(monkeypatch, natpmp=[[natpmp_reply(0, PUBLIC)]], ssdp=UPNP_ANSWER,
                services=[Svc(mappings=[mapping(8000, description="NVR web")])])
    r = h.run()
    assert tuple(r) == nc.NAT_RESULT_KEYS
    assert tuple(r["router"]) == nc.ROUTER_KEYS
    assert tuple(r["router"]["natpmp"]) == nc.NATPMP_KEYS and tuple(r["router"]["upnp"]) == nc.UPNP_KEYS
    assert tuple(r["port_mappings"]) == nc.PORT_MAPPINGS_KEYS
    assert tuple(r["port_mappings"]["entries"][0]) == nc.MAPPING_KEYS
    assert r["ts"] == T0 + 1000.0 and r["generation"] == 7 and isinstance(r["duration_ms"], int)
    assert (r["verdict"], r["confidence"], r["error"]) == ("single_nat", "high", None)
    assert (r["title"], r["explanation"]) == nc.NAT_TEXT["single_nat"]
    assert r["public_ip"] == PUBLIC and r["trace"] is None
    assert r["router"]["gateway"] == GATEWAY
    assert (r["router"]["wan_ip"], r["router"]["wan_source"]) == (PUBLIC, "upnp")
    assert r["router"]["natpmp"] == {"answered": True, "result": 0, "external_ip": PUBLIC}
    assert r["router"]["upnp"] == {"found": True, "server": SERVER, "model": "Example Router XR-1", "service": IP1,
                                   "status": "Connected", "external_ip": PUBLIC, "error": None}
    assert r["port_mappings"] == {"entries": [{"protocol": "TCP", "external_port": 8000, "internal_client": "10.0.0.60",
                                               "internal_port": 8000, "enabled": True, "description": "NVR web",
                                               "lease_s": 0}], "truncated": False, "error": None}
    traced = Harness(monkeypatch, hops={1: "192.168.50.1", 2: PUBLIC}).run()
    assert tuple(traced["trace"]) == nc.TRACE_KEYS
    assert [tuple(hop) for hop in traced["trace"]["hops"]] == [nc.HOP_KEYS, nc.HOP_KEYS]
    assert traced["port_mappings"] is None


@pytest.mark.parametrize("ip,expected", [
    ("10.20.30.40", "private"), ("172.16.5.4", "private"), ("172.31.255.254", "private"), ("172.32.0.9", "public"),
    ("192.168.50.1", "private"), ("100.64.0.1", "shared"), ("100.127.255.254", "shared"), ("100.128.0.9", "public"),
    ("100.63.255.254", "public"), ("192.0.0.2", "shared"), ("192.0.0.7", "shared"), ("192.0.0.8", "reserved"),
    ("192.0.0.170", "reserved"), ("0.0.0.0", "reserved"), ("0.1.2.3", "reserved"), ("127.0.0.1", "reserved"),
    ("169.254.1.1", "reserved"), ("198.18.0.9", "reserved"), ("198.19.255.254", "reserved"),
    ("198.20.0.9", "public"), ("224.0.0.251", "reserved"), ("239.255.255.250", "reserved"),
    ("240.0.0.9", "reserved"), ("255.255.255.255", "reserved"), ("192.0.2.1", "public"),
    ("198.51.100.7", "public"), ("203.0.113.5", "public"), ("192.0.1.9", "public"),
    (None, None), ("", None), ("fe80::1", None), ("2001:db8::5", None), ("::ffff:10.20.30.40", None),
    (" 203.0.113.5", None), ("203.0.113", None), ("router.example", None), (3405803781, None),
])
def test_range_of(ip, expected):
    assert nc.range_of(ip) == expected


def test_ranges_are_explicit_networks_in_order():
    assert nc.NAT_RANGES == (
        ("private", ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
        ("shared", ("100.64.0.0/10", "192.0.0.0/29")),
        ("reserved", ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "198.18.0.0/15", "224.0.0.0/4",
                      "240.0.0.0/4")),
    )


# =========================================================================== NAT-PMP
def test_natpmp_asks_the_gateway_for_its_external_address(monkeypatch):
    h = Harness(monkeypatch, natpmp=[[natpmp_reply(0, PUBLIC)]])
    r = h.run()
    sock = h.net.natpmp_socket()
    assert (sock.family, sock.kind, sock.connected) == (socket.AF_INET, socket.SOCK_DGRAM, (GATEWAY, 5351))
    assert sock.sent == [(b"\x00\x00", (GATEWAY, 5351))] and sock.closed
    assert r["router"]["natpmp"] == {"answered": True, "result": 0, "external_ip": PUBLIC}
    assert (r["router"]["wan_ip"], r["router"]["wan_source"]) == (PUBLIC, "natpmp")
    assert (r["verdict"], r["confidence"]) == ("single_nat", "high")
    assert h.pingers.made == []                   # a usable WAN address: no trace, no pinger


def test_natpmp_result_other_than_zero_has_no_address(monkeypatch):
    h = Harness(monkeypatch, natpmp=[[natpmp_reply(3)]])
    assert h.run()["router"]["natpmp"] == {"answered": True, "result": 3, "external_ip": None}
    assert nc.parse_natpmp_reply(struct.pack("!BBHI", 0, 0x80, 2, 1) + socket.inet_aton(PUBLIC)) == {
        "answered": True, "result": 2, "external_ip": None}


@pytest.mark.parametrize("datagram", [
    natpmp_reply(0, PUBLIC)[:8],                  # short (the unsupported-version form)
    natpmp_reply(0, PUBLIC)[:11],
    natpmp_reply(0, PUBLIC) + b"\x00",
    b"\x00\x81" + natpmp_reply(0, PUBLIC)[2:],    # wrong opcode
    b"\x02\x80" + natpmp_reply(0, PUBLIC)[2:],    # wrong version
])
def test_natpmp_ignores_anything_but_a_12_byte_address_response(monkeypatch, datagram):
    h = Harness(monkeypatch, natpmp=[[datagram]])
    r = h.run()
    sock = h.net.natpmp_socket()
    assert r["router"]["natpmp"] == {"answered": False, "result": None, "external_ip": None}
    assert len(sock.sent) == 3 and sock.closed
    assert sock.timeouts == [0.25, 0.25, 0.5, 1.0]   # the stray datagram does not end the first wait
    assert nc.parse_natpmp_reply(datagram) is None


def test_natpmp_port_unreachable_stops_at_once(monkeypatch):
    h = Harness(monkeypatch, natpmp=[[ConnectionResetError(10054, "An existing connection was forcibly closed")]])
    r = h.run()
    sock = h.net.natpmp_socket()
    assert r["router"]["natpmp"] == {"answered": False, "result": None, "external_ip": None}
    assert len(sock.sent) == 1 and sock.closed


def test_natpmp_silence_waits_250_500_1000_ms(monkeypatch):
    h = Harness(monkeypatch)
    h.run(ssdp_read_s=0.0, trace_ttls=0)
    assert h.net.natpmp_socket().timeouts == [0.25, 0.5, 1.0]


# =========================================================================== SSDP
def test_ssdp_request_bytes_are_pinned():
    agent = f"USER-AGENT: Windows/10.0 UPnP/1.1 TNT/{tnt.__version__}\r\n\r\n".encode()
    assert nc.DEFAULT_USER_AGENT == f"Windows/10.0 UPnP/1.1 TNT/{tnt.__version__}"
    assert nc.ssdp_request(GATEWAY, multicast=False) == (
        b"M-SEARCH * HTTP/1.1\r\nHOST: 192.0.2.1:1900\r\nMAN: \"ssdp:discover\"\r\n"
        b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" + agent)
    assert nc.ssdp_request("239.255.255.250", multicast=True) == (
        b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
        b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" + agent)


def test_ssdp_search_socket_order_and_first_reply(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc()])
    h.run()
    sock = h.net.ssdp_socket()
    assert (sock.family, sock.kind, sock.bound) == (socket.AF_INET, socket.SOCK_DGRAM, (PC_IP, 0))
    assert (socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(PC_IP)) in sock.options
    assert (socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2) in sock.options
    assert sock.sent == [(nc.ssdp_request(GATEWAY, multicast=False), (GATEWAY, 1900)),
                         (nc.ssdp_request("239.255.255.250", multicast=True), ("239.255.255.250", 1900))]
    assert sock.reads == 1 and sock.read_sizes == [2048] and sock.closed


@pytest.mark.parametrize("read_s,budget_s,window", [(2.5, 20.0, 2.5), (0.5, 20.0, 2.0), (4.0, 20.0, 4.0),
                                                     (2.5, 1.0, 1.0)])
def test_ssdp_read_window(monkeypatch, read_s, budget_s, window):
    h = Harness(monkeypatch)
    h.run(natpmp_waits_ms=(), ssdp_read_s=read_s, budget_s=budget_s, trace_ttls=0)
    assert h.net.ssdp_socket().timeouts == [window]


def test_ssdp_skips_strays_until_the_gateway_answers(monkeypatch):
    strays = [ConnectionResetError(10054, "reset"), (ssdp_reply(), (OTHER_PUBLIC, 1900)),
              (ssdp_reply(status="HTTP/1.1 404 Not Found"), (GATEWAY, 1900)),
              (ssdp_reply(f"http://{OTHER_PUBLIC}:5000/rootDesc.xml"), (GATEWAY, 1900)),
              (ssdp_reply(), (GATEWAY, 1900))]
    h = Harness(monkeypatch, ssdp=strays, services=[Svc()])
    r = h.run()
    assert r["router"]["upnp"]["found"] is True and h.net.ssdp_socket().reads == 5
    assert {host for host, _port, _timeout in h.router.connections} == {GATEWAY}


def test_ssdp_without_an_ipv4_address_on_the_adapter(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc()], hops={1: PUBLIC})
    r = h.run(nic=adapter(ip=None))
    assert h.net.ssdp_socket() is None and r["router"]["upnp"]["found"] is False


@pytest.mark.parametrize("data,source,accepted", [
    (ssdp_reply(), (GATEWAY, 1900), True),
    (ssdp_reply(), (GATEWAY, 49152), True),
    (ssdp_reply(f"http://{GATEWAY}/rootDesc.xml"), (GATEWAY, 1900), True),
    (ssdp_reply(), (OTHER_PUBLIC, 1900), False),
    (ssdp_reply(), None, False),
    (ssdp_reply(status="HTTP/1.1 404 Not Found"), (GATEWAY, 1900), False),
    (ssdp_reply(status="HTTP/1.0 200 OK"), (GATEWAY, 1900), False),
    (ssdp_reply(status="NOTIFY * HTTP/1.1"), (GATEWAY, 1900), False),
    (ssdp_reply(None), (GATEWAY, 1900), False),
    (ssdp_reply(f"http://{GATEWAY}:5000/" + "a" * 600), (GATEWAY, 1900), False),
    (ssdp_reply(f"http://{GATEWAY}:5000/" + "a" * (512 - len(f"http://{GATEWAY}:5000/"))), (GATEWAY, 1900), True),
    (ssdp_reply(f"http://{GATEWAY}:5000/" + "a" * (513 - len(f"http://{GATEWAY}:5000/"))), (GATEWAY, 1900), False),
    (ssdp_reply(f"https://{GATEWAY}:5000/rootDesc.xml"), (GATEWAY, 1900), False),
    (ssdp_reply("http://router.example:5000/rootDesc.xml"), (GATEWAY, 1900), False),
    (ssdp_reply(f"http://{OTHER_PUBLIC}:5000/rootDesc.xml"), (GATEWAY, 1900), False),
    (ssdp_reply("http://127.0.0.1:7130/api/dhcp/stop"), (GATEWAY, 1900), False),
    (ssdp_reply(f"http://{GATEWAY}:0/rootDesc.xml"), (GATEWAY, 1900), False),
    (ssdp_reply(f"http://{GATEWAY}:70000/rootDesc.xml"), (GATEWAY, 1900), False),
    (ssdp_reply(f"http://user@{GATEWAY}:5000/rootDesc.xml"), (GATEWAY, 1900), False),
    (ssdp_reply(f"http://{OTHER_PUBLIC}@{GATEWAY}:5000/rootDesc.xml"), (GATEWAY, 1900), False),
    (ssdp_reply(f"http://[::1]:5000/rootDesc.xml"), (GATEWAY, 1900), False),
])
def test_ssdp_reply_acceptance(data, source, accepted):
    got = nc._accept_ssdp(data, source, GATEWAY)
    assert (got is not None) is accepted
    if accepted:
        assert got[1] == SERVER


def test_router_url_check():
    assert nc._router_url(f"http://{GATEWAY}:5000/ctl/IPConn?x=1", GATEWAY) == (5000, "/ctl/IPConn?x=1")
    assert nc._router_url(f"http://{GATEWAY}", GATEWAY) == (80, "/")
    for bad in (f"http://{GATEWAY}:5000/ctl IPConn", f"http://{GATEWAY}:5000/ctl\r\nX-Evil: 1",
                f"HTTP://{GATEWAY}.:5000/", f"http://{GATEWAY}:abc/", f"ftp://{GATEWAY}/", "/ctl/IPConn", "",
                None, f"http://{GATEWAY}:5000/" + "x" * 520):
        assert nc._router_url(bad, GATEWAY) is None, bad


# =========================================================================== UPnP: requests and safety
def posts(h: Harness) -> List[tuple]:
    return [(r.target, r.headers["SOAPACTION"].strip('"').rpartition("#")[2]) for r in h.router.requests
            if r.method == "POST"]


def test_description_and_soap_requests_are_pinned_and_read_only(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc(mappings=[mapping(8000)])])
    h.run()
    get = h.router.requests[0]
    assert (get.host, get.port, get.method, get.target) == (GATEWAY, 5000, "GET", "/rootDesc.xml")
    assert get.headers == {"Host": "192.0.2.1:5000", "User-Agent": nc.DEFAULT_USER_AGENT, "Connection": "close"}
    first = h.router.requests[1]
    assert (first.method, first.target) == ("POST", "/ctl/IPConn")
    assert first.headers == {"Host": "192.0.2.1:5000", "User-Agent": nc.DEFAULT_USER_AGENT, "Connection": "close",
                             "Content-Type": 'text/xml; charset="utf-8"', "SOAPACTION": f'"{IP1}#GetStatusInfo"'}
    assert first.body == (
        SOAP_ENV + f'<u:GetStatusInfo xmlns:u="{IP1}"></u:GetStatusInfo></s:Body></s:Envelope>').encode()
    assert posts(h) == [("/ctl/IPConn", "GetStatusInfo"), ("/ctl/IPConn", "GetExternalIPAddress"),
                        ("/ctl/IPConn", "GetGenericPortMappingEntry"), ("/ctl/IPConn", "GetGenericPortMappingEntry")]
    walk = [r.body for r in h.router.requests if r.method == "POST"][2:]
    assert b"<NewPortMappingIndex>0</NewPortMappingIndex>" in walk[0]
    assert b"<NewPortMappingIndex>1</NewPortMappingIndex>" in walk[1]
    assert {r.method for r in h.router.requests} == {"GET", "POST"}
    assert {(host, port) for host, port, _timeout in h.router.connections} == {(GATEWAY, 5000)}
    assert nc.SOAP_ACTIONS == ("GetStatusInfo", "GetExternalIPAddress", "GetGenericPortMappingEntry")


@pytest.mark.parametrize("action", ["AddPortMapping", "DeletePortMapping", "SetConnectionType", "ForceTermination",
                                    "Subscribe"])
def test_soap_envelope_builds_read_only_actions_only(action):
    with pytest.raises(ValueError):
        nc.soap_envelope(IP1, action)
    with pytest.raises(ValueError):
        nc.soap_envelope("urn:schemas-upnp-org:service:WANIPConnection:3", "GetStatusInfo")
    assert nc.soap_envelope(PPP1, "GetGenericPortMappingEntry", [("NewPortMappingIndex", 3)]) == (
        SOAP_ENV + f'<u:GetGenericPortMappingEntry xmlns:u="{PPP1}"><NewPortMappingIndex>3</NewPortMappingIndex>'
        "</u:GetGenericPortMappingEntry></s:Body></s:Envelope>").encode()


@pytest.mark.parametrize("urlbase,control", [
    ("http://127.0.0.1:7130/", "/api/dhcp/stop"),         # an absolute URLBase at this PC's own API
    (None, f"http://{OTHER_PUBLIC}:5000/ctl/IPConn"),      # an absolute control URL on another host
    (None, "//198.51.100.7/ctl/IPConn"),                  # a network-path reference
    (None, f"https://{GATEWAY}:5000/ctl/IPConn"),
    (None, f"http://{GATEWAY}:0/ctl/IPConn"),
])
def test_a_control_address_off_the_router_opens_no_connection(monkeypatch, urlbase, control):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc(IP1, control), Svc(PPP1, control)], urlbase=urlbase)
    r = h.run(trace_ttls=0)
    assert h.router.connections == [(GATEWAY, 5000, 2.0)]          # the description, nothing else
    upnp = r["router"]["upnp"]
    assert (upnp["found"], upnp["service"], upnp["error"]) == (True, None, nc.CONTROL_NOT_ROUTER_ERROR)
    assert r["port_mappings"] is None and r["router"]["wan_ip"] is None


def test_a_bad_control_address_only_skips_that_service(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER,
                services=[Svc(IP2, f"http://{OTHER_PUBLIC}:5000/ctl/IP2"), Svc(IP1, "/ctl/IPConn")])
    r = h.run()
    assert {host for host, _port, _timeout in h.router.connections} == {GATEWAY}
    assert (r["router"]["upnp"]["service"], r["router"]["upnp"]["error"]) == (IP1, None)
    assert (r["verdict"], r["confidence"]) == ("single_nat", "high")


def test_redirects_are_never_followed(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc()])
    h.router.overrides[("GET", "/rootDesc.xml")] = Reply(302, b"<html>moved</html>")
    r = h.run(trace_ttls=0)
    assert len(h.router.connections) == 1 and h.router.responses[0].reads == 0
    assert (r["router"]["upnp"]["found"], r["router"]["upnp"]["model"], r["port_mappings"]) == (True, None, None)
    soap = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc()])
    soap.router.overrides[("POST", "/ctl/IPConn", "GetStatusInfo")] = Reply(307, b"moved")
    r = soap.run(trace_ttls=0)
    assert {host for host, _port, _timeout in soap.router.connections} == {GATEWAY}
    assert posts(soap) == [("/ctl/IPConn", "GetStatusInfo"), ("/ctl/IPConn", "GetGenericPortMappingEntry")]
    assert (r["router"]["upnp"]["service"], r["router"]["upnp"]["status"]) == (IP1, None)


def test_a_dripping_router_is_cut_off_at_the_deadline(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc()])
    h.router.overrides[("GET", "/rootDesc.xml")] = Reply(200, h.router.description, chunk=1, delay=0.5)
    r = h.run(natpmp_waits_ms=(), trace_ttls=0)
    assert h.router.responses[0].reads == 4                        # 1 byte every 0.5 s, 2.0 s allowed
    assert h.elapsed == pytest.approx(2.0)
    assert len(h.router.connections) == 1
    assert (r["router"]["upnp"]["found"], r["router"]["upnp"]["model"]) == (True, None)


@pytest.mark.parametrize("body", [
    b'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY a "b">]><root><device/></root>',
    b'<?xml version="1.0"?><!doctype root><root/>',
    b'<?xml version="1.0"?><root><!ENTITY a "b"></root>',
    '<?xml version="1.0" encoding="utf-16"?><!DOCTYPE root><root/>'.encode("utf-16"),
    b"<root><device><manufacturer>Example</manufacturer>",         # not XML
])
def test_an_unsafe_or_unreadable_description_is_refused(monkeypatch, body):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc()])
    h.router.overrides[("GET", "/rootDesc.xml")] = Reply(200, body)
    r = h.run(trace_ttls=0)
    assert len(h.router.connections) == 1
    assert (r["router"]["upnp"]["found"], r["router"]["upnp"]["model"], r["router"]["upnp"]["service"]) == (
        True, None, None)


def test_a_soap_reply_with_a_doctype_is_refused(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc()])
    doctype = soap_ok(IP1, "GetStatusInfo", NewConnectionStatus="Connected")
    doctype.body = doctype.body.replace(b"?>", b'?><!DOCTYPE s:Envelope [<!ENTITY c "Connected">]>', 1)
    h.router.overrides[("POST", "/ctl/IPConn", "GetStatusInfo")] = doctype
    r = h.run(trace_ttls=0)
    assert (r["router"]["upnp"]["status"], r["router"]["wan_ip"]) == (None, None)


def test_an_oversized_body_is_abandoned(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc()])
    padded = h.router.description.replace(b"</root>", b"<!-- " + b"x" * (300 * 1024) + b" --></root>")
    h.router.overrides[("GET", "/rootDesc.xml")] = Reply(200, padded)
    r = h.run(trace_ttls=0)
    assert h.router.responses[0].reads == nc.HTTP_BODY_MAX // nc.HTTP_CHUNK + 1    # not read to the end
    assert len(padded) > nc.HTTP_BODY_MAX + 2 * nc.HTTP_CHUNK
    assert (r["router"]["upnp"]["model"], r["port_mappings"]) == (None, None)


def test_an_error_status_body_is_not_read(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc()])
    h.router.overrides[("GET", "/rootDesc.xml")] = Reply(404, b"x" * 100_000)
    h.run(trace_ttls=0)
    assert h.router.responses[0].reads == 0 and h.router.responses[0].closed


class DripRaw:
    """The raw stream a DripSocket hands out: one byte per read, each taking ``delay`` fake seconds."""

    def __init__(self, sock: "DripSocket") -> None:
        self.sock = sock
        self.closed = False

    def readinto(self, buffer) -> int:
        self.sock.reads += 1
        self.sock.clock.advance(self.sock.delay)
        if self.sock.pos >= len(self.sock.data):
            return 0
        buffer[0] = self.sock.data[self.sock.pos]
        self.sock.pos += 1
        return 1

    def close(self) -> None:
        self.closed = True


class DripSocket:
    """A socket stand-in for http.client: only ``makefile`` and ``settimeout`` are used."""

    def __init__(self, clock: Clock, data: bytes, delay: float) -> None:
        self.clock, self.data, self.delay = clock, data, delay
        self.pos = 0
        self.reads = 0
        self.timeouts: List[float] = []

    def settimeout(self, value) -> None:
        self.timeouts.append(value)

    def makefile(self, mode="rb", buffering=None) -> DripRaw:
        return DripRaw(self)


def test_router_connection_bounds_the_status_line_and_headers_too():
    clock = Clock()
    conn = nc._RouterConnection(GATEWAY, 5000, 2.0)
    assert isinstance(conn, http.client.HTTPConnection) and conn.deadline is None
    conn.deadline = (clock.monotonic, clock.t + 2.0)
    slow = DripSocket(clock, b"HTTP/1.1 200 OK\r\nServer: slow\r\n\r\n", delay=0.5)
    response = conn.response_class(slow, method="GET")
    with pytest.raises(TimeoutError):
        response.begin()
    assert slow.reads == 4 and slow.timeouts == [2.0, 1.5, 1.0, 0.5]
    response.close()
    conn.deadline = (clock.monotonic, clock.t + 2.0)
    quick = DripSocket(clock, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", delay=0.0)
    response = conn.response_class(quick, method="GET")
    response.begin()
    assert (response.status, response.read()) == (200, b"ok")
    response.close()


def test_404_is_retried_once_with_the_host_root_path(monkeypatch):
    location = [(ssdp_reply(f"http://{GATEWAY}:5000/upnp/rootDesc.xml"), (GATEWAY, 1900))]
    h = Harness(monkeypatch, ssdp=location, services=[Svc(IP1, "ctl/IPConn", path="/ctl/IPConn",
                                                          mappings=[mapping(8000)])])
    h.router.desc_path = "/upnp/rootDesc.xml"
    r = h.run()
    assert posts(h) == [("/upnp/ctl/IPConn", "GetStatusInfo"), ("/ctl/IPConn", "GetStatusInfo"),
                        ("/ctl/IPConn", "GetExternalIPAddress"), ("/ctl/IPConn", "GetGenericPortMappingEntry"),
                        ("/ctl/IPConn", "GetGenericPortMappingEntry")]
    assert (r["verdict"], r["confidence"]) == ("single_nat", "high") and len(r["port_mappings"]["entries"]) == 1
    once = Harness(monkeypatch, ssdp=location, services=[Svc(IP2, "ctl/A", path="/gone-a"),
                                                          Svc(IP1, "ctl/B", path="/gone-b")])
    once.router.desc_path = "/upnp/rootDesc.xml"
    r = once.run(trace_ttls=0)
    assert posts(once) == [("/upnp/ctl/A", "GetStatusInfo"), ("/ctl/A", "GetStatusInfo"),
                           ("/upnp/ctl/B", "GetStatusInfo"), ("/upnp/ctl/A", "GetGenericPortMappingEntry")]
    assert r["port_mappings"] == {"entries": [], "truncated": False, "error": None}


def test_the_404_retry_is_spent_only_by_a_host_root_request_that_was_sent(monkeypatch):
    location = [(ssdp_reply(f"http://{GATEWAY}:5000/upnp/rootDesc.xml"), (GATEWAY, 1900))]
    h = Harness(monkeypatch, ssdp=location, services=[Svc(IP2, "/gone", path="/nowhere"),   # already host-root
                                                       Svc(IP1, "ctl/B", path="/ctl/B")])
    h.router.desc_path = "/upnp/rootDesc.xml"
    r = h.run()
    assert posts(h)[:4] == [("/gone", "GetStatusInfo"), ("/upnp/ctl/B", "GetStatusInfo"),
                            ("/ctl/B", "GetStatusInfo"), ("/ctl/B", "GetExternalIPAddress")]
    assert (r["router"]["upnp"]["service"], r["verdict"], r["confidence"]) == (IP1, "single_nat", "high")


def test_a_host_root_retry_that_fails_puts_the_control_path_back(monkeypatch):
    location = [(ssdp_reply(f"http://{GATEWAY}:5000/upnp/rootDesc.xml"), (GATEWAY, 1900))]
    h = Harness(monkeypatch, ssdp=location, services=[Svc(IP1, "ctl/A", path="/nowhere")])
    h.router.desc_path = "/upnp/rootDesc.xml"
    h.router.overrides[("POST", "/ctl/A")] = Reply(302, b"moved")
    r = h.run(trace_ttls=0)
    assert posts(h) == [("/upnp/ctl/A", "GetStatusInfo"), ("/ctl/A", "GetStatusInfo"),
                        ("/upnp/ctl/A", "GetGenericPortMappingEntry")]
    assert r["port_mappings"] == {"entries": [], "truncated": False, "error": None}


# =========================================================================== UPnP: choosing a service
def test_ppp_service_is_chosen_when_the_ip_service_is_disconnected(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc(IP1, "/ctl/IPConn", status="Disconnected", external=""),
                                                         Svc(PPP1, "/ctl/PPPConn", external=PUBLIC)])
    r = h.run()
    upnp = r["router"]["upnp"]
    assert (upnp["service"], upnp["status"], upnp["external_ip"]) == (PPP1, "Connected", PUBLIC)
    assert (r["router"]["wan_ip"], r["router"]["wan_source"]) == (PUBLIC, "upnp")
    assert (r["verdict"], r["confidence"]) == ("single_nat", "high")
    assert posts(h) == [("/ctl/IPConn", "GetStatusInfo"), ("/ctl/PPPConn", "GetStatusInfo"),
                        ("/ctl/PPPConn", "GetExternalIPAddress"), ("/ctl/PPPConn", "GetGenericPortMappingEntry")]


def test_services_by_preference_stopping_at_the_first_connected_public_one(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc(PPP1, "/ctl/P"), Svc(IP1, "/ctl/I1"),
                                                         Svc(IP2, "/ctl/I2")])
    r = h.run()
    assert posts(h) == [("/ctl/I2", "GetStatusInfo"), ("/ctl/I2", "GetExternalIPAddress"),
                        ("/ctl/I2", "GetGenericPortMappingEntry")]
    assert r["router"]["upnp"]["service"] == IP2


def test_at_most_four_services_and_the_first_one_when_none_is_connected(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER,
                services=[Svc(IP1, f"/ctl/{i}", status="Disconnected") for i in range(6)])
    r = h.run(trace_ttls=0)
    assert [t for t, action in posts(h) if action == "GetStatusInfo"] == ["/ctl/0", "/ctl/1", "/ctl/2", "/ctl/3"]
    assert "GetExternalIPAddress" not in [action for _t, action in posts(h)]
    upnp = r["router"]["upnp"]
    assert (upnp["service"], upnp["status"], upnp["external_ip"]) == (IP1, "Disconnected", None)
    assert posts(h)[-1] == ("/ctl/0", "GetGenericPortMappingEntry")


@pytest.mark.parametrize("services,chosen,external", [
    ([Svc(IP2, "/a", external=""), Svc(IP1, "/b", external="10.20.30.40")], "/b", "10.20.30.40"),
    ([Svc(IP2, "/a", external=""), Svc(IP1, "/b", external="0.0.0.0")], "/a", ""),
    ([Svc(IP2, "/a", status="Up", external="10.20.30.40"), Svc(IP1, "/b", external=PUBLIC)], "/b", PUBLIC),
])
def test_service_choice_rules(monkeypatch, services, chosen, external):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=services)
    r = h.run(trace_ttls=0)
    assert posts(h)[-1][0] == chosen and r["router"]["upnp"]["external_ip"] == external


def test_model_and_server_are_capped_device_text(monkeypatch):
    long_server = "Example" + "S" * 200
    ssdp = [(ssdp_reply(server=long_server), (GATEWAY, 1900))]
    description = describe([Svc()], manufacturer="Example\tCorp", model="R" * 100)
    h = Harness(monkeypatch, ssdp=ssdp, services=[Svc()], description=description)
    upnp = h.run()["router"]["upnp"]
    assert upnp["server"] == long_server[:120]
    assert upnp["model"] == ("Example Corp " + "R" * 100)[:80]


# =========================================================================== UPnP: the port-mapping walk
def test_walk_stops_on_713(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER,
                services=[Svc(mappings=[mapping(8000), mapping(554, "10.0.0.61", protocol="udp"), mapping(8443)])])
    pm = h.run()["port_mappings"]
    assert [e["external_port"] for e in pm["entries"]] == [8000, 554, 8443]
    assert pm["entries"][1]["protocol"] == "UDP" and (pm["truncated"], pm["error"]) == (False, None)
    assert [a for _t, a in posts(h)].count("GetGenericPortMappingEntry") == 4


def test_walk_stops_on_a_repeated_entry(monkeypatch):
    rows = [mapping(8000), mapping(554, "10.0.0.61")]

    def entry(index: int) -> Reply:
        return soap_ok(IP1, "GetGenericPortMappingEntry", **rows[min(index, 1)])

    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc(entry=entry)])
    pm = h.run()["port_mappings"]
    assert [e["external_port"] for e in pm["entries"]] == [8000, 554] and pm["truncated"] is False
    same_but_remote = Harness(monkeypatch, ssdp=UPNP_ANSWER,
                              services=[Svc(mappings=[mapping(8000), mapping(8000, remote=OTHER_PUBLIC)])])
    assert len(same_but_remote.run()["port_mappings"]["entries"]) == 2


def test_walk_stops_at_64_entries(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER,
                services=[Svc(entry=lambda i: soap_ok(IP1, "GetGenericPortMappingEntry", **mapping(1000 + i)))])
    pm = h.run()["port_mappings"]
    assert len(pm["entries"]) == 64 and pm["truncated"] is True and pm["error"] is None
    assert [a for _t, a in posts(h)].count("GetGenericPortMappingEntry") == 64


def test_walk_stops_at_its_deadline(monkeypatch):
    def slow(index: int) -> Reply:
        reply = soap_ok(IP1, "GetGenericPortMappingEntry", **mapping(1000 + index))
        reply.delay = 0.4
        return reply

    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc(entry=slow)])
    pm = h.run(walk_s=1.0)["port_mappings"]
    assert len(pm["entries"]) == 2 and pm["truncated"] is True


@pytest.mark.parametrize("first,error", [
    (soap_fault(606), nc.MAPPINGS_NOT_SHARED_ERROR), (soap_fault(501), nc.MAPPINGS_NOT_SHARED_ERROR),
    (Reply(401, b""), nc.MAPPINGS_NOT_SHARED_ERROR), (Reply(403, b""), nc.MAPPINGS_NOT_SHARED_ERROR),
    (Reply(501, b""), nc.MAPPINGS_NOT_SHARED_ERROR), (soap_fault(713), None), (soap_fault(402), None),
    (Reply(500, b"not xml"), None),
])
def test_walk_errors_at_index_0(monkeypatch, first, error):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc(entry=lambda i: first)])
    assert h.run()["port_mappings"] == {"entries": [], "truncated": False, "error": error}


def test_walk_refusal_after_some_entries_keeps_them(monkeypatch):
    def entry(index: int) -> Reply:
        return soap_ok(IP1, "GetGenericPortMappingEntry", **mapping(8000 + index)) if index < 2 else soap_fault(606)

    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc(entry=entry)])
    assert h.run()["port_mappings"] == {
        "entries": [dict(protocol="TCP", external_port=8000 + i, internal_client="10.0.0.60", internal_port=8000 + i,
                         enabled=True, description="Camera", lease_s=0) for i in range(2)],
        "truncated": False, "error": None}


def test_mapping_fields_are_device_text(monkeypatch):
    odd = {"NewRemoteHost": "", "NewExternalPort": "eighty", "NewProtocol": "udp", "NewInternalPort": "554",
           "NewInternalClient": "10.0.0.61", "NewEnabled": "0", "NewPortMappingDescription": "Cam\tera " + "d" * 100,
           "NewLeaseDuration": "3600"}
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc(mappings=[odd])])
    assert h.run()["port_mappings"]["entries"] == [{
        "protocol": "UDP", "external_port": None, "internal_client": "10.0.0.61", "internal_port": 554,
        "enabled": False, "description": ("Cam era " + "d" * 100)[:80], "lease_s": 3600}]


# =========================================================================== verdicts
PATH_DOUBLE = {1: "192.168.50.1", 2: PUBLIC}
DISCONNECTED = [Svc(status="Disconnected", external="")]
EMPTY_WAN = [Svc(external="")]


@pytest.mark.parametrize("natpmp,ssdp,services,hops,expected", [
    ([[natpmp_reply(2)]], UPNP_ANSWER, DISCONNECTED, PATH_DOUBLE, ("double_nat", "medium")),
    (None, None, (), PATH_DOUBLE, ("double_nat", "low")),
    ([[natpmp_reply(3)]], UPNP_ANSWER, EMPTY_WAN, {1: "192.168.50.1", 2: "100.64.0.1"}, ("cgnat", "high")),
    ([[natpmp_reply(3)]], UPNP_ANSWER, EMPTY_WAN, {}, ("nat_unclear_private_wan", "low")),
    ([[natpmp_reply(3)]], UPNP_ANSWER, EMPTY_WAN, {1: PUBLIC}, ("single_nat", "medium")),
    (None, None, (), {1: PUBLIC}, ("single_nat", "medium")),
    (None, None, (), {1: "192.168.50.1", 2: "198.51.100.1", 3: PUBLIC}, ("unknown", None)),
])
def test_trace_verdict_vectors(monkeypatch, natpmp, ssdp, services, hops, expected):
    h = Harness(monkeypatch, natpmp=natpmp, ssdp=ssdp, services=services, hops=hops)
    r = h.run()
    assert (r["verdict"], r["confidence"]) == expected
    assert r["router"]["wan_ip"] is None and r["trace"] is not None
    assert (r["title"], r["explanation"]) == nc.NAT_TEXT[expected[0]]


@pytest.mark.parametrize("natpmp,services,wan,expected", [
    ([[natpmp_reply(0, PUBLIC)]], EMPTY_WAN, (PUBLIC, "natpmp"), ("single_nat", "high")),
    (None, [Svc(external="192.0.0.2")], ("192.0.0.2", "upnp"), ("cgnat", "high")),
    ([[natpmp_reply(0, "100.64.0.9")]], (), ("100.64.0.9", "natpmp"), ("cgnat", "high")),
    (None, [Svc(external="10.20.30.40")], ("10.20.30.40", "upnp"), ("double_nat", "medium")),
    ([[natpmp_reply(0, PUBLIC)]], [Svc(external=OTHER_PUBLIC)], (OTHER_PUBLIC, "upnp"), ("upstream_nat", "low")),
    (None, [Svc(external="169.254.1.1")], (None, None), ("nat_unclear_private_wan", "low")),
    (None, [Svc(external="0.0.0.0")], (None, None), ("nat_unclear_private_wan", "low")),
    ([[natpmp_reply(0, "0.0.0.0")]], (), (None, None), ("unknown", None)),
    (None, [Svc(external="not an address")], (None, None), ("unknown", None)),
    (None, [Svc(status="Disconnected", external=PUBLIC)], (None, None), ("unknown", None)),
])
def test_wan_evidence_vectors(monkeypatch, natpmp, services, wan, expected):
    h = Harness(monkeypatch, natpmp=natpmp, ssdp=UPNP_ANSWER if services else None, services=services)
    r = h.run()
    assert (r["router"]["wan_ip"], r["router"]["wan_source"]) == wan
    assert (r["verdict"], r["confidence"]) == expected
    assert (r["trace"] is None) is (wan[0] is not None)
    if natpmp and services:
        assert r["router"]["natpmp"]["external_ip"] == PUBLIC      # both kept when they differ


def hop(ttl, ip):
    return {"ttl": ttl, "ip": ip, "rtt_ms": 1.0 if ip else None, "range": nc.range_of(ip)}


def trace(reached, *ips):
    return {"reached_ttl": reached, "hops": [hop(i + 1, ip) for i, ip in enumerate(ips)]}


@pytest.mark.parametrize("kwargs,expected", [
    (dict(wan_ip="100.64.0.9"), ("cgnat", "high")),
    (dict(wan_ip="192.0.0.2", unclear=True), ("cgnat", "high")),
    (dict(wan_ip="10.20.30.40", trace=trace(1, PUBLIC)), ("double_nat", "medium")),
    (dict(wan_ip=PUBLIC), ("single_nat", "high")),
    (dict(wan_ip=OTHER_PUBLIC), ("upstream_nat", "low")),
    (dict(trace=trace(1, PUBLIC), unclear=True), ("single_nat", "medium")),
    (dict(trace=trace(3, "192.168.50.1", "100.64.0.1", PUBLIC)), ("cgnat", "medium")),
    (dict(trace=trace(3, "192.168.50.1", "100.64.0.1", PUBLIC), unclear=True), ("cgnat", "high")),
    (dict(trace=trace(None, "192.168.50.1", None, "100.64.0.1")), ("cgnat", "medium")),
    (dict(trace=trace(None, "192.168.50.1", None, None, "100.64.0.1")), ("unknown", None)),
    (dict(trace=trace(None, "100.64.0.1")), ("unknown", None)),
    (dict(trace=trace(2, "192.168.50.1", PUBLIC), natpmp_answered=True), ("double_nat", "medium")),
    (dict(trace=trace(2, "192.168.50.1", PUBLIC), upnp_found=True), ("double_nat", "medium")),
    (dict(trace=trace(2, "192.168.50.1", PUBLIC), upnp_found=True, unclear=True), ("double_nat", "high")),
    (dict(trace=trace(2, None, PUBLIC)), ("double_nat", "low")),
    (dict(trace=trace(2, None, PUBLIC), unclear=True), ("double_nat", "medium")),
    (dict(trace=trace(3, "198.51.100.1", "192.168.50.1", PUBLIC)), ("double_nat", "low")),
    (dict(trace=trace(4, None, None, "10.20.30.40", PUBLIC), unclear=True), ("double_nat", "medium")),
    (dict(trace=trace(3, "192.168.50.1", None, PUBLIC)), ("unknown", None)),
    (dict(trace=trace(3, "192.168.50.1", None, PUBLIC), unclear=True), ("nat_unclear_private_wan", "low")),
    (dict(unclear=True), ("nat_unclear_private_wan", "low")),
    (dict(), ("unknown", None)),
])
def test_evaluate_verdict_rows(kwargs, expected):
    args = dict(wan_ip=None, public_ip=PUBLIC, trace=None, unclear=False)
    args.update(kwargs)
    assert nc.evaluate_verdict(**args) == expected


def assert_no_probes(h: Harness) -> None:
    assert h.net.sockets == [] and h.router.connections == [] and h.pingers.made == []


def test_offline_without_an_internet_adapter_or_a_public_ipv4(monkeypatch):
    h = Harness(monkeypatch)
    r = nc.check_nat(nic=None, adapters=[], public_ip=PUBLIC, generation=4, clock=h.clock.time,
                     monotonic=h.clock.monotonic)
    assert (r["verdict"], r["confidence"], r["error"], r["generation"]) == ("offline", None, nc.NO_INTERNET_ERROR, 4)
    assert tuple(r) == nc.NAT_RESULT_KEYS and r["public_ip"] is None
    for bad in (None, "2001:db8::5", "not an address"):
        r = h.run(public_ip=bad)
        assert (r["verdict"], r["error"], r["public_ip"]) == ("offline", nc.NO_PUBLIC_IP_ERROR, None)
    assert_no_probes(h)


def test_no_nat_when_the_public_address_is_on_this_pc(monkeypatch):
    h = Harness(monkeypatch)
    other = adapter("Ethernet 2", ip="192.0.2.20", extra_ips=(PUBLIC,), index=22)
    r = h.run(adapters=[adapter(), other])
    assert (r["verdict"], r["confidence"]) == ("no_nat", "high")
    ppp = adapter("Dial-up", ip=PUBLIC, gateways=(), if_type=23, description="WAN Miniport (PPPOE)")
    assert (h.run(nic=ppp)["verdict"], h.run(nic=ppp)["confidence"]) == ("no_nat", "high")
    assert_no_probes(h)


@pytest.mark.parametrize("if_type,description", [
    (53, "Example Tunnel"), (131, "Example Tunnel"), (23, "WAN Miniport (IKEv2)"), (6, "TAP-Windows Adapter V9"),
    (6, "PANGP Virtual Ethernet Adapter"), (6, "Wintun Userspace Tunnel"), (6, "WireGuard Tunnel"),
    (6, "Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter"), (6, "Juniper Networks Virtual Adapter"),
    (6, "Zscaler Network Adapter"), (6, "Example VPN Adapter"),
])
def test_vpn_adapters(monkeypatch, if_type, description):
    h = Harness(monkeypatch)
    r = h.run(nic=adapter(if_type=if_type, description=description))
    assert (r["verdict"], r["confidence"], r["router"]["gateway"]) == ("vpn", "medium", GATEWAY)
    assert_no_probes(h)


@pytest.mark.parametrize("if_type,description", [
    (243, "Example Mobile Broadband Adapter"), (237, "Example WWAN"), (244, "Example WWAN"),
    (243, "Example Mobile Broadband Virtual Adapter"),        # WWAN is never a VPN, whatever its description says
    (6, "Hyper-V Virtual Ethernet Adapter"), (6, "VMware Virtual Ethernet Adapter for VMnet8"),
    (6, "VirtualBox Host-Only Ethernet Adapter"), (71, "Example Wireless Adapter"),
])
def test_adapters_that_are_not_vpns_run_the_probes(monkeypatch, if_type, description):
    h = Harness(monkeypatch, hops={1: PUBLIC})
    r = h.run(nic=adapter(if_type=if_type, description=description))
    assert (r["verdict"], r["confidence"]) == ("single_nat", "medium")
    assert h.net.natpmp_socket() is not None and h.pingers.made


def test_cgnat_when_this_pcs_own_address_is_shared(monkeypatch):
    h = Harness(monkeypatch)
    r = h.run(nic=adapter(ip="100.64.5.6", gateways=("100.64.5.1",)))
    assert (r["verdict"], r["confidence"]) == ("cgnat", "high")
    assert_no_probes(h)


def test_ipv6_only_gateway_skips_the_router_and_uses_the_trace(monkeypatch):
    h = Harness(monkeypatch, ssdp=UPNP_ANSWER, services=[Svc()], hops=PATH_DOUBLE)
    r = h.run(nic=adapter(gateways=("fe80::1%13",)))
    assert h.net.sockets == [] and h.router.connections == []
    assert r["router"]["gateway"] is None
    assert r["router"]["natpmp"] == {"answered": False, "result": None, "external_ip": None}
    assert r["router"]["upnp"] == {"found": False, "server": None, "model": None, "service": None, "status": None,
                                   "external_ip": None, "error": nc.NO_GATEWAY_ERROR}
    assert (r["verdict"], r["confidence"], r["port_mappings"]) == ("double_nat", "low", None)
    both = Harness(monkeypatch, natpmp=[[natpmp_reply(0, PUBLIC)]])
    assert both.run(nic=adapter(gateways=("fe80::1%13", GATEWAY)))["router"]["gateway"] == GATEWAY


# =========================================================================== self-traceroute
def test_trace_hop_rules(monkeypatch):
    ticks = iter(i * 0.0125 for i in range(1000))
    real = nc.time
    monkeypatch.setattr(nc, "time", SimpleNamespace(perf_counter=lambda: next(ticks), time=real.time,
                                                    monotonic=real.monotonic))
    hops = {1: "192.168.50.1", 2: SimpleNamespace(ok=False, rtt_ms=None, responder=None),
            3: RuntimeError("the pinger broke"), 4: SimpleNamespace(ok=True, rtt_ms=None, responder=None),
            5: "100.64.0.1", 6: PUBLIC}
    h = Harness(monkeypatch, hops=hops)
    r = h.run(nic=adapter(gateways=()))
    assert r["trace"] == {"reached_ttl": 4, "hops": [
        {"ttl": 1, "ip": "192.168.50.1", "rtt_ms": 12.5, "range": "private"},
        {"ttl": 2, "ip": None, "rtt_ms": None, "range": None},
        {"ttl": 3, "ip": None, "rtt_ms": None, "range": None},
        {"ttl": 4, "ip": PUBLIC, "rtt_ms": 12.5, "range": "public"},     # ok without responder or rtt: target, wall
    ]}
    pinger = h.pingers.made[0]
    assert pinger.calls == [(PUBLIC, 32, 800, ttl) for ttl in (1, 2, 3, 4)] and pinger.closed
    assert (r["verdict"], r["confidence"]) == ("unknown", None)             # hop 3 did not answer
    reached = Harness(monkeypatch, hops={1: "192.168.50.1", 2: PUBLIC}).run()
    assert reached["trace"]["hops"][1] == {"ttl": 2, "ip": PUBLIC, "rtt_ms": 7.25, "range": "public"}
    unanswered = Harness(monkeypatch, hops={}).run(nic=adapter(gateways=()))
    assert unanswered["trace"] == {"reached_ttl": None,
                                   "hops": [{"ttl": n, "ip": None, "rtt_ms": None, "range": None} for n in range(1, 7)]}
    wrong = Harness(monkeypatch, hops={1: SimpleNamespace(ok=False, rtt_ms=None, responder=PUBLIC), 2: PUBLIC}).run()
    assert wrong["trace"]["reached_ttl"] == 2                           # not ok: not reached, even from the target


def test_trace_stops_when_the_budget_runs_short_and_the_pinger_is_closed(monkeypatch):
    h = Harness(monkeypatch, hops={}, per_ping_s=0.8)
    r = h.run(nic=adapter(gateways=()), budget_s=3.0)
    assert [hop["ttl"] for hop in r["trace"]["hops"]] == [1, 2, 3] and h.pingers.made[0].closed
    short = Harness(monkeypatch, hops={1: PUBLIC})
    assert short.run(nic=adapter(gateways=()), budget_s=0.85)["trace"] is None and short.pingers.made == []
    raising = Harness(monkeypatch, hops={n: OSError("no route") for n in range(1, 7)})
    r = raising.run(nic=adapter(gateways=()))
    assert len(r["trace"]["hops"]) == 6 and raising.pingers.made[0].closed


def test_trace_without_a_pinger_still_gives_a_verdict(monkeypatch):
    h = Harness(monkeypatch)

    def broken() -> Any:
        raise OSError("IcmpCreateFile failed")

    r = nc.check_nat(nic=adapter(gateways=()), adapters=[], public_ip=PUBLIC, pinger_factory=broken,
                     clock=h.clock.time, monotonic=h.clock.monotonic)
    assert (r["trace"], r["verdict"]) == (None, "unknown")


# =========================================================================== NatChecker
def fake_result(kwargs: Dict[str, Any], verdict: str = "single_nat",
                confidence: Optional[str] = "high") -> Dict[str, Any]:
    result = {key: None for key in nc.NAT_RESULT_KEYS}
    result.update(ts=kwargs["clock"](), generation=kwargs["generation"], duration_ms=12, verdict=verdict,
                  confidence=confidence, title=nc.NAT_TEXT[verdict][0], explanation=nc.NAT_TEXT[verdict][1],
                  public_ip=kwargs["public_ip"])
    return result


class FakeCheck:
    def __init__(self, hook: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.hook = hook

    def __call__(self, **kwargs: Any) -> Dict[str, Any]:
        self.calls.append(kwargs)
        if self.hook is not None:
            self.hook(kwargs)
        return fake_result(kwargs)


class World:
    def __init__(self) -> None:
        self.clock = Clock()
        self.generation = 1
        self.nic: Optional[Adapter] = adapter()
        self.public: Any = {"ip": PUBLIC, "ts": T0 + 900.0, "error": None, "checked_ts": T0 + 900.0}
        self.changed_ts: Optional[float] = T0 + 800.0
        self.refreshes = 0
        self.on_refresh: Optional[Callable[[], None]] = None

    def refresh(self) -> Dict[str, Any]:
        self.refreshes += 1
        if self.on_refresh is not None:
            self.on_refresh()
        return dict(self.public)

    def checker(self, check: Callable[..., Dict[str, Any]], **kwargs: Any) -> nc.NatChecker:
        kwargs.setdefault("refresh_fn", self.refresh)
        return nc.NatChecker(adapters_fn=lambda: [self.nic], internet_nic_fn=lambda: self.nic,
                             public_ip_fn=lambda: self.public, changed_ts_fn=lambda: self.changed_ts,
                             generation_fn=lambda: self.generation, clock=self.clock.time,
                             monotonic=self.clock.monotonic, check=check, **kwargs)


def test_run_hands_the_inputs_to_the_check_and_keeps_the_result():
    world, check, factory = World(), FakeCheck(), PingerFactory({})
    checker = world.checker(check, pinger_factory=factory)
    assert checker.last() is None and checker.running() is False
    result = checker.run()
    (call,) = check.calls
    assert call["nic"] is world.nic and call["adapters"] == [world.nic] and call["public_ip"] == PUBLIC
    assert (call["generation"], call["pinger_factory"]) == (1, factory)
    assert call["clock"] == world.clock.time and call["monotonic"] == world.clock.monotonic
    assert checker.last() == result and world.refreshes == 0
    checker.last()["verdict"] = "changed"
    assert checker.last()["verdict"] == "single_nat"


def test_throttle_by_generation():
    world, check = World(), FakeCheck()
    checker = world.checker(check)
    first = checker.run()
    world.clock.advance(14.9)
    assert checker.run() == first and len(check.calls) == 1
    world.generation = 2
    checker.run()
    assert len(check.calls) == 2
    world.clock.advance(14.9)
    checker.run()
    assert len(check.calls) == 2
    world.clock.advance(0.2)
    checker.run()
    assert len(check.calls) == 3
    checker.on_network_change({"generation": 2})
    assert checker.last() is None
    checker.run()
    assert len(check.calls) == 4


def test_a_result_that_outlived_its_network_is_not_kept():
    world = World()

    def change(_kwargs: Dict[str, Any]) -> None:
        world.generation += 1

    checker = world.checker(FakeCheck(change))
    assert checker.run()["generation"] == 1 and checker.last() is None
    holder: Dict[str, nc.NatChecker] = {}
    same_generation = world.checker(FakeCheck(lambda _kwargs: holder["checker"].on_network_change(None)))
    holder["checker"] = same_generation
    same_generation.run()
    assert same_generation.last() is None


def test_offline_without_an_internet_adapter_is_not_kept():
    world, check = World(), FakeCheck()
    world.nic = None
    checker = world.checker(check)
    result = checker.run()
    assert (result["verdict"], result["confidence"], result["error"], result["generation"]) == (
        "offline", None, nc.NO_INTERNET_ERROR, 1)
    assert tuple(result) == nc.NAT_RESULT_KEYS and tuple(result["router"]) == nc.ROUTER_KEYS
    assert (result["title"], result["explanation"]) == nc.NAT_TEXT["offline"]
    assert check.calls == [] and checker.last() is None


def test_a_stale_public_address_is_refreshed_once_then_offline_is_not_kept():
    world, check = World(), FakeCheck()
    world.changed_ts = T0 + 950.0                      # the network changed after the address was looked up
    checker = world.checker(check, refresh_wait_s=5.0)
    result = checker.run()
    assert world.refreshes == 1
    assert (result["verdict"], result["error"], result["public_ip"]) == ("offline", nc.NO_PUBLIC_IP_ERROR, None)
    assert check.calls == [] and checker.last() is None
    checker.run()
    assert world.refreshes == 2                        # not kept, so the next run tries again


def test_a_refreshed_public_address_runs_the_check():
    world, check = World(), FakeCheck()
    world.changed_ts = T0 + 950.0

    def looked_up() -> None:
        world.public = {"ip": PUBLIC, "ts": T0 + 960.0, "error": None, "checked_ts": T0 + 960.0}

    world.on_refresh = looked_up
    checker = world.checker(check, refresh_wait_s=5.0)
    assert checker.run()["verdict"] == "single_nat" and world.refreshes == 1 and len(check.calls) == 1


@pytest.mark.parametrize("public,changed_ts,refresh,fresh", [
    ({"ip": PUBLIC, "ts": T0 + 900.0}, None, True, True),
    ({"ip": PUBLIC, "ts": T0 + 800.0}, T0 + 800.0, True, True),
    ({"ip": "2001:db8::5", "ts": T0 + 900.0}, None, True, False),
    ({"ip": PUBLIC, "ts": None, "checked_ts": T0 + 900.0}, None, True, False),
    ({"ip": None, "ts": None, "error": "timed out", "checked_ts": T0 + 900.0}, None, True, False),
    ({}, None, True, False),
    (None, None, True, False),
    ({"ip": PUBLIC, "ts": T0 + 700.0}, T0 + 800.0, False, False),
])
def test_public_address_freshness(public, changed_ts, refresh, fresh):
    world, check = World(), FakeCheck()
    world.public, world.changed_ts = public, changed_ts
    checker = world.checker(check, **({} if refresh else {"refresh_fn": None}))
    result = checker.run()
    assert (result["verdict"] != "offline") is fresh
    assert world.refreshes == (0 if fresh or not refresh else 1)


def test_run_refuses_while_a_run_is_going():
    world = World()
    entered, release = threading.Event(), threading.Event()

    def block(_kwargs: Dict[str, Any]) -> None:
        entered.set()
        assert release.wait(5.0)

    checker = world.checker(FakeCheck(block))
    worker = threading.Thread(target=checker.run, daemon=True)
    worker.start()
    try:
        assert entered.wait(5.0) and checker.running() is True
        with pytest.raises(RuntimeError) as err:
            checker.run()
        assert str(err.value) == "a NAT check is already running"
    finally:
        release.set()
        worker.join(5.0)
    assert checker.running() is False and checker.last() is not None


def test_a_failing_check_releases_the_run():
    world = World()

    def boom(_kwargs: Dict[str, Any]) -> None:
        raise ValueError("broken check")

    checker = world.checker(FakeCheck(boom))
    with pytest.raises(ValueError):
        checker.run()
    assert checker.running() is False


def test_a_hung_refresh_is_waited_on_not_started_again():
    world, check = World(), FakeCheck()
    world.changed_ts = T0 + 950.0
    release = threading.Event()
    world.on_refresh = lambda: release.wait(5.0)
    checker = world.checker(check, refresh_wait_s=0.05)
    try:
        assert checker.run()["error"] == nc.NO_PUBLIC_IP_ERROR
        assert checker.run()["error"] == nc.NO_PUBLIC_IP_ERROR
        assert world.refreshes == 1
    finally:
        release.set()
    names = [t.name for t in threading.enumerate()]
    assert names.count("tnt-natcheck-refresh") <= 1


def test_natchecker_with_the_real_check_on_fakes(monkeypatch):
    h = Harness(monkeypatch, natpmp=[[natpmp_reply(0, PUBLIC)]])
    world = World()
    world.clock = h.clock
    world.public = {"ip": PUBLIC, "ts": h.clock.time(), "error": None, "checked_ts": h.clock.time()}
    checker = world.checker(nc.check_nat, pinger_factory=h.pingers)
    result = checker.run()
    assert (result["verdict"], result["generation"], result["router"]["wan_source"]) == ("single_nat", 1, "natpmp")
    assert checker.last() == result


def test_logs_keep_addresses_and_names_out_of_info(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger="tnt.natcheck")
    h = Harness(monkeypatch, natpmp=[[natpmp_reply(3)]], ssdp=UPNP_ANSWER,
                services=[Svc(external="", mappings=[mapping(8000)])], hops={1: "192.168.50.1", 2: "100.64.0.1"})
    world = World()
    world.clock = h.clock
    world.public = {"ip": PUBLIC, "ts": h.clock.time(), "error": None, "checked_ts": h.clock.time()}
    result = world.checker(nc.check_nat, pinger_factory=h.pingers).run()
    assert result["verdict"] == "cgnat"
    info = [r.getMessage() for r in caplog.records if r.levelno >= logging.INFO and r.name == "tnt.natcheck"]
    assert info == [f"NAT check: cgnat (high) in {result['duration_ms']} ms"]
    secrets = (PUBLIC, GATEWAY, PC_IP, "192.168.50.1", "100.64.0.1", "10.0.0.60", "Example", "MiniUPnPd")
    assert not [m for m in info if any(s in m for s in secrets)]
    assert any(PUBLIC in r.getMessage() or GATEWAY in r.getMessage() for r in caplog.records
               if r.levelno == logging.DEBUG)
