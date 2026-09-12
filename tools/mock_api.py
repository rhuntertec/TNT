#!/usr/bin/env python3
"""Mock TNT API server for developing the web UI without the service.

Stdlib only, no ``tnt`` imports.  Serves ``ui/`` and a realistic fake of every
``/api`` route the service exposes with plausible,
evolving data:

* three ping targets (gateway, 1.1.1.1, totalelectronics.com) with traffic lights,
  one ``ping.sample`` SSE event per target per second, occasional misses and a
  periodic "sluggish" phase so the yellow light and red sparkline ticks show up;
* an outage timeline for the last 24 h with a yellow (target) span, a red
  (total internet) span and a grey monitoring gap;
* 7 days of 15-minute speed tests with an evening slowdown and a few failures;
* a discovery scan that progresses over ~4 s after ``POST /api/discovery/scan``;
* a fake DHCP server (Tools view): ``POST /api/dhcp/start`` answers 409 with the
  "other server" payload unless ``force`` is set (or ``STATE.dhcp_force_none``);
  once on, three clients appear over ~8 s with ``dhcp.lease`` events;
* a traceroute (``POST /api/tools/traceroute``) of ~9 hops that arrive ~0.3 s apart
  with ``trace.start`` / ``trace.hop`` / ``trace.done`` events, one silent hop and a
  CGNAT hop included; ``GET /api/tools/traceroute/last`` keeps the last one;
* two LAN peers (``GET /api/tools/lan/peers``, ``lan.peers`` every 10 s) and a ~4 s
  throughput test (``POST /api/tools/lan/throughput``) with progress events and a
  result around 940 / 910 Mbps; 409 while one runs; ``/last`` keeps the result;
  ``PUT /api/tools/lan/settings`` ``{"enabled": false}`` switches discovery off: the
  peer list goes empty with ``listening`` false and ``error`` "disabled", the 10 s
  ``lan.peers`` broadcast stops, a throughput test is refused with 400 and the whole
  peers view is published as ``lan.state``;
* three saved Wi-Fi networks (``GET /api/tools/wifi/profiles``) on one wireless
  interface, two WPA2-PSK with a key and one open network without; ``reveal`` is off by
  default and leaves the keys out but keeps ``key_present``. ``reveal=1`` returns the keys but
  only to an administrator: ``STATE.wifi_admin`` is True by default so the UI works; a test can
  set it False to get the real service's 403 ``admin_required``. Like the service, a browser
  request from a page of another origin gets 403 ``forbidden`` instead;
* settings persisted in memory (``ui.show_ipv6`` included); ``POST /api/export``
  returns a tiny valid PDF; ``status.map.public_ip`` carries a fake WAN address;
* network changes: the fake PC sits on one of the synthetic networks of ``NET_PROFILE_NAMES``
  (office LAN "a" by default, another building on Wi-Fi "b", a mistyped static IP, APIPA, no
  network). ``POST /mock/network`` ``{"profile": "b"}`` (development only, outside ``/api``) moves
  it like Windows applying a new configuration, with the service's events in the service's order:
  ``lan.peers`` / ``lan.state`` (LAN peers hear first), ``net.changed`` with the service's payload
  (``changes`` shaped like ``tnt.netwatch.diff_states``), then ``ping.targets`` (the "gateway"
  alias follows) and a gateway ``map.sample``; a scan running across it ends with
  ``discovery.done`` ``network_changed: true``; diagnostics carry a ``network`` section;
  ``status.net`` / ``/api/netinfo`` carry the generation, adapters carry ``warnings`` (apipa,
  gateway_outside_subnet, no_dns, multiple_default_gateways) and the Discovery default range, the
  DHCP adapter picker, traceroute and LAN peers answer for the new network. ``GET /mock/network``
  names the current one. Tests set ``STATE.net_switch_after_status = (n, profile)`` instead;
* the WiFi page: ``GET /api/oui?prefix=AA:BB:CC`` (1-256 prefixes, repeated or comma-separated)
  answers invented vendor names for the invented OUIs of the fake survey, ``null`` for any other
  OUI and 400 for a malformed prefix. The survey itself never comes from the API (the real one
  runs inside the TNT window): ``index.html`` is served with ``/mock/wifi-bridge.js``
  (``tools/mock_wifi_bridge.js``, never shipped) injected before the UI scripts, a fake
  ``window.pywebview.api`` with the ``wifi_*`` bridge methods over ~30 simulated access points.
  ``?wifi=denied|noadapter|off|radiooff|error|starting|empty|late|outdated|nobridge`` picks a state;
* Reports: five synthetic saved site reports (``REPORT_SEEDS``: invented sites, one scanned twice, a known good office,
  partial reports with unavailable sections) behind every ``/api/reports`` route of the contract, PATCH included.
  ``POST /api/reports/scan`` starts the one full scan: the mock speed test and Discovery scan (a few ms each with
  ``STATE.report_fast``), then, like the service, it waits for the page's ``POST /api/reports/scan/wifi`` (the first
  usable snapshot; after an unavailable one ``report_wifi_grace_s`` more for a usable one; with none in
  ``report_wifi_timeout_s`` the report says "No TNT window was open to scan Wi-Fi"), reads the fake history and saves,
  with ``report.progress`` / ``report.saved`` / ``report.updated`` / ``report.deleted`` events and ``status.reports``. The
  summary, comparison, Wi-Fi snapshot and section rules are ``tnt/reports.py``'s, copied by hand (tests/test_ui.py holds the
  two to the same output); the report and comparison PDFs are tiny placeholders. Like the service, a report describes only the
  targets set up when it was made: the second Acme Dental scan leaves out a test address removed before it ("Left out: 1
  removed or disabled target"), and a full scan leaves out the targets removed from the mock within its window (with every
  target gone its ping section is not collected, as the service's is). Networks, like ``tnt.networks``: the fake PC has visited
  the invented sites' networks (``MOCK_ITINERARY``; each known by its router's MAC, Pinecrest Library's only by its gateway and
  subnet) and is on Acme Dental's, the office LAN of network "a". A report counts only its site network's visits in the week
  before it (``window_reason`` "site_network", ``ping.visits`` / ``monitored_s``, ``meta.network``): the second Acme Dental
  scan's week holds two. So a full scan on "a" suggests "Acme Dental" (the job's ``suggested_site``) and is saved under it when
  nobody names it; on "b" (a new network) nothing is suggested; "apipa" and "none" keep the last network. A suggested report
  renamed or deleted while the scan runs suggests again (``report.progress``). ``GET /api/networks/current`` answers the network,
  its newest named report and ``offline``, ``status.net.network_id`` its id. ``PATCH /api/networks/{id}`` ``{"portable"}`` marks a
  network carried from site to site: a scan on it is suggested nothing and reads only this connection. A scan started with no
  network ("apipa", "none") is on none: nothing suggested, the time rule.
* IP location: ``status.geoip`` (like ``tnt.geoip.GeoIpManager.status()``, state ``STATE.geoip_state``, "ready" by default),
  ``status.map.public_geo`` for the fake public address, hop ``location``s on the fake traceroute (one router name
  carries a hint), ``GET /api/geoip``, ``GET /api/geoip/lookup?ip=``, ``POST /api/geoip/check``, ``geoip.enabled`` in the
  settings with ``geoip.state`` events (no ``ts`` in the frame, unlike the service), and ``POST /mock/geoip {"state"}``
  (development only) to see downloading/error/starting in the UI. Invented providers and cities on documentation
  addresses; the key sets, the display-name and place rules and the router-name rule are held to ``tnt/geoip.py`` and
  ``tnt/geohints.py`` by tests/test_ui.py.

SSE framing: ``event: <type>`` / ``data: <json of the event's data>``; the first
event is ``hello``; ``: ping`` comments every 15 s.

Usage::

    python tools/mock_api.py --port 7136
"""
from __future__ import annotations

import argparse
import calendar
import copy
import ipaddress
import json
import logging
import math
import mimetypes
import os
import queue
import random
import re
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

log = logging.getLogger("mock_api")

ROOT = Path(__file__).resolve().parent.parent
UI_DIR = ROOT / "ui"
VERSION = "1.0.0"

DEFAULT_PORTS = [22, 80, 443, 554, 5060, 7001, 8000, 8080, 8443]
DEFAULTS: Dict[str, Any] = {
    "api": {"host": "127.0.0.1", "port": 7130},
    "ping": {"interval_s": 1.0, "timeout_ms": 1000, "loaded": True, "loaded_bytes": 1200,
             "unloaded_bytes": 32, "ttl": 128, "resolve_interval_s": 300},
    "outage": {"miss_threshold": 3, "recover_threshold": 3},
    "thresholds": {"window_s": 60, "local_warn_ms": 30, "internet_warn_ms": 150,
                   "warn_loss_pct": 2.0, "bad_loss_pct": 15.0},
    "speedtest": {"enabled": True, "interval_min": 15, "backend": "auto", "download_mb": 50, "upload_mb": 20,
                  "duration_s": 8, "connections": 4, "timeout_s": 120, "warn_below_pct": 50},
    "discovery": {"ports": list(DEFAULT_PORTS), "ping_timeout_ms": 500, "ping_attempts": 2,
                  "port_timeout_ms": 750, "concurrency": 128, "resolve_hostnames": True, "max_hosts": 4096},
    "retention": {"days": 365},
    "ui": {"theme": "light", "show_ipv6": False},
    "lan": {"enabled": True},
    "geoip": {"enabled": True},
    "targets": {"defaults_extra": ["1.1.1.1", "totalelectronics.com"]},
    "dhcp": {"adapter": "", "pool_start": "", "pool_end": "", "pool_size": 5, "lease_s": 3600,
             "static_ip": "172.16.4.100", "static_prefix": 24, "ping_check": True, "scan_wait_s": 8},
}
#: settings a release removed: PUT /api/settings drops them instead of storing them (same as tnt.config._RETIRED_KEYS)
RETIRED_SETTINGS = ("speedtest.ookla_path", "speedtest.ookla_server_id", "discovery.use_nmap", "discovery.nmap_path")

DHCP_FIREWALL_RULE = "TNT DHCP server (UDP 67 in)"
# up adapters with an IPv4 (candidates for the Tools adapter picker); Ethernet is DHCP-enabled so
# turning the server on "re-addresses" it to the static 172.16.4.100/24 -- and it is also the PC's
# internet connection (is_internet), so the UI shows its loud "this PC goes offline" warning
DHCP_ADAPTERS = [
    {"name": "Ethernet", "index": 12, "mac": "D8:BB:C1:12:34:08", "ip": "10.0.0.112", "prefix": 24, "mask": "255.255.255.0",
     "dhcp_enabled": True, "dhcp_server": "10.0.0.251", "gateway": "10.0.0.251", "is_physical": True, "type_name": "Ethernet", "status": "up",
     "is_internet": True},
    {"name": "vEthernet (Default Switch)", "index": 30, "mac": "00:15:5D:01:02:03", "ip": "172.29.64.1", "prefix": 20, "mask": "255.255.240.0",
     "dhcp_enabled": False, "dhcp_server": None, "gateway": None, "is_physical": False, "type_name": "Ethernet", "status": "up",
     "is_internet": False},
    {"name": "Tailscale", "index": 21, "mac": "", "ip": "100.101.22.7", "prefix": 32, "mask": "255.255.255.255",
     "dhcp_enabled": False, "dhcp_server": None, "gateway": None, "is_physical": False, "type_name": "Tunnel", "status": "up",
     "is_internet": False},
]
DHCP_FAKE_CLIENTS = [
    ("AA:BB:CC:10:20:01", "cam-lobby", "Hangzhou Hikvision Digital Technology Co., Ltd.", 1.4, [80, 554]),
    ("3C:D9:2B:12:34:03", "printer-hp", "Hewlett Packard", 2.1, [80, 443]),
    ("DA:12:34:12:34:0E", None, "Locally administered (randomized)", 11.2, []),
]
PUBLIC_IP = "203.0.113.5"
PC_HOSTNAME = "TEC-DESKTOP"            # its address comes from the network it is on (net_profile)
# the path to totalelectronics.com: (ip, hostname, kind, label, base rtt ms, probes lost)
# hop 5 never answers; hop 8 drops one of its three probes
TRACE_PATH = [
    ("10.0.0.251", "gateway.lan", "gateway", "Gateway", 0.6, 0),
    ("100.64.0.1", None, "lan", "LAN", 3.1, 0),
    ("198.51.100.1", "core1.anytown.example.net", "public", "Internet", 9.4, 0),
    ("198.51.100.9", "edge2.anytown.example.net", "public", "Internet", 12.2, 0),
    (None, None, "unknown", "No reply", None, 3),
    ("198.51.100.65", "ae-1.cr1.dllstx.example.net", "public", "Internet", 24.6, 0),
    ("198.51.100.130", "peer1.example.net", "public", "Internet", 19.3, 0),
    ("203.0.113.254", None, "public", "Internet", 128.0, 1),
    ("203.0.113.80", "totalelectronics.com", "destination", "Destination", 19.1, 0),
]
# IP location (tnt.geoip): the key sets, states and skipped networks are the service's (tests/test_ui.py compares them)
GEOIP_STATUS_KEYS = ("enabled", "state", "available", "month", "bytes", "installed_ts", "checked_ts",
                     "next_check_ts", "download", "error")
GEOIP_GEO_KEYS = ("ip", "place", "place_full", "city", "region", "region_code", "country", "country_code",
                  "lat", "lon", "asn", "as_org", "isp", "month")
GEOIP_LOCATION_KEYS = ("text", "source", "hint", "db_text", "asn", "as_org")
GEOIP_DOWNLOAD_KEYS = ("month", "file", "phase", "received", "total")
GEOIP_DIAG_KEYS = ("available", "status", "files")
GEOIP_STATES = ("disabled", "starting", "downloading", "ready", "error")
#: never looked up (LAN, CGNAT, link-local, loopback, multicast, reserved): tnt.geoip.SKIP_NETWORKS as CIDR strings, same order
GEOIP_SKIP_NETWORKS = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
                       "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
                       "::/128", "::1/128", "fe80::/10", "fc00::/7", "ff00::/8")
_GEOIP_SKIP = tuple(ipaddress.ip_network(n) for n in GEOIP_SKIP_NETWORKS)
GEOIP_CITY_BYTES = 127339927            # the installed files diagnostics lists (the 2026-09 DB-IP Lite sizes)
GEOIP_ASN_BYTES = 9511026
# (ip, isp, as_org, asn, city, region, region code, lat, lon): isp is the display name (tnt.geoip.isp_text), as_org the
# organisation as the database spells it; every row is in the United States
_MOCK_GEO_ROWS = (
    ("203.0.113.5", "Example Broadband", "Example Broadband", 64500, "Anytown", "Texas", "TX", 32.95, -96.73),
    ("198.51.100.77", "Sample Fiber", "Sample Fiber Co.", 64501, "Springfield", "Illinois", "IL", 39.80, -89.64),
    ("198.51.100.1", "Example Broadband", "Example Broadband", 64500, "Anytown", "Texas", "TX", 32.95, -96.73),
    ("198.51.100.9", "Example Broadband", "Example Broadband", 64500, "Anytown", "Texas", "TX", 32.95, -96.73),
    ("198.51.100.65", "Example Transit", "Example Transit, Inc.", 64510, "Richardson", "Texas", "TX", 32.95, -96.73),
    ("198.51.100.130", "Example Transit", "Example Transit, Inc.", 64510, "Dallas", "Texas", "TX", 32.78, -96.80),
    ("203.0.113.254", "Example Hosting", "Example Hosting LLC", 64511, "Dallas", "Texas", "TX", 32.78, -96.80),
    ("203.0.113.80", "Example Hosting", "Example Hosting LLC", 64511, "Dallas", "Texas", "TX", 32.78, -96.80),
)
#: ip -> GEO without "month" (added at lookup): invented providers and cities on documentation addresses
MOCK_GEO: Dict[str, Dict[str, Any]] = {
    ip: {"ip": ip, "place": f"{city}, {code}", "place_full": f"{city}, {region}, United States", "city": city, "region": region,
         "region_code": code, "country": "United States", "country_code": "US", "lat": lat, "lon": lon,
         "asn": asn, "as_org": as_org, "isp": isp}
    for ip, isp, as_org, asn, city, region, code, lat, lon in _MOCK_GEO_ROWS
}
#: router name -> (code, hint text), as tnt.geohints.location_hint reads it; a generic-tier hint, so a destination hop ignores it
MOCK_HOST_HINTS = {"ae-1.cr1.dllstx.example.net": ("dllstx", "Dallas, TX")}


def geoip_address(ip: Any) -> Optional[Any]:
    """An address object like tnt.geoip.normalize_ip (spaces, [brackets] and %scope removed, IPv4-mapped IPv6 as
    IPv4), or None for anything invalid."""
    if not isinstance(ip, str):
        return None
    text = ip.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        addr = ipaddress.ip_address(text.split("%", 1)[0].strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def geoip_skipped(addr: Any) -> bool:
    """Whether an address (geoip_address) is in GEOIP_SKIP_NETWORKS: never looked up."""
    return any(addr in net for net in _GEOIP_SKIP if net.version == addr.version)


LAN_PEERS = [
    ("7f3a9c1e", "TEC-LAPTOP-02", "10.0.0.42", VERSION, "Ethernet"),
    ("b21d0e77", "BENCH-PC", "10.0.0.77", "0.9.4", "Ethernet"),
]
#: the only key PUT /api/tools/lan/settings accepts (same as tnt.api.routes.LAN_SETTINGS_KEYS)
LAN_SETTINGS_KEYS = ("enabled",)
#: The synthetic networks the fake PC can be moved between (``POST /mock/network {"profile": "b"}``, or
#: ``MockState.net_switch_after_status`` for headless tests). "a" is where every other fake in this file
#: lives: the office LAN on Ethernet, plus a USB NIC nobody answered DHCP on (apipa) and a bench NIC with
#: a mistyped static gateway (gateway_outside_subnet, no_dns). "b" is another building on Wi-Fi,
#: "static-bad" a mistyped static IP on Ethernet, "apipa" a DHCP network with no DHCP server and "none"
#: every physical adapter down. RFC 1918 / RFC 5737 / link-local addresses, locally administered MACs.
NET_PROFILE_NAMES = ("a", "b", "static-bad", "apipa", "none")
#: how long the fake public-address lookup takes after a network change (the link map's WAN chip)
NET_RECHECK_S = 3.0
#: the host names that follow this PC's default gateway (tnt.pinger.GATEWAY_HOSTS)
GATEWAY_HOSTS = ("gateway", "default-gateway", "default gateway")
#: adapters[].warnings messages by code, worded like tnt.netinfo.adapter_warnings
NET_WARNINGS = {
    "apipa": "Self-assigned address {address}: no DHCP server answered",
    "duplicate_address": "{address} is already used by another device on this network",
    "gateway_outside_subnet": "Gateway {gateway} is outside this adapter's subnet {network}: check the IP address and subnet mask",
    "no_dns": "No DNS servers: host names will not resolve",
    "multiple_default_gateways": "{other} also has a default gateway ({other_gateway}); "
                                 "Windows sends traffic through the one with the lowest metric",
}


def net_adapter(index: int, name: str, description: str, mac: str, if_type: int, type_name: str, status: str, *,
                ipv4: tuple = (), ipv6: tuple = (), gateways: tuple = (), dns: tuple = (), dhcp: bool = False,
                dhcp_server: Optional[str] = None, suffix: str = "", speed_bps: Optional[int] = None, mtu: int = 1500,
                metric: Optional[int] = None, physical: bool = True, warnings: tuple = (),
                other_gateway: tuple = ("another adapter", "?")) -> Dict[str, Any]:
    """One /api/netinfo adapter (the keys of the service's adapter dict, ``warnings`` included). ``ipv4`` and
    ``ipv6`` are (address, prefix) pairs and ``warnings`` codes of NET_WARNINGS (``other_gateway`` = (name,
    gateway) of the other adapter a multiple_default_gateways warning names). A gateway outside every IPv4
    prefix goes in a trailing subnet group without a network, like tnt.netinfo.subnet_groups."""
    v4: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    for address, prefix in ipv4:
        mask = int2ip((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF)
        network = f"{int2ip(ip2int(address) & ip2int(mask))}/{prefix}"
        v4.append({"address": address, "prefix": prefix, "family": 4, "netmask": mask, "network": network})
        inside = [g for g in gateways if ip2int(g) & ip2int(mask) == ip2int(address) & ip2int(mask)]
        groups.append({"network": network, "family": 4, "mask": mask, "addresses": [address], "gateways": inside})
    v6 = [{"address": a, "prefix": p, "family": 6, "netmask": None, "network": f"{a.split('::')[0]}::/{p}"} for a, p in ipv6]
    groups += [{"network": e["network"], "family": 6, "mask": None, "addresses": [e["address"]], "gateways": []} for e in v6]
    stray = [g for g in gateways if not any(g in grp["gateways"] for grp in groups)]
    if stray:
        groups.append({"network": None, "family": 4, "mask": None, "addresses": [], "gateways": stray})
    first_net = v4[0]["network"] if v4 else ""
    texts = [{"code": code, "message": NET_WARNINGS[code].format(
        address=v4[0]["address"] if v4 else "?", gateway=(gateways or ("?",))[0], network=first_net,
        other=other_gateway[0], other_gateway=other_gateway[1])} for code in warnings]
    return {"index": index, "name": name, "description": description, "mac": mac, "if_type": if_type, "type_name": type_name,
            "status": status, "speed_bps": speed_bps, "mtu": mtu, "dhcp_enabled": dhcp, "dhcp_server": dhcp_server,
            "dns_suffix": suffix, "ipv4": v4, "ipv6": v6, "gateways": list(gateways), "dns": list(dns), "metric_v4": metric,
            "is_physical": physical, "is_loopback": False, "subnets": groups, "warnings": texts}


def net_profile(name: str) -> Dict[str, Any]:
    """Adapters and derived state of one NET_PROFILE_NAMES network, as fresh dicts: ``adapters``,
    ``internet_nic_index``, ``default_gateway``, ``public_ip``, ``default_range`` and the LAN ``peers``."""
    eth = dict(index=12, name="Ethernet", description="Intel(R) Ethernet Controller I225-V", mac="D8:BB:C1:12:34:08",
               if_type=6, type_name="Ethernet")
    wifi = dict(index=7, name="Wi-Fi", description="Intel(R) Wi-Fi 6E AX211 160MHz", mac="A4:6B:B6:12:34:0D",
                if_type=71, type_name="Wi-Fi")
    tailscale = net_adapter(21, "Tailscale", "Tailscale Tunnel", "", 53, "Tunnel", "up", ipv4=(("100.101.22.7", 32),),
                            dns=("100.100.100.100",), suffix="tail1234.ts.net", mtu=1280, metric=5, physical=False)
    hyperv = net_adapter(30, "vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", "00:15:5D:01:02:03", 6, "Ethernet",
                         "up", ipv4=(("172.29.64.1", 20),), speed_bps=10_000_000_000, metric=15, physical=False)
    eth_down = net_adapter(**eth, status="down", dhcp=True, metric=25)
    wifi_down = net_adapter(**wifi, status="down", dhcp=True, metric=35)
    if name == "b":
        adapters = [net_adapter(**wifi, status="up", ipv4=(("192.168.50.23", 24),), gateways=("192.168.50.1",), dns=("192.168.50.1",),
                                dhcp=True, dhcp_server="192.168.50.1", suffix="site-b.example", speed_bps=866_000_000, metric=35),
                    tailscale, hyperv, eth_down]
        return dict(adapters=adapters, internet_nic_index=7, default_gateway="192.168.50.1", public_ip="198.51.100.77",
                    default_range="192.168.50.0/24", peers=[("3e5d7a90", "SITE-B-PC", "192.168.50.60", VERSION, "Wi-Fi")])
    if name == "static-bad":
        adapters = [net_adapter(**eth, status="up", ipv4=(("172.16.20.15", 24),), gateways=("172.16.21.1",), speed_bps=1_000_000_000,
                                metric=25, warnings=("gateway_outside_subnet", "no_dns")), tailscale, hyperv, wifi_down]
        return dict(adapters=adapters, internet_nic_index=12, default_gateway="172.16.21.1", public_ip=None,
                    default_range="172.16.20.0/24", peers=[("b21d0e77", "BENCH-PC", "172.16.21.77", "0.9.4", None)])
    if name == "apipa":
        adapters = [net_adapter(**eth, status="up", ipv4=(("169.254.23.45", 16),), dhcp=True, speed_bps=1_000_000_000, metric=25,
                                warnings=("apipa",)), tailscale, hyperv, wifi_down]
        return dict(adapters=adapters, internet_nic_index=None, default_gateway=None, public_ip=None, default_range=None, peers=[])
    if name == "none":
        tunnel_down = net_adapter(21, "Tailscale", "Tailscale Tunnel", "", 53, "Tunnel", "down", mtu=1280, metric=5, physical=False)
        return dict(adapters=[eth_down, tunnel_down, hyperv, wifi_down], internet_nic_index=None, default_gateway=None,
                    public_ip=None, default_range=None, peers=[])
    adapters = [net_adapter(**eth, status="up", ipv4=(("10.0.0.112", 24),), ipv6=(("fe80::a1b2:c3d4:e5f6:1234", 64),),
                            gateways=("10.0.0.251",), dns=("10.0.0.251", "1.1.1.1"), dhcp=True, dhcp_server="10.0.0.251", suffix="lan",
                            speed_bps=2_500_000_000, metric=25, warnings=("multiple_default_gateways",),
                            other_gateway=("Ethernet 3", "172.16.21.1")),
                tailscale, hyperv, wifi_down,
                net_adapter(18, "Ethernet 2", "USB 2.5GbE Adapter (synthetic)", "02:5E:10:00:00:18", 6, "Ethernet", "up",
                            ipv4=(("169.254.23.45", 16),), dhcp=True, speed_bps=1_000_000_000, metric=25, warnings=("apipa",)),
                net_adapter(19, "Ethernet 3", "Bench NIC (synthetic)", "02:5E:10:00:00:19", 6, "Ethernet", "up",
                            ipv4=(("172.16.20.15", 24),), gateways=("172.16.21.1",), speed_bps=1_000_000_000, metric=35,
                            warnings=("gateway_outside_subnet", "no_dns"))]
    return dict(adapters=adapters, internet_nic_index=12, default_gateway="10.0.0.251", public_ip=PUBLIC_IP,
                default_range="10.0.0.0/24", peers=list(LAN_PEERS))


def net_internet_nic(prof: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return next((a for a in prof["adapters"] if a["index"] == prof["internet_nic_index"]), None)


def net_summary(prof: Dict[str, Any]) -> str:
    """The plain-text line of net.changed, for the toast (the rules of tnt.netwatch.summarize): the internet adapter,
    else the first up physical adapter with an IPv4 address (a real one before a self-assigned one)."""
    nic = net_internet_nic(prof)
    if nic is None:
        up = [a for a in prof["adapters"] if a["status"] == "up" and a["is_physical"] and a["ipv4"]]
        up.sort(key=lambda a: 1 if a["ipv4"][0]["address"].startswith("169.254.") else 0)
        nic = up[0] if up else None
    gw = prof["default_gateway"]
    if nic is None:
        return f"Default gateway {gw}" if gw else "No network connection"
    parts = []
    if nic["ipv4"]:
        first = nic["ipv4"][0]
        parts.append(f"{nic['name']}: {first['address']}/{first['prefix']}")
        if first["address"].startswith("169.254."):
            parts.append("self-assigned address, no DHCP server answered")
    else:
        parts.append(f"{nic['name']}: no IP address")
    parts.append(f"gateway {gw}" if gw else "no gateway")
    return " · ".join(parts)


def net_fingerprint(a: Dict[str, Any]) -> Dict[str, Any]:
    """What tnt.netwatch.build_state compares for one adapter, with the values ``changes`` carries: nothing of an
    adapter that is down, link-local IPv6 ignored, lists sorted."""
    up = a["status"] == "up"
    return {"up": up,
            "ipv4": sorted(f"{e['address']}/{e['prefix']}" for e in a["ipv4"]) if up else [],
            "ipv6": sorted(e["network"] for e in a["ipv6"] if not e["address"].lower().startswith("fe80:")) if up else [],
            "gateway": sorted(a["gateways"]) if up else [],
            "dns": {"servers": sorted(set(a["dns"])), "suffix": (a["dns_suffix"] or "").lower()} if up else {"servers": [], "suffix": ""},
            "dhcp": {"enabled": a["dhcp_enabled"], "server": a["dhcp_server"]} if up else {"enabled": None, "server": None}}


def net_changes(old: Dict[str, Any], new: Dict[str, Any]) -> List[Dict[str, Any]]:
    """What differs between two profiles as net.changed ``changes``, with tnt.netwatch.diff_states' rules and value
    shapes: ``added``/``removed`` (only for an adapter that is up; its IPv4 list), ``up``/``down`` (status strings;
    nothing else is listed for that adapter), ``ipv4``/``ipv6``/``gateway`` (sorted lists), ``dns`` ({servers, suffix}),
    ``dhcp`` ({enabled, server}), then ``internet_nic`` (names) and a ``gateway`` entry for a default gateway that moved
    while no adapter's list did."""
    out: List[Dict[str, Any]] = []
    before = {a["name"]: a for a in old["adapters"]}
    after = {a["name"]: a for a in new["adapters"]}
    for name in list(after) + [n for n in before if n not in after]:
        fa = net_fingerprint(before[name]) if name in before else None
        fb = net_fingerprint(after[name]) if name in after else None
        if fa is None or fb is None:
            if fa is None and fb["up"]:
                out.append({"adapter": name, "kind": "added", "old": None, "new": fb["ipv4"]})
            elif fb is None and fa["up"]:
                out.append({"adapter": name, "kind": "removed", "old": fa["ipv4"], "new": None})
            continue
        if fa["up"] != fb["up"]:
            out.append({"adapter": name, "kind": "up" if fb["up"] else "down", "old": before[name]["status"],
                        "new": after[name]["status"]})
            continue
        for kind in ("ipv4", "ipv6", "gateway", "dns", "dhcp"):
            if fb["up"] and fa[kind] != fb[kind]:
                out.append({"adapter": name, "kind": kind, "old": fa[kind], "new": fb[kind]})
    o, n = net_internet_nic(old), net_internet_nic(new)
    if old["internet_nic_index"] != new["internet_nic_index"]:
        out.append({"adapter": (n or o or {}).get("name", ""), "kind": "internet_nic", "old": o["name"] if o else None,
                    "new": n["name"] if n else None})
    if old["default_gateway"] != new["default_gateway"] and not any(c["kind"] == "gateway" for c in out):
        out.append({"adapter": (n or o or {}).get("name", ""), "kind": "gateway",
                    "old": [old["default_gateway"]] if old["default_gateway"] else [],
                    "new": [new["default_gateway"]] if new["default_gateway"] else []})
    return out


def net_change_phrase(c: Dict[str, Any]) -> Optional[str]:
    """One change in a few words (tnt.netwatch._change_phrase)."""
    adapter, kind, new, old = c["adapter"] or "An adapter", c["kind"], c["new"], c["old"]
    if kind in ("down", "removed"):
        return f"{adapter} {'disconnected' if kind == 'down' else 'removed'}"
    if kind in ("up", "added"):
        return f"{adapter} connected"
    if kind == "renamed":
        return f"{old} renamed to {new}"
    if kind == "ipv4":
        return f"{adapter}: " + (", ".join(new) if new else "no IPv4 address")
    if kind == "ipv6":
        return f"{adapter}: IPv6 addresses changed"
    if kind == "gateway":
        return f"{adapter}: " + (f"gateway {', '.join(new)}" if new else "no gateway")
    if kind == "dns":
        servers, suffix = (new or {}).get("servers") or [], (new or {}).get("suffix") or ""
        if servers != ((old or {}).get("servers") or []):
            return f"{adapter}: " + (f"DNS servers {', '.join(servers)}" if servers else "no DNS servers")
        return f"{adapter}: " + (f"DNS suffix {suffix}" if suffix else "no DNS suffix")
    if kind == "dhcp":
        enabled, server = (new or {}).get("enabled"), (new or {}).get("server")
        if enabled != (old or {}).get("enabled"):
            return f"{adapter}: DHCP {'on' if enabled else 'off'}"
        return f"{adapter}: DHCP server {server}" if server else f"{adapter}: DHCP server changed"
    return None


def net_change_lead(payload: Dict[str, Any], prof: Dict[str, Any]) -> Optional[str]:
    """What changed, ahead of the summary, when the default gateway and the internet adapter stayed (tnt.netwatch._change_lead)."""
    if payload["gateway_changed"] or payload["internet_nic_changed"]:
        return None
    inet = (net_internet_nic(prof) or {}).get("name")
    phrases: List[str] = []
    for c in payload["changes"]:
        if c["kind"] == "ipv4" and inet is not None and c["adapter"] == inet:
            continue
        phrase = net_change_phrase(c)
        if phrase and phrase not in phrases:
            phrases.append(phrase)
    if not phrases:
        return None
    more = len(phrases) - 2
    return " · ".join(phrases[:2]) + (f" (+{more} more)" if more > 0 else "")


def net_internet_brief(prof: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """net.changed ``internet_nic`` (tnt.netwatch.internet_nic_brief): prefix lengths as strings parallel to ``ipv4``,
    ``networks`` the matching CIDRs."""
    nic = net_internet_nic(prof)
    if nic is None:
        return None
    networks: List[str] = []
    for e in nic["ipv4"]:
        if e["network"] not in networks:
            networks.append(e["network"])
    return {"index": nic["index"], "name": nic["name"], "ipv4": [e["address"] for e in nic["ipv4"]],
            "ipv4_prefixes": [str(e["prefix"]) for e in nic["ipv4"]], "networks": networks, "dns": list(nic["dns"]),
            "dhcp": bool(nic["dhcp_enabled"])}


def _net_nic_brief(nic: Dict[str, Any]) -> Dict[str, Any]:
    first = nic["ipv4"][0] if nic["ipv4"] else None
    return {"index": nic["index"], "name": nic["name"], "description": nic["description"], "type_name": nic["type_name"],
            "ipv4": first["address"] if first else None, "network": first["network"] if first else None,
            "gateway": (nic["gateways"] or [None])[0], "mac": nic["mac"], "warnings": [w["code"] for w in nic["warnings"]]}


def net_status_nic(prof: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """status.netinfo.internet_nic as tnt.engine.Engine.netinfo_summary builds it: the bare address and its network, the
    warning codes."""
    nic = net_internet_nic(prof)
    return _net_nic_brief(nic) if nic is not None else None


def net_local_nic(prof: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """status.netinfo.local_nic (Engine.netinfo_summary): without an internet adapter, the first up physical adapter with
    an IPv4 address, a real address before a self-assigned one."""
    if net_internet_nic(prof) is not None:
        return None
    up = [a for a in prof["adapters"] if a["status"] == "up" and a["is_physical"] and a["ipv4"]]
    up.sort(key=lambda a: 1 if a["ipv4"][0]["address"].startswith("169.254.") else 0)
    return _net_nic_brief(up[0]) if up else None


def net_networks(prof: Dict[str, Any]) -> List[str]:
    """status.net.networks (tnt.netwatch.NetState.ipv4_networks): the IPv4 subnets of the up adapters, numerically."""
    nets = {e["network"] for a in prof["adapters"] if a["status"] == "up" for e in a["ipv4"]}
    return sorted(nets, key=lambda n: (ip2int(n.split("/")[0]), int(n.split("/")[1])))
#: this PC's wireless interface and the profiles it saved (GET /api/tools/wifi/profiles);
#: (name, ssid, authentication, encryption, key, connection_mode, non_broadcast)
WIFI_INTERFACE = {"guid": "12345678-9abc-4def-8123-456789abcdef",
                  "description": "Intel(R) Wireless-AC 9560 160MHz", "state": "connected"}
WIFI_PROFILES = [
    ("TEC-Office", "TEC-Office", "WPA2PSK", "AES", "example-office-passphrase", "auto", False),
    ("TEC-Guest", "TEC-Guest", "WPA2PSK", "AES", "example-guest-passphrase", "auto", False),
    ("SiteSurvey-5G", "SiteSurvey-5G", "open", "none", None, "manual", True),
]
#: the service's 403 when a non-admin asks for reveal=1 (mirrors tnt.api.routes.WIFI_ADMIN_REQUIRED_MSG)
WIFI_ADMIN_REQUIRED_MSG = "Showing saved Wi-Fi passwords needs a Windows administrator account."
#: ... and when a browser page of another origin asks (mirrors tnt.api.routes.WIFI_CROSS_ORIGIN_MSG)
WIFI_CROSS_ORIGIN_MSG = "Saved Wi-Fi passwords are only shown to the TNT window or a page served by this TNT service."
#: the fake pywebview bridge for the WiFi page (development only: it lives here, never under ui/)
MOCK_WIFI_BRIDGE = Path(__file__).resolve().parent / "mock_wifi_bridge.js"
MOCK_WIFI_BRIDGE_URL = "/mock/wifi-bridge.js"
#: GET /api/oui: invented vendors for the invented base OUIs of the simulated access points
OUI_VENDORS = {
    "C0:FF:EE": "Contoso Access Systems",
    "F0:0D:CA": "Fabrikam Networks",
    "D0:0D:AD": "Northwind Radio Co.",
    "EC:0B:0B": "Acme Radio Works",
    "DC:BA:5E": "Example Wireless Co.",
    "CC:A7:00": "Tailspin Devices",
}
OUI_MAX_PREFIXES = 256


_OUI_PREFIX_RE = re.compile(r"^([0-9A-Fa-f]{2})([:-]?)([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})$")


def oui_prefixes(values: List[str]) -> List[str]:
    """``prefix`` query values (repeated and/or comma separated) -> unique ``AA:BB:CC`` keys in request
    order, like the service (tnt.api.routes._oui_prefixes): ValueError for none, more than
    OUI_MAX_PREFIXES, or one that is not three hex pairs joined by one separator style (``:``, ``-``, none)."""
    raw = [part.strip() for value in values for part in str(value).split(",")]
    raw = [part for part in raw if part]
    if not raw:
        raise ValueError("prefix is required, e.g. ?prefix=AA:BB:CC")
    if len(raw) > OUI_MAX_PREFIXES:
        raise ValueError(f"at most {OUI_MAX_PREFIXES} prefixes per request, got {len(raw)}")
    keys: List[str] = []
    for part in raw:
        m = _OUI_PREFIX_RE.match(part)
        if m is None:
            raise ValueError(f"{part[:40]!r} is not a 24-bit OUI prefix (use AA:BB:CC)")
        key = f"{m.group(1)}:{m.group(3)}:{m.group(4)}".upper()
        if key not in keys:
            keys.append(key)
    return keys


def cross_origin_browser_request(headers: Any, port: int) -> bool:
    """The service's rule for reveal=1 (tnt.api.routes._cross_origin_browser_request): refused when
    ``Origin`` is not this server or ``Sec-Fetch-Site`` is neither absent, ``same-origin`` nor ``none``."""
    origin = (headers.get("Origin") or "").strip().lower()
    site = (headers.get("Sec-Fetch-Site") or "").strip().lower()
    if origin and origin not in {f"http://{host}:{port}" for host in ("127.0.0.1", "localhost", "[::1]")}:
        return True
    return site not in ("", "same-origin", "none")


def ip2int(ip: str) -> int:
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"{ip!r} is not an IPv4 address")
    out = 0
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            raise ValueError(f"{ip!r} is not an IPv4 address")
        out = (out << 8) | int(p)
    return out


def int2ip(n: int) -> str:
    return ".".join(str((n >> s) & 255) for s in (24, 16, 8, 0))


class DhcpConflict(RuntimeError):
    """Another DHCP server answered the probe: carries the 409 payload for the UI."""

    def __init__(self, servers: List[Dict[str, Any]], scan: Dict[str, Any]) -> None:
        super().__init__("Another DHCP server is active on this network")
        self.servers = servers
        self.scan = scan

    def payload(self) -> Dict[str, Any]:
        return {"error": {"code": "dhcp_server_present", "message": str(self)}, "servers": self.servers, "scan": self.scan}

MIME = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8", ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
    ".ttf": "font/ttf", ".woff2": "font/woff2", ".woff": "font/woff", ".md": "text/markdown; charset=utf-8",
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def changed_keys(old: Dict[str, Any], new: Dict[str, Any], prefix: str = "") -> List[str]:
    keys: List[str] = []
    for k in set(old) | set(new):
        a, b = old.get(k), new.get(k)
        if isinstance(a, dict) and isinstance(b, dict):
            keys += changed_keys(a, b, f"{prefix}{k}.")
        elif a != b:
            keys.append(f"{prefix}{k}")
    return sorted(keys)


def local_hour(ts: float) -> int:
    return time.localtime(ts).tm_hour


def local_weekday(ts: float) -> int:
    return time.localtime(ts).tm_wday


def _pdf_string(text: str) -> str:
    """Text for a PDF literal string: backslash and parentheses escaped (a site name may carry them)."""
    return str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def tiny_pdf(title: str, lines: List[str]) -> bytes:
    """Build a minimal but valid single-page PDF by hand."""
    content_lines = ["BT", "/F1 22 Tf", "72 720 Td", f"({_pdf_string(title)}) Tj"]
    y = 690
    for ln in lines:
        content_lines += ["/F1 12 Tf", f"1 0 0 1 72 {y} Tm", f"({_pdf_string(ln)}) Tj"]
        y -= 18
    content_lines.append("ET")
    content = "\n".join(content_lines).encode("latin-1", "replace")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


# ---------------------------------------------------------------------------
# reports (Full Scan): the contract's rules, kept standalone (the mock imports no tnt code)
# ---------------------------------------------------------------------------
#: a site name is trimmed with its inner whitespace collapsed, 1..80 characters (the service's rule)
REPORT_SITE_MAX = 80
#: the site of a report saved before anyone named it
REPORT_UNNAMED = "Unnamed site"
#: a full scan's phases, in order
REPORT_PHASES = ("speed", "discovery", "wifi", "history", "save")
#: the Wi-Fi phase waits this long for a TNT window's snapshot, and after an unavailable one this much longer for a usable one
REPORT_WIFI_TIMEOUT_S = 90.0
REPORT_WIFI_GRACE_S = 15.0
REPORT_NO_WINDOW = "No TNT window was open to scan Wi-Fi"
#: the ping section's reason when only targets removed since were pinged (tnt.reports.NO_TARGET_PINGS_REASON)
REPORT_NO_TARGET_PINGS = "No pings of the targets set up when the scan ran were recorded in this window"
#: a comparison's ping / outages note on the one report saved before reports left removed targets out (tnt.reports.OLDER_RULE_NOTE)
REPORT_OLDER_RULE_NOTE = "{side} was saved before reports left out removed or disabled targets"
REPORT_WIFI_MAX_BYTES = 2 * 1024 * 1024
REPORT_WIFI_MAX_APS = 1000
REPORT_WINDOW_S = 7 * 86400
REPORT_MAX_OUTAGES = 50
REPORT_MAX_HOSTS = 512
REPORT_MAX_APS = 200
#: "same" in a comparison: within 2 % of the larger value, or within this much in the row's unit (tnt.reports.UNIT_TOLERANCE)
REPORT_SAME_REL = 0.02
REPORT_SAME_ABS = {"Mbps": 1.0, "ms": 1.0, "%": 0.1, "dBm": 1.0, "per day": 0.1, "min/day": 1.0, "min": 1.0}
#: outage rates are per day monitored, compared only when both reports monitored a day (tnt.reports.MIN_RATE_S); SSIDs compared at most
REPORT_MIN_RATE_S = 86400.0
REPORT_MAX_COMPARE_SSIDS = 25
#: a target outage within this much of a network outage belongs to it (tnt.reports.FOLD_SLACK_S); free text and port caps
REPORT_FOLD_SLACK_S = 60.0
REPORT_TEXT_CAP = 128
REPORT_NOTE_CAP = 300
REPORT_MAX_HOST_PORTS = 64
REPORT_WINDOW_WORDS = {"network_change": "since this PC joined this network", "seven_days": "over the last 7 days",
                       "data_start": "since the ping data begins", "site_network": "on this network over the last 7 days"}
#: tagged pings on the site's network with no gap longer than this are one visit
REPORT_VISIT_GAP_S = 1800.0
#: The networks of the seeded reports and the ones the fake PC can be on (tnt.networks: a network is its router's MAC, else its
#: gateway, IPv4 subnet and DHCP server): key -> (router MAC or None, gateway, subnet, DHCP server, DNS suffix, adapter). Locally
#: administered MACs over the invented OUIs of OUI_VENDORS, so a router reads like a vendor's; RFC 1918 addresses. "acme" is the
#: fake PC's own LAN (net_profile "a"): a full scan there finds the Acme Dental reports and suggests that site.
MOCK_NETWORKS: Dict[str, Tuple[Optional[str], str, str, Optional[str], Optional[str], str]] = {
    "maple": ("F2:0D:CA:0A:0A:01", "192.168.10.1", "192.168.10.0/24", "192.168.10.1", "maple.example", "Ethernet"),
    "acme": ("C2:FF:EE:0A:00:FB", "10.0.0.251", "10.0.0.0/24", "10.0.0.251", "lan", "Ethernet"),
    "northside": ("D2:0D:AD:28:00:FE", "172.16.40.254", "172.16.40.0/24", "172.16.40.254", None, "Wi-Fi"),
    "pinecrest": (None, "10.44.0.1", "10.44.0.0/24", "10.44.0.1", None, "Wi-Fi"),          # its router's MAC was never read
    "b": ("D2:0D:AD:32:00:01", "192.168.50.1", "192.168.50.0/24", "192.168.50.1", "site-b.example", "Wi-Fi"),
    "static-bad": (None, "172.16.21.1", "172.16.20.0/24", None, None, "Ethernet"),           # a gateway off the subnet never answers ARP
}
#: the network of each NET_PROFILE_NAMES profile; "apipa" and "none" have no default gateway, so the fake PC stays on its last one
NET_PROFILE_NETWORK = {"a": "acme", "b": "b", "static-bad": "static-bad"}
#: where the fake PC has been, in days before the mock started: (network, arrived, left or None for the one it is on). Each seeded
#: report was made near the end of a visit (REPORT_SEEDS), and the second Acme Dental scan's week holds two visits to its network.
MOCK_ITINERARY = (("maple", 19.2, 12.2), ("acme", 9.03, 7.9), ("northside", 7.5, 5.3), ("pinecrest", 3.43, 3.4), ("acme", 3.2, None))
#: meta.network of a report whose network was not identified when its scan started (tnt.networks.unknown_network), and what the history
#: phase's message adds then (tnt.reports.UNKNOWN_NETWORK_MESSAGE)
REPORT_NETWORK_UNKNOWN = {"id": None, "mac": None, "vendor": None, "gateway_ip": None, "subnet": None, "dhcp_server": None, "identity": "unknown",
                          "virtual_mac": None, "portable": False}
REPORT_UNKNOWN_NETWORK_MESSAGE = "the network was not identified when the scan started, so they are read by time"
#: what the history message adds by why the site's network rule did not apply (tnt.reports.NETWORK_NOTE_MESSAGES)
REPORT_NETWORK_NOTE_MESSAGES = {
    "unknown": REPORT_UNKNOWN_NETWORK_MESSAGE,
    "offline": "this PC had no network with a gateway when the scan started, so they are read by time",
    "not_ready": "data is not tagged with networks yet (the database upgrade has not run, see the service log), so they are read by time",
    "portable": "this network is carried from site to site (a hotspot or travel router), so only this connection to it counts",
}
#: a comparison's note of its sides read on their site's network (tnt.reports.NETWORK_TIME_NOTE)
REPORT_NETWORK_TIME_NOTE = "On their networks: "


def mock_network_view(row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """A network as a report's meta.network describes it: its id, router MAC and vendor (from the MAC's OUI, a locally administered
    one's base OUI), gateway, subnet, DHCP server and how it was identified ("mac", "fingerprint"; "unknown" without a row)."""
    if not row:
        return dict(REPORT_NETWORK_UNKNOWN)
    return {"id": row["id"], "mac": row["mac"], "vendor": _vendor_for_bssid(row["mac"]) if row["mac"] else None, "gateway_ip": row["gateway_ip"],
            "subnet": row["subnet"], "dhcp_server": row["dhcp_server"], "identity": "mac" if row["mac"] else "fingerprint",
            "virtual_mac": None if row["mac"] else (row.get("virtual_mac") or None), "portable": bool(row.get("portable"))}


def report_duration_text(seconds: Any) -> str:
    """"42 s", "2m 05s", "1h 02m", "1d 2h": the page's durations, the time on a site's network in a comparison (tnt.reports.duration_text)."""
    s = _num(seconds)
    if s is None:
        return "-"
    s = int(max(0.0, s) + 0.5)
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60:02d}m"
    return f"{s // 86400}d {(s // 3600) % 24}h"


def report_visits(spans: List[Tuple[float, float]], start: float, end: float) -> List[Dict[str, float]]:
    """The visits to a network inside a report's window: its spans clipped to [start, end], merged when less than REPORT_VISIT_GAP_S
    apart, oldest first."""
    out: List[List[float]] = []
    for s, e in sorted((max(s, start), min(e, end)) for s, e in spans):
        if e <= s:
            continue
        if out and s - out[-1][1] <= REPORT_VISIT_GAP_S:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [{"start": round(s, 3), "end": round(e, 3)} for s, e in out]


def report_merge_spans(spans: Any) -> List[Tuple[float, float]]:
    """(start, end) spans sorted, overlapping or touching ones merged, backwards ones dropped (tnt.reports.merge_spans)."""
    out: List[Tuple[float, float]] = []
    for s, e in sorted((float(s), float(e)) for s, e in spans if _num(s) is not None and _num(e) is not None and float(e) >= float(s)):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def report_monitored_seconds(visits: Any, gaps: Any = ()) -> float:
    """Seconds of the visits without the monitoring gaps inside them (tnt.reports.monitored_seconds)."""
    spans = report_merge_spans((v.get("start"), v.get("end")) for v in visits or [] if isinstance(v, dict))
    total = sum(e - s for s, e in spans)
    for gs, ge in report_merge_spans(gaps):
        for s, e in spans:
            total -= max(0.0, min(e, ge) - max(s, gs))
    return round(max(0.0, total), 1)
REPORT_DEVICE_TYPE_ORDER = ("Router", "DW Server", "Camera", "Phone", "Ubiquiti")
#: unavailable Wi-Fi states that are this PC's situation rather than a failure: the phase is "skipped", not "error"
REPORT_WIFI_SKIPPED_STATES = ("no_bridge", "outdated", "no_adapter", "disabled")
REPORT_SPEED_KEYS = ("ts", "backend", "server", "isp", "external_ip", "download_mbps", "upload_mbps", "latency_ms", "jitter_ms",
                     "packet_loss_pct", "ok", "error", "id")
REPORT_OUTAGE_KINDS = ("target", "total_local", "total_internet", "gap")
REPORT_BANDS = ("2.4", "5", "6")
REPORT_WIFI_MAX_IFACES = 16
REPORT_MAX_EPOCH_S = 4_102_444_800.0
#: why an unavailable snapshot without its own error text has no data, by survey state (tnt.reports.WIFI_STATE_TEXT)
REPORT_WIFI_STATE_TEXT = {
    "no_bridge": "Wi-Fi can only be scanned from the TNT window",
    "outdated": "This TNT window is too old to scan Wi-Fi",
    "no_adapter": "This PC has no Wi-Fi adapter",
    "radio_off": "The Wi-Fi radio is switched off",
    "disabled": "The Wi-Fi survey is switched off in TNT",
    "location_denied": "Windows location access is off for TNT, so Wi-Fi networks cannot be listed",
    "starting": "The Wi-Fi survey had not read any networks yet",
}
#: a report id (in the path or ?a=&b=) is 1-15 decimal digits and not 0; a search string is at most 200 characters (400 otherwise)
_REPORT_ID_RE = re.compile(r"^[0-9]{1,15}$")
REPORT_QUERY_MAX = 200
_MAC_CHARS_RE = re.compile(r"^[0-9A-Fa-f:\-.\s]+$")
_MAC_SEPARATORS_RE = re.compile(r"[:\-.\s]")


class ReportBusy(RuntimeError):
    """POST /api/reports/scan while a full scan runs: carries the running job for the 409 reply."""

    def __init__(self, job: Dict[str, Any]) -> None:
        super().__init__("A full scan is already running")
        self.job = job


def site_normalize(text: Any) -> str:
    """A site name the way the service stores it (tnt.reports.normalize_site): control characters become spaces, whitespace runs
    collapse to one space, the ends are trimmed; ValueError for an empty, too long or non-string one."""
    if not isinstance(text, str):
        raise ValueError("site must be a string")
    site = re.sub(r"\s+", " ", "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in text)).strip()
    if not site:
        raise ValueError("site must not be empty")
    if len(site) > REPORT_SITE_MAX:
        raise ValueError(f"site must be at most {REPORT_SITE_MAX} characters")
    try:
        site.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("site contains characters that are not text") from None      # a lone surrogate, valid in JSON
    return site


def site_key(text: Any) -> str:
    """The key reports of one site share: whitespace collapsed, trimmed, casefolded (tnt.reports.site_key)."""
    return re.sub(r"\s+", " ", str(text or "")).strip().casefold()


def _ascii_name(text: str, limit: int) -> str:
    """ASCII letters and digits joined by '-', for a Content-Disposition file name that latin-1 headers can carry."""
    return re.sub(r"[^A-Za-z0-9]+", "-", str(text)).strip("-")[:limit].strip("-") or "site"


def report_filename(site: str, ts: float) -> str:
    return f"TNT-report-{_ascii_name(site, 40)}-{time.strftime('%Y-%m-%d-%H%M', time.localtime(ts))}.pdf"


def compare_filename(site_a: str, site_b: str) -> str:
    return f"TNT-compare-{_ascii_name(site_a, 30)}-vs-{_ascii_name(site_b, 30)}.pdf"


def _num(v: Any) -> Optional[float]:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) else None


def _median(values: List[float]) -> Optional[float]:
    xs = sorted(values)
    if not xs:
        return None
    n = len(xs)
    return round(xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2, 1)


def _vendor_for_bssid(bssid: str) -> Optional[str]:
    """The service's vendor rule for a BSSID: the OUI, or for a locally administered address its base OUI."""
    first = int(bssid[:2], 16)
    oui = f"{first & 0xFD:02X}{bssid[2:8]}" if first & 0x02 else bssid[:8]
    return OUI_VENDORS.get(oui)


def report_id_ok(text: Any) -> bool:
    """A report id the way the service takes one (in the path or ?a=&b=): 1-15 decimal digits, not 0."""
    text = str(text or "").strip()
    return bool(_REPORT_ID_RE.match(text)) and int(text) >= 1


def _mac(v: Any) -> Optional[str]:
    """"AA:BB:CC:DD:EE:FF" from the usual spellings (colons, dashes, dots, none), else None (tnt.oui.normalize_mac)."""
    if not isinstance(v, str) or not v.strip() or not _MAC_CHARS_RE.match(v.strip()):
        return None
    digits = _MAC_SEPARATORS_RE.sub("", v.strip()).upper()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)) if len(digits) == 12 else None


def _snap_text(v: Any, limit: int, strip: bool = True) -> Optional[str]:
    """Text with control characters as spaces, at most *limit* characters; None for anything but text (tnt.reports._text)."""
    if not isinstance(v, str):
        return None
    out = "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in v)
    return (out.strip() if strip else out)[:limit]


def _snap_num(v: Any) -> Optional[float]:
    """A finite number, numeric text included, never a bool (tnt.reports._num)."""
    if v is None or isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _snap_int(v: Any, lo: int, hi: int) -> Optional[int]:
    f = _snap_num(v)
    return int(f) if f is not None and f == int(f) and lo <= f <= hi else None


def report_wifi_snapshot(body: Any) -> Dict[str, Any]:
    """POST /api/reports/scan/wifi: validate and trim a snapshot like the service (tnt.reports.clean_wifi_snapshot; ValueError for
    a body of the wrong shape). An access point without a valid BSSID or a signal in -127..0 dBm is dropped, copies of one BSSID
    keep the fresh, strongest one, and the vendor comes from the BSSID, never from the page."""
    if not isinstance(body, dict):
        raise ValueError("the Wi-Fi snapshot must be a JSON object")
    available = body.get("available")
    if not isinstance(available, bool):
        raise ValueError("available must be true or false")
    state = body.get("state")
    if state is not None and not isinstance(state, str):
        raise ValueError("state must be text")
    state = re.sub(r"[^a-z0-9_]", "", (state or "").strip().lower())[:32] or ("ok" if available else "unavailable")
    error = body.get("error")
    if error is not None and not isinstance(error, str):
        raise ValueError("error must be text or null")
    collected_ts = _snap_num(body.get("collected_ts")) if body.get("collected_ts") is not None else time.time()
    if collected_ts is None or not 0.0 <= collected_ts <= REPORT_MAX_EPOCH_S:
        raise ValueError("collected_ts must be epoch seconds")
    ifaces, aps = body.get("interfaces"), body.get("aps")
    if ifaces is not None and not isinstance(ifaces, list):
        raise ValueError("interfaces must be a list")
    if aps is not None and not isinstance(aps, list):
        raise ValueError("aps must be a list")
    aps = aps or []
    if len(aps) > REPORT_WIFI_MAX_APS:
        raise ValueError(f"at most {REPORT_WIFI_MAX_APS} access points per snapshot, got {len(aps)}")
    interfaces = [{"description": _snap_text(i.get("description"), 128) or None, "state": _snap_text(i.get("state"), 32) or None,
                   "connected_bssid": _mac(i.get("connected_bssid")), "connected_ssid": _snap_text(i.get("connected_ssid"), 64, strip=False) or None}
                  for i in (ifaces or [])[:REPORT_WIFI_MAX_IFACES] if isinstance(i, dict)]
    kept: Dict[str, Dict[str, Any]] = {}
    for ap in aps:
        if not isinstance(ap, dict):
            continue
        bssid, rssi = _mac(ap.get("bssid")), _snap_num(ap.get("rssi"))
        if bssid is None or rssi is None or not -127 <= rssi <= 0:
            continue
        ssid = _snap_text(ap.get("ssid"), 64, strip=False) or ""
        band = ap.get("band")
        if isinstance(band, (int, float)) and not isinstance(band, bool):
            band = f"{band:g}"
        clean = {"bssid": bssid, "ssid": ssid, "hidden": ap["hidden"] if isinstance(ap.get("hidden"), bool) else not ssid.strip(),
                 "rssi": int(round(rssi)), "band": band if band in REPORT_BANDS else None, "channel": _snap_int(ap.get("channel"), 1, 233),
                 "center_channel": _snap_int(ap.get("center_channel"), 1, 233),
                 "width_mhz": _snap_int(ap.get("width_mhz"), 5, 320), "security": _snap_text(ap.get("security"), 48) or None,
                 "generation": _snap_text(ap.get("generation"), 16) or None, "connected": ap.get("connected") is True,
                 "stale": ap.get("stale") is True, "vendor": _vendor_for_bssid(bssid)}
        prev = kept.get(bssid)
        if prev is None or (clean["stale"], -clean["rssi"]) < (prev["stale"], -prev["rssi"]):
            kept[bssid] = clean
    return {"available": available, "state": state, "error": _snap_text(error, 300) or None, "collected_ts": round(collected_ts, 3),
            "interfaces": interfaces, "aps": list(kept.values())}


def _report_band_stats(aps: List[Dict[str, Any]]) -> Dict[str, Any]:
    rssis = [int(a["rssi"]) for a in aps]
    channels: Dict[int, int] = {}
    for a in aps:
        if a.get("channel") is not None:
            channels[int(a["channel"])] = channels.get(int(a["channel"]), 0) + 1
    busiest = min(channels.items(), key=lambda kv: (-kv[1], kv[0])) if channels else None
    return {"aps": len(aps), "networks": len({a["ssid"] for a in aps if a.get("ssid") and not a.get("hidden")}),
            "strongest_rssi": max(rssis) if rssis else None, "median_rssi": _median(rssis),
            "busiest_channel": busiest[0] if busiest else None, "busiest_channel_aps": busiest[1] if busiest else None}


def _channel_span(ap: Dict[str, Any]) -> Optional[Tuple[float, float]]:
    """(centre MHz, width MHz) of the channel an access point occupies (tnt.reports.channel_span)."""
    band, ch = ap.get("band"), ap.get("center_channel") or ap.get("channel")
    if band not in REPORT_BANDS or not isinstance(ch, int) or isinstance(ch, bool):
        return None
    centre = (2484.0 if ch == 14 else 2407.0 + 5.0 * ch) if band == "2.4" else (5000.0 if band == "5" else 5950.0) + 5.0 * ch
    width = _snap_num(ap.get("width_mhz"))
    return centre, (width if width and width > 0 else 20.0)


def _channels_overlap(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    sa, sb = _channel_span(a), _channel_span(b)
    return sa is not None and sb is not None and a.get("band") == b.get("band") and abs(sa[0] - sb[0]) < (sa[1] + sb[1]) / 2.0 - 1e-9


def report_wifi_reason(snapshot: Dict[str, Any]) -> str:
    """Why an unavailable snapshot has no data: its own error text, else a sentence for its state (tnt.reports.wifi_reason)."""
    return str(snapshot.get("error") or REPORT_WIFI_STATE_TEXT.get(str(snapshot.get("state") or "")) or "Wi-Fi could not be scanned")


def report_wifi_unavailable(reason: str, state: Optional[str] = None) -> Dict[str, Any]:
    """The wifi section in its full shape with nothing collected."""
    return {"available": False, "reason": reason, "state": state, "adapter": None, "collected_ts": None, "connected": None, "networks": 0,
            "aps_count": 0, "bands": {b: _report_band_stats([]) for b in REPORT_BANDS}, "aps": [], "aps_total": 0}


def report_wifi_section(snapshot: Optional[Dict[str, Any]], reason: Optional[str] = None) -> Dict[str, Any]:
    """The report's wifi section from a report_wifi_snapshot() result (None: nothing was posted), like tnt.reports.build_wifi_section:
    stale access points left out unless every one is, strongest first (at most 200 kept), networks counted by visible SSID, the
    connected access point (marked, else the one an interface names) with the access points on its channel; busiest_channel counts
    access points by primary channel."""
    section = report_wifi_unavailable(reason or REPORT_NO_WINDOW)
    if not isinstance(snapshot, dict):
        return section
    interfaces = [i for i in snapshot.get("interfaces") or [] if isinstance(i, dict)]
    iface = next((i for i in interfaces if i.get("connected_bssid") or i.get("connected_ssid")), None) or (interfaces[0] if interfaces else None)
    section.update(state=snapshot.get("state"), collected_ts=snapshot.get("collected_ts"), adapter=(iface or {}).get("description"))
    if not snapshot.get("available"):
        section["reason"] = report_wifi_reason(snapshot)
        return section
    every = [a for a in snapshot.get("aps") or [] if isinstance(a, dict)]
    aps = sorted([a for a in every if not a.get("stale")] or every, key=lambda a: (-int(a["rssi"]), a["bssid"]))
    bssids = {i["connected_bssid"] for i in interfaces if i.get("connected_bssid")}
    conn = next((a for a in aps if a.get("connected")), None) or next((a for a in aps if a["bssid"] in bssids), None)
    if conn is not None:
        section["connected"] = dict({k: conn.get(k) for k in ("ssid", "bssid", "rssi", "band", "channel", "width_mhz")},
                                    channel_aps=sum(1 for a in aps if conn.get("channel") is not None and a.get("band") == conn.get("band")
                                                    and a.get("channel") == conn.get("channel")),
                                    overlap_aps=sum(1 for a in aps if _channels_overlap(a, conn)) if _channel_span(conn) is not None else None)
    elif iface is not None and (iface.get("connected_bssid") or iface.get("connected_ssid")):
        section["connected"] = {"ssid": iface.get("connected_ssid"), "bssid": iface.get("connected_bssid"), "rssi": None, "band": None,
                                "channel": None, "width_mhz": None, "channel_aps": None, "overlap_aps": None}
    section.update(available=True, reason=None, networks=len({a["ssid"] for a in aps if a.get("ssid") and not a.get("hidden")}),
                   aps_count=len(aps), bands={b: _report_band_stats([a for a in aps if a.get("band") == b]) for b in REPORT_BANDS},
                   aps=[{k: a.get(k) for k in ("ssid", "hidden", "bssid", "band", "channel", "width_mhz", "rssi", "security", "generation",
                                               "vendor", "connected")} for a in aps[:REPORT_MAX_APS]],
                   aps_total=len(aps))
    return section


def _ip_key(ip: Any) -> Tuple[int, Any]:
    """Addresses in numeric order, anything else after them (the database's order of a run's hosts)."""
    try:
        return (0, int(ipaddress.ip_address(str(ip))))
    except ValueError:
        return (1, str(ip))


def report_discovery_section(run: Dict[str, Any]) -> Dict[str, Any]:
    """A discovery run as a report section (tnt.reports.build_discovery_section): hosts in address order, device types in the
    service's order, the duration to a tenth of a second, open ports 1-65535."""
    hosts = sorted((x for x in run.get("hosts") or [] if isinstance(x, dict) and x.get("ip")), key=lambda x: _ip_key(x["ip"]))
    counts: Dict[str, int] = {}
    for x in hosts:
        if x.get("device_type"):
            counts[str(x["device_type"])] = counts.get(str(x["device_type"]), 0) + 1
    types = {t: counts[t] for t in REPORT_DEVICE_TYPE_ORDER if counts.get(t)}
    types.update({t: n for t, n in sorted(counts.items()) if t not in types})
    duration = _snap_num(run.get("duration_s"))
    cap = lambda v: v[:REPORT_TEXT_CAP] if isinstance(v, str) else v  # noqa: E731
    return {"available": True, "reason": None, "run_id": run.get("id"), "range": run.get("cidr"), "started_ts": run.get("ts"),
            "duration_s": round(duration, 1) if duration is not None else None, "host_count": len(hosts), "device_types": types,
            "hosts": [{"ip": x.get("ip"), "hostname": cap(x.get("hostname")), "mac": x.get("mac"), "vendor": cap(x.get("vendor")),
                       "device_type": x.get("device_type"),
                       "open_ports": [n for n in (_snap_int(p, 1, 65535) for p in x.get("open_ports") or []) if n is not None][:REPORT_MAX_HOST_PORTS]}
                      for x in hosts[:REPORT_MAX_HOSTS]],
            "hosts_total": len(hosts), "note": None}


def report_target_name(label: Any, host: Any) -> Optional[str]:
    """A target the way the ping table names it: "NVR (172.16.40.20)", "gateway" for the row's "gateway (192.168.10.1)"
    (tnt.reports.target_name)."""
    host_text = host.strip() if isinstance(host, str) and host.strip() else None
    if host_text:
        m = re.match(r"^(.*\S) \(([^()\s]+)\)$", host_text)
        host_text = m.group(1) if m else host_text
    label_text = label.strip() if isinstance(label, str) and label.strip() else None
    name = f"{label_text} ({host_text})" if label_text and host_text and label_text.casefold() != host_text.casefold() else (label_text or host_text)
    return name[:REPORT_TEXT_CAP] if name else None


def report_left_out_note(targets: int, outages: int = 0, networks: int = 0) -> Optional[str]:
    """What a new report left out of its ping or outages section (tnt.reports.left_out_note): "Left out: 8 removed or disabled targets",
    in the outages section followed by " (1 network outage, 19 single-target outages)" for the network outages of left-out targets only
    and the single-target outages it left out, or with no target id to count "Left out: 2 single-target outages of removed or disabled
    targets"; None when nothing was."""
    def many(n: int, word: str) -> str:
        return f"{n} {word}{'' if n == 1 else 's'}"

    parts = ([many(networks, "network outage")] if networks > 0 else []) + ([many(outages, "single-target outage")] if outages > 0 else [])
    if targets > 0:
        text = "Left out: " + many(targets, "removed or disabled target")
        return (text + f" ({', '.join(parts)})") if parts else text
    return f"Left out: {' and '.join(parts)} of removed or disabled targets" if parts else None


def report_outages_section(rows: List[Dict[str, Any]], start: float, end: float, label_for: Optional[Callable[[Any], Optional[str]]] = None,
                           unavailable: Optional[str] = None, target_ids: Optional[List[Any]] = None,
                           left_out: Optional[set] = None, monitored_s: Optional[float] = None) -> Dict[str, Any]:
    """Outage rows read as incidents like tnt.reports.build_outages_section: rows clipped to the window (one still open, or running past
    the end, ends at the window's end with ``open``); overlapping total rows are one network outage, the target rows inside it (give or
    take a minute) its members; any other target row a single-target outage. ``count`` is both, ``network_down_s`` and ``longest_s``
    are the network outages', ``monitored_s`` the window without its gaps; items newest first, at most 50. An empty window or
    ``unavailable`` (no pings) counts nothing. With ``target_ids`` (the targets set up when the report was made) a target row of any
    other id, or of none, is left out before anything is counted, and ``note`` says how many targets (``left_out``, one set for both
    notes of a report, gains their ids and is what it counts; a row without an id counts as an outage only) and would-be
    single-target outages that was; a network outage whose member rows are all of left-out targets is left out too, and counted.
    ``monitored_s`` (a report of the site's network: its visits without the gaps) replaces the window without its gaps."""
    lo, hi = float(start), float(end)
    keep = None if target_ids is None else {i for i in (_snap_int(t, 0, 2 ** 62) for t in target_ids) if i is not None}
    by_kind = {k: 0 for k in REPORT_OUTAGE_KINDS}
    downtime = {k: 0.0 for k in REPORT_OUTAGE_KINDS}
    section = {"available": False, "reason": None, "window_start": round(lo, 3), "window_end": round(hi, 3), "count": 0, "network_outages": 0,
               "target_outages": 0, "by_kind": by_kind, "downtime_s": downtime, "network_down_s": 0.0, "longest_s": None, "monitored_s": None,
               "items": [], "items_total": 0, "note": None}
    if unavailable or hi <= lo:
        section["reason"] = unavailable or "The report window is empty"
        return section
    totals, targets, gaps, items, dropped, dropped_ids = [], [], [], [], [], set()
    for o in rows or []:
        kind, s0 = str(o.get("kind") or ""), _snap_num(o.get("start_ts"))
        if kind not in REPORT_OUTAGE_KINDS or s0 is None:
            continue
        e0 = _snap_num(o.get("end_ts"))
        still_open = e0 is None or bool(o.get("open"))
        s, e = max(s0, lo), min(hi if still_open else e0, hi)
        if e <= s:
            continue
        if kind == "target" and keep is not None:
            tid = _snap_int(o.get("target_id"), 0, 2 ** 62)
            if tid not in keep:
                dropped.append((s, e))          # removed or disabled since (a row without an id: an outage only): the note counts it
                if tid is not None:
                    dropped_ids.add(tid)
                continue
        if kind not in ("total_local", "total_internet"):
            by_kind[kind] += 1                  # a total counts once it is known to stay (a network outage of left-out targets does not)
            downtime[kind] += e - s
        pct = _snap_num(o.get("missed_pct"))
        host = o.get("host")
        label = label_for(o.get("target_id")) if kind == "target" and label_for is not None and o.get("target_id") is not None else None
        item = {"start_ts": round(s, 3), "end_ts": round(e, 3), "duration_s": round(e - s, 1), "kind": kind,
                "host": host[:REPORT_TEXT_CAP] if isinstance(host, str) else host, "missed": int(_snap_num(o.get("missed")) or 0),
                "missed_pct": round(pct, 2) if pct is not None else None,
                "note": o.get("note")[:REPORT_NOTE_CAP] if isinstance(o.get("note"), str) else o.get("note"),
                "open": still_open or (e0 is not None and e0 > hi), "name": report_target_name(label, host) if kind == "target" else None,
                "targets": []}
        if kind == "gap":
            gaps.append((s, e))
            items.append(item)
        else:
            (targets if kind == "target" else totals).append((s, e, item))
    nets: List[Dict[str, Any]] = []
    for s, e, row in sorted(totals, key=lambda t: (t[0], t[1])):
        if nets and s <= nets[-1]["end"]:
            nets[-1].update(end=max(nets[-1]["end"], e), open=nets[-1]["open"] or row["open"], note=nets[-1]["note"] or row["note"])
            nets[-1]["kinds"].add(row["kind"])
            nets[-1]["rows"].append((row["kind"], e - s))
        else:
            nets.append({"start": s, "end": e, "kinds": {row["kind"]}, "open": row["open"], "note": row["note"], "members": [],
                         "rows": [(row["kind"], e - s)], "kept": False, "dropped": False})
    every = list(nets)          # a left-out network outage still holds its member rows (they count as that network outage)

    def network_of(s: float, e: float) -> Optional[Dict[str, Any]]:
        return next((n for n in every if s >= n["start"] - REPORT_FOLD_SLACK_S and e <= n["end"] + REPORT_FOLD_SLACK_S), None)

    singles = []
    for s, e, row in sorted(targets, key=lambda t: (t[0], t[1])):
        home = network_of(s, e)
        if home is None:
            singles.append(row)
            continue
        home["kept"] = True
        if row["name"] and row["name"] not in home["members"]:
            home["members"].append(row["name"])
    for s, e in dropped:
        home = network_of(s, e)
        if home is not None:
            home["dropped"] = True
    # a network outage only left-out targets were members of is about targets the report does not describe: left out and counted
    gone = [n for n in nets if n["dropped"] and not n["kept"]]
    nets = [n for n in nets if not (n["dropped"] and not n["kept"])]      # network_of keeps looking at every one
    for n in nets:
        for kind, took in n["rows"]:
            by_kind[kind] += 1
            downtime[kind] += took
    for n in nets:
        items.append({"start_ts": round(n["start"], 3), "end_ts": round(n["end"], 3), "duration_s": round(n["end"] - n["start"], 1),
                      "kind": "total_local" if "total_local" in n["kinds"] else "total_internet", "host": None, "missed": 0, "missed_pct": None,
                      "note": n["note"], "open": n["open"], "name": None, "targets": n["members"]})
    items.extend(singles)
    merged: List[List[float]] = []
    for s, e in sorted(gaps):
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    monitored = hi - lo - sum(e - s for s, e in merged) if monitored_s is None else float(monitored_s)
    items.sort(key=lambda o: (o["start_ts"], o["end_ts"]), reverse=True)
    if left_out is not None:
        left_out |= dropped_ids
    # left-out rows outside every network outage (a left-out network outage's members are counted as that network outage)
    left_singles = sum(1 for s, e in dropped if network_of(s, e) is None)
    section.update(available=True, count=len(nets) + len(singles), network_outages=len(nets), target_outages=len(singles),
                   note=report_left_out_note(len(dropped_ids if left_out is None else left_out), left_singles, len(gone)) if dropped else None,
                   downtime_s={k: round(v, 1) for k, v in downtime.items()}, network_down_s=round(sum(n["end"] - n["start"] for n in nets), 1),
                   longest_s=round(max(n["end"] - n["start"] for n in nets), 1) if nets else None,
                   monitored_s=round(max(0.0, monitored), 1), items=items[:REPORT_MAX_OUTAGES], items_total=len(items))
    return section


def report_summary(data: Dict[str, Any]) -> Dict[str, Any]:
    """The report's summary: the numbers lists and quick comparisons show. Downtime is ``network_down_s`` (the union of the total
    outages); internet averages are weighted by the replies of every internet target."""
    sp = data.get("speed") or {}
    res = sp.get("result") if sp.get("available") else None
    res = res if res and res.get("ok") else None
    ping = data.get("ping") or {}
    targets = ping.get("targets") or [] if ping.get("available") else []
    gw = next((t for t in targets if t.get("role") == "gateway"), None)
    inet = [t for t in targets if t.get("role") == "internet" and t.get("samples")]
    sent = sum(t["samples"] for t in inet)
    received = sum(t["samples"] - (t.get("lost") or 0) for t in inet)
    weighted = sum((t["samples"] - (t.get("lost") or 0)) * t["avg_ms"] for t in inet if t.get("avg_ms") is not None)
    out = data.get("outages") or {}
    disc = data.get("discovery") or {}
    wifi = data.get("wifi") or {}
    win = ping if ping.get("available") else out if out.get("available") else {}
    hours = round((win["window_end"] - win["window_start"]) / 3600, 1) if win.get("window_start") is not None else None
    if ping.get("window_reason") == "site_network" and _num(ping.get("monitored_s")) is not None:
        hours = round(ping["monitored_s"] / 3600, 1)        # a report of the site's network: the hours monitored on it
    conn = wifi.get("connected") if wifi.get("available") else None
    return {"download_mbps": res and res.get("download_mbps"), "upload_mbps": res and res.get("upload_mbps"), "latency_ms": res and res.get("latency_ms"),
            "gateway_avg_ms": gw and gw.get("avg_ms"), "gateway_loss_pct": gw and gw.get("loss_pct"),
            "internet_avg_ms": round(weighted / received, 2) if received else None,
            "internet_loss_pct": round(100.0 * (sent - received) / sent, 2) if sent else None,
            "outages": out.get("count") if out.get("available") else None,
            "downtime_s": out.get("network_down_s") if out.get("available") else None,
            "hosts": disc.get("host_count") if disc.get("available") else None,
            "wifi_aps": wifi.get("aps_count") if wifi.get("available") else None, "wifi_networks": wifi.get("networks") if wifi.get("available") else None,
            "wifi_connected_rssi": conn and conn.get("rssi"), "window_hours": hours}


def _span_text(seconds: Optional[float]) -> str:
    """"45 min", "5.2 h", "6.9 days" (tnt.reports.span_text)."""
    if seconds is None:
        return "-"
    s = max(0.0, seconds)
    if s < 3600:
        return f"{int(round(s / 60.0))} min"
    if s < 2 * 86400:
        return f"{s / 3600.0:.1f} h"
    return f"{s / 86400.0:.1f} days"


def _cmp_row(key: str, label: str, unit: str, a: Any, b: Any, higher: Optional[bool], note: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """One comparison row, or None with no value on either side (tnt.reports.compare_row): delta = A - B, delta_pct relative
    to B (None when B is 0 and for dBm); better is None for an informational row (higher None) or a side without a value."""
    a = None if _num(a) is None else round(_num(a), 2)
    b = None if _num(b) is None else round(_num(b), 2)
    if a is None and b is None:
        return None
    row = {"key": key, "label": label, "unit": unit, "a": a, "b": b, "delta": None, "delta_pct": None, "better": None,
           "higher_is_better": higher, "note": note}
    if a is not None and b is not None:
        row["delta"] = round(a - b, 2)
        row["delta_pct"] = round(100.0 * (a - b) / abs(b), 1) if b and unit != "dBm" else None
        if higher is not None:
            tolerance = max(REPORT_SAME_ABS.get(unit, 0.0), REPORT_SAME_REL * max(abs(a), abs(b)))
            row["better"] = "same" if abs(a - b) <= tolerance + 1e-9 else ("a" if (a > b) == higher else "b")
    return row


def compare_reports(ra: Dict[str, Any], rb: Dict[str, Any]) -> Dict[str, Any]:
    """GET /api/reports/compare with tnt.reports.compare_reports' sections, rows, notes and tolerances: speed (with the links and the
    window's tests), ping (the targets both pinged; the first row notes both windows), network outages per day monitored (only with a
    day on each side, else each window's counts), Wi-Fi (the own network judged, other networks shown; per SSID only for one site)
    and Discovery; a section's ``note`` names the side that did not collect it."""
    da, db = ra.get("data") or {}, rb.get("data") or {}
    key_a, key_b = site_key(ra.get("site")), site_key(rb.get("site"))
    same_site = bool(key_a) and key_a == key_b

    def raw(d: Dict[str, Any], key: str) -> Dict[str, Any]:
        s = d.get(key)
        return s if isinstance(s, dict) else {}

    def avail(d: Dict[str, Any], key: str) -> Optional[Dict[str, Any]]:
        s = raw(d, key)
        return s if s.get("available") else None

    def window_len(s: Dict[str, Any]) -> Optional[float]:
        start, end = _num(s.get("window_start")), _num(s.get("window_end"))
        return None if start is None or end is None else max(0.0, end - start)

    def network_time(d: Dict[str, Any]) -> Optional[Tuple[float, int]]:
        """(seconds monitored, visits) of a report read on its site's network, else None (tnt.reports.network_time)."""
        ping = raw(d, "ping")
        if ping.get("window_reason") != "site_network":
            return None
        visits = [v for v in ping.get("visits") or [] if isinstance(v, dict)]
        monitored = _num(ping.get("monitored_s"))
        return (report_monitored_seconds(visits) if monitored is None else monitored), len(visits)

    def windows_note(sa: Dict[str, Any], sb: Dict[str, Any]) -> Optional[str]:
        """"Windows: A 6.0 days, B 30 min" of the sides read by time; a side of its site's network is in the comparison's own note."""
        wa, wb = window_len(sa), window_len(sb)
        if wa is None and wb is None:
            return None
        parts = [f"{side} {_span_text(w)}" for side, w, d in (("A", wa, da), ("B", wb, db)) if network_time(d) is None]
        return "Windows: " + ", ".join(parts) if parts else None

    def report_network(rep: Dict[str, Any]) -> Tuple[Optional[int], Dict[str, Any]]:
        """(network id, meta.network) of a report: the row's id, else meta.network's (tnt.reports.report_network)."""
        meta = raw(rep.get("data") if isinstance(rep.get("data"), dict) else {}, "meta")
        net = meta.get("network") if isinstance(meta.get("network"), dict) else {}
        nid = _snap_int(rep.get("network_id"), 1, 2 ** 62)
        return (nid if nid is not None else _snap_int(net.get("id"), 1, 2 ** 62)), net

    def keep(*rows: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [r for r in rows if r is not None]

    def plural(n: Any, word: str) -> str:
        return f"{int(n or 0)} {word if int(n or 0) == 1 else word + 's'}"

    def link_text(d: Dict[str, Any]) -> Optional[str]:
        nic = (avail(d, "network") or {}).get("internet_nic")
        if not isinstance(nic, dict):
            return None
        kind = str(nic.get("type_name") or nic.get("name") or "").strip()
        band = ((avail(d, "wifi") or {}).get("connected") or {}).get("band")
        is_wifi = any(w in " ".join(str(nic.get(k) or "") for k in ("type_name", "name", "description")).casefold()
                      for w in ("wi-fi", "wifi", "wireless", "wlan", "802.11"))
        if kind and band and is_wifi:
            kind += f" {band} GHz"
        bps = _num(nic.get("link_bps"))
        speed = None if not bps or bps <= 0 else f"{round(bps / 1e9, 1):g} Gbps" if bps >= 1e9 else f"{round(bps / 1e6):g} Mbps" if bps >= 1e6 else f"{round(bps / 1e3):g} kbps"
        return ", ".join(p for p in (kind, f"{speed} link" if speed else None) if p) or None

    def link_mbps(d: Dict[str, Any]) -> Optional[float]:
        nic = (avail(d, "network") or {}).get("internet_nic")
        bps = _num(nic.get("link_bps")) if isinstance(nic, dict) else None
        return bps / 1e6 if bps and bps > 0 else None

    def speed_rows() -> List[Dict[str, Any]]:
        ra_, rb_ = (avail(da, "speed") or {}).get("result") or {}, (avail(db, "speed") or {}).get("result") or {}
        notes = []
        la, lb = link_text(da), link_text(db)
        if la and lb and la != lb:
            notes.append(f"Links: A {la}; B {lb}")
        sa, sb = ra_.get("server") or ra_.get("backend"), rb_.get("server") or rb_.get("backend")
        if sa and sb and sa != sb:
            notes.append(f"Servers: A {sa}; B {sb}")
        wa = raw(da, "speed").get("window") if isinstance(raw(da, "speed").get("window"), dict) else {}
        wb = raw(db, "speed").get("window") if isinstance(raw(db, "speed").get("window"), dict) else {}
        window_note = f"A: {plural(wa.get('count'), 'test')}; B: {plural(wb.get('count'), 'test')}" if wa.get("count") or wb.get("count") else None
        return keep(_cmp_row("download_mbps", "Download", "Mbps", ra_.get("download_mbps"), rb_.get("download_mbps"), True, "; ".join(notes) or None),
                    _cmp_row("upload_mbps", "Upload", "Mbps", ra_.get("upload_mbps"), rb_.get("upload_mbps"), True),
                    _cmp_row("latency_ms", "Latency", "ms", ra_.get("latency_ms"), rb_.get("latency_ms"), False),
                    _cmp_row("jitter_ms", "Jitter", "ms", ra_.get("jitter_ms"), rb_.get("jitter_ms"), False),
                    _cmp_row("packet_loss_pct", "Packet loss", "%", ra_.get("packet_loss_pct"), rb_.get("packet_loss_pct"), False),
                    _cmp_row("download_window_avg", "Download, average in the window", "Mbps",
                             wa.get("download_avg") if wa.get("count") else None, wb.get("download_avg") if wb.get("count") else None, None, window_note),
                    _cmp_row("link_mbps", "Adapter link speed", "Mbps", link_mbps(da), link_mbps(db), None))

    def gateway(ping: Dict[str, Any]) -> Dict[str, Any]:
        found = [t for t in ping.get("targets") or [] if ping.get("available") and t.get("role") == "gateway" and (t.get("samples") or 0) > 0]
        return max(found, key=lambda t: t.get("samples") or 0) if found else {}

    def internet(ping: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
        if not ping.get("available"):
            return None, None
        return totals([t for t in ping.get("targets") or [] if t.get("role") == "internet"])

    def totals(targets: List[Dict[str, Any]]) -> Tuple[Optional[float], Optional[float]]:
        samples = sum(int(t.get("samples") or 0) for t in targets)
        lost = sum(int(t.get("lost") or 0) for t in targets)
        weighted, replies = 0.0, 0
        for t in targets:
            rec = int(t.get("samples") or 0) - int(t.get("lost") or 0)
            if rec > 0 and _num(t.get("avg_ms")) is not None:
                weighted += t["avg_ms"] * rec
                replies += rec
        return (round(weighted / replies, 2) if replies else None), (round(100.0 * lost / samples, 2) if samples else None)

    def by_host(ping: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for t in ping.get("targets") or [] if ping.get("available") else []:
            if t.get("role") == "internet" and t.get("host"):
                k = str(t["host"]).strip().casefold()
                if k not in out or (t.get("samples") or 0) > (out[k].get("samples") or 0):
                    out[k] = t
        return out

    def ping_rows() -> List[Dict[str, Any]]:
        pa, pb = raw(da, "ping"), raw(db, "ping")
        ga, gb = gateway(pa), gateway(pb)
        ha, hb = by_host(pa), by_host(pb)
        shared = sorted(set(ha) & set(hb))
        if shared:
            ia, ib = totals([ha[k] for k in shared]), totals([hb[k] for k in shared])
            names = [ha[k].get("label") or ha[k].get("host") for k in shared]
            inet_note = "Targets in both: " + ", ".join(str(n) for n in names[:4]) + (f" and {len(names) - 4} more" if len(names) > 4 else "")
            avg_label, loss_label, scored = "Internet average (targets in both)", "Internet loss (targets in both)", False
        else:
            ia, ib = internet(pa), internet(pb)
            avg_label, loss_label, scored = "Internet average (all targets)", "Internet loss (all targets)", None
            inet_note = ("No internet target is in both reports: each report's own targets, for information"
                         if ia[0] is not None and ib[0] is not None else None)
        rows = keep(_cmp_row("gateway_avg_ms", "Gateway average", "ms", ga.get("avg_ms"), gb.get("avg_ms"), False),
                    _cmp_row("gateway_p95_ms", "Gateway p95 of 1-min averages", "ms", ga.get("p95_ms"), gb.get("p95_ms"), False),
                    _cmp_row("gateway_max_ms", "Gateway maximum (one ping)", "ms", ga.get("max_ms"), gb.get("max_ms"), None),
                    _cmp_row("gateway_loss_pct", "Gateway loss", "%", ga.get("loss_pct"), gb.get("loss_pct"), False),
                    _cmp_row("internet_avg_ms", avg_label, "ms", ia[0], ib[0], scored, inet_note),
                    _cmp_row("internet_loss_pct", loss_label, "%", ia[1], ib[1], scored))
        for k in shared:
            name = ha[k].get("label") or ha[k].get("host")
            rows += keep(_cmp_row(f"host:{k}:avg_ms", f"{name} average", "ms", ha[k].get("avg_ms"), hb[k].get("avg_ms"), False),
                         _cmp_row(f"host:{k}:loss_pct", f"{name} loss", "%", ha[k].get("loss_pct"), hb[k].get("loss_pct"), False))
        if rows:
            rows[0]["note"] = windows_note(pa, pb)
        return rows

    def outage_numbers(s: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not s.get("available"):
            return None
        window = window_len(s) or 0.0
        monitored = _num(s.get("monitored_s"))
        monitored = window if monitored is None else max(0.0, min(monitored, window))
        kinds = s.get("by_kind") if isinstance(s.get("by_kind"), dict) else {}
        network, targets = _num(s.get("network_outages")), _num(s.get("target_outages"))
        return {"window": window, "monitored": monitored,
                "network": int(network if network is not None else (kinds.get("total_local") or 0) + (kinds.get("total_internet") or 0)),
                "down": _num(s.get("network_down_s")) or 0.0, "longest": _num(s.get("longest_s")) or 0.0,
                "targets": int(targets if targets is not None else kinds.get("target") or 0)}

    def monitored_text(n: Dict[str, Any]) -> str:
        return f"{_span_text(n['monitored'])} of {_span_text(n['window'])}" if n["window"] - n["monitored"] >= 60.0 else _span_text(n["window"])

    def outage_rows() -> List[Dict[str, Any]]:
        na, nb = outage_numbers(raw(da, "outages")), outage_numbers(raw(db, "outages"))
        if na is None and nb is None:
            return []
        by_time = [f"{side} {monitored_text(n)}" for side, n, d in (("A", na, da), ("B", nb, db)) if n and network_time(d) is None]
        note = ("Monitored: " + "; ".join(by_time)) if by_time else ""
        if na is not None and nb is not None and na["monitored"] >= REPORT_MIN_RATE_S and nb["monitored"] >= REPORT_MIN_RATE_S:
            day = lambda n, v: v / (n["monitored"] / 86400.0)  # noqa: E731
            return keep(_cmp_row("outages_per_day", "Network outages per day", "per day", day(na, na["network"]), day(nb, nb["network"]), False, note or None),
                        _cmp_row("downtime_min_per_day", "Network downtime per day", "min/day", day(na, na["down"] / 60.0), day(nb, nb["down"] / 60.0), False),
                        _cmp_row("longest_outage_min", "Longest network outage", "min", na["longest"] / 60.0, nb["longest"] / 60.0, False),
                        _cmp_row("target_outages_per_day", "Single-target outages per day", "per day", day(na, na["targets"]), day(nb, nb["targets"]), None))
        # the sides read by time say how much they had; a side of its site's network has it in the comparison's note
        shorts = [(side, n, d) for side, n, d in (("A", na, da), ("B", nb, db)) if n and n["monitored"] < REPORT_MIN_RATE_S]
        short = [f"{side} {_span_text(n['monitored'])}" for side, n, d in shorts if network_time(d) is None]
        if shorts:
            note += (". " if note else "") + "Too little history for daily rates (" + (f"{', '.join(short)}; " if short else "") + \
                "a day on each side is needed): the counts of each window"
        pick = lambda n, k, scale=1.0: None if n is None else n[k] / scale  # noqa: E731
        return keep(_cmp_row("network_outages", "Network outages", "outages", pick(na, "network"), pick(nb, "network"), None, note or None),
                    _cmp_row("downtime_min", "Network downtime", "min", pick(na, "down", 60.0), pick(nb, "down", 60.0), None),
                    _cmp_row("longest_outage_min", "Longest network outage", "min", pick(na, "longest", 60.0), pick(nb, "longest", 60.0), None),
                    _cmp_row("target_outages", "Single-target outages", "outages", pick(na, "targets"), pick(nb, "targets"), None))

    def ssid_strongest(w: Optional[Dict[str, Any]]) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for ap in (w or {}).get("aps") or []:
            if ap.get("ssid") and not ap.get("hidden") and _num(ap.get("rssi")) is not None:
                out[ap["ssid"]] = max(out.get(ap["ssid"], -1000), int(ap["rssi"]))
        return out

    def band_signals(w: Optional[Dict[str, Any]], band: str, own: Optional[str]) -> Tuple[Optional[int], Optional[int], Optional[float]]:
        mine = [int(ap["rssi"]) for ap in (w or {}).get("aps") or [] if ap.get("band") == band and _snap_num(ap.get("rssi")) is not None
                and own and ap.get("ssid") == own]
        other = [int(ap["rssi"]) for ap in (w or {}).get("aps") or [] if ap.get("band") == band and _snap_num(ap.get("rssi")) is not None
                 and not (own and ap.get("ssid") == own)]
        return (max(mine) if mine else None, max(other) if other else None, _median(other))

    def connection(w: Optional[Dict[str, Any]]) -> str:
        if not w:
            return "no Wi-Fi scan"
        c = w.get("connected") if isinstance(w.get("connected"), dict) else None
        if not c:
            return "not connected"
        where = ", ".join(x for x in (f"{c['band']} GHz" if c.get("band") else None, f"channel {c['channel']}" if c.get("channel") is not None else None,
                                      f"{c['width_mhz']} MHz" if c.get("width_mhz") else None) if x)
        return (c.get("ssid") or "a hidden network") + (f" ({where})" if where else "")

    def wifi_rows() -> List[Dict[str, Any]]:
        wa, wb = avail(da, "wifi"), avail(db, "wifi")
        if wa is None and wb is None:
            return []
        ca, cb = (wa or {}).get("connected") or {}, (wb or {}).get("connected") or {}
        note = f"A: {connection(wa)}; B: {connection(wb)}" if ca or cb else None
        rows = keep(_cmp_row("connected_rssi", "Connected signal", "dBm", ca.get("rssi"), cb.get("rssi"), True, note),
                    _cmp_row("connected_channel_aps", "APs on the connected channel", "APs", ca.get("channel_aps"), cb.get("channel_aps"), False),
                    _cmp_row("connected_overlap_aps", "APs overlapping the connected channel", "APs", ca.get("overlap_aps"), cb.get("overlap_aps"), False))
        own_a, own_b = ca.get("ssid") or None, cb.get("ssid") or None
        for band in ("2.4", "5", "6"):
            ba, bb = ((wa or {}).get("bands") or {}).get(band) or {}, ((wb or {}).get("bands") or {}).get(band) or {}
            if not (ba.get("aps") or bb.get("aps")):
                continue
            label = f"{band} GHz"
            ch = lambda b: str(b["busiest_channel"]) if b.get("busiest_channel") is not None else "none"  # noqa: E731
            channels = (f"Busiest channel: {ch(ba)} vs {ch(bb)}" if ba.get("busiest_channel") is not None or bb.get("busiest_channel") is not None else None)
            sig_a, sig_b = band_signals(wa, band, own_a), band_signals(wb, band, own_b)
            rows += keep(_cmp_row(f"band_{band}_own_rssi", f"Own network best signal, {label}", "dBm", sig_a[0], sig_b[0], True),
                         _cmp_row(f"band_{band}_other_rssi", f"Strongest other network, {label}", "dBm", sig_a[1], sig_b[1], None),
                         _cmp_row(f"band_{band}_median_rssi", f"Median signal of other APs, {label}", "dBm", sig_a[2], sig_b[2], None),
                         _cmp_row(f"band_{band}_networks", f"Networks visible, {label}", "networks", ba.get("networks", 0) if wa else None,
                                  bb.get("networks", 0) if wb else None, None),
                         _cmp_row(f"band_{band}_busiest_channel_aps", f"APs on the busiest channel, {label}", "APs", ba.get("busiest_channel_aps"),
                                  bb.get("busiest_channel_aps"), False, channels))
        if same_site:
            sa, sb = ssid_strongest(wa), ssid_strongest(wb)
            mine = {s for s in (own_a, own_b) if s}
            for ssid in sorted(set(sa) & set(sb), key=lambda s: (s not in mine, -max(sa[s], sb[s]), s))[:REPORT_MAX_COMPARE_SSIDS]:
                rows += keep(_cmp_row(f"ssid:{ssid}", f'"{ssid}" strongest signal', "dBm", sa[ssid], sb[ssid], True if ssid in mine else None))
        return rows

    def discovery_rows() -> List[Dict[str, Any]]:
        xa, xb = avail(da, "discovery"), avail(db, "discovery")
        if xa is None and xb is None:
            return []
        rows = keep(_cmp_row("hosts", "Devices found", "devices", xa.get("host_count") if xa else None, xb.get("host_count") if xb else None, None))
        ta, tb = (xa or {}).get("device_types") or {}, (xb or {}).get("device_types") or {}
        types = [t for t in REPORT_DEVICE_TYPE_ORDER if t in ta or t in tb]
        types += sorted(t for t in set(ta) | set(tb) if t not in types)
        for t in types:
            rows += keep(_cmp_row(f"type:{t}", t, "devices", ta.get(t, 0) if xa else None, tb.get(t, 0) if xb else None, None))
        return rows

    sections = []
    for key, title, fn in (("speed", "Speed test", speed_rows), ("ping", "Ping", ping_rows), ("outages", "Outages", outage_rows),
                           ("wifi", "Wi-Fi", wifi_rows), ("discovery", "Discovery", discovery_rows)):
        notes = [f"{side}: {raw(d, key).get('reason') or 'not collected'}" for side, d in (("A", da), ("B", db)) if not raw(d, key).get("available")]
        if key in ("ping", "outages"):
            # the one report saved before removed targets were left out (no note in these sections) is named
            older = [side for side, d in (("A", da), ("B", db)) if raw(d, key) and "note" not in raw(d, key)]
            newer = [side for side, d in (("A", da), ("B", db)) if "note" in raw(d, key)]
            if len(older) == 1 and len(newer) == 1 and raw(da if older[0] == "A" else db, key).get("available"):
                notes.append(REPORT_OLDER_RULE_NOTE.format(side=older[0]))
        sections.append({"key": key, "title": title, "rows": fn(), "note": "; ".join(notes) or None})
    head = lambda r: {"id": r.get("id"), "site": r.get("site"), "created_ts": r.get("created_ts"), "status": r.get("status")}  # noqa: E731
    # the comparison's own notes: the sides' time on their site's networks (tnt.reports.network_time_note), both scanned on one network
    # (tnt.reports.same_network_note)
    (ida, neta), (idb, netb) = report_network(ra), report_network(rb)
    notes = []
    times = [f"{side} {report_duration_text(t[0])} over {plural(t[1], 'visit')}" for side, t in (("A", network_time(da)), ("B", network_time(db))) if t]
    if times:
        notes.append(REPORT_NETWORK_TIME_NOTE + "; ".join(times))
    if ida is not None and ida == idb:
        mac = neta.get("mac") or netb.get("mac")
        notes.append(f"A and B were scanned on the same network ({'router ' + str(mac) if mac else 'identified by gateway and subnet'})")
    return {"a": head(ra), "b": head(rb), "sections": sections, "notes": notes}


#: the seeded saved reports: invented sites, RFC 1918 LANs, RFC 5737 public addresses, invented SSIDs and vendors
#: (the invented OUIs of OUI_VENDORS or locally administered MACs). (site, days before start, profile)
REPORT_SEEDS = (
    ("Maple Street Office", 12.2, "good"),
    ("Acme Dental", 7.95, "fair"),
    ("Northside Warehouse", 5.3, "poor"),
    ("Pinecrest Library", 3.4, "library"),
    ("Acme Dental", 2.05, "fair_again"),
)
#: what each seeded site looks like: its network (MOCK_NETWORKS), LAN, speed (down, up, latency, jitter), ping averages and loss, outages,
#: visits to its network in the week before the scan (hours before it: from, to; MOCK_ITINERARY in hours), devices, Wi-Fi; a *_reason
#: makes that section unavailable
REPORT_PROFILES: Dict[str, Dict[str, Any]] = {
    # the known good network: fibre, a quiet LAN, strong Wi-Fi, monitored the whole week
    "good": {"network": "maple", "subnet": "192.168.10", "gateway": 1, "pc": 23, "adapter": "Ethernet", "link_bps": 1_000_000_000, "public_ip": "198.51.100.20",
             "speed": (941.2, 884.6, 4.1, 0.6), "gateway_ms": 0.5, "internet_ms": 8.9, "gateway_loss": 0.0, "internet_loss": 0.02,
             "outages": 0, "visits": ((168.0, 0.0),), "hosts": 14, "ssid": "MapleStreet", "connected_rssi": -47, "neighbours": 5, "warnings": []},
    "fair": {"network": "acme", "subnet": "10.0.0", "gateway": 251, "pc": 112, "adapter": "Wi-Fi", "link_bps": 866_000_000, "public_ip": "203.0.113.44",
             "speed": (118.4, 31.2, 14.2, 2.1), "gateway_ms": 1.8, "internet_ms": 38.0, "gateway_loss": 0.4, "internet_loss": 1.2,
             "outages": 3, "visits": ((25.92, 0.0),), "hosts": 24, "ssid": "AcmeDental", "connected_rssi": -67, "neighbours": 18, "warnings": []},
    "poor": {"network": "northside", "subnet": "172.16.40", "gateway": 254, "pc": 37, "adapter": "Wi-Fi", "link_bps": 144_000_000, "public_ip": "203.0.113.160",
             "speed": (42.5, 9.6, 38.0, 9.4), "gateway_ms": 6.1, "internet_ms": 71.0, "gateway_loss": 2.8, "internet_loss": 4.1,
             "outages": 11, "visits": ((52.8, 0.0),), "hosts": 31, "ssid": "Northside-Ops", "connected_rssi": -79, "neighbours": 12,
             "warnings": ["multiple_default_gateways"]},
    # partial: the speed test was rate limited and Discovery was not available; a network known by its gateway and subnet only
    "library": {"network": "pinecrest", "subnet": "10.44.0", "gateway": 1, "pc": 57, "adapter": "Wi-Fi", "link_bps": 300_000_000, "public_ip": "198.51.100.91",
                "speed": None, "speed_reason": "The speed test failed: rate limited: the speed test servers asked to wait (try again in 12 min)",
                "gateway_ms": 2.4, "internet_ms": 22.0, "gateway_loss": 0.2, "internet_loss": 0.4, "outages": 0, "visits": ((0.72, 0.0),),
                "hosts": None, "discovery_reason": "Discovery is not available", "ssid": "Pinecrest-Public", "connected_rssi": -58, "neighbours": 9,
                "warnings": []},
    # the same dental office after its internet upgrade, scanned from a browser tab: no Wi-Fi; its week holds the first visit too
    "fair_again": {"network": "acme", "subnet": "10.0.0", "gateway": 251, "pc": 112, "adapter": "Ethernet", "link_bps": 1_000_000_000, "public_ip": "203.0.113.44",
                   "speed": (236.0, 48.5, 11.8, 1.4), "gateway_ms": 1.5, "internet_ms": 31.0, "gateway_loss": 0.1, "internet_loss": 0.6,
                   "outages": 1, "visits": ((167.52, 140.4), (27.6, 0.0)), "hosts": 25, "ssid": "AcmeDental", "connected_rssi": None, "neighbours": 18,
                   "wifi_reason": REPORT_NO_WINDOW, "warnings": [], "removed": "192.0.2.77"},
}
#: the devices a seeded scan finds, in turn after the router: (name, device_type, OUI or None for a locally administered MAC, ports)
REPORT_DEVICES = (
    ("dw-server", "DW Server", None, [7001, 8000]),
    ("cam-entry", "Camera", "CC:A7:00", [80, 554]),
    ("phone-desk", "Phone", "F0:0D:CA", [80, 5060]),
    ("ap-ceiling", "Ubiquiti", "D0:0D:AD", [22, 80, 443]),
    ("printer", None, "DC:BA:5E", [80, 443]),
    ("workstation", None, None, [3389]),
    ("tablet", None, None, []),
    (None, None, "EC:0B:0B", [443]),
)
REPORT_NEIGHBOURS = ("Harbor Cafe Guest", "Printer-Setup-4C2D", "Lakeside-5G", "", "Oak & Ivy", "Bluebird Mesh", "Transit-Hotspot",
                     "Cedar-IoT", "Pixel Pantry", "", "Riverbend-Guest", "Quill & Co")
#: the neighbours' BSSID prefixes: locally administered (0x02 set), most of them over an invented OUI of OUI_VENDORS
REPORT_NEIGHBOUR_OUIS = ("F2:0D:CA", "0E:5A:11", "D2:0D:AD", "EE:0B:0B", "1A:2B:3C", "DE:BA:5E")


def synthetic_report(site: str, created_ts: float, profile: str, network_id: Optional[int] = None) -> Dict[str, Any]:
    """A saved report of an invented site (every section of the contract), deterministic for a site and profile: its pings and outages
    come from the profile's visits to its network (MOCK_NETWORKS, with ``network_id`` as that network's id) in the week before it."""
    p = REPORT_PROFILES[profile]
    rng = random.Random(profile + ":" + site)
    subnet, gw_ip = p["subnet"], f"{p['subnet']}.{p['gateway']}"
    mac, _gw, net_subnet, dhcp_server = MOCK_NETWORKS[p["network"]][:4]
    net_meta = mock_network_view({"id": network_id, "mac": mac, "gateway_ip": gw_ip, "subnet": net_subnet, "dhcp_server": dhcp_server})
    reason = "site_network"
    start, end = created_ts - REPORT_WINDOW_S, created_ts
    visits = report_visits([(created_ts - a * 3600, created_ts - b * 3600) for a, b in p["visits"]], start, end)
    visit_s = sum(v["end"] - v["start"] for v in visits)
    hours = visit_s / 3600

    def at(frac: float) -> float:
        """The moment *frac* of the way through the time spent on the site's network (outages happen during visits)."""
        left = max(0.0, min(1.0, frac)) * visit_s
        for v in visits:
            if left <= v["end"] - v["start"]:
                return v["start"] + left
            left -= v["end"] - v["start"]
        return end

    phases, t = [], created_ts
    statuses = {"speed": "done" if p.get("speed") else "error", "discovery": "done" if p.get("hosts") else "skipped",
                "wifi": "skipped" if p.get("wifi_reason") else "done", "history": "done", "save": "done"}
    messages = {"speed": p.get("speed_reason") or "", "discovery": p.get("discovery_reason") or "", "wifi": p.get("wifi_reason") or ""}
    for key, took in zip(REPORT_PHASES, (21.0, 23.5, 12.0, 1.4, 0.3)):
        phases.append({"key": key, "status": statuses[key], "message": messages.get(key, ""), "started_ts": t, "finished_ts": t + took})
        t += took
    completed = t
    network = {"available": True, "reason": None,
               "internet_nic": {"name": p["adapter"], "description": f"{p['adapter']} adapter (synthetic)", "type_name": p["adapter"], "internet": True,
                                "ipv4": f"{subnet}.{p['pc']}", "prefix": 24, "gateway": gw_ip, "dns": [gw_ip, "1.1.1.1"],
                                "dhcp": True, "dhcp_server": gw_ip, "mac": "02:5E:10:00:%02X:%02X" % (p["pc"], p["gateway"] % 256), "link_bps": p["link_bps"]},
               "public_ip": p["public_ip"], "isp": None, "warnings": list(p["warnings"])}
    window_count = int(hours * 4)
    if p.get("speed"):
        down, up, lat, jit = p["speed"]
        speed = {"available": True, "reason": None,
                 "result": {"ts": created_ts + 1, "backend": "cloudflare", "server": "Cloudflare (synthetic)", "isp": None, "external_ip": p["public_ip"],
                            "download_mbps": down, "upload_mbps": up, "latency_ms": lat, "jitter_ms": jit, "packet_loss_pct": 0.0, "ok": True, "error": None, "id": None},
                 "window": {"count": window_count, "download_avg": round(down * 0.97, 1), "download_min": round(down * 0.78, 1), "download_max": round(down * 1.02, 1),
                            "upload_avg": round(up * 0.98, 1), "upload_min": round(up * 0.85, 1), "upload_max": round(up * 1.01, 1), "latency_avg": round(lat * 1.08, 1)}}
    else:
        speed = {"available": False, "reason": p["speed_reason"], "result": None,
                 "window": {"count": 0, "download_avg": None, "download_min": None, "download_max": None, "upload_avg": None, "upload_min": None,
                            "upload_max": None, "latency_avg": None}}
    secs = int(hours * 3600)

    def target(tid: int, host: str, label: Optional[str], role: str, ip: str, avg: float, loss: float) -> Dict[str, Any]:
        lost = int(round(secs * loss / 100))
        return {"id": tid, "host": host, "label": label, "role": role, "ip": ip, "samples": secs, "lost": lost, "loss_pct": round(loss, 2),
                "avg_ms": round(avg, 2), "min_ms": round(avg * 0.55, 2), "max_ms": round(avg * 9 + 25, 1), "p95_ms": round(avg * 1.9, 2),
                "jitter_ms": round(avg * 0.12 + 0.1, 2)}

    # the three targets set up for the scan; a profile's "removed" is a test address removed before it (id 4), whose pings and
    # outages are still in the history and left out of the report like the service leaves them out
    ids = {f"gateway ({gw_ip})": 1, "1.1.1.1": 2, "totalelectronics.com": 3}
    removed = p.get("removed")
    ping = {"available": True, "reason": None, "window_start": start, "window_end": end, "window_reason": reason, "visits": visits,
            "monitored_s": None,                        # the visits without the monitoring gaps in them, once the rows are made
            "targets": [target(1, "gateway", "Gateway", "gateway", gw_ip, p["gateway_ms"], p["gateway_loss"]),
                        target(2, "1.1.1.1", None, "internet", "1.1.1.1", p["internet_ms"] * 0.7, p["internet_loss"] * 0.9),
                        target(3, "totalelectronics.com", None, "internet", "203.0.113.80", p["internet_ms"] * 1.3, p["internet_loss"] * 1.1)],
            "note": report_left_out_note(1 if removed else 0), "untagged_since": None}
    rows = []
    n = p["outages"]
    for i in range(n):
        kind = ("target", "total_internet", "target", "target", "total_local")[i % 5]
        dur = round(25 + rng.random() * (540 if kind != "target" else 200), 1)
        st = at((i + 0.5) / (n + 1))
        host = None if kind != "target" else ("totalelectronics.com" if i % 2 else "1.1.1.1")
        rows.append({"start_ts": st, "end_ts": st + dur, "kind": kind, "target_id": ids.get(host), "host": host, "missed": int(dur) if kind == "target" else 0,
                     "missed_pct": round(90 + rng.random() * 10, 1) if kind == "target" else None, "note": None})
        # like the tracker: a total opens once every target of its group has an outage of its own, which the report folds into it
        members = {"total_internet": ("1.1.1.1", "totalelectronics.com"), "total_local": (f"gateway ({gw_ip})",)}.get(kind, ())
        for k, member in enumerate(members):
            rows.append({"start_ts": st - 2.0 - k, "end_ts": st + dur + 1.5 + k, "kind": "target", "target_id": ids[member], "host": member,
                         "missed": int(dur), "missed_pct": 100.0, "note": None})
    for k in range(2 if removed else 0):
        st = at((k + 1) / 4)
        rows.append({"start_ts": st, "end_ts": st + 240.0, "kind": "target", "target_id": 4, "host": removed, "missed": 240, "missed_pct": 100.0,
                     "note": "target removed" if k else None})
    if n > 2:
        rows.append({"start_ts": at(0.9), "end_ts": at(0.9) + 1800, "kind": "gap", "host": None, "missed": 0,
                     "missed_pct": None, "note": "system sleep"})
    ping["monitored_s"] = report_monitored_seconds(visits, [(r["start_ts"], r["end_ts"]) for r in rows if r["kind"] == "gap"])
    outages = report_outages_section(rows, start, end, None, None, [1, 2, 3], {4} if removed else set(), ping["monitored_s"])
    if p.get("hosts"):
        hosts, counts = [], {}
        for i in range(p["hosts"]):
            if i == 0:
                name, dtype, oui, ports, ip = "gateway", "Router", "C0:FF:EE", [80, 443], gw_ip
            else:
                name, dtype, oui, ports = REPORT_DEVICES[(i - 1) % len(REPORT_DEVICES)]
                ip = f"{subnet}.{10 + i}"
            counts[name] = counts.get(name, 0) + 1
            mac = f"{oui}:{(i * 37) % 256:02X}:{(i * 11) % 256:02X}:{i:02X}" if oui else f"0A:5E:{(i * 29) % 256:02X}:{(i * 7) % 256:02X}:{p['pc']:02X}:{i:02X}"
            if i == 0 and net_meta["mac"]:
                mac = net_meta["mac"]                       # the router that identifies the site's network
            hosts.append({"ip": ip, "hostname": f"{name}-{counts[name]}.lan" if name and name != "gateway" else ("gateway.lan" if name else None), "mac": mac,
                          "vendor": (net_meta["vendor"] if i == 0 and net_meta["mac"] else OUI_VENDORS[oui]) if oui else "Locally administered (randomized)",
                          "device_type": dtype, "open_ports": list(ports)})
        discovery = report_discovery_section({"id": None, "cidr": f"{subnet}.0/24", "ts": created_ts + 21, "duration_s": 18.4 + rng.random() * 4, "hosts": hosts})
    else:
        discovery = {"available": False, "reason": p["discovery_reason"], "run_id": None, "range": None, "started_ts": None, "duration_s": None,
                     "host_count": 0, "device_types": {}, "hosts": [], "hosts_total": 0, "note": None}
    if p.get("wifi_reason"):
        wifi = report_wifi_unavailable(p["wifi_reason"])
    else:
        ssid, conn = p["ssid"], p["connected_rssi"]
        # locally administered BSSIDs (the 0x02 bit set), as access points derive them; the vendor comes from the base OUI
        own = [(ssid + "-Staff", "2.4", 6, 20, conn + 3, False, "C2:FF:EE:40:00:01"), (ssid + "-Staff", "5", 36, 80, conn, True, "C2:FF:EE:40:00:02"),
               (ssid + "-Staff", "5", 149, 80, conn - 9, False, "C2:FF:EE:40:10:02"), (ssid + "-Guest", "2.4", 6, 20, conn + 2, False, "C2:FF:EE:41:00:01"),
               (ssid + "-Guest", "5", 36, 80, conn - 1, False, "C2:FF:EE:41:00:02")]
        aps = [{"ssid": s, "hidden": False, "bssid": b, "band": band, "channel": ch, "width_mhz": w, "rssi": r, "security": "WPA2/WPA3-Personal" if s.endswith("Staff") else "OWE",
                "generation": "Wi-Fi 6", "vendor": _vendor_for_bssid(b), "connected": c} for s, band, ch, w, r, c, b in own]
        for i in range(p["neighbours"]):
            s = REPORT_NEIGHBOURS[i % len(REPORT_NEIGHBOURS)]
            band = ("2.4", "5", "2.4", "5", "6")[i % 5]
            ch = {"2.4": (1, 6, 11)[i % 3], "5": (36, 44, 149, 157, 100)[i % 5], "6": (37, 69)[i % 2]}[band]
            bssid = "%s:%02X:%02X:%02X" % (REPORT_NEIGHBOUR_OUIS[i % len(REPORT_NEIGHBOUR_OUIS)], i, (i * 13) % 256, (i * 7 + 1) % 256)
            aps.append({"ssid": s, "hidden": not s, "bssid": bssid, "band": band, "channel": ch, "width_mhz": {"2.4": 20, "5": 80, "6": 160}[band],
                        "rssi": -62 - rng.randint(0, 30), "security": ("WPA2-Personal", "Open", "WPA3-Personal", "WPA2-Enterprise")[i % 4],
                        "generation": ("Wi-Fi 5", "Wi-Fi 6", "Wi-Fi 4", "Wi-Fi 6E")[i % 4] if band != "6" else "Wi-Fi 6E",
                        "vendor": _vendor_for_bssid(bssid), "connected": False})
        wifi = report_wifi_section(report_wifi_snapshot({
            "available": True, "state": "ok", "error": None, "collected_ts": created_ts + 50, "aps": aps,
            "interfaces": [{"description": "Wi-Fi 6E adapter (synthetic)", "state": "connected", "connected_bssid": "C2:FF:EE:40:00:02",
                            "connected_ssid": ssid + "-Staff"}]}))
    data = {"meta": {"site": site, "created_ts": created_ts, "completed_ts": completed, "duration_s": round(completed - created_ts, 1),
                     "tnt_version": VERSION, "hostname": PC_HOSTNAME, "scan_phases": phases, "network": net_meta},
            "network": network, "speed": speed, "ping": ping, "outages": outages, "discovery": discovery, "wifi": wifi}
    status = "complete" if all(ph["status"] == "done" for ph in phases) else "partial"
    return {"site": site, "site_key": site_key(site), "created_ts": created_ts, "completed_ts": completed, "status": status,
            "tnt_version": VERSION, "network_id": network_id, "summary": report_summary(data), "data": data}


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------
class SseHub:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clients: List["queue.Queue[str]"] = []

    def subscribe(self) -> "queue.Queue[str]":
        q: "queue.Queue[str]" = queue.Queue(maxsize=2000)
        with self._lock:
            self._clients.append(q)
        return q

    def unsubscribe(self, q: "queue.Queue[str]") -> None:
        with self._lock:
            if q in self._clients:
                self._clients.remove(q)

    def count(self) -> int:
        with self._lock:
            return len(self._clients)

    def publish(self, event_type: str, data: Dict[str, Any]) -> None:
        frame = f"event: {event_type}\ndata: {json.dumps(data, default=str)}\n\n"
        with self._lock:
            clients = list(self._clients)
        for q in clients:
            try:
                q.put_nowait(frame)
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait(frame)
                except (queue.Empty, queue.Full):
                    pass


class MockState:
    """All fake data lives here; every public method takes the lock."""

    def __init__(self, port: int) -> None:
        self.lock = threading.RLock()
        self.port = port
        self.started_ts = time.time() - 3 * 3600 - 421
        self.hub = SseHub()
        self.settings = copy.deepcopy(DEFAULTS)
        self.settings["api"]["port"] = port
        self.paused = False
        self.next_id = 1
        self.targets: List[Dict[str, Any]] = []
        self.removed_targets: Dict[int, float] = {}         # id -> when it was removed: a full scan leaves its history out
        self.samples: Dict[int, List[tuple]] = {}
        self.outages: List[Dict[str, Any]] = []
        self.speedtests: List[Dict[str, Any]] = []
        self.speed_running = False
        self.speed_progress = {"phase": "idle", "pct": 0.0}
        self.speed_next_ts = time.time() + 7 * 60
        self.disc_runs: List[Dict[str, Any]] = []
        self.disc_running = False
        self.disc_cancel = threading.Event()
        self.disc_progress = {"phase": "done", "done": 0, "total": 0, "found": 0, "elapsed_s": 0.0}
        self.disc_started_ts = 0.0
        self.disc_range: Optional[str] = None       # the running (or last started) scan, as the service reports it
        self.disc_ports: List[int] = []
        # fake DHCP server (Tools view)
        self.dhcp_running = False
        self.dhcp_since: Optional[float] = None
        self.dhcp_error: Optional[str] = None
        self.dhcp_warning: Optional[str] = None
        self.dhcp_changed = False           # we re-addressed the adapter to the static IP
        self.dhcp_clients: List[Dict[str, Any]] = []
        self.dhcp_last_scan: Optional[Dict[str, Any]] = None
        self.dhcp_force_none = False        # True: the probe finds no other server
        self.dhcp_fast = False              # tests: clients appear within a second
        self.dhcp_gen = 0                   # bumps on every start/stop so a stale worker exits
        # Tools: traceroute + LAN throughput (both synchronous, one at a time)
        self.trace_running = False
        self.trace_last: Optional[Dict[str, Any]] = None
        self.trace_fast = False             # tests: hops arrive within a few ms
        self.lan_running = False
        self.lan_last: Optional[Dict[str, Any]] = None
        self.lan_fast = False
        self.lan_peer_ts = time.time()      # the last "announcement" round (lan.peers every 10 s)
        self.lan_enabled = True             # the Tools switch (PUT /api/tools/lan/settings)
        self.wifi_admin = True              # tests: set False to simulate a non-admin caller (403 on reveal=1)
        # IP location (tnt.geoip): the fake manager's state (POST /mock/geoip), the text it shows in "error" and its data month
        self.geoip_state = "ready"
        self.geoip_error = "HTTP 503 from download.db-ip.com"
        self.geoip_month = time.strftime("%Y-%m", time.gmtime())
        self.public_ip_ts = time.time() - 4 * 60
        # the network this fake PC is on (NET_PROFILE_NAMES) and the change counter status.net reports
        self.net_profile = "a"
        self.net_generation = 0
        self.net_changed_ts: Optional[float] = None
        self.net_public_before: Optional[Dict[str, Any]] = None   # the WAN answer shown until the lookup after a change lands
        self.net_last_event: Optional[Dict[str, Any]] = None     # the last net.changed payload (diagnostics.network.last_change)
        self.disc_net_changed = False                             # the network changed while the running scan ran
        self.net_switch_after_status: Optional[tuple] = None       # tests: (n, profile) switches on the nth GET /api/status
        self.status_requests = 0
        # the networks the fake PC has been on and the seeded reports were made on (tnt.networks), the one it is on now (the last one
        # while it has none) and its visits, [network id, arrived, left or None]; a report of a site counts its network's visits only
        self.networks: List[Dict[str, Any]] = []
        self.net_id: Optional[int] = None
        self.net_spells: List[List[Any]] = []
        self.net_offline_since: Optional[float] = None             # no network since then: not yet a visit's end (it may come back)
        # Reports: the saved site reports (seeded) and the one full scan at a time
        self.reports: List[Dict[str, Any]] = []
        self.report_next_id = 1
        self.report_job: Optional[Dict[str, Any]] = None
        self.report_job_seq = 0
        self.report_network_why: Optional[str] = None      # why the running scan is on no site's network (REPORT_NETWORK_NOTE_MESSAGES)
        self.report_cancel = threading.Event()
        self.report_wifi_open = False                        # the running scan's Wi-Fi phase takes snapshots now
        self.report_wifi_taken = False                       # ... until it has a usable one (a later post is 409, like the service)
        self.report_wifi_inbox: List[Dict[str, Any]] = []
        self.report_wifi_event = threading.Event()
        self.report_wifi_posts: List[Dict[str, Any]] = []    # every snapshot a waiting scan accepted (tests count them)
        self.report_fast = False                             # tests: the speed test and Discovery take a few ms
        self.report_wifi_timeout_s = REPORT_WIFI_TIMEOUT_S
        self.report_wifi_grace_s = REPORT_WIFI_GRACE_S
        self.log_ring: List[Dict[str, Any]] = []
        self.events_db: List[Dict[str, Any]] = []
        self.rng = random.Random(7)
        self._seed()

    # -- seeding ---------------------------------------------------------
    def _seed(self) -> None:
        now = time.time()
        # the "gateway" alias, like the service's default tile: its address follows the network (switch_network)
        self._add_target("gateway", "Gateway", kind="local", ip="10.0.0.251", base=0.6)
        self._add_target("1.1.1.1", None, kind="internet", ip="1.1.1.1", base=12.0)
        self._add_target("totalelectronics.com", None, kind="internet", ip="203.0.113.80", base=38.0)
        # backfill 5 minutes of samples so sparklines are full on first paint
        for t in self.targets:
            for i in range(300, 0, -1):
                self.samples[t["id"]].append(self._make_sample(t, now - i))
        # outages in the last 24 h
        oid = 1

        def add(kind: str, tid: Optional[int], start: float, end: Optional[float], missed: int, note: Optional[str] = None,
                sent: Optional[int] = None) -> None:
            nonlocal oid
            self.outages.append({"id": oid, "kind": kind, "target_id": tid, "start_ts": start, "end_ts": end,
                                 "missed": missed, "sent": sent, "note": note})
            oid += 1

        add("gap", None, now - 20 * 3600, now - 20 * 3600 + 22 * 60, 0, "not monitoring")
        add("target", 1, now - 14 * 3600, now - 14 * 3600 + 95, 95)                            # an older row: estimated
        add("target", 2, now - 6 * 3600 - 260, now - 6 * 3600, 258, sent=260)
        add("target", 2, now - 2 * 3600 - 31 * 60, now - 2 * 3600 - 26 * 60 - 40, 241, sent=260)  # a flaky link: 92.6%
        add("target", 3, now - 2 * 3600 - 30 * 60, now - 2 * 3600 - 27 * 60, 180, sent=180)
        add("total_internet", None, now - 2 * 3600 - 30 * 60, now - 2 * 3600 - 27 * 60, 0)
        add("target", 3, now - 47 * 60, now - 46 * 60 - 20, 40, sent=40)
        # speed history: 7 days every 15 min
        t0 = now - 7 * 86400
        t = t0 - (t0 % 900)
        i = 0
        while t <= now - 900:
            i += 1
            self.speedtests.append(self._make_speed(t, fail=(i % 223 == 0)))
            t += 900
        self.speed_next_ts = now + self.rng.randint(120, 600)
        # two previous discovery runs
        self._add_disc_run(now - 26 * 3600, "10.0.0.0/24", list(DEFAULT_PORTS), 4.2, drop=1)
        self._add_disc_run(now - 3 * 3600 - 700, "10.0.0.0/24", list(DEFAULT_PORTS), 3.9, drop=0)
        # log ring + events
        base = now - 3 * 3600
        msgs = [
            ("INFO", "tnt.engine", "started v%s" % VERSION),
            ("INFO", "tnt.api.server", "listening on 127.0.0.1:%d" % self.port),
            ("INFO", "tnt.pinger", "target 1 gateway resolved -> 10.0.0.251 (local)"),
            ("INFO", "tnt.pinger", "target 2 1.1.1.1 resolved -> 1.1.1.1 (internet)"),
            ("INFO", "tnt.pinger", "target 3 totalelectronics.com resolved -> 203.0.113.80 (internet)"),
            ("INFO", "tnt.speedtest.scheduler", "next speed test in 60 s"),
            ("WARNING", "tnt.outages", "target 3 totalelectronics.com: outage started (3 misses)"),
            ("INFO", "tnt.outages", "target 3 totalelectronics.com: recovered after 40 s"),
            ("INFO", "tnt.speedtest.cloudflare", "download 117.4 Mbps upload 30.9 Mbps latency 11.8 ms"),
            ("DEBUG", "tnt.api.server", "GET /api/status 200"),
        ]
        for k, (lvl, name, msg) in enumerate(msgs):
            self.log_ring.append({"ts": base + k * 600, "level": lvl, "logger": name, "message": f"{name}: {msg}"})
        self.events_db = [
            {"id": 1, "ts": base, "level": "info", "category": "service", "message": "started v" + VERSION},
            {"id": 2, "ts": now - 47 * 60, "level": "warning", "category": "outage", "message": "totalelectronics.com down"},
            {"id": 3, "ts": now - 46 * 60, "level": "info", "category": "outage", "message": "totalelectronics.com recovered"},
        ]
        # the networks this PC was on (MOCK_ITINERARY), then the saved site reports for the Reports page (REPORT_SEEDS: invented sites)
        self._seed_networks(now)
        self._seed_reports(now)

    def _add_target(self, host: str, label: Optional[str], kind: str, ip: Optional[str], base: float) -> Dict[str, Any]:
        tid = self.next_id
        self.next_id += 1
        t = {"id": tid, "host": host, "label": label, "kind": kind, "ip": ip, "enabled": True,
             "resolved": ip is not None, "resolve_error": None if ip else "getaddrinfo failed",
             "in_outage": False, "since_ts": time.time(), "base": base, "consecutive_missed": 0,
             "consecutive_ok": 0}
        self.targets.append(t)
        self.samples[tid] = []
        return t

    def _make_sample(self, t: Dict[str, Any], ts: float) -> tuple:
        rng = self.rng
        base = t["base"]
        if not t.get("resolved"):
            return (ts, False, None)
        # on a network without internet (see NET_PROFILE_NAMES) only the local targets answer
        if t["kind"] == "internet" and self.net_profile != "a" and not net_profile(self.net_profile)["public_ip"]:
            return (ts, False, None)
        # sluggish phase: totalelectronics.com every 4 min for 45 s
        slug = t["host"] == "totalelectronics.com" and (int(ts) % 240) < 45
        miss_p = {"gateway": 0.0, "1.1.1.1": 0.012}.get(t["host"], 0.006)
        if slug:
            miss_p = 0.05
        if rng.random() < miss_p:
            return (ts, False, None)
        rtt = base * (1 + rng.gauss(0, 0.09))
        if slug:
            rtt = 170 + rng.gauss(0, 25)
        if rng.random() < 0.02:
            rtt *= 1 + rng.random() * 2.5
        rtt = max(0.2, rtt)
        return (ts, True, round(rtt, 2))

    def _make_speed(self, ts: float, fail: bool = False) -> Dict[str, Any]:
        rng = self.rng
        hour = local_hour(ts)
        evening = 19 <= hour < 22
        f = 0.6 if evening else 1.0
        if fail:
            return {"id": len(self.speedtests) + 1, "ts": ts, "ok": False, "backend": "cloudflare", "server": None,
                    "isp": None, "external_ip": None, "latency_ms": None, "jitter_ms": None,
                    "download_mbps": None, "upload_mbps": None, "packet_loss_pct": None, "duration_s": 12.1,
                    "error": "HTTP 503 from speed.cloudflare.com"}
        down = 118 * f * (1 + rng.gauss(0, 0.05))
        up = 31 * (0.9 if evening else 1.0) * (1 + rng.gauss(0, 0.05))
        lat = 12 + (7 if evening else 0) + rng.gauss(0, 1.4)
        return {"id": len(self.speedtests) + 1, "ts": ts, "ok": True, "backend": "cloudflare",
                "server": "Cloudflare AMS", "isp": "Example ISP", "external_ip": "203.0.113.5",
                "latency_ms": round(max(3, lat), 1), "jitter_ms": round(1 + abs(rng.gauss(0, 0.8)), 2),
                "download_mbps": round(max(1, down), 1), "upload_mbps": round(max(1, up), 1),
                "packet_loss_pct": 0.0, "duration_s": round(16 + rng.random() * 3, 1), "error": None}

    # (ip, hostname, mac, vendor, rtt_ms, open_ports, device_type) - the device_type values are what
    # tnt.discovery.classify_device would return for these rows (10.0.0.251 is the mock gateway)
    _HOSTS = [
        ("10.0.0.251", "gateway.lan", "24:5A:4C:12:34:01", "Ubiquiti Inc", 0.6, [80, 443], "Router"),
        ("10.0.0.10", "nas.lan", "00:11:32:12:34:02", "Synology Incorporated", 0.9, [80, 443, 8080], None),
        ("10.0.0.21", "printer-hp.lan", "3C:D9:2B:12:34:03", "Hewlett Packard", 2.1, [80, 443], None),
        ("10.0.0.35", None, "C0:56:E3:12:34:04", "Hangzhou Hikvision Digital Technology Co., Ltd.", 1.4, [80, 554], "Camera"),
        ("10.0.0.36", None, "C0:56:E3:12:34:05", "Hangzhou Hikvision Digital Technology Co., Ltd.", 1.5, [80, 554], "Camera"),
        ("10.0.0.62", "yealink-front.lan", "80:5E:C0:12:34:06", "Yealink(Xiamen) Network Technology", 2.6, [80, 5060], "Phone"),
        ("10.0.0.70", "iphone.lan", "DA:12:34:12:34:07", "Locally administered (randomized)", 11.2, [], None),
        ("10.0.0.112", "TEC-DESKTOP.lan", "D8:BB:C1:12:34:08", "Micro-Star INTL CO., LTD.", 0.3, [7001, 8000], "DW Server"),
        ("10.0.0.120", "samsung-tv.lan", "8C:79:F5:12:34:09", "Samsung Electronics Co.,Ltd", 4.8, [8000, 8080], None),
        ("10.0.0.130", "pi4.lan", "DC:A6:32:12:34:0A", "Raspberry Pi Trading Ltd", 0.7, [80, 8443], None),
        ("10.0.0.201", "sonos-kitchen.lan", "94:9F:3E:12:34:0B", "Sonos, Inc.", 3.2, [], None),
        ("10.0.0.240", "ap-warehouse.lan", "24:5A:4C:12:34:0C", "Ubiquiti Networks Inc.", 1.1, [22, 80, 443], "Ubiquiti"),
        ("10.0.0.230", None, None, None, None, [443], None),
    ]

    def _build_hosts(self, drop: int = 0, jitter: bool = True) -> List[Dict[str, Any]]:
        hosts = []
        for k, (ip, hn, mac, vendor, rtt, ports, device_type) in enumerate(self._HOSTS):
            if drop and k == 6:
                continue
            r = None if rtt is None else round(rtt * (1 + (self.rng.gauss(0, 0.15) if jitter else 0)), 2)
            hosts.append({"ip": ip, "hostname": hn, "mac": mac, "vendor": vendor, "ping_ok": rtt is not None,
                          "rtt_ms": r, "open_ports": list(ports), "device_type": device_type})
        return hosts

    def _add_disc_run(self, ts: float, cidr: str, ports: List[int], duration: float, drop: int = 0,
                      hosts: Optional[List[Dict[str, Any]]] = None, cancelled: bool = False) -> Dict[str, Any]:
        rid = len(self.disc_runs) + 1
        hosts = hosts if hosts is not None else self._build_hosts(drop=drop)
        run = {"id": rid, "ts": ts, "cidr": cidr, "ports": list(ports), "method": "native", "duration_s": duration,
               "scanned": 254, "found": len(hosts), "ok": True, "error": "cancelled" if cancelled else None,
               "hosts": [dict(h, run_id=rid) for h in hosts]}
        self.disc_runs.append(run)
        return run

    # -- ping / targets --------------------------------------------------
    def tick(self, ts: float) -> None:
        with self.lock:
            if self.paused:
                return
            out = []
            for t in self.targets:
                s = self._make_sample(t, ts)
                buf = self.samples[t["id"]]
                buf.append(s)
                if len(buf) > 3600:
                    del buf[: len(buf) - 3600]
                if s[1]:
                    t["consecutive_ok"] += 1
                    t["consecutive_missed"] = 0
                else:
                    t["consecutive_missed"] += 1
                    t["consecutive_ok"] = 0
                out.append({"target_id": t["id"], "ts": ts, "ok": s[1], "rtt_ms": s[2], "light": self._light(t)})
        for ev in out:
            self.hub.publish("ping.sample", ev)

    def _stats(self, tid: int, seconds: float) -> Dict[str, Any]:
        now = time.time()
        rows = [s for s in self.samples.get(tid, []) if s[0] >= now - seconds]
        sent = len(rows)
        oks = [s[2] for s in rows if s[1] and s[2] is not None]
        received = len(oks)
        lost = sent - received
        jit = None
        if len(oks) > 1:
            jit = sum(abs(oks[i] - oks[i - 1]) for i in range(1, len(oks))) / (len(oks) - 1)
        return {"seconds": int(seconds), "sent": sent, "received": received, "lost": lost,
                "loss_pct": round(100.0 * lost / sent, 2) if sent else 0.0,
                "avg_ms": round(sum(oks) / received, 2) if received else None,
                "min_ms": round(min(oks), 2) if received else None,
                "max_ms": round(max(oks), 2) if received else None,
                "jitter_ms": round(jit, 2) if jit is not None else None}

    def _light(self, t: Dict[str, Any]) -> str:
        # grey while paused, before the first sample, and for the gateway tile of a PC with no default gateway
        if self.paused or not self.samples.get(t["id"]) or (not t.get("resolved") and t["host"].lower() in GATEWAY_HOSTS):
            return "grey"
        th = self.settings["thresholds"]
        w = self._stats(t["id"], th["window_s"])
        if t["in_outage"] or w["loss_pct"] >= th["bad_loss_pct"]:
            return "red"
        warn = th["local_warn_ms"] if t["kind"] == "local" else th["internet_warn_ms"]
        if w["loss_pct"] >= th["warn_loss_pct"] or (w["avg_ms"] is not None and w["avg_ms"] > warn):
            return "yellow"
        return "green"

    def target_view(self, t: Dict[str, Any]) -> Dict[str, Any]:
        buf = self.samples.get(t["id"], [])
        last = buf[-1] if buf else None
        w = self._stats(t["id"], self.settings["thresholds"]["window_s"])
        # a plausible 24 h summary derived from the base RTT
        sent = int(min(86400, time.time() - self.started_ts))
        lost = int(sent * (0.0002 if t["kind"] == "local" else 0.004)) + (258 if t["id"] == 2 else 0)
        day = {"sent": sent, "received": sent - lost, "lost": lost,
               "loss_pct": round(100.0 * lost / sent, 2) if sent else 0.0,
               "avg_ms": round(t["base"] * 1.03, 2), "min_ms": round(t["base"] * 0.7, 2),
               "max_ms": round(t["base"] * 9.1 + 40, 2)}
        return {"id": t["id"], "host": t["host"], "label": t["label"], "kind": t["kind"], "ip": t["ip"],
                "enabled": t["enabled"], "resolved": t["resolved"], "resolve_error": t["resolve_error"],
                "light": self._light(t), "in_outage": t["in_outage"],
                "last": {"ts": last[0], "ok": last[1], "rtt_ms": last[2]} if last else None,
                "consecutive_missed": t["consecutive_missed"], "consecutive_ok": t["consecutive_ok"],
                "window": w, "day": day, "since_ts": t["since_ts"]}

    def targets_view(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [self.target_view(t) for t in self.targets]

    def add_target(self, host: str, label: Optional[str]) -> Dict[str, Any]:
        host = (host or "").strip()
        if not host or " " in host:
            raise ValueError("host is required and must not contain spaces")
        with self.lock:
            for t in self.targets:
                if t["host"].lower() == host.lower():
                    return self.target_view(t)
            is_ip = all(p.isdigit() for p in host.split(".")) and host.count(".") == 3
            kind = "local" if host.startswith(("10.", "192.168.", "172.")) else "internet"
            if host.lower() in ("nonexistent.invalid", "bad.example"):
                t = self._add_target(host, label, "internet", None, 40.0)
            else:
                ip = host if is_ip else "%d.%d.%d.%d" % tuple(self.rng.randint(1, 250) for _ in range(4))
                t = self._add_target(host, label, kind, ip, 1.0 if kind == "local" else 25.0 + self.rng.random() * 40)
            view = self.target_view(t)
            all_views = [self.target_view(x) for x in self.targets]
        self.hub.publish("ping.targets", {"targets": all_views})
        return view

    def remove_target(self, tid: int) -> bool:
        with self.lock:
            before = len(self.targets)
            self.targets = [t for t in self.targets if t["id"] != tid]
            self.samples.pop(tid, None)
            removed = len(self.targets) != before
            if removed:
                self.removed_targets[tid] = time.time()
            all_views = [self.target_view(x) for x in self.targets]
        if removed:
            self.hub.publish("ping.targets", {"targets": all_views})
        return removed

    def load_defaults(self) -> List[Dict[str, Any]]:
        # hard-coded like the real service: gateway, 1.1.1.1, totalelectronics.com; every other tile is
        # removed, the three come first in that order, and the gateway is resolved afresh from the
        # network the PC is on now (an existing gateway tile takes the new address)
        gw = net_profile(self.net_profile)["default_gateway"]
        wanted = [("gateway", "Gateway", "local", gw, 0.6), ("1.1.1.1", None, "internet", "1.1.1.1", 12.0),
                  ("totalelectronics.com", None, "internet", "203.0.113.80", 30.0)]
        keep = {w[0] for w in wanted}
        with self.lock:
            for t in list(self.targets):
                if t["host"].lower() not in keep:
                    self.targets.remove(t)
                    self.samples.pop(t["id"], None)
                    self.removed_targets[t["id"]] = time.time()
            hosts = {t["host"].lower() for t in self.targets}
            for host, label, kind, ip, base in wanted:
                if host.lower() not in hosts:
                    self._add_target(host, label, kind, ip, base)
            for t in self.targets:
                if t["host"].lower() in GATEWAY_HOSTS:
                    self._resolve_gateway(t, gw)
            order = [w[0] for w in wanted]
            self.targets.sort(key=lambda t: order.index(t["host"].lower()))
            views = [self.target_view(x) for x in self.targets]
        self.hub.publish("ping.targets", {"targets": views})
        return views

    def samples_view(self, tid: int, seconds: int) -> Optional[Dict[str, Any]]:
        with self.lock:
            if tid not in self.samples:
                return None
            now = time.time()
            rows = [[s[0], s[2] if s[1] else None] for s in self.samples[tid] if s[0] >= now - seconds]
            return {"target_id": tid, "samples": rows}

    def history_view(self, tid: int, start: float, end: float) -> Optional[Dict[str, Any]]:
        with self.lock:
            t = next((x for x in self.targets if x["id"] == tid), None)
            if not t:
                return None
            minutes = []
            m = int(start // 60 * 60)
            while m < end:
                rec = 60 - (1 if self.rng.random() < 0.05 else 0)
                minutes.append({"target_id": tid, "minute_ts": m, "sent": 60, "received": rec,
                                "avg_ms": round(t["base"] * (1 + self.rng.gauss(0, 0.05)), 2),
                                "min_ms": round(t["base"] * 0.8, 2), "max_ms": round(t["base"] * 2.2, 2),
                                "jitter_ms": round(t["base"] * 0.05, 2)})
                m += 60
            sent = sum(x["sent"] for x in minutes)
            rec = sum(x["received"] for x in minutes)
            return {"target_id": tid, "minutes": minutes,
                    "summary": {"sent": sent, "received": rec, "lost": sent - rec,
                                "loss_pct": round(100.0 * (sent - rec) / sent, 2) if sent else None,
                                "avg_ms": round(t["base"], 2), "min_ms": round(t["base"] * 0.8, 2),
                                "max_ms": round(t["base"] * 2.2, 2)}}

    # -- outages ---------------------------------------------------------
    @staticmethod
    def _missed_stats(o: Dict[str, Any], duration_s: float) -> Dict[str, Any]:
        """Same rules as tnt.outages.missed_percentage (kept standalone: the mock imports no tnt code)."""
        if o["kind"] != "target":
            return {"sent": None, "missed_pct": None, "sent_estimated": False}
        missed = int(o.get("missed") or 0)
        sent = o.get("sent")
        estimated = not sent
        if estimated:
            sent = max(missed, int(round(max(0.0, duration_s))))
        sent = max(int(sent), missed)
        pct = round(100.0 * missed / sent, 2) if sent else None
        return {"sent": sent or None, "missed_pct": pct, "sent_estimated": estimated}

    def _outage_view(self, o: Dict[str, Any]) -> Dict[str, Any]:
        now = time.time()
        host = None
        if o["target_id"] is not None:
            t = next((x for x in self.targets if x["id"] == o["target_id"]), None)
            host = t["host"] if t else f"target {o['target_id']}"
        end = o["end_ts"] if o["end_ts"] is not None else now
        duration = round(end - o["start_ts"], 1)
        return dict(o, host=host, duration_s=duration, open=o["end_ts"] is None, **self._missed_stats(o, duration))

    def outages_status(self) -> Dict[str, Any]:
        with self.lock:
            now = time.time()
            active = [self._outage_view(o) for o in self.outages if o["end_ts"] is None]
            total_active = next((o for o in active if o["kind"].startswith("total")), None)
            recent = [o for o in self.outages if o["kind"] != "gap" and (o["end_ts"] or now) >= now - 86400]
            last = max(recent, key=lambda o: o["start_ts"]) if recent else None
            return {"active": active, "total_active": total_active, "count_24h": len(recent),
                    "last": self._outage_view(last) if last else None, "monitoring": not self.paused}

    def outages_list(self, start: float, end: float) -> List[Dict[str, Any]]:
        with self.lock:
            rows = [self._outage_view(o) for o in self.outages
                    if o["start_ts"] <= end and (o["end_ts"] is None or o["end_ts"] >= start)]
            rows.sort(key=lambda o: o["start_ts"], reverse=True)
            return rows

    def timeline(self, hours: float) -> Dict[str, Any]:
        with self.lock:
            now = time.time()
            start = now - hours * 3600
            segs, totals, gaps = [], [], []
            for o in self.outages:
                end = o["end_ts"] if o["end_ts"] is not None else now
                if end < start or o["start_ts"] > now:
                    continue
                s = {"id": o["id"], "kind": o["kind"], "target_id": o["target_id"],
                     "host": self._outage_view(o)["host"], "start_ts": max(start, o["start_ts"]),
                     "end_ts": min(now, end), "open": o["end_ts"] is None, "missed": o["missed"],
                     **self._missed_stats(o, end - o["start_ts"])}
                if o["kind"] == "gap":
                    gaps.append({"start_ts": s["start_ts"], "end_ts": s["end_ts"]})
                elif o["kind"].startswith("total"):
                    totals.append(s)
                else:
                    segs.append(s)
            return {"start_ts": start, "end_ts": now, "hours": hours, "segments": segs, "total_segments": totals,
                    "gaps": gaps, "targets": [{"id": t["id"], "host": t["host"], "kind": t["kind"]} for t in self.targets]}

    # -- speed -----------------------------------------------------------
    def speed_status(self) -> Dict[str, Any]:
        with self.lock:
            last = self.speedtests[-1] if self.speedtests else None
            backend = self.settings["speedtest"]["backend"]
            return {"enabled": self.settings["speedtest"]["enabled"], "running": self.speed_running,
                    "next_run_ts": self.speed_next_ts, "last": dict(last, raw={}) if last else None,
                    "backend": "cloudflare" if backend == "auto" else backend,
                    "interval_min": self.settings["speedtest"]["interval_min"], "progress": dict(self.speed_progress)}

    def speed_history(self, start: float, end: float, limit: Optional[int]) -> List[Dict[str, Any]]:
        with self.lock:
            rows = [r for r in self.speedtests if start <= r["ts"] < end]
            rows.sort(key=lambda r: r["ts"], reverse=True)
            return rows[:limit] if limit else rows

    def speed_run(self) -> bool:
        with self.lock:
            if self.speed_running:
                return False
            self.speed_running = True
            self.speed_progress = {"phase": "latency", "pct": 0.0}
        threading.Thread(target=self._speed_worker, name="mock-speed", daemon=True).start()
        return True

    def speed_tick(self) -> None:
        """Run the scheduled test when it falls due (like the real SpeedScheduler)."""
        with self.lock:
            due = (self.settings["speedtest"]["enabled"] and not self.speed_running
                   and time.time() >= self.speed_next_ts)
            if not due:
                if not self.settings["speedtest"]["enabled"] and self.speed_next_ts < time.time():
                    # keep the countdown sane while automatic tests are switched off
                    self.speed_next_ts = time.time() + self.settings["speedtest"]["interval_min"] * 60
                return
        self.speed_run()

    def _speed_worker(self) -> None:
        self.hub.publish("speedtest.start", {"backend": "cloudflare"})
        phases = [("latency", 1.2), ("download", 3.0), ("upload", 2.6)]
        try:
            for phase, dur in phases:
                t0 = time.time()
                while time.time() - t0 < dur:
                    pct = min(1.0, (time.time() - t0) / dur)
                    with self.lock:
                        self.speed_progress = {"phase": phase, "pct": round(pct, 3)}
                    self.hub.publish("speedtest.progress", {"phase": phase, "pct": round(pct, 3)})
                    time.sleep(0.15)
            with self.lock:
                res = self._make_speed(time.time())
                self.speedtests.append(res)
                self.speed_running = False
                self.speed_progress = {"phase": "done", "pct": 1.0}
                self.speed_next_ts = time.time() + self.settings["speedtest"]["interval_min"] * 60
            self.hub.publish("speedtest.done", {"result": dict(res, raw={})})
        except Exception:  # noqa: BLE001
            log.exception("speed worker failed")
            with self.lock:
                self.speed_running = False

    def patterns(self, days: int) -> Dict[str, Any]:
        with self.lock:
            now = time.time()
            rows = [r for r in self.speedtests if r["ts"] >= now - days * 86400]
            ok = [r for r in rows if r["ok"]]
            downs = sorted(r["download_mbps"] for r in ok)
            ups = sorted(r["upload_mbps"] for r in ok)

            def median(xs: List[float]) -> Optional[float]:
                if not xs:
                    return None
                n = len(xs)
                return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2

            md, mu = median(downs), median(ups)
            by_hour = []
            for h in range(24):
                hs = [r for r in ok if local_hour(r["ts"]) == h]
                by_hour.append({"hour": h, "count": len(hs),
                                "avg_down": round(sum(r["download_mbps"] for r in hs) / len(hs), 1) if hs else None,
                                "avg_up": round(sum(r["upload_mbps"] for r in hs) / len(hs), 1) if hs else None,
                                "avg_latency": round(sum(r["latency_ms"] for r in hs) / len(hs), 1) if hs else None})
            by_wd = []
            for wd in range(7):
                ws = [r for r in ok if local_weekday(r["ts"]) == wd]
                by_wd.append({"weekday": wd, "count": len(ws),
                              "avg_down": round(sum(r["download_mbps"] for r in ws) / len(ws), 1) if ws else None})
            warn = self.settings["speedtest"]["warn_below_pct"]
            slow = [{"ts": r["ts"], "download_mbps": r["download_mbps"],
                     "pct_of_median": round(100.0 * r["download_mbps"] / md, 1)}
                    for r in ok if md and r["download_mbps"] < md * warn / 100.0]
            findings = []
            if md:
                ev = [b for b in by_hour if 19 <= b["hour"] < 22 and b["avg_down"]]
                if ev:
                    avg_ev = sum(b["avg_down"] for b in ev) / len(ev)
                    findings.append("Downloads are ~%d%% slower between 19:00 and 22:00" % round(100 * (1 - avg_ev / md)))
            fails = len(rows) - len(ok)
            if fails:
                findings.append("%d test%s failed in the last %d days" % (fails, "" if fails == 1 else "s", days))
            if md and mu and md / mu > 3:
                findings.append("Upload is much slower than download (%.0f vs %.0f Mbps) - typical for cable" % (mu, md))
            if ok:
                lat = sorted(r["latency_ms"] for r in ok)
                if lat[-1] > 3 * median(lat):
                    findings.append("Latency spiked to %.0f ms at least once (median %.0f ms)" % (lat[-1], median(lat)))
            mn = min(ok, key=lambda r: r["download_mbps"]) if ok else None
            mx = max(ok, key=lambda r: r["download_mbps"]) if ok else None
            return {"days": days, "count": len(rows), "ok_count": len(ok), "median_down": md, "median_up": mu,
                    "avg_down": round(sum(downs) / len(downs), 1) if downs else None,
                    "avg_up": round(sum(ups) / len(ups), 1) if ups else None,
                    "min_down": {"value": mn["download_mbps"], "ts": mn["ts"]} if mn else None,
                    "max_down": {"value": mx["download_mbps"], "ts": mx["ts"]} if mx else None,
                    "by_hour": by_hour, "by_weekday": by_wd, "slow_tests": slow[-20:], "findings": findings,
                    "trend_down_pct_per_day": -0.4}

    # -- discovery -------------------------------------------------------
    def _disc_last_summary(self) -> Optional[Dict[str, Any]]:
        """The newest run as the service summarises it (engine._run_summary)."""
        if not self.disc_runs:
            return None
        run = max(self.disc_runs, key=lambda r: r["ts"])
        return {k: run[k] for k in ("id", "ts", "cidr", "found", "duration_s", "ok", "error")}

    def disc_status(self) -> Dict[str, Any]:
        """Same keys as the service's engine.discovery_status(); the default range follows the network."""
        with self.lock:
            return {"available": True, "running": self.disc_running, "progress": dict(self.disc_progress),
                    "range": self.disc_range, "ports": list(self.disc_ports),
                    "started_ts": self.disc_started_ts if self.disc_running else None,
                    "last_run": self._disc_last_summary(), "default_range": net_profile(self.net_profile)["default_range"],
                    "default_ports": list(self.settings["discovery"]["ports"])}

    def disc_start(self, rng_text: Optional[str], ports: Optional[List[int]]) -> Dict[str, Any]:
        rng_text = (rng_text or "").strip() or net_profile(self.net_profile)["default_range"] or ""
        if not rng_text:
            raise ValueError("this PC has no IPv4 network to scan right now: type a range")
        if "/" not in rng_text and "-" not in rng_text and rng_text.count(".") != 3:
            raise ValueError("range must be a CIDR (10.0.0.0/24), a range (10.0.0.1-10.0.0.50) or a single IP")
        ports = [int(p) for p in (ports or self.settings["discovery"]["ports"])]
        with self.lock:
            if self.disc_running:
                raise RuntimeError("scan already running")
            self.disc_running = True
            self.disc_net_changed = False
            self.disc_cancel.clear()
            self.disc_started_ts = time.time()
            self.disc_range, self.disc_ports = rng_text, list(ports)
            self.disc_progress = {"phase": "ping", "done": 0, "total": 254, "found": 0, "elapsed_s": 0.0}
        threading.Thread(target=self._disc_worker, args=(rng_text, ports), name="mock-disc", daemon=True).start()
        return {"started": True, "range": rng_text, "ports": ports}

    def disc_cancel_scan(self) -> bool:
        self.disc_cancel.set()
        return True

    def _disc_worker(self, cidr: str, ports: List[int]) -> None:
        t0 = time.time()
        total = 254
        hosts = self._build_hosts(drop=self.rng.choice([0, 1]))
        if cidr.endswith("/24") and not cidr.startswith("10.0.0."):
            # the fake devices live on whichever /24 was scanned (the network the PC moved to, say)
            base = cidr.rsplit(".", 1)[0]
            hosts = [dict(host, ip=base + "." + host["ip"].rsplit(".", 1)[1]) for host in hosts]
        phases = [("ping", 2.0, total), ("ports", 1.4, total * len(ports)), ("arp", 0.2, 1), ("resolve", 0.4, len(hosts))]
        cancelled = False
        try:
            for phase, dur, ptotal in phases:
                p0 = time.time()
                while time.time() - p0 < dur:
                    if self.disc_cancel.is_set():
                        cancelled = True
                        break
                    frac = min(1.0, (time.time() - p0) / dur)
                    found = int(len(hosts) * min(1.0, frac if phase == "ping" else 1.0))
                    prog = {"phase": phase, "done": int(ptotal * frac), "total": ptotal, "found": found,
                            "elapsed_s": round(time.time() - t0, 1)}
                    with self.lock:
                        self.disc_progress = prog
                    self.hub.publish("discovery.progress", prog)
                    time.sleep(0.1)
                if cancelled:
                    break
            with self.lock:
                run = self._add_disc_run(time.time(), cidr, ports, round(time.time() - t0, 1),
                                         hosts=hosts[: (len(hosts) // 2 if cancelled else len(hosts))], cancelled=cancelled)
                self.disc_running = False
                self.disc_progress = {"phase": "done", "done": total, "total": total, "found": run["found"],
                                      "elapsed_s": round(time.time() - t0, 1)}
                net_changed, self.disc_net_changed = self.disc_net_changed, False
            self.hub.publish("discovery.progress", self.disc_progress)
            # network_changed: the PC changed networks during the scan (tnt.engine marks discovery.done the same way)
            self.hub.publish("discovery.done", {"run_id": run["id"], "cancelled": cancelled, "found": run["found"],
                                                "network_changed": net_changed})
        except Exception:  # noqa: BLE001
            log.exception("discovery worker failed")
            with self.lock:
                self.disc_running = False

    def disc_runs_view(self, limit: int) -> List[Dict[str, Any]]:
        with self.lock:
            runs = sorted(self.disc_runs, key=lambda r: r["ts"], reverse=True)[:limit]
            return [{k: v for k, v in r.items() if k != "hosts"} for r in runs]

    def disc_run(self, rid: int) -> Optional[Dict[str, Any]]:
        with self.lock:
            r = next((x for x in self.disc_runs if x["id"] == rid), None)
            return copy.deepcopy(r) if r else None

    def disc_last(self) -> Optional[Dict[str, Any]]:
        with self.lock:
            if not self.disc_runs:
                return None
            return copy.deepcopy(max(self.disc_runs, key=lambda r: r["ts"]))

    # -- DHCP server (Tools) ---------------------------------------------
    def _dhcp_adapters(self) -> List[Dict[str, Any]]:
        """The adapter picker's candidates: DHCP_ADAPTERS on network "a" (what the DHCP tests know), else the up
        adapters with an IPv4 address of the network the fake PC moved to (NET_PROFILE_NAMES)."""
        if self.net_profile == "a":
            return DHCP_ADAPTERS
        prof = net_profile(self.net_profile)
        out = []
        for a in prof["adapters"]:
            if a["status"] != "up" or not a["ipv4"]:
                continue
            first = a["ipv4"][0]
            out.append({"name": a["name"], "index": a["index"], "mac": a["mac"], "ip": first["address"], "prefix": first["prefix"],
                        "mask": first["netmask"], "dhcp_enabled": a["dhcp_enabled"], "dhcp_server": a["dhcp_server"],
                        "gateway": (a["gateways"] or [None])[0], "is_physical": a["is_physical"], "type_name": a["type_name"],
                        "status": a["status"], "is_internet": a["index"] == prof["internet_nic_index"]})
        return out

    def _dhcp_adapter(self) -> Optional[Dict[str, Any]]:
        """settings.adapter by name, else auto = the first physical Ethernet (else the first candidate)."""
        adapters = self._dhcp_adapters()
        name = self.settings["dhcp"].get("adapter") or ""
        if name:
            for a in adapters:
                if a["name"].lower() == name.lower():
                    return a
        return next((a for a in adapters if a["is_physical"] and a["type_name"] == "Ethernet"), adapters[0] if adapters else None)

    def _dhcp_server_ip(self, adapter: Dict[str, Any]) -> tuple:
        """(server_ip, prefix): the static address when the NIC is on DHCP, else its own."""
        cfg = self.settings["dhcp"]
        if adapter["dhcp_enabled"]:
            return cfg["static_ip"], int(cfg["static_prefix"])
        return adapter["ip"], int(adapter["prefix"])

    @staticmethod
    def _dhcp_default_pool(server_ip: str, prefix: int, size: int, exclude: List[str]) -> tuple:
        net = ip2int(server_ip) & (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        bcast = net | ((1 << (32 - prefix)) - 1)
        skip = {ip2int(server_ip), net, bcast} | {ip2int(x) for x in exclude if x}
        after = [n for n in range(ip2int(server_ip) + 1, bcast) if n not in skip][:size]
        if len(after) < size:
            before = [n for n in range(ip2int(server_ip) - 1, net, -1) if n not in skip][: size - len(after)]
            after = sorted(before) + after
        if len(after) < size:
            raise ValueError(f"the subnet /{prefix} cannot hold {size} addresses")
        return int2ip(after[0]), int2ip(after[-1])

    @staticmethod
    def _dhcp_validate_pool(start: str, end: str, server_ip: str, prefix: int, gateway: Optional[str]) -> tuple:
        s, e = ip2int(start), ip2int(end)
        net = ip2int(server_ip) & (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        bcast = net | ((1 << (32 - prefix)) - 1)
        if s > e:
            raise ValueError("pool start must not be after pool end")
        if not (net < s and e < bcast):
            raise ValueError(f"the pool must lie inside {int2ip(net)}/{prefix} (excluding network and broadcast)")
        if e - s + 1 > 250:
            raise ValueError("the pool may hold at most 250 addresses")
        for label, ip in (("the server address", server_ip), ("the gateway", gateway)):
            if ip and s <= ip2int(ip) <= e:
                raise ValueError(f"the pool must not contain {label} {ip}")
        return start, end

    def _dhcp_pool(self, adapter: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.settings["dhcp"]
        server_ip, prefix = self._dhcp_server_ip(adapter)
        if cfg["pool_start"] and cfg["pool_end"]:
            start, end = cfg["pool_start"], cfg["pool_end"]
            return {"start": start, "end": end, "size": ip2int(end) - ip2int(start) + 1, "auto": False}
        start, end = self._dhcp_default_pool(server_ip, prefix, int(cfg["pool_size"]), [adapter.get("gateway") or ""])
        return {"start": start, "end": end, "size": int(cfg["pool_size"]), "auto": True}

    def dhcp_summary(self) -> Dict[str, Any]:
        with self.lock:
            a = self._dhcp_adapter()
            try:
                pool = self._dhcp_pool(a) if a else None
            except ValueError:
                pool = None
            server_ip = self._dhcp_server_ip(a)[0] if a else None
            return {"available": True, "running": self.dhcp_running, "adapter": a["name"] if a else None,
                    "server_ip": server_ip, "pool": {k: pool[k] for k in ("start", "end", "size")} if pool else None,
                    "bound": sum(1 for c in self.dhcp_clients if c["state"] == "bound"),
                    "offered": sum(1 for c in self.dhcp_clients if c["state"] == "offered"),
                    "since_ts": self.dhcp_since, "error": self.dhcp_error}

    def dhcp_status(self) -> Dict[str, Any]:
        with self.lock:
            cfg = self.settings["dhcp"]
            a = self._dhcp_adapter()
            server_ip, prefix = self._dhcp_server_ip(a)
            error = self.dhcp_error
            try:
                pool = self._dhcp_pool(a)
            except ValueError as exc:
                pool, error = {"start": None, "end": None, "size": 0, "auto": True}, str(exc)
            adapter = {k: a[k] for k in ("name", "index", "mac", "ip", "prefix", "mask", "dhcp_enabled", "gateway", "is_physical", "type_name",
                                         "is_internet")}
            adapter.update({"will_change": bool(a["dhcp_enabled"]) and not self.dhcp_changed, "changed": self.dhcp_changed,
                            "static_ip": cfg["static_ip"], "static_prefix": int(cfg["static_prefix"])})
            if self.dhcp_changed:
                adapter["ip"], adapter["prefix"], adapter["mask"] = cfg["static_ip"], int(cfg["static_prefix"]), "255.255.255.0"
            clients = copy.deepcopy(self.dhcp_clients)
            return {"available": True, "running": self.dhcp_running, "since_ts": self.dhcp_since, "error": error,
                    "warning": self.dhcp_warning, "adapter": adapter,
                    "adapters": [{k: x[k] for k in ("name", "index", "ip", "prefix", "dhcp_enabled", "is_physical", "type_name", "status",
                                                    "is_internet")}
                                 for x in self._dhcp_adapters()],
                    "server_ip": server_ip, "pool": pool, "lease_s": int(cfg["lease_s"]), "gateway": server_ip, "dns": [],
                    "ping_check": bool(cfg["ping_check"]), "clients": clients,
                    "counts": {"bound": sum(1 for c in clients if c["state"] == "bound"),
                               "offered": sum(1 for c in clients if c["state"] == "offered"), "total": len(clients)},
                    "scan": copy.deepcopy(self.dhcp_last_scan),
                    "firewall": {"rule": DHCP_FIREWALL_RULE, "ok": True if self.dhcp_running else None, "error": None},
                    "settings": copy.deepcopy(cfg)}

    def dhcp_leases(self) -> List[Dict[str, Any]]:
        with self.lock:
            return copy.deepcopy(self.dhcp_clients)

    def dhcp_scan(self, wait_s: Optional[float] = None) -> Dict[str, Any]:
        """Relay-style probe on every adapter; the mock waits a shortened time then answers."""
        wait = float(wait_s) if wait_s is not None else float(self.settings["dhcp"]["scan_wait_s"])
        wait = max(0.0, min(30.0, wait))
        t0 = time.time()
        time.sleep(0.05 if self.dhcp_fast else min(wait, 1.5))
        with self.lock:
            servers: List[Dict[str, Any]] = []
            adapters = self._dhcp_adapters()
            if not self.dhcp_force_none:
                # the network's own DHCP server answers on each DHCP-configured adapter that has one (network "a": Ethernet)
                for a in adapters:
                    if a["dhcp_enabled"] and a["dhcp_server"]:
                        servers.append({"adapter": a["name"], "nic_ip": a["ip"], "server_ip": a["dhcp_server"], "source_ip": a["dhcp_server"],
                                        "offered_ip": a["ip"].rsplit(".", 1)[0] + ".191", "lease_s": 86400, "router": a["gateway"],
                                        "mask": a["mask"], "dns": [a["dhcp_server"]], "known": True, "answered": True})
            scan = {"ts": time.time(), "duration_s": round(time.time() - t0, 2), "wait_s": wait, "servers": servers,
                    "probed": [{"adapter": a["name"], "ip": a["ip"]} for a in adapters if a["prefix"] < 32],
                    "errors": [] if self.dhcp_force_none else ["Tailscale: not probed (a /32 tunnel has no broadcast domain)"]}
            self.dhcp_last_scan = scan
        self.hub.publish("dhcp.scan", scan)
        return copy.deepcopy(scan)

    def dhcp_start(self, force: bool = False) -> Dict[str, Any]:
        with self.lock:
            if self.dhcp_running:
                return self.dhcp_status()
        if not force:
            scan = self.dhcp_scan()
            if scan["servers"]:
                raise DhcpConflict(scan["servers"], scan)
        with self.lock:
            a = self._dhcp_adapter()
            self.dhcp_changed = bool(a["dhcp_enabled"])
            self.dhcp_running = True
            self.dhcp_since = time.time()
            self.dhcp_error = None
            self.dhcp_warning = None
            self.dhcp_gen += 1
            gen = self.dhcp_gen
            pool = self._dhcp_pool(a)
            fast = self.dhcp_fast
            st = self.dhcp_status()
        self.hub.publish("dhcp.state", dict(self.dhcp_summary(), running=True))
        threading.Thread(target=self._dhcp_worker, args=(gen, pool, fast), name="mock-dhcp", daemon=True).start()
        return st

    def dhcp_stop(self) -> Dict[str, Any]:
        with self.lock:
            self.dhcp_running = False
            self.dhcp_since = None
            self.dhcp_changed = False
            self.dhcp_gen += 1
            st = self.dhcp_status()
        self.hub.publish("dhcp.state", dict(self.dhcp_summary(), running=False))
        return st

    def _dhcp_worker(self, gen: int, pool: Dict[str, Any], fast: bool) -> None:
        """Three devices ask for an address over ~8 s (offered -> bound), each probed a second later."""
        try:
            delays = [0.15, 0.3, 0.45] if fast else [2.0, 3.0, 3.0]
            probe_delay = 0.15 if fast else 1.0
            lease_s = int(self.settings["dhcp"]["lease_s"])
            base = ip2int(pool["start"])
            for i, (mac, host, vendor, rtt, ports) in enumerate(DHCP_FAKE_CLIENTS):
                time.sleep(delays[i])
                with self.lock:
                    if self.dhcp_gen != gen:
                        return
                    ip = int2ip(base + i)
                    now = time.time()
                    existing = next((c for c in self.dhcp_clients if c["mac"] == mac), None)
                    lease = existing or {"ip": ip, "mac": mac, "hostname": host, "vendor": vendor, "ping_ok": None, "rtt_ms": None,
                                         "open_ports": [], "client_id": "01" + mac.replace(":", "").lower(), "first_ts": now,
                                         "probed_ts": None, "probing": False}
                    lease.update({"ip": ip, "state": "offered", "last_ts": now, "expires_ts": now + 45, "probing": False})
                    if not existing:
                        self.dhcp_clients.append(lease)
                    snap = copy.deepcopy(lease)
                self.hub.publish("dhcp.lease", {"lease": snap})
                time.sleep(0.1 if fast else 0.6)
                with self.lock:
                    if self.dhcp_gen != gen:
                        return
                    now = time.time()
                    lease.update({"state": "bound", "last_ts": now, "expires_ts": now + lease_s, "probing": True})
                    snap = copy.deepcopy(lease)
                self.hub.publish("dhcp.lease", {"lease": snap})
                time.sleep(probe_delay)
                with self.lock:
                    if self.dhcp_gen != gen:
                        return
                    lease.update({"ping_ok": True, "rtt_ms": round(rtt * (1 + self.rng.gauss(0, 0.1)), 2), "open_ports": list(ports),
                                  "probed_ts": time.time(), "probing": False})
                    snap = copy.deepcopy(lease)
                self.hub.publish("dhcp.lease", {"lease": snap})
        except Exception:  # noqa: BLE001
            log.exception("dhcp worker failed")

    def dhcp_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(patch, dict):
            raise ValueError("settings patch must be an object")
        with self.lock:
            cfg = copy.deepcopy(self.settings["dhcp"])
            if "adapter" in patch:
                name = str(patch["adapter"] or "").strip()
                if name and not any(a["name"].lower() == name.lower() for a in self._dhcp_adapters()):
                    raise ValueError(f"unknown adapter {name!r}")
                cfg["adapter"] = name
            if "pool_size" in patch:
                cfg["pool_size"] = max(1, min(250, int(patch["pool_size"])))
            if "lease_s" in patch:
                lease = int(patch["lease_s"])
                if not 120 <= lease <= 604800:
                    raise ValueError("lease_s must be between 120 and 604800 seconds")
                cfg["lease_s"] = lease
            if "ping_check" in patch:
                cfg["ping_check"] = bool(patch["ping_check"])
            start = str(patch.get("pool_start", cfg["pool_start"]) or "").strip()
            end = str(patch.get("pool_end", cfg["pool_end"]) or "").strip()
            if bool(start) != bool(end):
                raise ValueError("give both pool_start and pool_end, or neither for an automatic pool")
            old = self.settings["dhcp"]
            self.settings["dhcp"] = cfg          # the adapter choice affects the subnet the pool is checked against
            try:
                a = self._dhcp_adapter()
                server_ip, prefix = self._dhcp_server_ip(a)
                if start:
                    self._dhcp_validate_pool(start, end, server_ip, prefix, a.get("gateway"))
                cfg["pool_start"], cfg["pool_end"] = start, end
                self._dhcp_pool(a)               # the automatic pool must fit too
            except ValueError:
                self.settings["dhcp"] = old
                raise
            st = self.dhcp_status()
        self.hub.publish("settings.changed", {"changed": ["dhcp"]})
        if st["running"]:
            self.hub.publish("dhcp.state", dict(self.dhcp_summary(), running=True))
        return st

    def dhcp_forget(self, mac: str) -> bool:
        mac = (mac or "").strip().upper()
        with self.lock:
            before = len(self.dhcp_clients)
            self.dhcp_clients = [c for c in self.dhcp_clients if c["mac"].upper() != mac]
            removed = len(self.dhcp_clients) != before
        if removed:
            # same stub the real server sends: the UI drops the row instead of replacing it
            self.hub.publish("dhcp.lease", {"lease": {"mac": mac, "state": "forgotten"}})
            self.hub.publish("dhcp.state", self.dhcp_summary())
        return removed

    # -- IP location (tnt.geoip) -----------------------------------------
    def _geoip_enabled(self) -> bool:
        with self.lock:
            return bool((self.settings.get("geoip") or {}).get("enabled", True))

    def geoip_status(self) -> Dict[str, Any]:
        """status.geoip / GET /api/geoip, shaped like tnt.geoip.GeoIpManager.status() (exactly GEOIP_STATUS_KEYS) for
        ``geoip_state``; the disabled shape as soon as the setting is off."""
        with self.lock:
            st: Dict[str, Any] = dict.fromkeys(GEOIP_STATUS_KEYS)
            if not self._geoip_enabled():
                st.update(enabled=False, state="disabled", available=False)
                return st
            now = time.time()
            state = self.geoip_state
            st.update(enabled=True, state=state, available=False)
            if state == "ready":
                y, m = time.gmtime(now)[:2]
                # 03:00 UTC on the 1st of next month (tnt.geoip.MONTHLY_CHECK_OFFSET_S, without the jitter)
                nxt = calendar.timegm((y + (m == 12), m % 12 + 1, 1, 3, 0, 0))
                st.update(available=True, month=self.geoip_month, bytes=GEOIP_CITY_BYTES + GEOIP_ASN_BYTES,
                          installed_ts=self.started_ts - 3 * 86400, checked_ts=self.started_ts, next_check_ts=float(nxt))
            elif state == "downloading":
                st["download"] = {"month": self.geoip_month, "file": "city", "phase": "download", "received": 25000000,
                                  "total": 60287600}
            elif state == "error":
                st.update(error=self.geoip_error, checked_ts=self.started_ts, next_check_ts=now + 60)
            else:                                   # starting: the first check waits FIRST_CHECK_DELAY_S after the start
                st["next_check_ts"] = self.started_ts + 30
            return st

    def geoip_lookup(self, ip: Any) -> Optional[Dict[str, Any]]:
        """The GEO of an address (exactly GEOIP_GEO_KEYS) like tnt.geoip.GeoIpManager.lookup, or None: off, no data,
        a skipped address or nothing known."""
        with self.lock:
            if not self._geoip_enabled() or self.geoip_state != "ready":
                return None
            month = self.geoip_month
        addr = geoip_address(ip)
        if addr is None or geoip_skipped(addr) or str(addr) not in MOCK_GEO:
            return None
        return dict(copy.deepcopy(MOCK_GEO[str(addr)]), ip=str(addr), month=month)

    def _hop_location(self, ip: Optional[str], hostname: Optional[str], kind: str) -> Optional[Dict[str, Any]]:
        """A traceroute hop's ``location`` like tnt.geoip.GeoIpManager.locate_hop (exactly GEOIP_LOCATION_KEYS), or None.
        The router name wins over the database (MOCK_HOST_HINTS stands in for tnt.geohints and its speed-of-light
        guard); a destination hop takes no generic-tier hint."""
        addr = geoip_address(ip) if ip is not None else None
        if addr is None or geoip_skipped(addr):
            return None
        with self.lock:
            if not self._geoip_enabled() or self.geoip_state != "ready":
                return None
        geo = self.geoip_lookup(ip)
        db_text = geo["place"] if geo else None
        hint = MOCK_HOST_HINTS.get(hostname) if hostname and kind != "destination" else None
        if hint:
            text, source, code = hint[1], "hostname", hint[0]
        elif db_text:
            text, source, code = db_text, "database", None
        else:
            text, source, code = None, None, None
        asn = geo["asn"] if geo else None
        if text is None and asn is None:
            return None
        return {"text": text, "source": source, "hint": code, "db_text": db_text, "asn": asn, "as_org": geo["as_org"] if geo else None}

    def geoip_check(self) -> Optional[Dict[str, Any]]:
        """POST /api/geoip/check (Retry now): a failed download starts over (``geoip.state``); None while switched off."""
        with self.lock:
            if not self._geoip_enabled():
                return None
            retry = self.geoip_state == "error"
            if retry:
                self.geoip_state = "starting"
            status = self.geoip_status()
        if retry:
            self.hub.publish("geoip.state", status)
        return status

    def geoip_set_state(self, state: str) -> str:
        """POST /mock/geoip: move the fake manager to another GEOIP_STATES state (not "disabled": that is the setting)."""
        if state not in GEOIP_STATES[1:]:
            raise ValueError(f"unknown IP location state {state!r}; one of: {', '.join(GEOIP_STATES[1:])}")
        with self.lock:
            self.geoip_state = state
            status = self.geoip_status()
        self.hub.publish("geoip.state", status)
        return state

    # -- Tools: traceroute -----------------------------------------------
    @staticmethod
    def _hop_stats(rtts: List[Optional[float]]) -> Dict[str, Any]:
        ok = [r for r in rtts if r is not None]
        return {"rtts": rtts, "avg_ms": round(sum(ok) / len(ok), 2) if ok else None,
                "min_ms": round(min(ok), 2) if ok else None, "max_ms": round(max(ok), 2) if ok else None,
                "loss": len(rtts) - len(ok)}

    def _on_local_subnet(self, ip: str) -> bool:
        """Whether an IPv4 address is on the subnet of one of the fake PC's up adapters (a one-hop trace)."""
        addr = ip2int(ip)
        return any(a["status"] == "up" and addr & ip2int(e["netmask"]) == ip2int(e["address"]) & ip2int(e["netmask"])
                   for a in net_profile(self.net_profile)["adapters"] for e in a["ipv4"])

    def _trace_hops(self, host: str, target_ip: str, probes: int, resolve: bool) -> List[Dict[str, Any]]:
        """The fake path: one hop straight to an address on one of the PC's subnets, else the 9-hop internet
        route through the current default gateway."""
        rng = self.rng
        gw = net_profile(self.net_profile)["default_gateway"]
        if self._on_local_subnet(target_ip):
            base = 0.6 if target_ip == gw else 1.2
            rtts = [round(max(0.2, base * (1 + rng.gauss(0, 0.15))), 2) for _ in range(probes)]
            name = host if resolve and host != target_ip else None
            return [dict(ttl=1, ip=target_ip, alt_ips=[], hostname=name, responder_status=0, kind="destination", label="Destination",
                         **self._hop_stats(rtts), location=self._hop_location(target_ip, name, "destination"))]
        hops = []
        for i, (ip, hn, kind, label, base, lost) in enumerate(TRACE_PATH, start=1):
            if ip is None:
                rtts: List[Optional[float]] = [None] * probes
            else:
                rtts = [round(max(0.2, base * (1 + rng.gauss(0, 0.08))), 2) for _ in range(probes)]
                for k in range(min(lost, probes)):
                    rtts[(k * 2 + 1) % probes] = None
            if kind == "gateway":
                ip = gw                     # the first hop is whatever router the PC uses now
            if kind == "destination":
                ip, hn = target_ip, (host if host != target_ip else None)
            name = hn if resolve else None
            # the location is the final one: the service's live trace.hop may still lack the router-name hint
            hops.append(dict(ttl=i, ip=ip, alt_ips=[], hostname=name,
                             responder_status=(None if ip is None else 3 if kind == "destination" else 11),
                             kind=kind, label=label, **self._hop_stats(rtts), location=self._hop_location(ip, name, kind)))
        return hops

    def traceroute(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronous like the service: the hops are published one by one while the request waits."""
        host = str(body.get("host") or "").strip()
        if not host or " " in host:
            raise ValueError("host is required and must not contain spaces")
        try:
            max_hops = max(1, min(64, int(body.get("max_hops") or 30)))
            probes = max(1, min(5, int(body.get("probes") or 3)))
            timeout_ms = max(100, min(10000, int(body.get("timeout_ms") or 1500)))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"bad option: {exc}") from exc
        resolve = bool(body.get("resolve_names", True))
        if host.lower() in ("nonexistent.invalid", "bad.example") or host.endswith(".invalid"):
            raise ValueError(f"could not resolve {host}")
        is_ip = host.count(".") == 3 and all(p.isdigit() for p in host.split("."))
        prof = net_profile(self.net_profile)
        gw, nic = prof["default_gateway"], net_internet_nic(prof)
        if host.lower() in GATEWAY_HOSTS and gw is None:
            raise ValueError("this PC has no default gateway right now")
        target_ip = host if is_ip else (gw if host.lower() in GATEWAY_HOSTS else "203.0.113.80")
        if gw is None and not self._on_local_subnet(target_ip):
            raise ValueError(f"no route to {host}: this PC has no default gateway right now")
        pc_ip = nic["ipv4"][0]["address"] if nic and nic["ipv4"] else None
        with self.lock:
            if self.trace_running:
                raise RuntimeError("a traceroute is already running")
            self.trace_running = True
            fast = self.trace_fast
        t0 = time.time()
        try:
            self.hub.publish("trace.start", {"host": host, "target_ip": target_ip, "max_hops": max_hops, "probes": probes})
            path = self._trace_hops(host, target_ip, probes, resolve)
            hops: List[Dict[str, Any]] = []
            complete = False
            for hop in path:
                if len(hops) >= max_hops:
                    break
                time.sleep(0.01 if fast else (0.3 + (0.4 if hop["ip"] is None else 0.0)))
                hops.append(hop)
                self.hub.publish("trace.hop", {"host": host, "target_ip": target_ip, "hop": copy.deepcopy(hop)})
                if hop["kind"] == "destination":
                    complete = True
            trace = {"host": host, "target_ip": target_ip, "ts": t0, "duration_s": round(time.time() - t0, 2),
                     "max_hops": max_hops, "probes": probes, "timeout_ms": timeout_ms, "complete": complete,
                     "error": None if complete else f"no reply from {host} within {max_hops} hops",
                     "pc": {"ip": pc_ip, "hostname": PC_HOSTNAME}, "gateway": gw, "hops": hops}
            with self.lock:
                self.trace_last = trace
            self.hub.publish("trace.done", {"host": host, "target_ip": target_ip, "hops": len(hops), "complete": complete,
                                            "duration_s": trace["duration_s"]})
            return copy.deepcopy(trace)
        finally:
            with self.lock:
                self.trace_running = False

    def traceroute_last(self) -> Dict[str, Any]:
        with self.lock:
            return {"trace": copy.deepcopy(self.trace_last), "running": self.trace_running}

    # -- Tools: LAN peers + throughput -----------------------------------
    def lan_peers(self) -> Dict[str, Any]:
        """The peers view (same keys as ``tnt.lanpeers.LanPeers.peers_view``) on the network the fake PC is on.
        Switched off: no peers, ``listening`` / ``running`` false and ``error`` "disabled"."""
        now = time.time()
        with self.lock:
            on = self.lan_enabled
            prof = net_profile(self.net_profile)
            nic = net_internet_nic(prof)
            peers = []
            if on:
                for k, (pid, hn, ip, ver, adapter) in enumerate(prof["peers"]):
                    seen = self.lan_peer_ts - k * 2.5
                    peers.append({"id": pid, "hostname": hn, "ip": ip, "version": ver, "last_seen_ts": round(seen, 3),
                                  "age_s": round(max(0.0, now - seen), 1), "adapter": adapter})
            self_ip = nic["ipv4"][0]["address"] if nic and nic["ipv4"] else None
            if self_ip is None:
                # tnt.lanpeers._bench_ipv4: no internet adapter (a bench cable) -> the first up adapter's address, physical and
                # routable first, never a /32 tunnel
                ranked = sorted((0 if a["is_physical"] else 1, 1 if e["address"].startswith("169.254.") else 0, pos, e["address"])
                                for pos, a in enumerate(prof["adapters"]) if a["status"] == "up" for e in a["ipv4"] if e["prefix"] < 32)
                self_ip = ranked[0][3] if ranked else None
            return {"self": {"id": "c0ffee42", "hostname": PC_HOSTNAME, "ip": self_ip, "version": VERSION, "port": self.port + 3},
                    "peers": peers, "listening": on, "error": None if on else "disabled", "enabled": on, "running": on,
                    "throughput_running": self.lan_running, "beacon_port": self.port + 2, "throughput_port": self.port + 3,
                    "firewall": {"ok": True, "error": None} if on else {"ok": None, "error": None}}

    def lan_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """``{"enabled": true|false}`` -> the peers view, mirroring PUT /api/tools/lan/settings:
        ``enabled`` must be a JSON boolean (a truthy string must never switch discovery off) and
        no other key is accepted.  Publishes ``lan.state`` with the whole view."""
        if not isinstance(patch, dict):
            raise ValueError("settings patch must be an object")
        unknown = sorted(k for k in patch if k not in LAN_SETTINGS_KEYS)
        if unknown:
            raise ValueError(f"unknown LAN setting(s) {', '.join(unknown)}; accepted: {', '.join(LAN_SETTINGS_KEYS)}")
        if "enabled" not in patch:
            raise ValueError(f"nothing to update; accepted keys: {', '.join(LAN_SETTINGS_KEYS)}")
        if not isinstance(patch["enabled"], bool):
            raise ValueError("enabled must be true or false")
        on = patch["enabled"]
        with self.lock:
            self.lan_enabled = on
            self.settings.setdefault("lan", {})["enabled"] = on
            if on:
                self.lan_peer_ts = time.time()      # the peers are heard from again right away
        view = self.lan_peers()
        self.hub.publish("lan.state", copy.deepcopy(view))
        return view

    def lan_tick(self, now: float) -> None:
        """Every 10 s the peers 'announce' again: bump the sighting time and broadcast lan.peers.
        Nothing is announced while the switch is off."""
        with self.lock:
            if not self.lan_enabled or now - self.lan_peer_ts < 10:
                return
            self.lan_peer_ts = now
        self.hub.publish("lan.peers", {"peers": self.lan_peers()["peers"]})

    def lan_throughput(self, body: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            if not self.lan_enabled:
                raise ValueError("LAN discovery is turned off")
        peer_ip = str(body.get("peer") or "").strip()
        peer = next((p for p in net_profile(self.net_profile)["peers"] if p[2] == peer_ip), None)
        if not peer:
            raise ValueError(f"no TNT peer at {peer_ip!r} — pick one from the list")
        try:
            seconds = max(2, min(20, int(body.get("seconds") or 5)))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"bad seconds: {exc}") from exc
        with self.lock:
            if self.lan_running:
                raise RuntimeError("a throughput test is already running")
            self.lan_running = True
            fast = self.lan_fast
        t0 = time.time()
        rng = self.rng
        try:
            up_final = round(940 * (1 + rng.gauss(0, 0.02)), 1)
            down_final = round(910 * (1 + rng.gauss(0, 0.02)), 1)
            phases = [("connect", 0.4, 0.0), ("upload", 1.8, up_final), ("download", 1.8, down_final)]
            for phase, dur, target in phases:
                dur = 0.04 if fast else dur
                p0 = time.time()
                while True:
                    frac = min(1.0, (time.time() - p0) / dur)
                    mbps = round(target * min(1.0, 0.55 + frac * 0.5) * (1 + rng.gauss(0, 0.03)), 1) if target else 0.0
                    self.hub.publish("lan.throughput.progress", {"phase": phase, "pct": round(frac * 100, 1), "mbps": mbps})
                    if frac >= 1.0:
                        break
                    time.sleep(0.02 if fast else 0.15)
            result = {"ts": time.time(), "peer": {"ip": peer[2], "hostname": peer[1]}, "seconds": seconds,
                      "upload_mbps": up_final, "download_mbps": down_final, "latency_ms": round(0.35 + abs(rng.gauss(0, 0.08)), 2),
                      "duration_s": round(time.time() - t0, 2), "error": None}
            with self.lock:
                self.lan_last = result
            self.hub.publish("lan.throughput.done", {"result": copy.deepcopy(result)})
            return copy.deepcopy(result)
        finally:
            with self.lock:
                self.lan_running = False

    def lan_throughput_last(self) -> Dict[str, Any]:
        with self.lock:
            return {"result": copy.deepcopy(self.lan_last), "running": self.lan_running}

    # -- Tools: saved Wi-Fi networks -------------------------------------
    def wifi_profiles(self, reveal: bool = True) -> Dict[str, Any]:
        """Same shape as ``tnt.wifi.list_profiles`` (GET /api/tools/wifi/profiles).
        ``reveal=False`` leaves every key out while ``key_present`` still says whether there
        is one, exactly like the real route's ``?reveal=0``."""
        profiles = []
        for name, ssid, auth, enc, key, mode, hidden in WIFI_PROFILES:
            profiles.append({
                "name": name, "ssid": ssid, "authentication": auth, "encryption": enc,
                "key": key if (reveal and key) else None, "key_present": bool(key),
                "connection_mode": mode, "non_broadcast": bool(hidden),
                "interface": WIFI_INTERFACE["guid"], "error": None,
            })
        return {"available": True, "interfaces": [dict(WIFI_INTERFACE)], "profiles": profiles,
                "error": None, "source": "wlanapi", "ts": time.time()}

    # -- networks (tnt.networks) ------------------------------------------
    def _seed_networks(self, now: float) -> None:
        """The networks of MOCK_ITINERARY (ids in the order this PC first arrived) and its visits to them; it is on the last one."""
        for key, arrived, left in MOCK_ITINERARY:
            row = self._network_for_locked(key, now - arrived * 86400)
            end = None if left is None else now - left * 86400
            self.net_spells.append([row["id"], now - arrived * 86400, end])
            row["last_seen"] = now if end is None else end
        self.net_id = self.net_spells[-1][0]

    def _network_for_locked(self, key: str, ts: float) -> Dict[str, Any]:
        """The row of a MOCK_NETWORKS network, created when first seen: found by its router's MAC, else (a MAC never read) by its gateway,
        subnet and DHCP server among the rows without a MAC."""
        mac, gateway, subnet, dhcp, suffix, nic = MOCK_NETWORKS[key]
        row = next((n for n in self.networks if (n["mac"] == mac if mac else not n["mac"] and (n["gateway_ip"], n["subnet"], n["dhcp_server"]) ==
                                                 (gateway, subnet, dhcp))), None)
        if row is None:
            row = {"id": len(self.networks) + 1, "key": key, "mac": mac, "gateway_ip": gateway, "subnet": subnet, "dhcp_server": dhcp,
                   "dns_suffix": suffix, "nic": nic, "first_seen": ts, "last_seen": ts, "virtual_mac": None, "portable": False}
            self.networks.append(row)
        return row

    def _net_move_locked(self, profile: str, now: float) -> None:
        """The network tracker's side of a move to a NET_PROFILE_NAMES profile: one with a default gateway is a network (known or new);
        without one the PC stays on its last network. Back on the same network, the time without one was part of the visit (an outage
        at the site); on a different one, the old visit ended when the network went away (travel is nobody's visit)."""
        key = NET_PROFILE_NETWORK.get(profile)
        if key is None:
            if self.net_offline_since is None:
                self.net_offline_since = now
            return
        row = self._network_for_locked(key, now)
        row["last_seen"] = now
        offline, self.net_offline_since = self.net_offline_since, None
        if row["id"] == self.net_id:
            return
        if self.net_spells and self.net_spells[-1][2] is None:
            self.net_spells[-1][2] = offline if offline is not None else now
        self.net_spells.append([row["id"], now, None])
        self.net_id = row["id"]

    def _data_start_locked(self) -> float:
        """When this fake PC's ping data begins: its first visit (MOCK_ITINERARY)."""
        return min((spell[1] for spell in self.net_spells), default=self.started_ts - 4 * 86400)

    def network_current(self) -> Dict[str, Any]:
        """GET /api/networks/current: the network this fake PC is on (its last one while it has none), with the newest report made on it."""
        with self.lock:
            row = next((n for n in self.networks if n["id"] == self.net_id), None)
            if row is None:
                return {"network": None}
            now = time.time()
            if self.net_offline_since is None:
                row["last_seen"] = max(row["last_seen"], now - now % 60)       # refreshed at most once a minute
            last = self._newest_report_locked(row["id"])
            return {"network": dict(mock_network_view(row), first_seen=round(row["first_seen"], 3), last_seen=round(row["last_seen"], 3),
                                    last_report={"id": last["report_id"], "site": last["site"], "created_ts": last["created_ts"]} if last else None,
                                    offline=self.net_offline_since is not None)}

    def network_set_portable(self, nid: int, portable: bool) -> Optional[Dict[str, Any]]:
        """PATCH /api/networks/{id} {"portable"}: a network carried from site to site (a hotspot), or not (tnt.reports.ReportManager
        .set_network_portable): a running scan on it is suggested nothing (or its site again) and reads its window again. The network's
        view without times, None when there is no such network."""
        with self.lock:
            row = self._network_row_locked(nid)
            if row is None:
                return None
            row["portable"] = bool(portable)
            view = mock_network_view(row)
            job = self.report_job
            snap = None
            if job and job["status"] == "running" and job.get("network_id") == row["id"]:
                start, reason = self._report_window(job["started_ts"])
                job.update(suggested_site=self._suggested_site_locked(row["id"]), network=view, window_start=round(start, 3), window_reason=reason)
                snap = copy.deepcopy(job)
        if snap:
            self.hub.publish("report.progress", {"job": snap})
        return view

    def _network_row_locked(self, nid: Optional[int]) -> Optional[Dict[str, Any]]:
        return next((n for n in self.networks if n["id"] == nid), None) if nid is not None else None

    def _scan_network_locked(self) -> Tuple[Optional[int], Optional[str]]:
        """(network id, None) a full scan starts on, else (None, why): "offline" (no network with a gateway: the last one sticks for the
        data, but a scan now is on no site's network), "unknown" (tnt.reports.ReportManager._scan_network)."""
        if self.net_id is None:
            return None, "unknown"
        if self.net_offline_since is not None:
            return None, "offline"
        return self.net_id, None

    # -- reports (Full Scan) ---------------------------------------------
    def _seed_reports(self, now: float) -> None:
        for site, days, profile in REPORT_SEEDS:
            net = next(n for n in self.networks if n["key"] == REPORT_PROFILES[profile]["network"])
            self._report_add(synthetic_report(site, now - days * 86400, profile, net["id"]))

    def _newest_report_locked(self, network_id: Optional[int]) -> Optional[Dict[str, Any]]:
        """The newest saved report made on a network under a site name ("Unnamed site" names none) -> {site, report_id, created_ts}, else None."""
        if network_id is None:
            return None
        unnamed = site_key(REPORT_UNNAMED)
        rep = max((r for r in self.reports if r.get("network_id") == network_id and r["site_key"] != unnamed),
                  key=lambda r: (r["created_ts"], r["id"]), default=None)
        return {"site": rep["site"], "report_id": rep["id"], "created_ts": rep["created_ts"]} if rep else None

    def _suggested_site_locked(self, network_id: Optional[int]) -> Optional[Dict[str, Any]]:
        """What a full scan on a network suggests: the newest report made on it under a site name, never for a portable network (a hotspot's
        reports name the other sites it went to) -> {site, report_id, created_ts}, else None."""
        row = self._network_row_locked(network_id)
        return None if row is not None and row.get("portable") else self._newest_report_locked(network_id)

    def _refresh_suggestion_locked(self, rid: int) -> Optional[Dict[str, Any]]:
        """A running scan whose suggestion is the report *rid* (renamed or deleted since) suggests again -> the job to publish, else None."""
        job = self.report_job
        if not job or job["status"] != "running" or (job.get("suggested_site") or {}).get("report_id") != rid:
            return None
        job["suggested_site"] = self._suggested_site_locked(job.get("network_id"))
        return copy.deepcopy(job)

    def _report_add(self, rep: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            rep["id"] = self.report_next_id
            self.report_next_id += 1
            self.reports.append(rep)
            return rep

    @staticmethod
    def _report_row(rep: Dict[str, Any]) -> Dict[str, Any]:
        """A report as lists carry it: never the data."""
        return {k: copy.deepcopy(rep.get(k)) for k in ("id", "site", "created_ts", "completed_ts", "status", "network_id", "summary")}

    def _reports_status_locked(self) -> Dict[str, Any]:
        """status.reports (tnt.reports.ReportManager.status): the counts, the newest report and the job; the caller holds the lock."""
        newest = max(self.reports, key=lambda r: (r["created_ts"], r["id"]), default=None)
        return {"count": len(self.reports), "sites": len({r["site_key"] for r in self.reports}),
                "last": {k: newest[k] for k in ("id", "site", "created_ts", "status")} if newest else None,
                "job": copy.deepcopy(self.report_job)}

    def reports_list(self, key: str, q: str, limit: int, offset: int) -> Dict[str, Any]:
        """GET /api/reports: newest first; ``key`` an exact site key, ``q`` a case-insensitive part of the site name."""
        with self.lock:
            rows = sorted(self.reports, key=lambda r: (r["created_ts"], r["id"]), reverse=True)
            if key.strip():
                rows = [r for r in rows if r["site_key"] == site_key(key)]
            if q.strip():
                needle = site_key(q)
                rows = [r for r in rows if needle in r["site_key"]]
            return {"reports": [self._report_row(r) for r in rows[offset:offset + limit]], "total": len(rows)}

    def report_sites(self, q: str, limit: int) -> Dict[str, Any]:
        """GET /api/reports/sites: one row per site key with its newest report's spelling, most recently scanned first; with
        ``q`` only the sites containing it, those starting with it first; ``total`` counts them all before the limit."""
        with self.lock:
            groups: Dict[str, Dict[str, Any]] = {}
            for r in sorted(self.reports, key=lambda r: (r["created_ts"], r["id"]), reverse=True):
                g = groups.setdefault(r["site_key"], {"site": r["site"], "site_key": r["site_key"], "count": 0, "last_ts": r["created_ts"], "network_ids": []})
                g["count"] += 1
                if r.get("network_id") is not None and r["network_id"] not in g["network_ids"]:
                    g["network_ids"].append(r["network_id"])       # the networks its reports were made on
            sites = list(groups.values())
            for g in sites:
                g["network_ids"].sort()
        if q.strip():
            needle = site_key(q)
            sites = [s for s in sites if needle in s["site_key"]]
            sites.sort(key=lambda s: 0 if s["site_key"].startswith(needle) else 1)
        return {"sites": sites[:limit], "total": len(sites)}

    def report_get(self, rid: int) -> Optional[Dict[str, Any]]:
        with self.lock:
            rep = next((r for r in self.reports if r["id"] == rid), None)
            return copy.deepcopy({k: rep.get(k) for k in ("id", "site", "created_ts", "completed_ts", "status", "network_id", "summary", "data")}) if rep else None

    def report_rename(self, rid: int, site: Any) -> Optional[Dict[str, Any]]:
        name = site_normalize(site)
        with self.lock:
            rep = next((r for r in self.reports if r["id"] == rid), None)
            if rep is None:
                return None
            rep.update(site=name, site_key=site_key(name))
            rep["data"]["meta"]["site"] = name
            if self.report_job and self.report_job.get("report_id") == rid:
                self.report_job["site"] = name              # like the service: the scan that saved it is renamed too
            progress = self._refresh_suggestion_locked(rid)  # a running scan suggesting this report suggests its new name
            row = self._report_row(rep)
        self.hub.publish("report.updated", {"id": rid, "site": name})
        if progress:
            self.hub.publish("report.progress", {"job": progress})
        return row

    def report_delete(self, rid: int) -> bool:
        """DELETE /api/reports/{id}; like the service, the last scan's job forgets a report it saved (report_id null)."""
        forgot = None
        with self.lock:
            before = len(self.reports)
            self.reports = [r for r in self.reports if r["id"] != rid]
            gone = len(self.reports) != before
            if gone and self.report_job and self.report_job.get("report_id") == rid:
                self.report_job["report_id"] = None
                forgot = copy.deepcopy(self.report_job)
            if gone:
                forgot = self._refresh_suggestion_locked(rid) or forgot     # a running scan suggesting it suggests the next newest, or none
        if gone:
            self.hub.publish("report.deleted", {"id": rid})
        if forgot:
            self.hub.publish("report.progress", {"job": forgot})
        return gone

    def _report_window(self, now: float) -> Tuple[float, str]:
        """(window_start, window_reason) of a report made at *now*: on an identified network the week before it, cut short by the oldest
        ping data, of which only that network's visits count ("site_network"); without one, 7 days cut short by the last network change
        and by the oldest ping data."""
        with self.lock:
            oldest = self._data_start_locked()
            nid = self._scan_network_locked()[0]
            row = self._network_row_locked(nid)
            if row is not None and not row.get("portable"):
                return max(now - REPORT_WINDOW_S, oldest), "site_network"
            if row is not None and self.net_spells and self.net_spells[-1][0] == nid:
                # a portable network (a hotspot): only this connection to it counts
                return max(now - REPORT_WINDOW_S, oldest, min(self.net_spells[-1][1], now)), "network_change"
            bounds = [(now - REPORT_WINDOW_S, "seven_days"), (oldest, "data_start")]
            if self.net_changed_ts is not None:
                bounds.append((min(self.net_changed_ts, now), "network_change"))
        return max(bounds, key=lambda b: b[0])

    def _report_visits(self, now: float) -> Tuple[float, str, Optional[int], Optional[List[Dict[str, float]]]]:
        """(window_start, window_reason, network id, visits) of a report made at *now*: the visits to this PC's network in the window (of a
        portable network: this connection), or None (and no network id) for a report made by the time rule (no network with a gateway)."""
        start, reason = self._report_window(now)
        with self.lock:
            nid = self._scan_network_locked()[0]
            row = self._network_row_locked(nid)
            if row is None or (reason != "site_network" and not row.get("portable")):
                return start, reason, None, None
            return start, reason, nid, report_visits([(s, now if e is None else e) for n, s, e in self.net_spells if n == nid], start, now)

    def report_scan_job(self) -> Optional[Dict[str, Any]]:
        with self.lock:
            return copy.deepcopy(self.report_job)

    def report_scan_start(self, site: Any) -> Dict[str, Any]:
        """POST /api/reports/scan: start the one full scan (ReportBusy while one runs). A thread takes it through the phases."""
        # like the service: no site, or only whitespace, starts an unnamed scan
        name = None if site is None or (isinstance(site, str) and not site.strip()) else site_normalize(site)
        now = time.time()
        window_start, window_reason = self._report_window(now)
        with self.lock:
            if self.report_job and self.report_job["status"] == "running":
                raise ReportBusy(copy.deepcopy(self.report_job))
            self.report_job_seq += 1
            # the network the scan is on (none without a network with a gateway), how it was identified, and the site of the newest
            # report made on it (the name modal starts with it)
            nid, self.report_network_why = self._scan_network_locked()
            row = self._network_row_locked(nid)
            job = {"id": f"scan-{self.report_job_seq}-{int(now)}", "site": name, "started_ts": now, "status": "running", "phase": "speed", "pct": 0,
                   "message": "Starting the full scan",
                   "phases": [{"key": k, "status": "pending", "message": None, "started_ts": None, "finished_ts": None} for k in REPORT_PHASES],
                   "report_id": None, "error": None, "window_start": round(window_start, 3), "window_reason": window_reason,
                   "network_id": nid, "network": mock_network_view(row) if row else None, "suggested_site": self._suggested_site_locked(nid)}
            self.report_job = job
            self.report_wifi_open = False
            self.report_wifi_taken = False
            self.report_wifi_inbox = []
            cancel = self.report_cancel = threading.Event()
            snap = copy.deepcopy(job)
        self.hub.publish("report.progress", {"job": snap})
        threading.Thread(target=self._report_worker, args=(job["id"], cancel), name="mock-full-scan", daemon=True).start()
        return snap

    def report_scan_name(self, site: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """PATCH /api/reports/scan -> (job, None), or (job, code) for a 409 (tnt.reports.ReportManager.set_site): names the running
        scan's site, else renames the report the last scan saved; "no_scan" without a scan since the start, "not_running" for a
        cancelled or failed one, "not_found" when the report it saved has been deleted."""
        name = site_normalize(site)
        rename = None
        with self.lock:
            job = self.report_job
            if job is None:
                return None, "no_scan"
            if job["status"] == "running":
                job["site"] = name
            elif job["status"] == "saved" and job.get("report_id") is not None:
                rename = job["report_id"]
            elif job["status"] == "saved":
                return copy.deepcopy(job), "not_found"          # its report was deleted since
            else:
                return copy.deepcopy(job), "not_running"
            snap = copy.deepcopy(job)
        if rename is not None and self.report_rename(rename, name) is None:
            with self.lock:
                if self.report_job is job and job.get("report_id") == rename:
                    job["report_id"] = None
                return copy.deepcopy(job), "not_found"
        if rename is not None:
            snap = self.report_scan_job() or snap               # renaming its report renamed the job too
        self.hub.publish("report.progress", {"job": snap})
        return snap, None

    def report_scan_cancel(self) -> Optional[Dict[str, Any]]:
        """DELETE /api/reports/scan: stop the running scan, saving nothing (its running and pending phases "skipped"); the job as it
        is when it is not running, None when there never was one."""
        with self.lock:
            job = self.report_job
            if not job or job["status"] != "running":
                return copy.deepcopy(job)
            self.report_cancel.set()
            self.report_wifi_open = False
            now = time.time()
            for ph in job["phases"]:
                if ph["status"] == "running":
                    ph.update(status="skipped", message="Cancelled", finished_ts=now)
                elif ph["status"] == "pending":
                    ph["status"] = "skipped"
            job.update(status="cancelled", phase=None, message="Cancelled")
            snap = copy.deepcopy(job)
        self.report_wifi_event.set()
        self.hub.publish("report.progress", {"job": snap})
        return snap

    def report_scan_wifi(self, snapshot: Dict[str, Any], body: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """POST /api/reports/scan/wifi with a validated snapshot (``body``: what the page sent, kept for the tests): None when no scan
        is waiting for one, or the waiting scan already has a usable one. The Wi-Fi phase's message says what arrived, like the service."""
        if snapshot["available"]:
            message = f"Wi-Fi scan received: {len(snapshot['aps'])} access points"
        else:
            message = f"{report_wifi_reason(snapshot)}; waiting briefly for a TNT window that can scan"
        with self.lock:
            job = self.report_job
            if not job or job["status"] != "running" or not self.report_wifi_open or self.report_wifi_taken:
                return None
            self.report_wifi_taken = bool(snapshot["available"])
            self.report_wifi_posts.append({"job_id": job["id"], "ts": time.time(), "snapshot": copy.deepcopy(snapshot), "body": copy.deepcopy(body)})
            self.report_wifi_inbox.append(snapshot)
            wifi = next(x for x in job["phases"] if x["key"] == "wifi")
            wifi["message"] = job["message"] = message
            snap = copy.deepcopy(job)
        self.report_wifi_event.set()
        self.hub.publish("report.progress", {"job": snap})
        return snap

    def _report_step(self, job_id: str, key: str, status: str, message: str = "", pct: Optional[float] = None) -> bool:
        """Move one phase of the running scan, publishing the job when anything changed; False once the scan is not running."""
        with self.lock:
            job = self.report_job
            if not job or job["id"] != job_id or job["status"] != "running":
                return False
            ph = next(x for x in job["phases"] if x["key"] == key)
            before = (ph["status"], ph["message"], job["pct"], job["phase"])
            now = time.time()
            if ph["started_ts"] is None:
                ph["started_ts"] = now
            if status in ("done", "error", "skipped"):
                ph["finished_ts"] = now
            ph.update(status=status, message=message)
            if status == "running":
                job["phase"] = key if key in ("speed", "discovery", "wifi") else "finalize"
                job["message"] = message
            if pct is not None:
                job["pct"] = int(max(job["pct"], min(100, pct)))
            changed = before != (ph["status"], ph["message"], job["pct"], job["phase"])
            snap = copy.deepcopy(job)
        if changed:
            self.hub.publish("report.progress", {"job": snap})
        return True

    def _report_worker(self, job_id: str, cancel: threading.Event) -> None:
        try:
            speed = self._report_speed(job_id, cancel)
            discovery = None if cancel.is_set() else self._report_discovery(job_id, cancel)
            wifi = None if cancel.is_set() else self._report_wifi(job_id, cancel)
            if cancel.is_set() or not self._report_step(job_id, "history", "running", "Reading the ping and outage history", 87):
                return
            time.sleep(0.02 if self.report_fast else 0.5)
            network, ping, outages = self._report_history()
            with self.lock:
                if self.report_job and self.report_job["id"] == job_id:
                    self.report_job.update(window_start=round(ping["window_start"], 3), window_reason=ping["window_reason"])
            words = REPORT_WINDOW_WORDS.get(ping["window_reason"])
            span = _span_text(ping["window_end"] - ping["window_start"])
            window = f"Pings and outages {words} ({span})" if words else f"Pings and outages over {span}"    # tnt.reports.history_message
            with self.lock:
                job_row = self._network_row_locked((self.report_job or {}).get("network_id"))
                why = "portable" if job_row is not None and job_row.get("portable") else self.report_network_why
            if why in REPORT_NETWORK_NOTE_MESSAGES:
                window += f"; {REPORT_NETWORK_NOTE_MESSAGES[why]}"   # no site's network rule: no network, not identified, or a hotspot
            if not self._report_step(job_id, "history", "done", window, 94):
                return
            self._report_step(job_id, "save", "running", "Saving the report", 96)
            with self.lock:
                job = self.report_job
                if cancel.is_set() or not job or job["id"] != job_id or job["status"] != "running":
                    return
                now = time.time()
                next(x for x in job["phases"] if x["key"] == "save").update(status="done", message=None, finished_ts=now)
                # a scan nobody named goes under the site of the newest report of its network, as that report is now (renamed, or deleted)
                named = job["site"]
                suggested = None if named else self._suggested_site_locked(job.get("network_id"))
                site = named or (suggested["site"] if suggested else REPORT_UNNAMED)
                net_meta = mock_network_view(next((n for n in self.networks if n["id"] == job.get("network_id")), None))
                data = {"meta": {"site": site, "created_ts": job["started_ts"], "completed_ts": now, "duration_s": round(now - job["started_ts"], 1),
                                 "tnt_version": VERSION, "hostname": PC_HOSTNAME, "scan_phases": copy.deepcopy(job["phases"]), "network": net_meta},
                        "network": network, "speed": speed, "ping": ping, "outages": outages, "discovery": discovery, "wifi": wifi}
                status = "complete" if all(x["status"] == "done" for x in job["phases"]) else "partial"
                rep = self._report_add({"site": site, "site_key": site_key(site), "created_ts": job["started_ts"], "completed_ts": now, "status": status,
                                        "tnt_version": VERSION, "network_id": job.get("network_id"), "summary": report_summary(data), "data": data})
                message = f"Saved the report for {site}"
                if suggested and not named:
                    message += ", the site this network was scanned as before"
                    job.update(site=site, suggested_site=suggested)          # like the service: the job names the site it went under
                job.update(status="saved", phase=None, pct=100, message=message, report_id=rep["id"])
                next(x for x in job["phases"] if x["key"] == "save")["message"] = job["message"]
                snap = copy.deepcopy(job)
            self.hub.publish("report.progress", {"job": snap})
            self.hub.publish("report.saved", {"id": rep["id"], "site": rep["site"], "status": rep["status"]})
        except Exception as exc:  # noqa: BLE001
            log.exception("full scan failed")
            with self.lock:
                job = self.report_job
                snap = None
                if job and job["id"] == job_id and job["status"] == "running":
                    job.update(status="error", phase=None, error=str(exc), message="The full scan failed")
                    snap = copy.deepcopy(job)
            if snap:
                self.hub.publish("report.progress", {"job": snap})

    def _report_speed_window(self) -> Dict[str, Any]:
        now = time.time()
        start, _reason, _nid, visits = self._report_visits(now)
        with self.lock:
            # the tests of the window; of a site's network, only the ones run during its visits
            ok = [r for r in self.speedtests if r["ok"] and r["ts"] >= start and (visits is None or any(v["start"] <= r["ts"] <= v["end"] + 60 for v in visits))]

        def stats(k: str) -> tuple:
            xs = [r[k] for r in ok if r.get(k) is not None]
            return (round(sum(xs) / len(xs), 1), min(xs), max(xs)) if xs else (None, None, None)

        d, u, lat = stats("download_mbps"), stats("upload_mbps"), stats("latency_ms")
        return {"count": len(ok), "download_avg": d[0], "download_min": d[1], "download_max": d[2], "upload_avg": u[0], "upload_min": u[1],
                "upload_max": u[2], "latency_avg": lat[0]}

    def _report_speed(self, job_id: str, cancel: threading.Event) -> Dict[str, Any]:
        """The speed test: the mock's run-now test, or the one already running (waited for and used)."""
        self._report_step(job_id, "speed", "running", "Running the speed test", 1)
        with self.lock:
            before = len(self.speedtests)
            fast = self.report_fast
        if fast:
            time.sleep(0.02)
            with self.lock:
                self.speedtests.append(self._make_speed(time.time()))
        else:
            self.speed_run()
            deadline = time.time() + 60
            while time.time() < deadline and not cancel.is_set():
                with self.lock:
                    running, prog = self.speed_running, dict(self.speed_progress)
                if not running:
                    break
                base = {"latency": (0.0, 0.15), "download": (0.15, 0.45), "upload": (0.6, 0.4)}.get(prog.get("phase"), (0.0, 0.0))
                self._report_step(job_id, "speed", "running", "Running the speed test", 1 + 28 * (base[0] + base[1] * float(prog.get("pct") or 0)))
                cancel.wait(0.4)
        with self.lock:
            res = copy.deepcopy(self.speedtests[-1]) if len(self.speedtests) > before else None
        window = self._report_speed_window()
        if res is None:
            self._report_step(job_id, "speed", "error", "The speed test did not finish in time", 30)
            return {"available": False, "reason": "The speed test did not finish in time", "result": None, "window": window}
        result = dict({k: res.get(k) for k in REPORT_SPEED_KEYS}, ok=bool(res.get("ok")))
        if not result["ok"]:
            # like the service: a failed test keeps its result and leaves the section unavailable
            self._report_step(job_id, "speed", "error", f"The speed test failed: {res.get('error') or 'unknown error'}", 30)
            reason = f"The speed test failed: {res['error']}" if res.get("error") else "The speed test failed"
            return {"available": False, "reason": reason, "result": result, "window": window}

        def fmt(v: Any, unit: str) -> str:
            return f"{v:.1f} {unit}" if isinstance(v, (int, float)) else "-"

        self._report_step(job_id, "speed", "done", f"Download {fmt(res.get('download_mbps'), 'Mbps')}, upload {fmt(res.get('upload_mbps'), 'Mbps')}, "
                          f"latency {fmt(res.get('latency_ms'), 'ms')}", 30)
        return {"available": True, "reason": None, "result": result, "window": window}

    @staticmethod
    def _report_discovery_unavailable(reason: str) -> Dict[str, Any]:
        return {"available": False, "reason": reason, "run_id": None, "range": None, "started_ts": None, "duration_s": None, "host_count": 0,
                "device_types": {}, "hosts": [], "hosts_total": 0, "note": None}

    def _report_discovery(self, job_id: str, cancel: threading.Event) -> Dict[str, Any]:
        """Discovery over the default range: the mock's own scan, or the one already running (waited for, never cancelled)."""
        self._report_step(job_id, "discovery", "running", "Scanning the network", 31)
        with self.lock:
            seen = {r["id"] for r in self.disc_runs}
            fast = self.report_fast
        try:
            if fast:
                cidr = net_profile(self.net_profile)["default_range"]
                if not cidr:
                    raise ValueError("this PC has no IPv4 network to scan right now")
                time.sleep(0.02)
                with self.lock:
                    self._add_disc_run(time.time(), cidr, list(self.settings["discovery"]["ports"]), 0.4)
            else:
                mine = False
                try:
                    self.disc_start(None, None)
                    mine = True
                except RuntimeError:
                    pass                                    # a scan is running already: its result is used
                deadline = time.time() + 120
                while time.time() < deadline:
                    if cancel.is_set():
                        if mine:
                            self.disc_cancel_scan()
                        return {}
                    with self.lock:
                        running, prog = self.disc_running, dict(self.disc_progress)
                    if not running:
                        break
                    frac = {"ping": 0.0, "ports": 0.6, "arp": 0.95, "resolve": 0.96}.get(prog.get("phase"), 0.0)
                    self._report_step(job_id, "discovery", "running", "Scanning the network", 31 + 28 * frac)
                    cancel.wait(0.3)
        except ValueError as exc:
            self._report_step(job_id, "discovery", "error", f"Discovery could not start: {exc}", 60)
            return self._report_discovery_unavailable(f"Discovery could not start: {exc}")
        with self.lock:
            run = next((copy.deepcopy(r) for r in sorted(self.disc_runs, key=lambda r: r["id"], reverse=True) if r["id"] not in seen), None)
        if run is None:
            self._report_step(job_id, "discovery", "error", "The Discovery scan did not finish in time", 60)
            return self._report_discovery_unavailable("The Discovery scan did not finish in time")
        section = report_discovery_section(run)
        n = section["host_count"]
        self._report_step(job_id, "discovery", "done", f"{n} device{'s' if n != 1 else ''} found on {run['cidr']}", 60)
        return section

    def _report_wifi(self, job_id: str, cancel: threading.Event) -> Dict[str, Any]:
        """Wait for the page's Wi-Fi snapshot: the first usable one is taken; after an unavailable one ``report_wifi_grace_s`` more
        for a usable one, else that one is recorded; with none at all the phase gives up after ``report_wifi_timeout_s``."""
        with self.lock:
            self.report_wifi_inbox = []
            self.report_wifi_taken = False
            self.report_wifi_open = True
            deadline = time.time() + float(self.report_wifi_timeout_s)
            grace = float(self.report_wifi_grace_s)
        if not self._report_step(job_id, "wifi", "running", "Waiting for the TNT window to scan Wi-Fi", 61):
            return {}
        accepted = unavailable = None
        grace_end: Optional[float] = None
        try:
            while not cancel.is_set():
                with self.lock:
                    inbox, self.report_wifi_inbox = self.report_wifi_inbox, []
                for snap in inbox:
                    if snap["available"]:
                        accepted = snap
                        break
                    # the latest unavailable one is recorded; the grace time counts from the first
                    unavailable = snap
                    grace_end = time.time() + grace if grace_end is None else grace_end
                if accepted:
                    break
                end = min(deadline, grace_end) if grace_end is not None else deadline
                if time.time() >= end:
                    break
                self.report_wifi_event.wait(min(0.2, max(0.01, end - time.time())))
                self.report_wifi_event.clear()
        finally:
            with self.lock:
                self.report_wifi_open = False
        if cancel.is_set():
            return {}
        if accepted:
            section = report_wifi_section(accepted)
            self._report_step(job_id, "wifi", "done", f"{section['aps_count']} access points, {section['networks']} networks", 85)
            return section
        if unavailable:
            section = report_wifi_section(unavailable)
            self._report_step(job_id, "wifi", "skipped" if unavailable.get("state") in REPORT_WIFI_SKIPPED_STATES else "error", section["reason"], 85)
            return section
        self._report_step(job_id, "wifi", "skipped", REPORT_NO_WINDOW, 85)
        return report_wifi_unavailable(REPORT_NO_WINDOW)

    def _report_history(self) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """Network, ping and outages for a report made now. The window is 7 days, cut short by the last network change and by the
        oldest ping data (the fake PC has monitored since four days before the mock started)."""
        now = time.time()
        start, reason, nid, visits = self._report_visits(now)
        with self.lock:
            # a report of the site's network reads its visits and the outages that began on it (tagged with it); one made by the time
            # rule this PC's activity in the window and every outage
            spells = [(s, now if e is None else e) for n, s, e in self.net_spells if nid is None or n == nid]
            if visits is None:
                visits = report_visits(spells, start, now)
            rows = [o for o in self.outages_list(start, now) if nid is None or any(s <= o["start_ts"] <= e for s, e in spells)]
            monitored = report_monitored_seconds(visits, [(o["start_ts"], now if o["end_ts"] is None else o["end_ts"]) for o in rows if o["kind"] == "gap"])
            secs = max(1, int(monitored))
            # like the service: the targets set up now, read once; one set of the ids left out (removed within the window, so they
            # pinged in it, or disabled) for both notes
            configured = [t for t in self.targets if t.get("enabled", True)]
            labels = {t["id"]: t["label"] for t in configured}
            left_out = {tid for tid, ts in self.removed_targets.items() if ts >= start} | {t["id"] for t in self.targets if t not in configured}
            targets = []
            for t in configured:
                w = self._stats(t["id"], 300)
                loss = float(w["loss_pct"] or 0.0)
                avg = w["avg_ms"] if w["avg_ms"] is not None else t["base"]
                targets.append({"id": t["id"], "host": t["host"], "label": t["label"], "role": "gateway" if t["host"].lower() in GATEWAY_HOSTS else t["kind"],
                                "ip": t["ip"], "samples": secs, "lost": int(secs * loss / 100), "loss_pct": round(loss, 2), "avg_ms": round(avg, 2),
                                "min_ms": w["min_ms"], "max_ms": w["max_ms"], "p95_ms": round(avg * 1.6, 2), "jitter_ms": w["jitter_ms"]})
            prof = net_profile(self.net_profile)
            nic = net_internet_nic(prof)
            first = nic["ipv4"][0] if nic and nic["ipv4"] else None
            public = self._public_ip_view(now).get("ip")
        network = {"available": True, "reason": None,
                   "internet_nic": {"name": nic["name"], "description": nic["description"], "type_name": nic["type_name"], "internet": True,
                                    "ipv4": first["address"] if first else None, "prefix": first["prefix"] if first else None,
                                    "gateway": prof["default_gateway"], "dns": list(nic["dns"]), "dhcp": nic["dhcp_enabled"], "dhcp_server": nic["dhcp_server"],
                                    "mac": nic["mac"], "link_bps": nic["speed_bps"]} if nic else None,
                   "public_ip": public, "isp": None, "warnings": [w["code"] for w in nic["warnings"]] if nic else []}
        # tnt.reports.build_ping_section: with no row to show the section is not collected; when nothing at all was pinged (nothing left
        # out either) no outage could have been noticed, so the outages section is not collected either
        ping = {"available": bool(targets), "reason": None, "window_start": start, "window_end": now, "window_reason": reason,
                "visits": visits, "monitored_s": monitored, "targets": targets,
                "note": report_left_out_note(len(left_out)) if left_out else None,
                "untagged_since": None}                             # the fake PC's pings were all recorded with its networks identified
        if not targets:
            ping["reason"] = REPORT_NO_TARGET_PINGS if left_out else "No pings were recorded in this window"
        outages = report_outages_section(rows, start, now, labels.get, None if targets or left_out else ping["reason"],
                                         [t["id"] for t in configured], left_out, monitored if nid is not None else None)
        if ping["note"]:
            ping["note"] = report_left_out_note(len(left_out))     # like the history phase: an outage of a target that never pinged counts too
        if nid is None:
            ping["monitored_s"] = outages["monitored_s"]           # by the time rule: the window without its gaps, as the outages say
        return network, ping, outages

    # -- settings / misc -------------------------------------------------
    def update_settings(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(patch, dict):
            raise ValueError("settings patch must be an object")
        with self.lock:
            old = self.settings
            new = deep_merge(old, patch)
            for dotted in RETIRED_SETTINGS:
                section, _, leaf = dotted.rpartition(".")
                if isinstance(new.get(section), dict):
                    new[section].pop(leaf, None)
            sp = new["speedtest"]
            try:
                sp["interval_min"] = max(1, min(1440, int(sp["interval_min"])))
            except (TypeError, ValueError):
                sp["interval_min"] = 15
            if sp["backend"] not in ("auto", "cloudflare", "fastcom"):
                sp["backend"] = "auto"
            if new["ui"]["theme"] not in ("light", "dark"):
                new["ui"]["theme"] = "light"
            new["ui"]["show_ipv6"] = bool(new["ui"].get("show_ipv6", False))
            new.setdefault("lan", {})["enabled"] = bool(new.get("lan", {}).get("enabled", True))
            self.lan_enabled = new["lan"]["enabled"]        # one truth for the Tools switch
            new.setdefault("geoip", {})["enabled"] = bool(new.get("geoip", {}).get("enabled", True))
            new["ping"]["loaded"] = bool(new["ping"]["loaded"])
            changed = changed_keys(old, new)
            self.settings = new
            snap = copy.deepcopy(new)
        if changed:
            self.hub.publish("settings.changed", {"changed": changed})
        if "geoip.enabled" in changed:
            self.hub.publish("geoip.state", self.geoip_status())
        return {"settings": snap, "changed": changed}

    def netinfo(self) -> Dict[str, Any]:
        """GET /api/netinfo for the network the fake PC is on, with the generation of the last change."""
        with self.lock:
            prof = net_profile(self.net_profile)
            return {"ts": time.time(), "adapters": prof["adapters"], "internet_nic_index": prof["internet_nic_index"],
                    "default_gateway": prof["default_gateway"], "public_hint": None,
                    "generation": self.net_generation, "changed_ts": self.net_changed_ts}

    # -- the network the fake PC is on (NET_PROFILE_NAMES) ----------------
    def _resolve_gateway(self, t: Dict[str, Any], gateway: Optional[str]) -> None:
        """Point a gateway-alias target at `gateway`, or at nothing when the PC has no default gateway."""
        t.update(ip=gateway, resolved=gateway is not None, kind="local",
                 resolve_error=None if gateway else "this machine has no default gateway right now")

    def _public_ip_view(self, now: float) -> Dict[str, Any]:
        """status.map.public_ip, refreshed every 10 min. After a network change the answer from before it stays
        until the fake lookup lands NET_RECHECK_S later (an error on a network without internet)."""
        if self.net_changed_ts is None:
            ts = self.public_ip_ts + ((now - self.public_ip_ts) // 600) * 600
            return {"ip": PUBLIC_IP, "ts": ts, "error": None, "checked_ts": ts}
        if now - self.net_changed_ts < NET_RECHECK_S and self.net_public_before is not None:
            return dict(self.net_public_before)
        checked = self.net_changed_ts + NET_RECHECK_S
        checked += max(0.0, (now - checked) // 600) * 600
        ip = net_profile(self.net_profile)["public_ip"]
        if ip:
            return {"ip": ip, "ts": checked, "error": None, "checked_ts": checked}
        # tnt.linkmap.refresh_public_ip after a change to a network without internet: the address of the network it left is
        # dropped, `ts` stays that of the last address found and `checked_ts` says when the failed lookup ran
        return {"ip": None, "ts": (self.net_public_before or {}).get("ts"), "error": "no internet connection", "checked_ts": checked}

    def switch_network(self, profile: str) -> Dict[str, Any]:
        """Move the fake PC onto another synthetic network, like Windows applying a new configuration: the gateway
        target follows the new default gateway and a DHCP server whose adapter went away stops. Publishes in the
        service's order: what LanPeers.on_network_change sends while the watcher tells the components (lan.peers
        when the peer list changed, lan.state), then net.changed, then what the next probe ticks send (ping.targets,
        a gateway map.sample) and, for a stopped server, dhcp.state. Returns the net.changed payload."""
        name = str(profile or "").strip().lower()
        if name not in NET_PROFILE_NAMES:
            raise ValueError(f"unknown network profile {profile!r}; one of: {', '.join(NET_PROFILE_NAMES)}")
        now = time.time()
        with self.lock:
            old, new = net_profile(self.net_profile), net_profile(name)
            serving = self._dhcp_adapter() if self.dhcp_running else None
            peers_before = self.lan_peers()["peers"] if self.lan_enabled else []
            self.net_public_before = self._public_ip_view(now)
            self.net_profile = name
            self.net_generation += 1
            self.net_changed_ts = now
            self._net_move_locked(name, now)
            if self.disc_running:
                self.disc_net_changed = True        # discovery.done says the scan ran across the change
            gw = new["default_gateway"]
            for t in self.targets:
                if t["host"].lower() in GATEWAY_HOSTS:
                    self._resolve_gateway(t, gw)
            stopped = None
            if serving is not None:
                # tnt.dhcp.DhcpServer._serving_problem: gone, down, or no longer holding an address
                now_nic = next((a for a in new["adapters"] if a["name"] == serving["name"]), None)
                if now_nic is None:
                    stopped = f"{serving['name']} is no longer present"
                elif now_nic["status"] != "up":
                    stopped = f"{serving['name']} went down"
                elif not now_nic["ipv4"]:
                    stopped = f"{serving['name']} no longer has {self._dhcp_server_ip(serving)[0]}"
            if stopped:
                self.dhcp_running, self.dhcp_since, self.dhcp_changed = False, None, False
                self.dhcp_gen += 1
                self.dhcp_error = f"stopped: {stopped}"
            inet, was = net_internet_nic(new), net_internet_nic(old)
            nets = lambda p: sorted({e["network"] for a in p["adapters"] if a["status"] == "up" for e in a["ipv4"]})  # noqa: E731
            dns = lambda p: sorted((a["name"], tuple(net_fingerprint(a)["dns"]["servers"]), net_fingerprint(a)["dns"]["suffix"])  # noqa: E731
                                   for a in p["adapters"] if a["status"] == "up" and (a["dns"] or a["dns_suffix"]))
            payload = {
                "ts": now, "generation": self.net_generation, "default_gateway": gw, "previous_gateway": old["default_gateway"],
                "internet_nic": net_internet_brief(new),
                "changes": net_changes(old, new),
                "gateway_changed": gw != old["default_gateway"],
                "internet_nic_changed": (inet or {}).get("index") != (was or {}).get("index"),
                "subnets_changed": nets(old) != nets(new),
                "dns_changed": dns(old) != dns(new),
                "summary": net_summary(new),
                "cause": None,                      # "dhcp" when TNT's own DHCP server re-addressed the adapter
            }
            lead = net_change_lead(payload, new)
            if lead:
                payload["summary"] = lead + " · " + payload["summary"]
            self.net_last_event = copy.deepcopy(payload)
            self.events_db.append({"id": len(self.events_db) + 1, "ts": now, "level": "info", "category": "network",
                                   "message": "network changed: " + payload["summary"]})
            views = [self.target_view(t) for t in self.targets]
            lan_view = self.lan_peers()
        if [p["id"] for p in lan_view["peers"]] != [p["id"] for p in peers_before]:
            self.hub.publish("lan.peers", {"peers": lan_view["peers"]})
        self.hub.publish("lan.state", lan_view)
        self.hub.publish("net.changed", copy.deepcopy(payload))
        self.hub.publish("ping.targets", {"targets": views})
        self.hub.publish("map.sample", {"probe": "gateway", "ts": now, "ok": gw is not None, "rtt_ms": 0.7 if gw else None,
                                        "ip": gw, "state": "up" if gw else "down"})
        if stopped:
            self.hub.publish("dhcp.state", dict(self.dhcp_summary(), running=False))
        return payload

    def note_status_request(self) -> None:
        """Count GET /api/status. Tests set ``net_switch_after_status = (n, profile)`` to switch networks on the nth:
        a headless page's clock runs ahead of this server, so a switch on a timer would not land in step."""
        with self.lock:
            self.status_requests += 1
            plan = self.net_switch_after_status
            due = plan is not None and self.status_requests >= plan[0]
            if due:
                self.net_switch_after_status = None
        if due:
            self.switch_network(plan[1])

    def status(self) -> Dict[str, Any]:
        with self.lock:
            targets = [self.target_view(t) for t in self.targets]
            lights = [t["light"] for t in targets]
            overall = "grey"
            for c in ("red", "yellow", "green"):
                if c in lights:
                    overall = c
                    break
            last_run = max(self.disc_runs, key=lambda r: r["ts"]) if self.disc_runs else None
            now = time.time()
            prof = net_profile(self.net_profile)
            nic = net_internet_nic(prof)
            first = nic["ipv4"][0] if nic and nic["ipv4"] else None
            gw = prof["default_gateway"]
            answers = gw is not None and self.net_profile != "static-bad"     # a gateway outside the subnet never replies
            online = bool(prof["public_ip"])
            pub = self._public_ip_view(now)
            return {"version": VERSION, "started_ts": self.started_ts, "uptime_s": round(now - self.started_ts, 1),
                    "mode": "console", "monitoring": not self.paused and bool(self.targets), "paused": self.paused,
                    "overall_light": overall, "targets": targets, "outages": self.outages_status(),
                    "speed": self.speed_status(),
                    "discovery": {"running": self.disc_running, "progress": dict(self.disc_progress),
                                  "last_run": {"id": last_run["id"], "ts": last_run["ts"], "cidr": last_run["cidr"],
                                               "found": last_run["found"], "duration_s": last_run["duration_s"]} if last_run else None},
                    "dhcp": self.dhcp_summary(),
                    # the network generation the UI compares to reload its views after a change it did not hear about
                    "net": {"generation": self.net_generation, "changed_ts": self.net_changed_ts, "default_gateway": gw,
                            "internet_nic": nic["name"] if nic else None,
                            "summary": (self.net_last_event or {}).get("summary") or net_summary(prof),
                            "networks": net_networks(prof), "network_id": self.net_id},
                    "netinfo": {"internet_nic": net_status_nic(prof), "local_nic": net_local_nic(prof),
                                "adapter_count": len(prof["adapters"])},
                    "map": {"ts": now, "running": True, "internet_host": "totalelectronics.com",
                            "pc": {"hostname": PC_HOSTNAME, "ip": first["address"] if first else None, "adapter": nic["name"] if nic else None},
                            # the router's WAN address as seen from the internet, refreshed every 10 min
                            "public_ip": pub,
                            # its ISP and city (tnt.linkmap: always the stored address, even an old network's)
                            "public_geo": self.geoip_lookup(pub["ip"]) if pub["ip"] else None,
                            "gateway": {"name": "gateway", "host": "gateway", "ip": gw, "resolved": gw is not None,
                                        "resolve_error": None if gw else "this machine has no default gateway right now",
                                        "state": "up" if answers else "down", "last": {"ts": now, "ok": answers, "rtt_ms": 0.6 if answers else None},
                                        "consecutive_missed": 0 if answers else 30, "sent": 60, "received": 60 if answers else 0,
                                        "loss_pct": 0.0 if answers else 100.0, "avg_ms": 0.7 if answers else None},
                            "internet": {"name": "internet", "host": "totalelectronics.com", "ip": "203.0.113.80", "resolved": True,
                                         "resolve_error": None, "state": "up" if online else "down",
                                         "last": {"ts": now, "ok": online, "rtt_ms": 19.0 if online else None},
                                         "consecutive_missed": 0 if online else 30, "sent": 60, "received": 59 if online else 0,
                                         "loss_pct": 1.7 if online else 100.0, "avg_ms": 19.4 if online else None}},
                    # the Reports tile's numbers, like the service (the page itself reads /api/reports)
                    "reports": self._reports_status_locked(),
                    "geoip": self.geoip_status(),
                    "settings": {"theme": self.settings["ui"]["theme"], "loaded": self.settings["ping"]["loaded"]}}

    def diagnostics(self) -> Dict[str, Any]:
        with self.lock:
            now = time.time()
            threads = [{"name": th.name, "alive": th.is_alive(), "daemon": th.daemon} for th in threading.enumerate()]
            geo, m = self.geoip_status(), self.geoip_month
            geo_files = [{"name": f"dbip-city-lite-{m}.mmdb", "bytes": GEOIP_CITY_BYTES},
                         {"name": f"dbip-asn-lite-{m}.mmdb", "bytes": GEOIP_ASN_BYTES}] if geo["state"] == "ready" else []
            return {
                "service": {"name": "TNTService", "version": VERSION, "mode": "console", "pid": os.getpid(),
                            "started_ts": self.started_ts, "uptime_s": round(now - self.started_ts, 1),
                            "python": "3.12.4", "frozen": False, "exe": "C:\\Program Files\\TNT\\TNTService.exe",
                            "data_dir": "C:\\ProgramData\\TNT", "config_path": "C:\\ProgramData\\TNT\\config.json",
                            "log_file": "C:\\ProgramData\\TNT\\logs\\tnt-service.log"},
                "os": {"caption": "Microsoft Windows 11 Pro", "version": "10.0.22631", "build": "22631",
                       "hostname": "TEC-DESKTOP", "user": "SYSTEM", "is_admin": True},
                "api": {"host": "127.0.0.1", "port": self.port, "clients_sse": self.hub.count()},
                "db": {"path": "C:\\ProgramData\\TNT\\tnt.db", "size_bytes": 18_874_368,
                       "counts": {"targets": len(self.targets), "ping_minutes": 12960, "outages": len(self.outages),
                                  "speedtests": len(self.speedtests), "discovery_runs": len(self.disc_runs),
                                  "discovery_hosts": sum(r["found"] for r in self.disc_runs), "events": len(self.events_db)}},
                "logs": {"dir": "C:\\ProgramData\\TNT\\logs", "total_bytes": 4_210_688, "ping_log_files": 9},
                "ping": {"paused": self.paused,
                         "targets": [{"id": t["id"], "host": t["host"], "ip": t["ip"], "kind": t["kind"], "thread_alive": True,
                                      "last_ts": self.samples[t["id"]][-1][0] if self.samples.get(t["id"]) else None,
                                      "light": self._light(t)} for t in self.targets]},
                "outages": {"open": [o for o in self.outages if o["end_ts"] is None], "count_24h": self.outages_status()["count_24h"]},
                "speedtest": {"backends": [{"name": "cloudflare", "available": True, "detail": "https://speed.cloudflare.com"},
                                           {"name": "fastcom", "available": True, "detail": "api.fast.com"}],
                              "selected": "cloudflare", "running": self.speed_running, "next_run_ts": self.speed_next_ts,
                              "last": self.speedtests[-1] if self.speedtests else None},
                # tnt.diagnostics._discovery: last_run only once a run exists
                "discovery": dict({"available": True, "running": self.disc_running, "progress": dict(self.disc_progress),
                                   "last_run_ts": max((r["ts"] for r in self.disc_runs), default=None)},
                                  **({"last_run": self._disc_last_summary()} if self.disc_runs else {})),
                # tnt.diagnostics._network: the watcher's state plus the last net.changed
                "network": {"generation": self.net_generation, "changed_ts": self.net_changed_ts,
                            "default_gateway": net_profile(self.net_profile)["default_gateway"],
                            "internet_nic": (net_internet_nic(net_profile(self.net_profile)) or {}).get("name"),
                            "summary": (self.net_last_event or {}).get("summary") or net_summary(net_profile(self.net_profile)),
                            "networks": net_networks(net_profile(self.net_profile)), "running": True, "polls": 120 + self.net_generation,
                            "failures": 0, "last_error": None, "pending": False, "poll_s": 5.0, "available": True,
                            "last_change": copy.deepcopy(self.net_last_event)},
                # tnt.diagnostics._geoip: the manager's status and the data files it has loaded
                "geoip": {"available": True, "status": geo, "files": geo_files},
                "threads": threads, "memory_mb": 48.6, "cpu_pct": 0.4,
                "recent_log": list(self.log_ring)[-100:], "recent_events": list(reversed(self.events_db))[:50],
                "errors_24h": 0,
            }

    def log_tail(self, lines: int) -> Dict[str, Any]:
        with self.lock:
            out = []
            for r in self.log_ring:
                stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
                out.append(f"{stamp},{int((r['ts'] % 1) * 1000):03d} {r['level']:<7} {r['message']}")
            # pad with plausible periodic lines
            base = time.time() - 60 * len(out)
            for k in range(max(0, lines - len(out))):
                stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(base + k * 37))
                out.append(f"{stamp},{(k * 131) % 1000:03d} DEBUG   tnt.api.server: GET /api/status 200 0.8 ms")
            return {"file": "C:\\ProgramData\\TNT\\logs\\tnt-service.log", "lines": out[-lines:]}


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
STATE: MockState  # set in main()


class Handler(BaseHTTPRequestHandler):
    server_version = "TNT-mock/1.0"
    protocol_version = "HTTP/1.1"

    # -- plumbing --------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
        log.debug("%s " + fmt, self.address_string(), *args)

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, status: int, code: str, message: str) -> None:
        self._json({"error": {"code": code, "message": message}}, status)

    def _consume_body(self) -> None:
        """Read the request body off the socket exactly once, before routing.

        Every request goes through here whether or not its route looks at the body: an
        unread body (say ``POST /api/dhcp/stop`` with ``{}``, which the UI sends) would
        otherwise stay on the keep-alive connection and be parsed as the start of the
        NEXT request line (``{}GET /api/health`` -> 501 "Unsupported method").  The raw
        bytes are cached so ``_body()`` can be called any number of times.
        """
        self._raw_body: bytes = b""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n > 0:
            self._raw_body = self.rfile.read(n)
        elif "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            # not worth decoding for a dev mock: drop the connection after this reply so
            # the leftover chunks can never be mistaken for the next request
            self.close_connection = True

    def _body(self) -> Dict[str, Any]:
        raw = getattr(self, "_raw_body", None)
        if raw is None:                 # a route reached outside _handle(): read it now
            self._consume_body()
            raw = self._raw_body
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"invalid JSON body: {exc}") from exc
        return data if isinstance(data, dict) else {}

    def _static(self, path: str) -> None:
        rel = path.lstrip("/") or "index.html"
        target = (UI_DIR / rel).resolve()
        try:
            target.relative_to(UI_DIR.resolve())
        except ValueError:
            self._error(404, "not_found", "no such file")
            return
        if target.is_dir():
            target = target / "index.html"
        if not target.is_file():
            self._error(404, "not_found", "no such file")
            return
        ctype = MIME.get(target.suffix.lower()) or mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        data = target.read_bytes()
        if target == (UI_DIR / "index.html").resolve():
            # the WiFi page's fake bridge goes in before the UI scripts (development only)
            tag = b'<script src="js/api.js"></script>'
            data = data.replace(tag, f'<script src="{MOCK_WIFI_BRIDGE_URL}"></script>\n'.encode() + tag, 1)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _mock_file(self, target: Path) -> None:
        """A development-only script from tools/ (the WiFi page's fake bridge)."""
        if not target.is_file():
            self._error(404, "not_found", "no such file")
            return
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", MIME[".js"])
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _sse(self) -> None:
        q = STATE.hub.subscribe()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.wfile.write(f"event: hello\ndata: {json.dumps({'version': VERSION, 'ts': time.time()})}\n\n".encode())
            self.wfile.flush()
            while True:
                try:
                    frame = q.get(timeout=15)
                except queue.Empty:
                    frame = ": ping\n\n"
                self.wfile.write(frame.encode("utf-8"))
                self.wfile.flush()
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            STATE.hub.unsubscribe(q)
            self.close_connection = True

    # -- routing ---------------------------------------------------------
    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET", bad_request=False)

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._handle("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle("DELETE")

    def do_PATCH(self) -> None:  # noqa: N802
        self._handle("PATCH")

    def _pdf(self, name: str, pdf: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Length", str(len(pdf)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(pdf)

    def _reports_route(self, method: str, rest: List[str], qs: Dict[str, str]) -> None:  # noqa: C901 - flat like _route
        """/api/reports and below, like the service: the literal routes (sites, scan, scan/wifi, compare, compare/pdf) are matched
        before /reports/{id} and /reports/{id}/pdf, and an id that is not an integer is a 400."""

        def qint(name: str, default: int, lo: int, hi: int) -> int:
            try:
                value = int(qs.get(name, default))
            except (TypeError, ValueError):
                value = default
            return max(lo, min(hi, value))

        def refused(code: str, message: str) -> None:
            return self._json({"error": {"code": code, "message": message}, "job": STATE.report_scan_job()}, 409)

        def when(ts: float) -> str:
            return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))

        wrong = lambda: self._error(405, "method_not_allowed", method)  # noqa: E731
        long_q = next((k for k in ("q", "site_key") if len(qs.get(k) or "") > REPORT_QUERY_MAX), None)
        if not rest:
            if method != "GET":
                return wrong()
            if long_q:
                return self._error(400, "bad_request", f"{long_q} is longer than {REPORT_QUERY_MAX} characters")
            return self._json(STATE.reports_list(qs.get("site_key") or "", qs.get("q") or "", qint("limit", 50, 1, 500), qint("offset", 0, 0, 10_000_000)))
        if rest == ["sites"]:
            if method != "GET":
                return wrong()
            if long_q == "q":
                return self._error(400, "bad_request", f"q is longer than {REPORT_QUERY_MAX} characters")
            return self._json(STATE.report_sites(qs.get("q") or "", qint("limit", 20, 1, 500)))
        if rest == ["scan"]:
            if method == "GET":
                return self._json({"job": STATE.report_scan_job()})
            if method == "POST":
                try:
                    return self._json({"job": STATE.report_scan_start(self._body().get("site"))})
                except ReportBusy as exc:
                    return self._json({"error": {"code": "busy", "message": str(exc)}, "job": exc.job}, 409)
            if method == "PATCH":
                job, code = STATE.report_scan_name(self._body().get("site"))
                if code:
                    message = {"no_scan": "No full scan has run since the start", "not_found": "The report of the last full scan has been deleted"}.get(
                        code, "The full scan was not saved")
                    return self._json({"error": {"code": code, "message": message}, "job": job}, 409)
                return self._json({"job": job})
            if method == "DELETE":
                return self._json({"job": STATE.report_scan_cancel()})
            return wrong()
        if rest == ["scan", "wifi"]:
            if method != "POST":
                return wrong()
            if len(getattr(self, "_raw_body", b"")) > REPORT_WIFI_MAX_BYTES:
                return self._error(413, "payload_too_large", f"a Wi-Fi snapshot may be at most {REPORT_WIFI_MAX_BYTES} bytes")
            body = self._body()
            job = STATE.report_scan_wifi(report_wifi_snapshot(body), body)
            return self._json({"job": job}) if job else refused("not_waiting", "No full scan is waiting for a Wi-Fi scan")
        if rest[0] == "compare" and rest[1:] in ([], ["pdf"]):
            if method != "GET":
                return wrong()
            a, b = str(qs.get("a", "")).strip(), str(qs.get("b", "")).strip()
            if not (report_id_ok(a) and report_id_ok(b)):
                return self._error(400, "bad_request", "a and b must be report ids")
            ra, rb = STATE.report_get(int(a)), STATE.report_get(int(b))
            if ra is None or rb is None:
                return self._error(404, "not_found", "no such report")
            result = compare_reports(ra, rb)
            if not rest[1:]:
                return self._json(result)
            lines = [f"A: {ra['site']}  {when(ra['created_ts'])}", f"B: {rb['site']}  {when(rb['created_ts'])}"]
            lines += [f"{sec['title']} - {row['label']}: {row['a']} vs {row['b']} {row['unit']}" for sec in result["sections"] for row in sec["rows"][:4]]
            return self._pdf(compare_filename(ra["site"], rb["site"]), tiny_pdf("TNT comparison (mock)", lines[:30] + ["Generated by tools/mock_api.py - not real data."]))
        if len(rest) == 1 or (len(rest) == 2 and rest[1] == "pdf"):
            if not report_id_ok(rest[0]):
                return self._error(400, "bad_request", f"a report id is 1-15 digits, not {rest[0][:20]!r}")
            rid = int(rest[0])
            if len(rest) == 2:
                if method != "GET":
                    return wrong()
                rep = STATE.report_get(rid)
                if rep is None:
                    return self._error(404, "not_found", "no such report")
                s = rep["summary"]
                net = (rep["data"].get("meta") or {}).get("network") or {}
                visits = (rep["data"].get("ping") or {}).get("visits")
                lines = [f"{rep['site']}  {when(rep['created_ts'])}  ({rep['status']})",
                         "Network: " + ({"mac": f"router {net.get('mac')} ({net.get('vendor') or 'unknown vendor'})",
                                        "fingerprint": "identified by gateway and subnet"}.get(net.get("identity")) or "not identified")
                         + (f", {len(visits)} visit(s) in the window" if isinstance(visits, list) else ""),
                         f"Download {s.get('download_mbps')} Mbps, upload {s.get('upload_mbps')} Mbps, latency {s.get('latency_ms')} ms",
                         f"Gateway {s.get('gateway_avg_ms')} ms, internet {s.get('internet_avg_ms')} ms, outages {s.get('outages')}",
                         f"Devices {s.get('hosts')}, Wi-Fi access points {s.get('wifi_aps')}", "Generated by tools/mock_api.py - not real data."]
                return self._pdf(report_filename(rep["site"], rep["created_ts"]), tiny_pdf("TNT site report (mock)", lines))
            if method == "GET":
                rep = STATE.report_get(rid)
                return self._json(rep) if rep else self._error(404, "not_found", "no such report")
            if method == "PATCH":
                row = STATE.report_rename(rid, self._body().get("site"))
                return self._json(row) if row else self._error(404, "not_found", "no such report")
            if method == "DELETE":
                return self._json({"ok": True}) if STATE.report_delete(rid) else self._error(404, "not_found", "no such report")
            return wrong()
        return self._error(404, "not_found", f"no route for {method} /api/reports/{'/'.join(rest)}")

    def _handle(self, method: str, bad_request: bool = True) -> None:
        """Consume the body, route, and turn exceptions into JSON errors."""
        try:
            self._consume_body()
            self._route(method)
        except ValueError as exc:
            if not bad_request:
                log.exception("%s %s failed", method, self.path)
                self._error(500, "internal", str(exc))
            else:
                self._error(400, "bad_request", str(exc))
        except Exception as exc:  # noqa: BLE001
            log.exception("%s %s failed", method, self.path)
            self._error(500, "internal", str(exc))

    def _route(self, method: str) -> None:  # noqa: C901 - a flat router is easiest to read
        url = urlparse(self.path)
        path = url.path.rstrip("/") or "/"
        qs = {k: v[-1] for k, v in parse_qs(url.query).items()}
        if not path.startswith("/api"):
            if method in ("GET", "HEAD") and path == MOCK_WIFI_BRIDGE_URL:
                return self._mock_file(MOCK_WIFI_BRIDGE)
            if path == "/mock/network" and method in ("GET", "POST"):
                # development only: GET says which synthetic network the fake PC is on, POST {"profile": ...} moves it
                if method == "POST":
                    event = STATE.switch_network(str(self._body().get("profile") or ""))
                    return self._json({"profile": STATE.net_profile, "event": event})
                return self._json({"profile": STATE.net_profile, "profiles": list(NET_PROFILE_NAMES), "generation": STATE.net_generation})
            if path == "/mock/geoip" and method in ("GET", "POST"):
                # development only: GET says which IP location state the fake service is in, POST {"state": ...} picks another
                if method == "POST":
                    return self._json({"state": STATE.geoip_set_state(str(self._body().get("state") or ""))})
                with STATE.lock:
                    return self._json({"state": STATE.geoip_state, "states": list(GEOIP_STATES)})
            if method in ("GET", "HEAD"):
                self._static(path)
            else:
                self._error(405, "method_not_allowed", "static files are read-only")
            return
        p = path[4:] or "/"
        parts = [x for x in p.split("/") if x]
        if parts and parts[0] == "reports":
            return self._reports_route(method, parts[1:], qs)
        if parts[:1] == ["networks"]:
            # the network this PC is on (tnt.networks) and the newest report made on it; PATCH a network: portable (a hotspot) or not
            if parts[1:] == ["current"]:
                return self._json(STATE.network_current()) if method == "GET" else self._error(405, "method_not_allowed", method)
            if len(parts) == 2 and method == "PATCH":
                if not report_id_ok(parts[1]):
                    return self._error(400, "bad_request", f"a network id is 1-15 digits, got {parts[1][:20]!r}")
                body = self._body()
                if not isinstance(body.get("portable"), bool):
                    return self._error(400, "bad_request", "portable (true or false) is required")
                view = STATE.network_set_portable(int(parts[1]), body["portable"])
                return self._json({"network": view}) if view else self._error(404, "not_found", f"network {parts[1]} not found")
            if len(parts) == 2 and report_id_ok(parts[1]):
                return self._error(405, "method_not_allowed", method)
            return self._error(404, "not_found", f"no route for {method} {path}")
        now = time.time()

        def qf(name: str, default: float) -> float:
            try:
                return float(qs.get(name, default))
            except (TypeError, ValueError):
                return default

        if method == "GET":
            if p == "/health":
                return self._json({"ok": True})
            if p == "/status":
                STATE.note_status_request()
                return self._json(STATE.status())
            if p == "/netinfo":
                return self._json(STATE.netinfo())
            if p == "/geoip":
                return self._json(STATE.geoip_status())
            if p == "/geoip/lookup":
                # validated like tnt.api.routes.geoip_lookup; a GET's ValueError would be a 500 in _handle, so a bad
                # address is answered here. Nothing leaves the PC.
                text = str(qs.get("ip") or "").strip()
                if text.startswith("[") and text.endswith("]"):
                    text = text[1:-1]
                text = text.split("%", 1)[0]
                try:
                    if not text or len(text) > 64:
                        raise ValueError(text)
                    addr = ipaddress.ip_address(text)
                except ValueError:
                    return self._error(400, "bad_request", "ip must be an IPv4 or IPv6 address")
                return self._json({"ip": str(addr), "result": STATE.geoip_lookup(str(addr))})
            if p == "/targets":
                return self._json(STATE.targets_view())
            if len(parts) == 3 and parts[0] == "targets" and parts[2] == "samples":
                data = STATE.samples_view(int(parts[1]), int(qf("seconds", 300)))
                return self._json(data) if data else self._error(404, "not_found", "no such target")
            if len(parts) == 3 and parts[0] == "targets" and parts[2] == "history":
                data = STATE.history_view(int(parts[1]), qf("from", now - 86400), qf("to", now))
                return self._json(data) if data else self._error(404, "not_found", "no such target")
            if p == "/outages":
                return self._json({"outages": STATE.outages_list(qf("from", now - 86400), qf("to", now)),
                                   "status": STATE.outages_status()})
            if p == "/outages/timeline":
                return self._json(STATE.timeline(qf("hours", 24)))
            if p == "/speedtests":
                lim = int(qf("limit", 0)) or None
                return self._json({"results": STATE.speed_history(qf("from", now - 86400), qf("to", now + 1), lim),
                                   "status": STATE.speed_status()})
            if p == "/speedtests/patterns":
                return self._json(STATE.patterns(int(qf("days", 7))))
            if p == "/discovery/runs":
                return self._json({"runs": STATE.disc_runs_view(int(qf("limit", 50)))})
            if len(parts) == 3 and parts[0] == "discovery" and parts[1] == "runs":
                run = STATE.disc_run(int(parts[2]))
                return self._json(run) if run else self._error(404, "not_found", "no such run")
            if p == "/discovery/last":
                return self._json(STATE.disc_last())
            if p == "/discovery/status":
                return self._json(STATE.disc_status())
            if p == "/dhcp/status":
                return self._json(STATE.dhcp_status())
            if p == "/dhcp/leases":
                return self._json({"leases": STATE.dhcp_leases()})
            if p == "/tools/traceroute/last":
                return self._json(STATE.traceroute_last())
            if p == "/tools/lan/peers":
                return self._json(STATE.lan_peers())
            if p == "/tools/lan/throughput/last":
                return self._json(STATE.lan_throughput_last())
            if p == "/tools/wifi/profiles":
                # reveal defaults OFF, like the real route; reveal=1 needs an administrator
                reveal = str(qs.get("reveal", "0")).strip().lower() in ("1", "true", "yes", "on")
                if reveal and cross_origin_browser_request(self.headers, STATE.port):
                    return self._error(403, "forbidden", WIFI_CROSS_ORIGIN_MSG)
                if reveal and not STATE.wifi_admin:
                    return self._error(403, "admin_required", WIFI_ADMIN_REQUIRED_MSG)
                return self._json(STATE.wifi_profiles(reveal))
            if p == "/oui":
                # every value of every "prefix" parameter (qs above keeps only the last one); a GET's
                # ValueError would be a 500 in _handle, so a bad prefix is answered here
                try:
                    prefixes = oui_prefixes(parse_qs(url.query).get("prefix", []))
                except ValueError as exc:
                    return self._error(400, "bad_request", str(exc))
                return self._json({"vendors": {pre: OUI_VENDORS.get(pre) for pre in prefixes}})
            if p == "/settings":
                with STATE.lock:
                    return self._json(copy.deepcopy(STATE.settings))
            if p == "/easter":
                return self._json({"detonated": int(getattr(STATE, "easter_total", 0)), "max_sticks": 100})
            if p == "/diagnostics":
                return self._json(STATE.diagnostics())
            if p == "/diagnostics/log":
                return self._json(STATE.log_tail(int(qf("lines", 200))))
            if p == "/events":
                return self._sse()
            return self._error(404, "not_found", f"no route for GET {path}")

        if method == "POST":
            if p == "/targets":
                body = self._body()
                view = STATE.add_target(str(body.get("host", "")), body.get("label"))
                return self._json(view, 201)
            if p == "/targets/defaults":
                return self._json(STATE.load_defaults())
            if p == "/speedtests/run":
                if not STATE.speed_run():
                    return self._error(409, "conflict", "a speed test is already running")
                return self._json({"started": True})
            if p == "/discovery/scan":
                body = self._body()
                try:
                    return self._json(STATE.disc_start(body.get("range"), body.get("ports")))
                except RuntimeError as exc:
                    return self._error(409, "conflict", str(exc))
            if p == "/discovery/cancel":
                return self._json({"cancelled": STATE.disc_cancel_scan()})
            if p == "/dhcp/scan":
                body = self._body()
                return self._json(STATE.dhcp_scan(body.get("wait_s")))
            if p == "/dhcp/start":
                body = self._body()
                try:
                    return self._json(STATE.dhcp_start(bool(body.get("force"))))
                except DhcpConflict as exc:
                    return self._json(exc.payload(), 409)
            if p == "/dhcp/stop":
                return self._json(STATE.dhcp_stop())
            if p == "/tools/traceroute":
                try:
                    return self._json(STATE.traceroute(self._body()))
                except RuntimeError as exc:
                    return self._error(409, "conflict", str(exc))
            if p == "/geoip/check":
                # Retry now (tnt.api.routes.geoip_check): no body; a download in progress simply continues
                status = STATE.geoip_check()
                return self._json(status) if status is not None else self._error(409, "conflict", "IP location is switched off")
            if p == "/tools/lan/throughput":
                try:
                    return self._json(STATE.lan_throughput(self._body()))
                except RuntimeError as exc:
                    return self._error(409, "conflict", str(exc))
            if p == "/easter/detonate":
                body = self._body()
                n = int(body.get("sticks", 1))
                if not 1 <= n <= 100:
                    return self._error(400, "bad_request", "sticks must be between 1 and 100")
                with STATE.lock:
                    STATE.easter_total = int(getattr(STATE, "easter_total", 0)) + n
                    total = STATE.easter_total
                return self._json({"detonated": total, "added": n, "max_sticks": 100})
            if p == "/monitoring/pause":
                with STATE.lock:
                    STATE.paused = True
                STATE.hub.publish("monitoring.paused", {"paused": True})
                return self._json({"paused": True})
            if p == "/monitoring/resume":
                with STATE.lock:
                    STATE.paused = False
                STATE.hub.publish("monitoring.paused", {"paused": False})
                return self._json({"paused": False})
            if p == "/export":
                body = self._body()
                kind = body.get("range", "daily")
                spans = {"daily": 86400, "weekly": 7 * 86400, "monthly": 30 * 86400, "yearly": 365 * 86400}
                if kind == "custom":
                    start = float(body.get("from") or now - 86400)
                    end = float(body.get("to") or now)
                elif kind in spans:
                    start, end = now - spans[kind], now
                else:
                    raise ValueError("range must be daily, weekly, monthly, yearly or custom")
                if end <= start:
                    raise ValueError("'to' must be after 'from'")
                fmt = lambda t: time.strftime("%Y%m%d", time.localtime(t))  # noqa: E731
                name = f"TNT-report-{fmt(start)}-{fmt(end)}.pdf"
                pdf = tiny_pdf("TNT Network Report (mock)", [
                    "Period: %s to %s" % (time.strftime("%Y-%m-%d %H:%M", time.localtime(start)),
                                          time.strftime("%Y-%m-%d %H:%M", time.localtime(end))),
                    "Generated by tools/mock_api.py - not real data.",
                ])
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Length", str(len(pdf)))
                self.send_header("Content-Disposition", f"attachment; filename={name}")
                self.end_headers()
                self.wfile.write(pdf)
                return None
            return self._error(404, "not_found", f"no route for POST {path}")

        if method == "PUT":
            if p == "/settings":
                return self._json(STATE.update_settings(self._body()))
            if p == "/dhcp/settings":
                return self._json(STATE.dhcp_settings(self._body()))
            if p == "/tools/lan/settings":
                return self._json(STATE.lan_settings(self._body()))
            if p == "/targets/order":
                ids = self._body().get("ids")
                if not isinstance(ids, list) or not ids:
                    return self._error(400, "bad_request", "ids must be a non-empty list of target ids")
                with STATE.lock:
                    wanted = []
                    for i in ids:
                        try:
                            ti = int(i)
                        except (TypeError, ValueError):
                            return self._error(400, "bad_request", "ids must be integers")
                        if ti not in wanted:
                            wanted.append(ti)
                    known = {t["id"] for t in STATE.targets}
                    unknown = [i for i in wanted if i not in known]
                    if unknown:
                        return self._error(400, "bad_request", f"unknown target id(s): {unknown}")
                    by_id = {t["id"]: t for t in STATE.targets}
                    STATE.targets = [by_id[i] for i in wanted] + [t for t in STATE.targets if t["id"] not in wanted]
                    views = [STATE.target_view(t) for t in STATE.targets]
                STATE.hub.publish("ping.targets", {"targets": views})
                return self._json(views)
            return self._error(404, "not_found", f"no route for PUT {path}")

        if method == "DELETE":
            if len(parts) == 2 and parts[0] == "targets":
                if STATE.remove_target(int(parts[1])):
                    return self._json({"removed": True})
                return self._error(404, "not_found", "no such target")
            if len(parts) == 3 and parts[0] == "dhcp" and parts[1] == "leases":
                if STATE.dhcp_forget(unquote(parts[2])):
                    return self._json({"ok": True})
                return self._error(404, "not_found", "no such lease")
            return self._error(404, "not_found", f"no route for DELETE {path}")
        return self._error(405, "method_not_allowed", method)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def ticker(stop: threading.Event) -> None:
    nxt = math.floor(time.time()) + 1
    while not stop.is_set():
        delay = nxt - time.time()
        if delay > 0:
            stop.wait(delay)
            if stop.is_set():
                break
        try:
            STATE.tick(float(nxt))
            STATE.speed_tick()
            STATE.lan_tick(float(nxt))
        except Exception:  # noqa: BLE001
            log.exception("tick failed")
            time.sleep(0.5)
        nxt += 1
        if time.time() > nxt + 2:  # fell behind, realign
            nxt = math.floor(time.time()) + 1


def main(argv: Optional[List[str]] = None) -> int:
    global STATE
    ap = argparse.ArgumentParser(description="TNT mock API + UI server (dev only)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT") or 7136))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    STATE = MockState(args.port)
    try:
        httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        log.error("cannot bind %s:%d (%s) - is something else using it? try: netstat -ano | findstr :%d",
                  args.host, args.port, exc, args.port)
        return 2
    httpd.daemon_threads = True
    stop = threading.Event()
    th = threading.Thread(target=ticker, args=(stop,), name="mock-ticker", daemon=True)
    th.start()
    log.info("TNT mock API serving %s on http://%s:%d/  (Ctrl-C to stop)", UI_DIR, args.host, args.port)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        httpd.server_close()
        th.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
