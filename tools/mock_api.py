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
* Settings › History: ``POST /api/history/clear`` ``{"range": "5m" | ... | "all"}`` removes what the
  fake service recorded in that window by the service's rules (ping minutes and samples, outages
  and their events, speed tests, discovery runs, the listed captures for an administrator, the
  fault watch, the SIP results and flow slots, the Pro AV result; running jobs stop and keep
  nothing), answers the contract's dict and publishes it as ``history.cleared``; 400 ``bad_range``,
  409 ``full_scan_running`` / ``clear_running``, 403 for a page of another origin.
  ``GET /api/history`` names the eight ranges and the newest clear, and the timeline's ``cleared``
  spans are painted like a monitoring gap;
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
* the Tools page's DNS card and the top bar's quick tools (``tnt.nettools``): ``POST /api/tools/dns/lookup`` answers from
  documentation data (``DNS_ZONE`` / ``DNS_PTR``: www.example.com is a CNAME of example.com at 203.0.113.10 and 2001:db8::10,
  totalelectronics.com is 198.51.100.40, an IP address gets a PTR name, any other name "Non-existent domain", and the DNS
  server 192.0.2.1 never answers) after a short wait, with the service's 400 texts; the server asked is the one given, else
  the first DNS server of this PC's internet adapter on its network. ``POST /api/tools/dns/flush`` is ok after ~0.3 s and
  ``POST /api/tools/ip/renew`` answers after ~1.5 s with this PC's address and adapter, the DHCP adapters it went through
  and ``paused_monitoring``; 409 while one runs, 403 ``admin_required`` while ``STATE.wifi_admin`` is off. A browser page
  of another origin gets 403 ``forbidden`` from all three;
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
* the Network info card's checks (``tnt.natcheck``, ``tnt.switchport``, ``tnt.portcheck``): ``GET``/``POST /api/netcheck/nat``
  (network "a" is a single NAT behind the invented "Example Router XR-1" sharing two UPnP forwards, "b" a carrier-grade NAT,
  the others offline; a POST answers at once, or after ``STATE.nat_delay_s`` with ``running`` true and 409 meanwhile),
  ``GET``/``POST``/``DELETE /api/netcheck/switch`` (the network's wired adapters; a listen lasts ``STATE.switch_listen_s`` and
  hears LAB-SW-01 Port 7 with ``netcheck.switch`` events, or nothing with ``STATE.switch_found`` off) and ``POST
  /api/netcheck/portforward`` (after ``STATE.portcheck_delay_s`` TCP 8000 answers, 9 reaches no port checker and any other
  port does not answer; the service's gap and per-hour limits are ``STATE.portcheck_min_gap_s`` / ``portcheck_per_hour``, 0
  switches one off). A network change clears the three results. ``STATE.pktmon_reason`` makes Packet Monitor unavailable;
* the TFTP server card (``tnt.tftp``): ``/api/tftp/status``, ``start``, ``stop``, ``uploads``, ``settings`` and ``files`` with
  the service's shapes and 400 texts, off at start, ``status.tftp`` its summary. A phone reads its configuration file ~1.5 s
  after a start (``tftp.transfer``); ``STATE.tftp_port_owners`` makes a start 409 ``tftp_port_in_use``, and a network change
  stops a running server with "stopped: the adapter changed";
* packet capture (``tnt.capture``), the live analyser on its own page: ``/api/capture`` with ``start``, ``stop``, ``save``,
  ``discard``, ``open``, ``packets``, ``packets/{no}``, ``calls``, ``calls/{id}/audio`` and ``files/{name}`` below it, every
  one 403 ``admin_required`` while ``STATE.wifi_admin`` is off. A start invents traffic on a background thread, 8-25 packets
  a second, until ``STATE.capture_s`` passes (None: the ``max_seconds`` it was started with) or the byte budget runs out,
  then stops with the matching ``stop_reason``. The rows use documentation addresses (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24, 2001:db8::/32) and locally administered MACs only - never a real public address, never a real MAC - mixed
  so every protocol button of the page finds something (TCP, UDP, TLS, HTTP, DNS, ICMP, ARP, DHCP, RTSP, RTP, SIP), and a
  few seconds in a scripted SIP call rings, answers, talks RTP both ways and hangs up: one ``capture.sip`` event, the call
  on ``GET /api/capture/calls`` and ``calls/{id}/audio`` a real 8 kHz 16-bit mono WAV the page's player can play.
  ``capture.state`` carries the session about once a second and on every change (on ``/api/events`` only while
  ``STATE.wifi_admin`` is on, with ``capture.sip``: the service sends both to an administrator only). ``packets`` filters and
  pages exactly as ``CaptureManager.packets`` does and ``packets/{no}`` answers the detail tree and hex dump of the bytes the
  mock made up for that row. Saving lists a file whose download is a tiny valid pcapng, and opening one reads an invented
  packet list of its length back. A browser page of another origin gets 403 ``forbidden`` from every POST and DELETE of
  these routes and from the download. ``STATE.capture_reason`` is the text that makes capturing unavailable here (a
  capture no longer shares Packet Monitor with the switch port search: it runs its own ETW session, so the two can run
  together);
* the latency-under-load grade (``tnt.speedtest.quality``): every speed test carries ``quality`` (graded by the service's rules
  from invented probe windows, None for a failed test), ``/api/speedtests`` rows leave it out, and a run starts with the
  0.8 s idle ``baseline`` phase. The DNS card's record types (``type``: MX, TXT, NS, SOA, CAA and NAPTR of example.com, SRV of
  _sip._tcp.example.com, PTR of 10.113.0.203.in-addr.arpa) answer typed lookups; Auto still reads CNAME, A and AAAA only.

* the Pro AV page (``tnt.proav``), a whole invented broadcast-audio room: ``GET /api/proav`` is the STATUS with two
  adapters, ``POST /api/proav/scan`` ``{"seconds"?, "adapter"?, "deep"?}`` starts a listen that finishes in
  ``PROAV_FAKE_LISTEN_S`` however long was asked for (``proav.progress`` a dozen times, then ``proav.state``),
  ``POST /api/proav/cancel`` ends it early and ``GET /api/proav/result`` is the whole RESULT. The room is a Dante
  system on a GPS-locked grandmaster one boundary clock away, three announced AES67 streams (one still naming the
  grandmaster it was set up against: the "bad" finding), a transparent clock, an IGMP querier and a UniFi AV switch
  on LLDP. ``deep`` false leaves the Layer 2 listen and its three checks out. ``STATE.proav_reason`` makes scanning
  unavailable.

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
import struct
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
    # Network info > Realtime throughput: adapters left off the card, by Windows connection name
    "throughput": {"excluded": []},
    "ui": {"theme": "light", "show_ipv6": False},
    "lan": {"enabled": True},
    "geoip": {"enabled": True},
    "update": {"enabled": True, "auto_install": False, "check_interval_h": 24, "channel": "stable"},
    "targets": {"defaults_extra": ["1.1.1.1", "totalelectronics.com"]},
    "dhcp": {"adapter": "", "pool_start": "", "pool_end": "", "pool_size": 5, "lease_s": 3600,
             "static_ip": "172.16.4.100", "static_prefix": 24, "ping_check": True, "scan_wait_s": 8},
    "tftp": {"adapter": "", "max_upload_mb": 4096},
    "sip": {"host": "", "port": 5060, "window_h": 24,
            "stun": ["stun.l.google.com:19302", "stun.cloudflare.com:3478"]},
    # Settings > Tools (tnt.config.TOOLS): a tool that is off has no tile, no page and no automated action
    "tools": {"speed": True, "discovery": True, "wifi": True, "capture": True, "proav": True, "sip": True},
}
#: the main tools Settings can switch off, in tile order
TOOLS = ("speed", "discovery", "wifi", "capture", "proav", "sip")
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
# auto-update (tnt.updater): the key set and states are the service's (tests/test_ui.py compares them)
UPDATE_STATUS_KEYS = ("enabled", "state", "current_version", "latest_version", "latest_ts", "notes_url",
                      "asset", "checked_ts", "next_check_ts", "download", "error", "auto_install")
UPDATE_STATES = ("disabled", "idle", "checking", "up_to_date", "available", "downloading", "verifying",
                 "ready", "installing", "error")
UPDATE_LATEST_VERSION = "1.1.0"           # the version the fake "available"/"downloading"/... states offer
UPDATE_SETUP_BYTES = 41_500_000
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
    "apipa_ipv6": "Self-assigned IPv4 address {address}: no DHCP server answered, but IPv6 works (this network may be IPv6-only)",
    "duplicate_address": "{address} is already used by another device on this network",
    "gateway_outside_subnet": "Gateway {gateway} is outside this adapter's subnet {network}: check the IP address and subnet mask",
    "no_dns": "No DNS servers: host names will not resolve",
    # the fakes only ever name another adapter with another gateway address, so it is always the different-router wording
    "multiple_default_gateways": "{other} also has a default gateway: a different router ({other_gateway}); "
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


# -- realtime throughput (tnt.throughput) ------------------------------------------------
#: tnt.throughput.WINDOWS / NIC_KEYS / VIEW_KEYS; a test asserts these still match the service's.
TP_WINDOWS = (10, 30, 60, 300, 1800)
TP_DEFAULT_WINDOW_S = 30
TP_HISTORY_S = 1800
TP_MAX_POINTS = 600
TP_NIC_KEYS = ("id", "index", "name", "description", "type", "primary", "link_bps",
               "rx_bps", "tx_bps", "rx_pps", "tx_pps", "avg_rx_bps", "avg_tx_bps", "peak_rx_bps", "peak_tx_bps",
               "rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "samples")
TP_VIEW_KEYS = ("ts", "window_s", "step_s", "history_s", "windows", "nics", "note")
#: What each adapter pretends to carry: (receive Mbps, send Mbps, how much it swings).  An adapter that is
#: not named here moves nothing, which is what the Hyper-V switch looks like on a real machine - and what
#: gives the card a NIC to leave out.
TP_SHAPES = {
    "Ethernet": (7.4, 0.42, 0.85),
    "Ethernet 2": (0.9, 0.11, 0.35),
    "Wi-Fi": (4.2, 0.30, 0.90),
    "Tailscale": (0.06, 0.44, 0.30),
}
#: Bytes per packet each way.  Receive is near a full frame and send is ack-sized, which is why a browsing
#: machine's packet counts are so much closer together than its byte counts.
TP_RX_FRAME = 1180
TP_TX_FRAME = 320


def tp_rate(name: str, ts: float) -> Tuple[int, int]:
    """(receive, send) bits per second for one adapter at *ts*: a slow swell, a faster ripple and a burst
    every so often, all worked out from the timestamp, so the backlog GET /api/throughput hands over and
    the events that follow it describe the same traffic."""
    shape = TP_SHAPES.get(name)
    if not shape:
        return (0, 0)
    base_rx, base_tx, swing = shape
    swell = 1.0 + swing * math.sin(ts / 17.0)
    ripple = 1.0 + (swing / 3.0) * math.sin(ts / 2.3 + 1.7)
    burst = 3.4 if (int(ts) % 47) < 4 else 1.0          # a download starting, every so often
    rx = base_rx * swell * ripple * burst * 1e6
    tx = base_tx * swell * ripple * (1.0 + (burst - 1.0) * 0.25) * 1e6
    return (max(0, int(rx)), max(0, int(tx)))


def _tp_bucket(samples: List[List[int]], step: int) -> List[List[int]]:
    """tnt.throughput._bucket: average the per-second samples into `step` buckets, oldest first."""
    if step <= 1:
        return [list(s) for s in samples]
    acc: Dict[int, List[float]] = {}
    for s in samples:
        key = int(s[0]) // step * step
        row = acc.setdefault(key, [0.0, 0.0, 0.0, 0.0, 0.0])
        for i in range(4):
            row[i] += float(s[i + 1])
        row[4] += 1.0
    out = []
    for key in sorted(acc):
        row = acc[key]
        n = row[4] or 1.0
        out.append([key] + [int(round(row[i] / n)) for i in range(4)])
    return out


def _tp_mean(samples: List[List[int]], column: int) -> int:
    if not samples:
        return 0
    return int(round(sum(float(s[column]) for s in samples) / len(samples)))


def _tp_order(row: Dict[str, Any]) -> Tuple[int, int, str]:
    """tnt.throughput._order: the internet-facing NIC first, then the busiest, then by name."""
    return (0 if row.get("primary") else 1,
            -(int(row.get("rx_bps") or 0) + int(row.get("tx_bps") or 0)), str(row.get("name") or ""))


# -- faults: the passive watch (tnt.faults) ----------------------------------------------
#: tnt.faults' shapes; a test asserts these still match the service's.
FAULT_LEVELS = ("bad", "warn", "info", "good")
FAULT_FINDING_KEYS = ("id", "level", "title", "detail", "advice", "evidence")
FAULT_NIC_KEYS = ("name", "description", "index", "link_bps", "watched_s", "up", "last_read_s",
                  "rx_errors", "tx_errors", "rx_discards", "tx_discards",
                  "new_rx_errors", "new_tx_errors", "new_rx_discards", "new_tx_discards",
                  "new_rx_packets", "new_tx_packets", "error_pct", "discard_pct",
                  "window_s", "recent_rx_errors", "recent_tx_errors", "recent_rx_discards", "recent_tx_discards",
                  "recent_rx_packets", "recent_tx_packets")
#: tnt.faults.RATE_WINDOW_S: the levels judge this much of the most recent readings
FAULT_RATE_WINDOW_S = 300.0
FAULT_VIEW_KEYS = ("ts", "watching_since", "watched_s", "level", "findings", "nics", "arp", "note")
FAULT_TILE_KEYS = ("available", "reason", "level", "bad", "warn", "headline", "watched_s", "clean_s", "ts")
FAULT_MIN_WATCH_S = 60.0
#: The fake site has one bad patch lead on "Ethernet 2", which is the whole point of the page: a
#: tech should be able to see what a real fault reads like without breaking a real network.
FAULT_ERROR_NIC = "Ethernet 2"
FAULT_ERROR_RATE = 0.9          # damaged frames a second on that adapter
FAULT_DISCARD_NIC = "Ethernet"
FAULT_DISCARD_RATE = 2.2        # frames a second it queued to send and dropped (the only discards judged)


def _fault_duration(seconds: float) -> str:
    """tnt.faults._duration: "45 seconds", "3 minutes", "1 h 20 min"."""
    s = max(0, int(seconds))
    if s < 90:
        return f"{s:,} second" + ("" if s == 1 else "s")
    minutes = s // 60
    if minutes < 90:
        return f"{minutes:,} minute" + ("" if minutes == 1 else "s")
    return f"{minutes // 60} h {minutes % 60:02d} min"


def _fault_worst(findings: List[Dict[str, Any]]) -> str:
    """tnt.faults.worst_level: the worst level present, "good" for nothing at all."""
    order = {level: i for i, level in enumerate(FAULT_LEVELS)}
    worst = "good"
    for f in findings or []:
        if order.get(str(f.get("level")), 99) < order.get(worst, 99):
            worst = str(f.get("level"))
    return worst


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
    # tnt.netinfo._global_ipv6: the first IPv6 address that is not link-local (the fakes have no temporaries)
    v6 = next((e["address"] for e in nic["ipv6"] if not e["address"].lower().startswith("fe80:")), None)
    return {"index": nic["index"], "name": nic["name"], "description": nic["description"], "type_name": nic["type_name"],
            "ipv4": first["address"] if first else None, "network": first["network"] if first else None, "ipv6": v6,
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
#: Tools: DNS lookup, Flush DNS and IP Release/Renew (tnt.nettools; POST /api/tools/dns/lookup, /dns/flush, /ip/renew): the keys
#: of the service's answers, in its order (tests/test_ui.py holds them to tnt.nettools)
DNS_RESULT_KEYS = ("name", "type", "server", "resolver", "answer_name", "addresses", "aliases", "records", "authoritative", "ok",
                   "error", "duration_ms", "ts")
DNS_RECORD_KEYS = ("type", "name", "value", "ttl")
#: the record types a lookup may ask for (tnt.nettools.DNS_TYPES); none (Auto) asks for A and AAAA, or PTR for an address
DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "PTR", "NAPTR")
#: the pseudo-type "ALL" fans these out (tnt.nettools.ALL_TYPES); PTR is left out (it is only for addresses)
DNS_ALL_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "NAPTR")
FLUSH_RESULT_KEYS = ("ok", "method", "error", "duration_ms", "ts")
RENEW_RESULT_KEYS = ("ok", "address", "adapter", "adapters", "warnings", "paused_monitoring", "method", "error", "duration_ms", "ts")
RENEW_ADAPTER_KEYS = ("name", "released", "renewed", "error")
NETTOOLS_ROUTES = ("/tools/dns/lookup", "/tools/dns/flush", "/tools/ip/renew")
#: the fake DNS, documentation names and addresses only: name -> the answer's records in answer order (type, owner, value, ttl),
#: the values in tnt.nettools' formats. Auto reads the CNAME, A and AAAA rows: a name listed without address records answers "No
#: addresses found for this name", a name not listed "Non-existent domain". A typed lookup reads the CNAME rows and the rows of
#: its type at the end of the chain ("No MX records found for this name" when there are none)
DNS_ZONE: Dict[str, List[Tuple[str, str, str, int]]] = {
    "www.example.com": [("CNAME", "www.example.com", "example.com", 3600), ("A", "example.com", "203.0.113.10", 300),
                        ("AAAA", "example.com", "2001:db8::10", 300)],
    "example.com": [("A", "example.com", "203.0.113.10", 300), ("AAAA", "example.com", "2001:db8::10", 300),
                    ("MX", "example.com", "10 mail.example.com", 3600), ("MX", "example.com", "20 mail2.example.com", 3600),
                    ("TXT", "example.com", "v=spf1 ip4:203.0.113.0/24 -all", 3600),
                    ("NS", "example.com", "ns1.example.net", 86400), ("NS", "example.com", "ns2.example.net", 86400),
                    ("SOA", "example.com", "ns1.example.net hostmaster.example.com 2026091301 7200 3600 1209600 300", 3600),
                    ("CAA", "example.com", '0 issue "letsencrypt.org"', 3600),
                    ("NAPTR", "example.com", '100 10 "S" "SIP+D2U" "" _sip._udp.example.com', 3600)],
    "_sip._tcp.example.com": [("SRV", "_sip._tcp.example.com", "10 60 5060 sip.example.com", 3600)],
    "10.113.0.203.in-addr.arpa": [("PTR", "10.113.0.203.in-addr.arpa", "example.com", 3600)],
    "example.net": [("A", "example.net", "198.51.100.20", 600)],
    "ns1.example.net": [("A", "ns1.example.net", "198.51.100.53", 3600)],
    "totalelectronics.com": [("A", "totalelectronics.com", "198.51.100.40", 3600)],
    "mail.example.com": [],
}
#: the PTR names of the fake addresses (a DNS server's name comes from here too); any other address is host-<address>.example.net
DNS_PTR = {"203.0.113.10": "example.com", "2001:db8::10": "example.com", "198.51.100.20": "example.net", "198.51.100.53": "ns1.example.net",
           "198.51.100.40": "totalelectronics.com", "10.0.0.251": "gateway.lan", "192.168.50.1": "router.site-b.example"}
#: a DNS server that never answers
DNS_SILENT_SERVER = "192.0.2.1"
#: the service's texts (tnt.nettools EMPTY_NAME_TEXT, NO_SERVER_TEXT, TIMEOUT_TEXT, NO_ADDRESSES_TEXT, RCODE_TEXT[3],
#: NO_DHCP_ADAPTER_TEXT, NO_ADDRESS_TEXT)
DNS_NAME_REQUIRED_MSG = "Type a DNS name or IP address to look up"
DNS_NO_SERVER_MSG = "No DNS server is configured on this PC"
DNS_TIMEOUT_MSG = "No response from the DNS server (timed out)"
DNS_NO_ADDRESSES_MSG = "No addresses found for this name"
DNS_NXDOMAIN_MSG = "Non-existent domain"
#: a typed lookup's texts (tnt.nettools NO_RECORDS_TEXT and BAD_TYPE_TEXT, both templates, and IP_TYPE_TEXT) and the route's check
DNS_NO_RECORDS_MSG = "No {} records found for this name"
DNS_BAD_TYPE_MSG = '"{}" is not a DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR or NAPTR)'
DNS_IP_TYPE_MSG = "An IP address is looked up as PTR: type a DNS name to ask for other record types"
DNS_TYPE_NOT_TEXT_MSG = "type must be text or null"
IP_RENEW_NO_DHCP_MSG = "No adapter gets its address from DHCP"
IP_RENEW_NO_ADDRESS_MSG = "No IPv4 address after renewing: the DHCP server did not answer"
#: the service's 403 when a non-admin asks for a release/renew (tnt.api.routes.IP_RENEW_ADMIN_REQUIRED_MSG), its 409 while one
#: runs (tnt.engine) and its 403 forbidden for a browser page of another origin (tnt.api.routes.QUICK_TOOLS_CROSS_ORIGIN_MSG;
#: the real server refuses a cross-site POST before its routes, in words of its own)
IP_RENEW_ADMIN_REQUIRED_MSG = "Releasing and renewing IP addresses needs a Windows administrator account."
IP_RENEW_BUSY_MSG = "An IP release/renew is already running"
#: the service's 403 when a non-admin asks to install an update (tnt.api.routes.UPDATE_ADMIN_REQUIRED_MSG)
UPDATE_ADMIN_REQUIRED_MSG = "Installing an update needs a Windows administrator account."
QUICK_TOOLS_CROSS_ORIGIN_MSG = "This tool only answers the TNT window or a page served by this TNT service."
#: a host-name label, like tnt.nettools._LABEL_RE: letters, digits, "_" and "-", 1-63 characters, not starting or ending with "-"
_DNS_LABEL_RE = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?")
#: Network info: the NAT check (tnt.natcheck). The key tuples, texts and errors are the service's (tests/test_ui_115.py holds them to it)
NAT_VERDICTS = ("no_nat", "single_nat", "double_nat", "cgnat", "upstream_nat", "nat_unclear_private_wan", "vpn", "offline", "unknown")
NAT_RESULT_KEYS = ("ts", "generation", "duration_ms", "verdict", "confidence", "title", "explanation", "router", "public_ip", "trace",
                   "port_mappings", "error")
ROUTER_KEYS = ("gateway", "wan_ip", "wan_source", "natpmp", "upnp")
NATPMP_KEYS = ("answered", "result", "external_ip")
UPNP_KEYS = ("found", "server", "model", "service", "status", "external_ip", "error")
TRACE_KEYS = ("reached_ttl", "hops")
HOP_KEYS = ("ttl", "ip", "rtt_ms", "range")
PORT_MAPPINGS_KEYS = ("entries", "truncated", "error")
MAPPING_KEYS = ("protocol", "external_port", "internal_client", "internal_port", "enabled", "description", "lease_s")
CONFIDENCES = ("high", "medium", "low")
#: verdict -> (title, explanation), shown verbatim
NAT_TEXT: Dict[str, Tuple[str, str]] = {
    "no_nat": ("No NAT", "This PC has the public address itself. Nothing to forward: Windows Firewall decides what gets in."),
    "single_nat": ("Single NAT", "One router holds the public address. Port forwards on it work, unless the ISP blocks the port."),
    "double_nat": ("Double NAT", "Another NAT sits between this network's router and the internet (usually the ISP modem or gateway, "
                                 "sometimes the ISP itself). Forward ports on both, or put the ISP box in bridge / IP-passthrough mode."),
    "cgnat": ("Carrier-grade NAT (CGNAT)", "The ISP shares one public address between customers, so port forwarding from the internet "
                                           "cannot work on IPv4. Ask the ISP for a public or static IP, or use the device's cloud/P2P "
                                           "service or a VPN."),
    "upstream_nat": ("NAT beyond the router", "Websites see an address the router does not have, so something beyond it translates "
                                              "again (ISP NAT, an upstream firewall, a second line or a VPN)."),
    "nat_unclear_private_wan": ("Probably behind another NAT", "The router reports no usable public address although the internet "
                                                               "works. That usually means it sits behind another NAT."),
    "vpn": ("Traffic leaves through a VPN", "This PC's internet traffic goes through a VPN, so a check would describe the VPN, not this "
                                            "site's router. Disconnect it and check again."),
    "offline": ("Could not check", "No internet connection (or no public address yet), so NAT cannot be checked."),
    "unknown": ("Could not tell", "The router does not answer UPnP or NAT-PMP and the path gave no clear sign."),
}
NAT_NO_INTERNET_ERROR = "no internet connection"
NAT_NO_PUBLIC_IP_ERROR = "no public address yet"
NAT_NO_GATEWAY_ERROR = "no IPv4 gateway"
NAT_CONTROL_NOT_ROUTER_ERROR = "the router's control address is not the router"
NAT_MAPPINGS_NOT_SHARED_ERROR = "the router does not share its port forwards"
NAT_BUSY_TEXT = "a NAT check is already running"
#: the invented router of network "a" (the build contract's stand-ins), its UPnP service and the forwards it shares:
#: (protocol, external port, internal client, internal port, enabled, description, lease s); network "b"'s carrier address
NAT_ROUTER_SERVER = "ExampleOS/1.0 UPnP/1.1 MiniUPnPd/2.2.0"
NAT_ROUTER_MODEL = "Example Router XR-1"
NAT_UPNP_SERVICE = "urn:schemas-upnp-org:service:WANIPConnection:1"
NAT_PORT_MAPPINGS = (("TCP", 8000, "10.0.0.60", 8000, True, "NVR web", 0), ("TCP", 554, "10.0.0.61", 554, True, "Camera RTSP", 0))
NAT_CGNAT_WAN_IP = "100.64.0.10"
NAT_PROBE_MS = 640                      # what the probes of a check take, added to a POST's own time
#: Network info: the switch port finder (tnt.switchport, tnt.lldp) and the Packet Monitor texts it shares with capture (tnt.pktmon)
SWITCH_JOB_KEYS = ("state", "adapter", "started_ts", "listen_s", "elapsed_s", "neighbors", "error", "reason", "generation", "ts")
SWITCH_STATUS_KEYS = ("job", "adapters", "available", "reason")
SWITCH_JOB_ADAPTER_KEYS = ("name", "index", "mac")
SWITCH_WIRED_ADAPTER_KEYS = ("name", "index", "mac", "is_internet")
SWITCH_JOB_STATES = ("idle", "listening", "done", "error", "cancelled")
NEIGHBOR_KEYS = ("protocol", "switch_name", "switch_description", "vendor", "chassis_id", "port_id", "port_description", "vlan",
                 "voice_vlan", "management_ips", "capabilities", "poe", "link", "ttl_s")
SWITCH_DEFAULT_SECONDS = 65
SWITCH_SECONDS_RANGE = (20, 120)
SWITCH_SECONDS_TEXT = "seconds must be a whole number from 20 to 120"
SWITCH_ADAPTER_TEXT = "adapter '{name}' is not a wired adapter that is up"
SWITCH_NO_WIRED_TEXT = "Needs a wired (Ethernet) connection"
SWITCH_BUSY_TEXT = "a switch port search is already running"
SWITCH_NO_NEIGHBOR_TEXT = ("No LLDP or CDP heard in {seconds} s. The switch may not send them (unmanaged switches never do), "
                           "or LLDP is turned off on its port.")
PKTMON_REASONS = ("Needs Windows 10 version 2004 (build 19041) or later", "Packet Monitor (pktmon.exe) is missing from this PC",
                  "Packet Monitor on this PC is too old for this: update Windows")
#: who holds Packet Monitor -> the 409 the other one gets (a packet capture runs its own ETW session and never takes it)
PKTMON_LOCK_TEXTS = {"switchport": "TNT is finding the switch port: try again when it finishes"}
#: what a listen hears: the invented switch of the build contract, on a documentation management address
MOCK_NEIGHBOR = {"protocol": "lldp", "switch_name": "LAB-SW-01", "switch_description": "Example Switch 8P", "vendor": "Example Networks",
                 "chassis_id": "02:00:5E:10:00:02",
                 "port_id": "Port 7", "port_description": None, "vlan": 10, "voice_vlan": 20, "management_ips": ["192.0.2.2"],
                 "capabilities": ["bridge"], "poe": {"class": 4, "allocated_w": 24.0},
                 "link": {"autoneg": True, "mau": 30, "text": "1000BASE-T full"}, "ttl_s": 120}
#: Network info: the port-forward test (tnt.portcheck): keys, texts, providers and the default rate limits
PORTCHECK_RESULT_KEYS = ("ts", "generation", "port", "protocol", "public_ip", "reachable", "provider", "detail", "nat_verdict", "error",
                         "duration_ms")
PORTCHECK_PROTOCOL = "tcp"
PORTCHECK_PROVIDERS = ("portchecker.io", "globalping")
PORTCHECK_PROVIDER_NAMES = {"portchecker.io": "portchecker.io", "globalping": "Globalping"}
PORTCHECK_PORT_TEXT = "port must be a whole number from 1 to 65535"
PORTCHECK_VPN_TEXT = ("This PC's internet goes through a VPN, so the test would check the VPN's address, not this site's: disconnect "
                      "the VPN first")
PORTCHECK_NO_IP_TEXT = ("This network's public IPv4 address is not known yet (or it has none): wait for the WAN address on the link "
                        "map, then test again")
PORTCHECK_BUSY_TEXT = "a port-forward test is already running"
PORTCHECK_RATE_TEXT = "Too many tests: wait {seconds} s"
PORTCHECKER_OPEN_DETAIL = "portchecker.io connected to the port"
PORTCHECKER_CLOSED_DETAIL = "portchecker.io could not connect (tried twice)"
PORTCHECK_FAILED_TEXT = "The port checkers could not be reached: {reason}"
PORTCHECK_REASON_TIMEOUT = "did not answer in time"
PORTCHECK_MIN_GAP_S = 5.0
PORTCHECK_PER_HOUR = 30
PORTCHECK_RATE_WINDOW_S = 3600.0
#: the fake internet: something answers on TCP 8000, a test of port 9 reaches neither port checker, every other port stays shut
PORTCHECK_OPEN_PORT = 8000
PORTCHECK_ERROR_PORT = 9
#: the network tools' routes (below /api) a browser page of another origin may not POST, PUT or DELETE, the packet capture
#: routes that change something among them, plus the capture downloads (tnt.api.routes._quick_tool_origin, ._capture)
NETWORK_TOOL_ROUTES = ("/proav/scan", "/proav/cancel",
                       "/netcheck/nat", "/netcheck/switch", "/netcheck/portforward", "/capture/start", "/capture/stop",
                       "/capture/save", "/capture/discard", "/capture/open", "/tftp/start", "/tftp/stop",
                       "/tftp/uploads", "/tftp/settings",
                       "/sip/alg", "/sip/stun", "/sip/stun/lifetime", "/sip/flow")
CAPTURE_FILES_ROUTE = "/capture/files/"
#: Settings › History (tnt.history): the eight ranges, key -> seconds (None: all time) and label, in the service's order
HISTORY_RANGES = {"5m": 300, "30m": 1800, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000, "all": None}
HISTORY_RANGE_LABELS = {"5m": "Last 5 minutes", "30m": "Last 30 minutes", "1h": "Last hour", "6h": "Last 6 hours",
                        "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", "all": "All time"}
#: the eight counts of a clear's `cleared`, always all of them
HISTORY_CLEARED_KEYS = ("ping", "outages", "speed", "discovery", "captures", "faults", "sip", "proav")
HISTORY_SPANS_KEEP = 50                    # cleared spans kept for the timeline, newest last
HISTORY_SPAN_MAX_AGE_S = 30 * 86400        # ... and none older than this
HISTORY_PING_HORIZON_S = 30 * 86400        # how far back the fake ping minutes go (the service's retention)
HISTORY_BAD_RANGE_MSG = "range must be one of: " + ", ".join(HISTORY_RANGES)
HISTORY_FULL_SCAN_MSG = "A Full Scan is running and reads this history as it goes. Clear it once the scan has finished."
HISTORY_CLEAR_RUNNING_MSG = "History is already being cleared. Try again in a moment."
HISTORY_CAPTURES_ADMIN_MSG = "TNT is not running as administrator, so its packet captures were left alone"
HISTORY_CAPTURE_RECORDING_MSG = "a capture is recording: it was left alone (stop it, then clear again to remove it)"
HISTORY_CANCEL_REASON = "history cleared"
#: Tools: the TFTP server (tnt.tftp): keys, texts and limits
TFTP_STATUS_KEYS = ("available", "running", "since_ts", "error", "warning", "adapter", "adapters", "listen", "root", "uploads", "firewall",
                    "conflict", "transfers", "history", "counts", "settings")
TFTP_SUMMARY_KEYS = ("available", "running", "adapter", "listen_ips", "active", "uploads", "since_ts", "error")
TFTP_TRANSFER_KEYS = ("id", "client", "op", "file", "mode", "blksize", "windowsize", "size", "bytes", "state", "error", "started_ts",
                      "ended_ts")
TFTP_ADAPTER_KEYS = ("name", "index", "ip", "prefix", "type_name", "is_physical", "is_internet", "status")
TFTP_COUNT_KEYS = ("active", "done", "unconfirmed", "failed", "cancelled", "busy")
TFTP_SETTINGS_KEYS = ("adapter", "max_upload_mb")
TFTP_TRANSFER_STATES = ("negotiating", "sending", "receiving", "done", "unconfirmed", "failed", "cancelled")
TFTP_FIREWALL_RULE = "TNT TFTP server (UDP 69 in)"
TFTP_PORT = 69
TFTP_ROOT = "C:\\ProgramData\\TNT\\tftp"
TFTP_HISTORY_KEEP = 50
TFTP_MAX_UPLOAD_MB = (1, 65536)
TFTP_MAX_UPLOAD_MB_TEXT = "max_upload_mb must be a whole number from 1 to 65536"
TFTP_PORT_IN_USE_CODE = "tftp_port_in_use"
TFTP_MSG_CANCELLED = "Transfer cancelled"
#: what a network change does to a running mock server (the service names the adapter's problem)
TFTP_STOPPED_TEXT = "stopped: the adapter changed"
#: the files in the root folder: (name with "/", size, age in seconds at service start)
TFTP_FILES = (("boot/pxelinux.0", 26_828, 86400 * 12), ("firmware/lab-sw-fw-2.4.1.bin", 7_843_532, 86400 * 3),
              ("phones/SEP02005E100001.cnf.xml", 4_912, 3600 * 5))
#: Packet capture (tnt.capture), the live analyser on its own page: every shape it answers, keys in the service's order
CAPTURE_STATUS_KEYS = ("available", "reason", "adapters", "session", "files", "limits")
CAPTURE_SESSION_KEYS = ("id", "state", "source", "adapter", "file", "saved", "started_ts", "first_ts", "elapsed_s",
                        "packets", "shown", "bytes", "dropped", "truncated", "calls", "stop_reason", "error", "ts")
CAPTURE_ROW_KEYS = ("no", "ts", "rel", "src", "dst", "src_mac", "dst_mac", "proto", "sport", "dport", "length", "info")
CAPTURE_FILE_KEYS = ("name", "size", "created_ts", "packets")
CAPTURE_ADAPTER_KEYS = ("name", "index", "mac", "type_name", "wifi")
CAPTURE_LIMIT_KEYS = ("max_rows", "max_packets", "seconds", "sizes_mb", "default_seconds", "default_mb")
CAPTURE_PACKETS_KEYS = ("rows", "total", "shown", "matched", "last", "dropped_before", "session")
CAPTURE_DETAIL_KEYS = ("row", "layers", "hex", "bytes")
CAPTURE_LAYER_KEYS = ("name", "summary", "start", "length", "fields")
CAPTURE_FIELD_KEYS = ("name", "value", "start", "length")
CAPTURE_TILE_KEYS = ("available", "reason", "running", "adapter", "packets", "calls", "files")
#: the SIP call the capture rebuilds and its RTP streams (tnt.sipcalls: CALL_KEYS, STREAM_KEYS, MESSAGE_KEYS)
SIP_CALL_KEYS = ("id", "call_id", "from_uri", "to_uri", "state", "start_ts", "answer_ts", "end_ts", "duration_s",
                 "status", "messages", "streams", "note")
SIP_STREAM_KEYS = ("id", "src", "sport", "dst", "dport", "ssrc", "payload_type", "codec", "packets", "lost",
                   "out_of_order", "first_ts", "last_ts", "duration_s", "bytes", "jitter_ms", "decodable")
SIP_MESSAGE_KEYS = ("ts", "kind", "method", "status", "reason", "src", "dst", "cseq", "cseq_method", "via_branch",
                    "contact", "user_agent", "has_sdp", "sdp_c", "where", "side")
CAPTURE_SESSION_STATES = ("capturing", "stopped", "loaded", "error")
CAPTURE_STOP_REASONS = ("user", "seconds", "size", "packets", "adapter", "service")
CAPTURE_SECONDS = (60, 300, 900, 1800, 3600)       # what the start choices offer, and what the API accepts
CAPTURE_SIZES_MB = (64, 128, 256, 512, 1024)
CAPTURE_DEFAULT_SECONDS = 900
CAPTURE_DEFAULT_MB = 256
CAPTURE_MAX_ROWS = 50_000                          # rows held in memory; past that the oldest falls off the front
CAPTURE_MAX_PACKETS = 5_000_000
CAPTURE_ROW_LIMIT = 500                            # GET /api/capture/packets?limit= : its default and its cap
CAPTURE_MAX_ROW_LIMIT = 2000
CAPTURE_TICK_S = 1.0                               # how often capture.state goes out while a capture runs
CAPTURE_FILE_RE = r"^TNT-capture-\d{8}-\d{6}\.pcapng$"
CAPTURE_ADAPTER_TEXT = "adapter '{name}' is not up"
CAPTURE_SECONDS_TEXT = "max_seconds must be one of 60, 300, 900, 1800 or 3600"
CAPTURE_SIZE_TEXT = "max_mb must be one of 64, 128, 256, 512 or 1024"
CAPTURE_BUSY_TEXT = "A capture is already running: stop it first"
CAPTURE_NOTHING_TEXT = "No capture is open"
CAPTURE_FILE_MISSING_TEXT = "The capture file was not found"
#: opening any capture file on this PC by its full path (tnt.capture.open_path)
CAPTURE_PATH_TEXT = "path must be the full path of a file on this PC"
CAPTURE_PATH_BIG_TEXT = "That file is larger than {mb} MB, which is more than TNT opens"
CAPTURE_MAX_OPEN_BYTES = 4 * 1024 ** 3
CAPTURE_MAX_PATH_LEN = 4096
CAPTURE_PACKET_GONE_TEXT = "That packet is no longer in the list"
CAPTURE_NO_AUDIO_TEXT = "That call has no audio TNT can play"
#: the routes' 403 for a standard user, and for a caller the service could not identify (the mock's callers always are)
CAPTURE_ADMIN_REQUIRED_MSG = "Packet capture needs a Windows administrator account."
CAPTURE_ADMIN_UNVERIFIED_MSG = "Packet capture needs a Windows administrator account; this request could not be verified as one."
#: the event types /api/events sends only while STATE.wifi_admin is on (the service's routes.ADMIN_ONLY_EVENTS)
ADMIN_ONLY_EVENTS = frozenset({"capture.state", "capture.sip"})
#: the protocol keys the page's filter buttons send -> the proto and layer names they match (tnt.dissect.PROTO_FILTERS)
CAPTURE_PROTO_FILTERS = {
    "icmp": ("ICMP", "ICMPv6"), "arp": ("ARP",), "dns": ("DNS", "MDNS", "LLMNR", "NBNS"), "dhcp": ("DHCP", "DHCPv6"),
    "http": ("HTTP",), "https": ("TLS", "QUIC"), "tls": ("TLS",), "sip": ("SIP",), "rtp": ("RTP", "RTCP"),
    "rtsp": ("RTSP",), "tcp": ("TCP",), "udp": ("UDP",), "ipv4": ("IPv4",), "ipv6": ("IPv6",), "vlan": ("802.1Q",),
    "ntp": ("NTP",), "snmp": ("SNMP",), "smb": ("SMB",), "tftp": ("TFTP",), "quic": ("QUIC",),
}
#: the saved capture the mock starts with (2026-01-01 12:00:00 local time), for the page's "Open…" dialog
CAPTURE_SEED_FILE = "TNT-capture-20260101-120000.pcapng"
CAPTURE_SEED_PACKETS = 412
CAPTURE_SEED_BYTES = 318_704
#: the fake live capture: packets a second, the pcapng block every frame adds to the file and the frames it loses
CAPTURE_RATE_RANGE = (8.0, 25.0)
CAPTURE_BLOCK_BYTES = 32
CAPTURE_DROP_CHANCE = 0.002
_CAPTURE_FILE = re.compile(CAPTURE_FILE_RE, re.ASCII)
#: the invented network the capture sees: documentation addresses (RFC 5737, RFC 3849) and locally administered MACs
#: only - never a real public address and never a real MAC
CAPTURE_PC = {"ip": "192.0.2.50", "ip6": "2001:db8::50", "mac": "02:00:5e:00:00:50"}
CAPTURE_GATEWAY = {"ip": "192.0.2.1", "ip6": "2001:db8::1", "mac": "02:00:5e:00:00:01"}
CAPTURE_PHONE = {"ip": "192.0.2.60", "ip6": None, "mac": "02:00:5e:00:00:60"}
CAPTURE_PBX = {"ip": "192.0.2.70", "ip6": None, "mac": "02:00:5e:00:00:70"}
CAPTURE_CAMERA = {"ip": "192.0.2.31", "ip6": None, "mac": "02:00:5e:00:00:31"}
CAPTURE_NVR = {"ip": "192.0.2.40", "ip6": None, "mac": "02:00:5e:00:00:40"}
CAPTURE_LAN = (CAPTURE_PC, CAPTURE_GATEWAY, CAPTURE_PHONE, CAPTURE_PBX, CAPTURE_CAMERA, CAPTURE_NVR)
CAPTURE_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
#: what this PC talks to on the internet (invented names on documentation addresses)
CAPTURE_SERVERS = ({"name": "www.example.com", "ip": "203.0.113.10", "ip6": "2001:db8:a::10"},
                   {"name": "totalelectronics.com", "ip": "198.51.100.40", "ip6": None},
                   {"name": "updates.example.net", "ip": "203.0.113.72", "ip6": "2001:db8:b::72"},
                   {"name": "api.example.org", "ip": "198.51.100.88", "ip6": None})
CAPTURE_RESOLVERS = ("192.0.2.1", "203.0.113.53")
#: the background mix, (kind, weight): every protocol button of the page has something to find
CAPTURE_MIX = (("https", 26), ("tcp", 13), ("dns", 10), ("http", 8), ("udp", 7), ("icmp", 6), ("arp", 4),
               ("rtsp", 3), ("dhcp", 2))
#: the scripted SIP call, seconds after the capture began; RTP rows a second per direction (a real 20 ms stream is 50
#: a second: the mock samples it so the list stays readable), and the call's invented parties
CAPTURE_SIP_AT = {"invite": 3.0, "ringing": 3.35, "answer": 5.6, "ack": 5.65, "bye": 13.6, "byeok": 13.7}
CAPTURE_SIP_RTP_HZ = 5.0
CAPTURE_SIP_FROM = "sip:2001@192.0.2.70"
CAPTURE_SIP_TO = "sip:2002@192.0.2.70"
CAPTURE_SIP_RTP_PORTS = (16402, 20002)             # the phone's and the phone system's
CAPTURE_SIP_CODEC = "PCMU/8000"
CAPTURE_SIP_CONTACT = "sip:2001@192.0.2.60:5060"
CAPTURE_SIP_UA = "TEC-Phone/3.4.1"
#: the WAV calls/{id}/audio answers: a quiet two-tone warble, 8 kHz 16-bit mono (tnt.sipcalls.build_wav's shape)
CAPTURE_WAV_RATE = 8000
CAPTURE_WAV_SECONDS = 2.4
CAPTURE_WAV_TONES = (440.0, 620.0)
#: Speed: latency under load and call quality (tnt.speedtest.quality): keys, texts and the grading rules
QUALITY_KEYS = ("version", "available", "reason", "target", "interval_ms", "payload_bytes", "windows", "bufferbloat", "call")
WINDOW_KEYS = ("sent", "received", "skipped", "loss_pct", "median_ms", "mean_ms", "p95_ms", "max_ms", "jitter_ms")
LOADED_EXTRA_KEYS = ("increase_ms", "grade", "reason", "warning")
BUFFERBLOAT_KEYS = ("grade", "increase_ms", "direction", "text", "warning", "reason")
CALL_KEYS = ("method", "idle", "loaded", "checks")
SCORE_KEYS = ("r", "mos", "label")
CHECK_KEYS = ("key", "ok", "detail")
QUALITY_VERSION = 1
QUALITY_TARGET = "1.1.1.1"
QUALITY_INTERVAL_MS = 100
QUALITY_PAYLOAD = 32
GRADES = ("A+", "A", "B", "C", "D", "F")
#: exclusive upper bounds of the increase under load (ms): a value on a boundary gets the worse grade
GRADE_BOUNDS = ((5.0, "A+"), (30.0, "A"), (60.0, "B"), (200.0, "C"), (400.0, "D"))
GRADE_TEXT = {
    "A+": "No bufferbloat: latency stays flat while the line is busy",
    "A": "Excellent: calls and games are unaffected by heavy use",
    "B": "Good: small delay spikes while the line is busy",
    "C": "Bufferbloat: calls and games may lag while someone uploads or downloads",
    "D": "Severe bufferbloat: calls will break up while the line is busy",
    "F": "Unusable under load: the connection stalls when it is busy",
}
REASON_TOO_SHORT = "phase too short to grade"
REASON_MOST_LOST = "most probes were lost under load"
REASON_NO_REPLIES = "{target} did not answer pings"
REASON_NO_BASELINE = "idle latency could not be measured"
WARNING_SOME_LOST = "some probes were lost under load"
WARNING_DELAYED = "probes were delayed, so loss may be under-counted"
CALL_METHOD = "estimate (simplified E-model)"
#: inclusive lower bounds of R per label, below the last one CALL_LABEL_WORST; (key, mean ms, jitter ms, loss %, "or less")
CALL_LABELS = ((90.0, "Excellent"), (80.0, "Good"), (70.0, "Fair"), (60.0, "Poor"), (50.0, "Bad"))
CALL_LABEL_WORST = "Unusable"
CALL_CHECKS = (("zoom", 150.0, 40.0, 2.0, True), ("teams", 100.0, 30.0, 1.0, False))
QUALITY_MIN_SENT = 10
QUALITY_MIN_RECEIVED = 8
QUALITY_MOST_LOST_PCT = 50.0
QUALITY_SOME_LOST_PCT = 5.0
QUALITY_SKIPPED_WARN_SHARE = 0.10
QUALITY_BASELINE_MIN_ANSWERED = 0.5
QUALITY_SCOPE = {"baseline": "idle", "download": "while downloading", "upload": "while uploading"}
#: the mock speed test's phases and seconds, and the Full Scan speed step's part of each: phase -> (base, span) of the step
SPEED_PHASES = (("baseline", 0.8), ("latency", 1.2), ("download", 3.0), ("upload", 2.6))
REPORT_SPEED_STEPS = {"baseline": (0.0, 0.05), "latency": (0.05, 0.1), "download": (0.15, 0.45), "upload": (0.6, 0.4)}
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


def dns_address(text: str) -> Optional[Any]:
    """An IPv4 / IPv6 literal as an address object, else None."""
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def dns_validate(value: Any, what: str) -> Optional[str]:
    """The name rules of tnt.nettools._validate: None for a missing or empty value, else the address (normalized) or the ASCII
    host name without its trailing dot (a non-ASCII name turned into punycode with the idna codec; labels of letters, digits,
    "_" and "-", 1-63 characters, none starting or ending with "-"; 253 characters at most, never starting with "-").
    ValueError with the service's text (what was typed, cut to 80 characters) otherwise."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f'"{str(value)[:80]}" is not {what}')
    text = value.strip()
    if not text:
        return None
    invalid = ValueError(f'"{text[:80]}" is not {what}')
    body = text[:-1] if text.endswith(".") else text
    address = dns_address(body)
    if address is not None:
        return str(address)
    if not body.isascii():
        try:
            body = body.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            raise invalid from None
    if not body or len(body) > 253 or body.startswith("-") or not all(_DNS_LABEL_RE.fullmatch(label) for label in body.split(".")):
        raise invalid
    return body


def dns_query_name(value: Any) -> str:
    """The name of POST /api/tools/dns/lookup (tnt.nettools.validate_name): ValueError, a 400, with the service's text."""
    name = dns_validate(value, "a DNS name or IP address")
    if name is None:
        raise ValueError(DNS_NAME_REQUIRED_MSG)
    return name


def dns_query_server(value: Any) -> Optional[str]:
    """The DNS server of a lookup, None for this PC's own (tnt.nettools.validate_server)."""
    return dns_validate(value, "a DNS server name or IP address")


def dns_query_type(value: Any) -> Optional[str]:
    """The record type of a lookup (tnt.nettools.validate_type): its upper-case name from DNS_TYPES, or "ALL" (all record
    types at once) for "all" (any case), all trimmed; None for Auto (None, empty or spaces); ValueError with the service's
    text (what was sent, cut to 80 characters) otherwise."""
    if value is None:
        return None
    if isinstance(value, str):
        shown = value.strip()
        if not shown:
            return None
        if shown.upper() in DNS_TYPES or shown.upper() == "ALL":
            return shown.upper()
    else:
        shown = str(value).strip()
    raise ValueError(DNS_BAD_TYPE_MSG.format(shown[:80]))


def network_tool_route(p: str) -> bool:
    """Whether ``/api<p>`` is a network tool a browser page of another origin may not POST, PUT or DELETE (or download)."""
    return p in NETWORK_TOOL_ROUTES or (p.startswith(CAPTURE_FILES_ROUTE) and len(p) > len(CAPTURE_FILES_ROUTE))



# --------------------------------------------------------------------------- SIP (its own page)
#: The shapes the SIP page reads, from tnt.sipqual, tnt.sipalg, tnt.sipnat and tnt.sipflow.
SIP_QUALIFIER_KEYS = ("ts", "window_h", "network_id", "site", "sip_host", "verdict", "grade", "legs", "headline",
                      "findings", "speedtest_ts", "note")
SIP_LEG_KEYS = ("kind", "label", "target", "grade", "mos", "r", "call_label", "avg_ms", "jitter_ms", "loss_pct",
                "p95_ms", "samples", "window_h", "reason")
SIP_HEADLINE_KEYS = ("leg", "label", "grade", "mos", "r", "call_label", "avg_ms", "jitter_ms", "loss_pct",
                     "samples", "window_h", "reason")
SIP_FINDING_KEYS = ("id", "level", "title", "detail", "advice", "evidence")
SIP_ALG_KEYS = ("ts", "host", "port", "transport", "verdict", "probes", "changes", "public", "via_srv",
                "findings", "note")
SIP_PROBE_KEYS = ("port", "bound", "requested_port", "answered", "status", "reason", "elapsed_ms", "received",
                  "rport", "changes", "error")
SIP_CHANGE_KEYS = ("header", "sent", "seen")
SIP_STUN_KEYS = ("ts", "servers", "local_port", "requested_port", "bound", "mapping", "public", "port_preserved",
                 "findings", "note")
SIP_SERVER_KEYS = ("host", "port", "answered", "mapped_ip", "mapped_port", "elapsed_ms", "error")
SIP_FLOW_KEYS = ("ts", "sources", "calls", "skew", "findings", "counts")
SIP_SOURCE_KEYS = ("slot", "name", "path", "size", "packets", "sip_messages", "rtp_packets", "calls", "first_ts",
                   "last_ts", "error")
SIP_LADDER_KEYS = ("index", "ts", "rel", "side", "src", "dst", "label", "kind", "method", "status", "reason",
                   "cseq", "cseq_method", "has_sdp", "contact", "user_agent", "where", "note")
SIP_FLOWCALL_KEYS = ("id", "call_ids", "from_uri", "to_uri", "state", "status", "start_ts", "answer_ts", "end_ts",
                     "duration_s", "sides", "matched_by", "ladder", "streams", "findings", "note")

#: The fake site's phone system, on a documentation address like everything else here.
#: tnt.sipqual.MAX_LEGS_PER_KIND: most targets of one kind that become legs
SIP_MAX_LEGS_PER_KIND = 3
#: tnt.sipqual.MIN_SAMPLES: fewer pings than this behind a leg and it is not graded
SIP_MIN_SAMPLES = 30
SIP_PBX_HOST = "pbx.example.net"
SIP_PBX_IP = "198.51.100.25"
SIP_PHONE_IP = "192.0.2.60"
#: The phone as the capture shows it on the wire: a real private address, because "behind NAT" is
#: RFC 1918 / CGNAT / fc00::/7 and the documentation ranges this file uses as public stand-ins are
#: deliberately not counted as private (tnt.sipalg.behind_nat).
SIP_NATTED_PHONE = "10.20.30.40"
#: What the fake network's ALG does: "clean" (nothing in the way), "alg" (a router rewriting SIP) or
#: "inconclusive" (the PBX never answered).  POST /mock/sip picks another.
SIP_ALG_STATES = ("clean", "alg", "inconclusive")
#: What the fake NAT does to a mapping: the two that matter for voice, plus the happy case.
SIP_NAT_STATES = ("endpoint-independent", "address-dependent", "none")
SIP_STUN_SERVERS = (("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478))
SIP_CAPTURE_A = {"slot": "a", "name": "client-side.pcapng", "path": "C:\\Captures\\client-side.pcapng",
                 "size": 2_214_400}
SIP_CAPTURE_B = {"slot": "b", "name": "server-side.pcapng", "path": "C:\\Captures\\server-side.pcapng",
                 "size": 2_461_184}
#: Seconds between the two captures' clocks, which is what makes merging them worth doing at all.
SIP_SKEW_S = 4.8


def sip_grade(avg: float, jitter: float, loss: float) -> str:
    """tnt.sipqual.THRESHOLDS: the worst of the three decides, because a fast path that drops packets is not good."""
    for grade, max_avg, max_jitter, max_loss in (("excellent", 60.0, 10.0, 0.1), ("good", 120.0, 20.0, 0.5),
                                                 ("fair", 200.0, 40.0, 1.5), ("poor", 300.0, 60.0, 3.0)):
        if avg <= max_avg and jitter <= max_jitter and loss <= max_loss:
            return grade
    return "bad"


def sip_call_quality(avg: float, jitter: float, loss: float) -> Tuple[float, float]:
    """The simplified E-model of tnt.speedtest.quality.call_quality, so the mock shows the numbers the page will."""
    eff = avg + 2 * jitter + 10.0
    r = 93.2 - eff / 40.0 if eff < 160 else 93.2 - (eff - 120) / 10.0
    r = max(0.0, min(100.0, r - 2.5 * loss))
    mos = max(1.0, 1 + 0.035 * r + 7e-6 * r * (r - 60) * (100 - r))
    return round(r, 2), round(mos, 2)


def sip_call_label(r: float) -> str:
    for bound, text in ((90, "excellent"), (80, "good"), (70, "fair"), (60, "poor")):
        if r >= bound:
            return text
    return "bad"


def sip_headline(legs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """tnt.sipqual.headline: the weakest graded leg's numbers, because that is what limits the call."""
    graded = [leg for leg in legs if leg["grade"] != "unknown"]
    if not graded:
        return {"leg": None, "label": None, "grade": "unknown", "mos": None, "r": None, "call_label": None,
                "avg_ms": None, "jitter_ms": None, "loss_pct": None, "samples": 0, "window_h": None,
                "reason": "there is no graded leg to take the numbers from"}
    # worst grade, then lowest MOS, then slowest: on a healthy site every leg is excellent and the first of them
    # would put the gateway's 3 ms on screen as what a call gets (tnt.sipqual._weakest)
    worst = min(graded, key=lambda leg: (SIP_GRADES.index(leg["grade"]),
                                         leg["mos"] if isinstance(leg.get("mos"), (int, float)) else 5.0,
                                         -(leg["avg_ms"] if isinstance(leg.get("avg_ms"), (int, float)) else 0.0)))
    return {"leg": worst["kind"], "label": worst["label"], "grade": worst["grade"], "mos": worst["mos"],
            "r": worst["r"], "call_label": worst["call_label"], "avg_ms": worst["avg_ms"],
            "jitter_ms": worst["jitter_ms"], "loss_pct": worst["loss_pct"], "samples": worst["samples"],
            "window_h": worst["window_h"], "reason": None}


def sip_finding(ident: str, level: str, title: str, detail: Optional[str] = None, advice: Optional[str] = None,
                evidence: Any = None) -> Dict[str, Any]:
    return {"id": ident, "level": level, "title": title, "detail": detail, "advice": advice, "evidence": evidence}


SIP_GRADE_LEVEL = {"excellent": "good", "good": "good", "fair": "warn", "poor": "bad", "bad": "bad",
                   "unknown": "info"}
SIP_LEVELS = ("bad", "warn", "info", "good")
SIP_GRADES = ("bad", "poor", "fair", "good", "excellent", "unknown")


def sip_build_qualifier(legs: List[Dict[str, Any]], window_h: float,
                        sip_host: Optional[str], network_id: Optional[int], speedtest_ts: Optional[float],
                        bufferbloat: Optional[str], ts: float, left_out: int = 0) -> Dict[str, Any]:
    """tnt.sipqual.build_qualifier: the verdict is the worst leg, and the headline leads whatever its level."""
    graded = [leg for leg in legs if leg["grade"] != "unknown"]
    verdict = min((leg["grade"] for leg in graded), key=SIP_GRADES.index) if graded else "unknown"
    head = sip_headline(legs)
    ident_for = {"lan": "sip.lan", "wan": "sip.wan", "sip": "sip.trunk"}
    advice_for = {
        "lan": "A bad LAN leg is in the building: the switch, the cabling, or Wi-Fi between the phone and the "
               "gateway. Fix it here before looking outside.",
        "wan": "A bad WAN leg with a clean LAN is the circuit or the provider - that is a call to someone else, "
               "and these numbers are what to tell them.",
        "sip": "This is the path the calls themselves take. Bad here with a clean internet leg points at the route "
               "to the phone system rather than at the line.",
    }
    findings: List[Dict[str, Any]] = []
    for leg in legs:
        if leg["grade"] == "unknown":
            # tnt.sipqual: a leg with too little history says so rather than showing numbers it does not have
            findings.append(sip_finding(ident_for[leg["kind"]], "info", f"{leg['label']}: not enough history to grade",
                                        leg["reason"]))
            continue
        numbers = (f"{leg['avg_ms']} ms average, {leg['jitter_ms']} ms jitter, {leg['loss_pct']} % loss over "
                   f"{leg['samples']} pings")
        findings.append(sip_finding(
            ident_for[leg["kind"]], SIP_GRADE_LEVEL[leg["grade"]], f"{leg['label']}: {leg['grade']}",
            numbers + (f" - {leg['call_label']} (MOS {leg['mos']})" if leg["mos"] else ""),
            None if leg["grade"] in ("excellent", "good") else advice_for[leg["kind"]],
            {"avg_ms": leg["avg_ms"], "jitter_ms": leg["jitter_ms"], "loss_pct": leg["loss_pct"]}))
    window_text = f"{int(window_h)} hours" if window_h >= 2 else f"{int(window_h * 60)} minutes"
    if graded:
        worst = min(graded, key=lambda leg: SIP_GRADES.index(leg["grade"]))
        if verdict in ("excellent", "good"):
            findings.append(sip_finding("sip.ready", "good", f"This network looks {verdict} for SIP",
                                        f"Every leg measured over the last {window_text} is {verdict} or better"
                                        + (f" \u2014 MOS {head['mos']} at {head['avg_ms']} ms."
                                           if head["mos"] is not None else ".")))
        else:
            findings.append(sip_finding(
                "sip.ready", "bad" if verdict in ("bad", "poor") else "warn",
                f"Calls on this network would be {verdict}",
                f"The {worst['label'].lower()} is the weakest leg over the last {window_text}: "
                f"{worst['avg_ms']} ms average, {worst['loss_pct']} % loss, {worst['jitter_ms']} ms jitter.",
                "Start with the leg named above - the other legs are not the problem."))
    else:
        findings.append(sip_finding("sip.nodata", "info", "Not enough history for a rating yet",
                                    "None of the legs has enough pings on this network to be worth grading.",
                                    "Leave TNT running here for a while - even an hour gives it something to "
                                    "stand on."))
    if sip_host is None:
        findings.append(sip_finding(
            "sip.notarget", "info", "No SIP host has been named",
            "This rating grades the path to a general internet host. The path the calls actually take - to the "
            "PBX, SBC or registrar - may be a different route entirely.",
            "Name the SIP host and TNT will monitor it like any other target."))
    if bufferbloat in ("D", "F"):
        findings.append(sip_finding(
            "sip.bufferbloat", "bad", f"The line buffers badly under load (grade {bufferbloat})",
            "Latency climbs sharply while the line is busy. Calls hold up until somebody starts a download.",
            "This is the line's queueing, not its speed. Smart queue management on the router fixes it."))
    lead = [f for f in findings if f["id"] == "sip.ready"]
    rest = sorted((f for f in findings if f["id"] != "sip.ready"), key=lambda f: SIP_LEVELS.index(f["level"]))
    note = (f"{left_out} more monitored target(s) were not graded: the first {SIP_MAX_LEGS_PER_KIND} of each kind "
            "are, in the order the targets are listed on the Ping page.") if left_out else None
    return {"ts": ts, "window_h": window_h, "network_id": network_id, "site": None, "sip_host": sip_host,
            "verdict": verdict, "grade": verdict, "legs": legs, "headline": head,
            "findings": lead + rest, "speedtest_ts": speedtest_ts, "note": note}


# -- the ALG check (tnt.sipalg) ------------------------------------------------------------------
def sip_probe(port: int, answered: bool, changes: List[Dict[str, Any]], rport: Optional[int] = None,
              error: Optional[str] = None) -> Dict[str, Any]:
    return {"port": rport or port or 51840, "bound": bool(port), "requested_port": port, "answered": answered,
            "status": 200 if answered else None, "reason": "OK" if answered else None,
            "elapsed_ms": 42 if answered else None, "received": PUBLIC_IP if answered else None,
            "rport": rport, "changes": changes, "error": error}


def sip_alg_result(host: str, port: int, state: str) -> Dict[str, Any]:
    """The ALG check in whichever state the fake network is in: a router rewriting SIP, a clean path, or silence."""
    if state == "alg":
        changes = [{"header": "Via sent-by", "sent": f"{SIP_PHONE_IP}:5060", "seen": f"{PUBLIC_IP}:5060"},
                   {"header": "Via branch", "sent": "z9hG4bK7a1c9f2e", "seen": "z9hG4bK7a1c9f2e-alg"},
                   {"header": "Contact", "sent": f"sip:tnt@{SIP_PHONE_IP}:5060",
                    "seen": f"sip:tnt@{PUBLIC_IP}:5060"}]
        probes = [sip_probe(5060, True, changes), sip_probe(0, True, [])]
        findings = [sip_finding("alg.rewritten", "bad", "A SIP ALG is rewriting your SIP",
                                "The PBX echoed back headers this PC never sent. Something in the path between "
                                "this PC and the phone system is editing SIP as it goes by.",
                                "Turn SIP ALG off on the router or firewall. It is usually called SIP ALG, SIP "
                                "Transformations or SIP Helper."),
                    sip_finding("alg.port", "info", "Only port 5060 is touched",
                                "The probe from an ordinary source port came back untouched; the one from 5060 did "
                                "not. That is how most of these boxes behave.",
                                "Moving the phone system off 5060 dodges it, but turning the ALG off is the fix.")]
        verdict = "alg"
    elif state == "inconclusive":
        probes = [sip_probe(5060, False, [], error="no answer in 3.0 s"),
                  sip_probe(0, False, [], error="no answer in 3.0 s")]
        findings = [sip_finding("alg.silent", "info", "The PBX did not answer",
                                "Nothing came back from either probe, so there is nothing to compare. This says "
                                "the server is unreachable from here, not that the path is clean.",
                                "Check the address and that this PC can reach the phone system at all.")]
        verdict = "inconclusive"
    else:
        probes = [sip_probe(5060, True, []), sip_probe(0, True, [])]
        findings = [sip_finding("alg.clean", "good", "Nothing rewrote the SIP TNT sent",
                                "Every header the PBX echoed came back exactly as it was sent, from port 5060 and "
                                "from an ordinary port.",
                                "This is as much as a probe can show. A capture from both sides is the only "
                                "conclusive test.")]
        verdict = "clean"
    # a SIP domain resolves through SRV the way a phone does (tnt.sipalg.srv_targets); the fake host is a plain
    # name, so nothing was followed
    return {"ts": time.time(), "host": host, "port": port, "transport": "udp", "verdict": verdict,
            "probes": probes, "changes": probes[0]["changes"], "public": PUBLIC_IP, "via_srv": None,
            "findings": findings, "note": None}


# -- STUN (tnt.sipnat) ---------------------------------------------------------------------------
def sip_stun_result(servers: List[Tuple[str, int]], state: str) -> Dict[str, Any]:
    """Both servers asked from one socket; two different external ports is the one-way-audio NAT."""
    local = 51840
    rows = []
    for index, (host, port) in enumerate(servers):
        mapped_port = local if state == "none" else (49152 if state == "endpoint-independent" else 49152 + index * 7)
        mapped_ip = SIP_PHONE_IP if state == "none" else PUBLIC_IP
        rows.append({"host": host, "port": port, "answered": True, "mapped_ip": mapped_ip,
                     "mapped_port": mapped_port, "elapsed_ms": 28 + index * 6, "error": None})
    if state == "address-dependent":
        findings = [sip_finding("nat.symmetric", "bad", "This NAT gives every destination a different port",
                                "The two STUN servers were asked from one socket and saw two different external "
                                "ports. A phone system told about one of them sends its audio to the other.",
                                "This is the classic one-way audio NAT. Turn the router's SIP-aware mangling off, "
                                "or put the phone system behind an SBC that keeps a single mapping.")]
    elif state == "none":
        findings = [sip_finding("nat.none", "good", "This PC is not behind NAT",
                                "Both servers saw the address and port this PC actually used.",
                                None)]
    else:
        findings = [sip_finding("nat.endpoint", "good", "One mapping for every destination",
                                "Both STUN servers saw the same external address and port, which is what voice "
                                "wants.", None)]
    return {"ts": time.time(), "servers": rows, "local_port": local, "requested_port": 0, "bound": True,
            "mapping": state, "public": rows[0]["mapped_ip"] if rows else None,
            "port_preserved": state == "none", "findings": findings, "note": None}


def sip_lifetime_result(host: str, port: int, state: str) -> Dict[str, Any]:
    """How long a mapping survives with nothing using it; short is what breaks inbound calls between registrations."""
    short = state == "address-dependent"
    steps, survived, lost = [], None, None
    for idle in (15, 30, 60, 120, 240):
        kept = not (short and idle >= 30)
        steps.append({"idle_s": idle, "mapped_port": 49152 if kept else 49871, "kept": kept, "error": None})
        if kept:
            survived = idle
        else:
            lost = idle
            break
    if lost is not None:
        findings = [sip_finding("nat.shortlife", "bad", f"The mapping was gone after {lost} s idle",
                                f"It survived {survived} s but not {lost} s. Between one registration and the next "
                                "there is a window where an inbound call has nowhere to arrive.",
                                "Set the phone's registration interval, or its keep-alive, shorter than this.")]
        verdict = "short"
    else:
        findings = [sip_finding("nat.longlife", "good", f"The mapping survived {survived} s idle",
                                "Long enough that an ordinary registration interval keeps it open.", None)]
        verdict = "long"
    return {"ts": time.time(), "server": {"host": host, "port": port}, "local_port": 51840, "steps": steps,
            "survived_s": survived, "lost_at_s": lost, "verdict": verdict, "findings": findings}


# -- the call flows (tnt.sipflow) ----------------------------------------------------------------
SIP_LADDER_SCRIPT = (
    (0.00, "a", "phone", "pbx", "INVITE", "request", "INVITE", None, None, True),
    (0.04, "b", "phone", "pbx", "INVITE", "request", "INVITE", None, None, True),
    (0.31, "b", "pbx", "phone", "100 Trying", "response", None, 100, "Trying", False),
    (0.35, "b", "pbx", "phone", "180 Ringing", "response", None, 180, "Ringing", False),
    (0.39, "a", "pbx", "phone", "180 Ringing", "response", None, 180, "Ringing", False),
    (2.60, "b", "pbx", "phone", "200 OK", "response", None, 200, "OK", True),
    (2.64, "a", "pbx", "phone", "200 OK", "response", None, 200, "OK", True),
    (2.68, "a", "phone", "pbx", "ACK", "request", "ACK", None, None, False),
    (2.72, "b", "phone", "pbx", "ACK", "request", "ACK", None, None, False),
    (13.60, "a", "phone", "pbx", "BYE", "request", "BYE", None, None, False),
    (13.64, "b", "phone", "pbx", "BYE", "request", "BYE", None, None, False),
    (13.70, "b", "pbx", "phone", "200 OK", "response", None, 200, "OK", False),
    (13.74, "a", "pbx", "phone", "200 OK", "response", None, 200, "OK", False),
)


def sip_ladder(slots: List[str], start: float) -> List[Dict[str, Any]]:
    """The call flow a tech reads top to bottom: setup, ringing, answer, audio, teardown."""
    rows = []
    index = 0
    for rel, side, src, dst, label, kind, method, status, reason, sdp in SIP_LADDER_SCRIPT:
        if side not in slots:
            continue
        who = {"phone": SIP_PHONE_IP, "pbx": SIP_PBX_IP}
        rows.append({"index": index, "ts": start + rel, "rel": round(rel, 2), "side": side,
                     "src": who[src], "dst": who[dst], "label": label, "kind": kind, "method": method,
                     "status": status, "reason": reason, "cseq": 1 if label != "BYE" else 2,
                     "cseq_method": method or ("INVITE" if status else None), "has_sdp": sdp,
                     "contact": f"<sip:2001@{SIP_PHONE_IP}:5060>", "user_agent": "TEC-Phone/3.4.1",
                     "where": 1200 + index * 7, "note": None})
        index += 1
    return rows


def sip_streams(slots: List[str], start: float) -> List[Dict[str, Any]]:
    rows = []
    for side in slots:
        for which, (src, dst, sport, dport) in enumerate(((SIP_PHONE_IP, SIP_PBX_IP, 16402, 20002),
                                                          (SIP_PBX_IP, SIP_PHONE_IP, 20002, 16402))):
            rows.append({"id": f"{side}-{sport}-{dport}", "side": side, "src": src, "sport": sport, "dst": dst,
                         "dport": dport, "ssrc": 0x5A17C0DE + which, "payload_type": 0, "codec": "PCMU/8000",
                         "packets": 546 if (side == "a" or which == 0) else 0, "lost": 0 if which == 0 else 3,
                         "first_ts": start + 2.7, "last_ts": start + 13.5, "duration_s": 10.8,
                         "bytes": 546 * 172, "jitter_ms": 1.8 if which == 0 else 6.4,
                         "decodable": True})
    return rows


def sip_flow(slots: List[str]) -> Dict[str, Any]:
    """GET /api/sip/flow: the loaded captures, the calls in them, and the clock skew between the two."""
    now = time.time()
    start = now - 900.0
    sources = []
    for row in (SIP_CAPTURE_A, SIP_CAPTURE_B):
        if row["slot"] not in slots:
            continue
        sources.append({"slot": row["slot"], "name": row["name"], "path": row["path"], "size": row["size"],
                        "packets": 5860 if row["slot"] == "a" else 6142, "sip_messages": 7, "rtp_packets": 1092,
                        "calls": 1, "first_ts": start - 2.0, "last_ts": start + 20.0, "error": None})
    if not sources:
        return {"ts": now, "sources": [], "calls": [], "skew": {"seconds": None, "samples": 0, "matched_calls": 0,
                                                                "confident": False},
                "findings": [], "counts": {"calls": 0, "sip_messages": 0, "rtp_packets": 0}}
    both = len(sources) > 1
    ladder = sip_ladder(slots, start)
    streams = sip_streams(slots, start)
    findings = []
    if both:
        findings.append(sip_finding(
            "flow.rewritten", "bad", "The two captures do not agree on the Contact address",
            "The same call carries one Contact on the client side and another on the server side. Something "
            "between them rewrote it in flight.",
            "This is a SIP ALG, and unlike a probe it is conclusive: the message went in one way and came out "
            "another.", {"header": "contact"}))
        findings.append(sip_finding("flow.skew", "info", f"The captures' clocks differ by {SIP_SKEW_S:.1f} s",
                                    "Measured from the messages that appear in both, not assumed. The ladder is "
                                    "shown on one timeline.", None,
                                    {"seconds": SIP_SKEW_S}))
    findings.append(sip_finding("flow.jitter", "warn", "Audio from the phone system is jittery",
                                "6.4 ms of interarrival jitter on the inbound stream against 1.8 ms outbound.",
                                "Jitter one way only points at the path that direction, not at the phones.",
                                {"jitter_ms": 6.4}))
    if not both:
        # what one capture can see of the ALG (tnt.sipalg.passive_tells, wired into tnt.sipflow). Only offered
        # with one capture loaded: two sides prove the rewrite outright and an inference beside proof is noise.
        findings.append(sip_finding(
            "alg.contact", "warn", "A SIP ALG may be rewriting this call",
            f"{SIP_NATTED_PHONE} is behind NAT but its Contact says {PUBLIC_IP}, which is not. A phone writes its "
            "own Contact and does not know the address on the other side of the NAT unless something put it there.",
            "This is one capture's inference, not proof. The SIP ALG check on this page probes your own server and "
            "says outright whether something rewrote what TNT sent; a capture from both sides of the network "
            "settles it beyond doubt.",
            {"src": SIP_NATTED_PHONE, "contact": f"sip:2001@{PUBLIC_IP}:5060"}))
    call = {"id": "flow-1", "call_ids": ["7a1c9f2e3b@192.0.2.60"], "from_uri": f"sip:2001@{SIP_PBX_HOST}",
            "to_uri": f"sip:2002@{SIP_PBX_HOST}", "state": "ended", "status": 200, "start_ts": start,
            "answer_ts": start + 2.6, "end_ts": start + 13.74, "duration_s": 11.14,
            "sides": sorted(slots), "matched_by": "call-id" if both else "single",
            "ladder": ladder, "streams": streams, "findings": findings, "note": None}
    return {"ts": now, "sources": sources, "calls": [call],
            "skew": {"seconds": SIP_SKEW_S if both else None, "samples": 7 if both else 0,
                     "matched_calls": 1 if both else 0, "confident": both},
            "findings": findings,
            "counts": {"calls": 1, "sip_messages": len(ladder), "rtp_packets": 1092 * len(sources)}}


def sip_header_view(call: Dict[str, Any], row: Dict[str, Any]) -> Dict[str, Any]:
    """Every header of one SIP message, in the order it was sent, repeats and all (tnt.sipcalls.sip_headers)."""
    line = (f"{row['method']} sip:2002@{SIP_PBX_HOST} SIP/2.0" if row["kind"] == "request"
            else f"SIP/2.0 {row['status']} {row['reason']}")
    headers = [("Via", f"SIP/2.0/UDP {SIP_PHONE_IP}:5060;branch=z9hG4bK{row['index']:08x};rport"),
               ("Max-Forwards", "70"),
               ("From", f"\"Reception\" <sip:2001@{SIP_PBX_HOST}>;tag=8f2c1a"),
               ("To", f"<sip:2002@{SIP_PBX_HOST}>" + (";tag=99b31d" if row["status"] else "")),
               ("Call-ID", call["call_ids"][0]),
               ("CSeq", f"{row['cseq']} {row['cseq_method'] or 'INVITE'}"),
               ("Contact", row["contact"]),
               ("User-Agent", row["user_agent"]),
               ("Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS, REFER, NOTIFY"),
               ("Content-Type", "application/sdp") if row["has_sdp"] else ("Content-Length", "0")]
    body = ("v=0\r\no=- 1 1 IN IP4 " + SIP_PHONE_IP + "\r\ns=-\r\nc=IN IP4 " + SIP_PHONE_IP +
            "\r\nt=0 0\r\nm=audio 16402 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
            ) if row["has_sdp"] else ""
    return {"start": line, "kind": row["kind"], "method": row["method"], "status": row["status"],
            "reason": row["reason"], "uri": f"sip:2002@{SIP_PBX_HOST}" if row["kind"] == "request" else None,
            "headers": [{"name": name, "value": value} for name, value in headers],
            "body": body, "is_sdp": bool(row["has_sdp"]), "length_ok": True}


class ToolRefused(RuntimeError):
    """A network tool's refusal with the service's status, code and text (tnt.api.routes.TYPED_ERRORS, the admin check):
    ``extra`` joins the error body (a TFTP port conflict's ``owners``), ``headers`` the response (a 429's ``Retry-After``)."""

    def __init__(self, status: int, code: str, message: str, extra: Optional[Dict[str, Any]] = None,
                 headers: Optional[Dict[str, str]] = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.extra = dict(extra or {})
        self.headers = dict(headers or {})

    def payload(self) -> Dict[str, Any]:
        return dict({"error": {"code": self.code, "message": str(self)}}, **self.extra)


def _inet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def tiny_pcapng(ts: float) -> bytes:
    """A saved capture's bytes: a valid little-endian pcapng with one Section Header Block, one Ethernet Interface Description
    Block and one Enhanced Packet Block (an ICMP echo request from 192.0.2.10 to 192.0.2.1, locally administered MACs) at *ts*."""
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x7454, 1) + b"TNT mock capture"
    icmp = icmp[:2] + struct.pack("!H", _inet_checksum(icmp)) + icmp[4:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0, bytes([192, 0, 2, 10]), bytes([192, 0, 2, 1]))
    ip = ip[:10] + struct.pack("!H", _inet_checksum(ip)) + ip[12:]
    frame = bytes.fromhex("02005e100001" "02005e100002" "0800") + ip + icmp
    shb = struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28)
    idb = struct.pack("<IIHHI", 1, 20, 1, 0, 0) + struct.pack("<I", 20)
    micros = int(ts * 1_000_000)
    padded = frame + b"\x00" * (-len(frame) % 4)
    length = 32 + len(padded)
    epb = (struct.pack("<IIIIIII", 6, length, 0, micros >> 32, micros & 0xFFFFFFFF, len(frame), len(frame)) + padded
           + struct.pack("<I", length))
    return shb + idb + epb


def capture_start_values(body: Dict[str, Any], adapters: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The body of POST /api/capture/start checked in tnt.capture.CaptureManager.start's order (a key left out takes its
    default): ValueError with the service's text, else the adapter row of *adapters* and the two limits."""
    adapter = body.get("adapter")
    name = (adapter if isinstance(adapter, str) else ("" if adapter is None else str(adapter))).strip()
    row = next((a for a in adapters if a["name"] == name), None) if name else None
    if row is None:
        raise ValueError(CAPTURE_ADAPTER_TEXT.format(name=name[:40]))
    seconds = body["max_seconds"] if "max_seconds" in body else CAPTURE_DEFAULT_SECONDS
    if seconds not in CAPTURE_SECONDS:
        raise ValueError(CAPTURE_SECONDS_TEXT)
    size_mb = body["max_mb"] if "max_mb" in body else CAPTURE_DEFAULT_MB
    if size_mb not in CAPTURE_SIZES_MB:
        raise ValueError(CAPTURE_SIZE_TEXT)
    return {"adapter": dict(row), "max_seconds": int(seconds), "max_mb": int(size_mb)}


# -- packet capture: reading the list (tnt.capture.CaptureManager.packets, tnt.dissect's matchers) -----------------
def capture_norm_mac(text: Any) -> str:
    """A MAC filter as twelve lower-case hex digits, or "" when it is not one (any separator, or none)."""
    raw = "".join(c for c in str(text or "").lower() if c in "0123456789abcdef")
    return raw if len(raw) == 12 else ""


def capture_norm_ip(text: Any) -> str:
    """An IP filter as its canonical text, or "" when it is not an address."""
    value = str(text or "").strip()
    if not value or "/" in value or "%" in value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def capture_whole(value: Any, default: int, lo: int, hi: int) -> int:
    """A whole number inside [lo, hi]; *default* for anything else (list paging never fails a request)."""
    if isinstance(value, bool) or value is None:
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, number))


def capture_proto_keys(protos: Any) -> Tuple[str, ...]:
    """The protocol filter keys of a request, the ones CAPTURE_PROTO_FILTERS knows, sorted and without repeats."""
    if not protos:
        return ()
    wanted = protos if isinstance(protos, (list, tuple, set)) else str(protos).split(",")
    return tuple(sorted({str(p).strip().lower() for p in wanted if str(p).strip().lower() in CAPTURE_PROTO_FILTERS}))


def capture_matches(row: Dict[str, Any], layers: Tuple[str, ...], ip: str, mac: str, protos: Tuple[str, ...]) -> bool:
    """CaptureManager._matches: the IP matches source or destination, the MAC either MAC in any spelling, and the
    protocol keys are ORed among themselves; all three are ANDed."""
    if ip and ip != row["src"] and ip != row["dst"]:
        return False
    if mac and mac != capture_norm_mac(row["src_mac"]) and mac != capture_norm_mac(row["dst_mac"]):
        return False
    if protos:
        for key in protos:
            names = CAPTURE_PROTO_FILTERS.get(key) or ()
            if row["proto"] in names or any(name in layers for name in names):
                return True
        return False
    return True


# -- packet capture: the traffic the fake live capture invents (tnt.dissect's rows, tnt.sipcalls' calls) -----------
def capture_parts(**fields: Any) -> Dict[str, Any]:
    """One invented packet: the ROW fields but ``no``, ``ts`` and ``rel``, the protocol ``layers`` the filters match
    on, the application ``fields`` the detail tree shows, the ``payload`` bytes behind it and the little the header
    builders need (TCP ``flags``, the ICMP ``type, id, seq``)."""
    packet = {"src": "", "dst": "", "src_mac": "", "dst_mac": "", "proto": "UNKNOWN", "sport": None, "dport": None,
              "length": 60, "info": "", "layers": ("ETH",), "fields": (), "payload": b"", "flags": 0x18,
              "icmp": (8, 1, 1), "sip": None}
    packet.update(fields)
    return packet


def capture_mac_for(ip: str) -> str:
    """The MAC an address is behind on the wire: its own on this LAN, else the gateway's, as a real capture sees it."""
    for host in CAPTURE_LAN:
        if ip in (host["ip"], host["ip6"]):
            return host["mac"]
    return CAPTURE_GATEWAY["mac"]


def _capture_pick(rng: random.Random, table: Tuple[Tuple[str, int], ...]) -> str:
    draw = rng.randrange(sum(weight for _kind, weight in table))
    for kind, weight in table:
        draw -= weight
        if draw < 0:
            return kind
    return table[-1][0]


def capture_invent(rng: random.Random) -> Dict[str, Any]:  # noqa: C901 - one branch per protocol, flat on purpose
    """One packet of the background mix (CAPTURE_MIX), as capture_parts describes it."""
    kind = _capture_pick(rng, CAPTURE_MIX)
    pc, gw = CAPTURE_PC, CAPTURE_GATEWAY
    if kind == "arp":
        who = rng.choice((CAPTURE_PHONE, CAPTURE_CAMERA, CAPTURE_NVR, CAPTURE_PBX))
        if rng.random() < 0.55:
            return capture_parts(src=gw["ip"], dst=who["ip"], src_mac=gw["mac"], dst_mac=CAPTURE_BROADCAST_MAC,
                                 proto="ARP", length=60, layers=("ETH", "ARP"),
                                 info=f"Who has {who['ip']}? Tell {gw['ip']}",
                                 fields=(("Opcode", "request (1)"), ("Sender MAC address", gw["mac"]),
                                         ("Sender IP address", gw["ip"]), ("Target IP address", who["ip"])))
        return capture_parts(src=who["ip"], dst=gw["ip"], src_mac=who["mac"], dst_mac=gw["mac"], proto="ARP",
                             length=60, layers=("ETH", "ARP"), info=f"{who['ip']} is at {who['mac']}",
                             fields=(("Opcode", "reply (2)"), ("Sender MAC address", who["mac"]),
                                     ("Sender IP address", who["ip"]), ("Target IP address", gw["ip"])))
    if kind == "icmp":
        server = rng.choice(CAPTURE_SERVERS)
        ident, seq = 0x0001, rng.randrange(1, 4000)
        body = b"abcdefghijklmnopqrstuvwabcdefghi"
        out = rng.random() < 0.5
        src, dst = (pc["ip"], server["ip"]) if out else (server["ip"], pc["ip"])
        what = "request" if out else "reply"
        return capture_parts(src=src, dst=dst, src_mac=capture_mac_for(src), dst_mac=capture_mac_for(dst),
                             proto="ICMP", length=74, layers=("ETH", "IPv4", "ICMP"), payload=body,
                             icmp=(8 if out else 0, ident, seq),
                             info=f"Echo (ping) {what} id=0x{ident:04x} seq={seq}",
                             fields=(("Type", f"{8 if out else 0} (Echo (ping) {what})"), ("Code", "0"),
                                     ("Identifier", f"0x{ident:04x}"), ("Sequence number", str(seq))))
    if kind == "dns":
        server = rng.choice(CAPTURE_SERVERS)
        resolver = rng.choice(CAPTURE_RESOLVERS)
        txid = rng.randrange(0x1000, 0xFFFF)
        rtype = "AAAA" if server["ip6"] and rng.random() < 0.3 else "A"
        answer = server["ip6"] if rtype == "AAAA" else server["ip"]
        name = server["name"]
        if rng.random() < 0.5:
            return capture_parts(src=pc["ip"], dst=resolver, src_mac=pc["mac"], dst_mac=capture_mac_for(resolver),
                                 proto="DNS", sport=rng.randrange(49152, 65535), dport=53, length=rng.randrange(72, 96),
                                 layers=("ETH", "IPv4", "UDP", "DNS"), payload=name.encode("ascii"),
                                 info=f"Standard query 0x{txid:04x} {rtype} {name}",
                                 fields=(("Transaction ID", f"0x{txid:04x}"), ("Flags", "0x0100 Standard query"),
                                         ("Questions", "1"), ("Answer RRs", "0"), ("Name", name), ("Type", rtype)))
        return capture_parts(src=resolver, dst=pc["ip"], src_mac=capture_mac_for(resolver), dst_mac=pc["mac"],
                             proto="DNS", sport=53, dport=rng.randrange(49152, 65535), length=rng.randrange(100, 170),
                             layers=("ETH", "IPv4", "UDP", "DNS"), payload=name.encode("ascii"),
                             info=f"Standard query response 0x{txid:04x} {rtype} {name} {rtype} {answer}",
                             fields=(("Transaction ID", f"0x{txid:04x}"), ("Flags", "0x8180 Standard query response"),
                                     ("Questions", "1"), ("Answer RRs", "1"), ("Name", name), ("Type", rtype),
                                     ("Address", answer)))
    if kind == "dhcp":
        xid = rng.randrange(0x10000000, 0x7FFFFFFF)
        if rng.random() < 0.5:
            return capture_parts(src="0.0.0.0", dst="255.255.255.255", src_mac=CAPTURE_PHONE["mac"],
                                 dst_mac=CAPTURE_BROADCAST_MAC, proto="DHCP", sport=68, dport=67, length=342,
                                 layers=("ETH", "IPv4", "UDP", "DHCP"),
                                 info=f"DHCP Request - Transaction ID 0x{xid:08x}",
                                 fields=(("Message type", "Boot Request (1)"), ("Transaction ID", f"0x{xid:08x}"),
                                         ("Client MAC address", CAPTURE_PHONE["mac"]),
                                         ("Option 53", "DHCP Message Type (Request)"),
                                         ("Option 50", f"Requested IP Address ({CAPTURE_PHONE['ip']})")))
        return capture_parts(src=gw["ip"], dst=CAPTURE_PHONE["ip"], src_mac=gw["mac"], dst_mac=CAPTURE_PHONE["mac"],
                             proto="DHCP", sport=67, dport=68, length=342, layers=("ETH", "IPv4", "UDP", "DHCP"),
                             info=f"DHCP ACK - Transaction ID 0x{xid:08x}",
                             fields=(("Message type", "Boot Reply (2)"), ("Transaction ID", f"0x{xid:08x}"),
                                     ("Your (client) IP address", CAPTURE_PHONE["ip"]),
                                     ("Option 53", "DHCP Message Type (ACK)"),
                                     ("Option 51", "IP Address Lease Time (3600 s)")))
    if kind == "rtsp":
        cam = CAPTURE_CAMERA
        seq = rng.randrange(2, 40)
        if rng.random() < 0.5:
            verb = rng.choice(("DESCRIBE", "SETUP", "PLAY", "OPTIONS"))
            text = (f"{verb} rtsp://{cam['ip']}/stream1 RTSP/1.0\r\nCSeq: {seq}\r\n"
                    f"User-Agent: TNT mock\r\n\r\n").encode("ascii")
            return capture_parts(src=CAPTURE_NVR["ip"], dst=cam["ip"], src_mac=CAPTURE_NVR["mac"], dst_mac=cam["mac"],
                                 proto="RTSP", sport=rng.randrange(49152, 65535), dport=554, length=len(text) + 54,
                                 layers=("ETH", "IPv4", "TCP", "RTSP"), payload=text,
                                 info=f"{verb} rtsp://{cam['ip']}/stream1 RTSP/1.0",
                                 fields=(("Method", verb), ("URL", f"rtsp://{cam['ip']}/stream1"), ("CSeq", str(seq))))
        text = f"RTSP/1.0 200 OK\r\nCSeq: {seq}\r\nSession: 12345678\r\n\r\n".encode("ascii")
        return capture_parts(src=cam["ip"], dst=CAPTURE_NVR["ip"], src_mac=cam["mac"], dst_mac=CAPTURE_NVR["mac"],
                             proto="RTSP", sport=554, dport=rng.randrange(49152, 65535), length=len(text) + 54,
                             layers=("ETH", "IPv4", "TCP", "RTSP"), payload=text, info="RTSP/1.0 200 OK",
                             fields=(("Status", "200"), ("Reason", "OK"), ("CSeq", str(seq)), ("Session", "12345678")))
    if kind == "http":
        server = rng.choice(CAPTURE_SERVERS)
        port = rng.randrange(49152, 65535)
        if rng.random() < 0.5:
            path = rng.choice(("/", "/index.html", "/api/v1/status", "/images/logo.png"))
            text = (f"GET {path} HTTP/1.1\r\nHost: {server['name']}\r\nUser-Agent: Mozilla/5.0\r\n"
                    f"Accept: */*\r\nConnection: keep-alive\r\n\r\n").encode("ascii")
            return capture_parts(src=pc["ip"], dst=server["ip"], src_mac=pc["mac"], dst_mac=gw["mac"], proto="HTTP",
                                 sport=port, dport=80, length=len(text) + 54, layers=("ETH", "IPv4", "TCP", "HTTP"),
                                 payload=text, info=f"GET {path} HTTP/1.1",
                                 fields=(("Request method", "GET"), ("Request URI", path),
                                         ("Request version", "HTTP/1.1"), ("Host", server["name"])))
        text = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 1274\r\n"
                b"Server: ExampleHTTP/1.4\r\n\r\n")
        return capture_parts(src=server["ip"], dst=pc["ip"], src_mac=gw["mac"], dst_mac=pc["mac"], proto="HTTP",
                             sport=80, dport=port, length=len(text) + 54, layers=("ETH", "IPv4", "TCP", "HTTP"),
                             payload=text, info="HTTP/1.1 200 OK (text/html)",
                             fields=(("Response version", "HTTP/1.1"), ("Status code", "200"),
                                     ("Reason phrase", "OK"), ("Content-Type", "text/html; charset=utf-8"),
                                     ("Content-Length", "1274")))
    if kind == "tcp":
        server = rng.choice(CAPTURE_SERVERS)
        port = rng.choice((22, 3389, 8000, 9100, 445))
        mine = rng.randrange(49152, 65535)
        flag, bits, extra = rng.choice((("[SYN]", 0x02, "Seq=0 Win=64240 Len=0"),
                                        ("[SYN, ACK]", 0x12, "Seq=0 Ack=1 Win=65535 Len=0"),
                                        ("[ACK]", 0x10, "Seq=1 Ack=1 Win=502 Len=0"),
                                        ("[PSH, ACK]", 0x18, f"Seq=1 Ack=1 Win=502 Len={rng.randrange(24, 700)}"),
                                        ("[FIN, ACK]", 0x11, "Seq=734 Ack=1 Win=502 Len=0")))
        out = flag != "[SYN, ACK]"
        src, dst = (pc["ip"], server["ip"]) if out else (server["ip"], pc["ip"])
        sport, dport = (mine, port) if out else (port, mine)
        return capture_parts(src=src, dst=dst, src_mac=capture_mac_for(src), dst_mac=capture_mac_for(dst),
                             proto="TCP", sport=sport, dport=dport, length=rng.randrange(60, 120), flags=bits,
                             layers=("ETH", "IPv4", "TCP"), info=f"{sport} > {dport} {flag} {extra}",
                             fields=(("Source port", str(sport)), ("Destination port", str(dport)),
                                     ("Flags", flag), ("Window", "64240")))
    if kind == "udp":
        mine, port = rng.randrange(49152, 65535), rng.choice((3478, 5353, 1900, 123))
        length = rng.randrange(70, 220)
        return capture_parts(src=pc["ip"], dst="203.0.113.90", src_mac=pc["mac"], dst_mac=gw["mac"], proto="UDP",
                             sport=mine, dport=port, length=length, layers=("ETH", "IPv4", "UDP"),
                             info=f"{mine} > {port} Len={length - 42}",
                             fields=(("Source port", str(mine)), ("Destination port", str(port)),
                                     ("Length", str(length - 34))))
    # https: TLS over TCP, every so often over IPv6 so the list is not all v4
    server = rng.choice(CAPTURE_SERVERS)
    six = bool(server["ip6"]) and rng.random() < 0.2
    mine = rng.randrange(49152, 65535)
    out = rng.random() < 0.55
    theirs = server["ip6"] if six else server["ip"]
    mine_ip = pc["ip6"] if six else pc["ip"]
    src, dst = (mine_ip, theirs) if out else (theirs, mine_ip)
    sport, dport = (mine, 443) if out else (443, mine)
    record = rng.choice(("data", "data", "data", "client_hello", "server_hello"))
    if record == "client_hello":
        info = f"Client Hello (SNI={server['name']})"
        fields = (("Content Type", "Handshake (22)"), ("Version", "TLS 1.2 (0x0303)"),
                  ("Handshake Type", "Client Hello (1)"), ("Server Name", server["name"]))
        head, length = b"\x16\x03\x01", rng.randrange(280, 560)
    elif record == "server_hello":
        info = "Server Hello, Certificate, Server Hello Done"
        fields = (("Content Type", "Handshake (22)"), ("Version", "TLS 1.2 (0x0303)"),
                  ("Handshake Type", "Server Hello (2)"), ("Cipher Suite", "TLS_AES_128_GCM_SHA256 (0x1301)"))
        head, length = b"\x16\x03\x03", rng.randrange(900, 1480)
    else:
        info = "Application Data"
        length = rng.randrange(120, 1480)
        fields = (("Content Type", "Application Data (23)"), ("Version", "TLS 1.2 (0x0303)"),
                  ("Length", str(max(1, length - (74 if six else 54)))))
        head = b"\x17\x03\x03"
    return capture_parts(src=src, dst=dst, src_mac=capture_mac_for(src), dst_mac=capture_mac_for(dst), proto="TLS",
                         sport=sport, dport=dport, length=length, payload=head, info=info, fields=fields,
                         layers=("ETH", "IPv6" if six else "IPv4", "TCP", "TLS"))


def capture_sip_call(rng: random.Random) -> Dict[str, Any]:
    """The scripted call as tnt.sipcalls.CallTracker would answer it (SIP_CALL_KEYS), before any of it has happened."""
    tag = f"{rng.getrandbits(32):08x}{rng.getrandbits(16):04x}"
    call_id = f"{tag}@{CAPTURE_PHONE['ip']}"
    return {"id": f"{tag}-192-0-2-60-{tag[:8]}", "call_id": call_id, "from_uri": CAPTURE_SIP_FROM,
            "to_uri": CAPTURE_SIP_TO, "state": "calling", "start_ts": 0.0, "answer_ts": None, "end_ts": None,
            "duration_s": 0.0, "status": None, "messages": [], "streams": [], "note": None}


def _sip_message(call: Dict[str, Any], line: str, body: str = "") -> bytes:
    """One SIP datagram of the scripted call, the headers a phone really sends (RFC 3261) over an optional SDP body."""
    head = (f"{line}\r\n"
            f"Via: SIP/2.0/UDP {CAPTURE_PHONE['ip']}:5060;branch=z9hG4bK{call['id'][:16]}\r\n"
            f"From: \"Reception\" <{CAPTURE_SIP_FROM}>;tag={call['id'][:8]}\r\n"
            f"To: <{CAPTURE_SIP_TO}>\r\n"
            f"Call-ID: {call['call_id']}\r\n"
            f"CSeq: 1 INVITE\r\n"
            f"Contact: <sip:2001@{CAPTURE_PHONE['ip']}:5060>\r\n"
            f"User-Agent: ExamplePhone/2.4.1\r\n")
    if body:
        head += f"Content-Type: application/sdp\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    else:
        head += "Content-Length: 0\r\n\r\n"
    return head.encode("ascii", "replace")


def _sip_sdp(ip: str, port: int) -> str:
    return (f"v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n"
            f"m=audio {port} RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n")


def _sip_packet(call: Dict[str, Any], from_phone: bool, line: str, info: str, body: str = "") -> Dict[str, Any]:
    src, dst = (CAPTURE_PHONE, CAPTURE_PBX) if from_phone else (CAPTURE_PBX, CAPTURE_PHONE)
    payload = _sip_message(call, line, body)
    head = line.split()
    request = not line.startswith("SIP/2.0")
    return capture_parts(src=src["ip"], dst=dst["ip"], src_mac=src["mac"], dst_mac=dst["mac"], proto="SIP",
                         sport=5060, dport=5060, length=len(payload) + 42, layers=("ETH", "IPv4", "UDP", "SIP"),
                         payload=payload, info=info,
                         fields=(("Start line", line), ("Call-ID", call["call_id"]), ("From", CAPTURE_SIP_FROM),
                                 ("To", CAPTURE_SIP_TO), ("CSeq", "1 INVITE")),
                         # the MESSAGE row this packet adds to the call (tnt.sipcalls.MESSAGE_KEYS)
                         sip={"kind": "request" if request else "response",
                              "method": head[0] if request else None,
                              "status": None if request else int(head[1]),
                              "reason": None if request else " ".join(head[2:])})


def _rtp_packet(call: Dict[str, Any], from_phone: bool, seq: int, stamp: int, ssrc: int) -> Dict[str, Any]:
    src, dst = (CAPTURE_PHONE, CAPTURE_PBX) if from_phone else (CAPTURE_PBX, CAPTURE_PHONE)
    sport, dport = CAPTURE_SIP_RTP_PORTS if from_phone else CAPTURE_SIP_RTP_PORTS[::-1]
    header = struct.pack("!BBHII", 0x80, 0, seq & 0xFFFF, stamp & 0xFFFFFFFF, ssrc)
    return capture_parts(src=src["ip"], dst=dst["ip"], src_mac=src["mac"], dst_mac=dst["mac"], proto="RTP",
                         sport=sport, dport=dport, length=214, layers=("ETH", "IPv4", "UDP", "RTP"), payload=header,
                         info=f"PT=ITU-T G.711 PCMU, SSRC=0x{ssrc:08x}, Seq={seq}, Time={stamp}",
                         fields=(("Version", "2"), ("Payload type", "ITU-T G.711 PCMU (0)"), ("Sequence number", str(seq)),
                                 ("Timestamp", str(stamp)), ("Synchronization Source identifier", f"0x{ssrc:08x}")))


def capture_sip_plan(rng: random.Random, call: Dict[str, Any]) -> List[Tuple[float, Dict[str, Any], Optional[str]]]:
    """Every packet of the scripted call as ``(seconds after the capture began, the packet, the mark it moves the call
    to)``, oldest first: INVITE, 180 Ringing, 200 OK, ACK, RTP both ways, BYE and its 200 OK."""
    at = CAPTURE_SIP_AT
    ssrcs = (rng.getrandbits(32), rng.getrandbits(32))
    plan: List[Tuple[float, Dict[str, Any], Optional[str]]] = [
        (at["invite"], _sip_packet(call, True, f"INVITE {CAPTURE_SIP_TO} SIP/2.0", f"Request: INVITE {CAPTURE_SIP_TO}",
                                   _sip_sdp(CAPTURE_PHONE["ip"], CAPTURE_SIP_RTP_PORTS[0])), "invite"),
        (at["ringing"], _sip_packet(call, False, "SIP/2.0 180 Ringing", "Status: 180 Ringing"), "ringing"),
        (at["answer"], _sip_packet(call, False, "SIP/2.0 200 OK", "Status: 200 OK (INVITE)",
                                   _sip_sdp(CAPTURE_PBX["ip"], CAPTURE_SIP_RTP_PORTS[1])), "answer"),
        (at["ack"], _sip_packet(call, True, f"ACK {CAPTURE_SIP_TO} SIP/2.0", f"Request: ACK {CAPTURE_SIP_TO}"), None),
        (at["bye"], _sip_packet(call, True, f"BYE {CAPTURE_SIP_TO} SIP/2.0", f"Request: BYE {CAPTURE_SIP_TO}"), "bye"),
        (at["byeok"], _sip_packet(call, False, "SIP/2.0 200 OK", "Status: 200 OK (BYE)"), None),
    ]
    step = 1.0 / CAPTURE_SIP_RTP_HZ
    when, seq, stamp = at["ack"] + step, rng.randrange(1000, 40000), rng.randrange(0, 100000)
    while when < at["bye"]:
        for which in (True, False):
            plan.append((when, _rtp_packet(call, which, seq, stamp, ssrcs[0 if which else 1]), "rtp"))
        seq, stamp, when = seq + 1, stamp + int(8000 * step), when + step
    plan.sort(key=lambda entry: entry[0])
    return plan


def capture_sip_mark(call: Dict[str, Any], parts: Dict[str, Any], mark: Optional[str], ts: float,
                     no: Optional[int] = None) -> None:
    """Move the scripted call on as its next packet is emitted (tnt.sipcalls.CallTracker's state machine): the SIP
    message is recorded, the RTP is counted into the two streams and the state follows the mark."""
    sip = parts.get("sip")
    if sip:
        call["messages"].append({"ts": ts, "kind": sip["kind"], "method": sip["method"], "status": sip["status"],
                                 "reason": sip["reason"], "src": parts["src"], "dst": parts["dst"],
                                 "cseq": 1, "cseq_method": "INVITE", "via_branch": f"z9hG4bK-{no or 0}",
                                 "contact": CAPTURE_SIP_CONTACT if sip["kind"] == "request" else None,
                                 "user_agent": CAPTURE_SIP_UA, "has_sdp": bool(sip.get("sdp")),
                                 "sdp_c": CAPTURE_PHONE["ip"] if sip.get("sdp") else None,
                                 # the locator a ladder row clicks through on: the packet's own number in this capture
                                 "where": no, "side": None})
    if mark == "invite":
        call["start_ts"] = ts
    elif mark == "ringing":
        call["state"] = "ringing"
    elif mark == "answer":
        call.update(state="answered", answer_ts=ts, status=200)
        for index, from_phone in enumerate((True, False)):
            src, dst = (CAPTURE_PHONE, CAPTURE_PBX) if from_phone else (CAPTURE_PBX, CAPTURE_PHONE)
            sport, dport = CAPTURE_SIP_RTP_PORTS if from_phone else CAPTURE_SIP_RTP_PORTS[::-1]
            call["streams"].append({"id": f"{call['id']}-{index}", "src": src["ip"], "sport": sport, "dst": dst["ip"],
                                    "dport": dport, "ssrc": 0x1A2B3C4D + index, "payload_type": 0,
                                    "codec": CAPTURE_SIP_CODEC, "packets": 0, "lost": 0, "out_of_order": 0,
                                    "first_ts": ts, "last_ts": ts, "duration_s": 0.0, "bytes": 0,
                                    "jitter_ms": 0.0, "decodable": True})
    elif mark == "rtp":
        for stream in call["streams"]:
            stream["packets"] += 1
            stream["bytes"] += 172
            stream["last_ts"] = ts
            stream["duration_s"] = round(max(0.0, ts - stream["first_ts"]), 3)
    elif mark == "bye":
        call.update(state="ended", end_ts=ts)
    start = call["answer_ts"] if call["answer_ts"] is not None else call["start_ts"]
    call["duration_s"] = round(max(0.0, ts - float(start or ts)), 3)


def capture_make_rows(count: int, first_ts: float,
                      seed: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """*count* invented packets from *first_ts* on, as ``(rows, meta, calls)``: the background mix at its usual rate
    with the scripted SIP call among it, so a capture read back from a file looks like one taken here."""
    rng = random.Random(seed)
    call = capture_sip_call(rng)
    plan = capture_sip_plan(rng, call)
    rows: List[Dict[str, Any]] = []
    meta: List[Dict[str, Any]] = []
    wanted = max(0, int(count))
    at, rel, last = 0, 0.0, 0.0

    def add(when: float, parts: Dict[str, Any]) -> float:
        moment = max(when, last + 0.0002)                 # the list is always in arrival order
        rows.append({"no": len(rows) + 1, "ts": first_ts + moment, "rel": round(moment, 6), "src": parts["src"],
                     "dst": parts["dst"], "src_mac": parts["src_mac"], "dst_mac": parts["dst_mac"],
                     "proto": parts["proto"], "sport": parts["sport"], "dport": parts["dport"],
                     "length": int(parts["length"]), "info": parts["info"]})
        meta.append({"layers": tuple(parts["layers"]), "fields": tuple(parts["fields"]), "payload": parts["payload"],
                     "flags": parts["flags"], "icmp": parts["icmp"]})
        return moment

    while len(rows) < wanted:
        rel += 1.0 / rng.uniform(*CAPTURE_RATE_RANGE)
        while at < len(plan) and plan[at][0] <= rel and len(rows) < wanted:
            when, parts, mark = plan[at]
            at += 1
            last = add(when, parts)
            capture_sip_mark(call, parts, mark, first_ts + last, len(rows))
        if len(rows) >= wanted:
            break
        last = add(rel, capture_invent(rng))
    return rows, meta, ([call] if call["start_ts"] else [])


# -- packet capture: the bytes behind a row, its detail tree and its hex dump (tnt.dissect) ------------------------
def _mac_bytes(text: str) -> bytes:
    raw = bytes.fromhex("".join(c for c in str(text or "") if c in "0123456789abcdefABCDEF")[:12].rjust(12, "0"))
    return (raw + b"\x00" * 6)[:6]


def _ip_bytes(text: str, size: int) -> bytes:
    try:
        packed = ipaddress.ip_address(str(text)).packed
    except ValueError:
        packed = b"\x00" * size
    return (packed + b"\x00" * size)[:size]


def capture_frame(row: Dict[str, Any], layers: Tuple[str, ...], payload: bytes, flags: int,
                  icmp: Tuple[int, int, int]) -> bytes:
    """The bytes behind an invented row: a real Ethernet / IP / transport header stack over *payload*, filled out to
    the row's length so the hex dump the detail window shows matches what the list says."""
    dst_mac, src_mac = _mac_bytes(row["dst_mac"]), _mac_bytes(row["src_mac"])
    want = max(60, min(int(row["length"] or 60), 1514))
    if "ARP" in layers:
        op = 1 if str(row["info"]).startswith("Who has") else 2
        arp = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + src_mac + _ip_bytes(row["src"], 4)
               + (b"\x00" * 6 if op == 1 else dst_mac) + _ip_bytes(row["dst"], 4))
        return _capture_fill(dst_mac + src_mac + b"\x08\x06" + arp, want)
    body = payload
    if "TCP" in layers:
        upper = struct.pack("!HHIIBBHHH", int(row["sport"] or 0), int(row["dport"] or 0), 0x0BADC0DE, 0x0BADBEEF,
                            0x50, flags & 0xFF, 64240, 0, 0)
        protocol = 6
    elif "UDP" in layers:
        upper = struct.pack("!HHHH", int(row["sport"] or 0), int(row["dport"] or 0), 8 + len(body), 0)
        protocol = 17
    elif "ICMP" in layers:
        kind, ident, seq = icmp
        head = struct.pack("!BBHHH", kind, 0, 0, ident, seq) + body
        upper, body, protocol = head[:2] + struct.pack("!H", _inet_checksum(head)) + head[4:], b"", 1
    else:
        upper, protocol = b"", 59
    if "IPv6" in layers:
        head = (struct.pack("!IHBB", 0x60000000, len(upper) + len(body), protocol, 64)
                + _ip_bytes(row["src"], 16) + _ip_bytes(row["dst"], 16))
        return _capture_fill(dst_mac + src_mac + b"\x86\xdd" + head + upper + body, want)
    total = 20 + len(upper) + len(body)
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, int(row["no"]) & 0xFFFF, 0x4000, 64, protocol, 0,
                       _ip_bytes(row["src"], 4), _ip_bytes(row["dst"], 4))
    head = head[:10] + struct.pack("!H", _inet_checksum(head)) + head[12:]
    return _capture_fill(dst_mac + src_mac + b"\x08\x00" + head + upper + body, want)


def _capture_fill(frame: bytes, want: int) -> bytes:
    """*frame* padded out to *want* bytes with filler a real payload could hold, or cut to it."""
    if len(frame) >= want:
        return frame[:want]
    filler = bytes((0x30 + ((i * 7 + len(frame)) % 74)) & 0xFF for i in range(want - len(frame)))
    return frame + filler


def capture_time_text(ts: Optional[float]) -> str:
    """A packet's arrival time as tnt.dissect writes it: "2026-01-01 12:00:00.123456 UTC", else "not recorded"."""
    if ts is None:
        return "not recorded"
    whole = int(ts)
    micros = min(999_999, int((float(ts) - whole) * 1_000_000))
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(whole)) + f".{micros:06d} UTC"


def _layer(name: str, summary: str, start: int, length: int,
           fields: Tuple[Tuple[str, str], ...]) -> Dict[str, Any]:
    return {"name": name, "summary": summary, "start": start, "length": length,
            "fields": [{"name": n, "value": v, "start": start, "length": 0} for n, v in fields]}


def capture_detail(row: Dict[str, Any], layers: Tuple[str, ...], fields: Tuple[Tuple[str, str], ...],
                   frame: bytes) -> List[Dict[str, Any]]:
    """The detail tree of one invented row (tnt.dissect.detail): outermost first, the Frame pseudo-layer, the link
    layer, the network layer, the transport layer and the application layer the row's protocol names."""
    size = len(frame)
    kind = "ARP (0x0806)" if "ARP" in layers else ("IPv6 (0x86dd)" if "IPv6" in layers else "IPv4 (0x0800)")
    out = [{"name": "Frame", "summary": f"Frame: {row['length']} bytes on the wire, {size} bytes captured",
            "start": 0, "length": size,
            "fields": [{"name": "Arrival time", "value": capture_time_text(row["ts"]), "start": 0, "length": 0},
                       {"name": "Epoch time", "value": f"{row['ts']}", "start": 0, "length": 0},
                       {"name": "Captured length", "value": f"{size} bytes", "start": 0, "length": 0},
                       {"name": "Frame length", "value": f"{row['length']} bytes", "start": 0, "length": 0},
                       {"name": "Link type", "value": "Ethernet (1)", "start": 0, "length": 0}]},
           {"name": "ETH", "summary": f"Ethernet II, {row['src_mac']} > {row['dst_mac']}, type {kind}",
            "start": 0, "length": 14,
            "fields": [{"name": "Destination", "value": row["dst_mac"], "start": 0, "length": 6},
                       {"name": "Source", "value": row["src_mac"], "start": 6, "length": 6},
                       {"name": "Type", "value": kind, "start": 12, "length": 2}]}]
    at = 14
    if "ARP" in layers:
        out.append(_layer("ARP", row["info"], at, 28, fields))
        return out
    if "IPv6" in layers:
        out.append(_layer("IPv6", f"Internet Protocol Version 6, Src: {row['src']}, Dst: {row['dst']}", at, 40,
                          (("Version", "6"), ("Payload length", str(max(0, size - at - 40))), ("Hop limit", "64"),
                           ("Source", row["src"]), ("Destination", row["dst"]))))
        at += 40
    else:
        out.append(_layer("IPv4", f"Internet Protocol Version 4, Src: {row['src']}, Dst: {row['dst']}", at, 20,
                          (("Version", "4"), ("Header length", "20 bytes (5)"),
                           ("Total length", str(max(0, size - at))), ("Identification", f"0x{row['no'] & 0xFFFF:04x}"),
                           ("Time to live", "64"), ("Source", row["src"]), ("Destination", row["dst"]))))
        at += 20
    app = layers[-1] if layers and layers[-1] not in ("ETH", "IPv4", "IPv6", "TCP", "UDP", "ICMP", "ICMPv6") else ""
    if "TCP" in layers:
        out.append(_layer("TCP", f"Transmission Control Protocol, Src Port: {row['sport']}, Dst Port: {row['dport']}",
                          at, 20, fields if not app else (("Source port", str(row["sport"])),
                                                          ("Destination port", str(row["dport"])),
                                                          ("Header length", "20 bytes (5)"), ("Window", "64240"))))
        at += 20
    elif "UDP" in layers:
        out.append(_layer("UDP", f"User Datagram Protocol, Src Port: {row['sport']}, Dst Port: {row['dport']}", at, 8,
                          fields if not app else (("Source port", str(row["sport"])),
                                                  ("Destination port", str(row["dport"])),
                                                  ("Length", str(max(0, size - at))))))
        at += 8
    elif "ICMP" in layers:
        out.append(_layer("ICMP", row["info"], at, 8, fields))
        return out
    if app:
        out.append(_layer(app, row["info"], at, max(0, size - at), fields))
    return out


def capture_hex(data: bytes, width: int = 16) -> List[str]:
    """Classic offset / hex / ASCII lines, exactly as tnt.dissect.hex_dump writes them."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hexed = " ".join(f"{byte:02x}" for byte in chunk).ljust(width * 3 - 1)
        text = "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in chunk)
        lines.append(f"{offset:04x}  {hexed}   {text}")
    return lines


_CAPTURE_WAV: Optional[bytes] = None


def capture_call_wav() -> bytes:
    """A call rebuilt as audio (tnt.sipcalls.build_wav's shape): a quiet two-tone warble, 8 kHz 16-bit mono, built
    here with struct so the page's player visibly works. Built once and kept."""
    global _CAPTURE_WAV
    if _CAPTURE_WAV is not None:
        return _CAPTURE_WAV
    rate, low, high = CAPTURE_WAV_RATE, *CAPTURE_WAV_TONES
    count = int(rate * CAPTURE_WAV_SECONDS)
    samples = bytearray()
    for index in range(count):
        moment = index / rate
        fade = min(1.0, moment / 0.05, max(0.0, (CAPTURE_WAV_SECONDS - moment) / 0.05))
        warble = math.sin(2 * math.pi * low * moment) * 0.22 + math.sin(2 * math.pi * high * moment) * 0.14
        swell = 0.75 + 0.25 * math.sin(2 * math.pi * 1.7 * moment)
        samples += struct.pack("<h", int(max(-1.0, min(1.0, warble * swell * fade)) * 32767))
    header = (b"RIFF" + struct.pack("<I", 36 + len(samples)) + b"WAVEfmt "
              + struct.pack("<IHHIIHH", 16, 1, 1, rate, rate * 2, 2, 16) + b"data" + struct.pack("<I", len(samples)))
    _CAPTURE_WAV = header + bytes(samples)
    return _CAPTURE_WAV


def _quality_num(value: float) -> str:
    text = f"{float(value):.1f}"
    return text[:-2] if text.endswith(".0") else text


def bloat_grade(increase_ms: Optional[float]) -> Optional[str]:
    """tnt.speedtest.quality.bloat_grade: <5 A+, <30 A, <60 B, <200 C, <400 D, else F; None for None."""
    if increase_ms is None:
        return None
    for bound, grade in GRADE_BOUNDS:
        if float(increase_ms) < bound:
            return grade
    return "F"


def call_quality(mean_ms: Optional[float], jitter_ms: Optional[float], loss_pct: Optional[float]) -> Dict[str, Any]:
    """tnt.speedtest.quality.call_quality, the simplified E-model: {r, mos, label}; a missing value counts as 0."""
    leff = max(0.0, float(mean_ms or 0.0)) + 2.0 * max(0.0, float(jitter_ms or 0.0)) + 10.0
    r = 93.2 - leff / 40.0 if leff < 160.0 else 93.2 - (leff - 120.0) / 10.0
    r = max(0.0, min(100.0, r - 2.5 * max(0.0, float(loss_pct or 0.0))))
    mos = max(1.0, 1.0 + 0.035 * r + 7e-6 * r * (r - 60.0) * (100.0 - r))      # never below the bottom of the MOS scale
    r = round(r, 2)
    return {"r": r, "mos": round(mos, 2), "label": next((label for bound, label in CALL_LABELS if r >= bound), CALL_LABEL_WORST)}


def _quality_checks(window: Dict[str, Any], scope: str) -> List[Dict[str, Any]]:
    mean, jitter, loss = (float(window.get(k) or 0.0) for k in ("mean_ms", "jitter_ms", "loss_pct"))
    checks = []
    for key, max_mean, max_jitter, max_loss, inclusive in CALL_CHECKS:
        verb = "is above" if inclusive else "is not below"
        failures = [f"{what} {_quality_num(value)}{unit} {verb} {_quality_num(limit)}{unit}"
                    for what, value, limit, unit in (("latency", mean, max_mean, " ms"), ("jitter", jitter, max_jitter, " ms"),
                                                     ("loss", loss, max_loss, "%"))
                    if (value > limit if inclusive else value >= limit)]
        detail = "; ".join(failures) if failures else \
            f"latency {_quality_num(mean)} ms, jitter {_quality_num(jitter)} ms, loss {_quality_num(loss)}%"
        checks.append({"key": key, "ok": not failures, "detail": f"{detail} ({scope})"})
    return checks


def _quality_loaded(stats: Dict[str, Any], baseline_median: Optional[float]) -> Dict[str, Any]:
    window = dict(stats)
    window.update(dict.fromkeys(LOADED_EXTRA_KEYS))
    sent, received, skipped, loss = stats["sent"], stats["received"], stats["skipped"], stats["loss_pct"]
    increase = None
    if stats["mean_ms"] is not None and baseline_median is not None:
        increase = round(max(0.0, stats["mean_ms"] - baseline_median), 1)
    warnings = []
    if sent < QUALITY_MIN_SENT:
        window["reason"] = REASON_TOO_SHORT
    elif loss is not None and loss >= QUALITY_MOST_LOST_PCT:
        window.update(grade="F", reason=REASON_MOST_LOST, increase_ms=increase)
    elif received < QUALITY_MIN_RECEIVED:
        window["reason"] = REASON_TOO_SHORT
    else:
        window.update(increase_ms=increase, grade=bloat_grade(increase))
        if loss is not None and QUALITY_SOME_LOST_PCT <= loss < QUALITY_MOST_LOST_PCT:
            warnings.append(WARNING_SOME_LOST)
    if skipped and skipped > QUALITY_SKIPPED_WARN_SHARE * (sent + skipped):
        warnings.append(WARNING_DELAYED)
    window["warning"] = "; ".join(warnings) or None
    return window


def _quality_bufferbloat(loaded: Dict[str, Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    out: Dict[str, Any] = dict.fromkeys(BUFFERBLOAT_KEYS)
    graded = [(name, w) for name, w in loaded.items() if w is not None and w.get("grade") in GRADES]
    if not graded:
        reasons = [w["reason"] for w in loaded.values() if w is not None and w.get("reason")]
        out["reason"] = reasons[0] if reasons else REASON_TOO_SHORT
        return out
    direction, worst = max(graded, key=lambda item: (GRADES.index(item[1]["grade"]),
                                                     math.inf if item[1].get("increase_ms") is None else float(item[1]["increase_ms"])))
    warnings: List[str] = []
    for _name, window in [(direction, worst)] + [g for g in graded if g[0] != direction]:
        for text in str(window.get("warning") or "").split("; "):
            if text and text not in warnings:
                warnings.append(text)
    out.update(grade=worst["grade"], increase_ms=worst.get("increase_ms"), direction=direction, text=GRADE_TEXT[worst["grade"]],
               warning="; ".join(warnings) or None)
    return out


def _quality_call(baseline: Dict[str, Any], loaded: Dict[str, Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    idle = call_quality(baseline.get("mean_ms"), baseline.get("jitter_ms"), baseline.get("loss_pct"))
    worst: Optional[Tuple[str, Dict[str, Any], Dict[str, Any]]] = None
    for name, window in loaded.items():
        if window is None or int(window.get("sent") or 0) < QUALITY_MIN_SENT:
            continue
        score = call_quality(window.get("mean_ms"), window.get("jitter_ms"), window.get("loss_pct"))
        if worst is None or score["r"] < worst[2]["r"]:
            worst = (name, window, score)
    if worst is None:
        return {"method": CALL_METHOD, "idle": idle, "loaded": None, "checks": _quality_checks(baseline, QUALITY_SCOPE["baseline"])}
    name, window, score = worst
    return {"method": CALL_METHOD, "idle": idle, "loaded": dict(score, direction=name), "checks": _quality_checks(window, QUALITY_SCOPE[name])}


def speed_quality(baseline: Dict[str, Any], download: Optional[Dict[str, Any]], upload: Optional[Dict[str, Any]],
                  target: str = QUALITY_TARGET, interval_ms: int = QUALITY_INTERVAL_MS, payload: int = QUALITY_PAYLOAD) -> Dict[str, Any]:
    """A speed test's QUALITY from its probe windows (WINDOW statistics; a loaded window None when its phase never ran), graded
    like tnt.speedtest.quality.build_quality once it has split the echoes into windows."""
    reason = None
    if not baseline["sent"]:
        reason = REASON_NO_BASELINE
    elif baseline["received"] < QUALITY_BASELINE_MIN_ANSWERED * baseline["sent"]:
        reason = REASON_NO_REPLIES.format(target=target)
    windows: Dict[str, Optional[Dict[str, Any]]] = {"baseline": baseline}
    for name, stats in (("download", download), ("upload", upload)):
        if stats is None:
            windows[name] = None
        elif reason is None:
            windows[name] = _quality_loaded(stats, baseline["median_ms"])
        else:
            windows[name] = {**stats, **dict.fromkeys(LOADED_EXTRA_KEYS)}
    quality: Dict[str, Any] = dict.fromkeys(QUALITY_KEYS)
    quality.update(version=QUALITY_VERSION, available=reason is None, reason=reason, target=str(target), interval_ms=int(interval_ms),
                   payload_bytes=int(payload), windows=windows)
    if reason is None:
        loaded = {"download": windows["download"], "upload": windows["upload"]}
        quality["bufferbloat"] = _quality_bufferbloat(loaded)
        quality["call"] = _quality_call(baseline, loaded)
    return quality


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
# Pro AV (tnt.proav / tnt.ptp / tnt.mdns): a synthetic broadcast-audio network
#
# One invented room, built so every path the page can draw has something in it: a Dante system whose grandmaster is
# a GPS-locked Audinate clock one boundary clock away (a UniFi AV switch), a transparent clock writing a correction,
# six devices heard over mDNS, four of them following the clock, three announced AES67 streams - one of which still
# names the grandmaster it was set up against, which is the "bad" finding - and a Layer 2 listen that found a
# querier. The shapes below are tnt.proav's key tuples in order; the mock stays stdlib-only and never imports tnt,
# so this is written out rather than generated, exactly as the rest of this file is.
PROAV_SECONDS = (10, 20, 30, 60, 120, 300)
PROAV_DEFAULT_SECONDS = 30
#: How long the mock pretends to listen for, whatever was asked (a real 30 s wait would make the page tedious to work on).
PROAV_FAKE_LISTEN_S = 4.0

PROAV_GM_ID = "00:1D:C1:FF:FE:2A:41:08"
PROAV_GM_MAC = "00:1D:C1:2A:41:08"
PROAV_BC_ID = "74:AC:B9:FF:FE:31:0C:6E"
PROAV_BC_MAC = "74:AC:B9:31:0C:6E"
PROAV_STALE_GM = "AA:BB:CC:FF:FE:10:20:30"


def proav_adapters() -> List[Dict[str, Any]]:
    """The adapters a scan could listen on (tnt.proav.SCAN_ADAPTER_KEYS)."""
    return [
        {"name": "Ethernet", "index": 12, "mac": "9C:6B:00:11:22:33", "ip": "10.113.0.20",
         "type_name": "Ethernet", "speed_mbps": 1000, "wifi": False, "is_internet": True},
        {"name": "Wi-Fi", "index": 15, "mac": "9C:6B:00:44:55:66", "ip": "10.113.9.44",
         "type_name": "Wireless", "speed_mbps": 866, "wifi": True, "is_internet": False},
    ]


def proav_listeners(packets: bool = True) -> List[Dict[str, Any]]:
    """The four joined groups (tnt.proav.LISTENER_KEYS)."""
    rows = [("mdns", "Service discovery (mDNS)", "224.0.0.251", 5353, 214),
            ("sap", "Stream announcements (SAP)", "239.255.255.255", 9875, 9),
            ("ptp-event", "Clock, event messages (PTP)", "224.0.1.129", 319, 486),
            ("ptp-general", "Clock, announcements (PTP)", "224.0.1.129", 320, 173)]
    return [{"key": k, "label": label, "group": g, "port": p, "ok": True, "reason": None,
             "packets": n if packets else 0} for k, label, g, p, n in rows]


def _proav_master(ts: float) -> Dict[str, Any]:
    return {"identity": PROAV_GM_ID, "mac": PROAV_GM_MAC, "vendor": "Audinate Pty L", "ip": None,
            "priority1": 128, "priority2": 128, "clock_class": 6,
            "clock_class_text": "locked to a primary reference (GPS or equivalent)", "accuracy": 33,
            "accuracy_text": "100 ns", "variance": 16640, "steps_removed": 1, "time_source": 32,
            "time_source_text": "GPS", "utc_offset": 37, "leap61": False, "leap59": False,
            "time_traceable": True, "frequency_traceable": True, "locked": True, "two_step": True,
            "parent": PROAV_BC_ID, "parent_mac": PROAV_BC_MAC, "parent_vendor": "Ubiquiti Inc",
            "announce_s": 2.0, "count": 86, "first_ts": ts - 30, "last_ts": ts}


def _proav_follower(identity: str, mac: str, vendor: str, ip: str, asking: bool, ts: float) -> Dict[str, Any]:
    return {"identity": identity, "mac": mac, "vendor": vendor, "ip": ip, "asking": asking,
            "count": 58 if asking else 12, "first_ts": ts - 29, "last_ts": ts}


def proav_clock(ts: float) -> Dict[str, Any]:
    """The clock view (tnt.ptp.CLOCK_KEYS / DOMAIN_KEYS): one PTPv2 domain, one grandmaster, a boundary clock."""
    master = _proav_master(ts)
    followers = [
        _proav_follower("00:1D:C1:FF:FE:2A:41:5C", "00:1D:C1:2A:41:5C", "Audinate Pty L", "10.113.0.31", True, ts),
        _proav_follower("00:1D:C1:FF:FE:2A:42:11", "00:1D:C1:2A:42:11", "Audinate Pty L", "10.113.0.32", True, ts),
        _proav_follower("00:0F:D4:FF:FE:08:1A:90", "00:0F:D4:08:1A:90", "Soundcraft", "10.113.0.35", True, ts),
        _proav_follower("00:50:C2:FF:FE:AB:03:71", "00:50:C2:AB:03:71", "Attero Tech", "10.113.0.37", False, ts),
    ]
    domain = {
        "version": 2, "domain": 0, "label": "domain 0", "master": master, "masters": [master],
        "senders": [{"identity": PROAV_BC_ID, "mac": PROAV_BC_MAC, "vendor": "Ubiquiti Inc", "ip": "10.113.0.2",
                     "role": "boundary", "count": 259, "first_ts": ts - 30, "last_ts": ts}],
        "followers": followers, "messages": 659, "announce_s": 2.0, "sync_s": 0.125,
        "sync_jitter_ms": 0.41, "correction_ns": 738.2, "transparent": True, "changes": 0,
        "first_ts": ts - 30, "last_ts": ts,
    }
    return {"heard": True, "messages": 659, "dropped": 0, "versions": [2], "domains": [domain], "best": domain,
            "transparent": True, "first_ts": ts - 30, "last_ts": ts}


def _proav_stream(name: str, group: str, port: int, origin: str, channels: int, refclk: str, ts: float,
                  info: Optional[str] = None, ptime: float = 1.0, deleted: bool = False) -> Dict[str, Any]:
    packet_bytes = int(48000 * (ptime / 1000.0)) * channels * 3
    bitrate = round((1000.0 / ptime) * (packet_bytes + 78) * 8 / 1_000_000.0, 3)
    return {"id": f"{group}:{port}", "name": name, "info": info, "group": group, "port": port,
            "source": origin, "origin": origin, "family": "aes67", "codec": "L24", "rate": 48000,
            "channels": channels, "depth": 24, "ptime_ms": ptime, "packet_bytes": packet_bytes,
            "bitrate_mbps": bitrate, "refclk": refclk, "refclk_domain": 0, "refclk_kind": "IEEE1588-2008",
            "mediaclk": "direct=0", "direction": "sendonly", "scope": 32, "count": 3,
            "first_ts": ts - 28, "last_ts": ts, "deleted": deleted}


def proav_streams(ts: float) -> List[Dict[str, Any]]:
    return [
        _proav_stream("FOH Mix : Main LR", "239.69.4.12", 5004, "10.113.0.31", 2, PROAV_GM_ID, ts,
                      info="Front of house, main bus"),
        _proav_stream("Stage Box A : Inputs 1-16", "239.69.4.20", 5004, "10.113.0.35", 16, PROAV_GM_ID, ts),
        _proav_stream("Broadcast Feed 1-8", "239.69.4.31", 5004, "10.113.0.37", 8, PROAV_STALE_GM, ts,
                      info="Set up against a grandmaster that is no longer here"),
    ]


def _proav_service(service_type: str, label: str, instance: str, host: str, port: int,
                   txt: Dict[str, str]) -> Dict[str, Any]:
    return {"type": service_type, "label": label, "instance": instance, "host": host, "port": port, "txt": txt}


def _proav_device(ident: str, name: str, ip: Optional[str], mac: Optional[str], vendor: Optional[str],
                  kind: Optional[str], family: str, family_text: str, ts: float, *, model: Optional[str] = None,
                  firmware: Optional[str] = None, hostname: Optional[str] = None,
                  services: Optional[List[Dict[str, Any]]] = None, roles: Optional[List[str]] = None,
                  clock_role: Optional[str] = None, clock_identity: Optional[str] = None,
                  streams_out: int = 0, sources: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"id": ident, "name": name, "ip": ip, "ips": [ip] if ip else [], "mac": mac, "vendor": vendor,
            "vendor_kind": kind, "family": family, "family_text": family_text, "model": model,
            "firmware": firmware, "hostname": hostname, "services": services or [], "roles": roles or [],
            "clock_role": clock_role, "clock_identity": clock_identity, "streams_out": streams_out,
            "sources": sources or ["mdns"], "first_ts": ts - 29, "last_ts": ts}


def proav_devices(ts: float) -> List[Dict[str, Any]]:
    dante = lambda n: _proav_service("_netaudio-arc._udp.local", "Dante control", n, n.lower().replace(" ", "-") + ".local", 8000,
                                     {"mf": "Audinate", "arcp_vers": "2.9.0"})
    return [
        _proav_device("mac:00:1D:C1:2A:41:08", "Clock Master", None, PROAV_GM_MAC, "Audinate Pty L", "av",
                      "dante", "Dante", ts, model="PTP-GM", roles=["PTP grandmaster"], clock_role="grandmaster",
                      clock_identity=PROAV_GM_ID, sources=["ptp"]),
        _proav_device("mac:00:1D:C1:2A:41:5C", "FOH Console", "10.113.0.31", "00:1D:C1:2A:41:5C",
                      "Audinate Pty L", "av", "dante", "Dante", ts, model="DEV-64", firmware="4.2.1.3",
                      hostname="foh-console.local", services=[dante("FOH Console")],
                      roles=["Dante control", "PTP follower", "Stream source"], clock_role="follower",
                      clock_identity="00:1D:C1:FF:FE:2A:41:5C", streams_out=1, sources=["mdns", "ptp", "sap"]),
        _proav_device("mac:00:1D:C1:2A:42:11", "Amp Rack 1", "10.113.0.32", "00:1D:C1:2A:42:11",
                      "Audinate Pty L", "av", "dante", "Dante", ts, model="DEV-8", firmware="4.2.1.3",
                      hostname="amp-rack-1.local", services=[dante("Amp Rack 1")],
                      roles=["Dante control", "PTP follower"], clock_role="follower",
                      clock_identity="00:1D:C1:FF:FE:2A:42:11", sources=["mdns", "ptp"]),
        _proav_device("mac:00:0F:D4:08:1A:90", "Stage Box A", "10.113.0.35", "00:0F:D4:08:1A:90", "Soundcraft",
                      "av", "dante", "Dante", ts, model="SB-16", firmware="2.7.0", hostname="stage-box-a.local",
                      services=[dante("Stage Box A")], roles=["Dante control", "PTP follower", "Stream source"],
                      clock_role="follower", clock_identity="00:0F:D4:FF:FE:08:1A:90", streams_out=1,
                      sources=["mdns", "ptp", "sap"]),
        _proav_device("mac:00:50:C2:AB:03:71", "Broadcast Bridge", "10.113.0.37", "00:50:C2:AB:03:71",
                      "Attero Tech", "av", "aes67", "AES67", ts, model="unD6IO-BT", firmware="1.9.4",
                      hostname="bcast-bridge.local",
                      services=[_proav_service("_ravenna._tcp.local", "Ravenna", "Broadcast Bridge",
                                               "bcast-bridge.local", 9090, {"model": "unD6IO-BT"})],
                      roles=["Ravenna", "PTP follower", "Stream source"], clock_role="follower",
                      clock_identity="00:50:C2:FF:FE:AB:03:71", streams_out=1, sources=["mdns", "ptp", "sap"]),
        _proav_device("mac:74:AC:B9:31:0C:6E", "Ubiquiti Inc 31:0C:6E", "10.113.0.2", PROAV_BC_MAC,
                      "Ubiquiti Inc", "network", "other", "Other", ts, roles=["PTP boundary clock"],
                      clock_role="boundary", clock_identity=PROAV_BC_ID, sources=["ptp"]),
        _proav_device("mac:B0:7D:64:19:E2:04", "Show Control PC", "10.113.0.50", "B0:7D:64:19:E2:04",
                      "Intel Corporate", None, "other", "Other", ts, hostname="show-pc.local",
                      services=[_proav_service("_workstation._tcp.local", "Workstation", "Show Control PC",
                                               "show-pc.local", 9, {})]),
    ]


def _proav_finding(ident: str, level: str, title: str, detail: Optional[str], advice: Optional[str],
                   evidence: Any = None) -> Dict[str, Any]:
    return {"id": ident, "level": level, "title": title, "detail": detail, "advice": advice, "evidence": evidence}


def proav_findings() -> List[Dict[str, Any]]:
    """Worst first, as tnt.proav.build_findings sorts them."""
    return [
        _proav_finding(
            "stream.refclk", "bad", "1 stream(s) expect a grandmaster that is not the one on this network",
            "Each of these names a reference clock in its SDP that no announcement here matches. A receiver that "
            "trusts the SDP will not lock, or will lock to the wrong tree.",
            "Re-announce the streams from a device that is on the current grandmaster, or find out why the "
            "grandmaster changed after the streams were set up.",
            [{"name": "Broadcast Feed 1-8", "group": "239.69.4.31", "refclk": PROAV_STALE_GM,
              "expected": [PROAV_GM_ID, PROAV_GM_MAC]}]),
        _proav_finding(
            "clock.jitter", "warn", "Sync messages arrive unevenly",
            "Sync arrives every 0.125 s on average, varying by up to 0.41 ms.",
            "Worth watching. If it grows, look at QoS on the path: clock packets should be in the highest "
            "priority queue."),
        _proav_finding(
            "net.flood", "warn", "2 multicast group(s) are reaching this port unasked",
            "Traffic arrived for groups this PC never joined, 18.42 Mb/s in total, including 1 carrying media "
            "rates. Either IGMP snooping is off on this switch, or this port is being treated as a multicast "
            "router port.",
            "On an AV network this wastes the port's bandwidth and can swamp a slow device. Turn snooping on for "
            "this VLAN.",
            [{"group": "239.69.4.20", "port": 5004, "source": "10.113.0.35", "packets": 4013, "bytes": 4941999,
              "mbps": 18.31},
             {"group": "239.192.0.11", "port": 5004, "source": "10.113.0.37", "packets": 41, "bytes": 30012,
              "mbps": 0.11}]),
        _proav_finding(
            "clock.boundary", "info", "1 boundary clock(s) sit between this PC and the grandmaster",
            "The announcement arrived with stepsRemoved 1, re-served by Ubiquiti Inc. A switch acting as a PTP "
            "boundary clock terminates the domain and serves it again, which is what an AV switch's PTP support "
            "does.",
            "Nothing to do: this is what a boundary clock looks like from a follower. It is worth knowing because "
            "it means the switch, not the grandmaster, is what this PC is timing against."),
        _proav_finding(
            "clock.transparent", "info", "A transparent clock is in the path",
            "Sync messages arrive with a correction field of up to 738.2 ns, which only a switch that timestamps "
            "packets in transit can write.",
            "Nothing to do: this is a switch correcting for its own delay, which is what you want on an AV "
            "network. It is proof the switch's PTP support is doing something."),
        _proav_finding(
            "clock.followers", "info", "4 device(s) are following this clock",
            "3 of them are having their delay requests answered by the grandmaster, which is what a device that is "
            "really in the clock tree looks like. The other 1 were heard asking but no reply to them was seen.",
            None,
            [{"identity": "00:1D:C1:FF:FE:2A:41:5C", "vendor": "Audinate Pty L", "ip": "10.113.0.31", "asking": True},
             {"identity": "00:50:C2:FF:FE:AB:03:71", "vendor": "Attero Tech", "ip": "10.113.0.37", "asking": False}]),
        _proav_finding(
            "device.mixed", "info", "2 AV ecosystems share this network",
            "Dante (4), AES67 (1). That is common and usually fine, but they only pass audio to each other through "
            "a gateway or through AES67.", None),
        _proav_finding(
            "net.switch", "info", "This PC is on core-av-sw-01",
            "UniFi Enterprise Audio/Video XG 24 PoE, port Port 14, untagged VLAN 120, 1000BASE-T full, 7.4 W of "
            "PoE allocated", None,
            {"switch_name": "core-av-sw-01", "port_id": "Port 14", "vlan": 120}),
        _proav_finding(
            "device.found", "good", "6 AV device(s) found",
            "Dante x4, AES67 x1. 7 device(s) answered in total.", None),
        _proav_finding(
            "clock.locked", "good", "The grandmaster is locked to GPS",
            "Audinate Pty L (00:1D:C1:2A:41:08) - clock class 6 (locked to a primary reference (GPS or "
            "equivalent)), accuracy 100 ns.", None),
        _proav_finding(
            "stream.found", "good", "3 stream(s) are being announced",
            "Together they are 31.82 Mb/s on the wire, 3.2 % of this 1000 Mb/s link. Channel counts, sample rates "
            "and packet times are in the table.", None,
            [{"name": "FOH Mix : Main LR", "group": "239.69.4.12", "port": 5004, "bitrate_mbps": 2.928},
             {"name": "Stage Box A : Inputs 1-16", "group": "239.69.4.20", "port": 5004, "bitrate_mbps": 19.056}]),
        _proav_finding(
            "net.querier", "good", "An IGMP querier is on this VLAN",
            "General queries arrive from 10.113.0.1 every 125.0 s. That is what keeps IGMP snooping tables alive, "
            "and what multicast audio needs.", None),
        _proav_finding(
            "net.dscp", "good", "AV traffic arrives correctly marked",
            "Clock packets arrive with DSCP 56, audio with DSCP 46.", None),
    ]


def _proav_node(ident: str, kind: str, label: str, sub: Optional[str] = None, family: Optional[str] = None,
                level: Optional[str] = None, detail: Optional[str] = None) -> Dict[str, Any]:
    return {"id": ident, "kind": kind, "label": label, "sub": sub, "family": family, "level": level,
            "detail": detail}


def _proav_edge(source: str, target: str, kind: str, label: Optional[str] = None) -> Dict[str, Any]:
    return {"source": source, "target": target, "kind": kind, "label": label}


def proav_graph() -> Dict[str, Any]:
    """The two graphs the page draws (tnt.proav.build_graph): the clock tree, and the stream flow map."""
    clock_nodes = [
        _proav_node("d0:gm", "grandmaster", "Clock Master", "Grandmaster - GPS", "dante", "good",
                    "PTPv2 domain 0, clock class 6, priority1 128"),
        _proav_node("d0:bc", "boundary", "Ubiquiti Inc 31:0C:6E", "10.113.0.2", None, None,
                    "This switch terminated the domain and served it again; it is what this PC times against."),
        _proav_node("d0:tc", "transparent", "Transparent clock", "correction up to 738.2 ns", None, None,
                    "A switch timestamped these packets in transit."),
        _proav_node("d0:f:1", "follower", "FOH Console", "10.113.0.31", "dante", None,
                    "Its delay requests are being answered"),
        _proav_node("d0:f:2", "follower", "Amp Rack 1", "10.113.0.32", "dante", None,
                    "Its delay requests are being answered"),
        _proav_node("d0:f:3", "follower", "Stage Box A", "10.113.0.35", "dante", None,
                    "Its delay requests are being answered"),
        _proav_node("d0:f:4", "follower", "Broadcast Bridge", "10.113.0.37", "aes67", "warn",
                    "Heard asking, but no reply to it was seen"),
        _proav_node("d0:self", "self", "Ethernet", "Listening here"),
    ]
    clock_edges = [_proav_edge("d0:gm", "d0:bc", "clock", "1 step(s)"), _proav_edge("d0:bc", "d0:tc", "clock")]
    clock_edges += [_proav_edge("d0:tc", n, "clock") for n in ("d0:f:1", "d0:f:2", "d0:f:3", "d0:f:4", "d0:self")]
    flow_nodes = [
        _proav_node("t:10.113.0.31", "talker", "FOH Console", "10.113.0.31", "dante", None, "Audinate Pty L"),
        _proav_node("s:239.69.4.12:5004", "stream", "FOH Mix : Main LR", "239.69.4.12:5004", "aes67", None,
                    "L24, 48 kHz, 2 ch, 1.0 ms, 2.928 Mb/s"),
        _proav_node("t:10.113.0.35", "talker", "Stage Box A", "10.113.0.35", "dante", None, "Soundcraft"),
        _proav_node("s:239.69.4.20:5004", "stream", "Stage Box A : Inputs 1-16", "239.69.4.20:5004", "aes67", None,
                    "L24, 48 kHz, 16 ch, 1.0 ms, 19.056 Mb/s"),
        _proav_node("t:10.113.0.37", "talker", "Broadcast Bridge", "10.113.0.37", "aes67", None, "Attero Tech"),
        _proav_node("s:239.69.4.31:5004", "stream", "Broadcast Feed 1-8", "239.69.4.31:5004", "aes67", None,
                    "L24, 48 kHz, 8 ch, 1.0 ms, 9.84 Mb/s"),
        _proav_node("l:10.113.0.32", "listener", "Amp Rack 1", "10.113.0.32", "dante", None,
                    "Heard joining this group"),
        _proav_node("l:10.113.0.37", "listener", "Broadcast Bridge", "10.113.0.37", "aes67", None,
                    "Heard joining this group"),
    ]
    flow_edges = [
        _proav_edge("t:10.113.0.31", "s:239.69.4.12:5004", "flow", "2.93 Mb/s"),
        _proav_edge("t:10.113.0.35", "s:239.69.4.20:5004", "flow", "19.06 Mb/s"),
        _proav_edge("t:10.113.0.37", "s:239.69.4.31:5004", "flow", "9.84 Mb/s"),
        _proav_edge("s:239.69.4.12:5004", "l:10.113.0.32", "flow"),
        _proav_edge("s:239.69.4.12:5004", "l:10.113.0.37", "flow"),
        _proav_edge("s:239.69.4.20:5004", "l:10.113.0.32", "flow"),
    ]
    return {
        "clock": {"nodes": clock_nodes, "edges": clock_edges,
                  "note": "The clock tree is measured, not guessed: every line is something this PC heard. A switch "
                          "appears only when it announced itself as a boundary clock."},
        "flow": {"nodes": flow_nodes, "edges": flow_edges,
                 "note": "Talkers and streams come from the SAP announcements. Which devices are listening cannot "
                         "be seen from one port without reading the switch's IGMP snooping table, so receivers are "
                         "only shown where one was heard joining the group."},
    }


def proav_l2(ts: float) -> Dict[str, Any]:
    """The Layer 2 listen's result (tnt.proav.L2_KEYS)."""
    return {
        "ok": True, "reason": None, "frames": 48213, "lost": 0, "igmp_seen": 37,
        "querier": {"ip": "10.113.0.1", "interval_s": 125.0, "queries": 2},
        "memberships": [{"ip": "10.113.0.32", "group": "239.69.4.12", "reports": 2, "last_ts": ts},
                        {"ip": "10.113.0.32", "group": "239.69.4.20", "reports": 2, "last_ts": ts},
                        {"ip": "10.113.0.37", "group": "239.69.4.12", "reports": 1, "last_ts": ts}],
        "flooded": [{"group": "239.69.4.20", "port": 5004, "source": "10.113.0.35", "packets": 4013,
                     "bytes": 4941999, "mbps": 18.31, "first_ts": ts - 28, "last_ts": ts},
                    {"group": "239.192.0.11", "port": 5004, "source": "10.113.0.37", "packets": 41,
                     "bytes": 30012, "mbps": 0.11, "first_ts": ts - 27, "last_ts": ts}],
        "dscp": {"ptp": 56, "audio": 46},
    }


def proav_switch() -> Dict[str, Any]:
    """The LLDP neighbour of the switch-port lookup (tnt.lldp.NEIGHBOR_KEYS).  A fact about this port, not about
    the Layer 2 listen, so a scan reports it either way."""
    return {"protocol": "LLDP", "switch_name": "core-av-sw-01",
            "switch_description": "UniFi Enterprise Audio/Video XG 24 PoE", "vendor": "Ubiquiti Inc",
            "chassis_id": PROAV_BC_MAC, "port_id": "Port 14", "port_description": "FOH rack",
            "vlan": 120, "voice_vlan": None, "management_ips": ["10.113.0.2"],
            "capabilities": ["bridge", "router"], "poe": {"class": 3, "allocated_w": 7.4},
            "link": {"autoneg": True, "mau": 30, "text": "1000BASE-T full"}, "ttl_s": 120}


def proav_result(ts: float, seconds: int, adapter: Dict[str, Any], deep: bool,
                 cancelled: bool = False) -> Dict[str, Any]:
    """A whole scan result (tnt.proav.RESULT_KEYS)."""
    clock = proav_clock(ts)
    streams = proav_streams(ts)
    devices = proav_devices(ts)
    # only the Layer 2 checks depend on `deep`; the switch note is LLDP and is reported either way
    l2_only = ("net.querier", "net.flood", "net.dscp", "net.lost")
    findings = [f for f in proav_findings() if deep or f["id"] not in l2_only]
    if not deep:
        findings.append(_proav_finding(
            "net.l2", "info", "Multicast hygiene was not checked",
            "The Layer 2 listen was not run, so this scan cannot say whether there is an IGMP querier, whether "
            "groups are being flooded to this port, or how the traffic is marked.",
            "Run the scan with the Layer 2 listen turned on (it needs Windows administrator rights) to add those "
            "three checks."))
    return {
        "ts": ts, "seconds": seconds, "adapter": dict(adapter), "link_mbps": adapter.get("speed_mbps"),
        "counts": {"mdns": 214, "sap": 3, "ptp": 659, "frames": 48213 if deep else 0,
                   "devices": len(devices), "streams": len(streams)},
        "listeners": proav_listeners(), "clock": clock, "streams": streams,
        "services": [dict(s, ips=[d["ip"]] if d["ip"] else [], ts=ts)
                     for d in devices for s in d["services"]],
        "devices": devices, "findings": findings, "graph": proav_graph(),
        "l2": proav_l2(ts) if deep else None, "switch": proav_switch(), "cancelled": cancelled,
    }


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
        self.wifi_admin = True              # tests: set False to simulate a non-admin caller (403 on reveal=1 and on IP Release/Renew)
        # Tools: DNS lookup, Flush DNS and IP Release/Renew (tnt.nettools); tests shorten the waits
        self.dns_delay_s = 0.15
        self.dns_flush_s = 0.3
        self.ip_renew_s = 1.5
        self.ip_renew_running = False
        # Network info: the NAT check, the switch port finder and the port-forward test; tests shorten the waits and zero the limits
        self.nat_delay_s = 0.0                               # a POST answers at once; more keeps it running (GET running, 409)
        self.nat_running = False
        self.nat_last: Optional[Dict[str, Any]] = None
        self.nat_epoch = 0                                   # bumps on every network change: a check across one is not kept
        self.switch_listen_s = 2.0                           # how long a listen lasts before it hears the switch
        self.switch_found = True                             # False: a listen hears no LLDP or CDP
        self.switch_job: Optional[Dict[str, Any]] = None     # the latest search
        self.switch_kept: Dict[str, Dict[str, Any]] = {}     # adapter MAC -> its last finished search
        self.switch_gen = 0                                  # bumps on every start and cancel so a stale worker exits
        self.pktmon_reason: Optional[str] = None             # a PKTMON_REASONS text: Packet Monitor unavailable to both tools
        self.portcheck_delay_s = 1.5
        self.portcheck_min_gap_s = PORTCHECK_MIN_GAP_S
        self.portcheck_per_hour = PORTCHECK_PER_HOUR
        self.portcheck_running = False
        self.portcheck_starts: List[float] = []              # monotonic starts of the tests admitted in the last hour
        self.portcheck_last_start: Optional[float] = None
        self.portcheck_last: Optional[Dict[str, Any]] = None
        # Tools: the TFTP server (off after every start of the service, uploads too) and packet capture
        self.tftp_running = False
        self.tftp_since: Optional[float] = None
        self.tftp_error: Optional[str] = None
        self.tftp_uploads = False
        self.tftp_adapter: Optional[Dict[str, Any]] = None   # the TFTP_ADAPTER_KEYS row it serves on
        self.tftp_listen: List[Dict[str, Any]] = []
        self.tftp_conflict: Optional[Dict[str, Any]] = None
        self.tftp_port_owners: List[Dict[str, Any]] = []     # tests: [{"pid", "name"}] of another program on UDP 69 (409 at start)
        self.tftp_transfers: List[Dict[str, Any]] = []
        self.tftp_history: List[Dict[str, Any]] = []         # newest first
        self.tftp_counts = {k: 0 for k in TFTP_COUNT_KEYS if k != "active"}
        self.tftp_next_id = 1
        self.tftp_gen = 0                                    # bumps on every start and stop so a stale transfer exits
        self.tftp_fast = False                               # tests: the phone asks within a few ms
        # Pro AV: the running listen and the last result (tnt.proav.ProAvScanner)
        self.proav_reason: Optional[str] = None              # tests: a text makes Pro AV scanning unavailable here
        self.proav_job: Dict[str, Any] = self.proav_idle_job()
        self.proav_result: Optional[Dict[str, Any]] = None
        self.proav_last_run_ts: Optional[float] = None
        self.proav_gen = 0                                   # bumps on every start so a stale worker exits
        self.proav_stop_evt = threading.Event()              # Stop: end the listen and keep what it heard
        # Packet capture: the open session, its packet list and the SIP calls found in it (tnt.capture.CaptureManager)
        self.capture_s: Optional[float] = None               # tests: how long a capture runs (None: its max_seconds)
        self.capture_reason: Optional[str] = None            # tests: a text makes capturing unavailable here
        self.capture_session: Optional[Dict[str, Any]] = None
        self.capture_next_id = 1
        self.capture_gen = 0                                 # bumps on every start, open and discard so a stale worker exits
        self.capture_stop_evt = threading.Event()            # stop the running capture and keep what it caught
        self.capture_rows: List[Dict[str, Any]] = []         # the packet list (ROW dicts), at most CAPTURE_MAX_ROWS
        self.capture_meta: List[Dict[str, Any]] = []         # each row's layers, detail fields and payload, in lockstep
        self.capture_first_no = 1                            # the "no" of capture_rows[0]
        self.capture_total = 0                               # every packet of this capture, held or not
        self.capture_truncated = False
        self.capture_dropped = 0
        self.capture_bytes = 0
        self.capture_first_ts: Optional[float] = None
        self.capture_started_mono = 0.0
        self.capture_calls_found: List[Dict[str, Any]] = []   # the SIP calls of the open capture, newest first
        seed_ts = time.mktime((2026, 1, 1, 12, 0, 0, 0, 0, -1))
        self.capture_files: List[Dict[str, Any]] = [{"name": CAPTURE_SEED_FILE, "size": CAPTURE_SEED_BYTES,
                                                     "created_ts": seed_ts, "packets": CAPTURE_SEED_PACKETS}]
        # IP location (tnt.geoip): the fake manager's state (POST /mock/geoip), the text it shows in "error" and its data month
        self.geoip_state = "ready"
        self.geoip_error = "HTTP 503 from download.db-ip.com"
        self.geoip_month = time.strftime("%Y-%m", time.gmtime())
        # auto-update (tnt.updater): the fake manager's state (POST /mock/update {"state"}) and its error text
        self.update_state = "available"
        self.update_error = "HTTP 403 from api.github.com: the rate limit may be reached"
        self.public_ip_ts = time.time() - 4 * 60
        # SIP (tnt.sipqual, tnt.sipalg, tnt.sipnat, tnt.sipflow): what the fake network does to SIP and to a NAT
        # mapping (POST /mock/sip picks another), the last result of each check and the capture slots that are loaded
        self.sip_alg_state = "alg"
        self.sip_nat_state = "address-dependent"
        self.sip_alg_last: Optional[Dict[str, Any]] = None
        self.sip_stun_last: Optional[Dict[str, Any]] = None
        self.sip_flow_slots: set = set()
        # the network this fake PC is on (NET_PROFILE_NAMES) and the change counter status.net reports
        self.net_profile = "a"
        # the passive fault watch: when it started, and the level it last published
        self.faults_since = time.time()
        self.faults_level = "info"
        # what the fake watch "could not read" (tnt.faults' note, the tile's reason): None, or a
        # string such as "ARP table: OSError" for a page that has to show a partly blind watch
        self.faults_reason: Optional[str] = None
        # realtime throughput (Network info): cumulative counters per adapter index, and the samples
        self.tp_totals: Dict[int, Dict[str, int]] = {}
        self.tp_samples: Dict[int, List[List[int]]] = {}
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
        # Settings › History (tnt.history): the cleared spans (meta history_cleared), the ping minutes each clear took (the fake
        # minutes are made up on every read, so a read leaves out what a clear removed), the one clear at a time, and the jobs
        # a clear stops
        self.history_spans: List[Dict[str, Any]] = []
        self.history_clearing = False
        self.history_clear_delay_s = 0.0                     # tests: hold a clear open this long (409 clear_running meanwhile)
        self.speed_gen = 0                                   # bumps on every test and every clear that stops one
        self.disc_discard = False                            # the running scan was stopped by a clear: nothing of it is kept
        self.sip_flow_loaded: Dict[str, float] = {}          # slot -> when its capture was loaded
        self.sip_flow_files: Dict[str, str] = {}             # slot -> the file name it holds (a clear closes a deleted one)
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
        t = {"id": tid, "host": host, "label": label, "name": None, "kind": kind, "ip": ip, "enabled": True,
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
                    "error": "HTTP 503 from speed.cloudflare.com", "quality": None}
        down = 118 * f * (1 + rng.gauss(0, 0.05))
        up = 31 * (0.9 if evening else 1.0) * (1 + rng.gauss(0, 0.05))
        lat = 12 + (7 if evening else 0) + rng.gauss(0, 1.4)
        row = {"id": len(self.speedtests) + 1, "ts": ts, "ok": True, "backend": "cloudflare",
               "server": "Cloudflare AMS", "isp": "Example ISP", "external_ip": "203.0.113.5",
               "latency_ms": round(max(3, lat), 1), "jitter_ms": round(1 + abs(rng.gauss(0, 0.8)), 2),
               "download_mbps": round(max(1, down), 1), "upload_mbps": round(max(1, up), 1),
               "packet_loss_pct": 0.0, "duration_s": round(16 + rng.random() * 3, 1), "error": None}
        row["quality"] = self._speed_quality(row["latency_ms"], row["jitter_ms"], evening)
        return row

    @staticmethod
    def _speed_quality(lat: float, jitter: float, evening: bool) -> Dict[str, Any]:
        """The latency-under-load result of a test (no draws of the shared random generator): idle at the test's latency,
        loaded 9 / 21 ms higher (grade A), in the evening 24 / 47 ms higher with an echo lost each way (grade B)."""
        def window(sent: int, received: int, mean: float, spread: float) -> Dict[str, Any]:
            return {"sent": sent, "received": received, "skipped": 0, "loss_pct": round(100.0 * (sent - received) / sent, 1),
                    "median_ms": round(mean - 0.4, 1), "mean_ms": round(mean, 1), "p95_ms": round(mean + 2 * spread, 1),
                    "max_ms": round(mean + 3 * spread, 1), "jitter_ms": round(spread, 1)}

        baseline = dict(window(30, 30, lat + 0.4, jitter), median_ms=lat)
        down, up = (24.0, 47.0) if evening else (9.0, 21.0)
        lost = 1 if evening else 0
        return speed_quality(baseline, window(44, 44 - lost, lat + down, jitter * 1.8), window(38, 38 - lost, lat + up, jitter * 2.4))

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
        # a plausible 24 h summary derived from the base RTT, less whatever Clear history removed of the day (the
        # service re-reads its day summary from the rows left): nothing left reads like a target that never answered
        now = time.time()
        span = min(86400.0, now - self.started_ts)
        frac = self._recorded_fraction_locked(now - span, now) if self.history_spans else 1.0
        sent = int(span * frac)
        lost = int(sent * (0.0002 if t["kind"] == "local" else 0.004)) + (int(258 * frac) if t["id"] == 2 else 0)
        lost = min(lost, sent)
        if sent:
            day = {"sent": sent, "received": sent - lost, "lost": lost, "loss_pct": round(100.0 * lost / sent, 2),
                   "avg_ms": round(t["base"] * 1.03, 2), "min_ms": round(t["base"] * 0.7, 2),
                   "max_ms": round(t["base"] * 9.1 + 40, 2)}
        else:
            day = {"sent": 0, "received": 0, "lost": 0, "loss_pct": None, "avg_ms": None, "min_ms": None, "max_ms": None}
        return {"id": t["id"], "host": t["host"], "label": t["label"], "name": t.get("name"), "kind": t["kind"], "ip": t["ip"],
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

    def set_target_name(self, tid: int, name: Optional[str]) -> Optional[Dict[str, Any]]:
        """PATCH /api/targets/{id}: set or clear a target's custom name; None when it does not exist."""
        clean = (str(name).strip()[:80] if name is not None else "") or None
        with self.lock:
            t = next((x for x in self.targets if x["id"] == tid), None)
            if t is None:
                return None
            t["name"] = clean
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
                if self._ping_minute_cleared(m):
                    m += 60
                    continue
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
                    "gaps": gaps, "cleared": self._cleared_spans_locked(start, now),
                    "targets": [{"id": t["id"], "host": t["host"], "kind": t["kind"]} for t in self.targets]}

    # -- Settings › History: clear what was recorded in a time range (tnt.history, Engine.clear_history) -------------
    def _cleared_spans_locked(self, start: float, end: float) -> List[Dict[str, float]]:
        """The timeline's ``cleared``: every recorded clear as [since_ts, at], clipped to [start, end] (since_ts None: from the
        range start); a span wholly outside the range is left out."""
        out = []
        for span in self.history_spans:
            lo = start if span["since_ts"] is None else max(start, float(span["since_ts"]))
            hi = min(end, float(span["at"]))
            if hi > lo:
                out.append({"start_ts": lo, "end_ts": hi})
        return out

    def _recorded_fraction_locked(self, start: float, end: float) -> float:
        """How much of [start, end] no clear has removed, 0..1: the invented day summaries and SIP legs shrink with it,
        as the service's (re-read from what is left) do - after All time a Ping tile or SIP leg has nothing behind it."""
        if end <= start:
            return 1.0
        cut: List[Tuple[float, float]] = []
        for span in self.history_spans:
            lo = start if span["since_ts"] is None else max(start, float(span["since_ts"]))
            hi = min(end, float(span["at"]))
            if hi > lo:
                cut.append((lo, hi))
        gone, reach = 0.0, start
        for lo, hi in sorted(cut):
            lo = max(lo, reach)
            if hi > lo:
                gone += hi - lo
                reach = hi
        return max(0.0, 1.0 - gone / (end - start))

    def _ping_minute_cleared(self, minute_ts: float) -> bool:
        """Whether a clear removed the ping minute starting at ``minute_ts``: the service deletes minute rows with
        minute_ts > since - 60 (the minute the window starts in goes whole) up to the moment of the clear."""
        for span in self.history_spans:
            if minute_ts <= span["at"] and (span["since_ts"] is None or minute_ts > span["since_ts"] - 60):
                return True
        return False

    def history_info(self) -> Dict[str, Any]:
        """GET /api/history: the eight ranges for the select and the newest clear for Settings' status line."""
        with self.lock:
            return {"ranges": [{"key": k, "label": HISTORY_RANGE_LABELS[k]} for k in HISTORY_RANGES],
                    "last": dict(self.history_spans[-1]) if self.history_spans else None}

    def history_clear(self, range_key: Any, captures_allowed: bool = True) -> Dict[str, Any]:
        """POST /api/history/clear: remove what was recorded in [since_ts, now] by the service's rules (the overlap rule:
        anything recorded in or overlapping the window goes, whole) and publish ``history.cleared`` with the answer. 400
        bad_range, 409 full_scan_running while a Full Scan runs, 409 clear_running while another clear runs. Saved reports,
        their networks and every file outside the capture list are never touched."""
        if not isinstance(range_key, str) or range_key not in HISTORY_RANGES:
            raise ToolRefused(400, "bad_range", HISTORY_BAD_RANGE_MSG)
        with self.lock:
            if self.report_job and self.report_job.get("status") == "running":
                raise ToolRefused(409, "full_scan_running", HISTORY_FULL_SCAN_MSG)
            if self.history_clearing:
                raise ToolRefused(409, "clear_running", HISTORY_CLEAR_RUNNING_MSG)
            self.history_clearing = True
            delay = self.history_clear_delay_s
        try:
            if delay > 0:
                time.sleep(delay)
            return self._history_clear(range_key, captures_allowed)
        finally:
            with self.lock:
                self.history_clearing = False

    def _history_clear(self, range_key: str, captures_allowed: bool) -> Dict[str, Any]:
        now = time.time()
        seconds = HISTORY_RANGES[range_key]
        since = None if seconds is None else now - seconds
        lo = float("-inf") if since is None else since
        cleared = {k: 0 for k in HISTORY_CLEARED_KEYS}
        stopped: List[str] = []
        skipped: List[Dict[str, str]] = []
        publish: List[Tuple[str, Dict[str, Any]]] = []
        discard_capture = False
        with self.lock:
            # 1. running jobs: a speed test, a discovery scan and a Pro AV scan stop and keep nothing
            if self.speed_running:
                self.speed_gen += 1
                self.speed_running = False
                self.speed_progress = {"phase": "idle", "pct": 0.0}
                stopped.append("speed test")
                # the service's shape (tnt/speedtest/scheduler.py): the run ends "cancelled" and the event itself carries
                # silent + cancel_reason, so no page shows "Speed test failed" for it
                publish.append(("speedtest.done", {"result": {"ok": False, "ts": now, "error": "cancelled"}, "trigger": "manual",
                                                   "silent": True, "cancel_reason": HISTORY_CANCEL_REASON}))
            if self.disc_running:
                self.disc_discard = True
                self.disc_cancel.set()
                stopped.append("discovery scan")
            if self.proav_job.get("state") == "scanning":
                self.proav_gen += 1
                self.proav_stop_evt.set()
                self.proav_job = self.proav_idle_job()
                stopped.append("Pro AV scan")
            # 2. ping: the minutes (counted as the service counts its rows) and the live samples
            first = max(now - HISTORY_PING_HORIZON_S, lo - 60)
            m = int(first // 60 * 60)
            minutes = 0
            while m <= now:
                if m > lo - 60 and not self._ping_minute_cleared(m):
                    minutes += 1
                m += 60
            cleared["ping"] = minutes * len(self.targets)
            for tid in list(self.samples):
                self.samples[tid] = [x for x in self.samples[tid] if x[0] < lo]
            # 3. outages (every kind, gap included): open ones, and closed ones that end in the window; their events too
            keep = [o for o in self.outages if o["end_ts"] is not None and o["end_ts"] < lo]
            cleared["outages"] = len(self.outages) - len(keep)
            self.outages = keep
            # an open outage always goes, so no target is in one any more and its run of misses starts again (the
            # service's OutageTracker reset and set_in_outage(tid, False)); one still down opens a new outage later
            for t in self.targets:
                if t["in_outage"]:
                    t["in_outage"] = False
                    t["consecutive_missed"] = 0
            self.events_db = [e for e in self.events_db if not (e.get("category") == "outage" and e.get("ts", 0) >= lo)]
            # 4. speed tests and discovery scans recorded in the window
            n = len(self.speedtests)
            self.speedtests = [r for r in self.speedtests if r["ts"] < lo]
            cleared["speed"] = n - len(self.speedtests)
            n = len(self.disc_runs)
            self.disc_runs = [r for r in self.disc_runs if r["ts"] < lo]
            cleared["discovery"] = n - len(self.disc_runs)
            # 5. packet captures: the listed files only, and only for an administrator; a recording capture stays
            session = self.capture_session
            names: set = set()                       # the capture files this clear deletes (a SIP slot holding one closes)
            if not captures_allowed:
                skipped.append({"what": "captures", "reason": HISTORY_CAPTURES_ADMIN_MSG})
            else:
                names = {f["name"] for f in self.capture_files if f["created_ts"] >= lo}
                self.capture_files = [f for f in self.capture_files if f["name"] not in names]
                cleared["captures"] = len(names)
                if session is not None:
                    if session["state"] == "capturing":
                        skipped.append({"what": "captures", "reason": HISTORY_CAPTURE_RECORDING_MSG})
                    elif session["source"] == "file" and session.get("file") in names:
                        discard_capture = True           # the file open in the packet list was one of them
                    elif session["source"] == "live" and not session["saved"] and session["started_ts"] >= lo:
                        discard_capture = True           # a stopped capture never saved, started in the window
            # 6. faults: the counters are cumulative, so any range restarts the whole watch from now
            self.faults_since = now
            cleared["faults"] = 1
            # 7. SIP: the ALG and STUN results of the window, the call-flow slots loaded in it and any slot whose file was a
            #    capture this clear deleted (never the slot files themselves)
            if self.sip_alg_last is not None and self.sip_alg_last.get("ts", 0) >= lo:
                self.sip_alg_last = None
                cleared["sip"] += 1
            if self.sip_stun_last is not None and self.sip_stun_last.get("ts", 0) >= lo:
                self.sip_stun_last = None
                cleared["sip"] += 1
            for slot in sorted(self.sip_flow_slots):
                if self.sip_flow_loaded.get(slot, now) >= lo or self.sip_flow_files.get(slot) in names:
                    self.sip_flow_slots.discard(slot)
                    self.sip_flow_loaded.pop(slot, None)
                    self.sip_flow_files.pop(slot, None)
                    cleared["sip"] += 1
            # 8. Pro AV: the last result when it was recorded in the window
            if self.proav_result is not None and (self.proav_last_run_ts or now) >= lo:
                self.proav_result = None
                self.proav_last_run_ts = None
                cleared["proav"] = 1
            # 9. the cleared span, for the timeline and Settings' status line; "all" replaces the list
            entry = {"since_ts": since, "at": now, "range": range_key}
            if since is None:
                self.history_spans = [entry]
            else:
                spans = [x for x in self.history_spans if x["at"] >= now - HISTORY_SPAN_MAX_AGE_S] + [entry]
                self.history_spans = spans[-HISTORY_SPANS_KEEP:]
            result = {"range": range_key, "label": HISTORY_RANGE_LABELS[range_key], "since_ts": since, "ts": now,
                      "cleared": cleared, "stopped": stopped, "skipped": skipped}
            job = self.proav_job_locked()
            targets = [self.target_view(x) for x in self.targets]
        if discard_capture:
            self.capture_discard()
        elif cleared["captures"]:
            with self.lock:
                snap = self._capture_session_locked()
            self.hub.publish("capture.state", {"session": snap})
        for kind, data in publish:
            self.hub.publish(kind, data)
        if "Pro AV scan" in stopped or cleared["proav"]:
            self.hub.publish("proav.state", {"job": job})
        self.hub.publish("faults.state", self.faults_tile())
        self.hub.publish("ping.targets", {"targets": targets})
        self.hub.publish("history.cleared", copy.deepcopy(result))
        return result

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
        """The tests in [start, end), newest first; like the service's list, a row has no ``quality``."""
        with self.lock:
            rows = [{k: v for k, v in r.items() if k != "quality"} for r in self.speedtests if start <= r["ts"] < end]
            rows.sort(key=lambda r: r["ts"], reverse=True)
            return rows[:limit] if limit else rows

    def speed_run(self) -> bool:
        with self.lock:
            if self.speed_running:
                return False
            self.speed_running = True
            self.speed_progress = {"phase": "baseline", "pct": 0.0}
            self.speed_gen += 1
            gen = self.speed_gen
        threading.Thread(target=self._speed_worker, args=(gen,), name="mock-speed", daemon=True).start()
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

    def _speed_worker(self, gen: int = 0) -> None:
        self.hub.publish("speedtest.start", {"backend": "cloudflare"})
        try:
            for phase, dur in SPEED_PHASES:
                t0 = time.time()
                while time.time() - t0 < dur:
                    pct = min(1.0, (time.time() - t0) / dur)
                    with self.lock:
                        if gen and self.speed_gen != gen:
                            return                      # Clear history stopped this test: no row, and it said so already
                        self.speed_progress = {"phase": phase, "pct": round(pct, 3)}
                    self.hub.publish("speedtest.progress", {"phase": phase, "pct": round(pct, 3)})
                    time.sleep(0.15)
            with self.lock:
                if gen and self.speed_gen != gen:
                    return
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
            ups = sorted(r["upload_mbps"] for r in ok if r["upload_mbps"] is not None)   # an unmeasured upload has no figure

            def median(xs: List[float]) -> Optional[float]:
                if not xs:
                    return None
                n = len(xs)
                return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2

            md, mu = median(downs), median(ups)
            by_hour = []
            for h in range(24):
                hs = [r for r in ok if local_hour(r["ts"]) == h]
                hu = [r["upload_mbps"] for r in hs if r["upload_mbps"] is not None]
                by_hour.append({"hour": h, "count": len(hs),
                                "avg_down": round(sum(r["download_mbps"] for r in hs) / len(hs), 1) if hs else None,
                                "avg_up": round(sum(hu) / len(hu), 1) if hu else None,
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
                if self.disc_discard:
                    # Clear history stopped this scan: nothing of it is kept, and the clear already said so
                    self.disc_discard = False
                    self.disc_running = False
                    self.disc_net_changed = False
                    self.disc_progress = {"phase": "done", "done": 0, "total": total, "found": 0,
                                          "elapsed_s": round(time.time() - t0, 1)}
                    discarded = True
                else:
                    discarded = False
            if discarded:
                self.hub.publish("discovery.progress", self.disc_progress)
                # the service's shape (tnt/engine.py): not stored, run_id None, silent + cancel_reason on the event
                self.hub.publish("discovery.done", {"run_id": None, "cancelled": True, "found": 0, "network_changed": False,
                                                    "silent": True, "cancel_reason": HISTORY_CANCEL_REASON})
                return
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

    # -- auto-update (tnt.updater) ---------------------------------------
    def _update_enabled(self) -> bool:
        with self.lock:
            return bool((self.settings.get("update") or {}).get("enabled", True))

    def _update_auto(self) -> bool:
        with self.lock:
            return bool((self.settings.get("update") or {}).get("auto_install", False))

    def update_status(self) -> Dict[str, Any]:
        """status.update / GET /api/update, shaped like tnt.updater.UpdateManager.status() (exactly
        UPDATE_STATUS_KEYS) for ``update_state``; the disabled shape as soon as the setting is off."""
        with self.lock:
            st: Dict[str, Any] = dict.fromkeys(UPDATE_STATUS_KEYS)
            st.update(current_version=VERSION, auto_install=self._update_auto())
            if not self._update_enabled():
                st.update(enabled=False, state="disabled")
                return st
            now = time.time()
            state = self.update_state
            # a stable next check (like the geoip mock) so two reads of the same state compare equal
            st.update(enabled=True, state=state, checked_ts=self.started_ts, next_check_ts=self.started_ts + 24 * 3600)
            setup = f"TNT-Setup-{UPDATE_LATEST_VERSION}.exe"
            offering = state in ("available", "downloading", "verifying", "ready", "installing")
            if offering:
                st.update(latest_version=UPDATE_LATEST_VERSION, latest_ts=self.started_ts - 2 * 3600,
                          notes_url=f"https://github.com/rhuntertec/TNT/releases/tag/v{UPDATE_LATEST_VERSION}",
                          asset={"name": setup, "bytes": UPDATE_SETUP_BYTES})
            if state == "downloading":
                st["download"] = {"received": int(UPDATE_SETUP_BYTES * 0.4), "total": UPDATE_SETUP_BYTES, "phase": "download"}
            elif state == "verifying":
                st["download"] = {"received": UPDATE_SETUP_BYTES, "total": UPDATE_SETUP_BYTES, "phase": "verify"}
            elif state == "error":
                st.update(error=self.update_error, next_check_ts=now + 60)
            return st

    def update_check(self) -> Dict[str, Any]:
        """POST /api/update/check: pretend to look and land on "available" (or stay disabled)."""
        with self.lock:
            if not self._update_enabled():
                return self.update_status()
            self.update_state = "available"
            status = self.update_status()
        self.hub.publish("update.state", status)
        return status

    def update_install(self) -> Dict[str, Any]:
        """POST /api/update/install: begin the (fake) download; the UI watches update.state for progress."""
        with self.lock:
            self.update_state = "downloading"
            status = self.update_status()
        self.hub.publish("update.state", status)
        return status

    def update_set_state(self, state: str) -> str:
        """POST /mock/update: move the fake manager to another UPDATE_STATES state (not "disabled": the setting)."""
        if state not in UPDATE_STATES[1:]:
            raise ValueError(f"unknown update state {state!r}; one of: {', '.join(UPDATE_STATES[1:])}")
        with self.lock:
            self.update_state = state
            status = self.update_status()
        self.hub.publish("update.state", status)
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

    # -- Tools: DNS lookup, Flush DNS, IP Release/Renew (tnt.nettools) ----
    def dns_lookup(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """POST /api/tools/dns/lookup like the service: the name and the server checked (ValueError, a 400, with its text), then
        after a short wait the DNS_RESULT from DNS_ZONE / DNS_PTR. The server asked is the one given (a name is found in the fake
        data first), else the first DNS server of this PC's internet adapter on the network it is on. ``type`` null or empty is
        Auto; another type reads the CNAME rows and the rows of that type, like tnt.nettools' typed lookup."""
        name, server, record_type = body.get("name"), body.get("server"), body.get("type")
        # the route's own checks first (tnt.api.routes.tools_dns_lookup), then tnt.nettools.validate_lookup's order
        if name is not None and not isinstance(name, str):
            raise ValueError("name must be text")
        if server is not None and not isinstance(server, str):
            raise ValueError("server must be text or null")
        if record_type is not None and not isinstance(record_type, str):
            raise ValueError(DNS_TYPE_NOT_TEXT_MSG)
        name = dns_query_name(name or "")
        server = dns_query_server(server)
        rtype = dns_query_type(record_type)
        if rtype not in (None, "PTR", "ALL") and dns_address(name) is not None:
            raise ValueError(DNS_IP_TYPE_MSG)
        t0 = time.time()
        out: Dict[str, Any] = {"name": name, "type": rtype, "server": server, "resolver": {"name": None, "address": None}, "answer_name": None,
                               "addresses": [], "aliases": [], "records": [], "authoritative": None, "ok": False, "error": None}

        def done(**fields: Any) -> Dict[str, Any]:
            out.update(fields)
            out["duration_ms"] = int(round((time.time() - t0) * 1000))
            out["ts"] = time.time()
            return out

        time.sleep(self.dns_delay_s)
        if server is None:
            with self.lock:
                nic = net_internet_nic(net_profile(self.net_profile))
            asked = nic["dns"][0] if nic and nic["dns"] else None
            if asked is None:
                return done(error=DNS_NO_SERVER_MSG)
            out["resolver"] = {"name": DNS_PTR.get(asked), "address": asked}
        elif dns_address(server) is not None:
            out["resolver"] = {"name": None, "address": server}
        else:
            found = [value for rtype, _, value, _ in DNS_ZONE.get(server.lower(), []) if rtype == "A"]
            if not found:
                return done(error=f'Could not find the DNS server "{server}"')
            out["resolver"] = {"name": server, "address": found[0]}
        if out["resolver"]["address"] == DNS_SILENT_SERVER:
            time.sleep(self.dns_delay_s)
            return done(error=DNS_TIMEOUT_MSG)
        addr = dns_address(name)
        if addr is not None:
            # an address is a reverse (PTR) lookup: the answer is its name, the address the one looked up
            plain = ipaddress.ip_address(str(addr).split("%", 1)[0])
            ptr = DNS_PTR.get(str(plain)) or "host-" + re.sub(r"[.:]", "-", str(plain)) + ".example.net"
            return done(answer_name=ptr, addresses=[str(plain)], records=[{"type": "PTR", "name": plain.reverse_pointer, "value": ptr, "ttl": 3600}],
                        authoritative=False, ok=True)
        rows = DNS_ZONE.get(name.lower())
        if rows is None:
            return done(error=DNS_NXDOMAIN_MSG)
        if rtype == "ALL":
            # every type in DNS_ALL_TYPES at once: the CNAME chain, then the chain end's records of each type, merged and deduped
            hops = [row for row in rows if row[0] == "CNAME"]
            end = hops[-1][2] if hops else name
            tail = DNS_ZONE.get(end.lower(), []) if hops else rows
            merged: List[Dict[str, Any]] = []
            seen: set = set()

            def add_row(row: Tuple[str, str, str, int]) -> None:
                value = row[2] if row[0] in ("TXT", "CAA", "NAPTR") else row[2].lower()
                key = (row[0], row[1].lower(), value)
                if key not in seen:
                    seen.add(key)
                    merged.append(dict(zip(DNS_RECORD_KEYS, row)))

            for row in hops:
                add_row(row)
            for t in DNS_ALL_TYPES:
                if t == "CNAME":
                    continue
                for row in tail:
                    if row[0] == t:
                        add_row(row)
            aliases = [row[1] for row in hops]
            addresses = [r["value"] for r in merged if r["type"] == "A"] + [r["value"] for r in merged if r["type"] == "AAAA"]
            if not merged:
                return done(answer_name=end, aliases=aliases, records=merged, authoritative=False, error=DNS_NO_ADDRESSES_MSG)
            return done(answer_name=end, addresses=addresses, aliases=aliases, records=merged, authoritative=False, ok=True)
        if rtype is not None:
            # every answer is listed; found = the records of the type owned by a name on the CNAME chain (for CNAME, the chain's own)
            hops = [row for row in rows if row[0] == "CNAME"]
            end = hops[-1][2] if hops else name
            tail = [] if rtype == "CNAME" else [row for row in (DNS_ZONE.get(end.lower(), []) if hops else rows) if row[0] == rtype]
            answers = [dict(zip(DNS_RECORD_KEYS, row)) for row in hops + tail]
            names = {name.lower()} | {row[2].lower() for row in hops}
            found = [r["value"] for r in answers if r["type"] == rtype and r["name"].lower() in names]
            fields: Dict[str, Any] = {"records": answers, "aliases": [row[1] for row in hops]}
            if found or hops:
                fields["answer_name"] = found[0] if rtype == "PTR" and found else end
            if not found:
                return done(error=DNS_NO_RECORDS_MSG.format(rtype), **fields)
            if rtype in ("A", "AAAA"):
                fields["addresses"] = list(dict.fromkeys(found))
            return done(authoritative=False, ok=True, **fields)
        rows = [row for row in rows if row[0] in ("CNAME", "A", "AAAA")]
        records = [dict(zip(DNS_RECORD_KEYS, row)) for row in rows]
        aliases = [r["name"] for r in records if r["type"] == "CNAME"]
        answer = next((r["value"] for r in reversed(records) if r["type"] == "CNAME"), name)
        addresses = [r["value"] for r in records if r["type"] == "A"] + [r["value"] for r in records if r["type"] == "AAAA"]
        if not addresses:
            return done(answer_name=answer, aliases=aliases, records=records, authoritative=False, error=DNS_NO_ADDRESSES_MSG)
        return done(answer_name=answer, addresses=addresses, aliases=aliases, records=records, authoritative=False, ok=True)

    def dns_flush(self) -> Dict[str, Any]:
        """POST /api/tools/dns/flush: the service empties the Windows DNS cache; here it is ok after a short wait."""
        t0 = time.time()
        time.sleep(self.dns_flush_s)
        return {"ok": True, "method": "native", "error": None, "duration_ms": int(round((time.time() - t0) * 1000)), "ts": time.time()}

    def ip_renew(self) -> Dict[str, Any]:
        """POST /api/tools/ip/renew: one release/renew at a time (RuntimeError, a 409). Like the service it releases and renews
        every connected DHCP adapter of the network the fake PC is on, with ping monitoring paused meanwhile (paused_monitoring:
        it was running), and answers the internet adapter's address. A DHCP adapter no server answers on (network "a"'s
        self-assigned Ethernet 2) is a warning; with none renewed it is not ok."""
        with self.lock:
            if self.ip_renew_running:
                raise RuntimeError(IP_RENEW_BUSY_MSG)
            self.ip_renew_running = True
            paused = not self.paused
        t0 = time.time()
        try:
            time.sleep(self.ip_renew_s)
            with self.lock:
                prof = net_profile(self.net_profile)
            adapters: List[Dict[str, Any]] = []
            warnings: List[str] = []
            for a in prof["adapters"]:
                if a["status"] != "up" or not a["dhcp_enabled"]:
                    continue
                answered = bool(a["ipv4"]) and not a["ipv4"][0]["address"].startswith("169.254.")
                adapters.append({"name": a["name"], "released": True, "renewed": answered, "error": None if answered else "No DHCP server answered"})
                if not answered:
                    warnings.append(f"{a['name']}: no DHCP server answered, it kept a self-assigned address")
            if not adapters:
                error = IP_RENEW_NO_DHCP_MSG
            elif not any(x["renewed"] for x in adapters):
                error = IP_RENEW_NO_ADDRESS_MSG
            else:
                error = None
            nic = net_internet_nic(prof)
            renewed_nic = error is None and nic is not None and any(x["name"] == nic["name"] and x["renewed"] for x in adapters)
            return {"ok": error is None, "address": nic["ipv4"][0]["address"] if renewed_nic else None,
                    "adapter": nic["name"] if renewed_nic else None, "adapters": adapters, "warnings": warnings, "paused_monitoring": paused,
                    "method": "native", "error": error, "duration_ms": int(round((time.time() - t0) * 1000)), "ts": time.time()}
        finally:
            with self.lock:
                self.ip_renew_running = False

    # -- Network info: NAT check, switch port, port-forward test --------
    def nat_view(self) -> Dict[str, Any]:
        """GET /api/netcheck/nat: the result kept for this network and whether a check runs."""
        with self.lock:
            return {"result": copy.deepcopy(self.nat_last), "running": self.nat_running}

    def _nat_result(self, ts: float, profile: Optional[str] = None, generation: Optional[int] = None) -> Dict[str, Any]:
        """A NAT_RESULT for the network the fake PC is on (or *profile*, with its *generation*): "a" a single NAT, "b" a
        carrier-grade NAT, the others offline with the service's error (no internet adapter, or no public address)."""
        name = self.net_profile if profile is None else profile
        prof = net_profile(name)
        result: Dict[str, Any] = {"ts": ts, "generation": self.net_generation if generation is None else generation, "duration_ms": 0,
                                  "verdict": "offline", "confidence": None,
                                  "title": NAT_TEXT["offline"][0], "explanation": NAT_TEXT["offline"][1],
                                  "router": {"gateway": None, "wan_ip": None, "wan_source": None,
                                             "natpmp": {"answered": False, "result": None, "external_ip": None},
                                             "upnp": dict(dict.fromkeys(UPNP_KEYS), found=False)},
                                  "public_ip": None, "trace": None, "port_mappings": None, "error": None}
        public = prof["public_ip"]
        if prof["internet_nic_index"] is None or not public:
            result["error"] = NAT_NO_INTERNET_ERROR if prof["internet_nic_index"] is None else NAT_NO_PUBLIC_IP_ERROR
            return result
        router = result["router"]
        router["gateway"] = prof["default_gateway"]
        if name == "b":
            verdict, wan, source = "cgnat", NAT_CGNAT_WAN_IP, "natpmp"          # the router answers NAT-PMP only
        else:
            verdict, wan, source = "single_nat", public, "upnp"
            router["upnp"] = {"found": True, "server": NAT_ROUTER_SERVER, "model": NAT_ROUTER_MODEL, "service": NAT_UPNP_SERVICE,
                              "status": "Connected", "external_ip": public, "error": None}
            result["port_mappings"] = {"entries": [dict(zip(MAPPING_KEYS, row)) for row in NAT_PORT_MAPPINGS], "truncated": False,
                                       "error": None}
        router.update(wan_ip=wan, wan_source=source, natpmp={"answered": True, "result": 0, "external_ip": wan})
        result.update(verdict=verdict, confidence="high", title=NAT_TEXT[verdict][0], explanation=NAT_TEXT[verdict][1], public_ip=public,
                      duration_ms=NAT_PROBE_MS + int(round((time.time() - ts) * 1000)))
        return result

    def nat_run(self) -> Dict[str, Any]:
        """POST /api/netcheck/nat: check now (after nat_delay_s), 409 while a check runs. Like NatChecker.run the result describes
        the network the check started on and carries that generation; an offline result is not kept, nor one a network change
        overtook."""
        with self.lock:
            if self.nat_running:
                raise ToolRefused(409, "conflict", NAT_BUSY_TEXT)
            self.nat_running = True
            epoch, delay, profile, generation = self.nat_epoch, self.nat_delay_s, self.net_profile, self.net_generation
        t0 = time.time()
        try:
            if delay > 0:
                time.sleep(delay)
            with self.lock:
                result = self._nat_result(t0, profile, generation)
                if result["verdict"] != "offline" and self.nat_epoch == epoch:
                    self.nat_last = copy.deepcopy(result)
            return result
        finally:
            with self.lock:
                self.nat_running = False

    @staticmethod
    def _wired_adapters(prof: Dict[str, Any]) -> List[Dict[str, Any]]:
        """The adapters a switch port can be looked up on (tnt.switchport: Ethernet, physical, up)."""
        return [{"name": a["name"], "index": a["index"], "mac": a["mac"], "is_internet": a["index"] == prof["internet_nic_index"]}
                for a in prof["adapters"] if a["if_type"] == 6 and a["is_physical"] and a["status"] == "up"]

    def _pktmon_holder(self) -> Optional[str]:
        """Who holds Packet Monitor (tnt.pktmon.LOCK): "switchport" while a search listens. A packet capture runs its
        own ETW session and never takes it, so the two can run together."""
        if self.switch_job is not None and self.switch_job["state"] == "listening":
            return "switchport"
        return None

    def _switch_job_locked(self) -> Dict[str, Any]:
        """The latest search, else the newest kept one, else an idle job (a copy)."""
        if self.switch_job is not None:
            return copy.deepcopy(self.switch_job)
        if self.switch_kept:
            return copy.deepcopy(max(self.switch_kept.values(), key=lambda j: j.get("ts") or 0.0))
        return dict(dict.fromkeys(SWITCH_JOB_KEYS), state="idle", neighbors=[], generation=self.net_generation)

    def switch_status(self) -> Dict[str, Any]:
        """GET /api/netcheck/switch (SWITCH_STATUS)."""
        with self.lock:
            return {"job": self._switch_job_locked(), "adapters": self._wired_adapters(net_profile(self.net_profile)),
                    "available": self.pktmon_reason is None, "reason": self.pktmon_reason}

    def switch_start(self, adapter: Any, seconds: Any) -> Dict[str, Any]:
        """POST /api/netcheck/switch, checked in tnt.switchport's order: Packet Monitor, the adapter (by name, else the internet
        adapter when it is wired, else the first wired one), the seconds (null: 65, clamped to 20-120), one search at a time and
        the lock a running capture holds. Answers the listening job."""
        with self.lock:
            if self.pktmon_reason:
                raise ToolRefused(409, "unavailable", self.pktmon_reason)
            wired = self._wired_adapters(net_profile(self.net_profile))
            if adapter is not None and not isinstance(adapter, str):
                raise ValueError(SWITCH_ADAPTER_TEXT.format(name=str(adapter)[:40]))
            name = (adapter or "").strip()
            chosen = next((a for a in wired if a["name"] == name), None) if name else next((a for a in wired if a["is_internet"]),
                                                                                           wired[0] if wired else None)
            if chosen is None:
                if name:
                    raise ValueError(SWITCH_ADAPTER_TEXT.format(name=name[:40]))
                raise ToolRefused(409, "unavailable", SWITCH_NO_WIRED_TEXT)
            if seconds is None:
                seconds = SWITCH_DEFAULT_SECONDS
            if isinstance(seconds, bool) or not (isinstance(seconds, int) or (isinstance(seconds, float) and seconds.is_integer())):
                raise ValueError(SWITCH_SECONDS_TEXT)
            listen_s = max(SWITCH_SECONDS_RANGE[0], min(SWITCH_SECONDS_RANGE[1], int(seconds)))
            if self.switch_job is not None and self.switch_job["state"] == "listening":
                raise ToolRefused(409, "conflict", SWITCH_BUSY_TEXT)
            holder = self._pktmon_holder()
            if holder:
                raise ToolRefused(409, "conflict", PKTMON_LOCK_TEXTS[holder])
            now = time.time()
            job = {"state": "listening", "adapter": {k: chosen[k] for k in SWITCH_JOB_ADAPTER_KEYS}, "started_ts": now, "listen_s": listen_s,
                   "elapsed_s": 0.0, "neighbors": [], "error": None, "reason": None, "generation": self.net_generation, "ts": now}
            self.switch_job = job
            self.switch_gen += 1
            gen = self.switch_gen
            snap = copy.deepcopy(job)
        self.hub.publish("netcheck.switch", {"job": snap})
        threading.Thread(target=self._switch_worker, args=(gen, job), name="mock-switchport", daemon=True).start()
        return snap

    def _switch_worker(self, gen: int, job: Dict[str, Any]) -> None:
        """The listen: its progress every half second, then after switch_listen_s the switch it heard (kept for the adapter)."""
        t0 = time.time()
        while True:
            with self.lock:
                if self.switch_gen != gen:
                    return
                listen, elapsed = self.switch_listen_s, time.time() - t0
                job.update(elapsed_s=round(min(elapsed, listen), 1), ts=time.time())
                snap = copy.deepcopy(job)
            if elapsed >= listen:
                break
            self.hub.publish("netcheck.switch", {"job": snap})
            time.sleep(max(0.02, min(0.5, listen - elapsed)))
        with self.lock:
            if self.switch_gen != gen:
                return
            found, now = self.switch_found, time.time()
            job.update(state="done", neighbors=[copy.deepcopy(MOCK_NEIGHBOR)] if found else [],
                       reason=None if found else SWITCH_NO_NEIGHBOR_TEXT.format(seconds=job["listen_s"]), generation=self.net_generation, ts=now)
            self.switch_kept[job["adapter"]["mac"]] = copy.deepcopy(job)
            snap = copy.deepcopy(job)
        self.hub.publish("netcheck.switch", {"job": snap})

    def switch_stop(self) -> Dict[str, Any]:
        """DELETE /api/netcheck/switch: cancel a listen (nothing is kept); the latest job either way."""
        with self.lock:
            job = self.switch_job
            if job is None or job["state"] != "listening":
                return self._switch_job_locked()
            self.switch_gen += 1
            now = time.time()
            job.update(state="cancelled", elapsed_s=round(now - job["started_ts"], 1), ts=now)
            snap = copy.deepcopy(job)
        self.hub.publish("netcheck.switch", {"job": snap})
        return snap

    def _portcheck_wait(self, now: float) -> float:
        """Seconds until another test may start (tnt.portcheck.PortChecker._rate_wait, between monotonic starts); 0 turns a limit off."""
        self.portcheck_starts = [s for s in self.portcheck_starts if now - s < PORTCHECK_RATE_WINDOW_S]
        starts, last, wait = self.portcheck_starts, self.portcheck_last_start, 0.0
        if self.portcheck_min_gap_s > 0 and last is not None and now - last < self.portcheck_min_gap_s:
            wait = self.portcheck_min_gap_s - (now - last)
        if self.portcheck_per_hour > 0 and len(starts) >= self.portcheck_per_hour:
            wait = max(wait, starts[len(starts) - int(self.portcheck_per_hour)] + PORTCHECK_RATE_WINDOW_S - now)
        return wait

    def portcheck_test(self, port: Any) -> Dict[str, Any]:
        """POST /api/netcheck/portforward, refused in tnt.portcheck's order before anything runs: the port (400), a VPN, no fresh
        public address, a test running (409), the rate limits (429 with Retry-After). After portcheck_delay_s PORTCHECK_OPEN_PORT
        answers, PORTCHECK_ERROR_PORT reaches neither port checker and any other port does not answer."""
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(PORTCHECK_PORT_TEXT)
        with self.lock:
            verdict = (self.nat_last or {}).get("verdict")
            if verdict == "vpn":
                raise ToolRefused(409, "vpn", PORTCHECK_VPN_TEXT)
            generation = self.net_generation
            public = self._public_ip_view(time.time())
            if not public["ip"] or public["ts"] is None or (self.net_changed_ts is not None and public["ts"] < self.net_changed_ts):
                raise ToolRefused(409, "no_public_ip", PORTCHECK_NO_IP_TEXT)
            if self.portcheck_running:
                raise ToolRefused(409, "conflict", PORTCHECK_BUSY_TEXT)
            start = time.monotonic()
            wait = self._portcheck_wait(start)
            if wait > 0:
                seconds = max(1, math.ceil(round(wait, 6)))
                raise ToolRefused(429, "rate_limited", PORTCHECK_RATE_TEXT.format(seconds=seconds), headers={"Retry-After": str(seconds)})
            self.portcheck_running = True
            self.portcheck_last_start = start
            self.portcheck_starts.append(start)
            ip, delay = public["ip"], self.portcheck_delay_s
        ts = time.time()
        try:
            time.sleep(max(0.0, delay))
            names = PORTCHECK_PROVIDER_NAMES
            if port == PORTCHECK_ERROR_PORT:
                reason = f"{names['portchecker.io']} {PORTCHECK_REASON_TIMEOUT}, {names['globalping']} {PORTCHECK_REASON_TIMEOUT}"
                reachable, provider, detail, error = None, "globalping", None, PORTCHECK_FAILED_TEXT.format(reason=reason)
            elif port == PORTCHECK_OPEN_PORT:
                reachable, provider, detail, error = True, "portchecker.io", PORTCHECKER_OPEN_DETAIL, None
            else:
                reachable, provider, detail, error = False, "portchecker.io", PORTCHECKER_CLOSED_DETAIL, None
            result = {"ts": ts, "generation": generation, "port": port, "protocol": PORTCHECK_PROTOCOL, "public_ip": ip,
                      "reachable": reachable, "provider": provider, "detail": detail, "nat_verdict": verdict, "error": error,
                      "duration_ms": max(0, int(round((time.monotonic() - start) * 1000)))}
            with self.lock:
                if self.net_generation == generation:
                    self.portcheck_last = copy.deepcopy(result)
            return result
        finally:
            with self.lock:
                self.portcheck_running = False

    # -- Tools: TFTP server (tnt.tftp) -----------------------------------
    @staticmethod
    def _tftp_candidates(prof: Dict[str, Any]) -> List[Dict[str, Any]]:
        """The adapters it can serve on (tnt.tftp._candidates): up, with an IPv4 address."""
        return [a for a in prof["adapters"] if a["status"] == "up" and a["ipv4"]]

    @staticmethod
    def _tftp_adapter_row(a: Dict[str, Any], prof: Dict[str, Any]) -> Dict[str, Any]:
        first = a["ipv4"][0]
        return {"name": a["name"], "index": a["index"], "ip": first["address"], "prefix": first["prefix"], "type_name": a["type_name"],
                "is_physical": a["is_physical"], "is_internet": a["index"] == prof["internet_nic_index"], "status": a["status"]}

    @staticmethod
    def _tftp_pick(wanted: str, candidates: List[Dict[str, Any]], prof: Dict[str, Any]) -> Dict[str, Any]:
        """tnt.tftp._pick_adapter: the named adapter, else the first physical Ethernet, else the internet adapter, else the first."""
        if wanted:
            match = next((a for a in candidates if a["name"] == wanted), None)
            if match is None:
                raise ValueError(f"adapter '{wanted}' is not up or has no IPv4 address")
            return match
        pick = (next((a for a in candidates if a["if_type"] == 6 and a["is_physical"]), None)
                or next((a for a in candidates if a["index"] == prof["internet_nic_index"]), None) or (candidates[0] if candidates else None))
        if pick is None:
            raise ValueError("no network adapter is up with an IPv4 address")
        return pick

    def tftp_summary(self) -> Dict[str, Any]:
        """status.tftp and the tftp.state event (TftpServer.summary)."""
        with self.lock:
            running = self.tftp_running
            return {"available": True, "running": running, "adapter": self.tftp_adapter["name"] if running and self.tftp_adapter else None,
                    "listen_ips": [e["ip"] for e in self.tftp_listen] if running else [], "active": len(self.tftp_transfers),
                    "uploads": self.tftp_uploads, "since_ts": self.tftp_since, "error": self.tftp_error}

    def tftp_status(self) -> Dict[str, Any]:
        """GET /api/tftp/status (TftpServer.status): while it is off, the adapter a start would pick (or the reason there is none)."""
        with self.lock:
            prof = net_profile(self.net_profile)
            candidates = self._tftp_candidates(prof)
            settings = self.settings["tftp"]
            adapter, warning = (self.tftp_adapter if self.tftp_running else None), None
            if adapter is None:
                try:
                    adapter = self._tftp_adapter_row(self._tftp_pick(settings["adapter"], candidates, prof), prof)
                except ValueError as exc:
                    warning = None if self.tftp_running else str(exc)
            return {"available": True, "running": self.tftp_running, "since_ts": self.tftp_since, "error": self.tftp_error, "warning": warning,
                    "adapter": copy.deepcopy(adapter), "adapters": [self._tftp_adapter_row(a, prof) for a in candidates],
                    "listen": copy.deepcopy(self.tftp_listen), "root": TFTP_ROOT, "uploads": self.tftp_uploads,
                    "firewall": {"rule": TFTP_FIREWALL_RULE, "ok": None, "error": None}, "conflict": copy.deepcopy(self.tftp_conflict),
                    "transfers": copy.deepcopy(self.tftp_transfers), "history": copy.deepcopy(self.tftp_history),
                    "counts": {k: len(self.tftp_transfers) if k == "active" else self.tftp_counts[k] for k in TFTP_COUNT_KEYS},
                    "settings": {k: settings[k] for k in TFTP_SETTINGS_KEYS}}

    def tftp_files(self) -> List[Dict[str, Any]]:
        """GET /api/tftp/files: TFTP_FILES, sorted by name like TftpServer.files."""
        rows = [{"name": name, "size": size, "mtime": self.started_ts - age} for name, size, age in TFTP_FILES]
        return sorted(rows, key=lambda f: f["name"].casefold())

    def tftp_start(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """POST /api/tftp/start {"adapter", "uploads"} with the service's 400s; the status unchanged while it runs, 409
        ``tftp_port_in_use`` with the owners while tftp_port_owners lists any. A phone reads its file soon after a start."""
        adapter, uploads = body.get("adapter"), body.get("uploads", False)
        if not isinstance(uploads, bool):
            raise ValueError("uploads must be true or false")
        if adapter is not None and not isinstance(adapter, str):
            raise ValueError("adapter must be a name or null")
        with self.lock:
            if self.tftp_running:
                return self.tftp_status()
            self.tftp_error, self.tftp_conflict = None, None
            prof = net_profile(self.net_profile)
            wanted = self.settings["tftp"]["adapter"] if adapter is None else adapter.strip()
            chosen = self._tftp_pick(wanted, self._tftp_candidates(prof), prof)
            owners = [dict(o) for o in self.tftp_port_owners]
            refused = None
            if owners:
                self.tftp_error = f"UDP port {TFTP_PORT} is already used by {', '.join(str(o['name']) for o in owners)}"
                self.tftp_conflict = {"port": TFTP_PORT, "owners": owners}
                refused = ToolRefused(409, TFTP_PORT_IN_USE_CODE, self.tftp_error, extra={"owners": owners})
            else:
                self.tftp_running, self.tftp_since, self.tftp_uploads = True, time.time(), uploads
                self.tftp_adapter = self._tftp_adapter_row(chosen, prof)
                self.tftp_listen = [{"ip": e["address"], "port": TFTP_PORT} for e in chosen["ipv4"]]
                self.tftp_gen += 1
            gen, fast = self.tftp_gen, self.tftp_fast
        self.hub.publish("tftp.state", self.tftp_summary())
        if refused is not None:
            raise refused
        threading.Thread(target=self._tftp_worker, args=(gen, fast), name="mock-tftp", daemon=True).start()
        return self.tftp_status()

    def tftp_stop(self) -> Dict[str, Any]:
        """POST /api/tftp/stop: transfers end cancelled and uploads switch off; the error of a stop for a network change stays."""
        ended: List[Dict[str, Any]] = []
        with self.lock:
            was = self.tftp_running
            self.tftp_running, self.tftp_uploads, self.tftp_since, self.tftp_adapter, self.tftp_listen = False, False, None, None, []
            self.tftp_gen += 1
            now = time.time()
            for tr in self.tftp_transfers:
                tr.update(state="cancelled", error=TFTP_MSG_CANCELLED, ended_ts=now)
                self.tftp_counts["cancelled"] += 1
                ended.append(copy.deepcopy(tr))
            self.tftp_history = (list(reversed(self.tftp_transfers)) + self.tftp_history)[:TFTP_HISTORY_KEEP]
            self.tftp_transfers = []
        for tr in ended:
            self.hub.publish("tftp.transfer", {"transfer": tr})
        if was:
            self.hub.publish("tftp.state", self.tftp_summary())
        return self.tftp_status()

    def tftp_set_uploads(self, on: Any) -> Dict[str, Any]:
        """POST /api/tftp/uploads {"on"} (never saved)."""
        if not isinstance(on, bool):
            raise ValueError("on must be true or false")
        with self.lock:
            changed = self.tftp_uploads != on
            self.tftp_uploads = on
        if changed:
            self.hub.publish("tftp.state", self.tftp_summary())
        return self.tftp_status()

    def tftp_update_settings(self, patch: Any) -> Dict[str, Any]:
        """PUT /api/tftp/settings {"adapter", "max_upload_mb"} with TftpServer.update_settings' checks and texts."""
        if not isinstance(patch, dict):
            raise ValueError("settings patch must be an object")
        unknown = sorted(str(k) for k in patch if k not in TFTP_SETTINGS_KEYS)
        if unknown:
            raise ValueError(f"unknown TFTP setting '{unknown[0][:40]}'")
        new: Dict[str, Any] = {}
        with self.lock:
            if "adapter" in patch:
                value = patch.get("adapter")
                if value is not None and not isinstance(value, str):
                    raise ValueError("adapter must be a name or empty")
                name = (value or "").strip()
                if name and name not in [a["name"] for a in self._tftp_candidates(net_profile(self.net_profile))]:
                    raise ValueError(f"adapter '{name[:40]}' is not up or has no IPv4 address")
                new["adapter"] = name
            if "max_upload_mb" in patch:
                value = patch.get("max_upload_mb")
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError(TFTP_MAX_UPLOAD_MB_TEXT)
                try:
                    mb = int(value)
                except (ValueError, OverflowError):
                    raise ValueError(TFTP_MAX_UPLOAD_MB_TEXT) from None
                if mb != value or not TFTP_MAX_UPLOAD_MB[0] <= mb <= TFTP_MAX_UPLOAD_MB[1]:
                    raise ValueError(TFTP_MAX_UPLOAD_MB_TEXT)
                new["max_upload_mb"] = mb
            old = copy.deepcopy(self.settings["tftp"])
            self.settings["tftp"].update(new)
            changed = changed_keys({"tftp": old}, {"tftp": self.settings["tftp"]})
        if changed:
            self.hub.publish("settings.changed", {"changed": changed})
        if new:
            self.hub.publish("tftp.state", self.tftp_summary())
        return self.tftp_status()

    def _tftp_worker(self, gen: int, fast: bool) -> None:
        """A phone on the served subnet reads its configuration file (TFTP_FILES[2]) a moment after a start: tftp.transfer as it
        goes, tftp.state when it begins and ends."""
        try:
            time.sleep(0.05 if fast else 1.5)
            name, size, _age = TFTP_FILES[2]
            with self.lock:
                if self.tftp_gen != gen or not self.tftp_listen:
                    return
                own = self.tftp_listen[0]["ip"]
                tr = {"id": self.tftp_next_id, "client": ".".join(own.split(".")[:3] + ["62"]), "op": "read", "file": name, "mode": "octet",
                      "blksize": 1468, "windowsize": 1, "size": size, "bytes": 0, "state": "negotiating", "error": None,
                      "started_ts": time.time(), "ended_ts": None}
                self.tftp_next_id += 1
                self.tftp_transfers.append(tr)
                snap = copy.deepcopy(tr)
            self.hub.publish("tftp.transfer", {"transfer": snap})
            self.hub.publish("tftp.state", self.tftp_summary())
            for sent in list(range(tr["blksize"], size, tr["blksize"])) + [size]:
                time.sleep(0.02 if fast else 0.3)
                with self.lock:
                    if self.tftp_gen != gen:
                        return
                    tr.update(state="sending", bytes=sent)
                    snap = copy.deepcopy(tr)
                self.hub.publish("tftp.transfer", {"transfer": snap})
            with self.lock:
                if self.tftp_gen != gen:
                    return
                tr.update(state="done", ended_ts=time.time())
                self.tftp_transfers = [t for t in self.tftp_transfers if t is not tr]
                self.tftp_history = ([tr] + self.tftp_history)[:TFTP_HISTORY_KEEP]
                self.tftp_counts["done"] += 1
                snap = copy.deepcopy(tr)
            self.hub.publish("tftp.transfer", {"transfer": snap})
            self.hub.publish("tftp.state", self.tftp_summary())
        except Exception:  # noqa: BLE001
            log.exception("tftp worker failed")

    # -- Packet capture (tnt.capture): the live analyser of the Packet capture page ----------
    def capture_adapters(self) -> List[Dict[str, Any]]:
        """The adapters a capture can run on (CaptureManager.adapters): up, not loopback, physical."""
        with self.lock:
            prof = net_profile(self.net_profile)
        return [{"name": a["name"], "index": a["index"], "mac": a["mac"], "type_name": a["type_name"], "wifi": a["if_type"] == 71}
                for a in prof["adapters"] if a["status"] == "up" and a["is_physical"]]

    def _capture_files_locked(self) -> List[Dict[str, Any]]:
        return sorted(copy.deepcopy(self.capture_files), key=lambda f: (f["created_ts"], f["name"]), reverse=True)

    @staticmethod
    def capture_limits() -> Dict[str, Any]:
        """The choices the page's Start controls offer (CaptureManager.limits)."""
        return {"max_rows": CAPTURE_MAX_ROWS, "max_packets": CAPTURE_MAX_PACKETS, "seconds": list(CAPTURE_SECONDS),
                "sizes_mb": list(CAPTURE_SIZES_MB), "default_seconds": CAPTURE_DEFAULT_SECONDS,
                "default_mb": CAPTURE_DEFAULT_MB}

    def _capture_session_locked(self) -> Optional[Dict[str, Any]]:
        """The open SESSION as a copy, None when nothing is open; the counts are read off the list as they are asked
        for, and a running capture's time and size keep moving (CaptureManager.session)."""
        if self.capture_session is None:
            return None
        out = copy.deepcopy(self.capture_session)
        out["packets"] = self.capture_total
        out["shown"] = len(self.capture_rows)
        out["truncated"] = self.capture_truncated
        out["dropped"] = self.capture_dropped
        out["calls"] = len(self.capture_calls_found)
        if out["state"] == "capturing":
            out["elapsed_s"] = round(max(0.0, time.monotonic() - self.capture_started_mono), 1)
            out["bytes"] = self.capture_bytes
        return out

    # -- Pro AV (tnt.proav.ProAvScanner) ------------------------------------------------------------
    def proav_job_locked(self) -> Dict[str, Any]:
        return copy.deepcopy(self.proav_job)

    def proav_idle_job(self) -> Dict[str, Any]:
        return {"state": "idle", "adapter": None, "seconds": PROAV_DEFAULT_SECONDS, "deep": True,
                "started_ts": None, "elapsed_s": 0.0, "phase": None, "pct": 0.0,
                "counts": {"mdns": 0, "sap": 0, "ptp": 0, "frames": 0, "devices": 0, "streams": 0},
                "listeners": [], "error": None, "reason": None, "generation": 0, "ts": time.time()}

    def proav_status(self) -> Dict[str, Any]:
        with self.lock:
            return {"available": self.proav_reason is None, "reason": self.proav_reason,
                    "adapters": [] if self.proav_reason else proav_adapters(),
                    "job": self.proav_job_locked(), "last_run_ts": self.proav_last_run_ts,
                    "limits": {"seconds": list(PROAV_SECONDS), "default_seconds": PROAV_DEFAULT_SECONDS,
                               "min_seconds": 5, "max_seconds": 600}}

    def proav_tile(self) -> Dict[str, Any]:
        """The block /api/status carries for the Pro AV tile (ProAvScanner.tile): counts and the worst finding."""
        with self.lock:
            job = self.proav_job
            result = self.proav_result or {}
            findings = result.get("findings") or []
            worst = next((lvl for lvl in ("bad", "warn", "info", "good")
                          if any(f.get("level") == lvl for f in findings)), None)
            master = ((result.get("clock") or {}).get("best") or {}).get("master") or {}
            return {"available": self.proav_reason is None, "reason": self.proav_reason,
                    "running": job.get("state") == "scanning", "pct": job.get("pct") or 0.0,
                    "devices": len(result.get("devices") or []), "streams": len(result.get("streams") or []),
                    "clock": master.get("vendor") or master.get("mac"), "worst": worst,
                    "last_run_ts": self.proav_last_run_ts}

    def proav_start(self, body: Dict[str, Any]) -> Dict[str, Any]:
        seconds = body.get("seconds", PROAV_DEFAULT_SECONDS)
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or int(seconds) != seconds:
            raise ValueError("seconds must be a whole number from 5 to 600")
        seconds = int(seconds)
        if not 5 <= seconds <= 600:
            raise ValueError("seconds must be a whole number from 5 to 600")
        adapters = proav_adapters()
        wanted = body.get("adapter")
        adapter = adapters[0]
        if wanted not in (None, ""):
            match = next((a for a in adapters if a["name"] == str(wanted) or str(a["index"]) == str(wanted)), None)
            if match is None:
                raise ValueError("that adapter is not available for a scan")
            adapter = match
        deep = body.get("deep", True)
        with self.lock:
            if self.proav_reason:
                raise LookupError(self.proav_reason)
            if self.proav_job.get("state") == "scanning":
                raise RuntimeError("a Pro AV scan is already running")
            self.proav_gen += 1
            generation = self.proav_gen
            self.proav_stop_evt = threading.Event()
            stop = self.proav_stop_evt
            self.proav_result = None
            self.proav_job = {"state": "scanning", "adapter": dict(adapter), "seconds": seconds, "deep": bool(deep),
                              "started_ts": time.time(), "elapsed_s": 0.0, "phase": "starting", "pct": 0.0,
                              "counts": {"mdns": 0, "sap": 0, "ptp": 0, "frames": 0, "devices": 0, "streams": 0},
                              "listeners": proav_listeners(packets=False), "error": None, "reason": None,
                              "generation": generation, "ts": time.time()}
            job = self.proav_job_locked()
        threading.Thread(target=self._proav_worker, args=(generation, seconds, dict(adapter), bool(deep), stop),
                         daemon=True, name="mock-proav").start()
        self.hub.publish("proav.state", {"job": job})
        return job

    def proav_cancel(self) -> bool:
        with self.lock:
            if self.proav_job.get("state") != "scanning":
                return False
            stop = self.proav_stop_evt
        stop.set()
        return True

    def _proav_worker(self, generation: int, seconds: int, adapter: Dict[str, Any], deep: bool,
                      stop: threading.Event) -> None:
        """Pretend to listen: the progress the page draws, over PROAV_FAKE_LISTEN_S rather than the whole window."""
        steps = 12
        cancelled = False
        for step in range(1, steps + 1):
            if stop.wait(PROAV_FAKE_LISTEN_S / steps):
                cancelled = True
                break
            share = step / steps
            with self.lock:
                if self.proav_gen != generation:
                    return
                self.proav_job.update({
                    "phase": "listening", "pct": round(0.02 + 0.88 * share, 4),
                    "elapsed_s": round(seconds * share, 2),
                    "counts": {"mdns": int(214 * share), "sap": int(3 * share), "ptp": int(659 * share),
                               "frames": int(48213 * share) if deep else 0, "devices": int(7 * share),
                               "streams": int(3 * share)},
                    "listeners": [dict(l, packets=int(l["packets"] * share)) for l in proav_listeners()],
                    "ts": time.time()})
                job = self.proav_job_locked()
            self.hub.publish("proav.progress", {"job": job})
        now = time.time()
        result = proav_result(now, seconds, adapter, deep, cancelled=cancelled)
        with self.lock:
            if self.proav_gen != generation:
                return
            self.proav_result = result
            self.proav_last_run_ts = now
            self.proav_job.update({"state": "cancelled" if cancelled else "done", "phase": "done", "pct": 1.0,
                                   "counts": dict(result["counts"]), "listeners": list(result["listeners"]),
                                   "ts": now})
            job = self.proav_job_locked()
        self.hub.publish("proav.state", {"job": job})

    def proav_last(self) -> Optional[Dict[str, Any]]:
        with self.lock:
            return copy.deepcopy(self.proav_result)

    def capture_status(self) -> Dict[str, Any]:
        """GET /api/capture (CAPTURE_STATUS_KEYS): what can capture, the open session, the saved files and the limits."""
        adapters = self.capture_adapters()
        with self.lock:
            return {"available": self.capture_reason is None, "reason": self.capture_reason, "adapters": adapters,
                    "session": self._capture_session_locked(), "files": self._capture_files_locked(),
                    "limits": self.capture_limits()}

    def capture_tile(self) -> Dict[str, Any]:
        """The block /api/status carries for the Packet capture tile (CaptureManager.tile): counts and the adapter's
        name, never any packet contents."""
        with self.lock:
            session = self._capture_session_locked() or {}
            adapter = session.get("adapter") or {}
            return {"available": self.capture_reason is None, "reason": self.capture_reason,
                    "running": session.get("state") == "capturing", "adapter": adapter.get("name"),
                    "packets": int(session.get("packets") or 0), "calls": int(session.get("calls") or 0),
                    "files": len(self.capture_files)}

    def _capture_clear_locked(self) -> None:
        """Forget the open capture's packet list, its calls and its counts (a start, an open or a discard)."""
        self.capture_rows = []
        self.capture_meta = []
        self.capture_calls_found = []
        self.capture_first_no = 1
        self.capture_total = 0
        self.capture_truncated = False
        self.capture_dropped = 0
        self.capture_bytes = 0
        self.capture_first_ts = None

    def _capture_add_locked(self, row: Dict[str, Any], parts: Dict[str, Any]) -> None:
        """One row onto the list; past CAPTURE_MAX_ROWS the oldest falls off the front and the session is truncated."""
        self.capture_rows.append(row)
        self.capture_meta.append({"layers": tuple(parts["layers"]), "fields": tuple(parts["fields"]),
                                  "payload": parts["payload"], "flags": parts["flags"], "icmp": parts["icmp"]})
        self.capture_total += 1
        over = len(self.capture_rows) - CAPTURE_MAX_ROWS
        if over > 0:
            del self.capture_rows[:over]
            del self.capture_meta[:over]
            self.capture_first_no += over
            self.capture_truncated = True

    def capture_start(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """POST /api/capture/start: the body checked like the service (400), then whether capturing is possible here
        (409 unavailable) and whether one already runs (409 conflict). Answers the capturing SESSION; the traffic
        itself is invented on a background thread until capture_s (None: the max_seconds it was started with)."""
        values = capture_start_values(body, self.capture_adapters())
        with self.lock:
            if self.capture_reason:
                raise ToolRefused(409, "unavailable", self.capture_reason)
            if self.capture_session is not None and self.capture_session["state"] == "capturing":
                raise ToolRefused(409, "conflict", CAPTURE_BUSY_TEXT)
            now = time.time()
            self._capture_clear_locked()
            self.capture_session = {
                "id": self.capture_next_id, "state": "capturing", "source": "live", "adapter": values["adapter"],
                "file": None, "saved": False, "started_ts": now, "first_ts": None, "elapsed_s": 0.0, "packets": 0,
                "shown": 0, "bytes": 0, "dropped": 0, "truncated": False, "calls": 0, "stop_reason": None,
                "error": None, "ts": now}
            self.capture_next_id += 1
            self.capture_gen += 1
            self.capture_stop_evt.clear()
            self.capture_started_mono = time.monotonic()
            gen, seed = self.capture_gen, int(now * 1000) & 0x7FFFFFFF
            run_s = float(self.capture_s) if self.capture_s is not None else float(values["max_seconds"])
            budget = int(values["max_mb"]) * 1024 * 1024
            snap = self._capture_session_locked()
        self.hub.publish("capture.state", {"session": snap})
        threading.Thread(target=self._capture_worker, args=(gen, run_s, budget, seed), name="mock-capture",
                         daemon=True).start()
        return snap

    def _capture_worker(self, gen: int, run_s: float, budget: int, seed: int) -> None:
        """The fake live capture: 8-25 invented packets a second onto the list, the scripted SIP call at its own times,
        capture.state about once a second, and the stop the first limit reached asks for."""
        try:
            rng = random.Random(seed)
            call = capture_sip_call(rng)
            plan = capture_sip_plan(rng, call)
            started = time.monotonic()
            next_tick, at, announced, reason = CAPTURE_TICK_S, 0, False, None
            while True:
                elapsed = time.monotonic() - started
                while at < len(plan) and plan[at][0] <= elapsed:
                    _when, parts, mark = plan[at]
                    at += 1
                    if not self._capture_row(gen, parts, call, mark):
                        return
                    if mark == "invite" and not announced:
                        announced = True
                        with self.lock:
                            found = copy.deepcopy(call)
                        self.hub.publish("capture.sip", {"call": found})
                burst = rng.randint(1, 3)
                for _ in range(burst):
                    if rng.random() < CAPTURE_DROP_CHANCE:
                        with self.lock:
                            self.capture_dropped += 1
                        continue
                    if not self._capture_row(gen, capture_invent(rng), None, None):
                        return
                reason = self._capture_limit(gen, elapsed, run_s, budget)
                if reason is not None:
                    break
                if elapsed >= next_tick:
                    next_tick = elapsed + CAPTURE_TICK_S
                    with self.lock:
                        if self.capture_gen != gen:
                            return
                        snap = self._capture_session_locked()
                    self.hub.publish("capture.state", {"session": snap})
                if self.capture_stop_evt.wait(burst / rng.uniform(*CAPTURE_RATE_RANGE)):
                    reason = "user"
                    break
            self._capture_finish(gen, reason)
        except Exception:  # noqa: BLE001
            log.exception("mock capture worker failed")

    def _capture_row(self, gen: int, parts: Dict[str, Any], call: Optional[Dict[str, Any]], mark: Optional[str]) -> bool:
        """One invented packet onto the list (and on into the scripted call); False when this worker is stale."""
        ts = time.time()
        with self.lock:
            if self.capture_gen != gen or self.capture_session is None:
                return False
            if self.capture_first_ts is None:
                self.capture_first_ts = ts
                self.capture_session["first_ts"] = ts
            row = {"no": self.capture_total + 1, "ts": ts, "rel": round(max(0.0, ts - self.capture_first_ts), 6),
                   "src": parts["src"], "dst": parts["dst"], "src_mac": parts["src_mac"], "dst_mac": parts["dst_mac"],
                   "proto": parts["proto"], "sport": parts["sport"], "dport": parts["dport"],
                   "length": int(parts["length"]), "info": parts["info"]}
            self._capture_add_locked(row, parts)
            self.capture_bytes += row["length"] + CAPTURE_BLOCK_BYTES
            if call is not None:
                capture_sip_mark(call, parts, mark, ts, row["no"])
                if call not in self.capture_calls_found:
                    self.capture_calls_found.append(call)
        return True

    def _capture_limit(self, gen: int, elapsed: float, run_s: float, budget: int) -> Optional[str]:
        """Why the capture must end now, else None (CaptureManager._limit_reached: seconds, then size, then packets)."""
        with self.lock:
            if self.capture_gen != gen:
                return "service"
            if elapsed >= run_s:
                return "seconds"
            if self.capture_bytes >= budget:
                return "size"
            if self.capture_total >= CAPTURE_MAX_PACKETS:
                return "packets"
        return None

    def _capture_finish(self, gen: int, reason: Optional[str]) -> None:
        """End a running capture and keep what it caught: state "stopped" with its stop_reason, then capture.state."""
        with self.lock:
            if self.capture_gen != gen or self.capture_session is None:
                return
            if self.capture_session["state"] != "capturing":
                return
            self.capture_session.update(state="stopped", stop_reason=reason or "user",
                                        elapsed_s=round(max(0.0, time.monotonic() - self.capture_started_mono), 1),
                                        bytes=self.capture_bytes, ts=time.time())
            snap = self._capture_session_locked()
        self.hub.publish("capture.state", {"session": snap})

    def capture_stop(self) -> Optional[Dict[str, Any]]:
        """POST /api/capture/stop: end the capture now and keep it; at once when nothing runs. Waits up to a second
        for the worker to leave "capturing". The SESSION, None when none is open."""
        with self.lock:
            session = self.capture_session
            running = session is not None and session["state"] == "capturing"
            if running:
                self.capture_stop_evt.set()
        if running:
            deadline = time.time() + 1.0
            while time.time() < deadline:
                with self.lock:
                    if self.capture_session is None or self.capture_session["state"] != "capturing":
                        break
                time.sleep(0.02)
        with self.lock:
            return self._capture_session_locked()

    def _capture_free_name_locked(self, when: float) -> str:
        """A TNT-capture-... name nothing has taken yet; like the service, a clash moves it on by a second."""
        taken = {f["name"] for f in self.capture_files}
        stamp = when
        for _step in range(60):
            name = time.strftime("TNT-capture-%Y%m%d-%H%M%S.pcapng", time.localtime(stamp))
            if name not in taken:
                return name
            stamp += 1
        return time.strftime("TNT-capture-%Y%m%d-%H%M%S.pcapng", time.localtime(stamp))

    def capture_save(self) -> Dict[str, Any]:
        """POST /api/capture/save: keep the open capture under a listed name -> {"session", "files"}. A capture that
        still runs is stopped first; one that was already saved, or read from a file, answers without doing anything."""
        with self.lock:
            if self.capture_session is None:
                raise ToolRefused(404, "not_found", CAPTURE_NOTHING_TEXT)
        self.capture_stop()
        with self.lock:
            session = self.capture_session
            if session is None:
                raise ToolRefused(404, "not_found", CAPTURE_NOTHING_TEXT)
            if session["source"] == "file" or session["saved"]:
                return {"session": self._capture_session_locked(), "files": self._capture_files_locked()}
            now = time.time()
            name = self._capture_free_name_locked(now)
            self.capture_files.append({"name": name, "size": max(len(tiny_pcapng(now)), self.capture_bytes),
                                       "created_ts": now, "packets": self.capture_total})
            session.update(saved=True, file=name, ts=now)
            snap = self._capture_session_locked()
            files = self._capture_files_locked()
        self.hub.publish("capture.state", {"session": snap})
        return {"session": snap, "files": files}

    def capture_discard(self) -> None:
        """POST /api/capture/discard: throw the open capture away, packets and all."""
        with self.lock:
            self.capture_stop_evt.set()
            self.capture_gen += 1
            self.capture_session = None
            self._capture_clear_locked()
        self.hub.publish("capture.state", {"session": None})

    def capture_open(self, name: Any) -> Dict[str, Any]:
        """POST /api/capture/open: read a saved capture into the packet list -> the SESSION (source "file"). A capture
        that still runs is refused (409 conflict); the rows are invented here, as many as the file says it holds."""
        text = str(name or "")
        with self.lock:
            if self.capture_session is not None and self.capture_session["state"] == "capturing":
                raise ToolRefused(409, "conflict", CAPTURE_BUSY_TEXT)
            row = self._capture_file_locked(text)
            created, packets = float(row["created_ts"]), int(row["packets"] or 0)
            size = int(row["size"] or 0)
        rows, metas, calls = capture_make_rows(min(packets, CAPTURE_MAX_ROWS), created, hash(text) & 0x7FFFFFFF)
        now = time.time()
        with self.lock:
            self.capture_stop_evt.set()
            self.capture_gen += 1
            self._capture_clear_locked()
            self.capture_rows, self.capture_meta, self.capture_calls_found = rows, metas, calls
            # the rows are the FIRST len(rows) packets of the file and are numbered from 1, as the service numbers
            # them; `truncated` is how the page learns the file holds more than the list does
            self.capture_total = len(rows)
            self.capture_first_no = 1
            self.capture_truncated = packets > len(rows)
            self.capture_bytes = size
            self.capture_first_ts = rows[0]["ts"] if rows else created
            self.capture_session = {
                "id": self.capture_next_id, "state": "loaded", "source": "file", "adapter": None, "file": text,
                "saved": True, "started_ts": created, "first_ts": self.capture_first_ts, "elapsed_s": 0.0,
                "packets": len(rows), "shown": len(rows), "bytes": size, "dropped": 0,
                "truncated": self.capture_truncated, "calls": len(calls), "stop_reason": None, "error": None,
                "ts": now}
            self.capture_next_id += 1
            snap = self._capture_session_locked()
        self.hub.publish("capture.state", {"session": snap})
        return snap

    def capture_open_path(self, path: Any) -> Dict[str, Any]:
        """POST /api/capture/open with ``{"path"}``: any capture file on this PC (tnt.capture.open_path).

        The mock checks the path the way the service does and then invents a capture named after the file, so the page
        can be driven without a real pcapng lying about; a path that does exist lends its real size."""
        text = (path if isinstance(path, str) else "" if path is None else str(path)).strip().strip('"')
        if (not text or "\x00" in text or len(text) > CAPTURE_MAX_PATH_LEN or not os.path.isabs(text)
                or text.startswith("\\\\")):
            raise ToolRefused(400, "bad_request", CAPTURE_PATH_TEXT)
        with self.lock:
            if self.capture_session is not None and self.capture_session["state"] == "capturing":
                raise ToolRefused(409, "conflict", CAPTURE_BUSY_TEXT)
        name = os.path.basename(text) or text
        try:
            size = os.path.getsize(text)
        except OSError:
            size = 512 * 1024
        if size > CAPTURE_MAX_OPEN_BYTES:
            raise ToolRefused(400, "bad_request", CAPTURE_PATH_BIG_TEXT.format(mb=CAPTURE_MAX_OPEN_BYTES // (1024 ** 2)))
        created = time.time() - 3600.0
        packets = max(1, min(CAPTURE_MAX_ROWS, size // 700))
        rows, metas, calls = capture_make_rows(int(packets), created, hash(text) & 0x7FFFFFFF)
        now = time.time()
        with self.lock:
            self.capture_stop_evt.set()
            self.capture_gen += 1
            self._capture_clear_locked()
            self.capture_rows, self.capture_meta, self.capture_calls_found = rows, metas, calls
            self.capture_total = len(rows)
            self.capture_first_no = 1
            self.capture_truncated = False
            self.capture_bytes = size
            self.capture_first_ts = rows[0]["ts"] if rows else created
            self.capture_session = {
                "id": self.capture_next_id, "state": "loaded", "source": "file", "adapter": None, "file": name,
                "saved": True, "started_ts": created, "first_ts": self.capture_first_ts, "elapsed_s": 0.0,
                "packets": len(rows), "shown": len(rows), "bytes": size, "dropped": 0,
                "truncated": False, "calls": len(calls), "stop_reason": None, "error": None, "ts": now}
            self.capture_next_id += 1
            snap = self._capture_session_locked()
        self.hub.publish("capture.state", {"session": snap})
        return snap

    def capture_packets(self, *, since: Any = None, limit: Any = None, ip: Any = None, mac: Any = None,
                        protos: Any = None) -> Dict[str, Any]:
        """GET /api/capture/packets (CAPTURE_PACKETS_KEYS), exactly as CaptureManager.packets answers it: without
        ``since`` the newest ``limit`` matching rows, with it the matching rows numbered after it, oldest first. A
        filter it cannot read is ignored, never refused."""
        count = capture_whole(limit, CAPTURE_ROW_LIMIT, 1, CAPTURE_MAX_ROW_LIMIT)
        want_ip, want_mac, keys = capture_norm_ip(ip), capture_norm_mac(mac), capture_proto_keys(protos)
        empty = not (want_ip or want_mac or keys)
        with self.lock:
            dropped_before = False
            if since is None:
                start = 0
            else:
                after = capture_whole(since, 0, 0, 1 << 62)
                dropped_before = after + 1 < self.capture_first_no and self.capture_total > 0
                start = max(0, after + 1 - self.capture_first_no)
            picked = []
            for index in range(start, len(self.capture_rows)):
                if empty or capture_matches(self.capture_rows[index], self.capture_meta[index]["layers"], want_ip,
                                            want_mac, keys):
                    picked.append(self.capture_rows[index])
            matched = len(picked)
            if since is None and len(picked) > count:
                picked = picked[-count:]
            elif len(picked) > count:
                picked = picked[:count]
            rows = [dict(r) for r in picked]
            last = rows[-1]["no"] if rows else (self.capture_first_no + len(self.capture_rows) - 1
                                                if self.capture_rows else 0)
            return {"rows": rows, "total": self.capture_total, "shown": len(self.capture_rows), "matched": matched,
                    "last": last, "dropped_before": dropped_before, "session": self._capture_session_locked()}

    def capture_packet(self, no: Any) -> Dict[str, Any]:
        """GET /api/capture/packets/{no} (CAPTURE_DETAIL_KEYS): the row, its detail tree, its hex dump and the bytes
        behind it; 404 when the list has already rolled past that number."""
        number = capture_whole(no, 0, 0, 1 << 62)
        with self.lock:
            index = number - self.capture_first_no
            if not 0 <= index < len(self.capture_rows):
                raise ToolRefused(404, "not_found", CAPTURE_PACKET_GONE_TEXT)
            row, meta = dict(self.capture_rows[index]), self.capture_meta[index]
        frame = capture_frame(row, meta["layers"], meta["payload"], meta["flags"], meta["icmp"])
        return {"row": row, "layers": capture_detail(row, meta["layers"], meta["fields"], frame),
                "hex": capture_hex(frame), "bytes": len(frame)}

    def capture_calls(self) -> List[Dict[str, Any]]:
        """GET /api/capture/calls: the SIP calls found in the open capture, newest first."""
        with self.lock:
            return list(reversed(copy.deepcopy(self.capture_calls_found)))

    def capture_call_audio(self, call_id: Any) -> bytes:
        """GET /api/capture/calls/{id}/audio: the call's RTP rebuilt as a WAV; 404 for a call that has none."""
        wanted = str(call_id or "")
        with self.lock:
            call = next((c for c in self.capture_calls_found if c["id"] == wanted), None)
        if call is None or not any(s["decodable"] for s in call["streams"]):
            raise ToolRefused(404, "not_found", CAPTURE_NO_AUDIO_TEXT)
        return capture_call_wav()

    def _capture_file_locked(self, name: str) -> Dict[str, Any]:
        row = next((f for f in self.capture_files if f["name"] == name), None) if _CAPTURE_FILE.fullmatch(name or "") else None
        if row is None:
            raise ToolRefused(404, "not_found", CAPTURE_FILE_MISSING_TEXT)
        return row

    def capture_download(self, name: str) -> bytes:
        """GET /api/capture/files/{name}: the saved capture (a tiny pcapng); 404 for a name that is not one."""
        with self.lock:
            return tiny_pcapng(self._capture_file_locked(name)["created_ts"])

    def capture_delete(self, name: str) -> List[Dict[str, Any]]:
        """DELETE /api/capture/files/{name}: the files left; 404 for a name that is not one. The capture that is open
        is thrown away with its file, as the service does."""
        with self.lock:
            row = self._capture_file_locked(name)
            open_now = self.capture_session is not None and self.capture_session.get("file") == row["name"]
            self.capture_files.remove(row)
            files = self._capture_files_locked()
        if open_now:
            self.capture_discard()
        return files

    # -- SIP (tnt.sipqual, tnt.sipalg, tnt.sipnat, tnt.sipflow) -----------------------------------
    def _sip_leg(self, kind: str, label: str, target: str, avg: float, jitter: float, loss: float,
                 samples: int, window_h: float) -> Dict[str, Any]:
        if samples < SIP_MIN_SAMPLES:
            # tnt.sipqual.grade_leg: too little history (a clear took it) is "unknown" with the reason, not a grade
            return {"kind": kind, "label": label, "target": target, "grade": "unknown", "mos": None, "r": None,
                    "call_label": None, "avg_ms": None, "jitter_ms": None, "loss_pct": None, "p95_ms": None,
                    "samples": samples, "window_h": window_h,
                    "reason": (f"only {samples} ping(s) of history on this network - "
                               f"{SIP_MIN_SAMPLES} are needed before this is worth grading")}
        grade = sip_grade(avg, jitter, loss)
        r, mos = sip_call_quality(avg, jitter, loss)
        return {"kind": kind, "label": label, "target": target, "grade": grade, "mos": mos, "r": r,
                "call_label": sip_call_label(r), "avg_ms": round(avg, 1), "jitter_ms": round(jitter, 1),
                "loss_pct": round(loss, 2), "p95_ms": round(avg * 1.8, 1), "samples": samples,
                "window_h": window_h, "reason": None}

    def sip_qualifier(self, window_h: float = 24.0, host: Optional[str] = None) -> Dict[str, Any]:
        """GET /api/sip/qualifier: the rating built out of this fake site's ping history and last speed test."""
        with self.lock:
            speed = self.speedtests[-1] if self.speedtests else None
            network_id = self.net_id
            profile = self.net_profile
            now = time.time()
            # the legs stand on the ping history of the window: what Clear history took of it is not behind them
            kept = self._recorded_fraction_locked(now - window_h * 3600.0, now) if self.history_spans else 1.0
        bad = profile in ("hotel", "hotspot")                # the awkward networks a tech is sent to
        # built from the ping targets this fake site really has, capped like the service caps them
        # (tnt.sipqual.pick_targets): a site with twenty targets must not get twenty leg cards
        legs, left_out, counts = [], 0, {"lan": 0, "wan": 0}
        for target in self.targets_view():
            if not target.get("enabled"):
                continue
            name = str(target.get("host") or "")
            if host and name.lower() == str(host).strip().lower():
                continue                     # the named SIP host is added below, whatever the cap
            kind = "lan" if target.get("kind") == "local" or name in GATEWAY_HOSTS else "wan"
            if counts[kind] >= SIP_MAX_LEGS_PER_KIND:
                left_out += 1
                continue
            counts[kind] += 1
            label = (f"The LAN leg ({name})" if kind == "lan" else f"The internet leg ({name})")
            lan = kind == "lan"
            legs.append(self._sip_leg(
                kind, label, name,
                (3.4 if lan else 21.0) if not bad else (26.0 if lan else 148.0),
                (0.6 if lan else 3.1) if not bad else (9.0 if lan else 44.0),
                (0.0 if lan else 0.05) if not bad else (0.4 if lan else 3.6),
                int((1380 if lan else 1376) * kept), window_h))
        if host:
            legs.append(self._sip_leg("sip", f"The path to {host}", host, 28.0 if not bad else 190.0,
                                      4.4 if not bad else 61.0, 0.1 if not bad else 5.2, int(640 * kept), window_h))
        legs.sort(key=lambda leg: ("lan", "wan", "sip").index(leg["kind"]))
        bloat = (((speed or {}).get("quality") or {}).get("bufferbloat") or {}).get("grade")
        return sip_build_qualifier(legs, window_h=window_h, sip_host=host, network_id=network_id,
                                   speedtest_ts=(speed or {}).get("ts"), bufferbloat=bloat, ts=time.time(),
                                   left_out=left_out)

    def sip_tile(self) -> Dict[str, Any]:
        """status.sip: the qualifier's verdict and each leg's grade, plus whatever the two checks last kept."""
        with self.lock:
            host = (self.settings.get("sip") or {}).get("host") or None
            alg = (self.sip_alg_last or {}).get("verdict")
            nat = (self.sip_stun_last or {}).get("mapping")
        rating = self.sip_qualifier(float((self.settings.get("sip") or {}).get("window_h") or 24), host)
        grades = {leg["kind"]: leg["grade"] for leg in rating["legs"]}
        head = rating["headline"]
        return {"available": True, "reason": None, "verdict": rating["verdict"], "lan": grades.get("lan"),
                "wan": grades.get("wan"), "sip": grades.get("sip"), "mos": head["mos"], "avg_ms": head["avg_ms"],
                "jitter_ms": head["jitter_ms"], "sip_host": host, "ts": rating["ts"], "alg": alg, "nat": nat}

    def sip_alg_view(self) -> Dict[str, Any]:
        with self.lock:
            return {"result": copy.deepcopy(self.sip_alg_last), "running": False}

    def sip_alg_run(self, host: Any, port: Any) -> Dict[str, Any]:
        """POST /api/sip/alg: the ALG check against the site's own PBX, in whichever state the fake network is in."""
        text = str(host or "").strip()
        if not text:
            raise ToolRefused(400, "bad_request", "give the address of your PBX, SBC or registrar")
        number = 5060
        if port not in (None, "", 0):
            try:
                number = int(port)
            except (TypeError, ValueError):
                raise ToolRefused(400, "bad_request", "a SIP port is a number between 1 and 65535") from None
            if not 1 <= number <= 65535:
                raise ToolRefused(400, "bad_request", "a SIP port is a number between 1 and 65535")
        with self.lock:
            state = self.sip_alg_state
        result = sip_alg_result(text, number, state)
        with self.lock:
            self.sip_alg_last = copy.deepcopy(result)
        return result

    def sip_stun_view(self) -> Dict[str, Any]:
        with self.lock:
            return {"result": copy.deepcopy(self.sip_stun_last), "running": False}

    def sip_stun_run(self, servers: Any = None) -> Dict[str, Any]:
        """POST /api/sip/stun: both servers asked from one socket, and what the difference says."""
        wanted = []
        for entry in (servers or SIP_STUN_SERVERS):
            pair = entry if isinstance(entry, (list, tuple)) else (entry, None)
            name = str(pair[0] or "").strip()
            if not name:
                raise ToolRefused(400, "bad_request", "give a STUN server's address")
            wanted.append((name, int(pair[1]) if len(pair) > 1 and pair[1] else 3478))
        with self.lock:
            state = self.sip_nat_state
        result = sip_stun_result(wanted, state)
        with self.lock:
            self.sip_stun_last = copy.deepcopy(result)
        return result

    def sip_stun_lifetime(self, server: Any = None) -> Dict[str, Any]:
        """POST /api/sip/stun/lifetime: the slow one, which is why the page keeps it behind its own button."""
        pair = server if isinstance(server, (list, tuple)) else (server or SIP_STUN_SERVERS[0][0],
                                                                 SIP_STUN_SERVERS[0][1])
        with self.lock:
            state = self.sip_nat_state
        return sip_lifetime_result(str(pair[0]), int(pair[1] or 3478), state)

    def sip_flow_view(self) -> Dict[str, Any]:
        with self.lock:
            slots = sorted(self.sip_flow_slots)
        return sip_flow(slots)

    def sip_flow_open(self, path: Any, slot: Any) -> Dict[str, Any]:
        """POST /api/sip/flow: read a capture into slot a or b.  Any path is accepted here - the point of the mock
        is the merged view, not the file system."""
        text = str(path or "").strip()
        which = str(slot or "a")
        if which not in ("a", "b"):
            raise ToolRefused(400, "bad_request", f"a capture goes in slot a or b, not {which!r}")
        if not text:
            raise ToolRefused(400, "bad_request", "give the full path of a capture file")
        if not (text[1:3] == ":\\" or text.startswith("\\\\") or text.startswith("/")):
            raise ToolRefused(400, "bad_request", "give the full path of a capture file, not a relative one")
        if not text.lower().endswith((".pcap", ".pcapng", ".cap")):
            raise ToolRefused(400, "bad_request", "that capture could not be opened (not a capture file)")
        with self.lock:
            self.sip_flow_slots.add(which)
            self.sip_flow_loaded[which] = time.time()
            self.sip_flow_files[which] = re.split(r"[\\/]", text)[-1]
        return self.sip_flow_view()

    def sip_flow_close(self, slot: Any = None) -> Dict[str, Any]:
        with self.lock:
            if slot:
                self.sip_flow_slots.discard(str(slot))
                self.sip_flow_loaded.pop(str(slot), None)
                self.sip_flow_files.pop(str(slot), None)
            else:
                self.sip_flow_slots.clear()
                self.sip_flow_loaded.clear()
                self.sip_flow_files.clear()
        return self.sip_flow_view()

    def sip_flow_call(self, call_id: Any) -> Dict[str, Any]:
        wanted = str(call_id or "")
        for call in self.sip_flow_view()["calls"]:
            if call["id"] == wanted or wanted in (call["call_ids"] or []):
                return call
        raise ToolRefused(404, "not_found", "that call is not in the captures that are loaded")

    def sip_flow_headers(self, side: Any, number: Any) -> Dict[str, Any]:
        """GET /api/sip/flow/packets/{side}/{no}: every header of the packet a ladder row points at."""
        try:
            no = int(number)
        except (TypeError, ValueError):
            raise ToolRefused(400, "bad_request", "a packet number is a whole number") from None
        which = str(side or "a")
        for call in self.sip_flow_view()["calls"]:
            for row in call["ladder"]:
                if row["side"] == which and row["where"] == no:
                    return sip_header_view(call, row)
        raise ToolRefused(404, "not_found", "that packet is not in the captures that are loaded")

    def sip_flow_audio(self, call_id: Any, side: Any = None, stream: Any = None) -> bytes:
        call = self.sip_flow_call(call_id) if not stream else None
        if stream:
            for row in self.sip_flow_view()["calls"]:
                if any(s["id"] == str(stream) for s in row["streams"]):
                    call = row
                    break
        if call is None or not any(s["decodable"] for s in call["streams"]):
            raise ToolRefused(404, "not_found", "there is no audio in that call TNT can decode")
        return capture_call_wav()

    def sip_set_state(self, alg: Any = None, nat: Any = None) -> Dict[str, Any]:
        """POST /mock/sip: move the fake network between the states the page has to show well."""
        with self.lock:
            if alg is not None:
                if str(alg) not in SIP_ALG_STATES:
                    raise ToolRefused(400, "bad_request", f"alg is one of {', '.join(SIP_ALG_STATES)}")
                self.sip_alg_state = str(alg)
                self.sip_alg_last = None
            if nat is not None:
                if str(nat) not in SIP_NAT_STATES:
                    raise ToolRefused(400, "bad_request", f"nat is one of {', '.join(SIP_NAT_STATES)}")
                self.sip_nat_state = str(nat)
                self.sip_stun_last = None
            return {"alg": self.sip_alg_state, "nat": self.sip_nat_state,
                    "alg_states": list(SIP_ALG_STATES), "nat_states": list(SIP_NAT_STATES)}

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
                base = REPORT_SPEED_STEPS.get(prog.get("phase"), (0.0, 0.0))
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
            tftp = new.setdefault("tftp", {})          # like tnt.config: the cap truncated and clamped (4096 for junk), the name trimmed
            try:
                mb = tftp.get("max_upload_mb", 4096)
                tftp["max_upload_mb"] = 4096 if isinstance(mb, bool) else max(TFTP_MAX_UPLOAD_MB[0], min(TFTP_MAX_UPLOAD_MB[1], int(float(mb))))
            except (TypeError, ValueError, OverflowError):
                tftp["max_upload_mb"] = 4096
            tftp["adapter"] = str(tftp["adapter"]).strip() if tftp.get("adapter") is not None else ""
            new["ping"]["loaded"] = bool(new["ping"]["loaded"])
            changed = changed_keys(old, new)
            self.settings = new
            snap = copy.deepcopy(new)
        if changed:
            self.hub.publish("settings.changed", {"changed": changed})
        if "geoip.enabled" in changed:
            self.hub.publish("geoip.state", self.geoip_status())
        return {"settings": snap, "changed": changed}

    # -- realtime throughput (Network info) ------------------------------
    def _tp_adapters(self) -> List[Dict[str, Any]]:
        """The up, non-loopback adapters of the network the fake PC is on - what tnt.throughput's
        eligibility test leaves once the filter interfaces and loopback are dropped."""
        prof = net_profile(self.net_profile)
        return [a for a in prof["adapters"] if a.get("status") == "up" and not a.get("is_loopback")]

    def _tp_row(self, a: Dict[str, Any], idx: int, primary: Any, tot: Dict[str, int],
                buf: List[List[int]]) -> Dict[str, Any]:
        """One NIC row of the event: everything except the series and the window figures."""
        last = buf[-1] if buf else [0, 0, 0, 0, 0]
        return {"id": str(1689399632855040 + idx * 65536), "index": idx, "name": a.get("name") or "",
                "description": a.get("description") or "", "type": a.get("type_name") or "Other",
                "primary": idx == primary, "link_bps": a.get("speed_bps"),
                "rx_bps": last[1], "tx_bps": last[2], "rx_pps": last[3], "tx_pps": last[4],
                "rx_bytes": tot["rx_bytes"], "tx_bytes": tot["tx_bytes"],
                "rx_packets": tot["rx_packets"], "tx_packets": tot["tx_packets"]}

    def _tp_excluded(self) -> "set":
        """tnt.throughput.ThroughputMonitor._excluded: the names throughput.excluded leaves out."""
        names = (self.settings.get("throughput") or {}).get("excluded") or []
        return {n.strip().casefold() for n in names if isinstance(n, str) and n.strip()}

    def throughput_tick(self, ts: float) -> Dict[str, Any]:
        """Advance every adapter's counters by a second and publish the throughput.sample event."""
        rows = []
        with self.lock:
            excluded = self._tp_excluded()
            prof = net_profile(self.net_profile)
            primary = prof["internet_nic_index"]
            live = set()
            for a in self._tp_adapters():
                idx = int(a["index"])
                live.add(idx)
                rx_bps, tx_bps = tp_rate(str(a.get("name") or ""), ts)
                rx_pps = rx_bps // (8 * TP_RX_FRAME)
                tx_pps = tx_bps // (8 * TP_TX_FRAME)
                tot = self.tp_totals.get(idx)
                if tot is None:
                    # a machine that has been up a while, so the Control Panel figures are not all zeros
                    tot = {"rx_bytes": 1_000_000 * (idx * 37 + 11), "tx_bytes": 250_000 * (idx * 29 + 7),
                           "rx_packets": 900 * (idx * 37 + 11), "tx_packets": 780 * (idx * 29 + 7)}
                    self.tp_totals[idx] = tot
                tot["rx_bytes"] += rx_bps // 8
                tot["tx_bytes"] += tx_bps // 8
                tot["rx_packets"] += rx_pps
                tot["tx_packets"] += tx_pps
                buf = self.tp_samples.setdefault(idx, [])
                buf.append([int(ts), rx_bps, tx_bps, rx_pps, tx_pps])
                if len(buf) > TP_HISTORY_S:
                    del buf[: len(buf) - TP_HISTORY_S]
                # still sampled, just not reported: unticking the box brings the history back
                if str(a.get("name") or "").strip().casefold() not in excluded:
                    rows.append(self._tp_row(a, idx, primary, tot, buf))
            for idx in [i for i in self.tp_samples if i not in live]:
                # the adapter went away with a network change: its history goes with it
                self.tp_samples.pop(idx, None)
                self.tp_totals.pop(idx, None)
        rows.sort(key=_tp_order)
        event = {"ts": ts, "nics": rows}
        self.hub.publish("throughput.sample", event)
        return event

    def throughput(self, window_s: Any = TP_DEFAULT_WINDOW_S) -> Dict[str, Any]:
        """GET /api/throughput: the backlog for one window (tnt.throughput.ThroughputMonitor.view)."""
        try:
            want = int(float(window_s))
        except (TypeError, ValueError):
            want = TP_DEFAULT_WINDOW_S
        window = want if want in TP_WINDOWS else min(TP_WINDOWS, key=lambda w: (abs(w - want), w))
        step = max(1, int(math.ceil(window / float(TP_MAX_POINTS))))
        now = time.time()
        floor = now - window
        keep: List[Dict[str, Any]] = []
        every: List[Dict[str, Any]] = []
        with self.lock:
            prof = net_profile(self.net_profile)
            primary = prof["internet_nic_index"]
            excluded = self._tp_excluded()
            for a in self._tp_adapters():
                idx = int(a["index"])
                tot = self.tp_totals.get(idx)
                if tot is None:
                    continue                     # nothing sampled yet: the ticker has not reached it
                if str(a.get("name") or "").strip().casefold() in excluded:
                    continue                     # before anything else: the fallback must not bring it back
                buf = self.tp_samples.get(idx) or []
                window_rows = [s for s in buf if s[0] >= floor]
                row = self._tp_row(a, idx, primary, tot, buf)
                row["samples"] = _tp_bucket(window_rows, step)
                row["avg_rx_bps"] = _tp_mean(window_rows, 1)
                row["avg_tx_bps"] = _tp_mean(window_rows, 2)
                row["peak_rx_bps"] = max((s[1] for s in window_rows), default=0)
                row["peak_tx_bps"] = max((s[2] for s in window_rows), default=0)
                every.append(row)
                if row["primary"] or any(s[1] or s[2] for s in window_rows):
                    keep.append(row)
        if not keep:
            keep = every
        keep.sort(key=_tp_order)
        return {"ts": now, "window_s": window, "step_s": step, "history_s": TP_HISTORY_S,
                "windows": list(TP_WINDOWS), "nics": keep, "note": None}

    # -- faults: the passive watch --------------------------------------------
    def _fault_nics(self, now: float) -> List[Dict[str, Any]]:
        """One row per up adapter: what it has done since the fake watch started."""
        watched = max(0.0, now - self.faults_since)
        window = min(watched, FAULT_RATE_WINDOW_S)
        rows = []
        for a in self._tp_adapters():
            name = str(a.get("name") or "")
            idx = int(a["index"])
            buf = self.tp_samples.get(idx) or []
            rx_packets, tx_packets = sum(s[3] for s in buf), sum(s[4] for s in buf)
            recent = [s for s in buf if s[0] >= now - window]
            recent_rx, recent_tx = sum(s[3] for s in recent), sum(s[4] for s in recent)
            errors = int(watched * FAULT_ERROR_RATE) if name == FAULT_ERROR_NIC else 0
            discards = int(watched * FAULT_DISCARD_RATE) if name == FAULT_DISCARD_NIC else 0
            # inbound discards, which a healthy PC racks up all day and the service never judges
            inbound = int(watched * 6.5) if name == FAULT_DISCARD_NIC else 0
            row = {"name": name, "description": a.get("description") or "", "index": idx,
                   "link_bps": a.get("speed_bps"), "watched_s": round(watched, 1),
                   # every fake adapter is up and was read on the last tick
                   "up": True, "last_read_s": round(min(watched, 5.0) * 0.4, 1),
                   "rx_errors": errors + 27, "tx_errors": 0,
                   "rx_discards": inbound + 154_426, "tx_discards": discards + 12,
                   "new_rx_errors": errors, "new_tx_errors": 0,
                   "new_rx_discards": inbound, "new_tx_discards": discards,
                   "new_rx_packets": rx_packets, "new_tx_packets": tx_packets,
                   "error_pct": None, "discard_pct": None, "window_s": round(window, 1),
                   "recent_rx_errors": int(window * FAULT_ERROR_RATE) if errors else 0, "recent_tx_errors": 0,
                   "recent_rx_discards": int(window * 6.5) if inbound else 0,
                   "recent_tx_discards": int(window * FAULT_DISCARD_RATE) if discards else 0,
                   "recent_rx_packets": recent_rx, "recent_tx_packets": recent_tx}
            # tnt.faults: errors of every frame carried (Windows counts the damaged and the dropped
            # ones apart from the packets), discards of every frame queued to send
            frames = rx_packets + tx_packets + errors + inbound + discards
            if frames:
                row["error_pct"] = 100.0 * errors / frames
            if tx_packets + discards:
                row["discard_pct"] = 100.0 * discards / (tx_packets + discards)
            rows.append(row)
        rows.sort(key=lambda r: r["name"])
        return rows

    def fault_findings(self, now: float) -> List[Dict[str, Any]]:
        """What the fake watch has found: one bad lead, and congestion on the way out of the internet NIC,
        both judged on the recent window like the service (FAULT_RATE_WINDOW_S)."""
        watched = max(0.0, now - self.faults_since)
        nics = self._fault_nics(now)
        out: List[Dict[str, Any]] = []
        if watched < FAULT_MIN_WATCH_S:
            return [{"id": "fault.watching", "level": "info", "title": "Watching",
                     "detail": f"Nothing wrong so far. The adapter counters need 60 seconds of watching "
                               f"before they mean anything, and TNT has been here {int(watched)} seconds.",
                     "advice": "Nothing to do. This checks itself, from the moment the service starts.",
                     "evidence": None}]
        span = (f"in the {_fault_duration(watched)} since TNT started watching" if watched <= FAULT_RATE_WINDOW_S
                else f"in the last {_fault_duration(FAULT_RATE_WINDOW_S)}")
        # the service needs FAULT_MIN_PACKETS before it will judge a ratio; without any traffic
        # there is no percentage to quote, and no finding to make
        frames = {n["name"]: n["recent_rx_packets"] + n["recent_tx_packets"] + n["recent_rx_errors"]
                  + n["recent_rx_discards"] + n["recent_tx_discards"] for n in nics}
        bad = next((n for n in nics if n["recent_rx_errors"] and frames[n["name"]]), None)
        if bad:
            pct = 100.0 * bad["recent_rx_errors"] / frames[bad["name"]]
            out.append({"id": "fault.errors", "level": "bad",
                        "title": f"{bad['name']} is seeing frame errors",
                        "detail": f"{bad['recent_rx_errors']:,} arriving damaged out of {frames[bad['name']]:,} "
                                  f"frames {span} - {pct:.3g}% of them. These are frames the adapter received "
                                  "damaged, not frames dropped because the link was busy.",
                        "advice": "On a switched link this should be flat zero. Re-seat both ends of the cable "
                                  "and try a known good patch lead first; if it stays, suspect the run itself, "
                                  "the socket, or a duplex mismatch with the switch port.",
                        "evidence": [{"name": bad["name"], "rx_errors": bad["recent_rx_errors"],
                                      "tx_errors": 0, "pct": round(pct, 4), "level": "bad"}]})
        queued = {n["name"]: n["recent_tx_packets"] + n["recent_tx_discards"] for n in nics}
        busy = next((n for n in nics if n["recent_tx_discards"] and queued[n["name"]]
                     and 100.0 * n["recent_tx_discards"] / queued[n["name"]] >= 0.5), None)
        if busy:
            pct = 100.0 * busy["recent_tx_discards"] / queued[busy["name"]]
            level = "bad" if pct >= 5.0 else "warn"
            out.append({"id": "fault.discards", "level": level,
                        "title": f"{busy['name']} is dropping frames it could not send",
                        "detail": f"{busy['recent_tx_discards']:,} of the {queued[busy['name']]:,} frames this "
                                  f"PC queued to send {span} were discarded before they left - {pct:.3g}%. Nothing "
                                  "here is damaged: the adapter's send queue was full, or the link went down while "
                                  "they waited in it.",
                        "advice": "This is congestion on the way out, not a fault in the cable. Check what is "
                                  "saturating the link on the Realtime throughput card.",
                        "evidence": [{"name": busy["name"], "tx_discards": busy["recent_tx_discards"],
                                      "tx_packets": busy["recent_tx_packets"], "pct": round(pct, 4),
                                      "level": level}]})
        if not out and self.faults_reason:
            out.append({"id": "fault.clean", "level": "info", "title": "No faults found in what could be read",
                        "detail": f"The rest could not be read on the last look ({self.faults_reason}), so it "
                                  "was not checked.",
                        "advice": "The service log says which call failed.", "evidence": None})
        if not out:
            out.append({"id": "fault.clean", "level": "good", "title": "No faults found",
                        "detail": f"In the {_fault_duration(watched)} TNT has been watching: no frame errors, "
                                  "no frames dropped on the way out, every adapter addressed properly, and no "
                                  "address answered by two devices.",
                        "advice": "Nothing to do.", "evidence": None})
        return out

    def faults_view(self) -> Dict[str, Any]:
        """GET /api/faults (tnt.faults.FaultWatcher.view)."""
        now = time.time()
        with self.lock:
            findings = self.fault_findings(now)
            return {"ts": now, "watching_since": self.faults_since,
                    "watched_s": round(max(0.0, now - self.faults_since), 1),
                    "level": _fault_worst(findings), "findings": findings,
                    "nics": self._fault_nics(now),
                    "arp": {"tracked": 23, "conflicts": [], "window_s": 120.0,
                            "gateway": net_profile(self.net_profile)["default_gateway"]},
                    "note": self.faults_reason}

    def faults_tile(self) -> Dict[str, Any]:
        """status.faults (tnt.faults.FaultWatcher.tile)."""
        now = time.time()
        with self.lock:
            findings = self.fault_findings(now)
        level = _fault_worst(findings)
        watched = round(max(0.0, now - self.faults_since), 1)
        return {"available": True, "reason": self.faults_reason, "level": level,
                "bad": sum(1 for f in findings if f["level"] == "bad"),
                "warn": sum(1 for f in findings if f["level"] == "warn"),
                "headline": findings[0]["title"] if findings else "No faults found",
                # the fake watch is either clean from the start or not clean at all
                "watched_s": watched, "clean_s": watched if level == "good" else None, "ts": now}

    def faults_tick(self) -> None:
        """Publish faults.state when the level changes, exactly as the service does."""
        tile = self.faults_tile()
        if tile["level"] != self.faults_level:
            self.faults_level = tile["level"]
            self.hub.publish("faults.state", tile)

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
            # the network tools: the NAT, switch port and port-forward results described the old network, a switch port search
            # whose adapter went away is cancelled (a new network alone does not cancel one), a running TFTP server stops
            self.nat_last, self.portcheck_last = None, None
            self.nat_epoch += 1
            job = self.switch_job
            switch_changed = bool(self.switch_kept) or (job is not None and job["state"] != "listening")
            self.switch_kept = {}
            if job is not None and job["state"] != "listening":
                self.switch_job = None
            elif job is not None and job["adapter"]["mac"] not in {a["mac"] for a in self._wired_adapters(new)}:
                self.switch_gen += 1
                job.update(state="cancelled", ts=now)
                switch_changed = True
            tftp_stopped = self.tftp_running
            if tftp_stopped:
                self.tftp_error = TFTP_STOPPED_TEXT
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
        if switch_changed:
            with self.lock:
                snap = self._switch_job_locked()
            self.hub.publish("netcheck.switch", {"job": snap})
        if tftp_stopped:
            self.tftp_stop()
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
        tools = {name: self.settings.get("tools", {}).get(name, True) is not False for name in TOOLS}
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
                    "speed": self.speed_status() if tools.get("speed", True) else None,
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
                    "update": self.update_status(),
                    "tftp": self.tftp_summary(),
                    # the Packet capture tile's numbers (the page itself reads /api/capture)
                    "capture": self.capture_tile() if tools.get("capture", True) else None,
                    "proav": self.proav_tile() if tools.get("proav", True) else None,
                    # the SIP tile: the verdict, each leg and whatever the ALG and STUN checks last kept.
                    # A tool that is off gets null rather than a block, like the service.
                    "sip": self.sip_tile() if tools.get("sip", True) else None,
                    "faults": self.faults_tile(),
                    "tools": tools,
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

    def _json(self, payload: Any, status: int = 200, headers: Optional[Dict[str, str]] = None) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
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
                if not STATE.wifi_admin and frame.split("\n", 1)[0][7:] in ADMIN_ONLY_EVENTS:
                    continue                    # the service sends the capture job to a Windows administrator only
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

    def _need_tool(self, name: str) -> None:
        """Refuse when a main tool is switched off (tnt.api.routes._need_tool): 409, because the route exists
        and works again the moment the toggle goes back on."""
        if STATE.settings.get("tools", {}).get(name, True) is not False:
            return
        label = {"speed": "Speed", "discovery": "Discovery", "wifi": "WiFi", "capture": "Packet capture",
                 "proav": "Pro AV", "sip": "SIP"}.get(name, name)
        raise ToolRefused(409, "tool_off", f"The {label} tool is switched off in Settings")

    def _capture_admin(self) -> None:
        """Every packet capture route, after the origin check: the service's 403 for a standard user (STATE.wifi_admin off)."""
        if not STATE.wifi_admin:
            raise ToolRefused(403, "admin_required", CAPTURE_ADMIN_REQUIRED_MSG)

    def _sip_audio(self, call_id: str, side: Optional[str], stream: Optional[str]) -> None:
        """One call (or one RTP direction) from the loaded captures, as the service sends its FileResponse."""
        wav = STATE.sip_flow_audio(call_id, side, stream)
        safe = "".join(c for c in (stream or call_id) if c.isalnum() or c in "-_")[:64] or "call"
        self.send_response(200)
        self.send_header("Content-Type", "audio/wav")
        self.send_header("Content-Length", str(len(wav)))
        self.send_header("Content-Disposition", f'attachment; filename="TNT-{safe}.wav"')
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(wav)

    def _capture_audio(self, call_id: str) -> None:
        """One SIP call rebuilt as a WAV, as the service sends its FileResponse: audio/wav of its length, playable in
        the page (the call is looked up before any header goes out, so an unknown one is a clean 404)."""
        wav = STATE.capture_call_audio(call_id)
        safe = "".join(c for c in call_id if c.isalnum() or c in "-_")[:64] or "call"
        self.send_response(200)
        self.send_header("Content-Type", "audio/wav")
        self.send_header("Content-Length", str(len(wav)))
        self.send_header("Content-Disposition", f'attachment; filename="TNT-call-{safe}.wav"')
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(wav)

    def _capture_file(self, name: str) -> None:
        """A saved capture as the service sends a FileResponse: an attachment of its length, not cached, not sniffed (the name is
        checked against CAPTURE_FILE_RE before any header goes out)."""
        data = STATE.capture_download(name)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

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
        except ToolRefused as exc:
            self._json(exc.payload(), exc.status, exc.headers)
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
            if path == "/mock/update" and method in ("GET", "POST"):
                # development only: GET the fake auto-update state, POST {"state": ...} picks another
                if method == "POST":
                    return self._json({"state": STATE.update_set_state(str(self._body().get("state") or ""))})
                with STATE.lock:
                    return self._json({"state": STATE.update_state, "states": list(UPDATE_STATES)})
            if path == "/mock/sip" and method in ("GET", "POST"):
                # development only: GET what the fake network does to SIP and to a NAT mapping, POST {"alg", "nat"} picks
                if method == "POST":
                    body = self._body()
                    return self._json(STATE.sip_set_state(body.get("alg"), body.get("nat")))
                return self._json(STATE.sip_set_state())
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

        if method == "PATCH" and len(parts) == 2 and parts[0] == "targets":
            # set or clear a target's custom name (tnt.api.routes rename_target)
            view = STATE.set_target_name(int(parts[1]), self._body().get("name"))
            return self._json(view) if view is not None else self._error(404, "not_found", "no such target")

        if method == "GET":
            if p == "/health":
                return self._json({"ok": True})
            if p == "/status":
                STATE.note_status_request()
                return self._json(STATE.status())
            if p == "/netinfo":
                return self._json(STATE.netinfo())
            if p == "/throughput":
                return self._json(STATE.throughput(qs.get("window_s")))
            if p == "/faults":
                return self._json(STATE.faults_view())
            if p == "/geoip":
                return self._json(STATE.geoip_status())
            if p == "/update":
                return self._json(STATE.update_status())
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
            if p == "/history":
                return self._json(STATE.history_info())
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
            if p == "/netcheck/nat":
                return self._json(STATE.nat_view())
            if p == "/netcheck/switch":
                return self._json(STATE.switch_status())
            if p == "/tftp/status":
                return self._json(STATE.tftp_status())
            if p == "/tftp/files":
                return self._json({"files": STATE.tftp_files()})
            if p == "/proav":
                return self._json(STATE.proav_status())
            if p == "/proav/result":
                return self._json({"result": STATE.proav_last()})
            if p == "/capture":
                self._capture_admin()
                return self._json(STATE.capture_status())
            if p == "/capture/packets":
                # every value of every "proto" parameter, repeated and/or comma separated (qs keeps only the last one)
                self._capture_admin()
                protos = [x for raw in parse_qs(url.query).get("proto", []) for x in str(raw).split(",") if x.strip()]
                return self._json(STATE.capture_packets(since=qs.get("since"), limit=qs.get("limit"), ip=qs.get("ip"),
                                                        mac=qs.get("mac"), protos=protos))
            if len(parts) == 3 and parts[0] == "capture" and parts[1] == "packets":
                self._capture_admin()
                return self._json(STATE.capture_packet(unquote(parts[2])))
            if p == "/capture/calls":
                self._capture_admin()
                return self._json({"calls": STATE.capture_calls()})
            if len(parts) == 4 and parts[0] == "capture" and parts[1] == "calls" and parts[3] == "audio":
                self._capture_admin()
                return self._capture_audio(unquote(parts[2]))
            if network_tool_route(p) and p.startswith(CAPTURE_FILES_ROUTE):
                # the download, like the service: a page of another origin is refused first, then anyone but an administrator
                if cross_origin_browser_request(self.headers, STATE.port):
                    return self._error(403, "forbidden", QUICK_TOOLS_CROSS_ORIGIN_MSG)
                self._capture_admin()
                return self._capture_file(unquote(p[len(CAPTURE_FILES_ROUTE):]))
            if p == "/sip/qualifier":
                return self._json({"rating": STATE.sip_qualifier(float(qf("hours", 24.0) or 24.0),
                                                                 (qs.get("host") or "").strip() or None)})
            if p == "/sip/alg":
                return self._json(STATE.sip_alg_view())
            if p == "/sip/stun":
                return self._json(STATE.sip_stun_view())
            if p == "/sip/flow":
                return self._json({"flow": STATE.sip_flow_view()})
            if len(parts) == 4 and parts[:2] == ["sip", "flow"] and parts[2] == "calls":
                return self._json({"call": STATE.sip_flow_call(unquote(parts[3]))})
            if len(parts) == 5 and parts[:2] == ["sip", "flow"] and parts[2] == "calls" and parts[4] == "audio":
                return self._sip_audio(unquote(parts[3]), qs.get("side"), qs.get("stream"))
            if len(parts) == 5 and parts[:3] == ["sip", "flow", "packets"]:
                return self._json({"packet": STATE.sip_flow_headers(unquote(parts[3]), unquote(parts[4]))})
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
            if p == "/history/clear":
                # like the service: a page of another origin is refused first (a clear deletes history and capture
                # files); anything but a {"range": key} object is 400 bad_range; captures need an administrator, the
                # rest clears without one
                if cross_origin_browser_request(self.headers, STATE.port):
                    return self._error(403, "forbidden", QUICK_TOOLS_CROSS_ORIGIN_MSG)
                if getattr(self, "_raw_body", None) is None:
                    self._consume_body()
                try:
                    body = json.loads((self._raw_body or b"").decode("utf-8") or "null")
                except (ValueError, UnicodeDecodeError):
                    body = None
                if not isinstance(body, dict):
                    return self._error(400, "bad_range", HISTORY_BAD_RANGE_MSG)
                return self._json(STATE.history_clear(body.get("range"), captures_allowed=STATE.wifi_admin))
            if p == "/sip/alg":
                self._need_tool("sip")
                body = self._body()
                return self._json({"result": STATE.sip_alg_run(body.get("host"), body.get("port")),
                                   "running": False})
            if p == "/sip/stun":
                self._need_tool("sip")
                return self._json({"result": STATE.sip_stun_run(self._body().get("servers")), "running": False})
            if p == "/sip/stun/lifetime":
                self._need_tool("sip")
                return self._json({"result": STATE.sip_stun_lifetime(self._body().get("server"))})
            if p == "/sip/flow":
                self._need_tool("sip")
                body = self._body()
                return self._json({"flow": STATE.sip_flow_open(body.get("path"), body.get("slot"))})
            if p == "/targets":
                body = self._body()
                view = STATE.add_target(str(body.get("host", "")), body.get("label"))
                return self._json(view, 201)
            if p == "/targets/defaults":
                return self._json(STATE.load_defaults())
            if p == "/speedtests/run":
                self._need_tool("speed")
                if not STATE.speed_run():
                    return self._error(409, "conflict", "a speed test is already running")
                return self._json({"started": True})
            if p == "/discovery/scan":
                self._need_tool("discovery")
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
            if p == "/update/check":
                if not STATE._update_enabled():
                    return self._error(409, "conflict", "Automatic updates are switched off")
                return self._json(STATE.update_check())
            if p == "/update/install":
                # like the service: a browser page of another origin is refused first, then anyone but an administrator
                if cross_origin_browser_request(self.headers, STATE.port):
                    return self._error(403, "forbidden", QUICK_TOOLS_CROSS_ORIGIN_MSG)
                if not STATE.wifi_admin:
                    return self._error(403, "admin_required", UPDATE_ADMIN_REQUIRED_MSG)
                with STATE.lock:
                    off = not STATE._update_enabled()
                    has = STATE.update_state in ("available", "ready")
                if off:
                    return self._error(409, "conflict", "Automatic updates are switched off")
                if not has:
                    return self._error(409, "conflict", "No update is available to install")
                return self._json(STATE.update_install())
            if p == "/tools/lan/throughput":
                try:
                    return self._json(STATE.lan_throughput(self._body()))
                except RuntimeError as exc:
                    return self._error(409, "conflict", str(exc))
            if (p in NETTOOLS_ROUTES or network_tool_route(p)) and cross_origin_browser_request(self.headers, STATE.port):
                # like the service: a browser page of another origin may not run the network tools
                return self._error(403, "forbidden", QUICK_TOOLS_CROSS_ORIGIN_MSG)
            if p == "/netcheck/nat":
                return self._json({"result": STATE.nat_run(), "running": False})
            if p == "/netcheck/switch":
                body = self._body()
                return self._json({"job": STATE.switch_start(body.get("adapter"), body.get("seconds"))})
            if p == "/netcheck/portforward":
                return self._json(STATE.portcheck_test(self._body().get("port")))
            if p == "/proav/scan":
                self._need_tool("proav")
                try:
                    return self._json({"job": STATE.proav_start(self._body())})
                except LookupError as exc:
                    return self._error(409, "unavailable", str(exc))
                except ValueError as exc:
                    return self._error(400, "bad_request", str(exc))
                except RuntimeError as exc:
                    return self._error(409, "conflict", str(exc))
            if p == "/proav/cancel":
                return self._json({"cancelled": STATE.proav_cancel(), "job": STATE.proav_status()["job"]})
            if p == "/capture/start":
                self._need_tool("capture")
                self._capture_admin()
                return self._json({"session": STATE.capture_start(self._body())})
            if p == "/capture/stop":
                self._capture_admin()
                return self._json({"session": STATE.capture_stop()})
            if p == "/capture/save":
                self._capture_admin()
                return self._json(STATE.capture_save())
            if p == "/capture/discard":
                self._capture_admin()
                STATE.capture_discard()
                return self._json({"session": None})
            if p == "/capture/open":
                self._capture_admin()
                body = self._body()
                if body.get("path") is not None:
                    return self._json({"session": STATE.capture_open_path(body.get("path"))})
                if body.get("name") is None:
                    raise ToolRefused(400, "bad_request",
                                      "give a saved capture's name, or the path of a file on this PC")
                return self._json({"session": STATE.capture_open(body.get("name"))})
            if p == "/tftp/start":
                return self._json(STATE.tftp_start(self._body()))
            if p == "/tftp/stop":
                return self._json(STATE.tftp_stop())
            if p == "/tftp/uploads":
                return self._json(STATE.tftp_set_uploads(self._body().get("on")))
            if p == "/tools/dns/lookup":
                return self._json(STATE.dns_lookup(self._body()))      # a bad name or server: ValueError -> 400 in _handle
            if p == "/tools/dns/flush":
                return self._json(STATE.dns_flush())
            if p == "/tools/ip/renew":
                if not STATE.wifi_admin:
                    return self._error(403, "admin_required", IP_RENEW_ADMIN_REQUIRED_MSG)
                try:
                    return self._json(STATE.ip_renew())
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
            if network_tool_route(p) and cross_origin_browser_request(self.headers, STATE.port):
                return self._error(403, "forbidden", QUICK_TOOLS_CROSS_ORIGIN_MSG)
            if p == "/tftp/settings":
                return self._json(STATE.tftp_update_settings(self._body()))
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
            if network_tool_route(p) and cross_origin_browser_request(self.headers, STATE.port):
                return self._error(403, "forbidden", QUICK_TOOLS_CROSS_ORIGIN_MSG)
            if p == "/sip/flow":
                return self._json({"flow": STATE.sip_flow_close(qs.get("slot"))})
            if p == "/netcheck/switch":
                return self._json({"job": STATE.switch_stop()})
            if network_tool_route(p) and p.startswith(CAPTURE_FILES_ROUTE):
                self._capture_admin()
                return self._json({"files": STATE.capture_delete(unquote(p[len(CAPTURE_FILES_ROUTE):]))})
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
            STATE.throughput_tick(float(nxt))
            STATE.faults_tick()
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
