"""Node-driver tests for the pure helpers of the 1.15.0 UI modules: the Network info "NAT, switch port & port forward" card
(ui/js/netcheck.js), the Speed page's "Latency under load" card (views/speed.js qualityView), the DNS card's record types
(tools/dns.js), the TFTP server card (tools/tftp.js) and the Packet capture page (views/capture.js).

Every driver loads its module into a node vm with a stubbed ``window.TNT = {views:{}, util:{}, api:{}, ui:{}}`` (no DOM, no
app.js), the way ``_NODE_DNS_DRIVER`` in test_ui.py does, so what is pinned here stays pure; the Speed driver adds app.js's own
fmtMs / fmtPct, read from app.js. Offline: node and files only. The service modules are compared with when they are there.
"""
from __future__ import annotations

import importlib
import ipaddress
import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from test_ui import ROOT, UI, _read  # noqa: F401

NEW_MODULES = ("js/netcheck.js", "js/tools/portforward.js", "js/tools/tftp.js", "js/views/capture.js", "js/views/speed.js", "js/tools/dns.js")
NODE = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

_PRELUDE = r"""
const fs = require('fs'), vm = require('vm');
const window = { TNT: { views: {}, util: {}, api: {}, ui: {} } };
const ctx = vm.createContext({ window, console });
const load = (file) => vm.runInContext(fs.readFileSync(file, 'utf8'), ctx, { filename: file });
const input = JSON.parse(fs.readFileSync(process.argv[process.argv.length - 1], 'utf8'));
const T = window.TNT;
"""


def _node(tmp_path: Path, body: str, files: List[str], payload: Any = None) -> Any:
    """Runs _PRELUDE + body under node with the UI files (relative to ui/) and a JSON payload as arguments; the driver writes
    one JSON document to stdout."""
    driver = tmp_path / "driver.js"
    driver.write_text(_PRELUDE + body, encoding="utf-8")
    data = tmp_path / "payload.json"
    data.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    r = subprocess.run(["node", str(driver)] + [str(UI / f) for f in files] + [str(data)],
                       capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _service(name: str, attr: str) -> Optional[Any]:
    """A constant of a service module when that module (and the constant) exists yet, else None."""
    try:
        mod = importlib.import_module(name)
    except Exception:          # a module of another unit that is not written yet, or does not import on its own
        return None
    return getattr(mod, attr, None)


# --------------------------------------------------------------------------------------------- netcheck.js: NAT
NAT_TEXT = {
    "no_nat": ("No NAT", "This PC has the public address itself. Nothing to forward: Windows Firewall decides what gets in."),
    "single_nat": ("Single NAT", "One router holds the public address. Port forwards on it work, unless the ISP blocks the port."),
    "double_nat": ("Double NAT", "Another NAT sits between this network's router and the internet (usually the ISP modem or gateway, sometimes "
                                 "the ISP itself). Forward ports on both, or put the ISP box in bridge / IP-passthrough mode."),
    "cgnat": ("Carrier-grade NAT (CGNAT)", "The ISP shares one public address between customers, so port forwarding from the internet cannot "
                                           "work on IPv4. Ask the ISP for a public or static IP, or use the device's cloud/P2P service or a VPN."),
    "upstream_nat": ("NAT beyond the router", "Websites see an address the router does not have, so something beyond it translates again (ISP "
                                              "NAT, an upstream firewall, a second line or a VPN)."),
    "nat_unclear_private_wan": ("Probably behind another NAT", "The router reports no usable public address although the internet works. That "
                                                               "usually means it sits behind another NAT."),
    "vpn": ("Traffic leaves through a VPN", "This PC's internet traffic goes through a VPN, so a check would describe the VPN, not this site's "
                                            "router. Disconnect it and check again."),
    "offline": ("Could not check", "No internet connection (or no public address yet), so NAT cannot be checked."),
    "unknown": ("Could not tell", "The router does not answer UPnP or NAT-PMP and the path gave no clear sign."),
}
VERDICT_COLOUR = {"no_nat": "green", "single_nat": "green", "double_nat": "yellow", "upstream_nat": "yellow", "nat_unclear_private_wan": "yellow",
                  "unknown": "yellow", "vpn": "yellow", "cgnat": "red", "offline": "grey"}
FORWARDS_NOTE = "Only forwards the router shares over UPnP; ones made in its own settings page may be missing."
SWITCH_RESULT_NOTE = "If a small switch or a phone sits between this PC and the wall jack, this is the port that switch or phone is plugged into."
PORTCHECK_VPN_TEXT = ("This PC's internet goes through a VPN, so the test would check the VPN's address, not this site's: disconnect the VPN "
                      "first")
PORT_HINT = ("Something must answer on that TCP port (the camera/NVR must be on and the forward must point at it). No answer can also mean the "
             "ISP or a firewall blocks the port.")
PORT_NOTE = ("TCP only: UDP forwards (SIP, VPN) cannot be tested from outside. Uses portchecker.io (or Globalping), which sees this site's "
             "public IP.")


def _nat_result(verdict: str, **over: Any) -> Dict[str, Any]:
    """A NAT_RESULT like the mock's profile a (the §1.1 stand-ins), with `over` replacing top-level keys."""
    r = {"ts": 1757700000.0, "generation": 4, "duration_ms": 812, "verdict": verdict, "confidence": "high", "title": "?", "explanation": "?",
         "router": {"gateway": "192.0.2.1", "wan_ip": "203.0.113.5", "wan_source": "upnp",
                    "natpmp": {"answered": True, "result": 0, "external_ip": "203.0.113.5"},
                    "upnp": {"found": True, "server": "ExampleOS/1.0 UPnP/1.1 MiniUPnPd/2.2.0", "model": "Example Router XR-1",
                             "service": "urn:schemas-upnp-org:service:WANIPConnection:1", "status": "Connected", "external_ip": "203.0.113.5",
                             "error": None}},
         "public_ip": "203.0.113.5", "trace": None,
         "port_mappings": {"entries": [
             {"protocol": "TCP", "external_port": 8000, "internal_client": "10.0.0.60", "internal_port": 8000, "enabled": True,
              "description": "NVR web", "lease_s": 0},
             {"protocol": "TCP", "external_port": 554, "internal_client": "10.0.0.61", "internal_port": 554, "enabled": True,
              "description": "<b>camera</b>", "lease_s": 0}], "truncated": False, "error": None},
         "error": None}
    r.update(over)
    return r


_NAT_DRIVER = r"""
load(process.argv[2]);
const N = T.netcheck;
const out = {
  verdicts: Object.fromEntries(Object.entries(input.verdicts).map(([v, r]) => [v, N.natView(r, {})])),
  checking: N.natView(input.verdicts.single_nat, { running: true }),
  noResult: N.natView(null, {}),
  error: N.natView(null, { error: 'The NAT check is not available on this service' }),
  errorWithResult: N.natView(input.verdicts.cgnat, { error: 'x' }),
  waiting: input.waiting.map((w) => N.natView(null, w).waiting),
  views: input.views.map((r) => N.natView(r, {})),
  texts: N.TEXTS,
};
process.stdout.write(JSON.stringify(out));
"""


@NODE
def test_netcheck_nat_view_for_every_verdict(tmp_path):
    changed = {"net": {"generation": 4, "changed_ts": 1000.0}}
    waiting = [
        {"status": None, "now": 1010},                                                                          # no status: nothing to wait for
        {"status": {**changed, "map": {"public_ip": {"ip": "203.0.113.5", "ts": 900.0, "checked_ts": 900.0}}}, "now": 1050},   # old address
        {"status": {**changed, "map": {"public_ip": {"ip": "203.0.113.5", "ts": 1000.0}}}, "now": 1050},       # looked up at the change
        {"status": {**changed, "map": {"public_ip": {"ip": None, "ts": None, "checked_ts": 1005.0}}}, "now": 1050},   # a failed lookup
        {"status": {**changed, "map": {"public_ip": {"ip": "203.0.113.5", "ts": 900.0}}}, "now": 1119.9},
        {"status": {**changed, "map": {"public_ip": {"ip": "203.0.113.5", "ts": 900.0}}}, "now": 1120.0},     # 120 s after the change
        {"status": {**changed, "map": None}, "now": 1010},                                                      # no link map
        {"status": {"net": {"generation": 4, "changed_ts": None}, "map": {"public_ip": {"ip": None, "ts": None}}}, "now": 1010},
        {"status": {**changed, "map": {"public_ip": None}}, "now": 1010},
    ]
    hops = [{"ttl": 1, "ip": "192.168.50.1", "rtt_ms": 1.2, "range": "private"}, {"ttl": 2, "ip": "100.64.0.1", "rtt_ms": 8.0, "range": None},
            {"ttl": 3, "ip": None, "rtt_ms": None, "range": None}, {"ttl": 4, "ip": "203.0.113.5", "rtt_ms": 12.5, "range": "public"}]
    views = [
        _nat_result("unknown", confidence=None, public_ip=None, port_mappings=None, trace={"reached_ttl": 4, "hops": hops},
                    router={"gateway": "192.0.2.1", "wan_ip": None, "wan_source": None, "natpmp": {"answered": False, "result": None, "external_ip": None},
                            "upnp": {"found": False, "server": None, "model": None, "service": None, "status": None, "external_ip": None, "error": None}}),
        _nat_result("double_nat", confidence="medium", router={**_nat_result("x")["router"], "wan_ip": "192.168.50.2", "wan_source": "natpmp",
                                                               "upnp": {**_nat_result("x")["router"]["upnp"], "model": ""}},
                    port_mappings={"entries": [], "truncated": False, "error": "the router does not share its port forwards"}),
        _nat_result("single_nat", port_mappings={"entries": [], "truncated": False, "error": None}, trace={"reached_ttl": None, "hops": []}),
    ]
    out = _node(tmp_path, _NAT_DRIVER, ["js/netcheck.js"],
                {"verdicts": {v: _nat_result(v, confidence=None if v in ("offline", "unknown") else "high") for v in NAT_TEXT},
                 "waiting": waiting, "views": views})

    for verdict, (title, explanation) in NAT_TEXT.items():
        v = out["verdicts"][verdict]
        assert (v["verdict"], v["badge"], v["explanation"], v["cls"]) == (verdict, title, explanation, VERDICT_COLOUR[verdict]), verdict
        assert v["confidence"] == ("" if verdict in ("offline", "unknown") else "· high confidence") and v["waiting"] is False and v["error"] == ""
    assert out["texts"]["NAT_TEXT"] == {k: list(t) for k, t in NAT_TEXT.items()}
    service_text = _service("tnt.natcheck", "NAT_TEXT")
    if service_text is not None:
        assert {k: list(t) for k, t in service_text.items()} == out["texts"]["NAT_TEXT"], "the card shows the service's texts verbatim"

    # the details of profile a: the router's own address with its source, the public address, UPnP and the forwards it shares
    single = out["verdicts"]["single_nat"]
    assert single["rows"] == [
        {"k": "Router's own internet address", "v": "203.0.113.5", "copy": True, "suffix": " (UPnP)"},
        {"k": "Public address", "v": "203.0.113.5", "copy": True, "suffix": " (WAN on the map)"},
        {"k": "UPnP", "v": "on · Example Router XR-1"},
        {"k": "UPnP forwards", "v": "2 listed", "count": 2}]
    assert single["mappings"] == [{"protocol": "TCP", "forward": "8000 → 10.0.0.60:8000", "description": "NVR web"},
                                  {"protocol": "TCP", "forward": "554 → 10.0.0.61:554", "description": "<b>camera</b>"}]
    assert single["forwardsNote"] == FORWARDS_NOTE

    # while a check runs, with no result, and a request that failed
    grey = {"verdict": "checking", "cls": "grey", "badge": "Checking…", "confidence": "", "explanation": "", "waiting": False, "error": "",
            "rows": [], "mappings": [], "forwardsNote": ""}
    assert out["checking"] == grey and out["noResult"] == grey
    assert out["error"] == {**grey, "verdict": "error", "badge": "Could not check", "explanation": "The NAT check is not available on this service",
                            "error": "The NAT check is not available on this service"}
    assert out["errorWithResult"]["verdict"] == "cgnat", "a result on screen wins over a later failed request"

    # "Waiting for this network's public address": only while the link map has no address looked up since the change, and at most 120 s
    assert out["waiting"] == [False, True, False, True, True, False, False, False, True]

    no_router, double, empty = out["views"]
    assert no_router["badge"] == "Could not tell" and no_router["confidence"] == ""
    assert no_router["rows"] == [
        {"k": "Router's own internet address", "v": "none reported", "muted": True},
        {"k": "Public address", "v": "—", "muted": True},
        {"k": "UPnP", "v": "no answer"},
        {"k": "Path", "lines": ["1 192.168.50.1 (private)", "2 100.64.0.1 (shared)", "3 *", "4 203.0.113.5 (public)"]}]
    assert no_router["mappings"] == [] and no_router["forwardsNote"] == ""
    assert double["confidence"] == "· medium confidence"
    assert double["rows"][0] == {"k": "Router's own internet address", "v": "192.168.50.2", "copy": True, "suffix": " (NAT-PMP)"}
    assert double["rows"][2] == {"k": "UPnP", "v": "on · ExampleOS/1.0 UPnP/1.1 MiniUPnPd/2.2.0"}, "the server string when there is no model"
    assert double["rows"][3] == {"k": "UPnP forwards", "v": "the router does not share its port forwards", "muted": False}
    assert double["forwardsNote"] == FORWARDS_NOTE
    assert empty["rows"][3:] == [{"k": "UPnP forwards", "v": "none listed", "muted": True}, {"k": "Path", "lines": []}]


# --------------------------------------------------------------------------------------- netcheck.js: switch port
#: A NEIGHBOR as tnt.lldp reads it (the §1.1 stand-ins: LAB-SW-01 on Port 7).
_NEIGHBOR = {"protocol": "lldp", "switch_name": "LAB-SW-01", "switch_description": "Example Switch 8P", "vendor": "Example Networks",
             "chassis_id": "02:00:5E:10:00:0A",
             "port_id": "Port 7", "port_description": None, "vlan": 10, "voice_vlan": 20, "management_ips": ["192.0.2.2"],
             "capabilities": ["bridge"], "poe": {"class": 4, "allocated_w": 24.0}, "link": {"autoneg": True, "mau": 30, "text": "1000BASE-T full"},
             "ttl_s": 120}

_NEIGHBOR_DRIVER = r"""
load(process.argv[2]);
const N = T.netcheck;
process.stdout.write(JSON.stringify(input.map(([n, opts]) => N.neighborView(n, opts))));
"""


@NODE
def test_netcheck_neighbor_view(tmp_path):
    full = dict(_NEIGHBOR)
    cases = [
        [full, {"ago": "2 min ago"}],
        [{"protocol": "cdp", "switch_name": "LAB-SW-01", "port_id": "GigabitEthernet1/0/7", "port_description": "Port 7", "vlan": None,
          "poe": {"class": None, "allocated_w": 15.4}, "link": {"autoneg": False, "mau": 99, "text": None}, "management_ips": []}, None],
        [{"protocol": "lldp", "switch_name": "LAB-SW-01", "port_id": "Port 7", "poe": {"class": 3, "allocated_w": None}, "voice_vlan": None}, {"ago": ""}],
        [{}, None],
        [None, {"ago": "just now"}],
        [{"protocol": "lldp", "switch_name": "LAB-SW-01", "port_id": "Port 7", "vlan": 10}, {"ago": ""}],   # no vendor: it is left off the line
        [{"protocol": "lldp", "switch_name": "LAB-SW-01", "port_id": "Port 7", "vendor": "Example Networks"}, {"ago": ""}],
    ]
    out = _node(tmp_path, _NEIGHBOR_DRIVER, ["js/netcheck.js"], cases)
    # the switch manufacturer (the chassis MAC's OUI) sits on the line between the port and the VLAN; it is not a Details row
    assert out[0] == {"line": "LAB-SW-01 · Port 7 · Example Networks · VLAN 10", "via": "via LLDP · 2 min ago", "note": SWITCH_RESULT_NOTE, "rows": [
        {"k": "Switch description", "v": "Example Switch 8P"}, {"k": "Port ID", "v": "Port 7"}, {"k": "VLAN", "v": "10"}, {"k": "Voice VLAN", "v": "20"},
        {"k": "PoE", "v": "class 4 · 24.0 W"}, {"k": "Link", "v": "1000BASE-T full"}, {"k": "Management IP", "v": ["192.0.2.2"], "copy": True}]}
    assert not any(row["k"] == "Manufacturer" for row in out[0]["rows"])
    # the port's description wins over its id on the line; unknown values (the vendor here) leave their rows and line parts out
    assert out[1] == {"line": "LAB-SW-01 · Port 7", "via": "via CDP", "note": SWITCH_RESULT_NOTE,
                      "rows": [{"k": "Port ID", "v": "GigabitEthernet1/0/7"}, {"k": "PoE", "v": "15.4 W"}]}
    assert out[2]["rows"] == [{"k": "Port ID", "v": "Port 7"}, {"k": "PoE", "v": "class 3"}] and out[2]["via"] == "via LLDP"
    assert out[3] == {"line": "Unknown switch · unknown port", "rows": [], "via": "", "note": SWITCH_RESULT_NOTE}
    assert out[4]["line"] == "Unknown switch · unknown port" and out[4]["via"] == "just now"
    assert out[5]["line"] == "LAB-SW-01 · Port 7 · VLAN 10"              # vendor unknown: omitted, VLAN still shown
    assert out[6]["line"] == "LAB-SW-01 · Port 7 · Example Networks"      # vendor known, VLAN not


# --------------------------------------------------------------------------------- tools/portforward.js: port forward
def _port_result(**over: Any) -> Dict[str, Any]:
    """A PORTCHECK_RESULT for a reachable port 8000, with `over` replacing keys."""
    r = {"ts": 1.0, "generation": 4, "port": 8000, "protocol": "tcp", "public_ip": "203.0.113.5", "reachable": True, "provider": "portchecker.io",
         "detail": "portchecker.io connected to the port", "nat_verdict": "single_nat", "error": None, "duration_ms": 1240}
    r.update(over)
    return r


_PORT_DRIVER = r"""
load(process.argv[2]);
const N = T.tools.portforward;
process.stdout.write(JSON.stringify({ views: input.map(([r, c]) => N.portView(r, c)), texts: N.TEXTS }));
"""


@NODE
def test_portforward_port_view_texts(tmp_path):
    ok = _port_result()
    closed =dict(ok, port=8001, reachable=False, detail="portchecker.io could not connect (tried twice)", nat_verdict="double_nat")
    failed = dict(ok, port=9, reachable=None, detail=None, error="The port checkers could not be reached: timed out")
    err = lambda status, code, message: {"status": status, "code": code, "message": message}  # noqa: E731
    cases = [
        [None, {}],
        [None, {"testing": True}],
        [ok, {"natVerdict": "single_nat"}],
        [closed, {"natVerdict": "cgnat"}],
        [closed, {}],                                         # the result's own verdict when the NAT section has none
        [dict(closed, nat_verdict="upstream_nat"), {"natVerdict": "nat_unclear_private_wan"}],
        [dict(closed, nat_verdict=None), {"natVerdict": "no_nat"}],
        [failed, {}],
        [None, {"natVerdict": "vpn"}],
        [ok, {"error": err(0, "timeout", "Request timed out")}],
        [None, {"error": err(409, "no_public_ip", "This network's public IPv4 address is not known yet (or it has none): wait for the WAN address on the link map, then test again")}],
        [None, {"error": err(429, "rate_limited", "Too many tests: wait 4 s")}],
        [None, {"error": err(400, "bad_request", "port must be a whole number from 1 to 65535")}],
        [None, {"error": err(404, "not_found", "Not Found")}],
        [None, {"error": err(500, "internal", "boom")}],
    ]
    out = _node(tmp_path, _PORT_DRIVER, ["js/tools/portforward.js"], cases)
    views, texts = out["views"], out["texts"]
    idle = {"label": "TCP port", "placeholder": "8000", "button": "Test from the internet", "disabled": False, "blocked": "", "cls": "", "text": "",
            "detail": "", "hints": [], "note": PORT_NOTE}
    assert views[0] == idle
    assert views[1] == {**idle, "button": "Testing…", "disabled": True}
    assert views[2] == {**idle, "cls": "ok", "text": "TCP port 8000 is reachable from the internet", "detail": "portchecker.io connected to the port",
                        "hints": [PORT_HINT]}
    assert views[3] == {**idle, "cls": "bad", "text": "TCP port 8001 did not answer from the internet",
                        "detail": "portchecker.io could not connect (tried twice)", "hints": [PORT_HINT, "Carrier-grade NAT (CGNAT): forwarding may not work here"]}
    assert views[4]["hints"] == [PORT_HINT, "Double NAT: forwarding may not work here"]
    assert views[5]["hints"] == [PORT_HINT, "Probably behind another NAT: forwarding may not work here"]
    assert views[6]["hints"] == [PORT_HINT]
    assert views[7] == {**idle, "cls": "warn", "text": "The port checkers could not be reached: timed out"}, "an error result has no hints"
    assert views[8] == {**idle, "disabled": True, "blocked": PORTCHECK_VPN_TEXT}
    assert [v["text"] for v in views[9:]] == [
        "Still testing on the service, try again in a minute",
        "This network's public IPv4 address is not known yet (or it has none): wait for the WAN address on the link map, then test again",
        "Too many tests: wait 4 s", "port must be a whole number from 1 to 65535", "The port-forward test is not available on this service",
        "Could not test the port: boom"]
    assert all(v["cls"] == "warn" and v["hints"] == [] for v in views[9:])
    for key, text in {"portHint": PORT_HINT, "portNote": PORT_NOTE, "PORTCHECK_VPN_TEXT": PORTCHECK_VPN_TEXT,
                      "portTimeout": "Still testing on the service, try again in a minute", "portRisk": ": forwarding may not work here",
                      "portLabel": "TCP port", "portButton": "Test from the internet", "portBusy": "Testing…", "portPlaceholder": "8000",
                      "portInvalid": "port must be a whole number from 1 to 65535",
                      "portUnavailable": "The port-forward test is not available on this service"}.items():
        assert texts[key] == text, key
    for module, attr, text in (("tnt.portcheck", "PORTCHECK_VPN_TEXT", PORTCHECK_VPN_TEXT),):
        service_text = _service(module, attr)
        if service_text is not None:
            assert service_text == text, attr


_TEXTS_DRIVER = r"""
load(process.argv[2]);
process.stdout.write(JSON.stringify(T.netcheck.TEXTS));
"""


@NODE
def test_netcheck_card_texts(tmp_path):
    """The card is now "NAT & switch port" with a "Switch port - LLDP" heading; the port-forward texts moved to portforward.js."""
    texts = _node(tmp_path, _TEXTS_DRIVER, ["js/netcheck.js"])
    for key, text in {"title": "NAT & switch port", "switchLabel": "Switch port - LLDP", "checking": "Checking…",
                      "waiting": "Waiting for this network's public address", "checkAgain": "Check again",
                      "natBusy": "A NAT check is already running", "forwardsNote": FORWARDS_NOTE, "findSwitch": "Find switch port",
                      "listening": "Listening for the switch…", "stop": "Stop", "tryAgain": "Try again",
                      "noWired": "Needs a wired (Ethernet) connection", "SWITCH_RESULT_NOTE": SWITCH_RESULT_NOTE}.items():
        assert texts[key] == text, key
    assert "portHint" not in texts and "PORTCHECK_VPN_TEXT" not in texts, "the port-forward texts moved to portforward.js"


# ---------------------------------------------------------------------------------------- netcheck.js: rangeOf
_RANGE_NETS = [("private", "10.0.0.0/8"), ("private", "172.16.0.0/12"), ("private", "192.168.0.0/16"), ("shared", "100.64.0.0/10"),
               ("shared", "192.0.0.0/29"), ("reserved", "0.0.0.0/8"), ("reserved", "127.0.0.0/8"), ("reserved", "169.254.0.0/16"),
               ("reserved", "192.0.0.0/24"), ("reserved", "198.18.0.0/15"), ("reserved", "224.0.0.0/4"), ("reserved", "240.0.0.0/4")]


def _range_of(ip: Any) -> Optional[str]:
    """Contract §2.4: explicit networks checked in order, public for everything else, None for anything but an IPv4 literal."""
    if not isinstance(ip, str) or not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return None
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    return next((name for name, net in _RANGE_NETS if addr in ipaddress.ip_network(net)), "public")


_RANGE_DRIVER = r"""
load(process.argv[2]);
process.stdout.write(JSON.stringify(input.map((ip) => T.netcheck.rangeOf(ip))));
"""


@NODE
def test_netcheck_range_of_mirrors_the_service(tmp_path):
    vectors = {"10.0.0.1": "private", "172.16.0.1": "private", "172.31.255.255": "private", "172.32.0.1": "public", "192.168.1.1": "private",
               "100.64.0.1": "shared", "100.127.255.255": "shared", "100.128.0.1": "public", "192.0.0.1": "shared", "192.0.0.7": "shared",
               "192.0.0.8": "reserved", "192.0.0.255": "reserved", "192.0.1.1": "public", "192.0.2.1": "public", "198.51.100.7": "public",
               "203.0.113.5": "public", "0.0.0.0": "reserved", "127.0.0.1": "reserved", "169.254.1.1": "reserved", "198.18.0.1": "reserved",
               "198.19.255.255": "reserved", "198.20.0.1": "public", "224.0.0.1": "reserved", "239.255.255.250": "reserved", "240.0.0.1": "reserved",
               "255.255.255.255": "reserved", "8.8.8.8": "public", "11.0.0.1": "public"}
    # every network's first and last address and the addresses just outside it
    edges: List[str] = []
    for _, net in _RANGE_NETS:
        n = ipaddress.ip_network(net)
        for value in (int(n.network_address) - 1, int(n.network_address), int(n.broadcast_address), int(n.broadcast_address) + 1):
            if 0 <= value <= 0xFFFFFFFF:
                edges.append(str(ipaddress.IPv4Address(value)))
    junk = [None, "", "x", "1.2.3", "256.1.1.1", "01.2.3.4", "10.0.0.1 ", "2001:db8::1", 167772161]
    ips = list(vectors) + edges + junk
    out = _node(tmp_path, _RANGE_DRIVER, ["js/netcheck.js"], ips)
    got = dict(zip(map(str, ips), out))
    for ip, expected in vectors.items():
        assert got[ip] == expected, ip
    for ip, js in zip(ips, out):
        assert js == _range_of(ip), ip
    service = _service("tnt.natcheck", "range_of")
    if service is not None:
        for ip in list(vectors) + edges:
            assert service(ip) == got[ip], ip


# ---------------------------------------------------------------------------------- views/speed.js: qualityView
GRADE_TEXT = {"A+": "No bufferbloat: latency stays flat while the line is busy", "A": "Excellent: calls and games are unaffected by heavy use",
              "B": "Good: small delay spikes while the line is busy", "C": "Bufferbloat: calls and games may lag while someone uploads or downloads",
              "D": "Severe bufferbloat: calls will break up while the line is busy", "F": "Unusable under load: the connection stalls when it is busy"}
GRADE_COLOUR = {"A+": "green", "A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}


def _window(sent: int, received: int, loss: float, median: float, mean: float, jitter: float, **extra: Any) -> Dict[str, Any]:
    w = {"sent": sent, "received": received, "skipped": 0, "loss_pct": loss, "median_ms": median, "mean_ms": mean, "p95_ms": mean + 10,
         "max_ms": mean + 20, "jitter_ms": jitter}
    w.update(extra)
    return w


def _quality(**over: Any) -> Dict[str, Any]:
    """The contract §6.5 example: idle 14 ms, busy 26 / 52 ms, loss 0% / 2.9%, 30 / 34 probes, grade B."""
    q = {"version": 1, "available": True, "reason": None, "target": "1.1.1.1", "interval_ms": 100, "payload_bytes": 32,
         "windows": {"baseline": _window(30, 30, 0, 14, 14.2, 1.1),
                     "download": _window(30, 30, 0, 25, 26, 3, increase_ms=12, grade="A", reason=None, warning=None),
                     "upload": _window(34, 33, 2.9, 50, 52, 9, increase_ms=38, grade="B", reason=None, warning=None)},
         "bufferbloat": {"grade": "B", "increase_ms": 38, "direction": "upload", "text": GRADE_TEXT["B"], "warning": None, "reason": None},
         "call": {"method": "estimate (simplified E-model)", "idle": {"r": 88.2, "mos": 4.39, "label": "Good"},
                  "loaded": {"r": 76.2, "mos": 3.87, "label": "Fair", "direction": "upload"},
                  "checks": [{"key": "zoom", "ok": True, "detail": "mean 52 ms, jitter 9 ms, loss 2.9%"},
                             {"key": "teams", "ok": False, "detail": "loss 2.9% is 1% or more"}]}}
    q.update(over)
    return q


_SPEED_DRIVER = r"""
const app = fs.readFileSync(process.argv[3], 'utf8');
const grab = (name) => {
  const m = new RegExp('function ' + name + '\\(v\\) \\{[^\\n]*\\}').exec(app);
  if (!m) throw new Error('no ' + name + ' in app.js');
  return vm.runInNewContext('(' + m[0] + ')');
};
T.util.fmtMs = grab('fmtMs');
T.util.fmtPct = grab('fmtPct');
load(process.argv[2]);
process.stdout.write(JSON.stringify(input.map(([q, last]) => T.views.speed.qualityView(q, last))));
"""


@NODE
def test_speed_quality_view_states_and_grades(tmp_path):
    q = _quality()
    ungraded = _quality(windows={"baseline": _window(30, 30, 0, 14, 14.2, 1.1), "download": None, "upload": None},
                        bufferbloat={"grade": None, "increase_ms": None, "direction": None, "text": None, "warning": None, "reason": "phase too short to grade"},
                        call={"method": "estimate (simplified E-model)", "idle": {"r": 92.35, "mos": 4.39, "label": "Excellent"}, "loaded": None,
                              "checks": [{"key": "zoom", "ok": True, "detail": "idle: mean 14 ms, jitter 1.1 ms, loss 0%"}]})
    lost = _quality(bufferbloat={"grade": "F", "increase_ms": None, "direction": "upload", "text": None, "warning": "some probes were lost under load",
                                 "reason": "most probes were lost under load"})
    unavailable = _quality(available=False, reason="1.1.1.1 did not answer pings", bufferbloat=None, call=None)
    cases = [[None, None], [None, {"ok": False, "error": "timed out"}], [None, {"ok": True, "quality": None}], [None, {"ok": True}],
             [unavailable, {"ok": True}], [q, {"ok": True}], [None, {"ok": True, "quality": q}], [ungraded, {"ok": True}], [lost, {"ok": True}]]
    cases += [[_quality(bufferbloat={"grade": g, "increase_ms": 7, "direction": "download", "text": None, "warning": None, "reason": None}), {"ok": True}]
              for g in GRADE_TEXT]
    out = _node(tmp_path, _SPEED_DRIVER, ["js/views/speed.js", "js/app.js"], cases)
    # the call-quality lines and the Zoom/Teams checks are the SIP page's now (tests/test_ui_sip.py): what is
    # left here is the bufferbloat grade, which is measured here
    blank = {"state": "none", "grade": "—", "cls": "grey", "text": "", "headline": "", "gradeText": "", "warning": "",
             "details": ""}
    assert out[0] == {**blank, "text": "Runs with every speed test"}
    assert out[1] == {**blank, "state": "failed", "text": "The last speed test failed"}
    assert out[2] == out[3] == {**blank, "state": "missing", "text": "Not measured for this test"}, "a test from before 1.15 has no quality key"
    assert out[4] == {**blank, "state": "unavailable", "text": "1.1.1.1 did not answer pings"}
    assert out[5] == {"state": "measured", "grade": "B", "cls": "green", "text": "",
                      "headline": "Latency under load +38 ms (download +12 ms, upload +38 ms)", "gradeText": GRADE_TEXT["B"], "warning": "",
                      "details": "Idle 14 ms to 1.1.1.1 · busy 26 / 52 ms · loss 0% / 2.9% · 30 / 34 probes"}
    assert out[6] == out[5], "the quality comes from last.quality when q is not given"
    assert out[7] == {**blank, "state": "measured", "gradeText": "phase too short to grade",
                      "details": "Idle 14 ms to 1.1.1.1 · busy — / — ms · loss — / — · — / — probes"}
    assert (out[8]["grade"], out[8]["cls"], out[8]["headline"], out[8]["gradeText"], out[8]["warning"]) == (
        "F", "red", "", GRADE_TEXT["F"], "some probes were lost under load")
    for grade, view in zip(GRADE_TEXT, out[9:]):
        assert (view["grade"], view["cls"], view["gradeText"]) == (grade, GRADE_COLOUR[grade], GRADE_TEXT[grade]), grade
        assert view["headline"] == "Latency under load +7 ms (download +12 ms, upload +38 ms)"


@NODE
def test_speed_quality_view_reads_a_real_quality(tmp_path):
    """qualityView over what tnt.speedtest.quality.build_quality really returns: idle 14 ms, download 26 ms, upload 52 ms with
    one echo of 40 lost, and a baseline that never answered."""
    quality = pytest.importorskip("tnt.speedtest.quality")

    def sample(i: int, lost: set) -> tuple:
        ts = i / 10 + 0.05
        return (ts, False, None) if i in lost else (ts, True, 14.0 if i < 30 else 26.0 if i < 80 else 52.0)

    phases = {"baseline": (0.0, 3.0), "download": (3.0, 8.0), "upload": (8.0, 13.0)}
    graded = quality.build_quality([sample(i, {100}) for i in range(130)], phases, target="1.1.1.1", interval_ms=100, payload=32)
    silent = quality.build_quality([sample(i, set(range(30))) for i in range(130)], phases, target="1.1.1.1", interval_ms=100, payload=32)
    bb = graded["bufferbloat"]
    assert (bb["grade"], bb["direction"], bb["increase_ms"], bb["warning"]) == ("B", "upload", 38.0, None), "the synthetic run grades as planned"
    out = _node(tmp_path, _SPEED_DRIVER, ["js/views/speed.js", "js/app.js"], [[graded, {"ok": True}], [None, {"ok": True, "quality": silent}]])
    view = out[0]
    assert (view["state"], view["grade"], view["cls"], view["text"], view["warning"]) == ("measured", "B", "green", "", "")
    assert view["headline"] == "Latency under load +38 ms (download +12 ms, upload +38 ms)"
    assert view["gradeText"] == quality.GRADE_TEXT["B"] == GRADE_TEXT["B"]
    assert "call" not in view and "checks" not in view, "the call lines moved to the SIP page"
    assert view["details"] == "Idle 14 ms to 1.1.1.1 · busy 26 / 52 ms · loss 0% / 2.5% · 40 / 40 probes"
    assert out[1] == {"state": "unavailable", "grade": "—", "cls": "grey", "text": "1.1.1.1 did not answer pings", "headline": "", "gradeText": "",
                      "warning": "", "details": ""}
    assert silent["reason"] == quality.REASON_NO_REPLIES.format(target="1.1.1.1")


# ------------------------------------------------------------------------------------------- tools/dns.js: types
DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "PTR", "NAPTR"]
IP_TYPE_TEXT = "An IP address is looked up as PTR: type a DNS name to ask for other record types"
SRV_HINT = "SRV names start with the service, for example _sip._tcp.example.com"
_DNS_TYPE_CASES = [None, "", "  ", "A", "aaaa", " mx ", "Txt", "NS", "SOA", "SRV", "CAA", "PTR", "ptr", "CNAME", "naptr", "ANY", "HINFO",
                   "-type=mx", "M X", "x" * 100, 5, "all", "ALL"]
_DNS_TYPE_NAMES = ["example.com", "203.0.113.10", "203.0.113.10.", "2001:db8::10", "2001:db8::10.", "2001:db8::10%12", "_sip._tcp.example.com"]


def _valid_type(text: Any, name: str) -> Dict[str, Any]:
    """Contract §7: the type trimmed and upper-cased, one of DNS_TYPES, "ALL" or Auto; an IP literal takes only PTR or ALL."""
    s = "" if text is None else str(text).strip()
    if s and s.upper() not in DNS_TYPES and s.upper() != "ALL":
        return {"ok": False, "error": f'"{s[:80]}" is not a DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR or NAPTR)'}
    body = name.strip()[:-1] if name.strip().endswith(".") else name.strip()
    try:
        ipaddress.ip_address(body)
        is_ip = True
    except ValueError:
        is_ip = False
    if s and s.upper() not in ("PTR", "ALL") and is_ip:
        return {"ok": False, "error": IP_TYPE_TEXT}
    return {"ok": True, "type": s.upper()}


def _dns(name: str, rtype: Optional[str], answer: Optional[str], records: List[tuple], ok: bool = True, error: Optional[str] = None,
         addresses: Optional[List[str]] = None, aliases: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"name": name, "type": rtype, "server": None, "resolver": {"name": "gateway.lan", "address": "192.0.2.1"}, "answer_name": answer,
            "addresses": addresses or [], "aliases": aliases or [], "records": [{"type": t, "name": n, "value": v, "ttl": ttl} for t, n, v, ttl in records],
            "authoritative": False, "ok": ok, "error": error, "duration_ms": 41, "ts": 1.0}


_DNS_DRIVER = r"""
load(process.argv[2]);
const D = T.tools.dns;
process.stdout.write(JSON.stringify({ types: D.TYPES, valid: input.names.map((name) => input.types.map((t) => D.validType(t, name))),
                                      views: input.results.map(([r, opts]) => D.resultView(r, opts)) }));
"""


@NODE
def test_dns_record_types_validation_and_summaries(tmp_path):
    cname = ("CNAME", "www.example.com", "example.com", 3600)
    results = [
        [_dns("www.example.com", "MX", "example.com", [cname, ("MX", "example.com", "10 mail.example.com", 3600)], aliases=["www.example.com"]), None],
        [_dns("example.com", "TXT", "example.com", [("TXT", "example.com", "v=spf1 ip4:203.0.113.0/24 -all", 3600),
                                                    ("TXT", "example.com", "<script>alert(1)</script>", 3600)]), None],
        [_dns("example.com", "NS", "example.com", [("NS", "example.com", "ns1.example.net", 86400), ("NS", "example.com", "ns2.example.net", 86400)]), None],
        [_dns("example.com", "SOA", "example.com", [("SOA", "example.com", "ns1.example.net hostmaster.example.com 2026091301 7200 3600 1209600 300", 3600)]), None],
        [_dns("_sip._tcp.example.com", "SRV", "_sip._tcp.example.com", [("SRV", "_sip._tcp.example.com", "10 60 5060 sip.example.com", 300)]), None],
        [_dns("example.com", "CAA", "example.com", [("CAA", "example.com", '0 issue "letsencrypt.org"', 3600)]), None],
        [_dns("example.com", "NAPTR", "example.com", [("NAPTR", "example.com", '100 10 "S" "SIP+D2U" "" _sip._udp.example.com', 3600)]), None],
        [_dns("www.example.com", "CNAME", "example.com", [cname], aliases=["www.example.com"]), None],
        [_dns("10.113.0.203.in-addr.arpa", "PTR", "example.com", [("PTR", "10.113.0.203.in-addr.arpa", "example.com", 3600)]), None],
        [_dns("mail.example.com", "MX", None, [], ok=False, error="No MX records found for this name"), None],
        [_dns("example.com", "SRV", None, [], ok=False, error="No SRV records found for this name"), None],
        [_dns("_sip._udp.example.com", "SRV", None, [], ok=False, error="No SRV records found for this name"), None],
        [_dns("example.com", "AAAA", "example.com", [("AAAA", "example.com", "2001:db8::10", 3600)], addresses=["2001:db8::10"]), {"showIpv6": False}],
        [_dns("example.com", "A", "example.com", [("A", "example.com", "203.0.113.10", 3600), ("A", "example.com", "203.0.113.11", 3600)],
              addresses=["203.0.113.10", "203.0.113.11"]), {"showIpv6": False}],
        [_dns("www.example.com", None, "example.com", [cname, ("A", "example.com", "203.0.113.10", 3600), ("AAAA", "example.com", "2001:db8::10", 3600)],
              addresses=["203.0.113.10", "2001:db8::10"], aliases=["www.example.com"]), {"showIpv6": False}],
        [_dns("203.0.113.10", "PTR", "example.com", [("PTR", "10.113.0.203.in-addr.arpa", "example.com", 3600)], addresses=["203.0.113.10"]), {"showIpv6": False}],
        [None, None],
        [_dns("example.com", "ALL", "example.com",
              [("A", "example.com", "203.0.113.10", 300), ("AAAA", "example.com", "2001:db8::10", 300),
               ("MX", "example.com", "10 mail.example.com", 3600), ("TXT", "example.com", "v=spf1 -all", 3600),
               ("NS", "example.com", "ns1.example.net", 86400), ("SOA", "example.com", "ns1.example.net h 1 2 3 4 5", 3600),
               ("CAA", "example.com", '0 issue "letsencrypt.org"', 3600),
               ("NAPTR", "example.com", '100 10 "S" "SIP+D2U" "" _sip._udp.example.com', 3600)],
              addresses=["203.0.113.10", "2001:db8::10"]), None],
        [_dns("203.0.113.10", "ALL", "example.com", [("PTR", "10.113.0.203.in-addr.arpa", "example.com", 3600)], addresses=["203.0.113.10"]), None],
    ]
    out = _node(tmp_path, _DNS_DRIVER, ["js/tools/dns.js"], {"names": _DNS_TYPE_NAMES, "types": _DNS_TYPE_CASES, "results": results})

    assert out["types"] == DNS_TYPES
    service_types = _service("tnt.nettools", "DNS_TYPES")
    if service_types is not None:
        assert list(service_types) == DNS_TYPES
    # the page refuses what the service refuses, with the same words (the service's own chain when it is there)
    lookup = _service("tnt.nettools", "validate_lookup")
    for name, row in zip(_DNS_TYPE_NAMES, out["valid"]):
        for text, js in zip(_DNS_TYPE_CASES, row):
            assert js == _valid_type(text, name), (name, text)
            if lookup is not None:
                try:
                    py = {"ok": True, "type": lookup(name, None, text)[2] or ""}
                except ValueError as exc:
                    py = {"ok": False, "error": str(exc)}
                assert js == py, (name, text)
    valid = dict(zip(_DNS_TYPE_NAMES, out["valid"]))
    assert valid["example.com"][5] == {"ok": True, "type": "MX"} and valid["example.com"][0] == {"ok": True, "type": ""}
    assert valid["203.0.113.10"][5] == valid["2001:db8::10"][5] == {"ok": False, "error": IP_TYPE_TEXT}
    assert valid["203.0.113.10."][11] == {"ok": True, "type": "PTR"} and valid["203.0.113.10"][2] == {"ok": True, "type": ""}
    # an IPv6 literal with a trailing dot or a zone id is still an address to the service
    assert valid["2001:db8::10."][5] == valid["2001:db8::10%12"][5] == {"ok": False, "error": IP_TYPE_TEXT}
    assert valid["2001:db8::10%12"][11] == {"ok": True, "type": "PTR"}
    # "All record types" is accepted for a name and for an IP (it is a PTR lookup, like Auto)
    assert valid["example.com"][21] == valid["example.com"][22] == {"ok": True, "type": "ALL"}
    assert valid["203.0.113.10"][22] == valid["2001:db8::10"][21] == {"ok": True, "type": "ALL"}

    views = out["views"]
    assert [v["summary"] for v in views[:12]] == [
        "example.com has 1 mail server", "example.com has 2 TXT records", "example.com has 2 name servers",
        "example.com: primary name server ns1.example.net, serial 2026091301", "_sip._tcp.example.com has 1 SRV record",
        "example.com has 1 CAA record", "example.com has 1 NAPTR record", "www.example.com is an alias of example.com",
        "10.113.0.203.in-addr.arpa is example.com", "mail.example.com — No MX records found for this name",
        "example.com — No SRV records found for this name", "_sip._udp.example.com — No SRV records found for this name"]
    assert [v["type"] for v in views[:12]] == ["MX", "TXT", "NS", "SOA", "SRV", "CAA", "NAPTR", "CNAME", "PTR", "MX", "SRV", "SRV"]
    assert views[0]["values"] == ["10 mail.example.com"] and views[0]["addresses"] == [] and views[0]["aliases"] == ["www.example.com"]
    assert [r["type"] for r in views[0]["records"]] == ["CNAME", "MX"]
    assert views[1]["values"] == ["v=spf1 ip4:203.0.113.0/24 -all", "<script>alert(1)</script>"], "record text is kept as text"
    assert views[6]["values"] == ['100 10 "S" "SIP+D2U" "" _sip._udp.example.com']
    assert views[7]["values"] == ["example.com"] and views[8]["reverse"] is False and views[8]["values"] == ["example.com"]
    assert [v["hint"] for v in views[9:12]] == ["", SRV_HINT, ""], "the SRV tip only for a name without the service in front"
    assert all(v["hint"] == "" for v in views[:9])
    # an AAAA lookup shows its IPv6 answers while Settings hides IPv6; A and Auto keep the address chips
    aaaa, a, auto, rev = views[12:16]
    assert (aaaa["summary"], aaaa["hiddenV6"], aaaa["addresses"], [r["type"] for r in aaaa["records"]], aaaa["values"]) == (
        "example.com has 1 IPv6 address", 0, [{"address": "2001:db8::10", "family": "IPv6"}], ["AAAA"], [])
    assert (a["summary"], a["values"], len(a["addresses"])) == ("example.com has 2 IPv4 addresses", [], 2)
    assert (auto["summary"], auto["type"], auto["hiddenV6"], auto["values"], [r["type"] for r in auto["records"]]) == (
        "example.com has 1 address", "", 1, [], ["CNAME", "A"])
    assert (rev["reverse"], rev["summary"], rev["values"], rev["addresses"]) == (True, "203.0.113.10 is example.com", [], [{"address": "203.0.113.10", "family": "IPv4"}])
    assert views[16] == {"ok": False, "cls": "bad", "reverse": False, "type": "", "summary": "the lookup failed", "asked": None, "nonAuthoritative": False,
                         "addresses": [], "hiddenV6": 0, "aliases": [], "values": [], "groups": [], "hint": "", "records": []}
    # "All record types": the answer grouped by type (A/AAAA still shown as addresses), the summary counts records and types
    allv, ipall = views[17], views[18]
    assert (allv["type"], allv["reverse"], allv["summary"]) == ("ALL", False, "example.com — 8 records across 8 types")
    assert [a["address"] for a in allv["addresses"]] == ["203.0.113.10", "2001:db8::10"] and allv["values"] == []
    assert [g["type"] for g in allv["groups"]] == ["MX", "TXT", "NS", "SOA", "CAA", "NAPTR"]
    assert allv["groups"][0] == {"type": "MX", "values": ["10 mail.example.com"]}
    # an IP with ALL is a reverse (PTR) lookup, its type still "ALL"
    assert (ipall["type"], ipall["reverse"], ipall["summary"], ipall["groups"]) == ("ALL", True, "203.0.113.10 is example.com", [])
    assert [a["address"] for a in ipall["addresses"]] == ["203.0.113.10"]


# --------------------------------------------------------------------------------------------- tools/tftp.js
TFTP_SCOPE_TEXT = ("Serves files to devices that ask for them (phones, switches, bootloaders). A device that is itself the TFTP server, such as a "
                   "UniFi AP or airMAX in recovery, needs a TFTP client instead.")


def _transfer(tid: str, state: str, op: str = "read", ended: Optional[float] = None, **over: Any) -> Dict[str, Any]:
    t = {"id": tid, "client": "192.0.2.50", "op": op, "file": "phones/SEP02005E100001.cnf.xml", "mode": "octet", "blksize": 1468, "windowsize": 1,
         "size": 2048, "bytes": 512, "state": state, "error": None, "started_ts": 100.0, "ended_ts": ended}
    t.update(over)
    return t


_TFTP_DRIVER = r"""
load(process.argv[2]);
const F = T.tools.tftp;
process.stdout.write(JSON.stringify({
  badges: input.badges.map(([st, busy]) => F.badgeState(st, busy)),
  names: input.adapters.map((a) => [F.adapterName(a), F.adapterLabel(a)]),
  transfers: input.transfers.map((t) => F.transferView(t)),
  merged: input.merges.map(([a, b, t]) => F.mergeTransfer(a, b, t)),
  history: F.historyRows(input.history).map((t) => t.id),
  historyAll: F.historyRows(input.history, 50).length,
  files: [F.fileRows(input.files), F.fileRows({ files: input.files }), F.fileRows(null)],
  owners: input.owners.map((o) => F.ownersText(o)),
  polls: input.polls.map(([st, live]) => F.pollDelay(st, live)),
  differs: input.differs.map(([s, st]) => F.summaryDiffers(s, st)),
  texts: { scope: F.TFTP_SCOPE_TEXT, uploads: F.UPLOADS_NOTE, empty: F.EMPTY_FILES_TEXT, open: F.OPEN_FAILED_TEXT, shown: F.HISTORY_SHOWN },
}));
"""


@NODE
def test_tftp_card_helpers(tmp_path):
    running = {"running": True, "uploads": False, "error": None, "transfers": [_transfer("t1", "sending")], "history": []}
    history = [_transfer("h%02d" % i, "done", ended=200.0 + i) for i in range(12)] + [_transfer("hx", "failed", ended=None, started_ts=50.0)]
    payload = {
        "badges": [[None, ""], [{"running": False}, ""], [{"running": True}, ""], [{"running": True, "uploads": True}, ""],
                   [{"running": False, "error": "UDP port 69 is already used by tftpd64.exe"}, ""], [{"running": True, "uploads": True, "error": "x"}, ""],
                   [{"available": False}, ""], [{"running": False}, "starting"], [{"running": True}, "stopping"]],
        "adapters": [{"name": "Ethernet", "ip": "192.0.2.10", "prefix": 24}, {"name": "Wi-Fi"}, "Ethernet", None, {"ip": "192.0.2.10"}],
        "transfers": [_transfer("t1", "sending"), _transfer("t2", "receiving", op="write", size=None, bytes=4096),
                      _transfer("t3", "unconfirmed", ended=300.0, error="the last ACK did not come"), {}],
        "merges": [
            [[], [], _transfer("t1", "negotiating")],
            [[_transfer("t0", "sending"), _transfer("t1", "negotiating")], [], _transfer("t1", "sending", bytes=1024)],
            [[_transfer("t1", "sending")], [_transfer("old", "done", ended=10.0)], _transfer("t1", "done", ended=20.0)],
            [[], [_transfer("h%02d" % i, "done", ended=float(i)) for i in range(50)], _transfer("new", "failed", ended=99.0)],
            [[_transfer("t1", "sending")], [], None],
        ],
        "history": history,
        "files": [{"name": "phones/SEP02005E100001.cnf.xml", "size": 2048, "mtime": 1.0}, {"name": "firmware.bin", "size": 1048576, "mtime": 2.0},
                  {"size": 3}, "junk"],
        "owners": [[{"pid": 4120, "name": "tftpd64.exe"}, {"pid": 912, "name": None}], [], None, [{"pid": 7, "name": "PID 7"}]],
        "polls": [[running, False], [running, True], [dict(running, running=False), False], [dict(running, transfers=[]), False],
                  [{"running": True, "counts": {"active": 2}}, False], [None, False]],
        "differs": [[{"running": True, "uploads": False, "error": None, "active": 1}, running], [{"running": False, "active": 1}, running],
                    [{"running": True, "uploads": True, "active": 1}, running], [{"running": True, "error": "x", "active": 1}, running],
                    [{"running": True, "active": 0}, running], [None, running], [{"running": False}, None],
                    # restarted (another window) or serving on another adapter; an adapter while stopped says nothing
                    [{"running": True, "active": 1, "since_ts": 99.0}, dict(running, since_ts=100.0)],
                    [{"running": True, "active": 1, "since_ts": 100.0, "adapter": "Ethernet"}, dict(running, since_ts=100.0, adapter={"name": "Ethernet"})],
                    [{"running": True, "active": 1, "adapter": "Wi-Fi"}, dict(running, adapter={"name": "Ethernet"})],
                    [{"running": False, "adapter": None, "since_ts": None}, {"running": False, "adapter": {"name": "Ethernet"}}]],
    }
    out = _node(tmp_path, _TFTP_DRIVER, ["js/tools/tftp.js"], payload)
    assert out["badges"] == [{"cls": "grey", "text": "loading"}, {"cls": "grey", "text": "off"}, {"cls": "green", "text": "on"},
                             {"cls": "yellow", "text": "uploads on"}, {"cls": "red", "text": "error"}, {"cls": "red", "text": "error"},
                             {"cls": "grey", "text": "unavailable"}, {"cls": "yellow pulse", "text": "starting…"}, {"cls": "yellow pulse", "text": "stopping…"}]
    assert out["names"] == [["Ethernet", "Ethernet — 192.0.2.10/24"], ["Wi-Fi", "Wi-Fi"], ["Ethernet", "Ethernet"], ["", "?"], ["", "? — 192.0.2.10"]]
    t1, t2, t3, empty = out["transfers"]
    assert t1 == {"id": "t1", "active": True, "file": "phones/SEP02005E100001.cnf.xml", "client": "192.0.2.50", "op": "read", "pct": 0.25, "bytes": 512,
                  "size": 2048, "state": "sending", "cls": "blue", "error": "", "ended_ts": 100.0}
    assert (t2["op"], t2["pct"], t2["size"], t2["active"]) == ("write", None, None, True)
    assert (t3["active"], t3["cls"], t3["error"], t3["ended_ts"]) == (False, "yellow", "the last ACK did not come", 300.0)
    assert (empty["id"], empty["file"], empty["active"], empty["cls"]) == (None, "?", False, "grey")
    first, update, finish, capped, junk = out["merged"]
    assert [t["id"] for t in first["transfers"]] == ["t1"] and first["history"] == []
    assert [t["id"] for t in update["transfers"]] == ["t0", "t1"] and update["transfers"][1]["bytes"] == 1024, "a running transfer keeps its place"
    assert finish["transfers"] == [] and [t["id"] for t in finish["history"]] == ["t1", "old"]
    assert len(capped["history"]) == 50 and capped["history"][0]["id"] == "new" and capped["history"][-1]["id"] == "h48"
    assert [t["id"] for t in junk["transfers"]] == ["t1"]
    assert out["history"] == ["h11", "h10", "h09", "h08", "h07", "h06", "h05", "h04", "h03", "h02"] and out["historyAll"] == 13
    listed = [{"name": "firmware.bin", "size": 1048576, "mtime": 2.0}, {"name": "phones/SEP02005E100001.cnf.xml", "size": 2048, "mtime": 1.0}]
    assert out["files"] == [listed, listed, []]
    assert out["owners"] == ["UDP port 69 is already used by tftpd64.exe (PID 4120), PID 912", "", "", "UDP port 69 is already used by PID 7"]
    assert out["polls"] == [2000, 10000, None, None, 2000, None]
    assert out["differs"] == [False, True, True, True, True, False, True, True, False, True, False]
    assert out["texts"] == {"scope": TFTP_SCOPE_TEXT, "uploads": "Anyone on this network can upload files while this is on",
                            "empty": "No files yet: put the files devices will ask for in this folder", "open": "Could not open the TFTP folder", "shown": 10}


# ------------------------------------------------------------------------------------------- views/capture.js
CAPTURE_WARNING = ("Captures can contain passwords and private data. TNT keeps the newest 10 (at most 2 GB, 7 days) in a folder only "
                   "administrators can open; a copy you save elsewhere is not protected.")
CAPTURE_LEAVE_TITLE = "Save this capture?"
CAPTURE_FILE = "TNT-capture-20260101-120000.pcapng"
# the quick filter buttons, in the page's order; the keys are tnt.dissect.PROTO_FILTERS keys
CAPTURE_PROTOS = ["icmp", "arp", "dns", "dhcp", "http", "https", "tcp", "udp", "rtsp", "rtp", "sip"]
CAPTURE_COLUMNS = ["no", "time", "rel", "src", "dst", "proto", "length", "info"]


def _capture_session(**over: Any) -> Dict[str, Any]:
    """A SESSION 23.4 s into a live capture of Ethernet, with `over` replacing keys."""
    s = {"id": "c1", "state": "capturing", "source": "live", "adapter": {"name": "Ethernet"}, "file": None, "saved": False,
         "started_ts": 1767268800.0, "first_ts": 1767268800.25, "elapsed_s": 23.4, "packets": 12, "shown": 12, "bytes": 2048,
         "dropped": 0, "truncated": False, "calls": 0, "stop_reason": None, "error": None, "ts": 1767268823.4}
    s.update(over)
    return s


def _capture_file(name: str, size: int, created_ts: float, packets: Optional[int]) -> Dict[str, Any]:
    return {"name": name, "size": size, "created_ts": created_ts, "packets": packets}


def _capture_stream(**over: Any) -> Dict[str, Any]:
    """One rebuilt RTP stream of a call (tnt.sipcalls STREAM), G.711 µ-law and playable unless `over` says otherwise."""
    s = {"id": "s1", "src": "192.0.2.50", "sport": 16384, "dst": "192.0.2.60", "dport": 16386, "ssrc": 305419896,
         "payload_type": 0, "codec": "PCMU", "packets": 2100, "lost": 0, "out_of_order": 0, "first_ts": 1767268810.0,
         "last_ts": 1767268852.0, "duration_s": 42.0, "bytes": 336000, "jitter_ms": 1.75, "decodable": True}
    s.update(over)
    return s


def _capture_call(**over: Any) -> Dict[str, Any]:
    """An answered 42 s call (tnt.sipcalls CALL) with one playable stream, with `over` replacing keys."""
    c = {"id": "1", "call_id": "9f3c1a@192.0.2.50", "from_uri": "sip:1001@192.0.2.50", "to_uri": "sip:1002@192.0.2.60",
         "state": "answered", "start_ts": 1767268810.5, "answer_ts": 1767268812.0, "end_ts": 1767268852.5, "duration_s": 42.0,
         "status": None, "messages": [], "streams": [_capture_stream()], "note": None}
    c.update(over)
    return c


def _time_of_day(ts: float) -> str:
    """What views/capture.js timeOfDay(ts) must say in this PC's time zone: "HH:MM:SS.mmm"."""
    lt = time.localtime(ts)
    return "%02d:%02d:%02d.%03d" % (lt.tm_hour, lt.tm_min, lt.tm_sec, round(ts % 1 * 1000))


_CAPTURE_DRIVER = r"""
load(process.argv[2]);                      // js/api.js: the page's filter becomes its query string here
load(process.argv[3]);                      // js/views/capture.js
const C = T.views.capture;
T.util.fmtBytes = (n) => n + ' B';          // app.js's own, which the page borrows for a session's byte count
const shared = { ip: '192.0.2.7', mac: '02-00-5e-10-00-01', protos: ['sip', 'rtp'] };
process.stdout.write(JSON.stringify({
  times: input.times.map((ts) => C.timeOfDay(ts)),
  rels: input.rels.map((r) => C.relText(r)),
  protoClasses: input.protoNames.map((p) => C.protoClass(p)),
  queries: input.filters.map(([f, since]) => C.filterQuery(f, since)),
  copied: C.filterQuery(shared, null).protos !== shared.protos,
  on: input.filters.map(([f]) => C.filterOn(f)),
  urls: input.filters.map(([f, since]) => T.api.captureQuery(C.filterQuery(f, since))),
  rawUrls: input.raw.map((q) => T.api.captureQuery(q)),
  sessions: input.sessions.map((s) => C.sessionView(s)),
  stops: input.stops.map((r) => C.stopSuffix(r)),
  clocks: input.clocks.map((s) => C.clock(s)),
  calls: input.calls.map((c) => C.callView(c)),
  constants: { protos: C.PROTO_BUTTONS.map((p) => p.key), labels: C.PROTO_BUTTONS.map((p) => p.label),
               calls: C.PROTO_BUTTONS.filter((p) => p.calls).map((p) => p.key), columns: C.COLUMNS, tail: C.TAIL_MS,
               rows: C.DOM_ROWS, warning: C.WARNING_TEXT, admin: C.ADMIN_TEXT, leave: C.LEAVE_TITLE },
}));
"""


@NODE
def test_capture_page_helpers(tmp_path):
    """views/capture.js's pure helpers: a packet row's time and age, the protocol colour, the filter the page has on as a
    query (and the query string api.js makes of it), what a session says, why a capture stopped by itself, m:ss and one
    rebuilt SIP call."""
    stopped = _capture_session(state="stopped", source="live", elapsed_s=60.0, packets=340, shown=340, ts=1767268860.0)
    payload = {
        # 2026-01-01 12:00:23.500 local; a whole number of milliseconds so node and Python agree to the millisecond
        "times": [1767268823.5, 1767268823.25, 1767268800.0, None, "12:00", True],
        "rels": [0, 0.5, 12.48, 123.456, -3, None, "x"],
        "protoNames": ["SIP", "RTP", "RTCP", "RTSP", "TLS", "HTTPS", "QUIC", "HTTP", "DNS", "MDNS", "LLMNR", "NBNS", "ICMP",
                       "ICMPv6", "IGMP", "ARP", "LLDP", "CDP", "STP", "EAPOL", "DHCP", "DHCPv6", "NTP", "sip", "SSDP", "", None],
        "filters": [[None, None], [{}, 0], [{"ip": "192.0.2.7"}, None], [{"mac": "02-00-5E-10-00-01"}, None],
                    [{"protos": ["sip"]}, None], [{"ip": "", "mac": "", "protos": []}, None], [{"protos": "sip"}, None],
                    [{"ip": "192.0.2.7", "mac": "02-00-5E-10-00-01", "protos": ["sip", "rtp"]}, 4096]],
        # what api.captureQuery leaves out on its own, and the repeated protocol parameters
        "raw": [{}, {"limit": 800, "since": None, "ip": "", "mac": None}, {"since": 0, "limit": 800},
                {"limit": 800, "protos": ["sip", "", None, " rtp "]}, {"limit": 800, "ip": "2001:db8::7", "mac": "02:00:5E:10:00:01"}],
        "sessions": [
            None, {}, _capture_session(), _capture_session(adapter=None, elapsed_s=0, packets=1, bytes=0),
            _capture_session(dropped=3, truncated=True, shown=800),
            _capture_session(truncated=True, shown=None),
            stopped, dict(stopped, stop_reason="seconds"), dict(stopped, stop_reason="service"),
            dict(stopped, saved=True, file=CAPTURE_FILE), dict(stopped, saved=True, file=None),
            _capture_session(state="loaded", source="file", file=CAPTURE_FILE, saved=True),
            _capture_session(state="loaded", source="file", file=None, saved=True),
            _capture_session(state="error", error="Packet Monitor could not start (exit 87)"),
            _capture_session(state="error", error=None),
            _capture_session(state="winding-down"),
        ],
        "stops": [None, "user", "seconds", "size", "packets", "adapter", "service", "made up"],
        "clocks": [0, 23.4, 59.9, 60, 900, 3600, -5, None, "x"],
        "calls": [
            _capture_call(), _capture_call(state="ringing", duration_s=None, streams=[]),
            _capture_call(state="ended"), _capture_call(state="failed"), _capture_call(state="cancelled"),
            _capture_call(state="calling"), _capture_call(state=""),
            _capture_call(id=3, from_uri=None, to_uri=None, start_ts=None, streams=[_capture_stream(codec="G729", decodable=False)]),
            _capture_call(streams=[_capture_stream(codec=None), _capture_stream(decodable=False, codec="PCMU")]),
            {},
        ],
    }
    out = _node(tmp_path, _CAPTURE_DRIVER, ["js/api.js", "js/views/capture.js"], payload)
    assert out["times"] == [_time_of_day(1767268823.5), _time_of_day(1767268823.25), _time_of_day(1767268800.0), "", "", ""]
    assert out["rels"] == ["0.000", "0.500", "12.480", "123.456", "0.000", "", ""]
    # the protocol colours: voice, encrypted, web, name lookups, ICMP, link-local and the housekeeping protocols
    # ICMPv6 and DHCPv6 colour like their IPv4 siblings: protoClass upper-cases both sides of the comparison
    assert out["protoClasses"] == ["p-voice", "p-voice", "p-voice", "p-voice", "p-secure", "p-secure", "p-secure", "p-web",
                                   "p-name", "p-name", "p-name", "p-name", "p-icmp", "p-icmp", "p-icmp",
                                   "p-link", "p-link", "p-link", "p-link", "p-link", "p-admin", "p-admin", "p-admin",
                                   "p-voice", "", "", ""]
    # the query: the row limit always, `since` only while tailing, and only the filters that are on
    none, empty, ip, mac, proto, blank, junk, every = out["queries"]
    assert none == {"limit": 800} and empty == {"limit": 800, "since": 0}
    assert ip == {"limit": 800, "ip": "192.0.2.7"} and mac == {"limit": 800, "mac": "02-00-5E-10-00-01"}
    assert proto == {"limit": 800, "protos": ["sip"]} and blank == junk == {"limit": 800}
    assert every == {"limit": 800, "since": 4096, "ip": "192.0.2.7", "mac": "02-00-5E-10-00-01", "protos": ["sip", "rtp"]}
    assert out["copied"] is True, "the protocol list is copied, never the page's own array"
    assert out["on"] == [False, False, True, True, True, False, False, True]
    assert out["urls"][0] == "?limit=800" and out["urls"][1] == "?since=0&limit=800"
    assert out["urls"][-1] == ("?since=4096&limit=800&ip=192.0.2.7&mac=02-00-5E-10-00-01&proto=sip&proto=rtp")
    assert out["rawUrls"] == ["", "?limit=800", "?since=0&limit=800", "?limit=800&proto=sip&proto=rtp",
                              "?limit=800&ip=2001%3Adb8%3A%3A7&mac=02%3A00%3A5E%3A10%3A00%3A01"]
    (none, blank, capturing, first, dropped, unknown_shown, stopped_v, seconds, service, saved, saved_bare,
     loaded, loaded_bare, error, error_bare, junk_state) = out["sessions"]
    idle = {"state": "", "running": False, "unsaved": False, "label": "Not capturing", "detail": "", "cls": "muted"}
    assert none == idle and blank == dict(idle, detail="0 packets")
    # a running capture is always unsaved: the page asks before it is left
    assert capturing == {"state": "capturing", "running": True, "unsaved": True, "label": "Capturing on Ethernet · 0:23",
                         "detail": "12 packets · 2048 B", "cls": "ok"}
    assert first["label"] == "Capturing on this PC · 0:00" and first["detail"] == "1 packet"
    assert dropped["detail"] == "12 packets · 2048 B · 3 dropped · list holds the newest 800"
    assert unknown_shown["detail"].endswith("list holds the newest few")
    # stopped and never saved is unsaved too, and says so; a limit it reached by itself is named
    assert stopped_v == {"state": "stopped", "running": False, "unsaved": True, "label": "Stopped — not saved yet",
                         "detail": "340 packets · 2048 B", "cls": ""}
    assert seconds["label"] == "Stopped — not saved yet (it reached its time limit)" and seconds["unsaved"] is True
    assert service["label"] == "Stopped — not saved yet (the service stopped)"
    assert (saved["unsaved"], saved["cls"], saved["label"]) == (False, "ok", "Saved as " + CAPTURE_FILE)
    assert saved_bare["label"] == "Saved as a file"
    # a capture read back from a file, and one that failed: nothing to save either way
    assert (loaded["unsaved"], loaded["cls"], loaded["label"]) == (False, "", "Reading " + CAPTURE_FILE)
    assert loaded_bare["label"] == "Reading a saved capture"
    assert (error["unsaved"], error["cls"], error["label"]) == (False, "bad", "Packet Monitor could not start (exit 87)")
    assert error_bare["label"] == "The capture failed"
    # a state this page does not know (a newer service) reads as idle, with the state kept for the console
    assert junk_state["state"] == "winding-down" and (junk_state["label"], junk_state["cls"]) == ("Not capturing", "muted")
    # STOP_REASONS: only the user's own stop (and a reason a newer service invents) hangs nothing off "Stopped"
    assert out["stops"] == ["", "", " (it reached its time limit)", " (it reached its size limit)", " (it reached its packet limit)",
                            " (the adapter went away)", " (the service stopped)", ""]
    assert out["clocks"] == ["0:00", "0:23", "0:59", "1:00", "15:00", "60:00", "0:00", "0:00", "0:00"]
    (answered, ringing, ended, failed, cancelled, calling, no_state, one_way, mixed, bare) = out["calls"]
    assert answered == {"id": "1", "title": "sip:1001@192.0.2.50 → sip:1002@192.0.2.60", "state": "answered", "cls": "green",
                        "when": _time_of_day(1767268810.5), "duration": "0:42", "playable": True, "note": "PCMU"}
    assert (ringing["cls"], ringing["playable"], ringing["duration"]) == ("blue", False, "")
    assert ringing["note"] == "No audio was captured for this call"
    assert [c["cls"] for c in (ended, failed, cancelled, calling, no_state)] == ["grey", "red", "yellow", "blue", "blue"]
    # a codec TNT cannot rebuild is named, and so is the one it can where a call carries both
    assert one_way["id"] == "3" and one_way["title"] == "unknown → unknown" and one_way["when"] == ""
    assert (one_way["playable"], one_way["note"]) == (False, "G729 — TNT cannot play this codec")
    assert mixed["playable"] is True and mixed["note"] == "PCMU"
    assert bare == {"id": "", "title": "unknown → unknown", "state": "", "cls": "blue", "when": "", "duration": "",
                    "playable": False, "note": "No audio was captured for this call"}
    c = out["constants"]
    assert c["protos"] == CAPTURE_PROTOS and c["calls"] == ["sip"]
    assert c["labels"] == ["ICMP", "ARP", "DNS", "DHCP", "HTTP", "HTTPS", "TCP", "UDP", "RTSP", "RTP", "SIP calls"]
    assert c["columns"] == CAPTURE_COLUMNS and c["tail"] == 700 and c["rows"] == 3000
    assert c["warning"] == CAPTURE_WARNING and c["admin"] == "Packet capture needs a Windows administrator account"
    assert c["leave"] == CAPTURE_LEAVE_TITLE
    # every quick filter button is a filter the service knows, and every row column a field it sends
    filters = _service("tnt.dissect", "PROTO_FILTERS")
    if filters is not None:
        assert set(c["protos"]) <= set(filters), sorted(set(c["protos"]) - set(filters))
    row_keys = _service("tnt.capture", "ROW_KEYS")
    if row_keys is not None:
        # every column is a ROW field, but for "Time", which is the row's `ts` as a time of day
        assert set(c["columns"]) - {"time"} <= set(row_keys), sorted(set(c["columns"]) - {"time"} - set(row_keys))
        assert "ts" in row_keys
    limits = _service("tnt.capture", "MAX_ROWS")
    if limits is not None:
        assert c["rows"] <= limits, "the table never holds more rows than the service keeps"


# ------------------------------------------------------------------------------------------ fixtures vs the service
def test_fixtures_follow_the_service_shapes():
    """What the drivers above feed the views has the service's own keys, in its order, for every service module that is there
    yet, so a view is never pinned against a key the service does not send."""
    nat = _nat_result("single_nat", trace={"reached_ttl": 2, "hops": [{"ttl": 1, "ip": "192.168.50.1", "rtt_ms": 1.2, "range": "private"}]})
    dns = _dns("www.example.com", "MX", "example.com", [("MX", "example.com", "10 mail.example.com", 3600)])
    q = _quality()
    shapes = [
        ("tnt.natcheck", "NAT_RESULT_KEYS", nat), ("tnt.natcheck", "ROUTER_KEYS", nat["router"]),
        ("tnt.natcheck", "NATPMP_KEYS", nat["router"]["natpmp"]), ("tnt.natcheck", "UPNP_KEYS", nat["router"]["upnp"]),
        ("tnt.natcheck", "PORT_MAPPINGS_KEYS", nat["port_mappings"]), ("tnt.natcheck", "MAPPING_KEYS", nat["port_mappings"]["entries"][0]),
        ("tnt.natcheck", "TRACE_KEYS", nat["trace"]), ("tnt.natcheck", "HOP_KEYS", nat["trace"]["hops"][0]),
        ("tnt.natcheck", "NAT_VERDICTS", NAT_TEXT),
        ("tnt.portcheck", "PORTCHECK_RESULT_KEYS", _port_result()),
        ("tnt.lldp", "NEIGHBOR_KEYS", _NEIGHBOR),
        ("tnt.nettools", "DNS_RESULT_KEYS", dns), ("tnt.nettools", "DNS_RECORD_KEYS", dns["records"][0]),
        ("tnt.speedtest.quality", "QUALITY_KEYS", q), ("tnt.speedtest.quality", "WINDOW_KEYS", q["windows"]["baseline"]),
        ("tnt.speedtest.quality", "BUFFERBLOAT_KEYS", q["bufferbloat"]), ("tnt.speedtest.quality", "CALL_KEYS", q["call"]),
        ("tnt.speedtest.quality", "SCORE_KEYS", q["call"]["idle"]), ("tnt.speedtest.quality", "CHECK_KEYS", q["call"]["checks"][0]),
        ("tnt.tftp", "TFTP_TRANSFER_KEYS", _transfer("t1", "sending")),
        ("tnt.capture", "SESSION_KEYS", _capture_session()), ("tnt.capture", "CAPTURE_FILE_KEYS", _capture_file(CAPTURE_FILE, 1, 1.0, 1)),
        ("tnt.sipcalls", "CALL_KEYS", _capture_call()), ("tnt.sipcalls", "STREAM_KEYS", _capture_stream()),
    ]
    for module, attr, fixture in shapes:
        expected = _service(module, attr)
        if expected is not None:
            assert tuple(fixture) == tuple(expected), (module, attr)
    window, extra, score = (_service("tnt.speedtest.quality", a) for a in ("WINDOW_KEYS", "LOADED_EXTRA_KEYS", "SCORE_KEYS"))
    if window is not None and extra is not None and score is not None:
        assert tuple(q["windows"]["download"]) == tuple(q["windows"]["upload"]) == tuple(window) + tuple(extra)
        assert tuple(q["call"]["loaded"]) == tuple(score) + ("direction",)
    grade_text = _service("tnt.speedtest.quality", "GRADE_TEXT")
    if grade_text is not None:
        assert dict(grade_text) == GRADE_TEXT, "the card's fallback grade texts are the service's"
    # the fields the TFTP card reads from a status, a summary (status.tftp, tftp.state) and a switch-port status and job
    for module, attr, used in (("tnt.tftp", "TFTP_STATUS_KEYS", {"available", "running", "since_ts", "error", "warning", "adapter", "adapters", "listen",
                                                                   "root", "uploads", "firewall", "conflict", "transfers", "history", "counts", "settings"}),
                               ("tnt.tftp", "TFTP_SUMMARY_KEYS", {"running", "error", "uploads", "active", "since_ts", "adapter"}),
                               ("tnt.switchport", "SWITCH_STATUS_KEYS", {"job", "adapters", "available", "reason"}),
                               ("tnt.switchport", "SWITCH_JOB_KEYS", {"state", "listen_s", "elapsed_s", "neighbors", "error", "reason", "generation", "ts"})):
        keys = _service(module, attr)
        if keys is not None:
            assert used <= set(keys), (module, attr, used - set(keys))


# -------------------------------------------------------------------------------------------- source rules and pins
def test_new_ui_modules_follow_the_ui_rules():
    for rel in NEW_MODULES:
        src = _read(rel)
        assert src.startswith("/* TNT — "), rel
        # loaded before app.js: TNT.util / TNT.ui / TNT.state only inside functions
        top_level = [ln for ln in src.splitlines() if re.match(r"^  (const|let|var) ", ln)]
        assert not any(("TNT.util." in ln or "TNT.ui." in ln or "TNT.state" in ln) and "=>" not in ln for ln in top_level), (rel, top_level)
        # untrusted text only as text nodes: no html: attribute, and innerHTML only ever emptied
        assert not re.search(r"\bhtml:", src), rel
        assert set(re.findall(r"innerHTML\s*=\s*([^;]+);", src)) <= {"''"}, rel
        # no contractions in what the user reads
        assert not re.search(r"n\\'t\b|n't\b|n’t\b", src), rel
        # no fact about the owner's own site
        low = src.lower()
        for fact in ("netgear", "rs100", "poeswitch", "us-8-60w"):
            assert fact not in low, (rel, fact)


def test_new_card_sources_keep_the_contract():
    nc = _read("js/netcheck.js")
    for s in ("TNT.netcheck = { create, natView, neighborView, rangeOf, TEXTS };", "h('div', { class: 'card netcheck-card' }",
              "'nc-section nc-nat'", "'nc-section nc-switch'", "TNT.api.natGet()", "TNT.api.natRun()",
              "TNT.api.switchGet()", "TNT.api.switchStart(", "TNT.api.switchStop()", "'netcheck.switch'",
              "'aria-expanded'", "if (manual && err.status === 409) TNT.ui.toast(TEXTS.natBusy, 'warn');",
              "if (manual && nat) TNT.ui.toast(natError, 'error');", "TEXTS.switchLabel"):
        assert s in nc, s
    assert "portView" not in nc and "portForwardTest" not in nc and "nc-port" not in nc, "the port-forward test moved to tools/portforward.js"
    assert "icon(" not in nc.split("h('div', { class: 'card netcheck-card' }")[1].split(";")[0], "the card title has no icon"

    pf = _read("js/tools/portforward.js")
    for s in ("TNT.tools.portforward = { create, portView, validPort, TEXTS };", "TNT.api.portForwardTest(", "type: 'number'",
              "class: 'form-row tool-form pf-form'", "class: 'pf-hints'", "netChanged(info, state)"):
        assert s in pf, s

    sp = _read("js/views/speed.js")
    for s in ("baseline: 'Measuring idle latency'", "'Latency under load'", "h('div', { class: 'grid grid-2' }, latestCard, qualityCard), histCard, patCard)",
              "'grade-chip ", "qualityView,", "const { fmtMs, fmtPct } = TNT.util;", "fmtPct(down.loss_pct) + ' / ' + fmtPct(up.loss_pct)"):
        assert s in sp, s

    dns = _read("js/tools/dns.js")
    for s in ("TNT.tools.dns = { create, resultView, validName, validServer, validType, TYPES };", "TNT.api.dnsLookup(n.name, s.server, t.type)",
              "h('label', null, 'Record type')", "placeholder: 'www.example.com'", "'_sip._tcp.example.com'", "els.runBtn, els.clearBtn);"):
        assert s in dns, s
    labels = ["Auto (A + AAAA)", "All record types", "A — IPv4 address", "AAAA — IPv6 address", "CNAME — alias", "MX — mail servers",
              "TXT — text (SPF, verification)", "NS — name servers", "SOA — zone serial", "SRV — services (SIP…)", "CAA — certificate authorities",
              "PTR — name of an address", "NAPTR — SIP routing"]
    at = [dns.index("'" + label + "'") for label in labels]
    assert at == sorted(at), "the record types in the contract's order"
    # the select sits right after the name field: the first input is still the name and Clear still follows Look up
    form = dns[dns.index("const form = h('div', { class: 'form-row tool-form dns-form' }"):]
    assert form.index("'DNS name / IP address'") < form.index("'Record type'") < form.index("'DNS server (optional)'")

    tftp = _read("js/tools/tftp.js")
    for s in ("typeof (window.pywebview && window.pywebview.api && window.pywebview.api.open_path) === 'function'", "'pywebviewready'",
              "if (on) { open(); turnOn(); }", "netChanged()", "'tftp.state'", "'tftp.transfer'", "TNT.api.tftpStatus()", "TNT.api.tftpStart(",
              "TNT.api.tftpStop()", "TNT.api.tftpUploads(", "TNT.api.tftpSettings(", "TNT.api.tftpFiles()", "'Allow uploads'", "OPEN_FAILED_TEXT",
              "h('div', { class: 'dhcp-info warn tftp-uploads-note' }, TNT.ui.icon('warning'), h('span', null, UPLOADS_NOTE))"):
        assert s in tftp, s
    # the yellow note goes with the "Allow uploads" switch whether uploads are on or off (§9.7)
    assert "uploadsNote.hidden" not in tftp

    cap = _read("js/views/capture.js")
    for s in ("TNT.views.capture = {", "'capture.state'", "'capture.sip'", "netChanged()", "TNT.api.captureGet()",
              "TNT.api.captureStart(", "TNT.api.captureStop()", "TNT.api.captureSave()", "TNT.api.captureDiscard()",
              "TNT.api.captureOpen(", "TNT.api.capturePackets(filterQuery(filter, null))", "TNT.api.capturePackets(filterQuery(filter, lastNo))",
              "TNT.api.capturePacket(", "TNT.api.captureCalls()", "TNT.api.captureDeleteFile(", "err.code === 'admin_required'",
              # the packet list: tailed from the last row number, started over when the ring rolled past it, capped in the DOM
              "if (r.dropped_before) {", "els.tbody.children.length - DOM_ROWS",
              # leaving with a capture that was never saved: Save / Discard / Stay, and the same warning on the window
              "foot: [stay, throwAway, keep]", "window.addEventListener('beforeunload', beforeUnload)", "e.returnValue = ''",
              # a call's audio is fetched as a blob, so a 404 never navigates the page
              "const res = await fetch(TNT.api.captureCallAudioUrl(call.id), { credentials: 'same-origin' });", "URL.createObjectURL(blob)"):
        assert s in cap, s
    # a saved capture is downloaded through a link the page makes and throws away, never by navigating
    assert ("const a = h('a', { href: TNT.api.captureFileUrl(name), download: name, hidden: true });" in cap
            and "document.body.appendChild(a);" in cap and "a.click();" in cap and "a.remove();" in cap)
    assert "target:" not in cap
    # the page works in a plain browser tab: the one thing it asks the TNT window for is the native file picker, it
    # checks for it first (hasPicker) and hides Browse… without it, and the path field opens a file either way
    bridge = [line.strip() for line in cap.splitlines() if "window.pywebview" in line]
    assert bridge == [
        "return !!(window.pywebview && window.pywebview.api && typeof window.pywebview.api.pick_capture_file === 'function');",
        "const picked = await window.pywebview.api.pick_capture_file();"], bridge
    assert "hidden: !hasPicker()" in cap
    for s in ("TNT.api.captureOpenPath(what.path)", "TNT.api.captureOpen(what.name)"):
        assert s in cap, s
    # the only place the page sets location is the in-app link it held back while asking about an unsaved capture
    assert re.findall(r"\blocation\.\w+", cap) == ["location.hash"]
