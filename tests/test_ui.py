"""Tests for the web UI (ui/) and its development server (tools/mock_api.py).

The UI itself is plain HTML/CSS/JS with no build step, so the checks here are structural
(script order, view registration, no external resources, theme tokens, font fallback) plus
a syntax pass with node when it is installed.  The mock API server is stdlib-only and does
not import ``tnt``; it is loaded straight from its file and run on an ephemeral port so
every ``/api`` route can be exercised, including the SSE stream.
"""
from __future__ import annotations

import copy
import http.client
import importlib.util
import ipaddress
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "ui"
MOCK = ROOT / "tools" / "mock_api.py"
JS_FILES = [
    "js/api.js", "js/charts.js", "js/wifichart.js", "js/hosttable.js",
    "js/tools/subnet.js", "js/tools/traceroute.js", "js/tools/lan.js", "js/tools/subnetcalc.js", "js/tools/wifi.js",
    "js/reportsui.js",
    "js/views/ipinfo.js", "js/views/ping.js",
    "js/views/outages.js", "js/views/speed.js", "js/views/discovery.js", "js/views/tools.js", "js/views/wifi.js",
    "js/views/reports.js",
    "js/egg.js", "js/app.js",
]
VIEW_NAMES = ["ipinfo", "ping", "outages", "speed", "discovery", "wifi", "tools", "reports"]
MOCK_BRIDGE = ROOT / "tools" / "mock_wifi_bridge.js"


# ---------------------------------------------------------------------------
# static UI checks
# ---------------------------------------------------------------------------
def _read(rel: str) -> str:
    return (UI / rel).read_text(encoding="utf-8")


def _doc(rel: str) -> str:
    """A Markdown contract doc (``docs/DESIGN.md``, ``docs/ARCHITECTURE.md``), or skip the test.

    The Markdown docs are not part of the published source tree, so the checks that keep them in
    step with the UI only run where the docs exist.
    """
    path = ROOT / rel
    if not path.is_file():
        pytest.skip(f"{rel} is not in this checkout (the Markdown docs are not published)")
    return path.read_text(encoding="utf-8")


def test_doc_helper_skips_when_the_markdown_docs_are_missing(monkeypatch, tmp_path):
    """The public source tree has no *.md: a doc-sync test must skip there, not fail."""
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    with pytest.raises(pytest.skip.Exception, match="not published"):
        _doc("docs/DESIGN.md")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "DESIGN.md").write_text("# design\n", encoding="utf-8")
    assert _doc("docs/DESIGN.md") == "# design\n"


def test_ui_files_exist():
    for rel in ["index.html", "css/tnt.css", "assets/fonts/README.txt"] + JS_FILES:
        assert (UI / rel).is_file(), rel


def test_index_loads_scripts_in_contract_order():
    html = _read("index.html")
    assert '<link rel="stylesheet" href="css/tnt.css">' in html
    assert re.search(r'<html[^>]*\sdata-theme="light"', html)
    srcs = re.findall(r'<script src="([^"]+)"></script>', html)
    assert srcs == JS_FILES
    for name in VIEW_NAMES:
        assert f'id="tile-{name}"' in html and f'data-view="{name}"' in html
    for el in ("status-pill", "live-badge", "btn-settings", "view", "diagnostics", "toasts", "modal-root"):
        assert f'id="{el}"' in html


def test_each_view_registers_itself():
    for name in VIEW_NAMES:
        src = _read(f"js/views/{name}.js")
        assert re.search(rf"TNT\.views\.{name}\s*=\s*\{{", src), name
        for fn in ("mount(", "update(", "unmount("):
            assert fn in src, (name, fn)


def test_app_exposes_bridge_and_helpers():
    app = _read("js/app.js")
    assert "TNT.setTheme" in app
    assert "pywebview" in app and "save_file" in app
    assert "localStorage.setItem('tnt.theme'" in app
    assert "updateSettings({ ui: { theme } })" in app
    api = _read("js/api.js")
    assert "new EventSource(BASE + '/events')" in api
    assert "status.poll" in api and "pollInterval = 5000" in api


def test_no_external_resources_anywhere():
    files = ["index.html", "css/tnt.css"] + JS_FILES
    bad = re.compile(r"""(?:src|href)=["']https?://|url\(\s*["']?https?://|@import\b|new EventSource\(["']https?://|fetch\(["']https?://""")
    for rel in files:
        text = _read(rel)
        assert not bad.search(text), f"external resource reference in {rel}"


def test_font_face_is_optional_with_fallback_stack():
    css = _read("css/tnt.css")
    assert "@font-face" in css and "Nunito-Variable.ttf" in css and "font-display: swap" in css
    m = re.search(r"--font:\s*([^;]+);", css)
    assert m and '"Nunito"' in m.group(1) and '"Segoe UI"' in m.group(1) and "sans-serif" in m.group(1)
    readme = _read("assets/fonts/README.txt")
    assert "Nunito-Variable.ttf" in readme and "OFL" in readme


def test_theme_tokens_light_and_dark():
    css = _read("css/tnt.css")
    root = re.search(r":root\s*\{(.*?)\}", css, re.S).group(1)
    dark = re.search(r'\[data-theme="dark"\]\s*\{(.*?)\}', css, re.S).group(1)
    expect_light = {"--bg": "#FFF7E8", "--paper": "#FFFFFF", "--ink": "#2B2438", "--red": "#FF5C5C", "--green": "#6BCB77"}
    expect_dark = {"--bg": "#1E1B2E", "--paper": "#2A2640", "--ink": "#F3EEFF", "--red": "#FF6B6B", "--green": "#7ED987"}
    for k, v in expect_light.items():
        assert f"{k}: {v}" in root, k
    for k, v in expect_dark.items():
        assert f"{k}: {v}" in dark, k
    assert "tabular-nums" in css
    assert "prefers-reduced-motion" in css
    assert "overflow-x: auto" in css  # tables scroll inside their container


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_js_syntax_with_node():
    for rel in JS_FILES:
        r = subprocess.run(["node", "--check", str(UI / rel)], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, f"{rel}: {r.stderr}"


# ---------------------------------------------------------------------------
# discovery view: sortable columns, add-as-ping-target, open-port links
# ---------------------------------------------------------------------------
def test_discovery_view_markup_and_helpers():
    # the table machinery is shared (js/hosttable.js); discovery.js builds its table on it
    ht = _read("js/hosttable.js")
    src = _read("js/views/discovery.js")
    assert "TNT.hosttable = {" in ht and "TNT.hosttable.create(" in src
    # sortable headers are real buttons inside <th aria-sort>, remembered across renders/reloads
    assert "'aria-sort'" in ht and "th-sort" in ht and "'ascending'" in ht and "'descending'" in ht
    assert "localStorage" in ht and "tnt.discovery.sort" in src and "storeKey: SORT_STORE" in src
    # add-as-ping-target button on the IP cell, separate from the copy-on-click code element
    assert "add-target" in ht and "TNT.api.addTarget(" in ht and "e.stopPropagation()" in ht
    assert "' as a ping target'" in ht and "' to Ping'" in ht
    assert "TNT.api.targets()" in ht and "state.targets" in src
    # open-port pills are anchors opened through the bridge-aware helper; middle-click keeps working
    assert "TNT.openExternal(" in ht and "target: '_blank'" in ht and "rel: 'noopener'" in ht
    assert "'http://'" in ht and "'https://'" in ht
    # hosttable.js loads before app.js: TNT.util / TNT.ui may only be touched inside functions
    top_level = [ln for ln in ht.splitlines() if re.match(r"^  (const|let|var) ", ln)]
    assert not any("TNT.util." in ln and "=>" not in ln for ln in top_level), top_level
    # the scan is built in: the run's method is shown as recorded (older runs may name another one)
    assert "h('span', { class: 'badge orange' }, run.method || 'native')" in src and "s.default_range" in src
    app = _read("js/app.js")
    # Settings > Speed tests offers exactly the built-in backends
    assert "[['auto', 'Auto (Cloudflare, else fast.com)'], ['cloudflare', 'Cloudflare'], ['fastcom', 'fast.com']].map(" in app
    assert "TNT.openExternal = openExternal" in app
    assert "window.pywebview.api.open_url" in app and "window.open(url, '_blank', 'noopener')" in app
    # the Device Type column: rendered from the payload, with the fallback classifier for rows
    # that predate the field - the rules themselves live in tnt/discovery.py, not here
    assert "{ key: 'device_type', label: 'Device Type' }" in src
    assert "classify_device" in ht and "hst.device_type" in ht
    assert "'device_type' in hst" in ht and "internet_nic" in ht
    assert "DEVICE_TYPE_CLASS = { router: 'blue', 'dw server': 'purple', camera: 'orange', phone: 'green', ubiquiti: 'yellow' }" in ht
    assert "LEGACY_DEVICE_TYPES = new Map([['Wifi', 'Ubiquiti']])" in ht
    css = _read("css/tnt.css")
    assert "discovery results" in css
    for sel in (".table th.sortable", ".th-sort", ".sort-arrow", '.th-sort[data-dir="desc"]', ".table td.ip-cell",
                ".add-target", ".table td.ip-cell:focus-within .add-target", ".add-target.is-target",
                "a.pill.port-link", "a.pill.port-link .ext", ".table td.device-type",
                ".discovery-table th:first-child, .discovery-table td.ip-cell"):
        assert sel in css, sel
    # the IP column is pinned to its own content so Hostname/Device Type/Vendor get the slack
    assert "width: 1%; white-space: nowrap;" in css


def test_tools_view_markup_tile_and_danger_modal():
    html = _read("index.html")
    assert 'data-view="tools" href="#tools" style="--accent: var(--red)"' in html
    assert 'data-icon="tools"' in html and 'id="tile-tools"' in html
    app = _read("js/app.js")
    assert "tools: 'var(--red)'" in app and "'discovery', 'wifi', 'tools'" in app
    assert "tools:" in app and "warning:" in app and "dhcp:" in app  # icons
    # the Tools tile: the DHCP server's state, then the other tools by name as plain text
    assert "tileEls.tools" in app and "DHCP client" in app and "Tools for the field" not in app
    assert "const TOOLS_TILE_ITEMS = ['LAN throughput', 'Traceroute', 'Subnet calc', 'WiFi passwords'];" in app
    assert "TOOLS_TILE_ITEMS.map((name) => line(esc(name), 'tile-tool'))" in app
    # in two columns where the tile has room, so the list does not make the Tools tile's row taller than the others
    assert "'<div class=\"tile-tools\">' + TOOLS_TILE_ITEMS.map(" in app
    assert ".tile-tools { display: grid; grid-template-columns: repeat(auto-fill, minmax(112px, 1fr));" in _read("css/tnt.css")
    assert "ev.on('dhcp.state'" in app and "ev.on('dhcp.lease'" in app
    api = _read("js/api.js")
    for fn in ("dhcpStatus", "dhcpLeases", "dhcpScan", "dhcpStart", "dhcpStop", "dhcpSettings", "dhcpForget"):
        assert fn + ":" in api, fn
    assert "'/dhcp/start'" in api and "'/dhcp/scan'" in api and "this.body = body" in api
    src = _read("js/views/tools.js")
    assert "tnt.dhcp.sort" in src and "TNT.hosttable.create(" in src
    for s in ("Checking for other DHCP servers…", "Another DHCP server is already active", "Proceed anyway", "btn-danger",
              "classList.add('danger')", "No clients yet — devices that ask for an address appear here",
              "The DHCP server is not available on this service", "TNT.util.h", "'dhcp.state'", "'dhcp.lease'", "'dhcp.scan'",
              "TNT.api.dhcpForget(", "TNT.ui.confirm(", "untilText", "Auto (Ethernet)", "Check for other DHCP servers"):
        assert s in src, s
    assert "err.status === 409" in src and "turnOn(true)" in src
    # F12: the chosen adapter being this PC's internet connection is flagged loudly (card box, <select>
    # entry and the danger modal's checked-adapters line), driven only by the service's is_internet flag
    assert "a.is_internet !== true) return null" in src and "is_internet === true" in src
    assert "' (internet)'" in src and "is this PC's internet connection" in src and "with no gateway" in src
    assert "els.inet" in src and "'bad loud'" in src and "role: 'alert'" in src
    assert "internetWarning(status && status.adapter)" in src and "checkedText(probed)" in src
    # a start attempt that failed because the pre-start scan itself failed lands in the scan box too
    assert "err.status === 500 && /^could not check/i.test(" in src and "renderScanError(err.message)" in src
    assert "Could not check for other DHCP servers" in src and "if (scanError) { renderScanError(scanError); return; }" in src
    # the yellow box never repeats the "another DHCP server is active" warning while the red scan
    # box above already lists those servers; any other warning still shows
    assert "status.scan && (status.scan.servers || []).length" in src
    assert "/^another dhcp server is active/i.test(status.warning || '')" in src
    assert "status.warning && !dupWarning" in src
    css = _read("css/tnt.css")
    assert ".tiles > .tile" in css and "grid-column: span" not in css     # the tile row: equal widths, see test_tile_grid_rules
    for sel in (".modal.danger", ".hazard-tape", ".scan-box.bad", ".scan-box.ok", ".server-item", ".toggle.lg", ".lease-cell",
                ".btn-forget", ".dhcp-info", ".dhcp-info.loud", ".modal.danger .dhcp-info.loud"):
        assert sel in css, sel
    # the theme rule: no literal colours in the new rules, tokens only (the tape uses --yellow/--shadow)
    tools_css = css[css.index("tools: DHCP server card"):css.index("/* ---------- ip info")]
    assert not re.search(r"#[0-9A-Fa-f]{3,6}\b", tools_css), "hard-coded colour in the tools CSS"


_SORT_HOSTS = [
    {"ip": "10.0.0.10", "hostname": "nas.lan", "mac": "00:11:32:12:34:02", "vendor": "Synology", "ping_ok": True, "rtt_ms": 0.9, "open_ports": [80, 443, 8080]},
    {"ip": "10.0.0.9", "hostname": None, "mac": None, "vendor": None, "ping_ok": False, "rtt_ms": None, "open_ports": [443]},
    {"ip": "10.0.0.100", "hostname": "Alpha.lan", "mac": "C0:56:E3:12:34:04", "vendor": "hikvision", "ping_ok": True, "rtt_ms": 11.2, "open_ports": []},
    {"ip": "10.0.0.2", "hostname": "beta.lan", "mac": "3C:D9:2B:12:34:03", "vendor": "Apple", "ping_ok": True, "rtt_ms": 2.0, "open_ports": [22, 8443, 9000]},
]

_NODE_SORT_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
function ipKey(ip) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || '');
  if (!m) return Number.MAX_SAFE_INTEGER;
  return ((+m[1]) * 16777216) + ((+m[2]) * 65536) + ((+m[3]) * 256) + (+m[4]);
}
const window = { TNT: { views: {}, util: { ipKey }, api: {}, ui: {} } };
const ctx = vm.createContext({ window, console });
// hosttable.js first (discovery.js builds on it), exactly like index.html
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'hosttable.js' });
vm.runInContext(fs.readFileSync(process.argv[3], 'utf8'), ctx, { filename: 'discovery.js' });
const view = window.TNT.views.discovery;
const hosts = JSON.parse(fs.readFileSync(process.argv[4], 'utf8'));
const out = { columns: view.columns, urls: {} };
for (const key of view.columns) for (const dir of ['asc', 'desc']) out[key + ':' + dir] = view.sortHosts(hosts, key, dir).map((h) => h.ip);
for (const p of [80, 443, 22, 554, 8080]) out.urls[p] = view.portUrl('10.0.0.5', p);
out.actions = {};
for (const p of [80, 443, 22, 554, 7001, 8000, 8080, 8443, 9000, 3389]) out.actions[p] = view.portAction(p);
out.csv = view.runToCsv({ hosts: [{ ip: '10.0.0.5', hostname: 'a,b', mac: 'AA:BB', vendor: 'X "Y"', ping_ok: true, rtt_ms: 1.5, open_ports: [22, 80], device_type: 'Camera' },
                                 { ip: '10.0.0.6', hostname: null, mac: null, vendor: null, ping_ok: false, rtt_ms: null, open_ports: [] }] });
// device type: the payload wins, the fallback (same rules as tnt/discovery.py) only fires when
// the row has no device_type key at all, and every type maps to a badge colour
out.deviceType = {
  payload: view.deviceType({ ip: '10.0.0.9', device_type: 'Phone', open_ports: [554] }),
  emptyString: view.deviceType({ ip: '10.0.0.9', device_type: '', open_ports: [554] }),
  explicitNull: view.deviceType({ ip: '10.0.0.9', device_type: null, open_ports: [554] }),
  fallback: view.deviceType({ ip: '10.0.0.9', open_ports: [554] }),
  legacy: view.deviceType({ ip: '10.0.0.240', device_type: 'Wifi', open_ports: [22] }),   // 1.11 and older said "Wifi"
  none: view.deviceType(null),
};
out.classify = {
  router: view.classifyDevice({ ip: '10.0.0.251', open_ports: [80, 443] }, '10.0.0.251'),
  routerList: view.classifyDevice({ ip: '192.168.1.1', open_ports: [7001] }, ['10.0.0.251', '192.168.1.1']),
  routerBeatsService: view.classifyDevice({ ip: '10.0.0.251', open_ports: [7001, 554, 5060, 22], vendor: 'Ubiquiti Inc.' }, '10.0.0.251'),
  dw: view.classifyDevice({ ip: '10.0.0.112', open_ports: [7001, 8000] }, '10.0.0.251'),
  camera: view.classifyDevice({ ip: '10.0.0.35', open_ports: [80, 554] }, null),
  phone: view.classifyDevice({ ip: '10.0.0.62', open_ports: [80, 5060] }, null),
  ubiquiti: view.classifyDevice({ ip: '10.0.0.240', open_ports: [22, 80], vendor: 'Ubiquiti Networks Inc.' }, null),
  ubiquitiCase: view.classifyDevice({ ip: '10.0.0.241', open_ports: [22], vendor: 'UBIQUITI INC' }, null),
  sshNotUbiquiti: view.classifyDevice({ ip: '10.0.0.130', open_ports: [22], vendor: 'Raspberry Pi Trading Ltd' }, null),
  ubiquitiNoSsh: view.classifyDevice({ ip: '10.0.0.9', open_ports: [80, 443], vendor: 'Ubiquiti Inc.' }, null),
  noPorts: view.classifyDevice({ ip: '10.0.0.9', open_ports: [] }, null),
  noVendor: view.classifyDevice({ ip: '10.0.0.9', open_ports: [22] }, null),
  nothing: view.classifyDevice(null, null),
};
out.badges = {};
for (const t of window.TNT.hosttable.DEVICE_TYPES) out.badges[t] = view.deviceTypeClass(t);
out.badges.unknown = view.deviceTypeClass(null);
out.badges.legacyWifi = view.deviceTypeClass('Wifi');
const dtHosts = [{ ip: '10.0.0.4', device_type: null }, { ip: '10.0.0.1', device_type: 'Router' },
                 { ip: '10.0.0.3', device_type: 'camera' }, { ip: '10.0.0.2', device_type: 'Phone' }];
out.dt_asc = view.sortHosts(dtHosts, 'device_type', 'asc').map((h) => h.ip);
out.dt_desc = view.sortHosts(dtHosts, 'device_type', 'desc').map((h) => h.ip);
// the input must not be reordered in place
out.untouched = hosts.map((h) => h.ip);
// add-as-target check state: an ip added from the table stays checked through a stale targets
// snapshot, then is handed back to the service once listed so a removal elsewhere clears it
view.noteLocalAdd('10.0.0.35');
out.keys = [
  [...view.targetKeysFrom([])].sort(),
  [...view.targetKeysFrom([{ host: '10.0.0.35', ip: '10.0.0.35' }, { host: 'gateway', ip: '10.0.0.251' }])].sort(),
  [...view.targetKeysFrom([{ host: 'gateway', ip: '10.0.0.251' }])].sort(),
];
// the shared module sorts custom columns too (used by the DHCP clients table's Lease column)
const ht = window.TNT.hosttable;
const rank = { bound: 0, offered: 1, declined: 2, released: 3, expired: 4 };
const leaseCol = { key: 'lease', kind: 'custom', numeric: true, sortValue: (l) => [!l.state, rank[l.state] == null ? 9 : rank[l.state], l.expires_ts || 0] };
const leases = [{ ip: '10.0.0.3', state: 'offered', expires_ts: 50 }, { ip: '10.0.0.1', state: 'bound', expires_ts: 200 },
                { ip: '10.0.0.2', state: 'bound', expires_ts: 100 }, { ip: '10.0.0.4', state: null }];
out.lease_asc = ht.sortHosts(leases, 'lease', 'asc', ['ip', leaseCol]).map((l) => l.ip);
out.lease_desc = ht.sortHosts(leases, 'lease', 'desc', ['ip', leaseCol]).map((l) => l.ip);
out.normalized = ht.normalizeColumns(['ip', { key: 'rtt', label: 'Ping' }, leaseCol]).map((c) => c.key + ':' + c.kind);
out.loadSort = ht.loadSort('tnt.x.sort', ['ip', 'mac']);
process.stdout.write(JSON.stringify(out));
"""

_NODE_TOOLS_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
function ipKey(ip) { const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || ''); return m ? ((+m[1]) * 16777216) + ((+m[2]) * 65536) + ((+m[3]) * 256) + (+m[4]) : Number.MAX_SAFE_INTEGER; }
function untilText(ts, now) { if (ts == null) return '—'; const d = ts - now; if (d <= 0) return 'any moment'; if (d < 60) return 'in ' + Math.round(d) + ' s'; if (d < 3600) return 'in ' + Math.round(d / 60) + ' min'; return 'in ' + Math.floor(d / 3600) + ' h ' + Math.round((d % 3600) / 60) + ' min'; }
function relTime(ts, now) { if (ts == null) return '—'; const d = Math.max(0, now - ts); if (d < 5) return 'just now'; if (d < 60) return Math.round(d) + ' s ago'; if (d < 3600) return Math.round(d / 60) + ' min ago'; return Math.floor(d / 3600) + ' h ago'; }
function fmtDuration(s) { if (s == null) return '—'; if (s < 60) return s + ' s'; if (s < 3600) return Math.floor(s / 60) + 'm'; if (s < 86400) return Math.floor(s / 3600) + 'h'; return Math.floor(s / 86400) + 'd'; }
const window = { TNT: { views: {}, util: { ipKey, untilText, relTime, fmtDuration }, api: {}, ui: {} } };
const ctx = vm.createContext({ window, console });
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'hosttable.js' });
vm.runInContext(fs.readFileSync(process.argv[3], 'utf8'), ctx, { filename: 'tools.js' });
const view = window.TNT.views.tools;
const now = 1000000;
const out = { columns: view.columns, lease: {}, server: null };
for (const [k, l] of Object.entries({
  bound: { state: 'bound', expires_ts: now + 3480 }, offered: { state: 'offered', expires_ts: now + 30 },
  released: { state: 'released', last_ts: now - 120 }, expired: { state: 'expired', expires_ts: now - 7200 },
  declined: { state: 'declined' }, unknown: { state: null },
})) out.lease[k] = view.leaseText(l, now);
out.server = view.serverSummary({ adapter: 'Ethernet', nic_ip: '10.0.0.112', server_ip: '10.0.0.251', source_ip: '10.0.0.251', offered_ip: '10.0.0.191',
                                  lease_s: 86400, router: '10.0.0.251', mask: '255.255.255.0', dns: ['10.0.0.251'], known: true, answered: true });
out.server2 = view.serverSummary({ adapter: 'Wi-Fi', nic_ip: '192.168.1.5', server_ip: '192.168.1.1', source_ip: '192.168.1.2', known: false, answered: true });
const base = [{ mac: 'AA:BB:CC:00:00:01', ip: '172.16.4.101', state: 'offered' }, { mac: 'AA:BB:CC:00:00:02', ip: '172.16.4.102', state: 'bound' }];
out.apply = {
  replace: view.applyLease(base, { mac: 'AA:BB:CC:00:00:01', ip: '172.16.4.101', state: 'bound' }).map((l) => l.mac + ':' + l.state),
  append: view.applyLease(base, { mac: 'AA:BB:CC:00:00:03', ip: '172.16.4.103', state: 'offered' }).length,
  forgotten: view.applyLease(base, { mac: 'AA:BB:CC:00:00:01', state: 'forgotten' }).map((l) => l.mac),
  forgottenUnknown: view.applyLease(base, { mac: 'AA:BB:CC:00:00:09', state: 'forgotten' }).length,
  untouched: base.length,
};
// F12: adapter <select> labels and the "this is the PC's internet connection" warning
const eth = { name: 'Ethernet', ip: '10.0.0.112', prefix: 24, dhcp_enabled: true, is_internet: true, will_change: true, changed: false, static_ip: '172.16.4.100', static_prefix: 24 };
out.labels = {
  inet: view.adapterLabel(eth),
  plain: view.adapterLabel({ name: 'vEthernet (Default Switch)', ip: '172.29.64.1', prefix: 20, dhcp_enabled: false, is_internet: false }),
  legacy: view.adapterLabel({ name: 'Wi-Fi', ip: null, dhcp_enabled: true }),
};
out.inet = {
  readdressed: view.internetWarning(eth),
  running: view.internetWarning(Object.assign({}, eth, { will_change: false, changed: true })),
  static: view.internetWarning({ name: 'Ethernet 2', ip: '192.168.5.2', prefix: 24, dhcp_enabled: false, is_internet: true, will_change: false, changed: false }),
  notInternet: view.internetWarning(Object.assign({}, eth, { is_internet: false })),
  legacy: view.internetWarning({ name: 'Ethernet', dhcp_enabled: true, will_change: true }),
  truthyString: view.internetWarning(Object.assign({}, eth, { is_internet: 'yes' })),
  none: view.internetWarning(null),
};
process.stdout.write(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_discovery_sort_order_and_port_urls_with_node(tmp_path):
    driver = tmp_path / "driver.js"
    driver.write_text(_NODE_SORT_DRIVER, encoding="utf-8")
    fixture = tmp_path / "hosts.json"
    fixture.write_text(json.dumps(_SORT_HOSTS), encoding="utf-8")
    r = subprocess.run(["node", str(driver), str(UI / "js/hosttable.js"), str(UI / "js/views/discovery.js"), str(fixture)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    # Device Type sits between MAC and Vendor
    assert out["columns"] == ["ip", "hostname", "mac", "device_type", "vendor", "rtt", "ports"]
    # custom (lease) column: bound before offered, then by expiry; missing state last either way
    assert out["lease_asc"] == ["10.0.0.2", "10.0.0.1", "10.0.0.3", "10.0.0.4"]
    assert out["lease_desc"] == ["10.0.0.3", "10.0.0.1", "10.0.0.2", "10.0.0.4"]
    assert out["normalized"] == ["ip:ip", "rtt:num", "lease:custom"]
    assert out["loadSort"] == {"key": "ip", "dir": "asc"}  # no localStorage in node: the default
    assert out["untouched"] == ["10.0.0.10", "10.0.0.9", "10.0.0.100", "10.0.0.2"]
    # IP: dotted-quad aware (2 < 9 < 10 < 100), not lexicographic
    assert out["ip:asc"] == ["10.0.0.2", "10.0.0.9", "10.0.0.10", "10.0.0.100"]
    assert out["ip:desc"] == ["10.0.0.100", "10.0.0.10", "10.0.0.9", "10.0.0.2"]
    # text columns: case-insensitive, empty last in both directions
    assert out["hostname:asc"] == ["10.0.0.100", "10.0.0.2", "10.0.0.10", "10.0.0.9"]
    assert out["hostname:desc"] == ["10.0.0.10", "10.0.0.2", "10.0.0.100", "10.0.0.9"]
    assert out["vendor:asc"] == ["10.0.0.2", "10.0.0.100", "10.0.0.10", "10.0.0.9"]
    assert out["vendor:desc"] == ["10.0.0.10", "10.0.0.100", "10.0.0.2", "10.0.0.9"]
    assert out["mac:asc"] == ["10.0.0.10", "10.0.0.2", "10.0.0.100", "10.0.0.9"]
    assert out["mac:desc"] == ["10.0.0.100", "10.0.0.2", "10.0.0.10", "10.0.0.9"]
    # RTT numeric, "no reply" last either way
    assert out["rtt:asc"] == ["10.0.0.10", "10.0.0.2", "10.0.0.100", "10.0.0.9"]
    assert out["rtt:desc"] == ["10.0.0.100", "10.0.0.2", "10.0.0.10", "10.0.0.9"]
    # open ports: by count, then lowest port (22 before 80 among the 3-port hosts); none last
    assert out["ports:asc"] == ["10.0.0.9", "10.0.0.2", "10.0.0.10", "10.0.0.100"]
    assert out["ports:desc"] == ["10.0.0.10", "10.0.0.2", "10.0.0.9", "10.0.0.100"]
    # port 80 is plain http, other web ports https; 22 opens ssh through the client; 554 and custom ports do nothing
    assert out["urls"]["80"] == "http://10.0.0.5/" and out["urls"]["8080"] == "https://10.0.0.5:8080/"
    assert out["actions"] == {"80": "web", "443": "web", "7001": "web", "8000": "web", "8080": "web", "8443": "web",
                              "22": "ssh", "554": "none", "9000": "none", "3389": "none"}
    lines = out["csv"].split("\r\n")
    assert lines[0] == "ip,hostname,mac,device_type,vendor,ping_reply,rtt_ms,open_ports"
    assert lines[1] == '10.0.0.5,"a,b",AA:BB,Camera,"X ""Y""",yes,1.5,22 80'
    assert lines[2] == "10.0.0.6,,,,,no,,"
    # device type: the service's answer is rendered as-is; the fallback (identical rules to
    # tnt/discovery.py classify_device) only runs for rows from a service that had no such field
    assert out["deviceType"] == {"payload": "Phone", "emptyString": None, "explicitNull": None,
                                 "fallback": "Camera", "legacy": "Ubiquiti", "none": None}
    assert out["classify"] == {"router": "Router", "routerList": "Router", "routerBeatsService": "Router",
                               "dw": "DW Server", "camera": "Camera", "phone": "Phone", "ubiquiti": "Ubiquiti",
                               "ubiquitiCase": "Ubiquiti", "sshNotUbiquiti": None, "ubiquitiNoSsh": None,
                               "noPorts": None, "noVendor": None, "nothing": None}
    # a type stored by 1.11 or older ("Wifi") keeps its colour under its new name
    assert out["badges"] == {"Router": "blue", "DW Server": "purple", "Camera": "orange", "Phone": "green",
                             "Ubiquiti": "yellow", "unknown": "grey", "legacyWifi": "yellow"}
    # sortable like the other text columns: case-insensitive, unknown last in both directions
    assert out["dt_asc"] == ["10.0.0.3", "10.0.0.2", "10.0.0.1", "10.0.0.4"]
    assert out["dt_desc"] == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    # check state: kept through a stale snapshot, released once the service lists it, gone after removal
    assert out["keys"] == [["10.0.0.35"], ["10.0.0.251", "10.0.0.35", "gateway"], ["10.0.0.251", "gateway"]]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_tools_lease_badges_and_server_summary_with_node(tmp_path):
    driver = tmp_path / "driver.js"
    driver.write_text(_NODE_TOOLS_DRIVER, encoding="utf-8")
    r = subprocess.run(["node", str(driver), str(UI / "js/hosttable.js"), str(UI / "js/views/tools.js")],
                       capture_output=True, text=True, encoding="utf-8", timeout=30)  # the labels carry an em-dash
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["columns"] == ["ip", "hostname", "mac", "vendor", "rtt", "ports", "lease", "actions"]
    lease = out["lease"]
    assert lease["bound"] == {"cls": "green", "label": "bound", "detail": "expires in 58 min"}
    assert lease["offered"] == {"cls": "yellow", "label": "offered", "detail": "offer expires in 30 s"}
    assert lease["released"]["cls"] == "grey" and lease["released"]["detail"] == "released 2 min ago"
    assert lease["expired"]["cls"] == "grey" and lease["expired"]["detail"] == "expired 2 h ago"
    assert lease["declined"]["cls"] == "red" and "refused" in lease["declined"]["detail"]
    assert lease["unknown"] == {"cls": "grey", "label": "unknown", "detail": ""}
    s = out["server"]
    assert s["ip"] == "10.0.0.251" and s["adapter"] == "Ethernet" and s["nic_ip"] == "10.0.0.112"
    assert s["tags"] == ["answered", "known to Windows"]
    assert dict(s["detail"]) == {"offered us": "10.0.0.191", "lease": "1d", "gateway": "10.0.0.251", "mask": "255.255.255.0", "dns": "10.0.0.251"}
    s2 = out["server2"]
    assert s2["tags"] == ["answered"] and dict(s2["detail"]) == {"from": "192.168.1.2"}
    # dhcp.lease events: replace by MAC, append unknown, a "forgotten" stub removes the row (input untouched)
    a = out["apply"]
    assert a["replace"] == ["AA:BB:CC:00:00:01:bound", "AA:BB:CC:00:00:02:bound"]
    assert a["append"] == 3
    assert a["forgotten"] == ["AA:BB:CC:00:00:02"]
    assert a["forgottenUnknown"] == 2 and a["untouched"] == 2
    # F12: the internet NIC is marked in the picker; older services without the flag get the old label
    assert out["labels"] == {"inet": "Ethernet — 10.0.0.112/24 (DHCP) (internet)",
                             "plain": "vEthernet (Default Switch) — 172.29.64.1/20 (static)",
                             "legacy": "Wi-Fi — no IPv4 (DHCP)"}
    w = out["inet"]
    assert w["readdressed"]["name"] == "Ethernet" and w["readdressed"]["readdressed"] is True and w["readdressed"]["address"] == "172.16.4.100/24"
    assert w["readdressed"]["text"] == ("Ethernet is this PC's internet connection. While the DHCP server is on, this PC has no internet "
                                        "through it (it is moved to 172.16.4.100/24 with no gateway). Pick another adapter or plug the PC "
                                        "into the isolated bench network first.")
    assert w["running"]["text"] == w["readdressed"]["text"]  # still true while it runs (changed instead of will_change)
    assert w["static"]["readdressed"] is False and "answers every device on that network" in w["static"]["text"]
    assert "no internet" not in w["static"]["text"] and w["static"]["text"].startswith("Ethernet 2 is this PC's internet connection.")
    # only an explicit true from the service shows anything new
    assert w["notInternet"] is None and w["legacy"] is None and w["truthyString"] is None and w["none"] is None


def test_tools_batch_markup_settings_wan_and_cards():
    """Traceroute / LAN throughput / Subnet calculator cards, the WAN chip and the IPv6 setting."""
    app = _read("js/app.js")
    assert "'IPv6 addresses'" in app and "Show IPv6 addresses and subnets on the Network info page." in app
    assert "saveSettings({ ui: { show_ipv6: v } }" in app and "s.ui && s.ui.show_ipv6" in app
    for icon in ("lan:", "target:", "question:", "route:"):
        assert icon in app, icon
    api = _read("js/api.js")
    for fn, path in (("traceroute", "/tools/traceroute"), ("tracerouteLast", "/tools/traceroute/last"), ("lanPeers", "/tools/lan/peers"),
                     ("lanThroughput", "/tools/lan/throughput"), ("lanThroughputLast", "/tools/lan/throughput/last"),
                     ("lanSettings", "/tools/lan/settings")):
        assert fn + ":" in api and "'" + path + "'" in api, fn
    assert "timeout: 120000" in api and "timeout: 60000" in api
    for ev in ("trace.start", "trace.hop", "trace.done", "lan.peers", "lan.throughput.progress", "lan.throughput.done"):
        assert "'" + ev + "'" in api, ev
    tools = _read("js/views/tools.js")
    for t in ("'Traceroute'", "'LAN throughput'", "'Subnet calculator'"):
        assert t in tools, t
    assert "TNT.tools.traceroute.create()" in tools and "TNT.tools.lan.create()" in tools and "TNT.tools.subnetcalc.create()" in tools
    # card order on the Tools page: DHCP server, LAN throughput, Traceroute, Subnet calculator
    assert "els.card, els.unavailable, cards" in tools            # the DHCP card, then the tool cards
    assert tools.index("'LAN throughput'") < tools.index("'Traceroute'") < tools.index("'Subnet calculator'")
    assert "More tools" not in tools
    tr = _read("js/tools/traceroute.js")
    for s in ("'trace.start'", "'trace.hop'", "'trace.done'", "TNT.api.traceroute(", "TNT.api.tracerouteLast()", "totalelectronics.com",
              "the service keeps tracing", "err.status === 409", "TNT.tools.traceroute = {"):
        assert s in tr, s
    lan = _read("js/tools/lan.js")
    for s in ("'lan.peers'", "'lan.throughput.progress'", "'lan.throughput.done'", "TNT.api.lanPeers()", "TNT.api.lanThroughput(",
              "TNT.api.lanThroughputLast()", "No other TNT machines seen yet", "TNT.ui.fuse()", "PEER_REFRESH_MS = 10000", "[3, 5, 10]",
              # the on/off switch: PUT /tools/lan/settings, and lan.state keeps other windows in step
              "TNT.api.lanSettings(", "'lan.state'"):
        assert s in lan, s
    sc = _read("js/tools/subnetcalc.js")
    assert "TNT.subnet" in sc and "internet_nic" in sc and "TNT.api.netinfo()" in sc
    assert "TNT.subnet = {" in _read("js/tools/subnet.js")
    ipinfo = _read("js/views/ipinfo.js")
    for s in ("public_ip", "'WAN'", "show_ipv6", "visibleGroups(", "renderedV6", "family === 6"):
        assert s in ipinfo, s
    css = _read("css/tnt.css")
    for sel in (".lm-wan", ".tr-map", ".tr-node", ".tr-link", ".tr-rtt.green", ".tr-rtt.yellow", ".tr-rtt.red", ".tr-node.silent", ".tr-hop",
                ".peer-item", ".lan-progress", ".lan-phase", ".lan-result", ".subnet-grid", ".bin-panel", ".bin-panel .net", ".sn-split-list"):
        assert sel in css, sel
    new_css = css[css.index("tools: traceroute, LAN throughput, subnet calculator"):css.index("/* ---------- easter egg")]
    assert not re.search(r"#[0-9A-Fa-f]{3,6}\b", new_css), "hard-coded colour in the new tools CSS"
    # the tool modules load before app.js: TNT.util / TNT.ui may only be touched inside functions
    for rel in ("js/tools/subnet.js", "js/tools/traceroute.js", "js/tools/lan.js", "js/tools/subnetcalc.js"):
        top_level = [ln for ln in _read(rel).splitlines() if re.match(r"^  (const|let|var) ", ln)]
        assert not any(("TNT.util." in ln or "TNT.ui." in ln) and "=>" not in ln for ln in top_level), (rel, top_level)


def test_tools_batch_is_in_the_design_doc():
    docs = _doc("docs/DESIGN.md")
    for s in ("Traceroute", "LAN throughput", "Subnet calculator", "WAN", "IPv6"):
        assert s in docs, s


_NODE_TOOLS_BATCH_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const util = { relTime: (ts, now) => Math.round(now - ts) + ' s ago', fmtDateTime: (ts) => 'Today, 10:00' };
const window = { TNT: { views: {}, util, api: {}, ui: {} } };
const ctx = vm.createContext({ window, console });
const names = ['subnet.js', 'traceroute.js', 'lan.js', 'subnetcalc.js', 'ipinfo.js'];
names.forEach((n, i) => vm.runInContext(fs.readFileSync(process.argv[2 + i], 'utf8'), ctx, { filename: n }));
const S = window.TNT.subnet, T = window.TNT.tools.traceroute, L = window.TNT.tools.lan, C = window.TNT.tools.subnetcalc, I = window.TNT.views.ipinfo;
const out = {};
out.p24 = S.parse('10.0.0.112/24');
out.pmask = S.parse('10.0.0.112 255.255.255.0');
out.pbare = S.parse('10.0.0.112');
out.pslashmask = S.parse(' 10.0.0.112 / 255.255.255.0 ');
out.p30 = S.parse('192.168.1.9/30');
out.p31 = S.parse('192.168.1.9/31');
out.p32 = S.parse('192.168.1.9/32');
out.p0 = S.parse('1.2.3.4/0');
out.p20 = S.parse('172.29.64.1/20');
out.kinds = {};
for (const ip of ['10.1.2.3', '172.20.1.1', '172.32.1.1', '192.168.1.1', '8.8.8.8', '127.0.0.1', '169.254.1.1', '224.0.0.1', '100.64.1.1', '100.128.1.1', '240.0.0.1', '203.0.113.5', '150.1.1.1', '200.1.1.1', '255.255.255.255']) {
  const r = S.parse(ip + '/24'); out.kinds[ip] = [r.class, r.kind];
}
out.errors = {};
for (const t of ['', 'garbage', '300.1.1.1', '10.0.0.1/33', '10.0.0.1 255.0.255.0', '10.0.0/24', '10.0.0.1/abc', '10.0.0.1/-1', 'fe80::1/64']) out.errors[t] = S.parse(t).ok;
out.contains = [S.contains('10.0.0.112/24', '10.0.0.200'), S.contains('10.0.0.112/24', '10.0.1.1'), S.contains('10.0.0.0/24', '10.0.0.128/25'),
  S.contains('10.0.0.0/24', '10.0.0.128/23'), S.contains('garbage', '1.1.1.1'), S.contains('10.0.0.0/24', 'nope'), S.contains('0.0.0.0/0', '8.8.8.8'), S.contains('10.0.0.5/32', '10.0.0.5')];
out.split26 = S.split('10.0.0.0/24', 26);
out.split25 = S.split('10.0.0.112/24', 25);
out.splitCap = S.split('10.0.0.0/8', 24).length;
out.splitCount = S.splitCount('10.0.0.0/8', 24);
out.splitLast = S.split('10.0.0.0/8', 24)[255];
out.splitBad = [S.split('10.0.0.0/24', 24), S.split('10.0.0.0/24', 33), S.split('x', 26), S.split('10.0.0.0/24', 'q')];
out.rtt = [null, undefined, NaN, 0, 5, 19.99, 20, 50, 99.9, 100, 500].map(T.rttClass);
out.icons = {};
for (const k of ['gateway', 'lan', 'public', 'destination', 'unknown', 'weird']) out.icons[k] = T.hopIcon({ ip: '1.1.1.1', kind: k });
out.icons.silent = T.hopIcon({ ip: null, kind: 'gateway' });
out.icons.none = T.hopIcon(null);
out.labels = [T.hopLabel({ ip: null }), T.hopLabel({ ip: '1', kind: 'public' }), T.hopLabel({ ip: '1', kind: 'public', label: 'Custom' }), T.hopLabel({ ip: '1', kind: 'odd' })];
const base = [{ ttl: 1, ip: 'a' }, { ttl: 3, ip: 'c' }];
out.merge = {
  insert: T.mergeHop(base, { ttl: 2, ip: 'b' }).map((h) => h.ttl),
  replace: T.mergeHop(base, { ttl: 3, ip: 'C' }).map((h) => h.ip),
  append: T.mergeHop(base, { ttl: 9, ip: 'z' }).map((h) => h.ttl),
  ignore: T.mergeHop(base, null).length + T.mergeHop(base, {}).length,
  fromNothing: T.mergeHop(null, { ttl: 1 }).length,
  untouched: base.length,
};
const nine = Array.from({ length: 9 }, (_, i) => ({ ttl: i + 1 }));
out.summary = {
  idle: T.summaryText(null, 'idle'),
  running: T.summaryText({ host: 'h', target_ip: '1.2.3.4', max_hops: 30, hops: [{}, {}] }, 'running'),
  done: T.summaryText({ host: 'totalelectronics.com', target_ip: '203.0.113.80', duration_s: 4.21, complete: true, hops: nine }, 'done'),
  ipHost: T.summaryText({ host: '1.1.1.1', target_ip: '1.1.1.1', duration_s: 12.4, complete: true, hops: [{}] }, 'done'),
  incomplete: T.summaryText({ host: 'x', target_ip: '1.1.1.1', max_hops: 4, duration_s: 6, complete: false, hops: [{}, {}, {}, {}] }, 'done'),
  error: T.summaryText({ host: 'x', error: 'could not resolve x', hops: [] }, 'done'),
  cancelled: T.summaryText({ host: 'x', target_ip: '1.1.1.1', hops: [{}] }, 'cancelled'),
};
out.seen = [L.seenText(100, 100.5), L.seenText(100, 112), L.seenText(100, 400), L.seenText(100, 8000), L.seenText(null, null, 7), L.seenText(null, null, null)];
out.phases = { none: L.phaseStates(null), upload: L.phaseStates({ phase: 'upload', pct: 42, mbps: 900 }), connect: L.phaseStates({ phase: 'connect', pct: 10 }),
  download: L.phaseStates({ phase: 'download', pct: 100, mbps: 910 }), over: L.phaseStates({ phase: 'upload', pct: 140 }) };
out.prefill = [C.prefillFrom({ status: { netinfo: { internet_nic: { ipv4: '10.0.0.112/24' } } } }),
  C.prefillFrom({ status: { netinfo: { internet_nic: { ipv4: '10.0.0.112', network: '10.0.0.0/24' } } } }),
  C.prefillFrom({ status: { netinfo: { internet_nic: { ipv4: '10.0.0.112' } } } }), C.prefillFrom(null), C.prefillFrom({ status: { netinfo: {} } }),
  C.prefillFromNetinfo({ internet_nic_index: 12, adapters: [{ index: 21, ipv4: [{ address: '100.101.22.7', prefix: 32 }] }, { index: 12, ipv4: [{ address: '10.0.0.112', prefix: 24 }] }] }),
  C.prefillFromNetinfo({ internet_nic_index: 99, adapters: [{ index: 7, ipv4: [], subnets: [{ network: 'fe80::/64', family: 6, addresses: ['fe80::1'] }, { network: '192.168.7.0/24', family: 4, addresses: ['192.168.7.20'] }] }] }),
  C.prefillFromNetinfo(null)];
// Network info: the IPv6 filter and the WAN chip
const eth = { subnets: [{ network: '10.0.0.0/24', family: 4, mask: '255.255.255.0', addresses: ['10.0.0.112', 'fe80::9'], gateways: ['10.0.0.251', 'fe80::1'] },
                        { network: 'fe80::/64', family: 6, mask: null, addresses: ['fe80::a1b2'], gateways: [] }],
              dns: ['10.0.0.251', '2606:4700:4700::1111'] };
out.v6off = I.visibleGroups(eth, false);
out.v6on = I.visibleGroups(eth, true).map((g) => [g.network, g.addresses.length, g.gateways.length]);
out.dnsOff = I.visibleDns(eth, false);
out.dnsOn = I.visibleDns(eth, true).length;
out.v6none = [I.visibleGroups({}, false), I.visibleGroups(null, true), I.visibleDns(null, false)];
out.wan = [I.wanChip({ ip: '203.0.113.5', ts: 40, error: null }, 100), I.wanChip({ ip: null, ts: null, error: 'timed out' }, 100),
  I.wanChip({ ip: null, ts: null, error: null }, 100), I.wanChip(null, 100), I.wanChip(undefined, 100), I.wanChip({ ip: '1.2.3.4', ts: null, error: null }, 100)];
out.gwRows = {
  both: I.gatewayRows({ gateway: { ip: '10.0.0.251' }, public_ip: { ip: '203.0.113.5', ts: 40, error: null } }, 100).map((r) => [r.tag, r.value, !!r.plain]),
  lanOnly: I.gatewayRows({ gateway: { ip: '10.0.0.251' }, public_ip: null }, 100).map((r) => [r.tag, r.value]),
  wanError: I.gatewayRows({ gateway: { ip: '10.0.0.251' }, public_ip: { ip: null, ts: null, error: 'timed out' } }, 100).map((r) => [r.tag, r.value, !!r.plain]),
  noGateway: I.gatewayRows({ gateway: null, public_ip: null }, 100).map((r) => [r.tag, r.value]),
};
process.stdout.write(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_subnet_math_traceroute_lan_and_ipinfo_helpers_with_node(tmp_path):
    driver = tmp_path / "driver.js"
    driver.write_text(_NODE_TOOLS_BATCH_DRIVER, encoding="utf-8")
    files = [UI / "js/tools/subnet.js", UI / "js/tools/traceroute.js", UI / "js/tools/lan.js", UI / "js/tools/subnetcalc.js", UI / "js/views/ipinfo.js"]
    r = subprocess.run(["node", str(driver)] + [str(f) for f in files], capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    # --- TNT.subnet.parse: the three input forms give the same subnet
    p = out["p24"]
    assert p["ok"] is True and p["ip"] == "10.0.0.112" and p["prefix"] == 24 and p["cidr"] == "10.0.0.0/24" and p["assumed_prefix"] is False
    assert p["mask"] == "255.255.255.0" and p["wildcard"] == "0.0.0.255" and p["network"] == "10.0.0.0" and p["broadcast"] == "10.0.0.255"
    assert p["first_host"] == "10.0.0.1" and p["hosts"] == 256 and p["usable"] == 254
    # the last usable host sits right below the broadcast address asserted above (an exact string)
    assert p["last_host"] == str(ipaddress.IPv4Address("10.0.0.255") - 1)
    assert p["class"] == "A" and p["kind"] == "private" and "RFC 1918" in p["kind_label"]
    assert p["binary"] == {"ip": "00001010.00000000.00000000.01110000", "mask": "11111111.11111111.11111111.00000000"}
    for k in ("pmask", "pslashmask"):
        assert {kk: v for kk, v in out[k].items() if kk != "input"} == {kk: v for kk, v in p.items() if kk != "input"}, k
    bare = out["pbare"]
    assert bare["assumed_prefix"] is True and {k: v for k, v in bare.items() if k not in ("input", "assumed_prefix")} == {k: v for k, v in p.items() if k not in ("input", "assumed_prefix")}
    assert out["p30"]["network"] == "192.168.1.8" and out["p30"]["broadcast"] == "192.168.1.11" and out["p30"]["usable"] == 2 and out["p30"]["first_host"] == "192.168.1.9"
    assert out["p31"]["hosts"] == 2 and out["p31"]["usable"] == 2 and out["p31"]["first_host"] == "192.168.1.8" and out["p31"]["last_host"] == "192.168.1.9"
    assert out["p32"]["hosts"] == 1 and out["p32"]["usable"] == 1 and out["p32"]["first_host"] == "192.168.1.9" == out["p32"]["last_host"] and out["p32"]["mask"] == "255.255.255.255"
    assert out["p0"]["network"] == "0.0.0.0" and out["p0"]["broadcast"] == "255.255.255.255" and out["p0"]["hosts"] == 4294967296 and out["p0"]["mask"] == "0.0.0.0"
    assert out["p20"]["cidr"] == "172.29.64.0/20" and out["p20"]["mask"] == "255.255.240.0" and out["p20"]["broadcast"] == "172.29.79.255" and out["p20"]["usable"] == 4094
    # class and kind
    assert out["kinds"] == {"10.1.2.3": ["A", "private"], "172.20.1.1": ["B", "private"], "172.32.1.1": ["B", "public"], "192.168.1.1": ["C", "private"],
                            "8.8.8.8": ["A", "public"], "127.0.0.1": ["A", "loopback"], "169.254.1.1": ["B", "link-local"], "224.0.0.1": ["D", "multicast"],
                            "100.64.1.1": ["A", "cgnat"], "100.128.1.1": ["A", "public"], "240.0.0.1": ["E", "reserved"], "203.0.113.5": ["C", "reserved"],
                            "150.1.1.1": ["B", "public"], "200.1.1.1": ["C", "public"], "255.255.255.255": ["E", "reserved"]}
    # garbage is an error, never a throw
    assert all(v is False for v in out["errors"].values()), out["errors"]
    # contains / split
    assert out["contains"] == [True, False, True, False, False, False, True, True]
    assert out["split26"] == ["10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"]
    assert out["split25"] == ["10.0.0.0/25", "10.0.0.128/25"]
    assert out["splitCap"] == 256 and out["splitCount"] == 65536 and out["splitLast"] == "10.0.255.0/24"
    assert out["splitBad"] == [[], [], [], []]
    # --- traceroute helpers: rtt colour, icon by kind, hop merge, summary
    assert out["rtt"] == ["grey", "grey", "grey", "green", "green", "green", "yellow", "yellow", "yellow", "red", "red"]
    assert out["icons"] == {"gateway": "router", "lan": "lan", "public": "cloud", "destination": "target", "unknown": "question", "weird": "cloud",
                            "silent": "question", "none": "question"}
    assert out["labels"] == ["No reply", "Internet", "Custom", "Unknown"]
    m = out["merge"]
    assert m["insert"] == [1, 2, 3] and m["replace"] == ["a", "C"] and m["append"] == [1, 3, 9] and m["ignore"] == 4 and m["fromNothing"] == 1 and m["untouched"] == 2
    s = out["summary"]
    assert s["idle"]["cls"] == "muted" and "Run" in s["idle"]["text"]
    assert s["running"] == {"text": "Tracing h (1.2.3.4)… hop 2 of 30", "cls": "live"}
    assert s["done"] == {"text": "9 hops to totalelectronics.com (203.0.113.80) in 4.2 s · complete", "cls": "ok"}
    assert s["ipHost"]["text"] == "1 hop to 1.1.1.1 in 12 s · complete"
    assert s["incomplete"]["cls"] == "warn" and s["incomplete"]["text"].startswith("4 hops to x (1.1.1.1) in 6.0 s · gave up after 4 hops")
    assert s["error"] == {"text": "could not resolve x", "cls": "bad"}
    assert s["cancelled"]["cls"] == "muted" and s["cancelled"]["text"].startswith("Stopped watching after 1 hop")
    # --- LAN helpers
    assert out["seen"] == ["seen just now", "seen 12 s ago", "seen 5 min ago", "seen 2 h ago", "seen 7 s ago", "seen —"]
    ph = out["phases"]
    assert [p["state"] for p in ph["none"]] == ["idle", "idle", "idle"]
    assert [(p["phase"], p["pct"], p["state"]) for p in ph["upload"]] == [("connect", 100, "done"), ("upload", 42, "running"), ("download", 0, "idle")]
    assert ph["upload"][1]["mbps"] == 900
    assert [p["state"] for p in ph["connect"]] == ["running", "idle", "idle"] and [p["state"] for p in ph["download"]] == ["done", "done", "running"]
    assert ph["over"][1]["pct"] == 100
    # --- subnet calculator prefill
    assert out["prefill"] == ["10.0.0.112/24", "10.0.0.112/24", None, None, None, "10.0.0.112/24", "192.168.7.20/24", None]
    # --- Network info: IPv6 hidden -> family-6 groups dropped and IPv6 entries stripped, never counted
    assert out["v6off"] == [{"network": "10.0.0.0/24", "family": 4, "mask": "255.255.255.0", "addresses": ["10.0.0.112"], "gateways": ["10.0.0.251"]}]
    assert out["v6on"] == [["10.0.0.0/24", 2, 2], ["fe80::/64", 1, 0]]
    assert out["dnsOff"] == ["10.0.0.251"] and out["dnsOn"] == 2
    assert out["v6none"] == [[], [], []]
    # --- the WAN chip
    w = out["wan"]
    assert w[0]["ip"] == "203.0.113.5" and "checked 60 s ago" in w[0]["title"] and "10 min" in w[0]["title"]
    assert w[1] == {"error": "timed out", "title": "Public address unknown: timed out"}
    assert w[2] is None and w[3] is None and w[4] is None
    assert w[5]["ip"] == "1.2.3.4" and "not checked yet" in w[5]["title"]
    # --- the gateway node's chip rows: LAN first, WAN under it only when it is known
    g = out["gwRows"]
    assert g["both"] == [["LAN", "10.0.0.251", False], ["WAN", "203.0.113.5", False]]
    assert g["lanOnly"] == [["LAN", "10.0.0.251"]]
    assert g["wanError"] == [["LAN", "10.0.0.251", False], ["WAN", "timed out", True]], "a failed lookup shows as plain muted text, not a copy chip"
    assert g["noGateway"] == [["LAN", None]], "no gateway -> the row is dropped by fillChips, not rendered empty"


# ---------------------------------------------------------------------------
# following this PC onto another network (net.changed, status.net.generation) and the tile grid
# ---------------------------------------------------------------------------
def test_network_change_wiring():
    """net.changed and a newer status.net.generation reach every view that shows network state."""
    api = _read("js/api.js")
    assert "'net.changed'," in api and "api.net = {" in api
    app = _read("js/app.js")
    for s in ("ev.on('net.changed'", "api.net.fromEvent(lastNet, d, Date.now())", "api.net.compare(lastNet, st, Date.now())",
              "current.view.netChanged(merged, state)", "api.net.toastPlan(", "if (refreshing) { refreshAgain = true; return; }",
              "api.net.nicFromEvent(d)", "id: 'settings-gateway'", "setTargets", "api.net.runElsewhere(r.cidr",
              "if (net.stale)", "!net.restarted", "api.net.toastText(info)", "api.net.nicCidr(nic)", "d.network_changed"):
        assert s in app, s
    # every view that shows network state has the hook; the Tools view hands it to its cards
    for rel in ("js/views/ipinfo.js", "js/views/discovery.js", "js/views/tools.js", "js/views/outages.js",
                "js/tools/lan.js", "js/tools/subnetcalc.js", "js/tools/wifi.js"):
        assert "netChanged(" in _read(rel), rel
    tools = _read("js/views/tools.js")
    assert "if (m.netChanged) m.netChanged(info, state)" in tools and "danger.networkChanged()" in tools
    assert "if (busy) { netPending = true; return; }" in tools and "renderAdapterOptions(els.adapter.value)" in tools
    # Auto names the adapter the service picks now (Wi-Fi on a network without Ethernet), not always Ethernet
    assert "'Auto (' + (auto || 'Ethernet') + ')'" in tools and "!(status.settings && status.settings.adapter) && status.adapter" in tools
    assert "api.net.toastWanted(info, showIpv6)" in app and "st.net && st.net.networks" in app and "warningBadge(local)" in app
    ipinfo = _read("js/views/ipinfo.js")
    assert "TNT.api.events.on('net.changed', onNetChanged)" in ipinfo and "netChanged() { if (root) load(true); }" in ipinfo
    assert "if ('ip' in d) p.ip = d.ip;" in ipinfo and "adapterWarnings(a)" in ipinfo
    ping = _read("js/views/ping.js")
    assert "TNT.app.setTargets(list)" in ping and "defaultsToast(list)" in ping and "hostState(t)" in ping
    disc = _read("js/views/discovery.js")
    assert "rangeUpdate({" in disc and "showRangeHint(" in disc and "if (netPending) loadStatus();" in disc
    # a scan the PC changed networks during: discovery.done network_changed, remembered from load, a yellow badge
    assert "netChangedRuns.add(d.run_id)" in disc and "netChangedRuns.has(run.id)" in disc and "/network changed/i" not in disc
    assert "on: { click: () => useThisPc() }" in _read("js/tools/subnetcalc.js")
    css = _read("css/tnt.css")
    for sel in (".adapter-warnings", ".adapter-warn", ".adapter-warn.red", ".adapter-warn.grey", "code.copy.stale"):
        assert sel in css, sel
    # tokens only, like the rest of the stylesheet's newer rules
    warn_css = css[css.index("/* adapter warnings"):css.index(".adapter-warn svg.icon")]
    assert not re.search(r"#[0-9A-Fa-f]{3,6}\b", warn_css)


def test_network_change_is_in_the_design_doc():
    docs = _doc("docs/DESIGN.md")
    for s in ("Network changed", "status.net.generation", "adapter warnings", "gateway off subnet", "checking…", "no default gateway",
              "WiFi, Tools", "--tile-tight", "8 → 4 + 4"):
        assert s in docs, s
    assert "Tools for the field" not in docs


def test_tile_grid_rules():
    """Tiles are the same width in every row for any count: each band picks one row (`flex: 1 1 0`) or balanced
    rows (--tile-cols) by counting the tiles with :first-child:nth-last-child(), widest window first."""
    css = _read("css/tnt.css")
    base = _css_base(css)

    def both(n: str):
        first = f".tiles > .tile:first-child:nth-last-child({n})"
        return [first, first + " ~ .tile"]

    def at(query: str, sel: str) -> Dict[str, str]:
        return _css_decls(_css_media(css, query), sel)

    half = "0 0 calc((100% - var(--tile-gap)) / 2)"
    assert _css_decls(base, ".tiles") == {"--tile-gap": "20px", "display": "flex", "flex-wrap": "wrap", "gap": "var(--tile-gap)"}
    assert _css_decls(base, ".tiles > .tile") == {
        "--tile-cols": "4", "flex": "0 0 calc((100% - (var(--tile-cols) - 1) * var(--tile-gap)) / var(--tile-cols))"}
    assert _css_decls(base, ".tile").get("--tile-tight") == "0"
    # 1440 px and up: up to seven in one row, the row of seven with the tight head; eight fall back to rows of four
    for sel in both("-n + 7"):
        assert at("(min-width: 1440px)", sel) == {"flex": "1 1 0"}, sel
    for sel in both("7"):
        assert at("(min-width: 1440px)", sel) == {"--tile-tight": "1"}, sel
    # below: up to four in one row, five or six in rows of three, seven or more in rows of four (4 + 3, 4 + 4)
    for sel in both("-n + 4"):
        assert at("(max-width: 1439.98px)", sel) == {"flex": "1 1 0"}, sel
    for sel in both("n + 5):nth-last-child(-n + 6"):
        assert at("(max-width: 1439.98px)", sel) == {"--tile-cols": "3"}, sel
    for sel in both("4") + both("n + 7"):
        assert at("(max-width: 979px)", sel) == {"--tile-tight": "1"}, sel
    # below 900 px: rows of three (7 -> 3 + 3 + 1, 8 -> 3 + 3 + 2), four tiles in rows of two
    assert at("(max-width: 899px)", ".tiles > .tile") == {"--tile-cols": "3"}
    for sel in both("4"):
        assert at("(max-width: 899px)", sel) == {"flex": half, "--tile-tight": "0"}, sel
    for sel in both("n + 7"):
        assert at("(max-width: 899px)", sel) == {"--tile-tight": "0"}, sel
    for sel in both("3") + both("n + 5"):
        assert at("(max-width: 739px)", sel) == {"--tile-tight": "1"}, sel
    # 700 px and less: rows of two, no tile wider than the others
    assert at("(max-width: 700px)", ".tiles > .tile") == {"--tile-cols": "2"}
    for sel in both("n + 3"):
        assert at("(max-width: 700px)", sel) == {"flex": half, "--tile-tight": "0"}, sel
    # no band misses a fractional width between 1439 and 1440 CSS px (1799 px at 125 %): the next band starts at 1440
    assert "(max-width: 1439px)" not in css and "@media (min-width: 1440px)" in css
    # no :has() and no container queries: docs/COMPATIBILITY.md lists both as not used
    assert ":has(" not in css and "@container" not in css


def test_dark_theme_yellow_badges_are_readable():
    """Small bold badge text needs 4.5:1: dark ink on a brighter yellow in the dark theme (the warning badges of the
    Network info page), worked out from the palette tokens."""
    css = _read("css/tnt.css")
    assert '[data-theme="dark"] .badge.yellow { background: color-mix(in srgb, var(--yellow) 75%, var(--paper)); color: var(--ink-on-accent); }' in css

    def token(block: str, name: str) -> str:
        return re.search(re.escape(name) + r":\s*(#[0-9A-Fa-f]{6})", block).group(1)

    root = css[css.index(":root {"):css.index("}", css.index(":root {"))]
    dark = css[css.index('[data-theme="dark"] {'):css.index("}", css.index('[data-theme="dark"] {'))]

    def rgb(h: str) -> List[float]:
        return [int(h[i:i + 2], 16) for i in (1, 3, 5)]

    def lum(c: List[float]) -> float:
        lin = [((v / 255 + 0.055) / 1.055) ** 2.4 if v / 255 > 0.04045 else v / 255 / 12.92 for v in c]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

    def contrast(a: List[float], b: List[float]) -> float:
        hi, lo = sorted((lum(a), lum(b)), reverse=True)
        return (hi + 0.05) / (lo + 0.05)

    yellow, paper, ink = rgb(token(dark, "--yellow")), rgb(token(dark, "--paper")), rgb(token(root, "--ink-on-accent"))
    badge = [0.75 * y + 0.25 * p for y, p in zip(yellow, paper)]
    old = [0.55 * y + 0.45 * p for y, p in zip(yellow, paper)]
    assert contrast(badge, ink) >= 6.0 and contrast(old, rgb(token(dark, "--ink"))) < 4.5


_NODE_NET_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const util = { relTime: (ts, now) => Math.round(now - ts) + ' s ago', fmtDateTime: () => 'Today, 10:00', fmtMs: (v) => String(v), nowS: () => 1000 };
const window = { TNT: { views: {}, util, ui: {} } };
const ctx = vm.createContext({ window, console });
const names = ['subnet.js', 'api.js', 'hosttable.js', 'ipinfo.js', 'ping.js', 'discovery.js', 'lan.js', 'subnetcalc.js', 'wifi.js'];
names.forEach((n, i) => vm.runInContext(fs.readFileSync(process.argv[2 + i], 'utf8'), ctx, { filename: n }));
const T = window.TNT, N = T.api.net, I = T.views.ipinfo, P = T.views.ping, D = T.views.discovery;
const L = T.tools.lan, C = T.tools.subnetcalc, W = T.tools.wifi;
const st = (started, gen) => ({ started_ts: started, net: { generation: gen, changed_ts: 50, default_gateway: '10.0.0.251', internet_nic: 'Ethernet' } });
const out = {};
// --- the network generation: first load silent, a newer one or a restart reloads, an older one right after an event is skipped
const first = N.compare(null, st(1, 0), 0);
out.compare = { first, same: N.compare(first.next, st(1, 0), 10), newer: N.compare(first.next, st(1, 2), 10),
  restarted: N.compare({ started: 1, generation: 5, eventMs: 0 }, st(2, 0), 10),
  noNet: N.compare(first.next, { started_ts: 1 }, 10), noNetFirst: N.compare(null, { started_ts: 1 }, 10) };
const ev = N.fromEvent(first.next, { generation: 3 }, 1000);
out.event = ev;
out.eventDuplicate = N.fromEvent(ev.next, { generation: 3 }, 1200).fresh;
out.eventNoGen = N.fromEvent(ev.next, { summary: 'x' }, 1200);
out.eventFirst = N.fromEvent(null, { generation: 1 }, 5);
out.staleWithinGrace = N.compare(ev.next, st(1, 2), 1000 + N.STALE_GRACE_MS - 1);
out.staleAfterGrace = N.compare(ev.next, st(1, 2), 1000 + N.STALE_GRACE_MS + 1);
out.caughtUp = N.compare(ev.next, st(1, 3), 1100);
out.eventThenFirstStatus = N.compare(out.eventFirst.next, st(9, 1), 10);
out.merge = N.merge({ gateway_changed: true, dns_changed: false, changes: [{ adapter: 'Ethernet', kind: 'down' }], summary: 'old' },
  { gateway_changed: false, dns_changed: true, changes: [{ adapter: 'Wi-Fi', kind: 'up' }], summary: 'new' });
out.mergeNull = [N.merge(null, { a: 1 }), N.merge({ a: 1 }, null)];
// --- one network toast: rewrite it while it is up, otherwise at most one new one per gap
out.toast = [N.toastPlan(null, 0), N.toastPlan({ shownMs: 0, visible: true }, 500), N.toastPlan({ shownMs: 0, visible: false }, 3000),
  N.toastPlan({ shownMs: 0, visible: false }, N.TOAST_GAP_MS), N.toastPlan({ shownMs: 0, visible: false }, 100, 50)];
out.gaps = [N.STALE_GRACE_MS, N.TOAST_GAP_MS];
// status.netinfo.internet_nic as the service sends it: the bare address plus its network
out.summary = [
  N.summaryFromStatus({ netinfo: { internet_nic: { name: 'Wi-Fi', ipv4: '192.168.50.23', network: '192.168.50.0/24', gateway: '192.168.50.1' } }, net: { default_gateway: '192.168.50.1' } }),
  N.summaryFromStatus({ netinfo: { internet_nic: { name: 'Ethernet', ipv4: '172.16.20.15/24' } }, net: { default_gateway: null } }),
  N.summaryFromStatus({ netinfo: { internet_nic: null }, net: { default_gateway: null } }), N.summaryFromStatus(null)];
out.nic = [
  N.nicFromEvent({ default_gateway: '192.168.50.1', internet_nic: { index: 7, name: 'Wi-Fi', ipv4: ['192.168.50.23'], ipv4_prefixes: ['24'], networks: ['192.168.50.0/24'], dns: [], dhcp: true } }),
  N.nicFromEvent({ default_gateway: null, internet_nic: { name: 'Ethernet', ipv4: ['172.16.20.15'], ipv4_prefixes: ['24'] } }),
  N.nicFromEvent({ internet_nic: { name: 'Ethernet', ipv4: ['10.0.0.112/24'], ipv4_prefixes: [] } }),
  N.nicFromEvent({ internet_nic: { name: 'Wi-Fi', ipv4: ['192.168.50.23'], ipv4_prefixes: ['192.168.50.0/24'] } }),
  N.nicFromEvent({ internet_nic: null }), N.nicFromEvent(null)];
out.cidr = [N.nicCidr({ ipv4: '10.0.0.112', network: '10.0.0.0/24' }), N.nicCidr({ ipv4: '10.0.0.112/24' }), N.nicCidr({ ipv4: '10.0.0.112' }),
  N.nicCidr(null), N.nicCidr(out.nic[1])];
out.networkOf = [N.networkOf('192.168.77.23', 24), N.networkOf('10.20.0.50', '16'), N.networkOf('203.0.113.200', 32), N.networkOf('172.16.20.15', 0),
  N.networkOf('128.0.0.1', 1), N.networkOf('300.1.1.1', 24), N.networkOf('10.0.0.1', 33), N.networkOf('10.0.0.1', 'x'), N.networkOf(null, 24)];
out.toastText = [N.toastText({ summary: 'Wi-Fi: 192.168.50.23/24 · gateway 192.168.50.1', default_gateway: '192.168.50.1' }),
  N.toastText({ summary: 'No network connection', default_gateway: null }),
  N.toastText({ summary: 'DHCP server set Ethernet to 172.16.4.100 · Ethernet: 172.16.4.100/24 · no gateway', default_gateway: null, cause: 'dhcp' })];
const eth = { ipv4: '10.0.0.112/24' };
out.elsewhere = [N.runElsewhere('10.0.0.0/24', eth), N.runElsewhere('192.168.50.0/24', eth), N.runElsewhere('10.0.0.1-10.0.0.50', eth),
  N.runElsewhere('10.0.1.1-10.0.1.9', eth), N.runElsewhere('10.0.0.0/16', eth), N.runElsewhere('10.0.0.128/25', eth),
  N.runElsewhere('192.168.50.0/24', null), N.runElsewhere('garbage', eth), N.runElsewhere('', eth), N.runElsewhere('10.0.0.9', eth)];
const ethService = { ipv4: '10.0.0.112', network: '10.0.0.0/24' };
out.elsewhereService = [N.runElsewhere('10.0.0.0/24', ethService), N.runElsewhere('192.168.50.0/24', ethService),
  N.runElsewhere('10.0.1.1-10.0.1.9', ethService), N.runElsewhere('192.168.50.0/24', { ipv4: '10.0.0.112' })];
// --- Network info: adapter warnings, the WAN chip after a change, the gateway bar without a gateway
out.warnings = I.adapterWarnings({ warnings: [{ code: 'multiple_default_gateways', message: 'm' }, { code: 'no_dns', message: 'd' },
  { code: 'gateway_outside_subnet', message: 'g' }, { code: 'brand_new_code', message: 'n' }, { code: '' }, null, 'junk'] });
out.warningsNone = [I.adapterWarnings({}), I.adapterWarnings(null), I.warningView({ code: 'apipa' }), I.warningView({ code: 'duplicate_address', message: 'x' })];
out.wan = [I.wanChip({ ip: '203.0.113.5', ts: 40 }, 100, 90), I.wanChip({ ip: '198.51.100.77', ts: 95 }, 100, 90),
  I.wanChip({ ip: '203.0.113.5', ts: 40 }, 300, 90), I.wanChip(null, 100, 90), I.wanChip({ ip: '203.0.113.5', ts: 40 }, 100, null)];
out.gwRowsChecking = I.gatewayRows({ gateway: { ip: '192.168.50.1' }, public_ip: { ip: '203.0.113.5', ts: 40 } }, 100, 90).map((r) => [r.tag, r.value, !!r.plain]);
out.link = [I.linkView({ ip: null, resolve_error: 'no default gateway', state: 'unknown' }, 'gateway'),
  I.linkView({ ip: null, resolve_error: 'no default gateway', state: 'down' }, 'gateway'),
  I.linkView({ ip: '10.0.0.251', state: 'down' }, 'gateway'), I.linkView({ ip: null, resolve_error: 'getaddrinfo failed', state: 'down' }, 'internet'),
  I.linkView({ ip: '10.0.0.251', state: 'unknown' }, 'gateway'), I.linkView(null, 'gateway')];
out.sig = [I.netinfoSig({ ts: 1, adapters: [1] }) === I.netinfoSig({ ts: 2, adapters: [1] }), I.netinfoSig({ ts: 1, adapters: [1] }) === I.netinfoSig({ ts: 1, adapters: [2] })];
// --- Ping page: the address row and Load Default Tiles
out.host = [P.hostState({ host: 'gateway', ip: '192.168.50.1', resolved: true }),
  P.hostState({ host: 'gateway', ip: null, resolved: false, resolve_error: 'this machine has no default gateway right now' }),
  P.hostState({ host: 'Default Gateway', ip: '10.0.0.251', resolved: false }),
  P.hostState({ host: 'nas.lan', ip: '10.0.0.10', resolved: false, resolve_error: 'getaddrinfo failed' }),
  P.hostState({ host: '1.1.1.1', ip: '1.1.1.1', resolved: true, resolve_error: null })];
out.defaults = [P.defaultsToast([{ host: 'gateway', ip: '192.168.50.1', resolved: true }, { host: '1.1.1.1' }, { host: 'totalelectronics.com' }]),
  P.defaultsToast([{ host: 'gateway', ip: null, resolved: false }, { host: '1.1.1.1' }]), P.defaultsToast(null), P.defaultsToast([{ host: '1.1.1.1' }])];
out.alias = ['gateway', ' GATEWAY ', 'default-gateway', 'default gateway', 'gateway.lan', null].map(P.isGatewayAlias);
// --- Discovery: the default range follows the network until the user types one
const R = D.rangeUpdate;
out.range = { empty: R({ value: '' }, '10.0.0.0/24'), auto: R({ value: '10.0.0.0/24', auto: '10.0.0.0/24' }, '192.168.50.0/24'),
  same: R({ value: '10.0.0.0/24', auto: '10.0.0.0/24' }, '10.0.0.0/24'),
  typedChanged: R({ value: '10.0.0.1-10.0.0.50', auto: '10.0.0.0/24', touched: true, changed: true }, '192.168.50.0/24'),
  typedQuiet: R({ value: '10.0.0.1-10.0.0.50', auto: '10.0.0.0/24', touched: true }, '192.168.50.0/24'),
  typedBackToAuto: R({ value: '10.0.0.0/24', auto: '10.0.0.0/24', touched: true, changed: true }, '192.168.50.0/24'),
  running: R({ value: '10.0.0.0/24', auto: '10.0.0.0/24', running: true }, '192.168.50.0/24'),
  focused: R({ value: '10.0.0.0/24', auto: '10.0.0.0/24', focused: true }, '192.168.50.0/24'),
  focusedEmpty: R({ value: '', focused: true }, '10.0.0.0/24'), noDefault: R({ value: '10.0.0.0/24', auto: '10.0.0.0/24' }, null),
  noDefaultAfterChange: R({ value: '10.0.0.0/24', auto: '10.0.0.0/24', changed: true }, null),
  noDefaultTyped: R({ value: '10.0.0.1-10.0.0.50', auto: '10.0.0.0/24', touched: true, changed: true }, null),
  noDefaultFocused: R({ value: '10.0.0.0/24', auto: '10.0.0.0/24', changed: true, focused: true }, null) };
// --- LAN peers, the subnet calculator and the saved Wi-Fi networks card
out.away = [L.peerAway({ ip: '172.16.21.77', adapter: null }), L.peerAway({ ip: '10.0.0.42', adapter: 'Ethernet' }), L.peerAway({ ip: '10.0.0.42' }), L.peerAway(null)];
out.autoFill = [C.autoFill({ value: '', auto: null }, '10.0.0.112/24'), C.autoFill({ value: '10.0.0.112/24', auto: '10.0.0.112/24' }, '192.168.50.23/24'),
  C.autoFill({ value: '10.9.9.9/16', auto: '10.0.0.112/24' }, '192.168.50.23/24'), C.autoFill({ value: '', touched: true }, '10.0.0.112/24'),
  C.autoFill({ value: '10.0.0.112/24', auto: '10.0.0.112/24' }, null), C.autoFill({ value: '10.0.0.112/24', auto: '10.0.0.112/24' }, '10.0.0.112/24')];
// no internet adapter in the status any more: the filled-in address comes from the adapters list, a connected adapter first
out.refill = [C.refillFromAdapters({ value: '192.168.50.23/24', auto: '192.168.50.23/24' }, null),
  C.refillFromAdapters({ value: '192.168.50.23/24', auto: '192.168.50.23/24' }, '10.0.0.112/24'),
  C.refillFromAdapters({ value: '10.9.9.9/16', auto: '192.168.50.23/24' }, null), C.refillFromAdapters({ value: '', touched: true }, null),
  C.refillFromAdapters({ value: '' }, null), C.refillFromAdapters(null, null)];
out.prefillUpFirst = C.prefillFromNetinfo({ internet_nic_index: null, adapters: [{ index: 12, status: 'down', ipv4: [{ address: '10.20.30.45', prefix: 24 }] },
  { index: 18, status: 'up', ipv4: [{ address: '169.254.23.45', prefix: 16 }] }] });
out.wifiChange = [W.wifiInChange({ changes: [{ adapter: 'Wi-Fi', kind: 'up' }] }), W.wifiInChange({ changes: [{ adapter: 'Ethernet', kind: 'down' }] }),
  W.wifiInChange({ changes: [{ adapter: 'WLAN 2', kind: 'ipv4' }] }), W.wifiInChange({}), W.wifiInChange(null)];
// --- the service's own summary in /api/status, every local subnet, the toast kind and when a change toasts at all
out.summaryNet = N.summaryFromStatus({ netinfo: { internet_nic: null },
  net: { default_gateway: null, summary: 'Ethernet: 169.254.23.45/16 · self-assigned address, no DHCP server answered · no gateway' } });
const wifiNic = { ipv4: '10.1.2.3', network: '10.1.2.0/24' };
out.elsewhereNets = [N.runElsewhere('192.168.0.0/24', wifiNic, ['10.1.2.0/24', '192.168.0.0/24']),
  N.runElsewhere('172.16.0.0/24', wifiNic, ['10.1.2.0/24', '192.168.0.0/24']), N.runElsewhere('192.168.0.5', null, ['192.168.0.0/24']),
  N.runElsewhere('192.168.0.10-192.168.1.20', null, ['192.168.1.0/24']), N.runElsewhere('192.168.0.0/24', wifiNic, ['junk']),
  N.runElsewhere('192.168.0.0/24', null, [])];
out.toastKinds = [N.toastText({ summary: 'Ethernet: 192.168.1.10 is already in use on this network · gateway 192.168.1.1',
  default_gateway: '192.168.1.1', internet_nic: null }).kind, N.toastText({ summary: 'x', default_gateway: '192.168.1.1', internet_nic: 'Ethernet' }).kind];
const same = { gateway_changed: false, subnets_changed: false, dns_changed: false };
out.toastWanted = [N.toastWanted({ changes: [{ adapter: 'Ethernet', kind: 'ipv6' }] }, false),
  N.toastWanted({ changes: [{ adapter: 'Ethernet', kind: 'ipv6' }] }, true),
  N.toastWanted(Object.assign({ changes: [{ adapter: 'Wi-Fi', kind: 'internet_nic' }] }, same), false),
  N.toastWanted({ changes: [{ adapter: 'Wi-Fi', kind: 'internet_nic' }], gateway_changed: true }, false),
  N.toastWanted(Object.assign({ changes: [{ adapter: 'Wi-Fi', kind: 'internet_nic' }, { adapter: 'Wi-Fi', kind: 'ipv6' }] }, same), false),
  N.toastWanted({ source: 'status', summary: 'x' }, false), N.toastWanted(null, false)];
// a lookup after the change that failed: the service keeps the ts of the last address it found and stamps checked_ts
out.wanFailed = [I.wanChip({ ip: null, ts: 1000, error: 'URLError: timed out', checked_ts: 1010 }, 1020, 1005),
  I.wanChip({ ip: null, ts: 1000, error: 'URLError: timed out', checked_ts: 1001 }, 1020, 1005),
  I.wanChip({ ip: '198.51.100.77', ts: 1010, error: null, checked_ts: 1010 }, 1020, 1005)];
process.stdout.write(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_network_change_helpers_with_node(tmp_path):
    driver = tmp_path / "driver.js"
    driver.write_text(_NODE_NET_DRIVER, encoding="utf-8")
    files = ["js/tools/subnet.js", "js/api.js", "js/hosttable.js", "js/views/ipinfo.js", "js/views/ping.js", "js/views/discovery.js",
             "js/tools/lan.js", "js/tools/subnetcalc.js", "js/tools/wifi.js"]
    r = subprocess.run(["node", str(driver)] + [str(UI / f) for f in files], capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    quiet = {"changed": False, "stale": False, "restarted": False}
    c = out["compare"]
    assert c["first"] == dict(quiet, next={"started": 1, "generation": 0, "eventMs": 0}), "the first snapshot only sets the marker"
    assert c["same"] == dict(quiet, next={"started": 1, "generation": 0, "eventMs": 0})
    assert c["newer"]["changed"] is True and c["newer"]["restarted"] is False and c["newer"]["next"]["generation"] == 2
    assert c["restarted"]["changed"] is True and c["restarted"]["restarted"] is True, "a restarted service reloads the views (no toast)"
    assert c["noNet"] == dict(quiet, next=c["first"]["next"]) and c["noNetFirst"] == dict(quiet, next=None), "an older service: nothing"
    assert out["event"] == {"next": {"started": 1, "generation": 3, "eventMs": 1000}, "fresh": True}
    assert out["eventDuplicate"] is False, "a generation a status snapshot already brought is not handled twice"
    assert out["eventNoGen"]["fresh"] is True and out["eventFirst"] == {"next": {"generation": 1, "eventMs": 5}, "fresh": True}
    assert out["staleWithinGrace"] == dict(quiet, stale=True, next=out["event"]["next"]), "a snapshot older than the event is skipped"
    assert out["staleAfterGrace"]["stale"] is False and out["staleAfterGrace"]["changed"] is True, "but never for longer than the grace"
    assert out["caughtUp"] == dict(quiet, next={"started": 1, "generation": 3, "eventMs": 0})
    assert out["eventThenFirstStatus"] == dict(quiet, next={"started": 9, "generation": 1, "eventMs": 0}), "an event before the first status"
    assert out["merge"] == {"gateway_changed": True, "dns_changed": True, "internet_nic_changed": False, "subnets_changed": False,
                            "summary": "new", "changes": [{"adapter": "Ethernet", "kind": "down"}, {"adapter": "Wi-Fi", "kind": "up"}]}
    assert out["mergeNull"] == [{"a": 1}, {"a": 1}]
    assert out["toast"] == [{"action": "new", "waitMs": 0}, {"action": "update", "waitMs": 0}, {"action": "defer", "waitMs": 5000},
                            {"action": "new", "waitMs": 0}, {"action": "new", "waitMs": 0}]
    assert out["gaps"] == [15000, 8000]
    assert out["summaryNet"] == "Ethernet: 169.254.23.45/16 · self-assigned address, no DHCP server answered · no gateway", \
        "a change seen only through /api/status reads like the event"
    assert out["elsewhereNets"] == [False, True, False, False, True, False], "any subnet of this PC, not only the internet adapter's"
    assert out["toastKinds"] == ["warn", "info"], "a gateway but no adapter facing the internet is a warning"
    assert out["toastWanted"] == [False, True, False, True, True, True, True]
    wf = out["wanFailed"]
    assert "checking" not in wf[0] and wf[0].get("error"), "a failed lookup after the change is shown, not \"checking…\""
    assert wf[1]["checking"] is True and wf[2]["ip"] == "198.51.100.77"
    assert out["summary"] == ["Wi-Fi: 192.168.50.23/24 · gateway 192.168.50.1", "Ethernet: 172.16.20.15/24 · no gateway",
                              "No network connection", "No network connection"]
    # the dashboard's internet adapter patched from net.changed has the shape of status.netinfo.internet_nic
    assert out["nic"] == [{"name": "Wi-Fi", "ipv4": "192.168.50.23", "network": "192.168.50.0/24", "gateway": "192.168.50.1"},
                          {"name": "Ethernet", "ipv4": "172.16.20.15", "network": "172.16.20.0/24", "gateway": None},
                          {"name": "Ethernet", "ipv4": "10.0.0.112", "network": "10.0.0.0/24", "gateway": None},
                          {"name": "Wi-Fi", "ipv4": "192.168.50.23", "network": "192.168.50.0/24", "gateway": None}, None, None]
    assert out["cidr"] == ["10.0.0.112/24", "10.0.0.112/24", None, None, "172.16.20.15/24"]
    assert out["networkOf"] == ["192.168.77.0/24", "10.20.0.0/16", "203.0.113.200/32", "0.0.0.0/0", "128.0.0.0/1", None, None, None, None]
    assert out["toastText"] == [{"text": "Network changed — Wi-Fi: 192.168.50.23/24 · gateway 192.168.50.1", "kind": "info"},
                                {"text": "Network changed — No network connection", "kind": "warn"},
                                {"text": "DHCP server set Ethernet to 172.16.4.100 · Ethernet: 172.16.4.100/24 · no gateway", "kind": "info"}]
    assert out["elsewhere"] == [False, True, False, True, False, False, False, False, False, False]
    assert out["elsewhereService"] == [False, True, True, False], "the service's bare address + network, and nothing without a prefix"
    # Network info
    assert out["warnings"] == [{"code": "gateway_outside_subnet", "cls": "red", "label": "gateway off subnet", "message": "g"},
                               {"code": "no_dns", "cls": "yellow", "label": "no DNS", "message": "d"},
                               {"code": "brand_new_code", "cls": "yellow", "label": "brand new code", "message": "n"},
                               {"code": "multiple_default_gateways", "cls": "grey", "label": "multiple gateways", "message": "m"}]
    assert out["warningsNone"][:2] == [[], []]
    # "no DHCP" read as "DHCP is off" next to a DHCP row that says on: the badge names what the adapter got
    assert out["warningsNone"][2] == {"code": "apipa", "cls": "yellow", "label": "self-assigned IP", "message": "self-assigned IP"}
    assert out["warningsNone"][3]["cls"] == "red" and out["warningsNone"][3]["label"] == "duplicate IP"
    w = out["wan"]
    assert w[0]["checking"] is True and w[3]["checking"] is True, "an address looked up before the change is not shown as current"
    assert w[1]["ip"] == "198.51.100.77" and "checked 5 s ago" in w[1]["title"]
    assert w[2]["ip"] == "203.0.113.5" and w[4]["ip"] == "203.0.113.5", "never longer than 2 min, and not without a change"
    assert out["gwRowsChecking"] == [["LAN", "192.168.50.1", False], ["WAN", "checking…", True]]
    assert out["link"] == [{"color": "grey", "text": "no default gateway"}, {"color": "grey", "text": "no default gateway"},
                           {"color": "red", "text": "no reply"}, {"color": "red", "text": "getaddrinfo failed"},
                           {"color": "grey", "text": "waiting…"}, {"color": "grey", "text": "…"}]
    assert out["sig"] == [True, False]
    # Ping page
    h = out["host"]
    assert h[0] == {"ip": "192.168.50.1", "stale": False, "badge": None, "note": None}
    assert h[1] == {"ip": None, "stale": False, "note": None,
                    "badge": {"cls": "grey", "text": "no gateway", "title": "this machine has no default gateway right now"}}
    assert h[2]["stale"] is True and h[2]["badge"]["cls"] == "grey" and h[2]["badge"]["title"] == "This PC has no default gateway right now"
    assert h[3] == {"ip": "10.0.0.10", "stale": True, "note": "getaddrinfo failed",
                    "badge": {"cls": "red", "text": "unresolved", "title": "getaddrinfo failed"}}
    assert h[4] == {"ip": "1.1.1.1", "stale": False, "badge": None, "note": None}
    assert out["defaults"] == [{"text": "Default tiles loaded (3 targets) · Gateway 192.168.50.1", "kind": "ok"},
                               {"text": "Default tiles loaded (2 targets) · no default gateway right now", "kind": "warn"},
                               {"text": "Default tiles loaded (? targets)", "kind": "ok"},
                               {"text": "Default tiles loaded (1 targets)", "kind": "ok"}]
    assert out["alias"] == [True, True, True, True, False, False]
    # Discovery range
    rg = {k: (v["action"], v["value"]) for k, v in out["range"].items()}
    assert rg == {"empty": ("replace", "10.0.0.0/24"), "auto": ("replace", "192.168.50.0/24"), "same": ("none", "10.0.0.0/24"),
                  "typedChanged": ("hint", "192.168.50.0/24"), "typedQuiet": ("none", "192.168.50.0/24"),
                  "typedBackToAuto": ("hint", "192.168.50.0/24"), "running": ("wait", "192.168.50.0/24"),
                  "focused": ("wait", "192.168.50.0/24"), "focusedEmpty": ("replace", "10.0.0.0/24"), "noDefault": ("none", "10.0.0.0/24"),
                  # moved onto no IPv4 network: the old network's filled-in range goes, a typed one stays
                  "noDefaultAfterChange": ("replace", ""), "noDefaultTyped": ("none", "10.0.0.1-10.0.0.50"), "noDefaultFocused": ("wait", "")}
    # LAN peers, subnet calculator, saved Wi-Fi networks
    assert out["away"][0]["text"] == "other subnet" and out["away"][1:] == [None, None, None]
    assert out["autoFill"] == ["10.0.0.112/24", "192.168.50.23/24", None, None, None, None]
    assert out["refill"] == [True, False, False, False, True, True]
    assert out["prefillUpFirst"] == "169.254.23.45/16", "a connected adapter's address before a down one's"
    assert out["wifiChange"] == [True, False, True, False, False]


# ---------------------------------------------------------------------------
# saved Wi-Fi networks card (js/tools/wifi.js)
# ---------------------------------------------------------------------------
def test_wifi_card_markup_icon_and_api():
    html = _read("index.html")
    # loaded after the other tool modules and before the views (it uses TNT.hosttable.csvCell)
    assert '<script src="js/tools/wifi.js"></script>' in html
    assert html.index("js/tools/wifi.js") > html.index("js/hosttable.js")
    assert html.index("js/tools/wifi.js") < html.index("js/views/tools.js")
    app = _read("js/app.js")
    assert "wifi:" in app and "the saved Wi-Fi networks card" in app          # the icon
    api = _read("js/api.js")
    # reveal is sent explicitly both ways now (the service defaults it off)
    assert "wifiProfiles:" in api and "'/tools/wifi/profiles'" in api
    assert "'?reveal=0'" in api and "'?reveal=1'" in api
    tools = _read("js/views/tools.js")
    assert "'Saved Wi-Fi networks'" in tools and "TNT.tools.wifi.create()" in tools and "icon: 'wifi'" in tools
    # last card on the page: after the subnet calculator
    assert tools.index("'Subnet calculator'") < tools.index("'Saved Wi-Fi networks'")
    src = _read("js/tools/wifi.js")
    for s in ("TNT.tools.wifi = {", "TNT.api.wifiProfiles(", "TNT.app.saveBlob(", "TNT.hosttable.csvCell",
              "Every Wi-Fi network this PC has joined", "'Show keys'", "'Hide keys'", "'Export CSV'",
              "ssid', 'authentication', 'encryption', 'key', 'connection_mode'", "TNT-wifi-",
              "text/csv;charset=utf-8", "if (!mounted) return", "TNT.api.events.on('hello'"):
        assert s in src, s
    # a refused reveal (not an administrator) is handled: the 403 admin_required is caught, the
    # list stays masked, and the CSV never writes keys that were not actually revealed
    for s in ("admin_required", "administrator", "keyNote", "hasKeys"):
        assert s in src, s
    assert "setInterval" not in src                     # Refresh only, never polling
    assert "for (const u of unsubs)" in src and "unsubs = []" in src
    # the tool modules load before app.js: TNT.util / TNT.ui may only be touched inside functions
    top_level = [ln for ln in src.splitlines() if re.match(r"^  (const|let|var) ", ln)]
    assert not any(("TNT.util." in ln or "TNT.ui." in ln) and "=>" not in ln for ln in top_level), top_level
    css = _read("css/tnt.css")
    for sel in (".wifi-controls", ".wifi-table", ".wifi-table td.wifi-name", "code.copy.wifi-key", ".wifi-err"):
        assert sel in css, sel


def test_wifi_card_is_in_the_design_doc():
    docs = _doc("docs/DESIGN.md")
    assert "Saved Wi-Fi networks" in docs and "Show keys" in docs


def test_wifi_profiles_route_is_in_the_architecture_doc():
    arch = _doc("docs/ARCHITECTURE.md")
    assert "GET `/tools/wifi/profiles`" in arch and "LocalSystem/admin rights" in arch


_NODE_WIFI_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const window = { TNT: { views: {}, util: {}, api: {}, ui: {} } };
const ctx = vm.createContext({ window, console });
// hosttable.js first: rowsToCsv reuses its CSV quoting, exactly like index.html
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'hosttable.js' });
vm.runInContext(fs.readFileSync(process.argv[3], 'utf8'), ctx, { filename: 'wifi.js' });
const W = window.TNT.tools.wifi;
const out = { mask: W.MASK, columns: W.CSV_COLUMNS };
out.keys = [
  W.maskKey('example-office-passphrase', true, true),
  W.maskKey('example-office-passphrase', true, false),
  W.maskKey(null, true, true),
  W.maskKey(null, true, false),
  W.maskKey(null, false, true),
  W.maskKey(null, false, false),
  W.maskKey('', false, true),
];
out.cls = {};
for (const a of ['WPA2PSK', 'WPA3-Personal', 'WPA-Personal', 'WEP', 'open', 'none', 'RSNA', null, '']) out.cls[String(a)] = W.securityClass(a);
out.sec = [W.securityText({ authentication: 'WPA2PSK', encryption: 'AES' }), W.securityText({ authentication: 'open' }),
           W.securityText({}), W.securityText(null)];
out.csv = W.rowsToCsv([
  { name: 'TEC-Office', ssid: 'TEC-Office', authentication: 'WPA2PSK', encryption: 'AES', key: 'example-office-passphrase', connection_mode: 'auto' },
  { name: 'odd', ssid: 'bench, 5G', authentication: 'WPA2PSK', encryption: 'AES', key: 'a"b', connection_mode: 'auto' },
  { name: 'SiteSurvey-5G', ssid: null, authentication: 'open', encryption: 'none', key: null, connection_mode: null },
]);
out.csvEmpty = W.rowsToCsv([]);
out.names = [W.csvName('TEC-DESKTOP', 1757462400), W.csvName('  bench pc/2  ', 1757462400),
             W.csvName('', 1757462400), W.csvName(null, 1757462400)];
process.stdout.write(JSON.stringify(out));
"""


_NODE_OUTAGES_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const window = { TNT: { views: {}, util: {}, api: {}, ui: {} } };
const ctx = vm.createContext({ window, console });
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'outages.js' });
const O = window.TNT.views.outages;
const cells = (o) => O.missedCells(o);
process.stdout.write(JSON.stringify({
  all: cells({ kind: 'target', missed: 3, sent: 3, missed_pct: 100 }),
  most: cells({ kind: 'target', missed: 2449, sent: 2450, missed_pct: 99.96 }),
  flaky: cells({ kind: 'target', missed: 7, sent: 8, missed_pct: 87.5 }),
  legacy: cells({ kind: 'target', missed: 95, sent: 95, missed_pct: 100, sent_estimated: true }),
  tiny: cells({ kind: 'target', missed: 1, sent: 5000, missed_pct: 0.02 }),
  noPct: cells({ kind: 'target', missed: 3, missed_pct: null }),
  total: cells({ kind: 'total_internet', missed: 0, missed_pct: null }),
  gap: cells({ kind: 'gap', missed: 0 }),
  nothing: cells(null),
}));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_outages_missed_columns_with_node(tmp_path):
    driver = tmp_path / "driver.js"
    driver.write_text(_NODE_OUTAGES_DRIVER, encoding="utf-8")
    r = subprocess.run(["node", str(driver), str(UI / "js/views/outages.js")],
                       capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["all"] == {"pings": "3", "pct": "100%", "title": "3 of 3 pings missed"}
    assert out["most"]["pct"] == "99.9%", "floored: 99.96% must not read as 100%"
    assert out["flaky"] == {"pings": "7", "pct": "87.5%", "title": "7 of 8 pings missed"}
    assert out["legacy"]["pct"] == "≈100%" and "estimated" in out["legacy"]["title"]
    assert out["tiny"]["pct"] == "<0.1%"
    assert out["noPct"] == {"pings": "3", "pct": "—", "title": ""}
    for k in ("total", "gap", "nothing"):
        assert out[k] == {"pings": "—", "pct": "—", "title": ""}, k
    src = (UI / "js/views/outages.js").read_text(encoding="utf-8")
    assert "'Missed Pings'" in src and "'Missed %'" in src and "colspan: '7'" in src


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_wifi_helpers_with_node(tmp_path):
    driver = tmp_path / "driver.js"
    driver.write_text(_NODE_WIFI_DRIVER, encoding="utf-8")
    r = subprocess.run(["node", str(driver), str(UI / "js/hosttable.js"), str(UI / "js/tools/wifi.js")],
                       capture_output=True, text=True, encoding="utf-8", timeout=30)  # the mask is a bullet
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["mask"] == "•" * 8
    assert out["columns"] == ["ssid", "authentication", "encryption", "key", "connection_mode"]
    # shown -> the key, hidden -> the mask, no key at all -> an em dash either way
    assert out["keys"] == ["example-office-passphrase", out["mask"], "—", out["mask"], "—", "—", "—"]
    assert out["cls"] == {"WPA2PSK": "green", "WPA3-Personal": "green", "WPA-Personal": "yellow", "WEP": "red",
                          "open": "red", "none": "red", "RSNA": "grey", "null": "grey", "": "grey"}
    assert out["sec"] == ["WPA2PSK · AES", "open", "unknown", "unknown"]
    lines = out["csv"].split("\r\n")
    assert lines[0] == "ssid,authentication,encryption,key,connection_mode"
    assert lines[1] == "TEC-Office,WPA2PSK,AES,example-office-passphrase,auto"
    assert lines[2] == '"bench, 5G",WPA2PSK,AES,"a""b",auto'      # the shared CSV quoting
    assert lines[3] == "SiteSurvey-5G,open,none,,"                # the name stands in for a null ssid
    assert out["csvEmpty"] == "ssid,authentication,encryption,key,connection_mode\r\n"
    # the file name: the hostname when there is one, otherwise the local date (node and
    # Python read the same machine clock, so the stamp is computed here rather than pinned)
    stamp = time.strftime("%Y%m%d", time.localtime(1757462400))
    assert out["names"] == ["TNT-wifi-TEC-DESKTOP.csv", "TNT-wifi-bench-pc-2.csv",
                            f"TNT-wifi-{stamp}.csv", f"TNT-wifi-{stamp}.csv"]


# ---------------------------------------------------------------------------
# WiFi survey page (js/views/wifi.js, js/wifichart.js) and its tile
# ---------------------------------------------------------------------------
def test_wifi_tile_view_and_accent():
    html = _read("index.html")
    tiles = re.findall(r'<a class="tile" data-view="([a-z]+)" href="#\1" style="--accent: var\(--([a-z]+)\)">', html)
    # WiFi before Tools, then Reports as the eighth tile
    assert tiles == [("ipinfo", "blue"), ("ping", "green"), ("outages", "yellow"), ("speed", "purple"),
                     ("discovery", "orange"), ("wifi", "teal"), ("tools", "red"), ("reports", "grey")]
    assert 'data-icon="wifi"></span><span class="tile-title">WiFi</span>' in html and 'id="tile-wifi"' in html
    # the chart helpers load after charts.js (they extend its base class), the view with the others
    assert html.index("js/charts.js") < html.index("js/wifichart.js") < html.index("js/views/wifi.js") < html.index("js/app.js")
    # the tiles are plain markup in index.html, in this order: there is no saved tile order anywhere
    # that could leave the new tile out (the only reorderable tiles are the Ping page's targets)
    app = _read("js/app.js")
    assert "wifi: 'var(--teal)'" in app and "'discovery', 'wifi', 'tools', 'reports'];" in app
    assert "tileEls.wifi" in app and "tileSummary(ws.last, ws.bridgeState(), ws.error)" in app
    assert "TNT.wifiSurvey.startTilePolling(" in app and "spectrum:" in app
    assert "localStorage.setItem('tnt.tiles" not in app
    css = _read("css/tnt.css")
    root = re.search(r":root\s*\{(.*?)\}", css, re.S).group(1)
    dark = re.search(r'\[data-theme="dark"\]\s*\{(.*?)\}', css, re.S).group(1)
    assert "--teal: #4FD1C5" in root and "--teal: #67DCD1" in dark
    assert ".badge.teal" in css
    assert "teal: cssVar('--teal'" in _read("js/charts.js")
    # vendors: only 24-bit OUIs go to the service
    api = _read("js/api.js")
    assert "ouiVendors:" in api and "'/oui?'" in api and "'prefix=' + encodeURIComponent(p)" in api


def test_wifi_view_uses_the_bridge_never_the_api_for_the_survey():
    src = _read("js/views/wifi.js")
    assert re.search(r"TNT\.views\.wifi\s*=\s*\{", src)
    for name in ("wifi_survey", "wifi_scan_now", "wifi_clear", "wifi_set_enabled", "open_location_settings"):
        assert name in src, name
    assert "{ active: true, history_s: want }" in src and "{ active: false, history_s: 0 }" in src
    assert "POLL_MS = 2000" in src and "TILE_POLL_MS = 15000" in src
    assert "document.hidden" in src and "'pywebviewready'" in src
    # the survey is never fetched from the service; the only service call is the OUI lookup
    assert re.findall(r"TNT\.api\.(\w+)\(", src) == ["ouiVendors"]
    # untrusted SSIDs: tooltips go through escHtml, everything else through h() / textContent
    assert "innerHTML" not in re.sub(r"(list|el|tbody)\.innerHTML = ''", "", src)
    # rows never move under the pointer or the keyboard, and the table updates changed cells in place
    for s in ("interacting(els.netList) ? keepOrder(grouped, netOrder", "if (!interacting(els.tableWrap)) {", ": table.sorted(inOrder);",
              "matches(':hover')", ":focus-visible", "cellHtml.get(old) === html", "tr.replaceChild(td, old)",
              "stickyOrder(inOrder, tableOrder, (a) => a.bssid", "sortNetworks(grouped, netOrder, SORT_MARGIN_DB)",
              "if (sig === legendSig && el.firstChild) return;",
              "toggleSelect(pickBtn.dataset.pick, 'table')", "revealSelectedRow()", "TNT.ui.busy(btn, true, 'Trying…')"):
        assert s in src, s
    assert "table.render(" not in src, "the table's rows are kept by the page, not rebuilt by hosttable on every poll"
    charts_src = _read("js/wifichart.js")
    assert "this.renderNow()" not in charts_src, "hover redraws are coalesced to one per animation frame"
    for s in ("s._segCache", "this._cols.get(c)", "labelChannels(this.band, ticks)", "fillAlpha(list.length)", "a.selected && a.stale"):
        assert s in charts_src, s
    assert "escHtml" in src and "escHtml" in _read("js/wifichart.js")
    for s in ("Open location settings", "Turn the survey on", "Location access needed", "No Wi-Fi adapter", "Survey off",
              "The Wi-Fi survey runs in the TNT window", "Open in the TNT window", "Scan now", "Clear the Wi-Fi survey?",
              "briefly add latency", "Seeing 6 GHz needs a Wi-Fi 6E or Wi-Fi 7 adapter"):
        assert s in src, s
    # everything is released on unmount
    for s in ("clearTimeout(timer)", "charts.signal.destroy()", "c.destroy()", "table.destroy()", "for (const u of unsubs)"):
        assert s in src, s
    # loaded before app.js: TNT.util / TNT.ui are only touched inside functions
    for rel in ("js/views/wifi.js", "js/wifichart.js"):
        top_level = [ln for ln in _read(rel).splitlines() if re.match(r"^  (const|let|var) ", ln)]
        assert not any(("TNT.util." in ln or "TNT.ui." in ln) and "=>" not in ln for ln in top_level), (rel, top_level)
    charts = _read("js/wifichart.js")
    assert "class SignalChart extends WifiChart" in charts and "class SpectrumChart extends WifiChart" in charts
    assert "class WifiChart extends Base" in charts and "TNT.charts.Chart" in charts
    css = _read("css/tnt.css")
    for sel in (".survey-top", ".survey-net", ".survey-net.selected", ".survey-sw", ".survey-bars", ".survey-table-wrap thead th",
                ".survey-table tbody tr.is-selected td", ".survey-table tbody tr.is-stale td", ".survey-dbm.green", ".survey-state",
                ".survey-bands", "canvas.survey-signal-canvas", "canvas.survey-band-canvas", ".survey-pick:focus-visible",
                ".survey-band.is-empty .chart-wrap", ".survey-band-empty"):
        assert sel in css, sel
    # red text reaches 4.5:1 in the light theme (ink-darkened), the dark theme keeps the accent
    assert ".survey-net-dbm.red { color: color-mix(in srgb, var(--red) 65%, var(--ink)); }" in css
    assert '[data-theme="dark"] .survey-net-dbm.red { color: var(--red); }' in css and '[data-theme="dark"] .survey-callerr { color: var(--red); }' in css
    assert "text-transform: none" in re.search(r"\.badge\.survey-gen \{([^}]*)\}", css).group(1)
    assert re.search(r"\.survey-bands \{[^}]*grid-template-columns: minmax\(0, 1fr\) minmax\(0, 1fr\)", css)


def test_wifi_page_is_in_the_design_doc():
    docs = _doc("docs/DESIGN.md")
    for s in ("WiFi", "--teal", "2.4 GHz", "6 GHz", "location", "trapezoid", "spectrum"):
        assert s in docs, s


_NODE_WIFI_SURVEY_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const listeners = {};
const window = { TNT: { views: {}, util: {}, api: {}, ui: {} },
  addEventListener: (t, f) => { (listeners[t] = listeners[t] || []).push(f); } };
const ctx = vm.createContext({ window, console, setTimeout, clearTimeout, setInterval, clearInterval });
['charts.js', 'wifichart.js', 'wifi.js'].forEach((n, i) => vm.runInContext(fs.readFileSync(process.argv[2 + i], 'utf8'), ctx, { filename: n }));
const W = window.TNT.wifichart, V = window.TNT.views.wifi, S = window.TNT.wifiSurvey;
const out = {};
// --- channel -> frequency, with the band edges
out.freq = {
  g1: W.channelFreq('2.4', 1), g13: W.channelFreq('2.4', 13), g14: W.channelFreq('2.4', 14), g15: W.channelFreq('2.4', 15), g0: W.channelFreq('2.4', 0),
  a36: W.channelFreq('5', 36), a149: W.channelFreq('5', 149), a177: W.channelFreq('5', 177), a181: W.channelFreq('5', 181),
  x1: W.channelFreq('6', 1), x2: W.channelFreq('6', 2), x233: W.channelFreq('6', 233), x237: W.channelFreq('6', 237), bad: W.channelFreq('7', 1),
};
const ap = (o) => Object.assign({ width_mhz: 20 }, o);
out.spans = {
  ch14: W.apSpans(ap({ band: '2.4', channel: 14, center_channel: 14 })),
  ch1_40: W.apSpans(ap({ band: '2.4', channel: 1, center_channel: 3, width_mhz: 40 })),
  x1: W.apSpans(ap({ band: '6', channel: 1, center_channel: 1 })),
  x233: W.apSpans(ap({ band: '6', channel: 233, center_channel: 233 })),
  x320: W.apSpans(ap({ band: '6', channel: 37, center_channel: 31, width_mhz: 320 })),
  given: W.apSpans(ap({ band: '5', channel: 36, spans: [[5170, 5250], [5490, 5570]] })),
  junk: W.apSpans(ap({ band: '5', spans: [[5250, 5170], 'x'] , channel: null, center_channel: null, freq_mhz: null })),
};
// frequency -> x on each band axis (x0 = 0, x1 = 1000)
const X = (f, b) => Math.round(W.freqToX(f, b, 0, 1000) * 1000) / 1000;
out.x = { gLo: X(2400, '2.4'), gHi: X(2495, '2.4'), g14lo: X(2474, '2.4'), g14hi: X(2494, '2.4'),
  aLo: X(5150, '5'), aHi: X(5895, '5'), a177hi: X(5895, '5'), xLo: X(5925, '6'), x1lo: X(5945, '6'), x233hi: X(7125, '6'), xMid: X(6525, '6') };
out.y = [W.dbmToY(-20, 10, 90), W.dbmToY(-100, 10, 90), W.dbmToY(-60, 10, 90), W.dbmToY(-5, 10, 90), W.dbmToY(-130, 10, 90)];
// trapezoids for every width, clamped levels, and the two shapes of an 80+80 access point
out.trap = {};
for (const w of [20, 40, 80, 160, 320]) out.trap[w] = W.trapezoid([5950, 5950 + w], -50);
out.trapClamp = [W.trapezoid([2402, 2422], -10), W.trapezoid([2402, 2422], -120)];
out.shapes8080 = W.apShapes({ band: '5', channel: 36, center_channel: 42, width_mhz: 160, rssi: -69, spans: [[5170, 5250], [5490, 5570]] });
// ticks
const t24 = W.channelTicks('2.4'), t5 = W.channelTicks('5'), t6 = W.channelTicks('6');
out.ticks = { g: t24.map((t) => t.ch), gMajor: t24.every((t) => t.major), aMajor: t5.filter((t) => t.major).map((t) => t.ch), aAll: t5.map((t) => t.ch),
  xMajor: t6.filter((t) => t.major).map((t) => t.ch), xFirst: t6[0].ch, xLast: t6[t6.length - 1].ch, xCount: t6.length };
out.dbmTicks = [W.dbmTicks(200), W.dbmTicks(120)];
// signal colours and bars
out.cls = [-40, -59, -60, -61, -75, -76, -95, null].map(W.signalClass);
out.bars = [-45, -50, -51, -60, -61, -75, -76, -85, -86, null].map(W.signalBars);
out.dbm = [W.dbmText(-52.4), W.dbmText(null), W.dbmText(3)];
// time ticks: a 5-minute window over 700 px (30 s steps), an hour over 700 px (10 min), a day in UTC-5 (local hours)
const T0 = 1757600000;   // 2025-09-11 14:13:20 UTC
out.time5m = W.timeTicks(T0, T0 + 300, 700, 0);
out.time1h = W.timeTicks(T0, T0 + 3600, 700, 0).map((t) => t.label);
out.timeDay = W.timeTicks(T0, T0 + 86400, 700, 300).map((t) => t.label);
out.timeNone = [W.timeTicks(T0, T0, 700, 0), W.timeTicks(T0, T0 + 60, 0, 0)];
// palette: CSS for the DOM, hex for the canvas, from the same entries
out.css = [0, 5, 6, 7, 11, 12, 23, 24, -1].map(W.paletteCss);
const tokens = { blue: '#6FA8FF', orange: '#FFA45C', green: '#6BCB77', purple: '#B48CFF', red: '#FF5C5C', teal: '#4FD1C5', yellow: '#FFD166', ink: '#2B2438' };
out.hex = [0, 7, 12].map((i) => W.paletteHex(i, tokens));
out.mix = [W.mixHex('#FF0000', '#0000FF', 50), W.mixHex('#6FA8FF', '#2B2438', 65), W.mixHex('bad', '#000000', 50)];
out.size = W.PALETTE_SIZE;
// --- networks: grouping (hidden = one network per BSSID), sorting, filter
const aps = [
  { bssid: '02:00:00:00:00:01', ssid: 'Alpha', hidden: false, rssi: -70, band: '5', stale: false },
  { bssid: '02:00:00:00:00:02', ssid: 'Alpha', hidden: false, rssi: -50, band: '2.4', stale: true },
  { bssid: '02:00:00:00:00:03', ssid: 'Alpha', hidden: false, rssi: -62, band: '6', stale: false, connected: true },
  { bssid: '0a:00:00:00:00:04', ssid: '', hidden: true, rssi: -80, band: '5', stale: false },
  { bssid: '0A:00:00:00:00:05', ssid: '', hidden: true, rssi: -55, band: '2.4', stale: false },
  { bssid: '02:00:00:00:00:06', ssid: 'Bravo', hidden: false, rssi: -40, band: '5', stale: true },
  { bssid: '02:00:00:00:00:07', ssid: 'bravo', hidden: false, rssi: -66, band: '5', stale: false },
  { bssid: null, ssid: 'Nope' },
];
const nets = V.groupNetworks(aps);
out.groups = nets.map((n) => [n.key, n.name, n.count, n.best, n.connected, n.stale, n.bands.join('|'), n.hidden]);
out.sorted = V.sortNetworks(nets).map((n) => n.key);
out.filter = [V.filterNetworks(nets, 'ALP').map((n) => n.key), V.filterNetworks(nets, '00:05').map((n) => n.key), V.filterNetworks(nets, '  ').length];
out.keys = [V.networkKey({ ssid: 'X', bssid: 'aa' }), V.networkKey({ ssid: '', bssid: 'aa:bb' }), V.networkKey({ ssid: 'X', hidden: true, bssid: 'aa' }), V.networkName({ ssid: '', bssid: 'aa:bb' })];
// --- one stable colour per network
const book = V.createColorBook();
const first = book.assign(['s:Alpha', 's:Bravo', 'b:0A:00:00:00:00:05']);
const later = book.assign(['s:Charlie', 'b:0A:00:00:00:00:05', 's:Bravo', 's:Alpha']);
const fresh = V.createColorBook();
out.colors = { first, later, again: [book.get('s:Alpha'), book.get('s:Bravo')], freshAlpha: fresh.assign(['s:Alpha'])[0],
  pref: V.fnv1a('s:Alpha') % 24, fnv: [V.fnv1a(''), V.fnv1a('a')], unknown: book.get('s:Zulu') };
const many = V.createColorBook();
const keys = Array.from({ length: 24 }, (_, i) => 's:net' + i);
out.distinct = new Set(many.assign(keys)).size;
out.overflow = many.assign(['s:net24'])[0] >= 0;
// --- history cache: merge, dedupe, cutoff, cap; inputs untouched
const cache = { A: [[100, -50], [105, -52]], B: [[90, -70]] };
const incoming = { A: [[105, -53], [110, -55], [95, -40], ['x', 1], [120, null]], C: [[200, -60]] };
out.merge = V.mergeHistory(cache, incoming, 96, 3);
out.mergeCap = V.mergeHistory({}, { A: [[1, -1], [2, -2], [3, -3], [4, -4]] }, null, 2);
out.untouched = [cache.A.length, incoming.A.length];
const pts = [[10, -1], [20, -2], [30, -3], [40, -4]];
out.range = [V.pointsInRange(pts, 20, 30), V.pointsInRange(pts, 21, 29), V.pointsInRange(pts, null, 15), V.pointsInRange(pts, 35, null), V.pointsInRange([], 0, 9)];
out.windows = [V.rangeWindow(300, 1000, 10), V.rangeWindow(0, 1000, 10), V.rangeWindow(0, 1000, null)];
// a range longer than the readings held starts at the oldest reading (never narrower than 60 s)
out.clamped = [V.rangeWindow(900, 1000, 10, 500), V.rangeWindow(900, 1000, 10, 50), V.rangeWindow(900, 1000, 10, 990),
  V.rangeWindow(0, 1000, 10, 600), V.rangeWindow(3600, 5000, 10, null)];
out.gaps = [W.gapFor(300), W.gapFor(3600), W.gapFor(86400), W.gapFor(null)];
out.requests = [V.historyRequest(900, null, null, 1000), V.historyRequest(0, null, null, 1000), V.historyRequest(900, 100, 998, 1000),
  V.historyRequest(300, 100, 500, 1000), V.historyRequest(0, 100, 900, 1000), V.historyRequest(900, 100, null, 1000),
  V.historyRequest(0, 100, null, 1000), V.historyRequest(900, null, 990, 1000), V.historyRequest(0, 100, 999.5, 1000)];
// --- table text
out.channel = [
  V.channelText({ band: '2.4', channel: 6, center_channel: 8, width_mhz: 40 }),
  V.channelText({ band: '5', channel: 36, center_channel: 42, width_mhz: 80, freq_mhz: 5180 }),
  V.channelText({ band: '5', channel: 36, center_channel: 42, width_mhz: 160, spans: [[5170, 5250], [5490, 5570]] }),
  V.channelText({ channel: null }),
];
out.phy = [V.phyText({ phys: ['n', 'ac', 'ax'], phy: 'ax' }), V.phyText({ phy: 'g' }), V.phyText({})];
out.sec = ['Open', 'OWE', 'WEP', 'WPA-Personal', 'WPA2-Personal', 'WPA3-Personal', 'WPA2/WPA3-Personal', 'WPA2-Enterprise', 'WPA3-Enterprise 192-bit', 'Unknown', ''].map(V.securityClass);
const vend = { 'C0:FF:EE': 'Contoso Access Systems', '00:C0:DE': null };
out.vendor = [
  V.vendorText({ oui: 'C0:FF:EE', locally_administered: false }, vend),
  V.vendorText({ oui: 'C2:FF:EE', locally_administered: true, base_oui: 'C0:FF:EE' }, vend),
  V.vendorText({ oui: '02:C0:DE', locally_administered: true, base_oui: '00:C0:DE' }, vend),
  V.vendorText({ oui: '06:00:00', locally_administered: true, base_oui: null }, vend),
  V.vendorText({ oui: 'D0:0D:AD', locally_administered: false }, vend),
  V.vendorText({ oui: '00:C0:DE', locally_administered: false }, new Map([['00:C0:DE', null]])),
].map((v) => [v.text, v.muted]);
out.prefixes = V.vendorPrefixes([{ oui: 'C0:FF:EE' }, { oui: 'C2:FF:EE', locally_administered: true, base_oui: 'C0:FF:EE' },
  { oui: '06:00:00', locally_administered: true, base_oui: null }, { oui: 'bad' }, { oui: 'D0:0D:AD' }]);
// --- states and the tile
const sv = (state, extra) => Object.assign({ state, enabled: true, error: 'detail ' + state, aps: [] }, extra || {});
out.states = {};
for (const st of ['ok', 'starting', 'disabled', 'location_denied', 'no_adapter', 'radio_off', 'error', 'weird']) {
  const i = V.stateInfo(sv(st), 'ready', null);
  out.states[st] = i ? [i.kind, i.title, i.actions] : null;
}
for (const b of ['none', 'outdated', 'waiting']) { const i = V.stateInfo(null, b, null); out.states[b] = [i.kind, i.title]; }
out.states.callError = V.stateInfo(null, 'ready', 'boom');
out.states.noData = V.stateInfo(null, 'ready', null).kind;
const live = [
  { bssid: '02:00:00:00:00:01', ssid: 'Alpha', rssi: -70, band: '5', channel: 36, stale: false },
  { bssid: '02:00:00:00:00:02', ssid: 'Bravo', rssi: -48, band: '2.4', channel: 6, stale: false },
  { bssid: '02:00:00:00:00:03', ssid: 'Charlie', rssi: -30, band: '6', channel: 5, stale: true },
];
out.tile = {
  strongest: V.tileSummary(sv('ok', { aps: live }), 'ready'),
  connected: V.tileSummary(sv('ok', { aps: live.map((a, i) => Object.assign({}, a, { connected: i === 0 })) }), 'ready'),
  empty: V.tileSummary(sv('ok'), 'ready'),
  starting: V.tileSummary(sv('starting'), 'ready').kind,
  denied: V.tileSummary(sv('location_denied'), 'ready').headline,
  noadapter: V.tileSummary(sv('no_adapter'), 'ready').headline,
  off: V.tileSummary(sv('disabled'), 'ready').headline,
  nobridge: V.tileSummary(null, 'none').headline,
  waiting: V.tileSummary(null, 'waiting').kind,
  callError: V.tileSummary(null, 'ready', 'boom'),
};
out.columns = V.columns;
out.ranges = V.RANGES.map((r) => [r.value, r.label]);
out.errorState = V.stateInfo(sv('error'), 'ready', null);
out.errorTile = V.tileSummary(sv('error'), 'ready');
// --- stable ordering: a row passes another only by more than the margin; groups first; a frozen order
const so = (items, prev, margin) => V.stickyOrder(items, prev, (x) => x.k, (x) => (x.stale ? 1 : 0), (x) => x.v, margin).map((x) => x.k);
const abc = [{ k: 'a', v: -60 }, { k: 'b', v: -50 }, { k: 'c', v: -55 }];
out.sticky = {
  exact: so(abc, [], 6), kept: so(abc, ['a', 'b', 'c'], 6), noMargin: so(abc, ['a', 'b', 'c'], 0),
  newcomer: so(abc.concat([{ k: 'd', v: -40 }]), ['a', 'b', 'c'], 6), weakNewcomer: so(abc.concat([{ k: 'd', v: -90 }]), ['a', 'b', 'c'], 6),
  stale: so([{ k: 'x', v: -30, stale: true }, { k: 'y', v: -80 }], ['x', 'y'], 6), gone: so([{ k: 'c', v: -55 }], ['a', 'b', 'c'], 6),
  nulls: V.stickyOrder([{ k: 'n', v: null }, { k: 'm', v: -70 }], [], (x) => x.k, () => 0, (x) => x.v, 0).map((x) => x.k),
  margin: V.SORT_MARGIN_DB,
};
out.keepOrder = V.keepOrder([{ k: 'c' }, { k: 'a' }, { k: 'e' }, { k: 'd' }, { k: 'b' }], ['a', 'b', 'x', 'c'], (x) => x.k).map((x) => x.k);
let seedJ = 7;
const jitter = () => { seedJ = (seedJ * 1103515245 + 12345) % 2147483648; return (seedJ % 3) - 1; };   // -1, 0 or +1 dB
const bases = { 's:A': -50, 's:B': -51, 's:C': -52, 's:D': -53, 's:E': -54 };
const netsAt = (shift) => Object.keys(bases).map((key) => ({ key, name: key.slice(2), stale: false, best: bases[key] + jitter() + (shift[key] || 0) }));
const orders = { sticky: [], raw: [] };
let prevS = [], prevR = [];
for (let i = 0; i < 40; i++) {
  const nets = netsAt({});
  prevS = V.sortNetworks(nets, prevS, V.SORT_MARGIN_DB).map((n) => n.key); orders.sticky.push(prevS.join());
  prevR = V.sortNetworks(nets).map((n) => n.key); orders.raw.push(prevR.join());
}
const changes = (list) => list.slice(1).filter((o, i) => o !== list[i]).length;
out.jitter = { sticky: changes(orders.sticky), raw: changes(orders.raw) };
out.realMove = V.sortNetworks(netsAt({ 's:E': 12 }), prevS, V.SORT_MARGIN_DB).map((n) => n.key)[0];
out.keys2 = [
  V.listKeyTarget('ArrowDown', 0, 10, 1), V.listKeyTarget('ArrowDown', 9, 10, 1), V.listKeyTarget('ArrowUp', 0, 10, 1), V.listKeyTarget('ArrowRight', 3, 10, 1),
  V.listKeyTarget('ArrowDown', 1, 10, 3), V.listKeyTarget('ArrowUp', 4, 10, 3), V.listKeyTarget('ArrowRight', 4, 10, 3), V.listKeyTarget('ArrowLeft', 0, 10, 3),
  V.listKeyTarget('ArrowDown', 8, 10, 3), V.listKeyTarget('Home', 5, 10, 3), V.listKeyTarget('End', 5, 10, 3), V.listKeyTarget('x', 1, 10, 1), V.listKeyTarget('ArrowDown', 0, 0, 1),
];
out.hiddenLabel = [V.hiddenLabel('cc:a7:00:31:00:03'), V.hiddenLabel('')];
out.sixEmpty = [[{ description: 'Synthetic Wi-Fi 6E AX900 160MHz' }], [{ description: 'Synthetic Wi-Fi 7 BE900 320MHz' }], [{ description: 'Synthetic FastConnect 9900 Wi-Fi 7' }],
  [{ description: 'Synthetic Dual Band Wireless-AC 5000' }], [{ description: 'Synthetic Wi-Fi 6 MT9999' }], [], null].map((i) => V.sixGhzEmptyText(i) === V.EMPTY_6GHZ_CAPABLE);
// 2.4 GHz channel labels: one step for the whole axis at every canvas width
out.labels24 = {};
for (let w = 280; w <= 900; w += 1) {
  const ticks = W.channelTicks('2.4').map((tk) => Object.assign({ x: Math.round(W.freqToX(tk.f, '2.4', 48, w - 12)) + 0.5 }, tk));
  out.labels24[w] = W.labelChannels('2.4', ticks);
}
const t5x = W.channelTicks('5').map((tk) => Object.assign({ x: Math.round(W.freqToX(tk.f, '5', 48, 600)) + 0.5 }, tk));
out.labels5 = W.labelChannels('5', t5x);
out.fill = [1, 6, 12, 20, 40, 0].map(W.fillAlpha);
// hit testing searches the pixel columns near the pointer only
const sc = Object.create(W.SignalChart.prototype);
const pt = (x, y, key) => ({ x, y, ts: 1, v: -50, strong: false, s: { key, net: 's:' + key, name: key } });
sc._cols = new Map([[100, [pt(100, 50, 'a')]], [112, [pt(112, 60, 'b')]], [300, [pt(300, 50, 'c')]]]);
out.hit = [sc.hitTest(103, 51) && sc.hitTest(103, 51).key, sc.hitTest(111, 60) && sc.hitTest(111, 60).key, sc.hitTest(200, 50), sc.hitTest(286, 50) && sc.hitTest(286, 50).key];
// a gap never swallows the reading before it: a lone reading stays a one-point line and the last reading before
// a gap stays on its line (it used to be dropped, leaving an empty line that drawing threw on)
const segTs = (pts, t0, t1) => sc._segments({ points: pts }, (t) => t, (v) => -v, t0, t1).map((sg) => Array.from(new Set(sg.map((p) => p[2]))));
out.segs = [
  segTs([[0, -50], [400, -52], [410, -53]], 0, 1000),
  segTs([[0, -50], [10, -51], [20, -52], [400, -60], [700, -61]], 0, 1000),
  segTs([[0, -50], [0.2, -55], [400, -60]], 0, 1000),          // two readings in one pixel column, then a gap
];
// drawing such a history does not throw, and the lone reading is a dot
const calls = { arc: 0 };
const ctx2d = new Proxy({}, {
  get: (t, k) => (k in t ? t[k] : () => { if (k in calls) calls[k]++; return { width: 0 }; }),
  set: (t, k, v) => { t[k] = v; return true; },
});
const sd = Object.create(W.SignalChart.prototype);
Object.assign(sd, { c: { ink: '#101010', inkSoft: '#606060', green: '#00A000', yellow: '#C0A000', red: '#C00000', paper: '#FFFFFF' }, font: 'sans-serif',
  t0: 0, t1: 1000, dim: false, empty: '', _hoverKey: null, _cols: new Map(), _colsSeries: null, _colsGeom: '',
  series: [{ key: 'a', net: 's:a', name: 'a', color: 0, selected: true, points: [[100, -50], [600, -52], [610, -53]] }] });
sd.color = () => '#3060C0';
try { sd.draw(ctx2d, 1000, 300); out.drawGap = { error: null, arcs: calls.arc }; } catch (e) { out.drawGap = { error: String(e), arcs: calls.arc }; }
// the incremental merge agrees with the plain Map merge it replaced, on random caches, overlaps, junk and caps
function refMerge(cache, incoming, cutoff, cap) {
  const res = {}; const cut = cutoff == null ? -Infinity : cutoff;
  for (const k of new Set(Object.keys(cache || {}).concat(Object.keys(incoming || {})))) {
    const m = new Map();
    for (const src of [(cache || {})[k], (incoming || {})[k]]) {
      for (const p of Array.isArray(src) ? src : []) {
        if (!Array.isArray(p) || p.length < 2 || !isFinite(p[0]) || p[1] == null || !isFinite(p[1]) || p[0] < cut) continue;
        m.set(Number(p[0]), Number(p[1]));
      }
    }
    if (!m.size) continue;
    let l = Array.from(m.entries()).sort((a, b) => a[0] - b[0]);
    if (l.length > cap) l = l.slice(l.length - cap);
    res[k] = l;
  }
  return res;
}
let seedM = 11;
const rnd = (n) => { seedM = (seedM * 1103515245 + 12345) % 2147483648; return seedM % n; };
let mismatches = 0;
for (let i = 0; i < 400; i++) {
  const cap = 3 + rnd(40);
  const mk = (n, lo, span) => Array.from({ length: n }, () => (rnd(15) === 0 ? ['x', 1] : [lo + rnd(span), rnd(9) === 0 ? null : -40 - rnd(50)]));
  const cache = refMerge({}, { A: mk(rnd(60), 0, 100), B: mk(rnd(5), 50, 20) }, null, cap);
  const incoming = { A: mk(rnd(20), 60 + rnd(60), 60), C: mk(rnd(4), 0, 200) };
  if (rnd(2)) incoming.A.reverse();
  const cutoff = rnd(3) === 0 ? null : rnd(120);
  const got = V.mergeHistory(cache, incoming, cutoff, cap), want = refMerge(cache, incoming, cutoff, cap);
  const norm = (o) => JSON.stringify(Object.keys(o).sort().map((k) => [k, o[k]]));
  if (norm(got) !== norm(want)) mismatches++;
}
out.mergeMismatches = mismatches;
// --- the bridge client: no bridge, an older window, calls shared and never piled up
(async () => {
  out.bridge = { none: S.bridgeState() };
  S.readyFired = true;
  out.bridge.noneAfterReady = S.bridgeState();
  out.bridge.noApiCall = await S.call('wifi_clear');
  out.bridge.noApiFetch = await S.fetch({ active: true, history_s: 0 });
  window.pywebview = { api: { save_file: () => null } };
  out.bridge.outdated = S.bridgeState();
  let calls = 0;
  window.pywebview.api.wifi_survey = (o) => { calls++; return new Promise((r) => setTimeout(() => r({ state: 'ok', aps: [], history: {}, opts: o }), 20)); };
  window.pywebview.api.wifi_scan_now = () => { throw new Error('rate limited'); };
  window.pywebview.api.open_location_settings = () => true;
  out.bridge.ready = S.bridgeState();
  const [a, b] = await Promise.all([S.fetch({ active: true, history_s: 300 }), S.fetch({ active: true, history_s: 300 })]);
  out.bridge.shared = { calls, same: a === b, opts: a.opts };
  const [c, d] = await Promise.all([S.fetch({ active: true, history_s: 20 }), S.fetch({ active: false, history_s: 0 })]);
  out.bridge.different = { calls, c: c.opts, d: d.opts };
  out.bridge.thrown = await S.call('wifi_scan_now');
  out.bridge.truthy = await S.call('open_location_settings');
  window.pywebview.api.wifi_survey = () => ({ ok: false, error: 'not the TNT page' });
  out.bridge.refused = [await S.fetch({ active: true }), S.error];
  let hooked = 0;
  const off = S.hook(() => { hooked++; });
  listeners.pywebviewready.forEach((f) => f());
  off();
  listeners.pywebviewready.forEach((f) => f());
  out.bridge.hooked = hooked;
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_wifi_survey_helpers_with_node(tmp_path):
    driver = tmp_path / "driver.js"
    driver.write_text(_NODE_WIFI_SURVEY_DRIVER, encoding="utf-8")
    files = [UI / "js/charts.js", UI / "js/wifichart.js", UI / "js/views/wifi.js"]
    r = subprocess.run(["node", str(driver)] + [str(f) for f in files], capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    # channel -> centre frequency, band edges included (2.4 GHz ch 14, 6 GHz ch 1/2/233)
    assert out["freq"] == {"g1": 2412, "g13": 2472, "g14": 2484, "g15": None, "g0": None, "a36": 5180, "a149": 5745, "a177": 5885,
                           "a181": None, "x1": 5955, "x2": 5935, "x233": 7115, "x237": None, "bad": None}
    s = out["spans"]
    assert s["ch14"] == [[2474, 2494]] and s["ch1_40"] == [[2402, 2442]] and s["x1"] == [[5945, 5965]] and s["x233"] == [[7105, 7125]]
    assert s["x320"] == [[5945, 6265]] and s["given"] == [[5170, 5250], [5490, 5570]] and s["junk"] == []
    # every band axis starts at 0 and ends at 1000, and the edge channels stay inside it
    x = out["x"]
    assert x["gLo"] == 0 and x["gHi"] == 1000 and 0 < x["g14lo"] < x["g14hi"] < 1000
    assert x["aLo"] == 0 and x["aHi"] == 1000 and x["xLo"] == 0 and x["x233hi"] == 1000 and 0 < x["x1lo"] < 20 and x["xMid"] == 500
    assert out["y"] == [10, 90, 50, 10, 90]
    # the trapezoid: base = the span on the floor, sides slope in by 10 % of the width, top at the level
    for w, slope in ((20, 2), (40, 4), (80, 8), (160, 16), (320, 32)):
        assert out["trap"][str(w)] == [[5950, -100], [5950 + slope, -50], [5950 + w - slope, -50], [5950 + w, -100]], w
    assert out["trapClamp"][0][1] == [2404, -20] and out["trapClamp"][1][1] == [2404, -100]
    assert out["shapes8080"] == [[[5170, -100], [5178, -69], [5242, -69], [5250, -100]],
                                 [[5490, -100], [5498, -69], [5562, -69], [5570, -100]]]
    t = out["ticks"]
    assert t["g"] == list(range(1, 15)) and t["gMajor"] is True
    assert t["aMajor"] == [36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157, 165, 173]
    assert t["aAll"][0] == 36 and t["aAll"][-1] == 177 and 68 not in t["aAll"] and 96 not in t["aAll"] and 144 in t["aAll"]
    assert t["xMajor"] == list(range(1, 226, 16)) and t["xFirst"] == 1 and t["xLast"] == 233 and t["xCount"] == 59
    assert out["dbmTicks"] == [[-20, -30, -40, -50, -60, -70, -80, -90, -100], [-20, -40, -60, -80, -100]]
    # signal colours: green >= -60, yellow -60 .. -75, red below -75
    assert out["cls"] == ["green", "green", "green", "yellow", "yellow", "red", "red", "grey"]
    assert out["bars"] == [4, 4, 3, 3, 2, 2, 1, 1, 0, 0]
    assert out["dbm"] == ["−52 dBm", "—", "3 dBm"]
    # time ticks: 30 s steps with seconds, 10 min steps, local hours with a -5 h offset
    t5 = out["time5m"]
    assert [x["label"] for x in t5] == ["14:13:30", "14:14:00", "14:14:30", "14:15:00", "14:15:30", "14:16:00", "14:16:30",
                                        "14:17:00", "14:17:30", "14:18:00"]
    assert all(x["t"] % 30 == 0 for x in t5)
    assert out["time1h"] == ["14:20", "14:30", "14:40", "14:50", "15:00", "15:10"]
    assert out["timeDay"] == ["12:00", "15:00", "18:00", "21:00", "00:00", "03:00", "06:00", "09:00"]   # 09:13 local start, 3 h steps
    assert out["timeNone"] == [[], []]
    # the palette: 12 token hues and their deeper twins, the DOM and canvas forms agree
    assert out["size"] == 24
    assert out["css"] == ["var(--blue)", "var(--teal)", "var(--yellow)", "color-mix(in srgb, var(--red) 50%, var(--purple))",
                          "color-mix(in srgb, var(--orange) 50%, var(--yellow))", "color-mix(in srgb, var(--blue) 65%, var(--ink))",
                          "color-mix(in srgb, color-mix(in srgb, var(--orange) 50%, var(--yellow)) 65%, var(--ink))", "var(--blue)",
                          "color-mix(in srgb, color-mix(in srgb, var(--orange) 50%, var(--yellow)) 65%, var(--ink))"]
    assert out["mix"] == ["#800080", "#577AB9", "bad"]
    assert out["hex"] == ["#6FA8FF", "#DA74AE", "#577AB9"]
    # networks: SSIDs group their access points; each hidden BSSID is its own network
    groups = {g[0]: g[1:] for g in out["groups"]}
    assert set(groups) == {"s:Alpha", "b:0A:00:00:00:00:04", "b:0A:00:00:00:00:05", "s:Bravo", "s:bravo"}
    assert groups["s:Alpha"] == ["Alpha", 3, -62, True, False, "2.4|5|6", False]         # best = strongest *live* AP
    assert groups["s:Bravo"] == ["Bravo", 1, -40, False, True, "5", False]               # all stale: its last reading
    assert groups["b:0A:00:00:00:00:05"] == ["0A:00:00:00:00:05 (hidden)", 1, -55, False, False, "2.4", True]
    assert out["sorted"] == ["b:0A:00:00:00:00:05", "s:Alpha", "s:bravo", "b:0A:00:00:00:00:04", "s:Bravo"]
    assert out["filter"] == [["s:Alpha"], ["b:0A:00:00:00:00:05"], 5]
    assert out["keys"] == ["s:X", "b:AA:BB", "b:AA", "AA:BB (hidden)"]
    # colours: stable once given, new networks never take a colour in use, a fresh session repeats the hash choice
    c = out["colors"]
    assert c["later"][3] == c["first"][0] and c["later"][2] == c["first"][1] and c["later"][1] == c["first"][2]
    assert c["again"] == c["first"][:2] and c["later"][0] not in c["first"] and c["unknown"] is None
    assert c["freshAlpha"] == c["pref"] == c["first"][0]
    assert c["fnv"] == [2166136261, 3826002220]
    assert out["distinct"] == 24 and out["overflow"] is True
    # history: merged by timestamp (the newer value wins), sorted, cut off, capped; inputs untouched
    assert out["merge"] == {"A": [[100, -50], [105, -53], [110, -55]], "C": [[200, -60]]}
    assert out["mergeCap"] == {"A": [[3, -3], [4, -4]]}
    assert out["untouched"] == [2, 5]
    assert out["range"] == [[[20, -2], [30, -3]], [], [[10, -1]], [[40, -4]], []]
    assert out["windows"] == [[700, 1000], [10, 1000], [700, 1000]]
    # a range longer than the collected history starts at the oldest reading, never narrower than 60 s
    assert out["clamped"] == [[500, 1000], [100, 1000], [940, 1000], [600, 1000], [1400, 5000]]
    # lines break where readings are 150 s apart, or 1/60 of a long span
    assert out["gaps"] == [150, 150, 1440, 150]
    # incremental: from the last BSS-list read the page saw, with a 15 s margin; no read seen yet (or no
    # complete cache) asks for the whole range again, because a late beacon may be stamped anywhere after it
    assert out["requests"] == [900, None, 17, 300, 115, 900, None, 900, 16]
    ch = out["channel"]
    assert (ch[0]["text"], ch[0]["sub"]) == ("6 · 40 MHz", "centre 8") and "2427–2467 MHz" in ch[0]["title"]
    assert (ch[1]["text"], ch[1]["sub"]) == ("36 · 80 MHz", "") and "5170–5250 MHz" in ch[1]["title"] and "(5180 MHz)" in ch[1]["title"]
    assert (ch[2]["text"], ch[2]["sub"]) == ("36 · 80+80 MHz", "centre 42") and "5170–5250 MHz + 5490–5570 MHz" in ch[2]["title"]
    assert ch[3]["text"] == "—"
    assert out["phy"] == ["n, ac, ax", "g", "—"]
    assert out["sec"] == ["red", "green", "red", "yellow", "green", "green", "green", "green", "green", "grey", "grey"]
    assert out["vendor"] == [["Contoso Access Systems", False], ["likely Contoso Access Systems", False], ["Private address", True],
                             ["Private address", True], ["…", True], ["—", True]]
    assert out["prefixes"] == ["C0:FF:EE", "D0:0D:AD"]
    st = out["states"]
    assert st["ok"] is None and st["starting"] is None
    assert st["disabled"] == ["disabled", "Survey off", ["enable"]]
    assert st["location_denied"] == ["location_denied", "Location access needed", ["location", "retry"]]
    assert st["no_adapter"][1] == "No Wi-Fi adapter" and st["radio_off"][1] == "Wi-Fi is turned off"
    assert st["error"][0] == "error" and st["weird"][0] == "error"
    assert st["none"] == ["nobridge", "The Wi-Fi survey runs in the TNT window"] and st["outdated"][0] == "outdated" and st["waiting"][0] == "waiting"
    assert st["callError"]["kind"] == "error" and st["callError"]["text"] == "boom" and st["noData"] == "waiting"
    tile = out["tile"]
    assert tile["strongest"]["kind"] == "ok" and tile["strongest"]["networks"] == 2 and tile["strongest"]["aps"] == 2
    assert tile["strongest"]["top"] == {"name": "Bravo", "rssi": -48, "cls": "green", "bars": 4, "connected": False, "band": "2.4", "channel": 6}
    assert tile["connected"]["top"]["name"] == "Alpha" and tile["connected"]["top"]["connected"] is True and tile["connected"]["top"]["cls"] == "yellow"
    assert tile["empty"]["top"] is None and tile["starting"] == "starting"
    assert (tile["denied"], tile["noadapter"], tile["off"], tile["nobridge"]) == ("Location access needed", "No Wi-Fi adapter", "Survey off", "Open in the TNT window")
    assert tile["waiting"] == "waiting" and tile["callError"]["kind"] == "error"
    # the mockup's column order: the columns that tell networks apart first, the BSSID and the time last
    assert out["columns"] == ["ssid", "band", "channel", "rssi", "phy", "security", "vendor", "bssid", "last_seen"]
    assert out["ranges"] == [[300, "5 m"], [900, "15 m"], [3600, "1 h"], [0, "All"]]
    # the error state: plain words, the client's message in the mono detail line; no Win32 text on the tile
    assert out["errorState"]["text"] == "Something went wrong while reading nearby networks." and out["errorState"]["detail"] == "detail error"
    assert (out["errorTile"]["headline"], out["errorTile"]["detail"]) == ("Survey error", "Open the WiFi page for details")
    # rows move only for a real change: a row passes the one above it by more than 6 dB, a new row by any
    # margin, a live row always passes an out-of-range one; without a previous order the sort is exact
    st = out["sticky"]
    assert st["exact"] == ["b", "c", "a"] and st["noMargin"] == ["b", "c", "a"]
    assert st["kept"] == ["b", "a", "c"], "b passes a by 10 dB; c stays under a (5 dB is jitter)"
    assert st["newcomer"] == ["d", "b", "a", "c"] and st["weakNewcomer"] == ["b", "a", "c", "d"]
    assert st["stale"] == ["y", "x"] and st["gone"] == ["c"] and st["nulls"] == ["m", "n"] and st["margin"] == 6
    assert out["keepOrder"] == ["a", "b", "c", "e", "d"]
    assert out["jitter"]["sticky"] == 0 and out["jitter"]["raw"] > 5, out["jitter"]
    assert out["realMove"] == "s:E", "12 dB stronger moves a network to the top"
    assert out["keys2"] == [1, 9, 0, None, 4, 1, 5, 0, 9, 0, 9, None, None]
    assert out["hiddenLabel"] == ["hidden …00:03", "hidden …"]
    assert out["sixEmpty"] == [True, True, True, False, False, False, False]
    # 2.4 GHz channel labels: every channel, every other one or every fourth, never a mix (1366 px windows included)
    regular = {tuple(range(1, 15)), tuple(range(1, 14, 2)) + (14,), tuple(range(1, 14, 2)), (1, 5, 9, 13, 14), (1, 5, 9, 13)}
    irregular = {w: labels for w, labels in out["labels24"].items() if tuple(labels) not in regular}
    assert not irregular, irregular
    assert tuple(out["labels24"]["467"]) in regular and len(out["labels24"]["900"]) == 14
    assert out["labels5"][0] == 36 and all(c in (36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157, 165, 173) for c in out["labels5"])
    assert out["fill"] == [0.3, 0.3, 0.15, 0.1, 0.1, 0.3]
    assert out["hit"] == ["a", "b", None, None], "a reading 14 px away is out of reach"
    # a gap never loses the reading before it (a lone reading is a one-point line), and drawing that never throws
    assert out["segs"] == [[[0], [400, 410]], [[0, 10, 20], [400], [700]], [[0, 0.2], [400]]]
    assert out["drawGap"] == {"error": None, "arcs": 1}
    assert out["mergeMismatches"] == 0
    b = out["bridge"]
    assert b["none"] == "waiting" and b["noneAfterReady"] == "none" and b["outdated"] == "outdated" and b["ready"] == "ready"
    assert b["noApiCall"] == {"ok": False, "error": "The TNT window has no wifi_clear"} and b["noApiFetch"] is None
    assert b["shared"] == {"calls": 1, "same": True, "opts": {"active": True, "history_s": 300}}      # one call for two callers
    assert b["different"] == {"calls": 3, "c": {"active": True, "history_s": 20}, "d": {"active": False, "history_s": 0}}
    assert b["thrown"] == {"ok": False, "error": "rate limited"} and b["truthy"] == {"ok": True}
    assert b["refused"] == [None, "not the TNT page"]
    assert b["hooked"] == 1


_NODE_MOCK_BRIDGE_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const src = fs.readFileSync(process.argv[2], 'utf8');
function load(search) {
  const attrs = {};
  const events = [];
  const window = { location: { search }, addEventListener: () => {}, dispatchEvent: (e) => events.push(e.type) };
  const document = { documentElement: { setAttribute: (k, v) => { attrs[k] = v; } } };
  class Event { constructor(type) { this.type = type; } }
  const quiet = { error: () => {}, info: () => {}, log: () => {} };
  vm.runInContext(src, vm.createContext({ window, document, Event, URLSearchParams, console: quiet, setTimeout, clearTimeout, JSON, Math, Date }), { filename: 'mock_wifi_bridge.js' });
  return { window, attrs, events };
}
(async () => {
  const out = {};
  const ok = load('');
  const api = ok.window.pywebview.api;
  out.methods = Object.keys(api).sort();
  out.events = ok.events;
  out.errorsAttr = ok.attrs['data-mock-errors'];
  out.full = await api.wifi_survey({ active: true, history_s: null });
  out.none = await api.wifi_survey({ active: false, history_s: 0 });
  out.recent = await api.wifi_survey({ active: true, history_s: 60 });
  out.now = Date.now() / 1000;
  out.scan = [await api.wifi_scan_now(), await api.wifi_scan_now()];
  out.off = [await api.wifi_set_enabled(false), (await api.wifi_survey({ active: true })).state, (await api.wifi_scan_now()).ok];
  out.on = [await api.wifi_set_enabled(true), (await api.wifi_survey({ active: true })).state];
  out.clear = [await api.wifi_clear(), await api.wifi_survey({ active: true, history_s: null })];
  out.location = await api.open_location_settings();
  out.modes = {};
  for (const m of ['denied', 'noadapter', 'off', 'radiooff', 'error', 'empty', 'starting']) {
    const l = load('?wifi=' + m);
    const s = await l.window.pywebview.api.wifi_survey({ active: true, history_s: null });
    const scans = [await l.window.pywebview.api.wifi_scan_now(), await l.window.pywebview.api.wifi_scan_now()].map((r) => r.ok);
    out.modes[m] = { state: s.state, available: s.available, enabled: s.enabled, error: s.error, aps: s.aps.length, interfaces: s.interfaces.length,
      active: s.active, scans };
  }
  const nb = load('?wifi=nobridge');
  out.nobridge = [nb.window.pywebview === undefined, nb.attrs['data-mock-errors']];
  const od = load('?wifi=outdated');
  out.outdated = Object.keys(od.window.pywebview.api);
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""

#: the survey dict and its access point dicts, exactly as the shared contract with the client lists them
SURVEY_KEYS = {"available", "enabled", "state", "error", "started_ts", "last_read_ts", "last_scan_ts", "active", "scan_interval_s",
               "passive_interval_s", "interfaces", "aps", "history"}
SURVEY_IFACE_KEYS = {"guid", "description", "state", "connected_bssid", "connected_ssid"}
SURVEY_AP_KEYS = {"bssid", "ssid", "hidden", "rssi", "quality", "band", "channel", "center_channel", "width_mhz", "freq_mhz", "spans",
                  "phy", "phys", "generation", "security", "beacon_ms", "max_rate_mbps", "oui", "locally_administered", "base_oui",
                  "connected", "first_seen", "last_seen", "seen_count", "stale"}
SURVEY_STATES = {"ok", "starting", "disabled", "no_adapter", "radio_off", "location_denied", "error"}
SURVEY_SECURITY = {"Open", "OWE", "WEP", "WPA-Personal", "WPA2-Personal", "WPA3-Personal", "WPA2/WPA3-Personal", "WPA-Enterprise",
                   "WPA2-Enterprise", "WPA3-Enterprise", "WPA3-Enterprise 192-bit", "Unknown"}


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_mock_wifi_bridge_matches_the_survey_contract(tmp_path, mock):
    driver = tmp_path / "driver.js"
    driver.write_text(_NODE_MOCK_BRIDGE_DRIVER, encoding="utf-8")
    r = subprocess.run(["node", str(driver), str(MOCK_BRIDGE)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["methods"] == ["open_location_settings", "wifi_clear", "wifi_scan_now", "wifi_set_enabled", "wifi_survey"]
    assert out["events"] == ["pywebviewready"] and out["errorsAttr"] == "[]"
    s = out["full"]
    assert set(s) == SURVEY_KEYS
    assert s["available"] is True and s["enabled"] is True and s["state"] == "ok" and s["error"] is None and s["active"] is True
    assert s["scan_interval_s"] == 10 and s["passive_interval_s"] == 60
    assert s["started_ts"] < s["last_read_ts"] <= out["now"] and s["last_scan_ts"] is not None
    assert len(s["interfaces"]) == 1 and set(s["interfaces"][0]) == SURVEY_IFACE_KEYS
    aps = s["aps"]
    assert 28 <= len(aps) <= 40
    known_ouis = set(mock.mod.OUI_VENDORS)
    for ap in aps:
        assert set(ap) == SURVEY_AP_KEYS, ap["bssid"]
        assert re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}", ap["bssid"]) and ap["oui"] == ap["bssid"][:8]
        la = bool(int(ap["bssid"][:2], 16) & 2)
        assert ap["locally_administered"] is la
        # invented addresses only: locally administered, or one of the mock's invented OUIs
        assert la or ap["oui"] in known_ouis, ap["bssid"]
        if la:
            assert ap["base_oui"] == "%02X" % (int(ap["bssid"][:2], 16) & ~2) + ap["bssid"][2:8]
        else:
            assert ap["base_oui"] is None
        assert ap["hidden"] is (ap["ssid"] == "")
        assert ap["band"] in ("2.4", "5", "6") and ap["width_mhz"] in (20, 40, 80, 160, 320)
        assert isinstance(ap["rssi"], int) and -100 <= ap["rssi"] <= -20 and 0 <= ap["quality"] <= 100
        assert ap["spans"] and all(lo < hi for lo, hi in ap["spans"]) and len(ap["spans"]) in (1, 2)
        assert ap["phy"] in ("b", "g", "a", "n", "ac", "ax", "be") and ap["phys"][-1] == ap["phy"]
        assert ap["generation"] in (None, "Wi-Fi 4", "Wi-Fi 5", "Wi-Fi 6", "Wi-Fi 6E", "Wi-Fi 7")
        assert ap["security"] in SURVEY_SECURITY
        assert ap["first_seen"] <= ap["last_seen"] and ap["seen_count"] >= 1 and isinstance(ap["stale"], bool)
    # a lively environment: every band and width, 80+80, hidden networks, multi-AP SSIDs, one connection
    assert {a["band"] for a in aps} == {"2.4", "5", "6"} and {a["width_mhz"] for a in aps} == {20, 40, 80, 160, 320}
    assert any(len(a["spans"]) == 2 for a in aps) and sum(a["hidden"] for a in aps) >= 3
    assert {"Open", "OWE", "WEP", "WPA-Personal", "WPA2-Personal", "WPA3-Personal", "WPA2-Enterprise"} <= {a["security"] for a in aps}
    ssids = [a["ssid"] for a in aps if a["ssid"]]
    assert max(ssids.count(x) for x in ssids) >= 3
    assert [a["connected"] for a in aps].count(True) == 1
    assert s["interfaces"][0]["connected_bssid"] == next(a["bssid"] for a in aps if a["connected"])
    assert {2484, 5955, 7115} <= {a["freq_mhz"] for a in aps}   # 2.4 GHz ch 14, 6 GHz ch 1 and 233
    # history: only readings, per BSSID, within history_s
    assert s["history"] and set(s["history"]) <= {a["bssid"] for a in aps}
    assert all(len(p) == 2 and p[0] <= out["now"] for pts in s["history"].values() for p in pts)
    assert out["none"]["history"] == {} and out["none"]["active"] is True           # the lease from the call before
    assert all(p[0] >= out["now"] - 61 for pts in out["recent"]["history"].values() for p in pts)
    # scan rate limit, the switch, clear, location settings
    assert out["scan"][0] == {"ok": True, "error": None} and out["scan"][1]["ok"] is False
    assert out["off"] == [{"ok": True, "enabled": False}, "disabled", False]
    assert out["on"] == [{"ok": True, "enabled": True}, "ok"]
    assert out["clear"][0] == {"ok": True} and out["clear"][1]["started_ts"] > s["started_ts"]
    assert out["location"] == {"ok": True}
    m = out["modes"]
    assert m["denied"]["state"] == "location_denied" and m["denied"]["aps"] == 0 and m["denied"]["error"]
    assert m["noadapter"] == {"state": "no_adapter", "available": False, "enabled": True, "error": m["noadapter"]["error"], "aps": 0, "interfaces": 0,
                              "active": True, "scans": [True, False]}
    assert m["off"]["state"] == "disabled" and m["off"]["enabled"] is False and m["off"]["active"] is False
    assert m["radiooff"]["state"] == "radio_off" and m["error"]["state"] == "error" and "1168" in m["error"]["error"]
    assert m["empty"]["state"] == "ok" and m["empty"]["aps"] == 0
    assert m["starting"]["state"] == "starting" and m["starting"]["aps"] == 0
    assert all(v["state"] in SURVEY_STATES for v in m.values())
    # like the client: every state but "ok" says why in plain language, and "ok" carries no message
    assert all(isinstance(v["error"], str) and v["error"] for v in m.values() if v["state"] != "ok"), m
    assert m["empty"]["error"] is None
    # like the client: "Scan now" is refused only while switched off or within 5 s of the last request; in an
    # unhappy state it is the retry
    assert m["off"]["scans"] == [False, False]
    assert all(v["scans"] == [True, False] for k, v in m.items() if k != "off"), m
    assert out["nobridge"] == [True, "[]"] and out["outdated"] == ["save_file"]


def test_wifi_page_mock_and_client_share_one_survey_contract():
    """One contract, three sides: the client's own survey dict (client/wifi_survey.py on a fake native layer),
    the key sets the mock bridge is held to above, and every survey field the WiFi page dereferences."""
    from client import wifi_survey

    assert set(wifi_survey.STATES) == SURVEY_STATES
    assert set(wifi_survey.blank_view()) == SURVEY_KEYS

    class OneAccessPoint:
        def open(self) -> None: ...
        def close(self) -> None: ...
        def radio_on(self, ref: Any) -> bool: return True
        def scan(self, ref: Any) -> None: ...
        def current_connection(self, ref: Any) -> None: return None

        def interfaces(self) -> list:
            return [{"guid": "0badc0de-0000-4000-8000-000000000001", "description": "Synthetic Wi-Fi", "state": "disconnected", "ref": None}]

        def bss_list(self, ref: Any) -> list:
            return [{"ssid": b"Synthetic Lab", "bssid": b"\x02\x00\x00\x00\x00\x01", "phy_type": 0, "rssi": -50, "link_quality": 80,
                     "in_reg_domain": True, "beacon_period": 100, "timestamp": 1, "host_timestamp": 0, "capability": 1,
                     "freq_khz": 5180000, "rates": [], "ies": b""}]

    survey = wifi_survey.WifiSurvey(api_factory=OneAccessPoint, threaded=False)
    survey.window_shown()
    survey.tick()
    view = survey.survey({"active": False, "history_s": None})
    assert set(view) == SURVEY_KEYS and view["state"] == "ok" and view["error"] is None
    assert [set(i) for i in view["interfaces"]] == [SURVEY_IFACE_KEYS]
    assert [set(a) for a in view["aps"]] == [SURVEY_AP_KEYS] and view["aps"][0]["security"] in SURVEY_SECURITY
    for state in SURVEY_STATES - {"ok"}:
        assert set(wifi_survey.blank_view(state, "why")) == SURVEY_KEYS
    # the page reads nothing the contract does not have (a renamed field would fail here, not on screen)
    for rel, names in (("js/views/wifi.js", ("ap", "data", "iface")), ("js/wifichart.js", ("ap",))):
        src = _read(rel)
        allowed = {"ap": SURVEY_AP_KEYS, "data": SURVEY_KEYS, "iface": SURVEY_IFACE_KEYS}
        for name in names:
            used = set(re.findall(r"\b" + name + r"\.([a-z_]+)\b", src))
            assert used and used <= allowed[name], (rel, name, sorted(used - allowed[name]))


def test_mock_wifi_bridge_is_development_only():
    """The fake bridge lives under tools/ and is injected by the mock server, never by the UI."""
    assert MOCK_BRIDGE.is_file() and not (UI / "js" / "mock_wifi_bridge.js").exists()
    for rel in ["index.html", "css/tnt.css"] + JS_FILES:
        assert "mock" not in _read(rel).lower(), rel
    src = MOCK_BRIDGE.read_text(encoding="utf-8")
    assert "DEVELOPMENT ONLY" in src and "window.pywebview.api" in src


def test_mock_oui_route(mock):
    st, _, body = _req(mock.port, "GET", "/api/oui?prefix=C0:FF:EE&prefix=aa:bb:cc")
    assert st == 200 and body == {"vendors": {"C0:FF:EE": "Contoso Access Systems", "AA:BB:CC": None}}
    st, _, body = _req(mock.port, "GET", "/api/oui?prefix=F0-0D-CA,D00DAD,%20DC:BA:5E")
    assert st == 200 and body["vendors"] == {"F0:0D:CA": "Fabrikam Networks", "D0:0D:AD": "Northwind Radio Co.", "DC:BA:5E": "Example Wireless Co."}
    for bad in ("", "?prefix=", "?prefix=C0:FF", "?prefix=G0:FF:EE", "?prefix=C0:FF:EE:01", "?prefix=C0FFEE00", "?prefix=C0-FF:EE"):
        st, _, err = _req(mock.port, "GET", "/api/oui" + bad)
        assert st == 400 and err["error"]["code"] == "bad_request", bad
    # like the service: duplicates collapse (in request order), but they still count towards the 256
    st, _, body = _req(mock.port, "GET", "/api/oui?prefix=dc:ba:5e,C0:FF:EE&prefix=DCBA5E")
    assert st == 200 and list(body["vendors"]) == ["DC:BA:5E", "C0:FF:EE"]
    q = "&".join(f"prefix=02:{i // 256:02X}:{i % 256:02X}" for i in range(257))
    st, _, err = _req(mock.port, "GET", "/api/oui?" + q)
    assert st == 400 and "at most 256" in err["error"]["message"]
    q = "&".join(f"prefix=02:00:{i:02X}" for i in range(256))
    st, _, body = _req(mock.port, "GET", "/api/oui?" + q)
    assert st == 200 and len(body["vendors"]) == 256


def test_mock_serves_index_with_the_fake_bridge(mock):
    st, h, body = _req(mock.port, "GET", "/", raw=True)
    assert st == 200
    assert b'<script src="/mock/wifi-bridge.js"></script>\n<script src="js/api.js"></script>' in body
    assert body.index(b"/mock/wifi-bridge.js") < body.index(b"js/app.js")
    assert b"/mock/wifi-bridge.js" not in (UI / "index.html").read_bytes()      # the file on disk (and the build) stays clean
    st, h, js = _req(mock.port, "GET", "/mock/wifi-bridge.js", raw=True)
    assert st == 200 and h["content-type"].startswith("application/javascript") and js == MOCK_BRIDGE.read_bytes()
    st, _, _ = _req(mock.port, "GET", "/mock/other.js")
    assert st == 404


# ---------------------------------------------------------------------------
# small screens
# ---------------------------------------------------------------------------
def _css_rules(css: str):
    """(selectors, declarations) for every rule in ``css``, rules inside @media included."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    rules = []
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        decls = {}
        for part in m.group(2).split(";"):
            if ":" in part:
                key, value = part.split(":", 1)
                decls[key.strip()] = " ".join(value.split())
        rules.append(([s.strip() for s in m.group(1).split(",")], decls))
    return rules


def _css_decls(css: str, selector: str) -> Dict[str, str]:
    """Every declaration for exactly ``selector``, later rules winning (like the cascade)."""
    merged: Dict[str, str] = {}
    for selectors, decls in _css_rules(css):
        if selector in selectors:
            merged.update(decls)
    return merged


def _css_media_spans(css: str, query: str = r"[^{]*"):
    """(start, body start, end) of every ``@media <query> { ... }`` block."""
    spans = []
    for m in re.finditer(r"@media\s*" + query + r"\s*\{", css):
        depth, i = 1, m.end()
        while depth and i < len(css):
            depth += {"{": 1, "}": -1}.get(css[i], 0)
            i += 1
        spans.append((m.start(), m.end(), i))
    return spans


def _css_media(css: str, query: str) -> str:
    """The bodies of every ``@media <query> { ... }`` block, joined."""
    return "\n".join(css[body:end - 1] for _, body, end in _css_media_spans(css, re.escape(query)))


def _css_base(css: str) -> str:
    """``css`` without its @media blocks: the rules that apply at every window size."""
    for start, _, end in reversed(_css_media_spans(css)):
        css = css[:start] + css[end:]
    return css


def test_small_screen_layout_rules():
    # Static on purpose: the page x viewport matrix (1024x768 down to 800x600 / 853x480) is
    # measured in a browser; this catches a refactor that drops one of the declarations it rests on.
    css = _read("css/tnt.css")
    base = _css_base(css)

    def decl(sel: str) -> Dict[str, str]:
        return _css_decls(base, sel)

    # tables scroll inside their own box, never the page; being positioned, the wrap also clips the
    # absolutely positioned bits inside (the .sr-only header of the DHCP actions column once
    # widened the page to 1167 px at 800 px)
    wrap = decl(".table-wrap")
    assert wrap.get("overflow-x") == "auto" and wrap.get("position") == "relative"
    # a modal is a column capped at the viewport: the title row and the buttons stay put and only
    # the body scrolls, its children never squashed to fit
    modal = decl(".modal")
    assert modal.get("display") == "flex" and modal.get("flex-direction") == "column"
    assert modal.get("max-height") == "calc(100vh - 48px)" and modal.get("overflow") == "hidden"
    assert decl(".modal-backdrop").get("padding") == "24px"   # the 48px above
    body = decl(".modal > .modal-body")
    assert body.get("overflow-y") == "auto" and body.get("min-height") == "0" and body.get("flex") == "1 1 auto"
    assert body.get("position") == "relative"   # the toggles' hidden checkboxes scroll with it (Tab reveals them)
    assert decl(".modal > .modal-body > *").get("flex-shrink") == "0"
    for sel in (".modal-head", ".modal-foot"):
        assert decl(sel).get("flex") == "none", sel
    # toolbars, form rows and chip lines wrap instead of overflowing their card
    for sel in (".form-row", ".section-head", ".section-head .actions", ".row", ".modal-foot", ".tile-line", ".tr-map",
                ".setting", ".dhcp-summary", ".tool-summary", ".lan-self", ".ptile-sub", ".adapter-head", ".peer-meta",
                ".legend", ".chips", ".lan-result"):
        assert decl(sel).get("flex-wrap") == "wrap", sel
    # flex and grid children may shrink below their content width
    for sel in (".page", ".view", ".card", ".tile", ".tile-body", ".field", ".input", ".ptile-head", ".ptile-host",
                ".lm-node", ".lm-chips", ".peer-text", ".modal-body", ".status-pill"):
        assert decl(sel).get("min-width") == "0", sel
    # the tile grid: equal widths in every row for any tile count (test_tile_grid_rules has the bands, the
    # browser layout test the measured widths); a wrapping flex row, no grid spans, no tile across a row
    tiles = decl(".tiles")
    assert tiles.get("display") == "flex" and tiles.get("flex-wrap") == "wrap" and tiles.get("gap") == "var(--tile-gap)"
    assert "grid-column" not in css and "nth-child(odd)" not in css
    assert _css_decls(_css_media(css, "(max-width: 700px)"), ".tiles").get("--tile-gap") == "14px"
    # narrow tiles keep every title on its line: --tile-tight: 1 is a 30 px icon and a 16 px title
    assert decl(".tile-title").get("font-size") == "calc(19px - 3px * var(--tile-tight))"
    assert decl(".tile-icon").get("width") == "calc(34px - 4px * var(--tile-tight))"
    # the sticky header stays one row: the status pill shrinks and ellipsizes, brand/badge/gear do not
    right = decl(".topbar-right")
    assert right.get("flex-wrap") == "nowrap" and right.get("min-width") == "0"
    text = decl(".status-pill .status-text")
    assert text.get("overflow") == "hidden" and text.get("text-overflow") == "ellipsis" and text.get("min-width") == "0"
    for sel in (".brand", ".topbar-right > .live-badge", ".topbar-right > .btn"):
        assert decl(sel).get("flex") == "none", sel
    # ping tiles keep room for the grip and the remove button beside the (ellipsized) name
    assert decl(".ptile-head").get("padding-right") == "74px" and decl(".ptile-host").get("text-overflow") == "ellipsis"
    app = _read("js/app.js")
    assert "pill.title = o.text" in app   # the full status behind the ellipsis
    # a tile click on a short window brings its view up under the header (only a tile click)
    assert "function revealView(view, fromTile)" in app and "if (vh - top >= vh / 3) return;" in app
    assert "tileNav = true" in app and "showView(name, fromTile)" in app
    # canvases redraw to their container width at the device pixel ratio after a resize
    charts = _read("js/charts.js")
    assert "new ResizeObserver(() => this.render())" in charts and "window.devicePixelRatio" in charts


# ---------------------------------------------------------------------------
# mock API server
# ---------------------------------------------------------------------------
def _load_mock():
    spec = importlib.util.spec_from_file_location("tnt_mock_api_under_test", MOCK)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mock():
    mod = _load_mock()
    httpd = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    httpd.daemon_threads = True
    port = httpd.server_address[1]
    mod.STATE = mod.MockState(port)
    th = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.2}, name="mock-httpd", daemon=True)
    th.start()
    try:
        yield SimpleNamespace(mod=mod, state=mod.STATE, port=port)
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=3)


def _req(port: int, method: str, path: str, body: Optional[Dict[str, Any]] = None,
         raw: bool = False) -> Tuple[int, Dict[str, str], Any]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        payload = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        if raw:
            return resp.status, hdrs, payload
        return resp.status, hdrs, (json.loads(payload) if payload else None)
    finally:
        conn.close()


def test_mock_serves_ui_static_files(mock):
    st, h, body = _req(mock.port, "GET", "/", raw=True)
    assert st == 200 and h["content-type"].startswith("text/html")
    assert b"js/app.js" in body
    assert h.get("cache-control") == "no-cache"
    st, h, _ = _req(mock.port, "GET", "/css/tnt.css", raw=True)
    assert st == 200 and h["content-type"].startswith("text/css")
    st, h, _ = _req(mock.port, "GET", "/js/app.js", raw=True)
    assert st == 200 and h["content-type"].startswith("application/javascript")
    st, _, body = _req(mock.port, "GET", "/does-not-exist.js")
    assert st == 404 and body["error"]["code"] == "not_found"
    st, _, _ = _req(mock.port, "GET", "/../tools/mock_api.py")
    assert st == 404


def test_health_and_status_shape(mock):
    st, _, body = _req(mock.port, "GET", "/api/health")
    assert st == 200 and body == {"ok": True}
    st, h, s = _req(mock.port, "GET", "/api/status")
    assert st == 200 and h["content-type"].startswith("application/json")
    for k in ("version", "started_ts", "uptime_s", "mode", "monitoring", "paused", "overall_light",
              "targets", "outages", "speed", "discovery", "netinfo", "settings", "map", "dhcp", "net"):
        assert k in s, k
    # status.net: the network generation the UI compares to tell whether its views must reload
    assert set(s["net"]) == {"generation", "changed_ts", "default_gateway", "internet_nic", "summary", "networks", "network_id"}
    assert isinstance(s["net"]["network_id"], int), "the network this PC is on (tnt.networks): Acme Dental's LAN"
    assert s["net"]["summary"] == "Ethernet: 10.0.0.112/24 · gateway 10.0.0.251"
    assert s["net"]["networks"] == ["10.0.0.0/24", "100.101.22.7/32", "169.254.0.0/16", "172.16.20.0/24", "172.29.64.0/20"]
    assert s["netinfo"]["internet_nic"]["warnings"] == ["multiple_default_gateways"] and s["netinfo"]["local_nic"] is None
    assert isinstance(s["net"]["generation"], int) and s["net"]["default_gateway"] == "10.0.0.251" and s["net"]["internet_nic"] == "Ethernet"
    assert set(s["dhcp"]) == {"available", "running", "adapter", "server_ip", "pool", "bound", "offered", "since_ts", "error"}
    assert s["dhcp"]["running"] is False and s["dhcp"]["adapter"] == "Ethernet"
    assert s["map"]["gateway"]["state"] == "up" and s["map"]["internet"]["host"] == "totalelectronics.com"
    assert len(s["targets"]) == 3
    for t in s["targets"]:
        for k in ("id", "host", "label", "kind", "ip", "enabled", "resolved", "light", "in_outage", "last",
                  "consecutive_missed", "consecutive_ok", "window", "day", "since_ts"):
            assert k in t, k
        assert t["light"] in ("green", "yellow", "red", "grey")
        assert set(t["window"]) >= {"seconds", "sent", "received", "lost", "loss_pct", "avg_ms", "min_ms", "max_ms", "jitter_ms"}
    assert s["overall_light"] in ("green", "yellow", "red", "grey")
    assert s["settings"] == {"theme": "light", "loaded": True}
    assert s["netinfo"]["internet_nic"]["gateway"] == "10.0.0.251"
    assert set(s["speed"]) >= {"enabled", "running", "next_run_ts", "last", "backend", "interval_min", "progress"}
    assert set(s["discovery"]) >= {"running", "progress", "last_run"}


def test_netinfo(mock):
    st, _, n = _req(mock.port, "GET", "/api/netinfo")
    assert st == 200
    assert n["internet_nic_index"] == 12 and n["default_gateway"] == "10.0.0.251"
    assert isinstance(n["generation"], int) and "changed_ts" in n
    assert n["adapters"][0]["index"] == 12  # internet-facing first
    a = n["adapters"][0]
    assert a["subnets"][0]["network"] == "10.0.0.0/24" and a["subnets"][0]["gateways"] == ["10.0.0.251"]
    # every adapter carries warnings; secondary adapters show the codes the Network info page renders
    by_name = {x["name"]: x for x in n["adapters"]}
    codes = {name: [w["code"] for w in x["warnings"]] for name, x in by_name.items()}
    assert codes["Ethernet 2"] == ["apipa"] and by_name["Ethernet 2"]["ipv4"][0]["address"].startswith("169.254.")
    assert codes["Ethernet 3"] == ["gateway_outside_subnet", "no_dns"]
    assert by_name["Ethernet 3"]["subnets"][-1] == {"network": None, "family": 4, "mask": None, "addresses": [], "gateways": ["172.16.21.1"]}
    assert codes["Ethernet"] == ["multiple_default_gateways"] and codes["Wi-Fi"] == [] and codes["Tailscale"] == []
    assert all(set(w) == {"code", "message"} and w["message"] for x in n["adapters"] for w in x["warnings"])


def test_targets_crud_samples_history(mock):
    st, _, t = _req(mock.port, "POST", "/api/targets", {"host": "8.8.8.8", "label": "Google DNS"})
    assert st == 201 and t["host"] == "8.8.8.8" and t["label"] == "Google DNS" and t["kind"] == "internet"
    tid = t["id"]
    st, _, lst = _req(mock.port, "GET", "/api/targets")
    assert st == 200 and any(x["id"] == tid for x in lst)
    # duplicate host returns the existing target
    st, _, again = _req(mock.port, "POST", "/api/targets", {"host": "8.8.8.8"})
    assert st == 201 and again["id"] == tid
    st, _, err = _req(mock.port, "POST", "/api/targets", {"host": ""})
    assert st == 400 and err["error"]["code"] == "bad_request"
    # samples for a seeded target: [[ts, rtt|null], ...] within the window
    st, _, smp = _req(mock.port, "GET", "/api/targets/1/samples?seconds=120")
    assert st == 200 and smp["target_id"] == 1
    assert 100 <= len(smp["samples"]) <= 125
    assert all(len(s) == 2 for s in smp["samples"])
    st, _, hist = _req(mock.port, "GET", "/api/targets/1/history")
    assert st == 200 and "minutes" in hist and set(hist["summary"]) >= {"sent", "received", "lost", "loss_pct", "avg_ms"}
    st, _, _ = _req(mock.port, "GET", "/api/targets/999/samples")
    assert st == 404
    st, _, r = _req(mock.port, "DELETE", f"/api/targets/{tid}")
    assert st == 200 and r == {"removed": True}
    st, _, _ = _req(mock.port, "DELETE", f"/api/targets/{tid}")
    assert st == 404
    st, _, lst = _req(mock.port, "POST", "/api/targets/defaults")
    assert st == 200 and [x["host"] for x in lst] == ["gateway", "1.1.1.1", "totalelectronics.com"]
    # the gateway alias is resolved afresh from the network the PC is on now
    assert lst[0]["ip"] == "10.0.0.251" and lst[0]["resolved"] is True and lst[0]["kind"] == "local"


def test_outages_and_timeline(mock):
    st, _, o = _req(mock.port, "GET", "/api/outages")
    assert st == 200 and isinstance(o["outages"], list) and "status" in o
    assert o["outages"] == sorted(o["outages"], key=lambda x: x["start_ts"], reverse=True)
    for row in o["outages"]:
        assert set(row) >= {"id", "kind", "target_id", "start_ts", "end_ts", "missed", "host", "duration_s", "open",
                            "sent", "missed_pct", "sent_estimated"}
        if row["kind"] == "target":
            assert row["missed_pct"] is not None and 0 < row["missed_pct"] <= 100 and row["sent"] >= row["missed"]
        else:
            assert row["missed_pct"] is None and row["sent"] is None, "only target outages count pings"
    assert any(r["sent_estimated"] for r in o["outages"]) and any(r["kind"] == "target" and not r["sent_estimated"] for r in o["outages"])
    assert set(o["status"]) == {"active", "total_active", "count_24h", "last", "monitoring"}
    st, _, tl = _req(mock.port, "GET", "/api/outages/timeline?hours=24")
    assert st == 200
    assert set(tl) == {"start_ts", "end_ts", "hours", "segments", "total_segments", "gaps", "targets"}
    assert tl["hours"] == 24 and tl["end_ts"] - tl["start_ts"] == pytest.approx(86400, abs=5)
    assert len(tl["total_segments"]) == 1 and tl["total_segments"][0]["kind"] == "total_internet"
    assert len(tl["segments"]) >= 3 and all(s["kind"] == "target" for s in tl["segments"])
    assert len(tl["gaps"]) == 1
    for s in tl["segments"] + tl["total_segments"] + tl["gaps"]:
        assert tl["start_ts"] <= s["start_ts"] <= s["end_ts"] <= tl["end_ts"] + 1
    # narrower window clips
    st, _, tl6 = _req(mock.port, "GET", "/api/outages/timeline?hours=6")
    assert st == 200 and len(tl6["segments"]) + len(tl6["total_segments"]) < len(tl["segments"]) + len(tl["total_segments"])


def test_speedtests_history_patterns_and_run(mock):
    now = time.time()
    st, _, r = _req(mock.port, "GET", f"/api/speedtests?from={now - 86400}&to={now}")
    assert st == 200 and "results" in r and "status" in r
    assert 90 <= len(r["results"]) <= 100  # every 15 min for a day
    assert r["results"] == sorted(r["results"], key=lambda x: x["ts"], reverse=True)
    st, _, r3 = _req(mock.port, "GET", f"/api/speedtests?from={now - 86400}&to={now}&limit=3")
    assert st == 200 and len(r3["results"]) == 3
    st, _, p = _req(mock.port, "GET", "/api/speedtests/patterns?days=7")
    assert st == 200
    assert len(p["by_hour"]) == 24 and len(p["by_weekday"]) == 7
    assert p["median_down"] and p["median_up"] and isinstance(p["findings"], list) and p["findings"]
    evening = [b["avg_down"] for b in p["by_hour"] if 19 <= b["hour"] < 22 and b["avg_down"]]
    assert evening and max(evening) < p["median_down"] * 0.8  # the evening slowdown is visible
    st, _, run = _req(mock.port, "POST", "/api/speedtests/run")
    assert st == 200 and run == {"started": True}
    st, _, conflict = _req(mock.port, "POST", "/api/speedtests/run")
    assert st == 409 and conflict["error"]["code"] == "conflict"
    st, _, s = _req(mock.port, "GET", "/api/status")
    assert s["speed"]["running"] is True and s["speed"]["progress"]["phase"] in ("latency", "download", "upload")


def test_discovery_scan_cancel_and_runs(mock):
    st, _, d = _req(mock.port, "GET", "/api/discovery/status")
    assert st == 200 and d["running"] is False and d["default_range"] == "10.0.0.0/24"
    assert d["default_ports"] == [22, 80, 443, 554, 5060, 7001, 8000, 8080, 8443]
    # the service's keys (engine.discovery_status, pinned in tests/test_api.py), not a subset of them
    assert set(d) == {"available", "running", "progress", "range", "ports", "started_ts", "last_run", "default_range", "default_ports"}
    assert d["started_ts"] is None and set(d["last_run"]) == {"id", "ts", "cidr", "found", "duration_s", "ok", "error"}
    st, _, err = _req(mock.port, "POST", "/api/discovery/scan", {"range": "garbage"})
    assert st == 400
    st, _, r = _req(mock.port, "POST", "/api/discovery/scan", {"range": "10.0.0.0/24", "ports": [22, 80]})
    assert st == 200 and r["started"] is True and r["ports"] == [22, 80]
    st, _, d = _req(mock.port, "GET", "/api/discovery/status")
    assert d["running"] is True and d["progress"]["phase"] in ("ping", "ports", "arp", "resolve")
    st, _, conflict = _req(mock.port, "POST", "/api/discovery/scan", {})
    assert st == 409
    st, _, c = _req(mock.port, "POST", "/api/discovery/cancel")
    assert st == 200 and c == {"cancelled": True}
    deadline = time.time() + 5
    while time.time() < deadline:
        st, _, d = _req(mock.port, "GET", "/api/discovery/status")
        if not d["running"]:
            break
        time.sleep(0.1)
    assert d["running"] is False and d["progress"]["phase"] == "done"
    st, _, last = _req(mock.port, "GET", "/api/discovery/last")
    assert st == 200 and last["error"] == "cancelled" and last["ports"] == [22, 80] and isinstance(last["hosts"], list)
    st, _, runs = _req(mock.port, "GET", "/api/discovery/runs?limit=10")
    assert st == 200 and runs["runs"][0]["id"] == last["id"] and "hosts" not in runs["runs"][0]
    st, _, one = _req(mock.port, "GET", f"/api/discovery/runs/{runs['runs'][-1]['id']}")
    assert st == 200 and one["hosts"] and set(one["hosts"][0]) >= {"ip", "hostname", "mac", "vendor", "ping_ok", "rtt_ms",
                                                                   "open_ports", "device_type"}
    # the auto-categorised types the Discovery table renders as badges
    types = {h["device_type"] for h in one["hosts"] if h.get("device_type")}
    assert types == {"Router", "DW Server", "Camera", "Phone", "Ubiquiti"}
    st, _, _ = _req(mock.port, "GET", "/api/discovery/runs/999")
    assert st == 404


def test_dhcp_status_scan_start_conflict_force_and_stop(mock):
    mock.state.dhcp_fast = True
    st, _, d = _req(mock.port, "GET", "/api/dhcp/status")
    assert st == 200
    for k in ("available", "running", "since_ts", "error", "warning", "adapter", "adapters", "server_ip", "pool", "lease_s",
              "gateway", "dns", "ping_check", "clients", "counts", "scan", "firewall", "settings"):
        assert k in d, k
    assert d["running"] is False and d["available"] is True and d["dns"] == []
    a = d["adapter"]
    assert a["name"] == "Ethernet" and a["dhcp_enabled"] is True and a["will_change"] is True and a["changed"] is False
    assert a["static_ip"] == "172.16.4.100" and a["static_prefix"] == 24
    assert d["server_ip"] == "172.16.4.100" and d["gateway"] == "172.16.4.100"
    assert d["pool"] == {"start": "172.16.4.101", "end": "172.16.4.105", "size": 5, "auto": True}
    assert d["lease_s"] == 3600 and d["counts"] == {"bound": 0, "offered": 0, "total": 0}
    assert [x["name"] for x in d["adapters"]] == ["Ethernet", "vEthernet (Default Switch)", "Tailscale"]
    # F12: the auto-picked Ethernet is the PC's internet connection, so the UI's loud warning can be seen in the mock
    assert a["is_internet"] is True
    assert [x["is_internet"] for x in d["adapters"]] == [True, False, False]
    assert d["firewall"]["rule"] == "TNT DHCP server (UDP 67 in)"
    assert set(d["settings"]) == {"adapter", "pool_start", "pool_end", "pool_size", "lease_s", "static_ip", "static_prefix", "ping_check", "scan_wait_s"}
    # a scan finds the LAN's real server
    st, _, sc = _req(mock.port, "POST", "/api/dhcp/scan", {"wait_s": 1})
    assert st == 200 and set(sc) == {"ts", "duration_s", "wait_s", "servers", "probed", "errors"}
    assert sc["wait_s"] == 1 and len(sc["servers"]) == 1
    srv = sc["servers"][0]
    assert set(srv) == {"adapter", "nic_ip", "server_ip", "source_ip", "offered_ip", "lease_s", "router", "mask", "dns", "known", "answered"}
    assert srv["server_ip"] == "10.0.0.251" and srv["answered"] is True and {"adapter": "Ethernet", "ip": "10.0.0.112"} in sc["probed"]
    # start without force -> 409 with the servers in the body (the UI's danger modal needs them)
    q = mock.state.hub.subscribe()
    try:
        st, _, err = _req(mock.port, "POST", "/api/dhcp/start", {})
        assert st == 409 and err["error"]["code"] == "dhcp_server_present"
        assert err["servers"][0]["server_ip"] == "10.0.0.251" and "scan" in err
        st, _, d = _req(mock.port, "GET", "/api/dhcp/status")
        assert d["running"] is False and d["scan"]["servers"]
        # force -> running; the adapter is "re-addressed"; clients then appear with dhcp.lease events
        st, _, d = _req(mock.port, "POST", "/api/dhcp/start", {"force": True})
        assert st == 200 and d["running"] is True and d["since_ts"] and d["adapter"]["changed"] is True
        assert d["adapter"]["will_change"] is False and d["adapter"]["ip"] == "172.16.4.100"
        # other fakes (a speed test from an earlier test) keep publishing too: keep the dhcp.* frames only
        kinds = []
        deadline = time.time() + 8
        while time.time() < deadline and kinds.count("dhcp.lease") < 9:
            try:
                frame = q.get(timeout=1)
            except Exception:  # noqa: BLE001 - queue.Empty
                continue
            kind = frame.split("\n")[0][7:]
            if kind.startswith("dhcp."):
                kinds.append(kind)
                if kind == "dhcp.lease":
                    lease = json.loads(frame.split("\n")[1][6:])["lease"]
                    assert lease["state"] in ("offered", "bound") and lease["mac"]
        assert kinds.count("dhcp.scan") >= 1 and "dhcp.state" in kinds and kinds.count("dhcp.lease") >= 9, kinds
        st, _, ls = _req(mock.port, "GET", "/api/dhcp/leases")
        assert st == 200 and len(ls["leases"]) == 3
        lease = ls["leases"][0]
        for k in ("ip", "mac", "hostname", "vendor", "ping_ok", "rtt_ms", "open_ports", "client_id", "state", "first_ts", "last_ts",
                  "expires_ts", "probed_ts", "probing"):
            assert k in lease, k
        assert lease["state"] == "bound" and lease["ip"] == "172.16.4.101" and lease["open_ports"] == [80, 554] and lease["ping_ok"] is True
        st, _, s = _req(mock.port, "GET", "/api/status")
        assert s["dhcp"]["running"] is True and s["dhcp"]["bound"] == 3 and s["dhcp"]["pool"]["start"] == "172.16.4.101"
        st, _, d = _req(mock.port, "GET", "/api/dhcp/status")
        assert d["counts"] == {"bound": 3, "offered": 0, "total": 3}
        # start again is idempotent
        st, _, d = _req(mock.port, "POST", "/api/dhcp/start", {})
        assert st == 200 and d["running"] is True
    finally:
        mock.state.hub.unsubscribe(q)
    # settings: validated against the adapter's subnet
    st, _, err = _req(mock.port, "PUT", "/api/dhcp/settings", {"pool_start": "10.0.0.50", "pool_end": "10.0.0.60"})
    assert st == 400 and err["error"]["code"] == "bad_request"
    st, _, err = _req(mock.port, "PUT", "/api/dhcp/settings", {"pool_start": "172.16.4.90", "pool_end": "172.16.4.110"})
    assert st == 400  # contains the server address
    st, _, err = _req(mock.port, "PUT", "/api/dhcp/settings", {"lease_s": 10})
    assert st == 400
    st, _, err = _req(mock.port, "PUT", "/api/dhcp/settings", {"adapter": "Tailscale"})
    assert st == 400  # a /32 cannot hold a pool
    st, _, d = _req(mock.port, "PUT", "/api/dhcp/settings", {"pool_start": "172.16.4.150", "pool_end": "172.16.4.160", "lease_s": 600})
    assert st == 200 and d["pool"] == {"start": "172.16.4.150", "end": "172.16.4.160", "size": 11, "auto": False} and d["lease_s"] == 600
    st, _, d = _req(mock.port, "PUT", "/api/dhcp/settings", {"pool_start": "", "pool_end": ""})
    assert st == 200 and d["pool"]["auto"] is True
    # forget a lease
    st, _, r = _req(mock.port, "DELETE", "/api/dhcp/leases/AA:BB:CC:10:20:01")
    assert st == 200 and r == {"ok": True}
    st, _, _ = _req(mock.port, "DELETE", "/api/dhcp/leases/AA:BB:CC:10:20:01")
    assert st == 404
    st, _, ls = _req(mock.port, "GET", "/api/dhcp/leases")
    assert len(ls["leases"]) == 2
    # stop restores the adapter and is idempotent
    st, _, d = _req(mock.port, "POST", "/api/dhcp/stop")
    assert st == 200 and d["running"] is False and d["adapter"]["changed"] is False and d["adapter"]["will_change"] is True
    st, _, d = _req(mock.port, "POST", "/api/dhcp/stop")
    assert st == 200 and d["running"] is False
    # with no other server around, a plain start succeeds
    mock.state.dhcp_force_none = True
    try:
        st, _, sc = _req(mock.port, "POST", "/api/dhcp/scan", {})
        assert st == 200 and sc["servers"] == [] and sc["errors"] == []
        st, _, d = _req(mock.port, "POST", "/api/dhcp/start", {})
        assert st == 200 and d["running"] is True
    finally:
        mock.state.dhcp_force_none = False
        _req(mock.port, "POST", "/api/dhcp/stop")


def test_mock_consumes_unread_request_bodies_on_keepalive(mock):
    """A POST whose route never reads its body (the UI sends ``{}`` to /api/dhcp/stop) must not leave
    the bytes on the keep-alive connection, where they would be parsed as the start of the next
    request line (``{}GET /api/health`` -> 501 Unsupported method)."""
    conn = http.client.HTTPConnection("127.0.0.1", mock.port, timeout=10)
    try:
        conn.request("POST", "/api/dhcp/stop", body=b"{}", headers={"Content-Type": "application/json"})
        r1 = conn.getresponse()
        b1 = json.loads(r1.read())
        assert r1.status == 200 and b1["running"] is False and r1.getheader("Connection", "").lower() != "close"
        conn.request("GET", "/api/health")   # same socket: http.client reuses a keep-alive connection
        r2 = conn.getresponse()
        assert r2.status == 200 and json.loads(r2.read()) == {"ok": True}
        # a bigger unread body on a DELETE, then a PUT that does read its body, then a GET: all on one socket
        conn.request("DELETE", "/api/dhcp/leases/00:00:00:00:00:00", body=json.dumps({"why": "x" * 2000}).encode(),
                     headers={"Content-Type": "application/json"})
        r3 = conn.getresponse()
        assert r3.status == 404 and json.loads(r3.read())["error"]["code"] == "not_found"
        conn.request("PUT", "/api/dhcp/settings", body=b'{"lease_s": 3600}', headers={"Content-Type": "application/json"})
        r4 = conn.getresponse()
        assert r4.status == 200 and json.loads(r4.read())["lease_s"] == 3600
        conn.request("GET", "/api/health")
        r5 = conn.getresponse()
        assert r5.status == 200 and json.loads(r5.read()) == {"ok": True}
        # an invalid JSON body is still a 400 (parsed lazily, only by routes that read it) and does not poison the socket
        conn.request("PUT", "/api/dhcp/settings", body=b"{not json", headers={"Content-Type": "application/json"})
        r6 = conn.getresponse()
        assert r6.status == 400 and json.loads(r6.read())["error"]["code"] == "bad_request"
        conn.request("POST", "/api/dhcp/stop", body=b"{not json", headers={"Content-Type": "application/json"})
        r7 = conn.getresponse()
        assert r7.status == 200 and json.loads(r7.read())["running"] is False
        conn.request("GET", "/api/health")
        r8 = conn.getresponse()
        assert r8.status == 200 and json.loads(r8.read()) == {"ok": True}
    finally:
        conn.close()


def test_settings_persist_in_memory_and_are_validated(mock):
    st, _, s = _req(mock.port, "GET", "/api/settings")
    assert st == 200 and s["ui"]["theme"] == "light" and s["ping"]["loaded"] is True
    st, _, r = _req(mock.port, "PUT", "/api/settings", {"ui": {"theme": "dark"}, "speedtest": {"interval_min": 5000}, "ping": {"loaded": False}})
    assert st == 200 and set(r) == {"settings", "changed"}
    assert {"ui.theme", "speedtest.interval_min", "ping.loaded"} <= set(r["changed"])
    assert r["settings"]["speedtest"]["interval_min"] == 1440  # clamped
    st, _, s = _req(mock.port, "GET", "/api/settings")
    assert s["ui"]["theme"] == "dark" and s["ping"]["loaded"] is False
    st, _, status = _req(mock.port, "GET", "/api/status")
    assert status["settings"] == {"theme": "dark", "loaded": False}
    st, _, r = _req(mock.port, "PUT", "/api/settings", {"ui": {"theme": "blue"}, "speedtest": {"interval_min": 15}})
    assert st == 200 and r["settings"]["ui"]["theme"] == "light"
    st, _, r = _req(mock.port, "PUT", "/api/settings", {"ping": {"loaded": True}})
    assert st == 200


def test_settings_retired_keys_are_dropped_like_the_service(mock):
    """tnt.config drops the settings 1.7.0 removed (tests/test_api.py checks the service); the mock
    does the same, so a UI that still sent them would not look like it stored them."""
    removed = {"speedtest": {"ookla_path": "C:/Program Files/TNT/bin/speedtest.exe", "ookla_server_id": 1234},
               "discovery": {"use_nmap": "always", "nmap_path": "C:/Program Files (x86)/Nmap"}}
    assert {f"{section}.{key}" for section, keys in removed.items() for key in keys} == set(mock.mod.RETIRED_SETTINGS)
    st, _, r = _req(mock.port, "PUT", "/api/settings", removed)
    assert st == 200 and r["changed"] == []
    st, _, r = _req(mock.port, "PUT", "/api/settings", {"speedtest": {**removed["speedtest"], "backend": "ookla", "interval_min": 30}})
    assert st == 200 and r["changed"] == ["speedtest.interval_min"] and r["settings"]["speedtest"]["backend"] == "auto"
    st, _, s = _req(mock.port, "GET", "/api/settings")
    for section, keys in removed.items():
        assert not set(keys) & set(s[section])
    _req(mock.port, "PUT", "/api/settings", {"speedtest": {"interval_min": 15}})


def test_settings_show_ipv6_round_trip_and_public_ip(mock):
    st, _, s = _req(mock.port, "GET", "/api/settings")
    assert st == 200 and s["ui"]["show_ipv6"] is False and s["lan"] == {"enabled": True}
    st, _, r = _req(mock.port, "PUT", "/api/settings", {"ui": {"show_ipv6": True}})
    assert st == 200 and r["settings"]["ui"]["show_ipv6"] is True and "ui.show_ipv6" in r["changed"]
    assert r["settings"]["ui"]["theme"] in ("light", "dark")  # the rest of ui is untouched by the patch
    st, _, s = _req(mock.port, "GET", "/api/settings")
    assert s["ui"]["show_ipv6"] is True
    st, _, r = _req(mock.port, "PUT", "/api/settings", {"ui": {"show_ipv6": 0}})
    assert st == 200 and r["settings"]["ui"]["show_ipv6"] is False
    # the link map carries the router's public address
    st, _, status = _req(mock.port, "GET", "/api/status")
    pub = status["map"]["public_ip"]
    assert set(pub) == {"ip", "ts", "error", "checked_ts"} and pub["ip"] == "203.0.113.5" and pub["error"] is None
    assert pub["checked_ts"] == pub["ts"]
    assert isinstance(pub["ts"], float) and time.time() - 700 < pub["ts"] <= time.time()


def _drain(q, prefix: str, stop: str, deadline_s: float = 6.0):
    """Frames of one family (``trace.`` / ``lan.``) from a hub queue until ``stop`` arrives: [(type, data)]."""
    got = []
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            frame = q.get(timeout=1)
        except Exception:  # noqa: BLE001 - queue.Empty
            continue
        kind = frame.split("\n")[0][7:]
        if not kind.startswith(prefix):
            continue
        got.append((kind, json.loads(frame.split("\n")[1][6:])))
        if kind == stop:
            break
    return got


def test_traceroute_start_hops_done_and_last(mock):
    mock.state.trace_fast = True
    st, _, last = _req(mock.port, "GET", "/api/tools/traceroute/last")
    assert st == 200 and last == {"trace": None, "running": False}
    st, _, err = _req(mock.port, "POST", "/api/tools/traceroute", {"host": ""})
    assert st == 400 and err["error"]["code"] == "bad_request"
    st, _, err = _req(mock.port, "POST", "/api/tools/traceroute", {"host": "nonexistent.invalid"})
    assert st == 400 and "resolve" in err["error"]["message"]
    q = mock.state.hub.subscribe()
    try:
        st, _, tr = _req(mock.port, "POST", "/api/tools/traceroute", {"host": "totalelectronics.com", "max_hops": 30, "probes": 3, "timeout_ms": 1500})
        assert st == 200
        assert set(tr) == {"host", "target_ip", "ts", "duration_s", "max_hops", "probes", "timeout_ms", "complete", "error", "pc", "gateway", "hops"}
        assert tr["host"] == "totalelectronics.com" and tr["target_ip"] == "203.0.113.80" and tr["complete"] is True and tr["error"] is None
        assert tr["max_hops"] == 30 and tr["probes"] == 3 and tr["timeout_ms"] == 1500 and tr["duration_s"] >= 0
        assert tr["pc"] == {"ip": "10.0.0.112", "hostname": "TEC-DESKTOP"} and tr["gateway"] == "10.0.0.251"
        hops = tr["hops"]
        assert len(hops) == 9 and [h["ttl"] for h in hops] == list(range(1, 10))
        for h in hops:
            assert set(h) == {"ttl", "ip", "alt_ips", "hostname", "rtts", "avg_ms", "min_ms", "max_ms", "loss", "responder_status", "kind", "label", "location"}
            assert len(h["rtts"]) == 3 and h["kind"] in ("gateway", "lan", "public", "destination", "unknown") and h["alt_ips"] == []
            assert h["loss"] == h["rtts"].count(None)
            if h["ip"]:
                assert h["min_ms"] <= h["avg_ms"] <= h["max_ms"]
        assert hops[0]["kind"] == "gateway" and hops[0]["ip"] == "10.0.0.251" and hops[0]["label"] == "Gateway" and hops[0]["hostname"] == "gateway.lan"
        assert hops[1]["ip"] == "100.64.0.1" and hops[1]["kind"] == "lan" and hops[1]["label"] == "LAN"
        silent = hops[4]
        assert silent["ip"] is None and silent["rtts"] == [None, None, None] and silent["loss"] == 3 and silent["avg_ms"] is None
        assert silent["kind"] == "unknown" and silent["label"] == "No reply" and silent["responder_status"] is None
        assert hops[7]["loss"] == 1 and hops[7]["avg_ms"] > 100  # one lost probe, a red round trip
        assert hops[-1]["kind"] == "destination" and hops[-1]["ip"] == "203.0.113.80" and hops[-1]["hostname"] == "totalelectronics.com" and hops[-1]["label"] == "Destination"
        # IP location (tnt.geoip.GeoIpManager.locate_hop): none for the gateway, the CGNAT hop and the silent one; the
        # router name "dllstx" wins over the database's city; the destination's city comes from the database
        assert hops[0]["location"] is None and hops[1]["location"] is None and hops[4]["location"] is None
        assert hops[5]["ttl"] == 6 and hops[5]["location"] == {"text": "Dallas, TX", "source": "hostname", "hint": "dllstx",
                                                               "db_text": "Richardson, TX", "asn": 64510, "as_org": "Example Transit, Inc."}
        assert hops[-1]["location"]["source"] == "database"
        # the events: start, one hop per hop (in ttl order), done
        got = _drain(q, "trace.", "trace.done")
        kinds = [k for k, _ in got]
        assert kinds[0] == "trace.start" and kinds[-1] == "trace.done" and kinds.count("trace.hop") == 9, kinds
        assert got[0][1] == {"host": "totalelectronics.com", "target_ip": "203.0.113.80", "max_hops": 30, "probes": 3}
        assert [d["hop"]["ttl"] for k, d in got if k == "trace.hop"] == list(range(1, 10))
        # the mock's live hops already carry the final location (the service's may still lack the router-name hint)
        assert [d["hop"]["location"] for k, d in got if k == "trace.hop"] == [h["location"] for h in hops]
        assert got[-1][1] == {"host": "totalelectronics.com", "target_ip": "203.0.113.80", "hops": 9, "complete": True, "duration_s": tr["duration_s"]}
    finally:
        mock.state.hub.unsubscribe(q)
    st, _, last = _req(mock.port, "GET", "/api/tools/traceroute/last")
    assert st == 200 and last["running"] is False and last["trace"] == tr
    # the hop limit cuts the path short: incomplete with an error text
    st, _, tr4 = _req(mock.port, "POST", "/api/tools/traceroute", {"host": "totalelectronics.com", "max_hops": 4, "resolve_names": False})
    assert st == 200 and tr4["complete"] is False and len(tr4["hops"]) == 4 and tr4["error"] and all(h["hostname"] is None for h in tr4["hops"])
    # without names there is no router name to read: the database's city
    st, _, trn = _req(mock.port, "POST", "/api/tools/traceroute", {"host": "totalelectronics.com", "resolve_names": False})
    assert st == 200 and trn["hops"][5]["ttl"] == 6
    assert trn["hops"][5]["location"] == {"text": "Richardson, TX", "source": "database", "hint": None, "db_text": "Richardson, TX",
                                          "asn": 64510, "as_org": "Example Transit, Inc."}
    # a LAN address is one hop straight to the destination
    st, _, tr1 = _req(mock.port, "POST", "/api/tools/traceroute", {"host": "10.0.0.251"})
    assert st == 200 and len(tr1["hops"]) == 1 and tr1["hops"][0]["kind"] == "destination" and tr1["target_ip"] == "10.0.0.251" and tr1["complete"] is True
    assert tr1["hops"][0]["location"] is None
    # 409 while one runs
    mock.state.trace_running = True
    try:
        st, _, err = _req(mock.port, "POST", "/api/tools/traceroute", {"host": "1.1.1.1"})
        assert st == 409 and err["error"]["code"] == "conflict"
        st, _, last = _req(mock.port, "GET", "/api/tools/traceroute/last")
        assert last["running"] is True
    finally:
        mock.state.trace_running = False


#: tnt.geoip.GeoIpManager.status() switched off
GEOIP_DISABLED = {"enabled": False, "state": "disabled", "available": False, "month": None, "bytes": None, "installed_ts": None,
                  "checked_ts": None, "next_check_ts": None, "download": None, "error": None}
GEOIP_BAD_IP = {"code": "bad_request", "message": "ip must be an IPv4 or IPv6 address"}


def test_mock_geoip_status_lookup_settings_and_events(mock):
    """IP location in the mock, in tnt.geoip's shapes: status.geoip and map.public_geo, GET /api/geoip and its lookup,
    the setting and its geoip.state event, Retry now, and the development-only POST /mock/geoip."""
    mod = mock.mod
    mock.state.trace_fast = True
    st, _, s = _req(mock.port, "GET", "/api/status")
    g = s["geoip"]
    assert st == 200 and set(g) == set(mod.GEOIP_STATUS_KEYS) and g["state"] == "ready"
    assert g["enabled"] is True and g["available"] is True and g["month"] == mock.state.geoip_month and g["bytes"] == 136850953
    assert g["download"] is None and g["error"] is None and g["installed_ts"] < g["checked_ts"] < time.time() < g["next_check_ts"]
    geo = s["map"]["public_geo"]
    assert set(geo) == set(mod.GEOIP_GEO_KEYS) and geo["place"] == "Anytown, TX" and geo["ip"] == s["map"]["public_ip"]["ip"]
    assert geo["isp"] == "Example Broadband" and geo["asn"] == 64500 and geo["month"] == g["month"]
    st, _, g2 = _req(mock.port, "GET", "/api/geoip")
    assert st == 200 and g2 == g
    st, _, r = _req(mock.port, "GET", "/api/geoip/lookup?ip=203.0.113.5")
    assert st == 200 and r == {"ip": "203.0.113.5", "result": geo}
    # the address is read like the service reads it: brackets and a scope go, an IPv4-mapped address is the IPv4 one
    st, _, r = _req(mock.port, "GET", "/api/geoip/lookup?ip=%5B%3A%3Affff%3A203.0.113.5%5D")
    assert st == 200 and r["result"] == geo
    st, _, r = _req(mock.port, "GET", "/api/geoip/lookup?ip=10.0.0.1")
    assert st == 200 and r == {"ip": "10.0.0.1", "result": None}          # a LAN address is never looked up
    st, _, r = _req(mock.port, "GET", "/api/geoip/lookup?ip=2001:db8::1")
    assert st == 200 and r == {"ip": "2001:db8::1", "result": None}       # nothing is known about it
    for query in ("?ip=bad", "?ip=", "", "?ip=203.0.113.5.1", "?ip=" + "1" * 65):
        st, _, err = _req(mock.port, "GET", "/api/geoip/lookup" + query)
        assert st == 400 and err["error"] == GEOIP_BAD_IP, query
    # switched off: the disabled shape at once, with its event, and nothing is looked up
    q = mock.state.hub.subscribe()
    try:
        st, _, r = _req(mock.port, "PUT", "/api/settings", {"geoip": {"enabled": False}})
        assert st == 200 and "geoip.enabled" in r["changed"] and r["settings"]["geoip"] == {"enabled": False}
        got = _drain(q, "geoip.", "geoip.state", 3)
        assert got and got[-1][0] == "geoip.state"
        data = got[-1][1]
        assert set(data) - {"ts"} == set(mod.GEOIP_STATUS_KEYS) and data["enabled"] is False and data == GEOIP_DISABLED
        st, _, s = _req(mock.port, "GET", "/api/status")
        assert s["geoip"] == GEOIP_DISABLED and s["map"]["public_geo"] is None and s["map"]["public_ip"]["ip"] == "203.0.113.5"
        st, _, g = _req(mock.port, "GET", "/api/geoip")
        assert st == 200 and g == GEOIP_DISABLED
        st, _, r = _req(mock.port, "GET", "/api/geoip/lookup?ip=203.0.113.5")
        assert st == 200 and r == {"ip": "203.0.113.5", "result": None}
        st, _, tr = _req(mock.port, "POST", "/api/tools/traceroute", {"host": "totalelectronics.com"})
        assert st == 200 and len(tr["hops"]) == 9 and all(h["location"] is None for h in tr["hops"])
        st, _, err = _req(mock.port, "POST", "/api/geoip/check")
        assert st == 409 and err["error"] == {"code": "conflict", "message": "IP location is switched off"}
        st, _, d = _req(mock.port, "GET", "/api/diagnostics")
        assert d["geoip"] == {"available": True, "status": GEOIP_DISABLED, "files": []}
        st, _, cfg = _req(mock.port, "GET", "/api/settings")
        assert cfg["geoip"] == {"enabled": False}
        # the same value again changes nothing and says nothing
        st, _, r = _req(mock.port, "PUT", "/api/settings", {"geoip": {"enabled": False}})
        assert st == 200 and r["changed"] == []
        assert _drain(q, "geoip.", "geoip.state", 0.5) == []
    finally:
        mock.state.hub.unsubscribe(q)
        mock.state.update_settings({"geoip": {"enabled": True}})
    st, _, s = _req(mock.port, "GET", "/api/status")
    assert s["geoip"]["state"] == "ready" and s["map"]["public_geo"]["place"] == "Anytown, TX"
    # a failed download: Retry now starts over with an event; the development route shows the other states
    q = mock.state.hub.subscribe()
    try:
        st, _, r = _req(mock.port, "POST", "/mock/geoip", {"state": "error"})
        assert st == 200 and r == {"state": "error"}
        got = _drain(q, "geoip.", "geoip.state", 3)
        assert got and got[-1][1]["state"] == "error"
        st, _, s = _req(mock.port, "GET", "/api/status")
        g = s["geoip"]
        assert g["state"] == "error" and g["available"] is False and g["error"] == "HTTP 503 from download.db-ip.com"
        assert g["month"] is None and g["download"] is None and g["next_check_ts"] > time.time() and s["map"]["public_geo"] is None
        st, _, g = _req(mock.port, "POST", "/api/geoip/check")
        assert st == 200 and set(g) == set(mod.GEOIP_STATUS_KEYS) and g["state"] == "starting" and g["enabled"] is True
        assert g["available"] is False and g["error"] is None and g["next_check_ts"] is not None
        got = _drain(q, "geoip.", "geoip.state", 3)
        assert got and got[-1] == ("geoip.state", g)
        st, _, g2 = _req(mock.port, "POST", "/api/geoip/check")          # nothing failed: just the status
        assert st == 200 and g2 == g and _drain(q, "geoip.", "geoip.state", 0.5) == []
        st, _, r = _req(mock.port, "POST", "/mock/geoip", {"state": "downloading"})
        assert st == 200 and r == {"state": "downloading"}
        st, _, s = _req(mock.port, "GET", "/api/status")
        assert s["geoip"]["state"] == "downloading" and s["geoip"]["available"] is False and s["map"]["public_geo"] is None
        dl = s["geoip"]["download"]
        assert set(dl) == set(mod.GEOIP_DOWNLOAD_KEYS)
        assert dl == {"month": mock.state.geoip_month, "file": "city", "phase": "download", "received": 25000000, "total": 60287600}
        st, _, cur = _req(mock.port, "GET", "/mock/geoip")
        assert st == 200 and cur == {"state": "downloading", "states": ["disabled", "starting", "downloading", "ready", "error"]}
        for bad in ("disabled", "mars", ""):
            st, _, err = _req(mock.port, "POST", "/mock/geoip", {"state": bad})
            assert st == 400 and err["error"]["code"] == "bad_request", bad
        assert mock.state.geoip_state == "downloading"
    finally:
        mock.state.hub.unsubscribe(q)
        mock.state.geoip_state = "ready"
    st, _, s = _req(mock.port, "GET", "/api/status")
    assert s["geoip"]["state"] == "ready" and s["geoip"]["available"] is True


def test_mock_ip_location_follows_the_service(mock):
    """The mock's IP location is only worth testing the UI against if it says what the service says: tnt.geoip's key sets,
    states and skipped networks, the setting's default, tnt.geohints' reading of the fake route's router names, and the
    place, full place and ISP display name tnt.geoip builds from the same database records."""
    from tnt import config, geohints, geoip
    from tnt import traceroute as service_traceroute

    mod = mock.mod
    assert mod.GEOIP_STATUS_KEYS == geoip.STATUS_KEYS and mod.GEOIP_GEO_KEYS == geoip.GEO_KEYS
    assert mod.GEOIP_LOCATION_KEYS == geoip.LOCATION_KEYS and mod.GEOIP_DOWNLOAD_KEYS == geoip.DOWNLOAD_KEYS
    assert mod.GEOIP_DIAG_KEYS == geoip.DIAG_KEYS and mod.GEOIP_STATES == geoip.STATES
    assert list(mod.GEOIP_SKIP_NETWORKS) == [str(n) for n in geoip.SKIP_NETWORKS]
    # every network the tracer calls LAN is one the manager never looks up, so the two service filters cannot drift apart
    for net in service_traceroute._LAN_V4 + service_traceroute._LAN_V6:
        assert any(net.version == skip.version and net.subnet_of(skip) for skip in geoip.SKIP_NETWORKS), net
    assert mod.DEFAULTS["geoip"] == config.DEFAULTS["geoip"]
    # router names: the fake route's hint is the one tnt.geohints reads, and no other name there gives one
    origin = (mod.MOCK_GEO[mod.PUBLIC_IP]["lat"], mod.MOCK_GEO[mod.PUBLIC_IP]["lon"])
    named = set()
    for ip, name, kind, _label, base, _lost in mod.TRACE_PATH:
        if not name or not ip or kind == "destination" or not geoip.is_public_candidate(ip):
            continue
        named.add(name)
        hint = geohints.location_hint(name, ip)
        if name in mod.MOCK_HOST_HINTS:
            code, text = mod.MOCK_HOST_HINTS[name]
            assert hint is not None and geohints.hint_text(hint) == text and hint["code"] == code, (name, hint)
            # ... and the service's speed-of-light guard would keep it on this route
            assert geohints.plausible(hint, origin, base * 0.8), (name, hint)
        else:
            assert hint is None, (name, hint)
    assert set(mod.MOCK_HOST_HINTS) <= named
    fresh = mod.MockState(0)
    for ip, geo in mod.MOCK_GEO.items():
        city = {"city": {"names": {"en": geo["city"]}}, "subdivisions": [{"names": {"en": geo["region"]}}],
                "country": {"iso_code": geo["country_code"], "names": {"en": geo["country"]}},
                "location": {"latitude": geo["lat"], "longitude": geo["lon"]}}
        parts = geoip.place_parts(city)
        assert geo["place"] == geoip.place_text(parts) and geo["place_full"] == geoip.place_full_text(parts), ip
        assert geoip.isp_text(geo["asn"], geo["as_org"]) == geo["isp"], ip
        # the whole GEO the mock answers is the one the service builds from those records
        asn = {"autonomous_system_number": geo["asn"], "autonomous_system_organization": geo["as_org"]}
        assert fresh.geoip_lookup(ip) == geoip.build_geo(ip, city, asn, fresh.geoip_month), ip


#: every key tnt.lanpeers.LanPeers.peers_view() carries (the mock must mirror it exactly)
LAN_VIEW_KEYS = {"self", "peers", "listening", "error", "enabled", "running", "throughput_running",
                 "beacon_port", "throughput_port", "firewall"}


def test_lan_peers_and_throughput(mock):
    mock.state.lan_fast = True
    st, _, p = _req(mock.port, "GET", "/api/tools/lan/peers")
    assert st == 200 and set(p) == LAN_VIEW_KEYS
    assert set(p["self"]) == {"id", "hostname", "ip", "version", "port"} and p["self"]["hostname"] == "TEC-DESKTOP" and p["self"]["ip"] == "10.0.0.112"
    assert p["listening"] is True and p["error"] is None and p["enabled"] is True and p["running"] is True
    assert p["throughput_running"] is False and set(p["firewall"]) == {"ok", "error"}
    assert p["throughput_port"] == p["self"]["port"] and p["beacon_port"] != p["throughput_port"]
    assert [x["hostname"] for x in p["peers"]] == ["TEC-LAPTOP-02", "BENCH-PC"] and [x["ip"] for x in p["peers"]] == ["10.0.0.42", "10.0.0.77"]
    for x in p["peers"]:
        assert set(x) == {"id", "hostname", "ip", "version", "last_seen_ts", "age_s", "adapter"}
        assert 0 <= x["age_s"] < 120 and x["adapter"] == "Ethernet" and x["version"]
    st, _, last = _req(mock.port, "GET", "/api/tools/lan/throughput/last")
    assert st == 200 and last == {"result": None, "running": False}
    st, _, err = _req(mock.port, "POST", "/api/tools/lan/throughput", {"peer": "10.0.0.99"})
    assert st == 400 and err["error"]["code"] == "bad_request"
    q = mock.state.hub.subscribe()
    try:
        st, _, r = _req(mock.port, "POST", "/api/tools/lan/throughput", {"peer": "10.0.0.42", "seconds": 3})
        assert st == 200 and set(r) == {"ts", "peer", "seconds", "upload_mbps", "download_mbps", "latency_ms", "duration_s", "error"}
        assert r["peer"] == {"ip": "10.0.0.42", "hostname": "TEC-LAPTOP-02"} and r["seconds"] == 3 and r["error"] is None
        assert 850 < r["upload_mbps"] < 1030 and 820 < r["download_mbps"] < 1000 and 0 < r["latency_ms"] < 5 and r["duration_s"] >= 0
        got = _drain(q, "lan.throughput", "lan.throughput.done")
        prog = [d for k, d in got if k == "lan.throughput.progress"]
        assert prog and all(set(d) == {"phase", "pct", "mbps"} for d in prog)
        phases = []
        for d in prog:
            if not phases or phases[-1] != d["phase"]:
                phases.append(d["phase"])
        assert phases == ["connect", "upload", "download"]
        assert all(0 <= d["pct"] <= 100 for d in prog) and prog[-1]["pct"] == 100 and max(d["mbps"] for d in prog) > 800
        assert got[-1] == ("lan.throughput.done", {"result": r})
    finally:
        mock.state.hub.unsubscribe(q)
    st, _, last = _req(mock.port, "GET", "/api/tools/lan/throughput/last")
    assert st == 200 and last == {"result": r, "running": False}
    st, _, r2 = _req(mock.port, "POST", "/api/tools/lan/throughput", {"peer": "10.0.0.77", "seconds": 99})
    assert st == 200 and r2["seconds"] == 20 and r2["peer"]["hostname"] == "BENCH-PC"  # clamped to 2-20
    mock.state.lan_running = True
    try:
        st, _, err = _req(mock.port, "POST", "/api/tools/lan/throughput", {"peer": "10.0.0.42"})
        assert st == 409 and err["error"]["code"] == "conflict"
    finally:
        mock.state.lan_running = False
    # every 10 s the peers announce again: a lan.peers broadcast with the list
    q = mock.state.hub.subscribe()
    try:
        mock.state.lan_peer_ts = 0
        mock.state.lan_tick(time.time())
        got = _drain(q, "lan.peers", "lan.peers", 3)
        assert got and set(got[0][1]) == {"peers"} and [x["ip"] for x in got[0][1]["peers"]] == ["10.0.0.42", "10.0.0.77"]
        assert all(x["age_s"] < 10 for x in got[0][1]["peers"])
    finally:
        mock.state.hub.unsubscribe(q)


def test_lan_settings_switch(mock):
    """PUT /api/tools/lan/settings turns discovery off and on again (mirrors the real route)."""
    mock.state.lan_fast = True
    q = mock.state.hub.subscribe()
    try:
        st, _, off = _req(mock.port, "PUT", "/api/tools/lan/settings", {"enabled": False})
        assert st == 200 and set(off) == LAN_VIEW_KEYS
        assert off["enabled"] is False and off["listening"] is False and off["running"] is False
        assert off["error"] == "disabled" and off["peers"] == []
        # the whole view goes out as lan.state so a second window follows the switch
        got = _drain(q, "lan.state", "lan.state", 3)
        assert got and got[-1][0] == "lan.state" and got[-1][1] == off
        # the peer list stays empty while off, the settings snapshot agrees, and no test may start
        st, _, p = _req(mock.port, "GET", "/api/tools/lan/peers")
        assert st == 200 and p["peers"] == [] and p["enabled"] is False and p["error"] == "disabled"
        assert p["self"]["hostname"] == "TEC-DESKTOP"          # this machine is still described
        st, _, s = _req(mock.port, "GET", "/api/settings")
        assert st == 200 and s["lan"] == {"enabled": False}
        st, _, err = _req(mock.port, "POST", "/api/tools/lan/throughput", {"peer": "10.0.0.42"})
        assert st == 400 and err["error"] == {"code": "bad_request", "message": "LAN discovery is turned off"}
        # ... and nothing is announced any more
        mock.state.lan_peer_ts = 0
        mock.state.lan_tick(time.time())
        assert _drain(q, "lan.peers", "lan.peers", 0.5) == []
        # back on: the two peers are seen again
        st, _, on = _req(mock.port, "PUT", "/api/tools/lan/settings", {"enabled": True})
        assert st == 200 and on["enabled"] is True and on["listening"] is True and on["running"] is True
        assert on["error"] is None and [x["ip"] for x in on["peers"]] == ["10.0.0.42", "10.0.0.77"]
        got = _drain(q, "lan.state", "lan.state", 3)
        assert got and got[-1][1] == on
        st, _, p = _req(mock.port, "GET", "/api/tools/lan/peers")
        assert st == 200 and len(p["peers"]) == 2 and p["enabled"] is True
        st, _, s = _req(mock.port, "GET", "/api/settings")
        assert s["lan"] == {"enabled": True}
    finally:
        mock.state.hub.unsubscribe(q)
        mock.state.lan_enabled = True
        mock.state.settings["lan"]["enabled"] = True
    # enabled is a JSON boolean or nothing, and it is the only key
    for bad, message in (({"enabled": "yes"}, "enabled must be true or false"),
                         ({"enabled": "false"}, "enabled must be true or false"),
                         ({"enabled": 1}, "enabled must be true or false"),
                         ({"enabled": 0}, "enabled must be true or false"),
                         ({"enabled": None}, "enabled must be true or false"),
                         ({}, "nothing to update; accepted keys: enabled"),
                         ({"on": True}, "unknown LAN setting(s) on; accepted: enabled"),
                         ({"enabled": True, "bogus": 1}, "unknown LAN setting(s) bogus; accepted: enabled")):
        st, _, err = _req(mock.port, "PUT", "/api/tools/lan/settings", bad)
        assert st == 400 and err["error"] == {"code": "bad_request", "message": message}, bad
    assert mock.state.lan_enabled is True                       # none of them touched the switch
    st, _, p = _req(mock.port, "GET", "/api/tools/lan/peers")
    assert st == 200 and p["enabled"] is True and len(p["peers"]) == 2


#: the keys of a net.changed payload (the shared contract with the service)
NET_CHANGED_KEYS = {"ts", "generation", "default_gateway", "previous_gateway", "internet_nic", "changes", "gateway_changed",
                    "internet_nic_changed", "subnets_changed", "dns_changed", "summary", "cause"}


def test_mock_network_switch(mock):
    """POST /mock/network moves the fake PC onto another synthetic network the way the service reports one:
    net.changed first, then everything that follows the network (the gateway target, LAN peers, the link map,
    the Discovery default range, the DHCP adapter picker, Load Default Tiles) answers for the new network."""
    st, _, cur = _req(mock.port, "GET", "/mock/network")
    assert st == 200 and cur["profile"] == "a" and cur["profiles"] == ["a", "b", "static-bad", "apipa", "none"]

    def recheck_landed_status() -> Dict[str, Any]:
        """GET /api/status as it reads once the fake public-address lookup after the last change has landed."""
        changed = mock.state.net_changed_ts
        mock.state.net_changed_ts = changed - mock.mod.NET_RECHECK_S - 1
        try:
            return _req(mock.port, "GET", "/api/status")[2]
        finally:
            mock.state.net_changed_ts = changed

    st, _, s0 = _req(mock.port, "GET", "/api/status")
    gen0 = s0["net"]["generation"]
    q = mock.state.hub.subscribe()
    try:
        st, _, r = _req(mock.port, "POST", "/mock/network", {"profile": "b"})
        assert st == 200 and r["profile"] == "b" and set(r["event"]) == NET_CHANGED_KEYS
        ev = r["event"]
        assert ev["generation"] == gen0 + 1 and ev["default_gateway"] == "192.168.50.1" and ev["previous_gateway"] == "10.0.0.251"
        # tnt.netwatch.internet_nic_brief: prefix lengths parallel to ipv4, the networks beside them
        assert ev["internet_nic"] == {"index": 7, "name": "Wi-Fi", "ipv4": ["192.168.50.23"], "ipv4_prefixes": ["24"],
                                      "networks": ["192.168.50.0/24"], "dns": ["192.168.50.1"], "dhcp": True}
        assert ev["gateway_changed"] and ev["internet_nic_changed"] and ev["subnets_changed"] and ev["dns_changed"]
        assert ev["summary"] == "Wi-Fi: 192.168.50.23/24 · gateway 192.168.50.1" and ev["cause"] is None
        assert all(set(c) == {"adapter", "kind", "old", "new"} for c in ev["changes"])
        # tnt.netwatch.diff_states' rules (test_mock_network_events_match_the_service compares every value): an adapter that
        # came up or went down lists nothing else, a removed one carries its addresses, the default gateway follows
        assert [(c["adapter"], c["kind"]) for c in ev["changes"]] == [("Wi-Fi", "up"), ("Ethernet", "down"), ("Ethernet 2", "removed"),
                                                                     ("Ethernet 3", "removed"), ("Wi-Fi", "internet_nic"), ("Wi-Fi", "gateway")]
        assert ev["changes"][3]["old"] == ["172.16.20.15/24"] and ev["changes"][5]["new"] == ["192.168.50.1"]
        # on the stream, in the service's order: LAN peers hear about it while the watcher tells the components, then
        # net.changed, then what the next probe ticks bring
        order = []
        deadline = time.time() + 3
        while time.time() < deadline and "map.sample" not in order:
            try:
                frame = q.get(timeout=0.5)
            except Exception:  # noqa: BLE001 - queue.Empty
                continue
            kind = frame.split("\n")[0][7:]
            if kind in ("net.changed", "ping.targets", "lan.peers", "lan.state", "map.sample"):
                order.append(kind)
                if kind == "net.changed":
                    assert json.loads(frame.split("\n")[1][6:]) == ev
        assert order == ["lan.peers", "lan.state", "net.changed", "ping.targets", "map.sample"], order
    finally:
        mock.state.hub.unsubscribe(q)
    try:
        st, _, s = _req(mock.port, "GET", "/api/status")
        assert s["net"] == {"generation": gen0 + 1, "changed_ts": ev["ts"], "default_gateway": "192.168.50.1", "internet_nic": "Wi-Fi",
                            "summary": ev["summary"], "networks": ["100.101.22.7/32", "172.29.64.0/20", "192.168.50.0/24"],
                            "network_id": mock.state.net_id}
        assert s["net"]["network_id"] != s0["net"]["network_id"], "another router: another network (tnt.networks)"
        # tnt.engine.Engine.netinfo_summary's shape: the bare address and its network (the tile shows "192.168.50.23/24")
        nic = s["netinfo"]["internet_nic"]
        assert set(nic) == {"index", "name", "description", "type_name", "ipv4", "network", "gateway", "mac", "warnings"}
        assert s["netinfo"]["local_nic"] is None
        assert (nic["name"], nic["ipv4"], nic["network"], nic["gateway"]) == ("Wi-Fi", "192.168.50.23", "192.168.50.0/24", "192.168.50.1")
        gw = next(t for t in s["targets"] if t["host"] == "gateway")
        assert gw["ip"] == "192.168.50.1" and gw["resolved"] is True
        assert s["map"]["gateway"]["ip"] == "192.168.50.1" and s["map"]["pc"]["ip"] == "192.168.50.23"
        assert s["map"]["public_ip"]["ts"] < ev["ts"], "the old public address until the fake lookup after the change lands"
        # its ISP and city describe the stored address (the UI's checking… gate hides them), then the new network's
        assert s["map"]["public_geo"]["ip"] == s["map"]["public_ip"]["ip"] == "203.0.113.5"
        landed = recheck_landed_status()
        assert landed["map"]["public_ip"]["ip"] == "198.51.100.77" and landed["map"]["public_geo"]["ip"] == "198.51.100.77"
        assert landed["map"]["public_geo"]["place"] == "Springfield, IL" and landed["map"]["public_geo"]["isp"] == "Sample Fiber"
        st, _, n = _req(mock.port, "GET", "/api/netinfo")
        assert n["generation"] == gen0 + 1 and n["changed_ts"] == ev["ts"] and n["internet_nic_index"] == 7
        assert [a["name"] for a in n["adapters"] if a["status"] == "up"] == ["Wi-Fi", "Tailscale", "vEthernet (Default Switch)"]
        st, _, d = _req(mock.port, "GET", "/api/discovery/status")
        assert d["default_range"] == "192.168.50.0/24"
        st, _, p = _req(mock.port, "GET", "/api/tools/lan/peers")
        assert p["self"]["ip"] == "192.168.50.23" and [x["ip"] for x in p["peers"]] == ["192.168.50.60"]
        st, _, dh = _req(mock.port, "GET", "/api/dhcp/status")
        assert dh["adapter"]["name"] == "Wi-Fi" and dh["adapter"]["is_internet"] is True
        assert [a["name"] for a in dh["adapters"]] == ["Wi-Fi", "Tailscale", "vEthernet (Default Switch)"]
        st, _, lst = _req(mock.port, "POST", "/api/targets/defaults")
        assert lst[0]["host"] == "gateway" and lst[0]["ip"] == "192.168.50.1"
        # a static IP typed into the wrong subnet: the adapter says why; the gateway is what Windows reports
        st, _, r = _req(mock.port, "POST", "/mock/network", {"profile": "static-bad"})
        assert st == 200 and r["event"]["default_gateway"] == "172.16.21.1" and r["event"]["dns_changed"] is True
        st, _, n = _req(mock.port, "GET", "/api/netinfo")
        eth = next(a for a in n["adapters"] if a["name"] == "Ethernet")
        assert [w["code"] for w in eth["warnings"]] == ["gateway_outside_subnet", "no_dns"] and eth["dhcp_enabled"] is False
        # no network at all: the gateway tile has no gateway (grey, not red) and there is no default range
        st, _, r = _req(mock.port, "POST", "/mock/network", {"profile": "none"})
        assert r["event"]["default_gateway"] is None and r["event"]["internet_nic"] is None and r["event"]["summary"] == "No network connection"
        st, _, s = _req(mock.port, "GET", "/api/status")
        gw = next(t for t in s["targets"] if t["host"] == "gateway")
        assert gw["ip"] is None and gw["resolved"] is False and gw["resolve_error"] and gw["light"] == "grey"
        assert s["netinfo"]["internet_nic"] is None and s["net"]["default_gateway"] is None and s["map"]["gateway"]["ip"] is None
        assert s["netinfo"]["local_nic"] is None, "nothing physical is up"
        # without internet the failed public-address lookup (tnt.linkmap.refresh_public_ip) drops the old address, keeps the
        # ts of the last one it found and says when it tried, so the WAN chip stops "checking…" once it has
        changed = s["net"]["changed_ts"]
        pub = mock.state._public_ip_view(changed + mock.mod.NET_RECHECK_S + 1)
        assert pub["ip"] is None and pub["error"] == "no internet connection" and pub["checked_ts"] == changed + mock.mod.NET_RECHECK_S
        assert pub["ts"] is None or pub["ts"] < changed
        landed = recheck_landed_status()
        assert landed["map"]["public_ip"]["ip"] is None and landed["map"]["public_geo"] is None
        st, _, d = _req(mock.port, "GET", "/api/discovery/status")
        assert d["default_range"] is None
        st, _, err = _req(mock.port, "POST", "/api/discovery/scan", {})
        assert st == 400 and "type a range" in err["error"]["message"]
        st, _, err = _req(mock.port, "POST", "/mock/network", {"profile": "mars"})
        assert st == 400 and err["error"]["code"] == "bad_request"
        st, _, cur = _req(mock.port, "GET", "/mock/network?profile=b")      # reading never switches
        assert st == 200 and cur["profile"] == "none"
    finally:
        st, _, r = _req(mock.port, "POST", "/mock/network", {"profile": "a"})
        assert st == 200
    st, _, s = _req(mock.port, "GET", "/api/status")
    assert s["net"]["default_gateway"] == "10.0.0.251" and next(t for t in s["targets"] if t["host"] == "gateway")["ip"] == "10.0.0.251"


def _netinfo_adapter(row: Dict[str, Any]) -> Any:
    """A mock /api/netinfo adapter as the ``tnt.netinfo.Adapter`` the service would have read (preferred addresses)."""
    from tnt import netinfo

    def addrs(entries: List[Dict[str, Any]], version: int) -> List[Any]:
        return [netinfo._make_ipaddr(e["address"], version, e["prefix"], netinfo.IP_DAD_STATE_PREFERRED, 0) for e in entries]

    return netinfo.Adapter(index=row["index"], name=row["name"], description=row["description"], mac=row["mac"],
                           if_type=row["if_type"], type_name=row["type_name"], status=row["status"], speed_bps=row["speed_bps"],
                           mtu=row["mtu"], dhcp_enabled=row["dhcp_enabled"], dhcp_server=row["dhcp_server"],
                           dns_suffix=row["dns_suffix"], ipv4=addrs(row["ipv4"], 4), ipv6=addrs(row["ipv6"], 6),
                           gateways=list(row["gateways"]), dns=list(row["dns"]), metric_v4=row["metric_v4"] or 0,
                           is_physical=row["is_physical"], is_loopback=False)


def test_mock_network_events_match_the_service(mock, monkeypatch):
    """The mock is only worth testing the UI against if it says what the service says: every synthetic network's
    adapter warnings are tnt.netinfo.adapter_warnings of the same adapters, status.netinfo.internet_nic is
    Engine.netinfo_summary's, LAN peers' own address follows tnt.lanpeers' rule, and every move between the networks
    publishes exactly the tnt.netwatch.build_event payload (changes, flags, internet_nic, summary, cause)."""
    from tnt import lanpeers, netinfo, netwatch
    from tnt.engine import Engine

    def service_state(profile: str):
        prof = mock.mod.net_profile(profile)
        adapters = [_netinfo_adapter(a) for a in prof["adapters"]]
        nic = next((a for a in adapters if a.index == prof["internet_nic_index"]), None)
        return prof, adapters, netwatch.build_state(adapters, nic, prof["default_gateway"])

    for name in mock.mod.NET_PROFILE_NAMES:
        prof, adapters, _ = service_state(name)
        for row, a in zip(prof["adapters"], adapters):
            assert row["warnings"] == netinfo.adapter_warnings(a, adapters, prof["internet_nic_index"]), (name, row["name"])
    try:
        for name in ("b", "static-bad", "apipa", "none", "a", "apipa", "b", "a"):
            old = service_state(mock.state.net_profile)[2]
            event = mock.state.switch_network(name)
            prof, adapters, new = service_state(name)
            assert event == netwatch.build_event(old, new, event["generation"], event["ts"]), name
            # the same adapters read through the real netinfo layer (the route goes out of the internet adapter)
            nic = next((a for a in adapters if a.index == prof["internet_nic_index"]), None)
            monkeypatch.setattr(netinfo, "_query_adapters", lambda: [copy.deepcopy(a) for a in adapters])
            monkeypatch.setattr(netinfo, "_route_source_ip", lambda probe=None: nic.primary_ipv4 if nic is not None else None)
            netinfo._invalidate_cache()
            summary = Engine().netinfo_summary()
            assert mock.state.status()["netinfo"] == summary, name
            up = [a for a in adapters if a.is_up]
            own = (nic.primary_ipv4 if nic is not None else None) or lanpeers._bench_ipv4(up)
            assert mock.state.lan_peers()["self"]["ip"] == own, name
    finally:
        netinfo._invalidate_cache()
        mock.state.switch_network("a")


def test_mock_scan_across_a_network_change_is_marked(mock):
    """discovery.done carries network_changed for a scan the PC changed networks during, as tnt.engine sends it."""
    q = mock.state.hub.subscribe()
    try:
        st, _, r = _req(mock.port, "POST", "/api/discovery/scan", {"range": "10.0.0.0/24"})
        assert st == 200 and r["started"] is True
        st, _, _ = _req(mock.port, "POST", "/mock/network", {"profile": "b"})
        assert st == 200
        st, _, c = _req(mock.port, "POST", "/api/discovery/cancel")
        assert st == 200
        got = _drain(q, "discovery.done", "discovery.done", 6)
        assert got and got[-1][1]["network_changed"] is True and got[-1][1]["cancelled"] is True
    finally:
        mock.state.hub.unsubscribe(q)
        mock.state.switch_network("a")


#: every key tnt.wifi.list_profiles() carries (the mock must mirror it exactly)
WIFI_VIEW_KEYS = {"available", "interfaces", "profiles", "error", "source", "ts"}
WIFI_PROFILE_KEYS = {"name", "ssid", "authentication", "encryption", "key", "key_present",
                     "connection_mode", "non_broadcast", "interface", "error"}


def test_wifi_profiles(mock):
    # reveal is off by default now: the list arrives with the keys left out (the card's first view)
    st, _, w = _req(mock.port, "GET", "/api/tools/wifi/profiles")
    assert st == 200 and set(w) == WIFI_VIEW_KEYS
    assert w["available"] is True and w["error"] is None and w["source"] == "wlanapi" and w["ts"] > 0
    assert len(w["interfaces"]) == 1 and set(w["interfaces"][0]) == {"guid", "description", "state"}
    guid = w["interfaces"][0]["guid"]
    assert w["interfaces"][0]["state"] == "connected" and "Wireless" in w["interfaces"][0]["description"]
    assert [p["ssid"] for p in w["profiles"]] == ["TEC-Office", "TEC-Guest", "SiteSurvey-5G"]
    for p in w["profiles"]:
        assert set(p) == WIFI_PROFILE_KEYS
        assert p["interface"] == guid and p["error"] is None and p["name"] == p["ssid"]
        assert p["connection_mode"] in ("auto", "manual")
    assert [p["key"] for p in w["profiles"]] == [None, None, None]
    assert [p["key_present"] for p in w["profiles"]] == [True, True, False]
    # reveal=1 (admin allowed by default in the mock) returns the plaintext keys
    st, _, shown = _req(mock.port, "GET", "/api/tools/wifi/profiles?reveal=1")
    assert st == 200 and set(shown) == WIFI_VIEW_KEYS
    office, guest, survey = shown["profiles"]
    assert office["key"] == "example-office-passphrase" and office["key_present"] is True
    assert office["authentication"] == "WPA2PSK" and office["encryption"] == "AES" and office["non_broadcast"] is False
    assert guest["key"] == "example-guest-passphrase" and guest["key_present"] is True
    # the open network has no key at all, and it is the hidden one
    assert survey["key"] is None and survey["key_present"] is False
    assert survey["authentication"] == "open" and survey["encryption"] == "none"
    assert survey["connection_mode"] == "manual" and survey["non_broadcast"] is True
    # ?reveal=0 (and the empty/garbage forms, which keep the off default) drop every key
    for query in ("?reveal=0", "?reveal=", "?reveal=maybe"):
        st, _, masked = _req(mock.port, "GET", "/api/tools/wifi/profiles" + query)
        assert st == 200 and [p["key"] for p in masked["profiles"]] == [None, None, None], query
        assert [p["key_present"] for p in masked["profiles"]] == [True, True, False], query
    for query in ("?reveal=1", "?reveal=true", "?reveal=yes", "?reveal=on"):
        st, _, s = _req(mock.port, "GET", "/api/tools/wifi/profiles" + query)
        assert st == 200 and s["profiles"][0]["key"] == "example-office-passphrase", query


def test_wifi_profiles_reveal_needs_admin(mock):
    """The mock emulates the service's admin gate: a non-admin caller is refused reveal=1 with
    403 admin_required, but the masked list stays available."""
    mock.state.wifi_admin = False
    try:
        st, _, body = _req(mock.port, "GET", "/api/tools/wifi/profiles?reveal=1")
        assert st == 403 and body["error"]["code"] == "admin_required"
        assert "administrator" in body["error"]["message"]
        # reveal=0 (and the default) still work for anyone
        st, _, masked = _req(mock.port, "GET", "/api/tools/wifi/profiles?reveal=0")
        assert st == 200 and [p["key"] for p in masked["profiles"]] == [None, None, None]
        st, _, dflt = _req(mock.port, "GET", "/api/tools/wifi/profiles")
        assert st == 200 and dflt["available"] is True and dflt["profiles"][0]["key"] is None
    finally:
        mock.state.wifi_admin = True


def test_wifi_profiles_reveal_refuses_a_page_of_another_origin(mock):
    """Like the service (tests/test_wifi.py), the mock refuses reveal=1 to a browser page that is
    not served by it, and still allows the TNT window's own same-origin request."""
    def get(path: str, headers: Dict[str, str]) -> Tuple[int, Any]:
        conn = http.client.HTTPConnection("127.0.0.1", mock.port, timeout=10)
        try:
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read())
        finally:
            conn.close()

    for headers in ({"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
                    {"Sec-Fetch-Site": "same-site"}, {"Origin": "null"}):
        st, body = get("/api/tools/wifi/profiles?reveal=1", headers)
        assert st == 403 and body["error"]["code"] == "forbidden", headers
        assert body["error"]["message"] == mock.mod.WIFI_CROSS_ORIGIN_MSG
        st, body = get("/api/tools/wifi/profiles", headers)
        assert st == 200 and body["profiles"][0]["key"] is None
    st, body = get("/api/tools/wifi/profiles?reveal=1", {"Origin": f"http://127.0.0.1:{mock.port}", "Sec-Fetch-Site": "same-origin"})
    assert st == 200 and body["profiles"][0]["key"] == "example-office-passphrase"


def test_pause_and_resume(mock):
    st, _, r = _req(mock.port, "POST", "/api/monitoring/pause")
    assert st == 200 and r == {"paused": True}
    st, _, s = _req(mock.port, "GET", "/api/status")
    assert s["paused"] is True and all(t["light"] == "grey" for t in s["targets"])
    st, _, r = _req(mock.port, "POST", "/api/monitoring/resume")
    assert st == 200 and r == {"paused": False}
    st, _, s = _req(mock.port, "GET", "/api/status")
    assert s["paused"] is False and s["overall_light"] != "grey"


def test_export_returns_pdf(mock):
    st, h, body = _req(mock.port, "POST", "/api/export", {"range": "weekly"}, raw=True)
    assert st == 200 and h["content-type"] == "application/pdf"
    assert body.startswith(b"%PDF-1.") and body.rstrip().endswith(b"%%EOF")
    assert re.fullmatch(r"attachment; filename=TNT-report-\d{8}-\d{8}\.pdf", h["content-disposition"])
    now = time.time()
    st, h, body = _req(mock.port, "POST", "/api/export", {"range": "custom", "from": now - 3600, "to": now}, raw=True)
    assert st == 200 and body.startswith(b"%PDF")
    st, _, err = _req(mock.port, "POST", "/api/export", {"range": "custom", "from": now, "to": now - 10})
    assert st == 400 and err["error"]["code"] == "bad_request"
    st, _, err = _req(mock.port, "POST", "/api/export", {"range": "hourly"})
    assert st == 400


#: tnt.diagnostics._network: NetWatcher.state(), "available" and the last net.changed (tests/test_netchange_e2e.py reads the
#: same keys from the real service)
NETWORK_DIAG_KEYS = {"generation", "changed_ts", "default_gateway", "internet_nic", "summary", "networks", "running", "polls", "failures",
                     "last_error", "pending", "poll_s", "available", "last_change"}


def test_diagnostics_and_log_tail(mock):
    st, _, d = _req(mock.port, "GET", "/api/diagnostics")
    assert st == 200
    for k in ("service", "os", "api", "db", "logs", "ping", "outages", "speedtest", "discovery", "network", "threads",
              "memory_mb", "cpu_pct", "recent_log", "recent_events", "errors_24h"):
        assert k in d, k
    assert set(d["network"]) == NETWORK_DIAG_KEYS and d["network"]["available"] is True
    # tnt.diagnostics._geoip: the manager's status and its installed files
    assert set(d["geoip"]) == set(mock.mod.GEOIP_DIAG_KEYS) and d["geoip"]["available"] is True
    assert set(d["geoip"]["status"]) == set(mock.mod.GEOIP_STATUS_KEYS) and d["geoip"]["status"]["state"] == "ready"
    month = d["geoip"]["status"]["month"]
    assert [f["name"] for f in d["geoip"]["files"]] == [f"dbip-city-lite-{month}.mmdb", f"dbip-asn-lite-{month}.mmdb"]
    assert sum(f["bytes"] for f in d["geoip"]["files"]) == d["geoip"]["status"]["bytes"]
    assert d["service"]["version"] == mock.mod.VERSION and d["api"]["port"] == mock.port
    assert d["ping"]["targets"] and set(d["ping"]["targets"][0]) >= {"id", "host", "ip", "kind", "thread_alive", "last_ts", "light"}
    assert [b["name"] for b in d["speedtest"]["backends"]] == ["cloudflare", "fastcom"]
    # tnt.diagnostics._discovery's keys; last_run is there once a run exists (the mock seeds runs)
    assert set(d["discovery"]) == {"available", "running", "progress", "last_run_ts", "last_run"}
    assert d["discovery"]["last_run"]["ts"] == d["discovery"]["last_run_ts"]
    st, _, lg = _req(mock.port, "GET", "/api/diagnostics/log?lines=50")
    assert st == 200 and lg["file"].endswith("tnt-service.log") and len(lg["lines"]) == 50
    assert re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} ", lg["lines"][0])


def test_unknown_routes(mock):
    st, _, err = _req(mock.port, "GET", "/api/nope")
    assert st == 404 and err["error"]["code"] == "not_found"
    st, _, err = _req(mock.port, "POST", "/api/status")
    assert st == 404
    st, _, err = _req(mock.port, "POST", "/index.html")
    assert st == 405


def test_sse_stream_hello_then_ping_samples(mock):
    conn = http.client.HTTPConnection("127.0.0.1", mock.port, timeout=5)
    try:
        conn.request("GET", "/api/events")
        resp = conn.getresponse()
        assert resp.status == 200 and resp.getheader("Content-Type", "").startswith("text/event-stream")
        assert resp.getheader("Cache-Control") == "no-cache"

        def read_event():
            lines = []
            while True:
                ln = resp.readline().decode("utf-8").rstrip("\r\n")
                if ln == "":
                    if any(l.startswith("event:") for l in lines):
                        ev = next(l[6:].strip() for l in lines if l.startswith("event:"))
                        data = "".join(l[5:].strip() for l in lines if l.startswith("data:"))
                        return ev, json.loads(data)
                    lines = []  # a comment frame such as ': ping'
                    continue
                lines.append(ln)

        ev, data = read_event()
        assert ev == "hello" and data["version"] == mock.mod.VERSION and "ts" in data
        # no ticker thread runs in the tests: drive one tick by hand and expect one sample per target
        ts = float(int(time.time()))
        mock.state.tick(ts)
        seen = {}
        for _ in range(3):
            ev, data = read_event()
            assert ev == "ping.sample"
            assert set(data) == {"target_id", "ts", "ok", "rtt_ms", "light"} and data["ts"] == ts
            seen[data["target_id"]] = data
        assert set(seen) == {1, 2, 3}
        # settings changes are broadcast too
        mock.state.update_settings({"ui": {"theme": "light"}, "speedtest": {"interval_min": 30}})
        ev, data = read_event()
        assert ev == "settings.changed" and "speedtest.interval_min" in data["changed"]
    finally:
        conn.close()


def test_mock_cli_help_runs_without_tnt():
    r = subprocess.run([sys.executable, str(MOCK), "--help"], capture_output=True, text=True, timeout=30,
                       cwd=str(ROOT))
    assert r.returncode == 0 and "--port" in r.stdout
    src = MOCK.read_text(encoding="utf-8")
    assert not re.search(r"^\s*(from|import)\s+tnt\b", src, re.M)


# ---------------------------------------------------------------------------
# the WiFi page in a headless browser, against the mock and its fake bridge
# ---------------------------------------------------------------------------
_BROWSER: Dict[str, Optional[str]] = {}


def _dump_dom(browser: str, url: str, profile: Path, budget_ms: int = 5000, size: Tuple[int, int] = (1366, 900)) -> str:
    """The DOM after `budget_ms` of the page's (virtual) time. The browser may only reach 127.0.0.1:
    every other host fails to resolve and any other request goes to a dead proxy."""
    args = [browser, "--headless=new", "--do-not-de-elevate", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
            "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-extensions",
            "--disable-default-apps", f"--user-data-dir={profile}",
            "--proxy-server=http://127.0.0.1:9", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
            f"--window-size={size[0]},{size[1]}", f"--virtual-time-budget={budget_ms}", "--dump-dom", url]
    try:
        r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return r.stdout or ""


def _headless_browser(tmp: Path) -> Optional[str]:
    """A Chromium that can --dump-dom on this machine (TNT_TEST_BROWSER, else Chrome, else Edge), or None.
    Edge's headless mode hands off to another process on some machines and prints nothing: such a
    browser is skipped rather than failing the tests."""
    if "path" in _BROWSER:
        return _BROWSER["path"]
    found = None
    cands = [os.environ.get("TNT_TEST_BROWSER"), shutil.which("chrome"), shutil.which("google-chrome"), shutil.which("chromium"),
             r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
             shutil.which("msedge"), r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"]
    for i, cand in enumerate(c for c in cands if c):
        if Path(cand).is_file() and "tnt-probe-ok" in _dump_dom(cand, "data:text/html,<p>tnt-probe-ok</p>", tmp / f"probe{i}", budget_ms=100):
            found = cand
            break
    _BROWSER["path"] = found
    return found


@pytest.fixture()
def browser_page(mock, monkeypatch, tmp_path):
    browser = _headless_browser(tmp_path)
    if not browser:
        pytest.skip("no headless Chrome / Edge that can dump the DOM on this machine")
    # an event stream never ends, which would stall the browser's virtual clock: refuse it here
    # (the UI then polls /api/status instead, exactly as it does when the service goes away)
    monkeypatch.setattr(mock.mod.Handler, "_sse", lambda self: self._error(503, "unavailable", "no event stream in this test"))
    profiles = itertools.count()

    def dump(target: str, **kw: Any) -> str:
        dom = _dump_dom(browser, f"http://127.0.0.1:{mock.port}/{target}", tmp_path / f"profile{next(profiles)}", **kw)
        assert "</html>" in dom, "the browser produced no DOM"
        return dom
    return dump


def _tile_body(dom: str, name: str) -> str:
    m = re.search(r'id="tile-' + name + r'"[^>]*>(.*?)</div>\s*</a>', dom, re.S)
    assert m, name
    return m.group(1)


def test_wifi_page_mounts_in_a_browser_without_errors(browser_page):
    dom = browser_page("#wifi")
    # the mock bridge records uncaught errors, rejections and console.error calls here
    assert 'data-mock-errors="[]"' in dom
    assert len(re.findall(r'<a class="tile[^"]*" data-view="', dom)) == 8
    assert re.search(r'<a class="tile active" data-view="wifi" href="#wifi"', dom)
    tile = _tile_body(dom, "wifi")
    assert re.search(r'<span class="num">\d+</span><span class="muted">networks ·</span><span class="muted">\d+ APs</span>', tile)
    assert "Scanning every 10 s" in dom and "briefly add latency" in dom
    assert re.search(r'class="stack survey-content"(?! hidden)', dom)
    assert len(re.findall(r'<div class="survey-net[ "]', dom)) >= 20
    assert len(re.findall(r'<tr data-bssid="[0-9A-F:]{17}" data-net="', dom)) >= 28     # one table row per access point
    assert len(re.findall(r'<button class="survey-pick survey-ssid[^"]*" type="button" data-pick="', dom)) >= 28
    assert dom.count('class="survey-band-canvas"') == 3 and dom.count('class="survey-signal-canvas"') == 1
    assert re.search(r'<span class="survey-net-name">[0-9A-F:]{17}</span><span class="survey-net-sub"><span class="badge grey"[^>]*>hidden</span>', dom)
    assert "Contoso Access Systems" in dom and "likely Fabrikam Networks" in dom   # vendors via GET /api/oui
    assert 'aria-label="6 GHz spectrum: 5 access points"' in dom


def test_wifi_selected_network_is_highlighted_everywhere_in_a_browser(browser_page):
    dom = browser_page("?select=s:Fabrikam%20Mesh#wifi")
    assert 'data-mock-errors="[]"' in dom
    selected = re.findall(r'<div class="survey-net selected[^"]*" role="option" aria-selected="true" tabindex="0" data-key="([^"]+)"', dom)
    assert selected == ["s:Fabrikam Mesh"]
    rows = re.findall(r'<tr data-bssid="([^"]+)" data-net="([^"]+)" class="is-selected">', dom)
    assert sorted(b for b, _ in rows) == ["F0:0D:CA:55:01:10", "F0:0D:CA:55:01:11", "F0:0D:CA:55:02:11"] and {n for _, n in rows} == {"s:Fabrikam Mesh"}
    assert len(re.findall(r'data-pick="s:Fabrikam Mesh" aria-pressed="true"', dom)) == 3
    assert re.search(r'<span class="survey-legend-chip">.*?<strong>Fabrikam Mesh</strong>', dom)


def test_wifi_tile_on_the_dashboard_waits_for_a_late_bridge(browser_page):
    dom = browser_page("?wifi=late#ipinfo")
    assert 'data-mock-errors="[]"' in dom
    assert re.search(r'<a class="tile active" data-view="ipinfo"', dom)
    tile = _tile_body(dom, "wifi")
    assert "networks" in tile and "APs" in tile and "tile-ellipsis" in tile


@pytest.mark.parametrize("mode, texts", [
    ("denied", ["Location access needed", "Open location settings", "Windows is blocking the Wi-Fi scan"]),
    ("noadapter", ["No Wi-Fi adapter", "WLAN AutoConfig"]),
    ("off", ["Survey off", "Turn the survey on"]),
    ("radiooff", ["Wi-Fi is turned off", "Wi-Fi is off"]),
    ("error", ["The Wi-Fi survey hit a problem", "error 1168"]),
    ("nobridge", ["The Wi-Fi survey runs in the TNT window", "Open in the TNT window"]),
    ("outdated", ["This TNT window has no Wi-Fi survey yet", "Update TNT"]),
])
def test_wifi_states_render_their_message_in_a_browser(browser_page, mode, texts):
    dom = browser_page(f"?wifi={mode}#wifi")
    assert 'data-mock-errors="[]"' in dom
    for text in texts:
        assert text in dom, (mode, text)
    assert 'class="stack survey-content" hidden=""' in dom          # no empty cards under the message
    assert re.search(r'<div class="card survey-state" role="status" data-sig="[^"]*" data-kind="', dom)
    # nothing that reads as an empty neighbourhood, and no survey controls where there is no survey
    assert "0 access points" not in dom
    if mode in ("nobridge", "outdated"):
        assert re.search(r'<span class="survey-switch" hidden="">', dom) and 'Scan now' in dom
        assert re.search(r'<button class="btn btn-sm" type="button" title="Ask the adapter[^"]*"[^>]*\bhidden=""', dom)
        assert re.search(r'<button class="btn btn-sm" type="button" title="Forget every access point[^"]*"[^>]*\bhidden=""', dom)
    if mode == "error":
        assert re.search(r'<p class="survey-state-detail">[^<]*error 1168[^<]*</p>', dom), "the raw error in the mono line"


# the real index.html in one sandboxed iframe per window width (scripts off: the tile row is static markup and
# CSS), measured with its eight tiles and again with a copy of the last one as a ninth (never committed)
_TILE_PROBE = r"""<!doctype html><html><head><meta charset="utf-8"><title>tile probe</title></head><body>
<pre id="probe">pending</pre>
<script>
const WIDTHS = __WIDTHS__;
const results = {};
let pending = WIDTHS.length;
function measure(doc) {
  const box = doc.getElementById('tiles').getBoundingClientRect();
  return Array.from(doc.querySelectorAll('#tiles > .tile')).map((t) => {
    const r = t.getBoundingClientRect(), title = t.querySelector('.tile-title');
    return { y: Math.round(r.top - box.top), w: Math.round(r.width * 10) / 10, x: Math.round((r.left - box.left) * 10) / 10,
             right: Math.round((box.right - r.right) * 10) / 10, titleH: Math.round(title.getBoundingClientRect().height) };
  });
}
for (const w of WIDTHS) {
  const f = document.createElement('iframe');
  f.setAttribute('sandbox', 'allow-same-origin');
  f.style.cssText = 'width:' + w + 'px;height:900px;border:0;display:block';
  f.onload = () => {
    const doc = f.contentDocument;
    doc.body.style.minHeight = '2400px';   // taller than the window, like a real page: the scrollbar takes its share
    const done = () => {
      const real = measure(doc);
      const tiles = doc.getElementById('tiles');
      const extra = tiles.lastElementChild.cloneNode(true);
      extra.querySelector('.tile-title').textContent = 'Extra';
      tiles.appendChild(extra);
      results[w] = { real, extra: measure(doc), inner: doc.documentElement.clientWidth };
      if (--pending === 0) document.getElementById('probe').textContent = JSON.stringify(results);
    };
    (doc.fonts && doc.fonts.ready ? doc.fonts.ready : Promise.resolve()).then(() => setTimeout(done, 50));
  };
  f.src = '/index.html';
  document.body.appendChild(f);
}
</script></body></html>"""


def test_tile_grid_keeps_equal_widths_in_a_browser(browser_page, mock, monkeypatch):
    """The eight tiles, and a temporary ninth, at desktop down to small-window widths: balanced rows, every tile in
    every row the same width, nothing past the row's right edge, every title on one line."""
    widths = [1920, 1600, 1440, 1366, 1024, 980, 960, 900, 800, 740, 720, 700]
    page = _TILE_PROBE.replace("__WIDTHS__", json.dumps(widths)).encode("utf-8")
    original = mock.mod.Handler._static

    def static(self, path):
        if path != "/tile-probe.html":
            return original(self, path)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)
        return None

    monkeypatch.setattr(mock.mod.Handler, "_static", static)
    dom = browser_page("tile-probe.html", budget_ms=8000, size=(800, 600))
    m = re.search(r'<pre id="probe">(.*?)</pre>', dom, re.S)
    assert m and m.group(1) != "pending", "the probe page did not finish"
    res = json.loads(m.group(1))
    expect = {  # window width: (tiles per row with the eight tiles, with a ninth)
        1920: ([4, 4], [4, 4, 1]), 1600: ([4, 4], [4, 4, 1]), 1440: ([4, 4], [4, 4, 1]), 1366: ([4, 4], [4, 4, 1]),
        1024: ([4, 4], [4, 4, 1]), 960: ([4, 4], [4, 4, 1]), 900: ([4, 4], [4, 4, 1]), 800: ([3, 3, 2], [3, 3, 3]),
        720: ([3, 3, 2], [3, 3, 3]), 700: ([2, 2, 2, 2], [2, 2, 2, 2, 1]),
    }
    for w, (rows8, rows9) in expect.items():
        for key, rows in (("real", rows8), ("extra", rows9)):
            tiles = res[str(w)][key]
            tops = sorted({t["y"] for t in tiles})
            assert [sum(1 for t in tiles if t["y"] == y) for y in tops] == rows, (w, key, tiles)
            sizes = [t["w"] for t in tiles]
            assert max(sizes) - min(sizes) <= 0.5, (w, key, sizes)
            assert min(t["right"] for t in tiles) >= -0.5, (w, key, tiles)
            # the first tile of every row starts at the left edge and a full row reaches the right one
            assert all(t["x"] <= 0.5 for t in tiles if t["x"] < t["w"]), (w, key, tiles)
            assert min(t["right"] for t in tiles) <= 1.5, (w, key, tiles)
            # every title on one line (the tight head where the tiles are narrow)
            assert max(t["titleH"] for t in tiles) <= 30, (w, key, [t["titleH"] for t in tiles])


def test_open_views_follow_a_network_change_in_a_browser(browser_page, mock):
    """The field bug: TNT stays open while the PC joins another network. This page gets no event (the fixture
    refuses the stream), so it is the status-poll path: a newer status.net.generation reloads the open view."""
    mock.state.status_requests = 0
    mock.state.net_switch_after_status = (3, "b")
    try:
        dom = browser_page("#ipinfo", budget_ms=15000)
    finally:
        mock.state.net_switch_after_status = None
        mock.state.switch_network("a")
    assert 'data-mock-errors="[]"' in dom
    tile = _tile_body(dom, "ipinfo")
    assert "Wi-Fi" in tile and "192.168.50.23/24" in tile and "192.168.50.1" in tile and "10.0.0.112" not in tile
    view = dom.split('id="view"', 1)[1]
    # the adapters were read again without a reload: the Wi-Fi card, the new default gateway, nothing of the old network
    assert '<code class="copy" title="Click to copy">192.168.50.23</code>' in view and "10.0.0.112" not in view
    assert re.search(r'Default gateway</span><code class="copy" title="Click to copy">192\.168\.50\.1</code>', view)


def test_link_map_shows_isp_and_location_in_a_browser(browser_page, mock):
    """The live link map's Internet node names the ISP and city of the public address, with DB-IP's attribution under
    the card; while the data downloads the node says so and the attribution hides."""
    # a network change moments ago keeps the old public address "checking…" until the fake lookup lands
    while mock.state.net_changed_ts is not None and time.time() - mock.state.net_changed_ts < mock.mod.NET_RECHECK_S + 0.5:
        time.sleep(0.1)
    dom = browser_page("#ipinfo")
    assert 'data-mock-errors="[]"' in dom
    assert "Example Broadband" in dom and "Anytown, TX" in dom and "IP Geolocation by DB-IP" in dom
    attrib = re.search(r'<div class="lm-attrib"[^>]*>', dom)
    assert attrib and "hidden" not in attrib.group(0)
    mock.state.geoip_state = "downloading"
    try:
        dom = browser_page("#ipinfo")
    finally:
        mock.state.geoip_state = "ready"
    assert 'data-mock-errors="[]"' in dom
    assert "downloading data…" in dom and "Example Broadband" not in dom
    assert re.search(r'<div class="lm-attrib" hidden=""', dom)


def test_tools_page_follows_a_network_change_in_a_browser(browser_page, mock):
    mock.state.status_requests = 0
    mock.state.net_switch_after_status = (3, "b")
    try:
        dom = browser_page("#tools", budget_ms=15000)
    finally:
        mock.state.net_switch_after_status = None
        mock.state.switch_network("a")
    assert 'data-mock-errors="[]"' in dom
    # the DHCP card's adapter picker and the LAN card's "This PC" and peers follow the network
    assert "Wi-Fi — 192.168.50.23/24 (DHCP) (internet)" in dom
    assert "192.168.50.23" in re.search(r'<div class="lan-self">(.*?)</div>', dom, re.S).group(1)
    assert "SITE-B-PC" in dom and "TEC-LAPTOP-02" not in dom
    # the Tools tile: the DHCP server's line, then the tools by name
    tile = _tile_body(dom, "tools")
    assert re.findall(r'<div class="tile-line tile-tool">([^<]+)</div>', tile) == ["LAN throughput", "Traceroute", "Subnet calc", "WiFi passwords"]
    assert "DHCP server" in tile and "Tools for the field" not in tile


# ---------------------------------------------------------------------------
# Reports: the Full Scan button, the eighth tile, the compact page, the full-scan controller and the mock's routes
# ---------------------------------------------------------------------------
REPORT_ROW_KEYS = {"id", "site", "created_ts", "completed_ts", "status", "network_id", "summary"}
REPORT_SUMMARY_KEYS = {"download_mbps", "upload_mbps", "latency_ms", "gateway_avg_ms", "gateway_loss_pct", "internet_avg_ms", "internet_loss_pct",
                       "outages", "downtime_s", "hosts", "wifi_aps", "wifi_networks", "wifi_connected_rssi", "window_hours"}
REPORT_DATA_KEYS = {
    "meta": {"site", "created_ts", "completed_ts", "duration_s", "tnt_version", "hostname", "scan_phases", "network"},
    "network": {"available", "reason", "internet_nic", "public_ip", "isp", "warnings"},
    "speed": {"available", "reason", "result", "window"},
    "ping": {"available", "reason", "window_start", "window_end", "window_reason", "visits", "monitored_s", "targets", "note", "untagged_since"},
    "outages": {"available", "reason", "window_start", "window_end", "count", "network_outages", "target_outages", "by_kind", "downtime_s",
                "network_down_s", "longest_s", "monitored_s", "items", "items_total", "note"},
    "discovery": {"available", "reason", "run_id", "range", "started_ts", "duration_s", "host_count", "device_types", "hosts", "hosts_total", "note"},
    "wifi": {"available", "reason", "state", "adapter", "collected_ts", "connected", "networks", "aps_count", "bands", "aps", "aps_total"},
}
#: (with the additions the service documents in docs/ARCHITECTURE.md: network_down_s, network_outages, target_outages, monitored_s,
#: items[].open / name / targets, discovery.note, connected.channel_aps / overlap_aps, internet_nic description / type_name / internet,
#: speed.result.id, the job's window_start / window_reason; for networks: meta.network, ping.visits / monitored_s, the "site_network"
#: window, the list rows' network_id, the job's network_id / suggested_site)
REPORT_NETWORK_KEYS = {"id", "mac", "vendor", "gateway_ip", "subnet", "dhcp_server", "identity", "virtual_mac", "portable"}
REPORT_NIC_KEYS = {"name", "description", "type_name", "internet", "ipv4", "prefix", "gateway", "dns", "dhcp", "dhcp_server", "mac", "link_bps"}
REPORT_SPEED_RESULT_KEYS = {"ts", "backend", "server", "isp", "external_ip", "download_mbps", "upload_mbps", "latency_ms", "jitter_ms", "packet_loss_pct",
                            "ok", "error", "id"}
REPORT_SPEED_WINDOW_KEYS = {"count", "download_avg", "download_min", "download_max", "upload_avg", "upload_min", "upload_max", "latency_avg"}
REPORT_TARGET_KEYS = {"id", "host", "label", "role", "ip", "samples", "lost", "loss_pct", "avg_ms", "min_ms", "max_ms", "p95_ms", "jitter_ms"}
REPORT_OUTAGE_KEYS = {"start_ts", "end_ts", "duration_s", "kind", "host", "missed", "missed_pct", "note", "open", "name", "targets"}
REPORT_HOST_KEYS = {"ip", "hostname", "mac", "vendor", "device_type", "open_ports"}
REPORT_AP_KEYS = {"ssid", "hidden", "bssid", "band", "channel", "width_mhz", "rssi", "security", "generation", "vendor", "connected"}
REPORT_BAND_KEYS = {"aps", "networks", "strongest_rssi", "median_rssi", "busiest_channel", "busiest_channel_aps"}
REPORT_JOB_KEYS = {"id", "site", "started_ts", "status", "phase", "pct", "message", "phases", "report_id", "error", "window_start", "window_reason",
                   "network_id", "network", "suggested_site"}
REPORT_PHASE_KEYS = {"key", "status", "message", "started_ts", "finished_ts"}
COMPARE_ROW_KEYS = {"key", "label", "unit", "a", "b", "delta", "delta_pct", "better", "higher_is_better", "note"}


def _assert_report_shape(rep: Dict[str, Any]) -> None:
    """A report the way GET /api/reports/{id} carries it: every section present, the contract's keys at every level."""
    assert set(rep) == REPORT_ROW_KEYS | {"data"} and set(rep["summary"]) == REPORT_SUMMARY_KEYS and rep["status"] in ("complete", "partial")
    data = rep["data"]
    assert set(data) == set(REPORT_DATA_KEYS)
    for key, keys in REPORT_DATA_KEYS.items():
        assert set(data[key]) == keys, key
        if key != "meta":
            assert isinstance(data[key]["available"], bool) and (data[key]["available"] or data[key]["reason"]), key
    assert [p["key"] for p in data["meta"]["scan_phases"]] == ["speed", "discovery", "wifi", "history", "save"]
    assert all(set(p) == REPORT_PHASE_KEYS for p in data["meta"]["scan_phases"])
    net = data["meta"]["network"]
    assert set(net) == REPORT_NETWORK_KEYS and net["identity"] in ("mac", "fingerprint", "unknown") and rep["network_id"] == net["id"]
    assert (net["identity"] == "mac") == bool(net["mac"])
    nic = data["network"]["internet_nic"]
    assert nic is None or set(nic) == REPORT_NIC_KEYS
    assert set(data["speed"]["window"]) == REPORT_SPEED_WINDOW_KEYS
    if data["speed"]["available"]:
        assert set(data["speed"]["result"]) == REPORT_SPEED_RESULT_KEYS
    if data["ping"]["window_reason"] == "site_network":
        # only the site network's visits count: inside the window, oldest first, the time monitored their length
        visits = data["ping"]["visits"]
        assert all(set(v) == {"start", "end"} and data["ping"]["window_start"] - 0.01 <= v["start"] < v["end"] <= data["ping"]["window_end"] + 0.01 for v in visits)
        assert [v["start"] for v in visits] == sorted(v["start"] for v in visits) and net["identity"] != "unknown"
        assert 0 <= data["ping"]["monitored_s"] <= sum(v["end"] - v["start"] for v in visits) + 1.0, "the visits less the monitoring gaps in them"
    if data["ping"]["available"]:
        assert data["ping"]["window_reason"] in ("network_change", "seven_days", "data_start", "site_network")
        assert data["ping"]["window_start"] < data["ping"]["window_end"] and data["ping"]["targets"]
        assert all(set(t) == REPORT_TARGET_KEYS and t["role"] in ("gateway", "local", "internet") for t in data["ping"]["targets"])
    out = data["outages"]
    if out["available"]:
        assert set(out["by_kind"]) == set(out["downtime_s"]) == {"target", "total_local", "total_internet", "gap"}
        assert all(set(o) == REPORT_OUTAGE_KEYS for o in out["items"]) and len(out["items"]) <= 50 <= max(50, out["items_total"])
        assert [o["start_ts"] for o in out["items"]] == sorted((o["start_ts"] for o in out["items"]), reverse=True)
    if data["discovery"]["available"]:
        assert all(set(x) == REPORT_HOST_KEYS for x in data["discovery"]["hosts"]) and len(data["discovery"]["hosts"]) <= 512
    wifi = data["wifi"]
    if wifi["available"]:
        assert all(set(a) == REPORT_AP_KEYS for a in wifi["aps"]) and len(wifi["aps"]) <= 200
        assert [a["rssi"] for a in wifi["aps"]] == sorted((a["rssi"] for a in wifi["aps"]), reverse=True)
        assert all(set(b) == REPORT_BAND_KEYS for b in wifi["bands"].values())
        assert wifi["connected"] is None or set(wifi["connected"]) == {"ssid", "bssid", "rssi", "band", "channel", "width_mhz", "channel_aps",
                                                                       "overlap_aps"}


def test_reports_tile_full_scan_button_and_wiring():
    html = _read("index.html")
    # Full Scan is the first thing on the right of the header, immediately left of the status pill
    assert re.search(r'<div class="topbar-right">\s*<button class="btn topbar-scan" id="btn-full-scan" type="button"><span data-icon="report"></span>'
                     r'<span class="scan-label" id="full-scan-label">Full Scan</span></button>\s*<div class="status-pill', html)
    tiles = re.findall(r'<a class="tile" data-view="([a-z]+)"', html)
    assert len(tiles) == 8 and tiles[-1] == "reports"
    assert '<a class="tile" data-view="reports" href="#reports" style="--accent: var(--grey)">' in html
    assert '<span class="tile-icon" data-icon="report"></span><span class="tile-title">Reports</span>' in html
    assert html.index("js/reportsui.js") < html.index("js/views/ipinfo.js") and html.index("js/views/reports.js") < html.index("js/app.js")
    css = _read("css/tnt.css")
    base = _css_base(css)
    root = re.search(r":root\s*\{(.*?)\}", css, re.S).group(1)
    dark = re.search(r'\[data-theme="dark"\]\s*\{(.*?)\}', css, re.S).group(1)
    assert "--grey: var(--ink-soft)" in root and "--ink-soft: #B8B0CC" in dark        # the grey accent follows the theme
    assert _css_decls(base, ".topbar-right > .btn").get("flex") == "none"               # Full Scan never shrinks; the pill does
    scan = _css_decls(base, ".topbar-scan")
    assert scan.get("min-width") == "132px" and scan.get("font-variant-numeric") == "tabular-nums"
    assert "var(--pct)" in _css_decls(base, ".topbar-scan.running").get("background", "")
    app = _read("js/app.js")
    for s in ("reports: 'var(--grey)'", "tileEls.reports", "RU.createFullScan({ api, survey: TNT.wifiSurvey || null, live: () => api.events.state === 'live' })",
              "$('#btn-full-scan').addEventListener('click', fullScanClick)", "fullScan.subscribe(onFullScanJob)",
              "ev.on('report.progress', (d) => { if (d && d.job) fullScan.apply(d.job); })", "ev.on('report.saved'", "ev.on('report.deleted', scheduleReportsInfo)",
              "ev.on('report.updated', (d) => { scheduleReportsInfo(); if (d && fullScan.job && fullScan.job.report_id === d.id) fullScan.refresh(); })","ev.on('hello', () => { fullScan.refresh(); scheduleReportsInfo(); })",
              "report: '<svg", "swap: '<svg", "RU.siteCombo(", "'Save name'", "'Cancel scan'", "onEscape: () => combo.isOpen()",
              "api.renameReport(job.report_id, site)", "tileNav = true;", "Full Scan saves the first one", "RU.jobButton(job).label",
              # a network scanned before: the modal starts with that report's site, selected, and follows a late or changed suggestion
              "RU.suggestedSite(job)", "(job && job.site) || (suggested ? suggested.site : '')", "describedBy: 'site-modal-hint'",
              "RU.suggestionHint(j, ", "combo.input.select();", "if (siteModal && job) siteModal.sync(job);", "combo.touched()", "siteModal = { m, combo, sync };"):
        assert s in app, s
    # the controller lives at app.js module scope, never in the view: leaving the page never breaks a scan
    assert "createFullScan" not in _read("js/views/reports.js")
    # renderTiles never fetches: the tile reads counts cached by loadReportsInfo
    tiles_src = app[app.index("function renderTiles()"):app.index("/* ============================================================== router */")]
    assert "api.report" not in tiles_src and "loadReportsInfo(" not in tiles_src
    # Escape closes the modal on top only, and a field inside may keep the key (an open suggestion list)
    assert "modalStack[modalStack.length - 1] !== ctl" in app and "if (opts.onEscape && opts.onEscape(e)) return;" in app
    api = _read("js/api.js")
    assert "patch: (path, body, opts) => request('PATCH', path, body === undefined ? {} : body, opts)" in api
    for fn, path in (("reports", "api.get('/reports' + "), ("reportSites", "'/reports/sites?q='"), ("report", "api.get('/reports/' + encodeURIComponent(id), { timeout: 30000 })"),
                     ("renameReport", "api.patch('/reports/'"), ("deleteReport", "api.del('/reports/'"), ("reportPdf", "'/pdf', { blob: true, timeout: 120000 }"),
                     ("fullScanStart", "api.post('/reports/scan'"), ("fullScanJob", "api.get('/reports/scan')"), ("fullScanName", "api.patch('/reports/scan'"),
                     ("fullScanCancel", "api.del('/reports/scan')"), ("fullScanWifi", "api.post('/reports/scan/wifi'"), ("compareReports", "'/reports/compare?a='"),
                     ("comparePdf", "'/reports/compare/pdf?a='"), ("networkCurrent", "api.get('/networks/current')")):
        assert fn + ":" in api and path in api, fn
    assert "'report.progress', 'report.saved', 'report.deleted', 'report.updated'," in api
    # a stray '%' in a file name no longer throws out of a PDF download
    assert "try { filename = decodeURIComponent(filename); } catch (e)" in api


def test_reports_view_markup_and_compact_theme():
    src = _read("js/views/reports.js")
    ui = _read("js/reportsui.js")
    assert re.search(r"TNT\.views\.reports\s*=\s*\{", src)
    for s in ("TNT.app.fullScan.subscribe(onJob)", "TNT.app.fullScanClick()", "TNT.app.nameFullScan(site)", "TNT.app.fullScan.cancel()",
              "TNT.api.reportPdf(", "TNT.api.comparePdf(", "TNT.api.renameReport(", "TNT.api.deleteReport(", "TNT.api.compareReports(", "TNT.ui.confirm(",
              "TNT.app.saveBlob(", "U.compareCell(row)", "U.keyNumbers(rep.summary, data)", "'A − B'", "localStorage.setItem(COMPARE_B_STORE",
              "'Export comparison PDF'", "'Export PDF'", "'Rename'", "'Delete'", "'Current scan · '", "'Search site or date'", "'Search sites'",
              "No reports yet", "'Not collected: '", "for (const u of unsubs)", "destroyTables()", "role: 'progressbar'", "role: 'status'",
              "'aria-expanded'", "reveal() {", "history.replaceState(null, '', id == null ? '#reports' : '#reports?id=' + id)",
              # the outage labels agree (network outages, network down, the longest network outage), incidents named like the ping table
              "'Network down'", "'Longest network outage'", "'Single-target outages'", "U.outageWhat(o)", "U.coverageText(data, when)",
              # a report of the site's network: the router that identifies it and the visits its pings and outages come from
              "U.networkIdentity(data && data.meta ? data.meta.network : null)", "['Router', router]", "['Visits', visitsEl]",
              "U.untaggedText(data && data.ping, when)", "class: 'muted rpt-visits-more'", "class: 'rpt-note rpt-untagged'",
              "siteNet ? win.text : U.windowText(data.outages).text", "class: 'rpt-note rpt-net-note'", "els.cmpNotes", "Array.isArray(data.notes)",
              # what a new report left out of its ping and outage sections: a note line, also above a section without data
              "leftOutNote(ping)", "leftOutNote(out)", "class: 'rpt-note rpt-left-out'", "key === 'ping' || key === 'outages' ? leftOutNote(",
              # B follows A until it is picked; older reports reachable by search and "Show older"; failures retry
              "cmp.bPicked = !!cmp.b", "if (!cmp.bPicked && listsLoaded)", "scheduleCompareSearch()", "scheduleSiteSearch()", "'Show older ('",
              "errorBox('Could not load the reports: ' + listsError)", "RETRY_MS[Math.min(retries++, RETRY_MS.length - 1)]", "setHash(null)",
              # the progress card: one name field on screen, the name filled in and selected, a stopped bar keeps its percentage
              "TNT.app.siteModalOpen()", "pr.combo.setValue(RU().jobSite(job).site || '')", "pr.combo.input.select()", "'Name it'",
              # a suggested site: "Will be saved as <site> (this network was scanned before) · Change", no name field until Change
              "U.jobSite(job)", "'Will be saved as '", "' (this network was scanned before)'", "named.suggested ? 'Change' : 'Change name'",
              "running && (!named.site || nameOpen) && !modalOpen",
              # "Change" is named for what it changes, the name field is described by the site line, a suggestion is announced once
              "'aria-label': 'Change site name'", "describedBy: 'rpt-prog-site'", "'Full scan running, will be saved as '",
              "String(saved ? 100 : pct)", "'aria-valuetext'", "RU().jobButton(job).label", "U.jobWindowText(job, shortWhen)", "U.oneSided(rows)",
              "h('h3', { class: 'card-title' }, 'Saved reports'", "h('h3', { class: 'card-title' }, TNT.ui.icon('swap'), 'Compare'",
              "combo.input.select()"):
        assert s in src, s
    app = _read("js/app.js")
    # a danger confirm opens on its safe button; the modal takes a data-autofocus control first
    assert "card.querySelector('[data-autofocus]') ||" in app and "'data-autofocus': opts.danger ? '' : null" in app
    # a status snapshot's job reaches the controller (no event stream); a full scan's own tests make no toasts over its card
    for s in ("adoptStatusJob(st.reports && st.reports.job)", "if (r && !fullScan.running()) toast(", "if (fullScan.running()) {",
              "siteModalOpen: () => !!siteModal", "siteModalChanged();",
              # the first sentence follows the window's rule; a hotspot or travel router can be marked so nothing is suggested for it
              "intro.textContent = RU.modalIntro(j);", "api.setNetworkPortable(j.network_id, want)", "portableRow.hidden = !net;", "renderJob(j);"):
        assert s in app, s
    # a report is history: no "add as ping target" button, no port link that opens a browser or ssh, no classification now
    for s in ("addTargetButton", "portLink", "defaultCell", "classifyDevice", "openExternal"):
        assert s not in src, s
    # both files load before app.js: TNT.util / TNT.ui only inside functions
    for rel in ("js/reportsui.js", "js/views/reports.js"):
        top_level = [ln for ln in _read(rel).splitlines() if re.match(r"^  (const|let|var) ", ln)]
        assert not any(("TNT.util." in ln or "TNT.ui." in ln) and "=>" not in ln for ln in top_level), (rel, top_level)
    # the site name field: an ARIA combobox and listbox; options picked on mousedown so the input keeps the focus; stale answers dropped
    for s in ("role: 'combobox'", "'aria-autocomplete': 'list'", "'aria-expanded': 'false'", "'aria-controls': id + '-list'", "'aria-activedescendant'",
              "role: 'listbox'", "role: 'option'", "li.addEventListener('mousedown'", "e.key === 'ArrowDown'", "e.key === 'Escape'", "e.key === 'Enter'",
              "if (destroyed || mine !== seq) return;",
              # a hint linked to the field; until the user types, the page's text (a suggested site) lists the recent sites, not its matches
              "'aria-describedby': opts.describedBy || null", "load(typed ? input.value : '', true)", "touched: () => typed", "typed = false;"):
        assert s in ui, s
    assert "TNT.reportsui = {" in ui and "TNT.api." not in ui      # the controller gets its api injected (node tests)
    css = _read("css/tnt.css")
    base = _css_base(css)
    rpt = _css_decls(base, ".rpt")
    assert rpt.get("--shadow") == "transparent" and rpt.get("font-size") == "13px" and rpt.get("--radius") == "8px" and rpt.get("line-height") == "1.35"
    btn = _css_decls(base, ".rpt .btn")
    assert btn.get("height") == "28px" and btn.get("border-width") == "1px" and btn.get("box-shadow") == "none" and btn.get("font-size") == "12.5px"
    assert _css_decls(base, ".rpt .btn:hover").get("transform") == "none" and _css_decls(base, ".rpt .btn:active").get("transform") == "none"
    card = _css_decls(base, ".rpt .card")
    assert card.get("border") == "1px solid var(--rpt-line)" and card.get("box-shadow") == "none" and card.get("padding") == "10px 12px"
    assert _css_decls(base, ".rpt .table td").get("padding") == "3px 8px" and _css_decls(base, ".rpt .table-wrap").get("border") == "1px solid var(--rpt-line)"
    assert _css_decls(base, ".rpt .btn-primary") == {"background": "var(--ink)", "border-color": "var(--ink)", "color": "var(--paper)"}
    assert _css_decls(base, ".site-combo-list").get("overflow-y") == "auto" and "position" not in _css_decls(base, ".site-combo-list")
    narrow = _css_media(css, "(max-width: 1100px)")
    assert _css_decls(narrow, ".rpt-layout") == {"grid-template-columns": "minmax(0, 1fr)"}
    # one column: the saved reports come up under the heading's search box, in a short scroller; B's search gets its own row
    assert _css_decls(narrow, ".rpt-browser").get("order") == "-1" and _css_decls(narrow, ".rpt-browser-body").get("max-height") == "40vh"
    assert _css_decls(narrow, ".rpt-cmp-bpick .rpt-cmp-filter").get("flex") == "1 1 100%"
    # the comparison tables flow in columns, so a short one does not leave a gap as tall as its neighbour
    assert _css_decls(base, ".rpt-cmp-grid").get("columns") == "420px 3" and _css_decls(base, ".rpt-cmp-sec").get("break-inside") == "avoid"
    section = css[css.index("site name field with suggestions (js/reportsui.js siteCombo)"):]
    assert not re.search(r"#[0-9A-Fa-f]{3,6}\b", section), "hard-coded colour in the Reports CSS"
    assert "grid-column" not in css and ":has(" not in css and "@container" not in css


def test_reports_are_in_the_docs():
    readme = (ROOT / "README.txt").read_text(encoding="utf-8")
    assert "Reports" in readme and "Full Scan" in readme
    docs = _doc("docs/DESIGN.md")
    for s in ("Full Scan", "Reports", "compact", "--shadow: transparent", "Compare", "Name this site", "combobox", "WiFi, Tools, Reports", "report (a clipboard",
              "Will be saved as", "This network was scanned as", "identified by gateway and subnet", "last 7 days on this network, 2 visits"):
        assert s in docs, s


_NODE_REPORTS_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const window = { TNT: { views: {}, util: {}, api: {}, ui: {} } };
const ctx = vm.createContext({ window, console, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'reportsui.js' });
const R = window.TNT.reportsui;
const out = {};
out.norm = [R.normalizeSite('  Acme   Dental \t'), R.normalizeSite(null), R.normalizeSite('x'.repeat(100)).length, R.normalizeSite('  ' + 'y'.repeat(79) + '   z'),
  R.siteKey('  ACME   Dental ')];
const sites = [
  { site: 'Northside Warehouse', site_key: 'northside warehouse', count: 1, last_ts: 300 },
  { site: 'Acme Dental', site_key: 'acme dental', count: 2, last_ts: 500 },
  { site: 'Dental Arts Studio', site_key: 'dental arts studio', count: 1, last_ts: 100 },
  { site: 'Maple Street Office', site_key: 'maple street office', count: 1, last_ts: 50 },
  { site: 'ACME DENTAL', site_key: 'acme dental', count: 9, last_ts: 1 },
  { site: 'Harbor-Dental Group', site_key: 'harbor-dental group', count: 1, last_ts: 900 },
  null, { site: '' },
];
const names = (list) => list.map((s) => s.site);
out.rank = { den: names(R.rankSuggestions(sites, 'den')), dent: names(R.rankSuggestions(sites, ' DENT ', 2)), none: names(R.rankSuggestions(sites, '')),
  miss: names(R.rankSuggestions(sites, 'zzz')), street: names(R.rankSuggestions(sites, 'street')), junk: R.rankSuggestions(null, 'a') };
out.parts = [R.matchParts('Harbor-Dental Group', 'dental'), R.matchParts('Acme', 'x'), R.matchParts('Acme', '')];
out.fmt = [R.fmtValue(118.44, 'Mbps'), R.fmtValue(42.46, 'Mbps'), R.fmtValue(4.13, 'ms'), R.fmtValue(38, 'ms'), R.fmtValue(0, '%'), R.fmtValue(0.04, '%'),
  R.fmtValue(1.234, '%'), R.fmtValue(12.6, '%'), R.fmtValue(-52.4, 'dBm'), R.fmtValue(24, ''), R.fmtValue(0.43, 'per day'), R.fmtValue(10.91, 'per day'),
  R.fmtValue(125, 's'), R.fmtValue(null, 'ms'), R.fmtValue(NaN, 'Mbps'), R.fmtValue(3, 'min/day'), R.fmtValue(0.55, 'ms'), R.fmtValue(612.5, 'ms'),
  R.fmtValue(-81.5, 'dBm'), R.fmtValue(-80.5, 'dBm'), R.fmtValue(1, 'devices'), R.fmtValue(2, 'networks'), R.fmtValue(1, 'APs'), R.fmtValue(1, 'outages'),
  R.fmtValue(0, 'per day'), R.fmtValue(0.75, 'min')];
out.plural = [R.plural(1, 'AP'), R.plural(3, 'speed test'), R.plural(null, 'site')];
out.bps = [R.bpsText(1e9), R.bpsText(2.5e9), R.bpsText(866e6), R.bpsText(null), R.bpsText(0)];
out.durations = [R.durationText(42), R.durationText(3725), R.durationText(93600), R.durationText(null)];
out.cells = [
  R.compareCell({ unit: 'Mbps', a: 118.4, b: 941.2, better: 'b', higher_is_better: true, delta: -822.8 }),
  R.compareCell({ unit: 'ms', a: 11.8, b: 14.2, better: 'a', higher_is_better: false, delta: 2.4 }),
  R.compareCell({ unit: '', a: 25, b: 14, better: null, higher_is_better: null }),
  R.compareCell({ unit: 'dBm', a: null, b: -47, better: null, higher_is_better: true }),
  R.compareCell({ unit: '%', a: 0, b: 0, better: 'same', higher_is_better: false }),
  R.compareCell({ unit: 'ms', a: 12.2, b: 12, better: 'same', higher_is_better: false }),
  R.compareCell({ unit: 'dBm', a: -67, b: -79, better: 'a', higher_is_better: true }),
  R.compareCell({ unit: 'per day', a: 0.43, b: 0, better: 'b', higher_is_better: false }),
  R.compareCell(null),
  R.compareCell({ unit: '%', a: 2.42, b: 0, better: 'b', higher_is_better: false }),
  R.compareCell({ unit: 'ms', a: 719.8, b: 1.0, better: 'b', higher_is_better: false }),
  R.compareCell({ unit: 'ms', a: 1.5, b: 0.5, better: 'same', higher_is_better: false }),
  R.compareCell({ unit: '%', a: 0.004, b: 0.002, better: 'same', higher_is_better: false }),
  R.compareCell({ unit: 'APs', a: 1, b: 3, better: 'a', higher_is_better: false }),
];
out.oneSided = [R.oneSided([{ a: null, b: -48 }, { a: null, b: 3 }]), R.oneSided([{ a: 1, b: null }, { a: null, b: 2 }]), R.oneSided([{ a: 1, b: 2 }]), R.oneSided([])];
out.monitored = [R.monitoredText({ window_start: 0, window_end: 224640, monitored_s: 195840 }), R.monitoredText({ window_start: 0, window_end: 3600, monitored_s: 3600 }),
  R.monitoredText({ available: false }), R.monitoredText(null)];
out.jobWindow = ['network_change', 'seven_days', 'data_start', 'site_network'].map((reason) => R.jobWindowText({ window_start: 100, window_reason: reason }, (ts) => 'day' + ts))
  .concat([R.jobWindowText({ window_start: null }), R.jobWindowText(null)]);
out.what = [R.outageWhat({ kind: 'total_internet', targets: ['Public DNS (198.51.100.1)', 'example.net'] }), R.outageWhat({ kind: 'total_local', targets: [] }),
  R.outageWhat({ kind: 'gap', note: 'not monitoring' }), R.outageWhat({ kind: 'target', name: 'NVR (172.16.40.20)', host: '172.16.40.20' }), R.outageWhat({ kind: 'target', host: 'x' })];
const rep = { data: { speed: { available: false, reason: 'rate limited' }, ping: { available: true }, wifi: { available: false } } };
out.sections = [R.sectionState(rep, 'speed'), R.sectionState(rep, 'ping'), R.sectionState(rep, 'wifi'), R.sectionState(rep, 'discovery'), R.sectionState(null, 'network')];
out.windows = [R.windowText({ window_start: 0, window_end: 604800, window_reason: 'seven_days' }).text,
  R.windowText({ window_start: 1000, window_end: 1000 + 26 * 3600, window_reason: 'network_change' }).text,
  R.windowText({ window_start: 0, window_end: 2520, window_reason: 'data_start' }).text, R.windowText({}).text, R.windowText(null).text];
out.kpis = R.keyNumbers({ download_mbps: 118.4, upload_mbps: 31.2, latency_ms: 14.2, gateway_avg_ms: 1.8, gateway_loss_pct: 0.4, internet_avg_ms: 38,
  internet_loss_pct: 6.2, outages: 3, downtime_s: 725, hosts: 24, wifi_aps: 23, wifi_networks: 13, wifi_connected_rssi: -67 }).map((k) => [k.key, k.value, k.sub, k.level]);
out.kpisEmpty = R.keyNumbers(null).map((k) => k.value);
out.kpisLevels = R.keyNumbers({ download_mbps: 18.4, upload_mbps: 4.2, wifi_aps: 40, wifi_connected_rssi: -78 }, { wifi: { available: true, connected: { channel_aps: 8 } } })
  .filter((k) => k.level || k.key === 'wifi').map((k) => [k.key, k.sub, k.level]);
out.lines = [R.summaryLine({ download_mbps: 118.4, upload_mbps: 31.2, latency_ms: 14.2, hosts: 1, wifi_aps: 23 }), R.summaryLine({})];
const reps = [
  { id: 2, site: 'Acme Dental', created_ts: 200, status: 'complete' }, { id: 5, site: 'Acme Dental', created_ts: 500, status: 'partial' },
  { id: 1, site: 'Maple Street Office', created_ts: 100, status: 'complete' }, { id: 3, site: 'Northside Warehouse', created_ts: 300, status: 'complete' },
];
const label = (ts) => 'day' + ts;
out.options = R.reportOptions(reps, '', label).map((g) => [g.site, g.items.map((i) => [i.id, i.label])]);
out.optionsQ = R.reportOptions(reps, 'ACME', label).map((g) => g.items.map((i) => i.id));
out.optionsDate = R.reportOptions(reps, 'day3', label).map((g) => g.site);
out.defaultB = [R.defaultCompareB(reps, 5, '1'), R.defaultCompareB(reps, 5, '5'), R.defaultCompareB(reps, 5, '99'), R.defaultCompareB(reps, 2, null),
  R.defaultCompareB(reps, 3, null), R.defaultCompareB([], 1, null)];
out.buttons = [R.jobButton(null), R.jobButton({ status: 'saved' }), R.jobButton({ status: 'running', phase: 'wifi', pct: 63.6, site: 'Acme Dental' }),
  R.jobButton({ status: 'running', phase: 'finalize', pct: 140 }),
  R.jobButton({ status: 'running', phase: 'finalize', pct: 91, phases: [{ key: 'wifi', status: 'done' }, { key: 'history', status: 'running' }] }),
  R.jobButton({ status: 'running', phase: 'finalize', pct: 97, phases: [{ key: 'history', status: 'done' }, { key: 'save', status: 'running' }] })]
  .map((b) => [b.running, b.label, b.phase, b.pct]);
out.phases = R.jobPhases({ phases: [{ key: 'wifi', status: 'running', message: 'Waiting', started_ts: 5 }, { key: 'speed', status: 'done', started_ts: 1, finished_ts: 3 }] })
  .map((p) => [p.key, p.status, p.message, p.started_ts, p.finished_ts]);
const aps = [
  { bssid: '02:00:5E:00:00:01', ssid: 'Harbor Lab', hidden: false, rssi: -61, quality: 78, band: '5', channel: 36, center_channel: 42, width_mhz: 80, freq_mhz: 5180,
    spans: [[5170, 5250]], phy: 'ax', phys: ['ac', 'ax'], generation: 'Wi-Fi 6', security: 'WPA2-Personal', max_rate_mbps: 1200, oui: '02:00:5E',
    locally_administered: true, base_oui: '00:00:5E', connected: true, first_seen: 1, last_seen: 2, seen_count: 9, stale: false },
  { bssid: '02:00:5E:00:00:02', ssid: '', hidden: true, rssi: -48, band: '2.4', channel: 6, width_mhz: 20, stale: false },
  { bssid: '02:00:5E:00:00:03', ssid: 'Gone Cafe', rssi: -40, band: '2.4', channel: 1, stale: true },
  { ssid: 'no bssid', rssi: -30 }, null,
];
const survey = { state: 'ok', error: null, last_read_ts: 1234.5, aps, history: { '02:00:5E:00:00:01': [[1, -60]] },
  interfaces: [{ guid: 'g', description: 'Synthetic Wi-Fi', state: 'connected', connected_bssid: '02:00:5E:00:00:01', connected_ssid: 'Harbor Lab', extra: 1 }] };
const p = R.wifiPayload(survey, 99);
out.payload = { keys: Object.keys(p).sort(), available: p.available, state: p.state, error: p.error, collected: p.collected_ts, bssids: p.aps.map((a) => a.bssid),
  apKeys: Object.keys(p.aps[1]).sort(), ifaceKeys: Object.keys(p.interfaces[0]).sort() };
const many = Array.from({ length: 1200 }, (_, i) => ({ bssid: '02:00:00:00:' + ('0' + (i >> 8).toString(16)).slice(-2) + ':' + ('0' + (i & 255).toString(16)).slice(-2), rssi: -30 - (i % 70), stale: false }));
out.payloadCap = R.wifiPayload({ state: 'ok', last_read_ts: 5, aps: many }, 1).aps.length;
out.payloadDenied = R.wifiPayload({ state: 'location_denied', error: 'Location access is off', aps }, 7);
const ok = (ts) => ({ state: 'ok', last_read_ts: ts, aps: [], interfaces: [] });
const d = (s, el, err) => { const v = R.wifiDecision(s, 100, el, 1000, 555, err); return v.action === 'wait' ? 'wait' : [v.body.available, v.body.state, v.body.error, v.body.collected_ts]; };
out.decisions = [d(null, 10), d(null, 1000, 'the TNT window is not answering'), d(ok(90), 10), d(ok(101), 10), d(ok(90), 1000), d({ state: 'starting' }, 10),
  d({ state: 'starting' }, 1000), d({ state: 'location_denied', error: 'Location access is off' }, 10), d({ state: 'disabled', error: 'The Wi-Fi survey is switched off.' }, 10),
  d({ state: 'weird' }, 10)];
out.names = [R.reportFilename('Acme (Main) Dental/2', 1757462400), R.reportFilename('', 1757462400), R.compareFilename('Acme Dental', 'Maple Street Office'), R.compareFilename(null, '***')];
// a report of the site's network: the window, its visits and what the meta line says; how the network was identified
out.siteWindows = [R.windowText({ window_start: 0, window_end: 604800, window_reason: 'site_network' }).text,
  R.windowText({ window_start: 0, window_end: 3 * 86400, window_reason: 'site_network' }).text, R.windowText({ window_reason: 'site_network' }).text];
const at = (ts) => 't' + ts;
out.visits = [R.visitsText({ visits: [{ start: 5000, end: 9000 }, { start: 100, end: 3700 }], monitored_s: 7600 }, at), R.visitsText({ visits: [] }),
  R.visitsText({}), R.visitsText(null), R.visitsText({ visits: [{ start: 10, end: 5 }, null] }), R.visitsText({ visits: [{ start: 0, end: 5400 }] }, at).text];
out.coverage = [
  R.coverageText({ ping: { window_start: 0, window_end: 604800, window_reason: 'site_network', visits: [{ start: 100, end: 3700 }, { start: 5000, end: 118600 }], monitored_s: 117200 } }, at),
  R.coverageText({ ping: { available: true, window_start: 0, window_end: 224640, window_reason: 'network_change' }, outages: { window_start: 0, window_end: 224640, monitored_s: 195840 } }),
  R.coverageText({ ping: { available: false, window_start: 0, window_end: 604800, window_reason: 'site_network', visits: [] }, outages: { window_start: 0, window_end: 604800, monitored_s: 0 } }),
  R.coverageText({ ping: { available: false }, outages: { window_start: 0, window_end: 3600, monitored_s: 3600 } }), R.coverageText(null)];
out.identity = [R.networkIdentity({ id: 2, mac: 'C2:FF:EE:0A:00:FB', vendor: 'Contoso Access Systems', gateway_ip: '10.0.0.251', subnet: '10.0.0.0/24', dhcp_server: '10.0.0.251', identity: 'mac' }),
  R.networkIdentity({ id: 4, mac: null, vendor: null, gateway_ip: '10.44.0.1', subnet: '10.44.0.0/24', dhcp_server: null, identity: 'fingerprint' }),
  R.networkIdentity({ id: null, identity: 'unknown' }), R.networkIdentity(null), R.networkIdentity({ identity: 'mac', mac: null }), R.networkIdentity({ identity: 'weird' }),
  R.networkIdentity({ id: 5, mac: '00:00:5E:00:53:0A', vendor: 'ICANN, IANA Department', gateway_ip: '172.20.10.1', subnet: '172.20.10.0/28', identity: 'mac', portable: true }),
  R.networkIdentity({ id: 6, mac: null, gateway_ip: '192.168.1.1', subnet: '192.168.1.0/24', identity: 'fingerprint', virtual_mac: '00:00:5E:00:01:01' })];
out.localMac = ['C2:FF:EE:0A:00:FB', '00:00:5E:00:53:0A', '02-00-5E-10-00-01', 'junk', null].map((m) => R.localMac(m));
out.untagged = [R.untaggedText({ untagged_since: 100 }, (ts) => 'day' + ts), R.untaggedText({ untagged_since: null }), R.untaggedText(null)];
out.intro = [R.modalIntro({ window_reason: 'site_network' }), R.modalIntro({ window_reason: 'network_change' }), R.modalIntro(null)];
// a network scanned before: the job's suggested site, the site its report goes under, the name modal's hint
const sjob = { status: 'running', site: null, suggested_site: { site: '  Acme   Dental ', report_id: 5, created_ts: 1000 } };
out.suggest = [R.suggestedSite(sjob), R.suggestedSite({ suggested_site: { site: '  ' } }), R.suggestedSite(null),
  R.jobSite(sjob), R.jobSite(Object.assign({}, sjob, { site: 'Harbor View' })), R.jobSite(Object.assign({}, sjob, { status: 'saved' })),
  R.jobSite(Object.assign({}, sjob, { status: 'cancelled' })), R.jobSite({ status: 'running' }), R.jobSite(null),
  R.suggestionHint(sjob, (ts) => 'day' + ts), R.suggestionHint({ suggested_site: { site: 'X' } }), R.suggestionHint({ status: 'running' }), R.jobButton(sjob).title,
  R.suggestionHint(Object.assign({}, sjob, { network: { id: 5, mac: '00:00:5E:00:53:0A', vendor: 'Example Networks', gateway_ip: '172.20.10.1', identity: 'mac' } }), (ts) => 'day' + ts),
  R.suggestionHint(Object.assign({}, sjob, { network: { id: 6, mac: null, gateway_ip: '192.168.1.1', identity: 'fingerprint', virtual_mac: '00:00:5E:00:01:01' } }))];
process.stdout.write(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_reports_helpers_with_node(tmp_path):
    driver = tmp_path / "driver.js"
    driver.write_text(_NODE_REPORTS_DRIVER, encoding="utf-8")
    r = subprocess.run(["node", str(driver), str(UI / "js/reportsui.js")], capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    # site names: trimmed, whitespace collapsed, 80 characters at most; the page's key is the lower-cased name
    assert out["norm"] == ["Acme Dental", "", 80, "y" * 79, "acme dental"]
    # suggestions: a name starting with the text, then a word starting with it, then any match; the most recent first; one row per key
    rk = out["rank"]
    assert rk["den"] == ["Dental Arts Studio", "Harbor-Dental Group", "Acme Dental"]
    assert rk["dent"] == ["Dental Arts Studio", "Harbor-Dental Group"]
    assert rk["none"] == ["Harbor-Dental Group", "Acme Dental", "Northside Warehouse", "Dental Arts Studio", "Maple Street Office"]
    assert rk["miss"] == [] and rk["street"] == ["Maple Street Office"] and rk["junk"] == []
    assert out["parts"] == [["Harbor-", "Dental", " Group"], ["Acme", "", ""], ["Acme", "", ""]]
    # the PDFs' precision (tnt/report_pdf.py): ms to a tenth below 100, loss to a hundredth below 10 %, dBm half away from zero, singular counts
    assert out["fmt"] == ["118 Mbps", "42.5 Mbps", "4.1 ms", "38.0 ms", "0%", "0.04%", "1.23%", "12.6%", "−52 dBm", "24", "0.43/day", "10.9/day",
                          "2m 05s", "—", "—", "3.0 min/day", "0.55 ms", "613 ms", "−82 dBm", "−81 dBm", "1 device", "2 networks", "1 AP", "1 outage",
                          "0/day", "0.8 min"]
    assert out["plural"] == ["1 AP", "3 speed tests", "0 sites"]
    assert out["bps"] == ["1 Gbps", "2.5 Gbps", "866 Mbps", "—", "—"] and out["durations"] == ["42 s", "1h 02m", "1d 2h", "—"]
    # compare cells: A − B from the two values (whatever the sign of the row's delta), the change relative to B, colours by `better`
    cols = ("a", "b", "diff", "arrow", "aCls", "bCls", "diffCls", "verdict")
    cells = [tuple(c[k] for k in cols) for c in out["cells"]]
    assert cells == [
        ("118 Mbps", "941 Mbps", "−823 Mbps (−87%)", "▼", "worse", "better", "worse", "B is better"),
        ("11.8 ms", "14.2 ms", "−2.4 ms (−17%)", "▼", "better", "worse", "better", "A is better"),
        ("25", "14", "+11 (+79%)", "▲", "", "", "info", ""),
        ("—", "−47 dBm", "—", "", "", "", "", ""),
        ("0%", "0%", "same", "=", "", "", "same", "about the same"),
        ("12.2 ms", "12.0 ms", "+0.20 ms", "≈", "", "", "same", "about the same"),         # no percentage beside "about the same"
        ("−67 dBm", "−79 dBm", "+12 dB", "▲", "better", "worse", "better", "A is better"),
        ("0.43/day", "0/day", "+0.43/day", "▲", "worse", "better", "worse", "B is better"),
        ("—", "—", "—", "", "", "", "", ""),
        ("2.42%", "0%", "+2.42 pts", "▲", "worse", "better", "worse", "B is better"),       # loss moves in percentage points
        ("720 ms", "1.0 ms", "+719 ms (×720)", "▲", "worse", "better", "worse", "B is better"),   # a ratio, never "+71880%"
        ("1.5 ms", "0.50 ms", "+1.0 ms", "≈", "", "", "same", "about the same"),
        ("0.00%", "0.00%", "≈ 0", "≈", "", "", "same", "about the same"),
        ("1 AP", "3 APs", "−2 (−67%)", "▼", "better", "worse", "better", "A is better"),
    ]
    assert out["oneSided"] == ["b", None, None, None]
    assert out["monitored"] == ["monitored 2d 6h (8h 00m not monitoring)", "", "", ""]
    assert out["jobWindow"] == ["since day100, when this PC joined this network", "over the last 7 days, since day100",
                                "since day100, when its ping data begins", "on this network since day100, earlier visits included", "", ""]
    assert out["what"] == ["Internet down: Public DNS (198.51.100.1), example.net", "Local network down", "Not monitoring", "NVR (172.16.40.20)", "x"]
    assert out["sections"] == [{"key": "speed", "title": "Speed test", "available": False, "reason": "rate limited"},
                               {"key": "ping", "title": "Ping", "available": True, "reason": None},
                               {"key": "wifi", "title": "Wi-Fi", "available": False, "reason": "Not collected"},
                               {"key": "discovery", "title": "Discovery", "available": False, "reason": "Not in this report"},
                               {"key": "network", "title": "Network", "available": False, "reason": "Not in this report"}]
    assert out["windows"] == ["last 7 days", "last 1d 2h (since this PC joined the network)", "last 42m 00s (all the data there was)", "—", "—"]
    assert out["kpis"] == [["download", "118 Mbps", "", ""], ["upload", "31.2 Mbps", "", ""], ["latency", "14.2 ms", "", ""], ["gateway", "1.8 ms", "0.40% loss", ""],
                           ["internet", "38.0 ms", "6.20% loss", "bad"], ["outages", "3", "12m 05s network down", "warn"], ["devices", "24", "", ""],
                           ["wifi", "23", "13 networks · −67 dBm connected", ""]]
    assert out["kpisEmpty"] == ["—"] * 8
    # slow speed, a weak signal and a crowded channel are tinted too (the PDF strip uses the same thresholds)
    assert out["kpisLevels"] == [["download", "", "warn"], ["upload", "", "warn"], ["wifi", "−78 dBm connected · 8 on its channel", "bad"]]
    assert out["lines"] == ["↓ 118 ↑ 31.2 Mbps · 14.2 ms · 1 device · 23 APs", "No numbers"]
    assert out["options"] == [["Acme Dental", [[5, "day500 · partial"], [2, "day200"]]], ["Northside Warehouse", [[3, "day300"]]],
                              ["Maple Street Office", [[1, "day100"]]]]
    assert out["optionsQ"] == [[5, 2]] and out["optionsDate"] == ["Northside Warehouse"]
    # B: the one picked last time (a known good network), else the previous scan of A's site, else none
    assert out["defaultB"] == [1, 2, 2, None, None, None]
    # the finishing steps are named as the checklist shows them running
    assert out["buttons"] == [[False, "Full Scan", "", 0], [False, "Full Scan", "", 0], [True, "Wi-Fi 64%", "Wi-Fi", 64], [True, "Finishing 100%", "Finishing", 100],
                              [True, "History 91%", "History", 91], [True, "Saving 97%", "Saving", 97]]
    assert out["phases"] == [["speed", "done", "", 1, 3], ["discovery", "pending", "", None, None], ["wifi", "running", "Waiting", 5, None],
                             ["history", "pending", "", None, None], ["save", "pending", "", None, None]]
    # the Wi-Fi snapshot: in-range access points only, strongest first, the report's fields (no history, spans or stale flags), 1000 at most
    pl = out["payload"]
    assert pl["keys"] == ["aps", "available", "collected_ts", "error", "interfaces", "state"] and pl["available"] is True and pl["state"] == "ok"
    assert pl["error"] is None and pl["collected"] == 1234.5 and pl["bssids"] == ["02:00:5E:00:00:02", "02:00:5E:00:00:01"]
    assert pl["apKeys"] == ["band", "bssid", "center_channel", "channel", "connected", "first_seen", "freq_mhz", "generation", "hidden", "last_seen",
                            "max_rate_mbps", "phy", "quality", "rssi", "security", "ssid", "width_mhz"]
    assert pl["ifaceKeys"] == ["connected_bssid", "connected_ssid", "description", "guid", "state"]
    assert out["payloadCap"] == 1000
    assert out["payloadDenied"] == {"available": False, "state": "location_denied", "error": "Location access is off", "collected_ts": 7, "interfaces": [], "aps": []}
    assert out["decisions"] == ["wait", [False, "error", "the TNT window is not answering", 555], "wait", [True, "ok", None, 101], [True, "ok", None, 90], "wait",
                                [False, "starting", "The Wi-Fi survey was still starting", 555], [False, "location_denied", "Location access is off", 555],
                                [False, "disabled", "The Wi-Fi survey is switched off.", 555], [False, "weird", "The Wi-Fi survey is not available", 555]]
    stamp = time.strftime("%Y-%m-%d-%H%M", time.localtime(1757462400))
    assert out["names"] == [f"TNT-report-Acme-Main-Dental-2-{stamp}.pdf", f"TNT-report-site-{stamp}.pdf", "TNT-compare-Acme-Dental-vs-Maple-Street-Office.pdf",
                            "TNT-compare-site-vs-site.pdf"]
    # a report of the site's network: "last 7 days on this network", its visits (oldest first in the tooltip) and never "not monitoring"
    assert out["siteWindows"] == ["last 7 days on this network", "last 3d 0h on this network", "on this network"]
    assert out["visits"] == [{"text": "2 visits, 2h 06m monitored", "title": "t100 to t3700; t5000 to t9000"}, {"text": "nothing monitored", "title": ""},
                             {"text": "", "title": ""}, {"text": "", "title": ""}, {"text": "nothing monitored", "title": ""}, "1 visit, 1h 30m monitored"]
    cov = out["coverage"]
    assert cov[0]["text"] == "last 7 days on this network, 2 visits, 1d 8h monitored"
    assert cov[0]["title"].startswith("Only the pings and outages recorded on this site's network count") and cov[0]["title"].endswith(". Visits: t100 to t3700; t5000 to t118600")
    assert cov[1] == {"text": "last 2d 14h (since this PC joined the network), monitored 2d 6h (8h 00m not monitoring)",
                      "title": "Pings and outages since this PC joined the network it was on for the report, less than 7 days before it"}
    assert cov[2]["text"] == "last 7 days on this network, nothing monitored" and cov[3] == {"text": "last 1h 00m", "title": ""} and cov[4] == {"text": "—", "title": ""}
    ident = out["identity"]
    # a locally administered router MAC (0x02 set): its vendor is only a guess from the base OUI
    assert ident[0] == {"identity": "mac", "mac": "C2:FF:EE:0A:00:FB", "vendor": "likely Contoso Access Systems",
                        "text": "C2:FF:EE:0A:00:FB · likely Contoso Access Systems",
                        "title": "The site's network is the one behind this router (gateway 10.0.0.251, subnet 10.0.0.0/24, DHCP server 10.0.0.251). Its MAC is "
                                 "locally administered (a phone hotspot, a randomised or virtual interface), so the vendor is a guess from its base OUI",
                        "note": "", "portable": False}
    assert ident[1] == {"identity": "fingerprint", "mac": "", "vendor": "", "text": "identified by gateway and subnet",
                        "title": "The router's MAC could not be read, so the network is known by gateway 10.44.0.1, subnet 10.44.0.0/24", "note": "", "portable": False}
    assert ident[2]["identity"] == "unknown" and ident[2]["text"] == "" and \
        ident[2]["note"] == "The network was not identified when the scan started, so the pings and outages are read by time (the window above)."
    assert ident[3:6] == [None, None, None]
    # a universally administered MAC's vendor as registered; a portable network (a hotspot) says only its connection counts
    assert (ident[6]["vendor"], ident[6]["portable"]) == ("ICANN, IANA Department", True) and ident[6]["note"].startswith("This network is carried from site to site")
    assert ident[7]["text"] == "redundant gateway (virtual router MAC 00:00:5E:00:01:01), identified with its gateway and subnet"
    assert ident[7]["title"].startswith("Redundant routers answer from a virtual MAC") and ident[7]["note"] == ""
    assert out["localMac"] == [True, False, True, False, False]
    assert out["untagged"] == ["Pings recorded before this PC identified its networks count only from day100, when it joined this network.", "", ""]
    assert out["intro"][0] == ("A speed test, a Discovery scan and a Wi-Fi scan are running. The report adds the pings and outages recorded on this "
                               "network in the last 7 days. Which site is this?")
    assert "this PC's pings and outages since it joined this network, at most 7 days" in out["intro"][1] and out["intro"][2] == out["intro"][1]
    sg = out["suggest"]
    assert sg[:3] == [{"site": "Acme Dental", "report_id": 5, "created_ts": 1000}, None, None]
    assert sg[3:9] == [{"site": "Acme Dental", "suggested": True}, {"site": "Harbor View", "suggested": False}, {"site": "Acme Dental", "suggested": True},
                       {"site": None, "suggested": False}, {"site": None, "suggested": False}, {"site": None, "suggested": False}]
    assert sg[9] == ["This network was scanned as ", "Acme Dental", " on day1000. Save name to add this scan to its reports, or type another site."]
    assert sg[10] == ["This network was scanned as ", "X", " before. Save name to add this scan to its reports, or type another site."] and sg[11] is None
    assert sg[12] == "Full scan running: Scanning, 0 % done · Acme Dental. Click to open Reports."
    # the hint names the network, so a phone hotspot or a travel router brought from the last site is recognised
    assert sg[13] == ["This network (router 00:00:5E:00:53:0A · Example Networks, gateway 172.20.10.1) was scanned as ", "Acme Dental",
                      " on day1000. Save name to add this scan to its reports, or type another site."]
    assert sg[14][0] == "This network (virtual router 00:00:5E:00:01:01, gateway 192.168.1.1) was scanned as "


_NODE_FULL_SCAN_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const window = { TNT: { views: {}, util: {}, api: {}, ui: {} } };
const ctx = vm.createContext({ window, console, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'reportsui.js' });
const R = window.TNT.reportsui;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function waitFor(fn, ms) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(5); } return !!fn(); }
const nowS = () => Date.now() / 1000;
const job = (over) => Object.assign({ id: 'job-1', site: null, status: 'running', phase: 'speed', pct: 10, phases: [] }, over || {});
const T = { wifiPollMs: 5, wifiLimitMs: 150, bridgeWaitMs: 60, pollMs: 20, livePollMs: 5000 };
const APS = [
  { bssid: '02:00:5E:00:00:01', ssid: 'Harbor Lab', hidden: false, rssi: -61, band: '5', channel: 36, width_mhz: 80, connected: true, stale: false, spans: [[5170, 5250]] },
  { bssid: '02:00:5E:00:00:02', ssid: '', hidden: true, rssi: -48, band: '2.4', channel: 6, width_mhz: 20, stale: false },
  { bssid: '02:00:5E:00:00:03', ssid: 'Gone Cafe', hidden: false, rssi: -40, band: '2.4', channel: 1, stale: true },
];
function fakeApi(opts) {
  opts = opts || {};
  const api = { wifi: [], jobs: 0, current: null,
    fullScanWifi: (body) => { api.wifi.push(body); return opts.wifiFails ? Promise.reject(new Error('No full scan is waiting for a Wi-Fi scan')) : Promise.resolve({ job: api.current }); },
    fullScanJob: () => { api.jobs++; return Promise.resolve({ job: api.current }); },
    fullScanStart: (site) => (opts.busy ? Promise.reject(Object.assign(new Error('busy'), { status: 409, body: { job: opts.busy } })) : Promise.resolve({ job: job({ id: 'job-10', site }) })),
    fullScanName: (site) => Promise.resolve({ job: job({ site }) }),
    fullScanCancel: () => Promise.resolve({ job: job({ status: 'cancelled', phase: null }) }),
  };
  return api;
}
function fakeSurvey(kind) {
  const s = { calls: [], fetches: 0, error: null, opts: [], t0: Date.now(),
    bridgeState: () => (kind === 'waiting' ? (Date.now() - s.t0 < 30 ? 'waiting' : 'none') : kind === 'outdated' ? 'outdated' : 'ready'),
    call: (name) => { s.calls.push(name); return Promise.resolve({ ok: kind !== 'refused', error: kind === 'refused' ? 'A scan was just requested.' : null }); },
    fetch: (o) => {
      s.fetches++;
      s.opts.push(o);
      if (kind === 'broken') { s.error = 'the TNT window is not answering'; return Promise.resolve(null); }
      if (kind === 'denied') return Promise.resolve({ state: 'location_denied', error: 'Location access is off', aps: [], interfaces: [] });
      const fresh = (kind === 'fresh' || kind === 'refused') && s.fetches > 2;
      return Promise.resolve({ state: 'ok', error: null, last_read_ts: fresh ? nowS() + 0.001 : nowS() - 30, aps: APS, history: { x: [[1, -50]] },
        interfaces: [{ guid: 'g', description: 'Synthetic Wi-Fi', state: 'connected', connected_bssid: APS[0].bssid, connected_ssid: 'Harbor Lab' }] });
    } };
  return s;
}
async function wifiRun(survey, apiOpts) {
  const api = fakeApi(apiOpts);
  const c = R.createFullScan(Object.assign({ api, survey }, T));
  let notified = 0;
  c.subscribe(() => { notified++; });
  c.apply(job({ phase: 'speed' }));
  await sleep(15);
  const early = api.wifi.length;
  api.current = job({ phase: 'wifi', pct: 61 });
  // the phase announced over and over: by events, by a poll, by a later percentage
  c.apply(api.current); c.apply(api.current); c.apply(Object.assign({}, api.current, { pct: 62 }));
  await c.refresh();
  await waitFor(() => api.wifi.length > 0, 2000);
  await sleep(40);
  c.apply(api.current);
  await c.refresh();
  await sleep(20);
  c.stop();
  const b = api.wifi[0] || null;
  return { early, posts: api.wifi.length, entries: c.posts.map((e) => [e.job_id, e.ok, e.error]), notified: notified > 3,
    calls: survey ? survey.calls : null, opts: survey && survey.opts.length ? survey.opts[0] : null,
    body: b && { available: b.available, state: b.state, error: b.error, bssids: b.aps.map((a) => a.bssid), history: 'history' in b, keys: Object.keys(b).sort() } };
}
(async () => {
  const out = {};
  out.fresh = await wifiRun(fakeSurvey('fresh'));
  out.refused = await wifiRun(fakeSurvey('refused'));
  out.nobridge = await wifiRun(null);
  out.waiting = await wifiRun(fakeSurvey('waiting'));
  out.outdated = await wifiRun(fakeSurvey('outdated'));
  out.denied = await wifiRun(fakeSurvey('denied'));
  out.stale = await wifiRun(fakeSurvey('stale'));
  out.broken = await wifiRun(fakeSurvey('broken'));
  out.failedPost = await wifiRun(fakeSurvey('fresh'), { wifiFails: true });
  // a second job gets its own snapshot
  {
    const api = fakeApi();
    const c = R.createFullScan(Object.assign({ api, survey: null }, T));
    c.apply(job({ id: 'job-a', phase: 'wifi' }));
    await waitFor(() => api.wifi.length === 1, 1000);
    c.apply(job({ id: 'job-b', phase: 'wifi' }));
    await waitFor(() => api.wifi.length === 2, 1000);
    c.apply(job({ id: 'job-a', phase: 'wifi' }));
    await sleep(30);
    out.twoJobs = c.posts.map((e) => e.job_id);
    c.stop();
  }
  // polled every pollMs while it runs and the stream is down, never after it ended; a stale poll never revives a job
  {
    const api = fakeApi();
    api.current = job({ phase: 'discovery' });
    const c = R.createFullScan(Object.assign({ api, survey: null, live: () => false }, T));
    c.apply(api.current);
    await sleep(90);
    const polled = api.jobs;
    api.current = job({ status: 'saved', phase: null, pct: 100, report_id: 7 });
    await waitFor(() => c.job && c.job.status === 'saved', 500);
    const stoppedAt = api.jobs;
    await sleep(80);
    c.apply(job({ status: 'running', phase: 'wifi' }));
    out.polling = { polled, stoppedAt, later: api.jobs, status: c.job.status, reportId: c.job.report_id, posts: api.wifi.length, running: c.running() };
    c.stop();
  }
  // start: a scan already running (409 busy) is adopted; a new one gets the normalised site
  {
    const running = job({ id: 'job-9', site: 'Acme Dental', phase: 'discovery' });
    const c = R.createFullScan(Object.assign({ api: fakeApi({ busy: running }), survey: null }, T));
    const r = await c.start('Harbor View');
    let sent;
    const api2 = fakeApi();
    api2.fullScanStart = (site) => { sent = site; return Promise.resolve({ job: job({ id: 'job-10', site }) }); };
    const c2 = R.createFullScan(Object.assign({ api: api2, survey: null }, T));
    const r2 = await c2.start('  Harbor   View ');
    const sentNamed = sent;
    const c3 = R.createFullScan(Object.assign({ api: api2, survey: null }, T));
    await c3.start('   ');
    out.start = { busy: [r.started, r.job.id, c.job.id], started: [r2.started, sentNamed, c2.job.site], unnamed: sent };
    c3.stop();
    const other = R.createFullScan(Object.assign({ api: Object.assign(fakeApi(), { fullScanStart: () => Promise.reject(Object.assign(new Error('boom'), { status: 500 })) }), survey: null }, T));
    try { await other.start('x'); out.start.error = null; } catch (e) { out.start.error = e.message; }
    c.stop(); c2.stop(); other.stop();
  }
  // a scan on a network an earlier report was made on: the job carries its network and the suggested site, which a later job can change
  {
    const api = fakeApi();
    const suggested = { site: 'Acme Dental', report_id: 5, created_ts: 1000 };
    api.fullScanStart = () => Promise.resolve({ job: job({ id: 'job-11', network_id: 2, suggested_site: suggested }) });
    const c = R.createFullScan(Object.assign({ api, survey: null }, T));
    const seen = [];
    c.subscribe((j) => seen.push(R.jobSite(j).site));
    const r = await c.start();
    c.apply(job({ id: 'job-11', network_id: 2, suggested_site: Object.assign({}, suggested, { site: 'Acme Dental Clinic' }) }));
    c.apply(job({ id: 'job-11', network_id: 2, suggested_site: null }));
    out.suggested = { started: [r.started, r.job.network_id, R.jobSite(r.job)], seen };
    c.stop();
  }
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { process.stderr.write(String((e && e.stack) || e)); process.exit(1); });
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_full_scan_controller_posts_one_wifi_snapshot_with_node(tmp_path):
    driver = tmp_path / "driver.js"
    driver.write_text(_NODE_FULL_SCAN_DRIVER, encoding="utf-8")
    r = subprocess.run(["node", str(driver), str(UI / "js/reportsui.js")], capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    snapshot_keys = ["aps", "available", "collected_ts", "error", "interfaces", "state"]
    for name, res in out.items():
        if not isinstance(res, dict) or "early" not in res:
            continue
        # exactly one snapshot per job, whatever number of events and polls announce the Wi-Fi phase; none before it
        assert res["early"] == 0 and res["posts"] == 1 and len(res["entries"]) == 1 and res["entries"][0][0] == "job-1", (name, res)
        assert res["body"]["keys"] == snapshot_keys and res["body"]["history"] is False and res["notified"], (name, res)
    fresh = out["fresh"]
    assert fresh["calls"] == ["wifi_scan_now"] and fresh["opts"] == {"active": True, "history_s": 60}
    assert fresh["body"]["available"] is True and fresh["body"]["state"] == "ok" and fresh["body"]["bssids"] == ["02:00:5E:00:00:02", "02:00:5E:00:00:01"]
    assert fresh["entries"][0][1] is True
    assert out["refused"]["body"]["available"] is True, "a refused scan request (5 s rate limit) still reads the survey"
    nb = out["nobridge"]["body"]
    assert nb["available"] is False and nb["state"] == "no_bridge" and "TNT window" in nb["error"] and nb["bssids"] == []
    assert out["waiting"]["body"]["state"] == "no_bridge", "a bridge that never comes after the grace is no bridge"
    assert out["outdated"]["body"]["state"] == "outdated" and out["outdated"]["calls"] == []
    assert out["denied"]["body"] == {"available": False, "state": "location_denied", "error": "Location access is off", "bssids": [], "history": False,
                                     "keys": snapshot_keys}
    assert out["stale"]["body"]["available"] is True and out["stale"]["body"]["bssids"], "past the limit the latest good read is posted as it is"
    assert out["broken"]["body"]["state"] == "error" and out["broken"]["body"]["error"] == "the TNT window is not answering"
    assert out["failedPost"]["entries"][0][1] is False and "waiting" in out["failedPost"]["entries"][0][2], "a refused post is not retried"
    assert out["twoJobs"] == ["job-a", "job-b"]
    pl = out["polling"]
    assert pl["polled"] >= 2 and pl["later"] == pl["stoppedAt"], pl
    assert pl["status"] == "saved" and pl["reportId"] == 7 and pl["posts"] == 0 and pl["running"] is False
    st = out["start"]
    assert st["busy"] == [False, "job-9", "job-9"] and st["started"] == [True, "Harbor View", "Harbor View"]
    assert st["unnamed"] is None and st["error"] == "boom"
    # the suggested site follows the job: renamed, then gone
    assert out["suggested"] == {"started": [True, 2, {"site": "Acme Dental", "suggested": True}], "seen": ["Acme Dental", "Acme Dental Clinic", None]}


@pytest.fixture()
def fast_reports(mock):
    """The mock's full scan in a hurry, with its flags and every report a test adds put back afterwards."""
    state = mock.state
    before = {r["id"] for r in state.reports}
    state.report_fast = True
    state.report_wifi_grace_s = 0.3
    state.report_wifi_timeout_s = 20.0
    try:
        yield state
    finally:
        if state.report_job and state.report_job["status"] == "running":
            state.report_scan_cancel()
            time.sleep(0.2)
        state.report_fast = False
        state.report_wifi_grace_s = mock.mod.REPORT_WIFI_GRACE_S
        state.report_wifi_timeout_s = mock.mod.REPORT_WIFI_TIMEOUT_S
        for rid in [r["id"] for r in state.reports if r["id"] not in before]:
            state.report_delete(rid)


def _wait_job(port: int, pred, deadline_s: float = 6.0) -> Dict[str, Any]:
    deadline = time.time() + deadline_s
    job = None
    while time.time() < deadline:
        st, _, body = _req(port, "GET", "/api/reports/scan")
        job = body["job"]
        if job and pred(job):
            return job
        time.sleep(0.03)
    raise AssertionError(f"the job never got there: {job}")


def test_mock_reports_list_sites_get_rename_delete(mock, fast_reports):
    st, _, lst = _req(mock.port, "GET", "/api/reports")
    assert st == 200 and set(lst) == {"reports", "total"} and lst["total"] >= 5
    rows = lst["reports"]
    assert all(set(r) == REPORT_ROW_KEYS and set(r["summary"]) == REPORT_SUMMARY_KEYS for r in rows), "lists never carry the data"
    assert [r["created_ts"] for r in rows] == sorted((r["created_ts"] for r in rows), reverse=True)
    seeded = {r["site"] for r in rows}
    assert {"Maple Street Office", "Acme Dental", "Northside Warehouse", "Pinecrest Library"} <= seeded
    assert {r["status"] for r in rows} == {"complete", "partial"}
    st, _, acme = _req(mock.port, "GET", "/api/reports?site_key=acme%20dental")
    assert st == 200 and acme["total"] == 2 and {r["site"] for r in acme["reports"]} == {"Acme Dental"}
    st, _, q = _req(mock.port, "GET", "/api/reports?q=NORTH")
    assert q["total"] == 1 and q["reports"][0]["site"] == "Northside Warehouse"
    st, _, page = _req(mock.port, "GET", "/api/reports?limit=2&offset=1")
    assert page["total"] == lst["total"] and [r["id"] for r in page["reports"]] == [r["id"] for r in rows[1:3]]
    st, _, sites = _req(mock.port, "GET", "/api/reports/sites")
    assert st == 200 and all(set(s) == {"site", "site_key", "count", "last_ts", "network_ids"} for s in sites["sites"]) and sites["total"] == len(sites["sites"])
    assert _req(mock.port, "GET", "/api/reports/sites?limit=1")[2]["total"] == len(sites["sites"])
    assert [s["last_ts"] for s in sites["sites"]] == sorted((s["last_ts"] for s in sites["sites"]), reverse=True)
    assert next(s for s in sites["sites"] if s["site_key"] == "acme dental")["count"] == 2
    st, _, den = _req(mock.port, "GET", "/api/reports/sites?q=den")
    assert [s["site"] for s in den["sites"]] == ["Acme Dental"]
    # q is a case-insensitive part of the name; names starting with it come first
    st, _, a = _req(mock.port, "GET", "/api/reports/sites?q=A&limit=10")
    assert a["sites"][0]["site"] == "Acme Dental" and len(a["sites"]) == 4
    # every seeded report has every section, and the partial ones say why a section is missing
    for r in rows:
        st, _, rep = _req(mock.port, "GET", f"/api/reports/{r['id']}")
        assert st == 200 and rep["id"] == r["id"]
        _assert_report_shape(rep)
    library = next(r for r in rows if r["site"] == "Pinecrest Library")
    st, _, rep = _req(mock.port, "GET", f"/api/reports/{library['id']}")
    assert rep["status"] == "partial" and rep["data"]["speed"]["available"] is False and "rate limited" in rep["data"]["speed"]["reason"]
    assert rep["data"]["discovery"]["available"] is False and rep["summary"]["download_mbps"] is None
    newest_acme = acme["reports"][0]
    st, _, rep = _req(mock.port, "GET", f"/api/reports/{newest_acme['id']}")
    assert rep["data"]["wifi"] == dict(rep["data"]["wifi"], available=False, reason="No TNT window was open to scan Wi-Fi")
    # bad and unknown ids
    assert _req(mock.port, "GET", "/api/reports/999999")[0] == 404
    assert _req(mock.port, "GET", "/api/reports/abc")[0] == 400
    assert _req(mock.port, "GET", "/api/reports/1/nope")[0] == 404
    assert _req(mock.port, "PUT", "/api/reports/1", {"site": "x"})[0] == 405
    # rename and delete a scratch report (the seeded ones stay as they are for the other tests)
    scratch = fast_reports._report_add(mock.mod.synthetic_report("Scratch Site", time.time() - 7200, "good"))
    q_events = fast_reports.hub.subscribe()
    try:
        st, _, row = _req(mock.port, "PATCH", f"/api/reports/{scratch['id']}", {"site": "  Harbor   (Main)  Office "})
        assert st == 200 and set(row) == REPORT_ROW_KEYS and row["site"] == "Harbor (Main) Office"
        st, _, err = _req(mock.port, "PATCH", f"/api/reports/{scratch['id']}", {"site": "   "})
        assert st == 400 and err["error"]["code"] == "bad_request"
        assert _req(mock.port, "PATCH", f"/api/reports/{scratch['id']}", {"site": "y" * 81})[0] == 400
        assert _req(mock.port, "PATCH", "/api/reports/999999", {"site": "Nowhere"})[0] == 404
        st, h, pdf = _req(mock.port, "GET", f"/api/reports/{scratch['id']}/pdf", raw=True)
        assert st == 200 and h["content-type"] == "application/pdf" and pdf.startswith(b"%PDF-1.") and pdf.rstrip().endswith(b"%%EOF")
        assert re.fullmatch(r'attachment; filename="TNT-report-Harbor-Main-Office-\d{4}-\d{2}-\d{2}-\d{4}\.pdf"', h["content-disposition"])
        assert b"Harbor \\(Main\\) Office" in pdf, "parentheses in a site name are escaped in the PDF"
        st, _, ok = _req(mock.port, "DELETE", f"/api/reports/{scratch['id']}")
        assert st == 200 and ok == {"ok": True}
        assert _req(mock.port, "DELETE", f"/api/reports/{scratch['id']}")[0] == 404
        got = _drain(q_events, "report.", "report.deleted", 3)
        assert got == [("report.updated", {"id": scratch["id"], "site": "Harbor (Main) Office"}), ("report.deleted", {"id": scratch["id"]})]
    finally:
        fast_reports.hub.unsubscribe(q_events)


def test_mock_reports_compare_and_pdfs(mock):
    st, _, lst = _req(mock.port, "GET", "/api/reports?limit=50")
    by_site = {}
    for r in lst["reports"]:
        by_site.setdefault(r["site"], []).append(r)
    acme_new, acme_old = by_site["Acme Dental"][0], by_site["Acme Dental"][1]
    good = by_site["Maple Street Office"][0]
    st, _, cmp = _req(mock.port, "GET", f"/api/reports/compare?a={acme_new['id']}&b={good['id']}")
    # two networks: no same-network note, but both sides were read on their site's networks, which the one note of their time there says
    assert st == 200 and set(cmp) == {"a", "b", "sections", "notes"} and cmp["notes"] == ["On their networks: A 2d 6h over 2 visits; B 7d 0h over 1 visit"]
    # two scans of Acme Dental's network: the comparison says so, naming its router
    st, _, same_net = _req(mock.port, "GET", f"/api/reports/compare?a={acme_new['id']}&b={acme_old['id']}")
    assert same_net["notes"] == ["On their networks: A 2d 6h over 2 visits; B 1d 1h over 1 visit",
                                 "A and B were scanned on the same network (router C2:FF:EE:0A:00:FB)"]
    assert cmp["a"] == {"id": acme_new["id"], "site": "Acme Dental", "created_ts": acme_new["created_ts"], "status": "partial"}
    assert cmp["b"]["site"] == "Maple Street Office" and cmp["b"]["status"] == "complete"
    assert [s["key"] for s in cmp["sections"]] == ["speed", "ping", "outages", "wifi", "discovery"]
    for sec in cmp["sections"]:
        assert set(sec) == {"key", "title", "rows", "note"}
        for row in sec["rows"]:
            assert set(row) == COMPARE_ROW_KEYS and row["better"] in ("a", "b", "same", None), row
            assert row["a"] is not None or row["b"] is not None, "a row with no value on either side is left out"
            if row["a"] is not None and row["b"] is not None:
                assert row["delta"] == pytest.approx(row["a"] - row["b"], abs=1e-3)
            else:
                assert row["better"] is None and row["delta"] is None
            if row["higher_is_better"] is None:
                assert row["better"] is None, "informational rows are never better or worse"
    rows = {sec["key"]: {row["key"]: row for row in sec["rows"]} for sec in cmp["sections"]}
    assert [r["key"] for r in cmp["sections"][0]["rows"]] == ["download_mbps", "upload_mbps", "latency_ms", "jitter_ms", "packet_loss_pct",
                                                              "download_window_avg", "link_mbps"]
    assert rows["speed"]["download_mbps"]["better"] == "b" and rows["speed"]["download_mbps"]["higher_is_better"] is True
    assert rows["speed"]["latency_ms"]["higher_is_better"] is False and rows["speed"]["latency_ms"]["better"] == "b"
    assert rows["speed"]["packet_loss_pct"]["better"] == "same"
    assert rows["speed"]["link_mbps"]["higher_is_better"] is None and rows["speed"]["download_window_avg"]["higher_is_better"] is None
    assert {"gateway_avg_ms", "gateway_p95_ms", "gateway_max_ms", "gateway_loss_pct", "internet_avg_ms", "internet_loss_pct",
            "host:1.1.1.1:avg_ms", "host:1.1.1.1:loss_pct"} <= set(rows["ping"])
    assert rows["ping"]["gateway_max_ms"]["better"] is None and rows["ping"]["internet_avg_ms"]["label"] == "Internet average (targets in both)"
    # both sides were read on their site's networks: their time there is the comparison's one note, not repeated in the row notes
    assert cmp["sections"][1]["rows"][0]["note"] is None
    # the newer Acme scan monitored 2.3 days on its network over two visits: daily rates; Pinecrest Library's 43 minutes give each
    # window's counts, for information, instead
    assert list(rows["outages"]) == ["outages_per_day", "downtime_min_per_day", "longest_outage_min", "target_outages_per_day"]
    assert rows["outages"]["outages_per_day"]["note"] is None
    assert cmp["notes"][0] == "On their networks: A 2d 6h over 2 visits; B 7d 0h over 1 visit"
    library = by_site["Pinecrest Library"][0]
    st, _, cmp3 = _req(mock.port, "GET", f"/api/reports/compare?a={library['id']}&b={good['id']}")
    short = {row["key"]: row for sec in cmp3["sections"] if sec["key"] == "outages" for row in sec["rows"]}
    assert list(short) == ["network_outages", "downtime_min", "longest_outage_min", "target_outages"]
    assert "Too little history for daily rates" in short["network_outages"]["note"]
    assert all(r["better"] is None for r in short.values()) and short["network_outages"]["unit"] == "outages"
    # the newer Acme scan has no Wi-Fi: its side is empty, nothing is better or worse, and the section says why
    assert cmp["sections"][3]["note"] == "A: No TNT window was open to scan Wi-Fi" and cmp["sections"][0]["note"] is None
    assert rows["wifi"]["connected_rssi"]["a"] is None and rows["wifi"]["connected_rssi"]["better"] is None
    assert rows["discovery"]["hosts"]["higher_is_better"] is None and rows["discovery"]["hosts"]["unit"] == "devices"
    assert [k for k in rows["discovery"] if k.startswith("type:")][:3] == ["type:Router", "type:DW Server", "type:Camera"]
    # the two Acme scans with Wi-Fi on both sides: per band and per SSID seen in both
    st, _, cmp2 = _req(mock.port, "GET", f"/api/reports/compare?a={acme_old['id']}&b={by_site['Northside Warehouse'][0]['id']}")
    wifi = {row["key"]: row for sec in cmp2["sections"] if sec["key"] == "wifi" for row in sec["rows"]}
    assert wifi["connected_rssi"]["better"] == "a"
    assert wifi["connected_rssi"]["note"] == "A: AcmeDental-Staff (5 GHz, channel 36, 80 MHz); B: Northside-Ops-Staff (5 GHz, channel 36, 80 MHz)"
    assert wifi["band_2.4_networks"]["higher_is_better"] is None and wifi["band_2.4_networks"]["unit"] == "networks"
    assert wifi["connected_channel_aps"]["higher_is_better"] is False and wifi["connected_channel_aps"]["unit"] == "APs"
    assert wifi["connected_overlap_aps"]["higher_is_better"] is False
    assert wifi["band_5_busiest_channel_aps"]["note"].startswith("Busiest channel: ") and wifi["band_5_own_rssi"]["delta_pct"] is None
    assert wifi["band_5_own_rssi"]["higher_is_better"] is True and wifi["band_5_other_rssi"]["higher_is_better"] is None
    assert not any(k.startswith("ssid:") for k in wifi), "networks that happen to be visible at two different sites are not compared"
    st, _, same = _req(mock.port, "GET", f"/api/reports/compare?a={acme_old['id']}&b={acme_old['id']}")
    assert all(row["better"] in ("same", None) for sec in same["sections"] for row in sec["rows"])
    for query, code in (("", 400), ("?a=1", 400), ("?a=x&b=1", 400), ("?a=1&b=999999", 404)):
        assert _req(mock.port, "GET", "/api/reports/compare" + query)[0] == code, query
    st, h, pdf = _req(mock.port, "GET", f"/api/reports/compare/pdf?a={acme_new['id']}&b={good['id']}", raw=True)
    assert st == 200 and h["content-type"] == "application/pdf" and pdf.startswith(b"%PDF-1.")
    assert h["content-disposition"] == 'attachment; filename="TNT-compare-Acme-Dental-vs-Maple-Street-Office.pdf"'
    assert _req(mock.port, "POST", "/api/reports/compare?a=1&b=2")[0] == 405


#: Wi-Fi snapshots the mock and the service must clean and sum up alike: every quirk the intake handles (lower-case and dashed
#: BSSIDs, a stale copy of a fresher access point, numeric bands and channels, a hidden flag against a blank SSID, a signal out of
#: range or missing, a connection only an interface names, control characters, only stale access points) and unavailable states
PARITY_WIFI_BODIES: List[Dict[str, Any]] = [
    {"available": True, "state": " OK ", "error": None, "collected_ts": 1780000000.25,
     "interfaces": [{"guid": "g", "description": "Example Wireless Adapter", "state": "connected", "connected_bssid": "02-00-5e-20-00-09",
                     "connected_ssid": "Harbor Lab"}],
     "aps": [{"bssid": "02:00:5e:20:00:01", "ssid": "Harbor Lab", "rssi": -52.4, "band": 5, "channel": 36, "center_channel": 42, "width_mhz": 80,
              "security": "WPA2-Personal", "generation": "Wi-Fi 6", "vendor": "Not From The Page"},
             {"bssid": "02:00:5E:20:00:0A", "ssid": "Neighbour 48", "rssi": -77, "band": "5", "channel": 48, "width_mhz": 20},
             {"bssid": "02:00:5E:20:00:02", "ssid": "Harbor Guest", "rssi": -58, "band": "2.4", "channel": 6, "width_mhz": 20},
             {"bssid": "02:00:5E:20:00:02", "ssid": "Harbor Guest", "rssi": -50, "band": "2.4", "channel": 6, "width_mhz": 20, "stale": True},
             {"bssid": "02:00:5E:20:00:03", "ssid": "Harbor Guest", "rssi": -58, "band": 2.4, "channel": "6", "width_mhz": 20},
             {"bssid": "02:00:5E:20:00:04", "ssid": "", "rssi": -80, "band": "6", "channel": 37, "width_mhz": 160},
             {"bssid": "02:00:5E:20:00:05", "ssid": "  ", "hidden": False, "rssi": -81, "band": "5", "channel": None, "width_mhz": 160},
             {"bssid": "02:00:5E:20:00:06", "ssid": "No Signal", "band": "5", "channel": 40},
             {"bssid": "02:00:5E:20:00:07", "ssid": "Too Strong", "rssi": 3, "band": "5", "channel": 40},
             {"bssid": "02:00:5E:20:00:08", "ssid": "Old\x07Printer", "rssi": -88, "band": "2.4", "channel": 1, "stale": True},
             {"bssid": "02:00:5E:20:00:09", "ssid": "Harbor Lab", "rssi": -61, "band": "5", "channel": 36, "width_mhz": 80.0},
             {"bssid": "not-a-bssid", "ssid": "junk", "rssi": -40}, "junk"]},
    {"available": True, "state": "ok", "interfaces": [],
     "aps": [{"bssid": "02:00:5E:20:00:08", "ssid": "Only Stale", "rssi": -70, "band": "5", "channel": 44, "stale": True}]},
    {"available": False, "state": "no_bridge", "error": None},
    {"available": False, "state": "location_denied", "error": None, "interfaces": [{"description": "Example Wireless Adapter", "state": "disconnected"}]},
    {"available": False, "state": "error", "error": "  The TNT window did not answer\n"},
]
PARITY_OUTAGE_ROWS: List[Dict[str, Any]] = [
    {"start_ts": 100.0, "end_ts": 400.0, "kind": "target", "host": "198.51.100.7", "missed": 290, "missed_pct": 96.666, "note": None},
    {"start_ts": 50.0, "end_ts": 600.0, "kind": "total_internet", "host": None, "missed": 0, "missed_pct": None, "note": None},
    {"start_ts": 48.5, "end_ts": 601.0, "kind": "target", "target_id": 8, "host": "dns.example (198.51.100.8)", "missed": 540, "missed_pct": 99.0,
     "note": None},
    {"start_ts": 590.0, "end_ts": 640.0, "kind": "total_local", "host": None, "missed": 0, "missed_pct": None, "note": "no network connection"},
    {"start_ts": 900.0, "end_ts": 1500.0, "kind": "total_local", "host": None, "missed": 0, "missed_pct": None, "note": None},
    {"start_ts": 700.0, "end_ts": 800.0, "kind": "target", "target_id": 9, "host": "nvr.example", "missed": 90, "missed_pct": 90.0, "note": "x" * 400},
    {"start_ts": -300.0, "end_ts": 20.0, "kind": "target", "host": "gateway", "missed": 5, "missed_pct": 50.0, "note": "network changed"},
    {"start_ts": 10.0, "end_ts": 30.0, "kind": "gap", "host": None, "missed": 0, "missed_pct": None, "note": "system sleep"},
    {"start_ts": 2000.0, "end_ts": 2100.0, "kind": "target", "host": "after the window", "missed": 1, "missed_pct": 1.0},
    {"start_ts": 5.0, "end_ts": 6.0, "kind": "unknown"},
]
PARITY_LABELS = {8: "Public DNS", 9: "NVR"}
PARITY_RUN: Dict[str, Any] = {"id": 3, "cidr": "192.168.50.0/24", "ts": 5.0, "duration_s": 12.34, "hosts": [
    {"ip": "192.168.50.40", "hostname": "n" * 200, "mac": None, "vendor": "v" * 300, "open_ports": list(range(1, 100)), "device_type": "Zeta Box"},
    {"ip": "192.168.50.20", "hostname": None, "mac": "02:00:5E:10:00:14", "vendor": None, "open_ports": [554, 0, 70000], "device_type": "Camera"},
    {"ip": "192.168.50.3", "hostname": "nas", "mac": None, "vendor": None, "open_ports": [445], "device_type": "Zeta Box"},
    {"ip": "192.168.50.1", "hostname": "gw", "mac": "02:00:5E:10:00:01", "vendor": None, "open_ports": [80, 443], "device_type": "Router"},
    {"ip": "192.168.50.9", "hostname": None, "mac": None, "vendor": None, "open_ports": [], "device_type": "Alpha Box"}]}


def test_mock_reports_follow_the_service_rules(mock, tmp_path):
    """tools/mock_api.py copies tnt/reports.py's rules by hand (the mock imports no tnt code), so the page never meets data the
    service would not send: the seeded reports' shapes and summaries, every comparison between them, the Wi-Fi intake and
    section, the outage and Discovery sections, the id and search rules, the constants, the job and status.reports must come out
    exactly as the service's own code makes them. Vendor names are the one allowed difference: the mock's come from its invented
    OUI table, the service's from the IEEE registry."""
    from tnt import db as tnt_db
    from tnt import reports as service
    from tnt.api import routes as service_routes

    mod = mock.mod
    fresh = mod.MockState(0)
    seeded = [fresh.report_get(r["id"]) for r in fresh.reports]
    assert len(seeded) == len(mod.REPORT_SEEDS)
    for rep in seeded:
        _assert_report_shape(rep)
        assert rep["summary"] == service.build_summary(rep["data"]), rep["site"]
        for key in ("network", "speed", "ping", "outages", "discovery", "wifi"):
            assert set(rep["data"][key]) == set(service.empty_section(key, "x")), (rep["site"], key)
        assert set(rep["data"]["wifi"]["bands"]) == set(service.BANDS), rep["site"]
    # the second Acme Dental scan came after a test address was removed: its pings and outages are left out of it, and noted
    acme_again = max((r for r in seeded if r["site"] == "Acme Dental"), key=lambda r: r["created_ts"])
    assert acme_again["data"]["ping"]["note"] == "Left out: 1 removed or disabled target"
    assert acme_again["data"]["outages"]["note"] == "Left out: 1 removed or disabled target (2 single-target outages)"
    assert acme_again["data"]["outages"]["count"] == 1 and [r["data"]["ping"]["note"] for r in seeded].count(None) == len(seeded) - 1
    for ra, rb in itertools.product(seeded, repeat=2):
        assert mod.compare_reports(ra, rb) == service.compare_reports(ra, rb), (ra["site"], rb["site"])
    # a report saved before reports left removed targets out has no note in those two sections: compared with a new one, it says so
    older = copy.deepcopy(seeded[0])
    for key in ("ping", "outages"):
        del older["data"][key]["note"]
    for ra, rb in ((acme_again, older), (older, acme_again), (older, older)):
        assert mod.compare_reports(ra, rb) == service.compare_reports(ra, rb), (ra["id"], rb["id"])
    notes = {s["key"]: s["note"] for s in mod.compare_reports(acme_again, older)["sections"]}
    assert notes["ping"] == notes["outages"] == "B was saved before reports left out removed or disabled targets"
    assert {s["key"]: s["note"] for s in mod.compare_reports(older, older)["sections"]}["ping"] is None
    # two scans of one site (per-SSID rows) and a report with no outage history
    before, after = mod.synthetic_report("Acme Dental", 1_780_000_000.0, "fair"), mod.synthetic_report("acme dental", 1_780_900_000.0, "poor")
    for side, rep in enumerate((before, after), start=1):
        rep["id"] = side
    one_site = mod.compare_reports(after, before)
    assert one_site == service.compare_reports(after, before)
    assert any(r["key"].startswith("ssid:") for s in one_site["sections"] for r in s["rows"])
    after["data"]["outages"] = mod.report_outages_section([], 5.0, 5.0)
    assert mod.compare_reports(after, before) == service.compare_reports(after, before)

    def no_vendors(section: Dict[str, Any]) -> Dict[str, Any]:
        out = copy.deepcopy(section)
        for ap in out["aps"]:
            ap.pop("vendor")
        return out

    for body in PARITY_WIFI_BODIES:
        mine = no_vendors(mod.report_wifi_section(mod.report_wifi_snapshot(copy.deepcopy(body))))
        theirs = no_vendors(service.build_wifi_section(service.clean_wifi_snapshot(copy.deepcopy(body))))
        if "collected_ts" not in body:
            # stamped with the time of each call, rounded to the millisecond: under load the two calls can straddle one
            assert abs(mine.pop("collected_ts") - theirs.pop("collected_ts")) < 5.0, body.get("state")
        assert mine == theirs, body.get("state")
    assert mod.report_wifi_section(None) == service.build_wifi_section(None)
    for bad in ({"available": "yes"}, {"available": True, "state": 5}, {"available": True, "error": 3}, {"available": True, "collected_ts": "x"},
                {"available": True, "collected_ts": -1}, {"available": True, "aps": {}}, {"available": True, "interfaces": "x"},
                {"available": True, "aps": [{}] * 1001}, [1]):
        with pytest.raises(ValueError):
            mod.report_wifi_snapshot(bad)
        with pytest.raises(ValueError):
            service.clean_wifi_snapshot(bad)
    assert mod.report_outages_section(copy.deepcopy(PARITY_OUTAGE_ROWS), 0.0, 1000.0) == \
        service.build_outages_section(copy.deepcopy(PARITY_OUTAGE_ROWS), 0.0, 1000.0)
    incidents = mod.report_outages_section(copy.deepcopy(PARITY_OUTAGE_ROWS), 0.0, 1000.0, PARITY_LABELS.get)
    assert incidents == service.build_outages_section(copy.deepcopy(PARITY_OUTAGE_ROWS), 0.0, 1000.0, label_for=PARITY_LABELS.get)
    assert (incidents["network_outages"], incidents["target_outages"]) == (2, 1) and incidents["monitored_s"] == 980.0
    assert [it["targets"] for it in incidents["items"] if it["kind"] == "total_local"][-1] == ["gateway", "Public DNS (dns.example)", "198.51.100.7"]
    # a new report describes the targets set up when its scan ran (only id 8 here): every other target row is left out and noted
    scoped = mod.report_outages_section(copy.deepcopy(PARITY_OUTAGE_ROWS), 0.0, 1000.0, PARITY_LABELS.get, None, [8])
    assert scoped == service.build_outages_section(copy.deepcopy(PARITY_OUTAGE_ROWS), 0.0, 1000.0, label_for=PARITY_LABELS.get, target_ids=[8])
    assert (scoped["count"], scoped["network_outages"], scoped["target_outages"], scoped["by_kind"]["target"]) == (2, 2, 0, 1)
    assert [it["targets"] for it in scoped["items"] if it["kind"] == "total_local"][-1] == ["Public DNS (dns.example)"]
    # the rows without a target id are left out too, but counted as outages only: the one target left out is id 9
    assert scoped["note"] == "Left out: 1 removed or disabled target (1 single-target outage)" and incidents["note"] is None
    # one set of left-out ids for both notes of a report: the ping section's (41 pinged but had no outage) plus the outages section's
    mine, theirs = {41}, {41}
    shared = mod.report_outages_section(copy.deepcopy(PARITY_OUTAGE_ROWS), 0.0, 1000.0, PARITY_LABELS.get, None, [8], mine)
    assert shared == service.build_outages_section(copy.deepcopy(PARITY_OUTAGE_ROWS), 0.0, 1000.0, label_for=PARITY_LABELS.get,
                                                   target_ids=[8], left_out=theirs)
    assert mine == theirs == {9, 41} and shared["note"] == "Left out: 2 removed or disabled targets (1 single-target outage)"
    lone = [{"start_ts": 100.0, "end_ts": 200.0, "kind": "target", "host": "203.0.113.9", "missed": 90, "missed_pct": 90.0, "note": None}]
    no_id = mod.report_outages_section(copy.deepcopy(lone), 0.0, 1000.0, None, None, [8])
    assert no_id == service.build_outages_section(copy.deepcopy(lone), 0.0, 1000.0, target_ids=[8])
    assert (no_id["count"], no_id["note"]) == (0, "Left out: 1 single-target outage of removed or disabled targets")
    for counts in ((0, 0), (0, 2), (1, 0), (1, 1), (8, 19), (0, 0, 1), (0, 2, 1), (2, 0, 1), (8, 19, 2)):
        assert mod.report_left_out_note(*counts) == service.left_out_note(*counts), counts
    # a network outage whose every member target was left out is left out too, counted, and its total rows are not counted by kind
    lone = [{"start_ts": 100.0, "end_ts": 400.0, "kind": "total_internet", "host": None, "missed": 0, "missed_pct": None, "note": None},
            {"start_ts": 99.0, "end_ts": 401.0, "kind": "target", "target_id": 41, "host": "old.example", "missed": 290, "missed_pct": 97.0, "note": None},
            {"start_ts": 98.0, "end_ts": 402.0, "kind": "target", "target_id": 42, "host": "older.example", "missed": 290, "missed_pct": 97.0, "note": None},
            {"start_ts": 600.0, "end_ts": 700.0, "kind": "total_local", "host": None, "missed": 0, "missed_pct": None, "note": None},
            {"start_ts": 599.0, "end_ts": 701.0, "kind": "target", "target_id": 8, "host": "gw", "missed": 90, "missed_pct": 90.0, "note": None}]
    kept_only = mod.report_outages_section(copy.deepcopy(lone), 0.0, 1000.0, None, None, [8], None, 900.0)
    assert kept_only == service.build_outages_section(copy.deepcopy(lone), 0.0, 1000.0, target_ids=[8], monitored_s=900.0)
    assert (kept_only["network_outages"], kept_only["by_kind"]["total_internet"], kept_only["by_kind"]["total_local"], kept_only["monitored_s"]) == (1, 0, 1, 900.0)
    # its two member rows are that network outage, never single-target outages as well
    assert kept_only["note"] == "Left out: 2 removed or disabled targets (1 network outage)"
    # the site's network: spans merged, the time of its visits without the gaps in them, how a network is described
    spans = [(5.0, 10.0), (8.0, 12.0), (20.0, 19.0), (30.0, 30.0), ("x", 1)]
    assert mod.report_merge_spans(spans) == service.merge_spans(spans)
    visits, gaps = [{"start": 0.0, "end": 100.0}, {"start": 200.0, "end": 400.0}, "junk"], [(50.0, 250.0), (390.0, 500.0)]
    assert mod.report_monitored_seconds(visits, gaps) == service.monitored_seconds(visits, gaps) == 190.0
    from tnt import networks as service_networks
    row = {"id": 3, "mac": "02:00:5E:10:00:01", "gateway_ip": "192.168.50.1", "subnet": "192.168.50.0/24", "dhcp_server": "192.168.50.1"}
    for r in (row, dict(row, mac=None), dict(row, mac=None, virtual_mac="00:00:5E:00:01:01", portable=True)):
        assert dict(mod.mock_network_view(r), vendor=None) == dict(service_networks.network_view(r, with_times=False), vendor=None)
    assert mod.REPORT_NETWORK_UNKNOWN == service_networks.unknown_network()
    assert mod.REPORT_UNKNOWN_NETWORK_MESSAGE == service.UNKNOWN_NETWORK_MESSAGE
    assert (mod.REPORT_NETWORK_NOTE_MESSAGES, mod.REPORT_NETWORK_TIME_NOTE) == (service.NETWORK_NOTE_MESSAGES, service.NETWORK_TIME_NOTE)
    for secs in (None, 0, 42, 59.5, 125, 3599.6, 3720, 86399, 93600, 604800):
        assert mod.report_duration_text(secs) == service.duration_text(secs), secs
    # GET /api/networks/current: the service's network view (with first_seen / last_seen), the newest named report made on the network, offline
    assert set(fresh.network_current()["network"]) == set(service_networks.network_view(row)) | {"last_report", "offline"}
    # two scans of a network known by its gateway and subnet only: the comparison says they share it, in the service's words
    library = next(r for r in seeded if r["data"]["meta"]["network"]["identity"] == "fingerprint")
    library_again = dict(copy.deepcopy(library), id=max(r["id"] for r in seeded) + 1)
    assert mod.compare_reports(library_again, library) == service.compare_reports(library_again, library)
    assert mod.compare_reports(library_again, library)["notes"] == ["On their networks: A 43m 12s over 1 visit; B 43m 12s over 1 visit",
                                                                     "A and B were scanned on the same network (identified by gateway and subnet)"]
    for start, end, why in ((5.0, 5.0, None), (0.0, 1000.0, "No pings were recorded in this window")):
        assert mod.report_outages_section(copy.deepcopy(PARITY_OUTAGE_ROWS), start, end, None, why) == \
            service.build_outages_section(copy.deepcopy(PARITY_OUTAGE_ROWS), start, end, unavailable=why)
    run = copy.deepcopy(PARITY_RUN)
    by_address = dict(run, hosts=sorted(run["hosts"], key=lambda x: ipaddress.ip_address(x["ip"])))     # the database's order
    assert mod.report_discovery_section(run) == service.build_discovery_section(by_address, ["192.168.50.1"])

    # the same constants, report ids and 400s
    assert (mod.REPORT_SAME_ABS, mod.REPORT_SAME_REL, mod.REPORT_MIN_RATE_S) == (service.UNIT_TOLERANCE, service.SAME_REL, service.MIN_RATE_S)
    assert (mod.REPORT_FOLD_SLACK_S, mod.REPORT_TEXT_CAP, mod.REPORT_NOTE_CAP, mod.REPORT_MAX_HOST_PORTS, mod.REPORT_WINDOW_WORDS) == \
        (service.FOLD_SLACK_S, service.TEXT_CAP, service.NOTE_CAP, service.MAX_HOST_PORTS, service.WINDOW_WORDS)
    assert mod.REPORT_VISIT_GAP_S == service.VISIT_GAP_S and set(mod.REPORT_WINDOW_WORDS) == set(service.WINDOW_REASONS)
    assert mod.report_target_name("NVR", "172.16.40.20") == service.target_name("NVR", "172.16.40.20") == "NVR (172.16.40.20)"
    assert (mod.REPORT_NO_WINDOW, mod.REPORT_WIFI_STATE_TEXT, set(mod.REPORT_WIFI_SKIPPED_STATES)) == \
        (service.NO_WINDOW_REASON, service.WIFI_STATE_TEXT, set(service.WIFI_SKIP_STATES))
    assert (mod.REPORT_NO_TARGET_PINGS, mod.REPORT_OLDER_RULE_NOTE) == (service.NO_TARGET_PINGS_REASON, service.OLDER_RULE_NOTE)
    assert (mod.REPORT_WIFI_TIMEOUT_S, mod.REPORT_WIFI_GRACE_S, mod.REPORT_WIFI_MAX_APS) == (service.WIFI_WAIT_S, service.WIFI_GRACE_S, service.MAX_POST_APS)
    assert (mod.REPORT_SITE_MAX, mod.REPORT_UNNAMED, mod.REPORT_MAX_OUTAGES, mod.REPORT_MAX_HOSTS, mod.REPORT_MAX_APS) == \
        (service.SITE_MAX_LEN, service.UNNAMED_SITE, service.MAX_OUTAGE_ITEMS, service.MAX_HOSTS, service.MAX_APS)
    assert mod.REPORT_QUERY_MAX == service_routes.REPORT_QUERY_MAX
    for text in ("1", "007", "9" * 15, "0", "000", "9" * 16, "-1", "1.5", "1e3", "abc", ""):
        assert mod.report_id_ok(text) is (bool(service_routes._REPORT_ID_RE.match(text)) and int(text) >= 1), text
    for name in ("  Acme \t Dental\n", "North\x00side  Warehouse", "x" * 80):
        assert mod.site_normalize(name) == service.normalize_site(name) and mod.site_key(name) == service.site_key(name)
    for name in ("   ", "x" * 81, 5, "Acme " + chr(0xD800) + " Dental"):
        with pytest.raises(ValueError):
            mod.site_normalize(name)
        with pytest.raises(ValueError):
            service.normalize_site(name)
    for path in ("/api/reports/0", "/api/reports/" + "9" * 16, "/api/reports/compare?a=0&b=1", "/api/reports?q=" + "x" * 201,
                 "/api/reports?site_key=" + "x" * 201, "/api/reports/sites?q=" + "x" * 201):
        assert _req(mock.port, "GET", path)[0] == 400, path

    # the job and status.reports carry the service's keys (a manager with no engine: its phases are skipped until Wi-Fi)
    db = tnt_db.Database(tmp_path / "tnt.db")
    mgr = service.ReportManager(db, None, None, None, wifi_wait_s=30.0)
    try:
        job = mgr.start_scan("Acme Dental")
        assert set(job) == REPORT_JOB_KEYS and all(set(p) == REPORT_PHASE_KEYS for p in job["phases"])
        assert [p["key"] for p in job["phases"]] == list(mod.REPORT_PHASES) == list(service.PHASES)
        assert set(mgr.status()) == set(fresh.status()["reports"]) == {"count", "sites", "last", "job"}
    finally:
        mgr.stop()
        db.close()


def test_mock_full_scan_history_leaves_out_removed_targets(mock):
    """The mock's full scan reads its history like the service's history phase: targets removed within the window are left out of
    the ping table and the outages, one count on both notes; with every target gone the ping section is not collected, with the
    service's reason, while the outages section (network outages and gaps) stays."""
    from tnt import reports as service

    mod = mock.mod
    st = mod.MockState(0)
    ids = [t["id"] for t in st.targets]
    _net, ping, out = st._report_history()
    assert [t["id"] for t in ping["targets"]] == ids and ping["note"] is None and out["note"] is None and ping["available"]
    assert st.remove_target(ids[-1])
    _net, ping, out = st._report_history()
    assert [t["id"] for t in ping["targets"]] == ids[:-1] and ping["note"] == "Left out: 1 removed or disabled target"
    assert out["note"] in (None, "Left out: 1 removed or disabled target") or out["note"].startswith("Left out: 1 removed or disabled target (")
    assert not any(it["kind"] == "target" and it["host"] == "totalelectronics.com" for it in out["items"])
    for tid in ids[:-1]:
        assert st.remove_target(tid)
    _net, ping, out = st._report_history()
    assert (ping["available"], ping["reason"], ping["targets"]) == (False, mod.REPORT_NO_TARGET_PINGS, [])
    assert ping["reason"] == service.NO_TARGET_PINGS_REASON and ping["note"] == "Left out: 3 removed or disabled targets"
    assert out["available"] is True and out["target_outages"] == 0 and all(not it["targets"] for it in out["items"])
    assert out["note"] is None or out["note"].startswith("Left out: 3 removed or disabled targets")
    data = {"ping": ping, "outages": out}
    assert (service.build_summary(data)["gateway_avg_ms"], service.build_summary(data)["outages"]) == (None, out["count"])
    # nothing ever pinged and nothing removed: no outage could have been noticed either, as in the service
    empty = mod.MockState(0)
    empty.targets, empty.outages = [], []
    _net, ping, out = empty._report_history()
    assert (ping["available"], ping["reason"], ping["note"]) == (False, "No pings were recorded in this window", None)
    assert (out["available"], out["reason"]) == (False, "No pings were recorded in this window")


def test_mock_full_scan_lifecycle(mock, fast_reports):
    port = mock.port
    # like the service: a cancel without a running scan is a no-op that answers the job as it is; a name without any scan is 409
    st, _, idle = _req(port, "DELETE", "/api/reports/scan")
    assert st == 200 and (idle["job"] is None or idle["job"]["status"] != "running")
    fresh = mock.mod.MockState(0)
    assert fresh.report_scan_name("Nowhere") == (None, "no_scan") and fresh.report_scan_cancel() is None
    q = fast_reports.hub.subscribe()
    try:
        st, _, body = _req(port, "POST", "/api/reports/scan", {})
        assert st == 200 and set(body["job"]) == REPORT_JOB_KEYS
        job = body["job"]
        assert job["status"] == "running" and job["site"] is None and [p["key"] for p in job["phases"]] == ["speed", "discovery", "wifi", "history", "save"]
        assert all(set(p) == REPORT_PHASE_KEYS for p in job["phases"])
        st, _, busy = _req(port, "POST", "/api/reports/scan", {"site": "Other"})
        assert st == 409 and busy["error"]["code"] == "busy" and busy["job"]["id"] == job["id"]
        st, _, named = _req(port, "PATCH", "/api/reports/scan", {"site": "  Harbor   View "})
        assert st == 200 and named["job"]["site"] == "Harbor View"
        assert _req(port, "PATCH", "/api/reports/scan", {"site": ""})[0] == 400
        waiting = _wait_job(port, lambda j: j["phase"] == "wifi")
        assert waiting["status"] == "running" and 60 <= waiting["pct"] <= 85
        phases = {p["key"]: p for p in waiting["phases"]}
        assert phases["speed"]["status"] == "done" and phases["discovery"]["status"] == "done" and phases["wifi"]["status"] == "running"
        # validated like the service: an object with a boolean available, at most 1000 access points, at most 2 MiB
        assert _req(port, "POST", "/api/reports/scan/wifi", {"state": "ok"})[0] == 400
        assert _req(port, "POST", "/api/reports/scan/wifi", {"available": True, "aps": [{"bssid": "02:00:00:00:00:01"}] * 1001})[0] == 400
        big = {"available": True, "aps": [], "pad": "x" * (2 * 1024 * 1024 + 10)}
        assert _req(port, "POST", "/api/reports/scan/wifi", big)[0] == 413
        snapshot = {"available": True, "state": "ok", "error": None, "collected_ts": time.time(),
                    "interfaces": [{"guid": "g", "description": "Synthetic Wi-Fi 6E", "state": "connected", "connected_bssid": "C0:FF:EE:00:00:01", "connected_ssid": "Harbor Lab"}],
                    "aps": [{"bssid": "c0:ff:ee:00:00:01", "ssid": "Harbor Lab", "rssi": -52, "band": "5", "channel": 36, "width_mhz": 80, "connected": True, "vendor": "Evil Corp"},
                            {"bssid": "C2:FF:EE:00:00:02", "ssid": "Harbor Guest", "rssi": -58, "band": "2.4", "channel": 6, "width_mhz": 20},
                            {"bssid": "02:11:22:33:44:55", "ssid": "", "rssi": -80, "band": "6", "channel": 37, "width_mhz": 160},
                            {"bssid": "not-a-bssid", "ssid": "junk"}]}
        st, _, posted = _req(port, "POST", "/api/reports/scan/wifi", snapshot)
        assert st == 200 and posted["job"]["id"] == job["id"]
        got = _drain(q, "report.", "report.saved", 6)
        kinds = [k for k, _ in got]
        assert kinds[-1] == "report.saved" and kinds.count("report.progress") >= 6, kinds
        assert all(set(d["job"]) == REPORT_JOB_KEYS for k, d in got if k == "report.progress")
        saved = got[-1][1]
        assert saved["site"] == "Harbor View" and saved["status"] == "complete" and set(saved) == {"id", "site", "status"}
        done = _wait_job(port, lambda j: j["status"] == "saved")
        assert done["report_id"] == saved["id"] and done["pct"] == 100 and done["phase"] is None
        assert all(p["status"] == "done" and p["finished_ts"] >= p["started_ts"] for p in done["phases"])
        st, _, rep = _req(port, "GET", f"/api/reports/{saved['id']}")
        _assert_report_shape(rep)
        wifi = rep["data"]["wifi"]
        assert wifi["available"] is True and wifi["aps_count"] == 3 and wifi["adapter"] == "Synthetic Wi-Fi 6E" and wifi["connected"]["bssid"] == "C0:FF:EE:00:00:01"
        vendors = {a["bssid"]: a["vendor"] for a in wifi["aps"]}
        # the vendor comes from the BSSID (a locally administered one from its base OUI), never from the page
        assert vendors == {"C0:FF:EE:00:00:01": "Contoso Access Systems", "C2:FF:EE:00:00:02": "Contoso Access Systems", "02:11:22:33:44:55": None}
        assert wifi["bands"]["5"]["busiest_channel"] == 36 and wifi["bands"]["6"]["aps"] == 1
        assert rep["data"]["discovery"]["available"] is True and rep["data"]["ping"]["targets"]
        # the scan is over: a Wi-Fi post is refused; a name renames the report it saved; a cancel changes nothing
        st, _, late = _req(port, "POST", "/api/reports/scan/wifi", snapshot)
        assert st == 409 and late["error"]["code"] == "not_waiting" and late["job"]["status"] == "saved"
        st, _, renamed = _req(port, "PATCH", "/api/reports/scan", {"site": "Harbor View East"})
        assert st == 200 and renamed["job"]["status"] == "saved"
        assert _req(port, "GET", f"/api/reports/{saved['id']}")[2]["site"] == "Harbor View East"
        st, _, still = _req(port, "DELETE", "/api/reports/scan")
        assert st == 200 and still["job"]["status"] == "saved" and still["job"]["report_id"] == saved["id"]
        # the report deleted: the job forgets it, and naming the scan is refused instead of answering with a stale job
        assert _req(port, "DELETE", f"/api/reports/{saved['id']}")[0] == 200
        assert _req(port, "GET", "/api/reports/scan")[2]["job"]["report_id"] is None
        st, _, gone = _req(port, "PATCH", "/api/reports/scan", {"site": "Lakeside Clinic"})
        assert st == 409 and gone["error"]["code"] == "not_found" and gone["job"]["report_id"] is None

        # a page without the TNT window's bridge: its unavailable snapshot is kept once the grace runs out; no name on the network of the
        # Acme Dental reports -> saved under Acme Dental (test_mock_networks_and_the_suggested_site has the rest)
        st, _, body = _req(port, "POST", "/api/reports/scan", {})
        assert body["job"]["suggested_site"]["site"] == "Acme Dental"
        _wait_job(port, lambda j: j["phase"] == "wifi" and j["id"] == body["job"]["id"])
        st, _, _ = _req(port, "POST", "/api/reports/scan/wifi", {"available": False, "state": "no_bridge", "error": "This page is not the TNT window", "aps": []})
        assert st == 200
        done = _wait_job(port, lambda j: j["id"] == body["job"]["id"] and j["status"] != "running")
        st, _, rep = _req(port, "GET", f"/api/reports/{done['report_id']}")
        assert rep["site"] == "Acme Dental" and rep["status"] == "partial"
        _assert_report_shape(rep)
        assert rep["data"]["wifi"]["available"] is False and rep["data"]["wifi"]["reason"] == "This page is not the TNT window"
        assert {p["key"]: p["status"] for p in done["phases"]}["wifi"] == "skipped"

        # nothing posted in time: "No TNT window was open to scan Wi-Fi"
        fast_reports.report_wifi_timeout_s = 0.3
        st, _, body = _req(port, "POST", "/api/reports/scan", {"site": "Quiet Corner"})
        done = _wait_job(port, lambda j: j["id"] == body["job"]["id"] and j["status"] != "running")
        st, _, rep = _req(port, "GET", f"/api/reports/{done['report_id']}")
        assert rep["data"]["wifi"]["reason"] == "No TNT window was open to scan Wi-Fi" and rep["status"] == "partial"
        fast_reports.report_wifi_timeout_s = 20.0

        # cancel during the Wi-Fi phase: nothing is saved
        total = len(fast_reports.reports)
        st, _, body = _req(port, "POST", "/api/reports/scan", {"site": "Cancel Me"})
        _wait_job(port, lambda j: j["phase"] == "wifi" and j["id"] == body["job"]["id"])
        st, _, cancelled = _req(port, "DELETE", "/api/reports/scan")
        assert st == 200 and cancelled["job"]["status"] == "cancelled" and cancelled["job"]["phase"] is None
        assert all(p["status"] in ("done", "skipped") for p in cancelled["job"]["phases"]), "running and pending phases are skipped"
        st, _, err = _req(port, "PATCH", "/api/reports/scan", {"site": "Too Late"})
        assert st == 409 and err["error"]["code"] == "not_running" and err["job"]["status"] == "cancelled"
        time.sleep(0.3)
        assert len(fast_reports.reports) == total and _req(port, "GET", "/api/reports/scan")[2]["job"]["status"] == "cancelled"
        assert _req(port, "POST", "/api/reports/scan/wifi", snapshot)[0] == 409
    finally:
        fast_reports.hub.unsubscribe(q)


def test_mock_networks_and_the_suggested_site(mock, fast_reports):
    """Like tnt.networks and the Full Scan pre-fill: the fake PC is on the Acme Dental reports' network, so a scan there suggests that
    site (the newest report made on it) and one nobody names is saved under it; a suggestion renamed or deleted while the scan runs is
    worked out again; a new network suggests nothing, no network keeps the last one, and a router whose MAC is never read is known by
    its gateway and subnet."""
    port, state, mod = mock.port, fast_reports, mock.mod
    st, _, cur = _req(port, "GET", "/api/networks/current")
    net = cur["network"]
    assert st == 200 and set(net) == REPORT_NETWORK_KEYS | {"first_seen", "last_seen", "last_report", "offline"}
    assert (net["mac"], net["vendor"], net["gateway_ip"], net["subnet"], net["dhcp_server"], net["identity"], net["portable"], net["offline"]) == \
        ("C2:FF:EE:0A:00:FB", "Contoso Access Systems", "10.0.0.251", "10.0.0.0/24", "10.0.0.251", "mac", False, False)
    assert net["first_seen"] <= net["last_seen"] <= time.time() + 1
    acme = _req(port, "GET", "/api/reports?site_key=acme%20dental")[2]["reports"]
    assert net["last_report"] == {"id": acme[0]["id"], "site": "Acme Dental", "created_ts": acme[0]["created_ts"]}
    sites = _req(port, "GET", "/api/reports/sites")[2]["sites"]
    assert {r["network_id"] for r in acme} == {net["id"]} and next(s for s in sites if s["site_key"] == "acme dental")["network_ids"] == [net["id"]]
    assert _req(port, "GET", "/api/status")[2]["net"]["network_id"] == net["id"]
    assert _req(port, "POST", "/api/networks/current")[0] == 405 and _req(port, "GET", "/api/networks/other")[0] == 404
    # the second Acme Dental scan's week holds two visits to its network; Pinecrest Library's router was known by gateway and subnet only
    rep = _req(port, "GET", f"/api/reports/{acme[0]['id']}")[2]
    ping = rep["data"]["ping"]
    assert ping["window_reason"] == "site_network" and len(ping["visits"]) == 2 and rep["data"]["meta"]["network"]["id"] == net["id"]
    assert rep["summary"]["window_hours"] == round(ping["monitored_s"] / 3600, 1) < (ping["window_end"] - ping["window_start"]) / 3600
    library = next(r for r in _req(port, "GET", "/api/reports")[2]["reports"] if r["site"] == "Pinecrest Library")
    assert _req(port, "GET", f"/api/reports/{library['id']}")[2]["data"]["meta"]["network"] == dict(
        id=library["network_id"], mac=None, vendor=None, gateway_ip="10.44.0.1", subnet="10.44.0.0/24", dhcp_server="10.44.0.1", identity="fingerprint",
        virtual_mac=None, portable=False)
    q = state.hub.subscribe()
    try:
        # a newer report on this network is the suggestion; renamed while the scan runs, the suggestion is too; deleted, the one before it
        scratch = state._report_add(mod.synthetic_report("Lakeside Dental", time.time() - 60, "fair", net["id"]))
        st, _, body = _req(port, "POST", "/api/reports/scan", {})
        job = body["job"]
        assert st == 200 and set(job) == REPORT_JOB_KEYS and job["network_id"] == net["id"] and job["window_reason"] == "site_network"
        assert job["suggested_site"] == {"site": "Lakeside Dental", "report_id": scratch["id"], "created_ts": scratch["created_ts"]}
        assert _req(port, "PATCH", f"/api/reports/{scratch['id']}", {"site": "Lakeside Dental Care"})[0] == 200
        assert _req(port, "GET", "/api/reports/scan")[2]["job"]["suggested_site"]["site"] == "Lakeside Dental Care"
        assert _req(port, "DELETE", f"/api/reports/{scratch['id']}")[0] == 200
        assert _req(port, "GET", "/api/reports/scan")[2]["job"]["suggested_site"] == {"site": "Acme Dental", "report_id": acme[0]["id"], "created_ts": acme[0]["created_ts"]}
        got = _drain(q, "report.", "report.deleted", 3)
        got += _drain(q, "report.", "report.progress", 3)          # the suggestion worked out again comes right after the deletion
        suggested = [d["job"]["suggested_site"] for k, d in got if k == "report.progress" and d["job"]["id"] == job["id"]]
        assert suggested and suggested[-1]["site"] == "Acme Dental" and any(s and s["site"] == "Lakeside Dental Care" for s in suggested)
        # nobody names it: saved under the suggested site, and the job says why
        _wait_job(port, lambda j: j["phase"] == "wifi" and j["id"] == job["id"])
        assert _req(port, "POST", "/api/reports/scan/wifi", {"available": False, "state": "no_bridge", "error": "This page is not the TNT window", "aps": []})[0] == 200
        done = _wait_job(port, lambda j: j["id"] == job["id"] and j["status"] != "running")
        saved = _req(port, "GET", f"/api/reports/{done['report_id']}")[2]
        assert done["status"] == "saved" and saved["site"] == "Acme Dental" and saved["network_id"] == net["id"]
        assert done["message"] == "Saved the report for Acme Dental, the site this network was scanned as before"
        assert saved["data"]["meta"]["network"]["mac"] == "C2:FF:EE:0A:00:FB" and saved["data"]["ping"]["window_reason"] == "site_network"
        _assert_report_shape(saved)
    finally:
        state.hub.unsubscribe(q)
    # a network marked portable (a hotspot or travel router carried from site to site) is suggested nothing and reads only this connection
    st, _, body = _req(port, "POST", "/api/reports/scan", {})
    assert st == 200 and body["job"]["suggested_site"]["site"] == "Acme Dental" and body["job"]["network"]["mac"] == net["mac"]
    st, _, patched = _req(port, "PATCH", f"/api/networks/{net['id']}", {"portable": True})
    assert st == 200 and set(patched["network"]) == REPORT_NETWORK_KEYS and patched["network"]["portable"] is True
    marked = _req(port, "GET", "/api/reports/scan")[2]["job"]
    assert (marked["suggested_site"], marked["network"]["portable"], marked["window_reason"]) == (None, True, "network_change")
    assert _req(port, "PATCH", f"/api/networks/{net['id']}", {"portable": False})[2]["network"]["portable"] is False
    assert _req(port, "GET", "/api/reports/scan")[2]["job"]["suggested_site"]["site"] == "Acme Dental"
    for path, patch, code in ((f"/api/networks/{net['id']}", {}, 400), (f"/api/networks/{net['id']}", {"portable": "yes"}, 400),
                              ("/api/networks/0", {"portable": True}, 400), ("/api/networks/999", {"portable": True}, 404)):
        assert _req(port, "PATCH", path, patch)[0] == code, (path, patch)
    state.report_scan_cancel()
    # another network: nothing to suggest (a scan there is "Unnamed site" unless named); without a network the PC stays on it
    state.switch_network("b")
    try:
        other = _req(port, "GET", "/api/networks/current")[2]["network"]
        assert other["id"] != net["id"] and other["gateway_ip"] == "192.168.50.1" and other["identity"] == "mac" and other["last_report"] is None
        st, _, body = _req(port, "POST", "/api/reports/scan", {"site": "Harbor View"})
        assert body["job"]["network_id"] == other["id"] and body["job"]["suggested_site"] is None
        state.report_scan_cancel()
        state.switch_network("none")
        assert _req(port, "GET", "/api/status")[2]["net"]["network_id"] == other["id"], "no network: still the last one"
        assert _req(port, "GET", "/api/networks/current")[2]["network"]["offline"] is True
        # a full scan started without a network with a gateway is on no site's network: nothing suggested, the time rule
        job_off = _req(port, "POST", "/api/reports/scan", {})[2]["job"]
        assert (job_off["network_id"], job_off["network"], job_off["suggested_site"]) == (None, None, None) and job_off["window_reason"] != "site_network"
        state.report_scan_cancel()
        state.switch_network("static-bad")
        known = _req(port, "GET", "/api/networks/current")[2]["network"]
        assert (known["identity"], known["mac"], known["vendor"], known["gateway_ip"]) == ("fingerprint", None, None, "172.16.21.1")
    finally:
        state.switch_network("a")
    assert _req(port, "GET", "/api/networks/current")[2]["network"]["id"] == net["id"]


def test_reports_page_mounts_in_a_browser_without_errors(browser_page):
    dom = browser_page("#reports", budget_ms=6000)
    assert 'data-mock-errors="[]"' in dom
    assert len(re.findall(r'<a class="tile[^"]*" data-view="', dom)) == 8
    assert re.search(r'<a class="tile active" data-view="reports" href="#reports"', dom)
    assert dom.index('id="btn-full-scan"') < dom.index('id="status-pill"')
    tile = _tile_body(dom, "reports")
    assert re.search(r'<span class="num">\d+</span><span class="muted">reports ·</span><span class="muted">\d+ sites</span>', tile)
    assert '<div class="rpt">' in dom
    # the newest report (the second Acme Dental scan, partial: no Wi-Fi) with its key numbers and the reason its Wi-Fi is missing
    assert re.search(r'<h3 class="rpt-site" id="rpt-site-title">Acme Dental</h3><span class="badge yellow"', dom)
    assert len(re.findall(r'<div class="rpt-kpi[^"]*" role="listitem">', dom)) == 8
    assert "Not collected: No TNT window was open to scan Wi-Fi" in dom
    # a test address was removed before that scan: the Ping and Outages sections say what they left out
    assert '<p class="rpt-note rpt-left-out">Left out: 1 removed or disabled target</p>' in dom
    assert '<p class="rpt-note rpt-left-out">Left out: 1 removed or disabled target (2 single-target outages)</p>' in dom
    # the saved reports browser lists every site; Compare shows the current scan against the previous Acme Dental scan
    assert len(re.findall(r'<button class="rpt-site-btn" type="button"', dom)) >= 4
    # the pickers put the date first ("Current scan · Sep 9 14:02 · Acme Dental"), so a narrow select keeps the time
    assert re.search(r"Current scan · [A-Z][a-z]{2} \d{1,2}(, \d{4})? \d\d:\d\d · Acme Dental", dom)
    assert dom.count('class="table rpt-table rpt-cmp-table') == 5 and "A − B" in dom
    assert '<h3 class="card-title">Saved reports' in dom and re.search(r'<h3 class="card-title"><svg[^>]*>.*?</svg>Compare', dom, re.S)
    assert re.search(r'<td class="num cmp-val cmp-better">', dom) and re.search(r'<td class="num cmp-diff cmp-(better|worse)"', dom)


def test_reports_page_shows_what_a_report_left_out_under_not_collected(browser_page, mock):
    """A report scanned after every pinged target had been removed: its Ping section is not collected, with the service's reason,
    and still says what it left out; its Outages section keeps the network outages and notes the same count."""
    mod, state = mock.mod, mock.state
    rep = mod.synthetic_report("Harbor View", time.time() - 40 * 86400, "fair")
    rep["data"]["ping"].update(available=False, reason=mod.REPORT_NO_TARGET_PINGS, targets=[], note=mod.report_left_out_note(3))
    rep["data"]["outages"]["note"] = mod.report_left_out_note(3, 2)
    # its network was not identified when the scan started: no router, a note, and the time rule's window
    rep["data"]["meta"]["network"] = dict(mod.REPORT_NETWORK_UNKNOWN)
    rep["data"]["ping"].update(window_reason="network_change", window_start=rep["created_ts"] - 26 * 3600, visits=None, monitored_s=None)
    rep["summary"] = mod.report_summary(rep["data"])
    rid = state._report_add(rep)["id"]
    try:
        dom = browser_page(f"#reports?id={rid}", budget_ms=6000)
        assert 'data-mock-errors="[]"' in dom
        assert re.search(r'<h3 class="rpt-site" id="rpt-site-title">Harbor View</h3>', dom)
        assert "Not collected: No pings of the targets set up when the scan ran were recorded in this window" in dom
        assert '<p class="rpt-note rpt-left-out">Left out: 3 removed or disabled targets</p>' in dom
        assert '<p class="rpt-note rpt-left-out">Left out: 3 removed or disabled targets (2 single-target outages)</p>' in dom
        assert '<p class="rpt-note rpt-net-note">The network was not identified when the scan started' in dom
        assert '<span class="k">Router</span>' not in dom and '<span class="k">Visits</span>' not in dom
    finally:
        state.report_delete(rid)


def test_reports_page_names_the_suggested_site_and_the_network_in_a_browser(browser_page, mock, fast_reports):
    """A scan nobody named on the network of the Acme Dental reports: the progress card says which site it will be saved under (with
    Change, and no name field), and the newest report names the router of its network and counts the visits its pings came from."""
    fast_reports.report_wifi_grace_s = 20.0           # an unavailable Wi-Fi scan keeps the phase waiting while the page is read
    job = fast_reports.report_scan_start(None)
    deadline = time.time() + 5
    while time.time() < deadline and fast_reports.report_scan_job()["phase"] != "wifi":
        time.sleep(0.02)
    assert fast_reports.report_scan_job()["suggested_site"]["site"] == "Acme Dental"
    assert fast_reports.report_scan_wifi(mock.mod.report_wifi_snapshot({"available": False, "state": "no_bridge", "error": "No bridge", "aps": []}))
    dom = browser_page("?wifi=nobridge#reports", budget_ms=6000)
    assert 'data-mock-errors="[]"' in dom
    now = fast_reports.report_scan_job()
    assert now["id"] == job["id"] and now["status"] == "running" and now["site"] is None
    assert ('<span class="rpt-prog-site" id="rpt-prog-site"><span class="muted">Will be saved as </span><strong>Acme Dental</strong>'
            '<span class="muted"> (this network was scanned before)</span></span>') in dom
    assert '<button class="btn btn-sm" type="button" aria-label="Change site name">Change</button>' in dom and '<div class="rpt-prog-name" hidden="">' in dom
    # a screen reader hears where the report goes once, and the name field (when opened) is described by that line
    assert 'role="status">Full scan running, will be saved as Acme Dental</p>' in dom and 'aria-describedby="rpt-prog-site"' in dom
    # the newest report: its router and vendor (a guess: the MAC is locally administered), its two visits listed (the meta line counts
    # them), the window of the site's network on the meta line and headings
    assert re.search(r'<span class="k">Router</span><span class="v"><span class="rpt-router" title="[^"]*"><code class="copy"[^>]*>C2:FF:EE:0A:00:FB</code>'
                     r'<span class="muted">likely Contoso Access Systems</span>', dom)
    assert re.search(r'<span class="k">Visits</span><span class="v"><span class="rpt-visits"><span>[A-Z][a-z]{2} \d{1,2} \d\d:\d\d–[^<]*, [A-Z][a-z]{2} \d', dom)
    assert "2 visits, 2d 6h monitored<span" not in dom, "the count and hours are on the meta line only"
    assert "pings &amp; outages: last 7 days on this network, 2 visits, 2d 6h monitored" in dom
    assert dom.count('<span class="rpt-sec-meta">last 7 days on this network</span>') == 2 and "not monitoring" not in dom
    assert "<span class=\"k\">This PC's MAC</span>" in dom


@pytest.mark.parametrize("query, expect", [("", "ok"), ("?wifi=nobridge", "no_bridge")])
def test_full_scan_wifi_snapshot_from_a_browser(browser_page, mock, fast_reports, query, expect):
    """The page that is open while a full scan reaches its Wi-Fi phase posts exactly one snapshot: the survey through the (fake)
    TNT window bridge, or, in a browser tab without one, why there is none. The fixture refuses the event stream, so the
    page learns about the phase by polling GET /api/reports/scan."""
    job = fast_reports.report_scan_start("Harbor View")
    deadline = time.time() + 5
    while time.time() < deadline and fast_reports.report_scan_job()["phase"] != "wifi":
        time.sleep(0.02)
    assert fast_reports.report_scan_job()["phase"] == "wifi"
    dom = browser_page(query + "#reports", budget_ms=9000)
    assert 'data-mock-errors="[]"' in dom
    deadline = time.time() + 5
    while time.time() < deadline and fast_reports.report_scan_job()["status"] == "running":
        time.sleep(0.05)
    posts = [p for p in fast_reports.report_wifi_posts if p["job_id"] == job["id"]]
    assert len(posts) == 1, posts
    snap, body = posts[0]["snapshot"], posts[0]["body"]
    if expect == "ok":
        assert snap["available"] is True and snap["state"] == "ok" and len(snap["aps"]) >= 15
        assert all(REPORT_AP_KEYS <= set(a) and a["stale"] is False for a in snap["aps"])
        # what the page itself sent: the access points in range, strongest first, without the survey's history, spans or stale flags
        sent = body["aps"]
        assert len(sent) == len(snap["aps"]) and [a["rssi"] for a in sent] == sorted((a["rssi"] for a in sent), reverse=True)
        assert not any({"stale", "spans", "phys", "seen_count", "history", "oui", "vendor"} & set(a) for a in sent)
        assert set(body) == {"available", "state", "error", "collected_ts", "interfaces", "aps"}
        assert fast_reports.report_scan_job()["status"] == "saved"
    else:
        assert snap["available"] is False and snap["state"] == "no_bridge" and "TNT window" in snap["error"]
        assert body["available"] is False and body["aps"] == [] and body["state"] == "no_bridge"
