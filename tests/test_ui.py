"""Tests for the web UI (ui/) and its development server (tools/mock_api.py).

The UI itself is plain HTML/CSS/JS with no build step, so the checks here are structural
(script order, view registration, no external resources, theme tokens, font fallback) plus
a syntax pass with node when it is installed.  The mock API server is stdlib-only and does
not import ``tnt``; it is loaded straight from its file and run on an ephemeral port so
every ``/api`` route can be exercised, including the SSE stream.
"""
from __future__ import annotations

import http.client
import importlib.util
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional, Tuple

import pytest

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "ui"
MOCK = ROOT / "tools" / "mock_api.py"
JS_FILES = [
    "js/api.js", "js/charts.js", "js/hosttable.js",
    "js/tools/subnet.js", "js/tools/traceroute.js", "js/tools/lan.js", "js/tools/subnetcalc.js", "js/tools/wifi.js",
    "js/views/ipinfo.js", "js/views/ping.js",
    "js/views/outages.js", "js/views/speed.js", "js/views/discovery.js", "js/views/tools.js", "js/egg.js", "js/app.js",
]
VIEW_NAMES = ["ipinfo", "ping", "outages", "speed", "discovery", "tools"]


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
    assert "DEVICE_TYPE_CLASS = { router: 'blue', 'dw server': 'purple', camera: 'orange', phone: 'green', wifi: 'yellow' }" in ht
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
    assert "tools: 'var(--red)'" in app and "'discovery', 'tools'" in app
    assert "tools:" in app and "warning:" in app and "dhcp:" in app  # icons
    assert "tileEls.tools" in app and "DHCP client" in app and "Tools for the field" in app
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
    assert "repeat(6, minmax(0, 1fr))" in css
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
  none: view.deviceType(null),
};
out.classify = {
  router: view.classifyDevice({ ip: '10.0.0.251', open_ports: [80, 443] }, '10.0.0.251'),
  routerList: view.classifyDevice({ ip: '192.168.1.1', open_ports: [7001] }, ['10.0.0.251', '192.168.1.1']),
  routerBeatsService: view.classifyDevice({ ip: '10.0.0.251', open_ports: [7001, 554, 5060, 22], vendor: 'Ubiquiti Inc.' }, '10.0.0.251'),
  dw: view.classifyDevice({ ip: '10.0.0.112', open_ports: [7001, 8000] }, '10.0.0.251'),
  camera: view.classifyDevice({ ip: '10.0.0.35', open_ports: [80, 554] }, null),
  phone: view.classifyDevice({ ip: '10.0.0.62', open_ports: [80, 5060] }, null),
  wifi: view.classifyDevice({ ip: '10.0.0.240', open_ports: [22, 80], vendor: 'Ubiquiti Networks Inc.' }, null),
  wifiCase: view.classifyDevice({ ip: '10.0.0.241', open_ports: [22], vendor: 'UBIQUITI INC' }, null),
  sshNotUbiquiti: view.classifyDevice({ ip: '10.0.0.130', open_ports: [22], vendor: 'Raspberry Pi Trading Ltd' }, null),
  ubiquitiNoSsh: view.classifyDevice({ ip: '10.0.0.9', open_ports: [80, 443], vendor: 'Ubiquiti Inc.' }, null),
  noPorts: view.classifyDevice({ ip: '10.0.0.9', open_ports: [] }, null),
  noVendor: view.classifyDevice({ ip: '10.0.0.9', open_ports: [22] }, null),
  nothing: view.classifyDevice(null, null),
};
out.badges = {};
for (const t of window.TNT.hosttable.DEVICE_TYPES) out.badges[t] = view.deviceTypeClass(t);
out.badges.unknown = view.deviceTypeClass(null);
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
                                 "fallback": "Camera", "none": None}
    assert out["classify"] == {"router": "Router", "routerList": "Router", "routerBeatsService": "Router",
                               "dw": "DW Server", "camera": "Camera", "phone": "Phone", "wifi": "Wifi",
                               "wifiCase": "Wifi", "sshNotUbiquiti": None, "ubiquitiNoSsh": None,
                               "noPorts": None, "noVendor": None, "nothing": None}
    assert out["badges"] == {"Router": "blue", "DW Server": "purple", "Camera": "orange", "Phone": "green",
                             "Wifi": "yellow", "unknown": "grey"}
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
    assert "minmax(0, 1fr)" in decl(".tiles").get("grid-template-columns", "")
    assert "repeat(3, minmax(0, 1fr))" in _css_decls(_css_media(css, "(max-width: 1100px)"), ".tiles").get("grid-template-columns", "")
    assert "repeat(2, minmax(0, 1fr))" in _css_decls(_css_media(css, "(max-width: 700px)"), ".tiles").get("grid-template-columns", "")
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
              "targets", "outages", "speed", "discovery", "netinfo", "settings", "map", "dhcp"):
        assert k in s, k
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
    assert n["adapters"][0]["index"] == 12  # internet-facing first
    a = n["adapters"][0]
    assert a["subnets"][0]["network"] == "10.0.0.0/24" and a["subnets"][0]["gateways"] == ["10.0.0.251"]


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
    assert st == 200 and {x["host"] for x in lst} >= {"10.0.0.251", "1.1.1.1", "totalelectronics.com"}


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
    assert types == {"Router", "DW Server", "Camera", "Phone", "Wifi"}
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
    assert set(pub) == {"ip", "ts", "error"} and pub["ip"] == "203.0.113.5" and pub["error"] is None
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
            assert set(h) == {"ttl", "ip", "alt_ips", "hostname", "rtts", "avg_ms", "min_ms", "max_ms", "loss", "responder_status", "kind", "label"}
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
        # the events: start, one hop per hop (in ttl order), done
        got = _drain(q, "trace.", "trace.done")
        kinds = [k for k, _ in got]
        assert kinds[0] == "trace.start" and kinds[-1] == "trace.done" and kinds.count("trace.hop") == 9, kinds
        assert got[0][1] == {"host": "totalelectronics.com", "target_ip": "203.0.113.80", "max_hops": 30, "probes": 3}
        assert [d["hop"]["ttl"] for k, d in got if k == "trace.hop"] == list(range(1, 10))
        assert got[-1][1] == {"host": "totalelectronics.com", "target_ip": "203.0.113.80", "hops": 9, "complete": True, "duration_s": tr["duration_s"]}
    finally:
        mock.state.hub.unsubscribe(q)
    st, _, last = _req(mock.port, "GET", "/api/tools/traceroute/last")
    assert st == 200 and last["running"] is False and last["trace"] == tr
    # the hop limit cuts the path short: incomplete with an error text
    st, _, tr4 = _req(mock.port, "POST", "/api/tools/traceroute", {"host": "totalelectronics.com", "max_hops": 4, "resolve_names": False})
    assert st == 200 and tr4["complete"] is False and len(tr4["hops"]) == 4 and tr4["error"] and all(h["hostname"] is None for h in tr4["hops"])
    # a LAN address is one hop straight to the destination
    st, _, tr1 = _req(mock.port, "POST", "/api/tools/traceroute", {"host": "10.0.0.251"})
    assert st == 200 and len(tr1["hops"]) == 1 and tr1["hops"][0]["kind"] == "destination" and tr1["target_ip"] == "10.0.0.251" and tr1["complete"] is True
    # 409 while one runs
    mock.state.trace_running = True
    try:
        st, _, err = _req(mock.port, "POST", "/api/tools/traceroute", {"host": "1.1.1.1"})
        assert st == 409 and err["error"]["code"] == "conflict"
        st, _, last = _req(mock.port, "GET", "/api/tools/traceroute/last")
        assert last["running"] is True
    finally:
        mock.state.trace_running = False


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


def test_diagnostics_and_log_tail(mock):
    st, _, d = _req(mock.port, "GET", "/api/diagnostics")
    assert st == 200
    for k in ("service", "os", "api", "db", "logs", "ping", "outages", "speedtest", "discovery", "threads",
              "memory_mb", "cpu_pct", "recent_log", "recent_events", "errors_24h"):
        assert k in d, k
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
