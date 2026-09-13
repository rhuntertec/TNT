"""Tests for the IP location (DB-IP Lite) parts of the web UI.

The Internet node's ISP / Location chips and the Settings › IP location status line (js/views/ipinfo.js), the
traceroute Location column, note and attribution (js/tools/traceroute.js), the attribution and licence links, the
Settings group and the ``geoip.state`` event (js/app.js), the API wrappers (js/api.js) and their CSS. The checks are
static plus a node driver for the pure helpers; nothing here talks to a service or to the internet, and every address
is from a documentation range.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "ui"


def _read(rel: str) -> str:
    return (UI / rel).read_text(encoding="utf-8")


def _css_rule(css: str, sel: str) -> str:
    """The declarations of the rule whose selector is exactly ``sel`` (at the start of a line)."""
    m = re.search(r"(?m)^" + re.escape(sel) + r"\s*\{([^}]*)\}", css)
    assert m, f"no CSS rule for {sel}"
    return m.group(1)


# ---------------------------------------------------------------------------
# static markup / CSS
# ---------------------------------------------------------------------------
def test_ip_location_markup_and_css():
    ipinfo = _read("js/views/ipinfo.js")
    for s in ("internetRows(", "'ISP'", "'Location'", "public_geo", "lm-attrib", "geoStatusText", "monthLabel", "nextTryText",
              "sr-only"):
        assert s in ipinfo, s
    # the chip key only grows for rows with screen-reader text: the gateway rows keep today's key and DOM
    assert "(r.tag || '') + ' ' + r.value + (r.sr ? ' ' + r.sr : '')" in ipinfo
    assert "mapEls = { card, pc, gw, inet, l1, l2, attrib }" in ipinfo
    assert "fillChips(mapEls.inet.chips, inetRows)" in ipinfo and "the internet node carries no chips" not in ipinfo

    tr = _read("js/tools/traceroute.js")
    for s in ("th('Location')", "hopLocation", "hasLocations", "hasRouterNames", "locationNote", "'router name'", "tr-loc-src",
              "tr-note", "tr-attrib"):
        assert s in tr, s
    assert "th('Hostname'), th('Location'), th('Min', 'num')" in tr
    assert "form, els.options, els.summary, els.map, els.tableWrap, els.note, els.attrib" in tr
    assert ("TNT.tools.traceroute = { create, rttClass, hopIcon, hopLabel, mergeHop, summaryText, hopLocation, hasLocations,\n"
            "    hasRouterNames, locationNote, RTT_WARN_MS, RTT_BAD_MS };") in tr
    # the tool modules load before app.js: TNT.util / TNT.ui may only be touched inside functions
    top_level = [ln for ln in tr.splitlines() if re.match(r"^  (const|let|var) ", ln)]
    assert not any(("TNT.util." in ln or "TNT.ui." in ln or "TNT.state" in ln) and "=>" not in ln for ln in top_level), top_level

    app = _read("js/app.js")
    for s in ("geoAttribution", "geoLicence", "'IP Geolocation by DB-IP'", "'https://db-ip.com'",
              "'https://creativecommons.org/licenses/by/4.0/'", "'CC BY 4.0'",
              "id: 'settings-geoip'", "role: 'status'", "id: 'settings-geoip-retry'", "'Retry now'",
              "saveSettings({ geoip: { enabled: v } }", "'geoip.state'", "const { ts, ...st } = d",
              "about 65 MB a month", "about 140 MB on disk", "group('IP location'"):
        assert s in app, s
    assert "TNT.openExternal(url, e)" in app and "api.geoipCheck()" in app
    assert re.search(r"TNT\.ui = \{[^}]*\bgeoAttribution, geoLicence \};", app)
    # the status line follows every status refresh and network change
    assert app.count("renderSettingsGateway();\n    renderSettingsGeoip();") == 2
    # the group sits right after Appearance and before Speed tests
    assert app.index("group('Appearance'") < app.index("group('IP location'") < app.index("group('Speed tests'")
    assert not re.search(r"""href=["']https?://""", app)

    api = _read("js/api.js")
    for s in ("geoip: () => api.get('/geoip')", "geoipLookup: (ip) => api.get('/geoip/lookup?ip=' + encodeURIComponent(ip))",
              "geoipCheck: () => api.post('/geoip/check')", "'dhcp.state', 'dhcp.lease', 'dhcp.scan', 'map.sample', 'geoip.state',"):
        assert s in api, s

    css = _read("css/tnt.css")
    new_rules = (".lm-sub > span.muted", ".lm-geo > span.muted:not(.lm-tag)", ".lm-attrib", ".geo-attrib", ".geo-attrib:hover",
                 ".geo-status", ".tr-table td.tr-loc", ".tr-loc-src", ".tr-note", ".tr-attrib")
    for sel in (".lm-attrib", ".geo-attrib", ".geo-status", ".tr-loc", ".tr-loc-src", ".tr-note", ".tr-attrib"):
        assert sel in css, sel
    for sel in new_rules:
        assert not re.search(r"#[0-9A-Fa-f]{3,6}\b", _css_rule(css, sel)), f"hard-coded colour in {sel}"
    assert "flex-wrap: wrap" in _css_rule(css, ".geo-status") and "flex-wrap: wrap" in _css_rule(css, ".tr-attrib")
    assert "text-overflow: ellipsis" in _css_rule(css, ".lm-sub > span.muted")
    # the ISP / Location values are sized like the address chips (11.5 px), not the 16 px body, so provider names fit
    # the chip column; the size is not on .lm-sub > span.muted, which also matches the 9.5 px tags
    assert "font-size: 11.5px" in _css_rule(css, ".linkmap code.copy")
    geo_value = _css_rule(css, ".lm-geo > span.muted:not(.lm-tag)")
    assert "font-size: 11.5px" in geo_value and "font-weight: 700" in geo_value
    assert "font-size" not in _css_rule(css, ".lm-sub > span.muted")
    assert "font-size: 9.5px" in _css_rule(css, ".lm-tag")
    # the link map rules stay in the link map block, the traceroute ones in the tools block
    tools = css.index("tools: traceroute, LAN throughput, subnet calculator")
    assert css.index(".lm-attrib {") < tools < css.index(".tr-note {")
    assert css.index(".lm-geo > span.muted:not(.lm-tag) {") < tools


# ---------------------------------------------------------------------------
# pure helpers, run with node
# ---------------------------------------------------------------------------
_NODE_GEOIP_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const h = (tag, attrs, ...children) => ({ tag, attrs: attrs || {}, children });
const util = { h, relTime: (ts, now) => Math.round(now - ts) + ' s ago', fmtDateTime: (ts) => 'Today, 10:00' };
const window = { TNT: { views: {}, util, api: {}, ui: {}, state: { status: null, now: null } } };
const ctx = vm.createContext({ window, console });
['ipinfo.js', 'traceroute.js'].forEach((n, i) => vm.runInContext(fs.readFileSync(process.argv[2 + i], 'utf8'), ctx, { filename: n }));
const I = window.TNT.views.ipinfo, T = window.TNT.tools.traceroute;
const out = {};

// ---- the Internet node's chip rows
const now = 1788310000;
const ready = { enabled: true, state: 'ready', available: true, month: '2026-09', bytes: 136850953, installed_ts: now - 9000,
  checked_ts: now - 9000, next_check_ts: now + 2500000, download: null, error: null };
const disabled = { enabled: false, state: 'disabled', available: false, month: null, bytes: null, installed_ts: null,
  checked_ts: null, next_check_ts: null, download: null, error: null };
const downloading = { enabled: true, state: 'downloading', available: false, month: null, bytes: null, installed_ts: null, checked_ts: null,
  next_check_ts: now + 30, download: { month: '2026-09', file: 'city', phase: 'download', received: 25000000, total: 60287600 }, error: null };
const failed = { enabled: true, state: 'error', available: false, month: null, bytes: null, installed_ts: null, checked_ts: now - 30,
  next_check_ts: now + 60, download: null, error: 'HTTP 503 from download.db-ip.com' };
const geo = { ip: '203.0.113.5', place: 'Anytown, TX', place_full: 'Anytown, Texas, United States', city: 'Anytown', region: 'Texas',
  region_code: 'TX', country: 'United States', country_code: 'US', lat: 32.95, lon: -96.73, asn: 64500, as_org: 'Example Broadband',
  isp: 'Example Broadband', month: '2026-09' };
const pub = { ip: '203.0.113.5', ts: now - 300, error: null, checked_ts: now - 300 };
const map = (extra) => Object.assign({ public_ip: pub, public_geo: geo }, extra || {});
const proj = (rows) => rows.map((r) => [r.tag, r.value, !!r.plain]);
out.rows = {
  ready: proj(I.internetRows(map(), now, null, ready)),
  oldChange: proj(I.internetRows(map(), now, now - 3600, ready)),
  mismatch: proj(I.internetRows(map({ public_geo: Object.assign({}, geo, { ip: '203.0.113.9' }) }), now, null, ready)),
  checking: proj(I.internetRows(map(), now, now - 30, ready)),
  rechecked: proj(I.internetRows(map({ public_ip: Object.assign({}, pub, { checked_ts: now - 10 }) }), now, now - 30, ready)),
  disabled: proj(I.internetRows(map(), now, null, disabled)),
  geoipNull: proj(I.internetRows(map(), now, null, null)),
  geoipMissing: proj(I.internetRows(map(), now, null, undefined)),
  mapNull: proj(I.internetRows(null, now, null, ready)),
  downloading: proj(I.internetRows(map({ public_geo: null }), now, null, downloading)),
  error: proj(I.internetRows(map({ public_geo: null }), now, null, failed)),
  readyNoGeo: proj(I.internetRows(map({ public_geo: null }), now, null, ready)),
  noPublicIp: proj(I.internetRows(map({ public_ip: { ip: null, ts: null, error: 'timed out', checked_ts: now - 5 }, public_geo: null }), now, null, downloading)),
  ispOnly: proj(I.internetRows(map({ public_geo: Object.assign({}, geo, { place: null, place_full: null }) }), now, null, ready)),
  placeOnly: proj(I.internetRows(map({ public_geo: Object.assign({}, geo, { isp: null }) }), now, null, ready)),
  // a newer month downloading while last month's data still answers: the answer wins
  updating: proj(I.internetRows(map(), now, null, Object.assign({}, downloading, { available: true, month: '2026-08' }))),
};
out.full = I.internetRows(map(), now, null, ready);
out.noAsn = I.internetRows(map({ public_geo: Object.assign({}, geo, { asn: null, as_org: null }) }), now, null, ready);
out.errorRow = I.internetRows(map({ public_geo: null }), now, null, failed)[0];
out.downloadingRow = I.internetRows(map({ public_geo: null }), now, null, downloading)[0];

// ---- Settings › IP location status line
const sept12 = Date.UTC(2026, 8, 12, 12, 0, 0) / 1000, oct1 = Date.UTC(2026, 9, 1, 3, 0, 0) / 1000;
const dl = (d) => Object.assign({}, downloading, { download: Object.assign({}, downloading.download, d) });
out.status = {
  none: I.geoStatusText(null, now),
  notObject: I.geoStatusText('ready', now),
  off: I.geoStatusText(disabled, now),
  verify: I.geoStatusText(dl({ phase: 'verify', received: 60287600 }), now),
  city: I.geoStatusText(downloading, now),
  asnNoTotal: I.geoStatusText(dl({ file: 'asn', received: 12345678, total: null }), now),
  cityDone: I.geoStatusText(dl({ received: 60287600 }), now),
  overTotal: I.geoStatusText(dl({ received: 70000000 }), now),
  installed: I.geoStatusText(ready, now),
  installedNotice: I.geoStatusText(Object.assign({}, ready, { month: '2026-08', error: 'no newer data from DB-IP since 2026-08', next_check_ts: oct1 }), sept12),
  failed: I.geoStatusText(Object.assign({}, failed, { next_check_ts: now + 300 }), now),
  failedNoText: I.geoStatusText(Object.assign({}, failed, { error: null, next_check_ts: null }), now),
  starting: I.geoStatusText(Object.assign({}, disabled, { enabled: true, state: 'starting', next_check_ts: now + 30 }), now),
};
out.month = [I.monthLabel('2026-09'), I.monthLabel('2026-01'), I.monthLabel('2026-12'), I.monthLabel('2026-13'), I.monthLabel('x'), I.monthLabel(null), I.monthLabel(undefined)];
out.next = [I.nextTryText(now + 300, now), I.nextTryText(now + 3600, now), I.nextTryText(now - 50, now), I.nextTryText(now + 3601, now),
  I.nextTryText(now + 21600, now), I.nextTryText(oct1, sept12), I.nextTryText(null, now), I.nextTryText(now + 300, null)];

// ---- traceroute Location column
const loc = (o) => Object.assign({ text: 'Dallas, TX', source: 'hostname', hint: 'dllstx', db_text: 'Dallas, TX', asn: 64510, as_org: 'Example Transit, Inc.' }, o);
const hop = (l, o) => Object.assign({ ttl: 4, ip: '198.51.100.65', hostname: 'ae-1.cr1.dllstx.example.net', kind: 'public', location: l }, o || {});
const hAgree = hop(loc()), hDiffer = hop(loc({ db_text: 'Richardson, TX' }));
const hAccent = hop(loc({ text: 'Dusseldorf, Germany', hint: 'dus', db_text: 'Düsseldorf, Germany' }));
const hDb = hop(loc({ source: 'database', hint: null, asn: 64511, as_org: 'Example Hosting LLC' }), { ip: '203.0.113.80', hostname: null, kind: 'destination' });
const hAsn = hop(loc({ text: null, source: null, hint: null, db_text: null, asn: 64500, as_org: 'Example Broadband' }));
const hLan = { ttl: 1, ip: '192.0.2.1', kind: 'gateway', location: null };
const hSilent = { ttl: 5, ip: null, kind: 'unknown', location: loc() };
out.loc = {
  agree: T.hopLocation(hAgree), accent: T.hopLocation(hAccent), differ: T.hopLocation(hDiffer), database: T.hopLocation(hDb),
  asnOnly: T.hopLocation(hAsn), lan: T.hopLocation(hLan), silent: T.hopLocation(hSilent), noLocation: T.hopLocation({ ttl: 2, ip: '198.51.100.1' }),
  none: T.hopLocation(null),
};
out.hasLoc = [T.hasLocations([hLan, hAsn]), T.hasLocations([hLan, { ttl: 2, ip: '198.51.100.1', location: null }]), T.hasLocations([hSilent]),
  T.hasLocations([]), T.hasLocations(null), T.hasLocations([hDb])];
out.hasNames = [T.hasRouterNames([hLan, hDb, hAgree]), T.hasRouterNames([hLan, hDb, hAsn]), T.hasRouterNames([hSilent]), T.hasRouterNames(null)];
out.note = [T.locationNote(null), T.locationNote(undefined), T.locationNote(disabled), T.locationNote(ready), T.locationNote(downloading),
  T.locationNote(failed), T.locationNote(Object.assign({}, disabled, { enabled: true, state: 'starting' }))];
process.stdout.write(JSON.stringify(out));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_ip_location_helpers_with_node(tmp_path):
    driver = tmp_path / "driver.js"
    driver.write_text(_NODE_GEOIP_DRIVER, encoding="utf-8")
    files = [UI / "js/views/ipinfo.js", UI / "js/tools/traceroute.js"]
    r = subprocess.run(["node", str(driver)] + [str(f) for f in files], capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)

    # --- the Internet node: ISP then Location, only for this network's current public address
    rows = out["rows"]
    both = [["ISP", "Example Broadband", True], ["Location", "Anytown, TX", True]]
    assert rows["ready"] == both and rows["oldChange"] == both and rows["rechecked"] == both and rows["updating"] == both
    for k in ("mismatch", "checking", "disabled", "geoipNull", "geoipMissing", "mapNull", "readyNoGeo", "noPublicIp"):
        assert rows[k] == [], k
    assert rows["downloading"] == [["Location", "downloading data…", True]]
    assert rows["error"] == [["Location", "unavailable", True]]
    assert rows["ispOnly"] == [["ISP", "Example Broadband", True]]
    assert rows["placeOnly"] == [["Location", "Anytown, TX", True]]
    isp, place = out["full"]
    assert isp == {"tag": "ISP", "value": "Example Broadband", "plain": True, "cls": "lm-geo", "data": True,
                   "title": "AS64500 Example Broadband · internet provider of the public address (a VPN or proxy shows its own)",
                   "sr": "Internet provider of the public address: Example Broadband, AS64500 Example Broadband"}
    assert place == {"tag": "Location", "value": "Anytown, TX", "plain": True, "cls": "lm-geo", "data": True,
                     "title": "Anytown, Texas, United States · approximate location of the public address (a VPN or proxy shows its own)",
                     "sr": "Approximate location of the public address: Anytown, Texas, United States"}
    assert "AS64500 Example Broadband" in isp["title"] and "(a VPN or proxy shows its own)" in place["title"]
    assert "AS64500 Example Broadband" in isp["sr"]
    no_asn = out["noAsn"][0]
    assert no_asn["title"] == "Internet provider of the public address (a VPN or proxy shows its own)"
    assert no_asn["sr"] == "Internet provider of the public address: Example Broadband"
    # the waiting rows are not looked-up data: no attribution for them
    assert "see Settings › IP location" in out["errorRow"]["title"] and "data" not in out["errorRow"]
    assert "about 65 MB" in out["downloadingRow"]["title"] and "data" not in out["downloadingRow"]

    # --- Settings › IP location
    assert out["status"] == {
        "none": "Not available on this service",
        "notObject": "Not available on this service",
        "off": "Off: nothing is downloaded and no addresses are looked up",
        "verify": "Checking the September 2026 data…",
        "city": "Downloading the September 2026 city data… 40%",
        "asnNoTotal": "Downloading the September 2026 ISP data… 10 MB",
        "cityDone": "Downloading the September 2026 city data… 100%",
        "overTotal": "Downloading the September 2026 city data… 100%",
        "installed": "Installed: September 2026 data",
        "installedNotice": "Installed: August 2026 data · no newer data from DB-IP since 2026-08 · next try on 1 October",
        "failed": "Download failed: HTTP 503 from download.db-ip.com · next try within the hour",
        "failedNoText": "Download failed: unknown error",
        "starting": "No data yet: the service downloads it shortly",
    }
    assert out["month"] == ["September 2026", "January 2026", "December 2026", "2026-13", "x", "", ""]
    assert out["next"] == ["within the hour", "within the hour", "within the hour", "in about 2 h", "in about 6 h", "on 1 October", "", ""]

    # --- traceroute: the Location cell
    loc = out["loc"]
    transit = "AS64510 Example Transit, Inc."
    assert loc["agree"] == {"text": "Dallas, TX", "src": "router name",
                            "title": 'From the router name "dllstx" (the IP location database agrees) · ' + transit,
                            "label": 'Dallas, TX. From the router name "dllstx" (the IP location database agrees) · ' + transit}
    assert loc["accent"] == {"text": "Dusseldorf, Germany", "src": "router name",
                             "title": 'From the router name "dus" (the IP location database agrees) · ' + transit,
                             "label": 'Dusseldorf, Germany. From the router name "dus" (the IP location database agrees) · ' + transit}
    assert loc["differ"] == {"text": "Dallas, TX", "src": "router name",
                             "title": 'From the router name "dllstx" (IP location database: Richardson, TX) · ' + transit,
                             "label": 'Dallas, TX. From the router name "dllstx" (IP location database: Richardson, TX) · ' + transit}
    assert loc["database"] == {"text": "Dallas, TX", "src": None,
                               "title": "From the IP location database · AS64511 Example Hosting LLC",
                               "label": "Dallas, TX. From the IP location database · AS64511 Example Hosting LLC"}
    assert loc["asnOnly"] == {"text": None, "src": None,
                              "title": "No city known for this address · AS64500 Example Broadband",
                              "label": "No location. No city known for this address · AS64500 Example Broadband"}
    for k in ("lan", "silent", "noLocation", "none"):
        assert loc[k] is None, k
    assert out["hasLoc"] == [True, False, False, False, False, True]
    assert out["hasNames"] == [True, False, False, False]
    assert out["note"] == [None, None, "Location is off (Settings › IP location)", None, "Location: downloading the IP location data…",
                           "Location: no IP location data yet (Settings › IP location)",
                           "Location: no IP location data yet (Settings › IP location)"]


# ---------------------------------------------------------------------------
# the traceroute card's note follows geoip.state (update()), run with node on a tiny fake DOM
# ---------------------------------------------------------------------------
_NODE_TRACE_UPDATE_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
class El {
  constructor(tag) { this.tag = tag; this.children = []; this.hidden = false; this.className = ''; this.attrs = {}; this.dataset = {};
    this._text = ''; this.textWrites = 0; }
  appendChild(c) { this.children.push(c); return c; }
  addEventListener() {}
  setAttribute(k, v) { this.attrs[k] = v; }
  set innerHTML(v) { this.children = []; this._text = ''; }
  get textContent() { return this._text + this.children.map((c) => (typeof c === 'string' ? c : c.textContent)).join(''); }
  set textContent(v) { this.textWrites++; this._text = String(v); this.children = []; }
}
const h = (tag, attrs, ...children) => {
  const el = new El(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') el.className = v || ''; else if (k === 'hidden' || k === 'value') el[k] = v; else if (k !== 'on') el.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c != null) el.appendChild(c);
  return el;
};
const now = 1788310000;
const trace = { host: 'example.net', target_ip: '203.0.113.80', ts: now - 60, max_hops: 30, probes: 3, timeout_ms: 1500, complete: true,
  error: null, duration_s: 1.2, pc: { ip: '192.0.2.10', hostname: null }, gateway: null,
  hops: [{ ttl: 1, ip: '192.0.2.1', hostname: null, kind: 'gateway', location: null, min_ms: 1, avg_ms: 1, max_ms: 1, loss: 0 },
    { ttl: 2, ip: '203.0.113.80', hostname: null, kind: 'destination', min_ms: 20, avg_ms: 21, max_ms: 22, loss: 0,
      location: { text: 'Dallas, TX', source: 'database', hint: null, db_text: 'Dallas, TX', asn: 64511, as_org: 'Example Hosting LLC' } }] };
const state = { status: null, now };
const toggle = () => { const el = h('label'); el.input = h('input'); el.input.checked = true; return el; };
const window = { TNT: { util: { h, copyCode: (ip) => h('code', null, ip), fmtMs: (v) => String(v), nowS: () => now },
  ui: { icon: () => h('svg'), toggle, busy: () => {}, toast: () => {}, geoAttribution: () => h('a', null, 'IP Geolocation by DB-IP') },
  api: { traceroute: async () => trace, tracerouteLast: async () => ({ running: false, trace }), events: { on: () => () => {} } },
  state } };
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), vm.createContext({ window, console }), { filename: 'traceroute.js' });
const geo = {
  downloading: { enabled: true, state: 'downloading', available: false },
  ready: { enabled: true, state: 'ready', available: true },
  disabled: { enabled: false, state: 'disabled', available: false },
};
(async () => {
  const t = window.TNT.tools.traceroute.create();
  const find = (cls) => t.body.children.find((c) => c.className && c.className.split(' ').includes(cls));
  const note = find('tr-note'), attrib = find('tr-attrib');
  const snap = () => ({ hidden: note.hidden, text: note.textContent, attrib: attrib.hidden });
  const out = {};
  out.beforeMount = (t.update(), snap());               // not mounted: a no-op that does not throw
  state.status = { geoip: geo.downloading };
  t.mount();
  t.update();
  out.noHops = snap();                                   // no trace on screen yet: no note even while downloading
  await new Promise((r) => setImmediate(r));
  out.downloading = snap();                              // loadLast rendered the table
  state.status = { geoip: geo.ready };
  t.update();
  out.ready = snap();                                    // the data arrived: the note goes without a new trace
  const writes = note.textWrites;
  t.update();
  out.sameStateWrites = note.textWrites - writes;        // nothing changed: the note text is not rewritten
  state.status = { geoip: geo.disabled };
  t.update();
  out.off = snap();                                      // switched off in Settings while the trace shows
  state.status = null;
  t.update();
  out.olderService = snap();
  state.status = { geoip: geo.downloading };
  t.update();
  out.backOn = snap();
  t.unmount();
  state.status = { geoip: geo.disabled };
  t.update();
  out.afterUnmount = snap();                             // unmounted: update() leaves the card alone
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_traceroute_location_note_follows_geoip_state_with_node(tmp_path):
    driver = tmp_path / "driver.js"
    driver.write_text(_NODE_TRACE_UPDATE_DRIVER, encoding="utf-8")
    r = subprocess.run(["node", str(driver), str(UI / "js/tools/traceroute.js")], capture_output=True, text=True, encoding="utf-8",
                       timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    hidden = {"hidden": True, "text": "", "attrib": True}
    assert out["beforeMount"] == hidden and out["noHops"] == hidden
    downloading = {"hidden": False, "text": "Location: downloading the IP location data…", "attrib": False}
    assert out["downloading"] == downloading
    assert out["ready"] == {"hidden": True, "text": "", "attrib": False}
    assert out["sameStateWrites"] == 0
    assert out["off"] == {"hidden": False, "text": "Location is off (Settings › IP location)", "attrib": False}
    assert out["olderService"] == {"hidden": True, "text": "", "attrib": False}
    assert out["backOn"] == downloading
    assert out["afterUnmount"] == downloading
