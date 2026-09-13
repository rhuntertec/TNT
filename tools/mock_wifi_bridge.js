/* TNT mock — tools/mock_wifi_bridge.js (served by tools/mock_api.py as /mock/wifi-bridge.js)
   DEVELOPMENT ONLY: never shipped (it lives under tools/, not ui/). The mock server injects it into
   index.html so the WiFi page has something to show outside the TNT window.

   It defines the survey half of the TNT window's pywebview bridge on window.pywebview.api
   (wifi_survey, wifi_scan_now, wifi_clear, wifi_set_enabled, open_location_settings; any keys
   already there are kept) and simulates a lively, entirely invented radio environment: ~30
   access points on 2.4 / 5 / 6 GHz at 20-320 MHz (one 80+80), multi-AP networks, hidden networks,
   Open / OWE / WEP / WPA / WPA2 / WPA3 / Enterprise, one connected access point, signal random
   walks, access points that show up later, one that drops out and two that flap (one slower than the
   minute reads before the page opened, so its older history has lone readings between gaps). The session is
   backfilled for 20 minutes (the last 5 of them with active reads) so every range has lines. The connected
   access point's link speed steps between Wi-Fi 6 rates (its own seeded walk, so the signal walks stay the
   same) and is 0 while that access point is out of range.
   Every SSID, BSSID, vendor and GUID here is made up; the BSSIDs use locally administered or
   obviously fake OUIs.

   ?wifi=denied | noadapter | off | radiooff | error | starting | empty | late | outdated | nobridge
   switches the simulated state (late: the bridge appears after 1.5 s, like a slow pywebview);
   &select=<network key> (e.g. select=s:Fabrikam%20Mesh) clicks that network in the WiFi page's list
   once it shows up, for screenshots and tests of the highlighted state.

   It also records uncaught errors, unhandled rejections and console.error calls on
   <html data-mock-errors="[...]"> so a headless browser test can read them from the DOM. */
(function () {
  'use strict';

  /* ------------------------------------------------------ error collector */
  const errors = [];
  const flush = () => { try { document.documentElement.setAttribute('data-mock-errors', JSON.stringify(errors.slice(0, 20))); } catch (e) { /* no DOM */ } };
  if (typeof window.addEventListener === 'function') {
    window.addEventListener('error', (e) => { errors.push('error: ' + String((e && (e.message || e.error)) || 'unknown')); flush(); });
    window.addEventListener('unhandledrejection', (e) => { const r = e && e.reason; errors.push('unhandled rejection: ' + String((r && r.message) || r)); flush(); });
  }
  if (typeof console !== 'undefined' && console.error) {
    const orig = console.error;
    console.error = function () { errors.push(Array.prototype.map.call(arguments, (a) => String((a && a.stack) || a)).join(' ')); flush(); return orig.apply(console, arguments); };
  }
  flush();

  const params = new URLSearchParams((window.location && window.location.search) || '');
  const MODE = (params.get('wifi') || '').toLowerCase();
  if (MODE === 'nobridge') return;

  /* -------------------------------------------------------------- the air */
  // vendors of the (invented) base OUIs, mirrored by the mock's GET /api/oui
  // [ssid, bssid, band, primary, centre, width, security, phys, base dBm, extra]
  // extra: {connected, appear: s after load, gone: s after load, flap: period s, spans, beacon}
  const AIR = [
    ['Contoso-Office', 'C0:FF:EE:10:20:01', '2.4', 1, 1, 20, 'WPA2-Personal', ['b', 'g', 'n', 'ax'], -49],
    ['Contoso-Office', 'C0:FF:EE:10:20:02', '5', 36, 42, 80, 'WPA2/WPA3-Personal', ['a', 'n', 'ac', 'ax'], -52, { connected: true }],
    ['Contoso-Office', 'C0:FF:EE:10:20:03', '6', 37, 39, 80, 'WPA3-Personal', ['ax'], -61],
    ['Contoso-Guest', 'C2:FF:EE:10:20:02', '5', 36, 42, 80, 'OWE', ['a', 'n', 'ac', 'ax'], -53],
    ['Contoso-Guest', 'C2:FF:EE:10:20:01', '2.4', 1, 1, 20, 'OWE', ['b', 'g', 'n', 'ax'], -50],
    ['Contoso-Office', 'C0:FF:EE:10:30:02', '5', 149, 155, 80, 'WPA2/WPA3-Personal', ['a', 'n', 'ac', 'ax'], -73],
    ['Contoso-Office', 'C0:FF:EE:10:30:01', '2.4', 11, 11, 20, 'WPA2-Personal', ['b', 'g', 'n', 'ax'], -77],
    ['Fabrikam Mesh', 'F0:0D:CA:55:01:10', '2.4', 6, 8, 40, 'WPA2/WPA3-Personal', ['g', 'n', 'ax'], -57],
    ['Fabrikam Mesh', 'F0:0D:CA:55:01:11', '5', 100, 114, 160, 'WPA2/WPA3-Personal', ['a', 'n', 'ac', 'ax'], -78],
    ['Fabrikam Mesh', 'F0:0D:CA:55:02:11', '5', 132, 134, 40, 'WPA2/WPA3-Personal', ['a', 'n', 'ac', 'ax'], -74],
    ['', 'F2:0D:CA:55:01:11', '5', 100, 114, 160, 'WPA3-Personal', ['a', 'n', 'ac', 'ax'], -79],
    ['Northwind', 'D0:0D:AD:00:0B:01', '2.4', 11, 11, 20, 'WPA2-Personal', ['b', 'g', 'n'], -66],
    ['Northwind-5G', 'D0:0D:AD:00:0B:02', '5', 157, 155, 80, 'WPA2-Personal', ['a', 'n', 'ac'], -70],
    ['PixelPotato', 'EC:0B:0B:9A:00:01', '2.4', 6, 6, 20, 'WPA-Personal', ['b', 'g', 'n'], -83],
    ['Printer-Setup-7F2A', 'DE:BA:5E:7F:2A:01', '2.4', 11, 11, 20, 'Open', ['b', 'g', 'n'], -79],
    ['', 'CC:A7:00:31:00:03', '2.4', 3, 3, 20, 'WPA2-Personal', ['g', 'n'], -74],
    ['Tailspin-IoT', 'CC:A7:00:31:00:09', '2.4', 9, 9, 20, 'WPA2-Personal', ['b', 'g', 'n'], -88, { gone: 45 }],
    ['Coffee Corner', 'DC:BA:5E:C0:FE:13', '2.4', 13, 13, 20, 'OWE', ['g', 'n', 'ax'], -85, { appear: 25 }],
    ['Dockside-Cam', '02:C0:DE:0C:A0:06', '2.4', 6, 6, 20, 'WEP', ['b', 'g'], -90],
    ['Night-Owl', 'EE:0B:0B:14:00:01', '2.4', 14, 14, 20, 'WPA2-Personal', ['b'], -89, { flap: 50 }],
    ['WarehouseScan', 'D2:0D:AD:52:00:01', '5', 52, 54, 40, 'WPA2-Enterprise', ['a', 'n', 'ac'], -77],
    ['WarehouseScan', 'D2:0D:AD:60:00:01', '5', 60, 62, 40, 'WPA2-Enterprise', ['a', 'n', 'ac'], -81],
    ['', 'DE:BA:5E:44:00:01', '5', 44, 44, 20, 'WPA2-Personal', ['a', 'n', 'ac'], -80],
    ['Harbor-Lab', 'DC:BA:5E:80:80:01', '5', 36, 42, 160, 'WPA2/WPA3-Personal', ['a', 'n', 'ac'], -69, { spans: [[5170, 5250], [5490, 5570]] }],
    ['Maple-Guest', 'EC:0B:0B:A5:00:01', '5', 165, 165, 20, 'Open', ['a', 'n', 'ac'], -76],
    ['Maple-Staff', 'EE:0B:0B:A5:00:01', '5', 165, 165, 20, 'WPA3-Enterprise', ['a', 'n', 'ac'], -76],
    ['Lighthouse', 'D0:0D:AD:74:00:01', '5', 116, 118, 40, 'WPA2-Personal', ['a', 'n', 'ac'], -85],
    ['Sunflower', 'CC:A7:00:B1:77:01', '5', 177, 177, 20, 'WPA3-Personal', ['a', 'n', 'ac', 'ax'], -82, { appear: 40 }],
    // flaps slower than the minute reads before the page opened: lone readings with a gap either side
    ['Transit-Hotspot', 'CE:A7:00:64:00:01', '5', 64, 64, 20, 'WPA3-Enterprise 192-bit', ['a', 'n'], -91, { flap: 100 }],
    ['Studio-7', 'F0:0D:CA:07:07:01', '6', 37, 31, 320, 'WPA3-Personal', ['ax', 'be'], -58],
    ['Bench-Lab-6E', 'DC:BA:5E:6E:00:01', '6', 69, 79, 160, 'WPA3-Personal', ['ax'], -64],
    ['Skyline-6G', 'D0:0D:AD:E9:00:01', '6', 233, 233, 20, 'WPA3-Personal', ['ax'], -79],
    ['', 'F2:0D:CA:01:00:01', '6', 1, 1, 20, 'WPA3-Personal', ['ax', 'be'], -83],
  ];
  const IFACE = { guid: '12345678-9abc-4def-8123-456789abcdef', description: 'Intel(R) Wi-Fi 6E AX211 160MHz' };
  const RATE = { b: 11, g: 54, a: 54, n: 150, ac: 433, ax: 600, be: 720 };
  const STEPS_PER_WIDTH = { 20: 1, 40: 2, 80: 4, 160: 8, 320: 16 };
  // the connected access point's link speeds (Mbps, Wi-Fi 6 at 80 MHz), walked by a generator of their own
  const LINK_RATES = [1201, 1080.9, 960.8, 864.7, 720.6, 600.4, 480.4];
  let linkSeed = 424242;
  function linkRand() { linkSeed = (linkSeed * 1103515245 + 12345) % 2147483648; return linkSeed / 2147483648; }

  function channelFreq(band, ch) {
    if (band === '2.4') return ch === 14 ? 2484 : 2407 + 5 * ch;
    if (band === '5') return 5000 + 5 * ch;
    return ch === 2 ? 5935 : 5950 + 5 * ch;
  }
  function generation(phys, band) {
    if (phys.includes('be')) return 'Wi-Fi 7';
    if (phys.includes('ax')) return band === '6' ? 'Wi-Fi 6E' : 'Wi-Fi 6';
    if (phys.includes('ac')) return 'Wi-Fi 5';
    if (phys.includes('n')) return 'Wi-Fi 4';
    return null;
  }
  // a small seeded PRNG so every reload walks the same way
  let seed = 20260911;
  function rand() { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }

  const LOAD = Date.now() / 1000;
  const BACKFILL_S = 1200;
  const ACTIVE_TAIL_S = 300;
  const sim = {
    enabled: MODE !== 'off',
    startedTs: MODE === 'empty' || MODE === 'starting' ? LOAD : LOAD - BACKFILL_S,
    lastRead: null, lastScan: null, lastManualScan: null, leaseFrom: 0, leaseUntil: 0, nextRead: null, visible: new Set(),
    aps: new Map(),     // bssid -> live record
    history: new Map(), // bssid -> [[ts, rssi]]
    link: [],           // [[ts, Mbps]] of the connected access point, 0 while it is out of range
    rateIdx: 1,         // its LINK_RATES entry now
  };

  function visibleAt(def, t) {
    const x = def[9] || {};
    const rel = t - LOAD;
    if (MODE === 'empty') return false;
    if (x.appear != null && rel < x.appear) return false;
    if (x.gone != null && rel >= x.gone) return false;
    if (x.flap) return Math.floor((t - sim.startedTs) / x.flap) % 2 === 0;
    return true;
  }

  function read(t) {
    sim.visible = new Set();
    for (const def of AIR) {
      if (!visibleAt(def, t)) continue;
      const bssid = def[1];
      let rec = sim.aps.get(bssid);
      if (!rec) { rec = { rssi: def[8] + Math.round((rand() - 0.5) * 6), first: t, seen: 0 }; sim.aps.set(bssid, rec); }
      // mean-reverting random walk, a few dB per read
      rec.rssi = Math.max(-95, Math.min(-30, Math.round(rec.rssi + (rand() - 0.5) * 6 + (def[8] - rec.rssi) * 0.2)));
      rec.last = t;
      rec.seen++;
      sim.visible.add(bssid);
      let h = sim.history.get(bssid);
      if (!h) { h = []; sim.history.set(bssid, h); }
      h.push([Math.round(t * 10) / 10, rec.rssi]);
      if (h.length > 8640) h.splice(0, h.length - 8640);
    }
    // the connected access point's link speed: a step now and then, 0 while it is out of range
    const conn = AIR.find((d) => (d[9] || {}).connected);
    const up = !!conn && sim.visible.has(conn[1]);
    if (up) {
      const r = linkRand();
      if (r < 0.1) sim.rateIdx = Math.min(LINK_RATES.length - 1, sim.rateIdx + 1);
      else if (r < 0.2) sim.rateIdx = Math.max(0, sim.rateIdx - 1);
    }
    sim.link.push([Math.round(t * 10) / 10, up ? LINK_RATES[sim.rateIdx] : 0]);
    if (sim.link.length > 8640) sim.link.splice(0, sim.link.length - 8640);
    sim.lastRead = t;
  }

  /** Renew the 30 s active-scan lease (a lease that had run out starts again now). */
  function renew(now) {
    if (sim.leaseUntil < now) sim.leaseFrom = now;
    sim.leaseUntil = now + 30;
  }
  /** Active scanning at time t: the backfilled tail before the page loaded, then only under a lease. */
  function activeAt(t) {
    if (t < LOAD) return t >= LOAD - ACTIVE_TAIL_S;
    return t >= sim.leaseFrom - 0.001 && t <= sim.leaseUntil;
  }

  function catchUp(now) {
    if (!sim.enabled || stateNow(now) !== 'ok') return;
    if (sim.nextRead == null) sim.nextRead = sim.startedTs;
    if (activeAt(now) && sim.nextRead > now + 5) sim.nextRead = now;       // a lease just started
    let guard = 0;
    while (sim.nextRead <= now && guard++ < 5000) {
      const t = sim.nextRead;
      const active = activeAt(t);
      read(t);
      if (active && (!sim.lastScan || t - sim.lastScan >= 10)) sim.lastScan = t;
      sim.nextRead = t + (active ? 5 : 60);
    }
  }

  function stateNow(now) {
    if (!sim.enabled) return 'disabled';
    switch (MODE) {
      case 'denied': return 'location_denied';
      case 'noadapter': return 'no_adapter';
      case 'radiooff': return 'radio_off';
      case 'error': return 'error';
      case 'starting': return now - LOAD < 4 ? 'starting' : 'ok';
      default: return 'ok';
    }
  }
  // like the client, every state but "ok" carries a plain-language message
  const ERRORS = {
    starting: 'Reading the Wi-Fi adapter…',
    disabled: 'The Wi-Fi survey is switched off.',
    location_denied: 'Windows location access is off for TNT (WlanGetNetworkBssList: error 5, access denied)',
    no_adapter: 'No Wi-Fi interface was found',
    radio_off: 'The Wi-Fi radio is switched off',
    error: 'WlanGetNetworkBssList failed (error 1168)',
  };

  function apDict(def, rec, now) {
    const [ssid, bssid, band, channel, centre, width, security, phys] = def;
    const x = def[9] || {};
    const cf = channelFreq(band, centre);
    const spans = x.spans ? x.spans.map((s) => s.slice()) : [[cf - width / 2, cf + width / 2]];
    const first = parseInt(bssid.slice(0, 2), 16);
    const la = (first & 0x02) === 2;
    const oui = bssid.slice(0, 8);
    const stale = !sim.visible.has(bssid) || now - rec.last > 120;
    return {
      bssid, ssid, hidden: !ssid, rssi: rec.rssi, quality: Math.max(0, Math.min(100, 2 * (rec.rssi + 100))),
      band, channel, center_channel: centre, width_mhz: width, freq_mhz: channelFreq(band, channel), spans,
      phy: phys[phys.length - 1], phys: phys.slice(), generation: generation(phys, band), security,
      beacon_ms: x.beacon || 102, max_rate_mbps: Math.round(RATE[phys[phys.length - 1]] * (STEPS_PER_WIDTH[width] || 1) * 10) / 10,
      oui, locally_administered: la, base_oui: la ? ((first & ~0x02).toString(16).padStart(2, '0').toUpperCase() + oui.slice(2)) : null,
      connected: !!x.connected && !stale && sim.enabled, first_seen: rec.first, last_seen: rec.last, seen_count: rec.seen, stale,
    };
  }

  function surveyDict(opts) {
    const now = Date.now() / 1000;
    if (opts && opts.active) renew(now);
    catchUp(now);
    const state = stateNow(now);
    const available = state !== 'no_adapter';
    const aps = [];
    if (state === 'ok' || state === 'disabled') {
      for (const def of AIR) { const rec = sim.aps.get(def[1]); if (rec) aps.push(apDict(def, rec, now)); }
    }
    const hs = opts && opts.history_s;
    const from = hs == null ? -Infinity : now - Number(hs);
    const history = {};
    if (hs !== 0) {
      for (const [bssid, pts] of sim.history) {
        const sel = pts.filter((p) => p[0] >= from);
        if (sel.length) history[bssid] = sel;
      }
    }
    const conn = aps.find((a) => a.connected);
    // like the client: the association's link speeds (the newest reading) and the series in the window of the history
    const newest = sim.link.length ? sim.link[sim.link.length - 1][1] : 0;
    const tx = conn && newest > 0 ? newest : null;
    const rx = tx == null ? null : LINK_RATES[Math.max(0, sim.rateIdx - 1)];
    return {
      available, enabled: sim.enabled, state, error: ERRORS[state] || null,
      started_ts: sim.startedTs, last_read_ts: state === 'ok' ? sim.lastRead : null, last_scan_ts: sim.lastScan,
      active: sim.enabled && activeAt(now), scan_interval_s: 10, passive_interval_s: 60,
      interfaces: available ? [{ guid: IFACE.guid, description: IFACE.description, state: conn ? 'connected' : 'disconnected',
        connected_bssid: conn ? conn.bssid : null, connected_ssid: conn ? conn.ssid : null, rx_rate_mbps: rx, tx_rate_mbps: tx }] : [],
      aps, history, link_history: hs === 0 ? [] : sim.link.filter((p) => p[0] >= from),
    };
  }

  const later = (value, ms) => new Promise((resolve) => setTimeout(() => resolve(JSON.parse(JSON.stringify(value))), ms == null ? 40 : ms));

  const methods = {
    wifi_survey(options) { return later(surveyDict(options || {})); },
    // like the client: refused only while switched off or within 5 s of the last request; in a
    // denied / no-adapter / radio-off / error state it is the retry (which the mock never resolves)
    wifi_scan_now() {
      const now = Date.now() / 1000;
      if (!sim.enabled) return later({ ok: false, error: ERRORS.disabled });
      if (sim.lastManualScan && now - sim.lastManualScan < 5) return later({ ok: false, error: 'A scan was just requested. Try again in a few seconds.' });
      sim.lastManualScan = now;
      renew(now);
      if (stateNow(now) === 'ok') {
        sim.lastScan = now;
        sim.nextRead = Math.min(sim.nextRead == null ? now : sim.nextRead, now + 1.5);
      }
      return later({ ok: true, error: null });
    },
    wifi_clear() {
      sim.aps.clear(); sim.history.clear(); sim.link = []; sim.visible = new Set();
      sim.startedTs = Date.now() / 1000; sim.nextRead = sim.startedTs; sim.lastRead = null;
      return later({ ok: true });
    },
    wifi_set_enabled(on) {
      sim.enabled = !!on;
      if (sim.enabled) sim.nextRead = Date.now() / 1000;
      return later({ ok: true, enabled: sim.enabled });
    },
    open_location_settings() {
      console.info('[mock bridge] would open ms-settings:privacy-location');
      return later({ ok: true });
    },
  };

  function install() {
    window.pywebview = window.pywebview || {};
    const api = window.pywebview.api = window.pywebview.api || {};
    if (MODE === 'outdated') {
      if (typeof api.save_file !== 'function') api.save_file = () => later(null);   // an older window: no survey methods
    } else {
      Object.assign(api, methods);
    }
    try { window.dispatchEvent(new Event('pywebviewready')); } catch (e) { /* no DOM events */ }
  }
  if (MODE === 'late') setTimeout(install, 1500); else install();

  const SELECT = params.get('select');
  if (SELECT && typeof document.querySelector === 'function') {
    let tries = 0;
    const pick = () => {
      const row = Array.from(document.querySelectorAll('.survey-net')).find((r) => r.dataset.key === SELECT);
      if (row) { row.click(); return; }
      if (++tries < 50) setTimeout(pick, 200);
    };
    setTimeout(pick, 300);
  }

  // exposed for the node test that checks the survey dict against the contract
  window.__tntMockWifi = { AIR, surveyDict, methods, MODE };
})();
