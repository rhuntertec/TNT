/* TNT — views/wifi.js
   The WiFi page: a survey of every access point (BSSID) this PC can see, or has seen since TNT
   was opened — a network list, a sortable radio table, signal strength over time and one
   spectrum chart per band (2.4 / 5 / 6 GHz) where each access point is a shape as tall as its
   signal and as wide as its channel. Clicking a network (in the list, a table row or a shape)
   highlights all of its access points everywhere; clicking it again clears the highlight.

   The data never comes from the service API. Since Windows 11 24H2 the WLAN calls that list
   BSSIDs need the calling user's location consent, which the LocalSystem service does not have,
   so the survey runs inside the TNT window (TNT.exe) and reaches this page through the pywebview
   bridge: window.pywebview.api.wifi_survey / wifi_scan_now / wifi_clear / wifi_set_enabled /
   open_location_settings. Only 24-bit OUIs go to the service (GET /api/oui) for vendor names.
   In a plain browser tab there is no bridge and the page explains where the survey lives.

   Also owns TNT.wifiSurvey, the bridge client the WiFi tile on the dashboard shares (app.js).
   Loaded before app.js: TNT.util / TNT.ui are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  const POLL_MS = 2000;            // page on screen: one wifi_survey({active: true}) every 2 s
  const TILE_POLL_MS = 15000;      // dashboard tile: a cheap summary every 15 s
  const CALL_TIMEOUT_MS = 10000;   // a bridge call that has not answered by now counts as failed
  const BRIDGE_GRACE_MS = 2500;    // pywebview injects its bridge shortly after the page loads
  const HISTORY_MARGIN_S = 15;     // overlap when asking only for the readings since the last one
  const MAX_POINTS = 8640;         // per BSSID, like the client (24 h at one point per 10 s)
  const RANGE_STORE = 'tnt.wifi.range';
  const SORT_STORE = 'tnt.wifi.sort';
  const RANGES = [{ value: 300, label: '5 m' }, { value: 900, label: '15 m' }, { value: 3600, label: '1 h' }, { value: 0, label: 'All' }];
  /** The narrowest window the signal chart shows (seconds), however little history there is yet. */
  const MIN_WINDOW_S = 60;
  const BAND_ORDER = { '2.4': 0, '5': 1, '6': 2 };
  const PHY_ORDER = ['b', 'a', 'g', 'n', 'ac', 'ax', 'be'];
  const LOAD_MS = Date.now();
  const LATENCY_NOTE = "Scanning makes the Wi-Fi adapter hop across channels, which can briefly add latency to this PC's own Wi-Fi connection.";
  const EMPTY_6GHZ = 'No 6 GHz networks seen. Seeing 6 GHz needs a Wi-Fi 6E or Wi-Fi 7 adapter.';
  const EMPTY_6GHZ_CAPABLE = 'No 6 GHz networks in range.';
  const SORT_MARGIN_DB = 6;        // a row passes the one above it only when more than this much stronger

  const W = () => TNT.wifichart;

  /* ============================================================ pure helpers */
  /** A network is an SSID; a hidden network (no SSID) is one network per BSSID. */
  function networkKey(ap) {
    if (!ap) return '';
    return ap.hidden || !ap.ssid ? 'b:' + String(ap.bssid || '').toUpperCase() : 's:' + ap.ssid;
  }
  function networkName(ap) {
    if (!ap) return '';
    return ap.hidden || !ap.ssid ? String(ap.bssid || '?').toUpperCase() + ' (hidden)' : String(ap.ssid);
  }

  /** Group access points into networks: [{key, name, hidden, aps, count, best, bestAp, connected,
   *  bands, stale}] where best is the strongest live signal (a stale one only when all are stale). */
  function groupNetworks(aps) {
    const byKey = new Map();
    for (const ap of aps || []) {
      if (!ap || !ap.bssid) continue;
      const key = networkKey(ap);
      let n = byKey.get(key);
      if (!n) { n = { key, name: networkName(ap), hidden: !!(ap.hidden || !ap.ssid), aps: [], count: 0, best: null, bestAp: null, connected: false, bands: [], stale: true }; byKey.set(key, n); }
      n.aps.push(ap);
      n.count++;
      if (ap.connected) n.connected = true;
      if (!ap.stale) n.stale = false;
      if (ap.band && !n.bands.includes(ap.band)) n.bands.push(ap.band);
    }
    for (const n of byKey.values()) {
      const live = n.aps.filter((a) => !a.stale && a.rssi != null);
      const pool = live.length ? live : n.aps.filter((a) => a.rssi != null);
      for (const a of pool) if (!n.bestAp || a.rssi > n.bestAp.rssi) n.bestAp = a;
      n.best = n.bestAp ? n.bestAp.rssi : null;
      n.bands.sort((a, b) => (BAND_ORDER[a] - BAND_ORDER[b]));
    }
    return Array.from(byKey.values());
  }

  /** `items` in the order last shown: keys found in `prevOrder` in that order, anything new after them. */
  function keepOrder(items, prevOrder, keyOf) {
    const pos = new Map((prevOrder || []).map((k, i) => [k, i]));
    return (items || []).map((it, i) => ({ it, i, p: pos.has(keyOf(it)) ? pos.get(keyOf(it)) : Infinity }))
      .sort((a, b) => (a.p === b.p ? a.i - b.i : a.p - b.p)).map((x) => x.it);
  }

  /** A strongest-first order that does not shuffle with the jitter of every read. Rows start in the order
   *  of `prevOrder` (new ones after, by value, then `tie`) and an insertion pass lets a row pass the one above
   *  it only when its group comes first (`groupOf`, lower first) or, in the same group, its value is more
   *  than `margin` higher; against a row that is new on this pass, any higher value passes. Without a
   *  previous order this is an exact sort. Signals jump a few dB between reads, so with a margin of 6 dB a
   *  row moves only for a real change. */
  function stickyOrder(items, prevOrder, keyOf, groupOf, valueOf, margin, tie) {
    const pos = new Map((prevOrder || []).map((k, i) => [k, i]));
    const arr = (items || []).map((it, i) => {
      const k = keyOf(it), raw = valueOf(it), v = raw == null ? NaN : Number(raw);     // no value sorts last
      return { it, g: Number(groupOf(it)) || 0, v: isFinite(v) ? v : -Infinity, p: pos.has(k) ? pos.get(k) : Infinity, i };
    });
    arr.sort((a, b) => (a.p !== b.p ? (a.p < b.p ? -1 : 1) : (a.g - b.g) || (b.v > a.v ? 1 : b.v < a.v ? -1 : 0) || (tie ? tie(a.it, b.it) : 0) || (a.i - b.i)));
    const m = Math.max(0, Number(margin) || 0);
    for (let i = 1; i < arr.length; i++) {
      const x = arr[i];
      let j = i;
      while (j > 0) {
        const y = arr[j - 1];
        const passes = x.g !== y.g ? x.g < y.g : x.v - y.v > (x.p === Infinity || y.p === Infinity ? 0 : m);
        if (!passes) break;
        arr[j] = y;
        j--;
      }
      arr[j] = x;
    }
    return arr.map((x) => x.it);
  }

  /** Strongest first; networks with nothing live sink to the bottom; a tie goes by name. Given the order
   *  shown last, a network passes another only when more than `margin` dB stronger (stickyOrder). */
  function sortNetworks(nets, prevOrder, margin) {
    return stickyOrder(nets, prevOrder, (n) => n.key, (n) => (n.stale ? 1 : 0), (n) => (n.best == null ? -999 : n.best), margin,
      (a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
  }

  /** The row a key press in the network list moves to (null: the key does nothing). `cols` > 1 when the
   *  list is laid out as a grid (narrow windows): up/down move a whole row of cells, left/right one. */
  function listKeyTarget(key, index, count, cols) {
    const c = Math.max(1, cols || 1);
    if (!count) return null;
    const clampI = (i) => Math.max(0, Math.min(count - 1, i));
    switch (key) {
      case 'ArrowDown': return clampI(index + c);
      case 'ArrowUp': return clampI(index - c);
      case 'ArrowRight': return c > 1 ? clampI(index + 1) : null;
      case 'ArrowLeft': return c > 1 ? clampI(index - 1) : null;
      case 'Home': return 0;
      case 'End': return count - 1;
      default: return null;
    }
  }

  /** A hidden access point's label on the spectrum charts: short, with the last two octets to tell them apart. */
  function hiddenLabel(bssid) {
    const parts = String(bssid || '').toUpperCase().split(':');
    return 'hidden …' + (parts.length >= 2 ? parts.slice(-2).join(':') : parts.join(''));
  }

  /** What the 6 GHz card says with nothing on the band: an adapter whose name says it can hear 6 GHz
   *  (6E, Wi-Fi 7, BE200 ...) just has nothing in range; otherwise the hint about the adapter. */
  function sixGhzEmptyText(interfaces) {
    const descs = (interfaces || []).map((i) => String((i && i.description) || ''));
    return descs.some((d) => /\b6E\b|wi-?fi\s*7\b|\bBE\d{3}\b|802\.11be/i.test(d)) ? EMPTY_6GHZ_CAPABLE : EMPTY_6GHZ;
  }

  /** The text filter over the network list: name or any BSSID, case-insensitive. */
  function filterNetworks(nets, text) {
    const q = String(text || '').trim().toLowerCase();
    if (!q) return (nets || []).slice();
    return (nets || []).filter((n) => n.name.toLowerCase().includes(q) || n.aps.some((a) => String(a.bssid || '').toLowerCase().includes(q)));
  }

  /** 32-bit FNV-1a of a string. */
  function fnv1a(s) {
    let h = 0x811c9dc5;
    s = String(s);
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
    return h >>> 0;
  }

  /** One stable colour per network for the whole session. A network prefers the palette slot its
   *  name hashes to (so the same SSID tends to get the same colour next time too); a slot another
   *  network already holds sends it on to the next free one. Once given, a colour never changes. */
  function createColorBook(size) {
    const n = size || (TNT.wifichart ? TNT.wifichart.PALETTE_SIZE : 24);
    const map = new Map();
    const STRIDE = 5;   // coprime with 24: walks every slot
    return {
      size: n,
      get(key) { return map.has(key) ? map.get(key) : null; },
      assign(keys) {
        const used = new Set(map.values());
        for (const key of keys || []) {
          if (map.has(key)) continue;
          const pref = fnv1a(key) % n;
          let slot = pref;
          for (let i = 0; i < n; i++) {
            const s = (pref + i * STRIDE) % n;
            if (!used.has(s)) { slot = s; break; }
          }
          map.set(key, slot);
          used.add(slot);
        }
        return keys ? keys.map((k) => map.get(k)) : [];
      },
      clear() { map.clear(); },
    };
  }

  /** Index of the first point at or after ts in a time-sorted list. */
  function lowerIndex(pts, ts) {
    let lo = 0, hi = pts.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (pts[mid][0] < ts) lo = mid + 1; else hi = mid; }
    return lo;
  }

  /** Merge history readings into a cache: {bssid: [[ts, dBm], ...]} sorted by time, one point per
   *  timestamp (an incoming reading replaces a cached one), nothing older than `cutoff`, at most
   *  `maxPoints` (the newest) per BSSID. Returns a new object; neither input is modified (an untouched
   *  series may keep its array). The cache is this function's own output (sorted and clean), so a poll
   *  only checks the readings that came in, appends them and merges the few that overlap the cached
   *  tail; the cutoff is a binary search. A 24 h session costs about as much as a fresh one. */
  function mergeHistory(cache, incoming, cutoff, maxPoints) {
    const out = {};
    const cap = maxPoints || MAX_POINTS;
    const cut = cutoff == null ? -Infinity : cutoff;
    const old = cache || {}, inc = incoming || {};
    const keys = new Set(Object.keys(old).concat(Object.keys(inc)));
    for (const k of keys) {
      const base = Array.isArray(old[k]) ? old[k] : [];
      let add = [];
      let inOrder = true;
      for (const p of Array.isArray(inc[k]) ? inc[k] : []) {
        if (!Array.isArray(p) || p.length < 2 || !isFinite(p[0]) || p[1] == null || !isFinite(p[1])) continue;
        const ts = Number(p[0]);
        if (ts < cut) continue;
        if (add.length && ts < add[add.length - 1][0]) inOrder = false;
        add.push([ts, Number(p[1])]);
      }
      if (!inOrder) add.sort((a, b) => a[0] - b[0]);
      if (add.length > 1) {                        // one point per timestamp: the later incoming one
        const once = [];
        for (const p of add) { if (once.length && once[once.length - 1][0] === p[0]) once[once.length - 1] = p; else once.push(p); }
        add = once;
      }
      const from = lowerIndex(base, cut);
      let list;
      if (!add.length) list = from ? base.slice(from) : base;
      else {
        const at = Math.max(from, lowerIndex(base, add[0][0]));   // cached readings from here on overlap
        const tail = base.slice(at);
        let merged = add;
        if (tail.length) {
          merged = [];
          let i = 0, j = 0;
          while (i < tail.length || j < add.length) {
            if (j >= add.length || (i < tail.length && tail[i][0] < add[j][0])) merged.push(tail[i++]);
            else { if (i < tail.length && tail[i][0] === add[j][0]) i++; merged.push(add[j++]); }
          }
        }
        list = at > from ? base.slice(from, at).concat(merged) : merged;
      }
      if (list.length > cap) list = list.slice(list.length - cap);
      if (list.length) out[k] = list;
    }
    return out;
  }

  /** The readings of one BSSID inside [t0, t1] (binary search over a time-sorted list). */
  function pointsInRange(points, t0, t1) {
    const pts = points || [];
    const lower = (t) => { let lo = 0, hi = pts.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (pts[mid][0] < t) lo = mid + 1; else hi = mid; } return lo; };
    const a = t0 == null ? 0 : lower(t0);
    let b = pts.length;
    if (t1 != null) { b = lower(t1); while (b < pts.length && pts[b][0] === t1) b++; }
    return pts.slice(a, b);
  }

  /** [t0, t1] of the chart for a range in seconds (0 = the whole session). The window starts no earlier
   *  than the oldest reading shown (`earliestTs`), so a range longer than the history collected so far
   *  fills the chart instead of squeezing every line against its right edge; it spans at least
   *  MIN_WINDOW_S. */
  function rangeWindow(rangeS, now, startedTs, earliestTs) {
    let start = rangeS ? now - rangeS : (startedTs && startedTs < now ? startedTs : now - 300);
    if (earliestTs != null && isFinite(earliestTs) && earliestTs > start) start = Math.min(earliestTs, now - MIN_WINDOW_S);
    return [start, now];
  }

  /** How much history to ask the bridge for: the whole range on a first read (null = the session) or
   *  while no BSS-list read has been seen yet; after that only the readings since `lastReadTs`, the
   *  last_read_ts of the survey applied last, with a margin. The client never stamps a reading earlier
   *  than the read before the one that produced it (a beacon can be delivered late, so the newest point
   *  held is no safe baseline), which makes this window catch every later reading. */
  function historyRequest(rangeS, completeFrom, lastReadTs, now) {
    if (completeFrom == null || lastReadTs == null) return rangeS ? rangeS : null;
    const since = Math.ceil(now - lastReadTs + HISTORY_MARGIN_S);
    return Math.max(HISTORY_MARGIN_S, rangeS ? Math.min(rangeS, since) : since);
  }

  /** Channel column: "36 · 80 MHz"; 2.4 GHz bonded channels and 80+80 name their centre too. */
  function channelText(ap) {
    if (!ap || ap.channel == null) return { text: '—', sub: '', title: '' };
    const width = Number(ap.width_mhz) || 20;
    const spans = W() ? W().apSpans(ap) : [];
    let text = ap.channel + ' · ' + width + ' MHz';
    let sub = '';
    if (spans.length > 1) { text = ap.channel + ' · 80+80 MHz'; sub = 'centre ' + ap.center_channel; }
    else if (ap.band === '2.4' && width > 20 && ap.center_channel != null && ap.center_channel !== ap.channel) sub = 'centre ' + ap.center_channel;
    const bandLabel = ap.band ? ap.band + ' GHz' : '';
    const range = spans.map((s) => Math.round(s[0]) + '–' + Math.round(s[1]) + ' MHz').join(' + ');
    const title = [bandLabel, 'primary channel ' + ap.channel + (ap.freq_mhz ? ' (' + ap.freq_mhz + ' MHz)' : ''),
      ap.center_channel != null ? 'centre channel ' + ap.center_channel : '', width + ' MHz wide', range].filter(Boolean).join(' · ');
    return { text, sub, title };
  }

  /** PHY column: "n, ac, ax" (every PHY advertised, oldest first). */
  function phyText(ap) {
    const list = ap && Array.isArray(ap.phys) && ap.phys.length ? ap.phys : (ap && ap.phy ? [ap.phy] : []);
    return list.length ? list.join(', ') : '—';
  }

  /** Badge colour for a security string: open / WEP red, WPA (TKIP era) yellow, WPA2 / WPA3 / OWE /
   *  Enterprise green, unknown grey. */
  function securityClass(sec) {
    const s = String(sec || '').toLowerCase();
    if (!s || s === 'unknown') return 'grey';
    if (s === 'open' || s.includes('wep')) return 'red';
    if (s.startsWith('wpa-')) return 'yellow';
    return 'green';
  }

  /** Vendor column from the OUI lookups ({oui: name|null}, a Map or a plain object). A locally
   *  administered BSSID (a virtual or random address) names the vendor of its base OUI as "likely". */
  function vendorText(ap, vendors) {
    const get = (k) => (!k ? undefined : vendors && typeof vendors.get === 'function' ? vendors.get(k) : (vendors || {})[k]);
    if (!ap) return { text: '—', muted: true, title: '' };
    if (ap.locally_administered) {
      if (!ap.base_oui) return { text: 'Private address', muted: true, title: 'Locally administered BSSID (not a registered vendor address)' };
      const v = get(ap.base_oui);
      if (v === undefined) return { text: '…', muted: true, title: 'Looking up ' + ap.base_oui };
      if (!v) return { text: 'Private address', muted: true, title: 'Locally administered BSSID; ' + ap.base_oui + ' is not a known vendor' };
      return { text: 'likely ' + v, muted: false, title: 'Locally administered BSSID — the address it is derived from (' + ap.base_oui + ') belongs to ' + v };
    }
    const v = get(ap.oui);
    if (v === undefined) return { text: '…', muted: true, title: ap.oui ? 'Looking up ' + ap.oui : '' };
    if (!v) return { text: '—', muted: true, title: 'Unknown vendor' + (ap.oui ? ' (' + ap.oui + ')' : '') };
    return { text: String(v), muted: false, title: 'OUI ' + ap.oui };
  }

  /** The OUIs worth looking up for a list of access points (base OUIs for locally administered ones). */
  function vendorPrefixes(aps) {
    const out = new Set();
    for (const ap of aps || []) {
      const p = ap && (ap.locally_administered ? ap.base_oui : ap.oui);
      if (p && /^[0-9A-F]{2}(:[0-9A-F]{2}){2}$/.test(p)) out.add(p);
    }
    return Array.from(out);
  }

  /** What to say instead of data: {kind, title, text, actions} for every state that is not "ok",
   *  or null when the page should just show the survey. bridge: 'ready' | 'waiting' | 'none' | 'outdated'. */
  function stateInfo(survey, bridge, callError) {
    if (bridge === 'none') {
      return { kind: 'nobridge', title: 'The Wi-Fi survey runs in the TNT window',
        text: "It uses this PC's own Wi-Fi adapter and needs Windows location permission, so it only works inside the TNT app, not in a browser tab. Open TNT from the tray icon or the Start menu and pick the WiFi tile.", actions: [] };
    }
    if (bridge === 'outdated') {
      return { kind: 'outdated', title: 'This TNT window has no Wi-Fi survey yet',
        text: 'The page is newer than the TNT window around it. Update TNT, then open the window again.', actions: [] };
    }
    if (bridge === 'waiting') return { kind: 'waiting', title: 'Connecting to the TNT window…', text: '', actions: [] };
    if (!survey) {
      if (callError) return { kind: 'error', title: 'The TNT window did not answer', text: callError, actions: ['retry'] };
      return { kind: 'waiting', title: 'Starting the survey…', text: '', actions: [] };
    }
    const err = survey.error ? String(survey.error) : '';
    switch (survey.state) {
      case 'ok': return null;
      case 'starting': return null;
      case 'disabled': return { kind: 'disabled', title: 'Survey off', text: 'TNT is not reading nearby Wi-Fi networks. Switch the survey on to see them.', actions: ['enable'] };
      case 'location_denied': return { kind: 'location_denied', title: 'Location access needed',
        text: 'Windows only shows nearby access points to apps that may use your location. In Settings › Privacy & security › Location, turn on Location services and "Let desktop apps access your location", then try again.', detail: err, actions: ['location', 'retry'] };
      case 'no_adapter': return { kind: 'no_adapter', title: 'No Wi-Fi adapter', text: 'This PC has no Wi-Fi adapter TNT can use, or the WLAN AutoConfig service is stopped.', detail: err, actions: ['retry'] };
      case 'radio_off': return { kind: 'radio_off', title: 'Wi-Fi is turned off', text: "Turn Wi-Fi on (quick settings, or the adapter's switch) to survey nearby networks.", detail: err, actions: ['retry'] };
      // the client's own words go in the mono detail line, like the other states
      case 'error': return { kind: 'error', title: 'The Wi-Fi survey hit a problem', text: 'Something went wrong while reading nearby networks.', detail: err, actions: ['retry'] };
      default: return { kind: 'error', title: 'The Wi-Fi survey hit a problem', text: 'Something went wrong while reading nearby networks.', detail: err || 'Unknown survey state "' + survey.state + '".', actions: ['retry'] };
    }
  }

  /** The dashboard tile: {kind, headline, detail, networks, aps, top} (top = the connected network, or
   *  the strongest one: {name, rssi, cls, bars, connected, band, channel}). */
  function tileSummary(survey, bridge, callError) {
    if (bridge === 'waiting') return { kind: 'waiting', headline: 'Loading…', detail: '' };
    if (bridge === 'none') return { kind: 'nobridge', headline: 'Open in the TNT window', detail: 'The Wi-Fi survey runs in the TNT app' };
    if (bridge === 'outdated') return { kind: 'outdated', headline: 'Update TNT', detail: 'This window has no Wi-Fi survey' };
    if (!survey && callError) return { kind: 'error', headline: 'Survey not answering', detail: String(callError) };
    if (!survey) return { kind: 'waiting', headline: 'Starting the survey…', detail: '' };
    const short = { disabled: ['Survey off', 'Switch it on in the WiFi page'], location_denied: ['Location access needed', 'Windows is blocking the Wi-Fi scan'],
      no_adapter: ['No Wi-Fi adapter', 'Nothing to survey with'], radio_off: ['Wi-Fi is off', 'Turn the radio on to survey'], error: ['Survey error', 'Open the WiFi page for details'] };
    if (short[survey.state]) return { kind: survey.state, headline: short[survey.state][0], detail: String(short[survey.state][1] || '') };
    const aps = Array.isArray(survey.aps) ? survey.aps : [];
    const live = aps.filter((a) => !a.stale);
    const nets = groupNetworks(live);
    const pick = live.find((a) => a.connected) || live.slice().sort((a, b) => b.rssi - a.rssi)[0] || null;
    const WC = W();
    const top = pick ? { name: networkName(pick), rssi: pick.rssi, cls: WC ? WC.signalClass(pick.rssi) : 'grey', bars: WC ? WC.signalBars(pick.rssi) : 0,
      connected: !!pick.connected, band: pick.band, channel: pick.channel } : null;
    return { kind: survey.state === 'starting' && !aps.length ? 'starting' : 'ok', headline: survey.state === 'starting' && !aps.length ? 'Starting the survey…' : '',
      detail: '', networks: nets.length, aps: live.length, top };
  }

  /* ========================================================== bridge client */
  function errText(err) {
    if (!err) return 'unknown error';
    if (typeof err === 'string') return err;
    return err.message || String(err);
  }
  function withTimeout(promise, ms) {
    let timer = null;
    const t = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('the TNT window did not answer in time')), ms); });
    return Promise.race([promise, t]).finally(() => clearTimeout(timer));
  }

  /** Calls into window.pywebview.api that never overlap: a survey call still running is shared, a
   *  call stuck past CALL_TIMEOUT_MS is given up on, and at most two stuck calls may pile up. */
  const survey = {
    last: null,          // the latest survey dict from any caller (tile or page)
    lastOkMs: 0,
    error: null,         // why the last survey call failed (null when it worked)
    pending: 0,          // raw bridge calls that have not settled yet
    inflight: null,      // the survey call running now (settles within CALL_TIMEOUT_MS)
    inflightKey: null,   // ... and the options it was made with
    readyFired: false,
    _ready: null,        // callbacks for 'pywebviewready'

    api() {
      const pw = window.pywebview;
      const a = pw && pw.api;
      return a && typeof a.wifi_survey === 'function' ? a : null;
    },
    /** 'ready' | 'waiting' (the bridge may still be injected) | 'outdated' (a bridge without the survey) | 'none'. */
    bridgeState() {
      if (this.api()) return 'ready';
      const pw = window.pywebview;
      if (pw && pw.api && typeof pw.api.save_file === 'function') return 'outdated';
      if (!this.readyFired && Date.now() - LOAD_MS < BRIDGE_GRACE_MS) return 'waiting';
      return 'none';
    },
    /** Run fn when pywebview announces its bridge ('pywebviewready'); returns an unsubscribe. */
    hook(fn) {
      if (!this._ready) {
        this._ready = new Set();
        if (typeof window.addEventListener === 'function') {
          window.addEventListener('pywebviewready', () => {
            this.readyFired = true;
            for (const f of Array.from(this._ready)) { try { f(); } catch (e) { console.error(e); } }
          });
        }
      }
      if (fn) this._ready.add(fn);
      return () => { if (fn) this._ready.delete(fn); };
    },
    /** wifi_survey(opts) -> the survey dict, or null when there is no bridge or the call failed.
     *  A call with the same options already running is shared; one with other options waits for it,
     *  so the tile's summary read can never stand in for the page's read (which carries history). */
    fetch(opts) {
      opts = opts || {};
      const key = JSON.stringify(opts);
      if (this.inflight) return this.inflightKey === key ? this.inflight : this.inflight.then(() => this.fetch(opts));
      const a = this.api();
      if (!a) return Promise.resolve(null);
      if (this.pending >= 2) { this.error = 'the TNT window is not answering'; return Promise.resolve(null); }
      this.pending++;
      const raw = Promise.resolve().then(() => a.wifi_survey(opts));
      raw.then(() => { this.pending--; }, () => { this.pending--; });
      const p = withTimeout(raw, CALL_TIMEOUT_MS).then((r) => {
        if (r && typeof r === 'object' && Array.isArray(r.aps)) {
          this.last = r; this.lastOkMs = Date.now(); this.error = null;
          return r;
        }
        this.error = r && r.error ? String(r.error) : 'the TNT window sent an unexpected reply';
        return null;
      }, (err) => { this.error = errText(err); return null; })
        .finally(() => { if (this.inflight === p) { this.inflight = null; this.inflightKey = null; } });
      this.inflight = p;
      this.inflightKey = key;
      return p;
    },
    /** Any other bridge method; always resolves, {ok: false, error} when it could not be called. */
    call(name, ...args) {
      const pw = window.pywebview;
      const a = pw && pw.api;
      if (!a || typeof a[name] !== 'function') return Promise.resolve({ ok: false, error: 'The TNT window has no ' + name });
      return withTimeout(Promise.resolve().then(() => a[name](...args)), CALL_TIMEOUT_MS)
        .then((r) => (r && typeof r === 'object' ? r : { ok: !!r }), (err) => ({ ok: false, error: errText(err) }));
    },
    /** The dashboard tile's background read: every 15 s while the dashboard is visible and the WiFi
     *  page is not mounted (the page polls far more often and feeds `last` itself), and at once when
     *  the window comes back from the tray (the survey session starts then). While the survey is still
     *  "starting" (its first read takes a moment) it looks again after 2 s instead of 15 s. */
    startTilePolling(onUpdate) {
      let soon = null;
      const tick = () => {
        if (typeof document !== 'undefined' && document.hidden) return;
        if (TNT.state && TNT.state.view === 'wifi') return;
        if (!this.api()) { if (onUpdate) onUpdate(); return; }
        this.fetch({ active: false, history_s: 0 }).then((r) => {
          if (onUpdate) onUpdate();
          if (r && r.state === 'starting' && !soon) soon = setTimeout(() => { soon = null; tick(); }, 2000);
        });
      };
      this.hook(tick);
      if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
        document.addEventListener('visibilitychange', () => { if (!document.hidden) setTimeout(tick, 250); });
      }
      setTimeout(tick, 300);
      setTimeout(() => { if (onUpdate) onUpdate(); }, BRIDGE_GRACE_MS + 50);
      return setInterval(tick, TILE_POLL_MS);
    },
  };
  TNT.wifiSurvey = survey;

  /* =============================================================== the page */
  let root = null;
  let els = {};
  let charts = { signal: null, bands: {} };
  let table = null;
  let timer = null;
  let unsubs = [];
  let data = null;               // the survey applied to the page
  let history = {};              // bssid -> [[ts, dBm]] merged from every read
  let historyComplete = null;    // the cache holds every reading from this ts on (null = refetch)
  let historyStarted = null;     // the session (started_ts) the cache belongs to
  let lastReadSeen = null;       // last_read_ts of the survey applied last (the incremental baseline)
  let rangeS = loadRange();
  let selected = null;           // network key; kept while you visit other pages
  let filterText = '';
  let busyToggle = false;
  let listSig = '';
  let legendSig = '';
  let netOrder = [];             // network keys in the order the list showed them last
  let tableOrder = [];           // BSSIDs in the order the table showed them last
  const cellHtml = new WeakMap(); // table cell -> the HTML it was built with (changed cells only are replaced)
  let revealSelected = false;    // scroll the list to the selected network after the next render
  let resetListScroll = false;   // the next list render starts at the top (after Clear or a new filter)
  const colors = createColorBook();
  const vendors = new Map();     // OUI -> vendor | null
  const vendorPending = new Set();
  let vendorRetryMs = 0;

  function loadRange() {
    try { const v = parseInt(localStorage.getItem(RANGE_STORE), 10); if (RANGES.some((r) => r.value === v)) return v; } catch (e) { /* ignore */ }
    return 900;
  }
  const nowS = () => Date.now() / 1000;
  const aps = () => (data && Array.isArray(data.aps) ? data.aps : []);

  function schedule(ms) {
    if (timer) clearTimeout(timer);
    timer = root ? setTimeout(poll, ms) : null;
  }

  async function poll() {
    timer = null;
    if (!root) return;
    if (document.hidden) { schedule(POLL_MS); return; }   // no lease renewals while nobody looks
    const bs = survey.bridgeState();
    if (bs !== 'ready') { render(); schedule(bs === 'waiting' ? 400 : POLL_MS); return; }
    const want = historyRequest(rangeS, historyComplete, lastReadSeen, nowS());
    const r = await survey.fetch({ active: true, history_s: want });
    if (!root) return;
    apply(r, want);
    schedule(POLL_MS);
  }

  function apply(r, asked) {
    if (!r) { render(); return; }
    const now = nowS();
    let reset = false;
    if (historyStarted !== r.started_ts) {      // a new session (Clear, or TNT.exe restarted)
      reset = historyStarted !== null || historyComplete !== null;
      history = {}; historyComplete = null; historyStarted = r.started_ts;
    }
    lastReadSeen = typeof r.last_read_ts === 'number' ? r.last_read_ts : null;
    const needFrom = rangeS ? now - rangeS : (r.started_ts || 0);
    history = mergeHistory(history, r.history || {}, needFrom - 60, MAX_POINTS);
    if (historyComplete == null) {
      const from = asked == null ? (r.started_ts || 0) : Math.max(r.started_ts || 0, now - asked);
      // a session that changed under an incremental read may hold older readings: fetch them next time
      historyComplete = reset && from > needFrom + 1 ? null : from;
    }
    data = r;
    render();
  }

  /* ------------------------------------------------------------ actions */
  /** Select a network (or clear it when it is selected). From a chart or the table the list then scrolls
   *  its row into view, so the network's swatch and signal are on screen too. */
  function toggleSelect(key, source) {
    selected = selected === key ? null : key;
    revealSelected = !!selected && source !== 'list';
    render();
  }

  /** The pointer is over `el`, or keyboard focus is inside it: rows must not move under either. (A mouse
   *  click leaves focus on a row without :focus-visible, so the list re-sorts once the pointer leaves.) */
  function interacting(el) {
    try { return !!el && (el.matches(':hover') || !!el.querySelector(':focus-visible')); } catch (e) { return false; }
  }

  async function setEnabled(on) {
    if (busyToggle) return;
    busyToggle = true;
    els.toggle.classList.add('busy');
    const r = await survey.call('wifi_set_enabled', !!on);
    busyToggle = false;
    if (!root) return;
    els.toggle.classList.remove('busy');
    if (!r || r.ok === false) TNT.ui.toast('Could not switch the survey ' + (on ? 'on' : 'off') + (r && r.error ? ': ' + r.error : ''), 'error');
    else TNT.ui.toast(r.enabled ? 'Wi-Fi survey on' : 'Wi-Fi survey off — no more Wi-Fi scans', r.enabled ? 'ok' : 'warn');
    schedule(0);
  }

  async function scanNow() {
    TNT.ui.busy(els.scanBtn, true, 'Scanning…');
    const r = await survey.call('wifi_scan_now');
    if (!root) return;
    setTimeout(() => { if (root) TNT.ui.busy(els.scanBtn, false); render(); }, r && r.ok !== false ? 1500 : 0);
    if (!r || r.ok === false) TNT.ui.toast((r && r.error) || 'Could not start a scan', 'warn');
    schedule(0);
    if (r && r.ok !== false) setTimeout(() => { if (root) schedule(0); }, 4500);   // the results of the scan land ~4 s later
  }

  async function clearSurvey() {
    const ok = await TNT.ui.confirm({ title: 'Clear the Wi-Fi survey?', message: 'Every access point and all signal history from this session is forgotten. The survey starts again right away.', ok: 'Clear', danger: true });
    if (!ok || !root) return;
    const r = await survey.call('wifi_clear');
    if (!root) return;
    if (!r || r.ok === false) { TNT.ui.toast('Could not clear the survey' + (r && r.error ? ': ' + r.error : ''), 'error'); return; }
    history = {}; historyComplete = null; historyStarted = null; lastReadSeen = null; data = null; selected = null; listSig = '';
    netOrder = []; tableOrder = []; resetListScroll = true;
    if (els.netList) els.netList.scrollTop = 0;
    if (survey.last) survey.last = null;
    TNT.ui.toast('Survey cleared', 'ok');
    render();
    schedule(0);
  }

  async function openLocationSettings() {
    const r = await survey.call('open_location_settings');
    if (root && (!r || r.ok === false)) TNT.ui.toast('Could not open the Windows location settings' + (r && r.error ? ': ' + r.error : ''), 'error');
  }

  function requestVendors() {
    if (Date.now() < vendorRetryMs) return;
    const want = vendorPrefixes(aps()).filter((p) => !vendors.has(p) && !vendorPending.has(p)).slice(0, 256);
    if (!want.length || !TNT.api || !TNT.api.ouiVendors) return;
    want.forEach((p) => vendorPending.add(p));
    TNT.api.ouiVendors(want).then((r) => {
      const v = (r && r.vendors) || {};
      for (const p of want) vendors.set(p, v[p] == null ? null : String(v[p]));
      if (root) renderTable();
    }, (err) => {
      // an older service without /api/oui: stop asking for a while; anything else: retry soon
      vendorRetryMs = Date.now() + (err && (err.status === 404 || err.status === 400) ? 300000 : 30000);
    }).finally(() => { want.forEach((p) => vendorPending.delete(p)); });
  }

  /* ------------------------------------------------------------- render */
  function render() {
    if (!root) return;
    const bs = survey.bridgeState();
    const info = stateInfo(data, bs, bs === 'ready' ? survey.error : null);
    renderControls(bs);
    renderStatus(bs);
    renderState(info);
    const showData = bs === 'ready' && data && (!info || aps().length > 0);
    els.content.hidden = !showData;
    if (!showData) return;
    // strongest first, but a few dB of jitter moves no row (SORT_MARGIN_DB), and frozen while the pointer
    // or the keyboard is in the list (a click must land on the network that was under the pointer)
    const grouped = groupNetworks(aps());
    const nets = interacting(els.netList) ? keepOrder(grouped, netOrder, (n) => n.key) : sortNetworks(grouped, netOrder, SORT_MARGIN_DB);
    netOrder = nets.map((n) => n.key);
    colors.assign(nets.map((n) => n.key));
    if (selected && !nets.some((n) => n.key === selected)) selected = null;
    renderNetworks(nets);
    if (revealSelected) { revealSelected = false; revealSelectedRow(); }
    renderTable();
    renderCharts(nets);
    requestVendors();
  }

  function renderControls(bs) {
    const ready = bs === 'ready';
    const enabled = !!(data && data.enabled);
    // a browser tab or an older window has no survey to switch: no controls that pretend otherwise; before
    // the first answer the switch is left out rather than shown "Off"
    const noSurvey = bs === 'none' || bs === 'outdated';
    els.switchWrap.hidden = noSurvey || !data;
    els.scanBtn.hidden = noSurvey;
    els.clearBtn.hidden = noSurvey;
    if (!busyToggle) els.toggle.setChecked(ready && enabled);
    els.toggle.input.disabled = !ready || !data || busyToggle;
    const scanning = els.scanBtn.dataset.busy === '1';
    if (!scanning) els.scanBtn.disabled = !ready || !data || !enabled || ['no_adapter', 'radio_off', 'disabled'].includes(data.state);
    els.clearBtn.disabled = !ready || !data;
  }

  function renderStatus(bs) {
    const { h, relTime } = TNT.util;
    const el = els.status;
    el.innerHTML = '';
    if (bs !== 'ready' || !data) { el.hidden = true; els.note.hidden = true; return; }
    const now = nowS();
    const all = aps();
    const live = all.filter((a) => !a.stale);
    const running = data.state === 'ok' || data.state === 'starting';
    const parts = [];
    if (running) {
      if (data.active) parts.push(h('span', { class: 'survey-live' }, h('span', { class: 'spark-icon' }, TNT.ui.icon('spark')), 'Scanning every ' + (data.scan_interval_s || 10) + ' s'));
      else parts.push(h('span', null, 'Background reads every ' + (data.passive_interval_s || 60) + ' s'));
      parts.push(h('span', null, data.last_read_ts ? 'read ' + relTime(data.last_read_ts, now) : (data.state === 'starting' ? 'starting…' : 'no read yet')));
    }
    // counts only while the survey runs or old data is on screen: "0 access points" under a blocked
    // survey would read as an empty neighbourhood. In range, like the dashboard tile; out of range apart
    if (running || all.length) {
      const liveNets = groupNetworks(live).length;
      parts.push(h('span', null, live.length + (live.length === 1 ? ' access point' : ' access points') + ' · ' + liveNets + (liveNets === 1 ? ' network' : ' networks')));
      const stale = all.length - live.length;
      if (stale) parts.push(h('span', { title: 'Seen earlier in this session, not in the latest read' }, stale + ' out of range'));
    }
    const iface = (data.interfaces || [])[0];
    if (iface) {
      parts.push(h('span', { title: iface.guid ? 'Interface ' + iface.guid : '' }, iface.description || 'Wi-Fi adapter',
        iface.connected_ssid ? ' · connected to ' : (iface.state ? ' · ' + String(iface.state).replace(/_/g, ' ') : ''), iface.connected_ssid ? h('strong', null, iface.connected_ssid) : null));
    }
    if (survey.error) parts.push(h('span', { class: 'survey-callerr' }, 'last call failed: ' + survey.error));
    parts.forEach((p, i) => { if (i) el.appendChild(h('span', { class: 'survey-dot', 'aria-hidden': 'true' }, '·')); el.appendChild(p); });
    el.hidden = !parts.length;
    els.note.hidden = !running;
  }

  /** "Try again" on the state card: busy while the request runs, a refusal (one scan per 5 s) as a toast. */
  async function retryNow(btn) {
    if (btn.dataset.busy === '1') return;
    TNT.ui.busy(btn, true, 'Trying…');
    const r = await survey.call('wifi_scan_now');
    if (!root) return;
    const ok = r && r.ok !== false;
    if (!ok) TNT.ui.toast((r && r.error) || 'Could not ask the Wi-Fi adapter again', 'warn');
    schedule(0);
    // the card goes away by itself when the survey recovers; otherwise the button comes back after the read
    setTimeout(() => { if (btn.isConnected) TNT.ui.busy(btn, false); }, ok ? 2500 : 0);
  }

  function renderState(info) {
    const { h } = TNT.util;
    const el = els.state;
    const sig = info ? info.kind + '|' + info.title + '|' + (info.detail || '') + '|' + info.text : '';
    if (el.dataset.sig === sig) return;
    el.dataset.sig = sig;
    el.innerHTML = '';
    el.hidden = !info;
    if (!info) return;
    el.dataset.kind = info.kind;
    const icon = { nobridge: 'computer', outdated: 'refresh', waiting: 'spark', disabled: 'wifi', location_denied: 'target', no_adapter: 'wifi', radio_off: 'wifi', error: 'warning' }[info.kind] || 'info';
    const buttons = [];
    for (const a of info.actions || []) {
      if (a === 'location') buttons.push(h('button', { class: 'btn btn-primary', type: 'button', on: { click: openLocationSettings } }, TNT.ui.icon('gear'), 'Open location settings'));
      if (a === 'enable') buttons.push(h('button', { class: 'btn btn-primary', type: 'button', on: { click: () => setEnabled(true) } }, TNT.ui.icon('play'), 'Turn the survey on'));
      if (a === 'retry') buttons.push(h('button', { class: 'btn', type: 'button', on: { click: (e) => retryNow(e.currentTarget) } }, TNT.ui.icon('refresh'), 'Try again'));
    }
    el.appendChild(h('div', { class: 'survey-state-icon' + (info.kind === 'waiting' ? ' spark-icon' : '') }, TNT.ui.icon(icon)));
    el.appendChild(h('div', { class: 'survey-state-body' },
      h('h3', null, info.title),
      info.text ? h('p', null, info.text) : null,
      info.detail ? h('p', { class: 'survey-state-detail' }, info.detail) : null,
      buttons.length ? h('div', { class: 'row', style: { marginTop: '6px' } }, buttons) : null));
  }

  function swatch(key, stale) {
    const i = colors.get(key);
    return TNT.util.h('span', { class: 'survey-sw' + (stale ? ' stale' : ''), style: { background: stale ? null : W().paletteCss(i == null ? 0 : i) }, 'aria-hidden': 'true' });
  }

  function bars(rssi, stale) {
    const { h } = TNT.util;
    const n = W().signalBars(rssi);
    const cls = stale ? 'grey' : W().signalClass(rssi);
    const el = h('span', { class: 'survey-bars ' + cls, 'aria-hidden': 'true' });
    for (let i = 1; i <= 4; i++) el.appendChild(h('span', { class: i <= n ? 'on' : '' }));
    return el;
  }

  function dbmPill(rssi, stale) {
    const cls = stale ? 'grey' : W().signalClass(rssi);
    return TNT.util.h('span', { class: 'survey-dbm ' + cls, title: stale ? 'Last reading (out of range now)' : '' }, W().dbmText(rssi));
  }

  function renderNetworks(nets) {
    const { h } = TNT.util;
    const shown = filterNetworks(nets, filterText);
    els.netCount.textContent = String(nets.length);
    const sig = JSON.stringify([selected, filterText, shown.map((n) => [n.key, n.count, n.best, n.connected, n.stale, n.bands.join(), colors.get(n.key)])]);
    if (sig === listSig) return;
    listSig = sig;
    const list = els.netList;
    const focusedKey = list.contains(document.activeElement) && document.activeElement.dataset ? document.activeElement.dataset.key : null;
    const scroll = resetListScroll ? 0 : list.scrollTop;
    resetListScroll = false;
    list.innerHTML = '';
    if (!shown.length) {
      list.appendChild(h('div', { class: 'survey-net-empty' }, nets.length ? 'No network matches "' + filterText + '"' : 'No networks seen yet'));
      return;
    }
    const tabKey = shown.some((n) => n.key === focusedKey) ? focusedKey : (shown.some((n) => n.key === selected) ? selected : shown[0].key);
    for (const n of shown) {
      const isSel = n.key === selected;
      const bands = n.bands.map((b) => b + ' GHz').join(', ');
      const row = h('div', {
        class: 'survey-net' + (isSel ? ' selected' : '') + (n.stale ? ' stale' : '') + (n.hidden ? ' hidden-net' : ''),
        role: 'option', 'aria-selected': String(isSel), tabindex: n.key === tabKey ? '0' : '-1', data: { key: n.key },
        title: n.name + ' · ' + n.count + (n.count === 1 ? ' access point' : ' access points') + (bands ? ' · ' + bands : '') + (isSel ? ' · click to clear the highlight' : ' · click to highlight'),
      },
      swatch(n.key, n.stale),
      h('span', { class: 'survey-net-main' },
        // a hidden network: its BSSID (it has no other name) and a "hidden" badge that the ellipsis never cuts
        h('span', { class: 'survey-net-name' }, n.hidden ? String((n.aps[0] && n.aps[0].bssid) || '?').toUpperCase() : n.name),
        h('span', { class: 'survey-net-sub' },
          n.hidden ? h('span', { class: 'badge grey', title: 'This network does not broadcast its name' }, 'hidden') : null,
          n.connected ? h('span', { class: 'badge green', title: 'This PC is connected to this network' }, 'connected') : null,
          h('span', { class: 'survey-net-meta' }, n.count + (n.count === 1 ? ' AP' : ' APs') + (bands ? ' · ' + bands : '') + (n.stale ? ' · out of range' : '')))),
      h('span', { class: 'survey-net-side' },
        bars(n.best, n.stale),
        h('span', { class: 'survey-net-dbm ' + (n.stale ? 'grey' : W().signalClass(n.best)) }, W().dbmText(n.best))));
      list.appendChild(row);
    }
    list.scrollTop = scroll;
    if (focusedKey) {
      const again = list.querySelector('[data-key="' + cssEsc(focusedKey) + '"]');
      if (again) { try { again.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
    }
  }

  /** Scroll the network list (only the list, never the page) so the selected network's row is in view. */
  function revealSelectedRow() {
    const list = els.netList;
    const row = list && selected ? list.querySelector('.survey-net[data-key="' + cssEsc(selected) + '"]') : null;
    if (!row) return;
    const lr = list.getBoundingClientRect(), rr = row.getBoundingClientRect();
    if (rr.top < lr.top) list.scrollTop -= lr.top - rr.top + 6;
    else if (rr.bottom > lr.bottom) list.scrollTop += rr.bottom - lr.bottom + 6;
  }

  function cssEsc(s) {
    return (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/["\\]/g, '\\$&');
  }

  function onListKey(e) {
    const row = e.target.closest('.survey-net');
    if (!row) return;
    const rows = Array.from(els.netList.querySelectorAll('.survey-net'));
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleSelect(row.dataset.key, 'list'); return; }
    if (e.key === 'Escape' && selected) { e.preventDefault(); selected = null; render(); return; }
    // below 1100 px the list is a grid of 2-3 columns: up/down move a whole row there
    const tracks = getComputedStyle(els.netList).gridTemplateColumns;
    const cols = tracks && tracks !== 'none' ? tracks.trim().split(/\s+/).length : 1;
    const target = listKeyTarget(e.key, rows.indexOf(row), rows.length, cols);
    if (target == null) return;
    e.preventDefault();
    const next = rows[target];
    for (const r of rows) r.tabIndex = r === next ? 0 : -1;
    next.focus();
  }

  /* the radio table: the shared host table's sortable headers and sort, with rows kept here (updated in
     place, so a tooltip being read survives a poll) */
  function netCell(ap) {
    const { h } = TNT.util;
    const key = networkKey(ap);
    const isSel = key === selected;
    // the name is a button: Tab reaches it and Enter or Space selects the network, like a click on the row
    return h('td', { class: 'survey-netcell' }, h('span', { class: 'survey-netcell-in' },
      swatch(key, ap.stale),
      h('button', { class: 'survey-pick survey-ssid' + (ap.hidden || !ap.ssid ? ' muted' : ''), type: 'button', data: { pick: key }, 'aria-pressed': String(isSel),
        title: networkName(ap) + (isSel ? ' · click to clear the highlight' : ' · click to highlight') }, ap.hidden || !ap.ssid ? '(hidden)' : ap.ssid),
      ap.connected ? h('span', { class: 'badge green', title: 'This PC is connected to this access point' }, 'connected') : null));
  }
  // the order of the reference design: what tells networks apart first, the BSSID and the time last
  const COLUMNS = [
    { key: 'ssid', label: 'Network', kind: 'custom', sortValue: (ap) => [false, networkName(ap).toLowerCase(), ''], cell: netCell },
    { key: 'band', label: 'Band', kind: 'custom', numeric: true, sortValue: (ap) => [ap.band == null, BAND_ORDER[ap.band] == null ? 9 : BAND_ORDER[ap.band], ap.channel || 0],
      cell: (ap) => TNT.util.h('td', null, ap.band ? ap.band + ' GHz' : '—') },
    { key: 'channel', label: 'Channel', kind: 'custom', numeric: true, sortValue: (ap) => [ap.freq_mhz == null, ap.freq_mhz || 0, ap.width_mhz || 0],
      cell: (ap) => { const t = channelText(ap); return TNT.util.h('td', { title: t.title }, t.text, t.sub ? TNT.util.h('span', { class: 'survey-sub' }, t.sub) : null); } },
    // (renderTable orders this column with stickyOrder, so a row moves only for a real change in signal)
    { key: 'rssi', label: 'Signal', kind: 'custom', numeric: true, sortValue: (ap) => [ap.rssi == null, ap.rssi == null ? 0 : ap.rssi, ap.quality || 0],
      cell: (ap) => TNT.util.h('td', { class: 'survey-signal', title: ap.quality != null ? 'Link quality ' + ap.quality + ' %' : '' }, bars(ap.rssi, ap.stale), dbmPill(ap.rssi, ap.stale)) },
    { key: 'phy', label: 'PHY', kind: 'custom', numeric: true, sortValue: (ap) => [!ap.phy, PHY_ORDER.indexOf(ap.phy), (ap.phys || []).length],
      cell: (ap) => TNT.util.h('td', { title: ap.generation ? ap.generation + (ap.max_rate_mbps ? ' · up to ' + ap.max_rate_mbps + ' Mbps' : '') : '' },
        phyText(ap), ap.generation ? TNT.util.h('span', { class: 'badge teal survey-gen' }, ap.generation) : null) },
    { key: 'security', label: 'Security', kind: 'text',
      cell: (ap) => TNT.util.h('td', null, TNT.util.h('span', { class: 'badge survey-sec ' + securityClass(ap.security) }, ap.security || 'Unknown')) },
    { key: 'vendor', label: 'Vendor', kind: 'custom', sortValue: (ap) => { const v = vendorText(ap, vendors); return v.muted ? [true, '', ''] : [false, v.text.replace(/^likely /, '').toLowerCase(), '']; },
      cell: (ap) => { const v = vendorText(ap, vendors); return TNT.util.h('td', { class: 'survey-vendor' + (v.muted ? ' muted' : ''), title: v.title }, TNT.util.h('span', { class: 'survey-vendor-in' }, v.text)); } },
    { key: 'bssid', label: 'BSSID', kind: 'text',
      cell: (ap) => TNT.util.h('td', { class: 'survey-bssid' }, TNT.util.copyCode(ap.bssid, 'survey-mac')) },
    // every access point in range reads "now": they sort as equals (and keep their order), out of range by age
    { key: 'last_seen', label: 'Last seen', kind: 'custom', numeric: true, sortValue: (ap) => [!ap.last_seen, ap.stale ? (ap.last_seen || 0) : Infinity, 0],
      cell: (ap) => TNT.util.h('td', { class: 'survey-seen', title: ap.first_seen ? 'First seen ' + TNT.util.fmtTime(ap.first_seen) + ' · ' + (ap.seen_count || 0) + ' readings' : '' },
        ap.stale ? TNT.util.relTime(ap.last_seen, nowS()) : 'now') },
  ];

  function renderTable() {
    if (!table || !root) return;
    const { h } = TNT.util;
    const wrap = els.tableWrap;
    const scroll = wrap.scrollTop;
    const tbody = table.tbody;
    // no re-sort at all while the pointer or the keyboard is in the table; otherwise the chosen sort over the
    // rows in their last order (ties keep it), and the Signal column with the same jitter margin as the list
    const inOrder = keepOrder(aps(), tableOrder, (a) => a.bssid);
    let sorted = inOrder;
    if (!interacting(els.tableWrap)) {
      const s = table.sort;
      sorted = s.key === 'rssi'
        ? stickyOrder(inOrder, tableOrder, (a) => a.bssid, (a) => (a.rssi == null ? 1 : 0), (a) => (s.dir === 'asc' ? -1 : 1) * a.rssi, SORT_MARGIN_DB)
        : table.sorted(inOrder);
    }
    tableOrder = sorted.map((a) => a.bssid);
    els.apCount.textContent = String(sorted.length);
    if (!sorted.length) {
      tbody.innerHTML = '';
      tbody.appendChild(h('tr', { class: 'empty-row' }, h('td', { colspan: String(COLUMNS.length) }, 'No access points seen yet')));
      return;
    }
    // every row is kept by BSSID: a new access point gets a row, a reorder moves rows, and in a kept row only
    // the cells whose content changed are replaced (a title tooltip on any other cell stays up; keyboard focus
    // on a replaced cell's button moves to the new one)
    const rows = new Map();
    for (const tr of Array.from(tbody.children)) { if (tr.dataset.bssid) rows.set(tr.dataset.bssid, tr); else tr.remove(); }
    sorted.forEach((ap, i) => {
      let tr = rows.get(ap.bssid);
      if (!tr) {
        tr = h('tr', { data: { bssid: ap.bssid } });
        for (const c of COLUMNS) { const td = c.cell(ap); cellHtml.set(td, td.outerHTML); tr.appendChild(td); }
      } else {
        rows.delete(ap.bssid);
        COLUMNS.forEach((c, j) => {
          const old = tr.children[j];
          const td = c.cell(ap);
          const html = td.outerHTML;
          if (old && cellHtml.get(old) === html) return;
          const hadFocus = !!old && old.contains(document.activeElement);
          cellHtml.set(td, html);
          if (old) tr.replaceChild(td, old); else tr.appendChild(td);
          const focusable = hadFocus ? td.querySelector('button, code.copy') : null;
          if (focusable) { try { focusable.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
        });
      }
      if (tbody.children[i] !== tr) tbody.insertBefore(tr, tbody.children[i] || null);
      const key = networkKey(ap);
      tr.dataset.net = key;
      tr.classList.toggle('is-stale', !!ap.stale);
      tr.classList.toggle('is-selected', key === selected);
    });
    for (const tr of rows.values()) tr.remove();      // access points no longer in the survey (after a Clear)
    wrap.scrollTop = scroll;
  }

  function tipFor(ap) {
    const esc = W().escHtml;
    const ch = channelText(ap);
    return '<div class="t">' + esc(networkName(ap)) + (ap.connected ? ' · connected' : '') + '</div>' +
      esc(ap.bssid) + ' · ' + W().dbmText(ap.rssi) +
      '<div class="muted">' + esc((ap.band ? ap.band + ' GHz · ' : '') + 'ch ' + ch.text + (ch.sub ? ' (' + ch.sub + ')' : '')) + '</div>' +
      '<div class="muted">' + esc([phyText(ap), ap.security].filter((x) => x && x !== '—').join(' · ')) + (ap.stale ? ' · out of range' : '') + '</div>';
  }

  function renderCharts(nets) {
    const WC = W();
    const now = nowS();
    const byBssid = new Map(aps().map((a) => [a.bssid, a]));
    // the oldest reading inside the range: a range longer than the history held starts there
    const from = rangeS ? now - rangeS : -Infinity;
    let earliest = null;
    for (const bssid of Object.keys(history)) {
      if (!byBssid.has(bssid)) continue;
      const pts = history[bssid];
      const i = lowerIndex(pts, from);
      if (i < pts.length && (earliest == null || pts[i][0] < earliest)) earliest = pts[i][0];
    }
    const [t0, t1] = rangeWindow(rangeS, now, data && data.started_ts, earliest);
    if (els.signalSpan) els.signalSpan.textContent = rangeS && t1 - t0 < rangeS - 1 ? TNT.util.fmtDuration(Math.round(t1 - t0)) + ' of readings so far' : '';
    const esc = WC.escHtml;
    const gap = WC.gapFor(t1 - t0);
    // signal strength over time
    const series = [];
    for (const bssid of Object.keys(history)) {
      const ap = byBssid.get(bssid);
      if (!ap) continue;
      const key = networkKey(ap);
      const points = pointsInRange(history[bssid], t0 - gap, t1 + 1);
      if (!points.length) continue;
      series.push({ key: bssid, net: key, name: networkName(ap), color: colors.get(key) || 0, points, selected: key === selected,
        tip: (ts, v) => '<div class="t">' + esc(networkName(ap)) + '</div>' + esc(bssid) + ' · ' + WC.dbmText(v) + '<div class="muted">' + TNT.util.fmtTime(ts) + ' · ' + esc((ap.band ? ap.band + ' GHz ' : '') + 'ch ' + ap.channel) + '</div>' });
    }
    const starting = data && data.state === 'starting';
    charts.signal.setData({ series, t0, t1, dim: !!selected, empty: starting ? 'Starting the survey…' : 'No readings in this range yet' });
    renderLegend(nets);
    // spectrum, one chart per band
    for (const band of WC.BAND_KEYS) {
      const list = aps().filter((a) => a.band === band).map((ap) => {
        const key = networkKey(ap);
        return { key: ap.bssid, net: key, name: ap.hidden || !ap.ssid ? hiddenLabel(ap.bssid) : ap.ssid, color: colors.get(key) || 0, rssi: ap.rssi, spans: WC.apSpans(ap),
          band, stale: !!ap.stale, connected: !!ap.connected, selected: key === selected, tip: tipFor(ap) };
      });
      const chart = charts.bands[band];
      const empty = starting ? 'Starting the survey…' : 'No ' + WC.BANDS[band].label + ' networks seen.';
      chart.setData({ aps: list, dim: !!selected, empty });
      const live = list.filter((a) => !a.stale).length;
      els.bandCounts[band].textContent = list.length ? live + (live === 1 ? ' access point' : ' access points') + (list.length > live ? ' · ' + (list.length - live) + ' out of range' : '') : '';
      els.bandCanvas[band].setAttribute('aria-label', WC.BANDS[band].label + ' spectrum: ' + (list.length ? list.length + ' access points' : 'none seen'));
      if (band === '6') {
        // nothing on 6 GHz (most adapters cannot hear it): one line instead of an empty full-width chart
        const collapse = !list.length && !starting;
        els.bandCards['6'].classList.toggle('is-empty', collapse);
        els.bandEmpty6.hidden = !collapse;
        if (collapse) els.bandEmpty6.textContent = sixGhzEmptyText(data && data.interfaces);
      }
    }
  }

  function renderLegend(nets) {
    const { h } = TNT.util;
    const el = els.legend;
    const n = selected ? nets.find((x) => x.key === selected) : null;
    // rebuilt only when what it shows changed, so keyboard focus on its × survives the polls
    const sig = n ? [n.key, n.name, n.count, n.stale, colors.get(n.key)].join('|') : '';
    if (sig === legendSig && el.firstChild) return;
    legendSig = sig;
    const hadFocus = el.contains(document.activeElement);
    el.innerHTML = '';
    if (!n) { el.appendChild(h('span', { class: 'muted' }, 'Click a network, a row or a shape to highlight it')); return; }
    const clear = h('button', { class: 'btn btn-round-sm', type: 'button', title: 'Clear the highlight', 'aria-label': 'Clear the highlight', on: { click: () => { selected = null; render(); } } }, TNT.ui.icon('close'));
    el.appendChild(h('span', { class: 'survey-legend-chip' }, swatch(n.key, n.stale), h('strong', null, n.name),
      h('span', { class: 'muted' }, ' · ' + n.count + (n.count === 1 ? ' AP' : ' APs')), clear));
    if (hadFocus) { try { clear.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
  }

  /* ------------------------------------------------------------- mount */
  function build() {
    const { h } = TNT.util;
    els = {};
    els.toggle = TNT.ui.toggle({ checked: false, on: 'On', off: 'Off', accent: 'var(--teal)', onChange: (v) => setEnabled(v) });
    els.toggle.input.setAttribute('aria-label', 'Wi-Fi survey on or off');
    els.scanBtn = h('button', { class: 'btn btn-sm', type: 'button', title: 'Ask the adapter for a fresh scan now (at most one every 5 s)', on: { click: scanNow } }, TNT.ui.icon('refresh'), 'Scan now');
    els.clearBtn = h('button', { class: 'btn btn-sm', type: 'button', title: 'Forget every access point and all history', on: { click: clearSurvey } }, TNT.ui.icon('trash'), 'Clear');
    const seg = TNT.ui.segmented(RANGES, rangeS, (v) => {
      const grew = !rangeS ? false : (!v || v > rangeS);
      rangeS = v;
      try { localStorage.setItem(RANGE_STORE, String(v)); } catch (e) { /* ignore */ }
      if (grew) historyComplete = null;          // the cache does not reach back that far: fetch the range
      render();
      schedule(0);
    });
    seg.setAttribute('aria-label', 'History range');
    els.switchWrap = h('span', { class: 'survey-switch', hidden: true }, h('span', { class: 'label' }, 'Survey'), els.toggle);
    const head = h('div', { class: 'section-head' },
      h('h2', null, h('span', { class: 'section-accent' }), 'WiFi'),
      h('div', { class: 'actions' }, els.switchWrap, els.scanBtn, els.clearBtn, seg));
    els.status = h('div', { class: 'survey-status', role: 'status', 'aria-live': 'off', hidden: true });
    els.note = h('div', { class: 'tool-note survey-note', hidden: true }, LATENCY_NOTE);
    els.state = h('div', { class: 'card survey-state', hidden: true, role: 'status' });

    // networks
    els.netCount = h('span', { class: 'badge teal' }, '0');
    els.filter = h('input', { class: 'input sm', type: 'search', placeholder: 'Filter networks', 'aria-label': 'Filter networks', spellcheck: 'false', autocomplete: 'off' });
    els.filter.addEventListener('input', () => { filterText = els.filter.value; listSig = ''; resetListScroll = true; render(); });
    els.netList = h('div', { class: 'survey-net-list', role: 'listbox', 'aria-label': 'Networks' });
    els.netList.addEventListener('click', (e) => { const row = e.target.closest('.survey-net'); if (row) toggleSelect(row.dataset.key, 'list'); });
    els.netList.addEventListener('keydown', onListKey);
    // the order held while the pointer or the keyboard was in the list catches up as soon as they leave
    const catchUp = () => { if (root) setTimeout(() => { if (root && !interacting(els.netList)) render(); }, 0); };
    els.netList.addEventListener('mouseleave', catchUp);
    els.netList.addEventListener('focusout', catchUp);
    const netCard = h('div', { class: 'card survey-nets' },
      h('div', { class: 'card-title' }, TNT.ui.icon('wifi'), 'Networks', els.netCount), els.filter,
      h('div', { class: 'survey-net-scroll' }, els.netList));

    // radio table
    table = TNT.hosttable.create({ columns: COLUMNS, storeKey: SORT_STORE, defaultSort: { key: 'rssi', dir: 'desc' }, onSort: () => renderTable() });
    els.apCount = h('span', { class: 'badge teal' }, '0');
    els.tableWrap = h('div', { class: 'table-wrap survey-table-wrap' }, h('table', { class: 'table survey-table' }, table.thead, table.tbody));
    table.tbody.addEventListener('click', (e) => {
      const pickBtn = e.target.closest('[data-pick]');
      if (pickBtn) { toggleSelect(pickBtn.dataset.pick, 'table'); return; }
      if (e.target.closest('code.copy, button, a')) return;
      const tr = e.target.closest('tr[data-net]');
      if (tr) toggleSelect(tr.dataset.net, 'table');
    });
    const tableCatchUp = () => { if (root) setTimeout(() => { if (root && !interacting(els.tableWrap)) renderTable(); }, 0); };
    els.tableWrap.addEventListener('mouseleave', tableCatchUp);
    els.tableWrap.addEventListener('focusout', tableCatchUp);
    const apCard = h('div', { class: 'card survey-aps' }, h('div', { class: 'card-title' }, TNT.ui.icon('router'), 'Access points', els.apCount), els.tableWrap);

    // signal strength
    els.legend = h('div', { class: 'legend survey-legend' });
    const sigCanvas = h('canvas', { class: 'survey-signal-canvas', role: 'img', 'aria-label': 'Signal strength of every access point over time' });
    const sigCard = h('div', { class: 'card survey-signal-card' },
      h('div', { class: 'card-title' }, TNT.ui.icon('ping'), 'Signal strength',
        els.signalSpan = h('span', { class: 'muted small survey-signal-span' }), h('span', { class: 'spacer' }), els.legend),
      h('div', { class: 'chart-wrap' }, sigCanvas));

    // spectrum
    els.bandCounts = {}; els.bandCanvas = {}; els.bandCards = {};
    els.bandEmpty6 = h('p', { class: 'survey-band-empty', hidden: true });
    const bandCards = els.bandCards;
    for (const band of W().BAND_KEYS) {
      els.bandCounts[band] = h('span', { class: 'muted small survey-band-count' });
      els.bandCanvas[band] = h('canvas', { class: 'survey-band-canvas', role: 'img', 'aria-label': W().BANDS[band].label + ' spectrum' });
      bandCards[band] = h('div', { class: 'card survey-band', data: { band } },
        h('div', { class: 'card-title' }, TNT.ui.icon('spectrum'), W().BANDS[band].label, h('span', { class: 'spacer' }), els.bandCounts[band]),
        band === '6' ? els.bandEmpty6 : null,
        h('div', { class: 'chart-wrap' }, els.bandCanvas[band]));
    }
    // the network list sits beside the signal chart (pick a network, watch its lines); the radio
    // table gets the full width so every column fits without scrolling sideways
    els.content = h('div', { class: 'stack survey-content', hidden: true },
      h('div', { class: 'survey-top' }, netCard, sigCard),
      apCard,
      h('div', { class: 'survey-bands' }, bandCards['2.4'], bandCards['5']),
      bandCards['6']);
    root.appendChild(head);
    root.appendChild(h('div', { class: 'stack survey-page' }, h('div', { class: 'survey-status-wrap' }, els.status, els.note), els.state, els.content));

    const pick = (net) => toggleSelect(net, 'chart');
    const WC = W();
    charts.signal = new WC.SignalChart(sigCanvas, { onPick: pick });
    charts.bands = {};
    for (const band of WC.BAND_KEYS) charts.bands[band] = new WC.SpectrumChart(els.bandCanvas[band], { band, onPick: pick });
  }

  TNT.views.wifi = {
    mount(el) {
      root = el;
      data = survey.last && Array.isArray(survey.last.aps) ? survey.last : null;
      history = {}; historyComplete = null; historyStarted = null; lastReadSeen = null; listSig = ''; legendSig = ''; busyToggle = false;
      filterText = ''; revealSelected = !!selected; resetListScroll = false;
      build();
      unsubs.push(survey.hook(() => { if (root) schedule(0); }));
      const onVis = () => { if (root && !document.hidden) schedule(0); };
      document.addEventListener('visibilitychange', onVis);
      unsubs.push(() => document.removeEventListener('visibilitychange', onVis));
      render();
      schedule(0);
    },
    update() { /* the survey does not come from the service status */ },
    unmount() {
      for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
      unsubs = [];
      if (timer) { clearTimeout(timer); timer = null; }
      if (charts.signal) charts.signal.destroy();
      for (const c of Object.values(charts.bands || {})) c.destroy();
      charts = { signal: null, bands: {} };
      if (table) table.destroy();
      table = null;
      root = null; els = {}; history = {}; historyComplete = null; historyStarted = null; lastReadSeen = null; data = null;
      netOrder = []; tableOrder = [];
    },
    // exposed for tests
    networkKey, networkName, groupNetworks, sortNetworks, filterNetworks, fnv1a, createColorBook, mergeHistory, pointsInRange,
    rangeWindow, historyRequest, channelText, phyText, securityClass, vendorText, vendorPrefixes, stateInfo, tileSummary,
    stickyOrder, keepOrder, listKeyTarget, hiddenLabel, sixGhzEmptyText,
    columns: COLUMNS.map((c) => c.key), RANGES, POLL_MS, TILE_POLL_MS, LATENCY_NOTE, EMPTY_6GHZ, EMPTY_6GHZ_CAPABLE, SORT_MARGIN_DB,
  };
})();
