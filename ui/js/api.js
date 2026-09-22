/* TNT — api.js
   Fetch wrapper for the local JSON API and an SSE client with exponential backoff.
   Exposes window.TNT.api. Loaded first; must not depend on any other script. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  const BASE = '/api';
  const DEFAULT_TIMEOUT = 10000;

  class ApiError extends Error {
    constructor(message, code, status, body) {
      super(message);
      this.name = 'ApiError';
      this.code = code || 'error';
      this.status = status || 0;
      this.body = body || null;   // the parsed JSON error payload (409 replies may carry extra data)
    }
  }

  function describeNetworkError() {
    return 'Cannot reach the TNT service';
  }

  /** Pure: a query string for the SIP routes -> '' or '?a=1&b=2'. A null, an undefined and an empty string are
   *  left out, so "every target, the default window" is a bare path rather than a path with empty parameters. */
  function sipQuery(q) {
    const v = q && typeof q === 'object' ? q : {};
    const parts = [];
    for (const key of ['hours', 'host', 'side', 'stream']) {
      const value = v[key];
      if (value === null || value === undefined || value === '') continue;
      parts.push(key + '=' + encodeURIComponent(String(value)));
    }
    return parts.length ? '?' + parts.join('&') : '';
  }

  /** Pure: the packet list's query string for { since, limit, ip, mac, protos } -> '' or '?a=1&b=2'. A null, an empty
   *  string and a protocol the page does not have on are left out, and the protocols are repeated parameters. */
  function captureQuery(q) {
    const v = q && typeof q === 'object' ? q : {};
    const parts = [];
    for (const key of ['since', 'limit', 'ip', 'mac']) {
      const value = v[key];
      if (value === null || value === undefined || value === '') continue;
      parts.push(key + '=' + encodeURIComponent(String(value)));
    }
    for (const p of Array.isArray(v.protos) ? v.protos : []) {
      const text = String(p == null ? '' : p).trim();
      if (text) parts.push('proto=' + encodeURIComponent(text));
    }
    return parts.length ? '?' + parts.join('&') : '';
  }

  /** Perform a request. Resolves the parsed JSON body (or Blob for binary responses). */
  async function request(method, path, body, opts) {
    opts = opts || {};
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), opts.timeout || DEFAULT_TIMEOUT);
    const init = { method, headers: {}, signal: ctl.signal, cache: 'no-store' };
    if (body !== undefined && body !== null) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    let resp;
    try {
      resp = await fetch(BASE + path, init);
    } catch (err) {
      clearTimeout(timer);
      if (err && err.name === 'AbortError') throw new ApiError('Request timed out', 'timeout', 0);
      throw new ApiError(describeNetworkError(), 'network', 0);
    }
    clearTimeout(timer);
    const ctype = resp.headers.get('Content-Type') || '';
    if (!resp.ok) {
      let msg = resp.statusText || ('HTTP ' + resp.status);
      let code = 'http_' + resp.status;
      let payload = null;
      if (ctype.includes('json')) {
        try {
          const j = await resp.json();
          payload = j;
          if (j && j.error) { msg = j.error.message || msg; code = j.error.code || code; }
        } catch (e) { /* ignore */ }
      } else {
        try { const t = await resp.text(); if (t && t.length < 300) msg = t; } catch (e) { /* ignore */ }
      }
      throw new ApiError(msg, code, resp.status, payload);
    }
    if (opts.blob || (!ctype.includes('json') && !ctype.startsWith('text/'))) {
      const blob = await resp.blob();
      const cd = resp.headers.get('Content-Disposition') || '';
      const m = /filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(cd);
      let filename = m ? m[1].trim() : null;
      // a stray '%' in a plain filename= is not an escape: keep the name as sent rather than throw
      if (filename) { try { filename = decodeURIComponent(filename); } catch (e) { /* as sent */ } }
      return { blob, filename, headers: resp.headers };
    }
    if (resp.status === 204) return null;
    const text = await resp.text();
    if (!text) return null;
    try { return JSON.parse(text); } catch (e) { throw new ApiError('Bad JSON from the service', 'bad_json', resp.status); }
  }

  const api = {
    ApiError,
    request,
    get: (path, opts) => request('GET', path, undefined, opts),
    post: (path, body, opts) => request('POST', path, body === undefined ? {} : body, opts),
    put: (path, body, opts) => request('PUT', path, body, opts),
    patch: (path, body, opts) => request('PATCH', path, body === undefined ? {} : body, opts),
    del: (path, opts) => request('DELETE', path, undefined, opts),

    // convenience wrappers for every route in the contract
    health: () => api.get('/health'),
    status: () => api.get('/status'),
    netinfo: () => api.get('/netinfo'),
    // Faults: the passive watch's findings. The live feed is the faults.state event.
    faults: () => api.get('/faults'),
    // Realtime throughput: the backlog for one window. The live feed is the throughput.sample event.
    throughput: (windowS) => api.get('/throughput?window_s=' + encodeURIComponent(windowS)),
    // IP location (DB-IP Lite): the data's state, a lookup made on this PC only, and Retry now
    geoip: () => api.get('/geoip'),
    geoipLookup: (ip) => api.get('/geoip/lookup?ip=' + encodeURIComponent(ip)),
    geoipCheck: () => api.post('/geoip/check'),
    updateStatus: () => api.get('/update'),
    updateCheck: () => api.post('/update/check', {}, { timeout: 30000 }),
    updateInstall: () => api.post('/update/install', {}, { timeout: 30000 }),
    // Network info: the NAT check (POST answers once the check is done: a fresh public address first when the link map's is
    // stale, up to 12 s, then at most 20 s for the router's answers), the switch port (LLDP / CDP heard through Packet Monitor:
    // POST starts listening, DELETE stops) and a port-forward test from the internet (that public address first, up to 12 s,
    // then at most 35 s for the port checkers)
    natGet: () => api.get('/netcheck/nat'),
    natRun: () => api.post('/netcheck/nat', {}, { timeout: 45000 }),
    switchGet: () => api.get('/netcheck/switch'),
    switchStart: (body) => api.post('/netcheck/switch', body || {}),
    switchStop: () => api.del('/netcheck/switch'),
    portForwardTest: (port) => api.post('/netcheck/portforward', { port }, { timeout: 60000 }),
    targets: () => api.get('/targets'),
    addTarget: (host, label) => api.post('/targets', label ? { host, label } : { host }),
    removeTarget: (id) => api.del('/targets/' + encodeURIComponent(id)),
    renameTarget: (id, name) => api.patch('/targets/' + encodeURIComponent(id), { name: name == null ? null : name }),
    loadDefaultTargets: () => api.post('/targets/defaults'),
    reorderTargets: (ids) => api.put('/targets/order', { ids }),
    samples: (id, seconds) => api.get('/targets/' + encodeURIComponent(id) + '/samples?seconds=' + (seconds || 300)),
    history: (id, from, to) => api.get('/targets/' + encodeURIComponent(id) + '/history?from=' + from + '&to=' + to),
    outages: (from, to) => api.get('/outages' + (from ? '?from=' + from + '&to=' + to : '')),
    timeline: (hours) => api.get('/outages/timeline?hours=' + (hours || 24)),
    speedtests: (from, to, limit) => api.get('/speedtests?from=' + from + '&to=' + to + (limit ? '&limit=' + limit : '')),
    runSpeedtest: () => api.post('/speedtests/run'),
    easter: () => api.get('/easter'),
    detonate: (sticks) => api.post('/easter/detonate', { sticks }),
    speedPatterns: (days) => api.get('/speedtests/patterns?days=' + (days || 7)),
    discoveryRuns: (limit) => api.get('/discovery/runs?limit=' + (limit || 50)),
    discoveryRun: (id) => api.get('/discovery/runs/' + encodeURIComponent(id)),
    discoveryLast: () => api.get('/discovery/last'),
    discoveryScan: (range, ports) => {
      const body = {};
      if (range) body.range = range;
      if (ports && ports.length) body.ports = ports;
      return api.post('/discovery/scan', body);
    },
    discoveryCancel: () => api.post('/discovery/cancel'),
    discoveryStatus: () => api.get('/discovery/status'),
    // Tools: DHCP server. Start and scan wait for other DHCP servers to answer (up to the
    // configured scan_wait_s, max 30 s) so they get a generous timeout.
    dhcpStatus: () => api.get('/dhcp/status'),
    dhcpLeases: () => api.get('/dhcp/leases'),
    dhcpScan: (wait) => api.post('/dhcp/scan', wait ? { wait_s: wait } : {}, { timeout: 45000 }),
    dhcpStart: (force) => api.post('/dhcp/start', { force: !!force }, { timeout: 45000 }),
    dhcpStop: () => api.post('/dhcp/stop', {}, { timeout: 20000 }),
    dhcpSettings: (patch) => api.put('/dhcp/settings', patch || {}),
    dhcpForget: (mac) => api.del('/dhcp/leases/' + encodeURIComponent(mac)),
    // Tools: TFTP server. Start opens UDP 69 on the adapter (and adds its firewall rule on an installed service), so it gets a
    // longer timeout; uploads switches "Allow uploads", settings saves the adapter and the max upload size.
    tftpStatus: () => api.get('/tftp/status'),
    tftpStart: (body) => api.post('/tftp/start', body || {}, { timeout: 20000 }),
    tftpStop: () => api.post('/tftp/stop'),
    tftpUploads: (on) => api.post('/tftp/uploads', { on: !!on }),
    tftpSettings: (patch) => api.put('/tftp/settings', patch || {}),
    tftpFiles: () => api.get('/tftp/files'),
    // Tools: traceroute is synchronous on the service (up to ~60 s for 30 silent hops) and the
    // LAN throughput test runs both directions before it answers (up to ~45 s).
    traceroute: (body) => api.post('/tools/traceroute', body || {}, { timeout: 120000 }),
    tracerouteLast: () => api.get('/tools/traceroute/last'),
    lanPeers: () => api.get('/tools/lan/peers'),
    lanThroughput: (body) => api.post('/tools/lan/throughput', body || {}, { timeout: 60000 }),
    lanThroughputLast: () => api.get('/tools/lan/throughput/last'),
    lanSettings: (patch) => api.put('/tools/lan/settings', patch),
    // Tools: saved Wi-Fi networks. reveal defaults to off on the service, so we always send it
    // explicitly: ?reveal=0 leaves the keys out (key_present still says whether there is one);
    // ?reveal=1 asks for the plaintext keys, which the service only hands to a Windows
    // administrator (else 403 admin_required).
    wifiProfiles: (reveal) => api.get('/tools/wifi/profiles' + (reveal ? '?reveal=1' : '?reveal=0'), { timeout: 30000 }),
    // Tools: a DNS lookup asks the DNS server itself, like nslookup (the server given, else this PC's; one record type when
    // given, else A + AAAA), and the top bar's quick tools. A release/renew waits for DHCP on every adapter, so it gets the
    // longest timeout of all.
    dnsLookup: (name, server, type) => api.post('/tools/dns/lookup', Object.assign({ name }, server ? { server } : {}, type ? { type } : {}), { timeout: 30000 }),
    flushDns: () => api.post('/tools/dns/flush', {}, { timeout: 45000 }),
    ipRenew: () => api.post('/tools/ip/renew', {}, { timeout: 240000 }),
    // Packet capture (its own page), for a Windows administrator only (else 403 admin_required). start begins a live
    // capture on one adapter, stop ends it and keeps it, save writes it to disk under a listed name and discard throws it
    // away. capturePackets tails the list (since = the last row number seen; leave it out for the newest rows) with the
    // filters the page has on. captureFileUrl is the address of a saved capture for a download link: it makes no request.
    captureGet: () => api.get('/capture'),
    captureStart: (body) => api.post('/capture/start', body || {}, { timeout: 20000 }),
    captureStop: () => api.post('/capture/stop', {}, { timeout: 20000 }),
    captureSave: () => api.post('/capture/save', {}, { timeout: 30000 }),
    captureDiscard: () => api.post('/capture/discard', {}),
    captureOpen: (name) => api.post('/capture/open', { name }, { timeout: 60000 }),
    captureOpenPath: (path) => api.post('/capture/open', { path }, { timeout: 120000 }),
    capturePackets: (q) => api.get('/capture/packets' + captureQuery(q)),
    capturePacket: (no) => api.get('/capture/packets/' + encodeURIComponent(no)),
    captureCalls: () => api.get('/capture/calls'),
    captureCallAudioUrl: (id) => BASE + '/capture/calls/' + encodeURIComponent(id) + '/audio',
    captureDeleteFile: (name) => api.del('/capture/files/' + encodeURIComponent(name)),
    captureFileUrl: (name) => BASE + '/capture/files/' + encodeURIComponent(name),
    // SIP (its own page). sipQualifier grades this network for calls out of the ping history and the last speed
    // test (hours = the window, host = the SIP server to grade as its own leg); the rest run on request and block
    // while they do, which is why their timeouts are long. sipStunLifetime is the slow one - it sits idle for up
    // to eight minutes - and sipFlowAudioUrl is an address for an <audio> element, not a request.
    sipQualifier: (hours, host) => api.get('/sip/qualifier' + sipQuery({ hours, host })),
    sipAlg: () => api.get('/sip/alg'),
    sipAlgRun: (host, port) => api.post('/sip/alg', { host, port }, { timeout: 30000 }),
    sipStun: () => api.get('/sip/stun'),
    sipStunRun: (servers) => api.post('/sip/stun', { servers }, { timeout: 30000 }),
    sipStunLifetime: (server) => api.post('/sip/stun/lifetime', { server }, { timeout: 600000 }),
    sipFlow: () => api.get('/sip/flow'),
    sipFlowOpen: (path, slot) => api.post('/sip/flow', { path, slot }, { timeout: 120000 }),
    sipFlowClose: (slot) => api.del('/sip/flow' + (slot ? '?slot=' + encodeURIComponent(slot) : '')),
    sipFlowCall: (id) => api.get('/sip/flow/calls/' + encodeURIComponent(id)),
    sipFlowPacket: (side, no) => api.get('/sip/flow/packets/' + encodeURIComponent(side) + '/' + encodeURIComponent(no)),
    sipFlowAudioUrl: (id, opts) => BASE + '/sip/flow/calls/' + encodeURIComponent(id) + '/audio' + sipQuery(opts || {}),
    // WiFi page: vendor names for 24-bit OUIs ("AA:BB:CC", 1-256 per call). Only OUIs go to the
    // service, never a full BSSID: the survey itself stays inside the TNT window.
    ouiVendors: (prefixes) => api.get('/oui?' + (prefixes || []).map((p) => 'prefix=' + encodeURIComponent(p)).join('&')),
    settings: () => api.get('/settings'),
    updateSettings: (patch) => api.put('/settings', patch),
    pause: () => api.post('/monitoring/pause'),
    resume: () => api.post('/monitoring/resume'),
    diagnostics: () => api.get('/diagnostics', { timeout: 20000 }),
    diagnosticsLog: (lines) => api.get('/diagnostics/log?lines=' + (lines || 200), { timeout: 20000 }),
    exportPdf: (range, from, to) => {
      const body = { range };
      if (range === 'custom') { body.from = from; body.to = to; }
      return api.post('/export', body, { blob: true, timeout: 120000 });
    },
    // Reports: the site reports a Full Scan saves (the list rows carry the summary, never the data) and the one full
    // scan the service runs at a time. The report and comparison PDFs are built on request, so they get a long timeout.
    reports: (opts) => {
      const o = opts || {};
      const q = ['site_key', 'q', 'limit', 'offset'].filter((k) => o[k] != null && o[k] !== '').map((k) => k + '=' + encodeURIComponent(o[k]));
      return api.get('/reports' + (q.length ? '?' + q.join('&') : ''));
    },
    reportSites: (text, limit) => api.get('/reports/sites?q=' + encodeURIComponent(text || '') + (limit ? '&limit=' + limit : '')),
    report: (id) => api.get('/reports/' + encodeURIComponent(id), { timeout: 30000 }),
    renameReport: (id, site) => api.patch('/reports/' + encodeURIComponent(id), { site }),
    deleteReport: (id) => api.del('/reports/' + encodeURIComponent(id)),
    reportPdf: (id) => api.get('/reports/' + encodeURIComponent(id) + '/pdf', { blob: true, timeout: 120000 }),
    fullScanStart: (site) => api.post('/reports/scan', site ? { site } : {}),
    fullScanJob: () => api.get('/reports/scan'),
    fullScanName: (site) => api.patch('/reports/scan', { site }),
    fullScanCancel: () => api.del('/reports/scan'),
    fullScanWifi: (snapshot) => api.post('/reports/scan/wifi', snapshot, { timeout: 30000 }),
    compareReports: (a, b) => api.get('/reports/compare?a=' + encodeURIComponent(a) + '&b=' + encodeURIComponent(b), { timeout: 30000 }),
    comparePdf: (a, b) => api.get('/reports/compare/pdf?a=' + encodeURIComponent(a) + '&b=' + encodeURIComponent(b), { blob: true, timeout: 120000 }),
    // the network this PC is on (identified by its router's MAC, else its gateway and subnet) and the newest report made on it
    networkCurrent: () => api.get('/networks/current'),
    // a network carried from site to site (a phone hotspot, a travel router): no site is suggested for it
    setNetworkPortable: (id, portable) => api.patch('/networks/' + encodeURIComponent(id), { portable: !!portable }),
    // Settings › History: the eight ranges and the newest clear, and the clear itself (range: one of history.RANGES' keys).
    // A clear stops running jobs and deletes files, so it gets a long timeout.
    historyInfo: () => api.get('/history'),
    historyClear: (range) => api.post('/history/clear', { range }, { timeout: 120000 }),
  };

  /* ------------------------------------------------------ network changes */
  // Pure helpers for following this PC onto another network; app.js drives them (node tests load
  // this file on its own). The service counts every change it publishes as `net.changed` in
  // status.net.generation, which starts again at 0 whenever the service restarts.
  const NET_STALE_GRACE_MS = 15000;   // how long a status older than a net.changed event is skipped
  const NET_TOAST_GAP_MS = 8000;      // at most one new network toast in this long

  /** A /api/status snapshot against the last network marker { started, generation, eventMs } ->
   *  { next, changed, stale, restarted }. `changed`: the views that show network state reload (a
   *  higher generation, or a restarted service); `stale`: the snapshot predates a net.changed event
   *  this page applied in the last 15 s, so it is skipped. The first snapshot only sets the marker. */
  function netCompare(last, st, nowMs) {
    const n = st && st.net;
    if (!n || typeof n.generation !== 'number') return { next: last || null, changed: false, stale: false, restarted: false };
    const next = { started: st.started_ts == null ? null : st.started_ts, generation: n.generation, eventMs: 0 };
    if (!last) return { next, changed: false, stale: false, restarted: false };
    if (last.started !== undefined && next.started !== last.started) return { next, changed: true, stale: false, restarted: true };
    if (n.generation < last.generation && last.eventMs && nowMs - last.eventMs < NET_STALE_GRACE_MS) {
      return { next: last, changed: false, stale: true, restarted: false };
    }
    return { next, changed: n.generation !== last.generation, stale: false, restarted: false };
  }

  /** A net.changed event against the marker -> { next, fresh }. `fresh` is false for a generation
   *  this page already handled (a status snapshot got there first). */
  function netFromEvent(last, data, nowMs) {
    const gen = data && typeof data.generation === 'number' ? data.generation : null;
    if (gen === null) return { next: last || null, fresh: true };
    return { next: { started: last ? last.started : undefined, generation: gen, eventMs: nowMs }, fresh: !last || gen !== last.generation };
  }

  /** Several changes inside one settle window -> one: the newest payload, with every *_changed flag
   *  that was set by any of them and all of their `changes`. */
  function netMerge(prev, info) {
    if (!prev) return info;
    if (!info) return prev;
    const out = Object.assign({}, prev, info);
    for (const k of ['gateway_changed', 'internet_nic_changed', 'subnets_changed', 'dns_changed']) out[k] = !!(prev[k] || info[k]);
    out.changes = [].concat(Array.isArray(prev.changes) ? prev.changes : [], Array.isArray(info.changes) ? info.changes : []);
    return out;
  }

  /** How to show a network toast at `nowMs`: 'update' the one still on screen (text and timer), a
   *  'new' one, or 'defer' it by `waitMs`, so a burst of changes never stacks toasts.
   *  `last` = { shownMs, visible } of the previous network toast, or null. */
  function netToastPlan(last, nowMs, gapMs) {
    const gap = gapMs == null ? NET_TOAST_GAP_MS : gapMs;
    if (!last) return { action: 'new', waitMs: 0 };
    if (last.visible) return { action: 'update', waitMs: 0 };
    const since = nowMs - last.shownMs;
    return since >= gap ? { action: 'new', waitMs: 0 } : { action: 'defer', waitMs: gap - since };
  }

  /** The network toast for a change -> { text, kind }: "Network changed — <summary>", a warning without a
   *  default gateway. A change TNT's own DHCP server made (cause "dhcp") already says so in its summary
   *  ("DHCP server set Ethernet to 172.16.4.100 · …") and is never a warning: the user just asked for it. */
  function netToastText(info) {
    const summary = String((info && info.summary) || '');
    if (info && info.cause === 'dhcp') return { text: summary, kind: 'info' };
    // a warning too when no adapter faces the internet although a gateway is configured (a duplicate address, a gateway
    // that routes nowhere); a payload without the internet_nic key (an older service) goes by the gateway alone
    const noInternet = !!info && 'internet_nic' in info && !info.internet_nic;
    return { text: 'Network changed — ' + summary, kind: info && info.default_gateway && !noInternet ? 'info' : 'warn' };
  }

  /** Whether a change is worth a toast (the views reload either way): not when every change is to IPv6 addresses
   *  while IPv6 is hidden (`showIpv6` false), nor when only the adapter the internet goes through switched between
   *  two adapters on the same network (gateway, subnets and DNS unchanged: Windows prefers one over the other as
   *  link speeds move). A change without its `changes` (seen through /api/status) always is. */
  function netToastWanted(info, showIpv6) {
    const changes = info && Array.isArray(info.changes) ? info.changes : null;
    if (!changes || !changes.length) return true;
    if (!showIpv6 && changes.every((c) => c && c.kind === 'ipv6')) return false;
    const sameNetwork = !info.gateway_changed && !info.subnets_changed && !info.dns_changed;
    return !(sameNetwork && changes.every((c) => c && c.kind === 'internet_nic'));
  }

  /** "a.b.c.d/n" for status.netinfo.internet_nic, which the service sends as the bare address plus its
   *  network ({ ipv4: "10.0.0.112", network: "10.0.0.0/24" }); an ipv4 that already carries its prefix is
   *  taken as it is. null when either half is missing. */
  function netNicCidr(nic) {
    if (!nic || !nic.ipv4) return null;
    const ip = String(nic.ipv4);
    if (ip.includes('/')) return ip;
    const net = String(nic.network || '');
    return net.includes('/') ? ip + '/' + net.split('/')[1] : null;
  }

  /** "a.b.c.0/n", the IPv4 network of an address and prefix length; null for anything else. */
  function netNetworkOf(ip, prefix) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip == null ? '' : ip));
    const p = /^\d{1,2}$/.test(String(prefix == null ? '' : prefix)) ? Number(prefix) : NaN;
    if (!m || !(p >= 0 && p <= 32)) return null;
    const o = m.slice(1).map(Number);
    if (o.some((x) => x > 255)) return null;
    const mask = p === 0 ? 0 : (0xFFFFFFFF << (32 - p)) >>> 0;
    const net = ((((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]) & mask) >>> 0;
    return [net >>> 24, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join('.') + '/' + p;
  }

  /** Toast text for a change seen only through /api/status: status.net.summary (the service's text of its last
   *  change), else pieced together from the internet adapter (a service without it). */
  function netSummaryFromStatus(st) {
    const nic = st && st.netinfo && st.netinfo.internet_nic;
    const net = (st && st.net) || {};
    if (net.summary) return String(net.summary);
    const gw = net.default_gateway || (nic && nic.gateway) || null;
    const addr = nic ? netNicCidr(nic) || nic.ipv4 : null;
    if (nic && nic.name) return nic.name + (addr ? ': ' + addr : '') + (gw ? ' · gateway ' + gw : ' · no gateway');
    return gw ? 'Gateway ' + gw : 'No network connection';
  }

  /** status.netinfo.internet_nic the way the service's /api/status carries it ({ name, ipv4: "a.b.c.d",
   *  network: "a.b.c.0/n", gateway }), from a net.changed payload; null when there is no internet adapter.
   *  The network is internet_nic.networks[0], else worked out from ipv4_prefixes[0] (a prefix length; an
   *  "a.b.c.d/n" network is taken as it is). */
  function netNicFromEvent(data) {
    const nic = data && data.internet_nic;
    if (!nic) return null;
    let ip = Array.isArray(nic.ipv4) && nic.ipv4.length ? String(nic.ipv4[0]) : null;
    let prefix = null;
    if (ip && ip.includes('/')) [ip, prefix] = ip.split('/');
    const pre = Array.isArray(nic.ipv4_prefixes) && nic.ipv4_prefixes.length ? String(nic.ipv4_prefixes[0]) : null;
    let network = Array.isArray(nic.networks) && nic.networks.length ? String(nic.networks[0]) : null;
    if (!network && pre && pre.includes('/')) network = pre;
    if (!network && ip) network = netNetworkOf(ip, prefix != null ? prefix : pre);
    return { name: nic.name || null, ipv4: ip, network, gateway: data.default_gateway || null };
  }

  /** true when a scanned range (CIDR or "a-b") shares no address with any IPv4 subnet this PC is on: an old scan
   *  of another network. The subnets are `networks` (status.net.networks: every up adapter's, so a bench NIC's scan
   *  is not "elsewhere" while Wi-Fi carries the internet), else the internet adapter's (`nic` =
   *  status.netinfo.internet_nic, see netNicCidr). Needs TNT.subnet (js/tools/subnet.js) at call time; false
   *  whenever it cannot tell. */
  function netRunElsewhere(range, nic, networks) {
    const S = TNT.subnet;
    const text = String(range == null ? '' : range).trim();
    if (!S || !text) return false;
    const usable = (p) => !!p && p.ok && !p.assumed_prefix;
    let mine = (Array.isArray(networks) ? networks : []).map((n) => S.parse(String(n))).filter(usable);
    if (!mine.length) {
      const cidr = netNicCidr(nic);
      mine = [cidr ? S.parse(cidr) : null].filter(usable);
    }
    if (!mine.length) return false;
    let lo, hi;
    if (text.includes('/')) {
      const r = S.parse(text);
      if (!r.ok) return false;
      lo = S.ipToInt(r.network); hi = S.ipToInt(r.broadcast);
    } else {
      const m = /^(\S+)\s*-\s*(\S+)$/.exec(text);
      const a = m ? S.ipToInt(m[1]) : S.ipToInt(text), b = m ? S.ipToInt(m[2]) : a;
      if (a == null || b == null) return false;
      lo = Math.min(a, b); hi = Math.max(a, b);
    }
    if (lo == null || hi == null) return false;
    return mine.every((p) => hi < S.ipToInt(p.network) || lo > S.ipToInt(p.broadcast));
  }

  api.net = {
    compare: netCompare, fromEvent: netFromEvent, merge: netMerge, toastPlan: netToastPlan, toastText: netToastText,
    toastWanted: netToastWanted,
    summaryFromStatus: netSummaryFromStatus, nicFromEvent: netNicFromEvent, nicCidr: netNicCidr, networkOf: netNetworkOf,
    runElsewhere: netRunElsewhere,
    STALE_GRACE_MS: NET_STALE_GRACE_MS, TOAST_GAP_MS: NET_TOAST_GAP_MS,
  };

  api.captureQuery = captureQuery;
  api.sipQuery = sipQuery;

  /* ---------------------------------------------------------- quick tools */
  // Pure: what the Tools page's IP Release/Renew and Flush DNS buttons say once the service answered (app.js drives them;
  // node tests load this file on its own).
  const QUICK_NAMES = { renew: 'IP Release/Renew', flush: 'Flush DNS' };

  /** A quick tool's answer (RENEW_RESULT / FLUSH_RESULT) or the ApiError of its request -> { ok, kind, text }: `ok` picks
   *  the button's green or red flash, `kind` and `text` the toast. Whatever the service says is shown as it is: a refusal
   *  (403: not an administrator, or a page of another origin; 409: one is running already; 503: not available), a failed
   *  renew's error with the first warning, and a warning that came with a renew that worked. */
  function quickOutcome(tool, r, err) {
    const renew = tool === 'renew';
    const name = QUICK_NAMES[tool] || 'This tool';
    if (err) {
      const status = err.status || 0;
      let text;
      if (status === 403 || status === 409) text = err.message || name + ' was refused';
      else if (status === 503) text = err.message || name + ' is not available on this service';
      else if (status === 404) text = name + ' is not available on this service';     // an older service without the route
      else text = (renew ? 'Could not release and renew the IP address: ' : 'Could not flush the DNS cache: ') + (err.message || 'unknown error');
      const refused = status === 409 || (status === 403 && err.code === 'admin_required');
      return { ok: false, kind: refused ? 'warn' : 'error', text };
    }
    r = r || {};
    const warning = (Array.isArray(r.warnings) ? r.warnings.filter(Boolean).map(String) : [])[0];
    const more = warning ? ' · ' + warning : '';
    if (renew && r.ok) {
      return { ok: true, kind: warning ? 'warn' : 'ok', text: 'IP address renewed' + (r.address ? ': ' + r.address : '') + (r.adapter ? ' on ' + r.adapter : '') + more };
    }
    if (renew) return { ok: false, kind: 'error', text: 'IP release/renew failed: ' + (r.error || 'no address came back') + more };
    if (r.ok) return { ok: true, kind: 'ok', text: 'DNS cache flushed' };
    return { ok: false, kind: 'error', text: 'Could not flush the DNS cache: ' + (r.error || 'unknown error') };
  }

  api.quick = { outcome: quickOutcome, NAMES: QUICK_NAMES };

  /* ------------------------------------------------------- clear history */
  // Pure: Settings › History (app.js drives it; node tests load this file on its own). The eight ranges are the service's
  // tnt.history.RANGES / RANGE_LABELS, kept here as a copy because the page must draw the select before any request lands
  // (a test holds the two equal).
  const HISTORY_RANGES = [
    ['5m', 'Last 5 minutes'], ['30m', 'Last 30 minutes'], ['1h', 'Last hour'], ['6h', 'Last 6 hours'],
    ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days'], ['all', 'All time'],
  ];
  const HISTORY_DEFAULT = '1h';
  //: what a clear takes, in the order the confirm dialog and the Settings text name them (Wi-Fi is this window's own survey)
  const HISTORY_WHAT = ['Ping history', 'Outages', 'Speed tests', 'Previous discovery scans',
    "Packet captures saved in TNT's own folder", 'Fault history (the fault watch starts again from now)',
    'SIP results', 'Wi-Fi scans', 'Pro AV scans'];
  //: each count of the service's `cleared`, singular and plural, in the order the summary lists them (faults is a flag, below)
  const HISTORY_NOUNS = [
    ['ping', 'minute of ping history', 'minutes of ping history'], ['outages', 'outage', 'outages'],
    ['speed', 'speed test', 'speed tests'], ['discovery', 'discovery scan', 'discovery scans'],
    ['captures', 'packet capture', 'packet captures'], ['sip', 'SIP result', 'SIP results'],
    ['proav', 'Pro AV scan', 'Pro AV scans'],
  ];
  //: why Wi-Fi was left alone, for each way the page cannot reach the survey
  const HISTORY_WIFI_TEXT = {
    nobridge: 'Wi-Fi scans are kept by the TNT window, and this page is not it: clear them from the TNT window',
    nosurvey: 'this TNT window has no Wi-Fi survey to clear',
    nosince: 'the service did not say when the cleared time began, so the Wi-Fi survey was kept',
    outdated: 'this TNT window is older than the service and can only clear its whole Wi-Fi survey: pick All time, or use Clear on the WiFi page',
  };
  //: a refusal the service may send without a message of its own (an older service answers 404: it has no clear at all)
  const HISTORY_REFUSED = {
    full_scan_running: 'A Full Scan is running and reads this history as it goes. Clear it once the scan has finished.',
    clear_running: 'History is already being cleared. Try again in a moment.',
    bad_range: 'That time range is not one TNT knows.',
  };

  function historyLabel(key) {
    const r = HISTORY_RANGES.find((x) => x[0] === key);
    return r ? r[1] : String(key == null ? '' : key);
  }

  /** "in the last hour" / "in the last 7 days" / "ever" for a range key: how the confirm dialog names the range. */
  function historyPhrase(key) {
    if (key === 'all') return 'ever';
    return 'in the ' + historyLabel(key).toLowerCase();
  }

  /** The ApiError of POST /api/history/clear -> { kind, text }. A 409 (a Full Scan or another clear running) and a 400 are
   *  refusals, shown as the service words them; nothing was cleared. */
  function historyErrorOutcome(err) {
    const status = (err && err.status) || 0;
    const code = (err && err.code) || '';
    const message = err && err.message ? String(err.message) : '';
    if (status === 409 || status === 400 || status === 403) {
      return { kind: 'warn', text: message || HISTORY_REFUSED[code] || 'The service refused to clear history' };
    }
    if (status === 404) return { kind: 'error', text: 'This TNT service cannot clear history (it is older than this page)' };
    // no answer at all (a timeout, the link dropped): the service may well have cleared, so the page says it does not know
    // and waits a while for the history.cleared event, which it then treats as its own answer
    if (status === 0 && (code === 'timeout' || code === 'network')) {
      return { kind: 'warn', unknown: true, text: 'No answer from the service (' + (message || 'no reply') + '), so TNT cannot tell '
        + 'whether history was cleared. This window updates on its own if it was.' };
    }
    return { kind: 'error', text: 'Could not clear history: ' + (message || 'unknown error') };
  }

  /** What the page does about Wi-Fi for a clear answered with `res`, given the bridge methods it has ({ wifi_clear_since,
   *  wifi_clear, wifi_survey }: truthy when the window offers them, or null for no bridge at all) -> { call, args } or
   *  { skip: reason }. The survey lives in the TNT window's own process, so only the page can reach it. */
  function historyWifiPlan(res, bridge) {
    // Only 'all' clears the whole survey. Any other range needs a real start time: without one the page cannot tell what
    // to drop, and it keeps the survey rather than guess in the direction that deletes readings.
    const all = !!res && res.range === 'all';
    const since = res && typeof res.since_ts === 'number' && isFinite(res.since_ts) ? res.since_ts : null;
    if (!bridge) return { skip: HISTORY_WIFI_TEXT.nobridge };
    if (!all && since == null) return { skip: HISTORY_WIFI_TEXT.nosince };
    if (bridge.wifi_clear_since) return { call: 'wifi_clear_since', args: [all ? null : since] };
    if (all && bridge.wifi_clear) return { call: 'wifi_clear', args: [] };
    if (bridge.wifi_clear || bridge.wifi_survey) return { skip: HISTORY_WIFI_TEXT.outdated };
    return { skip: HISTORY_WIFI_TEXT.nosurvey };
  }

  /** The bridge's answer -> the Wi-Fi outcome the summary reports: { state: 'cleared', points, aps } | { state: 'failed', reason }. */
  function historyWifiResult(r) {
    if (!r || typeof r !== 'object' || r.ok === false) {
      return { state: 'failed', reason: r && r.error ? String(r.error) : 'the TNT window did not clear its Wi-Fi survey' };
    }
    const num = (v) => (typeof v === 'number' && isFinite(v) ? v : null);
    return { state: 'cleared', points: num(r.points_dropped), aps: num(r.aps_dropped) };
  }

  const plural = (n, one, many) => n + ' ' + (n === 1 ? one : many);

  /** The one toast after a clear: the service's answer `res` (the history.cleared dict) and the Wi-Fi outcome (from
   *  historyWifiResult, or { state: 'skipped', reason }) -> { kind, title, lines }. Every string in it is text for
   *  textContent: the label, the stopped jobs and the skipped reasons are the service's words. */
  function historySummary(res, wifi) {
    res = res && typeof res === 'object' ? res : {};
    const cleared = res.cleared && typeof res.cleared === 'object' ? res.cleared : {};
    const count = (k) => { const v = Number(cleared[k]); return isFinite(v) && v > 0 ? Math.round(v) : 0; };
    const gone = [];
    for (const [key, one, many] of HISTORY_NOUNS) if (count(key)) gone.push(plural(count(key), one, many));
    if (wifi && wifi.state === 'cleared') {
      if (wifi.points != null) {
        let t = plural(wifi.points, 'Wi-Fi reading', 'Wi-Fi readings');
        if (wifi.aps) t += ' (' + plural(wifi.aps, 'access point', 'access points') + ' gone)';
        if (wifi.points || wifi.aps) gone.push(t);
      } else gone.push('the Wi-Fi survey');
    }
    const lines = [];
    // no `cleared` at all: this window lost the service's answer and learned of the clear later (GET /api/history's
    // newest entry carries no counts), so it says what it knows rather than "nothing was recorded"
    const counted = !!(res.cleared && typeof res.cleared === 'object');
    if (!counted) lines.push('The clear finished while this window could not hear the service, so it cannot say what went.');
    if (gone.length) lines.push('Removed ' + gone.join(', ') + '.');
    else if (counted) lines.push('Nothing was recorded in that time.');
    if (count('faults')) lines.push('The fault watch starts again from now.');
    const stopped = (Array.isArray(res.stopped) ? res.stopped : []).map((s) => String(s == null ? '' : s)).filter(Boolean);
    if (stopped.length) lines.push('Stopped: ' + stopped.join(', ') + '.');
    const skipped = (Array.isArray(res.skipped) ? res.skipped : []).filter((s) => s && typeof s === 'object')
      .map((s) => ({ what: String(s.what == null ? '' : s.what), reason: String(s.reason == null ? '' : s.reason) }));
    if (wifi && (wifi.state === 'skipped' || wifi.state === 'failed')) skipped.push({ what: 'Wi-Fi', reason: String(wifi.reason || '') });
    for (const s of skipped) lines.push('Left alone: ' + (s.what || 'something') + (s.reason ? ' - ' + s.reason : '') + '.');
    const label = res.label ? String(res.label) : historyLabel(res.range);
    // a Wi-Fi survey this page could not reach is expected in a browser tab: only the service's own skips, or a bridge that
    // failed, make the toast a warning
    const warn = (Array.isArray(res.skipped) && res.skipped.length > 0) || (wifi && wifi.state === 'failed');
    return { kind: warn ? 'warn' : 'ok', title: 'History cleared: ' + label, lines };
  }

  /** Settings › History's status line for the newest clear (GET /api/history's `last`, or the history.cleared event read
   *  the same way: { range, at }) at time `now`, with `rel` = TNT.util.relTime. */
  function historyStatusText(last, now, rel) {
    if (!last || typeof last !== 'object') return 'Nothing has been cleared yet.';
    const at = typeof last.at === 'number' ? last.at : (typeof last.ts === 'number' ? last.ts : null);
    const when = at != null && rel ? ' · ' + rel(at, now) : '';
    return 'Last cleared: ' + historyLabel(last.range) + when + '.';
  }

  /** Whether GET /api/history's newest clear `last` ({since_ts, at, range}) is one this window never heard of, given
   *  `known`: undefined before the first answer (that answer only sets the baseline), else the `at`/`ts` of the newest
   *  clear it knows (null for none). A clear while the event stream was down, or in a tab polling /api/status, is caught
   *  this way on the next 'hello' or poll. The service stores the clear's `at` as the answer's `ts` (the same number), so
   *  only a millisecond of slack is allowed against `known`: two clears a second apart are still two clears. `seen`
   *  (optional) is every clear this window did handle, as {ts, range}: an entry of the same range within a few seconds of
   *  `at` is that clear, so a service that ever stamps `at` a little after the answer's `ts` cannot make every window
   *  toast "History cleared elsewhere" and re-mount its page a second time. */
  const HISTORY_SAME_CLEAR_S = 5;
  function historyMissed(known, last, seen) {
    if (known === undefined || !last || typeof last !== 'object') return false;
    const at = typeof last.at === 'number' && isFinite(last.at) ? last.at : null;
    if (at == null) return false;
    if (!(known == null || at > known + 0.001)) return false;
    for (const e of Array.isArray(seen) ? seen : []) {
      if (e && e.range === last.range && typeof e.ts === 'number' && Math.abs(e.ts - at) <= HISTORY_SAME_CLEAR_S) return false;
    }
    return true;
  }

  /** Whether a speedtest.done or discovery.done event is a job the clear cancelled or voided (no "Speed test failed", no
   *  "Scan finished" for it). The service marks the event itself: {"silent": true, "cancel_reason": "history cleared"}
   *  next to `result` (a discovery.done may keep cancelled false: a scan that finished while the clear ran is voided).
   *  Tolerant of where the mark is: a cancelled_by / cancel_reason naming history on the event or its result, or only
   *  a failed result whose error says history was cleared. */
  function historyCancelledTest(d) {
    if (!d || typeof d !== 'object') return false;
    const r = d.result && typeof d.result === 'object' ? d.result : {};
    const by = (v) => typeof v === 'string' && v.toLowerCase().indexOf('history') >= 0;
    if (by(d.cancelled_by) || by(r.cancelled_by) || by(r.cancel_reason) || by(d.cancel_reason)) return true;
    return r.ok === false && /history cleared/i.test(String(r.error || ''));
  }

  api.history = {
    RANGES: HISTORY_RANGES, DEFAULT: HISTORY_DEFAULT, WHAT: HISTORY_WHAT, WIFI_TEXT: HISTORY_WIFI_TEXT, REFUSED: HISTORY_REFUSED,
    label: historyLabel, phrase: historyPhrase, errorOutcome: historyErrorOutcome, wifiPlan: historyWifiPlan,
    wifiResult: historyWifiResult, summary: historySummary, statusText: historyStatusText, cancelledTest: historyCancelledTest,
    missed: historyMissed,
  };

  /* ------------------------------------------------------------------ SSE */
  const KNOWN_EVENTS = [
    'hello', 'ping.sample', 'ping.targets', 'outage.start', 'outage.end',
    'speedtest.start', 'speedtest.progress', 'speedtest.done',
    'discovery.progress', 'discovery.done', 'settings.changed', 'monitoring.paused',
    'dhcp.state', 'dhcp.lease', 'dhcp.scan', 'map.sample', 'throughput.sample', 'faults.state', 'geoip.state',
    'trace.start', 'trace.hop', 'trace.done',
    'lan.peers', 'lan.state', 'lan.throughput.progress', 'lan.throughput.done',
    'net.changed',
    'report.progress', 'report.saved', 'report.deleted', 'report.updated',
    'netcheck.switch',
    'tftp.state', 'tftp.transfer',
    'capture.state', 'capture.sip',
    'history.cleared',
  ];

  /**
   * EventSource wrapper: reconnects with exponential backoff (1 s → 30 s), reports its
   * state ('connecting' | 'live' | 'offline') and, while not live, polls /api/status every
   * 5 s and dispatches the result as a synthetic 'status.poll' event.
   */
  class Events {
    constructor() {
      this.state = 'connecting';
      this._es = null;
      this._handlers = new Map();      // type -> Set<fn>
      this._stateHandlers = new Set();
      this._attempt = 0;
      this._timer = null;
      this._pollTimer = null;
      this._closed = false;
      this._bound = new Set();         // event types bound on the current EventSource
      this._lastEventTs = 0;
      this._watchdog = null;
      this.pollInterval = 5000;
      this.maxBackoff = 30000;
    }

    on(type, fn) {
      if (!this._handlers.has(type)) this._handlers.set(type, new Set());
      this._handlers.get(type).add(fn);
      if (this._es && !this._bound.has(type) && type !== 'status.poll') this._bind(type);
      return () => { const s = this._handlers.get(type); if (s) s.delete(fn); };
    }

    onState(fn) {
      this._stateHandlers.add(fn);
      try { fn(this.state); } catch (e) { console.error(e); }
      return () => this._stateHandlers.delete(fn);
    }

    _emit(type, data, raw) {
      const s = this._handlers.get(type);
      if (!s) return;
      for (const fn of Array.from(s)) {
        try { fn(data, raw); } catch (err) { console.error('event handler failed for ' + type, err); }
      }
    }

    _setState(state) {
      if (this.state === state) return;
      this.state = state;
      for (const fn of Array.from(this._stateHandlers)) {
        try { fn(state); } catch (err) { console.error(err); }
      }
      if (state === 'live') this._stopPolling(); else this._startPolling();
    }

    _bind(type) {
      if (!this._es) return;
      this._bound.add(type);
      this._es.addEventListener(type, (ev) => {
        this._lastEventTs = Date.now();
        let data = null;
        try { data = ev.data ? JSON.parse(ev.data) : null; } catch (e) { data = ev.data; }
        if (type === 'hello') { this._attempt = 0; this._setState('live'); }
        this._emit(type, data, ev);
      });
    }

    connect() {
      this._closed = false;
      this._open();
      if (!this._watchdog) {
        // `: ping` comments are invisible to EventSource, so a stream with no targets is
        // silent. If nothing arrived for 90 s reopen it quietly (state stays 'live'; a real
        // failure surfaces through onerror as usual).
        this._watchdog = setInterval(() => {
          if (this.state === 'live' && this._lastEventTs && Date.now() - this._lastEventTs > 90000) {
            this._reconnect('stale');
          }
        }, 10000);
      }
    }

    _open(quiet) {
      if (this._closed || typeof EventSource === 'undefined') { this._setState('offline'); return; }
      this._cleanupSource();
      this._bound.clear();
      let es;
      try {
        es = new EventSource(BASE + '/events');
      } catch (err) {
        this._setState('offline');
        this._schedule();
        return;
      }
      this._es = es;
      this._lastEventTs = Date.now();
      if (!quiet) this._setState(this._attempt === 0 ? 'connecting' : 'offline');
      for (const t of KNOWN_EVENTS) this._bind(t);
      for (const t of this._handlers.keys()) if (!this._bound.has(t) && t !== 'status.poll') this._bind(t);
      es.onopen = () => { this._lastEventTs = Date.now(); };
      es.onmessage = () => { this._lastEventTs = Date.now(); };
      es.onerror = () => { this._reconnect('error'); };
    }

    _reconnect(reason) {
      this._cleanupSource();
      if (reason === 'stale') { this._open(true); return; }
      this._setState('offline');
      this._schedule();
    }

    _schedule() {
      if (this._closed || this._timer) return;
      const base = Math.min(this.maxBackoff, 1000 * Math.pow(2, this._attempt));
      const delay = Math.round(base * (0.7 + Math.random() * 0.6));
      this._attempt = Math.min(this._attempt + 1, 10);
      this._timer = setTimeout(() => { this._timer = null; this._open(); }, delay);
    }

    _cleanupSource() {
      if (this._es) {
        try { this._es.onerror = null; this._es.onopen = null; this._es.close(); } catch (e) { /* ignore */ }
        this._es = null;
      }
    }

    _startPolling() {
      if (this._pollTimer || this._closed) return;
      const tick = async () => {
        if (this.state === 'live' || this._closed) { this._stopPolling(); return; }
        try {
          const st = await api.status();
          this._emit('status.poll', st);
          // The API answers again (service restarted): do not sit out the rest of the
          // exponential backoff - cancel the pending retry and reconnect the stream now.
          if (this.state !== 'live' && !this._es) {
            if (this._timer) { clearTimeout(this._timer); this._timer = null; }
            this._attempt = 0;
            this._open(true);
          }
        } catch (err) {
          this._emit('status.poll', null, err);
        }
      };
      this._pollTimer = setInterval(tick, this.pollInterval);
      tick();
    }

    _stopPolling() {
      if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; }
    }

    close() {
      this._closed = true;
      if (this._timer) { clearTimeout(this._timer); this._timer = null; }
      if (this._watchdog) { clearInterval(this._watchdog); this._watchdog = null; }
      this._stopPolling();
      this._cleanupSource();
      this._setState('offline');
    }
  }

  api.events = new Events();
  api.Events = Events;
  TNT.api = api;
})();
