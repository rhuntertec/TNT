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
      return { blob, filename: m ? decodeURIComponent(m[1].trim()) : null, headers: resp.headers };
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
    del: (path, opts) => request('DELETE', path, undefined, opts),

    // convenience wrappers for every route in the contract
    health: () => api.get('/health'),
    status: () => api.get('/status'),
    netinfo: () => api.get('/netinfo'),
    targets: () => api.get('/targets'),
    addTarget: (host, label) => api.post('/targets', label ? { host, label } : { host }),
    removeTarget: (id) => api.del('/targets/' + encodeURIComponent(id)),
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
  };

  /* ------------------------------------------------------------------ SSE */
  const KNOWN_EVENTS = [
    'hello', 'ping.sample', 'ping.targets', 'outage.start', 'outage.end',
    'speedtest.start', 'speedtest.progress', 'speedtest.done',
    'discovery.progress', 'discovery.done', 'settings.changed', 'monitoring.paused',
    'dhcp.state', 'dhcp.lease', 'dhcp.scan', 'map.sample',
    'trace.start', 'trace.hop', 'trace.done',
    'lan.peers', 'lan.state', 'lan.throughput.progress', 'lan.throughput.done',
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
