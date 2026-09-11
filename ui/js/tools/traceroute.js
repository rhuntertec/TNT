/* TNT — tools/traceroute.js
   The "Traceroute" card of the Tools view: a host input with Run / Cancel and collapsed options,
   a sticker path map (This PC -> one node per hop -> destination) that fills in live from the
   trace.hop events, a compact hop table and a summary line. The last trace is restored from
   GET /api/tools/traceroute/last on mount. Cancel is client-side only: the service keeps tracing.
   Loaded before app.js: TNT.util / TNT.ui are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.tools = TNT.tools || {};

  const DEFAULT_HOST = 'totalelectronics.com';
  const RTT_WARN_MS = 20;    // under this: green
  const RTT_BAD_MS = 100;    // under this: yellow, else red
  const KIND_ICON = { gateway: 'router', lan: 'lan', public: 'cloud', destination: 'target', unknown: 'question' };
  const KIND_LABEL = { gateway: 'Gateway', lan: 'LAN', public: 'Internet', destination: 'Destination', unknown: 'Unknown' };
  const KIND_BADGE = { gateway: 'orange', lan: 'green', public: 'blue', destination: 'red', unknown: 'grey' };

  /* ------------------------------------------------ pure helpers (tests) */
  /** Traffic-light class for an average round trip: green < 20 ms, yellow < 100 ms, red above; grey when silent. */
  function rttClass(ms) {
    if (ms == null || !isFinite(ms)) return 'grey';
    if (ms < RTT_WARN_MS) return 'green';
    if (ms < RTT_BAD_MS) return 'yellow';
    return 'red';
  }
  /** Icon name for a hop: by kind, a question mark when nothing answered. */
  function hopIcon(hop) {
    if (!hop || !hop.ip) return 'question';
    return KIND_ICON[hop.kind] || 'cloud';
  }
  function hopLabel(hop) {
    if (!hop) return '';
    if (hop.label) return hop.label;
    if (!hop.ip) return 'No reply';
    return KIND_LABEL[hop.kind] || 'Unknown';
  }
  /** One trace.hop event applied to a hop list: replaces the same ttl, else inserts in ttl order. */
  function mergeHop(hops, hop) {
    const out = (hops || []).slice();
    if (!hop || hop.ttl == null) return out;
    const i = out.findIndex((x) => x.ttl === hop.ttl);
    if (i >= 0) out[i] = hop; else { out.push(hop); out.sort((a, b) => a.ttl - b.ttl); }
    return out;
  }
  function fmtSeconds(s) {
    if (s == null || !isFinite(s)) return '?';
    return (s < 10 ? s.toFixed(1) : String(Math.round(s))) + ' s';
  }
  /** { text, cls } for the line under the form. status: idle | running | cancelled | done */
  function summaryText(trace, status) {
    if (!trace) return { text: 'No trace yet — type a host and hit Run', cls: 'muted' };
    const hops = (trace.hops || []).length;
    const where = trace.host + (trace.target_ip && trace.target_ip !== trace.host ? ' (' + trace.target_ip + ')' : '');
    if (status === 'running') return { text: 'Tracing ' + where + '… hop ' + hops + ' of ' + (trace.max_hops || 30), cls: 'live' };
    if (status === 'cancelled') return { text: 'Stopped watching after ' + hops + (hops === 1 ? ' hop' : ' hops') + ' — the service finishes the trace to ' + where + ' on its own', cls: 'muted' };
    if (trace.error) return { text: trace.error, cls: 'bad' };
    let text = hops + (hops === 1 ? ' hop' : ' hops') + ' to ' + where + ' in ' + fmtSeconds(trace.duration_s);
    text += trace.complete ? ' · complete' : ' · gave up after ' + (trace.max_hops || hops) + ' hops without reaching the host';
    return { text, cls: trace.complete ? 'ok' : 'warn' };
  }

  /* ------------------------------------------------------------- card */
  function create() {
    const { h } = TNT.util;
    let trace = null;          // TRACE DICT (or a partial one while hops arrive)
    let status = 'idle';       // idle | running | cancelled | done
    let ownRun = false;        // our POST is in flight: its result replaces everything
    let runGen = 0;
    let mounted = false;
    let unsubs = [];
    const els = {};

    const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
    const statePc = () => {
      const st = TNT.state && TNT.state.status;
      const pc = (st && st.map && st.map.pc) || {};
      return { ip: pc.ip || null, hostname: pc.hostname || null };
    };

    // ---- form
    els.badge = h('span', { class: 'badge grey' }, 'idle');
    els.host = h('input', { class: 'input', type: 'text', value: DEFAULT_HOST, placeholder: 'host name or IP', 'aria-label': 'Host to trace', spellcheck: 'false', autocomplete: 'off' });
    els.host.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); });
    els.runBtn = h('button', { class: 'btn btn-primary', type: 'button', on: { click: run }, title: 'Trace the route to the host, one hop at a time (up to ~60 s)' }, TNT.ui.icon('route'), 'Run');
    els.cancelBtn = h('button', { class: 'btn', type: 'button', hidden: true, on: { click: cancel },
      title: 'Stops showing new hops here only — the service keeps tracing in the background until it reaches the host or the hop limit.' }, TNT.ui.icon('stop'), 'Cancel');
    els.optBtn = h('button', { class: 'btn btn-sm', type: 'button', 'aria-expanded': 'false', title: 'Hop limit, probes per hop and the reply timeout', on: { click: toggleOptions } }, TNT.ui.icon('gear'), 'Options');
    els.maxHops = h('input', { class: 'input sm', type: 'number', min: '1', max: '64', step: '1', value: '30', 'aria-label': 'Maximum hops' });
    els.probes = h('input', { class: 'input sm', type: 'number', min: '1', max: '5', step: '1', value: '3', 'aria-label': 'Probes per hop' });
    els.timeout = h('input', { class: 'input sm', type: 'number', min: '0.2', max: '10', step: '0.1', value: '1.5', 'aria-label': 'Reply timeout in seconds' });
    els.resolve = TNT.ui.toggle({ checked: true, on: 'Names', off: 'IPs only', accent: 'var(--blue)' });
    els.resolve.input.setAttribute('aria-label', 'Resolve host names');
    for (const k of ['maxHops', 'probes', 'timeout']) els[k].addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); });
    els.options = h('div', { class: 'form-row tool-options', hidden: true },
      h('div', { class: 'field' }, h('label', null, 'Max hops'), els.maxHops),
      h('div', { class: 'field' }, h('label', null, 'Probes per hop'), els.probes),
      h('div', { class: 'field' }, h('label', null, 'Timeout (s)'), els.timeout),
      h('div', { class: 'field' }, h('label', null, 'Host names'), els.resolve));
    const form = h('div', { class: 'form-row tool-form' },
      h('div', { class: 'field wide' }, h('label', null, 'Host'), els.host),
      els.runBtn, els.cancelBtn, els.optBtn);

    // ---- results
    els.summary = h('div', { class: 'tool-summary', role: 'status', 'aria-live': 'polite' });
    els.map = h('div', { class: 'tr-map', hidden: true });
    els.tbody = h('tbody');
    const th = (t, cls) => h('th', { class: cls || null }, t);
    els.tableWrap = h('div', { class: 'table-wrap', hidden: true },
      h('table', { class: 'table tr-table' },
        h('thead', null, h('tr', null, th('Hop', 'num'), th('IP'), th('Hostname'), th('Min', 'num'), th('Avg', 'num'), th('Max', 'num'), th('Loss', 'num'), th('Kind'))),
        els.tbody));
    const body = h('div', { class: 'tool-body' }, form, els.options, els.summary, els.map, els.tableWrap);

    function toggleOptions() {
      const open = els.options.hidden;
      els.options.hidden = !open;
      els.optBtn.setAttribute('aria-expanded', String(open));
    }

    // ---- rendering
    function setStatus(s) { status = s; }
    function renderBadge() {
      const b = status === 'running' ? { cls: 'yellow pulse', text: 'tracing…' }
        : status === 'cancelled' ? { cls: 'grey', text: 'stopped' }
          : trace && trace.error ? { cls: 'red', text: 'error' }
            : trace ? (trace.complete ? { cls: 'green', text: 'complete' } : { cls: 'yellow', text: 'incomplete' })
              : { cls: 'grey', text: 'idle' };
      els.badge.className = 'badge ' + b.cls;
      els.badge.textContent = b.text;
    }
    function renderSummary() {
      const s = summaryText(trace, status);
      els.summary.className = 'tool-summary ' + s.cls;
      els.summary.innerHTML = '';
      if (s.cls === 'live') els.summary.appendChild(h('span', { class: 'spark-icon' }, TNT.ui.icon('spark')));
      if (s.cls === 'bad') els.summary.appendChild(TNT.ui.icon('warning'));
      els.summary.appendChild(h('span', null, s.text));
    }
    function pcNode(pc) {
      const { copyCode } = TNT.util;
      return h('div', { class: 'tr-node pc', title: 'This PC' + (pc.hostname ? ' · ' + pc.hostname : '') },
        h('span', { class: 'tr-icon' }, TNT.ui.icon('computer')),
        h('div', { class: 'tr-name' }, 'This PC'),
        pc.ip ? copyCode(pc.ip) : h('div', { class: 'tr-host' }, '—'),
        pc.hostname ? h('div', { class: 'tr-host', title: pc.hostname }, pc.hostname) : null);
    }
    function hopNode(hop, probes) {
      const { copyCode, fmtMs } = TNT.util;
      const silent = !hop.ip;
      const cls = rttClass(hop.avg_ms);
      const tips = [hopLabel(hop)];
      if (hop.hostname) tips.push(hop.hostname);
      if (Array.isArray(hop.alt_ips) && hop.alt_ips.length) tips.push('also answered from ' + hop.alt_ips.join(', '));
      if (hop.min_ms != null) tips.push('min ' + fmtMs(hop.min_ms) + ' · avg ' + fmtMs(hop.avg_ms) + ' · max ' + fmtMs(hop.max_ms) + ' ms');
      if (hop.loss) tips.push(hop.loss + ' of ' + probes + ' probes lost');
      return h('div', { class: 'tr-node kind-' + (hop.kind || 'unknown') + (silent ? ' silent' : ''), title: tips.join(' · ') },
        h('span', { class: 'tr-hop' }, String(hop.ttl)),
        h('span', { class: 'tr-icon' }, TNT.ui.icon(hopIcon(hop))),
        h('div', { class: 'tr-name' }, hopLabel(hop)),
        silent ? h('div', { class: 'tr-host' }, '* * *') : copyCode(hop.ip),
        hop.hostname ? h('div', { class: 'tr-host', title: hop.hostname }, hop.hostname) : null,
        h('span', { class: 'tr-rtt ' + cls }, hop.avg_ms != null ? fmtMs(hop.avg_ms) + ' ms' : 'no reply'),
        hop.loss > 0 && !silent ? h('div', { class: 'tr-loss' }, hop.loss + '/' + probes + ' lost') : null);
    }
    function renderMap() {
      els.map.innerHTML = '';
      if (!trace) { els.map.hidden = true; return; }
      els.map.hidden = false;
      const probes = trace.probes || 3;
      els.map.appendChild(pcNode(trace.pc && trace.pc.ip ? trace.pc : statePc()));
      for (const hop of trace.hops || []) {
        els.map.appendChild(h('span', { class: 'tr-link ' + (hop.ip ? rttClass(hop.avg_ms) : 'grey'), 'aria-hidden': 'true' }));
        els.map.appendChild(hopNode(hop, probes));
      }
      if (status === 'running') {
        els.map.appendChild(h('span', { class: 'tr-link grey', 'aria-hidden': 'true' }));
        els.map.appendChild(h('div', { class: 'tr-node pending', title: 'Waiting for the next hop' },
          h('span', { class: 'tr-icon' }, h('span', { class: 'spark-icon' }, TNT.ui.icon('spark'))),
          h('div', { class: 'tr-name' }, 'hop ' + ((trace.hops || []).length + 1)),
          h('div', { class: 'tr-host' }, 'probing…')));
      }
    }
    function renderTable() {
      const { copyCode, fmtMs } = TNT.util;
      els.tbody.innerHTML = '';
      const hops = (trace && trace.hops) || [];
      els.tableWrap.hidden = !hops.length;
      const probes = (trace && trace.probes) || 3;
      const num = (v) => h('td', { class: 'num' }, v == null ? h('span', { class: 'muted' }, '—') : fmtMs(v));
      for (const hop of hops) {
        const tr = h('tr', { class: hop.ip ? '' : 'silent' },
          h('td', { class: 'num strong' }, String(hop.ttl)),
          h('td', null, hop.ip ? copyCode(hop.ip) : h('span', { class: 'muted' }, '* * *')),
          h('td', { class: 'wrap' }, hop.hostname ? h('span', { class: 'muted', title: hop.hostname }, hop.hostname) : h('span', { class: 'muted' }, '—')),
          num(hop.min_ms), h('td', { class: 'num strong ' + rttClass(hop.avg_ms) }, hop.avg_ms == null ? '—' : fmtMs(hop.avg_ms)), num(hop.max_ms),
          h('td', { class: 'num' + (hop.loss ? ' strong red' : '') }, (hop.loss || 0) + '/' + probes),
          h('td', null, h('span', { class: 'badge ' + (hop.ip ? (KIND_BADGE[hop.kind] || 'grey') : 'grey') }, hopLabel(hop))));
        els.tbody.appendChild(tr);
      }
    }
    function render() {
      if (!mounted) return;
      renderBadge();
      renderSummary();
      renderMap();
      renderTable();
      els.cancelBtn.hidden = status !== 'running';
      TNT.ui.busy(els.runBtn, status === 'running', 'Tracing…');
    }

    // ---- actions
    async function run() {
      if (!mounted || status === 'running') return;
      const host = (els.host.value || '').trim();
      if (!host || /\s/.test(host)) { TNT.ui.toast('Type a host name or IP address to trace', 'warn'); els.host.focus(); return; }
      const body = {
        host,
        max_hops: clamp(parseInt(els.maxHops.value, 10) || 30, 1, 64),
        probes: clamp(parseInt(els.probes.value, 10) || 3, 1, 5),
        timeout_ms: Math.round(clamp(parseFloat(els.timeout.value) || 1.5, 0.2, 10) * 1000),
        resolve_names: !!els.resolve.input.checked,
      };
      els.maxHops.value = String(body.max_hops); els.probes.value = String(body.probes); els.timeout.value = String(body.timeout_ms / 1000);
      const gen = ++runGen;
      ownRun = true;
      trace = { host, target_ip: null, ts: TNT.util.nowS(), max_hops: body.max_hops, probes: body.probes, timeout_ms: body.timeout_ms,
        complete: false, error: null, pc: statePc(), gateway: null, hops: [] };
      setStatus('running');
      render();
      try {
        const r = await TNT.api.traceroute(body);
        if (!mounted || gen !== runGen) return;
        ownRun = false;
        trace = r || trace;
        setStatus('done');
        render();
        if (r && !r.error) TNT.ui.toast((r.hops || []).length + ' hops to ' + host + (r.complete ? '' : ' (incomplete)'), r.complete ? 'ok' : 'warn');
      } catch (err) {
        if (!mounted || gen !== runGen) return;
        ownRun = false;
        if (err.status === 409) {
          // the service is busy with another trace (a second window): follow that one instead
          TNT.ui.toast('The service is still running another traceroute — showing that one', 'warn');
          loadLast();
          return;
        }
        trace = Object.assign({}, trace, { error: err.message || 'traceroute failed', complete: false });
        setStatus('done');
        render();
        TNT.ui.toast('Traceroute failed: ' + err.message, 'error');
      }
    }
    function cancel() {
      if (status !== 'running') return;
      runGen++;             // a late POST result is ignored
      ownRun = false;
      setStatus('cancelled');
      render();
    }
    async function loadLast() {
      try {
        const r = await TNT.api.tracerouteLast();
        if (!mounted || ownRun) return;
        if (r && r.trace) trace = r.trace;
        setStatus(r && r.running ? 'running' : (trace ? 'done' : 'idle'));
        if (r && r.trace && r.trace.host) els.host.value = r.trace.host;
        render();
      } catch (err) {
        if (!mounted) return;
        if (err.status === 404 || err.status === 503) { els.summary.className = 'tool-summary muted'; els.summary.textContent = 'Traceroute is not available on this service'; }
      }
    }

    // ---- events
    function onStart(d) {
      if (!mounted || !d || ownRun) return;
      trace = { host: d.host, target_ip: d.target_ip || null, ts: TNT.util.nowS(), max_hops: d.max_hops || 30, probes: d.probes || 3,
        complete: false, error: null, pc: statePc(), gateway: null, hops: [] };
      if (d.host) els.host.value = d.host;
      setStatus('running');
      render();
    }
    function onHop(d) {
      if (!mounted || !d || !d.hop || status !== 'running') return;
      if (!trace) trace = { host: d.host || '?', target_ip: d.target_ip || null, max_hops: 30, probes: 3, hops: [], complete: false, error: null, pc: statePc() };
      trace.hops = mergeHop(trace.hops, d.hop);
      if (!trace.target_ip && d.target_ip) trace.target_ip = d.target_ip;
      render();
    }
    function onDone(d) {
      if (!mounted || status !== 'running' || ownRun) return;
      if (trace && d) {
        if (Array.isArray(d.hops)) trace.hops = d.hops;
        if (d.complete != null) trace.complete = !!d.complete;
        if (d.duration_s != null) trace.duration_s = d.duration_s;
        if (d.target_ip) trace.target_ip = d.target_ip;
      }
      setStatus('done');
      render();
      loadLast();   // the canonical dict (hostnames, stats) from the service
    }

    return {
      body,
      head: els.badge,
      mount() {
        mounted = true;
        render();
        loadLast();
        unsubs.push(TNT.api.events.on('trace.start', onStart));
        unsubs.push(TNT.api.events.on('trace.hop', onHop));
        unsubs.push(TNT.api.events.on('trace.done', onDone));
        unsubs.push(TNT.api.events.on('hello', () => { if (mounted && !ownRun) loadLast(); }));
      },
      update() { /* nothing follows the status snapshot */ },
      unmount() {
        mounted = false;
        for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
        unsubs = [];
        runGen++;
        trace = null; status = 'idle'; ownRun = false;
      },
    };
  }

  TNT.tools.traceroute = { create, rttClass, hopIcon, hopLabel, mergeHop, summaryText, RTT_WARN_MS, RTT_BAD_MS };
})();
