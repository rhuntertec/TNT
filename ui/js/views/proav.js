/* TNT — views/proav.js
   The Pro AV page: point it at a broadcast-audio network and it says what is there and what is wrong with it.

   A scan joins four multicast groups on one adapter and listens — mDNS/DNS-SD for the devices, SAP for the
   announced streams, and PTP on both ports for the whole clock tree. Nothing is probed: the one question it asks is
   the mDNS meta-query the protocol exists to answer, so a room that is mid-show is never poked. A Layer 2 listen
   runs alongside for the three checks a socket cannot make (an IGMP querier, multicast flooding, DSCP marking); the
   service has the rights it needs, and where it cannot run the page says those were not checked, not that they
   passed. There is no switch for it: a tech wants the whole picture, and the API keeps `deep` for support.

   What the page shows, in the order an integrator would want it:
     - the Findings list, worst first: each one says what it measured and what to do about it;
     - the clock: the grandmaster, what it is locked to, how far away it is and how evenly its sync arrives;
     - the diagram, which is two graphs and a toggle — the PTP clock tree, and the stream flow map. Neither is a
       wiring diagram, and the note under each says why one cannot be drawn from a single port;
     - the announced streams, with the bandwidth each one really costs on the wire;
     - every device found, merged from every source that saw it.

   GET /api/proav on mount and on 'hello'; POST /api/proav/scan and /cancel drive it; proav.state and proav.progress
   move the job and GET /api/proav/result fetches the whole thing once a scan finishes. The job is also polled while
   a scan runs, so a dropped event never leaves the page stuck.
   Loaded after the other views; TNT.util / TNT.ui are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  const POLL_MS = 1200;             // the job is polled while a scan runs; the events are the primary signal
  const IDLE_MS = 15000;            // ... and the status far less often when nothing is running
  const UNAVAILABLE_TEXT = 'Pro AV scanning is not available on this service';

  const LEVEL_BADGE = { bad: 'red', warn: 'yellow', info: 'blue', good: 'green' };
  const LEVEL_TEXT = { bad: 'Problem', warn: 'Worth checking', info: 'Note', good: 'Good' };
  const LEVEL_ORDER = ['bad', 'warn', 'info', 'good'];
  const FAMILY_BADGE = {
    dante: 'blue', aes67: 'teal', ravenna: 'purple', st2110: 'purple', avb: 'orange', qsys: 'green',
    crestron: 'orange', livewire: 'pink', cobranet: 'grey', av: 'teal', other: 'grey',
  };
  const NODE_TEXT = {
    grandmaster: 'Grandmaster', boundary: 'Boundary clock', transparent: 'Transparent clock',
    follower: 'Follower', self: 'This PC', talker: 'Talker', stream: 'Stream', listener: 'Listener',
  };
  const CLOCK_ROLE_TEXT = {
    grandmaster: 'Grandmaster', boundary: 'Boundary clock', master: 'Master', follower: 'Follower',
  };

  // the diagram's geometry, in the SVG's own units (it is drawn once and scaled by the viewBox)
  const NODE_W = 200, NODE_H = 62, COL_GAP = 76, ROW_GAP = 14, PAD = 10;   // the gap holds an edge label
  const COL_W = NODE_W + COL_GAP;

  let root = null;
  let els = null;
  let data = { status: null, result: null };
  let timer = null;
  let plotName = 'clock';
  let selectedNode = null;
  let loading = false;

  /* ------------------------------------------------------------------ data */
  function job() { return (data.status && data.status.job) || null; }
  function running() { const j = job(); return !!j && j.state === 'scanning'; }

  async function loadStatus(andResult) {
    try {
      const status = await TNT.api.get('/proav');
      if (!root) return;
      data.status = status;
      if (andResult && !data.result) await loadResult();
      render();
    } catch (e) {
      if (!root) return;
      showUnavailable(e);
    }
  }

  async function loadResult() {
    try {
      const answer = await TNT.api.get('/proav/result');
      if (!root) return;
      data.result = (answer && answer.result) || null;
      selectedNode = null;
    } catch (e) { /* the status still renders; a missing result just shows the empty state */ }
  }

  function showUnavailable(err) {
    const { h } = TNT.util;
    const message = (err && err.code === 'unavailable' && err.message) || (err && err.message) || UNAVAILABLE_TEXT;
    els.body.innerHTML = '';
    els.body.appendChild(h('div', { class: 'card' }, TNT.ui.emptyState(message)));
  }

  async function scan() {
    if (loading || running()) return;
    loading = true;
    setBusy(true);
    try {
      const body = { seconds: parseInt(els.seconds.value, 10) };
      if (els.adapter.value) body.adapter = els.adapter.value;
      const answer = await TNT.api.post('/proav/scan', body);
      if (!root) return;
      if (answer && answer.job) { data.status = Object.assign({}, data.status, { job: answer.job }); }
      data.result = null;
      selectedNode = null;
      render();
      schedule();
    } catch (e) {
      TNT.ui.toast((e && e.message) || 'The scan could not start', 'error');
    } finally {
      loading = false;
      setBusy(false);
    }
  }

  async function cancel() {
    try {
      const answer = await TNT.api.post('/proav/cancel', {});
      if (!root) return;
      if (answer && answer.job) data.status = Object.assign({}, data.status, { job: answer.job });
      render();
    } catch (e) {
      TNT.ui.toast((e && e.message) || 'The scan could not be stopped', 'error');
    }
  }

  function setBusy(on) {
    if (!els || !els.scanBtn) return;
    els.scanBtn.disabled = !!on || running();
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(tick, running() ? POLL_MS : IDLE_MS);
  }

  async function tick() {
    if (!root) return;
    const wasRunning = running();
    await loadStatus(false);
    if (!root) return;
    // the listen has just ended: fetch the whole result once
    if (wasRunning && !running() && !data.result) { await loadResult(); render(); }
    schedule();
  }

  /* ---------------------------------------------------------------- render */
  function render() {
    if (!root || !els) return;
    const status = data.status;
    if (status && status.available === false) { showUnavailable({ message: status.reason }); return; }
    renderControls();
    renderBody();
  }

  function renderControls() {
    const status = data.status || {};
    const j = job() || {};
    const adapters = status.adapters || [];
    if (els.adapter.dataset.filled !== String(adapters.length) + (adapters[0] ? adapters[0].name : '')) {
      const chosen = els.adapter.value;
      els.adapter.innerHTML = '';
      for (const a of adapters) {
        const speed = a.speed_mbps ? ' · ' + (a.speed_mbps >= 1000 ? (a.speed_mbps / 1000) + ' Gb/s' : a.speed_mbps + ' Mb/s') : '';
        els.adapter.appendChild(TNT.util.h('option', { value: a.name }, a.name + ' · ' + a.ip + speed));
      }
      if (chosen && adapters.some((a) => a.name === chosen)) els.adapter.value = chosen;
      els.adapter.dataset.filled = String(adapters.length) + (adapters[0] ? adapters[0].name : '');
    }
    const on = running();
    els.scanBtn.hidden = on;
    els.stopBtn.hidden = !on;
    els.adapter.disabled = on;
    els.seconds.disabled = on;
    els.progress.hidden = !on;
    if (on) {
      const pct = Math.round((j.pct || 0) * 100);
      els.bar.style.width = pct + '%';
      const counts = j.counts || {};
      els.progressText.textContent =
        (j.phase === 'listening' ? 'Listening… ' : (j.phase || 'Working') + '… ')
        + pct + '%  ·  ' + (counts.mdns || 0) + ' service replies, ' + (counts.ptp || 0) + ' clock messages, '
        + (counts.streams || 0) + ' stream' + ((counts.streams || 0) === 1 ? '' : 's');
    }
    els.lastRun.textContent = status.last_run_ts ? 'Last scan ' + TNT.util.relTime(status.last_run_ts) : '';
    if (j.state === 'error' && j.error) {
      els.error.hidden = false;
      els.error.textContent = j.error;
    } else {
      els.error.hidden = true;
    }
  }

  function renderBody() {
    const { h } = TNT.util;
    const result = data.result;
    els.body.innerHTML = '';
    if (!result) {
      const j = job() || {};
      els.body.appendChild(h('div', { class: 'card' }, TNT.ui.emptyState(
        j.state === 'scanning' ? 'Listening to the network…'
          : 'Run a scan to see what is on this network, what it is streaming and what clock it is following.')));
      return;
    }
    els.body.appendChild(summaryCard(result));
    els.body.appendChild(findingsCard(result));
    const clock = clockCard(result);
    if (clock) els.body.appendChild(clock);
    els.body.appendChild(diagramCard(result));
    els.body.appendChild(streamsCard(result));
    els.body.appendChild(devicesCard(result));
    const listen = listenCard(result);
    if (listen) els.body.appendChild(listen);
  }

  /* ---- summary ---- */
  function summaryCard(result) {
    const { h, fmtNum } = TNT.util;
    const counts = result.counts || {};
    const best = (result.clock || {}).best || null;
    const master = best && best.master;
    const worst = worstLevel(result.findings || []);
    const totalMbps = (result.streams || []).reduce((a, s) => a + (s.bitrate_mbps || 0), 0);
    const kpi = (label, value, sub, cls) => h('div', { class: 'kpi' },
      h('div', { class: 'label' }, label),
      h('div', { class: 'value sm' + (cls ? ' ' + cls : '') }, value),
      h('div', { class: 'sub' }, sub || ''));
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, TNT.ui.icon('proav'), 'What is on this network',
        worst ? h('span', { class: 'badge ' + LEVEL_BADGE[worst] }, LEVEL_TEXT[worst]) : null),
      h('div', { class: 'kpis' },
        kpi('Devices', fmtNum(counts.devices || 0), (result.devices || []).filter(isAv).length + ' AV'),
        kpi('Streams', fmtNum(counts.streams || 0), totalMbps ? Math.round(totalMbps * 10) / 10 + ' Mb/s announced' : 'none announced'),
        kpi('Clock', master ? (master.vendor || master.mac || 'grandmaster') : 'none heard',
          master ? (master.time_source_text || 'no named source') : 'no PTP on this VLAN',
          master && master.locked === false ? 'warn' : ''),
        kpi('Listened', (result.seconds || 0) + ' s', (result.adapter || {}).name || '')),
      h('div', { class: 'muted small', style: { marginTop: '12px' } },
        'Heard ' + fmtNum(counts.mdns || 0) + ' service replies, ' + fmtNum(counts.ptp || 0) + ' clock messages and '
        + fmtNum(counts.sap || 0) + ' stream announcements'
        + (counts.frames ? ', and read ' + fmtNum(counts.frames) + ' frames for the Layer 2 checks' : '') + '.'));
  }

  function isAv(device) {
    return device.vendor_kind === 'av' || (device.family && device.family !== 'other');
  }

  function worstLevel(findings) {
    for (const level of LEVEL_ORDER) if (findings.some((f) => f.level === level)) return level;
    return null;
  }

  /* ---- findings ---- */
  function findingsCard(result) {
    const { h } = TNT.util;
    const findings = result.findings || [];
    const body = h('div', { class: 'pav-findings' });
    if (!findings.length) body.appendChild(TNT.ui.emptyState('Nothing to report.'));
    for (const f of findings) body.appendChild(findingRow(f));
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, TNT.ui.icon('check'), 'Findings',
        h('span', { class: 'badge grey' }, findings.length + (findings.length === 1 ? ' check' : ' checks'))),
      body);
  }

  function findingRow(f) {
    const { h } = TNT.util;
    const parts = [h('div', { class: 'pav-finding-head' },
      h('span', { class: 'badge ' + LEVEL_BADGE[f.level] }, LEVEL_TEXT[f.level] || f.level),
      h('span', { class: 'pav-finding-title' }, f.title))];
    if (f.detail) parts.push(h('div', { class: 'pav-finding-detail' }, f.detail));
    if (f.advice) parts.push(h('div', { class: 'pav-finding-advice' },
      h('span', { class: 'pav-advice-label' }, 'What to do'), f.advice));
    if (f.evidence) parts.push(evidenceBlock(f));
    return h('div', { class: 'pav-finding ' + f.level, 'data-id': f.id }, ...parts);
  }

  function evidenceBlock(f) {
    const { h } = TNT.util;
    const rows = Array.isArray(f.evidence) ? f.evidence : [f.evidence];
    if (!rows.length) return null;
    const keys = [];
    for (const row of rows) {
      if (!row || typeof row !== 'object') continue;
      for (const k of Object.keys(row)) if (!keys.includes(k)) keys.push(k);
    }
    if (!keys.length) return null;
    const table = h('table', { class: 'table' },
      h('thead', null, h('tr', null, ...keys.map((k) => h('th', null, k.replace(/_/g, ' '))))),
      h('tbody', null, ...rows.filter((r) => r && typeof r === 'object').map((row) =>
        h('tr', null, ...keys.map((k) => h('td', null, cellText(row[k])))))));
    return h('details', { class: 'pav-evidence' },
      h('summary', null, 'What this was measured from'), table);
  }

  function cellText(value) {
    if (value === null || value === undefined || value === '') return '—';
    if (Array.isArray(value)) return value.join(', ') || '—';
    if (typeof value === 'boolean') return value ? 'yes' : 'no';
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  }

  /* ---- clock ---- */
  function clockCard(result) {
    const { h } = TNT.util;
    const clock = result.clock || {};
    if (!clock.heard) return null;
    const domains = clock.domains || [];
    const best = clock.best;
    const master = best && best.master;
    const kv = (k, v, cls) => [h('div', { class: 'k' }, k), h('div', { class: 'v' + (cls ? ' ' + cls : '') }, v)];
    const rows = [];
    if (master) {
      rows.push(...kv('Grandmaster', (master.vendor || 'Unknown vendor') + (master.mac ? ' · ' + master.mac : '')));
      rows.push(...kv('Locked to', master.time_source_text || 'nothing it names',
        master.locked === true ? 'ok' : (master.locked === false ? 'bad' : '')));
      rows.push(...kv('Clock class', String(master.clock_class) + (master.clock_class_text ? ' — ' + master.clock_class_text : '')));
      if (master.accuracy_text) rows.push(...kv('Claims', 'within ' + master.accuracy_text));
      rows.push(...kv('Priority', 'priority1 ' + master.priority1 + ', priority2 ' + master.priority2));
      rows.push(...kv('Distance', (master.steps_removed || 0) === 0
        ? 'one hop: this PC hears it directly'
        : master.steps_removed + ' boundary clock' + (master.steps_removed === 1 ? '' : 's') + ' away'
          + (master.parent_vendor ? ', re-served by ' + master.parent_vendor : '')));
      if (master.utc_offset !== null && master.utc_offset !== undefined) {
        rows.push(...kv('UTC offset', master.utc_offset + ' s' + (master.time_traceable ? ', traceable' : '')));
      }
    }
    rows.push(...kv('Domain', domains.map(domainText).join(', ')));
    if (best && best.sync_s) {
      rows.push(...kv('Sync', 'every ' + best.sync_s + ' s'
        + (best.sync_jitter_ms !== null && best.sync_jitter_ms !== undefined
          ? ', varying by up to ' + best.sync_jitter_ms + ' ms' : ''),
        best.sync_jitter_ms >= 10 ? 'bad' : (best.sync_jitter_ms >= 1 ? 'warn' : '')));
    }
    if (best && best.announce_s) rows.push(...kv('Announce', 'every ' + best.announce_s + ' s'));
    if (best && best.transparent) {
      rows.push(...kv('Transparent clock', 'yes — correction up to ' + best.correction_ns + ' ns', 'ok'));
    }
    rows.push(...kv('Followers', String((best && (best.followers || []).length) || 0) + ' device(s) heard asking for the time'));
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, TNT.ui.icon('ping'), 'The clock',
        h('span', { class: 'badge ' + (master && master.locked === true ? 'green' : (master && master.locked === false ? 'red' : 'grey')) },
          'PTPv' + (best ? best.version : '?'))),
      h('div', { class: 'kv pav-kv' }, ...rows));
  }

  function domainText(domain) {
    return 'PTPv' + domain.version + ' ' + (domain.label || '') + ' (' + domain.messages + ' messages)';
  }

  /* ---- diagram ---- */
  function diagramCard(result) {
    const { h } = TNT.util;
    const graph = result.graph || {};
    const wrap = h('div', { class: 'pav-plot-wrap' });
    const note = h('p', { class: 'pav-plot-note' });
    const detail = h('div', { class: 'pav-node-detail', hidden: true });
    const draw = () => {
      const plot = graph[plotName] || { nodes: [], edges: [], note: null };
      wrap.innerHTML = '';
      wrap.appendChild(renderPlot(plot, detail));
      note.textContent = plot.note || '';
      detail.hidden = true;
    };
    const seg = TNT.ui.segmented(
      [{ value: 'clock', label: 'Clock tree' }, { value: 'flow', label: 'Stream flow' }],
      plotName, (value) => { plotName = value; selectedNode = null; draw(); });
    draw();
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, TNT.ui.icon('route'), 'Diagram',
        h('div', { style: { marginLeft: 'auto' } }, seg)),
      wrap, detail, note,
      h('p', { class: 'pav-plot-note strong' },
        'This is not a wiring diagram. One PC hears LLDP from its own switch port and nothing about anyone '
        + 'else’s, so which device is in which port cannot be known from here.'));
  }

  /** Lay a node/edge graph out in columns by depth and draw it as SVG. The clock tree is a tree and the flow map is
   *  talkers → streams → listeners, so a layered layout suits both: a node sits one column right of its deepest
   *  parent, and each column's nodes are stacked in the order their parents appear. */
  function layoutPlot(plot) {
    const nodes = (plot.nodes || []).slice();
    const edges = (plot.edges || []).filter((e) => e && e.source && e.target);
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const layer = new Map(nodes.map((n) => [n.id, 0]));
    const live = edges.filter((e) => byId.has(e.source) && byId.has(e.target));
    // longest path from a root, with a bounded number of passes so a cycle can never hang the page
    for (let pass = 0; pass < Math.min(nodes.length, 40); pass++) {
      let moved = false;
      for (const e of live) {
        const want = layer.get(e.source) + 1;
        if (want > layer.get(e.target)) { layer.set(e.target, want); moved = true; }
      }
      if (!moved) break;
    }
    const columns = [];
    for (const n of nodes) {
      const index = layer.get(n.id) || 0;
      (columns[index] = columns[index] || []).push(n);
    }
    const tallest = columns.reduce((a, c) => Math.max(a, c ? c.length : 0), 0);
    const height = Math.max(1, tallest) * (NODE_H + ROW_GAP) - ROW_GAP + PAD * 2;
    const placed = new Map();
    columns.forEach((column, index) => {
      if (!column) return;
      const span = column.length * (NODE_H + ROW_GAP) - ROW_GAP;
      const top = (height - span) / 2;
      column.forEach((n, row) => {
        placed.set(n.id, { node: n, x: PAD + index * COL_W, y: top + row * (NODE_H + ROW_GAP) });
      });
    });
    return { placed, edges: live, width: Math.max(1, columns.length) * COL_W - COL_GAP + PAD * 2, height };
  }

  function renderPlot(plot, detail) {
    const { h } = TNT.util;
    if (!(plot.nodes || []).length) return TNT.ui.emptyState(plot.note || 'Nothing to draw.');
    const { placed, edges, width, height } = layoutPlot(plot);
    const svg = svgEl('svg', {
      class: 'pav-plot', viewBox: '0 0 ' + width + ' ' + height, role: 'img',
      'aria-label': 'Diagram of ' + placed.size + ' nodes',
      style: { width: Math.min(width, 1400) + 'px', maxWidth: '100%', height: 'auto' },
    });
    const edgeLayer = svgEl('g', { class: 'pav-edges' });
    for (const e of edges) {
      const from = placed.get(e.source), to = placed.get(e.target);
      if (!from || !to) continue;
      const x1 = from.x + NODE_W, y1 = from.y + NODE_H / 2;
      const x2 = to.x, y2 = to.y + NODE_H / 2;
      const mid = (x1 + x2) / 2;
      edgeLayer.appendChild(svgEl('path', {
        class: 'pav-edge', d: 'M' + x1 + ' ' + y1 + ' C' + mid + ' ' + y1 + ' ' + mid + ' ' + y2 + ' ' + x2 + ' ' + y2,
      }));
      if (e.label) {
        edgeLayer.appendChild(svgEl('text', {
          class: 'pav-edge-label', x: mid, y: (y1 + y2) / 2 - 5, 'text-anchor': 'middle',
        }, e.label));
      }
    }
    svg.appendChild(edgeLayer);
    for (const { node, x, y } of placed.values()) {
      svg.appendChild(nodeEl(node, x, y, detail));
    }
    return h('div', { class: 'pav-plot-scroll' }, svg);
  }

  function nodeEl(node, x, y, detail) {
    const group = svgEl('g', {
      class: 'pav-node kind-' + (node.kind || 'other') + (node.level ? ' lvl-' + node.level : '')
        + (selectedNode === node.id ? ' on' : ''),
      transform: 'translate(' + x + ',' + y + ')', tabindex: '0', role: 'button',
    });
    group.appendChild(svgEl('rect', { width: NODE_W, height: NODE_H, rx: 12 }));
    group.appendChild(svgEl('text', { class: 'pav-node-kind', x: 12, y: 17 }, NODE_TEXT[node.kind] || ''));
    group.appendChild(svgEl('text', { class: 'pav-node-label', x: 12, y: 36 }, clip(node.label, 24)));
    group.appendChild(svgEl('text', { class: 'pav-node-sub', x: 12, y: 51 }, clip(node.sub || '', 27)));
    const title = svgEl('title', null,
      (node.label || '') + (node.sub ? ' — ' + node.sub : '') + (node.detail ? '\n' + node.detail : ''));
    group.appendChild(title);
    const show = () => {
      selectedNode = node.id;
      for (const other of group.ownerSVGElement.querySelectorAll('.pav-node')) other.classList.remove('on');
      group.classList.add('on');
      detail.hidden = false;
      detail.innerHTML = '';
      detail.appendChild(TNT.util.h('span', { class: 'badge grey' }, NODE_TEXT[node.kind] || node.kind));
      detail.appendChild(TNT.util.h('strong', null, ' ' + (node.label || '')));
      if (node.sub) detail.appendChild(TNT.util.h('span', { class: 'muted' }, ' · ' + node.sub));
      if (node.detail) detail.appendChild(TNT.util.h('div', { class: 'pav-node-detail-text' }, node.detail));
    };
    group.addEventListener('click', show);
    group.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); show(); } });
    return group;
  }

  function svgEl(name, attrs, text) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', name);
    for (const key of Object.keys(attrs || {})) {
      const value = attrs[key];
      if (value === null || value === undefined) continue;
      if (key === 'style' && typeof value === 'object') { for (const s of Object.keys(value)) el.style[s] = value[s]; continue; }
      el.setAttribute(key, String(value));
    }
    if (text !== undefined && text !== null) el.textContent = String(text);
    return el;
  }

  function clip(text, max) {
    const value = String(text === null || text === undefined ? '' : text);
    return value.length > max ? value.slice(0, max - 1) + '…' : value;
  }

  /* ---- streams ---- */
  function streamsCard(result) {
    const { h } = TNT.util;
    const streams = result.streams || [];
    const total = streams.reduce((a, s) => a + (s.bitrate_mbps || 0), 0);
    const head = ['Stream', 'Destination', 'Format', 'Packet', 'On the wire', 'Reference clock'];
    const rows = streams.map((s) => h('tr', { class: s.deleted ? 'pav-gone' : '' },
      h('td', { class: 'wrap' }, h('strong', null, s.name || '—'),
        s.info ? h('div', { class: 'muted small' }, s.info) : null,
        s.deleted ? h('span', { class: 'badge grey' }, 'withdrawn') : null),
      h('td', null, h('span', { class: 'mono' }, (s.group || '—') + (s.port ? ':' + s.port : ''))),
      h('td', null, [s.codec, s.rate ? Math.round(s.rate / 1000) + ' kHz' : null, s.channels ? s.channels + ' ch' : null]
        .filter(Boolean).join(' · ') || '—'),
      h('td', { class: 'num' }, s.ptime_ms ? s.ptime_ms + ' ms' : '—'),
      h('td', { class: 'num' }, s.bitrate_mbps ? s.bitrate_mbps + ' Mb/s' : '—'),
      h('td', { class: 'wrap' }, s.refclk ? h('span', { class: 'mono small' }, s.refclk) : '—',
        s.refclk_domain !== null && s.refclk_domain !== undefined
          ? h('span', { class: 'muted small' }, ' domain ' + s.refclk_domain) : null)));
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, TNT.ui.icon('spectrum'), 'Streams',
        h('span', { class: 'badge ' + (total ? 'teal' : 'grey') },
          total ? Math.round(total * 10) / 10 + ' Mb/s' : 'none')),
      streams.length
        ? h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
            h('thead', null, h('tr', null, ...head.map((t, i) => h('th', { class: i === 3 || i === 4 ? 'num' : '' }, t)))),
            h('tbody', null, ...rows)))
        : TNT.ui.emptyState('Nothing was announced on the SAP group. Dante only announces once its devices are in '
            + 'AES67 mode, so an all-Dante network is expected to be quiet here.'));
  }

  /* ---- devices ---- */
  function devicesCard(result) {
    const { h } = TNT.util;
    const devices = result.devices || [];
    const head = ['Device', 'Address', 'Made by', 'Kind', 'Role', 'Seen by'];
    const rows = devices.map((d) => h('tr', null,
      h('td', { class: 'wrap' }, h('strong', null, d.name || '—'),
        d.model ? h('div', { class: 'muted small' }, d.model + (d.firmware ? ' · ' + d.firmware : '')) : null,
        (d.services || []).length ? h('div', { class: 'pav-services' },
          ...(d.services || []).slice(0, 6).map((s) => h('span', { class: 'pill' }, s.label || s.type || '?'))) : null),
      h('td', null, d.ip ? h('span', { class: 'mono' }, d.ip) : '—',
        d.mac ? h('div', { class: 'muted small mono' }, d.mac) : null),
      h('td', { class: 'wrap' }, d.vendor || '—'),
      h('td', null, h('span', { class: 'badge ' + (FAMILY_BADGE[d.family] || 'grey') }, d.family_text || d.family)),
      h('td', null, d.clock_role ? CLOCK_ROLE_TEXT[d.clock_role] || d.clock_role : '—'),
      h('td', null, (d.sources || []).join(', ') || '—')));
    return h('div', { class: 'card' },
      h('div', { class: 'card-title' }, TNT.ui.icon('discovery'), 'Devices',
        h('span', { class: 'badge grey' }, devices.length + ' found')),
      devices.length
        ? h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
            h('thead', null, h('tr', null, ...head.map((t) => h('th', null, t)))),
            h('tbody', null, ...rows)))
        : TNT.ui.emptyState('Nothing answered. Check this PC is in the VLAN you meant to scan.'));
  }

  /* ---- the listen itself ---- */
  function listenCard(result) {
    const { h } = TNT.util;
    const listeners = result.listeners || [];
    const l2 = result.l2;
    if (!listeners.length) return null;
    const rows = listeners.map((l) => h('tr', null,
      h('td', { class: 'wrap' }, l.label),
      h('td', null, h('span', { class: 'mono small' }, (l.group || '—') + ':' + l.port)),
      h('td', null, l.ok ? h('span', { class: 'badge green' }, 'joined') : h('span', { class: 'badge red' }, 'failed')),
      h('td', { class: 'num' }, TNT.util.fmtNum(l.packets || 0)),
      h('td', { class: 'wrap muted' }, l.reason || '')));
    const l2Row = l2 && !l2.ok
      ? h('p', { class: 'muted small' }, 'The Layer 2 listen did not run' + (l2.reason ? ': ' + l2.reason : '')
          + '. Without it there is no IGMP querier, flooding or marking check.')
      : (l2 ? h('p', { class: 'muted small' }, 'The Layer 2 listen read ' + TNT.util.fmtNum(l2.frames || 0)
          + ' frames'
          + (l2.lost ? ' and dropped ' + TNT.util.fmtNum(l2.lost) + ' it could not keep up with' : '')
          + (l2.querier ? ', and an IGMP querier answered from ' + l2.querier.ip : '') + '.') : null);
    const switchRow = result.switch
      ? h('p', { class: 'muted small' }, 'This port’s switch, heard through LLDP: '
          + (result.switch.switch_name || result.switch.vendor || 'unnamed')
          + (result.switch.port_id ? ', ' + result.switch.port_id : '') + '.')
      : null;
    return h('details', { class: 'card pav-listen' },
      h('summary', null, h('span', { class: 'card-title', style: { margin: 0 } },
        TNT.ui.icon('info'), 'What the scan listened to')),
      h('div', { class: 'table-wrap', style: { marginTop: '12px' } }, h('table', { class: 'table' },
        h('thead', null, h('tr', null, h('th', null, 'Listener'), h('th', null, 'Group'), h('th', null, 'State'),
          h('th', { class: 'num' }, 'Packets'), h('th', null, 'Note'))),
        h('tbody', null, ...rows))),
      l2Row, switchRow);
  }

  /* ----------------------------------------------------------------- view */
  TNT.views.proav = {
    mount(el) {
      const { h } = TNT.util;
      root = el;
      els = {};
      data = { status: null, result: null };
      plotName = 'clock';
      selectedNode = null;
      els.adapter = h('select', { class: 'input', 'aria-label': 'Adapter' });
      els.seconds = h('select', { class: 'input', 'aria-label': 'How long to listen' },
        ...[10, 20, 30, 60, 120, 300].map((s) => h('option', { value: String(s), selected: s === 30 },
          s >= 60 ? (s / 60) + ' minute' + (s === 60 ? '' : 's') : s + ' seconds')));
      els.scanBtn = h('button', { class: 'btn btn-primary', type: 'button', on: { click: scan } },
        TNT.ui.icon('search'), 'Scan');
      els.stopBtn = h('button', { class: 'btn btn-danger', type: 'button', hidden: true, on: { click: cancel } },
        TNT.ui.icon('stop'), 'Stop');
      els.bar = h('div', { class: 'pav-bar-fill' });
      els.progressText = h('div', { class: 'pav-progress-text' });
      els.progress = h('div', { class: 'pav-progress', hidden: true },
        h('div', { class: 'pav-bar' }, els.bar), els.progressText);
      els.error = h('div', { class: 'dhcp-info bad', hidden: true, role: 'alert' });
      els.lastRun = h('span', { class: 'muted small' });
      const controls = h('div', { class: 'card' },
        h('div', { class: 'form-row' },
          h('div', { class: 'field', style: { flex: '2 1 260px' } }, h('label', null, 'Listen on'), els.adapter),
          h('div', { class: 'field', style: { flex: '1 1 150px' } }, h('label', null, 'For'), els.seconds),
          els.scanBtn, els.stopBtn),
        h('p', { class: 'muted small', style: { marginTop: '10px' } },
          'The scan only listens. It joins the mDNS, SAP and PTP groups and reads what is already being announced '
          + 'to every device on this VLAN — nothing is probed, scanned or connected to. It also reads frames off '
          + 'the adapter to check for an IGMP querier, multicast flooding and QoS marking; that part needs Windows '
          + 'administrator rights, and the findings say so when it could not run.'),
        els.progress, els.error);
      els.body = h('div');
      root.appendChild(h('div', { class: 'section-head' },
        h('h2', null, h('span', { class: 'section-accent' }), 'Pro AV'),
        h('div', { class: 'actions' }, els.lastRun)));
      root.appendChild(controls);
      root.appendChild(els.body);
      loadStatus(true);
      schedule();
    },

    update() { /* the page drives itself from /api/proav; status pushes nothing it needs */ },

    unmount() {
      clearTimeout(timer);
      timer = null;
      root = null;
      els = null;
      data = { status: null, result: null };
    },

    /** This PC moved to another network: the adapters and anything a scan found belong to the old one. */
    netChanged() {
      if (!root || running()) return;
      data.result = null;
      selectedNode = null;
      loadStatus(false);
    },

    /** The event bus calls these: a job moved, or the service said hello after a reconnect. */
    onEvent(name, payload) {
      if (!root) return;
      if (name === 'hello') { loadStatus(true); return; }
      const j = payload && payload.job;
      if (!j) return;
      const wasRunning = running();
      data.status = Object.assign({}, data.status || {}, { job: j });
      renderControls();
      if (wasRunning && j.state !== 'scanning') { loadResult().then(() => { if (root) render(); }); }
    },
  };
})();
