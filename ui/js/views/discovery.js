/* TNT — views/discovery.js
   Range + ports inputs (prefilled from /api/discovery/status), Scan / Cancel, fuse-style
   progress bar, a sortable results table with copy-on-click cells, an "add as ping target"
   button on every IP cell, a Device Type badge, open-port pills that open in the browser,
   previous runs select.
   The table machinery (sorting, port pills, add-target buttons, CSV) lives in js/hosttable.js
   and is shared with the DHCP clients list in the Tools view. */
(function () {
  'use strict';
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  let root = null, unsubs = [];
  let els = {};
  let running = false, currentRun = null;
  let rangeTouched = false, portsTouched = false;   // the user typed in Range / Ports: never overwrite that field
  let autoRange = '';               // the default range last filled in for the user
  let netPending = false;           // the PC changed networks and the new default range is not applied yet
  let pollTimer = null;
  let table = null;                 // TNT.hosttable instance while mounted
  // run ids of the scans this PC changed networks during (discovery.done network_changed; the service does not store
  // it with the run). Listened for from load, so a scan that ends while another view is open is marked too.
  const netChangedRuns = new Set();
  if (TNT.api && TNT.api.events && TNT.api.events.on) {
    TNT.api.events.on('discovery.done', (d) => { if (d && d.network_changed && d.run_id != null) netChangedRuns.add(d.run_id); });
  }

  /** Pure: what a new default range does to the Range field -> { action, value }. 'replace' fills it in
   *  (the field is empty or still holds the range filled in before, untouched); 'hint' offers it next
   *  to a range the user typed (only after a network change); 'wait' holds it while a scan runs or
   *  the field has the focus; 'none' when nothing changes. No default range after a network change (this
   *  PC is on no IPv4 network now) 'replace's an untouched filled-in range with '': it was the old network's. */
  function rangeUpdate(field, next) {
    field = field || {};
    const value = String(field.value || '').trim();
    const nextRange = String(next || '').trim();
    const untouchedAuto = !field.touched && !!value && value === String(field.auto || '');
    if (!nextRange) {
      if (!field.changed || !untouchedAuto) return { action: 'none', value };
      return { action: field.running || field.focused ? 'wait' : 'replace', value: '' };
    }
    if (nextRange === value) return { action: 'none', value };
    if (field.running) return { action: 'wait', value: nextRange };
    if (!value || untouchedAuto) return { action: field.focused && value ? 'wait' : 'replace', value: nextRange };
    return { action: field.changed ? 'hint' : 'none', value: nextRange };
  }

  const PHASES = { ping: 'Ping sweep', ports: 'Checking ports', arp: 'Reading ARP table', resolve: 'Resolving names', done: 'Done' };

  /* ------------------------------------------------------------- columns */
  // The sort is remembered per table (localStorage) so it survives re-renders, new scans, the
  // previous-runs dropdown and leaving/re-entering the view.
  const SORT_STORE = 'tnt.discovery.sort';
  const COLUMNS = [
    { key: 'ip', label: 'IP' },
    { key: 'hostname', label: 'Hostname' },
    { key: 'mac', label: 'MAC' },
    // what the service made of the host (Router / DW Server / Camera / Phone / Wifi); the rules
    // live in tnt/discovery.py, this table only renders hst.device_type as a coloured badge
    { key: 'device_type', label: 'Device Type' },
    { key: 'vendor', label: 'Vendor' },
    { key: 'rtt', label: 'Ping', cls: 'num' },
    { key: 'ports', label: 'Open ports' },
  ];
  const currentSort = () => (table ? table.sort : TNT.hosttable.loadSort(SORT_STORE, COLUMNS));
  const sortHosts = (hosts, key, dir) => TNT.hosttable.sortHosts(hosts, key, dir, COLUMNS);

  /* --------------------------------------------------------- CSV export */
  function runToCsv(run) {
    return TNT.hosttable.toCsv((run && run.hosts) || [], COLUMNS, currentSort());
  }

  async function exportCsv() {
    if (!currentRun || !(currentRun.hosts || []).length) { TNT.ui.toast('Nothing to export yet', 'warn'); return; }
    const d = new Date(currentRun.ts * 1000);
    const p2 = (n) => (n < 10 ? '0' : '') + n;
    const stamp = d.getFullYear() + p2(d.getMonth() + 1) + p2(d.getDate()) + '-' + p2(d.getHours()) + p2(d.getMinutes());
    const name = 'TNT-discovery-' + String(currentRun.cidr || 'scan').replace(/[^0-9A-Za-z.-]+/g, '_') + '-' + stamp + '.csv';
    try {
      await TNT.app.saveBlob(new Blob([runToCsv(currentRun)], { type: 'text/csv;charset=utf-8' }), name);
    } catch (err) { TNT.ui.toast('Export failed: ' + err.message, 'error'); }
  }

  /* --------------------------------------------------------------- scan */
  function parsePorts(text) {
    const out = [];
    for (const part of String(text || '').split(/[\s,;]+/)) {
      if (!part) continue;
      const n = parseInt(part, 10);
      if (!isFinite(n) || n < 1 || n > 65535) throw new Error('"' + part + '" is not a valid port (1–65535)');
      if (!out.includes(n)) out.push(n);
    }
    return out;
  }

  function setProgress(p) {
    if (!p || p.phase === 'done' && !running) {
      els.fuse.set(running ? 0 : 1, running ? 'running' : (p && p.phase === 'done' ? 'done' : 'idle'), '', '');
      if (!p || !running) { els.fuse.hidden = !(p && p.phase === 'done' && currentRun && (TNT.util.nowS() - currentRun.ts) < 20); }
      return;
    }
    els.fuse.hidden = false;
    const frac = p.total ? Math.min(1, p.done / p.total) : 0;
    // overall progress: ping sweep is the first ~60 %, ports the next 35 %, the rest 5 %
    const base = { ping: 0, ports: 0.6, arp: 0.95, resolve: 0.96, done: 1 }[p.phase] || 0;
    const span = { ping: 0.6, ports: 0.35, arp: 0.01, resolve: 0.04, done: 0 }[p.phase] || 0;
    const overall = p.phase === 'done' ? 1 : base + span * frac;
    const left = (PHASES[p.phase] || p.phase || '') + (p.total ? ' · ' + p.done + '/' + p.total : '');
    const right = (p.found || 0) + ' found · ' + (p.elapsed_s != null ? Number(p.elapsed_s).toFixed(1) + ' s' : '');
    els.fuse.set(overall, p.phase === 'done' ? 'done' : 'running', left, right);
  }

  function setRunning(v) {
    running = v;
    els.scanBtn.hidden = v;
    els.cancelBtn.hidden = !v;
    els.range.disabled = v;
    els.ports.disabled = v;
  }

  function renderRun(run) {
    const { h, copyCode, fmtDateTime, fmtDuration } = TNT.util;
    currentRun = run;
    if (!table) return;
    els.summary.innerHTML = '';
    if (!run) {
      table.render([], 'Nothing found yet — hit Scan.');
      els.resultsTitle.textContent = 'Results';
      if (els.exportBtn) els.exportBtn.hidden = true;
      return;
    }
    const hosts = run.hosts || [];
    els.resultsTitle.textContent = 'Results — ' + hosts.length + (hosts.length === 1 ? ' device' : ' devices');
    if (els.exportBtn) els.exportBtn.hidden = !hosts.length;
    els.summary.appendChild(copyCode(run.cidr));
    els.summary.appendChild(h('span', { class: 'muted' }, fmtDateTime(run.ts)));
    els.summary.appendChild(h('span', { class: 'muted' }, run.duration_s != null ? fmtDuration(run.duration_s) : ''));
    // the method as the run recorded it (older releases may have stored another name)
    els.summary.appendChild(h('span', { class: 'badge orange' }, run.method || 'native'));
    if (run.scanned) els.summary.appendChild(h('span', { class: 'muted' }, run.scanned + ' addresses'));
    if (run.error) els.summary.appendChild(h('span', { class: 'badge ' + (run.error === 'cancelled' ? 'yellow' : 'red') }, run.error));
    // a scan this PC changed networks during swept (part of) the network it left: a yellow note, not a failure
    if (run.id != null && netChangedRuns.has(run.id)) {
      els.summary.appendChild(h('span', { class: 'badge yellow', title: 'This PC changed networks while the scan ran: part of it may be of the network it left' }, 'network changed during scan'));
    }
    table.render(hosts, run.error === 'cancelled' ? 'Scan was cancelled before anything answered.' : 'No devices answered in ' + run.cidr + '.');
  }

  async function loadRuns(selectId) {
    try {
      const r = await TNT.api.discoveryRuns(50);
      if (!root) return;
      const runs = (r && r.runs) || [];
      const { h, fmtDateTime } = TNT.util;
      els.runs.innerHTML = '';
      els.runs.appendChild(h('option', { value: '' }, runs.length ? 'Previous runs…' : 'No previous runs'));
      for (const run of runs) els.runs.appendChild(h('option', { value: String(run.id) }, fmtDateTime(run.ts) + ' · ' + run.cidr + ' · ' + (run.found != null ? run.found + ' found' : '') + (run.error === 'cancelled' ? ' (cancelled)' : '')));
      els.runs.disabled = !runs.length;
      if (selectId != null) els.runs.value = String(selectId);
    } catch (err) { /* non-fatal */ }
  }

  async function loadRun(id) {
    try {
      const run = await TNT.api.discoveryRun(id);
      if (!root) return;
      renderRun(run);
    } catch (err) { TNT.ui.toast('Could not load run: ' + err.message, 'error'); }
  }

  /** The note under the form when this PC changed networks but the Range field holds the user's own range. */
  function showRangeHint(range) {
    const { h, copyCode } = TNT.util;
    if (!els.rangeHint) return;
    if (!range) { els.rangeHint.hidden = true; return; }
    const use = h('button', { class: 'btn btn-sm', type: 'button',
      on: { click: () => { els.range.value = range; autoRange = range; rangeTouched = false; showRangeHint(null); } } }, 'Use it');
    els.rangeHint.innerHTML = '';
    els.rangeHint.appendChild(TNT.ui.icon('info'));
    els.rangeHint.appendChild(h('span', { class: 'row', style: { gap: '8px' } }, 'This PC changed networks: the default range is now', copyCode(range), use));
    els.rangeHint.hidden = false;
  }

  async function loadStatus() {
    try {
      const s = await TNT.api.discoveryStatus();
      if (!root) return;
      // the default range follows the network until the user types a range of their own
      const u = rangeUpdate({ value: els.range.value, auto: autoRange, touched: rangeTouched, running: running || !!s.running,
        focused: document.activeElement === els.range, changed: netPending }, s.default_range);
      if (u.action === 'replace') { els.range.value = u.value; autoRange = u.value; showRangeHint(null); }
      else if (u.action === 'hint') showRangeHint(u.value);
      else if (u.action === 'none' && (!s.default_range || (els.range.value || '').trim() === s.default_range)) showRangeHint(null);
      if (u.action !== 'wait') netPending = false;       // 'wait': discovery.done or leaving the field asks again
      if (!portsTouched && Array.isArray(s.default_ports) && !els.ports.value) els.ports.value = s.default_ports.join(', ');
      setRunning(!!s.running);
      if (s.running) { setProgress(s.progress); startPoll(); }
    } catch (err) { TNT.ui.toast('Could not read discovery status: ' + err.message, 'error'); }
  }

  async function loadLast() {
    try {
      const run = await TNT.api.discoveryLast();
      if (!root) return;
      renderRun(run);
      if (run) els.runs.value = String(run.id);
    } catch (err) { renderRun(null); }
  }

  function startPoll() {
    // Fallback while a scan runs and SSE might be down: poll the status every 2 s.
    if (pollTimer) return;
    pollTimer = setInterval(async () => {
      if (!root || !running) { stopPoll(); return; }
      if (TNT.api.events.state === 'live') return;
      try {
        const s = await TNT.api.discoveryStatus();
        if (s.running) setProgress(s.progress); else { stopPoll(); setRunning(false); await loadLast(); await loadRuns(currentRun && currentRun.id); if (root && netPending) loadStatus(); }
      } catch (e) { /* ignore */ }
    }, 2000);
  }
  function stopPoll() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

  async function scan() {
    let ports;
    try { ports = parsePorts(els.ports.value); } catch (err) { TNT.ui.toast(err.message, 'warn'); els.ports.focus(); return; }
    const range = (els.range.value || '').trim();
    TNT.ui.busy(els.scanBtn, true);
    try {
      const r = await TNT.api.discoveryScan(range, ports);
      setRunning(true);
      setProgress({ phase: 'ping', done: 0, total: 0, found: 0, elapsed_s: 0 });
      TNT.ui.toast('Scanning ' + (r && r.range ? r.range : range || 'default range'), 'ok', 1800);
      startPoll();
    } catch (err) {
      if (err.status === 409) { TNT.ui.toast('A scan is already running', 'warn'); setRunning(true); startPoll(); }
      else TNT.ui.toast('Could not start the scan: ' + err.message, 'error');
    } finally { TNT.ui.busy(els.scanBtn, false); }
  }

  async function cancel() {
    TNT.ui.busy(els.cancelBtn, true);
    try { await TNT.api.discoveryCancel(); TNT.ui.toast('Cancelling…', 'warn', 1500); }
    catch (err) { TNT.ui.toast('Could not cancel: ' + err.message, 'error'); }
    finally { TNT.ui.busy(els.cancelBtn, false); }
  }

  TNT.views.discovery = {
    mount(el) {
      const { h } = TNT.util;
      root = el;
      els = {};
      running = false; rangeTouched = false; portsTouched = false; autoRange = ''; netPending = false; currentRun = null;
      els.runs = h('select', { class: 'input sm', 'aria-label': 'Previous runs', disabled: true, style: { maxWidth: 'min(360px, 80vw)' } }, h('option', { value: '' }, 'Previous runs…'));
      els.runs.addEventListener('change', () => { if (els.runs.value) loadRun(parseInt(els.runs.value, 10)); });
      const head = h('div', { class: 'section-head' },
        h('h2', null, h('span', { class: 'section-accent' }), 'Discovery'),
        h('div', { class: 'actions' }, els.runs));
      els.range = h('input', { class: 'input', type: 'text', placeholder: '10.0.0.0/24 or 10.0.0.1-10.0.0.50', 'aria-label': 'Range', spellcheck: 'false', autocomplete: 'off', style: { width: '100%' } });
      els.ports = h('input', { class: 'input', type: 'text', placeholder: '22, 80, 443, 8080', 'aria-label': 'Ports', spellcheck: 'false', autocomplete: 'off', style: { width: '100%' } });
      els.range.addEventListener('input', () => { rangeTouched = true; showRangeHint(null); });
      els.ports.addEventListener('input', () => { portsTouched = true; });
      // a new default range that arrived while the field had the focus is applied once it loses it
      els.range.addEventListener('blur', () => { if (root && netPending) loadStatus(); });
      els.rangeHint = h('div', { class: 'dhcp-info range-hint', hidden: true, role: 'status' });
      els.range.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !running) scan(); });
      els.ports.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !running) scan(); });
      els.scanBtn = h('button', { class: 'btn btn-primary', type: 'button', on: { click: scan } }, TNT.ui.icon('search'), 'Scan');
      els.cancelBtn = h('button', { class: 'btn btn-danger', type: 'button', hidden: true, on: { click: cancel } }, TNT.ui.icon('stop'), 'Cancel');
      els.fuse = TNT.ui.fuse();
      els.fuse.hidden = true;
      els.fuse.style.marginTop = '14px';
      const form = h('div', { class: 'form-row' },
        h('div', { class: 'field', style: { flex: '2 1 280px' } }, h('label', null, 'Range'), els.range),
        h('div', { class: 'field', style: { flex: '1 1 220px' } }, h('label', null, 'Ports'), els.ports),
        els.scanBtn, els.cancelBtn);
      // no card title here on purpose: the range/ports/Scan row is self-explanatory
      const ctlCard = h('div', { class: 'card' }, form, els.rangeHint, els.fuse);
      els.resultsTitle = h('span', null, 'Results');
      els.exportBtn = h('button', { class: 'btn btn-sm', type: 'button', hidden: true, title: 'Export this scan as a CSV file', on: { click: exportCsv } },
        TNT.ui.icon('download'), 'Export CSV');
      els.summary = h('div', { class: 'row', style: { gap: '10px', marginBottom: '12px' } });
      table = TNT.hosttable.create({ columns: COLUMNS, storeKey: SORT_STORE, onSort: () => renderRun(currentRun) });
      const tableWrap = h('div', { class: 'table-wrap' }, h('table', { class: 'table discovery-table' }, table.thead, table.tbody));
      const resCard = h('div', { class: 'card' }, h('div', { class: 'card-title' }, els.resultsTitle, h('span', { class: 'spacer' }), els.exportBtn), els.summary, tableWrap);
      root.appendChild(head);
      root.appendChild(h('div', { class: 'stack' }, ctlCard, resCard));
      TNT.hosttable.syncTargets(TNT.state && TNT.state.targets, true);
      renderRun(null);
      loadStatus();
      loadLast();
      loadRuns();
      TNT.hosttable.loadTargets();
      unsubs.push(TNT.api.events.on('discovery.progress', (d) => { if (!d || !root) return; if (d.phase !== 'done') { if (!running) setRunning(true); setProgress(d); } else { setProgress(d); } }));
      unsubs.push(TNT.api.events.on('discovery.done', async (d) => {
        if (!root) return;
        setRunning(false);
        stopPoll();
        // a scan Clear history stopped, or one that finished while the clear ran and was voided (cancelled false, silent
        // true): nothing of it was stored, so no "Done", and the list reloads without it
        if (d && TNT.api.history && TNT.api.history.cancelledTest(d)) {
          els.fuse.set(0, 'idle', '', '');
          els.fuse.hidden = true;
          await loadLast(); await loadRuns();
          return;
        }
        if (d && d.run_id != null) { await loadRun(d.run_id); await loadRuns(d.run_id); }
        else { await loadLast(); await loadRuns(currentRun && currentRun.id); }
        if (!root) return;
        setProgress({ phase: 'done', done: 1, total: 1, found: currentRun ? (currentRun.hosts || []).length : 0, elapsed_s: currentRun ? currentRun.duration_s : 0 });
        els.fuse.set(1, 'done', 'Done', (currentRun ? (currentRun.hosts || []).length : 0) + ' found');
        if (netPending) loadStatus();          // the PC changed networks during the scan: its default range now
      }));
      unsubs.push(TNT.api.events.on('hello', () => { if (root) loadStatus(); }));
    },
    update(state) {
      if (!table) return;
      TNT.hosttable.syncTargets(state && state.targets);
      const d = state.status && state.status.discovery;
      if (!d || !els.fuse) return;
      if (d.running && !running) { setRunning(true); setProgress(d.progress); startPoll(); }
    },
    // this PC changed networks (app.js, once a burst of changes settles): the default range follows it
    netChanged() {
      if (!root) return;
      netPending = true;
      loadStatus();
    },
    unmount() {
      for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
      unsubs = [];
      stopPoll();
      if (table) table.destroy();
      root = null; els = {}; currentRun = null; table = null; netPending = false;
    },
    // exposed for tests
    rangeUpdate,
    sortHosts,
    portUrl: (ip, port) => TNT.hosttable.portUrl(ip, port),
    portAction: (port) => TNT.hosttable.portAction(port),
    runToCsv,
    deviceType: (hst) => TNT.hosttable.deviceType(hst),
    deviceTypeClass: (type) => TNT.hosttable.deviceTypeClass(type),
    classifyDevice: (hst, gateway) => TNT.hosttable.classifyDevice(hst, gateway),
    targetKeysFrom: (targets) => TNT.hosttable.targetKeysFrom(targets),
    noteLocalAdd: (ip) => TNT.hosttable.noteLocalAdd(ip),
    columns: COLUMNS.map((c) => c.key),
  };
})();
