/* TNT — tools/capture.js
   The "Packet capture" card of the Tools view: one adapter's traffic captured by Windows' Packet Monitor (pktmon, run by the
   service) and saved as a pcapng file for Wireshark. The form: the adapter (Wi-Fi adapters marked "(Wi-Fi)"), how long (10 s
   to 15 min, 1 min by default), the file size limit, "Full packets" or "First 128 bytes", and an optional host, port and
   protocol (ICMP takes no port). "Start"; while a capture runs a fuse with the elapsed time and the file size, and "Stop and
   save", which keeps what was captured. The saved captures are listed (name, size, packets, Download, Delete) under a warning
   about what captures contain. Packet capture needs a Windows administrator account: a 403 admin_required shows that instead
   of the form.
   GET /api/tools/capture on mount, on 'hello' and after this PC changed networks (unless a start or stop is in flight);
   capture.state events move the job, and while it starts, captures or converts the status is polled (every 2 s while the event
   stream is down, every 10 s while it is live). Download reads the list first, then clicks a hidden <a download> link, the same
   in the TNT window and a browser tab, so an error answer never replaces the page. File names and error texts are text nodes.
   Loaded before app.js: TNT.util / TNT.ui are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.tools = TNT.tools || {};

  const DURATIONS = [[10, '10 s'], [30, '30 s'], [60, '1 min'], [300, '5 min'], [900, '15 min']];
  const DEFAULT_SECONDS = 60;
  const SIZES_MB = [64, 128, 256, 512, 1024];
  const DEFAULT_SIZE_MB = 128;
  const PROTOCOLS = [['', 'Any'], ['tcp', 'TCP'], ['udp', 'UDP'], ['icmp', 'ICMP']];
  const RUNNING_STATES = ['starting', 'capturing', 'converting'];
  const POLL_MS = 2000;             // the status, while a capture runs and the event stream is down
  const LIVE_POLL_MS = 10000;       // ... and while it is live (SSE has no replay: a missed event must not stick)
  const WARNING_TEXT = 'Captures can contain passwords and private data. TNT keeps the newest 10 (at most 2 GB, 7 days) in a folder only administrators can open; a copy you download is not protected.';
  const ADMIN_TEXT = 'Packet capture needs a Windows administrator account';
  const FIRST_BYTES_TITLE = 'Mostly headers, but the start of unencrypted data (such as FTP or SNMP passwords) can still be in it';
  const UNAVAILABLE_TEXT = 'Packet capture is not available on this service';
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

  /* ------------------------------------------------ pure helpers (tests) */
  const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
  const isNum = (v) => typeof v === 'number' && isFinite(v);

  /** Pure: an IP address for the host filter: a dotted-quad IPv4, or IPv6 (groups of 1-4 hex digits, eight of them or one "::"
   *  for the missing ones, an IPv4 tail allowed). The service checks it again. */
  function isIp(text) {
    const s = String(text == null ? '' : text);
    if (IPV4_RE.test(s)) return true;
    const colon = s.lastIndexOf(':');
    if (colon < 0) return false;
    let body = s;
    if (s.slice(colon + 1).includes('.')) {
      if (!IPV4_RE.test(s.slice(colon + 1))) return false;
      body = s.slice(0, colon + 1) + '0:0';
    }
    const halves = body.split('::');
    if (halves.length > 2) return false;
    const groups = halves.map((part) => (part === '' ? [] : part.split(':')));
    const all = groups[0].concat(groups[1] || []);
    if (!all.every((g) => /^[0-9A-Fa-f]{1,4}$/.test(g))) return false;
    return halves.length === 2 ? all.length <= 7 : all.length === 8;
  }

  /** Pure: the form -> { ok: true, body } (the POST /api/tools/capture body) or { ok: false, field, error } with the service's
   *  message. values: { adapter, seconds, size_mb, full_packets, host, port, protocol } as the form holds them. */
  function startBody(values) {
    const v = values || {};
    const host = String(v.host == null ? '' : v.host).trim();
    const portText = String(v.port == null ? '' : v.port).trim();
    const protocol = String(v.protocol == null ? '' : v.protocol).trim().toLowerCase() || null;
    if (host && !isIp(host)) return { ok: false, field: 'host', error: 'host must be an IP address' };
    let port = null;
    if (portText) {
      port = /^\d{1,5}$/.test(portText) ? Number(portText) : NaN;
      if (!(port >= 1 && port <= 65535)) return { ok: false, field: 'port', error: 'port must be a whole number from 1 to 65535' };
    }
    if (protocol && !['tcp', 'udp', 'icmp'].includes(protocol)) return { ok: false, field: 'protocol', error: 'protocol must be tcp, udp, icmp or null' };
    if (port != null && protocol === 'icmp') return { ok: false, field: 'port', error: 'port cannot be combined with protocol icmp' };
    return { ok: true, body: { adapter: String(v.adapter == null ? '' : v.adapter), seconds: Number(v.seconds) || DEFAULT_SECONDS,
      size_mb: Number(v.size_mb) || DEFAULT_SIZE_MB, full_packets: v.full_packets !== false, host: host || null, port, protocol } };
  }

  /** Pure: an adapter of the status ({ name, index, mac, type_name, wifi }) -> its select label ("Wi-Fi 2 (Wi-Fi)"). */
  function adapterLabel(a) {
    const x = isObj(a) ? a : {};
    return String(x.name || '?') + (x.wifi ? ' (Wi-Fi)' : '');
  }

  /** Pure: m:ss for a number of seconds ("0:23", "15:00"). */
  function clock(s) {
    const n = Math.max(0, Math.floor(isNum(s) ? s : 0));
    return Math.floor(n / 60) + ':' + String(n % 60).padStart(2, '0');
  }

  /** Pure: what a capture job (CAPTURE_JOB, or null) shows -> { running, state, label, pct, bytes, cls, text, note }. While it
   *  starts, captures or converts: the fuse's label ("Starting…", "Capturing… 0:23 of 1:00", "Saving the capture…") and fill
   *  (elapsed / seconds). Once it ended: a line, cls 'ok' "Saved <file>", 'bad' the error or 'muted' for a cancelled one; note is
   *  the service's note (Wi-Fi frames left out). */
  function jobView(job) {
    const j = isObj(job) ? job : null;
    const out = { running: false, state: j ? String(j.state || '') : '', label: '', pct: 0, bytes: j && isNum(j.bytes) ? j.bytes : null,
      cls: '', text: '', note: j && j.note ? String(j.note) : '' };
    if (!j) return out;
    const seconds = isNum(j.seconds) && j.seconds > 0 ? j.seconds : 0;
    const elapsed = isNum(j.elapsed_s) ? Math.max(0, j.elapsed_s) : 0;
    if (RUNNING_STATES.includes(j.state)) {
      out.running = true;
      out.pct = j.state === 'converting' ? 1 : seconds ? Math.min(1, elapsed / seconds) : 0;
      out.label = j.state === 'starting' ? 'Starting…' : j.state === 'converting' ? 'Saving the capture…' : 'Capturing… ' + clock(elapsed) + ' of ' + clock(seconds);
      return out;
    }
    if (j.state === 'done') { out.cls = 'ok'; out.text = 'Saved ' + (j.file ? String(j.file) : 'the capture'); }
    else if (j.state === 'error') { out.cls = 'bad'; out.text = String(j.error || 'The capture failed'); }
    else if (j.state === 'cancelled') { out.cls = 'muted'; out.text = 'The capture was cancelled'; }
    return out;
  }

  /** Pure: the saved captures (CAPTURE_FILE list) -> [{ name, size, packets (null until counted), created_ts }], newest first. */
  function fileRows(files) {
    return (Array.isArray(files) ? files : []).filter((f) => isObj(f) && f.name)
      .map((f) => ({ name: String(f.name), size: isNum(f.size) ? f.size : null, packets: isNum(f.packets) ? f.packets : null, created_ts: isNum(f.created_ts) ? f.created_ts : null }))
      .sort((a, b) => (b.created_ts || 0) - (a.created_ts || 0) || (a.name < b.name ? 1 : a.name > b.name ? -1 : 0));
  }

  /** Pure: when to read the status again -> POLL_MS while a job starts, captures or converts and the event stream is down,
   *  LIVE_POLL_MS while it is live, null otherwise. */
  function pollDelay(job, live) {
    return isObj(job) && RUNNING_STATES.includes(job.state) ? (live ? LIVE_POLL_MS : POLL_MS) : null;
  }

  /* ------------------------------------------------------------- card */
  function create() {
    const { h } = TNT.util;
    let st = null;                // GET /api/tools/capture: { available, reason, adapters, capture, files }
    let admin = false;            // the service answered 403 admin_required: the form and the files are not shown
    let unavailable = '';         // the route answers 404 / 503
    let busy = '';                // 'starting' | 'stopping' while that request is in flight
    let fullPackets = true;
    let netPending = false;       // this PC changed networks during a start or stop: read the adapters after it
    let mounted = false, loading = false, loadAgain = false;
    let pollTimer = null;
    let unsubs = [];
    const els = {};

    /* ---- the form */
    els.adapter = h('select', { class: 'input', 'aria-label': 'Adapter' });
    els.seconds = h('select', { class: 'input', 'aria-label': 'Duration' }, DURATIONS.map(([v, label]) => h('option', { value: String(v) }, label)));
    els.seconds.value = String(DEFAULT_SECONDS);
    els.size = h('select', { class: 'input', 'aria-label': 'File size limit' }, SIZES_MB.map((mb) => h('option', { value: String(mb) }, mb + ' MB')));
    els.size.value = String(DEFAULT_SIZE_MB);
    els.packets = TNT.ui.segmented([{ value: true, label: 'Full packets' }, { value: false, label: 'First 128 bytes' }], true, (v) => { fullPackets = v; });
    els.packets.setAttribute('aria-label', 'How much of each packet');
    if (els.packets.children[1]) els.packets.children[1].title = FIRST_BYTES_TITLE;
    els.host = h('input', { class: 'input', type: 'text', placeholder: 'any', 'aria-label': 'Host (optional)', spellcheck: 'false', autocomplete: 'off' });
    els.port = h('input', { class: 'input', type: 'number', min: '1', max: '65535', step: '1', placeholder: 'any', 'aria-label': 'Port (optional)' });
    // ICMP has no ports
    els.protocol = h('select', { class: 'input', 'aria-label': 'Protocol', on: { change: () => { clearInvalid(); renderForm(); } } },
      PROTOCOLS.map(([v, label]) => h('option', { value: v }, label)));
    els.startBtn = h('button', { class: 'btn btn-primary', type: 'button', on: { click: () => start() },
      title: 'Capture this adapter\'s traffic for the chosen time with Windows\' Packet Monitor' }, TNT.ui.icon('play'), 'Start');
    els.stopBtn = h('button', { class: 'btn', type: 'button', hidden: true, on: { click: () => stop() },
      title: 'End the capture now and keep what was captured' }, TNT.ui.icon('stop'), 'Stop and save');
    for (const input of [els.host, els.port]) {
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') start(); });
      input.addEventListener('input', () => clearInvalid());
    }
    els.form = h('div', { class: 'capture-form' },
      h('div', { class: 'form-row tool-form' },
        h('div', { class: 'field wide' }, h('label', null, 'Adapter'), els.adapter),
        h('div', { class: 'field' }, h('label', null, 'Duration'), els.seconds),
        h('div', { class: 'field' }, h('label', null, 'Size'), els.size)),
      h('div', { class: 'form-row tool-form' },
        h('div', { class: 'field' }, h('label', null, 'Host'), els.host),
        h('div', { class: 'field' }, h('label', null, 'Port'), els.port),
        h('div', { class: 'field' }, h('label', null, 'Protocol'), els.protocol)),
      h('div', { class: 'row capture-actions' }, els.packets, h('span', { class: 'spacer' }), els.startBtn, els.stopBtn));
    els.invalid = h('div', { class: 'tool-summary bad capture-invalid', role: 'alert', hidden: true });
    els.reason = h('div', { class: 'dhcp-info warn', hidden: true });
    els.fuse = TNT.ui.fuse();
    els.progress = h('div', { class: 'capture-progress', hidden: true, role: 'status', 'aria-live': 'polite' }, els.fuse);
    els.result = h('div', { class: 'tool-summary', hidden: true });
    els.note = h('div', { class: 'tool-note', hidden: true });
    els.refreshBtn = h('button', { class: 'btn btn-sm', type: 'button', title: 'List the saved captures again', on: { click: () => load() } }, TNT.ui.icon('refresh'), 'Refresh');
    els.files = h('div', { class: 'capture-files' });
    els.main = h('div', { class: 'capture-main' }, els.form, els.invalid, els.reason, els.progress, els.result, els.note,
      h('div', { class: 'row capture-files-head' }, h('span', { class: 'label' }, 'Saved captures'), h('span', { class: 'spacer' }), els.refreshBtn),
      h('div', { class: 'dhcp-info warn capture-warning' }, TNT.ui.icon('warning'), h('span', null, WARNING_TEXT)),
      els.files);
    els.admin = h('div', { class: 'dhcp-info warn capture-admin', hidden: true }, TNT.ui.icon('warning'), h('span', null, ADMIN_TEXT));
    els.unavailable = h('div', { hidden: true });
    const body = h('div', { class: 'tool-body' }, els.admin, els.unavailable, els.main);

    /* ---- rendering */
    const job = () => (st && isObj(st.capture) ? st.capture : null);
    function renderForm() {
      const adapters = st && Array.isArray(st.adapters) ? st.adapters.filter(isObj) : [];
      if (document.activeElement !== els.adapter) {
        const keep = els.adapter.value;
        els.adapter.innerHTML = '';
        for (const a of adapters) els.adapter.appendChild(h('option', { value: String(a.name || '') }, adapterLabel(a)));
        if (!adapters.length) els.adapter.appendChild(h('option', { value: '' }, st ? 'No adapter is up' : 'Loading…'));
        if (adapters.some((a) => String(a.name || '') === keep)) els.adapter.value = keep;
      }
      const v = jobView(job());
      const locked = v.running || !!busy;
      for (const el of [els.adapter, els.seconds, els.size, els.host, els.protocol]) el.disabled = locked;
      els.port.disabled = locked || els.protocol.value === 'icmp';
      for (const b of Array.from(els.packets.children)) b.disabled = locked;
      els.startBtn.hidden = v.running;
      els.stopBtn.hidden = !v.running;
      if (busy === 'starting') TNT.ui.busy(els.startBtn, true, 'Starting…');
      else { TNT.ui.busy(els.startBtn, false); els.startBtn.disabled = !st || st.available === false || !adapters.length; }
      els.stopBtn.disabled = busy === 'stopping' || v.state === 'converting';
      const reason = st && st.available === false ? String(st.reason || UNAVAILABLE_TEXT) : '';
      els.reason.innerHTML = '';
      els.reason.hidden = !reason;
      if (reason) { els.reason.appendChild(TNT.ui.icon('warning')); els.reason.appendChild(h('span', null, reason)); }
    }

    function renderJob() {
      const { fmtBytes } = TNT.util;
      const v = jobView(job());
      els.progress.hidden = !v.running;
      if (v.running) els.fuse.set(v.pct, 'running', v.label, v.bytes == null ? '' : fmtBytes(v.bytes));
      els.result.innerHTML = '';
      els.result.hidden = v.running || !v.text;
      if (!v.running && v.text) {
        els.result.className = 'tool-summary ' + (v.cls === 'muted' ? 'muted' : v.cls);
        if (v.cls !== 'muted') els.result.appendChild(TNT.ui.icon(v.cls === 'ok' ? 'check' : 'warning'));
        els.result.appendChild(h('span', null, v.text));
      }
      els.note.textContent = v.note;
      els.note.hidden = v.running || !v.note;
    }

    function renderFiles() {
      const { fmtBytes } = TNT.util;
      els.files.innerHTML = '';
      if (!st) { els.files.appendChild(h('div', { class: 'muted small' }, 'Loading…')); return; }
      const rows = fileRows(st.files);
      if (!rows.length) { els.files.appendChild(TNT.ui.emptyState('No captures yet')); return; }
      els.files.appendChild(h('div', { class: 'table-wrap' }, h('table', { class: 'table capture-table' },
        h('thead', null, h('tr', null, h('th', null, 'Name'), h('th', { class: 'num' }, 'Size'), h('th', { class: 'num' }, 'Packets'), h('th', { class: 'actions' }, h('span', { class: 'sr-only' }, 'Actions')))),
        h('tbody', null, rows.map((f) => h('tr', null,
          h('td', { class: 'wrap' }, f.name),
          h('td', { class: 'num' }, f.size == null ? '—' : fmtBytes(f.size)),
          h('td', { class: 'num', title: f.packets == null ? 'Not counted yet' : null }, f.packets == null ? '—' : String(f.packets)),
          h('td', { class: 'actions capture-file-actions' },
            h('button', { class: 'btn btn-sm', type: 'button', title: 'Save a copy of this capture', on: { click: () => download(f.name) } }, TNT.ui.icon('download'), 'Download'),
            h('button', { class: 'btn btn-round-sm', type: 'button', title: 'Delete this capture', 'aria-label': 'Delete ' + f.name, on: { click: () => remove(f.name) } },
              TNT.ui.icon('trash')))))))));
    }

    function render() {
      if (!mounted) return;
      const off = !admin && unavailable ? unavailable : '';
      els.admin.hidden = !admin;
      els.unavailable.innerHTML = '';
      els.unavailable.hidden = !off;
      if (off) els.unavailable.appendChild(TNT.ui.emptyState(off));
      els.main.hidden = admin || !!off;
      if (admin || off) return;
      renderForm();
      renderJob();
      renderFiles();
    }

    function showInvalid(message, field) {
      const fields = { host: els.host, port: els.port, protocol: els.protocol };
      els.invalid.innerHTML = '';
      els.invalid.appendChild(TNT.ui.icon('warning'));
      els.invalid.appendChild(h('span', null, message));
      els.invalid.hidden = false;
      for (const [k, el] of Object.entries(fields)) { if (k === field) el.setAttribute('aria-invalid', 'true'); else el.removeAttribute('aria-invalid'); }
      if (fields[field]) { try { fields[field].focus(); } catch (e) { /* ignore */ } }
    }
    function clearInvalid() {
      els.invalid.hidden = true;
      for (const el of [els.host, els.port, els.protocol]) el.removeAttribute('aria-invalid');
    }

    /* ---- reading the service */
    const live = () => !!(TNT.api.events && TNT.api.events.state === 'live');
    function stopPoll() { if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; } }
    /** While a capture starts, captures or converts: read the status again after pollDelay() (a capture.state event postpones it). */
    function schedulePoll() {
      stopPoll();
      const ms = mounted ? pollDelay(job(), live()) : null;
      if (ms != null) pollTimer = setTimeout(() => { pollTimer = null; if (mounted) load(); }, ms);
    }
    /** A job that was running and has ended: say so once. */
    function announce(before, after) {
      if (!isObj(before) || !isObj(after) || !RUNNING_STATES.includes(before.state) || RUNNING_STATES.includes(after.state)) return;
      if (before.id != null && after.id !== before.id) return;
      if (after.state === 'done') TNT.ui.toast('Capture saved' + (after.file ? ': ' + after.file : ''), 'ok');
      else if (after.state === 'error') TNT.ui.toast('The capture failed: ' + (after.error || 'unknown error'), 'error');
    }
    function applyStatus(next) {
      const before = job();
      st = isObj(next) ? next : null;
      admin = false;
      unavailable = '';
      announce(before, job());
      render();
      schedulePoll();
    }
    /** A request refused because this account is not an administrator: the note replaces the form. */
    function refused(err) {
      if (!(err && err.status === 403 && err.code === 'admin_required')) return false;
      admin = true;
      stopPoll();
      render();
      return true;
    }

    async function load() {
      if (!mounted) return;
      if (loading) { loadAgain = true; return; }
      loading = true;
      try {
        const r = await TNT.api.captureGet();
        if (!mounted) return;
        applyStatus(r);
      } catch (err) {
        if (!mounted || refused(err)) return;
        if (err.status === 404 || err.status === 503) { unavailable = err.status === 503 && err.message ? err.message : UNAVAILABLE_TEXT; stopPoll(); render(); }
        else {
          if (!st) TNT.ui.toast('Could not read the packet capture status: ' + err.message, 'error');
          schedulePoll();
        }
      } finally {
        loading = false;
        if (loadAgain && mounted) { loadAgain = false; load(); }
      }
    }

    /* ---- actions */
    function setBusy(mode) {
      busy = mode || '';
      renderForm();
      if (!busy && netPending && mounted) { netPending = false; setTimeout(() => { if (mounted) load(); }, 0); }
    }

    async function start() {
      if (!mounted || busy || (job() && RUNNING_STATES.includes(job().state))) return;
      // a number field whose text is not a number ('5060-') reads '' (validity.badInput): refuse it, never capture every port
      if (!els.port.disabled && els.port.validity && els.port.validity.badInput) { showInvalid('port must be a whole number from 1 to 65535', 'port'); return; }
      const b = startBody({ adapter: els.adapter.value, seconds: els.seconds.value, size_mb: els.size.value, full_packets: fullPackets,
        host: els.host.value, port: els.port.disabled ? '' : els.port.value, protocol: els.protocol.value });
      if (!b.ok) { showInvalid(b.error, b.field); return; }
      clearInvalid();
      setBusy('starting');
      try {
        const r = await TNT.api.captureStart(b.body);
        if (!mounted) return;
        setBusy('');
        if (r && isObj(r.capture)) applyStatus(Object.assign({}, st || {}, { capture: r.capture }));
        else load();
      } catch (err) {
        if (!mounted) return;
        setBusy('');
        if (refused(err)) return;
        // the service's own check of the form goes under it; busy (409) and other failures are a toast
        if (err.status === 400) showInvalid(err.message || 'The capture was refused', null);
        else TNT.ui.toast('Could not start the capture: ' + (err.message || 'unknown error'), err.status === 409 ? 'warn' : 'error');
        load();
      }
    }

    async function stop() {
      if (!mounted || busy) return;
      setBusy('stopping');
      try {
        const r = await TNT.api.captureStop();
        if (!mounted) return;
        setBusy('');
        if (r && isObj(r.capture)) applyStatus(Object.assign({}, st || {}, { capture: r.capture }));
        else load();
      } catch (err) {
        if (!mounted) return;
        setBusy('');
        if (refused(err)) return;
        TNT.ui.toast('Could not stop the capture: ' + (err.message || 'unknown error'), 'error');
        load();
      }
    }

    /* Download, the same in the TNT window and a browser tab: the list is read first (an error or a file that is gone is a
       toast), then a hidden link with a download attribute is clicked, so no answer ever navigates the page. */
    async function download(name) {
      if (!mounted) return;
      let r;
      try {
        r = await TNT.api.captureGet();
      } catch (err) {
        if (mounted) TNT.ui.toast('Could not download ' + name + ': ' + (err.message || 'unknown error'), 'error');
        return;
      }
      if (!mounted) return;
      applyStatus(r);
      if (!fileRows(r && r.files).some((f) => f.name === name)) { TNT.ui.toast(name + ' is no longer saved', 'warn'); return; }
      const a = h('a', {href: TNT.api.captureFileUrl(name), download: name, hidden: true}); document.body.appendChild(a); a.click(); a.remove();
    }

    async function remove(name) {
      const ok = await TNT.ui.confirm({ title: 'Delete ' + name + '?', message: 'The capture file is deleted from this PC.', ok: 'Delete', danger: true });
      if (!ok || !mounted) return;
      try {
        const r = await TNT.api.captureDeleteFile(name);
        if (!mounted) return;
        if (r && Array.isArray(r.files)) { st = Object.assign({}, st || {}, { files: r.files }); renderFiles(); }
        TNT.ui.toast('Deleted ' + name, 'ok');
      } catch (err) {
        if (!mounted || refused(err)) return;
        if (err.status === 404) { TNT.ui.toast(name + ' is no longer saved', 'warn'); load(); }
        else TNT.ui.toast('Could not delete ' + name + ': ' + (err.message || 'unknown error'), err.status === 409 ? 'warn' : 'error');
      }
    }

    /* ---- events */
    function onJob(d) {
      if (!mounted || !st || admin || !d || !isObj(d.capture)) return;
      const before = job();
      st = Object.assign({}, st, { capture: d.capture });
      announce(before, d.capture);
      renderForm();
      renderJob();
      schedulePoll();
      // a capture that ended has a new file (or none): list them again
      if (isObj(before) && RUNNING_STATES.includes(before.state) && !RUNNING_STATES.includes(d.capture.state)) load();
    }

    return {
      body,
      head: null,
      mount() {
        mounted = true;
        render();
        load();
        unsubs.push(TNT.api.events.on('capture.state', onJob));
        unsubs.push(TNT.api.events.on('hello', () => { if (mounted) load(); }));
      },
      update() { /* nothing here follows the status snapshot */ },
      // this PC changed networks: the adapters that are up (after a start or stop still in flight)
      netChanged() {
        if (!mounted) return;
        if (busy) { netPending = true; return; }
        load();
      },
      unmount() {
        mounted = false;
        for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
        unsubs = [];
        stopPoll();
        st = null; admin = false; unavailable = ''; busy = ''; netPending = false; loading = false; loadAgain = false;
      },
    };
  }

  TNT.tools.capture = { create, startBody, isIp, adapterLabel, clock, jobView, fileRows, pollDelay, DURATIONS, DEFAULT_SECONDS, SIZES_MB, DEFAULT_SIZE_MB,
    PROTOCOLS, WARNING_TEXT, ADMIN_TEXT, FIRST_BYTES_TITLE };
})();
