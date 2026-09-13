/* TNT — tools/tftp.js
   The "TFTP server" card of the Tools view: a TFTP server (UDP 69) in the service that hands the files in its folder to the
   devices that ask for them (phones, switches, bootloaders) and, only while "Allow uploads" is on, takes files from them.
   The card head carries a status badge (grey off, green on, yellow "uploads on", red error) and the on/off switch; switching
   it on opens the card (ctx.open(), as the DHCP server's switch does). The body: the adapter to serve on, "Allow uploads" with
   its warning, the folder as a copy chip with "Open folder" (only when the TNT window's bridge has open_path), the files in
   it, the transfers running (a fuse each) and the last 10 finished, boxes for an error, a warning, a firewall rule that could
   not be added and another program on UDP 69, the max upload size, and what the server is not for.
   GET /api/tftp/status on mount, on 'hello', after this PC changed networks (unless a start or stop is in flight) and when the
   status snapshot's summary (status.tftp) or a tftp.state event no longer matches; tftp.transfer events move the transfers,
   and while one runs the status is polled (every 2 s while the event stream is down, every 10 s while it is live).
   File names, client addresses and error texts are inserted as text.
   Loaded before app.js: TNT.util / TNT.ui are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.tools = TNT.tools || {};

  const HISTORY_SHOWN = 10;         // finished transfers listed
  const HISTORY_KEPT = 50;          // the service keeps this many
  const POLL_MS = 2000;             // the status, while a transfer runs and the event stream is down
  const LIVE_POLL_MS = 10000;       // ... and while it is live (SSE has no replay: a missed event must not stick)
  const ACTIVE_STATES = ['negotiating', 'sending', 'receiving'];
  const STATE_CLASS = { negotiating: 'blue', sending: 'blue', receiving: 'blue', done: 'green', unconfirmed: 'yellow', failed: 'red', cancelled: 'grey' };
  const TFTP_SCOPE_TEXT = 'Serves files to devices that ask for them (phones, switches, bootloaders). A device that is itself the TFTP server, such as a UniFi AP or airMAX in recovery, needs a TFTP client instead.';
  const UPLOADS_NOTE = 'Anyone on this network can upload files while this is on';
  const EMPTY_FILES_TEXT = 'No files yet: put the files devices will ask for in this folder';
  const OPEN_FAILED_TEXT = 'Could not open the TFTP folder';
  const UNAVAILABLE_TEXT = 'The TFTP server is not available on this service';
  const MAX_UPLOAD_INVALID_TEXT = 'max_upload_mb must be a whole number from 1 to 65536';     // the service's MAX_UPLOAD_MB_MSG

  /* ------------------------------------------------ pure helpers (tests) */
  const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
  const isNum = (v) => typeof v === 'number' && isFinite(v);

  /** Pure: the head badge for a TFTP status -> { cls, text }. busyMode: 'starting' | 'stopping' while that request is in
   *  flight, else ''. */
  function badgeState(st, busyMode) {
    if (busyMode) return { cls: 'yellow pulse', text: busyMode === 'stopping' ? 'stopping…' : 'starting…' };
    if (!isObj(st)) return { cls: 'grey', text: 'loading' };
    if (st.available === false) return { cls: 'grey', text: 'unavailable' };
    if (st.error) return { cls: 'red', text: 'error' };
    if (st.running && st.uploads) return { cls: 'yellow', text: 'uploads on' };
    if (st.running) return { cls: 'green', text: 'on' };
    return { cls: 'grey', text: 'off' };
  }

  /** Pure: an adapter entry of the status (a name, or { name, ip, prefix }) -> its name ('' when it has none). */
  function adapterName(a) { return isObj(a) ? String(a.name || '') : a == null ? '' : String(a); }

  /** Pure: one entry of the adapter select: "Ethernet — 192.0.2.10/24", or the name alone. */
  function adapterLabel(a) {
    if (!isObj(a)) return adapterName(a) || '?';
    const ip = a.ip ? a.ip + (a.prefix != null ? '/' + a.prefix : '') : '';
    return (a.name || '?') + (ip ? ' — ' + ip : '');
  }

  /** Pure: a transfer (TFTP_TRANSFER) as the card draws it -> { id, active, file, client, op ('read' | 'write'), pct (0..1, null
   *  without a size), bytes, size, state, cls, error, ended_ts }. */
  function transferView(t) {
    const x = isObj(t) ? t : {};
    const size = isNum(x.size) && x.size > 0 ? x.size : null;
    const bytes = isNum(x.bytes) ? x.bytes : 0;
    const state = String(x.state || '');
    return { id: x.id == null ? null : String(x.id), active: ACTIVE_STATES.includes(state), file: String(x.file || '?'), client: String(x.client || '?'),
      op: x.op === 'write' ? 'write' : 'read', pct: size ? Math.min(1, bytes / size) : null, bytes, size, state, cls: STATE_CLASS[state] || 'grey',
      error: x.error ? String(x.error) : '', ended_ts: isNum(x.ended_ts) ? x.ended_ts : isNum(x.started_ts) ? x.started_ts : null };
  }

  /** Pure: one tftp.transfer event's transfer applied to the status lists -> { transfers, history } (new arrays): a transfer
   *  that runs replaces its row among the transfers or joins them; a finished one leaves them and goes first in the history
   *  (one row per id, at most HISTORY_KEPT). */
  function mergeTransfer(transfers, history, t) {
    const list = Array.isArray(transfers) ? transfers.filter(isObj) : [];
    const past = Array.isArray(history) ? history.filter(isObj) : [];
    if (!isObj(t) || t.id == null) return { transfers: list, history: past };
    if (ACTIVE_STATES.includes(t.state)) {
      const i = list.findIndex((x) => x.id === t.id);
      if (i >= 0) list[i] = t; else list.push(t);
      return { transfers: list, history: past.filter((x) => x.id !== t.id) };
    }
    return { transfers: list.filter((x) => x.id !== t.id), history: [t].concat(past.filter((x) => x.id !== t.id)).slice(0, HISTORY_KEPT) };
  }

  /** Pure: the finished transfers to list, newest first (when they ended, else started), at most `limit` (HISTORY_SHOWN), as
   *  transferView()s. */
  function historyRows(history, limit) {
    const n = limit == null ? HISTORY_SHOWN : Math.max(0, limit);
    const rows = (Array.isArray(history) ? history.filter(isObj) : []).map((t, i) => ({ v: transferView(t), i }));
    rows.sort((a, b) => (b.v.ended_ts || 0) - (a.v.ended_ts || 0) || a.i - b.i);
    return rows.slice(0, n).map((r) => r.v);
  }

  /** Pure: GET /api/tftp/files (a list, or { files }) -> [{ name, size, mtime }], by name. */
  function fileRows(r) {
    const list = Array.isArray(r) ? r : isObj(r) && Array.isArray(r.files) ? r.files : [];
    return list.filter((f) => isObj(f) && f.name).map((f) => ({ name: String(f.name), size: isNum(f.size) ? f.size : null, mtime: isNum(f.mtime) ? f.mtime : null }))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  }

  /** Pure: the programs holding UDP 69 ([{ pid, name }]) -> "UDP port 69 is already used by tftpd64.exe (PID 4120), PID 912",
   *  or '' when there are none. */
  function ownersText(owners) {
    const names = (Array.isArray(owners) ? owners : []).filter(isObj).map((o) => {
      const name = o.name ? String(o.name) : '';
      const pid = o.pid != null ? 'PID ' + o.pid : '';
      return name && pid && name !== pid ? name + ' (' + pid + ')' : name || pid;
    }).filter(Boolean);
    return names.length ? 'UDP port 69 is already used by ' + names.join(', ') : '';
  }

  /** Pure: how many transfers of a status run (its transfers list, else counts.active). */
  function activeCount(st) {
    if (!isObj(st)) return 0;
    if (Array.isArray(st.transfers)) return st.transfers.filter((t) => isObj(t) && ACTIVE_STATES.includes(t.state)).length;
    return isObj(st.counts) && isNum(st.counts.active) ? st.counts.active : 0;
  }

  /** Pure: when to read the status again -> POLL_MS while the server runs a transfer and the event stream is down, LIVE_POLL_MS
   *  while it is live, null otherwise. */
  function pollDelay(st, live) {
    if (!isObj(st) || !st.running || !activeCount(st)) return null;
    return live ? LIVE_POLL_MS : POLL_MS;
  }

  /** Pure: whether a summary (status.tftp, or a tftp.state event) says something the card's status does not: running, the
   *  error, uploads, how many transfers run, when the server started, or (while both say it runs) the adapter it serves on. */
  function summaryDiffers(summary, st) {
    if (!isObj(summary)) return false;
    if (!isObj(st)) return true;
    return !!summary.running !== !!st.running || (summary.error || null) !== (st.error || null) || !!summary.uploads !== !!st.uploads
      || (isNum(summary.active) && summary.active !== activeCount(st))
      || (isNum(summary.since_ts) && summary.since_ts !== st.since_ts)
      || (!!summary.running && !!summary.adapter && String(summary.adapter) !== adapterName(st.adapter));
  }

  /* ------------------------------------------------------------- card */
  function create(ctx) {
    const { h } = TNT.util;
    const open = ctx && typeof ctx.open === 'function' ? ctx.open : () => {};
    let st = null;                // TFTP_STATUS from /api/tftp/status (the answers of start, stop, uploads and settings too)
    let files = null;             // fileRows() of /api/tftp/files; null until read
    let filesError = '';
    let unavailable = '';         // why the card has nothing to show (the route answers 404 / 503)
    let conflict = '';            // a start refused because another program holds UDP 69: the service's words
    let busyMode = '';            // 'starting' | 'stopping' while that request is in flight
    let settingsBusy = false;     // an uploads or settings request is in flight
    let netPending = false;       // this PC changed networks during a start or stop: read the status after it
    let mounted = false, loading = false, loadAgain = false;
    let pollTimer = null;
    let unsubs = [];
    const els = {};
    /** The TNT window's bridge can open a folder (a browser tab and older windows cannot). */
    const canOpenPath = () => typeof (window.pywebview && window.pywebview.api && window.pywebview.api.open_path) === 'function';

    /* ---- head: the badge and the switch (they work while the card is closed) */
    els.badge = h('span', { class: 'badge grey' }, 'loading');
    // switching the server on opens the card: an error, the firewall or another program on UDP 69 shows up in its body
    els.toggle = TNT.ui.toggle({ checked: false, on: 'On', off: 'Off', accent: 'var(--green)', onChange: (on) => { if (on) { open(); turnOn(); } else turnOff(); } });
    els.toggle.input.setAttribute('aria-label', 'TFTP server on or off');
    els.head = h('div', { class: 'tool-head-right' }, els.badge, els.toggle);

    /* ---- body */
    els.unavailable = h('div', { class: 'tftp-unavailable', hidden: true });
    els.summary = h('div', { class: 'tool-summary muted tftp-summary', role: 'status', 'aria-live': 'polite' });
    els.adapter = h('select', { class: 'input', 'aria-label': 'Adapter', on: { change: () => saveSettings({ adapter: els.adapter.value || '' }) } },
      h('option', { value: '' }, 'Auto'));
    els.uploads = TNT.ui.toggle({ checked: false, on: 'On', off: 'Off', accent: 'var(--yellow)', onChange: (on) => setUploads(on) });
    els.uploads.input.setAttribute('aria-label', 'Allow uploads');
    els.maxUpload = h('input', { class: 'input', type: 'number', min: '1', max: '65536', step: '1', 'aria-label': 'Max upload in MB', on: { change: () => saveMaxUpload() } });
    els.maxUpload.addEventListener('keydown', (e) => { if (e.key === 'Enter') saveMaxUpload(); });
    const form = h('div', { class: 'form-row tftp-form' },
      h('div', { class: 'field wide' }, h('label', null, 'Adapter'), els.adapter),
      h('div', { class: 'field tftp-uploads' }, h('label', null, 'Allow uploads'), els.uploads),
      h('div', { class: 'field tftp-max' }, h('label', null, 'Max upload (MB)'), els.maxUpload));
    // what "Allow uploads" means, always next to it (the switch works while the server is off too)
    els.uploadsNote = h('div', { class: 'dhcp-info warn tftp-uploads-note' }, TNT.ui.icon('warning'), h('span', null, UPLOADS_NOTE));
    els.err = h('div', { class: 'dhcp-info bad', hidden: true });
    els.conflict = h('div', { class: 'dhcp-info bad', hidden: true, role: 'alert' });
    els.fw = h('div', { class: 'dhcp-info warn', hidden: true });
    els.warning = h('div', { class: 'dhcp-info warn', hidden: true });
    els.folder = h('div', { class: 'row tftp-folder', hidden: true });
    els.refreshBtn = h('button', { class: 'btn btn-sm', type: 'button', title: 'List the files in the TFTP folder again', on: { click: () => loadFiles() } },
      TNT.ui.icon('refresh'), 'Refresh');
    els.files = h('div', { class: 'tftp-files' });
    els.transfers = h('div', { class: 'tftp-transfers', hidden: true });
    els.history = h('div', { class: 'tftp-history', hidden: true });
    els.main = h('div', { class: 'tftp-main' }, els.summary, form, els.uploadsNote, els.err, els.conflict, els.fw, els.warning, els.folder,
      h('div', { class: 'row tftp-files-head' }, h('span', { class: 'label' }, 'Files'), h('span', { class: 'spacer' }), els.refreshBtn),
      els.files, els.transfers, els.history);
    const body = h('div', { class: 'tool-body' }, els.unavailable, els.main, h('div', { class: 'tool-note tftp-scope' }, TFTP_SCOPE_TEXT));

    /* ---- rendering */
    function renderHead() {
      const b = badgeState(unavailable ? { available: false } : st, busyMode);
      els.badge.className = 'badge ' + b.cls;
      els.badge.textContent = b.text;
      els.badge.title = st && st.error ? String(st.error) : '';
      // while a request runs the switch shows what was asked for
      els.toggle.setChecked(busyMode ? busyMode === 'starting' : !!(st && st.running));
      els.toggle.classList.toggle('busy', !!busyMode);
      els.toggle.input.disabled = !!busyMode || !!unavailable || !st || st.available === false;
    }

    function renderSettings() {
      const { relTime } = TNT.util;
      if (!st) return;
      const s = isObj(st.settings) ? st.settings : {};
      const wanted = String(s.adapter || '');
      const current = adapterName(st.adapter);
      const adapters = Array.isArray(st.adapters) ? st.adapters : [];
      if (document.activeElement !== els.adapter) {
        els.adapter.innerHTML = '';
        els.adapter.appendChild(h('option', { value: '' }, 'Auto' + (!wanted && current ? ' (' + current + ')' : '')));
        for (const a of adapters) { const n = adapterName(a); if (n) els.adapter.appendChild(h('option', { value: n }, adapterLabel(a))); }
        // an adapter that is not up right now stays listed instead of turning into Auto
        if (wanted && !adapters.some((a) => adapterName(a) === wanted)) els.adapter.appendChild(h('option', { value: wanted }, wanted + ' — not connected'));
        els.adapter.value = wanted;
      }
      if (document.activeElement !== els.maxUpload && isNum(s.max_upload_mb)) els.maxUpload.value = String(s.max_upload_mb);
      els.uploads.setChecked(!!st.uploads);
      els.uploads.input.disabled = settingsBusy || !!busyMode;
      els.adapter.disabled = settingsBusy || !!busyMode;
      els.maxUpload.disabled = settingsBusy;
      const ips = (Array.isArray(st.listen) ? st.listen : []).map((x) => (isObj(x) ? x.ip : x)).filter(Boolean).map(String);
      if (st.running) {
        els.summary.className = 'tool-summary ok tftp-summary';
        els.summary.textContent = 'Serving on ' + (current || '?') + (ips.length ? ' · ' + ips.join(', ') : '') + (isNum(st.since_ts) ? ' · on ' + relTime(st.since_ts) : '');
      } else {
        els.summary.className = 'tool-summary muted tftp-summary';
        els.summary.textContent = current ? 'Would serve on ' + current : '';
      }
    }

    function box(el, kind, text) {
      el.innerHTML = '';
      el.hidden = !text;
      if (!text) return;
      el.className = 'dhcp-info ' + kind;
      el.appendChild(TNT.ui.icon('warning'));
      el.appendChild(h('span', null, text));
    }
    function renderInfo() {
      const owners = st && isObj(st.conflict) ? ownersText(st.conflict.owners) : '';
      const clash = conflict || owners;
      box(els.conflict, 'bad', clash);
      box(els.err, 'bad', st && st.error && String(st.error) !== clash ? String(st.error) : '');
      const fw = st && isObj(st.firewall) ? st.firewall : {};
      box(els.fw, 'warn', fw.ok === false ? 'Firewall rule "' + (fw.rule || 'TNT TFTP server (UDP 69 in)') + '" could not be added' + (fw.error ? ': ' + fw.error : '')
        + '. Devices may not reach the server until UDP port 69 is allowed in.' : '');
      box(els.warning, 'warn', st && st.warning ? String(st.warning) : '');
    }

    function renderFolder() {
      const { copyCode } = TNT.util;
      const root = st && st.root ? String(st.root) : '';
      els.folder.innerHTML = '';
      els.folder.hidden = !root;
      if (!root) return;
      els.folder.appendChild(h('span', { class: 'label' }, 'Folder'));
      els.folder.appendChild(copyCode(root));
      if (canOpenPath()) {
        els.folder.appendChild(h('button', { class: 'btn btn-sm', type: 'button', title: 'Open the TFTP folder in File Explorer', on: { click: openFolder } },
          TNT.ui.icon('computer'), 'Open folder'));
      }
    }

    function renderFiles() {
      const { fmtBytes } = TNT.util;
      els.files.innerHTML = '';
      if (filesError) { els.files.appendChild(h('div', { class: 'muted small' }, filesError)); return; }
      if (!files) { els.files.appendChild(h('div', { class: 'muted small' }, 'Loading…')); return; }
      if (!files.length) { els.files.appendChild(TNT.ui.emptyState(EMPTY_FILES_TEXT)); return; }
      els.files.appendChild(h('div', { class: 'table-wrap' }, h('table', { class: 'table tftp-table' },
        h('thead', null, h('tr', null, h('th', null, 'Name'), h('th', { class: 'num' }, 'Size'))),
        h('tbody', null, files.map((f) => h('tr', null, h('td', { class: 'wrap' }, f.name), h('td', { class: 'num' }, f.size == null ? '—' : fmtBytes(f.size))))))));
    }

    function renderTransfers() {
      const { fmtBytes, relTime } = TNT.util;
      const running = (st && Array.isArray(st.transfers) ? st.transfers : []).map(transferView).filter((t) => t.active);
      els.transfers.innerHTML = '';
      els.transfers.hidden = !running.length;
      if (running.length) els.transfers.appendChild(h('div', { class: 'label' }, 'Transfers'));
      for (const t of running) {
        const f = TNT.ui.fuse();
        f.set(t.pct == null ? 0 : t.pct, 'running', t.op === 'write' ? t.client + ' → ' + t.file : t.file + ' → ' + t.client,
          fmtBytes(t.bytes) + (t.size ? ' of ' + fmtBytes(t.size) : ''));
        els.transfers.appendChild(f);
      }
      const past = historyRows(st && st.history);
      els.history.innerHTML = '';
      els.history.hidden = !past.length;
      if (!past.length) return;
      els.history.appendChild(h('div', { class: 'label' }, 'Last transfers'));
      els.history.appendChild(h('div', { class: 'table-wrap' }, h('table', { class: 'table tftp-table' },
        h('thead', null, h('tr', null, h('th', null, 'When'), h('th', null, 'Client'), h('th', null, 'File'), h('th', { class: 'num' }, 'Bytes'), h('th', null, 'Result'))),
        h('tbody', null, past.map((t) => h('tr', null,
          h('td', null, t.ended_ts ? relTime(t.ended_ts) : '—'),
          h('td', null, t.client),
          h('td', { class: 'wrap', title: t.op === 'write' ? 'Uploaded by the device' : 'Sent to the device' }, (t.op === 'write' ? '↑ ' : '↓ ') + t.file),
          h('td', { class: 'num' }, fmtBytes(t.bytes)),
          h('td', null, h('span', { class: 'badge ' + t.cls, title: t.error || null }, t.state || '?'))))))));
    }

    function render() {
      if (!mounted) return;
      renderHead();
      const off = unavailable || (st && st.available === false ? String(st.error || UNAVAILABLE_TEXT) : '');
      els.unavailable.innerHTML = '';
      els.unavailable.hidden = !off;
      els.main.hidden = !!off;
      if (off) { els.unavailable.appendChild(TNT.ui.emptyState(off)); return; }
      renderSettings();
      renderInfo();
      renderFolder();
      renderFiles();
      renderTransfers();
    }

    /* ---- reading the service */
    const live = () => !!(TNT.api.events && TNT.api.events.state === 'live');
    function stopPoll() { if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; } }
    /** While a transfer runs: read the status again after pollDelay() (a transfer event postpones it). */
    function schedulePoll() {
      stopPoll();
      const ms = mounted ? pollDelay(st, live()) : null;
      if (ms != null) pollTimer = setTimeout(() => { pollTimer = null; if (mounted) loadStatus(); }, ms);
    }
    function applyStatus(next) {
      st = isObj(next) ? next : null;
      if (st && st.running) conflict = '';
      render();
      schedulePoll();
    }

    async function loadStatus() {
      if (!mounted) return;
      if (loading) { loadAgain = true; return; }
      loading = true;
      try {
        const r = await TNT.api.tftpStatus();
        if (!mounted) return;
        unavailable = '';
        applyStatus(r);
      } catch (err) {
        if (!mounted) return;
        if (err.status === 404 || err.status === 503) { unavailable = err.status === 503 && err.message ? err.message : UNAVAILABLE_TEXT; render(); }
        else {
          if (!st) TNT.ui.toast('Could not read the TFTP server status: ' + err.message, 'error');
          schedulePoll();
        }
      } finally {
        loading = false;
        if (loadAgain && mounted) { loadAgain = false; loadStatus(); }
      }
    }

    async function loadFiles() {
      if (!mounted) return;
      TNT.ui.busy(els.refreshBtn, true);
      try {
        const r = await TNT.api.tftpFiles();
        if (!mounted) return;
        files = fileRows(r);
        filesError = '';
      } catch (err) {
        if (!mounted) return;
        filesError = err.status === 404 || err.status === 503 ? UNAVAILABLE_TEXT : 'Could not list the TFTP folder: ' + err.message;
      } finally {
        if (mounted) { TNT.ui.busy(els.refreshBtn, false); renderFiles(); }
      }
    }

    /* ---- actions */
    function setBusy(mode) {
      busyMode = mode || '';
      renderHead();
      renderSettings();
      // the network changed while a start or stop ran: read the adapters again once its answer is in
      if (!busyMode && netPending && mounted) { netPending = false; setTimeout(() => { if (mounted) loadStatus(); }, 0); }
    }

    async function turnOn() {
      if (!mounted || busyMode) return;
      conflict = '';
      setBusy('starting');
      try {
        const r = await TNT.api.tftpStart({ adapter: els.adapter.value || null, uploads: !!els.uploads.input.checked });
        if (!mounted) return;
        setBusy('');
        applyStatus(r);
        if (r && r.running) TNT.ui.toast('TFTP server is on', 'ok');
        else TNT.ui.toast('The TFTP server did not start' + (r && r.error ? ': ' + r.error : ''), 'warn', 5000);
      } catch (err) {
        if (!mounted) return;
        setBusy('');
        const body = err.body || {};
        // another program holds UDP 69: its names go in the red box (the card is open: switching on opened it)
        if (err.status === 409 && (err.code === 'tftp_port_in_use' || Array.isArray(body.owners))) conflict = err.message || ownersText(body.owners);
        else TNT.ui.toast('Could not start the TFTP server: ' + err.message, 'error');
        render();
        loadStatus();
      }
    }

    async function turnOff() {
      if (!mounted || busyMode) return;
      setBusy('stopping');
      try {
        const r = await TNT.api.tftpStop();
        if (!mounted) return;
        setBusy('');
        applyStatus(r);
        TNT.ui.toast('TFTP server is off', 'ok');
      } catch (err) {
        if (!mounted) return;
        setBusy('');
        TNT.ui.toast('Could not stop the TFTP server: ' + err.message, 'error');
        render();
        loadStatus();
      }
    }

    async function setUploads(on) {
      if (!mounted || settingsBusy) return;
      settingsBusy = true;
      renderSettings();
      try {
        const r = await TNT.api.tftpUploads(!!on);
        if (!mounted) return;
        applyStatus(r);
        TNT.ui.toast(on ? 'Uploads are on' : 'Uploads are off', on ? 'warn' : 'ok');
      } catch (err) {
        if (mounted) TNT.ui.toast('Could not change uploads: ' + err.message, 'error');
      } finally {
        settingsBusy = false;
        if (mounted) render();                 // also snaps the switch back when the request failed
      }
    }

    async function saveSettings(patch) {
      if (!mounted || settingsBusy) return;
      settingsBusy = true;
      renderSettings();
      try {
        const r = await TNT.api.tftpSettings(patch);
        if (!mounted) return;
        applyStatus(r);
        TNT.ui.toast('TFTP settings saved', 'ok');
      } catch (err) {
        if (mounted) TNT.ui.toast(err.message || 'Could not save the TFTP settings', 'error');
      } finally {
        settingsBusy = false;
        if (mounted) render();
      }
    }
    /** The max upload size, sent when it changed (the service checks the number and says what is wrong). */
    function saveMaxUpload() {
      const cur = st && isObj(st.settings) ? st.settings.max_upload_mb : null;
      // a number field whose text is not a number ('40x') reads '' (validity.badInput): say so and show the size in force again
      if (els.maxUpload.validity && els.maxUpload.validity.badInput) {
        TNT.ui.toast(MAX_UPLOAD_INVALID_TEXT, 'warn');
        if (isNum(cur)) els.maxUpload.value = String(cur);
        return;
      }
      const text = String(els.maxUpload.value || '').trim();
      const n = Number(text);
      if (!text || n === cur) return;
      saveSettings({ max_upload_mb: Number.isInteger(n) ? n : text });
    }

    function openFolder() {
      const root = st && st.root ? String(st.root) : '';
      if (!root || !canOpenPath()) return;
      Promise.resolve().then(() => window.pywebview.api.open_path(root))
        .then((ok) => { if (!ok) TNT.ui.toast(OPEN_FAILED_TEXT, 'warn'); }, () => TNT.ui.toast(OPEN_FAILED_TEXT, 'error'));
    }

    /* ---- events */
    function onState(d) {
      if (mounted && isObj(d) && !busyMode && summaryDiffers(d, st)) loadStatus();
    }
    function onTransfer(d) {
      if (!mounted || !d || !isObj(d.transfer) || !st) return;
      st = Object.assign({}, st, mergeTransfer(st.transfers, st.history, d.transfer));
      renderTransfers();
      schedulePoll();
      if (d.transfer.op === 'write' && d.transfer.state === 'done') loadFiles();   // a device uploaded a file
    }
    // pywebview injects its bridge a moment after the page loads: "Open folder" may appear then
    const onBridge = () => { if (mounted) renderFolder(); };

    return {
      body,
      head: els.head,
      mount() {
        mounted = true;
        render();
        loadStatus();
        loadFiles();
        unsubs.push(TNT.api.events.on('tftp.state', onState));
        unsubs.push(TNT.api.events.on('tftp.transfer', onTransfer));
        unsubs.push(TNT.api.events.on('hello', () => { if (mounted) { loadStatus(); loadFiles(); } }));
        if (typeof window.addEventListener === 'function') window.addEventListener('pywebviewready', onBridge);
      },
      // the status snapshot's summary (status.tftp): read the full status when it says something the card does not show
      update(state) {
        if (!mounted || busyMode) return;
        const s = state && state.status ? state.status.tftp : undefined;
        if (s === undefined) return;
        if (s === null) { if (!st && !loading && !unavailable) { unavailable = UNAVAILABLE_TEXT; render(); } return; }
        if (unavailable) { unavailable = ''; loadStatus(); return; }
        if (summaryDiffers(s, st)) loadStatus();
      },
      // this PC changed networks: the adapters and their addresses (after a start or stop still in flight)
      netChanged() {
        if (!mounted) return;
        if (busyMode) { netPending = true; return; }
        loadStatus();
      },
      unmount() {
        mounted = false;
        for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
        unsubs = [];
        stopPoll();
        if (typeof window.removeEventListener === 'function') window.removeEventListener('pywebviewready', onBridge);
        st = null; files = null; filesError = ''; unavailable = ''; conflict = ''; busyMode = ''; settingsBusy = false; netPending = false;
        loading = false; loadAgain = false;
      },
    };
  }

  TNT.tools.tftp = { create, badgeState, adapterName, adapterLabel, transferView, mergeTransfer, historyRows, fileRows, ownersText, activeCount,
    pollDelay, summaryDiffers, TFTP_SCOPE_TEXT, UPLOADS_NOTE, EMPTY_FILES_TEXT, OPEN_FAILED_TEXT, MAX_UPLOAD_INVALID_TEXT, HISTORY_SHOWN };
})();
