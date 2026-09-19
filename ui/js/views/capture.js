/* TNT — views/capture.js
   The Packet capture page: a stripped-down network analyser. Pick an adapter that is up, Start, and the packets
   arrive in the list as they are captured — the number, the time of day, the time since the capture began, the
   addresses, the protocol, the length and a one-line summary. Stop keeps what was captured; Save writes it to disk
   as a pcapng file Wireshark can open, Open reads one back, Discard throws it away. Leaving the page with a capture
   that was never saved asks first (Save / Discard / Stay), and so does closing the window.

   The filters sit above the list and are applied by the service, over the packets it still holds:
     - an IP address field: every packet with it as source or destination, as you type (debounced);
     - a MAC address field, the same, in any spelling;
     - protocol buttons (ICMP, SIP, HTTP, HTTPS, DNS, ...): more than one is an OR, and they AND with the fields.
   "SIP calls" is one of those buttons. While it is on, a "Show calls" button appears beside it that opens the calls
   the capture reconstructed, each with its own player: TNT rebuilds the RTP of a G.711 call into a WAV. A call found
   while a capture runs (or while a file is read) raises a toast as well, once per call.

   Clicking a row opens the packet detail window: the protocol tree, one layer at a time, over the hex dump.

   GET /api/capture on mount, on 'hello' and after this PC changed networks; capture.state events move the session and
   capture.sip announces a call. While a capture runs the list is tailed with GET /api/capture/packets?since=... every
   TAIL_MS. Packet capture needs a Windows administrator account: a 403 admin_required shows that instead of the page.
   Loaded after the other views; TNT.util / TNT.ui are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  const TAIL_MS = 700;              // how often a running capture's list is tailed
  const IDLE_MS = 4000;             // ... and how often the status is read when nothing is capturing
  const TAIL_LIMIT = 800;           // rows asked for per tail request
  const DOM_ROWS = 3000;            // rows kept in the table (the oldest are dropped from the top)
  const FILTER_DEBOUNCE_MS = 250;
  const ADMIN_TEXT = 'Packet capture needs a Windows administrator account';
  const UNAVAILABLE_TEXT = 'Packet capture is not available on this service';
  const WARNING_TEXT = 'Captures can contain passwords and private data. TNT keeps the newest 10 (at most 2 GB, 7 days) in a folder only administrators can open; a copy you save elsewhere is not protected.';
  const LEAVE_TITLE = 'Save this capture?';
  const LEAVE_TEXT = 'This capture has not been saved. Save it as a file you can open again, or throw it away.';

  // the quick filter buttons, in order. `key` is what the service knows (tnt.dissect.PROTO_FILTERS).
  const PROTO_BUTTONS = [
    { key: 'icmp', label: 'ICMP', title: 'Ping and the other ICMP messages, IPv4 and IPv6' },
    { key: 'arp', label: 'ARP', title: 'Address resolution on this LAN' },
    { key: 'dns', label: 'DNS', title: 'Name lookups (also mDNS and LLMNR)' },
    { key: 'dhcp', label: 'DHCP', title: 'Address leases, IPv4 and IPv6' },
    { key: 'http', label: 'HTTP', title: 'Unencrypted web traffic' },
    { key: 'https', label: 'HTTPS', title: 'TLS, including the handshake that names the site' },
    { key: 'tcp', label: 'TCP', title: 'Every TCP packet' },
    { key: 'udp', label: 'UDP', title: 'Every UDP packet' },
    { key: 'rtsp', label: 'RTSP', title: 'Camera and media streaming control' },
    { key: 'rtp', label: 'RTP', title: 'The audio and video streams themselves' },
    { key: 'sip', label: 'SIP calls', title: 'SIP signalling, and the calls TNT rebuilt from it', calls: true },
  ];

  // the packet list's columns. `width` is fixed (the table is table-layout: fixed) so nothing moves as packets stream
  // in: an IPv6 address or a long TCP summary would otherwise re-measure every column on every append. Info has no
  // width and takes whatever is left. The two address columns are a percentage so they grow with the window (an
  // IPv6 address is 39 characters; past the column it is cut with the whole value in the tooltip).
  const COLUMNS = [
    { key: 'no', label: 'No.', cls: 'num', width: '64px' },
    { key: 'time', label: 'Time', cls: 'mono', width: '112px' },
    { key: 'rel', label: 'Since start', cls: 'num mono', width: '96px' },
    { key: 'src', label: 'Source', cls: 'mono', width: '15%' },
    { key: 'dst', label: 'Destination', cls: 'mono', width: '15%' },
    { key: 'proto', label: 'Protocol', cls: '', width: '96px' },
    { key: 'length', label: 'Length', cls: 'num', width: '74px' },
    { key: 'info', label: 'Info', cls: 'info', width: null },
  ];

  /* ------------------------------------------------ pure helpers (tests) */
  const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
  const isNum = (v) => typeof v === 'number' && isFinite(v);

  /** Pure: a packet's time of day, "HH:MM:SS.mmm" in this PC's time zone; '' without a timestamp. */
  function timeOfDay(ts) {
    if (!isNum(ts)) return '';
    const d = new Date(ts * 1000);
    const p2 = (n) => String(n).padStart(2, '0');
    return p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds()) + '.' + String(d.getMilliseconds()).padStart(3, '0');
  }

  /** Pure: the time since the capture began, in seconds with three decimals ("12.480"). */
  function relText(rel) {
    return isNum(rel) ? Math.max(0, rel).toFixed(3) : '';
  }

  /** Pure: the CSS class that colours a protocol's cell, so the list reads at a glance. The comparison is upper case
   *  on both sides — the service spells two of them ICMPv6 and DHCPv6, which would never match otherwise. */
  function protoClass(proto) {
    const p = String(proto || '').toUpperCase();
    if (p === 'SIP' || p === 'RTP' || p === 'RTCP' || p === 'RTSP') return 'p-voice';
    if (p === 'TLS' || p === 'HTTPS' || p === 'QUIC') return 'p-secure';
    if (p === 'HTTP') return 'p-web';
    if (p === 'DNS' || p === 'MDNS' || p === 'LLMNR' || p === 'NBNS') return 'p-name';
    if (p === 'ICMP' || p === 'ICMPV6' || p === 'IGMP') return 'p-icmp';
    if (p === 'ARP' || p === 'LLDP' || p === 'CDP' || p === 'STP' || p === 'EAPOL') return 'p-link';
    if (p === 'DHCP' || p === 'DHCPV6' || p === 'NTP') return 'p-admin';
    return '';
  }

  /** Pure: the filter the page has on -> the query object for TNT.api.capturePackets, with `since` when tailing. */
  function filterQuery(filter, since) {
    const f = isObj(filter) ? filter : {};
    const q = { limit: TAIL_LIMIT };
    if (since != null) q.since = since;
    if (f.ip) q.ip = f.ip;
    if (f.mac) q.mac = f.mac;
    if (Array.isArray(f.protos) && f.protos.length) q.protos = f.protos.slice();
    return q;
  }

  /** Pure: is any filter on? */
  function filterOn(filter) {
    const f = isObj(filter) ? filter : {};
    return !!(f.ip || f.mac || (Array.isArray(f.protos) && f.protos.length));
  }

  /** Pure: what a session (SESSION, or null) shows -> { state, running, unsaved, label, detail, cls }.
   *  `unsaved` drives the prompt before leaving: a live capture that was never saved, stopped or still running. */
  function sessionView(session) {
    const s = isObj(session) ? session : null;
    const out = { state: s ? String(s.state || '') : '', running: false, unsaved: false, label: 'Not capturing',
      detail: '', cls: 'muted' };
    if (!s) return out;
    const packets = isNum(s.packets) ? s.packets : 0;
    const bits = [packets.toLocaleString() + (packets === 1 ? ' packet' : ' packets')];
    if (isNum(s.bytes) && s.bytes > 0) bits.push(fmtBytes(s.bytes));
    if (isNum(s.dropped) && s.dropped > 0) bits.push(s.dropped.toLocaleString() + ' dropped');
    if (s.truncated) bits.push('list holds the newest ' + (isNum(s.shown) ? s.shown.toLocaleString() : 'few'));
    out.detail = bits.join(' · ');
    if (s.state === 'capturing') {
      const name = s.adapter && s.adapter.name ? s.adapter.name : 'this PC';
      out.running = true;
      out.unsaved = true;
      out.cls = 'ok';
      out.label = 'Capturing on ' + name + ' · ' + clock(s.elapsed_s);
    } else if (s.state === 'stopped') {
      out.unsaved = !s.saved;
      out.cls = s.saved ? 'ok' : '';
      out.label = s.saved ? 'Saved as ' + (s.file || 'a file') : 'Stopped — not saved yet' + stopSuffix(s.stop_reason);
    } else if (s.state === 'loaded') {
      out.cls = '';
      out.label = 'Reading ' + (s.file || 'a saved capture');
    } else if (s.state === 'error') {
      out.cls = 'bad';
      out.label = String(s.error || 'The capture failed');
    }
    return out;
  }

  /** Pure: why a capture stopped by itself, as a phrase to hang off "Stopped" ('' when the user stopped it). */
  function stopSuffix(reason) {
    if (reason === 'seconds') return ' (it reached its time limit)';
    if (reason === 'size') return ' (it reached its size limit)';
    if (reason === 'packets') return ' (it reached its packet limit)';
    if (reason === 'adapter') return ' (the adapter went away)';
    if (reason === 'service') return ' (the service stopped)';
    return '';                                    // 'user', and anything a newer service invents
  }

  /** Pure: m:ss for a number of seconds ("0:23", "15:00"). */
  function clock(s) {
    const n = Math.max(0, Math.floor(isNum(s) ? s : 0));
    return Math.floor(n / 60) + ':' + String(n % 60).padStart(2, '0');
  }

  function fmtBytes(n) {
    return TNT.util && TNT.util.fmtBytes ? TNT.util.fmtBytes(n) : String(n);
  }

  /** Pure: one SIP call (CALL) -> { id, title, state, cls, when, duration, playable, note }. */
  function callView(call) {
    const c = isObj(call) ? call : {};
    const state = String(c.state || '');
    const cls = state === 'answered' ? 'green' : state === 'ended' ? 'grey' : state === 'failed' ? 'red'
      : state === 'cancelled' ? 'yellow' : 'blue';
    const streams = Array.isArray(c.streams) ? c.streams : [];
    const playable = streams.some((s) => isObj(s) && s.decodable);
    const codecs = Array.from(new Set(streams.map((s) => (isObj(s) ? String(s.codec || '') : '')).filter(Boolean)));
    return {
      id: String(c.id || ''),
      title: String(c.from_uri || 'unknown') + ' → ' + String(c.to_uri || 'unknown'),
      state, cls,
      when: isNum(c.start_ts) ? timeOfDay(c.start_ts) : '',
      duration: isNum(c.duration_s) ? clock(c.duration_s) : '',
      playable,
      note: playable ? codecs.join(', ') : codecs.length ? codecs.join(', ') + ' — TNT cannot play this codec'
        : 'No audio was captured for this call',
    };
  }

  /* ------------------------------------------------------------- the page */
  let root = null;
  let unsubs = [];
  let els = {};
  let st = null;                 // GET /api/capture
  let admin = false;
  let unavailable = '';
  let busy = '';                 // 'starting' | 'stopping' | 'saving' | 'opening'
  let lastNo = 0;                // the highest row number the table holds
  let shownId = null;            // the session id the rows on screen came from
  let total = 0;                 // packets in the capture, and how many of them the filter matches
  let matched = 0;
  // every list request is numbered: a slow answer that arrives after a newer one (a filter changed while it was in
  // flight) is thrown away instead of putting the old rows back
  let reqSeq = 0;
  let filter = { ip: '', mac: '', protos: [] };
  let follow = true;
  let timer = null, filterTimer = null;
  let loading = false, tailing = false;
  let leaveGuard = null, beforeUnload = null;
  let announced = {};            // call ids already toasted
  let detailModal = null, callsModal = null;

  const session = () => (st && isObj(st.session) ? st.session : null);
  const live = () => !!(TNT.api.events && TNT.api.events.state === 'live');

  /* ---- building */
  function build() {
    const { h } = TNT.util;
    els = {};

    els.adapter = h('select', { class: 'input', 'aria-label': 'Adapter' });
    els.seconds = h('select', { class: 'input', 'aria-label': 'Stop after' });
    els.size = h('select', { class: 'input', 'aria-label': 'Size limit' });
    els.startBtn = h('button', { class: 'btn btn-primary', type: 'button', title: 'Start capturing this adapter\'s traffic',
      on: { click: () => start() } }, TNT.ui.icon('play'), 'Start');
    els.stopBtn = h('button', { class: 'btn', type: 'button', hidden: true, title: 'End the capture and keep what it caught',
      on: { click: () => stop() } }, TNT.ui.icon('stop'), 'Stop');
    els.saveBtn = h('button', { class: 'btn', type: 'button', title: 'Write this capture to disk as a pcapng file',
      on: { click: () => save() } }, TNT.ui.icon('download'), 'Save to disk');
    els.openBtn = h('button', { class: 'btn', type: 'button', title: 'Read a capture that was saved earlier',
      on: { click: () => openPicker() } }, TNT.ui.icon('search'), 'Open…');
    els.discardBtn = h('button', { class: 'btn', type: 'button', title: 'Throw this capture away',
      on: { click: () => discard() } }, TNT.ui.icon('trash'), 'Discard');

    els.status = h('div', { class: 'cap-status', role: 'status', 'aria-live': 'polite' });
    els.reason = h('div', { class: 'dhcp-info warn', hidden: true });
    const controls = h('div', { class: 'cap-controls' },
      h('div', { class: 'field wide' }, h('label', null, 'Adapter'), els.adapter),
      h('div', { class: 'field' }, h('label', null, 'Stop after'), els.seconds),
      h('div', { class: 'field' }, h('label', null, 'Size limit'), els.size),
      h('div', { class: 'cap-buttons' }, els.startBtn, els.stopBtn, els.saveBtn, els.openBtn, els.discardBtn));
    const captureCard = h('div', { class: 'card', data: { card: 'capture' } },
      h('div', { class: 'card-title' }, TNT.ui.icon('capture'), 'Capture'), controls, els.reason, els.status);

    /* ---- filters */
    els.ip = h('input', { class: 'input', type: 'text', placeholder: 'IP address', spellcheck: 'false',
      autocomplete: 'off', 'aria-label': 'Filter by IP address' });
    els.mac = h('input', { class: 'input', type: 'text', placeholder: 'MAC address', spellcheck: 'false',
      autocomplete: 'off', 'aria-label': 'Filter by MAC address' });
    for (const input of [els.ip, els.mac]) input.addEventListener('input', () => scheduleFilter());
    els.clearBtn = h('button', { class: 'btn btn-sm', type: 'button', title: 'Clear every filter',
      on: { click: () => clearFilters() } }, TNT.ui.icon('close'), 'Clear');
    els.protoBtns = {};
    const protoRow = h('div', { class: 'cap-protos' });
    for (const p of PROTO_BUTTONS) {
      const b = h('button', { class: 'cap-proto', type: 'button', title: p.title, 'aria-pressed': 'false',
        on: { click: () => toggleProto(p.key) } }, p.calls ? TNT.ui.icon('phone') : null, p.label);
      els.protoBtns[p.key] = b;
      protoRow.appendChild(b);
    }
    els.callsBtn = h('button', { class: 'btn btn-sm cap-calls-btn', type: 'button', hidden: true,
      title: 'The calls TNT rebuilt from this capture', on: { click: () => showCalls() } }, TNT.ui.icon('phone'), 'Show calls');
    protoRow.appendChild(els.callsBtn);
    els.follow = h('input', { type: 'checkbox', id: 'cap-follow', checked: 'checked' });
    els.follow.addEventListener('change', () => { follow = els.follow.checked; if (follow) scrollToEnd(); });
    els.counts = h('span', { class: 'muted small' }, '');
    const filterRow = h('div', { class: 'cap-filters' },
      els.ip, els.mac, els.clearBtn, h('span', { class: 'spacer' }),
      h('label', { class: 'cap-follow', for: 'cap-follow' }, els.follow, 'Follow'), els.counts);

    /* ---- the packet list */
    els.tbody = h('tbody');
    els.table = h('table', { class: 'table cap-table' },
      h('colgroup', null, COLUMNS.map((c) => h('col', c.width ? { style: 'width:' + c.width } : null))),
      h('thead', null, h('tr', null, COLUMNS.map((c) => h('th', { class: c.cls }, c.label)))),
      els.tbody);
    els.empty = h('div', { class: 'cap-empty' });
    els.scroll = h('div', { class: 'cap-scroll' }, els.table, els.empty);
    // the scroller and the checkbox are held by the listener itself, not read off `els`: unmount() empties `els`, and a
    // scroll event can still reach the element the page has already let go of
    const scroller = els.scroll, followBox = els.follow;
    scroller.addEventListener('scroll', () => {
      // scrolling up stops the list following; coming back to the bottom starts it again
      const atEnd = scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - 24;
      if (atEnd !== follow) { follow = atEnd; followBox.checked = atEnd; }
    });
    els.tbody.addEventListener('click', (e) => {
      const tr = e.target && e.target.closest ? e.target.closest('tr[data-no]') : null;
      if (tr) showDetail(Number(tr.dataset.no));
    });
    const listCard = h('div', { class: 'card cap-list-card' },
      h('div', { class: 'card-title' }, TNT.ui.icon('search'), 'Packets'),
      h('div', { class: 'cap-filter-wrap' }, filterRow, protoRow), els.scroll);

    els.main = h('div', { class: 'stack' }, captureCard, listCard,
      h('div', { class: 'dhcp-info warn cap-warning' }, TNT.ui.icon('warning'), h('span', null, WARNING_TEXT)));
    els.admin = h('div', { class: 'dhcp-info warn', hidden: true }, TNT.ui.icon('warning'), h('span', null, ADMIN_TEXT));
    els.unavailable = h('div', { hidden: true });

    const head = h('div', { class: 'section-head' },
      h('h2', null, h('span', { class: 'section-accent' }), 'Packet capture'));
    root.appendChild(head);
    root.appendChild(els.admin);
    root.appendChild(els.unavailable);
    root.appendChild(els.main);
  }

  /* ---- rendering */
  function renderControls() {
    const { h } = TNT.util;
    // the limits come from the service, so the page never offers a duration or a size it would refuse: the two
    // selects are filled once, on the first status that carries them
    const limits = (st && isObj(st.limits)) ? st.limits : null;
    if (limits && !els.seconds.options.length) {
      for (const s of Array.isArray(limits.seconds) ? limits.seconds : []) {
        els.seconds.appendChild(h('option', { value: String(s) }, s >= 60 ? (s / 60) + ' min' : s + ' s'));
      }
      els.seconds.value = String(limits.default_seconds || '');
      for (const mb of Array.isArray(limits.sizes_mb) ? limits.sizes_mb : []) {
        els.size.appendChild(h('option', { value: String(mb) }, mb + ' MB'));
      }
      els.size.value = String(limits.default_mb || '');
    }
    const adapters = st && Array.isArray(st.adapters) ? st.adapters.filter(isObj) : [];
    if (document.activeElement !== els.adapter) {
      const keep = els.adapter.value;
      els.adapter.innerHTML = '';
      for (const a of adapters) {
        els.adapter.appendChild(h('option', { value: String(a.name || '') }, String(a.name || '?') + (a.wifi ? ' (Wi-Fi)' : '')));
      }
      if (!adapters.length) els.adapter.appendChild(h('option', { value: '' }, st ? 'No adapter is up' : 'Loading…'));
      if (adapters.some((a) => String(a.name || '') === keep)) els.adapter.value = keep;
    }
    const v = sessionView(session());
    const locked = v.running || !!busy;
    for (const el of [els.adapter, els.seconds, els.size]) el.disabled = locked;
    els.startBtn.hidden = v.running;
    els.stopBtn.hidden = !v.running;
    els.stopBtn.disabled = busy === 'stopping';
    if (busy === 'starting') TNT.ui.busy(els.startBtn, true, 'Starting…');
    else { TNT.ui.busy(els.startBtn, false); els.startBtn.disabled = !st || st.available === false || !adapters.length; }
    const open = !!session();
    els.saveBtn.hidden = !open || (session() || {}).saved === true;
    els.saveBtn.disabled = busy === 'saving';
    els.discardBtn.hidden = !open;
    // reading a big file takes a few seconds (50 000 rows is the most the list holds), so the button says so
    if (busy === 'opening') TNT.ui.busy(els.openBtn, true, 'Opening…');
    else { TNT.ui.busy(els.openBtn, false); els.openBtn.disabled = v.running || !!busy; }
    const reason = st && st.available === false ? String(st.reason || UNAVAILABLE_TEXT) : '';
    els.reason.innerHTML = '';
    els.reason.hidden = !reason;
    if (reason) { els.reason.appendChild(TNT.ui.icon('warning')); els.reason.appendChild(TNT.util.h('span', null, reason)); }
  }

  function renderStatus() {
    const { h } = TNT.util;
    const v = sessionView(session());
    els.status.innerHTML = '';
    els.status.className = 'cap-status ' + (v.cls || '');
    if (v.running) els.status.appendChild(h('span', { class: 'spark-icon' }, TNT.ui.icon('spark')));
    els.status.appendChild(h('span', { class: 'strong' }, v.label));
    if (v.detail) els.status.appendChild(h('span', { class: 'muted' }, v.detail));
  }

  /** "1,234 packets", or "18 shown of 1,234" with a filter on. `matched` is counted across the whole capture, not
   *  per request: a tail answers with the rows after the last one seen, so its own `matched` is only the new ones. */
  function renderCounts(info) {
    if (info && isNum(info.total)) total = info.total;
    const text = filterOn(filter)
      ? matched.toLocaleString() + ' matching · ' + Number(total).toLocaleString() + ' captured'
      : Number(total).toLocaleString() + (total === 1 ? ' packet' : ' packets');
    if (els.counts.textContent !== text) els.counts.textContent = text;
  }

  function renderEmpty() {
    const rows = els.tbody.children.length;
    const v = sessionView(session());
    let text = '';
    if (!session()) text = 'Pick an adapter and hit Start, or open a capture you saved earlier.';
    else if (!rows && filterOn(filter)) text = 'No packet matches this filter yet.';
    else if (!rows) text = v.running ? 'Waiting for the first packet…' : 'This capture holds no packets.';
    els.empty.textContent = text;
    els.empty.hidden = !text;
    els.table.hidden = !!text;
  }

  function renderProtos() {
    for (const p of PROTO_BUTTONS) {
      const on = filter.protos.includes(p.key);
      const b = els.protoBtns[p.key];
      b.classList.toggle('on', on);
      b.setAttribute('aria-pressed', String(on));
    }
    const sipOn = filter.protos.includes('sip');
    const calls = (session() || {}).calls || 0;
    els.callsBtn.hidden = !sipOn;
    els.callsBtn.disabled = !calls;
    els.callsBtn.textContent = '';
    els.callsBtn.appendChild(TNT.ui.icon('phone'));
    els.callsBtn.appendChild(document.createTextNode(calls ? 'Show calls (' + calls + ')' : 'No calls found yet'));
  }

  function render() {
    if (!root) return;
    const off = !admin && unavailable ? unavailable : '';
    els.admin.hidden = !admin;
    els.unavailable.innerHTML = '';
    els.unavailable.hidden = !off;
    if (off) els.unavailable.appendChild(TNT.ui.emptyState(off));
    els.main.hidden = admin || !!off;
    if (admin || off) return;
    renderControls();
    renderStatus();
    renderProtos();
    renderCounts(null);
    renderEmpty();
  }

  /* ---- the packet rows */
  function rowEl(row) {
    const { h } = TNT.util;
    const src = row.src || row.src_mac || '';
    const dst = row.dst || row.dst_mac || '';
    const info = row.info || '';
    // every cell is one line: a long address or summary is cut with an ellipsis and kept whole in the tooltip, so a
    // row is always the same height and the list never jumps
    const cells = [
      h('td', { class: 'num' }, String(row.no)),
      h('td', { class: 'mono' }, timeOfDay(row.ts)),
      h('td', { class: 'num mono' }, relText(row.rel)),
      h('td', { class: 'mono', title: src }, src),
      h('td', { class: 'mono', title: dst }, dst),
      h('td', null, h('span', { class: 'cap-proto-tag ' + protoClass(row.proto) }, row.proto || '')),
      h('td', { class: 'num' }, isNum(row.length) ? String(row.length) : ''),
      h('td', { class: 'info', title: info }, info),
    ];
    return h('tr', { data: { no: String(row.no) }, tabindex: '0', title: 'Show this packet in detail' }, cells);
  }

  function appendRows(rows) {
    if (!rows || !rows.length) return;
    const frag = document.createDocumentFragment();
    for (const r of rows) {
      frag.appendChild(rowEl(r));
      if (isNum(r.no) && r.no > lastNo) lastNo = r.no;
    }
    els.tbody.appendChild(frag);
    let over = els.tbody.children.length - DOM_ROWS;
    while (over-- > 0 && els.tbody.firstElementChild) els.tbody.firstElementChild.remove();
    if (follow) scrollToEnd();
  }

  function resetRows() {
    els.tbody.innerHTML = '';
    lastNo = 0;
    matched = 0;
  }

  function scrollToEnd() {
    if (els.scroll) els.scroll.scrollTop = els.scroll.scrollHeight;
  }

  /* ---- reading the service */
  function stopTimer() { if (timer) { clearTimeout(timer); timer = null; } }

  function schedule() {
    stopTimer();
    if (!root || admin || unavailable) return;
    const v = sessionView(session());
    const ms = v.running ? TAIL_MS : (live() ? IDLE_MS * 3 : IDLE_MS);
    timer = setTimeout(() => { timer = null; if (!root) return; if (v.running) tail(); else load(); }, ms);
  }

  function refused(err) {
    if (!(err && err.status === 403 && err.code === 'admin_required')) return false;
    admin = true;
    stopTimer();
    render();
    return true;
  }

  async function load() {
    if (!root || loading) return;
    loading = true;
    try {
      const r = await TNT.api.captureGet();
      if (!root) return;
      st = isObj(r) ? r : null;
      admin = false;
      unavailable = '';
      render();
      // only a different capture (or one the page holds no rows of) rebuilds the list: an idle poll must never
      // throw away what the user is looking at, or scroll them back to the bottom
      const id = (session() || {}).id;
      if (id !== shownId || (id != null && !els.tbody.children.length)) {
        shownId = id;
        await refreshRows();
      }
    } catch (err) {
      if (!root || refused(err)) return;
      if (err.status === 404 || err.status === 503) {
        unavailable = err.status === 503 && err.message ? err.message : UNAVAILABLE_TEXT;
        stopTimer();
        render();
        return;
      }
      if (!st) TNT.ui.toast('Could not read the packet capture status: ' + err.message, 'error');
    } finally {
      loading = false;
      if (root) schedule();
    }
  }

  /** The list from scratch (a new capture, a changed filter, a file that was opened). */
  async function refreshRows() {
    if (!root || !session()) { resetRows(); renderEmpty(); return; }
    const mine = ++reqSeq;
    try {
      const r = await TNT.api.capturePackets(filterQuery(filter, null));
      if (!root || mine !== reqSeq) return;
      resetRows();
      matched = isNum(r.matched) ? r.matched : 0;
      appendRows(Array.isArray(r.rows) ? r.rows : []);
      if (isObj(r.session)) applySession(r.session);
      renderCounts(r);
      renderEmpty();
    } catch (err) {
      if (!root || refused(err)) return;
      if (err.status !== 404) TNT.ui.toast('Could not read the packets: ' + err.message, 'error');
    }
  }

  /** The rows after the last one shown, while a capture runs. */
  async function tail() {
    if (!root || tailing) { schedule(); return; }
    tailing = true;
    const mine = ++reqSeq;
    try {
      const r = await TNT.api.capturePackets(filterQuery(filter, lastNo));
      if (!root || mine !== reqSeq) return;
      if (r.dropped_before) {
        // the ring rolled past what the page holds: start the list again rather than show a hole
        await refreshRows();
      } else {
        const fresh = Array.isArray(r.rows) ? r.rows : [];
        matched += fresh.length;
        appendRows(fresh);
        renderCounts(r);
        renderEmpty();
      }
      if (isObj(r.session)) applySession(r.session);
    } catch (err) {
      if (!root || refused(err)) return;
    } finally {
      tailing = false;
      if (root) schedule();
    }
  }

  function applySession(next) {
    if (!st) st = { available: true, reason: null, adapters: [], session: null, files: [], limits: {} };
    st.session = next;
    renderControls();
    renderStatus();
    renderProtos();
    guard();
  }

  /* ---- actions */
  function setBusy(mode) { busy = mode || ''; renderControls(); }

  async function start() {
    if (!root || busy) return;
    const adapter = els.adapter.value;
    if (!adapter) { TNT.ui.toast('No adapter is up to capture on', 'warn'); return; }
    if (sessionView(session()).unsaved && !(await askToLeave())) return;
    setBusy('starting');
    try {
      const r = await TNT.api.captureStart({ adapter, max_seconds: Number(els.seconds.value) || 900,
        max_mb: Number(els.size.value) || 256 });
      if (!root) return;
      setBusy('');
      announced = {};
      resetRows();
      if (isObj(r.session)) applySession(r.session);
      shownId = (session() || {}).id;
      renderEmpty();
      follow = true;
      els.follow.checked = true;
      schedule();
    } catch (err) {
      if (!root) return;
      setBusy('');
      if (refused(err)) return;
      TNT.ui.toast('Could not start the capture: ' + (err.message || 'unknown error'), err.status === 409 ? 'warn' : 'error');
      load();
    }
  }

  async function stop() {
    if (!root || busy) return;
    setBusy('stopping');
    try {
      const r = await TNT.api.captureStop();
      if (!root) return;
      setBusy('');
      if (isObj(r.session)) applySession(r.session);
      await refreshRows();
    } catch (err) {
      if (!root) return;
      setBusy('');
      if (refused(err)) return;
      TNT.ui.toast('Could not stop the capture: ' + (err.message || 'unknown error'), 'error');
    } finally {
      if (root) schedule();
    }
  }

  async function save() {
    if (!root || busy) return false;
    setBusy('saving');
    try {
      const r = await TNT.api.captureSave();
      if (!root) return false;
      setBusy('');
      if (isObj(r.session)) applySession(r.session);
      if (Array.isArray(r.files) && st) st.files = r.files;
      const name = (session() || {}).file;
      TNT.ui.toast(name ? 'Capture saved: ' + name : 'Capture saved', 'ok');
      return true;
    } catch (err) {
      if (!root) return false;
      setBusy('');
      if (refused(err)) return false;
      TNT.ui.toast('Could not save the capture: ' + (err.message || 'unknown error'), 'error');
      return false;
    }
  }

  async function discard(skipAsk) {
    if (!root || busy) return false;
    if (!skipAsk) {
      const ok = await TNT.ui.confirm({ title: 'Throw this capture away?',
        message: 'The packets and the file behind them are deleted from this PC.', ok: 'Discard', danger: true });
      if (!ok || !root) return false;
    }
    try {
      await TNT.api.captureDiscard();
      if (!root) return false;
      st = st || {};
      st.session = null;
      resetRows();
      announced = {};
      render();
      return true;
    } catch (err) {
      if (!root || refused(err)) return false;
      TNT.ui.toast('Could not discard the capture: ' + (err.message || 'unknown error'), 'error');
      return false;
    } finally {
      if (root) { load(); }
    }
  }

  /* ---- opening a capture */
  /** Is the TNT window's native file picker there? In a plain browser tab it is not, and the path field is typed in. */
  function hasPicker() {
    return !!(window.pywebview && window.pywebview.api && typeof window.pywebview.api.pick_capture_file === 'function');
  }

  /** The "Open a capture" window: any file on this PC by its path (Browse… in the TNT window), then the captures TNT
   *  saved itself. The row actions are one flex row, so the three buttons share a centre line instead of stacking on
   *  their text baselines. */
  function openPicker() {
    const { h } = TNT.util;
    const files = st && Array.isArray(st.files) ? st.files : [];

    const pathInput = h('input', { class: 'input mono', type: 'text', spellcheck: 'false', autocomplete: 'off',
      'aria-label': 'Full path of a capture file on this PC', placeholder: 'C:\\Users\\…\\capture.pcapng' });
    const openPathBtn = h('button', { class: 'btn btn-sm btn-primary', type: 'button', on: { click: () => {
      const typed = pathInput.value.trim();
      if (!typed) { pathInput.focus(); return; }
      m.close();
      openCapture({ path: typed }, typed.split(/[\\/]/).pop() || typed);
    } } }, TNT.ui.icon('play'), 'Open');
    const browseBtn = h('button', { class: 'btn btn-sm', type: 'button', hidden: !hasPicker(),
      title: 'Pick a capture file from this PC', on: { click: async () => {
        try {
          const picked = await window.pywebview.api.pick_capture_file();
          if (picked) { pathInput.value = String(picked); openPathBtn.click(); }
        } catch (e) { TNT.ui.toast('The file picker could not be opened', 'warn'); }
      } } }, TNT.ui.icon('search'), 'Browse…');
    pathInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') openPathBtn.click(); });

    const body = h('div', { class: 'cap-open' },
      h('div', { class: 'cap-open-head' }, 'A capture file on this PC'),
      h('div', { class: 'cap-open-from' }, pathInput, browseBtn, openPathBtn),
      h('div', { class: 'cap-open-hint muted small' },
        hasPicker() ? 'Any pcapng file this PC can read — one from Wireshark, a switch or a colleague.'
          : 'Any pcapng file this PC can read. Paste its full path (the TNT window also has a Browse button).'),
      h('div', { class: 'cap-open-head' }, 'Captures TNT saved'));

    if (!files.length) body.appendChild(TNT.ui.emptyState('TNT has not saved a capture on this PC yet'));
    else {
      const savedRow = (f) => {
        const name = String(f.name || '');
        const actions = h('div', { class: 'cap-file-actions' },
          h('button', { class: 'btn btn-sm', type: 'button',
            on: { click: () => { m.close(); openCapture({ name }, name); } } }, 'Open'),
          h('button', { class: 'btn btn-round-sm', type: 'button', title: 'Save a copy of this capture elsewhere',
            'aria-label': 'Download ' + name, on: { click: () => downloadFile(name) } }, TNT.ui.icon('download')),
          h('button', { class: 'btn btn-round-sm', type: 'button', title: 'Delete this capture',
            'aria-label': 'Delete ' + name,
            on: { click: () => { m.close(); removeFile(name); } } }, TNT.ui.icon('trash')));
        return h('tr', null,
          h('td', { class: 'wrap mono' }, name),
          h('td', { class: 'num' }, isNum(f.size) ? fmtBytes(f.size) : '—'),
          h('td', { class: 'num' }, isNum(f.packets) ? String(f.packets) : '—'),
          h('td', { class: 'actions' }, actions));
      };
      const head = h('tr', null, h('th', null, 'Name'), h('th', { class: 'num' }, 'Size'),
        h('th', { class: 'num' }, 'Packets'), h('th', { class: 'actions' }, h('span', { class: 'sr-only' }, 'Actions')));
      body.appendChild(h('div', { class: 'table-wrap' },
        h('table', { class: 'table cap-files-table' }, h('thead', null, head), h('tbody', null, files.map(savedRow)))));
    }
    const m = TNT.ui.modal({ title: 'Open a capture', body, wide: true });
    setTimeout(() => { try { pathInput.focus(); } catch (e) { /* ignore */ } }, 0);
  }

  /** Read a capture into the list: `what` is { name } for one of TNT's own or { path } for any file on this PC. */
  async function openCapture(what, label) {
    if (!root || busy) return;
    if (sessionView(session()).unsaved && !(await askToLeave())) return;
    setBusy('opening');
    try {
      const r = what && what.path ? await TNT.api.captureOpenPath(what.path) : await TNT.api.captureOpen(what.name);
      if (!root) return;
      setBusy('');
      announced = {};
      resetRows();
      if (isObj(r.session)) applySession(r.session);
      shownId = (session() || {}).id;
      await refreshRows();
      const s = session() || {};
      TNT.ui.toast('Opened ' + label + ': ' + Number(s.packets || 0).toLocaleString() + ' packets', 'ok');
      if (s.truncated) TNT.ui.toast('That file holds more packets than the list does: the first ' +
        Number(s.shown || 0).toLocaleString() + ' are shown', 'warn', 7000);
    } catch (err) {
      if (!root) return;
      setBusy('');
      if (refused(err)) return;
      TNT.ui.toast('Could not open ' + label + ': ' + (err.message || 'unknown error'), 'error');
      load();
    }
  }

  function downloadFile(name) {
    const { h } = TNT.util;
    const a = h('a', { href: TNT.api.captureFileUrl(name), download: name, hidden: true });
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  async function removeFile(name) {
    const ok = await TNT.ui.confirm({ title: 'Delete ' + name + '?',
      message: 'The capture file is deleted from this PC.', ok: 'Delete', danger: true });
    if (!ok || !root) return;
    try {
      const r = await TNT.api.captureDeleteFile(name);
      if (!root) return;
      if (st && Array.isArray(r.files)) st.files = r.files;
      TNT.ui.toast('Deleted ' + name, 'ok');
      load();
    } catch (err) {
      if (!root || refused(err)) return;
      TNT.ui.toast('Could not delete ' + name + ': ' + (err.message || 'unknown error'), err.status === 409 ? 'warn' : 'error');
    }
  }

  /* ---- filters */
  function scheduleFilter() {
    if (filterTimer) clearTimeout(filterTimer);
    filterTimer = setTimeout(() => { filterTimer = null; applyFilter(); }, FILTER_DEBOUNCE_MS);
  }

  function applyFilter() {
    filter = { ip: els.ip.value.trim(), mac: els.mac.value.trim(), protos: filter.protos.slice() };
    refreshRows();
  }

  function toggleProto(key) {
    const at = filter.protos.indexOf(key);
    if (at >= 0) filter.protos.splice(at, 1);
    else filter.protos.push(key);
    renderProtos();
    applyFilter();
  }

  function clearFilters() {
    els.ip.value = '';
    els.mac.value = '';
    filter = { ip: '', mac: '', protos: [] };
    renderProtos();
    refreshRows();
  }

  /* ---- packet detail */
  async function showDetail(no) {
    if (!isNum(no)) return;
    let data;
    try {
      data = await TNT.api.capturePacket(no);
    } catch (err) {
      if (refused(err)) return;
      TNT.ui.toast('Could not read packet ' + no + ': ' + (err.message || 'unknown error'), 'warn');
      return;
    }
    if (!root) return;
    const { h } = TNT.util;
    const row = isObj(data.row) ? data.row : {};
    const tree = h('div', { class: 'cap-tree' });
    for (const layer of Array.isArray(data.layers) ? data.layers : []) {
      if (!isObj(layer)) continue;
      const fields = h('div', { class: 'cap-fields' });
      for (const f of Array.isArray(layer.fields) ? layer.fields : []) {
        if (!isObj(f)) continue;
        fields.appendChild(h('div', { class: 'cap-field' },
          h('span', { class: 'cap-field-name' }, String(f.name || '')),
          h('span', { class: 'cap-field-value mono' }, String(f.value == null ? '' : f.value))));
      }
      const open = h('details', { class: 'cap-layer', open: 'open' },
        h('summary', null, h('span', { class: 'strong' }, String(layer.name || '')),
          layer.summary ? h('span', { class: 'muted' }, String(layer.summary)) : null),
        fields);
      tree.appendChild(open);
    }
    const dump = h('pre', { class: 'cap-hex mono' }, (Array.isArray(data.hex) ? data.hex : []).join('\n'));
    const body = h('div', { class: 'cap-detail' },
      h('div', { class: 'cap-detail-head' },
        h('span', { class: 'strong' }, 'Packet ' + (row.no || no)),
        h('span', { class: 'muted' }, timeOfDay(row.ts) + ' · +' + relText(row.rel) + ' s · ' + (row.length || 0) + ' bytes')),
      tree, h('div', { class: 'cap-hex-head muted small' }, 'Bytes'), dump);
    detailModal = TNT.ui.modal({ title: (row.proto || 'Packet') + ' — ' + (row.src || '?') + ' → ' + (row.dst || '?'),
      body, wide: true, onClose: () => { detailModal = null; } });
  }

  /* ---- SIP calls */
  async function showCalls() {
    let data;
    try {
      data = await TNT.api.captureCalls();
    } catch (err) {
      if (refused(err)) return;
      TNT.ui.toast('Could not read the calls: ' + (err.message || 'unknown error'), 'error');
      return;
    }
    if (!root) return;
    const { h } = TNT.util;
    const calls = (Array.isArray(data.calls) ? data.calls : []).map(callView);
    const body = h('div', { class: 'cap-calls' });
    if (!calls.length) body.appendChild(TNT.ui.emptyState('No SIP call has been seen in this capture'));
    for (const c of calls) {
      const player = h('div', { class: 'cap-call-player' });
      const play = h('button', { class: 'btn btn-sm', type: 'button', disabled: !c.playable,
        title: c.playable ? 'Rebuild this call and play it' : c.note,
        on: { click: () => loadAudio(c, play, player) } }, TNT.ui.icon('play'), 'Listen');
      body.appendChild(h('div', { class: 'cap-call' },
        h('div', { class: 'cap-call-head' },
          h('span', { class: 'badge ' + c.cls }, c.state || 'unknown'),
          h('span', { class: 'strong cap-call-title', title: c.title }, c.title)),
        h('div', { class: 'cap-call-meta muted small' },
          (c.when ? 'Started ' + c.when : '') + (c.duration ? ' · ' + c.duration : '') + (c.note ? ' · ' + c.note : '')),
        h('div', { class: 'cap-call-actions' }, play, player)));
    }
    callsModal = TNT.ui.modal({ title: 'SIP calls', body, wide: true, onClose: () => { callsModal = null; } });
  }

  /** The call's audio, fetched as a blob so a 404 never navigates the page and the player works in the TNT window. */
  async function loadAudio(call, button, holder) {
    const { h } = TNT.util;
    TNT.ui.busy(button, true, 'Rebuilding…');
    try {
      const res = await fetch(TNT.api.captureCallAudioUrl(call.id), { credentials: 'same-origin' });
      if (!res.ok) throw new Error(res.status === 404 ? 'TNT could not rebuild this call' : 'HTTP ' + res.status);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      holder.innerHTML = '';
      const audio = h('audio', { controls: 'controls', src: url, preload: 'metadata' });
      holder.appendChild(audio);
      holder.appendChild(h('a', { class: 'btn btn-sm', href: url, download: 'TNT-call-' + call.id + '.wav' },
        TNT.ui.icon('download'), 'Save WAV'));
      button.hidden = true;
      try { audio.play(); } catch (e) { /* the user can press play */ }
    } catch (err) {
      TNT.ui.toast('Could not play this call: ' + (err.message || 'unknown error'), 'warn');
    } finally {
      TNT.ui.busy(button, false);
    }
  }

  /* ---- leaving the page with an unsaved capture */
  /** Save / Discard / Stay. Resolves true when the page may be left. */
  function askToLeave() {
    const { h } = TNT.util;
    return new Promise((resolve) => {
      let answered = false;
      const done = (v) => { if (!answered) { answered = true; resolve(v); } };
      const stay = h('button', { class: 'btn', type: 'button', on: { click: () => m.close('stay') } }, 'Stay here');
      const throwAway = h('button', { class: 'btn btn-danger', type: 'button', on: { click: () => m.close('discard') } }, 'Discard');
      const keep = h('button', { class: 'btn btn-primary', type: 'button', 'data-autofocus': '', on: { click: () => m.close('save') } }, 'Save to disk');
      const m = TNT.ui.modal({
        title: LEAVE_TITLE, body: LEAVE_TEXT, narrow: true, foot: [stay, throwAway, keep],
        onClose: async (value) => {
          if (value === 'save') { done(await save()); return; }
          if (value === 'discard') { done(await discard(true)); return; }
          done(false);
        },
      });
    });
  }

  /** While a capture is unsaved, a click on any in-app link asks first, and closing the window warns. */
  function guard() {
    const unsaved = sessionView(session()).unsaved;
    if (unsaved && !leaveGuard) {
      leaveGuard = (e) => {
        const a = e.target && e.target.closest ? e.target.closest('a[href^="#"]') : null;
        if (!a || a.getAttribute('href') === '#capture' || e.defaultPrevented || e.button !== 0) return;
        if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
        e.preventDefault();
        e.stopPropagation();
        const target = a.getAttribute('href');
        askToLeave().then((ok) => { if (ok) location.hash = target; });
      };
      document.addEventListener('click', leaveGuard, true);
      beforeUnload = (e) => { e.preventDefault(); e.returnValue = ''; return ''; };
      window.addEventListener('beforeunload', beforeUnload);
    } else if (!unsaved && leaveGuard) {
      releaseGuard();
    }
  }

  function releaseGuard() {
    if (leaveGuard) document.removeEventListener('click', leaveGuard, true);
    if (beforeUnload) window.removeEventListener('beforeunload', beforeUnload);
    leaveGuard = null;
    beforeUnload = null;
  }

  /* ---- events */
  function onState(d) {
    if (!root || admin || !isObj(d)) return;
    applySession(isObj(d.session) ? d.session : null);
    if (!d.session) { resetRows(); render(); }
  }

  function onSip(d) {
    if (!root || admin || !isObj(d) || !isObj(d.call)) return;
    const v = callView(d.call);
    if (!v.id || announced[v.id]) return;
    announced[v.id] = true;
    TNT.ui.toast('SIP call found: ' + v.title, 'info', 6000);
    renderProtos();
  }

  TNT.views.capture = {
    mount(el) {
      root = el;
      st = null; admin = false; unavailable = ''; busy = ''; loading = false; tailing = false;
      lastNo = 0; shownId = null; total = 0; matched = 0; follow = true; announced = {};
      filter = { ip: '', mac: '', protos: [] };
      build();
      render();
      load();
      unsubs.push(TNT.api.events.on('capture.state', onState));
      unsubs.push(TNT.api.events.on('capture.sip', onSip));
      unsubs.push(TNT.api.events.on('hello', () => { if (root) load(); }));
    },
    update() { /* the page reads /api/capture itself: the status snapshot carries counts only */ },
    netChanged() { if (root && !busy) load(); },
    unmount() {
      for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
      unsubs = [];
      stopTimer();
      if (filterTimer) { clearTimeout(filterTimer); filterTimer = null; }
      releaseGuard();
      if (detailModal) { try { detailModal.close(); } catch (e) { /* ignore */ } detailModal = null; }
      if (callsModal) { try { callsModal.close(); } catch (e) { /* ignore */ } callsModal = null; }
      root = null; els = {}; st = null; admin = false; unavailable = ''; busy = '';
      loading = false; tailing = false; lastNo = 0; shownId = null; total = 0; matched = 0; announced = {};
    },
    // exposed for tests
    timeOfDay, relText, protoClass, filterQuery, filterOn, sessionView, stopSuffix, clock, callView,
    PROTO_BUTTONS, COLUMNS: COLUMNS.map((c) => c.key), TAIL_MS, DOM_ROWS, WARNING_TEXT, ADMIN_TEXT, LEAVE_TITLE,
  };
})();
