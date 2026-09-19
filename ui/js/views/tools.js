/* TNT — views/tools.js
   Field tools. A Quick Tools row sits above every card: one-click tools that need no settings and no result
   pane (IP Release/Renew and Flush DNS today, more later). It is not collapsible — app.js owns the buttons'
   behaviour through TNT.app.quickRun / TNT.app.quickSync, and only their markup lives here.
   Under it the cards, mounted in one order (CARD_ORDER): LAN throughput, Port forward check, Traceroute, the
   DHCP server, the TFTP server, the Subnet calculator, DNS and the saved Wi-Fi networks. (Packet capture has
   its own page and tile now, not a card here.)
   The DHCP server is special (its own builder here): a big on/off switch, a status badge, adapter /
   pool / lease settings, a "check for other DHCP servers" probe with an inline result box, a loud
   danger modal when another server is already active, and a realtime clients table built on the shared
   host table (same columns as Discovery plus a Lease column and a forget button). Every other card's
   body comes from js/tools/*.js (create(ctx) -> { body, head, mount, update, unmount, netChanged };
   ctx.open() opens the card, which the TFTP server's switch calls when it is turned on, and the other
   modules ignore ctx).
   Every card, the DHCP server's included, is collapsible and starts collapsed: its title row opens
   and closes it (a chevron button first in the row, or a click on the title), while the controls in
   the row (the DHCP and TFTP switches, badges, a card's head element) never do and stay usable either
   way. The cards the user opened stay open for the rest of the window's life (leaving Tools and coming
   back keeps them; a reload starts collapsed again). The DHCP card opens by itself when the server is
   switched on or has a new error or warning to show, the TFTP card when its server is switched on. */
(function () {
  'use strict';
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  let root = null, unsubs = [];
  let els = {};
  let table = null;
  let extras = [];            // the mounted tool modules below the DHCP card

  // the tool cards below (all but the DHCP server, which has its own builder), in their relative order
  const EXTRA_CARDS = [
    { key: 'lan', title: 'LAN throughput', icon: 'lan', create: () => TNT.tools.lan.create() },
    { key: 'portforward', title: 'Port forward check', icon: 'target', create: (ctx) => TNT.tools.portforward.create(ctx) },
    { key: 'traceroute', title: 'Traceroute', icon: 'route', create: () => TNT.tools.traceroute.create() },
    { key: 'tftp', title: 'TFTP server', icon: 'tftp', create: (ctx) => TNT.tools.tftp.create(ctx) },
    { key: 'subnet', title: 'Subnet calculator', icon: 'network', create: () => TNT.tools.subnetcalc.create() },
    { key: 'dns', title: 'DNS', icon: 'dns', create: () => TNT.tools.dns.create() },
    { key: 'wifi', title: 'Saved Wi-Fi networks', icon: 'wifi', create: () => TNT.tools.wifi.create() },
  ];
  // the full mount order, top to bottom, the DHCP server card ('dhcp', its own builder) among the modules above
  const CARD_ORDER = ['lan', 'portforward', 'traceroute', 'dhcp', 'tftp', 'subnet', 'dns', 'wifi'];
  // the Quick Tools row above the cards: one click, no settings. app.js runs them (TNT.app.quickRun) and owns the
  // busy / flash behaviour; the ids are its (TNT.app.QUICK_TOOL_IDS), so it can find the button while the page is open.
  const QUICK_TOOLS = [
    { tool: 'renew', icon: 'renew', label: 'IP Release/Renew', title: "Release this PC's IP addresses and renew them from the DHCP server" },
    { tool: 'flush', icon: 'flush', label: 'Flush DNS', title: "Flush this PC's DNS cache" },
  ];
  // the cards the user opened ('dhcp' and the keys above): module level, so they stay open when Tools is left and
  // opened again; a reload starts with every card collapsed
  let openCards = [];
  let cardToggles = {};       // key -> { setOpen(open), isOpen() } of the mounted cards
  let attentionShown = null;  // the DHCP card's last alert (dhcpAttention): only a new one opens the card by itself
  let status = null;          // last full STATUS DICT from /api/dhcp/status
  let busy = false;           // a start / stop request is in flight
  let busyMode = '';          // 'checking' | 'starting' | 'stopping'
  let dirty = false;          // the settings inputs were edited: do not overwrite them from status
  let loading = false;
  let loadAgain = false;      // a reload was asked for while one was in flight
  let netPending = false;     // the PC changed networks during a start / stop request: reload after it
  let danger = null;          // the open "another DHCP server" modal: { networkChanged() }
  let unavailable = false;
  let tickTimer = null;
  let scanError = null;       // a start attempt failed because the pre-start scan itself failed: shown in the scan box

  const SORT_STORE = 'tnt.dhcp.sort';
  const LEASE_CLASS = { offered: 'yellow', bound: 'green', released: 'grey', expired: 'grey', declined: 'red' };
  const LEASE_RANK = { bound: 0, offered: 1, declined: 2, released: 3, expired: 4 };

  /* -------------------------------------------------------- pure helpers */
  /** Badge class, label and a short detail line ("expires in 58 min") for one lease. */
  function leaseText(lease, now) {
    const u = TNT.util;
    const st = String((lease && lease.state) || '').toLowerCase();
    const cls = LEASE_CLASS[st] || 'grey';
    let detail = '';
    if (st === 'bound') detail = lease.expires_ts ? 'expires ' + u.untilText(lease.expires_ts, now) : '';
    else if (st === 'offered') detail = lease.expires_ts ? 'offer expires ' + u.untilText(lease.expires_ts, now) : 'waiting for the device';
    else if (st === 'released') detail = lease.last_ts ? 'released ' + u.relTime(lease.last_ts, now) : '';
    else if (st === 'expired') detail = lease.expires_ts ? 'expired ' + u.relTime(lease.expires_ts, now) : '';
    else if (st === 'declined') detail = 'the device refused the address';
    return { cls, label: st || 'unknown', detail };
  }

  /** Title + [label, value] pairs describing a detected DHCP server (SERVER DICT). */
  function serverSummary(s) {
    const u = TNT.util;
    s = s || {};
    const ip = s.server_ip || s.source_ip || '?';
    const detail = [];
    if (s.source_ip && s.source_ip !== ip) detail.push(['from', s.source_ip]);
    if (s.offered_ip) detail.push(['offered us', s.offered_ip]);
    if (s.lease_s != null) detail.push(['lease', u.fmtDuration(s.lease_s)]);
    if (s.router) detail.push(['gateway', s.router]);
    if (s.mask) detail.push(['mask', s.mask]);
    if (Array.isArray(s.dns) && s.dns.length) detail.push(['dns', s.dns.join(', ')]);
    const tags = [];
    if (s.answered) tags.push('answered');
    if (s.known) tags.push('known to Windows');
    return { ip, adapter: s.adapter || '?', nic_ip: s.nic_ip || '', detail, tags };
  }

  /** Text for one entry of the adapter <select>: "Ethernet — 10.0.0.112/24 (DHCP) (internet)". */
  function adapterLabel(a) {
    a = a || {};
    const ip = a.ip ? a.ip + (a.prefix != null ? '/' + a.prefix : '') : 'no IPv4';
    return (a.name || '?') + ' — ' + ip + (a.dhcp_enabled ? ' (DHCP)' : ' (static)') + (a.is_internet === true ? ' (internet)' : '');
  }

  /* Pure: the "this is the PC's internet connection" warning for one adapter dict, or null when
     the service did not flag it (is_internet missing/false -> nothing new on screen). A DHCP-addressed
     adapter is moved to the static address with no gateway while the server runs, so the PC has no
     internet through it; a static one keeps its address, but the server still answers every device
     on the internet-facing network. */
  function internetWarning(a) {
    if (!a || a.is_internet !== true) return null;
    const name = a.name || 'This adapter';
    const address = (a.static_ip || '172.16.4.100') + '/' + (a.static_prefix != null ? a.static_prefix : 24);
    const readdressed = !!(a.will_change || a.changed);
    const text = readdressed
      ? name + " is this PC's internet connection. While the DHCP server is on, this PC has no internet through it (it is moved to " + address + ' with no gateway). Pick another adapter or plug the PC into the isolated bench network first.'
      : name + " is this PC's internet connection. While the DHCP server is on, it answers every device on that network. Pick another adapter or plug the PC into the isolated bench network first.";
    return { name, address, readdressed, text };
  }

  /** DOM for internetWarning(a): [strong name, text...] parts for infoBox / the danger modal. */
  function internetWarningParts(w) {
    const { h } = TNT.util;
    if (!w) return null;
    const rest = w.text.slice(w.name.length);
    if (!w.readdressed) return [h('strong', null, w.name), rest];
    const i = rest.indexOf(w.address);
    return [h('strong', null, w.name), rest.slice(0, i), h('code', null, w.address), rest.slice(i + w.address.length)];
  }

  /** Pure: the open card keys after opening (`open` true) or closing the card `key`; the list is never changed in place. */
  function withCardOpen(list, key, open) {
    const out = (list || []).filter((k) => k !== key);
    if (open) out.push(key);
    return out;
  }

  /* Pure: the alert that opens the DHCP card by itself, as a key ("scan:…", "error:…", "firewall:…", "warning:…"), or null:
     a pre-start scan that failed, an error, a firewall rule that could not be added, a warning the red scan box does not
     already show. Not the red "internet connection" box (it is there whenever the picked adapter carries the internet,
     server on or off), nor a finished scan's list of other servers (the user asked for that one). */
  function dhcpAttention(st, scanErr) {
    if (scanErr) return 'scan:' + scanErr;
    if (!st || st.available === false) return null;
    if (st.error) return 'error:' + st.error;
    const fw = st.firewall || {};
    if (fw.ok === false) return 'firewall:' + (fw.error || fw.rule || '');
    const conflictShown = !!(st.scan && (st.scan.servers || []).length) && /^another dhcp server is active/i.test(st.warning || '');
    return st.warning && !conflictShown ? 'warning:' + st.warning : null;
  }

  /* ------------------------------------------------- collapsible cards */
  /** Makes a card open and close: a chevron button (aria-expanded / aria-controls) goes first in its title row and a click
   *  anywhere in the row shows or hides `body`, except on a control there (`controls`: the DHCP switch and badge, a card's
   *  head element; any button, link, field, label or badge), which never does and stays usable while the card is closed. */
  function makeCollapsible(card, row, body, key, title, controls) {
    const { h } = TNT.util;
    body.id = 'tool-body-' + key;
    const btn = h('button', { class: 'card-toggle', type: 'button', 'aria-expanded': 'false', 'aria-controls': body.id, 'aria-label': title }, TNT.ui.icon('chevron'));
    row.insertBefore(btn, row.firstChild);
    row.classList.add('card-head');
    const setOpen = (open) => {
      body.hidden = !open;
      btn.setAttribute('aria-expanded', String(!!open));
      btn.title = (open ? 'Hide ' : 'Show ') + title;
      card.classList.toggle('collapsed', !open);
      openCards = withCardOpen(openCards, key, !!open);
    };
    row.addEventListener('click', (e) => {
      const t = e.target;
      if (!(t instanceof Element) || (controls || []).some((c) => c && c.contains(t))) return;
      const hit = t.closest('button, a, input, select, textarea, label, .badge');
      if (hit && hit !== btn) return;
      setOpen(body.hidden);
    });
    setOpen(openCards.includes(key));
    cardToggles[key] = { setOpen, isOpen: () => !body.hidden };
  }

  /** Opens a mounted card (the DHCP card when the server is switched on or has something new to show, a tool card through the
   *  ctx.open() its create got). */
  function openCard(key) {
    const c = cardToggles[key];
    if (c && !c.isOpen()) c.setOpen(true);
  }

  /** Opens the DHCP card for an alert it has not shown yet; the same alert again leaves a card the user closed shut. */
  function checkAttention() {
    const att = dhcpAttention(status, scanError);
    if (att && att !== attentionShown) openCard('dhcp');
    attentionShown = att;
  }

  /* --------------------------------------------------------- rendering */
  const dash = () => TNT.util.h('span', { class: 'muted' }, '—');
  const probingEl = () => TNT.util.h('span', { class: 'probing' }, TNT.util.h('span', { class: 'spark-icon' }, TNT.ui.icon('spark')), 'checking…');
  const rttOrProbe = (col) => (l) => {
    const { h } = TNT.util;
    if (l.probing) return h('td', { class: col.key === 'rtt' ? 'num' : 'ports' }, probingEl());
    if (l.probed_ts == null) return h('td', { class: col.key === 'rtt' ? 'num' : 'ports' }, dash());
    return TNT.hosttable.defaultCell({ key: col.key }, l);
  };

  function leaseCell(l) {
    const { h } = TNT.util;
    const t = leaseText(l, TNT.state && TNT.state.now);
    return h('td', { class: 'lease-cell' }, h('div', { class: 'lease-wrap' },
      h('span', { class: 'badge ' + t.cls }, t.label),
      t.detail ? h('span', { class: 'lease-sub', data: { mac: l.mac || '' } }, t.detail) : null));
  }

  function actionsCell(l) {
    const { h } = TNT.util;
    const btn = h('button', { class: 'btn btn-round-sm btn-forget', type: 'button', title: 'Forget this lease', 'aria-label': 'Forget the lease for ' + (l.ip || l.mac) }, TNT.ui.icon('trash'));
    btn.addEventListener('click', (e) => { e.stopPropagation(); forget(l); });
    return h('td', { class: 'actions' }, btn);
  }

  const COLUMNS = [
    { key: 'ip', label: 'IP' },
    { key: 'hostname', label: 'Hostname' },
    { key: 'mac', label: 'MAC' },
    { key: 'vendor', label: 'Vendor' },
    { key: 'rtt', label: 'Ping', cls: 'num', cell: rttOrProbe({ key: 'rtt' }) },
    { key: 'ports', label: 'Open ports', cell: rttOrProbe({ key: 'ports' }) },
    { key: 'lease', label: 'Lease', kind: 'custom', numeric: true, cell: leaseCell,
      sortValue: (l) => [!l.state, (l.state in LEASE_RANK) ? LEASE_RANK[l.state] : 9, l.expires_ts || 0],
      csv: [{ header: 'state', value: (l) => l.state || '' }, { header: 'expires_ts', value: (l) => l.expires_ts || '' }] },
    { key: 'actions', label: '', srLabel: 'Actions', sortable: false, cls: 'actions', cell: actionsCell },
  ];

  function setUnavailable(v) {
    unavailable = v;
    if (!els.card) return;
    els.card.hidden = v;
    els.unavailable.hidden = !v;
  }

  function badgeState() {
    if (busy) return { cls: 'yellow pulse', text: busyMode === 'checking' ? 'Checking for other DHCP servers…' : busyMode === 'stopping' ? 'Stopping…' : 'Starting…' };
    if (!status) return { cls: 'grey', text: 'loading' };
    if (status.error) return { cls: 'red', text: 'error' };
    if (status.running) return { cls: 'green', text: 'on' };
    return { cls: 'grey', text: 'off' };
  }

  function renderBadge() {
    if (!els.badge) return;
    const b = badgeState();
    els.badge.className = 'badge ' + b.cls;
    els.badge.textContent = b.text;
    els.badge.title = status && status.error ? status.error : '';
  }

  function renderToggle() {
    if (!els.toggle) return;
    // while a request runs the switch shows the state the user asked for
    const on = busy ? busyMode !== 'stopping' : !!(status && status.running);
    els.toggle.setChecked(on);
    els.toggle.classList.toggle('busy', busy);
    els.toggle.input.disabled = busy || unavailable;
  }

  function setInputsDisabled(v) {
    for (const k of ['adapter', 'poolStart', 'poolEnd', 'lease']) if (els[k]) els[k].disabled = v;
    if (els.applyBtn) els.applyBtn.disabled = v;
    if (els.scanBtn && !els.scanBtn.dataset.busy) els.scanBtn.disabled = v;
  }

  function renderSummary() {
    const { h, copyCode, fmtDuration, relTime } = TNT.util;
    const el = els.summary;
    if (!el) return;
    el.innerHTML = '';
    if (!status) return;
    const a = status.adapter;
    const pool = status.pool || {};
    if (!a) { el.appendChild(h('span', null, 'No usable network adapter was found — plug in a cable and reload.')); return; }
    el.appendChild(h('span', null, status.running ? 'Serving' : 'Would serve'));
    el.appendChild(copyCode((pool.start || '?') + ' – ' + (pool.end || '?')));
    el.appendChild(h('span', null, '(' + (pool.size != null ? pool.size : '?') + (pool.auto ? ' auto' : '') + ')'));
    el.appendChild(h('span', null, 'from'));
    el.appendChild(copyCode(status.server_ip || '?'));
    el.appendChild(h('span', null, 'on'));
    el.appendChild(h('span', { class: 'strong', style: { color: 'var(--ink)' } }, a.name));
    el.appendChild(h('span', null, '· lease ' + fmtDuration(status.lease_s)));
    if (status.running && status.since_ts) el.appendChild(h('span', null, '· on ' + relTime(status.since_ts, TNT.state && TNT.state.now)));
  }

  /** The adapter picker's entries from the last status with `wanted` selected; an adapter that is not
   *  there right now stays listed as "not connected" instead of silently turning into Auto. */
  function renderAdapterOptions(wanted) {
    const { h } = TNT.util;
    els.adapter.innerHTML = '';
    // Auto names the adapter the service picks right now (Wi-Fi once no Ethernet is up); status.adapter is that
    // pick only while the settings name no adapter
    const auto = !(status.settings && status.settings.adapter) && status.adapter && status.adapter.name;
    els.adapter.appendChild(h('option', { value: '' }, 'Auto (' + (auto || 'Ethernet') + ')'));
    for (const a of status.adapters || []) els.adapter.appendChild(h('option', { value: a.name }, adapterLabel(a)));
    if (wanted && !Array.from(els.adapter.options).some((o) => o.value === wanted)) els.adapter.appendChild(h('option', { value: wanted }, wanted + ' — not connected'));
    els.adapter.value = wanted || '';
  }

  function renderSettings() {
    if (!els.adapter || !status) return;
    const s = status.settings || {};
    // edited inputs stay as typed, but the adapter labels follow the network (addresses, the internet flag)
    if (dirty) { renderAdapterOptions(els.adapter.value); return; }
    renderAdapterOptions(s.adapter || '');
    const pool = status.pool || {};
    els.poolStart.placeholder = pool.auto && pool.start ? pool.start : 'auto';
    els.poolEnd.placeholder = pool.auto && pool.end ? pool.end : 'auto';
    els.poolStart.value = s.pool_start || '';
    els.poolEnd.value = s.pool_end || '';
    els.lease.value = String(Math.max(2, Math.round((s.lease_s || status.lease_s || 3600) / 60)));
  }

  function infoBox(el, kind, parts) {
    el.className = 'dhcp-info' + (kind ? ' ' + kind : '');
    el.innerHTML = '';
    el.appendChild(TNT.ui.icon(/\b(bad|warn)\b/.test(kind || '') ? 'warning' : 'info'));
    const span = TNT.util.h('span');
    for (const p of parts) span.appendChild(p instanceof Node ? p : document.createTextNode(String(p)));
    el.appendChild(span);
    el.hidden = false;
  }

  function renderInfo() {
    const { h } = TNT.util;
    if (!els.info || !status) return;
    const a = status.adapter;
    const parts = [];
    if (a && a.changed) {
      parts.push(h('strong', null, a.name), ' is on static ', h('code', null, a.static_ip + '/' + a.static_prefix), ' while the server runs; it goes back to DHCP when you turn the server off. ');
    } else if (a && a.will_change) {
      parts.push('While on, ', h('strong', null, a.name), ' (currently DHCP) is switched to static ', h('code', null, (a.static_ip || '172.16.4.100') + '/' + (a.static_prefix != null ? a.static_prefix : 24)), ' and put back to DHCP when the server is turned off. ');
    }
    parts.push('Devices get this PC (', h('code', null, status.server_ip || status.gateway || '?'), ') as their gateway and no DNS servers.');
    infoBox(els.info, '', parts);
    // loud red box when the chosen adapter is the PC's own internet connection (F12)
    const inet = internetWarning(a);
    if (inet) infoBox(els.inet, 'bad loud', internetWarningParts(inet)); else els.inet.hidden = true;
    const fw = status.firewall || {};
    // The "another DHCP server is active" warning is already the red scan box above (with the
    // servers listed): showing it again in yellow just says the same thing twice.
    const scanShowsConflict = !!(status.scan && (status.scan.servers || []).length);
    const dupWarning = scanShowsConflict && /^another dhcp server is active/i.test(status.warning || '');
    if (fw.ok === false) infoBox(els.fw, 'warn', ['Firewall rule "', fw.rule || 'TNT DHCP server', '" could not be added', fw.error ? ': ' + fw.error : '', '. Devices may not reach the server until UDP port 67 is allowed in.']);
    else if (status.warning && !dupWarning) infoBox(els.fw, 'warn', [status.warning]);
    else els.fw.hidden = true;
    if (status.error) infoBox(els.err, 'bad', [status.error]); else els.err.hidden = true;
  }

  function serverList(servers) {
    const { h, copyCode } = TNT.util;
    const ul = h('ul', { class: 'server-list' });
    for (const s of servers || []) {
      const v = serverSummary(s);
      const li = h('li', { class: 'server-item' });
      const head = h('div', { class: 'server-ip' }, TNT.ui.icon('router'), copyCode(v.ip), h('span', { class: 'muted small' }, 'on ' + v.adapter + (v.nic_ip ? ' (' + v.nic_ip + ')' : '')));
      for (const t of v.tags) head.appendChild(h('span', { class: 'badge ' + (t === 'answered' ? 'red' : 'grey') }, t));
      li.appendChild(head);
      if (v.detail.length) li.appendChild(h('div', { class: 'server-detail' }, v.detail.map(([k, val]) => h('span', null, k + ' ', h('b', null, val)))));
      ul.appendChild(li);
    }
    return ul;
  }

  /* The pre-start scan itself failed (HTTP 500 "could not check ..."): red box in place of a result.
     It stays until the next scan / start attempt or a dhcp.scan event replaces it. */
  function renderScanError(message) {
    const { h } = TNT.util;
    const box = els.scanBox;
    scanError = message || null;
    if (!box || !scanError) return;
    box.innerHTML = '';
    box.className = 'scan-box bad';
    box.appendChild(h('div', { class: 'scan-head' }, TNT.ui.icon('warning'), 'Could not check for other DHCP servers'));
    box.appendChild(h('div', { class: 'scan-meta' }, scanError, ' · The DHCP server was not started.'));
    box.hidden = false;
    checkAttention();
  }

  function renderScan(scan) {
    const { h, relTime } = TNT.util;
    const box = els.scanBox;
    if (!box) return;
    if (scanError) { renderScanError(scanError); return; }
    if (!scan) { box.hidden = true; return; }
    box.innerHTML = '';
    const servers = scan.servers || [];
    const probed = (scan.probed || []).map((p) => p.adapter).filter(Boolean);
    box.className = 'scan-box ' + (servers.length ? 'bad' : 'ok');
    if (servers.length) {
      box.appendChild(h('div', { class: 'scan-head' }, TNT.ui.icon('warning'), servers.length === 1 ? 'Another DHCP server is active' : servers.length + ' other DHCP servers are active'));
      box.appendChild(serverList(servers));
    } else {
      box.appendChild(h('div', { class: 'scan-head' }, TNT.ui.icon('check'), 'No other DHCP server answered on ' + (probed.length ? probed.join(', ') : 'any adapter')));
    }
    const meta = [];
    if (scan.wait_s != null) meta.push('waited ' + scan.wait_s + ' s');
    if (scan.ts) meta.push(relTime(scan.ts, TNT.state && TNT.state.now));
    if (probed.length && servers.length) meta.push('probed ' + probed.join(', '));
    for (const e of scan.errors || []) meta.push(String(e));
    if (meta.length) box.appendChild(h('div', { class: 'scan-meta' }, meta.join(' · ')));
    box.hidden = false;
  }

  function renderClients() {
    const { h } = TNT.util;
    if (!table || !status) return;
    const clients = status.clients || [];
    table.render(clients, 'No clients yet — devices that ask for an address appear here');
    els.clientsTitle.textContent = 'Clients' + (clients.length ? ' — ' + clients.length : '');
    els.counts.innerHTML = '';
    const c = status.counts || {};
    const bound = c.bound != null ? c.bound : clients.filter((l) => l.state === 'bound').length;
    const offered = c.offered != null ? c.offered : clients.filter((l) => l.state === 'offered').length;
    if (bound) els.counts.appendChild(h('span', { class: 'badge green' }, bound + ' bound'));
    if (offered) els.counts.appendChild(h('span', { class: 'badge yellow' }, offered + ' offered'));
  }

  function refreshCountdowns() {
    if (!table || !status) return;
    const byMac = {};
    for (const l of status.clients || []) if (l.mac) byMac[l.mac] = l;
    const now = TNT.state && TNT.state.now;
    for (const el of table.tbody.querySelectorAll('.lease-sub[data-mac]')) {
      const l = byMac[el.dataset.mac];
      if (!l) continue;
      const t = leaseText(l, now).detail;
      if (el.textContent !== t) el.textContent = t;
    }
    renderSummary();
  }

  function applyStatus(st) {
    status = st;
    if (!root) return;
    if (!st || st.available === false) { setUnavailable(true); renderToggle(); return; }
    setUnavailable(false);
    renderBadge();
    renderToggle();
    renderSummary();
    renderSettings();
    renderInfo();
    renderScan(st.scan);
    renderClients();
    setInputsDisabled(busy);
    checkAttention();
  }

  /* ------------------------------------------------------------ actions */
  async function loadStatus() {
    if (loading) { loadAgain = true; return; }
    loading = true;
    try {
      const st = await TNT.api.dhcpStatus();
      if (!root) return;
      applyStatus(st);
    } catch (err) {
      if (!root) return;
      if (err.status === 503 || err.status === 404) setUnavailable(true);
      else TNT.ui.toast('Could not read the DHCP server status: ' + err.message, 'error');
    } finally {
      loading = false;
      if (loadAgain && root) { loadAgain = false; loadStatus(); }
    }
  }

  function setBusy(v, mode) {
    busy = v;
    busyMode = v ? (mode || '') : '';
    renderBadge();
    renderToggle();
    setInputsDisabled(v);
    // the network changed while a start / stop ran: read the adapters again once its answer is applied
    if (!v && netPending && root) { netPending = false; setTimeout(() => { if (root) loadStatus(); }, 0); }
  }

  async function turnOn(force) {
    if (busy || !root) return;
    setBusy(true, force ? 'starting' : 'checking');
    scanError = null;
    try {
      const st = await TNT.api.dhcpStart(force);
      if (!root) return;
      setBusy(false);
      applyStatus(st);
      if (st && st.running) TNT.ui.toast('DHCP server is on — serving ' + ((st.pool && st.pool.start) || '') + ' – ' + ((st.pool && st.pool.end) || ''), 'ok', 4000);
      else TNT.ui.toast('The DHCP server did not start' + (st && st.error ? ': ' + st.error : ''), 'warn', 5000);
      if (st && st.warning) TNT.ui.toast(st.warning, 'warn', 6000);
    } catch (err) {
      if (!root) return;
      setBusy(false);
      if (status) status.running = false;
      renderBadge(); renderToggle();
      const body = err.body || {};
      if (err.status === 409 && (err.code === 'dhcp_server_present' || Array.isArray(body.servers))) {
        if (status && body.scan) { status.scan = body.scan; renderScan(body.scan); }
        openDanger(body.servers || [], body.scan);
        return;
      }
      // the service could not run the pre-start scan (a socket / adapter error): that reason
      // belongs in the scan box as well, where the tech looks for the check's result
      if (err.status === 500 && /^could not check/i.test(String(err.message || ''))) renderScanError(err.message);
      TNT.ui.toast('Could not start the DHCP server: ' + err.message, 'error');
      loadStatus();
    }
  }

  async function turnOff() {
    if (busy || !root) return;
    setBusy(true, 'stopping');
    try {
      const st = await TNT.api.dhcpStop();
      if (!root) return;
      setBusy(false);
      applyStatus(st);
      TNT.ui.toast('DHCP server is off' + (st && st.adapter && !st.adapter.changed && st.adapter.will_change ? ' — ' + st.adapter.name + ' is back on DHCP' : ''), 'ok');
    } catch (err) {
      if (!root) return;
      setBusy(false);
      TNT.ui.toast('Could not stop the DHCP server: ' + err.message, 'error');
      loadStatus();
    }
  }

  /** "Checked: Ethernet (10.0.0.112, internet), ..." — adapters the scan probed, internet NICs marked. */
  function checkedText(probed) {
    const inet = new Set(((status && status.adapters) || []).filter((a) => a.is_internet === true).map((a) => a.name));
    return 'Checked: ' + probed.map((p) => p.adapter + ' (' + [p.ip, inet.has(p.adapter) ? 'internet' : ''].filter(Boolean).join(', ') + ')').join(', ');
  }

  function openDanger(servers, scan) {
    const { h } = TNT.util;
    const n = (servers || []).length;
    const probed = scan && Array.isArray(scan.probed) ? scan.probed : [];
    const inet = internetWarning(status && status.adapter);
    const body = h('div', { class: 'stack', style: { gap: '16px' } },
      h('div', { class: 'hazard-tape', 'aria-hidden': 'true' }),
      h('p', { class: 'big-text' }, n === 1 ? 'A DHCP server is already handing out addresses on this network:' : n + ' DHCP servers are already handing out addresses on this network:'),
      serverList(servers),
      h('p', null, 'Two DHCP servers on one network both answer every device that asks for an address. Devices end up with addresses from whichever server answers first, get different gateways and subnets, and some will stop working or end up sharing the same address with another device. Phones, printers and cameras on this network can all break at once.'),
      h('p', { class: 'muted' }, 'Only proceed if that server is being replaced, or this PC is on an isolated cable or switch. Otherwise turn the other server off first and try again.'),
      probed.length ? h('p', { class: 'muted small' }, checkedText(probed)) : null);
    if (inet) {
      const box = h('div', { class: 'dhcp-info bad loud', style: { marginTop: '0' } });
      infoBox(box, 'bad loud', internetWarningParts(inet));
      body.appendChild(box);
    }
    // "Proceed anyway" skips the check, so it must never apply to a network nobody checked
    const moved = h('div', { class: 'dhcp-info warn', hidden: true, role: 'alert', style: { marginTop: '0' } }, TNT.ui.icon('warning'),
      h('span', null, 'This PC changed networks while this was open, so the check above is out of date. Cancel and check again.'));
    body.appendChild(moved);
    const cancel = h('button', { class: 'btn', type: 'button' }, TNT.ui.icon('back'), 'Cancel');
    const proceed = h('button', { class: 'btn btn-danger', type: 'button' }, TNT.ui.icon('warning'), 'Proceed anyway');
    let go = false;
    const ctl = { networkChanged() { proceed.disabled = true; moved.hidden = false; } };
    danger = ctl;
    const m = TNT.ui.modal({ title: 'Another DHCP server is already active', body, foot: [cancel, proceed],
      onClose: () => { if (danger === ctl) danger = null; if (go) turnOn(true); else { renderBadge(); renderToggle(); } } });
    m.el.classList.add('danger');
    const h2 = m.el.querySelector('.modal-head h2');
    if (h2) h2.insertBefore(TNT.ui.icon('warning'), h2.firstChild);
    cancel.addEventListener('click', () => m.close(false));
    proceed.addEventListener('click', () => { go = true; m.close(true); });
    // Cancel is the safe default: it gets the focus, not the red button
    setTimeout(() => { try { cancel.focus(); } catch (e) { /* ignore */ } }, 30);
  }

  async function scan() {
    if (!root) return;
    const { h } = TNT.util;
    TNT.ui.busy(els.scanBtn, true, 'Checking…');
    scanError = null;
    els.scanBox.className = 'scan-box';
    els.scanBox.innerHTML = '';
    els.scanBox.appendChild(h('div', { class: 'scan-head' }, h('span', { class: 'spark-icon' }, TNT.ui.icon('spark')), 'Asking every network adapter for DHCP servers… this takes a few seconds.'));
    els.scanBox.hidden = false;
    try {
      const r = await TNT.api.dhcpScan();
      if (!root) return;
      if (status) status.scan = r;
      renderScan(r);
      const n = (r && r.servers || []).length;
      TNT.ui.toast(n ? n + ' other DHCP server' + (n === 1 ? '' : 's') + ' found' : 'No other DHCP server answered', n ? 'warn' : 'ok');
    } catch (err) {
      if (!root) return;
      renderScan(status && status.scan);
      TNT.ui.toast('Could not check for DHCP servers: ' + err.message, 'error');
    } finally { if (root) TNT.ui.busy(els.scanBtn, false); }
  }

  async function applySettings() {
    if (!root) return;
    const patch = { adapter: els.adapter.value || '', pool_start: (els.poolStart.value || '').trim(), pool_end: (els.poolEnd.value || '').trim() };
    if (!!patch.pool_start !== !!patch.pool_end) { TNT.ui.toast('Give both a pool start and a pool end, or clear both for automatic', 'warn'); (patch.pool_start ? els.poolEnd : els.poolStart).focus(); return; }
    const ip4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
    for (const k of ['pool_start', 'pool_end']) if (patch[k] && !ip4.test(patch[k])) { TNT.ui.toast('"' + patch[k] + '" is not an IPv4 address', 'warn'); els[k === 'pool_start' ? 'poolStart' : 'poolEnd'].focus(); return; }
    const mins = parseInt(els.lease.value, 10);
    if (!isFinite(mins) || mins < 2 || mins > 10080) { TNT.ui.toast('Lease must be between 2 minutes and 7 days (10080 min)', 'warn'); els.lease.focus(); return; }
    patch.lease_s = mins * 60;
    TNT.ui.busy(els.applyBtn, true, 'Saving…');
    try {
      const st = await TNT.api.dhcpSettings(patch);
      if (!root) return;
      dirty = false;
      applyStatus(st);
      TNT.ui.toast('DHCP settings saved' + (st && st.running ? ' and applied' : ''), 'ok');
    } catch (err) {
      if (!root) return;
      TNT.ui.toast(err.message || 'Could not save the DHCP settings', 'error');
    } finally { if (root) TNT.ui.busy(els.applyBtn, false); }
  }

  async function forget(l) {
    const who = l.hostname || l.ip || l.mac;
    const ok = await TNT.ui.confirm({ title: 'Forget ' + who + '?', message: 'The lease for ' + (l.mac || l.ip) + ' is dropped and ' + (l.ip || 'its address') + ' becomes free again. The device keeps its address until it asks for a renewal.', ok: 'Forget', danger: true });
    if (!ok || !root) return;
    try {
      await TNT.api.dhcpForget(l.mac);
    } catch (err) {
      if (!root) return;
      if (err.status !== 404) { TNT.ui.toast('Could not forget the lease: ' + err.message, 'error'); return; }
    }
    if (status) { status.clients = (status.clients || []).filter((x) => x.mac !== l.mac); renderClients(); }
    TNT.ui.toast('Forgot ' + who, 'ok');
    loadStatus();
  }

  /* Pure: one dhcp.lease event applied to a client list. The server sends a stub
     { mac, state: 'forgotten' } after DELETE /api/dhcp/leases/{mac}: that removes the row
     instead of replacing it (a second tab, or the event racing our own delete). */
  function applyLease(list, lease) {
    const out = (list || []).slice();
    if (!lease) return out;
    const i = out.findIndex((x) => (lease.mac && x.mac === lease.mac) || (!lease.mac && lease.ip && x.ip === lease.ip));
    if (lease.state === 'forgotten') { if (i >= 0) out.splice(i, 1); return out; }
    if (i >= 0) out[i] = lease; else out.push(lease);
    return out;
  }

  function mergeLease(lease) {
    if (!status || !lease) return;
    const list = status.clients = applyLease(status.clients, lease);
    status.counts = { bound: list.filter((l) => l.state === 'bound').length, offered: list.filter((l) => l.state === 'offered').length, total: list.length };
    renderClients();
  }

  /* --------------------------------------------------------------- view */
  function buildDhcpCard() {
    const { h } = TNT.util;
    els.badge = h('span', { class: 'badge grey' }, 'loading');
    // switching the server on opens its card (the summary, the check for other servers and the clients are what to watch)
    // the same size switch as the TFTP server's (and every other card's controls), not a bespoke large one
    els.toggle = TNT.ui.toggle({ checked: false, on: 'On', off: 'Off', accent: 'var(--green)', onChange: (checked) => { if (checked) { openCard('dhcp'); turnOn(false); } else turnOff(); } });
    els.toggle.input.setAttribute('aria-label', 'DHCP server on or off');
    // the badge and the switch ride together on the right of the row, as the TFTP server's do (.tool-head-right)
    els.head = h('div', { class: 'tool-head-right' }, els.badge, els.toggle);
    const titleRow = h('div', { class: 'switch-row' },
      h('div', { class: 'card-title' }, TNT.ui.icon('dhcp'), 'DHCP server'), els.head);
    els.summary = h('div', { class: 'dhcp-summary' });

    els.adapter = h('select', { class: 'input', 'aria-label': 'Adapter' }, h('option', { value: '' }, 'Auto (Ethernet)'));
    els.poolStart = h('input', { class: 'input', type: 'text', placeholder: 'auto', 'aria-label': 'Pool start', spellcheck: 'false', autocomplete: 'off' });
    els.poolEnd = h('input', { class: 'input', type: 'text', placeholder: 'auto', 'aria-label': 'Pool end', spellcheck: 'false', autocomplete: 'off' });
    els.lease = h('input', { class: 'input', type: 'number', min: '2', max: '10080', step: '1', value: '60', 'aria-label': 'Lease in minutes' });
    for (const k of ['adapter', 'poolStart', 'poolEnd', 'lease']) {
      els[k].addEventListener('input', () => { dirty = true; });
      els[k].addEventListener('change', () => { dirty = true; });
      els[k].addEventListener('keydown', (e) => { if (e.key === 'Enter') applySettings(); });
    }
    els.applyBtn = h('button', { class: 'btn', type: 'button', on: { click: applySettings }, title: 'Save the adapter, pool and lease settings (applied live while the server runs)' }, TNT.ui.icon('check'), 'Apply');
    els.scanBtn = h('button', { class: 'btn', type: 'button', on: { click: scan }, title: 'Send a DHCP probe on every adapter and list the servers that answer' }, TNT.ui.icon('search'), 'Check for other DHCP servers');
    const form = h('div', { class: 'form-row dhcp-settings' },
      h('div', { class: 'field wide' }, h('label', null, 'Adapter'), els.adapter),
      h('div', { class: 'field' }, h('label', null, 'Pool start'), els.poolStart),
      h('div', { class: 'field' }, h('label', null, 'Pool end'), els.poolEnd),
      h('div', { class: 'field', style: { flex: '0 1 130px' } }, h('label', null, 'Lease (min)'), els.lease),
      els.applyBtn, els.scanBtn);
    els.scanBox = h('div', { class: 'scan-box', hidden: true, role: 'status', 'aria-live': 'polite' });
    els.inet = h('div', { class: 'dhcp-info bad loud', hidden: true, role: 'alert' });
    els.info = h('div', { class: 'dhcp-info', hidden: true });
    els.fw = h('div', { class: 'dhcp-info warn', hidden: true });
    els.err = h('div', { class: 'dhcp-info bad', hidden: true });

    table = TNT.hosttable.create({ columns: COLUMNS, storeKey: SORT_STORE, onSort: () => renderClients() });
    els.clientsTitle = h('span', null, 'Clients');
    els.counts = h('span', { class: 'row', style: { gap: '6px' } });
    els.refreshBtn = h('button', { class: 'btn btn-sm', type: 'button', title: 'Reload the client list', on: { click: () => loadStatus() } }, TNT.ui.icon('refresh'), 'Refresh');
    const tableWrap = h('div', { class: 'table-wrap' }, h('table', { class: 'table dhcp-table' }, table.thead, table.tbody));

    const body = h('div', { class: 'dhcp-body' }, els.summary, form, els.scanBox, els.inet, els.info, els.fw, els.err,
      h('hr', { class: 'divider', style: { margin: '18px 0 14px' } }),
      h('div', { class: 'card-title' }, els.clientsTitle, els.counts, h('span', { class: 'spacer' }), els.refreshBtn),
      tableWrap);
    els.card = h('div', { class: 'card', data: { tool: 'dhcp' } }, titleRow, body);
    makeCollapsible(els.card, titleRow, body, 'dhcp', 'DHCP server', [els.head]);
    els.unavailable = h('div', { class: 'card', hidden: true }, TNT.ui.emptyState('The DHCP server is not available on this service'));
  }

  /** The tool cards in CARD_ORDER: the DHCP server card (its own builder, els.card + els.unavailable) where the key is
   *  'dhcp', and one collapsible `.card` per EXTRA_CARDS module elsewhere — icon + title (+ the module's head element, e.g.
   *  a badge) over its body. Every module's create gets { open } to open its own card (the TFTP server's switch does, as
   *  the DHCP server's does). Returns the ordered card elements and fills `extras` with the mounted modules. */
  function buildCards() {
    const { h } = TNT.util;
    const byKey = {};
    for (const c of EXTRA_CARDS) byKey[c.key] = c;
    const cards = [];
    extras = [];
    for (const key of CARD_ORDER) {
      if (key === 'dhcp') { cards.push(els.card, els.unavailable); continue; }
      const c = byKey[key];
      let mod;
      try { mod = c.create({ open: () => openCard(c.key) }); }
      catch (e) { console.error('tool card failed', c.key, e); mod = { body: TNT.ui.emptyState('This tool failed to load. See the console.'), head: null }; }
      const title = h('div', { class: 'card-title' }, TNT.ui.icon(c.icon), c.title, mod.head || null);
      const card = h('div', { class: 'card tool-card', data: { tool: c.key } }, title, mod.body);
      makeCollapsible(card, title, mod.body, c.key, c.title, [mod.head]);
      cards.push(card);
      extras.push(mod);
    }
    return cards;
  }

  /** The Quick Tools row: a plain (never collapsible) card of one-click buttons above the tool cards. Each button
   *  carries the id app.js looks for, so a run started here keeps working while the page is open. */
  function buildQuickTools() {
    const { h } = TNT.util;
    const ids = (TNT.app && TNT.app.QUICK_TOOL_IDS) || {};
    const row = h('div', { class: 'quick-tools' });
    for (const q of QUICK_TOOLS) {
      row.appendChild(h('button', {
        class: 'btn quick-tool', type: 'button', id: ids[q.tool] || ('btn-quick-' + q.tool), title: q.title, 'aria-label': q.label,
        on: { click: () => { if (TNT.app && TNT.app.quickRun) TNT.app.quickRun(q.tool); } },
      }, TNT.ui.icon(q.icon), h('span', { class: 'quick-label' }, q.label)));
    }
    const title = h('div', { class: 'card-title' }, TNT.ui.icon('spark'), 'Quick Tools');
    return h('div', { class: 'card', data: { tool: 'quick' } }, title, row);
  }

  TNT.views.tools = {
    mount(el) {
      const { h } = TNT.util;
      root = el;
      els = {};
      status = null; busy = false; busyMode = ''; dirty = false; loading = false; loadAgain = false; netPending = false; danger = null;
      unavailable = false; scanError = null;
      cardToggles = {}; attentionShown = null;
      openCards = [];     // every time the Tools page opens, all cards start collapsed (a running DHCP alert still opens its card)
      const head = h('div', { class: 'section-head' }, h('h2', null, h('span', { class: 'section-accent' }), 'Tools'));
      buildDhcpCard();
      const cards = buildCards();
      root.appendChild(head);
      root.appendChild(h('div', { class: 'stack' }, buildQuickTools(), ...cards));
      if (TNT.app && TNT.app.quickSync) TNT.app.quickSync();
      TNT.hosttable.syncTargets(TNT.state && TNT.state.targets, true);
      renderBadge();
      renderToggle();
      table.render([], 'No clients yet — devices that ask for an address appear here');
      loadStatus();
      for (const m of extras) { try { if (m.mount) m.mount(); } catch (e) { console.error('tool mount failed', e); } }
      TNT.hosttable.loadTargets();
      unsubs.push(TNT.api.events.on('dhcp.state', (d) => {
        if (!root || !d) return;
        if (!status) { loadStatus(); return; }
        if (busy) return;
        if (!!d.running !== !!status.running || (d.error || null) !== (status.error || null)) loadStatus();
        else { if (d.since_ts !== undefined) status.since_ts = d.since_ts; renderBadge(); renderSummary(); }
      }));
      unsubs.push(TNT.api.events.on('dhcp.lease', (d) => { if (root && d && d.lease) mergeLease(d.lease); }));
      unsubs.push(TNT.api.events.on('dhcp.scan', (d) => { if (!root || !d) return; scanError = null; if (status) status.scan = d; if (!els.scanBtn.dataset.busy) renderScan(d); }));
      unsubs.push(TNT.api.events.on('hello', () => { if (root) loadStatus(); }));
      tickTimer = setInterval(() => { if (root) refreshCountdowns(); }, 10000);
    },
    /* This PC changed networks: the DHCP card's adapters, addresses and internet flag (after a start or
       stop still in flight), an open danger modal, and every tool card below it. */
    netChanged(info, state) {
      if (!root) return;
      for (const m of extras) { try { if (m.netChanged) m.netChanged(info, state); } catch (e) { console.error('tool netChanged failed', e); } }
      if (danger) danger.networkChanged();
      if (busy) { netPending = true; return; }
      loadStatus();
    },
    update(state) {
      if (!root) return;
      for (const m of extras) { try { if (m.update) m.update(state); } catch (e) { console.error('tool update failed', e); } }
      TNT.hosttable.syncTargets(state && state.targets);
      if (!state || !state.status) return;
      const d = state.status.dhcp;
      if (d === null || d === undefined) { if (status === null && !loading) setUnavailable(true); return; }
      if (d.available === false) { setUnavailable(true); return; }
      if (unavailable) { setUnavailable(false); loadStatus(); return; }
      if (busy || !status) return;
      if (!!d.running !== !!status.running || (d.error || null) !== (status.error || null)) loadStatus();
    },
    unmount() {
      for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
      unsubs = [];
      if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
      if (table) table.destroy();
      for (const m of extras) { try { if (m.unmount) m.unmount(); } catch (e) { /* ignore */ } }
      extras = [];
      root = null; els = {}; table = null; status = null; busy = false; busyMode = ''; loading = false; loadAgain = false; netPending = false; danger = null;
      scanError = null; cardToggles = {}; attentionShown = null;
    },
    // exposed for tests
    leaseText,
    serverSummary,
    applyLease,
    adapterLabel,
    internetWarning,
    withCardOpen,
    dhcpAttention,
    openCards: () => openCards.slice(),
    columns: COLUMNS.map((c) => c.key),
    cards: EXTRA_CARDS.map((c) => c.title),
  };
})();
