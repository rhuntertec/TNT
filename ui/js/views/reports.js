/* TNT — views/reports.js
   The Reports page (#reports): the site reports a Full Scan saves on this PC, in a compact look (small type, thin
   lines, no sticker shadows) so a whole report fits on a screen. Top to bottom: the heading row (Full Scan, search),
   the running scan's progress card (phases, bar, the site name field, Cancel), the selected report (the newest by
   default; Export PDF, Rename, Delete) beside the saved reports browser (sites, then a site's reports), and Compare
   below: report A (by default the current scan, the newest report) against any saved report B, section by section,
   with a PDF of the comparison.
   The full-scan controller lives in app.js (TNT.app.fullScan): this page only shows its job, so leaving it never
   stops a scan. The pure helpers are in js/reportsui.js (TNT.reportsui). Report hosts and access points are history:
   their tables have no "add as ping target" buttons and their ports are plain text, so nothing acts on another
   site's addresses from this PC. Loaded before app.js: TNT.util / TNT.ui are only touched inside functions. */
(function () {
  'use strict';
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  const COMPARE_B_STORE = 'tnt.reports.compareB';   // report B of the last comparison (a known good network, say)
  const LIST_LIMIT = 500;          // saved reports (and sites) read for the browser and the pickers; searches and "Show older" read on
  const SITE_ROWS = 200;           // one site's reports read at a time
  const OUTAGE_ROWS = 10;          // outage rows shown before "Show all"
  const RETRY_MS = [2000, 5000, 15000, 30000];       // reading the lists again after a failure
  const BAND_ORDER = { '2.4': 0, '5': 1, '6': 2 };
  const RU = () => TNT.reportsui;

  let root = null, els = {}, unsubs = [];
  let reports = [];                // the saved reports' list rows, newest first (no data)
  let sites = [];                  // GET /api/reports/sites rows
  let total = 0, sitesTotal = 0, listsLoaded = false, listsError = null, retryTimer = null, retries = 0;
  let openSite = null;             // the site_key opened in the browser
  const siteRows = new Map();      // site_key -> {rows, total} of that site (rows null while loading)
  const extraRows = new Map();     // id -> list rows beyond the newest LIST_LIMIT (a site's older reports, B searches)
  let searchSites = null, searchSeq = 0, searchTimer = null;         // sites the service found for the search box beyond the loaded ones
  let selectedId = null, selected = null, selectSeq = 0;
  let expanded = {};               // collapsible sections the user opened this session
  let tables = [];                 // host tables to destroy with the report
  let cmp = { a: 'current', b: null, bPicked: false, filterB: '', seq: 0, data: null, searchSeq: 0, searchTimer: null };
  let listsTimer = null, progressFrame = null;
  let dismissedJob = null, nameOpen = false, autoSelected = null;

  /* ------------------------------------------------------------- helpers */
  const isNum = (v) => typeof v === 'number' && isFinite(v);
  const when = (ts) => (isNum(ts) ? TNT.util.fmtDate(ts) + ' ' + TNT.util.fmtClock(ts) : '—');
  /** A report's date in a picker: "Sep 11 22:01" this year, "Sep 11, 2025 22:01" before, so a narrow select keeps the time. */
  const shortWhen = (ts) => {
    if (!isNum(ts)) return '—';
    const d = new Date(ts * 1000);
    const day = TNT.util.fmtDate(ts);
    return (d.getFullYear() === new Date().getFullYear() ? day.replace(/, \d{4}$/, '') : day) + ' ' + TNT.util.fmtClock(ts);
  };
  const knownRows = () => {
    const seen = new Set(reports.map((r) => r.id));
    return reports.concat(Array.from(extraRows.values()).filter((r) => !seen.has(r.id)));
  };
  const rememberRows = (rows) => { for (const r of rows || []) if (r && r.id != null) extraRows.set(r.id, r); };
  const dash = () => TNT.util.h('span', { class: 'muted' }, '—');
  const toast = (msg, kind, ms) => TNT.ui.toast(msg, kind, ms);
  const newestId = () => (reports.length ? reports[0].id : null);

  function kv(pairs) {
    const { h } = TNT.util;
    const el = h('div', { class: 'kv' });
    for (const [k, v] of pairs) {
      if (v === undefined) continue;
      el.appendChild(h('span', { class: 'k' }, k));
      el.appendChild(h('span', { class: 'v' }, v == null || v === '' ? dash() : v));
    }
    return el;
  }

  /** The note of a ping or outages section that left targets out (removed or disabled before the scan: "Left out: 8 removed or
   *  disabled targets (19 single-target outages)") as a note line, or null (nothing left out; older reports carry no note). */
  function leftOutNote(sec) {
    const { h } = TNT.util;
    const text = sec && typeof sec.note === 'string' ? sec.note.trim() : '';
    return text ? h('p', { class: 'rpt-note rpt-left-out' }, text) : null;
  }

  /** One report section: a small title (with a badge or meta on its right) and its body, or why it has no data. */
  function section(key, report, build, meta) {
    const { h } = TNT.util;
    const st = RU().sectionState(report, key);
    const head = h('h3', { class: 'rpt-sec-title' }, st.title, meta && st.available ? h('span', { class: 'rpt-sec-meta' }, meta) : null);
    const el = h('section', { class: 'rpt-sec rpt-sec-' + key, 'aria-label': st.title }, head);
    if (!st.available) {
      el.classList.add('is-unavailable');
      el.appendChild(h('p', { class: 'rpt-unavailable' }, TNT.ui.icon('info'), h('span', null, 'Not collected: ' + st.reason)));
      // only targets removed or disabled since were pinged in the window: the note says how many
      const note = key === 'ping' || key === 'outages' ? leftOutNote(report && report.data ? report.data[key] : null) : null;
      if (note) el.appendChild(note);
      return el;
    }
    try { el.appendChild(build(report.data[key])); }
    catch (err) { console.error('report section failed', key, err); el.appendChild(h('p', { class: 'rpt-unavailable' }, 'This section could not be shown.')); }
    return el;
  }

  /** A button that shows and hides a table built on first use (remembered while the page lives). */
  function collapsible(key, label, count, build) {
    const { h } = TNT.util;
    const body = h('div', { class: 'rpt-collapse-body', id: 'rpt-' + key + '-body', hidden: true });
    const btn = h('button', { class: 'btn btn-sm rpt-toggle', type: 'button', 'aria-controls': body.id, 'aria-expanded': 'false' },
      h('span', { class: 'rpt-caret', 'aria-hidden': 'true' }), label + ' (' + count + ')');
    let built = false;
    const sync = () => {
      const on = !!expanded[key];
      btn.setAttribute('aria-expanded', String(on));
      body.hidden = !on;
      if (on && !built) { built = true; body.appendChild(build()); }
    };
    btn.addEventListener('click', () => { expanded[key] = !expanded[key]; sync(); });
    sync();
    return h('div', { class: 'rpt-collapse' }, btn, body);
  }

  function tableWrap(thead, tbody, cls) {
    const { h } = TNT.util;
    return h('div', { class: 'table-wrap' }, h('table', { class: 'table ' + (cls || '') }, thead, tbody));
  }

  function lossCls(v) { return !isNum(v) ? '' : v >= 5 ? 'lvl-bad' : v >= 1 ? 'lvl-warn' : ''; }

  function signalChip(rssi) {
    const { h } = TNT.util;
    const cls = TNT.wifichart ? TNT.wifichart.signalClass(rssi) : 'grey';
    return h('span', { class: 'survey-dbm ' + cls }, RU().fmtValue(rssi, 'dBm'));
  }

  function scrollIntoViewSoft(el) {
    if (!el) return;
    const r = el.getBoundingClientRect();
    if (r.top >= 70 && r.top < window.innerHeight - 60) return;       // already on screen
    try { el.scrollIntoView({ block: 'start', behavior: 'smooth' }); } catch (e) { el.scrollIntoView(); }
  }

  /* ----------------------------------------------------------- sections */
  const VISITS_LISTED = 3;         // visits spelled out in the Network section (every one is in the tooltip)

  /** A visit to the site's network in a line: "Sep 5 08:10–17:40", "Sep 11 22:40–Sep 12 07:02". */
  function visitSpan(v) {
    const sameDay = new Date(v.start * 1000).toDateString() === new Date(v.end * 1000).toDateString();
    return shortWhen(v.start) + '–' + (sameDay ? TNT.util.fmtClock(v.end) : shortWhen(v.end));
  }

  function networkBody(net, data) {
    const { h, copyCode } = TNT.util;
    const U = RU();
    const nic = net.internet_nic || null;
    const wrap = h('div', { class: 'rpt-sec-body' });
    // the site's network: the router that identifies it, and the visits the pings and outages come from
    const ident = U.networkIdentity(data && data.meta ? data.meta.network : null);
    // visits only for a report of the site's network: under the time rule they would be this PC's time on any network. The meta line
    // says how many and how long; here every visit is listed, the first few on one line and the rest on the next
    const ping = data && data.ping && data.ping.window_reason === 'site_network' ? data.ping : null;
    const spans = ping && Array.isArray(ping.visits) ? ping.visits.filter((v) => v && isNum(v.start) && isNum(v.end)).sort((x, y) => x.start - y.start) : [];
    const router = !ident || ident.identity === 'unknown' ? undefined
      : ident.identity === 'mac' ? h('span', { class: 'rpt-router', title: ident.title }, copyCode(ident.mac), ident.vendor ? h('span', { class: 'muted' }, ident.vendor) : null)
        : h('span', { class: 'muted', title: ident.title }, ident.text);
    const visitsEl = !ping ? undefined : !spans.length ? 'nothing monitored'
      : h('span', { class: 'rpt-visits' }, h('span', null, spans.slice(0, VISITS_LISTED).map(visitSpan).join(', ')),
        spans.length > VISITS_LISTED ? h('span', { class: 'muted rpt-visits-more' }, spans.slice(VISITS_LISTED).map(visitSpan).join(', ')) : null);
    const warn = TNT.views.ipinfo && TNT.views.ipinfo.warningView;
    const badges = (Array.isArray(net.warnings) ? net.warnings : []).map((code) => {
      const w = warn ? warn({ code }) : { cls: 'yellow', label: String(code) };
      return w ? h('span', { class: 'badge ' + w.cls }, w.label) : null;
    }).filter(Boolean);
    if (badges.length) wrap.appendChild(h('div', { class: 'rpt-badges' }, badges));
    if (!nic) wrap.appendChild(h('p', { class: 'muted' }, 'No adapter faced the internet.'));
    const dns = nic && Array.isArray(nic.dns) && nic.dns.length ? h('span', { class: 'rpt-chips' }, nic.dns.map((x) => copyCode(x))) : null;
    const dhcp = !nic ? null : nic.dhcp ? 'on' + (nic.dhcp_server ? ' · server ' + nic.dhcp_server : '') : nic.dhcp === false ? 'off (static address)' : null;
    wrap.appendChild(kv([
      ['Router', router],
      ['Visits', visitsEl],
      ['Adapter', nic ? nic.name : null],
      ['IPv4', nic && nic.ipv4 ? copyCode(nic.ipv4 + (nic.prefix != null ? '/' + nic.prefix : '')) : null],
      ['Gateway', nic && nic.gateway ? copyCode(nic.gateway) : null],
      ['DNS', dns],
      ['DHCP', dhcp],
      ['This PC\'s MAC', nic && nic.mac ? copyCode(nic.mac) : null],
      ['Link', nic && isNum(nic.link_bps) ? U.bpsText(nic.link_bps) : null],
      ['Public IP', net.public_ip ? copyCode(net.public_ip) : null],
      ['ISP', net.isp || null],
    ]));
    // not identified when the scan started (the time rule), or a portable network (only the connection to it counts)
    if (ident && ident.note) wrap.appendChild(h('p', { class: 'rpt-note rpt-net-note' }, ident.note));
    // untagged pings recorded before this PC identified its networks count only since it joined this network
    const untagged = U.untaggedText(data && data.ping, when);
    if (untagged) wrap.appendChild(h('p', { class: 'rpt-note rpt-untagged' }, untagged));
    return wrap;
  }

  function speedBody(sp) {
    const { h } = TNT.util;
    const U = RU();
    const wrap = h('div', { class: 'rpt-sec-body' });
    const r = sp.result;
    if (r) {
      if (r.ok === false) wrap.appendChild(h('p', { class: 'rpt-error' }, 'The test failed: ' + (r.error || 'unknown error')));
      else {
        wrap.appendChild(h('div', { class: 'rpt-speed' },
          h('span', { class: 'rpt-big' }, h('span', { class: 'rpt-arrow down', 'aria-hidden': 'true' }, '↓'), U.fmtNumber(r.download_mbps, 'Mbps'), h('span', { class: 'unit' }, 'Mbps down')),
          h('span', { class: 'rpt-big' }, h('span', { class: 'rpt-arrow up', 'aria-hidden': 'true' }, '↑'), U.fmtNumber(r.upload_mbps, 'Mbps'), h('span', { class: 'unit' }, 'Mbps up'))));
        wrap.appendChild(kv([
          ['Latency', U.fmtValue(r.latency_ms, 'ms')], ['Jitter', U.fmtValue(r.jitter_ms, 'ms')],
          ['Packet loss', isNum(r.packet_loss_pct) ? U.fmtValue(r.packet_loss_pct, '%') : null],
          ['Server', [r.server, r.backend].filter(Boolean).join(' · ') || null], ['ISP', r.isp || null], ['Tested', when(r.ts)],
        ]));
      }
    } else wrap.appendChild(h('p', { class: 'muted' }, 'No test result in this report.'));
    const w = sp.window;
    if (w && w.count) {
      const range = (avg, lo, hi, unit) => U.fmtValue(avg, unit) + (isNum(lo) && isNum(hi) ? ' (' + U.fmtNumber(lo, unit) + '–' + U.fmtNumber(hi, unit) + ')' : '');
      wrap.appendChild(h('p', { class: 'rpt-note' }, U.plural(w.count, 'speed test') + ' in the window (this scan\'s included): ↓ ' + range(w.download_avg, w.download_min, w.download_max, 'Mbps') +
        ' · ↑ ' + range(w.upload_avg, w.upload_min, w.upload_max, 'Mbps') + (isNum(w.latency_avg) ? ' · ' + U.fmtValue(w.latency_avg, 'ms') : '')));
    }
    return wrap;
  }

  function pingBody(ping) {
    const { h, copyCode } = TNT.util;
    const U = RU();
    const targets = Array.isArray(ping.targets) ? ping.targets : [];
    const note = leftOutNote(ping);
    if (!targets.length) return h('div', { class: 'rpt-sec-body' }, note, h('p', { class: 'muted' }, 'No ping data in the window.'));
    const role = { gateway: ['gateway', 'blue'], local: ['local', 'green'], internet: ['internet', 'purple'] };
    const thead = h('thead', null, h('tr', null, ['Target', 'IP', 'Avg', 'p95', 'Max', 'Jitter', 'Loss', 'Pings'].map((t, i) => h('th', { class: i >= 2 ? 'num' : null, scope: 'col' }, t))));
    const tbody = h('tbody');
    for (const t of targets) {
      const r = role[t.role] || [t.role || '?', 'grey'];
      tbody.appendChild(h('tr', null,
        h('td', { class: 'rpt-target' }, h('span', { class: 'rpt-target-name', title: t.host || '' }, t.label || t.host || '—'), h('span', { class: 'badge ' + r[1] }, r[0])),
        h('td', null, t.ip ? copyCode(t.ip) : dash()),
        h('td', { class: 'num' }, U.fmtValue(t.avg_ms, 'ms')), h('td', { class: 'num' }, U.fmtValue(t.p95_ms, 'ms')),
        h('td', { class: 'num' }, U.fmtValue(t.max_ms, 'ms')), h('td', { class: 'num' }, U.fmtValue(t.jitter_ms, 'ms')),
        h('td', { class: 'num ' + lossCls(t.loss_pct) }, isNum(t.loss_pct) ? U.fmtValue(t.loss_pct, '%') : '—'),
        h('td', { class: 'num', title: isNum(t.lost) ? t.lost + ' lost' : '' }, isNum(t.samples) ? t.samples.toLocaleString() : '—')));
    }
    return h('div', { class: 'rpt-sec-body' }, note, tableWrap(thead, tbody, 'rpt-table'),
      h('p', { class: 'rpt-note' }, 'Averages and p95 from 1-minute aggregates: short spikes inside a minute are smoothed.'));
  }

  function outagesBody(out, report) {
    const { h } = TNT.util;
    const U = RU();
    const wrap = h('div', { class: 'rpt-sec-body' });
    const by = out.by_kind || {}, down = out.downtime_s || {};
    const summary = (report && report.summary) || {};
    // the incidents beside the per-kind rows the tracker wrote, then the newest incidents. A network outage is a whole group of
    // targets down (its member targets folded into it); a single-target outage one device or server.
    const network = isNum(out.network_outages) ? out.network_outages : null;
    const top = h('div', { class: 'rpt-out-top' }, kv([
      ['Outages', isNum(out.count) ? String(out.count) : null],
      ['Network outages', network != null ? String(network) : undefined],
      ['Network down', isNum(out.network_down_s) ? U.durationText(out.network_down_s) : isNum(summary.downtime_s) ? U.durationText(summary.downtime_s) : null],
      ['Longest network outage', isNum(out.longest_s) ? U.durationText(out.longest_s) : null],
      ['Single-target outages', isNum(out.target_outages) ? String(out.target_outages) : undefined],
    ]));
    top.firstChild.title = 'A network outage is the local network or the internet not answering at all; a single-target outage is one device or server';
    const kinds = [['target', 'One target'], ['total_local', 'Local network'], ['total_internet', 'Internet'], ['gap', 'Not monitoring']];
    const rows = kinds.filter(([k]) => isNum(by[k]) && by[k] > 0);
    if (rows.length) {
      // single-target rows overlap each other (one drop is a row per target), so they get no summed time
      top.appendChild(tableWrap(h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Rows by kind'), h('th', { class: 'num', scope: 'col' }, 'Count'), h('th', { class: 'num', scope: 'col' }, 'Time'))),
        h('tbody', null, rows.map(([k, label]) => h('tr', null, h('td', null, label), h('td', { class: 'num' }, String(by[k])),
          h('td', { class: 'num', title: k === 'target' ? 'Single-target outages overlap each other: their time is not added up' : null }, k === 'target' ? '—' : U.durationText(down[k]))))), 'rpt-table rpt-kinds'));
    }
    const note = leftOutNote(out);
    if (note) wrap.appendChild(note);
    wrap.appendChild(top);
    const items = Array.isArray(out.items) ? out.items : [];
    if (!items.length) { wrap.appendChild(h('p', { class: 'muted' }, 'No outages in the window.')); return wrap; }
    const kindName = { target: 'target', total_local: 'network', total_internet: 'internet', gap: 'gap' };
    const kindCls = { target: 'yellow', total_local: 'red', total_internet: 'red', gap: 'grey' };
    const tbody = h('tbody');
    const renderRows = (all) => {
      tbody.innerHTML = '';
      for (const o of all ? items : items.slice(0, OUTAGE_ROWS)) {
        const note = o.kind === 'gap' && String(o.note || '').trim().toLowerCase() === 'not monitoring' ? '' : (o.note || '');
        tbody.appendChild(h('tr', null,
          h('td', null, when(o.start_ts)), h('td', { class: 'num' }, U.durationText(o.duration_s)),
          h('td', null, h('span', { class: 'badge ' + (kindCls[o.kind] || 'grey') }, kindName[o.kind] || o.kind || '?')),
          h('td', { class: 'rpt-wrap' }, U.outageWhat(o)),
          h('td', { class: 'num' }, isNum(o.missed_pct) ? U.fmtValue(o.missed_pct, '%') : '—'),
          h('td', { class: 'rpt-wrap muted' }, note)));
      }
    };
    renderRows(!!expanded.outages);
    const thead = h('thead', null, h('tr', null, ['Started', 'Lasted', 'Kind', 'What', 'Missed', 'Note'].map((t, i) => h('th', { class: i === 1 || i === 4 ? 'num' : null, scope: 'col' }, t))));
    wrap.appendChild(tableWrap(thead, tbody, 'rpt-table'));
    const shownAll = items.length <= OUTAGE_ROWS;
    const kept = isNum(out.items_total) && out.items_total > items.length ? 'the newest ' + items.length + ' of ' + out.items_total + ' are kept in the report' : '';
    if (!shownAll || kept) {
      const btn = h('button', { class: 'btn btn-sm', type: 'button', hidden: shownAll }, expanded.outages ? 'Show fewer' : 'Show all ' + items.length);
      btn.addEventListener('click', () => { expanded.outages = !expanded.outages; renderRows(expanded.outages); btn.textContent = expanded.outages ? 'Show fewer' : 'Show all ' + items.length; });
      wrap.appendChild(h('div', { class: 'rpt-row' }, btn, kept ? h('span', { class: 'muted' }, kept) : null));
    }
    return wrap;
  }

  function discoveryBody(disc) {
    const { h, copyCode } = TNT.util;
    const U = RU();
    const HT = TNT.hosttable;
    const wrap = h('div', { class: 'rpt-sec-body' });
    const types = disc.device_types && typeof disc.device_types === 'object' ? Object.entries(disc.device_types).filter(([, n]) => n > 0) : [];
    if (types.length) {
      wrap.appendChild(h('div', { class: 'rpt-badges' }, types.sort((a, b) => b[1] - a[1]).map(([t, n]) =>
        h('span', { class: 'badge ' + (HT ? HT.deviceTypeClass(t) : 'grey') }, t + ' ' + n))));
    }
    const hosts = Array.isArray(disc.hosts) ? disc.hosts : [];
    if (!hosts.length) { wrap.appendChild(h('p', { class: 'muted' }, 'No devices answered.')); return wrap; }
    const label = isNum(disc.hosts_total) && disc.hosts_total > hosts.length ? 'Devices, ' + hosts.length + ' of ' + disc.hosts_total : 'Devices';
    wrap.appendChild(collapsible('hosts', label, hosts.length, () => {
      const columns = [
        { key: 'ip', label: 'IP', kind: 'ip', cell: (x) => h('td', { class: 'rpt-nowrap' }, x.ip ? copyCode(x.ip) : dash()) },
        { key: 'hostname', label: 'Hostname', kind: 'text', cell: (x) => h('td', { class: 'rpt-wrap' }, x.hostname || dash()) },
        { key: 'mac', label: 'MAC', kind: 'text', cell: (x) => h('td', null, x.mac ? copyCode(x.mac) : dash()) },
        // the type the scan recorded; a report is history, so no classification against this PC's gateway now
        { key: 'device_type', label: 'Type', cls: 'device-type', kind: 'custom',
          sortValue: (x) => (x.device_type ? [false, String(x.device_type).toLowerCase(), ''] : [true, '', '']),
          cell: (x) => h('td', { class: 'device-type' }, x.device_type ? h('span', { class: 'badge ' + HT.deviceTypeClass(x.device_type) }, x.device_type) : dash()) },
        { key: 'vendor', label: 'Vendor', kind: 'text', cell: (x) => h('td', { class: 'rpt-wrap' }, x.vendor || dash()) },
        // plain pills: an old site's address must not open a browser or ssh from here
        { key: 'ports', label: 'Open ports', kind: 'ports', cell: (x) => h('td', { class: 'ports' }, (x.open_ports || []).length ? x.open_ports.map((p) => h('span', { class: 'pill' }, String(p))) : dash()) },
      ];
      const t = HT.create({ columns, storeKey: 'tnt.reports.hosts.sort', onSort: () => t.render(hosts, '') });
      tables.push(t);
      t.render(hosts, '');
      return tableWrap(t.thead, t.tbody, 'rpt-table rpt-hosts');
    }));
    return wrap;
  }

  function wifiBody(wifi) {
    const { h, copyCode } = TNT.util;
    const U = RU();
    const wrap = h('div', { class: 'rpt-sec-body' });
    const c = wifi.connected;
    if (c) {
      const crowd = [isNum(c.channel_aps) ? U.plural(c.channel_aps, 'AP') + ' on its channel' : '',
        isNum(c.overlap_aps) && isNum(c.channel_aps) && c.overlap_aps > c.channel_aps ? c.overlap_aps + ' overlapping it' : ''].filter(Boolean).join(', ');
      wrap.appendChild(h('p', { class: 'rpt-wifi-conn' }, 'Connected to ', h('strong', null, c.ssid || '(hidden)'), ' ', signalChip(c.rssi),
        h('span', { class: 'muted' }, ' ' + [c.band ? c.band + ' GHz' : '', c.channel != null ? 'channel ' + c.channel : '', c.width_mhz ? c.width_mhz + ' MHz' : '', crowd].filter(Boolean).join(' · '))));
    } else wrap.appendChild(h('p', { class: 'muted' }, 'This PC was not connected to Wi-Fi.'));
    const bands = wifi.bands && typeof wifi.bands === 'object' ? wifi.bands : {};
    const bandKeys = Object.keys(bands).sort((a, b) => (BAND_ORDER[a] == null ? 9 : BAND_ORDER[a]) - (BAND_ORDER[b] == null ? 9 : BAND_ORDER[b]));
    if (bandKeys.length) {
      const thead = h('thead', null, h('tr', null, ['Band', 'APs', 'Networks', 'Strongest', 'Median', 'Busiest channel'].map((t, i) => h('th', { class: i > 0 && i < 5 ? 'num' : null, scope: 'col' }, t))));
      const tbody = h('tbody', null, bandKeys.map((k) => {
        const b = bands[k] || {};
        return h('tr', null, h('td', null, k + ' GHz'), h('td', { class: 'num' }, isNum(b.aps) ? String(b.aps) : '—'), h('td', { class: 'num' }, isNum(b.networks) ? String(b.networks) : '—'),
          h('td', { class: 'num' }, isNum(b.strongest_rssi) ? signalChip(b.strongest_rssi) : '—'), h('td', { class: 'num' }, U.fmtValue(b.median_rssi, 'dBm')),
          h('td', null, b.busiest_channel != null ? String(b.busiest_channel) + (isNum(b.busiest_channel_aps) ? ' (' + b.busiest_channel_aps + ' APs)' : '') : '—'));
      }));
      wrap.appendChild(tableWrap(thead, tbody, 'rpt-table rpt-bands'));
    }
    const aps = Array.isArray(wifi.aps) ? wifi.aps : [];
    if (!aps.length) { wrap.appendChild(h('p', { class: 'muted' }, 'No access points in range.')); return wrap; }
    const label = isNum(wifi.aps_total) && wifi.aps_total > aps.length ? 'Access points, ' + aps.length + ' strongest of ' + wifi.aps_total : 'Access points';
    wrap.appendChild(collapsible('aps', label, aps.length, () => {
      const num = (v) => (isNum(v) ? [false, v, 0] : [true, 0, 0]);
      const txt = (v) => (v ? [false, String(v).toLowerCase(), ''] : [true, '', '']);
      const columns = [
        { key: 'ssid', label: 'Network', kind: 'custom', sortValue: (ap) => txt(ap.ssid),
          cell: (ap) => h('td', { class: 'rpt-wrap' }, ap.ssid ? h('strong', null, ap.ssid) : h('span', { class: 'muted' }, '(hidden)'), ap.connected ? h('span', { class: 'badge green' }, 'connected') : null) },
        { key: 'band', label: 'Band', kind: 'custom', numeric: true, sortValue: (ap) => (ap.band in BAND_ORDER ? [false, BAND_ORDER[ap.band], ap.channel || 0] : [true, 0, 0]),
          cell: (ap) => h('td', null, ap.band ? ap.band + ' GHz' : '—') },
        { key: 'channel', label: 'Channel', kind: 'custom', numeric: true, sortValue: (ap) => (isNum(ap.channel) ? [false, ap.channel, ap.width_mhz || 0] : [true, 0, 0]),
          cell: (ap) => h('td', { class: 'rpt-nowrap' }, ap.channel != null ? String(ap.channel) + (ap.width_mhz ? ' · ' + ap.width_mhz + ' MHz' : '') : '—') },
        { key: 'rssi', label: 'Signal', kind: 'custom', numeric: true, sortValue: (ap) => num(ap.rssi), cell: (ap) => h('td', null, signalChip(ap.rssi)) },
        { key: 'security', label: 'Security', kind: 'custom', sortValue: (ap) => txt(ap.security), cell: (ap) => h('td', null, ap.security || '—') },
        { key: 'generation', label: 'Wi-Fi', kind: 'custom', sortValue: (ap) => txt(ap.generation), cell: (ap) => h('td', { class: 'rpt-nowrap' }, ap.generation || '—') },
        { key: 'vendor', label: 'Vendor', kind: 'custom', sortValue: (ap) => txt(ap.vendor), cell: (ap) => h('td', { class: 'rpt-wrap' }, ap.vendor || dash()) },
        { key: 'bssid', label: 'BSSID', kind: 'custom', sortValue: (ap) => txt(ap.bssid), cell: (ap) => h('td', null, ap.bssid ? copyCode(ap.bssid) : dash()) },
      ];
      const t = TNT.hosttable.create({ columns, storeKey: 'tnt.reports.aps.sort', defaultSort: { key: 'rssi', dir: 'desc' }, onSort: () => t.render(aps, '') });
      tables.push(t);
      t.render(aps, '');
      return tableWrap(t.thead, t.tbody, 'rpt-table rpt-aps');
    }));
    return wrap;
  }

  /* ------------------------------------------------------- the report view */
  function destroyTables() {
    for (const t of tables) { try { t.destroy(); } catch (e) { /* ignore */ } }
    tables = [];
  }

  function renderReport() {
    const { h } = TNT.util;
    const U = RU();
    const main = els.main;
    destroyTables();
    main.innerHTML = '';
    main.removeAttribute('aria-busy');
    if (!listsLoaded) {
      main.appendChild(listsError ? errorBox('Could not load the reports: ' + listsError) : h('div', { class: 'empty' }, 'Loading reports…'));
      return;
    }
    if (!reports.length) {
      main.appendChild(h('div', { class: 'rpt-empty' },
        h('h3', null, 'No reports yet'),
        h('p', null, 'A Full Scan runs a speed test, a Discovery scan and a Wi-Fi scan, adds up to 7 days of this PC\'s pings and outages and saves it all here as a report for the site. Scan the same site again later, or compare it with a known good network below.'),
        h('button', { class: 'btn btn-primary', type: 'button', on: { click: () => TNT.app.fullScanClick() } }, TNT.ui.icon('report'), 'Full Scan')));
      return;
    }
    const rep = selected;
    if (!rep) { main.setAttribute('aria-busy', 'true'); main.appendChild(h('div', { class: 'empty' }, 'Loading the report…')); return; }
    const data = rep.data || {};
    const meta = data.meta || {};
    // a report of the site's network counts that network's visits only: its sections say so rather than "last 2d 14h"
    const siteNet = !!(data.ping && data.ping.window_reason === 'site_network');
    const win = U.windowText(siteNet || (data.ping && data.ping.available !== false) ? data.ping : data.outages);
    const statusBadge = h('span', { class: 'badge ' + (rep.status === 'complete' ? 'green' : 'yellow'), title: rep.status === 'complete' ? 'Every part of the scan worked' : 'Some parts of the scan could not be collected' }, rep.status || '?');
    const pdfBtn = h('button', { class: 'btn btn-sm', type: 'button' }, TNT.ui.icon('download'), 'Export PDF');
    pdfBtn.addEventListener('click', () => exportPdf(rep, pdfBtn));
    const cmpBtn = h('button', { class: 'btn btn-sm', type: 'button', title: 'Compare this report with another one below' }, TNT.ui.icon('swap'), 'Compare');
    cmpBtn.addEventListener('click', () => { cmp.a = String(rep.id); renderPickers(); runCompare(); scrollIntoViewSoft(els.compare); });
    const renameBtn = h('button', { class: 'btn btn-sm', type: 'button' }, 'Rename');
    renameBtn.addEventListener('click', () => renameReport(rep));
    const delBtn = h('button', { class: 'btn btn-sm rpt-danger', type: 'button' }, TNT.ui.icon('trash'), 'Delete');
    delBtn.addEventListener('click', () => deleteReport(rep));
    const metaBits = [when(rep.created_ts), isNum(meta.duration_s) ? 'took ' + U.durationText(meta.duration_s) : null, meta.hostname ? 'on ' + meta.hostname : null,
      meta.tnt_version ? 'TNT ' + meta.tnt_version : null].filter(Boolean);
    main.appendChild(h('div', { class: 'rpt-rhead' },
      h('div', { class: 'rpt-rtitle' }, h('h3', { class: 'rpt-site', id: 'rpt-site-title' }, rep.site), statusBadge),
      h('div', { class: 'rpt-ractions' }, cmpBtn, pdfBtn, renameBtn, delBtn)));
    const cover = U.coverageText(data, when);
    main.appendChild(h('p', { class: 'rpt-meta' }, metaBits.join(' · '),
      cover.text !== '—' ? h('span', { class: 'rpt-window', title: cover.title }, ' · pings & outages: ' + cover.text) : null));
    const missing = (Array.isArray(meta.scan_phases) ? meta.scan_phases : []).filter((p) => p && p.status && p.status !== 'done');
    if (missing.length) {
      main.appendChild(h('p', { class: 'rpt-partial' }, TNT.ui.icon('warning'),
        h('span', null, missing.map((p) => (RU().PHASES.find((x) => x.key === p.key) || { label: p.key }).label + ' ' + p.status + (p.message ? ': ' + p.message : '')).join(' · '))));
    }
    main.appendChild(h('div', { class: 'rpt-kpis', role: 'list', 'aria-label': 'Key numbers' }, U.keyNumbers(rep.summary, data).map((k) =>
      h('div', { class: 'rpt-kpi' + (k.level ? ' lvl-' + k.level : ''), role: 'listitem' },
        h('span', { class: 'rpt-kpi-label' }, k.label), h('span', { class: 'rpt-kpi-value' }, k.value), k.sub ? h('span', { class: 'rpt-kpi-sub' }, k.sub) : null))));
    const disc = data.discovery || {};
    const wifi = data.wifi || {};
    const speed = data.speed || {};
    main.appendChild(h('div', { class: 'rpt-cols' },
      section('network', rep, (n) => networkBody(n, data)),
      section('speed', rep, speedBody, speed.result && speed.result.backend ? speed.result.backend : null)));
    main.appendChild(section('ping', rep, pingBody, win.text));
    main.appendChild(section('outages', rep, (o) => outagesBody(o, rep), siteNet ? win.text : U.windowText(data.outages).text));
    main.appendChild(section('discovery', rep, discoveryBody,
      [isNum(disc.host_count) ? disc.host_count + (disc.host_count === 1 ? ' device' : ' devices') : null, disc.range || null,
        isNum(disc.duration_s) ? U.durationText(disc.duration_s) : null].filter(Boolean).join(' · ')));
    main.appendChild(section('wifi', rep, wifiBody,
      [isNum(wifi.aps_count) ? wifi.aps_count + ' APs' : null, isNum(wifi.networks) ? wifi.networks + ' networks' : null, wifi.adapter || null].filter(Boolean).join(' · ')));
  }

  async function selectReport(id, opts) {
    opts = opts || {};
    if (id == null || !root) return;
    const mine = ++selectSeq;
    selectedId = Number(id);
    if (!selected || selected.id !== selectedId) { selected = null; renderReport(); }
    renderBrowser();
    try {
      const rep = await TNT.api.report(selectedId);
      if (!root || mine !== selectSeq) return;
      selected = rep;
      rememberRows([{ id: rep.id, site: rep.site, created_ts: rep.created_ts, completed_ts: rep.completed_ts, status: rep.status, summary: rep.summary }]);
      const key = RU().siteKey(rep.site);
      if (openSite !== key) { openSite = key; loadSiteRows(key); }
      renderReport();
      renderBrowser();
      if (opts.hash !== false) setHash(selectedId);
      if (opts.scroll) scrollIntoViewSoft(els.main);
    } catch (err) {
      if (!root || mine !== selectSeq) return;
      if (err.status === 404) {
        toast('That report is not there any more', 'warn');
        if (hashId() === selectedId) setHash(null);
        selectedId = null; selected = null; scheduleLists(); return;
      }
      els.main.innerHTML = '';
      els.main.appendChild(errorBox('Could not load the report: ' + err.message, () => selectReport(id, opts)));
    }
  }

  /** The address bar follows the report on screen: "#reports?id=N", or "#reports" when there is none (a deleted one). */
  function setHash(id) {
    if (location.hash.indexOf('#reports') !== 0) return;
    try { history.replaceState(null, '', id == null ? '#reports' : '#reports?id=' + id); } catch (e) { /* ignore */ }
  }

  /** A failure message with a Retry button (by default: read the lists again at once). */
  function errorBox(text, retry) {
    const { h } = TNT.util;
    const btn = h('button', { class: 'btn btn-sm', type: 'button' }, 'Retry');
    btn.addEventListener('click', () => { retries = 0; (retry || loadLists)(); });
    return h('div', { class: 'empty rpt-failed', role: 'alert' }, h('span', null, text), btn);
  }

  async function exportPdf(rep, btn) {
    TNT.ui.busy(btn, true, 'Building PDF…');
    try {
      const r = await TNT.api.reportPdf(rep.id);
      await TNT.app.saveBlob(r.blob, r.filename || RU().reportFilename(rep.site, rep.created_ts));
    } catch (err) { toast('Export failed: ' + err.message, 'error'); }
    finally { TNT.ui.busy(btn, false); }
  }

  function renameReport(rep) {
    const { h } = TNT.util;
    const combo = RU().siteCombo({ label: 'Site name', value: rep.site, fetchSites: (q) => TNT.api.reportSites(q, 50).then((r) => (r && r.sites) || []), onEnter: () => save() });
    const saveBtn = h('button', { class: 'btn btn-primary', type: 'button' }, TNT.ui.icon('check'), 'Rename');
    const cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
    const body = h('div', { class: 'site-modal-body' },
      h('p', { class: 'muted' }, 'The report of ' + when(rep.created_ts) + '. Pick an earlier site to file it with that site\'s reports.'),
      h('div', { class: 'field' }, h('label', { for: combo.input.id }, 'Site name'), combo.el));
    const m = TNT.ui.modal({ title: 'Rename report', narrow: true, body, foot: [cancel, saveBtn], onEscape: () => combo.isOpen(), onClose: () => combo.destroy() });
    m.el.classList.add('site-modal');
    // the modal focuses the field first (a zero timer too): select the old name after it, so typing replaces it
    setTimeout(() => { try { combo.input.focus(); combo.input.select(); } catch (e) { /* closed already */ } }, 0);
    cancel.addEventListener('click', () => m.close());
    async function save() {
      const site = combo.value();
      if (!site) { toast('Type the site name', 'warn'); combo.focus(); return; }
      if (site === rep.site) { m.close(); return; }
      TNT.ui.busy(saveBtn, true, 'Renaming…');
      try {
        await TNT.api.renameReport(rep.id, site);
        toast('Renamed to ' + site, 'ok');
        m.close('saved');
        siteRows.clear();
        if (root) { if (selected && selected.id === rep.id) selected = Object.assign({}, selected, { site }); loadLists(rep.id); }
      } catch (err) { toast('Could not rename the report: ' + err.message, 'error'); }
      finally { TNT.ui.busy(saveBtn, false); }
    }
    saveBtn.addEventListener('click', save);
  }

  async function deleteReport(rep) {
    const ok = await TNT.ui.confirm({ title: 'Delete this report?', message: 'The ' + rep.site + ' report of ' + when(rep.created_ts) + ' is removed from this PC for good.', ok: 'Delete', danger: true });
    if (!ok) return;
    try {
      await TNT.api.deleteReport(rep.id);
      toast('Report deleted', 'ok');
      if (hashId() === rep.id) setHash(null);
      if (selectedId === rep.id) { selectedId = null; selected = null; }
      extraRows.delete(rep.id);
      siteRows.clear();
      if (root) loadLists();
    } catch (err) { toast('Could not delete the report: ' + err.message, 'error'); }
  }

  /* ------------------------------------------------------ the browser */
  /** A site's reports for the browser, SITE_ROWS at a time; `more` reads the page after the ones listed ("Show older"). */
  async function loadSiteRows(key, more) {
    const have = siteRows.get(key);
    if (!key || (have && (have.loading || !more))) { renderBrowser(); return; }
    const before = more && have ? have.rows : [];
    siteRows.set(key, { rows: before, total: have ? have.total : 0, loading: true });
    renderBrowser();
    try {
      const r = await TNT.api.reports({ site_key: key, limit: SITE_ROWS, offset: before.length || null });
      if (!root) return;
      const rows = before.concat((r && r.reports) || []);
      rememberRows(rows);
      siteRows.set(key, { rows, total: Number(r && r.total) || rows.length, loading: false });
      if (more) renderPickers();
    } catch (err) {
      if (have) siteRows.set(key, have); else siteRows.delete(key);
      if (root) toast('Could not load the site\'s reports: ' + err.message, 'error');
    }
    if (root) renderBrowser();
  }

  /** The search box and more sites than were read: ask the service for the matching ones (older sites included). */
  function scheduleSiteSearch() {
    if (searchTimer) { clearTimeout(searchTimer); searchTimer = null; }
    const q = RU().normalizeSite(els.search ? els.search.value : '');
    if (!q || sitesTotal <= sites.length) { searchSites = null; return; }
    searchTimer = setTimeout(async () => {
      searchTimer = null;
      const mine = ++searchSeq;
      try {
        const r = await TNT.api.reportSites(q, LIST_LIMIT);
        if (!root || mine !== searchSeq) return;
        searchSites = { key: RU().siteKey(q), sites: (r && r.sites) || [] };
        renderBrowser();
      } catch (e) { /* the sites read already stay listed */ }
    }, 250);
  }

  function renderBrowser() {
    const { h, relTime } = TNT.util;
    const U = RU();
    const box = els.browser;
    if (!box) return;
    const q = els.search ? els.search.value : '';
    const siteCount = Math.max(sitesTotal, sites.length);
    els.browserCount.textContent = listsLoaded ? U.plural(total, 'report') + ' · ' + U.plural(siteCount, 'site') : '';
    box.innerHTML = '';
    if (!listsLoaded) { box.appendChild(listsError ? errorBox('Could not load: ' + listsError) : h('p', { class: 'muted' }, 'Loading…')); return; }
    if (!sites.length) { box.appendChild(h('p', { class: 'muted' }, 'No saved reports yet.')); return; }
    const searched = searchSites && searchSites.key === U.siteKey(q) ? searchSites.sites : null;
    const shown = U.rankSuggestions(searched || sites, q, null);
    if (!shown.length) { box.appendChild(h('p', { class: 'muted' }, 'No site matches “' + U.normalizeSite(q) + '”.')); return; }
    if (!U.normalizeSite(q) && siteCount > sites.length) {
      box.appendChild(h('p', { class: 'muted rpt-site-loading' }, 'The ' + sites.length + ' most recently scanned sites: search to find the others.'));
    }
    const ul = h('ul', { class: 'rpt-sites' });
    for (const s of shown) {
      const key = s.site_key || U.siteKey(s.site);
      const open = openSite === key;
      const [pre, hit, post] = U.matchParts(s.site, q);
      const btn = h('button', { class: 'rpt-site-btn', type: 'button', 'aria-expanded': String(open) },
        h('span', { class: 'rpt-caret', 'aria-hidden': 'true' }),
        h('span', { class: 'rpt-site-name', title: s.site }, pre, hit ? h('mark', null, hit) : null, post),
        h('span', { class: 'rpt-site-meta' }, (s.count || 0) + (s.count === 1 ? ' scan' : ' scans') + ' · ' + relTime(s.last_ts)));
      btn.addEventListener('click', () => { openSite = open ? null : key; if (!open) loadSiteRows(key); else renderBrowser(); });
      const li = h('li', { class: 'rpt-site-item' + (open ? ' open' : '') }, btn);
      if (open) {
        const entry = siteRows.get(key);
        if (!entry || (entry.loading && !entry.rows.length)) li.appendChild(h('p', { class: 'muted rpt-site-loading' }, 'Loading…'));
        else {
          li.appendChild(h('ul', { class: 'rpt-site-reports' }, entry.rows.map((r) => {
            const b = h('button', { class: 'rpt-report-btn', type: 'button', 'aria-current': String(r.id === selectedId) },
              h('span', { class: 'rpt-report-when' }, when(r.created_ts), r.status === 'partial' ? h('span', { class: 'badge yellow' }, 'partial') : null),
              h('span', { class: 'rpt-report-nums' }, U.summaryLine(r.summary)));
            b.addEventListener('click', () => selectReport(r.id, { scroll: true }));
            return h('li', null, b);
          })));
          if (entry.total > entry.rows.length) {
            const older = h('button', { class: 'btn btn-sm rpt-older', type: 'button', disabled: !!entry.loading },
              entry.loading ? 'Loading…' : 'Show older (' + (entry.total - entry.rows.length) + ' more)');
            older.addEventListener('click', () => loadSiteRows(key, true));
            li.appendChild(older);
          }
        }
      }
      ul.appendChild(li);
    }
    box.appendChild(ul);
  }

  async function loadLists(selectAfter) {
    if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
    try {
      const [list, st] = await Promise.all([TNT.api.reports({ limit: LIST_LIMIT }), TNT.api.reportSites('', LIST_LIMIT)]);
      if (!root) return;
      reports = (list && Array.isArray(list.reports) ? list.reports : []).slice().sort((a, b) => (b.created_ts || 0) - (a.created_ts || 0));
      total = Number(list && list.total) || reports.length;
      sites = st && Array.isArray(st.sites) ? st.sites : [];
      sitesTotal = Number(st && st.total) || sites.length;
      listsLoaded = true;
      listsError = null;
      retries = 0;
    } catch (err) {
      if (!root) return;
      listsError = err.message;
      // read again by itself, less and less often; Retry reads at once
      retryTimer = setTimeout(() => { retryTimer = null; if (root) loadLists(selectAfter); }, RETRY_MS[Math.min(retries++, RETRY_MS.length - 1)]);
      if (!listsLoaded) { renderReport(); renderBrowser(); runCompare(); }
      return;
    }
    siteRows.clear();
    renderPickers();
    const hashed = hashId();
    const listed = (id) => id != null && knownRows().some((r) => r.id === id);
    // a report named in the address may be older than the reports listed: it is read anyway (a 404 falls back to the newest)
    const want = selectAfter != null ? selectAfter : listed(selectedId) ? selectedId : hashed != null ? hashed : newestId();
    if (want == null) { selectedId = null; selected = null; renderReport(); renderBrowser(); runCompare(); return; }
    if (want !== selectedId || !selected || selectAfter != null) selectReport(want, { hash: selectAfter != null || hashed != null });
    else { renderReport(); renderBrowser(); if (openSite) loadSiteRows(openSite); }
    runCompare();
  }

  function scheduleLists(selectAfter) {
    if (listsTimer) clearTimeout(listsTimer);
    listsTimer = setTimeout(() => { listsTimer = null; if (root) loadLists(selectAfter); }, 400);
  }

  function hashId() {
    const m = /[?&]id=(\d+)/.exec(location.hash || '');
    return m ? Number(m[1]) : null;
  }

  /* ------------------------------------------------------------ compare */
  function renderPickers() {
    const { h } = TNT.util;
    const U = RU();
    if (!els.cmpA) return;
    // the newest reports and any older ones read since (a site's "Show older", a search for B, a report opened by its address)
    const rows = knownRows().sort((x, y) => (y.created_ts || 0) - (x.created_ts || 0));
    const newest = reports[0];
    // date first, then the site: a narrow select cuts the end of the text, and scans of one site differ only by their date
    const optionText = (g, it) => shortWhen(it.created_ts) + ' · ' + g.site + (/ · partial$/.test(it.label) ? ' · partial' : '');
    const optgroups = (gs, selectedValue) => gs.map((g) => h('optgroup', { label: g.site }, g.items.map((it) => h('option', { value: String(it.id), selected: String(it.id) === selectedValue }, optionText(g, it)))));
    els.cmpA.innerHTML = '';
    els.cmpA.appendChild(h('option', { value: 'current', selected: cmp.a === 'current' }, newest ? 'Current scan · ' + shortWhen(newest.created_ts) + ' · ' + newest.site : 'Current scan (none yet)'));
    for (const og of optgroups(U.reportOptions(rows, '', shortWhen), cmp.a)) els.cmpA.appendChild(og);
    if (cmp.a !== 'current' && !rows.some((r) => String(r.id) === cmp.a)) { cmp.a = 'current'; els.cmpA.value = 'current'; }
    if (!cmp.bPicked && listsLoaded) {
      // until B is picked: the one picked on an earlier visit (a known good network), else the previous scan of A's site, worked out
      // again whenever A or the newest report changes
      let remembered = null;
      try { remembered = localStorage.getItem(COMPARE_B_STORE); } catch (e) { /* no storage */ }
      const aId = cmp.a === 'current' ? (newest && newest.id) : Number(cmp.a);
      const b = U.defaultCompareB(rows, aId, remembered);
      cmp.b = b == null ? '' : String(b);
    }
    if (cmp.b && !rows.some((r) => String(r.id) === cmp.b)) cmp.b = '';
    const filtered = U.reportOptions(rows, cmp.filterB, shortWhen);
    els.cmpB.innerHTML = '';
    els.cmpB.appendChild(h('option', { value: '', selected: !cmp.b }, filtered.length ? 'Pick a report…' : 'No report matches'));
    // the chosen report stays in the list even when the search leaves it out
    if (cmp.b && !filtered.some((g) => g.items.some((it) => String(it.id) === cmp.b))) {
      const r = rows.find((x) => String(x.id) === cmp.b);
      if (r) els.cmpB.appendChild(h('option', { value: cmp.b, selected: true }, shortWhen(r.created_ts) + ' · ' + r.site));
    }
    for (const og of optgroups(filtered, cmp.b)) els.cmpB.appendChild(og);
    els.cmpB.value = cmp.b || '';
    els.cmpA.disabled = !rows.length;
    els.cmpB.disabled = !rows.length;
  }

  /** B's search box and more reports than were read: ask the service for the sites that match (older reports included). */
  function scheduleCompareSearch() {
    if (cmp.searchTimer) { clearTimeout(cmp.searchTimer); cmp.searchTimer = null; }
    const q = RU().normalizeSite(cmp.filterB);
    if (!q || total <= reports.length) return;
    cmp.searchTimer = setTimeout(async () => {
      cmp.searchTimer = null;
      const mine = ++cmp.searchSeq;
      try {
        const r = await TNT.api.reports({ q, limit: LIST_LIMIT });
        if (!root || mine !== cmp.searchSeq) return;
        rememberRows(r && r.reports);
        renderPickers();
      } catch (e) { /* the reports read already stay */ }
    }, 250);
  }

  function compareIds() {
    const a = cmp.a === 'current' ? newestId() : Number(cmp.a);
    const b = cmp.b ? Number(cmp.b) : null;
    return { a, b };
  }

  async function runCompare() {
    const { h } = TNT.util;
    if (!els.cmpBody) return;
    const { a, b } = compareIds();
    const mine = ++cmp.seq;
    els.cmpPdf.disabled = true;
    els.cmpHead.textContent = '';
    els.cmpNotes.textContent = '';
    const say = (text) => { els.cmpBody.innerHTML = ''; els.cmpBody.appendChild(h('p', { class: 'muted rpt-cmp-empty' }, text)); };
    if (!listsLoaded && listsError) { els.cmpBody.innerHTML = ''; els.cmpBody.appendChild(errorBox('Could not load the reports: ' + listsError)); return; }
    if (!listsLoaded) { say('Loading…'); return; }
    if (knownRows().length < 2) { say('Comparing needs two saved reports: run a Full Scan here and one on a network you know is good.'); return; }
    if (a == null || b == null) { say('Pick report B: another scan of this site, or a known good network.'); return; }
    if (a === b) { say('A and B are the same report: pick another one for B.'); return; }
    els.cmpBody.setAttribute('aria-busy', 'true');
    say('Comparing…');
    try {
      const data = await TNT.api.compareReports(a, b);
      if (!root || mine !== cmp.seq) return;
      cmp.data = data;
      renderCompare(data);
      els.cmpPdf.disabled = false;
    } catch (err) {
      if (!root || mine !== cmp.seq) return;
      say('Could not compare the reports: ' + err.message);
    } finally { if (root && mine === cmp.seq) els.cmpBody.removeAttribute('aria-busy'); }
  }

  /** A comparison cell's difference as two unbreakable pieces, the arrow with the change and then its percentage
   *  ("▲+8.14/day", "(+294%)"), so a narrow column wraps between them and never inside a number or its unit. */
  function diffParts(c) {
    const { h } = TNT.util;
    const m = /^(.*\S) (\([^()]*\))$/.exec(String(c.diff));
    const arrow = c.arrow ? h('span', { class: 'cmp-arrow', 'aria-hidden': 'true' }, c.arrow) : null;
    if (!m) return [h('span', { class: 'cmp-abs' }, arrow, c.diff)];
    return [h('span', { class: 'cmp-abs' }, arrow, m[1]), ' ', h('span', { class: 'cmp-rel' }, m[2])];
  }

  function renderCompare(data) {
    const { h } = TNT.util;
    const U = RU();
    const side = (s, tag) => h('span', { class: 'rpt-cmp-side' }, h('span', { class: 'rpt-cmp-tag' }, tag), h('strong', null, (s && s.site) || '?'), ' · ' + when(s && s.created_ts));
    els.cmpHead.innerHTML = '';
    els.cmpHead.append(side(data.a, 'A'), h('span', { class: 'muted' }, ' vs '), side(data.b, 'B'));
    // what the two reports are made of: their visits and time on their networks, or that both are the same network
    els.cmpNotes.innerHTML = '';
    for (const note of (Array.isArray(data.notes) ? data.notes : [data.note]).filter((n) => typeof n === 'string' && n.trim())) {
      els.cmpNotes.appendChild(h('p', { class: 'cmp-sec-note' }, note));
    }
    els.cmpBody.innerHTML = '';
    const grid = h('div', { class: 'rpt-cmp-grid' });
    for (const sec of Array.isArray(data.sections) ? data.sections : []) {
      const rows = Array.isArray(sec.rows) ? sec.rows : [];
      // the section's note says what either report could not collect ("A: No TNT window was open to scan Wi-Fi")
      const box = h('section', { class: 'rpt-cmp-sec', 'aria-label': 'Compare ' + (sec.title || sec.key) }, h('h4', null, sec.title || sec.key),
        sec.note ? h('p', { class: 'cmp-sec-note' }, sec.note) : null);
      if (!rows.length) { box.appendChild(h('p', { class: 'muted' }, 'Nothing to compare: neither report has these numbers.')); grid.appendChild(box); continue; }
      const only = U.oneSided(rows);
      if (only) {
        // one report did not collect this section: its numbers once, not a column of dashes beside them
        const tag = only.toUpperCase();
        box.appendChild(h('p', { class: 'cmp-sec-note' }, 'Only ' + tag + ' has these numbers.'));
        box.appendChild(tableWrap(h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Metric'), h('th', { class: 'num', scope: 'col' }, tag))),
          h('tbody', null, rows.filter((row) => !String(row.key).startsWith('ssid:')).map((row) => h('tr', { class: 'cmp-info' },
            h('td', { class: 'cmp-metric' }, h('span', null, row.label || row.key)), h('td', { class: 'num cmp-val' }, U.fmtValue(row[only], row.unit || ''))))),
          'rpt-table rpt-cmp-table rpt-cmp-one'));
        grid.appendChild(box);
        continue;
      }
      const thead = h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Metric'), h('th', { class: 'num', scope: 'col' }, 'A'), h('th', { class: 'num', scope: 'col' }, 'B'),
        h('th', { class: 'num', scope: 'col', title: 'A minus B, and how much that is of B' }, 'A − B')));
      const tbody = h('tbody');
      for (const row of rows) {
        const c = U.compareCell(row);
        tbody.appendChild(h('tr', { class: row.higher_is_better == null ? 'cmp-info' : null },
          h('td', { class: 'cmp-metric' }, h('span', null, row.label || row.key), row.note ? h('span', { class: 'cmp-note' }, row.note) : null),
          h('td', { class: 'num cmp-val' + (c.aCls ? ' cmp-' + c.aCls : '') }, c.a),
          h('td', { class: 'num cmp-val' + (c.bCls ? ' cmp-' + c.bCls : '') }, c.b),
          h('td', { class: 'num cmp-diff' + (c.diffCls ? ' cmp-' + c.diffCls : ''), title: c.verdict || '' },
            ...diffParts(c), c.verdict ? h('span', { class: 'sr-only' }, ' (' + c.verdict + ')') : null)));
      }
      box.appendChild(tableWrap(thead, tbody, 'rpt-table rpt-cmp-table'));
      grid.appendChild(box);
    }
    els.cmpBody.appendChild(grid);
    els.cmpBody.appendChild(h('p', { class: 'rpt-note' }, 'Green is the better value and red the worse one; grey rows are for information. Loss differences are in percentage points (pts). ' +
      'Outage rates are per day monitored, compared only when both reports have a day of history; otherwise each window\'s counts are shown.'));
  }

  async function exportCompare() {
    const { a, b } = compareIds();
    if (a == null || b == null || a === b) return;
    TNT.ui.busy(els.cmpPdf, true, 'Building PDF…');
    try {
      const r = await TNT.api.comparePdf(a, b);
      const rows = knownRows();
      const ra = rows.find((x) => x.id === a), rb = rows.find((x) => x.id === b);
      await TNT.app.saveBlob(r.blob, r.filename || RU().compareFilename(ra && ra.site, rb && rb.site));
    } catch (err) { toast('Export failed: ' + err.message, 'error'); }
    finally { TNT.ui.busy(els.cmpPdf, false); if (root) els.cmpPdf.disabled = !cmp.data; }
  }

  /* ------------------------------------------------------ progress card */
  function buildProgress(job) {
    const { h } = TNT.util;
    const card = els.progress;
    if (els.pr && els.pr.combo) els.pr.combo.destroy();
    card.innerHTML = '';
    nameOpen = false;
    const pr = els.pr = { jobId: job.id, announced: '' };
    pr.icon = h('span', { class: 'rpt-prog-icon', 'aria-hidden': 'true' });
    pr.title = h('strong', { class: 'rpt-prog-title' });
    pr.site = h('span', { class: 'rpt-prog-site', id: 'rpt-prog-site' });
    pr.pct = h('span', { class: 'rpt-prog-pct' });
    // "Change" beside a suggested site: its name says what it changes
    pr.rename = h('button', { class: 'btn btn-sm', type: 'button', 'aria-label': 'Change site name', on: { click: () => openName(true) } }, 'Change name');
    pr.cancel = h('button', { class: 'btn btn-sm rpt-danger', type: 'button', on: { click: cancelScan } }, TNT.ui.icon('stop'), 'Cancel');
    pr.open = h('button', { class: 'btn btn-sm btn-primary', type: 'button', hidden: true,
      on: { click: () => { const j = TNT.app.fullScan.job; if (j && j.report_id != null) selectReport(j.report_id, { scroll: true }); } } }, 'Open report');
    // a scan saved before anyone named it, on a network no earlier report was made on: its report is "Unnamed site" until renamed
    pr.nameIt = h('button', { class: 'btn btn-sm', type: 'button', hidden: true,
      on: { click: () => { const j = TNT.app.fullScan.job; if (j && j.report_id != null) renameReport({ id: j.report_id, site: RU().jobSite(j).site || 'Unnamed site', created_ts: j.started_ts }); } } }, 'Name it');
    pr.dismiss = h('button', { class: 'btn btn-sm rpt-icon-btn', type: 'button', 'aria-label': 'Dismiss', title: 'Dismiss', hidden: true,
      on: { click: () => { dismissedJob = pr.jobId; card.hidden = true; } } }, TNT.ui.icon('close'));
    pr.fill = h('span', { class: 'rpt-bar-fill' });
    pr.bar = h('div', { class: 'rpt-bar', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': '0', 'aria-label': 'Full scan progress' }, pr.fill);
    pr.window = h('p', { class: 'rpt-prog-window', hidden: true });
    pr.combo = RU().siteCombo({ label: 'Site name', placeholder: 'e.g. Acme Dental', describedBy: 'rpt-prog-site',
      fetchSites: (q) => TNT.api.reportSites(q, 50).then((r) => (r && r.sites) || []), onEnter: () => saveName() });
    // Escape with the suggestions closed puts the name back (the combobox closes an open list itself first)
    pr.combo.input.addEventListener('keydown', (e) => { if (e.key === 'Escape' && nameOpen && !pr.combo.isOpen()) { e.preventDefault(); openName(false); } });
    pr.save = h('button', { class: 'btn btn-sm btn-primary', type: 'button', on: { click: () => saveName() } }, 'Save name');
    pr.nameCancel = h('button', { class: 'btn btn-sm', type: 'button', hidden: true, on: { click: () => openName(false) } }, 'Cancel');
    pr.nameRow = h('div', { class: 'rpt-prog-name' }, h('label', { for: pr.combo.input.id }, 'Site name'), pr.combo.el, pr.save, pr.nameCancel);
    pr.phases = h('ol', { class: 'rpt-phases' });
    pr.status = h('p', { class: 'sr-only', role: 'status' });
    card.append(h('div', { class: 'rpt-prog-head' }, pr.icon, pr.title, pr.site, h('span', { class: 'spacer' }), pr.pct, pr.rename, pr.cancel, pr.open, pr.nameIt, pr.dismiss),
      pr.bar, pr.window, pr.nameRow, pr.phases, pr.status);
  }

  /** "Change name" ("Change" for a suggested site) opens the name field with the scan's site in it, selected; its Cancel (or
   *  Escape) closes it again. */
  function openName(on) {
    const pr = els.pr;
    if (!pr) return;
    const job = TNT.app.fullScan.job;
    nameOpen = !!on;
    updateProgress(job);
    if (on) {
      pr.combo.setValue(RU().jobSite(job).site || '');
      pr.combo.focus();
      try { pr.combo.input.select(); } catch (e) { /* ignore */ }
    } else pr.rename.focus();
  }

  function updateProgress(job) {
    const { h } = TNT.util;
    const U = RU();
    const card = els.progress;
    if (!card) return;
    if (!job || job.id == null) { card.hidden = true; return; }
    const running = job.status === 'running';
    if (!running && (!els.pr || els.pr.jobId !== job.id || dismissedJob === job.id)) { card.hidden = true; return; }
    if (!els.pr || els.pr.jobId !== job.id) buildProgress(job);
    const pr = els.pr;
    card.hidden = false;
    const phases = U.jobPhases(job);
    const partial = phases.some((p) => p.status === 'error' || p.status === 'skipped');
    const iconName = running ? 'spark' : job.status === 'saved' ? 'check' : job.status === 'cancelled' ? 'stop' : 'warning';
    if (pr.iconName !== iconName) { pr.iconName = iconName; pr.icon.innerHTML = ''; pr.icon.appendChild(TNT.ui.icon(iconName)); pr.icon.className = 'rpt-prog-icon is-' + job.status; }
    pr.title.textContent = running ? 'Full scan' : job.status === 'saved' ? (partial ? 'Report saved, partly' : 'Report saved') : job.status === 'cancelled' ? 'Full scan cancelled' : 'Full scan failed';
    const saved = job.status === 'saved';
    // the site: the name given; a network scanned before goes under that report's site unless someone names it
    const named = U.jobSite(job);
    const siteView = [running && named.suggested, named.site, running, saved].join('|');
    if (pr.siteView !== siteView) {
      pr.siteView = siteView;
      pr.site.innerHTML = '';
      if (running && named.suggested) {
        pr.site.append(h('span', { class: 'muted' }, 'Will be saved as '), h('strong', null, named.site), h('span', { class: 'muted' }, ' (this network was scanned before)'));
      } else pr.site.textContent = named.site || (running ? 'site not named yet' : saved ? 'Unnamed site' : '');
    }
    pr.site.classList.toggle('muted', !named.site);
    const pct = Math.max(0, Math.min(100, Math.round(Number(job.pct) || 0)));
    pr.pct.textContent = running ? pct + '%' : '';
    pr.fill.style.width = (saved ? 100 : pct) + '%';
    // a cancelled or failed scan keeps the percentage it reached, and says why it stopped there
    pr.bar.setAttribute('aria-valuenow', String(saved ? 100 : pct));
    if (running || saved) pr.bar.removeAttribute('aria-valuetext');
    else pr.bar.setAttribute('aria-valuetext', (job.status === 'cancelled' ? 'Cancelled at ' : 'Failed at ') + pct + '%');
    pr.bar.classList.toggle('done', saved);
    pr.bar.classList.toggle('stopped', job.status === 'cancelled' || job.status === 'error');
    const win = U.jobWindowText(job, shortWhen);
    pr.window.textContent = win ? 'The report reads pings and outages ' + win + '.' : '';
    pr.window.hidden = !running || !win;
    pr.cancel.hidden = !running;
    const renameText = named.suggested ? 'Change' : 'Change name';
    if (pr.rename.textContent !== renameText) pr.rename.textContent = renameText;
    pr.rename.hidden = !running || !named.site || nameOpen;
    pr.open.hidden = running || !saved || job.report_id == null;
    pr.nameIt.hidden = running || !saved || job.report_id == null || !!(named.site && named.site !== 'Unnamed site');
    pr.dismiss.hidden = running;
    // the name modal has the same field: one on screen at a time; a suggested site needs no field until "Change"
    const modalOpen = !!(TNT.app.siteModalOpen && TNT.app.siteModalOpen());
    const showName = running && (!named.site || nameOpen) && !modalOpen;
    if (pr.nameRow.hidden === showName) pr.nameRow.hidden = !showName;
    pr.nameCancel.hidden = !nameOpen;
    if (!showName) pr.combo.close();
    pr.phases.innerHTML = '';
    for (const p of phases) {
      const icon = { done: 'check', running: 'spark', error: 'warning', skipped: 'warning' }[p.status];
      const took = p.started_ts != null && p.finished_ts != null ? U.durationText(p.finished_ts - p.started_ts) : '';
      pr.phases.appendChild(h('li', { class: 'rpt-phase ph-' + p.status },
        h('span', { class: 'ph-icon', 'aria-hidden': 'true' }, icon ? TNT.ui.icon(icon) : null),
        h('span', { class: 'ph-label' }, p.label), h('span', { class: 'ph-state' }, p.status),
        h('span', { class: 'ph-msg', title: p.message }, p.message), h('span', { class: 'ph-time' }, took)));
    }
    if (job.error && !running) pr.phases.appendChild(h('li', { class: 'rpt-phase ph-error' }, h('span', { class: 'ph-icon' }, TNT.ui.icon('warning')), h('span', { class: 'ph-msg' }, job.error)));
    // the live region names the phase and the outcome, not every percent
    const current = phases.find((p) => p.status === 'running');
    const phaseSay = running ? (current ? current.label + ' running' : 'Full scan running') : pr.title.textContent + (named.site ? ': ' + named.site : '');
    let say = phaseSay;
    // a suggested site is announced once (a screen reader user who closed the name modal hears where the report goes), until the phase moves on
    if (running && named.suggested && named.site) {
      if (pr.saidSite !== named.site) { pr.saidSite = named.site; pr.saidAt = phaseSay; }
      if (pr.saidAt === phaseSay) say = 'Full scan running, will be saved as ' + named.site;
    }
    if (pr.announced !== say) { pr.announced = say; pr.status.textContent = say; }
  }

  function onJob(job, prev) {
    if (!root) return;
    if (els.scanLabel) els.scanLabel.textContent = RU().jobButton(job).label;          // worded like the top bar's button
    // coalesced on a timer, not an animation frame: a hidden or minimised TNT window runs no frames but should still
    // show the right card when it comes back
    if (!progressFrame) {
      progressFrame = setTimeout(() => { progressFrame = null; if (root) updateProgress(TNT.app.fullScan.job); }, 60);
    }
    // a scan this page watched saved its report: list it and show it (once per report)
    if (job && job.status === 'saved' && job.report_id != null && prev && prev.id === job.id && prev.status === 'running' && autoSelected !== job.report_id) {
      autoSelected = job.report_id;
      loadLists(job.report_id);
    }
  }

  async function saveName() {
    const pr = els.pr;
    if (!pr) return;
    const site = pr.combo.value();
    if (!site) { toast('Type the site name', 'warn'); pr.combo.focus(); return; }
    TNT.ui.busy(pr.save, true, 'Saving…');
    try {
      await TNT.app.nameFullScan(site);
      nameOpen = false;
      if (root) updateProgress(TNT.app.fullScan.job);
    } catch (err) { toast('Could not save the name: ' + err.message, 'error'); }
    finally { TNT.ui.busy(pr.save, false); }
  }

  async function cancelScan() {
    const ok = await TNT.ui.confirm({ title: 'Cancel the full scan?', message: 'The scan stops and no report is saved.', ok: 'Cancel scan', cancel: 'Keep scanning', danger: true });
    if (!ok) return;
    try { await TNT.app.fullScan.cancel(); toast('Full scan cancelled', 'warn'); }
    catch (err) { toast('Could not cancel the scan: ' + err.message, 'error'); }
  }

  /* ------------------------------------------------------------ the page */
  TNT.views.reports = {
    mount(el) {
      const { h } = TNT.util;
      root = el;
      els = {};
      reports = []; sites = []; total = 0; sitesTotal = 0; listsLoaded = false; listsError = null; retries = 0; openSite = null; siteRows.clear();
      extraRows.clear(); searchSites = null;
      selectedId = null; selected = null; tables = [];
      cmp = { a: 'current', b: null, bPicked: false, filterB: '', seq: 0, data: null, searchSeq: 0, searchTimer: null };
      nameOpen = false; autoSelected = null;
      const hashed = hashId();
      if (hashed != null) selectedId = hashed;

      els.scanLabel = h('span', null, 'Full Scan');
      const scanBtn = h('button', { class: 'btn btn-primary', type: 'button', on: { click: () => TNT.app.fullScanClick() } }, TNT.ui.icon('report'), els.scanLabel);
      els.search = h('input', { class: 'input rpt-search', type: 'search', placeholder: 'Search sites', 'aria-label': 'Search saved reports by site name', autocomplete: 'off', spellcheck: 'false',
        'aria-controls': 'rpt-browser' });
      els.search.addEventListener('input', () => { renderBrowser(); scheduleSiteSearch(); });
      els.head = h('div', { class: 'section-head' },
        h('h2', null, h('span', { class: 'section-accent' }), 'Reports'),
        h('div', { class: 'actions' }, scanBtn, els.search));
      els.progress = h('section', { class: 'card rpt-progress', 'aria-label': 'Full scan', hidden: true });
      els.main = h('section', { class: 'card rpt-report', 'aria-label': 'Report' });
      els.browserCount = h('span', { class: 'muted rpt-count' });
      els.browser = h('div', { class: 'rpt-browser-body' });
      // headings, so a screen reader's heading list reaches the browser and Compare like the report's sections
      const side = h('aside', { class: 'card rpt-browser', id: 'rpt-browser', 'aria-label': 'Saved reports' },
        h('h3', { class: 'card-title' }, 'Saved reports', els.browserCount), els.browser);
      els.cmpA = h('select', { class: 'input', id: 'rpt-cmp-a', 'aria-label': 'Report A' });
      els.cmpB = h('select', { class: 'input', id: 'rpt-cmp-b', 'aria-label': 'Report B' });
      els.cmpFilter = h('input', { class: 'input rpt-cmp-filter', type: 'search', placeholder: 'Search site or date', 'aria-label': 'Search the reports for B', autocomplete: 'off', spellcheck: 'false' });
      els.cmpA.addEventListener('change', () => {
        cmp.a = els.cmpA.value;
        renderPickers();
        runCompare();
      });
      els.cmpB.addEventListener('change', () => {
        cmp.b = els.cmpB.value;
        cmp.bPicked = !!cmp.b;
        try { if (cmp.b) localStorage.setItem(COMPARE_B_STORE, cmp.b); } catch (e) { /* no storage */ }
        runCompare();
      });
      els.cmpFilter.addEventListener('input', () => { cmp.filterB = els.cmpFilter.value; renderPickers(); scheduleCompareSearch(); });
      const swap = h('button', { class: 'btn btn-sm rpt-icon-btn', type: 'button', 'aria-label': 'Swap A and B', title: 'Swap A and B' }, TNT.ui.icon('swap'));
      swap.addEventListener('click', () => {
        const { a, b } = compareIds();
        if (a == null || b == null) return;
        cmp.a = String(b); cmp.b = String(a); cmp.bPicked = true;
        renderPickers();
        runCompare();
      });
      els.cmpPdf = h('button', { class: 'btn btn-sm', type: 'button', disabled: true, on: { click: exportCompare } }, TNT.ui.icon('download'), 'Export comparison PDF');
      els.cmpHead = h('p', { class: 'rpt-cmp-head' });
      els.cmpNotes = h('div', { class: 'rpt-cmp-notes' });
      els.cmpBody = h('div', { class: 'rpt-cmp-body' });
      els.compare = h('section', { class: 'card rpt-compare', 'aria-label': 'Compare reports' },
        h('h3', { class: 'card-title' }, TNT.ui.icon('swap'), 'Compare', h('span', { class: 'muted rpt-count' }, 'a scan against any saved scan, such as a known good network')),
        h('div', { class: 'rpt-cmp-pick' },
          h('div', { class: 'field' }, h('label', { for: 'rpt-cmp-a' }, 'A'), els.cmpA),
          swap,
          h('div', { class: 'field' }, h('label', { for: 'rpt-cmp-b' }, 'B'), h('div', { class: 'rpt-cmp-bpick' }, els.cmpFilter, els.cmpB)),
          els.cmpPdf),
        els.cmpHead, els.cmpNotes, els.cmpBody);
      const page = h('div', { class: 'rpt' }, els.head, els.progress,
        h('div', { class: 'rpt-layout' }, els.main, side), els.compare);
      root.appendChild(page);
      renderReport();
      renderBrowser();
      renderPickers();
      runCompare();
      loadLists();
      unsubs.push(TNT.app.fullScan.subscribe(onJob));
      onJob(TNT.app.fullScan.job, null);
      const relist = () => scheduleLists();
      unsubs.push(TNT.api.events.on('report.saved', relist));
      unsubs.push(TNT.api.events.on('report.updated', (d) => { siteRows.clear(); if (d && d.id === selectedId && selected) selected = Object.assign({}, selected, { site: d.site }); relist(); }));
      unsubs.push(TNT.api.events.on('report.deleted', (d) => {
        siteRows.clear();
        if (d) extraRows.delete(d.id);
        if (d && hashId() === d.id) setHash(null);
        if (d && d.id === selectedId) { selectedId = null; selected = null; }
        relist();
      }));
      unsubs.push(TNT.api.events.on('hello', relist));
      const onHash = () => { const id = hashId(); if (root && id != null && id !== selectedId && location.hash.indexOf('#reports') === 0) selectReport(id, { hash: false }); };
      window.addEventListener('hashchange', onHash);
      unsubs.push(() => window.removeEventListener('hashchange', onHash));
    },
    update() { /* everything comes from /api/reports and the full-scan controller, nothing from the status snapshot */ },
    /** The Full Scan button was pressed while this page is open: bring the progress card (or the heading) into view. */
    reveal() {
      if (!root) return;
      scrollIntoViewSoft(els.progress && !els.progress.hidden ? els.progress : els.head);
    },
    /** The app's site name modal opened or closed: the progress card shows its own name field only while that modal is closed. */
    siteModalChanged() {
      if (root) updateProgress(TNT.app.fullScan.job);
    },
    unmount() {
      for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
      unsubs = [];
      if (listsTimer) { clearTimeout(listsTimer); listsTimer = null; }
      if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
      if (searchTimer) { clearTimeout(searchTimer); searchTimer = null; }
      if (cmp.searchTimer) { clearTimeout(cmp.searchTimer); cmp.searchTimer = null; }
      if (progressFrame) { clearTimeout(progressFrame); progressFrame = null; }
      if (els.pr && els.pr.combo) els.pr.combo.destroy();
      destroyTables();
      root = null; els = {}; selected = null; reports = []; sites = []; siteRows.clear();
    },
  };
})();
