/* TNT — views/outages.js
   24 h timeline (canvas) + outage list, newest first. Refreshes every 60 s and on outage events. */
(function () {
  'use strict';
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  let root = null, timeline = null, tableBody = null, summaryEl = null, listTitle = null, refreshBtn = null;
  let timer = null, unsubs = [], reloadTimer = null;
  // range in hours: 15 min, 1 h, 6 h, 24 h, 7 d, 30 d (drives the timeline and the list)
  const RANGES = [[0.25, '15 m', '15 minutes'], [1, '1 h', 'hour'], [6, '6 h', '6 hours'], [24, '24 h', '24 hours'], [168, '7 d', '7 days'], [720, '30 d', '30 days']];
  let rangeH = 24, loading = false;
  let lastTl = null, tlTitle = null;
  function rangeName(h) { const r = RANGES.find((x) => x[0] === h); return r ? r[2] : h + ' h'; }

  function kindCell(o) {
    const { h } = TNT.util;
    const row = { class: 'row', style: { gap: '8px', flexWrap: 'nowrap' } };
    if (o.kind === 'total_internet') return h('span', row, h('span', { class: 'badge red' }, 'internet'), 'All internet targets down');
    if (o.kind === 'total_local') return h('span', row, h('span', { class: 'badge red' }, 'local'), 'All local targets down');
    if (o.kind === 'gap') return h('span', row, h('span', { class: 'badge grey' }, 'gap'), h('span', { class: 'muted' }, 'Not monitoring'));
    return h('span', row, h('span', { class: 'badge yellow' }, 'target'), TNT.util.copyCode(o.host || ('target ' + o.target_id)));
  }

  /* Pure: the Missed Pings / Missed % cells for one outage row -> { pings, pct, title }.
     Only target outages count pings; total and gap rows show a dash in both. The percentage is
     floored to one decimal so it never reads 100% while a single ping still got through. */
  function missedCells(o) {
    if (!o || o.kind !== 'target') return { pings: '—', pct: '—', title: '' };
    const missed = o.missed != null ? Number(o.missed) : null;
    const pings = missed != null && isFinite(missed) ? String(missed) : '—';
    const p = o.missed_pct;
    if (p == null || !isFinite(p)) return { pings, pct: '—', title: '' };
    let pct;
    if (p >= 100) pct = '100%';
    else if (p <= 0) pct = '0%';
    else if (p < 0.1) pct = '<0.1%';
    else pct = (Math.floor(p * 10) / 10).toFixed(1) + '%';
    const sent = o.sent != null ? Number(o.sent) : null;
    let title = sent != null && missed != null ? missed + ' of ' + sent + ' pings missed' : '';
    if (o.sent_estimated) title += (title ? ' - ' : '') + 'estimated from the outage length (recorded before TNT counted the pings sent)';
    return { pings, pct: (o.sent_estimated ? '≈' : '') + pct, title };
  }

  /** One outage table row (a <tr>), the row the Outages list draws. Reused by the Ping tile's
   *  detail modal so its "last 5 outages" list is exactly the same. */
  function outageRow(o, now) {
    const { h, fmtDateTime, fmtDateTimeSec, fmtTime, fmtDuration } = TNT.util;
    const open = !!o.open || o.end_ts == null;
    const dur = o.duration_s != null ? o.duration_s : ((open ? now : o.end_ts) - o.start_ts);
    return h('tr', null,
      h('td', { class: 'copy', data: { copy: TNT.util.fmtStamp(o.start_ts) } }, fmtDateTimeSec(o.start_ts)),
      // an open target outage is yellow; only an open full (total_*) outage is red
      h('td', { class: 'copy', data: { copy: open ? 'ongoing' : TNT.util.fmtStamp(o.end_ts) } }, open ? h('span', { class: 'badge ' + (String(o.kind || '').startsWith('total') ? 'red' : 'yellow') + ' pulse' }, 'ongoing') : (new Date(o.end_ts * 1000).toDateString() === new Date(o.start_ts * 1000).toDateString() ? fmtTime(o.end_ts) : fmtDateTime(o.end_ts))),
      h('td', { class: 'copy num' }, fmtDuration(dur)),
      h('td', null, kindCell(o)),
      h('td', { class: 'copy num' }, missedCells(o).pings),
      h('td', { class: 'copy num', title: missedCells(o).title || null }, missedCells(o).pct),
      h('td', { class: 'wrap muted small' }, o.note || ''));
  }

  /** The Outages table header row (Started / Ended / Duration / What / Missed Pings / Missed % / Note). */
  function outageHead() {
    const { h } = TNT.util;
    return h('thead', null, h('tr', null, h('th', null, 'Started'), h('th', null, 'Ended'), h('th', { class: 'num' }, 'Duration'),
      h('th', null, 'What'), h('th', { class: 'num' }, 'Missed Pings'), h('th', { class: 'num' }, 'Missed %'), h('th', null, 'Note')));
  }

  /** A complete outages table (a `.table-wrap`) for the given rows — the same look as the Outages list. */
  function outageTable(rows, emptyMsg) {
    const { h } = TNT.util;
    const body = h('tbody');
    const now = TNT.util.nowS();
    if (!rows || !rows.length) body.appendChild(h('tr', { class: 'empty-row' }, h('td', { colspan: '7' }, emptyMsg || 'No outages in this period — nice and quiet.')));
    else for (const o of rows) body.appendChild(outageRow(o, now));
    return h('div', { class: 'table-wrap' }, h('table', { class: 'table' }, outageHead(), body));
  }

  function renderList(rows) {
    tableBody.innerHTML = '';
    const now = TNT.util.nowS();
    if (!rows.length) tableBody.appendChild(TNT.util.h('tr', { class: 'empty-row' }, TNT.util.h('td', { colspan: '7' }, 'No outages in this period — nice and quiet.')));
    else for (const o of rows) tableBody.appendChild(outageRow(o, now));
  }

  function renderSummary(tl, rows) {
    const { h, fmtDuration } = TNT.util;
    summaryEl.innerHTML = '';
    if (!tl) return;
    const spans = (tl.segments || []).concat(tl.total_segments || []);
    const totals = (tl.total_segments || []).length;
    const n = (tl.segments || []).length + totals;
    let longest = 0;
    for (const s of spans) longest = Math.max(longest, (s.open ? tl.end_ts : s.end_ts) - s.start_ts);
    const ongoing = spans.filter((s) => s.open).length;
    const ongoingTotal = (tl.total_segments || []).some((s) => s.open);
    summaryEl.appendChild(h('span', { class: 'strong' }, n === 0 ? 'No outages in the last ' + rangeName(rangeH) : n + (n === 1 ? ' outage' : ' outages') + ' in the last ' + rangeName(rangeH)));
    if (totals) summaryEl.appendChild(h('span', { class: 'badge red' }, totals + ' total'));
    if (ongoing) summaryEl.appendChild(h('span', { class: 'badge ' + (ongoingTotal ? 'red' : 'yellow') + ' pulse' }, 'ongoing'));
    if (longest) summaryEl.appendChild(h('span', { class: 'muted' }, 'longest ' + fmtDuration(longest)));
    if ((tl.gaps || []).length) summaryEl.appendChild(h('span', { class: 'muted' }, (tl.gaps.length === 1 ? '1 gap' : tl.gaps.length + ' gaps') + ' in monitoring'));
  }

  async function load() {
    if (!root || loading) return;
    loading = true;
    TNT.ui.busy(refreshBtn, true);
    const now = TNT.util.nowS();
    try {
      const [tl, list] = await Promise.all([TNT.api.timeline(rangeH), TNT.api.outages(now - rangeH * 3600, now)]);
      if (!root) return;
      lastTl = tl;
      timeline.setData(tl);
      const rows = ((list && list.outages) || []).slice().sort((a, b) => b.start_ts - a.start_ts);
      renderList(rows);
      renderSummary(tl, rows);
      if (tlTitle) tlTitle.textContent = 'Last ' + rangeName(rangeH);
      listTitle.textContent = 'Outages — last ' + rangeName(rangeH) + ' (' + rows.length + ')';
    } catch (err) {
      if (root) TNT.ui.toast('Could not load outages: ' + err.message, 'error');
    } finally { loading = false; TNT.ui.busy(refreshBtn, false); }
  }

  function scheduleReload() {
    if (reloadTimer) clearTimeout(reloadTimer);
    reloadTimer = setTimeout(() => { reloadTimer = null; load(); }, 600);
  }

  TNT.views.outages = {
    mount(el) {
      const { h } = TNT.util;
      root = el;
      refreshBtn = h('button', { class: 'btn btn-sm', type: 'button', on: { click: load } }, TNT.ui.icon('refresh'), 'Refresh');
      const seg = TNT.ui.segmented(RANGES.map((r) => ({ value: r[0], label: r[1] })), rangeH, (v) => { rangeH = Number(v); load(); });
      const head = h('div', { class: 'section-head' },
        h('h2', null, h('span', { class: 'section-accent' }), 'Outages'),
        h('div', { class: 'actions' }, seg, refreshBtn));
      summaryEl = h('div', { class: 'row', style: { gap: '10px' } });
      const canvas = h('canvas', { class: 'timeline-canvas', 'aria-label': 'Outage timeline' });
      tlTitle = h('span', null, 'Last 24 hours');
      const legend = h('div', { class: 'legend' },
        h('span', null, h('span', { class: 'sw', style: { background: 'var(--green)' } }), 'fine'),
        h('span', null, h('span', { class: 'sw', style: { background: 'var(--yellow)' } }), 'a target was down'),
        h('span', null, h('span', { class: 'sw', style: { background: 'var(--red)' } }), 'everything down'),
        h('span', null, h('span', { class: 'sw', style: { background: 'repeating-linear-gradient(135deg, var(--paper-2) 0 3px, var(--ink-soft) 3px 5px)' } }), 'not monitoring'));
      const tlCard = h('div', { class: 'card' },
        h('div', { class: 'card-title' }, tlTitle, h('span', { class: 'spacer' }), legend),
        summaryEl,
        h('div', { class: 'chart-wrap', style: { marginTop: '10px' } }, canvas));
      listTitle = h('div', { class: 'card-title' }, 'Outages');
      tableBody = h('tbody');
      const table = h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
        h('thead', null, h('tr', null, h('th', null, 'Started'), h('th', null, 'Ended'), h('th', { class: 'num' }, 'Duration'), h('th', null, 'What'), h('th', { class: 'num' }, 'Missed Pings'), h('th', { class: 'num' }, 'Missed %'), h('th', null, 'Note'))),
        tableBody));
      const listCard = h('div', { class: 'card' }, listTitle, table);
      root.appendChild(head);
      root.appendChild(h('div', { class: 'stack' }, tlCard, listCard));
      timeline = new TNT.charts.Timeline(canvas);
      renderList([]);
      load();
      timer = setInterval(load, 60000);
      unsubs.push(TNT.api.events.on('outage.start', scheduleReload));
      unsubs.push(TNT.api.events.on('outage.end', scheduleReload));
      unsubs.push(TNT.api.events.on('hello', scheduleReload));
    },
    update() { /* data is fetched directly; nothing derived from the status snapshot */ },
    // an outage the service closes because the PC changed networks carries a note: show it
    netChanged() { if (root) scheduleReload(); },
    unmount() {
      if (timer) { clearInterval(timer); timer = null; }
      if (reloadTimer) { clearTimeout(reloadTimer); reloadTimer = null; }
      for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
      unsubs = [];
      if (timeline) { timeline.destroy(); timeline = null; }
      root = null; tableBody = null; summaryEl = null; listTitle = null; refreshBtn = null; lastTl = null; tlTitle = null;
    },
    // exposed for tests and for the Ping tile's detail modal (its "last 5 outages" list)
    missedCells,
    outageTable,
    outageRow,
    kindCell,
  };
})();
