/* TNT — views/faults.js
   The Faults page: what the passive watch has found, worst first, and the counters behind it.

   Three sources, none of which sends anything or needs an administrator: the adapters' own error
   and discard counters, their live address configuration, and the ARP table watched over time
   (tnt/faults.py). The page is a findings list in the level-tinted cards Pro AV established, then a
   table of what every adapter has actually done since TNT started watching. The findings judge the
   last few minutes (each adapter's window_s); the table is the whole watch, as context.

   It reads GET /api/faults on mount and every REFRESH_MS, and follows the faults.state event, which
   the service publishes only when the level changes. A level change is the one thing worth
   redrawing for immediately; everything else can wait for the next poll. */
(function () {
  'use strict';
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  const REFRESH_MS = 5000;              // the watcher ticks every 5 s; there is nothing newer to have
  const LEVEL_CLASS = { bad: 'red', warn: 'yellow', info: 'grey', good: 'green' };
  const LEVEL_WORD = { bad: 'fault', warn: 'worth checking', info: 'note', good: 'good' };

  let root = null, listEl = null, tableEl = null, headEl = null, summaryEl = null;
  let timer = 0, unsub = null, loading = false, data = null;

  /** "1,234" — every count on this page is a frame count, and they get large. */
  function num(v) {
    return v == null || !isFinite(v) ? '—' : Math.round(v).toLocaleString();
  }

  /** A share of frames, at the precision the number deserves: "0.004%", "12%". */
  function pct(v) {
    if (v == null || !isFinite(v)) return '—';
    if (v === 0) return '0%';
    if (v < 0.001) return '<0.001%';
    return (v < 1 ? Number(v.toPrecision(2)) : Math.round(v * 10) / 10) + '%';
  }

  /** The one line under the heading: what the watch is, how long it has been one, and how much of
   *  it the findings judge (the longest adapter window: the last five minutes once it has them). */
  function summaryText(d) {
    if (!d) return '';
    const watched = TNT.util.fmtDuration(d.watched_s);
    const nics = (d.nics || []).length;
    const window = Math.max(0, ...(d.nics || []).map((n) => Number(n.window_s) || 0));
    const judged = window > 0 && window < (d.watched_s || 0) - 5
      ? ' · judged on the last ' + TNT.util.fmtDuration(window) : '';
    return 'Watching ' + nics + (nics === 1 ? ' adapter' : ' adapters') + ' for ' + watched + judged
      + ' · nothing is sent, and no administrator rights are used';
  }

  /** One finding, in the same level-tinted card the Pro AV and SIP pages use. */
  function findingCard(f) {
    const { h } = TNT.util;
    const level = String(f.level || 'info');
    const cls = LEVEL_CLASS[level] || 'grey';
    const kids = [
      h('div', { class: 'fa-find-head' },
        h('span', { class: 'badge ' + cls }, LEVEL_WORD[level] || level),
        h('span', { class: 'fa-find-title' }, f.title || '')),
    ];
    if (f.detail) kids.push(h('p', { class: 'fa-find-detail' }, f.detail));
    if (f.advice) {
      kids.push(h('div', { class: 'fa-advice' },
        h('span', { class: 'pill' }, 'What to do'), h('span', null, f.advice)));
    }
    return h('div', { class: 'fa-find ' + cls, data: { id: f.id || '' } }, kids);
  }

  /** How the findings judged each adapter, from their evidence: { errors: {name: level},
   *  discards: {name: level} }. Each evidence row carries the level its own share earned. */
  function verdicts(findings) {
    const out = { errors: {}, discards: {} };
    for (const f of findings || []) {
      const kind = f.id === 'fault.errors' ? 'errors' : f.id === 'fault.discards' ? 'discards' : null;
      if (!kind || !Array.isArray(f.evidence)) continue;
      for (const e of f.evidence) if (e && e.name) out[kind][e.name] = e.level || f.level;
    }
    return out;
  }

  /** The counters table: what each adapter has done since the watch began, with the lifetime
   *  figure beside it in a muted column so the two are never confused for each other. A row is
   *  tinted by what the findings made of it (its evidence level), never by these counts: errors an
   *  hour ago on a link that has been clean for the last five minutes are context, and a red row
   *  under a green verdict would be the page contradicting itself. The discard columns are the
   *  outbound ones, the only ones judged; the inbound count sits beside them as context, because
   *  one is as often a frame nothing here speaks the protocol of as a full buffer (tnt/faults.py). */
  function nicRow(n, judged) {
    const { h } = TNT.util;
    const errors = (n.new_rx_errors || 0) + (n.new_tx_errors || 0);
    const inbound = n.new_rx_discards || 0;
    const outbound = n.new_tx_discards || 0;
    // every frame carried: Windows counts the damaged and the dropped ones apart from the packets
    const frames = (n.new_rx_packets || 0) + (n.new_tx_packets || 0) + errors + inbound + outbound;
    const errLevel = (judged && judged.errors[n.name]) || '';
    const dropLevel = (judged && judged.discards[n.name]) || '';
    const worst = [errLevel, dropLevel].includes('bad') ? 'fa-row-bad'
      : [errLevel, dropLevel].includes('warn') ? 'fa-row-warn' : '';
    const flagged = (level) => level === 'bad' || level === 'warn';
    const cell = (v, cls, title) => h('td', Object.assign(cls ? { class: cls } : {}, title ? { title } : {}), v);
    const recent = (n.recent_rx_errors || 0) + (n.recent_tx_errors || 0);
    // its window ends at its last reading, which is not now once the link is down or unreadable
    // (tnt/faults.py STALE_S, two ticks)
    const window = TNT.util.fmtDuration(n.window_s || 0);
    const stale = n.up === false || (n.last_read_s || 0) > 10;
    return h('tr', { class: worst },
      h('td', null,
        h('span', { class: 'fa-nic' }, n.name || ('Adapter ' + n.index)),
        // gone from the last reading: still judged on what it counted until that has aged out
        n.up === false ? [' ', h('span', { class: 'badge grey' }, 'link down')] : null,
        n.description && n.description !== n.name
          ? h('span', { class: 'fa-nic-desc muted' }, n.description) : null),
      cell(num(frames), 'num'),
      cell(num(errors), 'num' + (flagged(errLevel) ? ' fa-hot' : ''),
        num(recent) + ' of them in the ' + (stale ? window + ' before it was last read' : 'last ' + window)),
      cell(pct(n.error_pct), 'num muted'),
      cell([num(outbound), inbound ? h('span', { class: 'muted' }, ' · ' + num(inbound) + ' in') : null],
        'num' + (flagged(dropLevel) ? ' fa-warm' : ''),
        num(outbound) + ' on the way out · ' + num(inbound) + ' on the way in, counted but never judged'),
      cell(pct(n.discard_pct), 'num muted'),
      cell(num((n.rx_errors || 0) + (n.tx_errors || 0)) + ' / '
        + num((n.rx_discards || 0) + (n.tx_discards || 0)), 'num muted'));
  }

  function renderTable(d) {
    const { h } = TNT.util;
    tableEl.innerHTML = '';
    const nics = (d && d.nics) || [];
    if (!nics.length) {
      tableEl.appendChild(TNT.ui.emptyState('No adapter is up to watch.'));
      return;
    }
    const watched = TNT.util.fmtDuration(d.watched_s);
    const judged = verdicts(d.findings);
    tableEl.appendChild(h('div', { class: 'fa-table-head' },
      h('h3', null, 'What each adapter has done'),
      h('span', { class: 'muted' }, 'since TNT started watching, ' + watched + ' ago')));
    const table = h('table', { class: 'table fa-table' },
      h('thead', null, h('tr', null,
        h('th', null, 'Adapter'),
        h('th', { class: 'num' }, 'Frames'),
        h('th', { class: 'num' }, 'Errors'),
        h('th', { class: 'num' }, '%'),
        h('th', { class: 'num' }, 'Discards out · in'),
        h('th', { class: 'num' }, '%'),
        h('th', { class: 'num' }, 'Lifetime err / disc'))),
      h('tbody', null, nics.map((n) => nicRow(n, judged))));
    tableEl.appendChild(table);
    tableEl.appendChild(h('p', { class: 'muted small fa-note' },
      'An error is a frame that arrived or left damaged — cabling, a connector, or a duplex '
      + 'mismatch. A discard is a frame that was fine and was dropped anyway. On the way out that '
      + 'means the send queue was full, which is congestion; on the way in Windows also counts a '
      + 'frame nothing on this PC speaks the protocol of, or one a firewall or VPN filter dropped, so '
      + 'those are counted here but never judged, and the discard share is of the frames sent. The '
      + 'findings above judge each adapter’s last five minutes, and a row is tinted only when they '
      + 'found something on it; an adapter whose link went down stays until its five minutes are '
      + 'over. The lifetime column counts from when the adapter came up, which may be weeks ago; '
      + 'every other column counts from when TNT started watching.'));
  }

  function render() {
    if (!root || !data) return;
    const { h } = TNT.util;
    summaryEl.textContent = summaryText(data);
    const findings = data.findings || [];
    listEl.innerHTML = '';
    if (!findings.length) {
      listEl.appendChild(TNT.ui.emptyState('Nothing to report.'));
    } else {
      for (const f of findings) listEl.appendChild(findingCard(f));
    }
    const arp = data.arp || {};
    const conflicts = arp.conflicts || [];
    if (conflicts.length) {
      listEl.appendChild(h('p', { class: 'muted small fa-note' },
        'Addresses watched in the ARP table: ' + num(arp.tracked) + '.'));
    }
    if (data.note) {
      listEl.appendChild(h('div', { class: 'fa-find grey' },
        h('div', { class: 'fa-find-head' },
          h('span', { class: 'badge grey' }, 'note'),
          h('span', { class: 'fa-find-title' }, 'Something could not be read'),
        ), h('p', { class: 'fa-find-detail' }, data.note)));
    }
    renderTable(data);
  }

  async function load() {
    if (loading || !root) return;
    loading = true;
    try {
      const next = await TNT.api.faults();
      if (!root) return;
      data = next;
      render();
    } catch (err) {
      if (root && !data) {
        listEl.innerHTML = '';
        listEl.appendChild(TNT.ui.emptyState('Could not read the fault watch: ' + err.message));
      }
    } finally {
      loading = false;
    }
  }

  TNT.views.faults = {
    mount(el) {
      const { h } = TNT.util;
      root = el;
      summaryEl = h('div', { class: 'muted' });
      const refresh = h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => load() } },
        TNT.ui.icon('refresh'), 'Refresh');
      headEl = h('div', { class: 'section-head' },
        h('h2', null, h('span', { class: 'section-accent' }), 'Faults'),
        h('div', { class: 'actions' }, refresh));
      listEl = h('div', { class: 'fa-findings' });
      tableEl = h('div', { class: 'card fa-counters' });
      root.appendChild(headEl);
      root.appendChild(summaryEl);
      root.appendChild(listEl);
      root.appendChild(tableEl);
      data = null;
      load();
      timer = setInterval(load, REFRESH_MS);
      // the level changed: that is the one thing worth redrawing for before the next poll
      unsub = TNT.api.events.on('faults.state', () => load());
    },
    update() { },
    unmount() {
      if (timer) { clearInterval(timer); timer = 0; }
      if (unsub) { try { unsub(); } catch (e) { /* ignore */ } unsub = null; }
      root = null; listEl = null; tableEl = null; headEl = null; summaryEl = null; data = null;
    },
    // exposed for the tests
    summaryText,
    verdicts,
    num,
    pct,
    LEVEL_CLASS,
  };
})();
