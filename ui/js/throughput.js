/* TNT — throughput.js
   The "Realtime throughput" card of Network info: one cell of the adapter grid that
   views/ipinfo.js puts between the live link map and the NAT & switch port card
   (create() -> { el, update(state), unmount() }).

   One block per NIC that is moving something (plus the internet-facing one, always, because a
   flat line on that one is itself the answer): a Task-Manager-style chart of receive and send
   over a moving window with each direction's window average drawn across as a dashed rule, the
   current rate in bits per second under it, and the cumulative packet and byte counters the
   Control Panel's status dialog shows.

   Where the numbers come from: the service samples every adapter's 64-bit byte and packet
   counters once a second (tnt/throughput.py) and publishes them as a `throughput.sample` event.
   This card keeps its own half hour of those in memory, so changing the window is instant and
   costs nothing; GET /api/throughput is asked only for the backlog — on mount, when the window
   changes and after a gap in the stream, which is what a dropped SSE connection looks like from
   here. Nothing is polled.

   Loaded before app.js: TNT.util / TNT.ui / TNT.charts are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;

  /** [seconds, button label, axis label] — matches tnt.throughput.WINDOWS. */
  const WINDOWS = [
    [10, '10 s', '10 seconds'],
    [30, '30 s', '30 seconds'],
    [60, '1 min', '60 seconds'],
    [300, '5 min', '5 minutes'],
    [1800, '30 min', '30 minutes'],
  ];
  const DEFAULT_WINDOW_S = 30;
  const HISTORY_S = 1800;               // what the service keeps, so what is worth holding here
  const WINDOW_STORE = 'tnt.throughput.window';
  //: A stream quiet for longer than this has dropped samples (a reconnect, a slept machine):
  //: ask for the backlog instead of drawing a straight line across the hole.
  const GAP_S = 5;
  const CHART_H = 132;
  let seq = 0;                          // ids for aria-controls, one set per card

  /** A rate in bits per second, the way Task Manager writes it: "0 bps", "224 Kbps", "7.1 Mbps".
   *  One decimal below ten of the unit, whole above, so the text does not jitter in width. */
  function rateText(bps) {
    const v = Number(bps);
    if (!isFinite(v) || v <= 0) return '0 bps';
    const units = [[1e9, 'Gbps'], [1e6, 'Mbps'], [1e3, 'Kbps']];
    for (const [scale, unit] of units) {
      if (v >= scale) {
        const n = v / scale;
        return (n < 10 ? (Math.round(n * 10) / 10).toFixed(1) : String(Math.round(n))) + ' ' + unit;
      }
    }
    return Math.round(v) + ' bps';
  }

  /** A packet or byte total with thousands separators: the Control Panel's Activity figures. */
  function countText(n) {
    if (n === null || n === undefined) return '—';     // Number(null) is 0, which would read as "0 packets"
    const v = Number(n);
    if (!isFinite(v) || v < 0) return '—';
    return Math.round(v).toLocaleString();
  }

  /** A NIC's link speed for the block heading; '' when Windows does not report one. */
  function linkText(bps) {
    const v = Number(bps);
    if (!isFinite(v) || v <= 0) return '';
    if (v >= 1e9) return (v / 1e9 % 1 === 0 ? v / 1e9 : Math.round(v / 1e8) / 10) + ' Gbps';
    if (v >= 1e6) return Math.round(v / 1e6) + ' Mbps';
    return Math.round(v / 1e3) + ' Kbps';
  }

  function windowSpec(seconds) { return WINDOWS.find((w) => w[0] === seconds) || WINDOWS[1]; }

  function savedWindow() {
    try {
      const v = parseInt(localStorage.getItem(WINDOW_STORE), 10);
      if (WINDOWS.some((w) => w[0] === v)) return v;
    } catch (e) { /* no storage: the default is fine */ }
    return DEFAULT_WINDOW_S;
  }

  /** Which NICs belong on the card for this window: the internet-facing one, and anything that
   *  moved a bit inside it. The same rule the service applies to GET /api/throughput — applying
   *  it here too is what lets a NIC that starts carrying traffic appear without a refetch. */
  function shown(nics, windowS, now) {
    const floor = now - windowS;
    return nics.filter((n) => n.primary || (n.samples || []).some((s) => s[0] >= floor && (s[1] || s[2])));
  }

  /** The window average of one column of samples — the value each dashed rule is drawn at.
   *  Computed from the points that are actually on the chart, so the rule always agrees with
   *  the line it is drawn over even when the service has been up for less than the window.
   *
   *  Weighted by time, not by row: on the 30-minute window the backlog comes in 3-second buckets
   *  (tnt.throughput.step_for) and the live samples after it one a second, and each second in the
   *  window must count once. A row's step is its own sixth column (the card writes the backlog's
   *  step_s there), else `stepS`, else one second. A row stands for the seconds up to the next
   *  row, never more than its step (a longer hole is a hole, not time at the rate before it); the
   *  newest row for one second, or up to its step if `now` is further on. When every row is one
   *  second, every row weighs the same and this is the plain mean. */
  function average(samples, column, windowS, now, stepS) {
    const rows = (samples || []).filter((s) => s[0] >= now - windowS).sort((a, b) => a[0] - b[0]);
    if (!rows.length) return 0;
    const fallback = Math.max(1, Number(stepS) || 1);
    let sum = 0, secs = 0;
    for (let i = 0; i < rows.length; i++) {
      const step = Math.max(1, Number(rows[i][5]) || fallback);
      const until = i + 1 < rows.length ? rows[i + 1][0] : now + 1;
      const w = Math.max(1, Math.min(step, until - rows[i][0]));
      sum += (Number(rows[i][column]) || 0) * w;
      secs += w;
    }
    return sum / secs;
  }

  /** Merge one throughput.sample row into a NIC's series, newest last, half an hour deep.
   *  A repeated or out-of-order timestamp replaces rather than appends: the service aligns its
   *  ticks to the second, and two points at one second would draw a spike that never happened. */
  function push(series, sample) {
    const ts = sample[0];
    const last = series.length ? series[series.length - 1][0] : -Infinity;
    if (ts === last) series[series.length - 1] = sample;
    else if (ts > last) series.push(sample);
    else {
      const at = series.findIndex((s) => s[0] >= ts);
      if (at < 0) series.push(sample);
      else if (series[at][0] === ts) series[at] = sample;
      else series.splice(at, 0, sample);
    }
    const cut = series.length - HISTORY_S;
    if (cut > 0) series.splice(0, cut);
    return series;
  }

  /** Merge the rows a NIC held into its freshly fetched backlog, and return the backlog.
   *  The backlog is the service's own account of every second from its first row up to `upto`
   *  (the reply's ts), already averaged into `step`-second buckets on the 30-minute window. A held
   *  row inside that span says the same seconds again, at another size: left in, a bucket sat
   *  beside live rows for the seconds it stands for, the line stepped between them and the average
   *  took the bucket for one second of three. So a held row inside the span gives way. A held row
   *  after it (one that arrived while the GET was in flight) is newer than anything fetched and
   *  stays. With no ts the span ends where the last bucket does. */
  function mergeBacklog(fresh, held, step, upto) {
    step = Math.max(1, Number(step) || 1);
    const from = fresh.length ? fresh[0][0] : Infinity;
    const end = Number.isFinite(Number(upto)) && upto !== null
      ? Number(upto) : (fresh.length ? fresh[fresh.length - 1][0] + step - 1 : -Infinity);
    for (const s of held || []) {
      if (s[0] >= from && s[0] <= end) continue;
      // a held bucket of another size after the span still stands for seconds the fresh rows do not
      push(fresh, s);
    }
    return fresh;
  }

  function create() {
    const { h } = TNT.util;
    const id = 'tp' + (++seq);
    let winS = savedWindow();
    // id -> { meta, samples: [[ts, rx, tx, rxp, txp, stepS?], ...] }. A backlog row carries the
    // seconds it stands for (GET /api/throughput's step_s: 3 on the 30-minute window) so the chart
    // knows a 3 s spacing there is the data, not a hole, and the average weighs it by its seconds.
    // A live row is one second and carries nothing. The step belongs to the row, not the card: a
    // card-wide step went stale when a window changed and its backlog GET failed, and held the
    // live seconds after a 30-minute backlog to the buckets' looser tolerance.
    let nics = new Map();
    let blocks = new Map();            // id -> { el, chart, ... } for the NICs on screen
    let order = [];                    // the ids on screen, in the order they are drawn
    let bodyEl = null;
    let unsub = null;
    let seeding = false;
    let seedAgain = false;
    let lastEventTs = 0;
    let note = null;              // the service could not read the counters, and says why
    let seenIds = new Set();      // every NIC this card has ever held, so a returning one is known
    let dead = false;

    const seg = TNT.ui.segmented(WINDOWS.map((w) => ({ value: w[0], label: w[1] })), winS, (v) => setWindow(Number(v)));
    bodyEl = h('div', { class: 'tp-body', id: id + '-body' },
      TNT.ui.emptyState('Waiting for the first sample…'));
    const el = h('div', { class: 'card tp-card' },
      h('div', { class: 'card-title' },
        TNT.ui.icon('activity'), 'Realtime throughput',
        h('div', { class: 'tp-windows' }, seg)),
      bodyEl);

    function setWindow(value) {
      if (!WINDOWS.some((w) => w[0] === value) || value === winS) return;
      winS = value;
      try { localStorage.setItem(WINDOW_STORE, String(value)); } catch (e) { /* ignore */ }
      seed();                          // the longer window may reach further back than we hold
      render();
    }

    /** Ask for the backlog. Runs on mount, on a window change and after a gap in the stream;
     *  a seed asked for while one is in flight follows it rather than racing it. */
    async function seed() {
      if (seeding) { seedAgain = true; return; }
      seeding = true;
      try {
        const data = await TNT.api.throughput(winS);
        if (dead) return;
        const next = new Map();
        const step = Math.max(1, Number(data && data.step_s) || 1);
        for (const n of (data && data.nics) || []) {
          const rows = (n.samples || []).map((s) => (step > 1 ? s.slice(0, 5).concat([step]) : s.slice(0, 5)));
          next.set(n.id, { meta: n, samples: rows });
        }
        // a NIC we are holding that the backlog does not mention is idle, not gone: its own
        // samples stay, because the service only leaves one out when it moved nothing
        for (const [key, held] of nics) {
          const fresh = next.get(key);
          if (!fresh) next.set(key, held);
          else mergeBacklog(fresh.samples, held.samples, step, data && data.ts);
        }
        nics = next;
        note = (data && data.note) || null;
        lastEventTs = (data && data.ts) || lastEventTs;
        render();
      } catch (err) {
        if (!dead && !nics.size) {
          bodyEl.innerHTML = '';
          bodyEl.appendChild(TNT.ui.emptyState('Could not read the adapter counters: ' + err.message));
        }
      } finally {
        seeding = false;
        if (seedAgain && !dead) { seedAgain = false; seed(); }
      }
    }

    // the SSE wrapper hands the parsed payload straight to the handler, not the event around it
    function onSample(data) {
      if (!data || !Array.isArray(data.nics)) return;
      const ts = Number(data.ts) || 0;
      if (lastEventTs && ts - lastEventTs > GAP_S) seed();      // samples were missed: refill
      lastEventTs = ts || lastEventTs;
      const live = new Set();
      for (const n of data.nics) {
        live.add(n.id);
        let rec = nics.get(n.id);
        if (!rec) {
          rec = { meta: n, samples: [] };
          nics.set(n.id, rec);
          // a NIC we held before and dropped is back (its box was unticked, or it was replugged).
          // The service never stopped sampling it, so ask for the backlog rather than drawing its
          // line from this second on.
          if (seenIds.has(n.id)) seed();
        }
        seenIds.add(n.id);
        rec.meta = n;
        push(rec.samples, [Math.round(ts), n.rx_bps || 0, n.tx_bps || 0, n.rx_pps || 0, n.tx_pps || 0]);
      }
      // the event lists every adapter the service is willing to report, idle ones included, so one
      // that is missing from it is gone: hidden by its checkbox, or unplugged. Either way it goes
      // now rather than lingering on screen until its last samples age out of the window.
      for (const key of Array.from(nics.keys())) if (!live.has(key)) nics.delete(key);
      render();
    }

    /** Build one NIC's block. The canvas and its chart are made once and then only fed. */
    function block(rec) {
      const spec = windowSpec(winS);
      const canvas = h('canvas', { class: 'tp-canvas', height: String(CHART_H) });
      const chart = new TNT.charts.Throughput(canvas, {
        windowS: winS, windowLabel: spec[2], fmt: rateText, timeFmt: TNT.util.fmtTime,
      });
      const nameEl = h('span', { class: 'tp-name' });
      const descEl = h('span', { class: 'tp-desc muted' });
      const linkEl = h('span', { class: 'tp-link' });
      const cells = {};
      function figure(dir, label, arrow) {
        const rate = h('span', { class: 'tp-rate num' }, '0 bps');
        const pkts = h('span', { class: 'num' }, '—');
        const bytes = h('span', { class: 'num' }, '—');
        cells[dir] = { rate, pkts, bytes };
        return h('div', { class: 'tp-figure tp-' + dir },
          h('div', { class: 'tp-figure-head' },
            h('span', { class: 'tp-key', 'aria-hidden': 'true' }), arrow + ' ' + label),
          rate,
          h('dl', { class: 'tp-counts' },
            h('dt', null, 'Packets'), h('dd', null, pkts),
            h('dt', null, 'Bytes'), h('dd', null, bytes)));
      }
      const el2 = h('div', { class: 'tp-nic' },
        h('div', { class: 'tp-head' }, nameEl, descEl, linkEl),
        h('div', { class: 'tp-chart-wrap' }, canvas),
        h('div', { class: 'tp-figures' }, figure('rx', 'Receive', '↓'), figure('tx', 'Send', '↑')));
      return { el: el2, chart, nameEl, descEl, linkEl, cells };
    }

    /** How many adapters the settings are keeping off this card, so an empty card can say so
     *  instead of reading as "nothing is moving" when in fact nothing is allowed to show. */
    function hiddenCount() {
      const st = TNT.app && TNT.app.state;
      const list = st && st.settings && st.settings.throughput && st.settings.throughput.excluded;
      return Array.isArray(list) ? list.length : 0;
    }

    function render() {
      if (dead || !bodyEl) return;
      const now = lastEventTs || TNT.util.nowS();
      const list = shown(Array.from(nics.values()).map((r) => Object.assign({}, r.meta, { samples: r.samples })),
                         winS, now);
      if (!list.length) {
        // the note comes first: "waiting" for something that is never coming would be a lie
        const why = note ? 'The adapter counters could not be read: ' + note
          : hiddenCount() ? 'Every adapter is hidden. The checkboxes are under the adapter cards below.'
            : nics.size ? 'No adapter is moving anything right now.'
              : 'Waiting for the first sample…';
        if (order.length || bodyEl.firstChild === null || bodyEl.dataset.why !== why) {
          order = []; blocks = new Map();
          bodyEl.innerHTML = '';
          bodyEl.dataset.why = why;
          bodyEl.appendChild(TNT.ui.emptyState(why));
        }
        return;
      }
      bodyEl.dataset.why = '';
      const ids = list.map((n) => n.id);
      if (ids.length !== order.length || ids.some((v, i) => v !== order[i])) {
        // the set or the order changed (a NIC woke up, a cable came out): rebuild the column,
        // keeping the blocks that survive so their charts and their canvases carry on
        const kept = new Map();
        bodyEl.innerHTML = '';
        for (const n of list) {
          const b = blocks.get(n.id) || block(nics.get(n.id));
          kept.set(n.id, b);
          bodyEl.appendChild(b.el);
        }
        for (const [key, b] of blocks) { if (!kept.has(key)) b.chart.destroy(); }
        blocks = kept;
        order = ids;
      }
      const spec = windowSpec(winS);
      for (const n of list) {
        const b = blocks.get(n.id);
        if (!b) continue;
        b.nameEl.textContent = n.name || 'Adapter ' + n.index;
        b.descEl.textContent = n.description && n.description !== n.name ? n.description : '';
        b.linkEl.textContent = linkText(n.link_bps);
        b.cells.rx.rate.textContent = rateText(n.rx_bps);
        b.cells.tx.rate.textContent = rateText(n.tx_bps);
        b.cells.rx.pkts.textContent = countText(n.rx_packets);
        b.cells.tx.pkts.textContent = countText(n.tx_packets);
        b.cells.rx.bytes.textContent = countText(n.rx_bytes);
        b.cells.tx.bytes.textContent = countText(n.tx_bytes);
        b.chart.setSeries({
          rx: n.samples.map((s) => (s[5] ? [s[0], s[1], s[5]] : [s[0], s[1]])),
          tx: n.samples.map((s) => (s[5] ? [s[0], s[2], s[5]] : [s[0], s[2]])),
          now, windowS: winS, windowLabel: spec[2],
          avgRx: average(n.samples, 1, winS, now),
          avgTx: average(n.samples, 2, winS, now),
        });
      }
    }

    unsub = TNT.api.events.on('throughput.sample', onSample);
    seed();

    return {
      el,
      /** Nothing here follows /api/status: the card lives on its own event. */
      update() { },
      unmount() {
        dead = true;
        if (unsub) { try { unsub(); } catch (e) { /* ignore */ } unsub = null; }
        for (const b of blocks.values()) { try { b.chart.destroy(); } catch (e) { /* ignore */ } }
        blocks = new Map(); order = []; nics = new Map(); bodyEl = null;
      },
    };
  }

  TNT.throughput = { create, rateText, countText, linkText, shown, average, push, mergeBacklog, windowSpec, WINDOWS, HISTORY_S };
})();
