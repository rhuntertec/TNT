/* TNT — views/ping.js
   Ping sub-tiles: host, IP, kind badge, big current RTT, 5-minute sparkline, traffic light,
   avg/min/max/loss for 1 min and 24 h. Keeps ≤ 5 minutes of samples per target in memory,
   seeded from /api/targets/{id}/samples and fed by ping.sample SSE events. */
(function () {
  'use strict';
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  const WINDOW_S = 300;
  // sparkline windows the "5 min" label cycles through: [seconds, label, source]
  // live = per-second samples kept in memory (the service ring buffer holds 1 h),
  // minutes = per-minute aggregates from /api/targets/{id}/history, refreshed every 60 s
  const WINDOWS = [[300, '5 min', 'live'], [3600, '1 h', 'live'], [21600, '6 h', 'minutes'], [86400, '24 h', 'minutes']];
  const AGG_REFRESH_S = 60;
  function savedWindow(t) {
    try { const v = parseInt(localStorage.getItem('tnt.ping.win.' + (t.host || t.id)), 10); if (WINDOWS.some((w) => w[0] === v)) return v; } catch (e) { /* ignore */ }
    return WINDOW_S;
  }
  let root = null, gridEl = null, emptyEl = null, addInput = null, addBtn = null;
  let tiles = new Map();          // id -> tile record
  let samples = new Map();        // id -> [[ts, rtt|null], ...]
  let unsubs = [];
  let ticker = null;
  let lastState = null;

  function trim(arr, now, keepS) {
    const win = keepS || WINDOW_S;
    const cut = now - win - 2;
    let i = 0;
    while (i < arr.length && arr[i][0] < cut) i++;
    if (i) arr.splice(0, i);
    if (arr.length > win * 2 + 50) arr.splice(0, arr.length - (win * 2 + 50));
  }

  function liveKeepS(rec) { return rec && rec.winS > WINDOW_S && rec.winSource === 'live' ? rec.winS : WINDOW_S; }

  function localWindow(arr, now, seconds) {
    const cut = now - seconds;
    let sent = 0, recv = 0, sum = 0, min = Infinity, max = -Infinity;
    for (let i = arr.length - 1; i >= 0; i--) {
      const s = arr[i];
      if (s[0] < cut) break;
      sent++;
      if (s[1] != null) { recv++; sum += s[1]; if (s[1] < min) min = s[1]; if (s[1] > max) max = s[1]; }
    }
    if (!sent) return null;
    return { sent, received: recv, lost: sent - recv, loss_pct: 100 * (sent - recv) / sent, avg_ms: recv ? sum / recv : null, min_ms: recv ? min : null, max_ms: recv ? max : null };
  }

  function kindBadge(t) {
    const { h } = TNT.util;
    const kind = t.kind === 'local' ? 'local' : 'internet';
    return h('span', { class: 'badge ' + (kind === 'local' ? 'green' : 'blue') }, kind);
  }

  function createTile(t) {
    const { h, copyCode } = TNT.util;
    const ui = TNT.ui;
    const light = ui.light(t.light, true);
    const host = h('span', { class: 'ptile-host', title: t.host }, TNT.util.targetName(t));
    const badge = kindBadge(t);
    const grip = h('button', { class: 'ptile-grip', type: 'button', title: 'Drag to reorder (arrow keys work too)',
      'aria-label': 'Reorder ' + t.host }, ui.icon('grip'));
    const removeBtn = h('button', { class: 'btn btn-round-sm ptile-remove', type: 'button', 'aria-label': 'Remove ' + t.host, title: 'Remove target' }, ui.icon('close'));
    const sub = h('div', { class: 'ptile-sub' });
    const big = h('span', { class: 'big' }, '—');
    const unit = h('span', { class: 'unit' }, 'ms');
    const jitter = h('span', { class: 'muted small', style: { marginLeft: 'auto' } }, '');
    const rtt = h('div', { class: 'ptile-rtt' }, big, unit, jitter);
    const canvas = h('canvas', { class: 'spark-canvas', 'aria-label': 'Last 5 minutes of round-trip times' });
    const winBtn = h('button', { class: 'spark-label', type: 'button', title: 'Click to change the chart window' }, '5 min', h('span', { class: 'caret' }, '▾'));
    const wrap = h('div', { class: 'chart-wrap' }, canvas, winBtn);
    const cells = { m: {}, d: {} };
    const grid = h('div', { class: 'stat-grid' },
      h('span'), h('span', { class: 'h' }, 'avg'), h('span', { class: 'h' }, 'min'), h('span', { class: 'h' }, 'max'), h('span', { class: 'h' }, 'loss'),
      h('span', { class: 'r' }, '1 min'), ...['avg', 'min', 'max', 'loss'].map((k) => (cells.m[k] = h('span', { class: 'v' }, '—'))),
      h('span', { class: 'r' }, '24 h'), ...['avg', 'min', 'max', 'loss'].map((k) => (cells.d[k] = h('span', { class: 'v' }, '—'))));
    // the kind badge lives on the second row with the IP chips so the name gets the full width
    const el = h('div', { class: 'card ptile', data: { id: String(t.id) }, draggable: 'true' },
      grip, removeBtn, h('div', { class: 'ptile-head' }, light, host), sub, rtt, wrap, grid);
    removeBtn.addEventListener('click', () => removeTarget(t));
    const spark = new TNT.charts.Sparkline(canvas, { windowS: WINDOW_S, label: '' });
    const rec = { id: t.id, t, el, light, host, badge, sub, big, unit, jitter, spark, cells, canvas, winBtn, grip,
      lastTs: 0, seeded: false, hostKey: null, winS: WINDOW_S, winSource: 'live', agg: null, aggTs: 0, grabbed: false };
    winBtn.addEventListener('click', () => cycleWindow(rec));
    wireDrag(rec);
    applyWindow(rec, savedWindow(t), false);
    updateStatic(rec, t);
    return rec;
  }

  /* ------------------------------------------------------------- reordering */
  // Tiles are dragged by their grip (HTML5 drag and drop, live reordering of the grid) or
  // moved with the arrow keys on the grip. The order is stored by the service
  // (PUT /api/targets/order) so the top Ping tile, PDF reports and every client agree.
  let dragRec = null;          // tile being dragged
  let localOrder = null;       // ids in the order the user chose, until the service confirms it

  function wireDrag(rec) {
    const el = rec.el;
    el.addEventListener('pointerdown', (e) => { rec.grabbed = !!e.target.closest('.ptile-grip'); });
    el.addEventListener('dragstart', (e) => {
      if (!rec.grabbed) { e.preventDefault(); return; }    // only the grip starts a drag (copy/select elsewhere)
      dragRec = rec;
      el.classList.add('dragging');
      try { e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', String(rec.id)); } catch (err) { /* ignore */ }
    });
    el.addEventListener('dragend', () => {
      el.classList.remove('dragging');
      rec.grabbed = false;
      if (dragRec === rec) { dragRec = null; commitOrder(domOrder()); }
    });
    rec.grip.addEventListener('keydown', (e) => {
      const back = e.key === 'ArrowLeft' || e.key === 'ArrowUp', fwd = e.key === 'ArrowRight' || e.key === 'ArrowDown';
      if (!back && !fwd) return;
      e.preventDefault();
      const sib = back ? el.previousElementSibling : el.nextElementSibling;
      if (!sib) return;
      gridEl.insertBefore(el, back ? sib : sib.nextSibling);
      rec.grip.focus();
      commitOrder(domOrder());
    });
  }

  function wireGridDrop() {
    gridEl.addEventListener('dragover', (e) => {
      if (!dragRec) return;
      e.preventDefault();
      try { e.dataTransfer.dropEffect = 'move'; } catch (err) { /* ignore */ }
      const over = e.target.closest('.ptile');
      if (!over || over === dragRec.el) return;
      const r = over.getBoundingClientRect();
      const before = e.clientX < r.left + r.width / 2;
      if (before) { if (over.previousElementSibling !== dragRec.el) gridEl.insertBefore(dragRec.el, over); }
      else if (over.nextElementSibling !== dragRec.el) gridEl.insertBefore(dragRec.el, over.nextElementSibling);
    });
    gridEl.addEventListener('drop', (e) => { if (dragRec) e.preventDefault(); });
  }

  function domOrder() { return Array.from(gridEl.children).map((c) => Number(c.dataset.id)).filter((n) => isFinite(n)); }

  async function commitOrder(ids) {
    const current = (lastState && lastState.targets ? lastState.targets : []).map((t) => t.id);
    if (ids.length === current.length && ids.every((id, i) => id === current[i])) return;   // nothing moved
    localOrder = ids.slice();
    try {
      await TNT.api.reorderTargets(ids);
      TNT.app.refreshStatus();
    } catch (err) {
      localOrder = null;
      TNT.ui.toast('Could not save the order: ' + err.message, 'error');
      TNT.app.refreshStatus();
    }
  }

  function applyLocalOrder(targets) {
    if (!localOrder) return targets;
    const ids = targets.map((t) => t.id);
    if (ids.length !== localOrder.length || !localOrder.every((id) => ids.includes(id))) { localOrder = null; return targets; }
    if (ids.every((id, i) => id === localOrder[i])) { localOrder = null; return targets; }   // the service caught up
    const pos = new Map(localOrder.map((id, i) => [id, i]));
    return targets.slice().sort((a, b) => pos.get(a.id) - pos.get(b.id));
  }

  function windowSpec(seconds) { return WINDOWS.find((w) => w[0] === seconds) || WINDOWS[0]; }

  function applyWindow(rec, seconds, remember) {
    const [winS, label, source] = windowSpec(seconds);
    rec.winS = winS;
    rec.winSource = source;
    rec.winBtn.firstChild.textContent = label;
    rec.canvas.setAttribute('aria-label', 'Last ' + label + ' of round-trip times');
    rec.spark.setWindow(winS, source === 'minutes' ? 60 : 1, '');
    if (remember) { try { localStorage.setItem('tnt.ping.win.' + (rec.t.host || rec.id), String(winS)); } catch (e) { /* ignore */ } }
    if (source === 'live') {
      rec.agg = null;
      // a 1 h window needs more than the 5 min kept in memory: re-seed from the service
      if (winS > WINDOW_S) seed(rec); else redraw(rec, TNT.util.nowS());
    } else {
      rec.aggTs = 0;
      loadAggregate(rec);
    }
  }

  function cycleWindow(rec) {
    const i = WINDOWS.findIndex((w) => w[0] === rec.winS);
    applyWindow(rec, WINDOWS[(i + 1) % WINDOWS.length][0], true);
  }

  function redraw(rec, now) {
    if (rec.winSource === 'minutes') { if (rec.agg) rec.spark.setSamples(rec.agg, now); return; }
    rec.spark.setSamples(samplesFor(rec.id), now);
  }

  async function loadAggregate(rec) {
    const now = TNT.util.nowS();
    rec.aggTs = now;
    try {
      const r = await TNT.api.history(rec.id, Math.floor(now - rec.winS), Math.ceil(now));
      if (!tiles.has(rec.id) || rec.winSource !== 'minutes') return;
      const rows = (r && r.minutes) || [];
      // [minute midpoint, avg rtt or null when nothing came back, loss % for the red ticks]
      rec.agg = rows.map((m) => [Number(m.minute_ts) + 30, m.received ? m.avg_ms : null,
        m.sent ? (100 * (m.sent - m.received)) / m.sent : 0]);
      // the current, still open minute: from the live samples
      const live = samplesFor(rec.id);
      const curMin = Math.floor(now / 60) * 60;
      const cur = live.filter((s) => s[0] >= curMin);
      if (cur.length) {
        const ok = cur.filter((s) => s[1] != null);
        rec.agg.push([curMin + 30, ok.length ? ok.reduce((a, s) => a + s[1], 0) / ok.length : null, (100 * (cur.length - ok.length)) / cur.length]);
      }
      rec.spark.setSamples(rec.agg, now);
    } catch (err) {
      console.warn('history failed for target ' + rec.id, err);
    }
  }

  function updateStatic(rec, t) {
    const { h, copyCode, fmtDateTime } = TNT.util;
    rec.t = t;
    const name = TNT.util.targetName(t);
    if (rec.host.textContent !== name) rec.host.textContent = name;
    const kind = t.kind === 'local' ? 'local' : 'internet';
    const cls = 'badge ' + (kind === 'local' ? 'green' : 'blue');
    if (rec.badge.className !== cls) { rec.badge.className = cls; rec.badge.textContent = kind; }
    const key = [t.ip, t.host, t.label, t.resolved, t.resolve_error, t.enabled].join('|');
    if (rec.hostKey !== key) {
      rec.hostKey = key;
      rec.sub.innerHTML = '';
      rec.sub.appendChild(rec.badge);
      if (t.ip) rec.sub.appendChild(copyCode(t.ip));
      if (t.label && t.host !== t.ip) rec.sub.appendChild(copyCode(t.host));
      if (t.resolved === false) rec.sub.appendChild(h('span', { class: 'badge red' }, 'unresolved'));
      if (t.resolve_error) rec.sub.appendChild(h('span', { class: 'ongoing small', title: t.resolve_error }, t.resolve_error));
      if (t.enabled === false) rec.sub.appendChild(h('span', { class: 'badge grey' }, 'disabled'));
      rec.el.classList.toggle('unresolved', t.resolved === false);
    }
    const lc = 'light lg ' + (t.light || 'grey');
    if (rec.light.className !== lc) rec.light.className = lc;
    // 24 h stats from the server view
    const d = t.day || {};
    setCell(rec.cells.d.avg, TNT.util.fmtMs(d.avg_ms), false);
    setCell(rec.cells.d.min, TNT.util.fmtMs(d.min_ms), false);
    setCell(rec.cells.d.max, TNT.util.fmtMs(d.max_ms), false);
    setCell(rec.cells.d.loss, TNT.util.fmtPct(d.loss_pct), d.loss_pct != null && d.loss_pct >= 2);
    if (!samplesFor(t.id).length) updateWindowCells(rec, t.window);
    // If no live samples yet show the last known value
    if (!rec.lastTs && t.last) showLast(rec, t.last, false);
  }

  function setCell(el, text, warn) {
    if (el.textContent !== text) el.textContent = text;
    el.classList.toggle('warn', !!warn);
  }

  function updateWindowCells(rec, w) {
    if (!w) return;
    setCell(rec.cells.m.avg, TNT.util.fmtMs(w.avg_ms), false);
    setCell(rec.cells.m.min, TNT.util.fmtMs(w.min_ms), false);
    setCell(rec.cells.m.max, TNT.util.fmtMs(w.max_ms), false);
    setCell(rec.cells.m.loss, TNT.util.fmtPct(w.loss_pct), w.loss_pct != null && w.loss_pct >= 2);
  }

  function showLast(rec, last, animate) {
    if (!last) return;
    if (last.ok && last.rtt_ms != null) {
      const txt = TNT.util.fmtMs(last.rtt_ms);
      rec.big.classList.remove('miss');
      if (rec.big.textContent !== txt) { rec.big.textContent = txt; if (animate) TNT.util.pop(rec.big); }
      rec.unit.textContent = 'ms';
    } else {
      rec.big.textContent = '×';
      rec.big.classList.add('miss');
      rec.unit.textContent = last.ts ? 'no reply' : '';
      if (animate) TNT.util.pop(rec.big);
    }
  }

  function samplesFor(id) {
    let arr = samples.get(id);
    if (!arr) { arr = []; samples.set(id, arr); }
    return arr;
  }

  async function seed(rec) {
    try {
      const keepS = liveKeepS(rec);
      const r = await TNT.api.samples(rec.id, keepS);
      if (!tiles.has(rec.id)) return;
      const now = TNT.util.nowS();
      const arr = samplesFor(rec.id);
      const have = new Set(arr.map((s) => Math.round(s[0] * 10)));
      const merged = arr.slice();
      for (const s of (r && r.samples) || []) {
        if (!Array.isArray(s)) continue;
        const key = Math.round(s[0] * 10);
        if (!have.has(key)) { merged.push([s[0], s[1] == null ? null : s[1]]); have.add(key); }
      }
      merged.sort((a, b) => a[0] - b[0]);
      trim(merged, now, keepS);
      samples.set(rec.id, merged);
      rec.seeded = true;
      redraw(rec, now);
      const w = localWindow(merged, now, 60);
      if (w) updateWindowCells(rec, w);
      if (merged.length && !rec.lastTs) {
        const last = merged[merged.length - 1];
        showLast(rec, { ts: last[0], ok: last[1] != null, rtt_ms: last[1] }, false);
      }
    } catch (err) {
      console.warn('seed samples failed for target ' + rec.id, err);
    }
  }

  function onSample(d) {
    if (!d || !tiles.has(d.target_id)) return;
    const rec = tiles.get(d.target_id);
    const arr = samplesFor(d.target_id);
    const now = TNT.util.nowS();
    arr.push([d.ts, d.ok && d.rtt_ms != null ? d.rtt_ms : null]);
    trim(arr, now, liveKeepS(rec));
    rec.lastTs = d.ts;
    showLast(rec, d, true);
    if (d.light) { const lc = 'light lg ' + d.light; if (rec.light.className !== lc) rec.light.className = lc; }
    if (rec.winSource === 'live') rec.spark.setSamples(arr, now);
    const w = localWindow(arr, now, 60);
    if (w) updateWindowCells(rec, w);
    // jitter over the last minute
    let prev = null, acc = 0, n = 0;
    for (let i = arr.length - 1; i >= 0 && arr[i][0] >= now - 60; i--) {
      const v = arr[i][1];
      if (v != null) { if (prev != null) { acc += Math.abs(prev - v); n++; } prev = v; }
    }
    const jt = n ? 'jitter ' + TNT.util.fmtMs(acc / n) + ' ms' : '';
    if (rec.jitter.textContent !== jt) rec.jitter.textContent = jt;
  }

  function sync(targets) {
    if (!root) return;
    if (dragRec) return;                 // never fight the user's drag; the next update catches up
    targets = applyLocalOrder(targets);
    const { h } = TNT.util;
    const ids = new Set(targets.map((t) => t.id));
    for (const [id, rec] of Array.from(tiles.entries())) {
      if (!ids.has(id)) { rec.spark.destroy(); rec.el.remove(); tiles.delete(id); samples.delete(id); }
    }
    let prevEl = null;
    for (const t of targets) {
      let rec = tiles.get(t.id);
      if (!rec) {
        rec = createTile(t);
        tiles.set(t.id, rec);
        seed(rec);
      } else updateStatic(rec, t);
      // keep DOM order = target order
      const want = prevEl ? prevEl.nextSibling : gridEl.firstChild;
      if (want !== rec.el) gridEl.insertBefore(rec.el, want);
      prevEl = rec.el;
    }
    emptyEl.hidden = targets.length > 0;
    gridEl.hidden = targets.length === 0;
  }

  async function addTarget() {
    const host = (addInput.value || '').trim();
    if (!host) { addInput.focus(); return; }
    if (/\s/.test(host)) { TNT.ui.toast('A host name cannot contain spaces', 'warn'); return; }
    TNT.ui.busy(addBtn, true);
    try {
      const t = await TNT.api.addTarget(host);
      addInput.value = '';
      TNT.ui.toast('Added ' + (t && t.host ? t.host : host), 'ok');
      TNT.app.refreshStatus();
    } catch (err) { TNT.ui.toast('Could not add ' + host + ': ' + err.message, 'error'); }
    finally { TNT.ui.busy(addBtn, false); addInput.focus(); }
  }

  async function removeTarget(t) {
    const ok = await TNT.ui.confirm({ title: 'Remove ' + TNT.util.targetName(t) + '?', message: 'Monitoring of ' + t.host + ' stops and its tile goes away. History stays in the database.', ok: 'Remove', danger: true });
    if (!ok) return;
    try {
      await TNT.api.removeTarget(t.id);
      TNT.ui.toast('Removed ' + t.host, 'ok');
      TNT.app.refreshStatus();
    } catch (err) { TNT.ui.toast('Could not remove: ' + err.message, 'error'); }
  }

  async function loadDefaults(btn) {
    const current = (lastState && lastState.targets) || [];
    const extras = current.filter((t) => !['gateway', '1.1.1.1', 'totalelectronics.com'].includes(String(t.host).toLowerCase()));
    if (extras.length) {
      const ok = await TNT.ui.confirm({ title: 'Load the default tiles?',
        message: 'The tiles reset to Gateway, 1.1.1.1 and totalelectronics.com. ' + extras.length + (extras.length === 1 ? ' other tile is' : ' other tiles are') + ' removed (history stays in the database).',
        ok: 'Load defaults', danger: true });
      if (!ok) return;
    }
    TNT.ui.busy(btn, true);
    try {
      const list = await TNT.api.loadDefaultTargets();
      TNT.ui.toast('Default tiles loaded (' + (Array.isArray(list) ? list.length : '?') + ' targets)', 'ok');
      TNT.app.refreshStatus();
    } catch (err) { TNT.ui.toast('Could not load defaults: ' + err.message, 'error'); }
    finally { TNT.ui.busy(btn, false); }
  }

  TNT.views.ping = {
    mount(el) {
      const { h } = TNT.util;
      root = el;
      addInput = h('input', { class: 'input', type: 'text', placeholder: 'Add host or IP…', 'aria-label': 'Host or IP to add', autocomplete: 'off', spellcheck: 'false', style: { width: '220px' } });
      addInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); addTarget(); } });
      addBtn = h('button', { class: 'btn btn-primary', type: 'button', on: { click: addTarget } }, TNT.ui.icon('plus'), 'Add target');
      const defaultsBtn = h('button', { class: 'btn', type: 'button' }, TNT.ui.icon('refresh'), 'Load Default Tiles');
      defaultsBtn.addEventListener('click', () => loadDefaults(defaultsBtn));
      const head = h('div', { class: 'section-head' },
        h('h2', null, h('span', { class: 'section-accent' }), 'Ping'),
        h('div', { class: 'actions' }, addInput, addBtn, defaultsBtn));
      gridEl = h('div', { class: 'ping-grid' });
      wireGridDrop();
      emptyEl = h('div', { class: 'card', hidden: true }, TNT.ui.emptyState('No targets yet — add a host above or Load Default Tiles.'));
      root.appendChild(head);
      root.appendChild(emptyEl);
      root.appendChild(gridEl);
      tiles = new Map();
      samples = new Map();
      unsubs.push(TNT.api.events.on('ping.sample', onSample));
      unsubs.push(TNT.api.events.on('hello', () => { for (const rec of tiles.values()) seed(rec); }));
      ticker = setInterval(() => {
        const now = TNT.util.nowS();
        for (const rec of tiles.values()) {
          const arr = samplesFor(rec.id);
          trim(arr, now, liveKeepS(rec));
          if (rec.winSource === 'minutes') {
            if (now - rec.aggTs >= AGG_REFRESH_S) loadAggregate(rec); else if (rec.agg) rec.spark.setSamples(rec.agg, now);
          } else rec.spark.setSamples(arr, now);
        }
      }, 1000);
    },
    update(state) {
      lastState = state;
      sync(state.targets || []);
    },
    unmount() {
      for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
      unsubs = [];
      if (ticker) { clearInterval(ticker); ticker = null; }
      for (const rec of tiles.values()) rec.spark.destroy();
      tiles = new Map();
      samples = new Map();
      dragRec = null; localOrder = null;
      root = null; gridEl = null; emptyEl = null; addInput = null; addBtn = null;
    },
  };
})();
