/* TNT — views/speed.js
   Latest result (big numbers), Run now with live progress, history chart (24 h / 7 d / 30 d),
   patterns panel (by-hour bars + findings). */
(function () {
  'use strict';
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  let root = null, unsubs = [];
  let els = {};
  let historyChart = null, hourChart = null;
  let rangeDays = 1;
  let lastTs = null;
  let progressState = { running: false, phase: '', pct: 0 };
  let ticker = null;

  const PHASES = { starting: 'Starting', latency: 'Measuring latency', download: 'Downloading', upload: 'Uploading', done: 'Done', idle: '' };

  function renderLatest(sp) {
    const { fmtMbps, fmtMs, relTime, untilText, fmtDateTime, h } = TNT.util;
    if (!sp) return;
    const last = sp.last;
    const now = TNT.util.nowS();
    if (last && last.ok) {
      const changed = last.ts !== lastTs;
      els.down.textContent = fmtMbps(last.download_mbps);
      els.up.textContent = fmtMbps(last.upload_mbps);
      els.lat.textContent = fmtMs(last.latency_ms);
      els.jit.textContent = fmtMs(last.jitter_ms);
      if (changed && lastTs !== null) { TNT.util.pop(els.down); TNT.util.pop(els.up); }
      lastTs = last.ts;
      els.meta.innerHTML = '';
      els.meta.appendChild(h('span', { class: 'badge purple' }, last.backend || sp.backend || '—'));
      if (last.server) els.meta.appendChild(TNT.util.copyCode(last.server));
      if (last.isp) els.meta.appendChild(h('span', { class: 'muted' }, last.isp));
      if (last.external_ip) els.meta.appendChild(TNT.util.copyCode(last.external_ip));
      els.meta.appendChild(h('span', { class: 'muted', title: fmtDateTime(last.ts) }, relTime(last.ts, now)));
      if (last.packet_loss_pct) els.meta.appendChild(h('span', { class: 'badge yellow' }, 'loss ' + TNT.util.fmtPct(last.packet_loss_pct)));
      els.failed.hidden = true;
    } else if (last) {
      els.down.textContent = '—'; els.up.textContent = '—'; els.lat.textContent = '—'; els.jit.textContent = '—';
      els.meta.innerHTML = '';
      els.meta.appendChild(h('span', { class: 'badge red' }, 'failed'));
      els.meta.appendChild(h('span', { class: 'muted' }, relTime(last.ts, now)));
      els.failed.hidden = false;
      els.failed.textContent = 'Last test failed: ' + (last.error || 'unknown error');
    } else {
      els.meta.innerHTML = '';
      els.meta.appendChild(h('span', { class: 'muted' }, 'No speed test yet'));
      els.failed.hidden = true;
    }
    const nextText = sp.running ? 'Running now' : sp.enabled === false ? 'Automatic tests are off' : 'Next test ' + untilText(sp.next_run_ts, now) + ' · every ' + (sp.interval_min || '?') + ' min';
    els.next.textContent = nextText;
    if (sp.running && !progressState.running) setProgress(true, (sp.progress && sp.progress.phase) || 'starting', (sp.progress && sp.progress.pct) || 0);
    if (!sp.running && progressState.running && progressState.phase !== 'done') setProgress(false, 'idle', 0);
  }

  function setProgress(running, phase, pct) {
    progressState = { running, phase, pct };
    els.runBtn.disabled = running;
    els.runBtn.innerHTML = '';
    els.runBtn.appendChild(TNT.ui.icon(running ? 'spark' : 'play'));
    els.runBtn.appendChild(document.createTextNode(running ? 'Testing…' : 'Run now'));
    if (running) {
      els.fuse.hidden = false;
      els.fuse.set(pct, 'running', PHASES[phase] || phase, Math.round(pct * 100) + '%');
    } else if (phase === 'done') {
      els.fuse.hidden = false;
      els.fuse.set(1, 'done', 'Done', '100%');
      setTimeout(() => { if (els.fuse && progressState.phase === 'done') { els.fuse.hidden = true; progressState.phase = 'idle'; } }, 4000);
    } else {
      els.fuse.hidden = true;
      els.fuse.set(0, 'idle', '', '');
    }
  }

  async function runNow() {
    try {
      await TNT.api.runSpeedtest();
      setProgress(true, 'starting', 0);
      TNT.ui.toast('Speed test started', 'ok', 1800);
    } catch (err) {
      if (err.status === 409) { TNT.ui.toast('A speed test is already running', 'warn'); setProgress(true, 'starting', 0); }
      else TNT.ui.toast('Could not start: ' + err.message, 'error');
    }
  }

  async function loadHistory() {
    if (!root) return;
    const now = TNT.util.nowS();
    const from = now - rangeDays * 86400;
    try {
      const r = await TNT.api.speedtests(from, now + 60);
      if (!root) return;
      const rows = (r && r.results) || [];
      const ok = rows.filter((x) => x.ok);
      const byTs = new Map(rows.map((x) => [x.ts, x]));
      const failed = rows.filter((x) => !x.ok);
      // averages over the visible range (a test whose upload came back unknown does not drag the upload average down)
      const mean = (vals) => (vals.length ? vals.reduce((a, v) => a + v, 0) / vals.length : null);
      const avgDown = mean(ok.map((x) => x.download_mbps).filter((v) => v != null && isFinite(v)));
      const avgUp = mean(ok.map((x) => x.upload_mbps).filter((v) => v != null && isFinite(v)));
      const colors = TNT.charts.colors();
      historyChart.setData({
        xMin: from, xMax: now,
        unit: 'Mbps',
        series: [
          { name: 'Download', color: colors.purple, points: ok.map((x) => [x.ts, x.download_mbps]) },
          { name: 'Upload', color: colors.blue, points: ok.map((x) => [x.ts, x.upload_mbps]), fill: false },
        ],
        hlines: [
          { value: avgDown, color: colors.purple, label: 'avg ↓ ' + TNT.util.fmtMbps(avgDown), tip: 'Average download over the visible range' },
          { value: avgUp, color: colors.blue, label: 'avg ↑ ' + TNT.util.fmtMbps(avgUp), tip: 'Average upload over the visible range' },
        ],
        marks: failed.map((x) => ({ ts: x.ts, label: 'Test failed', detail: x.error || '' })),
      });
      historyChart.formatTip = (t) => {
        const x = byTs.get(t);
        const { fmtDateTime, fmtMbps, fmtMs } = TNT.util;
        if (!x) return fmtDateTime(t);
        return '<div class="t">' + fmtDateTime(t) + '</div>↓ ' + fmtMbps(x.download_mbps) + ' Mbps · ↑ ' + fmtMbps(x.upload_mbps) + ' Mbps' +
          '<div class="muted">' + fmtMs(x.latency_ms) + ' ms latency · ' + (x.backend || '') + (x.server ? ' · ' + x.server : '') + '</div>';
      };
      const n = ok.length;
      const avgD = n ? ok.reduce((a, x) => a + (x.download_mbps || 0), 0) / n : null;
      const avgU = n ? ok.reduce((a, x) => a + (x.upload_mbps || 0), 0) / n : null;
      els.histSummary.textContent = n ? n + ' tests · avg ↓ ' + TNT.util.fmtMbps(avgD) + ' ↑ ' + TNT.util.fmtMbps(avgU) + ' Mbps' + (failed.length ? ' · ' + failed.length + ' failed' : '') : 'No tests in this range';
    } catch (err) {
      if (root) TNT.ui.toast('Could not load history: ' + err.message, 'error');
    }
  }

  async function loadPatterns() {
    if (!root) return;
    try {
      const p = await TNT.api.speedPatterns(7);
      if (!root) return;
      const { h, fmtMbps, fmtMs, fmtDateTime, pad2 } = TNT.util;
      els.kpis.innerHTML = '';
      const kpi = (label, value, sub) => h('div', { class: 'kpi' }, h('span', { class: 'label' }, label), h('span', { class: 'value sm' }, value), sub ? h('span', { class: 'sub' }, sub) : null);
      els.kpis.appendChild(kpi('Median ↓', fmtMbps(p.median_down) + ' Mbps', 'avg ' + fmtMbps(p.avg_down)));
      els.kpis.appendChild(kpi('Median ↑', fmtMbps(p.median_up) + ' Mbps', 'avg ' + fmtMbps(p.avg_up)));
      els.kpis.appendChild(kpi('Slowest ↓', p.min_down ? fmtMbps(p.min_down.value) + ' Mbps' : '—', p.min_down ? fmtDateTime(p.min_down.ts) : ''));
      els.kpis.appendChild(kpi('Fastest ↓', p.max_down ? fmtMbps(p.max_down.value) + ' Mbps' : '—', p.max_down ? fmtDateTime(p.max_down.ts) : ''));
      els.kpis.appendChild(kpi('Tests', String(p.count || 0), (p.count || 0) - (p.ok_count || 0) + ' failed · ' + (p.days || 7) + ' days'));
      if (p.trend_down_pct_per_day != null) els.kpis.appendChild(kpi('Trend', (p.trend_down_pct_per_day > 0 ? '+' : '') + Number(p.trend_down_pct_per_day).toFixed(1) + '%/day', 'download over the week'));
      const bars = (p.by_hour || []).map((b) => ({
        label: pad2(b.hour) + ':00',
        value: b.avg_down,
        tip: '<div class="t">' + pad2(b.hour) + ':00 – ' + pad2((b.hour + 1) % 24) + ':00</div>↓ ' + fmtMbps(b.avg_down) + ' Mbps · ↑ ' + fmtMbps(b.avg_up) + ' Mbps<div class="muted">' + fmtMs(b.avg_latency) + ' ms · ' + (b.count || 0) + ' tests</div>',
        color: p.median_down && b.avg_down != null && b.avg_down < p.median_down * 0.75 ? TNT.charts.colors().orange : undefined,
      }));
      hourChart.setData({ bars, unit: 'Mbps ↓', reference: p.median_down || null, labelEvery: 3 });
      els.findings.innerHTML = '';
      const f = p.findings || [];
      if (!f.length) els.findings.appendChild(h('li', null, h('span', { class: 'spark-icon' }, TNT.ui.icon('spark')), 'Nothing unusual found yet — patterns show up after a few days of tests.'));
      for (const s of f) els.findings.appendChild(h('li', null, h('span', { class: 'spark-icon' }, TNT.ui.icon('spark')), s));
    } catch (err) {
      if (root) TNT.ui.toast('Could not load patterns: ' + err.message, 'error');
    }
  }

  TNT.views.speed = {
    mount(el) {
      const { h } = TNT.util;
      root = el;
      els = {};
      els.runBtn = h('button', { class: 'btn btn-primary', type: 'button', on: { click: runNow } }, TNT.ui.icon('play'), 'Run now');
      const head = h('div', { class: 'section-head' },
        h('h2', null, h('span', { class: 'section-accent' }), 'Speed'),
        h('div', { class: 'actions' }, els.runBtn));
      // latest
      els.down = h('span', { class: 'value' }, '—'); els.up = h('span', { class: 'value' }, '—');
      els.lat = h('span', { class: 'value sm' }, '—'); els.jit = h('span', { class: 'value sm' }, '—');
      const hero = h('div', { class: 'speed-hero' },
        h('div', { class: 'kpi' }, h('span', { class: 'label' }, 'Download'), h('span', null, h('span', { class: 'arrow down' }, '↓'), els.down, h('span', { class: 'unit' }, 'Mbps'))),
        h('div', { class: 'kpi' }, h('span', { class: 'label' }, 'Upload'), h('span', null, h('span', { class: 'arrow up' }, '↑'), els.up, h('span', { class: 'unit' }, 'Mbps'))),
        h('div', { class: 'kpi' }, h('span', { class: 'label' }, 'Latency'), h('span', null, els.lat, h('span', { class: 'unit' }, 'ms'))),
        h('div', { class: 'kpi' }, h('span', { class: 'label' }, 'Jitter'), h('span', null, els.jit, h('span', { class: 'unit' }, 'ms'))));
      els.meta = h('div', { class: 'row', style: { gap: '10px', marginTop: '12px' } });
      els.failed = h('div', { class: 'ongoing strong small', hidden: true });
      els.next = h('div', { class: 'muted small', style: { marginTop: '6px' } }, '');
      els.fuse = TNT.ui.fuse();
      els.fuse.hidden = true;
      els.fuse.style.marginTop = '14px';
      const latestCard = h('div', { class: 'card' }, h('div', { class: 'card-title' }, 'Latest result'), hero, els.meta, els.failed, els.next, els.fuse);
      // history
      const seg = TNT.ui.segmented([{ value: 1, label: '24 h' }, { value: 7, label: '7 d' }, { value: 30, label: '30 d' }], rangeDays, (v) => { rangeDays = v; loadHistory(); });
      const hcanvas = h('canvas', { style: { height: '240px' }, 'aria-label': 'Speed test history' });
      els.histSummary = h('span', { class: 'muted small' }, '');
      const legend = h('div', { class: 'legend' },
        h('span', null, h('span', { class: 'sw', style: { background: 'var(--purple)' } }), 'download'),
        h('span', null, h('span', { class: 'sw', style: { background: 'var(--blue)' } }), 'upload'),
        h('span', null, h('span', { class: 'sw', style: { background: 'var(--red)' } }), 'failed'));
      const histCard = h('div', { class: 'card' },
        h('div', { class: 'card-title' }, 'History', h('span', { class: 'spacer' }), seg),
        h('div', { class: 'row between', style: { marginBottom: '8px' } }, legend, els.histSummary),
        h('div', { class: 'chart-wrap' }, hcanvas));
      // patterns
      els.kpis = h('div', { class: 'kpis', style: { marginBottom: '14px' } });
      const bcanvas = h('canvas', { style: { height: '200px' }, 'aria-label': 'Average download by hour of day' });
      els.findings = h('ul', { class: 'findings' });
      const patCard = h('div', { class: 'card' },
        h('div', { class: 'card-title' }, 'Patterns', h('span', { class: 'badge purple' }, 'last 7 days')),
        els.kpis,
        h('div', { class: 'label', style: { marginBottom: '6px' } }, 'Average download by hour of day'),
        h('div', { class: 'chart-wrap' }, bcanvas),
        h('div', { class: 'label', style: { margin: '14px 0 8px' } }, 'Findings'),
        els.findings);
      root.appendChild(head);
      root.appendChild(h('div', { class: 'stack' }, latestCard, histCard, patCard));
      historyChart = new TNT.charts.LineChart(hcanvas, { unit: 'Mbps' });
      hourChart = new TNT.charts.BarChart(bcanvas, { unit: 'Mbps' });
      lastTs = null;
      progressState = { running: false, phase: 'idle', pct: 0 };
      loadHistory();
      loadPatterns();
      unsubs.push(TNT.api.events.on('speedtest.start', () => setProgress(true, 'starting', 0)));
      unsubs.push(TNT.api.events.on('speedtest.progress', (d) => { if (d) setProgress(true, d.phase, d.pct || 0); }));
      unsubs.push(TNT.api.events.on('speedtest.done', () => { setProgress(false, 'done', 1); setTimeout(() => { loadHistory(); loadPatterns(); }, 300); }));
      unsubs.push(TNT.api.events.on('hello', () => { loadHistory(); loadPatterns(); }));
      ticker = setInterval(() => { const st = TNT.state.status; if (st && st.speed) renderLatest(st.speed); }, 5000);
    },
    update(state) {
      if (state.status && state.status.speed) renderLatest(state.status.speed);
    },
    unmount() {
      for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
      unsubs = [];
      if (ticker) { clearInterval(ticker); ticker = null; }
      if (historyChart) { historyChart.destroy(); historyChart = null; }
      if (hourChart) { hourChart.destroy(); hourChart = null; }
      root = null; els = {};
    },
  };
})();
