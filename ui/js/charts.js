/* TNT — charts.js
   Hand-written canvas charts: Sparkline (5-minute RTT), Timeline (24 h outages),
   LineChart (speed history), BarChart (by-hour patterns) and Throughput (live per-NIC
   send/receive over a moving window). All charts scale for
   devicePixelRatio, re-render on resize (ResizeObserver) and read their colours from the
   CSS custom properties so they follow the theme. Exposes window.TNT.charts. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;

  const registry = new Set();

  function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback || '#000';
  }

  function colors() {
    return {
      bg: cssVar('--bg', '#FFF7E8'),
      paper: cssVar('--paper', '#fff'),
      paper2: cssVar('--paper-2', '#FFF1D6'),
      ink: cssVar('--ink', '#2B2438'),
      inkSoft: cssVar('--ink-soft', '#6B6480'),
      red: cssVar('--red', '#FF5C5C'),
      yellow: cssVar('--yellow', '#FFD166'),
      green: cssVar('--green', '#6BCB77'),
      blue: cssVar('--blue', '#6FA8FF'),
      purple: cssVar('--purple', '#B48CFF'),
      orange: cssVar('--orange', '#FFA45C'),
      teal: cssVar('--teal', '#4FD1C5'),
    };
  }

  function fontFamily() {
    return getComputedStyle(document.body).fontFamily || 'system-ui, sans-serif';
  }

  function alpha(hex, a) {
    // hex "#RRGGBB" → "rgba(r,g,b,a)"; anything else passes through with opacity via globalAlpha instead
    const m = /^#([0-9a-f]{6})$/i.exec(hex.trim());
    if (!m) return hex;
    const n = parseInt(m[1], 16);
    return 'rgba(' + (n >> 16) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
  }

  function roundRect(ctx, x, y, w, h, r) {
    r = Math.max(0, Math.min(r, w / 2, h / 2));
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.arcTo(x + w, y, x + w, y + r, r);
    ctx.lineTo(x + w, y + h - r);
    ctx.arcTo(x + w, y + h, x + w - r, y + h, r);
    ctx.lineTo(x + r, y + h);
    ctx.arcTo(x, y + h, x, y + h - r, r);
    ctx.lineTo(x, y + r);
    ctx.arcTo(x, y, x + r, y, r);
    ctx.closePath();
  }

  /** Text made safe to sit inside a tooltip's HTML. A tooltip is built as a string and handed to
   *  innerHTML, and much of what goes into one came from somewhere else: a failed speed test's error
   *  carries the first bytes of whatever answered the probe (a captive portal's page, a proxy's block
   *  page), a target's host name is whatever was typed. Every such string goes through this, so it
   *  reads as the text it is and never becomes an element in the TNT window. charts.js loads before
   *  app.js, so it keeps its own copy of TNT.util.esc. */
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  }

  function pad2(n) { return (n < 10 ? '0' : '') + n; }
  function clock(ts) { const d = new Date(ts * 1000); return pad2(d.getHours()) + ':' + pad2(d.getMinutes()); }
  function clockS(ts) { const d = new Date(ts * 1000); return clock(ts) + ':' + pad2(d.getSeconds()); }
  /* " (87.5%)" for a timeline segment's missed percentage, floored like the Outages list ('' when unknown) */
  function missedPctText(s) {
    const p = s && s.missed_pct;
    if (p == null || !isFinite(p)) return '';
    const t = p >= 100 ? '100%' : p <= 0 ? '0%' : p < 0.1 ? '<0.1%' : (Math.floor(p * 10) / 10).toFixed(1) + '%';
    return ' (' + (s.sent_estimated ? '≈' : '') + t + ')';
  }
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  function dayLabel(ts) { const d = new Date(ts * 1000); return MONTHS[d.getMonth()] + ' ' + d.getDate(); }
  function durationText(s) {
    s = Math.max(0, Math.round(s));
    if (s < 60) return s + ' s';
    if (s < 3600) return Math.floor(s / 60) + 'm ' + pad2(s % 60) + 's';
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    if (s < 86400) return h + 'h ' + pad2(m) + 'm';
    return Math.floor(s / 86400) + 'd ' + (h % 24) + 'h';
  }
  function niceStep(range, ticks) {
    const raw = range / Math.max(1, ticks);
    const mag = Math.pow(10, Math.floor(Math.log10(raw || 1)));
    for (const m of [1, 2, 2.5, 5, 10]) { if (m * mag >= raw) return m * mag; }
    return 10 * mag;
  }

  /* ---------------------------------------------------------------- base */
  class Chart {
    constructor(canvas, opts) {
      this.canvas = canvas;
      this.opts = opts || {};
      this.ctx = canvas.getContext('2d');
      this.hits = [];
      this._w = 0; this._h = 0; this._dpr = 0;
      this._raf = 0;
      this._tip = null;
      this._hover = null;
      this._onMove = (e) => this._mouse(e);
      this._onLeave = () => this._leave();
      canvas.addEventListener('mousemove', this._onMove);
      canvas.addEventListener('mouseleave', this._onLeave);
      canvas.addEventListener('touchstart', (e) => { if (e.touches[0]) this._mouse(e.touches[0]); }, { passive: true });
      this._ro = null;
      if (typeof ResizeObserver !== 'undefined') {
        this._ro = new ResizeObserver(() => this.render());
        this._ro.observe(canvas);
      } else {
        this._onResize = () => this.render();
        window.addEventListener('resize', this._onResize);
      }
      registry.add(this);
    }

    _prepare() {
      const rect = this.canvas.getBoundingClientRect();
      const w = Math.max(1, Math.round(rect.width));
      const h = Math.max(1, Math.round(rect.height));
      const dpr = Math.max(1, window.devicePixelRatio || 1);
      if (w !== this._w || h !== this._h || dpr !== this._dpr) {
        this._w = w; this._h = h; this._dpr = dpr;
        this.canvas.width = Math.round(w * dpr);
        this.canvas.height = Math.round(h * dpr);
      }
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      return { w, h };
    }

    /** Schedule a render on the next animation frame (coalesces bursts). */
    render() {
      if (this._raf) return;
      this._raf = requestAnimationFrame(() => { this._raf = 0; this.renderNow(); });
    }

    renderNow() {
      if (!this.canvas.isConnected) return;
      const { w, h } = this._prepare();
      if (w < 4 || h < 4) return;
      const ctx = this.ctx;
      ctx.clearRect(0, 0, w, h);
      this.hits = [];
      this.c = colors();
      this.font = fontFamily();
      try { this.draw(ctx, w, h); } catch (err) { console.error('chart draw failed', err); }
    }

    draw() { /* override */ }

    _mouse(e) {
      const rect = this.canvas.getBoundingClientRect();
      const x = e.clientX - rect.left, y = e.clientY - rect.top;
      const hit = this.hitTest(x, y);
      if (hit !== this._hover) {
        this._hover = hit;
        this.onHover(hit, x, y);
      } else if (hit) {
        this._positionTip(x, y);
      }
    }

    _leave() { this._hover = null; this.onHover(null); }

    hitTest(x, y) {
      let best = null, bestPri = -1;
      for (const h of this.hits) {
        if (x >= h.x0 && x <= h.x1 && y >= h.y0 && y <= h.y1) {
          const pri = h.priority || 0;
          if (pri > bestPri) { best = h; bestPri = pri; }
        }
      }
      return best;
    }

    onHover(hit, x, y) {
      if (!hit || !hit.tip) { this.hideTip(); return; }
      this.showTip(hit.tip, x, y);
    }

    /** `html` is markup: the tooltips built in this file escape every string that came from
     *  elsewhere (esc above), and a caller that hands in its own markup (a LineChart's formatTip,
     *  a bar's tip) escapes its own fields the same way, with TNT.util.esc. An average rule's
     *  label and tip are text. */
    showTip(html, x, y) {
      const parent = this.canvas.parentElement;
      if (!parent) return;
      if (!this._tip) {
        this._tip = document.createElement('div');
        this._tip.className = 'chart-tip';
        parent.appendChild(this._tip);
      }
      this._tip.innerHTML = html;
      this._tip.style.display = 'block';
      this._positionTip(x, y);
    }

    _positionTip(x, y) {
      if (!this._tip || this._tip.style.display === 'none') return;
      const parent = this.canvas.parentElement;
      const pw = parent.clientWidth;
      const tw = this._tip.offsetWidth, th = this._tip.offsetHeight;
      let left = x + 14, top = y - th - 12;
      if (left + tw > pw - 4) left = Math.max(4, x - tw - 14);
      if (top < 0) top = y + 16;
      this._tip.style.left = left + 'px';
      this._tip.style.top = top + 'px';
    }

    hideTip() { if (this._tip) this._tip.style.display = 'none'; }

    destroy() {
      registry.delete(this);
      if (this._ro) this._ro.disconnect();
      if (this._onResize) window.removeEventListener('resize', this._onResize);
      if (this._raf) cancelAnimationFrame(this._raf);
      this.canvas.removeEventListener('mousemove', this._onMove);
      this.canvas.removeEventListener('mouseleave', this._onLeave);
      if (this._tip) this._tip.remove();
    }
  }

  /* ----------------------------------------------------------- sparkline */
  /** 5-minute RTT sparkline: ink line, green fill, red ticks for misses. */
  class Sparkline extends Chart {
    constructor(canvas, opts) {
      super(canvas, opts);
      this.samples = [];   // [[ts, rtt|null, lossPct?], ...] ascending
      this.windowS = (opts && opts.windowS) || 300;
      this.stepS = (opts && opts.stepS) || 1;          // spacing between samples (1 s live, 60 s aggregated)
      this.label = opts && opts.label !== undefined ? opts.label : '5 min';   // '' hides the canvas label
      this.now = 0;
    }

    setSamples(samples, now) {
      this.samples = samples;
      this.now = now || (Date.now() / 1000);
      this.render();
    }

    /** Switch the visible window (seconds), sample spacing and label; re-renders. */
    setWindow(windowS, stepS, label) {
      this.windowS = windowS || 300;
      this.stepS = stepS || 1;
      if (label !== undefined) this.label = label;
      this.render();
    }

    draw(ctx, w, h) {
      const c = this.c;
      const now = this.now || Date.now() / 1000;
      const t0 = now - this.windowS;
      const padT = 14, tick = 9, padB = 3;
      const baseY = h - padB - 1;
      const plotH = baseY - padT - tick;
      const xOf = (ts) => ((ts - t0) / this.windowS) * (w - 2) + 1;

      // baseline
      ctx.strokeStyle = alpha(c.ink, 0.25);
      ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(0, baseY + 0.5); ctx.lineTo(w, baseY + 0.5); ctx.stroke();

      const rows = this.samples.filter((s) => s[0] >= t0 - 1 && s[0] <= now + 1);
      let max = 0, count = 0;
      for (const s of rows) { if (s[1] != null) { if (s[1] > max) max = s[1]; count++; } }
      if (!rows.length) {
        ctx.fillStyle = c.inkSoft;
        ctx.font = '700 12px ' + this.font;
        ctx.textAlign = 'center';
        ctx.fillText('waiting for samples…', w / 2, h / 2 + 4);
        return;
      }
      const yMax = Math.max(1, max * 1.15);
      const yOf = (v) => baseY - tick - (v / yMax) * plotH;

      // segments of consecutive ok samples (a miss or a >2.5 s gap breaks the line)
      const segs = [];
      let cur = null, prevTs = null;
      for (const s of rows) {
        if (s[1] == null) { cur = null; prevTs = s[0]; continue; }
        if (!cur || (prevTs != null && s[0] - prevTs > 2.5 * this.stepS)) { cur = []; segs.push(cur); }
        cur.push(s);
        prevTs = s[0];
      }
      // fills
      ctx.fillStyle = alpha(c.green, 0.4);
      for (const seg of segs) {
        ctx.beginPath();
        ctx.moveTo(xOf(seg[0][0]), baseY - tick);
        for (const s of seg) ctx.lineTo(xOf(s[0]), yOf(s[1]));
        ctx.lineTo(xOf(seg[seg.length - 1][0]), baseY - tick);
        ctx.closePath();
        ctx.fill();
      }
      // lines
      ctx.strokeStyle = c.ink;
      ctx.lineWidth = 2;
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';
      for (const seg of segs) {
        ctx.beginPath();
        if (seg.length === 1) {
          ctx.arc(xOf(seg[0][0]), yOf(seg[0][1]), 1.5, 0, Math.PI * 2);
          ctx.fillStyle = c.ink; ctx.fill();
          continue;
        }
        ctx.moveTo(xOf(seg[0][0]), yOf(seg[0][1]));
        for (let i = 1; i < seg.length; i++) ctx.lineTo(xOf(seg[i][0]), yOf(seg[i][1]));
        ctx.stroke();
      }
      // misses: short red ticks at the bottom
      ctx.fillStyle = c.red;
      const tickW = Math.max(2, Math.round(((w - 2) / this.windowS) * this.stepS));
      for (const s of rows) {
        if (s[1] == null || (s[2] != null && s[2] > 0)) ctx.fillRect(Math.round(xOf(s[0])) - 1, baseY - tick + 1, tickW, tick - 1);
      }
      // scale label
      ctx.fillStyle = c.inkSoft;
      ctx.font = '800 11px ' + this.font;
      ctx.textAlign = 'right';
      ctx.fillText('max ' + (max < 10 ? max.toFixed(1) : Math.round(max)) + ' ms', w - 4, 11);
      if (this.label) { ctx.textAlign = 'left'; ctx.fillText(this.label, 3, 11); }
    }
  }

  /* ------------------------------------------------------------ timeline */
  /** 24 h outage timeline. */
  class Timeline extends Chart {
    constructor(canvas, opts) {
      super(canvas, opts);
      this.data = null;
    }

    setData(data) { this.data = data; this.render(); }

    draw(ctx, w, h) {
      const c = this.c, d = this.data;
      const padL = 14, padR = 30;
      const barY = 44, barH = 28, r = 14;
      const x0 = padL, x1 = w - padR;
      const now = d ? d.end_ts : Date.now() / 1000;
      const start = d ? d.start_ts : now - 86400;
      const span = Math.max(1, now - start);
      const xOf = (ts) => x0 + ((ts - start) / span) * (x1 - x0);
      const font = this.font;

      // base bar (green) with ink outline
      roundRect(ctx, x0, barY, x1 - x0, barH, r);
      ctx.fillStyle = c.green;
      ctx.fill();

      // gaps: hatched grey, clipped to the bar
      const gaps = (d && d.gaps) || [];
      if (gaps.length) {
        ctx.save();
        roundRect(ctx, x0, barY, x1 - x0, barH, r);
        ctx.clip();
        for (const g of gaps) {
          const gx0 = xOf(g.start_ts), gx1 = Math.max(xOf(g.end_ts), xOf(g.start_ts) + 3);
          ctx.fillStyle = c.paper2;
          ctx.fillRect(gx0, barY, gx1 - gx0, barH);
          ctx.save();
          ctx.beginPath(); ctx.rect(gx0, barY, gx1 - gx0, barH); ctx.clip();
          ctx.strokeStyle = alpha(c.ink, 0.35);
          ctx.lineWidth = 2;
          for (let x = gx0 - barH; x < gx1 + barH; x += 7) {
            ctx.beginPath(); ctx.moveTo(x, barY + barH); ctx.lineTo(x + barH, barY); ctx.stroke();
          }
          ctx.restore();
          ctx.strokeStyle = alpha(c.ink, 0.5);
          ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.moveTo(gx0 + 0.5, barY); ctx.lineTo(gx0 + 0.5, barY + barH); ctx.stroke();
          ctx.beginPath(); ctx.moveTo(gx1 - 0.5, barY); ctx.lineTo(gx1 - 0.5, barY + barH); ctx.stroke();
          this.hits.push({ x0: gx0, x1: gx1, y0: barY, y1: barY + barH, priority: 1,
            tip: '<div class="t">Not monitoring</div>' + clockS(g.start_ts) + ' – ' + clockS(g.end_ts) +
              '<div class="muted">' + durationText(g.end_ts - g.start_ts) + '</div>' });
        }
        ctx.restore();
      }

      // spans: target (yellow) under total (red)
      const totals = ((d && d.total_segments) || []).slice().sort((a, b) => a.start_ts - b.start_ts);
      const targets = ((d && d.segments) || []).filter((s) =>
        !totals.some((t) => t.start_ts <= s.start_ts + 0.5 && t.end_ts >= s.end_ts - 0.5)
      ).sort((a, b) => a.start_ts - b.start_ts);

      const drawSpan = (s, fill, pri) => {
        const sx0 = xOf(s.start_ts);
        const sx1 = Math.max(xOf(s.end_ts), sx0 + 5);
        roundRect(ctx, sx0, barY + 1, sx1 - sx0, barH - 2, 8);
        ctx.fillStyle = fill; ctx.fill();
        ctx.strokeStyle = c.ink; ctx.lineWidth = 2; ctx.stroke();
        const title = s.kind === 'total_internet' ? 'Internet outage'
          : s.kind === 'total_local' ? 'Local network outage'
          : (s.host || ('target ' + s.target_id)) + ' down';
        const end = s.open ? now : s.end_ts;
        const tip = '<div class="t">' + esc(title) + (s.open ? ' <span class="ongoing">· ongoing</span>' : '') + '</div>' +
          clockS(s.start_ts) + ' – ' + (s.open ? 'now' : clockS(end)) +
          '<div class="muted">' + durationText(end - s.start_ts) +
          (s.missed ? ' · ' + esc(s.missed) + ' missed' + esc(missedPctText(s)) : '') + '</div>';
        this.hits.push({ x0: sx0, x1: sx1, y0: barY - 2, y1: barY + barH + 2, priority: pri, tip });
        return { x: sx0, x1: sx1, s, title };
      };
      const placed = [];
      for (const s of targets) placed.push(Object.assign(drawSpan(s, c.yellow, 2), { color: c.yellow }));
      for (const s of totals) placed.push(Object.assign(drawSpan(s, c.red, 3), { color: c.red }));

      // bar outline on top of everything
      roundRect(ctx, x0, barY, x1 - x0, barH, r);
      ctx.strokeStyle = c.ink; ctx.lineWidth = 3; ctx.stroke();

      // leader lines above each span (no timestamps: a busy day turned those into a pile-up;
      // the hover tooltip carries start/end/duration)
      for (const p of placed) {
        const lx = Math.round(p.x) + 0.5;
        ctx.strokeStyle = alpha(c.ink, 0.5); ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.moveTo(lx, barY); ctx.lineTo(lx, barY - 10); ctx.stroke();
        ctx.fillStyle = p.color;
        ctx.beginPath(); ctx.arc(lx, barY - 12, 3, 0, Math.PI * 2); ctx.fill();
        ctx.strokeStyle = c.ink; ctx.lineWidth = 1.5; ctx.stroke();
      }

      // time axis: minute ticks for short ranges, hour ticks up to two days, and day /
      // week delimiters drawn through the bar for the long ranges
      const hours = d ? d.hours : 24;
      ctx.font = '700 12px ' + font;
      ctx.textAlign = 'center';
      const minPx = 46;
      let lastLabelX = -Infinity;
      const tick = (x, major) => {
        ctx.strokeStyle = alpha(c.ink, major ? 0.7 : 0.35);
        ctx.lineWidth = major ? 2 : 1;
        ctx.beginPath(); ctx.moveTo(x, barY + barH + 2); ctx.lineTo(x, barY + barH + (major ? 9 : 5)); ctx.stroke();
      };
      const label = (x, text) => {
        if (x - lastLabelX >= minPx && x < x1 - 8) { ctx.fillStyle = c.inkSoft; ctx.fillText(text, x, barY + barH + 24); lastLabelX = x; }
      };
      if (hours > 48) {
        // one delimiter per local midnight; in the 30-day view Mondays are the strong,
        // labelled ones and the other days stay faint and unlabelled
        const weekly = hours > 24 * 10;
        const dt = new Date(start * 1000);
        dt.setHours(0, 0, 0, 0);
        dt.setDate(dt.getDate() + 1);
        for (; dt.getTime() / 1000 <= now; dt.setDate(dt.getDate() + 1)) {
          const t = dt.getTime() / 1000;
          const x = Math.round(xOf(t)) + 0.5;
          const strong = !weekly || dt.getDay() === 1;
          ctx.save();
          ctx.strokeStyle = alpha(c.ink, strong ? 0.6 : 0.28);
          ctx.lineWidth = strong ? 2 : 1;
          ctx.setLineDash(strong ? [] : [3, 3]);
          ctx.beginPath(); ctx.moveTo(x, barY - 4); ctx.lineTo(x, barY + barH + 9); ctx.stroke();
          ctx.restore();
          if (strong) label(x, (weekly ? 'Mon ' : ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][dt.getDay()] + ' ') + (dt.getMonth() + 1) + '/' + dt.getDate());
        }
      } else {
        const stepMin = hours <= 0.25 ? 1 : hours <= 1 ? 5 : hours <= 6 ? 15 : 60;
        const labelMin = hours <= 0.25 ? 5 : hours <= 1 ? 15 : hours <= 6 ? 60 : (hours <= 12 ? 120 : 180);
        const first = new Date(start * 1000);
        first.setSeconds(0, 0);
        first.setMinutes(Math.ceil(first.getMinutes() / stepMin) * stepMin);
        for (let t = first.getTime() / 1000; t <= now; t += stepMin * 60) {
          const x = Math.round(xOf(t)) + 0.5;
          const dt = new Date(t * 1000);
          const minuteOfDay = dt.getHours() * 60 + dt.getMinutes();
          const major = minuteOfDay % labelMin === 0;
          tick(x, major);
          if (major) label(x, pad2(dt.getHours()) + ':' + pad2(dt.getMinutes()));
          if (minuteOfDay === 0 && hours > 6) {   // midnight delimiter through the bar in the 24 h view
            ctx.save();
            ctx.strokeStyle = alpha(c.ink, 0.5); ctx.lineWidth = 2; ctx.setLineDash([4, 3]);
            ctx.beginPath(); ctx.moveTo(x, barY - 4); ctx.lineTo(x, barY + barH + 4); ctx.stroke();
            ctx.restore();
          }
        }
      }

      // "now" marker at the right edge
      const nx = Math.round(x1) + 0.5;
      ctx.strokeStyle = c.ink; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.moveTo(nx, barY - 8); ctx.lineTo(nx, barY + barH + 8); ctx.stroke();
      ctx.fillStyle = c.orange;
      ctx.beginPath(); ctx.moveTo(nx - 6, barY - 14); ctx.lineTo(nx + 6, barY - 14); ctx.lineTo(nx, barY - 6); ctx.closePath();
      ctx.fill(); ctx.strokeStyle = c.ink; ctx.lineWidth = 1.5; ctx.stroke();
      ctx.fillStyle = c.ink;
      ctx.font = '800 11px ' + font;
      ctx.textAlign = 'left';
      ctx.fillText('now', nx + 4, barY + barH + 24);
    }
  }

  /* ----------------------------------------------------------- linechart */
  /** Multi-series line chart over time. series: [{name, color, points:[[ts, value]]}]. */
  class LineChart extends Chart {
    constructor(canvas, opts) {
      super(canvas, opts);
      this.series = [];
      this.marks = [];
      this.xMin = 0; this.xMax = 0;
      this.unit = (opts && opts.unit) || '';
      this.formatTip = (opts && opts.formatTip) || null;
    }

    setData(d) {
      this.series = d.series || [];
      this.marks = d.marks || [];
      // horizontal reference lines, e.g. averages: [{value, color, label}]
      this.hlines = (d.hlines || []).filter((l) => l && l.value != null && isFinite(l.value));
      this.xMin = d.xMin; this.xMax = d.xMax;
      if (d.unit !== undefined) this.unit = d.unit;
      this.render();
    }

    draw(ctx, w, h) {
      const c = this.c, font = this.font;
      const padL = 46, padR = 14, padT = 14, padB = 28;
      const px0 = padL, px1 = w - padR, py0 = padT, py1 = h - padB;
      let xMin = this.xMin, xMax = this.xMax;
      const all = [];
      for (const s of this.series) for (const p of s.points) if (p[1] != null) all.push(p);
      if (!xMin || !xMax) {
        if (all.length) { xMin = Math.min.apply(null, all.map((p) => p[0])); xMax = Math.max.apply(null, all.map((p) => p[0])); }
        else { xMax = Date.now() / 1000; xMin = xMax - 86400; }
      }
      if (xMax <= xMin) xMax = xMin + 1;
      let yMax = 0;
      for (const p of all) if (p[1] > yMax) yMax = p[1];
      for (const l of this.hlines || []) if (l.value > yMax) yMax = l.value;
      yMax = yMax > 0 ? yMax * 1.12 : 10;
      const step = niceStep(yMax, 4);
      yMax = Math.ceil(yMax / step) * step;
      const xOf = (t) => px0 + ((t - xMin) / (xMax - xMin)) * (px1 - px0);
      const yOf = (v) => py1 - (v / yMax) * (py1 - py0);

      // grid + y labels
      ctx.font = '700 12px ' + font;
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      for (let v = 0; v <= yMax + 1e-9; v += step) {
        const y = Math.round(yOf(v)) + 0.5;
        ctx.strokeStyle = alpha(c.ink, v === 0 ? 0.6 : 0.15);
        ctx.lineWidth = v === 0 ? 2 : 1;
        ctx.setLineDash(v === 0 ? [] : [3, 4]);
        ctx.beginPath(); ctx.moveTo(px0, y); ctx.lineTo(px1, y); ctx.stroke();
        ctx.fillStyle = c.inkSoft;
        ctx.fillText(String(Math.round(v)), px0 - 8, y);
      }
      ctx.setLineDash([]);
      ctx.textBaseline = 'alphabetic';
      if (this.unit) {
        ctx.textAlign = 'left';
        ctx.fillStyle = c.inkSoft;
        ctx.font = '800 11px ' + font;
        ctx.fillText(this.unit, px0 + 4, py0 - 2);
      }

      // x ticks
      const rangeS = xMax - xMin;
      const days = rangeS / 86400;
      ctx.textAlign = 'center';
      ctx.font = '700 12px ' + font;
      const ticks = [];
      if (days <= 2) {
        const stepH = days <= 0.5 ? 1 : (days <= 1 ? 3 : 6);
        const d0 = new Date(xMin * 1000); d0.setMinutes(0, 0, 0);
        for (let t = d0.getTime() / 1000; t <= xMax; t += 3600) {
          if (new Date(t * 1000).getHours() % stepH === 0 && t >= xMin) ticks.push({ t, label: clock(t) });
        }
      } else {
        const stepD = days <= 8 ? 1 : (days <= 16 ? 2 : (days <= 40 ? 5 : 10));
        const d0 = new Date(xMin * 1000); d0.setHours(0, 0, 0, 0);
        let i = 0;
        for (let t = d0.getTime() / 1000; t <= xMax; t += 86400, i++) {
          if (i % stepD === 0 && t >= xMin) ticks.push({ t, label: dayLabel(t) });
        }
      }
      let lastX = -Infinity;
      for (const tk of ticks) {
        const x = Math.round(xOf(tk.t)) + 0.5;
        ctx.strokeStyle = alpha(c.ink, 0.35); ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(x, py1); ctx.lineTo(x, py1 + 6); ctx.stroke();
        if (x - lastX >= 44) { ctx.fillStyle = c.inkSoft; ctx.fillText(tk.label, x, py1 + 20); lastX = x; }
      }

      // series
      for (const s of this.series) {
        const pts = s.points.filter((p) => p[1] != null && p[0] >= xMin && p[0] <= xMax).sort((a, b) => a[0] - b[0]);
        if (!pts.length) continue;
        if (s.fill !== false) {
          ctx.fillStyle = alpha(s.color, 0.12);
          ctx.beginPath();
          ctx.moveTo(xOf(pts[0][0]), py1);
          for (const p of pts) ctx.lineTo(xOf(p[0]), yOf(p[1]));
          ctx.lineTo(xOf(pts[pts.length - 1][0]), py1);
          ctx.closePath(); ctx.fill();
        }
        ctx.strokeStyle = s.line || s.color; ctx.lineWidth = 2.5; ctx.lineJoin = 'round'; ctx.lineCap = 'round';
        ctx.beginPath();
        ctx.moveTo(xOf(pts[0][0]), yOf(pts[0][1]));
        for (let i = 1; i < pts.length; i++) ctx.lineTo(xOf(pts[i][0]), yOf(pts[i][1]));
        ctx.stroke();
        // ink outline dots when few points
        if (pts.length <= 60) {
          for (const p of pts) {
            ctx.beginPath(); ctx.arc(xOf(p[0]), yOf(p[1]), 3.5, 0, Math.PI * 2);
            ctx.fillStyle = s.color; ctx.fill(); ctx.strokeStyle = c.ink; ctx.lineWidth = 1.5; ctx.stroke();
          }
        }
      }
      // horizontal reference lines (averages): dashed in the series colour with a sticker
      // label at the right edge; labels that would overlap are pushed apart
      if (this.hlines && this.hlines.length) {
        ctx.font = '800 11px ' + font;
        const placed = [];
        const lines = this.hlines.slice().sort((a, b) => yOf(b.value) - yOf(a.value));   // bottom first
        for (const l of lines) {
          const y = Math.round(yOf(l.value)) + 0.5;
          ctx.save();
          ctx.strokeStyle = l.color || c.ink;
          ctx.lineWidth = 2;
          ctx.setLineDash([7, 5]);
          ctx.beginPath(); ctx.moveTo(px0, y); ctx.lineTo(px1, y); ctx.stroke();
          ctx.restore();
          if (!l.label) continue;
          const text = l.label;
          const tw = ctx.measureText(text).width, bw = tw + 14, bh = 18;
          let ly = y - bh / 2;   // label centred on the line, right-aligned inside the plot
          for (const p of placed) if (Math.abs(ly - p) < bh + 2) ly = p - bh - 2;   // stack upwards if crowded
          ly = Math.max(py0 - 2, Math.min(py1 - bh, ly));
          placed.push(ly);
          const lx = px1 - bw - 4;
          ctx.fillStyle = c.paper;
          ctx.strokeStyle = l.color || c.ink;
          ctx.lineWidth = 2;
          roundRect(ctx, lx, ly, bw, bh, 9);
          ctx.fill(); ctx.stroke();
          ctx.fillStyle = c.ink;
          ctx.textAlign = 'left';
          ctx.textBaseline = 'middle';
          ctx.fillText(text, lx + 7, ly + bh / 2 + 0.5);
          ctx.textBaseline = 'alphabetic';
          this.hits.push({ x0: lx, x1: lx + bw, y0: ly, y1: ly + bh, priority: 6,
            tip: '<div class="t">' + esc(text) + '</div>' + esc(l.tip || 'average over the visible range') });
        }
      }
      // marks (failed tests): red x at the bottom
      for (const m of this.marks) {
        if (m.ts < xMin || m.ts > xMax) continue;
        const x = xOf(m.ts), y = py1 - 7;
        ctx.strokeStyle = m.color || c.red; ctx.lineWidth = 2.5;
        ctx.beginPath(); ctx.moveTo(x - 4, y - 4); ctx.lineTo(x + 4, y + 4); ctx.moveTo(x + 4, y - 4); ctx.lineTo(x - 4, y + 4); ctx.stroke();
        this.hits.push({ x0: x - 6, x1: x + 6, y0: y - 8, y1: y + 8, priority: 5,
          // m.detail is a failed speed test's error, which can carry the raw body of the reply
          tip: '<div class="t">' + esc(m.label || 'Failed') + '</div>' + clock(m.ts) + ' · ' + dayLabel(m.ts) + (m.detail ? '<div class="muted">' + esc(m.detail) + '</div>' : '') });
      }

      // hover columns: one hit per x-sample across series (nearest point by time)
      const times = new Set();
      for (const s of this.series) for (const p of s.points) if (p[0] >= xMin && p[0] <= xMax) times.add(p[0]);
      const sorted = Array.from(times).sort((a, b) => a - b);
      for (let i = 0; i < sorted.length; i++) {
        const t = sorted[i];
        const x = xOf(t);
        const left = i === 0 ? px0 : (xOf(sorted[i - 1]) + x) / 2;
        const right = i === sorted.length - 1 ? px1 : (x + xOf(sorted[i + 1])) / 2;
        const vals = this.series.map((s) => { const p = s.points.find((q) => q[0] === t); return { name: s.name, color: s.color, v: p ? p[1] : null }; });
        let tip;
        if (this.formatTip) tip = this.formatTip(t, vals);
        else tip = '<div class="t">' + clock(t) + ' · ' + dayLabel(t) + '</div>' + vals.map((v) => esc(v.name) + ': ' + (v.v == null ? '—' : esc(v.v))).join('<br>');
        this.hits.push({ x0: left, x1: right, y0: py0, y1: py1, priority: 1, tip, x, t, vals });
      }
    }

    onHover(hit, x, y) {
      super.onHover(hit, x, y);
      this._drawGuide(hit);
    }

    _drawGuide(hit) {
      // Re-render then draw the guide + dots on top (cheap enough; charts are small).
      this.renderNow();
      if (!hit || hit.x === undefined) return;
      const ctx = this.ctx, c = this.c;
      const h = this._h, padT = 14, padB = 28;
      ctx.save();
      ctx.strokeStyle = alpha(c.ink, 0.5); ctx.lineWidth = 1.5; ctx.setLineDash([4, 4]);
      ctx.beginPath(); ctx.moveTo(hit.x, padT); ctx.lineTo(hit.x, h - padB); ctx.stroke();
      ctx.restore();
    }
  }

  /* ------------------------------------------------------------ barchart */
  /** Vertical bars, e.g. 24 hour-of-day buckets. bars: [{label, value, tip, color?}] */
  class BarChart extends Chart {
    constructor(canvas, opts) {
      super(canvas, opts);
      this.bars = [];
      this.unit = (opts && opts.unit) || '';
      this.labelEvery = (opts && opts.labelEvery) || 3;
      this.reference = null;   // dashed reference line value (e.g. median)
    }

    setData(d) {
      this.bars = d.bars || [];
      if (d.unit !== undefined) this.unit = d.unit;
      if (d.reference !== undefined) this.reference = d.reference;
      if (d.labelEvery) this.labelEvery = d.labelEvery;
      this.render();
    }

    draw(ctx, w, h) {
      const c = this.c, font = this.font;
      const padL = 46, padR = 12, padT = 14, padB = 28;
      const px0 = padL, px1 = w - padR, py0 = padT, py1 = h - padB;
      const n = this.bars.length;
      if (!n) return;
      let yMax = 0;
      for (const b of this.bars) if (b.value != null && b.value > yMax) yMax = b.value;
      if (this.reference && this.reference > yMax) yMax = this.reference;
      yMax = yMax > 0 ? yMax * 1.12 : 10;
      const step = niceStep(yMax, 4);
      yMax = Math.ceil(yMax / step) * step;
      const yOf = (v) => py1 - (v / yMax) * (py1 - py0);
      const slot = (px1 - px0) / n;
      const bw = Math.max(3, slot * 0.68);

      ctx.font = '700 12px ' + font;
      ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
      for (let v = 0; v <= yMax + 1e-9; v += step) {
        const y = Math.round(yOf(v)) + 0.5;
        ctx.strokeStyle = alpha(c.ink, v === 0 ? 0.6 : 0.15); ctx.lineWidth = v === 0 ? 2 : 1;
        ctx.setLineDash(v === 0 ? [] : [3, 4]);
        ctx.beginPath(); ctx.moveTo(px0, y); ctx.lineTo(px1, y); ctx.stroke();
        ctx.fillStyle = c.inkSoft; ctx.fillText(String(Math.round(v)), px0 - 8, y);
      }
      ctx.setLineDash([]);
      ctx.textBaseline = 'alphabetic';
      if (this.unit) { ctx.textAlign = 'left'; ctx.font = '800 11px ' + font; ctx.fillStyle = c.inkSoft; ctx.fillText(this.unit, px0 + 4, py0 - 2); }

      for (let i = 0; i < n; i++) {
        const b = this.bars[i];
        const cx = px0 + slot * i + slot / 2;
        const x = cx - bw / 2;
        if (b.value != null) {
          const y = yOf(b.value);
          roundRect(ctx, x, y, bw, py1 - y, Math.min(6, bw / 2));
          ctx.fillStyle = b.color || c.purple; ctx.fill();
          ctx.strokeStyle = c.ink; ctx.lineWidth = 2; ctx.stroke();
          this.hits.push({ x0: cx - slot / 2, x1: cx + slot / 2, y0: py0, y1: py1, priority: 1, tip: b.tip || ('<div class="t">' + esc(b.label) + '</div>' + esc(b.value)) });
        } else {
          ctx.fillStyle = alpha(c.ink, 0.12);
          ctx.fillRect(x, py1 - 3, bw, 3);
          this.hits.push({ x0: cx - slot / 2, x1: cx + slot / 2, y0: py0, y1: py1, priority: 1, tip: b.tip || ('<div class="t">' + esc(b.label) + '</div><span class="muted">no data</span>') });
        }
        if (i % this.labelEvery === 0) {
          ctx.fillStyle = c.inkSoft; ctx.font = '700 12px ' + font; ctx.textAlign = 'center';
          ctx.fillText(b.label, cx, py1 + 20);
        }
      }
      if (this.reference) {
        const y = Math.round(yOf(this.reference)) + 0.5;
        ctx.strokeStyle = c.ink; ctx.lineWidth = 2; ctx.setLineDash([6, 5]);
        ctx.beginPath(); ctx.moveTo(px0, y); ctx.lineTo(px1, y); ctx.stroke();
        ctx.setLineDash([]);
        ctx.font = '800 11px ' + font; ctx.textAlign = 'right'; ctx.fillStyle = c.ink;
        ctx.fillText('median', px1 - 4, y - 4);
      }
    }
  }

  /* --------------------------------------------------------------- throughput */
  /** Round a rate up to a readable axis top: 1, 1.5, 2, 2.5, 3, 4, 5, 6, 8 or 10 × a power of ten. */
  function niceCeil(v) {
    if (!(v > 0)) return 0;
    const mag = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) { if (m * mag >= v - 1e-9) return m * mag; }
    return 10 * mag;
  }

  /** One NIC's live throughput: receive and send as filled lines over a moving window, each with
      its window average drawn across as a dashed rule.
      Points are placed by their timestamp, not by their index, so a second nobody sampled is a
      gap in the line rather than a straight run across it — the service stops sampling while the
      machine sleeps, and a line drawn through that would be a claim about time nobody measured.
      The y axis is bits per second and rescales to whatever is in the window (never below
      MIN_TOP_BPS, so an idle adapter's stray packet is not amplified to full height). */
  class Throughput extends Chart {
    constructor(canvas, opts) {
      super(canvas, opts);
      // [[ts, bps, stepS?], ...] ascending. A point's own step is the seconds it stands for: 3 for
      // a bucket of the 30-minute backlog, left out (so this.stepS, 1) for a live second.
      this.rx = [];                 // receive
      this.tx = [];                 // send
      this.windowS = (opts && opts.windowS) || 30;
      this.stepS = (opts && opts.stepS) || 1;
      this.windowLabel = (opts && opts.windowLabel) || '30 seconds';
      this.now = 0;
      this.avgRx = 0;
      this.avgTx = 0;
      // how a rate is written on the axis and in the tooltip; the card passes its own
      this.fmt = (opts && opts.fmt) || ((v) => Math.round(v) + ' bps');
      this.timeFmt = (opts && opts.timeFmt) || clockS;
    }

    /** {rx, tx, now, windowS, stepS, windowLabel, avgRx, avgTx} — any key may be left out. */
    setSeries(o) {
      const s = o || {};
      if (s.rx) this.rx = s.rx;
      if (s.tx) this.tx = s.tx;
      if (s.now) this.now = s.now;
      if (s.windowS) this.windowS = s.windowS;
      if (s.stepS) this.stepS = s.stepS;
      if (s.windowLabel !== undefined) this.windowLabel = s.windowLabel;
      if (s.avgRx !== undefined) this.avgRx = s.avgRx || 0;
      if (s.avgTx !== undefined) this.avgTx = s.avgTx || 0;
      this.render();
    }

    /** Top of the y axis: the tallest point in the window rounded up, with headroom. */
    top() {
      const t0 = this.now - this.windowS;
      let peak = 0;
      for (const set of [this.rx, this.tx]) {
        for (const p of set) { if (p[0] >= t0 && p[1] > peak) peak = p[1]; }
      }
      return Math.max(Throughput.MIN_TOP_BPS, niceCeil(peak * 1.15));
    }

    /** The points inside the window, cut into runs with no gap wider than two steps. The step is
     *  the earlier point's own: the 30-minute window holds 3 s buckets and then live seconds, and
     *  one tolerance for both would either break every bucket off on its own or draw a live hole
     *  of a few seconds straight across. */
    runs(points) {
      const t0 = this.now - this.windowS;
      const out = [];
      let run = null;
      for (const p of points) {
        if (p[0] < t0 || p[0] > this.now + 1) continue;
        const prev = run && run[run.length - 1];
        if (prev && p[0] - prev[0] > Math.max(2, (prev[2] || this.stepS) * 2 + 0.5)) run = null;
        if (!run) { run = []; out.push(run); }
        run.push(p);
      }
      return out;
    }

    draw(ctx, w, h) {
      const c = this.c, font = this.font;
      const px0 = 2, px1 = w - 2, py0 = 14, py1 = h - 15;
      if (px1 <= px0 || py1 <= py0) return;
      const t0 = this.now - this.windowS, span = Math.max(1, this.windowS);
      const top = this.top();
      const x = (ts) => px0 + ((ts - t0) / span) * (px1 - px0);
      const y = (bps) => py1 - Math.max(0, Math.min(1, bps / top)) * (py1 - py0);

      // plot area and the Task Manager grid: ten columns, five rows, faint
      ctx.fillStyle = c.paper2;
      roundRect(ctx, px0, py0, px1 - px0, py1 - py0, 6);
      ctx.fill();
      ctx.save();
      ctx.beginPath();
      roundRect(ctx, px0, py0, px1 - px0, py1 - py0, 6);
      ctx.clip();
      ctx.strokeStyle = alpha(c.inkSoft, 0.16);
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let i = 1; i < 10; i++) {
        const gx = Math.round(px0 + ((px1 - px0) * i) / 10) + 0.5;
        ctx.moveTo(gx, py0); ctx.lineTo(gx, py1);
      }
      for (let i = 1; i < 5; i++) {
        const gy = Math.round(py0 + ((py1 - py0) * i) / 5) + 0.5;
        ctx.moveTo(px0, gy); ctx.lineTo(px1, gy);
      }
      ctx.stroke();

      // receive under send: receive is usually the taller of the two, so it goes down first
      this._series(ctx, this.rx, c.blue, x, y, py1);
      this._series(ctx, this.tx, c.orange, x, y, py1);

      // the window averages, drawn across the whole plot
      // receive labels at the left, send at the right: the two rules sit on top of each other
      // whenever a machine is downloading, which is most of the time
      this._average(ctx, this.avgRx, c.blue, 'avg ↓', px0, px1, py0, y, font, 'left');
      this._average(ctx, this.avgTx, c.orange, 'avg ↑', px0, px1, py0, y, font, 'right');
      ctx.restore();

      // frame, then the three labels Task Manager puts around the plot
      ctx.strokeStyle = alpha(c.inkSoft, 0.35);
      ctx.lineWidth = 1;
      roundRect(ctx, px0 + 0.5, py0 + 0.5, px1 - px0 - 1, py1 - py0 - 1, 6);
      ctx.stroke();
      ctx.font = '700 10px ' + font;
      ctx.fillStyle = c.inkSoft;
      ctx.textAlign = 'right';
      ctx.textBaseline = 'alphabetic';
      ctx.fillText(this.fmt(top), px1, py0 - 4);
      ctx.fillText('0', px1, py1 + 11);
      ctx.textAlign = 'left';
      ctx.fillText(this.windowLabel, px0, py1 + 11);

      this._hits(px0, px1, py0, py1, x);
    }

    _series(ctx, points, color, x, y, py1) {
      for (const run of this.runs(points)) {
        if (!run.length) continue;
        ctx.beginPath();
        ctx.moveTo(x(run[0][0]), y(run[0][1]));
        for (let i = 1; i < run.length; i++) ctx.lineTo(x(run[i][0]), y(run[i][1]));
        // the fill closes down to the baseline; the stroke is re-run so it is not filled over
        ctx.lineTo(x(run[run.length - 1][0]), py1);
        ctx.lineTo(x(run[0][0]), py1);
        ctx.closePath();
        ctx.fillStyle = alpha(color, 0.3);
        ctx.fill();
        ctx.beginPath();
        ctx.moveTo(x(run[0][0]), y(run[0][1]));
        for (let i = 1; i < run.length; i++) ctx.lineTo(x(run[i][0]), y(run[i][1]));
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.6;
        ctx.lineJoin = 'round';
        ctx.stroke();
      }
    }

    _average(ctx, value, color, label, px0, px1, py0, y, font, side) {
      if (!(value > 0)) return;          // nothing moved: a rule along the floor says nothing
      const gy = Math.round(y(value)) + 0.5;
      ctx.save();
      ctx.setLineDash([5, 4]);
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.moveTo(px0 + 1, gy);
      ctx.lineTo(px1 - 1, gy);
      ctx.stroke();
      ctx.restore();
      const text = label + ' ' + this.fmt(value);
      ctx.font = '800 10px ' + font;
      ctx.textAlign = 'left';
      ctx.textBaseline = 'alphabetic';
      const tw = ctx.measureText(text).width;
      // above its own rule, or below it when the rule is near the top of the plot
      const ty = gy - 3 < py0 + 10 ? gy + 11 : gy - 3;
      const tx = side === 'right' ? px1 - tw - 5 : px0 + 5;
      ctx.fillStyle = alpha(this.c.paper2, 0.85);
      ctx.fillRect(tx - 2, ty - 9, tw + 4, 11);
      ctx.fillStyle = color;
      ctx.fillText(text, tx, ty);
    }

    /** One hit column per step, so hovering anywhere reads off both series at that second. */
    _hits(px0, px1, py0, py1, x) {
      const byTs = new Map();
      const t0 = this.now - this.windowS;
      for (const p of this.rx) { if (p[0] >= t0) byTs.set(p[0], { rx: p[1], tx: 0, step: p[2] }); }
      for (const p of this.tx) {
        if (p[0] < t0) continue;
        const row = byTs.get(p[0]) || { rx: 0, tx: 0, step: p[2] };
        row.tx = p[1];
        byTs.set(p[0], row);
      }
      const perS = (px1 - px0) / (2 * Math.max(1, this.windowS));
      for (const [ts, row] of byTs) {
        const cx = x(ts);
        if (cx < px0 || cx > px1) continue;
        const half = Math.max(2, perS * (row.step || this.stepS));
        this.hits.push({
          x0: cx - half, x1: cx + half, y0: py0, y1: py1, priority: 1,
          tip: '<b>' + esc(this.timeFmt(ts)) + '</b><br>↓ ' + esc(this.fmt(row.rx)) + '<br>↑ ' + esc(this.fmt(row.tx)),
        });
      }
    }
  }
  //: An idle adapter's one stray packet must not fill the plot: 100 kbps is the shortest axis.
  Throughput.MIN_TOP_BPS = 100000;

  TNT.charts = {
    Chart, Sparkline, Timeline, LineChart, BarChart, Throughput,
    colors, roundRect, alpha, niceStep, niceCeil,
    rerenderAll() { for (const ch of Array.from(registry)) ch.render(); },
    count() { return registry.size; },
  };
})();
