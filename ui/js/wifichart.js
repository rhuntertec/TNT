/* TNT — wifichart.js
   Canvas charts for the WiFi page, built on the charts.js base class (hi-DPI, ResizeObserver,
   theme colours read from the CSS tokens, tooltips, destroy on unmount):
   * SignalChart   — one line per access point over time on a dBm axis (-100 … -20); the
                     selected network's lines are drawn thick with an ink outline, on top.
   * SpectrumChart — one band (2.4 / 5 / 6 GHz): every access point is a translucent trapezoid
                     over the spectrum it occupies, its top edge at the signal level, labelled
                     with its network name; the selected network gets a thick ink outline.
   Everything that is plain maths (channel -> frequency, frequency -> x, the trapezoid, channel
   and time ticks, signal colour thresholds, the network colour palette) is exported on
   TNT.wifichart for the node tests. Loaded after charts.js and before app.js. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;

  /* ------------------------------------------------------------- constants */
  const DBM_TOP = -20;         // top of every dBm axis
  const DBM_BOTTOM = -100;     // bottom (the noise floor the shapes stand on)
  const SLOPE = 0.1;           // each sloped side of a spectrum shape covers 10 % of its span
  const GAP_S = 150;           // a line breaks where two readings are further apart than this

  /** The three bands: the drawn frequency range (MHz), the channel ticks and the U-NII blocks. */
  const BANDS = {
    '2.4': { key: '2.4', label: '2.4 GHz', fMin: 2400, fMax: 2495, sub: [] },
    '5': {
      key: '5', label: '5 GHz', fMin: 5150, fMax: 5895,
      sub: [{ name: 'U-NII-1', lo: 5150, hi: 5250 }, { name: 'U-NII-2A', lo: 5250, hi: 5350 },
        { name: 'U-NII-2C', lo: 5470, hi: 5725 }, { name: 'U-NII-3', lo: 5725, hi: 5850 }, { name: 'U-NII-4', lo: 5850, hi: 5895 }],
    },
    '6': {
      key: '6', label: '6 GHz', fMin: 5925, fMax: 7125,
      sub: [{ name: 'U-NII-5', lo: 5925, hi: 6425 }, { name: 'U-NII-6', lo: 6425, hi: 6525 },
        { name: 'U-NII-7', lo: 6525, hi: 6875 }, { name: 'U-NII-8', lo: 6875, hi: 7125 }],
    },
  };
  const BAND_KEYS = ['2.4', '5', '6'];

  /* ------------------------------------------------------------ pure maths */
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

  /** Centre frequency (MHz) of a channel number in a band, or null for a channel that band has not. */
  function channelFreq(band, ch) {
    ch = Number(ch);
    if (!isFinite(ch) || ch !== Math.round(ch)) return null;
    if (band === '2.4') {
      if (ch === 14) return 2484;
      return ch >= 1 && ch <= 13 ? 2407 + 5 * ch : null;
    }
    if (band === '5') return ch >= 32 && ch <= 177 ? 5000 + 5 * ch : null;
    if (band === '6') {
      if (ch === 2) return 5935;
      return ch >= 1 && ch <= 233 ? 5950 + 5 * ch : null;
    }
    return null;
  }

  /** The occupied spectrum of an access point: its `spans` when present, else [centre ± width/2]. */
  function apSpans(ap) {
    if (!ap) return [];
    if (Array.isArray(ap.spans) && ap.spans.length) {
      return ap.spans.filter((s) => Array.isArray(s) && s.length === 2 && isFinite(s[0]) && isFinite(s[1]) && s[1] > s[0])
        .map((s) => [Number(s[0]), Number(s[1])]);
    }
    const width = Number(ap.width_mhz) || 20;
    const centre = channelFreq(ap.band, ap.center_channel) || channelFreq(ap.band, ap.channel) || Number(ap.freq_mhz);
    return isFinite(centre) && centre > 0 ? [[centre - width / 2, centre + width / 2]] : [];
  }

  /** x (px) of a frequency on a band axis drawn from x0 to x1. */
  function freqToX(f, band, x0, x1) {
    const b = BANDS[band];
    if (!b) return x0;
    return x0 + ((f - b.fMin) / (b.fMax - b.fMin)) * (x1 - x0);
  }

  /** y (px) of a signal level on a dBm axis: DBM_TOP at y0, DBM_BOTTOM at y1 (clamped to the axis). */
  function dbmToY(dbm, y0, y1) {
    const v = clamp(Number(dbm), DBM_BOTTOM, DBM_TOP);
    return y0 + ((DBM_TOP - v) / (DBM_TOP - DBM_BOTTOM)) * (y1 - y0);
  }

  /** One spectrum shape in (MHz, dBm) space: the base covers the span on the floor, each side slopes
   *  in by SLOPE of the width, the top edge sits at the signal level (clamped to the axis). */
  function trapezoid(span, rssi) {
    const lo = Number(span[0]), hi = Number(span[1]);
    const s = (hi - lo) * SLOPE;
    const top = clamp(Number(rssi), DBM_BOTTOM, DBM_TOP);
    return [[lo, DBM_BOTTOM], [lo + s, top], [hi - s, top], [hi, DBM_BOTTOM]];
  }

  /** Every shape of an access point (two for an 80+80 MHz access point). */
  function apShapes(ap) {
    return apSpans(ap).map((span) => trapezoid(span, ap.rssi));
  }

  /** Channel ticks under a band axis: [{ch, f, major}]; majors carry a label.
   *  2.4 GHz: channels 1-14. 5 GHz: every 20 MHz channel of U-NII-1/2A (36-64), 2C (100-144)
   *  and 3/4 (149-177), labelled every 8 channels. 6 GHz: every 20 MHz channel, labelled
   *  every 16 (1, 17, 33 … 225). */
  function channelTicks(band) {
    const out = [];
    const add = (ch, major) => { const f = channelFreq(band, ch); if (f != null) out.push({ ch, f, major }); };
    if (band === '2.4') { for (let ch = 1; ch <= 14; ch++) add(ch, true); }
    else if (band === '5') {
      for (let ch = 36; ch <= 64; ch += 4) add(ch, (ch - 36) % 8 === 0);
      for (let ch = 100; ch <= 144; ch += 4) add(ch, (ch - 100) % 8 === 0);
      for (let ch = 149; ch <= 177; ch += 4) add(ch, (ch - 149) % 8 === 0);
    } else if (band === '6') { for (let ch = 1; ch <= 233; ch += 4) add(ch, (ch - 1) % 16 === 0); }
    return out;
  }

  /** The channels to label under a band axis, from ticks carrying their x (px). 2.4 GHz uses one fixed
   *  step for the whole axis (every channel, every other one, or every fourth: 1 5 9 13), never a
   *  mix, plus channel 14 when it has room; the other bands label their majors at least 22 px apart. */
  function labelChannels(band, ticks) {
    const out = [];
    if (!ticks || !ticks.length) return out;
    let last = -Infinity;
    if (band === '2.4') {
      const px = ticks.length > 1 ? Math.abs(ticks[1].x - ticks[0].x) : 100;
      const step = px >= 24 ? 1 : px >= 12 ? 2 : 4;
      for (const tk of ticks) {
        const onStep = tk.ch !== 14 && (tk.ch - 1) % step === 0;
        if (onStep || (tk.ch === 14 && tk.x - last >= 22)) { out.push(tk.ch); last = tk.x; }
      }
      return out;
    }
    for (const tk of ticks) {
      if (tk.major && tk.x - last >= 22) { out.push(tk.ch); last = tk.x; }
    }
    return out;
  }

  /** Fill opacity of the shapes on a band with `count` access points: 30 % up to six, less beyond (at
   *  least 10 %), so a pile of overlapping shapes still shows the colours instead of a solid block. */
  function fillAlpha(count) {
    return clamp(0.3 * 6 / Math.max(6, Number(count) || 0), 0.1, 0.3);
  }

  /** dBm gridlines for a plot of the given height: every 10 dB, or every 20 dB when that is crowded. */
  function dbmTicks(plotH) {
    const step = plotH / ((DBM_TOP - DBM_BOTTOM) / 10) >= 22 ? 10 : 20;
    const out = [];
    for (let v = DBM_TOP; v >= DBM_BOTTOM; v -= step) out.push(v);
    return out;
  }

  /** Signal colour thresholds: green >= -60 dBm, yellow -60 … -75 dBm, red below -75 dBm. */
  function signalClass(rssi) {
    if (rssi == null || !isFinite(rssi)) return 'grey';
    if (rssi >= -60) return 'green';
    if (rssi >= -75) return 'yellow';
    return 'red';
  }

  /** 0-4 signal bars: 4 >= -50, 3 >= -60, 2 >= -75, 1 >= -85 dBm (so green = 3-4, yellow = 2, red = 0-1). */
  function signalBars(rssi) {
    if (rssi == null || !isFinite(rssi)) return 0;
    if (rssi >= -50) return 4;
    if (rssi >= -60) return 3;
    if (rssi >= -75) return 2;
    if (rssi >= -85) return 1;
    return 0;
  }

  const TIME_STEPS = [5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200];
  const p2 = (n) => (n < 10 ? '0' : '') + n;

  /** Time axis ticks for [t0, t1] (epoch s) over `px` pixels: the smallest "nice" step that keeps
   *  labels at least minPx apart, aligned to the local clock. [{t, label}]; HH:MM:SS below a minute. */
  function timeTicks(t0, t1, px, tzOffsetMin, minPx) {
    const span = t1 - t0;
    if (!(span > 0) || !(px > 0)) return [];
    const gap = minPx || 70;
    let step = TIME_STEPS[TIME_STEPS.length - 1];
    for (const s of TIME_STEPS) { if ((s / span) * px >= gap) { step = s; break; } }
    const tz = (tzOffsetMin == null ? new Date(t0 * 1000).getTimezoneOffset() : tzOffsetMin) * 60;   // minutes west of UTC
    const out = [];
    for (let t = Math.ceil((t0 - tz) / step) * step + tz; t <= t1 + 1e-6; t += step) {
      const local = ((Math.round(t - tz) % 86400) + 86400) % 86400;
      const hh = Math.floor(local / 3600), mm = Math.floor((local % 3600) / 60), ss = local % 60;
      out.push({ t, label: p2(hh) + ':' + p2(mm) + (step < 60 ? ':' + p2(ss) : '') });
    }
    return out;
  }

  /** Readings further apart than this (seconds) start a new line on a chart spanning `span` seconds:
   *  GAP_S, widened on long spans, where the background reads made while the WiFi page is closed
   *  (about one a minute, and only when Windows has a fresh beacon) are further apart. */
  function gapFor(span) {
    return Math.max(GAP_S, (Number(span) || 0) / 60);
  }

  /* --------------------------------------------------------------- palette */
  /** One colour per network, derived from TNT's tokens: 12 hues (the seven accents and five 50/50
   *  mixes of neighbours), then the same 12 mixed 35 % towards --ink (darker in the light theme,
   *  lighter in the dark one). Each entry is [token, other token, % of the first]. The DOM uses the
   *  CSS form (color-mix, so it follows the theme by itself); the canvas mixes the token values. */
  const HUES = [['blue'], ['orange'], ['green'], ['purple'], ['red'], ['teal'], ['yellow'],
    ['red', 'purple', 50], ['green', 'yellow', 50], ['blue', 'purple', 50], ['blue', 'teal', 50], ['orange', 'yellow', 50]];
  const PALETTE = HUES.concat(HUES.map((hue) => ['mix', hue, 65]));
  const PALETTE_SIZE = PALETTE.length;

  function hueCss(hue) {
    return hue.length === 1 ? 'var(--' + hue[0] + ')' : 'color-mix(in srgb, var(--' + hue[0] + ') ' + hue[2] + '%, var(--' + hue[1] + '))';
  }
  /** CSS colour of palette entry i (any integer; wraps). */
  function paletteCss(i) {
    const e = PALETTE[((Number(i) || 0) % PALETTE_SIZE + PALETTE_SIZE) % PALETTE_SIZE];
    if (e[0] === 'mix') return 'color-mix(in srgb, ' + hueCss(e[1]) + ' ' + e[2] + '%, var(--ink))';
    return hueCss(e);
  }

  function parseHex(hex) {
    const m = /^#?([0-9a-f]{6})$/i.exec(String(hex || '').trim());
    if (!m) return null;
    const n = parseInt(m[1], 16);
    return [n >> 16, (n >> 8) & 255, n & 255];
  }
  /** "#RRGGBB" of `pct` % of a mixed with the rest b, per channel in sRGB (what color-mix(in srgb) does). */
  function mixHex(a, b, pct) {
    const x = parseHex(a), y = parseHex(b);
    if (!x || !y) return a;
    const w = clamp(Number(pct), 0, 100) / 100;
    return '#' + x.map((v, k) => Math.round(v * w + y[k] * (1 - w)).toString(16).padStart(2, '0')).join('').toUpperCase();
  }
  /** Hex colour of palette entry i for a token set ({blue, orange, …, ink} as "#RRGGBB"). */
  function paletteHex(i, tokens) {
    const e = PALETTE[((Number(i) || 0) % PALETTE_SIZE + PALETTE_SIZE) % PALETTE_SIZE];
    const hue = (h) => (h.length === 1 ? tokens[h[0]] : mixHex(tokens[h[0]], tokens[h[1]], h[2]));
    if (e[0] === 'mix') return mixHex(hue(e[1]), tokens.ink, e[2]);
    return hue(e);
  }

  function escHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  }
  /** "−52 dBm" with a real minus sign. */
  function dbmText(v) {
    if (v == null || !isFinite(v)) return '—';
    const n = Math.round(v);
    return (n < 0 ? '−' + Math.abs(n) : String(n)) + ' dBm';
  }

  /* ---------------------------------------------------------------- charts */
  // The base class lives in charts.js; the node tests stub it, so nothing below runs at load time
  // except the class definitions.
  const Base = (TNT.charts && TNT.charts.Chart) || class {};
  const alpha = (hex, a) => (TNT.charts && TNT.charts.alpha ? TNT.charts.alpha(hex, a) : hex);

  /** Shared bits of both WiFi charts: key-based hover (shapes are rebuilt on every render), a click
   *  that picks a network, and the theme palette. */
  class WifiChart extends Base {
    constructor(canvas, opts) {
      super(canvas, opts);
      this._hoverKey = null;
      this._pal = null; this._palTheme = null;
      this._onClick = (e) => {
        const rect = this.canvas.getBoundingClientRect();
        const hit = this.hitTest(e.clientX - rect.left, e.clientY - rect.top);
        if (hit && this.opts.onPick) this.opts.onPick(hit.net);
      };
      canvas.addEventListener('click', this._onClick);
    }
    /** Hex colour for palette index i in the current theme (cached per theme). */
    color(i) {
      const theme = document.documentElement.getAttribute('data-theme') || 'light';
      if (!this._pal || this._palTheme !== theme) {
        const t = this.c || {};     // charts.colors(): every accent token and --ink, as hex
        this._pal = PALETTE.map((_, k) => paletteHex(k, t));
        this._palTheme = theme;
      }
      return this._pal[((i % PALETTE_SIZE) + PALETTE_SIZE) % PALETTE_SIZE] || this.c.ink;
    }
    _mouse(e) {
      const rect = this.canvas.getBoundingClientRect();
      const x = e.clientX - rect.left, y = e.clientY - rect.top;
      const hit = this.hitTest(x, y);
      const key = hit ? hit.key : null;
      this.canvas.style.cursor = hit && this.opts.onPick ? 'pointer' : '';
      // redraws go through render() (one per animation frame): a mouse move is never a synchronous redraw
      if (key !== this._hoverKey) {
        this._hoverKey = key;
        this.render();
        if (hit) this.showTip(hit.tip, x, y); else this.hideTip();
      } else if (hit) {
        if (hit.follow) { this.render(); this.showTip(hit.tip, x, y); }
        this._positionTip(x, y);
      }
    }
    _leave() { this._hoverKey = null; this.canvas.style.cursor = ''; this.hideTip(); this.render(); }
    destroy() {
      this.canvas.removeEventListener('click', this._onClick);
      super.destroy();
    }
  }

  /* ----------------------------------------------------------- SignalChart */
  /** Signal strength over time. setData({series: [{key, net, name, bssid, color, points: [[ts, dBm]],
   *  selected, tip(ts, dBm)}], t0, t1, dim, empty}). */
  class SignalChart extends WifiChart {
    constructor(canvas, opts) {
      super(canvas, opts);
      this.series = []; this.t0 = 0; this.t1 = 0; this.dim = false; this.empty = '';
      this._cols = new Map();    // pixel column -> the drawn readings in it (hit testing looks at nearby columns only)
      this._colsSeries = null; this._colsGeom = '';
    }
    setData(d) {
      this.series = d.series || [];
      this.t0 = d.t0; this.t1 = d.t1;
      this.dim = !!d.dim;
      this.empty = d.empty || '';
      this.render();
    }
    draw(ctx, w, h) {
      const c = this.c, font = this.font;
      const padL = 48, padR = 14, padT = 12, padB = 26;
      const px0 = padL, px1 = w - padR, py0 = padT, py1 = h - padB;
      const t0 = this.t0, t1 = Math.max(this.t1, this.t0 + 1);
      const xOf = (t) => px0 + ((t - t0) / (t1 - t0)) * (px1 - px0);
      const yOf = (v) => dbmToY(v, py0, py1);

      // signal zones as a thin strip left of the plot: green / yellow / red
      const zone = (hi, lo, col) => { ctx.fillStyle = col; ctx.fillRect(px0 - 7, yOf(hi), 5, yOf(lo) - yOf(hi)); };
      zone(DBM_TOP, -60, c.green); zone(-60, -75, c.yellow); zone(-75, DBM_BOTTOM, c.red);
      // dBm gridlines
      ctx.font = '700 12px ' + font;
      ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
      for (const v of dbmTicks(py1 - py0)) {
        const y = Math.round(yOf(v)) + 0.5;
        ctx.strokeStyle = alpha(c.ink, v === DBM_BOTTOM ? 0.6 : 0.15);
        ctx.lineWidth = v === DBM_BOTTOM ? 2 : 1;
        ctx.setLineDash(v === DBM_BOTTOM ? [] : [3, 4]);
        ctx.beginPath(); ctx.moveTo(px0, y); ctx.lineTo(px1, y); ctx.stroke();
        ctx.fillStyle = c.inkSoft;
        ctx.fillText(String(v), px0 - 11, y);
      }
      ctx.setLineDash([]);
      ctx.textBaseline = 'alphabetic';
      ctx.textAlign = 'left'; ctx.font = '800 11px ' + font; ctx.fillStyle = c.inkSoft;
      ctx.fillText('dBm', px0 + 4, py0 + 10);
      // time axis
      ctx.font = '700 12px ' + font; ctx.textAlign = 'center';
      let lastX = -Infinity;
      for (const tk of timeTicks(t0, t1, px1 - px0)) {
        const x = Math.round(xOf(tk.t)) + 0.5;
        if (x < px0 - 1 || x > px1 + 1) continue;
        ctx.strokeStyle = alpha(c.ink, 0.35); ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(x, py1); ctx.lineTo(x, py1 + 5); ctx.stroke();
        if (x - lastX >= 56 && x > px0 + 14 && x < px1 - 14) { ctx.fillStyle = c.inkSoft; ctx.fillText(tk.label, x, py1 + 19); lastX = x; }
      }

      // lines: everything else thin (faded while a network is selected), the selected network
      // thick with an ink outline on top; the hovered line is lifted too
      const order = this.series.slice().sort((a, b) => (a.selected - b.selected) || ((a.key === this._hoverKey) - (b.key === this._hoverKey)));
      let drawn = 0;
      ctx.save();
      ctx.beginPath(); ctx.rect(px0, py0 - 4, px1 - px0, py1 - py0 + 8); ctx.clip();
      ctx.lineJoin = 'round'; ctx.lineCap = 'round';
      // a hover redraw reuses every series' screen points and the hit-test columns: only new data
      // (setData) or a new size rebuilds them
      const geom = [t0, t1, px0, px1, py0, py1].join('|');
      const rebuildHits = this._colsSeries !== this.series || this._colsGeom !== geom;
      if (rebuildHits) { this._cols = new Map(); this._colsSeries = this.series; this._colsGeom = geom; }
      for (const s of order) {
        let segs;
        if (s._segCache && s._segCache.geom === geom && s._segCache.points === s.points) segs = s._segCache.segs;
        else { segs = this._segments(s, xOf, yOf, t0, t1); s._segCache = { geom, points: s.points, segs }; }
        if (!segs.length) continue;
        drawn++;
        const col = this.color(s.color);
        const hover = s.key === this._hoverKey;
        const strong = s.selected || hover;
        const path = () => {
          ctx.beginPath();
          for (const seg of segs) {
            if (!seg.length) continue;
            ctx.moveTo(seg[0][0], seg[0][1]);
            if (seg.length === 1) ctx.lineTo(seg[0][0] + 0.01, seg[0][1]);
            for (let i = 1; i < seg.length; i++) ctx.lineTo(seg[i][0], seg[i][1]);
          }
        };
        if (strong) {
          path(); ctx.strokeStyle = c.ink; ctx.lineWidth = s.selected ? 6 : 5; ctx.globalAlpha = 1; ctx.stroke();
          path(); ctx.strokeStyle = col; ctx.lineWidth = s.selected ? 3 : 2.5; ctx.stroke();
        } else {
          path(); ctx.strokeStyle = mixHex(col, c.ink, 80); ctx.lineWidth = 2; ctx.globalAlpha = this.dim ? 0.28 : 0.85; ctx.stroke();
          ctx.globalAlpha = 1;
        }
        // a reading with no neighbour close enough for a line (sparse background reads) is a dot, not a speck
        for (const seg of segs) {
          if (seg.length !== 1) continue;
          ctx.beginPath(); ctx.arc(seg[0][0], seg[0][1], strong ? 4 : 3, 0, Math.PI * 2);
          if (strong) { ctx.fillStyle = col; ctx.fill(); ctx.strokeStyle = c.ink; ctx.lineWidth = 1.5; ctx.stroke(); }
          else { ctx.fillStyle = mixHex(col, c.ink, 80); ctx.globalAlpha = this.dim ? 0.28 : 0.85; ctx.fill(); ctx.globalAlpha = 1; }
        }
        if (!rebuildHits) continue;
        for (const seg of segs) {
          for (const p of seg) {
            const pt = { x: p[0], y: p[1], ts: p[2], v: p[3], s, strong: s.selected };
            const cx = Math.round(p[0]);
            const col = this._cols.get(cx);
            if (col) col.push(pt); else this._cols.set(cx, [pt]);
          }
        }
      }
      ctx.restore();
      // the hovered reading
      const hp = this._hoverPoint;
      if (hp && hp.s.key === this._hoverKey) {
        ctx.beginPath(); ctx.arc(hp.x, hp.y, 5, 0, Math.PI * 2);
        ctx.fillStyle = this.color(hp.s.color); ctx.fill();
        ctx.strokeStyle = c.ink; ctx.lineWidth = 2; ctx.stroke();
      }
      if (!drawn) {
        ctx.fillStyle = c.inkSoft; ctx.font = '700 14px ' + font; ctx.textAlign = 'center';
        ctx.fillText(this.empty || 'No readings in this range yet', (px0 + px1) / 2, (py0 + py1) / 2);
      }
    }
    /** Screen points of one series inside [t0, t1], split where readings are further apart than
     *  gapFor(t1 - t0) and thinned to at most a first / min / max / last per pixel column. */
    _segments(s, xOf, yOf, t0, t1) {
      const pts = s.points || [];
      const gap = gapFor(t1 - t0);
      const segs = [];
      let cur = null, prevTs = null, col = null;
      for (let i = 0; i < pts.length; i++) {
        const ts = pts[i][0], v = pts[i][1];
        if (v == null || ts < t0 - gap || ts > t1 + 1) continue;
        if (!cur || (prevTs != null && ts - prevTs > gap)) {
          // the pixel column still open belongs to the line the gap ends: without it a lone reading before
          // a gap left an empty line, and drawing that threw and blanked the whole chart
          if (col && cur) flush(cur, col);
          cur = []; segs.push(cur); col = null;
        }
        prevTs = ts;
        const x = xOf(ts), y = yOf(v), cx = Math.round(x);
        const p = [x, y, ts, v];             // one array per reading: flush() skips a reading it already took by identity
        if (col && col.cx === cx) {          // same pixel column: keep its extremes and its last value
          if (y < col.min[1]) col.min = p;
          if (y > col.max[1]) col.max = p;
          col.last = p;
          continue;
        }
        if (col) flush(cur, col);
        col = { cx, first: p, min: p, max: p, last: p };
      }
      if (col && cur) flush(cur, col);
      return segs;
      function flush(seg, cc) {
        const list = [cc.first];
        const mid = cc.min[2] <= cc.max[2] ? [cc.min, cc.max] : [cc.max, cc.min];
        for (const p of mid.concat([cc.last])) if (p !== list[list.length - 1]) list.push(p);
        for (const p of list) seg.push(p);
      }
    }
    hitTest(x, y) {
      // only readings within 14 px can win, so only the pixel columns within 14 px are searched
      let best = null, bestD = 14 * 14;
      const cx = Math.round(x);
      for (let c = cx - 15; c <= cx + 15; c++) {
        const col = this._cols.get(c);
        if (!col) continue;
        for (const p of col) {
          const d = (p.x - x) * (p.x - x) + (p.y - y) * (p.y - y) - (p.strong ? 30 : 0);
          if (d < bestD) { bestD = d; best = p; }
        }
      }
      this._hoverPoint = best;
      if (!best) return null;
      const s = best.s;
      const tip = s.tip ? s.tip(best.ts, best.v) : '<div class="t">' + escHtml(s.name) + '</div>' + dbmText(best.v);
      return { key: s.key, net: s.net, tip, follow: true };
    }
  }

  /* --------------------------------------------------------- SpectrumChart */
  /** One band. setData({aps: [{key, net, name, color, rssi, spans, stale, selected, connected, tip}],
   *  dim, empty}). opts.band: '2.4' | '5' | '6'. */
  class SpectrumChart extends WifiChart {
    constructor(canvas, opts) {
      super(canvas, opts);
      this.band = (opts && opts.band) || '5';
      this.aps = []; this.dim = false; this.empty = '';
      this._shapes = [];
    }
    setData(d) {
      this.aps = d.aps || [];
      this.dim = !!d.dim;
      this.empty = d.empty || '';
      this.render();
    }
    draw(ctx, w, h) {
      const c = this.c, font = this.font, band = BANDS[this.band];
      const padL = 48, padR = 12, padT = 22, padB = 26;
      const px0 = padL, px1 = w - padR, py0 = padT, py1 = h - padB;
      const xOf = (f) => freqToX(f, this.band, px0, px1);
      const yOf = (v) => dbmToY(v, py0, py1);

      // U-NII blocks: alternating faint shading with a small name at the top
      ctx.font = '800 10px ' + font; ctx.textAlign = 'left'; ctx.textBaseline = 'alphabetic';
      band.sub.forEach((sb, i) => {
        const x0 = xOf(sb.lo), x1 = xOf(sb.hi);
        if (i % 2 === 0) { ctx.fillStyle = alpha(c.ink, 0.04); ctx.fillRect(x0, py0, x1 - x0, py1 - py0); }
        ctx.strokeStyle = alpha(c.ink, 0.18); ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(Math.round(x0) + 0.5, py0 - 8); ctx.lineTo(Math.round(x0) + 0.5, py1); ctx.stroke();
        const label = sb.name;
        if (ctx.measureText(label).width + 8 <= x1 - x0) { ctx.fillStyle = c.inkSoft; ctx.fillText(label, x0 + 4, py0 - 7); }
      });
      // dBm gridlines
      ctx.font = '700 12px ' + font; ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
      for (const v of dbmTicks(py1 - py0)) {
        if (v === DBM_BOTTOM) continue;
        const y = Math.round(yOf(v)) + 0.5;
        ctx.strokeStyle = alpha(c.ink, 0.15); ctx.lineWidth = 1; ctx.setLineDash([3, 4]);
        ctx.beginPath(); ctx.moveTo(px0, y); ctx.lineTo(px1, y); ctx.stroke();
        ctx.fillStyle = c.inkSoft; ctx.fillText(String(v), px0 - 8, y);
      }
      ctx.setLineDash([]);
      ctx.fillStyle = c.inkSoft; ctx.fillText(String(DBM_BOTTOM), px0 - 8, py1 - 2);
      // channel ticks and the floor
      ctx.textBaseline = 'alphabetic'; ctx.textAlign = 'center'; ctx.font = '700 12px ' + font;
      const ticks = channelTicks(this.band).map((tk) => Object.assign({ x: Math.round(xOf(tk.f)) + 0.5 }, tk));
      const channelLabels = new Set(labelChannels(this.band, ticks));
      for (const tk of ticks) {
        const x = tk.x;
        ctx.strokeStyle = alpha(c.ink, tk.major ? 0.6 : 0.3); ctx.lineWidth = tk.major ? 2 : 1;
        ctx.beginPath(); ctx.moveTo(x, py1); ctx.lineTo(x, py1 + (tk.major ? 6 : 4)); ctx.stroke();
        if (channelLabels.has(tk.ch)) { ctx.fillStyle = c.inkSoft; ctx.fillText(String(tk.ch), x, py1 + 19); }
      }
      ctx.strokeStyle = c.ink; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.moveTo(px0, py1 + 0.5); ctx.lineTo(px1, py1 + 0.5); ctx.stroke();

      // shapes: stale ones first, then the rest from the strongest down (so a lower shape's
      // outline is never buried under a taller one's fill), the selected network last
      const rank = (a) => (a.selected ? 2 : a.stale ? 0 : 1);
      const list = this.aps.slice().sort((a, b) => (rank(a) - rank(b)) || ((b.rssi || -200) - (a.rssi || -200)));
      const fillA = fillAlpha(list.length);         // a crowded band gets lighter fills
      this._shapes = [];
      ctx.save();
      ctx.beginPath(); ctx.rect(px0, py0 - 2, px1 - px0, py1 - py0 + 3); ctx.clip();
      ctx.lineJoin = 'round';
      for (const a of list) {
        const col = this.color(a.color);
        const hover = a.key === this._hoverKey;
        for (const shape of apShapes(a)) {
          const pts = shape.map((p) => [xOf(p[0]), yOf(p[1])]);
          const path = () => { ctx.beginPath(); ctx.moveTo(pts[0][0], pts[0][1]); for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i][0], pts[i][1]); ctx.closePath(); };
          path();
          if (a.stale && !a.selected) {
            ctx.fillStyle = alpha(c.inkSoft, 0.1); ctx.fill();
            ctx.setLineDash([5, 4]); ctx.strokeStyle = alpha(c.inkSoft, hover ? 0.95 : 0.6); ctx.lineWidth = hover ? 2.5 : 1.5; ctx.stroke();
            ctx.setLineDash([]);
          } else if (a.selected && a.stale) {
            // selected but out of range: still bold, dashed and paler, so it does not pass for a live reading
            ctx.fillStyle = alpha(col, 0.2); ctx.fill();
            ctx.setLineDash([7, 5]); ctx.strokeStyle = c.ink; ctx.lineWidth = 4; ctx.stroke();
            ctx.setLineDash([]);
          } else if (a.selected) {
            ctx.fillStyle = alpha(col, 0.5); ctx.fill();
            ctx.strokeStyle = c.ink; ctx.lineWidth = 4; ctx.stroke();
          } else {
            ctx.fillStyle = alpha(col, this.dim ? Math.min(0.12, fillA) : fillA); ctx.fill();
            ctx.strokeStyle = mixHex(col, c.ink, 75); ctx.globalAlpha = this.dim && !hover ? 0.45 : 1;
            ctx.lineWidth = hover ? 3 : 2; ctx.stroke();
            ctx.globalAlpha = 1;
          }
          this._shapes.push({ pts, a });
        }
      }
      ctx.restore();

      // labels: the selected network first, then the strongest. Each label tries a few spots along
      // its shape (above the top edge, centred, then its left and right ends, then just inside the
      // top edge) and is left out when every spot would overlap a label already placed
      const placed = [];
      const labelled = list.slice().sort((a, b) => (b.selected - a.selected) || (a.stale - b.stale) || ((b.rssi || -200) - (a.rssi || -200)));
      ctx.font = '800 12px ' + font; ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic';
      for (const a of labelled) {
        const text = a.name || '';
        if (!text) continue;
        const tw = ctx.measureText(text).width;
        for (const span of apSpans(a)) {
          const x0 = xOf(span[0]), x1 = xOf(span[1]);
          if (!a.selected && (x1 - x0) * 3 + 24 < tw) continue;            // far too narrow to name
          const inset = (x1 - x0) * SLOPE;
          const top = yOf(a.rssi);
          const above = top - 6 - 12 < py0 ? top + 16 : top - 6;
          const xs = [(x0 + x1) / 2];
          if (x1 - x0 > tw * 1.6) xs.push(x0 + inset + tw / 2 + 4, x1 - inset - tw / 2 - 4);
          const spots = [];
          for (const x of xs) spots.push([x, above]);
          if (top + 16 < py1 - 4) for (const x of xs) spots.push([x, top + 16]);
          for (const [sx, ly] of spots) {
            const cx = clamp(sx, px0 + tw / 2 + 2, px1 - tw / 2 - 2);
            const box = { x0: cx - tw / 2 - 3, x1: cx + tw / 2 + 3, y0: ly - 12, y1: ly + 3 };
            if (placed.some((p) => box.x0 < p.x1 && box.x1 > p.x0 && box.y0 < p.y1 && box.y1 > p.y0)) continue;
            placed.push(box);
            ctx.lineWidth = 3.5; ctx.strokeStyle = c.paper; ctx.lineJoin = 'round';
            ctx.strokeText(text, cx, ly);
            // out of range, or not the selected network while one is: soft ink, so the selection's names stand out
            ctx.fillStyle = a.stale || (this.dim && !a.selected) ? c.inkSoft : c.ink;
            ctx.fillText(text, cx, ly);
            break;
          }
        }
      }

      if (!this.aps.length) {
        ctx.fillStyle = c.inkSoft; ctx.font = '700 14px ' + font; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        const lines = String(this.empty || ('No ' + band.label + ' networks seen.')).split('\n');
        lines.forEach((ln, i) => ctx.fillText(ln, (px0 + px1) / 2, (py0 + py1) / 2 + (i - (lines.length - 1) / 2) * 20));
        ctx.textBaseline = 'alphabetic';
      }
    }
    hitTest(x, y) {
      // topmost first: the last shape drawn wins
      for (let i = this._shapes.length - 1; i >= 0; i--) {
        const sh = this._shapes[i];
        if (inPolygon(x, y, sh.pts)) {
          const a = sh.a;
          return { key: a.key, net: a.net, tip: a.tip || ('<div class="t">' + escHtml(a.name) + '</div>' + dbmText(a.rssi)) };
        }
      }
      return null;
    }
  }

  function inPolygon(x, y, pts) {
    let inside = false;
    for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
      const xi = pts[i][0], yi = pts[i][1], xj = pts[j][0], yj = pts[j][1];
      if (((yi > y) !== (yj > y)) && (x < ((xj - xi) * (y - yi)) / (yj - yi) + xi)) inside = !inside;
    }
    return inside;
  }

  TNT.wifichart = {
    DBM_TOP, DBM_BOTTOM, SLOPE, GAP_S, BANDS, BAND_KEYS, PALETTE_SIZE,
    channelFreq, apSpans, freqToX, dbmToY, trapezoid, apShapes, channelTicks, labelChannels, fillAlpha, dbmTicks,
    signalClass, signalBars, timeTicks, gapFor, paletteCss, paletteHex, mixHex, escHtml, dbmText, inPolygon,
    SignalChart, SpectrumChart,
  };
})();
