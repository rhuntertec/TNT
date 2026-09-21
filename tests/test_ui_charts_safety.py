"""The UI's charts: what they put into the page, and what they draw for the half-hour throughput view.

Two defects from the 1.21.2 review live here.

* Chart tooltips are HTML strings that ``Chart.showTip`` hands to ``innerHTML``. A failed speed test
  stores the first bytes of the HTTP reply in ``SpeedResult.error``, so whatever answered the speed
  probe (a captive portal, a filtering proxy) chose markup that ran inside the TNT window, the one that
  exposes ``window.pywebview.api``. Every backend string a chart puts into a tooltip is escaped now,
  and ``views/speed.js`` escapes what its own tooltip builders take from a result.
* The 30-minute throughput window is served in 3-second buckets (``tnt.throughput.step_for(1800)``),
  but the card told its chart the step was 1 s, so every bucket was a line segment of its own, one
  point long, and drew nothing: the half hour before the card was opened was blank. The card now
  hands the chart the service's ``step_s``, and its dashed average weighs a bucket for the seconds it
  stands for.

The arithmetic is checked with node against the real files; the page itself with headless Chrome
against tools/mock_api.py, like tests/test_ui.py.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from test_ui import mock, browser_page, _serve_probe  # noqa: F401  (fixtures)
from test_ui_115 import _run_probe

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "ui"

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

# what a hostile answer to the speed probe can carry into SpeedResult.error (tnt/speedtest/base.py HttpError)
XSS = "HTTP 511 for /cdn-cgi/trace: <!DOCTYPE html><html><body><img src=x onerror=\"document.body.dataset.xss='fired'\">"


def _serve_app_that_draws(mock: Any, monkeypatch: Any) -> None:
    """Serve the app once more at /charts-app.html with requestAnimationFrame on a timer.

    Headless Chrome with --dump-dom produces no animation frames (or only now and then), and a chart's
    render() waits for one, so a chart there draws only by luck: its hover targets are made while it
    draws, and a probe that hovers one would pass or fail at random. The page is otherwise exactly what
    the mock serves at /index.html, its bridge script included. A probe opens it with
    ``frame.src = '/charts-app.html#<view>'``."""
    tag = '<script src="js/api.js"></script>'
    shim = ('<script>window.requestAnimationFrame = (fn) => setTimeout(() => fn(performance.now()), 16);'
            ' window.cancelAnimationFrame = (id) => clearTimeout(id);</script>\n')
    index = (UI / "index.html").read_text(encoding="utf-8")
    assert tag in index
    _serve_probe(mock, monkeypatch, "charts-app.html",
                 index.replace(tag, f'<script src="{mock.mod.MOCK_WIFI_BRIDGE_URL}"></script>\n' + shim + tag, 1))


def _node(driver: str, tmp_path: Path, *args: str) -> Any:
    path = tmp_path / "driver.js"
    path.write_text(driver, encoding="utf-8")
    r = subprocess.run(["node", str(path), *args], capture_output=True, encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# =========================================================================================
# tooltips: every backend string is text, never markup
# =========================================================================================
_TIP_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
// charts.js touches the DOM only in a chart's constructor; a stub canvas and a context that
// accepts every call are enough to run draw() and read the hits it leaves behind
const canvas = {
  addEventListener: () => {}, removeEventListener: () => {}, parentElement: null,
  getBoundingClientRect: () => ({ width: 700, height: 240 }), isConnected: false,
  getContext: () => ({}), width: 700, height: 240,
};
const window = {
  TNT: {}, devicePixelRatio: 1, addEventListener: () => {}, removeEventListener: () => {},
  requestAnimationFrame: () => 0, cancelAnimationFrame: () => {},
  getComputedStyle: () => ({ getPropertyValue: () => '#6FA8FF', fontFamily: 'sans-serif' }),
};
const document = { documentElement: {}, body: {}, createElement: () => ({ style: {} }) };
const ctx = vm.createContext({ window, document, console, ResizeObserver: undefined,
                               getComputedStyle: window.getComputedStyle,
                               requestAnimationFrame: () => 0, cancelAnimationFrame: () => {} });
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'charts.js' });
const C = window.TNT.charts;
const bad = process.argv[3];
const pen = new Proxy({}, {
  get: (t, k) => (k in t ? t[k] : k === 'measureText' ? () => ({ width: 40 }) : k === 'getLineDash' ? () => [] : () => {}),
  set: (t, k, v) => { t[k] = v; return true; },
});
function drawn(chart) {
  chart.c = C.colors(); chart.font = 'sans-serif'; chart.hits = [];
  chart.draw(pen, 700, 240);
  return chart.hits.map((h) => h.tip);
}
const now = 1700000000;
const out = {};

// the speed history: a failed test's error, an average rule's label and tip, and a series name
const line = new C.LineChart(canvas, { unit: 'Mbps' });
line.setData({
  xMin: now - 86400, xMax: now, unit: 'Mbps',
  series: [{ name: bad, color: '#B48CFF', points: [[now - 7200, 100], [now - 600, 120]] }],
  hlines: [{ value: 110, color: '#B48CFF', label: bad, tip: bad }],
  marks: [{ ts: now - 3600, label: bad, detail: bad }],
});
out.line = drawn(line);

// the by-hour bars when the caller gives no tip of its own
const bars = new C.BarChart(canvas, { unit: 'Mbps' });
bars.setData({ bars: [{ label: bad, value: 5 }, { label: bad, value: null }] });
out.bars = drawn(bars);

// the outage timeline: a target's host name is whatever was typed into the target list
const tl = new C.Timeline(canvas);
tl.setData({ start_ts: now - 86400, end_ts: now, gaps: [],
             segments: [{ kind: 'target', host: bad, target_id: 3, start_ts: now - 5000, end_ts: now - 4000, missed: bad }],
             total_segments: [] });
out.timeline = drawn(tl);

// the throughput chart's hover columns go through the card's formatters
const tp = new C.Throughput(canvas, { windowS: 30, stepS: 1, fmt: () => bad, timeFmt: () => bad });
tp.now = now; tp.rx = [[now - 5, 1000]]; tp.tx = [[now - 5, 10]];
out.throughput = drawn(tp);
process.stdout.write(JSON.stringify(out));
"""


@needs_node
def test_a_chart_tooltip_carries_backend_text_as_text_never_as_markup(tmp_path):
    out = _node(_TIP_DRIVER, tmp_path, str(UI / "js/charts.js"), XSS)
    escaped = "&lt;img src=x onerror=&quot;document.body.dataset.xss=&#39;fired&#39;&quot;&gt;"
    for chart in ("line", "bars", "timeline", "throughput"):
        tips = [t for t in out[chart] if t]
        assert tips, chart
        for tip in tips:
            assert "<img" not in tip and "<!DOCTYPE" not in tip, (chart, tip)
        # and nothing is lost: the reason the technician needs is all there, as text
        assert any(escaped in t for t in tips), (chart, tips)

    # the red X of the failed test: the chart's own markup is untouched (the title and the muted line
    # are still elements) and the error sits inside it as text
    assert any(t.startswith('<div class="t">HTTP 511') and '<div class="muted">HTTP 511 for /cdn-cgi/trace: &lt;!DOCTYPE html&gt;' in t
               for t in out["line"]), out["line"]


@needs_node
def test_a_chart_tooltip_still_shows_ordinary_text_unchanged(tmp_path):
    """The escaping is at the sink: plain text reads exactly as it did.

    A guard against over-escaping, not a reproduction of the defect: it passed before the fix too, and
    is here so the fix can never turn an ordinary error into entity soup."""
    out = _node(_TIP_DRIVER, tmp_path, str(UI / "js/charts.js"), "HTTP 503 from speed.cloudflare.com")
    assert any('<div class="muted">HTTP 503 from speed.cloudflare.com</div>' in t for t in out["line"])
    assert any("<b>HTTP 503 from speed.cloudflare.com</b>" in t for t in out["throughput"])


# the Speed page against the mock: a failed test whose error is an <img onerror> and a successful test
# whose server name is one, hovered the way a technician hovers them
_SPEED_PROBE = r"""
async function run() {
  // let the first load (/index.html) finish, so switching pages does not cut a reply off half way
  await until(() => app() && app().readyState === 'complete', 15000);
  frame.src = '/charts-app.html#speed';
  const doc = await until(() => app() && app().location.pathname === '/charts-app.html'
    && app().querySelector('#view canvas[aria-label="Speed test history"]') && app(), 15000);
  const canvas = doc.querySelector('#view canvas[aria-label="Speed test history"]');
  // the history has loaded once the summary counts the failed tests
  await until(() => /failed/.test(text(doc.querySelector('#view .card .row.between .muted.small')) || ''), 15000);
  await sleep(300);
  const win = frame.contentWindow;
  const rect = canvas.getBoundingClientRect();
  const tips = new Map();
  const hover = (x, y) => {
    canvas.dispatchEvent(new win.MouseEvent('mousemove', { clientX: rect.left + x, clientY: rect.top + y, bubbles: true }));
    const tip = canvas.parentElement.querySelector('.chart-tip');
    if (tip && tip.style.display !== 'none') tips.set(tip.innerHTML, { text: tip.textContent, imgs: tip.querySelectorAll('img').length });
  };
  // the red X sits 7 px above the plot's floor (padB 28); the hover columns cover the whole plot
  for (let x = 40; x < rect.width - 10; x += 3) { hover(x, rect.height - 35); hover(x, rect.height / 2); }
  await sleep(500);                                  // an <img src=x> would have failed to load by now
  out.tips = Array.from(tips.entries()).map(([html, v]) => ({ html, text: v.text, imgs: v.imgs }));
  out.imgs = doc.querySelectorAll('.chart-tip img').length;
  out.fired = doc.body.dataset.xss || null;
}
"""


def test_hovering_a_failed_speed_test_shows_its_error_as_text_in_a_browser(browser_page, mock, monkeypatch):
    state = mock.state
    server_xss = "<img src=y onerror=\"document.body.dataset.xss='server'\">"
    now = time.time()
    with state.lock:
        base = next(r for r in reversed(state.speedtests) if r["ok"])
        n = len(state.speedtests)
        failed = dict(base, id=n + 1, ts=now - 3 * 3600, ok=False, error=XSS, download_mbps=None, upload_mbps=None,
                      latency_ms=None, jitter_ms=None, server=None, quality=None)
        hostile_ok = dict(base, id=n + 2, ts=now - 5 * 3600 - 450, backend="<b>cloudflare</b>", server=server_xss)
        state.speedtests.extend([failed, hostile_ok])
        state.speedtests.sort(key=lambda r: r["ts"])
    try:
        _serve_app_that_draws(mock, monkeypatch)
        res = _run_probe(browser_page, mock, monkeypatch, "speed-tip-probe.html", "speed", _SPEED_PROBE)
    finally:
        with state.lock:
            state.speedtests.remove(failed)
            state.speedtests.remove(hostile_ok)

    # the handler never ran and no element was made from either string
    assert res["fired"] is None
    assert res["imgs"] == 0
    assert all(t["imgs"] == 0 for t in res["tips"]), res["tips"]
    # the failed test's tooltip reads the error, word for word, as text
    failed_tips = [t for t in res["tips"] if t["text"].startswith("Test failed")]
    assert failed_tips, [t["text"][:60] for t in res["tips"]]
    assert any(XSS in t["text"] for t in failed_tips), failed_tips
    # the successful test's tooltip names its backend and server as text too
    ok_tips = [t for t in res["tips"] if server_xss in t["text"]]
    assert ok_tips, "the hostile server name never showed"
    assert all("<b>cloudflare</b>" in t["text"] for t in ok_tips)


def test_speed_views_tooltip_builders_escape_what_they_take_from_a_result():
    """views/speed.js builds two tooltips of its own (a test's history point, an hour's bar): every
    field it takes from a result goes through TNT.util.esc."""
    src = (UI / "js/views/speed.js").read_text(encoding="utf-8")
    fmt = src[src.index("historyChart.formatTip = "):src.index("const n = ok.length;")]
    assert "esc(x.backend" in fmt and "esc(x.server)" in fmt
    assert "+ (x.backend || '') +" not in fmt and "' · ' + x.server" not in fmt
    bars = src[src.index("const bars = (p.by_hour"):src.index("hourChart.setData(")]
    assert "esc(b.count || 0) + ' tests" in bars and "esc(pad2(b.hour))" in bars


# =========================================================================================
# the 30-minute window: the service's step reaches the chart
# =========================================================================================
_AVG_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const window = { TNT: {} };
const ctx = vm.createContext({ window, console, document: undefined });
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'throughput.js' });
const tp = window.TNT.throughput;
const out = {};
// 500 three-second buckets at 1 Mbps (the backlog GET /api/throughput?window_s=1800 hands over), then
// 300 live one-second samples at 10 Mbps: 1500 s of one and 300 s of the other
const series = [];
for (let i = 0; i < 500; i++) series.push([1000 + i * 3, 1000000, 0, 0, 0]);
for (let i = 1; i <= 300; i++) series.push([1000 + 499 * 3 + i, 10000000, 0, 0, 0]);
const now = series[series.length - 1][0];
out.weighted = tp.average(series, 1, 1800, now, 3);
// a step of one (or none given) is the plain mean it always was
out.plain = tp.average(series.slice(500), 1, 1800, now, 1);
out.noStep = tp.average([[997, 30, 6, 0, 0], [998, 20, 4, 0, 0], [999, 10, 2, 0, 0]], 1, 30, 1000);
// unsorted input is read in time order
out.unsorted = tp.average([[1009, 9, 0, 0, 0], [1000, 3, 0, 0, 0], [1003, 3, 0, 0, 0], [1006, 3, 0, 0, 0], [1010, 9, 0, 0, 0]], 1, 1800, 1010, 3);
// a hole in the stream is not counted as time at the rate before it: a bucket never stands for more than its step
out.hole = tp.average([[1000, 6, 0, 0, 0], [1100, 0, 0, 0, 0]], 1, 1800, 1100, 3);
process.stdout.write(JSON.stringify(out));
"""


@needs_node
def test_the_window_average_weighs_a_bucket_for_the_seconds_it_stands_for(tmp_path):
    out = _node(_AVG_DRIVER, tmp_path, str(UI / "js/throughput.js"))
    # the time-weighted truth (and the service's avg_rx_bps): (1500 * 1 + 300 * 10) / 1800 Mbps
    assert out["weighted"] == pytest.approx(2_500_000, rel=1e-3)
    assert out["plain"] == 10_000_000 and out["noStep"] == 20
    # 1000/1003/1006 are 3 s buckets, 1009 and 1010 live seconds: (3*3 + 3*3 + 3*3 + 9 + 9) / 11
    assert out["unsorted"] == pytest.approx((27 + 18) / 11)
    # 3 s at 6, the last row 1 s at 0
    assert out["hole"] == pytest.approx(18 / 4)


_TP_PROBE = r"""
function instrument(win) {
  // record what the canvas of the watched NIC is asked to draw: each stroke's style, dash and x extent,
  // and every text it writes
  const P = win.CanvasRenderingContext2D.prototype;
  const rec = { strokes: [], texts: [] };
  const orig = { beginPath: P.beginPath, moveTo: P.moveTo, lineTo: P.lineTo, stroke: P.stroke, fillText: P.fillText };
  const mine = (c) => c.canvas === win.__tpTarget;
  P.beginPath = function () { if (mine(this)) this.__xs = []; return orig.beginPath.apply(this, arguments); };
  P.moveTo = function (x) { if (mine(this) && this.__xs) this.__xs.push(x); return orig.moveTo.apply(this, arguments); };
  P.lineTo = function (x) { if (mine(this) && this.__xs) this.__xs.push(x); return orig.lineTo.apply(this, arguments); };
  P.stroke = function () {
    if (mine(this) && this.__xs && this.__xs.length) {
      let a = Infinity, b = -Infinity;
      for (const v of this.__xs) { if (v < a) a = v; if (v > b) b = v; }
      rec.strokes.push({ style: String(this.strokeStyle), dash: this.getLineDash().length, x0: a, x1: b });
    }
    return orig.stroke.apply(this, arguments);
  };
  P.fillText = function (t) { if (mine(this)) rec.texts.push({ text: String(t), style: String(this.fillStyle) }); return orig.fillText.apply(this, arguments); };
  return rec;
}
function coverage(rec, width) {
  // how much of the plot the receive line covers: the solid strokes in the colour of the "avg ↓" label
  const avg = rec.texts.find((t) => t.text.indexOf('avg ↓') === 0);
  if (!avg) return { cover: 0, avg: null };
  const spans = rec.strokes.filter((s) => s.style === avg.style && !s.dash && s.x1 > s.x0).map((s) => [s.x0, s.x1]).sort((p, q) => p[0] - q[0]);
  let total = 0, end = -Infinity;
  for (const [a, b] of spans) { if (b <= end) continue; total += b - Math.max(a, end); end = b; }
  return { cover: total / (width - 4), avg: avg.text, runs: spans.length };
}
async function measure(win, rec, label) {
  const nic = Array.from(app().querySelectorAll('#view .tp-nic')).find((b) => text(b.querySelector('.tp-name')) === '@NIC@');
  const canvas = nic.querySelector('.tp-canvas');
  win.__tpTarget = canvas;
  // wait for the window asked for to be the one drawn (its label is written under the plot)
  for (let i = 0; i < 60; i++) {
    rec.strokes.length = 0; rec.texts.length = 0;
    win.TNT.charts.rerenderAll();
    await sleep(120);
    if (rec.texts.some((t) => t.text === label)) break;
  }
  return Object.assign(coverage(rec, canvas.getBoundingClientRect().width), { label: rec.texts.some((t) => t.text === label) });
}
async function pick(name) {
  const b = Array.from(app().querySelectorAll('#view .tp-windows button')).find((x) => x.textContent === name);
  b.click();
  await sleep(400);
}
async function run() {
  // let the first load (/index.html) finish, so switching pages does not cut a reply off half way
  await until(() => app() && app().readyState === 'complete', 15000);
  frame.src = '/charts-app.html#ipinfo';
  await until(() => app() && app().location.pathname === '/charts-app.html' && app().querySelector('#view .tp-card .tp-nic .tp-canvas'), 15000);
  const win = frame.contentWindow;
  const rec = instrument(win);
  await pick('30 min');
  out.backlog = await measure(win, rec, '30 minutes');
  // then a live stream: one throughput.sample a second, straight after the last second the backlog holds
  const view = await (await fetch('/api/throughput?window_s=1800')).json();
  const end = Math.floor(view.ts);
  for (let ts = @LAST@ + 1; ts <= end; ts++) {
    const nics = view.nics.map((n) => Object.assign({}, n, { samples: undefined }, n.name === '@NIC@' ? { rx_bps: @LIVE@ } : {}));
    win.TNT.api.events._emit('throughput.sample', { ts, nics });
  }
  out.liveEnd = end;
  out.live = await measure(win, rec, '30 minutes');
  await pick('5 min');
  out.five = await measure(win, rec, '5 minutes');
  await pick('1 min');
  out.one = await measure(win, rec, '60 seconds');
}
"""


def _rate(text: str) -> float:
    m = re.search(r"([\d.]+) (Gbps|Mbps|Kbps|bps)$", text)
    assert m, text
    return float(m.group(1)) * {"Gbps": 1e9, "Mbps": 1e6, "Kbps": 1e3, "bps": 1.0}[m.group(2)]


def test_the_thirty_minute_window_draws_its_backlog_and_a_time_weighted_average_in_a_browser(browser_page, mock, monkeypatch):
    """§10: open the card on 30 min with 25 minutes of history behind it and five minutes streaming in live.
    The whole half hour draws (not only the live tail), the dashed rule sits at the time-weighted average,
    and the 5-minute and 1-minute windows still draw the same way they did."""
    state = mock.state
    live_bps = 400_000_000
    now = int(time.time())
    with state.lock:
        state.tp_samples.clear()
    last = now - 301
    for ts in range(now - 2100, last + 1):            # history that stops five minutes ago
        state.throughput_tick(float(ts))
    prof = mock.mod.net_profile(state.net_profile)
    primary = next(a for a in state._tp_adapters() if int(a["index"]) == prof["internet_nic_index"])
    nic = str(primary["name"])
    truth_rows = [s for s in state.tp_samples[int(primary["index"])]]
    _serve_app_that_draws(mock, monkeypatch)
    body = _TP_PROBE.replace("@NIC@", nic).replace("@LAST@", str(last)).replace("@LIVE@", str(live_bps))
    res = _run_probe(browser_page, mock, monkeypatch, "tp-step-probe.html", "ipinfo", body, budget_ms=40000)

    # the backlog alone: 25 of the 30 minutes hold samples, and they draw as one line, not 500 dots
    assert res["backlog"]["label"], res["backlog"]
    assert res["backlog"]["cover"] > 0.75, res["backlog"]
    # with five minutes of live seconds after it the whole window is drawn
    assert res["live"]["cover"] > 0.95, res["live"]

    # the dashed rule: every second in the window counted once, whether it came as part of a 3 s bucket or live
    end = res["liveEnd"]
    floor = end - 1800
    backlog = [s[1] for s in truth_rows if floor <= s[0] <= last]
    live = end - last
    truth = (sum(backlog) + live * live_bps) / (len(backlog) + live)
    assert _rate(res["live"]["avg"]) == pytest.approx(truth, rel=0.04), (res["live"]["avg"], truth)

    # the short windows (one-second samples) still draw across the plot
    for key in ("five", "one"):
        assert res[key]["label"] and res[key]["cover"] > 0.9, (key, res[key])
        assert _rate(res[key]["avg"]) == pytest.approx(live_bps, rel=0.02), (key, res[key])


def test_the_card_hands_the_chart_the_services_step():
    src = (UI / "js/throughput.js").read_text(encoding="utf-8")
    assert "stepS: 1," not in src
    assert "data.step_s" in src


# =========================================================================================
# the step belongs to each sample, not to the card
# =========================================================================================
# One step for the whole card was wrong both ways once the 30-minute backlog arrived: on that window
# the live seconds after the backlog were held to the backlog's 3 s tolerance (a 3-5 s hole in the
# stream was drawn straight across and counted as time at the rate before it), and on a shorter
# window whose backlog GET failed the card kept step 3 for samples one second apart. A backlog row
# now carries its own step (its sixth column), and a live row is one second.
_STEP_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const canvas = {
  addEventListener: () => {}, removeEventListener: () => {}, parentElement: null,
  getBoundingClientRect: () => ({ width: 700, height: 240 }), isConnected: false,
  getContext: () => ({}), width: 700, height: 240,
};
const window = {
  TNT: {}, devicePixelRatio: 1, addEventListener: () => {}, removeEventListener: () => {},
  requestAnimationFrame: () => 0, cancelAnimationFrame: () => {},
  getComputedStyle: () => ({ getPropertyValue: () => '#6FA8FF', fontFamily: 'sans-serif' }),
};
const document = { documentElement: {}, body: {}, createElement: () => ({ style: {} }) };
const ctx = vm.createContext({ window, document, console, ResizeObserver: undefined,
                               getComputedStyle: window.getComputedStyle,
                               requestAnimationFrame: () => 0, cancelAnimationFrame: () => {} });
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'charts.js' });
vm.runInContext(fs.readFileSync(process.argv[3], 'utf8'), ctx, { filename: 'throughput.js' });
const C = window.TNT.charts, tp = window.TNT.throughput;
const out = {};

const chart = new C.Throughput(canvas, { windowS: 1800 });
chart.now = 1100;
// three 3 s buckets, then live seconds, then a 4 s hole in the live stream (under GAP_S, so no refetch)
chart.rx = [[990, 1, 3], [993, 1, 3], [996, 1, 3], [999, 1], [1000, 1], [1004, 1], [1005, 1]];
out.mixed = chart.runs(chart.rx).map((r) => r.map((p) => p[0]));
// a bucket's hover column is as wide as its three seconds, a live second's as wide as one
const hits = [];
chart.hits = hits;
chart._hits(0, 18000, 0, 100, (ts) => (ts - (chart.now - chart.windowS)) * 10);
out.widths = hits.map((h) => Math.round(h.x1 - h.x0));

// the average: a bucket counts its three seconds, a live second one, and a live hole is a hole
const rows = [[1000, 6, 0, 0, 0, 3], [1003, 6, 0, 0, 0, 3], [1006, 0, 0, 0, 0], [1010, 0, 0, 0, 0]];
out.avg = tp.average(rows, 1, 1800, 1010);
out.avgWithCardStep = tp.average(rows, 1, 1800, 1010, 3);
process.stdout.write(JSON.stringify(out));
"""


@needs_node
def test_each_sample_carries_its_own_step_so_a_live_hole_breaks_the_line_on_the_long_window(tmp_path):
    out = _node(_STEP_DRIVER, tmp_path, str(UI / "js/charts.js"), str(UI / "js/throughput.js"))
    # the buckets join each other and the live tail; the 4 s hole between 1000 and 1004 breaks the line
    assert out["mixed"] == [[990, 993, 996, 999, 1000], [1004, 1005]]
    # hover columns: 3 s wide for a bucket, 1 s for a live row (the plot is 10 px a second here)
    assert out["widths"] == [30, 30, 30, 10, 10, 10, 10]


@needs_node
def test_the_average_takes_each_rows_step_from_the_row(tmp_path):
    out = _node(_STEP_DRIVER, tmp_path, str(UI / "js/charts.js"), str(UI / "js/throughput.js"))
    # 3 s at 6 + 3 s at 6 + 1 s at 0 (then a 3 s hole, not credited) + the last row's second at 0
    assert out["avg"] == pytest.approx(36 / 8)
    # a step handed in by the caller is only for rows that carry none, and never overrides a row's own:
    # here it stretches the untagged row at 1006 to three seconds, the tagged buckets are unchanged
    assert out["avgWithCardStep"] == pytest.approx(36 / 10)


def test_the_card_tags_its_backlog_with_the_services_step_and_holds_no_step_of_its_own():
    src = (UI / "js/throughput.js").read_text(encoding="utf-8")
    seed = src[src.index("async function seed()"):src.index("function onSample(")]
    assert "data.step_s" in seed
    # no card-wide step left to go stale when a window changes and its backlog GET fails
    assert "let stepS" not in src


# =========================================================================================
# the contract holds without exceptions: even text charts.js writes itself is escaped
# =========================================================================================
# A missed percentage under a tenth of a percent reads "<0.1%". The parser happens to keep "<0"
# as text, but the tooltip contract is that every piece of text goes into the tip escaped, so
# nothing depends on which characters a browser forgives.
_MISSED_DRIVER = _TIP_DRIVER.split("// the speed history:")[0] + r"""
const tl = new C.Timeline(canvas);
tl.setData({ start_ts: now - 86400, end_ts: now, gaps: [],
             segments: [{ kind: 'target', host: 'printer.example', target_id: 3, start_ts: now - 5000,
                          end_ts: now - 4000, missed: 1, missed_pct: 0.05, sent_estimated: true }],
             total_segments: [] });
process.stdout.write(JSON.stringify({ timeline: drawn(tl) }));
"""


@needs_node
def test_a_tiny_missed_percentage_goes_into_the_outage_tip_escaped(tmp_path):
    out = _node(_MISSED_DRIVER, tmp_path, str(UI / "js/charts.js"))
    tip = next(t for t in out["timeline"] if t and "missed" in t)
    assert "(\u2248&lt;0.1%)" in tip
    assert "<0.1" not in tip


# =========================================================================================
# a re-seed on the 30-minute window: the fresh buckets and the held live seconds do not overlap
# =========================================================================================
# After a gap in the stream the card asks for the backlog again while it still holds live
# one-second rows. On the 30-minute window the fresh rows are 3 s buckets (keyed by their first
# second) that already average those same seconds. Merging both left a bucket beside live rows
# for the seconds it stands for: the line stepped between the bucket's mean and each second, and
# the average took the bucket for one second of what was three. The backlog is the service's
# own account of every second up to its `ts`, so a held row inside it gives way; a held row after
# it (a sample that arrived while the GET was in flight) is newer than anything in it and stays.
_MERGE_DRIVER = r"""
const fs = require('fs'), vm = require('vm');
const window = { TNT: {} };
const ctx = vm.createContext({ window, console, document: undefined });
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), ctx, { filename: 'throughput.js' });
const tp = window.TNT.throughput;
const out = {};
// held: live seconds 295..306 at 9; fresh: buckets at 297, 300 and 303 at 6, served at ts 305.4
const held = [];
for (let t = 295; t <= 306; t++) held.push([t, 9, 0, 0, 0]);
const fresh = [[297, 6, 0, 0, 0, 3], [300, 6, 0, 0, 0, 3], [303, 6, 0, 0, 0, 3]];
const merged = tp.mergeBacklog(fresh.map((r) => r.slice()), held, 3, 305.4);
out.ts = merged.map((r) => r[0]);
out.steps = merged.map((r) => r[5] || 1);
out.avg = tp.average(merged, 1, 1800, 306);
// on a one-second window the same rule changes nothing: the fresh row for a second wins, the rest stay
const f1 = [[300, 1, 0, 0, 0], [301, 1, 0, 0, 0]];
const h1 = [[299, 7, 0, 0, 0], [300, 7, 0, 0, 0], [302, 7, 0, 0, 0]];
out.one = tp.mergeBacklog(f1, h1, 1, 301.5).map((r) => [r[0], r[1]]);
// a NIC the backlog brought back with no rows keeps everything it held
out.empty = tp.mergeBacklog([], h1, 3, 301.5).map((r) => r[0]);
// with no ts in the reply, the backlog reaches to the end of its last bucket
out.noTs = tp.mergeBacklog(fresh.map((r) => r.slice()), held, 3, undefined).map((r) => r[0]);
process.stdout.write(JSON.stringify(out));
"""


@needs_node
def test_a_reseed_on_the_long_window_does_not_leave_buckets_beside_live_seconds_they_cover(tmp_path):
    out = _node(_MERGE_DRIVER, tmp_path, str(UI / "js/throughput.js"))
    # 295 and 296 are before the backlog, 306 after it; 297..305 are the buckets' own seconds
    assert out["ts"] == [295, 296, 297, 300, 303, 306]
    assert out["steps"] == [1, 1, 3, 3, 3, 1]
    # 2 s at 9, 9 s at 6, the newest second at 9: each second once
    assert out["avg"] == pytest.approx((18 + 54 + 9) / 12)
    assert out["one"] == [[299, 7], [300, 1], [301, 1], [302, 7]]
    assert out["empty"] == [299, 300, 302]
    assert out["noTs"] == [295, 296, 297, 300, 303, 306]
