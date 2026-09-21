"""Tests for the Pro AV page of the web UI (js/views/proav.js, its tile and its CSS).

Static checks on the markup, the registries in js/app.js and the stylesheet; a contract check that the mock's
hand-written room really is the shape ``tnt.proav`` produces (the mock is stdlib-only and never imports tnt, so the
two can drift and only this notices); and a headless-browser pass that mounts the page against a seeded scan and
measures the diagram it draws. Nothing here talks to a network.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict

import pytest

from tnt import proav, ptp
# the shared mock server, headless browser and probe helpers
from tests.test_ui import (TILE_NAMES, _css_decls, _probe_result, _read, _serve_probe, browser_page,  # noqa: F401
                           mock)

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "ui"


# ---------------------------------------------------------------------------
# markup, registries and CSS
# ---------------------------------------------------------------------------
def test_the_tile_sits_to_the_right_of_packet_capture():
    html = _read("index.html")
    assert TILE_NAMES[TILE_NAMES.index("proav") - 1] == "wifi"
    assert ('<a class="tile half" data-view="proav" href="#proav" style="--accent: var(--lime)">' in html)
    assert '<span class="tile-icon" data-icon="proav"></span><span class="tile-title">Pro AV</span>' in html
    assert '<div class="tile-body" id="tile-proav">' in html
    # it comes after Packet capture on the grid, and its view still loads after that one
    assert html.index('data-view="capture"') < html.index('data-view="wifi"') < html.index('data-view="proav"')
    assert html.index("js/views/capture.js") < html.index("js/views/proav.js") < html.index("js/app.js")


def test_app_js_knows_the_tenth_tile():
    app = _read("js/app.js")
    for needle in ("proav: 'var(--lime)'", "'capture', 'proav', 'sip']", "proav: 'ProAV'",
                   "const el = tileEls.proav", "TNT.views.proav",
                   "for (const name of ['proav.state', 'proav.progress'])"):
        assert needle in app, needle
    # the icon is a real entry in the set, not a fallback to 'info'
    icons = re.search(r"const ICONS = \{(.*?)\n  \};", app, re.S).group(1)
    assert re.search(r"\n    proav: '<svg ' \+ S \+ '>", icons)


def test_the_lime_accent_is_defined_in_both_themes():
    css = _read("css/tnt.css")
    light = re.search(r":root\s*\{(.*?)\}", css, re.S).group(1)
    assert re.search(r"--lime:\s*#[0-9A-Fa-f]{6};", light)
    # the dark block redefines it, so the wash behind the squares and the diagram reads in either theme
    assert len(re.findall(r"--lime:\s*#[0-9A-Fa-f]{6};", css)) >= 2


def test_the_page_and_diagram_have_their_own_styles():
    css = _read("css/tnt.css")
    for sel in (".pav-findings", ".pav-finding", ".pav-finding-head", ".pav-finding-detail", ".pav-finding-advice",
                ".pav-evidence", ".pav-plot", ".pav-edge", ".pav-node-label", ".pav-node-sub", ".pav-node-kind",
                ".pav-plot-note", ".pav-node-detail", ".pav-bar", ".pav-bar-fill", ".pav-progress-text"):
        assert _css_decls(css, sel), sel
    # every level of a finding, and every node kind the graph can emit, is styled
    for level in proav.FINDING_LEVELS:
        if level == "info":
            continue                        # the plain card is the note's own look
        assert _css_decls(css, f".pav-finding.{level}"), level
    for kind in ("grandmaster", "boundary", "transparent", "self", "talker", "stream", "listener"):
        assert _css_decls(css, f".pav-node.kind-{kind} rect"), kind
    assert _css_decls(css, ".pav-plot-scroll").get("overflow-x") == "auto"


def test_the_view_uses_the_services_own_vocabulary():
    view = _read("js/views/proav.js")
    # the levels and node kinds the page styles on are exactly what tnt.proav emits
    levels = re.search(r"const LEVEL_BADGE = \{(.*?)\};", view, re.S).group(1)
    assert sorted(re.findall(r"(\w+):", levels)) == sorted(proav.FINDING_LEVELS)
    kinds = re.search(r"const NODE_TEXT = \{(.*?)\};", view, re.S).group(1)
    for kind in ("grandmaster", "boundary", "transparent", "follower", "self", "talker", "stream", "listener"):
        assert re.search(rf"\b{kind}:", kinds), kind
    for needle in ("TNT.api.get('/proav')", "TNT.api.get('/proav/result')", "TNT.api.post('/proav/scan'",
                   "TNT.api.post('/proav/cancel'", "netChanged(", "onEvent(", "unmount("):
        assert needle in view, needle


def test_the_page_says_what_a_single_port_cannot_know():
    """The honest limit is part of the page, not a footnote to be dropped: a wiring diagram cannot be drawn from one
    host, and the page has to say so where the diagram is."""
    view = _read("js/views/proav.js")
    assert "not a wiring diagram" in view
    assert "nothing is probed" in view.lower()


def test_the_page_offers_no_way_to_ask_for_less_than_the_whole_picture():
    """The Layer 2 listen has no switch on the page: a tech wants every check, the service always has the rights
    for it, and a control nobody should touch is one somebody eventually will. `deep` stays on the API for support,
    which is why the mock still takes it."""
    view = _read("js/views/proav.js")
    assert "deep:" not in view and "els.deep" not in view
    assert "TNT.ui.toggle" not in view
    assert "administrator rights" in view          # the page still says what it does and when it cannot
    assert "deep" in _read("js/views/proav.js").split("*/")[0]   # the docstring explains where the option went


def test_the_scan_length_choices_are_the_services_own():
    view = _read("js/views/proav.js")
    offered = [int(x) for x in re.search(r"\[(10, 20, 30, [^\]]*)\]\.map", view).group(1).split(", ")]
    assert offered == list(proav.SCAN_SECONDS)


# ---------------------------------------------------------------------------
# the mock's room is the shape the service really produces
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def room(mock):
    """One whole scan result out of the mock, as the page would receive it."""
    return mock.mod.proav_result(1_700_000_000.0, 30, mock.mod.proav_adapters()[0], True)


def test_the_mocks_result_is_the_contract_shape(room):
    assert list(room) == list(proav.RESULT_KEYS)
    assert list(room["counts"]) == list(proav.COUNTS_KEYS)
    assert list(room["adapter"]) == list(proav.SCAN_ADAPTER_KEYS)
    assert all(list(entry) == list(proav.LISTENER_KEYS) for entry in room["listeners"])
    assert list(room["l2"]) == list(proav.L2_KEYS)
    assert room["switch"] and room["switch"]["switch_name"]
    assert all(list(s) == list(proav.STREAM_KEYS) for s in room["streams"])
    assert all(list(d) == list(proav.DEVICE_KEYS) for d in room["devices"])
    assert all(list(f) == list(proav.FINDING_KEYS) for f in room["findings"])


def test_the_mocks_clock_is_the_shape_tnt_ptp_produces(room):
    clock = room["clock"]
    assert list(clock) == list(ptp.CLOCK_KEYS)
    for domain in clock["domains"]:
        assert list(domain) == list(ptp.DOMAIN_KEYS)
        assert list(domain["master"]) == list(ptp.MASTER_KEYS)
        assert all(list(s) == list(ptp.SENDER_KEYS) for s in domain["senders"])
        assert all(list(f) == list(ptp.FOLLOWER_KEYS) for f in domain["followers"])


def test_the_mocks_graphs_are_the_shape_build_graph_produces(room):
    assert sorted(room["graph"]) == ["clock", "flow"]
    for plot in room["graph"].values():
        assert list(plot) == list(proav.PLOT_KEYS)
        assert all(list(n) == list(proav.NODE_KEYS) for n in plot["nodes"])
        assert all(list(e) == list(proav.EDGE_KEYS) for e in plot["edges"])
        known = {n["id"] for n in plot["nodes"]}
        assert all(e["source"] in known and e["target"] in known for e in plot["edges"]), plot["edges"]
        assert plot["note"]


def test_every_finding_the_mock_invents_is_one_the_service_can_emit(room):
    for finding in room["findings"]:
        assert finding["id"] in proav.FINDING_IDS, finding["id"]
        assert finding["level"] in proav.FINDING_LEVELS
    levels = {f["level"] for f in room["findings"]}
    assert levels == set(proav.FINDING_LEVELS), "the room should show one of every level so the page can be seen"


def test_the_mocks_own_arithmetic_holds(room):
    """The stream table's total and the bandwidth finding have to agree, or the page contradicts itself."""
    total = round(sum(s["bitrate_mbps"] for s in room["streams"]), 2)
    found = next(f for f in room["findings"] if f["id"] == "stream.found")
    assert f"{total} Mb/s" in found["detail"]
    share = round(total / room["link_mbps"] * 100.0, 1)
    assert f"{share} %" in found["detail"]
    # and each stream's own figures are what tnt.proav would compute
    for stream in room["streams"]:
        samples = stream["rate"] * (stream["ptime_ms"] / 1000.0)
        assert stream["packet_bytes"] == int(round(samples * stream["channels"] * stream["depth"] / 8.0))
        expected = (1000.0 / stream["ptime_ms"]) * (stream["packet_bytes"] + proav.PACKET_OVERHEAD_BYTES) * 8
        assert stream["bitrate_mbps"] == pytest.approx(expected / 1_000_000.0, abs=0.001)


def test_a_shallow_scan_leaves_out_only_the_checks_that_need_a_layer_2_listen(mock):
    """`deep` is gone from the page but stays on the API for support. What it drops is the three frame-based checks
    and nothing else: the switch note is LLDP and survives, which is the whole reason it was ungated."""
    shallow = mock.mod.proav_result(1_700_000_000.0, 30, mock.mod.proav_adapters()[0], False)
    ids = [f["id"] for f in shallow["findings"]]
    assert shallow["l2"] is None
    assert "net.l2" in ids
    assert not [i for i in ids if i in ("net.querier", "net.flood", "net.dscp", "net.lost")]
    assert "net.switch" in ids and shallow["switch"] is not None


def test_the_mocks_limits_and_adapters_match_the_service(mock):
    status = mock.state.proav_status()
    assert list(status) == list(proav.SCAN_STATUS_KEYS)
    assert list(status["job"]) == list(proav.JOB_KEYS)
    assert status["limits"]["seconds"] == list(proav.SCAN_SECONDS)
    assert status["limits"]["default_seconds"] == proav.DEFAULT_SECONDS
    assert all(list(a) == list(proav.SCAN_ADAPTER_KEYS) for a in status["adapters"])
    assert list(mock.state.proav_tile()) == list(proav.TILE_KEYS)


# ---------------------------------------------------------------------------
# the page in a browser
# ---------------------------------------------------------------------------
@pytest.fixture
def seeded(mock):
    """The mock with a finished scan already in it, so the page renders a whole result on mount."""
    with mock.state.lock:
        mock.state.proav_result = mock.mod.proav_result(time.time(), 30, mock.mod.proav_adapters()[0], True)
        mock.state.proav_last_run_ts = time.time()
    yield mock
    with mock.state.lock:
        mock.state.proav_result = None
        mock.state.proav_last_run_ts = None


def test_the_page_mounts_and_draws_the_whole_scan(browser_page, seeded):
    dom = browser_page("#proav")
    assert 'data-mock-errors="[]"' in dom
    assert re.search(r'<a class="tile half active" data-view="proav" href="#proav"', dom)
    view = dom.split('id="view"', 1)[1].split('<section class="diagnostics"', 1)[0]
    assert "Pro AV</h2>" in view and "style=\"--accent: var(--lime);\"" in view
    # the controls: the mock's two adapters, the service's listen lengths and Scan (Stop hidden)
    assert '<option value="Ethernet">Ethernet · 10.113.0.20 · 1 Gb/s</option>' in view
    assert '<option value="Wi-Fi">Wi-Fi · 10.113.9.44 · 866 Mb/s</option>' in view
    assert ">30 seconds</option>" in view and ">5 minutes</option>" in view
    assert re.search(r'<button class="btn btn-primary" type="button">(?:(?!</button>).)*Scan</button>', view, re.S)
    assert re.search(r'<button class="btn btn-danger" type="button" hidden="">', view)
    # the findings, worst first, with the advice each one carries
    assert view.index('class="badge red">Problem<') < view.index('class="badge green">Good<')
    assert "expect a grandmaster that is not the one on this network" in view
    assert view.count('class="pav-advice-label">What to do</span>') >= 5
    assert '<details class="pav-evidence">' in view
    # the clock card
    assert "The clock</div>" in view or "The clock<" in view
    assert "locked to a primary reference" in view and "GPS" in view
    assert "1 boundary clock away, re-served by Ubiquiti Inc" in view
    # the diagram and its honesty note
    assert '<svg class="pav-plot"' in view
    for kind in ("grandmaster", "boundary", "transparent", "follower", "self"):
        assert re.search(r'class="pav-node kind-' + kind + r'[ "]', view), kind
    assert "not a wiring diagram" in view
    # the tables
    assert "FOH Mix : Main LR" in view and "239.69.4.12:5004" in view and "19.056 Mb/s" in view
    assert "Broadcast Bridge" in view and "Audinate Pty L" in view
    # the tile
    tile = re.search(r'id="tile-proav"[^>]*>(.*?)</div>\s*</a>', dom, re.S).group(1)
    assert re.search(r'<span class="num">\d+</span><span class="muted">devices</span>', tile)
    assert 'class="badge red">to fix<' in tile


def test_the_page_says_so_when_scanning_is_not_available(browser_page, mock):
    with mock.state.lock:
        mock.state.proav_reason = "Pro AV scanning needs Windows"
    try:
        dom = browser_page("#proav")
        assert 'data-mock-errors="[]"' in dom
        assert "Pro AV scanning needs Windows" in dom
    finally:
        with mock.state.lock:
            mock.state.proav_reason = None


_PLOT_PROBE = r"""<!doctype html><html><head><meta charset="utf-8"><title>proav plot probe</title></head><body style="margin:0">
<pre id="probe">pending</pre>
<iframe id="app" src="/index.html#proav" style="width:1280px;height:860px;border:0;display:block"></iframe>
<script>
const out = {};
const frame = document.getElementById('app');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms) {
  const end = Date.now() + ms;
  for (;;) {
    let v = null;
    try { v = fn(); } catch (e) { v = null; }
    if (v) return v;
    if (Date.now() > end) return null;
    await sleep(40);
  }
}
// one plot: the nodes with their text, and whether any of it escapes its own box or overlaps the line above it
function plot(doc) {
  const svg = doc.querySelector('.pav-plot');
  if (!svg) return null;
  const nodes = Array.from(doc.querySelectorAll('.pav-node')).map((g) => {
    const rect = g.querySelector('rect');
    const w = parseFloat(rect.getAttribute('width')), h = parseFloat(rect.getAttribute('height'));
    const parts = ['.pav-node-kind', '.pav-node-label', '.pav-node-sub'].map((sel) => g.querySelector(sel));
    const boxes = parts.map((el) => (el && el.textContent ? el.getBBox() : null));
    let overflow = 0, overlap = false;
    for (let i = 0; i < boxes.length; i++) {
      const b = boxes[i];
      if (!b) continue;
      overflow = Math.max(overflow, Math.round(b.x + b.width - w), Math.round(b.y + b.height - h));
      const next = boxes[i + 1];
      if (next && b.y + b.height > next.y) overlap = true;
    }
    return { kind: (g.getAttribute('class').match(/kind-([a-z]+)/) || [])[1],
             text: parts.map((el) => (el ? el.textContent : '')),
             w: w, h: h, overflow: overflow, overlap: overlap };
  });
  const box = svg.getBoundingClientRect();
  return { count: nodes.length, edges: doc.querySelectorAll('.pav-edge').length, nodes: nodes,
           width: Math.round(box.width), viewBox: svg.getAttribute('viewBox'),
           note: (doc.querySelector('.pav-plot-note') || {}).textContent || '' };
}
async function run() {
  await until(() => frame.contentDocument && frame.contentDocument.querySelector('.pav-plot'), 10000);
  const doc = frame.contentDocument, win = frame.contentWindow;
  out.clock = plot(doc);
  const tabs = Array.from(doc.querySelectorAll('.seg button'));
  out.tabs = tabs.map((b) => b.textContent.trim());
  // a node is a button: clicking one opens the detail line under the diagram
  doc.querySelector('.pav-node.kind-grandmaster').dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
  await sleep(100);
  const detail = doc.querySelector('.pav-node-detail');
  out.detail = { hidden: detail.hidden, text: detail.textContent };
  // the Stream flow tab draws the other graph into the same card, and clears the open detail
  tabs.find((b) => b.textContent.trim() === 'Stream flow').click();
  await sleep(150);
  out.flow = plot(doc);
  out.detailCleared = doc.querySelector('.pav-node-detail').hidden;
  // and back again
  tabs.find((b) => b.textContent.trim() === 'Clock tree').click();
  await sleep(150);
  out.backToClock = (doc.querySelector('.pav-node.kind-grandmaster') !== null);
  // nothing on the page runs past the window
  const el = doc.documentElement;
  out.overflow = el.scrollWidth - el.clientWidth;
  out.errors = doc.documentElement.getAttribute('data-mock-errors');
  document.getElementById('probe').textContent = JSON.stringify(out);
}
run().catch((e) => {
  out.probeError = String((e && e.stack) || e);
  document.getElementById('probe').textContent = JSON.stringify(out);
});
</script></body></html>"""


def test_the_diagram_draws_both_graphs_without_clipping_a_word(browser_page, seeded, monkeypatch):
    """The clock tree and the stream flow map in a real browser: every node's three lines fit inside its own box and
    none overlaps the line above it (the text is SVG, so nothing wraps or ellipsises on its own)."""
    _serve_probe(seeded, monkeypatch, "proav-plot-probe.html", _PLOT_PROBE)
    res = _probe_result(browser_page("proav-plot-probe.html", budget_ms=25000, size=(1366, 900)))
    assert res.get("errors") == "[]", res.get("errors")
    assert res["tabs"] == ["Clock tree", "Stream flow"]

    clock = res["clock"]
    kinds = [n["kind"] for n in clock["nodes"]]
    assert kinds[:3] == ["grandmaster", "boundary", "transparent"]
    assert "self" in kinds and kinds.count("follower") == 4
    assert clock["edges"] == len(clock["nodes"]) - 1        # a tree: one edge into every node but the root
    assert "measured, not guessed" in clock["note"]

    flow = res["flow"]
    assert sorted({n["kind"] for n in flow["nodes"]}) == ["listener", "stream", "talker"]
    assert flow["edges"] >= 6 and "cannot be seen from one port" in flow["note"]

    for name in ("clock", "flow"):
        for node in res[name]["nodes"]:
            assert node["overflow"] <= 0, (name, node)     # every line inside its own box
            assert node["overlap"] is False, (name, node)
            assert node["text"][1].strip(), (name, node)   # and every node is named
    # clicking a node explains it, and the tab goes back
    assert res["detail"]["hidden"] is False and "Grandmaster" in res["detail"]["text"]
    assert res["detailCleared"] is True      # switching graphs closes a detail that belonged to the other one
    assert res["backToClock"] is True
    assert res["overflow"] == 0                            # the page itself never scrolls sideways
