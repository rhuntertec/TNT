"""Tests for the SIP page of the web UI (js/views/sip.js, its tile and its CSS).

Static checks on the markup, the registries in js/app.js and the stylesheet; node checks on the page's pure views
(including the call-quality lines it took over from the Speed page, which is where the Speed tests used to pin
them); a contract check that the mock's hand-written rating really is the shape ``tnt.sipqual`` produces (the mock
is stdlib-only and never imports tnt, so the two can drift and only this notices); and a headless-browser pass
that drives the page the way a tech does — check the ALG, test the NAT, load two captures, open a call and open a
packet. Nothing here talks to a network.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import pytest

from tnt import sipalg, sipcalls, sipflow, sipnat, sipqual
# the shared mock server, headless browser and probe helpers
from tests.test_ui import (TILE_NAMES, _css_decls, _probe_result, _read, _serve_probe, browser_page,  # noqa: F401
                           mock)

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "ui"
NODE = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


@pytest.fixture(autouse=True)
def _no_captures_loaded(request):
    """The mock server is module-scoped, so a capture one test loads is the next one's starting state. Every test
    here starts with both slots empty."""
    if "mock" not in request.fixturenames:
        yield
        return
    state = request.getfixturevalue("mock").state
    state.sip_flow_close(None)
    try:
        yield
    finally:
        state.sip_flow_close(None)

_PRELUDE = r"""
const fs = require('fs'), vm = require('vm');
const window = { TNT: { views: {}, util: {}, api: {}, ui: {} } };
const ctx = vm.createContext({ window, console });
const load = (file) => vm.runInContext(fs.readFileSync(file, 'utf8'), ctx, { filename: file });
const input = JSON.parse(fs.readFileSync(process.argv[process.argv.length - 1], 'utf8'));
const T = window.TNT;
"""


def _node(tmp_path: Path, body: str, files: List[str], payload: Any = None) -> Any:
    driver = tmp_path / "driver.js"
    driver.write_text(_PRELUDE + body, encoding="utf-8")
    data = tmp_path / "payload.json"
    data.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    r = subprocess.run(["node", str(driver)] + [str(UI / f) for f in files] + [str(data)],
                       capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# ---------------------------------------------------------------------------
# markup, registries and CSS
# ---------------------------------------------------------------------------
def test_the_tile_sits_between_faults_and_wifi():
    html = _read("index.html")
    assert TILE_NAMES[TILE_NAMES.index("sip") - 1] == "faults"
    assert TILE_NAMES[TILE_NAMES.index("sip") + 1] == "wifi"
    assert '<a class="tile half" data-view="sip" href="#sip" style="--accent: var(--sand)">' in html
    assert '<span class="tile-icon" data-icon="sip"></span><span class="tile-title">SIP</span>' in html
    assert '<div class="tile-body" id="tile-sip">' in html
    assert html.index('data-view="faults"') < html.index('data-view="sip"') < html.index('data-view="wifi"')
    # the scripts load in dependency order, which is not the tile order and never was
    assert html.index("js/views/proav.js") < html.index("js/views/sip.js") < html.index("js/app.js")


def test_app_js_knows_the_eleventh_tile():
    app = _read("js/app.js")
    for needle in ("sip: 'var(--sand)'", "'proav', 'sip'];", "const el = tileEls.sip", "TNT.views.sip"):
        assert needle in app, needle
    icons = re.search(r"const ICONS = \{(.*?)\n  \};", app, re.S).group(1)
    assert re.search(r"\n    sip: '<svg ' \+ S \+ '>", icons), "the icon is a real entry, not a fallback"


def test_the_sand_accent_is_defined_in_both_themes_and_is_nobody_elses():
    """The palette's ten accents were all spent, so SIP needed an eleventh hue rather than a second
    use of one - and Faults a twelfth after it. Every tile's accent is still its own."""
    css = _read("css/tnt.css")
    light = re.search(r":root\s*\{(.*?)\}", css, re.S).group(1)
    assert re.search(r"--sand:\s*#[0-9A-Fa-f]{6};", light)
    assert len(re.findall(r"--sand:\s*#[0-9A-Fa-f]{6};", css)) >= 2, "the dark theme redefines it too"
    app = _read("js/app.js")
    # ACCENT is keyed by view name and written in its own order, which is not the tile order:
    # assert what it maps, not where each entry happens to sit
    pairs = re.findall(r"(\w+): 'var\(--(\w+)\)'", re.search(r"const ACCENT = \{(.*?)\};", app, re.S).group(1))
    accent = dict(pairs)
    assert sorted(accent) == sorted(TILE_NAMES), sorted(accent)
    assert len(accent) == len(set(accent.values())) == 12, accent
    assert accent["sip"] == "sand" and accent["faults"] == "rust"
    # the twelfth is defined the same way: a hue of its own, in both themes
    assert re.search(r"--rust:\s*#[0-9A-Fa-f]{6};", light)
    assert len(re.findall(r"--rust:\s*#[0-9A-Fa-f]{6};", css)) >= 2, "the dark theme redefines it too"


def test_the_page_has_its_own_styles():
    css = _read("css/tnt.css")
    assert "/* ---------- SIP (views/sip.js) ---------- */" in css
    for selector in (".sip-page", ".sip-leg", ".sip-findings", ".sip-ladder-row", ".sip-headers", ".sip-call"):
        assert _css_decls(css, selector), selector
    # every ladder colour is a theme token, so the flow reads in either theme
    for cls in ("req", "prog", "ok", "redirect", "fail", "end"):
        decls = _css_decls(css, ".sip-ladder-row." + cls)
        assert decls and "var(--" in decls.get("border-left-color", ""), cls


def test_the_speed_page_gave_up_the_call_lines_and_kept_the_bufferbloat_grade():
    """The move is the point: somebody asking about calls looks at the SIP page, and the bufferbloat grade stays
    where the measurement is made."""
    speed = _read("js/views/speed.js")
    assert "quality-call" not in speed and "CHECK_NAMES" not in speed
    assert "bufferbloat" in speed and "GRADE_CLASS" in speed
    sip = _read("js/views/sip.js")
    assert "callQualityView" in sip and "Zoom" in sip and "Teams" in sip


# ---------------------------------------------------------------------------
# the page's pure views, under node
# ---------------------------------------------------------------------------
_DRIVER = r"""
load(process.argv[2]);
process.stdout.write(JSON.stringify(input.map(([fn, arg]) => T.views.sip[fn](arg))));
"""


def _run(tmp_path: Path, cases: List[Any]) -> Any:
    return _node(tmp_path, _DRIVER, ["js/views/sip.js"], cases)


@NODE
def test_the_findings_list_is_worst_first_and_drops_what_it_cannot_label(tmp_path):
    findings = [{"id": "a", "level": "good", "title": "fine", "detail": None, "advice": None, "evidence": None},
                {"id": "b", "level": "bad", "title": "broken", "detail": "d", "advice": "do this", "evidence": None},
                {"id": "c", "level": "info", "title": "note", "detail": None, "advice": None, "evidence": None},
                {"id": "d", "level": "warn", "title": "hm", "detail": None, "advice": None, "evidence": None},
                {"id": "e", "level": "nonsense", "title": "from a newer service", "detail": None, "advice": None}]
    out = _run(tmp_path, [["findingViews", findings]])[0]
    assert [f["level"] for f in out] == ["bad", "warn", "info", "good"], "worst first"
    assert [f["what"] for f in out] == ["Problem", "Worth checking", "Note", "Good"]
    assert all(f["title"] != "from a newer service" for f in out), "a level TNT cannot label is left out"


@NODE
def test_an_ungraded_leg_shows_its_reason_instead_of_numbers(tmp_path):
    """An ungraded leg must not look like a graded one: that is the whole reason the service refuses to grade it."""
    graded = {"kind": "lan", "label": "The LAN leg (gateway)", "target": "gateway", "grade": "excellent",
              "mos": 4.4, "r": 92.0, "call_label": "excellent", "avg_ms": 3.4, "jitter_ms": 0.6,
              "loss_pct": 0.0, "p95_ms": 6.1, "samples": 1380, "window_h": 24, "reason": None}
    thin = dict(graded, grade="unknown", mos=None, r=None, call_label=None, avg_ms=None, jitter_ms=None,
                loss_pct=None, samples=4, reason="only 4 ping(s) of history on this network")
    out = _run(tmp_path, [["legView", graded], ["legView", thin]])
    assert out[0]["numbers"] == "3.4 ms · ± 0.6 ms · 0 % loss" and out[0]["cls"] == "green"
    assert out[0]["mos"] == "MOS 4.40 (excellent)"
    assert out[1]["numbers"] == "" and out[1]["cls"] == "grey"
    assert "only 4 ping" in out[1]["reason"]


@NODE
def test_the_call_quality_lines_the_speed_page_handed_over(tmp_path):
    """The same content the Speed page used to show, on the page somebody asking about calls actually opens."""
    call = {"method": "estimate", "idle": {"r": 92.35, "mos": 4.39, "label": "Excellent"},
            "loaded": {"r": 80.1, "mos": 3.87, "label": "Fair"},
            "checks": [{"key": "zoom", "ok": True, "detail": "mean 52 ms"},
                       {"key": "teams", "ok": False, "detail": "loss 2.9% is 1% or more"}]}
    last = {"ok": True, "quality": {"available": True, "call": call}}
    out = _run(tmp_path, [["callQualityView", last],
                          ["callQualityView", {"ok": False}],
                          ["callQualityView", {"ok": True}],
                          ["callQualityView", None]])
    assert out[0]["idle"] == "Excellent (MOS 4.39)" and out[0]["busy"] == "Fair (MOS 3.87)"
    assert [c["label"] for c in out[0]["checks"]] == ["Zoom ✓", "Teams ✗"]
    assert [c["ok"] for c in out[0]["checks"]] == [True, False]
    assert out[0]["checks"][1]["title"] == "loss 2.9% is 1% or more"
    assert (out[1]["state"], out[2]["state"], out[3]["state"]) == ("failed", "missing", "none")
    assert all(not v["idle"] and not v["checks"] for v in out[1:]), "nothing is invented without a measurement"


@NODE
def test_a_ladder_row_is_coloured_by_what_it_is(tmp_path):
    rows = [{"kind": "request", "method": "INVITE", "status": None, "rel": 0.0, "where": 1},
            {"kind": "request", "method": "BYE", "status": None, "rel": 13.6, "where": 2},
            {"kind": "response", "method": None, "status": 100, "rel": 0.3, "where": 3},
            {"kind": "response", "method": None, "status": 200, "rel": 2.6, "where": 4},
            {"kind": "response", "method": None, "status": 302, "rel": 2.7, "where": 5},
            {"kind": "response", "method": None, "status": 486, "rel": 2.8, "where": 6}]
    out = _run(tmp_path, [["ladderView", r] for r in rows])
    assert [r["cls"] for r in out] == ["req", "end", "prog", "ok", "redirect", "fail"]
    assert out[0]["rel"] == "0.00 s" and out[1]["rel"] == "13.60 s"


@NODE
def test_a_call_seen_from_both_sides_says_so(tmp_path):
    one = {"id": "c1", "call_ids": ["x@a"], "from_uri": "sip:2001@pbx", "to_uri": "sip:2002@pbx", "state": "ended",
           "status": 200, "start_ts": 1.0, "answer_ts": 2.0, "end_ts": 13.0, "duration_s": 12.0, "sides": ["a"],
           "matched_by": "single", "ladder": [], "streams": [], "findings": [], "note": None}
    both = dict(one, sides=["a", "b"], matched_by="call-id",
                findings=[{"id": "flow.rewritten", "level": "bad", "title": "Contact rewritten", "detail": None,
                           "advice": None, "evidence": None}],
                streams=[{"id": "s1", "decodable": True, "codec": "PCMU/8000"}])
    out = _run(tmp_path, [["flowCallView", one], ["flowCallView", both]])
    assert out[0]["bothSides"] is False and out[0]["playable"] is False
    assert out[1]["bothSides"] is True and out[1]["sides"] == "a + b" and out[1]["matched"] == "call-id"
    assert out[1]["worst"]["cls"] == "red" and out[1]["playable"] is True


# ---------------------------------------------------------------------------
# the mock's hand-written data against the service's real shapes
# ---------------------------------------------------------------------------
def test_the_mock_rating_is_the_shape_the_qualifier_really_returns(mock):
    rating = mock.state.sip_qualifier(24.0, None)
    assert tuple(rating) == sipqual.QUALIFIER_KEYS
    assert tuple(rating["headline"]) == sipqual.HEADLINE_KEYS
    for leg in rating["legs"]:
        assert tuple(leg) == sipqual.LEG_KEYS
        assert leg["kind"] in sipqual.LEG_KINDS and leg["grade"] in sipqual.GRADES
    for finding in rating["findings"]:
        assert tuple(finding) == sipqual.FINDING_KEYS and finding["id"] in sipqual.FINDING_IDS
    assert rating["verdict"] in sipqual.GRADES


def test_the_mock_grades_and_headline_agree_with_the_service(mock):
    """The mock re-implements the E-model and the headline rule because it never imports tnt. Only this notices
    when the two drift, and a page built against a mock that disagrees with the service is built against fiction."""
    for avg, jitter, loss in ((3.4, 0.6, 0.0), (21.0, 3.1, 0.05), (148.0, 44.0, 3.6), (900.0, 200.0, 40.0)):
        leg = mock.state._sip_leg("wan", "x", "1.1.1.1", avg, jitter, loss, 600, 24)
        real = sipqual.grade_leg({"samples": 600, "lost": 0, "loss_pct": round(loss, 2), "avg_ms": round(avg, 1),
                                  "min_ms": avg, "max_ms": avg, "p95_ms": avg, "jitter_ms": round(jitter, 1)},
                                 kind="wan", label="x")
        assert leg["grade"] == real["grade"], (avg, jitter, loss)
        assert leg["mos"] == real["mos"] and leg["r"] == real["r"], (avg, jitter, loss)
    # and the headline rule: worst grade, then lowest MOS, then slowest
    cases = [
        [mock.state._sip_leg("lan", "lan", "gateway", 3.4, 0.6, 0.0, 600, 24),
         mock.state._sip_leg("wan", "wan", "1.1.1.1", 21.0, 3.1, 0.05, 600, 24)],
        [mock.state._sip_leg("lan", "lan", "gateway", 4.0, 1.0, 0.0, 600, 24),
         mock.state._sip_leg("wan", "wan", "1.1.1.1", 300.0, 55.0, 2.0, 600, 24)],
        [mock.state._sip_leg("wan", "wan", "1.1.1.1", 90.0, 15.0, 0.4, 600, 24)],
    ]
    for legs in cases:
        mine = mock.mod.sip_headline(legs)
        real = sipqual.headline(legs)
        assert tuple(mine) == tuple(real) == sipqual.HEADLINE_KEYS
        assert (mine["leg"], mine["mos"], mine["avg_ms"]) == (real["leg"], real["mos"], real["avg_ms"]), legs


def test_the_mock_alg_stun_and_flow_are_the_shapes_the_service_returns(mock):
    alg = mock.state.sip_alg_run("pbx.example.net", 5060)
    assert tuple(alg) == sipalg.ALG_KEYS and alg["verdict"] in sipalg.VERDICTS
    assert all(tuple(p) == sipalg.PROBE_KEYS for p in alg["probes"])
    assert all(tuple(c) == sipalg.CHANGE_KEYS for c in alg["changes"])

    stun = mock.state.sip_stun_run(None)
    assert tuple(stun) == sipnat.STUN_KEYS and stun["mapping"] in sipnat.MAPPINGS
    assert all(tuple(s) == sipnat.SERVER_KEYS for s in stun["servers"])
    life = mock.state.sip_stun_lifetime(None)
    assert tuple(life) == sipnat.LIFETIME_KEYS

    mock.state.sip_flow_open(r"C:\Captures\client-side.pcapng", "a")
    mock.state.sip_flow_open(r"C:\Captures\server-side.pcapng", "b")
    flow = mock.state.sip_flow_view()
    assert tuple(flow) == sipflow.FLOW_KEYS
    assert all(tuple(s) == sipflow.SOURCE_KEYS for s in flow["sources"])
    assert tuple(flow["skew"]) == sipflow.SKEW_KEYS
    call = flow["calls"][0]
    assert tuple(call) == sipflow.FLOWCALL_KEYS
    assert all(tuple(r) == sipflow.LADDER_KEYS for r in call["ladder"])
    row = next(r for r in call["ladder"] if r["has_sdp"])
    assert tuple(mock.state.sip_flow_headers(row["side"], row["where"])) == sipcalls.HEADER_VIEW_KEYS


def test_the_mock_tile_is_the_shape_the_home_page_reads(mock):
    tile = mock.state.sip_tile()
    assert tuple(tile) == sipqual.TILE_KEYS + ("alg", "nat")
    assert (tile["mos"], tile["avg_ms"], tile["jitter_ms"]) != (None, None, None), "the three headline numbers"
    assert mock.state.status()["sip"]["verdict"] in sipqual.GRADES


# ---------------------------------------------------------------------------
# the page in a headless browser
# ---------------------------------------------------------------------------
_SIP_PROBE = r"""<!doctype html><html><head><meta charset="utf-8"><title>sip probe</title></head><body style="margin:0">
<pre id="probe">pending</pre>
<iframe id="app" src="/index.html#sip" style="width:1280px;height:900px;border:0;display:block"></iframe>
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
function text(doc) { return doc.querySelector('#view').textContent; }
(async () => {
  const doc = await until(() => frame.contentDocument && frame.contentDocument.querySelector('.sip-page')
    && frame.contentDocument, 12000);
  if (!doc) { document.getElementById('probe').textContent = JSON.stringify({error: 'the page never mounted'}); return; }
  const win = frame.contentWindow;
  out.errors = JSON.stringify(win.__mockErrors || []);
  // the rating arrives on its own
  await until(() => doc.querySelectorAll('.sip-leg').length >= 2, 8000);
  out.legs = Array.from(doc.querySelectorAll('.sip-leg')).map((el) => el.textContent.replace(/\s+/g, ' ').trim());
  out.verdictChip = doc.querySelector('.sip-card .badge.lg').textContent;
  // the three numbers, first thing under the host field
  const hl = doc.querySelector('.sip-headline');
  out.headline = hl ? { values: Array.from(hl.querySelectorAll('.sip-hl-value')).map((e) => e.textContent.trim()),
                        what: Array.from(hl.querySelectorAll('.sip-hl-what')).map((e) => e.textContent.trim()),
                        from: hl.querySelector('.sip-hl-from').textContent.replace(/\s+/g, ' ').trim(),
                        beforeLegs: !!(doc.querySelector('.sip-legs')
                          && (hl.compareDocumentPosition(doc.querySelector('.sip-legs')) & 4)) } : null;
  out.capacityGone = !doc.querySelector('.sip-capacity');
  out.callQuality = !!doc.querySelector('.sip-callq');
  out.findingIds = Array.from(doc.querySelectorAll('.sip-finding')).length;

  const inputs = Array.from(doc.querySelectorAll('#view input'));
  const buttons = Array.from(doc.querySelectorAll('#view button'));
  const set = (el, v) => { el.value = v; el.dispatchEvent(new Event('input', {bubbles: true}));
                           el.dispatchEvent(new Event('change', {bubbles: true})); };
  const press = (label) => buttons.find((b) => b.textContent.trim() === label).click();

  set(inputs[1], 'pbx.example.net');
  press('Check');
  await until(() => doc.querySelector('.sip-change'), 8000);
  out.alg = doc.querySelectorAll('.sip-change').length;
  out.algVerdict = doc.querySelectorAll('.sip-card .badge.lg')[1].textContent;

  press('Test');
  await until(() => doc.querySelectorAll('.sip-stun-server').length >= 2, 8000);
  out.stunServers = Array.from(doc.querySelectorAll('.sip-stun-server code')).map((c) => c.textContent);
  out.stunVerdict = doc.querySelectorAll('.sip-card .badge.lg')[2].textContent;

  set(inputs[3], 'C:\\Captures\\client-side.pcapng');
  set(inputs[4], 'C:\\Captures\\server-side.pcapng');
  const loads = buttons.filter((b) => b.textContent.trim() === 'Load');
  loads[0].click();
  await until(() => doc.querySelector('.sip-call'), 8000);
  out.callsAfterOne = doc.querySelectorAll('.sip-call').length;
  out.skewAfterOne = !!doc.querySelector('.sip-skew');
  loads[1].click();
  await until(() => doc.querySelector('.sip-skew'), 8000);
  out.skew = doc.querySelector('.sip-skew') ? doc.querySelector('.sip-skew').textContent.trim() : '';

  doc.querySelector('.sip-call').click();
  const ladder = await until(() => (doc.querySelectorAll('.sip-ladder-row').length ? doc : null), 8000);
  out.ladder = ladder ? Array.from(doc.querySelectorAll('.sip-ladder-row')).map(
    (r) => r.textContent.replace(/\s+/g, ' ').trim()) : [];
  out.streams = doc.querySelectorAll('.sip-stream').length;
  out.audioButtons = Array.from(doc.querySelectorAll('.sip-stream-actions button')).map(
    (b) => b.textContent.replace(/\s+/g, ' ').trim());
  // the whole call first, the way the Packet capture page offers it
  const listen = Array.from(doc.querySelectorAll('.sip-stream-actions button')).find(
    (b) => b.textContent.includes('Listen to the call'));
  listen.click();
  out.player = !!(await until(() => doc.querySelector('.sip-stream-player audio'), 8000));

  const sdpRow = Array.from(doc.querySelectorAll('.sip-ladder-row')).find((r) => r.textContent.includes('SDP'));
  sdpRow.click();
  const pk = await until(() => doc.querySelector('.sip-packet'), 8000);
  out.packetStart = pk ? pk.querySelector('.sip-packet-start').textContent : '';
  out.headers = pk ? Array.from(pk.querySelectorAll('.sip-header-name')).map((el) => el.textContent) : [];
  out.sdpBody = !!(pk && pk.querySelector('.sip-packet-body'));
  out.errorsAfter = JSON.stringify(win.__mockErrors || []);
  document.getElementById('probe').textContent = JSON.stringify(out);
})();
</script></body></html>
"""


def test_the_page_answers_all_four_questions_in_a_browser(browser_page, mock, monkeypatch):
    """The tech's whole pass over the page: read the rating, check the ALG, test the NAT, load two captures, open a
    call and open a packet in it."""
    _serve_probe(mock, monkeypatch, "sip-probe.html", _SIP_PROBE)
    res = _probe_result(browser_page("sip-probe.html", budget_ms=30000, size=(1280, 900)))
    assert "error" not in res, res

    # the rating, from the ping history the fake site has been collecting: one leg per monitored target, LAN first
    assert len(res["legs"]) == 3, res["legs"]
    assert "LAN" in res["legs"][0] and "gateway" in res["legs"][0]
    assert "Internet" in res["legs"][1] and "1.1.1.1" in res["legs"][1]
    assert "Internet" in res["legs"][2] and "totalelectronics.com" in res["legs"][2]
    assert res["verdictChip"].strip().lower() in ("excellent", "good", "fair", "poor", "bad", "not rated")
    assert res["callQuality"] is True, "the call-quality lines the Speed page handed over"

    # the three numbers a call is judged by, first and biggest, above the legs they came from
    assert res["capacityGone"] is True, "the simultaneous-calls figure is gone"
    hl = res["headline"]
    assert hl and hl["what"] == ["MOS", "Delay", "Jitter"], hl
    assert hl["beforeLegs"] is True, "the headline comes before the legs, under the host field"
    assert re.fullmatch(r"\d\.\d\d", hl["values"][0]), hl["values"]
    assert all(re.fullmatch(r"[\d.]+ ?m?s?", v) for v in hl["values"][1:]), hl["values"]
    assert "leg" in hl["from"] and "pings" in hl["from"], hl["from"]
    assert res["findingIds"] >= 3

    # the ALG check: the fake network rewrites SIP, and the page shows what came back different
    assert res["algVerdict"].strip() == "alg"
    assert res["alg"] >= 2, "the rewritten headers are listed one by one"

    # STUN: two different external ports from one socket is the one-way-audio NAT
    assert res["stunVerdict"].strip() == "address-dependent"
    ports = [row.rsplit(":", 1)[1] for row in res["stunServers"]]
    assert len(ports) == 2 and ports[0] != ports[1], res["stunServers"]

    # one capture is a call on its own; the second adds the other side and a measured skew
    assert res["callsAfterOne"] == 1 and res["skewAfterOne"] is False
    assert "clocks differ" in res["skew"], res["skew"]

    # the ladder, and a packet out of it
    assert len(res["ladder"]) >= 10, res["ladder"]
    assert any("INVITE" in row for row in res["ladder"]) and any("200 OK" in row for row in res["ladder"])
    assert res["streams"] >= 3, "the whole call, then each direction on its own"
    assert res["audioButtons"][0] == "Listen to the call", res["audioButtons"]
    assert res["player"] is True, "the rebuilt WAV plays in the page"
    assert res["audioButtons"].count("Listen") >= 2, "and each direction has its own, which is how one-way audio is heard"
    assert res["packetStart"].startswith("INVITE "), res["packetStart"]
    assert "Call-ID" in res["headers"] and "Via" in res["headers"] and "CSeq" in res["headers"]
    assert res["sdpBody"] is True, "the INVITE's SDP is shown, which is where the audio addresses are agreed"
    assert res["errorsAfter"] == "[]", res["errorsAfter"]


def _sip_tile_text(dom: str) -> str:
    body = re.search(r'<div class="tile-body" id="tile-sip"[^>]*>(.*?)</a>', dom, re.S)
    assert body, "the SIP tile has no body"
    return re.sub(r"<[^>]+>", " ", body.group(1))


def test_the_tile_is_the_grade_and_the_three_numbers(browser_page):
    """Nothing else. The grade and MOS / delay / jitter are what a glance is for; which leg was
    weakest is on the SIP page, where there is room to act on it."""
    dom = browser_page("#sip")
    assert 'data-mock-errors="[]"' in dom
    text = _sip_tile_text(dom)
    assert re.search(r"excellent|good|fair|poor|bad|not rated", text), text
    # the three numbers, not a call count
    assert "MOS" in text and " ms " in text and "jit" in text, text
    assert "call" not in text.replace("calls page", ""), text


@pytest.mark.parametrize("verdict, weakest", [("fair", "lan"), ("poor", "wan"), ("bad", "sip")])
def test_a_verdict_below_excellent_still_names_no_leg(browser_page, mock, monkeypatch, verdict, weakest):
    """The regression this replaces: the tile used to append "the LAN leg" (or the internet leg, or
    the trunk) beside any verdict that was not excellent.

    The mock grades everything excellent, so that branch never ran in a test or on the dev server -
    it only showed up on a real machine whose line was not perfect. Here the tile is driven through
    each of the three legs instead.
    """
    real = mock.state.sip_tile

    def graded() -> Dict[str, Any]:
        tile = dict(real())
        tile.update(verdict=verdict, lan=None, wan=None, sip=None)
        tile[weakest] = verdict
        return tile

    monkeypatch.setattr(mock.state, "sip_tile", graded)
    text = _sip_tile_text(browser_page("#sip"))
    assert verdict in text, text
    for leg in ("LAN leg", "internet leg", "trunk", "leg"):
        assert leg not in text, f"{leg!r} is back on the tile: {text!r}"
    # and the numbers are still there, which is the half of the tile that stayed
    assert "MOS" in text and "jit" in text, text


def test_the_tile_renderer_has_no_leg_wording_left():
    """The source check that survives the mock grading everything excellent."""
    app = _read("js/app.js")
    tile = app[app.index("      const el = tileEls.sip;"):app.index("  function syncTools()")]
    for phrase in ("the LAN leg", "the internet leg", "the trunk", "WHERE"):
        assert phrase not in tile, phrase


def test_the_mock_offers_the_one_capture_alg_tell_and_drops_it_with_two(mock):
    """The fake network has a SIP ALG, so one capture from it shows what one capture can see. Two do not: they
    prove the rewrite outright, and an inference beside proof reads as a second, weaker finding."""
    mock.state.sip_flow_open(r"C:\Captures\client-side.pcapng", "a")
    one = {f["id"] for f in mock.state.sip_flow_view()["findings"]}
    assert "alg.contact" in one and "flow.rewritten" not in one
    assert set(one) <= set(sipflow.FINDING_IDS), one
    mock.state.sip_flow_open(r"C:\Captures\server-side.pcapng", "b")
    two = {f["id"] for f in mock.state.sip_flow_view()["findings"]}
    assert "flow.rewritten" in two and "alg.contact" not in two
    assert set(two) <= set(sipflow.FINDING_IDS), two


# ---------------------------------------------------------------------------
# picking a capture off disk
# ---------------------------------------------------------------------------
def test_the_page_uses_the_same_file_picker_bridge_the_capture_page_does():
    """One dialog, one definition: client/tray.py's pick_capture_file serves both pages."""
    sip = _read("js/views/sip.js")
    capture = _read("js/views/capture.js")
    for text in sip, capture:
        assert "window.pywebview.api.pick_capture_file" in text
    assert "function hasPicker()" in sip
    tray = (ROOT / "client" / "tray.py").read_text(encoding="utf-8")
    assert tray.count("def pick_capture_file") == 1, "the SIP page must not have grown a second one"
    assert "SIP page" in tray.split("def pick_capture_file")[1].split('"""')[1]


def test_the_slot_row_has_its_own_styles():
    css = _read("css/tnt.css")
    for selector in (".sip-slot", ".sip-slot-label", ".sip-slot-row"):
        assert _css_decls(css, selector), selector


_PICKER_PROBE = r"""<!doctype html><html><head><meta charset="utf-8"><title>sip picker probe</title></head><body style="margin:0">
<pre id="probe">pending</pre>
<iframe id="app" src="/index.html#sip" style="width:1280px;height:900px;border:0;display:block"></iframe>
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
(async () => {
  // the TNT window's bridge, installed before the page mounts so hasPicker() sees it
  const win = await until(() => (frame.contentWindow && frame.contentWindow.TNT ? frame.contentWindow : null), 12000);
  if (!win) { document.getElementById('probe').textContent = JSON.stringify({error: 'no window'}); return; }
  out.asked = 0;
  win.pywebview = { api: { pick_capture_file: () => { out.asked++;
    return Promise.resolve(out.asked === 1 ? 'C:\\Captures\\client-side.pcapng' : 'C:\\Captures\\server-side.pcapng'); } } };
  win.location.hash = '#ping';
  await sleep(120);
  win.location.hash = '#sip';                      // remount, now that the bridge is there
  const doc = await until(() => (frame.contentDocument && frame.contentDocument.querySelector('.sip-slot')
    ? frame.contentDocument : null), 12000);
  if (!doc) { document.getElementById('probe').textContent = JSON.stringify({error: 'the page never mounted'}); return; }
  const browse = () => Array.from(doc.querySelectorAll('.sip-slot-row button')).filter(
    (b) => /Browse|Replace/.test(b.textContent));
  out.pathInputs = doc.querySelectorAll('.sip-slot-row input').length;
  out.buttons = browse().map((b) => b.textContent.replace(/\s+/g, ' ').trim());

  // what the picker handed over goes to the service untouched: a path mangled on the way is the failure this
  // whole feature exists to avoid, and it would otherwise show up only as "no calls"
  win.__flowErr = '';
  const realOpen = win.TNT.api.sipFlowOpen;
  win.TNT.api.sipFlowOpen = (p, sl) => realOpen(p, sl).catch((e) => {
    win.__flowErr = String(p) + ' -> ' + ((e && e.message) || e); throw e; });
  browse()[0].click();                              // no typing at all
  await until(() => doc.querySelector('.sip-call'), 8000);
  out.flowErr = win.__flowErr;
  out.afterOne = { calls: doc.querySelectorAll('.sip-call').length,
                   loaded: doc.querySelector('.sip-loaded').textContent.trim(),
                   labels: browse().map((b) => b.textContent.replace(/\s+/g, ' ').trim()) };
  browse()[1].click();
  await until(() => doc.querySelector('.sip-skew'), 8000);
  out.afterTwo = { sources: doc.querySelectorAll('.sip-loaded').length,
                   skew: !!doc.querySelector('.sip-skew') };
  out.errors = JSON.stringify(win.__mockErrors || []);
  document.getElementById('probe').textContent = JSON.stringify(out);
})();
</script></body></html>
"""


def test_browse_picks_a_capture_with_nothing_typed_in_a_browser(browser_page, mock, monkeypatch):
    """The TNT window's picker hands back a path and the slot loads from it: no path field, no typing, no Load."""
    _serve_probe(mock, monkeypatch, "sip-picker-probe.html", _PICKER_PROBE)
    res = _probe_result(browser_page("sip-picker-probe.html", budget_ms=30000, size=(1280, 900)))
    assert "error" not in res, res
    assert res["pathInputs"] == 0, "with a picker there is nothing to type into"
    assert res["buttons"] == ["Browse…", "Browse…"], res["buttons"]
    assert res["asked"] >= 1, "the bridge was the thing that was asked"
    assert res.get("flowErr") == "", "the path the picker gave went to the service untouched"
    assert res["afterOne"]["calls"] == 1
    assert "client-side.pcapng" in res["afterOne"]["loaded"], res["afterOne"]
    # a loaded slot says the button swaps it rather than adding a third capture
    assert res["afterOne"]["labels"][0] == "Replace…", res["afterOne"]["labels"]
    assert res["afterOne"]["labels"][1] == "Browse…", res["afterOne"]["labels"]
    assert res["afterTwo"]["skew"] is True, "the second slot merged, so the clocks were lined up"
    assert res["errors"] == "[]", res["errors"]


def test_a_plain_browser_tab_falls_back_to_a_typed_path(browser_page):
    """There is no native picker in a browser tab, and the page says so rather than showing a button that cannot
    work. The headless browser has no bridge, so this is what every other test here has been exercising."""
    dom = browser_page("#sip")
    assert 'data-mock-errors="[]"' in dom
    assert dom.count('class="sip-slot"') == 2
    assert "cannot open this PC" in dom and "Browse button instead" in dom
    # the browse buttons are there but hidden, exactly as the Packet capture page hides its own
    assert len(re.findall(r'<button[^>]*hidden=""[^>]*>(?:(?!</button>).)*Browse', dom, re.S)) == 2, dom[:0]
