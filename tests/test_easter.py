"""The dynamite easter egg: machine-wide detonation counter routes, the UI wiring, and where the explosion lands."""
import http.client
import json
import re
from pathlib import Path

import pytest

from tnt.api import server as api_server
from tnt.db import Database
# the shared mock server, headless browser and probe helpers
from tests.test_ui import _probe_result, _serve_probe, browser_page, mock  # noqa: F401

ROOT = Path(__file__).resolve().parent.parent


class _Engine:
    version = "0.0-test"
    bus = None

    def __init__(self, db):
        self.db = db


def _req(port, method, path, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Host": f"127.0.0.1:{port}"}
    if data:
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    payload = resp.read()
    conn.close()
    return resp.status, (json.loads(payload) if payload else None)


@pytest.fixture
def served(tmp_path):
    db = Database(tmp_path / "t.db")
    srv = api_server.ApiServer(_Engine(db), "127.0.0.1", 0)
    srv.start()
    try:
        yield srv.port, db
    finally:
        srv.stop(timeout=3)
        db.close()


def test_easter_counter_persists_and_validates(served):
    port, db = served
    assert _req(port, "GET", "/api/easter") == (200, {"detonated": 0, "max_sticks": 100})
    status, body = _req(port, "POST", "/api/easter/detonate", {"sticks": 3})
    assert status == 200 and body["detonated"] == 3 and body["added"] == 3
    status, body = _req(port, "POST", "/api/easter/detonate")          # empty body -> one stick
    assert status == 200 and body["detonated"] == 4
    status, body = _req(port, "POST", "/api/easter/detonate", {"sticks": 100})
    assert status == 200 and body["detonated"] == 104
    for bad in ({"sticks": 0}, {"sticks": 101}, {"sticks": "boom"}, {"sticks": True}, {"sticks": 2.5e400}):
        status, body = _req(port, "POST", "/api/easter/detonate", bad)
        assert status == 400, bad
    assert db.get_meta("easter_detonated") == "104"                     # survives a restart: it is in the db
    assert _req(port, "GET", "/api/easter")[1]["detonated"] == 104


def test_easter_ui_wiring():
    html = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
    assert '<script src="js/egg.js"></script>' in html
    assert html.index("js/egg.js") < html.index("js/app.js")
    egg = (ROOT / "ui" / "js" / "egg.js").read_text(encoding="utf-8")
    assert "MAX_STICKS = 100" in egg and "FUSE_MS = 5000" in egg
    assert "#brand-logo" in egg and "e.preventDefault()" in egg          # the logo click must not navigate
    assert "getTotalLength" in egg and "strokeDashoffset" in egg          # one fuse that burns down
    assert "TNT.api.detonate" in egg and "TNT.api.easter" in egg
    assert "brand-count" in egg
    api = (ROOT / "ui" / "js" / "api.js").read_text(encoding="utf-8")
    assert "'/easter/detonate'" in api
    css = (ROOT / "ui" / "css" / "tnt.css").read_text(encoding="utf-8")
    for sel in (".brand-count", ".egg-overlay", ".egg-stick", ".egg-fuse-path", ".egg-burst", ".egg-word", "body.egg-shake"):
        assert sel in css, sel
    # the tiny counter is absolutely positioned so it never shifts the header
    m = re.search(r"\.brand-count\s*\{([^}]*)\}", css)
    assert m and "position: absolute" in m.group(1) and "font-size: 9px" in m.group(1)


def test_the_overlay_is_outside_the_element_the_shake_transforms():
    """The explosion shakes the page by animating a transform on <body>. An ancestor with any transform - the
    identity one the keyframes start on counts - becomes the containing block for a `position: fixed` descendant, so
    an overlay inside <body> stops being measured from the viewport the moment the shake starts and snaps to the top
    of the document. It lives on <html> instead."""
    egg = (ROOT / "ui" / "js" / "egg.js").read_text(encoding="utf-8")
    assert "document.documentElement.appendChild(overlay)" in egg
    assert "document.body.appendChild(overlay)" not in egg
    css = (ROOT / "ui" / "css" / "tnt.css").read_text(encoding="utf-8")
    assert "position: fixed" in re.search(r"\.egg-overlay\s*\{([^}]*)\}", css).group(1)
    assert "transform" in re.search(r"@keyframes egg-shake\s*\{(.*?)\}\s*$", css, re.S | re.M).group(1)


def test_a_minecraft_block_turns_up_about_once_in_a_hundred():
    egg = (ROOT / "ui" / "js" / "egg.js").read_text(encoding="utf-8")
    assert "const BLOCK_ODDS = 1 / 100;" in egg


_BOOM_PROBE = r"""<!doctype html><html><head><meta charset="utf-8"><title>boom probe</title></head><body style="margin:0">
<pre id="probe">pending</pre>
<iframe id="app" src="/index.html#capture" style="width:1280px;height:900px;border:0;display:block"></iframe>
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
async function run() {
  await until(() => frame.contentWindow && frame.contentWindow.TNT && frame.contentWindow.TNT.egg, 10000);
  const doc = frame.contentDocument, win = frame.contentWindow;
  await until(() => doc.querySelector('#view .card'), 8000);
  // the page has to be long enough to scroll: the bug only shows once the document is offset under the viewport
  doc.getElementById('view').style.minHeight = '2400px';
  win.scrollTo({ top: 1500 });
  await sleep(120);
  out.scrollY = Math.round(win.scrollY);
  out.innerHeight = win.innerHeight;
  out.want = Math.round(win.innerHeight * 0.55);          // PILE_Y: the pile sits here in the viewport
  win.TNT.egg.throwStick();
  win.TNT.egg.throwStick();
  await sleep(120);
  out.pile = Math.round(doc.querySelector('.egg-pile').getBoundingClientRect().top);
  out.overlayParent = doc.querySelector('.egg-overlay').parentElement.tagName;
  // the hazard itself, applied by hand so the test does not depend on where the shake animation happens to be:
  // any transform on <body> at all is enough to move a fixed descendant's containing block
  doc.body.style.transform = 'translate(2px, 2px)';
  win.TNT.egg.explodeNow();
  await sleep(120);
  const boom = doc.querySelector('.egg-boom');
  out.boom = boom ? Math.round(boom.getBoundingClientRect().top) : null;
  out.bodyTransform = win.getComputedStyle(doc.body).transform;
  out.errors = doc.documentElement.getAttribute('data-mock-errors');
  document.getElementById('probe').textContent = JSON.stringify(out);
}
run().catch((e) => {
  out.probeError = String((e && e.stack) || e);
  document.getElementById('probe').textContent = JSON.stringify(out);
});
</script></body></html>"""


def test_the_explosion_lands_on_the_pile_however_far_the_page_is_scrolled(browser_page, mock, monkeypatch):
    """Scrolled well down, with <body> transformed exactly as the shake transforms it: the pile and the boom both
    sit where the pile has always sat, 55 % down the viewport. Before the overlay moved to <html> the boom landed
    `scrollY` pixels higher - off the top of the screen on any page long enough to scroll."""
    _serve_probe(mock, monkeypatch, "boom-probe.html", _BOOM_PROBE)
    res = _probe_result(browser_page("boom-probe.html", budget_ms=20000, size=(1366, 960)))
    assert res.get("probeError") is None, res.get("probeError")
    assert res.get("errors") == "[]", res.get("errors")
    assert res["scrollY"] > 400, res                       # the page really did scroll
    assert res["bodyTransform"] not in (None, "none")      # the hazard was in place when the boom was measured
    # the symptom first: the boom sits on the pile, not res["want"] - res["scrollY"] up at the top of the document
    assert abs(res["pile"] - res["want"]) <= 2, res
    assert abs(res["boom"] - res["want"]) <= 2, res
    assert res["overlayParent"] == "HTML"                  # ... and the mechanism that keeps it there
