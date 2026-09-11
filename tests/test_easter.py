"""The dynamite easter egg: machine-wide detonation counter routes and the UI wiring."""
import http.client
import json
import re
from pathlib import Path

import pytest

from tnt.api import server as api_server
from tnt.db import Database

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
