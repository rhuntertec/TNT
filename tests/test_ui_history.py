"""Settings › History ("Clear history" with a time range) in the UI and the mock.

What is pinned here:

* the pure helpers of ui/js/api.js (``TNT.api.history``: the eight ranges, the refusal texts, the Wi-Fi plan, the one
  summary toast, the status line, a test the clear cancelled) and charts.js' ``hatchedSpans``, in a node vm with no DOM;
* the markup and CSS the contract names (the History group right after Updates, the Updates row as a ``.setting`` row,
  ``.setting-control > .btn { width: 100% }``), read from the source;
* tools/mock_api.py's mirror of ``POST /api/history/clear``, ``GET /api/history``, the timeline's ``cleared`` spans and
  the ``history.cleared`` event, over HTTP against a fresh MockState for every test (a clear changes everything);
* the real page in headless Chrome against the mock: Check now and Clear history… measured against the toggles and
  selects above them at 1366 px and stacked at 700 and 600 px, the confirm dialog, Cancel, the success toast with each Wi-Fi
  bridge shape (a fake ``window.pywebview.api`` injected by the probe), the refusals, the escaping of every service
  string, every window's refresh on ``history.cleared`` (only pages that show history mount again), a missed or
  unanswered clear caught up, and the Outages timeline's cleared spans.

browser_page refuses the event stream (a stream never ends and would stall the virtual clock), so a probe that needs an
event hands it to the page's own dispatcher, ``TNT.api.events._emit``, exactly as the stream's listener does. Offline:
the mock on 127.0.0.1, node and a headless browser only; nothing touches the real data folder.
"""
from __future__ import annotations

import http.client
import importlib
import json
import queue
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest

from test_ui import ROOT, UI, _doc, _read, _req, _serve_probe, _probe_result, browser_page, mock  # noqa: F401

NODE = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

# the contract's table: key, seconds (None = all time), label
CONTRACT_RANGES = [("5m", 300, "Last 5 minutes"), ("30m", 1800, "Last 30 minutes"), ("1h", 3600, "Last hour"),
                   ("6h", 21600, "Last 6 hours"), ("24h", 86400, "Last 24 hours"), ("7d", 604800, "Last 7 days"),
                   ("30d", 2592000, "Last 30 days"), ("all", None, "All time")]
CLEARED_KEYS = ["ping", "outages", "speed", "discovery", "captures", "faults", "sip", "proav"]
RESULT_KEYS = ["range", "label", "since_ts", "ts", "cleared", "stopped", "skipped"]
CROSS_SITE_HEADERS = ({"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"})


# ------------------------------------------------------------------------------------------------------ helpers
_PRELUDE = r"""
const fs = require('fs'), vm = require('vm');
const window = { TNT: { views: {}, util: {}, api: {}, ui: {} } };
const ctx = vm.createContext({ window, console, setTimeout, clearTimeout });
const load = (file) => vm.runInContext(fs.readFileSync(file, 'utf8'), ctx, { filename: file });
const input = JSON.parse(fs.readFileSync(process.argv[process.argv.length - 1], 'utf8'));
const T = window.TNT;
"""


def _node(tmp_path: Path, body: str, files: List[str], payload: Any = None) -> Any:
    """_PRELUDE + body under node with the UI files (relative to ui/) and a JSON payload; the driver prints one JSON value."""
    driver = tmp_path / "driver.js"
    driver.write_text(_PRELUDE + body, encoding="utf-8")
    data = tmp_path / "payload.json"
    data.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    r = subprocess.run(["node", str(driver)] + [str(UI / f) for f in files] + [str(data)],
                       capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _service(name: str, attr: str) -> Optional[Any]:
    """A constant of a service module when that module (and the constant) exists, else None: the service part of this
    feature is written alongside the UI, so the comparison runs wherever it is there."""
    try:
        mod = importlib.import_module(name)
    except Exception:          # not written yet in this checkout, or it does not import on its own
        return None
    return getattr(mod, attr, None)


@pytest.fixture()
def fresh(mock):
    """A MockState of its own for one test: a clear takes the seeded history with it, so no test may see another's."""
    old = mock.mod.STATE
    state = mock.mod.MockState(mock.port)
    mock.mod.STATE = state
    try:
        yield SimpleNamespace(mod=mock.mod, state=state, port=mock.port)
    finally:
        mock.mod.STATE = old


def _post(port: int, body: Any, headers: Optional[Dict[str, str]] = None, raw: Optional[bytes] = None) -> Tuple[int, Any]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        sent = {"Content-Type": "application/json", **(headers or {})}
        data = raw if raw is not None else json.dumps(body).encode()
        conn.request("POST", "/api/history/clear", body=data, headers=sent)
        resp = conn.getresponse()
        payload = resp.read()
        return resp.status, (json.loads(payload) if payload else None)
    finally:
        conn.close()


def _events(q: "queue.Queue[str]", kind: str) -> List[Any]:
    """The payloads of every `kind` frame queued so far."""
    out = []
    while True:
        try:
            frame = q.get_nowait()
        except queue.Empty:
            return out
        head, data = frame.split("\n")[0], frame.split("\n")[1]
        if head == "event: " + kind:
            out.append(json.loads(data[6:]))


# ---------------------------------------------------------------------------------------- pure helpers (node)
@NODE
def test_the_ui_offers_the_contracts_eight_ranges_like_the_service_and_the_mock(tmp_path, offline_mod):
    """The page draws the select before any request lands, so it keeps its own copy of tnt.history's ranges: the same
    eight keys in the same order, the same labels, Last hour first chosen. The mock's copy is the same table."""
    got = _node(tmp_path, "load(process.argv[2]); console.log(JSON.stringify({ r: T.api.history.RANGES, d: T.api.history.DEFAULT }));",
                ["js/api.js"])
    assert got["r"] == [[k, label] for k, _s, label in CONTRACT_RANGES]
    assert got["d"] == "1h"
    assert offline_mod.HISTORY_RANGES == {k: s for k, s, _l in CONTRACT_RANGES}
    assert list(offline_mod.HISTORY_RANGES) == [k for k, _s, _l in CONTRACT_RANGES]
    assert offline_mod.HISTORY_RANGE_LABELS == {k: label for k, _s, label in CONTRACT_RANGES}
    assert list(offline_mod.HISTORY_CLEARED_KEYS) == CLEARED_KEYS
    service = _service("tnt.history", "RANGES")
    if service is not None:
        assert list(service.items()) == [(k, s) for k, s, _l in CONTRACT_RANGES]
        labels = _service("tnt.history", "RANGE_LABELS")
        assert dict(labels) == {k: label for k, _s, label in CONTRACT_RANGES}


@pytest.fixture(scope="module")
def offline_mod():
    from test_ui import _load_mock
    return _load_mock()


_SUMMARY_DRIVER = r"""
load(process.argv[2]);
const H = T.api.history;
const out = {};
for (const [name, res, wifi] of input.cases) out[name] = H.summary(res, wifi);
out.phrases = ['5m', '1h', '24h', 'all'].map(H.phrase);
out.labels = ['7d', 'all', 'nope'].map(H.label);
console.log(JSON.stringify(out));
"""


@NODE
def test_the_summary_toast_names_what_went_what_stopped_and_what_was_left_alone(tmp_path):
    """One toast after a clear: a title with the range, one line of what went (plural or not, zero counts left out, the
    Wi-Fi outcome the page added), the fault watch restarting, the jobs the clear stopped and one line per skipped item.
    It is a warning only for the service's own skips or a bridge that failed: a browser tab that cannot reach Wi-Fi is
    expected and says so without turning the toast yellow."""
    full = {"range": "1h", "label": "Last hour", "since_ts": 1790000000.0, "ts": 1790003600.0,
            "cleared": {"ping": 57, "outages": 2, "speed": 1, "discovery": 0, "captures": 1, "faults": 1, "sip": 2, "proav": 0},
            "stopped": ["speed test", "discovery scan"],
            "skipped": [{"what": "captures", "reason": "TNT is not running as administrator, so its packet captures were left alone"}]}
    quiet = {"range": "5m", "label": "Last 5 minutes", "since_ts": 1.0, "ts": 301.0,
             "cleared": {k: 0 for k in CLEARED_KEYS}, "stopped": [], "skipped": []}
    cases = [
        ["full", full, {"state": "cleared", "points": 40, "aps": 2}],
        ["quiet_nobridge", quiet, {"state": "skipped", "reason": "no bridge here"}],
        ["one_each", dict(quiet, cleared=dict(quiet["cleared"], ping=1, outages=1, speed=1, discovery=1, captures=1, sip=1, proav=1, faults=1)),
         {"state": "cleared", "points": None, "aps": None}],
        ["wifi_failed", quiet, {"state": "failed", "reason": "the window said no"}],
        ["no_label", dict(quiet, label=None, range="7d"), None],
        # learned of later from GET /api/history's newest entry, which has no counts: it must not claim nothing went
        ["uncounted", {"range": "1h", "since_ts": 1.0, "ts": 3601.0}, {"state": "cleared", "points": 3, "aps": 0}],
        ["faults_only", dict(quiet, cleared=dict(quiet["cleared"], faults=1)), None],
    ]
    got = _node(tmp_path, _SUMMARY_DRIVER, ["js/api.js"], {"cases": cases})
    assert got["full"] == {"kind": "warn", "title": "History cleared: Last hour", "lines": [
        "Removed 57 minutes of ping history, 2 outages, 1 speed test, 1 packet capture, 2 SIP results, 40 Wi-Fi readings (2 access points gone).",
        "The fault watch starts again from now.",
        "Stopped: speed test, discovery scan.",
        "Left alone: captures - TNT is not running as administrator, so its packet captures were left alone."]}
    assert got["quiet_nobridge"] == {"kind": "ok", "title": "History cleared: Last 5 minutes", "lines": [
        "Nothing was recorded in that time.", "Left alone: Wi-Fi - no bridge here."]}
    assert got["one_each"]["lines"][0] == ("Removed 1 minute of ping history, 1 outage, 1 speed test, 1 discovery scan, 1 packet capture, "
                                           "1 SIP result, 1 Pro AV scan, the Wi-Fi survey.")
    assert got["one_each"]["kind"] == "ok"
    assert got["wifi_failed"]["kind"] == "warn" and got["wifi_failed"]["lines"][-1] == "Left alone: Wi-Fi - the window said no."
    assert got["no_label"]["title"] == "History cleared: Last 7 days"
    assert got["uncounted"]["lines"] == ["The clear finished while this window could not hear the service, so it cannot say what went.",
                                         "Removed 3 Wi-Fi readings."]
    assert got["faults_only"]["lines"] == ["Nothing was recorded in that time.", "The fault watch starts again from now."]
    assert got["phrases"] == ["in the last 5 minutes", "in the last hour", "in the last 24 hours", "ever"]
    assert got["labels"] == ["Last 7 days", "All time", "nope"]


_PLAN_DRIVER = r"""
load(process.argv[2]);
const H = T.api.history;
console.log(JSON.stringify({
  plans: input.plans.map(([res, bridge]) => H.wifiPlan(res, bridge)),
  results: input.results.map(H.wifiResult),
  errors: input.errors.map((e) => H.errorOutcome(e)),
  cancelled: input.done.map(H.cancelledTest),
  status: input.status.map((s) => H.statusText(s, 1000, (ts, now) => (now - ts) + ' s ago')),
  texts: H.WIFI_TEXT,
  missed: input.missed.map(([known, last, seen]) => H.missed(known === 'undef' ? undefined : known, last, seen)),
}));
"""


@NODE
def test_wifi_plan_errors_cancelled_tests_and_the_status_line_follow_the_contract(tmp_path):
    """The Wi-Fi survey lives in the TNT window, so the page asks the bridge: wifi_clear_since(since_ts) when it has it
    (null for All time), wifi_clear only for All time on an older window, and otherwise it is left alone with the reason.
    A 409 and a 400 are shown as the service words them; a speedtest.done the clear caused is recognised wherever the
    mark sits; the status line names the newest clear."""
    since = {"range": "1h", "since_ts": 1790000000.5}
    every = {"range": "all", "since_ts": None}
    full = {"wifi_clear_since": True, "wifi_clear": True, "wifi_survey": True}
    older = {"wifi_clear_since": False, "wifi_clear": True, "wifi_survey": True}
    bare = {"wifi_clear_since": False, "wifi_clear": False, "wifi_survey": False}
    payload = {
        # the last four: a range short of All time whose start is missing, null, a string or not finite keeps the whole
        # survey (the tolerant fallback must never widen a 5-minute clear into wiping every reading)
        "plans": [[since, full], [every, full], [every, older], [since, older], [since, None], [since, bare],
                  [{"range": "1h", "since_ts": "1790000000.5"}, full], [{"range": "5m", "since_ts": None}, older],
                  [{"range": "5m"}, full], [{"range": "30m", "since_ts": None}, full]],
        "results": [{"ok": True, "aps_dropped": 1, "points_dropped": 9}, {"ok": False, "error": "refused"}, None, {"ok": True}],
        "errors": [{"status": 409, "code": "full_scan_running", "message": "A Full Scan is running"},
                   {"status": 409, "code": "clear_running", "message": ""},
                   {"status": 400, "code": "bad_range", "message": "range must be one of: 5m"},
                   {"status": 404, "code": "http_404", "message": "Not Found"},
                   {"status": 0, "code": "network", "message": "Cannot reach the TNT service"},
                   {"status": 0, "code": "timeout", "message": "Request timed out"},
                   {"status": 500, "code": "http_500", "message": "database is locked"}],
        "done": [{"result": {"ok": False, "cancelled_by": "history"}}, {"cancelled_by": "history", "result": {"ok": False}},
                 {"result": {"ok": False, "error": "history cleared"}}, {"result": {"ok": False, "error": "timeout"}},
                 {"result": {"ok": True, "download_mbps": 90}}, None, {"cancelled": True, "cancelled_by": "history"},
                 # the service's own marks (tnt/speedtest/scheduler.py, tnt/engine.py): on the event, next to result;
                 # a discovery scan that finished while the clear ran is voided with cancelled still false
                 {"result": {"ok": True, "download_mbps": 90}, "trigger": "manual", "silent": True, "cancel_reason": "history cleared"},
                 {"run_id": None, "ok": True, "cancelled": False, "found": 4, "silent": True, "cancel_reason": "history cleared"},
                 {"run_id": 7, "ok": True, "cancelled": False, "found": 4}, {"run_id": None, "cancelled": True, "found": 0}],
        "status": [None, {"range": "6h", "at": 990, "since_ts": 1}, {"range": "all", "since_ts": None}],
        # a clear this window never heard of: only once it has a baseline, and only when newer than the newest it knows
        # (the service's `at` is the answer's `ts`; half a second apart is a second clear)
        "missed": [["undef", {"at": 500.0, "range": "1h"}], [None, {"at": 500.0, "range": "1h"}], [None, None],
                   [500.0, {"at": 500.0, "range": "1h"}], [400.0, {"at": 500.0, "range": "1h"}], [400.0, {"range": "1h"}],
                   [400.0, {"at": "600", "range": "1h"}], [499.5, {"at": 500.0, "range": "1h"}],
                   # a clear this window did handle, its `at` stamped a moment after the answer's ts: not missed; a
                   # different range, or the same range a minute later, is another clear
                   [499.5, {"at": 501.2, "range": "1h"}, [{"ts": 499.5, "range": "1h"}]],
                   [499.5, {"at": 501.2, "range": "6h"}, [{"ts": 499.5, "range": "1h"}]],
                   [499.5, {"at": 560.0, "range": "1h"}, [{"ts": 499.5, "range": "1h"}]]],
    }
    got = _node(tmp_path, _PLAN_DRIVER, ["js/api.js"], payload)
    texts = got["texts"]
    assert got["plans"] == [{"call": "wifi_clear_since", "args": [1790000000.5]}, {"call": "wifi_clear_since", "args": [None]},
                            {"call": "wifi_clear", "args": []}, {"skip": texts["outdated"]}, {"skip": texts["nobridge"]},
                            {"skip": texts["nosurvey"]}] + [{"skip": texts["nosince"]}] * 4
    assert "kept" in texts["nosince"]
    assert "not it" in texts["nobridge"] and "older" in texts["outdated"]
    assert got["results"] == [{"state": "cleared", "points": 9, "aps": 1}, {"state": "failed", "reason": "refused"},
                              {"state": "failed", "reason": "the TNT window did not clear its Wi-Fi survey"},
                              {"state": "cleared", "points": None, "aps": None}]
    assert got["errors"] == [{"kind": "warn", "text": "A Full Scan is running"},
                             {"kind": "warn", "text": "History is already being cleared. Try again in a moment."},
                             {"kind": "warn", "text": "range must be one of: 5m"},
                             {"kind": "error", "text": "This TNT service cannot clear history (it is older than this page)"},
                             {"kind": "warn", "unknown": True, "text": "No answer from the service (Cannot reach the TNT service), so TNT "
                              "cannot tell whether history was cleared. This window updates on its own if it was."},
                             {"kind": "warn", "unknown": True, "text": "No answer from the service (Request timed out), so TNT cannot "
                              "tell whether history was cleared. This window updates on its own if it was."},
                             {"kind": "error", "text": "Could not clear history: database is locked"}]
    assert got["cancelled"] == [True, True, True, False, False, False, True, True, True, False, False]
    assert got["missed"] == [False, True, False, False, True, False, False, True, False, True, True]
    assert got["status"] == ["Nothing has been cleared yet.", "Last cleared: Last 6 hours · 10 s ago.", "Last cleared: All time."]


@NODE
def test_the_timeline_hatches_cleared_spans_like_gaps_with_their_own_tooltip(tmp_path):
    """charts.js' hatchedSpans: the monitoring gaps ("Not monitoring") and then the cleared spans ("History cleared");
    anything that is not a pair of numbers is left out rather than drawn at the epoch."""
    body = r"""
load(process.argv[2]);
console.log(JSON.stringify([T.charts.hatchedSpans(input.d), T.charts.hatchedSpans(null), T.charts.hatchedSpans({ gaps: null })]));
"""
    d = {"gaps": [{"start_ts": 10, "end_ts": 20}], "cleared": [{"start_ts": 30, "end_ts": 90}, {"start_ts": None, "end_ts": 5},
                                                              {"start_ts": 50, "end_ts": 40}]}
    got = _node(tmp_path, body, ["js/charts.js"], {"d": d})
    assert got == [[{"start_ts": 10, "end_ts": 20, "title": "Not monitoring"}, {"start_ts": 30, "end_ts": 90, "title": "History cleared"}],
                   [], []]


# ------------------------------------------------------------------------------------------- markup and CSS
def _settings_body() -> str:
    app = _read("js/app.js")
    return app.split("async function openSettings()", 1)[1].split("\n  function ", 1)[0]


def test_the_history_group_sits_directly_under_updates_with_the_contracts_ids():
    body = _settings_body()
    order = re.findall(r"(?:group|tileGroup)\((?:'(\w+)', )?'([^']+)'", body)
    titles = [t for _v, t in order]
    assert titles[:4] == ["Tools", "General", "Updates", "History"], titles
    history = body.split("group('History'", 1)[1].split("body.appendChild(", 1)[0]
    assert "settingRow('Clear history', HISTORY_DESC, histRange)" in history
    assert "id: 'settings-history', role: 'status'" in history and "class: 'setting-control' }, histBtn" in history
    head = body.split("group('History'", 1)[0]
    assert "id: 'settings-history-range'" in head and "api.history.RANGES.map" in head and "v === api.history.DEFAULT" in head
    assert "class: 'btn btn-danger', id: 'settings-history-clear'" in head and "'Clear history…'" in head
    app = _read("js/app.js")
    desc = app.split("const HISTORY_DESC = ", 1)[1].split(";\n", 1)[0]
    for word in ("ping history", "outages", "speed tests", "previous discovery", "packet captures saved in TNT’s own folder",
                 "fault history", "SIP results", "Wi-Fi scans", "Pro AV scans", "Fault ", "always restarts from now",
                 "still recording", "outside TNT’s own folder", "Saved site reports are never cleared"):
        assert word in desc, word


def test_the_updates_status_and_check_now_are_one_setting_row():
    """The owner: "the update button should also align with the other elements above". Check now sat in a plain flex
    line after its status text; it is a .setting row now, button in the control column, and a button there fills it."""
    body = _settings_body()
    updates = body.split("body.appendChild(group('Updates'", 1)[1].split("]));", 1)[0]
    assert "geo-status" not in updates
    assert "h('span', { class: 's', id: 'settings-update', role: 'status' }" in updates
    assert "h('div', { class: 'setting-control' }, upCheck)" in updates
    css = _read("css/tnt.css")
    assert re.search(r"(?m)^\.setting-control > \.btn \{ width: 100%; \}", css)
    # the IP location row keeps its own status line
    assert "h('div', { class: 'geo-status' }, h('span', { id: 'settings-geoip'" in body
    for bad in (":has(", "grid-column", "@container", "nth-child(odd)"):
        assert bad not in css, bad


def test_every_window_refreshes_on_history_cleared_and_service_text_stays_text():
    app = _read("js/app.js")
    assert "'history.cleared'," in _read("js/api.js")
    assert "ev.on('history.cleared', (d) => historyCleared(d));" in app
    fn = app.split("function historyCleared(d, force) {", 1)[1].split("\n  }\n", 1)[0]
    for step in ("TNT.wifiSurvey.last = null", "refreshStatus();", "remountView();", "renderSettingsHistory();"):
        assert step in fn, step
    remount = app.split("function remountView() {", 1)[1].split("\n  }\n", 1)[0]
    assert "current = { name: null, view: null };" in remount and "showView(name);" in remount
    # the summary goes into the DOM through h() (text nodes); nothing of the clear is ever handed to innerHTML
    block = app.split("/* ---- Settings › History", 1)[1].split("async function openSettings()", 1)[0]
    assert "innerHTML" not in block and "html:" not in block
    assert "api.history.cancelledTest(d)" in app and "TNT.api.history.cancelledTest(d)" in _read("js/views/speed.js")


def test_the_design_doc_describes_the_history_group_and_the_cleared_timeline():
    doc = _doc("docs/DESIGN.md")
    for text in ("Settings › History, directly under the Updates group's Check now", "`#settings-history-range`",
                 "`#settings-history-clear`", "`.setting-control > .btn", "wifi_clear_since(since_ts)",
                 "tooltip \"History cleared\"", "not monitoring or history cleared",
                 "only told to redraw", "`GET /api/history`'s newest entry", "tell whether history was cleared"):
        assert text in doc, text


# ------------------------------------------------------------------------------------------------- the mock
def test_mock_clear_routes_stay_outside_the_network_tool_prefixes(offline_mod):
    """The parity test of tests/test_ui_115.py pins the network tools' routes; the clear is a route of its own."""
    assert not any(r.startswith("/history") for r in offline_mod.NETWORK_TOOL_ROUTES)


def test_mock_clear_of_the_last_hour_follows_the_contract(fresh):
    mod, state, port = fresh.mod, fresh.state, fresh.port
    now = time.time()
    with state.lock:
        state.capture_files.append({"name": "TNT-capture-20990101-000000.pcapng", "size": 4096, "created_ts": now - 60, "packets": 12})
        state.sip_alg_last = {"ts": now - 30, "verdict": "alg"}
        state.sip_stun_last = {"ts": now - 7200, "servers": []}
        state.sip_flow_slots.add("a")
        state.sip_flow_loaded["a"] = now - 10
        state.proav_result = {"devices": [], "streams": []}
        state.proav_last_run_ts = now - 20
        state.outages.append({"id": 99, "kind": "target", "target_id": 1, "start_ts": now - 3 * 3600, "end_ts": None,
                              "missed": 5, "sent": 5, "note": None})
        speed_in = sum(1 for r in state.speedtests if r["ts"] >= now - 3600)
        speed_total = len(state.speedtests)
        outages_in = sum(1 for o in state.outages if o["end_ts"] is None or o["end_ts"] >= now - 3600)
        runs = len(state.disc_runs)
        targets = len(state.targets)
    reports_before = _req(port, "GET", "/api/reports")[2]
    q = state.hub.subscribe()
    try:
        st, res = _post(port, {"range": "1h"})
    finally:
        state.hub.unsubscribe(q)
    assert st == 200, res
    assert list(res) == RESULT_KEYS and list(res["cleared"]) == CLEARED_KEYS
    assert (res["range"], res["label"]) == ("1h", "Last hour")
    assert abs(res["ts"] - res["since_ts"] - 3600) < 1e-6 and abs(res["ts"] - time.time()) < 5
    c = res["cleared"]
    assert c["speed"] == speed_in and speed_in >= 3
    assert c["outages"] == outages_in and c["outages"] >= 2            # the open one and the one 47 minutes ago
    assert c["discovery"] == 0 and c["captures"] == 1 and c["faults"] == 1
    assert c["sip"] == 2 and c["proav"] == 1                            # the ALG result and flow slot a; STUN is older
    # every minute row with minute_ts > since - 60, up to the clear: the minute the window starts in goes whole
    assert c["ping"] == targets * (int(res["ts"] // 60) - int(res["since_ts"] // 60) + 1), c
    assert res["stopped"] == [] and res["skipped"] == []
    # the event carries exactly the answer
    assert _events(q, "history.cleared") == [res]
    # what went, and what stayed
    with state.lock:
        assert len(state.speedtests) == speed_total - speed_in and all(r["ts"] < res["since_ts"] for r in state.speedtests)
        assert len(state.disc_runs) == runs
        assert [f["name"] for f in state.capture_files] == [mod.CAPTURE_SEED_FILE]
        assert state.sip_alg_last is None and state.sip_stun_last is not None and state.sip_flow_slots == set()
        assert state.proav_result is None
        assert all(o["end_ts"] is not None and o["end_ts"] < res["since_ts"] for o in state.outages)
        assert all(x[0] < res["since_ts"] for pts in state.samples.values() for x in pts)
        assert state.faults_since == pytest.approx(res["ts"], abs=1)
    assert _req(port, "GET", "/api/reports")[2] == reports_before, "saved site reports are never touched"
    # the timeline paints [since_ts, ts] as cleared; GET /api/history names it
    tl = _req(port, "GET", "/api/outages/timeline?hours=24")[2]
    assert len(tl["cleared"]) == 1
    assert tl["cleared"][0]["start_ts"] == pytest.approx(res["since_ts"]) and tl["cleared"][0]["end_ts"] == pytest.approx(res["ts"])
    info = _req(port, "GET", "/api/history")[2]
    assert info["ranges"] == [{"key": k, "label": label} for k, _s, label in CONTRACT_RANGES]
    assert info["last"] == {"since_ts": res["since_ts"], "at": res["ts"], "range": "1h"}
    # the ping minutes of the window are gone from the chart's history, the ones before it stay
    hist = _req(port, "GET", f"/api/targets/1/history?from={now - 7200}&to={now}")[2]["minutes"]
    assert hist and all(m["minute_ts"] <= res["since_ts"] - 60 for m in hist)
    assert min(m["minute_ts"] for m in hist) <= now - 7000


def test_mock_clear_of_all_time_empties_everything_but_the_reports(fresh):
    state, port = fresh.state, fresh.port
    reports_before = _req(port, "GET", "/api/reports")[2]
    assert _post(port, {"range": "1h"})[0] == 200
    st, res = _post(port, {"range": "all"})
    assert st == 200 and res["since_ts"] is None and res["label"] == "All time"
    assert res["cleared"]["captures"] == 1                   # the seeded capture file, the only one listed
    with state.lock:
        assert state.speedtests == [] and state.outages == [] and state.disc_runs == [] and state.capture_files == []
        assert [e for e in state.events_db if e["category"] == "outage"] == []
        assert [e for e in state.events_db if e["category"] != "outage"], "only outage events go"
        assert state.history_spans == [{"since_ts": None, "at": res["ts"], "range": "all"}], "all time replaces the list"
    tl = _req(port, "GET", "/api/outages/timeline?hours=6")[2]
    assert tl["cleared"] == [{"start_ts": tl["start_ts"], "end_ts": pytest.approx(res["ts"])}] and tl["segments"] == [] and tl["gaps"] == []
    assert _req(port, "GET", "/api/speedtests")[2]["status"]["last"] is None
    assert _req(port, "GET", "/api/reports")[2] == reports_before


def test_mock_tiles_forget_what_the_clear_took_so_a_stale_tile_would_show(fresh):
    """The mock's Ping tiles and SIP tile are invented from the base RTT, so after a clear they must shrink the way the
    service's do (it re-reads its day summary and drops the SIP tile cache): otherwise a browser test could never catch
    a page that keeps showing yesterday's figures. An open outage always goes, so no target stays "in outage"."""
    state, port = fresh.state, fresh.port

    def day(tid: int) -> Dict[str, Any]:
        return next(t for t in _req(port, "GET", "/api/targets")[2] if t["id"] == tid)["day"]

    before = day(1)
    assert before["sent"] > 3 * 3600 and before["avg_ms"] is not None
    assert _req(port, "GET", "/api/status")[2]["sip"]["verdict"] != "unknown"
    with state.lock:
        state.targets[0]["in_outage"], state.targets[0]["consecutive_missed"] = True, 12
    assert _post(port, {"range": "1h"})[0] == 200
    after = day(1)
    # the hour is gone from the day (give or take the seconds the requests took), the rest is still there
    assert before["sent"] - 3700 < after["sent"] < before["sent"] - 3500, (before, after)
    with state.lock:
        assert state.targets[0]["in_outage"] is False and state.targets[0]["consecutive_missed"] == 0
    assert _post(port, {"range": "all"})[0] == 200
    empty = day(1)
    assert empty["sent"] < 5 and empty["lost"] <= empty["sent"]      # only the seconds since the clear
    assert _req(port, "GET", "/api/status")[2]["sip"]["verdict"] == "unknown"
    legs = _req(port, "GET", "/api/sip/qualifier")[2]["rating"]["legs"]
    assert legs and all(leg["grade"] == "unknown" and leg["reason"].startswith("only ") for leg in legs), legs


def test_mock_clear_refusals_change_nothing(fresh):
    state, port = fresh.state, fresh.port

    def snapshot() -> str:
        with state.lock:
            return json.dumps([len(state.speedtests), len(state.outages), len(state.disc_runs), state.history_spans,
                               [f["name"] for f in state.capture_files]])

    before = snapshot()
    for body in ({"range": "2h"}, {"range": None}, {}, {"range": ["1h"]}):
        assert _post(port, body) == (400, {"error": {"code": "bad_range", "message": fresh.mod.HISTORY_BAD_RANGE_MSG}}), body
    assert _post(port, None, raw=b"[\"1h\"]")[1]["error"]["code"] == "bad_range"
    for headers in CROSS_SITE_HEADERS:
        st, res = _post(port, {"range": "1h"}, headers)
        assert st == 403 and res["error"]["code"] == "forbidden", headers
    with state.lock:
        state.report_job = {"status": "running"}
    try:
        assert _post(port, {"range": "1h"}) == (409, {"error": {"code": "full_scan_running", "message": fresh.mod.HISTORY_FULL_SCAN_MSG}})
    finally:
        with state.lock:
            state.report_job = None
    # a second clear while one runs
    state.history_clear_delay_s = 0.6
    first: Dict[str, Any] = {}
    th = threading.Thread(target=lambda: first.update(r=_post(port, {"range": "5m"})))
    th.start()
    deadline = time.time() + 5
    while not state.history_clearing and time.time() < deadline:
        time.sleep(0.01)
    assert _post(port, {"range": "1h"}) == (409, {"error": {"code": "clear_running", "message": fresh.mod.HISTORY_CLEAR_RUNNING_MSG}})
    th.join(10)
    assert first["r"][0] == 200 and first["r"][1]["range"] == "5m"
    assert snapshot() != before       # only the clear that was let through changed anything


def test_mock_clear_leaves_captures_to_an_administrator_and_a_recording_capture_alone(fresh):
    state, port = fresh.state, fresh.port
    state.wifi_admin = False
    st, res = _post(port, {"range": "all"})
    assert st == 200 and res["cleared"]["captures"] == 0
    assert res["skipped"] == [{"what": "captures", "reason": "TNT is not running as administrator, so its packet captures were left alone"}]
    with state.lock:
        assert [f["name"] for f in state.capture_files] == [fresh.mod.CAPTURE_SEED_FILE]
        assert state.speedtests == [], "the rest still clears"
    state.wifi_admin = True
    with state.lock:
        state.capture_session = {"id": 1, "state": "capturing", "source": "live", "saved": False, "file": None, "started_ts": time.time()}
    st, res = _post(port, {"range": "1h"})
    assert res["skipped"] == [{"what": "captures", "reason": fresh.mod.HISTORY_CAPTURE_RECORDING_MSG}]
    with state.lock:
        assert state.capture_session is not None and state.capture_session["state"] == "capturing"
        state.capture_session = None


def test_mock_clear_closes_a_sip_flow_slot_whose_capture_it_deleted(fresh):
    """The contract closes any call-flow slot whose file was a capture the clear deleted, however long ago the slot was
    loaded: the slot would otherwise keep showing calls from a file that is gone. A slot loaded before the window from a
    file that stays is left open."""
    state, port = fresh.state, fresh.port
    now = time.time()
    gone = "TNT-capture-20990101-000000.pcapng"
    with state.lock:
        state.capture_files.append({"name": gone, "size": 4096, "created_ts": now - 60, "packets": 12})
        state.sip_alg_last = state.sip_stun_last = None
    state.sip_flow_open("C:\\ProgramData\\TNT\\captures\\" + gone, "a")
    state.sip_flow_open("C:\\Users\\tech\\Desktop\\site-call.pcapng", "b")
    with state.lock:
        state.sip_flow_loaded["a"] = state.sip_flow_loaded["b"] = now - 7200     # both loaded before the last hour
    st, res = _post(port, {"range": "1h"})
    assert st == 200 and res["cleared"]["captures"] == 1
    with state.lock:
        assert state.sip_flow_slots == {"b"}, "the slot holding the deleted capture closed; the other stays"
        assert set(state.sip_flow_files) == {"b"}
    assert res["cleared"]["sip"] == 1


def test_mock_clear_stops_running_jobs_and_keeps_nothing_of_them(fresh):
    state, port = fresh.state, fresh.port
    assert state.speed_run()
    state.disc_start("10.0.0.0/24", [80])
    state.proav_start({"seconds": 10})
    q = state.hub.subscribe()
    try:
        tests_before = len(state.speedtests)
        st, res = _post(port, {"range": "5m"})
        assert st == 200 and res["stopped"] == ["speed test", "discovery scan", "Pro AV scan"]
        deadline = time.time() + 8
        while time.time() < deadline and (state.disc_running or not _events_peek(q, "discovery.done")):
            time.sleep(0.05)
        time.sleep(0.3)
    finally:
        state.hub.unsubscribe(q)
    frames = _drain(q)
    done = [d for k, d in frames if k == "speedtest.done"]
    # the service's shape (tnt/speedtest/scheduler.py): the run ends "cancelled", the mark sits on the event
    assert done == [{"result": {"ok": False, "ts": res["ts"], "error": "cancelled"}, "trigger": "manual",
                     "silent": True, "cancel_reason": "history cleared"}]
    disc = [d for k, d in frames if k == "discovery.done"]
    assert disc and disc[-1]["run_id"] is None and disc[-1]["cancelled"] is True
    assert (disc[-1]["silent"], disc[-1]["cancel_reason"]) == (True, "history cleared")
    with state.lock:
        assert not state.speed_running and not state.disc_running
        assert len(state.speedtests) == tests_before - res["cleared"]["speed"], "the stopped test left no row"
        assert all(r["ts"] < time.time() - 60 for r in state.disc_runs), "the stopped scan left no run"
        assert state.proav_job["state"] == "idle" and state.proav_result is None


_PEEKED: List[Tuple[str, Any]] = []


def _drain(q: "queue.Queue[str]") -> List[Tuple[str, Any]]:
    out = list(_PEEKED)
    _PEEKED.clear()
    while True:
        try:
            frame = q.get_nowait()
        except queue.Empty:
            return out
        lines = frame.split("\n")
        out.append((lines[0][7:], json.loads(lines[1][6:])))


def _events_peek(q: "queue.Queue[str]", kind: str) -> bool:
    _PEEKED.extend(_drain(q))
    return any(k == kind for k, _d in _PEEKED)


# --------------------------------------------------------------------------------------- the page, headless
_HEAD = r"""<!doctype html><html><head><meta charset="utf-8"><title>history probe</title></head><body style="margin:0">
<pre id="probe">pending</pre>
<iframe id="app" src="/index.html@QUERY@#@VIEW@" style="width:1366px;height:900px;border:0;display:block"></iframe>
<script>
const out = {};
const frame = document.getElementById('app');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(fn, ms) {
  const end = Date.now() + ms;
  for (;;) {
    let v = null;
    try { v = fn(); } catch (e) { v = null; }
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out waiting for ' + String(fn).slice(0, 200));
    await sleep(40);
  }
}
const app = () => frame.contentDocument;
const W = () => frame.contentWindow;
const text = (el) => (el ? el.textContent : null);
const texts = (els) => Array.from(els).map((e) => e.textContent);
const box = (el) => { const r = el.getBoundingClientRect(); return { left: Math.round(r.left), width: Math.round(r.width), top: Math.round(r.top), bottom: Math.round(r.bottom) }; };
const ready = () => until(() => app() && W().TNT && W().TNT.app && W().TNT.state.status && app().getElementById('btn-settings'), 15000);
const topModal = () => { const ms = app().querySelectorAll('#modal-root .modal'); return ms[ms.length - 1] || null; };
async function openSettings() {
  app().getElementById('btn-settings').click();
  return until(() => app().getElementById('settings-history-clear'), 8000);
}
// every POST /api/history/clear the page makes, and its answer
const posts = [];
function watchFetch() {
  const orig = W().fetch.bind(W());
  W().fetch = (url, init) => {
    const p = orig(url, init);
    if (String(url).indexOf('/api/history/clear') >= 0) {
      const rec = { body: init && init.body ? JSON.parse(init.body) : null };
      posts.push(rec);
      p.then((r) => r.clone().json()).then((j) => { rec.res = j; }, () => {});
    }
    return p;
  };
}
// Clear history… for `range`, then the confirm dialog's `button` ('Clear history' or 'Cancel'); -> the dialog as read
async function clickClear(range, button) {
  const sel = app().getElementById('settings-history-range');
  sel.value = range;
  app().getElementById('settings-history-clear').click();
  const dlg = await until(() => { const m = topModal(); return m && m.querySelector('.history-confirm') ? m : null; }, 5000);
  await sleep(50);
  const seen = { title: text(dlg.querySelector('.modal-head h2')), lead: text(dlg.querySelector('.history-confirm p')),
                 items: texts(dlg.querySelectorAll('.history-what li')), body: text(dlg.querySelector('.history-confirm')),
                 buttons: texts(dlg.querySelectorAll('.modal-foot .btn')), focus: app().activeElement ? app().activeElement.textContent : null };
  Array.from(dlg.querySelectorAll('.modal-foot .btn')).find((b) => b.textContent === button).click();
  return seen;
}
// at most five toasts stay on screen, so a new one is told by a mark on the old ones, not by counting
const toasts = () => Array.from(app().querySelectorAll('#toasts .toast'));
const fresh = () => toasts().filter((t) => !t.dataset.seen);
function mark() { for (const t of toasts()) t.dataset.seen = '1'; return 0; }
async function nextToast() { return until(() => fresh().pop(), 10000); }
async function nextHistoryToast() { return until(() => fresh().filter((t) => t.querySelector('.history-toast')).pop(), 10000); }
function readToast(t) {
  const hist = t.querySelector('.history-toast');
  return { cls: t.className, text: t.textContent, title: hist ? text(hist.querySelector('.strong')) : null,
           lines: hist ? Array.from(hist.children).slice(1).map((e) => e.textContent) : null,
           elements: hist ? Array.from(hist.querySelectorAll('*')).map((e) => e.tagName) : null };
}
"""
_TAIL = r"""
run().catch((e) => { out.failed = String((e && e.stack) || e); }).then(() => {
  try { out.errors = frame.contentDocument.documentElement.getAttribute('data-mock-errors'); } catch (e) { out.errors = 'unreadable: ' + e; }
  document.getElementById('probe').textContent = JSON.stringify(out).replace(/[&<>]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
});
</script></body></html>"""


def _probe(browser_page: Any, mock: Any, monkeypatch: Any, name: str, view: str, body: str, query: str = "",
           budget_ms: int = 30000) -> Dict[str, Any]:
    _serve_probe(mock, monkeypatch, name, _HEAD.replace("@VIEW@", view).replace("@QUERY@", query) + body + _TAIL)
    res = _probe_result(browser_page(name, budget_ms=budget_ms))
    assert "failed" not in res, (res.get("failed"), res.get("errors"))
    assert res["errors"] == "[]", res["errors"]
    return res


_LAYOUT_PROBE = r"""
async function run() {
  await ready();
  await openSettings();
  const doc = app();
  // the dialog's pop-in (modal-in, scale 0.98) never finishes on the page's virtual clock: measured through it every box
  // is 2 % small (the 186 px column read 182), so it is switched off and the layout itself is measured
  doc.querySelector('#modal-root .modal').style.animation = 'none';
  await sleep(50);
  const measure = () => {
    const upd = doc.getElementById('settings-update-check'), clr = doc.getElementById('settings-history-clear');
    const rng = doc.getElementById('settings-history-range');
    const updGroup = upd.closest('.setting-group');
    const row = (el) => el.closest('.setting');
    const scroller = doc.querySelector('#modal-root .modal > .modal-body');
    return {
      upd: box(upd), clr: box(clr), rng: box(rng),
      toggles: Array.from(updGroup.querySelectorAll('.setting-control .toggle')).map(box),
      selects: Array.from(updGroup.querySelectorAll('.setting-control > select.input')).map(box),
      updDesc: box(row(upd).querySelector('.desc')), clrDesc: box(row(clr).querySelector('.desc')), rngDesc: box(row(rng).querySelector('.desc')),
      overflow: scroller.scrollWidth > scroller.clientWidth || doc.documentElement.scrollWidth > doc.documentElement.clientWidth,
    };
  };
  out.wide = measure();
  const groups = Array.from(doc.querySelectorAll('#modal-root .modal .setting-group > h3')).map((h) => h.textContent);
  const rng = doc.getElementById('settings-history-range');
  out.page = { groups, options: texts(rng.options), selected: rng.value, clr: text(doc.getElementById('settings-history-clear')),
               clrClass: doc.getElementById('settings-history-clear').className,
               status: text(doc.getElementById('settings-history')), statusRole: doc.getElementById('settings-history').getAttribute('role'),
               updInDesc: !!doc.querySelector('.setting .desc #settings-update'), histInDesc: !!doc.querySelector('.setting .desc #settings-history'),
               desc: text(rng.closest('.setting').querySelector('.desc .s')) };
  frame.style.width = '700px';
  await sleep(400);
  out.narrow700 = measure();
  frame.style.width = '600px';
  await sleep(400);
  out.narrow = measure();
}
"""


def test_check_now_and_clear_history_line_up_with_the_controls_above_in_a_browser(browser_page, fresh, monkeypatch):
    """At 1366 px, Check now and Clear history… have the left edge and width of the toggles and selects above them (the
    186 px control column); at 700 and 600 px every row stacks, each control under its description and left-aligned with it,
    and nothing scrolls sideways. The History group comes right after Updates, Last hour chosen."""
    res = _probe(browser_page, fresh, monkeypatch, "history-layout.html", "ipinfo", _LAYOUT_PROBE)
    wide, narrow, page = res["wide"], res["narrow"], res["page"]
    column = wide["toggles"][0]
    assert len(wide["toggles"]) == 2 and len(wide["selects"]) == 1, wide
    for el in wide["toggles"] + wide["selects"] + [wide["upd"], wide["clr"], wide["rng"]]:
        assert (el["left"], el["width"]) == (column["left"], column["width"]), (el, column)
    assert column["width"] == 186, column          # the fixed control column, var(--setting-control, 186px)
    assert wide["upd"]["left"] > wide["updDesc"]["left"] + 100, "the button sits in the control column, not after the text"
    assert wide["overflow"] is False
    # 700 px and phone width: one column, each control under its own description and left-aligned with it
    for narrow in (res["narrow700"], res["narrow"]):
        for ctl, desc in (("upd", "updDesc"), ("clr", "clrDesc"), ("rng", "rngDesc")):
            assert narrow[ctl]["top"] >= narrow[desc]["bottom"], (ctl, narrow)
            assert narrow[ctl]["left"] == narrow[desc]["left"], (ctl, narrow)
        assert narrow["upd"]["width"] == narrow["clr"]["width"] == narrow["rng"]["width"] > column["width"]
        assert narrow["clr"]["top"] > narrow["rng"]["top"] > narrow["upd"]["top"]
        assert narrow["overflow"] is False
    groups = page["groups"]
    assert groups[groups.index("Updates") + 1] == "History", groups
    assert page["options"] == [label for _k, _s, label in CONTRACT_RANGES] and page["selected"] == "1h"
    assert (page["clr"], page["clrClass"]) == ("Clear history…", "btn btn-danger")
    assert (page["status"], page["statusRole"]) == ("Nothing has been cleared yet.", "status")
    assert page["updInDesc"] and page["histInDesc"]
    assert "Saved site reports are never cleared" in page["desc"] and "Fault history always restarts from now" in page["desc"]


_CLEAR_PROBE = r"""
async function run() {
  await ready();
  await until(() => app().querySelector('#view .speed-hero') && W().TNT.state.status.speed.last, 10000);
  await until(() => app().querySelector('#view .speed-hero .value').textContent !== '—', 10000);
  out.before = texts(app().querySelectorAll('#view .speed-hero .value'));
  app().querySelector('#view .speed-hero').dataset.old = '1';
  watchFetch();
  const calls = [];
  W().pywebview = { api: { wifi_clear_since: (s) => { calls.push(['since', s]); return Promise.resolve({ ok: true, aps_dropped: 2, points_dropped: 40 }); } } };
  W().TNT.wifiSurvey.last = { aps: [] };
  await openSettings();
  // Cancel sends nothing
  out.cancelled = await clickClear('1h', 'Cancel');
  await sleep(300);
  out.afterCancel = { posts: posts.length, calls: calls.length, open: !!app().querySelector('.history-confirm'),
                      marker: !!app().querySelector('#view .speed-hero[data-old]') };
  // Clear history: the last hour, with a bridge that has wifi_clear_since
  let n = mark();
  out.confirmed = await clickClear('1h', 'Clear history');
  out.toast1 = readToast(await nextHistoryToast());
  await until(() => posts[0] && posts[0].res, 5000);
  out.posts1 = posts.map((p) => p.body);
  out.res1 = posts[0].res;
  out.calls1 = calls.slice();
  out.wifiLast = W().TNT.wifiSurvey.last;
  out.remounted = !app().querySelector('#view .speed-hero[data-old]') && !!app().querySelector('#view .speed-hero');
  out.status1 = text(app().getElementById('settings-history'));
  // All time, on an older window that only has wifi_clear: that is called
  W().pywebview = { api: { wifi_clear: () => { calls.push(['all']); return Promise.resolve({ ok: true }); }, wifi_survey: () => Promise.resolve({ aps: [] }) } };
  n = mark();
  out.confirmedAll = await clickClear('all', 'Clear history');
  out.toast2 = readToast(await nextHistoryToast());
  out.calls2 = calls.slice();
  // no test left: the Speed page's numbers are dashes
  await until(() => texts(app().querySelectorAll('#view .speed-hero .value')).every((t) => t === '—'), 10000);
  out.after = texts(app().querySelectorAll('#view .speed-hero .value'));
  out.meta = text(app().querySelector('#view .speed-hero').parentElement.querySelector('.row'));
  out.status2 = text(app().getElementById('settings-history'));
  out.elsewhere = toasts().some((t) => t.textContent.indexOf('elsewhere') >= 0);
}
"""


def test_clear_history_asks_first_then_clears_and_says_what_went_in_a_browser(browser_page, fresh, monkeypatch):
    """Cancel sends nothing. Confirmed, one POST per clear, the Wi-Fi bridge's wifi_clear_since gets the answer's
    since_ts (an older window's wifi_clear is used only for All time), the open page is mounted again, the WiFi tile's
    cache goes, one summary toast says what went, and with every test gone the Speed page shows dashes."""
    state = fresh.state
    q = state.hub.subscribe()
    try:
        res = _probe(browser_page, fresh, monkeypatch, "history-clear.html", "speed", _CLEAR_PROBE)
        events = _events(q, "history.cleared")
    finally:
        state.hub.unsubscribe(q)
    dlg = res["cancelled"]
    assert dlg["title"] == "Clear history?"
    assert dlg["lead"] == "This removes everything TNT recorded in the last hour:"
    assert dlg["items"] == ["Ping history", "Outages", "Speed tests", "Previous discovery scans", "Packet captures saved in TNT's own folder",
                            "Fault history (the fault watch starts again from now)", "SIP results", "Wi-Fi scans", "Pro AV scans"]
    assert "Saved site reports are never touched. Delete those by hand on the Reports page." in dlg["body"]
    assert dlg["buttons"] == ["Cancel", "Clear history"] and dlg["focus"] == "Cancel", "a danger confirm starts on its safe button"
    assert res["afterCancel"] == {"posts": 0, "calls": 0, "open": False, "marker": True}
    assert res["confirmedAll"]["lead"] == "This removes everything TNT has ever recorded:"
    assert res["posts1"] == [{"range": "1h"}]
    r1 = res["res1"]
    assert r1["range"] == "1h" and list(r1) == RESULT_KEYS
    assert res["calls1"] == [["since", r1["since_ts"]]]
    assert res["calls2"] == [["since", r1["since_ts"]], ["all"]]
    assert res["wifiLast"] is None and res["remounted"] is True
    t1 = res["toast1"]
    assert "toast ok" in t1["cls"] and t1["title"] == "History cleared: Last hour"
    assert t1["lines"][0].startswith("Removed ") and "40 Wi-Fi readings (2 access points gone)" in t1["lines"][0]
    assert f"{r1['cleared']['speed']} speed test" in t1["lines"][0]
    assert t1["lines"][1] == "The fault watch starts again from now."
    t2 = res["toast2"]
    assert t2["title"] == "History cleared: All time" and "the Wi-Fi survey." in t2["lines"][0]
    assert res["before"] != ["—"] * 4 and res["after"] == ["—"] * 4
    assert "No speed test yet" in res["meta"]
    assert res["status1"].startswith("Last cleared: Last hour") and res["status2"].startswith("Last cleared: All time")
    assert res["elsewhere"] is False, "the window that asked shows its own summary, not the other-window note"
    assert [e["range"] for e in events] == ["1h", "all"] and events[0] == r1


_REFUSED_PROBE = r"""
async function run() {
  await ready();
  await until(() => app().querySelector('#view .speed-hero'), 10000);
  app().querySelector('#view .speed-hero').dataset.old = '1';
  watchFetch();
  const calls = [];
  W().pywebview = { api: { wifi_clear_since: (s) => { calls.push(s); return Promise.resolve({ ok: true, aps_dropped: 0, points_dropped: 0 }); } } };
  await openSettings();
  const status = text(app().getElementById('settings-history'));
  out.refused = [];
  for (let i = 0; i < 3; i++) {
    const n = mark();
    await clickClear('1h', 'Clear history');
    const t = await nextToast(n);
    out.refused.push({ cls: t.className, text: t.textContent });
  }
  out.afterRefused = { calls: calls.length, marker: !!app().querySelector('#view .speed-hero[data-old]'),
                       status: text(app().getElementById('settings-history')) === status,
                       busy: app().getElementById('settings-history-clear').disabled };
  // the service's words go in as text: no element is made of them
  let n = mark();
  await clickClear('1h', 'Clear history');
  out.nasty = readToast(await nextHistoryToast());
  out.title = app().title;
  // an older window with only wifi_clear, and a range short of All time: Wi-Fi is left alone and the toast says why
  W().pywebview = { api: { wifi_clear: () => { calls.push('all'); return Promise.resolve({ ok: true }); }, wifi_survey: () => Promise.resolve({ aps: [] }) } };
  n = mark();
  await clickClear('6h', 'Clear history');
  out.older = readToast(await nextHistoryToast());
  // a browser tab: no bridge at all
  delete W().pywebview;
  n = mark();
  await clickClear('24h', 'Clear history');
  out.tab = readToast(await nextHistoryToast());
  out.calls = calls;
}
"""


def test_refusals_change_nothing_and_every_service_string_stays_text_in_a_browser(browser_page, fresh, monkeypatch):
    """409 full_scan_running, 409 clear_running and 400 bad_range: a warning toast with the service's message, no Wi-Fi
    call, the page not mounted again. A summary made of markup-looking service strings is shown as those characters.
    Without wifi_clear_since, a clear short of All time leaves Wi-Fi alone; a browser tab has no bridge; both say why."""
    mod = fresh.mod
    nasty = {"range": "1h", "label": "<img src=x onerror=\"document.title='pwned'\">Last hour", "since_ts": time.time() - 3600,
             "ts": time.time(), "cleared": {k: 0 for k in CLEARED_KEYS}, "stopped": ["<b>speed test</b>"],
             "skipped": [{"what": "<i>captures</i>", "reason": "<script>document.title='pwned'</script>"}]}

    def plain(range_key: str) -> Dict[str, Any]:
        return {"range": range_key, "label": mod.HISTORY_RANGE_LABELS[range_key], "since_ts": time.time() - 60, "ts": time.time(),
                "cleared": {k: 0 for k in CLEARED_KEYS}, "stopped": [], "skipped": []}

    script: List[Any] = [mod.ToolRefused(409, "full_scan_running", mod.HISTORY_FULL_SCAN_MSG),
                         mod.ToolRefused(409, "clear_running", mod.HISTORY_CLEAR_RUNNING_MSG),
                         mod.ToolRefused(400, "bad_range", mod.HISTORY_BAD_RANGE_MSG), nasty, "6h", "24h"]

    def scripted(range_key: Any, captures_allowed: bool = True) -> Dict[str, Any]:
        step = script.pop(0)
        if isinstance(step, Exception):
            raise step
        return plain(step) if isinstance(step, str) else step

    monkeypatch.setattr(fresh.state, "history_clear", scripted)
    res = _probe(browser_page, fresh, monkeypatch, "history-refused.html", "speed", _REFUSED_PROBE)
    assert [(("toast warn" in r["cls"]), r["text"]) for r in res["refused"]] == [
        (True, mod.HISTORY_FULL_SCAN_MSG), (True, mod.HISTORY_CLEAR_RUNNING_MSG), (True, mod.HISTORY_BAD_RANGE_MSG)]
    assert res["afterRefused"] == {"calls": 0, "marker": True, "status": True, "busy": False}
    n = res["nasty"]
    assert n["title"] == "History cleared: " + nasty["label"]
    assert "Stopped: <b>speed test</b>." in n["lines"] and "Left alone: <i>captures</i> - <script>document.title='pwned'</script>." in n["lines"]
    assert set(n["elements"]) == {"SPAN"}, n["elements"]
    assert res["title"] != "pwned"
    older = res["older"]
    assert older["title"] == "History cleared: Last 6 hours"
    assert older["lines"][-1] == "Left alone: Wi-Fi - " + _wifi_text("outdated") + "."
    assert res["tab"]["lines"][-1] == "Left alone: Wi-Fi - " + _wifi_text("nobridge") + "."
    assert "toast ok" in res["tab"]["cls"], "a browser tab not reaching Wi-Fi is expected, not a warning"
    # the one bridge call is the markup clear's wifi_clear_since; the older window's wifi_clear is for All time only
    assert res["calls"] == [pytest.approx(nasty["since_ts"])]
    assert script == []


def _wifi_text(key: str) -> str:
    api = _read("js/api.js")
    return re.search(key + r": '([^']+)'", api.split("const HISTORY_WIFI_TEXT = {", 1)[1]).group(1)


_EVENT_PROBE = r"""
async function run() {
  await ready();
  const V = () => W().TNT.views.outages;
  await until(() => V().timelineHits().some((h) => h.tip.indexOf('History cleared') >= 0), 10000);
  out.hits = V().timelineHits().map((h) => h.tip).filter((t) => t.indexOf('History cleared') >= 0 || t.indexOf('Not monitoring') >= 0);
  out.legend = texts(app().querySelectorAll('#view .legend > span'));
  out.summary = text(app().querySelector('#view .card .row'));
  // another window cleared the last 30 minutes: this one hears history.cleared
  app().querySelector('#view .timeline-canvas').dataset.old = '1';
  W().TNT.wifiSurvey.last = { aps: [] };
  const urls = [];
  const orig = W().fetch.bind(W());
  W().fetch = (url, init) => { urls.push(String(url)); return orig(url, init); };
  const ev = { range: '30m', label: 'Last 30 minutes', since_ts: Date.now() / 1000 - 1800, ts: Date.now() / 1000 + 1,
               cleared: { ping: 1, outages: 0, speed: 0, discovery: 0, captures: 0, faults: 1, sip: 0, proav: 0 }, stopped: [], skipped: [] };
  let n = mark();
  W().TNT.api.events._emit('history.cleared', ev);
  out.syncUrls = urls.slice();
  out.remounted = !app().querySelector('#view .timeline-canvas[data-old]') && !!app().querySelector('#view .timeline-canvas');
  out.wifiLast = W().TNT.wifiSurvey.last;
  out.elsewhere = readToast(await nextToast(n)).text;
  // the same clear heard twice (the event and a reconnect): once is enough
  n = mark();
  W().TNT.api.events._emit('history.cleared', ev);
  await sleep(300);
  out.dupToasts = fresh().length;
  // Settings open: its status line follows the event
  await openSettings();
  W().TNT.api.events._emit('history.cleared', Object.assign({}, ev, { range: '5m', label: 'Last 5 minutes', ts: ev.ts + 1 }));
  out.status = text(app().getElementById('settings-history'));
  // a speed test the clear cancelled has no "failed" toast; a real failure still has one
  n = mark();
  W().TNT.api.events._emit('speedtest.done', { result: { ok: false, ts: ev.ts, error: 'history cleared', cancelled_by: 'history' } });
  // and in the service's own shape: a run that ended "cancelled", the mark on the event
  W().TNT.api.events._emit('speedtest.done', { result: { ok: false, ts: ev.ts, error: 'cancelled' }, trigger: 'manual', silent: true, cancel_reason: 'history cleared' });
  await sleep(300);
  out.cancelledToasts = fresh().map((t) => t.textContent);
  mark();
  W().TNT.api.events._emit('speedtest.done', { result: { ok: false, ts: ev.ts, error: 'timed out' } });
  out.failedToast = readToast(await nextToast()).text;
}
"""


def test_every_window_refreshes_on_history_cleared_and_the_timeline_shows_cleared_time_in_a_browser(browser_page, fresh, monkeypatch):
    """A clear made elsewhere reaches this window as history.cleared: the status is read at once, the open page is
    mounted again, the WiFi tile's survey is dropped, a note says where it came from (once per clear) and an open
    Settings updates its status line. The Outages timeline hatches the cleared time with "History cleared", never
    green, and its legend says so. A speed test the clear cancelled has no "Speed test failed" toast."""
    st, cleared = _post(fresh.port, {"range": "1h"})
    assert st == 200
    res = _probe(browser_page, fresh, monkeypatch, "history-event.html", "outages", _EVENT_PROBE)
    assert any(t.startswith('<div class="t">History cleared</div>') for t in res["hits"]), res["hits"]
    # the seeded monitoring gap 20 h ago keeps its own tooltip: the two hatchings say which is which
    assert any(t.startswith('<div class="t">Not monitoring</div>') for t in res["hits"]), res["hits"]
    assert "not monitoring or history cleared" in res["legend"]
    assert "history cleared for part of this range" in res["summary"]
    assert "/api/status" in res["syncUrls"]
    assert res["remounted"] is True and res["wifiLast"] is None
    assert res["elsewhere"] == "History cleared elsewhere: Last 30 minutes"
    assert res["dupToasts"] == 0
    assert res["status"].startswith("Last cleared: Last 5 minutes")
    assert not any("failed" in t for t in res["cancelledToasts"]), res["cancelledToasts"]
    assert res["failedToast"] == "Speed test failed: timed out"


_MISSED_PROBE = r"""
async function run() {
  await ready();
  await until(() => app().querySelector('#view').firstElementChild, 10000);
  const E = W().TNT.api.events;
  // every GET /api/history the page makes, and whether its answer has landed
  const gets = [];
  const orig = W().fetch.bind(W());
  let dropClear = false;
  const sent = [];
  W().fetch = (url, init) => {
    const u = String(url);
    const p = orig(url, init);
    if (/\/api\/history$/.test(u)) { const rec = { done: false }; gets.push(rec); p.then(() => { rec.done = true; }, () => { rec.done = true; }); }
    // the service gets the clear and answers, but the answer never reaches the page (a link that dropped)
    if (dropClear && u.indexOf('/api/history/clear') >= 0) {
      const rec = {}; sent.push(rec);
      const mode = dropClear;
      return p.then((r) => r.clone().json()).then((j) => {
        rec.res = j;
        // 'heard': the service's event reaches the page before its request gives up (a 120 s timeout on a slow link)
        if (mode === 'heard') E._emit('history.cleared', j);
        throw new TypeError('Failed to fetch');
      });
    }
    return p;
  };
  // 1. the Tools page shows no recorded history: a clear leaves it as it is (a traceroute running there keeps going)
  app().querySelector('#view').firstElementChild.dataset.old = '1';
  let n = mark();
  E._emit('history.cleared', { range: '5m', label: 'Last 5 minutes', since_ts: 700, ts: 1000,
                               cleared: { ping: 0, outages: 0, speed: 0, discovery: 0, captures: 0, faults: 1, sip: 0, proav: 0 }, stopped: [], skipped: [] });
  out.toolsToast = readToast(await nextToast()).text;
  out.toolsKept = !!app().querySelector('#view > [data-old]');
  // 2. another window clears while this one's event stream is down: the next 'hello' asks GET /api/history and catches up
  E._emit('hello', {});
  await until(() => gets.length && gets.every((g) => g.done), 8000);
  await sleep(100);
  n = mark();
  const other = await (await orig('/api/history/clear', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ range: '30m' }) })).json();
  out.otherRange = other.range;
  E._emit('hello', {});
  out.missedToast = readToast(await until(() => fresh().filter((t) => t.textContent.indexOf('elsewhere') >= 0).pop(), 10000)).text;
  // 3. this window's own clear whose answer is lost: it says it cannot tell, then the catch-up is taken as its answer
  const calls = [];
  W().pywebview = { api: { wifi_clear_since: (s) => { calls.push(s); return Promise.resolve({ ok: true, aps_dropped: 0, points_dropped: 3 }); } } };
  await openSettings();
  // 3a. the event came while the request was still out, then the request failed: the event was the answer
  dropClear = 'heard';
  n = mark();
  await clickClear('6h', 'Clear history');
  out.heardToast = readToast(await nextHistoryToast());
  await sleep(300);
  out.heardOthers = fresh().filter((t) => !t.querySelector('.history-toast')).map((t) => t.textContent);
  // 3b. nothing heard: "cannot tell", and the clear the next 'hello' finds is taken as this window's answer (a status
  //     poll may find it first; either way it is this window's summary, never "cleared elsewhere")
  dropClear = 'lost';
  n = mark();
  await clickClear('1h', 'Clear history');
  const first = await until(() => fresh().filter((t) => t.querySelector('.history-toast') || t.textContent.indexOf('No answer') === 0).pop(), 10000);
  out.unknownToast = first.querySelector('.history-toast') ? null : first.textContent;
  await until(() => sent[1] && sent[1].res, 8000);
  dropClear = false;
  if (out.unknownToast) E._emit('hello', {});
  out.ownToast = readToast(first.querySelector('.history-toast') ? first : await nextHistoryToast());
  await sleep(300);
  out.elsewhereForOwn = fresh().some((t) => t.textContent.indexOf('elsewhere') >= 0);
  out.sentSince = sent.map((x) => x.res.since_ts);
  out.calls = calls.slice();
  out.status = text(app().getElementById('settings-history'));
  // 4. Discovery: a scan the clear stopped shows no "Done" on the page's fuse, and no "Scan cancelled" toast
  const m = topModal(); if (m) { const x = m.querySelector('.modal-foot .btn, .modal-close'); if (x) x.click(); }
  W().location.hash = '#discovery';
  await until(() => W().TNT.state.view === 'discovery' && app().querySelector('#view .fuse-wrap'), 8000);
  E._emit('discovery.progress', { phase: 'sweep', done: 3, total: 254, found: 0, elapsed_s: 1 });
  n = mark();
  E._emit('discovery.done', { run_id: null, cancelled: true, cancelled_by: 'history', found: 0, network_changed: false });
  await until(() => app().querySelector('#view .fuse-wrap').hidden, 8000);
  await sleep(300);
  out.discFuse = { hidden: app().querySelector('#view .fuse-wrap').hidden, left: text(app().querySelector('#view .fuse-wrap .fuse-label .l')) };
  out.discToasts = fresh().map((t) => t.textContent);
  // the service's voided scan: it finished on its own while the clear ran (cancelled false), was not stored and says
  // so with silent + cancel_reason - no "Done", no "Scan finished: 4 devices"
  E._emit('discovery.progress', { phase: 'sweep', done: 9, total: 254, found: 4, elapsed_s: 2 });
  await until(() => !app().querySelector('#view .fuse-wrap').hidden, 8000);
  n = mark();
  E._emit('discovery.done', { run_id: null, ok: true, cancelled: false, found: 4, network_changed: false, silent: true, cancel_reason: 'history cleared' });
  await until(() => app().querySelector('#view .fuse-wrap').hidden, 8000);
  await sleep(300);
  out.voidFuse = { hidden: app().querySelector('#view .fuse-wrap').hidden, left: text(app().querySelector('#view .fuse-wrap .fuse-label .l')) };
  out.voidToasts = fresh().map((t) => t.textContent);
}
"""


def test_a_missed_or_unanswered_clear_is_caught_up_and_only_pages_with_history_remount_in_a_browser(browser_page, fresh, monkeypatch):
    """Four holes the review found, closed. The Tools page shows no recorded history, so a clear only notifies it (a
    traceroute or unsaved DHCP edits there survive). A clear this window never heard of (its stream was down) is caught
    on the next 'hello' by GET /api/history. This window's own clear whose answer was lost says it cannot tell, and the
    clear it then learns of is taken as its answer: the Wi-Fi survey is cleared from that clear's start and the summary
    toast is shown, not "cleared elsewhere". A discovery scan the clear stopped never shows "Done"."""
    res = _probe(browser_page, fresh, monkeypatch, "history-missed.html", "tools", _MISSED_PROBE)
    assert res["toolsToast"] == "History cleared elsewhere: Last 5 minutes"
    assert res["toolsKept"] is True, "the Tools page was mounted again"
    assert res["otherRange"] == "30m"
    assert res["missedToast"] == "History cleared elsewhere: Last 30 minutes"
    heard = res["heardToast"]
    assert heard["title"] == "History cleared: Last 6 hours" and heard["lines"][0].startswith("Removed "), heard
    assert not any("No answer" in t or "elsewhere" in t for t in res["heardOthers"]), res["heardOthers"]
    if res["unknownToast"] is not None:
        assert res["unknownToast"].startswith("No answer from the service (Cannot reach the TNT service)")
    own = res["ownToast"]
    assert own["title"] == "History cleared: Last hour"
    assert "Removed 3 Wi-Fi readings." in own["lines"]
    assert res["elsewhereForOwn"] is False
    assert res["calls"] == [pytest.approx(x) for x in res["sentSince"]]
    assert res["status"].startswith("Last cleared: Last hour")
    assert res["discFuse"]["hidden"] is True and res["discFuse"]["left"] != "Done"
    assert not any("cancelled" in t or "finished" in t for t in res["discToasts"]), res["discToasts"]
    assert res["voidFuse"]["hidden"] is True and res["voidFuse"]["left"] != "Done"
    assert not any("cancelled" in t or "finished" in t for t in res["voidToasts"]), res["voidToasts"]
