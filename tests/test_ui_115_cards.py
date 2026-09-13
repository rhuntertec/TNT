"""Node-driver tests for what three 1.15.0 cards do, on a small fake DOM (their pure helpers are pinned in
test_ui_115_views.py): the Network info card's NAT section after a check that failed (ui/js/netcheck.js), and the packet
capture Port and TFTP Max upload number fields holding text that is not a number (tools/capture.js, tools/tftp.js).

A number field whose text cannot be read as a number reports ``value === ''`` with ``validity.badInput`` (the HTML value
sanitization WebView2 and Chromium follow); the fake inputs here are set up that way.  Each driver loads one module into a
node vm with a fake document, fake timers only the driver moves, and a scripted TNT.api: nothing reaches a service.
Offline: node and files only.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from test_ui import UI
from tnt import tftp as tnt_tftp

NODE = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

_PRELUDE = r"""
const fs = require('fs'), vm = require('vm');
class TextNode { constructor(t) { this._t = String(t); } get textContent() { return this._t; } }
class El {
  constructor(tag) {
    this.tagName = tag; this.children = []; this.attrs = {}; this.dataset = {}; this.className = ''; this.hidden = false; this.disabled = false;
    this.value = ''; this._text = ''; this.listeners = {}; this.style = {};
    const self = this;
    this.classList = { contains: (c) => self.className.split(' ').includes(c), add() {}, remove() {}, toggle() {} };
  }
  appendChild(c) { this.children.push(c); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  removeAttribute(k) { delete this.attrs[k]; }
  addEventListener(type, f) { (this.listeners[type] = this.listeners[type] || []).push(f); }
  fire(type, e) { for (const f of this.listeners[type] || []) f(e || {}); }
  contains() { return false; }
  querySelector() { return null; }
  focus() {}
  click() {}
  remove() {}
  set innerHTML(v) { this.children = []; this._text = ''; }
  get innerHTML() { return ''; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
}
function h(tag, attrs, ...children) {
  const el = new El(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'on') for (const [type, f] of Object.entries(v)) el.addEventListener(type, f);
    else if (k === 'data') Object.assign(el.dataset, v);
    else if (['value', 'checked', 'disabled', 'hidden'].includes(k)) el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  const add = (c) => {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) { c.forEach(add); return; }
    el.appendChild(c instanceof El || c instanceof TextNode ? c : new TextNode(c));
  };
  children.forEach(add);
  return el;
}
/** The first element under root (root included, depth first) that pred accepts. */
function find(root, pred) {
  if (!(root instanceof El)) return null;
  if (pred(root)) return root;
  for (const c of root.children) { const hit = find(c, pred); if (hit) return hit; }
  return null;
}
let clockMs = 1788000000000;
const timers = new Map();
let timerId = 0;
const setTimeoutFake = (fn, ms) => { const id = ++timerId; timers.set(id, { fn, at: clockMs + (ms || 0), every: 0 }); return id; };
const setIntervalFake = (fn, ms) => { const id = ++timerId; timers.set(id, { fn, at: clockMs + ms, every: ms }); return id; };
const clearTimer = (id) => { timers.delete(id); };
const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r)); };
/** Moves the fake clock on by ms, running every timer that falls due on the way. */
async function advance(ms) {
  const end = clockMs + ms;
  for (;;) {
    let next = null;
    for (const [id, t] of timers) if (t.at <= end && (!next || t.at < next[1].at)) next = [id, t];
    if (!next) break;
    clockMs = Math.max(clockMs, next[1].at);
    if (next[1].every) next[1].at += next[1].every; else timers.delete(next[0]);
    next[1].fn();
    await settle();
  }
  clockMs = end;
  await settle();
}
const document = { activeElement: null, body: new El('body') };
const toasts = [];
const calls = {};
const queues = {};
const handlers = {};
/** Forgets the calls, answers, events, toasts and timers of an earlier scenario. */
function reset() {
  for (const o of [calls, queues, handlers]) for (const k of Object.keys(o)) delete o[k];
  toasts.length = 0;
  timers.clear();
}
/** A scripted API call: records its arguments and answers with the next queued answer (the last one repeats). */
const scripted = (name) => (...args) => {
  (calls[name] = calls[name] || []).push(args);
  const q = queues[name] || [];
  const answer = q.length > 1 ? q.shift() : q[0];
  return answer ? answer() : new Promise(() => {});
};
const ok = (v) => () => Promise.resolve(v);
const fail = (status, code, message) => () => Promise.reject(Object.assign(new Error(message), { status, code, message }));
const count = (name) => (calls[name] || []).length;
const emit = (type, data) => (handlers[type] || []).forEach((f) => f(data));
const window = { addEventListener() {}, removeEventListener() {} };
window.TNT = {
  views: {}, tools: {},
  util: { h, nowS: () => clockMs / 1000, copyCode: (t) => h('code', null, String(t)), relTime: () => 'just now', fmtBytes: (n) => n + ' B' },
  ui: {
    icon: () => new El('svg'), toast: (m, kind) => toasts.push([m, kind]), busy() {}, emptyState: (t) => h('div', { class: 'empty' }, t),
    fuse: () => { const e = new El('div'); e.set = () => {}; return e; },
    segmented: (items) => h('div', { class: 'segmented' }, items.map((i) => h('button', { type: 'button' }, i.label))),
    toggle: () => { const el = h('label'); el.input = h('input'); el.setChecked = (v) => { el.input.checked = !!v; }; return el; },
    confirm: () => Promise.resolve(true),
  },
  api: { events: { state: 'live', on(type, f) { (handlers[type] = handlers[type] || []).push(f); return () => {}; } } },
  state: { status: null },
};
const T = window.TNT;
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'),
  vm.createContext({ window, document, console, setTimeout: setTimeoutFake, clearTimeout: clearTimer, setInterval: setIntervalFake,
    clearInterval: clearTimer }),
  { filename: process.argv[2] });
const done = (out) => process.stdout.write(JSON.stringify(out));
const crash = (e) => { process.stderr.write(String((e && e.stack) || e)); process.exit(1); };
"""


def _drive(tmp_path: Path, body: str, module: str) -> Any:
    """Runs _PRELUDE + body under node with the UI module (relative to ui/); the driver writes one JSON document."""
    driver = tmp_path / "driver.js"
    driver.write_text(_PRELUDE + body, encoding="utf-8")
    r = subprocess.run(["node", str(driver), str(UI / module)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# --------------------------------------------------------------------------------------------- netcheck.js: NAT
_NAT_DRIVER = r"""
const netErr = fail(0, 'network', 'Cannot reach the TNT service');
const natResult = (verdict) => ({ ts: clockMs / 1000, generation: 1, duration_ms: 10, verdict, confidence: 'high', title: '', explanation: '',
  router: null, public_ip: null, trace: null, port_mappings: null, error: null });
const status = { net: { generation: 1, changed_ts: null }, map: null };
const swIdle = ok({ job: { state: 'idle', neighbors: [], generation: 1 }, adapters: [], available: true, reason: null });
for (const name of ['natGet', 'natRun', 'switchGet', 'switchStart', 'switchStop', 'portForwardTest']) T.api[name] = scripted(name);

/** The automatic check fails (runFailure), "Check again" maybe fails too, the service stays away for a minute, then answers. */
async function scenario(runFailure, manualFailure) {
  reset();
  T.state.status = status;
  queues.switchGet = [swIdle];
  queues.natGet = [ok({ result: null, running: false })];
  queues.natRun = [runFailure];
  const card = T.netcheck.create();
  await settle();
  const snap = () => {
    const badge = find(card.el, (e) => e.tagName === 'span' && e.className.split(' ').includes('badge'));
    const explain = find(card.el, (e) => e.className.split(' ').includes('nc-explain'));
    return { natRun: count('natRun'), badge: badge.textContent, cls: badge.className, explain: explain.textContent };
  };
  const failed = snap();
  if (manualFailure) {
    queues.natRun = [manualFailure];
    find(card.el, (e) => e.tagName === 'button' && e.textContent === 'Check again').fire('click');
    await settle();
  }
  const afterManual = snap();
  // still away: a 'hello' whose GET fails, and a minute of status snapshots
  queues.natGet = [netErr];
  emit('hello');
  await settle();
  for (let i = 0; i < 30; i++) { card.update({ status }); await advance(2000); }
  const stillDown = snap();
  // back: its 'hello' GET answers with nothing running and no result
  queues.natGet = [ok({ result: null, running: false })];
  queues.natRun = [ok({ result: natResult('single_nat'), running: false })];
  emit('hello');
  await settle();
  const seen = [];
  for (let i = 0; i < 30; i++) { card.update({ status }); await advance(2000); seen.push(snap()); }
  card.unmount();
  return { failed, afterManual, stillDown, back: snap(), idleChecking: seen.some((s) => s.badge === 'Checking…' && !s.cls.includes('pulse')) };
}

(async () => {
  const internal = fail(500, 'internal', 'internal error');
  done({
    unreachable: await scenario(netErr, null),
    http500: await scenario(internal, null),
    manual: await scenario(netErr, internal),
  });
})().catch(crash);
"""


@NODE
def test_netcheck_nat_checks_again_once_the_service_answers_after_a_failed_check(tmp_path):
    """A check whose request failed (the service restarting, a 500) is not a check: the card shows "Could not check" while the
    service is away, and once a GET answers again (its 'hello') it runs the automatic check once more instead of sitting on
    an idle grey "Checking…" with nothing running. Also when "Check again" failed the same way before the service came back."""
    out = _drive(tmp_path, _NAT_DRIVER, "js/netcheck.js")
    assert set(out) == {"unreachable", "http500", "manual"}
    for name, s in out.items():
        runs = 2 if name == "manual" else 1
        assert (s["failed"]["natRun"], s["failed"]["badge"], s["failed"]["cls"]) == (1, "Could not check", "badge grey"), name
        assert s["failed"]["explain"].startswith("Could not check NAT: "), name
        assert (s["afterManual"]["natRun"], s["afterManual"]["badge"]) == (runs, "Could not check"), name
        # while the service stays away nothing more is POSTed: no retry loop
        assert (s["stillDown"]["natRun"], s["stillDown"]["badge"]) == (runs, "Could not check"), name
        # it answers again: exactly one more automatic check, and its verdict
        assert (s["back"]["natRun"], s["back"]["badge"], s["back"]["cls"]) == (runs + 1, "Single NAT", "badge green"), name
        assert s["idleChecking"] is False, name


# ------------------------------------------------------------------------------------------ tools/capture.js
_CAPTURE_DRIVER = r"""
(async () => {
  const status = { available: true, reason: null, capture: null, files: [],
    adapters: [{ name: 'Ethernet', index: 12, mac: '02:00:5E:10:00:01', type_name: 'Ethernet', wifi: false }] };
  for (const name of ['captureGet', 'captureStart', 'captureStop', 'captureDeleteFile']) T.api[name] = scripted(name);
  T.api.captureFileUrl = (name) => '/api/tools/capture/files/' + name;
  queues.captureGet = [ok(status)];
  queues.captureStart = [ok({ capture: null })];
  const card = T.tools.capture.create();
  card.mount();
  await settle();
  const field = (label) => find(card.body, (e) => e.attrs['aria-label'] === label);
  const port = field('Port (optional)'), host = field('Host (optional)'), protocol = field('Protocol');
  const startBtn = find(card.body, (e) => e.tagName === 'button' && e.textContent === 'Start');
  const invalid = find(card.body, (e) => e.className.split(' ').includes('capture-invalid'));
  const snap = () => ({ starts: (calls.captureStart || []).map((args) => [args[0].host, args[0].port, args[0].protocol]),
    invalidHidden: invalid.hidden, invalidText: invalid.textContent, portInvalid: port.getAttribute('aria-invalid') });
  const out = {};
  host.value = '192.0.2.50';
  port.value = ''; port.validity = { badInput: true, valid: false };        // '5060-' typed: the field reads ''
  startBtn.fire('click'); await settle();
  out.click = snap();
  port.fire('keydown', { key: 'Enter' }); await settle();
  out.enter = snap();
  port.validity = { badInput: false, valid: true }; port.value = '5060';
  startBtn.fire('click'); await settle();
  out.number = snap();
  port.value = '';
  startBtn.fire('click'); await settle();
  out.empty = snap();
  protocol.value = 'icmp'; protocol.fire('change');                          // ICMP takes no port: the field is disabled
  port.validity = { badInput: true, valid: false };
  startBtn.fire('click'); await settle();
  out.icmp = snap();
  card.unmount();
  done(out);
})().catch(crash);
"""


@NODE
def test_capture_refuses_a_port_that_is_not_a_number_instead_of_capturing_every_port(tmp_path):
    """'5060-' in Port reads as '' in a number field: the capture must not start without a port filter. Start and Enter both
    give the service's message under the form with Port marked; an empty Port still means every port, and with ICMP (Port
    disabled) the field is not read."""
    out = _drive(tmp_path, _CAPTURE_DRIVER, "js/tools/capture.js")
    message = "port must be a whole number from 1 to 65535"
    for step in ("click", "enter"):
        assert out[step] == {"starts": [], "invalidHidden": False, "invalidText": message, "portInvalid": "true"}, step
    assert (out["number"]["starts"], out["number"]["invalidHidden"], out["number"]["portInvalid"]) == ([["192.0.2.50", 5060, None]], True, None)
    assert out["empty"]["starts"] == [["192.0.2.50", 5060, None], ["192.0.2.50", None, None]]
    assert out["icmp"]["starts"] == [["192.0.2.50", 5060, None], ["192.0.2.50", None, None], ["192.0.2.50", None, "icmp"]]


# --------------------------------------------------------------------------------------------- tools/tftp.js
_TFTP_DRIVER = r"""
(async () => {
  const status = { available: true, running: false, since_ts: null, error: null, warning: null, adapter: null, adapters: [], listen: [],
    root: 'C:/ProgramData/TNT/tftp', uploads: false, firewall: { rule: 'TNT TFTP server (UDP 69 in)', ok: null, error: null }, conflict: null,
    transfers: [], history: [], counts: {}, settings: { adapter: '', max_upload_mb: 4096 } };
  for (const name of ['tftpStatus', 'tftpStart', 'tftpStop', 'tftpUploads', 'tftpSettings', 'tftpFiles']) T.api[name] = scripted(name);
  queues.tftpStatus = [ok(status)];
  queues.tftpFiles = [ok({ files: [] })];
  queues.tftpSettings = [ok(Object.assign({}, status, { settings: { adapter: '', max_upload_mb: 512 } }))];
  const card = T.tools.tftp.create({ open() {} });
  card.mount();
  await settle();
  const max = find(card.body, (e) => e.attrs['aria-label'] === 'Max upload in MB');
  const snap = () => ({ saves: (calls.tftpSettings || []).map((args) => args[0]), toasts: toasts.slice(), value: max.value });
  const out = {};
  out.loaded = snap();
  max.value = ''; max.validity = { badInput: true, valid: false };           // '40x' typed: the field reads ''
  max.fire('change'); await settle();
  out.change = snap();
  max.value = ''; max.fire('keydown', { key: 'Enter' }); await settle();
  out.enter = snap();
  max.validity = { badInput: false, valid: true }; max.value = '';
  max.fire('change'); await settle();
  out.empty = snap();
  max.value = '512'; max.fire('change'); await settle();
  out.number = snap();
  card.unmount();
  done({ out, text: T.tools.tftp.MAX_UPLOAD_INVALID_TEXT });
})().catch(crash);
"""


@NODE
def test_tftp_max_upload_that_is_not_a_number_is_refused_not_ignored(tmp_path):
    """'40x' in Max upload reads as '' in a number field: the card says so (the service's own text) and shows the size in
    force again, on change and on Enter, instead of saving nothing without a word. An empty field still saves nothing."""
    res = _drive(tmp_path, _TFTP_DRIVER, "js/tools/tftp.js")
    out, text = res["out"], res["text"]
    assert text == tnt_tftp.MAX_UPLOAD_MB_MSG
    warn = [text, "warn"]
    assert out["loaded"] == {"saves": [], "toasts": [], "value": "4096"}
    assert out["change"] == {"saves": [], "toasts": [warn], "value": "4096"}
    assert out["enter"] == {"saves": [], "toasts": [warn, warn], "value": "4096"}
    assert out["empty"] == {"saves": [], "toasts": [warn, warn], "value": ""}
    assert out["number"]["saves"] == [{"max_upload_mb": 512}] and out["number"]["value"] == "512"
