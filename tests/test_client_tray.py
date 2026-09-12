"""client.tray helpers that need no GUI: the ssh launcher script, the self-healing window (quit
when Windows ends the session, relaunch when the embedded WebView2 browser dies), the window
geometry that fits any screen, the .NET / WebView2 startup checks, --remote-debugging-port and the
Wi-Fi survey bridge (its origin guard, session start, client.json switch and shutdown)."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client import tray  # noqa: E402
from client import wifi_survey  # noqa: E402

DESIGN = (1280, 860, 1024, 700)
DESIGN_GEOMETRY = {"width": 1280, "height": 860, "min_size": (1024, 700)}
SERVICE = "http://127.0.0.1:7130"


class NoAdapterApi:
    """The Wlan API stand-in every ClientApp in this file gets: no Wi-Fi interface, no real call."""

    calls: list = []

    def open(self):
        NoAdapterApi.calls.append("open")

    def close(self):
        pass

    def interfaces(self):
        return []


@pytest.fixture(autouse=True)
def _no_real_wifi_survey(monkeypatch):
    """No test may touch this PC's Wi-Fi adapter: every ClientApp's survey runs without its scanner
    thread, on a native layer that reports no adapter."""
    real = wifi_survey.WifiSurvey

    def factory(*args, **kwargs):
        kwargs.setdefault("threaded", False)
        kwargs.setdefault("api_factory", NoAdapterApi)
        return real(*args, **kwargs)

    monkeypatch.setattr(tray.wifi_survey, "WifiSurvey", factory)
    monkeypatch.setattr(tray.wifi_survey, "WlanSurveyApi", NoAdapterApi)


def test_ssh_prompt_script_asks_for_a_user_name():
    script = tray.ssh_prompt_script("10.0.0.5")
    assert "$h = '10.0.0.5'" in script
    assert "Read-Host" in script and "User name" in script
    # blank answer -> plain ssh host; otherwise user@host
    assert "ssh $h" in script and "ssh ($u + '@' + $h)" in script
    # single quotes only: nothing the validated host can contain escapes the string, and no
    # double quotes reach PowerShell's command-line parser
    assert '"' not in script


# --------------------------------------------------------------------------- self-healing window
def _args(**kw):
    base = dict(minimized=False, port=tray.DEFAULT_PORT, url=None, debug=False, remote_debugging_port=None)
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.fixture
def app(tmp_path, monkeypatch):
    """A ClientApp with no GUI: client.json lives in tmp_path and nothing can exit the test run."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    a = tray.ClientApp(_args())
    a._hard_exit = lambda code: None
    return a


@pytest.fixture
def no_spawn(app, monkeypatch):
    """relaunch() without side effects: records the command lines it would start."""
    import subprocess

    popen_calls = []
    monkeypatch.setattr(subprocess, "Popen", lambda argv, **kw: popen_calls.append(argv))
    monkeypatch.setattr(tray, "release_single_instance", lambda: None)
    monkeypatch.setattr(tray, "_window_visible", lambda title=tray.TITLE: False)
    monkeypatch.setattr(app.tray, "stop", lambda: None)
    app.window = SimpleNamespace(destroy=lambda: None)
    return popen_calls


def test_session_ending_reads_sm_shuttingdown(monkeypatch):
    calls = []

    class FakeUser32:
        class GetSystemMetrics:  # a callable with ctypes-style attributes
            argtypes = restype = None

            def __new__(cls, index):
                calls.append(index)
                return FakeUser32.value

    for value, expected in ((0, False), (1, True)):
        FakeUser32.value = value
        monkeypatch.setattr(tray, "_user32", lambda: FakeUser32)
        monkeypatch.setattr(tray.os, "name", "nt")
        assert tray.session_ending() is expected
    assert calls == [tray.SM_SHUTTINGDOWN, tray.SM_SHUTTINGDOWN]

    def boom():
        raise OSError("no user32")

    monkeypatch.setattr(tray, "_user32", boom)
    assert tray.session_ending() is False, "never raises; an unknown state is 'not ending'"


def test_process_alive():
    assert tray.process_alive(os.getpid()) is True
    for bad in (None, "x", 0, -5):
        assert tray.process_alive(bad) is False
    # a pid that cannot exist on Windows (pids are multiples of 4, far below this)
    assert tray.process_alive(0x7FFFFFFD) is False


def test_failure_action_maps_every_process_kind():
    assert tray.failure_action(0) == "relaunch"                       # browser process: the whole WebView2
    assert [tray.failure_action(k) for k in (1, 2, 3)] == ["reload"] * 3   # renderer died or hung: reload the page
    assert [tray.failure_action(k) for k in (4, 5, 6, 7, 8, 9)] == ["ignore"] * 6   # WebView2 restarts these itself
    for junk in (None, "x", -1, 42):
        assert tray.failure_action(junk) == "ignore"
    assert set(tray.PROCESS_FAILED_KINDS) == set(range(10))


def test_relaunch_allowed_rate_limit():
    now = 10_000.0
    assert tray.relaunch_allowed([], now)
    assert tray.relaunch_allowed([now - 10, now - 20], now)
    assert not tray.relaunch_allowed([now - 10, now - 20, now - 30], now), "3 in 10 minutes is the cap"
    assert tray.relaunch_allowed([now - 700, now - 800, now - 900], now), "older ones age out"
    assert tray.relaunch_allowed([now + 50, "x", None, True, now - 1], now), "junk and future stamps do not count"


def test_client_state_accepts_a_utf8_byte_order_mark(tmp_path, monkeypatch):
    """client.json edited by hand and saved with a BOM keeps its theme and relaunch history."""
    import json

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    p = tray.client_state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\xef\xbb\xbf" + json.dumps({"theme": "dark", "relaunches": [1.0, 2.0]}).encode("utf-8"))
    state = tray.load_state()
    assert state.get("theme") == "dark" and state.get("relaunches") == [1.0, 2.0]
    tray.save_state({"theme": "light"})
    assert tray.load_state() == {"theme": "light", "relaunches": [1.0, 2.0]}, "a save keeps the other keys"


def test_relaunch_history_drops_junk():
    assert tray.relaunch_history({"relaunches": [1.5, "x", None, True, 7]}) == [1.5, 7]
    assert tray.relaunch_history({"relaunches": 42}) == []
    assert tray.relaunch_history({}) == []


def test_relaunch_argv_keeps_the_service_settings():
    exe = r"C:\Program Files\TNT\TNT.exe"
    assert tray.relaunch_argv(_args(), show=True, executable=exe, frozen=True) == [exe]
    assert tray.relaunch_argv(_args(), show=False, executable=exe, frozen=True) == [exe, "--minimized"]
    assert tray.relaunch_argv(_args(port=7135, debug=True), show=True, executable=exe, frozen=True) == [exe, "--port", "7135", "--debug"]
    assert tray.relaunch_argv(_args(url="http://127.0.0.1:7136", port=7135), show=True, executable=exe, frozen=True) == \
        [exe, "--url", "http://127.0.0.1:7136"]
    assert tray.relaunch_argv(_args(), show=True, executable="python.exe", frozen=False, script="client/tray.py") == \
        ["python.exe", "client/tray.py"]


def test_relaunch_argv_keeps_remote_debugging():
    exe = r"C:\Program Files\TNT\TNT.exe"
    assert tray.relaunch_argv(_args(remote_debugging_port=7137), show=False, executable=exe, frozen=True) == \
        [exe, "--remote-debugging-port", "7137", "--minimized"]
    parsed = tray.parse_args(["--port", "7135", "--debug", "--remote-debugging-port", "7137"])
    argv = tray.relaunch_argv(parsed, show=True, executable=exe, frozen=True)
    assert argv == [exe, "--port", "7135", "--debug", "--remote-debugging-port", "7137"]
    again = tray.parse_args(argv[1:])
    assert (again.port, again.debug, again.remote_debugging_port) == (7135, True, 7137), "round-trips through parse_args"


def test_remote_debugging_port_argument(capsys):
    assert tray.parse_args([]).remote_debugging_port is None, "off unless asked for"
    assert tray.parse_args(["--remote-debugging-port", "7137"]).remote_debugging_port == 7137
    assert tray.parse_args(["--remote-debugging-port", "1024"]).remote_debugging_port == 1024
    assert tray.parse_args(["--remote-debugging-port", "65535"]).remote_debugging_port == 65535
    for bad in ("80", "1023", "65536", "0", "-1", "abc"):
        with pytest.raises(SystemExit):
            tray.parse_args(["--remote-debugging-port", bad])
    with pytest.raises(SystemExit):
        tray.parse_args(["--remote-debugging-port"])      # the value is required
    assert "remote-debugging-port" in capsys.readouterr().err


def test_remote_debugging_is_announced_in_the_tray(tmp_path, monkeypatch):
    """The DevTools port lets any local program drive the window with the user's rights (saved
    Wi-Fi passwords included), so it is never on silently: a tray notification at every start."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    off = tray.ClientApp(_args())
    notes = []
    monkeypatch.setattr(off.tray, "wait_ready", lambda timeout: True)
    monkeypatch.setattr(off.tray, "notify", lambda message, title="TNT": notes.append(message) or True)
    assert off.warn_remote_debugging() is False and notes == []

    on = tray.ClientApp(_args(remote_debugging_port=7137))
    monkeypatch.setattr(on.tray, "wait_ready", lambda timeout: True)
    monkeypatch.setattr(on.tray, "notify", lambda message, title="TNT": notes.append(message) or True)
    assert on.warn_remote_debugging() is True
    assert notes == [tray.REMOTE_DEBUGGING_WARNING.format(port=7137)]
    assert "7137" in notes[0] and "Wi-Fi passwords" in notes[0] and len(notes[0]) <= tray.NOTIFY_MAX
    monkeypatch.setattr(on.tray, "wait_ready", lambda timeout: False)        # the tray never came up
    assert on.warn_remote_debugging() is False

    # it runs with the other background threads only when the port is set
    started = []
    monkeypatch.setattr(tray, "_create_activate_event", lambda: None)
    monkeypatch.setattr(tray.threading, "Thread", lambda target, name, daemon: SimpleNamespace(start=lambda: started.append(name)))
    for app_, expected in ((off, False), (on, True)):
        started.clear()
        monkeypatch.setattr(app_.tray, "start", lambda: None)
        app_._after_gui_started()
        assert ("remote-debugging-warning" in started) is expected and "status-poll" in started


def test_remote_debugging_help_names_the_risk(capsys):
    with pytest.raises(SystemExit):
        tray.parse_args(["--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert "Any program on this PC can then control the TNT window" in help_text and "Wi-Fi passwords" in help_text


def test_closing_hides_to_tray_normally(app, monkeypatch):
    monkeypatch.setattr(tray, "session_ending", lambda: False)
    assert app._on_closing() is False, "a normal close is cancelled (hide to tray)"
    assert app._quitting is False and not app._stop.is_set()


def test_closing_quits_when_windows_ends_the_session(app, monkeypatch):
    monkeypatch.setattr(tray, "session_ending", lambda: True)
    stopped, destroyed = threading.Event(), threading.Event()
    monkeypatch.setattr(app.tray, "stop", stopped.set)
    app.window = SimpleNamespace(destroy=destroyed.set, hide=lambda: None)
    assert app._on_closing() is None, "the close is allowed so the restart is never held up"
    assert stopped.wait(2.0), "the tray icon is stopped"
    assert destroyed.wait(2.0), "and the window is destroyed: WM_QUERYENDSESSION alone would leave it open"
    assert app._quitting is True and app._stop.is_set()
    # once quitting, a later close (the real one) goes straight through
    assert app._on_closing() is None


def test_webview_state_without_a_window(app):
    assert app.webview_state() == "unknown"


def _window_with_core(core):
    """A stand-in for the pywebview window whose form hosts a WebView2 control with *core*."""
    return SimpleNamespace(native=SimpleNamespace(browser=SimpleNamespace(webview=SimpleNamespace(CoreWebView2=core))))


def test_webview_state_recorded_pid_dead_needs_no_ui_thread(app, monkeypatch):
    ui_calls = []
    monkeypatch.setattr(app, "_on_ui", lambda fn, timeout=0: ui_calls.append(fn) or ("timeout", None))
    app._hooks_installed = True
    app._browser_pid = 0x7FFFFFFD          # a browser process that is gone
    assert app.webview_state() == "dead"
    assert ui_calls == [], "decided from the recorded PID alone, even with a hung UI thread"


def test_webview_state_core_dropped_after_hooks_is_dead(app, monkeypatch):
    monkeypatch.setattr(app, "_on_ui", lambda fn, timeout=0: ("ok", fn()))
    app.window = _window_with_core(None)
    assert app.webview_state() == "unknown", "no CoreWebView2 before the first initialisation"
    app._hooks_installed = True
    app._browser_pid = os.getpid()         # recorded PID still running, but the control dropped its core
    assert app.webview_state() == "dead"
    app.window = _window_with_core(SimpleNamespace(BrowserProcessId=os.getpid()))
    assert app.webview_state() == "alive"
    app.window = _window_with_core(SimpleNamespace(BrowserProcessId=0x7FFFFFFD))
    assert app.webview_state() == "dead"


class _FakeEvent:
    """A .NET event stand-in: supports ``+=``."""

    def __init__(self):
        self.handlers = []

    def __iadd__(self, handler):
        self.handlers.append(handler)
        return self


class _FakeCore:
    def __init__(self, pid, version="152.0.4191.66"):
        self.ProcessFailed = _FakeEvent()
        self.NavigationStarting = _FakeEvent()
        self.BrowserProcessId = pid
        self.Environment = SimpleNamespace(BrowserVersionString=version)

    def Equals(self, other):  # noqa: N802 - .NET name
        return self is other


def test_hook_on_ui_records_the_browser_pid_and_watches_a_new_core(app, monkeypatch):
    checked = []
    monkeypatch.setattr(app, "check_webview2_version", lambda version=None: checked.append(version))
    wv = SimpleNamespace(CoreWebView2=_FakeCore(1234), CoreWebView2InitializationCompleted=_FakeEvent())
    app.window = SimpleNamespace(native=SimpleNamespace(browser=SimpleNamespace(webview=wv), FormClosing=_FakeEvent()))

    app._hook_on_ui()
    assert app._hooks_installed and app._browser_pid == 1234 and app._webview_ready.is_set()
    assert len(wv.CoreWebView2.ProcessFailed.handlers) == 1
    assert wv.CoreWebView2.NavigationStarting.handlers == [app._on_navigation_starting], "the single-origin guard"
    (on_ready,) = wv.CoreWebView2InitializationCompleted.handlers    # attached although the core existed
    on_ready(wv, SimpleNamespace(IsSuccess=True))
    assert len(wv.CoreWebView2.ProcessFailed.handlers) == 1, "the same core is not hooked twice"

    new_core = _FakeCore(5678)
    wv.CoreWebView2 = new_core               # the control re-initialised with a new browser
    on_ready(wv, SimpleNamespace(IsSuccess=True))
    assert app._browser_pid == 5678 and len(new_core.ProcessFailed.handlers) == 1
    assert len(new_core.NavigationStarting.handlers) == 1
    on_ready(wv, SimpleNamespace(IsSuccess=False, InitializationException="0x8007139F"))   # logged, never raises

    deadline = time.monotonic() + 2.0
    while not checked and time.monotonic() < deadline:
        time.sleep(0.02)
    assert checked == ["152.0.4191.66"], "the runtime version in use is checked once per process"


def test_relaunch_starts_a_new_copy_and_is_rate_limited(app, monkeypatch):
    popen_calls, released, destroyed = [], [], []
    import subprocess

    monkeypatch.setattr(subprocess, "Popen", lambda argv, **kw: popen_calls.append((argv, kw)))
    monkeypatch.setattr(tray, "release_single_instance", lambda: released.append(True))
    monkeypatch.setattr(tray, "_window_visible", lambda title=tray.TITLE: True)
    monkeypatch.setattr(app.tray, "stop", lambda: None)
    app.window = SimpleNamespace(destroy=lambda: destroyed.append(True))

    assert app.relaunch(reason="test") is True
    assert released == [True], "the mutex is given up so the new copy becomes the primary instance"
    (argv, kw), = popen_calls
    assert "--minimized" not in argv, "a visible window relaunches visible"
    assert kw["creationflags"] & tray.DETACHED_PROCESS
    assert destroyed == [True] and app._quitting is True and app._stop.is_set()
    assert app.relaunch(reason="again") is False, "one relaunch per process"
    assert len(tray.load_state()["relaunches"]) == 1

    # a fresh process that already relaunched 3 times in the last 10 minutes gives up
    tray.save_state({"relaunches": [tray.time.time() - 5] * tray.RELAUNCH_MAX})
    fresh = tray.ClientApp(_args())
    fresh._hard_exit = lambda code: None
    popen_calls.clear()
    assert fresh.relaunch(reason="loop") is False
    assert popen_calls == [] and fresh._quitting is False, "no relaunch storm"


def test_refused_relaunch_logs_once_and_the_watchdog_waits_for_the_cap(app, no_spawn, monkeypatch, caplog):
    probes, relaunch_calls = [], []
    real_relaunch = app.relaunch
    monkeypatch.setattr(app, "webview_state", lambda: probes.append(1) or "dead")
    monkeypatch.setattr(app, "relaunch", lambda **kw: relaunch_calls.append(kw) or real_relaunch(**kw))
    app._hooks_installed = True
    tray.save_state({"relaunches": [tray.time.time() - 5] * tray.RELAUNCH_MAX})

    with caplog.at_level(logging.DEBUG, logger="client.tray"):
        app.watchdog_tick()                                    # dead -> relaunch refused by the cap
        assert real_relaunch(reason="ProcessFailed") is False  # refused again (e.g. the event)
        caplog.clear()
        app.watchdog_tick()
        app.watchdog_tick()
        assert caplog.records == [], "quiet while the cap holds: no log at all"
    assert len(probes) == 1 and len(relaunch_calls) == 1 and no_spawn == []
    assert app._quitting is False

    tray.save_state({"relaunches": []})       # the oldest aged out (or the history was cleared)
    app.watchdog_tick()
    assert len(probes) == 2 and len(relaunch_calls) == 2
    assert len(no_spawn) == 1 and app._quitting is True, "relaunches on the next tick"


def test_refused_relaunch_error_is_logged_once(app, no_spawn, caplog):
    tray.save_state({"relaunches": [tray.time.time() - 5] * tray.RELAUNCH_MAX})
    with caplog.at_level(logging.ERROR, logger="client.tray"):
        for _ in range(3):
            assert app.relaunch(reason="WebView2 browser process exited") is False
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1 and "keeps losing its browser" in errors[0].getMessage()


def test_user_initiated_relaunch_bypasses_the_cap_and_is_recorded(app, no_spawn):
    start = tray.time.time()
    tray.save_state({"relaunches": [start - 5] * tray.RELAUNCH_MAX})
    assert app.relaunch(reason="watchdog") is False
    assert app.relaunch(show=True, reason="Open TNT", user_initiated=True) is True
    (argv,) = no_spawn
    assert "--minimized" not in argv
    history = tray.load_state()["relaunches"]
    assert len(history) == tray.RELAUNCH_MAX + 1 and history[-1] >= start, "the user's relaunch still counts"


def test_show_window_relaunches_instead_of_showing_a_dead_browser(app, monkeypatch):
    shown, relaunched = [], []
    app.window = SimpleNamespace(show=lambda: shown.append(True))
    app._hooks_installed = True
    monkeypatch.setattr(app, "relaunch", lambda show=None, reason="", user_initiated=False:
                        relaunched.append((show, reason, user_initiated)) or True)

    monkeypatch.setattr(app, "webview_state", lambda: "dead")
    app.show_window()
    assert shown == [] and relaunched and relaunched[0][0] is True
    assert relaunched[0][2] is True, "opening the window is user-initiated: the cap does not apply"

    relaunched.clear()
    monkeypatch.setattr(app, "webview_state", lambda: "alive")
    monkeypatch.setattr(tray, "find_window", lambda title=tray.TITLE: 0)
    app.show_window()
    assert shown == [True] and relaunched == []


# --------------------------------------------------------------------------- window geometry
FIT_CASES = [
    # work area (logical px)  -> (w, h, min_w, min_h)
    ((5120, 1392), (1280, 860, 1024, 700)),   # 5120x1440 ultrawide
    ((1920, 1040), (1280, 860, 1024, 700)),   # 1920x1080 minus the taskbar
    ((1366, 728), (1256, 669, 1024, 669)),    # 1366x768 laptop at 100 %
    ((1093, 582), (1005, 560, 1005, 560)),    # 1366x768 at 125 %
    ((1024, 728), (942, 669, 942, 669)),      # 1024x768 minus the taskbar
    ((960, 508), (883, 508, 883, 508)),       # 1920x1080 at 200 %
    ((853, 450), (800, 450, 800, 450)),       # 1280x720 at 150 %
    ((800, 560), (800, 560, 800, 560)),       # exactly the floor
]


@pytest.mark.parametrize("work, expected", FIT_CASES)
def test_fit_window_table(work, expected):
    assert tray.fit_window(*work) == expected


@pytest.mark.parametrize("work", [(0, 0), (-1, 700), (1920, -5), (None, 1080), ("1920", "1080"),
                                  (float("nan"), 1080), (1920, float("inf")), (True, 1080)])
def test_fit_window_degenerate_work_area_keeps_the_design_size(work):
    assert tray.fit_window(*work) == DESIGN


def test_fit_window_rules_hold_for_every_work_area():
    for ww in range(120, 5200, 41):
        for wh in range(90, 2200, 29):
            w, h, min_w, min_h = tray.fit_window(ww, wh)
            assert min_w <= w <= ww and min_h <= h <= wh, (ww, wh)
            assert w <= 1280 and h <= 860 and min_w <= 1024 and min_h <= 700, (ww, wh)
            assert w <= max(int(ww * 0.92), min_w) and h <= max(int(wh * 0.92), min_h), (ww, wh)
            assert min_w == ww if ww <= 800 else min_w >= 800, (ww, wh)
            assert min_h == wh if wh <= 560 else min_h >= 560, (ww, wh)


def test_fit_window_bad_margin_falls_back():
    for margin in (0, -1, 2, float("nan"), "x"):
        assert tray.fit_window(1093, 582, margin=margin) == (1005, 560, 1005, 560)


def test_window_geometry_centres_on_the_work_area():
    assert tray.window_geometry((0, 0, 1093, 582)) == {"width": 1005, "height": 560, "min_size": (1005, 560),
                                                       "x": 44, "y": 11}
    g = tray.window_geometry((0, 40, 1920, 1040))           # taskbar at the top
    assert (g["width"], g["height"], g["x"], g["y"]) == (1280, 860, 320, 130)
    g = tray.window_geometry((62, 0, 1858, 1080))           # taskbar on the left
    assert g["x"] == 62 + (1858 - 1280) // 2 and g["y"] == (1080 - 860) // 2
    g = tray.window_geometry((0, 0, 800, 560))
    assert (g["x"], g["y"]) == (0, 0), "a window as large as the work area starts at its corner"
    for junk in (None, (0, 0, 0, 0), (0, 0, -5, 700), "junk", (1, 2, 3)):
        assert tray.window_geometry(junk) == DESIGN_GEOMETRY


def test_center_in_never_leaves_the_work_area():
    assert tray.center_in((0, 0, 1920, 1040), 1280, 860) == (320, 90)
    assert tray.center_in((100, 50, 800, 560), 900, 600) == (100, 50)


def test_logical_rect_converts_device_pixels():
    assert tray.logical_rect(0, 0, 1366, 728, 120) == (0, 0, 1092, 582)      # 1366x768 at 125 %
    assert tray.logical_rect(0, 0, 1920, 1040, 96) == (0, 0, 1920, 1040)
    assert tray.logical_rect(0, 0, 1920, 1032, 192) == (0, 0, 960, 516)      # 200 %
    assert tray.logical_rect(0, 0, 1280, 672, 144) == (0, 0, 853, 448)       # 150 %
    assert tray.logical_rect(48, 0, 1920, 1080, 120) == (38, 0, 1497, 864)   # taskbar on the left
    assert tray.logical_rect(0, 0, 1024, 728, 0) == (0, 0, 1024, 728), "an unreadable DPI counts as 96"
    assert tray.logical_rect(0, 0, 0, 0, 96) is None
    assert tray.logical_rect(10, 10, 5, 5, 96) is None
    assert tray.logical_rect(None, 0, 1, 1, 96) is None


def test_work_area_probe_never_raises(monkeypatch):
    def boom():
        raise OSError("no user32")

    monkeypatch.setattr(tray, "_user32", boom)
    assert tray.system_dpi() == 96
    assert tray.primary_work_area() is None
    assert tray.window_geometry(tray.primary_work_area()) == DESIGN_GEOMETRY, "falls back to today's geometry"


@pytest.mark.skipif(os.name != "nt", reason="Win32 work area")
def test_primary_work_area_on_this_pc():
    import ctypes

    u = ctypes.WinDLL("user32")
    u.GetThreadDpiAwarenessContext.restype = ctypes.c_void_p
    u.GetAwarenessFromDpiAwarenessContext.argtypes = [ctypes.c_void_p]

    def awareness():
        return u.GetAwarenessFromDpiAwarenessContext(u.GetThreadDpiAwarenessContext())

    before = awareness()
    area = tray.primary_work_area()
    assert area is not None and area[2] > 0 and area[3] > 0
    assert awareness() == before, "the thread's DPI awareness is restored for pywebview"
    assert 48 <= tray.system_dpi() <= 960


class _FakeFn:
    """A ctypes-function stand-in (accepts argtypes/restype)."""

    def __init__(self, fn):
        self.fn, self.argtypes, self.restype = fn, None, None

    def __call__(self, *args):
        return self.fn(*args)


def test_primary_work_area_restores_the_dpi_context_when_the_read_fails(monkeypatch):
    contexts = []
    fake = SimpleNamespace(SetThreadDpiAwarenessContext=_FakeFn(lambda ctx: contexts.append(ctx.value) or 17),
                           SystemParametersInfoW=_FakeFn(lambda *args: 0))
    monkeypatch.setattr(tray, "_user32", lambda: fake)
    assert tray.primary_work_area() is None
    assert len(contexts) == 2 and contexts[1] == 17, "switched to system aware, then back to the previous context"


def test_keep_on_screen_leaves_a_visible_window_alone():
    full_hd = [(0, 0, 1920, 1040)]
    assert tray.keep_on_screen((320, 90, 1280, 860), full_hd, (1024, 700)) is None
    # snapped to the left half: Windows' invisible resize borders stick out of the work area
    assert tray.keep_on_screen((-7, 0, 974, 1047), full_hd, (800, 560)) is None
    # spanning two monitors
    assert tray.keep_on_screen((1500, 100, 1280, 860), full_hd + [(1920, 0, 1920, 1040)], (1024, 700)) is None
    # on a second monitor that is still there
    assert tray.keep_on_screen((2200, 100, 1280, 860), full_hd + [(1920, 0, 2560, 1400)], (1024, 700)) is None


def test_keep_on_screen_brings_back_a_window_from_a_missing_monitor():
    full_hd = [(0, 0, 1920, 1040)]
    assert tray.keep_on_screen((2200, 100, 1280, 860), full_hd, (1024, 700)) == ((640, 100, 1280, 860), (1024, 700))
    assert tray.keep_on_screen((-1500, 200, 1280, 860), full_hd, (1024, 700)) == ((0, 180, 1280, 860), (1024, 700))
    # title bar above the top edge: cannot be dragged
    assert tray.keep_on_screen((100, -800, 1280, 860), full_hd, (1024, 700)) == ((100, 0, 1280, 860), (1024, 700))


def test_keep_on_screen_shrinks_a_window_larger_than_its_screen():
    # shown again on a 1366x768 laptop at 125 % after being hidden on a big monitor
    assert tray.keep_on_screen((320, 90, 1280, 860), [(0, 0, 1093, 582)], (1024, 700)) == \
        ((88, 22, 1005, 560), (1005, 560))
    # only too tall: the width and its minimum stay
    assert tray.keep_on_screen((100, 100, 1000, 900), [(0, 0, 1366, 728)], (800, 560)) == \
        ((100, 59, 1000, 669), (800, 560))


def test_keep_on_screen_ignores_junk():
    assert tray.keep_on_screen(None, [(0, 0, 1920, 1040)], (1024, 700)) is None
    assert tray.keep_on_screen((0, 0, 100, 100), [], (1024, 700)) is None
    assert tray.keep_on_screen((0, 0, 100, 100), None, None) is None
    assert tray.keep_on_screen((5000, 0, 100, 100), [(0, 0, 0, 0), "x"], (1, 1)) is None


# --------------------------------------------------------------------------- .NET load failure
def _both_runtimes_failed():
    """The exception chain pywebview's ``import clr`` retry leaves when neither .NET Framework nor
    .NET loads (reproduced with pythonnet 3.1.0 / clr_loader 0.3.1)."""
    try:
        try:
            try:
                raise OSError("cannot load library 'C:\\TNT\\_client\\clr_loader\\ffi\\dlls\\amd64\\ClrLoader.dll': error 0x7e")
            except OSError as exc:
                raise RuntimeError('Failed to create a default .NET runtime, which would\n                    have '
                                   'been "netfx" on this system. Either install a\n                    compatible '
                                   'runtime or configure it explicitly via\n                    `set_runtime` or the '
                                   '`PYTHONNET_*` environment variables\n                    (see set_runtime_from_env).') from exc
        except RuntimeError:
            try:
                raise RuntimeError("Can not determine dotnet root")
            except RuntimeError as inner:
                raise RuntimeError("Failed to create a .NET runtime (coreclr) using the\n                parameters {}.") from inner
    except RuntimeError as final:
        return final


def test_is_dotnet_load_error_recognises_pythonnet_and_clr_loader_failures():
    chain = _both_runtimes_failed()
    assert tray.is_dotnet_load_error(chain)
    assert tray.is_dotnet_load_error(RuntimeError("Failed to create a .NET runtime (coreclr) using the\n  parameters {}."))
    assert tray.is_dotnet_load_error(RuntimeError(
        r"Failed to resolve Python.Runtime.Loader.Initialize from C:\Program Files\TNT\_client\pythonnet\runtime\Python.Runtime.dll"))
    assert tray.is_dotnet_load_error(RuntimeError("Failed to initialize Python.Runtime.dll"))
    assert tray.is_dotnet_load_error(RuntimeError("Could not find a suitable hostfxr library in C:\\Program Files\\dotnet."))
    wrapped = ValueError("something else")
    wrapped.__cause__ = RuntimeError("Can not determine dotnet root")
    assert tray.is_dotnet_load_error(wrapped), "found anywhere in the cause/context chain"

    from clr_loader.util.hostfxr_errors import get_hostfxr_error

    assert tray.is_dotnet_load_error(get_hostfxr_error(0x80008096))          # ClrError FrameworkMissingFailure
    fake_clr_error = type("ClrError", (Exception,), {"__module__": "clr_loader.util.clr_error"})
    assert tray.is_dotnet_load_error(fake_clr_error(0x80008089))
    bad_image = type("BadImageFormatException", (Exception,), {"__module__": "System"})
    assert tray.is_dotnet_load_error(bad_image(
        "Could not load file or assembly 'Microsoft.Web.WebView2.WinForms'. This assembly is built by a runtime "
        "newer than the currently loaded runtime and cannot be loaded."))


def test_is_dotnet_load_error_ignores_everything_else():
    class Hostile(Exception):
        def __str__(self):
            raise RuntimeError("no str for you")

    looped_a, looped_b = RuntimeError("a"), RuntimeError("b")
    looped_a.__context__, looped_b.__context__ = looped_b, looped_a
    for other in (RuntimeError("Main window failed to load"), OSError("[WinError 5] Access is denied"),
                  ValueError("x"), KeyError("REMOTE_DEBUGGING_PORT"), Hostile(), looped_a, None,
                  "Failed to create a .NET runtime", 42,
                  type("ClrError", (Exception,), {"__module__": "somewhere.else"})("x")):
        assert tray.is_dotnet_load_error(other) is False, other


def test_dotnet_message_is_plain_language(tmp_path):
    msg = tray.dotnet_missing_message(tmp_path / "client.log")
    assert ".NET Framework 4.7.2" in msg and "Windows 10 version 1809" in msg
    assert "keeps running in the TNT service" in msg and str(tmp_path / "client.log") in msg
    assert "RuntimeError" not in msg and "Traceback" not in msg and "coreclr" not in msg


@pytest.fixture
def main_env(tmp_path, monkeypatch):
    dialogs = []
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(tray, "setup_client_logging", lambda level=None: tmp_path / "client.log")
    monkeypatch.setattr(tray, "acquire_single_instance", lambda name=tray.MUTEX_NAME: True)
    monkeypatch.setattr(tray, "release_single_instance", lambda: None)
    monkeypatch.setattr(tray, "_fatal_dialog", dialogs.append)
    return dialogs


def test_main_explains_a_missing_dotnet_runtime(main_env, monkeypatch, tmp_path):
    def run(self):
        raise _both_runtimes_failed()

    monkeypatch.setattr(tray.ClientApp, "run", run)
    assert tray.main([]) == tray.EXIT_DOTNET_MISSING == 4
    (msg,) = main_env
    assert msg == tray.dotnet_missing_message(tmp_path / "client.log")


def test_main_other_startup_errors_keep_the_generic_dialog(main_env, monkeypatch):
    def run(self):
        raise ValueError("boom")

    monkeypatch.setattr(tray.ClientApp, "run", run)
    assert tray.main([]) == tray.EXIT_FATAL == 1
    (msg,) = main_env
    assert msg.startswith("TNT could not start its window.") and "boom" in msg
    assert tray.EXIT_WEBVIEW2_MISSING == 3


# --------------------------------------------------------------------------- WebView2 version / init
@pytest.mark.parametrize("text, major", [
    ("152.0.4191.66", 152), ("110.0.1587.63", 110), ("120.0.2210.91 beta", 120), (" 99.0.1150.30 ", 99),
    ("111", 111), ("0.0.0.0", None), ("", None), (None, None), ("garbage", None), ("v110.0.1587.63", None),
    ("1.2.3.x", None), (152, None),
])
def test_webview2_major(text, major):
    assert tray.webview2_major(text) == major


@pytest.mark.parametrize("text, outdated", [
    ("152.0.4191.66", False), ("111.0.1661.41", False), ("110.0.1587.63", True), ("86.0.622.38", True),
    ("110.0.1587.63 dev", True), ("0.0.0.0", False), ("", False), (None, False), ("garbage", False),
])
def test_needs_webview2_update(text, outdated):
    assert tray.MIN_WEBVIEW2_MAJOR == 111
    assert tray.needs_webview2_update(text, tray.MIN_WEBVIEW2_MAJOR) is outdated
    assert tray.needs_webview2_update(text) is outdated


def test_needs_webview2_update_minimum_is_easy_to_change():
    assert tray.needs_webview2_update("120.0.2210.91", 121) is True
    assert tray.needs_webview2_update("120.0.2210.91", "x") is False


def test_old_webview2_runtime_is_notified_once_per_version(app, monkeypatch):
    notes = []
    monkeypatch.setattr(app.tray, "wait_ready", lambda timeout: True)
    monkeypatch.setattr(app.tray, "notify", lambda message, title="TNT": notes.append(message) or True)

    assert app.check_webview2_version("152.0.4191.66") is False and notes == []
    assert app.check_webview2_version("110.0.1587.63") is True
    assert notes == [tray.webview2_outdated_message("110.0.1587.63")]
    assert "out of date (version 110.0.1587.63)" in notes[0] and len(notes[0]) <= tray.NOTIFY_MAX
    assert app.check_webview2_version("110.0.1587.63") is False, "no nagging on every start"
    assert tray.ClientApp(_args()).check_webview2_version("110.0.1587.63") is False, "remembered in client.json"
    assert app.check_webview2_version("109.0.1518.78") is True and len(notes) == 2, "another old version is new news"

    monkeypatch.setattr(app.tray, "wait_ready", lambda timeout: False)       # tray never came up
    assert app.check_webview2_version("108.0.1462.54") is False
    assert tray.load_state()["webview2_outdated_notified"] == "109.0.1518.78", "not remembered: try next start"

    monkeypatch.setattr(app.tray, "wait_ready", lambda timeout: True)
    monkeypatch.setattr(tray, "webview2_registry_version", lambda: "100.0.1185.36")
    assert app.check_webview2_version(None) is True and "100.0.1185.36" in notes[-1], "registry fallback"


def test_tray_notify_and_wait_before_start(app):
    assert app.tray.notify("x") is False
    assert app.tray.wait_ready(0.01) is False


def test_webview_init_watchdog_warns_once_and_never_relaunches(app, monkeypatch, caplog):
    notes, relaunched = [], []
    monkeypatch.setattr(app.tray, "wait_ready", lambda timeout: True)
    monkeypatch.setattr(app.tray, "notify", lambda message, title="TNT": notes.append(message) or True)
    monkeypatch.setattr(app, "relaunch", lambda **kw: relaunched.append(kw))
    monkeypatch.setattr(app, "_on_ui", lambda fn, timeout=0: ("ok", False))    # the control exists, no CoreWebView2

    with caplog.at_level(logging.ERROR, logger="client.tray"):
        assert app.webview_init_watchdog(timeout=0.2) is True
    assert notes == [tray.WEBVIEW_INIT_FAILED_MESSAGE] and len(notes[0]) <= tray.NOTIFY_MAX
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "WebView2 Runtime is missing or corrupt" in text and "security software" in text
    assert str(tray.client_dir() / "webview") in text
    assert app.webview_init_watchdog(timeout=0.05) is False and len(notes) == 1, "one notification per process"
    assert relaunched == []


def test_webview_init_watchdog_is_quiet_when_the_webview_started(app, monkeypatch):
    notes = []
    monkeypatch.setattr(app.tray, "notify", lambda message, title="TNT": notes.append(message) or True)
    app._webview_ready.set()
    started = time.monotonic()
    assert app.webview_init_watchdog(timeout=30) is False and time.monotonic() - started < 5
    fresh = tray.ClientApp(_args())
    monkeypatch.setattr(fresh, "_on_ui", lambda fn, timeout=0: ("ok", True))   # initialised, event missed
    monkeypatch.setattr(fresh.tray, "notify", lambda message, title="TNT": notes.append(message) or True)
    assert fresh.webview_init_watchdog(timeout=0.05) is False
    stopping = tray.ClientApp(_args())
    stopping._stop.set()
    started = time.monotonic()
    assert stopping.webview_init_watchdog(timeout=30) is False and time.monotonic() - started < 5, "quitting"
    assert notes == []


# --------------------------------------------------------------------------- Wi-Fi survey bridge
WIFI_BRIDGE_METHODS = ("wifi_survey", "wifi_scan_now", "wifi_clear", "wifi_set_enabled", "open_location_settings")


def _page(url):
    """A pywebview window stand-in whose WinForms backend reports *url* as the page on show."""
    return SimpleNamespace(uid="master", gui=SimpleNamespace(get_current_url=lambda uid: url),
                           show=lambda: None, destroy=lambda: None)


@pytest.mark.parametrize("url, ok", [
    (SERVICE, True), (SERVICE + "/", True), (SERVICE + "/#wifi", True), ("HTTP://127.0.0.1:7130/index.html?x=1", True),
    ("http://127.0.0.1:7131/", False), ("http://localhost:7130/", False), ("https://127.0.0.1:7130/", False),
    ("http://127.0.0.1:7130@example.com/", False), ("http://example.com/?next=http://127.0.0.1:7130", False),
    ("file:///C:/TNT/ui/index.html", False), ("data:text/html,x", False), ("about:blank", False),
    ("http://127.0.0.1:99999/", False), ("", False), (None, False), (42, False),
])
def test_same_origin(url, ok):
    assert tray.same_origin(url, SERVICE) is ok


def test_same_origin_default_ports():
    assert tray.same_origin("http://127.0.0.1/", "http://127.0.0.1:80")
    assert tray.same_origin("https://tnt.test:443/x", "https://tnt.test")
    assert not tray.same_origin(SERVICE, None)


def test_page_url_reads_pywebviews_record_without_waiting(app):
    assert app.page_url() is None and not app.showing_service_page(), "no window yet"
    app.window = _page(SERVICE + "/#wifi")
    assert app.page_url() == SERVICE + "/#wifi" and app.showing_service_page()
    app.window = _page(None)                                   # the inline starting / error page
    assert app.page_url() is None and not app.showing_service_page()
    app.window = SimpleNamespace(uid="master", gui=None)       # before webview.start
    assert app.page_url() is None

    def boom(uid):
        raise RuntimeError("form disposed")

    app.window = SimpleNamespace(uid="master", gui=SimpleNamespace(get_current_url=boom))
    assert app.page_url() is None and not app.showing_service_page()


@pytest.mark.parametrize("url", [None, "http://127.0.0.1:7131/", "https://example.com/wifi", "about:blank"])
def test_wifi_bridge_refuses_any_other_page(app, monkeypatch, url):
    opened, touched = [], []
    monkeypatch.setattr(tray.os, "startfile", opened.append, raising=False)
    for name in ("survey", "scan_now", "clear", "set_enabled"):
        monkeypatch.setattr(app.wifi, name, lambda *a, _n=name, **k: touched.append(_n))
    app.window = _page(url)
    assert app.bridge.wifi_survey({"active": True}) == wifi_survey.blank_view("error", tray.WIFI_BRIDGE_REFUSED)
    assert app.bridge.wifi_scan_now() == {"ok": False, "error": tray.WIFI_BRIDGE_REFUSED}
    assert app.bridge.wifi_clear() == {"ok": False, "error": tray.WIFI_BRIDGE_REFUSED}
    assert app.bridge.wifi_set_enabled(False) == {"ok": False, "enabled": True, "error": tray.WIFI_BRIDGE_REFUSED}
    assert app.bridge.open_location_settings() == {"ok": False, "error": tray.WIFI_BRIDGE_REFUSED}
    assert touched == [] and opened == [] and not app.wifi.session_started
    app.window = None
    assert app.bridge.wifi_survey()["state"] == "error"


def test_wifi_bridge_answers_the_dashboard(app, monkeypatch):
    opened = []
    monkeypatch.setattr(tray.os, "startfile", opened.append, raising=False)
    monkeypatch.setattr(tray, "_window_visible", lambda title=tray.TITLE: True)
    app.window = _page(SERVICE + "/#wifi")
    view = app.bridge.wifi_survey({"active": True, "history_s": 300})
    assert set(view) == set(wifi_survey.blank_view()) and view["enabled"] is True and view["active"] is True
    assert app.wifi.session_started and view["started_ts"] is not None
    json.dumps(view, allow_nan=False)
    app.wifi.tick()                                            # the fake native layer: no Wi-Fi interface
    assert app.bridge.wifi_survey({})["state"] == "no_adapter"
    assert app.bridge.wifi_scan_now() == {"ok": True, "error": None}, "taken although a scan was just attempted"
    assert app.bridge.wifi_scan_now() == {"ok": False, "error": wifi_survey.SCAN_TOO_SOON_TEXT}, "one request per 5 s"
    assert app.bridge.wifi_clear() == {"ok": True}
    assert app.bridge.open_location_settings() == {"ok": True} and opened == ["ms-settings:privacy-location"]
    assert tray.LOCATION_SETTINGS_URI == "ms-settings:privacy-location"


def test_wifi_survey_call_from_a_hidden_window_does_not_start_the_session(app, monkeypatch):
    app.window = _page(SERVICE)
    monkeypatch.setattr(tray, "_window_visible", lambda title=tray.TITLE: False)
    view = app.bridge.wifi_survey({"active": False})
    assert (view["state"], view["started_ts"]) == ("starting", None) and not app.wifi.session_started
    monkeypatch.setattr(tray, "_window_visible", lambda title=tray.TITLE: True)
    app.bridge.wifi_survey({})
    assert app.wifi.session_started, "the window is on screen"
    hidden_but_active = tray.ClientApp(_args())
    hidden_but_active.window = _page(SERVICE)
    monkeypatch.setattr(tray, "_window_visible", lambda title=tray.TITLE: False)
    hidden_but_active.bridge.wifi_survey({"active": True})
    assert hidden_but_active.wifi.session_started, "the WiFi page says it is on screen"


def test_wifi_bridge_is_exception_safe(app, monkeypatch, caplog):
    app.window = _page(SERVICE)

    def boom(*args, **kwargs):
        raise RuntimeError("survey exploded")

    for name in ("survey", "scan_now", "clear", "set_enabled"):
        monkeypatch.setattr(app.wifi, name, boom)
    monkeypatch.setattr(tray.os, "startfile", boom, raising=False)
    with caplog.at_level(logging.ERROR, logger="client.tray"):
        assert app.bridge.wifi_survey({}) == wifi_survey.blank_view("error", tray.WIFI_BRIDGE_FAILED, enabled=True)
        assert app.bridge.wifi_scan_now() == {"ok": False, "error": tray.WIFI_BRIDGE_FAILED}
        assert app.bridge.wifi_clear() == {"ok": False, "error": tray.WIFI_BRIDGE_FAILED}
        assert app.bridge.wifi_set_enabled(True) == {"ok": False, "enabled": True, "error": tray.WIFI_BRIDGE_FAILED}
        assert app.bridge.open_location_settings()["ok"] is False
    assert len([r for r in caplog.records if r.levelno >= logging.ERROR]) == 5
    monkeypatch.setattr(app, "showing_service_page", boom)
    assert app.bridge.wifi_scan_now() == {"ok": False, "error": tray.WIFI_BRIDGE_REFUSED}, "an unreadable page is refused"
    monkeypatch.setattr(type(app.wifi), "enabled", property(boom))
    assert app.bridge.wifi_set_enabled(True) == {"ok": False, "enabled": False, "error": tray.WIFI_BRIDGE_REFUSED}


def test_wifi_set_enabled_is_remembered_in_client_json(app):
    app.window = _page(SERVICE)
    for junk in ("false", 0, 1, None, {}, []):
        assert app.bridge.wifi_set_enabled(junk) == {"ok": False, "enabled": True, "error": "on must be true or false"}
    assert tray.WIFI_ENABLED_KEY not in tray.load_state(), "nothing saved for junk"
    assert app.bridge.wifi_set_enabled(False) == {"ok": True, "enabled": False}
    assert tray.load_state()[tray.WIFI_ENABLED_KEY] is False
    assert tray.ClientApp(_args()).wifi.enabled is False, "the next TNT.exe remembers it"
    assert app.bridge.wifi_survey()["state"] == "disabled"
    assert app.bridge.wifi_set_enabled(True) == {"ok": True, "enabled": True}
    assert tray.ClientApp(_args()).wifi.enabled is True


def test_wifi_switch_reads_client_json_with_a_bom_and_keeps_other_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    p = tray.client_state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\xef\xbb\xbf" + json.dumps({"theme": "dark", "wifi_survey_enabled": False}).encode("utf-8"))
    app = tray.ClientApp(_args())
    assert app.wifi.enabled is False and app.theme == "dark"
    app.window = _page(SERVICE)
    assert app.bridge.wifi_set_enabled(True)["enabled"] is True
    assert tray.load_state() == {"theme": "dark", "wifi_survey_enabled": True}
    assert [tray.wifi_enabled_setting(s) for s in ({}, {"wifi_survey_enabled": "no"}, {"wifi_survey_enabled": 0},
                                                   {"wifi_survey_enabled": False}, None)] == [True, True, True, False, True]


def test_wifi_session_starts_the_first_time_the_window_is_shown(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(tray, "_create_activate_event", lambda: None)
    monkeypatch.setattr(tray.threading, "Thread", lambda target, name, daemon: SimpleNamespace(start=lambda: None))
    at_sign_in = tray.ClientApp(_args(minimized=True))
    monkeypatch.setattr(at_sign_in.tray, "start", lambda: None)
    at_sign_in._after_gui_started()
    assert not at_sign_in.wifi.session_started, "TNT.exe waiting in the tray after sign-in: no survey"
    opened = tray.ClientApp(_args())
    monkeypatch.setattr(opened.tray, "start", lambda: None)
    opened._after_gui_started()
    assert opened.wifi.session_started, "the window opened on screen"
    monkeypatch.setattr(tray, "find_window", lambda title=tray.TITLE: 0)
    at_sign_in.window = SimpleNamespace(show=lambda: None)
    at_sign_in.show_window()
    assert at_sign_in.wifi.session_started, "Open TNT from the tray"
    off = tray.ClientApp(_args())
    off.wifi.set_enabled(False)
    off.window = SimpleNamespace(show=lambda: None)
    off.show_window()
    assert not off.wifi.session_started, "switched off: nothing starts"


def test_quit_and_shutdown_stop_the_wifi_survey(app, monkeypatch):
    stops = []
    monkeypatch.setattr(app.wifi, "stop", lambda timeout=2.0: stops.append(timeout))
    monkeypatch.setattr(app.tray, "stop", lambda: None)
    monkeypatch.setattr(tray, "release_single_instance", lambda: None)
    app.window = SimpleNamespace(destroy=lambda: None)
    app.quit()
    app._shutdown()
    assert stops == [1.0, 1.0]

    def boom(timeout=2.0):
        raise RuntimeError("stuck")

    monkeypatch.setattr(app.wifi, "stop", boom)
    app.stop_wifi_survey()                                     # logged, never raises


def test_bridge_exposes_the_wifi_methods_and_nothing_else_new():
    public = {n for n in dir(tray.JsBridge) if not n.startswith("_")}
    assert set(WIFI_BRIDGE_METHODS) <= public
    assert all(callable(getattr(tray.JsBridge, n)) for n in public), "pywebview would expose a public attribute's contents"


def test_bridge_functions_are_exposed_by_name_so_no_attribute_path_reaches_the_app(app, monkeypatch):
    """pywebview resolves a js_api call name as a dotted attribute path, underscores included, so a page that
    posted ``_app.wifi.survey`` or ``_app.quit`` used to reach ClientApp past every bridge method's own check.
    The window gets each public method through window.expose instead (looked up by exact name) and no js_api."""
    import inspect

    from webview import util as webview_util

    run_src = inspect.getsource(tray.ClientApp.run)
    assert "js_api" not in run_src.replace("# no js_api", "") and "self.window.expose(*bridge_functions(self.bridge))" in run_src
    functions = tray.bridge_functions(app.bridge)
    assert [f.__name__ for f in functions] == sorted(n for n in vars(tray.JsBridge) if not n.startswith("_"))
    assert all(getattr(f, "__self__", None) is app.bridge for f in functions)
    quits, results = [], []
    monkeypatch.setattr(app, "quit", lambda: quits.append(True))
    monkeypatch.setattr(app.wifi, "survey", lambda *a, **k: quits.append("survey"))
    app.window = _page(SERVICE)
    # what Window.expose builds, dispatched by pywebview's own bridge call
    window = SimpleNamespace(_functions={f.__name__: f for f in functions}, _js_api=None, evaluate_js=results.append)
    for path in ("_app.quit", "_app.wifi.survey", "_app.wifi._view_locked", "save_file.__func__.__globals__.clear",
                 "wifi_survey.__self__._app.quit", "_JsBridge__app"):
        webview_util.js_bridge_call(window, path, [], "probe")
    webview_util.js_bridge_call(window, "client_info", [], "ok")
    deadline = time.monotonic() + 5
    while not results and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.1)
    assert quits == [], "nothing but the exposed functions is callable"
    assert len(results) == 1 and '"version"' in results[0] and "client_info" in results[0]


@pytest.mark.parametrize("uri, ok", [
    (SERVICE, True), (SERVICE + "/#diagnostics", True), (SERVICE + "/index.html?x=1", True),
    ("data:text/html;charset=utf-8;base64,PGh0bWw+PGJvZHk+", True), ("about:blank", True), ("blob:" + SERVICE + "/5f0c", True),
    ("http://127.0.0.1:7131/", False), ("https://example.com/", False), ("file:///C:/Windows/", False),
    ("blob:https://example.com/5f0c", False), ("javascript:alert(1)", False), ("ms-settings:privacy-location", False),
    ("http://127.0.0.1:7130@example.com/", False), ("about:srcdoc", False), ("", False), (None, False), (7, False),
])
def test_navigation_allowed(uri, ok):
    assert tray.navigation_allowed(uri, SERVICE) is ok


def test_navigation_guard_keeps_the_window_on_the_dashboard(app, monkeypatch, caplog):
    import webbrowser

    opened = []
    monkeypatch.setattr(webbrowser, "open", lambda url, new=0: opened.append((url, new)))

    def navigate(uri, user=False):
        args = SimpleNamespace(Uri=uri, IsUserInitiated=user, Cancel=False)
        app._on_navigation_starting(None, args)
        return args.Cancel

    with caplog.at_level(logging.INFO, logger="client.tray"):
        assert navigate(SERVICE + "/#wifi", user=True) is False
        assert navigate("data:text/html;charset=utf-8;base64,PGh0bWw+", user=False) is False, "the inline starting page"
        assert navigate("https://example.com/docs?token=secret", user=True) is True
        assert navigate("http://127.0.0.1:9/", user=False) is True
        assert navigate("file:///C:/Users/", user=True) is True
        assert navigate("http://[::1/", user=True) is True, "a malformed URL is cancelled too"
    deadline = time.monotonic() + 5
    while not opened and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.1)
    assert opened == [("https://example.com/docs?token=secret", 2)], "only a clicked http(s) link opens in the browser"
    assert "token=secret" not in caplog.text and "https://example.com" in caplog.text, "only the origin is logged"
    app._on_navigation_starting(None, object())                 # never raises


def test_client_bundle_and_selfcheck_include_the_wifi_modules():
    import inspect

    source = inspect.getsource(tray.client_selfcheck)
    assert '"client.wifi_ies", "client.wifi_survey"' in source and "wifi_ies.self_test()" in source
    spec = (ROOT / "installer" / "tnt_client.spec").read_text(encoding="utf-8")
    assert '"client.wifi_ies", "client.wifi_survey"' in spec
