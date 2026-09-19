"""Settings > Tools: switching a main tool off takes its tile, its page and its automated work with it.

The point of the switch is the last of those. Hiding a tile is cosmetic; a site that has switched Speed off and
still finds a speed test running every fifteen minutes has been lied to. So most of what is pinned here is what
*stops*: the scheduler, the Full Scan's sections, and the routes that would make this PC do something.
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

import pytest

from tnt import config
# the shared mock server fixture
from tests.test_ui import mock  # noqa: F401

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "ui"


class FakeConfig:
    """Just the dotted read the helper makes."""

    def __init__(self, data: Optional[Dict[str, Any]] = None, raises: bool = False) -> None:
        self._data = data or {}
        self._raises = raises

    def get(self, dotted: str, default: Any = None) -> Any:
        if self._raises:
            raise RuntimeError("the settings could not be read")
        cur: Any = self._data
        for part in dotted.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        return default if cur is None else cur


# ---------------------------------------------------------------------------
# the setting itself
# ---------------------------------------------------------------------------
def test_every_switchable_tool_defaults_to_on():
    assert set(config.DEFAULTS["tools"]) == set(config.TOOLS)
    assert all(config.DEFAULTS["tools"][name] is True for name in config.TOOLS)


def test_the_six_are_the_ones_a_site_might_never_use():
    """Network info, Ping, Outages, Tools and Reports have no switch: they are the monitoring TNT exists to do."""
    assert config.TOOLS == ("speed", "discovery", "wifi", "capture", "proav", "sip")
    for always_on in ("ipinfo", "ping", "outages", "tools", "reports"):
        assert always_on not in config.TOOLS


def test_the_switches_are_coerced_to_booleans():
    """A hand-edited config is coerced the way every other boolean in this file is, so there is one rule for
    all of them rather than a special case here."""
    out = config.validate({"tools": {"speed": 0, "sip": None, "capture": 1}})["tools"]
    assert out["speed"] is False and out["capture"] is True and out["sip"] is False
    assert config.validate({"tools": {}})["tools"] == dict(config.DEFAULTS["tools"]), "a missing switch is on"


def test_a_tool_nobody_has_heard_of_is_on():
    assert config.tool_on(FakeConfig({"tools": {"ping": False}}), "ping") is True


def test_a_switch_that_cannot_be_read_leaves_the_tool_on():
    """A tool that disappeared because a settings read failed would be a far worse failure than one that stayed:
    the tech would be hunting a missing page, not a broken setting."""
    assert config.tool_on(FakeConfig(raises=True), "speed") is True
    assert config.tool_on(None, "speed") is True
    assert config.tool_on(FakeConfig({}), "speed") is True


def test_only_an_explicit_false_switches_a_tool_off():
    assert config.tool_on(FakeConfig({"tools": {"speed": False}}), "speed") is False
    assert config.tool_on(FakeConfig({"tools": {"speed": True}}), "speed") is True


def test_the_switch_survives_a_save_and_a_reload(tmp_path):
    path = tmp_path / "config.json"
    cfg = config.Config(path).load()
    cfg.update({"tools": {"proav": False}})
    assert config.Config(path).load().get("tools.proav") is False


# ---------------------------------------------------------------------------
# what stops
# ---------------------------------------------------------------------------
def test_the_speed_scheduler_does_not_schedule_when_the_tool_is_off():
    """The whole point: no test runs by itself. `speedtest.enabled` cannot override the tool being off."""
    from tnt.speedtest.scheduler import SpeedScheduler

    sched = SpeedScheduler.__new__(SpeedScheduler)
    sched._config = FakeConfig({"tools": {"speed": False}, "speedtest": {"enabled": True}})
    assert sched._enabled() is False

    sched._config = FakeConfig({"tools": {"speed": True}, "speedtest": {"enabled": True}})
    assert sched._enabled() is True
    sched._config = FakeConfig({"tools": {"speed": True}, "speedtest": {"enabled": False}})
    assert sched._enabled() is False, "the tool being on does not turn automatic tests on"


def test_an_unreadable_tools_block_leaves_the_scheduler_running():
    from tnt.speedtest.scheduler import SpeedScheduler

    sched = SpeedScheduler.__new__(SpeedScheduler)
    sched._config = FakeConfig(raises=True)
    assert sched._enabled() is True


@pytest.mark.parametrize("phase,tool,label", [("_speed_phase", "speed", "Speed"),
                                              ("_discovery_phase", "discovery", "Discovery"),
                                              ("_wifi_phase", "wifi", "WiFi")])
def test_a_full_scan_skips_the_section_of_a_tool_that_is_off(phase, tool, label):
    """A section for a tool the site switched off would be an empty section nobody asked for."""
    from tnt import reports

    mgr = reports.ReportManager.__new__(reports.ReportManager)
    mgr._config = FakeConfig({"tools": {tool: False}})
    seen = []
    mgr._phase_update = lambda scan, name, **kw: seen.append((name, kw.get("status"), kw.get("message")))
    getattr(mgr, phase)(SimpleNamespace(), {})
    assert len(seen) == 1, "the phase said one thing and did nothing else"
    name, status, message = seen[0]
    assert status == "skipped" and label in message and "Settings" in message


def test_a_full_scan_runs_the_section_when_the_tool_is_on():
    from tnt import reports

    mgr = reports.ReportManager.__new__(reports.ReportManager)
    mgr._config = FakeConfig({"tools": {"speed": True}})
    assert mgr._tool_on("speed") is True


# ---------------------------------------------------------------------------
# the API
# ---------------------------------------------------------------------------
def _routes(tools: Optional[Dict[str, Any]] = None):
    from tnt.api import routes

    engine = SimpleNamespace(config=FakeConfig({"tools": tools} if tools else {}))
    return routes, engine


def test_the_route_helper_reports_every_switch():
    routes, engine = _routes({"proav": False})
    on = routes._tools_on(engine)
    assert set(on) == set(config.TOOLS)
    assert on["proav"] is False and on["speed"] is True


def test_a_start_route_refuses_while_its_tool_is_off():
    """409, not 404: the route exists and works again the moment the toggle goes back on."""
    from tnt.api.routes import ApiError

    routes, engine = _routes({"capture": False})
    with pytest.raises(ApiError) as caught:
        routes._need_tool(engine, "capture")
    assert caught.value.status == 409 and caught.value.code == routes.TOOL_OFF_CODE
    assert "Packet capture" in str(caught.value) and "Settings" in str(caught.value)


def test_a_start_route_is_let_through_while_its_tool_is_on():
    routes, engine = _routes({"capture": True})
    assert routes._need_tool(engine, "capture") is None


def test_every_switchable_tool_has_a_name_a_person_would_recognise():
    from tnt.api import routes

    assert set(routes.TOOL_NAMES) == set(config.TOOLS)
    assert routes.TOOL_NAMES["capture"] == "Packet capture" and routes.TOOL_NAMES["proav"] == "Pro AV"


def test_every_route_that_makes_this_pc_do_something_is_gated():
    """A new start route that forgets the check would let a switched-off tool act. This is the list."""
    source = (ROOT / "tnt" / "api" / "routes.py").read_text(encoding="utf-8")
    for route, tool in (("/api/speedtests/run", "speed"), ("/api/discovery/scan", "discovery"),
                        ("/api/proav/scan", "proav"), ("/api/capture/start", "capture"),
                        ("/api/sip/alg", "sip"), ("/api/sip/stun", "sip"),
                        ("/api/sip/stun/lifetime", "sip"), ("/api/sip/flow", "sip")):
        block = source.split('@r.post("' + route + '")', 1)
        assert len(block) == 2, route
        head = block[1].split("@r.", 1)[0]
        assert f'_need_tool(engine, "{tool}")' in head, route


# ---------------------------------------------------------------------------
# the mock says the same thing as the service
# ---------------------------------------------------------------------------
def test_the_mock_knows_the_same_six_tools(mock):
    assert tuple(mock.mod.TOOLS) == config.TOOLS
    assert set(mock.mod.DEFAULTS["tools"]) == set(config.TOOLS)


def test_the_mock_status_carries_the_switches_and_drops_what_is_off(mock):
    state = mock.state
    try:
        assert state.status()["tools"] == {name: True for name in config.TOOLS}
        state.settings["tools"]["speed"] = False
        state.settings["tools"]["sip"] = False
        st = state.status()
        assert st["tools"]["speed"] is False and st["speed"] is None
        assert st["sip"] is None, "the qualifier's database reads go with the tile"
        assert st["capture"] is not None, "a tool that is still on is untouched"
    finally:
        state.settings["tools"] = {name: True for name in config.TOOLS}


def test_the_mock_refuses_a_start_route_like_the_service(mock):
    from tnt.api import routes

    state = mock.state
    try:
        state.settings["tools"]["proav"] = False
        with pytest.raises(mock.mod.ToolRefused) as caught:
            state._need_tool("proav") if hasattr(state, "_need_tool") else mock.mod.Handler._need_tool(state, "proav")
    finally:
        state.settings["tools"]["proav"] = True
    assert caught.value.status == 409 and caught.value.code == routes.TOOL_OFF_CODE
    assert "Pro AV" in str(caught.value)


# ---------------------------------------------------------------------------
# the page
# ---------------------------------------------------------------------------
def _read(rel: str) -> str:
    return (UI / rel).read_text(encoding="utf-8")


def test_the_page_knows_the_same_six_tools():
    app = _read("js/app.js")
    listed = re.search(r"const TOOLS = \[(.*?)\];", app).group(1)
    assert [n.strip().strip("'") for n in listed.split(",")] == list(config.TOOLS)
    names = re.search(r"const TOOL_NAMES = \{(.*?)\};", app, re.S).group(1)
    for name in config.TOOLS:
        assert name in names and name in app


def test_a_tool_that_is_off_has_no_tile_and_no_page():
    app = _read("js/app.js")
    assert "function syncTools()" in app and "tile.hidden = !on" in app
    # the router sends a switched-off view to the landing page rather than mounting it
    assert "VIEW_NAMES.includes(hash) && toolOn(hash) ? hash : 'ipinfo'" in app
    # and the shortcut strip hides its square rather than being rebuilt (which would double its listeners)
    assert "a.hidden = !toolOn(view)" in app
    body = app.split("function syncTools()", 1)[1].split("\n  function ", 1)[0]
    code = "\n".join(line.split("//")[0] for line in body.splitlines())   # the comment says why, and names it
    assert "buildJumps()" not in code, "rebuilding the strip would leave two rows and two scroll listeners"


def test_the_settings_dialog_leads_with_the_tools_and_ends_with_the_service():
    app = _read("js/app.js")
    body = app.split("async function openSettings()", 1)[1].split("\n  function ", 1)[0]
    order = re.findall(r"(?:group|tileGroup)\((?:'(\w+)', )?'([^']+)'", body)
    titles = [t for _view, t in order]
    assert titles[0] == "Tools", titles
    assert titles[-1] == "Service", titles
    # app-wide first, then one section per tile
    assert titles[:3] == ["Tools", "General", "Updates"], titles
    assert [v for v, _t in order if v] == ["ipinfo", "ping", "speed", "sip"], order


def test_the_per_tile_sections_wear_their_own_tile_colour():
    app = _read("js/app.js")
    assert "ACCENT[view] || 'var(--blue)'" in app and "TILE_ICONS[view]" in app
    css = _read("css/tnt.css")
    assert ".setting-group.tile-group" in css and "color-mix(in srgb, var(--accent)" in css


def test_the_controls_line_up_in_one_column():
    """Every toggle track starts at the same x whatever its labels say — the dialog used to space-between them,
    so "Unloaded Loaded" and "Ask Auto" pushed their tracks to different places."""
    css = _read("css/tnt.css")
    setting = re.search(r"\n\.setting \{([^}]*)\}", css).group(1)
    assert "grid" in setting and "--setting-control" in setting
    assert "space-between" not in setting
    assert ".setting-control .toggle {" in css
    app = _read("js/app.js")
    assert "class: 'setting-control'" in app, "every row wraps its control in the fixed column"


def test_the_app_wide_toggles_no_longer_each_pick_their_own_colour():
    """They took --green, --purple and --blue at random. App-wide controls use the dialog's own accent now, and
    a control inside a tile section inherits that tile's."""
    app = _read("js/app.js")
    body = app.split("async function openSettings()", 1)[1].split("\n  function ", 1)[0]
    general = body.split("group('General'", 1)[0].split("body.appendChild(group('Tools'", 1)[1]
    assert "accent: 'var(--green)'" not in general and "accent: 'var(--purple)'" not in general


def test_export_pdf_is_gone_from_settings():
    """The Reports page exports a real report; this exported a thinner one from the same data."""
    app = _read("js/app.js")
    body = app.split("async function openSettings()", 1)[1].split("\n  function ", 1)[0]
    assert "Export PDF" not in body and "exportPdf" not in body
    # but the Reports page still has it, so the API and the blob helper are not orphaned
    assert "TNT.app.saveBlob" in _read("js/views/reports.js")
    assert "exportPdf:" in _read("js/api.js")


def test_the_github_link_sits_above_diagnostics():
    app = _read("js/app.js")
    body = app.split("async function openSettings()", 1)[1].split("\n  function ", 1)[0]
    assert "TNT_REPO_URL" in body and "TNT on GitHub" in body
    assert body.index("repoLink") < body.index("h('div', { class: 'row' }, diagBtn)")
    # it opens the way every other external link does, not by navigating the app's own window
    assert "openExternal(e, TNT_REPO_URL)" in body
    url = re.search(r"const TNT_REPO_URL = '([^']+)'", app).group(1)
    from tnt.updater import REPO

    assert url == "https://github.com/" + REPO


def test_the_sip_tile_says_jitter_not_jit():
    app = _read("js/app.js")
    assert "'</span><span class=\"muted\">jitter</span>'" in app
    assert ">jit<" not in app
