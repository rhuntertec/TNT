"""Local-security regressions: loopback-only API host, Host/Origin checks."""
import json
import os
import http.client
import threading

import pytest

from tnt import config
from tnt.api import server as api_server


# --------------------------------------------------------------------------- config hardening
def test_api_host_is_forced_to_loopback():
    for host in ("0.0.0.0", "10.0.0.5", "example.com", "", None, "::"):
        assert config.validate({"api": {"host": host}})["api"]["host"] == "127.0.0.1", host
    for host in ("127.0.0.1", "localhost", "::1", "127.0.0.2"):
        assert config.validate({"api": {"host": host}})["api"]["host"] == host


def test_non_finite_numbers_fall_back_to_defaults():
    cfg = config.validate({"ping": {"timeout_ms": float("inf")}, "speedtest": {"interval_min": float("nan")},
                           "discovery": {"ports": [float("inf"), 80], "concurrency": True}})
    assert cfg["ping"]["timeout_ms"] == config.DEFAULTS["ping"]["timeout_ms"]
    assert cfg["speedtest"]["interval_min"] == config.DEFAULTS["speedtest"]["interval_min"]
    assert cfg["discovery"]["ports"] == [80]
    assert cfg["discovery"]["concurrency"] == config.DEFAULTS["discovery"]["concurrency"]


def test_no_setting_names_a_program_to_run():
    """The service runs as LocalSystem: a setting naming an executable, or a folder to find one in,
    would let whoever can change settings run a program as SYSTEM. 1.7.0 removed the last ones (the
    speed-test CLI and scanner paths); a new setting must not bring the pattern back. (That no
    speed test or scan starts a process is checked in test_speedtest.py and test_discovery.py.)"""
    def flatten(d, prefix=""):
        out = {}
        for k, v in d.items():
            if isinstance(v, dict):
                out.update(flatten(v, f"{prefix}{k}."))
            else:
                out[f"{prefix}{k}"] = v
        return out

    flat = flatten(config.DEFAULTS)
    words = ("path", "exe", "dir", "folder", "cmd", "command", "program", "binary", "bin", "executable")
    named = [k for k in flat if any(k.rsplit(".", 1)[-1].lower() == w or k.lower().endswith("_" + w) for w in words)]
    assert named == [], f"settings that look like they name a program or its folder: {named}"
    programs = [k for k, v in flat.items() if isinstance(v, str) and v.lower().endswith((".exe", ".bat", ".cmd", ".ps1", ".msi", ".dll"))]
    assert programs == []
    # the removed ones stay removed wherever a config comes from
    cleaned = flatten(config.validate({"speedtest": {"ookla_path": "C:/x/speedtest.exe"}, "discovery": {"nmap_path": "C:/x"}}))
    assert not {"speedtest.ookla_path", "discovery.nmap_path"} & set(cleaned)


def test_env_overrides_apply_in_memory_but_are_not_persisted(tmp_path, monkeypatch):
    monkeypatch.setenv("TNT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PORT", "7139")
    monkeypatch.setenv("HOST", "0.0.0.0")   # not loopback -> ignored
    monkeypatch.delenv("TNT_SERVICE_MODE", raising=False)
    c = config.Config(tmp_path / "config.json").load()
    assert c.get("api.port") == 7139
    assert c.get("api.host") == "127.0.0.1"
    c.update({"ping": {"loaded": False}})
    on_disk = json.loads((tmp_path / "config.json").read_text())
    assert on_disk["api"]["port"] == config.DEFAULT_PORT  # env override never written
    assert on_disk["ping"]["loaded"] is False
    # the generic PORT is ignored in service mode, TNT_PORT is not
    monkeypatch.setenv("TNT_SERVICE_MODE", "1")
    c2 = config.Config(tmp_path / "config.json").load()
    assert c2.get("api.port") == config.DEFAULT_PORT
    monkeypatch.setenv("TNT_PORT", "7138")
    c3 = config.Config(tmp_path / "config.json").load()
    assert c3.get("api.port") == 7138


# --------------------------------------------------------------------------- Host / Origin checks
@pytest.mark.parametrize("host,ok", [
    ("127.0.0.1:7130", True), ("localhost:7130", True), ("[::1]:7130", True), ("127.0.0.1", True),
    ("LOCALHOST:7130", True), ("127.0.0.5:7130", True),
    ("evil.example.com:7130", False), ("127.0.0.1.evil.com:7130", False), ("localhost:9999", False),
    ("10.0.0.5:7130", False), ("[::1]", True), ("[::1]x:7130", False), ("localhost:abc", False),
])
def test_host_allowed(host, ok):
    assert api_server.host_allowed(host, 7130) is ok


@pytest.mark.parametrize("origin,ok", [
    ("http://127.0.0.1:7130", True), ("http://localhost:7130", True), ("http://[::1]:7130", True),
    ("", True), ("null", False), ("http://evil.example.com", False), ("https://127.0.0.1:7130", False),
    ("http://127.0.0.1:7131", False),
])
def test_origin_allowed(origin, ok):
    assert api_server.origin_allowed(origin, 7130) is ok


class _FakeEngine:
    version = "0.0-test"
    bus = None

    def __init__(self):
        self.calls = []


def _start_server(tmp_path):
    engine = _FakeEngine()
    srv = api_server.ApiServer(engine, "127.0.0.1", 0)
    srv.start()
    return srv, engine


def _request(port, method, path, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def test_server_rejects_rebound_host_and_cross_origin_mutations(tmp_path):
    try:
        srv, _ = _start_server(tmp_path)
    except Exception as exc:  # noqa: BLE001 - constructor signature drift is reported, not hidden
        pytest.skip(f"ApiServer could not be started with a fake engine: {exc}")
    port = srv.port
    try:
        status, _ = _request(port, "GET", "/api/health", {"Host": f"127.0.0.1:{port}"})
        assert status == 200
        status, body = _request(port, "GET", "/api/health", {"Host": "attacker.example:80"})
        assert status == 403 and b"Host" in body
        # cross-site browser POST is refused even though the TCP peer is loopback
        status, _ = _request(port, "POST", "/api/monitoring/pause",
                             {"Host": f"localhost:{port}", "Origin": "http://evil.example", "Content-Length": "0"})
        assert status == 403
        status, _ = _request(port, "POST", "/api/monitoring/pause",
                             {"Host": f"localhost:{port}", "Sec-Fetch-Site": "cross-site", "Content-Length": "0"})
        assert status == 403
        # same-origin browser requests and header-less scripts get through to the router
        for hdrs in ({"Host": f"127.0.0.1:{port}", "Origin": f"http://127.0.0.1:{port}", "Content-Length": "0"},
                     {"Host": f"127.0.0.1:{port}", "Content-Length": "0"}):
            status, _ = _request(port, "POST", "/api/monitoring/pause", hdrs)
            assert status != 403
    finally:
        srv.stop(timeout=3)
