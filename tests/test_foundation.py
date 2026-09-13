import time

from tnt import config, db, events


def test_config_validate_clamps_and_enums(data_dir):
    c = config.Config().load()
    assert c.get("api.port") == 7130
    changed = c.update({"ping": {"loaded": False, "timeout_ms": 999999}, "speedtest": {"backend": "bogus"}})
    assert "ping.loaded" in changed and "ping.timeout_ms" in changed
    assert c.get("ping.timeout_ms") == 10000
    assert c.get("speedtest.backend") == "auto"
    assert c.ping_bytes == 32
    c2 = config.Config().load()
    assert c2.get("ping.loaded") is False


def test_config_update_section_defaults_and_validation(data_dir):
    c = config.Config().load()
    assert c.get("update") == {"enabled": True, "auto_install": False, "check_interval_h": 24, "channel": "stable"}
    changed = c.update({"update": {"enabled": "yes", "auto_install": 1, "check_interval_h": 9999, "channel": "bogus"}})
    # enabled default True and "yes"->True is no change; auto_install and the interval do change
    assert {"update.auto_install", "update.check_interval_h"} <= changed
    assert c.get("update.enabled") is True and c.get("update.auto_install") is True    # coerced to bool
    assert c.get("update.check_interval_h") == 168                                     # clamped (1..168)
    assert c.get("update.channel") == "stable"                                         # bad enum -> default
    assert c.update({"update": {"channel": "prerelease", "check_interval_h": 0}}) and c.get("update.channel") == "prerelease"
    assert c.get("update.check_interval_h") == 1


def test_config_accepts_a_utf8_byte_order_mark(data_dir):
    """A config.json saved "UTF-8 with BOM" (Notepad on older Windows 10, PowerShell 5.1) is
    read normally: it used to be renamed to .corrupt and every setting reset to the defaults."""
    import json

    path = data_dir / "config.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"ping": {"loaded": False}, "discovery": {"ports": [80, 9000]}}).encode("utf-8"))
    c = config.Config(path).load()
    assert c.get("ping.loaded") is False
    assert c.get("discovery.ports") == [80, 9000]
    assert not (data_dir / "config.json.corrupt").exists(), "a BOM is not corruption"
    # real garbage is still set aside, and the defaults still apply
    path.write_text("{not json", encoding="utf-8")
    assert config.Config(path).load().get("ping.loaded") is True
    assert (data_dir / "config.json.corrupt").exists()


def test_config_migrates_legacy_port_list(data_dir):
    import json

    path = data_dir / "config.json"
    # a config.json saved before 22 joined the defaults: upgraded and persisted
    path.write_text(json.dumps({"discovery": {"ports": [80, 443, 554, 7001, 8000, 8080, 8443]}}), encoding="utf-8")
    c = config.Config(path).load()
    assert c.get("discovery.ports") == config.DEFAULT_PORTS
    assert json.loads(path.read_text(encoding="utf-8"))["discovery"]["ports"] == config.DEFAULT_PORTS
    # ... and again for the list saved before 5060 (SIP, the Phone category) joined them
    path.write_text(json.dumps({"discovery": {"ports": [22, 80, 443, 554, 7001, 8000, 8080, 8443]}}), encoding="utf-8")
    assert config.Config(path).load().get("discovery.ports") == config.DEFAULT_PORTS
    assert 5060 in config.DEFAULT_PORTS
    # a list the user edited is theirs
    path.write_text(json.dumps({"discovery": {"ports": [80, 9000]}}), encoding="utf-8")
    assert config.Config(path).load().get("discovery.ports") == [80, 9000]


# --------------------------------------------------------------------------- upgrade from 1.6.1
#: The settings 1.7.0 removed with the external speed-test CLI and network scanner support.
REMOVED_1_7_0 = {"speedtest.ookla_path", "speedtest.ookla_server_id", "discovery.use_nmap", "discovery.nmap_path"}

#: config.json as TNT 1.6.1 saved it: the full DEFAULTS structure of that release (the removed
#: settings included) with a technician's edits in every section.
CONFIG_1_6_1 = {
    "api": {"host": "127.0.0.1", "port": 7130},
    "ping": {"interval_s": 2.0, "timeout_ms": 1500, "loaded": False, "loaded_bytes": 1200, "unloaded_bytes": 32,
             "ttl": 64, "resolve_interval_s": 600},
    "outage": {"miss_threshold": 5, "recover_threshold": 2},
    "thresholds": {"window_s": 120, "local_warn_ms": 20, "internet_warn_ms": 120, "warn_loss_pct": 1.5,
                   "bad_loss_pct": 10.0},
    "speedtest": {"enabled": False, "interval_min": 30, "backend": "ookla",
                  "ookla_path": "C:\\Program Files\\TNT\\bin\\speedtest.exe", "ookla_server_id": 1234,
                  "download_mb": 25, "upload_mb": 10, "duration_s": 6, "connections": 2, "timeout_s": 90,
                  "warn_below_pct": 40},
    "discovery": {"ports": [22, 80, 443, 9000], "ping_timeout_ms": 400, "ping_attempts": 3, "port_timeout_ms": 500,
                  "concurrency": 64, "use_nmap": "always", "nmap_path": "C:\\Program Files (x86)\\Nmap\\nmap.exe",
                  "resolve_hostnames": False, "max_hosts": 1024},
    "retention": {"days": 90},
    "map": {"internet_host": "example.com"},
    "ui": {"theme": "dark", "show_ipv6": True},
    "lan": {"enabled": False},
    "targets": {"defaults_extra": ["1.1.1.1", "totalelectronics.com", "9.9.9.9"]},
    "dhcp": {"adapter": "Ethernet 2", "pool_start": "192.168.50.20", "pool_end": "192.168.50.30", "pool_size": 11,
             "lease_s": 7200, "static_ip": "192.168.50.1", "static_prefix": 24, "ping_check": False,
             "scan_wait_s": 10},
}


def _flatten(d, prefix=""):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(_flatten(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def _no_env_overrides(monkeypatch):
    for name in ("PORT", "HOST", "TNT_PORT", "TNT_HOST"):
        monkeypatch.delenv(name, raising=False)


def test_config_1_6_1_fixture_is_the_defaults_structure_plus_the_removed_settings():
    flat = _flatten(CONFIG_1_6_1)
    assert REMOVED_1_7_0 <= set(flat)
    assert set(flat) - REMOVED_1_7_0 <= set(_flatten(config.DEFAULTS))
    assert not REMOVED_1_7_0 & set(_flatten(config.DEFAULTS))


def test_config_upgrade_from_1_6_1_keeps_every_setting_and_drops_the_removed_ones(data_dir, monkeypatch, caplog):
    import json

    _no_env_overrides(monkeypatch)
    path = data_dir / "config.json"
    path.write_text(json.dumps(CONFIG_1_6_1, indent=2), encoding="utf-8")      # exactly how 1.6.1 saved it
    expected = {k: v for k, v in _flatten(CONFIG_1_6_1).items() if k not in REMOVED_1_7_0}
    expected["speedtest.backend"] = "auto"                                         # the CLI backend is gone

    with caplog.at_level("INFO", logger="tnt.config"):
        c = config.Config(path).load()
    assert not (data_dir / "config.json.corrupt").exists(), "an old config is not corruption"
    snap = _flatten(c.snapshot())
    assert {k: snap.get(k) for k in expected} == expected
    assert not REMOVED_1_7_0 & set(snap)
    notes = [r.getMessage() for r in caplog.records if "config migration" in r.getMessage()]
    assert len(notes) == 1 and all(k in notes[0] for k in sorted(REMOVED_1_7_0 | {"speedtest.backend"}))

    # the file was rewritten straight away without the removed settings ...
    on_disk = _flatten(json.loads(path.read_text(encoding="utf-8")))
    assert {k: on_disk.get(k) for k in expected} == expected and not REMOVED_1_7_0 & set(on_disk)
    # ... loading it again changes nothing and writes nothing
    before = path.read_bytes()
    again = config.Config(path).load()
    assert again.snapshot() == c.snapshot() and path.read_bytes() == before
    # a later save (any settings change) keeps it clean
    assert c.update({"ping": {"ttl": 128}}) == {"ping.ttl"}
    on_disk = _flatten(json.loads(path.read_text(encoding="utf-8")))
    assert on_disk["ping.ttl"] == 128 and on_disk["speedtest.interval_min"] == 30 and not REMOVED_1_7_0 & set(on_disk)


def test_config_upgrade_from_an_untouched_1_6_1_config(data_dir, monkeypatch):
    """The common case: 1.6.1 wrote its defaults, removed settings included, and nobody edited them."""
    import copy
    import json

    _no_env_overrides(monkeypatch)
    old = copy.deepcopy(config.DEFAULTS)
    old["speedtest"].update({"backend": "auto", "ookla_path": "", "ookla_server_id": None})
    old["discovery"].update({"use_nmap": "auto", "nmap_path": ""})
    path = data_dir / "config.json"
    path.write_text(json.dumps(old, indent=2), encoding="utf-8")
    c = config.Config(path).load()
    assert c.snapshot() == config.DEFAULTS
    assert json.loads(path.read_text(encoding="utf-8")) == config.DEFAULTS


def test_config_removed_settings_are_never_stored(data_dir, monkeypatch):
    import json

    _no_env_overrides(monkeypatch)
    cleaned = config.validate({"speedtest": {"backend": "ookla", "ookla_path": "C:\\x\\speedtest.exe", "ookla_server_id": 7},
                               "discovery": {"use_nmap": "always", "nmap_path": "C:\\x"}})
    assert cleaned["speedtest"]["backend"] == "auto" and "ookla_path" not in cleaned["speedtest"]
    assert "ookla_server_id" not in cleaned["speedtest"]
    assert "use_nmap" not in cleaned["discovery"] and "nmap_path" not in cleaned["discovery"]
    # a hand-edited file holding only the retired backend value is migrated and rewritten too
    path = data_dir / "config.json"
    path.write_text(json.dumps({"speedtest": {"backend": "ookla", "interval_min": 45}}), encoding="utf-8")
    c = config.Config(path).load()
    assert c.get("speedtest.backend") == "auto" and c.get("speedtest.interval_min") == 45
    assert json.loads(path.read_text(encoding="utf-8"))["speedtest"]["backend"] == "auto"
    # update(): removed keys are dropped (not reported as changed), a retired backend value becomes "auto"
    c.update({"speedtest": {"backend": "fastcom"}})
    changed = c.update({"speedtest": {"backend": "ookla", "ookla_path": "C:\\x\\speedtest.exe"},
                        "discovery": {"use_nmap": "always"}})
    assert changed == {"speedtest.backend"} and c.get("speedtest.backend") == "auto"
    assert c.get("speedtest.ookla_path") is None and c.get("discovery.use_nmap") is None
    on_disk = _flatten(json.loads(path.read_text(encoding="utf-8")))
    assert not REMOVED_1_7_0 & set(on_disk)
    # unlike a key this version never knew, which is still kept (forward compatibility)
    assert c.update({"speedtest": {"future_option": 1}}) == {"speedtest.future_option"}
    assert c.get("speedtest.future_option") == 1


def test_config_upgrade_of_a_read_only_1_6_1_config(data_dir, monkeypatch, caplog):
    """The migration rewrite is best effort: a config.json that cannot be written (read-only
    attribute) still loads with every setting migrated in memory, and the engine does not report a
    degraded config. The file keeps the retired keys (nothing reads them) and no .json.tmp is left."""
    import json
    import os
    import stat

    from tnt.engine import Engine

    _no_env_overrides(monkeypatch)
    path = data_dir / "config.json"
    path.write_text(json.dumps(CONFIG_1_6_1, indent=2), encoding="utf-8")
    before = path.read_bytes()
    expected = {k: v for k, v in _flatten(CONFIG_1_6_1).items() if k not in REMOVED_1_7_0}
    expected["speedtest.backend"] = "auto"
    os.chmod(path, stat.S_IREAD)
    try:
        with caplog.at_level("WARNING", logger="tnt.config"):
            c = config.Config(path).load()
        snap = _flatten(c.snapshot())
        assert {k: snap.get(k) for k in expected} == expected and not REMOVED_1_7_0 & set(snap)
        assert path.read_bytes() == before
        assert not (data_dir / "config.json.tmp").exists() and not (data_dir / "config.json.corrupt").exists()
        assert any("could not rewrite" in r.getMessage() for r in caplog.records)

        eng = Engine(console=True, port=0, data_dir=data_dir)
        eng._start_config()
        assert "config" not in eng.errors and eng.config.get("speedtest.backend") == "auto"
        assert eng.config.get("speedtest.interval_min") == 30 and not (data_dir / "config.json.tmp").exists()
    finally:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    # once the file is writable again the next start finishes the migration
    config.Config(path).load()
    assert not REMOVED_1_7_0 & set(_flatten(json.loads(path.read_text(encoding="utf-8"))))


def test_config_save_failure_leaves_no_tmp_file(data_dir, monkeypatch):
    import pytest

    c = config.Config(data_dir / "config.json").load()

    def refuse(src, dst):
        raise PermissionError(13, "Access is denied", str(dst))

    monkeypatch.setattr(config.os, "replace", refuse)
    with pytest.raises(PermissionError):
        c.update({"ping": {"ttl": 64}})
    assert not (data_dir / "config.json.tmp").exists()


def test_config_section_that_is_not_an_object_falls_back_alone(data_dir, monkeypatch, caplog):
    """A hand-edited ``"speedtest": null`` used to make validate() raise, so load() failed and
    every setting ran on its default. Now only that section does; a patch doing the same is refused."""
    import json

    import pytest

    _no_env_overrides(monkeypatch)
    raw = json.loads(json.dumps(CONFIG_1_6_1))
    raw["speedtest"] = None
    raw["discovery"] = "garbage"
    raw["retention"] = [365]
    path = data_dir / "config.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with caplog.at_level("WARNING", logger="tnt.config"):
        c = config.Config(path).load()
    assert c.section("speedtest") == config.DEFAULTS["speedtest"]
    assert c.section("discovery") == config.DEFAULTS["discovery"]
    assert c.section("retention") == config.DEFAULTS["retention"]
    assert c.get("ping.ttl") == 64 and c.get("ui.theme") == "dark" and c.get("dhcp.adapter") == "Ethernet 2"
    warned = " ".join(r.getMessage() for r in caplog.records)
    assert all(f"'{name}'" in warned for name in ("speedtest", "discovery", "retention"))
    assert config.validate({"ping": 5})["ping"] == config.DEFAULTS["ping"]

    for bad in ({"speedtest": None}, {"ui": "dark"}, {"targets": ["1.1.1.1"]}):
        with pytest.raises(ValueError, match="must be an object"):
            c.update(bad)
    assert c.get("ui.theme") == "dark"
    assert c.update({"future_section": 1}) == {"future_section"}      # unknown top-level keys are still kept


def test_config_network_poll_interval_default_and_clamps(data_dir):
    c = config.Config().load()
    assert c.get("network.poll_s") == 5 and config.DEFAULTS["network"] == {"poll_s": 5}
    assert config.validate({"network": {"poll_s": 1}})["network"]["poll_s"] == 2
    assert config.validate({"network": {"poll_s": 3600}})["network"]["poll_s"] == 60
    assert config.validate({"network": {"poll_s": "fast"}})["network"]["poll_s"] == 5
    assert c.update({"network": {"poll_s": 10}}) == {"network.poll_s"}
    assert config.Config().load().get("network.poll_s") == 10


def test_config_geoip_enabled_default_and_bool(data_dir):
    import pytest

    assert config.DEFAULTS["geoip"] == {"enabled": True}
    c = config.Config().load()
    assert c.get("geoip.enabled") is True
    assert config.validate({"geoip": {"enabled": 0}})["geoip"]["enabled"] is False
    assert config.validate({"geoip": {"enabled": "yes"}})["geoip"]["enabled"] is True
    assert config.validate({})["geoip"] == {"enabled": True}          # a 1.11 config gains the key in memory
    assert c.update({"geoip": {"enabled": False}}) == {"geoip.enabled"}
    assert config.Config().load().get("geoip.enabled") is False
    with pytest.raises(ValueError, match="must be an object"):
        c.update({"geoip": "x"})
    assert c.get("geoip.enabled") is False


def test_paths_geoip_dir_follows_data_dir(data_dir):
    from tnt import paths

    assert paths.geoip_dir() == data_dir / "geoip"
    assert not paths.geoip_dir().exists()      # ensure_dirs() leaves it alone: the IP location manager creates it lazily


def test_db_roundtrip(data_dir):
    d = db.Database(data_dir / "t.db")
    t = d.add_target("1.1.1.1")
    assert d.add_target("1.1.1.1")["id"] == t["id"]
    now = int(time.time() // 60 * 60)
    d.upsert_ping_minute(t["id"], now, 30, 29, 20.0, 18, 25)
    d.upsert_ping_minute(t["id"], now, 30, 30, 22.0, 17, 30)
    s = d.ping_summary(t["id"], now - 60, now + 60)
    assert s["sent"] == 60 and s["received"] == 59 and s["min_ms"] == 17 and s["max_ms"] == 30
    oid = d.open_outage("target", t["id"], time.time() - 100)
    d.close_outage(oid, time.time(), 5)
    assert len(d.list_outages(time.time() - 3600, time.time())) == 1
    d.add_speedtest({"ts": time.time(), "ok": True, "backend": "cloudflare", "download_mbps": 1.0})
    assert d.last_speedtest()["download_mbps"] == 1.0
    assert d.retention(365)["ping_minutes"] == 0
    d.close()


def test_event_bus_isolates_bad_subscriber():
    bus = events.EventBus()
    seen = []
    bus.subscribe(lambda e: 1 / 0)
    bus.subscribe(lambda e: seen.append(e["type"]))
    bus.publish("x", {"a": 1})
    assert seen == ["x"]
