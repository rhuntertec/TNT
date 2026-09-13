"""Tests for tnt.updater: version logic, release/asset/checksum selection, and the check + verify + install
flow driven with a fake GitHub and a fake installer launcher (no network, nothing is ever executed)."""
from __future__ import annotations

import hashlib
import io
import json
import os

import pytest

from tnt import config as cfgmod
from tnt import updater
from tnt.updater import (UpdateManager, display_version, is_newer, parse_version, parse_checksum,
                         pick_checksum_asset, pick_setup_asset, relaunch_command, select_release)

SETUP = "TNT-Setup-1.16.0.exe"
ASSETS = [{"name": SETUP, "size": 42, "browser_download_url": "https://dl/x/s.exe"},
          {"name": SETUP + ".sha256", "size": 80, "browser_download_url": "https://dl/x/s.sha256"}]
REL_STABLE = {"tag_name": "v1.16.0", "draft": False, "prerelease": False, "html_url": "https://n/1.16.0",
              "assets": ASSETS, "published_at": "2026-09-13T12:00:00Z"}
REL_PRE = {"tag_name": "v1.17.0-rc.1", "draft": False, "prerelease": True, "assets": ASSETS}
REL_DRAFT = {"tag_name": "v2.0.0", "draft": True, "prerelease": False, "assets": ASSETS}


# --------------------------------------------------------------------------- pure helpers
class TestVersion:
    def test_parse_and_display(self):
        assert parse_version("v1.16.0") == (1, 16, 0, 1, ())
        assert parse_version("1.16.0")[:4] == (1, 16, 0, 1)
        assert parse_version("1.16.0-rc.1")[3] == 0        # a pre-release ranks below the release
        assert parse_version("bogus") is None and parse_version(None) is None
        assert display_version("v1.16.0") == "1.16.0" and display_version("1.16.0") == "1.16.0"

    @pytest.mark.parametrize("a,b,newer", [
        ("1.16.0", "1.15.0", True),
        ("1.15.0", "1.15.0", False),
        ("1.15.0", "1.16.0", False),
        ("v1.16.0", "1.15.9", True),
        ("1.16.0", "1.16.0-rc.1", True),        # the release beats its own pre-release
        ("1.16.0-rc.1", "1.16.0", False),
        ("1.16.0-rc.2", "1.16.0-rc.1", True),
        ("2.0.0", "1.99.99", True),
    ])
    def test_is_newer(self, a, b, newer):
        assert is_newer(a, b) is newer

    def test_is_newer_needs_both_to_parse(self):
        assert is_newer("bogus", "1.0.0") is False and is_newer("1.0.0", "bogus") is False


class TestSelectRelease:
    def test_stable_picks_newest_release(self):
        assert select_release([REL_STABLE, REL_PRE, REL_DRAFT], "stable", "1.15.0")["tag_name"] == "v1.16.0"

    def test_prerelease_channel_includes_prereleases(self):
        assert select_release([REL_STABLE, REL_PRE, REL_DRAFT], "prerelease", "1.15.0")["tag_name"] == "v1.17.0-rc.1"

    def test_drafts_are_never_eligible(self):
        assert select_release([REL_DRAFT], "prerelease", "1.0.0") is None

    def test_nothing_newer(self):
        assert select_release([REL_STABLE], "stable", "1.16.0") is None
        assert select_release([REL_STABLE], "stable", "1.17.0") is None

    def test_empty(self):
        assert select_release([], "stable", "1.15.0") is None and select_release(None, "stable", "1.0.0") is None


class TestAssetsAndChecksum:
    def test_pick_setup_asset(self):
        assert pick_setup_asset(ASSETS)["name"] == SETUP
        assert pick_setup_asset([{"name": "notes.txt"}]) is None
        assert pick_setup_asset([]) is None

    def test_pick_checksum_prefers_per_file(self):
        assert pick_checksum_asset(ASSETS, SETUP)["name"] == SETUP + ".sha256"

    def test_pick_checksum_falls_back_to_shared_list(self):
        a = [ASSETS[0], {"name": "SHA256SUMS", "browser_download_url": "https://dl/sums"}]
        assert pick_checksum_asset(a, SETUP)["name"] == "SHA256SUMS"
        assert pick_checksum_asset([ASSETS[0]], SETUP) is None

    def test_parse_checksum_forms(self):
        h = "ab" * 32
        assert parse_checksum(h + "  " + SETUP, SETUP) == h
        assert parse_checksum(h + " *" + SETUP, SETUP) == h
        assert parse_checksum("# a comment\n" + h + "  " + SETUP + "\n", SETUP) == h
        assert parse_checksum(h, SETUP) == h                       # a bare hex file
        assert parse_checksum(("cd" * 32) + "  other.exe", SETUP) is None
        assert parse_checksum("not a hash", SETUP) is None

    def test_relaunch_command_uses_cmd_not_tnt(self):
        cmd = relaunch_command(r"C:\Program Files\TNT\TNT.exe", 5)
        assert cmd[0] == "cmd.exe" and "TNT.exe" in cmd[-1] and "start" in cmd[-1]


# --------------------------------------------------------------------------- fakes
class FakeResp:
    def __init__(self, status, body=b"", host="api.github.com", headers=None):
        self.status = status
        self._buf = io.BytesIO(body)
        self.headers = headers if headers is not None else {"content-length": str(len(body))}
        self.host = host

    def read_all(self, cap):
        return self._buf.read(cap + 1)

    def readinto(self, b):
        d = self._buf.read(len(b))
        b[:len(d)] = d
        return len(d)

    def close(self):
        pass

    def abort(self):
        pass


def make_manager(tmp_path, urlopen, launched, **cfg):
    config = cfgmod.Config(tmp_path / "config.json")
    if cfg:
        config.update({"update": cfg}, persist=False)
    return UpdateManager(config, None, current_version="1.15.0", urlopen=urlopen,
                         installer_launch=lambda exe: launched.append(exe),
                         temp_dir_fn=lambda: tmp_path / "dl")


def gh(rel=REL_STABLE, exe_body=b"INSTALLER", checksum=None):
    """A fake ``urlopen`` serving one release + its asset + its checksum."""
    digest = hashlib.sha256(exe_body).hexdigest() if checksum is None else checksum

    def opener(url, timeout=30.0, headers=None, max_redirects=5):
        if url == updater.LATEST_URL:
            return FakeResp(200, json.dumps(rel).encode()) if rel else FakeResp(404)
        if url == updater.RELEASES_URL:
            return FakeResp(200, json.dumps([rel] if rel else []).encode())
        if url.endswith("/s.exe"):
            return FakeResp(200, exe_body, host="objects.githubusercontent.com")
        if url.endswith("/s.sha256"):
            return FakeResp(200, (digest + "  " + SETUP).encode() if digest is not None else b"", host="objects.githubusercontent.com") if digest is not None else FakeResp(404)
        return FakeResp(404)
    return opener, digest


# --------------------------------------------------------------------------- manager
class TestStatus:
    def test_status_shape(self, tmp_path):
        um = make_manager(tmp_path, gh()[0], [])
        st = um.status()
        assert set(st.keys()) == set(updater.STATUS_KEYS)
        assert st["enabled"] is True and st["current_version"] == "1.15.0" and st["auto_install"] is False

    def test_disabled_shape(self, tmp_path):
        um = make_manager(tmp_path, gh()[0], [], enabled=False)
        st = um.status()
        assert st["enabled"] is False and st["state"] == "disabled"


class TestCheck:
    def test_finds_update(self, tmp_path):
        um = make_manager(tmp_path, gh()[0], [])
        assert um._do_check() == "available"
        st = um.status()
        assert st["latest_version"] == "1.16.0" and st["state"] == "available"
        assert st["asset"]["name"] == SETUP and st["notes_url"] == "https://n/1.16.0"
        assert st["latest_ts"] is not None and st["checked_ts"] is not None

    def test_up_to_date(self, tmp_path):
        um = make_manager(tmp_path, gh(rel=None)[0], [])          # /latest 404: no releases
        assert um._do_check() == "up_to_date"
        assert um.status()["state"] == "up_to_date" and um.status()["latest_version"] is None

    def test_not_newer_is_up_to_date(self, tmp_path):
        rel = dict(REL_STABLE, tag_name="v1.15.0")
        um = make_manager(tmp_path, gh(rel=rel)[0], [])
        assert um._do_check() == "up_to_date"

    def test_prerelease_channel(self, tmp_path):
        um = make_manager(tmp_path, gh(rel=REL_PRE)[0], [], channel="prerelease")
        assert um._do_check() == "available"
        assert um.status()["latest_version"] == "1.17.0-rc.1"

    def test_offline_is_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TNT_UPDATE_OFFLINE", "1")
        um = UpdateManager(cfgmod.Config(tmp_path / "c.json"), None, current_version="1.15.0",
                           temp_dir_fn=lambda: tmp_path / "dl")   # real http_open, blocked by offline
        assert um._do_check() == "error"
        assert um.status()["state"] == "error" and um.status()["error"]

    def test_auto_install_requests_install(self, tmp_path):
        um = make_manager(tmp_path, gh()[0], [], auto_install=True)
        um._do_check()
        assert um._install_requested is True


class TestInstall:
    def test_good_checksum_installs(self, tmp_path):
        launched = []
        opener, _ = gh()
        um = make_manager(tmp_path, opener, launched)
        um._do_check()
        um.request_install()
        um._install_requested = False
        assert um._do_install() == "installing"
        assert launched and launched[0].endswith(SETUP) and os.path.exists(launched[0])
        assert um.status()["state"] == "installing"

    def test_bad_checksum_refuses_and_deletes(self, tmp_path):
        launched = []
        opener, _ = gh(checksum="00" * 32)
        um = make_manager(tmp_path, opener, launched)
        um._do_check()
        assert um._do_install() == "error"
        assert not launched
        assert "SHA-256" in (um.status()["error"] or "")
        assert not os.path.exists(tmp_path / "dl" / SETUP)

    def test_missing_checksum_refuses(self, tmp_path):
        launched = []
        rel = dict(REL_STABLE, assets=[ASSETS[0]])                # no checksum asset
        opener, _ = gh(rel=rel)
        um = make_manager(tmp_path, opener, launched)
        um._do_check()
        assert um._do_install() == "error"
        assert not launched and "checksum" in (um.status()["error"] or "").lower()


class TestControls:
    def test_request_install_without_update(self, tmp_path):
        um = make_manager(tmp_path, gh()[0], [])
        with pytest.raises(RuntimeError):
            um.request_install()

    def test_request_install_when_disabled(self, tmp_path):
        um = make_manager(tmp_path, gh()[0], [], enabled=False)
        with pytest.raises(RuntimeError):
            um.request_install()

    def test_check_now_returns_false_when_disabled(self, tmp_path):
        um = make_manager(tmp_path, gh()[0], [], enabled=False)
        assert um.check_now() is False

    def test_check_now_schedules(self, tmp_path):
        um = make_manager(tmp_path, gh()[0], [])
        assert um.check_now() is True
