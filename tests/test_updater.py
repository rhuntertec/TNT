"""Tests for tnt.updater: version logic, release/asset/checksum selection, and the check + verify + install
flow driven with a fake GitHub and a fake installer launcher (no network, nothing is ever executed)."""
from __future__ import annotations

import hashlib
import io
import json
import os

import pytest

import base64

from tnt import config as cfgmod
from tnt import updater
from tnt.updater import (INSTALLER_ARGS, UpdateManager, display_version, installer_args, is_newer,
                         parse_version, parse_checksum, pick_checksum_asset, pick_setup_asset,
                         relaunch_command, select_release)

SETUP = "TNT-Setup-1.16.0.exe"
ASSETS = [{"name": SETUP, "size": 42, "browser_download_url": "https://dl/x/s.exe"},
          {"name": SETUP + ".sha256", "size": 80, "browser_download_url": "https://dl/x/s.sha256"}]
REL_STABLE = {"tag_name": "v1.16.0", "draft": False, "prerelease": False, "html_url": "https://n/1.16.0",
              "assets": ASSETS, "published_at": "2026-09-13T12:00:00Z"}
REL_PRE = {"tag_name": "v1.17.0-rc.1", "draft": False, "prerelease": True, "assets": ASSETS}
REL_DRAFT = {"tag_name": "v2.0.0", "draft": True, "prerelease": False, "assets": ASSETS}


# --------------------------------------------------------------------------- pure helpers
#: Every tag form TNT has actually published on GitHub, and the version each one means.  The
#: releases from 1.16.0 on are tagged "TNT<ver>"; 1.7.0 and 1.12.0 used "v<ver>".
PUBLISHED_TAGS = {
    "v1.7.0": "1.7.0",
    "v1.12.0": "1.12.0",
    "TNT1.16.0": "1.16.0",
    "TNT1.20.0": "1.20.0",
    "TNT1.20.1": "1.20.1",
}


class TestVersion:
    def test_parse_and_display(self):
        assert parse_version("v1.16.0") == (1, 16, 0, 1, ())
        assert parse_version("1.16.0")[:4] == (1, 16, 0, 1)
        assert parse_version("1.16.0-rc.1")[3] == 0        # a pre-release ranks below the release
        assert parse_version("bogus") is None and parse_version(None) is None
        assert display_version("v1.16.0") == "1.16.0" and display_version("1.16.0") == "1.16.0"

    @pytest.mark.parametrize("tag, version", sorted(PUBLISHED_TAGS.items()))
    def test_every_tag_this_project_has_published_parses(self, tag, version):
        """The bug this guards: the pattern took an optional "v" but not the "TNT" prefix TNT's own
        releases use, so everything from 1.16.0 - the release that *introduced* auto-update - parsed
        as None and no client could ever see an update.  It went unnoticed because the tests here
        only ever used "v1.16.0", a form the project had stopped tagging with.
        """
        assert parse_version(tag) is not None, f"{tag} does not parse: no client can see this release"
        assert display_version(tag) == version

    def test_a_tag_that_is_not_ours_is_left_alone(self):
        for tag in ("bogus", "TNT-Setup-1.20.1.exe", "release", "TNTv", ""):
            assert parse_version(tag) is None, tag
        assert display_version("bogus") == "bogus"
        assert display_version("TNT-Setup") == "TNT-Setup"
        assert display_version(None) == ""

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



class TestPublishedTagsAreDiscoverable:
    """End to end over the shapes GitHub really returns, because the parser is only half of it."""

    @staticmethod
    def _rel(tag: str) -> "dict":
        return {"tag_name": tag, "draft": False, "prerelease": False, "html_url": "https://x/" + tag,
                "published_at": "2026-09-19T21:00:00Z",
                "assets": [{"name": f"TNT-Setup-{display_version(tag)}.exe", "size": 32_000_000,
                            "browser_download_url": "https://x/setup.exe"},
                           {"name": f"TNT-Setup-{display_version(tag)}.exe.sha256", "size": 86,
                            "browser_download_url": "https://x/setup.exe.sha256"}]}

    @pytest.mark.parametrize("tag, version", sorted(PUBLISHED_TAGS.items()))
    def test_a_client_one_version_back_finds_it(self, tag, version):
        older = version.rsplit(".", 1)[0] + ".0" if not version.endswith(".0") else "1.0.0"
        rel = self._rel(tag)
        assert select_release([rel], "stable", older) is rel, f"a {older} client cannot see {tag}"
        asset = pick_setup_asset(rel["assets"])
        assert asset is not None and pick_checksum_asset(rel["assets"], asset["name"]) is not None

    def test_the_newest_wins_across_both_tag_styles(self):
        """1.12.0 was tagged v1.12.0 and 1.20.1 TNT1.20.1: a mixed list has to order correctly."""
        rels = [self._rel("v1.12.0"), self._rel("TNT1.16.0"), self._rel("TNT1.20.1")]
        assert select_release(rels, "stable", "1.12.0")["tag_name"] == "TNT1.20.1"
        assert select_release(rels, "stable", "1.20.1") is None       # already on the newest

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

    def test_the_relaunch_helper_is_not_tnt_itself(self):
        """The installer's PrepareToInstall runs ``taskkill /IM TNT.exe /F``.  A waiter that was
        TNT.exe would be killed along with the window it exists to bring back."""
        cmd = relaunch_command(r"C:\Program Files\TNT\TNT.exe")
        assert "tnt.exe" not in cmd[0].lower()
        assert cmd[0].lower().endswith("powershell.exe")

    def test_the_relaunch_helper_waits_for_the_installer_not_a_fixed_delay(self):
        """The bug this replaces: the waiter slept a flat 30 s from the moment of the click, which
        is before the download even starts.  On a connection slower than about 1.5 MB/s the sleep
        ran out mid-download, the waiter opened TNT, the installer then killed it, and nothing was
        left to try again - the update succeeded and the application vanished.  Reproduced on a real
        machine before this changed.
        """
        script = _relaunch_script(relaunch_command(r"C:\Program Files\TNT\TNT.exe"))
        assert "ping" not in script, "a fixed sleep is exactly what went wrong"
        # it waits on the exe being replaced, which is the thing that actually says "installer done"
        assert "LastWriteTimeUtc" in script and "$now -ne $was" in script
        # and it will not start a second window over a client that is somehow still alive
        assert "Get-Process -Name 'TNT'" in script and "Start-Process" in script

    def test_the_relaunch_helper_reads_its_own_baseline(self):
        """A tick count computed in Python and one read in PowerShell are two stacks' answers to the
        same question, and a float second cannot hold 100 ns.  If they disagreed the waiter would
        think the exe had already been replaced and fire on its first poll - worse than the bug."""
        script = _relaunch_script(relaunch_command(r"C:\Program Files\TNT\TNT.exe"))
        assert "$was = ''" in script and "if (-not $was)" in script
        assert script.count("LastWriteTimeUtc") == 2, "the baseline and the comparison, both read there"

    def test_the_relaunch_helper_gives_up_eventually_and_opens_the_window_anyway(self):
        """An update that fails outright must still leave the user their application."""
        script = _relaunch_script(relaunch_command(r"C:\Program Files\TNT\TNT.exe", timeout_s=42))
        assert "AddSeconds(42)" in script
        start_at = script.index("Start-Process")
        assert script.index("while (") < script.index("$deadline)") < start_at, \
            "the launch is after the loop, so a timeout still reaches it"

    def test_a_path_with_a_quote_in_it_cannot_break_out_of_the_script(self):
        odd = "C:\\weird's dir\\TNT.exe"
        script = _relaunch_script(relaunch_command(odd))
        assert "'C:\\weird''s dir\\TNT.exe'" in script, script[:200]

    def test_the_installer_writes_a_log_next_to_itself(self):
        """A silent install that failed used to leave no record anywhere of why."""
        args = installer_args(r"C:\ProgramData\TNT\update\TNT-Setup-9.9.9.exe")
        assert args[:3] == list(INSTALLER_ARGS)
        assert args[-1] == r"/LOG=C:\ProgramData\TNT\update\install.log"


def _relaunch_script(cmd):
    """The PowerShell the relaunch helper will run, decoded back out of -EncodedCommand."""
    assert "-EncodedCommand" in cmd, cmd
    return base64.b64decode(cmd[cmd.index("-EncodedCommand") + 1]).decode("utf-16-le")


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
