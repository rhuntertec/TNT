"""Settings > Clear history, one store at a time: the packet capture files, the fault watch, the Pro AV scan, the SIP
checks, call-flow slots and tile cache, and the Wi-Fi survey in TNT.exe with its bridge method.

The service's orchestration (``Engine.clear_history``, ``tnt.history``, the route) and the page are tested elsewhere;
this file is what each store does when it is told to clear from a time on (or everything, ``None``).

Deleting packet captures is the most dangerous code in the feature: the owner's rule is that TNT never deletes a
capture file outside its own storage folder.  So most of the capture tests prove what SURVIVES - a file opened from
another folder under a matching name, a SIP flow slot's file, links and junctions planted in the folder, a hard link,
the switch-port lookup's work files, the exports folder, anything not named like a saved capture, and a capture that
is still recording - and only then that what should go does.

Every folder is a tmp_path: the captures folder is handed to CaptureManager, the "other folders" are tmp folders
beside it, and ``data_dir`` points TNT_DATA_DIR at tmp for the exports test.  No ETW session, packet capture, socket
or Wi-Fi adapter is used (a fake ETW, fake socket and fake Wlan API stand in).  Addresses are 192.0.2.0/24 only.
"""
from __future__ import annotations

import os
import re
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from test_capture import (SIP_INVITE, T0, _write_capture, arp_frame, feed, icmp_frame, make, started, udp_frame,
                          wait_for, wait_packets)
from test_client_tray import _no_real_wifi_survey, _page, app, SERVICE  # noqa: F401 - fixtures (the first is autouse)
from test_faults import Bus as FaultBus, counters, ids, watcher
from test_proav import FakeAdapter, FakeSocket, _NoL2, _wait, scanner  # noqa: F401 - the scanner fixture is used by name
from test_sipqual import FakeDb, GATEWAY, minute_rows
from test_wifi_survey import BSSID_A, BSSID_B, FakeClock, World, ap_entry, make_survey, simulate

from client import tray, wifi_survey
from tnt import capture, faults, paths, proav, sipalg, sipflow, sipnat, sipqual
from tnt.capture import CLEAR_KEYS, CLEAR_SKIP_KEYS, CaptureManager
from tnt.proav import ProAvScanner

NAME_OLD = "TNT-capture-20260101-080000.pcapng"
NAME_MID = "TNT-capture-20260101-110000.pcapng"
NAME_NEW = "TNT-capture-20260101-115900.pcapng"
WINDOWS = pytest.mark.skipif(sys.platform != "win32", reason="junctions and file sharing locks are Windows behaviour")


# --------------------------------------------------------------------------- helpers
def put(path: Path, *, mtime: float, frames=None) -> Path:
    """A small, readable pcapng at *path* whose modification time (the saved list's ``created_ts``) is *mtime*."""
    _write_capture(path, frames or [icmp_frame(), arp_frame()])
    os.utime(path, (mtime, mtime))
    return path


def fingerprint(path: Path) -> tuple:
    """What a file IS, for "it survived untouched": its bytes and its modification time."""
    return path.read_bytes(), os.stat(path).st_mtime_ns


@pytest.fixture
def cap(tmp_path):
    made = make(tmp_path)
    made.folder.mkdir(parents=True, exist_ok=True)
    yield made
    made.mgr.close(0.5)


# =========================================================================================
# packet captures: what must SURVIVE
# =========================================================================================
def test_a_capture_opened_from_another_folder_under_a_matching_name_survives_its_twin_being_deleted(cap, tmp_path):
    """The packet list is showing a file from Downloads that happens to carry a saved-capture name - the same name
    as one in TNT's folder.  Clearing everything deletes TNT's copy and never the one the user opened from elsewhere:
    nothing is ever built from open_path's path or from the session's file name."""
    inside = put(cap.folder / NAME_MID, mtime=T0 - 60)
    elsewhere = put(tmp_path / "Downloads" / NAME_MID, mtime=T0 - 60, frames=[icmp_frame(), arp_frame(), icmp_frame()])
    other = put(tmp_path / "Downloads" / NAME_NEW, mtime=T0 - 30)
    before, before_other = fingerprint(elsewhere), fingerprint(other)
    cap.mgr.open_path(str(elsewhere))

    result = cap.mgr.clear_history(None)

    assert result["deleted_names"] == [NAME_MID] and not inside.exists()
    assert fingerprint(elsewhere) == before and fingerprint(other) == before_other
    # the session on the outside file is not TNT's history: it stays open and still reads its own file
    session = cap.mgr.session()
    assert session is not None and session["source"] == "file" and session["packets"] == 3
    assert cap.mgr.packet(3)["row"]["proto"] == "ICMP"


def test_a_sip_flow_slot_on_a_capture_in_another_folder_is_never_deleted(cap, tmp_path):
    """A call-flow slot holds whatever path the user typed.  Neither the capture clear nor the flow clear deletes it,
    even when it is named like a saved capture and a same-named capture in TNT's folder is deleted."""
    call = [udp_frame(5060, 5060, SIP_INVITE, src="192.0.2.10", dst="192.0.2.20")]
    put(cap.folder / NAME_NEW, mtime=T0 - 60, frames=call)
    elsewhere = put(tmp_path / "Captures from site" / NAME_NEW, mtime=T0 - 60, frames=call)
    before = fingerprint(elsewhere)
    reader = sipflow.FlowReader(clock=lambda: T0 - 7200)          # loaded two hours ago: outside a 1 h clear
    reader.open(str(elsewhere), "a")

    result = cap.mgr.clear_history(T0 - 3600)
    deleted_paths = [os.path.join(cap.folder, name) for name in result["deleted_names"]]
    closed = reader.clear_history(T0 - 3600, deleted_paths)

    assert result["deleted_names"] == [NAME_NEW]
    assert closed == 0 and [s["slot"] for s in reader.sources()] == ["a"], "a different file, only the same name"
    assert fingerprint(elsewhere) == before
    assert reader.clear_history(None, deleted_paths) == 1 and reader.sources() == []
    assert fingerprint(elsewhere) == before, "closing a slot never touches its file"


def test_a_symbolic_link_in_the_captures_folder_is_never_followed_or_deleted(cap, tmp_path):
    target = put(tmp_path / "elsewhere" / "switch-mirror.pcapng", mtime=T0 - 60)
    before = fingerprint(target)
    link = cap.folder / NAME_NEW
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symbolic links cannot be created here ({exc})")
    result = cap.mgr.clear_history(None)
    assert result["deleted"] == 0 and result["skipped"] == []           # it was never one of TNT's captures
    assert os.path.lexists(link) and fingerprint(target) == before


@WINDOWS
def test_a_junction_in_the_captures_folder_is_never_walked(cap, tmp_path):
    """A junction needs no privilege at all, so it is the link an attacker would plant.  One named like a saved
    capture, pointing at a folder of captures: nothing in that folder is deleted, nor the junction itself."""
    import _winapi

    outside = tmp_path / "outside"
    victims = [put(outside / NAME_OLD, mtime=T0 - 60), put(outside / NAME_NEW, mtime=T0 - 60)]
    before = [fingerprint(p) for p in victims]
    junction = cap.folder / NAME_MID
    _winapi.CreateJunction(str(outside), str(junction))
    try:
        result = cap.mgr.clear_history(None)
        assert result["deleted"] == 0 and result["skipped"] == []
        assert [fingerprint(p) for p in victims] == before and os.path.lexists(junction)
    finally:
        os.rmdir(junction)


@WINDOWS
def test_a_captures_folder_that_is_itself_a_junction_is_never_cleared(tmp_path):
    """The folder itself pointing somewhere else: files() lists nothing, so nothing there can be deleted."""
    import _winapi

    outside = tmp_path / "someone-elses-captures"
    victims = [put(outside / NAME_OLD, mtime=T0 - 60), put(outside / NAME_NEW, mtime=T0 - 60)]
    before = [fingerprint(p) for p in victims]
    junction = tmp_path / "captures"
    _winapi.CreateJunction(str(outside), str(junction))
    made = make(tmp_path, captures_dir_fn=lambda: junction)
    try:
        result = made.mgr.clear_history(None)
        assert result["deleted"] == 0 and result["skipped"] == []
        assert [fingerprint(p) for p in victims] == before
    finally:
        made.mgr.close(0.5)
        os.rmdir(junction)


def test_a_hard_link_to_a_file_outside_the_folder_is_skipped_and_reported(cap, tmp_path):
    """A second name for a file whose data lives on elsewhere: deleting TNT's name would be harmless to the data, but
    it is not a capture TNT made, so it is left alone and the result says why."""
    outside = put(tmp_path / "evidence" / "keep.pcapng", mtime=T0 - 60)
    before = fingerprint(outside)
    os.link(outside, cap.folder / NAME_NEW)
    put(cap.folder / NAME_MID, mtime=T0 - 60)
    result = cap.mgr.clear_history(None)
    assert result["deleted_names"] == [NAME_MID]
    assert result["skipped"] == [{"name": NAME_NEW, "reason": capture.CLEAR_LINKED_TEXT}]
    assert all(list(entry) == list(CLEAR_SKIP_KEYS) for entry in result["skipped"])
    assert fingerprint(outside) == before and (cap.folder / NAME_NEW).exists()


def test_the_switch_port_work_files_and_anything_not_named_like_a_saved_capture_survive(cap):
    """The switch-port lookup shares the folder: its .etl/.pcapng and the crash marker are how a crash is cleaned up
    later.  Nor is anything else touched that is not exactly a saved capture's name, a folder included."""
    keep = [cap.folder / name for name in (
        "TNT-switchport-20260101-115000.etl", "TNT-switchport-20260101-115000.pcapng", "TNT-pktmon-session.json",
        "TNT-pktmon-session.json.part", "TNT-capture-1.pcapng", "TNT-capture-20260101-120000.pcapng.bak",
        "TNT-capture-20260101-120000.pcap", "capture.pcapng", "notes.txt", "TNT-live-20260101-115500.pcapng")]
    for path in keep:
        put(path, mtime=T0 - 60)
    folder_named_like_one = cap.folder / "TNT-capture-20260101-116000.pcapng"
    folder_named_like_one.mkdir()
    inner = put(folder_named_like_one / NAME_NEW, mtime=T0 - 60)
    before = {path.name: fingerprint(path) for path in keep + [inner]}

    result = cap.mgr.clear_history(None)

    assert result == {"deleted": 0, "deleted_names": [], "skipped": [], "recording": False, "discarded_unsaved": False}
    assert {path.name: fingerprint(path) for path in keep + [inner]} == before


def test_the_exports_folder_is_never_touched(data_dir):
    """Report PDFs (and anything else) in the exports folder are not captures, whatever they are called."""
    made = make(Path(data_dir), captures_dir_fn=paths.captures_dir)
    try:
        paths.captures_dir().mkdir(parents=True, exist_ok=True)
        put(paths.captures_dir() / NAME_NEW, mtime=T0 - 60)
        exports = paths.exports_dir()
        exports.mkdir(parents=True, exist_ok=True)
        pdf = exports / "TNT-report-20260101-115900.pdf"
        pdf.write_bytes(b"%PDF-1.4 a site report")
        twin = put(exports / NAME_NEW, mtime=T0 - 60)
        before = fingerprint(pdf), fingerprint(twin)
        result = made.mgr.clear_history(None)
        assert result["deleted_names"] == [NAME_NEW] and not (paths.captures_dir() / NAME_NEW).exists()
        assert (fingerprint(pdf), fingerprint(twin)) == before
    finally:
        made.mgr.close(0.5)


def test_a_capture_that_is_recording_is_left_alone_and_reported_while_the_rest_clears(cap):
    put(cap.folder / NAME_NEW, mtime=T0 - 60)
    started(cap)
    feed(cap, icmp_frame())
    wait_packets(cap, 1)
    live = [p for p in cap.folder.iterdir() if p.name.startswith("TNT-live-")]

    result = cap.mgr.clear_history(None)

    assert result["recording"] is True and result["discarded_unsaved"] is False
    assert result["deleted_names"] == [NAME_NEW], "a recording capture never stops the rest of the clear"
    assert len(live) == 1 and live[0].exists()
    assert cap.mgr.session()["state"] == "capturing"
    feed(cap, arp_frame())
    wait_packets(cap, 2)                                      # still recording, into the same file
    assert cap.mgr.session()["packets"] == 2


# =========================================================================================
# packet captures: a path that changes between the check and the delete
# =========================================================================================
def swap_after_the_check(monkeypatch, mgr, swap) -> None:
    """Run *swap* right after _resolve approves the first file: the moment a path could be changed under a delete
    that goes by path."""
    real = mgr._resolve
    done: List[str] = []

    def resolve(name):
        found = real(name)
        if not done:
            done.append(name)
            swap(found[0])
        return found

    monkeypatch.setattr(mgr, "_resolve", resolve)


@WINDOWS
def test_a_captures_folder_swapped_for_a_junction_after_the_check_deletes_nothing_elsewhere(cap, tmp_path,
                                                                                            monkeypatch):
    """The folder renamed away and a junction to another folder put where it was, between the check and the delete:
    the path now leads to a same-named capture somewhere else.  The delete goes by a handle checked to be the file
    that was approved, so the capture elsewhere survives - and so does TNT's own, now in a folder that is not TNT's
    captures folder.  The clear says it could not delete it."""
    import _winapi

    put(cap.folder / NAME_MID, mtime=T0 - 60)
    outside = tmp_path / "outside"
    victim = put(outside / NAME_MID, mtime=T0 - 60, frames=[icmp_frame()])
    before = fingerprint(victim)
    moved = tmp_path / "moved"

    def swap(_path):
        os.rename(cap.folder, moved)
        _winapi.CreateJunction(str(outside), str(cap.folder))

    swap_after_the_check(monkeypatch, cap.mgr, swap)
    try:
        result = cap.mgr.clear_history(None)
    finally:
        if os.path.lexists(cap.folder):
            os.rmdir(cap.folder)                              # the junction, never what it points at
    assert fingerprint(victim) == before and (moved / NAME_MID).exists()
    assert result["deleted"] == 0 and result["skipped"] == [{"name": NAME_MID, "reason": capture.CLEAR_FAILED_TEXT}]


@WINDOWS
def test_a_captures_folder_moved_and_linked_back_after_the_check_is_left_alone(cap, tmp_path, monkeypatch):
    """The same file, but no longer in TNT's captures folder: the folder was renamed and a junction back to it put
    where it was.  Being the approved file is not enough - its real folder must still be the captures folder."""
    import _winapi

    saved = put(cap.folder / NAME_MID, mtime=T0 - 60)
    before = fingerprint(saved)
    moved = tmp_path / "moved"

    def swap(_path):
        os.rename(cap.folder, moved)
        _winapi.CreateJunction(str(moved), str(cap.folder))

    swap_after_the_check(monkeypatch, cap.mgr, swap)
    try:
        result = cap.mgr.clear_history(None)
    finally:
        if os.path.lexists(cap.folder):
            os.rmdir(cap.folder)
    assert fingerprint(moved / NAME_MID) == before
    assert result["skipped"] == [{"name": NAME_MID, "reason": capture.CLEAR_FAILED_TEXT}]


@WINDOWS
def test_a_saved_capture_swapped_for_a_link_after_the_check_is_left_alone_and_the_target_survives(cap, tmp_path,
                                                                                                  monkeypatch):
    """The file itself replaced by a symbolic link to a capture elsewhere: the delete opens the link as the link,
    sees it is not the approved file, and touches neither the link nor what it points at."""
    put(cap.folder / NAME_MID, mtime=T0 - 60)
    victim = put(tmp_path / "evidence" / "switch-mirror.pcapng", mtime=T0 - 60)
    before = fingerprint(victim)
    probe = tmp_path / "can-i-link"
    try:
        os.symlink(victim, probe)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symbolic links cannot be created here ({exc})")
    os.remove(probe)

    def swap(path):
        os.remove(path)
        os.symlink(victim, path)

    swap_after_the_check(monkeypatch, cap.mgr, swap)
    result = cap.mgr.clear_history(None)
    assert fingerprint(victim) == before and os.path.islink(cap.folder / NAME_MID)
    assert result["skipped"] == [{"name": NAME_MID, "reason": capture.CLEAR_FAILED_TEXT}]


@WINDOWS
def test_a_saved_capture_replaced_by_another_file_after_the_check_is_not_the_one_deleted(cap, tmp_path, monkeypatch):
    """Only the file that was checked is deleted, not whatever carries its name a moment later.  Here the name is
    given to a hard link of a capture kept elsewhere (no privilege needed): the delete button refuses it as not
    found, and the second name stays (the file elsewhere still has two)."""
    put(cap.folder / NAME_MID, mtime=T0 - 60)
    kept = put(tmp_path / "evidence" / "keep.pcapng", mtime=T0 - 60, frames=[icmp_frame()])
    before = fingerprint(kept)

    def swap(path):
        os.remove(path)
        os.link(kept, path)

    swap_after_the_check(monkeypatch, cap.mgr, swap)
    with pytest.raises(capture.CaptureFileMissing):
        cap.mgr.delete_file(NAME_MID)
    assert (cap.folder / NAME_MID).exists() and os.stat(kept).st_nlink == 2 and fingerprint(kept) == before


@WINDOWS
@pytest.mark.parametrize("how", ["the delete button", "the retention"])
def test_the_delete_button_and_the_retention_delete_the_same_guarded_way(cap, tmp_path, monkeypatch, how):
    """The page's delete and the daily retention share the guarded delete, so the same swap takes nothing with them
    either."""
    import _winapi

    put(cap.folder / NAME_OLD, mtime=T0 - capture.MAX_AGE_S - 60)     # old enough for the retention to delete
    outside = tmp_path / "outside"
    victim = put(outside / NAME_OLD, mtime=T0 - capture.MAX_AGE_S - 60, frames=[icmp_frame()])
    before = fingerprint(victim)
    moved = tmp_path / "moved"

    def swap(_path):
        os.rename(cap.folder, moved)
        _winapi.CreateJunction(str(outside), str(cap.folder))

    swap_after_the_check(monkeypatch, cap.mgr, swap)
    try:
        if how == "the delete button":
            with pytest.raises(capture.CaptureFileMissing):
                cap.mgr.delete_file(NAME_OLD)
        else:
            assert cap.mgr.enforce_retention(T0) == 0
    finally:
        if os.path.lexists(cap.folder):
            os.rmdir(cap.folder)
    assert fingerprint(victim) == before and (moved / NAME_OLD).exists()


# =========================================================================================
# packet captures: what goes
# =========================================================================================
def test_saved_captures_in_the_range_are_deleted_and_older_ones_stay(cap):
    """The range is judged on the file's modification time, which is when the capture stopped - the same time the
    saved list shows and the retention uses."""
    put(cap.folder / NAME_OLD, mtime=T0 - 4 * 3600)
    put(cap.folder / NAME_MID, mtime=T0 - 1800)
    put(cap.folder / NAME_NEW, mtime=T0 - 60)

    result = cap.mgr.clear_history(T0 - 3600)

    assert list(result) == list(CLEAR_KEYS)
    assert result["deleted"] == 2 and sorted(result["deleted_names"]) == [NAME_MID, NAME_NEW]
    assert result["skipped"] == [] and result["recording"] is False and result["discarded_unsaved"] is False
    assert [f["name"] for f in cap.mgr.files()] == [NAME_OLD]
    assert cap.mgr.tile()["files"] == 1, "the tile's cached count is refreshed"


def test_all_time_deletes_every_saved_capture_however_old(cap):
    put(cap.folder / NAME_OLD, mtime=T0 - 400 * 86400)
    put(cap.folder / NAME_NEW, mtime=T0 - 60)
    result = cap.mgr.clear_history(None)
    assert result["deleted"] == 2 and cap.mgr.files() == []


def test_a_capture_being_downloaded_is_skipped_and_reported_and_the_rest_still_go(cap):
    put(cap.folder / NAME_MID, mtime=T0 - 60)
    put(cap.folder / NAME_NEW, mtime=T0 - 60)
    fh, _size = cap.mgr.file_download(NAME_NEW)
    try:
        if sys.platform != "win32":
            pytest.skip("only Windows refuses to delete a file another handle holds open")
        result = cap.mgr.clear_history(None)
    finally:
        fh.close()
    assert result["deleted_names"] == [NAME_MID]
    assert result["skipped"] == [{"name": NAME_NEW, "reason": capture.CLEAR_BUSY_TEXT}]
    assert cap.mgr.clear_history(None)["deleted_names"] == [NAME_NEW], "once the download ends, it goes next time"


def test_a_capture_being_downloaded_stays_open_in_the_packet_list_because_it_stays_on_disk(cap):
    """The packet list closes only for a file that is really going: a download holding the file keeps it on disk, so
    the list showing it stays open and readable, and it closes when a later clear does delete the file."""
    put(cap.folder / NAME_NEW, mtime=T0 - 60)
    cap.mgr.open_file(NAME_NEW)
    fh, _size = cap.mgr.file_download(NAME_NEW)
    try:
        if sys.platform != "win32":
            pytest.skip("only Windows refuses to delete a file another handle holds open")
        result = cap.mgr.clear_history(None)
    finally:
        fh.close()
    assert result["skipped"] == [{"name": NAME_NEW, "reason": capture.CLEAR_BUSY_TEXT}]
    assert cap.mgr.session()["file"] == NAME_NEW and cap.mgr.packet(1)["row"]["proto"] == "ICMP"
    assert cap.mgr.clear_history(None)["deleted_names"] == [NAME_NEW]
    assert cap.mgr.session() is None


@WINDOWS
def test_a_read_only_capture_is_reported_as_read_only_and_stays_open_in_the_packet_list(cap):
    """Someone marked this capture read-only to keep it.  The clear leaves it, says why in words that fit, and the
    list showing it stays open; the rest still go.  The delete button says the same instead of "being downloaded"."""
    put(cap.folder / NAME_MID, mtime=T0 - 60)
    keep = put(cap.folder / NAME_NEW, mtime=T0 - 60)
    os.chmod(keep, 0o444)
    try:
        cap.mgr.open_file(NAME_NEW)
        result = cap.mgr.clear_history(None)
        assert result["deleted_names"] == [NAME_MID]
        assert result["skipped"] == [{"name": NAME_NEW, "reason": capture.CLEAR_READONLY_TEXT}]
        assert keep.exists() and cap.mgr.session()["file"] == NAME_NEW
        with pytest.raises(capture.CaptureFileBusy, match=capture.FILE_READONLY_TEXT):
            cap.mgr.delete_file(NAME_NEW)
        assert keep.exists() and cap.mgr.session()["file"] == NAME_NEW
    finally:
        os.chmod(keep, 0o666)


@WINDOWS
@pytest.mark.parametrize("where", ["open", "delete"])
def test_a_file_windows_will_not_delete_is_reported_and_never_stops_the_rest(cap, monkeypatch, where):
    """Access denied - by the file's permissions when it is opened for the delete, or by Windows at the delete
    itself - is "could not be deleted", not "being downloaded"; the file and the list showing it stay, the rest go."""
    put(cap.folder / NAME_MID, mtime=T0 - 60)
    keep = put(cap.folder / NAME_NEW, mtime=T0 - 60)
    before = fingerprint(keep)
    cap.mgr.open_file(NAME_NEW)
    if where == "open":
        real_open = capture._open_for_delete
        monkeypatch.setattr(capture, "_open_for_delete",
                            lambda path: (None, 5) if os.path.basename(path) == NAME_NEW else real_open(path))
    else:
        real_mark = capture._mark_for_delete

        def stubborn(handle):
            if os.path.basename(capture._final_path(handle)) == NAME_NEW:
                return 5                      # ERROR_ACCESS_DENIED
            return real_mark(handle)

        monkeypatch.setattr(capture, "_mark_for_delete", stubborn)
    result = cap.mgr.clear_history(None)
    assert result["deleted_names"] == [NAME_MID]
    assert result["skipped"] == [{"name": NAME_NEW, "reason": capture.CLEAR_FAILED_TEXT}]
    assert fingerprint(keep) == before and cap.mgr.session()["file"] == NAME_NEW


def test_the_saved_capture_open_in_the_packet_list_is_discarded_first_with_its_sip_calls(cap):
    """A capture saved from the page is still open, with the SIP calls it found: the clear deletes the file and the
    session (its packet list and its CallTracker) goes with it, so nothing keeps reading a file that is gone."""
    started(cap)
    feed(cap, udp_frame(5060, 5060, SIP_INVITE, src="192.0.2.10", dst="192.0.2.20"))
    wait_packets(cap, 1)
    assert wait_for(lambda: len(cap.mgr.calls()) == 1)
    name = cap.mgr.save()["file"]
    before = len(cap.bus.of(capture.EVENT))

    result = cap.mgr.clear_history(None)

    assert result["deleted_names"] == [name] and not (cap.folder / name).exists()
    assert cap.mgr.session() is None and cap.mgr.calls() == [] and cap.mgr.packets()["total"] == 0
    published = cap.bus.of(capture.EVENT)[before:]
    assert published and published[-1]["session"] is None, "capture.state tells the page"


@WINDOWS
def test_the_packet_list_is_closed_before_its_file_leaves_the_disk(cap, monkeypatch):
    """"Discarded first": the list closes once the delete is certain, while the file is still in the folder (marked
    for deletion, it goes when TNT lets go of it), so nothing ever reads a file that has gone."""
    put(cap.folder / NAME_NEW, mtime=T0 - 60)
    cap.mgr.open_file(NAME_NEW)
    seen: List[bool] = []
    real = cap.mgr._close_if_reading

    def closing(*paths):
        seen.append(NAME_NEW in os.listdir(cap.folder))
        return real(*paths)

    monkeypatch.setattr(cap.mgr, "_close_if_reading", closing)
    assert cap.mgr.clear_history(None)["deleted_names"] == [NAME_NEW]
    assert seen == [True] and cap.mgr.session() is None
    assert NAME_NEW not in os.listdir(cap.folder)


def test_a_saved_capture_opened_by_its_full_path_is_cleared_like_the_others(cap):
    """Only a file opened by path from OUTSIDE the captures folder is left alone.  One opened by path that is itself
    one of TNT's saved captures is in the folder, so it is history like the rest, and the list showing it closes."""
    saved = put(cap.folder / NAME_NEW, mtime=T0 - 60)
    cap.mgr.open_path(str(saved))
    assert cap.mgr.session()["source"] == "file"
    result = cap.mgr.clear_history(None)
    assert result["deleted_names"] == [NAME_NEW] and not saved.exists() and cap.mgr.session() is None


def test_a_saved_capture_open_but_older_than_the_range_stays_open(cap):
    put(cap.folder / NAME_OLD, mtime=T0 - 4 * 3600)
    cap.mgr.open_file(NAME_OLD)
    result = cap.mgr.clear_history(T0 - 3600)
    assert result["deleted"] == 0 and cap.mgr.session()["file"] == NAME_OLD


def test_a_stopped_capture_that_was_never_saved_is_discarded_when_it_started_in_the_range(cap):
    started(cap)
    feed(cap, udp_frame(5060, 5060, SIP_INVITE, src="192.0.2.10", dst="192.0.2.20"))
    wait_packets(cap, 1)
    cap.mgr.stop()
    live = [p for p in cap.folder.iterdir() if p.name.startswith("TNT-live-")]
    assert len(live) == 1

    kept = cap.mgr.clear_history(T0 + 60)                    # it started before the range: not this clear's
    assert kept["discarded_unsaved"] is False and live[0].exists() and cap.mgr.session()["state"] == "stopped"

    result = cap.mgr.clear_history(T0 - 60)
    assert result["discarded_unsaved"] is True and result["deleted"] == 0
    assert not live[0].exists() and cap.mgr.session() is None and cap.mgr.calls() == []


def test_all_time_discards_a_stopped_unsaved_capture_whenever_it_started(cap):
    started(cap)
    feed(cap, icmp_frame())
    wait_packets(cap, 1)
    cap.mgr.stop()
    assert cap.mgr.clear_history(None)["discarded_unsaved"] is True
    assert [p.name for p in cap.folder.iterdir()] == []


def test_an_unsaved_session_whose_working_file_is_not_tnts_own_loses_the_session_but_never_the_file(cap, tmp_path):
    """Belt and braces: whatever the session says its working file is, only a TNT-live file start() made in the
    captures folder is ever deleted by the clear."""
    started(cap)
    feed(cap, icmp_frame())
    wait_packets(cap, 1)
    cap.mgr.stop()
    stranger = put(tmp_path / "elsewhere" / "TNT-live-20260101-120000.pcapng", mtime=T0)
    before = fingerprint(stranger)
    cap.mgr._work_path = str(stranger)                       # what a bug elsewhere could leave behind
    assert cap.mgr.clear_history(None)["discarded_unsaved"] is True
    assert cap.mgr.session() is None and fingerprint(stranger) == before


@WINDOWS
def test_a_stopped_unsaved_capture_stays_when_the_captures_folder_cannot_be_verified(cap, tmp_path):
    """The captures folder has been swapped for a junction, so nothing in it can be checked.  The unsaved capture's
    working file is in that folder, so its session stays open, the file stays where it is, and the result does not
    claim the capture was discarded."""
    import _winapi

    started(cap)
    feed(cap, icmp_frame())
    wait_packets(cap, 1)
    cap.mgr.stop()
    live = [p.name for p in cap.folder.iterdir() if p.name.startswith("TNT-live-")]
    assert len(live) == 1
    moved = tmp_path / "moved"
    os.rename(cap.folder, moved)
    _winapi.CreateJunction(str(moved), str(cap.folder))
    before = fingerprint(moved / live[0])
    try:
        result = cap.mgr.clear_history(None)
    finally:
        os.rmdir(cap.folder)                                  # the junction, never what it points at
    assert result["discarded_unsaved"] is False and result["deleted"] == 0
    assert fingerprint(moved / live[0]) == before and cap.mgr.session()["state"] == "stopped"


def test_the_clear_publishes_capture_state_even_when_there_was_nothing_to_delete(cap):
    cap.mgr.clear_history(None)
    assert cap.bus.of(capture.EVENT), "the Packet capture page lists the folder again"


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), True, "1790000000", 10 ** 400, [1]])
def test_a_since_that_is_not_a_time_deletes_no_capture_at_all(cap, bad):
    """A NaN compares false with every time, so taken as it is every saved capture would be "in the range" and a
    short clear would become "all time".  Anything but None or a finite time is refused before anything is
    touched."""
    old = put(cap.folder / NAME_OLD, mtime=T0 - 400 * 86400)
    new = put(cap.folder / NAME_NEW, mtime=T0 - 60)
    before = fingerprint(old), fingerprint(new)
    with pytest.raises(ValueError, match=re.escape(capture.CLEAR_SINCE_TEXT)):
        cap.mgr.clear_history(bad)
    assert (fingerprint(old), fingerprint(new)) == before


def test_a_since_that_is_not_a_time_never_discards_the_unsaved_capture(cap):
    started(cap)
    feed(cap, icmp_frame())
    wait_packets(cap, 1)
    cap.mgr.stop()
    live = [p for p in cap.folder.iterdir() if p.name.startswith("TNT-live-")]
    with pytest.raises(ValueError):
        cap.mgr.clear_history(float("nan"))
    assert len(live) == 1 and live[0].exists() and cap.mgr.session()["state"] == "stopped"


# =========================================================================================
# the fault watch
# =========================================================================================
def _faulty_watch(bus=None):
    """A watch that has judged 900 damaged frames as bad: an adapter that went down with errors of its own too."""
    rows = [[counters(1, packets=0), counters(2, name="Wi-Fi", packets=0)],
            [counters(1, packets=100_000, errors=900), counters(2, name="Wi-Fi", packets=100_000, errors=400)],
            [counters(1, packets=100_000, errors=900)],
            [counters(1, packets=100_000, errors=900)],
            [counters(1, packets=200_000, errors=900)]]
    w, clock, state = watcher(rows, bus=bus)
    w.tick()
    clock.now += faults.MIN_WATCH_S + 1.0
    w.tick()
    clock.now += 5.0
    w.tick()                                                  # Wi-Fi's link went down: it stays, judged, marked down
    assert w.view()["level"] == "bad" and "fault.errors" in ids(w.view()["findings"])
    return w, clock


def test_a_clear_of_any_range_forgets_the_errors_in_both_the_recent_and_the_since_start_figures():
    """The counters are cumulative, so a five-minute range cannot be cut out of them: any clear starts the whole
    watch again, on every adapter including the one whose link is down."""
    w, clock = _faulty_watch()
    assert w.clear_history(clock.now - 300) == 1
    view = w.view()
    assert view["level"] == "info" and ids(view["findings"]) == ["fault.watching"]
    assert [(n["name"], n["up"]) for n in view["nics"]] == [("Ethernet", True), ("Wi-Fi", False)]
    for nic in view["nics"]:
        assert (nic["new_rx_errors"], nic["recent_rx_errors"], nic["watched_s"]) == (0, 0, 0.0), nic["name"]
    # the adapter's own lifetime counter is Windows', not TNT's history: it stays as context
    assert view["nics"][0]["rx_errors"] == 900
    clock.now += 5.0
    w.tick()                                                  # the same counters again: nothing new happened
    assert w.view()["nics"][0]["new_rx_errors"] == 0


def test_after_a_clear_the_tile_says_watching_and_then_clean_once_it_has_watched_long_enough():
    w, clock = _faulty_watch()
    w.clear_history(None)
    tile = w.tile()
    assert (tile["level"], tile["headline"], tile["bad"], tile["watched_s"], tile["clean_s"]) == \
        ("info", "Watching", 0, 0.0, None)
    assert w.view()["watching_since"] == clock.now
    clock.now += 5.0
    w.tick()
    clock.now += faults.MIN_WATCH_S + 1.0
    w.tick()                                                  # 100 000 more frames, not one more error
    assert w.view()["nics"][0]["new_rx_packets"] == 100_000
    assert ids(w.view()["findings"]) == ["fault.clean"], "the 900 errors from before the clear are never judged again"


def test_errors_after_the_clear_are_counted_from_it():
    w, clock = _faulty_watch()
    w.clear_history(None)
    w._reader = lambda: [counters(1, packets=300_000, errors=950)]
    clock.now += 5.0
    w.tick()
    assert w.view()["nics"][0]["new_rx_errors"] == 50


def test_the_clear_publishes_faults_state_with_the_new_tile():
    bus = FaultBus()
    w, _clock = _faulty_watch(bus)
    before = len(bus.events)
    w.clear_history(None)
    published = bus.events[before:]
    assert [e["type"] for e in published] == ["faults.state"]
    assert published[0]["data"]["level"] == "info" and published[0]["data"]["headline"] == "Watching"


def test_a_tick_that_was_reading_while_the_clear_ran_cannot_bring_the_cleared_errors_back():
    """The tick reads the counters without the lock.  When the clear lands between that read and the tick taking the
    lock, the reading it holds may be from before the clear: it becomes the new baseline, never a reading whose
    errors count."""
    clock = SimpleNamespace(now=1_700_000_000.0)
    reading = {"errors": 0, "packets": 0, "clear_now": False}
    holder: Dict[str, Any] = {}

    def reader():
        if reading["clear_now"]:
            reading["clear_now"] = False
            holder["watch"].clear_history(None)              # the clear runs while this tick is reading
        return [counters(1, packets=reading["packets"], errors=reading["errors"])]

    w = faults.FaultWatcher(None, clock=lambda: clock.now, reader=reader, adapters_fn=lambda: [],
                            arp_fn=lambda: {}, gateway_fn=lambda: None)
    holder["watch"] = w
    w.tick()
    clock.now += faults.MIN_WATCH_S + 1.0
    reading.update(errors=900, packets=100_000, clear_now=True)
    w.tick()
    assert w.view()["nics"][0]["new_rx_errors"] == 0 and w.view()["nics"][0]["recent_rx_errors"] == 0
    clock.now += 5.0
    w.tick()                                                  # the same 900: they happened before the clear
    assert w.view()["nics"][0]["new_rx_errors"] == 0
    assert ids(w.view()["findings"]) == ["fault.watching"]


def test_the_arp_watch_forgets_every_answer():
    rows = [[counters(packets=0)]]
    tables = [{"192.0.2.1": "02:00:5e:10:00:01"}, {"192.0.2.1": "02:00:5e:10:00:02"},
              {"192.0.2.1": "02:00:5e:10:00:02"}]
    w, clock, _ = watcher(rows, arp=tables, gateway="192.0.2.1")
    w.tick()
    clock.now += 5.0
    w.tick()
    assert w.view()["arp"]["conflicts"], "two MACs answered for the gateway"
    w.clear_history(None)
    assert w.view()["arp"]["conflicts"] == [] and w.view()["arp"]["tracked"] == 0
    clock.now += 5.0
    w.tick()
    assert w.view()["arp"]["conflicts"] == []


# =========================================================================================
# Pro AV
# =========================================================================================
def _finished(scanner) -> Dict[str, Any]:
    """A real (short) scan on the fake sockets: started, stopped by hand, its result kept."""
    scanner.start(seconds=120)
    scanner.cancel()
    _wait(scanner)
    assert scanner.last() is not None
    return scanner.last()


@pytest.fixture
def av_sockets(monkeypatch):
    monkeypatch.setattr(ProAvScanner, "_open_socket", lambda self, port, groups, ip: FakeSocket())


def test_a_pro_av_result_before_the_range_stays_and_one_inside_it_goes(scanner, av_sockets):
    result = _finished(scanner)
    assert scanner.clear_history(result["ts"] + 1) == {"cleared": 0, "stopped": False}
    assert scanner.last() is not None and scanner.job()["state"] == "cancelled"
    assert scanner.clear_history(result["ts"] - 1) == {"cleared": 1, "stopped": False}
    assert scanner.last() is None and scanner.job()["state"] == "idle"
    assert scanner.status()["last_run_ts"] is None and scanner.tile()["devices"] == 0


def test_all_time_always_clears_the_pro_av_result(scanner, av_sockets):
    _finished(scanner)
    assert scanner.clear_history(None) == {"cleared": 1, "stopped": False}
    assert scanner.clear_history(None) == {"cleared": 0, "stopped": False}


def test_a_pro_av_scan_running_during_the_clear_is_stopped_and_what_it_heard_is_thrown_away(monkeypatch, av_sockets):
    monkeypatch.setattr(proav.os, "name", "nt", raising=False)
    monkeypatch.setattr(ProAvScanner, "_adapter_list", lambda self: [FakeAdapter()])
    monkeypatch.setattr(ProAvScanner, "_internet_index", lambda self, adapters: 12)
    monkeypatch.setattr(ProAvScanner, "_arp_table", lambda self: {})
    monkeypatch.setattr(proav, "_L2Listener", lambda if_index, joined: _NoL2())
    seen: List[tuple] = []
    lock = threading.Lock()

    class Bus:
        def publish(self, event, payload):
            with lock:
                seen.append((event, payload))

    scanner = ProAvScanner(Bus())
    scanner.start(seconds=120)
    assert scanner.clear_history(None) == {"cleared": 0, "stopped": True}
    _wait(scanner)
    assert scanner.last() is None, "the scan finished after the clear, and its result was not kept"
    assert scanner.job()["state"] == "idle" and scanner.status()["last_run_ts"] is None
    with lock:
        states = [payload["job"]["state"] for event, payload in seen if event == proav.EVENT]
    assert states[-1] == "idle", "proav.state tells the page and the tile"
    # the next scan is an ordinary one: nothing of the clear lingers
    assert _finished(scanner)["cancelled"] is True


def test_the_pro_av_clear_publishes_its_state(monkeypatch):
    seen = []

    class Bus:
        def publish(self, event, payload):
            seen.append(event)

    ProAvScanner(Bus()).clear_history(None)
    assert seen == [proav.EVENT]


# =========================================================================================
# SIP: the ALG and STUN checks, the call-flow slots and the tile cache
# =========================================================================================
def _alg(ts: float) -> Dict[str, Any]:
    return {"ts": ts, "host": "192.0.2.5", "port": 5060, "transport": "udp", "verdict": "clean", "probes": [],
            "changes": [], "public": None, "via_srv": None, "findings": [], "note": None}


def _stun(ts: float) -> Dict[str, Any]:
    return {"ts": ts, "mapping": "endpoint-independent"}


@pytest.mark.parametrize("kind", ["alg", "stun"])
def test_a_sip_check_result_inside_the_range_goes_and_one_before_it_stays(monkeypatch, kind):
    if kind == "alg":
        checker = sipalg.AlgChecker()
        monkeypatch.setattr(sipalg.AlgChecker, "_check", lambda self, host, port, ports: _alg(T0))
        run = lambda: checker.check("192.0.2.5")                       # noqa: E731
    else:
        checker = sipnat.StunChecker()
        monkeypatch.setattr(sipnat.StunChecker, "_check", lambda self, servers, local_port: _stun(T0))
        run = lambda: checker.check()                                   # noqa: E731
    run()
    assert checker.clear_history(T0 + 10) == 0 and checker.last()["ts"] == T0
    assert checker.clear_history(T0) == 1 and checker.last() is None, "at since_ts is inside the range"
    run()
    assert checker.clear_history(None) == 1 and checker.clear_history(None) == 0


@pytest.mark.parametrize("kind", ["alg", "stun"])
def test_a_sip_check_running_during_the_clear_answers_its_button_but_is_not_kept(monkeypatch, kind):
    holder: Dict[str, Any] = {}

    def slow(*_args: Any) -> Dict[str, Any]:
        assert holder["checker"].running() is True
        holder["checker"].clear_history(None)                 # the clear lands while the check is out on the wire
        return _alg(T0) if kind == "alg" else _stun(T0)

    if kind == "alg":
        holder["checker"] = sipalg.AlgChecker()
        monkeypatch.setattr(sipalg.AlgChecker, "_check", lambda self, host, port, ports: slow())
        run = lambda: holder["checker"].check("192.0.2.5")             # noqa: E731
    else:
        holder["checker"] = sipnat.StunChecker()
        monkeypatch.setattr(sipnat.StunChecker, "_check", lambda self, servers, local_port: slow())
        run = lambda: holder["checker"].check()                         # noqa: E731
    assert run()["ts"] == T0, "the button that started it still gets its answer"
    assert holder["checker"].last() is None
    monkeypatch.setattr(type(holder["checker"]), "_check",
                        (lambda self, host, port, ports: _alg(T0 + 1)) if kind == "alg"
                        else (lambda self, servers, local_port: _stun(T0 + 1)))
    run()
    assert holder["checker"].last()["ts"] == T0 + 1, "a check started after the clear is kept as usual"


def _flow_file(path: Path) -> Path:
    return put(path, mtime=T0 - 60, frames=[udp_frame(5060, 5060, SIP_INVITE, src="192.0.2.10", dst="192.0.2.20")])


def test_call_flow_slots_loaded_in_the_range_close_and_their_files_are_never_touched(tmp_path):
    loaded = {"at": T0 - 7200}
    reader = sipflow.FlowReader(clock=lambda: loaded["at"])
    first, second = _flow_file(tmp_path / "client.pcapng"), _flow_file(tmp_path / "server.pcapng")
    before = fingerprint(first), fingerprint(second)
    reader.open(str(first), "a")
    loaded["at"] = T0 - 600
    reader.open(str(second), "b")

    assert reader.clear_history(T0 - 3600) == 1
    assert [s["slot"] for s in reader.sources()] == ["a"]
    assert reader.clear_history(None) == 1 and reader.sources() == []
    assert (fingerprint(first), fingerprint(second)) == before


def test_a_call_flow_slot_on_a_capture_the_same_clear_deleted_is_closed_whenever_it_was_loaded(cap):
    reader = sipflow.FlowReader(clock=lambda: T0 - 7200)
    saved = _flow_file(cap.folder / NAME_NEW)
    reader.open(str(saved), "a")
    result = cap.mgr.clear_history(T0 - 3600)
    assert result["deleted_names"] == [NAME_NEW]
    closed = reader.clear_history(T0 - 3600, [os.path.join(cap.folder, n) for n in result["deleted_names"]])
    assert closed == 1 and reader.sources() == []


def test_a_capture_read_into_a_call_flow_slot_while_the_history_is_cleared_is_not_kept(tmp_path, monkeypatch):
    """A big capture takes a while to read, and a clear that lands during the read finds no slot to close yet: the
    reading would appear afterwards, loaded inside the cleared time.  So a read notes the clears before it starts,
    and when one ran meanwhile the reading is not kept and the button is told why.  The file is never touched."""
    reader = sipflow.FlowReader(clock=lambda: T0)
    first = _flow_file(tmp_path / "site.pcapng")
    before = fingerprint(first)
    real = reader._read_into

    def read_across_a_clear(source):
        real(source)
        assert reader.clear_history(T0 - 300) == 0            # nothing in a slot yet for the clear to close

    monkeypatch.setattr(reader, "_read_into", read_across_a_clear)
    with pytest.raises(sipflow.FlowError, match=re.escape(sipflow.CLEARED_TEXT)):
        reader.open(str(first), "a")
    assert reader.sources() == [] and fingerprint(first) == before
    monkeypatch.setattr(reader, "_read_into", real)
    reader.open(str(first), "a")
    assert [s["slot"] for s in reader.sources()] == ["a"], "a load after the clear is kept as usual"


def test_the_sip_tile_cache_is_dropped_so_the_next_tile_reads_what_is_left():
    db = FakeDb((GATEWAY,), {1: minute_rows(120, avg=2.0, jitter=0.5)})
    qual = sipqual.SipQualifier(db, clock=lambda: 1_700_000_000.0)
    qual.tile()
    reads = len(db.calls)
    qual.tile()
    assert len(db.calls) == reads, "served from the cache"
    qual.invalidate()
    qual.tile()
    assert len(db.calls) > reads, "read again after the clear"


def test_a_sip_tile_being_built_while_the_cache_is_dropped_is_answered_but_not_kept():
    class RacingDb(FakeDb):
        def list_targets(self, enabled_only=False):
            if not self.calls:
                holder["qual"].invalidate()                   # the clear lands mid-read
            return super().list_targets(enabled_only)

    holder: Dict[str, Any] = {}
    db = RacingDb((GATEWAY,), {1: minute_rows(120, avg=2.0, jitter=0.5)})
    holder["qual"] = sipqual.SipQualifier(db, clock=lambda: 1_700_000_000.0)
    assert holder["qual"].tile()["available"] is True
    reads = len(db.calls)
    holder["qual"].tile()
    assert len(db.calls) > reads, "the tile built across the clear was not cached"


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), True, "1790000000"])
def test_the_sip_and_pro_av_clears_refuse_a_since_that_is_not_a_time_and_keep_what_they_hold(
        monkeypatch, tmp_path, scanner, av_sockets, bad):
    """The same rule as the capture clear: None or a finite time, nothing else.  A refused clear changes nothing, and
    it does not count as a clear either (a check that finishes afterwards is still kept)."""
    result = _finished(scanner)
    alg, stun = sipalg.AlgChecker(), sipnat.StunChecker()
    monkeypatch.setattr(sipalg.AlgChecker, "_check", lambda self, host, port, ports: _alg(T0))
    monkeypatch.setattr(sipnat.StunChecker, "_check", lambda self, servers, local_port: _stun(T0))
    alg.check("192.0.2.5")
    stun.check()
    reader = sipflow.FlowReader(clock=lambda: T0)
    reader.open(str(_flow_file(tmp_path / "site.pcapng")), "a")

    for clear in (scanner.clear_history, alg.clear_history, stun.clear_history, reader.clear_history):
        with pytest.raises(ValueError):
            clear(bad)

    assert scanner.last() == result and scanner.job()["state"] == "cancelled"
    assert alg.last()["ts"] == T0 and stun.last()["ts"] == T0
    assert [s["slot"] for s in reader.sources()] == ["a"]
    assert alg._cleared == 0 and stun._cleared == 0 and reader._cleared == 0


# =========================================================================================
# the Wi-Fi survey (TNT.exe) and its bridge method
# =========================================================================================
@pytest.fixture
def wifi():
    clock = FakeClock()
    world = World(clock)
    world.interfaces[0]["state"] = "connected"
    world.connection = {"ssid": b"Synthetic Lab", "bssid": BSSID_A, "rx_kbps": 866700, "tx_kbps": 780000}
    survey = make_survey(world, clock)
    survey.window_shown()
    return SimpleNamespace(clock=clock, world=world, survey=survey, start=clock.wall)


def hear(w, seconds: float, bssids) -> None:
    """Fresh beacons from *bssids* for *seconds*, read every 5 s under an active lease."""
    for _ in range(int(seconds // 5)):
        w.world.entries = [ap_entry(b, -50 - i, w.clock.wall) for i, b in enumerate(bssids)]
        simulate(w.survey, w.clock, 5, renew_every=5)


def _points(view) -> int:
    return sum(len(points) for points in view["history"].values()) + len(view["link_history"])


def test_wifi_points_from_the_cut_on_go_from_every_ap_and_the_link_and_an_emptied_ap_goes(wifi):
    hear(wifi, 120, [BSSID_A])
    cut = wifi.clock.wall
    hear(wifi, 60, [BSSID_A, BSSID_B])                        # B is only ever heard after the cut
    before = wifi.survey.survey()
    assert len(before["aps"]) == 2

    result = wifi.survey.clear_since(cut)

    after = wifi.survey.survey()
    assert result == {"aps_dropped": 1, "points_dropped": _points(before) - _points(after)}
    assert result["points_dropped"] > 0
    assert [ap["bssid"] for ap in after["aps"]] == ["02:11:22:33:44:01"]
    assert after["history"]["02:11:22:33:44:01"] and all(t < cut for t, _ in after["history"]["02:11:22:33:44:01"])
    assert after["link_history"] and all(t < cut for t, _ in after["link_history"])
    ap = after["aps"][0]
    newest = after["history"]["02:11:22:33:44:01"][-1]
    assert ap["last_seen"] < cut and (ap["last_seen"], ap["rssi"]) == (newest[0], newest[1])
    assert after["started_ts"] == wifi.start, "a partial clear keeps the session"


def test_wifi_none_is_the_same_as_clear(wifi):
    hear(wifi, 30, [BSSID_A, BSSID_B])
    before = wifi.survey.survey()
    result = wifi.survey.clear_since(None)
    view = wifi.survey.survey()
    assert result == {"aps_dropped": 2, "points_dropped": _points(before)}
    assert view["aps"] == [] and view["history"] == {} and view["link_history"] == []
    assert view["started_ts"] == wifi.clock.wall, "the session restarted, as clear() does"


def test_wifi_a_beacon_from_the_cleared_time_read_after_the_clear_is_stamped_at_the_clear(wifi):
    hear(wifi, 60, [BSSID_A])
    cut = wifi.clock.wall - 30
    wifi.clock.advance(1)
    cleared_at = wifi.clock.wall
    wifi.survey.clear_since(cut)
    # Windows' cached list still holds a beacon heard ten seconds before the clear, which no read has seen yet
    wifi.world.entries = [ap_entry(BSSID_A, -61, cleared_at - 10)]
    simulate(wifi.survey, wifi.clock, 5, renew_every=5)
    history = wifi.survey.survey()["history"]["02:11:22:33:44:01"]
    assert all(t < cut or t >= cleared_at for t, _ in history), history
    assert history[-1][1] == -61 and history[-1][0] >= cleared_at


def test_wifi_a_read_that_straddles_the_clear_cannot_land_in_the_cleared_time():
    """A read pass talks to Windows without the lock and takes the time when it is done; the clear can land between
    that and the pass taking the lock.  Its readings, the signal and the link speed alike, are then stamped at the
    clear, never inside the time the clear removed."""
    clock = FakeClock()
    world = World(clock)
    world.interfaces[0]["state"] = "connected"
    world.connection = {"ssid": b"Synthetic Lab", "bssid": BSSID_A, "rx_kbps": 866700, "tx_kbps": 780000}
    plan = {"armed": False, "cut": None, "cleared_at": None}

    def wall() -> float:
        if plan["armed"]:                                     # the pass has just read Windows and asks the time
            plan["armed"] = False
            read_at = clock.time()
            clock.advance(1.0)
            plan["cleared_at"] = clock.time()
            survey.clear_since(plan["cut"])                   # ... and the clear runs before the pass is applied
            return read_at
        return clock.time()

    survey = wifi_survey.WifiSurvey(api_factory=world.factory, clock=wall, monotonic=clock.monotonic, threaded=False)
    survey.window_shown()
    w = SimpleNamespace(clock=clock, world=world, survey=survey)
    hear(w, 60, [BSSID_A])
    plan["cut"] = clock.wall - 20
    world.entries = [ap_entry(BSSID_A, -63, clock.wall - 2)]   # a new beacon, inside the time about to be cleared
    clock.advance(5.0)
    survey.survey({"active": True})
    plan["armed"] = True
    survey.tick()
    assert plan["cleared_at"] is not None, "the clear ran inside the pass"
    view = survey.survey()
    stamps = [t for t, _ in view["history"]["02:11:22:33:44:01"]] + [t for t, _ in view["link_history"]]
    assert all(t < plan["cut"] or t >= plan["cleared_at"] for t in stamps), (plan, stamps)
    assert view["history"]["02:11:22:33:44:01"][-1] == [plan["cleared_at"], -63]


def test_wifi_the_first_point_after_a_clear_never_moves_the_newest_kept_one():
    """Points close together are coalesced into one per COALESCE_S bucket, the newest reading winning.  The newest
    point a clear keeps is from before the clear; if the first point after it fell in the same bucket it would
    overwrite it, moving a kept reading into time after the clear.  So the first point after a clear is its own."""
    series = wifi_survey._Series()
    bucket = int(wifi_survey.COALESCE_S * 10)
    series.add(100, -50, bucket, 100)
    series.add(160, -52, bucket, 100)
    assert series.drop_from(180) == 0                     # nothing stamped from the cut on, but the clear still ran
    series.add(190, -70, bucket, 100)                     # the same bucket as the kept 160
    assert [list(a) for a in series.window(None)] == [[100, 160, 190], [-50, -52, -70]]
    series.add(195, -71, bucket, 100)                     # after that, coalescing is as usual
    assert [list(a) for a in series.window(None)] == [[100, 160, 195], [-50, -52, -71]]


@pytest.mark.parametrize("bad", [True, "1790000000", float("nan"), float("inf"), 10 ** 400, [1], {}])
def test_wifi_a_since_that_is_not_a_time_is_refused(wifi, bad):
    with pytest.raises(ValueError):
        wifi.survey.clear_since(bad)


@pytest.mark.parametrize("url", [None, "http://127.0.0.1:7131/", "https://example.com/wifi", "about:blank"])
def test_the_wifi_clear_since_bridge_refuses_exactly_as_wifi_clear_does(app, monkeypatch, url):
    touched = []
    monkeypatch.setattr(app.wifi, "clear_since", lambda *a, **k: touched.append("clear_since"))
    monkeypatch.setattr(app.wifi, "clear", lambda *a, **k: touched.append("clear"))
    app.window = _page(url)
    refused = {"ok": False, "error": tray.WIFI_BRIDGE_REFUSED}
    assert app.bridge.wifi_clear_since(1_790_000_000.0) == refused == app.bridge.wifi_clear()
    assert app.bridge.wifi_clear_since(None) == refused and touched == []


def test_the_wifi_clear_since_bridge_answers_the_dashboard(app, monkeypatch):
    app.window = _page(SERVICE + "/#settings")
    calls = []
    monkeypatch.setattr(app.wifi, "clear_since", lambda since: calls.append(since) or {"aps_dropped": 3,
                                                                                       "points_dropped": 40})
    assert app.bridge.wifi_clear_since(1_790_000_000) == {"ok": True, "aps_dropped": 3, "points_dropped": 40}
    assert app.bridge.wifi_clear_since(None) == {"ok": True, "aps_dropped": 3, "points_dropped": 40}
    assert calls == [1_790_000_000, None]
    for junk in (True, "1790000000", [], {}, float("nan"), 10 ** 400):
        assert app.bridge.wifi_clear_since(junk) == {"ok": False, "error": tray.WIFI_SINCE_TEXT}
    assert calls == [1_790_000_000, None], "junk never reaches the survey"
    assert "wifi_clear_since" in [f.__name__ for f in tray.bridge_functions(app.bridge)]


def test_the_wifi_clear_since_bridge_on_a_real_survey_and_when_it_fails(app, monkeypatch):
    app.window = _page(SERVICE)
    assert app.bridge.wifi_clear_since(None) == {"ok": True, "aps_dropped": 0, "points_dropped": 0}

    def boom(since):
        raise RuntimeError("survey exploded")

    monkeypatch.setattr(app.wifi, "clear_since", boom)
    assert app.bridge.wifi_clear_since(1.0) == {"ok": False, "error": tray.WIFI_BRIDGE_FAILED}
