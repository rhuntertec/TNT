"""tnt.switchport: listening for the switch's LLDP / CDP announcement through Packet Monitor.

A fake Packet Monitor runner (:class:`test_pktmon.FakePktmon`) plays pktmon.exe, the components and capability are
handed in, the folder security is a recorder, and time is a fake clock that only ``wait`` moves: no test runs pktmon or
sleeps for real.  Stand-ins: the switch LAB-SW-01 ("Example Switch 8P") on Port 7, the adapter ``Ethernet``
(component 3, ifIndex 21) with MAC 02:00:5e:10:00:01.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from test_pktmon import (ADAPTER_MAC, COMPONENTS, Acl, Bus, Clock, FakePktmon, Gate, lldp_frame, nic,  # noqa: F401
                         own_lldp_frame, pcapng_file, wifi)
from tnt import pktmon, winacl
from tnt import switchport as sp
from tnt.pktmon import PktmonBusy, PktmonUnavailable
from tnt.switchport import SWITCH_JOB_KEYS, SWITCH_STATUS_KEYS, SwitchPortFinder

OK = {"ok": True, "reason": None}
NO_NEIGHBOR = ("No LLDP or CDP heard in {} s. The switch may not send them (unmanaged switches never do), or LLDP is "
               "turned off on its port.")


@pytest.fixture(autouse=True)
def _pktmon_lock_left_free():
    yield
    holder = pktmon.LOCK.holder()
    pktmon.LOCK.release()
    assert holder is None, f"a test left tnt.pktmon.LOCK held by {holder}"


def adapter_list(state: dict) -> list:
    if state["broken"]:
        raise OSError("GetAdaptersAddresses failed (TNT test)")
    return state["adapters"]


def wait_until(predicate, timeout: float = 5.0) -> bool:
    """Polls *predicate* briefly (another thread's step, never a contract timer)."""
    done = threading.Event()
    for _ in range(int(timeout / 0.005)):
        if predicate():
            return True
        done.wait(0.005)
    return bool(predicate())


def make(tmp_path, fake: FakePktmon, *, adapters=None, clock=None, acl=None, components=None, capability=None,
         **kw: Any) -> SimpleNamespace:
    clock = clock or Clock()
    state = {"adapters": list(adapters if adapters is not None else [nic()]), "generation": 1, "nic": None,
             "broken": False}
    bus = Bus()
    acl = acl or Acl()
    finder = SwitchPortFinder(
        bus, adapters_fn=lambda: adapter_list(state), internet_nic_fn=lambda: state["nic"],
        generation_fn=lambda: state["generation"], runner=fake, clock=clock.time, monotonic=clock.monotonic,
        wait=clock.wait, session_running_fn=lambda: fake.running,
        components_fn=lambda: list(components if components is not None else COMPONENTS),
        capability_fn=lambda: dict(capability or OK), work_dir_fn=lambda: tmp_path / "captures", acl=acl, **kw)
    return SimpleNamespace(finder=finder, bus=bus, acl=acl, clock=clock, state=state, fake=fake,
                           folder=tmp_path / "captures")


def join(*names: str, timeout: float = 5.0) -> None:
    names = names or (sp.THREAD_NAME,)
    for thread in threading.enumerate():
        if thread.name in names and thread is not threading.current_thread():
            thread.join(timeout)
            assert not thread.is_alive(), f"{thread.name} did not finish"


def stem(clock: Clock) -> str:
    return "TNT-switchport-" + time.strftime("%Y%m%d-%H%M%S", time.localtime(clock.now))


def states(env) -> list:
    return [e["job"]["state"] for e in env.bus.of(sp.EVENT)]


# --------------------------------------------------------------------------- guard
def test_conftest_guard_is_active_for_a_finder_without_fakes(tmp_path):
    assert getattr(pktmon._subprocess_run, "__module__", None) == "conftest", \
        "tests/conftest.py must replace tnt.pktmon._subprocess_run"
    finder = SwitchPortFinder(Bus(), adapters_fn=lambda: [nic()], internet_nic_fn=lambda: None, capability_fn=lambda: OK,
                              work_dir_fn=lambda: tmp_path / "captures", acl=Acl())
    with pytest.raises(PktmonUnavailable) as err:          # its default `pktmon list --all` met the guard
        finder.start()
    assert str(err.value) == "Packet Monitor does not list this adapter"
    assert pktmon.LOCK.holder() is None and not (tmp_path / "captures" / pktmon.MARKER_NAME).exists()


# --------------------------------------------------------------------------- vendor
def test_neighbours_get_the_vendor_from_the_chassis_mac(monkeypatch):
    """_add_vendors fills vendor from the chassis MAC's OUI; a non-MAC chassis id (a CDP device name) or none gets None."""
    monkeypatch.setattr(sp.oui, "vendor_for_mac", lambda mac: "Example Networks" if sp.oui.normalize_mac(str(mac)) else None)
    neighbors = [{"chassis_id": "02:00:5E:10:00:02", "vendor": None}, {"chassis_id": "LAB-SW-01", "vendor": None},
                 {"chassis_id": None, "vendor": None}]
    assert SwitchPortFinder._add_vendors(neighbors) is neighbors
    assert [n["vendor"] for n in neighbors] == ["Example Networks", None, None]


# --------------------------------------------------------------------------- a listen
def test_early_stop_finds_the_switch_and_cleans_up(tmp_path):
    fake = FakePktmon(inbound=[0, 0, 2], pcaps=[pcapng_file(own_lldp_frame(), lldp_frame())])
    env = make(tmp_path, fake)
    name = stem(env.clock)
    etl, pcap = str(env.folder / (name + ".etl")), str(env.folder / (name + ".pcapng"))
    job = env.finder.start()
    assert job["state"] == "listening" and job["listen_s"] == 65 and job["generation"] == 1
    assert job["adapter"] == {"name": "Ethernet", "index": 21, "mac": ADAPTER_MAC}
    join()
    job = env.finder.job()
    assert tuple(job) == SWITCH_JOB_KEYS
    assert (job["state"], job["error"], job["reason"]) == ("done", None, None)
    assert [(n["protocol"], n["switch_name"], n["switch_description"], n["port_id"]) for n in job["neighbors"]] == \
        [("lldp", "LAB-SW-01", "Example Switch 8P", "Port 7")]                 # Windows' own LLDPDU is left out
    assert env.clock.waits == [2.0, 2.0, 2.0, 1.0]                             # three polls, then the settle
    assert job["elapsed_s"] == 7.0 and job["started_ts"] < job["ts"]
    assert fake.commands() == [
        ["filter", "list"],
        ["filter", "add", "TNT-LLDP", "-d", "35020"],
        ["filter", "add", "TNT-CDP", "-m", "01-00-0C-CC-CC-CC"],
        ["start", "--capture", "--comp", "3", "--pkt-size", "0", "-f", etl, "-s", "64"],
        ["counters", "--json"], ["counters", "--json"], ["counters", "--json"],
        ["stop"],
        ["filter", "remove"],
        ["etl2pcap", etl, "--out", pcap, "--component-id", "3"],
    ]
    assert list(env.folder.iterdir()) == []                                   # ETL, pcapng and marker gone
    assert env.acl.calls == [(str(env.folder), winacl.CAPTURES_SDDL)]
    seen = states(env)
    assert seen[0] == "listening" and seen[-1] == "done" and seen.count("listening") >= 3
    assert all(tuple(e["job"]) == SWITCH_JOB_KEYS for e in env.bus.of(sp.EVENT))


def test_the_marker_is_written_before_the_capture_starts(tmp_path):
    gate = Gate()
    fake = FakePktmon(gates={"start": gate}, inbound=[1], pcaps=[pcapng_file(lldp_frame())])
    env = make(tmp_path, fake)
    env.finder.start()
    try:
        assert gate.entered.wait(5)
        marker = json.loads((env.folder / pktmon.MARKER_NAME).read_text("utf-8"))
        assert marker == {"purpose": "switchport", "files": [stem(env.clock) + ".etl", stem(env.clock) + ".pcapng"],
                          "started_ts": env.clock.now}
    finally:
        gate.release()
        join()
    assert env.finder.job()["state"] == "done" and list(env.folder.iterdir()) == []


def test_no_neighbour_in_the_window_gives_the_reason(tmp_path):
    fake = FakePktmon(inbound=[0], pcaps=[pcapng_file()])
    env = make(tmp_path, fake)
    env.finder.start(seconds=20)
    join()
    job = env.finder.job()
    assert (job["state"], job["neighbors"], job["error"]) == ("done", [], None)
    assert job["reason"] == NO_NEIGHBOR.format(20)
    assert sum(env.clock.waits) == 20 and fake.keys().count("counters") == 10
    assert fake.keys().count("start") == 1 and fake.keys().count("etl2pcap") == 1


def test_unreadable_counters_listen_the_whole_window_then_convert_once(tmp_path):
    fake = FakePktmon(inbound=[None], pcaps=[pcapng_file(lldp_frame())])
    env = make(tmp_path, fake)
    env.finder.start(seconds=30)
    join()
    job = env.finder.job()
    assert job["state"] == "done" and [n["switch_name"] for n in job["neighbors"]] == ["LAB-SW-01"]
    assert fake.keys().count("counters") == 1 and fake.keys().count("etl2pcap") == 1
    assert sum(env.clock.waits) == 30 and job["elapsed_s"] == 30.0


def test_own_lldp_frame_is_ignored_and_the_capture_restarts_for_the_time_left(tmp_path):
    fake = FakePktmon(inbound=[1, 1, 2], pcaps=[pcapng_file(own_lldp_frame()), pcapng_file(lldp_frame())])
    env = make(tmp_path, fake)
    env.finder.start(seconds=30)
    join()
    job = env.finder.job()
    assert job["state"] == "done" and [n["switch_name"] for n in job["neighbors"]] == ["LAB-SW-01"]
    assert fake.keys().count("start") == 2 and fake.keys().count("etl2pcap") == 2
    # round 1 heard a frame at the first poll (it was Windows' own); after the restart a counter that still reads 1 is
    # no news, the 2 is
    assert env.clock.waits == [2.0, 1.0, 2.0, 2.0, 1.0]
    assert list(env.folder.iterdir()) == []


def test_a_foreign_packet_monitor_session_ends_the_job_in_error(tmp_path):
    fake = FakePktmon(running=True)
    env = make(tmp_path, fake)
    assert env.finder.start()["state"] == "listening"
    join()
    job = env.finder.job()
    assert (job["state"], job["error"]) == ("error", "Packet Monitor is already capturing for another program")
    assert fake.calls == [] and list(env.folder.iterdir()) == []


def test_the_docs_say_another_programs_capture_ends_the_listen_not_the_post():
    """start() never looks for another program's capture or filters (§3.4 has no such step: the worker's session does), so
    POST /api/netcheck/switch answers `listening` and the job ends `error` (the test above).  The route table and DESIGN
    must not promise a 409 for it."""
    root = Path(__file__).resolve().parents[1]
    arch, design = root / "docs" / "ARCHITECTURE.md", root / "docs" / "DESIGN.md"
    if not (arch.is_file() and design.is_file()):
        pytest.skip("the Markdown docs are not in this checkout (they are not published)")
    row = next(ln for ln in arch.read_text(encoding="utf-8").splitlines() if ln.startswith("| POST `/netcheck/switch` |"))
    conflict = row.split("**409** `conflict`", 1)[1].split("**409** `unavailable`", 1)[0]
    assert "another program" not in conflict, conflict
    assert "Packet Monitor is already capturing for another program" in row and "Packet Monitor has filters set by another program" in row
    text = " ".join(design.read_text(encoding="utf-8").split())
    assert "a 409 (the other Packet Monitor tool, another program's capture) a toast" not in text
    assert "another program's capture or filters end the listen" in text


@pytest.mark.parametrize("fake, error", [
    (FakePktmon(inbound=[3], rc={"etl2pcap": 2}), "Packet Monitor could not convert (exit 2)"),
    (FakePktmon(inbound=[3], rc={"start": 87}), "Packet Monitor could not start (exit 87)"),
    (FakePktmon(inbound=[3], pcaps=[b"not a capture"]), "The capture could not be read"),
])
def test_failures_end_the_job_in_error_and_clean_up(tmp_path, fake, error):
    env = make(tmp_path, fake)
    env.finder.start()
    join()
    job = env.finder.job()
    assert (job["state"], job["error"], job["neighbors"]) == ("error", error, [])
    assert list(env.folder.iterdir()) == [] and not fake.running and fake.filters == []
    assert env.bus.of(sp.EVENT)[-1]["job"]["state"] == "error"


# --------------------------------------------------------------------------- stopping
def test_stop_cancels_a_listen_and_keeps_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(sp, "STOP_WAIT_S", 0.05)
    clock = Clock()
    clock.hold()
    fake = FakePktmon(inbound=[0], pcaps=[pcapng_file(lldp_frame())])
    env = make(tmp_path, fake, clock=clock)
    env.finder.start()
    assert clock.entered.wait(5)                       # the worker waits for its first poll
    assert env.finder.stop()["state"] == "cancelled"   # at once, though the worker is still cleaning up
    with pytest.raises(PktmonBusy, match="TNT is finding the switch port"):
        pktmon.LOCK.acquire("capture")                 # ... and it keeps Packet Monitor until it is done
    clock.release()
    join()
    job = env.finder.job()
    assert (job["state"], job["neighbors"], job["reason"]) == ("cancelled", [], None)
    assert fake.keys()[-2:] == ["stop", "filter remove"] and "etl2pcap" not in fake.keys()
    assert list(env.folder.iterdir()) == []
    assert states(env)[-1] == "cancelled"
    before = len(fake.calls)
    assert env.finder.stop()["state"] == "cancelled" and len(fake.calls) == before


def test_close_cancels_a_listen_and_returns_at_once_when_idle(tmp_path):
    fake = FakePktmon()
    env = make(tmp_path, fake)
    env.finder.close(1.0)
    assert fake.calls == [] and env.finder.job()["state"] == "idle"
    gate = Gate()
    fake.gates = {"counters": gate}
    env.finder.start()
    assert gate.entered.wait(5)
    env.finder.close(0.0)
    gate.release()
    join()
    assert env.finder.job()["state"] == "cancelled" and list(env.folder.iterdir()) == []


def test_a_network_change_that_takes_the_adapter_down_cancels_without_waiting(tmp_path):
    gate = Gate()
    fake = FakePktmon(inbound=[0], gates={"counters": gate})
    env = make(tmp_path, fake)
    env.finder.start()
    try:
        assert gate.entered.wait(5)                    # the worker is inside `pktmon counters`
        env.state["adapters"] = [nic(status="down")]
        env.state["generation"] = 2
        t0 = time.monotonic()
        env.finder.on_network_change({"generation": 2})
        assert time.monotonic() - t0 < 0.5
        assert any(t.name == "tnt-switchport-netstop" for t in threading.enumerate())
        assert wait_until(env.finder._cancel.is_set)   # the helper asked the listen to stop before pktmon answers
        assert env.finder.job()["state"] == "listening"
    finally:
        gate.release()
    join(sp.NETSTOP_THREAD_NAME, sp.THREAD_NAME)
    job = env.finder.job()
    assert job["state"] == "cancelled"
    assert "etl2pcap" not in fake.keys() and fake.keys()[-2:] == ["stop", "filter remove"]


def test_a_generation_change_clears_kept_results_but_never_cancels_a_listen(tmp_path):
    fake = FakePktmon(inbound=[2], pcaps=[pcapng_file(lldp_frame())])
    env = make(tmp_path, fake)
    env.finder.start()
    join()
    assert (env.finder.job()["state"], env.finder.job()["generation"]) == ("done", 1)
    published = len(env.bus.of(sp.EVENT))
    env.finder.on_network_change({"generation": 1})               # same network: the result stays
    assert env.finder.job()["state"] == "done" and len(env.bus.of(sp.EVENT)) == published
    env.state["generation"] = 2
    env.finder.on_network_change({"generation": 2})
    assert (env.finder.job()["state"], env.finder.job()["generation"]) == ("idle", 2)
    assert env.bus.of(sp.EVENT)[-1]["job"]["state"] == "idle"
    # a listen carries on across a generation change while its adapter stays up, and ends with the new generation
    gate = Gate()
    fake.gates = {"counters": gate}
    env.finder.start()
    try:
        assert gate.entered.wait(5)
        env.state["generation"] = 3
        env.finder.on_network_change({"generation": 3})
        assert not any(t.name == sp.NETSTOP_THREAD_NAME for t in threading.enumerate())
    finally:
        gate.release()
    join()
    job = env.finder.job()
    assert (job["state"], job["generation"]) == ("done", 3) and job["neighbors"]


def test_a_result_that_arrives_after_stop_stays_cancelled_and_is_not_kept(tmp_path, monkeypatch):
    monkeypatch.setattr(sp, "STOP_WAIT_S", 0.05)
    gate = Gate()
    fake = FakePktmon(inbound=[2], pcaps=[pcapng_file(lldp_frame())], gates={"etl2pcap": gate})
    env = make(tmp_path, fake)
    env.finder.start()
    try:
        assert gate.entered.wait(5)                    # the switch was heard; its capture is being converted
        assert env.finder.stop()["state"] == "cancelled"
    finally:
        gate.release()
    join()
    job = env.finder.job()
    assert (job["state"], job["neighbors"], job["reason"], job["error"]) == ("cancelled", [], None, None)
    assert [s for s in states(env) if s != "listening"] == ["cancelled", "cancelled"]    # never "done"
    assert list(env.folder.iterdir()) == [] and pktmon.LOCK.holder() is None
    env.state["generation"] = 2
    env.finder.on_network_change({"generation": 2})
    assert env.finder.job()["state"] == "idle"                                           # nothing was kept


def test_a_network_change_that_cannot_list_the_adapters_drops_and_cancels_nothing(tmp_path):
    fake = FakePktmon(inbound=[2], pcaps=[pcapng_file(lldp_frame())])
    env = make(tmp_path, fake)
    env.finder.start()
    join()
    env.state["broken"] = True
    env.finder.on_network_change({"generation": 1})
    assert env.finder.job()["state"] == "done"         # the adapter is not known to be down: the result stays
    env.state["broken"] = False
    gate = Gate()
    fake.gates = {"counters": gate}
    env.finder.start()
    try:
        assert gate.entered.wait(5)
        env.state["broken"] = True
        env.finder.on_network_change({"generation": 1})
        assert not any(t.name == sp.NETSTOP_THREAD_NAME for t in threading.enumerate())
        assert env.finder.job()["state"] == "listening"
    finally:
        env.state["broken"] = False
        gate.release()
    join()
    assert env.finder.job()["state"] == "done"


def test_the_network_stop_helper_cancels_only_the_listen_it_was_started_for(tmp_path):
    gate = Gate()
    fake = FakePktmon(inbound=[0], gates={"counters": gate})
    env = make(tmp_path, fake)
    env.finder.start()
    try:
        assert gate.entered.wait(5)
        earlier = env.finder.job()                     # a copy: it stands for a listen that already ended
        env.finder._stop_for_network(earlier)
        assert env.finder.job()["state"] == "listening" and pktmon.LOCK.holder() == "switchport"
    finally:
        env.finder.close(0.0)
        gate.release()
        join()
    assert env.finder.job()["state"] == "cancelled"


def test_kept_results_are_per_adapter_mac(tmp_path):
    second = nic("Ethernet 2", index=22, mac="02:00:5E:10:00:05")
    components = COMPONENTS + [{"id": 4, "if_index": 22, "name": "Ethernet 2"}]
    fake = FakePktmon(inbound=[2], pcaps=[pcapng_file(lldp_frame())])
    env = make(tmp_path, fake, adapters=[nic(), second], components=components)
    env.finder.start(adapter="Ethernet")
    join()
    env.clock.now += 60
    env.finder.start(adapter="Ethernet 2")
    join()
    assert env.finder.job()["adapter"]["name"] == "Ethernet 2"
    env.state["adapters"] = [nic()]                                # Ethernet 2 unplugged; the network did not change
    env.finder.on_network_change({"generation": 1})
    job = env.finder.job()
    assert (job["state"], job["adapter"]["name"]) == ("done", "Ethernet")
    assert env.bus.of(sp.EVENT)[-1]["job"]["adapter"]["name"] == "Ethernet"


# --------------------------------------------------------------------------- starting
def test_start_checks_capability_adapter_and_seconds_in_order(tmp_path):
    fake = FakePktmon(inbound=[2], pcaps=[pcapng_file(lldp_frame())])
    reason = "Packet Monitor on this PC is too old for this: update Windows"
    env = make(tmp_path, fake, adapters=[], capability={"ok": False, "reason": reason})
    with pytest.raises(PktmonUnavailable, match=f"^{reason}$"):
        env.finder.start(adapter="Nope", seconds="soon")
    env = make(tmp_path, fake, adapters=[wifi(), nic("vEthernet (Example)", index=30, physical=False),
                                         nic("Ethernet 2", index=22, status="down")])
    with pytest.raises(PktmonUnavailable, match=r"^Needs a wired \(Ethernet\) connection$"):
        env.finder.start(seconds="soon")
    with pytest.raises(ValueError) as err:
        env.finder.start(adapter="Wi-Fi")
    assert str(err.value) == "adapter 'Wi-Fi' is not a wired adapter that is up"
    with pytest.raises(ValueError, match="^adapter '5' is not a wired adapter that is up$"):
        env.finder.start(adapter=5)
    env = make(tmp_path, fake)
    for bad in ("30", 30.5, True, float("nan"), [30]):
        with pytest.raises(ValueError) as err:
            env.finder.start(seconds=bad)
        assert str(err.value) == "seconds must be a whole number from 20 to 120"
    assert fake.calls == [] and env.acl.calls == [] and pktmon.LOCK.holder() is None
    for given, listened in ((5, 20), (500, 120), (None, 65), (30.0, 30), (45, 45)):
        assert env.finder.start(seconds=given)["listen_s"] == listened
        join()
        assert env.finder.job()["state"] == "done"


def test_start_prefers_the_internet_adapter_then_the_first_wired_one(tmp_path):
    second = nic("Ethernet 2", index=22, mac="02:00:5E:10:00:05")
    components = COMPONENTS + [{"id": 4, "if_index": 22, "name": "Ethernet 2"}]
    fake = FakePktmon(inbound=[2], pcaps=[pcapng_file(lldp_frame())])
    env = make(tmp_path, fake, adapters=[nic(), second], components=components)
    env.state["nic"] = second
    assert env.finder.start()["adapter"]["name"] == "Ethernet 2"
    join()
    assert ["start", "--capture", "--comp", "4"] == fake.commands()[3][:4]
    env.state["nic"] = wifi()
    assert env.finder.start()["adapter"]["name"] == "Ethernet"
    join()


def test_a_second_start_while_listening_is_refused(tmp_path):
    gate = Gate()
    fake = FakePktmon(inbound=[0], gates={"counters": gate})
    env = make(tmp_path, fake)
    env.finder.start()
    try:
        assert gate.entered.wait(5)
        with pytest.raises(RuntimeError) as err:
            env.finder.start()
        assert str(err.value) == "a switch port search is already running"
    finally:
        env.finder.close(0.0)
        gate.release()
        join()


def test_the_lock_held_by_a_capture_refuses_a_search(tmp_path):
    fake = FakePktmon()
    env = make(tmp_path, fake)
    pktmon.LOCK.acquire("capture")
    try:
        with pytest.raises(PktmonBusy) as err:
            env.finder.start()
        assert str(err.value) == "A packet capture is running: stop it first"
    finally:
        pktmon.LOCK.release()
    assert fake.calls == [] and env.acl.calls == [] and env.finder.job()["state"] == "idle"


def test_a_folder_that_cannot_be_secured_fails_closed(tmp_path):
    fake = FakePktmon()
    acl = Acl(fail=PermissionError(5, "Access is denied"))
    env = make(tmp_path, fake, acl=acl)
    with pytest.raises(PktmonUnavailable) as err:
        env.finder.start()
    assert str(err.value) == "The capture folder could not be secured"
    assert acl.calls == [(str(env.folder), winacl.CAPTURES_SDDL)]
    assert fake.calls == [] and pktmon.LOCK.holder() is None and not env.folder.exists()
    assert env.finder.job()["state"] == "idle"


def test_an_adapter_packet_monitor_does_not_list_is_unavailable(tmp_path):
    fake = FakePktmon()
    env = make(tmp_path, fake, components=[{"id": 9, "if_index": 17, "name": "Wi-Fi"}])
    with pytest.raises(PktmonUnavailable, match="^Packet Monitor does not list this adapter$"):
        env.finder.start()
    assert fake.calls == [] and pktmon.LOCK.holder() is None and list(env.folder.iterdir()) == []


# --------------------------------------------------------------------------- views
def test_wired_adapters_and_status(tmp_path):
    third = nic("Ethernet 3", index=23, mac="02:00:5E:10:00:06")
    adapters = [nic(), nic("Ethernet 2", index=22, status="down"), nic("vEthernet (Example)", index=30, physical=False),
                wifi(), third]
    env = make(tmp_path, FakePktmon(), adapters=adapters)
    env.state["nic"] = third
    expected = [{"name": "Ethernet", "index": 21, "mac": ADAPTER_MAC, "is_internet": False},
                {"name": "Ethernet 3", "index": 23, "mac": "02:00:5E:10:00:06", "is_internet": True}]
    assert env.finder.wired_adapters() == expected
    assert all(tuple(a) == sp.WIRED_ADAPTER_KEYS for a in expected)
    status = env.finder.status()
    assert tuple(status) == SWITCH_STATUS_KEYS
    assert status == {"job": env.finder.job(), "adapters": expected, "available": True, "reason": None}
    assert status["job"]["state"] == "idle" and tuple(status["job"]) == SWITCH_JOB_KEYS
    reason = "Needs Windows 10 version 2004 (build 19041) or later"
    env = make(tmp_path, FakePktmon(), capability={"ok": False, "reason": reason})
    assert (env.finder.status()["available"], env.finder.status()["reason"]) == (False, reason)


def test_a_two_minute_listen_takes_no_real_time(tmp_path):
    fake = FakePktmon(inbound=[0], pcaps=[pcapng_file()])
    env = make(tmp_path, fake)
    t0 = time.perf_counter()
    env.finder.start(seconds=120)
    join()
    assert time.perf_counter() - t0 < 5.0
    assert sum(env.clock.waits) == 120 and env.finder.job()["reason"] == NO_NEIGHBOR.format(120)
