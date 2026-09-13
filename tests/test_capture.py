"""tnt.capture: the packet capture tool (validation, filters, the capture lifecycle, the Wi-Fi rewrite, files, counting
and retention).

A fake Packet Monitor runner (:class:`test_pktmon.FakePktmon`) plays pktmon.exe, the components, capability and free disk
space are handed in, the folder security is a recorder, and time is a fake clock that only ``wait`` moves: no test runs
pktmon or sleeps for real.  Adapters are the stand-ins ``Ethernet`` (component 3, ifIndex 21) and ``Wi-Fi`` (component 9,
ifIndex 17); frames carry MACs 02:00:5e:10:00:0x and addresses from 192.0.2.0/24 and 2001:db8::/32.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

from test_pktmon import (ADAPTER, ADAPTER_MAC, COMPONENTS, ETH_FRAME, IPV4_UDP, T0, WIFI_MAC, Acl, Bus, Clock,  # noqa: F401
                         FakePktmon, Gate, nic, pcapng_file, wifi)
from tnt import capture, pcapng, pktmon, winacl
from tnt.capture import (CAPTURE_FILE_KEYS, CAPTURE_JOB_KEYS, CAPTURE_STATUS_KEYS, CaptureFileBusy, CaptureFileMissing,
                         CaptureManager)
from tnt.pktmon import PktmonBusy, PktmonUnavailable
from tnt.switchport import SwitchPortFinder

OK = {"ok": True, "reason": None}
MIB, GIB = 1024 ** 2, 1024 ** 3
NAME = "TNT-capture-20260101-120000.pcapng"
AP = bytes.fromhex("02005e100007")
HOST = bytes.fromhex("02005e100008")
SNAP = b"\xaa\xaa\x03\x00\x00\x00"


@pytest.fixture(autouse=True)
def _pktmon_lock_left_free():
    yield
    holder = pktmon.LOCK.holder()
    pktmon.LOCK.release()
    assert holder is None, f"a test left tnt.pktmon.LOCK held by {holder}"


def make(tmp_path, fake: FakePktmon, *, adapters=None, clock=None, acl=None, components=None, capability=None,
         free: int = 10 * 1024 ** 4, **kw: Any) -> SimpleNamespace:
    clock = clock or Clock()
    state = {"adapters": list(adapters if adapters is not None else [nic(), wifi()])}
    bus = Bus()
    acl = acl or Acl()
    options = dict(adapters_fn=lambda: state["adapters"], runner=fake, clock=clock.time, monotonic=clock.monotonic,
                   wait=clock.wait, session_running_fn=lambda: fake.running,
                   components_fn=lambda: list(COMPONENTS if components is None else components),
                   capability_fn=lambda: dict(capability or OK), captures_dir_fn=lambda: tmp_path / "captures",
                   acl=acl, disk_free_fn=lambda path: free)
    options.update(kw)
    return SimpleNamespace(mgr=CaptureManager(bus, **options), bus=bus, acl=acl, clock=clock, state=state, fake=fake,
                           folder=tmp_path / "captures")


def join(*names: str, timeout: float = 5.0) -> None:
    names = names or (capture.THREAD_NAME,)
    for thread in threading.enumerate():
        if thread.name in names and thread is not threading.current_thread():
            thread.join(timeout)
            assert not thread.is_alive(), f"{thread.name} did not finish"


def stem(clock: Clock) -> str:
    return "TNT-capture-" + time.strftime("%Y%m%d-%H%M%S", time.localtime(clock.now))


def names(folder) -> list:
    return sorted(p.name for p in folder.iterdir())


def dot11(body: bytes, *, subtype: int = 8, frame_type: int = 2) -> bytes:
    """An 802.11 frame from the access point (FromDS, Protected set, as Packet Monitor delivers them): QoS data by
    default."""
    header = bytes([(subtype << 4) | (frame_type << 2), 0x42]) + b"\x00\x00" + ADAPTER + AP + HOST + b"\x10\x00"
    if frame_type == 2 and subtype & 8:
        header += b"\x00\x00"
    return header + body


def link_to(target, link):
    """A symbolic link to *target*, else (no privilege for one) a junction to its folder; returns the remover."""
    directory = os.path.isdir(target)
    try:
        os.symlink(target, link, target_is_directory=directory)
        return (lambda: os.rmdir(link)) if directory else (lambda: os.unlink(link))
    except (OSError, NotImplementedError):
        if sys.platform != "win32":
            pytest.skip("this system cannot make a link")
    import _winapi
    _winapi.CreateJunction(str(target if directory else os.path.dirname(target)), str(link))
    return lambda: os.rmdir(link)


# --------------------------------------------------------------------------- guard and constants
def test_conftest_guard_is_active_for_a_manager_without_fakes(tmp_path):
    assert getattr(pktmon._subprocess_run, "__module__", None) == "conftest", \
        "tests/conftest.py must replace tnt.pktmon._subprocess_run"
    mgr = CaptureManager(Bus(), adapters_fn=lambda: [nic()], capability_fn=lambda: OK,
                         captures_dir_fn=lambda: tmp_path / "captures", acl=Acl(), disk_free_fn=lambda path: 10 * GIB)
    with pytest.raises(PktmonUnavailable) as err:          # its default `pktmon list --all` met the guard
        mgr.start(adapter="Ethernet")
    assert str(err.value) == "Packet Monitor does not list this adapter"
    assert (mgr.job()["state"], mgr.job()["error"]) == ("error", "Packet Monitor does not list this adapter")
    assert pktmon.LOCK.holder() is None


def test_shapes_and_constants():
    assert capture.CAPTURE_SECONDS == (10, 30, 60, 300, 900)
    assert capture.CAPTURE_SIZES_MB == (64, 128, 256, 512, 1024)
    assert capture.FILE_RE == r"^TNT-capture-\d{8}-\d{6}\.pcapng$"
    assert CAPTURE_JOB_KEYS == ("id", "state", "adapter", "filters", "full_packets", "seconds", "size_mb", "started_ts",
                                "elapsed_s", "bytes", "file", "error", "note", "ts")
    assert CAPTURE_FILE_KEYS == ("name", "size", "created_ts", "packets")
    assert (capture.MAX_FILES, capture.MAX_TOTAL_BYTES, capture.MAX_AGE_S) == (10, 2 * GIB, 7 * 86400)
    assert issubclass(CaptureFileBusy, RuntimeError) and issubclass(CaptureFileMissing, LookupError)


# --------------------------------------------------------------------------- validation and filters
@pytest.mark.parametrize("body, message", [
    ({"seconds": 4}, "seconds must be a whole number from 5 to 1800"),
    ({"seconds": 1801}, "seconds must be a whole number from 5 to 1800"),
    ({"seconds": "60"}, "seconds must be a whole number from 5 to 1800"),
    ({"seconds": 60.5}, "seconds must be a whole number from 5 to 1800"),
    ({"seconds": True}, "seconds must be a whole number from 5 to 1800"),
    ({"seconds": None}, "seconds must be a whole number from 5 to 1800"),
    ({"size_mb": 100}, "size_mb must be one of 64, 128, 256, 512 or 1024"),
    ({"size_mb": "128"}, "size_mb must be one of 64, 128, 256, 512 or 1024"),
    ({"host": "example.com"}, "host must be an IP address"),
    ({"host": "192.0.2.0/24"}, "host must be an IP address"),
    ({"host": "fe80::1%12"}, "host must be an IP address"),
    ({"host": 3221225994}, "host must be an IP address"),                         # 192.0.2.10 as a number
    ({"port": 0}, "port must be a whole number from 1 to 65535"),
    ({"port": 65536}, "port must be a whole number from 1 to 65535"),
    ({"port": "80"}, "port must be a whole number from 1 to 65535"),
    ({"port": False}, "port must be a whole number from 1 to 65535"),
    ({"protocol": "sctp"}, "protocol must be tcp, udp, icmp or null"),
    ({"protocol": 6}, "protocol must be tcp, udp, icmp or null"),
    ({"port": 80, "protocol": "icmp"}, "port cannot be combined with protocol icmp"),
    ({"adapter": "Ethernet 9"}, "adapter 'Ethernet 9' is not up"),
    ({"adapter": "Ethernet 2"}, "adapter 'Ethernet 2' is not up"),                  # it is down
    ({"adapter": "vEthernet (Example)"}, "adapter 'vEthernet (Example)' is not up"),  # not physical
    ({"adapter": None}, "adapter '' is not up"),
    ({"full_packets": "yes"}, "full_packets must be true or false"),
    ({"full_packets": 1}, "full_packets must be true or false"),
])
def test_validation_texts(tmp_path, body, message):
    fake = FakePktmon()
    env = make(tmp_path, fake, adapters=[nic(), wifi(), nic("Ethernet 2", index=22, status="down"),
                                         nic("vEthernet (Example)", index=30, physical=False)])
    args = {"adapter": "Ethernet", "seconds": 60, "size_mb": 128, "full_packets": True, **body}
    with pytest.raises(ValueError) as err:
        env.mgr.start(**args)
    assert str(err.value) == message
    assert fake.calls == [] and env.acl.calls == [] and env.mgr.job() is None and pktmon.LOCK.holder() is None


NONE = {"host": None, "port": None, "protocol": None}


@pytest.mark.parametrize("criteria, filters, shown", [
    ({}, [], NONE),
    ({"host": "", "protocol": ""}, [], NONE),
    ({"host": " 192.0.2.10 "}, [["TNT-CAP", "-i", "192.0.2.10"]], {**NONE, "host": "192.0.2.10"}),
    ({"host": "192.0.2.10", "port": 443, "protocol": "tcp"}, [["TNT-CAP", "-i", "192.0.2.10", "-p", "443", "-t", "TCP"]],
     {"host": "192.0.2.10", "port": 443, "protocol": "tcp"}),
    ({"port": 53.0, "protocol": "UDP"}, [["TNT-CAP", "-p", "53", "-t", "UDP"]], {**NONE, "port": 53, "protocol": "udp"}),
    ({"host": "192.0.2.1", "protocol": "icmp"}, [["TNT-CAP", "-i", "192.0.2.1", "-t", "ICMP"]],
     {**NONE, "host": "192.0.2.1", "protocol": "icmp"}),
    ({"host": "2001:DB8::1", "protocol": "ICMP"}, [["TNT-CAP", "-i", "2001:db8::1", "-t", "ICMPv6"]],
     {**NONE, "host": "2001:db8::1", "protocol": "icmp"}),
    ({"protocol": "icmp"}, [["TNT-CAP4", "-t", "ICMP"], ["TNT-CAP6", "-t", "ICMPv6"]], {**NONE, "protocol": "icmp"}),
], ids=["none", "empty", "host", "host-port-tcp", "port-udp", "icmp-v4", "icmp-v6", "icmp-no-host"])
def test_start_argv_for_each_filter_combination(tmp_path, criteria, filters, shown):
    fake = FakePktmon(pcaps=[pcapng_file(ETH_FRAME)])
    env = make(tmp_path, fake)
    etl = str(env.folder / (stem(env.clock) + ".etl"))
    env.mgr.start(adapter="Ethernet", seconds=10, size_mb=256, full_packets=False, **criteria)
    join()
    commands = fake.commands()
    assert commands[0] == ["filter", "list"]
    assert [c[2:] for c in commands if c[:2] == ["filter", "add"]] == filters
    assert ["start", "--capture", "--comp", "3", "--pkt-size", "128", "-f", etl, "-s", "256"] in commands
    assert commands.count(["filter", "remove"]) == (1 if filters else 0)
    job = env.mgr.job()
    assert (job["state"], job["filters"], job["full_packets"], job["size_mb"]) == ("done", shown, False, 256)
    assert capture.capture_filters(shown["host"], shown["port"], shown["protocol"]) == filters


# --------------------------------------------------------------------------- the capture lifecycle
def test_stop_ends_the_capture_early_and_keeps_it(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "STOP_WAIT_S", 0.05)
    clock = Clock()
    fake = FakePktmon(pcaps=[pcapng_file(ETH_FRAME, ETH_FRAME, ETH_FRAME)])
    env = make(tmp_path, fake, clock=clock)
    name = stem(clock)
    etl, raw = str(env.folder / (name + ".etl")), str(env.folder / (name + ".raw.pcapng"))
    clock.hold()
    job = env.mgr.start(adapter="Ethernet", seconds=300)
    assert tuple(job) == CAPTURE_JOB_KEYS
    assert (job["id"], job["state"], job["seconds"], job["size_mb"], job["full_packets"], job["bytes"]) == \
        (1, "capturing", 300, 128, True, 300)
    assert job["adapter"] == {"name": "Ethernet", "index": 21, "mac": ADAPTER_MAC, "type_name": "Ethernet",
                              "wifi": False}
    assert job["filters"] == NONE and job["started_ts"] == T0
    assert clock.entered.wait(5)
    assert env.mgr.stop()["state"] == "capturing"          # the worker is still inside its tick wait
    clock.release()
    join()
    job = env.mgr.job()
    assert (job["state"], job["file"], job["note"], job["error"], job["elapsed_s"]) == \
        ("done", name + ".pcapng", None, None, 2.0)
    saved = env.folder / (name + ".pcapng")
    assert job["bytes"] == saved.stat().st_size
    assert env.mgr.files() == [{"name": saved.name, "size": saved.stat().st_size, "created_ts": saved.stat().st_mtime,
                                "packets": 3}]
    assert fake.commands() == [
        ["filter", "list"],
        ["start", "--capture", "--comp", "3", "--pkt-size", "0", "-f", etl, "-s", "128"],
        ["stop"],
        ["etl2pcap", etl, "--out", raw, "--component-id", "3"],
    ]
    assert names(env.folder) == [saved.name]                 # the ETL, the raw file and the marker are gone
    assert env.acl.calls == [(str(env.folder), winacl.CAPTURES_SDDL)]
    seen = [e["capture"]["state"] for e in env.bus.of(capture.EVENT)]
    assert seen[0] == "starting" and {"capturing", "converting"} <= set(seen) and seen[-1] == "done"
    assert env.mgr.stop()["state"] == "done" and len(fake.calls) == 4


def test_a_capture_runs_for_its_seconds_and_publishes_elapsed_and_size(tmp_path):
    fake = FakePktmon(pcaps=[pcapng_file(ETH_FRAME)])
    env = make(tmp_path, fake)
    assert env.mgr.start(adapter="Ethernet", seconds=5, size_mb=64)["state"] == "capturing"
    join()
    assert env.clock.waits == [2.0, 2.0, 1.0]
    ticks = [e["capture"] for e in env.bus.of(capture.EVENT) if e["capture"]["state"] == "capturing"]
    assert {2.0, 4.0, 5.0} <= {t["elapsed_s"] for t in ticks} and all(t["bytes"] == 300 for t in ticks)
    job = env.mgr.job()
    assert (job["state"], job["elapsed_s"], job["id"]) == ("done", 5.0, 1)
    assert fake.commands()[1][-2:] == ["-s", "64"]
    env.clock.now += 10
    assert env.mgr.start(adapter="Ethernet", seconds=5)["id"] == 2
    join()


def test_stop_while_starting_cancels_and_deletes_the_partial_files(tmp_path):
    gate = Gate()
    fake = FakePktmon(gates={"start": gate})
    env = make(tmp_path, fake)
    result = {}
    starter = threading.Thread(target=lambda: result.update(job=env.mgr.start(adapter="Ethernet")))
    starter.start()
    try:
        assert gate.entered.wait(5)                        # inside `pktmon start`
        assert env.mgr.job()["state"] == "starting"
        assert (env.folder / pktmon.MARKER_NAME).exists()  # written before the start
        assert env.mgr.stop()["state"] == "starting"
    finally:
        gate.release()
        starter.join(5)
    assert result["job"]["state"] == "cancelled"
    assert fake.keys() == ["filter list", "start", "stop"]  # the session that did start is stopped again
    assert list(env.folder.iterdir()) == [] and env.mgr.files() == [] and pktmon.LOCK.holder() is None
    assert env.bus.of(capture.EVENT)[-1]["capture"]["state"] == "cancelled"


def test_stop_before_packet_monitor_starts_cancels_without_a_command(tmp_path):
    gate = Gate()

    def components():
        gate.hold()
        return list(COMPONENTS)

    fake = FakePktmon()
    env = make(tmp_path, fake, components_fn=components)
    result = {}
    starter = threading.Thread(target=lambda: result.update(job=env.mgr.start(adapter="Ethernet")))
    starter.start()
    try:
        assert gate.entered.wait(5)
        assert env.mgr.stop()["state"] == "starting"
    finally:
        gate.release()
        starter.join(5)
    assert result["job"]["state"] == "cancelled"
    assert fake.calls == [] and list(env.folder.iterdir()) == [] and pktmon.LOCK.holder() is None


def test_close_cancels_a_capture_and_stops_packet_monitor(tmp_path):
    clock = Clock()
    fake = FakePktmon(pcaps=[pcapng_file(ETH_FRAME)])
    env = make(tmp_path, fake, clock=clock)
    env.mgr.close(1.0)
    assert fake.calls == []                                # idle: at once, no pktmon command
    clock.hold()
    env.mgr.start(adapter="Ethernet", seconds=60)
    assert clock.entered.wait(5)
    env.mgr.close(1.5)
    assert [kw["timeout"] for args, kw in fake.calls if args == ["stop"]] == [1.5]
    clock.release()
    join()
    job = env.mgr.job()
    assert (job["state"], job["file"]) == ("cancelled", None)
    assert "etl2pcap" not in fake.keys() and fake.keys().count("stop") == 1
    assert list(env.folder.iterdir()) == [] and env.mgr.files() == []
    before = len(fake.calls)
    env.mgr.close(1.0)
    assert len(fake.calls) == before


def test_a_wifi_capture_is_rewritten_to_ethernet_with_a_note(tmp_path):
    data_frame = dot11(SNAP + b"\x08\x00" + IPV4_UDP)
    beacon = dot11(bytes(12), subtype=8, frame_type=0)
    null_function = dot11(b"", subtype=4)
    fake = FakePktmon(pcaps=[pcapng_file(data_frame, beacon, data_frame, null_function)])
    env = make(tmp_path, fake)
    name = stem(env.clock)
    etl, raw = str(env.folder / (name + ".etl")), str(env.folder / (name + ".raw.pcapng"))
    env.mgr.start(adapter="Wi-Fi", seconds=5)
    join()
    job = env.mgr.job()
    assert (job["state"], job["adapter"]["wifi"], job["file"]) == ("done", True, name + ".pcapng")
    assert job["note"] == "2 Wi-Fi frames that were not data frames were left out"
    commands = fake.commands()
    assert ["start", "--capture", "--comp", "9", "--pkt-size", "0", "-f", etl, "-s", "128"] in commands
    assert ["etl2pcap", etl, "--out", raw, "--component-id", "9"] in commands
    packets = pcapng.read_packets((env.folder / job["file"]).read_bytes())
    assert [(p["data"][:6], p["data"][6:12], p["data"][12:14]) for p in packets] == [(ADAPTER, HOST, b"\x08\x00")] * 2
    assert env.mgr.files()[0]["packets"] == 2
    assert names(env.folder) == [job["file"]]
    assert capture.wifi_note(1) == "1 Wi-Fi frame that was not a data frame was left out"
    assert capture.wifi_note(0) is None


@pytest.mark.parametrize("adapter, fake, error", [
    ("Ethernet", FakePktmon(rc={"etl2pcap": 2}), "Packet Monitor could not convert (exit 2)"),
    ("Ethernet", FakePktmon(rc={"stop": 5}, running=False), "Packet Monitor could not stop (exit 5)"),
    ("Wi-Fi", FakePktmon(pcaps=[b"not a capture file"]), "The Wi-Fi capture could not be converted"),
])
def test_a_capture_that_cannot_be_saved_ends_in_error_and_deletes_the_partial_files(tmp_path, adapter, fake, error):
    if fake.rc.get("stop"):
        # pktmon stop fails while the session still runs
        env = make(tmp_path, fake, session_running_fn=lambda: None)
    else:
        env = make(tmp_path, fake)
    env.mgr.start(adapter=adapter, seconds=5)
    join()
    job = env.mgr.job()
    assert (job["state"], job["error"], job["file"]) == ("error", error, None)
    assert list(env.folder.iterdir()) == [] and env.mgr.files() == [] and pktmon.LOCK.holder() is None
    assert env.bus.of(capture.EVENT)[-1]["capture"]["state"] == "error"


@pytest.mark.parametrize("fake_kw, components, error", [
    ({}, [{"id": 9, "if_index": 17, "name": "Wi-Fi"}], "Packet Monitor does not list this adapter"),
    ({"filters": [["Other", "-p", "443"]]}, None, "Packet Monitor has filters set by another program"),
    ({"running": True}, None, "Packet Monitor is already capturing for another program"),
    ({"rc": {"start": 87}}, None, "Packet Monitor could not start (exit 87)"),
])
def test_start_failures_end_the_job_in_error_and_are_raised(tmp_path, fake_kw, components, error):
    fake = FakePktmon(**fake_kw)
    env = make(tmp_path, fake, components=components)
    with pytest.raises((PktmonBusy, PktmonUnavailable)) as err:
        env.mgr.start(adapter="Ethernet")
    assert str(err.value) == error
    assert (env.mgr.job()["state"], env.mgr.job()["error"]) == ("error", error)
    assert list(env.folder.iterdir()) == [] and pktmon.LOCK.holder() is None
    assert env.bus.of(capture.EVENT)[-1]["capture"]["state"] == "error"
    assert fake.filters == [list(f) for f in fake_kw.get("filters", [])]     # another program's filters stay


def test_start_needs_twice_the_size_plus_1_gib_free_and_runs_retention_first(tmp_path):
    fake = FakePktmon(pcaps=[pcapng_file(ETH_FRAME)])
    env = make(tmp_path, fake, free=128 * 2 * MIB + GIB - 1)
    env.folder.mkdir()
    old = env.folder / NAME
    old.write_bytes(b"x")
    os.utime(old, (T0 - 8 * 86400, T0 - 8 * 86400))
    with pytest.raises(PktmonUnavailable) as err:
        env.mgr.start(adapter="Ethernet", size_mb=128)
    assert str(err.value) == "Not enough free disk space for this capture (needs 1280 MB)"
    assert not old.exists()                                 # retention ran before the check
    assert fake.calls == [] and env.mgr.job()["state"] == "error" and pktmon.LOCK.holder() is None
    env = make(tmp_path, fake, free=128 * 2 * MIB + GIB)
    env.mgr.start(adapter="Ethernet", seconds=5, size_mb=128)
    join()
    assert env.mgr.job()["state"] == "done"


def test_a_folder_that_cannot_be_secured_fails_closed(tmp_path):
    fake = FakePktmon()
    acl = Acl(fail=PermissionError(5, "Access is denied"))
    env = make(tmp_path, fake, acl=acl)
    with pytest.raises(PktmonUnavailable) as err:
        env.mgr.start(adapter="Ethernet")
    assert str(err.value) == "The capture folder could not be secured"
    assert acl.calls == [(str(env.folder), winacl.CAPTURES_SDDL)]
    assert fake.calls == [] and not env.folder.exists() and pktmon.LOCK.holder() is None
    assert (env.mgr.job()["state"], env.mgr.job()["error"]) == ("error", "The capture folder could not be secured")


def test_a_switch_port_search_holds_packet_monitor(tmp_path):
    gate = Gate()
    clock = Clock()
    finder_fake = FakePktmon(inbound=[0], gates={"counters": gate})
    finder = SwitchPortFinder(Bus(), adapters_fn=lambda: [nic()], internet_nic_fn=lambda: None, runner=finder_fake,
                              clock=clock.time, monotonic=clock.monotonic, wait=clock.wait,
                              session_running_fn=lambda: finder_fake.running, components_fn=lambda: list(COMPONENTS),
                              capability_fn=lambda: OK, work_dir_fn=lambda: tmp_path / "captures", acl=Acl())
    finder.start()
    fake = FakePktmon()
    env = make(tmp_path, fake)
    try:
        assert gate.entered.wait(5)
        with pytest.raises(PktmonBusy) as err:
            env.mgr.start(adapter="Ethernet")
        assert str(err.value) == "TNT is finding the switch port: try again when it finishes"
        assert fake.calls == [] and env.mgr.job() is None and env.bus.events == []
    finally:
        finder.close(0.0)
        gate.release()
        join("tnt-switchport")
    assert finder.job()["state"] == "cancelled" and pktmon.LOCK.holder() is None


def test_adapters_and_status(tmp_path):
    adapters = [nic(), wifi(), nic("vEthernet (Example)", index=30, physical=False),
                nic("Ethernet 2", index=22, status="down"),
                nic("Loopback Pseudo-Interface 1", index=1, if_type=24, loopback=True)]
    env = make(tmp_path, FakePktmon(), adapters=adapters)
    rows = env.mgr.adapters()
    assert rows == [{"name": "Ethernet", "index": 21, "mac": ADAPTER_MAC, "type_name": "Ethernet", "wifi": False},
                    {"name": "Wi-Fi", "index": 17, "mac": WIFI_MAC, "type_name": "Wi-Fi", "wifi": True}]
    assert all(tuple(r) == capture.CAPTURE_ADAPTER_KEYS for r in rows)
    status = env.mgr.status()
    assert tuple(status) == CAPTURE_STATUS_KEYS
    assert status == {"available": True, "reason": None, "adapters": rows, "capture": None, "files": []}
    reason = "Packet Monitor (pktmon.exe) is missing from this PC"
    env = make(tmp_path, FakePktmon(), capability={"ok": False, "reason": reason})
    assert (env.mgr.status()["available"], env.mgr.status()["reason"]) == (False, reason)
    with pytest.raises(PktmonUnavailable, match=r"^Packet Monitor \(pktmon.exe\) is missing from this PC$"):
        env.mgr.start(adapter="Ethernet")
    assert env.mgr.job() is None and env.acl.calls == []


def test_info_logs_carry_no_host_or_file_name(tmp_path, caplog):
    caplog.set_level(logging.DEBUG, logger="tnt")
    fake = FakePktmon(pcaps=[pcapng_file(ETH_FRAME)])
    env = make(tmp_path, fake)
    env.mgr.start(adapter="Ethernet", seconds=5, host="192.0.2.10", port=443, protocol="tcp")
    join()
    saved = env.mgr.job()["file"]
    info = " ".join(r.getMessage() for r in caplog.records if r.levelno >= logging.INFO)
    debug = " ".join(r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG)
    assert "packet capture started on 'Ethernet'" in info and "packet capture saved" in info
    assert "192.0.2.10" not in info and saved not in info
    assert "192.0.2.10" in debug and saved in debug


# --------------------------------------------------------------------------- files
def test_files_are_counted_once_by_the_counting_thread(tmp_path, monkeypatch):
    fake = FakePktmon()
    env = make(tmp_path, fake)
    env.folder.mkdir()
    good = env.folder / NAME
    good.write_bytes(pcapng_file(ETH_FRAME, ETH_FRAME))
    bad = env.folder / "TNT-capture-20260102-120000.pcapng"
    bad.write_bytes(b"not a pcapng file")
    (env.folder / "other.pcapng").write_bytes(pcapng_file(ETH_FRAME))
    (env.folder / (NAME + ".part")).write_bytes(b"")
    os.utime(good, (T0 - 20, T0 - 20))
    os.utime(bad, (T0 - 10, T0 - 10))
    rows = env.mgr.files()
    assert all(tuple(r) == CAPTURE_FILE_KEYS for r in rows)
    assert [(r["name"], r["size"], r["created_ts"], r["packets"]) for r in rows] == \
        [(bad.name, 17, T0 - 10, None), (good.name, good.stat().st_size, T0 - 20, None)]   # newest first
    env.mgr.recover()
    join(capture.COUNT_THREAD_NAME)
    assert fake.calls == []                                 # no marker: Packet Monitor is left alone
    assert [(r["name"], r["packets"]) for r in env.mgr.files()] == [(bad.name, None), (good.name, 2)]
    event = env.bus.of(capture.EVENT)[-1]
    assert event["capture"] is None and [(f["name"], f["packets"]) for f in event["files"]] == \
        [(bad.name, None), (good.name, 2)]
    published = len(env.bus.events)
    real_count = pcapng.count_packets

    def must_not_count(path):
        raise AssertionError(f"{path} was counted again")

    monkeypatch.setattr(pcapng, "count_packets", must_not_count)
    env.mgr.recover()
    join(capture.COUNT_THREAD_NAME)
    assert len(env.bus.events) == published
    monkeypatch.setattr(pcapng, "count_packets", real_count)
    good.write_bytes(pcapng_file(ETH_FRAME))                # a changed file is counted again
    os.utime(good, (T0 - 5, T0 - 5))
    env.mgr.recover()
    join(capture.COUNT_THREAD_NAME)
    assert env.mgr.files()[0] == {"name": good.name, "size": good.stat().st_size, "created_ts": T0 - 5, "packets": 1}


def test_recover_cleans_up_a_crashed_capture_then_counts_the_files(tmp_path):
    fake = FakePktmon()
    env = make(tmp_path, fake, session_running_fn=lambda: None)
    env.folder.mkdir()
    leftovers = ["TNT-capture-20260101-130000.etl", "TNT-capture-20260101-130000.raw.pcapng"]
    for leftover in leftovers:
        (env.folder / leftover).write_bytes(b"x")
    (env.folder / NAME).write_bytes(pcapng_file(ETH_FRAME, ETH_FRAME))
    pktmon.write_marker(env.folder, {"purpose": "capture", "started_ts": T0,
                                     "files": leftovers + ["TNT-capture-20260101-130000.pcapng.part"]})
    env.mgr.recover()
    join(capture.COUNT_THREAD_NAME)
    assert fake.keys() == ["stop", "filter remove"]
    assert names(env.folder) == [NAME] and env.mgr.files()[0]["packets"] == 2
    assert pktmon.LOCK.holder() is None
    env = make(tmp_path / "elsewhere", FakePktmon())        # no folder at all
    env.mgr.recover()
    join(capture.COUNT_THREAD_NAME)
    assert env.fake.calls == [] and env.mgr.files() == []


def test_open_file_and_delete_file(tmp_path):
    env = make(tmp_path, FakePktmon())
    with pytest.raises(CaptureFileMissing):
        env.mgr.open_file(NAME)                             # no folder yet
    env.folder.mkdir()
    data = pcapng_file(ETH_FRAME)
    (env.folder / NAME).write_bytes(data)
    with pytest.raises(CaptureFileMissing) as err:
        env.mgr.open_file("TNT-capture-20260101-120001.pcapng")
    assert str(err.value) == "The capture file was not found"
    fh, size = env.mgr.open_file(NAME)
    with fh:
        assert (size, fh.read()) == (len(data), data)
    assert env.mgr.delete_file(NAME) == [] and not (env.folder / NAME).exists()
    with pytest.raises(CaptureFileMissing):
        env.mgr.delete_file(NAME)


@pytest.mark.parametrize("name", [
    "..\\" + NAME, "../" + NAME, "captures\\" + NAME, "C:\\" + NAME, "CON", "NUL.pcapng", "TNT-capture-2026-01-01.pcapng",
    NAME + "\n", NAME.replace("0", "\u0660"), NAME.upper(), NAME + ".part", NAME[:-len(".pcapng")] + ".etl",
    "TNT-capture-20260101-120000.raw.pcapng", "", None, 42,
])
def test_names_that_are_not_saved_captures_are_missing(tmp_path, name):
    env = make(tmp_path, FakePktmon())
    env.folder.mkdir()
    (env.folder / NAME).write_bytes(pcapng_file(ETH_FRAME))
    (tmp_path / NAME).write_bytes(b"outside the folder")
    with pytest.raises(CaptureFileMissing) as err:
        env.mgr.open_file(name)
    assert str(err.value) == "The capture file was not found"
    with pytest.raises(CaptureFileMissing):
        env.mgr.delete_file(name)
    assert (env.folder / NAME).exists() and (tmp_path / NAME).exists()


def test_open_file_refuses_a_reparse_point(tmp_path):
    env = make(tmp_path, FakePktmon())
    env.folder.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    secret = elsewhere / NAME
    secret.write_bytes(pcapng_file(ETH_FRAME))
    remove = link_to(secret, env.folder / NAME)
    try:
        with pytest.raises(CaptureFileMissing):
            env.mgr.open_file(NAME)
        with pytest.raises(CaptureFileMissing):
            env.mgr.delete_file(NAME)
        assert env.mgr.files() == []
    finally:
        remove()
    env.folder.rmdir()
    remove = link_to(elsewhere, env.folder)                 # the captures folder itself is a link
    try:
        with pytest.raises(CaptureFileMissing):
            env.mgr.open_file(NAME)
        assert env.mgr.files() == []
    finally:
        remove()
    assert secret.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="only Windows refuses to delete a file that is open")
def test_deleting_a_file_that_is_being_downloaded_is_busy(tmp_path):
    env = make(tmp_path, FakePktmon())
    env.folder.mkdir()
    (env.folder / NAME).write_bytes(pcapng_file(ETH_FRAME))
    fh, _size = env.mgr.open_file(NAME)
    try:
        with pytest.raises(CaptureFileBusy) as err:
            env.mgr.delete_file(NAME)
        assert str(err.value) == "The file is being downloaded"
    finally:
        fh.close()
    assert env.mgr.delete_file(NAME) == []


def test_retention_keeps_ten_files_two_gb_and_seven_days(tmp_path, monkeypatch):
    env = make(tmp_path, FakePktmon())
    assert env.mgr.enforce_retention(T0) == 0               # no folder
    env.folder.mkdir()
    now = time.time()
    saved = [f"TNT-capture-202601{day:02d}-120000.pcapng" for day in range(1, 15)]   # oldest first
    for i, name in enumerate(saved):
        path = env.folder / name
        path.write_bytes(bytes(100))
        ts = now - (len(saved) - i) * 60
        os.utime(path, (ts, ts))
    (env.folder / "notes.txt").write_bytes(b"not a capture")
    newest = saved[::-1]
    assert env.mgr.enforce_retention(now) == 4
    assert [r["name"] for r in env.mgr.files()] == newest[:10]
    monkeypatch.setattr(capture, "MAX_TOTAL_BYTES", 350)    # 2 GB in miniature: three 100-byte files fit
    assert env.mgr.enforce_retention(now) == 7
    assert [r["name"] for r in env.mgr.files()] == newest[:3]
    stale = env.folder / newest[2]
    os.utime(stale, (now - 7 * 86400 - 60, now - 7 * 86400 - 60))
    assert env.mgr.enforce_retention(now) == 1               # too old, although it fits
    locked = env.folder / newest[1]
    os.utime(locked, (now - 8 * 86400, now - 8 * 86400))
    handle = open(locked, "rb")                              # a download holds it
    try:
        while_open = env.mgr.enforce_retention(now)
        still_there = locked.exists()
    finally:
        handle.close()
    if sys.platform == "win32":
        assert (while_open, still_there) == (0, True)       # skipped, and tried again next time
        assert env.mgr.enforce_retention(now) == 1
    assert [r["name"] for r in env.mgr.files()] == [newest[0]]
    # no time given: the manager's clock decides
    os.utime(env.folder / newest[0], (T0 - 8 * 86400, T0 - 8 * 86400))
    assert env.mgr.enforce_retention(None) == 1 and env.mgr.files() == []
    assert (env.folder / "notes.txt").exists()
