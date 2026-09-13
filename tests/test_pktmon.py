"""tnt.pktmon: the Packet Monitor command line, the capability probe, the ETW session query, output parsing by shape,
the shared lock, one capture session and the crash marker.

Nothing here runs Packet Monitor: tests/conftest.py makes ``tnt.pktmon._subprocess_run`` fail for the whole session, and
every test hands in :class:`FakePktmon`, a runner that plays pktmon.exe.  The ETW query runs against a fake advapi32.
Adapters are the stand-ins ``Ethernet`` (component 3, ifIndex 21) and ``Wi-Fi`` (component 9, ifIndex 17) with MACs
02:00:5e:10:00:0x; frames use the stand-in switch LAB-SW-01 on Port 7 and addresses from 192.0.2.0/24.

The fakes and builders at the top are shared with tests/test_switchport.py and tests/test_capture.py.
"""
from __future__ import annotations

import copy
import ctypes
import json
import logging
import os
import struct
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from tnt import arp, pktmon
from tnt.netinfo import IF_TYPE_NAMES, Adapter
from tnt.pktmon import PktmonBusy, PktmonSession, PktmonUnavailable

T0 = 1_788_000_000.0                          # the fake wall clock's start (late August 2026)
ADAPTER_MAC = "02:00:5E:10:00:01"             # the wired adapter, as netinfo writes it
WIFI_MAC = "02:00:5E:10:00:02"
ADAPTER = bytes.fromhex("02005e100001")
PEER = bytes.fromhex("02005e100002")
SWITCH_PORT = bytes.fromhex("02005e100003")   # the switch port's own MAC (LLDP source)
SWITCH = bytes.fromhex("02005e100004")        # the switch's chassis MAC
LLDP_DST = bytes.fromhex("0180c200000e")
IPV4_UDP = (bytes([0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 10, 192, 0, 2, 1])
            + struct.pack(">HHHH", 50000, 53, 8, 0))
ETH_FRAME = PEER + ADAPTER + b"\x08\x00" + IPV4_UDP

COMPONENTS_TEXT = """\
Network adapter: Ethernet
    Id: 3
    Driver: example-eth.sys
    MAC Address: 02-00-5E-10-00-01
    ifIndex: 21

    Filter drivers:
        Id  Name
        --  ----
         4  Example Filter

Network adapter: Wi-Fi
    Id: 9
    Driver: example-wifi.sys
    MAC Address: 02-00-5E-10-00-02
    ifIndex: 17
"""
COMPONENTS = [{"id": 3, "if_index": 21, "name": "Ethernet"}, {"id": 9, "if_index": 17, "name": "Wi-Fi"}]
GOOD_EXE = b"MZ\x90\x00" + b"".join(s.encode("utf-16-le") + b"\x00\x00" for s in pktmon.REQUIRED_EXE_STRINGS)
FAILURE_OUTPUT = "Error: example failure output (TNT test)"


# --------------------------------------------------------------------------- shared fakes and builders
def nic(name: str = "Ethernet", *, index: int = 21, if_type: int = 6, mac: str = ADAPTER_MAC, status: str = "up",
        physical: bool = True, loopback: bool = False) -> Adapter:
    return Adapter(index=index, name=name, description=f"Example {name} adapter", mac=mac, if_type=if_type,
                   type_name=IF_TYPE_NAMES.get(if_type, "Other"), status=status, speed_bps=None, mtu=1500,
                   dhcp_enabled=True, dhcp_server=None, dns_suffix="", is_physical=physical, is_loopback=loopback)


def wifi(**kw: Any) -> Adapter:
    return nic("Wi-Fi", index=17, if_type=71, mac=WIFI_MAC, **kw)


def counters_json(inbound: int, comp_id: int = 3) -> str:
    """``pktmon counters --json`` output: a localised heading, then the JSON (the Wi-Fi component counts too)."""
    def component(name: str, cid: int, packets: int) -> Dict[str, Any]:
        return {"Name": name, "Id": cid, "Counters": [
            {"Name": "Upper", "Type": "Flows", "Inbound": {"Packets": packets, "Bytes": packets * 64},
             "Outbound": {"Packets": 1, "Bytes": 64}}]}

    return "Example counters heading\r\n" + json.dumps(
        [{"Group": "Network adapters", "Components": [component("Ethernet", comp_id, inbound),
                                                      component("Wi-Fi", 9, 11)]}])


class Gate:
    """Holds a fake command until released (bounded, so a broken test cannot hang the run)."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.released = threading.Event()

    def hold(self) -> None:
        self.entered.set()
        self.released.wait(5)

    def release(self) -> None:
        self.released.set()


class FakePktmon:
    """A ``subprocess.run`` stand-in playing Packet Monitor.

    ``calls`` holds ``(args, kwargs)`` per command (the arguments after the program path; ``programs`` the paths).  It
    keeps the session (``running``) and filter state; answers ``counters --json`` from ``inbound`` (None prints text
    that is not JSON; the last answer repeats); writes a 300-byte ETL at ``start -f``; and writes the next of ``pcaps``
    at ``etl2pcap --out`` (None writes nothing; the last repeats).  ``rc`` maps a command key (:meth:`key`) to its exit
    code, and ``gates`` maps one to a :class:`Gate` that holds it."""

    def __init__(self, *, inbound=(0,), pcaps=(None,), rc: Optional[Dict[str, int]] = None,
                 gates: Optional[Dict[str, Gate]] = None, components: str = COMPONENTS_TEXT, running: bool = False,
                 filters=()) -> None:
        self.calls: List[tuple] = []
        self.programs: List[str] = []
        self.inbound = list(inbound)
        self.pcaps = list(pcaps)
        self.rc = dict(rc or {})
        self.gates = dict(gates or {})
        self.components = components
        self.running = running
        self.filters = [list(f) for f in filters]
        self.lock = threading.Lock()

    @staticmethod
    def key(args: List[str]) -> str:
        if args[:1] == ["filter"]:
            return " ".join(args[:2])
        return args[0] if args else ""

    def commands(self) -> List[List[str]]:
        with self.lock:
            return [list(args) for args, _kw in self.calls]

    def keys(self) -> List[str]:
        return [self.key(args) for args in self.commands()]

    def _next(self, items: list) -> Any:
        with self.lock:
            return items.pop(0) if len(items) > 1 else items[0]

    def __call__(self, argv, **kwargs):
        args = [str(a) for a in argv[1:]]
        key = self.key(args)
        with self.lock:
            self.calls.append((args, kwargs))
            self.programs.append(argv[0])
        gate = self.gates.get(key)
        if gate is not None:
            gate.hold()
        rc = self.rc.get(key, 0)
        out = FAILURE_OUTPUT if rc else ""
        if rc:
            pass
        elif key == "filter list":
            out = "Packet Filters:\r\n"
            if self.filters:
                out += "     #  Name     Arguments\r\n     -  ----     ---------\r\n"
                out += "".join(f"     {i + 1}  {' '.join(f)}\r\n" for i, f in enumerate(self.filters))
            else:
                out += "    None\r\n"
        elif key == "filter add":
            self.filters.append(args[2:])
        elif key == "filter remove":
            self.filters = []
        elif key == "list":
            out = self.components
        elif key == "start":
            self.running = True
            with open(args[args.index("-f") + 1], "wb") as fh:
                fh.write(b"ETL" * 100)
        elif key == "stop":
            self.running = False
        elif key == "counters":
            value = self._next(self.inbound)
            out = "Counters are not available" if value is None else counters_json(value)
        elif key == "etl2pcap":
            data = self._next(self.pcaps)
            if data is not None:
                with open(args[args.index("--out") + 1], "wb") as fh:
                    fh.write(data)
        return SimpleNamespace(returncode=rc, stdout=out.encode("ascii"), stderr=b"")


class Clock:
    """Wall and monotonic time that only :meth:`wait` moves.  After :meth:`hold`, a wait blocks (``entered`` is set)
    until :meth:`release`, then moves time on as usual."""

    def __init__(self, now: float = T0) -> None:
        self.now = now
        self.mono = 5000.0
        self.waits: List[float] = []
        self.entered = threading.Event()
        self._held: Optional[threading.Event] = None

    def time(self) -> float:
        return self.now

    def monotonic(self) -> float:
        return self.mono

    def hold(self) -> None:
        self.entered.clear()
        self._held = threading.Event()

    def release(self) -> None:
        held, self._held = self._held, None
        if held is not None:
            held.set()

    def wait(self, seconds: float) -> bool:
        held = self._held
        if held is not None:
            self.entered.set()
            held.wait(5)
        self.waits.append(seconds)
        self.now += seconds
        self.mono += seconds
        return False


class Bus:
    def __init__(self) -> None:
        self.events: List[tuple] = []
        self.lock = threading.Lock()

    def publish(self, event_type, data=None, ts=None):
        with self.lock:
            self.events.append((event_type, copy.deepcopy(data)))

    def of(self, event_type: str) -> List[Any]:
        with self.lock:
            return [d for t, d in self.events if t == event_type]


class Acl:
    """Stands in for tnt.winacl.secure_dir: records ``(path, sddl)`` and creates the folder (no DACL change)."""

    def __init__(self, fail: Optional[BaseException] = None) -> None:
        self.calls: List[tuple] = []
        self.fail = fail

    def __call__(self, path, sddl):
        self.calls.append((str(path), sddl))
        if self.fail is not None:
            raise self.fail
        os.makedirs(path, exist_ok=True)


def pcapng_file(*frames: bytes, linktype: int = 1) -> bytes:
    """A little-endian pcapng file: SHB, one IDB and one EPB per frame."""
    def block(block_type: int, body: bytes) -> bytes:
        length = len(body) + 12
        return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)

    data = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + block(1, struct.pack("<HHI", linktype, 0, 0))
    for index, frame in enumerate(frames):
        fixed = struct.pack("<IIIII", 0, 0, index, len(frame), len(frame))
        data += block(6, fixed + frame + bytes(-len(frame) % 4))
    return data


def tlv(tlv_type: int, value: bytes = b"") -> bytes:
    return struct.pack(">H", (tlv_type << 9) | len(value)) + value


def lldp_frame(system_name: bytes = b"LAB-SW-01", port: bytes = b"Port 7", *, src: bytes = SWITCH_PORT,
               chassis: bytes = SWITCH) -> bytes:
    payload = (tlv(1, b"\x04" + chassis) + tlv(2, b"\x05" + port) + tlv(3, struct.pack(">H", 120))
               + tlv(5, system_name) + tlv(6, b"Example Switch 8P") + tlv(0))
    return LLDP_DST + src + struct.pack(">H", 0x88CC) + payload


def own_lldp_frame() -> bytes:
    """Windows' own LLDPDU, sent from the adapter (Packet Monitor captures it with the switch's frames)."""
    return lldp_frame(b"PC-01", b"Ethernet", src=ADAPTER, chassis=ADAPTER)


def session(fake: FakePktmon, tmp_path, **kw: Any) -> PktmonSession:
    kw.setdefault("comp_id", 3)
    kw.setdefault("filters", [["TNT-LLDP", "-d", "35020"], ["TNT-CDP", "-m", "01-00-0C-CC-CC-CC"]])
    kw.setdefault("etl_path", str(tmp_path / "TNT-test.etl"))
    kw.setdefault("size_mb", 64)
    kw.setdefault("pkt_size", 0)
    kw.setdefault("session_running_fn", lambda: fake.running)
    return PktmonSession(runner=fake, **kw)


@pytest.fixture(autouse=True)
def _pktmon_lock_left_free():
    yield
    holder = pktmon.LOCK.holder()
    pktmon.LOCK.release()
    assert holder is None, f"a test left tnt.pktmon.LOCK held by {holder}"


# --------------------------------------------------------------------------- the conftest guard and the convention
def test_conftest_guard_is_active():
    seam = pktmon._subprocess_run
    assert seam is not subprocess.run and getattr(seam, "__module__", None) == "conftest", \
        "tests/conftest.py must replace tnt.pktmon._subprocess_run"
    with pytest.raises(OSError, match="pktmon is disabled in tests"):
        seam(["pktmon", "list"])
    # every default runner looks the seam up when it runs, so it meets the guard too
    assert pktmon.run_pktmon(["filter", "list"]) == (1, "could not run pktmon: pktmon is disabled in tests")
    assert pktmon.filters_present() is None and pktmon.list_components() == []


def test_pktmon_exe_comes_from_system32(monkeypatch, tmp_path):
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    assert pktmon.pktmon_exe() == os.path.join(str(tmp_path), "System32", "PktMon.exe")   # even when it is missing
    monkeypatch.delenv("SystemRoot")
    assert pktmon.pktmon_exe() == os.path.join("C:\\Windows", "System32", "PktMon.exe")


def test_run_pktmon_runs_hidden_with_no_stdin_and_a_timeout(monkeypatch, tmp_path):
    calls = []
    raw = b"Packet Filters:\r\n    None \x82\r\n"

    def recorder(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")

    monkeypatch.setattr(pktmon, "_subprocess_run", recorder)
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    rc, out = pktmon.run_pktmon(["filter", "list"])
    (argv, kwargs), = calls
    assert argv == [os.path.join(str(tmp_path), "System32", "PktMon.exe"), "filter", "list"]
    assert kwargs["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
    assert kwargs["stdin"] is subprocess.DEVNULL and kwargs["capture_output"] is True and not kwargs.get("shell")
    assert kwargs["timeout"] == pktmon.PKTMON_TIMEOUT_S == 30.0 and kwargs["check"] is False
    assert (rc, out) == (0, arp._decode_console(raw).strip())                  # the OEM code page
    pktmon.run_pktmon(["stop"], timeout_s=10)
    assert calls[-1][1]["timeout"] == 10


@pytest.mark.parametrize("exc, expected", [
    (FileNotFoundError(), (9009, "PktMon.exe was not found")),
    (subprocess.TimeoutExpired(["pktmon"], 30), (1460, "pktmon timed out after 30 s")),
    (PermissionError(5, "Access is denied"), (1, "could not run pktmon: [Errno 5] Access is denied")),
    (ValueError("a broken runner"), (1, "pktmon failed: a broken runner")),
])
def test_run_pktmon_never_raises(exc, expected):
    def runner(argv, **kwargs):
        raise exc

    assert pktmon.run_pktmon(["stop"], runner) == expected


def test_failure_text():
    assert pktmon.failure_text("convert", 87) == "Packet Monitor could not convert (exit 87)"


# --------------------------------------------------------------------------- every command's argv
def test_the_argv_of_every_command(tmp_path):
    fake = FakePktmon(inbound=[4], pcaps=[pcapng_file(ETH_FRAME)])
    s = session(fake, tmp_path)
    etl = str(tmp_path / "TNT-test.etl")
    s.start()
    assert s.active
    assert s.inbound() == 4
    s.stop()
    assert not s.active
    first, second = tmp_path / "a.pcapng", tmp_path / "b.pcapng"
    assert s.convert(first, component_id=3) is True and first.read_bytes() == pcapng_file(ETH_FRAME)
    assert s.convert(second) is True
    assert fake.commands() == [
        ["filter", "list"],
        ["filter", "add", "TNT-LLDP", "-d", "35020"],
        ["filter", "add", "TNT-CDP", "-m", "01-00-0C-CC-CC-CC"],
        ["start", "--capture", "--comp", "3", "--pkt-size", "0", "-f", etl, "-s", "64"],
        ["counters", "--json"],
        ["stop"],
        ["filter", "remove"],
        ["etl2pcap", etl, "--out", str(first), "--component-id", "3"],
        ["etl2pcap", etl, "--out", str(second)],
    ]
    assert [kw["timeout"] for _a, kw in fake.calls] == [30.0] * 7 + [pktmon.CONVERT_TIMEOUT_S] * 2
    assert set(fake.programs) == {pktmon.pktmon_exe()}
    assert pktmon.list_components(fake) == COMPONENTS and fake.commands()[-1] == ["list", "--all"]
    assert pktmon.filters_present(fake) is False and fake.commands()[-1] == ["filter", "list"]
    assert all("unload" not in args for args in fake.commands())


@pytest.mark.parametrize("etl, size_mb, message", [
    ("TNT-switchport.etl", 64, "etl_path must be an absolute path"),
    ("captures\\TNT-switchport.etl", 64, "etl_path must be an absolute path"),
    ("\\captures\\TNT-switchport.etl", 64, "etl_path must be an absolute path"),      # no drive
    ("C:TNT-switchport.etl", 64, "etl_path must be an absolute path"),                # drive-relative
    (None, 32, "size_mb must be a whole number of at least 64"),                       # -s 32 works, but is refused
    (None, 16, "size_mb must be a whole number of at least 64"),
    (None, 64.0, "size_mb must be a whole number of at least 64"),
    (None, True, "size_mb must be a whole number of at least 64"),
])
def test_start_refuses_a_relative_etl_path_or_a_small_file(tmp_path, etl, size_mb, message):
    fake = FakePktmon()
    s = session(fake, tmp_path, etl_path=etl if etl is not None else str(tmp_path / "TNT.etl"), size_mb=size_mb)
    with pytest.raises(ValueError) as err:
        s.start()
    assert str(err.value) == message
    assert fake.calls == []


# --------------------------------------------------------------------------- parsing by shape
def test_list_components_reads_sections_by_shape():
    assert pktmon.parse_components(COMPONENTS_TEXT) == COMPONENTS
    assert all(tuple(c) == pktmon.COMPONENT_KEYS for c in pktmon.parse_components(COMPONENTS_TEXT))
    localised = ("Adaptateur réseau : Ethernet\r\n"
                 "    Identificateur : 3\r\n"
                 "    Pilote : example-eth.sys\r\n"
                 "    Adresse MAC : 02-00-5E-10-00-01\r\n"
                 "    Index d'interface : 21\r\n"
                 "Netzwerkadapter: Wi-Fi\r\n"
                 "\tKennung: 9\r\n"
                 "\tSchnittstellenindex: 17\r\n")
    assert pktmon.parse_components(localised) == COMPONENTS
    odd = ("Network Adapters:\n"                        # a heading with no name opens nothing
           "    Id: 99\n"
           "    ifIndex: 98\n"
           "Loopback: Loopback Pseudo-Interface 1\n"     # only one number: skipped
           "    Id: 1\n"
           "    Driver: none\n"
           "Id  Name\n"                                  # a table heading ends a section
           "Network adapter: Ethernet\n"
           "    Id: 3\n"
           "    MAC Address: 02-00-5E-10-00-01\n"
           "    ifIndex: 21\n"
           "    Protocol Id: 5\n")                       # a third number is not read
    assert pktmon.parse_components(odd) == [COMPONENTS[0]]
    assert pktmon.parse_components("") == [] and pktmon.parse_components(None) == []
    assert pktmon.list_components(FakePktmon(rc={"list": 5})) == []


def test_component_for_matches_by_ifindex_only():
    assert pktmon.component_for(nic(), COMPONENTS) == 3
    assert pktmon.component_for(wifi(), COMPONENTS) == 9
    assert pktmon.component_for({"name": "Wi-Fi", "index": 21, "mac": WIFI_MAC}, COMPONENTS) == 3   # not by name/MAC
    assert pktmon.component_for({"index": 22}, COMPONENTS) is None
    assert pktmon.component_for({"index": None}, COMPONENTS) is None
    assert pktmon.component_for({"index": True}, [{"id": 7, "if_index": 1}]) is None
    assert pktmon.component_for(nic(), []) is None
    assert pktmon.component_for(nic(), [{"id": "3", "if_index": 21}, "junk"]) is None


def test_counters_inbound_sums_the_component_after_any_text():
    assert pktmon.counters_inbound(counters_json(25), 3) == 25
    assert pktmon.counters_inbound(counters_json(25), 9) == 11
    assert pktmon.counters_inbound(counters_json(25).encode("ascii"), 3) == 25                     # bytes too
    assert pktmon.counters_inbound("[1] [note] Example heading\r\n" + counters_json(25), 3) == 25  # brackets before it
    two = json.dumps([
        {"Group": "Adapters", "Components": [{"Name": "Ethernet", "Id": 3, "Counters": [
            {"Name": "Upper", "Inbound": {"Packets": 2}}, {"Name": "Lower", "Inbound": {"Packets": 5}},
            {"Name": "Drops"}]}]},
        {"Group": "Protocols", "Components": [{"Name": "Ethernet", "Id": "3", "Counters": [
            {"Name": "Upper", "Inbound": {"Packets": 1}, "Outbound": {"Packets": 9}}]}]},
        {"Group": "Summary"}])
    assert pktmon.counters_inbound("[warning] text before it\n" + two, 3) == 8
    assert pktmon.counters_inbound(counters_json(1), 42) == 0                                      # not listed
    for junk in ("", "Counters are not available", "{\"Id\": 3}", "[1, 2, 3]", "[{\"Group\": \"x\"}]", "[{"):
        assert pktmon.counters_inbound(junk, 3) is None, junk


def test_filters_present_counts_lines():
    def answer(rc, out):
        return lambda argv, **kw: SimpleNamespace(returncode=rc, stdout=out.encode("ascii"), stderr=b"")

    assert pktmon.filters_present(answer(0, "Packet Filters:\r\n    None\r\n\r\n")) is False
    assert pktmon.filters_present(answer(0, "Packet Filters:\n  #  Name\n  1  Other  -p 443\n")) is True
    assert pktmon.filters_present(answer(0, "")) is False
    assert pktmon.filters_present(answer(5, "Failed to communicate with the PktMon driver")) is None
    assert pktmon.filters_present(FakePktmon(filters=[["Other", "-p", "443"]])) is True


# --------------------------------------------------------------------------- capability
def exe_file(tmp_path, data: bytes = GOOD_EXE, name: str = "PktMon.exe"):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_capability_needs_build_19041(tmp_path):
    exe = exe_file(tmp_path)
    old = {"ok": False, "reason": "Needs Windows 10 version 2004 (build 19041) or later"}
    assert pktmon.capability(build_fn=lambda: 19040, exe_path=exe, read_fn=lambda p: GOOD_EXE) == old
    assert pktmon.capability(build_fn=lambda: None, exe_path=exe, read_fn=lambda p: GOOD_EXE) == old

    def broken():
        raise OSError("no registry")

    assert pktmon.capability(build_fn=broken, exe_path=exe, read_fn=lambda p: GOOD_EXE) == old
    assert pktmon.capability(build_fn=lambda: "19041", exe_path=exe, read_fn=lambda p: GOOD_EXE) == \
        {"ok": True, "reason": None}
    assert tuple(pktmon.capability(build_fn=lambda: 26200, exe_path=exe, read_fn=lambda p: GOOD_EXE)) == \
        pktmon.CAPABILITY_KEYS


def test_capability_needs_the_program(tmp_path):
    missing = {"ok": False, "reason": "Packet Monitor (pktmon.exe) is missing from this PC"}
    assert pktmon.capability(build_fn=lambda: 26200, exe_path=tmp_path / "PktMon.exe") == missing
    assert pktmon.capability(build_fn=lambda: 26200, exe_path=tmp_path) == missing                # a folder

    def unreadable(path):
        raise PermissionError(5, "Access is denied")

    assert pktmon.capability(build_fn=lambda: 26200, exe_path=exe_file(tmp_path), read_fn=unreadable) == missing


def test_capability_probes_the_utf16_option_strings(tmp_path):
    exe = exe_file(tmp_path)
    too_old = {"ok": False, "reason": "Packet Monitor on this PC is too old for this: update Windows"}
    assert pktmon.capability(build_fn=lambda: 26200, exe_path=exe, read_fn=lambda p: GOOD_EXE)["ok"] is True
    for left_out in pktmon.REQUIRED_EXE_STRINGS:
        data = b"MZ" + b"".join(s.encode("utf-16-le") for s in pktmon.REQUIRED_EXE_STRINGS if s != left_out)
        if left_out == "--comp":
            data = data.replace("--comp".encode("utf-16-le"), b"")
        assert pktmon.capability(build_fn=lambda: 26200, exe_path=exe, read_fn=lambda p, d=data: d) == too_old
    ascii_only = b"MZ" + b" ".join(s.encode("ascii") for s in pktmon.REQUIRED_EXE_STRINGS)
    assert pktmon.capability(build_fn=lambda: 26200, exe_path=exe, read_fn=lambda p: ascii_only) == too_old
    beyond = bytes(pktmon.EXE_READ_LIMIT) + GOOD_EXE                   # the strings sit past the first 4 MiB
    assert pktmon.capability(build_fn=lambda: 26200, exe_path=exe, read_fn=lambda p: beyond) == too_old


def test_capability_reads_at_most_4_mib_once_per_process(tmp_path, monkeypatch):
    far = exe_file(tmp_path, bytes(pktmon.EXE_READ_LIMIT) + GOOD_EXE, "far.exe")
    assert pktmon.capability(build_fn=lambda: 26200, exe_path=far)["reason"] == pktmon.TOO_OLD_REASON
    exe = exe_file(tmp_path)
    assert pktmon.capability(build_fn=lambda: 26200, exe_path=exe) == {"ok": True, "reason": None}
    reads = []
    real_open = open

    def counting_open(file, mode="r", *args, **kwargs):
        reads.append(str(file))
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", counting_open)
    exe.write_bytes(b"MZ")                                              # cached: not read again
    assert pktmon.capability(build_fn=lambda: 26200, exe_path=exe) == {"ok": True, "reason": None}
    assert str(exe) not in reads


# --------------------------------------------------------------------------- the ETW session query
@pytest.mark.skipif(ctypes.sizeof(ctypes.c_void_p) != 8, reason="EVENT_TRACE_PROPERTIES is laid out for x64")
def test_event_trace_properties_layout():
    assert ctypes.sizeof(pktmon.WNODE_HEADER) == 48
    assert ctypes.sizeof(pktmon.EVENT_TRACE_PROPERTIES) == 120
    assert pktmon.EVENT_TRACE_PROPERTIES.LoggerThreadId.offset == 104
    assert pktmon.EVENT_TRACE_PROPERTIES.LogFileNameOffset.offset == 112
    assert pktmon.EVENT_TRACE_PROPERTIES.LoggerNameOffset.offset == 116


@pytest.mark.skipif(sys.platform != "win32" or ctypes.sizeof(ctypes.c_void_p) != 8, reason="the query is x64 Windows")
def test_session_running_queries_the_pktmon_logger(monkeypatch):
    seen = []

    class FakeAdvapi:
        def __init__(self, answer):
            self.answer = answer

        def ControlTraceW(self, handle, name, props, code):
            seen.append((handle, name, code, ctypes.string_at(props, 120 + 2048)))
            if isinstance(self.answer, BaseException):
                raise self.answer
            return self.answer

    for answer, expected in ((0, True), (4201, False), (5, None), (87, None), (OSError("no advapi32"), None)):
        monkeypatch.setattr(pktmon, "_advapi", lambda a=answer: FakeAdvapi(a))
        assert pktmon.session_running() is expected, answer
    handle, name, code, raw = seen[0]
    assert (handle, name, code) == (0, "PktMon", 0)                    # EVENT_TRACE_CONTROL_QUERY
    assert struct.unpack_from("<I", raw, 0)[0] == 120 + 2048           # Wnode.BufferSize
    assert struct.unpack_from("<II", raw, 112) == (1144, 120)          # LogFileNameOffset, LoggerNameOffset
    assert raw[120:] == bytes(2048)


# --------------------------------------------------------------------------- busy
def test_a_foreign_session_or_foreign_filters_make_packet_monitor_busy(tmp_path):
    fake = FakePktmon(running=True)
    s = session(fake, tmp_path)
    with pytest.raises(PktmonBusy) as err:
        s.start()
    assert str(err.value) == "Packet Monitor is already capturing for another program"
    assert fake.calls == []                                            # the ETW query decided; no filter touched
    fake = FakePktmon(filters=[["Other", "-p", "443"]])
    s = session(fake, tmp_path)
    with pytest.raises(PktmonBusy) as err:
        s.start()
    assert str(err.value) == "Packet Monitor has filters set by another program"
    s.cleanup()
    assert fake.keys() == ["filter list"] and fake.filters == [["Other", "-p", "443"]]   # never cleared
    assert issubclass(PktmonBusy, RuntimeError) and issubclass(PktmonUnavailable, RuntimeError)


def test_the_lock_names_its_holder():
    lock = pktmon.PktmonLock()
    assert lock.holder() is None
    lock.acquire("switchport")
    with pytest.raises(PktmonBusy) as err:
        lock.acquire("capture")
    assert str(err.value) == "TNT is finding the switch port: try again when it finishes"
    assert lock.holder() == "switchport"
    lock.release()
    lock.acquire("capture")
    with pytest.raises(PktmonBusy) as err:
        lock.acquire("switchport")
    assert str(err.value) == "A packet capture is running: stop it first"
    lock.release()
    assert lock.holder() is None
    with pytest.raises(ValueError):
        lock.acquire("somebody")
    assert isinstance(pktmon.LOCK, pktmon.PktmonLock)


# --------------------------------------------------------------------------- failures and clean-up
def test_a_failed_start_cleans_up_and_shows_only_the_exit_code(tmp_path, caplog):
    caplog.set_level(logging.DEBUG, logger="tnt.pktmon")
    fake = FakePktmon(rc={"start": 87})
    s = session(fake, tmp_path, session_running_fn=lambda: None)       # unknown: the clean-up stops to be sure
    with pytest.raises(PktmonUnavailable) as err:
        s.start()
    assert str(err.value) == "Packet Monitor could not start (exit 87)" == s.last_error
    assert fake.keys() == ["filter list", "filter add", "filter add", "start", "stop", "filter remove"]
    assert FAILURE_OUTPUT not in str(err.value)
    assert any(FAILURE_OUTPUT in r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG)
    assert not any(FAILURE_OUTPUT in r.getMessage() for r in caplog.records if r.levelno > logging.DEBUG)

    # the one race "TNT does not start while another program captures" leaves: the ETW check found no session, another
    # program's capture started before TNT's `pktmon start`, which then fails, and the clean-up stops the session that runs
    # (it cannot tell whose: §3.3 stops when running or unknown).  The docs describe that race; they do not promise more.
    answers = iter([False, True])                                        # the check before the start, then the clean-up's
    fake = FakePktmon(rc={"start": 87})
    with pytest.raises(PktmonUnavailable):
        session(fake, tmp_path, session_running_fn=lambda: next(answers)).start()
    assert fake.keys() == ["filter list", "filter add", "filter add", "start", "stop", "filter remove"]
    texts = {"tnt/pktmon.py": Path(pktmon.__file__).read_text(encoding="utf-8")}
    for rel in ("docs/COMPATIBILITY.md", "docs/ARCHITECTURE.md"):
        doc = Path(__file__).resolve().parents[1] / rel
        if doc.is_file():                                                # the Markdown docs are not published
            texts[rel] = doc.read_text(encoding="utf-8")
    for rel, text in texts.items():
        flat = " ".join(text.split())
        assert "never stops or clears" not in flat and "Never someone else's capture" not in flat, rel
        assert "in the same second" in flat, rel

    fake = FakePktmon(rc={"start": 1})
    with pytest.raises(PktmonUnavailable, match=r"^Packet Monitor could not start \(exit 1\)$"):
        session(fake, tmp_path).start()                                # the session never ran: no stop
    assert fake.keys() == ["filter list", "filter add", "filter add", "start", "filter remove"]

    fake = FakePktmon(rc={"filter add": 2})
    with pytest.raises(PktmonUnavailable, match=r"^Packet Monitor could not start \(exit 2\)$"):
        session(fake, tmp_path).start()
    assert fake.keys() == ["filter list", "filter add", "filter remove"]

    # an inconclusive filter check: a first filter that was not added removes nothing (the filters could be another
    # program's) ...
    fake = FakePktmon(rc={"filter add": 2})
    with pytest.raises(PktmonUnavailable, match=r"^Packet Monitor could not start \(exit 2\)$"):
        session(fake, tmp_path, filters_present_fn=lambda: None).start()
    assert fake.keys() == ["filter add"]
    # ... but one that timed out may have been added, so it is removed
    fake = FakePktmon(rc={"filter add": pktmon.TIMEOUT_RC})
    with pytest.raises(PktmonUnavailable, match=r"^Packet Monitor could not start \(exit 1460\)$"):
        session(fake, tmp_path, filters_present_fn=lambda: None).start()
    assert fake.keys() == ["filter add", "filter remove"]


def test_stop_failure_text_and_a_session_that_is_already_gone(tmp_path):
    fake = FakePktmon(rc={"stop": 5})
    s = session(fake, tmp_path)
    s.start()
    with pytest.raises(PktmonUnavailable) as err:
        s.stop()
    assert str(err.value) == "Packet Monitor could not stop (exit 5)" and s.active
    assert fake.keys()[-2:] == ["stop", "filter remove"]
    # pktmon exits non-zero when the session had already ended: the stop still counts
    fake = FakePktmon(rc={"stop": 1})
    s = session(fake, tmp_path)
    s.start()
    fake.running = False
    s.stop()
    assert not s.active and fake.keys()[-2:] == ["stop", "filter remove"]
    # a filter remove that fails is retried by the clean-up
    fake = FakePktmon(rc={"filter remove": 4})
    s = session(fake, tmp_path)
    s.start()
    s.stop()
    fake.rc = {}
    s.cleanup()
    assert fake.keys()[-3:] == ["stop", "filter remove", "filter remove"] and fake.filters == []


def test_convert_needs_exit_0_and_the_output_file(tmp_path):
    fake = FakePktmon(rc={"etl2pcap": 3}, pcaps=[pcapng_file()])
    s = session(fake, tmp_path)
    s.start()
    s.stop()
    out = tmp_path / "a.pcapng"
    assert s.convert(out) is False and s.last_error == "Packet Monitor could not convert (exit 3)"
    fake.rc, fake.pcaps = {}, [None]                                   # exit 0 but no file
    out.write_bytes(b"an older file")
    assert s.convert(out, component_id=3) is False and not out.exists()
    assert s.last_error == "Packet Monitor could not convert (exit 0)"


def test_cleanup_stops_and_removes_filters_once_and_never_unloads(tmp_path):
    fake = FakePktmon()
    s = session(fake, tmp_path)
    s.start()
    s.cleanup()
    s.cleanup()
    assert fake.keys() == ["filter list", "filter add", "filter add", "start", "stop", "filter remove"]
    assert not s.active and not fake.running
    with pytest.raises(RuntimeError):
        s.start()                                                       # single-use
    idle = session(FakePktmon(), tmp_path)
    idle.cleanup()
    idle.stop()
    assert idle._runner.calls == []
    assert all("unload" not in args for args in fake.commands())


# --------------------------------------------------------------------------- crash marker
def test_recover_cleans_up_what_the_marker_lists_inside_the_folder_only(tmp_path):
    folder = tmp_path / "captures"
    folder.mkdir()
    outside = tmp_path / "outside.etl"
    outside.write_bytes(b"not TNT's")
    leftovers = ["TNT-capture-20260101-120000.etl", "TNT-capture-20260101-120000.raw.pcapng"]
    for name in leftovers:
        (folder / name).write_bytes(b"x")
    kept = folder / "TNT-capture-20260101-110000.pcapng"
    kept.write_bytes(pcapng_file(ETH_FRAME))
    info = {"purpose": "capture", "started_ts": T0,
            "files": leftovers + ["..\\outside.etl", "../outside.etl", str(outside), "", 7, "missing.part"]}
    pktmon.write_marker(folder, info)
    assert json.loads((folder / pktmon.MARKER_NAME).read_text(encoding="utf-8")) == info
    fake = FakePktmon()
    holders = []

    def runner(argv, **kwargs):
        holders.append(pktmon.LOCK.holder())
        return fake(argv, **kwargs)

    assert pktmon.recover(folder, runner=runner, session_running_fn=lambda: None) is True
    assert fake.keys() == ["stop", "filter remove"]
    assert [kw["timeout"] for _a, kw in fake.calls] == [10.0, 10.0]
    assert holders == ["capture", "capture"] and pktmon.LOCK.holder() is None
    assert sorted(p.name for p in folder.iterdir()) == [kept.name]
    assert outside.read_bytes() == b"not TNT's"
    # no marker, no folder: nothing runs
    fake = FakePktmon()
    assert pktmon.recover(folder, runner=fake) is False
    assert pktmon.recover(tmp_path / "missing", runner=fake) is False
    assert fake.calls == []
    # a session known to be stopped is not stopped again, but the filters always go
    pktmon.write_marker(folder, {"purpose": "switchport", "files": []})
    assert pktmon.recover(folder, runner=fake, session_running_fn=lambda: False) is True
    assert fake.keys() == ["filter remove"] and not (folder / pktmon.MARKER_NAME).exists()


def test_recover_skips_while_tnt_uses_packet_monitor_and_clears_an_unreadable_marker(tmp_path):
    folder = tmp_path / "captures"
    folder.mkdir()
    (folder / pktmon.MARKER_NAME).write_text("{not json", encoding="utf-8")
    fake = FakePktmon()
    pktmon.LOCK.acquire("switchport")
    try:
        assert pktmon.recover(folder, runner=fake, session_running_fn=lambda: True) is False
    finally:
        pktmon.LOCK.release()
    assert fake.calls == [] and (folder / pktmon.MARKER_NAME).exists()
    assert pktmon.recover(folder, runner=fake, session_running_fn=lambda: True) is True
    assert fake.keys() == ["stop", "filter remove"] and list(folder.iterdir()) == []
    pktmon.clear_marker(folder)                                        # nothing there: no error
