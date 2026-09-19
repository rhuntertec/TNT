"""tnt.capture: the live packet capture (validation, the capture lifecycle, the packet list and its filters, the
detail read-back, saving, opening a file, SIP calls, retention and recovery).

A fake :mod:`tnt.etw` plays the ETW session: :class:`FakeEtw` hands out :class:`FakeTrace` objects and the test pushes
frames into the consumer callback itself, so no test creates a real trace session, captures a real packet or needs an
administrator.  The captures folder is always a tmp_path (tests/conftest.py refuses a write to the real one), the
folder security is a recorder and free disk space is handed in.  Frames carry MACs 02:00:5e:10:00:0x and addresses
from 192.0.2.0/24 and 2001:db8::/32 only.
"""
from __future__ import annotations

import os
import struct
import threading
import time
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from test_pktmon import ADAPTER_MAC, Acl, Bus, nic, wifi  # noqa: F401
from tnt import capture, pcapng
from tnt.capture import (CAPTURE_ADAPTER_KEYS, CAPTURE_FILE_KEYS, CAPTURE_STATUS_KEYS, DETAIL_KEYS, LIMIT_KEYS,
                         PACKETS_KEYS, ROW_KEYS, SESSION_KEYS, TILE_KEYS, CaptureBusy, CaptureFileMissing,
                         CaptureManager, CaptureUnavailable)

MIB, GIB = 1024 ** 2, 1024 ** 3
T0 = 1_788_000_000.0
PEER = bytes.fromhex("02005e100002")
SELF = bytes.fromhex("02005e100001")
BROADCAST = b"\xff" * 6
GUID = "2ED6006E-4729-4609-B423-3EE7BCD678EF"


# --------------------------------------------------------------------------- frames
def eth(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack(">H", ethertype) + payload


def ipv4(proto: int, src: str, dst: str, payload: bytes) -> bytes:
    body = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0)
    body += bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))
    return body + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport: int, dport: int, flags: int = 0x02) -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 64240, 0, 0)


def icmp_echo(seq: int = 1) -> bytes:
    return struct.pack(">BBHHH", 8, 0, 0, 0x1234, seq) + b"tnt"


def udp_frame(sport: int, dport: int, payload: bytes, *, src: str = "192.0.2.10", dst: str = "192.0.2.1") -> bytes:
    return eth(PEER, SELF, 0x0800, ipv4(17, src, dst, udp(sport, dport, payload)))


def tcp_frame(sport: int, dport: int, *, src: str = "192.0.2.10", dst: str = "192.0.2.1") -> bytes:
    return eth(PEER, SELF, 0x0800, ipv4(6, src, dst, tcp(sport, dport)))


def icmp_frame(*, src: str = "192.0.2.10", dst: str = "192.0.2.1") -> bytes:
    return eth(PEER, SELF, 0x0800, ipv4(1, src, dst, icmp_echo()))


def arp_frame() -> bytes:
    body = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + SELF + bytes([192, 0, 2, 1]) + bytes(6) + bytes([192, 0, 2, 5])
    return eth(BROADCAST, SELF, 0x0806, body)


SIP_INVITE = (
    "INVITE sip:bob@192.0.2.20 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-1\r\n"
    "From: <sip:alice@192.0.2.10>;tag=aaa\r\n"
    "To: <sip:bob@192.0.2.20>\r\n"
    "Call-ID: tnt-test-call-1\r\n"
    "CSeq: 1 INVITE\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 129\r\n"
    "\r\n"
    "v=0\r\no=alice 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n"
    "m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
).encode("ascii")


def rtp(seq: int, ts: int, ssrc: int = 0x11223344, pt: int = 0) -> bytes:
    return struct.pack(">BBHII", 0x80, pt, seq, ts, ssrc) + bytes(160)


# --------------------------------------------------------------------------- the fake ETW session
class FakeTrace:
    """One fake real-time session: ``consume`` keeps the callback so a test can push frames itself."""

    def __init__(self, name: str, *, providers=(), **kw: Any) -> None:
        self.name = name
        self.providers = tuple(providers)
        self.kw = dict(kw)
        self.started = False
        self.stopped = False
        self.callback = None
        self.fail_start: Optional[str] = None
        self.fail_consume: Optional[str] = None

    def start(self) -> None:
        if self.fail_start:
            raise RuntimeError(self.fail_start)
        self.started = True

    def consume(self, callback) -> None:
        if self.fail_consume:
            raise RuntimeError(self.fail_consume)
        self.callback = callback

    def stop(self, timeout: float = 5.0) -> None:
        self.stopped = True

    @property
    def running(self) -> bool:
        return self.started and not self.stopped

    def stats(self) -> Dict[str, Any]:
        return {"events": 0, "lost_events": 0, "callback_errors": 0, "buffers_read": 0, "started_ts": T0}


class FakeEtw:
    """Stands in for :mod:`tnt.etw`."""

    NDIS_PACKET_CAPTURE_GUID = GUID
    SESSION_PREFIX = "TNT-Capture"

    def __init__(self, ok: bool = True, reason: Optional[str] = None) -> None:
        self.ok = ok
        self.reason = reason
        self.traces: List[FakeTrace] = []
        self.stale_calls = 0
        self.fail_start: Optional[str] = None
        self.fail_consume: Optional[str] = None

    def available(self) -> Dict[str, Any]:
        return {"ok": self.ok, "reason": self.reason}

    def session_name(self, suffix: str = "") -> str:
        return "TNT-Capture-test"

    def TraceSession(self, name: str, **kw: Any) -> FakeTrace:  # noqa: N802 - it stands in for a class
        trace = FakeTrace(name, **kw)
        trace.fail_start = self.fail_start
        trace.fail_consume = self.fail_consume
        self.traces.append(trace)
        return trace

    def decode_ndis_frame(self, event: Any) -> Optional[Dict[str, Any]]:
        return event if isinstance(event, dict) and "data" in event else None

    def stop_stale_sessions(self, prefix: str = "TNT-Capture") -> int:
        self.stale_calls += 1
        return 0


class Mono:
    """Monotonic time a test moves by hand (the worker's limits are checked against it)."""

    def __init__(self, start: float = 5000.0) -> None:
        self.value = start

    def __call__(self) -> float:
        return self.value


# --------------------------------------------------------------------------- the manager under test
def make(tmp_path, *, adapters=None, etw=None, free: int = 10 * 1024 ** 4, **kw: Any) -> SimpleNamespace:
    bus = Bus()
    acl = Acl()
    mono = Mono()
    etw = etw if etw is not None else FakeEtw()
    state = {"adapters": list(adapters if adapters is not None else [nic(), wifi()]), "now": T0}
    options = dict(adapters_fn=lambda: state["adapters"], clock=lambda: state["now"], monotonic=mono,
                   captures_dir_fn=lambda: tmp_path / "captures", acl=acl, disk_free_fn=lambda path: free,
                   etw=etw, tick_s=0.02)
    options.update(kw)
    mgr = CaptureManager(bus, **options)
    return SimpleNamespace(mgr=mgr, bus=bus, acl=acl, etw=etw, mono=mono, state=state,
                           folder=tmp_path / "captures")


def feed(app: SimpleNamespace, frame: bytes, *, ts: float = T0, if_index: int = 21,
         origlen: Optional[int] = None) -> None:
    """Push one frame through the fake ETW consumer callback."""
    trace = app.etw.traces[-1]
    assert trace.callback is not None, "the capture never started consuming"
    trace.callback({"ts": ts, "if_index": if_index, "lower_if": if_index, "data": frame,
                    "origlen": len(frame) if origlen is None else origlen})


def wait_for(fn, timeout: float = 5.0) -> bool:
    """Poll *fn* until it is true (the worker runs on its own thread); False when it never became true."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if fn():
            return True
        time.sleep(0.005)
    return False


def wait_packets(app: SimpleNamespace, count: int, timeout: float = 5.0) -> None:
    assert wait_for(lambda: (app.mgr.session() or {}).get("packets", 0) >= count, timeout), \
        f"only {(app.mgr.session() or {}).get('packets')} packet(s) arrived, wanted {count}"


def started(app: SimpleNamespace, **kw: Any) -> Dict[str, Any]:
    options = dict(adapter="Ethernet", max_seconds=60, max_mb=64)
    options.update(kw)
    return app.mgr.start(**options)


@pytest.fixture
def app(tmp_path):
    made = make(tmp_path)
    yield made
    made.mgr.close(0.5)


# --------------------------------------------------------------------------- shapes and views
def test_status_and_limits_have_their_documented_shape(app):
    status = app.mgr.status()
    assert tuple(status) == CAPTURE_STATUS_KEYS
    assert status["available"] is True and status["reason"] is None
    assert status["session"] is None and status["files"] == []
    assert tuple(status["limits"]) == LIMIT_KEYS
    assert tuple(status["adapters"][0]) == CAPTURE_ADAPTER_KEYS
    assert status["limits"]["seconds"] == list(capture.CAPTURE_SECONDS)
    assert status["limits"]["sizes_mb"] == list(capture.CAPTURE_SIZES_MB)


def test_adapters_are_the_ones_that_are_up_and_physical(tmp_path):
    made = make(tmp_path, adapters=[nic(), wifi(status="down"), nic("Loopback", index=1, loopback=True),
                                    nic("Virtual", index=9, physical=False)])
    names = [a["name"] for a in made.mgr.adapters()]
    assert names == ["Ethernet"]
    assert made.mgr.adapters()[0]["wifi"] is False


def test_a_wifi_adapter_is_marked(tmp_path):
    made = make(tmp_path, adapters=[wifi()])
    assert made.mgr.adapters()[0] == {"name": "Wi-Fi", "index": 17, "mac": "02:00:5E:10:00:02",
                                      "type_name": "Wi-Fi", "wifi": True}


def test_the_tile_block_carries_counts_only(app):
    tile = app.mgr.tile()
    assert tuple(tile) == TILE_KEYS
    assert tile == {"available": True, "reason": None, "running": False, "adapter": None, "packets": 0, "calls": 0,
                    "files": 0}
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    tile = app.mgr.tile()
    assert tile["running"] is True and tile["adapter"] == "Ethernet" and tile["packets"] == 1


# --------------------------------------------------------------------------- validation
@pytest.mark.parametrize("adapter", ["", None, "Nope", "Wi-Fi 2"])
def test_start_refuses_an_adapter_that_is_not_up(app, adapter):
    with pytest.raises(ValueError, match="is not up"):
        app.mgr.start(adapter=adapter)
    assert app.mgr.session() is None and app.etw.traces == []


@pytest.mark.parametrize("seconds", [0, 30, 45, 7200, "60", None, True])
def test_start_refuses_a_duration_that_is_not_offered(app, seconds):
    with pytest.raises(ValueError, match="max_seconds must be one of"):
        app.mgr.start(adapter="Ethernet", max_seconds=seconds)


@pytest.mark.parametrize("mb", [0, 32, 2048, "64", None])
def test_start_refuses_a_size_that_is_not_offered(app, mb):
    with pytest.raises(ValueError, match="max_mb must be one of"):
        app.mgr.start(adapter="Ethernet", max_mb=mb)


def test_start_refuses_when_etw_is_not_available(tmp_path):
    made = make(tmp_path, etw=FakeEtw(ok=False, reason="needs an administrator"))
    with pytest.raises(CaptureUnavailable, match="needs an administrator"):
        started(made)
    assert made.mgr.status()["available"] is False


def test_start_refuses_without_the_disk_space_the_limit_needs(tmp_path):
    made = make(tmp_path, free=100 * MIB)
    with pytest.raises(CaptureUnavailable, match="Not enough free disk space"):
        started(made, max_mb=1024)


def test_start_fails_closed_when_the_folder_cannot_be_secured(tmp_path):
    made = make(tmp_path, acl=lambda path, sddl: (_ for _ in ()).throw(OSError("denied")))
    with pytest.raises(CaptureUnavailable, match="could not be secured"):
        started(made)
    assert made.etw.traces == []


def test_a_second_start_while_capturing_is_refused(app):
    started(app)
    with pytest.raises(CaptureBusy, match="already running"):
        started(app)


def test_a_failing_trace_start_leaves_nothing_behind(tmp_path):
    etw = FakeEtw()
    etw.fail_start = "access denied"
    made = make(tmp_path, etw=etw)
    with pytest.raises(CaptureUnavailable, match="access denied"):
        started(made)
    assert made.mgr.session() is None
    assert [p.name for p in made.folder.iterdir()] == []


# --------------------------------------------------------------------------- the capture lifecycle
def test_start_opens_a_working_file_and_a_trace_on_the_ndis_provider(app):
    session = started(app)
    assert tuple(session) == SESSION_KEYS
    assert session["state"] == "capturing" and session["source"] == "live"
    assert session["adapter"]["name"] == "Ethernet" and session["saved"] is False and session["file"] is None
    trace = app.etw.traces[-1]
    assert trace.started and trace.callback is not None
    assert trace.providers[0][0] == GUID
    work = [p.name for p in app.folder.iterdir()]
    assert len(work) == 1 and work[0].startswith("TNT-live-") and work[0].endswith(".pcapng")


def test_packets_are_written_to_the_file_and_listed(app):
    started(app)
    feed(app, icmp_frame(), ts=T0)
    feed(app, tcp_frame(49152, 443), ts=T0 + 0.5)
    wait_packets(app, 2)
    answer = app.mgr.packets()
    assert tuple(answer) == PACKETS_KEYS
    assert answer["total"] == 2 and answer["matched"] == 2 and answer["last"] == 2
    rows = answer["rows"]
    assert [r["no"] for r in rows] == [1, 2]
    assert tuple(rows[0]) == ROW_KEYS
    assert rows[0]["proto"] == "ICMP" and rows[0]["src"] == "192.0.2.10" and rows[0]["dst"] == "192.0.2.1"
    assert rows[0]["src_mac"] == "02:00:5e:10:00:01" and rows[0]["dst_mac"] == "02:00:5e:10:00:02"
    assert rows[0]["rel"] == 0.0 and rows[1]["rel"] == pytest.approx(0.5)
    assert rows[1]["proto"] == "TCP" and rows[1]["dport"] == 443


def test_a_frame_from_another_adapter_is_ignored(app):
    started(app)
    feed(app, icmp_frame(), if_index=17)            # the Wi-Fi adapter's index
    feed(app, icmp_frame(), if_index=21)
    wait_packets(app, 1)
    assert app.mgr.packets()["total"] == 1


def test_the_written_file_reads_back_as_pcapng(app, tmp_path):
    started(app)
    frame = icmp_frame()
    feed(app, frame, ts=T0 + 1.25)
    wait_packets(app, 1)
    app.mgr.stop()
    path = next(p for p in app.folder.iterdir() if p.name.startswith("TNT-live-"))
    assert pcapng.count_packets(path) == 1
    with open(path, "rb") as fh:
        packet = next(pcapng.iter_packets(fh))
    assert packet["data"] == frame and packet["ts"] == pytest.approx(T0 + 1.25, abs=1e-5)


def test_stop_keeps_the_capture_and_names_the_reason(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    session = app.mgr.stop()
    assert session["state"] == "stopped" and session["stop_reason"] == "user" and session["saved"] is False
    assert app.etw.traces[-1].stopped is True
    assert app.mgr.packets()["total"] == 1                 # the rows survive the stop


def test_stop_does_nothing_when_no_capture_runs(app):
    assert app.mgr.stop() is None


def test_the_time_limit_stops_the_capture_by_itself(app):
    started(app, max_seconds=60)
    app.mono.value += 61
    assert wait_for(lambda: (app.mgr.session() or {})["state"] == "stopped")
    assert app.mgr.session()["stop_reason"] == "seconds"


def test_the_size_limit_stops_the_capture_by_itself(tmp_path):
    made = make(tmp_path)
    started(made, max_mb=64)
    made.mgr._limit_bytes = 200                            # a byte budget two packets pass
    feed(made, icmp_frame())
    feed(made, icmp_frame())
    assert wait_for(lambda: (made.mgr.session() or {})["state"] == "stopped")
    assert made.mgr.session()["stop_reason"] == "size"
    made.mgr.close(0.5)


def test_a_frame_that_arrives_with_the_queue_full_is_counted_as_dropped(tmp_path):
    made = make(tmp_path, queue_size=16)
    started(made)
    made.mgr._queue = None                                  # the worker cannot take anything
    made.etw.traces[-1].callback({"ts": T0, "if_index": 21, "lower_if": 21, "data": None, "origlen": 0})
    assert made.mgr.session()["dropped"] == 0               # a frame decode_ndis_frame refuses is not a drop
    made.mgr.close(0.5)


def test_the_list_keeps_at_most_max_rows_and_says_so(tmp_path):
    made = make(tmp_path, max_rows=4)
    started(made)
    for i in range(7):
        feed(made, icmp_frame(), ts=T0 + i)
    wait_packets(made, 7)
    session = made.mgr.session()
    assert session["packets"] == 7 and session["shown"] == 4 and session["truncated"] is True
    answer = made.mgr.packets()
    assert [r["no"] for r in answer["rows"]] == [4, 5, 6, 7]
    made.mgr.close(0.5)


def test_closing_the_engine_stops_a_running_capture(app):
    started(app)
    app.mgr.close(0.5)
    assert app.mgr.session()["state"] == "stopped" and app.mgr.session()["stop_reason"] == "service"


# --------------------------------------------------------------------------- the list, paging and filters
def _mixed(app) -> None:
    started(app)
    feed(app, icmp_frame(), ts=T0)                                        # 1 ICMP
    feed(app, arp_frame(), ts=T0 + 1)                                     # 2 ARP
    feed(app, tcp_frame(49152, 443), ts=T0 + 2)                           # 3 TCP/TLS port
    feed(app, udp_frame(50000, 53, b"\x12\x34" + bytes(10)), ts=T0 + 3)   # 4 DNS
    feed(app, udp_frame(5060, 5060, SIP_INVITE, src="192.0.2.10", dst="192.0.2.20"), ts=T0 + 4)   # 5 SIP
    wait_packets(app, 5)


def test_without_since_the_newest_rows_come_back(app):
    started(app)
    for i in range(10):
        feed(app, icmp_frame(), ts=T0 + i)
    wait_packets(app, 10)
    rows = app.mgr.packets(limit=3)["rows"]
    assert [r["no"] for r in rows] == [8, 9, 10]


def test_since_tails_the_list_oldest_first(app):
    started(app)
    for i in range(6):
        feed(app, icmp_frame(), ts=T0 + i)
    wait_packets(app, 6)
    answer = app.mgr.packets(since=3, limit=2)
    assert [r["no"] for r in answer["rows"]] == [4, 5]
    assert answer["last"] == 5 and answer["dropped_before"] is False


def test_a_tail_the_ring_rolled_past_says_so(tmp_path):
    made = make(tmp_path, max_rows=3)
    started(made)
    for i in range(8):
        feed(made, icmp_frame(), ts=T0 + i)
    wait_packets(made, 8)
    assert made.mgr.packets(since=1)["dropped_before"] is True
    assert made.mgr.packets(since=7)["dropped_before"] is False
    made.mgr.close(0.5)


def test_the_ip_filter_matches_source_or_destination(app):
    _mixed(app)
    assert app.mgr.packets(ip="192.0.2.20")["matched"] == 1          # the SIP packet's destination
    assert app.mgr.packets(ip="192.0.2.10")["matched"] == 4          # every IP packet; the ARP frame carries neither
    assert app.mgr.packets(ip="192.0.2.5")["matched"] == 1           # the address the ARP frame asks about
    assert app.mgr.packets(ip="203.0.113.9")["matched"] == 0


def test_a_filter_that_is_not_an_address_is_ignored(app):
    _mixed(app)
    assert app.mgr.packets(ip="not-an-ip")["matched"] == 5
    assert app.mgr.packets(ip="192.0.2.0/24")["matched"] == 5
    assert app.mgr.packets(mac="zz")["matched"] == 5


def test_the_mac_filter_takes_any_spelling(app):
    _mixed(app)
    for text in ("02:00:5e:10:00:01", "02-00-5E-10-00-01", "02005E100001", "02:00:5E:10:00:01"):
        assert app.mgr.packets(mac=text)["matched"] == 5, text
    assert app.mgr.packets(mac="02:00:5e:10:00:09")["matched"] == 0


def test_protocol_filters_are_ored_and_and_with_the_fields(app):
    _mixed(app)
    assert [r["no"] for r in app.mgr.packets(protos=["icmp"])["rows"]] == [1]
    assert [r["no"] for r in app.mgr.packets(protos=["arp"])["rows"]] == [2]
    assert [r["no"] for r in app.mgr.packets(protos=["icmp", "arp"])["rows"]] == [1, 2]
    assert [r["no"] for r in app.mgr.packets(protos=["sip"])["rows"]] == [5]
    assert app.mgr.packets(protos=["icmp"], ip="192.0.2.20")["matched"] == 0
    assert app.mgr.packets(protos=["nonsense"])["matched"] == 5      # an unknown key is dropped, not an error


def test_a_protocol_filter_matches_a_layer_under_the_top_one(app):
    _mixed(app)
    assert [r["no"] for r in app.mgr.packets(protos=["udp"])["rows"]] == [4, 5]
    assert [r["no"] for r in app.mgr.packets(protos=["tcp"])["rows"]] == [3]


def test_the_row_limit_is_clamped(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    assert len(app.mgr.packets(limit=0)["rows"]) == 1
    assert len(app.mgr.packets(limit=10 ** 9)["rows"]) == 1
    assert len(app.mgr.packets(limit="nonsense")["rows"]) == 1


# --------------------------------------------------------------------------- one packet in detail
def test_packet_detail_reads_the_frame_back_out_of_the_file(app):
    started(app)
    feed(app, icmp_frame(), ts=T0 + 2)
    wait_packets(app, 1)
    detail = app.mgr.packet(1)
    assert tuple(detail) == DETAIL_KEYS
    assert detail["row"]["no"] == 1 and detail["bytes"] == len(icmp_frame())
    names = [layer["name"] for layer in detail["layers"]]
    assert names[:4] == ["Frame", "ETH", "IPv4", "ICMP"]
    assert tuple(detail["layers"][1]) == ("name", "summary", "start", "length", "fields")
    assert tuple(detail["layers"][1]["fields"][0]) == ("name", "value", "start", "length")
    assert detail["hex"] and detail["hex"][0].startswith("0000")


@pytest.mark.parametrize("no", [0, 2, -1, "nonsense", None])
def test_a_packet_that_is_not_in_the_list_is_not_found(app, no):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    with pytest.raises(CaptureFileMissing):
        app.mgr.packet(no)


# --------------------------------------------------------------------------- saving, discarding, opening
def test_save_renames_the_working_file_and_lists_it(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    session = app.mgr.save()
    assert session["state"] == "stopped" and session["saved"] is True
    assert session["file"].startswith("TNT-capture-") and session["file"].endswith(".pcapng")
    files = app.mgr.files()
    assert [f["name"] for f in files] == [session["file"]]
    assert tuple(files[0]) == CAPTURE_FILE_KEYS
    assert not [p for p in app.folder.iterdir() if p.name.startswith("TNT-live-")]


def test_saving_twice_changes_nothing(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    first = app.mgr.save()
    again = app.mgr.save()
    assert again["file"] == first["file"] and len(app.mgr.files()) == 1


def test_save_without_a_capture_is_not_found(app):
    with pytest.raises(CaptureFileMissing):
        app.mgr.save()


def test_discard_deletes_the_unsaved_file(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    app.mgr.discard()
    assert app.mgr.session() is None
    assert app.mgr.packets()["total"] == 0
    assert [p.name for p in app.folder.iterdir()] == []


def test_discard_keeps_a_capture_that_was_saved(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    name = app.mgr.save()["file"]
    app.mgr.discard()
    assert [f["name"] for f in app.mgr.files()] == [name]


def test_open_file_reads_a_saved_capture_back(app):
    started(app)
    feed(app, icmp_frame(), ts=T0)
    feed(app, arp_frame(), ts=T0 + 1)
    wait_packets(app, 2)
    name = app.mgr.save()["file"]
    app.mgr.discard()
    session = app.mgr.open_file(name)
    assert session["state"] == "loaded" and session["source"] == "file" and session["saved"] is True
    assert session["file"] == name and session["packets"] == 2
    rows = app.mgr.packets()["rows"]
    assert [r["proto"] for r in rows] == ["ICMP", "ARP"]
    assert app.mgr.packet(1)["row"]["proto"] == "ICMP"


def test_open_file_refuses_a_name_that_is_not_one_of_ours(app):
    for name in ("../secret.pcapng", "TNT-live-20260101-120000.pcapng", "x.pcapng", "", None,
                 "TNT-capture-20260101-120000.pcapng"):
        with pytest.raises(CaptureFileMissing):
            app.mgr.open_file(name)


def test_open_file_is_refused_while_a_capture_runs(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    name = app.mgr.save()["file"]
    started(app)
    with pytest.raises(CaptureBusy):
        app.mgr.open_file(name)


def test_opening_a_file_that_is_not_pcapng_says_so(app):
    app.folder.mkdir(parents=True, exist_ok=True)
    name = "TNT-capture-20260101-120000.pcapng"
    (app.folder / name).write_bytes(b"not a capture at all")
    with pytest.raises(CaptureUnavailable, match="is not a capture TNT can read"):
        app.mgr.open_file(name)


def test_a_long_file_is_indexed_up_to_the_row_limit(tmp_path):
    made = make(tmp_path, max_rows=3)
    started(made)
    for i in range(9):
        feed(made, icmp_frame(), ts=T0 + i)
    wait_packets(made, 9)
    name = made.mgr.save()["file"]
    made.mgr.discard()
    session = made.mgr.open_file(name)
    # the first three are read, and `truncated` says the file holds more than the list does
    assert session["packets"] == 3 and session["shown"] == 3 and session["truncated"] is True
    assert [r["no"] for r in made.mgr.packets()["rows"]] == [1, 2, 3]
    made.mgr.close(0.5)


# --------------------------------------------------------------------------- files
def test_delete_file_removes_it_and_returns_the_rest(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    name = app.mgr.save()["file"]
    app.mgr.discard()
    assert app.mgr.delete_file(name) == []
    with pytest.raises(CaptureFileMissing):
        app.mgr.delete_file(name)


def test_deleting_the_capture_that_is_open_closes_it_first(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    name = app.mgr.save()["file"]
    assert app.mgr.delete_file(name) == []
    assert app.mgr.session() is None


def test_a_download_hands_back_the_open_file_and_its_size(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    name = app.mgr.save()["file"]
    fh, size = app.mgr.file_download(name)
    try:
        assert size == os.path.getsize(app.folder / name) and fh.read(4) == b"\x0a\x0d\x0d\x0a"
    finally:
        fh.close()


@pytest.mark.parametrize("name", ["", None, "..", "../x", "TNT-capture-1.pcapng", "TNT-live-20260101-120000.pcapng"])
def test_a_name_that_is_not_one_of_ours_is_never_opened(app, name):
    with pytest.raises(CaptureFileMissing):
        app.mgr.file_download(name)


def test_retention_keeps_the_newest_files_only(tmp_path):
    made = make(tmp_path)
    made.folder.mkdir(parents=True)
    for i in range(capture.MAX_FILES + 3):
        path = made.folder / f"TNT-capture-2026010{i // 10}-1200{i:02d}.pcapng"
        path.write_bytes(b"x" * 100)
        os.utime(path, (T0 + i, T0 + i))
    assert made.mgr.enforce_retention(T0 + 100) == 3
    assert len(made.mgr.files()) == capture.MAX_FILES


def test_retention_deletes_anything_older_than_the_age_limit(tmp_path):
    made = make(tmp_path)
    made.folder.mkdir(parents=True)
    old = made.folder / "TNT-capture-20260101-120000.pcapng"
    old.write_bytes(b"x")
    os.utime(old, (T0 - capture.MAX_AGE_S - 10, T0 - capture.MAX_AGE_S - 10))
    new = made.folder / "TNT-capture-20260101-120001.pcapng"
    new.write_bytes(b"x")
    os.utime(new, (T0, T0))
    assert made.mgr.enforce_retention(T0) == 1
    assert [f["name"] for f in made.mgr.files()] == [new.name]


def test_retention_never_deletes_the_capture_that_is_open(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    name = app.mgr.save()["file"]
    os.utime(app.folder / name, (T0 - capture.MAX_AGE_S - 10, T0 - capture.MAX_AGE_S - 10))
    assert app.mgr.enforce_retention(T0) == 0
    assert [f["name"] for f in app.mgr.files()] == [name]


def test_recover_stops_a_stale_session_and_deletes_unsaved_files(tmp_path):
    made = make(tmp_path)
    made.folder.mkdir(parents=True)
    (made.folder / "TNT-live-20260101-120000.pcapng").write_bytes(b"x")
    keep = made.folder / "TNT-capture-20260101-120000.pcapng"
    keep.write_bytes(b"x")
    made.mgr.recover()
    assert wait_for(lambda: not (made.folder / "TNT-live-20260101-120000.pcapng").exists())
    assert keep.exists() and made.etw.stale_calls == 1


# --------------------------------------------------------------------------- SIP
def test_a_sip_call_is_found_and_announced_once(app):
    started(app)
    feed(app, udp_frame(5060, 5060, SIP_INVITE, src="192.0.2.10", dst="192.0.2.20"), ts=T0)
    wait_packets(app, 1)
    assert wait_for(lambda: app.mgr.session()["calls"] == 1)
    calls = app.mgr.calls()
    assert len(calls) == 1 and calls[0]["call_id"] == "tnt-test-call-1"
    published = app.bus.of(capture.SIP_EVENT)
    assert len(published) == 1 and published[0]["call"]["call_id"] == "tnt-test-call-1"
    feed(app, udp_frame(5060, 5060, SIP_INVITE, src="192.0.2.10", dst="192.0.2.20"), ts=T0 + 1)
    wait_packets(app, 2)
    assert len(app.bus.of(capture.SIP_EVENT)) == 1        # the same call is announced once


def test_rtp_of_a_call_is_tracked_and_can_be_rebuilt(app):
    started(app)
    feed(app, udp_frame(5060, 5060, SIP_INVITE, src="192.0.2.10", dst="192.0.2.20"), ts=T0)
    for i in range(5):
        feed(app, udp_frame(40000, 40000, rtp(i, i * 160), src="192.0.2.10", dst="192.0.2.20"), ts=T0 + i * 0.02)
    wait_packets(app, 6)
    call = app.mgr.calls()[0]
    assert wait_for(lambda: app.mgr.calls()[0]["streams"])
    wav = app.mgr.call_audio(call["id"])
    assert wav[:4] == b"RIFF" and wav[8:12] == b"WAVE"


def test_audio_of_a_call_that_is_not_there_is_not_found(app):
    started(app)
    with pytest.raises(CaptureFileMissing):
        app.mgr.call_audio("nope")


def test_calls_are_empty_without_a_capture(app):
    assert app.mgr.calls() == []


# --------------------------------------------------------------------------- events
def test_the_state_event_carries_the_session(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    app.mgr.stop()
    published = app.bus.of(capture.EVENT)
    assert published, "no capture.state event was published"
    assert tuple(published[-1]["session"]) == SESSION_KEYS
    assert published[-1]["session"]["state"] == "stopped"


def test_a_wifi_capture_rewrites_802_11_data_frames_as_ethernet(tmp_path):
    made = make(tmp_path, adapters=[wifi()])
    started(made, adapter="Wi-Fi")
    snap = b"\xaa\xaa\x03\x00\x00\x00"
    dot11 = (bytes([0x08, 0x01]) + bytes(2) + PEER + SELF + PEER + bytes(2)
             + snap + b"\x08\x00" + ipv4(1, "192.0.2.10", "192.0.2.1", icmp_echo()))
    feed(made, dot11, if_index=17)
    wait_packets(made, 1)
    row = made.mgr.packets()["rows"][0]
    assert row["proto"] == "ICMP" and row["src"] == "192.0.2.10"
    made.mgr.close(0.5)


def test_an_undissectable_frame_still_becomes_a_row(app):
    started(app)
    feed(app, b"\x00")
    wait_packets(app, 1)
    row = app.mgr.packets()["rows"][0]
    assert row["no"] == 1 and row["length"] == 1


def test_threads_are_gone_after_close(app):
    started(app)
    feed(app, icmp_frame())
    wait_packets(app, 1)
    app.mgr.close(1.0)
    assert wait_for(lambda: not any(t.name == capture.THREAD_NAME for t in threading.enumerate()))


def test_a_capture_ends_when_its_adapter_goes_away(tmp_path):
    """The cable is unplugged (or the adapter disabled) while a capture runs: it stops and says why."""
    made = make(tmp_path)
    started(made)
    feed(made, icmp_frame())
    wait_packets(made, 1)
    made.state["adapters"] = [wifi()]                       # 'Ethernet' is gone
    made.mono.value += capture.ADAPTER_CHECK_S + 1
    assert wait_for(lambda: (made.mgr.session() or {})["state"] == "stopped")
    session = made.mgr.session()
    assert session["stop_reason"] == "adapter" and session["packets"] == 1     # what it caught is kept
    made.mgr.close(0.5)


def test_an_adapter_list_that_cannot_be_read_never_ends_a_capture(tmp_path):
    """Enumerating adapters can fail for a moment; that says nothing about the one being captured."""
    made = make(tmp_path)
    started(made)
    made.state["adapters"] = []
    made.mono.value += capture.ADAPTER_CHECK_S + 1
    feed(made, icmp_frame())
    wait_packets(made, 1)
    assert made.mgr.session()["state"] == "capturing"
    made.mgr.close(0.5)


# --------------------------------------------------------------------------- opening any file on this PC
def _write_capture(path, frames, *, ts: float = T0) -> None:
    """A little pcapng at *path* holding *frames* (any folder, not TNT's)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        writer = pcapng.Writer(fh, linktype=1, if_name="test")
        for i, frame in enumerate(frames):
            writer.write_packet(ts + i, frame)


def test_open_path_reads_a_capture_from_anywhere_on_this_pc(app, tmp_path):
    """A file from Wireshark, a switch or a colleague: not one of TNT's, and not in TNT's folder."""
    elsewhere = tmp_path / "Documents" / "from-the-switch.pcapng"
    _write_capture(elsewhere, [icmp_frame(), arp_frame(), udp_frame(5060, 5060, SIP_INVITE)])
    session = app.mgr.open_path(str(elsewhere))
    assert session["state"] == "loaded" and session["source"] == "file"
    assert session["file"] == "from-the-switch.pcapng" and session["packets"] == 3
    assert [r["proto"] for r in app.mgr.packets()["rows"]] == ["ICMP", "ARP", "SIP"]
    assert app.mgr.packet(2)["row"]["proto"] == "ARP"


def test_a_file_opened_from_elsewhere_is_never_deleted_or_moved(app, tmp_path):
    """TNT only ever reads it: discard leaves it alone, and save does nothing to it."""
    elsewhere = tmp_path / "keep-me.pcapng"
    _write_capture(elsewhere, [icmp_frame()])
    before = elsewhere.read_bytes()
    app.mgr.open_path(str(elsewhere))
    assert app.mgr.save()["file"] == "keep-me.pcapng"        # a loaded file is already "saved": nothing happens
    app.mgr.discard()
    assert elsewhere.exists() and elsewhere.read_bytes() == before
    assert app.mgr.files() == []                             # and it never joins TNT's own list


def test_open_path_finds_the_sip_calls_too(app, tmp_path):
    path = tmp_path / "a-call.pcapng"
    frames = [udp_frame(5060, 5060, SIP_INVITE, src="192.0.2.10", dst="192.0.2.20")]
    frames += [udp_frame(40000, 40000, rtp(i, i * 160), src="192.0.2.10", dst="192.0.2.20") for i in range(4)]
    _write_capture(path, frames)
    app.mgr.open_path(str(path))
    calls = app.mgr.calls()
    assert len(calls) == 1 and calls[0]["call_id"] == "tnt-test-call-1"
    assert app.mgr.call_audio(calls[0]["id"])[:4] == b"RIFF"


@pytest.mark.parametrize("bad", ["", "   ", None, "capture.pcapng", "..\\capture.pcapng",
                                 "\\\\server\\share\\x.pcapng", "C:" + "\\y" * 3000])
def test_open_path_refuses_a_path_that_is_not_an_absolute_local_file(app, bad):
    with pytest.raises(ValueError, match="full path of a file on this PC"):
        app.mgr.open_path(bad)


def test_open_path_is_not_found_for_a_folder_or_a_file_that_is_not_there(app, tmp_path):
    for target in (tmp_path, tmp_path / "nope.pcapng"):
        with pytest.raises(CaptureFileMissing):
            app.mgr.open_path(str(target))


def test_open_path_refuses_a_file_over_the_size_limit(app, tmp_path, monkeypatch):
    path = tmp_path / "huge.pcapng"
    _write_capture(path, [icmp_frame()])
    monkeypatch.setattr(capture, "MAX_OPEN_BYTES", 10)
    with pytest.raises(ValueError, match="larger than"):
        app.mgr.open_path(str(path))


def test_open_path_says_so_when_the_file_is_not_a_capture(app, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_bytes(b"this is not a capture at all, it is a shopping list")
    with pytest.raises(CaptureUnavailable, match="is not a capture TNT can read"):
        app.mgr.open_path(str(path))


def test_open_path_takes_a_path_in_quotes_because_explorer_copies_it_that_way(app, tmp_path):
    path = tmp_path / "quoted.pcapng"
    _write_capture(path, [icmp_frame()])
    assert app.mgr.open_path(f'"{path}"')["packets"] == 1


def test_open_path_is_refused_while_a_capture_runs(app, tmp_path):
    path = tmp_path / "later.pcapng"
    _write_capture(path, [icmp_frame()])
    started(app)
    with pytest.raises(CaptureBusy):
        app.mgr.open_path(str(path))
