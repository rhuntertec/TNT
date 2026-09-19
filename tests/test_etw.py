"""tnt.etw: the ctypes structure layout, the session state machine and the NDIS packet payload.

No test here creates a real ETW session or enables a real provider: every TraceSession is driven through a fake
advapi32 seam, _Advapi itself through a fake DLL, and the two callbacks are built and called in this process only.
MACs are 02:00:5e:10:00:0x and addresses come from 192.0.2.0/24.

tnt.etw stays importable anywhere (it is, off Windows, in test_available_off_windows), but the sizes and offsets it
documents are Windows x64: c_wchar is 2 bytes there and 4 elsewhere, and c_void_p is 4 on a 32-bit build, so the two
tests that measure a structure carry the ``x64_only`` mark and everything else runs on any platform.
"""
from __future__ import annotations

import ctypes
import struct
import sys
import threading
import uuid

import pytest

from tnt import etw
from tnt.etw import (ACCESS_DENIED_TEXT, AVAILABILITY_KEYS, CONSUMER_THREAD_NAME, CONTROL_STATS_KEYS,
                     DEFAULT_BUFFER_KB, DEFAULT_MAX_BUFFERS, DEFAULT_MIN_BUFFERS, EVENT_KEYS, FLUSH_TIMER_S,
                     FRAME_KEYS, HEADER_LEN, MAX_FRAME, MAX_STALE_NAMES, NDIS_PACKET_CAPTURE_GUID, NOT_ADMIN_REASON,
                     NOT_WINDOWS_REASON, NO_API_REASON, SESSION_PREFIX, STATS_KEYS, STRUCT_SIZES, EtwError,
                     TraceSession, available, decode_ndis_frame, session_name, stop_stale_sessions)

ERROR_SUCCESS = 0
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_ALREADY_EXISTS = 183
ERROR_WMI_INSTANCE_NOT_FOUND = 4201
ERROR_CTX_CLOSE_PENDING = 7007                # what CloseTrace answers a real-time consumer that is still draining

#: The documented sizes and offsets below are the x64 Windows layout; c_wchar and c_void_p are not that size elsewhere.
x64_only = pytest.mark.skipif(sys.platform != "win32" or ctypes.sizeof(ctypes.c_void_p) != 8,
                              reason="the documented ETW structure sizes are the Windows x64 layout")

HOST = bytes.fromhex("02005e100001")          # this PC
GATEWAY = bytes.fromhex("02005e100002")       # the router
# an Ethernet frame carrying IPv4 + UDP, 192.0.2.10 -> 192.0.2.1 (nothing here checks checksums)
IP_PACKET = (bytes([0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 10, 192, 0, 2, 1])
             + struct.pack(">HHHH", 50000, 53, 8, 0))
FRAME = GATEWAY + HOST + b"\x08\x00" + IP_PACKET
IF_INDEX, LOWER_IF = 14, 0
TS = 1_700_000_000.5
#: the FILETIME-style 100 ns count since 1601-01-01 that reads back as TS
FILETIME = int((TS + 11_644_473_600) * 10_000_000)


# --------------------------------------------------------------------------- builders
def payload(frame=FRAME, *, if_index=IF_INDEX, lower_if=LOWER_IF, fragment_size=None):
    """An NDIS packet event payload: MiniportIfIndex, LowerIfIndex and FragmentSize, then the frame."""
    claimed = len(frame) if fragment_size is None else fragment_size
    return struct.pack("<III", if_index, lower_if, claimed) + frame


def event(data=None, *, provider=NDIS_PACKET_CAPTURE_GUID, event_id=1001, ts=TS):
    return {"provider": provider, "event_id": event_id, "ts": ts, "data": payload() if data is None else data}


class FakeApi:
    """Stands in for tnt.etw._Advapi: it records every call, answers with canned return codes and hands the event
    callback to the test, which drives it from its own thread. ``process_trace`` blocks like the real one until
    ``close_trace`` releases it."""

    def __init__(self, *, start_rcs=(ERROR_SUCCESS,), enable_rc=ERROR_SUCCESS, open_rc=ERROR_SUCCESS,
                 control_rcs=None, control_rc=ERROR_SUCCESS, handle=0x1234, trace_handle=0x99, stats=None,
                 process_rc=ERROR_SUCCESS):
        self.calls = []
        self.start_rcs = list(start_rcs)
        self.enable_rc = enable_rc
        self.open_rc = open_rc
        self.control_rcs = dict(control_rcs or {})
        self.control_rc = control_rc
        self.handle = handle
        self.trace_handle = trace_handle
        self.process_rc = process_rc
        self.stats = dict(stats or {"events_lost": 0, "buffers_written": 0, "real_time_buffers_lost": 0})
        self.on_event = None
        self.on_buffer = None
        self.processing = threading.Event()
        self.released = threading.Event()

    def names(self):
        return [call[0] for call in self.calls]

    # -- the seam ------------------------------------------------------------------------------
    def start_trace(self, name, *, buffer_kb, min_buffers, max_buffers, flush_timer_s):
        self.calls.append(("start_trace", name, buffer_kb, min_buffers, max_buffers, flush_timer_s))
        rc = self.start_rcs.pop(0) if self.start_rcs else ERROR_SUCCESS
        return rc, (self.handle if rc == ERROR_SUCCESS else 0)

    def enable_trace(self, handle, guid, level, keywords):
        self.calls.append(("enable_trace", handle, guid, level, keywords))
        return self.enable_rc

    def control_trace(self, handle, name, code):
        self.calls.append(("control_trace", handle, name, code))
        return self.control_rcs.get(name, self.control_rc), dict(self.stats)

    def open_trace(self, name, on_event, on_buffer):
        self.calls.append(("open_trace", name))
        self.on_event, self.on_buffer = on_event, on_buffer
        return self.open_rc, (self.trace_handle if self.open_rc == ERROR_SUCCESS else 0)

    def process_trace(self, handle):
        self.calls.append(("process_trace", handle))
        self.processing.set()
        self.released.wait(5)
        return self.process_rc

    def close_trace(self, handle):
        self.calls.append(("close_trace", handle))
        self.released.set()
        return ERROR_SUCCESS


class FakeDll:
    """Stands in for advapi32 in the one place tnt.etw touches it: it records what the module passed and answers with
    canned return codes. Nothing here starts a session, opens a trace or reads a real buffer, and ``ProcessTrace``
    blocks like the real one until the test releases it."""

    def __init__(self, *, start_rc=ERROR_SUCCESS, handle=0x1234, trace_handle=0x99, process_rc=ERROR_SUCCESS,
                 close_rc=ERROR_CTX_CLOSE_PENDING):
        self.start_rc, self.handle = start_rc, handle
        self.trace_handle, self.process_rc, self.close_rc = trace_handle, process_rc, close_rc
        self.properties = None            # a copy of the EVENT_TRACE_PROPERTIES StartTraceW was handed
        self.logfile_addr = self.logfile_mode = None
        self.logger_name = None
        self.closed = []
        self.processed = []
        self.processing = threading.Event()
        self.released = threading.Event()

    def StartTraceW(self, handle_ref, name, props_addr):
        size = ctypes.sizeof(etw.EVENT_TRACE_PROPERTIES)
        raw = bytes((ctypes.c_ubyte * size).from_address(props_addr))
        self.properties = etw.EVENT_TRACE_PROPERTIES.from_buffer_copy(raw)
        self.logger_name = name
        getattr(handle_ref, "_obj", handle_ref).value = self.handle
        return self.start_rc

    def OpenTraceW(self, addr):
        logfile = etw.EVENT_TRACE_LOGFILEW.from_address(addr)
        self.logfile_addr, self.logfile_mode = int(addr), int(logfile.ProcessTraceMode)
        self.logger_name = logfile.LoggerName
        return self.trace_handle

    def ProcessTrace(self, handles, count, start, end):
        self.processed.append(int(handles[0]))
        self.processing.set()
        assert self.released.wait(5), "the test never released ProcessTrace"
        return self.process_rc

    def CloseTrace(self, handle):
        self.closed.append(int(handle.value))
        return self.close_rc


def advapi(monkeypatch, **kwargs):
    """A real tnt.etw._Advapi bound to a FakeDll instead of advapi32."""
    dll = FakeDll(**kwargs)
    monkeypatch.setattr(etw, "_load_advapi32", lambda: dll)
    return etw._Advapi(), dll


def started(api=None, **kwargs):
    """A TraceSession on a fake seam that has already started."""
    api = api if api is not None else FakeApi()
    session = TraceSession("TNT-Capture-test", api=api, **kwargs)
    session.start()
    return session, api


# --------------------------------------------------------------------------- the native layout
def test_the_documented_sizes_are_the_ones_the_module_promises():
    """The table itself, on any platform: the measurement below needs a Windows x64 build."""
    assert set(STRUCT_SIZES) == {"GUID", "WNODE_HEADER", "EVENT_TRACE_PROPERTIES", "EVENT_TRACE_HEADER",
                                 "ETW_BUFFER_CONTEXT", "EVENT_TRACE", "SYSTEMTIME", "TIME_ZONE_INFORMATION",
                                 "TRACE_LOGFILE_HEADER", "EVENT_DESCRIPTOR", "EVENT_HEADER", "EVENT_RECORD",
                                 "EVENT_TRACE_LOGFILEW", "ENABLE_TRACE_PARAMETERS"}
    assert STRUCT_SIZES == {"GUID": 16, "WNODE_HEADER": 48, "EVENT_TRACE_PROPERTIES": 120, "EVENT_TRACE_HEADER": 48,
                            "ETW_BUFFER_CONTEXT": 4, "EVENT_TRACE": 88, "SYSTEMTIME": 16,
                            "TIME_ZONE_INFORMATION": 172, "TRACE_LOGFILE_HEADER": 280, "EVENT_DESCRIPTOR": 16,
                            "EVENT_HEADER": 80, "EVENT_RECORD": 112, "EVENT_TRACE_LOGFILEW": 448,
                            "ENABLE_TRACE_PARAMETERS": 48}


@x64_only
def test_every_structure_has_its_documented_x64_size():
    """A mis-declared field is caught here, before it corrupts memory at run time."""
    for name, size in STRUCT_SIZES.items():
        assert ctypes.sizeof(getattr(etw, name)) == size, name


@x64_only
@pytest.mark.parametrize("structure, field, offset", [
    ("EVENT_TRACE_PROPERTIES", "LoggerThreadId", 104),        # the HANDLE that makes the structure 120 bytes
    ("EVENT_TRACE_PROPERTIES", "LoggerNameOffset", 116),
    ("EVENT_HEADER", "TimeStamp", 16),
    ("EVENT_HEADER", "EventDescriptor", 40),
    ("EVENT_RECORD", "UserDataLength", 86),
    ("EVENT_RECORD", "UserData", 96),
    ("TRACE_LOGFILE_HEADER", "BootTime", 248),                # the 172-byte time zone ends at 244: padded to 248
    ("EVENT_TRACE_LOGFILEW", "LogfileHeader", 120),
    ("EVENT_TRACE_LOGFILEW", "EventRecordCallback", 424),
])
def test_the_fields_this_module_reads_sit_where_the_headers_put_them(structure, field, offset):
    assert getattr(getattr(etw, structure), field).offset == offset


def test_a_provider_guid_is_built_in_the_byte_order_windows_reads_it():
    """The one thing a round trip cannot see: _guid_struct and _guid_text could both be wrong the same way and still
    agree with each other, while EnableTraceEx2 was handed a byte-swapped GUID and enabled the wrong provider."""
    guid = etw._guid_struct(NDIS_PACKET_CAPTURE_GUID)
    assert (guid.Data1, guid.Data2, guid.Data3) == (0x2ED6006E, 0x4729, 0x4609)
    assert bytes(guid.Data4) == bytes.fromhex("B4233EE7BCD678EF")
    assert bytes(guid) == bytes.fromhex("6E00D62E29470946B4233EE7BCD678EF")   # the little-endian memory layout
    assert bytes(guid)[:4] == b"\x6e\x00\xd6\x2e"
    assert bytes(guid) != uuid.UUID(NDIS_PACKET_CAPTURE_GUID).bytes           # ... which is not the text order
    assert etw._guid_text(guid) == NDIS_PACKET_CAPTURE_GUID                   # and it still reads back
    assert bytes(etw._guid_struct("{" + NDIS_PACKET_CAPTURE_GUID.lower() + "}")) == bytes(guid)
    assert etw._guid_struct("not-a-guid") is None and etw._guid_text(b"short") is None


def test_the_key_tuples_are_the_documented_order():
    assert EVENT_KEYS == ("provider", "event_id", "ts", "data")
    assert FRAME_KEYS == ("ts", "if_index", "lower_if", "data", "origlen")
    assert STATS_KEYS == ("events", "lost_events", "callback_errors", "buffers_read", "started_ts")
    assert CONTROL_STATS_KEYS == ("events_lost", "buffers_written", "real_time_buffers_lost")
    assert AVAILABILITY_KEYS == ("ok", "reason")
    assert (DEFAULT_BUFFER_KB, DEFAULT_MIN_BUFFERS, DEFAULT_MAX_BUFFERS, FLUSH_TIMER_S) == (64, 16, 256, 1)
    assert (MAX_FRAME, HEADER_LEN, SESSION_PREFIX) == (65536, 12, "TNT-Capture")


def test_the_event_callback_reads_a_record_the_way_the_headers_describe_it():
    """Built and called in this process: no session, no provider, no DLL. It proves the EVENT_HEADER offsets."""
    seen = []
    callback = etw._Advapi._event_callback(seen.append)
    user_data = ctypes.create_string_buffer(payload(), len(payload()))
    record = etw.EVENT_RECORD()
    record.EventHeader.TimeStamp = FILETIME
    record.EventHeader.ProviderId = etw._guid_struct(NDIS_PACKET_CAPTURE_GUID)
    record.EventHeader.EventDescriptor.Id = 1001
    record.UserData = ctypes.cast(user_data, ctypes.c_void_p)
    record.UserDataLength = len(payload())

    callback(ctypes.pointer(record))

    [got] = seen
    assert tuple(got) == EVENT_KEYS
    assert got["provider"] == NDIS_PACKET_CAPTURE_GUID and got["event_id"] == 1001
    assert got["ts"] == pytest.approx(TS, abs=1e-6)
    assert got["data"] == payload()
    assert decode_ndis_frame(got)["data"] == FRAME


def test_the_event_callback_swallows_an_empty_record_and_a_handler_that_raises():
    seen = []

    def angry(evt):
        seen.append(evt)
        raise RuntimeError("the handler is broken")

    callback = etw._Advapi._event_callback(angry)
    record = etw.EVENT_RECORD()                      # no user data at all: a zero length and a null pointer
    callback(ctypes.pointer(record))                 # must not raise out of a ctypes callback
    assert seen[0]["data"] == b"" and seen[0]["ts"] == 0.0


def test_the_buffer_callback_reports_the_counters_and_passes_the_answer_back():
    seen = []
    callback = etw._Advapi._buffer_callback(lambda info: seen.append(info) or len(seen) < 2)
    logfile = etw.EVENT_TRACE_LOGFILEW()
    logfile.BuffersRead, logfile.EventsLost = 12, 3
    assert callback(ctypes.addressof(logfile)) == 1          # the handler said carry on
    assert callback(ctypes.addressof(logfile)) == 0          # ... and then said stop
    assert seen == [{"buffers_read": 12, "events_lost": 3}] * 2
    angry = etw._Advapi._buffer_callback(lambda info: (_ for _ in ()).throw(RuntimeError("broken")))
    assert angry(ctypes.addressof(logfile)) == 1             # a broken handler never ends the capture


# --------------------------------------------------------------------------- the real advapi32 seam (on a fake DLL)
def test_the_seam_fills_in_the_properties_and_starts_a_session(monkeypatch):
    """_Advapi.start_trace really runs: the properties helper must not be shadowed by an instance attribute."""
    api, dll = advapi(monkeypatch)

    rc, handle = api.start_trace("TNT-Capture-test", buffer_kb=64, min_buffers=16, max_buffers=256, flush_timer_s=1)

    assert (rc, handle) == (ERROR_SUCCESS, dll.handle)
    props = dll.properties
    assert (props.BufferSize, props.MinimumBuffers, props.MaximumBuffers, props.FlushTimer) == (64, 16, 256, 1)
    assert props.LogFileMode == etw.EVENT_TRACE_REAL_TIME_MODE
    assert props.LogFileNameOffset == 0                  # no log file: a real offset with an empty name would fail
    assert props.LoggerNameOffset == ctypes.sizeof(etw.EVENT_TRACE_PROPERTIES)
    assert props.Wnode.BufferSize == ctypes.sizeof(etw.EVENT_TRACE_PROPERTIES) + 2 * etw.TRACE_NAME_BYTES
    assert props.Wnode.Flags == etw.WNODE_FLAG_TRACED_GUID and props.Wnode.ClientContext == 1
    # a second session on the same seam is built the same way: StartTraceW copied the first, nothing is kept
    assert api.start_trace("TNT-Capture-two", buffer_kb=8, min_buffers=2, max_buffers=4,
                           flush_timer_s=2) == (ERROR_SUCCESS, dll.handle)
    assert dll.properties.BufferSize == 8


def test_the_trace_is_opened_for_converted_timestamps_and_not_raw_clock_ticks(monkeypatch):
    """EVENT_HEADER.TimeStamp is a FILETIME only because RAW_TIMESTAMP is off; _unix_ts would land in 1601 with it."""
    api, dll = advapi(monkeypatch)

    rc, handle = api.open_trace("TNT-Capture-test", lambda evt: None, lambda info: True)

    assert (rc, handle) == (ERROR_SUCCESS, dll.trace_handle)
    assert dll.logfile_mode == etw.PROCESS_TRACE_MODE_REAL_TIME | etw.PROCESS_TRACE_MODE_EVENT_RECORD
    assert not dll.logfile_mode & etw.PROCESS_TRACE_MODE_RAW_TIMESTAMP
    assert dll.logger_name == "TNT-Capture-test"


def test_close_trace_keeps_the_callbacks_alive_until_process_trace_has_drained(monkeypatch):
    """CloseTrace on a real-time consumer answers ERROR_CTX_CLOSE_PENDING and ProcessTrace keeps calling back, so
    nothing the kernel can still reach may be dropped until that call has returned."""
    api, dll = advapi(monkeypatch)
    rc, handle = api.open_trace("TNT-Capture-test", lambda evt: None, lambda info: True)
    assert rc == ERROR_SUCCESS
    kept = api._open[handle]["objects"]
    assert ctypes.addressof(kept[0]) == dll.logfile_addr          # the very structure ETW writes its counters into
    answers = []
    thread = threading.Thread(target=lambda: answers.append(api.process_trace(handle)), daemon=True)
    thread.start()
    assert dll.processing.wait(2) and dll.processed == [handle]

    assert api.close_trace(handle) == ERROR_CTX_CLOSE_PENDING     # the real answer for a consumer still draining

    assert dll.closed == [handle]
    assert api._open[handle]["objects"] is kept                   # still referenced: ProcessTrace has not returned
    dll.released.set()
    thread.join(5)
    assert answers == [ERROR_SUCCESS] and not thread.is_alive()
    assert api._open == {}                                        # ... and let go the moment it did


def test_a_trace_nobody_ever_read_is_let_go_at_the_close(monkeypatch):
    api, dll = advapi(monkeypatch)
    rc, handle = api.open_trace("TNT-Capture-test", lambda evt: None, lambda info: True)
    assert rc == ERROR_SUCCESS and handle in api._open

    assert api.close_trace(handle) == ERROR_CTX_CLOSE_PENDING

    assert api._open == {}
    assert api.process_trace(handle) == ERROR_INVALID_HANDLE      # its callbacks are gone: it must not be processed
    assert dll.processed == []


# --------------------------------------------------------------------------- available() and session_name()
def test_available_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert available() == {"ok": False, "reason": NOT_WINDOWS_REASON}
    assert tuple(available()) == AVAILABILITY_KEYS


def test_available_without_the_tracing_api_or_without_admin_rights(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(etw, "_api_available", lambda: False)
    monkeypatch.setattr(etw, "_is_admin", lambda: True)
    assert available() == {"ok": False, "reason": NO_API_REASON}
    monkeypatch.setattr(etw, "_api_available", lambda: True)
    monkeypatch.setattr(etw, "_is_admin", lambda: False)
    assert available() == {"ok": False, "reason": NOT_ADMIN_REASON}


def test_available_says_yes_for_an_administrator_and_for_an_unknown_answer(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(etw, "_api_available", lambda: True)
    for answer in (True, None):                              # LocalSystem: the check may not be able to tell
        monkeypatch.setattr(etw, "_is_admin", lambda: answer)
        assert available() == {"ok": True, "reason": None}


@pytest.mark.parametrize("suffix, expected", [
    ("", "TNT-Capture"),
    ("eth0", "TNT-Capture-eth0"),
    ("Wi-Fi 2", "TNT-Capture-Wi-Fi2"),
    ("a/b\\c:*?", "TNT-Capture-abc"),
    ("***", "TNT-Capture"),
    ("x" * 80, "TNT-Capture-" + "x" * 32),
    (None, "TNT-Capture"),
])
def test_session_name_keeps_only_safe_characters(suffix, expected):
    assert session_name(suffix) == expected


# --------------------------------------------------------------------------- start()
def test_start_creates_the_session_and_enables_every_provider():
    api = FakeApi()
    session = TraceSession("TNT-Capture-test", providers=[(NDIS_PACKET_CAPTURE_GUID, 5, 0xFF)], api=api)
    assert session.running is False
    assert session.stats() == {"events": 0, "lost_events": 0, "callback_errors": 0, "buffers_read": 0,
                               "started_ts": None}

    session.start()

    assert api.calls == [("start_trace", "TNT-Capture-test", 64, 16, 256, 1),
                         ("enable_trace", 0x1234, NDIS_PACKET_CAPTURE_GUID, 5, 0xFF)]
    assert session.running is True
    stats = session.stats()
    assert tuple(stats) == STATS_KEYS and stats["started_ts"] > 0
    session.stop()
    assert session.running is False


def test_start_stops_a_session_left_behind_and_tries_again():
    api = FakeApi(start_rcs=[ERROR_ALREADY_EXISTS, ERROR_SUCCESS])
    session = TraceSession("TNT-Capture-test", api=api)
    session.start()
    assert api.names() == ["start_trace", "control_trace", "start_trace"]
    assert api.calls[1] == ("control_trace", 0, "TNT-Capture-test", etw.EVENT_TRACE_CONTROL_STOP)
    assert session.running is True


def test_a_name_that_still_exists_after_the_retry_fails():
    api = FakeApi(start_rcs=[ERROR_ALREADY_EXISTS, ERROR_ALREADY_EXISTS])
    with pytest.raises(EtwError, match=r"could not start \(error 183\)"):
        TraceSession("TNT-Capture-test", api=api).start()


def test_start_access_denied_says_tnt_must_run_as_a_service():
    api = FakeApi(start_rcs=[ERROR_ACCESS_DENIED])
    with pytest.raises(EtwError) as caught:
        TraceSession("TNT-Capture-test", api=api).start()
    assert str(caught.value) == ACCESS_DENIED_TEXT
    assert "service" in str(caught.value) and "access denied" in str(caught.value)


def test_a_provider_that_cannot_be_enabled_stops_the_session_again():
    api = FakeApi(enable_rc=ERROR_ACCESS_DENIED)
    session = TraceSession("TNT-Capture-test", providers=[(NDIS_PACKET_CAPTURE_GUID, 4, 0)], api=api)
    with pytest.raises(EtwError, match="must run as a service"):
        session.start()
    assert api.names() == ["start_trace", "enable_trace", "control_trace"]
    assert api.calls[-1][3] == etw.EVENT_TRACE_CONTROL_STOP
    assert session.running is False

    api = FakeApi(enable_rc=87)
    with pytest.raises(EtwError, match=r"provider could not be enabled \(error 87\)"):
        TraceSession("TNT-Capture-test", providers=[(NDIS_PACKET_CAPTURE_GUID, 4, 0)], api=api).start()


def test_starting_twice_raises_and_leaves_one_session():
    session, api = started()
    with pytest.raises(EtwError, match="already started"):
        session.start()
    assert api.names().count("start_trace") == 1


def test_the_constructor_clamps_the_buffer_numbers_and_refuses_a_bad_name_or_guid():
    session = TraceSession("TNT-Capture-test", buffer_kb=0, min_buffers=1, max_buffers=4, flush_timer_s=9999,
                           api=FakeApi())
    assert (session.buffer_kb, session.min_buffers, session.max_buffers, session.flush_timer_s) == (4, 2, 4, 60)
    huge = TraceSession("TNT-Capture-test", buffer_kb=1 << 20, min_buffers=900, max_buffers=4, api=FakeApi())
    assert (huge.buffer_kb, huge.min_buffers, huge.max_buffers) == (1024, 900, 900)   # never under the minimum
    bad = TraceSession("TNT-Capture-test", buffer_kb="lots", flush_timer_s=None, api=FakeApi())
    assert (bad.buffer_kb, bad.flush_timer_s) == (DEFAULT_BUFFER_KB, FLUSH_TIMER_S)
    for name in ("", "   ", "x" * 201, None):
        with pytest.raises(ValueError, match="session name"):
            TraceSession(name, api=FakeApi())
    with pytest.raises(ValueError, match="provider GUID"):
        TraceSession("TNT-Capture-test", providers=[("not-a-guid", 5, 0)], api=FakeApi())


def test_an_infinite_or_nan_buffer_number_clamps_instead_of_raising():
    """json.loads reads the bare literals Infinity and NaN, so either can reach the constructor; int() refuses both."""
    session = TraceSession("TNT-Capture-test", buffer_kb=float("inf"), min_buffers=float("-inf"),
                           max_buffers=float("inf"), flush_timer_s=float("nan"), api=FakeApi())
    assert (session.buffer_kb, session.min_buffers, session.max_buffers) == (1024, 2, 1024)
    assert session.flush_timer_s == FLUSH_TIMER_S        # a NaN is not a number at all: the default
    assert etw._clamp(float("-inf"), "flush_timer_s", FLUSH_TIMER_S) == 1
    assert etw._clamp(float("nan"), "buffer_kb", DEFAULT_BUFFER_KB) == DEFAULT_BUFFER_KB
    assert etw._clamp(10 ** 400, "buffer_kb", DEFAULT_BUFFER_KB) == 1024      # a whole number no float could hold


# --------------------------------------------------------------------------- consume()
def test_consume_delivers_events_to_the_callback():
    session, api = started()
    seen = []
    session.consume(seen.append)
    assert api.processing.wait(2)
    assert api.names() == ["start_trace", "open_trace", "process_trace"]
    assert CONSUMER_THREAD_NAME in {t.name for t in threading.enumerate()}

    first, second = event(), event(payload(FRAME[:20], fragment_size=len(FRAME)), event_id=1002)
    api.on_event(first)
    api.on_event(second)

    assert seen == [first, second]
    assert session.stats()["events"] == 2 and session.stats()["callback_errors"] == 0
    session.stop()
    assert CONSUMER_THREAD_NAME not in {t.name for t in threading.enumerate() if t.is_alive()}


def test_a_callback_that_raises_is_counted_and_never_kills_the_consumer():
    session, api = started()
    seen = []

    def sometimes_angry(evt):
        seen.append(evt)
        if evt["event_id"] == 1001:
            raise ValueError("this callback is broken")

    session.consume(sometimes_angry)
    assert api.processing.wait(2)
    for event_id in (1001, 1001, 1002):
        api.on_event(event(event_id=event_id))          # none of these may raise out to the consumer
    assert [e["event_id"] for e in seen] == [1001, 1001, 1002]
    assert session.stats() == dict(session.stats(), events=3, callback_errors=2)
    api.on_event(event(event_id=1002))
    assert session.stats()["events"] == 4 and session.stats()["callback_errors"] == 2
    session.stop()


def test_the_buffer_callback_counts_and_stops_the_consumer_once_the_session_is_stopping():
    session, api = started(FakeApi(stats={"events_lost": 41, "buffers_written": 7, "real_time_buffers_lost": 2}))
    session.consume(lambda evt: None)
    assert api.processing.wait(2)
    assert api.on_buffer({"buffers_read": 9, "events_lost": 4}) is True
    assert api.on_buffer({"buffers_read": 3, "events_lost": 1}) is True       # counters never go backwards
    assert api.on_buffer({}) is True
    assert api.on_buffer("rubbish") is True
    stats = session.stats()
    assert (stats["buffers_read"], stats["lost_events"]) == (9, 4)

    session.stop()

    assert api.on_buffer({"buffers_read": 9, "events_lost": 4}) is False      # stopping: the consumer may end
    assert session.stats()["lost_events"] == 41                              # what ControlTraceW wrote back


def test_consume_needs_a_started_session_and_runs_once():
    api = FakeApi()
    session = TraceSession("TNT-Capture-test", api=api)
    with pytest.raises(EtwError, match="not running"):
        session.consume(lambda evt: None)
    session.start()
    session.consume(lambda evt: None)
    assert api.processing.wait(2)
    with pytest.raises(EtwError, match="already delivering"):
        session.consume(lambda evt: None)
    assert api.names().count("open_trace") == 1
    session.stop()
    with pytest.raises(EtwError, match="not running"):
        session.consume(lambda evt: None)


@pytest.mark.parametrize("api, match", [
    (FakeApi(open_rc=ERROR_ACCESS_DENIED), "must run as a service"),
    (FakeApi(open_rc=1168), r"opened for reading \(error 1168\)"),
    (FakeApi(trace_handle=0), r"opened for reading \(error 1\)"),
    (FakeApi(trace_handle=etw.INVALID_PROCESSTRACE_HANDLE), r"opened for reading \(error 1\)"),
], ids=["access_denied", "error_code", "null_handle", "invalid_handle"])
def test_consume_raises_when_the_trace_cannot_be_opened(api, match):
    session = TraceSession("TNT-Capture-test", api=api)
    session.start()
    with pytest.raises(EtwError, match=match):
        session.consume(lambda evt: None)
    assert "process_trace" not in api.names()
    session.stop()


# --------------------------------------------------------------------------- stop()
def test_stop_closes_the_trace_joins_the_thread_and_stops_the_session():
    session, api = started()
    session.consume(lambda evt: None)
    assert api.processing.wait(2)

    session.stop()

    assert api.names() == ["start_trace", "open_trace", "process_trace", "close_trace", "control_trace"]
    assert api.calls[-2] == ("close_trace", 0x99)
    assert api.calls[-1] == ("control_trace", 0x1234, "TNT-Capture-test", etw.EVENT_TRACE_CONTROL_STOP)
    assert session.running is False


def test_stop_is_idempotent_and_never_raises():
    session, api = started()
    session.consume(lambda evt: None)
    assert api.processing.wait(2)
    session.stop()
    before = list(api.calls)
    session.stop()
    session.stop(timeout=0.0)
    assert api.calls == before
    # a session that was never started asks the seam for nothing at all
    quiet = FakeApi()
    TraceSession("TNT-Capture-test", api=quiet).stop()
    assert quiet.calls == []


def test_stop_survives_a_seam_that_raises_everywhere():
    class BrokenApi(FakeApi):
        def close_trace(self, handle):
            self.released.set()
            raise OSError("CloseTrace is broken")

        def control_trace(self, handle, name, code):
            raise OSError("ControlTraceW is broken")

    api = BrokenApi()
    session = TraceSession("TNT-Capture-test", api=api)
    session.start()                                   # start_trace answers before control_trace is ever needed
    session.consume(lambda evt: None)
    assert api.processing.wait(2)
    session.stop()                                    # never raises
    assert session.running is False


def test_a_failed_control_trace_at_the_stop_leaves_the_counters_alone():
    session, api = started(FakeApi(control_rc=ERROR_WMI_INSTANCE_NOT_FOUND, stats={"events_lost": 99}))
    session.consume(lambda evt: None)
    assert api.processing.wait(2)
    api.on_buffer({"buffers_read": 2, "events_lost": 5})
    session.stop()
    assert session.stats()["lost_events"] == 5


# --------------------------------------------------------------------------- stop_stale_sessions()
def test_stop_stale_sessions_stops_only_the_names_that_were_really_there():
    api = FakeApi(control_rc=ERROR_WMI_INSTANCE_NOT_FOUND,
                  control_rcs={"TNT-Capture": ERROR_SUCCESS, "TNT-Capture-3": ERROR_SUCCESS,
                               "TNT-Capture-5": ERROR_ACCESS_DENIED})

    assert stop_stale_sessions(api=api) == 2

    tried = [call[2] for call in api.calls]
    assert tried == [SESSION_PREFIX] + [f"{SESSION_PREFIX}-{n}" for n in range(1, MAX_STALE_NAMES)]
    assert len(tried) == MAX_STALE_NAMES
    assert {call[3] for call in api.calls} == {etw.EVENT_TRACE_CONTROL_STOP}


def test_stop_stale_sessions_takes_a_prefix_and_never_raises():
    api = FakeApi(control_rc=ERROR_SUCCESS)
    assert stop_stale_sessions("TNT-Other", api=api) == MAX_STALE_NAMES
    assert api.calls[0][2] == "TNT-Other" and api.calls[-1][2] == f"TNT-Other-{MAX_STALE_NAMES - 1}"
    assert stop_stale_sessions("   ", api=api) == 0

    class BrokenApi(FakeApi):
        def control_trace(self, handle, name, code):
            raise OSError("ControlTraceW is broken")

    assert stop_stale_sessions(api=BrokenApi()) == 0


# --------------------------------------------------------------------------- decode_ndis_frame()
def test_decode_reads_the_three_header_fields_and_the_frame():
    frame = decode_ndis_frame(event())
    assert tuple(frame) == FRAME_KEYS
    assert frame == {"ts": TS, "if_index": IF_INDEX, "lower_if": LOWER_IF, "data": FRAME, "origlen": len(FRAME)}
    lower = decode_ndis_frame(event(payload(if_index=7, lower_if=21)))
    assert (lower["if_index"], lower["lower_if"]) == (7, 21)


@pytest.mark.parametrize("event_id", [1001, 1002, 1003])
def test_every_packet_event_id_decodes(event_id):
    assert decode_ndis_frame(event(event_id=event_id))["data"] == FRAME


@pytest.mark.parametrize("size", list(range(0, HEADER_LEN)) + [HEADER_LEN])
def test_a_payload_that_ends_inside_the_header_is_not_a_frame(size):
    """0 to 11 bytes is too short for the header; exactly 12 is a header claiming a frame that is not there."""
    assert decode_ndis_frame(event(payload()[:size])) is None


def test_the_smallest_payload_that_is_still_a_frame():
    """HEADER_LEN + 1 bytes: the header and one byte of frame behind it, the first length that is not refused."""
    smallest = struct.pack("<III", IF_INDEX, LOWER_IF, 1) + b"\xff"
    assert len(smallest) == HEADER_LEN + 1
    frame = decode_ndis_frame(event(smallest))
    assert frame["data"] == b"\xff" and frame["origlen"] == 1
    assert (frame["if_index"], frame["lower_if"]) == (IF_INDEX, LOWER_IF)
    claims_more = struct.pack("<III", IF_INDEX, LOWER_IF, 4000) + b"\xff"     # the same byte, a header claiming 4000
    clamped = decode_ndis_frame(event(claims_more))
    assert clamped["data"] == b"\xff" and clamped["origlen"] == 4000


def test_a_fragment_size_longer_than_the_payload_is_clamped_and_origlen_keeps_the_claim():
    frame = decode_ndis_frame(event(payload(FRAME[:20], fragment_size=len(FRAME))))
    assert frame["data"] == FRAME[:20] and frame["origlen"] == len(FRAME)
    silly = decode_ndis_frame(event(payload(FRAME, fragment_size=MAX_FRAME)))
    assert silly["data"] == FRAME and silly["origlen"] == MAX_FRAME
    assert len(silly["data"]) < silly["origlen"]


@pytest.mark.parametrize("fragment_size", [MAX_FRAME + 1, 0x7FFFFFFF, 0xFFFFFFFF, 0])
def test_a_fragment_size_over_the_cap_or_of_nothing_is_refused(fragment_size):
    assert decode_ndis_frame(event(payload(FRAME, fragment_size=fragment_size))) is None


def test_the_cap_itself_is_still_a_frame():
    big = decode_ndis_frame(event(struct.pack("<III", IF_INDEX, 0, MAX_FRAME) + bytes(MAX_FRAME)))
    assert big["origlen"] == MAX_FRAME and len(big["data"]) == MAX_FRAME


@pytest.mark.parametrize("bad", [
    {"provider": "11111111-2222-3333-4444-555555555555", "event_id": 1001, "ts": TS, "data": payload()},
    {"provider": NDIS_PACKET_CAPTURE_GUID, "event_id": 2001, "ts": TS, "data": payload()},
    {"provider": NDIS_PACKET_CAPTURE_GUID, "event_id": None, "ts": TS, "data": payload()},
    {"provider": NDIS_PACKET_CAPTURE_GUID, "event_id": True, "ts": TS, "data": payload()},
    {"provider": NDIS_PACKET_CAPTURE_GUID, "event_id": 1001, "ts": TS, "data": payload().hex()},
    {"provider": NDIS_PACKET_CAPTURE_GUID, "event_id": 1001, "ts": TS, "data": None},
    {"provider": NDIS_PACKET_CAPTURE_GUID, "event_id": 1001, "ts": TS},
    {},
], ids=["other_provider", "other_event_id", "no_event_id", "bool_event_id", "text_payload", "no_payload",
        "payload_missing", "empty"])
def test_an_event_that_is_not_an_ndis_packet_is_not_decoded(bad):
    assert decode_ndis_frame(bad) is None


@pytest.mark.parametrize("junk", [None, b"", "an event", 7, [payload()], (1, 2)])
def test_garbage_in_place_of_an_event_is_not_decoded(junk):
    assert decode_ndis_frame(junk) is None


def test_the_provider_may_be_missing_or_written_any_way_round():
    assert decode_ndis_frame(event(provider=None))["data"] == FRAME
    assert decode_ndis_frame(event(provider="{" + NDIS_PACKET_CAPTURE_GUID.lower() + "}"))["data"] == FRAME
    assert decode_ndis_frame(event(provider="rubbish")) is None


def test_a_missing_or_silly_timestamp_reads_as_zero():
    assert decode_ndis_frame(event(ts=None))["ts"] == 0.0
    assert decode_ndis_frame(event(ts="lunchtime"))["ts"] == 0.0
    assert decode_ndis_frame(event(ts=True))["ts"] == 0.0
    assert decode_ndis_frame(event(ts=0))["ts"] == 0.0
    assert decode_ndis_frame(event(ts=3))["ts"] == 3.0


def test_a_timestamp_no_float_can_hold_reads_as_zero_instead_of_raising():
    """decode_ndis_frame answers None or a FRAME dict; a silly ts must never raise out of the consumer thread."""
    assert decode_ndis_frame(event(ts=10 ** 400))["ts"] == 0.0        # float() of this raises OverflowError
    assert decode_ndis_frame(event(ts=-(10 ** 400)))["ts"] == 0.0
    assert decode_ndis_frame(event(ts=float("nan")))["ts"] == 0.0
    assert decode_ndis_frame(event(ts=float("inf")))["ts"] == float("inf")   # a real float: it is passed through


@pytest.mark.parametrize("filetime, expected", [
    (FILETIME, TS),
    (0, 0.0),                                   # 1601-01-01: before the epoch, so 0
    (116_444_736_000_000_000, 0.0),             # exactly the epoch
    (116_444_736_000_000_000 + 10_000_000, 1.0),
    (-5, 0.0),
    ("not a time", 0.0),
    (None, 0.0),
])
def test_the_filetime_conversion(filetime, expected):
    assert etw._unix_ts(filetime) == pytest.approx(expected, abs=1e-6)
