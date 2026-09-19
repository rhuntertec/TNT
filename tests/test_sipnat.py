"""tnt.sipnat: STUN, and what this network's NAT does to the ports voice depends on.

The checks run against fake STUN servers on loopback - one that answers honestly, one that reports a different
external port per server the way symmetric NAT does, and one that says nothing. Nothing here leaves the machine.
"""
from __future__ import annotations

import socket
import struct
import threading
from typing import Any, Dict, List, Optional

import pytest

from tnt import sipnat
from tnt.sipnat import (DEFAULT_SERVERS, FINDING_IDS, FINDING_KEYS, LIFETIME_KEYS, MAGIC_COOKIE, MAPPINGS,
                        SERVER_KEYS, STEP_KEYS, STUN_KEYS, StunChecker, build_binding_request,
                        parse_binding_response, validate_server)


# --------------------------------------------------------------------------- a STUN server on loopback
class FakeStun:
    """Answers a Binding Request with an XOR-MAPPED-ADDRESS. `mapped` fixes what it claims to have seen, which is
    how a symmetric NAT is simulated: two servers reporting two different ports for one socket."""

    def __init__(self, *, mapped: Optional[tuple] = None, silent: bool = False, plain: bool = False) -> None:
        self.mapped, self.silent, self.plain = mapped, silent, plain
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.asked = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            if len(data) < 20 or self.silent:
                continue
            self.asked += 1
            transaction = data[8:20]
            ip, port = self.mapped or peer
            self.sock.sendto(self._reply(transaction, ip, port), peer)

    def _reply(self, transaction: bytes, ip: str, port: int) -> bytes:
        packed = bytes(int(x) for x in ip.split("."))
        if self.plain:                                   # the pre-RFC-5389 MAPPED-ADDRESS some servers still send
            value = bytes([0, 0x01]) + struct.pack(">H", port) + packed
            attr = struct.pack(">HH", 0x0001, len(value)) + value
        else:
            xor_port = port ^ (MAGIC_COOKIE >> 16)
            key = struct.pack(">I", MAGIC_COOKIE)
            value = bytes([0, 0x01]) + struct.pack(">H", xor_port) + bytes(a ^ b for a, b in zip(packed, key))
            attr = struct.pack(">HH", 0x0020, len(value)) + value
        return struct.pack(">HHI", 0x0101, len(attr), MAGIC_COOKIE) + transaction + attr

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture
def stun():
    made: List[FakeStun] = []

    def make(**kwargs: Any) -> FakeStun:
        server = FakeStun(**kwargs)
        made.append(server)
        return server
    yield make
    for server in made:
        server.close()


def _pair(servers) -> List[tuple]:
    return [("127.0.0.1", server.port) for server in servers]


# --------------------------------------------------------------------------- the protocol
def test_a_binding_request_is_twenty_bytes_and_carries_its_own_identity():
    request, transaction = build_binding_request()
    assert len(request) == 20 and len(transaction) == 12
    kind, length, cookie = struct.unpack_from(">HHI", request, 0)
    assert (kind, length, cookie) == (0x0001, 0, MAGIC_COOKIE)
    assert request[8:20] == transaction
    # fresh each time, so an answer to an earlier question cannot be read as this one's
    assert build_binding_request()[1] != transaction


def test_an_xor_mapped_address_is_unpacked():
    server = FakeStun(mapped=("203.0.113.9", 51234))
    try:
        request, transaction = build_binding_request()
        answer = parse_binding_response(server._reply(transaction, "203.0.113.9", 51234), transaction)
        assert answer["address"] == "203.0.113.9" and answer["port"] == 51234
    finally:
        server.close()


def test_the_older_plain_mapped_address_is_read_too():
    server = FakeStun(plain=True)
    try:
        request, transaction = build_binding_request()
        answer = parse_binding_response(server._reply(transaction, "198.51.100.7", 40000), transaction)
        assert answer["address"] == "198.51.100.7" and answer["port"] == 40000
    finally:
        server.close()


def test_an_answer_to_someone_elses_question_is_ignored():
    """The transaction id exists so a stale reply cannot be mistaken for this probe's."""
    server = FakeStun()
    try:
        _request, mine = build_binding_request()
        _other, theirs = build_binding_request()
        reply = server._reply(theirs, "203.0.113.9", 1234)
        assert parse_binding_response(reply, mine) is None
        assert parse_binding_response(reply, theirs) is not None
    finally:
        server.close()


@pytest.mark.parametrize("payload", [b"", b"\x00" * 19, b"\x01\x01\x00\x00" + b"\x00" * 16])
def test_rubbish_is_none_not_an_exception(payload):
    assert parse_binding_response(payload, b"x" * 12) is None


def test_a_truncated_attribute_does_not_reach_past_the_end():
    _request, transaction = build_binding_request()
    head = struct.pack(">HHI", 0x0101, 40, MAGIC_COOKIE) + transaction
    assert parse_binding_response(head + struct.pack(">HH", 0x0020, 40) + b"\x00\x01", transaction) is None


# --------------------------------------------------------------------------- the address
@pytest.mark.parametrize("given,expected", [
    ("stun.example.com", ("stun.example.com", 3478)),
    ("stun.example.com:19302", ("stun.example.com", 19302)),
    ("stun:stun.example.com", ("stun.example.com", 3478)),
    ("[2001:db8::1]:3479", ("2001:db8::1", 3479)),
])
def test_a_stun_address_is_read(given, expected):
    assert validate_server(given) == expected


@pytest.mark.parametrize("bad", ["", "  ", "a b", "a/b", None])
def test_a_bad_stun_address_is_refused(bad):
    with pytest.raises(ValueError):
        validate_server(bad)


def test_the_default_pair_is_two_operators_not_two_names_for_one():
    """Symmetric NAT is found by comparing what two *different* servers saw. A pair behind one operator could
    resolve to the same host and answer 'endpoint-independent' for every network on earth."""
    assert len(DEFAULT_SERVERS) == 2
    hosts = {host.split(".", 1)[1] for host, _port in DEFAULT_SERVERS}
    assert len(hosts) == 2, DEFAULT_SERVERS


# --------------------------------------------------------------------------- the quick check
def test_one_port_for_both_servers_is_what_working_voice_looks_like(stun):
    servers = [stun(mapped=("203.0.113.9", 40001)), stun(mapped=("203.0.113.9", 40001))]
    result = StunChecker(timeout_s=1.5).check(_pair(servers))
    assert list(result) == list(STUN_KEYS)
    assert all(list(row) == list(SERVER_KEYS) for row in result["servers"])
    assert result["mapping"] == "endpoint-independent" and result["mapping"] in MAPPINGS
    assert result["public"] == "203.0.113.9"
    found = {f["id"]: f for f in result["findings"]}
    assert found["nat.cone"]["level"] == "good"
    assert all(f["id"] in FINDING_IDS and list(f) == list(FINDING_KEYS) for f in result["findings"])


def test_a_different_port_per_server_is_symmetric_nat(stun):
    """The classic one-way-audio network: the port a phone puts in its SDP only ever accepted traffic from whoever
    it first talked to, so the far end's RTP arrives somewhere that will not have it."""
    servers = [stun(mapped=("203.0.113.9", 40001)), stun(mapped=("203.0.113.9", 40002))]
    result = StunChecker(timeout_s=1.5).check(_pair(servers))
    assert result["mapping"] == "address-dependent"
    found = {f["id"]: f for f in result["findings"]}
    assert found["nat.symmetric"]["level"] == "bad"
    assert "one-way-audio" in found["nat.symmetric"]["advice"]
    assert "40001" in str(found["nat.symmetric"]["evidence"]) and "40002" in str(found["nat.symmetric"]["evidence"])


def test_one_server_answering_is_not_enough_to_judge_the_mapping(stun):
    servers = [stun(mapped=("203.0.113.9", 40001)), stun(silent=True)]
    result = StunChecker(timeout_s=1.0).check(_pair(servers))
    assert result["mapping"] == "unknown"
    assert result["public"] == "203.0.113.9"          # the address is known even so
    found = {f["id"]: f for f in result["findings"]}
    assert found["nat.unknown"]["level"] == "warn"
    assert "two different servers" in found["nat.unknown"]["detail"]


def test_nothing_answering_says_so_rather_than_passing(stun):
    servers = [stun(silent=True), stun(silent=True)]
    result = StunChecker(timeout_s=0.8).check(_pair(servers))
    assert result["mapping"] == "unknown"
    found = {f["id"]: f for f in result["findings"]}
    assert found["nat.silent"]["level"] == "warn"
    assert "blocked" not in found["nat.silent"]["title"].lower()


def test_no_translation_at_all_is_recognised(stun):
    """A PC on a routable address with its own port: nothing is translating, so nothing can mistranslate."""
    checker = StunChecker(timeout_s=1.5)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("", 0))
    mine = probe.getsockname()[1]
    probe.close()
    servers = [stun(mapped=("203.0.113.9", mine)), stun(mapped=("203.0.113.9", mine))]
    result = checker.check(_pair(servers), local_port=mine)
    if result["local_port"] != mine:
        pytest.skip("the port was taken between picking it and binding it")
    assert result["mapping"] == "none"
    assert {f["id"] for f in result["findings"]} >= {"nat.none"}


def test_the_port_it_really_used_is_always_reported(stun):
    servers = [stun(), stun()]
    checker = StunChecker(timeout_s=1.5)
    busy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    busy.bind(("", 0))
    taken = busy.getsockname()[1]
    try:
        result = checker.check(_pair(servers), local_port=taken)
        assert result["requested_port"] == taken
        assert result["bound"] is False and result["local_port"] != taken
        found = {f["id"]: f for f in result["findings"]}
        assert "could not be used" in found["nat.port"]["title"]
    finally:
        busy.close()


def test_a_bad_server_address_never_reaches_a_socket():
    with pytest.raises(ValueError):
        StunChecker().check(["   "])


# --------------------------------------------------------------------------- the slow one
def test_a_mapping_that_survives_every_step(stun, monkeypatch):
    monkeypatch.setattr(sipnat, "_sleep", lambda seconds: None)     # the waiting is the point, not the test
    server = stun(mapped=("203.0.113.9", 40001))
    result = StunChecker(timeout_s=1.5).lifetime(("127.0.0.1", server.port), steps=(15, 30))
    assert list(result) == list(LIFETIME_KEYS)
    assert all(list(step) == list(STEP_KEYS) for step in result["steps"])
    assert result["verdict"] == "long" and result["survived_s"] == 30 and result["lost_at_s"] is None
    found = {f["id"]: f for f in result["findings"]}
    assert found["nat.lifetime"]["level"] == "good"


def test_a_mapping_that_is_dropped_stops_at_the_step_that_lost_it(stun, monkeypatch):
    """Outbound calls work and inbound ones do not, for no visible reason, until this number is measured."""
    monkeypatch.setattr(sipnat, "_sleep", lambda seconds: None)
    server = stun(mapped=("203.0.113.9", 40001))
    calls = {"n": 0}
    real = server._reply

    def changing(transaction, ip, port):
        calls["n"] += 1
        return real(transaction, ip, 40001 if calls["n"] <= 2 else 40099)   # the NAT forgot it after the 2nd ask
    server._reply = changing
    result = StunChecker(timeout_s=1.5).lifetime(("127.0.0.1", server.port), steps=(15, 30, 60))
    assert result["verdict"] == "short"
    assert result["survived_s"] == 15 and result["lost_at_s"] == 30
    assert len(result["steps"]) == 2                    # it stopped at the first failure
    found = {f["id"]: f for f in result["findings"]}
    assert found["nat.lifetime-short"]["level"] == "bad"
    assert "registration interval" in found["nat.lifetime-short"]["advice"]


def test_a_lifetime_probe_that_never_got_a_mapping_says_so(stun, monkeypatch):
    monkeypatch.setattr(sipnat, "_sleep", lambda seconds: None)
    server = stun(silent=True)
    result = StunChecker(timeout_s=0.8).lifetime(("127.0.0.1", server.port), steps=(15,))
    assert result["verdict"] == "unknown" and result["steps"] == []
    found = {f["id"]: f for f in result["findings"]}
    assert found["nat.lifetime-unknown"]["level"] == "warn"


def test_the_quick_check_never_waits(stun, monkeypatch):
    """The lifetime probe is its own call precisely so the quick one stays quick."""
    def boom(seconds):
        raise AssertionError("the quick check slept")
    monkeypatch.setattr(sipnat, "_sleep", boom)
    servers = [stun(), stun()]
    StunChecker(timeout_s=1.0).check(_pair(servers))


def test_no_filtering_verdict_is_offered():
    """RFC 5780 filtering discovery needs the server to answer from another address on request, and most public
    ones ignore it. The RFC 3489 'NAT type' names are deprecated because they were reported anyway and were often
    wrong; this module reports what it measured and nothing else."""
    assert "full-cone" not in MAPPINGS and "restricted" not in MAPPINGS
    assert set(MAPPINGS) == {"endpoint-independent", "address-dependent", "none", "unknown"}
    assert not [name for name in FINDING_IDS if "filter" in name]


# --------------------------------------------------------------------------- driving it from a button
def test_the_result_is_kept_so_the_page_has_something_to_show(stun):
    checker = StunChecker(timeout_s=1.0)
    assert checker.last() is None and checker.running() is False
    result = checker.check([("127.0.0.1", stun().port), ("127.0.0.1", stun().port)])
    assert checker.last() == result

def test_the_kept_result_is_a_copy_a_caller_cannot_scribble_on(stun):
    checker = StunChecker(timeout_s=1.0)
    checker.check([("127.0.0.1", stun().port), ("127.0.0.1", stun().port)])
    checker.last()["mapping"] = "nonsense"
    assert checker.last()["mapping"] in MAPPINGS

def test_two_tests_at_once_are_refused(stun):
    """The comparison only means anything because one socket is used throughout; a second run would open another."""
    server = stun()
    checker = StunChecker(timeout_s=1.0)
    started = threading.Event()
    real_ask = checker._ask

    def slow_ask(*a: Any, **kw: Any) -> Any:
        started.set()
        import time as _t
        _t.sleep(0.4)
        return real_ask(*a, **kw)

    checker._ask = slow_ask                                         # type: ignore[assignment]
    worker = threading.Thread(target=lambda: checker.check([("127.0.0.1", server.port)] * 2))
    worker.start()
    try:
        started.wait(2.0)
        with pytest.raises(RuntimeError, match="already running"):
            checker.check([("127.0.0.1", server.port)] * 2)
    finally:
        worker.join(10.0)
    assert checker.running() is False

def test_the_lifetime_test_takes_the_same_guard(stun):
    """It holds a local port for minutes: a quick check starting underneath it would open its own and compare
    mappings that never belonged to the same socket."""
    server = stun()
    checker = StunChecker(timeout_s=1.0)
    started = threading.Event()
    monkey = sipnat._sleep

    def slow_sleep(seconds: float) -> None:
        started.set()
        monkey(0.4)

    sipnat._sleep = slow_sleep
    try:
        worker = threading.Thread(target=lambda: checker.lifetime(("127.0.0.1", server.port), steps=(1,)))
        worker.start()
        started.wait(2.0)
        with pytest.raises(RuntimeError, match="already running"):
            checker.check([("127.0.0.1", server.port)] * 2)
        worker.join(10.0)
    finally:
        sipnat._sleep = monkey
    assert checker.running() is False

def test_a_failed_test_does_not_leave_the_checker_stuck_busy():
    checker = StunChecker(timeout_s=1.0)
    with pytest.raises(ValueError):
        checker.check([("", None)] * 2)
    assert checker.running() is False

def test_a_network_change_drops_the_kept_result(stun):
    checker = StunChecker(timeout_s=1.0)
    checker.check([("127.0.0.1", stun().port), ("127.0.0.1", stun().port)])
    checker.on_network_change({"generation": 2})
    assert checker.last() is None
