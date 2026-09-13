"""Tests for tnt.portcheck: the port-forward test through portchecker.io, with Globalping as the fallback.

Offline: the checker's requests go to a scripted fake passed as ``request`` (for the whole session the real seam,
``tnt.portcheck._https_request``, is the tests/conftest.py guard), the HTTPS client itself runs against a fake
connection class, and time is a fake clock that only ``sleep`` and the fake requests move, so no test waits a real
retry, poll, refresh or deadline.  Addresses are documentation ranges (RFC 5737, RFC 3849).
"""
from __future__ import annotations

import http.client
import json
import logging
import socket
import ssl
import threading
import time
from types import SimpleNamespace

import pytest

import tnt
from tnt import portcheck as pc

T0 = 1_700_000_000.0            # wall clock of the link map's public address lookup
IP = "203.0.113.5"
OTHER_IP = "198.51.100.23"
UA = f"TNT/{tnt.__version__}"
MEASUREMENT = "gp0000demo01"
PORTCHECKER_JSON = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": UA}


class FakeTime:
    """``monotonic()`` and ``sleep()`` over one counter; only ``sleep`` and the fake requests move it."""

    def __init__(self, start=500.0):
        self.now = start
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class FakeNet:
    """Stands in for ``_https_request``: pops a scripted answer per endpoint and records every call.

    An answer is ``(status, obj)`` (obj is JSON-encoded unless it is bytes), ``(status, obj, cost_s)`` (the fake clock
    moves on by ``cost_s`` while the request runs) or an exception instance to raise."""

    def __init__(self, t, portchecker=(), create=(), poll=()):
        self.t = t
        self.queues = {"portchecker": list(portchecker), "create": list(create), "poll": list(poll)}
        self.calls = []

    def __call__(self, method, host, path, body, timeout, headers):
        if (method, host, path) == ("POST", "portchecker.io", "/api/query"):
            kind = "portchecker"
        elif (method, host, path) == ("POST", "api.globalping.io", "/v1/measurements"):
            kind = "create"
        elif method == "GET" and host == "api.globalping.io" and path.startswith("/v1/measurements/"):
            kind = "poll"
        else:
            raise AssertionError(f"unexpected request {method} {host}{path}")
        self.calls.append({"kind": kind, "method": method, "host": host, "path": path, "raw": body,
                           "body": json.loads(body) if body is not None else None, "timeout": timeout,
                           "headers": dict(headers), "at": self.t.now})
        assert self.queues[kind], f"no answer scripted for {kind}"
        answer = self.queues[kind].pop(0)
        if isinstance(answer, BaseException):
            raise answer
        status, obj, cost = (tuple(answer) + (0.0,))[:3]
        self.t.now += cost
        return status, obj if isinstance(obj, bytes) else json.dumps(obj).encode("utf-8")

    def kinds(self):
        return [call["kind"] for call in self.calls]


def checked(status, port=8000):
    """portchecker.io's answer for one port."""
    return 200, {"error": False, "msg": None, "check": [{"port": port, "status": status}], "host": IP}


CREATED = (202, {"id": MEASUREMENT, "probesCount": 1})
RUNNING = (200, {"id": MEASUREMENT, "type": "ping", "status": "in-progress", "results": []})


def finished(rcv=0, total=3, probe="finished", stats=None):
    """A finished Globalping measurement whose one probe result has status *probe*."""
    if stats is None:
        stats = {"min": None, "max": None, "avg": None, "total": total, "loss": round(100 * (total - rcv) / total),
                 "rcv": rcv, "drop": total - rcv}
    return 200, {"id": MEASUREMENT, "type": "ping", "status": "finished", "target": IP, "probesCount": 1,
                 "results": [{"probe": {"continent": "EU", "country": "FI"},
                              "result": {"status": probe, "timings": [], "stats": stats}}]}


def make(t, request, *, ip=IP, ip_ts=T0, changed_ts=T0 - 60.0, verdict="single_nat", generation=7, refresh=None,
         **knobs):
    """A PortChecker on fake time, plus the state its accessors read (change the state to change what they return)."""
    state = SimpleNamespace(pip={"ip": ip, "ts": ip_ts, "error": None, "checked_ts": ip_ts}, changed_ts=changed_ts,
                            verdict=verdict, generation=generation, reads=[])

    def verdict_fn():
        state.reads.append("verdict")
        return state.verdict

    def public_ip_fn():
        state.reads.append("public_ip")
        return dict(state.pip) if isinstance(state.pip, dict) else state.pip

    checker = pc.PortChecker(public_ip_fn=public_ip_fn, changed_ts_fn=lambda: state.changed_ts, refresh_fn=refresh,
                             generation_fn=lambda: state.generation, nat_verdict_fn=verdict_fn,
                             clock=lambda: T0 + 100.0, monotonic=t.monotonic, sleep=t.sleep, request=request, **knobs)
    return checker, state


def failed_text(portchecker_reason, globalping_reason):
    return (f"The port checkers could not be reached: portchecker.io {portchecker_reason}, "
            f"Globalping {globalping_reason}")


# =========================================================================== the conftest guard
def test_conftest_guard_is_active():
    assert pc._https_request is not pc.https_request, "tests/conftest.py must replace tnt.portcheck._https_request"
    with pytest.raises(OSError) as err:
        pc._https_request("POST", "portchecker.io", "/api/query", b"{}", 1.0, {})
    assert str(err.value) == "network access is disabled in tests (tnt.portcheck)"
    # a checker built without request= looks the seam up when it runs, so it meets the guard as well
    t = FakeTime()
    checker, _ = make(t, None)
    result = checker.test(8000)
    assert (result["reachable"], result["provider"], result["detail"]) == (None, "globalping", None)
    assert result["error"] == failed_text("could not connect", "could not connect")
    assert t.sleeps == []


# =========================================================================== portchecker.io
def test_reachable_at_the_first_answer():
    t = FakeTime(start=500.0)
    net = FakeNet(t, portchecker=[checked(True) + (1.24,)])
    checker, _ = make(t, net)
    result = checker.test(8000)
    assert list(result) == list(pc.PORTCHECK_RESULT_KEYS)
    assert result == {"ts": T0 + 100.0, "generation": 7, "port": 8000, "protocol": "tcp", "public_ip": IP,
                      "reachable": True, "provider": "portchecker.io", "detail": "portchecker.io connected to the port",
                      "nat_verdict": "single_nat", "error": None, "duration_ms": 1240}
    [call] = net.calls
    assert (call["method"], call["host"], call["path"]) == ("POST", "portchecker.io", "/api/query")
    assert call["raw"] == b'{"host":"203.0.113.5","ports":[8000]}'
    assert call["timeout"] == 10.0 and call["headers"] == PORTCHECKER_JSON
    assert t.sleeps == []


@pytest.mark.parametrize("second,reachable,detail", [
    (checked(False), False, "portchecker.io could not connect (tried twice)"),
    (checked(True), True, "portchecker.io connected to the port"),
])
def test_a_false_is_asked_once_more(second, reachable, detail):
    t = FakeTime()
    net = FakeNet(t, portchecker=[checked(False), second])
    checker, _ = make(t, net)
    result = checker.test(8000)
    assert (result["reachable"], result["provider"], result["detail"], result["error"]) == \
        (reachable, "portchecker.io", detail, None)
    assert net.kinds() == ["portchecker", "portchecker"] and t.sleeps == [1.0]
    assert net.calls[1]["at"] == net.calls[0]["at"] + 1.0 and net.calls[1]["raw"] == net.calls[0]["raw"]
    assert result["duration_ms"] == 1000


def test_the_retry_delay_is_a_knob():
    t = FakeTime()
    net = FakeNet(t, portchecker=[checked(False), checked(False)])
    checker, _ = make(t, net, retry_delay_s=0.25)
    assert checker.test(8000)["reachable"] is False
    assert t.sleeps == [0.25]


def test_a_retry_that_errors_goes_to_globalping():
    t = FakeTime()
    net = FakeNet(t, portchecker=[checked(False), ConnectionResetError(10054, "reset")], create=[CREATED],
                  poll=[finished(rcv=0)])
    checker, _ = make(t, net)
    result = checker.test(8000)
    assert (result["reachable"], result["provider"], result["detail"], result["error"]) == \
        (False, "globalping", "0 of 3 connections answered (Globalping)", None)
    assert net.kinds() == ["portchecker", "portchecker", "create", "poll"] and t.sleeps == [1.0, 1.0]


PORTCHECKER_ERRORS = [
    ((400, {"status_code": 400, "detail": "validation error: host",
            "extra": [{"key": "host", "message": "does not appear to be public"}]}), "answered HTTP 400"),
    ((429, {"error": "too many requests"}), "answered HTTP 429"),
    ((503, b"<html>unavailable</html>"), "answered HTTP 503"),
    ((302, b""), "answered HTTP 302"),                                              # a redirect is never followed
    ((200, b"<html>checking your browser</html>"), "gave an unreadable answer"),
    ((200, {"error": True, "msg": "host is not public", "check": []}), "reported an error"),
    ((200, {"msg": None, "check": [{"port": 8000, "status": True}]}), "gave an unreadable answer"),   # no "error"
    ((200, {"error": False, "check": [{"port": 8001, "status": True}]}), "gave an unreadable answer"),
    ((200, {"error": False, "check": [{"port": True, "status": True}]}), "gave an unreadable answer"),
    ((200, {"error": False, "check": [{"port": 8000, "status": "true"}]}), "gave an unreadable answer"),
    ((200, {"error": False, "check": []}), "gave an unreadable answer"),
    ((200, [{"port": 8000, "status": True}]), "gave an unreadable answer"),
    (TimeoutError("timed out"), "did not answer in time"),
    (ConnectionResetError(10054, "reset"), "could not connect"),
    (ssl.SSLCertVerificationError("certificate verify failed"), "has a certificate this PC does not trust"),
]


@pytest.mark.parametrize("answer,reason", PORTCHECKER_ERRORS)
def test_portchecker_errors_go_to_globalping(answer, reason):
    t = FakeTime()
    net = FakeNet(t, portchecker=[answer], create=[CREATED], poll=[RUNNING, finished(rcv=2)])
    checker, _ = make(t, net)
    result = checker.test(8000)
    assert (result["reachable"], result["provider"], result["detail"], result["error"]) == \
        (True, "globalping", "2 of 3 connections answered (Globalping)", None)
    assert net.kinds() == ["portchecker", "create", "poll", "poll"]          # an error is never asked again
    create, poll = net.calls[1], net.calls[2]
    assert (create["method"], create["host"], create["path"]) == ("POST", "api.globalping.io", "/v1/measurements")
    assert create["raw"] == (b'{"type":"ping","target":"203.0.113.5","limit":1,'
                             b'"measurementOptions":{"packets":3,"protocol":"TCP","port":8000}}')
    assert create["headers"] == PORTCHECKER_JSON and create["timeout"] == 10.0
    assert (poll["method"], poll["host"], poll["path"], poll["raw"]) == \
        ("GET", "api.globalping.io", f"/v1/measurements/{MEASUREMENT}", None)
    assert poll["headers"] == {"Accept": "application/json", "User-Agent": UA}
    assert t.sleeps == [1.0, 1.0]                                               # poll_s before each read


@pytest.mark.parametrize("answer,reason", PORTCHECKER_ERRORS)
def test_both_failing_names_a_reason_for_each(answer, reason):
    t = FakeTime()
    net = FakeNet(t, portchecker=[answer], create=[(429, {"error": {"type": "too_many_requests"}})])
    checker, _ = make(t, net)
    result = checker.test(8000)
    assert result["error"] == failed_text(reason, "answered HTTP 429")
    assert (result["reachable"], result["detail"], result["provider"]) == (None, None, "globalping")
    assert IP not in result["error"] and "8000" not in result["error"]


# =========================================================================== Globalping
@pytest.mark.parametrize("answer,reachable,detail", [
    (finished(rcv=3), True, "3 of 3 connections answered (Globalping)"),
    (finished(rcv=1), True, "1 of 3 connections answered (Globalping)"),
    (finished(rcv=0), False, "0 of 3 connections answered (Globalping)"),
    (finished(stats={"rcv": 0, "loss": 100, "drop": 3}), False, "0 of 3 connections answered (Globalping)"),
    (finished(stats={"rcv": 2}), True, "2 of 3 connections answered (Globalping)"),     # 3 packets were asked for
])
def test_globalping_answers(answer, reachable, detail):
    t = FakeTime()
    net = FakeNet(t, portchecker=[(503, b"")], create=[CREATED], poll=[answer])
    checker, _ = make(t, net)
    result = checker.test(8000)
    assert (result["reachable"], result["provider"], result["detail"], result["error"]) == \
        (reachable, "globalping", detail, None)


@pytest.mark.parametrize("create,poll,reason,polls", [
    ([(500, {})], [], "answered HTTP 500", 0),
    ([socket.gaierror(11001, "getaddrinfo failed")], [], "could not be looked up (no DNS)", 0),
    ([(200, {"id": MEASUREMENT})], [], "answered HTTP 200", 0),              # only a 202 creates a measurement
    ([(202, {"probesCount": 1})], [], "gave an unreadable answer", 0),
    ([(202, {"id": "../limits"})], [], "gave an unreadable answer", 0),     # never put into a request path
    ([CREATED], [(404, {})], "answered HTTP 404", 1),
    ([CREATED], [RUNNING, (200, b"{")], "gave an unreadable answer", 2),
    ([CREATED], [(200, {"id": MEASUREMENT, "status": "queued"})], "gave an unreadable answer", 1),
    ([CREATED], [finished(probe="failed", stats={})], "reported that its probe failed", 1),
    ([CREATED], [finished(probe="offline", stats={})], "reported that its probe was offline", 1),
    ([CREATED], [finished(stats={"rcv": "3", "total": 3})], "gave an unreadable answer", 1),
    ([CREATED], [(200, {"id": MEASUREMENT, "status": "finished", "results": []})], "gave an unreadable answer", 1),
    ([CREATED], [RUNNING, TimeoutError("timed out")], "did not answer in time", 2),
    ([CREATED], [RUNNING] * 6, "had no result in time", 3),                 # poll_max_s=3 below
])
def test_globalping_failures(create, poll, reason, polls):
    t = FakeTime()
    net = FakeNet(t, portchecker=[(503, b"")], create=create, poll=poll)
    checker, _ = make(t, net, poll_max_s=3.0)
    result = checker.test(8000)
    assert result["error"] == failed_text("answered HTTP 503", reason)
    assert (result["reachable"], result["detail"], result["provider"]) == (None, None, "globalping")
    assert net.kinds() == ["portchecker", "create"] + ["poll"] * polls


# =========================================================================== the deadline
def test_one_deadline_covers_both_providers():
    t = FakeTime(start=0.0)
    net = FakeNet(t, portchecker=[checked(False) + (10.0,), (429, {}, 10.0)], create=[CREATED + (2.0,)],
                  poll=[RUNNING + (3.0,)] * 6)
    checker, _ = make(t, net)
    result = checker.test(8000)
    assert result["error"] == failed_text("answered HTTP 429", "did not answer in time")
    assert (result["reachable"], result["provider"], result["duration_ms"]) == (None, "globalping", 35000)
    assert net.kinds() == ["portchecker", "portchecker", "create", "poll", "poll", "poll"]
    # every request got min(10 s, time left), and nothing was asked at or after the 35 s deadline
    assert [call["at"] for call in net.calls] == [0.0, 11.0, 21.0, 24.0, 28.0, 32.0]
    assert [call["timeout"] for call in net.calls] == [10.0, 10.0, 10.0, 10.0, 7.0, 3.0]
    assert all(call["at"] + call["timeout"] <= 35.0 for call in net.calls)
    assert t.sleeps == [1.0, 1.0, 1.0, 1.0]
    assert t.now == 35.0


def test_no_time_left_for_globalping():
    t = FakeTime(start=0.0)
    net = FakeNet(t, portchecker=[checked(False) + (5.0,)])
    checker, _ = make(t, net, deadline_s=5.0)
    result = checker.test(8000)
    assert result["error"] == failed_text("did not answer in time", "was not tried (no time left)")
    assert (result["reachable"], result["provider"], result["detail"]) == (None, "portchecker.io", None)
    assert net.kinds() == ["portchecker"] and net.calls[0]["timeout"] == 5.0 and t.sleeps == []


def test_sleeps_are_cut_to_the_deadline():
    t = FakeTime(start=0.0)
    net = FakeNet(t, portchecker=[checked(False) + (2.5,)])
    checker, _ = make(t, net, deadline_s=3.0, retry_delay_s=1.0)
    result = checker.test(8000)
    assert t.sleeps == [0.5] and net.kinds() == ["portchecker"]
    assert result["error"] == failed_text("did not answer in time", "was not tried (no time left)")


# =========================================================================== refusals
@pytest.mark.parametrize("port", [0, -1, 65536, True, False, "8000", 8000.0, None, [8000]])
def test_port_must_be_a_whole_number_from_1_to_65535(port):
    t = FakeTime()
    net = FakeNet(t)
    checker, state = make(t, net)
    with pytest.raises(ValueError) as err:
        checker.test(port)
    assert str(err.value) == "port must be a whole number from 1 to 65535" == pc.PORTCHECK_PORT_TEXT
    assert state.reads == [] and net.calls == []


def test_the_first_and_last_ports_are_accepted():
    t = FakeTime()
    net = FakeNet(t, portchecker=[checked(True, port=1), checked(False, port=65535), checked(False, port=65535)])
    checker, _ = make(t, net, min_gap_s=0)
    assert checker.test(1)["reachable"] is True
    assert checker.test(65535)["reachable"] is False
    assert [call["body"]["ports"] for call in net.calls] == [[1], [65535], [65535]]


def test_a_vpn_verdict_refuses_before_anything_is_sent():
    t = FakeTime()
    net = FakeNet(t, portchecker=[checked(True)])
    refreshed = []
    checker, state = make(t, net, verdict="vpn", changed_ts=T0 + 5.0, refresh=lambda: refreshed.append(1))
    with pytest.raises(pc.VpnActive) as err:
        checker.test(8000)
    assert str(err.value) == ("This PC's internet goes through a VPN, so the test would check the VPN's address, "
                              "not this site's: disconnect the VPN first") == pc.PORTCHECK_VPN_TEXT
    assert isinstance(err.value, RuntimeError)
    assert net.calls == [] and refreshed == [] and state.reads == ["verdict"]
    # a refusal takes no rate-limit slot: with the VPN gone (and a fresh address) the test runs at once
    state.verdict, state.changed_ts = "double_nat", T0 - 1.0
    result = checker.test(8000)
    assert (result["reachable"], result["nat_verdict"]) == (True, "double_nat")


@pytest.mark.parametrize("pip,changed_ts", [
    ({"ip": IP, "ts": T0, "error": None, "checked_ts": T0}, T0 + 30.0),       # looked up before the network changed
    ({"ip": IP, "ts": None, "error": None, "checked_ts": T0}, None),
    ({"ip": None, "ts": None, "error": "URLError: timed out", "checked_ts": T0}, None),
    ({"ip": "2001:db8::5", "ts": T0, "error": None, "checked_ts": T0}, None),  # the fallback host answered over IPv6
    ({"ip": "203.0.113", "ts": T0, "error": None, "checked_ts": T0}, None),
    ({"ip": " 203.0.113.5", "ts": T0, "error": None, "checked_ts": T0}, None),
    ({"ip": IP, "ts": True, "error": None, "checked_ts": T0}, None),           # a ts must be a time
    ({"ip": IP, "ts": "1700000000", "error": None, "checked_ts": T0}, None),
    ({"ip": IP, "ts": float("nan"), "error": None, "checked_ts": T0}, None),
    ({"ip": IP, "ts": T0, "error": None, "checked_ts": T0}, float("nan")),     # and so must the change time
    ({}, None),
    (None, None),
])
def test_a_stale_public_ip_is_refreshed_once_then_no_public_ip(pip, changed_ts):
    t = FakeTime()
    net = FakeNet(t, portchecker=[checked(True)])
    refreshed = []

    def refresh():
        refreshed.append((threading.current_thread().name, threading.current_thread().daemon))

    checker, state = make(t, net, changed_ts=changed_ts, refresh=refresh)
    state.pip = pip
    with pytest.raises(pc.NoPublicIp) as err:
        checker.test(8000)
    assert str(err.value) == ("This network's public IPv4 address is not known yet (or it has none): wait for the "
                              "WAN address on the link map, then test again") == pc.PORTCHECK_NO_IP_TEXT
    assert isinstance(err.value, RuntimeError)
    assert refreshed == [("tnt-portcheck-refresh", True)]
    assert state.reads == ["verdict", "public_ip", "public_ip"] and net.calls == []
    # no rate-limit slot was taken: once the address is fresh the test runs at the same moment
    state.pip, state.changed_ts = {"ip": IP, "ts": T0, "error": None, "checked_ts": T0}, T0 - 1.0
    assert checker.test(8000)["reachable"] is True and len(refreshed) == 1


def test_without_a_refresh_function_a_stale_address_is_refused_at_once():
    t = FakeTime()
    net = FakeNet(t)
    checker, state = make(t, net, changed_ts=T0 + 1.0, refresh=None)
    with pytest.raises(pc.NoPublicIp):
        checker.test(8000)
    assert state.reads == ["verdict", "public_ip"] and net.calls == []


def _raises():
    raise RuntimeError("the accessor failed")


def test_accessors_that_raise():
    """A failing verdict or generation reads as not known; a failing address or change time never lets a test run
    (§2.3: the address is fresh only when the change time is None or not after its ts, and a failure is neither)."""
    t = FakeTime()
    net = FakeNet(t, portchecker=[checked(True)])
    refreshed = []
    knobs = dict(public_ip_fn=lambda: {"ip": IP, "ts": T0, "error": None, "checked_ts": T0},
                 changed_ts_fn=lambda: T0 - 60.0, refresh_fn=lambda: refreshed.append(1), generation_fn=lambda: 7,
                 nat_verdict_fn=lambda: "single_nat", clock=lambda: T0, monotonic=t.monotonic, sleep=t.sleep,
                 request=net)
    result = pc.PortChecker(**dict(knobs, nat_verdict_fn=_raises, generation_fn=_raises)).test(8000)
    assert (result["reachable"], result["nat_verdict"], result["generation"]) == (True, None, None)
    assert refreshed == []
    for broken in ("public_ip_fn", "changed_ts_fn"):
        with pytest.raises(pc.NoPublicIp):
            pc.PortChecker(**dict(knobs, **{broken: _raises})).test(8000)
    assert refreshed == [1, 1] and len(net.calls) == 1              # one lookup each, and nothing was sent


def test_a_refresh_that_brings_a_fresh_address_is_used():
    t = FakeTime()
    net = FakeNet(t, portchecker=[checked(True)])
    holder = {}

    def refresh():
        holder["state"].pip = {"ip": OTHER_IP, "ts": T0 + 40.0, "error": None, "checked_ts": T0 + 40.0}
        holder["state"].generation = 8

    checker, state = make(t, net, changed_ts=T0 + 30.0, refresh=refresh)
    holder["state"] = state
    result = checker.test(8000)
    assert (result["public_ip"], result["generation"], result["reachable"]) == (OTHER_IP, 8, True)
    assert net.calls[0]["body"] == {"host": OTHER_IP, "ports": [8000]}


def test_a_refresh_that_hangs_is_waited_for_at_most_refresh_wait_s():
    t = FakeTime()
    net = FakeNet(t)
    release = threading.Event()
    checker, _ = make(t, net, changed_ts=T0 + 30.0, refresh=lambda: release.wait(5), refresh_wait_s=0.05)
    try:
        started = time.monotonic()
        with pytest.raises(pc.NoPublicIp):
            checker.test(8000)
        assert time.monotonic() - started < 2.0
    finally:
        release.set()
    assert net.calls == []


def test_a_lookup_still_running_is_waited_for_instead_of_starting_another():
    t = FakeTime()
    net = FakeNet(t)
    release = threading.Event()
    lookups = []

    def hang():
        lookups.append(1)
        release.wait(5)

    checker, _ = make(t, net, changed_ts=T0 + 30.0, refresh=hang, refresh_wait_s=0.05)
    try:
        for _ in range(3):                                     # clicks while the first lookup still hangs
            with pytest.raises(pc.NoPublicIp):
                checker.test(8000)
        assert lookups == [1]
    finally:
        release.set()
    checker._refresh_thread.join(5)
    with pytest.raises(pc.NoPublicIp):                        # that lookup is over: the next test starts a new one
        checker.test(8000)
    assert lookups == [1, 1] and net.calls == []


def test_one_test_at_a_time():
    t = FakeTime()
    entered, release = threading.Event(), threading.Event()

    def slow(method, host, path, body, timeout, headers):
        entered.set()
        assert release.wait(5)
        status, obj = checked(True)
        return status, json.dumps(obj).encode("utf-8")

    checker, _ = make(t, slow)
    results = []
    worker = threading.Thread(target=lambda: results.append(checker.test(8000)), daemon=True)
    worker.start()
    try:
        assert entered.wait(5)
        with pytest.raises(RuntimeError) as err:             # busy is checked before the rate limit
            checker.test(8001)
        assert type(err.value) is RuntimeError and str(err.value) == "a port-forward test is already running"
    finally:
        release.set()
        worker.join(5)
    assert results and results[0]["reachable"] is True
    # done: the next test is no longer "running" but still inside the 5 s gap
    with pytest.raises(pc.RateLimited):
        checker.test(8001)
    t.now += 5.0
    assert checker.test(8000)["reachable"] is True


# =========================================================================== rate limits
def test_the_gap_between_tests_and_its_retry_after_seconds():
    t = FakeTime(start=1000.0)
    net = FakeNet(t, portchecker=[checked(True)] * 3)
    checker, _ = make(t, net)                                  # the defaults: 5 s between starts, 30 an hour
    checker.test(8000)
    t.now = 1002.0
    with pytest.raises(pc.RateLimited) as err:
        checker.test(8000)
    assert str(err.value) == "Too many tests: wait 3 s" and err.value.retry_after_s == 3
    assert isinstance(err.value, RuntimeError) and type(err.value.retry_after_s) is int
    t.now = 1004.2
    with pytest.raises(pc.RateLimited) as err:
        checker.test(8000)
    assert (str(err.value), err.value.retry_after_s) == ("Too many tests: wait 1 s", 1)     # whole seconds, rounded up
    t.now = 1005.0
    assert checker.test(8000)["reachable"] is True
    assert len(net.calls) == 2                                 # refused tests sent nothing


def test_tests_per_hour_and_their_retry_after_seconds():
    t = FakeTime(start=0.0)
    net = FakeNet(t, portchecker=[checked(True)] * 10)
    checker, _ = make(t, net, min_gap_s=0, per_hour=3)
    for at in (0.0, 100.0, 200.0):
        t.now = at
        checker.test(8000)
    t.now = 1000.0
    with pytest.raises(pc.RateLimited) as err:
        checker.test(8000)
    assert (str(err.value), err.value.retry_after_s) == ("Too many tests: wait 2600 s", 2600)
    t.now = 3599.5
    with pytest.raises(pc.RateLimited) as err:
        checker.test(8000)
    assert err.value.retry_after_s == 1
    t.now = 3600.0                                             # the first test has left the hour
    checker.test(8000)
    t.now = 3601.0
    with pytest.raises(pc.RateLimited) as err:
        checker.test(8000)
    assert err.value.retry_after_s == 99                       # the test at 100 s leaves the hour at 3700 s
    assert len(net.calls) == 4


def test_the_longer_wait_wins_and_zero_knobs_switch_the_limits_off():
    t = FakeTime(start=0.0)
    net = FakeNet(t, portchecker=[checked(True)] * 5)
    checker, _ = make(t, net, min_gap_s=5.0, per_hour=1)
    checker.test(8000)
    t.now = 2.0
    with pytest.raises(pc.RateLimited) as err:
        checker.test(8000)
    assert err.value.retry_after_s == 3598
    unlimited, _ = make(t, net, min_gap_s=0, per_hour=0)
    for _ in range(4):
        assert unlimited.test(8000)["reachable"] is True


def test_the_refusal_classes():
    assert issubclass(pc.RateLimited, RuntimeError) and issubclass(pc.NoPublicIp, RuntimeError)
    assert issubclass(pc.VpnActive, RuntimeError)
    assert str(pc.NoPublicIp()) == pc.PORTCHECK_NO_IP_TEXT and str(pc.VpnActive()) == pc.PORTCHECK_VPN_TEXT
    limited = pc.RateLimited("Too many tests: wait 7 s", retry_after_s=7)
    assert (str(limited), limited.retry_after_s) == ("Too many tests: wait 7 s", 7)
    # the route maps only a plain RuntimeError saying "already running" to 409 conflict
    for text in (pc.PORTCHECK_VPN_TEXT, pc.PORTCHECK_NO_IP_TEXT, pc.PORTCHECK_RATE_TEXT):
        assert "already running" not in text.lower()
    assert "already running" in pc.PORTCHECK_BUSY_TEXT


# =========================================================================== logging
def test_info_log_carries_no_address_or_port(caplog):
    t = FakeTime()
    net = FakeNet(t, portchecker=[(503, b"")], create=[CREATED], poll=[finished(rcv=0)])
    checker, _ = make(t, net)
    with caplog.at_level(logging.DEBUG, logger="tnt.portcheck"):
        checker.test(8123)
        with pytest.raises(pc.RateLimited):
            checker.test(8123)
    infos = [r.getMessage() for r in caplog.records if r.levelno >= logging.INFO]
    assert infos == ["Port-forward test: False via globalping in 1000 ms"]
    debug = [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]
    assert any(IP in message and "8123" in message for message in debug)       # the details are at DEBUG


# =========================================================================== the HTTPS client
class FakeSock:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)


class FakeResponse:
    def __init__(self, status, chunks, headers=None, t=None, per_read_s=0.0):
        self.status = status
        self.chunks = list(chunks)
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.t, self.per_read_s = t, per_read_s
        self.reads = 0
        self.closed = False

    def getheader(self, name, default=None):
        return self.headers.get(name.lower(), default)

    def read1(self, n):
        self.reads += 1
        if self.t is not None:
            self.t.now += self.per_read_s
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        assert len(chunk) <= n
        return chunk

    def close(self):
        self.closed = True


class FakeConnection:
    """Plays http.client.HTTPSConnection: the factory call records the arguments and returns the connection."""

    def __init__(self, response):
        self.response = response
        self.sock = None
        self.closed = False
        self.sent = None

    def __call__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.timeout, self.context = host, port, timeout, context
        return self

    def connect(self):
        self.sock = FakeSock()

    def request(self, method, path, body=None, headers=None):
        self.sent = (method, path, body, dict(headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def test_https_request_uses_the_stdlib_client_with_a_verifying_tls_context(monkeypatch):
    resp = FakeResponse(200, [b'{"error":false,', b'"check":[]}'])
    conn = FakeConnection(resp)
    monkeypatch.setattr(http.client, "HTTPSConnection", conn)      # the default factory is looked up at call time
    status, body = pc.https_request("POST", "portchecker.io", "/api/query", b"{}", 7.5,
                                    {"Content-Type": "application/json", "Accept": "application/json"})
    assert (status, body) == (200, b'{"error":false,"check":[]}')
    assert (conn.host, conn.port, conn.timeout) == ("portchecker.io", 443, 7.5)
    assert isinstance(conn.context, ssl.SSLContext)
    assert conn.context.verify_mode == ssl.CERT_REQUIRED and conn.context.check_hostname is True
    assert conn.sent == ("POST", "/api/query", b"{}", {"Content-Type": "application/json",
                                                       "Accept": "application/json", "User-Agent": UA})
    assert conn.closed and resp.closed
    assert all(0 < value <= 7.5 for value in conn.sock.timeouts)


def test_https_request_keeps_a_given_user_agent_and_returns_any_status():
    resp = FakeResponse(302, [b"moved"], headers={"Location": "https://example.com/"})
    conn = FakeConnection(resp)
    status, body = pc.https_request("GET", "api.globalping.io", "/v1/measurements/x", None, 3.0,
                                    {"User-Agent": "other"}, connection_factory=conn)
    assert (status, body) == (302, b"moved") and conn.sent[3] == {"User-Agent": "other"}


def test_https_request_caps_the_body_at_256_kib():
    exact = FakeResponse(200, [b"a" * 65536] * 4)
    assert len(pc.https_request("GET", "h", "/", None, 5.0, {}, connection_factory=FakeConnection(exact))[1]) == 262144
    over = FakeResponse(200, [b"a" * 65536] * 4 + [b"b"])
    conn = FakeConnection(over)
    with pytest.raises(pc.ResponseTooLarge):
        pc.https_request("GET", "h", "/", None, 5.0, {}, connection_factory=conn)
    assert conn.closed and over.closed
    declared = FakeResponse(200, [b"{}"], headers={"Content-Length": "262145"})
    with pytest.raises(pc.ResponseTooLarge):
        pc.https_request("GET", "h", "/", None, 5.0, {}, connection_factory=FakeConnection(declared))
    assert declared.reads == 0                                  # refused before reading


def test_https_request_cuts_off_a_dripping_answer_at_the_timeout():
    t = FakeTime(start=0.0)
    drip = FakeResponse(200, [b"x"] * 100, t=t, per_read_s=4.0)
    conn = FakeConnection(drip)
    with pytest.raises(TimeoutError):
        pc.https_request("GET", "h", "/", None, 10.0, {}, connection_factory=conn, monotonic=t.monotonic)
    assert drip.reads == 3 and t.now == 12.0 and conn.closed
    assert conn.sock.timeouts == [10.0, 10.0, 10.0, 6.0, 2.0]


@pytest.mark.parametrize("exc,reason", [
    (ssl.SSLCertVerificationError("certificate verify failed"), "has a certificate this PC does not trust"),
    (ssl.SSLError("wrong version number"), "could not set up a secure connection"),
    (socket.gaierror(11001, "getaddrinfo failed"), "could not be looked up (no DNS)"),
    (TimeoutError("timed out"), "did not answer in time"),
    (socket.timeout("timed out"), "did not answer in time"),
    (ConnectionRefusedError(10061, "refused"), "could not connect"),
    (http.client.RemoteDisconnected("closed without an answer"), "could not connect"),
    (http.client.BadStatusLine("garbage"), "gave an unreadable answer"),
    (pc.ResponseTooLarge("too big"), "gave an unreadable answer"),
    (OSError("network access is disabled in tests (tnt.portcheck)"), "could not connect"),
])
def test_failure_reasons_never_repeat_the_exception_text(exc, reason):
    assert pc.failure_reason(exc) == reason
