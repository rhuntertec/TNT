"""tnt.sipalg: proving whether something on the path rewrites SIP.

The active check is run against a fake PBX on loopback that answers OPTIONS - one that echoes the request properly,
and ones that rewrite a header on the way back the way an ALG would. Nothing here leaves the machine.
"""
from __future__ import annotations

import socket
import threading
import time
from typing import Any, Dict, List, Optional

import pytest

from tnt import sipalg, sipcalls
from tnt.sipalg import (ALG_KEYS, CHANGE_KEYS, FINDING_IDS, FINDING_KEYS, PROBE_KEYS, VERDICTS, AlgChecker,
                        build_options, compare_echo, passive_tells, validate_target)


# --------------------------------------------------------------------------- a PBX that answers on loopback
class FakePbx:
    """Answers OPTIONS the way a SIP server must: the request's Via, Call-ID, CSeq and From back exactly as they
    arrived, plus the received/rport it is allowed to add. `rewrite` makes it lie, which is what an ALG's victim
    sees."""

    def __init__(self, *, rewrite: Optional[Dict[str, str]] = None, silent: bool = False,
                 rewrite_ports: Optional[tuple] = None) -> None:
        self.rewrite = rewrite or {}
        self.silent = silent
        self.rewrite_ports = rewrite_ports          # only mangle probes that came from these source ports
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.seen: List[int] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            view = sipcalls.sip_headers(data)
            if view is None or self.silent:
                continue
            self.seen.append(peer[1])
            headers = {h["name"]: h["value"] for h in view["headers"]}
            via = headers.get("via", "")
            mangle = self.rewrite_ports is None or peer[1] in self.rewrite_ports
            if mangle and "via" in self.rewrite:
                via = self.rewrite["via"]
            via = f"{via};received={peer[0]};rport={peer[1]}"
            call_id = self.rewrite.get("call-id") if mangle else None
            reply = (
                "SIP/2.0 200 OK\r\n"
                f"Via: {via}\r\n"
                f"From: {headers.get('from', '')}\r\n"
                f"To: {headers.get('to', '')};tag=pbx-side\r\n"
                f"Call-ID: {call_id or headers.get('call-id', '')}\r\n"
                f"CSeq: {headers.get('cseq', '')}\r\n"
                "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            try:
                self.sock.sendto(reply.encode(), peer)
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture
def pbx():
    servers: List[FakePbx] = []

    def make(**kwargs: Any) -> FakePbx:
        server = FakePbx(**kwargs)
        servers.append(server)
        return server
    yield make
    for server in servers:
        server.close()


# --------------------------------------------------------------------------- the address
@pytest.mark.parametrize("given,expected", [
    ("pbx.example.com", ("pbx.example.com", 5060)),
    ("pbx.example.com:5080", ("pbx.example.com", 5080)),
    ("sip:pbx.example.com", ("pbx.example.com", 5060)),
    ("sip:2001@pbx.example.com:5065", ("pbx.example.com", 5065)),
    ("  PBX.example.com.  ", ("PBX.example.com", 5060)),
    ("198.51.100.20", ("198.51.100.20", 5060)),
    ("2001:db8::1", ("2001:db8::1", 5060)),
    ("[2001:db8::1]:5080", ("2001:db8::1", 5080)),
])
def test_an_address_is_read_the_way_a_tech_would_type_it(given, expected):
    assert validate_target(given) == expected


@pytest.mark.parametrize("bad", ["", "   ", "has space", "a/b", "x" * 300, None])
def test_a_bad_address_is_refused_with_words(bad):
    with pytest.raises(ValueError):
        validate_target(bad)


@pytest.mark.parametrize("port", [0, -1, 70000, "abc", 1.5])
def test_a_bad_port_is_refused(port):
    with pytest.raises(ValueError, match="port"):
        validate_target("pbx.example.com", port)


# --------------------------------------------------------------------------- the request and the mirror
def test_the_request_is_an_options_with_markers_that_have_to_come_back():
    message, sent = build_options("pbx.example", 5060, "10.0.0.5", 5060)
    view = sipcalls.sip_headers(message)
    assert view["start"].startswith("OPTIONS sip:pbx.example:5060")
    assert view["method"] == "OPTIONS"                 # asks what the far end can do, and rings nobody
    names = [h["name"] for h in view["headers"]]
    for needed in ("via", "from", "to", "call-id", "cseq", "contact", "max-forwards"):
        assert needed in names, needed
    assert sent["branch"].startswith("z9hG4bK")        # RFC 3261 magic cookie
    # the markers are fresh each time, so a stale reply to an earlier probe cannot be read as this one's
    _second, again = build_options("pbx.example", 5060, "10.0.0.5", 5060)
    assert again["branch"] != sent["branch"] and again["call-id"] != sent["call-id"]


def _response(sent: Dict[str, str], *, via: str = None, call_id: str = None, cseq: str = None,
              from_header: str = None, to_tag: str = ";tag=pbx") -> Dict[str, Any]:
    raw = ("SIP/2.0 200 OK\r\n"
           f"Via: {via or sent['via']}\r\n"
           f"From: {from_header or sent['from']}\r\n"
           f"To: {sent['to']}{to_tag}\r\n"
           f"Call-ID: {call_id or sent['call-id']}\r\n"
           f"CSeq: {cseq or sent['cseq']}\r\n"
           "Content-Length: 0\r\n\r\n").encode()
    return sipcalls.sip_headers(raw)


def test_the_additions_a_server_is_allowed_to_make_are_not_rewrites():
    """received and rport on the top Via, and a tag on To, are required of the server - reading them as tampering
    would make every check a false positive."""
    _message, sent = build_options("pbx.example", 5060, "10.0.0.5", 5060)
    view = _response(sent, via=sent["via"] + ";received=203.0.113.7;rport=5060")
    assert compare_echo(sent, view) == []


@pytest.mark.parametrize("field,kwargs,header", [
    ("via", {"via": "SIP/2.0/UDP 203.0.113.7:5060;branch=REPLACED"}, "Via sent-by"),
    ("branch", {"via": "SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bKsomethingelse"}, "Via branch"),
    ("call-id", {"call_id": "rewritten@203.0.113.7"}, "Call-Id"),
    ("cseq", {"cseq": "9 OPTIONS"}, "Cseq"),
    ("from", {"from_header": "<sip:tnt@203.0.113.7>;tag=zzz"}, "From"),
])
def test_every_echoed_header_that_changed_is_caught(field, kwargs, header):
    _message, sent = build_options("pbx.example", 5060, "10.0.0.5", 5060)
    changes = compare_echo(sent, _response(sent, **kwargs))
    assert any(change["header"] == header for change in changes), (field, changes)
    assert all(list(change) == list(CHANGE_KEYS) for change in changes)


# --------------------------------------------------------------------------- the check end to end
def _check(server: FakePbx, **kwargs: Any) -> Dict[str, Any]:
    checker = AlgChecker(timeout_s=1.5)
    return checker.check("127.0.0.1", server.port, **kwargs)


def test_a_server_that_echoes_properly_reads_as_clean(pbx):
    result = _check(pbx())
    assert list(result) == list(ALG_KEYS)
    assert result["verdict"] == "clean" and result["verdict"] in VERDICTS
    assert all(list(probe) == list(PROBE_KEYS) for probe in result["probes"])
    assert any(probe["answered"] for probe in result["probes"])
    assert result["changes"] == []
    found = {f["id"]: f for f in result["findings"]}
    assert found["alg.clean"]["level"] == "good"
    # and it says plainly what a clean result does not prove
    assert "not proof" in found["alg.clean"]["advice"]
    assert all(f["id"] in FINDING_IDS and list(f) == list(FINDING_KEYS) for f in result["findings"])


def test_a_rewritten_via_is_called_what_it_is(pbx):
    server = pbx(rewrite={"via": "SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bKmangled"})
    result = _check(server)
    assert result["verdict"] == "alg"
    found = {f["id"]: f for f in result["findings"]}
    assert found["alg.rewritten"]["level"] == "bad"
    assert "SIP ALG" in found["alg.rewritten"]["advice"]
    assert any(change["header"].startswith("Via") for change in result["changes"])


def test_rewriting_that_only_happens_on_5060_is_named(pbx):
    """ALGs watch 5060 and ignore everything else. Seeing that difference is both the proof and the workaround."""
    checker = AlgChecker(timeout_s=1.5)
    server = pbx(rewrite={"via": "SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bKmangled"}, rewrite_ports=(5060,))
    # ask for 5060 and a high port; if 5060 is not free on this machine the test has nothing to compare
    result = checker.check("127.0.0.1", server.port)
    used = {probe["port"] for probe in result["probes"] if probe["answered"]}
    if 5060 not in used:
        pytest.skip("UDP 5060 is in use on this machine, so the two-port comparison cannot run")
    assert result["verdict"] == "alg"
    found = {f["id"]: f for f in result["findings"]}
    assert found["alg.port"]["level"] == "bad"
    assert "5065" in found["alg.port"]["advice"]


def test_a_server_that_says_nothing_is_inconclusive_not_clean(pbx):
    """The distinction that matters: no answer means nothing is known, and calling that a pass would be a lie."""
    result = _check(pbx(silent=True))
    assert result["verdict"] == "inconclusive"
    found = {f["id"]: f for f in result["findings"]}
    assert found["alg.silent"]["level"] == "warn"
    assert "not a clean result" in found["alg.silent"]["detail"]


def test_a_tls_port_says_the_question_does_not_apply(pbx):
    checker = AlgChecker(timeout_s=0.5)
    result = checker.check("pbx.example.com", 5061)
    assert result["verdict"] == "moot" and result["transport"] == "tls"
    assert result["probes"] == []
    found = {f["id"]: f for f in result["findings"]}
    assert found["alg.tls"]["level"] == "good"
    assert "can read it" in found["alg.tls"]["detail"]


def test_the_probe_reports_which_source_port_it_really_used(pbx):
    result = _check(pbx())
    for probe in result["probes"]:
        assert isinstance(probe["port"], int) and probe["port"] > 0
    # when 5060 could not be had, the result says so rather than quietly testing something else
    asked_5060 = [p for p in result["probes"] if p["requested_port"] == 5060]
    assert asked_5060
    if not asked_5060[0]["bound"]:
        assert any(f["id"] == "alg.port" and "could not be used" in f["title"] for f in result["findings"])


def test_the_public_address_the_server_saw_comes_back(pbx):
    result = _check(pbx())
    assert result["public"] == "127.0.0.1"             # what the far end saw as the source


def test_a_bad_address_never_reaches_a_socket():
    with pytest.raises(ValueError):
        AlgChecker().check("", None)


# --------------------------------------------------------------------------- the passive tells
def test_a_private_phone_advertising_a_public_contact_is_a_tell():
    """A phone writes its own Contact. It does not know the public address unless something put it there."""
    calls = [{"id": "c1", "ladder": [
        {"label": "INVITE", "src": "192.168.1.50:5060", "contact": "<sip:2001@203.0.113.9:5060>"},
        {"label": "ACK", "src": "192.168.1.50:5060", "contact": "<sip:2001@192.168.1.50:5060>"},
    ]}]
    tells = passive_tells(calls)
    assert len(tells) == 1
    assert tells[0]["id"] == "alg.contact" and tells[0]["call"] == "c1" and tells[0]["message"] == "INVITE"
    assert "203.0.113.9" in tells[0]["detail"] and "behind NAT" in tells[0]["detail"]


def test_the_ranges_that_count_as_behind_nat_are_the_rfc_1918_ones():
    """Not ipaddress.is_private: that counts the documentation ranges too, and 203.0.113.9 stands in for a public
    address all over this codebase - reading it as private would make the check never fire."""
    assert sipalg.behind_nat("192.168.1.50") is True and sipalg.behind_nat("10.1.2.3") is True
    assert sipalg.behind_nat("100.64.0.1") is True                      # carrier-grade NAT
    assert sipalg.behind_nat("203.0.113.9") is False and sipalg.behind_nat("8.8.8.8") is False
    assert sipalg.behind_nat("not-an-address") is None


def test_a_phone_on_a_public_address_is_not_a_tell():
    calls = [{"id": "c1", "ladder": [
        {"label": "INVITE", "src": "203.0.113.50:5060", "contact": "<sip:2001@203.0.113.99:5060>"}]}]
    assert passive_tells(calls) == []


def test_a_contact_that_matches_the_sender_is_not_a_tell():
    calls = [{"id": "c1", "ladder": [
        {"label": "INVITE", "src": "192.168.1.50:5060", "contact": "<sip:2001@192.168.1.50:5060>"}]}]
    assert passive_tells(calls) == []


@pytest.mark.parametrize("calls", [[], None, [{"id": "c", "ladder": []}], [{"id": "c"}]])
def test_passive_tells_survives_nothing_to_look_at(calls):
    assert passive_tells(calls) == []


def test_an_sdp_pointing_somewhere_the_sender_is_not_is_the_one_way_audio_tell():
    """c= is where the sender asks for its audio. A phone behind NAT writes its own address there; anything else
    was written by something else, and the far end then sends RTP where nothing is listening."""
    calls = [{"id": "c1", "ladder": [
        {"label": "INVITE", "src": "192.168.1.50:5060", "contact": "<sip:2001@192.168.1.50:5060>",
         "sdp_c": "203.0.113.9"}]}]
    tells = passive_tells(calls)
    assert [tell["id"] for tell in tells] == ["alg.sdp"]
    assert "one-way audio" in tells[0]["detail"]
    assert tells[0]["evidence"] == {"src": "192.168.1.50", "sdp_c": "203.0.113.9"}


def test_an_sdp_that_matches_the_sender_is_not_a_tell():
    calls = [{"id": "c1", "ladder": [
        {"label": "INVITE", "src": "192.168.1.50:5060", "sdp_c": "192.168.1.50"}]}]
    assert passive_tells(calls) == []


def test_a_content_length_that_does_not_match_the_body_is_visible_in_the_header_view():
    good = (b"OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.5:5060;branch=z1\r\nFrom: <sip:a@x>;tag=t\r\n"
            b"To: <sip:b@x>\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n")
    assert sipcalls.sip_headers(good)["length_ok"] is True
    bad = good.replace(b"Content-Length: 0", b"Content-Length: 40")
    assert sipcalls.sip_headers(bad)["length_ok"] is False
    missing = good.replace(b"Content-Length: 0\r\n", b"")
    assert sipcalls.sip_headers(missing)["length_ok"] is None      # nothing declared is not a mismatch


# --------------------------------------------------------------------------- driving it from a button
def test_the_result_is_kept_so_the_page_has_something_to_show(pbx):
    checker = AlgChecker(timeout_s=1.5)
    assert checker.last() is None and checker.running() is False
    result = checker.check("127.0.0.1", pbx().port)
    assert checker.last() == result

def test_the_kept_result_is_a_copy_a_caller_cannot_scribble_on(pbx):
    checker = AlgChecker(timeout_s=1.5)
    checker.check("127.0.0.1", pbx().port)
    checker.last()["verdict"] = "nonsense"
    assert checker.last()["verdict"] in VERDICTS

def test_two_runs_at_once_are_refused_rather_than_fighting_over_the_bind(pbx):
    """Both runs ask for source port 5060 first.  Letting the second through would surface as the port being
    unavailable, which reads as a finding rather than as the button having been pressed twice."""
    server = pbx()
    checker = AlgChecker(timeout_s=1.5)
    errors: List[Any] = []
    started = threading.Event()
    real_probe = checker._probe

    def slow_probe(*a: Any, **kw: Any) -> Any:
        started.set()
        time.sleep(0.4)
        return real_probe(*a, **kw)

    checker._probe = slow_probe                                     # type: ignore[assignment]
    worker = threading.Thread(target=lambda: checker.check("127.0.0.1", server.port))
    worker.start()
    try:
        started.wait(2.0)
        assert checker.running() is True
        with pytest.raises(RuntimeError, match="already running"):
            checker.check("127.0.0.1", server.port)
    finally:
        worker.join(10.0)
    assert checker.running() is False and errors == []

def test_a_failed_run_does_not_leave_the_checker_stuck_busy():
    checker = AlgChecker(timeout_s=1.5)
    with pytest.raises(ValueError):
        checker.check("not a host at all")
    assert checker.running() is False

def test_a_network_change_drops_the_kept_result(pbx):
    """It described the network this PC was on, not the one it is on now."""
    checker = AlgChecker(timeout_s=1.5)
    checker.check("127.0.0.1", pbx().port)
    checker.on_network_change({"generation": 2})
    assert checker.last() is None


# --------------------------------------------------------------------------- a probe that never ran
def test_a_name_that_does_not_resolve_is_not_a_port_conflict():
    """The bug this pins: a host name that will not resolve fails before any bind, and `bound` was starting at
    False, so the check reported "something else on this PC is using 5060" — a cause it had never looked at."""
    result = AlgChecker(timeout_s=1.0).check("no-such-host.invalid", 5060)
    assert result["verdict"] == "inconclusive"
    assert all(probe["bound"] is None for probe in result["probes"]), "never got as far as binding"
    ids = [f["id"] for f in result["findings"]]
    assert "alg.port" not in ids, ids
    assert ids == ["alg.dns"], ids

def test_a_name_that_does_not_resolve_says_so_and_says_where_to_look():
    result = AlgChecker(timeout_s=1.0).check("no-such-host.invalid", 5060)
    dns = next(f for f in result["findings"] if f["id"] == "alg.dns")
    assert "does not resolve" in dns["title"] and "no-such-host.invalid" in dns["title"]
    assert "nothing was sent" in dns["detail"]
    assert "VPN" in dns["advice"] or "internal DNS" in dns["advice"]
    assert list(dns) == list(FINDING_KEYS) and dns["id"] in FINDING_IDS

def test_a_probe_that_could_not_run_reports_bound_as_unknown_not_false():
    """Three states, because they are three different things: got the port, was refused it, never got there."""
    result = AlgChecker(timeout_s=1.0).check("no-such-host.invalid", 5060)
    for probe in result["probes"]:
        assert list(probe) == list(PROBE_KEYS)
        assert probe["bound"] is None and probe["port"] is None and probe["error"]

def test_a_source_port_that_really_is_taken_is_still_reported(pbx):
    """The other half: when 5060 is genuinely held, the finding must still fire — it is the workaround worth
    knowing, and a check that stopped reporting it would have traded one wrong answer for another."""
    server = pbx()
    hog = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            hog.bind(("", sipalg.SIP_PORT))
        except OSError:
            pytest.skip("UDP 5060 is already in use on this machine")
        result = AlgChecker(timeout_s=1.5).check("127.0.0.1", server.port)
        asked = next(p for p in result["probes"] if p["requested_port"] == sipalg.SIP_PORT)
        assert asked["bound"] is False and asked["port"] != sipalg.SIP_PORT
        port_finding = next(f for f in result["findings"] if f["id"] == "alg.port")
        assert "refused" in port_finding["detail"] and "softphone" in port_finding["detail"]
    finally:
        hog.close()

def test_a_free_source_port_raises_nothing_about_ports(pbx):
    server = pbx()
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # closed before the check, or it would hold 5060
    try:
        probe.bind(("", sipalg.SIP_PORT))
    except OSError:
        pytest.skip("UDP 5060 is already in use on this machine")
    finally:
        probe.close()
    result = AlgChecker(timeout_s=1.5).check("127.0.0.1", server.port)
    asked = next(p for p in result["probes"] if p["requested_port"] == sipalg.SIP_PORT)
    assert asked["bound"] is True and asked["port"] == sipalg.SIP_PORT
    assert "alg.port" not in [f["id"] for f in result["findings"]]

def test_only_a_wholly_unresolvable_run_is_called_a_dns_failure(pbx):
    """One probe failing to resolve while the other answered is not a name problem, and must not be relabelled
    as one — the reply is the thing worth reporting."""
    assert sipalg._name_failed([]) is False
    assert sipalg._name_failed([{"error": "getaddrinfo failed"}, {"error": None}]) is False
    assert sipalg._name_failed([{"error": "getaddrinfo failed"}, {"error": "No such host is known"}]) is True
    assert sipalg._name_failed([{"error": "timed out"}]) is False


# --------------------------------------------------------------------------- finding the server (RFC 3263)
def _srv(*rows):
    """A dns_lookup stand-in: rows are (prefix, "priority weight port target")."""
    def lookup(name, record_type=None):
        want = [value for prefix, value in rows if name == prefix + "example.net"]
        return {"ok": True, "records": [{"type": "SRV", "name": name, "value": v} for v in want]}
    return lookup

def test_a_sip_domain_is_followed_through_srv_the_way_a_phone_does():
    """What a tech reads off a phone is the SIP domain, not a host with an A record. A phone looks up
    _sip._udp.<domain> and talks to what it names; without doing the same this answered "does not resolve" for
    the exact string the phones are configured with."""
    targets = sipalg.srv_targets("example.net", _srv(("_sip._udp.", "10 20 5060 sbc1.example.net")))
    assert targets == [("sbc1.example.net", 5060, "_sip._udp.")]

def test_srv_targets_come_back_in_the_order_rfc_2782_says_to_try_them():
    lookup = _srv(("_sip._udp.", "20 10 5060 third.example.net"),
                  ("_sip._udp.", "10 10 5060 second.example.net"),
                  ("_sip._udp.", "10 90 5061 first.example.net"))
    assert [t for t, _p, _x in sipalg.srv_targets("example.net", lookup)] == [
        "first.example.net", "second.example.net", "third.example.net"], "lowest priority, then highest weight"

def test_udp_wins_over_tcp_so_one_result_never_mixes_transports():
    lookup = _srv(("_sip._udp.", "10 10 5060 udp.example.net"), ("_sip._tcp.", "1 10 5060 tcp.example.net"))
    assert sipalg.srv_targets("example.net", lookup)[0][0] == "udp.example.net"

def test_a_domain_with_no_srv_record_falls_back_to_the_name_itself():
    assert sipalg.srv_targets("example.net", lambda name, record_type=None: {"ok": True, "records": []}) == []
    assert sipalg.srv_targets("example.net", lambda name, record_type=None: {"ok": False}) == []

def test_a_resolver_that_blows_up_is_not_allowed_to_sink_the_check():
    def broken(name, record_type=None):
        raise RuntimeError("no resolver")
    assert sipalg.srv_targets("example.net", broken) == []

def test_a_malformed_srv_row_is_skipped_rather_than_sinking_the_others():
    """One bad row in a zone should not stop the other target being tried."""
    lookup = _srv(("_sip._udp.", "not a record"), ("_sip._udp.", "10 10 0 bad-port.example.net"),
                  ("_sip._udp.", "10 10 5060 good.example.net"))
    assert [t for t, _p, _x in sipalg.srv_targets("example.net", lookup)] == ["good.example.net"]

def test_the_rfc_2782_way_of_saying_no_service_is_honoured():
    """A single "." target means the service is deliberately not offered."""
    assert sipalg.srv_targets("example.net", _srv(("_sip._udp.", "0 0 5060 ."))) == []

def test_an_ip_literal_is_never_looked_up_as_a_domain(pbx):
    server = pbx()
    asked = []
    checker = AlgChecker(timeout_s=1.5, lookup=lambda name, record_type=None: asked.append(name) or {"ok": False})
    checker.check("127.0.0.1", server.port)
    assert asked == [], "an address has no SRV record to follow"

def test_a_non_standard_port_means_the_tech_named_a_host_not_a_domain(pbx):
    """Typing 5065 is saying "this exact server on this exact port": following SRV would ignore what was asked.
    The test is the standard port rather than "no port given", because the API fills the configured sip.port in
    before the checker ever sees it — "no port" never arrives here."""
    server = pbx()
    asked = []
    checker = AlgChecker(timeout_s=1.5, lookup=lambda name, record_type=None: asked.append(name) or {"ok": False})
    checker.check("example.net", 5065)
    assert asked == [], "a named port is taken at its word"

def test_the_standard_port_still_follows_srv_because_it_means_nothing_was_asked_for(pbx):
    server = pbx()
    asked = []

    def lookup(name, record_type=None):
        asked.append(name)
        return {"ok": True, "records": [{"type": "SRV", "name": name,
                                         "value": f"10 10 {server.port} 127.0.0.1"}]} if "_udp" in name else {"ok": False}

    result = AlgChecker(timeout_s=1.5, lookup=lookup).check("example.net", 5060)
    assert asked == ["_sip._udp.example.net"]
    assert result["via_srv"]["host"] == "127.0.0.1" and result["via_srv"]["port"] == server.port

def test_the_result_says_which_server_the_domain_sent_it_to(pbx):
    server = pbx()
    lookup = _srv(("_sip._udp.", f"10 10 {server.port} 127.0.0.1"))
    result = AlgChecker(timeout_s=1.5, lookup=lookup).check("example.net")
    assert list(result) == list(ALG_KEYS)
    assert list(result["via_srv"]) == list(sipalg.SRV_KEYS)
    assert result["via_srv"] == {"domain": "example.net", "host": "127.0.0.1", "port": server.port,
                                 "transport": "udp"}
    assert result["host"] == "127.0.0.1" and result["port"] == server.port
    srv = next(f for f in result["findings"] if f["id"] == "alg.srv")
    assert "SIP domain, not a host" in srv["title"] and "127.0.0.1" in srv["detail"]

def test_a_host_reached_directly_carries_no_srv_note(pbx):
    server = pbx()
    result = AlgChecker(timeout_s=1.5).check("127.0.0.1", server.port)
    assert result["via_srv"] is None
    assert "alg.srv" not in [f["id"] for f in result["findings"]]
