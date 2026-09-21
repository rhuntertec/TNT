"""SIP call analysis and the STUN NAT check must give the right verdict, not merely a verdict.

Each test here is a fault-finder accuracy case that 1.21.2 got wrong:

* a call challenged for credentials (401/407) and then answered read as "The call failed: 401 Unauthorized";
* an RTP timestamp wrap produced millions of milliseconds of jitter on a perfectly even stream;
* packets that arrived out of order were counted as lost, so a complete stream raised "Audio packets were lost";
* a dynamic payload type (Opus, iLBC, AMR) never got a jitter figure, and the call then read as clean;
* a NAT that keeps the source port (OpenWrt, UniFi, MikroTik, Cisco IOS) was reported as "not behind NAT".

Pure code only - the tracker fed parsed SIP and RTP, sipflow's own ladder and finding builders, the STUN verdict fed
rows and, for the one whole-path check, fake STUN servers on loopback. Documentation addresses only.
"""
from __future__ import annotations

import random
import socket
import struct
import threading
from typing import Iterable, List, Optional, Sequence

import pytest

from tnt import sipcalls, sipflow, sipnat
from tnt.sipcalls import CallTracker, parse_rtp, parse_sip, ulaw_to_pcm16
from tnt.sipnat import MAGIC_COOKIE, StunChecker

ALICE, BOB = "192.0.2.10", "198.51.100.20"
ALICE_RTP, BOB_RTP = 40000, 40002
CALL_ID = "accuracy-1@192.0.2.10"
SSRC_A, SSRC_B = 0x11223344, 0x55667788
SAMPLES = 160
CRLF = "\r\n"


# --------------------------------------------------------------------------- building messages
def sdp_body(address: str, port: int, formats: str = "0", rtpmap: Sequence[str] = ("0 PCMU/8000",)) -> str:
    lines = ["v=0", f"o=- 20 20 IN IP4 {address}", "s=call", f"c=IN IP4 {address}", "t=0 0",
             f"m=audio {port} RTP/AVP {formats}", *[f"a=rtpmap:{entry}" for entry in rtpmap], "a=sendrecv"]
    return CRLF.join(lines) + CRLF


def message(start: str, *headers: str, cseq: str, body: str = "") -> dict:
    lines = [start, f"Via: SIP/2.0/UDP {ALICE}:5060;branch=z9hG4bK-{cseq.replace(' ', '-')}",
             f'From: "Alice" <sip:alice@{BOB}>;tag=alice-1', f"To: <sip:bob@{BOB}>", f"Call-ID: {CALL_ID}",
             f"CSeq: {cseq}", *headers]
    if body:
        lines.append("Content-Type: application/sdp")
    lines += [f"Content-Length: {len(body.encode())}", "", body]
    parsed = parse_sip(CRLF.join(lines).encode())
    assert parsed is not None
    return parsed


def invite(cseq: int, *headers: str, body: Optional[str] = None) -> dict:
    return message(f"INVITE sip:bob@{BOB} SIP/2.0", *headers, cseq=f"{cseq} INVITE",
                   body=sdp_body(ALICE, ALICE_RTP) if body is None else body)


def reply(status: str, cseq: int, method: str = "INVITE", *headers: str, body: str = "") -> dict:
    return message(f"SIP/2.0 {status}", *headers, cseq=f"{cseq} {method}", body=body)


def request(method: str, cseq: int) -> dict:
    return message(f"{method} sip:bob@{BOB} SIP/2.0", cseq=f"{cseq} {method}")


def rtp(seq: int, stamp: int, payload: bytes = b"\xff" * SAMPLES, *, pt: int = 0, ssrc: int = SSRC_A) -> dict:
    parsed = parse_rtp(struct.pack(">BBHII", 0x80, pt, seq & 0xFFFF, stamp & 0xFFFFFFFF, ssrc) + payload)
    assert parsed is not None
    return parsed


def to_bob(tracker: CallTracker, msg: dict, ts: float) -> None:
    tracker.add_sip(msg, ts, ALICE, 5060, BOB, 5060)


def to_alice(tracker: CallTracker, msg: dict, ts: float) -> None:
    tracker.add_sip(msg, ts, BOB, 5060, ALICE, 5060)


def both_ways_audio(tracker: CallTracker, start: float, count: int = 10) -> None:
    for i in range(count):
        tracker.add_rtp(rtp(i, i * SAMPLES), start + i * 0.02, ALICE, ALICE_RTP, BOB, BOB_RTP)
        tracker.add_rtp(rtp(i, i * SAMPLES, ssrc=SSRC_B), start + 0.01 + i * 0.02, BOB, BOB_RTP, ALICE, ALICE_RTP)


def findings_for(call: dict) -> List[dict]:
    """Exactly what FlowReader.view() does for a single-sided call."""
    sides = {"a": call}
    return sipflow.call_findings(sides, sipflow.build_ladder(sides), sipflow._stream_rows(sides), two_sided=False)


# --------------------------------------------------------------------------- 1. the credential challenge
CHALLENGES = [("401 Unauthorized", "WWW-Authenticate", "Authorization"),
              ("407 Proxy Authentication Required", "Proxy-Authenticate", "Proxy-Authorization")]


def challenged_call(challenge: str, ask: str, answer: str, *, with_bye: bool, with_audio: bool = True,
                    retried: bool = True, retry_status: str = "200 OK") -> CallTracker:
    """INVITE (CSeq 1) -> 401/407 -> ACK -> INVITE with credentials (CSeq 2) -> 100 -> 180 -> 200 -> ACK -> RTP.

    The path nearly every call through Asterisk, FreePBX, 3CX or an authenticating trunk takes."""
    tracker = CallTracker()
    to_bob(tracker, invite(1), 100.0)
    to_alice(tracker, reply(challenge, 1, "INVITE", f'{ask}: Digest realm="pbx", nonce="abc"'), 100.05)
    to_bob(tracker, request("ACK", 1), 100.06)
    if not retried:
        return tracker
    to_bob(tracker, invite(2, f'{answer}: Digest username="alice", realm="pbx", nonce="abc", response="0"'), 100.10)
    to_alice(tracker, reply("100 Trying", 2), 100.15)
    to_alice(tracker, reply("180 Ringing", 2), 100.50)
    final = retry_status.startswith("2")
    to_alice(tracker, reply(retry_status, 2, body=sdp_body(BOB, BOB_RTP) if final else ""), 103.0)
    to_bob(tracker, request("ACK", 2), 103.05)
    if final and with_audio:
        both_ways_audio(tracker, 103.10)
    if final and with_bye:
        to_bob(tracker, request("BYE", 3), 160.0)
        to_alice(tracker, reply("200 OK", 3, "BYE"), 160.05)
    return tracker


@pytest.mark.parametrize("challenge,ask,answer", CHALLENGES)
@pytest.mark.parametrize("with_bye", [True, False])
def test_a_call_challenged_for_credentials_and_then_answered_is_answered(challenge, ask, answer, with_bye):
    [call] = challenged_call(challenge, ask, answer, with_bye=with_bye).calls()
    assert call["answer_ts"] == 103.0
    assert call["state"] == ("ended" if with_bye else "answered")
    assert call["status"] == 200
    if with_bye:
        assert call["end_ts"] == 160.0 and call["duration_s"] == 57.0      # from the answer, not from the INVITE
    else:
        assert call["end_ts"] is None


@pytest.mark.parametrize("challenge,ask,answer", CHALLENGES)
def test_a_challenge_that_was_answered_with_credentials_is_not_reported_as_a_failed_call(challenge, ask, answer):
    [call] = challenged_call(challenge, ask, answer, with_bye=True).calls()
    ids = [f["id"] for f in findings_for(call)]
    assert "flow.failed" not in ids
    assert ids == ["flow.ok"]


def test_one_way_audio_is_still_found_on_a_challenged_call_captured_mid_way():
    tracker = challenged_call(*CHALLENGES[0], with_bye=False, with_audio=False)
    for i in range(10):                                  # the PBX's audio never arrives
        tracker.add_rtp(rtp(i, i * SAMPLES), 103.1 + i * 0.02, ALICE, ALICE_RTP, BOB, BOB_RTP)
    [call] = tracker.calls()
    assert call["state"] == "answered"
    assert "flow.oneway" in [f["id"] for f in findings_for(call)]


def test_no_media_is_still_found_on_a_challenged_call_captured_mid_way():
    [call] = challenged_call(*CHALLENGES[0], with_bye=False, with_audio=False).calls()
    assert "flow.nomedia" in [f["id"] for f in findings_for(call)]


@pytest.mark.parametrize("challenge,ask,answer", CHALLENGES)
def test_a_challenge_that_was_never_retried_is_a_failure_and_says_it_was_a_challenge(challenge, ask, answer):
    [call] = challenged_call(challenge, ask, answer, with_bye=False, retried=False).calls()
    assert call["state"] == "failed" and call["status"] == int(challenge[:3])
    found = {f["id"]: f for f in findings_for(call)}
    failed = found["flow.failed"]
    assert failed["level"] == "bad"
    assert challenge.split(" ", 1)[1].lower() in failed["title"].lower()
    words = f"{failed['title']} {failed['detail']} {failed['advice']}".lower()
    assert "credentials" in words and "never" in words
    # the advice must not call the very thing it headlines as a failure "not a failure"
    assert "not a failure" not in words


def test_a_retry_that_is_refused_is_the_failure_the_call_reports_not_the_challenge():
    [call] = challenged_call(*CHALLENGES[0], with_bye=False, retry_status="403 Forbidden").calls()
    assert call["state"] == "failed" and call["status"] == 403
    failed = {f["id"]: f for f in findings_for(call)}["flow.failed"]
    assert "forbidden" in failed["title"].lower() and "unauthorized" not in failed["title"].lower()


def test_a_retransmitted_first_invite_does_not_reopen_a_challenged_call():
    """The same CSeq again is the original INVITE crossing the 401 on the wire, not a retry with credentials."""
    tracker = challenged_call(*CHALLENGES[0], with_bye=False, retried=False)
    to_bob(tracker, invite(1), 100.07)
    to_alice(tracker, reply("401 Unauthorized", 1, "INVITE", 'WWW-Authenticate: Digest realm="pbx"'), 100.08)
    [call] = tracker.calls()
    assert call["state"] == "failed" and call["end_ts"] == 100.05


def test_a_late_copy_of_the_challenge_does_not_fail_the_retry():
    tracker = challenged_call(*CHALLENGES[0], with_bye=False, with_audio=False)
    to_alice(tracker, reply("401 Unauthorized", 1, "INVITE", 'WWW-Authenticate: Digest realm="pbx"'), 103.5)
    [call] = tracker.calls()
    assert call["state"] == "answered" and call["status"] == 200 and call["end_ts"] is None


def test_a_call_that_is_answered_stays_answered_when_a_re_invite_is_refused():
    """A mid-call re-INVITE (hold, a codec change) with a higher CSeq is not a retry: the call is not reopened."""
    tracker = challenged_call(*CHALLENGES[0], with_bye=False, with_audio=False)
    to_bob(tracker, invite(3), 110.0)
    to_alice(tracker, reply("491 Request Pending", 3), 110.1)
    [call] = tracker.calls()
    assert call["state"] == "answered" and call["answer_ts"] == 103.0


def test_the_callees_own_re_invite_does_not_hide_the_answer_to_the_callers():
    """Each end numbers its own requests (RFC 3261 8.1.1.5), and a callee's CSeq can start anywhere. Its re-INVITE
    at CSeq 9000 is not newer than the caller's re-INVITE at CSeq 3: the two are in different number spaces."""
    tracker = challenged_call(*CHALLENGES[0], with_bye=False, with_audio=False)
    to_alice(tracker, invite(9000), 110.0)                  # Bob's re-INVITE (hold), Bob -> Alice
    to_bob(tracker, reply("200 OK", 9000, body=sdp_body(ALICE, ALICE_RTP)), 110.1)
    to_bob(tracker, invite(3), 120.0)                       # Alice's own re-INVITE, refused
    to_alice(tracker, reply("488 Not Acceptable Here", 3), 120.1)
    [call] = tracker.calls()
    assert call["state"] == "answered" and call["answer_ts"] == 103.0
    assert call["status"] == 488                            # the last final answer to an INVITE, as documented
    failed = {f["id"]: f for f in findings_for(call)}.get("flow.failed")
    assert failed is not None and failed["evidence"]["status"] == 488


def _msg(ts: float, kind: str, src: str, dst: str, cseq: int, *, method: Optional[str] = None,
         status: Optional[int] = None, cseq_method: str = "INVITE") -> dict:
    return {"ts": ts, "kind": kind, "method": method, "status": status, "reason": None, "src": src, "dst": dst,
            "cseq": cseq, "cseq_method": cseq_method, "has_sdp": False}


PHONE, SBC_IN, SBC_OUT, CARRIER = "192.0.2.10:5060", "192.0.2.1:5060", "198.51.100.1:5060", "198.51.100.20:5060"


def _two_legs(a_messages: List[dict], b_messages: List[dict]) -> List[dict]:
    """Two captures of one call either side of an SBC, which gives each leg its own Call-ID and its own CSeq."""
    sides = {"a": {"state": "calling", "status": None, "messages": a_messages},
             "b": {"state": "failed", "status": None, "messages": b_messages}}
    return sipflow.call_findings(sides, sipflow.build_ladder(sides), [], two_sided=True)


def test_a_carriers_refusal_on_the_far_leg_is_not_superseded_by_a_retry_on_the_near_leg():
    """Leg A: the SBC challenged the phone, which retried at CSeq 102. Leg B: the SBC's INVITE at CSeq 1 was refused
    503 by the carrier. CSeq 102 on one leg says nothing about CSeq 1 on the other, so the 503 is the failure."""
    found = _two_legs(
        [_msg(0.00, "request", PHONE, SBC_IN, 101, method="INVITE"),
         _msg(0.01, "response", SBC_IN, PHONE, 101, status=407),
         _msg(0.02, "request", PHONE, SBC_IN, 101, method="ACK", cseq_method="ACK"),
         _msg(0.03, "request", PHONE, SBC_IN, 102, method="INVITE")],
        [_msg(0.05, "request", SBC_OUT, CARRIER, 1, method="INVITE"),
         _msg(0.20, "response", CARRIER, SBC_OUT, 1, status=503),
         _msg(0.21, "request", SBC_OUT, CARRIER, 1, method="ACK", cseq_method="ACK")])
    failed = {f["id"]: f for f in found}.get("flow.failed")
    assert failed is not None and failed["level"] == "bad"
    assert failed["evidence"]["status"] == 503


def test_a_high_cseq_on_the_far_leg_does_not_hide_the_near_legs_own_refusal():
    found = _two_legs(
        [_msg(0.00, "request", PHONE, SBC_IN, 1, method="INVITE"),
         _msg(0.10, "response", SBC_IN, PHONE, 1, status=486)],
        [_msg(0.05, "request", SBC_OUT, CARRIER, 31337, method="INVITE"),
         _msg(0.20, "response", CARRIER, SBC_OUT, 31337, status=480)])
    failed = {f["id"]: f for f in found}.get("flow.failed")
    assert failed is not None and failed["evidence"]["status"] == 486


def test_a_challenge_retried_on_the_same_leg_is_still_not_the_failure_with_two_captures():
    """The same Call-ID seen by both captures (no SBC between them): the retry supersedes the challenge on each."""
    leg = [_msg(0.00, "request", PHONE, CARRIER, 1, method="INVITE"),
           _msg(0.05, "response", CARRIER, PHONE, 1, status=401),
           _msg(0.06, "request", PHONE, CARRIER, 1, method="ACK", cseq_method="ACK"),
           _msg(0.10, "request", PHONE, CARRIER, 2, method="INVITE"),
           _msg(3.00, "response", CARRIER, PHONE, 2, status=200),
           _msg(3.05, "request", PHONE, CARRIER, 2, method="ACK", cseq_method="ACK")]
    found = _two_legs([dict(m) for m in leg], [dict(m, ts=m["ts"] + 0.001) for m in leg])
    assert "flow.failed" not in [f["id"] for f in found]


# --------------------------------------------------------------------------- 2. jitter across a timestamp wrap
def test_a_timestamp_wrap_does_not_turn_an_even_stream_into_millions_of_milliseconds_of_jitter():
    tracker = CallTracker()
    to_bob(tracker, invite(1), 100.0)
    to_alice(tracker, reply("200 OK", 1, body=sdp_body(BOB, BOB_RTP)), 101.0)
    start = 0xFFFFFCDF                                     # the field wraps between the 5th and 6th packet
    for i in range(40):
        tracker.add_rtp(rtp(i, start + i * SAMPLES), 101.1 + i * 0.02, ALICE, ALICE_RTP, BOB, BOB_RTP)
    [stream] = tracker.calls()[0]["streams"]
    assert stream["jitter_ms"] is not None and stream["jitter_ms"] < 0.01
    assert "flow.jitter" not in [f["id"] for f in findings_for(tracker.calls()[0])]


# --------------------------------------------------------------------------- 3. reordering is not loss
def _stream_over(order: Iterable[int], base: int = 0) -> sipcalls._Stream:
    stream = sipcalls._Stream("x", ALICE, ALICE_RTP, BOB, BOB_RTP, SSRC_A, 0, "PCMU", 101.0)
    for index, seq in enumerate(order):
        stream.count((base + seq) & 0xFFFF, 101.0 + index * 0.02, 172, 1000 + seq * SAMPLES)
    return stream


def test_packets_that_arrive_out_of_order_are_not_lost():
    stream = _stream_over([0, 1, 3, 2, 4, 5, 7, 6, 8, 9])  # every one of 0..9 exactly once
    assert (stream.packets, stream.lost, stream.out_of_order) == (10, 0, 2)


def test_a_complete_reordered_stream_raises_no_loss_finding_and_rebuilds_whole():
    tracker = CallTracker()
    to_bob(tracker, invite(1), 100.0)
    to_alice(tracker, reply("200 OK", 1, body=sdp_body(BOB, BOB_RTP)), 101.0)
    to_bob(tracker, request("ACK", 1), 101.01)
    tone = bytes(range(SAMPLES))
    for index, seq in enumerate([0, 1, 3, 2, 4, 5, 7, 6, 8, 9]):
        tracker.add_rtp(rtp(seq, 1000 + seq * SAMPLES, tone), 101.1 + index * 0.02, ALICE, ALICE_RTP, BOB, BOB_RTP)
    for i in range(10):
        tracker.add_rtp(rtp(i, i * SAMPLES, ssrc=SSRC_B), 101.11 + i * 0.02, BOB, BOB_RTP, ALICE, ALICE_RTP)
    call = tracker.calls()[0]
    forward = next(s for s in call["streams"] if s["ssrc"] == SSRC_A)
    assert forward["lost"] == 0
    assert tracker.audio(forward["id"])[44:] == ulaw_to_pcm16(tone * 10)
    rows = sipflow._stream_rows({"a": call})
    assert all(row["loss_pct"] == 0.0 for row in rows)
    assert "flow.loss" not in [f["id"] for f in findings_for(call)]


def test_five_minutes_of_light_reordering_does_not_read_as_one_percent_loss():
    order = list(range(15000))
    swaps = range(96, len(order) - 1, 96)                  # about 1 % of packets displaced by one slot
    for i in swaps:
        order[i], order[i + 1] = order[i + 1], order[i]
    stream = _stream_over(order)
    assert stream.lost == 0 and stream.out_of_order == len(swaps)


def test_real_loss_is_still_counted():
    stream = _stream_over([0, 1, 3, 4, 5, 7, 8, 9])        # 2 and 6 really missing
    assert (stream.packets, stream.lost, stream.out_of_order) == (8, 2, 0)


def test_a_duplicate_is_neither_loss_nor_reordering_and_cannot_give_back_loss_twice():
    stream = _stream_over([0, 1, 3, 2, 2, 3, 1, 5])        # 2 late once; then 2, 3, 1 again; 4 really missing
    assert (stream.packets, stream.lost, stream.out_of_order) == (8, 1, 1)


def test_reordering_across_the_sequence_wrap_is_not_loss():
    stream = _stream_over([0, 1, 3, 2, 4, 5], base=0xFFFD)  # 0xFFFD, 0xFFFE, 0x0000, 0xFFFF, 0x0001, 0x0002
    assert (stream.lost, stream.out_of_order) == (0, 1)


def test_a_hole_left_a_whole_sequence_cycle_ago_is_not_filled_by_the_same_number_now():
    """A 16-bit sequence repeats every 65536 packets: the old hole must not be given back by a packet that is only
    behind the newest by a little and happens to carry the same number."""
    stream = _stream_over([0, 2])                           # 1 missing
    for n in range(3, 0x10000 + 3):                         # a full cycle later, still in order
        stream.count(n & 0xFFFF, 200.0, 172, n * SAMPLES)
    assert stream.lost == 1
    stream.count(1, 200.0, 172, 0)                          # 0x0001 again: a duplicate of the one just seen
    assert (stream.lost, stream.out_of_order) == (1, 0)


def test_a_restarted_stream_is_still_not_loss():
    stream = _stream_over([0, 1, 2])
    stream.count(30000, 102.0, 172, 0)                      # the phone restarted its sequence
    stream.count(30001, 102.02, 172, SAMPLES)
    assert stream.lost == 0


# --------------------------------------------------------------------------- 4. jitter on a dynamic payload type
PACKETS = 200


def jittery_call(pt: int, rtpmap: Sequence[str], step: int, *, sdp: bool = True) -> dict:
    """An answered two-way call on payload type *pt*, every packet delayed by up to 150 ms, ended with a BYE."""
    tracker = CallTracker()
    formats = str(pt)
    offer = sdp_body(ALICE, ALICE_RTP, formats, rtpmap) if sdp else sdp_body(ALICE, ALICE_RTP, formats, ())
    to_bob(tracker, invite(1, body=offer), 100.0)
    answer = sdp_body(BOB, BOB_RTP, formats, rtpmap) if sdp else sdp_body(BOB, BOB_RTP, formats, ())
    to_alice(tracker, reply("200 OK", 1, body=answer), 101.0)
    to_bob(tracker, request("ACK", 1), 101.01)
    for ssrc, seed, src, sport, dst, dport in ((SSRC_A, 7, ALICE, ALICE_RTP, BOB, BOB_RTP),
                                               (SSRC_B, 11, BOB, BOB_RTP, ALICE, ALICE_RTP)):
        rng = random.Random(seed)
        for i in range(PACKETS):
            when = 101.1 + i * 0.02 + rng.uniform(0.0, 0.15)
            tracker.add_rtp(rtp(i, 1000 + i * step, bytes(60), pt=pt, ssrc=ssrc), when, src, sport, dst, dport)
    to_bob(tracker, request("BYE", 2), 106.0)
    [call] = tracker.calls()
    return call


@pytest.mark.parametrize("pt,rtpmap,step,name", [
    (111, ("111 opus/48000/2",), 960, "opus"),             # RFC 7587: the Opus RTP clock is always 48 kHz
    (97, ("97 iLBC/8000",), 160, "iLBC"),
    (98, ("98 AMR-WB/16000",), 320, "AMR-WB"),
    (100, ("100 speex/16000",), 320, "speex"),
])
def test_a_dynamic_payload_type_gets_its_jitter_from_the_sdp_clock_rate(pt, rtpmap, step, name):
    control = jittery_call(0, ("0 PCMU/8000",), 160)
    call = jittery_call(pt, rtpmap, step)
    assert {s["codec"] for s in call["streams"]} == {name}
    by_ssrc = {s["ssrc"]: s["jitter_ms"] for s in control["streams"]}
    for stream in call["streams"]:
        # the same arrival pattern, measured in the codec's own clock, is the same jitter in milliseconds
        assert stream["jitter_ms"] == pytest.approx(by_ssrc[stream["ssrc"]], abs=0.01)
        assert stream["jitter_ms"] >= sipflow.JITTER_WARN_MS
    ids = [f["id"] for f in findings_for(call)]
    assert "flow.jitter" in ids and "flow.ok" not in ids


def test_a_dynamic_payload_type_without_its_sdp_says_jitter_was_not_measured_rather_than_clean():
    call = jittery_call(111, (), 960, sdp=False)
    assert all(s["jitter_ms"] is None for s in call["streams"])
    found = {f["id"]: f for f in findings_for(call)}
    assert "flow.jitter" not in found
    ok = found.get("flow.ok")
    assert ok is not None
    assert "clean" not in (ok["detail"] or "").lower()
    assert "jitter" in (ok["detail"] or "").lower() and "not" in (ok["detail"] or "").lower()


def test_jitter_measured_over_only_the_last_few_packets_is_not_reported():
    """The rtpmap turned up only in a re-INVITE near the end: four steps of the estimator are not a measurement, and
    an answer of 0.0 from them would let the call read as clean."""
    tracker = CallTracker()
    to_bob(tracker, invite(1, body=sdp_body(ALICE, ALICE_RTP, "111", ())), 100.0)
    to_alice(tracker, reply("200 OK", 1, body=sdp_body(BOB, BOB_RTP, "111", ())), 101.0)
    to_bob(tracker, request("ACK", 1), 101.01)
    rng = random.Random(3)

    def burst(first: int, count: int) -> None:
        for i in range(first, first + count):
            when = 101.1 + i * 0.02
            for ssrc, src, sport, dst, dport in ((SSRC_A, ALICE, ALICE_RTP, BOB, BOB_RTP),
                                                 (SSRC_B, BOB, BOB_RTP, ALICE, ALICE_RTP)):
                tracker.add_rtp(rtp(i, 1000 + i * 960, bytes(60), pt=111, ssrc=ssrc),
                                when + rng.uniform(0.0, 0.15), src, sport, dst, dport)

    burst(0, 190)
    to_bob(tracker, invite(2, body=sdp_body(ALICE, ALICE_RTP, "111", ("111 opus/48000/2",))), 105.0)
    to_alice(tracker, reply("200 OK", 2, body=sdp_body(BOB, BOB_RTP, "111", ("111 opus/48000/2",))), 105.01)
    burst(190, 5)
    to_bob(tracker, request("BYE", 3), 106.0)
    [call] = tracker.calls()
    assert {s["codec"] for s in call["streams"]} == {"opus"}
    assert all(s["jitter_ms"] is None for s in call["streams"])
    ok = {f["id"]: f for f in findings_for(call)}.get("flow.ok")
    assert ok is not None and "not measured" in ok["detail"]


def test_a_short_stream_measured_from_its_first_packet_still_reports_jitter():
    """The minimum is on packets the estimator missed, not on short streams: five even G.711 packets, every step
    measured, still give a figure."""
    stream = _stream_over(range(5))
    assert sipcalls._stream_dict(stream)["jitter_ms"] == 0.0


def test_an_absurd_clock_rate_in_the_sdp_is_not_used():
    call = jittery_call(111, ("111 opus/99999999999",), 960)
    assert all(s["jitter_ms"] is None for s in call["streams"])


# --------------------------------------------------------------------------- 5. STUN behind a port-preserving NAT
PUBLIC = "203.0.113.9"


def _rows(ip: str, port: int) -> List[dict]:
    return [{"host": host, "port": 3478, "answered": True, "mapped_ip": ip, "mapped_port": port,
             "elapsed_ms": 12.0, "error": None} for host in ("stun-a.example", "stun-b.example")]


def test_a_nat_that_keeps_the_source_port_is_still_a_nat():
    """OpenWrt, UniFi, MikroTik masquerade, Cisco IOS overload: the WAN address with the socket's own port."""
    result = StunChecker()._verdict(_rows(PUBLIC, 50000), 50000, 0, True, local_ips={"192.0.2.77"})
    ids = [f["id"] for f in result["findings"]]
    assert result["mapping"] == "endpoint-independent" and "nat.cone" in ids and "nat.none" not in ids
    assert result["port_preserved"] is True


def test_the_servers_seeing_this_pcs_own_address_and_port_is_no_nat():
    result = StunChecker()._verdict(_rows(PUBLIC, 50000), 50000, 0, True, local_ips={PUBLIC})
    assert result["mapping"] == "none"
    assert [f["id"] for f in result["findings"]] == ["nat.none"]


def test_no_nat_is_never_claimed_when_the_pcs_own_address_is_not_known():
    result = StunChecker()._verdict(_rows(PUBLIC, 50000), 50000, 0, True)
    assert result["mapping"] != "none"
    result = StunChecker()._verdict(_rows(PUBLIC, 50000), 50000, 0, True, local_ips=set())
    assert result["mapping"] != "none"


class _FakeStun:
    """Answers every Binding Request with the address and port it is told to report."""

    def __init__(self, mapped: tuple) -> None:
        self.mapped = mapped
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
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
            if len(data) < 20:
                continue
            ip, port = self.mapped
            value = (bytes([0, 0x01]) + struct.pack(">H", port ^ (MAGIC_COOKIE >> 16))
                     + bytes(a ^ b for a, b in zip(bytes(int(x) for x in ip.split(".")),
                                                   struct.pack(">I", MAGIC_COOKIE))))
            attr = struct.pack(">HH", 0x0020, len(value)) + value
            self.sock.sendto(struct.pack(">HHI", 0x0101, len(attr), MAGIC_COOKIE) + data[8:20] + attr, peer)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()


def test_the_whole_check_compares_the_mapped_address_with_the_one_this_pc_sends_from(monkeypatch):
    monkeypatch.setattr(sipnat, "_source_address", lambda host, port: "192.0.2.77")   # a LAN address, not PUBLIC
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("", 0))
    mine = probe.getsockname()[1]
    probe.close()
    servers = [_FakeStun((PUBLIC, mine)), _FakeStun((PUBLIC, mine))]                  # a port-preserving NAT
    try:
        result = StunChecker(timeout_s=1.5).check([("127.0.0.1", s.port) for s in servers], local_port=mine)
    finally:
        for server in servers:
            server.close()
    if result["local_port"] != mine:
        pytest.skip("the port was taken between picking it and binding it")
    assert result["mapping"] == "endpoint-independent"
    assert "nat.none" not in [f["id"] for f in result["findings"]]


def test_the_source_address_lookup_sends_nothing_and_answers_an_address():
    """A UDP connect() is a route lookup; it must give an address or None, never raise."""
    found = sipnat._source_address("127.0.0.1", 3478)
    assert found == "127.0.0.1"
    assert sipnat._source_address("", 0) is None
