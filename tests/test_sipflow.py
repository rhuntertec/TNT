"""tnt.sipflow: SIP call flows read out of one or two capture files, merged and diagnosed.

The invented call is one INVITE / 180 / 200 / ACK / BYE / 200 between a phone on 192.0.2.50 and a phone system on
198.51.100.20, written into real pcapng files. The two-sided cases write the *same* call twice: once as the client
saw it and once as the server did, with a clock offset between the captures and - where the test is about an ALG -
a Contact the middlebox rewrote on the way through. Nothing here touches a network.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from tnt import pcapng, sipflow
from tnt.sipflow import (FINDING_IDS, FINDING_KEYS, FLOW_KEYS, FLOWCALL_KEYS, LADDER_KEYS, SKEW_KEYS, SOURCE_KEYS,
                         STREAM_KEYS, FlowError, FlowReader, build_ladder, estimate_skew, pair_across_sbc)

PHONE, PBX = "192.0.2.50", "198.51.100.20"
PHONE_MAC, PBX_MAC = bytes.fromhex("02005e100001"), bytes.fromhex("02005e100002")
CALL_ID = "a84b4c76e66710@192.0.2.50"
PHONE_RTP, PBX_RTP = 16402, 20002
SSRC_PHONE, SSRC_PBX = 0x11223344, 0x55667788


# --------------------------------------------------------------------------- frames
def _eth(dst: bytes, src: bytes, payload: bytes) -> bytes:
    return dst + src + struct.pack(">H", 0x0800) + payload


def _ipv4(src: str, dst: str, payload: bytes) -> bytes:
    head = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0, 64, 17, 0)
    head += bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))
    return head + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def frame(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    out = PHONE_MAC if src == PBX else PBX_MAC
    return _eth(out, PHONE_MAC if src == PHONE else PBX_MAC, _ipv4(src, dst, _udp(sport, dport, payload)))


def sip(start: str, *, contact: str, cseq: str = "1 INVITE", sdp: bool = False, extra: str = "") -> bytes:
    body = ("v=0\r\no=- 1 1 IN IP4 " + PHONE + "\r\ns=call\r\nc=IN IP4 " + PHONE + "\r\nt=0 0\r\n"
            "m=audio " + str(PHONE_RTP) + " RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n") if sdp else ""
    head = (f"{start}\r\n"
            f"Via: SIP/2.0/UDP {PHONE}:5060;branch=z9hG4bK-{cseq.split()[0]}\r\n"
            f"From: <sip:2001@{PBX}>;tag=aaa111\r\n"
            f"To: <sip:2002@{PBX}>\r\n"
            f"Call-ID: {CALL_ID}\r\n"
            f"CSeq: {cseq}\r\n"
            f"Contact: <{contact}>\r\n"
            f"User-Agent: TEC-Phone/3.4.1\r\n"
            + extra
            + (f"Content-Type: application/sdp\r\nContent-Length: {len(body)}\r\n" if sdp
               else "Content-Length: 0\r\n")
            + "\r\n")
    return (head + body).encode("utf-8")


def rtp(ssrc: int, seq: int, stamp: int) -> bytes:
    return struct.pack("!BBHII", 0x80, 0, seq & 0xFFFF, stamp & 0xFFFFFFFF, ssrc) + b"\xff" * 160


#: (offset from the call's start, from, to, sport, dport, payload-builder) for one clean call
def call_script(contact: str, *, with_media: bool = True, both_ways: bool = True, answer: bool = True,
                ack: bool = True, failure: str = None):
    out = [
        (0.00, PHONE, PBX, 5060, 5060, sip(f"INVITE sip:2002@{PBX} SIP/2.0", contact=contact, sdp=True)),
        (0.05, PBX, PHONE, 5060, 5060, sip("SIP/2.0 100 Trying", contact=contact)),
        (0.30, PBX, PHONE, 5060, 5060, sip("SIP/2.0 180 Ringing", contact=contact)),
    ]
    if failure:
        out.append((2.0, PBX, PHONE, 5060, 5060, sip(f"SIP/2.0 {failure}", contact=contact)))
        return out
    if answer:
        out.append((2.00, PBX, PHONE, 5060, 5060, sip("SIP/2.0 200 OK", contact=contact, sdp=True)))
    if ack:
        out.append((2.05, PHONE, PBX, 5060, 5060, sip(f"ACK sip:2002@{PBX} SIP/2.0", contact=contact,
                                                      cseq="1 ACK")))
    if with_media:
        for i in range(6):
            out.append((2.10 + i * 0.02, PHONE, PBX, PHONE_RTP, PBX_RTP, rtp(SSRC_PHONE, i, i * 160)))
            if both_ways:
                out.append((2.11 + i * 0.02, PBX, PHONE, PBX_RTP, PHONE_RTP, rtp(SSRC_PBX, i, i * 160)))
    out.append((9.00, PHONE, PBX, 5060, 5060, sip(f"BYE sip:2002@{PBX} SIP/2.0", contact=contact, cseq="2 BYE")))
    out.append((9.05, PBX, PHONE, 5060, 5060, sip("SIP/2.0 200 OK", contact=contact, cseq="2 BYE")))
    return out


def write_capture(path: Path, script, *, base_ts: float = 1_700_000_000.0) -> Path:
    with open(path, "wb") as fh:
        writer = pcapng.Writer(fh, linktype=1, if_name="test")
        for offset, src, dst, sport, dport, payload in script:
            writer.write_packet(base_ts + offset, frame(src, dst, sport, dport, payload))
    return path


@pytest.fixture
def one_side(tmp_path):
    return write_capture(tmp_path / "client.pcapng", call_script(f"sip:2001@{PHONE}:5060"))


# --------------------------------------------------------------------------- one capture
def test_one_capture_gives_a_whole_ladder(one_side):
    reader = FlowReader()
    source = reader.open(str(one_side), "a")
    assert list(source) == list(SOURCE_KEYS)
    assert source["slot"] == "a" and source["calls"] == 1 and source["error"] is None
    assert source["sip_messages"] == 7 and source["rtp_packets"] == 12

    view = reader.view()
    assert list(view) == list(FLOW_KEYS)
    assert list(view["skew"]) == list(SKEW_KEYS)
    assert view["counts"]["calls"] == 1 and view["counts"]["matched"] == 0
    call = view["calls"][0]
    assert list(call) == list(FLOWCALL_KEYS)
    assert call["sides"] == ["a"] and call["matched_by"] is None
    assert call["call_ids"] == [CALL_ID]
    assert call["state"] == "ended"

    ladder = call["ladder"]
    assert all(list(row) == list(LADDER_KEYS) for row in ladder)
    assert [row["label"] for row in ladder] == [
        "INVITE", "100 Trying (INVITE)", "180 Ringing (INVITE)", "200 OK (INVITE)", "ACK", "BYE", "200 OK (BYE)"]
    assert [row["rel"] for row in ladder] == sorted(row["rel"] for row in ladder)   # in the order they happened
    assert ladder[0]["rel"] == 0.0 and ladder[0]["has_sdp"] is True
    assert all(row["side"] == "a" for row in ladder)
    assert all(isinstance(row["where"], int) and row["where"] > 0 for row in ladder)


def test_every_ladder_row_can_be_read_back_as_headers(one_side):
    """The ladder carries a packet number, not the text. Clicking a row re-reads that packet off the file."""
    reader = FlowReader()
    reader.open(str(one_side), "a")
    call = reader.view()["calls"][0]
    invite = call["ladder"][0]
    view = reader.headers("a", invite["where"])
    assert view is not None
    assert view["start"].startswith("INVITE sip:2002@")
    names = [header["name"] for header in view["headers"]]
    assert names[:3] == ["via", "from", "to"] and "call-id" in names and "contact" in names
    assert view["is_sdp"] is True and "m=audio" in view["body"]
    assert view["packet"] == invite["where"] and view["side"] == "a"
    # a row that points nowhere gives nothing rather than the wrong packet
    assert reader.headers("a", 99999) is None
    assert reader.headers("b", invite["where"]) is None


def test_the_streams_carry_what_makes_audio_bad(one_side):
    reader = FlowReader()
    reader.open(str(one_side), "a")
    streams = reader.view()["calls"][0]["streams"]
    assert len(streams) == 2 and all(list(s) == list(STREAM_KEYS) for s in streams)
    assert {s["direction"] for s in streams} == {f"{PHONE} -> {PBX}", f"{PBX} -> {PHONE}"}
    assert all(s["packets"] == 6 and s["loss_pct"] == 0.0 for s in streams)
    assert all(s["jitter_ms"] is not None and s["decodable"] for s in streams)


def test_a_clean_call_says_so_rather_than_inventing_a_problem(one_side):
    reader = FlowReader()
    reader.open(str(one_side), "a")
    findings = reader.view()["calls"][0]["findings"]
    assert all(list(f) == list(FINDING_KEYS) for f in findings)
    assert all(f["id"] in FINDING_IDS for f in findings)
    assert [f["id"] for f in findings] == ["flow.ok"]


def test_audio_comes_back_as_a_playable_wav(one_side):
    reader = FlowReader()
    reader.open(str(one_side), "a")
    call = reader.view()["calls"][0]
    wav = reader.audio(call["id"])
    assert wav and wav[:4] == b"RIFF" and wav[8:12] == b"WAVE"
    # and each direction on its own, which is how one-way audio is confirmed by ear
    for stream in call["streams"]:
        one = reader.stream_audio(stream["id"])
        assert one and one[:4] == b"RIFF"


# --------------------------------------------------------------------------- what is wrong with a call
def _findings_for(tmp_path, script, name="c.pcapng"):
    reader = FlowReader()
    reader.open(str(write_capture(tmp_path / name, script)), "a")
    return {f["id"]: f for f in reader.view()["calls"][0]["findings"]}


def test_audio_only_one_way_is_the_headline(tmp_path):
    found = _findings_for(tmp_path, call_script(f"sip:2001@{PHONE}:5060", both_ways=False))
    assert found["flow.oneway"]["level"] == "bad"
    assert "one direction" in found["flow.oneway"]["detail"]
    assert "ALG" in found["flow.oneway"]["advice"]


def test_an_answered_call_with_no_media_at_all(tmp_path):
    found = _findings_for(tmp_path, call_script(f"sip:2001@{PHONE}:5060", with_media=False))
    assert found["flow.nomedia"]["level"] == "bad"
    assert "flow.oneway" not in found                     # no media is not one-way media


def test_a_missing_ack(tmp_path):
    found = _findings_for(tmp_path, call_script(f"sip:2001@{PHONE}:5060", ack=False))
    assert found["flow.noack"]["level"] == "warn"


@pytest.mark.parametrize("status,level,needle", [
    ("486 Busy Here", "bad", "busy"), ("404 Not Found", "bad", "dial plan"),
    ("488 Not Acceptable Here", "bad", "codec"), ("503 Service Unavailable", "bad", "provider"),
    ("401 Unauthorized", "bad", "authentication")])
def test_a_failure_is_explained_not_just_reported(tmp_path, status, level, needle):
    found = _findings_for(tmp_path, call_script(f"sip:2001@{PHONE}:5060", failure=status),
                          name=f"f{status[:3]}.pcapng")
    assert found["flow.failed"]["level"] == level
    assert status.split(" ", 1)[1].lower() in found["flow.failed"]["title"].lower()
    assert needle in (found["flow.failed"]["advice"] or "").lower()


# --------------------------------------------------------------------------- two captures
def two_sided(tmp_path, *, contact_b=None, skew=4.2, drop_from_b=()):
    """The same call written twice: as the client saw it, and as the server did `skew` seconds later by its clock.

    `contact_b` different from the client's is a middlebox having rewritten it on the way through."""
    client = call_script(f"sip:2001@{PHONE}:5060")
    server = call_script(contact_b or f"sip:2001@{PHONE}:5060")
    server = [entry for index, entry in enumerate(server) if index not in drop_from_b]
    a = write_capture(tmp_path / "client.pcapng", client, base_ts=1_700_000_000.0)
    b = write_capture(tmp_path / "server.pcapng", server, base_ts=1_700_000_000.0 + skew)
    reader = FlowReader()
    reader.open(str(a), "a")
    reader.open(str(b), "b")
    return reader


def test_two_captures_are_matched_on_call_id_and_the_clock_offset_is_measured(tmp_path):
    """Not on time-of-day: two capture PCs' clocks differ, and here they differ by 4.2 s on purpose. Call-ID is
    identity; the offset is what gets measured from the calls that matched."""
    reader = two_sided(tmp_path, skew=4.2)
    view = reader.view()
    assert view["counts"]["sources"] == 2 and view["counts"]["matched"] == 1
    assert view["skew"]["seconds"] == pytest.approx(4.2, abs=0.01)
    assert view["skew"]["confident"] is True and view["skew"]["matched_calls"] == 1
    call = view["calls"][0]
    assert call["sides"] == ["a", "b"] and call["matched_by"] == "call-id"
    # both sides' rows are in one ladder, and the skew has been taken out so they interleave in real order
    assert {row["side"] for row in call["ladder"]} == {"a", "b"}
    assert [row["rel"] for row in call["ladder"]] == sorted(row["rel"] for row in call["ladder"])
    same = [row for row in call["ladder"] if row["label"] == "INVITE"]
    assert len(same) == 2 and abs(same[0]["rel"] - same[1]["rel"]) < 0.05    # the same INVITE, lined up


def test_a_header_that_differs_between_the_two_sides_is_proof_something_rewrote_it(tmp_path):
    """The thing two captures are uniquely for. No probe can establish this from one side; comparing the same
    message as it left one end and as it arrived at the other establishes it by looking."""
    reader = two_sided(tmp_path, contact_b="sip:2001@203.0.113.9:5060")
    call = reader.view()["calls"][0]
    found = {f["id"]: f for f in call["findings"]}
    rewritten = found["flow.rewritten"]
    assert rewritten["level"] == "bad"
    assert "contact" in rewritten["detail"]
    fields = {change["field"] for change in rewritten["evidence"]}
    assert "contact" in fields
    change = next(c for c in rewritten["evidence"] if c["field"] == "contact")
    assert change["a"] == f"sip:2001@{PHONE}:5060" and change["b"] == "sip:2001@203.0.113.9:5060"
    assert "ALG" in rewritten["advice"]


def test_a_message_in_one_capture_and_not_the_other_is_reported(tmp_path):
    reader = two_sided(tmp_path, drop_from_b=(2,))        # the server's capture never caught the 180 Ringing
    call = reader.view()["calls"][0]
    found = {f["id"]: f for f in call["findings"]}
    assert found["flow.missing"]["level"] == "bad"
    assert any("180" in row["message"] for row in found["flow.missing"]["evidence"])


def test_an_invite_that_never_reached_the_server_is_a_one_sided_call_not_a_missing_message(tmp_path):
    """A call opens at its INVITE. If the server capture never saw one there is no call on that side at all, which
    is a different and louder fact than a call that exists on both sides with a message missing from one."""
    reader = two_sided(tmp_path, drop_from_b=(0,))
    view = reader.view()
    call = view["calls"][0]
    assert call["sides"] == ["a"]
    assert "flow.missing" not in {f["id"] for f in call["findings"]}
    onesided = next(f for f in view["findings"] if f["id"] == "flow.onesided")
    assert onesided["evidence"][0]["side"] == "a"


def test_the_measured_offset_is_reported_at_the_top_level_too(tmp_path):
    reader = two_sided(tmp_path, skew=-2.5)
    view = reader.view()
    skew = next(f for f in view["findings"] if f["id"] == "flow.skew")
    assert "2.5 s" in skew["title"]
    assert "behind" in skew["detail"]


def test_two_captures_with_nothing_in_common_say_so_instead_of_guessing(tmp_path):
    a = write_capture(tmp_path / "a.pcapng", call_script(f"sip:2001@{PHONE}:5060"), base_ts=1_700_000_000.0)
    reader = FlowReader()
    reader.open(str(a), "a")
    empty = tmp_path / "empty.pcapng"
    write_capture(empty, [], base_ts=1_700_000_500.0)
    reader.open(str(empty), "b")
    view = reader.view()
    assert view["skew"]["seconds"] is None and view["skew"]["confident"] is False
    skew = next(f for f in view["findings"] if f["id"] == "flow.skew")
    assert skew["level"] == "warn" and "could not be lined up" in skew["title"]


# --------------------------------------------------------------------------- the pure helpers
def test_estimate_skew_takes_the_median_so_one_delayed_packet_does_not_drag_it():
    def call(times):
        return [{"call_id": "x", "messages": [
            {"kind": "request", "method": "INVITE", "cseq": 1, "cseq_method": "INVITE", "status": None, "ts": t}
            if i == 0 else
            {"kind": "response", "method": None, "cseq": 1, "cseq_method": "INVITE", "status": 100 + i, "ts": t}
            for i, t in enumerate(times)]}]
    a = call([100.0, 101.0, 102.0, 103.0])
    b = call([105.0, 106.0, 107.0, 130.0])               # the last one was held up for 27 s
    skew = estimate_skew(a, b)
    assert skew["seconds"] == pytest.approx(5.0)          # not 9.75, which the mean would have given
    assert skew["samples"] == 4 and skew["confident"] is True


def test_estimate_skew_is_not_confident_on_one_sample():
    a = [{"call_id": "x", "messages": [{"kind": "request", "method": "INVITE", "cseq": 1,
                                        "cseq_method": "INVITE", "status": None, "ts": 10.0}]}]
    b = [{"call_id": "x", "messages": [{"kind": "request", "method": "INVITE", "cseq": 1,
                                        "cseq_method": "INVITE", "status": None, "ts": 11.0}]}]
    skew = estimate_skew(a, b)
    assert skew["seconds"] == pytest.approx(1.0) and skew["confident"] is False


def test_calls_are_paired_across_an_sbc_by_their_parties():
    """A B2BUA gives each side its own Call-ID, which is exactly when two captures matter most."""
    left = [{"call_id": "left-id", "from_uri": "sip:2001@a", "to_uri": "sip:2002@a",
             "start_ts": 100.0, "end_ts": 140.0}]
    right = [{"call_id": "right-id", "from_uri": "<sip:2001@b>;tag=x", "to_uri": "sip:2002@b",
              "start_ts": 105.0, "end_ts": 145.0}]
    pairs = pair_across_sbc(left, right, skew=5.0)
    assert len(pairs) == 1 and pairs[0][0] is left[0] and pairs[0][1] is right[0]


def test_calls_between_the_same_parties_at_different_times_are_not_paired():
    left = [{"call_id": "l", "from_uri": "sip:2001@a", "to_uri": "sip:2002@a", "start_ts": 100.0, "end_ts": 110.0}]
    right = [{"call_id": "r", "from_uri": "sip:2001@b", "to_uri": "sip:2002@b", "start_ts": 900.0, "end_ts": 910.0}]
    assert pair_across_sbc(left, right, skew=0.0) == []


def test_build_ladder_takes_the_skew_out_of_the_second_side():
    sides = {
        "a": {"messages": [{"ts": 100.0, "kind": "request", "method": "INVITE", "src": "x", "dst": "y"}]},
        "b": {"messages": [{"ts": 104.2, "kind": "request", "method": "INVITE", "src": "x", "dst": "y"}]},
    }
    rows = build_ladder(sides, skew=4.2)
    assert [row["side"] for row in rows] == ["a", "b"]
    assert rows[0]["rel"] == 0.0 and rows[1]["rel"] == pytest.approx(0.0, abs=0.001)


# --------------------------------------------------------------------------- refusals
def test_a_path_that_is_not_a_capture_is_refused_with_a_reason(tmp_path):
    reader = FlowReader()
    with pytest.raises(FlowError):
        reader.open(str(tmp_path / "nope.pcapng"), "a")
    with pytest.raises(FlowError):
        reader.open(str(tmp_path), "a")                    # a directory
    with pytest.raises(ValueError):
        reader.open("relative.pcapng", "a")
    with pytest.raises(ValueError):
        reader.open("", "a")


def test_only_two_slots_exist(one_side):
    reader = FlowReader()
    with pytest.raises(ValueError, match="slot"):
        reader.open(str(one_side), "c")


def test_a_capture_larger_than_the_cap_is_refused(tmp_path, one_side):
    reader = FlowReader(max_bytes=10)
    with pytest.raises(FlowError, match="larger than"):
        reader.open(str(one_side), "a")


def test_a_file_that_is_not_a_capture_at_all_is_survivable(tmp_path):
    junk = tmp_path / "junk.pcapng"
    junk.write_bytes(b"not a capture at all, not even close")
    reader = FlowReader()
    source = reader.open(str(junk), "a")
    assert source["packets"] == 0 and source["calls"] == 0
    view = reader.view()
    assert view["calls"] == [] and view["counts"]["calls"] == 0


def test_a_slot_can_be_replaced_and_closed(one_side):
    reader = FlowReader()
    reader.open(str(one_side), "a")
    reader.open(str(one_side), "b")
    assert len(reader.sources()) == 2
    reader.close("b")
    assert [s["slot"] for s in reader.sources()] == ["a"]
    reader.clear()
    assert reader.sources() == [] and reader.view()["calls"] == []


# --------------------------------------------------------------------------- one capture, ALG tells
#: A phone on a real private address, so behind_nat() has something to say about it. The rest of this file uses
#: documentation ranges as public stand-ins, which are deliberately NOT counted as private.
NATTED_PHONE = "10.20.30.40"


def natted_frame(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    out = PHONE_MAC if src == PBX else PBX_MAC
    return _eth(out, PHONE_MAC if src == NATTED_PHONE else PBX_MAC, _ipv4(src, dst, _udp(sport, dport, payload)))


def natted_sip(start: str, *, contact: str, sdp_host: str, cseq: str = "1 INVITE") -> bytes:
    body = (f"v=0\r\no=- 1 1 IN IP4 {sdp_host}\r\ns=call\r\nc=IN IP4 {sdp_host}\r\nt=0 0\r\n"
            f"m=audio {PHONE_RTP} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
    head = (f"{start}\r\n"
            f"Via: SIP/2.0/UDP {NATTED_PHONE}:5060;branch=z9hG4bK-{cseq.split()[0]}\r\n"
            f"From: <sip:2001@{PBX}>;tag=aaa111\r\n"
            f"To: <sip:2002@{PBX}>\r\n"
            f"Call-ID: {CALL_ID}\r\n"
            f"CSeq: {cseq}\r\n"
            f"Contact: <{contact}>\r\n"
            f"Content-Type: application/sdp\r\nContent-Length: {len(body)}\r\n\r\n")
    return (head + body).encode("utf-8")


def write_natted(path, *, contact_host: str, sdp_host: str):
    """One INVITE from a phone behind NAT, with whatever Contact and SDP address the test wants it to carry."""
    script = [(0.0, NATTED_PHONE, PBX, 5060, 5060,
               natted_sip(f"INVITE sip:2002@{PBX} SIP/2.0", contact=f"sip:2001@{contact_host}:5060",
                          sdp_host=sdp_host)),
              (2.0, PBX, NATTED_PHONE, 5060, 5060,
               natted_sip("SIP/2.0 200 OK", contact=f"sip:2002@{PBX}:5060", sdp_host=PBX))]
    with open(path, "wb") as fh:
        writer = pcapng.Writer(fh, linktype=1, if_name="test")
        for offset, src, dst, sport, dport, payload in script:
            writer.write_packet(1_700_000_000.0 + offset, natted_frame(src, dst, sport, dport, payload))
    return path


def test_one_capture_still_offers_what_it_can_see_of_an_alg(tmp_path):
    """The usual case: a tech has one capture, not two. A phone behind NAT does not know its public address, so a
    Contact carrying one was put there by something in the path."""
    path = write_natted(tmp_path / "one.pcapng", contact_host="198.51.100.77", sdp_host="198.51.100.77")
    reader = FlowReader()
    reader.open(str(path), "a")
    findings = {f["id"]: f for f in reader.view()["findings"]}
    assert "alg.contact" in findings and "alg.sdp" in findings
    for f in findings.values():
        assert list(f) == list(FINDING_KEYS) and f["id"] in FINDING_IDS
    assert "not proof" in findings["alg.contact"]["advice"], "a one-sided inference must not be sold as proof"


def test_a_phone_whose_contact_matches_its_own_address_is_not_a_tell(tmp_path):
    path = write_natted(tmp_path / "clean.pcapng", contact_host=NATTED_PHONE, sdp_host=NATTED_PHONE)
    reader = FlowReader()
    reader.open(str(path), "a")
    assert not [f for f in reader.view()["findings"] if f["id"].startswith("alg.")]


def test_two_captures_drop_the_inference_because_they_have_the_proof(tmp_path):
    """With both sides in hand the rewrite is shown outright, and an inferred tell beside it would read as a
    second, weaker finding about the same thing."""
    a = write_natted(tmp_path / "a.pcapng", contact_host="198.51.100.77", sdp_host="198.51.100.77")
    b = write_natted(tmp_path / "b.pcapng", contact_host="198.51.100.77", sdp_host="198.51.100.77")
    reader = FlowReader()
    reader.open(str(a), "a")
    reader.open(str(b), "b")
    assert not [f for f in reader.view()["findings"] if f["id"].startswith("alg.")]


def test_the_tells_are_capped(tmp_path):
    """Past a couple they are the same tell about the same rewrite, and a page of them reads as a page of faults."""
    script = []
    for i in range(12):
        body = f"v=0\r\no=- 1 1 IN IP4 198.51.100.77\r\ns=call\r\nc=IN IP4 198.51.100.77\r\nt=0 0\r\nm=audio {PHONE_RTP} RTP/AVP 0\r\n"
        head = (f"INVITE sip:2002@{PBX} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP {NATTED_PHONE}:5060;branch=z9hG4bK-{i}\r\n"
                f"From: <sip:2001@{PBX}>;tag=aaa{i}\r\n"
                f"To: <sip:2002@{PBX}>\r\n"
                f"Call-ID: call-{i}@{NATTED_PHONE}\r\n"
                f"CSeq: 1 INVITE\r\n"
                f"Contact: <sip:2001@198.51.100.77:5060>\r\n"
                f"Content-Type: application/sdp\r\nContent-Length: {len(body)}\r\n\r\n")
        script.append((i * 0.1, NATTED_PHONE, PBX, 5060, 5060, (head + body).encode("utf-8")))
    path = tmp_path / "many.pcapng"
    with open(path, "wb") as fh:
        writer = pcapng.Writer(fh, linktype=1, if_name="test")
        for offset, src, dst, sport, dport, payload in script:
            writer.write_packet(1_700_000_000.0 + offset, natted_frame(src, dst, sport, dport, payload))
    reader = FlowReader()
    reader.open(str(path), "a")
    tells = [f for f in reader.view()["findings"] if f["id"].startswith("alg.")]
    assert 0 < len(tells) <= sipflow.MAX_TELLS
