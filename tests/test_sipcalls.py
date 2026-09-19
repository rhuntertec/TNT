"""tnt.sipcalls: SIP and SDP parsing, RTP decoding, G.711 companding and the call tracker's audio rebuilding.

Every message, body and packet is built here from the RFC 3261, RFC 4566, RFC 3550 and ITU-T G.711 field layouts, with
the stand-in phones Alice (192.0.2.10) and Bob (192.0.2.20) and MACs 02:00:5e:10:00:0x. Nothing here touches a network,
a file or a program.
"""
from __future__ import annotations

import ast
import struct
from pathlib import Path

import pytest

from tnt import sipcalls
from tnt.sipcalls import (CALL_KEYS, CALL_STATES, DECODABLE, MAX_GAP_SECONDS, MEDIA_KEYS, MESSAGE_KEYS,
                          PAYLOAD_TYPES, RTP_KEYS, SDP_KEYS, SIP_KEYS, STATS_KEYS, STREAM_KEYS, CallTracker,
                          alaw_to_pcm16, build_wav, decodable, is_sip, looks_like_rtp, parse_rtp, parse_sdp,
                          parse_sip, ulaw_to_pcm16)

ALICE, BOB = "192.0.2.10", "192.0.2.20"
ALICE_RTP, BOB_RTP = 40000, 40002
CALL_ID = "3c26700e1a0f-4f2b@192.0.2.10"
SSRC_A, SSRC_B = 0x11223344, 0x55667788
RATE = 8000
SAMPLES = 160                               # 20 ms of G.711
PACKET_S = 0.02                             # the arrival step the builders below use
FIRST_TS = 101.0
TONE_A = bytes(range(0, 160))               # two payloads that decode to different audio
TONE_B = bytes(range(96, 256))


# --------------------------------------------------------------------------- builders
def message(start, *headers, body=""):
    """A SIP message: start line, headers, a Content-Length that matches, a blank line and the body."""
    lines = [start, *headers, f"Content-Length: {len(body.encode())}", "", body]
    return "\r\n".join(lines).encode()


def sdp_body(address, port, *, formats="0 101", rtpmap=("0 PCMU/8000", "101 telephone-event/8000"), extra=()):
    lines = ["v=0", f"o=- 20 20 IN IP4 {address}", "s=TNT test call", f"c=IN IP4 {address}", "t=0 0",
             f"m=audio {port} RTP/AVP {formats}", *[f"a=rtpmap:{entry}" for entry in rtpmap], "a=sendrecv", *extra]
    return "\r\n".join(lines) + "\r\n"


def invite(call_id=CALL_ID, *, body=None, port=ALICE_RTP):
    return message(f"INVITE sip:bob@{BOB} SIP/2.0",
                   f"Via: SIP/2.0/UDP {ALICE}:5060;branch=z9hG4bK-invite-1",
                   "Max-Forwards: 70",
                   f'From: "Alice" <sip:alice@{ALICE}>;tag=alice-1',
                   f"To: <sip:bob@{BOB}>",
                   f"Call-ID: {call_id}",
                   "CSeq: 1 INVITE",
                   f"Contact: <sip:alice@{ALICE}>",
                   "User-Agent: TNT Test 1.0",
                   "Content-Type: application/sdp",
                   body=sdp_body(ALICE, port) if body is None else body)


def response(status, reason, *, call_id=CALL_ID, cseq="1 INVITE", body="", content_type=None, to_tag="bob-1"):
    headers = [f"Via: SIP/2.0/UDP {ALICE}:5060;branch=z9hG4bK-invite-1",
               f'From: "Alice" <sip:alice@{ALICE}>;tag=alice-1',
               f"To: <sip:bob@{BOB}>;tag={to_tag}" if to_tag else f"To: <sip:bob@{BOB}>",
               f"Call-ID: {call_id}", f"CSeq: {cseq}", "Server: TNT Test 1.0"]
    if content_type is not None:
        headers.append(f"Content-Type: {content_type}")
    return message(f"SIP/2.0 {status} {reason}", *headers, body=body)


def request(method, *, call_id=CALL_ID, cseq=None):
    return message(f"{method} sip:bob@{BOB} SIP/2.0",
                   f"Via: SIP/2.0/UDP {ALICE}:5060;branch=z9hG4bK-{method.lower()}-1",
                   f'From: "Alice" <sip:alice@{ALICE}>;tag=alice-1',
                   f"To: <sip:bob@{BOB}>;tag=bob-1",
                   f"Call-ID: {call_id}",
                   f"CSeq: {cseq or ('2 ' + method)}")


def rtp(seq, timestamp, payload, *, ssrc=SSRC_A, pt=0, marker=False, csrcs=(), padding=0, version=2, extension=None):
    """An RTP packet: the 12-byte fixed header, the CSRC list, an optional extension header, the payload, padding."""
    first = (version << 6) | (0x20 if padding else 0) | (0x10 if extension is not None else 0) | len(csrcs)
    header = struct.pack(">BBHII", first, (0x80 if marker else 0) | pt, seq & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc)
    header += b"".join(struct.pack(">I", source) for source in csrcs)
    if extension is not None:
        header += struct.pack(">HH", 0xBEDE, extension) + bytes(4 * extension)
    body = bytes(payload)
    if padding:
        body += bytes(padding - 1) + bytes([padding])
    return header + body


def packet(seq, timestamp, payload, **kwargs):
    """The parsed RTP dict a capture loop would hand the tracker."""
    return parse_rtp(rtp(seq, timestamp, payload, **kwargs))


def answered_call(tracker, *, start=100.0):
    """INVITE, 180 and 200 with the answer SDP; returns the call's id slug."""
    call_id = tracker.add_sip(parse_sip(invite()), start, ALICE, 5060, BOB, 5060)
    tracker.add_sip(parse_sip(response(180, "Ringing")), start + 0.5, BOB, 5060, ALICE, 5060)
    tracker.add_sip(parse_sip(response(200, "OK", body=sdp_body(BOB, BOB_RTP), content_type="application/sdp")),
                    start + 1.0, BOB, 5060, ALICE, 5060)
    return call_id


def feed(tracker, count, *, ssrc=SSRC_A, src=ALICE, sport=ALICE_RTP, dst=BOB, dport=BOB_RTP, first=FIRST_TS,
         seq=100, timestamp=1000, payload=TONE_A, pt=0):
    for index in range(count):
        tracker.add_rtp(packet(seq + index, timestamp + index * SAMPLES, payload, ssrc=ssrc, pt=pt),
                        first + index * PACKET_S, src, sport, dst, dport)


def wav_data(blob):
    """The samples of a WAV file built by build_wav (the header is exactly 44 bytes)."""
    return blob[44:]


# --------------------------------------------------------------------------- SIP
def test_invite_with_sdp_decodes_every_field_in_key_order():
    msg = parse_sip(invite())
    assert tuple(msg) == SIP_KEYS
    assert tuple(msg["sdp"]) == SDP_KEYS
    assert tuple(msg["sdp"]["media"][0]) == MEDIA_KEYS
    assert msg == {
        "kind": "request", "method": "INVITE", "status": None, "reason": None, "uri": f"sip:bob@{BOB}",
        "call_id": CALL_ID, "from_uri": f"sip:alice@{ALICE}", "from_tag": "alice-1", "to_uri": f"sip:bob@{BOB}",
        "to_tag": None, "cseq": 1, "cseq_method": "INVITE", "via_branch": "z9hG4bK-invite-1",
        "contact": f"sip:alice@{ALICE}", "user_agent": "TNT Test 1.0", "content_type": "application/sdp",
        "sdp": {"session": "TNT test call", "connection": ALICE,
                "media": [{"type": "audio", "port": ALICE_RTP, "proto": "RTP/AVP", "formats": [0, 101],
                           "rtpmap": {0: "PCMU/8000", 101: "telephone-event/8000"}, "direction": "sendrecv",
                           "connection": ALICE}]}}


def test_response_carries_the_status_the_reason_and_the_to_tag():
    msg = parse_sip(response(200, "OK", body=sdp_body(BOB, BOB_RTP), content_type="application/sdp"))
    assert tuple(msg) == SIP_KEYS
    assert (msg["kind"], msg["method"], msg["status"], msg["reason"], msg["uri"]) == ("response", None, 200, "OK", None)
    assert (msg["to_uri"], msg["to_tag"], msg["from_tag"]) == (f"sip:bob@{BOB}", "bob-1", "alice-1")
    assert (msg["cseq"], msg["cseq_method"]) == (1, "INVITE")
    assert msg["sdp"]["media"][0]["port"] == BOB_RTP
    trying = parse_sip(response(100, "Trying", to_tag=None))
    assert (trying["status"], trying["reason"], trying["to_tag"]) == (100, "Trying", None)
    assert parse_sip(b"SIP/2.0 486 \r\n\r\n")["reason"] is None


def test_compact_headers_and_folded_lines_are_read():
    compact = message(f"INVITE sip:bob@{BOB} SIP/2.0",
                      f"v: SIP/2.0/UDP {ALICE}:5060;branch=z9hG4bK-compact",
                      f"f: <sip:alice@{ALICE}>;tag=alice-9",
                      f"t: <sip:bob@{BOB}>",
                      "i: compact-1@192.0.2.10",
                      "CSeq: 7 INVITE",
                      f"m: <sip:alice@{ALICE}>",
                      "c: application/sdp",
                      body=sdp_body(ALICE, ALICE_RTP))
    msg = parse_sip(compact)
    assert (msg["call_id"], msg["from_tag"], msg["to_uri"]) == ("compact-1@192.0.2.10", "alice-9", f"sip:bob@{BOB}")
    assert (msg["via_branch"], msg["contact"], msg["cseq"]) == ("z9hG4bK-compact", f"sip:alice@{ALICE}", 7)
    assert msg["sdp"]["media"][0]["formats"] == [0, 101]
    folded = message(f"BYE sip:bob@{BOB} SIP/2.0", "Call-ID: folded-1", "From: <sip:alice@192.0.2.10>",
                     "\t;tag=alice-2", "CSeq: 3 BYE")
    assert parse_sip(folded)["from_tag"] == "alice-2"


def test_a_display_name_without_angle_brackets_still_gives_a_uri():
    plain = message(f"INVITE sip:bob@{BOB} SIP/2.0", f"From: sip:alice@{ALICE};tag=alice-3",
                    f"To: sip:bob@{BOB}", "Call-ID: plain-1", "CSeq: 1 INVITE")
    msg = parse_sip(plain)
    assert (msg["from_uri"], msg["from_tag"], msg["to_uri"], msg["to_tag"]) == (f"sip:alice@{ALICE}", "alice-3",
                                                                               f"sip:bob@{BOB}", None)


@pytest.mark.parametrize("payload", [
    b"",
    b"\x00" * 64,
    bytes(range(256)),
    b"GET /index.html HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n",
    b"SIP/2.0 20 OK\r\n\r\n",                                  # a two-digit status
    b"SIP/2.0 700 Nonsense\r\n\r\n",                           # outside 100..699
    b"SIP/2.0/UDP 192.0.2.10:5060\r\n\r\n",                    # a Via line on its own
    b"NOTAMETHOD sip:bob@192.0.2.20 SIP/2.0\r\n\r\n",
    b"INVITE sip:bob@192.0.2.20 SIP/1.0\r\n\r\n",
    b"INVITE sip:bob@192.0.2.20\r\n\r\n",                      # no version
    b"INVITE",
    invite()[:12],                                             # truncated inside the start line
    b"\x00" + invite(),
    b"A" * 70000,                                              # over MAX_MESSAGE
    "SIP/2.0 ²²² OK\r\n\r\n".encode(),                         # superscripts: str.isdigit(), not int()
    "SIP/2.0 ①①① Odd\r\n\r\n".encode(),                        # circled digits, likewise
    "SIP/2.0 ٢٠٠ Arabic\r\n\r\n".encode(),                     # decimal digits, but not this protocol's
    b"SIP/2.0 \xff\xfe\xfd OK\r\n\r\n",                        # bytes that decode to replacement characters
], ids=["empty", "zeroes", "every_byte", "http", "short_status", "status_700", "via_line", "unknown_method",
        "sip_1_0", "no_version", "method_only", "truncated_start_line", "leading_nul", "too_long",
        "superscript_status", "circled_status", "arabic_indic_status", "undecodable_status"])
def test_garbage_is_not_a_sip_message(payload):
    assert parse_sip(payload) is None


def test_unicode_digits_that_int_refuses_are_not_numbers():
    """``str.isdigit()`` is true for every Numeric_Type=Digit character, a strict superset of what ``int()`` reads,
    so a superscript or a circled digit passes that guard and then raises. A datagram is decoded with
    ``errors="replace"``, which carries those characters through from raw bytes, so every numeric field is guarded."""
    msg = parse_sip("INVITE sip:bob@192.0.2.20 SIP/2.0\r\nCall-ID: digits-1\r\nCSeq: ² INVITE\r\n\r\n".encode())
    assert (msg["cseq"], msg["cseq_method"], msg["call_id"]) == (None, "INVITE", "digits-1")
    sdp = parse_sdp("v=0\r\nm=audio ² RTP/AVP ³ 0\r\na=rtpmap:² PCMU/8000\r\na=rtpmap:0 PCMA/8000\r\n")
    assert (sdp["media"][0]["port"], sdp["media"][0]["formats"]) == (0, [0])
    assert sdp["media"][0]["rtpmap"] == {0: "PCMA/8000"}        # the entry with the superscript is dropped, not read
    tracker = CallTracker()                                     # and the whole message still reaches the tracker
    body = f"v=0\r\nc=IN IP4 {ALICE}\r\nm=audio ² RTP/AVP 0\r\n"
    assert tracker.add_sip(parse_sip(invite(body=body)), 1.0, ALICE, 5060, BOB, 5060) is not None
    assert tracker.expected_rtp() == set()                      # a port that could not be read names no endpoint


def test_a_message_stops_at_max_headers_and_a_value_at_max_header_value():
    filler = [f"X-Pad-{index}: {index}" for index in range(sipcalls.MAX_HEADERS)]
    late = message(f"INVITE sip:bob@{BOB} SIP/2.0", *filler, "Call-ID: too-late@192.0.2.10", "CSeq: 1 INVITE")
    assert parse_sip(late)["call_id"] is None                   # the header sits past MAX_HEADERS
    padded_from = message(f"INVITE sip:bob@{BOB} SIP/2.0", "Call-ID: caps-1", "CSeq: 1 INVITE",
                          f"From: <sip:alice@{ALICE}>;pad=" + "y" * sipcalls.MAX_HEADER_VALUE + ";tag=cut")
    assert parse_sip(padded_from)["from_tag"] is None           # the tag sits past MAX_HEADER_VALUE
    long_id = message(f"INVITE sip:bob@{BOB} SIP/2.0", "Call-ID: " + "z" * 500, "CSeq: 1 INVITE")
    assert parse_sip(long_id)["call_id"] == "z" * sipcalls.MAX_TEXT


def test_a_message_without_headers_or_a_body_still_parses():
    msg = parse_sip(b"OPTIONS sip:bob@192.0.2.20 SIP/2.0\r\n\r\n")
    assert tuple(msg) == SIP_KEYS
    assert (msg["method"], msg["call_id"], msg["sdp"], msg["cseq"]) == ("OPTIONS", None, None, None)
    # a header line without a colon, and a body with no blank line before it, are both survivable
    assert parse_sip(b"BYE sip:bob@192.0.2.20 SIP/2.0\r\nnot a header\r\nCall-ID: x\r\n\r\n")["call_id"] == "x"
    assert parse_sip(b"BYE sip:bob@192.0.2.20 SIP/2.0\r\nCall-ID: y\r\n")["call_id"] == "y"


def test_a_body_is_only_sdp_when_the_content_type_or_the_body_says_so():
    text = message(f"MESSAGE sip:bob@{BOB} SIP/2.0", "Call-ID: text-1", "CSeq: 1 MESSAGE", "Content-Type: text/plain",
                   body="v=0\r\nnot really sdp\r\n")
    assert parse_sip(text)["sdp"] is None
    typed = message(f"INVITE sip:bob@{BOB} SIP/2.0", "Call-ID: typed-1", "CSeq: 1 INVITE",
                    "Content-Type: application/sdp;charset=utf-8", body=sdp_body(ALICE, ALICE_RTP))
    assert parse_sip(typed)["sdp"]["connection"] == ALICE
    untyped = message(f"INVITE sip:bob@{BOB} SIP/2.0", "Call-ID: untyped-1", "CSeq: 1 INVITE",
                      body=sdp_body(ALICE, ALICE_RTP))
    assert untyped.find(b"Content-Type") == -1
    assert parse_sip(untyped)["sdp"]["media"][0]["port"] == ALICE_RTP


@pytest.mark.parametrize("payload, expected", [
    (invite(), True),
    (b"SIP/2.0 200 OK\r\n", True),
    (b"REGISTER sip:192.0.2.1 SIP/2.0\r\n", True),
    (b"SUBSCRIBE sip:192.0.2.1 SIP/2.0\r\n", True),
    (b"SIP/2.0/UDP 192.0.2.10", False),
    (b"INVITEsip:bob@192.0.2.20", False),
    (b"GET / HTTP/1.1\r\n", False),
    (b"invite sip:bob@192.0.2.20 SIP/2.0", False),          # methods are upper case
    (b"", False),
    (b"\x80\x00\x00\x01", False),                            # an RTP packet
], ids=["invite", "response", "register", "subscribe", "via", "no_space", "http", "lower_case", "empty", "rtp"])
def test_is_sip_sniffs_the_first_bytes(payload, expected):
    assert is_sip(payload) is expected


# --------------------------------------------------------------------------- SDP
def test_two_media_lines_keep_their_own_rtpmap_direction_and_connection():
    body = ("v=0\r\n"
            "o=- 20 20 IN IP4 192.0.2.10\r\n"
            "s=-\r\n"
            "c=IN IP4 192.0.2.10\r\n"
            "t=0 0\r\n"
            "a=recvonly\r\n"
            "m=audio 40000 RTP/AVP 0 8 101\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            "a=rtpmap:101 telephone-event/8000\r\n"
            "a=sendrecv\r\n"
            "m=video 40002 RTP/AVP 96\r\n"
            "c=IN IP4 192.0.2.11\r\n"
            "a=rtpmap:96 H264/90000\r\n").encode()
    sdp = parse_sdp(body)
    assert tuple(sdp) == SDP_KEYS
    assert (sdp["session"], sdp["connection"]) == ("-", "192.0.2.10")
    audio, video = sdp["media"]
    assert tuple(audio) == MEDIA_KEYS
    assert audio == {"type": "audio", "port": 40000, "proto": "RTP/AVP", "formats": [0, 8, 101],
                     "rtpmap": {0: "PCMU/8000", 8: "PCMA/8000", 101: "telephone-event/8000"},
                     "direction": "sendrecv", "connection": "192.0.2.10"}
    assert video == {"type": "video", "port": 40002, "proto": "RTP/AVP", "formats": [96],
                     "rtpmap": {96: "H264/90000"}, "direction": "recvonly", "connection": "192.0.2.11"}
    assert parse_sdp(body.decode()) == sdp                   # text is accepted as well as bytes


@pytest.mark.parametrize("body, expected", [
    (b"", None),
    (b"\x00\xff\x00", None),
    (b"s=no version\r\nm=audio 40000 RTP/AVP 0\r\n", None),   # not SDP without v=
    (b"v=0\n", {"session": None, "connection": None, "media": []}),
], ids=["empty", "garbage", "no_version", "version_only"])
def test_a_body_that_is_not_sdp_or_carries_nothing(body, expected):
    assert parse_sdp(body) == expected


def test_media_lines_that_are_short_or_out_of_range_do_not_break_the_body():
    sdp = parse_sdp("v=0\r\nc=IN IP4\r\nm=audio\r\nm=audio 99999 RTP/AVP\r\nm=audio 40000/2 RTP/AVP 0 xx\r\n")
    assert sdp["connection"] is None                          # a c= line with no address
    assert [(entry["port"], entry["formats"]) for entry in sdp["media"]] == [(0, []), (40000, [0])]
    assert sdp["media"][0]["direction"] == "sendrecv"          # the default when nothing says otherwise
    assert parse_sdp("v=0\r\nc=IN IP4 233.252.0.1/127/2\r\n")["connection"] == "233.252.0.1"


def test_only_the_first_eight_media_sections_are_kept():
    lines = ["v=0"] + [f"m=audio {40000 + n * 2} RTP/AVP 0" for n in range(20)]
    assert len(parse_sdp("\r\n".join(lines))["media"]) == 8


def test_a_media_line_that_cannot_be_read_takes_its_own_lines_with_it():
    """RFC 4566 §5.14 puts everything after an m= line at media level. An m= line this module cannot read must not
    leave the section before it open: the c= line that follows would then move a genuine media address, and a capture
    loop sniffing on expected_rtp() would be steered at whatever host:port the sender named."""
    body = ("v=0\r\n"
            "o=- 1 1 IN IP4 192.0.2.10\r\n"
            "s=-\r\n"
            f"c=IN IP4 {ALICE}\r\n"
            "t=0 0\r\n"
            f"m=audio {ALICE_RTP} RTP/AVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "m=audio\r\n"                                       # two tokens: this section cannot be read
            "c=IN IP4 203.0.113.9\r\n"
            "a=recvonly\r\n"
            "a=rtpmap:8 PCMA/8000\r\n")
    [audio] = parse_sdp(body)["media"]
    assert (audio["connection"], audio["direction"]) == (ALICE, "sendrecv")
    assert audio["rtpmap"] == {0: "PCMU/8000"}
    assert parse_sdp("v=0\r\ns=real\r\nm=audio\r\ns=hijacked\r\n")["session"] == "real"
    tracker = CallTracker()
    assert tracker.add_sip(parse_sip(invite(body=body)), 1.0, ALICE, 5060, BOB, 5060) is not None
    assert tracker.expected_rtp() == {(ALICE, ALICE_RTP)}       # and never the address the unreadable section named


def test_max_sdp_lines_and_max_formats_cap_a_body():
    formats = " ".join(str(number) for number in range(64))
    rtpmap = [f"a=rtpmap:{number} CODEC{number}/8000" for number in range(64)]
    [audio] = parse_sdp("\r\n".join(["v=0", f"m=audio {ALICE_RTP} RTP/AVP {formats}", *rtpmap]) + "\r\n")["media"]
    assert len(audio["formats"]) == sipcalls.MAX_FORMATS
    assert len(audio["rtpmap"]) == sipcalls.MAX_FORMATS
    deep = ["v=0"] + [f"a=pad:{index}" for index in range(sipcalls.MAX_SDP_LINES)] + [f"m=audio {ALICE_RTP} RTP/AVP 0"]
    assert parse_sdp("\r\n".join(deep))["media"] == []          # the m= line sits past MAX_SDP_LINES


# --------------------------------------------------------------------------- RTP
def test_a_plain_rtp_packet_decodes_in_key_order():
    parsed = parse_rtp(rtp(1000, 160, TONE_A, marker=True))
    assert tuple(parsed) == RTP_KEYS
    assert parsed == {"version": 2, "padding": False, "extension": False, "csrc_count": 0, "marker": True,
                      "payload_type": 0, "seq": 1000, "ts": 160, "ssrc": SSRC_A, "payload": TONE_A}


def test_csrcs_extension_and_padding_are_taken_off_the_payload():
    with_csrcs = parse_rtp(rtp(1, 0, TONE_A, csrcs=(0x01020304, 0x05060708)))
    assert (with_csrcs["csrc_count"], with_csrcs["payload"]) == (2, TONE_A)
    with_extension = parse_rtp(rtp(1, 0, TONE_A, extension=3))
    assert (with_extension["extension"], with_extension["payload"]) == (True, TONE_A)
    both = parse_rtp(rtp(1, 0, TONE_A, csrcs=(0x01020304,), extension=1, padding=4))
    assert (both["csrc_count"], both["extension"], both["padding"], both["payload"]) == (1, True, True, TONE_A)
    empty = parse_rtp(rtp(1, 0, b""))
    assert empty["payload"] == b""


def padded(frame, count):
    """*frame* with the padding bit set in its first byte and *count* written into its last byte."""
    body = bytearray(frame)
    body[0] |= 0x20
    body[-1] = count
    return bytes(body)


@pytest.mark.parametrize("payload", [
    b"",
    rtp(1, 0, TONE_A)[:11],                                    # one byte short of the fixed header
    rtp(1, 0, TONE_A, version=1),
    rtp(1, 0, TONE_A, version=0),
    rtp(1, 0, b"", csrcs=(1, 2))[:16],                         # the CSRC list runs past the packet
    rtp(1, 0, b"", extension=0)[:14],                          # the extension header runs past the packet
    rtp(1, 0, b"", extension=2)[:16],                          # the extension words run past the packet
    padded(rtp(1, 0, TONE_A), 0),                              # a padding count of zero counts not even itself
    padded(rtp(1, 0, TONE_A), 250),                            # padding reaching in front of the payload
    padded(rtp(1, 0, b"\x00\x00\x00"), 200),
], ids=["empty", "eleven_bytes", "version_1", "version_0", "csrc_past_end", "extension_past_end",
        "extension_words_past_end", "zero_padding", "padding_past_the_payload", "padding_past_the_packet"])
def test_truncated_and_malformed_rtp(payload):
    assert parse_rtp(payload) is None


def test_valid_padding_is_taken_off_the_payload():
    parsed = parse_rtp(rtp(1, 0, TONE_A, padding=4))
    assert (parsed["padding"], parsed["payload"]) == (True, TONE_A)
    exact = parse_rtp(padded(rtp(1, 0, b"\x00" * 4), 4))       # the padding is the whole payload
    assert exact["payload"] == b""


@pytest.mark.parametrize("payload, expected", [
    (rtp(1, 0, TONE_A), True),
    (rtp(1, 0, TONE_A, pt=8), True),
    (rtp(1, 0, TONE_A, marker=True), True),                    # the marker bit is not part of the payload type
    (rtp(1, 0, b"", csrcs=(1, 2)), True),
    (rtp(1, 0, TONE_A, version=1), False),
    (rtp(1, 0, TONE_A)[:11], False),
    (rtp(1, 0, b"", csrcs=(1, 2))[:16], False),
    (bytes([0x81, 200]) + bytes(20), False),                   # an RTCP receiver report (type 201 without its marker)
    (bytes([0x81, 72]) + bytes(20), False),                    # payload types 64..95 belong to RTCP
    (b"", False),
], ids=["pcmu", "pcma", "marker", "csrcs", "version_1", "short", "csrc_past_end", "rtcp_report", "rtcp_low",
        "empty"])
def test_looks_like_rtp(payload, expected):
    assert looks_like_rtp(payload) is expected


# --------------------------------------------------------------------------- G.711
def ulaw_reference(code):
    """The ITU-T G.711 mu-law decoder written out again: the byte travels inverted, then sign, 3-bit segment and
    4-bit interval; within a segment the step is 8 * 2^segment and the first interval sits 132 * (2^segment - 1)
    above zero (the 14-bit law scaled by 4 to fill 16 bits)."""
    stored = ~code & 0xFF
    segment, interval = (stored >> 4) & 0x07, stored & 0x0F
    magnitude = 132 * (2 ** segment - 1) + interval * 8 * 2 ** segment
    return -magnitude if stored & 0x80 else magnitude


def alaw_reference(code):
    """The ITU-T G.711 A-law decoder written out again: every other bit travels inverted (^ 0x55), the sign bit set
    means positive, segment 0 is linear with a step of 16 and an offset of 8, and each further segment doubles both
    (the 13-bit law scaled by 8 to fill 16 bits)."""
    stored = code ^ 0x55
    segment, interval = (stored >> 4) & 0x07, stored & 0x0F
    magnitude = 16 * interval + 8 if segment == 0 else (264 + 16 * interval) * 2 ** (segment - 1)
    return magnitude if stored & 0x80 else -magnitude


@pytest.mark.parametrize("code, expected", [
    (0xFF, 0), (0x7F, 0), (0xFE, 8), (0x7E, -8), (0xF0, 120), (0xEF, 132), (0x9F, 8316),
    (0x80, 32124), (0x00, -32124),
])
def test_ulaw_matches_the_values_the_g711_definition_gives(code, expected):
    assert ulaw_reference(code) == expected
    assert struct.unpack("<h", ulaw_to_pcm16(bytes([code])))[0] == expected


@pytest.mark.parametrize("code, expected", [
    (0xD5, 8), (0x55, -8), (0xD4, 24), (0xC5, 264), (0xAA, 32256), (0x2A, -32256),
])
def test_alaw_matches_the_values_the_g711_definition_gives(code, expected):
    assert alaw_reference(code) == expected
    assert struct.unpack("<h", alaw_to_pcm16(bytes([code])))[0] == expected


def test_every_g711_code_decodes_to_one_little_endian_sample():
    codes = bytes(range(256))
    assert ulaw_to_pcm16(codes) == struct.pack("<256h", *[ulaw_reference(code) for code in codes])
    assert alaw_to_pcm16(codes) == struct.pack("<256h", *[alaw_reference(code) for code in codes])
    assert len(ulaw_to_pcm16(TONE_A)) == 2 * len(TONE_A)
    assert ulaw_to_pcm16(b"") == alaw_to_pcm16(b"") == b""


def test_the_payload_type_table_names_the_static_types_this_screen_meets():
    assert DECODABLE == (0, 8)
    assert [decodable(pt) for pt in (0, 8, 9, 18, 101)] == [True, True, False, False, False]
    for payload_type, expected in [(0, ("PCMU", 8000, 1)), (3, ("GSM", 8000, 1)), (4, ("G723", 8000, 1)),
                                   (8, ("PCMA", 8000, 1)), (9, ("G722", 8000, 1)), (13, ("CN", 8000, 1)),
                                   (18, ("G729", 8000, 1))]:
        assert PAYLOAD_TYPES[payload_type] == expected
    assert 96 not in PAYLOAD_TYPES                             # dynamic types come from an SDP rtpmap


# --------------------------------------------------------------------------- WAV
def test_build_wav_writes_the_canonical_44_byte_header():
    pcm = ulaw_to_pcm16(TONE_A)
    blob = build_wav(pcm)
    assert blob[:44] == (b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVE"
                         + b"fmt " + struct.pack("<I", 16) + struct.pack("<HH", 1, 1)
                         + struct.pack("<II", 8000, 16000) + struct.pack("<HH", 2, 16)
                         + b"data" + struct.pack("<I", len(pcm)))
    assert blob[44:] == pcm and len(blob) == 44 + 2 * len(TONE_A)
    stereo = build_wav(pcm, rate=16000, channels=2)
    assert struct.unpack_from("<HHII HH", stereo, 20) == (1, 2, 16000, 64000, 4, 16)
    assert build_wav(b"")[:4] == b"RIFF" and len(build_wav(b"")) == 44


def test_build_wav_trims_part_frames_and_refuses_a_rate_or_channel_count_that_is_not_a_wav():
    assert len(build_wav(b"\x01\x02\x03")) == 44 + 2         # a stray byte is not half a sample
    assert len(build_wav(b"\x01\x02\x03\x04\x05", channels=2)) == 44 + 4
    for rate, channels in [(0, 1), (-8000, 1), (200000, 1), (8000, 0), (8000, 3), (8000, True)]:
        with pytest.raises(ValueError, match="a WAV needs a rate"):
            build_wav(b"\x00\x00", rate=rate, channels=channels)


# --------------------------------------------------------------------------- the tracker: one whole call
def test_a_whole_call_from_invite_to_bye():
    tracker = CallTracker()
    invite_msg = parse_sip(invite())
    slug = tracker.add_sip(invite_msg, 100.0, ALICE, 5060, BOB, 5060)
    assert slug is not None
    assert tracker.call(slug)["state"] == "calling"
    assert tracker.expected_rtp() == {(ALICE, ALICE_RTP)}

    assert tracker.add_sip(parse_sip(response(180, "Ringing")), 100.5, BOB, 5060, ALICE, 5060) == slug
    assert tracker.call(CALL_ID)["state"] == "ringing"
    answer = parse_sip(response(200, "OK", body=sdp_body(BOB, BOB_RTP), content_type="application/sdp"))
    assert tracker.add_sip(answer, 101.0, BOB, 5060, ALICE, 5060) == slug
    assert tracker.expected_rtp() == {(ALICE, ALICE_RTP), (BOB, BOB_RTP)}
    assert tracker.add_sip(parse_sip(request("ACK")), 101.05, ALICE, 5060, BOB, 5060) is None   # no state change

    feed(tracker, 5, ssrc=SSRC_A, payload=TONE_A)
    feed(tracker, 5, ssrc=SSRC_B, src=BOB, sport=BOB_RTP, dst=ALICE, dport=ALICE_RTP, seq=7000, timestamp=50_000,
         payload=TONE_B)

    assert tracker.add_sip(parse_sip(request("BYE")), 105.0, ALICE, 5060, BOB, 5060) == slug
    assert tracker.add_sip(parse_sip(response(200, "OK", cseq="2 BYE")), 105.1, BOB, 5060, ALICE, 5060) is None

    [call] = tracker.calls()
    assert tuple(call) == CALL_KEYS
    assert tuple(call["messages"][0]) == MESSAGE_KEYS
    assert (call["id"], call["call_id"], call["state"], call["status"]) == (slug, CALL_ID, "ended", 200)
    assert (call["from_uri"], call["to_uri"]) == (f"sip:alice@{ALICE}", f"sip:bob@{BOB}")
    assert (call["start_ts"], call["answer_ts"], call["end_ts"]) == (100.0, 101.0, 105.0)
    assert (call["duration_s"], call["note"]) == (4.0, None)
    assert len(call["messages"]) == 6
    assert call["messages"][0] == {
        "ts": 100.0, "kind": "request", "method": "INVITE", "status": None, "reason": None,
        "src": f"{ALICE}:5060", "dst": f"{BOB}:5060", "cseq": 1, "cseq_method": "INVITE",
        "via_branch": "z9hG4bK-invite-1", "contact": f"sip:alice@{ALICE}", "user_agent": "TNT Test 1.0",
        "has_sdp": True, "sdp_c": ALICE,
        # the locator and the side are whatever the caller passed; this feed passed neither
        "where": None, "side": None}
    assert call["messages"][1]["status"] == 180

    streams = {stream["src"]: stream for stream in call["streams"]}
    assert len(streams) == 2 and all(tuple(stream) == STREAM_KEYS for stream in streams.values())
    assert streams[ALICE] == {"id": streams[ALICE]["id"], "src": ALICE, "sport": ALICE_RTP, "dst": BOB,
                              "dport": BOB_RTP, "ssrc": SSRC_A, "payload_type": 0, "codec": "PCMU", "packets": 5,
                              "lost": 0, "out_of_order": 0, "first_ts": FIRST_TS,
                              "last_ts": FIRST_TS + 4 * PACKET_S, "duration_s": 0.08, "bytes": 5 * SAMPLES,
                              # a stream fed at exactly its own packet time has no interarrival jitter at all
                              "jitter_ms": 0.0, "decodable": True}
    assert streams[BOB]["ssrc"] == SSRC_B and streams[BOB]["dport"] == ALICE_RTP

    one_way = tracker.audio(streams[ALICE]["id"])
    assert wav_data(one_way) == ulaw_to_pcm16(TONE_A * 5)
    mixed = tracker.call_audio(slug)
    assert len(mixed) == 44 + 2 * 5 * SAMPLES                  # both directions start together, so nothing shifts
    assert struct.unpack_from("<I", mixed, 24)[0] == RATE
    assert tracker.call_audio(CALL_ID) == mixed                # the Call-ID works as well as the slug

    stats = tracker.stats()
    assert tuple(stats) == STATS_KEYS
    assert stats == {"calls": 1, "streams": 2, "sip_messages": 6, "rtp_packets": 10, "dropped": 0}


def test_the_two_directions_are_mixed_with_clipping_and_their_own_start_offset():
    tracker = CallTracker()
    slug = answered_call(tracker)
    loud = bytes([0x80]) * SAMPLES                             # mu-law 0x80 is +32124: two of them clip
    feed(tracker, 2, ssrc=SSRC_A, payload=loud, first=FIRST_TS)
    feed(tracker, 1, ssrc=SSRC_B, src=BOB, sport=BOB_RTP, dst=ALICE, dport=ALICE_RTP, payload=loud,
         first=FIRST_TS + PACKET_S)
    data = wav_data(tracker.call_audio(slug))
    assert len(data) == 2 * 2 * SAMPLES                        # the second direction starts 20 ms (160 samples) later
    samples = struct.unpack(f"<{SAMPLES * 2}h", data)
    assert samples[:SAMPLES] == (32124,) * SAMPLES             # only the first direction
    assert samples[SAMPLES:] == (32767,) * SAMPLES             # both, clipped


def test_a_call_that_is_cancelled_and_one_that_fails():
    tracker = CallTracker()
    slug = tracker.add_sip(parse_sip(invite("cancel-me@192.0.2.10")), 10.0, ALICE, 5060, BOB, 5060)
    tracker.add_sip(parse_sip(response(180, "Ringing", call_id="cancel-me@192.0.2.10")), 10.5, BOB, 5060, ALICE, 5060)
    assert tracker.add_sip(parse_sip(request("CANCEL", call_id="cancel-me@192.0.2.10", cseq="1 CANCEL")),
                           12.0, ALICE, 5060, BOB, 5060) == slug
    cancelled = tracker.call(slug)
    assert (cancelled["state"], cancelled["end_ts"], cancelled["status"]) == ("cancelled", 12.0, None)
    # the 487 that follows a CANCEL records its status without taking the call out of "cancelled"
    tracker.add_sip(parse_sip(response(487, "Request Terminated", call_id="cancel-me@192.0.2.10")),
                    12.1, BOB, 5060, ALICE, 5060)
    assert (tracker.call(slug)["state"], tracker.call(slug)["status"]) == ("cancelled", 487)

    busy = tracker.add_sip(parse_sip(invite("busy@192.0.2.10")), 20.0, ALICE, 5060, BOB, 5060)
    assert tracker.add_sip(parse_sip(response(486, "Busy Here", call_id="busy@192.0.2.10")),
                           21.0, BOB, 5060, ALICE, 5060) == busy
    failed = tracker.call(busy)
    assert (failed["state"], failed["status"], failed["end_ts"], failed["duration_s"]) == ("failed", 486, 21.0, 1.0)
    assert failed["note"] == "no RTP was seen for this call"
    assert [call["id"] for call in tracker.calls()] == [busy, slug]     # newest first
    assert set(CALL_STATES) >= {call["state"] for call in tracker.calls()}


def test_a_redirect_records_its_status_without_moving_the_call():
    tracker = CallTracker()
    slug = tracker.add_sip(parse_sip(invite("moved@192.0.2.10")), 30.0, ALICE, 5060, BOB, 5060)
    assert tracker.add_sip(parse_sip(response(302, "Moved Temporarily", call_id="moved@192.0.2.10")),
                           30.5, BOB, 5060, ALICE, 5060) is None
    assert (tracker.call(slug)["state"], tracker.call(slug)["status"]) == ("calling", 302)
    # a 100 Trying is not a state of its own either
    other = tracker.add_sip(parse_sip(invite("trying@192.0.2.10")), 40.0, ALICE, 5060, BOB, 5060)
    assert tracker.add_sip(parse_sip(response(100, "Trying", call_id="trying@192.0.2.10", to_tag=None)),
                           40.2, BOB, 5060, ALICE, 5060) is None
    assert (tracker.call(other)["state"], tracker.call(other)["status"]) == ("calling", None)


def test_a_message_that_starts_no_call_and_a_call_id_that_is_missing_are_ignored():
    tracker = CallTracker()
    assert tracker.add_sip(parse_sip(request("BYE", call_id="unknown@192.0.2.10")), 1.0, ALICE, 5060, BOB, 5060) is None
    assert tracker.add_sip(parse_sip(b"OPTIONS sip:bob@192.0.2.20 SIP/2.0\r\n\r\n"), 1.0, ALICE, 5060, BOB, 5060) is None
    assert tracker.add_sip("not a dict", 1.0, ALICE, 5060, BOB, 5060) is None
    assert tracker.add_sip(parse_sip(invite()), None, ALICE, 5060, BOB, 5060) is None
    assert tracker.calls() == [] and tracker.call("nothing") is None and tracker.stream("nothing") is None
    # the message that was not even a dict is the one of the four that is not counted
    assert tracker.stats() == {"calls": 0, "streams": 0, "sip_messages": 3, "rtp_packets": 0, "dropped": 0}


def test_sdp_with_a_wildcard_address_falls_back_to_the_sender():
    tracker = CallTracker()
    body = sdp_body(ALICE, ALICE_RTP).replace(f"c=IN IP4 {ALICE}", "c=IN IP4 0.0.0.0")
    tracker.add_sip(parse_sip(invite(body=body)), 1.0, ALICE, 5060, BOB, 5060)
    assert tracker.expected_rtp() == {(ALICE, ALICE_RTP)}


def test_an_rtp_packet_that_matches_no_call_is_still_tracked():
    tracker = CallTracker()
    tracker.add_rtp(packet(1, 0, TONE_A), 5.0, "198.51.100.5", 30000, "198.51.100.6", 30002)
    assert tracker.calls() == [] and tracker.expected_rtp() == set()
    assert tracker.stats() == {"calls": 0, "streams": 1, "sip_messages": 0, "rtp_packets": 1, "dropped": 0}


# --------------------------------------------------------------------------- the tracker: audio rebuilding
def test_reordered_and_duplicated_rtp_rebuild_in_timestamp_order():
    tracker = CallTracker()
    answered_call(tracker)
    pieces = [bytes([0x80 + n]) * SAMPLES for n in range(4)]
    arrivals = [(100, 1000, pieces[0]), (101, 1160, pieces[1]), (103, 1480, pieces[3]), (102, 1320, pieces[2]),
                (103, 1480, pieces[3])]                        # 103 arrives early, then again
    for index, (seq, timestamp, payload) in enumerate(arrivals):
        tracker.add_rtp(packet(seq, timestamp, payload), 101.0 + index * 0.02, ALICE, ALICE_RTP, BOB, BOB_RTP)
    [stream] = tracker.calls()[0]["streams"]
    assert (stream["packets"], stream["lost"], stream["out_of_order"]) == (5, 1, 1)
    assert wav_data(tracker.audio(stream["id"])) == ulaw_to_pcm16(b"".join(pieces))


def test_a_timestamp_gap_is_filled_with_silence_and_a_wild_jump_is_capped():
    tracker = CallTracker()
    answered_call(tracker)
    tracker.add_rtp(packet(1, 1000, TONE_A), 101.0, ALICE, ALICE_RTP, BOB, BOB_RTP)
    tracker.add_rtp(packet(2, 1160, TONE_A), 101.02, ALICE, ALICE_RTP, BOB, BOB_RTP)
    tracker.add_rtp(packet(3, 1320 + 800, TONE_B), 101.04, ALICE, ALICE_RTP, BOB, BOB_RTP)   # 100 ms of silence
    [stream] = tracker.calls()[0]["streams"]
    assert wav_data(tracker.audio(stream["id"])) == (ulaw_to_pcm16(TONE_A * 2) + bytes(2 * 800)
                                                     + ulaw_to_pcm16(TONE_B))

    wild = CallTracker()
    answered_call(wild)
    wild.add_rtp(packet(1, 0, TONE_A), 101.0, ALICE, ALICE_RTP, BOB, BOB_RTP)
    wild.add_rtp(packet(2, 100_000_000, TONE_B), 101.02, ALICE, ALICE_RTP, BOB, BOB_RTP)
    [stream] = wild.calls()[0]["streams"]
    expected = 2 * (SAMPLES + int(MAX_GAP_SECONDS * RATE) + SAMPLES)
    assert len(wav_data(wild.audio(stream["id"]))) == expected


def test_a_timestamp_that_wraps_past_32_bits_stays_in_order():
    tracker = CallTracker()
    answered_call(tracker)
    start = 0xFFFFFFFF - SAMPLES                               # the next packet wraps the 32-bit field
    for index, payload in enumerate((TONE_A, TONE_B)):
        tracker.add_rtp(packet(1 + index, (start + index * SAMPLES) & 0xFFFFFFFF, payload),
                        101.0 + index * 0.02, ALICE, ALICE_RTP, BOB, BOB_RTP)
    [stream] = tracker.calls()[0]["streams"]
    assert wav_data(tracker.audio(stream["id"])) == ulaw_to_pcm16(TONE_A + TONE_B)


def test_max_seconds_caps_the_rebuilt_audio():
    tracker = CallTracker()
    answered_call(tracker)
    feed(tracker, 25, payload=TONE_A)                          # half a second of audio
    [stream] = tracker.calls()[0]["streams"]
    assert len(wav_data(tracker.audio(stream["id"]))) == 2 * 25 * SAMPLES
    assert len(wav_data(tracker.audio(stream["id"], max_seconds=0.04))) == 2 * 2 * SAMPLES
    assert len(wav_data(tracker.call_audio(tracker.calls()[0]["id"], max_seconds=0.04))) == 2 * 2 * SAMPLES
    assert tracker.audio(stream["id"], max_seconds=0) is None
    assert tracker.audio("no-such-stream") is None
    assert tracker.call_audio("no-such-call") is None


def test_max_stream_packets_stops_storing_and_counts_the_rest_as_dropped():
    tracker = CallTracker(max_stream_packets=3)
    answered_call(tracker)
    feed(tracker, 5, payload=TONE_A)
    [stream] = tracker.calls()[0]["streams"]
    assert (stream["packets"], stream["bytes"]) == (5, 5 * SAMPLES)     # the counters keep counting
    assert tracker.stats()["dropped"] == 2
    assert len(wav_data(tracker.audio(stream["id"]))) == 2 * 3 * SAMPLES


def test_max_stored_bytes_charges_the_whole_frame_and_not_only_its_payload(monkeypatch):
    """The cap is a bound on memory, so a frame costs its payload plus FRAME_OVERHEAD: the tuple, the bytes header,
    the two uncached timestamps and the list slot around it. For 20 ms of G.711 that is more than the payload."""
    monkeypatch.setattr(sipcalls, "MAX_STORED_BYTES", 3 * (SAMPLES + sipcalls.FRAME_OVERHEAD))
    tracker = CallTracker()
    answered_call(tracker)
    feed(tracker, 5, payload=TONE_A)
    [stream] = tracker.calls()[0]["streams"]
    assert (stream["packets"], stream["bytes"]) == (5, 5 * SAMPLES)     # the counters keep counting
    assert tracker.stats()["dropped"] == 2                             # six would fit if only payload were charged
    assert len(wav_data(tracker.audio(stream["id"]))) == 2 * 3 * SAMPLES


def test_forgetting_a_call_gives_back_the_streams_and_the_bytes_it_held(monkeypatch):
    """A call rolled out by max_calls has to free what it held, or a long capture is a one-way climb to the cap."""
    monkeypatch.setattr(sipcalls, "MAX_STORED_BYTES", 2 * (SAMPLES + sipcalls.FRAME_OVERHEAD))
    tracker = CallTracker(max_calls=1)
    answered_call(tracker)
    feed(tracker, 2, payload=TONE_A)
    assert (tracker.stats()["streams"], tracker.stats()["dropped"]) == (1, 0)   # the tracker is now exactly full

    tracker.add_sip(parse_sip(invite("second@192.0.2.10")), 200.0, ALICE, 5060, BOB, 5060)
    assert tracker.stats()["streams"] == 0                             # the rolled-out call took its stream with it
    feed(tracker, 2, ssrc=SSRC_B, payload=TONE_B, first=201.0)
    [stream] = tracker.calls()[0]["streams"]
    assert len(wav_data(tracker.audio(stream["id"]))) == 2 * 2 * SAMPLES       # so there is room for the new call
    assert tracker.stats()["dropped"] == 0


def test_a_timestamp_that_is_not_a_finite_number_is_ignored():
    """A NaN or an infinity is a float and would pass an isinstance guard, then raise in int() where a recording is
    placed and serialise to invalid JSON in a stream dict. A capture file read off disk is untrusted."""
    tracker = CallTracker()
    slug = answered_call(tracker)
    feed(tracker, 1, ssrc=SSRC_A, payload=TONE_A, first=FIRST_TS)
    for bad in (float("nan"), float("inf"), float("-inf"), 10 ** 400):
        tracker.add_rtp(packet(1, 0, TONE_B, ssrc=SSRC_B), bad, BOB, BOB_RTP, ALICE, ALICE_RTP)
        assert tracker.add_sip(parse_sip(request("BYE")), bad, ALICE, 5060, BOB, 5060) is None
    assert tracker.stats()["streams"] == 1                             # none of them started a stream
    [stream] = tracker.calls()[0]["streams"]
    assert stream["first_ts"] == FIRST_TS and tracker.call(slug)["state"] == "answered"
    assert len(wav_data(tracker.call_audio(slug))) == 2 * SAMPLES      # and the call still rebuilds


def test_a_forward_sequence_jump_larger_than_max_seq_gap_reads_as_a_restart():
    """Up to MAX_SEQ_GAP a forward gap is loss; past it the sender restarted, and counting that as loss would report
    tens of thousands of packets lost on every re-registration."""
    def lost_after(step):
        tracker = CallTracker()
        answered_call(tracker)
        tracker.add_rtp(packet(100, 1000, TONE_A), FIRST_TS, ALICE, ALICE_RTP, BOB, BOB_RTP)
        tracker.add_rtp(packet(100 + step, 1000 + SAMPLES * step, TONE_A), FIRST_TS + PACKET_S,
                        ALICE, ALICE_RTP, BOB, BOB_RTP)
        [stream] = tracker.calls()[0]["streams"]
        return stream["lost"]
    assert (lost_after(1), lost_after(2)) == (0, 1)
    assert lost_after(sipcalls.MAX_SEQ_GAP) == sipcalls.MAX_SEQ_GAP - 1
    assert lost_after(sipcalls.MAX_SEQ_GAP + 1) == 0


def test_max_expected_caps_the_endpoints_learned_from_sdp():
    tracker = CallTracker(max_calls=100)
    sections = [f"m=audio {41000 + index} RTP/AVP 0" for index in range(8)]
    for number in range(65):                                   # 65 calls x 8 sections = 520 endpoints offered
        body = "\r\n".join(["v=0", f"c=IN IP4 198.51.100.{number}", "t=0 0", *sections]) + "\r\n"
        tracker.add_sip(parse_sip(invite(f"bulk-{number}@192.0.2.10", body=body)), 1.0 + number,
                        ALICE, 5060, BOB, 5060)
    assert len(tracker.expected_rtp()) == sipcalls.MAX_EXPECTED


def test_a_call_lists_eight_streams_and_mixes_four_of_them():
    tracker = CallTracker()
    slug = answered_call(tracker)
    for index in range(10):                                    # ten SSRCs, each starting 20 ms after the one before
        feed(tracker, 1, ssrc=SSRC_A + index, payload=TONE_A, first=FIRST_TS + index * PACKET_S, seq=100 + index)
    call = tracker.call(slug)
    assert tracker.stats()["streams"] == 10
    assert len(call["streams"]) == sipcalls.MAX_STREAMS_PER_CALL
    assert [stream["first_ts"] for stream in call["streams"]] == [FIRST_TS + n * PACKET_S for n in range(8)]
    # four mixed, each 20 ms long and 20 ms apart, reach 4 * 160 samples; a fifth would reach 800
    assert len(wav_data(tracker.call_audio(slug))) == 2 * sipcalls.MAX_MIXED_STREAMS * SAMPLES


def test_mixing_clips_at_the_negative_end_too():
    tracker = CallTracker()
    slug = answered_call(tracker)
    quiet = bytes([0x00]) * SAMPLES                            # mu-law 0x00 is -32124: two of them clip
    feed(tracker, 1, ssrc=SSRC_A, payload=quiet, first=FIRST_TS)
    feed(tracker, 1, ssrc=SSRC_B, src=BOB, sport=BOB_RTP, dst=ALICE, dport=ALICE_RTP, payload=quiet, first=FIRST_TS)
    data = wav_data(tracker.call_audio(slug))
    assert struct.unpack(f"<{SAMPLES}h", data) == (-32767,) * SAMPLES
    # the mixer clips everything it is handed, a lone -32768 with only silence under it included
    assert sipcalls._mix([(0, struct.pack("<3h", -32768, -32768, 32767))], 3) == struct.pack("<3h", -32767, -32767,
                                                                                             32767)


def test_max_streams_refuses_a_new_stream_and_max_calls_forgets_the_oldest():
    tracker = CallTracker(max_streams=1)
    answered_call(tracker)
    feed(tracker, 1, ssrc=SSRC_A)
    feed(tracker, 1, ssrc=SSRC_B, src=BOB, sport=BOB_RTP, dst=ALICE, dport=ALICE_RTP)
    assert (tracker.stats()["streams"], tracker.stats()["dropped"]) == (1, 1)

    small = CallTracker(max_calls=2)
    slugs = [small.add_sip(parse_sip(invite(f"call-{n}@192.0.2.10")), 10.0 + n, ALICE, 5060, BOB, 5060)
             for n in range(3)]
    assert [call["call_id"] for call in small.calls()] == ["call-2@192.0.2.10", "call-1@192.0.2.10"]
    assert small.call(slugs[0]) is None and small.stats() == {"calls": 2, "streams": 0, "sip_messages": 3,
                                                              "rtp_packets": 0, "dropped": 0}


def test_max_messages_caps_what_one_call_keeps():
    tracker = CallTracker(max_messages=2)
    slug = answered_call(tracker)
    assert len(tracker.call(slug)["messages"]) == 2
    assert tracker.stats()["dropped"] == 1


def test_a_codec_this_module_cannot_rebuild_is_counted_but_not_played():
    tracker = CallTracker()
    slug = answered_call(tracker)
    feed(tracker, 3, pt=18, payload=TONE_A)                    # G.729
    call = tracker.call(slug)
    [stream] = call["streams"]
    assert (stream["codec"], stream["payload_type"], stream["decodable"], stream["packets"]) == ("G729", 18, False, 3)
    assert call["note"] == "the audio is G729 and cannot be rebuilt here"
    assert tracker.audio(stream["id"]) is None and tracker.call_audio(slug) is None


def test_a_dynamic_payload_type_is_named_from_the_sdp_rtpmap():
    tracker = CallTracker()
    body = sdp_body(ALICE, ALICE_RTP, formats="96", rtpmap=("96 opus/48000/2",))
    tracker.add_sip(parse_sip(invite(body=body)), 100.0, ALICE, 5060, BOB, 5060)
    tracker.add_rtp(packet(1, 0, TONE_A, pt=96), 101.0, BOB, BOB_RTP, ALICE, ALICE_RTP)
    [stream] = tracker.calls()[0]["streams"]
    assert (stream["codec"], stream["decodable"]) == ("opus", False)
    other = CallTracker()
    other.add_rtp(packet(1, 0, TONE_A, pt=99), 1.0, ALICE, ALICE_RTP, BOB, BOB_RTP)
    assert other.stats()["streams"] == 1


def test_only_the_stream_payload_type_is_rebuilt():
    """A telephone-event (RFC 4733) packet shares the SSRC; it is counted but kept out of the audio."""
    tracker = CallTracker()
    answered_call(tracker)
    tracker.add_rtp(packet(1, 1000, TONE_A), 101.0, ALICE, ALICE_RTP, BOB, BOB_RTP)
    tracker.add_rtp(packet(2, 1160, b"\x05\x0a\x00\xa0", pt=101), 101.02, ALICE, ALICE_RTP, BOB, BOB_RTP)
    tracker.add_rtp(packet(3, 1320, TONE_B), 101.04, ALICE, ALICE_RTP, BOB, BOB_RTP)
    [stream] = tracker.calls()[0]["streams"]
    assert (stream["packets"], stream["payload_type"]) == (3, 0)
    assert wav_data(tracker.audio(stream["id"])) == ulaw_to_pcm16(TONE_A) + bytes(2 * SAMPLES) + ulaw_to_pcm16(TONE_B)


def test_rtp_dicts_that_are_missing_fields_are_ignored():
    tracker = CallTracker()
    answered_call(tracker)
    for bad in ("not a dict", {}, dict(packet(1, 0, TONE_A), ssrc=None), dict(packet(1, 0, TONE_A), payload="text"),
                dict(packet(1, 0, TONE_A), seq=True)):
        tracker.add_rtp(bad, 101.0, ALICE, ALICE_RTP, BOB, BOB_RTP)
    tracker.add_rtp(packet(1, 0, TONE_A), None, ALICE, ALICE_RTP, BOB, BOB_RTP)
    stats = tracker.stats()
    assert (stats["streams"], stats["rtp_packets"]) == (0, 5)


# --------------------------------------------------------------------------- ids
@pytest.mark.parametrize("call_id", [
    "../../x",
    "../../../windows/system32",
    "a/b\\c",
    "..",
    "....",
    "%2e%2e/etc",
    "call\x00id@192.0.2.10",
    "‮@192.0.2.10",
    "?query=1&x=2#fragment",
    "x" * 500,
])
def test_a_hostile_call_id_gives_a_url_safe_id(call_id):
    tracker = CallTracker()
    slug = tracker.add_sip(parse_sip(invite(call_id)), 1.0, ALICE, 5060, BOB, 5060)
    assert slug and len(slug) <= 60
    assert not set(slug) - set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    assert ".." not in slug and "/" not in slug and "\\" not in slug
    assert tracker.call(slug)["call_id"] == call_id[:sipcalls.MAX_TEXT]
    assert tracker.call(call_id[:sipcalls.MAX_TEXT])["id"] == slug


def test_two_call_ids_that_sanitise_the_same_way_still_get_different_ids():
    tracker = CallTracker()
    first = tracker.add_sip(parse_sip(invite("../x@192.0.2.10")), 1.0, ALICE, 5060, BOB, 5060)
    second = tracker.add_sip(parse_sip(invite("~~x@192.0.2.10")), 2.0, ALICE, 5060, BOB, 5060)
    assert first != second
    assert {call["id"] for call in tracker.calls()} == {first, second}


def test_stream_ids_are_url_safe_and_one_per_direction():
    tracker = CallTracker()
    answered_call(tracker)
    feed(tracker, 1, ssrc=SSRC_A)
    feed(tracker, 1, ssrc=SSRC_B, src=BOB, sport=BOB_RTP, dst=ALICE, dport=ALICE_RTP)
    ids = [stream["id"] for stream in tracker.calls()[0]["streams"]]
    assert len(set(ids)) == 2
    for stream_id in ids:
        assert not set(stream_id) - set("0123456789abcdef-")
        assert tracker.stream(stream_id)["id"] == stream_id


def test_module_opens_no_socket_and_runs_no_program():
    """tnt.sipcalls has no I/O seam for tests/conftest.py to guard: it only decodes the bytes it is given.

    This is a lint over the source and not a sandbox: it reads the import statements and the names called, so an
    import round the back (``__import__``, ``importlib``) or an ``eval`` would have to be spelled out to get past
    it, but a module that reached the network some other way would still pass. Read it as a guard on the imports."""
    tree = ast.parse(Path(sipcalls.__file__).read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {(node.module or "").split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not imported & {"socket", "subprocess", "ctypes", "http", "urllib", "ssl", "asyncio", "multiprocessing",
                           "os", "pathlib", "shutil", "tempfile", "time", "importlib"}
    called = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call)
              and isinstance(node.func, ast.Name)}
    called |= {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call)
               and isinstance(node.func, ast.Attribute)}
    assert not called & {"__import__", "import_module", "eval", "exec", "compile", "open", "system", "popen",
                         "run", "connect", "urlopen"}
