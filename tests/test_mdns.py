"""tnt.mdns: building a DNS-SD question and reading the answers back.

Every message is built here from the RFC 1035 wire format, with invented Dante gear on 192.0.2.0/24. Nothing here
touches a network.
"""
from __future__ import annotations

import struct

import pytest

from tnt import mdns
from tnt.mdns import (MESSAGE_KEYS, QUESTION_KEYS, RECORD_KEYS, build_query, instance_name, parse, service_proto,
                      split_service)

ARC = "_netaudio-arc._udp.local"
INSTANCE = "FOH Console." + ARC


def name(text: str) -> bytes:
    """A dotted name as wire labels (unescaping each label, the way a responder would have encoded it)."""
    out = bytearray()
    for label in mdns._split_labels(text):
        raw = instance_name(label).encode("utf-8")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def record(owner: str, kind: int, data: bytes, ttl: int = 4500, flush: bool = False) -> bytes:
    return name(owner) + struct.pack(">HHIH", kind, 1 | (0x8000 if flush else 0), ttl, len(data)) + data


def txt(pairs) -> bytes:
    out = bytearray()
    for item in pairs:
        raw = item.encode("utf-8")
        out.append(len(raw))
        out += raw
    return bytes(out)


def srv(port: int, target: str) -> bytes:
    return struct.pack(">HHH", 0, 0, port) + name(target)


def message(*records: bytes, response: bool = True, questions: bytes = b"", qdcount: int = 0,
            truncated: bool = False) -> bytes:
    flags = (0x8400 if response else 0x0000) | (0x0200 if truncated else 0)
    head = struct.pack(">HHHHHH", 0, flags, qdcount, len(records), 0, 0)
    return head + questions + b"".join(records)


# ---------------------------------------------------------------------------
# questions
# ---------------------------------------------------------------------------
def test_a_query_asks_for_the_ptr_of_every_name_in_order():
    raw = build_query([mdns.META_QUERY, ARC])
    back = parse(raw)
    assert list(back) == list(MESSAGE_KEYS)
    assert back["response"] is False
    assert [q["name"] for q in back["questions"]] == [mdns.META_QUERY, ARC]
    assert list(back["questions"][0]) == list(QUESTION_KEYS)
    assert [q["type"] for q in back["questions"]] == ["PTR", "PTR"]
    assert all(q["unicast"] is False for q in back["questions"])


def test_the_qu_bit_asks_for_the_answer_straight_back():
    assert parse(build_query([ARC], unicast=True))["questions"][0]["unicast"] is True


def test_a_name_that_does_not_fit_the_format_is_left_out_not_truncated():
    long_label = "x" * 64                                   # a label may be at most 63 octets
    raw = build_query([ARC, long_label + ".local", "_ok._tcp.local"])
    assert [q["name"] for q in parse(raw)["questions"]] == [ARC, "_ok._tcp.local"]


def test_a_query_is_capped_at_max_names():
    names = [f"_svc{i}._tcp.local" for i in range(mdns.MAX_NAMES + 10)]
    assert len(parse(build_query(names))["questions"]) == mdns.MAX_NAMES


def test_build_query_ignores_rubbish_in_the_list():
    assert parse(build_query([ARC, "", None, 7]))["questions"][0]["name"] == ARC


# ---------------------------------------------------------------------------
# answers
# ---------------------------------------------------------------------------
def test_a_full_dns_sd_answer_reads_back_as_the_chain_it_is():
    raw = message(
        record(mdns.META_QUERY, 12, name(ARC)),
        record(ARC, 12, name(INSTANCE)),
        record(INSTANCE, 33, srv(8000, "foh-console.local")),
        record(INSTANCE, 16, txt(["mf=Audinate", "model=DEV-64", "arcp_vers=2.9.0", "bare"]), flush=True),
        record("foh-console.local", 1, bytes([192, 0, 2, 31])),
        record("foh-console.local", 28, bytes.fromhex("20010db8000000000000000000000031")))
    out = parse(raw)
    assert out["response"] is True and out["truncated"] is False
    kinds = {r["type"]: r for r in reversed(out["records"])}    # the first of each type; there are two PTRs
    assert list(out["records"][0]) == list(RECORD_KEYS)
    assert [r["value"] for r in out["records"] if r["type"] == "PTR"] == [ARC, INSTANCE]
    assert kinds["SRV"]["value"] == {"priority": 0, "weight": 0, "port": 8000, "target": "foh-console.local"}
    assert kinds["TXT"]["value"] == {"mf": "Audinate", "model": "DEV-64", "arcp_vers": "2.9.0", "bare": None}
    assert kinds["TXT"]["flush"] is True
    assert kinds["A"]["value"] == "192.0.2.31"
    assert kinds["AAAA"]["value"] == "2001:db8::31"


def test_records_from_every_section_are_read_into_one_list():
    """mDNS puts an answer's SRV/TXT/A in the additional section as often as not, and nothing downstream cares."""
    body = record(ARC, 12, name(INSTANCE)) + record(INSTANCE, 33, srv(8000, "h.local"))
    raw = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 1) + body
    assert [r["type"] for r in parse(raw)["records"]] == ["PTR", "SRV"]


def test_a_compression_pointer_is_followed_backwards():
    owner = name("foh-console.local")
    body = owner + struct.pack(">HHIH", 1, 1, 10, 4) + bytes([192, 0, 2, 31])
    pointer = struct.pack(">H", 0xC000 | 12) + struct.pack(">HHIH", 1, 1, 10, 4) + bytes([198, 51, 100, 7])
    raw = struct.pack(">HHHHHH", 0, 0x8400, 0, 2, 0, 0) + body + pointer
    records = parse(raw)["records"]
    assert [r["name"] for r in records] == ["foh-console.local", "foh-console.local"]
    assert [r["value"] for r in records] == ["192.0.2.31", "198.51.100.7"]


def test_a_forward_pointer_ends_that_name_instead_of_looping():
    raw = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x20" + struct.pack(">HHIH", 1, 1, 10, 4) + b"\x0a\x00\x00\x01"
    assert parse(raw)["records"] == []                      # nothing read, and it returned


def test_a_pointer_to_itself_ends_that_name():
    raw = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 10, 4) + b"\x0a\x00\x00\x01"
    assert parse(raw)["records"] == []


def test_a_malformed_tail_keeps_the_records_that_came_before_it():
    good = record(ARC, 12, name(INSTANCE))
    raw = struct.pack(">HHHHHH", 0, 0x8400, 0, 3, 0, 0) + good + b"\x05trunc"
    out = parse(raw)
    assert [r["type"] for r in out["records"]] == ["PTR"]


def test_a_record_that_claims_more_data_than_is_there_stops_the_read():
    raw = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + name(ARC) + struct.pack(">HHIH", 1, 1, 10, 40) + b"\x00\x00"
    assert parse(raw)["records"] == []


def test_a_type_this_module_does_not_decode_is_still_reported():
    raw = message(record(ARC, 99, b"\x01\x02"))
    assert [(r["type"], r["value"]) for r in parse(raw)["records"]] == [("type 99", None)]


@pytest.mark.parametrize("payload", [b"", b"\x00" * 11])
def test_a_message_too_short_to_be_dns_is_none(payload):
    assert parse(payload) is None


def test_the_truncated_flag_is_reported():
    assert parse(message(truncated=True))["truncated"] is True


def test_a_txt_record_keeps_the_first_spelling_of_a_repeated_key():
    raw = message(record(INSTANCE, 16, txt(["id=one", "id=two"])))
    assert parse(raw)["records"][0]["value"] == {"id": "one"}


def test_a_message_is_capped_at_max_records(monkeypatch):
    monkeypatch.setattr(mdns, "MAX_RECORDS", 3)
    raw = message(*[record(ARC, 12, name(INSTANCE)) for _ in range(9)])
    assert len(parse(raw)["records"]) == 3


# ---------------------------------------------------------------------------
# names
# ---------------------------------------------------------------------------
def test_split_service_separates_the_instance_from_its_type():
    assert split_service(INSTANCE) == ("FOH Console", ARC)
    assert split_service(ARC) == (None, ARC)
    assert split_service("foh-console.local") == (None, "foh-console.local")


def test_a_dot_inside_an_instance_label_survives_the_round_trip():
    """AV gear is full of devices called "Amp 1.2", and the instance is one wire label however many dots it has."""
    raw = message(record(ARC, 12, name(r"Amp 1\.2." + ARC)))
    pointed = parse(raw)["records"][0]["value"]
    assert pointed == r"Amp 1\.2._netaudio-arc._udp.local"
    assert split_service(pointed) == ("Amp 1.2", ARC)


def test_a_backslash_in_an_instance_label_survives_too():
    raw = message(record(ARC, 12, name(r"Rack\\A." + ARC)))
    assert split_service(parse(raw)["records"][0]["value"]) == ("Rack\\A", ARC)


def test_service_proto_finds_the_service_and_protocol_labels():
    assert service_proto(INSTANCE) == "_netaudio-arc._udp"
    assert service_proto(ARC) == "_netaudio-arc._udp"
    assert service_proto("_nmos-node._tcp.local") == "_nmos-node._tcp"
    assert service_proto("foh-console.local") is None


def test_instance_name_undoes_the_dns_sd_escapes():
    assert instance_name(r"Amp 1\.2") == "Amp 1.2"
    assert instance_name(r"a\\b") == "a\\b"
    assert instance_name(r"\065mp") == "Amp"                # the decimal escape of RFC 1035
    assert instance_name("plain") == "plain"


def test_the_seed_list_leads_with_the_meta_query_and_covers_the_big_ecosystems():
    assert mdns.SEED_QUERIES[0] == mdns.META_QUERY
    joined = " ".join(mdns.SEED_QUERIES)
    for needle in ("netaudio-arc", "nmos-node", "ravenna", "qsys"):
        assert needle in joined
