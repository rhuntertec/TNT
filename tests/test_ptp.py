"""tnt.ptp: IEEE 1588 v1/v2 parsing and the clock tree a Pro AV scan builds from it.

Every message is built here from the IEEE 1588-2008 and IEEE 1588-2002 field layouts, with invented gear: an Audinate
grandmaster, a Ubiquiti boundary clock and three followers, all on MACs from the documentation-safe 02:00:5e range
except where an OUI's own vendor text is the point. Nothing here touches a network.
"""
from __future__ import annotations

import struct

import pytest

from tnt import ptp
from tnt.ptp import (ANNOUNCE_KEYS, CLOCK_KEYS, DOMAIN_KEYS, FOLLOWER_KEYS, MASTER_KEYS, MESSAGE_KEYS, SENDER_KEYS,
                     ClockTracker, identity_mac, identity_text, parse)

GM = bytes.fromhex("001dc1fffe2a4108")          # Audinate, an EUI-64 built from 00:1D:C1:2A:41:08
GM_MAC = "00:1D:C1:2A:41:08"
BC = bytes.fromhex("74acb9fffe310c6e")          # Ubiquiti, the boundary clock that re-serves the domain
BC_MAC = "74:AC:B9:31:0C:6E"
F1 = bytes.fromhex("001dc1fffe2a415c")
F2 = bytes.fromhex("000fd4fffe081a90")
OTHER_GM = bytes.fromhex("02005e10fffe0001")

ANNOUNCE, SYNC, DELAY_REQ, DELAY_RESP, FOLLOW_UP = 0x0B, 0x00, 0x01, 0x09, 0x08


def v2(kind, *, source=GM, domain=0, seq=1, correction_ns=0.0, two_step=True, log_interval=1, utc_valid=True,
       gm=GM, steps=0, clock_class=6, accuracy=0x21, variance=0x4000, p1=128, p2=128, time_source=0x20, utc=37,
       flags_lo_extra=0x18, requesting=None):
    """One PTPv2 message: the 34-byte common header plus the body ``kind`` calls for."""
    header = bytearray(34)
    header[0] = kind
    header[1] = 0x02
    header[4] = domain
    header[6] = 0x02 if two_step else 0x00
    header[7] = (0x04 if utc_valid else 0x00) | flags_lo_extra
    struct.pack_into(">q", header, 8, int(round(correction_ns * 65536)))
    header[20:28] = source
    struct.pack_into(">H", header, 28, 1)
    struct.pack_into(">H", header, 30, seq)
    header[33] = log_interval & 0xFF
    if kind == ANNOUNCE:
        body = bytearray(30)
        struct.pack_into(">h", body, 10, utc)
        body[13], body[14], body[15] = p1, clock_class, accuracy
        struct.pack_into(">H", body, 16, variance)
        body[18] = p2
        body[19:27] = gm
        struct.pack_into(">H", body, 27, steps)
        body[29] = time_source
    elif kind == DELAY_RESP:
        body = bytearray(20)
        body[10:18] = requesting or F1
    else:
        body = bytearray(10)
    struct.pack_into(">H", header, 2, 34 + len(body))
    return bytes(header + body)


def v1(kind=SYNC, *, source=bytes.fromhex("001dc12a415c"), subdomain="_DFLT", seq=1, gm=bytes.fromhex("001dc12a4108"),
       stratum=1, identifier="GPS ", steps=1, sync_interval=1, utc=37, variance=0x4000, preferred=1, boundary=0,
       parent=None):
    """One PTPv1 message (IEEE 1588-2002): a 40-byte header, and for a Sync the grandmaster fields after it."""
    data = bytearray(132)
    struct.pack_into(">H", data, 0, 1)                      # versionPTP
    struct.pack_into(">H", data, 2, 1)                      # versionNetwork
    data[4:4 + len(subdomain)] = subdomain.encode()
    data[20] = 1
    data[22:28] = source
    struct.pack_into(">H", data, 28, 1)
    struct.pack_into(">H", data, 30, seq)
    data[32] = {SYNC: 0, DELAY_REQ: 1, FOLLOW_UP: 2, DELAY_RESP: 3}[kind]
    if kind == SYNC:
        struct.pack_into(">h", data, 50, utc)
        data[54:60] = gm
        data[67] = stratum
        data[68:72] = identifier.encode()[:4].ljust(4, b" ")
        struct.pack_into(">H", data, 74, variance)
        data[77] = preferred
        data[79] = boundary
        data[83] = sync_interval
        struct.pack_into(">H", data, 90, steps)
        data[102:108] = parent or source
    return bytes(data)


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------
def test_v2_announce_reads_every_grandmaster_fact():
    message = parse(v2(ANNOUNCE, steps=2))
    assert list(message) == list(MESSAGE_KEYS)
    assert list(message["announce"]) == list(ANNOUNCE_KEYS)
    assert (message["version"], message["type"], message["domain"]) == (2, "Announce", 0)
    assert message["source"] == identity_text(GM) == "00:1D:C1:FF:FE:2A:41:08"
    assert message["source_mac"] == GM_MAC
    assert message["two_step"] is True and message["unicast"] is False and message["parent"] is None
    assert message["interval_s"] == 2.0                     # logMessageInterval 1
    a = message["announce"]
    assert (a["grandmaster"], a["grandmaster_mac"]) == (identity_text(GM), GM_MAC)
    assert (a["clock_class"], a["locked"]) == (6, True)
    assert a["clock_class_text"].startswith("locked to a primary reference")
    assert (a["accuracy"], a["accuracy_text"]) == (0x21, "100 ns")
    assert (a["time_source"], a["time_source_text"]) == (0x20, "GPS")
    assert (a["steps_removed"], a["utc_offset"], a["time_traceable"]) == (2, 37, True)


@pytest.mark.parametrize("clock_class,locked", [(6, True), (13, True), (7, False), (248, False), (200, None)])
def test_clock_class_says_whether_the_grandmaster_is_really_locked(clock_class, locked):
    assert parse(v2(ANNOUNCE, clock_class=clock_class))["announce"]["locked"] is locked


def test_utc_offset_is_none_unless_the_message_says_it_is_valid():
    assert parse(v2(ANNOUNCE, utc_valid=False))["announce"]["utc_offset"] is None
    assert parse(v2(ANNOUNCE, utc_valid=True))["announce"]["utc_offset"] == 37


def test_correction_field_is_nanoseconds_and_signed():
    assert parse(v2(SYNC, correction_ns=812.5))["correction_ns"] == pytest.approx(812.5)
    assert parse(v2(SYNC, correction_ns=-12.0))["correction_ns"] == pytest.approx(-12.0)
    assert parse(v2(SYNC))["correction_ns"] == 0.0


@pytest.mark.parametrize("raw,seconds", [(0, 1.0), (1, 2.0), (3, 8.0), (0xFF, 0.5), (0xF8, 1 / 256), (0x7F, None)])
def test_log_message_interval_is_a_signed_power_of_two(raw, seconds):
    assert parse(v2(SYNC, log_interval=raw))["interval_s"] == (None if seconds is None else pytest.approx(seconds))


def test_delay_resp_names_the_follower_that_asked():
    assert parse(v2(DELAY_RESP, requesting=F1))["requesting"] == identity_text(F1)


def test_identity_mac_only_unpacks_a_eui64_built_from_one():
    assert identity_mac(GM) == GM_MAC
    assert identity_mac(bytes.fromhex("001dc1ffff2a4108")) == GM_MAC       # the older EUI-48 encapsulation
    assert identity_mac(bytes.fromhex("0102030405060708")) is None         # an identity the device made up
    assert identity_mac(b"\x00" * 7) is None


@pytest.mark.parametrize("payload", [b"", b"\x00", b"\x0b\x02", b"\x0b\x03" + b"\x00" * 60,
                                     bytes([0x0E, 0x02]) + b"\x00" * 60, b"\x0b\x02" + b"\x00" * 20])
def test_rubbish_is_none_not_an_exception(payload):
    assert parse(payload) is None


def test_a_version_this_module_does_not_read_is_none():
    assert parse(bytes([0x0B, 0x09]) + b"\x00" * 62) is None               # versionPTP 9
    assert parse(struct.pack(">H", 7) + b"\x00" * 60) is None              # a v1 header claiming version 7


def test_v1_sync_carries_the_grandmaster_the_way_dante_clocks():
    message = parse(v1(SYNC, stratum=1, identifier="GPS "))
    assert list(message) == list(MESSAGE_KEYS)     # the shape never depends on the version
    assert (message["version"], message["type"]) == (1, "Sync")
    assert message["domain_text"] == "subdomain _DFLT"
    assert message["source"] == "00:1D:C1:2A:41:5C"
    a = message["announce"]
    assert (a["grandmaster"], a["grandmaster_mac"]) == ("00:1D:C1:2A:41:08", "00:1D:C1:2A:41:08")
    assert (a["clock_class"], a["locked"], a["time_source_text"]) == (6, True, "GPS")
    assert a["steps_removed"] == 1
    assert message["correction_ns"] == 0.0                                 # v1 has no transparent clocks


@pytest.mark.parametrize("stratum,clock_class", [(1, 6), (2, 7), (3, 13), (4, 248)])
def test_v1_stratum_maps_onto_the_v2_class_that_means_the_same(stratum, clock_class):
    assert parse(v1(SYNC, stratum=stratum))["announce"]["clock_class"] == clock_class


# ---------------------------------------------------------------------------
# the clock tree
# ---------------------------------------------------------------------------
def feed(tracker, messages, start=1000.0, step=0.5, src_ip=None):
    ts = start
    for message in messages:
        tracker.add(message, ts, src_ip=src_ip)
        ts += step
    return ts


def test_a_plain_network_puts_the_grandmaster_one_hop_away():
    tracker = ClockTracker()
    for i in range(4):
        tracker.add(v2(ANNOUNCE, source=GM, seq=i), 1000.0 + i * 2, src_ip="192.0.2.10")
        tracker.add(v2(SYNC, source=GM, seq=i), 1000.5 + i * 2, src_ip="192.0.2.10")
    view = tracker.view()
    assert list(view) == list(CLOCK_KEYS)
    assert view["heard"] is True and view["versions"] == [2] and len(view["domains"]) == 1
    domain = view["best"]
    assert list(domain) == list(DOMAIN_KEYS)
    assert list(domain["master"]) == list(MASTER_KEYS)
    assert domain["master"]["identity"] == identity_text(GM)
    assert domain["master"]["ip"] == "192.0.2.10"           # it announced itself, so the address really is its own
    assert domain["master"]["parent"] is None
    assert [s["role"] for s in domain["senders"]] == ["grandmaster"]
    assert list(domain["senders"][0]) == list(SENDER_KEYS)


def test_a_boundary_clock_is_a_different_device_from_the_grandmaster_it_relays():
    """The announcement names a grandmaster that may be hops away; the packet came from whatever port served it
    last. Giving the grandmaster the sender's address would put the switch's IP on the wrong row, and counting the
    sender as a master would report a contention that is not there."""
    tracker = ClockTracker()
    for i in range(4):
        tracker.add(v2(ANNOUNCE, source=BC, gm=GM, steps=1, seq=i), 1000.0 + i * 2, src_ip="192.0.2.2")
        tracker.add(v2(SYNC, source=BC, seq=i), 1000.5 + i * 2, src_ip="192.0.2.2")
    domain = tracker.view()["best"]
    master = domain["master"]
    assert master["identity"] == identity_text(GM) and master["mac"] == GM_MAC
    assert master["ip"] is None                             # the grandmaster never claimed this address
    assert master["steps_removed"] == 1
    assert (master["parent"], master["parent_mac"]) == (identity_text(BC), BC_MAC)
    assert len(domain["masters"]) == 1                      # one grandmaster, not two
    assert [(s["identity"], s["role"], s["ip"]) for s in domain["senders"]] == [(identity_text(BC), "boundary", "192.0.2.2")]


def test_two_grandmasters_in_one_domain_are_both_kept():
    tracker = ClockTracker()
    tracker.add(v2(ANNOUNCE, source=GM, gm=GM), 1000.0)
    tracker.add(v2(ANNOUNCE, source=OTHER_GM, gm=OTHER_GM), 1001.0)
    domain = tracker.view()["best"]
    assert len(domain["masters"]) == 2
    assert domain["changes"] == 1                           # the active grandmaster moved once


def test_delay_requests_enumerate_the_followers_and_a_reply_confirms_one():
    tracker = ClockTracker()
    tracker.add(v2(ANNOUNCE, source=GM), 1000.0)
    for i in range(3):
        tracker.add(v2(DELAY_REQ, source=F1, seq=i), 1001.0 + i, src_ip="192.0.2.31")
        tracker.add(v2(DELAY_REQ, source=F2, seq=i), 1001.2 + i, src_ip="192.0.2.35")
    tracker.add(v2(DELAY_RESP, source=GM, requesting=F1), 1004.0)
    followers = tracker.view()["best"]["followers"]
    assert list(followers[0]) == list(FOLLOWER_KEYS)
    assert [(f["identity"], f["ip"], f["asking"]) for f in followers] == [
        (identity_text(F1), "192.0.2.31", True), (identity_text(F2), "192.0.2.35", False)]


def test_a_master_is_never_listed_as_a_follower_of_its_own_tree():
    tracker = ClockTracker()
    tracker.add(v2(ANNOUNCE, source=BC, gm=GM, steps=1), 1000.0)
    tracker.add(v2(DELAY_REQ, source=BC), 1001.0)           # the boundary clock asking its own upstream
    assert tracker.view()["best"]["followers"] == []


def test_two_domains_and_two_versions_are_kept_apart():
    tracker = ClockTracker()
    tracker.add(v2(ANNOUNCE, source=GM, domain=0), 1000.0)
    tracker.add(v2(ANNOUNCE, source=OTHER_GM, domain=127), 1000.1)
    tracker.add(v1(SYNC), 1000.2)
    view = tracker.view()
    assert len(view["domains"]) == 3
    assert sorted(view["versions"]) == [1, 2]
    assert {(d["version"], d["domain"]) for d in view["domains"]} == {(2, 0), (2, 127), (1, 0)}


def test_the_busiest_domain_is_the_one_the_room_is_running_on():
    tracker = ClockTracker()
    tracker.add(v2(ANNOUNCE, source=OTHER_GM, domain=127), 1000.0)
    for i in range(6):
        tracker.add(v2(SYNC, source=GM, domain=0, seq=i), 1001.0 + i)
    assert tracker.view()["best"]["domain"] == 0


def test_sync_interval_and_jitter_are_measured_not_announced():
    tracker = ClockTracker()
    # eight Syncs a quarter of a second apart, one of them 40 ms late
    times = [0.0, 0.25, 0.5, 0.75, 1.0, 1.29, 1.54, 1.79]
    for i, offset in enumerate(times):
        tracker.add(v2(SYNC, source=GM, seq=i), 1000.0 + offset)
    domain = tracker.view()["best"]
    assert domain["sync_s"] == pytest.approx(0.25, abs=0.005)
    assert domain["sync_jitter_ms"] == pytest.approx(40.0, abs=1.0)


def test_an_interval_needs_enough_samples_before_it_is_reported():
    tracker = ClockTracker()
    tracker.add(v2(SYNC, source=GM), 1000.0)
    tracker.add(v2(SYNC, source=GM), 1000.25)
    domain = tracker.view()["best"]
    assert domain["sync_s"] is None and domain["sync_jitter_ms"] is None


def test_a_non_zero_correction_field_is_a_transparent_clock():
    tracker = ClockTracker()
    tracker.add(v2(SYNC, source=GM, correction_ns=0.0), 1000.0)
    assert tracker.view()["transparent"] is False
    tracker.add(v2(SYNC, source=GM, correction_ns=738.25), 1000.5)
    view = tracker.view()
    assert view["transparent"] is True
    assert view["best"]["correction_ns"] == pytest.approx(738.25)


def test_the_v1_sync_puts_the_sender_and_the_grandmaster_in_the_right_places():
    tracker = ClockTracker()
    for i in range(3):
        tracker.add(v1(SYNC, seq=i), 1000.0 + i, src_ip="192.0.2.31")
    domain = tracker.view()["best"]
    assert domain["version"] == 1
    assert domain["master"]["identity"] == "00:1D:C1:2A:41:08"
    assert [s["identity"] for s in domain["senders"]] == ["00:1D:C1:2A:41:5C"]


def test_a_tracker_is_bounded_by_its_own_caps(monkeypatch):
    monkeypatch.setattr(ptp, "MAX_DOMAINS", 2)
    monkeypatch.setattr(ptp, "MAX_FOLLOWERS", 3)
    tracker = ClockTracker()
    for domain in range(5):
        tracker.add(v2(ANNOUNCE, source=GM, domain=domain), 1000.0 + domain)
    for i in range(8):
        follower = bytes.fromhex("02005e10fffe") + bytes([0, i])
        tracker.add(v2(DELAY_REQ, source=follower, domain=0), 1010.0 + i)
    view = tracker.view()
    assert len(view["domains"]) == 2
    assert len(view["domains"][0]["followers"]) <= 3
    assert view["dropped"] > 0


def test_reset_empties_the_tracker():
    tracker = ClockTracker()
    tracker.add(v2(ANNOUNCE, source=GM), 1000.0)
    tracker.reset()
    view = tracker.view()
    assert view["heard"] is False and view["domains"] == [] and view["best"] is None


def test_vendor_text_comes_from_the_oui_registry_and_a_failure_is_survivable(monkeypatch):
    tracker = ClockTracker()
    tracker.add(v2(ANNOUNCE, source=GM), 1000.0)
    assert "Audinate" in (tracker.view()["best"]["master"]["vendor"] or "")
    monkeypatch.setattr(ptp, "_vendor_for_mac", lambda _mac: None)
    other = ClockTracker()
    other.add(v2(ANNOUNCE, source=GM), 1000.0)
    assert other.view()["best"]["master"]["vendor"] is None
