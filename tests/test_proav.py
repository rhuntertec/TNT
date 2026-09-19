"""tnt.proav: SAP/SDP, device merging, the findings and the two graphs, and the scanner that collects them.

The invented room is the one the mock serves: an Audinate grandmaster one Ubiquiti boundary clock away, four
followers, three announced AES67 streams (one naming a grandmaster that is not here) and a Layer 2 listen that found
a querier. Addresses are from 192.0.2.0/24 and 239.69.0.0/16. No socket is opened except by the scanner tests, which
bind to loopback through a stub.
"""
from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

from tnt import proav, ptp
from tnt.proav import (DEVICE_KEYS, EDGE_KEYS, FINDING_IDS, FINDING_KEYS, JOB_KEYS, LISTENER_KEYS, NODE_KEYS,
                       PLOT_KEYS, RESULT_KEYS, SCAN_ADAPTER_KEYS, SCAN_STATUS_KEYS, STREAM_KEYS, TILE_KEYS,
                       ProAvScanner, build_devices, build_findings, build_graph, classify_service, classify_vendor,
                       parse_sap, parse_sdp)

GM_ID = "00:1D:C1:FF:FE:2A:41:08"
GM_MAC = "00:1D:C1:2A:41:08"
BC_ID = "74:AC:B9:FF:FE:31:0C:6E"
BC_MAC = "74:AC:B9:31:0C:6E"
STALE_GM = "AA:BB:CC:FF:FE:10:20:30"

SDP = """v=0
o=- 1311738121 1311738121 IN IP4 192.0.2.31
s=FOH Mix : Main LR
i=Front of house, main bus
c=IN IP4 239.69.4.12/32
t=0 0
m=audio 5004 RTP/AVP 98
a=rtpmap:98 L24/48000/8
a=ptime:1
a=ts-refclk:ptp=IEEE1588-2008:00-1D-C1-FF-FE-2A-41-08:0
a=mediaclk:direct=0
a=sendonly
"""


def sap(body: str, *, source: str = "192.0.2.31", deletion: bool = False, mime: bool = True,
        auth_words: int = 0, version: int = 1, ipv6: bool = False) -> bytes:
    flags = (version << 5) | (0x10 if ipv6 else 0) | (0x04 if deletion else 0)
    head = bytes([flags, auth_words]) + struct.pack(">H", 0x1234) + socket.inet_aton(source)
    return head + b"\x00" * (auth_words * 4) + (b"application/sdp\x00" if mime else b"") + body.encode()


def clock_view(*, steps: int = 1, changes: int = 0, jitter: float = 0.41, versions=(2,), domains: int = 1,
               clock_class: int = 6, locked=True, masters: int = 1, transparent: bool = True) -> dict:
    master = {"identity": GM_ID, "mac": GM_MAC, "vendor": "Audinate Pty L", "ip": None, "priority1": 128,
              "priority2": 128, "clock_class": clock_class, "clock_class_text": "text", "accuracy": 0x21,
              "accuracy_text": "100 ns", "variance": 0x4100, "steps_removed": steps, "time_source": 0x20,
              "time_source_text": "GPS", "utc_offset": 37, "leap61": False, "leap59": False,
              "time_traceable": True, "frequency_traceable": True, "locked": locked, "two_step": True,
              "parent": BC_ID if steps else None, "parent_mac": BC_MAC if steps else None,
              "parent_vendor": "Ubiquiti Inc" if steps else None, "announce_s": 2.0, "count": 86,
              "first_ts": 1000.0, "last_ts": 1030.0}
    all_masters = [master]
    for i in range(1, masters):
        all_masters.append(dict(master, identity=f"02:00:5E:FF:FE:00:00:0{i}", mac=f"02:00:5E:00:00:0{i}"))
    followers = [
        {"identity": "00:1D:C1:FF:FE:2A:41:5C", "mac": "00:1D:C1:2A:41:5C", "vendor": "Audinate Pty L",
         "ip": "192.0.2.31", "asking": True, "count": 58, "first_ts": 1000.0, "last_ts": 1030.0},
        {"identity": "00:50:C2:FF:FE:AB:03:71", "mac": "00:50:C2:AB:03:71", "vendor": "Attero Tech",
         "ip": "192.0.2.37", "asking": False, "count": 12, "first_ts": 1000.0, "last_ts": 1030.0},
    ]
    out = []
    for index in range(domains):
        out.append({"version": versions[min(index, len(versions) - 1)], "domain": index,
                    "label": f"domain {index}", "master": all_masters[0], "masters": all_masters,
                    "senders": [{"identity": BC_ID, "mac": BC_MAC, "vendor": "Ubiquiti Inc", "ip": "192.0.2.2",
                                 "role": "boundary", "count": 259, "first_ts": 1000.0, "last_ts": 1030.0}],
                    "followers": followers, "messages": 659 - index, "announce_s": 2.0, "sync_s": 0.125,
                    "sync_jitter_ms": jitter, "correction_ns": 738.2 if transparent else None,
                    "transparent": transparent, "changes": changes, "first_ts": 1000.0, "last_ts": 1030.0})
    return {"heard": True, "messages": 659, "dropped": 0, "versions": sorted(set(versions)), "domains": out,
            "best": out[0], "transparent": transparent, "first_ts": 1000.0, "last_ts": 1030.0}


def ids(findings):
    return [f["id"] for f in findings]


def level_of(findings, ident):
    return next((f["level"] for f in findings if f["id"] == ident), None)


# ---------------------------------------------------------------------------
# SAP and SDP
# ---------------------------------------------------------------------------
def test_sap_header_and_its_sdp_body():
    head = parse_sap(sap(SDP))
    assert head["version"] == 1 and head["deletion"] is False
    assert head["source"] == "192.0.2.31" and head["content_type"] == "application/sdp"
    assert head["body"].startswith("v=0")


def test_sap_without_a_content_type_still_finds_the_body():
    assert parse_sap(sap(SDP, mime=False))["body"].startswith("v=0")


def test_sap_skips_the_authentication_block():
    assert parse_sap(sap(SDP, auth_words=3))["body"].startswith("v=0")


def test_a_deletion_is_marked_as_one():
    assert parse_sap(sap(SDP, deletion=True))["deletion"] is True


@pytest.mark.parametrize("payload", [b"", b"\x20\x00\x00", bytes([0x40, 0, 0, 0, 1, 2, 3, 4]) + b"v=0"])
def test_sap_this_module_does_not_read_is_none(payload):
    assert parse_sap(payload) is None


def test_an_encrypted_or_compressed_announcement_is_refused_rather_than_guessed_at():
    assert parse_sap(bytes([0x22, 0, 0, 0, 192, 0, 2, 1]) + b"v=0") is None      # encrypted
    assert parse_sap(bytes([0x21, 0, 0, 0, 192, 0, 2, 1]) + b"v=0") is None      # compressed


def test_sdp_reads_the_whole_stream():
    stream = parse_sdp(SDP, source="192.0.2.31", ts=1000.0)
    assert list(stream) == list(STREAM_KEYS)
    assert stream["name"] == "FOH Mix : Main LR" and stream["info"] == "Front of house, main bus"
    assert (stream["group"], stream["port"], stream["scope"]) == ("239.69.4.12", 5004, 32)
    assert (stream["codec"], stream["rate"], stream["channels"], stream["depth"]) == ("L24", 48000, 8, 24)
    assert stream["ptime_ms"] == 1.0
    assert stream["origin"] == "192.0.2.31" and stream["direction"] == "sendonly"
    assert stream["id"] == "239.69.4.12:5004"


def test_the_reference_clock_and_its_domain_are_read_apart():
    """"ptp=IEEE1588-2008:<identity>:<domain>" is an identity *and* a domain; a greedy address match ate the domain."""
    stream = parse_sdp(SDP)
    assert stream["refclk"] == GM_ID
    assert stream["refclk_domain"] == 0
    assert stream["refclk_kind"] == "IEEE1588-2008"


def test_a_reference_clock_with_no_domain_still_reads():
    body = SDP.replace(":00-1D-C1-FF-FE-2A-41-08:0", ":00-1D-C1-FF-FE-2A-41-08")
    stream = parse_sdp(body)
    assert stream["refclk"] == GM_ID and stream["refclk_domain"] is None


def test_a_sender_that_is_its_own_clock_says_so():
    body = SDP.replace("a=ts-refclk:ptp=IEEE1588-2008:00-1D-C1-FF-FE-2A-41-08:0", "a=ts-refclk:localmac=00-1D-C1-2A-41-5C")
    stream = parse_sdp(body)
    assert stream["refclk_kind"] == "localmac" and stream["refclk"] == "00:1D:C1:2A:41:5C"


def test_the_bandwidth_is_computed_from_the_format_not_announced():
    """48 kHz x 1 ms = 48 samples; 48 x 8 channels x 3 bytes = 1152 B, and 1000 packets a second of that plus the
    RTP/UDP/IP/Ethernet overhead is what the stream really costs on the link."""
    stream = parse_sdp(SDP)
    assert stream["packet_bytes"] == 1152
    assert stream["bitrate_mbps"] == pytest.approx((1152 + proav.PACKET_OVERHEAD_BYTES) * 8 / 1000.0, abs=0.001)


def test_a_session_level_connection_line_is_used_when_the_media_has_none():
    assert parse_sdp(SDP)["group"] == "239.69.4.12"


def test_a_media_level_connection_line_wins():
    body = SDP.replace("m=audio 5004", "m=audio 5004").replace("a=rtpmap", "c=IN IP4 239.69.9.9/8\na=rtpmap")
    assert parse_sdp(body)["group"] == "239.69.9.9"


def test_sdp_with_no_media_line_is_none():
    assert parse_sdp("v=0\no=- 1 1 IN IP4 192.0.2.1\ns=nothing\nt=0 0\n") is None
    assert parse_sdp("") is None


def test_an_unknown_codec_leaves_the_bandwidth_unknown_rather_than_guessed():
    body = SDP.replace("L24/48000/8", "SOMETHING/48000/8")
    stream = parse_sdp(body)
    assert stream["codec"] == "SOMETHING" and stream["depth"] is None
    assert stream["packet_bytes"] is None and stream["bitrate_mbps"] is None


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("service,family", [
    ("FOH._netaudio-arc._udp.local", "dante"), ("_netaudio-cmc._udp.local", "dante"),
    ("_nmos-node._tcp.local", "st2110"), ("_ravenna._tcp.local", "ravenna"), ("_qsys._tcp.local", "qsys"),
    ("_netaudio-brandnew._udp.local", "dante"),          # not in the table: the substring rule catches it
    ("_http._tcp.local", ""), ("_ftp._tcp.local", "other"), (None, "other")])
def test_service_types_are_classified(service, family):
    assert classify_service(service)[0] == family


@pytest.mark.parametrize("vendor,family,kind", [
    ("Audinate Pty L", "dante", "av"), ("QSC Audio Products", "qsys", "av"), ("Shure Incorporated", None, "av"),
    ("Ubiquiti Inc", None, "network"), ("Cisco Systems, Inc", None, "network"),
    ("Some Unknown Co", None, None), (None, None, None)])
def test_vendors_are_classified_from_the_registry_text(vendor, family, kind):
    assert classify_vendor(vendor) == (family, kind)


def test_a_laptop_maker_is_not_called_network_infrastructure():
    """Dell and HP make switches, but far more of their addresses are laptops; calling them infrastructure would
    hide them from the "not AV gear" finding, which is the point of that check on a dedicated AV VLAN."""
    assert classify_vendor("Dell Inc.") == (None, None)


# ---------------------------------------------------------------------------
# devices
# ---------------------------------------------------------------------------
def services_seen():
    return [
        {"instance": "FOH Console", "type": "_netaudio-arc._udp.local", "host": "foh.local", "port": 8000,
         "txt": {"mf": "Audinate", "model": "DEV-64", "arcp_vers": "4.2.1"}, "ips": ["192.0.2.31"], "ts": 1000.0},
        {"instance": "FOH Console", "type": "_http._tcp.local", "host": "foh.local", "port": 80,
         "txt": {}, "ips": [], "ts": 1000.0},
        {"instance": "Show PC", "type": "_workstation._tcp.local", "host": "pc.local", "port": 9,
         "txt": {}, "ips": ["192.0.2.50"], "ts": 1000.0},
    ]


def test_one_device_per_box_however_many_ways_it_was_seen():
    devices = build_devices(services_seen(), clock_view(), [parse_sdp(SDP, ts=1000.0)],
                            arp={"192.0.2.31": "00:1D:C1:2A:41:5C", "192.0.2.50": "B0:7D:64:19:E2:04"},
                            vendor_lookup=lambda mac: {"00:1D:C1:2A:41:5C": "Audinate Pty L"}.get(mac))
    assert all(list(d) == list(DEVICE_KEYS) for d in devices)
    foh = next(d for d in devices if d["name"] == "FOH Console")
    assert foh["ip"] == "192.0.2.31" and foh["mac"] == "00:1D:C1:2A:41:5C"
    assert foh["model"] == "DEV-64" and foh["firmware"] == "4.2.1"
    assert foh["family"] == "dante" and foh["clock_role"] == "follower"
    assert foh["streams_out"] == 1
    assert sorted(foh["sources"]) == ["mdns", "ptp", "sap"]
    assert len([s for s in foh["services"]]) == 2            # its two service instances are on the one row


def test_the_grandmaster_and_the_boundary_clock_that_relays_it_are_two_rows():
    devices = build_devices([], clock_view(steps=1), [], vendor_lookup=lambda mac: None)
    roles = {d["clock_identity"]: d["clock_role"] for d in devices}
    assert roles[GM_ID] == "grandmaster"
    assert roles[BC_ID] == "boundary"
    gm = next(d for d in devices if d["clock_identity"] == GM_ID)
    assert gm["ip"] is None                                  # the address belonged to the switch, not to it
    bc = next(d for d in devices if d["clock_identity"] == BC_ID)
    assert bc["ip"] == "192.0.2.2"


def test_an_ipv4_address_is_preferred_over_a_link_local_ipv6_one():
    services = [{"instance": "Mixer", "type": "_netaudio-arc._udp.local", "host": "m.local", "port": 8000,
                 "txt": {}, "ips": ["fe80::1", "192.0.2.31"], "ts": 1000.0}]
    device = build_devices(services, {}, [])[0]
    assert device["ip"] == "192.0.2.31"
    assert set(device["ips"]) == {"fe80::1", "192.0.2.31"}


def test_two_instances_of_one_name_merge_even_when_only_one_carries_an_address():
    services = [
        {"instance": "Printer", "type": "_ipp._tcp.local", "host": None, "port": None, "txt": {}, "ips": [],
         "ts": 1000.0},
        {"instance": "Printer", "type": "_pdl-datastream._tcp.local", "host": "p.local", "port": 9100, "txt": {},
         "ips": ["192.0.2.60"], "ts": 1000.0}]
    devices = build_devices(services, {}, [])
    assert len(devices) == 1 and devices[0]["ip"] == "192.0.2.60"


def test_two_devices_that_share_a_name_but_have_different_addresses_stay_apart():
    services = [
        {"instance": "Amp", "type": "_netaudio-arc._udp.local", "host": "a1.local", "port": 8000, "txt": {},
         "ips": ["192.0.2.41"], "ts": 1000.0},
        {"instance": "Amp", "type": "_netaudio-arc._udp.local", "host": "a2.local", "port": 8000, "txt": {},
         "ips": ["192.0.2.42"], "ts": 1000.0}]
    assert len(build_devices(services, {}, [])) == 2


def test_a_device_with_no_name_is_called_by_its_vendor_and_the_tail_of_its_mac():
    devices = build_devices([], clock_view(), [], vendor_lookup=lambda mac: "Audinate Pty L")
    gm = next(d for d in devices if d["clock_identity"] == GM_ID)
    assert gm["name"] == "Audinate Pty L 2A:41:08"


def test_the_device_list_is_bounded(monkeypatch):
    monkeypatch.setattr(proav, "MAX_DEVICES", 3)
    services = [{"instance": f"Box {i}", "type": "_http._tcp.local", "host": f"b{i}.local", "port": 80,
                 "txt": {}, "ips": [f"192.0.2.{i + 10}"], "ts": 1000.0} for i in range(9)]
    assert len(build_devices(services, {}, [])) == 3


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------
def test_every_finding_id_is_declared_and_the_shape_is_the_contract():
    findings = build_findings(clock_view(), [parse_sdp(SDP)], build_devices(services_seen(), clock_view(), []),
                              l2=None, link_mbps=1000.0)
    assert findings
    for f in findings:
        assert list(f) == list(FINDING_KEYS)
        assert f["id"] in FINDING_IDS
        assert f["level"] in proav.FINDING_LEVELS


def test_findings_are_sorted_worst_first():
    findings = build_findings(clock_view(changes=2), [parse_sdp(SDP.replace(GM_ID.replace(":", "-"), STALE_GM.replace(":", "-")))],
                              build_devices(services_seen(), clock_view(), []), link_mbps=1000.0)
    order = [proav.FINDING_LEVELS.index(f["level"]) for f in findings]
    assert order == sorted(order)


def test_two_domains_is_a_problem_and_two_versions_a_warning():
    findings = build_findings(clock_view(domains=2, versions=(2, 1)), [], [])
    assert level_of(findings, "clock.domains") == "bad"
    assert level_of(findings, "clock.versions") == "warn"


def test_a_free_running_grandmaster_warns_and_a_holdover_one_is_a_problem():
    assert level_of(build_findings(clock_view(clock_class=248, locked=False), [], []), "clock.free") == "warn"
    assert level_of(build_findings(clock_view(clock_class=7, locked=False), [], []), "clock.holdover") == "bad"
    assert level_of(build_findings(clock_view(), [], []), "clock.locked") == "good"


def test_a_grandmaster_that_changed_mid_listen_is_a_problem():
    assert level_of(build_findings(clock_view(changes=3), [], []), "clock.changed") == "bad"
    assert "clock.changed" not in ids(build_findings(clock_view(changes=0), [], []))


def test_more_than_one_master_in_a_domain_is_contention():
    assert level_of(build_findings(clock_view(masters=2), [], []), "clock.contention") == "warn"
    assert "clock.contention" not in ids(build_findings(clock_view(masters=1), [], []))


@pytest.mark.parametrize("jitter,level", [(0.2, None), (2.0, "warn"), (25.0, "bad")])
def test_sync_jitter_is_graded(jitter, level):
    assert level_of(build_findings(clock_view(jitter=jitter), [], []), "clock.jitter") == level


def test_a_boundary_clock_and_a_transparent_clock_are_both_reported():
    findings = build_findings(clock_view(steps=2, transparent=True), [], [])
    assert level_of(findings, "clock.boundary") == "info"
    assert level_of(findings, "clock.transparent") == "info"
    assert "clock.boundary" not in ids(build_findings(clock_view(steps=0, transparent=False), [], []))


def test_a_stream_naming_a_grandmaster_that_is_not_here_is_the_headline_problem():
    stale = parse_sdp(SDP.replace("00-1D-C1-FF-FE-2A-41-08", STALE_GM.replace(":", "-")))
    findings = build_findings(clock_view(), [parse_sdp(SDP), stale], [], link_mbps=1000.0)
    assert level_of(findings, "stream.refclk") == "bad"
    evidence = next(f for f in findings if f["id"] == "stream.refclk")["evidence"]
    assert evidence[0]["refclk"] == STALE_GM


def test_a_stream_that_is_its_own_clock_is_a_warning():
    body = SDP.replace("a=ts-refclk:ptp=IEEE1588-2008:00-1D-C1-FF-FE-2A-41-08:0", "a=ts-refclk:localmac=00-1D-C1-2A-41-5C")
    assert level_of(build_findings(clock_view(), [parse_sdp(body)], []), "stream.domain") == "warn"


@pytest.mark.parametrize("link,level", [(10000.0, None), (50.0, "warn"), (40.0, "bad")])
def test_announced_bandwidth_is_graded_against_the_link(link, level):
    streams = [parse_sdp(SDP) for _ in range(3)]
    for i, s in enumerate(streams):
        s["id"] = f"239.69.4.{i}:5004"
        s["group"] = f"239.69.4.{i}"
    assert level_of(build_findings(clock_view(), streams, [], link_mbps=link), "stream.bandwidth") == level


def test_mixed_packet_times_are_a_note():
    fast, slow = parse_sdp(SDP), parse_sdp(SDP.replace("a=ptime:1", "a=ptime:4"))
    slow["group"], slow["id"] = "239.69.4.99", "239.69.4.99:5004"
    assert level_of(build_findings(clock_view(), [fast, slow], []), "stream.ptime") == "info"


def test_a_multicast_ttl_of_one_is_a_warning():
    body = SDP.replace("c=IN IP4 239.69.4.12/32", "c=IN IP4 239.69.4.12/1")
    assert level_of(build_findings(clock_view(), [parse_sdp(body)], []), "stream.scope") == "warn"


def test_no_clock_on_a_network_of_pro_gear_is_a_warning_but_on_one_without_it_is_a_note():
    quiet = {"heard": False, "messages": 0, "dropped": 0, "versions": [], "domains": [], "best": None,
             "transparent": False, "first_ts": None, "last_ts": None}
    dante = build_devices(services_seen(), {}, [])
    assert level_of(build_findings(quiet, [], dante), "clock.none") == "warn"
    plain = build_devices([services_seen()[2]], {}, [])
    assert level_of(build_findings(quiet, [], plain), "clock.none") == "info"


def test_without_a_layer_2_listen_the_checks_that_need_one_say_so_rather_than_passing():
    findings = build_findings(clock_view(), [], [], l2=None)
    assert level_of(findings, "net.l2") == "info"
    for ident in ("net.querier", "net.flood", "net.dscp"):
        assert ident not in ids(findings)


def l2_view(*, querier=True, flooded=(), dscp=(56, 46), lost=0):
    return {"ok": True, "reason": None, "frames": 100, "lost": lost, "igmp_seen": 12,
            "querier": {"ip": "192.0.2.1", "interval_s": 125.0, "queries": 2} if querier else None,
            "memberships": [], "flooded": list(flooded), "dscp": {"ptp": dscp[0], "audio": dscp[1]}}


SWITCH = {"switch_name": "core-av-sw-01", "switch_description": "UniFi Enterprise Audio/Video XG 24 PoE",
          "port_id": "Port 14", "vlan": 120, "link": {"text": "1000BASE-T full"},
          "poe": {"class": 3, "allocated_w": 7.4}}


def test_a_missing_querier_is_a_problem_where_there_is_audio_and_a_note_where_there_is_not():
    streams = [parse_sdp(SDP)]
    assert level_of(build_findings(clock_view(), streams, [], l2=l2_view(querier=False)), "net.querier") == "bad"
    quiet = {"heard": False, "messages": 0, "dropped": 0, "versions": [], "domains": [], "best": None,
             "transparent": False, "first_ts": None, "last_ts": None}
    assert level_of(build_findings(quiet, [], [], l2=l2_view(querier=False)), "net.querier") == "info"
    assert level_of(build_findings(clock_view(), streams, [], l2=l2_view(querier=True)), "net.querier") == "good"


def test_flooding_is_graded_by_what_the_flooded_groups_are_carrying():
    control = [{"group": "239.192.0.11", "port": 5004, "source": "192.0.2.37", "packets": 41, "bytes": 30012,
                "mbps": 0.11}]
    media = control + [{"group": "239.69.4.20", "port": 5004, "source": "192.0.2.35", "packets": 4013,
                        "bytes": 4941999, "mbps": 18.31}]
    assert level_of(build_findings(clock_view(), [], [], l2=l2_view(flooded=control)), "net.flood") == "info"
    assert level_of(build_findings(clock_view(), [], [], l2=l2_view(flooded=media)), "net.flood") == "warn"


def test_unmarked_traffic_is_only_a_finding_where_there_is_av_traffic_to_mark():
    findings = build_findings(clock_view(), [parse_sdp(SDP)], [], l2=l2_view(dscp=(0, 0)))
    bad = next(f for f in findings if f["id"] == "net.dscp")
    assert bad["level"] == "warn"
    assert bad["detail"].startswith("Clock packets arrive with DSCP 0")      # not lower-cased by a stray capitalize
    quiet = {"heard": False, "messages": 0, "dropped": 0, "versions": [], "domains": [], "best": None,
             "transparent": False, "first_ts": None, "last_ts": None}
    assert "net.dscp" not in ids(build_findings(quiet, [], [], l2=l2_view(dscp=(0, 0))))


def test_the_switch_this_pc_is_plugged_into_is_reported_with_or_without_a_layer_2_listen():
    """It comes from the switch-port lookup's LLDP neighbour, which has nothing to do with reading frames, so
    turning the Layer 2 listen off must not take it away."""
    for l2 in (l2_view(), None):
        findings = build_findings(clock_view(), [parse_sdp(SDP)], [], l2=l2, switch=SWITCH)
        note = next(f for f in findings if f["id"] == "net.switch")
        assert "core-av-sw-01" in note["title"]
        assert "Port 14" in note["detail"] and "120" in note["detail"]
        assert "net.vlan" in ids(findings)
    assert "net.switch" not in ids(build_findings(clock_view(), [], [], switch=None))


def test_a_listen_that_dropped_frames_says_so_and_stops_short_of_what_it_cannot_stand_behind():
    """A capture session that could not keep up loses whole buffers. The flooding rate it collected is then a lower
    bound, and "no IGMP querier" is not a verdict: a general query is one packet every couple of minutes."""
    flooded = [{"group": "239.69.4.20", "port": 5004, "source": "192.0.2.35", "packets": 40, "bytes": 49419,
                "mbps": 18.31}]
    clean = build_findings(clock_view(), [parse_sdp(SDP)], [], l2=l2_view(querier=False, flooded=flooded))
    lossy = build_findings(clock_view(), [parse_sdp(SDP)], [],
                           l2=l2_view(querier=False, flooded=flooded, lost=1200))
    assert "net.lost" not in ids(clean)
    assert level_of(clean, "net.querier") == "bad"
    lost = next(f for f in lossy if f["id"] == "net.lost")
    assert lost["level"] == "warn" and "1200" in lost["detail"]
    assert level_of(lossy, "net.querier") == "warn"          # not a fault when the packet may simply have been lost
    assert "scan again" in next(f for f in lossy if f["id"] == "net.querier")["detail"]
    assert "at least" in next(f for f in lossy if f["id"] == "net.flood")["detail"]


# ---------------------------------------------------------------------------
# the graphs
# ---------------------------------------------------------------------------
def test_the_clock_tree_is_the_chain_that_was_heard():
    devices = build_devices(services_seen(), clock_view(), [])
    graph = build_graph(clock_view(steps=1), [parse_sdp(SDP)], devices, self_label="Ethernet")
    assert sorted(graph) == ["clock", "flow"]
    plot = graph["clock"]
    assert list(plot) == list(PLOT_KEYS)
    assert all(list(n) == list(NODE_KEYS) for n in plot["nodes"])
    assert all(list(e) == list(EDGE_KEYS) for e in plot["edges"])
    kinds = [n["kind"] for n in plot["nodes"]]
    assert kinds[:3] == ["grandmaster", "boundary", "transparent"]
    assert "self" in kinds and kinds.count("follower") == 2
    # every edge joins two nodes that are really there
    known = {n["id"] for n in plot["nodes"]}
    assert all(e["source"] in known and e["target"] in known for e in plot["edges"])


def test_the_clock_tree_says_how_many_boundary_clocks_when_none_named_itself():
    view = clock_view(steps=3)
    view["best"]["master"]["parent"] = None
    view["domains"][0]["master"]["parent"] = None
    node = next(n for n in build_graph(view, [], [])["clock"]["nodes"] if n["kind"] == "boundary")
    assert node["label"] == "3 boundary clock(s)"


def test_the_flow_map_is_talkers_streams_and_the_listeners_that_were_heard_joining():
    l2 = l2_view()
    l2["memberships"] = [{"ip": "192.0.2.32", "group": "239.69.4.12", "reports": 2, "last_ts": 1000.0}]
    plot = build_graph(clock_view(), [parse_sdp(SDP)], [], l2=l2)["flow"]
    kinds = sorted(n["kind"] for n in plot["nodes"])
    assert kinds == ["listener", "stream", "talker"]
    known = {n["id"] for n in plot["nodes"]}
    assert all(e["source"] in known and e["target"] in known for e in plot["edges"])


def test_a_graph_with_nothing_in_it_says_so_instead_of_drawing_an_empty_box():
    quiet = {"heard": False, "messages": 0, "dropped": 0, "versions": [], "domains": [], "best": None,
             "transparent": False, "first_ts": None, "last_ts": None}
    graph = build_graph(quiet, [], [])
    assert graph["clock"]["nodes"] == [] and "no ptp clock" in graph["clock"]["note"].lower()
    assert graph["flow"]["nodes"] == [] and "no streams" in graph["flow"]["note"].lower()


def test_no_physical_topology_is_ever_drawn():
    """One host hears LLDP from its own switch port and nothing about anyone else's, so a wiring diagram from here
    would be invention. The note is part of the contract, not decoration."""
    assert "not a wiring diagram" in proav.NO_PHYSICAL_NOTE
    graph = build_graph(clock_view(), [parse_sdp(SDP)], [])
    for plot in graph.values():
        assert "switch" not in [n["kind"] for n in plot["nodes"]]


# ---------------------------------------------------------------------------
# the scanner
# ---------------------------------------------------------------------------
class FakeAdapter:
    def __init__(self, name="Ethernet", index=12, ip="192.0.2.20", speed=1_000_000_000, wifi=False):
        self.name, self.index, self.mac = name, index, "02:00:5E:10:00:01"
        self.status, self.is_loopback, self.is_physical = "up", False, True
        self.if_type = 71 if wifi else 6
        self.type_name = "Wireless" if wifi else "Ethernet"
        self.speed_bps, self.primary_ipv4 = speed, ip


class FakeSocket:
    """A stand-in for one joined group: a canned list of packets, and a real socketpair so ``select`` behaves.

    One byte is queued per packet, so the socket reads as readable exactly while a packet is left and ``recvfrom``
    raises ``BlockingIOError`` once they are gone - which is what a real non-blocking socket does."""

    def __init__(self, packets=()):
        self._packets = list(packets)
        self.sent = []
        self.closed = False
        self._rx, self._tx = socket.socketpair()
        self._rx.setblocking(False)
        for _ in self._packets:
            self._tx.send(b"x")

    def fileno(self):
        return self._rx.fileno()

    def recvfrom(self, _size):
        if not self._packets:
            raise BlockingIOError()
        payload, address = self._packets.pop(0)
        try:
            self._rx.recv(1)
        except OSError:
            pass
        return payload, (address, 5353)

    def sendto(self, data, _address):
        self.sent.append(data)
        return len(data)

    def close(self):
        self.closed = True
        for end in (self._rx, self._tx):
            try:
                end.close()
            except OSError:
                pass


@pytest.fixture
def scanner(monkeypatch):
    monkeypatch.setattr(proav.os, "name", "nt", raising=False)
    monkeypatch.setattr(ProAvScanner, "_adapter_list", lambda self: [FakeAdapter()])
    monkeypatch.setattr(ProAvScanner, "_internet_index", lambda self, adapters: 12)
    monkeypatch.setattr(ProAvScanner, "_arp_table", lambda self: {})
    monkeypatch.setattr(proav, "_L2Listener", lambda if_index, joined: _NoL2())
    return ProAvScanner()


class _NoL2:
    ok = False
    reason = "not an administrator"
    frames = 0

    def start(self):
        return False

    def stop(self):
        pass

    def view(self, switch=None):
        return {}


def test_status_and_adapters_are_the_contract_shape(scanner):
    status = scanner.status()
    assert list(status) == list(SCAN_STATUS_KEYS)
    assert status["available"] is True and status["reason"] is None
    assert list(status["adapters"][0]) == list(SCAN_ADAPTER_KEYS)
    assert status["adapters"][0]["speed_mbps"] == 1000
    assert list(status["job"]) == list(JOB_KEYS)
    assert status["job"]["state"] == "idle"
    assert list(scanner.tile()) == list(TILE_KEYS)


def test_no_adapter_means_no_scan(monkeypatch, scanner):
    monkeypatch.setattr(ProAvScanner, "_adapter_list", lambda self: [])
    status = scanner.status()
    assert status["available"] is False and "adapter" in status["reason"]


@pytest.mark.parametrize("seconds", [0, 4, 601, 1.5, True, "30"])
def test_a_bad_listen_length_is_refused(scanner, seconds):
    with pytest.raises(ValueError):
        scanner.start(seconds=seconds)


def test_an_unknown_adapter_is_refused(scanner):
    with pytest.raises(ValueError):
        scanner.start(adapter="Nonexistent")


def test_a_scan_that_can_open_no_listener_at_all_fails_with_a_reason(monkeypatch, scanner):
    def refuse(self, port, groups, local_ip):
        raise OSError(10048, "the port is already in use")
    monkeypatch.setattr(ProAvScanner, "_open_socket", refuse)
    scanner.start(seconds=5)
    _wait(scanner)
    job = scanner.job()
    assert job["state"] == "error" and proav.NO_LISTENER_TEXT in job["error"]
    assert all(entry["ok"] is False for entry in job["listeners"])
    assert all("already in use" in (entry["reason"] or "") for entry in job["listeners"])


def test_one_listener_that_will_not_open_never_ends_the_scan(monkeypatch, scanner):
    def some(self, port, groups, local_ip):
        if port == proav.SAP_PORT:
            raise OSError(10048, "in use")
        return FakeSocket()
    monkeypatch.setattr(ProAvScanner, "_open_socket", some)
    scanner.start(seconds=5)
    _wait(scanner)
    result = scanner.last()
    assert scanner.job()["state"] == "done"
    assert [entry["ok"] for entry in result["listeners"]] == [True, False, True, True]


def test_a_whole_scan_hears_the_packets_and_answers_the_contract_shape(monkeypatch, scanner):
    from tests.test_ptp import v2 as ptp_v2, GM as PTP_GM
    from tests.test_mdns import message as mdns_message, record as mdns_record, name as mdns_name, srv, txt

    mdns_reply = mdns_message(
        mdns_record("_netaudio-arc._udp.local", 12, mdns_name("FOH Console._netaudio-arc._udp.local")),
        mdns_record("FOH Console._netaudio-arc._udp.local", 33, srv(8000, "foh.local")),
        mdns_record("FOH Console._netaudio-arc._udp.local", 16, txt(["mf=Audinate", "model=DEV-64"])),
        mdns_record("foh.local", 1, bytes([192, 0, 2, 31])))
    sockets = {}

    def open_socket(self, port, groups, local_ip):
        if port == proav.SAP_PORT:
            sock = FakeSocket([(sap(SDP), "192.0.2.31")])
        elif port == ptp.GENERAL_PORT:
            sock = FakeSocket([(ptp_v2(0x0B, source=PTP_GM), "192.0.2.10")])
        elif port == 5353:
            sock = FakeSocket([(mdns_reply, "192.0.2.31")])
        else:
            sock = FakeSocket([(ptp_v2(0x01, source=PTP_GM), "192.0.2.31")])
        sockets[port] = sock
        return sock
    monkeypatch.setattr(ProAvScanner, "_open_socket", open_socket)
    scanner.start(seconds=5)
    _wait(scanner)
    assert scanner.job()["state"] == "done", [entry["reason"] for entry in scanner.job()["listeners"]]
    result = scanner.last()
    assert list(result) == list(RESULT_KEYS)
    assert all(list(entry) == list(LISTENER_KEYS) for entry in result["listeners"])
    assert result["clock"]["heard"] is True
    assert [s["name"] for s in result["streams"]] == ["FOH Mix : Main LR"]
    assert any(d["name"] == "FOH Console" for d in result["devices"])
    assert result["cancelled"] is False
    assert result["l2"]["ok"] is False and result["l2"]["reason"] == "not an administrator"
    assert list(result["l2"]) == list(proav.L2_KEYS)
    assert result["switch"] is None                          # no switch-port lookup was wired into this scanner
    assert "net.l2" in ids(result["findings"])
    # the mDNS question really went out, and it led with the meta-query
    asked = [proav._mdns.parse(raw) for raw in sockets[5353].sent]
    assert asked and asked[0]["questions"][0]["name"] == proav._mdns.META_QUERY
    assert all(sock.closed for sock in sockets.values())


def test_the_scanner_reports_the_switch_port_lookups_neighbour(monkeypatch):
    """engine.proav is given the switch-port finder's last neighbour; a scan reports it alongside what it heard,
    and a lookup that raises never costs the scan its result."""
    monkeypatch.setattr(proav.os, "name", "nt", raising=False)
    monkeypatch.setattr(ProAvScanner, "_adapter_list", lambda self: [FakeAdapter()])
    monkeypatch.setattr(ProAvScanner, "_internet_index", lambda self, adapters: 12)
    monkeypatch.setattr(ProAvScanner, "_arp_table", lambda self: {})
    monkeypatch.setattr(ProAvScanner, "_open_socket", lambda self, port, groups, ip: FakeSocket())
    monkeypatch.setattr(proav, "_L2Listener", lambda if_index, joined: _NoL2())
    for switch_fn, expected in ((lambda: SWITCH, SWITCH), (_raises, None), (None, None)):
        scanner = ProAvScanner(switch_fn=switch_fn)
        scanner.start(seconds=5)
        _wait(scanner)
        result = scanner.last()
        assert result["switch"] == expected
        assert ("net.switch" in ids(result["findings"])) is (expected is not None)


def _raises():
    raise RuntimeError("the switch-port lookup blew up")


def test_a_second_scan_while_one_runs_is_refused(monkeypatch, scanner):
    monkeypatch.setattr(ProAvScanner, "_open_socket", lambda self, port, groups, ip: FakeSocket())
    scanner.start(seconds=30)
    try:
        with pytest.raises(RuntimeError, match="already running"):
            scanner.start(seconds=30)
    finally:
        scanner.cancel()
        _wait(scanner)


def test_cancel_keeps_what_was_heard(monkeypatch, scanner):
    monkeypatch.setattr(ProAvScanner, "_open_socket", lambda self, port, groups, ip: FakeSocket())
    scanner.start(seconds=120)
    assert scanner.cancel() is True
    _wait(scanner)
    assert scanner.job()["state"] == "cancelled"
    assert scanner.last()["cancelled"] is True
    assert scanner.cancel() is False            # nothing is running any more


def test_close_ends_a_running_listen(monkeypatch, scanner):
    monkeypatch.setattr(ProAvScanner, "_open_socket", lambda self, port, groups, ip: FakeSocket())
    scanner.start(seconds=120)
    scanner.close(3.0)
    assert not scanner.running


def test_progress_and_state_reach_the_event_bus(monkeypatch):
    monkeypatch.setattr(proav.os, "name", "nt", raising=False)
    monkeypatch.setattr(ProAvScanner, "_adapter_list", lambda self: [FakeAdapter()])
    monkeypatch.setattr(ProAvScanner, "_internet_index", lambda self, adapters: 12)
    monkeypatch.setattr(ProAvScanner, "_arp_table", lambda self: {})
    monkeypatch.setattr(ProAvScanner, "_open_socket", lambda self, port, groups, ip: FakeSocket())
    monkeypatch.setattr(proav, "_L2Listener", lambda if_index, joined: _NoL2())
    seen = []

    class Bus:
        def publish(self, event, payload):
            seen.append((event, payload))

    scanner = ProAvScanner(Bus())
    scanner.start(seconds=5)
    _wait(scanner)
    names = [event for event, _ in seen]
    assert proav.EVENT in names and proav.PROGRESS_EVENT in names
    assert all(list(payload["job"]) == list(JOB_KEYS) for _event, payload in seen)


def _wait(scanner, timeout=20.0):
    end = time.monotonic() + timeout
    while scanner.running and time.monotonic() < end:
        time.sleep(0.05)
    assert not scanner.running, scanner.job()
