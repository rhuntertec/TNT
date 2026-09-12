"""IP location manager (tnt/geoip.py): pure helpers, downloads and swaps, the month budget, Windows file handling,
threads, lookups and the HTTP seam.

Every manager is built through tests/geoip_helpers.py on a tmp_path folder with an injected fake HTTP seam; the real
``http_open`` is exercised only against servers on 127.0.0.1. The real DB-IP Lite files are read only by the env-gated
smoke test (TNT_TEST_DBIP_DIR). Addresses are documentation ranges, except the well-known resolver probes of §0.3.
"""
import calendar
import email.utils
import gzip
import http.client
import json
import logging
import math
import os
import random
import re
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from geoip_helpers import FakeHttp, installed_manager, make_manager, write_fixture_files
from mmdb_writer import (ASN_FIXTURE, CITY_FIXTURE, MARKER, asn_record, build_mmdb, city_record, fixture_pair,
                         gzip_bytes, month_epoch)
from tnt import geohints, geohints_data, geoip, mmdb
from tnt.events import EventBus
from tnt.geoip import MiB

# belt and braces: tests/conftest.py sets this for the whole session; never let a test here reach the internet
os.environ.setdefault(geoip.OFFLINE_ENV, "1")

T0 = float(calendar.timegm((2026, 9, 15, 12, 0, 0)))          # 2026-09-15 12:00 UTC
BLOCKED_TEXTS = ("OSError: network access is disabled in tests (tnt.geoip)",      # tests/conftest.py's seam
                 "OSError: network access is disabled (TNT_GEOIP_OFFLINE)")      # the http_open guard alone
DALLAS = (32.78, -96.80)


@pytest.fixture(autouse=True)
def _stop_every_manager(monkeypatch):
    """Stop (and so unmap) every manager a test built, whatever the test did."""
    made = []
    real_init = geoip.GeoIpManager.__init__

    def init(self, *args, **kw):
        real_init(self, *args, **kw)
        made.append(self)

    monkeypatch.setattr(geoip.GeoIpManager, "__init__", init)
    yield
    for mgr in made:
        mgr.stop()


@pytest.fixture
def bus():
    b = EventBus()
    b.events = []
    b.subscribe(b.events.append)
    return b


def _clock(ts=T0):
    box = {"now": ts}
    return box, (lambda: box["now"])


def _wait_for(pred, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def _geoip_threads():
    return [t for t in threading.enumerate() if t.name == geoip.THREAD_NAME and t.is_alive()]


def _names(folder: Path):
    return sorted(os.listdir(folder)) if folder.is_dir() else []


def _parts(folder: Path):
    return [n for n in _names(folder) if n.endswith(".part") or n.endswith(".tmp")]


def _random_bytes(n: int, seed: int = 1) -> bytes:
    return random.Random(seed).randbytes(n)


def _padded_asn(month: str, pad: int) -> bytes:
    """A valid asn database with ``pad`` unreferenced random bytes at the end of its data section."""
    raw = fixture_pair(month)[1]
    idx = raw.rfind(MARKER)
    return raw[:idx] + _random_bytes(pad, seed=5) + raw[idx:]


# ============================================================================================ pure helpers
def test_month_helpers():
    assert geoip.month_of(T0) == "2026-09"
    assert geoip.month_of(calendar.timegm((2026, 12, 31, 23, 59, 59))) == "2026-12"
    assert geoip.month_of(calendar.timegm((2027, 1, 1, 0, 0, 0))) == "2027-01"
    assert geoip.previous_month("2026-09") == "2026-08"
    assert geoip.previous_month("2026-01") == "2025-12"
    for bad in ("2026-13", "2026-00", "bad", "", None):
        with pytest.raises(ValueError):
            geoip.previous_month(bad)
    assert geoip.next_month_start("2026-09") == calendar.timegm((2026, 10, 1, 0, 0, 0))
    assert geoip.next_month_start("2026-12") == calendar.timegm((2027, 1, 1, 0, 0, 0))
    assert geoip.valid_month("2026-09") and geoip.valid_month("2026-12") and geoip.valid_month("2026-01")
    for bad in ("2026-00", "2026-13", "26-09", "2026-9", "2026-09-01", None, 202609, " 2026-09"):
        assert not geoip.valid_month(bad)
    assert geoip.file_url("city", "2026-09") == "https://download.db-ip.com/free/dbip-city-lite-2026-09.mmdb.gz"
    assert geoip.local_name("city", "2026-09") == "dbip-city-lite-2026-09.mmdb"
    assert geoip.local_name("asn", "2026-09", 1) == "dbip-asn-lite-2026-09.1.mmdb"
    assert [geoip.backoff_s(n) for n in range(-1, 8)] == [0.0, 0.0, 60.0, 300.0, 900.0, 3600.0, 21600.0, 21600.0,
                                                          21600.0]


def test_normalize_and_skip_networks():
    for ip in ("203.0.113.9", "198.51.100.7", "192.0.2.10", "2001:db8::1", " 203.0.113.9 "):
        assert geoip.is_public_candidate(ip), ip
    for ip in ("0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.10.1", "172.16.5.4", "172.31.255.1",
               "192.168.1.1", "224.0.0.251", "239.255.255.250", "240.0.0.1", "255.255.255.255", "::", "::1",
               "fe80::1", "fd00::1", "fc00::5", "ff02::1", "::ffff:10.0.0.1", "::ffff:192.168.1.1"):
        assert not geoip.is_public_candidate(ip), ip
    import ipaddress
    assert geoip.normalize_ip("::ffff:203.0.113.9") == ipaddress.IPv4Address("203.0.113.9")
    assert geoip.normalize_ip("[2001:db8::1]") == ipaddress.IPv6Address("2001:db8::1")
    assert geoip.normalize_ip("fe80::1%12") == ipaddress.IPv6Address("fe80::1")
    assert geoip.normalize_ip(" 198.51.100.7 ") == ipaddress.IPv4Address("198.51.100.7")
    assert geoip.normalize_ip(ipaddress.IPv6Address("::ffff:198.51.100.7")) == ipaddress.IPv4Address("198.51.100.7")
    for junk in ("", "x", "203.0.113.256", "203.0.113", None, 5, b"203.0.113.9", ["203.0.113.9"], "[]"):
        assert geoip.normalize_ip(junk) is None, junk
        assert not geoip.is_public_candidate(junk)


def _place(city, region, cc, country, lat=10.0, lon=20.0):
    parts = geoip.place_parts(city_record(city, region, cc, country, lat, lon))
    return parts, geoip.place_text(parts), geoip.place_full_text(parts)


def test_place_text_rules():
    assert _place("Dallas", "Texas", "US", "United States")[1] == "Dallas, TX"
    parts, place, full = _place("Washington D.C. (Northwest Washington)", "District of Columbia", "US", "United States")
    assert (parts["city"], place, parts["city_full"]) == ("Washington", "Washington, DC",
                                                          "Washington D.C. (Northwest Washington)")
    assert parts["region_code"] == "DC"
    parts, place, full = _place("Richardson (Canyon Creek)", "Texas", "US", "United States")
    assert (place, full) == ("Richardson, TX", "Richardson (Canyon Creek), Texas, United States")
    assert _place("Springfield [Downtown]", "Illinois", "US", "United States")[1] == "Springfield, IL"
    parts, place, _full = _place("Château-Chinon(Campagne)", "Bourgogne-Franche-Comté", "FR", "France")
    assert (parts["city"], place) == ("Château-Chinon", "Château-Chinon, France")
    assert _place("Montreal", "Quebec", "CA", "Canada")[1] == "Montreal, QC"
    assert _place("Anytown", "Unknown Province", "CA", "Canada")[1] == "Anytown, Canada"
    parts, place, _full = _place("San Juan", "San Juan", "PR", "Puerto Rico")
    assert (place, parts["region_code"]) == ("San Juan, PR", "PR")
    assert _place("Sydney", "New South Wales", "AU", "Australia")[1] == "Sydney, Australia"
    assert _place("Singapore", None, "SG", "Singapore")[1:] == ("Singapore", "Singapore")
    assert _place("Anytown", "Unknown Region", "US", "United States")[1] == "Anytown, United States"
    assert _place(None, "Texas", "US", "United States")[1] == "Texas, United States"
    parts, place, _full = _place("Kralendijk", None, "BQ", "Bonaire, Sint Eustatius, and Saba ")
    assert parts["country"] == "Bonaire, Sint Eustatius, and Saba"
    assert place == "Kralendijk, Bonaire, Sint Eustatius, and Saba"
    parts, place, full = _place("Campo Pequeno, Lisbon, Portugal", "Lisbon", "PT", "Portugal")
    assert place == full == "Campo Pequeno, Lisbon, Portugal"
    parts, place, full = _place(None, None, "ZZ", "Undefined")
    assert (place, full, parts["country"], parts["country_code"]) == (None, None, None, None)
    assert _place(None, None, "HM", "Heard Island and McDonald Islands")[1] == "Heard Island and McDonald Islands"
    parts = geoip.place_parts(None)
    assert set(parts) == {"city", "city_full", "region", "region_code", "country", "country_code", "lat", "lon"}
    assert all(v is None for v in parts.values()) and geoip.place_text(parts) is None
    assert all(v is None for v in geoip.place_parts("not a record").values())
    parts, _place_text, _full = _place("Anytown", "Texas", "US", "United States", 32.123456, -96.987654)
    assert (parts["lat"], parts["lon"]) == (32.1235, -96.9877)
    rec = city_record("Anytown", "Texas", "US", "United States", 1.0, 2.0)
    rec["location"] = {"latitude": True, "longitude": float("nan")}
    assert (geoip.place_parts(rec)["lat"], geoip.place_parts(rec)["lon"]) == (None, None)


def test_usps_table_complete():
    assert len(geoip.USPS_CODES) == 51
    assert geoip.USPS_CODES["District of Columbia"] == "DC" and geoip.USPS_CODES["Texas"] == "TX"
    codes = list(geoip.USPS_CODES.values())
    assert len(set(codes)) == 51
    assert all(len(c) == 2 and c.isalpha() and c.isupper() for c in codes)
    assert len(geoip.CA_PROVINCE_CODES) == 13


@pytest.mark.parametrize("org, asn, expected", [
    ("Example Cable Communications, LLC", 64500, "Example Cable Communications"),
    ("Example Transit, Inc.", 64510, "Example Transit"),
    ("Example Hosting LLC", 64511, "Example Hosting"),
    ("Sample Fiber Co.", 64501, "Sample Fiber"),
    ("Example Broadband ", 64500, "Example Broadband"),
    ("Example Net Co., Ltd.", 64502, "Example Net"),
    ("Example Networks Pty Ltd", 64503, "Example Networks"),
    ("Example Holdings d/b/a Example Fiber", 64504, "Example Fiber"),
    ("LLC", 64505, "LLC"),
    ("Example " * 10, 64506, "Example Example Example Example Example Example Example Example Example Example…"),
    ("", 64500, "AS64500"),
    (None, 64500, "AS64500"),
    (None, None, None),
    (None, True, None),
])
def test_isp_text(org, asn, expected):
    assert geoip.isp_text(asn, org) == expected


def test_build_geo_shape():
    city = city_record("Anytown", "Texas", "US", "United States", 32.95, -96.73)
    geo = geoip.build_geo("203.0.113.9", city, asn_record(64510, "Example Transit, Inc."), "2026-09")
    assert tuple(geo) == geoip.GEO_KEYS
    assert geo == {"ip": "203.0.113.9", "place": "Anytown, TX", "place_full": "Anytown, Texas, United States",
                   "city": "Anytown", "region": "Texas", "region_code": "TX", "country": "United States",
                   "country_code": "US", "lat": 32.95, "lon": -96.73, "asn": 64510,
                   "as_org": "Example Transit, Inc.", "isp": "Example Transit", "month": "2026-09"}
    assert geoip.build_geo("203.0.113.9", None, None, "2026-09") is None
    assert geoip.build_geo("203.0.113.9", {}, {}, "2026-09") is None
    assert geoip.build_geo("203.0.113.9", city_record(None, None, "ZZ", "Undefined", 0.0, 0.0), None, "2026-09") is None
    only_asn = geoip.build_geo("2001:db8::1", None, asn_record(64511, "Example Hosting LLC"), None)
    assert tuple(only_asn) == geoip.GEO_KEYS
    assert (only_asn["place"], only_asn["isp"], only_asn["as_org"], only_asn["asn"]) == (
        None, "Example Hosting", "Example Hosting LLC", 64511)
    weird = geoip.build_geo("203.0.113.9", city, {"autonomous_system_number": "64500"}, "2026-09")
    assert weird["asn"] is None and weird["isp"] is None and weird["as_org"] is None


def test_hint_text_matches_place_text():
    records = {
        "dallas-tx": city_record("Dallas", "Texas", "US", "United States", 32.78, -96.80),
        "toronto-on": city_record("Toronto", "Ontario", "CA", "Canada", 43.65, -79.38),
        "london-gb": city_record("London", "England", "GB", "United Kingdom", 51.51, -0.13, continent="EU"),
        "washington-dc": city_record("Washington D.C. (Northwest Washington)", "District of Columbia", "US",
                                     "United States", 38.91, -77.04),
    }
    for key, rec in records.items():
        city, region, cc, lat, lon = geohints_data.METROS[key]
        hint = {"key": key, "city": city, "region": region, "cc": cc, "lat": lat, "lon": lon}
        assert geohints.hint_text(hint) == geoip.place_text(geoip.place_parts(rec)), key


def test_friendly_error_texts():
    h = "download.db-ip.com"
    cases = [
        (geoip.DownloadError("HTTP 503 from download.db-ip.com"), "HTTP 503 from download.db-ip.com"),
        (socket.gaierror(11001, "getaddrinfo failed"), f"could not look up {h} (no DNS or no internet)"),
        (ssl.SSLCertVerificationError(1, "certificate verify failed"),
         f"the certificate of {h} could not be verified (TLS inspection or a missing Windows root certificate)"),
        (TimeoutError("timed out"), f"{h} did not answer in time (a proxy may be required)"),
        (socket.timeout("timed out"), f"{h} did not answer in time (a proxy may be required)"),
        (ConnectionRefusedError(10061, "refused"),
         f"the connection to {h} was refused (a firewall or proxy may be blocking it)"),
        (ConnectionResetError(10054, "reset"),
         f"the connection to {h} was closed (a firewall or proxy may be blocking it)"),
        (ConnectionAbortedError(10053, "aborted"),
         f"the connection to {h} was closed (a firewall or proxy may be blocking it)"),
        (http.client.RemoteDisconnected("Remote end closed connection without response"),
         f"the connection to {h} was closed (a firewall or proxy may be blocking it)"),
        (ssl.SSLError(1, "wrong version number"), f"TLS error with {h}: SSLError"),
        (RuntimeError("boom"), "RuntimeError: boom"),
    ]
    for exc, expected in cases:
        assert geoip.friendly_error(exc, h) == expected, exc
    assert len(geoip.friendly_error(RuntimeError("x" * 500), h)) == 200
    assert geoip.host_text("192.0.2.1") == "another site"
    assert geoip.host_text("[2001:db8::1]") == "another site"
    assert geoip.host_text(None) == geoip.host_text("") == "another site"
    assert geoip.host_text("Download.DB-IP.com") == "download.db-ip.com"
    ip_host = geoip.host_text("192.0.2.1")
    for exc, _expected in cases[1:-1]:
        assert not re.search(r"\d+\.\d+\.\d+\.\d+|2001:db8", geoip.friendly_error(exc, ip_host))


# ============================================================================================ downloads and swap
def test_first_install_current_month(tmp_path, bus):
    box, clock = _clock()
    http = FakeHttp()
    http.serve_month("2026-09")
    mgr = make_manager(tmp_path, bus=bus, clock=clock, urlopen=http)
    assert mgr.run_check() == "installed"
    assert http.urls == [geoip.file_url("asn", "2026-09"), geoip.file_url("city", "2026-09")]
    st = mgr.status()
    assert (st["state"], st["available"], st["month"], st["error"], st["download"]) == (
        "ready", True, "2026-09", None, None)
    assert st["checked_ts"] == T0 and st["installed_ts"] == T0 and st["bytes"] > 0
    assert st["next_check_ts"] == geoip.next_month_start("2026-09") + 3 * 3600
    folder = tmp_path / "geoip"
    assert _names(folder) == ["dbip-asn-lite-2026-09.mmdb", "dbip-city-lite-2026-09.mmdb", "manifest.json",
                              "state.json"]
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == 1 and manifest["month"] == "2026-09" and manifest["installed_ts"] == T0
    assert manifest["files"]["city"]["name"] == "dbip-city-lite-2026-09.mmdb"
    assert manifest["files"]["asn"]["build_epoch"] == month_epoch("2026-09")
    state = json.loads((folder / "state.json").read_text(encoding="utf-8"))
    assert state["version"] == 1 and state["failures"] == 0 and state["months"] == {}
    assert [f["name"] for f in mgr.files()] == ["dbip-city-lite-2026-09.mmdb", "dbip-asn-lite-2026-09.mmdb"]
    assert sum(f["bytes"] for f in mgr.files()) == st["bytes"]

    a = mgr.lookup("203.0.113.9")
    assert (a["place"], a["isp"], a["as_org"], a["asn"], a["month"]) == (
        "Anytown, TX", "Example Broadband", "Example Broadband", 64500, "2026-09")
    b = mgr.lookup("203.0.113.200")
    assert (b["place"], b["lat"], b["isp"]) == ("Dallas, TX", 32.78, "Example Broadband")
    c = mgr.lookup("198.51.100.7")
    assert (c["place"], c["place_full"], c["isp"], c["as_org"], c["asn"]) == (
        "Richardson, TX", "Richardson (Canyon Creek), Texas, United States", "Example Transit",
        "Example Transit, Inc.", 64510)
    d = mgr.lookup("192.0.2.10")
    assert (d["place"], d["isp"], d["as_org"], d["asn"]) == ("Montreal, QC", None, None, None)
    e = mgr.lookup("2001:db8::1")
    assert (e["place"], e["isp"], e["as_org"], e["asn"]) == (
        "London, United Kingdom", "Example Hosting", "Example Hosting LLC", 64511)
    assert mgr.lookup("::ffff:203.0.113.9") == a
    assert mgr.lookup("10.0.0.1") is None and mgr.lookup("198.18.0.1") is None

    seen = [(ev["data"]["state"], (ev["data"]["download"] or {}).get("file"),
             (ev["data"]["download"] or {}).get("phase")) for ev in bus.events if ev["type"] == "geoip.state"]
    assert all(set(ev["data"]) == set(geoip.STATUS_KEYS) for ev in bus.events if ev["type"] == "geoip.state")
    order = [seen.index(("downloading", "asn", "download")), seen.index(("downloading", "city", "download")),
             seen.index(("downloading", "city", "verify")), seen.index(("ready", None, None))]
    assert order == sorted(order)


def test_current_month_404_falls_back_to_previous(tmp_path):
    box, clock = _clock()
    http = FakeHttp()
    http.serve_month("2026-08")
    mgr = make_manager(tmp_path, clock=clock, urlopen=http)
    assert mgr.run_check() == "installed"
    assert http.urls == [geoip.file_url("asn", "2026-09"), geoip.file_url("asn", "2026-08"),
                         geoip.file_url("city", "2026-08")]
    st = mgr.status()
    assert (st["month"], st["state"], st["next_check_ts"]) == ("2026-08", "ready", T0 + 6 * 3600)
    assert mgr.lookup("203.0.113.9")["month"] == "2026-08"
    old_readers = list(mgr._data.readers.values())

    stop, results = threading.Event(), []

    def hammer():
        while not stop.is_set():
            results.append(mgr.lookup("203.0.113.9"))

    worker = threading.Thread(target=hammer)
    worker.start()
    try:
        box["now"] += 6 * 3600
        http.serve_month("2026-09")
        assert mgr.run_check() == "installed"
    finally:
        stop.set()
        worker.join(5)
    assert results and all(r is not None and r["place"] == "Anytown, TX" for r in results)
    assert mgr.status()["month"] == "2026-09" and mgr.lookup("203.0.113.9")["month"] == "2026-09"
    assert all(r.closed for r in old_readers)
    folder = tmp_path / "geoip"
    assert not [n for n in _names(folder) if "2026-08" in n]
    assert _names(folder) == ["dbip-asn-lite-2026-09.mmdb", "dbip-city-lite-2026-09.mmdb", "manifest.json",
                              "state.json"]


@pytest.mark.parametrize("status", [404, 410])
def test_nothing_published_without_data_is_an_error_with_backoff(tmp_path, status):
    box, clock = _clock()
    http = FakeHttp(default_status=status)
    mgr = make_manager(tmp_path, clock=clock, urlopen=http)
    waits = []
    for _ in range(6):
        assert mgr.run_check() == "not_published"
        st = mgr.status()
        assert (st["state"], st["error"], st["available"]) == (
            "error", "DB-IP has no data for 2026-09 or 2026-08 yet", False)
        waits.append(st["next_check_ts"] - box["now"])
        box["now"] = st["next_check_ts"]
    assert waits == [60.0, 300.0, 900.0, 3600.0, 21600.0, 21600.0]
    assert http.urls == [geoip.file_url("asn", "2026-09"), geoip.file_url("asn", "2026-08")] * 6
    assert not _parts(tmp_path / "geoip")


def test_403_is_an_error_not_a_publishing_delay(tmp_path):
    text = "download.db-ip.com refused the download (HTTP 403): a firewall or proxy may be blocking it"
    box, clock = _clock()
    http = FakeHttp({geoip.file_url("asn", "2026-09"): (403, {}, b"Forbidden")})
    mgr = make_manager(tmp_path / "a", clock=clock, urlopen=http)
    assert mgr.run_check() == "error"
    st = mgr.status()
    assert (st["state"], st["error"], st["next_check_ts"]) == ("error", text, T0 + 60)
    assert http.urls == [geoip.file_url("asn", "2026-09")]
    assert mgr._failures == 1

    http2 = FakeHttp({geoip.file_url("asn", "2026-09"): (403, {}, b"")})
    with_data = installed_manager(tmp_path / "b", "2026-08", clock=clock, urlopen=http2)
    assert with_data.run_check() == "error"
    st = with_data.status()
    assert (st["state"], st["available"], st["error"], st["month"]) == ("ready", True, text, "2026-08")


def test_missing_city_after_asn_costs_only_the_asn_file(tmp_path):
    box, clock = _clock()
    http = FakeHttp()
    http.serve_month("2026-09")
    asn_body = http.table[geoip.file_url("asn", "2026-09")][2]
    del http.table[geoip.file_url("city", "2026-09")]
    mgr = make_manager(tmp_path, clock=clock, urlopen=http)
    assert mgr.run_check() == "not_published"
    assert http.urls == [geoip.file_url("asn", "2026-09"), geoip.file_url("city", "2026-09"),
                         geoip.file_url("asn", "2026-08")]
    assert http.responses[0].pos == len(asn_body) and http.responses[0].closed
    folder = tmp_path / "geoip"
    assert not _parts(folder) and not [n for n in _names(folder) if n.endswith(".mmdb")]
    st = mgr.status()
    assert (st["state"], st["download"], st["error"]) == ("error", None, "DB-IP has no data for 2026-09 or 2026-08 yet")
    assert mgr._months == {}


def test_up_to_date_schedules_next_month(tmp_path):
    box, clock = _clock()
    http = FakeHttp()
    mgr = installed_manager(tmp_path, clock=clock, urlopen=http)
    assert mgr.run_check() == "up_to_date"
    assert http.urls == []
    st = mgr.status()
    assert (st["state"], st["error"], st["checked_ts"]) == ("ready", None, T0)
    assert st["next_check_ts"] == geoip.next_month_start("2026-09") + geoip.MONTHLY_CHECK_OFFSET_S


def test_http_error_keeps_old_data(tmp_path):
    box, clock = _clock()
    http = FakeHttp({geoip.file_url("asn", "2026-09"): (503, {}, b"busy")})
    mgr = installed_manager(tmp_path, "2026-08", clock=clock, urlopen=http)
    assert mgr.run_check() == "error"
    st = mgr.status()
    assert (st["state"], st["available"], st["error"], st["month"]) == (
        "ready", True, "HTTP 503 from download.db-ip.com", "2026-08")
    assert st["next_check_ts"] == T0 + 60
    assert mgr.lookup("203.0.113.9")["place"] == "Anytown, TX"
    assert not _parts(tmp_path / "geoip")


def _assert_kept_old_data(mgr, tmp_path, error):
    st = mgr.status()
    assert (st["state"], st["available"], st["month"], st["error"]) == ("ready", True, "2026-08", error)
    assert mgr.lookup("198.51.100.7")["place"] == "Richardson, TX"
    folder = tmp_path / "geoip"
    assert not _parts(folder) and not [n for n in _names(folder) if "2026-09" in n]


@pytest.mark.parametrize("case", ["content_length", "stream", "gzip_bomb"])
def test_caps(tmp_path, case):
    box, clock = _clock()
    http = FakeHttp(chunk=1024)
    http.serve_month("2026-09")
    url = geoip.file_url("asn", "2026-09")
    if case == "content_length":
        http.table[url] = (200, {"content-length": str(26 * MiB)}, http.table[url][2])
        caps, error = None, "the ISP download is larger than expected"
    elif case == "stream":
        http.table[url] = (200, {}, gzip_bytes(_random_bytes(64 * 1024)))
        caps, error = {"asn": (4096, 64 * MiB)}, "the ISP download is larger than expected"
    else:
        http.table[url] = (200, {}, gzip.compress(bytes(64 * MiB), compresslevel=9, mtime=0))
        caps, error = {"asn": (25 * MiB, 1 * MiB)}, "the ISP data is larger than expected"
    mgr = installed_manager(tmp_path, "2026-08", clock=clock, urlopen=http, caps=caps)
    assert mgr.run_check() == "error"
    _assert_kept_old_data(mgr, tmp_path, error)
    if case == "content_length":
        assert http.responses[0].pos == 0            # refused before reading
    if case == "stream":
        assert http.responses[0].pos <= 4096 + 1024


def test_truncated_gzip_and_trailing_garbage(tmp_path):
    box, clock = _clock()
    asn_url = geoip.file_url("asn", "2026-09")
    gz = gzip_bytes(fixture_pair("2026-09")[1])

    http = FakeHttp()
    http.serve_month("2026-09")
    http.table[asn_url] = (200, {"content-length": str(len(gz) - 10)}, gz[:-10])
    mgr = installed_manager(tmp_path / "cut", "2026-08", clock=clock, urlopen=http)
    assert mgr.run_check() == "error"
    _assert_kept_old_data(mgr, tmp_path / "cut", "the ISP download was cut short")

    http = FakeHttp(chunk=1024)
    http.serve_month("2026-09")
    body = gz + b"\x00trailing garbage" * 20000
    http.table[asn_url] = (200, {}, body)
    reads = []
    http.read_hook = lambda resp, pos: reads.append(pos)
    mgr = installed_manager(tmp_path / "garbage", "2026-08", clock=clock, urlopen=http)
    assert mgr.run_check() == "error"
    _assert_kept_old_data(mgr, tmp_path / "garbage", "the ISP download is not valid gzip data")
    # rejected at the read that delivered the first byte after the gzip member: no further read
    assert len(reads) <= math.ceil(len(gz) / 1024) + 1 and len(reads) < len(body) // 1024

    http = FakeHttp()
    http.serve_month("2026-09")
    http.table[asn_url] = (200, {}, _random_bytes(4096))
    mgr = installed_manager(tmp_path / "junk", "2026-08", clock=clock, urlopen=http)
    assert mgr.run_check() == "error"
    _assert_kept_old_data(mgr, tmp_path / "junk", "the ISP download is not valid gzip data")


@pytest.mark.parametrize("delta", [5, -5])
def test_content_length_mismatch(tmp_path, delta):
    box, clock = _clock()
    http = FakeHttp()
    http.serve_month("2026-09")
    url = geoip.file_url("city", "2026-09")
    body = http.table[url][2]
    http.table[url] = (200, {"content-length": str(len(body) + delta)}, body)
    mgr = installed_manager(tmp_path, "2026-08", clock=clock, urlopen=http)
    assert mgr.run_check() == "error"
    _assert_kept_old_data(mgr, tmp_path, "the city download was cut short")


def _verify_case(case):
    epoch = month_epoch("2026-09")
    if case == "database_type":
        return {"asn": build_mmdb(ASN_FIXTURE, record_size=24, database_type="GeoLite2-ASN", build_epoch=epoch)}, \
            "the downloaded ISP data failed its check: unexpected database type"
    if case == "build_month":
        return {"city": build_mmdb(CITY_FIXTURE, database_type="DBIP-City-Lite", build_epoch=month_epoch("2026-07"))}, \
            "the downloaded city data failed its check: it was built in 2026-07"
    if case == "absent_probe":
        networks = CITY_FIXTURE + [("10.0.0.0/8", city_record("Anytown", "Texas", "US", "United States", 1.0, 2.0))]
        return {"city": build_mmdb(networks, database_type="DBIP-City-Lite", build_epoch=epoch)}, \
            "the downloaded city data failed its check: a private address has a record"
    if case == "present_probe":
        networks = [ASN_FIXTURE[0], ASN_FIXTURE[2]]
        return {"asn": build_mmdb(networks, record_size=24, database_type="DBIP-ASN-Lite", build_epoch=epoch)}, \
            "the downloaded ISP data failed its check: a well-known address has no record"
    city = bytearray(fixture_pair("2026-09")[0])
    city[0:7] = b"\xff" * 7                              # node 0 points past the data section
    return {"city": bytes(city)}, "the downloaded city data failed its check: "


@pytest.mark.parametrize("case", ["database_type", "build_month", "absent_probe", "present_probe", "corrupt_tree"])
def test_verify_rejects(tmp_path, case):
    box, clock = _clock()
    files, error = _verify_case(case)
    http = FakeHttp()
    http.serve_month("2026-09", **files)
    mgr = make_manager(tmp_path, clock=clock, urlopen=http)
    assert mgr.run_check() == "error"
    st = mgr.status()
    assert st["state"] == "error" and st["error"].startswith(error), st["error"]
    assert len(st["error"]) <= 200 and "10.0.0.1" not in st["error"]
    folder = tmp_path / "geoip"
    assert not _parts(folder) and not [n for n in _names(folder) if n.endswith(".mmdb")]
    assert mgr._paused("2026-09") and mgr._months["2026-09"]["verify_failed"] is True
    assert not mgr.available


def test_stall_and_abort(tmp_path):
    box, clock = _clock()
    asn_url = geoip.file_url("asn", "2026-09")

    # a trickle: 1 KiB every 10 s is far below 1 MiB per 5 min
    mono = {"now": 1000.0}
    http = FakeHttp(chunk=1024)
    http.serve_month("2026-09")
    http.table[asn_url] = (200, {}, gzip_bytes(_random_bytes(256 * 1024)))

    def trickle(resp, pos):
        mono["now"] += 10.0

    http.read_hook = trickle
    mgr = make_manager(tmp_path / "stall", clock=clock, monotonic=lambda: mono["now"], urlopen=http)
    assert mgr.run_check() == "error"
    assert mgr.status()["error"] == "the ISP download stalled (less than 1 MB in 5 min)"
    assert 25 <= http.responses[0].pos // 1024 <= 40          # ~30 reads fill the first 5 min window
    assert not _parts(tmp_path / "stall" / "geoip")

    # slow but steady: 256 KiB a minute is >= 1 MiB in every 5 min window, over many windows
    mono = {"now": 1000.0}
    http = FakeHttp(chunk=256 * 1024)
    http.serve_month("2026-09", asn=_padded_asn("2026-09", 6 * MiB))

    def steady(resp, pos):
        mono["now"] += 60.0

    http.read_hook = steady
    mgr = make_manager(tmp_path / "steady", clock=clock, monotonic=lambda: mono["now"], urlopen=http)
    assert mgr.run_check() == "installed"
    assert mono["now"] - 1000.0 >= 4 * geoip.STALL_WINDOW_S
    assert mgr.lookup("203.0.113.9")["isp"] == "Example Broadband"

    # switching the setting off mid-download aborts silently, whatever the aborted read does next
    for mode in ("zero", "oserror", "valueerror"):
        folder = tmp_path / f"abort-{mode}"
        http = FakeHttp(chunk=128)
        http.serve_month("2026-09")
        mgr = make_manager(folder, clock=clock, urlopen=http)
        mgr.config.add_listener(mgr._on_config)

        def disable_on_second_read(resp, pos, mode=mode, mgr=mgr):
            if pos == 0:
                return
            if mgr.enabled():
                mgr.config.update({"geoip": {"enabled": False}})
            assert resp.aborted
            if mode == "oserror":
                raise OSError(10053, "An established connection was aborted")
            if mode == "valueerror":
                raise ValueError("Read on closed or unwrapped SSL socket")

        http.read_hook = disable_on_second_read
        assert mgr.run_check() == "disabled", mode
        assert mgr._failures == 0 and mgr._error is None and mgr._checked_ts is None and mgr._months == {}
        assert not _parts(folder / "geoip")
        assert mgr.apply_enabled() == "disabled"
        assert mgr.status()["state"] == "disabled" and mgr._state == "disabled"


def test_abort_cannot_spin(tmp_path):
    box, clock = _clock()
    http = FakeHttp()
    http.serve_month("2026-09")
    mgr = make_manager(tmp_path / "a", clock=clock, urlopen=http)
    mgr._abort.set()
    assert mgr.run_check() == "disabled"
    assert mgr.status()["next_check_ts"] >= box["now"] + geoip.MIN_CHECK_INTERVAL_S
    assert http.urls == []
    assert mgr.apply_enabled() == "enabled"
    assert not mgr._abort.is_set()
    # a stale abort left behind while already active (off/on listeners interleaved) must not wedge every check
    mgr._abort.set()
    assert mgr.apply_enabled() == "unchanged"
    assert not mgr._abort.is_set()
    assert mgr.run_check() == "installed"
    assert len(http.urls) == 2

    http = FakeHttp()
    http.serve_month("2026-09")
    mgr = make_manager(tmp_path / "b", clock=clock, urlopen=http)
    toggled = {"done": False}

    def toggle(resp, pos):
        if not toggled["done"]:
            toggled["done"] = True
            mgr.config.update({"geoip": {"enabled": False}})
            mgr.config.update({"geoip": {"enabled": True}})

    http.read_hook = toggle
    mgr.start()
    assert _wait_for(lambda: toggled["done"])
    time.sleep(1.0)
    assert len(http.urls) <= 2
    assert mgr.running
    mgr.stop()
    assert _wait_for(lambda: not mgr.running, 3.0)


def _cut_short_big(month="2026-09"):
    """An asn download that fails after more than 1 MiB arrived (gzip of random data, cut)."""
    gz = gzip_bytes(_random_bytes(2 * MiB, seed=3))
    return {geoip.file_url("asn", month): (200, {}, gz[:int(1.5 * MiB)])}


def test_month_budget_pauses_and_retry_resumes(tmp_path, caplog):
    box, clock = _clock()
    monthly = geoip.next_month_start("2026-09") + geoip.MONTHLY_CHECK_OFFSET_S

    # three big failures pause the month
    http = FakeHttp(_cut_short_big(), chunk=256 * 1024)
    mgr = installed_manager(tmp_path / "big", "2026-08", clock=clock, urlopen=http)
    with caplog.at_level(logging.WARNING, logger="tnt.geoip"):
        for _ in range(3):
            assert mgr.run_check() == "error"
            assert mgr.status()["error"] == "the ISP download was cut short"
    assert mgr._months["2026-09"] == {"big_failures": 3, "verify_failed": False}
    assert "IP location data update paused for 2026-09 after repeated failures (Retry in Settings)" in caplog.text
    fetched = len(http.urls)
    assert mgr.run_check() == "paused"
    assert len(http.urls) == fetched
    st = mgr.status()
    assert st["error"] == "the ISP download was cut short" + geoip.PAUSE_SUFFIX
    assert (st["state"], st["next_check_ts"]) == ("ready", monthly)
    assert mgr.run_check() == "paused"
    assert mgr.status()["error"].count(geoip.PAUSE_SUFFIX) == 1

    mgr._flush_dirty_files()
    state = json.loads((tmp_path / "big" / "geoip" / "state.json").read_text(encoding="utf-8"))
    assert state["months"]["2026-09"]["big_failures"] == 3

    assert mgr.check_now() is True
    st = mgr.status()
    assert (mgr._failures, mgr._months, st["next_check_ts"]) == (0, {}, box["now"])
    http.serve_month("2026-09")
    assert mgr.run_check() == "installed"
    assert mgr.status()["month"] == "2026-09"

    # without data the not-paused previous month is still tried, but the paused month is not downloaded again
    http = FakeHttp(_cut_short_big(), chunk=256 * 1024)
    bare = make_manager(tmp_path / "bare", clock=clock, urlopen=http)
    for _ in range(3):
        assert bare.run_check() == "error"
    assert bare.run_check() == "not_published"
    assert http.urls[-1] == geoip.file_url("asn", "2026-08")
    assert http.urls.count(geoip.file_url("asn", "2026-09")) == 3

    # one failed check of the data pauses the month at once
    http = FakeHttp()
    http.serve_month("2026-09", asn=build_mmdb(ASN_FIXTURE, record_size=24, database_type="GeoLite2-ASN",
                                                 build_epoch=month_epoch("2026-09")))
    verify = installed_manager(tmp_path / "verify", "2026-08", clock=clock, urlopen=http)
    assert verify.run_check() == "error"
    fetched = len(http.urls)
    assert verify.run_check() == "paused"
    assert len(http.urls) == fetched
    assert verify.status()["error"].endswith(geoip.PAUSE_SUFFIX)
    # a newer month is not paused
    box["now"] = float(calendar.timegm((2026, 10, 15, 12, 0, 0)))
    http.serve_month("2026-10")
    assert verify.run_check() == "installed"
    assert verify.status()["month"] == "2026-10"
    box["now"] = T0

    # small failures never pause
    http = FakeHttp({geoip.file_url("asn", "2026-09"): (503, {}, b"")})
    small = installed_manager(tmp_path / "small", "2026-08", clock=clock, urlopen=http)
    for _ in range(6):
        assert small.run_check() == "error"
    assert not small._paused("2026-09") and small._months == {}

    small.config.update({"geoip": {"enabled": False}})
    assert small.check_now() is False


def test_backoff_survives_a_restart(tmp_path):
    box, clock = _clock()
    http = FakeHttp({geoip.file_url("asn", "2026-09"): (503, {}, b"")})
    first = make_manager(tmp_path, clock=clock, urlopen=http)
    assert first.apply_enabled() == "enabled"
    for _ in range(2):
        assert first.run_check() == "error"
        box["now"] += 10
    last = first._last_attempt_ts
    first._flush_dirty_files()
    first.stop()

    second = make_manager(tmp_path, clock=clock, urlopen=http, first_check_delay_s=30.0)
    assert second.apply_enabled() == "enabled"
    assert second._failures == 2
    assert second.status()["next_check_ts"] == last + geoip.backoff_s(2)
    assert second.status()["next_check_ts"] > box["now"] + 30.0


def test_clock_skew_uses_the_server_date(tmp_path):
    box, clock = _clock(float(calendar.timegm((2027, 3, 15, 12, 0, 0))))
    date = email.utils.formatdate(T0, usegmt=True)
    http = FakeHttp({geoip.file_url("asn", "2027-03"): (404, {"date": date}, b""),
                     geoip.file_url("asn", "2027-02"): (404, {"date": date}, b"")})
    http.serve_month("2026-09", date=date)
    mgr = make_manager(tmp_path, clock=clock, urlopen=http)
    assert mgr.run_check() == "installed"
    st = mgr.status()
    assert (st["month"], st["next_check_ts"]) == ("2026-09", box["now"] + 6 * 3600)
    assert http.urls == [geoip.file_url("asn", "2027-03"), geoip.file_url("asn", "2027-02"),
                         geoip.file_url("asn", "2026-09"), geoip.file_url("city", "2026-09")]
    assert mgr.run_check() == "not_published"
    st = mgr.status()
    assert (st["state"], st["error"]) == ("ready", None)


def test_stale_data_notice(tmp_path):
    box, clock = _clock()
    mgr = installed_manager(tmp_path, "2026-07", clock=clock, urlopen=FakeHttp())
    assert mgr.run_check() == "not_published"
    st = mgr.status()
    assert (st["state"], st["error"], st["month"]) == ("ready", "no newer data from DB-IP since 2026-07", "2026-07")
    assert st["next_check_ts"] == T0 + 6 * 3600
    recent = installed_manager(tmp_path / "recent", "2026-08", clock=clock, urlopen=FakeHttp())
    assert recent.run_check() == "not_published"
    assert recent.status()["error"] is None


def test_disk_space_check(tmp_path):
    box, clock = _clock()
    http = FakeHttp()
    http.serve_month("2026-09")
    mgr = make_manager(tmp_path, clock=clock, urlopen=http, disk_free_fn=lambda p: 100 * MiB)
    assert mgr.run_check() == "error"
    assert mgr.status()["error"] == "not enough free disk space (512 MB needed)"
    assert http.urls == []


# ============================================================================================ Windows file handling
@pytest.mark.skipif(sys.platform != "win32", reason="Windows sharing-violation retries")
def test_replace_retries_on_a_locked_source(tmp_path, monkeypatch):
    real_replace = os.replace
    calls = {"n": 0}

    def locked(src, dst):
        if str(src).endswith(".mmdb.part") and calls["n"] < 2:
            calls["n"] += 1
            raise PermissionError(13, "The process cannot access the file", None, 32)
        return real_replace(src, dst)

    monkeypatch.setattr(geoip.os, "replace", locked)
    monkeypatch.setattr(geoip, "REPLACE_RETRY_S", (0.01, 0.01, 0.01))
    mgr = installed_manager(tmp_path)
    assert calls["n"] == 2
    assert [f["name"] for f in mgr.files()] == ["dbip-city-lite-2026-09.mmdb", "dbip-asn-lite-2026-09.mmdb"]


def test_reinstall_of_the_open_month_uses_the_next_name(tmp_path):
    mgr = installed_manager(tmp_path)
    g1 = mgr.generation
    mgr.install_from_files("2026-09", *write_fixture_files(tmp_path / "src2"))
    assert mgr.generation == g1 + 1
    assert [f["name"] for f in mgr.files()] == ["dbip-city-lite-2026-09.1.mmdb", "dbip-asn-lite-2026-09.1.mmdb"]
    folder = tmp_path / "geoip"
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["files"]["asn"]["name"] == "dbip-asn-lite-2026-09.1.mmdb"
    assert mgr.lookup("198.51.100.7")["isp"] == "Example Transit"
    mgr.cleanup()
    assert _names(folder) == ["dbip-asn-lite-2026-09.1.mmdb", "dbip-city-lite-2026-09.1.mmdb", "manifest.json",
                              "state.json"]


def test_manifest_write_failure_is_not_an_install_failure(tmp_path, monkeypatch, caplog):
    box, clock = _clock()
    http = FakeHttp()
    mgr = installed_manager(tmp_path, "2026-08", clock=clock, urlopen=http)
    real_write = geoip._write_json_atomic
    failed = {"n": 0}

    def flaky(path, obj):
        if path.name == "manifest.json" and failed["n"] == 0:
            failed["n"] = 1
            raise OSError(28, "No space left on device")
        return real_write(path, obj)

    monkeypatch.setattr(geoip, "_write_json_atomic", flaky)
    http.serve_month("2026-09")
    with caplog.at_level(logging.WARNING, logger="tnt.geoip"):
        assert mgr.run_check() == "installed"
    assert "IP location data manifest could not be written: OSError: [Errno 28] No space left on device" in caplog.text
    st = mgr.status()
    assert (st["state"], st["month"], st["error"]) == ("ready", "2026-09", None)
    assert mgr._manifest_dirty
    folder = tmp_path / "geoip"
    assert json.loads((folder / "manifest.json").read_text(encoding="utf-8"))["month"] == "2026-08"

    fetched = len(http.urls)
    assert mgr.run_check() == "up_to_date"
    assert len(http.urls) == fetched
    mgr.cleanup()
    assert "dbip-city-lite-2026-08.mmdb" in _names(folder) and "dbip-city-lite-2026-09.mmdb" in _names(folder)

    mgr._flush_dirty_files()
    assert not mgr._manifest_dirty
    assert json.loads((folder / "manifest.json").read_text(encoding="utf-8"))["month"] == "2026-09"
    mgr.cleanup()
    assert not [n for n in _names(folder) if "2026-08" in n]


def test_cleanup_never_trusts_an_unreadable_manifest(tmp_path, caplog):
    first = installed_manager(tmp_path)
    first.stop()
    folder = tmp_path / "geoip"
    (folder / "manifest.json").write_bytes(b"")
    leftovers = ["dbip-city-lite-2026-10.mmdb.part", "manifest.json.tmp", "state.json.tmp"]
    for name in leftovers:
        (folder / name).write_bytes(b"x")
    (folder / "dbip-asn-lite-2026-07.mmdb").write_bytes(fixture_pair("2026-07")[1])

    mgr = make_manager(tmp_path)
    mgr.cleanup()
    names = _names(folder)
    assert not any(n in names for n in leftovers)
    for name in ("dbip-city-lite-2026-09.mmdb", "dbip-asn-lite-2026-09.mmdb", "dbip-asn-lite-2026-07.mmdb",
                 "manifest.json", "state.json"):
        assert name in names
    with caplog.at_level(logging.WARNING, logger="tnt.geoip"):
        assert mgr.load_installed() is True
    assert "IP location data manifest was missing or invalid; using the 2026-09 files" in caplog.text
    assert mgr.status()["month"] == "2026-09"
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["month"] == "2026-09" and manifest["files"]["city"]["name"] == "dbip-city-lite-2026-09.mmdb"


def test_stop_during_verify_loads_nothing(tmp_path, monkeypatch, caplog):
    mgr = make_manager(tmp_path / "verify")
    real_self_check = mmdb.Reader.self_check

    def stop_first(reader, samples=64):
        mgr.stop()
        return real_self_check(reader, samples)

    monkeypatch.setattr(mmdb.Reader, "self_check", stop_first)
    with caplog.at_level(logging.INFO, logger="tnt.geoip"):
        with pytest.raises(geoip.GeoIpError):
            mgr.install_from_files("2026-09", *write_fixture_files(tmp_path / "src"))
    monkeypatch.setattr(mmdb.Reader, "self_check", real_self_check)
    assert not mgr.available and mgr.lookup("203.0.113.9") is None
    assert "installed" not in caplog.text

    # a stop that lands after the move: the swap is refused and the final files stay for a later cleanup
    late = make_manager(tmp_path / "late")
    real_replace = os.replace

    def replace_then_stop(src, dst):
        real_replace(src, dst)
        if str(src).endswith("dbip-asn-lite-2026-09.mmdb.part"):
            late.stop()

    monkeypatch.setattr(geoip.os, "replace", replace_then_stop)
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="tnt.geoip"):
        with pytest.raises(geoip.GeoIpError, match="the install was interrupted"):
            late.install_from_files("2026-09", *write_fixture_files(tmp_path / "src"))
    assert not late.available and "installed" not in caplog.text
    assert _names(tmp_path / "late" / "geoip") == ["dbip-asn-lite-2026-09.mmdb", "dbip-city-lite-2026-09.mmdb"]


# ============================================================================================ lifecycle and threads
def test_load_installed_at_start_and_bad_manifests(tmp_path, caplog):
    first = installed_manager(tmp_path / "good")
    first.stop()
    http = FakeHttp()
    mgr = make_manager(tmp_path / "good", urlopen=http)
    assert mgr.load_installed() is True
    st = mgr.status()
    assert (st["state"], st["available"], st["month"]) == ("ready", True, "2026-09")
    assert http.urls == []
    mgr.stop()

    good = {"version": 1, "month": "2026-09", "installed_ts": T0,
            "files": {"city": {"name": "dbip-city-lite-2026-09.mmdb"}, "asn": {"name": "dbip-asn-lite-2026-09.mmdb"}}}

    def variant(**changes):
        doc = json.loads(json.dumps(good))
        for dotted, value in changes.items():
            target = doc
            *path, last = dotted.split("__")
            for part in path:
                target = target[part]
            target[last] = value
        return json.dumps(doc)

    bad_manifests = [
        "{not json",
        variant(files__city={"name": "../dbip-city-lite-2026-09.mmdb"}),
        variant(files__asn={"name": "sub/dbip-asn-lite-2026-09.mmdb"}),
        variant(files__city={"name": "dbip-asn-lite-2026-09.mmdb"}),
        variant(files__asn={"name": "dbip-asn-lite-2026-08.mmdb"}),
        variant(files__city={"name": "dbip-city-lite-2026-09.mmdb\n"}),
        variant(version=2),
        variant(version=True),
        variant(month="2026-13"),
        json.dumps([1, 2]),
    ]
    for i, text in enumerate(bad_manifests):
        folder = tmp_path / f"bad{i}" / "geoip"
        folder.mkdir(parents=True)
        (folder / "manifest.json").write_text(text, encoding="utf-8")
        (folder / "dbip-city-lite-2026-09.mmdb").write_bytes(b"not a database")
        assert make_manager(tmp_path / f"bad{i}").load_installed() is False, text

    # a valid manifest whose files cannot be loaded: a warning, no fallback
    folder = tmp_path / "missing-files" / "geoip"
    folder.mkdir(parents=True)
    (folder / "manifest.json").write_text(json.dumps(good), encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="tnt.geoip"):
        assert make_manager(tmp_path / "missing-files").load_installed() is False
    assert "IP location data could not be loaded:" in caplog.text

    # an invalid manifest with a valid pair on disk: the fallback loads it
    second = installed_manager(tmp_path / "fallback")
    second.stop()
    folder = tmp_path / "fallback" / "geoip"
    (folder / "manifest.json").write_text(variant(files__city={"name": "dbip-asn-lite-2026-09.mmdb"}), encoding="utf-8")
    (folder / "dbip-city-lite-2026-10.mmdb").write_bytes(b"a newer month that does not load")
    mgr = make_manager(tmp_path / "fallback")
    assert mgr.load_installed() is True
    assert mgr.status()["month"] == "2026-09"
    assert json.loads((folder / "manifest.json").read_text(encoding="utf-8"))["files"]["city"]["name"] == \
        "dbip-city-lite-2026-09.mmdb"


def test_missing_data_folder_is_empty(tmp_path):
    folder = tmp_path / "nope" / "geoip"
    mgr = make_manager(tmp_path, dir_fn=lambda: folder)
    mgr.cleanup()
    assert mgr.load_installed() is False
    assert mgr.apply_enabled() == "enabled"
    assert not mgr.available and mgr.status()["state"] == "starting"
    assert not folder.exists()


def test_thread_survives_errors(tmp_path):
    mgr = make_manager(tmp_path, urlopen=False, dir_fn=lambda: tmp_path / "missing" / "geoip")
    mgr.start()
    assert _wait_for(lambda: mgr.status()["state"] == "error")
    assert mgr.running and mgr.status()["error"] in BLOCKED_TEXTS

    calls = {"n": 0}

    def boom():
        calls["n"] += 1
        raise RuntimeError("unexpected")

    mgr.run_check = boom
    # Retry until the loop picks it up (the first check may still be leaving its own schedule behind)
    assert _wait_for(lambda: calls["n"] >= 1 or not mgr.check_now())
    assert _wait_for(lambda: mgr.status()["error"] == "RuntimeError: unexpected")
    time.sleep(0.2)
    assert mgr.running and calls["n"] >= 1
    st = mgr.status()
    assert st["state"] == "error" and mgr._failures == 1
    assert st["next_check_ts"] >= time.time() + geoip.backoff_s(1) - 5
    mgr.stop()
    assert _wait_for(lambda: not mgr.running, 3.0)


def test_cleanup_deletes_only_unreferenced_known_files(tmp_path):
    mgr = installed_manager(tmp_path)
    folder = tmp_path / "geoip"
    (folder / "foo.txt").write_text("keep me", encoding="utf-8")
    old = folder / "dbip-asn-lite-2026-07.mmdb"
    old.write_bytes(fixture_pair("2026-07")[1])
    still_open = folder / "dbip-city-lite-2026-06.mmdb"
    still_open.write_bytes(fixture_pair("2026-06")[0])
    reader = mmdb.Reader(still_open)
    try:
        mgr.cleanup()
        assert (folder / "foo.txt").exists() and (folder / "state.json").exists()
        assert not old.exists()
        if sys.platform == "win32":
            assert still_open.exists()                 # mapped: skipped without raising
    finally:
        reader.close()
    mgr.cleanup()
    assert not still_open.exists()
    assert _names(folder) == ["dbip-asn-lite-2026-09.mmdb", "dbip-city-lite-2026-09.mmdb", "foo.txt",
                              "manifest.json", "state.json"]


def test_disable_unloads_and_enable_reloads(tmp_path, bus):
    box, clock = _clock()
    mgr = installed_manager(tmp_path, clock=clock, bus=bus)
    mgr.config.update({"geoip": {"enabled": False}})
    disabled = {"enabled": False, "state": "disabled", "available": False, "month": None, "bytes": None,
                "installed_ts": None, "checked_ts": None, "next_check_ts": None, "download": None, "error": None}
    assert mgr.status() == disabled
    assert mgr.available                                 # not applied yet
    assert mgr.apply_enabled() == "disabled"
    assert mgr.status() == disabled and not mgr.available
    assert mgr.lookup("203.0.113.9") is None and mgr.locate_hop("203.0.113.9") is None
    assert mgr.run_check() == "disabled"
    folder = tmp_path / "geoip"
    assert "dbip-city-lite-2026-09.mmdb" in _names(folder)
    assert mgr.apply_enabled() == "unchanged"

    mgr.config.update({"geoip": {"enabled": True}})
    assert mgr.status()["state"] == "starting"
    box["now"] += 100.0
    assert mgr.apply_enabled() == "enabled"
    st = mgr.status()
    assert (st["state"], st["available"], st["month"], st["next_check_ts"]) == ("ready", True, "2026-09", box["now"])
    assert mgr.lookup("203.0.113.9")["place"] == "Anytown, TX"
    assert mgr.apply_enabled() == "unchanged"
    assert [ev["data"]["state"] for ev in bus.events if ev["type"] == "geoip.state"][-1] == "ready"


def test_start_stop_thread_bounded(tmp_path):
    mgr = make_manager(tmp_path, urlopen=False)
    t0 = time.monotonic()
    mgr.start()
    assert time.monotonic() - t0 < 0.5
    assert mgr.running and _geoip_threads()
    assert _wait_for(lambda: mgr.status()["state"] == "error")
    assert mgr.status()["error"] in BLOCKED_TEXTS
    t0 = time.monotonic()
    mgr.stop()
    assert time.monotonic() - t0 < 1.5
    assert _wait_for(lambda: not _geoip_threads(), 3.0)
    mgr.stop()
    mgr.start()
    assert mgr.running
    assert _wait_for(lambda: mgr.status()["state"] == "error")
    mgr.stop()
    assert _wait_for(lambda: not _geoip_threads(), 3.0)


def test_start_refuses_a_second_thread(tmp_path, caplog):
    assert _wait_for(lambda: not _geoip_threads(), 5.0)     # no thread left over from an earlier test
    box, clock = _clock()
    http = FakeHttp()
    http.serve_month("2026-09")
    entered, release = threading.Event(), threading.Event()

    def ignore_abort(resp, pos):
        if not entered.is_set():
            entered.set()
            release.wait(3.0)

    http.read_hook = ignore_abort
    mgr = make_manager(tmp_path, clock=clock, urlopen=http)
    mgr.start()
    try:
        assert entered.wait(5.0)
        with caplog.at_level(logging.WARNING, logger="tnt.geoip"):
            t0 = time.monotonic()
            mgr.stop()
            assert time.monotonic() - t0 < geoip.STOP_JOIN_S + 0.5
            assert mgr.running
            mgr.start()
        assert "IP location thread is still finishing a download step" in caplog.text
        assert "IP location thread from the previous start is still finishing; not starting another" in caplog.text
        assert len(_geoip_threads()) == 1
    finally:
        release.set()
    assert _wait_for(lambda: not mgr.running, 5.0)
    assert not mgr.available


def test_stop_interrupts_a_stalled_read(tmp_path):
    box, clock = _clock()
    http = FakeHttp()
    http.serve_month("2026-09")
    entered = threading.Event()

    def stall_until_abort(resp, pos):
        entered.set()
        resp.abort_event.wait(30.0)

    http.read_hook = stall_until_abort
    mgr = make_manager(tmp_path, clock=clock, urlopen=http)
    mgr.start()
    assert entered.wait(5.0)
    t0 = time.monotonic()
    mgr.stop()
    assert _wait_for(lambda: not mgr.running, geoip.STOP_JOIN_S + 1.0)
    assert time.monotonic() - t0 < geoip.STOP_JOIN_S + 1.0
    assert mgr._failures == 0 and not _parts(tmp_path / "geoip")


def test_lookup_cache_and_generation(tmp_path, monkeypatch):
    mgr = installed_manager(tmp_path)
    gets = {"n": 0}
    real_get = mmdb.Reader.get

    def counting_get(reader, ip):
        gets["n"] += 1
        return real_get(reader, ip)

    monkeypatch.setattr(mmdb.Reader, "get", counting_get)
    g1 = mgr.generation
    first = mgr.lookup("203.0.113.9")
    assert gets["n"] == 2 and (g1, "203.0.113.9") in mgr._cache
    first["place"] = "changed"
    again = mgr.lookup("::ffff:203.0.113.9")
    assert gets["n"] == 2 and again["place"] == "Anytown, TX"
    assert mgr.lookup("198.18.0.1") is None and mgr._cache[(g1, "198.18.0.1")] is None
    assert mgr.lookup("198.18.0.1") is None and gets["n"] == 4

    mgr.install_from_files("2026-09", *write_fixture_files(tmp_path / "src2"))
    assert mgr.generation > g1 and mgr._cache == {}
    gets["n"] = 0                                          # the install's verify probes use Reader.get too
    assert mgr.lookup("203.0.113.9")["place"] == "Anytown, TX" and gets["n"] == 2

    monkeypatch.setattr(geoip, "LOOKUP_CACHE_MAX", 4)
    for i in range(1, 11):
        mgr.lookup(f"203.0.113.{i}")
    assert len(mgr._cache) <= 4


def test_concurrent_lookups_and_status_during_swap(tmp_path):
    mgr = installed_manager(tmp_path, "2026-08")
    stop, errors, bad = threading.Event(), [], []

    def guarded(fn):
        def run():
            try:
                while not stop.is_set():
                    fn()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
        return run

    def lookups():
        for ip in ("203.0.113.9", "198.51.100.7", "2001:db8::1", "192.0.2.10"):
            geo = mgr.lookup(ip)
            if geo is not None and tuple(geo) != geoip.GEO_KEYS:
                bad.append(geo)

    def statuses():
        st = mgr.status()
        if tuple(st) != geoip.STATUS_KEYS:
            bad.append(st)

    def hops():
        loc = mgr.locate_hop("198.51.100.65", "ae-1.cr1.dllstx.example.net", 12.0, DALLAS)
        if loc is not None and tuple(loc) != geoip.LOCATION_KEYS:
            bad.append(loc)

    threads = [threading.Thread(target=guarded(lookups)) for _ in range(4)]
    threads += [threading.Thread(target=guarded(statuses)), threading.Thread(target=guarded(hops))]
    for t in threads:
        t.start()
    try:
        mgr.install_from_files("2026-09", *write_fixture_files(tmp_path / "src9", "2026-09"))
        mgr.install_from_files("2026-08", *write_fixture_files(tmp_path / "src8", "2026-08"))
    finally:
        stop.set()
        for t in threads:
            t.join(5.0)
    assert not any(t.is_alive() for t in threads)
    assert errors == [] and bad == []
    assert mgr.status()["month"] == "2026-08"


def _fake_hint(city, region, cc, lat, lon, code, confidence):
    return {"key": "x", "city": city, "region": region, "cc": cc, "lat": lat, "lon": lon, "code": code,
            "kind": "clli", "rule": "generic" if confidence != "carrier" else "carrier.example.net",
            "confidence": confidence}


def test_locate_hop(tmp_path, monkeypatch):
    mgr = installed_manager(tmp_path)
    loc = mgr.locate_hop("203.0.113.9")
    assert tuple(loc) == geoip.LOCATION_KEYS
    assert loc == {"text": "Anytown, TX", "source": "database", "hint": None, "db_text": "Anytown, TX",
                   "asn": 64500, "as_org": "Example Broadband"}

    router = "ae-1.cr1.dllstx.example.net"
    loc = mgr.locate_hop("198.51.100.65", router, 12.0, DALLAS)
    assert loc == {"text": "Dallas, TX", "source": "hostname", "hint": "dllstx", "db_text": "Richardson, TX",
                   "asn": 64510, "as_org": "Example Transit, Inc."}
    # a generic hint needs the speed-of-light guard
    assert mgr.locate_hop("198.51.100.65", router, 12.0, None)["source"] == "database"
    assert mgr.locate_hop("198.51.100.65", router, None, DALLAS)["source"] == "database"
    # the destination takes carrier hints only
    loc = mgr.locate_hop("198.51.100.65", router, 12.0, DALLAS, kind="destination")
    assert (loc["text"], loc["source"], loc["hint"]) == ("Richardson, TX", "database", None)

    real_hint = geohints.location_hint
    london = _fake_hint("London", "", "GB", 51.51, -0.13, "londen", "generic-strong")
    monkeypatch.setattr(geoip.geohints, "location_hint", lambda hostname, ip=None: dict(london))
    loc = mgr.locate_hop("198.51.100.65", "ae1.cr2.londen.example.net", 12.0, DALLAS)
    assert (loc["text"], loc["source"], loc["db_text"]) == ("Richardson, TX", "database", "Richardson, TX")

    carrier = _fake_hint("Dallas", "TX", "US", 32.78, -96.80, "dllstx", "carrier")
    monkeypatch.setattr(geoip.geohints, "location_hint", lambda hostname, ip=None: dict(carrier))
    loc = mgr.locate_hop("198.51.100.65", "ae1.cr2.dllstx.carrier.example.net", None, None)
    assert (loc["text"], loc["source"], loc["hint"]) == ("Dallas, TX", "hostname", "dllstx")
    loc = mgr.locate_hop("198.51.100.65", "ae1.cr2.dllstx.carrier.example.net", 12.0, DALLAS, kind="destination")
    assert loc["source"] == "hostname"
    # a hint on an address without any record still gives a location
    loc = mgr.locate_hop("198.18.0.1", "ae1.cr2.dllstx.carrier.example.net", None, None)
    assert loc == {"text": "Dallas, TX", "source": "hostname", "hint": "dllstx", "db_text": None, "asn": None,
                   "as_org": None}
    monkeypatch.setattr(geoip.geohints, "location_hint", real_hint)

    for ip in ("10.0.0.1", "192.168.1.1", "100.64.0.1", None, "", "junk"):
        assert mgr.locate_hop(ip, router, 12.0, DALLAS) is None, ip
    assert mgr.locate_hop("198.18.0.1") is None
    assert make_manager(tmp_path / "empty").locate_hop("203.0.113.9") is None


def test_origin_uses_public_ip_fn(tmp_path):
    assert installed_manager(tmp_path / "a", public_ip="203.0.113.200").origin() == (32.78, -96.8)
    assert installed_manager(tmp_path / "b", public_ip=None).origin() is None
    assert installed_manager(tmp_path / "c", public_ip="10.0.0.1").origin() is None

    def boom():
        raise RuntimeError("no public ip")

    assert installed_manager(tmp_path / "d", public_ip_fn=boom).origin() is None
    assert make_manager(tmp_path / "e").origin() is None


def test_status_shape_every_state(tmp_path):
    box, clock = _clock()
    http = FakeHttp()
    http.serve_month("2026-09")
    mgr = make_manager(tmp_path / "a", clock=clock, urlopen=http)
    st = mgr.status()
    assert tuple(st) == geoip.STATUS_KEYS and (st["state"], st["download"]) == ("starting", None)

    during = []
    http.read_hook = lambda resp, pos: during.append(mgr.status())
    assert mgr.run_check() == "installed"
    assert during and all(tuple(s) == geoip.STATUS_KEYS for s in during)
    downloading = during[0]
    assert downloading["state"] == "downloading" and tuple(downloading["download"]) == geoip.DOWNLOAD_KEYS
    assert downloading["download"]["month"] == "2026-09" and downloading["download"]["file"] == "asn"
    st = mgr.status()
    assert tuple(st) == geoip.STATUS_KEYS and st["state"] == "ready"

    err = make_manager(tmp_path / "b", clock=clock, urlopen=FakeHttp({geoip.file_url("asn", "2026-09"): (503, {}, b"")}))
    err.run_check()
    st = err.status()
    assert tuple(st) == geoip.STATUS_KEYS and (st["state"], st["available"]) == ("error", False)

    mgr.config.update({"geoip": {"enabled": False}})
    st = mgr.status()
    assert tuple(st) == geoip.STATUS_KEYS and st["state"] == "disabled"
    assert set(geoip.STATES) == {"disabled", "starting", "downloading", "ready", "error"}


def test_no_ip_or_location_in_info_logs(tmp_path, caplog):
    box, clock = _clock()
    forbidden = ("203.0.113", "192.0.2", "198.51.100", "2001:db8", "Anytown", "Richardson", "Example Broadband",
                 "Example Transit")
    with _local_server() as base, caplog.at_level(logging.INFO):
        http = FakeHttp()
        http.serve_month("2026-09")
        mgr = make_manager(tmp_path, clock=clock, urlopen=http)
        assert mgr.apply_enabled() == "enabled"
        assert mgr.run_check() == "installed"
        for ip in ("203.0.113.9", "198.51.100.7", "2001:db8::1", "192.0.2.10"):
            assert mgr.lookup(ip) is not None
        assert mgr.locate_hop("198.51.100.65", "ae-1.cr1.dllstx.example.net", 12.0, DALLAS) is not None
        assert mgr.origin() is not None
        resp = geoip.http_open(base + "/to-ip-literal")     # a followed redirect to an IP-literal host
        resp.close()
        http.table[geoip.file_url("asn", "2026-10")] = (503, {}, b"")
        box["now"] = float(calendar.timegm((2026, 10, 15, 12, 0, 0)))
        assert mgr.run_check() == "error"
        with pytest.raises(geoip.DownloadError):
            geoip.http_open(base + "/ip")
    infos = [r for r in caplog.records if r.levelno >= logging.INFO]
    assert any("redirected to another site" in r.getMessage() for r in infos)
    assert any("installed" in r.getMessage() for r in infos)
    for record in infos:
        message = record.getMessage()
        assert not any(bad in message for bad in forbidden), message
        assert "127.0.0.1" not in message, message


# ============================================================================================ HTTP (local server)
class _Handler(BaseHTTPRequestHandler):
    agents: list = []

    def do_GET(self):  # noqa: N802 - http.server API
        type(self).agents.append(self.headers.get("User-Agent", ""))
        port = self.server.server_address[1]
        routes = {
            "/ok": (200, None),
            "/loop": (302, "/ok"),
            "/to-ip-literal": (302, f"http://127.0.0.1:{port}/ok"),
            "/evil": (302, "http://evil.example/"),
            "/ip": (302, "http://192.0.2.1/"),
            "/dbip": (302, "https://download.db-ip.com/x"),
            "/nolocation": (302, ""),
            "/r1": (302, "/r2"), "/r2": (302, "/r3"), "/r3": (302, "/r4"), "/r4": (302, "/r5"), "/r5": (200, None),
        }
        status, location = routes.get(self.path, (404, None))
        body = b"hello" if status == 200 else b"redirect or missing"
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _local_server:
    def __enter__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(5)


def _read_all(resp) -> bytes:
    out, buf = bytearray(), bytearray(1024)
    while True:
        n = resp.readinto(buf)
        if not n:
            return bytes(out)
        out += buf[:n]


def test_http_open_redirects(monkeypatch):
    monkeypatch.setenv(geoip.OFFLINE_ENV, "1")
    connects = []

    def no_https(*args, **kw):
        connects.append(args)
        raise AssertionError("an https connection must never be attempted")

    monkeypatch.setattr(geoip.http.client, "HTTPSConnection", no_https)
    _Handler.agents = []
    with _local_server() as base:
        resp = geoip.http_open(base + "/loop")
        try:
            assert resp.status == 200 and resp.url == base + "/ok" and resp.host == "another site"
            assert resp.headers["content-length"] == "5" and _read_all(resp) == b"hello"
        finally:
            resp.close()
            resp.close()
        with pytest.raises(geoip.DownloadError, match="^refused a redirect to evil.example$"):
            geoip.http_open(base + "/evil")
        with pytest.raises(geoip.DownloadError, match="^refused a redirect to another site$"):
            geoip.http_open(base + "/ip")
        with pytest.raises(OSError, match=re.escape("network access is disabled (TNT_GEOIP_OFFLINE)")):
            geoip.http_open(base + "/dbip")
        assert connects == []
        with pytest.raises(geoip.DownloadError, match="^too many redirects from another site$"):
            geoip.http_open(base + "/r1")
        resp = geoip.http_open(base + "/r2")                 # three redirects are fine
        assert resp.status == 200
        resp.close()
        with pytest.raises(geoip.DownloadError, match="^HTTP 302 from another site$"):
            geoip.http_open(base + "/nolocation")
        resp = geoip.http_open(base + "/missing")
        assert resp.status == 404
        resp.close()
    assert _Handler.agents and all(a.startswith("TNT/") for a in _Handler.agents)
    assert _Handler.agents[0] == geoip.USER_AGENT
    for url in ("http://example.net/x", "ftp://127.0.0.1/x", "file:///C:/x", "http:///x"):
        with pytest.raises(ValueError):
            geoip.http_open(url)
    with pytest.raises(OSError, match="TNT_GEOIP_OFFLINE"):
        geoip.http_open("https://download.db-ip.com/free/x")
    assert connects == []


def test_http_abort_after_getresponse():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    release = threading.Event()

    def serve():
        conn, _addr = listener.accept()
        with conn:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\n" + b"x" * 10)
            release.wait(10.0)

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    try:
        resp = geoip.http_open(f"http://127.0.0.1:{port}/stall", timeout=20.0)
        assert resp.status == 200
        outcome = {}

        def reader():
            buf = bytearray(65536)
            try:
                while resp.readinto(buf):
                    pass
                outcome["result"] = "eof"
            except Exception as exc:  # noqa: BLE001
                outcome["result"] = type(exc).__name__

        worker = threading.Thread(target=reader, daemon=True)
        worker.start()
        time.sleep(0.3)
        assert worker.is_alive()
        t0 = time.monotonic()
        resp.abort()
        resp.abort()
        worker.join(2.0)
        assert not worker.is_alive() and time.monotonic() - t0 < 2.0
        assert "result" in outcome
        resp.close()
    finally:
        release.set()
        listener.close()
        server.join(5)


class _trickle_server:
    """A loopback server answering 200 and then trickling ``body`` (``step`` bytes every ``every`` s, for at most
    ``limit_s`` s) with Content-Length or chunked framing."""

    def __init__(self, body: bytes, *, chunked: bool = False, step: int = 2000, every: float = 0.2,
                 limit_s: float = 10.0):
        self.body, self.chunked, self.step, self.every, self.limit_s = body, chunked, step, every, limit_s

    def __enter__(self):
        self.done = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.listener.getsockname()[1]}"

    def __exit__(self, *exc):
        self.done.set()
        self.listener.close()
        self.thread.join(5)

    def _serve(self):
        while not self.done.is_set():
            try:
                conn, _addr = self.listener.accept()
            except OSError:
                continue
            try:
                self._send(conn)
            except OSError:
                pass                    # the client gave up on the download
            finally:
                conn.close()

    def _send(self, conn):
        conn.settimeout(5.0)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        framing = (b"Transfer-Encoding: chunked" if self.chunked
                   else b"Content-Length: %d" % len(self.body))
        conn.sendall(b"HTTP/1.1 200 OK\r\n" + framing + b"\r\nConnection: close\r\n\r\n")
        deadline, pos = time.monotonic() + self.limit_s, 0
        while pos < len(self.body) and time.monotonic() < deadline and not self.done.is_set():
            piece = self.body[pos:pos + self.step]
            pos += len(piece)
            conn.sendall(b"%x\r\n%s\r\n" % (len(piece), piece) if self.chunked else piece)
            self.done.wait(self.every)


@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
def test_http_trickle_trips_the_stall_rule(tmp_path, monkeypatch, chunked):
    """The real http_open over loopback: a trickle trips the stall rule once the window passes, not only when a whole
    READ_CHUNK buffer has filled (a buffered readinto waits for that, or for the end of the stream)."""
    monkeypatch.setattr(geoip, "STALL_WINDOW_S", 1.0)
    box, clock = _clock()
    opened = []
    with _trickle_server(gzip_bytes(_random_bytes(MiB, seed=7)), chunked=chunked) as base:

        def urlopen(url, *, timeout):
            opened.append(url)
            return geoip.http_open(base + "/" + url.rsplit("/", 1)[-1], timeout=timeout)

        mgr = make_manager(tmp_path, clock=clock, urlopen=urlopen)
        t0 = time.monotonic()
        assert mgr.run_check() == "error"
        elapsed = time.monotonic() - t0
    assert mgr.status()["error"] == "the ISP download stalled (less than 1 MB in 5 min)"
    assert elapsed < 3.0, elapsed                  # the buffered read took the server's whole 10 s
    assert opened == [geoip.file_url("asn", "2026-09")]
    assert not _parts(tmp_path / "geoip")


def test_conftest_blocks_urlopen():
    with pytest.raises(OSError):
        geoip._urlopen("https://download.db-ip.com/free/x")
    assert os.environ["TNT_GEOIP_OFFLINE"] == "1"


# ============================================================================================ smoke (real files)
@pytest.mark.skipif(not os.environ.get("TNT_TEST_DBIP_DIR"), reason="set TNT_TEST_DBIP_DIR to a folder with DB-IP Lite files")
def test_real_dbip_install_smoke(tmp_path):
    source = Path(os.environ["TNT_TEST_DBIP_DIR"])

    def months(suffix):
        found = {}
        for path in source.glob(f"dbip-*-lite-*{suffix}"):
            m = re.fullmatch(r"dbip-(city|asn)-lite-(\d{4}-\d{2})" + re.escape(suffix), path.name)
            if m:
                found.setdefault(m.group(2), {})[m.group(1)] = path
        return sorted((m for m, kinds in found.items() if len(kinds) == 2), reverse=True), found

    gz_months, gz_files = months(".mmdb.gz")
    if gz_months:
        month = gz_months[0]
        year, mon = (int(x) for x in month.split("-"))
        box, clock = _clock(float(calendar.timegm((year, mon, 15, 12, 0, 0))))
        http = FakeHttp(chunk=geoip.READ_CHUNK)
        for kind in ("city", "asn"):
            body = gz_files[month][kind].read_bytes()
            http.table[geoip.file_url(kind, month)] = (200, {"content-length": str(len(body))}, body)
        mgr = make_manager(tmp_path, clock=clock, urlopen=http, verify_probes=geoip.VERIFY_PROBES)
        assert mgr.run_check() == "installed"
    else:
        mmdb_months, mmdb_files = months(".mmdb")
        assert mmdb_months, "TNT_TEST_DBIP_DIR holds no DB-IP Lite city/asn pair"
        month = mmdb_months[0]
        mgr = make_manager(tmp_path, verify_probes=geoip.VERIFY_PROBES)
        mgr.install_from_files(month, mmdb_files[month]["city"], mmdb_files[month]["asn"])
    assert mgr.status()["state"] == "ready" and mgr.status()["month"] == month
    geo = mgr.lookup("8.8.8.8")
    assert geo is not None
    assert (geo["country_code"], geo["asn"]) == ("US", 15169) and geo["isp"]
    assert mgr.lookup("1.1.1.1")["asn"] == 13335
    assert mgr.lookup("10.0.0.1") is None
