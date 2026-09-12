"""Tests for tnt.networks (which network this PC is on) and the database side of tagging data with networks.

Everything is synthetic: RFC 1918 / RFC 5737 addresses, locally administered MACs (02:00:5E:..), invented DNS suffixes.  The
adapters and the neighbour table are fakes: no native call, no network.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest

from tnt import db as tnt_db
from tnt import networks
from tnt.db import Database

T0 = 1_780_000_020.0            # a minute boundary + 20 s
DAY = 86400.0
MAC_A = "02:00:5E:10:00:0A"
MAC_B = "02:00:5E:10:00:0B"
MAC_C = "02:00:5E:10:00:0C"


def minute(ts: float) -> int:
    return int(ts // 60) * 60


class Clock:
    def __init__(self, t: float = T0) -> None:
        self.t = float(t)

    def __call__(self) -> float:
        return self.t


class World:
    """The adapters (as gateway facts) and the neighbour table this fake PC sees."""

    def __init__(self) -> None:
        self.facts: Optional[Dict[str, Any]] = self.site("192.168.1.1", "192.168.1.0/24", "192.168.1.1", "site-a.example")
        self.neigh: Dict[str, Tuple[str, Optional[str]]] = {}
        self.reads = 0

    @staticmethod
    def site(gateway: str, subnet: str, dhcp: Optional[str], suffix: str = "", nic: str = "Wi-Fi", index: int = 7) -> Dict[str, Any]:
        return {"gateway_ip": gateway, "subnet": subnet, "dhcp_server": dhcp, "dns_suffix": suffix or None, "nic": nic, "if_index": index}

    def facts_fn(self, hint: Optional[str]) -> Optional[Dict[str, Any]]:
        return dict(self.facts) if self.facts else None

    def neighbour_fn(self, ip: str, if_index: Optional[int]) -> Optional[Tuple[str, Optional[str]]]:
        self.reads += 1
        return self.neigh.get(ip)


def tracker(db: Database, world: World, clock: Optional[Clock] = None, **kw: Any) -> networks.NetworkTracker:
    opts = dict(mac_wait_s=3.0, mac_poll_s=0.02, confirm_s=0.1, touch_every_s=0.0)
    opts.update(kw)
    return networks.NetworkTracker(db, clock=clock or Clock(), facts_fn=world.facts_fn, neighbour_fn=world.neighbour_fn, **opts)


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "tnt.db")
    yield d
    d.close()


def rows(db: Database, sql: str, *params: Any) -> List[tuple]:
    return [tuple(r) for r in db._conn.execute(sql, params).fetchall()]


# --------------------------------------------------------------------------------------------- pure helpers
def test_fingerprint_is_stable_and_names_gateway_subnet_and_dhcp_server():
    fp = networks.fingerprint("192.168.1.1", "192.168.1.0/24", "192.168.1.1")
    assert fp == networks.fingerprint(" 192.168.1.1 ", "192.168.1.0/24", "192.168.1.1") and len(fp) == 32
    assert fp != networks.fingerprint("192.168.1.1", "192.168.1.0/24", None)
    assert fp != networks.fingerprint("192.168.1.254", "192.168.1.0/24", "192.168.1.1")
    assert fp != networks.fingerprint("192.168.1.1", "192.168.1.0/24", "192.168.1.1", "00:00:5E:00:01:01")


def test_virtual_router_macs():
    for mac in ("00:00:5E:00:01:01", "00-00-5e-00-02-10", "00:00:0C:07:AC:01", "00:00:0C:9F:F0:01", "00:07:B4:00:01:02"):
        assert networks.is_virtual_router_mac(mac), mac
    for mac in (MAC_A, "00:00:5E:00:53:01", None, "not a mac"):
        assert not networks.is_virtual_router_mac(mac), mac


def test_gateway_facts_read_the_adapter_that_owns_the_gateway():
    def v4(address: str, network: str, preferred: bool = True) -> Any:
        return SimpleNamespace(address=address, network=network, preferred=preferred)

    vpn = SimpleNamespace(index=30, name="Example VPN", is_up=True, gateways=[], ipv4=[v4("10.99.0.2", "10.99.0.0/24")], ipv6=[],
                          dhcp_server=None, dns_suffix="vpn.example", metric_v4=1)
    wifi = SimpleNamespace(index=7, name="Wi-Fi", is_up=True, gateways=["192.168.1.1", "fe80::1%7"],
                           ipv4=[v4("169.254.10.1", "169.254.0.0/16", False), v4("192.168.1.23", "192.168.1.0/24")],
                           ipv6=[v4("fe80::23", "fe80::/64"), v4("2001:db8:1::23", "2001:db8:1::/64")],
                           dhcp_server="192.168.1.1", dns_suffix="site-a.example", metric_v4=35)
    dock = SimpleNamespace(index=12, name="Ethernet", is_up=False, gateways=["192.168.1.1"], ipv4=[], ipv6=[],
                           dhcp_server=None, dns_suffix="", metric_v4=5)
    facts = networks.gateway_facts([vpn, dock, wifi], "192.168.1.1", internet_index=30)
    assert facts == {"gateway_ip": "192.168.1.1", "subnet": "192.168.1.0/24", "dhcp_server": "192.168.1.1",
                     "dns_suffix": "site-a.example", "nic": "Wi-Fi", "if_index": 7}, "the up owner, not the VPN tunnel or a down dock"
    v6 = networks.gateway_facts([wifi], "fe80::1%12")
    assert (v6["gateway_ip"], v6["subnet"], v6["if_index"]) == ("fe80::1", "2001:db8:1::/64", 7), "the zone is not part of the network"
    assert networks.gateway_facts([wifi], None) is None
    assert networks.gateway_facts([], "10.0.0.1") == {"gateway_ip": "10.0.0.1", "subnet": None, "dhcp_server": None,
                                                      "dns_suffix": None, "nic": None, "if_index": None}


def test_network_view_and_unknown_network():
    row = {"id": 4, "mac": MAC_A, "fingerprint": "x", "gateway_ip": "192.168.1.1", "subnet": "192.168.1.0/24",
           "dhcp_server": "192.168.1.1", "first_seen": T0, "last_seen": T0 + 5}
    view = networks.network_view(row)
    assert set(view) == {"id", "mac", "vendor", "gateway_ip", "subnet", "dhcp_server", "identity", "virtual_mac", "portable",
                         "first_seen", "last_seen"}
    assert view["identity"] == "mac" and view["mac"] == MAC_A and view["portable"] is False and view["virtual_mac"] is None
    vrrp = networks.network_view(dict(row, mac=None, virtual_mac="00:00:5E:00:01:01", portable=1), with_times=False)
    assert (vrrp["identity"], vrrp["virtual_mac"], vrrp["portable"]) == ("fingerprint", "00:00:5E:00:01:01", True)
    assert networks.network_view(None) is None
    assert networks.unknown_network() == {"id": None, "mac": None, "vendor": None, "gateway_ip": None, "subnet": None,
                                          "dhcp_server": None, "identity": "unknown", "virtual_mac": None, "portable": False}


# --------------------------------------------------------------------------------------------- identification
def test_the_router_mac_names_the_network_at_once(db):
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    tr = tracker(db, world)
    tr.start()
    try:
        nid = tr.current_network_id()
        row = db.get_network(nid)
        assert (row["mac"], row["gateway_ip"], row["subnet"], row["dhcp_server"], row["dns_suffix"], row["nic"]) == \
            (MAC_A, "192.168.1.1", "192.168.1.0/24", "192.168.1.1", "site-a.example", "Wi-Fi")
        assert tr.current()["identity"] == "mac" and tr.gateway_mac("192.168.1.1") == MAC_A and tr.gateway_mac("10.0.0.1") is None
        assert tr.wait_idle(1.0), "no MAC poll for a router that answered"
        # a second start on the same network: the same row, and the id survives a restart
        again = tracker(db, world)
        assert again.previous_id == nid
        again.start()
        assert again.current_network_id() == nid and len(db.list_networks()) == 1
        again.stop()
    finally:
        tr.stop()


def test_without_a_mac_the_network_is_known_by_its_fingerprint(db):
    world = World()
    tr = tracker(db, world, mac_wait_s=0.2)
    tr.start()
    try:
        assert tr.wait_idle(3.0)
        row = db.get_network(tr.current_network_id())
        assert row["mac"] is None and row["fingerprint"] == networks.fingerprint("192.168.1.1", "192.168.1.0/24", "192.168.1.1")
        assert tr.current()["identity"] == "fingerprint" and world.reads >= 2, "looked for the MAC a while"
    finally:
        tr.stop()


def test_a_provisional_network_takes_the_mac_that_arrives(db):
    world = World()
    events: List[Dict[str, Any]] = []
    tr = tracker(db, world)
    tr.add_listener(events.append)
    tr.start()
    try:
        prov = tr.current_network_id()
        world.neigh["192.168.1.1"] = (MAC_A, "reachable")
        assert tr.wait_idle(5.0)
        assert tr.current_network_id() == prov and db.get_network(prov)["mac"] == MAC_A, "attached to the row this start created"
        assert [e["late"] for e in events] == [False], "no merge: the id never changed after the start"
    finally:
        tr.stop()


def test_a_provisional_network_is_merged_into_the_router_that_answers(db):
    """At site B again (known by its router from an earlier visit), the router is not in the neighbour table yet: data is tagged
    with a provisional network until the MAC arrives, then moved to B; the provisional row is deleted; a write still queued under
    the provisional id lands on B."""
    world = World()
    fp = networks.fingerprint("192.168.1.1", "192.168.1.0/24", "192.168.1.1")
    b = db.add_network(T0 - DAY, mac=MAC_B, fingerprint=fp, gateway_ip="192.168.1.1", subnet="192.168.1.0/24", dhcp_server="192.168.1.1")
    tid = db.add_target("198.51.100.10")["id"]
    db.upsert_ping_minute(tid, minute(T0 - DAY), 60, 60, 9.0, 8.0, 10.0, 0.5, b["id"])
    db.add_report("Harbor View", "harbor view", T0 - DAY, T0 - DAY + 90, "complete", "x", {}, {}, network_id=b["id"])
    events: List[Dict[str, Any]] = []
    tr = tracker(db, world, mac_wait_s=5.0)
    tr.add_listener(events.append)
    try:
        tr.on_network_change({"ts": T0, "default_gateway": "192.168.1.1"})
        prov = tr.current_network_id()
        assert prov != b["id"] and db.get_network(prov)["mac"] is None
        m = minute(T0 + 30)
        db.upsert_ping_minute(tid, m, 30, 30, 10.0, 9.0, 11.0, 0.5, prov)
        db.upsert_ping_minute(tid, m, 20, 20, 30.0, 25.0, 35.0, 0.5, b["id"])       # (a part B wrote itself: merged, not overwritten)
        oid = db.open_outage("target", tid, T0 + 40, host="198.51.100.10", network_id=prov)
        sid = db.add_speedtest({"ts": T0 + 50, "ok": True, "backend": "fake", "download_mbps": 90.0, "network_id": prov})
        did = db.add_discovery_run({"ts": T0 + 55, "cidr": "192.168.1.0/24", "ports": [80], "network_id": prov}, [])
        world.neigh["192.168.1.1"] = (MAC_B, "reachable")
        assert tr.wait_idle(8.0)
        assert tr.current_network_id() == b["id"] and tr.current()["identity"] == "mac"
        assert db.get_network(prov) is None, "the provisional row is deleted once nothing references it"
        assert rows(db, "SELECT network_id, sent, received, ROUND(avg_ms, 2) FROM ping_minutes WHERE minute_ts=?", m) == [(b["id"], 50, 50, 18.0)]
        assert db.get_outage(oid)["network_id"] == b["id"]
        assert rows(db, "SELECT network_id FROM speedtests WHERE id=?", sid) == [(b["id"],)]
        assert rows(db, "SELECT network_id FROM discovery_runs WHERE id=?", did) == [(b["id"],)]
        assert events == [{"old_id": None, "new_id": prov, "ts": T0, "late": False, "reason": "network change"},
                          {"old_id": prov, "new_id": b["id"], "ts": T0, "late": True, "reason": "router identified"}]
        db.upsert_ping_minute(tid, m, 10, 10, 18.0, 18.0, 18.0, 0.5, prov)       # queued under the provisional id before the merge
        assert rows(db, "SELECT network_id, sent FROM ping_minutes WHERE minute_ts=?", m) == [(b["id"], 60)]
        assert db.newest_report_on_network(b["id"])["site"] == "Harbor View"
    finally:
        tr.stop()


def test_offline_keeps_the_id_and_a_trip_to_another_network_is_travel(db):
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    clock = Clock()
    tr = tracker(db, world, clock)
    try:
        tr.start()
        a = tr.current_network_id()
        # Wi-Fi drops at the site and comes back: the id stays on A, the spell is A's own
        tr.on_network_change({"ts": T0 + 100, "default_gateway": None})
        assert tr.current_network_id() == a and tr.offline and db.open_offline_spell_row()["network_id"] == a
        tr.on_network_change({"ts": T0 + 160, "default_gateway": "192.168.1.1"})
        spell = db.offline_spells(a, 0, T0 + DAY)[0]
        assert (spell["start_ts"], spell["end_ts"], spell["next_network_id"]) == (T0 + 100, T0 + 160, a)
        # then carried to another site: offline on the way, a different network at the end
        tr.on_network_change({"ts": T0 + 1000, "default_gateway": None})
        tr.on_network_change({"ts": T0 + 1000, "default_gateway": None})         # a repeated event opens nothing more
        world.facts = World.site("10.20.30.1", "10.20.30.0/24", "10.20.30.1", "site-b.example", "Ethernet", 12)
        world.neigh = {"10.20.30.1": (MAC_B, "reachable")}
        tr.on_network_change({"ts": T0 + 2800, "default_gateway": "10.20.30.1"})
        b = tr.current_network_id()
        assert b != a and not tr.offline
        spells = db.offline_spells(a, 0, T0 + DAY)
        assert [(s["start_ts"], s["end_ts"], s["next_network_id"]) for s in spells] == [(T0 + 100, T0 + 160, a), (T0 + 1000, T0 + 2800, b)]
        from tnt import reports

        assert reports.travel_spans(spells) == [(T0 + 1000, T0 + 2800)], "only the trip to B is travel"
    finally:
        tr.stop()


def test_the_same_gateway_address_with_another_router_is_another_network(db):
    """Two consumer routers on 192.168.1.1/24 at two sites: the MAC tells them apart."""
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    events: List[Dict[str, Any]] = []
    tr = tracker(db, world)
    tr.add_listener(events.append)
    try:
        tr.start()
        a = tr.current_network_id()
        tr.on_network_change({"ts": T0 + 100, "default_gateway": None})
        world.neigh["192.168.1.1"] = (MAC_B, "reachable")
        tr.on_network_change({"ts": T0 + 900, "default_gateway": "192.168.1.1"})
        b = tr.current_network_id()
        assert b != a and db.get_network(b)["mac"] == MAC_B and db.get_network(a)["mac"] == MAC_A
        assert events[-1] == {"old_id": a, "new_id": b, "ts": T0 + 900, "late": False, "reason": "network change"}
    finally:
        tr.stop()


def test_a_network_kept_by_its_fingerprint_is_corrected_when_another_router_answers(db):
    """Back from a trip to a site that looks the same (gateway, subnet, DHCP server) but whose router is not in the table yet: the
    id stays on A until B's router answers; then what was tagged since the change moves to B, and the trip becomes travel."""
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    events: List[Dict[str, Any]] = []
    tr = tracker(db, world, mac_wait_s=5.0)
    tr.add_listener(events.append)
    tid = db.add_target("198.51.100.10")["id"]
    try:
        tr.start()
        a = tr.current_network_id()
        db.upsert_ping_minute(tid, minute(T0 + 60), 60, 60, 9.0, 8.0, 10.0, 0.5, tr.current_network_id())
        tr.on_network_change({"ts": T0 + 100, "default_gateway": None})
        world.neigh = {}
        tr.on_network_change({"ts": T0 + 400, "default_gateway": "192.168.1.1"})
        assert tr.current_network_id() == a, "kept: the same gateway, subnet and DHCP server"
        db.upsert_ping_minute(tid, minute(T0 + 460), 60, 60, 30.0, 25.0, 35.0, 0.5, tr.current_network_id())
        world.neigh["192.168.1.1"] = (MAC_B, "reachable")
        assert tr.wait_idle(8.0)
        b = tr.current_network_id()
        assert b != a and db.get_network(b)["mac"] == MAC_B and db.get_network(a) is not None, "A's row stays: it is a real network"
        assert rows(db, "SELECT minute_ts - ?, network_id FROM ping_minutes ORDER BY minute_ts", minute(T0)) == [(60, a), (420, b)]
        assert events[-1] == {"old_id": a, "new_id": b, "ts": T0 + 400, "late": True, "reason": "router identified"}
        spell = db.offline_spells(a, 0, T0 + DAY)[0]
        assert (spell["end_ts"], spell["next_network_id"]) == (T0 + 400, b), "the spell's next network follows the correction"
        # A is current again later: its own data is never moved to B by the alias the correction left
        tr.on_network_change({"ts": T0 + 5000, "default_gateway": None})
        world.neigh["192.168.1.1"] = (MAC_A, "reachable")
        tr.on_network_change({"ts": T0 + 9000, "default_gateway": "192.168.1.1"})
        assert tr.current_network_id() == a
        db.upsert_ping_minute(tid, minute(T0 + 9060), 60, 60, 9.0, 8.0, 10.0, 0.5, a)
        assert rows(db, "SELECT network_id FROM ping_minutes WHERE minute_ts=?", minute(T0 + 9060)) == [(a,)]
    finally:
        tr.stop()


def test_a_router_replaced_behind_the_same_address_is_noticed_by_the_heartbeat(db):
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    clock = Clock()
    tr = tracker(db, world, clock)
    tid = db.add_target("198.51.100.10")["id"]
    try:
        tr.start()
        a = tr.current_network_id()
        db.upsert_ping_minute(tid, minute(T0 + 60), 60, 60, 9.0, 8.0, 10.0, 0.5, a)
        world.neigh["192.168.1.1"] = (MAC_C, "stale")
        clock.t = T0 + 600
        tr.touch()
        assert tr.current_network_id() == a, "a stale entry proves nothing"
        assert db.get_network(a)["last_seen"] == T0 + 600
        world.neigh["192.168.1.1"] = (MAC_C, "reachable")
        clock.t = T0 + 700
        tr.touch()
        c = tr.current_network_id()
        assert c != a and db.get_network(c)["mac"] == MAC_C
        assert rows(db, "SELECT network_id FROM ping_minutes") == [(a,)], "nothing earlier is moved: the swap is dated now"
    finally:
        tr.stop()


def test_an_unconfirmed_mac_counts_once_seen_twice_apart(db):
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "stale")
    tr = tracker(db, world, confirm_s=0.3)
    try:
        tr.start()
        nid = tr.current_network_id()
        assert db.get_network(nid)["mac"] is None, "not at once"
        assert tr.wait_idle(5.0)
        assert db.get_network(nid)["mac"] == MAC_A
        # the arp -a fallback has no state at all: the same rule
        world2 = World()
        world2.facts = World.site("10.20.30.1", "10.20.30.0/24", "10.20.30.1")
        world2.neigh["10.20.30.1"] = (MAC_B, None)
        other = tracker(db, world2, confirm_s=0.2)
        other.start()
        assert other.wait_idle(5.0) and db.get_network(other.current_network_id())["mac"] == MAC_B
        other.stop()
    finally:
        tr.stop()


def test_virtual_router_macs_are_known_by_a_fingerprint_with_the_mac(db):
    vrrp = "00:00:5E:00:01:01"
    world = World()
    world.neigh["192.168.1.1"] = (vrrp, "reachable")
    tr = tracker(db, world)
    tr.start()
    one = db.get_network(tr.current_network_id())
    tr.stop()
    assert one["mac"] is None and one["fingerprint"] == networks.fingerprint("192.168.1.1", "192.168.1.0/24", "192.168.1.1", vrrp)
    world2 = World()
    world2.facts = World.site("172.16.40.254", "172.16.40.0/24", "172.16.40.10")
    world2.neigh["172.16.40.254"] = (vrrp, "reachable")
    tr2 = tracker(db, world2)
    tr2.start()
    try:
        assert tr2.current_network_id() != one["id"], "the same VRRP group at another site is another network"
    finally:
        tr2.stop()


def test_a_restart_without_a_network_keeps_the_last_id_and_opens_a_spell(db):
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    first = tracker(db, world)
    first.start()
    a = first.current_network_id()
    first.stop()
    world.facts = None
    again = tracker(db, world, Clock(T0 + 3600))
    again.start()
    try:
        assert again.previous_id == a and again.current_network_id() == a and again.offline
        spell = db.open_offline_spell_row()
        assert (spell["network_id"], spell["start_ts"], spell["end_ts"]) == (a, T0 + 3600, None)
    finally:
        again.stop()


def test_nothing_is_tracked_before_the_migration(db):
    db.networks_ready = False
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    tr = tracker(db, world)
    tr.start()
    tr.on_network_change({"ts": T0, "default_gateway": "192.168.1.1"})
    assert tr.current_network_id() is None and world.reads == 0 and tr.confirm() is None
    db.networks_ready = True


# --------------------------------------------------------------------------------------------- the database
#: the 1.10.0 tables whose shape the networks migration changes (as tnt/db.py 1.10.0 created them, ALTERed columns included)
OLD_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE targets (id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL UNIQUE COLLATE NOCASE, label TEXT,
    kind TEXT NOT NULL DEFAULT 'auto', enabled INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0, created_ts REAL NOT NULL);
CREATE TABLE ping_minutes (target_id INTEGER NOT NULL, minute_ts INTEGER NOT NULL, sent INTEGER NOT NULL, received INTEGER NOT NULL,
    avg_ms REAL, min_ms REAL, max_ms REAL, jitter_ms REAL, PRIMARY KEY (target_id, minute_ts)) WITHOUT ROWID;
CREATE INDEX ix_ping_minutes_ts ON ping_minutes(minute_ts);
CREATE TABLE outages (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, target_id INTEGER, start_ts REAL NOT NULL, end_ts REAL,
    missed INTEGER NOT NULL DEFAULT 0, note TEXT, host TEXT, sent INTEGER);
CREATE TABLE speedtests (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, ok INTEGER NOT NULL, backend TEXT NOT NULL, server TEXT,
    isp TEXT, external_ip TEXT, latency_ms REAL, jitter_ms REAL, download_mbps REAL, upload_mbps REAL, packet_loss_pct REAL,
    duration_s REAL, error TEXT, raw_json TEXT);
CREATE TABLE discovery_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, cidr TEXT NOT NULL, ports TEXT NOT NULL,
    method TEXT NOT NULL, duration_s REAL, scanned INTEGER, found INTEGER, ok INTEGER NOT NULL DEFAULT 1, error TEXT);
CREATE TABLE reports (id INTEGER PRIMARY KEY, site TEXT NOT NULL, site_key TEXT NOT NULL, created_ts REAL NOT NULL, completed_ts REAL,
    status TEXT NOT NULL, tnt_version TEXT, summary TEXT NOT NULL DEFAULT '{}', data TEXT NOT NULL DEFAULT '{}');
"""


def old_database(path: Path, minutes: int = 60_000, targets: int = 3) -> Dict[str, Any]:
    """A 1.10.0-shaped database with *minutes* minute rows over *targets* targets, outages, speed tests, a run and a report."""
    conn = sqlite3.connect(str(path), isolation_level=None)
    conn.executescript(OLD_SCHEMA)
    conn.execute("INSERT INTO meta VALUES('schema_version', '1')")
    per = minutes // targets
    base = minute(T0) - per * 60
    conn.execute("BEGIN")
    for t in range(1, targets + 1):
        conn.execute("INSERT INTO targets(id, host, kind, created_ts) VALUES(?, ?, 'internet', ?)", (t, f"198.51.100.{t}", T0))
        conn.executemany("INSERT INTO ping_minutes VALUES(?,?,?,?,?,?,?,?)",
                         ((t, base + i * 60, 60, 60 - (i % 7 == 0), 10.0 + (i % 13), 9.0, 20.0, 0.5) for i in range(per)))
    conn.execute("INSERT INTO outages(kind, target_id, start_ts, end_ts, missed, host, sent) VALUES('target', 1, ?, ?, 5, '198.51.100.1', 6)",
                 (T0 - 600, T0 - 590))
    conn.execute("INSERT INTO speedtests(ts, ok, backend, download_mbps) VALUES(?, 1, 'cloudflare', 88.0)", (T0 - 900,))
    conn.execute("INSERT INTO discovery_runs(ts, cidr, ports, method) VALUES(?, '192.168.1.0/24', '[80]', 'native')", (T0 - 800,))
    conn.execute("INSERT INTO reports(site, site_key, created_ts, status) VALUES('Harbor View', 'harbor view', ?, 'complete')", (T0 - 700,))
    conn.execute("COMMIT")
    sums = conn.execute("SELECT COUNT(*), TOTAL(sent), TOTAL(received), TOTAL(minute_ts), TOTAL(avg_ms) FROM ping_minutes").fetchone()
    conn.close()
    return {"sums": tuple(sums), "base": base}


def sums(db: Database) -> tuple:
    return tuple(db._conn.execute("SELECT COUNT(*), TOTAL(sent), TOTAL(received), TOTAL(minute_ts), TOTAL(avg_ms) FROM ping_minutes").fetchone())


def key_columns(db: Database, table: str = "ping_minutes") -> List[str]:
    return [r["name"] for r in sorted((r for r in db._conn.execute(f"PRAGMA table_info({table})").fetchall() if r["pk"]),
                                      key=lambda r: r["pk"])]


def test_a_1_10_0_database_is_rebuilt_once_with_every_row_and_a_safety_copy(tmp_path):
    path = tmp_path / "tnt.db"
    old = old_database(path)
    t0 = time.monotonic()
    d = Database(path)
    took = time.monotonic() - t0
    try:
        assert d.networks_ready and d.migration_info["rebuilt"] and d.migration_info["rows"] == 60_000
        assert took < 10.0, f"the rebuild of 60k rows took {took:.1f} s"
        assert sums(d) == old["sums"], "every row kept, unchanged"
        assert key_columns(d) == ["target_id", "minute_ts", "network_id"]
        assert rows(d, "SELECT DISTINCT network_id FROM ping_minutes") == [(0,)], "old rows are untagged"
        indexes = {r[1] for r in d._conn.execute("SELECT type, name FROM sqlite_master WHERE type='index'").fetchall()}
        assert {"ix_ping_minutes_ts", "ix_outages_network", "ix_speedtests_network", "ix_discovery_runs_network",
                "ix_reports_network", "ix_networks_fingerprint"} <= indexes
        for table in ("outages", "speedtests", "discovery_runs", "reports"):
            assert rows(d, f"SELECT network_id FROM {table}") == [(None,)], table
        assert not rows(d, "SELECT name FROM sqlite_master WHERE name='ping_minutes_new'")
        backup = Path(str(path) + tnt_db.NETWORKS_BACKUP_SUFFIX)
        assert backup.exists() and d.migration_info["backup"] == str(backup)
        check = sqlite3.connect(str(backup))
        assert check.execute("SELECT COUNT(*) FROM ping_minutes").fetchone()[0] == 60_000
        assert "network_id" not in [r[1] for r in check.execute("PRAGMA table_info(ping_minutes)")], "the copy is the 1.10.0 file"
        check.close()
        stamp = backup.stat().st_mtime_ns
        # the new key: a minute of another network is a second row, the upsert merges within one network
        m = old["base"]
        d.upsert_ping_minute(1, m, 10, 10, 30.0, 30.0, 30.0, 0.5, 5)
        d.upsert_ping_minute(1, m, 10, 9, 20.0, 18.0, 22.0, 0.5, 5)
        assert rows(d, "SELECT network_id, sent, received FROM ping_minutes WHERE target_id=1 AND minute_ts=? ORDER BY network_id", m) == \
            [(0, 60, 59), (5, 20, 19)]
    finally:
        d.close()
    again = Database(path)
    try:
        assert again.networks_ready and again.migration_info == {}, "nothing to do on the next open"
        assert Path(str(path) + tnt_db.NETWORKS_BACKUP_SUFFIX).stat().st_mtime_ns == stamp, "the copy is taken once"
    finally:
        again.close()


def test_a_failed_rebuild_leaves_the_database_working_and_the_next_start_tries_again(tmp_path, monkeypatch, caplog):
    path = tmp_path / "tnt.db"
    old = old_database(path, minutes=3000)

    def fail(self: Database, name: str) -> None:
        if name == "drop":
            raise sqlite3.OperationalError("disk I/O error (simulated)")

    monkeypatch.setattr(Database, "_migration_step", fail)
    with caplog.at_level("ERROR", logger="tnt.db"):
        d = Database(path)
    try:
        assert not d.networks_ready and "rebuilding ping_minutes for networks failed" in caplog.text
        assert key_columns(d) == ["target_id", "minute_ts"] and sums(d) == old["sums"], "rolled back: the old table, every row"
        assert not rows(d, "SELECT name FROM sqlite_master WHERE name='ping_minutes_new'")
        # everything still works the 1.10.0 way; network ids are simply not stored
        d.upsert_ping_minute(1, old["base"], 5, 5, 10.0, 10.0, 10.0, 0.5, 7)
        assert rows(d, "SELECT sent FROM ping_minutes WHERE target_id=1 AND minute_ts=?", old["base"]) == [(65,)]
        oid = d.open_outage("gap", None, T0, note="not monitoring", network_id=7)
        assert d.get_outage(oid)["network_id"] is None
        d.add_speedtest({"ts": T0, "ok": True, "backend": "fake", "network_id": 7})
        rid = d.add_report("Harbor View", "harbor view", T0, T0 + 5, "complete", "x", {}, {}, network_id=7)
        assert d.get_report(rid)["network_id"] is None and d.newest_report_on_network(7) is None
        assert d.report_sites()[0][0]["network_ids"] == [] and len(d.ping_minute_rows(1, 0, 4e9, network_id=7, legacy_since=0)) == 1000
        assert d.retag_network(1, 2, T0) == {"deleted": False} and d.open_offline_spell(1, T0) is None
    finally:
        d.close()
    monkeypatch.undo()
    fixed = Database(path)
    try:
        assert fixed.networks_ready and key_columns(fixed) == ["target_id", "minute_ts", "network_id"]
        assert sums(fixed)[0] == 3000
    finally:
        fixed.close()


def test_the_rebuild_waits_for_disk_space(tmp_path, monkeypatch, caplog):
    path = tmp_path / "tnt.db"
    old_database(path, minutes=3000)
    monkeypatch.setattr(tnt_db.shutil, "disk_usage", lambda p: SimpleNamespace(total=10**9, used=10**9 - 1000, free=1000))
    with caplog.at_level("ERROR", logger="tnt.db"):
        d = Database(path)
    try:
        assert not d.networks_ready and "free next to the database" in caplog.text
        assert not Path(str(path) + tnt_db.NETWORKS_BACKUP_SUFFIX).exists()
    finally:
        d.close()


def test_a_new_database_is_created_tagged(tmp_path):
    d = Database(tmp_path / "fresh.db")
    try:
        assert d.networks_ready and d.migration_info == {} and key_columns(d) == ["target_id", "minute_ts", "network_id"]
        assert not Path(str(tmp_path / "fresh.db") + tnt_db.NETWORKS_BACKUP_SUFFIX).exists()
        assert {"networks", "network_offline"} <= set(d.counts())
    finally:
        d.close()


def test_split_minutes_read_as_one_minute_and_filters_by_network(db):
    tid = db.add_target("198.51.100.10")["id"]
    m = minute(T0)
    db.upsert_ping_minute(tid, m - 120, 60, 60, 5.0, 4.0, 6.0, 0.2)                 # untagged, before
    db.upsert_ping_minute(tid, m, 40, 40, 10.0, 9.0, 12.0, 1.0, 1)                  # the first 40 s on network 1
    db.upsert_ping_minute(tid, m, 20, 19, 40.0, 30.0, 55.0, 3.0, 2)                 # the rest on network 2
    hist = db.ping_minutes(tid, m, m + 60)
    assert len(hist) == 1 and (hist[0]["sent"], hist[0]["received"], hist[0]["min_ms"], hist[0]["max_ms"]) == (60, 59, 9.0, 55.0)
    assert hist[0]["avg_ms"] == pytest.approx((10.0 * 40 + 40.0 * 19) / 59) and set(hist[0]) == {
        "target_id", "minute_ts", "sent", "received", "avg_ms", "min_ms", "max_ms", "jitter_ms"}
    assert hist[0]["jitter_ms"] == pytest.approx((1.0 * 39 + 3.0 * 18) / 57)
    assert db.ping_minutes(tid, m - 120, m - 60)[0]["avg_ms"] == 5.0, "a whole minute reads as stored"
    assert db.ping_summary(tid, m - 200, m + 60)["sent"] == 120
    assert [r[0] for r in db.ping_minute_rows(tid, 0, 4e9, network_id=1)] == [40]
    assert [r[0] for r in db.ping_minute_rows(tid, 0, 4e9, network_id=2, legacy_since=m - 120)] == [60, 20]
    assert db.ping_minute_rows(tid, 0, 4e9, network_id=1, exclude=[(m + 10, m + 30)]) == [], "a minute overlapping a trip is left out"
    assert db.ping_target_ids(0, 4e9, network_id=3) == [] and db.ping_activity_minutes(0, 4e9, network_id=2, legacy_since=0) == [m - 120, m]


def test_speed_tests_are_stored_with_the_network_they_started_on(data_dir, monkeypatch):
    from tnt import config as tnt_config
    from tnt import events as tnt_events
    from tnt.speedtest import scheduler as sched_mod
    from tnt.speedtest.base import SpeedResult

    current = {"id": 3}

    class Backend:
        name = "fake"

        def available(self, config: Any) -> Tuple[bool, str]:
            return True, "fake"

        def run(self, config: Any, progress: Any = None, cancel: Any = None) -> SpeedResult:
            current["id"] = 4                       # the PC moved during the test: the row keeps the network it started on
            return SpeedResult(ok=True, ts=time.time(), backend="fake", download_mbps=50.0, upload_mbps=10.0, latency_ms=12.0,
                               duration_s=1.0)

    monkeypatch.setattr(sched_mod, "select_backend", lambda c: Backend())
    d = Database(data_dir / "tnt.db")
    bus = tnt_events.EventBus()
    seen: List[Dict[str, Any]] = []
    bus.subscribe(seen.append)
    sched = sched_mod.SpeedScheduler(d, tnt_config.Config(data_dir / "config.json").load(), bus, network_fn=lambda: current["id"])
    try:
        assert sched.run_now() is True
        deadline = time.time() + 10
        while time.time() < deadline and not any(e["type"] == "speedtest.done" for e in seen):
            time.sleep(0.02)
        done = next(e for e in seen if e["type"] == "speedtest.done")
        assert "network_id" not in done["data"]["result"], "the published result is unchanged"
        assert rows(d, "SELECT network_id, download_mbps FROM speedtests") == [(3, 50.0)]
        assert d.list_speedtests(0, time.time() + 10, network_id=4) == [] and len(d.list_speedtests(0, time.time() + 10, network_id=3)) == 1
    finally:
        sched.stop()
        d.close()


# --------------------------------------------------------------------------------------------- engine wiring
def test_engine_starts_the_tracker_first_and_tags_what_the_writers_store(data_dir, monkeypatch):
    from tnt import engine as engine_mod
    from tnt.engine import Engine

    eng = Engine(console=True, port=0, data_dir=data_dir)
    eng._start_networks()
    assert eng.networks is None and eng.errors["networks"] == "database unavailable"
    eng.errors.clear()
    eng.db = Database(data_dir / "tnt.db")
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    real = networks.NetworkTracker

    class Faked(real):  # type: ignore[misc, valid-type]
        def __init__(self, db: Any, **kw: Any) -> None:
            super().__init__(db, facts_fn=world.facts_fn, neighbour_fn=world.neighbour_fn, touch_every_s=0.0, **kw)

    monkeypatch.setattr(networks, "NetworkTracker", Faked)
    try:
        eng._start_networks()
        nid = eng.networks.current_network_id()
        assert nid is not None and "networks" not in eng.errors and eng._network_id() == nid
        # net.changed: the tracker hears it before the ping manager (whose samples are tagged with what it decided)
        order: List[str] = []
        eng.networks.on_network_change = lambda data: order.append("networks")
        eng.ping = SimpleNamespace(on_network_change=lambda data: order.append("ping"))
        eng._on_net_changed({"generation": 1, "ts": T0, "summary": "Wi-Fi: 192.168.1.23/24 · gateway 192.168.1.1"})
        assert order == ["networks", "ping"]
        eng.ping = None
        # the heartbeat refreshes last_seen
        later = time.time() + 3600
        eng._heartbeat(later)
        assert eng.db.get_network(nid)["last_seen"] == later
        # a Discovery run is stored with the network it started on
        done = threading.Event()
        eng.bus = SimpleNamespace(publish=lambda t, d, ts=None: done.set() if t == "discovery.done" else None)
        from tnt import config as tnt_config

        eng.config = tnt_config.Config(data_dir / "config.json").load()

        class Scanner:
            def default_cidr(self) -> str:
                return "192.168.1.0/24"

            def parse_range(self, text: str) -> str:
                return text

            def scan(self, range_text: str, ports: Any = None, progress: Any = None, cancel: Any = None) -> Any:
                eng.networks._id = 999                   # the network changed during the scan: the run keeps its start's
                return {"ts": T0, "cidr": range_text, "ports": list(ports or []), "method": "native", "hosts": [], "scanned": 254,
                        "duration_s": 1.0, "ok": True, "error": None, "cancelled": False}

        eng.discovery = Scanner()
        assert eng.discovery_start(None, [80]) is True and done.wait(5.0)
        assert rows(eng.db, "SELECT network_id FROM discovery_runs") == [(nid,)]
    finally:
        if eng.networks is not None:
            eng.networks.stop()
        eng.db.close()
    assert engine_mod is not None


# --------------------------------------------------------------------------------------------- resolution: the review round
def known(db: Database, mac: str, gateway: str = "10.0.0.1", subnet: str = "10.0.0.0/24", dhcp: Optional[str] = "10.0.0.1") -> Dict[str, Any]:
    """A network of an earlier visit, known by its router's MAC."""
    return db.add_network(T0 - DAY, mac=mac, fingerprint=networks.fingerprint(gateway, subnet, dhcp), gateway_ip=gateway, subnet=subnet,
                          dhcp_server=dhcp)


def test_a_second_event_that_finds_the_router_merges_the_provisional_network(db):
    """Joining B: the gateway is up but its router is not in the neighbour table yet (provisional P); a second net.changed seconds later
    (an IPv6 prefix, the DNS servers) finds the router reachable: P is merged into B from its change and deleted, a late event, and the
    outage whose first miss was sent just before the change moves with it."""
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    b = known(db, MAC_B)
    tid = db.add_target("198.51.100.10")["id"]
    events: List[Dict[str, Any]] = []
    clock = Clock()
    tr = tracker(db, world, clock)
    tr.add_listener(events.append)
    try:
        tr.start()
        world.facts, world.neigh = World.site("10.0.0.1", "10.0.0.0/24", "10.0.0.1"), {}
        clock.t = T0 + 100
        tr.on_network_change({"ts": T0 + 100, "default_gateway": "10.0.0.1"})
        p = tr.current_network_id()
        db.upsert_ping_minute(tid, minute(T0 + 101), 3, 1, 5.0, 4.0, 6.0, 0.2, p)
        oid = db.open_outage("target", tid, T0 + 99.4, host="198.51.100.10", network_id=p)
        world.neigh = {"10.0.0.1": (MAC_B, "reachable")}
        clock.t = T0 + 104
        tr.on_network_change({"ts": T0 + 104, "default_gateway": "10.0.0.1"})
        assert tr.wait_idle(5.0) and tr.current_network_id() == b["id"] and db.get_network(p) is None
        assert rows(db, "SELECT network_id, sent FROM ping_minutes") == [(b["id"], 3)] and db.get_outage(oid)["network_id"] == b["id"]
        assert events[-1] == {"old_id": p, "new_id": b["id"], "ts": T0 + 100, "late": True, "reason": "router identified"}
    finally:
        tr.stop()


def test_a_link_flap_inside_the_mac_wait_is_the_same_connection(db):
    """Joining B provisionally, the link drops six seconds later and is back thirty seconds after with the router answering: the flap
    was at B, so the provisional network is merged into B from its change and the offline spell is B's own (not travel)."""
    from tnt import reports

    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    b = known(db, MAC_B)
    tr = tracker(db, world)
    try:
        tr.start()
        world.facts, world.neigh = World.site("10.0.0.1", "10.0.0.0/24", "10.0.0.1"), {}
        tr.on_network_change({"ts": T0 + 100, "default_gateway": "10.0.0.1"})
        p = tr.current_network_id()
        world.facts = None
        tr.on_network_change({"ts": T0 + 106, "default_gateway": None})
        assert tr.current_network_id() == p and tr.offline
        oid = db.open_outage("total_internet", None, T0 + 106, network_id=p)
        db.close_outage(oid, T0 + 136, 30)
        world.facts, world.neigh = World.site("10.0.0.1", "10.0.0.0/24", "10.0.0.1"), {"10.0.0.1": (MAC_B, "reachable")}
        tr.on_network_change({"ts": T0 + 136, "default_gateway": "10.0.0.1"})
        assert tr.wait_idle(5.0) and tr.current_network_id() == b["id"] and db.get_network(p) is None
        spells = db.offline_spells(b["id"], 0, T0 + DAY)
        assert [(s["start_ts"], s["end_ts"], s["next_network_id"]) for s in spells] == [(T0 + 106, T0 + 136, b["id"])]
        assert reports.travel_spans(spells) == [] and db.get_outage(oid)["network_id"] == b["id"]
    finally:
        tr.stop()


def test_a_return_after_the_flap_window_is_a_new_connection(tmp_path):
    """The same drop, but back only after ``flap_s``: the provisional network keeps what it had (a fingerprint network of its own), the
    router read now names a new connection, and the spell between the two reads as travel."""
    from tnt import reports

    d = Database(tmp_path / "flap.db")
    world = World()
    world.facts, world.neigh = World.site("10.0.0.1", "10.0.0.0/24", "10.0.0.1"), {}
    b = known(d, MAC_B)
    tr = tracker(d, world, flap_s=0.0)
    try:
        tr.start()
        p = tr.current_network_id()
        world.facts = None
        tr.on_network_change({"ts": T0 + 6, "default_gateway": None})
        time.sleep(0.05)
        world.facts, world.neigh = World.site("10.0.0.1", "10.0.0.0/24", "10.0.0.1"), {"10.0.0.1": (MAC_B, "reachable")}
        tr.on_network_change({"ts": T0 + 600, "default_gateway": "10.0.0.1"})
        assert tr.wait_idle(5.0) and tr.current_network_id() == b["id"] and d.get_network(p) is not None
        assert reports.travel_spans(d.offline_spells(p, 0, T0 + DAY)) == [(T0 + 6, T0 + 600)]
    finally:
        tr.stop()
        d.close()


def test_a_merge_moves_every_row_of_a_network_the_change_created_whatever_its_time(db):
    """Rows tagged with a provisional network can carry times before its change: a wall clock put back during the MAC wait, an echo sent
    just before the switch (its minute), a minute written after the merge.  A network the change created is merged whole and deleted, and
    no row keeps its id; a network that existed before moves only what is dated from RETAG_SLACK_S before the change."""
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    b = known(db, MAC_B)
    tid = db.add_target("198.51.100.10")["id"]
    tr = tracker(db, world)
    try:
        tr.start()
        world.facts, world.neigh = World.site("10.0.0.1", "10.0.0.0/24", "10.0.0.1"), {}
        tr.on_network_change({"ts": T0 + 100, "default_gateway": "10.0.0.1"})
        p = tr.current_network_id()
        db.upsert_ping_minute(tid, minute(T0 - 200), 10, 10, 5.0, 4.0, 6.0, 0.2, p)      # the clock was put back five minutes
        db.upsert_ping_minute(tid, minute(T0 + 30), 1, 0, None, None, None, None, p)      # an echo of the minute before the change
        world.neigh = {"10.0.0.1": (MAC_B, "reachable")}
        assert tr.wait_idle(5.0) and tr.current_network_id() == b["id"] and db.get_network(p) is None
        assert rows(db, "SELECT network_id, COUNT(*) FROM ping_minutes GROUP BY network_id") == [(b["id"], 2)]
        db.upsert_ping_minute(tid, minute(T0 - 3000), 1, 1, 5.0, 5.0, 5.0, 0.2, p)        # still queued under P, dated long before
        assert rows(db, "SELECT COUNT(*) FROM ping_minutes WHERE network_id NOT IN (SELECT id FROM networks)") == [(0,)]
    finally:
        tr.stop()
    c = db.add_network(T0, fingerprint="c" * 32)["id"]
    d = db.add_network(T0, mac=MAC_C, fingerprint="d" * 32)["id"]
    db.upsert_ping_minute(tid, minute(T0 + 5000), 5, 5, 5.0, 5.0, 5.0, 0.2, c)
    early = db.open_outage("target", tid, T0 + 8000 - tnt_db.RETAG_SLACK_S - 1, network_id=c)
    late = db.open_outage("target", tid, T0 + 8000 - tnt_db.RETAG_SLACK_S + 1, network_id=c)
    assert db.retag_network(c, d, T0 + 8000)["deleted"] is False
    assert (db.get_outage(early)["network_id"], db.get_outage(late)["network_id"]) == (c, d)
    assert rows(db, "SELECT network_id FROM ping_minutes WHERE minute_ts=?", minute(T0 + 5000)) == [(c,)], "its earlier visit stays"


def test_the_same_router_on_another_adapter_is_the_same_network_with_no_event(db):
    """Docked: an Ethernet adapter with a static address on the same LAN becomes the internet adapter (no DHCP server: another
    fingerprint) before the router is in its neighbour table; undocked: Wi-Fi again, the router's entry stale.  The same router all
    along: no id change (it would close every open outage), and the network keeps the fingerprint its router was confirmed on."""
    world = World()
    world.facts = World.site("10.0.0.1", "10.0.0.0/24", "10.0.0.1", nic="Wi-Fi", index=7)
    world.neigh = {"10.0.0.1": (MAC_A, "reachable")}
    events: List[Dict[str, Any]] = []
    tr = tracker(db, world, mac_wait_s=1.0)
    tr.add_listener(events.append)
    try:
        tr.start()
        a = tr.current_network_id()
        fp = db.get_network(a)["fingerprint"]
        world.facts, world.neigh = World.site("10.0.0.1", "10.0.0.0/24", None, nic="Ethernet", index=12), {}
        tr.on_network_change({"ts": T0 + 200, "default_gateway": "10.0.0.1"})
        world.neigh = {"10.0.0.1": (MAC_A, "reachable")}
        assert tr.wait_idle(5.0) and tr.current_network_id() == a
        world.facts, world.neigh = World.site("10.0.0.1", "10.0.0.0/24", "10.0.0.1", nic="Wi-Fi", index=7), {"10.0.0.1": (MAC_A, "stale")}
        tr.on_network_change({"ts": T0 + 900, "default_gateway": "10.0.0.1"})
        assert tr.wait_idle(5.0) and tr.current_network_id() == a
        assert [e["new_id"] for e in events] == [a] and len(db.list_networks()) == 1
        assert (db.get_network(a)["fingerprint"], db.get_network(a)["nic"]) == (fp, "Wi-Fi")
    finally:
        tr.stop()


def test_a_start_on_another_network_makes_the_stopped_time_travel(db):
    """Shut down at A, started at B with the network already up: the time since the last heartbeat is a spell of A that ended on B, so
    A's report leaves the stale gap out as travel.  Started without a network, the spell starts at the last heartbeat; started on the
    same network again, that spell is its own."""
    from tnt import outages, reports

    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    first = tracker(db, world, Clock())
    first.start()
    a = first.current_network_id()
    first.stop()
    db.set_meta("last_heartbeat", repr(T0 + 600))
    world.facts, world.neigh = World.site("10.20.30.1", "10.20.30.0/24", "10.20.30.1"), {"10.20.30.1": (MAC_B, "reachable")}
    at_b = tracker(db, world, Clock(T0 + 50_000))
    at_b.start()
    b = at_b.current_network_id()
    at_b.stop()
    spells = db.offline_spells(a, 0, T0 + DAY)
    assert b != a and [(s["start_ts"], s["end_ts"], s["next_network_id"]) for s in spells] == [(T0 + 600, T0 + 50_000, b)]
    assert reports.travel_spans(spells) == [(T0 + 600, T0 + 50_000)]
    info = outages.close_stale_outages(db, T0 + 50_000, network_id=at_b.previous_id)
    assert reports.scope_outage_rows([db.get_outage(info["gap_id"])], a, None, reports.travel_spans(spells)) == []
    db.set_meta("last_heartbeat", repr(T0 + 60_000))
    world.facts = None
    offline = tracker(db, world, Clock(T0 + 70_000))
    offline.start()
    assert db.open_offline_spell_row()["start_ts"] == T0 + 60_000 and offline.current_network_id() == b
    offline.stop()
    world.facts, world.neigh = World.site("10.20.30.1", "10.20.30.0/24", "10.20.30.1"), {"10.20.30.1": (MAC_B, "reachable")}
    again = tracker(db, world, Clock(T0 + 80_000))
    again.start()
    again.stop()
    assert [(s["start_ts"], s["end_ts"], s["next_network_id"]) for s in db.offline_spells(b, 0, T0 + DAY)] == [(T0 + 60_000, T0 + 80_000, b)]


def test_time_on_a_network_without_a_gateway_is_travel_even_back_on_the_same_network(db):
    """Off A's LAN onto a camera bench (a static address, no gateway), or TNT's DHCP server re-addressing the adapter, then back on A:
    that spell is travel for A (the pings failing meanwhile were not done from A's network).  A gateway-less network this PC already had
    when it went offline (a second adapter), or A's own subnet without a gateway, is not."""
    from tnt import reports

    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    lans: List[str] = ["172.16.99.0/24"]
    tr = networks.NetworkTracker(db, clock=Clock(), facts_fn=world.facts_fn, neighbour_fn=world.neighbour_fn, lans_fn=lambda: list(lans),
                                 mac_wait_s=1.0, mac_poll_s=0.02, confirm_s=0.1, touch_every_s=0.0)
    try:
        tr.start()
        a = tr.current_network_id()
        tr.on_network_change({"ts": T0 + 100, "default_gateway": None})
        lans.append("192.168.1.0/24")
        tr.on_network_change({"ts": T0 + 110, "default_gateway": None})
        tr.on_network_change({"ts": T0 + 160, "default_gateway": "192.168.1.1"})
        lans[:] = ["172.16.99.0/24"]
        tr.on_network_change({"ts": T0 + 1000, "default_gateway": None})
        lans.append("192.0.2.0/24")
        tr.on_network_change({"ts": T0 + 1100, "default_gateway": None})
        assert tr.current_network_id() == a
        tr.on_network_change({"ts": T0 + 4000, "default_gateway": "192.168.1.1"})
        lans[:] = ["172.16.99.0/24"]
        tr.on_network_change({"ts": T0 + 5000, "default_gateway": None, "cause": "dhcp"})
        tr.on_network_change({"ts": T0 + 6000, "default_gateway": "192.168.1.1"})
        spells = db.offline_spells(a, 0, T0 + DAY)
        assert [(s["start_ts"], s["end_ts"], s["next_network_id"], s["reason"]) for s in spells] == [
            (T0 + 100, T0 + 160, a, None), (T0 + 1000, T0 + 4000, a, "lan"), (T0 + 5000, T0 + 6000, a, "lan")]
        assert reports.travel_spans(spells) == [(T0 + 1000, T0 + 4000), (T0 + 5000, T0 + 6000)]
    finally:
        tr.stop()


def test_offline_the_tracker_confirms_no_network_for_a_full_scan(db):
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    tr = tracker(db, world)
    try:
        tr.start()
        a = tr.current_network_id()
        assert tr.confirm() == a and tr.current()["offline"] is False and tr.connected_since(a) == T0 and tr.connected_since(a + 1) is None
        tr.on_network_change({"ts": T0 + 100, "default_gateway": None})
        assert tr.current_network_id() == a, "the data stays tagged with the last network"
        assert tr.confirm() is None and tr.current()["offline"] is True and tr.connected_since(a) is None
    finally:
        tr.stop()


def test_a_stale_entry_of_the_last_router_does_not_hold_the_next_site_behind_the_same_address(db):
    """Sites A and B both 192.168.1.1/24 with DHCP on the router.  Arriving at B the neighbour table still holds A's router as a stale
    entry for longer than confirm_s: that proves nothing, so the MAC wait does not settle on A; when B's router answers (here only after
    the wait, at the heartbeat) the data since the arrival moves to B and the drive from A becomes travel."""
    from tnt import reports

    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    tid = db.add_target("198.51.100.10")["id"]
    clock = Clock()
    tr = tracker(db, world, clock, mac_wait_s=0.5)
    try:
        tr.start()
        a = tr.current_network_id()
        tr.on_network_change({"ts": T0 + 100, "default_gateway": None})
        world.neigh["192.168.1.1"] = (MAC_A, "stale")
        clock.t = T0 + 3000
        tr.on_network_change({"ts": T0 + 3000, "default_gateway": "192.168.1.1"})
        assert tr.wait_idle(5.0) and tr.current_network_id() == a, "kept by its address for now"
        db.upsert_ping_minute(tid, minute(T0 + 3030), 30, 30, 20.0, 18.0, 25.0, 0.4, a)
        world.neigh["192.168.1.1"] = (MAC_B, "reachable")
        clock.t = T0 + 3200
        tr.touch()
        b = tr.current_network_id()
        assert b != a and db.get_network(b)["mac"] == MAC_B
        assert rows(db, "SELECT network_id FROM ping_minutes") == [(b,)], "the data since the arrival is B's"
        assert reports.travel_spans(db.offline_spells(a, 0, T0 + DAY)) == [(T0 + 100, T0 + 3000)]
    finally:
        tr.stop()


def test_a_router_mac_that_answers_after_the_wait_still_names_the_network(db):
    """The router's MAC was not readable during the MAC wait (a slow neighbour table after resume): the network stays known by its
    fingerprint until the heartbeat (or a Full Scan's look) reads it: the row this connection created takes the MAC, or, when the router
    is a known network's, everything tagged with the provisional network moves there and the provisional row goes."""
    world = World()
    tr = tracker(db, world, mac_wait_s=0.2)
    try:
        tr.start()
        nid = tr.current_network_id()
        assert tr.wait_idle(3.0) and db.get_network(nid)["mac"] is None
        world.neigh["192.168.1.1"] = (MAC_A, "reachable")
        tr.touch()
        assert tr.current_network_id() == nid and db.get_network(nid)["mac"] == MAC_A
    finally:
        tr.stop()
    b = known(db, MAC_B)
    world2 = World()
    world2.facts = World.site("10.0.0.1", "10.0.0.0/24", "10.0.0.1")
    tid = db.add_target("198.51.100.10")["id"]
    tr2 = tracker(db, world2, mac_wait_s=0.2)
    try:
        tr2.start()
        p = tr2.current_network_id()
        assert p != b["id"] and tr2.wait_idle(3.0)
        db.upsert_ping_minute(tid, minute(T0 + 60), 60, 60, 9.0, 8.0, 10.0, 0.5, p)
        world2.neigh["10.0.0.1"] = (MAC_B, "reachable")
        assert tr2.confirm() == b["id"] and db.get_network(p) is None
        assert rows(db, "SELECT network_id FROM ping_minutes") == [(b["id"],)]
    finally:
        tr2.stop()


def test_ha_firewall_macs_hotspots_and_the_site_adapter_under_a_vpn():
    for mac in ("00:09:0F:09:00:02", "00:1B:17:00:01:10", "00:10:DB:FF:10:01"):
        assert networks.is_virtual_router_mac(mac), mac
    assert not networks.is_virtual_router_mac("00:09:0F:0A:00:02")
    assert networks.is_locally_administered(MAC_A) and not networks.is_locally_administered("00:00:5E:00:53:01")
    assert not networks.is_locally_administered(None)
    assert networks.looks_like_hotspot({"gateway_ip": "172.20.10.1", "subnet": "172.20.10.0/28"})
    assert not networks.looks_like_hotspot({"gateway_ip": "172.20.10.1", "subnet": "172.20.0.0/16"}) and not networks.looks_like_hotspot(None)

    def v4(address: str, network: str) -> Any:
        return SimpleNamespace(address=address, network=network, preferred=True)

    vpn = SimpleNamespace(index=30, name="Example VPN", is_up=True, is_physical=False, gateways=["10.99.0.1"],
                          ipv4=[v4("10.99.0.2", "10.99.0.0/24")], ipv6=[], dhcp_server="10.99.0.1", dns_suffix="vpn.example", metric_v4=1)
    wifi = SimpleNamespace(index=7, name="Wi-Fi", is_up=True, is_physical=True, gateways=["192.168.1.1"],
                           ipv4=[v4("192.168.1.23", "192.168.1.0/24")], ipv6=[], dhcp_server="192.168.1.1", dns_suffix="site-a.example", metric_v4=35)
    bench = SimpleNamespace(index=12, name="Ethernet", is_up=True, is_physical=True, gateways=[],
                            ipv4=[v4("172.16.4.100", "172.16.4.0/24"), v4("169.254.3.4", "169.254.0.0/16")], ipv6=[], metric_v4=5)
    hyperv = SimpleNamespace(index=40, name="vEthernet (Default Switch)", is_up=True, is_physical=False, gateways=[],
                             ipv4=[v4("172.30.0.1", "172.30.0.0/20")], ipv6=[], metric_v4=5000)
    assert networks.site_gateway([vpn, wifi], vpn) == ("192.168.1.1", 7), "the network the tunnel runs over, not the tunnel's gateway"
    assert networks.site_gateway([vpn, wifi], wifi) == ("192.168.1.1", 7)
    assert networks.site_gateway([vpn], vpn) == ("10.99.0.1", 30), "no physical adapter with a gateway: the tunnel's"
    assert networks.site_gateway([], None) == (None, None)
    facts = networks.gateway_facts([vpn, wifi], *networks.site_gateway([vpn, wifi], vpn))
    assert (facts["gateway_ip"], facts["nic"], facts["dhcp_server"]) == ("192.168.1.1", "Wi-Fi", "192.168.1.1")
    assert networks.gatewayless_networks([vpn, wifi, bench, hyperv]) == ["172.16.4.0/24"], "physical, no gateway, not APIPA"


def test_a_phone_hotspot_is_portable_and_any_network_can_be_marked_so(db):
    world = World()
    world.facts = World.site("172.20.10.1", "172.20.10.0/28", "172.20.10.1")
    world.neigh["172.20.10.1"] = (MAC_C, "reachable")
    tr = tracker(db, world)
    try:
        tr.start()
        hotspot = tr.current()
        assert hotspot["portable"] is True and db.get_network(hotspot["id"])["portable"] == 1
        assert tr.set_portable(hotspot["id"], False)["portable"] is False and tr.current()["portable"] is False
        assert tr.set_portable(999, True) is None
    finally:
        tr.stop()


def test_reports_saved_before_networks_are_tagged_with_the_router_their_discovery_found(db):
    """A 1.10.0 report has no network id, but its Discovery run found the gateway's MAC: when that router's network gets a row, the
    report is tagged with it (a Full Scan there suggests its site); a report behind another router, or with unreadable data, is not."""
    def data(mac: str) -> Dict[str, Any]:
        return {"network": {"internet_nic": {"gateway": "192.168.1.1"}}, "discovery": {"hosts": [{"ip": "192.168.1.9", "mac": MAC_C},
                                                                                                  {"ip": "192.168.1.1", "mac": mac}]}}

    old = db.add_report("Harbor View", "harbor view", T0 - DAY, T0 - DAY + 90, "complete", "1.10.0", {}, data(MAC_A.replace(":", "-").lower()))
    other = db.add_report("Northside Warehouse", "northside warehouse", T0 - DAY, T0 - DAY + 90, "complete", "1.10.0", {}, data(MAC_B))
    broken = db.add_report("Broken", "broken", T0, T0, "partial", "1.10.0", {}, {})
    db._conn.execute("UPDATE reports SET data='not json' WHERE id=?", (broken,))
    world = World()
    world.neigh["192.168.1.1"] = (MAC_A, "reachable")
    tr = tracker(db, world)
    try:
        tr.start()
        a = tr.current_network_id()
        assert [db.get_report(r)["network_id"] for r in (old, other, broken)] == [a, None, None]
        assert db.newest_report_on_network(a)["site"] == "Harbor View"
    finally:
        tr.stop()


def test_the_newest_report_of_a_network_can_skip_unnamed_ones(db):
    nid = db.add_network(T0, mac=MAC_A, fingerprint="a" * 32)["id"]
    named = db.add_report("Harbor View", "harbor view", T0, T0 + 90, "complete", "x", {}, {}, network_id=nid)
    db.add_report("Unnamed site", "unnamed site", T0 + 100, T0 + 190, "complete", "x", {}, {}, network_id=nid)
    assert db.newest_report_on_network(nid)["site"] == "Unnamed site"
    assert db.newest_report_on_network(nid, "unnamed site")["id"] == named


def test_the_migration_does_not_wait_for_a_reader_holding_a_snapshot(tmp_path):
    """Another program reading the file (a database browser, a backup tool) keeps a read transaction open: the migration's WAL
    checkpoints give up after a second instead of the 30 s busy timeout, and every row is still there."""
    path = tmp_path / "tnt.db"
    old_database(path, minutes=30_000)
    reader = sqlite3.connect(str(path), isolation_level=None)
    reader.execute("PRAGMA journal_mode=WAL")
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM ping_minutes").fetchone()
    t0 = time.monotonic()
    d = Database(path)
    took = time.monotonic() - t0
    try:
        assert d.networks_ready and d.migration_info["rebuilt"] and sums(d)[0] == 30_000
        assert took < 10.0, f"the migration waited {took:.1f} s for the reader"
        assert d._conn.execute("PRAGMA busy_timeout").fetchone()[0] == 30000, "the normal busy timeout is back"
    finally:
        reader.execute("ROLLBACK")
        reader.close()
        d.close()
