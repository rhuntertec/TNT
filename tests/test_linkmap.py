"""Live link map probes (this PC -> gateway -> internet) and the outage host memory."""
import threading
import time

from tnt.config import Config
from tnt.db import Database
from tnt.events import EventBus
from tnt.icmp import PingResult
from tnt.linkmap import LinkMap


class ScriptedPinger:
    """Returns ok/miss per ip from a script; records calls."""

    def __init__(self):
        self.script = {}     # ip -> list of bools (popped from the front; last value sticks)
        self.calls = []

    def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
        self.calls.append((ip, size, timeout_ms))
        seq = self.script.get(ip, [True])
        ok = seq.pop(0) if len(seq) > 1 else seq[0]
        return PingResult(ok=ok, rtt_ms=1.5 if ok else None, status=0 if ok else 11010, error=None, ttl=64, size=size, ip=ip)

    def close(self):
        pass


def make(tmp_path, gateway="10.0.0.251", internet_ip="198.51.100.9"):
    cfg = Config(tmp_path / "config.json").load()
    bus = EventBus()
    events = []
    bus.subscribe(lambda e: events.append(e))
    pinger = ScriptedPinger()
    clock = {"now": 1_700_000_000.0}
    lm = LinkMap(cfg, bus, pinger=pinger, clock=lambda: clock["now"], sleep=lambda s: None,
                 resolver=lambda host: internet_ip, gateway_lookup=lambda: gateway)
    return lm, pinger, events, clock, cfg


def test_probe_states_and_events(tmp_path):
    lm, pinger, events, clock, cfg = make(tmp_path)
    v = lm.view()
    assert v["gateway"]["state"] == "unknown" and v["internet"]["state"] == "unknown"
    assert v["internet_host"] == "totalelectronics.com"

    d = lm.tick("gateway")
    assert d["ok"] is True and d["ip"] == "10.0.0.251" and d["state"] == "up"
    assert pinger.calls[-1] == ("10.0.0.251", cfg.ping_bytes, cfg.get("ping.timeout_ms"))
    assert events[-1]["type"] == "map.sample" and events[-1]["data"]["probe"] == "gateway"

    # one miss -> degraded, three in a row -> down, a reply -> up again
    pinger.script["198.51.100.9"] = [False, False, False, True, True]
    clock["now"] += 1
    assert lm.tick("internet")["state"] == "degraded"
    clock["now"] += 1
    lm.tick("internet")
    clock["now"] += 1
    assert lm.tick("internet")["state"] == "down"
    assert lm.view()["internet"]["consecutive_missed"] == 3
    clock["now"] += 1
    assert lm.tick("internet")["state"] == "up"
    assert lm.view()["internet"]["loss_pct"] == 75.0

    # loaded/unloaded toggle applies on the next tick
    cfg.update({"ping": {"loaded": False}}, persist=False)
    clock["now"] += 1
    lm.tick("gateway")
    assert pinger.calls[-1][1] == cfg.get("ping.unloaded_bytes")


def test_public_ip_lookup_and_refresh_on_internet_recovery(tmp_path):
    lm, pinger, events, clock, cfg = make(tmp_path)
    answers = ["203.0.113.5"]
    calls = {"n": 0}

    def fetch():
        calls["n"] += 1
        a = answers[min(calls["n"] - 1, len(answers) - 1)]
        if isinstance(a, Exception):
            raise a
        return a

    lm._wan_fetch = fetch
    v = lm.view()
    assert v["public_ip"] == {"ip": None, "ts": None, "error": None, "checked_ts": None}
    assert v["gateway"]["public_ip"] is None
    w = lm.refresh_public_ip()
    assert w["ip"] == "203.0.113.5" and w["error"] is None and w["ts"] == clock["now"]
    assert lm.view()["gateway"]["public_ip"] == "203.0.113.5"
    # a failed refresh keeps the last known address and records the error
    answers.append(RuntimeError("offline"))
    calls["n"] = 1
    clock["now"] += 60
    w = lm.refresh_public_ip()
    assert w["ip"] == "203.0.113.5" and "offline" in w["error"] and w["checked_ts"] == clock["now"] and w["ts"] == clock["now"] - 60
    # the internet probe coming back up wakes the WAN loop
    pinger.script["198.51.100.9"] = [False, False, False, True, True]
    for _ in range(3):
        clock["now"] += 1
        lm.tick("internet")
    assert lm.view()["internet"]["state"] == "down"
    lm._wan_wake.clear()
    clock["now"] += 1
    lm.tick("internet")
    assert lm._wan_wake.is_set(), "recovery schedules a fresh public-IP lookup"


def test_view_public_geo_follows_the_public_ip(tmp_path):
    cfg = Config(tmp_path / "config.json").load()
    clock = {"now": 1_700_000_000.0}
    wan = {"ip": None}
    calls = []
    answer = {"fn": lambda ip: {"ip": ip, "place": "Anytown, TX", "isp": "Example Broadband", "asn": 64500}}

    def geo_lookup(ip):
        calls.append(ip)
        return answer["fn"](ip)

    lm = LinkMap(cfg, EventBus(), pinger=ScriptedPinger(), clock=lambda: clock["now"], sleep=lambda s: None,
                 resolver=lambda host: "198.51.100.9", gateway_lookup=lambda: "10.0.0.251",
                 wan_fetch=lambda: wan["ip"], geo_lookup=geo_lookup)
    v = lm.view()
    assert v["public_geo"] is None and calls == [] and lm.public_ip() is None   # no address: no lookup

    wan["ip"] = "203.0.113.5"
    lm.refresh_public_ip()
    v = lm.view()
    assert v["public_geo"] == {"ip": "203.0.113.5", "place": "Anytown, TX", "isp": "Example Broadband", "asn": 64500}
    assert calls == ["203.0.113.5"] and lm.public_ip() == "203.0.113.5"
    assert list(v).index("public_geo") == list(v).index("public_ip") + 1
    assert set(v["public_ip"]) == {"ip", "ts", "error", "checked_ts"} and v["public_ip"]["ip"] == "203.0.113.5"

    # a lookup that raises or answers something that is not a dict: no location, the rest of the view still works
    def boom(ip):
        raise RuntimeError("database gone")

    answer["fn"] = boom
    v = lm.view()
    assert v is not None and v["public_geo"] is None
    assert v["public_ip"]["ip"] == "203.0.113.5" and v["gateway"]["public_ip"] == "203.0.113.5"
    answer["fn"] = lambda ip: "Anytown, TX"
    assert lm.view()["public_geo"] is None
    answer["fn"] = lambda ip: None
    assert lm.view()["public_geo"] is None

    # the address dropped after a network change takes its location with it
    answer["fn"] = lambda ip: {"ip": ip, "place": "Anytown, TX", "isp": "Example Broadband"}
    clock["now"] += 10
    lm.on_network_change({"summary": "test"})
    wan["ip"] = None
    clock["now"] += 1
    lm.refresh_public_ip()
    v = lm.view()
    assert v["public_ip"]["ip"] is None and v["public_geo"] is None and lm.public_ip() is None

    # a link map without IP location
    lm2 = LinkMap(cfg, EventBus(), pinger=ScriptedPinger(), clock=lambda: clock["now"], sleep=lambda s: None,
                  resolver=lambda host: "198.51.100.9", gateway_lookup=lambda: "10.0.0.251", wan_fetch=lambda: "203.0.113.5")
    lm2.refresh_public_ip()
    assert lm2.view()["public_geo"] is None and lm2.public_ip() == "203.0.113.5"


def test_public_geo_debug_log_once_per_change(tmp_path, caplog):
    import logging

    caplog.set_level(logging.DEBUG, logger="tnt.linkmap")
    cfg = Config(tmp_path / "config.json").load()
    places = {"203.0.113.5": "Anytown, TX", "198.51.100.44": "Springfield, IL"}
    wan = {"ip": "203.0.113.5"}
    lm = LinkMap(cfg, EventBus(), pinger=ScriptedPinger(), clock=time.time, sleep=lambda s: None,
                 resolver=lambda host: "198.51.100.9", gateway_lookup=lambda: "10.0.0.251", wan_fetch=lambda: wan["ip"],
                 geo_lookup=lambda ip: {"ip": ip, "place": places[ip], "isp": "Example Broadband"})

    def geo_records():
        return [r for r in caplog.records if r.name == "tnt.linkmap" and "public IP location" in r.getMessage()]

    lm.refresh_public_ip()
    for _ in range(3):
        lm.view()
    assert len(geo_records()) == 1 and geo_records()[0].levelno == logging.DEBUG
    assert "Anytown, TX" in geo_records()[0].getMessage() and "Example Broadband" in geo_records()[0].getMessage()

    wan["ip"] = "198.51.100.44"
    lm.refresh_public_ip()
    lm.view()
    lm.view()
    assert len(geo_records()) == 2 and "Springfield, IL" in geo_records()[1].getMessage()
    places["198.51.100.44"] = "Chatham, IL"          # same address, another answer (a newer data month)
    lm.view()
    lm.view()
    assert len(geo_records()) == 3 and all(r.levelno == logging.DEBUG for r in geo_records())

    for r in caplog.records:
        if r.levelno >= logging.INFO:
            msg = r.getMessage()
            assert not any(s in msg for s in ("Anytown", "Springfield", "Chatham", "Example Broadband")), msg


def test_missing_gateway_is_down_and_recovers(tmp_path):
    gw = {"ip": None}
    cfg = Config(tmp_path / "config.json").load()
    lm = LinkMap(cfg, EventBus(), pinger=ScriptedPinger(), clock=time.time, sleep=lambda s: None,
                 resolver=lambda host: "198.51.100.9", gateway_lookup=lambda: gw["ip"])
    d = lm.tick("gateway")
    assert d["ok"] is False and d["ip"] is None and d["state"] == "down"
    assert "no default gateway" in (lm.view()["gateway"]["resolve_error"] or "")
    gw["ip"] = "192.168.50.1"
    time.sleep(0.01)
    # a failed resolve is retried every RESOLVE_RETRY_S; force it by rewinding the stamp
    lm._probes["gateway"].last_resolve_ts = 0.0
    d = lm.tick("gateway")
    assert d["ip"] == "192.168.50.1" and d["state"] == "up"


def test_start_and_stop_threads(tmp_path):
    lm, pinger, events, clock, cfg = make(tmp_path)
    lm._sleep = None            # real waits so the worker loop is exercised
    lm._clock = time.time
    lm._wan_fetch = lambda: "198.51.100.200"
    lm.start()
    try:
        deadline = time.time() + 3
        while time.time() < deadline and (len(pinger.calls) < 2 or lm.view()["public_ip"]["ip"] is None):
            time.sleep(0.05)
        assert len(pinger.calls) >= 2
        v = lm.view()
        assert v["running"] and v["gateway"]["state"] == "up" and v["pc"]["hostname"]
        assert v["public_ip"]["ip"] == "198.51.100.200" and v["gateway"]["public_ip"] == "198.51.100.200"
    finally:
        lm.stop()
    assert not lm.running
    assert not any(t.name == "tnt-linkmap-wan" and t.is_alive() for t in threading.enumerate())


def test_outage_rows_remember_the_host(tmp_path):
    db = Database(tmp_path / "t.db")
    oid = db.open_outage("target", 42, 1000.0, host="old-target.test")
    db.close_outage(oid, 1100.0, 5)
    assert db.last_outage_host(42) == "old-target.test"
    assert db.list_outages(0, 2000)[0]["host"] == "old-target.test"
    assert db.last_outage_host(99) is None
    db.close()


def test_backfill_hosts_of_older_outages(tmp_path):
    """Rows from before the host column: filled from the targets table or the raw ping log."""
    from tnt.outages import backfill_outage_hosts
    from tnt.pinger import RawPingLog

    db = Database(tmp_path / "t.db")
    now = time.time()
    two_days_ago = now - 2 * 86400
    raw = RawPingLog(tmp_path / "pings")
    raw.write(two_days_ago, 7, "cam.test", False, None, 1200)         # removed target, older day
    raw.write(now - 30, 8, "10.0.0.9", True, 1.0, 1200)               # removed target, today (open file)
    raw.close()
    live = db.add_target("1.1.1.1")["id"]

    o_cam = db.open_outage("target", 7, two_days_ago + 5)
    db.close_outage(o_cam, two_days_ago + 60, 3)
    o_ip = db.open_outage("target", 8, now - 20)
    o_live = db.open_outage("target", live, now - 10)
    o_unknown = db.open_outage("target", 99, now - 5)                 # never pinged: stays unnamed
    assert all(r["host"] is None for r in db.list_outages(0, now + 10))

    # a fresh log object gzips the older day's file in the background; host_for reads both forms
    raw2 = RawPingLog(tmp_path / "pings")
    raw2.close(wait_background_s=10)
    assert (tmp_path / "pings" / (time.strftime("%Y-%m-%d", time.localtime(two_days_ago)) + ".csv.gz")).exists()
    assert raw2.host_for(7, two_days_ago) == "cam.test"
    assert raw2.host_for(8, now) == "10.0.0.9"
    assert raw2.host_for(7, now) is None

    assert backfill_outage_hosts(db, raw2) == 3
    hosts = {r["id"]: r["host"] for r in db.list_outages(0, now + 10)}
    assert hosts[o_cam] == "cam.test" and hosts[o_ip] == "10.0.0.9" and hosts[o_live] == "1.1.1.1" and hosts[o_unknown] is None
    assert backfill_outage_hosts(db, raw2) == 0, "nothing left to fill"
    assert db.last_outage_host(7) == "cam.test"
    db.close()


# --- network changes (tnt.netwatch -> LinkMap.on_network_change); synthetic addresses only ------
def _wait(pred, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def test_network_change_follows_the_new_gateway_and_forgets_the_old_one(tmp_path):
    lm, pinger, events, clock, cfg = make(tmp_path)
    gw = {"ip": "10.0.0.251"}
    lm._gateway_lookup = lambda: gw["ip"]
    for _ in range(3):
        lm.tick("gateway")
        clock["now"] += 1
    assert lm.view()["gateway"]["sent"] == 3
    gw["ip"] = "10.20.30.1"
    lm.tick("gateway")
    assert lm.view()["gateway"]["ip"] == "10.0.0.251", "a healthy gateway is not looked up every second"
    lm._pc_cache = (clock["now"], {"hostname": "DESK-01", "ip": "192.168.10.23", "adapter": "Wi-Fi"})
    lm._wan_wake.clear()
    lm.on_network_change({"gateway_changed": True})
    assert lm._wan_wake.is_set() and lm._pc_cache == (0.0, {})
    assert lm._probes["internet"].force is True, "the internet host is looked up again too"
    clock["now"] += 1
    d = lm.tick("gateway")
    v = lm.view()["gateway"]
    assert d["ip"] == "10.20.30.1" and v["ip"] == "10.20.30.1" and pinger.calls[-1][0] == "10.20.30.1"
    assert v["sent"] == 1 and v["consecutive_missed"] == 0, "the old router's samples are gone"


def test_gateway_is_rechecked_every_poll_and_after_a_miss_and_cleared_without_one(tmp_path):
    lm, pinger, events, clock, cfg = make(tmp_path)
    gw = {"ip": "10.0.0.251"}
    lm._gateway_lookup = lambda: gw["ip"]
    lm.tick("gateway")
    gw["ip"] = "10.20.30.1"
    clock["now"] += 5                                        # network.poll_s after the lookup
    assert lm.tick("gateway")["ip"] == "10.20.30.1"
    gw["ip"] = "192.168.50.1"
    pinger.script["10.20.30.1"] = [False]
    clock["now"] += 1
    assert lm.tick("gateway")["ip"] == "10.20.30.1"          # the miss
    clock["now"] += 1
    assert lm.tick("gateway")["ip"] == "192.168.50.1"        # 2 s after the lookup, with a miss behind it
    gw["ip"] = None                                          # no default gateway any more
    lm.on_network_change({})
    clock["now"] += 1
    calls = len(pinger.calls)
    d = lm.tick("gateway")
    assert d["ip"] is None and d["state"] == "down" and len(pinger.calls) == calls
    v = lm.view()["gateway"]
    assert v["ip"] is None and "no default gateway" in v["resolve_error"] and v["sent"] == 1


def test_a_lookup_overtaken_by_a_network_change_is_repeated(tmp_path):
    lm, pinger, events, clock, cfg = make(tmp_path)
    answers = iter(["10.0.0.251", "10.20.30.1"])

    def lookup():
        answer = next(answers)
        if answer == "10.0.0.251":
            lm.on_network_change({})                          # reported while this lookup was running
        return answer

    lm._gateway_lookup = lookup
    assert lm.tick("gateway")["ip"] == "10.20.30.1"


def test_public_ip_is_rechecked_right_after_a_network_change(tmp_path):
    lm, pinger, events, clock, cfg = make(tmp_path)
    lm._sleep = None
    lm._clock = time.time
    fetched = []
    lm._wan_fetch = lambda: (fetched.append(time.time()), "198.51.100.200")[1]
    lm.start()
    try:
        assert _wait(lambda: fetched and lm.view()["internet"]["state"] == "up")
        time.sleep(0.3)                  # the internet probe's first reply has already woken the loop once
        n = len(fetched)
        lm.on_network_change({"gateway_changed": True})
        assert _wait(lambda: len(fetched) > n), "checked again at once, not WAN_REFRESH_S later"
    finally:
        lm.stop()


def test_a_failed_lookup_after_a_network_change_drops_the_old_public_ip(tmp_path):
    """A transient failure keeps the last known public address; one on the network this PC moved to must not
    present the previous network's address as current (the map shows the error instead)."""
    lm, pinger, events, clock, cfg = make(tmp_path)
    answer = {"ip": "203.0.113.5"}

    def fetch():
        if answer["ip"] is None:
            raise OSError("no route to host")
        return answer["ip"]

    lm._wan_fetch = fetch
    t0 = clock["now"]
    assert lm.refresh_public_ip()["ip"] == "203.0.113.5"
    clock["now"] += 60
    answer["ip"] = None
    w = lm.refresh_public_ip()
    assert w["ip"] == "203.0.113.5" and "no route" in w["error"], "a failure on the same network keeps the address"
    clock["now"] += 5
    lm.on_network_change({"gateway_changed": True})
    clock["now"] += 1
    w = lm.refresh_public_ip()
    assert w["ip"] is None and "no route" in w["error"] and w["ts"] == t0 and w["checked_ts"] == clock["now"]
    assert lm.view()["gateway"]["public_ip"] is None
    answer["ip"] = "198.51.100.77"
    clock["now"] += 10
    assert lm.refresh_public_ip() == {"ip": "198.51.100.77", "ts": clock["now"], "error": None, "checked_ts": clock["now"]}


def test_a_flapping_network_costs_one_public_address_lookup_per_gap(tmp_path, monkeypatch):
    import tnt.linkmap as linkmap_module

    monkeypatch.setattr(linkmap_module, "WAN_CHANGE_MIN_GAP_S", 0.6)
    lm, pinger, events, clock, cfg = make(tmp_path)
    lm._sleep = None
    lm._clock = time.time
    fetched = []
    lm._wan_fetch = lambda: (fetched.append(time.time()), "198.51.100.200")[1]
    lm.start()
    try:
        assert _wait(lambda: fetched and lm.view()["internet"]["state"] == "up")
        time.sleep(0.3)
        n = len(fetched)
        lm.on_network_change({"gateway_changed": True})
        assert _wait(lambda: len(fetched) == n + 1), "the first change: looked up at once"
        for _ in range(12):                                  # then a change every 50 ms
            lm.on_network_change({"gateway_changed": True})
            time.sleep(0.05)
        time.sleep(1.0)
        extra = fetched[n + 1:]
        assert 1 <= len(extra) <= 2, [round(t - fetched[n], 2) for t in extra]
        assert extra[0] - fetched[n] >= 0.55, "never sooner than the gap after the last lookup a change asked for"
    finally:
        lm.stop()
