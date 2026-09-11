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
