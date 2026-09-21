"""tnt.traceroute: classic ICMP traceroute on top of the shared pinger (scripted, no network)."""
from __future__ import annotations

import socket
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from tnt import traceroute as tr
from tnt.events import EventBus
from tnt.icmp import PingResult
from tnt.traceroute import SILENT_HOPS_LIMIT, THREAD_NAME, Tracer, classify_hop, is_lan_address

T0 = 1_700_000_000.0
TARGET = "198.51.100.7"
GATEWAY = "10.0.0.251"
CGNAT = "100.64.0.1"
PUBLIC = "203.0.113.9"
PUBLIC_ALT = "203.0.113.10"
NAMES = {GATEWAY: "router.lan", PUBLIC: "core1.isp.example", TARGET: "www.example"}

# ttl -> one entry per probe (the last one repeats): (responder | None, rtt_ms | None[, status])
FULL_PATH: Dict[int, List[Tuple[Any, ...]]] = {
    1: [(GATEWAY, 0.8), (GATEWAY, 0.9), (GATEWAY, 1.0)],
    2: [(CGNAT, 5.0), (None, None), (CGNAT, 7.0)],           # one probe lost
    3: [(None, None)],                                         # a silent hop in the middle
    4: [(PUBLIC, 12.0), (PUBLIC_ALT, 13.0), (PUBLIC, None)],   # load-balanced; third reply carries no rtt
    5: [(TARGET, 20.0), (TARGET, 22.0), (TARGET, 21.0)],
}


class ScriptedPinger:
    """Answers per (ttl, probe index) from a script and records every call with its thread name."""

    def __init__(self, script: Dict[int, List[Tuple[Any, ...]]]) -> None:
        self.script = script
        self.calls: List[Tuple[str, int, int, int, str]] = []
        self.hook: Optional[Callable[[int], None]] = None   # runs before each probe

    def ping(self, ip: str, size: int = 32, timeout_ms: int = 1000, ttl: int = 128) -> PingResult:
        if self.hook is not None:
            self.hook(ttl)
        idx = sum(1 for c in self.calls if c[3] == ttl)
        self.calls.append((ip, size, timeout_ms, ttl, threading.current_thread().name))
        seq = self.script.get(ttl, [(None, None)])
        entry = seq[min(idx, len(seq) - 1)]
        responder, rtt = entry[0], entry[1]
        status = entry[2] if len(entry) > 2 else None
        if responder is None:
            return PingResult(False, None, 11010, "Request timed out", None, size, ip, responder=None)
        if status is not None:
            return PingResult(False, None, status, f"Destination host unreachable (reply from {responder})",
                              None, size, ip, responder=responder)
        if responder == ip:
            return PingResult(True, rtt, 0, None, 52, size, ip, responder=ip)
        # a real "TTL expired" reply carries no rtt (the tracer times the probe); the script may give one
        return PingResult(False, rtt, 11013, f"TTL expired in transit (reply from {responder})", None, size, ip,
                          responder=responder)

    def close(self) -> None:
        pass


def _resolve(host: str) -> Optional[str]:
    if host == "www.example":
        return TARGET
    return host if host[:1].isdigit() else None


def make(script: Dict[int, List[Tuple[Any, ...]]], gateway: Optional[str] = GATEWAY, names: Optional[Dict[str, str]] = None,
         resolver: Callable[[str], Optional[str]] = _resolve, local: Any = "10.0.0.112", geo: Optional[Callable[[], Any]] = None):
    bus = EventBus()
    events: List[Dict[str, Any]] = []
    bus.subscribe(lambda e: events.append(e))
    pinger = ScriptedPinger(script)
    clock = {"now": T0}
    table = NAMES if names is None else names
    reverse_calls: List[str] = []

    def reverse(ip: str) -> Optional[str]:
        reverse_calls.append(ip)
        return table.get(ip)

    local_fn = local if callable(local) else (lambda: local)
    tracer = Tracer(pinger, bus, clock=lambda: clock["now"], resolver=resolver, reverse=reverse,
                    gateway_fn=lambda: gateway, local_fn=local_fn, geo=geo)
    return tracer, pinger, events, clock, reverse_calls


def test_full_path_classification_stats_and_events():
    tracer, pinger, events, clock, reverse_calls = make(FULL_PATH)
    res = tracer.trace("www.example")

    assert set(res) == {"host", "target_ip", "ts", "duration_s", "max_hops", "probes", "timeout_ms", "complete", "error",
                        "pc", "gateway", "hops"}
    assert res["host"] == "www.example" and res["target_ip"] == TARGET and res["ts"] == T0
    assert res["complete"] is True and res["error"] is None
    assert (res["max_hops"], res["probes"], res["timeout_ms"]) == (30, 3, 1500)
    assert res["gateway"] == GATEWAY and res["pc"] == {"ip": "10.0.0.112", "hostname": socket.gethostname()}
    assert tracer.last is res and tracer.running is False

    hops = res["hops"]
    assert [h["ttl"] for h in hops] == [1, 2, 3, 4, 5]
    for h in hops:
        assert set(h) == {"ttl", "ip", "alt_ips", "hostname", "rtts", "avg_ms", "min_ms", "max_ms", "loss",
                          "responder_status", "kind", "label", "location"}
        assert list(h)[-1] == "location" and h["location"] is None      # no geo provider
    assert [h["kind"] for h in hops] == ["gateway", "lan", "unknown", "public", "destination"]
    assert [h["label"] for h in hops] == ["Gateway", "LAN", "No reply", "Internet", "Destination"]

    gw, cg, silent, pub, dst = hops
    assert gw["ip"] == GATEWAY and gw["rtts"] == [0.8, 0.9, 1.0] and gw["loss"] == 0 and gw["alt_ips"] == []
    assert (gw["avg_ms"], gw["min_ms"], gw["max_ms"]) == (0.9, 0.8, 1.0)
    assert gw["responder_status"] == 11013 and gw["hostname"] == "router.lan"
    assert cg["ip"] == CGNAT and cg["rtts"] == [5.0, None, 7.0] and cg["loss"] == 1
    assert (cg["avg_ms"], cg["min_ms"], cg["max_ms"]) == (6.0, 5.0, 7.0) and cg["hostname"] is None
    assert silent["ip"] is None and silent["rtts"] == [None, None, None] and silent["loss"] == 3
    assert silent["avg_ms"] is None and silent["min_ms"] is None and silent["max_ms"] is None
    assert silent["responder_status"] is None and silent["hostname"] is None and silent["alt_ips"] == []
    assert pub["ip"] == PUBLIC and pub["alt_ips"] == [PUBLIC_ALT] and pub["loss"] == 0
    assert pub["rtts"][:2] == [12.0, 13.0] and isinstance(pub["rtts"][2], float) and pub["rtts"][2] >= 0.0
    assert pub["min_ms"] == min(pub["rtts"]) and pub["max_ms"] == 13.0 and pub["hostname"] == "core1.isp.example"
    assert dst["ip"] == TARGET and dst["rtts"] == [20.0, 22.0, 21.0] and dst["avg_ms"] == 21.0
    assert dst["responder_status"] == 0 and dst["hostname"] == "www.example"

    # every probe went to the target with the classic parameters, from the tnt-ping-* thread
    assert all(c[0] == TARGET and c[1] == 32 and c[2] == 1500 and c[4] == THREAD_NAME for c in pinger.calls)
    assert [c[3] for c in pinger.calls] == [1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5]
    # each answering router is reverse-resolved exactly once
    assert sorted(reverse_calls) == sorted([GATEWAY, CGNAT, PUBLIC, TARGET])

    assert [e["type"] for e in events] == ["trace.start"] + ["trace.hop"] * 5 + ["trace.done"]
    assert events[0]["data"] == {"host": "www.example", "target_ip": TARGET, "max_hops": 30, "probes": 3}
    assert [e["data"]["hop"]["ttl"] for e in events[1:6]] == [1, 2, 3, 4, 5]
    assert events[1]["data"]["hop"]["kind"] == "gateway" and events[5]["data"]["hop"]["kind"] == "destination"
    done = events[-1]["data"]
    assert done == {"host": "www.example", "target_ip": TARGET, "hops": 5, "complete": True, "error": None,
                    "duration_s": res["duration_s"]}


def test_resolve_names_off_skips_reverse_dns_and_custom_parameters_reach_the_pinger():
    tracer, pinger, events, clock, reverse_calls = make(FULL_PATH)
    clock["now"] = T0 + 100
    res = tracer.trace(TARGET, max_hops=10, probes=2, timeout_ms=700, resolve_names=False)
    assert res["complete"] is True and reverse_calls == []
    assert all(h["hostname"] is None for h in res["hops"])
    assert (res["max_hops"], res["probes"], res["timeout_ms"]) == (10, 2, 700) and res["ts"] == T0 + 100
    assert all(c[2] == 700 for c in pinger.calls) and [c[3] for c in pinger.calls] == [1, 1, 2, 2, 3, 3, 4, 4, 5, 5]
    assert res["hops"][1]["rtts"] == [5.0, None] and res["hops"][1]["loss"] == 1
    assert res["hops"][3]["alt_ips"] == [PUBLIC_ALT]
    assert events[0]["data"]["max_hops"] == 10 and events[0]["data"]["probes"] == 2


def test_a_silent_tail_runs_to_max_hops_on_one_probe_per_hop_and_says_where_replies_stopped():
    """Silent hops no longer end the trace (the destination may answer beyond a silent core, as tracert shows); this
    test used to pin the old stop after five silent hops, which reported a reachable destination as dead. A tail that
    really is silent still reads "no reply after hop 2", and past the fifth silent hop each hop costs one probe."""
    tracer, pinger, events, clock, _ = make({1: [(GATEWAY, 1.0)], 2: [(CGNAT, 4.0)]})
    res = tracer.trace(TARGET)
    assert res["complete"] is False and res["error"] == "no reply after hop 2"
    assert len(res["hops"]) == 30
    assert [h["kind"] for h in res["hops"]] == ["gateway", "lan"] + ["unknown"] * 28
    assert max(c[3] for c in pinger.calls) == 30
    assert len(pinger.calls) == 2 * 3 + SILENT_HOPS_LIMIT * 3 + (28 - SILENT_HOPS_LIMIT)
    assert events[-1]["type"] == "trace.done" and events[-1]["data"]["complete"] is False
    assert events[-1]["data"]["hops"] == 30 and events[-1]["data"]["error"] == "no reply after hop 2"
    assert tracer.last is res

    # a silent hop between answering ones resets the count (see FULL_PATH); when nothing at all answers, it says so
    tracer2, pinger2, _, _, _ = make({})
    res2 = tracer2.trace(TARGET)
    assert res2["complete"] is False and len(res2["hops"]) == 30
    assert res2["error"] == "no reply from any of the 30 hops"


def test_max_hops_exhausted_and_unreachable_reply_stop_the_trace():
    tracer, pinger, events, clock, _ = make({1: [(GATEWAY, 1.0)], 2: [(CGNAT, 4.0)], 3: [(PUBLIC, 9.0)]})
    res = tracer.trace(TARGET, max_hops=3)
    assert res["complete"] is False and res["error"] == "destination not reached within 3 hops"
    assert [h["kind"] for h in res["hops"]] == ["gateway", "lan", "public"]   # the last hop is not the destination
    assert max(c[3] for c in pinger.calls) == 3

    # a router reporting the destination unreachable ends the trace at that hop
    tracer, pinger, events, clock, _ = make({1: [(GATEWAY, 0.5, 11003)]})
    res = tracer.trace(TARGET)
    assert res["complete"] is False and "unreachable" in res["error"] and GATEWAY in res["error"]
    assert len(res["hops"]) == 1 and res["hops"][0]["kind"] == "gateway" and res["hops"][0]["responder_status"] == 11003
    # the scripted unreachable reply carries no rtt (like a real one): each probe is wall-clock timed
    assert len(res["hops"][0]["rtts"]) == 3 and all(isinstance(x, float) and x >= 0.0 for x in res["hops"][0]["rtts"])
    assert res["hops"][0]["loss"] == 0


def test_destination_is_the_gateway_itself_and_pinger_without_responder_field():
    tracer, pinger, events, clock, _ = make({1: [(GATEWAY, 0.4)]}, resolver=lambda h: GATEWAY)
    res = tracer.trace("gateway-box")
    assert res["complete"] is True and len(res["hops"]) == 1
    assert res["hops"][0]["kind"] == "destination" and res["hops"][0]["ip"] == GATEWAY

    class BarePinger:
        def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
            from types import SimpleNamespace
            return SimpleNamespace(ok=True, rtt_ms=2.5, status=0, error=None)

    def boom() -> Optional[str]:
        raise RuntimeError("no adapters")

    tracer = Tracer(BarePinger(), None, resolver=lambda h: TARGET, reverse=lambda ip: None, gateway_fn=boom, local_fn=boom)
    res = tracer.trace(TARGET, probes=1)
    assert res["complete"] is True and res["hops"][0]["ip"] == TARGET and res["hops"][0]["rtts"] == [2.5]
    assert res["gateway"] is None and res["pc"]["ip"] is None and res["hops"][0]["hostname"] is None


def test_only_one_trace_at_a_time():
    tracer, pinger, events, clock, _ = make({1: [(TARGET, 1.0)]})
    started = threading.Event()
    release = threading.Event()

    def hook(ttl: int) -> None:
        started.set()
        release.wait(5)

    pinger.hook = hook
    out: Dict[str, Any] = {}
    t = threading.Thread(target=lambda: out.setdefault("res", tracer.trace(TARGET)), daemon=True)
    t.start()
    assert started.wait(5)
    assert tracer.running is True
    with pytest.raises(RuntimeError, match="a traceroute is already running"):
        tracer.trace(TARGET)
    release.set()
    t.join(5)
    assert not t.is_alive() and tracer.running is False
    assert out["res"]["complete"] is True and tracer.last is out["res"]
    assert [e["type"] for e in events] == ["trace.start", "trace.hop", "trace.done"]   # the refused call published nothing

    pinger.hook = None
    assert tracer.trace(TARGET)["complete"] is True    # free again


def test_resolve_failure_and_bad_arguments():
    tracer, pinger, events, clock, _ = make({}, resolver=lambda host: None)
    with pytest.raises(ValueError, match="could not resolve nope.invalid"):
        tracer.trace("nope.invalid")
    assert tracer.running is False and tracer.last is None and events == [] and pinger.calls == []

    tracer, pinger, events, clock, _ = make(FULL_PATH)
    for kwargs in ({"host": ""}, {"host": "  "}, {"host": None}, {"host": TARGET, "max_hops": 0}, {"host": TARGET, "max_hops": 65},
                   {"host": TARGET, "probes": 0}, {"host": TARGET, "probes": 6}, {"host": TARGET, "probes": True},
                   {"host": TARGET, "timeout_ms": 10}, {"host": TARGET, "timeout_ms": "lots"}):
        with pytest.raises(ValueError):
            tracer.trace(**kwargs)
    assert pinger.calls == [] and events == [] and tracer.running is False
    with pytest.raises(RuntimeError):
        Tracer(None, None).trace(TARGET)
    # a resolver that raises counts as "could not resolve"
    def broken(host: str) -> Optional[str]:
        raise OSError("dns down")
    tracer, *_ = make({}, resolver=broken)
    with pytest.raises(ValueError, match="could not resolve"):
        tracer.trace("x.example")
    assert tracer.running is False


def test_cancel_stops_between_probes():
    tracer, pinger, events, clock, _ = make(FULL_PATH)
    cancel = threading.Event()
    pinger.hook = lambda ttl: cancel.set() if ttl == 2 else None
    res = tracer.trace(TARGET, cancel=cancel)
    assert res["complete"] is False and res["error"] == "cancelled"
    assert len(res["hops"]) == 2 and res["hops"][1]["rtts"] == [5.0] and res["hops"][1]["loss"] == 0
    assert events[-1]["type"] == "trace.done" and events[-1]["data"]["error"] == "cancelled"
    assert tracer.running is False


def test_caller_stops_waiting_when_the_worker_hangs(monkeypatch):
    monkeypatch.setattr(tr, "WAIT_GRACE_S", 0.2)
    monkeypatch.setattr(tr, "REVERSE_DNS_DEADLINE_S", 0.0)
    tracer, pinger, events, clock, _ = make({1: [(GATEWAY, 1.0)], 2: [(TARGET, 2.0)]})
    release = threading.Event()
    pinger.hook = lambda ttl: release.wait(5) if ttl == 2 else None
    res = tracer.trace(TARGET, probes=1, timeout_ms=100, resolve_names=False)
    assert res["complete"] is False and "did not finish" in res["error"]
    assert [h["ttl"] for h in res["hops"]] == [1] and res["hops"][0]["kind"] == "gateway"
    assert tracer.running is True and tracer.last is res          # the worker still owns the pinger
    with pytest.raises(RuntimeError, match="already running"):
        tracer.trace(TARGET)
    release.set()
    deadline = threading.Event()
    for _ in range(100):
        if not tracer.running:
            break
        deadline.wait(0.05)
    assert tracer.running is False
    assert tracer.last is not res and tracer.last["complete"] is True   # the worker's real result replaced the snapshot


def test_reverse_dns_deadline_is_bounded(monkeypatch):
    monkeypatch.setattr(tr, "REVERSE_DNS_DEADLINE_S", 0.2)
    release = threading.Event()

    def slow_reverse(ip: str) -> Optional[str]:
        if ip == GATEWAY:
            return "router.lan"
        release.wait(5)
        return "late.example"

    tracer = Tracer(ScriptedPinger({1: [(GATEWAY, 1.0)], 2: [(TARGET, 3.0)]}), EventBus(), resolver=lambda h: TARGET,
                    reverse=slow_reverse, gateway_fn=lambda: GATEWAY, local_fn=lambda: None)
    res = tracer.trace(TARGET, probes=1)
    release.set()
    assert res["complete"] is True
    assert res["hops"][0]["hostname"] == "router.lan" and res["hops"][1]["hostname"] is None   # the slow one was abandoned


def test_lan_address_and_hop_classification():
    for ip in ("10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.1", "169.254.7.7", "100.64.0.1", "100.127.255.1",
               "127.0.0.1", "fe80::1", "fd00::1", "::1", "::ffff:10.0.0.1"):
        assert is_lan_address(ip), ip
    for ip in ("8.8.8.8", "172.32.0.1", "100.128.0.1", "203.0.113.9", "198.51.100.7", "2001:db8::1", "garbage", "", None):
        assert not is_lan_address(ip), ip
    assert classify_hop(None, GATEWAY) == ("unknown", "No reply")
    assert classify_hop(GATEWAY, GATEWAY) == ("gateway", "Gateway")
    assert classify_hop(GATEWAY, GATEWAY, reached=True) == ("destination", "Destination")
    assert classify_hop("192.168.0.1", GATEWAY) == ("lan", "LAN")
    assert classify_hop("192.168.0.1", None) == ("lan", "LAN")
    assert classify_hop(CGNAT, GATEWAY) == ("lan", "LAN")
    assert classify_hop(PUBLIC, GATEWAY) == ("public", "Internet")
    assert set(tr.KIND_LABELS) == {"gateway", "lan", "public", "destination", "unknown"}


# -- hop locations (tnt.geoip) ---------------------------------------------------------------------------------
# a router name with a generic Dallas code on the public hop; the fixture data (tests/mmdb_writer.py) places
# PUBLIC in Anytown, TX, TARGET in Richardson, TX and this PC's public address 203.0.113.200 in Dallas
GEO_NAMES = {PUBLIC: "ae-1.cr1.dllstx.example.net", TARGET: "www.example"}
GEO_PATH: Dict[int, List[Tuple[Any, ...]]] = {
    1: [(GATEWAY, 0.8)],
    2: [(CGNAT, 5.0)],
    3: [(None, None)],
    4: [(PUBLIC, 12.0), (PUBLIC, 12.4), (PUBLIC, 12.1)],
    5: [(TARGET, 20.0), (TARGET, 22.0), (TARGET, 21.0)],
}
PUBLIC_DB = {"text": "Anytown, TX", "source": "database", "hint": None, "db_text": "Anytown, TX", "asn": 64500,
             "as_org": "Example Broadband"}
TARGET_DB = {"text": "Richardson, TX", "source": "database", "hint": None, "db_text": "Richardson, TX", "asn": 64510,
             "as_org": "Example Transit, Inc."}


@pytest.fixture
def geo_mgr(tmp_path):
    """A real IP location manager with the fixture data installed in a tmp_path folder (never the data folder)."""
    from geoip_helpers import installed_manager

    mgr = installed_manager(tmp_path, public_ip="203.0.113.200")
    yield mgr
    mgr.stop()


def test_hop_locations_from_database_and_router_names(geo_mgr, tmp_path):
    tracer, pinger, events, clock, reverse_calls = make(GEO_PATH, names=GEO_NAMES, geo=lambda: geo_mgr)
    res = tracer.trace("www.example")
    assert res["complete"] is True and tracer.last is res
    gw, cg, silent, pub, dst = res["hops"]
    assert gw["location"] is None and cg["location"] is None and silent["location"] is None
    # the router name wins: the speed-of-light guard runs with origin Dallas and min_ms 12.0
    assert pub["hostname"] == "ae-1.cr1.dllstx.example.net" and pub["min_ms"] == 12.0
    assert pub["location"] == {"text": "Dallas, TX", "source": "hostname", "hint": "dllstx", "db_text": "Anytown, TX",
                               "asn": 64500, "as_org": "Example Broadband"}
    assert dst["hostname"] == "www.example" and dst["location"] == TARGET_DB
    assert all(list(h)[-1] == "location" for h in res["hops"])

    # the live events carry the hop-completion value: the database, or the name if the reverse lookup was back
    live = {e["data"]["hop"]["ttl"]: e["data"]["hop"] for e in events if e["type"] == "trace.hop"}
    assert live[1]["location"] is None and live[3]["location"] is None
    assert live[4]["location"]["source"] in ("database", "hostname") and live[4]["location"]["db_text"] == "Anytown, TX"
    assert live[4]["location"] is not pub["location"]           # refined into a new dict, never mutated in place
    assert live[5]["location"]["db_text"] == "Richardson, TX"

    # origin() is really used: seen from a public address in London the Dallas name is 12 ms too far away
    from geoip_helpers import installed_manager

    far = installed_manager(tmp_path / "far", public_ip="2001:db8::5")
    try:
        tracer, *_ = make(GEO_PATH, names=GEO_NAMES, geo=lambda: far)
        assert tracer.trace("www.example")["hops"][3]["location"] == PUBLIC_DB
    finally:
        far.stop()


def test_destination_hop_ignores_generic_router_names(geo_mgr):
    tracer, *_ = make(GEO_PATH, names={TARGET: "ae-1.cr1.dllstx.example.net"}, geo=lambda: geo_mgr)
    res = tracer.trace("www.example")
    dst = res["hops"][-1]
    assert dst["kind"] == "destination" and dst["hostname"] == "ae-1.cr1.dllstx.example.net"
    assert dst["location"] == TARGET_DB
    assert res["hops"][3]["hostname"] is None and res["hops"][3]["location"] == PUBLIC_DB


def test_hop_locations_without_names_are_database_only(geo_mgr):
    tracer, pinger, events, clock, reverse_calls = make(GEO_PATH, names=GEO_NAMES, geo=lambda: geo_mgr)
    res = tracer.trace("www.example", resolve_names=False)
    assert res["complete"] is True and reverse_calls == []
    assert [h["location"] for h in res["hops"]] == [None, None, None, PUBLIC_DB, TARGET_DB]
    live = [e["data"]["hop"] for e in events if e["type"] == "trace.hop"]
    assert [h["location"] for h in live] == [None, None, None, PUBLIC_DB, TARGET_DB]


def test_abandoned_reverse_lookup_keeps_database_location(geo_mgr, monkeypatch):
    monkeypatch.setattr(tr, "REVERSE_DNS_DEADLINE_S", 0.2)
    release = threading.Event()

    def slow_reverse(ip: str) -> Optional[str]:
        if ip == PUBLIC:
            release.wait(5)
            return "ae-1.cr1.dllstx.example.net"
        return None

    tracer = Tracer(ScriptedPinger({1: [(GATEWAY, 1.0)], 2: [(PUBLIC, 12.0)], 3: [(TARGET, 20.0)]}), EventBus(),
                    resolver=lambda h: TARGET, reverse=slow_reverse, gateway_fn=lambda: GATEWAY, local_fn=lambda: None,
                    geo=lambda: geo_mgr)
    try:
        res = tracer.trace(TARGET, probes=1)
    finally:
        release.set()
    assert res["complete"] is True
    pub = res["hops"][1]
    assert pub["hostname"] is None and pub["location"] == PUBLIC_DB
    threading.Event().wait(0.1)                  # the abandoned lookup finishing later changes nothing
    assert tracer.last["hops"][1]["hostname"] is None and tracer.last["hops"][1]["location"] == PUBLIC_DB


def test_lan_destination_and_disabled_geo_give_none(geo_mgr):
    lan_target = "192.168.1.20"
    tracer, *_ = make({1: [(lan_target, 0.5)]}, gateway="192.168.1.1", resolver=lambda h: lan_target, geo=lambda: geo_mgr)
    res = tracer.trace(lan_target)
    assert res["complete"] is True and res["hops"][0]["kind"] == "destination" and res["hops"][0]["location"] is None

    tracer, *_ = make(GEO_PATH, names=GEO_NAMES, geo=lambda: None)
    res = tracer.trace("www.example")
    assert res["complete"] is True and all(h["location"] is None for h in res["hops"])

    def broken() -> Any:
        raise RuntimeError("no IP location")

    tracer, *_ = make(GEO_PATH, names=GEO_NAMES, geo=broken)
    res = tracer.trace("www.example")
    assert res["complete"] is True and res["error"] is None and all(h["location"] is None for h in res["hops"])

    # the setting switched off: the manager answers None for every hop
    geo_mgr.config.update({"geoip": {"enabled": False}}, persist=False)
    tracer, *_ = make(GEO_PATH, names=GEO_NAMES, geo=lambda: geo_mgr)
    res = tracer.trace("www.example")
    assert res["complete"] is True and all(h["location"] is None for h in res["hops"])


def test_geo_locate_raising_is_contained():
    class BrokenGeo:
        def __init__(self) -> None:
            self.calls: List[Tuple[Any, ...]] = []

        def origin(self) -> Any:
            raise RuntimeError("origin failed")

        def locate_hop(self, ip, hostname=None, min_ms=None, origin=None, kind=None):
            self.calls.append((ip, hostname, min_ms, origin, kind))
            raise RuntimeError("lookup failed")

    geo = BrokenGeo()
    tracer, *_ = make(GEO_PATH, names=GEO_NAMES, geo=lambda: geo)
    res = tracer.trace("www.example")
    assert res["complete"] is True and res["error"] is None and all(h["location"] is None for h in res["hops"])
    assert {c[0] for c in geo.calls} == {PUBLIC, TARGET}         # never asked about LAN, CGNAT or silent hops
    assert all(c[3] is None for c in geo.calls)                  # origin() raising gives no origin
    assert ("public", "destination") == (geo.calls[0][4], [c for c in geo.calls if c[0] == TARGET][0][4])

    class OddGeo:
        def origin(self) -> Any:
            return None

        def locate_hop(self, *args: Any, **kwargs: Any) -> Any:
            return ["not", "a", "location"]

    tracer, *_ = make(GEO_PATH, names=GEO_NAMES, geo=lambda: OddGeo())
    res = tracer.trace("www.example")
    assert res["complete"] is True and all(h["location"] is None for h in res["hops"])


def test_ipv6_public_hop_location(geo_mgr):
    v6 = "2001:db8::1"
    tracer, *_ = make({1: [(GATEWAY, 0.5)], 2: [(v6, 30.0)]}, names={}, resolver=lambda h: v6, geo=lambda: geo_mgr)
    res = tracer.trace(v6)
    assert res["complete"] is True
    hop = res["hops"][-1]
    assert hop["kind"] == "destination" and hop["location"] == {
        "text": "London, United Kingdom", "source": "database", "hint": None, "db_text": "London, United Kingdom",
        "asn": 64511, "as_org": "Example Hosting LLC"}
