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
         resolver: Callable[[str], Optional[str]] = _resolve, local: Any = "10.0.0.112"):
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
                    gateway_fn=lambda: gateway, local_fn=local_fn)
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
                          "responder_status", "kind", "label"}
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


def test_gives_up_after_five_silent_hops():
    tracer, pinger, events, clock, _ = make({1: [(GATEWAY, 1.0)], 2: [(CGNAT, 4.0)]})
    res = tracer.trace(TARGET)
    assert res["complete"] is False and res["error"] == "no reply after hop 2"
    assert len(res["hops"]) == 2 + SILENT_HOPS_LIMIT
    assert [h["kind"] for h in res["hops"]] == ["gateway", "lan"] + ["unknown"] * SILENT_HOPS_LIMIT
    assert max(c[3] for c in pinger.calls) == 2 + SILENT_HOPS_LIMIT     # never went on to hop 8..30
    assert events[-1]["type"] == "trace.done" and events[-1]["data"]["complete"] is False
    assert events[-1]["data"]["hops"] == 7 and events[-1]["data"]["error"] == "no reply after hop 2"
    assert tracer.last is res

    # a silent hop between answering ones resets the count (see FULL_PATH), nothing at all gives up too
    tracer2, pinger2, _, _, _ = make({})
    res2 = tracer2.trace(TARGET)
    assert res2["complete"] is False and len(res2["hops"]) == SILENT_HOPS_LIMIT
    assert res2["error"] == f"no reply from the first {SILENT_HOPS_LIMIT} hops"


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
