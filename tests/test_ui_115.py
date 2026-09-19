from test_ui import mock, browser_page, _req, _serve_probe, _probe_result, _load_mock, _read, _doc, UI, ROOT  # noqa: F401

# The mock API (tools/mock_api.py) for the 1.15.0 network tools, held to the service: every key tuple, text, limit and rule the mock
# mirrors equals tnt.natcheck / tnt.switchport / tnt.lldp / tnt.pktmon / tnt.portcheck / tnt.tftp / tnt.capture / tnt.dissect /
# tnt.sipcalls / tnt.speedtest.quality / tnt.nettools / tnt.api.routes (the test_mock_network_tools_follow_the_service pattern), and its
# routes answer with the service's shapes, status codes and error codes, their timing knobs shortened and put back afterwards. Offline:
# the mock on 127.0.0.1 and the tnt modules with fakes only.
# Packet capture is the live analyser of its own page (/api/capture and below, ui/js/views/capture.js), not a Tools card any more.
import contextlib
import http.client
import json
import queue
import re
import struct
import threading
import time
from collections import deque
from types import SimpleNamespace
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import pytest

SEED_CAPTURE = "TNT-capture-20260101-120000.pcapng"
CROSS_SITE_HEADERS = ({"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}, {"Origin": "null"})


@pytest.fixture(scope="module")
def offline():
    """The mock module and one MockState with no server, for the parity checks."""
    mod = _load_mock()
    return SimpleNamespace(mod=mod, state=mod.MockState(0))


@contextlib.contextmanager
def _knobs(state: Any, **values: Any) -> Iterator[Any]:
    """Set MockState attributes for a block and put the old values back in finally."""
    old = {name: getattr(state, name) for name in values}
    for name, value in values.items():
        setattr(state, name, value)
    try:
        yield state
    finally:
        for name, value in old.items():
            setattr(state, name, value)


def _send(port: int, method: str, path: str, body: Optional[Dict[str, Any]] = None,
          headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        sent = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            sent["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=sent)
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
    finally:
        conn.close()


def _until(fn: Callable[[], Any], timeout: float = 5.0) -> Any:
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(0.02)
    return fn()


def _frames(q: "queue.Queue[str]", kinds: Tuple[str, ...], until: Callable[[str, Any], bool], timeout: float = 5.0) -> List[Tuple[str, Any]]:
    """(type, data) of the hub frames of `kinds` until `until(type, data)` holds."""
    got: List[Tuple[str, Any]] = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            frame = q.get(timeout=0.1)
        except queue.Empty:
            continue
        kind = frame.split("\n")[0][7:]
        if kind in kinds:
            got.append((kind, json.loads(frame.split("\n")[1][6:])))
            if until(*got[-1]):
                break
    return got


def _outcome(fn: Callable[[], Any]) -> Tuple[str, Any]:
    try:
        return ("ok", fn())
    except ValueError as exc:
        return ("error", str(exc))


def _same(mod: Any, service: Any, pairs: Dict[str, str]) -> None:
    for mine, theirs in pairs.items():
        assert getattr(mod, mine) == getattr(service, theirs), mine


# --------------------------------------------------------------------------------------------------- parity: the mirrored rules
def test_mock_nat_check_follows_the_service(offline):
    from tnt import natcheck
    mod, state = offline.mod, offline.state
    _same(mod, natcheck, {k: k for k in ("NAT_VERDICTS", "NAT_RESULT_KEYS", "ROUTER_KEYS", "NATPMP_KEYS", "UPNP_KEYS", "TRACE_KEYS", "HOP_KEYS",
                                         "PORT_MAPPINGS_KEYS", "MAPPING_KEYS", "CONFIDENCES", "NAT_TEXT")})
    _same(mod, natcheck, {"NAT_NO_INTERNET_ERROR": "NO_INTERNET_ERROR", "NAT_NO_PUBLIC_IP_ERROR": "NO_PUBLIC_IP_ERROR",
                          "NAT_NO_GATEWAY_ERROR": "NO_GATEWAY_ERROR", "NAT_CONTROL_NOT_ROUTER_ERROR": "CONTROL_NOT_ROUTER_ERROR",
                          "NAT_MAPPINGS_NOT_SHARED_ERROR": "MAPPINGS_NOT_SHARED_ERROR", "NAT_BUSY_TEXT": "BUSY_TEXT"})
    assert mod.NAT_UPNP_SERVICE in natcheck.SERVICE_TYPES
    # every result has the service's keys, and the service's own verdict rules give the mock's verdict for its router's answers
    try:
        for profile, verdict in (("a", "single_nat"), ("b", "cgnat"), ("static-bad", "offline"), ("apipa", "offline"), ("none", "offline")):
            state.net_profile = profile
            r = state._nat_result(time.time())
            assert list(r) == list(natcheck.NAT_RESULT_KEYS) and list(r["router"]) == list(natcheck.ROUTER_KEYS), profile
            assert list(r["router"]["natpmp"]) == list(natcheck.NATPMP_KEYS) and list(r["router"]["upnp"]) == list(natcheck.UPNP_KEYS)
            assert r["verdict"] == verdict and (r["title"], r["explanation"]) == natcheck.NAT_TEXT[verdict], profile
            if verdict == "offline":
                assert r["confidence"] is None and r["router"]["upnp"] == natcheck._empty_upnp() and r["public_ip"] is None
                assert r["error"] == (natcheck.NO_PUBLIC_IP_ERROR if profile == "static-bad" else natcheck.NO_INTERNET_ERROR)
                continue
            wan = r["router"]["wan_ip"]
            assert natcheck.range_of(wan) in ("public", "shared") and natcheck._usable_wan(wan)
            assert natcheck.evaluate_verdict(wan_ip=wan, public_ip=r["public_ip"], trace=None, unclear=False) == (r["verdict"], r["confidence"])
            mappings = r["port_mappings"]
            assert mappings is None or (list(mappings) == list(natcheck.PORT_MAPPINGS_KEYS)
                                        and all(list(m) == list(natcheck.MAPPING_KEYS) for m in mappings["entries"]))
    finally:
        state.net_profile = "a"


def test_mock_switch_port_finder_follows_the_service(offline, monkeypatch, tmp_path):
    from tnt import lldp, pktmon, switchport
    mod, state = offline.mod, offline.state
    _same(mod, switchport, {"SWITCH_JOB_KEYS": "SWITCH_JOB_KEYS", "SWITCH_STATUS_KEYS": "SWITCH_STATUS_KEYS", "SWITCH_JOB_ADAPTER_KEYS": "JOB_ADAPTER_KEYS",
                            "SWITCH_WIRED_ADAPTER_KEYS": "WIRED_ADAPTER_KEYS", "SWITCH_JOB_STATES": "JOB_STATES",
                            "SWITCH_DEFAULT_SECONDS": "DEFAULT_SECONDS", "SWITCH_NO_WIRED_TEXT": "NO_WIRED_TEXT", "SWITCH_BUSY_TEXT": "BUSY_TEXT",
                            "SWITCH_NO_NEIGHBOR_TEXT": "NO_NEIGHBOR_TEXT"})
    assert mod.NEIGHBOR_KEYS == lldp.NEIGHBOR_KEYS and list(mod.MOCK_NEIGHBOR) == list(lldp.NEIGHBOR_KEYS)
    assert mod.PKTMON_REASONS == (pktmon.OLD_WINDOWS_REASON, pktmon.MISSING_REASON, pktmon.TOO_OLD_REASON)
    # a packet capture runs its own ETW session now and never takes Packet Monitor: the switch port search is the only holder
    assert mod.PKTMON_LOCK_TEXTS == {"switchport": pktmon.LOCK_TEXTS["switchport"]}
    assert "LOCK.acquire" not in (ROOT / "tnt" / "capture.py").read_text(encoding="utf-8"), "the capture takes no Packet Monitor lock"
    no_folder = {"work_dir_fn": lambda: tmp_path, "acl": lambda path, sddl: None}      # never the real captures folder
    default = switchport.SwitchPortFinder(None, **no_folder)
    assert mod.SWITCH_SECONDS_RANGE == (default._min_seconds, default._max_seconds)
    # a start that passed every check looks up the adapter's Packet Monitor component: note the adapter it chose, list none
    picked: List[str] = []
    monkeypatch.setattr(pktmon, "component_for", lambda adapter, components: picked.append(adapter["name"]))

    def service(profile: Dict[str, Any], adapter: Any, seconds: Any) -> Tuple[str, Any]:
        finder = switchport.SwitchPortFinder(None, adapters_fn=lambda: profile["adapters"], internet_nic_fn=lambda: mod.net_internet_nic(profile),
                                             capability_fn=lambda: {"ok": True, "reason": None}, components_fn=lambda: [],
                                             work_dir_fn=lambda: tmp_path, acl=lambda path, sddl: None)
        picked.clear()
        try:
            finder.start(adapter=adapter, seconds=seconds)
        except ValueError as exc:
            return ("400", str(exc))
        except pktmon.PktmonUnavailable as exc:
            if str(exc) != pktmon.NOT_LISTED_TEXT:
                return ("409", str(exc))
            return ("ok", (picked[-1], finder._listen_seconds(seconds)))       # the adapter it chose, the seconds it would listen
        return ("started", None)

    def mocked(adapter: Any, seconds: Any) -> Tuple[str, Any]:
        try:
            job = state.switch_start(adapter, seconds)
        except ValueError as exc:
            return ("400", str(exc))
        except mod.ToolRefused as exc:
            return (str(exc.status), str(exc))
        state.switch_stop()
        return ("ok", (job["adapter"]["name"], job["listen_s"]))

    cases = [(None, None), ("", 21), ("Ethernet", 20), ("Ethernet 2", 19.0), ("  Ethernet 3 ", 500), (None, -5), (None, 1e300), ("Nope", None),
             ("Wi-Fi", 65), (5, None), (None, "65"), (None, True), (None, 65.5), (None, float("nan")), ("x" * 60, None)]
    try:
        for profile_name in mod.NET_PROFILE_NAMES:          # "apipa": no internet adapter, so the first wired one
            state.net_profile = profile_name
            profile = mod.net_profile(profile_name)
            assert state.switch_status()["adapters"] == switchport.SwitchPortFinder(
                None, adapters_fn=lambda: profile["adapters"], internet_nic_fn=lambda: mod.net_internet_nic(profile),
                capability_fn=lambda: {"ok": True}, **no_folder).wired_adapters(), profile_name
            for adapter, seconds in cases:
                assert mocked(adapter, seconds) == service(profile, adapter, seconds), (profile_name, adapter, seconds)
    finally:
        state.switch_stop()
        state.net_profile = "a"
    assert pktmon.LOCK.holder() is None


def test_mock_port_forward_test_follows_the_service(offline):
    from tnt import portcheck
    mod, state = offline.mod, offline.state
    _same(mod, portcheck, {k: k for k in ("PORTCHECK_RESULT_KEYS", "PORTCHECK_PROTOCOL", "PORTCHECK_PORT_TEXT", "PORTCHECK_VPN_TEXT",
                                          "PORTCHECK_NO_IP_TEXT", "PORTCHECK_BUSY_TEXT", "PORTCHECK_RATE_TEXT", "PORTCHECKER_OPEN_DETAIL",
                                          "PORTCHECKER_CLOSED_DETAIL", "PORTCHECK_FAILED_TEXT")})
    _same(mod, portcheck, {"PORTCHECK_PROVIDERS": "PROVIDERS", "PORTCHECK_PROVIDER_NAMES": "PROVIDER_NAMES", "PORTCHECK_REASON_TIMEOUT": "REASON_TIMEOUT",
                           "PORTCHECK_MIN_GAP_S": "MIN_GAP_S", "PORTCHECK_PER_HOUR": "PER_HOUR", "PORTCHECK_RATE_WINDOW_S": "RATE_WINDOW_S"})
    for port in (0, 65536, -1, True, False, "8000", 8000.0, None):
        with pytest.raises(ValueError) as mocked:
            state.portcheck_test(port)
        with pytest.raises(ValueError) as service:
            portcheck.validate_port(port)
        assert str(mocked.value) == str(service.value), port
    # the rate limits: the same wait for the same monotonic starts, a limit of 0 switched off
    checker = portcheck.PortChecker(public_ip_fn=None, changed_ts_fn=None, refresh_fn=None, generation_fn=None, nat_verdict_fn=None)
    for gap, per_hour, starts, now in ((5.0, 30, [100.0], 102.4), (5.0, 30, [100.0], 105.0), (0.0, 2, [10.0, 20.0], 1000.0),
                                       (0.0, 2, [10.0, 20.0], 3610.0), (5.0, 0, [100.0, 101.0, 102.0], 103.5), (0.0, 0, [1.0], 1.0),
                                       (30.0, 3, [0.0, 1.0, 2.0], 2.5)):
        checker._min_gap_s, checker._per_hour = gap, per_hour
        checker._starts, checker._last_start = deque(starts), starts[-1]
        with _knobs(state, portcheck_min_gap_s=gap, portcheck_per_hour=per_hour, portcheck_starts=list(starts), portcheck_last_start=starts[-1]):
            assert state._portcheck_wait(now) == pytest.approx(checker._rate_wait(now)), (gap, per_hour, starts, now)


def _service_adapter(row: Dict[str, Any]) -> Any:
    """A mock adapter row as the attribute object the TFTP server reads (tnt.dhcp's adapter helpers, tnt.netinfo.get_internet_nic)."""
    return SimpleNamespace(index=row["index"], name=row["name"], description=row["description"], mac=row["mac"], if_type=row["if_type"],
                           type_name=row["type_name"], status=row["status"], is_up=row["status"] == "up", is_loopback=False,
                           is_physical=row["is_physical"], mtu=row["mtu"], gateways=list(row["gateways"]), metric_v4=row["metric_v4"] or 0,
                           primary_ipv4=row["ipv4"][0]["address"] if row["ipv4"] else None,
                           ipv4=[SimpleNamespace(address=e["address"], prefix=e["prefix"], preferred=True) for e in row["ipv4"]])


class _Config:
    """The tnt.config reads and writes a TftpServer makes."""

    def __init__(self, tftp_settings: Dict[str, Any]) -> None:
        self.data = {"tftp": dict(tftp_settings)}

    def get(self, dotted: str, default: Any = None) -> Any:
        section, _, leaf = dotted.partition(".")
        return self.data.get(section, {}).get(leaf, default)

    def update(self, patch: Dict[str, Any]) -> None:
        for section, values in patch.items():
            self.data.setdefault(section, {}).update(values)


def test_mock_tftp_server_follows_the_service(offline, monkeypatch, tmp_path):
    from tnt import config, netinfo, tftp
    from tnt.api import routes
    mod, state = offline.mod, offline.state
    _same(mod, tftp, {k: k for k in ("TFTP_STATUS_KEYS", "TFTP_SUMMARY_KEYS", "TFTP_TRANSFER_KEYS", "TFTP_ADAPTER_KEYS", "TFTP_COUNT_KEYS",
                                     "TFTP_SETTINGS_KEYS")})
    _same(mod, tftp, {"TFTP_TRANSFER_STATES": "TRANSFER_STATES", "TFTP_FIREWALL_RULE": "FIREWALL_RULE_NAME", "TFTP_PORT": "DEFAULT_PORT",
                      "TFTP_HISTORY_KEEP": "HISTORY_KEEP", "TFTP_MAX_UPLOAD_MB_TEXT": "MAX_UPLOAD_MB_MSG", "TFTP_MSG_CANCELLED": "MSG_CANCELLED"})
    assert mod.TFTP_MAX_UPLOAD_MB == (tftp.MAX_UPLOAD_MB_MIN, tftp.MAX_UPLOAD_MB_MAX)
    assert mod.TFTP_PORT_IN_USE_CODE == routes.TFTP_PORT_IN_USE_CODE
    assert mod.DEFAULTS["tftp"] == config.DEFAULTS["tftp"]
    assert all(tftp.clean_name(name) for name, _size, _age in mod.TFTP_FILES), "names a device could ask for"
    bus = SimpleNamespace(publish=lambda *args: None)

    def server(profile: Dict[str, Any], settings: Dict[str, Any]) -> Any:
        adapters = [_service_adapter(a) for a in profile["adapters"]]
        nic = next((a for a in adapters if a.index == profile["internet_nic_index"]), None)
        monkeypatch.setattr(netinfo, "_route_source_ip", lambda probe=None: nic.primary_ipv4 if nic is not None else None)
        # a root in tmp_path and a no-op folder securer: a start that got past its checks could never touch a real folder
        return tftp.TftpServer(None, _Config(settings), bus, adapters_fn=lambda: adapters, root=tmp_path / "tftp", acl=lambda path, sddl: None)

    patches = [{}, {"adapter": "Ethernet"}, {"adapter": "  Ethernet 3  "}, {"adapter": ""}, {"adapter": None}, {"adapter": 7}, {"adapter": "Wi-Fi"},
               {"adapter": "x" * 60}, {"max_upload_mb": 1}, {"max_upload_mb": 65536}, {"max_upload_mb": 0}, {"max_upload_mb": 65537},
               {"max_upload_mb": 12.5}, {"max_upload_mb": 100.0}, {"max_upload_mb": True}, {"max_upload_mb": "10"}, {"max_upload_mb": None},
               {"max_upload_mb": float("inf")}, {"port": 69}, {"zeta": 1, "alpha": 2}, {"adapter": "Ethernet", "max_upload_mb": 0}, []]
    starts = [{"uploads": "yes"}, {"uploads": None}, {"adapter": 5}, {"adapter": "Nope"}, {"adapter": " Wi-Fi 9 "}, {"adapter": "x" * 60}]   # refused everywhere
    try:
        for name in mod.NET_PROFILE_NAMES:
            state.net_profile = name
            profile = mod.net_profile(name)
            state.settings["tftp"] = dict(mod.DEFAULTS["tftp"])
            srv = server(profile, config.DEFAULTS["tftp"])
            # what the card shows while the server is off: the adapters, the one a start would pick, the settings, the summary
            mine, theirs = state.tftp_status(), srv.status()
            assert list(mine) == list(theirs), name
            assert {k: v for k, v in mine.items() if k != "root"} == {k: v for k, v in theirs.items() if k != "root"}, name
            assert state.tftp_summary() == srv.summary(), name
            for patch in patches:
                state.settings["tftp"] = dict(mod.DEFAULTS["tftp"])
                srv = server(profile, config.DEFAULTS["tftp"])
                got = _outcome(lambda: state.tftp_update_settings(patch)["settings"])
                assert got == _outcome(lambda: srv.update_settings(patch)["settings"]), (name, patch)
            for body in starts:
                srv = server(profile, config.DEFAULTS["tftp"])
                assert _outcome(lambda: state.tftp_start(body)) == _outcome(
                    lambda: srv.start(adapter=body.get("adapter"), uploads=body.get("uploads", False))), (name, body)
            for on in ("yes", None, 1):
                assert _outcome(lambda: state.tftp_set_uploads(on)) == _outcome(lambda: server(profile, config.DEFAULTS["tftp"]).set_uploads(on))
    finally:
        state.net_profile = "a"
        state.settings["tftp"] = dict(mod.DEFAULTS["tftp"])


def test_mock_packet_capture_follows_the_service(offline, tmp_path):
    """The live analyser (tnt.capture, with tnt.dissect's filters and tnt.sipcalls' calls): every key tuple, state, limit
    and text the mock mirrors is the service's, its start checks the body exactly as CaptureManager.start does, and the
    saved capture it hands out is a pcapng the service's own reader accepts."""
    from tnt import capture, dissect, pcapng, sipcalls
    from tnt.api import routes
    mod, state = offline.mod, offline.state
    _same(mod, capture, {k: k for k in ("CAPTURE_STATUS_KEYS", "CAPTURE_FILE_KEYS", "CAPTURE_ADAPTER_KEYS", "CAPTURE_SECONDS",
                                        "CAPTURE_SIZES_MB")})
    _same(mod, capture, {"CAPTURE_SESSION_KEYS": "SESSION_KEYS", "CAPTURE_ROW_KEYS": "ROW_KEYS", "CAPTURE_LIMIT_KEYS": "LIMIT_KEYS",
                         "CAPTURE_PACKETS_KEYS": "PACKETS_KEYS", "CAPTURE_DETAIL_KEYS": "DETAIL_KEYS", "CAPTURE_TILE_KEYS": "TILE_KEYS",
                         "CAPTURE_SESSION_STATES": "SESSION_STATES", "CAPTURE_STOP_REASONS": "STOP_REASONS",
                         "CAPTURE_DEFAULT_SECONDS": "DEFAULT_SECONDS", "CAPTURE_DEFAULT_MB": "DEFAULT_MB", "CAPTURE_MAX_ROWS": "MAX_ROWS",
                         "CAPTURE_MAX_PACKETS": "MAX_PACKETS", "CAPTURE_ROW_LIMIT": "DEFAULT_ROW_LIMIT",
                         "CAPTURE_MAX_ROW_LIMIT": "MAX_ROW_LIMIT", "CAPTURE_TICK_S": "TICK_S", "CAPTURE_FILE_RE": "FILE_RE",
                         "CAPTURE_ADAPTER_TEXT": "ADAPTER_TEXT", "CAPTURE_SECONDS_TEXT": "SECONDS_TEXT", "CAPTURE_SIZE_TEXT": "SIZE_TEXT",
                         "CAPTURE_BUSY_TEXT": "BUSY_TEXT", "CAPTURE_NOTHING_TEXT": "NOTHING_TEXT",
                         "CAPTURE_FILE_MISSING_TEXT": "FILE_MISSING_TEXT"})
    # the packet list's own shapes come from tnt.dissect, the calls from tnt.sipcalls
    assert (mod.CAPTURE_LAYER_KEYS, mod.CAPTURE_FIELD_KEYS) == (dissect.DETAIL_KEYS, dissect.FIELD_KEYS)
    assert mod.CAPTURE_PROTO_FILTERS == {k: dissect.PROTO_FILTERS[k] for k in mod.CAPTURE_PROTO_FILTERS}
    page = _read("js/views/capture.js")
    at = page.index("const PROTO_BUTTONS = [")
    buttons = set(re.findall(r"\{ key: '(\w+)'", page[at:page.index("];", at)]))
    assert buttons and buttons <= set(mod.CAPTURE_PROTO_FILTERS), sorted(buttons - set(mod.CAPTURE_PROTO_FILTERS))
    assert (mod.SIP_CALL_KEYS, mod.SIP_STREAM_KEYS, mod.SIP_MESSAGE_KEYS) == (sipcalls.CALL_KEYS, sipcalls.STREAM_KEYS, sipcalls.MESSAGE_KEYS)
    source = (ROOT / "tnt" / "capture.py").read_text(encoding="utf-8")
    for text in (mod.CAPTURE_PACKET_GONE_TEXT, mod.CAPTURE_NO_AUDIO_TEXT):
        assert f'"{text}"' in source, text                     # the two the service writes inline, not as a constant
    assert (mod.CAPTURE_ADMIN_REQUIRED_MSG, mod.CAPTURE_ADMIN_UNVERIFIED_MSG) == (routes.CAPTURE_ADMIN_REQUIRED_MSG,
                                                                                  routes.CAPTURE_ADMIN_UNVERIFIED_MSG)
    assert mod.ADMIN_ONLY_EVENTS == routes.ADMIN_ONLY_EVENTS == frozenset({capture.EVENT, capture.SIP_EVENT})
    assert set(routes.CAPTURE_START_KEYS) == {"adapter", "max_seconds", "max_mb"}
    assert capture._is_capture_name(mod.CAPTURE_SEED_FILE) and mod.CAPTURE_SEED_PACKETS > 0
    assert set(routes.TYPED_ERRORS["tnt.capture"].values()) == {(409, "conflict"), (404, "not_found"), (409, "unavailable")}

    # the list's filters and paging: the mock reads a query exactly as the service does
    mgr = capture.CaptureManager(None, captures_dir_fn=lambda: tmp_path, acl=lambda path, sddl: None)    # never the real folder
    assert state.capture_limits() == mgr.limits()
    for value in ("d8:bb:c1:12:34:08", "D8-BB-C1-12-34-08", "d8bbc1123408", "D8:BB:C1:12:34", "", "  ", None, 5, "192.0.2.10"):
        assert mod.capture_norm_mac(value) == capture._norm_mac(value), value
    for value in ("192.0.2.10", " 2001:0DB8::1 ", "2001:db8::1%12", "192.0.2.0/24", "example.com", "", None, 5, True):
        assert mod.capture_norm_ip(value) == capture._norm_ip(value), value
    for value in (None, "", "5", 5, 5.9, True, False, -3, 10 ** 9, "x", [1]):
        assert mod.capture_whole(value, mod.CAPTURE_ROW_LIMIT, 1, mod.CAPTURE_MAX_ROW_LIMIT) == capture._whole(
            value, capture.DEFAULT_ROW_LIMIT, 1, capture.MAX_ROW_LIMIT), value
    for protos in (None, (), ["sip"], ["SIP", " rtp "], "sip,rtp", "icmp, arp ,nope", ["sip", "sip", "dns"], ("udp", "tcp"), ["nope"], 5):
        assert mod.capture_proto_keys(protos) == mgr._make_filter(protos=protos).protos, protos

    # a row matches the same filters here as tnt.dissect's matchers give for the same row
    rows, metas, calls = mod.capture_make_rows(160, 1767268800.0, 4242)
    assert len(rows) == len(metas) == 160 and len(calls) == 1
    seen = {row["proto"] for row in rows}
    assert {"SIP", "RTP"} <= seen and len(seen) >= 6, seen
    filters = [(None, None, None), ("192.0.2.50", None, None), (mod.CAPTURE_PHONE["ip"], None, ["sip"]),
               (None, mod.CAPTURE_PBX["mac"].upper(), None), (None, "02-00-5E-00-00-60", ["rtp", "sip"]),
               (None, None, ["icmp", "arp"]), ("2001:db8::50", None, ["https"]), (None, None, ["tcp"])]
    for ip, mac, protos in filters:
        keys = mod.capture_proto_keys(protos)
        for row, meta in zip(rows, metas):
            summary = dict(row, layers=list(meta["layers"]))
            want = ((not ip or dissect.matches_ip(summary, ip)) and (not mac or dissect.matches_mac(summary, mac))
                    and (not keys or any(dissect.matches_proto(summary, key) for key in keys)))
            got = mod.capture_matches(row, meta["layers"], mod.capture_norm_ip(ip), mod.capture_norm_mac(mac), keys)
            assert got == want, (ip, mac, protos, row)
    # a filter the service cannot read is ignored, never refused
    assert mod.capture_norm_ip("example.com") == "" and mod.capture_norm_mac("nope") == "" and mod.capture_proto_keys(["nope"]) == ()

    # the start: the body checked in the service's order, the values it would have run with
    bodies = [{"adapter": "Ethernet"}, {}, {"adapter": None}, {"adapter": ""}, {"adapter": 5}, {"adapter": "Wi-Fi"}, {"adapter": "Tailscale"},
              {"adapter": "  Ethernet 2 "}, {"adapter": "Nope", "max_seconds": 5}]
    for key, values in (("max_seconds", [60, 300, 900, 1800, 3600, 5, 59, 3601, 900.0, "900", None, True]),
                        ("max_mb", [64, 128, 256, 512, 1024, 1, 100, 256.0, "256", None, True, False])):
        bodies += [{"adapter": "Ethernet", key: value} for value in values]

    def refuse(path: str, sddl: str) -> None:
        raise OSError("no folder is secured in this test")

    try:
        for name in mod.NET_PROFILE_NAMES:
            state.net_profile = name
            profile = mod.net_profile(name)
            # this PC can capture and nothing else runs: a start that passed its checks stops at the folder securer
            mgr = capture.CaptureManager(None, adapters_fn=lambda: profile["adapters"], captures_dir_fn=lambda: tmp_path, acl=refuse,
                                         etw=SimpleNamespace(available=lambda: {"ok": True, "reason": None}))
            assert state.capture_adapters() == mgr.adapters(), name

            def service(body: Dict[str, Any]) -> Tuple[str, Any]:
                kwargs = {k: body[k] for k in routes.CAPTURE_START_KEYS if k in body}
                kwargs["adapter"] = body.get("adapter")
                try:
                    mgr.start(**kwargs)
                except ValueError as exc:
                    return ("error", str(exc))
                except capture.CaptureUnavailable as exc:
                    assert str(exc) == capture.FOLDER_TEXT, exc
                    return ("ok", {"adapter": mgr._check_adapter(body.get("adapter")),       # the values it would have run with
                                   "max_seconds": kwargs.get("max_seconds", capture.DEFAULT_SECONDS),
                                   "max_mb": kwargs.get("max_mb", capture.DEFAULT_MB)})
                return ("started", None)

            for body in bodies:
                assert _outcome(lambda: mod.capture_start_values(body, state.capture_adapters())) == service(body), (name, body)
            assert state.capture_session is None, "no start of this test opened a session"
    finally:
        state.net_profile = "a"

    # the download: a valid pcapng with one Ethernet packet the service's reader counts, checksums right
    data = mod.tiny_pcapng(1767268800.25)
    path = tmp_path / mod.CAPTURE_SEED_FILE
    path.write_bytes(data)
    assert data[:4] == b"\x0a\x0d\x0d\x0a" and pcapng.count_packets(str(path)) == 1
    [packet] = pcapng.read_packets(data)
    assert (packet["interface"], packet["linktype"], packet["caplen"], packet["origlen"]) == (0, 1, 58, 58)
    assert packet["ts"] == pytest.approx(1767268800.25, abs=1e-6)
    frame = packet["data"]
    assert frame[12:14] == b"\x08\x00" and mod._inet_checksum(frame[14:34]) == 0 and mod._inet_checksum(frame[34:]) == 0
    seeded = state.capture_status()["files"]
    assert [list(f) for f in seeded] == [list(capture.CAPTURE_FILE_KEYS)] and seeded[0]["name"] == mod.CAPTURE_SEED_FILE
    assert state.capture_download(mod.CAPTURE_SEED_FILE) == mod.tiny_pcapng(seeded[0]["created_ts"])


def _echoes(start: float, end: float, rtt: Callable[[int], float], lost: Any = (), skipped: Any = (), step: float = 0.1) -> List[Tuple[Any, ...]]:
    """Probe samples every `step` s in [start, end): echo i answers in rtt(i) ms, is lost when i is in `lost` and finds the pool full
    when i is in `skipped`."""
    out: List[Tuple[Any, ...]] = []
    i, t = 0, start
    while t < end - 1e-9:
        out.append((t, None, None) if i in skipped else (t, False, None) if i in lost else (t, True, rtt(i)))
        i += 1
        t = round(start + i * step, 6)
    return out


def test_mock_speed_quality_follows_the_service(offline):
    from tnt import reports
    from tnt.speedtest import quality
    mod, state = offline.mod, offline.state
    _same(mod, quality, {k: k for k in ("QUALITY_KEYS", "WINDOW_KEYS", "LOADED_EXTRA_KEYS", "BUFFERBLOAT_KEYS", "CALL_KEYS", "SCORE_KEYS",
                                        "CHECK_KEYS", "QUALITY_VERSION", "GRADES", "GRADE_TEXT", "REASON_TOO_SHORT", "REASON_MOST_LOST",
                                        "REASON_NO_REPLIES", "REASON_NO_BASELINE", "WARNING_SOME_LOST", "WARNING_DELAYED", "CALL_METHOD",
                                        "CALL_LABEL_WORST", "CALL_CHECKS")})
    _same(mod, quality, {"QUALITY_TARGET": "DEFAULT_TARGET", "QUALITY_INTERVAL_MS": "DEFAULT_INTERVAL_MS", "QUALITY_PAYLOAD": "DEFAULT_PAYLOAD",
                         "QUALITY_MIN_SENT": "MIN_SENT", "QUALITY_MIN_RECEIVED": "MIN_RECEIVED", "QUALITY_MOST_LOST_PCT": "MOST_LOST_PCT",
                         "QUALITY_SOME_LOST_PCT": "SOME_LOST_PCT", "QUALITY_SKIPPED_WARN_SHARE": "SKIPPED_WARN_SHARE",
                         "QUALITY_BASELINE_MIN_ANSWERED": "BASELINE_MIN_ANSWERED", "CALL_LABELS": "_CALL_LABELS", "GRADE_BOUNDS": "_GRADE_BOUNDS",
                         "QUALITY_SCOPE": "_SCOPE"})
    assert mod.REASON_NO_REPLIES.format(target="1.1.1.1") == "1.1.1.1 did not answer pings"
    for increase in (None, 0, 4.9, 5.0, 29.9, 30, 59.9, 60, 199.9, 200, 399.9, 400, 1e6):
        assert mod.bloat_grade(increase) == quality.bloat_grade(increase), increase
    for args in ((20, 2, 0), (60, 15, 1), (150, 40, 2), (300, 60, 5), (0, 0, 0), (1000, 500, 50), (None, None, None), (139.9, 5, 0.4),
                 (100, 0, 35.5), (992, 0, 0)):
        assert mod.call_quality(*args) == quality.call_quality(*args), args

    # the whole grade: the mock's rules over the service's windows give build_quality's answer
    phases = {"baseline": (100.0, 103.0), "download": (103.0, 108.0), "upload": (108.0, 112.0)}
    base = _echoes(100.0, 103.0, lambda i: 14.0 + i % 3)
    down = _echoes(103.0, 108.0, lambda i: 26.0 + i % 5, lost={47})
    up = _echoes(108.0, 112.0, lambda i: 52.0 + 2 * (i % 4))
    scenarios = [
        (base + down + up, phases),
        (base + _echoes(103.0, 108.0, lambda i: 90.0, lost={i for i in range(50) if i % 3}) + up, phases),        # most echoes lost: F
        (_echoes(100.0, 103.0, lambda i: 14.0, lost=set(range(30))) + down + up, phases),                       # the target never answered
        (base + _echoes(103.0, 104.0, lambda i: 30.0), {"baseline": (100.0, 103.0), "download": (103.0, 104.0)}),   # too short, no upload
        (base + down + _echoes(108.0, 112.0, lambda i: 40.0 + i % 7, lost={13, 19, 25}, skipped=set(range(10, 40, 5))), phases),  # warnings
        (down + up, {"download": (103.0, 108.0), "upload": (108.0, 112.0)}),                                    # no idle baseline
        (_echoes(100.0, 103.0, lambda i: 10.0) + _echoes(103.0, 108.0, lambda i: 450.0 + i) + up, phases),        # severe: F by the increase
    ]
    for n, (samples, spans) in enumerate(scenarios):
        split = quality._split_windows(samples, spans)
        stats = {name: None if chunk is None else quality.window_stats(chunk) for name, chunk in split.items()}
        expected = quality.build_quality(samples, spans, target="1.1.1.1", interval_ms=100, payload=32)
        assert mod.speed_quality(stats["baseline"], stats["download"], stats["upload"]) == expected, n

    # the mock's seeded tests carry a graded quality (None for a failed one); the phases and the Full Scan step are the service's
    for row in state.speedtests[-100:]:
        q = row["quality"]
        if not row["ok"]:
            assert q is None
            continue
        assert list(q) == list(quality.QUALITY_KEYS) and q["available"] is True and q["target"] == "1.1.1.1"
        assert list(q["windows"]["baseline"]) == list(quality.WINDOW_KEYS)
        assert list(q["windows"]["upload"]) == list(quality.WINDOW_KEYS) + list(quality.LOADED_EXTRA_KEYS)
        assert q["bufferbloat"]["grade"] in ("A", "B") and q["bufferbloat"]["text"] == quality.GRADE_TEXT[q["bufferbloat"]["grade"]]
        assert [c["key"] for c in q["call"]["checks"]] == ["zoom", "teams"] and list(q["call"]) == list(quality.CALL_KEYS)
    assert any(not r["ok"] for r in state.speedtests) and any(r["ok"] for r in state.speedtests)
    assert [phase for phase, _seconds in mod.SPEED_PHASES] == ["baseline", "latency", "download", "upload"]
    for phase, (base_frac, span) in mod.REPORT_SPEED_STEPS.items():
        start, end = reports.SPEED_STEPS[phase]
        assert (base_frac, base_frac + span) == (pytest.approx(start), pytest.approx(end)), phase


def test_mock_dns_record_types_follow_the_service(offline):
    from tnt import nettools
    mod, state = offline.mod, offline.state
    assert (mod.DNS_RESULT_KEYS, mod.DNS_TYPES, mod.DNS_ALL_TYPES) == (nettools.DNS_RESULT_KEYS, nettools.DNS_TYPES, nettools.ALL_TYPES)
    assert (mod.DNS_NO_RECORDS_MSG, mod.DNS_BAD_TYPE_MSG, mod.DNS_IP_TYPE_MSG) == (nettools.NO_RECORDS_TEXT, nettools.BAD_TYPE_TEXT, nettools.IP_TYPE_TEXT)
    assert f'"{mod.DNS_TYPE_NOT_TEXT_MSG}"' in (ROOT / "tnt" / "api" / "routes.py").read_text(encoding="utf-8")
    for value in (None, "", "   ", "a", "mx", " Mx ", "NAPTR", "naptr", "all", "ALL", " All ", "AXFR", "ANY", "txt.",
                  chr(0x17F) + "oa", "q" * 90 + " z", 5, 1.5, True):
        assert _outcome(lambda: mod.dns_query_type(value)) == _outcome(lambda: nettools.validate_type(value)), value
    # name, then server, then type, then an address asked for another type than PTR; the typed rows are in the service's formats
    with _knobs(state, dns_delay_s=0.0):
        for name, server, rtype in (("", None, "MX"), ("bad name", None, "BAD"), ("example.com", "bad server", "BAD"), ("example.com", None, "BAD"),
                                    ("203.0.113.10", None, "MX"), ("203.0.113.10", None, "ptr"), ("203.0.113.10", None, "all"),
                                    ("2001:db8::10.", None, "A"), ("example.com", None, " mx "), ("example.com", None, "all"),
                                    ("example.com", "1.1.1.1", None)):
            mocked = _outcome(lambda: state.dns_lookup({"name": name, "server": server, "type": rtype})["type"])
            service = _outcome(lambda: nettools.validate_lookup(name, server, rtype)[2])
            assert mocked == service, (name, server, rtype)
    rows = {row[0]: row for rows in mod.DNS_ZONE.values() for row in rows}
    assert set(rows) >= {"MX", "TXT", "NS", "SOA", "CAA", "SRV", "PTR", "NAPTR"}
    assert rows["NAPTR"] == ("NAPTR", "example.com", '100 10 "S" "SIP+D2U" "" _sip._udp.example.com', 3600)
    assert len(rows["SOA"][2].split()) == 7 and len(rows["SRV"][2].split()) == 4 and rows["CAA"][2] == '0 issue "letsencrypt.org"'


def test_mock_guards_every_state_changing_network_tool_route(offline):
    """The routes the mock refuses to a page of another origin are the service's POST, PUT and DELETE routes of the network tools,
    and the capture download."""
    from tnt.api import routes
    mod = offline.mod
    table = routes.build_routes(SimpleNamespace(), SimpleNamespace(port=7130)).patterns()
    tools = [(pattern, methods) for pattern, methods in table
             if pattern.startswith(("/api/netcheck/", "/api/tftp/", "/api/capture", "/api/proav", "/api/sip"))]
    assert len(tools) >= 20 and not [p for p, _m in table if p.startswith("/api/tools/capture")], "packet capture has its own routes now"
    changing = set()
    for pattern, methods in tools:
        path = pattern[len("/api"):]
        if "{name}" in pattern:
            assert mod.network_tool_route(path.replace("{name}", mod.CAPTURE_SEED_FILE)), pattern
        elif set(methods) & {"POST", "PUT", "DELETE"}:
            changing.add(path)
        else:
            assert not mod.network_tool_route(path), pattern
    assert changing == set(mod.NETWORK_TOOL_ROUTES)
    assert mod.QUICK_TOOLS_CROSS_ORIGIN_MSG == routes.QUICK_TOOLS_CROSS_ORIGIN_MSG
    assert {code for errors in routes.TYPED_ERRORS.values() for _status, code in errors.values()} == {
        "conflict", "unavailable", "rate_limited", "no_public_ip", "vpn", "tftp_port_in_use", "not_found",
        "bad_request"}


# ------------------------------------------------------------------------------------------------------------ the mock's routes
def test_mock_nat_check_routes(mock):
    state, port = mock.state, mock.port
    with _knobs(state, nat_last=None):
        assert _req(port, "GET", "/api/netcheck/nat")[2] == {"result": None, "running": False}
        st, _, run = _req(port, "POST", "/api/netcheck/nat", {})
        assert st == 200 and run["running"] is False
        r = run["result"]
        assert list(r) == list(mock.mod.NAT_RESULT_KEYS) and r["generation"] == _req(port, "GET", "/api/status")[2]["net"]["generation"]
        assert (r["verdict"], r["confidence"], r["title"], r["public_ip"], r["error"], r["trace"]) == (
            "single_nat", "high", "Single NAT", "203.0.113.5", None, None)
        assert r["router"] == {"gateway": "10.0.0.251", "wan_ip": "203.0.113.5", "wan_source": "upnp",
                               "natpmp": {"answered": True, "result": 0, "external_ip": "203.0.113.5"},
                               "upnp": {"found": True, "server": "ExampleOS/1.0 UPnP/1.1 MiniUPnPd/2.2.0", "model": "Example Router XR-1",
                                        "service": "urn:schemas-upnp-org:service:WANIPConnection:1", "status": "Connected",
                                        "external_ip": "203.0.113.5", "error": None}}
        assert [(m["protocol"], m["external_port"], m["internal_client"], m["internal_port"]) for m in r["port_mappings"]["entries"]] == [
            ("TCP", 8000, "10.0.0.60", 8000), ("TCP", 554, "10.0.0.61", 554)]
        assert _req(port, "GET", "/api/netcheck/nat")[2] == {"result": r, "running": False}, "kept for this network"
        # a check that takes a while: GET says so and a second POST is refused
        with _knobs(state, nat_delay_s=0.4):
            answers: Dict[str, Any] = {}
            th = threading.Thread(target=lambda: answers.update(slow=_req(port, "POST", "/api/netcheck/nat", {})), daemon=True)
            th.start()
            assert _until(lambda: state.nat_running)
            assert _req(port, "GET", "/api/netcheck/nat")[2]["running"] is True
            st, _, busy = _req(port, "POST", "/api/netcheck/nat", {})
            assert st == 409 and busy["error"] == {"code": "conflict", "message": "a NAT check is already running"}
            th.join(timeout=5)
        assert answers["slow"][0] == 200 and _req(port, "GET", "/api/netcheck/nat")[2]["running"] is False
        # the other networks; a network change forgets the result, a check it overtook answers for the network the check started
        # on (with that generation) and is not kept, and an offline result is never kept
        try:
            with _knobs(state, nat_delay_s=0.4):
                started = _req(port, "GET", "/api/status")[2]["net"]["generation"]
                overtaken: Dict[str, Any] = {}
                th = threading.Thread(target=lambda: overtaken.update(slow=_req(port, "POST", "/api/netcheck/nat", {})), daemon=True)
                th.start()
                assert _until(lambda: state.nat_running)
                state.switch_network("b")
                th.join(timeout=5)
            st, _, late = overtaken["slow"]
            assert st == 200 and (late["result"]["verdict"], late["result"]["generation"], late["result"]["public_ip"]) == (
                "single_nat", started, "203.0.113.5")
            assert _req(port, "GET", "/api/netcheck/nat")[2]["result"] is None
            cg = _req(port, "POST", "/api/netcheck/nat", {})[2]["result"]
            assert (cg["verdict"], cg["confidence"], cg["router"]["wan_ip"], cg["router"]["wan_source"], cg["public_ip"]) == (
                "cgnat", "high", "100.64.0.10", "natpmp", "198.51.100.77")
            assert cg["router"]["upnp"]["found"] is False and cg["port_mappings"] is None and cg["title"] == "Carrier-grade NAT (CGNAT)"
            for profile, error in (("static-bad", "no public address yet"), ("apipa", "no internet connection"), ("none", "no internet connection")):
                state.switch_network(profile)
                off = _req(port, "POST", "/api/netcheck/nat", {})[2]["result"]
                assert (off["verdict"], off["confidence"], off["error"], off["duration_ms"]) == ("offline", None, error, 0), profile
                assert _req(port, "GET", "/api/netcheck/nat")[2]["result"] is None, profile
        finally:
            state.switch_network("a")


def test_mock_switch_port_routes(mock):
    mod, state, port = mock.mod, mock.state, mock.port
    q = state.hub.subscribe()
    kept_capture = (state.capture_session, state.capture_next_id)
    try:
        with _knobs(state, switch_listen_s=0.3, switch_job=None, switch_kept={}):
            st, _, s = _req(port, "GET", "/api/netcheck/switch")
            assert st == 200 and list(s) == list(mod.SWITCH_STATUS_KEYS) and (s["available"], s["reason"]) == (True, None)
            assert s["adapters"] == [{"name": "Ethernet", "index": 12, "mac": "D8:BB:C1:12:34:08", "is_internet": True},
                                     {"name": "Ethernet 2", "index": 18, "mac": "02:5E:10:00:00:18", "is_internet": False},
                                     {"name": "Ethernet 3", "index": 19, "mac": "02:5E:10:00:00:19", "is_internet": False}]
            assert list(s["job"]) == list(mod.SWITCH_JOB_KEYS) and s["job"]["state"] == "idle" and s["job"]["neighbors"] == []
            for body, message in (({"seconds": "65"}, "seconds must be a whole number from 20 to 120"),
                                  ({"adapter": "Wi-Fi"}, "adapter 'Wi-Fi' is not a wired adapter that is up"),
                                  ({"adapter": 5}, "adapter '5' is not a wired adapter that is up")):
                st, _, err = _req(port, "POST", "/api/netcheck/switch", body)
                assert st == 400 and err["error"] == {"code": "bad_request", "message": message}, body
            st, _, started = _req(port, "POST", "/api/netcheck/switch", {"adapter": None, "seconds": None})
            job = started["job"]
            assert st == 200 and list(job) == list(mod.SWITCH_JOB_KEYS)
            assert (job["state"], job["adapter"], job["listen_s"], job["neighbors"], job["error"]) == (
                "listening", {"name": "Ethernet", "index": 12, "mac": "D8:BB:C1:12:34:08"}, 65, [], None)
            st, _, busy = _req(port, "POST", "/api/netcheck/switch", {"adapter": "Ethernet 3"})
            assert st == 409 and busy["error"] == {"code": "conflict", "message": "a switch port search is already running"}
            # a packet capture runs its own ETW session: it and the switch port search no longer block each other
            with _knobs(state, capture_s=30.0, capture_reason=None):
                st, _, together = _req(port, "POST", "/api/capture/start", {"adapter": "Ethernet"})
                assert st == 200 and together["session"]["state"] == "capturing", together
                assert _req(port, "GET", "/api/netcheck/switch")[2]["job"]["state"] == "listening", "the search kept listening"
                assert _req(port, "GET", "/api/capture")[2]["session"]["state"] == "capturing"
                assert _req(port, "GET", "/api/status")[2]["capture"]["running"] is True
                state.capture_discard()
            frames = _frames(q, ("netcheck.switch",), lambda kind, data: data["job"]["state"] == "done")
            assert frames and frames[-1][1]["job"]["state"] == "done"
            done = _req(port, "GET", "/api/netcheck/switch")[2]["job"]
            assert (done["state"], done["neighbors"], done["reason"], done["elapsed_s"]) == ("done", [mod.MOCK_NEIGHBOR], None, 0.3)
            assert done["neighbors"][0]["switch_name"] == "LAB-SW-01" and done["neighbors"][0]["port_id"] == "Port 7"
            # another search, cancelled: nothing heard, nothing kept for it
            job = _req(port, "POST", "/api/netcheck/switch", {"adapter": "Ethernet 2", "seconds": 500})[2]["job"]
            assert job["listen_s"] == 120 and job["adapter"]["name"] == "Ethernet 2"
            st, _, stopped = _req(port, "DELETE", "/api/netcheck/switch")
            assert st == 200 and stopped["job"]["state"] == "cancelled" and stopped["job"]["neighbors"] == []
            assert _req(port, "DELETE", "/api/netcheck/switch")[2]["job"]["state"] == "cancelled"
        with _knobs(state, switch_listen_s=0.05, switch_found=False, switch_job=None, switch_kept={}):
            _req(port, "POST", "/api/netcheck/switch", {"seconds": 20})
            quiet = _until(lambda: (lambda j: j if j["state"] == "done" else None)(_req(port, "GET", "/api/netcheck/switch")[2]["job"]))
            assert quiet["neighbors"] == [] and quiet["reason"] == mod.SWITCH_NO_NEIGHBOR_TEXT.format(seconds=20)
            # a network change forgets it; network "b" has no wired adapter
            try:
                state.switch_network("b")
                s = _req(port, "GET", "/api/netcheck/switch")[2]
                assert s["job"]["state"] == "idle" and s["adapters"] == []
                st, _, err = _req(port, "POST", "/api/netcheck/switch", {})
                assert st == 409 and err["error"] == {"code": "unavailable", "message": "Needs a wired (Ethernet) connection"}
            finally:
                state.switch_network("a")
        with _knobs(state, pktmon_reason=mod.PKTMON_REASONS[2]):
            s = _req(port, "GET", "/api/netcheck/switch")[2]
            assert (s["available"], s["reason"]) == (False, "Packet Monitor on this PC is too old for this: update Windows")
            st, _, err = _req(port, "POST", "/api/netcheck/switch", {})
            assert st == 409 and err["error"] == {"code": "unavailable", "message": s["reason"]}
    finally:
        state.hub.unsubscribe(q)
        state.switch_stop()
        state.capture_discard()
        state.capture_session, state.capture_next_id = kept_capture


def test_mock_port_forward_routes(mock, monkeypatch):
    mod, state, port = mock.mod, mock.state, mock.port
    monkeypatch.setattr(mod, "NET_RECHECK_S", 0.0)          # the WAN address of a network is looked up at once after a change
    # the tests run here are not left in the rate limits, nor their last result
    monkeypatch.setattr(state, "portcheck_starts", list(state.portcheck_starts))
    monkeypatch.setattr(state, "portcheck_last_start", state.portcheck_last_start)
    monkeypatch.setattr(state, "portcheck_last", state.portcheck_last)

    def test(body: Dict[str, Any]) -> Tuple[int, Dict[str, str], Any]:
        return _req(port, "POST", "/api/netcheck/portforward", body)

    with _knobs(state, portcheck_delay_s=0.0, portcheck_min_gap_s=0, portcheck_per_hour=0):
        gen = _req(port, "GET", "/api/status")[2]["net"]["generation"]
        st, _, open_ = test({"port": 8000})
        assert st == 200 and list(open_) == list(mod.PORTCHECK_RESULT_KEYS)
        assert (open_["port"], open_["protocol"], open_["public_ip"], open_["reachable"], open_["provider"], open_["detail"], open_["error"],
                open_["generation"]) == (8000, "tcp", "203.0.113.5", True, "portchecker.io", "portchecker.io connected to the port", None, gen)
        assert open_["nat_verdict"] == (state.nat_last or {}).get("verdict") and isinstance(open_["duration_ms"], int)
        shut = test({"port": 8001})[2]
        assert (shut["reachable"], shut["provider"], shut["detail"], shut["error"]) == (
            False, "portchecker.io", "portchecker.io could not connect (tried twice)", None)
        failed = test({"port": 9})[2]
        assert (failed["reachable"], failed["provider"], failed["detail"]) == (None, "globalping", None)
        assert failed["error"] == "The port checkers could not be reached: portchecker.io did not answer in time, Globalping did not answer in time"
        assert state.portcheck_last == failed
        for body in ({"port": 0}, {"port": 65536}, {"port": "8000"}, {"port": 8000.5}, {"port": True}, {}):
            st, _, err = test(body)
            assert st == 400 and err["error"] == {"code": "bad_request", "message": "port must be a whole number from 1 to 65535"}, body
    # the service's limits: a gap between the starts of two tests, and so many tests an hour, with Retry-After
    with _knobs(state, portcheck_delay_s=0.0, portcheck_min_gap_s=30.0, portcheck_per_hour=0, portcheck_starts=[], portcheck_last_start=None):
        assert test({"port": 8000})[0] == 200
        st, headers, err = test({"port": 8000})
        assert st == 429 and err["error"] == {"code": "rate_limited", "message": "Too many tests: wait 30 s"} and headers["retry-after"] == "30"
    with _knobs(state, portcheck_delay_s=0.0, portcheck_min_gap_s=0, portcheck_per_hour=2, portcheck_starts=[], portcheck_last_start=None):
        assert [test({"port": 8000})[0] for _ in range(2)] == [200, 200]
        st, headers, err = test({"port": 8000})
        assert st == 429 and err["error"]["message"] == "Too many tests: wait 3600 s" and headers["retry-after"] == "3600"
    # one test at a time
    with _knobs(state, portcheck_delay_s=0.4, portcheck_min_gap_s=0, portcheck_per_hour=0):
        answers: Dict[str, Any] = {}
        th = threading.Thread(target=lambda: answers.update(slow=test({"port": 8000})), daemon=True)
        th.start()
        assert _until(lambda: state.portcheck_running)
        st, _, busy = test({"port": 8001})
        assert st == 409 and busy["error"] == {"code": "conflict", "message": "a port-forward test is already running"}
        th.join(timeout=5)
        assert answers["slow"][0] == 200
    # a network change forgets the result; no public address (no internet) is a 409, a VPN verdict too
    with _knobs(state, portcheck_delay_s=0.0, portcheck_min_gap_s=0, portcheck_per_hour=0):
        try:
            state.switch_network("none")
            assert state.portcheck_last is None
            st, _, err = test({"port": 8000})
            assert st == 409 and err["error"] == {"code": "no_public_ip", "message": mod.PORTCHECK_NO_IP_TEXT}
        finally:
            state.switch_network("a")
        with _knobs(state, nat_last={"verdict": "vpn"}):
            st, _, err = test({"port": 8000})
            assert st == 409 and err["error"] == {"code": "vpn", "message": mod.PORTCHECK_VPN_TEXT}
        assert test({"port": 8000})[2]["generation"] == _req(port, "GET", "/api/status")[2]["net"]["generation"]


def test_mock_tftp_server_routes(mock):
    mod, state, port = mock.mod, mock.state, mock.port
    q = state.hub.subscribe()
    kept = (state.tftp_history, dict(state.tftp_counts), state.tftp_next_id)
    try:
        with _knobs(state, tftp_fast=True):
            st, _, s = _req(port, "GET", "/api/tftp/status")
            assert st == 200 and list(s) == list(mod.TFTP_STATUS_KEYS)
            assert (s["available"], s["running"], s["error"], s["warning"], s["listen"], s["uploads"], s["conflict"], s["transfers"]) == (
                True, False, None, None, [], False, None, [])
            assert s["adapter"] == {"name": "Ethernet", "index": 12, "ip": "10.0.0.112", "prefix": 24, "type_name": "Ethernet", "is_physical": True,
                                    "is_internet": True, "status": "up"}
            assert [a["name"] for a in s["adapters"]] == ["Ethernet", "Tailscale", "vEthernet (Default Switch)", "Ethernet 2", "Ethernet 3"]
            assert s["firewall"] == {"rule": "TNT TFTP server (UDP 69 in)", "ok": None, "error": None} and s["root"].endswith("\\tftp")
            assert list(s["counts"]) == list(mod.TFTP_COUNT_KEYS) and s["settings"] == {"adapter": "", "max_upload_mb": 4096}
            summary = _req(port, "GET", "/api/status")[2]["tftp"]
            assert list(summary) == list(mod.TFTP_SUMMARY_KEYS) and summary["running"] is False
            files = _req(port, "GET", "/api/tftp/files")[2]["files"]
            assert [f["name"] for f in files] == ["boot/pxelinux.0", "firmware/lab-sw-fw-2.4.1.bin", "phones/SEP02005E100001.cnf.xml"]
            assert all(set(f) == {"name", "size", "mtime"} for f in files)
            for method, path, body, message in (
                    ("POST", "/api/tftp/start", {"uploads": "yes"}, "uploads must be true or false"),
                    ("POST", "/api/tftp/start", {"adapter": 5}, "adapter must be a name or null"),
                    ("POST", "/api/tftp/start", {"adapter": "Wi-Fi"}, "adapter 'Wi-Fi' is not up or has no IPv4 address"),
                    ("POST", "/api/tftp/uploads", {"on": "yes"}, "on must be true or false"),
                    ("PUT", "/api/tftp/settings", {"port": 69}, "unknown TFTP setting 'port'"),
                    ("PUT", "/api/tftp/settings", {"max_upload_mb": 0}, "max_upload_mb must be a whole number from 1 to 65536"),
                    ("PUT", "/api/tftp/settings", {"adapter": "Nope"}, "adapter 'Nope' is not up or has no IPv4 address")):
                st, _, err = _req(port, method, path, body)
                assert st == 400 and err["error"] == {"code": "bad_request", "message": message}, (path, body)
            try:
                st, _, saved = _req(port, "PUT", "/api/tftp/settings", {"adapter": " Ethernet 3 ", "max_upload_mb": 512})
                assert st == 200 and saved["settings"] == {"adapter": "Ethernet 3", "max_upload_mb": 512} and saved["adapter"]["name"] == "Ethernet 3"
                assert _req(port, "GET", "/api/settings")[2]["tftp"] == {"adapter": "Ethernet 3", "max_upload_mb": 512}
            finally:
                state.settings["tftp"] = dict(mod.DEFAULTS["tftp"])
            # on, with uploads; a phone reads its file; off again
            st, _, on = _req(port, "POST", "/api/tftp/start", {"adapter": None, "uploads": True})
            assert st == 200 and (on["running"], on["uploads"], on["listen"], on["adapter"]["name"]) == (True, True, [{"ip": "10.0.0.112", "port": 69}], "Ethernet")
            assert _req(port, "POST", "/api/tftp/start", {})[2]["since_ts"] == on["since_ts"], "already on: the status, unchanged"
            frames = _frames(q, ("tftp.state", "tftp.transfer"), lambda kind, data: kind == "tftp.transfer" and data["transfer"]["state"] == "done")
            began = [data for kind, data in frames if kind == "tftp.state" and data["running"]]
            assert began and list(began[0]) == list(mod.TFTP_SUMMARY_KEYS)
            assert (began[0]["adapter"], began[0]["listen_ips"], began[0]["uploads"], began[0]["since_ts"]) == ("Ethernet", ["10.0.0.112"], True, on["since_ts"])
            done = frames[-1][1]["transfer"]
            assert list(done) == list(mod.TFTP_TRANSFER_KEYS) and (done["op"], done["client"], done["bytes"], done["size"]) == (
                "read", "10.0.0.62", 4912, 4912)
            s = _until(lambda: (lambda x: x if x["history"] else None)(_req(port, "GET", "/api/tftp/status")[2]))
            assert s["history"][0]["id"] == done["id"] and s["counts"]["done"] >= 1 and s["transfers"] == []
            assert _req(port, "POST", "/api/tftp/uploads", {"on": False})[2]["uploads"] is False
            st, _, off = _req(port, "POST", "/api/tftp/stop", {})
            assert st == 200 and (off["running"], off["uploads"], off["listen"], off["since_ts"]) == (False, False, [], None)
            # another program holds UDP 69
            with _knobs(state, tftp_port_owners=[{"pid": 4242, "name": "tftpd64.exe"}]):
                st, _, conflict = _req(port, "POST", "/api/tftp/start", {})
                assert st == 409 and conflict == {"error": {"code": "tftp_port_in_use", "message": "UDP port 69 is already used by tftpd64.exe"},
                                                  "owners": [{"pid": 4242, "name": "tftpd64.exe"}]}
                s = _req(port, "GET", "/api/tftp/status")[2]
                assert s["running"] is False and s["conflict"] == {"port": 69, "owners": [{"pid": 4242, "name": "tftpd64.exe"}]}
            # a network change stops a running server
            assert _req(port, "POST", "/api/tftp/start", {})[2]["running"] is True and _req(port, "GET", "/api/tftp/status")[2]["conflict"] is None
            try:
                state.switch_network("b")
                s = _req(port, "GET", "/api/tftp/status")[2]
                assert (s["running"], s["error"], s["adapter"]["name"]) == (False, "stopped: the adapter changed", "Wi-Fi")
                assert _req(port, "GET", "/api/status")[2]["tftp"]["error"] == "stopped: the adapter changed"
            finally:
                state.switch_network("a")
    finally:
        state.hub.unsubscribe(q)
        state.tftp_stop()
        state.tftp_error = None
        with state.lock:                                     # the transfers seen here are not left in the card's history
            state.tftp_history, state.tftp_counts, state.tftp_next_id = kept[0], dict(kept[1]), kept[2]


#: every capture route of the service, as (the service's pattern, method, the mock's path, body): the whole surface the
#: administrator check guards (tnt.api.routes' "-- packet capture (its own page) --" block)
CAPTURE_ROUTES = (
    ("/api/capture", "GET", "/api/capture", None),
    ("/api/capture/start", "POST", "/api/capture/start", {"adapter": "Ethernet"}),
    ("/api/capture/stop", "POST", "/api/capture/stop", {}),
    ("/api/capture/save", "POST", "/api/capture/save", {}),
    ("/api/capture/discard", "POST", "/api/capture/discard", {}),
    ("/api/capture/open", "POST", "/api/capture/open", {"name": SEED_CAPTURE}),
    ("/api/capture/packets", "GET", "/api/capture/packets", None),
    ("/api/capture/packets/{no}", "GET", "/api/capture/packets/1", None),
    ("/api/capture/calls", "GET", "/api/capture/calls", None),
    ("/api/capture/calls/{call}/audio", "GET", "/api/capture/calls/a-call/audio", None),
    ("/api/capture/files/{name}", "GET", f"/api/capture/files/{SEED_CAPTURE}", None),
    ("/api/capture/files/{name}", "DELETE", f"/api/capture/files/{SEED_CAPTURE}", None),
)


def test_mock_capture_routes_need_a_windows_administrator(mock):
    """The service refuses every capture route to anyone but a Windows administrator (403 admin_required), the reads and
    the download included, and nothing it holds changes."""
    from tnt.api import routes
    mod, state, port = mock.mod, mock.state, mock.port
    table = routes.build_routes(SimpleNamespace(), SimpleNamespace(port=7130)).patterns()
    service = {(pattern, method) for pattern, methods in table if pattern.startswith("/api/capture") for method in methods}
    assert {(pattern, method) for pattern, method, _path, _body in CAPTURE_ROUTES} == service, "every capture route is tried here"

    def snapshot() -> Any:
        with state.lock:
            return json.dumps([state.capture_session, [f["name"] for f in state.capture_files], state.capture_total], sort_keys=True)

    before = snapshot()
    with _knobs(state, wifi_admin=False):
        for _pattern, method, path, body in CAPTURE_ROUTES:
            st, _, err = _req(port, method, path, body)
            assert st == 403 and err["error"] == {"code": "admin_required", "message": mod.CAPTURE_ADMIN_REQUIRED_MSG}, (method, path)
    assert snapshot() == before


def test_mock_packet_capture_routes(mock):
    """GET /api/capture and the analyser's own routes: the status and the Packet capture tile, a capture that runs its
    time and stops by itself (with its capture.state events), save, open, discard and the saved files."""
    from tnt import capture, etw
    mod, state, port = mock.mod, mock.state, mock.port
    seed_path = f"/api/capture/files/{SEED_CAPTURE}"
    seeded = [dict(f) for f in state.capture_files]
    before = (state.capture_session, state.capture_next_id)
    try:
        st, _, s = _req(port, "GET", "/api/capture")
        assert st == 200 and list(s) == list(mod.CAPTURE_STATUS_KEYS) and (s["available"], s["reason"], s["session"]) == (True, None, None)
        assert s["adapters"] == [{"name": "Ethernet", "index": 12, "mac": "D8:BB:C1:12:34:08", "type_name": "Ethernet", "wifi": False},
                                 {"name": "Ethernet 2", "index": 18, "mac": "02:5E:10:00:00:18", "type_name": "Ethernet", "wifi": False},
                                 {"name": "Ethernet 3", "index": 19, "mac": "02:5E:10:00:00:19", "type_name": "Ethernet", "wifi": False}]
        assert list(s["limits"]) == list(mod.CAPTURE_LIMIT_KEYS) and s["limits"] == {
            "max_rows": 50_000, "max_packets": 5_000_000, "seconds": [60, 300, 900, 1800, 3600],
            "sizes_mb": [64, 128, 256, 512, 1024], "default_seconds": 900, "default_mb": 256}
        assert [list(f) for f in s["files"]] == [list(mod.CAPTURE_FILE_KEYS)] and s["files"][0]["name"] == SEED_CAPTURE
        # the block /api/status carries for the Packet capture tile: counts and the adapter's name, never any packet
        tile = _req(port, "GET", "/api/status")[2]["capture"]
        assert list(tile) == list(capture.TILE_KEYS)
        assert tile == {"available": True, "reason": None, "running": False, "adapter": None, "packets": 0, "calls": 0, "files": 1}
        # the download, as a FileResponse: an attachment of its length, not cached, not sniffed; HEAD sends the headers only
        st, headers, data = _req(port, "GET", seed_path, raw=True)
        assert st == 200 and data == mod.tiny_pcapng(s["files"][0]["created_ts"]) and int(headers["content-length"]) == len(data)
        assert (headers["content-type"], headers["content-disposition"], headers["cache-control"], headers["x-content-type-options"]) == (
            "application/octet-stream", f'attachment; filename="{SEED_CAPTURE}"', "no-cache", "nosniff")
        st, head, body = _send(port, "HEAD", seed_path)
        assert st == 200 and body == b"" and head["content-length"] == str(len(data))
        for method, path in (("GET", "/api/capture/files/TNT-capture-20990101-000000.pcapng"), ("GET", "/api/capture/files/..%5Cx.pcapng"),
                             ("DELETE", "/api/capture/files/notes.txt")):
            st, _, err = _req(port, method, path)
            assert st == 404 and err["error"] == {"code": "not_found", "message": mod.CAPTURE_FILE_MISSING_TEXT}, path
        st, _, err = _req(port, "POST", "/api/capture/open", {"name": "notes.txt"})
        assert st == 404 and err["error"] == {"code": "not_found", "message": mod.CAPTURE_FILE_MISSING_TEXT}
        # a body with neither a saved capture's name nor a path on this PC is 400, as the service answers
        for body in ({}, {"name": None}):
            st, _, err = _req(port, "POST", "/api/capture/open", body)
            assert st == 400 and err["error"]["code"] == "bad_request", body
        # opening any file on this PC by its path: the same checks the service makes (tnt.capture._check_open_path)
        for bad in ("", "capture.pcapng", "..\\capture.pcapng", "\\\\server\\share\\x.pcapng"):
            st, _, err = _req(port, "POST", "/api/capture/open", {"path": bad})
            assert st == 400 and err["error"] == {"code": "bad_request", "message": mod.CAPTURE_PATH_TEXT}, bad
        st, _, ok = _req(port, "POST", "/api/capture/open", {"path": "C:\\Users\\me\\from-the-switch.pcapng"})
        assert st == 200 and ok["session"]["source"] == "file" and ok["session"]["file"] == "from-the-switch.pcapng"
        assert list(ok["session"]) == list(mod.CAPTURE_SESSION_KEYS)
        assert _req(port, "POST", "/api/capture/discard", {})[0] == 200
        st, _, err = _req(port, "POST", "/api/capture/save", {})
        assert st == 404 and err["error"] == {"code": "not_found", "message": mod.CAPTURE_NOTHING_TEXT}, "nothing is open"
        assert _req(port, "POST", "/api/capture/stop", {})[2] == {"session": None}
        for body, message in (({"adapter": "Wi-Fi"}, "adapter 'Wi-Fi' is not up"), ({}, "adapter '' is not up"),
                              ({"adapter": "Ethernet", "max_seconds": 45}, mod.CAPTURE_SECONDS_TEXT),
                              ({"adapter": "Ethernet", "max_mb": 100}, mod.CAPTURE_SIZE_TEXT)):
            st, _, err = _req(port, "POST", "/api/capture/start", body)
            assert st == 400 and err["error"] == {"code": "bad_request", "message": message}, body
        # this PC cannot capture at all
        with _knobs(state, capture_reason=etw.NOT_WINDOWS_REASON):
            st, _, err = _req(port, "POST", "/api/capture/start", {"adapter": "Ethernet"})
            assert st == 409 and err["error"] == {"code": "unavailable", "message": etw.NOT_WINDOWS_REASON}
            off = _req(port, "GET", "/api/capture")[2]
            assert (off["available"], off["reason"]) == (False, etw.NOT_WINDOWS_REASON)
            assert _req(port, "GET", "/api/status")[2]["capture"]["available"] is False
        # a capture that runs its time: capture.state while it runs, and once more when it stops by itself
        q = state.hub.subscribe()
        try:
            with _knobs(state, capture_s=0.5):
                st, _, started = _req(port, "POST", "/api/capture/start", {"adapter": "Ethernet", "max_seconds": 60, "max_mb": 64})
                session = started["session"]
                assert st == 200 and list(session) == list(mod.CAPTURE_SESSION_KEYS) and list(session["adapter"]) == list(mod.CAPTURE_ADAPTER_KEYS)
                assert (session["state"], session["source"], session["adapter"]["name"], session["file"], session["saved"], session["packets"],
                        session["truncated"], session["stop_reason"], session["error"]) == ("capturing", "live", "Ethernet", None, False, 0, False,
                                                                                            None, None)
                st, _, busy = _req(port, "POST", "/api/capture/start", {"adapter": "Ethernet 2"})
                assert st == 409 and busy["error"] == {"code": "conflict", "message": mod.CAPTURE_BUSY_TEXT}
                st, _, busy = _req(port, "POST", "/api/capture/open", {"name": SEED_CAPTURE})
                assert st == 409 and busy["error"] == {"code": "conflict", "message": mod.CAPTURE_BUSY_TEXT}
                running = _req(port, "GET", "/api/status")[2]["capture"]
                assert (running["running"], running["adapter"]) == (True, "Ethernet")
                frames = _frames(q, ("capture.state",), lambda kind, data: (data["session"] or {}).get("state") == "stopped")
                assert frames and all(list(data["session"]) == list(mod.CAPTURE_SESSION_KEYS) for _kind, data in frames)
                assert frames[-1][1]["session"]["stop_reason"] == "seconds"
            done = _req(port, "GET", "/api/capture")[2]["session"]
            assert (done["state"], done["source"], done["stop_reason"], done["saved"], done["file"]) == ("stopped", "live", "seconds", False, None)
            assert done["packets"] >= 1 and done["packets"] == done["shown"] and done["bytes"] > 0 and 0.4 <= done["elapsed_s"] < 5
            # saving lists it under a name of the service's own shape; saving again does nothing
            st, _, saved = _req(port, "POST", "/api/capture/save", {})
            name = saved["session"]["file"]
            assert st == 200 and mod._CAPTURE_FILE.fullmatch(name) and name != SEED_CAPTURE
            assert (saved["session"]["saved"], saved["session"]["state"]) == (True, "stopped")
            row = next(f for f in saved["files"] if f["name"] == name)
            assert (row["packets"], row["size"]) == (done["packets"], max(len(data), done["bytes"]))
            assert [f["name"] for f in saved["files"]] == [name, SEED_CAPTURE], "newest first"
            assert _req(port, "POST", "/api/capture/save", {})[2]["session"]["file"] == name
            assert _req(port, "GET", f"/api/capture/files/{name}", raw=True)[2][:4] == b"\x0a\x0d\x0d\x0a"
            # a saved capture read back: the rows the file says it holds, its calls, and no adapter
            st, _, opened = _req(port, "POST", "/api/capture/open", {"name": SEED_CAPTURE})
            loaded = opened["session"]
            assert st == 200 and (loaded["state"], loaded["source"], loaded["file"], loaded["saved"], loaded["adapter"]) == (
                "loaded", "file", SEED_CAPTURE, True, None)
            assert (loaded["packets"], loaded["shown"], loaded["truncated"], loaded["dropped"]) == (
                mod.CAPTURE_SEED_PACKETS, mod.CAPTURE_SEED_PACKETS, False, 0)
            assert loaded["calls"] == 1 and loaded["id"] != done["id"]
            assert _req(port, "POST", "/api/capture/stop", {})[2]["session"]["state"] == "loaded", "nothing is running"
            # deleting the file that is open throws the open capture away with it
            st, _, left = _req(port, "DELETE", seed_path)
            assert st == 200 and [f["name"] for f in left["files"]] == [name]
            assert _req(port, "GET", "/api/capture")[2]["session"] is None
            gone = _frames(q, ("capture.state",), lambda kind, data: data["session"] is None)
            assert gone and gone[-1][1] == {"session": None}
        finally:
            state.hub.unsubscribe(q)
        # discard leaves nothing open and forgets the packets
        _req(port, "POST", "/api/capture/open", {"name": name})
        assert _req(port, "POST", "/api/capture/discard", {})[2] == {"session": None}
        empty = _req(port, "GET", "/api/capture")[2]
        assert empty["session"] is None and _req(port, "GET", "/api/capture/packets")[2]["rows"] == []
        assert [f["name"] for f in _req(port, "DELETE", f"/api/capture/files/{name}")[2]["files"]] == []
    finally:
        state.capture_discard()
        state.capture_files = seeded
        state.capture_session, state.capture_next_id = before


def test_mock_capture_packet_list_is_filtered_and_paged_like_the_service(mock, monkeypatch):
    """GET /api/capture/packets: the newest `limit` rows, the rows after `since` while the page tails, `dropped_before`
    when the ring has already rolled past it (and `truncated` on the session), the ip / mac / proto filters (repeated and
    comma separated, ORed among themselves and ANDed with the fields), and one packet's detail tree and hex dump."""
    mod, state, port = mock.mod, mock.state, mock.port
    seeded = [dict(f) for f in state.capture_files]
    before = (state.capture_session, state.capture_next_id)
    held = mod.CAPTURE_SEED_PACKETS
    try:
        opened = _req(port, "POST", "/api/capture/open", {"name": SEED_CAPTURE})[2]["session"]
        assert (opened["packets"], opened["shown"], opened["truncated"]) == (held, held, False)
        st, _, page = _req(port, "GET", "/api/capture/packets")
        rows = page["rows"]
        assert st == 200 and list(page) == list(mod.CAPTURE_PACKETS_KEYS)
        assert [list(r) for r in rows] == [list(mod.CAPTURE_ROW_KEYS)] * len(rows)
        assert (page["total"], page["shown"], page["matched"], page["dropped_before"]) == (held, held, held, False)
        assert [r["no"] for r in rows] == list(range(1, held + 1)) and page["last"] == held
        assert list(page["session"]) == list(mod.CAPTURE_SESSION_KEYS)
        assert all(r["rel"] >= 0 and r["length"] > 0 for r in rows)
        # limit: without `since` the newest rows, with it the oldest after it; both clamped, never refused
        assert [r["no"] for r in _req(port, "GET", "/api/capture/packets?limit=5")[2]["rows"]] == [r["no"] for r in rows[-5:]]
        assert len(_req(port, "GET", "/api/capture/packets?limit=0")[2]["rows"]) == 1
        assert len(_req(port, "GET", "/api/capture/packets?limit=nonsense")[2]["rows"]) == held, "the default 500"
        assert len(_req(port, "GET", f"/api/capture/packets?limit={mod.CAPTURE_MAX_ROW_LIMIT + 1000}")[2]["rows"]) == held
        tail = _req(port, "GET", f"/api/capture/packets?since={rows[-3]['no']}")[2]
        assert [r["no"] for r in tail["rows"]] == [r["no"] for r in rows[-2:]] and tail["dropped_before"] is False
        assert _req(port, "GET", f"/api/capture/packets?since={rows[-1]['no']}")[2]["rows"] == []
        assert [r["no"] for r in _req(port, "GET", f"/api/capture/packets?since={rows[0]['no']}&limit=2")[2]["rows"]] == [
            r["no"] for r in rows[1:3]], "oldest first while tailing"
        assert _req(port, "GET", "/api/capture/packets?since=99999")[2]["rows"] == []
        # the filters: an address, a MAC in any spelling, and the protocol keys of the page's buttons
        ip = mod.CAPTURE_PC["ip"]
        mine = _req(port, "GET", f"/api/capture/packets?ip={ip}")[2]
        wanted = [r["no"] for r in rows if ip in (r["src"], r["dst"])]
        assert wanted and [r["no"] for r in mine["rows"]] == wanted and mine["matched"] == len(wanted)
        assert (mine["total"], mine["shown"]) == (held, held), "the counts are the whole list's, not the filter's"
        for spelling in (mod.CAPTURE_GATEWAY["mac"], mod.CAPTURE_GATEWAY["mac"].upper(), mod.CAPTURE_GATEWAY["mac"].replace(":", "-"),
                         mod.CAPTURE_GATEWAY["mac"].replace(":", "")):
            by_mac = _req(port, "GET", f"/api/capture/packets?mac={spelling}")[2]
            wanted = [r["no"] for r in rows if mod.capture_norm_mac(mod.CAPTURE_GATEWAY["mac"]) in (
                mod.capture_norm_mac(r["src_mac"]), mod.capture_norm_mac(r["dst_mac"]))]
            assert wanted and [r["no"] for r in by_mac["rows"]] == wanted, spelling
        icmp = [r["no"] for r in _req(port, "GET", "/api/capture/packets?proto=icmp")[2]["rows"]]
        arp = [r["no"] for r in _req(port, "GET", "/api/capture/packets?proto=ARP")[2]["rows"]]
        both = [r["no"] for r in _req(port, "GET", "/api/capture/packets?proto=icmp&proto=arp")[2]["rows"]]
        comma = [r["no"] for r in _req(port, "GET", "/api/capture/packets?proto=icmp,arp")[2]["rows"]]
        mixed = [r["no"] for r in _req(port, "GET", "/api/capture/packets?proto=icmp&proto=arp,nonsense")[2]["rows"]]
        assert icmp and arp and both == comma == mixed == sorted(set(icmp) | set(arp))
        assert {r["proto"] for r in _req(port, "GET", "/api/capture/packets?proto=icmp,arp")[2]["rows"]} <= {"ICMP", "ICMPv6", "ARP"}
        # the three AND: the phone's SIP only
        sip = _req(port, "GET", f"/api/capture/packets?proto=sip&ip={mod.CAPTURE_PHONE['ip']}")[2]["rows"]
        assert sip and all(r["proto"] == "SIP" and mod.CAPTURE_PHONE["ip"] in (r["src"], r["dst"]) for r in sip)
        assert len(sip) < len([r for r in rows if r["proto"] == "SIP"]) + 1
        # a filter the service cannot read is ignored, never refused
        loose = _req(port, "GET", "/api/capture/packets?ip=example.com&mac=nonsense&proto=nonsense")[2]
        assert [r["no"] for r in loose["rows"]] == [r["no"] for r in rows]
        # one packet: the detail tree and the hex dump of the bytes behind that row
        st, _, detail = _req(port, "GET", f"/api/capture/packets/{rows[-1]['no']}")
        assert st == 200 and list(detail) == list(mod.CAPTURE_DETAIL_KEYS) and detail["row"] == rows[-1]
        assert [list(layer) for layer in detail["layers"]] == [list(mod.CAPTURE_LAYER_KEYS)] * len(detail["layers"])
        assert all(list(f) == list(mod.CAPTURE_FIELD_KEYS) for layer in detail["layers"] for f in layer["fields"])
        assert [layer["name"] for layer in detail["layers"]][:2] == ["Frame", "ETH"]
        assert detail["bytes"] >= 60 and len(detail["hex"]) == -(-detail["bytes"] // 16)
        assert re.fullmatch(r"0000  (?:[0-9a-f]{2} ){15}[0-9a-f]{2}   .{16}", detail["hex"][0]), detail["hex"][0]
        st, _, gone = _req(port, "GET", f"/api/capture/packets/{held + 1}")
        assert st == 404 and gone["error"] == {"code": "not_found", "message": mod.CAPTURE_PACKET_GONE_TEXT}
        assert _req(port, "GET", "/api/capture/packets/nonsense")[2]["error"]["code"] == "not_found"
        # a capture whose list rolls past what it holds: the session is truncated and a tail from before the hole is told
        monkeypatch.setattr(mod, "CAPTURE_MAX_ROWS", 8)
        with _knobs(state, capture_s=30.0):
            assert _req(port, "POST", "/api/capture/start", {"adapter": "Ethernet"})[0] == 200
            assert _until(lambda: state.capture_total > 20, timeout=15.0), "the fake capture invented no packets"
            live = _req(port, "POST", "/api/capture/stop", {})[2]["session"]
        assert (live["truncated"], live["shown"]) == (True, 8) and live["packets"] > 20
        rolled = _req(port, "GET", "/api/capture/packets")[2]
        assert [r["no"] for r in rolled["rows"]] == list(range(live["packets"] - 7, live["packets"] + 1))
        assert (rolled["dropped_before"], rolled["total"], rolled["shown"]) == (False, live["packets"], 8)
        assert rolled["session"]["truncated"] is True
        hole = _req(port, "GET", "/api/capture/packets?since=1")[2]
        assert hole["dropped_before"] is True and [r["no"] for r in hole["rows"]] == [r["no"] for r in rolled["rows"]]
        assert _req(port, "GET", f"/api/capture/packets?since={rolled['rows'][0]['no'] - 1}")[2]["dropped_before"] is False
        assert _req(port, "GET", f"/api/capture/packets/{rolled['rows'][0]['no'] - 1}")[0] == 404, "that packet rolled off"
    finally:
        state.capture_discard()
        state.capture_files = seeded
        state.capture_session, state.capture_next_id = before


def test_mock_capture_finds_the_sip_call_and_rebuilds_its_audio(mock, monkeypatch):
    """The scripted SIP call: one capture.sip while the capture runs, the call on GET /api/capture/calls with its
    messages and its two RTP streams, and calls/{id}/audio a real WAV the page's player can play."""
    mod, state, port = mock.mod, mock.state, mock.port
    # the call's script, shortened so the capture is over in under two seconds
    monkeypatch.setattr(mod, "CAPTURE_SIP_AT", {"invite": 0.2, "ringing": 0.3, "answer": 0.5, "ack": 0.55, "bye": 1.0, "byeok": 1.05})
    seeded = [dict(f) for f in state.capture_files]
    before = (state.capture_session, state.capture_next_id)
    q = state.hub.subscribe()
    try:
        with _knobs(state, capture_s=1.8):
            assert _req(port, "POST", "/api/capture/start", {"adapter": "Ethernet"})[0] == 200
            frames = _frames(q, ("capture.sip", "capture.state"),
                             lambda kind, data: kind == "capture.state" and (data["session"] or {}).get("state") == "stopped", timeout=15.0)
        heard = [data["call"] for kind, data in frames if kind == "capture.sip"]
        assert len(heard) == 1, "one capture.sip per call, however long it runs"
        assert list(heard[0]) == list(mod.SIP_CALL_KEYS) and heard[0]["state"] in ("calling", "ringing")
        st, _, answer = _req(port, "GET", "/api/capture/calls")
        assert st == 200 and len(answer["calls"]) == 1
        call = answer["calls"][0]
        assert list(call) == list(mod.SIP_CALL_KEYS) and call["id"] == heard[0]["id"]
        assert (call["from_uri"], call["to_uri"], call["state"], call["status"]) == (mod.CAPTURE_SIP_FROM, mod.CAPTURE_SIP_TO, "ended", 200)
        assert call["answer_ts"] > call["start_ts"] and call["end_ts"] >= call["answer_ts"] and call["duration_s"] > 0
        assert all(list(m) == list(mod.SIP_MESSAGE_KEYS) for m in call["messages"])
        assert [m["method"] or m["status"] for m in call["messages"]] == ["INVITE", 180, 200, "ACK", "BYE", 200]
        assert all(list(s) == list(mod.SIP_STREAM_KEYS) for s in call["streams"])
        assert {(s["src"], s["sport"], s["dst"], s["dport"]) for s in call["streams"]} == {
            (mod.CAPTURE_PHONE["ip"], mod.CAPTURE_SIP_RTP_PORTS[0], mod.CAPTURE_PBX["ip"], mod.CAPTURE_SIP_RTP_PORTS[1]),
            (mod.CAPTURE_PBX["ip"], mod.CAPTURE_SIP_RTP_PORTS[1], mod.CAPTURE_PHONE["ip"], mod.CAPTURE_SIP_RTP_PORTS[0])}
        assert all(s["codec"] == mod.CAPTURE_SIP_CODEC and s["decodable"] and s["packets"] > 0 for s in call["streams"])
        assert _req(port, "GET", "/api/capture")[2]["session"]["calls"] == 1
        assert _req(port, "GET", "/api/status")[2]["capture"]["calls"] == 1
        # the audio: an 8 kHz 16-bit mono RIFF/WAVE the browser can play, sent like the service's FileResponse
        st, headers, wav = _req(port, "GET", f"/api/capture/calls/{call['id']}/audio", raw=True)
        assert st == 200 and wav[:4] == b"RIFF" and wav[8:12] == b"WAVE" and wav[12:16] == b"fmt "
        assert struct.unpack("<I", wav[4:8])[0] == len(wav) - 8 and struct.unpack("<I", wav[40:44])[0] == len(wav) - 44
        assert struct.unpack("<HHIIHH", wav[20:36]) == (1, 1, mod.CAPTURE_WAV_RATE, mod.CAPTURE_WAV_RATE * 2, 2, 16)
        assert (headers["content-type"], int(headers["content-length"]), headers["x-content-type-options"]) == ("audio/wav", len(wav), "nosniff")
        assert headers["content-disposition"].startswith('attachment; filename="TNT-call-') and headers["cache-control"] == "no-cache"
        st, _, err = _req(port, "GET", "/api/capture/calls/no-such-call/audio")
        assert st == 404 and err["error"] == {"code": "not_found", "message": mod.CAPTURE_NO_AUDIO_TEXT}
        # the packet list holds the call's signalling and its RTP both ways
        sip_rows = _req(port, "GET", "/api/capture/packets?proto=sip&limit=2000")[2]["rows"]
        rtp_rows = _req(port, "GET", "/api/capture/packets?proto=rtp&limit=2000")[2]["rows"]
        assert len(sip_rows) == 6 and len(rtp_rows) >= 2
        assert [r["info"].split(":")[0] for r in sip_rows] == ["Request", "Status", "Status", "Request", "Request", "Status"]
        assert {r["src"] for r in rtp_rows} == {mod.CAPTURE_PHONE["ip"], mod.CAPTURE_PBX["ip"]}
        assert all(r["sport"] in mod.CAPTURE_SIP_RTP_PORTS for r in rtp_rows)
        # every address it made up is a documentation one, every MAC locally administered
        for row in _req(port, "GET", "/api/capture/packets?limit=2000")[2]["rows"]:
            for value in (row["src"], row["dst"]):
                assert value == "" or _documentation_address(value), value
            for value in (row["src_mac"], row["dst_mac"]):
                assert value == mod.CAPTURE_BROADCAST_MAC or int(value.split(":")[0], 16) & 0x02, value
        assert _req(port, "POST", "/api/capture/discard", {})[2] == {"session": None}
        assert _req(port, "GET", "/api/capture/calls")[2] == {"calls": []}
    finally:
        state.hub.unsubscribe(q)
        state.capture_discard()
        state.capture_files = seeded
        state.capture_session, state.capture_next_id = before


def _documentation_address(value: str) -> bool:
    """True for the addresses a mock may invent: RFC 5737 / RFC 3849 documentation ranges, and the unspecified and
    broadcast addresses of a DHCP exchange - never a real public address."""
    import ipaddress

    if value in ("0.0.0.0", "255.255.255.255"):
        return True
    address = ipaddress.ip_address(value)
    nets = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
    return any(address in ipaddress.ip_network(net) for net in nets if address.version == ipaddress.ip_network(net).version)


def _sse_until(resp: Any, want: str) -> List[Tuple[str, Any]]:
    """(type, data) of the frames read from an open /api/events response, up to and including the first `want` one."""
    got: List[Tuple[str, Any]] = []
    lines: List[str] = []
    while True:
        raw = resp.readline()
        assert raw, f"the stream ended before {want}: {got}"
        line = raw.decode("utf-8").rstrip("\r\n")
        if line:
            lines.append(line)
            continue
        kind = next((ln[6:].strip() for ln in lines if ln.startswith("event:")), None)
        data = "".join(ln[5:].strip() for ln in lines if ln.startswith("data:"))
        lines = []
        if kind is None:
            continue                                         # a ': ping' comment
        got.append((kind, json.loads(data)))
        if kind == want:
            return got


def test_mock_event_stream_sends_capture_events_to_administrators_only(mock):
    """GET /api/events follows the service: capture.state (the open session) and capture.sip (a call the capture
    rebuilt), which every capture route refuses to a standard user, go only to a Windows administrator
    (STATE.wifi_admin); every other event goes to everyone."""
    from tnt.api import routes
    mod, state, port = mock.mod, mock.state, mock.port
    assert mod.ADMIN_ONLY_EVENTS == routes.ADMIN_ONLY_EVENTS == frozenset({"capture.state", "capture.sip"})
    session = {"session": {"id": 4242, "state": "capturing", "source": "live", "packets": 12, "calls": 1}}
    call = {"call": {"id": "sse-admin-test", "from_uri": "sip:2001@192.0.2.70", "to_uri": "sip:2002@192.0.2.70", "state": "ringing"}}
    for admin in (False, True):
        with _knobs(state, wifi_admin=admin):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                conn.request("GET", "/api/events")
                resp = conn.getresponse()
                assert resp.status == 200 and _sse_until(resp, "hello")[-1][0] == "hello"
                state.hub.publish("capture.state", session)
                state.hub.publish("capture.sip", call)
                state.hub.publish("test.sentinel", {"admin": admin})
                seen = _sse_until(resp, "test.sentinel")
            finally:
                conn.close()
        mine = [data for kind, data in seen if kind == "capture.state" and (data.get("session") or {}).get("id") == 4242]
        sip = [data for kind, data in seen if kind == "capture.sip" and (data.get("call") or {}).get("id") == "sse-admin-test"]
        assert (mine, sip) == (([session], [call]) if admin else ([], [])), admin


def test_mock_speed_tests_carry_quality(mock, monkeypatch):
    mod, state, port = mock.mod, mock.state, mock.port
    s = _req(port, "GET", "/api/status")[2]["speed"]
    last = s["last"]
    assert "quality" in last and (last["quality"] is None) == (not last["ok"])
    if last["ok"]:
        assert list(last["quality"]) == list(mod.QUALITY_KEYS) and last["quality"]["bufferbloat"]["grade"] in ("A", "B")
    now = time.time()
    rows = _req(port, "GET", f"/api/speedtests?from={now - 7 * 86400}&to={now + 1}")[2]["results"]
    assert rows and all("quality" not in r for r in rows), "the service's list has no quality"
    assert any("quality" in r for r in state.speedtests)
    # a run starts in the baseline phase. Its phases are shortened and the test waits for it to end, so no later test of this
    # module meets a run still going (409 on POST /api/speedtests/run); the test it adds is taken out again
    monkeypatch.setattr(mod, "SPEED_PHASES", (("baseline", 0.6), ("latency", 0.05), ("download", 0.05), ("upload", 0.05)))
    assert _until(lambda: not state.speed_running, timeout=15.0), "a speed run from before this test did not end"
    with state.lock:
        kept = (list(state.speedtests), dict(state.speed_progress), state.speed_next_ts)
    try:
        assert _req(port, "POST", "/api/speedtests/run")[2] == {"started": True}
        assert _req(port, "GET", "/api/status")[2]["speed"]["progress"]["phase"] == "baseline"
        assert _until(lambda: not state.speed_running, timeout=15.0), "the shortened speed run did not end"
        with state.lock:
            added = state.speedtests[len(kept[0]):]
        assert len(added) == 1 and (added[0]["quality"] is None) == (not added[0]["ok"])
    finally:
        _until(lambda: not state.speed_running, timeout=15.0)
        with state.lock:
            state.speedtests, state.speed_progress, state.speed_next_ts = kept[0], kept[1], kept[2]


def test_mock_dns_lookups_of_one_record_type(mock):
    state, port = mock.state, mock.port

    def look(body: Dict[str, Any]) -> Dict[str, Any]:
        st, _, res = _req(port, "POST", "/api/tools/dns/lookup", body)
        assert st == 200 and list(res) == list(mock.mod.DNS_RESULT_KEYS), (body, res)
        return res

    def values(res: Dict[str, Any]) -> List[Tuple[str, str, str]]:
        return [(r["type"], r["name"], r["value"]) for r in res["records"]]

    with _knobs(state, dns_delay_s=0.0):
        mx = look({"name": "example.com", "type": "mx"})
        assert (mx["type"], mx["ok"], mx["error"], mx["answer_name"], mx["addresses"], mx["aliases"], mx["authoritative"]) == (
            "MX", True, None, "example.com", [], [], False)
        assert values(mx) == [("MX", "example.com", "10 mail.example.com"), ("MX", "example.com", "20 mail2.example.com")]
        via = look({"name": "www.example.com", "type": "MX"})
        assert via["ok"] and via["aliases"] == ["www.example.com"] and via["answer_name"] == "example.com"
        assert values(via)[0] == ("CNAME", "www.example.com", "example.com") and len(via["records"]) == 3
        assert values(look({"name": "example.com", "type": "TXT"})) == [("TXT", "example.com", "v=spf1 ip4:203.0.113.0/24 -all")]
        assert [v for _t, _n, v in values(look({"name": "example.com", "type": "NS"}))] == ["ns1.example.net", "ns2.example.net"]
        assert values(look({"name": "example.com", "type": "SOA"}))[0][2].split()[2] == "2026091301"
        assert values(look({"name": "example.com", "type": "CAA"})) == [("CAA", "example.com", '0 issue "letsencrypt.org"')]
        assert values(look({"name": "example.com", "type": "NAPTR"})) == [("NAPTR", "example.com", '100 10 "S" "SIP+D2U" "" _sip._udp.example.com')]
        srv = look({"name": "_sip._tcp.example.com", "type": "SRV"})
        assert srv["ok"] and values(srv) == [("SRV", "_sip._tcp.example.com", "10 60 5060 sip.example.com")] and srv["addresses"] == []
        none = look({"name": "example.com", "type": "SRV"})
        assert (none["ok"], none["error"], none["records"], none["answer_name"], none["authoritative"]) == (
            False, "No SRV records found for this name", [], None, None)
        ptr = look({"name": "10.113.0.203.in-addr.arpa", "type": "PTR"})
        assert (ptr["ok"], ptr["answer_name"], ptr["addresses"]) == (True, "example.com", [])
        assert look({"name": "example.com", "type": "AAAA"})["addresses"] == ["2001:db8::10"]
        cname = look({"name": "www.example.com", "type": "cname"})
        assert (cname["ok"], values(cname), cname["answer_name"]) == (True, [("CNAME", "www.example.com", "example.com")], "example.com")
        assert look({"name": "nope.example", "type": "MX"})["error"] == "Non-existent domain"
        reverse, typed = look({"name": "203.0.113.10"}), look({"name": "203.0.113.10", "type": "PTR"})
        assert typed["type"] == "PTR" and reverse["type"] is None
        assert {k: v for k, v in typed.items() if k not in ("type", "duration_ms", "ts")} == {k: v for k, v in reverse.items() if k not in ("type", "duration_ms", "ts")}
        auto = look({"name": "example.com", "type": ""})
        assert auto["type"] is None and [r["type"] for r in auto["records"]] == ["A", "AAAA"], "Auto reads A and AAAA only"
        # ALL fans every type out and merges them, per-record type kept, result type "ALL"
        allc = look({"name": "example.com", "type": "all"})
        assert (allc["type"], allc["ok"], allc["answer_name"], allc["addresses"]) == ("ALL", True, "example.com", ["203.0.113.10", "2001:db8::10"])
        assert [r["type"] for r in allc["records"]] == ["A", "AAAA", "MX", "MX", "TXT", "NS", "NS", "SOA", "CAA", "NAPTR"]
        via_all = look({"name": "www.example.com", "type": "ALL"})
        assert (via_all["aliases"], via_all["answer_name"]) == (["www.example.com"], "example.com")
        assert [r["type"] for r in via_all["records"]] == ["CNAME", "A", "AAAA", "MX", "MX", "TXT", "NS", "NS", "SOA", "CAA", "NAPTR"]
        ip_all = look({"name": "203.0.113.10", "type": "ALL"})
        assert (ip_all["type"], ip_all["ok"], ip_all["answer_name"], ip_all["addresses"]) == ("ALL", True, "example.com", ["203.0.113.10"])
        for body, message in (({"name": "example.com", "type": 5}, "type must be text or null"), ({"name": "", "type": 5}, "type must be text or null"),
                              ({"name": "example.com", "type": "AXFR"}, '"AXFR" is not a DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR or NAPTR)'),
                              ({"name": "203.0.113.10", "type": "MX"}, "An IP address is looked up as PTR: type a DNS name to ask for other record types")):
            st, _, err = _req(port, "POST", "/api/tools/dns/lookup", body)
            assert st == 400 and err["error"] == {"code": "bad_request", "message": message}, body


@pytest.mark.parametrize("method, path, body", [
    ("POST", "/api/netcheck/nat", {}), ("POST", "/api/netcheck/switch", {}), ("DELETE", "/api/netcheck/switch", None),
    ("POST", "/api/netcheck/portforward", {"port": 8000}),
    ("POST", "/api/capture/start", {"adapter": "Ethernet"}), ("POST", "/api/capture/stop", {}), ("POST", "/api/capture/save", {}),
    ("POST", "/api/capture/discard", {}), ("POST", "/api/capture/open", {"name": SEED_CAPTURE}),
    ("GET", f"/api/capture/files/{SEED_CAPTURE}", None), ("DELETE", f"/api/capture/files/{SEED_CAPTURE}", None),
    ("POST", "/api/tftp/start", {}), ("POST", "/api/tftp/stop", {}), ("POST", "/api/tftp/uploads", {"on": True}),
    ("PUT", "/api/tftp/settings", {"max_upload_mb": 1}),
])
def test_mock_network_tools_refuse_a_page_of_another_origin_115(mock, method, path, body):
    """A browser page of another origin gets 403 forbidden before anything runs, before the capture routes' administrator check."""
    state, port = mock.state, mock.port

    def snapshot() -> Any:
        with state.lock:
            return json.dumps([state.nat_last, state.nat_running, state.switch_job, state.portcheck_last, state.portcheck_running, state.tftp_running,
                               state.tftp_uploads, state.settings["tftp"], state.capture_session, state.capture_total,
                               [f["name"] for f in state.capture_files]], sort_keys=True)

    before = snapshot()
    with _knobs(state, wifi_admin=False, portcheck_delay_s=0.0):
        for headers in CROSS_SITE_HEADERS:
            st, _, raw = _send(port, method, path, body, headers)
            assert st == 403 and json.loads(raw)["error"] == {"code": "forbidden", "message": mock.mod.QUICK_TOOLS_CROSS_ORIGIN_MSG}, headers
    assert snapshot() == before


# ------------------------------------------------------------------------------------------ the new cards in a headless browser
# The real page (scripts on) in a same-origin iframe of 1366 px against this module's mock, driven like a user (the _TOOLS_PROBE
# pattern of tests/test_ui.py). browser_page refuses the mock's event stream, so the page polls /api/status, as it does while the
# service's stream is down. A headless page's clock runs ahead while nothing is pending and stands still while a request is: a probe
# that waits on the mock's own timers (a switch port listen, a capture) asks GET /probe-wait?ms=N, answered after N ms of real time.
# Every knob a test changes is put back, and the page logs no error (data-mock-errors "[]").
_PROBE_HEAD = r"""<!doctype html><html><head><meta charset="utf-8"><title>1.15 probe</title></head><body style="margin:0">
<pre id="probe">pending</pre>
<iframe id="app" src="/index.html#@VIEW@" style="width:1366px;height:900px;border:0;display:block"></iframe>
<script>
const out = {};
const frame = document.getElementById('app');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const realWait = (ms) => fetch('/probe-wait?ms=' + ms).then((r) => r.json());
async function until(fn, ms) {
  const end = Date.now() + ms;
  for (;;) {
    let v = null;
    try { v = fn(); } catch (e) { v = null; }
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out waiting for ' + String(fn).slice(0, 200));
    await sleep(40);
  }
}
const app = () => frame.contentDocument;
const text = (el) => (el ? el.textContent : null);
const texts = (els) => Array.from(els).map((e) => e.textContent);
const shown = (el) => !!el && !el.closest('[hidden]');
const fire = (el, type) => el.dispatchEvent(new frame.contentWindow.Event(type, { bubbles: true }));
"""
_PROBE_TAIL = r"""
run().catch((e) => { out.failed = String((e && e.stack) || e); }).then(() => {
  try { out.errors = frame.contentDocument.documentElement.getAttribute('data-mock-errors'); } catch (e) { out.errors = 'unreadable: ' + e; }
  // &, < and > as JSON escapes: the dumped DOM would carry them as entities
  document.getElementById('probe').textContent = JSON.stringify(out).replace(/[&<>]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
});
</script></body></html>"""


def _run_probe(browser_page: Any, mock: Any, monkeypatch: Any, name: str, view: str, body: str, budget_ms: int = 20000) -> Dict[str, Any]:
    """Serve the probe page `name` (the app at #`view` and the probe's `async function run()`) plus GET /probe-wait, run it, and
    return what it found; the probe must finish and the page must log no error."""
    from urllib.parse import parse_qs, urlparse

    _serve_probe(mock, monkeypatch, name, _PROBE_HEAD.replace("@VIEW@", view) + body + _PROBE_TAIL)
    served = mock.mod.Handler._static

    def static(self: Any, path: str) -> None:
        if path != "/probe-wait":
            return served(self, path)
        ms = parse_qs(urlparse(self.path).query).get("ms", ["0"])[0]
        time.sleep(min(3.0, max(0.0, float(ms) / 1000.0)))
        return self._json({"ok": True})

    monkeypatch.setattr(mock.mod.Handler, "_static", static)
    res = _probe_result(browser_page(name, budget_ms=budget_ms))
    assert "failed" not in res, (res.get("failed"), res.get("errors"))
    assert res["errors"] == "[]", res["errors"]
    return res


_NAT_CARD_PROBE = r"""
async function run() {
  const doc = await until(() => app() && app().querySelector('#view .adapter-grid .adapter') && app(), 10000);
  const card = doc.querySelector('#view .netcheck-card');
  const nat = card.querySelector('.nc-nat');
  const badge = nat.querySelector('.nc-verdict .badge');
  await until(() => badge.textContent !== 'Checking…', 10000);
  const grid = doc.querySelector('#view .adapter-grid');
  const cells = Array.from(grid.children);
  const box = (el) => { const r = el.getBoundingClientRect(); return { left: Math.round(r.left), top: Math.round(r.top), width: Math.round(r.width) }; };
  out.layout = { cells: cells.slice(0, 4).map((c) => c.className), columns: getComputedStyle(grid).gridTemplateColumns.split(' ').length,
                 map: box(cells[0]), throughput: box(cells[1]), card: box(cells[2]), third: box(cells[3]),
                 overflow: doc.documentElement.scrollWidth > doc.documentElement.clientWidth };
  const detailsBtn = nat.querySelector('.nc-details-btn');
  out.nat = { title: text(card.querySelector('.card-title')), titleIcon: !!card.querySelector('.card-title svg'),
              sections: texts(card.querySelectorAll('.nc-section > .nc-head > .label')), badge: badge.textContent, badgeClass: badge.className,
              confidence: text(nat.querySelector('.nc-verdict .muted')), explanation: text(nat.querySelector('.nc-explain')),
              waiting: shown(nat.querySelector('.nc-waiting')), check: text(nat.querySelector('.nc-head .btn')),
              expanded: detailsBtn.getAttribute('aria-expanded'), detailsShown: shown(nat.querySelector('.nc-details')) };
  detailsBtn.click();
  const details = nat.querySelector('.nc-details');
  out.details = { expanded: detailsBtn.getAttribute('aria-expanded'), shown: shown(details),
                  rows: Array.from(details.querySelectorAll('.kv .k')).map((k) => [k.textContent, k.nextElementSibling.textContent]),
                  note: text(details.querySelector('.nc-note')), forwardsShown: !!details.querySelector('.nc-forwards') };
  details.querySelector('.nc-show-btn').click();
  out.forwards = Array.from(details.querySelectorAll('.nc-forwards tbody tr')).map((tr) => texts(tr.children));
  out.showButton = text(details.querySelector('.nc-show-btn'));
  const sw = card.querySelector('.nc-switch-body');
  out.switch = { buttons: texts(sw.querySelectorAll('button')), options: texts(sw.querySelectorAll('select option')), result: !!sw.querySelector('.nc-result') };
  out.portCard = !card.querySelector('.nc-port');      // the port-forward test moved to a Tools card: no port section here
  out.wanTitle = Array.from(doc.querySelectorAll('#view .linkmap [title]')).map((e) => e.title)
    .find((t) => t.indexOf('public address as the internet sees it') >= 0) || null;
}
"""


def test_network_info_card_follows_the_link_map_and_checks_nat_by_itself_in_a_browser(browser_page, mock, monkeypatch):
    """§5.1 / §5.3: at 1366 px the NAT & switch port card is the grid cell right after the live link map (one cell of the same
    width in the same row, no title icon, two sections; the port-forward test is a Tools card now). On network "a" it POSTs one
    check by itself once the link map has this network's public address and shows the verdict's title as a green badge, "· high
    confidence", the explanation and folded Details; the switch port section waits to be asked."""
    mod, state, port = mock.mod, mock.state, mock.port
    monkeypatch.setattr(mod, "NET_RECHECK_S", 0.0)          # this network's public address is looked up at once after a change
    posts: List[Dict[str, Any]] = []
    run_check = state.nat_run

    def counted() -> Dict[str, Any]:
        result = run_check()
        posts.append(result)
        return result

    monkeypatch.setattr(state, "nat_run", counted)
    with _knobs(state, nat_last=None, nat_delay_s=0.0, switch_job=None, switch_kept={}, portcheck_last=None):
        res = _run_probe(browser_page, mock, monkeypatch, "nat-probe.html", "ipinfo", _NAT_CARD_PROBE)
    lay = res["layout"]
    # the live link map, then realtime throughput, then NAT & switch port, then the adapters
    assert "linkmap" in lay["cells"][0].split() and lay["cells"][1] == "card tp-card", lay
    assert lay["cells"][2] == "card netcheck-card" and "adapter" in lay["cells"][3].split(), lay
    assert lay["columns"] == 3 and lay["overflow"] is False, lay
    # three to a row, all the same width: the throughput card is one cell like the other two
    assert lay["map"]["top"] == lay["throughput"]["top"] == lay["card"]["top"], lay
    assert lay["map"]["left"] < lay["throughput"]["left"] < lay["card"]["left"], lay
    assert abs(lay["card"]["width"] - lay["map"]["width"]) <= 1, lay
    assert abs(lay["throughput"]["width"] - lay["map"]["width"]) <= 1, lay
    assert lay["third"]["top"] > lay["map"]["top"] and lay["third"]["left"] == lay["map"]["left"], lay
    nat = res["nat"]
    title, explanation = mod.NAT_TEXT["single_nat"]
    assert (nat["title"], nat["titleIcon"], nat["sections"]) == ("NAT & switch port", False, ["NAT", "Switch port - LLDP"])
    assert (nat["badge"], nat["badgeClass"], nat["confidence"], nat["explanation"], nat["waiting"]) == (title, "badge green", "· high confidence",
                                                                                                         explanation, False)
    assert (nat["check"], nat["expanded"], nat["detailsShown"]) == ("Check again", "false", False)
    assert len(posts) == 1, "one automatic check"
    r = posts[0]
    assert r["verdict"] == "single_nat" and r["generation"] == _req(port, "GET", "/api/status")[2]["net"]["generation"]
    wan, public, entries = r["router"]["wan_ip"], r["public_ip"], r["port_mappings"]["entries"]
    d = res["details"]
    assert (d["expanded"], d["shown"], d["forwardsShown"]) == ("true", True, False)
    assert d["rows"] == [["Router's own internet address", f"{wan} (UPnP)"], ["Public address", f"{public} (WAN on the map)"],
                         ["UPnP", f"on · {mod.NAT_ROUTER_MODEL}"], ["UPnP forwards", f"{len(entries)} listedShow"]]
    assert d["note"] == "Only forwards the router shares over UPnP; ones made in its own settings page may be missing."
    assert res["forwards"] == [[m["protocol"], f"{m['external_port']} → {m['internal_client']}:{m['internal_port']}", m["description"]] for m in entries]
    assert res["showButton"] == "Hide"
    assert res["switch"] == {"buttons": ["Find switch port"], "options": ["Ethernet (internet)", "Ethernet 2", "Ethernet 3"], "result": False}
    assert res["portCard"] is True, "the port-forward test is a Tools card now, not a section of this card"
    assert res["wanTitle"].startswith("This network's public address as the internet sees it (behind double NAT or CGNAT this is not the "
                                      "router's own address) · "), res["wanTitle"]


_PORT_CLEARED_PROBE = r"""
async function run() {
  const card = await until(() => app() && app().querySelector('#view [data-tool="portforward"]'), 10000);
  card.querySelector('.card-title').click();                 // the tool card starts collapsed: open it
  const input = await until(() => card.querySelector('.pf-form input'), 5000);
  const button = card.querySelector('.pf-form .btn');
  const result = card.querySelector('.pf-result'), hints = card.querySelector('.pf-hints');
  input.value = '70000';
  button.click();
  await until(() => shown(result), 3000);
  out.invalid = { text: result.textContent, cls: result.className, hints: shown(hints) };
  input.value = '8000';
  button.click();
  await until(() => shown(result) && result.classList.contains('ok'), 10000);
  out.tested = { text: result.textContent, cls: result.className, hints: texts(hints.querySelectorAll('li')), hintsShown: shown(hints), button: text(button) };
  // this PC moves to network "b" (the mock's development route): the next status names another generation
  const moved = await fetch('/mock/network', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ profile: 'b' }) })
    .then((r) => r.json());
  out.generation = moved.event.generation;
  await until(() => !shown(result), 20000);
  out.cleared = { result: shown(result), hints: shown(hints), typed: input.value };
}
"""


def test_port_forward_result_is_cleared_after_a_network_change_in_a_browser(browser_page, mock, monkeypatch):
    """§5.2 / §5.5, as moved to Tools: a port refused on the Port forward card, then a reachable port with its hint; after
    switch_network the result and the hints go at once and the typed port stays."""
    mod, state, port = mock.mod, mock.state, mock.port
    monkeypatch.setattr(mod, "NET_RECHECK_S", 0.0)
    monkeypatch.setattr(state, "portcheck_starts", list(state.portcheck_starts))
    monkeypatch.setattr(state, "portcheck_last_start", state.portcheck_last_start)
    generation = _req(port, "GET", "/api/status")[2]["net"]["generation"]
    try:
        with _knobs(state, nat_last=None, nat_delay_s=0.0, portcheck_last=None, portcheck_delay_s=0.0, portcheck_min_gap_s=0, portcheck_per_hour=0,
                    switch_job=None, switch_kept={}):
            res = _run_probe(browser_page, mock, monkeypatch, "port-probe.html", "tools", _PORT_CLEARED_PROBE, budget_ms=30000)
    finally:
        state.switch_network("a")
        state.nat_last = state.portcheck_last = None
    hint = ("Something must answer on that TCP port (the camera/NVR must be on and the forward must point at it). No answer can also mean the ISP "
            "or a firewall blocks the port.")
    assert res["invalid"] == {"text": "port must be a whole number from 1 to 65535", "cls": "tool-summary pf-result warn", "hints": False}
    assert res["tested"] == {"text": "TCP port 8000 is reachable from the internet· portchecker.io connected to the port",
                             "cls": "tool-summary pf-result ok", "hints": [hint], "hintsShown": True, "button": "Test from the internet"}
    assert res["generation"] == generation + 1
    cleared = res["cleared"]
    assert (cleared["result"], cleared["hints"], cleared["typed"]) == (False, False, "8000")


_SWITCH_PROBE = r"""
async function run() {
  const doc = await until(() => app() && app().querySelector('#view .netcheck-card [data-nc="find"]') && app(), 10000);
  const body = doc.querySelector('#view .netcheck-card .nc-switch-body');
  const select = body.querySelector('select');
  out.before = { options: texts(select.options), picked: select.value, buttons: texts(body.querySelectorAll('button')) };
  select.value = 'Ethernet 2';
  fire(select, 'change');
  body.querySelector('[data-nc="find"]').click();
  const stop = await until(() => body.querySelector('[data-nc="stop"]'), 5000);
  out.listening = { fuse: text(body.querySelector('.fuse-label .l')), stop: text(stop), find: !!body.querySelector('[data-nc="find"]'),
                    select: !!body.querySelector('select') };
  await realWait(900);
  await until(() => body.querySelector('.nc-result'), 20000);
  const detailsBtn = body.querySelector('.nc-details-btn');
  out.done = { lines: texts(body.querySelectorAll('.nc-result')), expanded: detailsBtn.getAttribute('aria-expanded'),
               detailsShown: shown(body.querySelector('.nc-details')), buttons: texts(body.querySelectorAll('.nc-actions button')),
               picked: body.querySelector('select').value };
  detailsBtn.click();
  const details = body.querySelector('.nc-details');
  out.details = { expanded: body.querySelector('.nc-details-btn').getAttribute('aria-expanded'), shown: shown(details),
                  rows: Array.from(details.querySelectorAll('.kv .k')).map((k) => [k.textContent, k.nextElementSibling.textContent]),
                  via: texts(details.querySelectorAll(':scope > .muted.small:not(.nc-note)')), note: text(details.querySelector('.nc-note')),
                  noteMatches: text(details.querySelector('.nc-note')) === frame.contentWindow.TNT.netcheck.TEXTS.SWITCH_RESULT_NOTE };
  const status = await frame.contentWindow.fetch('/api/netcheck/switch').then((r) => r.json());
  out.job = { state: status.job.state, adapter: status.job.adapter.name };
}
"""


def test_switch_port_listen_then_done_in_a_browser(browser_page, mock, monkeypatch):
    """§5.4: "Find switch port" on the adapter picked in the select listens (a countdown fuse and Stop, no other control), polls
    while the mock listens, then names the switch and the port with folded Details and the result note."""
    mod, state = mock.mod, mock.state
    try:
        with _knobs(state, switch_listen_s=0.4, switch_found=True, switch_job=None, switch_kept={}, nat_last=None, nat_delay_s=0.0, pktmon_reason=None):
            res = _run_probe(browser_page, mock, monkeypatch, "switch-probe.html", "ipinfo", _SWITCH_PROBE, budget_ms=30000)
    finally:
        state.switch_stop()
        state.nat_last = None
    n = mod.MOCK_NEIGHBOR
    assert res["before"] == {"options": ["Ethernet (internet)", "Ethernet 2", "Ethernet 3"], "picked": "Ethernet", "buttons": ["Find switch port"]}
    listening = res["listening"]
    left = re.fullmatch(r"Listening for the switch… (\d+) s", listening["fuse"] or "")
    assert left and 55 <= int(left.group(1)) <= 65, listening
    assert (listening["stop"], listening["find"], listening["select"]) == ("Stop", False, False), listening
    line = f"{n['switch_name']} · {n['port_description'] or n['port_id']} · {n['vendor']} · VLAN {n['vlan']}"
    assert res["done"] == {"lines": [line], "expanded": "false", "detailsShown": False, "buttons": ["Find switch port"], "picked": "Ethernet 2"}
    d = res["details"]
    poe = n["poe"]
    assert (d["expanded"], d["shown"], d["noteMatches"]) == ("true", True, True)
    assert d["rows"] == [["Switch description", n["switch_description"]], ["Port ID", n["port_id"]], ["VLAN", str(n["vlan"])],
                         ["Voice VLAN", str(n["voice_vlan"])], ["PoE", f"class {poe['class']} · {poe['allocated_w']:.1f} W"], ["Link", n["link"]["text"]],
                         ["Management IP", "".join(n["management_ips"])]]
    assert len(d["via"]) == 1 and d["via"][0].startswith("via LLDP"), d["via"]
    assert d["note"].startswith("If a small switch or a phone sits between this PC and the wall jack")
    assert res["job"] == {"state": "done", "adapter": "Ethernet 2"}


_TFTP_PROBE = r"""
async function run() {
  const doc = await until(() => app() && app().querySelector('[data-tool="tftp"] .tool-head-right .badge') && app(), 10000);
  const win = frame.contentWindow;
  const card = doc.querySelector('[data-tool="tftp"]');
  const badge = card.querySelector('.tool-head-right .badge');
  const toggle = card.querySelector('.tool-head-right input[type="checkbox"]');
  const cardToggle = card.querySelector('.card-toggle');
  const tile = doc.getElementById('tile-tools');
  // the half-height Tools tile: the DHCP server's line carries the TFTP server's badge, and the tool names are one line
  const tftpBadge = () => {
    const b = Array.from(tile.querySelectorAll('.tile-line .badge')).find((x) => x.textContent.indexOf('TFTP') === 0);
    return b ? { text: b.textContent, badge: b.className, line: b.closest('.tile-line').textContent } : null;
  };
  const names = () => { const l = tile.querySelector('.tile-line .tile-ellipsis'); return l ? { text: l.textContent, title: l.title } : null; };
  const boxes = () => texts(Array.from(card.querySelectorAll('.dhcp-info.bad')).filter((b) => !b.hidden));
  await until(() => badge.textContent === 'error' && tftpBadge(), 10000);
  out.error = { badge: badge.textContent, cls: badge.className, title: badge.title, checked: toggle.checked, expanded: cardToggle.getAttribute('aria-expanded'),
                boxes: boxes(), tile: tftpBadge() };
  toggle.click();
  await until(() => badge.textContent === 'on' && card.querySelector('.tftp-files tbody tr'), 10000);
  out.on = { badge: badge.textContent, cls: badge.className, checked: toggle.checked, expanded: cardToggle.getAttribute('aria-expanded'), errorBoxes: boxes().length,
             summary: text(card.querySelector('.tftp-summary')), files: texts(card.querySelectorAll('.tftp-files tbody tr td:first-child')),
             folder: text(card.querySelector('.tftp-folder code')), note: text(card.querySelector('.tftp-uploads-note')),
             scopeMatches: text(card.querySelector('.tftp-scope')) === win.TNT.tools.tftp.TFTP_SCOPE_TEXT };
  out.toastsOn = texts(doc.querySelectorAll('#toasts .toast'));      // before the tile wait: a toast leaves after 3.2 s of the page's clock
  out.tileOn = await until(() => { const b = tftpBadge(); return b && b.text === 'TFTP on' ? b : null; }, 20000);
  // "Allow uploads" while it serves: yellow on the card and on the Tools tile, then green again
  const uploads = () => card.querySelector('input[aria-label="Allow uploads"]');
  uploads().click();
  await until(() => badge.textContent === 'uploads on', 10000);
  out.uploads = { badge: badge.textContent, cls: badge.className, checked: uploads().checked, toasts: texts(doc.querySelectorAll('#toasts .toast')) };
  out.tileUploads = await until(() => { const b = tftpBadge(); return b && b.text === 'TFTP uploads' ? b : null; }, 20000);
  uploads().click();
  await until(() => badge.textContent === 'on', 10000);
  out.uploadsOff = { checked: uploads().checked, tile: await until(() => { const b = tftpBadge(); return b && b.text === 'TFTP on' ? b : null; }, 20000) };
  toggle.click();
  await until(() => badge.textContent === 'off', 10000);
  await until(() => !tftpBadge(), 20000);
  out.off = { badge: badge.textContent, cls: badge.className, checked: toggle.checked, tile: tftpBadge(), summary: text(card.querySelector('.tftp-summary')),
              names: names(), lines: tile.querySelectorAll('.tile-line').length };
  out.server = await win.fetch('/api/tftp/status').then((r) => r.json()).then((s) => ({ running: s.running, error: s.error }));
}
"""


def test_tftp_card_on_and_off_and_its_tools_tile_line_in_a_browser(browser_page, mock, monkeypatch):
    """§9.7 / §10.1 as built: a server stopped by a network change shows a red "error" badge (the error as its title and in a red
    box) and a red "TFTP error" badge on the DHCP line of the half-height Tools tile while it is off; switching it on opens the
    card, serves (green "on", the files, the folder, the uploads note, the scope text) and the tile badge turns green; "Allow
    uploads" turns the card badge and the tile badge yellow and back; switching it off clears the tile badge. The tools
    themselves are one ellipsized line of names there (Packet capture has its own tile now)."""
    mod, state = mock.mod, mock.state
    kept = (state.tftp_history, dict(state.tftp_counts), state.tftp_next_id)
    stopped = mod.TFTP_STOPPED_TEXT
    try:
        with _knobs(state, tftp_error=stopped, tftp_fast=False, tftp_port_owners=[], tftp_uploads=False):
            res = _run_probe(browser_page, mock, monkeypatch, "tftp-probe.html", "tools", _TFTP_PROBE, budget_ms=30000)
    finally:
        state.tftp_stop()
        state.tftp_error = None
        with state.lock:                                     # the phone's read during the test is not left in the history
            state.tftp_history, state.tftp_counts, state.tftp_next_id = kept[0], dict(kept[1]), kept[2]
    err = res["error"]
    assert (err["badge"], err["cls"], err["title"], err["checked"], err["expanded"], err["boxes"]) == ("error", "badge red", stopped, False, "false", [stopped])
    assert (err["tile"]["text"], err["tile"]["badge"]) == ("TFTP error", "badge red")
    assert err["tile"]["line"].startswith("DHCP server"), err["tile"]
    on = res["on"]
    assert (on["badge"], on["cls"], on["checked"], on["expanded"], on["errorBoxes"], on["scopeMatches"]) == ("on", "badge green", True, "true", 0, True)
    assert re.fullmatch(r"Serving on Ethernet · \d{1,3}(\.\d{1,3}){3} · on .+", on["summary"]), on["summary"]
    assert on["files"] == sorted(name for name, _size, _age in mod.TFTP_FILES)
    assert on["folder"].endswith("\\tftp") and on["note"] == "Anyone on this network can upload files while this is on"
    assert (res["tileOn"]["text"], res["tileOn"]["badge"]) == ("TFTP on", "badge green")
    assert "TFTP server is on" in res["toastsOn"]
    up = res["uploads"]
    assert (up["badge"], up["cls"], up["checked"]) == ("uploads on", "badge yellow", True) and "Uploads are on" in up["toasts"], up
    assert (res["tileUploads"]["text"], res["tileUploads"]["badge"]) == ("TFTP uploads", "badge yellow")
    assert res["uploadsOff"]["checked"] is False
    assert (res["uploadsOff"]["tile"]["text"], res["uploadsOff"]["tile"]["badge"]) == ("TFTP on", "badge green")
    off = res["off"]
    assert (off["badge"], off["cls"], off["checked"], off["tile"], off["summary"]) == ("off", "badge grey", False, None, "Would serve on Ethernet")
    # the tools on one ellipsized line, in the order of their cards; Packet capture is a page with its own tile now
    names = ["LAN throughput", "Port forward check", "Traceroute", "TFTP server", "Subnet calc", "DNS", "WiFi passwords"]
    assert off["names"] == {"text": " · ".join(names), "title": ", ".join(names)}
    assert "Packet capture" not in off["names"]["text"] and off["lines"] == 2, "the half-height tile: one state line and the names"
    assert res["server"] == {"running": False, "error": None}


_CAPTURE_ADMIN_PROBE = r"""
async function run() {
  const doc = await until(() => app() && app().querySelector('#view > .dhcp-info.warn') && app(), 10000);
  const note = doc.querySelector('#view > .dhcp-info.warn');
  await until(() => shown(note), 10000);
  out.admin = { text: text(note), shown: shown(note), main: shown(doc.querySelector('#view .cap-controls')),
                heading: text(doc.querySelector('#view .section-head h2')), toasts: texts(doc.querySelectorAll('#toasts .toast')) };
  const r = await frame.contentWindow.fetch('/api/capture');
  out.status = { code: r.status, body: await r.json() };
}
"""

_CAPTURE_RUN_PROBE = r"""
async function run() {
  const doc = await until(() => app() && app().querySelector('#view .cap-controls select[aria-label="Adapter"]') && app(), 10000);
  const win = frame.contentWindow;
  const q = (s) => doc.querySelector('#view ' + s);
  const adapter = q('select[aria-label="Adapter"]'), seconds = q('select[aria-label="Stop after"]'), size = q('select[aria-label="Size limit"]');
  const start = q('.cap-buttons .btn-primary');
  const buttons = () => texts(Array.from(doc.querySelectorAll('#view .cap-buttons button')).filter((b) => shown(b)));
  const rows = () => Array.from(doc.querySelectorAll('#view .cap-table tbody tr')).map((tr) => texts(tr.children));
  const status = () => text(q('.cap-status')) || '';
  await until(() => seconds.options.length && adapter.options.length, 10000);
  out.form = { adapters: texts(adapter.options), seconds: texts(seconds.options), secondsValue: seconds.value, sizes: texts(size.options),
               sizeValue: size.value, buttons: buttons(), columns: texts(doc.querySelectorAll('#view .cap-table thead th')),
               protos: Array.from(doc.querySelectorAll('#view .cap-proto')).map((b) => [b.textContent, b.getAttribute('aria-pressed')]),
               warningMatches: text(q('.cap-warning')) === win.TNT.views.capture.WARNING_TEXT,
               callsShown: shown(q('.cap-calls-btn')), status: status(), empty: text(q('.cap-empty')), rows: rows().length };
  start.click();
  await until(() => status().indexOf('Capturing on') === 0, 10000);
  out.started = { status: status(), buttons: buttons(), adapterDisabled: adapter.disabled, secondsDisabled: seconds.disabled };
  await realWait(2400);                                      // the mock's capture runs its time and its scripted SIP call
  await until(() => status().indexOf('Stopped') === 0 && rows().length > 5, 20000);
  out.captured = { status: status(), buttons: buttons(), rows: rows().length, counts: text(q('.cap-filters .muted.small')),
                   protos: Array.from(new Set(rows().map((r) => r[5]))).sort(), first: rows()[0], adapterDisabled: adapter.disabled };
  // the SIP calls filter: the list narrows to the call's signalling and the "Show calls" button appears
  const sip = Array.from(doc.querySelectorAll('#view .cap-proto')).find((b) => b.textContent.indexOf('SIP calls') >= 0);
  sip.click();
  await until(() => { const r = rows(); return r.length && r.every((c) => c[5] === 'SIP'); }, 10000);
  out.sip = { pressed: sip.getAttribute('aria-pressed'), on: sip.classList.contains('on'), rows: rows().length,
              protos: Array.from(new Set(rows().map((r) => r[5]))), infos: rows().map((r) => r[7].split(':')[0]),
              counts: text(q('.cap-filters .muted.small')), calls: text(q('.cap-calls-btn')), callsShown: shown(q('.cap-calls-btn')) };
  // a row opens the packet detail window: the layer tree over the hex dump
  doc.querySelector('#view .cap-table tbody tr').click();
  const detail = await until(() => doc.querySelector('#modal-root .modal .cap-detail'), 10000);
  const modal = detail.closest('.modal');
  out.detail = { title: text(modal.querySelector('.modal-head h2')), head: text(detail.querySelector('.cap-detail-head')),
                 layers: texts(detail.querySelectorAll('.cap-layer > summary .strong')),
                 fields: texts(detail.querySelectorAll('.cap-layer .cap-field-name')).slice(0, 3),
                 hex: (text(detail.querySelector('.cap-hex')) || '').split('\n')[0], hexLines: (text(detail.querySelector('.cap-hex')) || '').split('\n').length };
  modal.querySelector('.modal-head button').click();
  await until(() => !doc.querySelector('#modal-root .modal'), 5000);
  // "Show calls (1)" opens the calls the capture rebuilt, each with its own player
  q('.cap-calls-btn').click();
  const calls = await until(() => doc.querySelector('#modal-root .modal .cap-calls'), 10000);
  out.calls = { title: text(calls.closest('.modal').querySelector('.modal-head h2')),
                rows: Array.from(calls.querySelectorAll('.cap-call')).map((c) => [text(c.querySelector('.badge')), c.querySelector('.badge').className,
                                                                                  text(c.querySelector('.cap-call-title')), text(c.querySelector('.cap-call-meta'))]),
                buttons: texts(calls.querySelectorAll('.cap-call-actions button')) };
  out.session = await win.fetch('/api/capture').then((r) => r.json()).then((s) => ({ state: s.session.state, source: s.session.source,
    stop: s.session.stop_reason, saved: s.session.saved, calls: s.session.calls, packets: s.session.packets, adapter: s.session.adapter.name }));
}
"""


def test_packet_capture_page_needs_an_administrator_then_captures_in_a_browser(browser_page, mock, monkeypatch):
    """§8.8 as built: the Packet capture page. A standard user's 403 admin_required shows the note instead of the page (no
    toast); an administrator gets the controls the service's limits filled in, Start captures on the picked adapter (the
    buttons change, the selects lock) and the rows arrive in the list; the SIP calls filter narrows the list to the call's
    signalling and reveals "Show calls (1)", which lists the rebuilt call; a row opens the packet detail window with its
    layer tree and hex dump."""
    mod, state = mock.mod, mock.state
    seeded = [dict(f) for f in state.capture_files]
    before = (state.capture_session, state.capture_next_id)
    # the scripted call, shortened so the whole capture is over inside the probe's wait
    monkeypatch.setattr(mod, "CAPTURE_SIP_AT", {"invite": 0.2, "ringing": 0.3, "answer": 0.5, "ack": 0.55, "bye": 1.0, "byeok": 1.05})
    try:
        with _knobs(state, wifi_admin=False):
            admin = _run_probe(browser_page, mock, monkeypatch, "capture-admin-probe.html", "capture", _CAPTURE_ADMIN_PROBE)
        with _knobs(state, wifi_admin=True, capture_s=1.8, capture_reason=None, capture_session=None):
            res = _run_probe(browser_page, mock, monkeypatch, "capture-probe.html", "capture", _CAPTURE_RUN_PROBE, budget_ms=30000)
    finally:
        state.capture_discard()
        state.capture_files = seeded
        state.capture_session, state.capture_next_id = before
    assert admin["admin"] == {"text": "Packet capture needs a Windows administrator account", "shown": True, "main": False,
                              "heading": "Packet capture", "toasts": []}
    assert admin["status"] == {"code": 403, "body": {"error": {"code": "admin_required", "message": mod.CAPTURE_ADMIN_REQUIRED_MSG}}}
    f = res["form"]
    assert f["adapters"] == ["Ethernet", "Ethernet 2", "Ethernet 3"]
    assert (f["seconds"], f["secondsValue"]) == (["1 min", "5 min", "15 min", "30 min", "60 min"], str(mod.CAPTURE_DEFAULT_SECONDS))
    assert (f["sizes"], f["sizeValue"]) == ([f"{mb} MB" for mb in mod.CAPTURE_SIZES_MB], str(mod.CAPTURE_DEFAULT_MB))
    assert f["buttons"] == ["Start", "Open…"] and f["warningMatches"] is True and f["callsShown"] is False
    assert f["columns"] == ["No.", "Time", "Since start", "Source", "Destination", "Protocol", "Length", "Info"]
    assert [label for label, _pressed in f["protos"]] == ["ICMP", "ARP", "DNS", "DHCP", "HTTP", "HTTPS", "TCP", "UDP", "RTSP", "RTP", "SIP calls"]
    assert {pressed for _label, pressed in f["protos"]} == {"false"} and f["rows"] == 0
    assert (f["status"], f["empty"]) == ("Not capturing", "Pick an adapter and hit Start, or open a capture you saved earlier.")
    started = res["started"]
    # the label ("Capturing on <adapter> · m:ss") and the detail ("<n> packets · <size>") share the line
    assert re.fullmatch(r"Capturing on Ethernet · \d+:\d\d[\d,]* packets?(?: · .+)?", started["status"]), started["status"]
    assert started["buttons"] == ["Stop", "Save to disk", "Open…", "Discard"] and started["adapterDisabled"] is True
    assert started["secondsDisabled"] is True
    cap = res["captured"]
    assert cap["status"].startswith("Stopped — not saved yet (it reached its time limit)"), cap["status"]
    assert cap["buttons"] == ["Start", "Save to disk", "Open…", "Discard"] and cap["adapterDisabled"] is False
    assert cap["rows"] > 5 and re.fullmatch(r"[\d,]+ packets", cap["counts"] or ""), cap["counts"]
    assert {"SIP", "RTP"} <= set(cap["protos"]), cap["protos"]
    assert re.fullmatch(r"\d\d:\d\d:\d\d\.\d{3}", cap["first"][1]) and re.fullmatch(r"\d+\.\d{3}", cap["first"][2]), cap["first"]
    sip = res["sip"]
    assert (sip["pressed"], sip["on"], sip["protos"]) == ("true", True, ["SIP"])
    assert sip["rows"] == 6 and sip["infos"] == ["Request", "Status", "Status", "Request", "Request", "Status"]
    assert sip["counts"] == f"6 matching · {cap['counts'].split(' ')[0]} captured", sip["counts"]
    assert (sip["calls"], sip["callsShown"]) == ("Show calls (1)", True)
    d = res["detail"]
    assert d["title"] == f"SIP — {mod.CAPTURE_PHONE['ip']} → {mod.CAPTURE_PBX['ip']}", d["title"]
    assert d["layers"] == ["Frame", "ETH", "IPv4", "UDP", "SIP"] and d["fields"] == ["Arrival time", "Epoch time", "Captured length"]
    assert re.match(r"^Packet \d+\d\d:\d\d:\d\d\.\d{3} · \+\d+\.\d{3} s · \d+ bytes$", d["head"] or ""), d["head"]
    assert re.fullmatch(r"0000  (?:[0-9a-f]{2} ){15}[0-9a-f]{2}   .{16}", d["hex"]) and d["hexLines"] > 4
    calls = res["calls"]
    assert calls["title"] == "SIP calls" and calls["buttons"] == ["Listen"]
    assert calls["rows"] == [["ended", "badge grey", f"{mod.CAPTURE_SIP_FROM} → {mod.CAPTURE_SIP_TO}",
                              calls["rows"][0][3]]], calls["rows"]
    assert re.fullmatch(r"Started \d\d:\d\d:\d\d\.\d{3} · 0:0\d · PCMU/8000", calls["rows"][0][3]), calls["rows"][0][3]
    assert res["session"] == {"state": "stopped", "source": "live", "stop": "seconds", "saved": False, "calls": 1,
                              "packets": res["session"]["packets"], "adapter": "Ethernet"}
    assert res["session"]["packets"] > 5


_DNS_TYPES_PROBE = r"""
async function run() {
  const doc = await until(() => app() && app().querySelector('[data-tool="dns"] .dns-form select') && app(), 10000);
  const card = doc.querySelector('[data-tool="dns"]');
  card.querySelector('.card-title').click();
  const name = card.querySelector('.dns-form input'), type = card.querySelector('.dns-form select'), look = card.querySelector('.dns-form .btn-primary');
  const summary = () => text(card.querySelector('.tool-summary[role="status"]'));
  const pick = (v) => { type.value = v; fire(type, 'change'); };
  out.form = { labels: texts(card.querySelectorAll('.dns-form .field label')), options: Array.from(type.options).map((o) => [o.value, o.textContent]),
               picked: type.value, placeholder: name.placeholder, typeAfterName: name.closest('.field').nextElementSibling === type.closest('.field') };
  pick('SRV');
  out.srvPlaceholder = name.placeholder;
  pick('MX');
  out.mxPlaceholder = name.placeholder;
  name.value = 'example.com';
  fire(name, 'input');
  pick('NAPTR');
  look.click();
  await until(() => summary().indexOf('NAPTR') >= 0 && summary().indexOf('Asking') !== 0, 10000);
  out.naptr = { summary: summary(), values: texts(card.querySelectorAll('.dns-value')), hint: shown(card.querySelector('.dns-hint')) };
  pick('SRV');
  look.click();
  await until(() => summary().indexOf('SRV') >= 0 && summary().indexOf('Asking') !== 0, 10000);
  out.srv = { summary: summary(), hint: text(card.querySelector('.dns-hint')), hintShown: shown(card.querySelector('.dns-hint')),
              values: texts(card.querySelectorAll('.dns-value')) };
  name.value = '203.0.113.10';
  fire(name, 'input');
  pick('MX');
  look.click();
  const invalid = card.querySelector('.dns-invalid');
  out.ipWithType = { text: text(invalid), shown: shown(invalid), typeInvalid: type.getAttribute('aria-invalid') };
  pick('PTR');
  out.ptrClears = !shown(invalid);
}
"""


def test_dns_card_record_types_in_a_browser(browser_page, mock, monkeypatch):
    """§7: the Record type select right after the name (Auto, then the service's types in order), the SRV placeholder, a NAPTR
    lookup summarised as the service's count, an SRV lookup without the service label showing the hint, and an IP address with
    a type other than PTR refused on the select."""
    mod, state = mock.mod, mock.state
    with _knobs(state, dns_delay_s=0.0):
        res = _run_probe(browser_page, mock, monkeypatch, "dns-types-probe.html", "tools", _DNS_TYPES_PROBE)
    options = [["", "Auto (A + AAAA)"], ["ALL", "All record types"], ["A", "A — IPv4 address"], ["AAAA", "AAAA — IPv6 address"], ["CNAME", "CNAME — alias"],
               ["MX", "MX — mail servers"], ["TXT", "TXT — text (SPF, verification)"], ["NS", "NS — name servers"], ["SOA", "SOA — zone serial"],
               ["SRV", "SRV — services (SIP…)"], ["CAA", "CAA — certificate authorities"], ["PTR", "PTR — name of an address"], ["NAPTR", "NAPTR — SIP routing"]]
    assert [value for value, _label in options[2:]] == list(mod.DNS_TYPES)      # Auto, then ALL, then the real types in order
    assert res["form"] == {"labels": ["DNS name / IP address", "Record type", "DNS server (optional)"], "options": options, "picked": "",
                           "placeholder": "www.example.com", "typeAfterName": True}
    assert (res["srvPlaceholder"], res["mxPlaceholder"]) == ("_sip._tcp.example.com", "www.example.com")
    zone = {row[0]: row for rows in mod.DNS_ZONE.values() for row in rows}
    assert res["naptr"] == {"summary": "example.com has 1 NAPTR record", "values": [zone["NAPTR"][2]], "hint": False}
    assert res["srv"] == {"summary": "example.com — No SRV records found for this name", "hint": "SRV names start with the service, for example _sip._tcp.example.com",
                          "hintShown": True, "values": []}
    assert res["ipWithType"] == {"text": mod.DNS_IP_TYPE_MSG, "shown": True, "typeInvalid": "true"} and res["ptrClears"] is True


_QUALITY_PROBE = r"""
async function run() {
  const doc = await until(() => app() && app().querySelector('#view .quality-card .grade-chip') && app(), 10000);
  const win = frame.contentWindow;
  const card = doc.querySelector('#view .quality-card');
  const chip = card.querySelector('.grade-chip');
  await until(() => chip.textContent !== '—', 10000);
  const read = () => ({ chip: chip.textContent, cls: chip.className, title: chip.title,
    lines: Array.from(card.querySelectorAll('.quality-body > *')).map((e) => [e.className, e.textContent]),
    checks: Array.from(card.querySelectorAll('.quality-checks .badge')).map((b) => [b.textContent, b.className, b.title]) });
  out.cards = Array.from(doc.querySelectorAll('#view .stack > .card > .card-title, #view .stack > .grid-2 > .card > .card-title')).map((t) => t.firstChild.textContent);
  out.measured = read();
  // the other states, drawn by the view's own update() from this status with another last test
  const st = win.TNT.state.status, last = st.speed.last;
  const show = (value) => { win.TNT.views.speed.update({ status: Object.assign({}, st, { speed: Object.assign({}, st.speed, { last: value }) }) }); return read(); };
  out.unavailable = show(Object.assign({}, last, { quality: Object.assign({}, last.quality, { available: false, reason: '1.1.1.1 did not answer pings' }) }));
  out.missing = show(Object.assign({}, last, { quality: null }));
  out.failedTest = show(Object.assign({}, last, { ok: false, error: 'HTTP 503 from speed.cloudflare.com', quality: null }));
  out.none = show(null);
  out.again = show(last);
}
"""


def test_latency_under_load_card_states_in_a_browser(browser_page, mock, monkeypatch):
    """§6.5: the card between Latest result and History. A graded test shows the grade chip (A+ / A / B green), the headline with
    both directions, the grade text and the details line; a result without the measurement, an unavailable one, a failed test and
    no test yet show a grey "—" and their text. The call-quality lines and the Zoom / Teams chips are not here any more: they
    moved to the SIP page, which is where somebody asking about calls is looking (tests/test_ui_sip.py)."""
    import math

    mod, state = mock.mod, mock.state
    assert _until(lambda: not state.speed_running, timeout=15.0), "a speed run is still going"
    with state.lock:
        base = next(r for r in reversed(state.speedtests) if r["ok"])
        row = dict(base, id=len(state.speedtests) + 1, ts=time.time() - 60, latency_ms=12.0, jitter_ms=1.0,
                   quality=state._speed_quality(12.0, 1.0, True))            # the evening shape: grade B, an echo lost each way
        state.speedtests.append(row)
    try:
        res = _run_probe(browser_page, mock, monkeypatch, "quality-probe.html", "speed", _QUALITY_PROBE)
    finally:
        with state.lock:
            state.speedtests.remove(row)

    def js_round(v: float) -> int:
        return int(math.floor(v + 0.5))

    def fmt_ms(v: float) -> str:                              # TNT.util.fmtMs
        return f"{v:.1f}" if v < 10 else str(js_round(v))

    def fmt_pct(v: float) -> str:                             # TNT.util.fmtPct
        return ("0" if v == 0 else f"{v:.2f}" if v < 0.1 else f"{v:.1f}" if v < 10 else str(js_round(v))) + "%"

    q = row["quality"]
    bb = q["bufferbloat"]
    base_w, down, up = q["windows"]["baseline"], q["windows"]["download"], q["windows"]["upload"]
    lines = [["strong quality-headline", f"Latency under load +{js_round(bb['increase_ms'])} ms (download +{js_round(down['increase_ms'])} ms, "
                                         f"upload +{js_round(up['increase_ms'])} ms)"],
             ["", bb["text"]]]
    if bb["warning"]:
        lines.append(["muted small quality-warning", bb["warning"]])
    lines.append(["muted small quality-details", f"Idle {fmt_ms(base_w['median_ms'])} ms to {q['target']} · busy {fmt_ms(down['mean_ms'])} / "
                                                 f"{fmt_ms(up['mean_ms'])} ms · loss {fmt_pct(down['loss_pct'])} / {fmt_pct(up['loss_pct'])} · "
                                                 f"{down['sent']} / {up['sent']} probes"])
    colour = {"A+": "green", "A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}[bb["grade"]]
    measured = {"chip": bb["grade"], "cls": f"grade-chip {colour}", "title": f"Bufferbloat grade {bb['grade']}", "lines": lines,
                "checks": []}
    assert res["cards"] == ["Latest result", "Latency under load", "History", "Patterns"]
    assert res["measured"] == measured and res["again"] == measured
    grey = {"chip": "—", "cls": "grade-chip grey", "title": "", "checks": []}
    assert res["unavailable"] == dict(grey, lines=[["muted", mod.REASON_NO_REPLIES.format(target="1.1.1.1")]])
    assert res["missing"] == dict(grey, lines=[["muted", "Not measured for this test"]])
    assert res["failedTest"] == dict(grey, lines=[["muted", "The last speed test failed"]])
    assert res["none"] == dict(grey, lines=[["muted", "Runs with every speed test"]])


# ---------------------------------------------------------------------------------------------------------- the new CSS blocks
_NAT_CSS = "/* ---------- network info: NAT & switch port ---------- */"
_QUALITY_CSS = "/* ---------- speed: latency under load ---------- */"
_NAMED_COLOUR = re.compile(r"(?<![-\w])(?:white|black|red|green|blue|yellow|orange|purple|pink|gray|grey)(?![-\w])")


def _tokens_only(css: str, start: str, end: str) -> str:
    """The span of tnt.css from the comment `start` to the next `end`, checked: colours only through the theme's tokens (every var()
    defined; no hex, colour function or named colour), and none of grid-column, :has(, @container or nth-child(odd)."""
    from test_ui import _css_rules

    assert css.count(start) == 1, start
    span = css[css.index(start):css.index(end, css.index(start))]
    body = re.sub(r"/\*.*?\*/", "", span, flags=re.S)
    assert body.strip(), start
    assert not re.search(r"#[0-9A-Fa-f]{3,8}\b", body), f"{start}: a hard-coded colour"
    assert not re.search(r"\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch)\(", body), f"{start}: a colour function instead of a token"
    for banned in ("grid-column", ":has(", "@container", "nth-child(odd)"):
        assert banned not in body, (start, banned)
    for selectors, decls in _css_rules(body):
        for prop, value in decls.items():
            assert not _NAMED_COLOUR.search(value), (start, selectors, prop, value)
    defined = set(re.findall(r"(--[\w-]+)\s*:", css))
    used = set(re.findall(r"var\(\s*(--[\w-]+)", body))
    assert used and used <= defined, (start, sorted(used - defined))
    return span


def test_network_info_card_css_block_uses_tokens_only():
    """§5.6: the card's rules sit after the .subnet-title rule and before the modals, tokens only."""
    css = _read("css/tnt.css")
    span = _tokens_only(css, _NAT_CSS, "/* ---------- modals")
    assert css.index(".subnet-title {") < css.index(_NAT_CSS)
    for sel in (".netcheck-card", ".nc-section", ".nc-head", ".nc-verdict", ".nc-details-btn", ".nc-details", ".nc-forwards", ".nc-path", ".nc-result",
                ".nc-actions"):
        assert sel in span, sel
    assert ".nc-port" not in span and ".nc-hints" not in span, "the port-forward rules moved to the tools section"


def test_latency_under_load_css_block_uses_tokens_only():
    """§6.5: the card's rules follow the speed section and come before discovery, tokens only."""
    css = _read("css/tnt.css")
    span = _tokens_only(css, _QUALITY_CSS, "/* ---------- discovery")
    assert css.index("/* ---------- speed ---------- */") < css.index(_QUALITY_CSS)
    for sel in (".quality-row", ".grade-chip", ".grade-chip.green", ".grade-chip.yellow", ".grade-chip.red", ".grade-chip.grey", ".quality-body",
                ".quality-headline", ".quality-warning", ".quality-call", ".quality-checks", ".quality-details"):
        assert sel in span, sel


def test_tftp_capture_and_dns_type_rules_sit_in_the_tools_css_section():
    """§10.4 / §1.8: every TFTP, packet capture (the page's own .cap- rules) and DNS record-type rule sits inside the tools
    section (the comment prefix tests/test_ui.py slices on), before the easter egg, and that section uses no colour function and none
    of grid-column, :has(, @container or nth-child(odd) (tests/test_ui.py already refuses hex colours there).
    The old card's .capture- rules went with the card: none may come back."""
    css = _read("css/tnt.css")
    start, end = css.index("tools: traceroute, LAN throughput, subnet calculator"), css.index("/* ---------- easter egg")
    code = re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group(0)), css, flags=re.S)      # comments blanked, offsets kept
    assert not re.search(r"\.capture-", code), "the deleted Packet capture card's .capture- rules are back"
    for pattern in (r"\.tftp-", r"\.cap-", r"\.dns-(?:type|values?|hint)\b"):
        at = [m.start() for m in re.finditer(pattern, code)]
        assert at and all(start <= p < end for p in at), (pattern, "rules outside the tools section", [p for p in at if not start <= p < end])
    tools = code[start:end]
    assert not re.search(r"\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch)\(", tools), "a colour function instead of a token in the tools section"
    for banned in ("grid-column", ":has(", "@container", "nth-child(odd)"):
        assert banned not in tools, banned


def test_shared_ui_wiring_keeps_the_contract():
    """§10.1-§10.3 and §5.1, which the browser tests cannot see (they refuse the event stream, and a missing icon falls back to
    another one silently): the api.js wrappers with their paths, methods and timeouts, the new KNOWN_EVENTS lines (every event the
    new cards and the capture page listen to is one of them), the icons they use, the tftp.state merge into the Tools tile, the
    Tools card entries and ctx.open, and the Network info card made before the first render and placed after the map."""
    api = _read("js/api.js")
    for s in ("natGet: () => api.get('/netcheck/nat'),", "natRun: () => api.post('/netcheck/nat', {}, { timeout: 45000 }),",
              "switchGet: () => api.get('/netcheck/switch'),", "switchStart: (body) => api.post('/netcheck/switch', body || {}),",
              "switchStop: () => api.del('/netcheck/switch'),",
              "portForwardTest: (port) => api.post('/netcheck/portforward', { port }, { timeout: 60000 }),",
              "tftpStatus: () => api.get('/tftp/status'),", "tftpStart: (body) => api.post('/tftp/start', body || {}, { timeout: 20000 }),",
              "tftpStop: () => api.post('/tftp/stop'),", "tftpUploads: (on) => api.post('/tftp/uploads', { on: !!on }),",
              "tftpSettings: (patch) => api.put('/tftp/settings', patch || {}),", "tftpFiles: () => api.get('/tftp/files'),",
              # the packet capture page: its own routes, and two URLs the page hands to a download link and an <audio>
              "captureGet: () => api.get('/capture'),", "captureStart: (body) => api.post('/capture/start', body || {}, { timeout: 20000 }),",
              "captureStop: () => api.post('/capture/stop', {}, { timeout: 20000 }),",
              "captureSave: () => api.post('/capture/save', {}, { timeout: 30000 }),",
              "captureDiscard: () => api.post('/capture/discard', {}),",
              "captureOpen: (name) => api.post('/capture/open', { name }, { timeout: 60000 }),",
              # any capture file on this PC, by its full path: a bigger timeout, because it may be a 4 GB one
              "captureOpenPath: (path) => api.post('/capture/open', { path }, { timeout: 120000 }),",
              "capturePackets: (q) => api.get('/capture/packets' + captureQuery(q)),",
              "capturePacket: (no) => api.get('/capture/packets/' + encodeURIComponent(no)),",
              "captureCalls: () => api.get('/capture/calls'),",
              "captureCallAudioUrl: (id) => BASE + '/capture/calls/' + encodeURIComponent(id) + '/audio',",
              "captureDeleteFile: (name) => api.del('/capture/files/' + encodeURIComponent(name)),",
              "captureFileUrl: (name) => BASE + '/capture/files/' + encodeURIComponent(name),",   # a URL only: no request
              "api.captureQuery = captureQuery;"):
        assert s in api, s
    assert "'/tools/capture" not in api, "the capture routes moved out of /tools"
    assert not (UI / "js" / "tools" / "capture.js").exists(), "the Packet capture card became js/views/capture.js"
    at = api.index("const KNOWN_EVENTS = [")
    events = api[at:api.index("];", at)]
    lines = [ln.strip() for ln in events.splitlines()[1:] if ln.strip()]
    assert "'dhcp.state', 'dhcp.lease', 'dhcp.scan', 'map.sample', 'throughput.sample', 'geoip.state'," in lines, "the pinned line is unchanged"
    report = lines.index("'report.progress', 'report.saved', 'report.deleted', 'report.updated',")
    assert lines[report + 1:] == ["'netcheck.switch',", "'tftp.state', 'tftp.transfer',", "'capture.state', 'capture.sip',"], lines[report:]
    known = set(re.findall(r"'([\w.]+)'", events))
    for rel, heard in (("js/netcheck.js", {"netcheck.switch", "hello"}), ("js/tools/tftp.js", {"tftp.state", "tftp.transfer", "hello"}),
                       ("js/views/capture.js", {"capture.state", "capture.sip", "hello"})):
        found = set(re.findall(r"TNT\.api\.events\.on\('([\w.]+)'", _read(rel)))
        assert found == heard and found <= known, (rel, sorted(found), sorted(found - known))

    app = _read("js/app.js")
    icons = app[app.index("const ICONS = {"):app.index("TNT.icons = {")]
    names = set(re.findall(r"^    '?([\w-]+)'?\s*:", icons, re.M))
    assert {"tftp", "capture", "phone"} <= names and "natcheck" not in names
    # every icon the new cards and the capture page brought carries a "// picture: where" comment of its own
    described = [c for c in re.findall(r"^    // (.+)$", icons, re.M) if ": the " in c]
    for what in ("the TFTP server card", "the Packet capture", "the SIP calls"):
        assert any(what in c for c in described), (what, described)
    used = set()
    for rel in ("js/netcheck.js", "js/tools/tftp.js", "js/views/capture.js", "js/tools/dns.js", "js/views/speed.js"):
        used |= set(re.findall(r"\bicon\('([\w-]+)'", _read(rel)))
    tools = _read("js/views/tools.js")
    cards_at = tools.index("const EXTRA_CARDS = [")
    cards = tools[cards_at:tools.index("];", cards_at)]
    used |= set(re.findall(r"icon: '([\w-]+)'", cards))
    assert used and used <= names, sorted(used - names)
    dhcp_at = app.index("ev.on('dhcp.state', ")
    tftp_line = ("ev.on('tftp.state', (d) => { if (state.status && d) { state.status.tftp = Object.assign({}, state.status.tftp || {}, d); "
                 "renderTiles(); } });")
    assert app.index("ev.on(", dhcp_at + 1) == app.index(tftp_line), "the tftp.state merge comes right after dhcp.state"

    assert re.findall(r"\{ key: '(\w+)'", cards) == ["lan", "portforward", "traceroute", "tftp", "subnet", "dns", "wifi"]
    assert "const CARD_ORDER = ['lan', 'portforward', 'traceroute', 'dhcp', 'tftp', 'subnet', 'dns', 'wifi'];" in tools
    assert "capture" not in cards and "TNT.tools.capture" not in tools, "Packet capture is a page of its own now"
    for s in ("{ key: 'tftp', title: 'TFTP server', icon: 'tftp', create: (ctx) => TNT.tools.tftp.create(ctx) },",
              "{ key: 'portforward', title: 'Port forward check', icon: 'target', create: (ctx) => TNT.tools.portforward.create(ctx) },",
              "try { mod = c.create({ open: () => openCard(c.key) }); }"):
        assert s in tools, s
    # the page itself: its own view, its own tile, loaded like the other views
    index = _read("index.html")
    assert '<script src="js/views/capture.js"></script>' in index and "js/tools/capture.js" not in index
    assert '<a class="tile half" data-view="capture" href="#capture"' in index
    assert '<span class="tile-icon" data-icon="capture"></span><span class="tile-title">Packet capture</span>' in index
    assert '<div class="tile-body" id="tile-capture">' in index
    capture = _read("js/views/capture.js")
    assert "TNT.views.capture = {" in capture and "TNT.api.captureGet()" in capture and "TNT.api.capturePackets(" in capture
    assert "tileEls.capture" in app and "const c = st && st.capture;" in app, "the tile reads status.capture"

    ipinfo = _read("js/views/ipinfo.js")
    mount = ipinfo[ipinfo.index("    mount(el) {"):ipinfo.index("    update(state) {")]
    for made in ("tp = TNT.throughput.create();", "nc = TNT.netcheck.create();"):
        assert mount.index(made) < mount.index("render();"), f"{made} must run before the first render"
    render = ipinfo[ipinfo.index("  function render() {"):ipinfo.index("  async function load(quiet) {")]
    appends = re.findall(r"gridEl\.appendChild\(([^;]*)\);", render)
    # both branches of render() (loading, and with the adapters) lay the same three out in the same
    # order: the live link map, realtime throughput, then NAT & switch port
    maps = [i for i, a in enumerate(appends) if a == "buildMapCard()"]
    assert len(maps) == 2, appends
    for i in maps:
        assert appends[i + 1:i + 3] == ["tp.el", "nc.el"], appends
    load = ipinfo[ipinfo.index("  async function load(quiet) {"):]
    error = load.index("TNT.ui.emptyState('Could not load adapters: '")
    # a failed adapter read says nothing about the counters or about a NAT result already in hand
    assert load.index("if (tp) gridEl.appendChild(tp.el);") < load.index("if (nc) gridEl.appendChild(nc.el);") < error
    for s in ("if (nc) nc.update(state);", "nc.unmount();", "if (tp) tp.update(state);", "tp.unmount();",
              "netChanged() { if (root) load(true); },"):
        assert s in ipinfo, s
