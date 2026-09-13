from test_ui import mock, browser_page, _req, _serve_probe, _probe_result, _load_mock, _read, _doc, UI, ROOT  # noqa: F401

# The mock API (tools/mock_api.py) for the 1.15.0 network tools, held to the service: every key tuple, text, limit and rule the mock
# mirrors equals tnt.natcheck / tnt.switchport / tnt.lldp / tnt.pktmon / tnt.portcheck / tnt.tftp / tnt.capture /
# tnt.speedtest.quality / tnt.nettools / tnt.api.routes (the test_mock_network_tools_follow_the_service pattern), and its routes answer
# with the service's shapes, status codes and error codes, their timing knobs shortened and put back afterwards. Offline: the mock on
# 127.0.0.1 and the tnt modules with fakes only.
import contextlib
import http.client
import json
import queue
import re
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
    assert mod.PKTMON_LOCK_TEXTS == pktmon.LOCK_TEXTS
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
    from tnt import capture, pcapng, pktmon
    from tnt.api import routes
    mod, state = offline.mod, offline.state
    _same(mod, capture, {k: k for k in ("CAPTURE_JOB_KEYS", "CAPTURE_FILE_KEYS", "CAPTURE_STATUS_KEYS", "CAPTURE_ADAPTER_KEYS", "CAPTURE_STATES",
                                        "CAPTURE_SECONDS", "CAPTURE_SIZES_MB")})
    _same(mod, capture, {"CAPTURE_FILTER_KEYS": "FILTER_KEYS", "CAPTURE_RUNNING_STATES": "RUNNING_STATES", "CAPTURE_PROTOCOLS": "PROTOCOLS",
                         "CAPTURE_FILE_RE": "FILE_RE", "CAPTURE_SECONDS_TEXT": "SECONDS_TEXT", "CAPTURE_SIZE_TEXT": "SIZE_TEXT",
                         "CAPTURE_HOST_TEXT": "HOST_TEXT", "CAPTURE_PORT_TEXT": "PORT_TEXT", "CAPTURE_PROTOCOL_TEXT": "PROTOCOL_TEXT",
                         "CAPTURE_PORT_ICMP_TEXT": "PORT_ICMP_TEXT", "CAPTURE_ADAPTER_TEXT": "ADAPTER_TEXT",
                         "CAPTURE_FULL_PACKETS_TEXT": "FULL_PACKETS_TEXT", "CAPTURE_FILE_MISSING_TEXT": "FILE_MISSING_TEXT"})
    manager = capture.CaptureManager(None, captures_dir_fn=lambda: tmp_path, acl=lambda path, sddl: None)    # never the real folder
    assert mod.CAPTURE_SECONDS_RANGE == (manager._min_seconds, manager._max_seconds)
    assert (mod.CAPTURE_ADMIN_REQUIRED_MSG, mod.CAPTURE_ADMIN_UNVERIFIED_MSG) == (routes.CAPTURE_ADMIN_REQUIRED_MSG,
                                                                                  routes.CAPTURE_ADMIN_UNVERIFIED_MSG)
    assert set(routes.CAPTURE_START_KEYS) == {"adapter", "seconds", "size_mb", "full_packets", "host", "port", "protocol"}
    assert capture._is_capture_name(mod.CAPTURE_SEED_FILE)

    bodies = [{"adapter": "Ethernet"}, {}, {"adapter": None}, {"adapter": ""}, {"adapter": 5}, {"adapter": "Wi-Fi"}, {"adapter": "Tailscale"},
              {"adapter": "  Ethernet 2 "}]
    for key, values in (("seconds", [4, 5, 1800, 1801, 30.0, 30.5, "60", None, True]), ("size_mb", [64, 100, 128.0, None, "128"]),
                        ("host", ["192.0.2.10", " 2001:db8::1 ", "", "   ", "fe80::1%12", "192.0.2.0/24", "example.com", 5, None]),
                        ("port", [0, 1, 65535, 65536, 8000.0, "80", True, None]), ("protocol", ["TCP", " udp ", "icmp", "", "sctp", 7, None]),
                        ("full_packets", [False, "yes", None, 0])):
        bodies += [{"adapter": "Ethernet", key: value} for value in values]
    bodies += [{"adapter": "Ethernet", "port": 80, "protocol": "icmp"}, {"adapter": "Ethernet", "host": "2001:db8::1", "protocol": "ICMP"},
               {"adapter": "Nope", "seconds": 4}, {"adapter": "Ethernet", "size_mb": 1, "host": "bad"}]
    def refuse(path: str, sddl: str) -> None:
        raise OSError("no folder is secured in this test")

    try:
        for name in mod.NET_PROFILE_NAMES:
            state.net_profile = name
            profile = mod.net_profile(name)
            # Packet Monitor is there and its lock is free: a start that passed its checks stops at the folder securer
            mgr = capture.CaptureManager(None, adapters_fn=lambda: profile["adapters"], capability_fn=lambda: {"ok": True, "reason": None},
                                         captures_dir_fn=lambda: tmp_path, acl=refuse)
            assert state.capture_adapters() == mgr.adapters(), name

            def service(body: Dict[str, Any]) -> Tuple[str, Any]:
                kwargs = {k: body[k] for k in routes.CAPTURE_START_KEYS if k in body}
                kwargs["adapter"] = body.get("adapter")
                try:
                    mgr.start(**kwargs)
                except ValueError as exc:
                    return ("error", str(exc))
                except pktmon.PktmonUnavailable as exc:
                    assert str(exc) == pktmon.FOLDER_NOT_SECURED_TEXT, exc
                    job = mgr.job()                             # the values the capture would have run with
                    return ("ok", {k: job[k] for k in ("adapter", "filters", "full_packets", "seconds", "size_mb")})
                return ("started", None)

            for body in bodies:
                assert _outcome(lambda: mod.capture_start_values(body, state.capture_adapters())) == service(body), (name, body)
    finally:
        state.net_profile = "a"
    assert pktmon.LOCK.holder() is None

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
    assert [f["size"] for f in state.capture_status()["files"]] == [len(data)]


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
    tools = [(pattern, methods) for pattern, methods in table if pattern.startswith(("/api/netcheck/", "/api/tftp/", "/api/tools/capture"))]
    assert len(tools) >= 10
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
        "conflict", "unavailable", "rate_limited", "no_public_ip", "vpn", "tftp_port_in_use", "not_found"}


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
            st, _, locked = _req(port, "POST", "/api/tools/capture", {"adapter": "Ethernet"})
            assert st == 409 and locked["error"] == {"code": "conflict", "message": "TNT is finding the switch port: try again when it finishes"}
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


def test_mock_packet_capture_routes(mock):
    mod, state, port = mock.mod, mock.state, mock.port
    files = f"/api/tools/capture/files/{SEED_CAPTURE}"
    seeded = [dict(f) for f in state.capture_files]
    before = (state.capture_job, state.capture_next_id)
    try:
        # a standard user: the service's 403 from every capture route, the download included
        with _knobs(state, wifi_admin=False):
            for method, path, body in (("GET", "/api/tools/capture", None), ("POST", "/api/tools/capture", {"adapter": "Ethernet"}),
                                       ("DELETE", "/api/tools/capture", None), ("GET", files, None), ("DELETE", files, None)):
                st, _, err = _req(port, method, path, body)
                assert st == 403 and err["error"] == {"code": "admin_required", "message": "Packet capture needs a Windows administrator account."}, path
        st, _, s = _req(port, "GET", "/api/tools/capture")
        assert st == 200 and list(s) == list(mod.CAPTURE_STATUS_KEYS) and (s["available"], s["reason"], s["capture"]) == (True, None, None)
        assert s["adapters"] == [{"name": "Ethernet", "index": 12, "mac": "D8:BB:C1:12:34:08", "type_name": "Ethernet", "wifi": False},
                                 {"name": "Ethernet 2", "index": 18, "mac": "02:5E:10:00:00:18", "type_name": "Ethernet", "wifi": False},
                                 {"name": "Ethernet 3", "index": 19, "mac": "02:5E:10:00:00:19", "type_name": "Ethernet", "wifi": False}]
        assert [list(f) for f in s["files"]] == [list(mod.CAPTURE_FILE_KEYS)] and s["files"][0]["name"] == SEED_CAPTURE
        # the download, as a FileResponse: an attachment of its length, not cached, not sniffed; HEAD sends the headers only
        st, headers, data = _req(port, "GET", files, raw=True)
        assert st == 200 and data[:4] == b"\x0a\x0d\x0d\x0a" and int(headers["content-length"]) == len(data) == s["files"][0]["size"]
        assert (headers["content-type"], headers["content-disposition"], headers["cache-control"], headers["x-content-type-options"]) == (
            "application/octet-stream", f'attachment; filename="{SEED_CAPTURE}"', "no-cache", "nosniff")
        st, head, body = _send(port, "HEAD", files)
        assert st == 200 and body == b"" and head["content-length"] == str(len(data))
        for method, path in (("GET", "/api/tools/capture/files/TNT-capture-20990101-000000.pcapng"), ("GET", "/api/tools/capture/files/..%5Cx.pcapng"),
                             ("DELETE", "/api/tools/capture/files/notes.txt")):
            st, _, err = _req(port, method, path)
            assert st == 404 and err["error"] == {"code": "not_found", "message": "The capture file was not found"}, path
        for body, message in (({"adapter": "Ethernet", "seconds": 4}, "seconds must be a whole number from 5 to 1800"),
                              ({"adapter": "Wi-Fi"}, "adapter 'Wi-Fi' is not up"),
                              ({"adapter": "Ethernet", "port": 80, "protocol": "icmp"}, "port cannot be combined with protocol icmp"),
                              ({"adapter": "Ethernet", "size_mb": 100}, "size_mb must be one of 64, 128, 256, 512 or 1024")):
            st, _, err = _req(port, "POST", "/api/tools/capture", body)
            assert st == 400 and err["error"] == {"code": "bad_request", "message": message}, body
        with _knobs(state, pktmon_reason=mod.PKTMON_REASONS[1]):
            st, _, err = _req(port, "POST", "/api/tools/capture", {"adapter": "Ethernet"})
            assert st == 409 and err["error"] == {"code": "unavailable", "message": "Packet Monitor (pktmon.exe) is missing from this PC"}
            assert _req(port, "GET", "/api/tools/capture")[2]["available"] is False
        # a capture that runs its time and lists a new file
        q = state.hub.subscribe()
        try:
            with _knobs(state, capture_s=0.3):
                st, _, started = _req(port, "POST", "/api/tools/capture", {"adapter": "Ethernet", "seconds": 10, "size_mb": 64, "full_packets": False,
                                                                            "host": " 192.0.2.10 ", "protocol": "ICMP"})
                job = started["capture"]
                assert st == 200 and list(job) == list(mod.CAPTURE_JOB_KEYS) and list(job["adapter"]) == list(mod.CAPTURE_ADAPTER_KEYS)
                assert (job["state"], job["filters"], job["full_packets"], job["seconds"], job["size_mb"], job["file"]) == (
                    "capturing", {"host": "192.0.2.10", "port": None, "protocol": "icmp"}, False, 10, 64, None)
                st, _, busy = _req(port, "POST", "/api/tools/capture", {"adapter": "Ethernet 2"})
                assert st == 409 and busy["error"] == {"code": "conflict", "message": "A packet capture is running: stop it first"}
                st, _, busy = _req(port, "POST", "/api/netcheck/switch", {})
                assert st == 409 and busy["error"]["message"] == "A packet capture is running: stop it first"
                frames = _frames(q, ("capture.state",), lambda kind, data: data["capture"]["state"] == "done")
                assert [data["capture"]["state"] for _kind, data in frames][-2:] == ["converting", "done"]
            done = _req(port, "GET", "/api/tools/capture")[2]
            name = done["capture"]["file"]
            assert done["capture"]["state"] == "done" and done["files"][0] == {"name": name, "size": len(data), "created_ts": done["files"][0]["created_ts"],
                                                                                 "packets": 1}
            assert mod._CAPTURE_FILE.fullmatch(name)
            # Stop and save keeps the capture
            with _knobs(state, capture_s=30.0):
                _req(port, "POST", "/api/tools/capture", {"adapter": "Ethernet 3"})
                st, _, stopped = _req(port, "DELETE", "/api/tools/capture")
                assert st == 200 and stopped["capture"]["state"] in ("converting", "done")
                kept = _until(lambda: (lambda c: c if c["state"] == "done" else None)(_req(port, "GET", "/api/tools/capture")[2]["capture"]))
                assert kept["file"] and kept["file"] != name and kept["elapsed_s"] < 5
        finally:
            state.hub.unsubscribe(q)
        st, _, left = _req(port, "DELETE", f"/api/tools/capture/files/{name}")
        assert st == 200 and name not in [f["name"] for f in left["files"]] and SEED_CAPTURE in [f["name"] for f in left["files"]]
    finally:
        state.capture_files = seeded
        state.capture_job, state.capture_next_id = before


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


def test_mock_event_stream_sends_capture_state_to_administrators_only(mock):
    """GET /api/events follows the service: capture.state (the capture job, which every capture route refuses to a standard
    user) goes only to a Windows administrator (STATE.wifi_admin), every other event to everyone."""
    from tnt.api import routes
    mod, state, port = mock.mod, mock.state, mock.port
    assert mod.ADMIN_ONLY_EVENTS == routes.ADMIN_ONLY_EVENTS
    job = {"capture": {"id": "sse-admin-test", "state": "capturing", "filters": {"host": "192.0.2.50", "port": 5060, "protocol": "udp"}}}
    for admin in (False, True):
        with _knobs(state, wifi_admin=admin):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                conn.request("GET", "/api/events")
                resp = conn.getresponse()
                assert resp.status == 200 and _sse_until(resp, "hello")[-1][0] == "hello"
                state.hub.publish("capture.state", job)
                state.hub.publish("test.sentinel", {"admin": admin})
                seen = _sse_until(resp, "test.sentinel")
            finally:
                conn.close()
        mine = [data for kind, data in seen if kind == "capture.state" and (data.get("capture") or {}).get("id") == "sse-admin-test"]
        assert mine == ([job] if admin else []), admin


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
    ("POST", "/api/netcheck/portforward", {"port": 8000}), ("POST", "/api/tools/capture", {"adapter": "Ethernet"}), ("DELETE", "/api/tools/capture", None),
    ("GET", f"/api/tools/capture/files/{SEED_CAPTURE}", None), ("DELETE", f"/api/tools/capture/files/{SEED_CAPTURE}", None),
    ("POST", "/api/tftp/start", {}), ("POST", "/api/tftp/stop", {}), ("POST", "/api/tftp/uploads", {"on": True}),
    ("PUT", "/api/tftp/settings", {"max_upload_mb": 1}),
])
def test_mock_network_tools_refuse_a_page_of_another_origin_115(mock, method, path, body):
    """A browser page of another origin gets 403 forbidden before anything runs, before the capture routes' administrator check."""
    state, port = mock.state, mock.port

    def snapshot() -> Any:
        with state.lock:
            return json.dumps([state.nat_last, state.nat_running, state.switch_job, state.portcheck_last, state.portcheck_running, state.tftp_running,
                               state.tftp_uploads, state.settings["tftp"], state.capture_job, [f["name"] for f in state.capture_files]], sort_keys=True)

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
  out.layout = { cells: cells.slice(0, 3).map((c) => c.className), columns: getComputedStyle(grid).gridTemplateColumns.split(' ').length,
                 map: box(cells[0]), card: box(cells[1]), third: box(cells[2]),
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
    assert "linkmap" in lay["cells"][0].split() and lay["cells"][1] == "card netcheck-card" and "adapter" in lay["cells"][2].split(), lay
    assert lay["columns"] == 3 and lay["overflow"] is False, lay
    assert lay["map"]["top"] == lay["card"]["top"] == lay["third"]["top"], lay
    assert lay["map"]["left"] < lay["card"]["left"] < lay["third"]["left"] and abs(lay["card"]["width"] - lay["map"]["width"]) <= 1, lay
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
  const tftpLine = () => {
    const l = Array.from(tile.querySelectorAll('.tile-line')).find((x) => x.textContent.indexOf('TFTP server ') === 0);
    return l ? { text: l.textContent, badge: l.querySelector('.badge').className, title: l.title } : null;
  };
  const boxes = () => texts(Array.from(card.querySelectorAll('.dhcp-info.bad')).filter((b) => !b.hidden));
  await until(() => badge.textContent === 'error' && tftpLine(), 10000);
  out.error = { badge: badge.textContent, cls: badge.className, title: badge.title, checked: toggle.checked, expanded: cardToggle.getAttribute('aria-expanded'),
                boxes: boxes(), tile: tftpLine() };
  toggle.click();
  await until(() => badge.textContent === 'on' && card.querySelector('.tftp-files tbody tr'), 10000);
  out.on = { badge: badge.textContent, cls: badge.className, checked: toggle.checked, expanded: cardToggle.getAttribute('aria-expanded'), errorBoxes: boxes().length,
             summary: text(card.querySelector('.tftp-summary')), files: texts(card.querySelectorAll('.tftp-files tbody tr td:first-child')),
             folder: text(card.querySelector('.tftp-folder code')), note: text(card.querySelector('.tftp-uploads-note')),
             scopeMatches: text(card.querySelector('.tftp-scope')) === win.TNT.tools.tftp.TFTP_SCOPE_TEXT };
  out.toastsOn = texts(doc.querySelectorAll('#toasts .toast'));      // before the tile wait: a toast leaves after 3.2 s of the page's clock
  out.tileOn = await until(() => { const l = tftpLine(); return l && l.text === 'TFTP server on' ? l : null; }, 20000);
  // "Allow uploads" while it serves: yellow on the card and on the Tools tile, then green again
  const uploads = () => card.querySelector('input[aria-label="Allow uploads"]');
  uploads().click();
  await until(() => badge.textContent === 'uploads on', 10000);
  out.uploads = { badge: badge.textContent, cls: badge.className, checked: uploads().checked, toasts: texts(doc.querySelectorAll('#toasts .toast')) };
  out.tileUploads = await until(() => { const l = tftpLine(); return l && l.text === 'TFTP server uploads on' ? l : null; }, 20000);
  uploads().click();
  await until(() => badge.textContent === 'on', 10000);
  out.uploadsOff = { checked: uploads().checked, tile: await until(() => { const l = tftpLine(); return l && l.text === 'TFTP server on' ? l : null; }, 20000) };
  toggle.click();
  await until(() => badge.textContent === 'off', 10000);
  await until(() => !tftpLine(), 20000);
  out.off = { badge: badge.textContent, cls: badge.className, checked: toggle.checked, tile: tftpLine(), summary: text(card.querySelector('.tftp-summary')),
              names: texts(tile.querySelectorAll('.tile-tool')) };
  out.server = await win.fetch('/api/tftp/status').then((r) => r.json()).then((s) => ({ running: s.running, error: s.error }));
}
"""


def test_tftp_card_on_and_off_and_its_tools_tile_line_in_a_browser(browser_page, mock, monkeypatch):
    """§9.7 / §10.1 as built: a server stopped by a network change shows a red "error" badge (the error as its title and in a red
    box) and a red "TFTP server error" line on the Tools tile while it is off; switching it on opens the card, serves (green "on",
    the files, the folder, the uploads note, the scope text) and the tile line turns green; "Allow uploads" turns the badge and the
    tile line yellow ("uploads on") and back; switching it off clears the tile line."""
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
    assert err["tile"] == {"text": "TFTP server error", "badge": "badge red", "title": stopped}
    on = res["on"]
    assert (on["badge"], on["cls"], on["checked"], on["expanded"], on["errorBoxes"], on["scopeMatches"]) == ("on", "badge green", True, "true", 0, True)
    assert re.fullmatch(r"Serving on Ethernet · \d{1,3}(\.\d{1,3}){3} · on .+", on["summary"]), on["summary"]
    assert on["files"] == sorted(name for name, _size, _age in mod.TFTP_FILES)
    assert on["folder"].endswith("\\tftp") and on["note"] == "Anyone on this network can upload files while this is on"
    assert res["tileOn"] == {"text": "TFTP server on", "badge": "badge green", "title": ""}
    assert "TFTP server is on" in res["toastsOn"]
    up = res["uploads"]
    assert (up["badge"], up["cls"], up["checked"]) == ("uploads on", "badge yellow", True) and "Uploads are on" in up["toasts"], up
    assert res["tileUploads"] == {"text": "TFTP server uploads on", "badge": "badge yellow", "title": ""}
    assert res["uploadsOff"] == {"checked": False, "tile": {"text": "TFTP server on", "badge": "badge green", "title": ""}}
    off = res["off"]
    assert (off["badge"], off["cls"], off["checked"], off["tile"], off["summary"]) == ("off", "badge grey", False, None, "Would serve on Ethernet")
    assert off["names"] == ["LAN throughput", "Port forward", "Traceroute", "TFTP server", "Subnet calc", "DNS", "Packet capture", "WiFi passwords"]
    assert res["server"] == {"running": False, "error": None}


_CAPTURE_ADMIN_PROBE = r"""
async function run() {
  const doc = await until(() => app() && app().querySelector('[data-tool="capture"] .capture-admin') && app(), 10000);
  const card = doc.querySelector('[data-tool="capture"]');
  await until(() => !card.querySelector('.capture-admin').hidden, 10000);
  card.querySelector('.card-title').click();
  out.admin = { text: text(card.querySelector('.capture-admin')), shown: shown(card.querySelector('.capture-admin')), main: shown(card.querySelector('.capture-main')),
                expanded: card.querySelector('.card-toggle').getAttribute('aria-expanded'), toasts: texts(doc.querySelectorAll('#toasts .toast')) };
  const r = await frame.contentWindow.fetch('/api/tools/capture');
  out.status = { code: r.status, body: await r.json() };
}
"""

_CAPTURE_RUN_PROBE = r"""
async function run() {
  const doc = await until(() => app() && app().querySelector('[data-tool="capture"] .capture-table tbody tr') && app(), 10000);
  const win = frame.contentWindow;
  const card = doc.querySelector('[data-tool="capture"]');
  card.querySelector('.card-title').click();
  const q = (s) => card.querySelector(s);
  const adapter = q('select[aria-label="Adapter"]'), duration = q('select[aria-label="Duration"]'), size = q('select[aria-label="File size limit"]');
  const protocol = q('select[aria-label="Protocol"]'), host = q('input[aria-label="Host (optional)"]'), port = q('input[aria-label="Port (optional)"]');
  const start = q('.capture-actions .btn-primary');
  const stop = Array.from(card.querySelectorAll('.capture-actions button')).find((b) => b.textContent === 'Stop and save');
  const rows = () => Array.from(card.querySelectorAll('.capture-table tbody tr')).map((tr) => texts(Array.from(tr.children).slice(0, 3)));
  out.form = { adapters: texts(adapter.options), durations: texts(duration.options), duration: duration.value, sizes: texts(size.options), size: size.value,
               protocols: texts(protocol.options),
               packets: Array.from(card.querySelectorAll('.capture-actions .seg button')).map((b) => [b.textContent, b.getAttribute('aria-selected'), b.title]),
               warningMatches: text(q('.capture-warning')) === win.TNT.tools.capture.WARNING_TEXT, stopShown: shown(stop), files: rows() };
  protocol.value = 'icmp';
  fire(protocol, 'change');
  out.icmpPortDisabled = port.disabled;
  protocol.value = '';
  fire(protocol, 'change');
  out.portEnabledAgain = !port.disabled;
  host.value = 'not an address';
  start.click();
  out.invalid = { text: text(q('.capture-invalid')), shown: shown(q('.capture-invalid')), ariaInvalid: host.getAttribute('aria-invalid') };
  host.value = '';
  fire(host, 'input');
  out.invalidCleared = !shown(q('.capture-invalid'));
  duration.value = '10';
  start.click();
  await until(() => shown(q('.capture-progress')), 5000);
  out.running = { label: text(q('.capture-progress .fuse-label .l')), stopShown: shown(stop), startShown: shown(start), adapterDisabled: adapter.disabled };
  await realWait(900);
  await until(() => q('.capture-main > .tool-summary.ok') && rows().length === 2, 20000);
  out.done = { result: text(q('.capture-main > .tool-summary.ok')), files: rows(), progress: shown(q('.capture-progress')), startShown: shown(start),
               toasts: texts(doc.querySelectorAll('#toasts .toast')) };
  // the download is this page's own origin (the service refuses a page of another origin)
  const url = win.TNT.api.captureFileUrl(out.done.files[0][0]);
  const r = await win.fetch(url);
  const bytes = new Uint8Array(await r.arrayBuffer());
  out.download = { url, status: r.status, magic: Array.from(bytes.slice(0, 4)), length: bytes.length, disposition: r.headers.get('content-disposition') };
}
"""


def test_packet_capture_card_needs_an_administrator_then_captures_in_a_browser(browser_page, mock, monkeypatch):
    """§8.8: a standard user's 403 admin_required shows the note instead of the form (no toast); an administrator gets the form
    (durations, sizes, protocols, Full packets / First 128 bytes, the warning), ICMP disables Port, a bad host is caught on the page,
    and a capture runs (fuse, Stop and save) and is listed first with its packet count, downloadable from the page's own origin."""
    mod, state = mock.mod, mock.state
    seeded = [dict(f) for f in state.capture_files]
    before = (state.capture_job, state.capture_next_id)
    try:
        with _knobs(state, wifi_admin=False):
            admin = _run_probe(browser_page, mock, monkeypatch, "capture-admin-probe.html", "tools", _CAPTURE_ADMIN_PROBE)
        with _knobs(state, wifi_admin=True, capture_s=0.3, pktmon_reason=None, switch_job=None):
            res = _run_probe(browser_page, mock, monkeypatch, "capture-probe.html", "tools", _CAPTURE_RUN_PROBE, budget_ms=30000)
    finally:
        _until(lambda: (state.capture_job or {}).get("state") not in ("starting", "capturing", "converting"), timeout=5.0)
        state.capture_files = seeded
        state.capture_job, state.capture_next_id = before
    assert admin["admin"] == {"text": "Packet capture needs a Windows administrator account", "shown": True, "main": False, "expanded": "true", "toasts": []}
    assert admin["status"] == {"code": 403, "body": {"error": {"code": "admin_required", "message": mod.CAPTURE_ADMIN_REQUIRED_MSG}}}
    f = res["form"]
    assert f["adapters"] == ["Ethernet", "Ethernet 2", "Ethernet 3"]
    assert (f["durations"], f["duration"]) == (["10 s", "30 s", "1 min", "5 min", "15 min"], "60")
    assert (f["sizes"], f["size"]) == ([f"{mb} MB" for mb in mod.CAPTURE_SIZES_MB], "128")
    assert f["protocols"] == ["Any", "TCP", "UDP", "ICMP"]
    assert f["packets"] == [["Full packets", "true", ""],
                            ["First 128 bytes", "false", "Mostly headers, but the start of unencrypted data (such as FTP or SNMP passwords) can still be in it"]]
    assert f["warningMatches"] is True and f["stopShown"] is False
    assert [row[0] for row in f["files"]] == [SEED_CAPTURE] and f["files"][0][2] == "1"
    assert (res["icmpPortDisabled"], res["portEnabledAgain"]) == (True, True)
    assert res["invalid"] == {"text": "host must be an IP address", "shown": True, "ariaInvalid": "true"} and res["invalidCleared"] is True
    running = res["running"]
    assert re.fullmatch(r"Capturing… 0:0\d of 0:10", running["label"] or ""), running
    assert (running["stopShown"], running["startShown"], running["adapterDisabled"]) == (True, False, True), running
    done = res["done"]
    name = done["files"][0][0]
    assert re.fullmatch(r"TNT-capture-\d{8}-\d{6}\.pcapng", name) and name != SEED_CAPTURE
    assert [row[0] for row in done["files"]] == [name, SEED_CAPTURE] and [row[2] for row in done["files"]] == ["1", "1"]
    assert (done["result"], done["progress"], done["startShown"]) == (f"Saved {name}", False, True)
    assert f"Capture saved: {name}" in done["toasts"]
    assert res["download"] == {"url": f"/api/tools/capture/files/{name}", "status": 200, "magic": [10, 13, 13, 10], "length": len(mod.tiny_pcapng(0.0)),
                               "disposition": f'attachment; filename="{name}"'}


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
    both directions, the grade text, the call quality idle and busy, the Zoom / Teams chips with the service's detail and the
    details line; a result without the measurement, an unavailable one, a failed test and no test yet show a grey "—" and their
    text."""
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
    bb, call = q["bufferbloat"], q["call"]
    base_w, down, up = q["windows"]["baseline"], q["windows"]["download"], q["windows"]["upload"]
    checks = [[{"zoom": "Zoom", "teams": "Teams"}[c["key"]] + (" ✓" if c["ok"] else " ✗"), "badge " + ("green" if c["ok"] else "red"), c["detail"] or ""]
              for c in call["checks"]]
    lines = [["strong quality-headline", f"Latency under load +{js_round(bb['increase_ms'])} ms (download +{js_round(down['increase_ms'])} ms, "
                                         f"upload +{js_round(up['increase_ms'])} ms)"],
             ["", bb["text"]]]
    if bb["warning"]:
        lines.append(["muted small quality-warning", bb["warning"]])
    lines.append(["quality-call", f"Call quality: {call['idle']['label']} (MOS {call['idle']['mos']:.2f}, estimate)"])
    if call["loaded"]:
        lines.append(["quality-call", f"While the line is busy: {call['loaded']['label']} (MOS {call['loaded']['mos']:.2f})"])
    lines.append(["row quality-checks", "".join(c[0] for c in checks)])
    lines.append(["muted small quality-details", f"Idle {fmt_ms(base_w['median_ms'])} ms to {q['target']} · busy {fmt_ms(down['mean_ms'])} / "
                                                 f"{fmt_ms(up['mean_ms'])} ms · loss {fmt_pct(down['loss_pct'])} / {fmt_pct(up['loss_pct'])} · "
                                                 f"{down['sent']} / {up['sent']} probes"])
    colour = {"A+": "green", "A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}[bb["grade"]]
    measured = {"chip": bb["grade"], "cls": f"grade-chip {colour}", "title": f"Bufferbloat grade {bb['grade']}", "lines": lines, "checks": checks}
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
    """§10.4 / §1.8: every TFTP, capture and DNS record-type rule sits inside the tools section (the comment prefix tests/test_ui.py
    slices on), before the easter egg, and that section uses no colour function and none of grid-column, :has(, @container or
    nth-child(odd) (tests/test_ui.py already refuses hex colours there)."""
    css = _read("css/tnt.css")
    start, end = css.index("tools: traceroute, LAN throughput, subnet calculator"), css.index("/* ---------- easter egg")
    code = re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group(0)), css, flags=re.S)      # comments blanked, offsets kept
    for pattern in (r"\.tftp-", r"\.capture-", r"\.dns-(?:type|values?|hint)\b"):
        at = [m.start() for m in re.finditer(pattern, code)]
        assert at and all(start <= p < end for p in at), (pattern, "rules outside the tools section", [p for p in at if not start <= p < end])
    tools = code[start:end]
    assert not re.search(r"\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch)\(", tools), "a colour function instead of a token in the tools section"
    for banned in ("grid-column", ":has(", "@container", "nth-child(odd)"):
        assert banned not in tools, banned


def test_shared_ui_wiring_keeps_the_contract():
    """§10.1-§10.3 and §5.1, which the browser tests cannot see (they refuse the event stream, and a missing icon falls back to
    another one silently): the api.js wrappers with their paths, methods and timeouts, the new KNOWN_EVENTS lines (every event the
    new cards listen to is one of them), the two icons and every icon name the new cards use, the tftp.state merge into the Tools
    tile, the Tools card entries and ctx.open, and the Network info card made before the first render and placed after the map."""
    api = _read("js/api.js")
    for s in ("natGet: () => api.get('/netcheck/nat'),", "natRun: () => api.post('/netcheck/nat', {}, { timeout: 45000 }),",
              "switchGet: () => api.get('/netcheck/switch'),", "switchStart: (body) => api.post('/netcheck/switch', body || {}),",
              "switchStop: () => api.del('/netcheck/switch'),",
              "portForwardTest: (port) => api.post('/netcheck/portforward', { port }, { timeout: 60000 }),",
              "tftpStatus: () => api.get('/tftp/status'),", "tftpStart: (body) => api.post('/tftp/start', body || {}, { timeout: 20000 }),",
              "tftpStop: () => api.post('/tftp/stop'),", "tftpUploads: (on) => api.post('/tftp/uploads', { on: !!on }),",
              "tftpSettings: (patch) => api.put('/tftp/settings', patch || {}),", "tftpFiles: () => api.get('/tftp/files'),",
              "captureGet: () => api.get('/tools/capture'),", "captureStart: (body) => api.post('/tools/capture', body || {}, { timeout: 20000 }),",
              "captureStop: () => api.del('/tools/capture'),",
              "captureDeleteFile: (name) => api.del('/tools/capture/files/' + encodeURIComponent(name)),",
              "captureFileUrl: (name) => BASE + '/tools/capture/files/' + encodeURIComponent(name),"):   # a URL only: no request
        assert s in api, s
    at = api.index("const KNOWN_EVENTS = [")
    events = api[at:api.index("];", at)]
    lines = [ln.strip() for ln in events.splitlines()[1:] if ln.strip()]
    assert "'dhcp.state', 'dhcp.lease', 'dhcp.scan', 'map.sample', 'geoip.state'," in lines, "the pinned line is unchanged"
    report = lines.index("'report.progress', 'report.saved', 'report.deleted', 'report.updated',")
    assert lines[report + 1:] == ["'netcheck.switch',", "'tftp.state', 'tftp.transfer',", "'capture.state',"], lines[report:]
    known = set(re.findall(r"'([\w.]+)'", events))
    for rel, heard in (("js/netcheck.js", {"netcheck.switch", "hello"}), ("js/tools/tftp.js", {"tftp.state", "tftp.transfer", "hello"}),
                       ("js/tools/capture.js", {"capture.state", "hello"})):
        found = set(re.findall(r"TNT\.api\.events\.on\('([\w.]+)'", _read(rel)))
        assert found == heard and found <= known, (rel, sorted(found), sorted(found - known))

    app = _read("js/app.js")
    icons = app[app.index("const ICONS = {"):app.index("TNT.icons = {")]
    names = set(re.findall(r"^    '?([\w-]+)'?\s*:", icons, re.M))
    assert {"tftp", "capture"} <= names and "natcheck" not in names
    for name in ("tftp", "capture"):
        comment = icons[:icons.index(f"\n    {name}: '<svg ")].splitlines()[-1]
        assert re.match(r"^    // .+: the .+ card", comment), (name, comment)          # // picture: where
    used = set()
    for rel in ("js/netcheck.js", "js/tools/tftp.js", "js/tools/capture.js", "js/tools/dns.js", "js/views/speed.js"):
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

    assert re.findall(r"\{ key: '(\w+)'", cards) == ["lan", "portforward", "traceroute", "tftp", "subnet", "dns", "capture", "wifi"]
    assert "const CARD_ORDER = ['lan', 'portforward', 'traceroute', 'dhcp', 'tftp', 'subnet', 'dns', 'capture', 'wifi'];" in tools
    for s in ("{ key: 'tftp', title: 'TFTP server', icon: 'tftp', create: (ctx) => TNT.tools.tftp.create(ctx) },",
              "{ key: 'portforward', title: 'Port forward', icon: 'target', create: (ctx) => TNT.tools.portforward.create(ctx) },",
              "{ key: 'capture', title: 'Packet capture', icon: 'capture', create: () => TNT.tools.capture.create() },",
              "try { mod = c.create({ open: () => openCard(c.key) }); }"):
        assert s in tools, s

    ipinfo = _read("js/views/ipinfo.js")
    mount = ipinfo[ipinfo.index("    mount(el) {"):ipinfo.index("    update(state) {")]
    assert mount.index("nc = TNT.netcheck.create();") < mount.index("render();"), "the card exists before the first render"
    render = ipinfo[ipinfo.index("  function render() {"):ipinfo.index("  async function load(quiet) {")]
    appends = re.findall(r"gridEl\.appendChild\(([^;]*)\);", render)
    placed = [i for i, a in enumerate(appends) if a == "nc.el"]
    assert len(placed) == 2 and all(i > 0 and appends[i - 1] == "buildMapCard()" for i in placed), appends   # loading and normal branches
    load = ipinfo[ipinfo.index("  async function load(quiet) {"):]
    assert load.index("if (nc) gridEl.appendChild(nc.el);") < load.index("TNT.ui.emptyState('Could not load adapters: '"), "before the error card"
    for s in ("if (nc) nc.update(state);", "nc.unmount();", "netChanged() { if (root) load(true); },"):
        assert s in ipinfo, s
