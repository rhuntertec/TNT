"""Tests for tnt.export_pdf: range bounds and PDF report building.

No network needed. Uses a temp-dir Database; reportlab renders everything in-process.
"""
from __future__ import annotations

import base64
import random
import re
import sys
import time
import types
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from tnt import export_pdf
from tnt.db import Database

DAY = 86400.0
HOUR = 3600.0


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------
def _page_count(pdf: bytes) -> int:
    """Count page objects without pypdf: '/Type /Page' but not '/Type /Pages'."""
    return len(re.findall(rb"/Type\s*/Page(?![s/])", pdf))


def _pdf_text(pdf: bytes) -> bytes:
    """Concatenate all decoded content streams so literal strings can be searched.

    reportlab writes streams as ASCII85(Flate(data)) by default; tolerate either filter being absent.
    """
    out = b""
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        raw = m.group(1).strip()
        try:
            raw = base64.a85decode(raw, adobe=True)
        except ValueError:
            pass
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            pass
        out += raw
    return out


def _make_db(tmp_path: Path, name: str = "tnt.db") -> Database:
    return Database(tmp_path / name)


def populate(db: Database, now: float, clock: export_pdf._Clock) -> Dict[str, Any]:
    """2 targets, 48 h of minute rows (with a 2 h gap), 3 outages (target/total/open), 200 speed
    tests with an evening slowdown, one discovery run with 5 hosts. Returns useful timestamps."""
    rnd = random.Random(7)
    t_gw = db.add_target("10.0.0.251", "Gateway")
    t_net = db.add_target("1.1.1.1")
    start = now - 48 * HOUR
    minute0 = int(start // 60) * 60
    gap_a = minute0 + 20 * 3600
    gap_b = gap_a + 2 * 3600
    outage_a = minute0 + 30 * 3600
    outage_b = outage_a + 600
    conn = db._conn  # bulk insert inside one transaction keeps the test fast
    with db._lock:
        conn.execute("BEGIN")
        try:
            for tid, base in ((t_gw["id"], 1.2), (t_net["id"], 18.0)):
                for m in range(48 * 60):
                    mts = minute0 + m * 60
                    if gap_a <= mts < gap_b:
                        continue
                    rec = 60 if rnd.random() > 0.05 else rnd.randint(40, 59)
                    if tid == t_net["id"] and outage_a <= mts < outage_b:
                        rec = 0
                    avg = (base + rnd.random() * 3) if rec else None
                    db.upsert_ping_minute(tid, mts, 60, rec, avg, (avg - 0.5) if avg else None,
                                          (avg + 5) if avg else None, 0.4)
            for i in range(200):
                ts = start + i * (48 * HOUR / 200)
                hour = clock.hour(ts)
                slow = 0.55 if 19 <= hour < 22 else 1.0
                ok = i % 40 != 7
                db.add_speedtest({
                    "ts": ts, "ok": ok, "backend": "cloudflare", "server": "Cloudflare AMS", "isp": "Example ISP",
                    "external_ip": "203.0.113.5", "latency_ms": (18 + rnd.random() * 6) if ok else None,
                    "jitter_ms": 1.2, "download_mbps": (120 * slow + rnd.random() * 10) if ok else None,
                    "upload_mbps": (30 + rnd.random() * 4) if ok else None, "packet_loss_pct": 0.0,
                    "duration_s": 20, "error": None if ok else "timeout", "raw": {"k": 1},
                })
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    # outages: closed target outage, closed total outage, open target outage (+ a monitoring gap)
    o1 = db.open_outage("target", t_net["id"], outage_a)
    db.close_outage(o1, outage_b, missed=600)
    o2 = db.open_outage("total_internet", None, outage_a + 5)
    db.close_outage(o2, outage_b - 10)
    open_id = db.open_outage("target", t_gw["id"], now - 900)
    gap_id = db.open_outage("gap", None, gap_a, note="not monitoring")
    db.close_outage(gap_id, gap_b)
    hosts = [
        {"ip": "10.0.0.1", "hostname": "router.lan", "mac": "AA:BB:CC:00:00:01", "vendor": "Ubiquiti",
         "ping_ok": True, "rtt_ms": 0.8, "open_ports": [80, 443]},
        {"ip": "10.0.0.20", "hostname": None, "mac": "AA:BB:CC:00:00:02", "vendor": "Hikvision",
         "ping_ok": True, "rtt_ms": 2.1, "open_ports": [554, 8000]},
        {"ip": "10.0.0.31", "hostname": "printer", "mac": None, "vendor": None,
         "ping_ok": False, "rtt_ms": None, "open_ports": [80]},
        {"ip": "10.0.0.112", "hostname": "desktop.lan", "mac": "AA:BB:CC:00:00:04", "vendor": "Intel Corporate",
         "ping_ok": True, "rtt_ms": 0.3, "open_ports": []},
        {"ip": "10.0.0.200", "hostname": None, "mac": "02:11:22:33:44:55",
         "vendor": "Locally administered (randomized)", "ping_ok": True, "rtt_ms": 5.5, "open_ports": [7001]},
    ]
    run_id = db.add_discovery_run({"ts": now - HOUR, "cidr": "10.0.0.0/24", "ports": [80, 443, 554, 7001, 8000],
                                   "method": "native", "duration_s": 12.5, "scanned": 254, "ok": True}, hosts)
    return {"start": start, "gap": (gap_a, gap_b), "outage": (outage_a, outage_b), "open_id": open_id,
            "run_id": run_id, "targets": [t_gw, t_net]}


# --------------------------------------------------------------------------------------
# range_bounds
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("kind,days", [("daily", 1), ("weekly", 7), ("monthly", 30), ("yearly", 365)])
def test_range_bounds_fixed_kinds(kind: str, days: int) -> None:
    now = 1_800_000_000.0
    start, end = export_pdf.range_bounds(kind, now)
    assert end == now
    assert start == pytest.approx(now - days * DAY)
    # case-insensitive / padded
    assert export_pdf.range_bounds(f"  {kind.upper()} ", now) == (start, end)


def test_range_bounds_custom() -> None:
    now = 1_800_000_000.0
    a, b = now - 5 * DAY, now - 2 * DAY
    assert export_pdf.range_bounds("custom", now, a, b) == (a, b)
    # reversed bounds are swapped
    assert export_pdf.range_bounds("custom", now, b, a) == (a, b)
    # missing end -> now; missing start -> 24 h before the end
    assert export_pdf.range_bounds("custom", now, a, None) == (a, now)
    assert export_pdf.range_bounds("custom", now, None, b) == (b - DAY, b)
    assert export_pdf.range_bounds("custom", now) == (now - DAY, now)
    # an empty period is widened to 24 h
    assert export_pdf.range_bounds("custom", now, b, b) == (b - DAY, b)


def test_range_bounds_unknown_kind() -> None:
    with pytest.raises(ValueError):
        export_pdf.range_bounds("fortnightly", 1_800_000_000.0)


# --------------------------------------------------------------------------------------
# build_report: empty database
# --------------------------------------------------------------------------------------
def test_build_report_empty_db(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    try:
        now = time.time()
        pdf = export_pdf.build_report(db, now - DAY, now)
    finally:
        db.close()
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1024
    assert _page_count(pdf) >= 1
    text = _pdf_text(pdf)
    assert b"in this period" in text          # friendly "No ... data in this period" boxes
    assert b"TNT Network Report" in text


def test_build_report_empty_db_yearly_and_fixed_tz(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    try:
        now = time.time()
        for tz in (None, 0, -5 * 3600, 5 * 3600 + 1800):
            pdf = export_pdf.build_report(db, *export_pdf.range_bounds("yearly", now), tz_offset_s=tz)
            assert pdf.startswith(b"%PDF") and len(pdf) > 1024
    finally:
        db.close()


# --------------------------------------------------------------------------------------
# build_report: populated database
# --------------------------------------------------------------------------------------
def test_build_report_populated_multi_page_and_fast(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    try:
        now = time.time()
        clock = export_pdf._Clock(None)
        info = populate(db, now, clock)
        netinfo = {"internet_nic": {"name": "Ethernet", "ipv4": "10.0.0.112", "network": "10.0.0.0/24",
                                    "gateway": "10.0.0.251"}, "adapter_count": 3}
        live_targets = [{"id": info["targets"][0]["id"], "host": "10.0.0.251", "label": "Gateway", "kind": "local"},
                        {"id": info["targets"][1]["id"], "host": "1.1.1.1", "label": None, "kind": "internet"}]
        t0 = time.perf_counter()
        pdf = export_pdf.build_report(db, info["start"], now, title="Two-day check", targets=live_targets,
                                      netinfo=netinfo)
        elapsed = time.perf_counter() - t0
    finally:
        db.close()
    assert elapsed < 5.0, f"report took {elapsed:.2f} s"
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 10_000
    assert _page_count(pdf) >= 2
    text = _pdf_text(pdf)
    assert b"Two-day check" in text
    assert b"ongoing" in text                    # the open outage
    assert b"All internet targets down" in text  # the total outage
    assert b"10.0.0.200" in text                 # discovery hosts table
    assert b"Ethernet" in text                   # network summary from netinfo
    assert b"19:00 and 22:00" in text            # evening slowdown finding


def test_build_report_populated_yearly_and_snapshot_netinfo(tmp_path: Path) -> None:
    """A yearly range over the same data must bucket (<= ~500 chart points) and still be quick."""
    db = _make_db(tmp_path)
    try:
        now = time.time()
        populate(db, now, export_pdf._Clock(None))
        snapshot = {"ts": now, "internet_nic_index": 7, "default_gateway": "10.0.0.251", "adapters": [
            {"index": 7, "name": "Wi-Fi", "description": "Intel Wireless", "ipv4": [
                {"address": "10.0.0.112", "prefix": 24, "family": 2, "netmask": "255.255.255.0", "network": "10.0.0.0/24"}],
             "gateways": ["10.0.0.251"], "dns": ["10.0.0.251", "1.1.1.1"]}]}
        t0 = time.perf_counter()
        pdf = export_pdf.build_report(db, *export_pdf.range_bounds("yearly", now), netinfo=snapshot, tz_offset_s=-18000)
        elapsed = time.perf_counter() - t0
    finally:
        db.close()
    assert elapsed < 5.0
    assert pdf.startswith(b"%PDF") and _page_count(pdf) >= 2
    assert b"Wi-Fi" in _pdf_text(pdf)


# --------------------------------------------------------------------------------------
# data helpers
# --------------------------------------------------------------------------------------
def test_ping_buckets_are_hourly_and_keep_the_gap(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    try:
        now = time.time()
        clock = export_pdf._Clock(0)
        info = populate(db, now, clock)
        tid = info["targets"][0]["id"]
        buckets, coverage = export_pdf._ping_buckets(db, tid, info["start"], now, 3600, clock)
    finally:
        db.close()
    # coverage: two runs split exactly at the 2 h gap
    assert len(coverage) == 2
    assert coverage[0][1] == pytest.approx(info["gap"][0]) and coverage[1][0] == pytest.approx(info["gap"][1])
    assert 45 <= len(buckets) <= 49                     # 48 h minus a 2 h gap, +/- edge hours
    keys = [b["key"] for b in buckets]
    assert keys == sorted(keys)
    assert max(keys) - min(keys) + 1 > len(keys)        # the gap leaves missing bucket keys
    gap_a, gap_b = info["gap"]
    # no bucket whose whole hour lies inside the gap may exist (edge hours are partial and keep data)
    assert not any(gap_a <= b["ts"] - 1800 and b["ts"] + 1800 <= gap_b for b in buckets)
    for b in buckets:
        assert b["sent"] > 0 and 0 <= b["received"] <= b["sent"]
        assert b["avg_ms"] is None or b["min_ms"] <= b["avg_ms"] <= b["max_ms"]


def test_coverage_helpers() -> None:
    merged = export_pdf._merge_runs([(10, 20), (5, 12), (30, 40), (40, 45), (50, 50)])
    assert merged == [(5.0, 20.0), (30.0, 45.0)]
    # holes inside [0, 60] that are at least 1 s long
    assert export_pdf._uncovered(merged, 0, 60, min_len=1) == [(0, 5.0), (20.0, 30.0), (45.0, 60)]
    assert export_pdf._uncovered(merged, 6, 19, min_len=1) == []
    assert export_pdf._uncovered([], 0, 100, min_len=1) == [(0, 100)]
    assert export_pdf._uncovered(merged, 0, 60, min_len=20) == []


def test_gather_ping_reports_coverage(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    try:
        now = time.time()
        clock = export_pdf._Clock(None)
        info = populate(db, now, clock)
        ping = export_pdf._gather_ping(db, info["start"], now, clock, export_pdf._collect_targets(db, None))
    finally:
        db.close()
    assert ping["sent"] > 0 and ping["coverage"]
    gap_a, gap_b = info["gap"]
    assert export_pdf._uncovered(ping["coverage"], info["start"], now)[0] == pytest.approx((gap_a, gap_b), abs=1)
    assert ping["covered_s"] == pytest.approx(48 * HOUR - 2 * HOUR, abs=120)


def test_bucket_seconds_caps_chart_points() -> None:
    now = 1_800_000_000.0
    assert export_pdf._bucket_seconds(now - DAY, now) == 3600
    year = export_pdf._bucket_seconds(now - 365 * DAY, now)
    assert year % 3600 == 0
    assert (365 * DAY) / year <= export_pdf.MAX_CHART_POINTS


def test_gather_outages_marks_open_and_total(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    try:
        now = time.time()
        info = populate(db, now, export_pdf._Clock(None))
        targets = export_pdf._collect_targets(db, None)
        res = export_pdf._gather_outages(db, info["start"], now, targets)
    finally:
        db.close()
    assert res["count"] == 3 and res["n_total"] == 1 and res["n_target"] == 2 and res["n_gap"] == 1
    opened = [o for o in res["items"] if o["open"]]
    assert len(opened) == 1 and opened[0]["id"] == info["open_id"] and opened[0]["end_ts"] == now
    assert any(o["what"].startswith("Gateway") for o in res["items"])
    assert res["items"][0]["start_ts"] >= res["items"][-1]["start_ts"]  # newest first


def test_local_findings_detect_evening_slowdown() -> None:
    clock = export_pdf._Clock(0)  # fixed UTC so hours are deterministic
    base = 1_800_000_000.0 - (1_800_000_000.0 % DAY)
    rows: List[Dict[str, Any]] = []
    for i in range(96 * 3):  # 3 days, every 15 min
        ts = base + i * 900
        h = clock.hour(ts)
        rows.append({"ts": ts, "ok": True, "download_mbps": 60.0 if 19 <= h < 22 else 100.0,
                     "upload_mbps": 30.0, "latency_ms": 20.0, "jitter_ms": 1.0, "error": None})
    rows.append({"ts": base + 5, "ok": False, "download_mbps": None, "upload_mbps": None, "latency_ms": None,
                 "jitter_ms": None, "error": "timeout"})
    findings = export_pdf._local_findings(rows, clock)
    assert any("19:00 and 22:00" in f and "slower" in f for f in findings)
    assert any("1 speed test failed" in f for f in findings)


def test_local_findings_with_too_little_data() -> None:
    clock = export_pdf._Clock(0)
    assert export_pdf._local_findings([], clock) == ["Not enough successful speed tests for a pattern analysis yet."]


def test_findings_prefer_patterns_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """When tnt.speedtest.patterns.analyse_patterns is importable its findings are used verbatim."""
    seen: Dict[str, Any] = {}

    def fake_analyse(rows: List[Dict[str, Any]], now: float, warn_below_pct: float, tz_offset_s: int) -> Dict[str, Any]:
        seen.update(rows=len(rows), now=now, warn=warn_below_pct, tz=tz_offset_s)
        return {"findings": ["from patterns module"]}

    if "tnt.speedtest" not in sys.modules:
        pkg = types.ModuleType("tnt.speedtest")
        pkg.__path__ = []  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "tnt.speedtest", pkg)
    mod = types.ModuleType("tnt.speedtest.patterns")
    mod.analyse_patterns = fake_analyse  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "tnt.speedtest.patterns", mod)
    clock = export_pdf._Clock(3600)
    rows = [{"ts": 1.0, "ok": True, "download_mbps": 1.0, "upload_mbps": 1.0, "latency_ms": 1.0}]
    assert export_pdf._findings(rows, 123.0, clock) == ["from patterns module"]
    assert seen == {"rows": 1, "now": 123.0, "warn": 50, "tz": 3600}

    # a broken patterns module falls back to the local rules instead of failing the report
    def broken(*_a: Any, **_k: Any) -> Dict[str, Any]:
        raise RuntimeError("boom")

    mod.analyse_patterns = broken  # type: ignore[attr-defined]
    out = export_pdf._findings(rows, 123.0, clock)
    assert out and all(isinstance(f, str) for f in out)


# --------------------------------------------------------------------------------------
# robustness
# --------------------------------------------------------------------------------------
class _BrokenDb:
    """Every query raises: the report must still render with 'could not load' boxes."""

    def list_targets(self) -> List[Dict[str, Any]]:
        return [{"id": 1, "host": "1.1.1.1", "label": None, "kind": "auto", "enabled": True}]

    def __getattr__(self, name: str) -> Any:
        def fail(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError(f"db exploded in {name}")
        return fail


def test_build_report_survives_db_errors() -> None:
    now = time.time()
    pdf = export_pdf.build_report(_BrokenDb(), now - DAY, now)  # type: ignore[arg-type]
    assert pdf.startswith(b"%PDF") and len(pdf) > 1024
    assert b"Could not load" in _pdf_text(pdf)


def test_build_report_normalises_bad_bounds(tmp_path: Path) -> None:
    db = _make_db(tmp_path)
    try:
        now = time.time()
        pdf = export_pdf.build_report(db, now, now - DAY)      # reversed
        assert pdf.startswith(b"%PDF")
        pdf = export_pdf.build_report(db, now, now)            # empty period
        assert pdf.startswith(b"%PDF")
    finally:
        db.close()


def test_cards_row_equalises_heights() -> None:
    """Summary cards in a row are stretched to the tallest one (equal-size tiles)."""
    short = export_pdf._card("Ping", "0", "one line", export_pdf.GREEN, 0)
    tall = export_pdf._card("Speed", "124 Mbps", "a much longer subtitle that will certainly wrap onto several lines "
                            "inside a narrow card", export_pdf.PURPLE, 0)
    table = export_pdf._cards_row([short, tall], 300)
    table.wrap(300, 1000)
    assert short._box_h == pytest.approx(tall._box_h)
    assert tall._box_h > 2 * 9 + 22  # taller than a single-line card


def test_clock_local_time_helpers() -> None:
    fixed = export_pdf._Clock(-5 * 3600)
    ts = 1_800_000_000.0
    assert fixed.offset(ts) == -18000
    assert fixed.zone_label(ts) == "UTC-05:00"
    assert fixed.hour(ts) == (fixed.local(ts)).hour
    ds = fixed.day_start(ts)
    assert ds <= ts < ds + DAY
    assert fixed.add_days(ds, 1) == ds + DAY
    system = export_pdf._Clock(None)
    assert isinstance(system.zone_label(ts), str) and system.zone_label(ts).startswith("UTC")
    assert system.day_start(ts) <= ts
