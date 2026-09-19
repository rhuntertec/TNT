"""The SIP qualifier: would calls work well on this network (:mod:`tnt.sipqual`)?

What these pin is mostly *honesty*.  A rating that grades four minutes of history, or that invents a capacity
figure with no speed test behind it, or that answers "the network is bad" without saying which leg, would look
exactly as convincing as a real one - so the tests for those cases are the important ones here.
"""

from __future__ import annotations

import pytest

from tnt import sipqual
from tnt.speedtest import quality


def stats(samples=600, lost=0, avg=20.0, jitter=3.0, p95=None):
    """A :func:`tnt.reports.ping_stats` window, the shape a leg is graded from."""
    return {"samples": samples, "lost": lost, "loss_pct": round(lost * 100.0 / samples, 2) if samples else 0.0,
            "avg_ms": avg, "min_ms": avg, "max_ms": avg, "p95_ms": p95 if p95 is not None else avg,
            "jitter_ms": jitter}


def minute_rows(count, avg=20.0, jitter=3.0, sent=60, received=60):
    return [(sent, received, avg, avg, avg, jitter)] * count


class FakeDb:
    """Just the four reads the qualifier makes."""

    def __init__(self, targets=(), history=None, speedtest=None):
        self._targets = [dict(t) for t in targets]
        self._history = dict(history or {})
        self._speedtest = speedtest
        self.calls = []

    def list_targets(self, enabled_only=False):
        self.calls.append(("list_targets", enabled_only))
        return [dict(t) for t in self._targets]

    def ping_minute_rows(self, target_id, start_ts, end_ts, network_id=None):
        self.calls.append(("ping_minute_rows", target_id, start_ts, end_ts, network_id))
        return list(self._history.get(target_id, []))

    def last_speedtest(self, ok_only=False):
        self.calls.append(("last_speedtest", ok_only))
        return dict(self._speedtest) if self._speedtest else None


GATEWAY = {"id": 1, "host": "gateway", "label": "gateway", "name": None, "kind": "local", "enabled": True}
INTERNET = {"id": 2, "host": "1.1.1.1", "label": None, "name": None, "kind": "internet", "enabled": True}
PBX = {"id": 3, "host": "pbx.example.net", "label": None, "name": None, "kind": "internet", "enabled": True}


def finding(rating, ident):
    return next((f for f in rating["findings"] if f["id"] == ident), None)


def leg(rating, kind):
    return next((leg for leg in rating["legs"] if leg["kind"] == kind), None)


# --------------------------------------------------------------------------- grading one leg
class TestGradingALeg:
    def test_a_quiet_fast_path_is_excellent(self):
        row = sipqual.grade_leg(stats(avg=8.0, jitter=1.0), kind="lan", label="The LAN leg")
        assert row["grade"] == "excellent"

    def test_the_grade_walks_down_as_the_numbers_get_worse(self):
        grades = [sipqual.grade_leg(stats(avg=avg, jitter=jit, lost=lost), kind="wan", label="x")["grade"]
                  for avg, jit, lost in ((8, 1, 0), (90, 15, 1), (150, 30, 5), (250, 50, 12), (900, 200, 120))]
        assert grades == ["excellent", "good", "fair", "poor", "bad"]

    def test_the_worst_of_the_three_numbers_decides_the_grade(self):
        """Latency, jitter and loss are not averaged: a fast path that drops 4 % of packets is not a good path."""
        row = sipqual.grade_leg(stats(avg=8.0, jitter=1.0, lost=24), kind="wan", label="x")
        assert row["grade"] == "bad"

    def test_jitter_alone_can_pull_a_fast_path_down(self):
        row = sipqual.grade_leg(stats(avg=10.0, jitter=45.0), kind="wan", label="x")
        assert row["grade"] == "poor"

    def test_a_leg_carries_the_numbers_it_was_graded_from(self):
        row = sipqual.grade_leg(stats(avg=33.0, jitter=7.0, lost=6, p95=70.0), kind="wan", label="x",
                                target="1.1.1.1", window_h=6)
        assert (row["avg_ms"], row["jitter_ms"], row["p95_ms"]) == (33.0, 7.0, 70.0)
        assert (row["samples"], row["target"], row["window_h"]) == (600, "1.1.1.1", 6)

    def test_a_leg_carries_the_same_mos_the_speed_page_would_show(self):
        row = sipqual.grade_leg(stats(avg=33.0, jitter=7.0, lost=6), kind="wan", label="x")
        expected = quality.call_quality(33.0, 7.0, row["loss_pct"])
        assert (row["mos"], row["r"], row["call_label"]) == (expected["mos"], expected["r"], expected["label"])

    def test_too_little_history_is_not_graded_at_all(self):
        row = sipqual.grade_leg(stats(samples=4), kind="lan", label="The LAN leg")
        assert row["grade"] == "unknown"
        assert "4 ping" in row["reason"] and "30" in row["reason"]

    def test_history_with_no_round_trip_times_is_not_graded(self):
        row = sipqual.grade_leg({"samples": 600, "lost": 600, "loss_pct": 100.0, "avg_ms": None, "min_ms": None,
                                 "max_ms": None, "p95_ms": None, "jitter_ms": None}, kind="wan", label="x")
        assert row["grade"] == "unknown" and "round-trip" in row["reason"]

    def test_missing_jitter_does_not_block_a_grade(self):
        """Older minute rows have no jitter column; a leg is still worth grading on latency and loss."""
        row = sipqual.grade_leg(stats(avg=15.0, jitter=None), kind="lan", label="x")
        assert row["grade"] == "excellent" and row["jitter_ms"] is None

    def test_every_leg_has_the_declared_shape(self):
        row = sipqual.grade_leg(stats(), kind="lan", label="x")
        assert tuple(row) == sipqual.LEG_KEYS


# --------------------------------------------------------------------------- the whole rating
class TestTheRating:
    def test_the_verdict_is_the_worst_leg_not_the_average(self):
        """One bad leg is a bad network for calls, however good the other one is."""
        legs = [sipqual.grade_leg(stats(avg=4.0, jitter=1.0), kind="lan", label="The LAN leg"),
                sipqual.grade_leg(stats(avg=400.0, jitter=90.0, lost=60), kind="wan", label="The internet leg")]
        rating = sipqual.build_qualifier(legs, window_h=24)
        assert rating["verdict"] == "bad"

    def test_a_bad_rating_names_the_leg_to_start_with(self):
        legs = [sipqual.grade_leg(stats(avg=4.0, jitter=1.0), kind="lan", label="The LAN leg (gateway)"),
                sipqual.grade_leg(stats(avg=400.0, jitter=90.0, lost=60), kind="wan",
                                  label="The internet leg (1.1.1.1)")]
        rating = sipqual.build_qualifier(legs, window_h=24)
        assert "internet leg" in finding(rating, "sip.ready")["detail"]
        assert "lan" not in finding(rating, "sip.ready")["detail"].lower()

    def test_a_bad_lan_leg_sends_the_tech_into_the_building(self):
        legs = [sipqual.grade_leg(stats(avg=300.0, jitter=90.0, lost=60), kind="lan", label="The LAN leg")]
        advice = finding(sipqual.build_qualifier(legs, window_h=24), "sip.lan")["advice"]
        assert "switch" in advice and "building" in advice

    def test_a_bad_wan_leg_sends_the_tech_to_the_provider(self):
        legs = [sipqual.grade_leg(stats(avg=300.0, jitter=90.0, lost=60), kind="wan", label="The internet leg")]
        advice = finding(sipqual.build_qualifier(legs, window_h=24), "sip.wan")["advice"]
        assert "provider" in advice or "circuit" in advice

    def test_a_good_leg_is_not_given_advice(self):
        legs = [sipqual.grade_leg(stats(avg=4.0, jitter=1.0), kind="lan", label="The LAN leg")]
        assert finding(sipqual.build_qualifier(legs, window_h=24),
                       "sip.lan")["advice"] is None

    def test_a_good_network_says_so_first(self):
        legs = [sipqual.grade_leg(stats(avg=4.0, jitter=1.0), kind="lan", label="The LAN leg"),
                sipqual.grade_leg(stats(avg=90.0, jitter=15.0), kind="wan", label="The internet leg")]
        rating = sipqual.build_qualifier(legs, window_h=24)
        assert rating["verdict"] == "good"
        assert rating["findings"][0]["id"] == "sip.ready" and rating["findings"][0]["level"] == "good"

    def test_the_worst_finding_is_first(self):
        legs = [sipqual.grade_leg(stats(avg=4.0, jitter=1.0), kind="lan", label="The LAN leg"),
                sipqual.grade_leg(stats(avg=400.0, jitter=90.0, lost=60), kind="wan", label="The internet leg")]
        rating = sipqual.build_qualifier(legs, window_h=24)
        levels = [f["level"] for f in rating["findings"]]
        assert levels == sorted(levels, key=("bad", "warn", "info", "good").index)

    def test_no_gradeable_leg_is_not_a_verdict(self):
        """Silence is not a pass.  A network TNT has barely watched gets no rating at all."""
        legs = [sipqual.grade_leg(stats(samples=2), kind="lan", label="The LAN leg")]
        rating = sipqual.build_qualifier(legs, window_h=24)
        assert rating["verdict"] == "unknown"
        assert finding(rating, "sip.nodata") is not None
        assert finding(rating, "sip.ready") is None

    def test_an_ungraded_leg_does_not_drag_a_verdict_down(self):
        legs = [sipqual.grade_leg(stats(avg=4.0, jitter=1.0), kind="lan", label="The LAN leg"),
                sipqual.grade_leg(stats(samples=1), kind="wan", label="The internet leg")]
        assert sipqual.build_qualifier(legs, window_h=24)["verdict"] == "excellent"

    def test_without_a_named_sip_host_the_rating_says_what_it_did_not_grade(self):
        legs = [sipqual.grade_leg(stats(), kind="wan", label="The internet leg")]
        note = finding(sipqual.build_qualifier(legs, window_h=24), "sip.notarget")
        assert note is not None and "PBX" in note["detail"]

    def test_a_named_sip_host_removes_that_caveat(self):
        legs = [sipqual.grade_leg(stats(), kind="sip", label="The path to pbx.example.net")]
        rating = sipqual.build_qualifier(legs, window_h=24,
                                         sip_host="pbx.example.net")
        assert finding(rating, "sip.notarget") is None
        assert rating["sip_host"] == "pbx.example.net"

    def test_the_trunk_leg_is_called_out_separately_from_the_internet_leg(self):
        legs = [sipqual.grade_leg(stats(avg=4.0, jitter=1.0), kind="wan", label="The internet leg"),
                sipqual.grade_leg(stats(avg=300.0, jitter=80.0, lost=60), kind="sip",
                                  label="The path to pbx.example.net")]
        rating = sipqual.build_qualifier(legs, window_h=24, sip_host="pbx.example.net")
        assert rating["verdict"] == "bad"
        assert "phone system" in finding(rating, "sip.trunk")["advice"]

    def test_a_badly_buffering_line_is_reported_even_when_every_leg_is_good(self):
        """This is the "the phones are random" complaint: fine idle, broken the moment somebody downloads."""
        legs = [sipqual.grade_leg(stats(avg=8.0, jitter=1.0), kind="lan", label="x")]
        rating = sipqual.build_qualifier(legs, window_h=24, bufferbloat="F")
        assert rating["verdict"] == "excellent"
        bloat = finding(rating, "sip.bufferbloat")
        assert bloat["level"] == "bad" and "queue" in bloat["advice"]

    def test_a_line_that_buffers_well_is_not_reported(self):
        legs = [sipqual.grade_leg(stats(), kind="lan", label="x")]
        for grade in ("A+", "A", "B", "C", None):
            rating = sipqual.build_qualifier(legs, window_h=24, bufferbloat=grade)
            assert finding(rating, "sip.bufferbloat") is None

    def test_the_window_is_stated_in_words_a_tech_reads(self):
        legs = [sipqual.grade_leg(stats(avg=4.0, jitter=1.0), kind="lan", label="x", window_h=0.5)]
        for hours, text in ((0.5, "30 minutes"), (24, "24 hours"), (168, "7 days")):
            rating = sipqual.build_qualifier(legs, window_h=hours)
            assert text in finding(rating, "sip.ready")["detail"]

    def test_the_rating_has_the_declared_shape(self):
        rating = sipqual.build_qualifier([sipqual.grade_leg(stats(), kind="lan", label="x")],
                                         window_h=24)
        assert tuple(rating) == sipqual.QUALIFIER_KEYS
        for f in rating["findings"]:
            assert tuple(f) == sipqual.FINDING_KEYS
            assert f["id"] in sipqual.FINDING_IDS

    def test_every_declared_finding_id_is_one_the_code_can_actually_raise(self):
        raised = set()
        cases = (
            ([sipqual.grade_leg(stats(), kind="lan", label="x"),
              sipqual.grade_leg(stats(), kind="wan", label="x"),
              sipqual.grade_leg(stats(), kind="sip", label="x")], "F", None),
            ([sipqual.grade_leg(stats(samples=1), kind="lan", label="x")], None, None),
            ([sipqual.grade_leg(stats(avg=900.0, jitter=200.0, lost=400), kind="wan", label="x")],
             None, "pbx.example.net"),
        )
        for legs, bloat, host in cases:
            rating = sipqual.build_qualifier(legs, window_h=24, bufferbloat=bloat, sip_host=host)
            raised.update(f["id"] for f in rating["findings"])
        assert raised == set(sipqual.FINDING_IDS) - {"sip.jitter", "sip.loss", "sip.latency"}


# --------------------------------------------------------------------------- the three headline numbers
class TestTheHeadlineNumbers:
    """MOS, mean round trip and mean jitter: what a call on this network would actually get."""

    def leg(self, kind, avg, jitter, loss=0.0, samples=600, label=None):
        return sipqual.grade_leg(stats(samples=samples, lost=int(samples * loss / 100), avg=avg, jitter=jitter),
                                 kind=kind, label=label or ("The %s leg" % kind))

    def test_it_is_the_weakest_leg_not_a_sum_of_them(self):
        """A ping to an internet host already crosses the gateway, so the internet leg's round trip contains the
        LAN leg's. Adding them would count the same milliseconds twice."""
        head = sipqual.headline([self.leg("lan", 4.0, 1.0), self.leg("wan", 90.0, 15.0)])
        assert head["avg_ms"] == 90.0 and head["leg"] == "wan"
        assert head["avg_ms"] != 94.0, "not the sum"

    def test_it_is_not_an_average_of_them_either(self):
        """Averaging a good leg with a bad one hides the bad one, which is what the split exists to prevent."""
        head = sipqual.headline([self.leg("lan", 4.0, 1.0), self.leg("wan", 300.0, 55.0, loss=2.0)])
        assert head["avg_ms"] == 300.0 and head["grade"] == "poor"
        assert head["avg_ms"] != 152.0

    def test_a_worse_grade_wins_over_better_numbers(self):
        head = sipqual.headline([self.leg("wan", 250.0, 50.0, loss=2.0), self.leg("lan", 8.0, 1.0)])
        assert head["leg"] == "wan" and head["grade"] == "poor"

    def test_legs_of_the_same_grade_break_on_the_worse_numbers(self):
        """On a healthy site every leg is excellent. Taking the first would put the gateway's 3 ms on screen as
        what a call gets, when the call goes out over the internet leg."""
        head = sipqual.headline([self.leg("lan", 3.4, 0.6), self.leg("wan", 21.0, 3.1)])
        assert head["leg"] == "wan" and head["avg_ms"] == 21.0

    def test_a_named_sip_host_can_be_the_headline(self):
        head = sipqual.headline([self.leg("lan", 3.4, 0.6), self.leg("wan", 21.0, 3.1),
                                 self.leg("sip", 40.0, 30.0, label="The path to pbx.example.net")])
        assert head["leg"] == "sip" and head["label"] == "The path to pbx.example.net"

    def test_the_mos_is_the_legs_own_not_a_second_calculation(self):
        leg = self.leg("wan", 33.0, 7.0, loss=1.0)
        head = sipqual.headline([leg])
        assert (head["mos"], head["r"], head["call_label"]) == (leg["mos"], leg["r"], leg["call_label"])

    def test_nothing_graded_gives_no_numbers_rather_than_zeroes(self):
        """A rating with four minutes of history behind it must not put a confident 4.40 on screen."""
        head = sipqual.headline([sipqual.grade_leg(stats(samples=4), kind="lan", label="x")])
        assert head["grade"] == "unknown"
        assert head["mos"] is None and head["avg_ms"] is None and head["jitter_ms"] is None
        assert "4 ping" in head["reason"]

    def test_an_empty_rating_has_a_headline_too(self):
        head = sipqual.headline([])
        assert head["grade"] == "unknown" and head["mos"] is None and head["reason"]

    def test_an_ungraded_leg_never_becomes_the_headline(self):
        head = sipqual.headline([sipqual.grade_leg(stats(samples=2), kind="lan", label="x"),
                                 self.leg("wan", 21.0, 3.1)])
        assert head["leg"] == "wan" and head["mos"] is not None

    def test_the_headline_has_the_declared_shape(self):
        assert tuple(sipqual.headline([self.leg("wan", 21.0, 3.1)])) == sipqual.HEADLINE_KEYS
        assert tuple(sipqual.headline([])) == sipqual.HEADLINE_KEYS

    def test_the_rating_carries_it_and_it_agrees_with_the_verdict(self):
        legs = [self.leg("lan", 3.4, 0.6), self.leg("wan", 250.0, 50.0, loss=2.0)]
        rating = sipqual.build_qualifier(legs, window_h=24)
        assert rating["headline"]["grade"] == rating["verdict"] == "poor"
        assert rating["headline"]["leg"] == "wan"

    def test_the_tile_carries_the_same_three_numbers(self):
        rows = [{"id": 1, "host": "1.1.1.1", "label": None, "name": None, "kind": "internet", "enabled": True}]
        db = FakeDb(rows, {1: minute_rows(120, avg=21.0, jitter=3.1)})
        qual = sipqual.SipQualifier(db, clock=lambda: 1_700_000_000.0)
        tile, rating = qual.tile(), qual.rating()
        assert tuple(tile) == sipqual.TILE_KEYS
        assert (tile["mos"], tile["avg_ms"], tile["jitter_ms"]) == (
            rating["headline"]["mos"], rating["headline"]["avg_ms"], rating["headline"]["jitter_ms"])


# --------------------------------------------------------------------------- which leg a target is
class TestSortingTargetsIntoLegs:
    def test_the_gateway_is_the_lan_leg(self):
        assert sipqual.leg_kind(GATEWAY) == "lan"

    def test_a_private_address_is_inside_the_building(self):
        assert sipqual.leg_kind({"host": "192.168.10.5", "kind": "auto"}) == "lan"

    def test_a_target_pinging_the_gateway_address_is_the_lan_leg(self):
        assert sipqual.leg_kind({"host": "router", "ip": "192.168.10.1", "kind": "auto"},
                                gateway="192.168.10.1") == "lan"

    def test_a_public_address_is_the_internet_leg(self):
        assert sipqual.leg_kind(INTERNET) == "wan"

    def test_the_named_sip_host_wins_over_being_an_ordinary_internet_target(self):
        assert sipqual.leg_kind(PBX, "pbx.example.net") == "sip"

    def test_the_sip_host_is_matched_without_regard_to_case_or_spacing(self):
        assert sipqual.leg_kind(PBX, "  PBX.Example.NET  ") == "sip"

    def test_a_leg_is_labelled_the_way_the_ping_table_names_the_target(self):
        assert sipqual.leg_label("lan", GATEWAY) == "The LAN leg (gateway)"
        assert sipqual.leg_label("sip", PBX) == "The path to pbx.example.net"


# --------------------------------------------------------------------------- reading it out of the database
class TestReadingTheHistory:
    def build(self, **kw):
        return sipqual.SipQualifier(clock=lambda: 1_700_000_000.0, **kw)

    def test_a_rating_is_built_from_the_history_of_every_target(self):
        db = FakeDb((GATEWAY, INTERNET), {1: minute_rows(120, avg=2.0, jitter=0.5),
                                          2: minute_rows(120, avg=90.0, jitter=15.0)},
                    {"ts": 1_699_999_000.0, "ok": 1, "upload_mbps": 10.0, "download_mbps": 300.0})
        rating = self.build(db=db).rating()
        assert [leg["kind"] for leg in rating["legs"]] == ["lan", "wan"]
        assert leg(rating, "lan")["grade"] == "excellent"
        assert rating["verdict"] == "good"
        assert rating["headline"]["mos"] is not None

    def test_the_window_is_the_one_asked_for(self):
        db = FakeDb((INTERNET,), {2: minute_rows(120)})
        self.build(db=db).rating(window_h=6)
        call = next(c for c in db.calls if c[0] == "ping_minute_rows")
        assert call[2] == pytest.approx(1_700_000_000.0 - 6 * 3600) and call[3] == 1_700_000_000.0

    def test_only_this_network_is_graded(self):
        """History from the last site is not evidence about this one."""
        db = FakeDb((INTERNET,), {2: minute_rows(120)})
        self.build(db=db).rating(network_id=7)
        assert next(c for c in db.calls if c[0] == "ping_minute_rows")[4] == 7

    def test_only_enabled_targets_are_graded(self):
        db = FakeDb((INTERNET,), {2: minute_rows(120)})
        self.build(db=db).rating()
        assert ("list_targets", True) in db.calls

    def test_only_a_good_speed_test_becomes_a_capacity_figure(self):
        db = FakeDb((INTERNET,), {2: minute_rows(120)})
        self.build(db=db).rating()
        assert ("last_speedtest", True) in db.calls

    def test_the_bufferbloat_grade_comes_out_of_the_stored_speed_test(self):
        db = FakeDb((INTERNET,), {2: minute_rows(120, avg=20.0)},
                    {"ts": 1.0, "ok": 1, "upload_mbps": 10.0, "download_mbps": 300.0,
                     "raw_json": '{"quality": {"bufferbloat": {"grade": "F", "increase_ms": 900}}}'})
        assert finding(self.build(db=db).rating(), "sip.bufferbloat") is not None

    def test_the_named_sip_host_is_graded_as_its_own_leg(self):
        db = FakeDb((INTERNET, PBX), {2: minute_rows(120, avg=20.0), 3: minute_rows(120, avg=40.0, jitter=30.0)})
        rating = self.build(db=db).rating(sip_host="pbx.example.net")
        assert leg(rating, "sip")["grade"] == "fair" and leg(rating, "wan")["grade"] == "excellent"
        assert rating["verdict"] == "fair"

    def test_a_target_with_no_history_on_this_network_is_reported_not_dropped(self):
        db = FakeDb((GATEWAY, INTERNET), {2: minute_rows(120)})
        rating = self.build(db=db).rating()
        assert leg(rating, "lan")["grade"] == "unknown"
        assert "0 ping" in leg(rating, "lan")["reason"]

    def test_a_database_that_cannot_be_read_still_gives_a_rating(self):
        class Broken(FakeDb):
            def list_targets(self, enabled_only=False):
                raise RuntimeError("the database is locked")

        rating = self.build(db=Broken()).rating()
        assert rating["verdict"] == "unknown" and rating["legs"] == []

    def test_one_unreadable_target_does_not_lose_the_other_legs(self):
        class Flaky(FakeDb):
            def ping_minute_rows(self, target_id, start_ts, end_ts, network_id=None):
                if target_id == 1:
                    raise RuntimeError("no")
                return super().ping_minute_rows(target_id, start_ts, end_ts, network_id)

        db = Flaky((GATEWAY, INTERNET), {2: minute_rows(120, avg=20.0)})
        rating = self.build(db=db).rating()
        assert leg(rating, "lan")["grade"] == "unknown" and leg(rating, "wan")["grade"] == "excellent"

    def test_a_broken_speed_test_row_costs_the_bufferbloat_warning_and_nothing_else(self):
        """The three numbers come from ping history; the speed test is only consulted for the way the line
        behaves under load."""
        db = FakeDb((INTERNET,), {2: minute_rows(120, avg=20.0)},
                    {"ts": 1.0, "ok": 1, "upload_mbps": None, "raw_json": "not json at all"})
        rating = self.build(db=db).rating()
        assert rating["verdict"] == "excellent" and rating["headline"]["avg_ms"] == 20.0
        assert not [f for f in rating["findings"] if f["id"] == "sip.bufferbloat"]

    def test_a_qualifier_with_no_database_says_so_rather_than_inventing_a_rating(self):
        with pytest.raises(RuntimeError, match="no database"):
            sipqual.SipQualifier().rating()


# --------------------------------------------------------------------------- how many legs
class TestHowManyLegsAreGraded:
    def targets(self, lan=1, wan=1, sip=False):
        rows = [dict(GATEWAY, id=0)] if lan else []
        rows += [{"id": 100 + i, "host": f"10.0.0.{i}", "label": None, "name": None, "kind": "local",
                  "enabled": True} for i in range(1, lan)]
        rows += [{"id": 200 + i, "host": f"198.51.100.{i}", "label": None, "name": None, "kind": "internet",
                  "enabled": True} for i in range(wan)]
        if sip:
            rows.append(dict(PBX))
        return rows

    def test_a_site_with_twenty_targets_does_not_get_twenty_legs(self):
        """Twenty leg cards would be a list, not an answer."""
        chosen, left_out = sipqual.pick_targets(self.targets(lan=8, wan=12))
        assert len(chosen) == 2 * sipqual.MAX_LEGS_PER_KIND == 6
        assert left_out == 20 - 6

    def test_it_takes_the_first_of_each_kind_in_the_order_the_targets_are_listed(self):
        """Database.list_targets orders by sort_order then id, which is the order the tech arranged them in."""
        chosen, _left = sipqual.pick_targets(self.targets(lan=1, wan=6))
        assert [t["host"] for kind, t in chosen if kind == "wan"] == ["198.51.100.0", "198.51.100.1",
                                                                     "198.51.100.2"]

    def test_the_two_kinds_are_capped_separately(self):
        """Three internet targets must not crowd out the gateway: the LAN leg is the other half of the answer."""
        chosen, _left = sipqual.pick_targets(self.targets(lan=1, wan=9))
        assert [kind for kind, _t in chosen].count("lan") == 1
        assert [kind for kind, _t in chosen].count("wan") == sipqual.MAX_LEGS_PER_KIND

    def test_the_named_sip_host_is_never_capped_away(self):
        """It was named on purpose; dropping the one leg the user asked for is the one thing this cap must not do."""
        chosen, _left = sipqual.pick_targets(self.targets(lan=1, wan=9, sip=True), "pbx.example.net")
        assert ("sip", PBX) in [(kind, dict(t)) for kind, t in chosen] or any(
            kind == "sip" and t["host"] == "pbx.example.net" for kind, t in chosen)

    def test_a_site_inside_the_cap_leaves_nothing_out(self):
        chosen, left_out = sipqual.pick_targets(self.targets(lan=1, wan=1))
        assert len(chosen) == 2 and left_out == 0

    def test_only_targets_it_would_have_graded_count_as_left_out(self):
        """The number in the note is what the cap cost, not how many targets the site has."""
        _chosen, left_out = sipqual.pick_targets(self.targets(lan=3, wan=3))
        assert left_out == 0, "a site exactly at the cap lost nothing"

    def test_what_was_left_out_is_said_out_loud(self):
        """A rating that graded three of a site's twenty targets and said nothing would read as a rating of the site."""
        rating = sipqual.build_qualifier([sipqual.grade_leg(stats(), kind="wan", label="x")],
                                         window_h=24, left_out=14)
        assert rating["note"] and "14 more" in rating["note"] and "Ping page" in rating["note"]

    def test_a_rating_that_left_nothing_out_carries_no_note(self):
        rating = sipqual.build_qualifier([sipqual.grade_leg(stats(), kind="wan", label="x")],
                                         window_h=24)
        assert rating["note"] is None

    def test_the_cap_applies_end_to_end(self):
        history = {t: minute_rows(120, avg=20.0) for t in range(200, 212)}
        rows = [{"id": 200 + i, "host": f"198.51.100.{i}", "label": None, "name": None, "kind": "internet",
                 "enabled": True} for i in range(12)]
        db = FakeDb(rows, history)
        rating = sipqual.SipQualifier(db, clock=lambda: 1_700_000_000.0).rating()
        assert len(rating["legs"]) == sipqual.MAX_LEGS_PER_KIND
        assert "9 more" in rating["note"]
        # and the history of a target that was left out is never read: the cap saves the queries too
        read = [c[1] for c in db.calls if c[0] == "ping_minute_rows"]
        assert read == [200, 201, 202], read
