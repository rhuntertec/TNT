"""tnt.geohints: router host name location hints (pure; no network). Real carrier backbone names appear only here."""
from __future__ import annotations

import ast
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from tnt import geohints_data as gd
from tnt.geohints import (CONFIDENCES, HINT_KEYS, KM_PER_MS, MAX_NAME, REASONS, SLACK_KM, distance_km, explain,
                          hint_text, location_hint, plausible)

# (hostname, hop ip, "City, REGION" or "City, CC" when there is no region, confidence or reason)
Vector = Tuple[str, Optional[str], Optional[str], str]

HINT_KINDS = ("iata", "iata_cc", "iata_st", "clli", "clli_cc", "clli4_st", "city", "city_st", "override", "facility")
RULE_KINDS = ("customer",) + HINT_KINDS[:-1]
DALLAS = (32.78, -96.80)

# the prototype's 73 vectors; customer and access PTRs keep documentation-range addresses
PROTO_VECTORS: List[Vector] = [
    # carrier tier
    ("be2763.ccr41.dfw03.atlas.cogentco.com", None, "Dallas, TX", "carrier"),
    ("be2441.ccr41.iah01.atlas.cogentco.com", None, "Houston, TX", "carrier"),
    ("ae-0.a00.dllstx04.us.bb.gin.ntt.net", None, "Dallas, TX", "carrier"),
    ("xe-0-0-28-0.a02.snjsca04.us.ce.gin.ntt.net", None, "San Jose, CA", "carrier"),
    ("ae-0.a02.londen12.uk.bb.gin.ntt.net", None, "London, GB", "carrier"),               # uk -> GB
    ("ae-2-3502.ear1.washington1.level3.net", None, "Washington, DC", "carrier"),          # level3 default
    ("ae-1-3501.EDGE5.Dallas3.Level3.net.", None, "Dallas, TX", "carrier"),               # case + trailing dot
    ("ae-2-4.bear1.manchesteruk1.level3.net", None, "Manchester, GB", "carrier"),
    ("100ge1-1.core1.ash1.he.net", None, "Ashburn, VA", "carrier"),                       # not Nashua NH
    ("10ge10-1.core1.fmt2.he.net", None, "Fremont, CA", "carrier"),
    ("ae0.mcs1.sjc2.us.eth.zayo.com", None, "San Jose, CA", "carrier"),
    ("ae12.mpr1.tor2.ca.zip.zayo.com", None, "Toronto, ON", "carrier"),                   # not Torrington WY
    ("ae0.cr1-chi1.ip4.gtt.net", None, "Chicago, IL", "carrier"),
    ("6-1.sea2m-e40.ip4.gtt.net", None, "Seattle, WA", "carrier"),
    ("if-ae-2-2.tcore1.nto-newyork.as6453.net", None, "New York, NY", "carrier"),
    ("if-ae-12-2.tcore1.fnm-frankfurt.as6453.net", None, "Frankfurt, DE", "carrier"),
    ("0.ae1.gw1.dfw27.alter.net", None, "Dallas, TX", "carrier"),
    ("B3373.BSTNMA-LCR-22.verizon-gni.net", None, "Boston, MA", "carrier"),
    ("so-6-0-0-0.LAX01-BB-RTR1.verizon-gni.net", "198.51.100.44", "Los Angeles, CA", "carrier"),  # interface != IP
    ("cr2.cgcil.ip.att.net", None, "Chicago, IL", "carrier"),
    ("cr1.n54ny.ip.att.net", None, "New York, NY", "carrier"),
    ("bu-ether12.dllstx976iw-bcr00.tbone.rr.com", None, "Dallas, TX", "carrier"),
    ("agg1.nycmnyov01m.netops.charter.com", None, "New York, NY", "carrier"),
    ("sea09s29-in-f3.1e100.net", None, "Seattle, WA", "carrier"),
    ("nyk-bb1-link.ip.twelve99.net", None, "New York, NY", "carrier"),                    # not Nanyuki KE
    ("ffm-bb2-link.ip.twelve99.net", None, "Frankfurt, DE", "carrier"),                   # not Fergus Falls MN
    ("dal-core-02.inet.qwest.net", None, "Dallas, TX", "carrier"),
    ("chc-edge-03.inet.qwest.net", None, "Chicago, IL", "carrier"),                       # not Christchurch
    ("ae0-0.cr02.asbn01-va.us.windstream.net", None, "Ashburn, VA", "carrier"),
    ("ge-1-0-0.101-jun04.mtc3.okc.ok.cox.net", None, "Oklahoma City, OK", "carrier"),
    ("sanjbprj01-ae0.0.rd.sj.cox.net", None, "San Jose, CA", "carrier"),
    # generic tier (unknown domains)
    ("den1-core-01-xe-1-1-0.example.net", None, "Denver, CO", "generic-weak"),
    ("cr1.chicago2.example.net", None, "Chicago, IL", "generic-strong"),
    ("ae3.rtr1.dnvrco01.example.net", None, None, "no-hint"),                             # observed-only tables
    ("cr1.portland1.or.example.net", None, "Portland, OR", "generic-strong"),              # state label decides
    ("eug-core-r1.example.org", None, "Eugene, OR", "generic-weak"),                      # first token + role word
    ("be-11724-cr02.dallas.tx.example.net", None, "Dallas, TX", "generic-strong"),        # state label anchors the city
    ("be-31532-cs03.56marietta.ga.example.net", None, "Atlanta, GA", "generic-strong"),   # facility, not Marietta
    ("be-2411-pe11.350ecermak.il.example.net", None, "Chicago, IL", "generic-strong"),
    # negatives
    ("ae-1-3", None, None, "no-host-part"),
    ("core1", None, None, "no-host-part"),
    ("xe-0-0-0.example.net", None, None, "no-hint"),
    ("lag-12.example.net", None, None, "no-hint"),
    ("research.example.edu", None, None, "no-hint"),                                      # 'sea' inside 'research'
    ("sea.example.net", None, None, "no-hint"),                                           # bare code, no digits
    ("c-203-0-113-7.hsd1.ga.example.net", "203.0.113.7", None, "customer"),               # embedded address
    ("cpe-198-51-100-23.socal.res.rr.com", "198.51.100.23", None, "customer"),
    ("pool-198-51-100-9.nycmny.fios.verizon.net", "198.51.100.9", None, "customer"),       # city code ignored
    ("203-0-113-5.lightspeed.hstntx.sbcglobal.net", "203.0.113.5", None, "customer"),
    ("syn-203-000-113-061.res.spectrum.com", "203.0.113.61", None, "customer"),           # zero-padded
    ("203-0-113-40.dr03.nrwc.ny.frontiernet.net", "203.0.113.40", None, "customer"),
    ("host-198-51-100-77.customer.example.net", None, None, "customer"),                  # heuristic without ip
    ("las-b24-link.ip.twelve99.net", None, None, "unknown-code"),                         # no IATA fallback
    ("xe-0-0-0-ash1-bcr1.bb.example.com", None, None, "no-hint"),                         # carrier-only 'ash'
    ("gig-0-1.cpe1.example.net", None, None, "no-hint"),                                  # gig/cpe collisions
    ("eth0.san01.example.net", None, None, "no-hint"),                                    # san = storage
    ("dns.google", None, None, "no-host-part"),
    ("one.one.one.one", None, None, "no-hint"),
    ("bl-in-f94.1e100.net", None, None, "carrier-no-pattern"),
    ("ae-5.cr01.mcks01-pa.us.windstream.net", None, None, "state-only"),                  # unknown place, known state
    ("cr1.portland1.example.net", None, None, "no-hint"),                                 # ambiguous Portland
    ("cr1.washington1.example.net", None, None, "no-hint"),                               # ambiguous Washington
    ("et-0-0-1.dr01.dlls.pa.frontiernet.net", None, None, "state-only"),                  # Dallas PA is not TX
    ("ae-10-0.cr01.cley01-oh.us.windstream.net", None, None, "state-only"),               # carrier-private code
    ("dfw1-lax2.example.net", None, None, "ambiguous"),
    ("cr1.dfw1.ca.example.net", None, None, "inconsistent"),
    ("2001-db8--1.ip6.example.net", None, None, "customer"),
    ("www.dallas.org", None, None, "no-hint"),                                            # registrable domain
    ("totalelectronics.com", None, None, "no-host-part"),
    ("203.0.113.9", None, None, "not-a-hostname"),
    ("", None, None, "not-a-hostname"),
    ("a" * 64 + ".example.net", None, None, "not-a-hostname"),
    ("xn--dallas-9ya.example.net", None, None, "no-hint"),                                # punycode label skipped
]

# contract additions (the mock parity test, the traceroute tests and the selfcheck use these)
EXTRA_VECTORS: List[Vector] = [
    ("ae3.rtr1.dllstx01.example.net", None, "Dallas, TX", "generic-strong"),
    ("ae-1.cr1.dllstx.example.net", "198.51.100.65", "Dallas, TX", "generic-strong"),
    ("core1.anytown.example.net", "198.51.100.1", None, "no-hint"),
    ("edge2.anytown.example.net", "198.51.100.9", None, "no-hint"),
    ("peer1.example.net", "198.51.100.130", None, "no-hint"),
    ("totalelectronics.com", "203.0.113.80", None, "no-host-part"),
    ("charlotte.host.example.com", None, None, "no-hint"),
    ("sydney.example.net", None, None, "no-hint"),
    ("paloalto-fw1.cust.example.net", None, None, "no-hint"),
    ("mail.boston.example.com", None, None, "no-hint"),
    ("austin2.example.net", None, "Austin, TX", "generic-strong"),
    ("core-austin.example.net", None, "Austin, TX", "generic-strong"),
    ("richardson.tx.example.net", None, "Richardson, TX", "generic-strong"),
    ("aus1-core.example.net", None, None, "no-hint"),          # aus and ind also mean Australia and India
    ("ind-core1.example.net", None, None, "no-hint"),
    # a state label anchors only the city labels to its left; a label right of it is the regional hub
    ("ae-2-rur01.pueblo.co.denver.example.net", None, None, "no-hint"),
    ("ae-3-ar01.sacramento.ca.sanjose.example.net", None, "Sacramento, CA", "generic-strong"),
    ("ae-1-ar01.springfield.il.chicago.example.net", None, "Springfield, IL", "generic-strong"),
]

# (hostname, PC lat/lon or None, min_ms, accepted)
ACCEPTANCE: List[Tuple[str, Optional[Tuple[float, float]], Optional[float], bool]] = [
    ("be2763.ccr41.dfw03.atlas.cogentco.com", DALLAS, 1.2, True),
    ("ae0.cr10-lon1.ip4.gtt.net", DALLAS, 12.0, False),          # London cannot be 12 ms from Dallas
    ("ae0.cr10-lon1.ip4.gtt.net", DALLAS, 110.0, True),
    ("ae-1.mia01.example.net", DALLAS, 4.0, False),              # Miami ~1,790 km away at 4 ms: impossible
    ("den1-core-01-xe-1-1-0.example.net", None, 20.0, False),    # a generic hint needs the guard
    ("den1-core-01-xe-1-1-0.example.net", DALLAS, 20.0, True),
    ("nyk-bb1-link.ip.twelve99.net", None, None, True),          # carrier hint without the guard: accepted
    ("cr1.chicago2.example.net", None, None, False),             # generic-strong without the guard: not accepted
]

# one example per [rule] row, each matched by that row's own regex
RULE_EXAMPLES: Dict[Tuple[str, str], Vector] = {
    ("rr.com", "customer"): ("cpe-198-51-100-23.socal.res.rr.com", "198.51.100.23", None, "customer"),
    ("spectrum.com", "customer"): ("syn-203-000-113-061.res.spectrum.com", "203.0.113.61", None, "customer"),
    ("verizon.net", "customer"): ("pool-198-51-100-9.nycmny.fios.verizon.net", "198.51.100.9", None, "customer"),
    ("sbcglobal.net", "customer"): ("203-0-113-5.lightspeed.hstntx.sbcglobal.net", "203.0.113.5", None, "customer"),
    ("att.net", "customer"): ("adsl.example.dsl.att.net", None, None, "customer"),
    ("ip.att.net", "override"): ("cr2.cgcil.ip.att.net", None, "Chicago, IL", "carrier"),
    ("level3.net", "city"): ("ae-2-3502.ear1.washington1.level3.net", None, "Washington, DC", "carrier"),
    ("lumen.tech", "city"): ("ae2.3615.edge1.dallas2.net.lumen.tech", None, "Dallas, TX", "carrier"),
    ("cogentco.com", "iata"): ("be2763.ccr41.dfw03.atlas.cogentco.com", None, "Dallas, TX", "carrier"),
    ("he.net", "iata"): ("100ge1-1.core1.ash1.he.net", None, "Ashburn, VA", "carrier"),
    ("zayo.com", "iata_cc"): ("ae12.mpr1.tor2.ca.zip.zayo.com", None, "Toronto, ON", "carrier"),
    ("gtt.net", "iata"): ("ae0.cr1-chi1.ip4.gtt.net", None, "Chicago, IL", "carrier"),
    ("ntt.net", "clli_cc"): ("ae-0.a00.dllstx04.us.bb.gin.ntt.net", None, "Dallas, TX", "carrier"),
    ("twelve99.net", "override"): ("nyk-bb1-link.ip.twelve99.net", None, "New York, NY", "carrier"),
    ("telia.net", "override"): ("nyk-b1-link.telia.net", None, "New York, NY", "carrier"),
    ("as6453.net", "city"): ("if-ae-2-2.tcore1.nto-newyork.as6453.net", None, "New York, NY", "carrier"),
    ("alter.net", "iata"): ("0.ae1.gw1.dfw27.alter.net", None, "Dallas, TX", "carrier"),
    ("verizon-gni.net", "clli"): ("B3373.BSTNMA-LCR-22.verizon-gni.net", None, "Boston, MA", "carrier"),
    ("verizon-gni.net", "iata"): ("so-6-0-0-0.LAX01-BB-RTR1.verizon-gni.net", None, "Los Angeles, CA", "carrier"),
    ("tbone.rr.com", "clli"): ("bu-ether12.dllstx976iw-bcr00.tbone.rr.com", None, "Dallas, TX", "carrier"),
    ("netops.charter.com", "clli"): ("agg1.nycmnyov01m.netops.charter.com", None, "New York, NY", "carrier"),
    ("qwest.net", "override"): ("dal-core-02.inet.qwest.net", None, "Dallas, TX", "carrier"),
    ("cox.net", "override"): ("sanjbprj01-ae0.0.rd.sj.cox.net", None, "San Jose, CA", "carrier"),
    ("cox.net", "iata_st"): ("ge-1-0-0.101-jun04.mtc3.okc.ok.cox.net", None, "Oklahoma City, OK", "carrier"),
    ("windstream.net", "clli4_st"): ("ae0-0.cr02.asbn01-va.us.windstream.net", None, "Ashburn, VA", "carrier"),
    ("frontiernet.net", "clli4_st"): ("ae1.dr01.dlls.tx.frontiernet.net", None, "Dallas, TX", "carrier"),
    ("1e100.net", "iata"): ("sea09s29-in-f3.1e100.net", None, "Seattle, WA", "carrier"),
}

# one name shape per override set: that set's own rule, the code in its location position
OVERRIDE_SHAPES: Dict[str, Tuple[str, str]] = {
    "he": ("100ge0-1.core1.{code}1.he.net", "iata"),
    "gtt": ("ae0.cr1-{code}1.ip4.gtt.net", "iata"),
    "zayo": ("ae0.mpr1.{code}1.{cc}.zip.zayo.com", "iata_cc"),
    "cogent": ("be1.ccr41.{code}01.atlas.cogentco.com", "iata"),
    "alter": ("0.ae1.gw1.{code}1.alter.net", "iata"),
    "ntt": ("ae-0.a00.{code}04.{cc}.bb.gin.ntt.net", "clli_cc"),
    "arelion": ("{code}-bb1-link.ip.twelve99.net", "override"),
    "qwest": ("{code}-edge-01.inet.qwest.net", "override"),
    "att": ("cr1.{code}.ip.att.net", "override"),
    "cox": ("{code}bprj01-ae0.0.rd.xx.cox.net", "override"),
    "level3": ("ae-1.ear1.{code}1.level3.net", "city"),
    "tata": ("if-ae-2-2.tcore1.xyz-{code}.as6453.net", "city"),
}

COUNTRY_NAMES = {
    "AE": "United Arab Emirates", "AT": "Austria", "AU": "Australia", "BE": "Belgium", "BG": "Bulgaria", "BR": "Brazil",
    "CA": "Canada", "CH": "Switzerland", "CZ": "Czechia", "DE": "Germany", "DK": "Denmark", "ES": "Spain",
    "FI": "Finland", "FR": "France", "GB": "United Kingdom", "HK": "Hong Kong", "HU": "Hungary", "ID": "Indonesia",
    "IE": "Ireland", "IN": "India", "IT": "Italy", "JP": "Japan", "KR": "South Korea", "MX": "Mexico",
    "MY": "Malaysia", "NL": "The Netherlands", "NO": "Norway", "PL": "Poland", "PT": "Portugal", "RO": "Romania",
    "RU": "Russia", "SE": "Sweden", "SG": "Singapore", "SK": "Slovakia", "TR": "Turkey", "TW": "Taiwan",
    "UA": "Ukraine", "US": "United States", "ZA": "South Africa",
}


def _place(key: str) -> str:
    city, region, cc, _lat, _lon = gd.METROS[key]
    return f"{city}, {region or cc}"


def _fmt(hint: Optional[Dict[str, Any]]) -> Optional[str]:
    return None if hint is None else f"{hint['city']}, {hint['region'] or hint['cc']}"


def _cc_token(key: str) -> str:
    cc = gd.METROS[key][2]
    return "uk" if cc == "GB" else cc.lower()


def _table_vectors() -> List[Vector]:
    """A vector for every lookup row: each code through a carrier rule and through the generic tier."""
    out: List[Vector] = []
    for code, (key, generic) in gd.IATA.items():
        out.append((f"be1.ccr41.{code}01.atlas.cogentco.com", None, _place(gd.OVERRIDES["cogent"].get(code, key)),
                    "carrier"))
        out.append((f"cr1.{code}1.example.net", None, _place(key) if generic else None,
                    "generic-weak" if generic else "no-hint"))
    for code, key in gd.CLLI.items():
        out.append((f"ae-0.a00.{code}04.{_cc_token(key)}.bb.gin.ntt.net", None, _place(key), "carrier"))
        out.append((f"ae3.rtr1.{code}01.example.net", None, _place(key), "generic-strong"))
    for name, rows in gd.CITY.items():
        level3 = gd.OVERRIDES["level3"].get(name)
        if level3 or len(rows) == 1:
            out.append((f"ae-1.ear1.{name}1.level3.net", None, _place(level3 or rows[0][0]), "carrier"))
        else:
            out.append((f"ae-1.ear1.{name}1.level3.net", None, None, "ambiguous-city"))
        out.append((f"www.{name}.example.net", None, None, "no-hint"))            # a bare city name
        strong = len(rows) == 1 and rows[0][1]
        out.append((f"cr1.{name}2.example.net", None, _place(rows[0][0]) if strong else None,
                    "generic-strong" if strong else "no-hint"))
        for key, _generic in rows:
            _city, region, cc, _lat, _lon = gd.METROS[key]
            if cc == "US":
                out.append((f"cr1.{name}2.{region.lower()}.example.net", None, _place(key), "generic-strong"))
    for token, key in gd.FACILITY.items():
        out.append((f"be1.{token}.example.net", None, _place(key), "generic-strong"))
    for oset, codes in gd.OVERRIDES.items():
        shape = OVERRIDE_SHAPES[oset][0]
        for code, key in codes.items():
            out.append((shape.format(code=code, cc=_cc_token(key)), None, _place(key), "carrier"))
    return out


VECTORS = PROTO_VECTORS + EXTRA_VECTORS + list(RULE_EXAMPLES.values()) + _table_vectors()


def test_vector_lists_match_the_contract():
    assert len(PROTO_VECTORS) == 73 and len(ACCEPTANCE) == 8
    assert set(RULE_EXAMPLES) == {(suffix, kind) for suffix, kind, _oset, _rx in gd.RULES}
    assert len(RULE_EXAMPLES) == len(gd.RULES)
    assert set(OVERRIDE_SHAPES) == set(gd.OVERRIDES)


@pytest.mark.parametrize("host, ip, want, tag", VECTORS, ids=[f"{v[0][:80]}@{v[1]}" for v in VECTORS])
def test_vectors(host: str, ip: Optional[str], want: Optional[str], tag: str):
    hint, reason = explain(host, ip)
    assert reason in REASONS
    assert (hint is not None) == (reason == "ok")
    assert (_fmt(hint), hint["confidence"] if hint else reason) == (want, tag)
    assert location_hint(host, ip) == hint
    if hint is not None:
        assert tuple(hint) == HINT_KEYS
        assert hint["key"] in gd.METROS and hint["kind"] in HINT_KINDS and hint["confidence"] in CONFIDENCES
        assert isinstance(hint["lat"], float) and isinstance(hint["lon"], float)
        assert hint["code"] == hint["code"].lower() and hint["code"] in host.lower()
        assert (hint["rule"] == "generic") == (hint["confidence"] != "carrier")


def test_rule_examples_use_their_own_row():
    for (suffix, kind), (host, ip, _want, _tag) in RULE_EXAMPLES.items():
        rx = next(r for s, k, _o, r in gd.RULES if (s, k) == (suffix, kind))
        assert re.search(rx, host.lower().rstrip(".")), (suffix, kind)
        hint, reason = explain(host, ip)
        if kind == "customer":
            assert (hint, reason) == (None, "customer")
        else:
            assert hint is not None and (hint["rule"], hint["kind"]) == (suffix, kind), (suffix, kind, reason)


def test_override_rows_resolve_through_their_set():
    for oset, codes in gd.OVERRIDES.items():
        shape, kind = OVERRIDE_SHAPES[oset]
        for code, key in codes.items():
            hint = location_hint(shape.format(code=code, cc=_cc_token(key)))
            assert hint is not None and (hint["key"], hint["code"], hint["kind"]) == (key, code, kind), (oset, code)


@pytest.mark.parametrize("host, origin, min_ms, accepted", ACCEPTANCE)
def test_acceptance_vectors(host: str, origin: Optional[Tuple[float, float]], min_ms: Optional[float], accepted: bool):
    hint = location_hint(host)
    assert hint is not None
    assert plausible(hint, origin, min_ms) is accepted


@pytest.mark.parametrize("host, text", [
    ("ae-0.a00.dllstx04.us.bb.gin.ntt.net", "Dallas, TX"),
    ("ae12.mpr1.tor2.ca.zip.zayo.com", "Toronto, ON"),
    ("ae-0.a02.londen12.uk.bb.gin.ntt.net", "London, United Kingdom"),
    ("ae-0.a03.sngpsi07.sg.bb.gin.ntt.net", "Singapore"),
    ("ae-2-3502.ear1.washington1.level3.net", "Washington, DC"),
    ("if-ae-12-2.tcore1.fnm-frankfurt.as6453.net", "Frankfurt, Germany"),
])
def test_hint_text(host: str, text: str):
    assert hint_text(location_hint(host)) == text


def test_hint_text_for_every_metro():
    for key, (city, region, cc, lat, lon) in gd.METROS.items():
        text = hint_text({"key": key, "city": city, "region": region, "cc": cc, "lat": lat, "lon": lon})
        if cc in ("US", "CA"):
            assert text == f"{city}, {region}"
        elif gd.COUNTRY_NAMES[cc].lower() == city.lower():
            assert text == city                       # "Singapore", "Hong Kong"
        else:
            assert text == f"{city}, {gd.COUNTRY_NAMES[cc]}"
    assert hint_text({"city": "Hong Kong", "region": "", "cc": "HK"}) == "Hong Kong"


def test_bare_city_names_are_no_hint():
    for host in ("charlotte.host.example.com", "sydney.example.net", "paloalto-fw1.cust.example.net",
                 "mail.boston.example.com", "core1.austin.example.net", "austin-fw1.example.net"):
        assert explain(host) == (None, "no-hint"), host
    # a US state label anchors a US city only ("de" is also Germany's country code)
    for host in ("cr1.hamburg.ny.example.net", "cr1.toronto.oh.example.net", "cr1.milan.tn.example.net",
                 "cr1.frankfurt.de.example.net"):
        assert explain(host) == (None, "no-hint"), host
    # ... and only a city label to its left: one to its right is a regional hub, not the router's town
    for host in ("cr1.tx.dallas.example.net", "po-1-rur01.pueblo.co.denver.example.net",
                 "po-1-rur01.woburn.ma.boston.example.net"):
        assert explain(host) == (None, "no-hint"), host
    assert explain("cr1.austin.mn.example.net") == (None, "inconsistent")
    for host, place in (("austin2.example.net", "Austin, TX"), ("core-austin.example.net", "Austin, TX"),
                        ("austin-core.example.net", "Austin, TX"), ("core1-austin.example.net", "Austin, TX"),
                        ("richardson.tx.example.net", "Richardson, TX"), ("cr1.chicago2.example.net", "Chicago, IL"),
                        ("cr1.portland1.or.example.net", "Portland, OR"),
                        ("cr1.frankfurt2.de.example.net", "Frankfurt, DE")):
        hint, reason = explain(host)
        assert reason == "ok" and _fmt(hint) == place, host
        assert (hint["kind"], hint["confidence"]) == ("city", "generic-strong")


def test_plausible_needs_the_guard_for_generic_hints():
    carrier = location_hint("ae0.cr10-lon1.ip4.gtt.net")             # London
    strong = location_hint("cr1.chicago2.example.net")                 # Chicago
    weak = location_hint("den1-core-01-xe-1-1-0.example.net")         # Denver
    assert [h["confidence"] for h in (carrier, strong, weak)] == list(CONFIDENCES)
    assert plausible(None, DALLAS, 5.0) is False and plausible(None, None, None) is False
    no_guard = [(None, 5.0), (None, None), (DALLAS, None), (DALLAS, float("nan")), (DALLAS, -1.0),
                (DALLAS, float("inf")), ("32.78,-96.80", 5.0), ((32.78,), 5.0), ((float("nan"), -96.80), 5.0)]
    for origin, min_ms in no_guard:
        assert plausible(carrier, origin, min_ms) is True, (origin, min_ms)
        assert plausible(strong, origin, min_ms) is False, (origin, min_ms)
        assert plausible(weak, origin, min_ms) is False, (origin, min_ms)
    for hint in (carrier, strong, weak):
        d = distance_km(DALLAS[0], DALLAS[1], hint["lat"], hint["lon"])
        assert d > SLACK_KM
        edge = (d - SLACK_KM) / KM_PER_MS
        assert plausible(hint, DALLAS, edge + 1e-6) is True
        assert plausible(hint, DALLAS, edge - 1e-6) is False
        assert plausible(hint, DALLAS, 0.0) is False
        assert plausible(hint, list(DALLAS), 500) is True           # an int min_ms and a list origin both work
    dallas = location_hint("be2763.ccr41.dfw03.atlas.cogentco.com")
    assert plausible(dallas, DALLAS, 0.0) is True                    # within the slack


def test_distance_km():
    assert distance_km(*DALLAS, *DALLAS) == 0.0
    assert abs(distance_km(*DALLAS, 51.51, -0.13) - 7641) < 5       # Dallas - London
    assert abs(distance_km(*DALLAS, 25.76, -80.19) - 1787) < 5      # Dallas - Miami
    assert abs(distance_km(0.0, 0.0, 0.0, 180.0) - math.pi * 6371.0) < 1e-6
    assert distance_km(51.51, -0.13, *DALLAS) == pytest.approx(distance_km(*DALLAS, 51.51, -0.13))


def test_embedded_address_is_a_customer():
    for host, ip in (("7.113.0.203.example.net", "203.0.113.7"),              # reversed octets
                     ("static-203-000-113-007.example.net", "203.0.113.7"),   # zero-padded
                     ("h.2001-db8-0-0.example.net", "2001:db8::1"),           # IPv6 leading groups
                     ("dllstx-198-51-100-4.example.net", "198.51.100.4")):    # the address wins over a place code
        assert explain(host, ip) == (None, "customer"), host
    assert _fmt(location_hint("xe-0-0-0-0.cr1.dllstx.example.net", "198.51.100.4")) == "Dallas, TX"


def test_service_code_uses_invented_router_names():
    # real carrier backbone names are allowed in this test file only (contract §0.3); a bare suffix is fine
    suffixes = {suffix for suffix, _kind, _oset, _rx in gd.RULES}
    package = Path(gd.__file__).parent
    real: List[str] = []
    for path in sorted(package.rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for name in re.findall(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", line.lower()):
                if name not in suffixes and any(name.endswith("." + suffix) for suffix in suffixes):
                    real.append(f"{path.name}:{number}: {name}")
    assert real == []
    # every carrier suffix the module docstring cites is a [rule] suffix
    doc = ast.get_docstring(ast.parse((package / "geohints.py").read_text(encoding="utf-8"))) or ""
    cited = [name for name in re.findall(r"``([a-z0-9-]+(?:\.[a-z0-9-]+)+)``", doc)
             if name.endswith((".net", ".com")) and not name.endswith(".example.net")]
    assert cited and [name for name in cited if name not in suffixes] == []


def _literal_duplicates(source: str) -> List[Any]:
    dups: List[Any] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Dict):
            keys = [ast.literal_eval(k) for k in node.keys if k is not None]
        elif isinstance(node, ast.Set):
            keys = [ast.literal_eval(e) for e in node.elts]
        else:
            continue
        dups += sorted({k for k in keys if keys.count(k) > 1})
    return dups


def test_table_integrity():
    source = Path(gd.__file__).read_text(encoding="utf-8")
    # no duplicates (a dict or set literal would silently drop one)
    assert _literal_duplicates(source) == []
    assert len(set(gd.RULES)) == len(gd.RULES)
    assert all(len(set(rows)) == len(rows) and len({m for m, _g in rows}) == len(rows) for rows in gd.CITY.values())
    # counts (observed-only tables)
    assert len(gd.CLLI) == 47
    assert sum(len(codes) for codes in gd.OVERRIDES.values()) == 74
    assert len(gd.RULES) == 27
    assert len(gd.METROS) == 268
    assert sum(1 for m in gd.METROS.values() if m[2] == "US") == 217
    assert len(gd.IATA) == 274 and sum(1 for _k, g in gd.IATA.values() if g) == 171
    assert len(gd.CITY) == 106 and sum(len(rows) for rows in gd.CITY.values()) == 113
    assert len(gd.FACILITY) == 3 and len(gd.STOP) == 176 and len(gd.US_STATES) == 52
    assert {"dc", "pr"} <= set(gd.US_STATES)
    # metros
    for key, (city, region, cc, lat, lon) in gd.METROS.items():
        assert re.fullmatch(r"[a-z]+-[a-z]{2}", key) and city and cc in gd.COUNTRY_NAMES, key
        assert isinstance(lat, float) and isinstance(lon, float) and -90 <= lat <= 90 and -180 <= lon <= 180, key
        if cc == "US":
            assert region.lower() in gd.US_STATES and key.endswith("-" + region.lower()), key
        if cc == "CA":
            assert re.fullmatch(r"[A-Z]{2}", region), key
    assert gd.COUNTRY_NAMES == COUNTRY_NAMES
    assert set(gd.COUNTRY_NAMES) == {cc for _c, _r, cc, _la, _lo in gd.METROS.values() if cc}
    assert set(gd.CC_TOKENS.values()) <= set(gd.COUNTRY_NAMES)
    # every referenced metro exists
    referenced = ([m for m, _g in gd.IATA.values()] + list(gd.CLLI.values()) + list(gd.FACILITY.values())
                  + [m for rows in gd.CITY.values() for m, _g in rows]
                  + [m for codes in gd.OVERRIDES.values() for m in codes.values()])
    assert [m for m in referenced if m not in gd.METROS] == []
    assert all(re.fullmatch(r"[a-z]{3}", code) for code in gd.IATA)
    # a US CLLI's last 2 letters equal the metro state
    for code, key in gd.CLLI.items():
        assert re.fullmatch(r"[a-z]{6}", code), code
        if gd.METROS[key][2] == "US":
            assert code[4:] == gd.METROS[key][1].lower(), code
    # ambiguous city rows are generic=False
    assert [name for name, rows in gd.CITY.items() if len(rows) > 1 and any(g for _m, g in rows)] == []
    # every rule regex compiles with a code group (customer rows only flag a name)
    for suffix, kind, oset, rx in gd.RULES:
        pattern = re.compile(rx)
        assert kind in RULE_KINDS, (suffix, kind)
        assert oset == "-" or oset in gd.OVERRIDES, (suffix, oset)
        if kind == "customer":
            continue
        assert "code" in pattern.groupindex, (suffix, kind)
        assert ("st" in pattern.groupindex) == kind.endswith("_st"), (suffix, kind)
        assert ("cc" in pattern.groupindex) == kind.endswith("_cc"), (suffix, kind)
        assert kind != "override" or oset != "-", suffix
    assert {oset for _s, _k, oset, _r in gd.RULES if oset != "-"} == set(gd.OVERRIDES)
    assert all(re.fullmatch(r"[a-z0-9]+", tok) for tok in gd.STOP)
    # the arelion "bpt" collision (Budapest; IATA BPT is Beaumont, TX) is the only one, and it is documented
    collisions = {(oset, code) for oset, codes in gd.OVERRIDES.items() for code, key in codes.items()
                  if code in gd.IATA and gd.IATA[code][0] != key}
    assert collisions == {("arelion", "bpt")}
    assert re.search(r'"bpt": "budapest-hu",\s*#[^\n]*\bBPT\b[^\n]*Beaumont', source)


def test_never_raises_on_junk():
    junk: List[object] = [None, 5, b"x", "a" * 10000, "..", "-", "xn--", 3.5, object(), ["core1.example.net"],
                          "\x00", "é.example.net", "a..b.example.net", "1" * 63 + ".example.net",
                          "x" * (MAX_NAME + 1), "cr1." + "a" * 63 + "." + "b" * 63 + ".example.net"]
    for value in junk:
        for ip in (None, "", 5, b"x", "not-an-ip", "198.51.100.1", "2001:db8::1", "fe80::1%3"):
            hint, reason = explain(value, ip)             # type: ignore[arg-type]
            assert reason in REASONS and (hint is None) == (reason != "ok")
            assert location_hint(value, ip) == hint       # type: ignore[arg-type]
    for value in (None, 5, b"x", "a" * 10000, ".."):
        assert explain(value) == (None, "not-a-hostname")
    assert explain("-") == (None, "no-host-part")
    assert explain("xn--") == (None, "no-host-part")
    for hint in ({}, {"confidence": "generic-strong"}, {"confidence": "carrier", "lat": "x", "lon": None}):
        for origin, min_ms in ((None, None), (DALLAS, 5.0), ("x", "y"), ((1, 2, 3), 5)):
            assert plausible(hint, origin, min_ms) in (True, False)       # type: ignore[arg-type]
    assert plausible("not a hint", DALLAS, 5.0) is False                  # type: ignore[arg-type]
    assert hint_text({}) == ""


def test_mixed_case_and_trailing_dot():
    base = explain("ae-1.cr1.dllstx.example.net")
    assert base[0] is not None and base[0]["code"] == "dllstx"
    for name in ("AE-1.CR1.DLLSTX.EXAMPLE.NET", "ae-1.cr1.DllsTx.example.net.", " Ae-1.Cr1.Dllstx.Example.Net. "):
        assert explain(name) == base
    carrier = explain("ae-1-3501.EDGE5.Dallas3.Level3.net.")
    assert carrier == explain("ae-1-3501.edge5.dallas3.level3.net")
    assert carrier[0] is not None and (carrier[0]["code"], carrier[0]["rule"]) == ("dallas", "level3.net")
