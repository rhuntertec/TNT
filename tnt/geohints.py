"""Router host name location hints for the traceroute Location column.

:func:`explain` reads a reverse-DNS name such as ``ae3.rtr1.dllstx01.example.net`` and returns the place its
location code refers to, or ``None`` with the reason there is no hint. The tables live in :mod:`tnt.geohints_data`
(only codes seen in public router names). Nothing here does I/O: every call is local and pure.

* **Normalise.** A ``str`` only; stripped, trailing dot removed, lower-cased; ``[a-z0-9._-]``, at most
  :data:`MAX_NAME` characters, labels of 1-63; IP literals are not host names.
* **Carrier tier.** The longest known carrier suffix (``ntt.net``, ``level3.net`` ...) picks that carrier's rules.
  A customer rule, or a name that embeds the hop address, means ``customer`` (the database wins). The other rules
  are tried in table order: the code is resolved through the rule's override set first, then the dictionary of its
  kind (an ``override`` rule never falls back). A state or country token must agree with the place. A known suffix
  with no matching rule gives no hint and never falls through to the generic tier.
* **Generic tier** (unknown domains). The registrable domain is dropped and every ``-``/``_`` token of the remaining
  labels is read. A 6-letter place code or a ``56marietta``-style facility token is strong. A city name is strong
  only when anchored: trailing digits (``chicago2``), a US state label to its right in the host part for a US city
  (``richardson.tx``; labels right of the state label name a region or hub, not the router's town) or a role word
  next to it in the same label (``core-austin``). A bare city name is a server, person or brand name, so it is no
  hint. A 3-letter airport code is weak and needs digits (``den1``) or, as the first token, a role word after it
  (``eug-core``). Two places, or a state label that disagrees, give no hint.

:func:`plausible` is the speed-of-light guard applied before a hint replaces the database city: the hint may not be
farther from the PC than ``min_ms * KM_PER_MS + SLACK_KM``. Without the guard only ``carrier`` hints pass.
"""
from __future__ import annotations

import ipaddress
import math
import re
from typing import Any, Dict, List, Optional, Tuple

from . import geohints_data as _data

__all__ = ["KM_PER_MS", "SLACK_KM", "MAX_NAME", "HINT_KEYS", "REASONS", "CONFIDENCES", "explain", "location_hint",
           "plausible", "distance_km", "hint_text"]

KM_PER_MS = 100.0        # light in fibre ~200,000 km/s over a round trip
SLACK_KM = 150.0         # database city error + approximate city centres
MAX_NAME = 253
HINT_KEYS = ("key", "city", "region", "cc", "lat", "lon", "code", "kind", "rule", "confidence")
REASONS = ("ok", "not-a-hostname", "customer", "carrier-no-pattern", "unknown-code", "state-only",
           "ambiguous-city", "inconsistent", "no-host-part", "no-hint", "ambiguous")
CONFIDENCES = ("carrier", "generic-strong", "generic-weak")

_EARTH_RADIUS_KM = 6371.0
# a role word before (or, for a city name, beside) a place token marks a router name: "eug-core", "core-austin"
_ROLE_NEXT = frozenset({"core", "edge", "cr", "br", "gw", "rtr", "bb", "pe", "ar", "er", "agg", "border", "peer",
                        "router"})
_CUSTOMER_PREFIX = frozenset({"c", "cpe", "pool", "static", "syn", "dsl", "adsl", "dhcp", "dyn", "dynamic", "ip", "host",
                              "rrcs", "wsip", "ool", "ppp", "customer", "cust", "user", "client", "h", "d", "s", "x",
                              "b"})
_TWO_LEVEL_SLD = frozenset({"co", "com", "net", "org", "ac", "gov", "edu", "ne", "or", "go", "gv", "mil"})

_NAME_RE = re.compile(r"[a-z0-9._-]+")
_DOTTED_QUAD_RE = re.compile(r"^([a-z]{1,8})?-?(\d{1,3})[-.](\d{1,3})[-.](\d{1,3})[-.](\d{1,3})(?![0-9])")
_V6_DOUBLE_DASH_RE = re.compile(r"[0-9a-f]{1,4}(?:-{1,2}[0-9a-f]{1,4}){2,}")
_V6_GROUPS_RE = re.compile(r"[0-9a-f]{1,4}(?:-[0-9a-f]{1,4}){4,}")
_HEX_LETTERS_RE = re.compile(r"[a-f][0-9a-f]{2,}|[0-9a-f]{2,}[a-f]")
_TOKEN_SPLIT_RE = re.compile(r"[-_]")
_FACILITY_TOKEN_RE = re.compile(r"\d+[a-z]+")
_PLACE_TOKEN_RE = re.compile(r"([a-z]+)(\d*)")
_TRAILING_DIGITS_RE = re.compile(r"\d+$")

_Rule = Tuple[str, str, "re.Pattern[str]"]


def _compile_rules() -> Dict[str, List[_Rule]]:
    rules: Dict[str, List[_Rule]] = {}
    for suffix, kind, oset, rx in _data.RULES:
        rules.setdefault(suffix, []).append((kind, oset, re.compile(rx)))
    return rules


_RULES = _compile_rules()


# --------------------------------------------------------------------------- helpers
def _norm(hostname: object) -> Optional[str]:
    if not isinstance(hostname, str):
        return None
    h = hostname.strip().rstrip(".").lower()
    if not h or len(h) > MAX_NAME or not _NAME_RE.fullmatch(h):
        return None
    if any(not 0 < len(label) <= 63 for label in h.split(".")):
        return None
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    return h


def _embeds_ip(h: str, ip: object) -> bool:
    """Customer PTRs embed the address they describe; interface names like ``so-6-0-0-0`` do not match an IP."""
    if isinstance(ip, str) and ip:
        try:
            addr: Any = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if isinstance(addr, ipaddress.IPv4Address):
            octets = str(addr).split(".")
            for seq in (octets, octets[::-1]):
                pattern = r"(?<![0-9])" + r"[-.]".join("0{0,2}" + x for x in seq) + r"(?![0-9])"
                if re.search(pattern, h):
                    return True
        elif isinstance(addr, ipaddress.IPv6Address):
            groups = addr.exploded.split(":")
            short = [g.lstrip("0") or "0" for g in groups]
            if "-".join(short[:4]) in h or "-".join(groups[:4]) in h:
                return True
    first = h.split(".")[0]
    m = _DOTTED_QUAD_RE.match(h)
    if m and (m.group(1) is None or m.group(1) in _CUSTOMER_PREFIX) and all(int(x) <= 255 for x in m.groups()[1:]):
        return True
    if ("--" in first and _V6_DOUBLE_DASH_RE.fullmatch(first)) or (
            _V6_GROUPS_RE.fullmatch(first) and _HEX_LETTERS_RE.search(first)):
        return True
    return False


def _hint(key: str, code: str, kind: str, rule: str, confidence: str) -> Dict[str, Any]:
    city, region, cc, lat, lon = _data.METROS[key]
    return {"key": key, "city": city, "region": region, "cc": cc, "lat": lat, "lon": lon, "code": code,
            "kind": kind, "rule": rule, "confidence": confidence}


def _consistent(key: str, st: Optional[str], cc: Optional[str]) -> bool:
    _city, region, metro_cc, _lat, _lon = _data.METROS[key]
    if cc and _data.CC_TOKENS.get(cc, cc.upper()) != metro_cc:
        return False
    if st and (metro_cc != "US" or st.upper() != region):
        return False
    return True


def _carrier_rules(h: str) -> Tuple[Optional[str], List[_Rule]]:
    """The longest carrier suffix that ends ``h`` on a label boundary, with its rules."""
    labels = h.split(".")
    for i in range(len(labels)):
        suffix = ".".join(labels[i:])
        rules = _RULES.get(suffix)
        if rules:
            return suffix, rules
    return None, []


# --------------------------------------------------------------------------- carrier tier
def _carrier(h: str, ip: object) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    suffix, rules = _carrier_rules(h)
    if suffix is None:
        return False, None, "no-hint"
    # the same brand can have several suffixes (verizon.net customers, verizon-gni.net routers): only this one's rows
    for kind, _oset, rx in rules:
        if kind == "customer" and rx.search(h):
            return True, None, "customer"
    if _embeds_ip(h, ip):
        return True, None, "customer"
    for kind, oset, rx in rules:
        if kind == "customer":
            continue
        m = rx.search(h)
        if not m:
            continue
        groups = m.groupdict()
        code, st, cc = groups.get("code"), groups.get("st"), groups.get("cc")
        ov = _data.OVERRIDES.get(oset, {}) if oset != "-" else {}
        key: Optional[str] = None
        if kind == "override":
            key = ov.get(code)
            if key is None:
                return True, None, "unknown-code"
        elif kind in ("iata", "iata_cc", "iata_st"):
            key = ov.get(code) or (_data.IATA[code][0] if code in _data.IATA else None)
        elif kind in ("clli", "clli_cc"):
            key = ov.get(code) or _data.CLLI.get(code)
        elif kind == "clli4_st":
            key = _data.CLLI.get(code + st) if st in _data.US_STATES else None
            if key is None:
                return True, None, "state-only"
        elif kind == "city":
            if code in ov:
                key = ov[code]
            elif code in _data.CITY:
                rows = _data.CITY[code]
                if len(rows) > 1:
                    return True, None, "ambiguous-city"
                key = rows[0][0]
        elif kind == "city_st":
            if code in _data.FACILITY:
                key = _data.FACILITY[code]
            elif code in _data.CITY:
                state = (st or "").upper()
                fit = [mk for mk, _generic in _data.CITY[code]
                       if _data.METROS[mk][2] == "US" and _data.METROS[mk][1] == state]
                key = fit[0] if len(fit) == 1 else None
            if key is None:
                return True, None, "state-only"
        if key is None:
            return True, None, "unknown-code"
        if not _consistent(key, st, cc):
            return True, None, "inconsistent"
        return True, _hint(key, code, kind, suffix, "carrier"), "ok"
    return True, None, "carrier-no-pattern"


# --------------------------------------------------------------------------- generic tier
def _role_word_beside(tokens: List[str], i: int) -> bool:
    for j in (i - 1, i + 1):
        if 0 <= j < len(tokens) and _TRAILING_DIGITS_RE.sub("", tokens[j]) in _ROLE_NEXT:
            return True
    return False


def _generic(h: str, ip: object) -> Tuple[Optional[Dict[str, Any]], str]:
    if _embeds_ip(h, ip):
        return None, "customer"
    labels = h.split(".")
    drop = 2
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _TWO_LEVEL_SLD:
        drop = 3
    host = labels[:-drop] if len(labels) > drop else []
    if not host:
        return None, "no-host-part"
    state_labels = {label for label in host if label in _data.US_STATES}
    # a state label anchors only the city labels to its left: labels to its right name a region or hub
    # ("rur01.pueblo.co.denver" is a router in Pueblo, not Denver)
    st_at = max((n for n, label in enumerate(host) if label in _data.US_STATES), default=-1)
    cands: List[Tuple[str, str, str, bool]] = []   # (metro key, kind, code, strong)
    first_token = True
    for li, label in enumerate(host):
        if label.startswith("xn--"):           # punycode (IDN) label: never a place code
            first_token = False
            continue
        tokens = _TOKEN_SPLIT_RE.split(label)
        for i, tok in enumerate(tokens):
            is_first = first_token
            first_token = False
            if not tok or tok.isdigit():
                continue
            if _FACILITY_TOKEN_RE.fullmatch(tok):     # digits never stripped: "56marietta" is not Marietta
                if tok in _data.FACILITY:
                    cands.append((_data.FACILITY[tok], "facility", tok, True))
                continue
            m = _PLACE_TOKEN_RE.fullmatch(tok)
            if not m:
                continue
            base, digits = m.group(1), m.group(2)
            if base in _data.STOP or len(base) < 3:
                continue
            if len(base) == 6 and base in _data.CLLI:
                cands.append((_data.CLLI[base], "clli", base, True))
            elif len(base) >= 5 and base in _data.CITY:
                rows = _data.CITY[base]
                if len(rows) == 1 and rows[0][1]:
                    # a bare city name is no hint ("charlotte.host", "sydney"): it needs an anchor. A state label
                    # anchors a US city only: "hamburg.ny" is not Hamburg (and a US city in another state is
                    # "inconsistent" below)
                    if digits or (li < st_at and _data.METROS[rows[0][0]][2] == "US") or _role_word_beside(tokens, i):
                        cands.append((rows[0][0], "city", base, True))
                elif li < st_at:
                    fit = [mk for mk, _generic in rows
                           if _data.METROS[mk][2] == "US" and _data.METROS[mk][1].lower() in state_labels]
                    if len(fit) == 1:
                        cands.append((fit[0], "city", base, True))
            elif len(base) == 3 and base in _data.IATA and _data.IATA[base][1]:
                nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
                if digits or (is_first and _TRAILING_DIGITS_RE.sub("", nxt) in _ROLE_NEXT):
                    cands.append((_data.IATA[base][0], "iata", base, False))
    keys = {c[0] for c in cands}
    if not keys:
        return None, "no-hint"
    if len(keys) > 1:
        return None, "ambiguous"
    key = keys.pop()
    _city, region, cc, _lat, _lon = _data.METROS[key]
    if state_labels and cc == "US" and region.lower() not in state_labels:
        return None, "inconsistent"
    best = sorted(cands, key=lambda c: not c[3])[0]
    return _hint(key, best[2], best[1], "generic", "generic-strong" if best[3] else "generic-weak"), "ok"


# --------------------------------------------------------------------------- public API
def explain(hostname: object, ip: Optional[str] = None) -> Tuple[Optional[Dict[str, Any]], str]:
    """``(hint, reason)``: a dict with exactly :data:`HINT_KEYS` and ``"ok"``, or ``None`` and why. Never raises."""
    try:
        h = _norm(hostname)
        if h is None:
            return None, "not-a-hostname"
        matched, hint, reason = _carrier(h, ip)
        if matched:
            return hint, reason
        return _generic(h, ip)
    except Exception:  # noqa: BLE001 - a hint is optional; it must never break a traceroute
        return None, "not-a-hostname"


def location_hint(hostname: object, ip: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """The hint dict for ``hostname`` (hop address ``ip``), or ``None``: ``explain()[0]``."""
    return explain(hostname, ip)[0]


def _finite(value: object) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def plausible(hint: Optional[Dict[str, Any]], origin: Optional[Tuple[float, float]],
              min_ms: Optional[float]) -> bool:
    """Whether ``hint`` may replace the database city for a hop answering in ``min_ms`` from ``origin`` (lat, lon).

    With both known (``min_ms`` finite and >= 0) the hint may be at most ``min_ms * KM_PER_MS + SLACK_KM`` away.
    When the guard cannot run only ``carrier`` hints are accepted."""
    if not isinstance(hint, dict):
        return False
    ms = _finite(min_ms)
    point = None
    if isinstance(origin, (tuple, list)) and len(origin) == 2:
        lat, lon = _finite(origin[0]), _finite(origin[1])
        if lat is not None and lon is not None:
            point = (lat, lon)
    if point is None or ms is None or ms < 0:
        return hint.get("confidence") == "carrier"
    hint_lat, hint_lon = _finite(hint.get("lat")), _finite(hint.get("lon"))
    if hint_lat is None or hint_lon is None:
        return False
    return not distance_km(point[0], point[1], hint_lat, hint_lon) > ms * KM_PER_MS + SLACK_KM


def distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km (haversine, mean Earth radius)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * _EARTH_RADIUS_KM * math.asin(math.sqrt(min(1.0, a)))


def hint_text(hint: Dict[str, Any]) -> str:
    """Display text: "Dallas, TX", "Toronto, ON", "London, United Kingdom"; "Singapore" when both parts agree."""
    city = str(hint.get("city") or "")
    region = str(hint.get("region") or "")
    cc = str(hint.get("cc") or "")
    second = region if cc in ("US", "CA") and region else _data.COUNTRY_NAMES.get(cc, cc)
    if not second or second.lower() == city.lower():
        return city
    return f"{city}, {second}"
