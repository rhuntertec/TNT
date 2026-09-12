"""IP location + ISP for TNT from the DB-IP Lite databases (city and ASN, CC BY 4.0).

:class:`GeoIpManager` (``engine.geoip``) keeps the two monthly DB-IP Lite files in the data folder's ``geoip``
sub-folder, loads them with the pure-stdlib reader in :mod:`tnt.mmdb` and answers lookups for the Network info page
(``status.map.public_geo``) and the traceroute Location column (:meth:`GeoIpManager.locate_hop`, which also reads
router host names through :mod:`tnt.geohints`). Every lookup is local: nothing about an address leaves the PC.

Download, verify, swap
----------------------
On its own daemon thread (``tnt-geoip``) the manager fetches ``dbip-asn-lite-YYYY-MM.mmdb.gz`` and then the city
file from ``download.db-ip.com`` over HTTPS (a fresh default TLS context per download, certificate checks always
on). Each stream is gunzipped on the fly into ``*.mmdb.part`` with a compressed and a decompressed size cap, bounded
zlib output per call (a gzip bomb cannot exhaust memory), no trailing data and a stall rule (less than 1 MB in any
5 minutes aborts). Both parts are then opened and checked: IPv6 tree, database type, build month, a sampled walk of
the tree and known-answer probes. Only then are they moved to versioned names (``...-2026-09.mmdb``, ``.1`` when that
name is still mapped), opened, and swapped in as one immutable snapshot; the old readers close after the swap,
``manifest.json`` is written and the old files are deleted. A crash at any point leaves the previous data usable.

Schedule and budget
-------------------
The first check runs ``FIRST_CHECK_DELAY_S`` after start, then at 03:00 UTC (+ jitter) on the 1st of each month,
every 6 h while the month is not published (only HTTP 404/410 mean that; the previous month is used meanwhile), and
with a backoff of 1 min .. 6 h after failures. ``state.json`` keeps the failures, the last attempt and a per-month
budget across restarts: three failed attempts that each received more than 1 MiB, or one failed check of the data,
pause that month until a newer month is out or Retry (:meth:`GeoIpManager.check_now`) clears it.

Locks
-----
``_readers_lock`` guards the snapshot swap and every lookup; ``_lock`` guards the rest of the state. The two are never
held together, and no config call, event or I/O happens under either. ``stop()`` and switching the setting off abort
an active download (the socket is shut down) and unload the data; the downloaded files stay on disk.

Privacy
-------
INFO/WARNING lines and status texts never contain an IP address, a city or an ISP; an IP-literal host is written as
"another site". Lookup details go to DEBUG only.

Attribution: "IP Geolocation by DB-IP" (https://db-ip.com), licensed CC BY 4.0; ISP names are shortened for display.
"""
from __future__ import annotations

import calendar
import email.utils
import http.client
import importlib
import ipaddress
import json
import logging
import math
import os
import random
import re
import shutil
import socket
import ssl
import threading
import time
import zlib
from pathlib import Path
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple, Union
from urllib.parse import urljoin, urlsplit

from . import __version__
from . import geohints, mmdb

log = logging.getLogger(__name__)

MiB = 1024 * 1024
BASE_URL = "https://download.db-ip.com/free/"
FILE_KINDS = ("city", "asn")              # manifest, files() and verify order: city first
DOWNLOAD_ORDER = ("asn", "city")          # the 5 MB file first: a month whose second file is missing costs ~5 MB, not 60
DB_TYPE_PREFIX = {"city": "DBIP-City-Lite", "asn": "DBIP-ASN-Lite"}
MANIFEST_NAME = "manifest.json"
MANIFEST_VERSION = 1
STATE_FILE_NAME = "state.json"            # failures, last attempt, per-month budget (§4.5.3)
STATE_FILE_VERSION = 1
FILE_NAME_RE = re.compile(r"^dbip-(city|asn)-lite-(\d{4}-\d{2})(?:\.(\d))?\.mmdb$")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
MAX_REDIRECTS = 3
SOCKET_TIMEOUT_S = 30.0                   # connect and per-read timeout
STALL_WINDOW_S = 300.0                    # the stall rule: fewer than STALL_MIN_BYTES in any 5 min window aborts
STALL_MIN_BYTES = 1 * MiB
READ_CHUNK = 256 * 1024
DECOMPRESS_STEP = 4 * MiB                 # max bytes produced per zlib call (bounds memory against a gzip bomb)
CAPS = {"city": (150 * MiB, 400 * MiB), "asn": (25 * MiB, 64 * MiB)}   # (compressed, decompressed)
MIN_FREE_BYTES = 512 * MiB
FIRST_CHECK_DELAY_S = 30.0                # after service start (boot networking; never in the start path)
PUBLISH_RECHECK_S = 6 * 3600.0            # the current month is not out yet
MONTHLY_CHECK_OFFSET_S = 3 * 3600.0       # 03:00 UTC on the 1st (DB-IP publishes ~01:40 UTC)
MONTHLY_JITTER_S = 6 * 3600.0
RETRY_BACKOFF_S = (60.0, 300.0, 900.0, 3600.0, 21600.0)
MIN_CHECK_INTERVAL_S = 60.0               # run_check() always leaves the next check at least this far away
ERROR_WAIT_S = 60.0                       # the thread loop's pause after an unexpected exception
BIG_ATTEMPT_BYTES = 1 * MiB               # a failed attempt that received more than this counts against the month budget
MAX_BIG_FAILURES_PER_MONTH = 3
REPLACE_RETRY_S = (0.25, 0.5, 1.0, 2.0, 4.0)   # os.replace / open retries while antivirus holds a fresh file
PREWARM_CHUNK = 1 * MiB
MAX_WAIT_S = 3600.0                       # the loop re-evaluates at least hourly (clock jumps)
MAX_SCHEDULE_AHEAD_S = 40 * 86400.0
PROGRESS_EVENT_S = 2.0
STOP_JOIN_S = 0.8                         # below the engine's 1.0 s share (§5.3)
THREAD_NAME = "tnt-geoip"
LOOKUP_CACHE_MAX = 2048
NOT_PUBLISHED_STATUSES = (404, 410)       # 403/429 are errors, never "not published yet"
VERIFY_SAMPLES = 256
LOAD_VERIFY_SAMPLES = 16
OFFLINE_ENV = "TNT_GEOIP_OFFLINE"         # when set (tests/conftest.py), http_open refuses every non-loopback host
PAUSE_SUFFIX = " · paused until a newer month or Retry"
USER_AGENT = f"TNT/{__version__} (+https://github.com/rhuntertec/TNT)"
ATTRIBUTION_TEXT = "IP Geolocation by DB-IP"
ATTRIBUTION_URL = "https://db-ip.com"
LICENCE_URL = "https://creativecommons.org/licenses/by/4.0/"
STATES = ("disabled", "starting", "downloading", "ready", "error")
STATUS_KEYS = ("enabled", "state", "available", "month", "bytes", "installed_ts", "checked_ts",
               "next_check_ts", "download", "error")
DOWNLOAD_KEYS = ("month", "file", "phase", "received", "total")
GEO_KEYS = ("ip", "place", "place_full", "city", "region", "region_code", "country", "country_code",
            "lat", "lon", "asn", "as_org", "isp", "month")
LOCATION_KEYS = ("text", "source", "hint", "db_text", "asn", "as_org")
DIAG_KEYS = ("available", "status", "files")
VERIFY_PROBES = {
    "city": {"present": ("8.8.8.8", "1.1.1.1"), "absent": ("10.0.0.1",)},
    "asn": {"present": ("8.8.8.8", "1.1.1.1"), "absent": ("10.0.0.1",)},
}
USPS_CODES: Dict[str, str] = {
    "Alabama": "AL", "Alaska": "AK", "Arizona": "AZ", "Arkansas": "AR", "California": "CA",
    "Colorado": "CO", "Connecticut": "CT", "Delaware": "DE", "District of Columbia": "DC",
    "Florida": "FL", "Georgia": "GA", "Hawaii": "HI", "Idaho": "ID", "Illinois": "IL",
    "Indiana": "IN", "Iowa": "IA", "Kansas": "KS", "Kentucky": "KY", "Louisiana": "LA",
    "Maine": "ME", "Maryland": "MD", "Massachusetts": "MA", "Michigan": "MI", "Minnesota": "MN",
    "Mississippi": "MS", "Missouri": "MO", "Montana": "MT", "Nebraska": "NE", "Nevada": "NV",
    "New Hampshire": "NH", "New Jersey": "NJ", "New Mexico": "NM", "New York": "NY",
    "North Carolina": "NC", "North Dakota": "ND", "Ohio": "OH", "Oklahoma": "OK", "Oregon": "OR",
    "Pennsylvania": "PA", "Rhode Island": "RI", "South Carolina": "SC", "South Dakota": "SD",
    "Tennessee": "TN", "Texas": "TX", "Utah": "UT", "Vermont": "VT", "Virginia": "VA",
    "Washington": "WA", "West Virginia": "WV", "Wisconsin": "WI", "Wyoming": "WY",
}
CA_PROVINCE_CODES = {"Alberta": "AB", "British Columbia": "BC", "Manitoba": "MB", "New Brunswick": "NB",
                     "Newfoundland and Labrador": "NL", "Northwest Territories": "NT", "Nova Scotia": "NS",
                     "Nunavut": "NU", "Ontario": "ON", "Prince Edward Island": "PE", "Quebec": "QC",
                     "Saskatchewan": "SK", "Yukon": "YT"}
US_TERRITORIES = ("PR", "GU", "VI", "AS", "MP")
ISP_SUFFIX_RE = re.compile(
    r"(?:,\s*|\s+)(?:LLC|L\.L\.C\.|Inc\.?|Incorporated|Corp\.?|Corporation|Co\.|Ltd\.?|Limited|LLP|LP|L\.P\.|PLC|"
    r"GmbH|AG|S\.A\.?|SA|B\.V\.?|BV|S\.p\.A\.|S\.r\.l\.|SAS|AB|AS|A/S|Oy|Pty\.?\s+Ltd\.?)$", re.IGNORECASE)
DBA_RE = re.compile(r"\s+d/?b/?a\s+", re.IGNORECASE)
SKIP_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "fe80::/10", "fc00::/7", "ff00::/8"))
# deliberately NOT ipaddress.is_private/is_global: the documentation ranges stay look-up-able (tests; the real data has no record for them)
# every network in tnt.traceroute._LAN_V4/_LAN_V6 lies inside one of these (checked by the mock parity test)

_MAX_TEXT = 200
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_REDIRECT_BODY_MAX = 64 * 1024
_MONTH_RE = re.compile(r"^(\d{4})-(\d{2})$")
_CITY_SUFFIX_RE = re.compile(r"\s*[\(\[].*$")

IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class GeoIpError(Exception):
    """Base; str(exc) is the user-facing status text (<= 200 chars, never an IP)."""


class DownloadError(GeoIpError):
    """A download failed (HTTP status, size cap, stall, cut short, not gzip, disk space, redirect)."""


class VerifyError(GeoIpError):
    """A downloaded month's data failed its check: pauses that month (§4.5.3)."""


class _Aborted(Exception):
    """Internal: stop/disable interrupted a check; never recorded as a failure."""


# --------------------------------------------------------------------------- pure helpers
def _cut(text: str, limit: int = _MAX_TEXT) -> str:
    return text if len(text) <= limit else text[:limit]


def month_of(ts: float) -> str:
    """UTC "YYYY-MM" of an epoch timestamp."""
    try:
        tm = time.gmtime(float(ts))
    except (TypeError, ValueError, OverflowError, OSError):
        tm = time.gmtime(0)
    return f"{tm.tm_year:04d}-{tm.tm_mon:02d}"


def _month_parts(month: object) -> Tuple[int, int]:
    m = _MONTH_RE.match(month) if isinstance(month, str) else None
    if m is None or not 1 <= int(m.group(2)) <= 12:
        raise ValueError(f"not a month: {month!r}")
    return int(m.group(1)), int(m.group(2))


def previous_month(month: str) -> str:
    """"2026-01" -> "2025-12"; ValueError on a bad month."""
    year, mon = _month_parts(month)
    return f"{year - 1:04d}-12" if mon == 1 else f"{year:04d}-{mon - 1:02d}"


def next_month_start(month: str) -> float:
    """Epoch of 00:00:00 UTC on the 1st of the month after ``month``; ValueError on a bad month."""
    year, mon = _month_parts(month)
    year, mon = (year + 1, 1) if mon == 12 else (year, mon + 1)
    return float(calendar.timegm((year, mon, 1, 0, 0, 0, 0, 0, 0)))


def valid_month(month: object) -> bool:
    """"YYYY-MM" with 1 <= MM <= 12."""
    try:
        _month_parts(month)
        return True
    except ValueError:
        return False


def file_url(kind: str, month: str) -> str:
    return BASE_URL + f"dbip-{kind}-lite-{month}.mmdb.gz"


def local_name(kind: str, month: str, n: int = 0) -> str:
    """"dbip-city-lite-2026-09.mmdb"; n > 0 -> "dbip-city-lite-2026-09.1.mmdb"."""
    return f"dbip-{kind}-lite-{month}.{n}.mmdb" if n > 0 else f"dbip-{kind}-lite-{month}.mmdb"


def backoff_s(failures: int) -> float:
    """The wait after ``failures`` failed checks in a row (0.0 for none)."""
    if not isinstance(failures, int) or failures <= 0:
        return 0.0
    return RETRY_BACKOFF_S[min(failures, len(RETRY_BACKOFF_S)) - 1]


def normalize_ip(ip: object) -> Optional[IpAddress]:
    """An address object for a str/ipaddress input (spaces, [brackets] and %scope removed, IPv4-mapped IPv6 as
    IPv4), or None for anything invalid."""
    try:
        if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            text = str(ip)
        elif isinstance(ip, str):
            text = ip.strip()
        else:
            return None
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        addr = ipaddress.ip_address(text.split("%", 1)[0].strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _skipped(addr: IpAddress) -> bool:
    return any(addr in net for net in SKIP_NETWORKS)


def is_public_candidate(ip: object) -> bool:
    """A valid address outside SKIP_NETWORKS (LAN, CGNAT, link-local, loopback, multicast, reserved)."""
    addr = normalize_ip(ip)
    return addr is not None and not _skipped(addr)


def host_text(host: object) -> str:
    """The lower-cased host name for messages; "another site" for None, "" or an IP literal."""
    if not isinstance(host, str):
        return "another site"
    text = host.strip().strip("[]").lower()
    if not text or normalize_ip(text) is not None:
        return "another site"
    return text


def friendly_error(exc: BaseException, host: str) -> str:
    """Plain-language status text for an exception met while talking to ``host`` (already host_text'ed)."""
    if isinstance(exc, GeoIpError):
        text = str(exc)
    elif isinstance(exc, socket.gaierror):
        text = f"could not look up {host} (no DNS or no internet)"
    elif isinstance(exc, ssl.SSLCertVerificationError):
        text = (f"the certificate of {host} could not be verified "
                f"(TLS inspection or a missing Windows root certificate)")
    elif isinstance(exc, TimeoutError):
        text = f"{host} did not answer in time (a proxy may be required)"
    elif isinstance(exc, ConnectionRefusedError):
        text = f"the connection to {host} was refused (a firewall or proxy may be blocking it)"
    elif isinstance(exc, (ConnectionResetError, ConnectionAbortedError)):
        text = f"the connection to {host} was closed (a firewall or proxy may be blocking it)"
    elif isinstance(exc, ssl.SSLError):
        text = f"TLS error with {host}: {getattr(exc, 'reason', None) or type(exc).__name__}"
    else:
        text = f"{type(exc).__name__}: {exc}"
    return _cut(text)


def clean_text(s: object) -> str:
    """Whitespace collapsed, a trailing U+FFFD (a name DB-IP cut inside a character) removed; "" for non-str."""
    if not isinstance(s, str):
        return ""
    return " ".join(s.split()).rstrip("�").rstrip()


def _dig(value: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _coord(value: object) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return round(float(value), 4)


def place_parts(city_record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """{"city","city_full","region","region_code","country","country_code","lat","lon"} of a DB-IP city record."""
    rec = city_record if isinstance(city_record, dict) else {}
    city_full = clean_text(_dig(rec, "city", "names", "en")) or None
    city = None
    if city_full:
        city = clean_text(_CITY_SUFFIX_RE.sub("", city_full)) or city_full
    raw_cc = _dig(rec, "country", "iso_code")
    cc_upper = raw_cc.upper() if isinstance(raw_cc, str) else None
    country_code = cc_upper if cc_upper is not None and len(cc_upper) == 2 and cc_upper != "ZZ" else None
    country = None if cc_upper == "ZZ" else (clean_text(_dig(rec, "country", "names", "en")) or None)
    region = None
    subdivisions = rec.get("subdivisions")
    if isinstance(subdivisions, list) and subdivisions and isinstance(subdivisions[0], dict):
        region = clean_text(_dig(subdivisions[0], "names", "en")) or None
    if country_code == "US":
        region_code = USPS_CODES.get(region) if region else None
    elif country_code == "CA":
        region_code = CA_PROVINCE_CODES.get(region) if region else None
    elif country_code in US_TERRITORIES:
        region_code = country_code
    else:
        region_code = None
    if country_code == "US" and region_code == "DC" and city == "Washington D.C.":
        city = "Washington"              # the router-name hint says "Washington, DC"
    location = rec.get("location") if isinstance(rec.get("location"), dict) else {}
    return {"city": city, "city_full": city_full, "region": region, "region_code": region_code,
            "country": country, "country_code": country_code,
            "lat": _coord(location.get("latitude")), "lon": _coord(location.get("longitude"))}


def _dedupe(parts: List[Optional[str]]) -> List[str]:
    """Keep a part only when it is non-empty and neither equals a kept part nor one of its comma pieces."""
    kept: List[str] = []
    for part in parts:
        if not part:
            continue
        folded = part.casefold()
        if any(folded == k.casefold() or folded in (p.strip().casefold() for p in k.split(",")) for k in kept):
            continue
        kept.append(part)
    return kept


def place_text(parts: Dict[str, Any]) -> Optional[str]:
    """"City, ST" for the US/CA/US territories, "City, Country" elsewhere; see §4.3."""
    city = parts.get("city")
    cc = parts.get("country_code")
    if cc == "US":
        st = parts.get("region_code") or "United States"
    elif cc in US_TERRITORIES:
        st = cc
    elif cc == "CA":
        st = parts.get("region_code") or "Canada"
    else:
        st = parts.get("country")
    if city:
        if not st or st.casefold() == city.casefold() or st.casefold() == city.split(",")[-1].strip().casefold():
            return city
        return f"{city}, {st}"
    return ", ".join(_dedupe([parts.get("region"), parts.get("country")])) or None


def place_full_text(parts: Dict[str, Any]) -> Optional[str]:
    """"Richardson (Canyon Creek), Texas, United States": the full database names, deduplicated."""
    return ", ".join(_dedupe([parts.get("city_full"), parts.get("region"), parts.get("country")])) or None


def isp_text(asn: object, org: object) -> Optional[str]:
    """The ISP display name: the AS organisation without legal suffixes ("Example Transit, Inc." -> "Example
    Transit"), "AS64500" without a name, None without either."""
    raw = clean_text(org)
    if not raw:
        return f"AS{asn}" if type(asn) is int else None
    if len(str(org).encode("utf-8", "replace")) >= 80:
        return raw + "…"                 # DB-IP cut the name at 80 UTF-8 bytes: keep what is there
    pieces = DBA_RE.split(raw)
    if len(pieces) > 1 and pieces[-1].strip():
        raw = pieces[-1].strip()
    for _ in range(2):
        stripped = ISP_SUFFIX_RE.sub("", raw).rstrip(" ,")
        if not stripped:
            break
        raw = stripped
    return raw


def build_geo(ip: str, city_record: Optional[Dict[str, Any]], asn_record: Optional[Dict[str, Any]],
              month: Optional[str]) -> Optional[Dict[str, Any]]:
    """The GEO dict (exactly GEO_KEYS) for one address, or None when nothing is known."""
    if city_record is None and asn_record is None:
        return None
    parts = place_parts(city_record)
    place = place_text(parts)
    asn_value = _dig(asn_record, "autonomous_system_number")
    asn = asn_value if type(asn_value) is int else None
    org = _dig(asn_record, "autonomous_system_organization")
    if place is None and asn is None:
        return None
    return {"ip": ip, "place": place, "place_full": place_full_text(parts), "city": parts["city"],
            "region": parts["region"], "region_code": parts["region_code"], "country": parts["country"],
            "country_code": parts["country_code"], "lat": parts["lat"], "lon": parts["lon"], "asn": asn,
            "as_org": clean_text(org) or None, "isp": isp_text(asn, org), "month": month}


# --------------------------------------------------------------------------- HTTP download seam
class HttpResponse:
    """One GET response: ``readinto`` streams the body; ``abort()`` shuts the socket from another thread."""

    def __init__(self, conn: http.client.HTTPConnection, resp: http.client.HTTPResponse, sock: Any, url: str,
                 host: str) -> None:
        self._conn = conn
        self._resp = resp
        self._sock = sock
        self._closed = False
        self.status: int = resp.status
        self.headers: Dict[str, str] = {str(k).lower(): v for k, v in resp.getheaders()}
        self.url = url
        self.host = host

    def readinto(self, buf: Union[bytearray, memoryview]) -> int:
        # read1: at most one recv per call, so the stall rule sees a trickle (a buffered readinto waits to fill buf)
        data = self._resp.read1(len(buf))
        n = len(data)
        buf[:n] = data
        return n

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for closer in (self._resp.close, self._conn.close):
            try:
                closer()
            except Exception:  # noqa: BLE001
                pass

    def abort(self) -> None:
        sock, self._sock = self._sock, None
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:  # noqa: BLE001 - already closed or never connected
            pass
        # On Windows a shutdown does not wake a recv blocked in another thread (checked on 3.12); closing the handle
        # does. detach() first, so the response's own close() later never closes a handle number twice.
        try:
            fd = socket.socket.detach(sock)
            if fd >= 0:
                socket.close(fd)
        except Exception:  # noqa: BLE001
            pass


def _allowed_initial(scheme: str, host: str) -> bool:
    return bool(host) and (scheme == "https" or (scheme == "http" and host in LOOPBACK_HOSTS))


def http_open(url: str, *, timeout: float = SOCKET_TIMEOUT_S, headers: Optional[Dict[str, str]] = None,
              max_redirects: int = MAX_REDIRECTS) -> HttpResponse:
    """GET ``url`` (https, or http on loopback), following https redirects; any final status is returned unread."""
    parts = urlsplit(url)
    scheme, host = (parts.scheme or "").lower(), (parts.hostname or "").lower()
    if not _allowed_initial(scheme, host):
        raise ValueError(f"only https downloads are allowed (not {scheme or 'no scheme'} to {host_text(host)})")
    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close"}
    request_headers.update(headers or {})
    current, redirects = url, 0
    while True:
        if os.environ.get(OFFLINE_ENV) and host not in LOOPBACK_HOSTS:
            raise OSError("network access is disabled (TNT_GEOIP_OFFLINE)")
        if scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                host, parts.port or 443, timeout=timeout, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(host, parts.port or 80, timeout=timeout)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        try:
            conn.request("GET", path, headers=request_headers)
            sock = conn.sock          # getresponse() may set conn.sock = None; the response keeps the socket open
            resp = conn.getresponse()
        except BaseException:  # noqa: BLE001 - closed and re-raised
            conn.close()
            raise
        if resp.status not in _REDIRECT_STATUSES:
            return HttpResponse(conn, resp, sock, current, host_text(host))
        try:
            resp.read(_REDIRECT_BODY_MAX)
        except Exception:  # noqa: BLE001 - the body of a redirect is never used
            pass
        location = resp.getheader("Location")
        resp.close()
        conn.close()
        if not location:
            raise DownloadError(f"HTTP {resp.status} from {host_text(host)}")
        target = urljoin(current, location.strip())
        tparts = urlsplit(target)
        tscheme, thost = (tparts.scheme or "").lower(), (tparts.hostname or "").lower()
        if not ((tscheme == "https" and thost)
                or (tscheme == "http" and host in LOOPBACK_HOSTS and thost in LOOPBACK_HOSTS)):
            raise DownloadError(f"refused a redirect to {host_text(thost)}")
        redirects += 1
        if redirects > max_redirects:
            raise DownloadError(f"too many redirects from {host_text(host)}")
        log.info("IP location download redirected to %s", host_text(thost))
        current, parts, scheme, host = target, tparts, tscheme, thost


_urlopen = http_open     # THE SEAM: GeoIpManager calls `_urlopen(url, timeout=SOCKET_TIMEOUT_S)` via a module-global
                         # lookup at call time unless a `urlopen` was injected; tests/conftest.py replaces it (§9.1)


def _abort_response(resp: Any) -> None:
    abort = getattr(resp, "abort", None)
    if callable(abort):
        try:
            abort()
        except Exception:  # noqa: BLE001
            pass


def _close_readers(data: Any) -> None:
    readers = getattr(data, "readers", None)
    for reader in (readers or {}).values():
        try:
            reader.close()
        except Exception:  # noqa: BLE001
            pass


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _write_json_atomic(path: Path, obj: Any) -> None:
    """``path.tmp``, flush, fsync, os.replace; raises OSError (the tmp file is removed)."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:  # noqa: BLE001 - cleaned up and re-raised
        _unlink(tmp)
        raise


def _parse_date(value: object) -> Optional[float]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return email.utils.parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


def _default_dir() -> Path:
    return importlib.import_module("tnt.paths").geoip_dir()


def _disk_free(path: str) -> int:
    return shutil.disk_usage(path).free


def _label(kind: str) -> str:
    return "ISP" if kind == "asn" else kind


def _os_reason(exc: BaseException) -> str:
    return getattr(exc, "strerror", None) or type(exc).__name__


# --------------------------------------------------------------------------- manager
class _Data(NamedTuple):
    readers: Optional[Dict[str, "mmdb.Reader"]]   # {"city": Reader, "asn": Reader} or None
    month: Optional[str]
    bytes: Optional[int]                          # city + asn file sizes
    installed_ts: Optional[float]
    generation: int


class GeoIpManager:
    """Keeps the DB-IP Lite city + ASN data current on its own thread and answers local lookups (§4.5)."""

    def __init__(self, config: Any, bus: Any = None, *,
                 public_ip_fn: Optional[Callable[[], Optional[str]]] = None,
                 dir_fn: Optional[Callable[[], Union[str, os.PathLike]]] = None,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 urlopen: Optional[Callable[..., Any]] = None,
                 verify_probes: Optional[Dict[str, Dict[str, Tuple[str, ...]]]] = None,
                 caps: Optional[Dict[str, Tuple[int, int]]] = None,
                 first_check_delay_s: float = FIRST_CHECK_DELAY_S,
                 jitter_s: Optional[float] = None,
                 disk_free_fn: Optional[Callable[[str], int]] = None) -> None:
        self.config = config
        self.bus = bus
        self._public_ip_fn = public_ip_fn
        self._dir_fn = dir_fn if dir_fn is not None else _default_dir
        self._clock = clock
        self._monotonic = monotonic
        self._injected_urlopen = urlopen
        self._probes = verify_probes if verify_probes is not None else VERIFY_PROBES
        self._caps = dict(CAPS, **(caps or {}))
        self._first_check_delay_s = float(first_check_delay_s)
        self._jitter_s = float(jitter_s) if jitter_s is not None else random.uniform(0.0, MONTHLY_JITTER_S)
        self._disk_free_fn = disk_free_fn if disk_free_fn is not None else _disk_free

        # installed-data snapshot, lookup cache and _closed: _readers_lock (never held together with _lock)
        self._readers_lock = threading.Lock()
        self._data = _Data(None, None, None, None, 0)
        self._cache: Dict[Tuple[int, str], Optional[Dict[str, Any]]] = {}
        self._closed = False

        # everything else: _lock
        self._lock = threading.RLock()
        self._state = "starting" if self.enabled() else "disabled"
        self._error: Optional[str] = None
        self._checked_ts: Optional[float] = None
        self._next_check_ts: Optional[float] = None
        self._download: Optional[Dict[str, Any]] = None
        self._failures = 0
        self._last_attempt_ts: Optional[float] = None
        self._months: Dict[str, Dict[str, Any]] = {}
        self._active: Optional[bool] = None
        self._abort_seq = 0
        self._resp: Any = None
        self._first_activation = True
        self._manifest_dirty = False
        self._state_file_dirty = False

        self._stop = threading.Event()
        self._abort = threading.Event()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._remove_listener: Optional[Callable[[], None]] = None
        self._progress_at = 0.0

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        """Start the ``tnt-geoip`` thread (idempotent, never blocks, never a second thread)."""
        thread = self._thread
        if thread is not None and thread.is_alive():
            if self._stop.is_set():
                log.warning("IP location thread from the previous start is still finishing; not starting another")
            return
        self._stop.clear()
        self._abort.clear()
        with self._readers_lock:
            self._closed = False
        with self._lock:
            self._active = None
            self._first_activation = True
        add_listener = getattr(self.config, "add_listener", None)
        if callable(add_listener) and self._remove_listener is None:
            try:
                self._remove_listener = add_listener(self._on_config)
            except Exception:  # noqa: BLE001
                self._remove_listener = None
        self._thread = threading.Thread(target=self._run, name=THREAD_NAME, daemon=True)
        self._thread.start()
        try:
            folder: Any = self._dir_fn()
        except Exception:  # noqa: BLE001
            folder = "unknown"
        log.info("IP location started (data folder %s)", folder)

    def stop(self) -> None:
        """Abort any download, unload the data, then join the thread for STOP_JOIN_S (idempotent)."""
        self._stop.set()
        with self._lock:
            self._abort_seq += 1
            resp = self._resp
        self._abort.set()
        self._wake.set()
        _abort_response(resp)
        _close_readers(self._unload(closed=True))
        remove, self._remove_listener = self._remove_listener, None
        if remove is not None:
            try:
                remove()
            except Exception:  # noqa: BLE001
                pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(STOP_JOIN_S)
        log.info("IP location stopped")
        if thread is not None and thread.is_alive():
            log.warning("IP location thread is still finishing a download step")

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    # ------------------------------------------------------------------ state
    def enabled(self) -> bool:
        try:
            return bool(self.config.get("geoip.enabled", True))
        except Exception:  # noqa: BLE001
            return True

    @property
    def available(self) -> bool:
        return self._data.readers is not None

    @property
    def generation(self) -> int:
        return self._data.generation

    def status(self) -> Dict[str, Any]:
        """STATUS (exactly STATUS_KEYS): cheap, no I/O, never raises."""
        try:
            en = self.enabled()
            d = self._data
            if not en:
                out = dict.fromkeys(STATUS_KEYS)
                out.update({"enabled": False, "state": "disabled", "available": False})
                return out
            with self._lock:
                return {"enabled": True,
                        "state": "starting" if self._state == "disabled" else self._state,
                        "available": d.readers is not None, "month": d.month, "bytes": d.bytes,
                        "installed_ts": d.installed_ts, "checked_ts": self._checked_ts,
                        "next_check_ts": self._next_check_ts,
                        "download": dict(self._download) if self._download is not None else None,
                        "error": self._error}
        except Exception:  # noqa: BLE001
            out = dict.fromkeys(STATUS_KEYS)
            out.update({"enabled": True, "state": "error", "available": False, "error": "status unavailable"})
            return out

    def files(self) -> List[Dict[str, Any]]:
        readers = self._data.readers
        if readers is None:
            return []
        return [{"name": os.path.basename(readers[kind].path), "bytes": readers[kind].size}
                for kind in FILE_KINDS if kind in readers]

    def _publish(self) -> None:
        bus = self.bus
        if bus is None:
            return
        try:
            bus.publish("geoip.state", self.status())
        except Exception:  # noqa: BLE001
            log.debug("geoip.state publish failed", exc_info=True)

    def _aborted(self, seq0: int) -> bool:
        # lock-free reads: Events are thread-safe and an int attribute read is atomic
        return self._stop.is_set() or self._abort.is_set() or self._abort_seq != seq0

    def _unload(self, closed: bool) -> _Data:
        with self._readers_lock:
            old = self._data
            self._data = _Data(None, None, None, None, old.generation + 1)
            self._cache.clear()
            if closed:
                self._closed = True
        return old

    def _folder(self) -> Path:
        return Path(self._dir_fn())

    # ------------------------------------------------------------------ enable / disable
    def _on_config(self, snapshot: Any, changed: Any) -> None:
        try:
            # "geoip" alone: a config without the section yet reports the whole section as changed
            if not any(str(key) == "geoip" or str(key).startswith("geoip.") for key in changed):
                return
            if not self.enabled():
                with self._lock:
                    self._abort_seq += 1
                    resp = self._resp
                self._abort.set()
                _abort_response(resp)
            elif not self._stop.is_set():
                self._abort.clear()          # a quick off/on must not leave a stale abort behind
            self._wake.set()
        except Exception:  # noqa: BLE001
            pass

    def apply_enabled(self) -> str:
        """Apply the setting now: "disabled" (T7), "enabled" (T1) or "unchanged". Never raises."""
        try:
            en = self.enabled()
            with self._lock:
                active = self._active
            if en:
                if active is True:
                    if not self._stop.is_set() and self._abort.is_set():
                        self._abort.clear()      # a stale abort from interleaved off/on listeners must not stick
                    return "unchanged"
                self._switch_on()
                return "enabled"
            if active is False:
                return "unchanged"
            self._switch_off()
            return "disabled"
        except Exception:  # noqa: BLE001
            log.debug("IP location: applying the setting failed", exc_info=True)
            return "unchanged"

    def _switch_on(self) -> None:
        """T1."""
        if not self._stop.is_set():
            self._abort.clear()
        with self._lock:
            memory_is_newer = self._state_file_dirty
        if not memory_is_newer:
            failures, last_attempt_ts, months = self._read_state_file()
            with self._lock:
                self._failures, self._last_attempt_ts, self._months = failures, last_attempt_ts, months
        self.cleanup()
        self.load_installed()
        available = self._data.readers is not None
        now = self._clock()
        with self._lock:
            first = self._first_activation
            self._state = "ready" if available else "starting"
            self._error = None
            base = now + (self._first_check_delay_s if first else 0.0)
            last = self._last_attempt_ts
            if not available and self._failures > 0 and last is not None and last <= now:
                self._next_check_ts = max(base, last + backoff_s(self._failures))
            else:
                self._next_check_ts = base
            self._first_activation = False
            self._active = True
        if not first:
            log.info("IP location switched on")
        self._publish()

    def _switch_off(self) -> None:
        """T7: abort, unload (the files stay on disk), state disabled."""
        with self._lock:
            self._abort_seq += 1
            resp = self._resp
        self._abort.set()
        _abort_response(resp)
        _close_readers(self._unload(closed=False))
        with self._lock:
            self._error = None
            self._download = None
            self._next_check_ts = None
            self._state = "disabled"
            self._active = False
        log.info("IP location switched off")
        self._publish()

    def check_now(self) -> bool:
        """Retry: clears the month budget and the failures and schedules a check now; False when switched off."""
        if not self.enabled():
            return False
        now = self._clock()
        with self._lock:
            self._months = {}
            self._failures = 0
            self._next_check_ts = now
            self._state_file_dirty = True
        self._wake.set()
        self._publish()
        return True

    # ------------------------------------------------------------------ thread
    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.clear()
            try:
                self._flush_dirty_files()
                self.apply_enabled()
                if self._stop.is_set():
                    break
                if not self.enabled():
                    self._wake.wait(MAX_WAIT_S)
                    continue
                now = self._clock()
                with self._lock:
                    nxt = self._next_check_ts
                if nxt is None or nxt - now > MAX_SCHEDULE_AHEAD_S:     # wall clock went back
                    with self._lock:
                        self._next_check_ts = now + PUBLISH_RECHECK_S
                    continue
                if now >= nxt:
                    self.run_check()
                    continue
                self._wake.wait(min(nxt - now, MAX_WAIT_S))
            except Exception as exc:  # noqa: BLE001
                log.exception("IP location thread error")
                try:
                    self._record_failure(exc, "download.db-ip.com")
                except Exception:  # noqa: BLE001
                    pass
                self._wake.wait(ERROR_WAIT_S)
        try:
            self._flush_dirty_files()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ checks
    def _paused(self, month: str) -> bool:
        with self._lock:
            entry = self._months.get(month)
        if not entry:
            return False
        return entry.get("big_failures", 0) >= MAX_BIG_FAILURES_PER_MONTH or bool(entry.get("verify_failed"))

    def run_check(self) -> str:
        """One check: "disabled" | "up_to_date" | "installed" | "not_published" | "paused" | "error"."""
        if not self.enabled():
            return "disabled"
        now = self._clock()
        cur = month_of(now)
        prev = previous_month(cur)
        inst = self._data.month
        monthly = next_month_start(cur) + MONTHLY_CHECK_OFFSET_S + self._jitter_s
        if inst is None:
            wanted = [cur, prev]
        elif inst < cur:
            wanted = [cur] + ([prev] if inst < prev else [])
        else:
            wanted = []
        outcome: Optional[str] = None
        try:
            if not wanted:
                with self._lock:
                    self._next_check_ts = monthly
                outcome = "up_to_date"
            elif all(self._paused(m) for m in wanted):
                self._paused_result(wanted[0], monthly)
                outcome = "paused"
            else:
                date_ts: Optional[float] = None
                for m in [m for m in wanted if not self._paused(m)]:
                    result, seen = self._install_month(m)
                    date_ts = seen if seen is not None else date_ts
                    if result == "installed":
                        with self._lock:
                            self._next_check_ts = monthly if m == cur else now + PUBLISH_RECHECK_S
                        outcome = "installed"
                        break
                if outcome is None and date_ts is not None:     # clock skew: the server's month may not be ours
                    sm = month_of(date_ts)
                    extra = [m for m in (sm, previous_month(sm))
                             if m not in wanted and (inst is None or m > inst) and not self._paused(m)]
                    log.debug("IP location: server month %s, local month %s", sm, cur)
                    for m in extra:
                        result, _seen = self._install_month(m)
                        if result == "installed":
                            with self._lock:
                                self._next_check_ts = now + PUBLISH_RECHECK_S
                            outcome = "installed"
                            break
                if outcome is None:
                    self._not_published(now, cur, prev, month_of(date_ts) if date_ts is not None else cur)
                    outcome = "not_published"
        except _Aborted:
            outcome = "disabled"
            available = self._data.readers is not None
            with self._lock:
                self._download = None
                if self._state == "downloading":
                    self._state = "ready" if available else "starting"
        except Exception as exc:  # noqa: BLE001
            self._record_failure(exc, "download.db-ip.com")
            outcome = "error"
        if outcome != "disabled":
            with self._lock:
                self._checked_ts = now
        if self.enabled():
            floor = self._clock() + MIN_CHECK_INTERVAL_S
            with self._lock:
                self._next_check_ts = max(self._next_check_ts or 0.0, floor)
        self._publish()
        return outcome

    def _record_failure(self, exc: BaseException, host: str) -> None:
        """T5."""
        text = friendly_error(exc, host)
        log.debug("IP location check failed: %r", exc)
        now = self._clock()
        available = self._data.readers is not None
        with self._lock:
            self._failures += 1
            self._last_attempt_ts = now
            self._error = text
            self._download = None
            self._state = "ready" if available else "error"
            wait = backoff_s(self._failures)
            self._next_check_ts = now + wait
            self._state_file_dirty = True
        log.warning("IP location data update failed: %s (next try in %d min)", text, max(1, round(wait / 60.0)))
        self._publish()

    def _not_published(self, now: float, cur: str, prev: str, ref_month: str) -> None:
        """T6: every candidate answered 404/410."""
        d = self._data
        if d.readers is not None:
            notice = f"no newer data from DB-IP since {d.month}" if d.month and d.month < previous_month(ref_month) else None
            with self._lock:
                self._state = "ready"
                self._download = None
                self._error = notice
                self._next_check_ts = now + PUBLISH_RECHECK_S
            log.info("IP location: DB-IP has not published %s yet; checking again in 6 h", cur)
        else:
            text = f"DB-IP has no data for {cur} or {prev} yet"
            with self._lock:
                self._failures += 1
                self._last_attempt_ts = now
                self._state = "error"
                self._download = None
                self._error = text
                wait = backoff_s(self._failures)
                self._next_check_ts = now + wait
                self._state_file_dirty = True
            log.warning("IP location data update failed: %s (next try in %d min)", text, max(1, round(wait / 60.0)))
        self._publish()

    def _paused_result(self, month: str, monthly: float) -> None:
        """T6b: every wanted month is paused."""
        available = self._data.readers is not None
        with self._lock:
            base = self._error or f"the {month} data could not be installed"
            if base.endswith(PAUSE_SUFFIX):
                base = base[:-len(PAUSE_SUFFIX)]
            self._error = base[:_MAX_TEXT - len(PAUSE_SUFFIX)] + PAUSE_SUFFIX
            self._state = "ready" if available else "error"
            self._download = None
            self._next_check_ts = monthly
        self._publish()

    def _charge_month(self, month: str, received: int, verify_failed: bool) -> None:
        """The per-month budget after a failed attempt (§4.5.3)."""
        if received <= BIG_ATTEMPT_BYTES and not verify_failed:
            return
        was_paused = self._paused(month)
        with self._lock:
            entry = self._months.setdefault(month, {"big_failures": 0, "verify_failed": False})
            if received > BIG_ATTEMPT_BYTES:
                entry["big_failures"] = int(entry.get("big_failures", 0)) + 1
            if verify_failed:
                entry["verify_failed"] = True
            self._state_file_dirty = True
        if not was_paused and self._paused(month):
            log.warning("IP location data update paused for %s after repeated failures (Retry in Settings)", month)

    # ------------------------------------------------------------------ download
    def _install_month(self, month: str) -> Tuple[str, Optional[float]]:
        """Download, verify and install one month: ("installed" | "not_published", server Date or None)."""
        with self._lock:
            seq0 = self._abort_seq
        ctx: Dict[str, Any] = {"received": 0, "host": host_text(urlsplit(file_url("asn", month)).hostname),
                               "date_ts": None}
        folder: Optional[Path] = None
        try:
            folder = self._folder()
            folder.mkdir(parents=True, exist_ok=True)
            if self._disk_free_fn(str(folder)) < MIN_FREE_BYTES:
                raise DownloadError("not enough free disk space (512 MB needed)")
            for index, kind in enumerate(DOWNLOAD_ORDER):
                if not self._fetch(kind, month, folder, seq0, ctx, first=index == 0):
                    self._delete_parts(folder, month)
                    return "not_published", ctx["date_ts"]
            self._verify_and_install(month, folder, seq0)
            return "installed", ctx["date_ts"]
        except _Aborted:
            self._delete_parts(folder, month)
            raise
        except Exception as exc:  # noqa: BLE001
            self._delete_parts(folder, month)
            if self._aborted(seq0):
                raise _Aborted() from None       # the error an abort causes is never a failure
            self._charge_month(month, ctx["received"], isinstance(exc, VerifyError))
            if isinstance(exc, GeoIpError):
                raise
            log.debug("IP location download error: %r", exc)
            raise DownloadError(friendly_error(exc, ctx["host"])) from exc

    def _fetch(self, kind: str, month: str, folder: Path, seq0: int, ctx: Dict[str, Any], first: bool) -> bool:
        """Stream one file into its .part; False when it is not published (404/410)."""
        if self._aborted(seq0):
            raise _Aborted()
        url = file_url(kind, month)
        opener = self._injected_urlopen if self._injected_urlopen is not None else _urlopen
        resp = opener(url, timeout=SOCKET_TIMEOUT_S)
        with self._lock:
            self._resp = resp
        try:
            if self._aborted(seq0):
                _abort_response(resp)
                raise _Aborted()
            host = getattr(resp, "host", None) or host_text(urlsplit(url).hostname)
            ctx["host"] = host
            headers = {str(k).lower(): v for k, v in (getattr(resp, "headers", None) or {}).items()}
            date_ts = _parse_date(headers.get("date"))
            if date_ts is not None:
                ctx["date_ts"] = date_ts
            status = int(resp.status)
            if status in NOT_PUBLISHED_STATUSES:
                return False
            if status == 403:
                raise DownloadError(f"{host} refused the download (HTTP 403): a firewall or proxy may be blocking it")
            if status != 200:
                raise DownloadError(f"HTTP {status} from {host}")
            total: Optional[int] = None
            try:
                total = int(str(headers.get("content-length", "")).strip())
                total = total if total >= 0 else None
            except ValueError:
                total = None
            if total is not None and total > self._caps[kind][0]:
                raise DownloadError(f"the {_label(kind)} download is larger than expected")
            with self._lock:
                if first:
                    self._state = "downloading"
                self._download = {"month": month, "file": kind, "phase": "download", "received": 0, "total": total}
            self._progress_at = time.monotonic()
            self._publish()
            self._stream(resp, kind, folder / (local_name(kind, month) + ".part"), total, seq0, ctx)
            return True
        finally:
            try:
                resp.close()
            except Exception:  # noqa: BLE001
                pass
            with self._lock:
                self._resp = None

    def _stream(self, resp: Any, kind: str, part: Path, total: Optional[int], seq0: int,
                ctx: Dict[str, Any]) -> None:
        label = _label(kind)
        cap_compressed, cap_decompressed = self._caps[kind]
        not_gzip = f"the {label} download is not valid gzip data"
        decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
        buf = bytearray(READ_CHUNK)
        received = produced = 0
        win_start, win_bytes = self._monotonic(), 0

        def unpack(data: bytes, f: Any) -> None:
            nonlocal produced
            while True:
                out = decomp.decompress(data, DECOMPRESS_STEP)
                if decomp.eof and (decomp.unused_data or decomp.unconsumed_tail):
                    raise DownloadError(not_gzip)
                produced += len(out)
                if produced > cap_decompressed:
                    raise DownloadError(f"the {label} data is larger than expected")
                if out:
                    f.write(out)
                data = decomp.unconsumed_tail
                if not data:
                    return

        try:
            with open(part, "wb") as f:
                while True:
                    n = resp.readinto(buf)
                    if self._aborted(seq0):
                        raise _Aborted()          # a socket shut by abort() reads 0 or raises
                    if not n:
                        break
                    received += n
                    ctx["received"] += n
                    win_bytes += n
                    now = self._monotonic()
                    if now - win_start >= STALL_WINDOW_S:
                        if win_bytes < STALL_MIN_BYTES:
                            raise DownloadError(f"the {label} download stalled (less than 1 MB in 5 min)")
                        win_start, win_bytes = now, 0
                    if received > cap_compressed:
                        raise DownloadError(f"the {label} download is larger than expected")
                    if decomp.eof:
                        raise DownloadError(not_gzip)      # data after the gzip member
                    unpack(bytes(buf[:n]), f)
                    with self._lock:
                        if self._download is not None:
                            self._download["received"] = received
                    tick = time.monotonic()
                    if tick - self._progress_at >= PROGRESS_EVENT_S:
                        self._progress_at = tick
                        self._publish()
                tail = decomp.flush()
                produced += len(tail)
                if produced > cap_decompressed:
                    raise DownloadError(f"the {label} data is larger than expected")
                if tail:
                    f.write(tail)
                f.flush()
                os.fsync(f.fileno())
                if not decomp.eof or (total is not None and total != received):
                    raise DownloadError(f"the {label} download was cut short")
        except zlib.error:
            raise DownloadError(not_gzip) from None

    def _delete_parts(self, folder: Optional[Path], month: str) -> None:
        if folder is None:
            return
        for kind in FILE_KINDS:
            _unlink(folder / (local_name(kind, month) + ".part"))

    # ------------------------------------------------------------------ verify and install
    def _verify_and_install(self, month: str, folder: Path, seq0: int) -> None:
        """§4.5.4 steps 3-12 on the two .part files."""
        with self._lock:
            if self._download is not None:
                self._download["phase"] = "verify"
        self._publish()
        if self._aborted(seq0):
            raise _Aborted()
        parts = {kind: folder / (local_name(kind, month) + ".part") for kind in FILE_KINDS}
        for kind in FILE_KINDS:
            self._verify_part(parts[kind], kind, month)
            if self._aborted(seq0):
                raise _Aborted()
        finals = {kind: self._move_into_place(parts[kind], folder, kind, month, seq0) for kind in FILE_KINDS}
        new = self._open_finals(finals, seq0)
        size = sum(reader.size for reader in new.values())
        ts = self._clock()
        with self._readers_lock:
            refused = self._closed or self._aborted(seq0)
            old = self._data
            if not refused:
                self._data = _Data(new, month, size, ts, old.generation + 1)
                self._cache.clear()
        if refused:
            _close_readers(_Data(new, None, None, None, 0))
            raise _Aborted()                      # the final files stay until a later cleanup()
        _close_readers(old)
        with self._lock:
            self._state = "ready"
            self._error = None
            self._failures = 0
            self._download = None
            self._months.pop(month, None)
            self._state_file_dirty = True
        log.info("IP location data %s installed (city %.1f MiB, ISP %.1f MiB)", month,
                 new["city"].size / MiB, new["asn"].size / MiB)
        self._publish()
        self._save_manifest()
        self._save_state_file()
        self.cleanup()

    def _verify_part(self, part: Path, kind: str, month: str) -> None:
        label = _label(kind)

        def failed(detail: str) -> VerifyError:
            return VerifyError(_cut(f"the downloaded {label} data failed its check: {detail}"))

        try:
            reader = mmdb.Reader(part)
        except mmdb.MmdbError as exc:
            raise failed(str(exc)) from None
        try:
            if reader.ip_version != 6:
                raise failed("it is not an IPv6 database")
            if not reader.database_type.startswith(DB_TYPE_PREFIX[kind]):
                raise failed(f"unexpected database type {reader.database_type[:40]!r}")
            built = month_of(reader.build_epoch)
            if built not in (month, previous_month(month)):
                raise failed(f"it was built in {built}, not for {month}")
            reader.self_check(VERIFY_SAMPLES)
            probes = self._probes.get(kind) or {}
            for ip in probes.get("present", ()):
                rec = reader.get(ip)
                if not isinstance(rec, dict):
                    raise failed("a well-known address has no record")
                if kind == "city":
                    code = _dig(rec, "country", "iso_code")
                    if not (isinstance(code, str) and len(code) == 2):
                        raise failed("a well-known address has no country")
                elif type(rec.get("autonomous_system_number")) is not int:
                    raise failed("a well-known address has no AS number")
            for ip in probes.get("absent", ()):
                if reader.get(ip) is not None:
                    raise failed("a private address has a record")
        except mmdb.MmdbError as exc:
            raise failed(str(exc)) from None
        finally:
            reader.close()                        # Windows cannot rename a mapped file

    def _move_into_place(self, part: Path, folder: Path, kind: str, month: str, seq0: int) -> Path:
        """os.replace the verified part to the first free versioned name, retrying through antivirus locks."""
        text = f"could not move the downloaded {_label(kind)} data into place"
        mapped = {os.path.normcase(os.path.abspath(r.path)) for r in (self._data.readers or {}).values()}
        last: Optional[BaseException] = None
        for n in range(10):
            final = folder / local_name(kind, month, n)
            if os.path.normcase(os.path.abspath(final)) in mapped:
                continue
            attempt = 0
            while True:
                try:
                    os.replace(part, final)
                    return final
                except PermissionError as exc:
                    last = exc
                    if final.exists() and getattr(exc, "winerror", 5) == 5:
                        break                     # the destination itself is mapped: the next name at once
                    if attempt < len(REPLACE_RETRY_S):
                        self._abort.wait(REPLACE_RETRY_S[attempt])
                        attempt += 1
                        if self._aborted(seq0):
                            raise _Aborted() from None
                        continue
                    if final.exists():
                        break
                    raise GeoIpError(_cut(f"{text}: {_os_reason(exc)}")) from None
                except OSError as exc:
                    raise GeoIpError(_cut(f"{text}: {_os_reason(exc)}")) from None
        raise GeoIpError(_cut(f"{text}: {_os_reason(last) if last is not None else 'no free file name'}"))

    def _open_finals(self, finals: Dict[str, Path], seq0: int) -> Dict[str, "mmdb.Reader"]:
        new: Dict[str, mmdb.Reader] = {}
        kind = FILE_KINDS[0]
        try:
            for kind in FILE_KINDS:
                attempt = 0
                while True:
                    try:
                        new[kind] = mmdb.Reader(finals[kind])
                        break
                    except PermissionError:
                        if attempt >= len(REPLACE_RETRY_S):
                            raise
                        self._abort.wait(REPLACE_RETRY_S[attempt])
                        attempt += 1
                        if self._aborted(seq0):
                            raise _Aborted() from None
        except BaseException as exc:  # noqa: BLE001 - closes what opened, then converts or re-raises
            _close_readers(_Data(new, None, None, None, 0))
            if isinstance(exc, mmdb.MmdbError):
                raise VerifyError(_cut(f"the downloaded {_label(kind)} data failed its check: {exc}")) from None
            if isinstance(exc, OSError):
                raise GeoIpError(_cut(f"could not open the downloaded {_label(kind)} data: {_os_reason(exc)}")) from None
            raise
        return new

    def install_from_files(self, month: str, city_path: Union[str, os.PathLike],
                           asn_path: Union[str, os.PathLike]) -> None:
        """Install an uncompressed city/asn pair (copy -> .part -> verify -> install); raises GeoIpError."""
        if not valid_month(month):
            raise GeoIpError(f"not a valid month: {str(month)[:20]}")
        with self._lock:
            seq0 = self._abort_seq
        folder = self._folder()
        try:
            folder.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(city_path, folder / (local_name("city", month) + ".part"))
            shutil.copyfile(asn_path, folder / (local_name("asn", month) + ".part"))
            self._verify_and_install(month, folder, seq0)
        except _Aborted:
            self._delete_parts(folder, month)
            raise GeoIpError("the install was interrupted") from None
        except GeoIpError:
            self._delete_parts(folder, month)
            raise
        except Exception as exc:  # noqa: BLE001
            self._delete_parts(folder, month)
            log.debug("IP location install error: %r", exc)
            raise GeoIpError(friendly_error(exc, "the data folder")) from exc

    # ------------------------------------------------------------------ manifest, state.json, cleanup
    def _read_manifest(self, folder: Path) -> Optional[Dict[str, Any]]:
        """The manifest when valid (§4.5.5 step 1), else None."""
        try:
            data = json.loads((folder / MANIFEST_NAME).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != MANIFEST_VERSION:
            return None
        month = data.get("month")
        files = data.get("files")
        if not valid_month(month) or not isinstance(files, dict):
            return None
        names: Dict[str, str] = {}
        for kind in FILE_KINDS:
            name = _dig(files, kind, "name")
            m = FILE_NAME_RE.fullmatch(name) if isinstance(name, str) else None
            if m is None or m.group(1) != kind or m.group(2) != month:
                return None
            names[kind] = name
        installed_ts = data.get("installed_ts")
        if isinstance(installed_ts, bool) or not isinstance(installed_ts, (int, float)) or not math.isfinite(installed_ts):
            installed_ts = None
        return {"month": month, "names": names, "installed_ts": installed_ts}

    def _save_manifest(self) -> None:
        """Write manifest.json from the snapshot; a failure only marks it dirty (the loop retries)."""
        d = self._data
        if d.readers is None:
            return
        doc = {"version": MANIFEST_VERSION, "month": d.month, "installed_ts": d.installed_ts,
               "files": {kind: {"name": os.path.basename(d.readers[kind].path), "bytes": d.readers[kind].size,
                                "build_epoch": d.readers[kind].build_epoch} for kind in FILE_KINDS}}
        try:
            _write_json_atomic(self._folder() / MANIFEST_NAME, doc)
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                was_dirty, self._manifest_dirty = self._manifest_dirty, True
            if was_dirty:
                log.debug("IP location data manifest still cannot be written: %r", exc)
            else:
                log.warning("IP location data manifest could not be written: %s",
                            friendly_error(exc, "the data folder"))
            return
        with self._lock:
            self._manifest_dirty = False

    def _read_state_file(self) -> Tuple[int, Optional[float], Dict[str, Dict[str, Any]]]:
        """(failures, last_attempt_ts, months) from state.json; the defaults when missing or invalid."""
        try:
            data = json.loads((self._folder() / STATE_FILE_NAME).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return 0, None, {}
        if not isinstance(data, dict) or data.get("version") != STATE_FILE_VERSION:
            return 0, None, {}
        failures = data.get("failures")
        failures = failures if type(failures) is int and failures >= 0 else 0
        last = data.get("last_attempt_ts")
        if isinstance(last, bool) or not isinstance(last, (int, float)) or not math.isfinite(last):
            last = None
        months: Dict[str, Dict[str, Any]] = {}
        raw = data.get("months")
        for month, entry in (raw.items() if isinstance(raw, dict) else ()):
            if not valid_month(month) or not isinstance(entry, dict):
                continue
            big = entry.get("big_failures")
            months[month] = {"big_failures": big if type(big) is int and big >= 0 else 0,
                             "verify_failed": entry.get("verify_failed") is True}
        return failures, (float(last) if last is not None else None), months

    def _save_state_file(self) -> None:
        """Write state.json when dirty (atomic; a failure is logged at DEBUG and retried by the loop)."""
        cur = month_of(self._clock())
        keep = (cur, previous_month(cur))
        with self._lock:
            if not self._state_file_dirty:
                return
            self._state_file_dirty = False
            doc = {"version": STATE_FILE_VERSION, "failures": self._failures, "last_attempt_ts": self._last_attempt_ts,
                   "months": {m: dict(e) for m, e in self._months.items() if m in keep}}
        try:
            folder = self._folder()
            folder.mkdir(parents=True, exist_ok=True)
            _write_json_atomic(folder / STATE_FILE_NAME, doc)
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._state_file_dirty = True
            log.debug("IP location state.json could not be written: %r", exc)

    def _flush_dirty_files(self) -> None:
        with self._lock:
            manifest_dirty = self._manifest_dirty
        if manifest_dirty:
            self._save_manifest()
        self._save_state_file()

    def cleanup(self) -> None:
        """Delete leftover parts/tmp files and database files neither in the manifest nor loaded. Never raises."""
        try:
            folder = self._folder()
            if not folder.is_dir():
                return
            names = os.listdir(folder)
            for name in names:
                if name.endswith(".mmdb.part") or name in (MANIFEST_NAME + ".tmp", STATE_FILE_NAME + ".tmp"):
                    _unlink(folder / name)
            manifest = self._read_manifest(folder)
            with self._lock:
                dirty = self._manifest_dirty
            if manifest is None or dirty:
                return                            # an unreadable manifest never deletes a database file
            keep = set(manifest["names"].values())
            keep.update(os.path.basename(r.path) for r in (self._data.readers or {}).values())
            for name in names:
                if FILE_NAME_RE.fullmatch(name) and name not in keep:
                    _unlink(folder / name)
        except Exception:  # noqa: BLE001
            log.debug("IP location cleanup failed", exc_info=True)

    # ------------------------------------------------------------------ loading
    def load_installed(self) -> bool:
        """Load the installed pair (manifest, else the newest loadable pair on disk). Never raises."""
        try:
            return self._load_installed()
        except Exception:  # noqa: BLE001
            log.debug("IP location data could not be loaded", exc_info=True)
            return False

    def _open_checked(self, path: Path, kind: str) -> "mmdb.Reader":
        reader = mmdb.Reader(path)
        try:
            if reader.ip_version != 6:
                raise mmdb.MmdbError("not an IPv6 database")
            if not reader.database_type.startswith(DB_TYPE_PREFIX[kind]):
                raise mmdb.MmdbError("unexpected database type")
            reader.self_check(LOAD_VERIFY_SAMPLES)
        except BaseException:  # noqa: BLE001 - closed and re-raised
            reader.close()
            raise
        return reader

    def _load_installed(self) -> bool:
        folder = self._folder()
        if not folder.is_dir():
            return False
        manifest = self._read_manifest(folder)
        readers: Dict[str, mmdb.Reader] = {}
        if manifest is not None:
            month = manifest["month"]
            try:
                for kind in FILE_KINDS:
                    readers[kind] = self._open_checked(folder / manifest["names"][kind], kind)
            except Exception as exc:  # noqa: BLE001
                _close_readers(_Data(readers, None, None, None, 0))
                log.warning("IP location data could not be loaded: %s",
                            friendly_error(exc, "the data folder") if not isinstance(exc, mmdb.MmdbError) else str(exc))
                return False
            installed_ts = manifest["installed_ts"]
            fallback = False
        else:
            found = self._fallback_pair(folder)
            if found is None:
                return False
            month, readers = found
            installed_ts = None
            fallback = True
        if installed_ts is None:
            try:
                installed_ts = max(os.path.getmtime(r.path) for r in readers.values())
            except OSError:
                installed_ts = self._clock()
        self._prewarm(readers)
        with self._readers_lock:
            refused = self._closed
            old = self._data
            if not refused:
                self._data = _Data(readers, month, sum(r.size for r in readers.values()), float(installed_ts),
                                   old.generation + 1)
                self._cache.clear()
        if refused:
            _close_readers(_Data(readers, None, None, None, 0))
            return False
        _close_readers(old)
        if fallback:
            log.warning("IP location data manifest was missing or invalid; using the %s files", month)
            self._save_manifest()
        with self._lock:
            if self._state != "disabled":
                self._state = "ready"
        log.info("IP location data %s loaded", month)
        self._publish()
        return True

    def _fallback_pair(self, folder: Path) -> Optional[Tuple[str, Dict[str, "mmdb.Reader"]]]:
        """The newest month whose city and asn files (highest ``n`` first) both open and pass the checks."""
        groups: Dict[str, Dict[str, List[Tuple[int, str]]]] = {}
        for name in os.listdir(folder):
            m = FILE_NAME_RE.fullmatch(name)
            if m:
                groups.setdefault(m.group(2), {}).setdefault(m.group(1), []).append((int(m.group(3) or 0), name))
        for month in sorted(groups, reverse=True):
            chosen: Dict[str, mmdb.Reader] = {}
            for kind in FILE_KINDS:
                for _n, name in sorted(groups[month].get(kind, []), reverse=True):
                    try:
                        chosen[kind] = self._open_checked(folder / name, kind)
                        break
                    except Exception:  # noqa: BLE001
                        continue
                if kind not in chosen:
                    break
            if len(chosen) == len(FILE_KINDS):
                return month, chosen
            _close_readers(_Data(chosen, None, None, None, 0))
        return None

    def _prewarm(self, readers: Dict[str, "mmdb.Reader"]) -> None:
        """Read each search tree once with a GIL-free readinto, so a later mmap lookup never takes a cold fault."""
        buf = bytearray(PREWARM_CHUNK)
        for reader in readers.values():
            end = reader.node_count * reader.record_size // 4
            try:
                with open(reader.path, "rb", buffering=0) as f:
                    done = 0
                    while done < end and not self._stop.is_set():
                        n = f.readinto(buf)
                        if not n:
                            break
                        done += n
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------ lookups
    def lookup(self, ip: object) -> Optional[Dict[str, Any]]:
        """GEO for ``ip``, or None (off, no data, special address, no record). Never blocks on a download."""
        failures: List[BaseException] = []
        try:
            if not self.enabled():
                return None
            addr = normalize_ip(ip)
            if addr is None or _skipped(addr):
                return None
            text = str(addr)
            with self._readers_lock:
                d = self._data
                if d.readers is None:
                    return None
                key = (d.generation, text)
                if key in self._cache:
                    geo = self._cache[key]
                else:
                    records: List[Optional[Dict[str, Any]]] = []
                    for kind in FILE_KINDS:
                        try:
                            rec = d.readers[kind].get(addr)
                        except (mmdb.MmdbError, ValueError, OSError) as exc:
                            failures.append(exc)
                            rec = None
                        records.append(rec if isinstance(rec, dict) else None)
                    geo = build_geo(text, records[0], records[1], d.month)
                    if len(self._cache) >= LOOKUP_CACHE_MAX:
                        self._cache.clear()
                    self._cache[key] = geo
            return dict(geo) if geo is not None else None
        except Exception as exc:  # noqa: BLE001
            failures.append(exc)
            return None
        finally:
            for exc in failures:
                log.debug("IP location lookup of %s failed: %r", ip, exc)

    def origin(self) -> Optional[Tuple[float, float]]:
        """(lat, lon) of this PC's public address, from the database, or None."""
        fn = self._public_ip_fn
        if fn is None:
            return None
        try:
            ip = fn()
        except Exception:  # noqa: BLE001
            return None
        geo = self.lookup(ip)
        if geo is None or geo.get("lat") is None or geo.get("lon") is None:
            return None
        return geo["lat"], geo["lon"]

    def locate_hop(self, ip: object, hostname: Optional[str] = None, min_ms: Optional[float] = None,
                   origin: Optional[Tuple[float, float]] = None,
                   kind: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """LOCATION (exactly LOCATION_KEYS) for a traceroute hop, or None. Never raises."""
        try:
            if not self.enabled() or not self.available or not is_public_candidate(ip):
                return None
            geo = self.lookup(ip)
            db_text = geo["place"] if geo else None
            hint = None
            if isinstance(hostname, str) and hostname:
                hint = geohints.location_hint(hostname, str(normalize_ip(ip)))
                if hint is not None and not (geohints.plausible(hint, origin, min_ms)
                                             and (kind != "destination" or hint.get("confidence") == "carrier")):
                    hint = None
            if hint is not None:
                text, source, hint_code = geohints.hint_text(hint), "hostname", hint["code"]
            elif db_text:
                text, source, hint_code = db_text, "database", None
            else:
                text, source, hint_code = None, None, None
            asn = geo["asn"] if geo else None
            as_org = geo["as_org"] if geo else None
            if text is None and asn is None:
                return None
            return {"text": text, "source": source, "hint": hint_code, "db_text": db_text, "asn": asn,
                    "as_org": as_org}
        except Exception:  # noqa: BLE001
            log.debug("IP location of hop %s failed", ip, exc_info=True)
            return None
