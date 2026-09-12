"""Site reports: the Full Scan, the saved-report store and comparisons (ARCHITECTURE 3.19).

TNT is carried from customer network to customer network (a *site*).  A **Full Scan** is always
started by hand: it runs a speed test, a Discovery sweep and a Wi-Fi scan, combines them with up
to seven days of ping and outage history and saves the lot as one report (table ``reports``) for
later review, PDF export (:mod:`tnt.report_pdf`) and comparison with another report.

Pieces
------
* Pure helpers: :func:`normalize_site` / :func:`site_key` (names are trimmed with internal
  whitespace collapsed, 1..80 characters; the key is that name casefolded), :func:`report_window`,
  :func:`ping_stats`, one ``build_*_section`` per report section, :func:`clean_wifi_snapshot`,
  :func:`build_summary`, :func:`compare_reports` and the PDF file names.
* :class:`ReportManager` (``engine.reports``): the one Full Scan job (in memory), its thread, the
  Wi-Fi snapshot intake, the "joined this network" marker and the store calls the API makes.

The job
-------
Phases in order, each bounded and each allowed to fail without stopping the scan (a failed phase is
``error`` or ``skipped`` with a plain message and the report is then saved as ``partial``):

1. ``speed``: ``engine.speed.run_now()``.  The job subscribes to the bus *before* starting, so the
   result cannot slip past.  When a test is already running (scheduled or started from the Speed
   page) the job waits for that test's ``speedtest.done`` and uses its result, unless that test was
   cut short (error ``cancelled``: the test of a scan cancelled a moment ago, still winding down):
   then the job runs its own.  Its own test is
   recognised by the ``speedtest.start`` published after the call (a previous test's late
   ``speedtest.done`` is ignored).  ``speedtest.done`` is published before the scheduler lets go
   of its running flag, so a refused start with nothing running is retried every 0.2 s.  Bound:
   ``2 x (speedtest.timeout_s + 10 s) + 30 s``; on expiry, or when the job is cancelled, only a
   test the job started itself is cut short (``SpeedScheduler.cancel_current``).
2. ``discovery``: ``engine.discovery_start(None, None)`` (the default range and ports).  A scan
   that is already running is waited for and used (a cancelled one is not: the job then runs its
   own); a refused start with nothing running (it just
   ended) is retried.  Bound: :data:`DISCOVERY_WAIT_S` (10 min) for both, and only the job's own
   scan is cancelled on expiry or cancel (``Engine.discovery_cancel``; the engine still stores the
   partial run, as for any cancelled scan).
3. ``wifi``: the service cannot list BSSIDs (Windows keeps them from LocalSystem), so the job waits
   for a TNT window to post a survey snapshot (``POST /api/reports/scan/wifi``; the intake opens in the step
   that announces the phase, and a post is answered with the job as it left it).  The first
   snapshot with ``available: true`` is taken at once.  An unavailable one (no bridge, no adapter,
   location denied ...) is kept and, if nothing better arrives within :data:`WIFI_GRACE_S` (15 s)
   of the first such post, recorded.  With no post at all the phase gives up after
   :data:`WIFI_WAIT_S` (90 s) with the reason :data:`NO_WINDOW_REASON`.
4. ``history``: the network, ping, outage, speed and discovery sections.
5. ``save``: one ``reports`` row.  A job without a site name by then is saved under the site of the
   newest report saved on its network (``suggested_site``, read again now: a rename or delete since
   counts), else as :data:`UNNAMED_SITE` (renamed later); a name set while the row is being written
   renames it straight after.

``DELETE /api/reports/scan`` cancels: the job is ``cancelled`` at once, the running phase stops
(the job's own speed test / discovery scan with it) and nothing is saved.  Once the row is being
written a cancel no longer applies and the job ends ``saved``.  Only one job runs at a time; the
last finished one stays readable (``job()``) until the next starts or the service stops.  A new
scan may start while a cancelled one's thread is still winding down (a database read cannot be
interrupted): each scan keeps its flags in its own :class:`_Scan`, so the old thread never touches
the new scan's.  The job carries ``window_start`` / ``window_reason`` (additions): the window the
report will read, worked out at the start and again by the history phase, so the page can show it
while the scan runs.  Deleting the report the last scan saved sets that job's ``report_id`` to null.
It also carries ``network_id`` (the network the scan started on, ``tnt.networks``) and ``suggested_site``
``{"site","report_id","created_ts"}`` or null: the newest report saved on that network, which a rename or
delete of that report while the scan runs updates (with a ``report.progress``).

Events: ``report.progress {"job"}`` on a status, phase or message change, otherwise at most every
:data:`PROGRESS_GAP_S` for a percentage step of 1 or more (the SSE queues drop their oldest entries
when they fill); ``report.saved {"id","site","status"}``; ``report.updated {"id","site"}``;
``report.deleted {"id"}``.  SSE has no replay: a page that connects mid-scan reads
``GET /api/reports/scan``.  Publishers of ``report.progress`` take turns and copy the job inside their turn,
so the stream never shows an older state after a newer one.

Decisions where the contract is silent (documented in ARCHITECTURE 3.19)
-----------------------------------------------------------------------
* ``created_ts`` of a report is when the Full Scan started, and that is the end of its ping and
  outage window ("the report time"): the job's own speed test saturates the link and its Discovery
  sweep sends a burst of probes, so the minutes after the start would inflate latency and loss.
  It also means every minute of the window is flushed to the database by the time the history is
  read (the current minute is only written when the next one starts).
* **Site networks** (ARCHITECTURE 3.20): only the data of the network the scan started on counts.  On a known
  network the window is the last seven days (bounded by the oldest ping data, ``window_reason``
  ``site_network``) and the ping minutes, outages and window speed tests read are that network's
  (``network_id``), plus untagged rows (saved before networks were tagged) from the time rule's start below
  on.  Travel is left out: an offline spell of the site's network that ended on another network drops the
  minutes from :data:`LEAVE_SLACK_S` before it to its end and the outages that began then, and cuts an outage
  still open when it began (:func:`scope_outage_rows`).  ``ping.visits`` are the runs of the network's minutes
  split at gaps over :data:`VISIT_GAP_S`; ``monitored_s`` (both sections) is the visits without the monitoring
  gaps inside them, ``summary.window_hours`` those hours.  ``meta.network`` describes the network.  Unknown
  (no tracker, not identified yet, or the database not migrated): the time rule, and the history phase says so.
* The time rule (untagged rows, an unknown network): the window starts at the latest of: seven days before its end, the
  oldest ping minute stored, and the moment this PC joined its current network.  That moment is the db meta key
  :data:`NET_JOINED_META_KEY` (JSON ``{"ts","gateway","networks","nic","gateway_mac","mac_ts","seen_ts"}``),
  kept by :meth:`ReportManager.on_network_change`: ``ts`` moves only when a non-empty default gateway
  differs from the last non-empty one, the internet adapter's IPv4 networks share nothing with the
  last non-empty set, or the same gateway address answers from another MAC (``tnt.arp``: most small
  networks use the same default subnet, so the router's MAC is what tells two sites apart; the MAC is
  looked up for up to :data:`MAC_WAIT_S` after each change, the pinger resolves it within seconds).
  Losing the connection and coming back to the same network does not move it.  Changes are applied
  in the order the watcher published them (numbered on arrival), never by their wall-clock times,
  which a clock correction can reorder.  At start the current network (``netwatch.state()``
  gateway, the internet adapter's network from ``netinfo_summary()``, the gateway's MAC) is compared
  with the marker: a PC that moved while the service was stopped gets ``ts`` = the engine's start.
  Without a marker (the first start of a release that has reports) ``ts`` is the latest sign of a
  move within the window (:meth:`ReportManager._seed_join_ts`: a "network changed" events row, or
  the end of a monitoring gap of 30 min or more), else unknown: a shorter window beats one that mixes
  two sites.  Before a report reads its window the gateway's MAC is checked once more; a change the
  events missed dates the join at the last moment the marker saw the old network.  A join time
  later than now (stamped by a clock that was put back since) is dated by the monotonic clock, or
  at the service start (:meth:`ReportManager.joined_ts`).  ``window_reason`` names the bound that won.
* A new report describes the targets set up when the scan ran (a technician's target list changes
  from site to site): the rows of the targets table that are enabled when the history phase reads
  them, the ``gateway`` alias included (:meth:`ReportManager._configured_targets`, read once: the
  ping table's hosts, labels and kinds and the ids both sections keep come from that one read, so a
  target removed while the phase runs keeps its name there).  Removing a target deletes only its
  targets row, so the minute and outage rows of removed targets stay in the database, like those of
  disabled ones: both are left out.  Only ids count.  A host removed and added again is a new id and
  its older rows are left out as well, not merged: minute rows carry no host (it is only on outage
  rows, so a target that never had an outage could not be matched and the same re-add would merge in
  one report and not the next), the removal itself closes the old target's open outage with "target
  removed", the same text may have pinged another address or been another kind, and the rest of TNT
  (the Ping page history, the outage tracker) keys targets by id too.  What was left out is counted in
  the section's ``note`` (an addition): ``"Left out: 8 removed or disabled targets"``, in the outages
  section followed by ``"(19 single-target outages)"``; None when nothing was.  Both notes count one
  set, the ids left out of either section, so a removed target with pings but no outage in the window
  is one of the 8 on both headings.  A target outage row without a target id (the tracker never writes
  one) is left out and counted among the outages only.  A comparison notes the one report saved before
  this rule (its ping and outages sections have no ``note``: :data:`OLDER_RULE_NOTE`).  Saved reports
  keep what they stored.
* Ping statistics come from the per-minute aggregates (there are no per-ping values in the
  database): ``samples``/``lost`` are the sums, ``loss_pct = lost / samples``, ``avg_ms`` is weighted
  by the replies of each minute, ``min_ms``/``max_ms`` are the extremes of the minute extremes,
  ``p95_ms`` is the reply-weighted 95th percentile of the 1-minute averages (it smooths spikes
  shorter than a minute, so it is a lower bound of the per-ping p95) and ``jitter_ms`` pools the
  per-minute jitter (mean absolute difference of consecutive successful RTTs) weighted by the pairs
  each minute had (``received - 1``), so it is exact for pairs inside a minute and ignores the step
  from one minute to the next.  ``role`` is ``gateway`` for the gateway alias or a target whose
  address is this PC's default gateway, otherwise the live view's ``kind`` (the stored one without a
  live view, an address-based guess for a stored ``auto``).
* Outages are read as incidents, because the tracker writes one real event as several rows: a total
  (``total_local`` / ``total_internet``) opens only once every member target has its own open outage,
  so an internet drop with two internet targets is three rows.  Rows are clipped to the window (an
  open row ends at the window's end; ``open`` says it had not ended).  A **network outage** is a
  total row, overlapping totals merged (a lost connection opens both); its member target rows (a
  target outage inside its span, give or take :data:`FOLD_SLACK_S`) are folded into it and named in
  the item's ``targets``.  A **single-target outage** is a target row inside no network outage (a
  camera switched off overnight, a host that stopped answering).  ``count`` is both
  (``network_outages`` + ``target_outages``, additions); ``network_down_s`` (an addition, the
  summary's ``downtime_s``) and ``longest_s`` are about network outages only, so one device off for
  hours never reads as a 9-hour outage.  ``monitored_s`` (an addition) is the window without the
  monitoring gaps in it.  ``by_kind`` / ``downtime_s`` stay per raw row.  Items are the incidents
  and the gaps, newest first, at most 50; a target item's ``name`` (an addition) is the target as the
  ping table names it.  The target rows of targets a new report leaves out (see above) are dropped
  before all of this: not counted (``by_kind`` included), not listed, not named among a network
  outage's ``targets``; a network outage whose every folded target row was left out is left out too and
  counted in the note (one with no target row at all stays).  With no pings at all in the window (or an
  empty window) the section is unavailable with the ping section's reason: no outage could have been
  noticed.  When only left-out targets were pinged it stays available: monitoring ran, so its network
  outages and gaps are still facts about the site.
* Free text is capped (:data:`TEXT_CAP` for host names, vendors and labels, :data:`NOTE_CAP` for
  notes, :data:`MAX_HOST_PORTS` open ports per host), so a report stays within a few hundred KB.
* Wi-Fi: access points the survey marks ``stale`` (not in its latest read) are left out unless every
  one is stale.  ``busiest_channel`` counts access points by primary channel; ``connected.channel_aps``
  (an addition) counts the ones on the connected access point's channel and ``connected.overlap_aps``
  (an addition) the ones whose spectrum overlaps it (:func:`channels_overlap`: the centre of each
  bonded channel, from the survey's ``center_channel`` or else the primary channel, closer than half
  the two widths; 2.4 GHz channels 1 and 4 overlap, 1 and 6 do not; both counts include the connected
  access point).  Vendors come from the OUI registry here, from the BSSID itself (``base_oui`` with the
  locally-administered bit cleared when it is set), never from posted fields.
* Compare: ``delta = a - b`` and ``delta_pct`` relative to B (A is the current scan, B the reference;
  no percentage for dBm, a logarithmic unit, or when B is 0).
  ``better`` is ``same`` when the values differ by no more than the larger of 2 % and the unit's
  tolerance (:data:`UNIT_TOLERANCE`).  Speed rows note differing links ("Wi-Fi 2.4 GHz, 144 Mbps link")
  and servers, with two informational rows (the average of the tests in each window, the adapter's
  link speed).  The combined internet rows use the internet targets both reports pinged (informational
  when they share none); the gateway maximum, a single ping, is informational.  Outage rates are
  network outages, downtime and single-target outages per day *monitored*, compared only when both
  reports monitored at least :data:`MIN_RATE_S` (a day); otherwise the rows are each window's counts,
  informational.  Wi-Fi judges the site's own network (the connected SSID: the connected signal and
  its best signal per band) and crowding (access points on or overlapping the connected channel, on
  the busiest channel); other networks' signals are informational, and per-SSID rows only appear for
  two reports of one site (the connected SSID judged, the rest informational).  Rows with no value on
  either side are left out; a section also carries ``note`` naming a side that did not collect it and,
  for ping and outages, the one side saved before reports left removed targets out (its section has
  no ``note`` key, so its numbers may still count them: :data:`OLDER_RULE_NOTE`).
"""
from __future__ import annotations

import importlib
import ipaddress
import json
import logging
import math
import queue
import re
import secrets
import socket
import statistics
import threading
import time
import unicodedata
from collections import Counter
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import __version__

log = logging.getLogger(__name__)

SITE_MAX_LEN = 80
UNNAMED_SITE = "Unnamed site"
WINDOW_S = 7 * 86400.0
#: db meta key of the "this PC joined its current network" marker (see the module docstring)
NET_JOINED_META_KEY = "net.joined"
MAX_OUTAGE_ITEMS = 50
MAX_HOSTS = 512
MAX_APS = 200
MAX_POST_APS = 1000
MAX_POST_INTERFACES = 16
MAX_COMPARE_SSIDS = 25
WIFI_WAIT_S = 90.0
WIFI_GRACE_S = 15.0
DISCOVERY_WAIT_S = 600.0
SPEED_SOCKET_S = 10.0           # speedtest.base SOCKET_TIMEOUT_S: one more socket timeout per attempt
SPEED_EXTRA_S = 30.0
START_RETRY_S = 0.2
START_RETRIES = 25
STOP_JOIN_S = 1.0
PROGRESS_GAP_S = 0.5
#: outage rates (per day monitored) are only compared when both reports monitored at least this long
MIN_RATE_S = 86400.0
#: a single-target outage within this much of a network outage's span is one of its members, not an incident of its own
FOLD_SLACK_S = 60.0
#: without a marker, the end of a monitoring gap at least this long may be when this PC arrived (see _seed_join_ts)
SEED_GAP_S = 1800.0
#: a join time later than now by more than this was stamped by a clock that has since been put back
CLOCK_SLACK_S = 5.0
#: how long the network marker waits for the default gateway's MAC to appear in the ARP table, and how often it looks
MAC_WAIT_S = 15.0
MAC_POLL_S = 1.0
#: free text kept per field: host names, vendors and labels; notes; open ports per Discovery host
TEXT_CAP = 128
NOTE_CAP = 300
MAX_HOST_PORTS = 64
MAX_EPOCH_S = 4_102_444_800.0   # 2100-01-01, like the API's epoch bounds
SPEED_CANCELLED = "cancelled"   # tnt.speedtest.base.CANCELLED: the error of a test cut short
NO_WINDOW_REASON = "No TNT window was open to scan Wi-Fi"
#: the ping section's reason when every target pinged in the window is one a new report leaves out (removed or disabled since)
NO_TARGET_PINGS_REASON = "No pings of the targets set up when the scan ran were recorded in this window"
#: a comparison's ping / outages note on the one report saved before reports left removed targets out (no ``note`` there)
OLDER_RULE_NOTE = "{side} was saved before reports left out removed or disabled targets"
#: the window's bound in words (phase messages; the PDF and the page word it the same way)
WINDOW_WORDS = {"network_change": "since this PC joined this network", "seven_days": "over the last 7 days",
                "data_start": "since the ping data begins", "site_network": "on this network over the last 7 days"}
#: visits: minutes of the site's network further apart than this are two visits
VISIT_GAP_S = 1800.0
#: travel: an outage that began this long before this PC lost the site's network (or later) is that loss itself, and the minutes
#: this long before it go with the trip
LEAVE_SLACK_S = 60.0
#: added to the history phase's message when the network was not identified when the scan started (the time rule is used)
UNKNOWN_NETWORK_MESSAGE = "the network was not identified when the scan started, so they are read by time"
#: what the history phase's message adds, by why the site's network rule did not apply: not identified, no network with a gateway
#: when the scan started (the last network's id sticks for the writers, but a scan then is on no site's network), data not tagged
#: (the database upgrade did not run), a portable network (a hotspot or travel router: only this connection to it counts)
NETWORK_NOTE_MESSAGES = {
    "unknown": UNKNOWN_NETWORK_MESSAGE,
    "offline": "this PC had no network with a gateway when the scan started, so they are read by time",
    "not_ready": "data is not tagged with networks yet (the database upgrade has not run, see the service log), so they are read by time",
    "portable": "this network is carried from site to site (a hotspot or travel router), so only this connection to it counts",
}
#: the comparison note of the sides read on their site's network: "On their networks: A 23h 37m over 3 visits; B 8h 00m over 1 visit"
NETWORK_TIME_NOTE = "On their networks: "
#: travel: a link that came back to the site's network for a moment less than this before this PC left it (the car park) is
#: part of that trip
LEAVE_MERGE_S = 120.0

PHASES: Tuple[str, ...] = ("speed", "discovery", "wifi", "history", "save")
#: ``job["phase"]`` while each phase runs
JOB_PHASE = {"speed": "speed", "discovery": "discovery", "wifi": "wifi", "history": "finalize", "save": "finalize"}
#: the part of the job's 0..100 each phase covers
PHASE_PCT = {"speed": (0.0, 35.0), "discovery": (35.0, 70.0), "wifi": (70.0, 90.0), "history": (90.0, 97.0),
             "save": (97.0, 100.0)}
#: a phase's own progress mapped onto its part: speed-test steps and discovery phases
SPEED_STEPS = {"connect": (0.0, 0.05), "latency": (0.05, 0.15), "download": (0.15, 0.6), "upload": (0.6, 1.0),
               "done": (1.0, 1.0)}
DISCOVERY_STEPS = {"ping": (0.0, 0.3), "ports": (0.3, 0.85), "arp": (0.85, 0.9), "resolve": (0.9, 1.0),
                   "done": (1.0, 1.0)}
BANDS: Tuple[str, ...] = ("2.4", "5", "6")
OUTAGE_KINDS: Tuple[str, ...] = ("target", "total_local", "total_internet", "gap")
DEVICE_TYPE_ORDER: Tuple[str, ...] = ("Router", "DW Server", "Camera", "Phone", "Ubiquiti")
WINDOW_REASONS: Tuple[str, ...] = ("network_change", "seven_days", "data_start", "site_network")
#: why a posted Wi-Fi snapshot has no data, by survey state (the snapshot's own error text wins)
WIFI_STATE_TEXT = {
    "no_bridge": "Wi-Fi can only be scanned from the TNT window",
    "outdated": "This TNT window is too old to scan Wi-Fi",
    "no_adapter": "This PC has no Wi-Fi adapter",
    "radio_off": "The Wi-Fi radio is switched off",
    "disabled": "The Wi-Fi survey is switched off in TNT",
    "location_denied": "Windows location access is off for TNT, so Wi-Fi networks cannot be listed",
    "starting": "The Wi-Fi survey had not read any networks yet",
}
#: unavailable Wi-Fi states that are this PC's situation rather than a failure (phase "skipped")
WIFI_SKIP_STATES = frozenset({"no_bridge", "outdated", "no_adapter", "disabled"})
#: "same" in a comparison: the values differ by no more than max(this, 2 % of the larger)
UNIT_TOLERANCE = {"Mbps": 1.0, "ms": 1.0, "%": 0.1, "dBm": 1.0, "per day": 0.1, "min/day": 1.0, "min": 1.0}
SAME_REL = 0.02
SPEED_RESULT_KEYS = ("ts", "backend", "server", "isp", "external_ip", "download_mbps", "upload_mbps", "latency_ms",
                     "jitter_ms", "packet_loss_pct", "ok", "error")

_WS_RE = re.compile(r"\s+")
_HOST_IP_RE = re.compile(r"^(.*\S) \(([^()\s]+)\)$")
_MAC_HEX_RE = re.compile(r"[^0-9A-Fa-f]")
_RETRY = object()


class ScanBusy(RuntimeError):
    """A Full Scan is already running (HTTP 409 ``busy`` with that job)."""

    code = "busy"

    def __init__(self, job: Optional[Dict[str, Any]]) -> None:
        super().__init__("A full scan is already running")
        self.job = job


class ScanConflict(RuntimeError):
    """The request does not fit the job's state (HTTP 409 with *code* and the job)."""

    def __init__(self, message: str, job: Optional[Dict[str, Any]] = None, code: str = "conflict") -> None:
        super().__init__(message)
        self.job = job
        self.code = code


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------
def _num(value: Any) -> Optional[float]:
    """A finite float (bools and non-numbers are None)."""
    if value is None or isinstance(value, bool):
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _r(value: Any, digits: int = 2) -> Optional[float]:
    f = _num(value)
    return None if f is None else round(f, digits)


def _int_in(value: Any, lo: int, hi: int) -> Optional[int]:
    f = _num(value)
    if f is None or f != int(f) or not lo <= f <= hi:
        return None
    return int(f)


def _text(value: Any, limit: int, strip: bool = True) -> Optional[str]:
    """Text without control characters, at most *limit* characters (None for non-text)."""
    if not isinstance(value, str):
        return None
    out = "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in value)
    if strip:
        out = out.strip()
    return out[:limit]


def _cap(value: Any, limit: int = TEXT_CAP) -> Any:
    """Text cut to *limit* characters; anything else as it is (a report keeps what the scan recorded)."""
    return value[:limit] if isinstance(value, str) else value


def _plural(n: Any, word: str, many: Optional[str] = None) -> str:
    """``"1 access point"``, ``"3 access points"``."""
    count = int(n or 0)
    return f"{count} {word if count == 1 else (many or word + 's')}"


def _mac(value: Any) -> Optional[str]:
    """``AA:BB:CC:DD:EE:FF`` or None (``tnt.oui.normalize_mac`` when importable)."""
    if not isinstance(value, str):
        return None
    try:
        from . import oui

        return oui.normalize_mac(value)
    except Exception:  # noqa: BLE001 - the OUI module is optional at runtime
        digits = _MAC_HEX_RE.sub("", value)
        return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).upper() if len(digits) == 12 else None


def _vendor(oui_prefix: Optional[str]) -> Optional[str]:
    if not oui_prefix:
        return None
    try:
        from . import oui

        return oui.vendor_for_oui(oui_prefix)
    except Exception:  # noqa: BLE001 - netaddr missing or broken: no vendor names
        log.debug("OUI lookup failed for %s", oui_prefix, exc_info=True)
        return None


def oui_parts(bssid: str) -> Tuple[str, bool, Optional[str]]:
    """``(oui, locally_administered, base_oui)`` of ``AA:BB:CC:DD:EE:FF`` (``client/wifi_ies.oui_info``):
    ``base_oui`` is the OUI with the locally-administered bit cleared, only when that bit is set."""
    first = int(bssid[:2], 16)
    local = bool(first & 0x02)
    return bssid[:8], local, (f"{first & ~0x02 & 0xFF:02X}{bssid[2:8]}" if local else None)


def _is_gateway_alias(host: Any) -> bool:
    try:
        from .pinger import is_gateway_alias

        return bool(is_gateway_alias(host))
    except Exception:  # noqa: BLE001 - pinger missing: the names it uses
        return isinstance(host, str) and host.strip().lower() in ("gateway", "default-gateway", "default gateway")


def _copy_job(job: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if job is None:
        return None
    out = dict(job)
    out["phases"] = [dict(p) for p in job.get("phases") or []]
    if isinstance(job.get("suggested_site"), dict):
        out["suggested_site"] = dict(job["suggested_site"])      # a rename changes the job's, never a copy handed out
    return out


def _drain(q: "queue.Queue[Any]") -> None:
    while True:
        try:
            q.get_nowait()
        except queue.Empty:
            return


def _step_frac(steps: Dict[str, Tuple[float, float]], phase: Any, frac: Any) -> Optional[float]:
    span = steps.get(str(phase or ""))
    if span is None:
        return None
    f = _num(frac)
    f = 0.0 if f is None else max(0.0, min(1.0, f))
    return span[0] + (span[1] - span[0]) * f


def span_text(seconds: Any) -> str:
    """``"45 min"``, ``"5.2 h"``, ``"6.9 days"``."""
    s = _num(seconds)
    if s is None:
        return "-"
    s = max(0.0, s)
    if s < 3600:
        return f"{int(round(s / 60.0))} min"
    if s < 2 * 86400:
        return f"{s / 3600.0:.1f} h"
    return f"{s / 86400.0:.1f} days"


def duration_text(seconds: Any) -> str:
    """``"42 s"``, ``"2m 05s"``, ``"1h 02m"``, ``"1d 2h"``: the Reports page's durations (reportsui ``durationText``), so the time on a
    site's network reads the same in a comparison's note as in the report."""
    s = _num(seconds)
    if s is None:
        return "-"
    s = int(max(0.0, s) + 0.5)
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60:02d}m"
    return f"{s // 86400}d {(s // 3600) % 24}h"


# --------------------------------------------------------------------------------------
# site names
# --------------------------------------------------------------------------------------
def normalize_site(value: Any) -> str:
    """The site name as stored: control characters become spaces, whitespace runs collapse to one space,
    the ends are trimmed.  ``ValueError`` when it is not text, empty, or longer than :data:`SITE_MAX_LEN`."""
    if not isinstance(value, str):
        raise ValueError("the site name must be text")
    text = _WS_RE.sub(" ", "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in value)).strip()
    if not text:
        raise ValueError("the site name is empty")
    if len(text) > SITE_MAX_LEN:
        raise ValueError(f"the site name is longer than {SITE_MAX_LEN} characters")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # a lone surrogate ("\ud800" is valid JSON): the database could not store it
        raise ValueError("the site name contains characters that are not text") from None
    return text


def site_key(site: Any) -> str:
    """The grouping key of a site name: whitespace collapsed, trimmed, casefolded (``"Acme  DENTAL"`` and
    ``"acme dental"`` are one site; casefold also folds non-ASCII letters, which SQLite cannot)."""
    return _WS_RE.sub(" ", str(site or "")).strip().casefold()


def search_key(q: Any) -> Optional[str]:
    """A search string as a site key, or None when it is empty or not text."""
    if not isinstance(q, str):
        return None
    key = site_key(q)[: SITE_MAX_LEN * 2]
    return key or None


def _file_part(text: Any, limit: int) -> str:
    ascii_text = unicodedata.normalize("NFKD", str(text or "")).encode("ascii", "ignore").decode("ascii")
    part = re.sub(r"[^A-Za-z0-9]+", "-", ascii_text).strip("-")[:limit].strip("-")
    return part or "site"


def pdf_filename(site: Any, created_ts: Any) -> str:
    """``TNT-report-<site>-<YYYY-MM-DD-HHMM>.pdf`` (local time): ASCII letters, digits and ``-`` only, so the
    header is plain latin-1 and nothing in it needs quoting or decoding."""
    try:
        stamp = time.strftime("%Y-%m-%d-%H%M", time.localtime(float(created_ts)))
    except (TypeError, ValueError, OverflowError, OSError):
        stamp = "undated"
    return f"TNT-report-{_file_part(site, 48)}-{stamp}.pdf"


def compare_filename(site_a: Any, site_b: Any) -> str:
    """``TNT-compare-<siteA>-vs-<siteB>.pdf`` (sanitised like :func:`pdf_filename`)."""
    return f"TNT-compare-{_file_part(site_a, 32)}-vs-{_file_part(site_b, 32)}.pdf"


# --------------------------------------------------------------------------------------
# window and ping statistics
# --------------------------------------------------------------------------------------
def report_window(end_ts: float, joined_ts: Any = None, oldest_ts: Any = None,
                  span_s: float = WINDOW_S) -> Tuple[float, str]:
    """``(window_start, window_reason)`` for a window ending at *end_ts*: the latest of *span_s* before it
    (``seven_days``), the oldest ping data (``data_start``) and the time this PC joined its network
    (``network_change``; it wins a tie).  Never after *end_ts*."""
    end = float(end_ts)
    candidates: List[Tuple[float, int, str]] = [(end - float(span_s), 0, "seven_days")]
    oldest = _num(oldest_ts)
    if oldest is not None:
        candidates.append((oldest, 1, "data_start"))
    joined = _num(joined_ts)
    if joined is not None:
        candidates.append((joined, 2, "network_change"))
    start, _rank, reason = max(candidates)
    return min(start, end), reason


def history_message(start: float, end: float, reason: Optional[str]) -> str:
    """The history phase's message: ``"Pings and outages since this PC joined this network (2.6 days)"``."""
    words = WINDOW_WORDS.get(str(reason or ""))
    span = span_text(max(0.0, float(end) - float(start)))
    return f"Pings and outages {words} ({span})" if words else f"Pings and outages over {span}"


def weighted_percentile(points: Iterable[Tuple[float, float]], pct: float) -> Optional[float]:
    """The smallest value whose cumulative weight reaches *pct* % of the total (nearest rank)."""
    pts = sorted((float(v), float(w)) for v, w in points if w and w > 0)
    total = sum(w for _v, w in pts)
    if not pts or total <= 0:
        return None
    goal = total * float(pct) / 100.0
    acc = 0.0
    for value, weight in pts:
        acc += weight
        if acc >= goal - 1e-9:
            return value
    return pts[-1][0]


def ping_stats(rows: Iterable[Sequence[Any]]) -> Dict[str, Any]:
    """Window statistics from minute rows ``(sent, received, avg_ms, min_ms, max_ms, jitter_ms)``
    (``Database.ping_minute_rows``); the method is in the module docstring."""
    sent = received = weighted_n = pairs = 0
    weighted = jitter_sum = 0.0
    lo: Optional[float] = None
    hi: Optional[float] = None
    points: List[Tuple[float, float]] = []
    for row in rows:
        s, rec, avg, mn, mx, jit = (list(row) + [None] * 6)[:6]
        s = int(s or 0)
        rec = int(rec or 0)
        sent += s
        received += rec
        avg_f = _num(avg)
        if rec > 0 and avg_f is not None:
            weighted += avg_f * rec
            weighted_n += rec
            points.append((avg_f, rec))
        mn_f, mx_f, jit_f = _num(mn), _num(mx), _num(jit)
        if mn_f is not None:
            lo = mn_f if lo is None else min(lo, mn_f)
        if mx_f is not None:
            hi = mx_f if hi is None else max(hi, mx_f)
        if rec >= 2 and jit_f is not None:
            jitter_sum += jit_f * (rec - 1)
            pairs += rec - 1
    lost = max(0, sent - received)
    return {
        "samples": sent,
        "lost": lost,
        "loss_pct": round(100.0 * lost / sent, 2) if sent else None,
        "avg_ms": round(weighted / weighted_n, 2) if weighted_n else None,
        "min_ms": _r(lo),
        "max_ms": _r(hi),
        "p95_ms": _r(weighted_percentile(points, 95)),
        "jitter_ms": round(jitter_sum / pairs, 2) if pairs else None,
    }


def guess_kind(host: Any) -> str:
    """``local`` for a private, link-local or loopback address, else ``internet`` (host names included)."""
    try:
        addr = ipaddress.ip_address(str(host or "").strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return "internet"
    return "local" if (addr.is_private or addr.is_link_local or addr.is_loopback) else "internet"


def target_role(host: Any, ip: Any = None, kind: Any = None, gateway: Any = None) -> str:
    """``gateway`` for the gateway alias or a target pinging the default gateway, else *kind*
    (``local``/``internet``), else :func:`guess_kind`."""
    if _is_gateway_alias(host) or (gateway and ip and str(ip).strip().lower() == str(gateway).strip().lower()):
        return "gateway"
    if kind in ("local", "internet"):
        return str(kind)
    return guess_kind(ip or host)


# --------------------------------------------------------------------------------------
# sections
# --------------------------------------------------------------------------------------
def _band_stats(aps: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    rssis = [int(a["rssi"]) for a in aps]
    channels = Counter(int(a["channel"]) for a in aps if a.get("channel") is not None)
    busiest = min(channels.items(), key=lambda kv: (-kv[1], kv[0])) if channels else None
    return {
        "aps": len(aps),
        "networks": len({a["ssid"] for a in aps if a.get("ssid") and not a.get("hidden")}),
        "strongest_rssi": max(rssis) if rssis else None,
        "median_rssi": _r(statistics.median(rssis), 1) if rssis else None,
        "busiest_channel": busiest[0] if busiest else None,
        "busiest_channel_aps": busiest[1] if busiest else None,
    }


def _speed_window(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    def stat(key: str) -> Tuple[Optional[float], Optional[float], Optional[float]]:
        vals = [f for f in (_num(r.get(key)) for r in rows) if f is not None]
        if not vals:
            return None, None, None
        return round(sum(vals) / len(vals), 2), round(min(vals), 2), round(max(vals), 2)

    down, up, lat = stat("download_mbps"), stat("upload_mbps"), stat("latency_ms")
    return {"count": len(rows), "download_avg": down[0], "download_min": down[1], "download_max": down[2],
            "upload_avg": up[0], "upload_min": up[1], "upload_max": up[2], "latency_avg": lat[0]}


def empty_section(key: str, reason: Optional[str]) -> Dict[str, Any]:
    """A section in its full shape, with nothing collected (``available`` false and *reason*)."""
    base: Dict[str, Any] = {"available": False, "reason": reason}
    if key == "network":
        base.update(internet_nic=None, public_ip=None, isp=None, warnings=[])
    elif key == "speed":
        base.update(result=None, window=_speed_window([]))
    elif key == "ping":
        base.update(window_start=None, window_end=None, window_reason=None, targets=[], note=None, visits=[], monitored_s=None,
                    untagged_since=None)
    elif key == "outages":
        base.update(window_start=None, window_end=None, count=0, network_outages=0, target_outages=0,
                    by_kind={k: 0 for k in OUTAGE_KINDS}, downtime_s={k: 0.0 for k in OUTAGE_KINDS}, network_down_s=0.0,
                    longest_s=None, monitored_s=None, items=[], items_total=0, note=None)
    elif key == "discovery":
        base.update(run_id=None, range=None, started_ts=None, duration_s=None, host_count=0, device_types={},
                    hosts=[], hosts_total=0, note=None)
    elif key == "wifi":
        base.update(state=None, adapter=None, collected_ts=None, connected=None, networks=0, aps_count=0,
                    bands={b: _band_stats([]) for b in BANDS}, aps=[], aps_total=0)
    return base


def build_network_section(snapshot: Any, public_ip: Any = None, isp: Any = None) -> Dict[str, Any]:
    """The adapter this PC reaches the internet through, from a ``netinfo.netinfo_snapshot()`` dict (else the
    first up physical adapter with an IPv4 address, a real address before a self-assigned one)."""
    section = empty_section("network", "Network adapters could not be read")
    section["public_ip"] = _text(public_ip, 64) or None
    section["isp"] = _text(isp, 120) or None
    if not isinstance(snapshot, dict):
        return section
    adapters = [a for a in snapshot.get("adapters") or [] if isinstance(a, dict)]
    index = snapshot.get("internet_nic_index")
    nic = next((a for a in adapters if index is not None and a.get("index") == index), None)
    internet = nic is not None
    if nic is None:
        bench = [a for a in adapters if a.get("status") == "up" and a.get("is_physical") and a.get("primary_ipv4")]
        bench.sort(key=lambda a: 1 if str(a.get("primary_ipv4")).startswith("169.254.") else 0)
        nic = bench[0] if bench else None
    if nic is None:
        if adapters:
            section["reason"] = "This PC is not connected to a network"
        return section
    v4 = [x for x in nic.get("ipv4") or [] if isinstance(x, dict)]
    primary = nic.get("primary_ipv4")
    addr = next((x for x in v4 if x.get("address") == primary), v4[0] if v4 else {})
    gateway = snapshot.get("default_gateway") if internet else None
    if not gateway:
        gateway = next((g for g in nic.get("gateways") or [] if ":" not in str(g)), None)
    warnings: List[str] = []
    for w in nic.get("warnings") or []:
        code = w.get("code") if isinstance(w, dict) else w
        if isinstance(code, str) and code and code not in warnings:
            warnings.append(code)
    section.update(available=True, reason=None, warnings=warnings, internet_nic={
        "name": nic.get("name"),
        "description": nic.get("description"),
        "type_name": nic.get("type_name"),
        "internet": internet,
        "ipv4": primary or addr.get("address"),
        "prefix": addr.get("prefix"),
        "gateway": gateway,
        "dns": [str(d) for d in (nic.get("dns") or [])][:8],
        "dhcp": bool(nic.get("dhcp_enabled")),
        "dhcp_server": nic.get("dhcp_server"),
        "mac": nic.get("mac"),
        "link_bps": nic.get("speed_bps"),
    })
    return section


def build_speed_section(result: Any, window_rows: Sequence[Dict[str, Any]] = (),
                        error: Optional[str] = None) -> Dict[str, Any]:
    """The Full Scan's own (or waited-for) speed test plus the successful tests in the window.  A failed test
    keeps its ``result`` (``ok`` false, ``error``) and makes the section unavailable."""
    section = empty_section("speed", error or "No speed test ran")
    section["window"] = _speed_window([r for r in window_rows or [] if isinstance(r, dict) and r.get("ok")])
    if not isinstance(result, dict):
        return section
    res: Dict[str, Any] = {k: result.get(k) for k in SPEED_RESULT_KEYS}
    for key in ("download_mbps", "upload_mbps", "latency_ms", "jitter_ms", "packet_loss_pct"):
        res[key] = _r(res.get(key))
    res["ok"] = bool(result.get("ok"))
    res["id"] = result.get("id")
    section["result"] = res
    if res["ok"]:
        section.update(available=True, reason=None)
    else:
        # the same plain sentence as the phase message: a bare "timeout" under "Not collected" says too little
        section["reason"] = f"The speed test failed: {res['error']}" if res.get("error") else str(error or "The speed test failed")
    return section


def left_out_note(targets: int, outages: int = 0, networks: int = 0) -> Optional[str]:
    """What a new report left out of its ping or outages section (the module docstring): ``"Left out: 8 removed or disabled
    targets"``, in the outages section followed by ``" (1 network outage, 19 single-target outages)"`` for what of theirs was left
    out (network outages whose targets were all left out, single-target outages), or with no target id to count ``"Left out: 1
    network outage and 2 single-target outages of removed or disabled targets"``; None when nothing was."""
    parts = ([_plural(networks, "network outage")] if networks > 0 else []) + \
        ([_plural(outages, "single-target outage")] if outages > 0 else [])
    if targets > 0:
        text = "Left out: " + _plural(targets, "removed or disabled target")
        return f"{text} ({', '.join(parts)})" if parts else text
    return f"Left out: {' and '.join(parts)} of removed or disabled targets" if parts else None


def _id_set(ids: Iterable[Any]) -> "set[int]":
    return {i for i in (_int_in(v, 0, 2 ** 62) for v in ids) if i is not None}


# --------------------------------------------------------------------------------------
# the site's network (ARCHITECTURE 3.19 "Networks")
# --------------------------------------------------------------------------------------
def merge_spans(spans: Iterable[Tuple[Any, Any]]) -> List[Tuple[float, float]]:
    """``(start, end)`` spans sorted, overlapping or touching ones merged (spans with an end before their start are dropped)."""
    out: List[Tuple[float, float]] = []
    for s, e in sorted((float(s), float(e)) for s, e in spans if _num(s) is not None and _num(e) is not None and float(e) >= float(s)):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def travel_spans(spells: Iterable[Dict[str, Any]]) -> List[Tuple[float, float]]:
    """``(start, end)`` of the offline spells (``Database.offline_spells``) that were travel: this PC had no network after the
    site's and the next network identified was another one, or it was on another network without a gateway meanwhile (``reason``
    ``lan``: a camera LAN, TNT's DHCP server).  A spell still open, or one that ended back on the same network, is the site's
    own (an outage there counts), unless a trip began less than :data:`LEAVE_MERGE_S` after it ended: the link came back for a
    moment as this PC left, and that spell and moment are the trip too."""
    trips: List[Tuple[float, float]] = []
    own_spells: List[Tuple[float, float]] = []
    for sp in spells or []:
        if not isinstance(sp, dict):
            continue
        s, e = _num(sp.get("start_ts")), _num(sp.get("end_ts"))
        own, nxt = _int_in(sp.get("network_id"), 0, 2 ** 62), _int_in(sp.get("next_network_id"), 0, 2 ** 62)
        if s is None or e is None or own is None:
            continue
        if sp.get("reason") == "lan" or (nxt is not None and nxt != own):
            trips.append((s, max(s, e)))
        elif nxt is not None:
            own_spells.append((s, max(s, e)))
    for s, e in own_spells:
        later = [ts for ts, _te in trips if 0.0 <= ts - e <= LEAVE_MERGE_S]
        if later:
            trips.append((s, min(later)))
    return merge_spans(trips)


def visits_from_minutes(minutes: Iterable[Any], start: float, end: float, gap_s: float = VISIT_GAP_S, breaks: Iterable[Any] = (),
                        spans: Iterable[Tuple[Any, Any]] = ()) -> List[Dict[str, float]]:
    """``[{"start","end"}]`` from the minute buckets of the site's network (``Database.ping_activity_minutes``): minutes further
    apart than *gap_s*, or with a minute of another network between them (*breaks*, ``Database.ping_other_network_minutes``: a
    hop to a neighbour's network) or a trip (*spans*, :func:`travel_spans`), are two visits; a visit runs from its first minute
    to the end of its last, clipped to ``[start, end]``."""
    others = sorted({int(x) for x in breaks or [] if _num(x) is not None})
    trips = merge_spans(spans or [])
    runs: List[List[float]] = []
    j = 0
    for m in sorted({int(x) for x in minutes if _num(x) is not None}):
        if runs:
            last = runs[-1][1] - 60.0
            while j < len(others) and others[j] <= last:
                j += 1
            apart = m - runs[-1][1] > gap_s or (j < len(others) and others[j] < m) or \
                any(ts < m and te > runs[-1][1] for ts, te in trips)
            if not apart:
                runs[-1][1] = m + 60.0
                continue
        runs.append([float(m), m + 60.0])
    out: List[Dict[str, float]] = []
    for s, e in runs:
        s, e = max(s, float(start)), min(e, float(end))
        if e > s:
            out.append({"start": round(s, 3), "end": round(e, 3)})
    return out


def monitored_seconds(visits: Iterable[Dict[str, Any]], gaps: Iterable[Tuple[float, float]] = ()) -> float:
    """Seconds of *visits* without the monitoring gaps inside them (a lid closed at the site for twenty minutes)."""
    spans = merge_spans((v.get("start"), v.get("end")) for v in visits or [] if isinstance(v, dict))
    total = sum(e - s for s, e in spans)
    for gs, ge in merge_spans(gaps):
        for s, e in spans:
            total -= max(0.0, min(e, ge) - max(s, gs))
    return round(max(0.0, total), 1)


def scope_outage_rows(rows: Iterable[Dict[str, Any]], network_id: int, legacy_since: Optional[float] = None,
                      travel: Sequence[Tuple[float, float]] = ()) -> List[Dict[str, Any]]:
    """The outage rows a report of network *network_id* reads: its own, and untagged rows (saved before networks were tagged)
    from *legacy_since* on (clipped there: the time rule).  Then *travel* (:func:`travel_spans`): a row that began less than
    :data:`LEAVE_SLACK_S` before a trip, or during it, is left out (it is the loss of the site's network as this PC left, or the
    trip itself); one that began earlier and was still open when the trip began ends there.  Copies; the input is unchanged."""
    want = int(network_id)
    out: List[Dict[str, Any]] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        s0 = _num(r.get("start_ts"))
        if s0 is None:
            continue
        tag = _int_in(r.get("network_id"), 0, 2 ** 62) if r.get("network_id") is not None else None
        row = dict(r)
        if tag is None:
            if legacy_since is None:
                continue
            e0 = _num(r.get("end_ts"))
            if e0 is not None and not r.get("open") and e0 <= legacy_since:
                continue
            row["start_ts"] = s0 = max(s0, float(legacy_since))
        elif tag != want:
            continue
        keep = True
        for ts, te in travel or ():
            if ts - LEAVE_SLACK_S <= s0 < te:
                keep = False
                break
            e0 = _num(row.get("end_ts"))
            if s0 < ts and (e0 is None or bool(row.get("open")) or e0 > ts):
                row["end_ts"], row["open"] = float(ts), False
        if keep:
            out.append(row)
    return out


def network_time(data: Any) -> Optional[Tuple[float, int]]:
    """``(seconds monitored, visits)`` of a report read on its site's network (``ping.window_reason`` ``site_network``), else None."""
    ping = _section(data, "ping")
    if ping.get("window_reason") != "site_network":
        return None
    visits = [v for v in ping.get("visits") or [] if isinstance(v, dict)]
    monitored = _num(ping.get("monitored_s"))
    return (monitored_seconds(visits) if monitored is None else monitored), len(visits)


def network_time_text(data: Any, fmt: Optional[Callable[[Any], str]] = None) -> Optional[str]:
    """``"23h 37m over 3 visits"`` for a report read on its site's network (*fmt* formats the seconds: :func:`duration_text`, the
    page's way; the PDF passes its own), else None."""
    got = network_time(data)
    if got is None:
        return None
    return f"{(fmt or duration_text)(got[0])} over {_plural(got[1], 'visit')}"


def network_time_note(a_data: Any, b_data: Any) -> Optional[str]:
    """The comparison's note of its sides read on their site's network: ``"On their networks: A 23h 37m over 3 visits; B 8h 00m
    over 1 visit"`` (only such sides), else None.  Their windows and monitored time are not repeated in the row notes."""
    parts = [f"{side} {text}" for side, text in (("A", network_time_text(a_data)), ("B", network_time_text(b_data))) if text]
    return NETWORK_TIME_NOTE + "; ".join(parts) if parts else None


def report_network(report: Any) -> Tuple[Optional[int], Dict[str, Any]]:
    """``(network id, data.meta.network)`` of a stored report: the id from its row (it follows a merge of a provisional network),
    else from ``meta.network``."""
    rep = report if isinstance(report, dict) else {}
    meta = _section(rep.get("data"), "meta")
    net = meta.get("network") if isinstance(meta.get("network"), dict) else {}
    nid = _int_in(rep.get("network_id"), 1, 2 ** 62)
    return (nid if nid is not None else _int_in(net.get("id"), 1, 2 ** 62)), net


def same_network_note(a: Any, b: Any) -> Optional[str]:
    """``"A and B were scanned on the same network (router 02:00:5E:10:00:01)"``, or ``"... (identified by gateway and subnet)"``;
    None when they were not, or one of them has no network."""
    (ida, neta), (idb, netb) = report_network(a), report_network(b)
    if ida is None or ida != idb:
        return None
    mac = neta.get("mac") or netb.get("mac")
    return f"A and B were scanned on the same network ({'router ' + str(mac) if mac else 'identified by gateway and subnet'})"


def build_ping_section(db: Any, start: float, end: float, reason: str, targets: Optional[Sequence[Dict[str, Any]]] = None,
                       gateway: Optional[str] = None, configured: Optional[Sequence[Dict[str, Any]]] = None,
                       left_out: Optional["set[int]"] = None, network: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Per-target statistics for ``[start, end)`` of the targets the report describes, gateway first, then local, then internet:
    *configured*, the rows of the targets table set up when the scan ran (``Database.list_targets(enabled_only=True)``, read here
    when None), which also give a target's host, label and kind where *targets* (the live views) do not.  The minute rows of any
    other id (a target removed since, the old id of a host added again, a disabled target) are left out and counted in ``note``:
    *left_out*, one set for both notes of a report, gains those ids and is what the note counts.  *network*
    (``{"id","legacy_since","travel"}``, the site's network) keeps only that network's minutes, untagged ones from
    ``legacy_since`` on, and none of a trip (:func:`travel_spans`, from :data:`LEAVE_SLACK_S` before it).  ``visits`` are the
    runs of the minutes read (any target), ``monitored_s`` their length (the history phase takes the monitoring gaps off)."""
    section = empty_section("ping", None)
    section.update(window_start=round(float(start), 3), window_end=round(float(end), 3), window_reason=reason)
    if end <= start:
        section["reason"] = ("This PC joined another network during the scan, so there is no ping history"
                             if reason == "network_change" else "The report window is empty")
        return section
    scope: Dict[str, Any] = {}
    if isinstance(network, dict) and network.get("id") is not None:
        scope = {"network_id": int(network["id"]), "legacy_since": network.get("legacy_since"),
                 "exclude": [(float(s) - LEAVE_SLACK_S, float(e)) for s, e in network.get("travel") or []]}
    live: Dict[int, Dict[str, Any]] = {}
    for view in targets or []:
        tid = _int_in(view.get("id") if isinstance(view, dict) else None, 0, 2 ** 62)
        if tid is not None:
            live[tid] = view
    stored: Dict[int, Dict[str, Any]] = {}
    for row in db.list_targets(enabled_only=True) if configured is None else configured:
        tid = _int_in(row.get("id") if isinstance(row, dict) else None, 0, 2 ** 62)
        if tid is not None:
            stored[tid] = row
    out: List[Dict[str, Any]] = []
    skipped: "set[int]" = set()
    for tid in db.ping_target_ids(start, end, **scope):
        row = stored.get(tid)
        if row is None:
            skipped.add(tid)                        # its minutes are not even read
            continue
        stats = ping_stats(db.ping_minute_rows(tid, start, end, **scope))
        if not stats["samples"]:
            continue
        view = live.get(tid) or {}
        host = view.get("host") or row.get("host") or f"target #{tid}"
        ip = view.get("ip") or None
        kind = view.get("kind") if view.get("kind") in ("local", "internet") else row.get("kind")
        out.append({"id": tid, "host": _cap(host), "label": _cap(view.get("label", row.get("label"))), "ip": ip,
                    "role": target_role(host, ip, kind, gateway), **stats})
    rank = {"gateway": 0, "local": 1, "internet": 2}
    out.sort(key=lambda t: (rank.get(t["role"], 3), t["id"]))
    section["targets"] = out
    activity = getattr(db, "ping_activity_minutes", None)
    if callable(activity):
        others = getattr(db, "ping_other_network_minutes", None)
        breaks = others(start, end, scope["network_id"]) if scope and callable(others) else []
        trips = [(s, e) for s, e in (network or {}).get("travel") or []] if scope else []
        section["visits"] = visits_from_minutes(activity(start, end, **scope), start, end, breaks=breaks, spans=trips)
        section["monitored_s"] = monitored_seconds(section["visits"])
    # untagged minutes before the time rule's start were left out (recorded before networks were identified): the page says since when
    legacy = _num(scope.get("legacy_since")) if scope else None
    untagged = getattr(db, "has_untagged_minutes", None)
    section["untagged_since"] = (round(legacy, 3) if legacy is not None and legacy > start and callable(untagged)
                                 and untagged(start, min(legacy, end)) else None)
    if left_out is not None:
        left_out |= skipped
    section["note"] = left_out_note(len(skipped if left_out is None else left_out)) if skipped else None
    if out:
        section["available"] = True
    else:
        section["reason"] = NO_TARGET_PINGS_REASON if skipped else "No pings were recorded in this window"
    return section


def target_name(label: Any, host: Any) -> Optional[str]:
    """A target the way the ping table names it: ``"NVR (172.16.40.20)"``, ``"gateway"``, ``"example.net"``.  An outage row's
    ``"gateway (192.168.10.1)"`` (the address it pinged) is read as its host."""
    host_text = str(host).strip() if isinstance(host, str) and host.strip() else None
    if host_text:
        m = _HOST_IP_RE.match(host_text)
        host_text = m.group(1) if m else host_text
    label_text = str(label).strip() if isinstance(label, str) and label.strip() else None
    if label_text and host_text and label_text.casefold() != host_text.casefold():
        return _cap(f"{label_text} ({host_text})")
    return _cap(label_text or host_text)


def build_outages_section(rows: Iterable[Dict[str, Any]], start: float, end: float, interval_s: float = 1.0,
                          host_for: Optional[Callable[[Any], Optional[str]]] = None,
                          label_for: Optional[Callable[[Any], Optional[str]]] = None,
                          unavailable: Optional[str] = None, target_ids: Optional[Iterable[Any]] = None,
                          left_out: Optional["set[int]"] = None, monitored_s: Optional[float] = None) -> Dict[str, Any]:
    """Outage rows (``OutageTracker.list`` or ``Database.list_outages``) clipped to ``[start, end]`` and read as incidents (the
    method is in the module docstring).  An empty window, or *unavailable* (why there is no history to read: no pings were
    recorded, so no outage could be noticed either), gives the section with nothing counted and ``available`` false.  With
    *target_ids* (the targets set up when the scan ran) a target row of any other id, or of none, is left out before anything is
    counted; ``note`` says how many targets that was (*left_out*, one set for both notes of a report, gains their ids and is what
    it counts; a row without an id counts as an outage only), how many network outages were left out because every target row
    folded into them was (a network outage with no target row at all stays) and how many of the left-out rows were outside
    every network outage.  *monitored_s* (the site's network: its visits without the gaps) replaces the window without its gaps."""
    from .outages import missed_percentage

    section = empty_section("outages", None)
    lo, hi = float(start), float(end)
    section.update(window_start=round(lo, 3), window_end=round(hi, 3))
    if unavailable or hi <= lo:
        section["reason"] = unavailable or "The report window is empty"
        return section
    section["available"] = True
    keep = None if target_ids is None else _id_set(target_ids)
    totals: List[Tuple[float, float, Dict[str, Any]]] = []
    targets: List[Tuple[float, float, Dict[str, Any]]] = []
    dropped: List[Tuple[float, float]] = []
    dropped_ids: "set[int]" = set()
    gaps: List[Tuple[float, float]] = []
    items: List[Dict[str, Any]] = []
    for r in rows or []:
        kind = str(r.get("kind") or "")
        s0 = _num(r.get("start_ts"))
        if kind not in OUTAGE_KINDS or s0 is None:
            continue
        e0 = _num(r.get("end_ts"))
        still_open = e0 is None or bool(r.get("open"))
        s = max(s0, lo)
        e = min(hi if still_open else e0, hi)
        if e <= s:
            continue
        if kind == "target" and keep is not None:
            tid = _int_in(r.get("target_id"), 0, 2 ** 62)
            if tid not in keep:
                # removed or disabled since: only the note counts it.  A row without an id (the tracker never writes one) cannot be
                # told apart from another target's by its host text, so it is counted among the outages only
                dropped.append((s, e))
                if tid is not None:
                    dropped_ids.add(tid)
                continue
        duration = e - s
        if kind not in ("total_local", "total_internet"):
            section["by_kind"][kind] += 1               # totals are counted once it is known they stay (a network outage of left-out targets)
            section["downtime_s"][kind] += duration
        missed = int(_num(r.get("missed")) or 0)
        if "missed_pct" in r:
            pct = _r(r.get("missed_pct"))
        else:
            full = ((hi if still_open else e0) or s0) - s0
            pct = missed_percentage(kind, missed, r.get("sent"), full, interval_s)[1]
        host = r.get("host") or (host_for(r.get("target_id")) if kind == "target" and host_for is not None else None)
        label = label_for(r.get("target_id")) if kind == "target" and label_for is not None and r.get("target_id") is not None else None
        item = {"start_ts": round(s, 3), "end_ts": round(e, 3), "duration_s": round(duration, 1), "kind": kind,
                "host": _cap(host), "missed": missed, "missed_pct": pct, "note": _cap(r.get("note"), NOTE_CAP),
                "open": still_open or (e0 is not None and e0 > hi),
                "name": target_name(label, host) if kind == "target" else None, "targets": []}
        if kind == "gap":
            gaps.append((s, e))
            items.append(item)
        elif kind == "target":
            targets.append((s, e, item))
        else:
            totals.append((s, e, item))
    # network outages: total rows, the ones that overlap (a lost connection opens total_local and total_internet) as one
    nets: List[Dict[str, Any]] = []
    for s, e, row in sorted(totals, key=lambda t: (t[0], t[1])):
        if nets and s <= nets[-1]["end"]:
            net = nets[-1]
            net["end"] = max(net["end"], e)
            net["kinds"].add(row["kind"])
            net["open"] = net["open"] or row["open"]
            net["note"] = net["note"] or row["note"]
            net["rows"].append((s, e, row["kind"]))
        else:
            nets.append({"start": s, "end": e, "kinds": {row["kind"]}, "open": row["open"], "note": row["note"], "members": [],
                         "rows": [(s, e, row["kind"])], "kept": False, "dropped": 0})
    def network_of(s: float, e: float) -> Optional[Dict[str, Any]]:
        return next((n for n in nets if s >= n["start"] - FOLD_SLACK_S and e <= n["end"] + FOLD_SLACK_S), None)

    # a target outage inside a network outage (give or take FOLD_SLACK_S) is one of the targets it took down
    singles: List[Dict[str, Any]] = []
    for s, e, row in sorted(targets, key=lambda t: (t[0], t[1])):
        home = network_of(s, e)
        if home is None:
            singles.append(row)
            continue
        home["kept"] = True
        if row["name"] and row["name"] not in home["members"]:
            home["members"].append(row["name"])
    for s, e in dropped:
        home = network_of(s, e)
        if home is not None:
            home["dropped"] += 1
    # a network outage whose every folded target row was left out is about targets the report does not describe: left out too
    left_nets = [n for n in nets if n["dropped"] and not n["kept"]]
    kept_nets = [n for n in nets if not (n["dropped"] and not n["kept"])]      # network_of keeps looking at every one
    for net in kept_nets:
        for s, e, kind in net["rows"]:
            section["by_kind"][kind] += 1
            section["downtime_s"][kind] += e - s
    for net in kept_nets:
        duration = net["end"] - net["start"]
        items.append({"start_ts": round(net["start"], 3), "end_ts": round(net["end"], 3), "duration_s": round(duration, 1),
                      "kind": "total_local" if "total_local" in net["kinds"] else "total_internet", "host": None, "missed": 0,
                      "missed_pct": None, "note": net["note"], "open": net["open"], "name": None, "targets": net["members"]})
    items.extend(singles)
    not_monitored = 0.0
    cur: Optional[List[float]] = None
    for s, e in sorted(gaps):
        if cur is not None and s <= cur[1]:
            cur[1] = max(cur[1], e)
            continue
        if cur is not None:
            not_monitored += cur[1] - cur[0]
        cur = [s, e]
    if cur is not None:
        not_monitored += cur[1] - cur[0]
    items.sort(key=lambda it: (it["start_ts"], it["end_ts"]), reverse=True)
    if left_out is not None:
        left_out |= dropped_ids
    # left-out rows outside every network outage (a left-out network outage's members are counted as that network outage)
    left_singles = sum(1 for s, e in dropped if network_of(s, e) is None)
    monitored = _num(monitored_s)
    section.update(
        note=left_out_note(len(dropped_ids if left_out is None else left_out), left_singles, len(left_nets)) if dropped else None,
        count=len(kept_nets) + len(singles),
        network_outages=len(kept_nets),
        target_outages=len(singles),
        downtime_s={k: round(v, 1) for k, v in section["downtime_s"].items()},
        network_down_s=round(sum(n["end"] - n["start"] for n in kept_nets), 1),
        longest_s=round(max(n["end"] - n["start"] for n in kept_nets), 1) if kept_nets else None,
        monitored_s=round(max(0.0, monitored), 1) if monitored is not None else round(max(0.0, hi - lo - not_monitored), 1),
        items=items[:MAX_OUTAGE_ITEMS],
        items_total=len(items),
    )
    return section


def build_discovery_section(run: Any, gateways: Iterable[str] = (), error: Optional[str] = None,
                            note: Optional[str] = None) -> Dict[str, Any]:
    """A stored discovery run (``Database.get_discovery_run``) with device types filled in (the gateways given,
    never a fresh adapter enumeration)."""
    section = empty_section("discovery", error or "No Discovery scan ran")
    if not isinstance(run, dict):
        return section
    hosts = [h for h in run.get("hosts") or [] if isinstance(h, dict) and h.get("ip")]
    try:
        from .discovery import fill_device_types

        fill_device_types(hosts, gateways=[g for g in gateways if g])
    except Exception:  # noqa: BLE001 - the types are a nicety
        log.debug("device types unavailable for the report", exc_info=True)
    types = Counter(str(h["device_type"]) for h in hosts if h.get("device_type"))
    ordered = {t: types[t] for t in DEVICE_TYPE_ORDER if types.get(t)}
    ordered.update({t: n for t, n in sorted(types.items()) if t not in ordered})
    section.update(
        available=True, reason=None, run_id=run.get("id"), range=run.get("cidr"), started_ts=run.get("ts"),
        duration_s=_r(run.get("duration_s"), 1), host_count=len(hosts), device_types=ordered, note=note,
        hosts=[{"ip": h.get("ip"), "hostname": _cap(h.get("hostname")), "mac": h.get("mac"), "vendor": _cap(h.get("vendor")),
                "device_type": h.get("device_type"),
                "open_ports": [int(p) for p in h.get("open_ports") or [] if _int_in(p, 1, 65535) is not None][:MAX_HOST_PORTS]}
               for h in hosts[:MAX_HOSTS]],
        hosts_total=len(hosts),
    )
    return section


def _clean_ap(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    bssid = _mac(raw.get("bssid"))
    rssi = _num(raw.get("rssi"))
    if bssid is None or rssi is None or not -127 <= rssi <= 0:
        return None
    ssid = _text(raw.get("ssid"), 64, strip=False) or ""
    band = raw.get("band")
    if isinstance(band, (int, float)) and not isinstance(band, bool):
        band = f"{band:g}"
    oui, local, base = oui_parts(bssid)
    return {
        "bssid": bssid,
        "ssid": ssid,
        "hidden": raw["hidden"] if isinstance(raw.get("hidden"), bool) else not ssid.strip(),
        "rssi": int(round(rssi)),
        "band": band if band in BANDS else None,
        "channel": _int_in(raw.get("channel"), 1, 233),
        "center_channel": _int_in(raw.get("center_channel"), 1, 233),
        "width_mhz": _int_in(raw.get("width_mhz"), 5, 320),
        "security": _text(raw.get("security"), 48) or None,
        "generation": _text(raw.get("generation"), 16) or None,
        "connected": raw.get("connected") is True,
        "stale": raw.get("stale") is True,
        "oui": oui,
        "locally_administered": local,
        "base_oui": base,
        "vendor": _vendor(base if local else oui),
    }


def clean_wifi_snapshot(body: Any, now: Optional[float] = None) -> Dict[str, Any]:
    """Validate and trim a posted Wi-Fi survey snapshot.  ``ValueError`` (HTTP 400) for a body of the wrong shape:
    ``available`` not a bool, ``state``/``error`` not text, ``collected_ts`` not epoch seconds, ``interfaces``
    or ``aps`` not lists, more than :data:`MAX_POST_APS` access points.  Single access points that are not
    usable (no valid BSSID, no signal in -127..0 dBm) are dropped and counted in ``dropped``; duplicates of
    one BSSID keep the fresh, strongest copy.  The OUI fields and ``vendor`` are derived here."""
    if not isinstance(body, dict):
        raise ValueError("the Wi-Fi snapshot must be a JSON object")
    available = body.get("available")
    if not isinstance(available, bool):
        raise ValueError("available must be true or false")
    state = body.get("state")
    if state is not None and not isinstance(state, str):
        raise ValueError("state must be text")
    state = re.sub(r"[^a-z0-9_]", "", (state or "").strip().lower())[:32] or ("ok" if available else "unavailable")
    error = body.get("error")
    if error is not None and not isinstance(error, str):
        raise ValueError("error must be text or null")
    collected = body.get("collected_ts")
    if collected is None:
        collected_ts = float(now if now is not None else time.time())
    else:
        collected_ts = _num(collected)
        if collected_ts is None or not 0.0 <= collected_ts <= MAX_EPOCH_S:
            raise ValueError("collected_ts must be epoch seconds")
    interfaces = body.get("interfaces")
    if interfaces is not None and not isinstance(interfaces, list):
        raise ValueError("interfaces must be a list")
    aps = body.get("aps")
    if aps is not None and not isinstance(aps, list):
        raise ValueError("aps must be a list")
    aps = aps or []
    if len(aps) > MAX_POST_APS:
        raise ValueError(f"at most {MAX_POST_APS} access points per snapshot, got {len(aps)}")
    clean_ifaces = []
    for iface in (interfaces or [])[:MAX_POST_INTERFACES]:
        if isinstance(iface, dict):
            clean_ifaces.append({"description": _text(iface.get("description"), 128) or None,
                                 "state": _text(iface.get("state"), 32) or None,
                                 "connected_bssid": _mac(iface.get("connected_bssid")),
                                 "connected_ssid": _text(iface.get("connected_ssid"), 64, strip=False) or None})
    kept: Dict[str, Dict[str, Any]] = {}
    dropped = 0
    for raw in aps:
        ap = _clean_ap(raw)
        if ap is None:
            dropped += 1
            continue
        prev = kept.get(ap["bssid"])
        if prev is None or (ap["stale"], -ap["rssi"]) < (prev["stale"], -prev["rssi"]):
            kept[ap["bssid"]] = ap
    return {"available": available, "state": state, "error": _text(error, 300) or None,
            "collected_ts": round(collected_ts, 3), "interfaces": clean_ifaces, "aps": list(kept.values()),
            "dropped": dropped}


def wifi_reason(snapshot: Dict[str, Any]) -> str:
    """Why an unavailable snapshot has no data: its own error text, else a sentence for its state."""
    return str(snapshot.get("error") or WIFI_STATE_TEXT.get(str(snapshot.get("state") or ""))
               or "Wi-Fi could not be scanned")


def channel_span(ap: Dict[str, Any]) -> Optional[Tuple[float, float]]:
    """``(centre MHz, width MHz)`` of the channel an access point occupies: the centre of its (bonded) channel, else its primary
    channel, and 20 MHz when the width is unknown; None without a band and channel."""
    band = ap.get("band")
    ch = ap.get("center_channel") or ap.get("channel")
    if band not in BANDS or not isinstance(ch, int) or isinstance(ch, bool):
        return None
    if band == "2.4":
        centre = 2484.0 if ch == 14 else 2407.0 + 5.0 * ch
    elif band == "5":
        centre = 5000.0 + 5.0 * ch
    else:
        centre = 5950.0 + 5.0 * ch
    width = _num(ap.get("width_mhz"))
    return centre, (width if width and width > 0 else 20.0)


def channels_overlap(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """Whether two access points of one band occupy overlapping spectrum (their spans' centres closer than half their widths)."""
    sa, sb = channel_span(a), channel_span(b)
    if sa is None or sb is None or a.get("band") != b.get("band"):
        return False
    return abs(sa[0] - sb[0]) < (sa[1] + sb[1]) / 2.0 - 1e-9


def build_wifi_section(snapshot: Any, reason: Optional[str] = None) -> Dict[str, Any]:
    """The Wi-Fi section from a :func:`clean_wifi_snapshot` result (None: nothing was posted)."""
    section = empty_section("wifi", reason or NO_WINDOW_REASON)
    if not isinstance(snapshot, dict):
        return section
    interfaces = [i for i in snapshot.get("interfaces") or [] if isinstance(i, dict)]
    iface = next((i for i in interfaces if i.get("connected_bssid") or i.get("connected_ssid")), None)
    iface = iface or (interfaces[0] if interfaces else None)
    section.update(state=snapshot.get("state"), collected_ts=snapshot.get("collected_ts"),
                   adapter=(iface or {}).get("description"))
    if not snapshot.get("available"):
        section["reason"] = wifi_reason(snapshot)
        return section
    every = [a for a in snapshot.get("aps") or [] if isinstance(a, dict)]
    aps = [a for a in every if not a.get("stale")] or every
    aps.sort(key=lambda a: (-int(a["rssi"]), a["bssid"]))
    bssids = {i.get("connected_bssid") for i in interfaces if i.get("connected_bssid")}
    connected = next((a for a in aps if a.get("connected")), None) or next((a for a in aps if a["bssid"] in bssids), None)
    if connected is not None:
        same = [a for a in aps if connected.get("channel") is not None and a.get("band") == connected.get("band")
                and a.get("channel") == connected.get("channel")]
        overlapping = [a for a in aps if channels_overlap(a, connected)]
        section["connected"] = {"ssid": connected.get("ssid"), "bssid": connected["bssid"], "rssi": connected["rssi"],
                                "band": connected.get("band"), "channel": connected.get("channel"),
                                "width_mhz": connected.get("width_mhz"), "channel_aps": len(same),
                                "overlap_aps": len(overlapping) if channel_span(connected) is not None else None}
    elif iface is not None and (iface.get("connected_bssid") or iface.get("connected_ssid")):
        section["connected"] = {"ssid": iface.get("connected_ssid"), "bssid": iface.get("connected_bssid"), "rssi": None,
                                "band": None, "channel": None, "width_mhz": None, "channel_aps": None, "overlap_aps": None}
    section.update(
        available=True, reason=None,
        networks=len({a["ssid"] for a in aps if a.get("ssid") and not a.get("hidden")}),
        aps_count=len(aps),
        bands={b: _band_stats([a for a in aps if a.get("band") == b]) for b in BANDS},
        aps=[{k: a.get(k) for k in ("ssid", "hidden", "bssid", "band", "channel", "width_mhz", "rssi", "security",
                                    "generation", "vendor", "connected")} for a in aps[:MAX_APS]],
        aps_total=len(aps),
    )
    return section


# --------------------------------------------------------------------------------------
# summary and comparison
# --------------------------------------------------------------------------------------
def _section(data: Any, key: str) -> Dict[str, Any]:
    sec = data.get(key) if isinstance(data, dict) else None
    return sec if isinstance(sec, dict) else {}


def _available(data: Any, key: str) -> Optional[Dict[str, Any]]:
    sec = _section(data, key)
    return sec if sec.get("available") else None


def rename_legacy_device_types(report: Any) -> Any:
    """A saved report (``Database.get_report``) with the device types older versions stored renamed, in place
    (``tnt.discovery.LEGACY_DEVICE_TYPES``: 1.11 and older said "Wifi"), so it reads and compares like a new one."""
    sec = _section(report.get("data") if isinstance(report, dict) else None, "discovery")
    if not sec:
        return report
    try:
        from .discovery import LEGACY_DEVICE_TYPES

        types = sec.get("device_types")
        if isinstance(types, dict) and any(t in LEGACY_DEVICE_TYPES for t in types):
            sec["device_types"] = {LEGACY_DEVICE_TYPES.get(t, t): n for t, n in types.items()}
        for h in sec.get("hosts") or []:
            old = h.get("device_type") if isinstance(h, dict) else None
            if isinstance(old, str) and old in LEGACY_DEVICE_TYPES:
                h["device_type"] = LEGACY_DEVICE_TYPES[old]
    except Exception:  # noqa: BLE001 - the new names are a nicety; the report still reads
        log.debug("could not rename the device types of a saved report", exc_info=True)
    return report


def gateway_target(ping: Any) -> Optional[Dict[str, Any]]:
    """The ``gateway`` target with the most samples, or None."""
    if not isinstance(ping, dict) or not ping.get("available"):
        return None
    found = [t for t in ping.get("targets") or [] if isinstance(t, dict) and t.get("role") == "gateway"
             and (t.get("samples") or 0) > 0]
    return max(found, key=lambda t: t.get("samples") or 0) if found else None


def internet_totals(ping: Any) -> Tuple[Optional[float], Optional[float]]:
    """``(avg_ms, loss_pct)`` over every internet target: the average weighted by replies, the loss by samples."""
    if not isinstance(ping, dict) or not ping.get("available"):
        return None, None
    return _target_totals([t for t in ping.get("targets") or [] if isinstance(t, dict) and t.get("role") == "internet"])


def _target_totals(targets: Sequence[Dict[str, Any]]) -> Tuple[Optional[float], Optional[float]]:
    samples = sum(int(t.get("samples") or 0) for t in targets)
    lost = sum(int(t.get("lost") or 0) for t in targets)
    weighted, replies = 0.0, 0
    for t in targets:
        rec = int(t.get("samples") or 0) - int(t.get("lost") or 0)
        avg = _num(t.get("avg_ms"))
        if rec > 0 and avg is not None:
            weighted += avg * rec
            replies += rec
    return (round(weighted / replies, 2) if replies else None), (round(100.0 * lost / samples, 2) if samples else None)


def build_summary(data: Dict[str, Any]) -> Dict[str, Any]:
    """The key numbers of a report (lists, the tile and quick comparisons)."""
    speed = _available(data, "speed") or {}
    result = speed.get("result") if isinstance(speed.get("result"), dict) else {}
    ping = _section(data, "ping")
    gateway = gateway_target(ping) or {}
    inet_avg, inet_loss = internet_totals(ping)
    outages = _available(data, "outages")
    discovery = _available(data, "discovery")
    wifi = _available(data, "wifi")
    start = _num(ping.get("window_start"))
    end = _num(ping.get("window_end"))
    # read on the site's network: the hours monitored there (its visits), not the seven days
    monitored = _num(ping.get("monitored_s")) if ping.get("window_reason") == "site_network" else None
    return {
        "download_mbps": _r(result.get("download_mbps")),
        "upload_mbps": _r(result.get("upload_mbps")),
        "latency_ms": _r(result.get("latency_ms")),
        "gateway_avg_ms": _r(gateway.get("avg_ms")),
        "gateway_loss_pct": _r(gateway.get("loss_pct")),
        "internet_avg_ms": inet_avg,
        "internet_loss_pct": inet_loss,
        "outages": int(outages.get("count") or 0) if outages else None,
        "downtime_s": _r(outages.get("network_down_s"), 1) if outages else None,
        "hosts": int(discovery.get("host_count") or 0) if discovery else None,
        "wifi_aps": int(wifi.get("aps_count") or 0) if wifi else None,
        "wifi_networks": int(wifi.get("networks") or 0) if wifi else None,
        "wifi_connected_rssi": ((wifi.get("connected") or {}).get("rssi")) if wifi else None,
        "window_hours": (round(monitored / 3600.0, 1) if monitored is not None
                         else round((end - start) / 3600.0, 1) if start is not None and end is not None else None),
    }


def compare_row(key: str, label: str, unit: str, a: Any, b: Any, higher_is_better: Optional[bool],
                note: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """One comparison row, or None when neither side has a value.  ``delta_pct`` is None when B is 0 and for
    dBm (a logarithmic unit: a percentage of a signal level means nothing)."""
    av, bv = _r(a), _r(b)
    if av is None and bv is None:
        return None
    delta = delta_pct = better = None
    if av is not None and bv is not None:
        delta = round(av - bv, 2)
        delta_pct = round(100.0 * (av - bv) / abs(bv), 1) if bv and unit != "dBm" else None
        if higher_is_better is not None:
            tolerance = max(UNIT_TOLERANCE.get(unit, 0.0), SAME_REL * max(abs(av), abs(bv)))
            if abs(av - bv) <= tolerance + 1e-9:
                better = "same"
            else:
                better = "a" if (av > bv) == bool(higher_is_better) else "b"
    return {"key": key, "label": label, "unit": unit, "a": av, "b": bv, "delta": delta, "delta_pct": delta_pct,
            "better": better, "higher_is_better": higher_is_better, "note": note}


def _rows(*rows: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [r for r in rows if r is not None]


def _window_len(section: Dict[str, Any]) -> Optional[float]:
    start, end = _num(section.get("window_start")), _num(section.get("window_end"))
    return None if start is None or end is None else max(0.0, end - start)


def _windows_note(sa: Dict[str, Any], sb: Dict[str, Any], da: Any = None, db_: Any = None) -> Optional[str]:
    """``"Windows: A 6.0 days, B 30 min"`` of the sides read by time; a side read on its site's network is left out (its time
    there is the comparison's own note, :func:`network_time_note`), and with both such sides there is no note."""
    wa, wb = _window_len(sa), _window_len(sb)
    if wa is None and wb is None:
        return None
    parts = [f"{side} {span_text(w)}" for side, w, data in (("A", wa, da), ("B", wb, db_)) if network_time(data) is None]
    return "Windows: " + ", ".join(parts) if parts else None


def _is_wifi_adapter(nic: Dict[str, Any]) -> bool:
    text = " ".join(str(nic.get(k) or "") for k in ("type_name", "name", "description")).casefold()
    return any(word in text for word in ("wi-fi", "wifi", "wireless", "wlan", "802.11"))


def _bps_text(bps: Any) -> Optional[str]:
    v = _num(bps)
    if v is None or v <= 0:
        return None
    if v >= 1e9:
        return f"{round(v / 1e9, 1):g} Gbps"
    return f"{round(v / 1e6):g} Mbps" if v >= 1e6 else f"{round(v / 1e3):g} kbps"


def link_text(data: Any) -> Optional[str]:
    """How a report's PC reached the internet: ``"Wi-Fi 2.4 GHz, 144 Mbps link"``, ``"Ethernet, 1 Gbps link"``, or None."""
    nic = (_available(data, "network") or {}).get("internet_nic")
    if not isinstance(nic, dict):
        return None
    kind = str(nic.get("type_name") or nic.get("name") or "").strip()
    wifi = _available(data, "wifi") or {}
    band = (wifi.get("connected") or {}).get("band")
    if kind and band and _is_wifi_adapter(nic):
        kind += f" {band} GHz"
    speed = _bps_text(nic.get("link_bps"))
    parts = [p for p in (kind, f"{speed} link" if speed else None) if p]
    return ", ".join(parts) or None


def _compare_speed(da: Dict[str, Any], db_: Dict[str, Any], _ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    ra = (_available(da, "speed") or {}).get("result") or {}
    rb = (_available(db_, "speed") or {}).get("result") or {}
    notes = []
    la, lb = link_text(da), link_text(db_)
    if la and lb and la != lb:
        notes.append(f"Links: A {la}; B {lb}")
    sa, sb = ra.get("server") or ra.get("backend"), rb.get("server") or rb.get("backend")
    if sa and sb and sa != sb:
        notes.append(f"Servers: A {sa}; B {sb}")
    wa, wb = _section(_section(da, "speed"), "window"), _section(_section(db_, "speed"), "window")
    window_note = None
    if wa.get("count") or wb.get("count"):
        window_note = f"A: {_plural(wa.get('count'), 'test')}; B: {_plural(wb.get('count'), 'test')}"

    def link_mbps(data: Dict[str, Any]) -> Optional[float]:
        nic = (_available(data, "network") or {}).get("internet_nic")
        bps = _num(nic.get("link_bps")) if isinstance(nic, dict) else None
        return bps / 1e6 if bps and bps > 0 else None

    return _rows(
        compare_row("download_mbps", "Download", "Mbps", ra.get("download_mbps"), rb.get("download_mbps"), True, "; ".join(notes) or None),
        compare_row("upload_mbps", "Upload", "Mbps", ra.get("upload_mbps"), rb.get("upload_mbps"), True),
        compare_row("latency_ms", "Latency", "ms", ra.get("latency_ms"), rb.get("latency_ms"), False),
        compare_row("jitter_ms", "Jitter", "ms", ra.get("jitter_ms"), rb.get("jitter_ms"), False),
        compare_row("packet_loss_pct", "Packet loss", "%", ra.get("packet_loss_pct"), rb.get("packet_loss_pct"), False),
        compare_row("download_window_avg", "Download, average in the window", "Mbps",
                    wa.get("download_avg") if wa.get("count") else None, wb.get("download_avg") if wb.get("count") else None,
                    None, window_note),
        compare_row("link_mbps", "Adapter link speed", "Mbps", link_mbps(da), link_mbps(db_), None),
    )


def _internet_by_host(ping: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if not ping.get("available"):
        return out
    for t in ping.get("targets") or []:
        if isinstance(t, dict) and t.get("role") == "internet" and t.get("host"):
            key = str(t["host"]).strip().casefold()
            if key not in out or (t.get("samples") or 0) > (out[key].get("samples") or 0):
                out[key] = t
    return out


def _names_text(names: Sequence[Any], most: int = 4) -> str:
    shown = [str(n) for n in names[:most]]
    return ", ".join(shown) + (f" and {len(names) - most} more" if len(names) > most else "")


def _compare_ping(da: Dict[str, Any], db_: Dict[str, Any], _ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    pa, pb = _section(da, "ping"), _section(db_, "ping")
    ga, gb = gateway_target(pa) or {}, gateway_target(pb) or {}
    hosts_a, hosts_b = _internet_by_host(pa), _internet_by_host(pb)
    shared = sorted(set(hosts_a) & set(hosts_b))
    if shared:
        # the same targets on both sides: a distant server only one report pinged would tip the combined numbers
        ia, ib = _target_totals([hosts_a[k] for k in shared]), _target_totals([hosts_b[k] for k in shared])
        inet_label, inet_scored = "Internet average (targets in both)", False
        inet_note = "Targets in both: " + _names_text([hosts_a[k].get("label") or hosts_a[k].get("host") for k in shared])
        loss_label = "Internet loss (targets in both)"
    else:
        ia, ib = internet_totals(pa), internet_totals(pb)
        inet_label, inet_scored, loss_label = "Internet average (all targets)", None, "Internet loss (all targets)"
        inet_note = ("No internet target is in both reports: each report's own targets, for information"
                     if ia[0] is not None and ib[0] is not None else None)
    rows = _rows(
        compare_row("gateway_avg_ms", "Gateway average", "ms", ga.get("avg_ms"), gb.get("avg_ms"), False),
        compare_row("gateway_p95_ms", "Gateway p95 of 1-min averages", "ms", ga.get("p95_ms"), gb.get("p95_ms"), False),
        compare_row("gateway_max_ms", "Gateway maximum (one ping)", "ms", ga.get("max_ms"), gb.get("max_ms"), None),
        compare_row("gateway_loss_pct", "Gateway loss", "%", ga.get("loss_pct"), gb.get("loss_pct"), False),
        compare_row("internet_avg_ms", inet_label, "ms", ia[0], ib[0], inet_scored, inet_note),
        compare_row("internet_loss_pct", loss_label, "%", ia[1], ib[1], inet_scored),
    )
    for key in shared:
        ta, tb = hosts_a[key], hosts_b[key]
        name = ta.get("label") or ta.get("host")
        rows += _rows(compare_row(f"host:{key}:avg_ms", f"{name} average", "ms", ta.get("avg_ms"), tb.get("avg_ms"), False),
                      compare_row(f"host:{key}:loss_pct", f"{name} loss", "%", ta.get("loss_pct"), tb.get("loss_pct"), False))
    if rows:
        rows[0]["note"] = _windows_note(pa, pb, da, db_)
    return rows


def outage_numbers(section: Any) -> Optional[Dict[str, Any]]:
    """What a comparison reads from an available outages section: ``{"window", "monitored", "network", "down", "longest",
    "targets"}`` (seconds and counts; ``monitored`` is the window without the time not monitored), else None."""
    if not isinstance(section, dict) or not section.get("available"):
        return None
    window = _window_len(section) or 0.0
    monitored = _num(section.get("monitored_s"))
    monitored = window if monitored is None else max(0.0, min(monitored, window))
    by_kind = section.get("by_kind") if isinstance(section.get("by_kind"), dict) else {}
    network = _num(section.get("network_outages"))
    targets = _num(section.get("target_outages"))
    return {"window": window, "monitored": monitored,
            "network": int(network if network is not None else (by_kind.get("total_local") or 0) + (by_kind.get("total_internet") or 0)),
            "down": _num(section.get("network_down_s")) or 0.0, "longest": _num(section.get("longest_s")) or 0.0,
            "targets": int(targets if targets is not None else by_kind.get("target") or 0)}


def monitored_text(numbers: Dict[str, Any]) -> str:
    """``"54.4 h of 62.4 h"`` when part of the window was not monitored, else the window: ``"7.0 days"``."""
    if numbers["window"] - numbers["monitored"] >= 60.0:
        return f"{span_text(numbers['monitored'])} of {span_text(numbers['window'])}"
    return span_text(numbers["window"])


def _compare_outages(da: Dict[str, Any], db_: Dict[str, Any], _ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    na, nb = outage_numbers(_section(da, "outages")), outage_numbers(_section(db_, "outages"))
    if na is None and nb is None:
        return []
    # the sides read by time say how much of their window was monitored; one read on its site's network is in the comparison's note
    by_time = [f"{side} {monitored_text(n)}" for side, n, data in (("A", na, da), ("B", nb, db_)) if n and network_time(data) is None]
    note = ("Monitored: " + "; ".join(by_time)) if by_time else ""
    if na is not None and nb is not None and na["monitored"] >= MIN_RATE_S and nb["monitored"] >= MIN_RATE_S:
        # rates per day monitored: a laptop that slept at the site is not judged against an always-on reference's week
        def per_day(n: Dict[str, Any], value: float) -> float:
            return value / (n["monitored"] / 86400.0)

        return _rows(
            compare_row("outages_per_day", "Network outages per day", "per day", per_day(na, na["network"]),
                        per_day(nb, nb["network"]), False, note or None),
            compare_row("downtime_min_per_day", "Network downtime per day", "min/day", per_day(na, na["down"] / 60.0),
                        per_day(nb, nb["down"] / 60.0), False),
            compare_row("longest_outage_min", "Longest network outage", "min", na["longest"] / 60.0, nb["longest"] / 60.0, False),
            compare_row("target_outages_per_day", "Single-target outages per day", "per day", per_day(na, na["targets"]),
                        per_day(nb, nb["targets"]), None),
        )
    # too little history on either side: the sides read by time say how much they had (a side of its site's network has it in the
    # comparison's note already)
    shorts = [(side, n, data) for side, n, data in (("A", na, da), ("B", nb, db_)) if n and n["monitored"] < MIN_RATE_S]
    short = [f"{side} {span_text(n['monitored'])}" for side, n, data in shorts if network_time(data) is None]
    if shorts:
        note += (". " if note else "") + "Too little history for daily rates (" + \
            (f"{', '.join(short)}; " if short else "") + "a day on each side is needed): the counts of each window"

    def pick(n: Optional[Dict[str, Any]], key: str, scale: float = 1.0) -> Optional[float]:
        return None if n is None else n[key] / scale

    return _rows(
        compare_row("network_outages", "Network outages", "outages", pick(na, "network"), pick(nb, "network"), None, note or None),
        compare_row("downtime_min", "Network downtime", "min", pick(na, "down", 60.0), pick(nb, "down", 60.0), None),
        compare_row("longest_outage_min", "Longest network outage", "min", pick(na, "longest", 60.0), pick(nb, "longest", 60.0), None),
        compare_row("target_outages", "Single-target outages", "outages", pick(na, "targets"), pick(nb, "targets"), None),
    )


def _ssid_strongest(wifi: Optional[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for ap in (wifi or {}).get("aps") or []:
        if isinstance(ap, dict) and ap.get("ssid") and not ap.get("hidden") and _num(ap.get("rssi")) is not None:
            out[ap["ssid"]] = max(out.get(ap["ssid"], -1000), int(ap["rssi"]))
    return out


def _band_signals(wifi: Optional[Dict[str, Any]], band: str, own_ssid: Optional[str]) -> Tuple[Optional[int], Optional[int], Optional[float]]:
    """``(the own network's best signal, the strongest other network, the median of the other access points)`` in *band*,
    from the report's access points (the strongest 200); the own network is the SSID this PC was connected to."""
    own: List[int] = []
    other: List[int] = []
    for ap in (wifi or {}).get("aps") or []:
        if not isinstance(ap, dict) or ap.get("band") != band or _num(ap.get("rssi")) is None:
            continue
        (own if own_ssid and ap.get("ssid") == own_ssid else other).append(int(ap["rssi"]))
    return (max(own) if own else None, max(other) if other else None,
            _r(statistics.median(other), 1) if other else None)


def connection_text(wifi: Optional[Dict[str, Any]]) -> str:
    """``"Northside-Ops (2.4 GHz, channel 6, 20 MHz)"``, ``"not connected"`` or ``"no Wi-Fi scan"``."""
    if not wifi:
        return "no Wi-Fi scan"
    conn = wifi.get("connected") if isinstance(wifi.get("connected"), dict) else None
    if not conn:
        return "not connected"
    where = [f"{conn['band']} GHz" if conn.get("band") else None,
             f"channel {conn['channel']}" if conn.get("channel") is not None else None,
             f"{conn['width_mhz']} MHz" if conn.get("width_mhz") else None]
    where_text = ", ".join(w for w in where if w)
    return (conn.get("ssid") or "a hidden network") + (f" ({where_text})" if where_text else "")


def _compare_wifi(da: Dict[str, Any], db_: Dict[str, Any], ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    wa, wb = _available(da, "wifi"), _available(db_, "wifi")
    if wa is None and wb is None:
        return []
    ca, cb = (wa or {}).get("connected") or {}, (wb or {}).get("connected") or {}
    note = f"A: {connection_text(wa)}; B: {connection_text(wb)}" if ca or cb else None
    rows = _rows(
        compare_row("connected_rssi", "Connected signal", "dBm", ca.get("rssi"), cb.get("rssi"), True, note),
        compare_row("connected_channel_aps", "APs on the connected channel", "APs", ca.get("channel_aps"),
                    cb.get("channel_aps"), False),
        compare_row("connected_overlap_aps", "APs overlapping the connected channel", "APs", ca.get("overlap_aps"),
                    cb.get("overlap_aps"), False),
    )
    own_a, own_b = ca.get("ssid") or None, cb.get("ssid") or None
    for band in BANDS:
        ba = ((wa or {}).get("bands") or {}).get(band) or {}
        bb = ((wb or {}).get("bands") or {}).get(band) or {}
        if not (ba.get("aps") or bb.get("aps")):
            continue
        label = f"{band} GHz"
        channels = None
        if ba.get("busiest_channel") is not None or bb.get("busiest_channel") is not None:
            def channel(b: Dict[str, Any]) -> str:
                return str(b["busiest_channel"]) if b.get("busiest_channel") is not None else "none"

            channels = f"Busiest channel: {channel(ba)} vs {channel(bb)}"
        sig_a, sig_b = _band_signals(wa, band, own_a), _band_signals(wb, band, own_b)
        # the site's own network is judged; the neighbours' networks are only shown (a strong neighbour is no merit)
        rows += _rows(
            compare_row(f"band_{band}_own_rssi", f"Own network best signal, {label}", "dBm", sig_a[0], sig_b[0], True),
            compare_row(f"band_{band}_other_rssi", f"Strongest other network, {label}", "dBm", sig_a[1], sig_b[1], None),
            compare_row(f"band_{band}_median_rssi", f"Median signal of other APs, {label}", "dBm", sig_a[2], sig_b[2], None),
            compare_row(f"band_{band}_networks", f"Networks visible, {label}", "networks",
                        ba.get("networks", 0) if wa else None, bb.get("networks", 0) if wb else None, None),
            compare_row(f"band_{band}_busiest_channel_aps", f"APs on the busiest channel, {label}", "APs",
                        ba.get("busiest_channel_aps"), bb.get("busiest_channel_aps"), False, channels),
        )
    if ctx.get("same_site"):
        # two scans of one site: every network seen in both, the one this PC used judged, the others shown
        sa, sb = _ssid_strongest(wa), _ssid_strongest(wb)
        mine = {s for s in (own_a, own_b) if s}
        shared = sorted(set(sa) & set(sb), key=lambda s: (s not in mine, -max(sa[s], sb[s]), s))[:MAX_COMPARE_SSIDS]
        for ssid in shared:
            rows += _rows(compare_row(f"ssid:{ssid}", f'"{ssid}" strongest signal', "dBm", sa[ssid], sb[ssid],
                                      True if ssid in mine else None))
    return rows


def _compare_discovery(da: Dict[str, Any], db_: Dict[str, Any], _ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    xa, xb = _available(da, "discovery"), _available(db_, "discovery")
    if xa is None and xb is None:
        return []
    rows = _rows(compare_row("hosts", "Devices found", "devices", xa.get("host_count") if xa else None,
                             xb.get("host_count") if xb else None, None))
    ta, tb = (xa or {}).get("device_types") or {}, (xb or {}).get("device_types") or {}
    types = [t for t in DEVICE_TYPE_ORDER if t in ta or t in tb]
    types += sorted(t for t in set(ta) | set(tb) if t not in types)
    for t in types:
        rows += _rows(compare_row(f"type:{t}", t, "devices", ta.get(t, 0) if xa else None, tb.get(t, 0) if xb else None, None))
    return rows


COMPARE_SECTIONS: Tuple[Tuple[str, str, Callable[[Dict[str, Any], Dict[str, Any], Dict[str, Any]], List[Dict[str, Any]]]], ...] = (
    ("speed", "Speed test", _compare_speed),
    ("ping", "Ping", _compare_ping),
    ("outages", "Outages", _compare_outages),
    ("wifi", "Wi-Fi", _compare_wifi),
    ("discovery", "Discovery", _compare_discovery),
)


def compare_reports(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """The comparison payload of two stored reports (``Database.get_report`` dicts); rules in the module docstring."""
    da = a.get("data") if isinstance(a.get("data"), dict) else {}
    db_ = b.get("data") if isinstance(b.get("data"), dict) else {}
    key_a, key_b = site_key(a.get("site")), site_key(b.get("site"))
    ctx = {"same_site": bool(key_a) and key_a == key_b}
    sections = []
    for key, title, fn in COMPARE_SECTIONS:
        notes = []
        for side, data in (("A", da), ("B", db_)):
            sec = _section(data, key)
            if not sec.get("available"):
                notes.append(f"{side}: {sec.get('reason') or 'not collected'}")
        if key in ("ping", "outages"):
            # a report saved before removed targets were left out has no note in these sections, and its numbers may count them
            secs = {side: _section(data, key) for side, data in (("A", da), ("B", db_))}
            older = [side for side, sec in secs.items() if sec and "note" not in sec]
            newer = [side for side, sec in secs.items() if "note" in sec]
            if len(older) == 1 and len(newer) == 1 and secs[older[0]].get("available"):
                notes.append(OLDER_RULE_NOTE.format(side=older[0]))
        sections.append({"key": key, "title": title, "rows": fn(da, db_, ctx), "note": "; ".join(notes) or None})

    def head(rep: Dict[str, Any]) -> Dict[str, Any]:
        return {"id": rep.get("id"), "site": rep.get("site"), "created_ts": rep.get("created_ts"), "status": rep.get("status")}

    # the comparison's own notes: the sides' time on their site's networks, and that both were scanned on one network
    notes = [n for n in (network_time_note(da, db_), same_network_note(a, b)) if n]
    return {"a": head(a), "b": head(b), "sections": sections, "notes": notes}


# --------------------------------------------------------------------------------------
# network marker (pure)
# --------------------------------------------------------------------------------------
def parse_marker(raw: Any) -> Optional[Dict[str, Any]]:
    """The stored ``net.joined`` marker, or None when missing or unreadable."""
    try:
        value = json.loads(raw) if isinstance(raw, str) and raw else None
    except ValueError:
        return None
    if not isinstance(value, dict):
        return None
    return {"ts": _num(value.get("ts")), "gateway": value.get("gateway") or None,
            "networks": sorted({str(n) for n in value.get("networks") or [] if n}), "nic": value.get("nic") or None,
            "gateway_mac": _mac(value.get("gateway_mac")), "mac_ts": _num(value.get("mac_ts")), "seen_ts": _num(value.get("seen_ts"))}


def next_marker(marker: Dict[str, Any], ts: float, gateway: Optional[str], networks: Iterable[str],
                nic: Optional[str] = None, gateway_mac: Optional[str] = None) -> Tuple[Dict[str, Any], bool]:
    """``(marker, moved)`` after seeing this PC on *gateway* / *networks* (and the gateway's MAC, when known) at *ts*.  It
    moved when a non-empty gateway differs from the last non-empty one, non-empty networks share none with the last
    non-empty set, or the same gateway address answers from another MAC (another site's router on the same default subnet,
    which is most small networks); an empty gateway or network list never moves it and leaves the last known one in place."""
    nets = sorted({str(n) for n in networks or [] if n})
    mac = _mac(gateway_mac) if gateway_mac else None
    old_gateway = marker.get("gateway") or None
    old_nets = list(marker.get("networks") or [])
    old_mac = marker.get("gateway_mac") or None
    moved = (bool(gateway and old_gateway and gateway != old_gateway) or bool(nets and old_nets and set(nets).isdisjoint(old_nets))
             or bool(mac and old_mac and mac != old_mac and (not gateway or gateway == old_gateway)))
    out = dict(marker)
    out.setdefault("gateway_mac", None)
    out.setdefault("mac_ts", None)
    if moved:
        out["ts"] = float(ts)
        if gateway and gateway != old_gateway:
            out["gateway_mac"] = out["mac_ts"] = None       # the MAC of the router left behind
    if gateway:
        out["gateway"] = gateway
    if nets:
        out["networks"] = nets
    if nic:
        out["nic"] = nic
    if mac:
        out["gateway_mac"], out["mac_ts"] = mac, float(ts)
    return out, moved


# --------------------------------------------------------------------------------------
# the manager
# --------------------------------------------------------------------------------------
class _Scan:
    """One Full Scan: its job dict and the state its thread and the API calls share (read and written under the manager's
    lock).  Kept per scan, not on the manager, so a cancelled scan whose thread is still winding down never touches the
    flags of the scan started after it."""

    def __init__(self, job: Dict[str, Any]) -> None:
        self.job = job
        self.cancel = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.own_speed = False
        self.own_discovery = False
        self.saving = False
        self.pending_site: Optional[str] = None
        self.wifi_waiting = False
        self.wifi_accepted: Optional[Dict[str, Any]] = None
        self.wifi_fallback: Optional[Dict[str, Any]] = None
        self.wifi_fallback_at: Optional[float] = None
        #: why the scan is on no site's network (NETWORK_NOTE_MESSAGES: offline, not_ready, unknown), None when it is on one
        self.network_why: Optional[str] = None


class ReportManager:
    """``engine.reports``: the Full Scan job, the Wi-Fi intake, the network marker and the report store."""

    def __init__(self, db: Any, config: Any, bus: Any, engine: Any = None, *, clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic, netinfo_fn: Optional[Callable[[], Any]] = None,
                 network_fn: Optional[Callable[[], Tuple[Optional[str], List[str], Optional[str]]]] = None,
                 gateway_mac_fn: Optional[Callable[[str], Optional[str]]] = None,
                 hostname_fn: Optional[Callable[[], str]] = None, wifi_wait_s: float = WIFI_WAIT_S,
                 wifi_grace_s: float = WIFI_GRACE_S, discovery_wait_s: float = DISCOVERY_WAIT_S,
                 mac_wait_s: float = MAC_WAIT_S, networks: Any = None) -> None:
        self._db = db
        self._config = config
        self._bus = bus
        self._engine = engine
        self._network_tracker = networks        # tnt.networks.NetworkTracker; None: engine.networks
        self._clock = clock
        self._mono = monotonic
        self._netinfo_fn = netinfo_fn
        self._network_fn = network_fn
        self._gateway_mac_fn = gateway_mac_fn
        self._hostname_fn = hostname_fn
        self.wifi_wait_s = float(wifi_wait_s)
        self.wifi_grace_s = float(wifi_grace_s)
        self.discovery_wait_s = float(discovery_wait_s)
        self.mac_wait_s = float(mac_wait_s)

        self._lock = threading.RLock()
        self._wifi_cond = threading.Condition(self._lock)
        self._scan: Optional[_Scan] = None
        self._thread: Optional[threading.Thread] = None     # the current scan's thread while it runs
        self._progress_at = 0.0
        self._progress_pct = -1
        self._pub_lock = threading.RLock()      # report.progress publishers take turns (see _publish_progress)
        self._stats: Optional[Dict[str, Any]] = None
        self._stats_gen = 0                     # bumped by every change: a status read that raced one is not cached
        self._stopped = False

        self._net_lock = threading.Lock()
        self._net_marker: Optional[Dict[str, Any]] = None
        self._net_loaded = False
        self._net_events = 0                    # net.changed events handed to helper threads (their order, from 1)
        self._net_applied = 0                   # the newest one applied (0: none, or the start-up check)
        self._joined_mono: Optional[float] = None
        self._start_mono = float(monotonic())

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        """Compare the network with the stored marker (on a helper thread: start() stays quick)."""
        self._stopped = False
        threading.Thread(target=self._startup_network_check, name="tnt-reports-net", daemon=True).start()

    def stop(self) -> None:
        """Cancel a running Full Scan (nothing is saved) and give its thread a moment to finish."""
        self._stopped = True
        self.cancel("The service is stopping")
        t = self._thread
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(STOP_JOIN_S)

    # -- bus -----------------------------------------------------------------
    def _publish(self, event_type: str, data: Dict[str, Any]) -> None:
        bus = self._bus
        if bus is None:
            return
        try:
            bus.publish(event_type, data)
        except Exception:  # noqa: BLE001
            log.exception("publishing %s failed", event_type)

    def _subscribe(self, q: "queue.Queue[Any]", types: Iterable[str]) -> Callable[[], None]:
        subscribe = getattr(self._bus, "subscribe", None)
        if not callable(subscribe):
            return lambda: None
        wanted = frozenset(types)

        def on_event(event: Any) -> None:
            if isinstance(event, dict) and event.get("type") in wanted:
                q.put(event)

        try:
            unsub = subscribe(on_event)
        except Exception:  # noqa: BLE001
            log.exception("full scan: subscribing to the event bus failed")
            return lambda: None
        return unsub if callable(unsub) else (lambda: None)

    def _publish_progress(self, job: Optional[Dict[str, Any]], force: bool = False) -> None:
        """``report.progress`` with *job* as it is now.  Publishers take turns and copy the job inside their turn, so the
        stream never shows an older state after a newer one (two threads changing the job at once would otherwise race
        from their copies to the bus, and the percentage could go back)."""
        if job is None:
            return
        with self._pub_lock:
            now = float(self._mono())
            with self._lock:
                snap = _copy_job(job)
                if not force and (abs(int(snap.get("pct") or 0) - self._progress_pct) < 1 or now - self._progress_at < PROGRESS_GAP_S):
                    return
                self._progress_at = now
                self._progress_pct = int(snap.get("pct") or 0)
            self._publish("report.progress", {"job": snap})

    # -- network marker ------------------------------------------------------
    def _marker_locked(self) -> Optional[Dict[str, Any]]:
        if not self._net_loaded:
            self._net_loaded = True
            try:
                self._net_marker = parse_marker(self._db.get_meta(NET_JOINED_META_KEY))
            except Exception:  # noqa: BLE001
                log.exception("reading the network marker failed")
                self._net_marker = None
        return self._net_marker

    def _store_marker_locked(self, marker: Dict[str, Any]) -> None:
        self._net_marker = marker
        self._db.set_meta(NET_JOINED_META_KEY, json.dumps(marker, separators=(",", ":")))

    def joined_ts(self, now: Optional[float] = None) -> Optional[float]:
        """When this PC joined its current network, if known.  A stored time later than now was stamped by a clock that has
        been put back since (a laptop's clock is often corrected just as it joins a customer's network): the join is then
        dated by the monotonic clock when it happened in this service run, else at this run's start (a shorter window,
        never an empty one)."""
        with self._net_lock:
            marker = self._marker_locked()
            joined_mono = self._joined_mono
        ts = _num((marker or {}).get("ts"))
        if ts is None:
            return None
        now = float(self._clock()) if now is None else float(now)
        if ts <= now + CLOCK_SLACK_S:
            return ts
        mono = float(self._mono())
        since = mono - joined_mono if joined_mono is not None else mono - self._start_mono
        return now - max(0.0, since)

    def on_network_change(self, data: Dict[str, Any]) -> None:
        """``net.changed`` (the Engine, on the watcher thread): hands the marker update to a helper thread.  Events are
        numbered here, in the order the watcher published them: a helper thread that runs late never undoes a newer change
        (their wall-clock times cannot tell, the clock may have been put back in between)."""
        if not isinstance(data, dict):
            return
        with self._net_lock:
            self._net_events += 1
            seq = self._net_events
        threading.Thread(target=self._apply_network_change, args=(dict(data), seq), name="tnt-reports-net", daemon=True).start()

    def _apply_network_change(self, data: Dict[str, Any], seq: Optional[int] = None) -> None:
        try:
            nic = data.get("internet_nic") if isinstance(data.get("internet_nic"), dict) else {}
            gateway = str(data.get("default_gateway") or "") or None
            networks = [str(n) for n in nic.get("networks") or [] if n]
            now = float(self._clock())
            ts = _num(data.get("ts"))
            ts = now if ts is None else ts
            with self._net_lock:
                if seq is None:
                    self._net_events += 1
                    seq = self._net_events
                if seq < self._net_applied:
                    return                              # an older change handled after a newer one
                self._net_applied = seq
                marker = self._marker_locked()
                if marker is None:
                    marker = {"ts": None, "gateway": str(data.get("previous_gateway") or "") or None, "networks": [],
                              "nic": None, "gateway_mac": None, "mac_ts": None, "seen_ts": None}
                new, moved = next_marker(marker, ts, gateway, networks, nic.get("name"))
                new["seen_ts"] = ts
                self._store_marker_locked(new)
                if moved:
                    self._joined_mono = float(self._mono()) - max(0.0, now - ts)
            if moved:
                log.info("reports: this PC joined another network (gateway %s, %s)", gateway, ", ".join(networks) or "-")
            if gateway:
                # the router's MAC tells two sites on the same default subnet apart; the pinger resolves it within seconds
                mac = self._wait_gateway_mac(gateway, seq)
                if mac:
                    self._note_gateway_mac(gateway, mac, ts, seq)
        except Exception:  # noqa: BLE001
            log.exception("reports: recording the network change failed")

    # the default gateway's MAC (tnt.arp) ------------------------------------
    def _gateway_mac(self, gateway: Optional[str]) -> Optional[str]:
        if not gateway:
            return None
        try:
            if self._gateway_mac_fn is not None:
                return _mac(self._gateway_mac_fn(gateway))
            tracker = self._networks()
            known = getattr(tracker, "gateway_mac", None) if tracker is not None else None
            mac = _mac(known(gateway)) if callable(known) else None
            if mac:
                return mac                              # the network tracker already read (and confirmed) it
            from .arp import get_arp_table

            return _mac(get_arp_table().get(gateway))
        except Exception:  # noqa: BLE001 - no MAC: the marker goes by the addresses alone
            log.debug("reports: the gateway's MAC could not be read", exc_info=True)
            return None

    def _wait_gateway_mac(self, gateway: str, seq: int) -> Optional[str]:
        """The MAC of *gateway* from the ARP table, looked for every MAC_POLL_S for up to ``mac_wait_s``; None when it does
        not appear, the service stops or a newer network change supersedes *seq*."""
        deadline = float(self._mono()) + self.mac_wait_s
        while True:
            mac = self._gateway_mac(gateway)
            if mac or self._stopped or float(self._mono()) >= deadline:
                return mac
            with self._net_lock:
                if self._net_applied != seq:
                    return None
            time.sleep(min(MAC_POLL_S, max(0.01, deadline - float(self._mono()))))

    def _note_gateway_mac(self, gateway: str, mac: str, ts: Optional[float], seq: int) -> bool:
        """Record the gateway's MAC in the marker; True when it shows this PC moved.  *ts* None: when the move happened is
        unknown, so the latest moment the marker still saw the old network stands for it (a shorter window, not a mixed one)."""
        with self._net_lock:
            if self._net_applied != seq:
                return False
            marker = self._marker_locked()
            if marker is None or (marker.get("gateway") or None) != gateway:
                return False
            now = float(self._clock())
            when = now if ts is None else ts
            new, moved = next_marker(marker, when, gateway, [], None, mac)
            if moved and ts is None:
                known = [t for t in (_num(marker.get("seen_ts")), _num(marker.get("mac_ts"))) if t is not None]
                when = min(max(known), now) if known else now
                new, moved = next_marker(marker, when, gateway, [], None, mac)
            if new != marker:
                self._store_marker_locked(new)
            if moved:
                self._joined_mono = float(self._mono()) - max(0.0, now - when)
        if moved:
            log.info("reports: this PC joined another network behind the same gateway address %s (router MAC %s)", gateway, mac)
        return moved

    def _check_gateway_mac(self) -> None:
        """Before a report reads its window: a router swap the network events missed (its MAC was not known yet)."""
        try:
            gateway = self._current_network()[0]
            mac = self._gateway_mac(gateway)
            if gateway and mac:
                with self._net_lock:
                    seq = self._net_applied
                self._note_gateway_mac(gateway, mac, None, seq)
        except Exception:  # noqa: BLE001
            log.exception("reports: checking the gateway's MAC failed")

    def _seed_join_ts(self, now: float) -> Optional[float]:
        """For a database without a marker (the first start of a release with reports): the latest sign within the report
        window that this PC may have changed networks: a "network changed" events row (every change the watcher saw,
        also before this release) or the end of a monitoring gap of SEED_GAP_S or more (the PC off or asleep, perhaps while
        it was carried somewhere else).  None when there is neither: the whole window was monitored on one network."""
        found: List[float] = []
        since = now - WINDOW_S
        try:
            ts = self._db.last_event_ts("network", "network changed", since)
            if ts is not None:
                found.append(float(ts))
        except Exception:  # noqa: BLE001
            log.exception("reports: reading the network events failed")
        try:
            for row in self._db.list_outages(since, now, kinds=("gap",), include_open=False):
                s, e = _num(row.get("start_ts")), _num(row.get("end_ts"))
                if s is not None and e is not None and e - s >= SEED_GAP_S:
                    found.append(e)
        except Exception:  # noqa: BLE001
            log.exception("reports: reading the monitoring gaps failed")
        found = [t for t in found if since <= t]
        return min(max(found), now) if found else None

    def _current_network(self) -> Tuple[Optional[str], List[str], Optional[str]]:
        if self._network_fn is not None:
            gateway, networks, nic = self._network_fn()
            return gateway, list(networks or []), nic
        engine = self._engine
        gateway: Optional[str] = None
        nic_name: Optional[str] = None
        networks: List[str] = []
        watch = getattr(engine, "netwatch", None)
        if watch is not None:
            state = watch.state() or {}
            gateway, nic_name = state.get("default_gateway"), state.get("internet_nic")
        summary_fn = getattr(engine, "netinfo_summary", None)
        if callable(summary_fn):
            nic = (summary_fn() or {}).get("internet_nic") or {}
            if nic.get("network"):
                networks = [str(nic["network"])]
            gateway = gateway or nic.get("gateway")
            nic_name = nic_name or nic.get("name")
        return gateway, networks, nic_name

    def _startup_network_check(self) -> None:
        try:
            gateway, networks, nic = self._current_network()
            now = float(self._clock())
            started = min(_num(getattr(self._engine, "started_ts", None)) or now, now)
            moved = False
            seed = self._seed_join_ts(started) if self._marker_missing() else None
            with self._net_lock:
                if self._net_events:
                    return                              # a net.changed already brought the marker up to date
                marker = self._marker_locked()
                if marker is None:
                    new: Dict[str, Any] = {"ts": seed, "gateway": gateway or None,
                                           "networks": sorted({str(n) for n in networks if n}), "nic": nic or None,
                                           "gateway_mac": None, "mac_ts": None}
                    if seed is not None:
                        log.info("reports: no network marker yet; this PC may have joined its network at %.0f", seed)
                else:
                    new, moved = next_marker(marker, started, gateway, networks, nic)
                new["seen_ts"] = started
                if new != marker:
                    self._store_marker_locked(new)
                if moved:
                    self._joined_mono = self._start_mono
            if moved:
                log.info("reports: this PC is on another network than before the service started (gateway %s)", gateway)
            if gateway:
                mac = self._wait_gateway_mac(gateway, 0)
                if mac:
                    self._note_gateway_mac(gateway, mac, started, 0)
        except Exception:  # noqa: BLE001
            log.exception("reports: checking the network at start failed")

    def _marker_missing(self) -> bool:
        with self._net_lock:
            return self._marker_locked() is None

    # -- job state -----------------------------------------------------------
    def job(self) -> Optional[Dict[str, Any]]:
        """The running Full Scan, else the last one this service run finished, else None."""
        with self._lock:
            return _copy_job(self._scan.job if self._scan is not None else None)

    def _job_locked(self) -> Optional[Dict[str, Any]]:
        return _copy_job(self._scan.job if self._scan is not None else None)

    def _oldest_minute(self) -> Optional[int]:
        try:
            return self._db.oldest_ping_minute()
        except Exception:  # noqa: BLE001
            log.exception("full scan: reading the oldest ping data failed")
            return None

    def window_preview(self, end: float, network_id: Any = None) -> Tuple[float, str]:
        """``(window_start, window_reason)`` a report made at *end* would read its pings and outages over (as it stands now:
        the history phase works it out again).  On a known network (*network_id*, data tagged) the last seven days, bounded by
        the oldest ping data (``site_network``: only that network's data counts); on a portable one (a hotspot or travel router)
        the time since this PC joined it (``network_change``: its data at other sites never counts); else the time rule
        (:func:`report_window`)."""
        oldest = self._oldest_minute()
        if network_id is not None and getattr(self._db, "networks_ready", False):
            start = float(end) - WINDOW_S
            if _num(oldest) is not None:
                start = max(start, float(oldest))      # type: ignore[arg-type]
            row = self._network_row(network_id)
            if row is None or not row.get("portable"):
                return min(start, float(end)), "site_network"
            joined = self._connected_since(row["id"])
            if joined is not None:
                return min(max(start, joined), float(end)), "network_change"
        return report_window(end, self.joined_ts(), oldest)

    # -- the site's network (tnt.networks) --------------------------------------
    def _networks(self) -> Any:
        return self._network_tracker if self._network_tracker is not None else getattr(self._engine, "networks", None)

    def _network_row(self, network_id: Any) -> Optional[Dict[str, Any]]:
        """The networks row *network_id* stands for now (after a merge), or None."""
        try:
            nid = self._db.map_network_id(network_id)
            return self._db.get_network(nid) if nid is not None else None
        except Exception:  # noqa: BLE001
            log.exception("full scan: reading network %s failed", network_id)
            return None

    def _network_view_of(self, network_id: Any) -> Optional[Dict[str, Any]]:
        from .networks import network_view

        row = self._network_row(network_id) if network_id is not None else None
        return network_view(row, with_times=False) if row else None

    def _connected_since(self, network_id: Any) -> Optional[float]:
        """When this PC joined (or came back to) *network_id*, the network it is on now (the tracker), else None."""
        fn = getattr(self._networks(), "connected_since", None)
        try:
            return _num(fn(network_id)) if callable(fn) else None
        except Exception:  # noqa: BLE001
            log.exception("full scan: reading when this PC joined its network failed")
            return None

    def _scan_network(self) -> Tuple[Optional[int], Optional[str]]:
        """``(id, None)`` of the network a Full Scan starts on (a quick router check first), else ``(None, why)``: ``offline`` (no
        network with a gateway: the last network's id sticks for the writers, but a scan now is on no site's network, and is not
        suggested that site), ``not_ready`` (data is not tagged), ``unknown``; ``(None, None)`` without a network tracker."""
        tracker = self._networks()
        if tracker is None:
            return None, None
        if not getattr(self._db, "networks_ready", False):
            return None, "not_ready"
        if getattr(tracker, "offline", False):
            return None, "offline"
        try:
            fn = getattr(tracker, "confirm", None)
            nid = _int_in(fn() if callable(fn) else tracker.current_network_id(), 1, 2 ** 62)
        except Exception:  # noqa: BLE001
            log.exception("full scan: reading the current network failed")
            return None, "unknown"
        if nid is None:
            return None, "offline" if getattr(tracker, "offline", False) else "unknown"
        return nid, None

    def _suggested_site(self, network_id: Any) -> Optional[Dict[str, Any]]:
        """``{"site","report_id","created_ts"}`` of the newest report saved on *network_id* under a site name (an "Unnamed site"
        report names none), or None; always None for a portable network (a hotspot's reports name the other sites it went to)."""
        fn = getattr(self._db, "newest_report_on_network", None)
        if network_id is None or not callable(fn):
            return None
        network = self._network_row(network_id)
        if network is not None and network.get("portable"):
            return None
        try:
            row = fn(network_id, site_key(UNNAMED_SITE))
        except Exception:  # noqa: BLE001
            log.exception("full scan: reading the reports of this network failed")
            return None
        return {"site": row["site"], "report_id": int(row["id"]), "created_ts": row["created_ts"]} if row else None

    def _site_scope(self, network_id: Any, end: float) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any], Optional[str]]:
        """``(scope, meta.network, why)`` of a report whose scan started on *network_id* at *end*: ``{"id","legacy_since","travel",
        "portable"}`` (the network as it stands after a merge, the time rule's start for untagged rows (none on a portable
        network), the trips) and its description; the scope is None when it was not identified (or data is not tagged: the
        unknown network, *why* ``unknown``) or it is a portable network this PC is no longer on (its description, ``portable``).
        *why* is ``portable`` for a portable network's scope too (the history message says so)."""
        from .networks import network_view, unknown_network

        if network_id is None or not getattr(self._db, "networks_ready", False):
            return None, unknown_network(), "unknown"
        try:
            nid = self._db.map_network_id(network_id, end)
            row = self._db.get_network(nid) if nid is not None else None
            if row is None:
                return None, unknown_network(), "unknown"
            view = network_view(row, with_times=False) or unknown_network()
            portable = bool(row.get("portable"))
            if portable and self._connected_since(row["id"]) is None:
                return None, view, "portable"
            start = self.window_preview(end, row["id"])[0]
            spells = self._db.offline_spells(int(row["id"]), start - LEAVE_SLACK_S, end)
        except Exception:  # noqa: BLE001
            log.exception("full scan: reading the scan's network failed; the time rule is used")
            return None, unknown_network(), "unknown"
        legacy_since = None if portable else report_window(end, self.joined_ts(), self._oldest_minute())[0]
        return ({"id": int(row["id"]), "legacy_since": legacy_since, "travel": travel_spans(spells), "portable": portable},
                view, "portable" if portable else None)

    def on_network_id_change(self, event: Dict[str, Any]) -> None:
        """``tnt.networks`` listener: the provisional network a running Full Scan started on turned out to be its router's
        network (``late``): the job follows it, that network's description, window and suggested site."""
        if not isinstance(event, dict) or not event.get("late") or event.get("new_id") is None:
            return
        new_id = _int_in(event.get("new_id"), 1, 2 ** 62)
        with self._lock:
            scan = self._scan
            if new_id is None or scan is None or scan.job.get("status") != "running" or scan.job.get("network_id") != event.get("old_id"):
                return
            scan.job["network_id"] = new_id
        self._refresh_job_network()

    def _refresh_job_network(self) -> None:
        """A running scan's network changed (merged, marked portable or not): its description, window and suggested site again."""
        with self._lock:
            scan = self._scan
            if scan is None or scan.job.get("status") != "running" or scan.job.get("network_id") is None:
                return
            job = scan.job
            nid, started = job["network_id"], float(job.get("started_ts") or self._clock())
        suggested = self._suggested_site(nid)
        view = self._network_view_of(nid)
        start, reason = self.window_preview(started, nid)
        with self._lock:
            if job.get("network_id") != nid or job.get("status") != "running":
                return
            job.update(suggested_site=suggested, network=view, window_start=round(start, 3), window_reason=reason)
        self._publish_progress(job, force=True)

    def set_network_portable(self, network_id: Any, portable: bool) -> Optional[Dict[str, Any]]:
        """Mark a network carried from site to site (a phone hotspot, a travel router, an LTE box), or not
        (``PATCH /api/networks/{id}``): no site is suggested for a portable network and its report reads only the current
        connection to it.  A running scan on it follows at once.  The network's view (``network_view`` without times), None
        when there is no such network; ``RuntimeError`` without a network tracker."""
        fn = getattr(self._networks(), "set_portable", None)
        if not callable(fn):
            raise RuntimeError("networks are not identified by this service")
        view = fn(network_id, bool(portable))
        if view is not None:
            self._refresh_job_network()
        return view

    def start_scan(self, site: Optional[str] = None) -> Dict[str, Any]:
        """Start a Full Scan; :class:`ScanBusy` while one runs, ``ValueError`` for a bad site name."""
        name = normalize_site(site) if site is not None else None
        started = round(float(self._clock()), 3)
        network_id, network_why = self._scan_network()
        suggested = self._suggested_site(network_id)
        network = self._network_view_of(network_id)
        window_start, window_reason = self.window_preview(started, network_id)
        with self._lock:
            if self._stopped:
                raise ScanConflict("The service is stopping", self._job_locked(), code="stopping")
            if self._scan is not None and self._scan.job.get("status") == "running":
                raise ScanBusy(self._job_locked())
            job: Dict[str, Any] = {
                "id": secrets.token_hex(6), "site": name, "started_ts": started,
                "status": "running", "phase": "speed", "pct": 0, "message": "Starting the full scan",
                "phases": [{"key": k, "status": "pending", "message": None, "started_ts": None, "finished_ts": None}
                           for k in PHASES],
                "report_id": None, "error": None, "window_start": round(window_start, 3), "window_reason": window_reason,
                "network_id": network_id, "network": network, "suggested_site": suggested,
            }
            scan = _Scan(job)
            scan.network_why = network_why
            scan.thread = threading.Thread(target=self._run, args=(scan,), name="tnt-reports-scan", daemon=True)
            self._scan = scan
            self._thread = scan.thread
            snap = _copy_job(job)
        log.info("full scan %s started%s", job["id"], f" for {name!r}" if name else "")
        self._publish_progress(job, force=True)
        scan.thread.start()
        return snap  # type: ignore[return-value]

    def set_site(self, site: Any) -> Dict[str, Any]:
        """Name the running scan's site, or rename the report the last scan saved.  ``ValueError`` for a bad
        name, :class:`ScanConflict` when there is no such scan (``no_scan``), it was not saved (``not_running``) or its
        report has been deleted since (``not_found``)."""
        name = normalize_site(site)
        rename_id = None
        with self._lock:
            scan = self._scan
            if scan is None:
                raise ScanConflict("No full scan has run since the service started", None, code="no_scan")
            job = scan.job
            if job["status"] == "running":
                job["site"] = name
                if scan.saving:
                    scan.pending_site = name
            elif job["status"] == "saved" and job.get("report_id") is not None:
                rename_id = job["report_id"]
            elif job["status"] == "saved":
                raise ScanConflict("The report of the last full scan has been deleted", _copy_job(job), code="not_found")
            else:
                raise ScanConflict("The full scan was not saved", _copy_job(job), code="not_running")
            snap = _copy_job(job)
        if rename_id is not None:
            if self.rename(rename_id, name) is None:
                with self._lock:
                    if scan.job.get("report_id") == rename_id:
                        scan.job["report_id"] = None
                    snap = _copy_job(scan.job)
                self._publish_progress(scan.job, force=True)
                raise ScanConflict("The report of the last full scan has been deleted", snap, code="not_found")
            snap = self.job()
        self._publish_progress(job, force=True)
        return snap  # type: ignore[return-value]

    def cancel(self, reason: str = "Cancelled") -> Optional[Dict[str, Any]]:
        """Cancel the running Full Scan (nothing is saved); returns the job (unchanged when it is not running
        or its report is already being written), None when there never was one."""
        with self._lock:
            scan = self._scan
            if scan is None or scan.job["status"] != "running" or scan.saving:
                return self._job_locked()
            job = scan.job
            scan.cancel.set()
            now = round(float(self._clock()), 3)
            job.update(status="cancelled", phase=None, message=reason)
            for ph in job["phases"]:
                if ph["status"] == "running":
                    ph.update(status="skipped", message=reason, finished_ts=now)
                elif ph["status"] == "pending":
                    ph["status"] = "skipped"
            own_speed, own_discovery = scan.own_speed, scan.own_discovery
            self._wifi_cond.notify_all()
            snap = _copy_job(job)
        engine = self._engine
        if own_speed:
            self._cancel_own_speed(getattr(engine, "speed", None))
        if own_discovery and callable(getattr(engine, "discovery_cancel", None)):
            try:
                engine.discovery_cancel()
            except Exception:  # noqa: BLE001
                log.exception("full scan: cancelling its discovery scan failed")
        log.info("full scan %s cancelled (%s)", snap["id"] if snap else "?", reason)
        self._publish_progress(job, force=True)
        return snap

    def post_wifi(self, body: Any) -> Dict[str, Any]:
        """A Wi-Fi survey snapshot from a TNT window; ``ValueError`` for a bad body, :class:`ScanConflict` when
        no Full Scan is waiting for one."""
        snapshot = clean_wifi_snapshot(body, now=float(self._clock()))
        with self._lock:
            scan = self._scan
            if scan is None or scan.job["status"] != "running" or not scan.wifi_waiting or scan.wifi_accepted is not None:
                raise ScanConflict("No full scan is waiting for a Wi-Fi scan", self._job_locked(), code="not_waiting")
            job = scan.job
            if snapshot["available"]:
                scan.wifi_accepted = snapshot
                message = f"Wi-Fi scan received: {_plural(len(snapshot['aps']), 'access point')}"
            else:
                scan.wifi_fallback = snapshot
                if scan.wifi_fallback_at is None:
                    scan.wifi_fallback_at = float(self._mono())
                message = f"{wifi_reason(snapshot)}; waiting briefly for a TNT window that can scan"
            # the answer is the job as this post left it: the scan thread only wakes once the lock is free
            phase = next(p for p in job["phases"] if p["key"] == "wifi")
            phase["message"] = job["message"] = message
            snap = _copy_job(job)
            self._wifi_cond.notify_all()
        self._publish_progress(job, force=True)
        log.info("full scan: Wi-Fi snapshot received (available=%s, state %s, %d access points)",
                 snapshot["available"], snapshot["state"], len(snapshot["aps"]))
        return snap  # type: ignore[return-value]

    def _phase_update(self, scan: _Scan, key: str, status: Optional[str] = None, message: Optional[str] = None,
                      frac: Optional[float] = None, open_wifi: bool = False) -> None:
        """Change one phase of *scan*'s job, while it runs, and publish it.  *open_wifi* opens the Wi-Fi intake in the same step."""
        with self._lock:
            job = scan.job
            if job.get("status") != "running":
                return
            if open_wifi:
                scan.wifi_accepted = scan.wifi_fallback = scan.wifi_fallback_at = None
                scan.wifi_waiting = True
            phase = next(p for p in job["phases"] if p["key"] == key)
            now = round(float(self._clock()), 3)
            changed = False
            if status is not None and phase["status"] != status:
                changed = True
                phase["status"] = status
                if status == "running":
                    phase["started_ts"] = now
                    job["phase"] = JOB_PHASE[key]
                else:
                    phase["finished_ts"] = now
                    if phase["started_ts"] is None:
                        phase["started_ts"] = now
            if message is not None and (phase["message"] != message or job["message"] != message):
                changed = True
                phase["message"] = message
                job["message"] = message
            lo, hi = PHASE_PCT[key]
            pct: Optional[float] = None
            if status in ("done", "error", "skipped"):
                pct = hi
            elif status == "running":
                pct = lo
            elif frac is not None:
                pct = lo + (hi - lo) * max(0.0, min(1.0, float(frac)))
            if pct is not None:
                job["pct"] = max(int(job.get("pct") or 0), min(100, int(pct)))
        self._publish_progress(job, force=changed)

    # -- the job thread ------------------------------------------------------
    def _run(self, scan: _Scan) -> None:
        ctx: Dict[str, Any] = {}
        job, cancel = scan.job, scan.cancel
        try:
            for step in (self._speed_phase, self._discovery_phase, self._wifi_phase, self._history_phase):
                if cancel.is_set():
                    return
                step(scan, ctx)
            if not cancel.is_set():
                self._save_phase(scan, ctx)
        except Exception as exc:  # noqa: BLE001 - the job must end in a state the UI can show
            log.exception("full scan %s failed", job.get("id"))
            with self._lock:
                if job.get("status") == "running":
                    now = round(float(self._clock()), 3)
                    job.update(status="error", phase=None, error=f"{type(exc).__name__}: {exc}",
                               message="The full scan failed")
                    for ph in job["phases"]:
                        if ph["status"] == "running":
                            ph.update(status="error", message=job["error"], finished_ts=now)
            self._publish_progress(job, force=True)
        finally:
            with self._lock:
                scan.wifi_waiting = False
                scan.own_speed = scan.own_discovery = False
                scan.saving = False
                if self._thread is threading.current_thread():
                    self._thread = None

    # speed ------------------------------------------------------------------
    def _speed_wait_s(self) -> float:
        try:
            timeout = float(self._config.get("speedtest.timeout_s", 120)) if self._config is not None else 120.0
        except (TypeError, ValueError):
            timeout = 120.0
        return 2.0 * (max(10.0, timeout) + SPEED_SOCKET_S) + SPEED_EXTRA_S

    @staticmethod
    def _speed_running(sched: Any) -> bool:
        try:
            return bool(getattr(sched, "running", False))
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def _cancel_own_speed(sched: Any) -> None:
        fn = getattr(sched, "cancel_current", None)
        if callable(fn):
            try:
                fn()
            except Exception:  # noqa: BLE001
                log.exception("full scan: cancelling its speed test failed")

    def _speed_phase(self, scan: _Scan, ctx: Dict[str, Any]) -> None:
        self._phase_update(scan, "speed", status="running", message="Starting the speed test")
        sched = getattr(self._engine, "speed", None)
        if sched is None or not callable(getattr(sched, "run_now", None)):
            ctx["speed_error"] = "Speed tests are not available"
            self._phase_update(scan, "speed", status="skipped", message=ctx["speed_error"])
            return
        events: "queue.Queue[Any]" = queue.Queue()
        unsub = self._subscribe(events, ("speedtest.start", "speedtest.progress", "speedtest.done"))
        try:
            result, error = self._await_speed(scan, sched, events)
        finally:
            unsub()
            with self._lock:
                scan.own_speed = False
        if scan.cancel.is_set():
            return
        if isinstance(result, dict):
            result.pop("raw", None)
            ctx["speed_result"] = result
            if result.get("ok"):
                def fmt(v: Any, unit: str) -> str:
                    f = _num(v)
                    return f"{f:.1f} {unit}" if f is not None else "-"

                self._phase_update(scan, "speed", status="done", message=(
                    f"Download {fmt(result.get('download_mbps'), 'Mbps')}, upload {fmt(result.get('upload_mbps'), 'Mbps')}, "
                    f"latency {fmt(result.get('latency_ms'), 'ms')}"))
                return
            error = f"The speed test failed: {result.get('error') or 'unknown error'}"
        ctx["speed_error"] = error or "The speed test did not run"
        self._phase_update(scan, "speed", status="error", message=ctx["speed_error"])

    def _await_speed(self, scan: _Scan, sched: Any, events: "queue.Queue[Any]") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        cancel = scan.cancel
        deadline = float(self._mono()) + self._speed_wait_s()
        attempts = 0
        while not cancel.is_set():
            attempts += 1
            _drain(events)
            try:
                own = bool(sched.run_now())
            except Exception as exc:  # noqa: BLE001
                log.exception("full scan: starting the speed test failed")
                return None, f"The speed test could not be started: {exc}"
            if not own and not self._speed_running(sched):
                # the previous test has published its result but not yet let go of the scheduler
                if attempts >= START_RETRIES or float(self._mono()) >= deadline:
                    return None, "The speed test could not be started"
                cancel.wait(START_RETRY_S)
                continue
            with self._lock:
                scan.own_speed = own
            self._phase_update(scan, "speed", message="Running the speed test" if own
                               else "Waiting for the speed test that is already running")
            outcome = self._speed_events(scan, sched, events, own, deadline)
            if outcome is not _RETRY:
                return outcome  # type: ignore[return-value]
        return None, None

    def _speed_events(self, scan: _Scan, sched: Any, events: "queue.Queue[Any]", own: bool, deadline: float) -> Any:
        cancel = scan.cancel
        seen_start = not own
        idle_since: Optional[float] = None
        while not cancel.is_set():
            now = float(self._mono())
            if now >= deadline:
                if own:
                    self._cancel_own_speed(sched)
                return None, "The speed test did not finish in time"
            try:
                event = events.get(timeout=max(0.01, min(0.25, deadline - now)))
            except queue.Empty:
                if not own and not self._speed_running(sched):
                    idle_since = now if idle_since is None else idle_since
                    if now - idle_since >= 1.0:
                        return _RETRY           # the test waited for ended unseen: run one of our own
                continue
            idle_since = None
            etype = event.get("type")
            data = event.get("data") if isinstance(event.get("data"), dict) else {}
            if etype == "speedtest.start":
                seen_start = True
            elif etype == "speedtest.progress" and seen_start:
                frac = _step_frac(SPEED_STEPS, data.get("phase"), data.get("pct"))
                if frac is not None:
                    self._phase_update(scan, "speed", frac=frac)
            elif etype == "speedtest.done" and seen_start:
                result = data.get("result")
                if not own and isinstance(result, dict) and not result.get("ok") and result.get("error") == SPEED_CANCELLED:
                    # the test waited for was cut short (the scan cancelled just before this one, say): run one of our own
                    return _RETRY
                if isinstance(result, dict):
                    return dict(result), None
                return None, "The speed test returned no result"
        return None, None

    # discovery --------------------------------------------------------------
    @staticmethod
    def _discovery_running(engine: Any) -> bool:
        try:
            fn = getattr(engine, "discovery_running", None)
            if callable(fn):
                return bool(fn())
            status = getattr(engine, "discovery_status", None)
            return bool((status() or {}).get("running")) if callable(status) else False
        except Exception:  # noqa: BLE001
            return False

    def _discovery_phase(self, scan: _Scan, ctx: Dict[str, Any]) -> None:
        self._phase_update(scan, "discovery", status="running", message="Starting the Discovery scan")
        engine = self._engine
        if engine is None or getattr(engine, "discovery", None) is None or not callable(getattr(engine, "discovery_start", None)):
            ctx["discovery_error"] = "Network discovery is not available"
            self._phase_update(scan, "discovery", status="skipped", message=ctx["discovery_error"])
            return
        events: "queue.Queue[Any]" = queue.Queue()
        unsub = self._subscribe(events, ("discovery.start", "discovery.progress", "discovery.done"))
        try:
            done, status, message = self._await_discovery(scan, engine, events)
        finally:
            unsub()
            with self._lock:
                scan.own_discovery = False
        if scan.cancel.is_set():
            return
        run = None
        if isinstance(done, dict):
            try:
                run = self._db.get_discovery_run(int(done["run_id"])) if done.get("run_id") is not None else None
            except Exception:  # noqa: BLE001
                log.exception("full scan: reading the discovery run failed")
            if done.get("cancelled"):
                status, message = "error", "The Discovery scan was cancelled before it finished"
            elif not done.get("ok", True):
                status, message = "error", f"Discovery failed: {done.get('error') or 'unknown error'}"
            elif run is None:
                status, message = "error", "The Discovery results could not be read"
            else:
                n = len(run.get("hosts") or [])
                status, message = "done", f"{_plural(n, 'device')} found on {run.get('cidr')}"
            notes = []
            if done.get("cancelled"):
                notes.append("The scan was cancelled before it finished")
            if done.get("network_changed"):
                notes.append("The network changed during the scan")
            ctx["discovery_note"] = "; ".join(notes) or None
        ctx["discovery_run"] = run
        ctx["discovery_error"] = None if status == "done" else message
        self._phase_update(scan, "discovery", status=status or "error", message=message or "Discovery did not run")

    def _await_discovery(self, scan: _Scan, engine: Any,
                         events: "queue.Queue[Any]") -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
        cancel = scan.cancel
        deadline = float(self._mono()) + self.discovery_wait_s
        attempts = 0
        while not cancel.is_set():
            attempts += 1
            _drain(events)
            try:
                own = bool(engine.discovery_start(None, None))
            except ValueError as exc:
                return None, "error", f"Discovery could not start: {exc}"
            except RuntimeError:
                return None, "skipped", "Network discovery is not available"
            except Exception as exc:  # noqa: BLE001
                log.exception("full scan: starting discovery failed")
                return None, "error", f"Discovery could not start: {exc}"
            if not own and not self._discovery_running(engine):
                if attempts >= START_RETRIES or float(self._mono()) >= deadline:
                    return None, "error", "The Discovery scan could not be started"
                cancel.wait(START_RETRY_S)
                continue
            with self._lock:
                scan.own_discovery = own
            self._phase_update(scan, "discovery", message="Scanning the network" if own
                               else "Waiting for the Discovery scan that is already running")
            outcome = self._discovery_events(scan, engine, events, own, deadline)
            if outcome is not _RETRY:
                return outcome  # type: ignore[return-value]
        return None, None, None

    def _discovery_events(self, scan: _Scan, engine: Any, events: "queue.Queue[Any]", own: bool, deadline: float) -> Any:
        cancel = scan.cancel
        seen_start = not own
        idle_since: Optional[float] = None
        while not cancel.is_set():
            now = float(self._mono())
            if now >= deadline:
                if own:
                    try:
                        engine.discovery_cancel()
                    except Exception:  # noqa: BLE001
                        log.exception("full scan: cancelling the discovery scan failed")
                return None, "error", "The Discovery scan did not finish in time"
            try:
                event = events.get(timeout=max(0.01, min(0.25, deadline - now)))
            except queue.Empty:
                if not own and not self._discovery_running(engine):
                    idle_since = now if idle_since is None else idle_since
                    if now - idle_since >= 1.0:
                        return _RETRY
                continue
            idle_since = None
            etype = event.get("type")
            data = event.get("data") if isinstance(event.get("data"), dict) else {}
            if etype == "discovery.start":
                seen_start = True
            elif etype == "discovery.progress" and seen_start:
                total = _num(data.get("total"))
                done = _num(data.get("done"))
                frac = _step_frac(DISCOVERY_STEPS, data.get("phase"), (done / total) if total and done is not None else 0.0)
                if frac is not None:
                    self._phase_update(scan, "discovery", frac=frac)
            elif etype == "discovery.done" and seen_start:
                if not own and data.get("cancelled"):
                    return _RETRY               # the sweep waited for was cancelled before it finished: run one of our own
                return dict(data), None, None
        return None, None, None

    # wifi --------------------------------------------------------------------
    def _wifi_phase(self, scan: _Scan, ctx: Dict[str, Any]) -> None:
        # the intake opens in the step that announces the phase: a page without the bridge posts the moment it hears of
        # it, and no post is taken before the job says it waits for one
        self._phase_update(scan, "wifi", status="running", message="Waiting for the TNT window to scan Wi-Fi", open_wifi=True)
        cancel = scan.cancel
        began = float(self._mono())
        last_frac = 0.0
        try:
            while True:
                with self._wifi_cond:
                    if cancel.is_set() or scan.wifi_accepted is not None:
                        break
                    now = float(self._mono())
                    deadline = began + self.wifi_wait_s
                    if scan.wifi_fallback_at is not None:
                        deadline = min(deadline, scan.wifi_fallback_at + self.wifi_grace_s)
                    if now >= deadline:
                        break
                    self._wifi_cond.wait(max(0.01, min(0.5, deadline - now)))
                frac = min(1.0, (float(self._mono()) - began) / self.wifi_wait_s) if self.wifi_wait_s > 0 else 1.0
                if frac - last_frac >= 0.05:
                    last_frac = frac
                    self._phase_update(scan, "wifi", frac=frac)
        finally:
            with self._lock:
                scan.wifi_waiting = False
                accepted, fallback = scan.wifi_accepted, scan.wifi_fallback
        if cancel.is_set():
            return
        if accepted is not None:
            section = build_wifi_section(accepted)
            status = "done"
            message = f"{_plural(section['aps_count'], 'access point')}, {_plural(section['networks'], 'network')}"
        elif fallback is not None:
            section = build_wifi_section(fallback)
            status = "skipped" if fallback.get("state") in WIFI_SKIP_STATES else "error"
            message = section["reason"]
        else:
            section = build_wifi_section(None, NO_WINDOW_REASON)
            status, message = "skipped", NO_WINDOW_REASON
        ctx["wifi"] = section
        self._phase_update(scan, "wifi", status=status, message=message)

    # history -----------------------------------------------------------------
    def _netinfo_snapshot(self) -> Any:
        if self._netinfo_fn is not None:
            return self._netinfo_fn()
        return importlib.import_module("tnt.netinfo").netinfo_snapshot()

    def _live_public_ip(self) -> Optional[str]:
        linkmap = getattr(self._engine, "linkmap", None)
        if linkmap is None:
            return None
        try:
            return ((linkmap.view() or {}).get("public_ip") or {}).get("ip")
        except Exception:  # noqa: BLE001
            log.debug("link map view unavailable for the report", exc_info=True)
            return None

    def _interval_s(self) -> float:
        try:
            value = float(self._config.get("ping.interval_s", 1.0)) if self._config is not None else 1.0
        except (TypeError, ValueError):
            value = 1.0
        return value if value > 0 else 1.0

    def _history_phase(self, scan: _Scan, ctx: Dict[str, Any]) -> None:
        self._phase_update(scan, "history", status="running", message="Reading the ping and outage history")
        with self._lock:
            end = float(scan.job.get("started_ts") or self._clock())
            job_network = scan.job.get("network_id")
        problems: List[str] = []
        result = ctx.get("speed_result") if isinstance(ctx.get("speed_result"), dict) else {}
        good = bool(result.get("ok"))
        try:
            ctx["network"] = build_network_section(self._netinfo_snapshot(),
                                                   (result.get("external_ip") if good else None) or self._live_public_ip(),
                                                   result.get("isp") if good else None)
        except Exception as exc:  # noqa: BLE001
            log.exception("full scan: the network section failed")
            problems.append("network")
            ctx["network"] = empty_section("network", f"Could not be collected: {exc}")
        gateway = (ctx["network"].get("internet_nic") or {}).get("gateway")
        self._check_gateway_mac()
        # only the data of the network the scan started on counts (and untagged data by the time rule); unknown: the time rule
        scope, ctx["network_meta"], why = self._site_scope(job_network, end)
        if job_network is None:
            why = scan.network_why
        start, reason = self.window_preview(end, scope["id"] if scope is not None else None)
        ctx["window"] = (start, end, reason)
        with self._lock:
            scan.job.update(window_start=round(start, 3), window_reason=reason)
            if scope is not None:
                scan.job["network_id"] = scope["id"]
        try:
            ping_mgr = getattr(self._engine, "ping", None)
            views = ping_mgr.targets() if ping_mgr is not None else []
        except Exception:  # noqa: BLE001
            log.debug("live target views unavailable for the report", exc_info=True)
            views = []
        no_history = None
        configured: Optional[List[Dict[str, Any]]] = None
        left_out: "set[int]" = set()                    # the targets this report leaves out: both notes count this one set
        try:
            configured = self._configured_targets()     # read once: both sections describe the same targets
            ctx["ping"] = build_ping_section(self._db, start, end, reason, views, gateway, configured, left_out, network=scope)
            if not ctx["ping"]["available"] and not ctx["ping"]["note"]:
                no_history = ctx["ping"]["reason"]      # nothing pinged in the window: no outage could have been noticed either
        except Exception as exc:  # noqa: BLE001
            log.exception("full scan: the ping section failed")
            problems.append("ping")
            ctx["ping"] = empty_section("ping", f"Could not be collected: {exc}")
            ctx["ping"].update(window_start=round(start, 3), window_end=round(end, 3), window_reason=reason)
        gaps: List[Tuple[float, float]] = []
        try:
            if configured is None:
                configured = self._configured_targets()  # never count the outages of removed targets for want of the list
            rows = self._outage_rows(start, end)
            monitored = None
            if scope is not None:
                rows = scope_outage_rows(rows, scope["id"], scope["legacy_since"], scope["travel"])
                # the monitoring gaps of the site's network only: another network's gap (and a trip's) is not inside its visits
                for r in rows:
                    s, e = _num(r.get("start_ts")), _num(r.get("end_ts"))
                    if r.get("kind") == "gap" and s is not None:
                        gaps.append((max(s, start), min(end if e is None else e, end)))
                monitored = monitored_seconds(ctx["ping"].get("visits") or [], gaps)
            ctx["outages"] = build_outages_section(rows, start, end, self._interval_s(),
                                                   self._host_lookup(), self._label_lookup(views, configured), no_history,
                                                   [row["id"] for row in configured], left_out, monitored_s=monitored)
        except Exception as exc:  # noqa: BLE001
            log.exception("full scan: the outages section failed")
            problems.append("outages")
            ctx["outages"] = empty_section("outages", f"Could not be collected: {exc}")
        if ctx["ping"].get("note"):
            # a target with an outage row but no minutes in the window (its last minutes never stored) counts on both headings
            ctx["ping"]["note"] = left_out_note(len(left_out))
        # monitored time, the same on both sections: on the site's network its visits without the gaps; by time the window without them
        if scope is not None:
            ctx["ping"]["monitored_s"] = monitored_seconds(ctx["ping"].get("visits") or [], gaps)
        else:
            ctx["ping"]["monitored_s"] = ctx["outages"].get("monitored_s")
        try:
            by_network = {"network_id": scope["id"], "legacy_since": scope["legacy_since"]} if scope is not None else {}
            rows = self._db.list_speedtests(start, float(self._clock()) + 1.0, ok_only=True, **by_network)
            ctx["speed"] = build_speed_section(ctx.get("speed_result"), rows, ctx.get("speed_error"))
        except Exception as exc:  # noqa: BLE001
            log.exception("full scan: the speed section failed")
            problems.append("speed")
            ctx["speed"] = build_speed_section(ctx.get("speed_result"), [], ctx.get("speed_error"))
        ctx["discovery"] = build_discovery_section(ctx.get("discovery_run"), [gateway] if gateway else [],
                                                   ctx.get("discovery_error"), ctx.get("discovery_note"))
        if scan.cancel.is_set():
            return
        if problems:
            self._phase_update(scan, "history", status="error", message=f"Could not read: {', '.join(problems)}")
        else:
            message = history_message(start, end, reason)
            if why in NETWORK_NOTE_MESSAGES:
                message += f"; {NETWORK_NOTE_MESSAGES[why]}"
            self._phase_update(scan, "history", status="done", message=message)

    def _configured_targets(self) -> List[Dict[str, Any]]:
        """The targets a new report describes: the rows of the targets table that are enabled now, the gateway alias included (a
        removed target has no row any more, a disabled one is left out too; the module docstring says why only ids count).  Read
        once per scan: the ping table's hosts, labels and kinds and the ids both sections keep all come from these rows."""
        return list(self._db.list_targets(enabled_only=True))

    def _label_lookup(self, views: Sequence[Dict[str, Any]], configured: Sequence[Dict[str, Any]]) -> Callable[[Any], Optional[str]]:
        """A target's label (the live view's, else that of the row the scan read) for the outage items."""
        labels: Dict[int, Optional[str]] = {}
        for row in configured or []:
            tid = _int_in(row.get("id") if isinstance(row, dict) else None, 0, 2 ** 62)
            if tid is not None:
                labels[tid] = row.get("label")
        for view in views or []:
            tid = _int_in(view.get("id") if isinstance(view, dict) else None, 0, 2 ** 62)
            if tid is not None and "label" in view:
                labels[tid] = view.get("label")

        def label_for(tid: Any) -> Optional[str]:
            key = _int_in(tid, 0, 2 ** 62)
            return labels.get(key) if key is not None else None

        return label_for

    def _outage_rows(self, start: float, end: float) -> List[Dict[str, Any]]:
        tracker = getattr(self._engine, "outages", None)
        if tracker is not None and callable(getattr(tracker, "list", None)):
            return list(tracker.list(start, end) or [])
        return list(self._db.list_outages(start, end) or [])

    def _host_lookup(self) -> Callable[[Any], Optional[str]]:
        cache: Dict[Any, Optional[str]] = {}

        def host_for(tid: Any) -> Optional[str]:
            if tid is None:
                return None
            if tid not in cache:
                try:
                    row = self._db.get_target(int(tid))
                    cache[tid] = (row or {}).get("host") or self._db.last_outage_host(int(tid))
                except Exception:  # noqa: BLE001
                    cache[tid] = None
            return cache[tid]

        return host_for

    # save --------------------------------------------------------------------
    def _hostname(self) -> Optional[str]:
        try:
            return self._hostname_fn() if self._hostname_fn is not None else socket.gethostname()
        except Exception:  # noqa: BLE001
            return None

    def _save_phase(self, scan: _Scan, ctx: Dict[str, Any]) -> None:
        self._phase_update(scan, "save", status="running", message="Saving the report")
        job = scan.job
        with self._lock:
            if scan.cancel.is_set() or job.get("status") != "running":
                return
            scan.saving = True
            named = job.get("site")
            job_network = job.get("network_id")
            created = float(job["started_ts"])
            completed = round(float(self._clock()), 3)
            phases = [{k: p.get(k) for k in ("key", "status", "message", "started_ts", "finished_ts")} for p in job["phases"]]
        # not named: the site this network was scanned as last, read again now (its report may have been renamed or deleted)
        suggested = None if named else self._suggested_site(job_network)
        site = named or (suggested or {}).get("site") or UNNAMED_SITE
        network_meta = ctx.get("network_meta")
        if not isinstance(network_meta, dict):
            from .networks import unknown_network

            network_meta = unknown_network()
        for ph in phases:
            if ph["key"] == "save":
                ph.update(status="done", message=None, finished_ts=completed)
        status = "complete" if all(p["status"] == "done" for p in phases) else "partial"
        data = {
            "meta": {"site": site, "created_ts": created, "completed_ts": completed,
                     "duration_s": round(completed - created, 1), "tnt_version": __version__,
                     "hostname": self._hostname(), "scan_phases": phases, "network": network_meta},
            "network": ctx.get("network") or empty_section("network", "Not collected"),
            "speed": ctx.get("speed") or empty_section("speed", "Not collected"),
            "ping": ctx.get("ping") or empty_section("ping", "Not collected"),
            "outages": ctx.get("outages") or empty_section("outages", "Not collected"),
            "discovery": ctx.get("discovery") or empty_section("discovery", "Not collected"),
            "wifi": ctx.get("wifi") or empty_section("wifi", NO_WINDOW_REASON),
        }
        summary = build_summary(data)
        tagged = {"network_id": network_meta["id"]} if network_meta.get("id") is not None else {}
        try:
            report_id = self._db.add_report(site, site_key(site), created, completed, status, __version__, summary, data, **tagged)
        except Exception:
            with self._lock:
                scan.saving = False
            raise
        with self._lock:
            pending, scan.pending_site = scan.pending_site, None
            self._stats, self._stats_gen = None, self._stats_gen + 1
            message = f"Saved the report for {site}"
            if suggested and not named:
                message += ", the site this network was scanned as before"
                job.update(site=site, suggested_site=suggested)
            job.update(status="saved", phase=None, pct=100, report_id=report_id, message=message)
            for ph in job["phases"]:
                if ph["key"] == "save":
                    ph.update(status="done", message=job["message"], finished_ts=completed)
            scan.saving = False
        log.info("full scan %s saved as report %d (%s, %s)", job.get("id"), report_id, site, status)
        self._publish_progress(job, force=True)
        self._publish("report.saved", {"id": report_id, "site": site, "status": status})
        if pending and pending != site:
            self.rename(report_id, pending)
            self._publish_progress(job, force=True)

    # -- store -----------------------------------------------------------------
    def list_reports(self, site_key_value: Any = None, q: Any = None, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        key = search_key(site_key_value)
        rows, total = self._db.list_reports(key, search_key(q), int(limit), int(offset))
        return {"reports": rows, "total": total}

    def sites(self, q: Any = None, limit: int = 20) -> Dict[str, Any]:
        rows, total = self._db.report_sites(search_key(q), int(limit))
        return {"sites": rows, "total": total}

    def get(self, report_id: int) -> Optional[Dict[str, Any]]:
        """A saved report, the device types older versions stored renamed (:func:`rename_legacy_device_types`)."""
        return rename_legacy_device_types(self._db.get_report(int(report_id)))

    def rename(self, report_id: int, site: Any) -> Optional[Dict[str, Any]]:
        """``ValueError`` for a bad name; None when the report does not exist."""
        name = normalize_site(site)
        row = self._db.rename_report(int(report_id), name, site_key(name))
        if row is None:
            return None
        with self._lock:
            self._stats, self._stats_gen = None, self._stats_gen + 1
            job = self._scan.job if self._scan is not None else None
            if job is not None and job.get("report_id") == row["id"]:
                job["site"] = name
            suggested = job.get("suggested_site") if job is not None else None
            follow = (job is not None and job.get("status") == "running" and isinstance(suggested, dict)
                      and suggested.get("report_id") == row["id"])
            if follow:
                job["suggested_site"] = dict(suggested, site=name)     # the running scan suggests the site by its new name
        self._publish("report.updated", {"id": row["id"], "site": name})
        if follow:
            self._publish_progress(job, force=True)
        return row

    def delete(self, report_id: int) -> bool:
        """Delete a report; the last scan's job forgets it when it is the one that scan saved (``report_id`` null)."""
        ok = bool(self._db.delete_report(int(report_id)))
        if ok:
            forgot = None
            resuggest = None
            with self._lock:
                self._stats, self._stats_gen = None, self._stats_gen + 1
                job = self._scan.job if self._scan is not None else None
                if job is not None and job.get("report_id") == int(report_id):
                    job["report_id"] = None
                    forgot = job
                suggested = job.get("suggested_site") if job is not None else None
                if (job is not None and job.get("status") == "running" and isinstance(suggested, dict)
                        and suggested.get("report_id") == int(report_id)):
                    resuggest = job
            if resuggest is not None:
                # the running scan suggested that report's site: the network's newest report left, if any
                fresh = self._suggested_site(resuggest.get("network_id"))
                with self._lock:
                    if resuggest.get("status") == "running":
                        resuggest["suggested_site"] = fresh
            self._publish("report.deleted", {"id": int(report_id)})
            if forgot is not None:
                self._publish_progress(forgot, force=True)
            elif resuggest is not None:
                self._publish_progress(resuggest, force=True)
        return ok

    def compare(self, a_id: int, b_id: int) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """``(report_a, report_b, comparison)``; ``KeyError`` naming the id that does not exist."""
        a = self.get(a_id)
        if a is None:
            raise KeyError(a_id)
        b = a if b_id == a_id else self.get(b_id)
        if b is None:
            raise KeyError(b_id)
        return a, b, compare_reports(a, b)

    def status(self) -> Dict[str, Any]:
        """``{"count", "sites", "last": {"id","site","created_ts","status"}|None, "job"}`` for ``/api/status``."""
        with self._lock:
            stats, gen = self._stats, self._stats_gen
        if stats is None:
            stats = self._db.report_stats()
            with self._lock:
                if self._stats_gen == gen:      # no save, rename or delete while it was read: the counts are current
                    self._stats = stats
        return {"count": stats.get("count", 0), "sites": stats.get("sites", 0), "last": stats.get("last"), "job": self.job()}


__all__ = [
    "NET_JOINED_META_KEY", "NO_WINDOW_REASON", "ReportManager", "ScanBusy", "ScanConflict", "UNNAMED_SITE",
    "build_discovery_section", "build_network_section", "build_outages_section", "build_ping_section",
    "build_speed_section", "build_summary", "build_wifi_section", "channel_span", "channels_overlap", "clean_wifi_snapshot",
    "compare_filename", "compare_reports", "connection_text", "history_message", "link_text", "monitored_text",
    "normalize_site", "outage_numbers", "pdf_filename", "ping_stats", "report_window", "search_key", "site_key", "target_name",
    "merge_spans", "monitored_seconds", "network_time", "network_time_note", "network_time_text", "report_network", "same_network_note",
    "scope_outage_rows", "travel_spans", "visits_from_minutes", "left_out_note", "duration_text", "NETWORK_NOTE_MESSAGES",
    "NETWORK_TIME_NOTE",
]
