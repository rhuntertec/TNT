"""Wi-Fi survey for the WiFi tile: every access point this PC hears, with its signal over time.

Why this runs in ``TNT.exe`` and not in the service
---------------------------------------------------
Since Windows 11 24H2 the WLAN functions that expose BSSIDs (``WlanGetNetworkBssList``,
``WlanGetAvailableNetworkList``, ``WlanScan``, ``WlanQueryInterface`` for the current
connection) fail with ``ERROR_ACCESS_DENIED`` unless the calling user has granted precise
location access: a BSSID list is a location fix. The LocalSystem service has no user to ask
(SYSTEM's own consent is normally "Deny"), so the survey runs inside the tray/window client,
as the signed-in user, where Windows can show its one-time location prompt and where the
Settings page lists TNT. The results reach the UI only through the pywebview bridge
(``window.pywebview.api.wifi_*``, see ``client/tray.py``), never through the loopback HTTP API,
so no other local program can read this PC's surroundings off ``127.0.0.1``.

Microsoft's guidance is to ask at a user action and to throttle, so the "location in use" icon
is not shown all the time: the session starts only when the TNT window is actually shown (not
while TNT.exe waits minimised in the tray after sign-in), a background read of Windows' cached
BSS list happens once a minute, and active scanning runs only while the WiFi page holds a lease.

Scheduling (one daemon thread, ``wifi-survey``)
-----------------------------------------------
* Session: starts on the first :meth:`WifiSurvey.window_shown` or on a :meth:`WifiSurvey.survey`
  call the caller allows to start it (the window is visible or the page is active), and only
  while enabled. It lives until TNT.exe quits; :meth:`WifiSurvey.clear` restarts it.
  :meth:`WifiSurvey.clear_since` (Settings > Clear history) removes the readings from a time on
  and keeps the session; ``None`` is :meth:`WifiSurvey.clear`.
* Passive: ``WlanGetNetworkBssList`` (the cached list, no ``WlanScan``) every
  ``passive_interval_s`` (60 s).
* Active, while the lease from ``survey({"active": true})`` / :meth:`WifiSurvey.scan_now` is valid
  (30 s): ``WlanScan`` every ``scan_interval_s`` (10 s, never more often than every 5 s), a read
  4 s after each scan request and every 5 s. ``scan_now`` asks for an immediate read + scan and
  is rate limited to one request per 5 s; a request within 5 s of an automatic scan is accepted
  and its scan waits until 5 s after that one.
* ``ERROR_ACCESS_DENIED`` -> ``location_denied``, retried at most every 60 s or on ``scan_now``;
  WLAN AutoConfig stopped or missing (``ERROR_SERVICE_NOT_ACTIVE``, ``ERROR_SERVICE_DOES_NOT_EXIST``),
  no ``wlanapi.dll``, no Wi-Fi interface, or every interface unplugged while a pass ran
  (``ERROR_NOT_FOUND`` from the list or scan call) -> ``no_adapter``; every radio off
  (``wlan_intf_opcode_radio_state``, or ``ERROR_NDIS_DOT11_POWER_STATE_INVALID`` from the list or
  scan call when the radio state could not be read) -> ``radio_off`` (no list or scan calls).
* Disabled (``wifi_survey_enabled`` false in client.json): no WLAN call at all and the handle is
  closed; the collected data stays until cleared.

Store
-----
One ``RLock`` guards everything; the native calls run outside it and the bridge methods only
copy. A read counts each BSSID once, with the copy whose beacon Windows received last (the same
AP heard through two adapters, or listed twice). That reading is *fresh* when
``ullHostTimestamp`` (or the beacon TSF) differs from the one seen before -- the cached list
repeats old values between scans, and only fresh readings update ``rssi``/``last_seen``/
``seen_count`` and add a history point. ``last_seen`` is the time Windows received that beacon
(``ullHostTimestamp`` is a FILETIME; an implausible value falls back to the read time). An AP is
``stale`` when it was not in the latest successful read or its last beacon is older than 120 s.
At most 1000 BSSIDs are kept (the ones with the oldest last beacon are evicted) and at most 8640
history points each (24 h at one point per 10 s), coalesced to one point per 5 s and stored
compactly (``array('I')`` deciseconds since the session start + ``array('b')`` dBm in a ring).
A reading whose beacon is more than 15 s older than the session start adds no history point.
A history point is stamped with its beacon time, but never earlier than the session start or the
previous successful read (a scan's results can reach the cached list after a read that happened
while the scan was still running): a caller that has seen ``last_read_ts`` = T therefore gets
every later reading by asking for ``history_s`` >= now - T, which is how the WiFi page fetches
only what is new. When the wall clock steps back (checked against the monotonic clock on every
pass and survey call), every stored time moves back with it, so the history stays in order and
``stale`` keeps working; a forward jump (also what a sleep looks like) is left alone.

Link speed: every read pass that asks an interface for its association also takes the association's
``ulTxRate`` / ``ulRxRate`` (kb/s): ``interfaces[].tx_rate_mbps`` / ``rx_rate_mbps``, the speed of the
link from this PC to its access point and back (what the Windows Wi-Fi status dialog calls "Speed";
None while not connected). The transmit rate of the first connected interface (enumeration order) also
goes into one session-long series, ``link_history`` (``[[epoch s, Mbps], ...]``), stamped with the time
the pass ended: 0 when no interface is associated (or the radio is off, or the adapter is gone), no point
when the association could not be read. It has the store's bounds (one point per 5 s, at most 8640 in an
``array('I')`` ring of kb/s) and the same ``history_s`` window and thinning as the signal history.

What one survey call returns is bounded: readings from the last hour before the call
(``HISTORY_FULL_S``) are returned as stored, so the page's 5 min / 15 min / 1 h ranges are exact,
and older readings in the requested window are thinned to the lowest and the highest reading of
each of ``HISTORY_THIN_BUCKETS`` equal slices of their span. Only the ring slices are copied
under the lock; the lists are built after it is released.

Nothing here logs an SSID or a BSSID above debug level. The module is import-safe off Windows
(``wlanapi`` loads lazily in :func:`_dll`) and every native piece has a seam: ``api_factory``
(anything shaped like :class:`WlanSurveyApi`), ``clock``/``monotonic`` and ``threaded=False``
(tests drive :meth:`WifiSurvey.tick` by hand).
"""
from __future__ import annotations

import bisect
import ctypes
import heapq
import logging
import math
import threading
import time
from array import array
from ctypes import POINTER, Structure, byref, c_int32, c_uint8, c_uint16, c_uint32, c_uint64, c_void_p
from typing import Any, Callable, Dict, List, Optional, Tuple

from client import wifi_ies

log = logging.getLogger(__name__)

__all__ = [
    "WifiSurvey", "WlanSurveyApi", "blank_view", "read_bss_list", "layout_ok", "history_points", "is_epoch_time",
    "SCAN_INTERVAL_S", "PASSIVE_INTERVAL_S", "LEASE_S", "MAX_APS", "MAX_POINTS", "STATES",
]

# -- schedule and bounds ------------------------------------------------------------------------
SCAN_INTERVAL_S = 10.0
MIN_SCAN_GAP_S = 5.0
PASSIVE_INTERVAL_S = 60.0
ACTIVE_READ_S = 5.0
POST_SCAN_READ_S = 4.0
LEASE_S = 30.0
LOCATION_RETRY_S = 60.0
STALE_S = 120.0
MAX_APS = 1000
MAX_AP_AGE_S = 24 * 3600.0      # drop (and never list) an access point not heard in the last 24 h, so the list does not accumulate every AP ever seen
MAX_POINTS = 8640
COALESCE_S = 5.0
#: A beacon this much older than the session start still adds a history point (at the start).
HISTORY_GRACE_S = 15.0
#: ``ullHostTimestamp`` converted to epoch seconds must fall within this window of "now".
BEACON_MAX_AGE_S = 6 * 3600.0
BEACON_MAX_AHEAD_S = 120.0
#: The scanner thread waits at most this long without a wake-up (and at least MIN_WAIT_S).
IDLE_WAIT_S = 3600.0
MIN_WAIT_S = 0.05
RETRY_AFTER_ERROR_S = 5.0
#: The wall clock running this much behind the monotonic clock since the last check is a step back.
CLOCK_STEP_S = 5.0
#: A survey call returns this much recent history as stored (the page's longest finite range) ...
HISTORY_FULL_S = 3600.0
#: ... and thins older readings to the lowest and highest of this many slices of their span.
HISTORY_THIN_BUCKETS = 300
#: A link speed above this (kb/s: 100 Gb/s) is a garbled structure, not a reading.
MAX_LINK_KBPS = 100_000_000

STATES = ("ok", "starting", "disabled", "no_adapter", "radio_off", "location_denied", "error")

NOT_STARTED_TEXT = "The Wi-Fi survey starts when the TNT window is opened."
STARTING_TEXT = "Reading the Wi-Fi adapter..."
DISABLED_TEXT = "The Wi-Fi survey is switched off."
NO_ADAPTER_TEXT = ("No Wi-Fi adapter was found on this PC, or the Windows WLAN AutoConfig service is not "
                   "running.")
RADIO_OFF_TEXT = "Wi-Fi is turned off on this PC. Turn Wi-Fi on in Windows to see nearby networks."
LOCATION_DENIED_TEXT = ("Windows is not letting TNT see nearby Wi-Fi networks. Turn on location access "
                        "(Settings > Privacy & security > Location, including \"Let desktop apps access "
                        "your location\") and try again.")
SCAN_TOO_SOON_TEXT = "A scan was just requested. Try again in a few seconds."

# -- Win32 --------------------------------------------------------------------------------------
WLAN_API_VERSION = 2
ERROR_SUCCESS = 0
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_MOD_NOT_FOUND = 126
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_NOT_ACTIVE = 1062
ERROR_NOT_FOUND = 1168
ERROR_INVALID_STATE = 5023
#: A list or scan call on an interface whose radio is off.
ERROR_NDIS_DOT11_POWER_STATE_INVALID = 0x80342002
#: Codes that mean "nothing to survey with": no wlanapi.dll, WLAN AutoConfig missing or stopped.
NO_ADAPTER_CODES = (ERROR_MOD_NOT_FOUND, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE)
DOT11_BSS_TYPE_ANY = 3
WLAN_INTF_OPCODE_RADIO_STATE = 4
WLAN_INTF_OPCODE_CURRENT_CONNECTION = 7
DOT11_RADIO_STATE_OFF = 2
#: ``FILETIME`` of the Unix epoch (100 ns ticks since 1601-01-01).
FILETIME_UNIX_EPOCH = 116444736000000000

WLAN_INTERFACE_STATES: Dict[int, str] = {
    0: "not_ready", 1: "connected", 2: "ad_hoc_network_formed", 3: "disconnecting",
    4: "disconnected", 5: "associating", 6: "discovering", 7: "authenticating",
}

MAX_INTERFACES = 64
MAX_BSS_ENTRIES = 4096
MAX_BSS_LIST_BYTES = 64 * 1024 * 1024
MAX_IE_BYTES = 64 * 1024
WLAN_MAX_NAME_LENGTH = 256

# Fixed-width aliases, so the layout is the Windows x64 one on any interpreter.
DWORD = c_uint32
LONG = c_int32
BOOL = c_int32
BOOLEAN = c_uint8
USHORT = c_uint16
ULONGLONG = c_uint64
WCHAR = c_uint16


# --- native structures (x64 layout per wlanapi.h / windot11.h) -----------------------------------
class GUID(Structure):
    _fields_ = [("Data1", DWORD), ("Data2", USHORT), ("Data3", USHORT), ("Data4", c_uint8 * 8)]   # 16


class WLAN_INTERFACE_INFO(Structure):
    _fields_ = [
        ("InterfaceGuid", GUID),                                  # 0
        ("strInterfaceDescription", WCHAR * WLAN_MAX_NAME_LENGTH),  # 16
        ("isState", DWORD),                                       # 528
    ]                                                             # sizeof == 532


class WLAN_INTERFACE_INFO_LIST(Structure):
    _fields_ = [("dwNumberOfItems", DWORD), ("dwIndex", DWORD), ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class DOT11_SSID(Structure):
    _fields_ = [("uSSIDLength", DWORD), ("ucSSID", c_uint8 * 32)]    # 36


class WLAN_RATE_SET(Structure):
    _fields_ = [("uRateSetLength", DWORD), ("usRateSet", USHORT * 126)]   # 256


class WLAN_BSS_ENTRY(Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),            # 0
        ("uPhyId", DWORD),                    # 36
        ("dot11Bssid", c_uint8 * 6),          # 40 (+2 padding)
        ("dot11BssType", DWORD),              # 48
        ("dot11BssPhyType", DWORD),           # 52
        ("lRssi", LONG),                      # 56
        ("uLinkQuality", DWORD),              # 60
        ("bInRegDomain", BOOLEAN),            # 64 (+1)
        ("usBeaconPeriod", USHORT),           # 66 (+4)
        ("ullTimestamp", ULONGLONG),          # 72
        ("ullHostTimestamp", ULONGLONG),      # 80
        ("usCapabilityInformation", USHORT),  # 88 (+2)
        ("ulChCenterFrequency", DWORD),       # 92 (kHz)
        ("wlanRateSet", WLAN_RATE_SET),       # 96
        ("ulIeOffset", DWORD),                # 352 (from the start of this entry)
        ("ulIeSize", DWORD),                  # 356
    ]                                         # sizeof == 360


class WLAN_BSS_LIST(Structure):
    _fields_ = [("dwTotalSize", DWORD), ("dwNumberOfItems", DWORD), ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]


class WLAN_ASSOCIATION_ATTRIBUTES(Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),            # 0
        ("dot11BssType", DWORD),              # 36
        ("dot11Bssid", c_uint8 * 6),          # 40 (+2)
        ("dot11PhyType", DWORD),              # 48
        ("uDot11PhyIndex", DWORD),            # 52
        ("wlanSignalQuality", DWORD),         # 56
        ("ulRxRate", DWORD),                  # 60
        ("ulTxRate", DWORD),                  # 64
    ]                                         # sizeof == 68


class WLAN_SECURITY_ATTRIBUTES(Structure):
    _fields_ = [("bSecurityEnabled", BOOL), ("bOneXEnabled", BOOL), ("dot11AuthAlgorithm", DWORD),
                ("dot11CipherAlgorithm", DWORD)]     # 16


class WLAN_CONNECTION_ATTRIBUTES(Structure):
    _fields_ = [
        ("isState", DWORD),                                  # 0
        ("wlanConnectionMode", DWORD),                       # 4
        ("strProfileName", WCHAR * WLAN_MAX_NAME_LENGTH),    # 8
        ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES),   # 520
        ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES),         # 588
    ]                                                        # sizeof == 604


class WLAN_PHY_RADIO_STATE(Structure):
    _fields_ = [("dwPhyIndex", DWORD), ("dot11SoftwareRadioState", DWORD), ("dot11HardwareRadioState", DWORD)]


class WLAN_RADIO_STATE(Structure):
    _fields_ = [("dwNumberOfPhys", DWORD), ("PhyRadioState", WLAN_PHY_RADIO_STATE * 64)]   # 772


_IFACE_ROWS_OFFSET = WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset
_BSS_ROWS_OFFSET = WLAN_BSS_LIST.wlanBssEntries.offset
_BSS_ENTRY_SIZE = ctypes.sizeof(WLAN_BSS_ENTRY)


def layout_ok() -> bool:
    """The structure sizes match wlanapi.h on x64 (checked by tests and ``TNT.exe --selfcheck``)."""
    return (ctypes.sizeof(WLAN_BSS_ENTRY) == 360 and _BSS_ROWS_OFFSET == 8 and _IFACE_ROWS_OFFSET == 8
            and WLAN_BSS_ENTRY.ulIeOffset.offset == 352 and ctypes.sizeof(WLAN_INTERFACE_INFO) == 532
            and ctypes.sizeof(WLAN_CONNECTION_ATTRIBUTES) == 604 and ctypes.sizeof(WLAN_RADIO_STATE) == 772)


_dll_lock = threading.Lock()
_wlanapi: Any = None


def _dll() -> Any:
    """``wlanapi`` with every prototype declared, loaded on first use (ctypes without argtypes
    crashes on x64; see tnt/arp.py)."""
    global _wlanapi
    with _dll_lock:
        if _wlanapi is None:
            dll = ctypes.WinDLL("wlanapi", use_last_error=True)
            dll.WlanOpenHandle.argtypes = [DWORD, c_void_p, POINTER(DWORD), POINTER(c_void_p)]
            dll.WlanOpenHandle.restype = DWORD
            dll.WlanCloseHandle.argtypes = [c_void_p, c_void_p]
            dll.WlanCloseHandle.restype = DWORD
            dll.WlanEnumInterfaces.argtypes = [c_void_p, c_void_p, POINTER(c_void_p)]
            dll.WlanEnumInterfaces.restype = DWORD
            dll.WlanGetNetworkBssList.argtypes = [c_void_p, POINTER(GUID), POINTER(DOT11_SSID), DWORD, BOOL,
                                                  c_void_p, POINTER(c_void_p)]
            dll.WlanGetNetworkBssList.restype = DWORD
            dll.WlanScan.argtypes = [c_void_p, POINTER(GUID), POINTER(DOT11_SSID), c_void_p, c_void_p]
            dll.WlanScan.restype = DWORD
            dll.WlanQueryInterface.argtypes = [c_void_p, POINTER(GUID), DWORD, c_void_p, POINTER(DWORD),
                                               POINTER(c_void_p), POINTER(DWORD)]
            dll.WlanQueryInterface.restype = DWORD
            dll.WlanFreeMemory.argtypes = [c_void_p]
            dll.WlanFreeMemory.restype = None
            _wlanapi = dll
        return _wlanapi


def _format_error(rc: int) -> str:
    try:
        text = ctypes.FormatError(int(rc))  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - not Windows, or an unknown code
        text = ""
    return f"{text} ({rc})" if text else f"error {rc}"


def _winerror(exc: BaseException) -> Optional[int]:
    code = getattr(exc, "winerror", None)
    if code is None:
        code = getattr(exc, "errno", None)
    try:
        return int(code) if code is not None else None
    except (TypeError, ValueError):
        return None


def _code_suffix(exc: BaseException) -> str:
    """`` (error 1722)`` for a Win32 failure, empty for anything without a code."""
    code = _winerror(exc)
    return f" (error {code})" if code is not None else ""


def _guid_text(guid: GUID) -> str:
    tail = "".join(f"{b:02x}" for b in bytes(guid.Data4))
    return f"{guid.Data1 & 0xFFFFFFFF:08x}-{guid.Data2:04x}-{guid.Data3:04x}-{tail[:4]}-{tail[4:]}"


def _wide_text(chars: Any) -> str:
    raw = bytes(chars)
    text = raw.decode("utf-16-le", errors="replace")
    return text.split("\x00", 1)[0].strip()


def read_bss_list(address: int) -> List[Dict[str, Any]]:
    """Copy every entry of the ``WLAN_BSS_LIST`` at *address* into plain dicts
    (:data:`client.wifi_ies.ENTRY_KEYS`). Every read is bounds-checked against ``dwTotalSize``, so
    a corrupt count or IE offset can never make ctypes read outside the API's buffer."""
    header = WLAN_BSS_LIST.from_address(address)
    total = int(header.dwTotalSize)
    count = int(header.dwNumberOfItems)
    if not _BSS_ROWS_OFFSET <= total <= MAX_BSS_LIST_BYTES or count > MAX_BSS_ENTRIES:
        raise OSError(0, f"WlanGetNetworkBssList returned an implausible list ({count} entries, {total} bytes)")
    fits = (total - _BSS_ROWS_OFFSET) // _BSS_ENTRY_SIZE
    if count > fits:
        log.debug("BSS list claims %d entries but only %d fit in %d bytes", count, fits, total)
        count = fits
    rows_end = address + _BSS_ROWS_OFFSET + count * _BSS_ENTRY_SIZE
    list_end = address + total
    out: List[Dict[str, Any]] = []
    for i in range(count):
        base = address + _BSS_ROWS_OFFSET + i * _BSS_ENTRY_SIZE
        e = WLAN_BSS_ENTRY.from_address(base)
        ssid_len = min(int(e.dot11Ssid.uSSIDLength), 32)
        n_rates = min(int(e.wlanRateSet.uRateSetLength), 126)
        ie_start = base + int(e.ulIeOffset)
        ie_size = int(e.ulIeSize)
        ies = b""
        if 0 < ie_size <= MAX_IE_BYTES and ie_start >= rows_end and ie_start + ie_size <= list_end:
            ies = ctypes.string_at(ie_start, ie_size)
        out.append({
            "ssid": bytes(e.dot11Ssid.ucSSID)[:ssid_len],
            "bssid": bytes(e.dot11Bssid),
            "phy_type": int(e.dot11BssPhyType),
            "rssi": int(e.lRssi),
            "link_quality": int(e.uLinkQuality),
            "in_reg_domain": bool(e.bInRegDomain),
            "beacon_period": int(e.usBeaconPeriod),
            "timestamp": int(e.ullTimestamp),
            "host_timestamp": int(e.ullHostTimestamp),
            "capability": int(e.usCapabilityInformation),
            "freq_khz": int(e.ulChCenterFrequency),
            "rates": [int(r) for r in e.wlanRateSet.usRateSet[:n_rates] if r],
            "ies": ies,
        })
    return out


class WlanSurveyApi:
    """The Wlan API calls the survey makes, one handle per instance (the scanner thread keeps one
    and reopens it after a failure). Every method raises ``OSError`` with the Win32 code as
    ``errno`` on failure (``ERROR_ACCESS_DENIED`` = no location consent)."""

    def __init__(self) -> None:
        self._dll: Any = None
        self._handle: Any = None

    # -- lifecycle ---------------------------------------------------------------------
    def open(self) -> None:
        try:
            dll = _dll()
        except OSError as exc:          # no wlanapi.dll (a Windows Server without the Wireless LAN Service)
            raise OSError(ERROR_MOD_NOT_FOUND, f"wlanapi.dll could not be loaded: {exc}") from exc
        handle = c_void_p()
        negotiated = DWORD(0)
        rc = int(dll.WlanOpenHandle(WLAN_API_VERSION, None, byref(negotiated), byref(handle)))
        if rc != ERROR_SUCCESS:
            raise OSError(rc, f"WlanOpenHandle failed: {_format_error(rc)}")
        self._dll, self._handle = dll, handle

    def close(self) -> None:
        dll, handle = self._dll, self._handle
        self._dll = self._handle = None
        if dll is None or handle is None:
            return
        try:
            dll.WlanCloseHandle(handle, None)
        except Exception:  # noqa: BLE001 - closing must never be the reason a pass fails
            log.debug("WlanCloseHandle failed", exc_info=True)

    def _require(self) -> Tuple[Any, Any]:
        if self._dll is None or self._handle is None:
            raise OSError(ERROR_INVALID_HANDLE, "the Wlan API handle is not open")
        return self._dll, self._handle

    def _free(self, ptr: Any) -> None:
        try:
            self._dll.WlanFreeMemory(ptr)
        except Exception:  # noqa: BLE001
            log.debug("WlanFreeMemory failed", exc_info=True)

    def _query(self, ref: GUID, opcode: int, struct_type: Any) -> Tuple[int, Any]:
        """``WlanQueryInterface`` -> ``(rc, copy of the structure or None)``; the buffer is freed."""
        dll, handle = self._require()
        size = DWORD(0)
        data = c_void_p()
        kind = DWORD(0)
        rc = int(dll.WlanQueryInterface(handle, byref(ref), opcode, None, byref(size), byref(data), byref(kind)))
        if rc != ERROR_SUCCESS or not data.value:
            return rc, None
        try:
            if int(size.value) < ctypes.sizeof(struct_type):
                return rc, None
            copy = struct_type()
            ctypes.memmove(byref(copy), data.value, ctypes.sizeof(struct_type))
            return rc, copy
        finally:
            self._free(data)

    # -- calls ------------------------------------------------------------------------
    def interfaces(self) -> List[Dict[str, Any]]:
        """``[{"guid","description","state","ref"}]`` for every Wi-Fi interface."""
        dll, handle = self._require()
        ptr = c_void_p()
        rc = int(dll.WlanEnumInterfaces(handle, None, byref(ptr)))
        if rc != ERROR_SUCCESS:
            raise OSError(rc, f"WlanEnumInterfaces failed: {_format_error(rc)}")
        if not ptr.value:
            return []
        out: List[Dict[str, Any]] = []
        try:
            count = int(WLAN_INTERFACE_INFO_LIST.from_address(ptr.value).dwNumberOfItems)
            if not 0 <= count <= MAX_INTERFACES:
                raise OSError(0, f"WlanEnumInterfaces reported an implausible {count} interfaces")
            rows = (WLAN_INTERFACE_INFO * count).from_address(ptr.value + _IFACE_ROWS_OFFSET)
            for row in rows:
                ref = GUID()
                ctypes.memmove(byref(ref), byref(row.InterfaceGuid), ctypes.sizeof(GUID))
                out.append({"guid": _guid_text(ref), "description": _wide_text(row.strInterfaceDescription),
                            "state": WLAN_INTERFACE_STATES.get(int(row.isState), "unknown"), "ref": ref})
        finally:
            self._free(ptr)
        return out

    def radio_on(self, ref: GUID) -> Optional[bool]:
        """False when every PHY's software or hardware radio switch is off; None when unknown."""
        rc, state = self._query(ref, WLAN_INTF_OPCODE_RADIO_STATE, WLAN_RADIO_STATE)
        if state is None:
            return None
        phys = list(state.PhyRadioState[:min(int(state.dwNumberOfPhys), 64)])
        if not phys:
            return None
        return any(int(p.dot11SoftwareRadioState) != DOT11_RADIO_STATE_OFF
                   and int(p.dot11HardwareRadioState) != DOT11_RADIO_STATE_OFF for p in phys)

    def scan(self, ref: GUID) -> None:
        dll, handle = self._require()
        rc = int(dll.WlanScan(handle, byref(ref), None, None, None))
        if rc != ERROR_SUCCESS:
            raise OSError(rc, f"WlanScan failed: {_format_error(rc)}")

    def bss_list(self, ref: GUID) -> List[Dict[str, Any]]:
        dll, handle = self._require()
        ptr = c_void_p()
        rc = int(dll.WlanGetNetworkBssList(handle, byref(ref), None, DOT11_BSS_TYPE_ANY, False, None, byref(ptr)))
        if rc != ERROR_SUCCESS:
            raise OSError(rc, f"WlanGetNetworkBssList failed: {_format_error(rc)}")
        if not ptr.value:
            return []
        try:
            return read_bss_list(ptr.value)
        finally:
            self._free(ptr)

    def current_connection(self, ref: GUID) -> Optional[Dict[str, Any]]:
        """``{"ssid": bytes, "bssid": bytes, "rx_kbps": int, "tx_kbps": int}`` of the association (the link
        speeds in kb/s: 390000 is the "390.0 Mbps" of the Windows Wi-Fi status dialog), None when not connected."""
        rc, attrs = self._query(ref, WLAN_INTF_OPCODE_CURRENT_CONNECTION, WLAN_CONNECTION_ATTRIBUTES)
        if rc == ERROR_ACCESS_DENIED:
            raise OSError(rc, "WlanQueryInterface(current_connection) was denied")
        if attrs is None:
            return None
        assoc = attrs.wlanAssociationAttributes
        n = min(int(assoc.dot11Ssid.uSSIDLength), 32)
        return {"ssid": bytes(assoc.dot11Ssid.ucSSID)[:n], "bssid": bytes(assoc.dot11Bssid),
                "rx_kbps": int(assoc.ulRxRate), "tx_kbps": int(assoc.ulTxRate)}


# --- store -------------------------------------------------------------------------------------
class _Series:
    """One series: a ring of (deciseconds since the session start, value) at most *cap* long -- a BSSID's dBm
    (``array('b')``, the default) or the link speed in kb/s (``array('I')``)."""

    __slots__ = ("ts", "values", "head", "sealed")

    def __init__(self, typecode: str = "b") -> None:
        self.ts = array("I")
        self.values = array(typecode)
        self.head = 0
        #: set by drop_from: the newest point is from before a clear, so the next one never coalesces into it
        self.sealed = False

    def __len__(self) -> int:
        return len(self.ts)

    def add(self, t_ds: int, value: int, bucket_ds: int, cap: int) -> None:
        n = len(self.ts)
        if n:
            last = (self.head - 1) % n
            if t_ds < self.ts[last]:
                return                          # out of order (clock stepped back): keep it monotonic
            if not self.sealed and t_ds // bucket_ds == self.ts[last] // bucket_ds:
                self.ts[last], self.values[last] = t_ds, value
                return
        self.sealed = False
        if n < cap:
            self.ts.append(t_ds)
            self.values.append(value)
        else:
            self.ts[self.head], self.values[self.head] = t_ds, value
            self.head = (self.head + 1) % n

    def window(self, min_ds: Optional[float]) -> Tuple[array, array]:
        """Copies of ``(deciseconds, value)`` oldest first, from *min_ds* on (None: all). The ring is two
        sorted runs (``[head:]`` then ``[:head]``), each searched in place and copied as one array slice,
        so this is cheap enough to run under the store lock."""
        n = len(self.ts)
        runs = ((self.head, n), (0, self.head)) if self.head else ((0, n),)
        low = int(math.ceil(min_ds)) if min_ds is not None and min_ds > 0 else None
        ts, values = array("I"), array(self.values.typecode)
        for lo, hi in runs:
            start = bisect.bisect_left(self.ts, low, lo, hi) if low is not None else lo
            ts.extend(self.ts[start:hi])
            values.extend(self.values[start:hi])
        return ts, values

    def points(self, base_ts: float, min_ds: Optional[float]) -> List[List[Any]]:
        """``[[epoch s, dBm], ...]`` oldest first, from *min_ds* on (None: all), unthinned."""
        ts, rssi = self.window(min_ds)
        return history_points(base_ts, ts, rssi)

    def drop_from(self, min_ds: float) -> int:
        """Remove every point stamped at or after *min_ds* (deciseconds since the session start) and return how many
        went; what is left is kept oldest first as a plain run (``head`` 0), which ``add`` carries on from.  The next
        point ``add`` gets starts a new one rather than coalescing into the newest kept point: that point is from
        before the clear and must stay as it is, not be moved to after it."""
        ts, values = self.window(None)
        keep = bisect.bisect_left(ts, int(math.ceil(min_ds))) if min_ds > 0 else 0
        dropped = len(ts) - keep
        if dropped:
            self.ts, self.values, self.head = ts[:keep], values[:keep], 0
        self.sealed = True
        return dropped

    def last_point(self) -> Optional[Tuple[int, int]]:
        """``(deciseconds, value)`` of the newest point, None when there is none."""
        n = len(self.ts)
        if not n:
            return None
        last = (self.head - 1) % n
        return int(self.ts[last]), int(self.values[last])


def history_points(base_ts: float, ts: Any, rssi: Any, full_from_ds: Optional[float] = None,
                   buckets: int = HISTORY_THIN_BUCKETS) -> List[List[Any]]:
    """``[[epoch s, dBm], ...]`` from one series window (time-sorted deciseconds since *base_ts* and dBm).
    Readings from *full_from_ds* on (None: every reading) are returned as stored; when more than
    ``2 * buckets`` readings lie before it, those are thinned to the lowest and the highest reading of
    each of *buckets* equal slices of their time span (in time order; a dip or a peak is never lost)."""
    n = len(ts)
    cut = n if full_from_ds is None else bisect.bisect_left(ts, full_from_ds)
    out: List[List[Any]] = []
    start = 0
    if full_from_ds is not None and cut > 2 * buckets:
        first = ts[0]
        span = ts[cut - 1] - first + 1
        i = 0
        for b in range(1, buckets + 1):
            j = cut if b == buckets else bisect.bisect_left(ts, first + -(-span * b // buckets), i, cut)
            if j <= i:
                continue
            chunk = rssi[i:j]
            lo_i, hi_i = i + chunk.index(min(chunk)), i + chunk.index(max(chunk))
            for k in ((lo_i, hi_i) if lo_i < hi_i else (hi_i, lo_i) if hi_i < lo_i else (lo_i,)):
                out.append([round(base_ts + ts[k] / 10.0, 1), int(rssi[k])])
            i = j
        start = cut
    out.extend([round(base_ts + ts[k] / 10.0, 1), int(rssi[k])] for k in range(start, n))
    return out


class _Ap:
    __slots__ = ("desc", "rssi", "quality", "first_seen", "last_seen", "seen_count", "fresh_key", "read_seq", "series")

    def __init__(self, seen: float) -> None:
        self.desc: Dict[str, Any] = {}
        self.rssi = -100
        self.quality = 0
        self.first_seen = seen
        self.last_seen = seen
        self.seen_count = 0
        self.fresh_key: Any = None
        self.read_seq = 0
        self.series = _Series()


def _as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _rate_mbps(kbps: Any) -> Optional[float]:
    """A link speed from ``WLAN_ASSOCIATION_ATTRIBUTES`` (kb/s) in Mbps with one decimal; None for none or nonsense."""
    value = _as_int(kbps)
    if not 0 < value <= MAX_LINK_KBPS:
        return None
    return round(value / 1000.0, 1)


def is_epoch_time(value: Any) -> bool:
    """Whether *value* is a usable time in epoch seconds: a finite int or float, not a bool (JSON's true is not a
    time) and not an int too large to be a float."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _survey_options(options: Any) -> Tuple[bool, Optional[float]]:
    """``(active, history_s)`` from the bridge's options object; junk means passive / whole session."""
    if not isinstance(options, dict):
        return False, None
    active = options.get("active") is True
    raw = options.get("history_s")
    history_s = None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool) and math.isfinite(raw) and raw >= 0:
        history_s = float(raw)
    return active, history_s


def blank_view(state: str = "error", error: Optional[str] = None, enabled: bool = False) -> Dict[str, Any]:
    """A survey dict with no data (used when the bridge refuses or fails)."""
    return {
        "available": False, "enabled": bool(enabled), "state": state, "error": error,
        "started_ts": None, "last_read_ts": None, "last_scan_ts": None, "active": False,
        "scan_interval_s": SCAN_INTERVAL_S, "passive_interval_s": PASSIVE_INTERVAL_S,
        "interfaces": [], "aps": [], "history": {}, "link_history": [],
    }


class WifiSurvey:
    """The survey session, its store and the scanner thread (see the module docstring)."""

    def __init__(self, enabled: bool = True, persist: Optional[Callable[[bool], Any]] = None,
                 api_factory: Optional[Callable[[], Any]] = None, clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic, threaded: bool = True,
                 scan_interval_s: float = SCAN_INTERVAL_S, passive_interval_s: float = PASSIVE_INTERVAL_S,
                 lease_s: float = LEASE_S, max_aps: int = MAX_APS, max_points: int = MAX_POINTS) -> None:
        self._persist = persist
        self._api_factory = api_factory
        self._clock = clock
        self._mono = monotonic
        self._threaded = bool(threaded)
        self.scan_interval_s = max(MIN_SCAN_GAP_S, float(scan_interval_s))
        self.passive_interval_s = max(ACTIVE_READ_S, float(passive_interval_s))
        self.lease_s = max(1.0, float(lease_s))
        self.max_aps = max(1, int(max_aps))
        self.max_points = max(1, int(max_points))

        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._api: Any = None                     # only touched by the pass that owns it (thread or tick caller)

        self._enabled = bool(enabled)
        self._stopping = False
        self._session = False
        self._started_ts: Optional[float] = None
        self._state = "starting"
        self._error: Optional[str] = STARTING_TEXT
        self._available = False
        self._interfaces: List[Dict[str, Any]] = []
        self._connected: set = set()
        self._aps: Dict[str, _Ap] = {}
        self._link = _Series("I")                 # this PC's link speed in kb/s (0: not associated), see the docstring
        self._clock_ref: Optional[Tuple[float, float]] = None   # (wall, monotonic) at the last clock check
        # when history was last cleared (clear_since): no point is stamped earlier than this, so a beacon heard in
        # the cleared time but read after the clear cannot put it back
        self._history_floor: Optional[float] = None
        self._read_seq = 0
        self._parse_errors = 0
        self._last_read_ts: Optional[float] = None
        self._last_scan_ts: Optional[float] = None
        self._last_read_mono: Optional[float] = None
        self._last_scan_mono: Optional[float] = None
        self._last_request_mono: Optional[float] = None
        self._post_scan_read_at: Optional[float] = None
        self._lease_until = -math.inf
        self._scan_requested = False
        self._request_seq = 0
        self._denied_retry_at = -math.inf

    # -- properties ----------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled

    @property
    def session_started(self) -> bool:
        with self._lock:
            return self._session

    # -- session / lifecycle ------------------------------------------------------------
    def window_shown(self) -> None:
        """The TNT window became visible: start the session (when enabled). Never raises."""
        try:
            with self._lock:
                if self._enabled and not self._session and not self._stopping:
                    self._start_session_locked()
        except Exception:  # noqa: BLE001
            log.exception("could not start the Wi-Fi survey")

    def _start_session_locked(self) -> None:
        self._session = True
        self._started_ts = self._clock()
        self._clock_ref = (self._started_ts, self._mono())
        self._last_read_mono = None               # read the cached list right away
        if self._state not in ("no_adapter", "radio_off", "location_denied", "error"):
            self._state, self._error = "starting", STARTING_TEXT
        log.info("Wi-Fi survey session started")
        self._ensure_thread_locked()
        self._wake.set()

    def _ensure_thread_locked(self) -> None:
        if not self._threaded or self._thread is not None:
            return
        t = threading.Thread(target=self._run, name="wifi-survey", daemon=True)
        self._thread = t
        t.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Stop the scanner thread (idempotent) and close the Wlan handle once it has exited."""
        with self._lock:
            self._stopping = True
            t = self._thread
        self._stop_event.set()
        self._wake.set()
        alive = False
        if t is not None and t is not threading.current_thread():
            try:
                t.join(max(0.0, float(timeout)))
                alive = bool(t.is_alive())
            except Exception:  # noqa: BLE001 - a stand-in thread in tests
                alive = False
        if not alive:
            self._close_api()

    def _run(self) -> None:
        try:
            while not self._stop_event.is_set():
                self._wake.clear()
                delay = self.tick()
                if self._stop_event.is_set():
                    break
                self._wake.wait(delay)
        except Exception:  # noqa: BLE001 - never let the thread die with a traceback on quit
            log.exception("Wi-Fi survey thread crashed")
        finally:
            self._close_api()
            log.debug("Wi-Fi survey thread ended")

    # -- bridge operations --------------------------------------------------------------
    def survey(self, options: Any = None, visible: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
        """The survey dict. ``options``: ``{"active": bool, "history_s": number|null}``; ``active`` renews
        the scan lease. The session starts here when it has not yet and the page is active or *visible*
        says the window is on screen (no *visible*: always)."""
        active, history_s = _survey_options(options)
        may_start = active or visible is None
        if not may_start:
            with self._lock:
                idle = self._enabled and not self._session and not self._stopping
            may_start = idle and _safe_bool(visible)     # the Win32 check runs without the store lock held
        now_m, now = self._mono(), self._clock()
        with self._lock:
            self._follow_clock_locked(now, now_m)
            if self._enabled and not self._stopping:
                if active:
                    self._renew_lease_locked(now_m)
                if not self._session and may_start:
                    self._start_session_locked()
            view, windows, link = self._view_locked(now, now_m, history_s)
        # the point lists are built without the lock: the scanner thread never waits for a big history
        started = view["started_ts"]
        full_from = (now - HISTORY_FULL_S - started) * 10.0 if started is not None else None
        view["history"] = {bssid: history_points(started, ts, rssi, full_from) if started is not None else []
                           for bssid, (ts, rssi) in windows.items()}
        view["link_history"] = ([[t, round(kbps / 1000.0, 1)] for t, kbps in history_points(started, link[0], link[1], full_from)]
                                if started is not None else [])
        return view

    def scan_now(self) -> Dict[str, Any]:
        """Ask for an immediate read + scan (one per 5 s); also renews the lease."""
        now_m = self._mono()
        with self._lock:
            if not self._enabled:
                return {"ok": False, "error": DISABLED_TEXT}
            if self._stopping:
                return {"ok": False, "error": "TNT is closing."}
            self._renew_lease_locked(now_m)
            if not self._session:
                self._start_session_locked()
            # one request per 5 s; a request just after an automatic scan is taken and its WlanScan waits
            # for the 5 s gap (_plan_locked), so "Scan now" is not refused half the time while scanning
            last = self._last_request_mono
            if self._scan_requested or (last is not None and now_m - last < MIN_SCAN_GAP_S):
                return {"ok": False, "error": SCAN_TOO_SOON_TEXT}
            self._scan_requested = True
            self._request_seq += 1
            self._last_request_mono = now_m
            self._wake.set()
            return {"ok": True, "error": None}

    def clear(self) -> Dict[str, Any]:
        """Forget every AP and all history (the link speed's too); the session restarts now."""
        with self._lock:
            self._aps.clear()
            self._link = _Series("I")
            self._connected = set()
            self._history_floor = None            # the new session's start is the floor now
            if self._enabled and not self._stopping:
                self._session = False
                self._start_session_locked()
            else:
                self._started_ts = self._clock() if self._session else None
            log.info("Wi-Fi survey cleared")
            return {"ok": True}

    def clear_since(self, since_ts: Optional[float]) -> Dict[str, int]:
        """Settings > Clear history: forget what was heard from *since_ts* (epoch seconds) on; ``{"aps_dropped",
        "points_dropped"}``.  *since_ts* None is everything, exactly :meth:`clear` (the session restarts).

        Every signal point stamped at or after *since_ts* goes, from every access point, and the link speed's points
        with them (``points_dropped`` counts both).  An access point left with no point at all goes too when it lost
        points here or its last beacon was at or after *since_ts*; one that keeps older points reads as its newest
        kept point (``rssi``, ``last_seen``) until it is heard again.  The session and its start stay, so the page
        resets its own copy (as it does after a clear).  From now on no point is stamped earlier than this clear: a
        beacon heard in the cleared time but read afterwards is recorded at the clear, not in the cleared time, and
        the first point after the clear is a point of its own: it never coalesces into (and so never moves) the
        newest point the clear kept.  ``ValueError`` for a *since_ts* that is not a number."""
        with self._lock:
            if since_ts is None:
                aps = len(self._aps)
                points = sum(len(ap.series) for ap in self._aps.values()) + len(self._link)
                self.clear()
                return {"aps_dropped": aps, "points_dropped": points}
            if not is_epoch_time(since_ts):
                raise ValueError("since_ts must be a time in epoch seconds, or None for everything")
            since = float(since_ts)
            now = float(self._clock())
            self._history_floor = max(now, self._history_floor if self._history_floor is not None else now)
            started = self._started_ts
            aps_dropped = points = 0
            if started is not None:
                cut_ds = (since - started) * 10.0
                for bssid in list(self._aps):
                    ap = self._aps[bssid]
                    dropped = ap.series.drop_from(cut_ds)
                    points += dropped
                    newest = ap.series.last_point()
                    if newest is None:
                        if dropped or ap.last_seen >= since:
                            del self._aps[bssid]
                            aps_dropped += 1
                        continue
                    if dropped or ap.last_seen >= since:
                        # what the list shows is the newest reading the history still holds
                        ap.last_seen = min(ap.last_seen, started + newest[0] / 10.0)
                        ap.rssi = newest[1]
                        ap.seen_count = max(len(ap.series), ap.seen_count - dropped)
                points += self._link.drop_from(cut_ds)
            log.info("Wi-Fi survey: history cleared from %.0f s ago (%d access point(s), %d point(s))",
                     max(0.0, now - since), aps_dropped, points)
            return {"aps_dropped": aps_dropped, "points_dropped": points}

    def set_enabled(self, on: bool) -> Dict[str, Any]:
        """Switch the survey on or off (persisted through *persist*). Off stops every WLAN call."""
        on = bool(on)
        with self._lock:
            changed = on != self._enabled
            self._enabled = on
            if on:
                if not self._session and not self._stopping:
                    self._start_session_locked()
            else:
                self._lease_until = -math.inf
                self._scan_requested = False
                self._post_scan_read_at = None
            self._wake.set()
        if changed:
            log.info("Wi-Fi survey switched %s", "on" if on else "off")
        if self._persist is not None:
            try:
                self._persist(on)
            except Exception:  # noqa: BLE001
                log.exception("could not remember the Wi-Fi survey setting")
        return {"ok": True, "enabled": on}

    def _renew_lease_locked(self, now_m: float) -> None:
        was_active = now_m < self._lease_until
        self._lease_until = now_m + self.lease_s
        if not was_active:
            self._wake.set()

    # -- scheduler ----------------------------------------------------------------------
    def tick(self) -> float:
        """One scheduler pass: the due WLAN calls, then the seconds until the next one is due. Never raises."""
        try:
            return self._tick()
        except Exception:  # noqa: BLE001
            log.exception("Wi-Fi survey pass failed")
            self._close_api()
            return RETRY_AFTER_ERROR_S

    def _tick(self) -> float:
        now_m = self._mono()
        with self._lock:
            idle = self._stopping or not (self._enabled and self._session)
            if not idle:
                do_scan, do_read, due = self._plan_locked(now_m)
                req_seq = self._request_seq
        if idle:
            self._close_api()
            return IDLE_WAIT_S
        if not (do_scan or do_read):
            return _wait_for(due - now_m)
        result = self._native_pass(do_scan=do_scan, do_read=do_read)
        done_m, done = self._mono(), self._clock()
        with self._lock:
            if self._stopping or not (self._enabled and self._session):
                return MIN_WAIT_S
            self._follow_clock_locked(done, done_m)
            self._apply_locked(result, now_m, done_m, done, req_seq)
            _, _, due = self._plan_locked(done_m)
        return _wait_for(due - done_m)

    def _plan_locked(self, now_m: float) -> Tuple[bool, bool, float]:
        """``(scan now, read now, when the next call is due)``."""
        active = now_m < self._lease_until
        if self._last_read_mono is None:
            read_due = now_m
        else:
            read_due = self._last_read_mono + (ACTIVE_READ_S if active else self.passive_interval_s)
        if self._post_scan_read_at is not None:
            read_due = min(read_due, self._post_scan_read_at)
        if self._scan_requested:
            scan_due = now_m
            requested = self._last_request_mono
            if requested is not None and (self._last_read_mono is None or self._last_read_mono < requested):
                read_due = now_m                  # one read of the cached list since the request, not one per tick
        elif active:
            scan_due = now_m if self._last_scan_mono is None else self._last_scan_mono + self.scan_interval_s
        else:
            scan_due = math.inf
        if self._last_scan_mono is not None:
            scan_due = max(scan_due, self._last_scan_mono + MIN_SCAN_GAP_S)
        if self._state == "location_denied" and not self._scan_requested:
            read_due = max(read_due, self._denied_retry_at)
            scan_due = max(scan_due, self._denied_retry_at)
        return scan_due <= now_m, read_due <= now_m, min(read_due, scan_due)

    def _ensure_api(self) -> Any:
        if self._api is None:
            api = (self._api_factory or WlanSurveyApi)()
            api.open()
            self._api = api
        return self._api

    def _close_api(self) -> None:
        api, self._api = self._api, None
        if api is not None:
            try:
                api.close()
            except Exception:  # noqa: BLE001
                log.debug("closing the Wlan handle failed", exc_info=True)

    def _native_pass(self, do_scan: bool, do_read: bool) -> Dict[str, Any]:
        """The WLAN calls of one pass (no lock held): read the list first (it holds the previous scan's
        results), then request the scan."""
        # link_kbps: the link speed this pass read (see the docstring): 0 = not associated, None = not known
        res: Dict[str, Any] = {"read_attempted": do_read, "scan_attempted": do_scan, "read_ok": False,
                               "scan_ok": False, "denied": False, "no_adapter": False, "radio_off": False,
                               "error": None, "interfaces": None, "entries": [], "connection_unknown": set(),
                               "link_kbps": None}
        try:
            api = self._ensure_api()
            infos = [i for i in (api.interfaces() or []) if isinstance(i, dict)]
        except Exception as exc:  # noqa: BLE001 - OSError from the API, anything else from a broken driver
            self._close_api()
            if _winerror(exc) in NO_ADAPTER_CODES:
                res["no_adapter"] = True
                res["link_kbps"] = 0 if do_read else None
            else:
                res["error"] = f"Windows' Wi-Fi service could not be queried{_code_suffix(exc)}."
                log.debug("Wi-Fi survey: the Wlan API is not usable: %s", exc)   # the state change is logged
            return res
        if not infos:
            res["no_adapter"] = True
            res["interfaces"] = []
            res["link_kbps"] = 0 if do_read else None
            return res
        usable = []
        views = []
        for info in infos:
            view = {"guid": str(info.get("guid") or ""), "description": str(info.get("description") or ""),
                    "state": str(info.get("state") or "unknown"), "connected_bssid": None, "connected_ssid": None,
                    "rx_rate_mbps": None, "tx_rate_mbps": None}
            views.append(view)
            try:
                radio = api.radio_on(info.get("ref"))
            except Exception:  # noqa: BLE001 - unknown radio state: try the interface anyway
                log.debug("radio state query failed", exc_info=True)
                radio = None
            if radio is not False:
                usable.append((info.get("ref"), view))
        res["interfaces"] = views
        if not usable:
            res["radio_off"] = True
            res["link_kbps"] = 0 if do_read else None
            return res
        unplugged: set = set()        # id() of the views whose interface vanished while this pass ran
        powered_off: set = set()      # ... or whose radio turned out to be off (its state could not be read)
        answered: set = set()         # ... or whose current connection was asked for and answered

        def lost(code: Optional[int], view: Dict[str, Any]) -> bool:
            if code == ERROR_NOT_FOUND:                         # unplugged since WlanEnumInterfaces
                unplugged.add(id(view))
            elif code == ERROR_NDIS_DOT11_POWER_STATE_INVALID:  # the radio is off
                powered_off.add(id(view))
            else:
                return False
            return True

        if do_read:
            for ref, view in usable:
                try:
                    res["entries"].extend(api.bss_list(ref) or [])
                    res["read_ok"] = True
                except Exception as exc:  # noqa: BLE001
                    code = _winerror(exc)
                    if code == ERROR_ACCESS_DENIED:
                        res["denied"] = True
                    elif lost(code, view):
                        log.debug("WlanGetNetworkBssList: the interface is gone or its radio is off: %s", exc)
                        continue
                    else:
                        res["error"] = f"Windows could not list nearby Wi-Fi networks{_code_suffix(exc)}."
                        log.debug("WlanGetNetworkBssList failed: %s", exc)
                        if code in (ERROR_INVALID_HANDLE, None):     # reopen the handle on the next pass
                            self._close_api()
                            break
                if view["state"] == "connected" and not res["denied"]:
                    try:
                        conn = api.current_connection(ref)
                    except Exception:  # noqa: BLE001 - the connected mark is a nicety: keep the one known
                        log.debug("current connection query failed", exc_info=True)
                        continue
                    answered.add(id(view))
                    if isinstance(conn, dict):
                        view["connected_bssid"] = wifi_ies.format_bssid(conn.get("bssid"))
                        view["connected_ssid"] = wifi_ies.decode_ssid(conn.get("ssid"))[0] or None
                        view["rx_rate_mbps"] = _rate_mbps(conn.get("rx_kbps"))
                        view["tx_rate_mbps"] = _rate_mbps(conn.get("tx_kbps"))
                        if res["link_kbps"] is None and view["tx_rate_mbps"] is not None:
                            res["link_kbps"] = _as_int(conn.get("tx_kbps"))     # the first connected interface's
        if do_scan and self._api is not None:
            for ref, view in usable:
                if id(view) in unplugged or id(view) in powered_off:
                    continue
                try:
                    api.scan(ref)
                    res["scan_ok"] = True
                except Exception as exc:  # noqa: BLE001
                    code = _winerror(exc)
                    if code == ERROR_ACCESS_DENIED:
                        res["denied"] = True
                    elif not lost(code, view):   # a busy or reconnecting adapter refuses a scan now and then
                        log.debug("WlanScan failed: %s", exc)
        if do_read and res["link_kbps"] is None and not res["denied"] \
                and not any(view["state"] == "connected" for _ref, view in usable):
            res["link_kbps"] = 0                  # no interface is associated: the link is down
        # a pass that did not hear from a connected interface (a scan-only pass, a failed query) keeps the
        # association the last pass saw (_apply_locked), so "connected to <SSID>" does not blink off
        res["connection_unknown"] = {view["guid"] for _ref, view in usable
                                     if view["state"] == "connected" and id(view) not in answered | unplugged | powered_off}
        if unplugged:
            res["interfaces"] = [v for v in views if id(v) not in unplugged]
        if not (res["read_ok"] or res["scan_ok"] or res["denied"] or res["error"]) \
                and all(id(v) in unplugged or id(v) in powered_off for _ref, v in usable):
            # every interface this pass tried went away or turned out to be switched off
            res["radio_off" if powered_off else "no_adapter"] = True
        return res

    def _set_state_locked(self, state: str, error: Optional[str]) -> None:
        if state != self._state:
            log.info("Wi-Fi survey state: %s -> %s", self._state, state)
        self._state, self._error = state, error

    def _add_link_locked(self, kbps: int, now: float) -> None:
        """One link speed reading (kb/s, 0 = not associated) stamped *now*, coalesced like the signal history."""
        started = self._started_ts
        if started is None:
            return
        floor = started if self._history_floor is None else max(started, self._history_floor)
        at_ds = int(round((max(floor, now) - started) * 10))
        self._link.add(at_ds, max(0, min(MAX_LINK_KBPS, int(kbps))), int(COALESCE_S * 10), self.max_points)

    def _apply_locked(self, res: Dict[str, Any], plan_m: float, now_m: float, now: float, req_seq: int) -> None:
        if res["read_attempted"]:
            self._last_read_mono = now_m
            if self._post_scan_read_at is not None and self._post_scan_read_at <= plan_m:
                self._post_scan_read_at = None
        if res["scan_attempted"]:
            self._last_scan_mono = now_m
            if self._request_seq == req_seq:
                self._scan_requested = False
        if res.get("link_kbps") is not None:
            self._add_link_locked(res["link_kbps"], now)
        if res["no_adapter"]:
            res["interfaces"] = []
        if res["interfaces"] is not None:
            # "connected" follows the interfaces of every pass that has them: an adapter that went away, a
            # radio switched off or a refused query drops the mark, a scan-only pass keeps the last one known
            unknown = () if res["denied"] else res.get("connection_unknown") or ()
            self._interfaces = self._carry_connection_locked(res["interfaces"], unknown)
            self._connected = {v["connected_bssid"] for v in self._interfaces if v.get("connected_bssid")}
        if res["no_adapter"]:
            self._available = False
            self._set_state_locked("no_adapter", NO_ADAPTER_TEXT)
            return
        if res["interfaces"]:
            self._available = True
        if res["radio_off"]:
            self._set_state_locked("radio_off", RADIO_OFF_TEXT)
            return
        if res["read_ok"]:
            previous_read = self._last_read_ts
            self._last_read_ts = now
            self._ingest_locked(res["entries"], now, previous_read)
            self._set_state_locked("ok", None)
        elif res["denied"]:
            self._denied_retry_at = now_m + LOCATION_RETRY_S
            self._post_scan_read_at = None
            self._set_state_locked("location_denied", LOCATION_DENIED_TEXT)
            return
        elif res["error"] and (res["read_attempted"] or self._state == "starting"):
            self._set_state_locked("error", res["error"])
        elif res["scan_ok"] and self._state in ("location_denied", "no_adapter", "radio_off", "error"):
            self._set_state_locked("starting", STARTING_TEXT)
        if res["scan_ok"]:
            self._last_scan_ts = now
            self._post_scan_read_at = now_m + POST_SCAN_READ_S

    def _carry_connection_locked(self, views: List[Dict[str, Any]], unknown: Any) -> List[Dict[str, Any]]:
        """*views* with the association of the previous pass (and its link speeds) copied into each interface (by
        GUID) this pass did not ask, while it still reports itself connected."""
        if unknown:
            before = {v.get("guid"): v for v in self._interfaces}
            for view in views:
                old = before.get(view.get("guid"))
                if view.get("guid") in unknown and view.get("state") == "connected" and old is not None:
                    for key in ("connected_bssid", "connected_ssid", "rx_rate_mbps", "tx_rate_mbps"):
                        view[key] = old.get(key)
        return views

    def _follow_clock_locked(self, now: float, now_m: float) -> None:
        """Move every stored wall time back by as much as the wall clock stepped back (an NTP correction, a
        manual change) since the last check. Otherwise last_seen stays in the future, so nothing goes stale,
        and the history, kept in time order, takes no new point until the clock catches up. A forward jump
        is left alone: after a sleep the wall clock is also ahead of the monotonic one, and the readings
        taken before it did happen then."""
        ref, self._clock_ref = self._clock_ref, (now, now_m)
        if ref is None:
            return
        step = (now - ref[0]) - (now_m - ref[1])
        if step >= -CLOCK_STEP_S:
            return
        log.info("Wi-Fi survey: the wall clock stepped back %.0f s; the session's times follow it", -step)
        if self._started_ts is not None:
            self._started_ts += step
        if self._last_read_ts is not None:
            self._last_read_ts += step
        if self._last_scan_ts is not None:
            self._last_scan_ts += step
        if self._history_floor is not None:
            self._history_floor += step
        for ap in self._aps.values():
            ap.first_seen += step
            ap.last_seen += step

    def _beacon_time(self, host_ts: int, now: float) -> float:
        """``ullHostTimestamp`` (FILETIME) as epoch seconds, or *now* when it is not plausible."""
        if host_ts > FILETIME_UNIX_EPOCH:
            t = (host_ts - FILETIME_UNIX_EPOCH) / 1e7
            if now - BEACON_MAX_AGE_S <= t <= now + BEACON_MAX_AHEAD_S:
                return min(t, now)
        return now

    def _ingest_locked(self, entries: List[Dict[str, Any]], now: float, previous_read: Optional[float] = None) -> None:
        self._read_seq += 1
        seq = self._read_seq
        started = self._started_ts if self._started_ts is not None else now
        # a history point is never stamped before the session start or the previous successful read
        # (see the module docstring: the page asks only for the readings since the last read it saw)
        floor = max(started, previous_read) if previous_read is not None else started
        if self._history_floor is not None:
            floor = max(floor, self._history_floor)       # nothing lands in time a clear_since removed
        bucket_ds = int(COALESCE_S * 10)
        errors = 0
        # one reading per BSSID per read: the copy Windows received last. The same AP heard through two
        # adapters (or listed twice) would otherwise take turns against the stored reading, and every read
        # would turn their unchanged cached values into "fresh" readings
        newest: Dict[str, Tuple[int, Dict[str, Any]]] = {}
        for raw in entries:
            bssid = wifi_ies.format_bssid(raw.get("bssid")) if isinstance(raw, dict) else None
            if bssid is None:
                errors += 1
                continue
            host_ts = _as_int(raw.get("host_timestamp"))
            held = newest.get(bssid)
            if held is None or host_ts > held[0]:
                newest[bssid] = (host_ts, raw)
        for bssid, (host_ts, raw) in newest.items():
            ap = self._aps.get(bssid)
            key: Any = (host_ts, _as_int(raw.get("timestamp")))
            if key == (0, 0):
                key = ("signal", raw.get("rssi"), raw.get("link_quality"))
            if ap is None or key != ap.fresh_key:
                desc = wifi_ies.describe_bss(raw)
                if desc is None:
                    errors += 1
                    if ap is None:
                        continue
                beacon = self._beacon_time(host_ts, now)
                rssi = max(-127, min(127, _as_int(raw.get("rssi"), -100)))
                if ap is None:
                    ap = _Ap(beacon)
                    self._aps[bssid] = ap
                if desc is not None:
                    ap.desc = desc
                ap.rssi = rssi
                ap.quality = max(0, min(100, _as_int(raw.get("link_quality"))))
                ap.last_seen = max(ap.last_seen, beacon)
                ap.seen_count += 1
                ap.fresh_key = key
                if beacon >= started - HISTORY_GRACE_S:
                    at = max(started, min(max(beacon, floor), now))
                    if self._history_floor is not None:
                        at = max(at, self._history_floor)     # a pass that read Windows before the clear
                    ap.series.add(int(round((at - started) * 10)), rssi, bucket_ds, self.max_points)
            ap.read_seq = seq
        # drop access points not heard in the last 24 h so the list shows only recently found networks, not every AP ever seen
        cutoff = now - MAX_AP_AGE_S
        for bssid in [b for b, a in self._aps.items() if a.last_seen < cutoff and b not in self._connected]:
            del self._aps[bssid]
        excess = len(self._aps) - self.max_aps
        if excess > 0:
            # the least recently seen go: the oldest last beacon, then the ones missing from this read
            for bssid, _ap in heapq.nsmallest(excess, self._aps.items(), key=lambda kv: (kv[1].last_seen, kv[1].read_seq)):
                del self._aps[bssid]
        if errors:
            self._parse_errors += errors
        log.debug("Wi-Fi survey read: %d entries, %d access points known, %d unreadable",
                  len(entries), len(self._aps), errors)

    # -- view ---------------------------------------------------------------------------
    def _view_locked(self, now: float, now_m: float, history_s: Optional[float]) -> Tuple[Dict[str, Any], Dict[str, Any], Tuple[array, array]]:
        """The survey dict without its histories, ``{bssid: (deciseconds, dBm)}`` copies of every series window and the
        ``(deciseconds, kb/s)`` window of the link speed, for :meth:`survey` to turn into point lists once the lock is released."""
        if not self._enabled:
            state, error = "disabled", DISABLED_TEXT
        elif not self._session:
            state, error = "starting", NOT_STARTED_TEXT
        else:
            state, error = self._state, self._error
        started = self._started_ts
        min_ds = None
        if history_s is not None and started is not None:
            min_ds = (now - history_s - started) * 10.0
        aps: List[Dict[str, Any]] = []
        windows: Dict[str, Tuple[array, array]] = {}
        for bssid, ap in self._aps.items():
            if now - ap.last_seen > MAX_AP_AGE_S and bssid not in self._connected:
                continue                      # only recently found networks (last 24 h) are listed
            row = dict(ap.desc)
            row["spans"] = [list(s) for s in ap.desc.get("spans", [])]
            row["phys"] = list(ap.desc.get("phys", []))
            row.update({
                "bssid": bssid,
                "rssi": ap.rssi,
                "quality": ap.quality,
                "connected": bssid in self._connected,
                "first_seen": round(ap.first_seen, 3),
                "last_seen": round(ap.last_seen, 3),
                "seen_count": ap.seen_count,
                "stale": ap.read_seq != self._read_seq or now - ap.last_seen > STALE_S,
            })
            aps.append(row)
            windows[bssid] = ap.series.window(min_ds) if started is not None else (array("I"), array("b"))
        aps.sort(key=lambda a: (a["stale"], -a["rssi"], a["bssid"]))
        return {
            "available": bool(self._available),
            "enabled": self._enabled,
            "state": state,
            "error": error,
            "started_ts": started,
            "last_read_ts": self._last_read_ts,
            "last_scan_ts": self._last_scan_ts,
            "active": bool(self._enabled and self._session and not self._stopping and now_m < self._lease_until),
            "scan_interval_s": self.scan_interval_s,
            "passive_interval_s": self.passive_interval_s,
            "interfaces": [dict(v) for v in self._interfaces],
            "aps": aps,
            "history": {},
            "link_history": [],
        }, windows, (self._link.window(min_ds) if started is not None else (array("I"), array("I")))


def _wait_for(seconds: float) -> float:
    if not math.isfinite(seconds):
        return IDLE_WAIT_S
    return max(MIN_WAIT_S, min(IDLE_WAIT_S, seconds))


def _safe_bool(fn: Callable[[], Any]) -> bool:
    try:
        return bool(fn())
    except Exception:  # noqa: BLE001
        log.debug("visibility check failed", exc_info=True)
        return False
