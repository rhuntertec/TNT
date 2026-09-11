"""Saved Wi-Fi networks (Tools page): every WLAN profile this PC has stored, with the key
Windows kept for it.

Why this exists
---------------
The everyday job: a technician is on site, the laptop in their hand already joined the
customer's Wi-Fi months ago, and now a second device has to go on the same network.  The
key is on that laptop -- Windows itself hands it to an administrator with
``netsh wlan show profile name=<x> key=clear``.  This module is the same answer, in the
loopback API, in one list instead of one command per network.  Nothing is sent anywhere:
the plaintext keys need the service's LocalSystem/admin rights and never leave the
127.0.0.1 API.

Two sources, in this order:

* **The native Wlan API** (``wlanapi.dll`` through ctypes) -- the primary one, because it
  is *language neutral*: ``WlanGetProfile`` returns the profile XML, the same on an
  English, German or Chinese Windows, while ``netsh`` prints localised labels.  The chain
  is ``WlanOpenHandle(2, ...)`` -> ``WlanEnumInterfaces`` -> ``WlanGetProfileList`` ->
  ``WlanGetProfile`` (with the in/out flag :data:`WLAN_PROFILE_GET_PLAINTEXT_KEY`, which
  is what turns ``<keyMaterial>`` from an encrypted blob into the key) -> ``WlanFreeMemory``
  -> ``WlanCloseHandle``.  Every function gets ``argtypes``/``restype``: this repo learned
  the hard way (see :mod:`tnt.arp`) that ctypes without prototypes crashes on x64.
* **``netsh wlan``** -- the fallback, used when the API is unavailable or comes back empty.
  ``netsh wlan show profiles`` then ``netsh wlan show profile name=<n> key=clear`` for each
  (as an argv list, so the shell's ``name="<n>"`` quoting is not needed and never added).
  Its output is *localised*, so it is parsed by **shape**, not by label, the same way
  :func:`tnt.arp.parse_arp_output` does: ``Label : value`` pairs, the quoted value is the
  SSID, values from the (untranslated) crypto vocabulary are the authentication and the
  cipher, and the last label that mentions a key carries the key content.

``reveal=False`` omits every key but still reports ``key_present``, so the UI can show the
list with the keys masked without ever fetching them (the native path then does not even
ask for the plaintext key; the netsh path asks and drops it, because ``netsh`` only prints
the "security key" line at all when ``key=clear`` is given).

Shapes::

    {"available": bool, "interfaces": [{"guid","description","state"}], "profiles": [PROFILE],
     "error": None|str, "source": "wlanapi"|"netsh", "ts": float}
    PROFILE = {"name","ssid","authentication","encryption","key": None|str, "key_present": bool,
               "connection_mode": "auto"|"manual"|None, "non_broadcast": bool,
               "interface": guid|None, "error": None|str}

Nothing here raises: a PC without a wireless adapter comes back as ``available: False`` with
the friendly :data:`NO_ADAPTER_TEXT`, a profile that could not be read carries its own
``error`` and the rest of the list still arrives.  The module is import-safe off Windows
(the ``WinDLL`` load happens inside :func:`_dll`).

Injectable seams (keyword arguments, defaulting to the real thing): ``api`` (anything with
``open() / interfaces() / profile_names(ref) / profile_xml(ref, name, plaintext) / close()``,
i.e. :class:`WlanApi`) and ``runner`` (a ``subprocess.run`` stand-in for netsh, handed to
:func:`tnt.firewall.run_netsh`), so tests never touch the real radio.
"""
from __future__ import annotations

import ctypes
import importlib
import logging
import re
import sys
import threading
import time
import xml.etree.ElementTree as ET
from ctypes import POINTER, Structure, byref, c_ubyte, c_ulong, c_ushort, c_void_p, c_wchar, c_wchar_p
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

__all__ = [
    "list_profiles", "parse_profile_xml", "parse_netsh_profile", "parse_netsh_profile_names",
    "parse_netsh_interfaces", "WlanApi", "PROFILE_NS", "NO_ADAPTER_TEXT",
    "WLAN_PROFILE_GET_PLAINTEXT_KEY", "WLAN_INTERFACE_STATES", "MAX_PROFILES",
]

#: ``WlanOpenHandle`` client version: 2 = Vista and later (1 is XP SP3 only).
WLAN_API_VERSION = 2
#: In/out flag of ``WlanGetProfile``: return ``<keyMaterial>`` in the clear (needs admin).
WLAN_PROFILE_GET_PLAINTEXT_KEY = 0x00000004
ERROR_SUCCESS = 0
#: The WLAN AutoConfig service (wlansvc) is stopped -- same user-visible cause as "no adapter".
ERROR_SERVICE_NOT_ACTIVE = 1062

#: The profile XML namespace.  Only the *local* names are matched (see :func:`_child`) so a
#: profile whose MSM section uses the v2/v3 namespaces parses just as well.
PROFILE_NS = "http://www.microsoft.com/networking/WLAN/profile/v1"
PROFILE_ROOT_TAG = "WLANProfile"

NO_ADAPTER_TEXT = "this PC has no wireless adapter (or the Windows WLAN AutoConfig service is not running)"
NOT_WINDOWS_TEXT = "saved Wi-Fi networks can only be read on Windows"

#: ``WLAN_INTERFACE_STATE``.
WLAN_INTERFACE_STATES: Dict[int, str] = {
    0: "not_ready",
    1: "connected",
    2: "ad_hoc_network_formed",
    3: "disconnecting",
    4: "disconnected",
    5: "associating",
    6: "discovering",
    7: "authenticating",
}

#: Guards against a corrupt count from a layout mismatch (see tnt.arp's ``_MAX_ROWS``) and
#: against spending minutes in the netsh fallback on a machine with a silly profile list.
MAX_PROFILES = 500
MAX_INTERFACES = 64
WLAN_MAX_NAME_LENGTH = 256


# --- native structures (x64 layout per wlanapi.h) -------------------------------------------
class GUID(Structure):
    _fields_ = [
        ("Data1", c_ulong),
        ("Data2", c_ushort),
        ("Data3", c_ushort),
        ("Data4", c_ubyte * 8),
    ]                                                   # sizeof == 16


class WLAN_INTERFACE_INFO(Structure):
    _fields_ = [
        ("InterfaceGuid", GUID),                                    # 0
        ("strInterfaceDescription", c_wchar * WLAN_MAX_NAME_LENGTH),  # 16
        ("isState", c_ulong),                                       # 528  WLAN_INTERFACE_STATE
    ]                                                               # sizeof == 532


class WLAN_INTERFACE_INFO_LIST(Structure):
    _fields_ = [
        ("dwNumberOfItems", c_ulong),
        ("dwIndex", c_ulong),
        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),     # ANY_SIZE; rows start at offset 8
    ]


class WLAN_PROFILE_INFO(Structure):
    _fields_ = [
        ("strProfileName", c_wchar * WLAN_MAX_NAME_LENGTH),  # 0
        ("dwFlags", c_ulong),                                # 512
    ]                                                        # sizeof == 516


class WLAN_PROFILE_INFO_LIST(Structure):
    _fields_ = [
        ("dwNumberOfItems", c_ulong),
        ("dwIndex", c_ulong),
        ("ProfileInfo", WLAN_PROFILE_INFO * 1),         # ANY_SIZE; rows start at offset 8
    ]


_IFACE_ROWS_OFFSET = WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset
_PROFILE_ROWS_OFFSET = WLAN_PROFILE_INFO_LIST.ProfileInfo.offset

_dll_lock = threading.Lock()
_wlanapi: Any = None


def _dll() -> Any:
    """Load ``wlanapi`` lazily with every prototype declared (so importing this module never
    fails off Windows, and no call is made without ``argtypes`` on x64)."""
    global _wlanapi
    with _dll_lock:
        if _wlanapi is None:
            dll = ctypes.WinDLL("wlanapi", use_last_error=True)
            dll.WlanOpenHandle.argtypes = [c_ulong, c_void_p, POINTER(c_ulong), POINTER(c_void_p)]
            dll.WlanOpenHandle.restype = c_ulong
            dll.WlanCloseHandle.argtypes = [c_void_p, c_void_p]
            dll.WlanCloseHandle.restype = c_ulong
            dll.WlanEnumInterfaces.argtypes = [c_void_p, c_void_p, POINTER(POINTER(WLAN_INTERFACE_INFO_LIST))]
            dll.WlanEnumInterfaces.restype = c_ulong
            dll.WlanGetProfileList.argtypes = [c_void_p, POINTER(GUID), c_void_p, POINTER(POINTER(WLAN_PROFILE_INFO_LIST))]
            dll.WlanGetProfileList.restype = c_ulong
            dll.WlanGetProfile.argtypes = [c_void_p, POINTER(GUID), c_wchar_p, c_void_p,
                                           POINTER(c_wchar_p), POINTER(c_ulong), POINTER(c_ulong)]
            dll.WlanGetProfile.restype = c_ulong
            dll.WlanFreeMemory.argtypes = [c_void_p]
            dll.WlanFreeMemory.restype = None
            _wlanapi = dll
        return _wlanapi


def _format_error(rc: int) -> str:
    """``FormatError`` text for a Win32 code (just the number off Windows)."""
    try:
        text = ctypes.FormatError(int(rc))  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - not Windows, or an unknown code
        text = ""
    return f"{text} ({rc})" if text else f"error {rc}"


def guid_text(guid: GUID) -> str:
    """``"12345678-9abc-4def-8123-456789abcdef"`` (lower case, no braces: the form netsh prints)."""
    tail = "".join(f"{b:02x}" for b in bytes(guid.Data4))
    return f"{guid.Data1 & 0xFFFFFFFF:08x}-{guid.Data2:04x}-{guid.Data3:04x}-{tail[:4]}-{tail[4:]}"


class WlanApi:
    """The native Wlan API behind five small methods (the ``api`` seam of :func:`list_profiles`).

    ``open()`` -> ``interfaces()`` -> ``profile_names(ref)`` / ``profile_xml(ref, name,
    plaintext)`` -> ``close()``.  ``ref`` is the opaque interface token returned in each
    interface dict (here: a copy of its ``GUID``, because the list it came from is freed
    right away).  Every method raises ``OSError`` with the Win32 code on failure; the
    callers in this module turn that into an ``error`` string.
    """

    def __init__(self) -> None:
        self._dll: Any = None
        self._handle: Any = None

    # -- lifecycle ---------------------------------------------------------------------
    def open(self) -> None:
        dll = _dll()
        handle = c_void_p()
        negotiated = c_ulong(0)
        rc = int(dll.WlanOpenHandle(WLAN_API_VERSION, None, byref(negotiated), byref(handle)))
        if rc == ERROR_SERVICE_NOT_ACTIVE:
            raise OSError(rc, "the Windows WLAN AutoConfig service (wlansvc) is not running")
        if rc != ERROR_SUCCESS:
            raise OSError(rc, f"WlanOpenHandle failed: {_format_error(rc)}")
        self._dll = dll
        self._handle = handle

    def close(self) -> None:
        dll, handle = self._dll, self._handle
        self._dll = self._handle = None
        if dll is None or handle is None:
            return
        try:
            dll.WlanCloseHandle(handle, None)
        except Exception:  # noqa: BLE001 - closing must never be the reason a call fails
            log.debug("WlanCloseHandle failed", exc_info=True)

    def _require(self) -> Tuple[Any, Any]:
        if self._dll is None or self._handle is None:
            raise OSError(0, "the Wlan API handle is not open")
        return self._dll, self._handle

    def _free(self, ptr: Any) -> None:
        try:
            self._dll.WlanFreeMemory(ctypes.cast(ptr, c_void_p))
        except Exception:  # noqa: BLE001
            log.debug("WlanFreeMemory failed", exc_info=True)

    # -- queries -----------------------------------------------------------------------
    def interfaces(self) -> List[Dict[str, Any]]:
        """``[{"guid","description","state","ref"}]`` for every wireless interface."""
        dll, handle = self._require()
        plist = POINTER(WLAN_INTERFACE_INFO_LIST)()
        rc = int(dll.WlanEnumInterfaces(handle, None, byref(plist)))
        if rc != ERROR_SUCCESS:
            raise OSError(rc, f"WlanEnumInterfaces failed: {_format_error(rc)}")
        if not plist:
            return []
        out: List[Dict[str, Any]] = []
        try:
            count = int(plist.contents.dwNumberOfItems)
            if not 0 <= count <= MAX_INTERFACES:
                raise OSError(0, f"WlanEnumInterfaces reported an implausible {count} interfaces")
            rows = (WLAN_INTERFACE_INFO * count).from_address(ctypes.addressof(plist.contents) + _IFACE_ROWS_OFFSET)
            for row in rows:
                ref = GUID()
                ctypes.memmove(byref(ref), byref(row.InterfaceGuid), ctypes.sizeof(GUID))
                out.append({
                    "guid": guid_text(ref),
                    "description": (row.strInterfaceDescription or "").strip() or None,
                    "state": WLAN_INTERFACE_STATES.get(int(row.isState)),
                    "ref": ref,
                })
        finally:
            self._free(plist)
        return out

    def profile_names(self, ref: Any) -> List[str]:
        """Every stored profile name on one interface, in Windows' own preference order."""
        dll, handle = self._require()
        plist = POINTER(WLAN_PROFILE_INFO_LIST)()
        rc = int(dll.WlanGetProfileList(handle, byref(ref), None, byref(plist)))
        if rc != ERROR_SUCCESS:
            raise OSError(rc, f"WlanGetProfileList failed: {_format_error(rc)}")
        if not plist:
            return []
        out: List[str] = []
        try:
            count = int(plist.contents.dwNumberOfItems)
            if not 0 <= count <= MAX_PROFILES:
                raise OSError(0, f"WlanGetProfileList reported an implausible {count} profiles")
            rows = (WLAN_PROFILE_INFO * count).from_address(ctypes.addressof(plist.contents) + _PROFILE_ROWS_OFFSET)
            for row in rows:
                name = (row.strProfileName or "").strip()
                if name:
                    out.append(name)
        finally:
            self._free(plist)
        return out

    def profile_xml(self, ref: Any, name: str, plaintext: bool = True) -> str:
        """The profile XML.  With *plaintext* the ``<keyMaterial>`` comes back in the clear
        (that is what needs the service's admin rights); without it, encrypted."""
        dll, handle = self._require()
        flags = c_ulong(WLAN_PROFILE_GET_PLAINTEXT_KEY if plaintext else 0)
        access = c_ulong(0)
        xml = c_wchar_p()
        rc = int(dll.WlanGetProfile(handle, byref(ref), str(name), None, byref(xml), byref(flags), byref(access)))
        if rc != ERROR_SUCCESS:
            raise OSError(rc, f"WlanGetProfile failed: {_format_error(rc)}")
        try:
            return xml.value or ""      # .value copies the string out of the API's buffer
        finally:
            self._free(xml)


# --- profile XML ----------------------------------------------------------------------------
def _local(tag: Any) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _child(el: Any, name: str) -> Any:
    """The first child element with that *local* name (namespace version agnostic)."""
    if el is None:
        return None
    for kid in el:
        if _local(kid.tag) == name:
            return kid
    return None


def _path(root: Any, *names: str) -> Any:
    el = root
    for n in names:
        el = _child(el, n)
        if el is None:
            return None
    return el


def _text(el: Any) -> Optional[str]:
    if el is None or el.text is None:
        return None
    text = el.text.strip()
    return text or None


def _flag(el: Any) -> Optional[bool]:
    text = (_text(el) or "").lower()
    if text in ("true", "1", "yes"):
        return True
    if text in ("false", "0", "no"):
        return False
    return None


def blank_profile(name: Optional[str] = None) -> Dict[str, Any]:
    """An all-``None`` PROFILE dict (every field of the contract, in order)."""
    return {"name": name, "ssid": None, "authentication": None, "encryption": None, "key": None,
            "key_present": False, "connection_mode": None, "non_broadcast": False,
            "interface": None, "error": None}


def parse_profile_xml(xml_text: Any, reveal: bool = True) -> Dict[str, Any]:
    """One PROFILE dict from the XML ``WlanGetProfile`` returned.  Never raises: malformed
    XML comes back as a profile whose ``error`` says so.

    ``<sharedKey><protected>true</protected>`` means Windows handed back the *encrypted*
    blob -- either because the key was not asked for (``reveal=False``) or because this
    process may not see it (a per-user profile read without the rights): the key is dropped
    and, when it was asked for, the reason lands in ``error``.
    """
    prof = blank_profile()
    try:
        text = str(xml_text or "").lstrip("﻿").strip()   # WlanGetProfile prepends a BOM
        root = ET.fromstring(text)
        if root.tag.startswith("{") and _local(root.tag) == PROFILE_ROOT_TAG and PROFILE_NS not in root.tag:
            log.debug("profile XML uses %s, not %s", root.tag, PROFILE_NS)
    except ET.ParseError as exc:
        prof["error"] = f"the profile XML could not be parsed: {exc}"
        return prof
    except Exception as exc:  # noqa: BLE001 - never let a broken profile break the list
        log.exception("profile XML parsing failed")
        prof["error"] = f"the profile XML could not be read: {exc}"
        return prof

    ssid_cfg = _child(root, "SSIDConfig")
    security = _path(root, "MSM", "security")
    auth_enc = _child(security, "authEncryption")
    shared = _child(security, "sharedKey")

    prof["name"] = _text(_child(root, "name"))
    prof["ssid"] = _text(_path(ssid_cfg, "SSID", "name"))
    if prof["ssid"] is None:                      # a non-broadcast / non-UTF-8 SSID is hex only
        prof["ssid"] = _hex_ssid(_text(_path(ssid_cfg, "SSID", "hex")))
    prof["authentication"] = _text(_child(auth_enc, "authentication"))
    prof["encryption"] = _text(_child(auth_enc, "encryption"))

    mode = (_text(_child(root, "connectionMode")) or "").lower()
    prof["connection_mode"] = mode if mode in ("auto", "manual") else None
    non_broadcast = _flag(_child(ssid_cfg, "nonBroadcast"))
    if non_broadcast is None:
        non_broadcast = _flag(_child(root, "nonBroadcast"))
    prof["non_broadcast"] = bool(non_broadcast)

    material = _text(_child(shared, "keyMaterial"))
    protected = _flag(_child(shared, "protected"))
    prof["key_present"] = bool(material) or _text(_child(shared, "keyType")) is not None
    if material and not protected:
        prof["key"] = material if reveal else None
    elif material and protected and reveal:
        prof["error"] = "the key is stored encrypted for another Windows account and cannot be shown"
    return prof


def _hex_ssid(hex_text: Optional[str]) -> Optional[str]:
    """``"5445432D4F6666696365"`` -> ``"TEC-Office"`` (``None`` when it is not text)."""
    if not hex_text:
        return None
    try:
        raw = bytes.fromhex(hex_text.strip())
    except ValueError:
        return None
    try:
        return raw.decode("utf-8").strip() or None
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace").strip() or None


# --- netsh (fallback) -----------------------------------------------------------------------
#: Values Windows prints for the authentication field.  These are *not* translated (they are
#: the standard's own names), which is what makes shape-based parsing possible at all.  The
#: match is anchored at both ends so an SSID that happens to start with one of them (a
#: network called "Open Wifi") is never mistaken for the security setting.
_AUTH_RE = re.compile(r"^(?:open|shared|owe|rsna(?:[- ]psk)?|802\.1x|wpa[0-9]?(?:[- ](?:personal|enterprise))?(?:psk)?)$", re.I)
_CIPHER_VALUES = {"none", "wep", "wep-40", "wep-104", "tkip", "ccmp", "aes", "gcmp",
                  "ccmp-128", "ccmp-256", "gcmp-128", "gcmp-256", "bip", "wep-40bit", "wep-104bit"}
#: Label stems that mean "this line carries a key".  The *last* such line of a profile is the
#: key content: Windows always prints the "security key present/absent" marker (and, for WEP,
#: the key index) before it, in every language.
_KEY_LABEL_STEMS = ("key content", "key material", "schlüsselinhalt", "contenido de la clave",
                    "contenu de la clé", "conteúdo da chave", "contenuto della chiave",
                    "密钥内容", "キー コンテンツ", "содержимое ключа",
                    "key", "schlüssel", "schluessel", "schlussel", "clave", "clé", "cle",
                    "chave", "chiave", "密钥", "キー", "ключ")
_GUID_RE = re.compile(r"^\{?[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?$")
_STATE_VALUES = {"connected", "disconnected", "not ready", "associating", "authenticating",
                 "discovering", "disconnecting", "ad hoc network formed"}
_NONE_VALUES = {"<none>", "(none)", "none", "n/a"}


def _run_netsh(args: Sequence[str], runner: Optional[Callable[..., Any]] = None) -> Tuple[int, str]:
    """``netsh <args>`` through the shared helper (System32 exe, hidden window, OEM decoding,
    timeout).  ``tnt.firewall`` is imported lazily so a stand-in in ``sys.modules`` is
    honoured and a broken import degrades to an error string, not an exception."""
    try:
        firewall = importlib.import_module("tnt.firewall")
    except Exception as exc:  # noqa: BLE001
        return 1, f"could not load the netsh helper: {exc}"
    return firewall.run_netsh(list(args), runner)


def _pairs(text: str) -> List[Tuple[str, str]]:
    """Every ``Label : value`` line as ``(lower-case label, value)``.  Split on the *first*
    colon only: an SSID or a key may well contain one."""
    out: List[Tuple[str, str]] = []
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        label, _sep, value = line.partition(":")
        label = label.strip().lower()
        if not label:
            continue
        out.append((label, value.strip()))
    return out


def parse_netsh_profile_names(text: str) -> List[str]:
    """Profile names from ``netsh wlan show profiles``.

    Shape, not label: the names are the *indented* ``Label : value`` lines ("    All User
    Profile     : TEC-Office"); the section headings and the "Profiles on interface Wi-Fi:"
    line start in column 0, and "<None>" is the empty-section placeholder.
    """
    out: List[str] = []
    for line in (text or "").splitlines():
        if not line[:1].isspace() or ":" not in line:
            continue
        label, _sep, value = line.partition(":")
        value = value.strip()
        if not label.strip() or not value or value.lower() in _NONE_VALUES:
            continue
        if value not in out:
            out.append(value)
    return out


def parse_netsh_interfaces(text: str) -> List[Dict[str, Any]]:
    """``[{"guid","description","state"}]`` from ``netsh wlan show interfaces``.

    Shape again: the value that *looks like* a GUID starts an interface, its description is
    the value on the line above (netsh prints Name / Description / GUID / ... in that order)
    and the state is the first later value from the (untranslated) state vocabulary, or the
    value of a label that mentions "state".
    """
    out: List[Dict[str, Any]] = []
    prev = ""
    for label, value in _pairs(text):
        if _GUID_RE.match(value):
            out.append({"guid": value.strip("{}").lower(), "description": prev or None, "state": None})
        elif out and out[-1]["state"] is None and (value.lower() in _STATE_VALUES or "state" in label):
            out[-1]["state"] = value.lower().replace(" ", "_") or None
        prev = value
    return out


def parse_netsh_profile(text: str, name: Optional[str] = None) -> Dict[str, Any]:
    """One PROFILE dict from ``netsh wlan show profile name=<n> key=clear``.

    The labels are localised, so only the *shape* of the output is trusted: the quoted value
    is the SSID, a value from the authentication / cipher vocabularies is the security, and
    the last label mentioning a key carries the key (with the "security key present" marker
    -- and, for WEP, the key index -- printed before it).  ``connection_mode`` comes from the
    verb in the *value* ("Connect automatically" / "Automatisch verbinden"); ``non_broadcast``
    is the one English-only sentence and stays ``False`` when it cannot be recognised.  The
    native path always has both.
    """
    prof = blank_profile(name)
    pairs = _pairs(text)
    key_pairs: List[Tuple[str, str]] = []
    for label, value in pairs:
        low = value.lower()
        keyish = any(stem in label for stem in _KEY_LABEL_STEMS)
        if prof["ssid"] is None and len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            prof["ssid"] = value[1:-1] or None
            continue
        if name and value == name and not keyish:
            continue                    # the profile-name line is never a security value
        # the vocabularies come before the key labels: the German cipher label
        # ("Verschlüsselung") carries the very same "schlüssel" stem the key labels do
        if prof["authentication"] is None and _AUTH_RE.match(value):
            prof["authentication"] = value
            continue
        if prof["encryption"] is None and low in _CIPHER_VALUES:
            prof["encryption"] = value
            continue
        if keyish:
            key_pairs.append((label, value))
            continue
        # the connection mode is read from the *value* ("Connect automatically", "Automatisch
        # verbinden", "Se connecter automatiquement"): the label is translated, the verb stem
        # survives in most languages and no other line carries one
        if prof["connection_mode"] is None and ("automat" in low or low == "auto"):
            prof["connection_mode"] = "auto"
            continue
        if prof["connection_mode"] is None and ("manual" in low or "manuel" in low or "manuell" in low):
            prof["connection_mode"] = "manual"
            continue
        if "broadcast" in label or "broadcast" in low:
            prof["non_broadcast"] = "not broadcasting" in low or "non-broadcast" in low
    # >= 2 key lines: the marker (and maybe a key index) then the key itself.  Exactly one is
    # the marker alone -- an open network, or a key netsh would not print.
    if len(key_pairs) >= 2 and key_pairs[-1][1]:
        prof["key"] = key_pairs[-1][1]
        prof["key_present"] = True
    elif key_pairs:
        prof["key_present"] = False
    if prof["name"] is None:
        prof["name"] = prof["ssid"]
    if prof["ssid"] is None:
        prof["ssid"] = prof["name"]
    return prof


def _netsh_scan(reveal: bool, runner: Optional[Callable[..., Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Optional[str]]:
    """``(interfaces, profiles, error)`` from netsh.  ``error`` is set only when the whole
    thing could not run (no adapter, no wlansvc, no netsh)."""
    rc, out = _run_netsh(["wlan", "show", "profiles"], runner)
    if rc != ERROR_SUCCESS:
        short = " ".join((out or "").split())[:200]
        return [], [], f"{NO_ADAPTER_TEXT}{': ' + short if short else ''}"
    names = parse_netsh_profile_names(out)
    interfaces: List[Dict[str, Any]] = []
    rc_if, out_if = _run_netsh(["wlan", "show", "interfaces"], runner)
    if rc_if == ERROR_SUCCESS:
        interfaces = parse_netsh_interfaces(out_if)
    guid = interfaces[0]["guid"] if interfaces else None
    profiles: List[Dict[str, Any]] = []
    for pname in names[:MAX_PROFILES]:
        # argv list, so netsh gets the name verbatim: the shell form's quotes must not be added
        rc_p, out_p = _run_netsh(["wlan", "show", "profile", f"name={pname}", "key=clear"], runner)
        if rc_p != ERROR_SUCCESS:
            prof = blank_profile(pname)
            prof["ssid"] = pname
            prof["error"] = " ".join((out_p or "").split())[:200] or f"netsh could not read this profile ({rc_p})"
        else:
            prof = parse_netsh_profile(out_p, pname)
        prof["interface"] = guid
        if not reveal:
            prof["key"] = None      # key=clear was still needed to know whether there *is* one
        profiles.append(prof)
    return interfaces, profiles, None


# --- the public view ------------------------------------------------------------------------
def _native_scan(reveal: bool, api: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """``(interfaces, profiles)`` through the Wlan API.  Raises ``OSError`` when the API
    itself is unusable (no handle, enumeration failed); a single unreadable profile only
    lands in that profile's ``error``."""
    api.open()
    try:
        interfaces: List[Dict[str, Any]] = []
        profiles: List[Dict[str, Any]] = []
        for info in list(api.interfaces() or []):
            info = dict(info)
            ref = info.pop("ref", None)
            guid = info.get("guid") or None
            interfaces.append({"guid": guid, "description": info.get("description"), "state": info.get("state")})
            try:
                names = list(api.profile_names(ref) or [])
            except Exception as exc:  # noqa: BLE001 - one dead interface must not hide the others
                log.warning("WlanGetProfileList failed for interface %s: %s", guid, exc)
                continue
            for pname in names[:MAX_PROFILES]:
                profiles.append(_native_profile(api, ref, guid, pname, reveal))
        return interfaces, profiles
    finally:
        try:
            api.close()
        except Exception:  # noqa: BLE001
            log.debug("closing the Wlan API handle failed", exc_info=True)


def _native_profile(api: Any, ref: Any, guid: Optional[str], name: str, reveal: bool) -> Dict[str, Any]:
    try:
        xml_text = api.profile_xml(ref, name, plaintext=reveal)
    except Exception as exc:  # noqa: BLE001
        log.warning("WlanGetProfile failed for %r: %s", name, exc)
        prof = blank_profile(name)
        prof["ssid"] = name
        prof["interface"] = guid
        prof["error"] = f"the profile could not be read: {exc}"
        return prof
    prof = parse_profile_xml(xml_text, reveal=reveal)
    prof["name"] = prof["name"] or name
    prof["ssid"] = prof["ssid"] or prof["name"]
    prof["interface"] = guid
    return prof


def list_profiles(reveal: bool = True, api: Any = None, runner: Optional[Callable[..., Any]] = None) -> Dict[str, Any]:
    """Every Wi-Fi profile this PC has stored, with the key Windows kept for it.

    ``{"available", "interfaces", "profiles", "error", "source", "ts"}`` (see the module
    docstring).  ``reveal=False`` leaves every ``key`` ``None`` while ``key_present`` still
    says whether there is one.  Never raises: a machine without a wireless adapter comes
    back as ``available: False`` with a friendly ``error``.
    """
    reveal = bool(reveal)
    view: Dict[str, Any] = {"available": False, "interfaces": [], "profiles": [],
                            "error": None, "source": "wlanapi", "ts": time.time()}
    if api is None and runner is None and sys.platform != "win32":
        view["error"] = NOT_WINDOWS_TEXT
        return view

    native_error: Optional[str] = None
    try:
        interfaces, profiles = _native_scan(reveal, api if api is not None else WlanApi())
        if interfaces or profiles:
            view.update(available=True, interfaces=interfaces, profiles=profiles, source="wlanapi")
            return view
        log.info("the Wlan API reported no wireless interface; trying netsh")
    except Exception as exc:  # noqa: BLE001 - fall back, never break the Tools page
        native_error = str(exc) or type(exc).__name__
        log.warning("the native Wlan API failed (%s); falling back to netsh", native_error)

    try:
        interfaces, profiles, error = _netsh_scan(reveal, runner)
    except Exception as exc:  # noqa: BLE001
        log.exception("the netsh fallback failed")
        interfaces, profiles, error = [], [], f"could not run netsh: {exc}"
    view.update(source="netsh", interfaces=interfaces, profiles=profiles)
    if interfaces or profiles:
        view["available"] = True
        return view
    view["available"] = False
    view["error"] = error or NO_ADAPTER_TEXT
    if native_error:
        view["error"] = f"{view['error']} (the Wlan API also failed: {native_error})"
    log.info("no saved Wi-Fi networks: %s", view["error"])
    return view
