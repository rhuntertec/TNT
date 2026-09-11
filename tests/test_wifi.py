"""Saved Wi-Fi networks (``tnt/wifi.py``) and its route ``GET /api/tools/wifi/profiles``.

Nothing here touches the real radio: the native Wlan API is replaced by :class:`FakeWlan`
(the five-method ``api`` seam) and ``netsh`` by :class:`FakeNetsh` (a ``subprocess.run``
stand-in handed to ``tnt.firewall.run_netsh``).  The route tests run a real
:class:`~tnt.api.server.ApiServer` on port 0 against a stand-in engine, the same way
``tests/test_api.py`` does, with ``tnt.wifi.list_profiles`` monkeypatched so no profile is
ever read from the machine running the suite.

The ctypes structure sizes are checked for real on Windows (a layout mistake there is what
made ``tnt.arp`` crash once), but no Wlan call is made.
"""
from __future__ import annotations

import ctypes
import http.client
import json
import sys
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from tnt import wifi
from tnt.api.server import ApiServer

GUID_A = "12345678-9abc-4def-8123-456789abcdef"
GUID_B = "fedcba98-7654-4321-8fed-cba987654321"
OFFICE_KEY = "example-office-passphrase"


# ---------------------------------------------------------------------------
# fixtures: profile XML, netsh output, the two seams
# ---------------------------------------------------------------------------
def profile_xml(name: str, ssid: Optional[str] = None, auth: str = "WPA2PSK", enc: str = "AES",
                key: Optional[str] = OFFICE_KEY, mode: str = "auto", non_broadcast: bool = False,
                protected: bool = False, hex_ssid: Optional[str] = None, ns: str = wifi.PROFILE_NS) -> str:
    """A profile XML in the shape ``WlanGetProfile`` returns (BOM and tabs included)."""
    ssid_el = f"\t\t\t<name>{ssid}</name>\n" if ssid is not None else ""
    hex_el = f"\t\t\t<hex>{hex_ssid}</hex>\n" if hex_ssid else ""
    shared = ""
    if key is not None:
        shared = (
            "\t\t\t<sharedKey>\n"
            "\t\t\t\t<keyType>passPhrase</keyType>\n"
            f"\t\t\t\t<protected>{'true' if protected else 'false'}</protected>\n"
            f"\t\t\t\t<keyMaterial>{key}</keyMaterial>\n"
            "\t\t\t</sharedKey>\n"
        )
    return (
        "\ufeff<?xml version=\"1.0\"?>\n"
        f"<WLANProfile xmlns=\"{ns}\">\n"
        f"\t<name>{name}</name>\n"
        "\t<SSIDConfig>\n"
        "\t\t<SSID>\n"
        f"{hex_el}{ssid_el}"
        "\t\t</SSID>\n"
        f"\t\t<nonBroadcast>{'true' if non_broadcast else 'false'}</nonBroadcast>\n"
        "\t</SSIDConfig>\n"
        "\t<connectionType>ESS</connectionType>\n"
        f"\t<connectionMode>{mode}</connectionMode>\n"
        "\t<MSM>\n"
        "\t\t<security>\n"
        "\t\t\t<authEncryption>\n"
        f"\t\t\t\t<authentication>{auth}</authentication>\n"
        f"\t\t\t\t<encryption>{enc}</encryption>\n"
        "\t\t\t\t<useOneX>false</useOneX>\n"
        "\t\t\t</authEncryption>\n"
        f"{shared}"
        "\t\t</security>\n"
        "\t</MSM>\n"
        "\t<MacRandomization xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v3\">\n"
        "\t\t<enableRandomization>false</enableRandomization>\n"
        "\t</MacRandomization>\n"
        "</WLANProfile>\n"
    )


OFFICE_XML = profile_xml("TEC-Office", "TEC-Office")
GUEST_XML = profile_xml("TEC-Guest", "TEC-Guest", key="example-guest-passphrase")
OPEN_XML = profile_xml("SiteSurvey-5G", "SiteSurvey-5G", auth="open", enc="none", key=None,
                       mode="manual", non_broadcast=True)

NETSH_PROFILES = """
Profiles on interface Wi-Fi:

Group policy profiles (read only)
---------------------------------
    <None>

User profiles
-------------
    All User Profile     : TEC-Office
    All User Profile     : TEC-Guest
    All User Profile     : SiteSurvey-5G
"""

NETSH_INTERFACES = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 12345678-9abc-4def-8123-456789abcdef
    Physical address       : 9c:b6:d0:11:22:33
    State                  : connected
    SSID                   : TEC-Office
"""

NETSH_OFFICE = """
Profile TEC-Office on interface Wi-Fi:
=======================================================================

Applied: All User Profile

Profile information
-------------------
    Version                : 1
    Type                   : Wireless LAN
    Name                   : TEC-Office
    Control options        :
        Connection mode    : Connect automatically
        Network broadcast  : Connect only if this network is broadcasting
        AutoSwitch         : Do not switch to other networks
        MAC Randomization  : Disabled

Connectivity settings
---------------------
    Number of SSIDs        : 1
    SSID name              : "TEC-Office"
    Network type           : Infrastructure
    Radio type             : [ Any Radio Type ]
    Vendor extension          : Not present

Security settings
-----------------
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Authentication         : WPA2-Personal
    Cipher                 : GCMP
    Security key           : Present
    Key Content            : example-office-passphrase

Cost settings
-------------
    Cost                   : Unrestricted
    Congested              : No
"""

NETSH_OPEN = """
Profile SiteSurvey-5G on interface Wi-Fi:
=======================================================================

Applied: All User Profile

Profile information
-------------------
    Version                : 1
    Type                   : Wireless LAN
    Name                   : SiteSurvey-5G
    Control options        :
        Connection mode    : Connect manually
        Network broadcast  : Connect even if this network is not broadcasting

Connectivity settings
---------------------
    Number of SSIDs        : 1
    SSID name              : "SiteSurvey-5G"
    Network type           : Infrastructure

Security settings
-----------------
    Authentication         : Open
    Cipher                 : None
    Security key           : Absent
"""

#: The same office profile from a German Windows: every label is translated, the values are
#: not.  The parser must still find the SSID (quoted), the security (crypto vocabulary), the
#: key (the last key-ish label) and the connection mode (the verb in the value).
NETSH_OFFICE_DE = """
Profil TEC-Office auf Schnittstelle WLAN:
=======================================================================

Angewendet: Alle Benutzerprofile

Profilinformationen
-------------------
    Version                : 1
    Typ                    : Drahtlos-LAN
    Name                   : TEC-Office
    Steuerungsoptionen     :
        Verbindungsmodus   : Automatisch verbinden
        Netzwerkübertragung: Nur verbinden, wenn dieses Netzwerk sendet

Verbindungseinstellungen
------------------------
    Anzahl der SSIDs       : 1
    SSID-Name              : "TEC-Office"
    Netzwerktyp            : Infrastruktur
    Funktyp                : [ Beliebiger Funktyp ]

Sicherheitseinstellungen
------------------------
    Authentifizierung      : WPA2-Personal
    Verschlüsselung        : CCMP
    Sicherheitsschlüssel   : Vorhanden
    Schlüsselinhalt        : example-office-passphrase
"""

#: ... and the same thing after a console code page mangled the umlauts (an OEM decode that
#: guessed wrong): the ASCII stems still find the key.
NETSH_OFFICE_DE_ASCII = NETSH_OFFICE_DE.replace("ü", "ue")

NO_ADAPTER_OUTPUT = "The Wireless AutoConfig Service (wlansvc) is not running.\n"


class FakeWlan:
    """The ``api`` seam: the same five methods as :class:`tnt.wifi.WlanApi`, no ctypes."""

    def __init__(self, interfaces: Optional[List[Dict[str, Any]]] = None,
                 profiles: Optional[Dict[str, Dict[str, Any]]] = None,
                 open_error: Optional[BaseException] = None,
                 list_error: Optional[BaseException] = None,
                 enum_error: Optional[BaseException] = None) -> None:
        self.interface_rows = interfaces if interfaces is not None else [
            {"guid": GUID_A, "description": "Intel(R) Wi-Fi 6 AX201 160MHz", "state": "connected"}]
        self.profiles = profiles if profiles is not None else {
            GUID_A: {"TEC-Office": OFFICE_XML, "TEC-Guest": GUEST_XML, "SiteSurvey-5G": OPEN_XML}}
        self.open_error = open_error
        self.list_error = list_error
        self.enum_error = enum_error
        self.opened = 0
        self.closed = 0
        self.asked: List[Any] = []          # (name, plaintext) per WlanGetProfile

    def open(self) -> None:
        if self.open_error is not None:
            raise self.open_error
        self.opened += 1

    def close(self) -> None:
        self.closed += 1

    def interfaces(self) -> List[Dict[str, Any]]:
        if self.enum_error is not None:
            raise self.enum_error
        return [dict(row, ref=row["guid"]) for row in self.interface_rows]

    def profile_names(self, ref: Any) -> List[str]:
        if self.list_error is not None:
            raise self.list_error
        return list(self.profiles.get(ref, {}))

    def profile_xml(self, ref: Any, name: str, plaintext: bool = True) -> str:
        self.asked.append((name, plaintext))
        entry = self.profiles.get(ref, {}).get(name)
        if isinstance(entry, BaseException):
            raise entry
        return entry or ""


class FakeNetsh:
    """``subprocess.run`` stand-in for ``netsh wlan ...`` (what ``firewall.run_netsh`` calls)."""

    def __init__(self, profiles: str = NETSH_PROFILES, interfaces: str = NETSH_INTERFACES,
                 details: Optional[Dict[str, str]] = None, rc: int = 0) -> None:
        self.profiles = profiles
        self.interfaces = interfaces
        self.details = details if details is not None else {
            "TEC-Office": NETSH_OFFICE, "TEC-Guest": NETSH_OFFICE.replace("TEC-Office", "TEC-Guest"),
            "SiteSurvey-5G": NETSH_OPEN}
        self.rc = rc
        self.commands: List[List[str]] = []
        self.kwargs: List[dict] = []

    def __call__(self, argv: Any, **kwargs: Any) -> Any:
        self.commands.append([str(a) for a in argv])
        self.kwargs.append(kwargs)
        args = [str(a) for a in argv[1:]]
        assert args[:2] == ["wlan", "show"], args
        if args[2] == "profiles":
            return SimpleNamespace(returncode=self.rc, stdout=self.profiles, stderr="")
        if args[2] == "interfaces":
            return SimpleNamespace(returncode=self.rc, stdout=self.interfaces, stderr="")
        assert args[2] == "profile" and args[4] == "key=clear", args
        name = args[3].split("=", 1)[1]
        text = self.details.get(name)
        if text is None:
            return SimpleNamespace(returncode=1, stdout=f"Profile {name} is not found on the system.", stderr="")
        return SimpleNamespace(returncode=0, stdout=text, stderr="")


def dead_api(exc: BaseException = OSError(5, "Access is denied")) -> FakeWlan:
    return FakeWlan(open_error=exc)


# ---------------------------------------------------------------------------
# profile XML
# ---------------------------------------------------------------------------
def test_parse_profile_xml_full():
    p = wifi.parse_profile_xml(OFFICE_XML)
    assert p == {"name": "TEC-Office", "ssid": "TEC-Office", "authentication": "WPA2PSK", "encryption": "AES",
                 "key": OFFICE_KEY, "key_present": True, "connection_mode": "auto", "non_broadcast": False,
                 "interface": None, "error": None}


def test_parse_profile_xml_open_network_has_no_key():
    p = wifi.parse_profile_xml(OPEN_XML)
    assert p["ssid"] == "SiteSurvey-5G" and p["authentication"] == "open" and p["encryption"] == "none"
    assert p["key"] is None and p["key_present"] is False and p["error"] is None
    assert p["connection_mode"] == "manual" and p["non_broadcast"] is True


def test_parse_profile_xml_reveal_false_keeps_key_present():
    p = wifi.parse_profile_xml(OFFICE_XML, reveal=False)
    assert p["key"] is None and p["key_present"] is True and p["error"] is None
    assert p["ssid"] == "TEC-Office" and p["authentication"] == "WPA2PSK"


def test_parse_profile_xml_protected_key():
    """A per-user profile read without the rights: the blob is never shown as the key."""
    xml = profile_xml("TEC-Office", "TEC-Office", key="0100000...D08C9DDF", protected=True)
    p = wifi.parse_profile_xml(xml)
    assert p["key"] is None and p["key_present"] is True
    assert "encrypted" in p["error"]
    # reveal=False asked for the encrypted blob on purpose: that is not an error
    assert wifi.parse_profile_xml(xml, reveal=False)["error"] is None


def test_parse_profile_xml_hex_only_ssid_and_other_namespace():
    xml = profile_xml("hidden-lab", ssid=None, hex_ssid="5445432D4C4142",
                      ns="http://www.microsoft.com/networking/WLAN/profile/v2")
    p = wifi.parse_profile_xml(xml)
    assert p["ssid"] == "TEC-LAB" and p["name"] == "hidden-lab" and p["key"] == OFFICE_KEY


@pytest.mark.parametrize("bad", ["", "   ", "<WLANProfile>", "not xml at all", None, b"\x00\x01", 17])
def test_parse_profile_xml_never_raises(bad):
    p = wifi.parse_profile_xml(bad)
    assert p["error"] and p["key"] is None and p["key_present"] is False
    assert set(p) == set(wifi.blank_profile())


# ---------------------------------------------------------------------------
# the native path
# ---------------------------------------------------------------------------
def test_list_profiles_native():
    api = FakeWlan()
    view = wifi.list_profiles(api=api)
    assert set(view) == {"available", "interfaces", "profiles", "error", "source", "ts"}
    assert view["available"] is True and view["source"] == "wlanapi" and view["error"] is None
    assert isinstance(view["ts"], float) and view["ts"] > 0
    assert view["interfaces"] == [{"guid": GUID_A, "description": "Intel(R) Wi-Fi 6 AX201 160MHz",
                                   "state": "connected"}]
    names = [p["name"] for p in view["profiles"]]
    assert names == ["TEC-Office", "TEC-Guest", "SiteSurvey-5G"]
    for p in view["profiles"]:
        assert set(p) == set(wifi.blank_profile())
        assert p["interface"] == GUID_A
    office, guest, survey = view["profiles"]
    assert office["key"] == OFFICE_KEY and office["key_present"] is True and office["encryption"] == "AES"
    assert guest["key"] == "example-guest-passphrase"
    assert survey["key"] is None and survey["key_present"] is False and survey["non_broadcast"] is True
    # the handle is opened once and always closed, and the plaintext key was asked for
    assert api.opened == 1 and api.closed == 1
    assert api.asked == [("TEC-Office", True), ("TEC-Guest", True), ("SiteSurvey-5G", True)]


def test_list_profiles_reveal_false_never_asks_for_the_key():
    api = FakeWlan()
    view = wifi.list_profiles(reveal=False, api=api)
    assert view["available"] is True and view["source"] == "wlanapi"
    assert [p["key"] for p in view["profiles"]] == [None, None, None]
    assert [p["key_present"] for p in view["profiles"]] == [True, True, False]
    assert api.asked == [("TEC-Office", False), ("TEC-Guest", False), ("SiteSurvey-5G", False)]


def test_list_profiles_native_two_interfaces():
    api = FakeWlan(
        interfaces=[{"guid": GUID_A, "description": "Intel AX201", "state": "connected"},
                    {"guid": GUID_B, "description": "USB dongle", "state": "disconnected"}],
        profiles={GUID_A: {"TEC-Office": OFFICE_XML}, GUID_B: {"TEC-Guest": GUEST_XML}})
    view = wifi.list_profiles(api=api)
    assert [i["guid"] for i in view["interfaces"]] == [GUID_A, GUID_B]
    assert [(p["name"], p["interface"]) for p in view["profiles"]] == [("TEC-Office", GUID_A), ("TEC-Guest", GUID_B)]


def test_one_unreadable_profile_only_marks_its_own_row():
    api = FakeWlan(profiles={GUID_A: {"TEC-Office": OFFICE_XML,
                                      "TEC-Guest": OSError(5, "Access is denied"),
                                      "SiteSurvey-5G": OPEN_XML}})
    view = wifi.list_profiles(api=api)
    assert view["available"] is True and view["error"] is None
    office, guest, survey = view["profiles"]
    assert office["key"] == OFFICE_KEY and survey["ssid"] == "SiteSurvey-5G"
    assert guest["name"] == "TEC-Guest" and guest["ssid"] == "TEC-Guest" and guest["key"] is None
    assert "could not be read" in guest["error"] and "Access is denied" in guest["error"]


def test_a_dead_interface_does_not_hide_the_others():
    class OneBadList(FakeWlan):
        def profile_names(self, ref):
            if ref == GUID_A:
                raise OSError(1168, "element not found")
            return super().profile_names(ref)

    api = OneBadList(interfaces=[{"guid": GUID_A, "description": "A", "state": "not_ready"},
                                 {"guid": GUID_B, "description": "B", "state": "connected"}],
                     profiles={GUID_B: {"TEC-Office": OFFICE_XML}})
    view = wifi.list_profiles(api=api)
    assert len(view["interfaces"]) == 2
    assert [p["name"] for p in view["profiles"]] == ["TEC-Office"]
    assert view["available"] is True


# ---------------------------------------------------------------------------
# netsh: the pure parsers
# ---------------------------------------------------------------------------
def test_parse_netsh_profile_names():
    assert wifi.parse_netsh_profile_names(NETSH_PROFILES) == ["TEC-Office", "TEC-Guest", "SiteSurvey-5G"]
    assert wifi.parse_netsh_profile_names("") == []
    # an SSID with a colon survives (only the first colon splits) and <None> is not a profile
    text = "Profiles on interface Wi-Fi:\n\nUser profiles\n-------------\n    All User Profile     : bench:5G\n"
    assert wifi.parse_netsh_profile_names(text) == ["bench:5G"]
    assert wifi.parse_netsh_profile_names("Group policy profiles\n---------\n    <None>\n") == []


def test_parse_netsh_interfaces():
    assert wifi.parse_netsh_interfaces(NETSH_INTERFACES) == [
        {"guid": "12345678-9abc-4def-8123-456789abcdef",
         "description": "Intel(R) Wi-Fi 6 AX201 160MHz", "state": "connected"}]
    assert wifi.parse_netsh_interfaces("") == []
    assert wifi.parse_netsh_interfaces("There are 0 interfaces on the system.") == []


def test_parse_netsh_profile_english_and_open():
    p = wifi.parse_netsh_profile(NETSH_OFFICE, "TEC-Office")
    assert p["name"] == "TEC-Office" and p["ssid"] == "TEC-Office"
    assert p["authentication"] == "WPA2-Personal" and p["encryption"] == "CCMP"
    assert p["key"] == OFFICE_KEY and p["key_present"] is True
    assert p["connection_mode"] == "auto" and p["non_broadcast"] is False and p["error"] is None
    o = wifi.parse_netsh_profile(NETSH_OPEN, "SiteSurvey-5G")
    assert o["authentication"] == "Open" and o["encryption"] == "None"
    assert o["key"] is None and o["key_present"] is False
    assert o["connection_mode"] == "manual" and o["non_broadcast"] is True


def test_parse_netsh_profile_localized_output():
    """Every label translated: the SSID, the security and the key still come out."""
    p = wifi.parse_netsh_profile(NETSH_OFFICE_DE, "TEC-Office")
    assert p["ssid"] == "TEC-Office"
    assert p["authentication"] == "WPA2-Personal" and p["encryption"] == "CCMP"
    assert p["key"] == OFFICE_KEY and p["key_present"] is True
    assert p["connection_mode"] == "auto"
    ascii_p = wifi.parse_netsh_profile(NETSH_OFFICE_DE_ASCII, "TEC-Office")
    assert ascii_p["key"] == OFFICE_KEY and ascii_p["encryption"] == "CCMP"


def test_parse_netsh_profile_does_not_mistake_an_ssid_for_the_security():
    text = NETSH_OFFICE.replace("Name                   : TEC-Office", "Name                   : Open Wifi")
    text = text.replace('"TEC-Office"', '"Open Wifi"')
    p = wifi.parse_netsh_profile(text, "Open Wifi")
    assert p["ssid"] == "Open Wifi" and p["authentication"] == "WPA2-Personal" and p["key"] == OFFICE_KEY


def test_parse_netsh_profile_key_equal_to_the_profile_name():
    """The name line is skipped as a security value, but a key that happens to equal the
    name still comes through (the key label wins over the name rule)."""
    text = NETSH_OFFICE.replace("Key Content            : example-office-passphrase",
                                "Key Content            : TEC-Office")
    p = wifi.parse_netsh_profile(text, "TEC-Office")
    assert p["key"] == "TEC-Office" and p["key_present"] is True
    assert p["authentication"] == "WPA2-Personal" and p["encryption"] == "CCMP"


def test_parse_netsh_profile_never_raises():
    for bad in ("", "   ", "no colons here", ":\n:\n:", "Key Content : "):
        p = wifi.parse_netsh_profile(bad, None)
        assert set(p) == set(wifi.blank_profile())


# ---------------------------------------------------------------------------
# netsh: the fallback
# ---------------------------------------------------------------------------
def test_wlan_open_handle_failure_falls_back_to_netsh():
    runner = FakeNetsh()
    view = wifi.list_profiles(api=dead_api(), runner=runner)
    assert view["available"] is True and view["source"] == "netsh" and view["error"] is None
    assert [p["name"] for p in view["profiles"]] == ["TEC-Office", "TEC-Guest", "SiteSurvey-5G"]
    assert view["profiles"][0]["key"] == OFFICE_KEY
    assert view["profiles"][2]["key"] is None and view["profiles"][2]["key_present"] is False
    assert view["interfaces"][0]["guid"] == GUID_A
    assert all(p["interface"] == GUID_A for p in view["profiles"])
    # the profile name goes to netsh verbatim in an argv list: no shell quoting is added
    assert runner.commands[0][1:] == ["wlan", "show", "profiles"]
    assert ["wlan", "show", "profile", "name=TEC-Office", "key=clear"] == runner.commands[2][1:]
    # ... hidden window, no stdin, a timeout: the house netsh conventions (tnt.firewall)
    kw = runner.kwargs[0]
    assert kw["capture_output"] is True and kw["check"] is False and kw["timeout"] > 0
    assert "stdin" in kw and "creationflags" in kw


def test_netsh_fallback_reveal_false_drops_the_keys():
    view = wifi.list_profiles(reveal=False, api=dead_api(), runner=FakeNetsh())
    assert view["source"] == "netsh"
    assert [p["key"] for p in view["profiles"]] == [None, None, None]
    assert [p["key_present"] for p in view["profiles"]] == [True, True, False]


def test_netsh_fallback_marks_one_unreadable_profile():
    runner = FakeNetsh(details={"TEC-Office": NETSH_OFFICE})     # the other two are "not found"
    view = wifi.list_profiles(api=dead_api(), runner=runner)
    assert view["available"] is True
    assert view["profiles"][0]["key"] == OFFICE_KEY and view["profiles"][0]["error"] is None
    assert "not found" in view["profiles"][1]["error"] and view["profiles"][1]["name"] == "TEC-Guest"


def test_native_returning_nothing_falls_back_to_netsh():
    """The API answered but has no interface: netsh gets the last word."""
    api = FakeWlan(interfaces=[], profiles={})
    view = wifi.list_profiles(api=api, runner=FakeNetsh())
    assert view["available"] is True and view["source"] == "netsh"
    assert [p["name"] for p in view["profiles"]] == ["TEC-Office", "TEC-Guest", "SiteSurvey-5G"]


# ---------------------------------------------------------------------------
# no wireless adapter / total failure
# ---------------------------------------------------------------------------
def test_no_wireless_adapter():
    runner = FakeNetsh(profiles=NO_ADAPTER_OUTPUT, rc=1)
    view = wifi.list_profiles(api=FakeWlan(interfaces=[], profiles={}), runner=runner)
    assert view["available"] is False and view["profiles"] == [] and view["interfaces"] == []
    assert wifi.NO_ADAPTER_TEXT in view["error"]
    assert "this PC has no wireless adapter" in view["error"]
    assert "wlansvc" in view["error"] or "AutoConfig" in view["error"]
    # netsh was asked once and then given up on: no per-profile calls
    assert [c[1:] for c in runner.commands] == [["wlan", "show", "profiles"]]


def test_no_adapter_error_also_names_the_api_failure():
    view = wifi.list_profiles(api=dead_api(OSError(1062, "the service is not running")),
                              runner=FakeNetsh(profiles=NO_ADAPTER_OUTPUT, rc=1))
    assert view["available"] is False and wifi.NO_ADAPTER_TEXT in view["error"]
    assert "the Wlan API also failed" in view["error"] and "not running" in view["error"]


def test_list_profiles_never_raises():
    class Exploding:
        def open(self):
            raise RuntimeError("boom")

        def close(self):
            raise RuntimeError("boom again")

        def interfaces(self):
            raise RuntimeError("boom")

        def profile_names(self, ref):
            raise RuntimeError("boom")

        def profile_xml(self, ref, name, plaintext=True):
            raise RuntimeError("boom")

    def exploding_runner(argv, **kwargs):
        raise OSError("netsh is on fire")

    view = wifi.list_profiles(api=Exploding(), runner=exploding_runner)
    assert view["available"] is False and view["profiles"] == [] and isinstance(view["error"], str)
    assert set(view) == {"available", "interfaces", "profiles", "error", "source", "ts"}
    # a runner that returns nonsense is just as harmless
    view = wifi.list_profiles(api=Exploding(), runner=lambda argv, **kw: SimpleNamespace(returncode=0, stdout=None, stderr=None))
    assert view["available"] is False and isinstance(view["error"], str)


# ---------------------------------------------------------------------------
# native plumbing (structures / prototypes) -- Windows only, no Wlan call
# ---------------------------------------------------------------------------
def test_structure_layout():
    assert ctypes.sizeof(wifi.GUID) == 16
    assert ctypes.sizeof(wifi.WLAN_INTERFACE_INFO) == 16 + 512 + 4
    assert ctypes.sizeof(wifi.WLAN_PROFILE_INFO) == 512 + 4
    assert wifi._IFACE_ROWS_OFFSET == 8 and wifi._PROFILE_ROWS_OFFSET == 8
    assert wifi.WLAN_PROFILE_GET_PLAINTEXT_KEY == 0x00000004 and wifi.WLAN_API_VERSION == 2
    g = wifi.GUID(0x12345678, 0x9ABC, 0x4DEF, (ctypes.c_ubyte * 8)(0x81, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF))
    assert wifi.guid_text(g) == GUID_A


@pytest.mark.skipif(sys.platform != "win32", reason="wlanapi.dll is Windows only")
def test_wlanapi_prototypes_are_declared():
    dll = wifi._dll()
    for name in ("WlanOpenHandle", "WlanCloseHandle", "WlanEnumInterfaces", "WlanGetProfileList",
                 "WlanGetProfile", "WlanFreeMemory"):
        fn = getattr(dll, name)
        assert fn.argtypes, name          # ctypes without argtypes crashes on x64
        assert fn.restype is not None or name == "WlanFreeMemory"


def test_import_is_safe_without_windows(monkeypatch):
    """No ctypes call happens at import time, and off Windows the module says so politely."""
    monkeypatch.setattr(wifi.sys, "platform", "linux")
    view = wifi.list_profiles()
    assert view["available"] is False and view["error"] == wifi.NOT_WINDOWS_TEXT
    assert view["profiles"] == [] and view["source"] == "wlanapi"


# ---------------------------------------------------------------------------
# the route: GET /api/tools/wifi/profiles
# ---------------------------------------------------------------------------
class RouteEngine:
    """The engine surface the wifi route needs: none of it (it only uses tnt.wifi)."""

    def __init__(self) -> None:
        self.version = "test"
        self.started_ts = None
        self.console = True
        self.config = None
        self.db = None
        self.bus = None
        self.api = None


class RecordingCheck:
    """A stand-in for the real ``tnt.peer.reveal_allowed`` admin check: records every
    ``(peer, local)`` it is called with and answers with a fixed decision."""

    def __init__(self, decision: str = "allowed") -> None:
        self.decision = decision
        self.calls: List[Any] = []

    def __call__(self, peer: Any, local: Any) -> str:
        self.calls.append((peer, local))
        return self.decision


@pytest.fixture
def server():
    srv = ApiServer(RouteEngine(), "127.0.0.1", 0)
    # inject the admin check so the route never runs the real Windows token lookup against the
    # test process (whose privilege level is unknown); default: this caller is an administrator
    srv.wifi_reveal_check = RecordingCheck("allowed")
    srv.start()
    assert srv.running and srv.port not in (0, 7130)
    yield srv
    srv.stop()


def call_json(srv: Any, method: str, path: str, headers: Optional[Dict[str, str]] = None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
    try:
        conn.request(method, path, headers=dict(headers or {}))
        resp = conn.getresponse()
        payload = resp.read()
        assert (resp.getheader("Content-Type") or "").startswith("application/json")
        return resp.status, (json.loads(payload) if payload else None)
    finally:
        conn.close()


@pytest.fixture
def fake_list(monkeypatch):
    """``tnt.wifi.list_profiles`` replaced: the suite never reads this machine's profiles."""
    calls: List[Dict[str, Any]] = []

    def fake(reveal: bool = True, api: Any = None, runner: Any = None) -> Dict[str, Any]:
        calls.append({"reveal": reveal})
        p = wifi.parse_profile_xml(OFFICE_XML, reveal=reveal)
        p["interface"] = GUID_A
        return {"available": True, "interfaces": [{"guid": GUID_A, "description": "Intel", "state": "connected"}],
                "profiles": [p], "error": None, "source": "wlanapi", "ts": 1.0}

    monkeypatch.setattr(wifi, "list_profiles", fake)
    return calls


def test_route_lists_profiles_masked_by_default(server, fake_list):
    """No ``reveal`` -> the keys are left out (the card's default view) and the admin check is
    never consulted; the list still arrives for any local caller."""
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles")
    assert status == 200
    assert set(body) == {"available", "interfaces", "profiles", "error", "source", "ts"}
    assert body["available"] is True and body["source"] == "wlanapi"
    assert body["interfaces"] == [{"guid": GUID_A, "description": "Intel", "state": "connected"}]
    assert body["profiles"][0]["key"] is None and body["profiles"][0]["key_present"] is True
    assert set(body["profiles"][0]) == set(wifi.blank_profile())
    assert calls_reveal(fake_list) == [False]
    assert server.wifi_reveal_check.calls == []      # reveal=False never runs the admin check


def test_route_reveal_one_allowed_returns_the_key(server, fake_list):
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles?reveal=1")
    assert status == 200
    assert body["profiles"][0]["key"] == OFFICE_KEY and body["profiles"][0]["key_present"] is True
    assert calls_reveal(fake_list) == [True]
    # the check ran once, and was handed this connection's two loopback endpoints
    assert len(server.wifi_reveal_check.calls) == 1
    peer, local = server.wifi_reveal_check.calls[0]
    assert peer and local and peer[0].startswith("127.") and int(local[1]) == server.port


def calls_reveal(calls: List[Dict[str, Any]]) -> List[bool]:
    return [c["reveal"] for c in calls]


@pytest.mark.parametrize("query,expected", [
    ("", False), ("?reveal=", False), ("?reveal=maybe", False),
    ("?reveal=0", False), ("?reveal=false", False), ("?reveal=no", False), ("?reveal=OFF", False),
    ("?reveal=1", True), ("?reveal=true", True), ("?reveal=yes", True), ("?reveal=on", True),
])
def test_route_reveal_query(server, fake_list, query, expected):
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles" + query)
    assert status == 200 and calls_reveal(fake_list) == [expected]
    assert (body["profiles"][0]["key"] is None) is (not expected)
    assert body["profiles"][0]["key_present"] is True
    # the check runs only when a reveal was actually asked for
    assert len(server.wifi_reveal_check.calls) == (1 if expected else 0)


@pytest.mark.parametrize("decision,message_needle", [
    ("denied", "administrator"),
    ("unknown", "verified"),
])
def test_route_reveal_refused_is_403(server, fake_list, decision, message_needle):
    server.wifi_reveal_check = RecordingCheck(decision)
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles?reveal=1")
    assert status == 403 and body["error"]["code"] == "admin_required"
    assert message_needle in body["error"]["message"]
    assert calls_reveal(fake_list) == []             # a refusal never reads the profiles/keys


def test_route_reveal_check_error_refuses(server, fake_list):
    """A check that raises must fail closed (403), never 500 or reveal keys."""
    def boom(peer: Any, local: Any) -> str:
        raise RuntimeError("token read exploded")
    server.wifi_reveal_check = boom
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles?reveal=1")
    assert status == 403 and body["error"]["code"] == "admin_required"
    assert calls_reveal(fake_list) == []


def _browser(server, site: Optional[str], origin: Optional[str] = "self") -> Dict[str, str]:
    """Headers a browser attaches to a fetch: ``Sec-Fetch-Site`` and, cross-origin, ``Origin``."""
    headers = {}
    if site is not None:
        headers["Sec-Fetch-Site"] = site
    if origin == "self":
        origin = f"http://127.0.0.1:{server.port}"
    if origin:
        headers["Origin"] = origin
    return headers


@pytest.mark.parametrize("site,origin", [
    ("cross-site", "https://evil.example"),
    ("cross-site", None),                           # an Origin-less cross-site request
    ("same-site", "http://localhost:8081"),         # another local web server is another origin
    ("same-site", None),
    (None, "https://evil.example"),                 # a browser without Sec-Fetch-* still sends Origin
    ("same-origin", "http://127.0.0.1:1"),          # an Origin that is not this server
    (None, "null"),                                 # a sandboxed frame or a file:// page
])
def test_route_reveal_refuses_a_page_of_another_origin(server, fake_list, site, origin):
    """Browsers send Origin / Sec-Fetch-Site; the reveal is refused for any page that is not served
    by this API before the admin check even runs, so a hostile page open in an administrator's
    browser cannot make the service write the keys onto that browser's connection."""
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles?reveal=1", _browser(server, site, origin))
    assert status == 403 and body["error"]["code"] == "forbidden"
    assert "TNT window" in body["error"]["message"]
    assert server.wifi_reveal_check.calls == [] and calls_reveal(fake_list) == []
    # the masked list (no keys) is not affected
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles", _browser(server, site, origin))
    assert status == 200 and body["profiles"][0]["key"] is None


@pytest.mark.parametrize("site,origin", [
    ("same-origin", "self"),       # the TNT window / a tab on this server
    ("same-origin", None),         # same-origin GET fetches usually carry no Origin
    ("none", None),                # the address typed into the browser
    (None, None),                  # not a browser: curl, PowerShell, scripts
])
def test_route_reveal_allows_same_origin_and_non_browser_callers(server, fake_list, site, origin):
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles?reveal=1", _browser(server, site, origin))
    assert status == 200 and body["profiles"][0]["key"] == OFFICE_KEY
    assert len(server.wifi_reveal_check.calls) == 1          # the admin check still decides


@pytest.mark.parametrize("decision,status", [("allowed", 200), ("denied", 403), ("unknown", 403)])
def test_route_uses_tnt_peer_when_no_check_is_injected(server, fake_list, monkeypatch, decision, status):
    """The production path: without an injected check the route asks tnt.peer.reveal_allowed."""
    import tnt.peer

    seen: List[Any] = []
    monkeypatch.setattr(tnt.peer, "reveal_allowed", lambda peer, local: seen.append((peer, local)) or decision)
    server.wifi_reveal_check = None
    got, body = call_json(server, "GET", "/api/tools/wifi/profiles?reveal=1")
    assert got == status and len(seen) == 1
    peer, local = seen[0]
    assert peer[0].startswith("127.") and int(local[1]) == server.port
    if status == 200:
        assert body["profiles"][0]["key"] == OFFICE_KEY and calls_reveal(fake_list) == [True]
    else:
        assert body["error"]["code"] == "admin_required" and calls_reveal(fake_list) == []


def test_route_refuses_when_tnt_peer_cannot_be_imported(server, fake_list, monkeypatch):
    monkeypatch.setitem(sys.modules, "tnt.peer", None)       # importing it now raises ImportError
    server.wifi_reveal_check = None
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles?reveal=1")
    assert status == 403 and body["error"]["code"] == "admin_required" and "verified" in body["error"]["message"]
    assert calls_reveal(fake_list) == []
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles")       # the masked list still works
    assert status == 200 and body["profiles"][0]["key"] is None


def test_route_reveal_zero_never_runs_the_check(server, fake_list):
    server.wifi_reveal_check = RecordingCheck("denied")   # would refuse if it were consulted
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles?reveal=0")
    assert status == 200 and body["profiles"][0]["key"] is None
    assert server.wifi_reveal_check.calls == [] and calls_reveal(fake_list) == [False]


def test_route_is_503_when_the_module_cannot_be_imported(server, monkeypatch):
    monkeypatch.setitem(sys.modules, "tnt.wifi", None)
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles")
    assert status == 503 and body["error"]["code"] == "unavailable"
    assert "Wi-Fi" in body["error"]["message"]


def test_route_only_answers_get(server, fake_list):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    try:
        conn.request("POST", "/api/tools/wifi/profiles", body=b"{}", headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 405 and "GET" in (resp.getheader("Allow") or "")
    finally:
        conn.close()
    assert calls_reveal(fake_list) == []


def test_route_is_registered_once():
    router = ApiServer(RouteEngine(), "127.0.0.1", 0).router
    patterns = dict(router.patterns())
    assert patterns["/api/tools/wifi/profiles"] == ["GET"]


def test_a_no_adapter_view_is_still_200(server, monkeypatch):
    """A PC without a wireless adapter is a normal answer, not an error status."""
    monkeypatch.setattr(wifi, "list_profiles", lambda **kw: {
        "available": False, "interfaces": [], "profiles": [], "error": wifi.NO_ADAPTER_TEXT,
        "source": "netsh", "ts": 2.0})
    status, body = call_json(server, "GET", "/api/tools/wifi/profiles")
    assert status == 200 and body["available"] is False and body["profiles"] == []
    assert "no wireless adapter" in body["error"]
