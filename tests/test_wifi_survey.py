"""client.wifi_ies (802.11 information elements) and client.wifi_survey (WLAN structures, store, scheduler).

Synthetic data only: locally administered BSSIDs (``02:...``), invented SSIDs, made-up GUIDs. No test
touches a real Wi-Fi adapter: the scheduler runs against :class:`FakeApi` with a fake clock and
``threaded=False`` (one test starts the real thread, still on the fake API).
"""
from __future__ import annotations

import ctypes
import json
import math
import random
import struct
import sys
import threading
import time
from array import array
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client import wifi_ies, wifi_survey  # noqa: E402
from client.wifi_ies import BAND_5, BAND_6, BAND_24  # noqa: E402

BSSID_A = b"\x02\x11\x22\x33\x44\x01"
BSSID_B = b"\x02\x11\x22\x33\x44\x02"
BSSID_C = b"\x02\x11\x22\x33\x44\x03"
TEXT_A = "02:11:22:33:44:01"
GUID_A = "0badc0de-0000-4000-8000-00000000000a"
GUID_B = "0badc0de-0000-4000-8000-00000000000b"
IEEE = b"\x00\x0f\xac"


# --------------------------------------------------------------------------- element builders
def ie(eid: int, body: bytes = b"") -> bytes:
    return bytes([eid, len(body)]) + bytes(body)


def ext(ext_id: int, body: bytes = b"") -> bytes:
    return ie(255, bytes([ext_id]) + bytes(body))


def ssid_ie(name: Any) -> bytes:
    return ie(0, name.encode("utf-8") if isinstance(name, str) else name)


def rates_ie(*mbps: float, extended: tuple = ()) -> bytes:
    out = ie(1, bytes(int(r * 2) for r in mbps))
    if extended:
        out += ie(50, bytes(int(r * 2) for r in extended))
    return out


def ds_ie(channel: int) -> bytes:
    return ie(3, bytes([channel]))


def ht_op(primary: int, offset: int = 0, wide: bool = True) -> bytes:
    return ie(61, bytes([primary, offset | (0x04 if wide else 0)]) + bytes(20))


def ht_cap(nss: int = 2, ht40: bool = True, sgi20: bool = True, sgi40: bool = True) -> bytes:
    info = (0x02 if ht40 else 0) | (0x20 if sgi20 else 0) | (0x40 if sgi40 else 0)
    return ie(45, struct.pack("<HB", info, 0x17) + bytes([0xFF] * nss + [0] * (16 - nss)) + bytes(7))


def vht_op(width: int, c0: int, c1: int = 0) -> bytes:
    return ie(192, bytes([width, c0, c1]) + b"\xfc\xff")


def mcs_map(nss: int, code: int) -> bytes:
    value = 0
    for i in range(8):
        value |= (code if i < nss else 3) << (2 * i)
    return struct.pack("<H", value)


def vht_cap(nss: int = 2, code: int = 2, sgi80: bool = True, sgi160: bool = False) -> bytes:
    info = (0x20 if sgi80 else 0) | (0x40 if sgi160 else 0)
    return ie(191, struct.pack("<I", info) + mcs_map(nss, code) + b"\x00\x00" + mcs_map(nss, code) + b"\x00\x00")


def he_cap(nss: int = 2, code: int = 2) -> bytes:
    return ext(35, bytes(6) + bytes(11) + mcs_map(nss, code) + mcs_map(nss, code))


def eht_cap(nss: int = 2, top: int = 13) -> bytes:
    nib = nss | (nss << 4)
    return ext(108, bytes(2) + bytes(9) + bytes([nib, nib if top >= 11 else 0, nib if top >= 13 else 0]))


def six_info(primary: int, width_code: int, c0: int, c1: int = 0) -> bytes:
    return bytes([primary, width_code, c0, c1, 6])


def he_op(vht: Optional[tuple] = None, cohosted: Optional[int] = None, six: Optional[bytes] = None) -> bytes:
    params = (1 << 14 if vht else 0) | (1 << 15 if cohosted is not None else 0) | (1 << 17 if six else 0)
    body = params.to_bytes(3, "little") + b"\x3f" + b"\xfc\xff"
    body += bytes(vht) if vht else b""
    body += bytes([cohosted]) if cohosted is not None else b""
    body += six or b""
    return ext(36, body)


def eht_op(width_code: int, c0: int, c1: int = 0, present: bool = True) -> bytes:
    return ext(106, bytes([0x01 if present else 0x00]) + b"\xfc\xff\xff\xff" + bytes([width_code, c0, c1]))


def rsn_ie(*akms: int, mfpr: bool = False, akm_oui: bytes = IEEE) -> bytes:
    body = struct.pack("<H", 1) + IEEE + b"\x04" + struct.pack("<H", 1) + IEEE + b"\x04"
    body += struct.pack("<H", len(akms)) + b"".join(akm_oui + bytes([a]) for a in akms)
    body += struct.pack("<H", 0xC0 if mfpr else 0x80)
    return ie(48, body)


def wpa_ie(*akms: int) -> bytes:
    ms = b"\x00\x50\xf2"
    body = ms + b"\x01" + struct.pack("<H", 1) + ms + b"\x02" + struct.pack("<H", 1) + ms + b"\x02"
    body += struct.pack("<H", len(akms)) + b"".join(ms + bytes([a]) for a in akms)
    return ie(221, body)


def filetime(epoch: float) -> int:
    return int(round(epoch * 1e7)) + wifi_survey.FILETIME_UNIX_EPOCH


def entry(freq_mhz: int, ies: bytes = b"", bssid: bytes = BSSID_A, rssi: int = -50, capability: int = 0x0001,
          host_ts: int = 0, tsf: int = 1, dot11_ssid: bytes = b"", phy_type: int = 0, rate_set: tuple = (),
          quality: int = 80, beacon_period: int = 100) -> Dict[str, Any]:
    return {"ssid": dot11_ssid, "bssid": bssid, "phy_type": phy_type, "rssi": rssi, "link_quality": quality,
            "in_reg_domain": True, "beacon_period": beacon_period, "timestamp": tsf, "host_timestamp": host_ts,
            "capability": capability, "freq_khz": freq_mhz * 1000, "rates": list(rate_set), "ies": ies}


def describe(freq_mhz: int, *parts: bytes, **kw: Any) -> Dict[str, Any]:
    d = wifi_ies.describe_bss(entry(freq_mhz, b"".join(parts), **kw))
    assert d is not None
    return d


# =========================================================================== frequency math
@pytest.mark.parametrize("freq, expected", [
    (2412, (BAND_24, 1)), (2437, (BAND_24, 6)), (2472, (BAND_24, 13)), (2484, (BAND_24, 14)),
    (5180, (BAND_5, 36)), (5500, (BAND_5, 100)), (5825, (BAND_5, 165)), (5885, (BAND_5, 177)),
    (4920, (BAND_5, 184)),
    (5935, (BAND_6, 2)), (5955, (BAND_6, 1)), (6115, (BAND_6, 33)), (7115, (BAND_6, 233)),
    (2436, (BAND_24, 6)), (5957, (BAND_6, 1)),   # rounding tolerance
    (0, None), (2300, None), (2478, None), (5925, None), (7200, None), (None, None), ("x", None), (True, None),
    (5960, None), (5965, None), (6000, None), (7125, None),   # 6 GHz between two 20 MHz channels: no channel
])
def test_freq_to_channel(freq, expected):
    assert wifi_ies.freq_to_channel(freq) == expected


def test_channel_to_freq_round_trips_and_edges():
    for band, channels in ((BAND_24, range(1, 15)), (BAND_5, list(range(32, 178, 4)) + [184, 196]),
                           (BAND_6, [2] + list(range(1, 234, 4)))):
        for ch in channels:
            f = wifi_ies.channel_to_freq(band, ch)
            assert wifi_ies.freq_to_channel(f) == (band, ch), (band, ch, f)
    assert wifi_ies.channel_to_freq(BAND_24, 14) == 2484 and wifi_ies.channel_to_freq(BAND_24, 1) == 2412
    assert wifi_ies.channel_to_freq(BAND_6, 2) == 5935, "channel 2 is the 20 MHz-only exception"
    assert wifi_ies.channel_to_freq(BAND_6, 1) == 5955 and wifi_ies.channel_to_freq(BAND_6, 233) == 7115
    for band, ch in ((BAND_24, 0), (BAND_24, 15), (BAND_6, 0), (BAND_6, 234), ("7", 1), (BAND_5, None)):
        assert wifi_ies.channel_to_freq(band, ch) is None


# =========================================================================== width, centre, spans
WIDTH_CASES = [
    ("2.4 GHz 20", 2437, [ds_ie(6), ht_op(6, 0)], (BAND_24, 6, 6, 20, [[2427, 2447]])),
    ("2.4 GHz 40 above", 2412, [ds_ie(1), ht_op(1, 1)], (BAND_24, 1, 3, 40, [[2402, 2442]])),
    ("2.4 GHz 40 below", 2462, [ds_ie(11), ht_op(11, 3)], (BAND_24, 11, 9, 40, [[2432, 2472]])),
    ("2.4 GHz 40 above past channel 13 stays 20", 2462, [ht_op(11, 1)], (BAND_24, 11, 11, 20, [[2452, 2472]])),
    ("2.4 GHz STA channel width bit clear", 2412, [ht_op(1, 1, wide=False)], (BAND_24, 1, 1, 20, [[2402, 2422]])),
    ("2.4 GHz channel 14", 2484, [ds_ie(14)], (BAND_24, 14, 14, 20, [[2474, 2494]])),
    ("2.4 GHz VHT 80 is capped at 40", 2412, [ht_op(1, 1), vht_op(1, 7)], (BAND_24, 1, 3, 40, [[2402, 2442]])),
    ("5 GHz 40", 5180, [ht_op(36, 1)], (BAND_5, 36, 38, 40, [[5170, 5210]])),
    ("5 GHz 80", 5180, [ht_op(36, 1), vht_op(1, 42)], (BAND_5, 36, 42, 80, [[5170, 5250]])),
    ("5 GHz 80, primary at the top", 5240, [ht_op(48, 3), vht_op(1, 42)], (BAND_5, 48, 42, 80, [[5170, 5250]])),
    ("5 GHz 160", 5180, [ht_op(36, 1), vht_op(1, 42, 50)], (BAND_5, 36, 50, 160, [[5170, 5330]])),
    ("5 GHz 80+80", 5180, [ht_op(36, 1), vht_op(1, 42, 106)], (BAND_5, 36, 42, 160, [[5170, 5250], [5490, 5570]])),
    ("5 GHz legacy 160", 5500, [ht_op(100, 1), vht_op(2, 114)], (BAND_5, 100, 114, 160, [[5490, 5650]])),
    ("5 GHz legacy 80+80", 5180, [ht_op(36, 1), vht_op(3, 42, 155)],
     (BAND_5, 36, 42, 160, [[5170, 5250], [5735, 5815]])),
    ("5 GHz VHT centre off the primary falls back to HT", 5180, [ht_op(36, 1), vht_op(1, 58)],
     (BAND_5, 36, 38, 40, [[5170, 5210]])),
    ("5 GHz VHT CCFS1 between 8 and 16 is 80", 5180, [ht_op(36, 1), vht_op(1, 42, 54)], (BAND_5, 36, 42, 80, [[5170, 5250]])),
    ("5 GHz 80 from HE Operation's VHT information", 5745, [ht_op(149, 1), he_op(vht=(1, 155, 0))],
     (BAND_5, 149, 155, 80, [[5735, 5815]])),
    ("5 GHz EHT 160", 5180, [ht_op(36, 1), vht_op(1, 42), eht_op(3, 42, 50)], (BAND_5, 36, 50, 160, [[5170, 5330]])),
    ("5 GHz EHT 320 is capped at 160", 5180, [ht_op(36, 1), vht_op(1, 42), eht_op(4, 50, 63)],
     (BAND_5, 36, 42, 80, [[5170, 5250]])),
    ("6 GHz HE 20", 5955, [he_op(six=six_info(1, 0, 1))], (BAND_6, 1, 1, 20, [[5945, 5965]])),
    ("6 GHz HE 40", 5975, [he_op(six=six_info(5, 1, 3))], (BAND_6, 5, 3, 40, [[5945, 5985]])),
    ("6 GHz HE 80", 5975, [he_op(six=six_info(5, 2, 7))], (BAND_6, 5, 7, 80, [[5945, 6025]])),
    ("6 GHz HE 160", 5975, [he_op(six=six_info(5, 3, 7, 15))], (BAND_6, 5, 15, 160, [[5945, 6105]])),
    ("6 GHz HE 160 without CCFS1 on an 80 MHz centre is 80", 5975, [he_op(six=six_info(5, 3, 7, 0))],
     (BAND_6, 5, 7, 80, [[5945, 6025]])),
    ("6 GHz HE 160 without CCFS1 on a 160 MHz centre", 5975, [he_op(six=six_info(5, 3, 15, 0))],
     (BAND_6, 5, 15, 160, [[5945, 6105]])),
    ("6 GHz HE 80 after a co-hosted BSS byte", 6135, [he_op(cohosted=7, six=six_info(37, 2, 39))],
     (BAND_6, 37, 39, 80, [[6105, 6185]])),
    ("6 GHz HE 80 after VHT information too", 6135, [he_op(vht=(0, 0, 0), cohosted=1, six=six_info(37, 2, 39))],
     (BAND_6, 37, 39, 80, [[6105, 6185]])),
    ("6 GHz 80 centre off the raster is ignored", 5975, [he_op(six=six_info(5, 2, 9))], (BAND_6, 5, 5, 20, [[5965, 5985]])),
    ("6 GHz EHT 320-1", 5975, [he_op(six=six_info(5, 3, 7, 15)), eht_op(4, 15, 31)], (BAND_6, 5, 31, 320, [[5945, 6265]])),
    ("6 GHz EHT 320-2", 6295, [he_op(six=six_info(69, 3, 71, 79)), eht_op(4, 79, 63)],
     (BAND_6, 69, 63, 320, [[6105, 6425]])),
    ("6 GHz EHT information absent", 5975, [he_op(six=six_info(5, 2, 7)), eht_op(4, 15, 31, present=False)],
     (BAND_6, 5, 7, 80, [[5945, 6025]])),
    ("6 GHz channel 2", 5935, [he_op(six=six_info(2, 0, 2))], (BAND_6, 2, 2, 20, [[5925, 5945]])),
    ("6 GHz channel 233", 7115, [he_op(six=six_info(233, 0, 233))], (BAND_6, 233, 233, 20, [[7105, 7125]])),
    ("6 GHz channel 233 cannot be 40", 7115, [he_op(six=six_info(233, 1, 235))], (BAND_6, 233, 233, 20, [[7105, 7125]])),
    # a claim that runs past the band edge or off the 802.11 channel lists falls back to what is valid
    ("6 GHz channel 233 cannot be 80 on 231 (past 7125 MHz)", 7115, [he_op(six=six_info(233, 2, 231))],
     (BAND_6, 233, 233, 20, [[7105, 7125]])),
    ("6 GHz channel 229 cannot be 80 on 231", 7095, [he_op(six=six_info(229, 2, 231))], (BAND_6, 229, 229, 20, [[7085, 7105]])),
    ("6 GHz EHT 320 on 223 runs past the band: the valid 160 stays", 6915,
     [he_op(six=six_info(193, 3, 199, 207)), eht_op(4, 207, 223)], (BAND_6, 193, 207, 160, [[6905, 7065]])),
    ("6 GHz EHT 320 on 191 fits", 6915, [he_op(six=six_info(193, 3, 199, 207)), eht_op(4, 207, 191)],
     (BAND_6, 193, 191, 320, [[6745, 7065]])),
    ("5 GHz VHT 80 on CCFS0 40 is not an 80 MHz channel: HT 40 stays", 5180, [ht_op(36, 1), vht_op(1, 40)],
     (BAND_5, 36, 38, 40, [[5170, 5210]])),
    ("5 GHz HT 40 below on channel 36 is not a 40 MHz channel", 5180, [ht_op(36, 3)], (BAND_5, 36, 36, 20, [[5170, 5190]])),
    ("5 GHz 160 on 163 (U-NII-3/4)", 5745, [ht_op(149, 1), vht_op(1, 155, 163)], (BAND_5, 149, 163, 160, [[5735, 5895]])),
]


@pytest.mark.parametrize("name, freq, parts, expected", WIDTH_CASES, ids=[c[0] for c in WIDTH_CASES])
def test_channel_width_centre_and_spans(name, freq, parts, expected):
    d = describe(freq, *parts)
    assert (d["band"], d["channel"], d["center_channel"], d["width_mhz"], d["spans"]) == expected
    assert d["freq_mhz"] == wifi_ies.channel_to_freq(d["band"], d["channel"])
    for lo, hi in d["spans"]:
        assert lo < d["freq_mhz"] < hi or len(d["spans"]) == 2


def test_primary_channel_prefers_the_aps_own_element_nearby():
    # a 2.4 GHz beacon of channel 6 heard while the radio was tuned to channel 5
    d = describe(2432, ds_ie(6), ht_op(6, 0))
    assert d["channel"] == 6 and d["freq_mhz"] == 2437 and d["spans"] == [[2427, 2447]]
    # an element 60 MHz away from the receive frequency is not believed
    d = describe(2412, ds_ie(13))
    assert d["channel"] == 1
    # 6 GHz: the HE 6 GHz Operation Information names the primary channel, also for a frequency between two
    # 20 MHz channels (which alone places nothing: 5960 MHz is not channel 2, which is 5935 MHz)
    d = describe(5960, he_op(six=six_info(1, 0, 1)))
    assert (d["band"], d["channel"], d["freq_mhz"], d["spans"]) == (BAND_6, 1, 5955, [[5945, 5965]])
    assert wifi_ies.describe_bss(entry(5960)) is None
    assert wifi_ies.describe_bss(entry(5960, he_op(six=six_info(3, 0, 3)))) is None, "channel 3 is off the raster"
    assert describe(5975, he_op(six=six_info(3, 0, 3)))["channel"] == 5, "an off-raster element channel is not believed"


def test_entry_without_a_usable_frequency():
    assert describe(0, ds_ie(11))["band"] == BAND_24, "a 2.4 GHz channel number alone places the AP"
    assert describe(0, ds_ie(11))["channel"] == 11
    assert wifi_ies.describe_bss(entry(0, ssid_ie("Synthetic Lab"))) is None
    assert wifi_ies.describe_bss(entry(9999)) is None


# =========================================================================== truncated / garbage
def test_parse_elements_keeps_complete_elements_before_a_truncated_one():
    blob = ssid_ie("Synthetic Lab") + ds_ie(6) + bytes([61, 22, 6, 5, 0])      # HT Operation cut short
    els = wifi_ies.parse_elements(blob)
    assert els.truncated and els.get(0) == b"Synthetic Lab" and els.get(3) == b"\x06" and els.get(61) is None
    assert wifi_ies.parse_elements(ssid_ie("x") + b"\x00").truncated, "a lone trailing byte"
    assert not wifi_ies.parse_elements(ssid_ie("x") + ext(35, b"\x00")).truncated
    assert wifi_ies.parse_elements(ie(255, b"")).get(255) is None, "an extension element without its id is skipped"
    for junk in (None, b"", object()):
        assert len(wifi_ies.parse_elements(junk)) == 0


@pytest.mark.parametrize("parts, width", [
    ([ie(61, b"\x06")], 20),                                               # HT Operation of one byte
    ([ie(192, b"\x01\x2a")], 20),                                          # VHT Operation without CCFS1
    ([ext(36, b"\x00\x00\x02\x3f")], 20),                                  # HE Operation shorter than its fixed part
    ([ext(36, (1 << 17).to_bytes(3, "little") + b"\x3f\xfc\xff" + b"\x05\x02")], 20),   # 6 GHz info cut off
    ([ext(106, b"\x01\xfc\xff")], 20),                                     # EHT Operation without its information
    ([bytes([192, 5, 1, 42])], 20),                                        # element longer than the blob
])
def test_truncated_width_elements_are_ignored(parts, width):
    freq = 5975 if any(p[:1] == b"\xff" and p[2:3] == b"\x24" for p in parts) else 5180
    d = describe(freq, *parts)
    assert d["width_mhz"] == width and len(d["spans"]) == 1


def test_describe_never_raises_on_garbage():
    rng = random.Random(20260911)
    for _ in range(1500):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120)))
        # bias towards the interesting element ids
        if blob and rng.random() < 0.7:
            blob = bytes([rng.choice([0, 1, 3, 45, 48, 50, 61, 191, 192, 221, 255])]) + blob[1:]
        freq = rng.choice([0, 2412, 2484, 5180, 5935, 5975, 7115, 123456])
        d = wifi_ies.describe_bss(entry(freq, blob, capability=rng.randrange(65536), rate_set=(rng.randrange(65536),)))
        if d is not None:
            json.dumps(d, allow_nan=False)
            assert d["width_mhz"] in (20, 40, 80, 160, 320) and d["band"] in (BAND_24, BAND_5, BAND_6)
    for bad in (None, 42, "entry", [], {"bssid": None}, {"bssid": b"\x01"}, {"bssid": BSSID_A, "freq_khz": "x"},
                {"bssid": BSSID_A, "freq_khz": 5180000, "ies": 42, "rates": 7}):
        wifi_ies.describe_bss(bad)       # no exception


# =========================================================================== PHY, generation, rate
def test_phy_lists_generations_and_rates():
    b_only = describe(2437, ds_ie(6), rates_ie(1, 2, 5.5, 11))
    assert (b_only["phys"], b_only["phy"], b_only["generation"], b_only["max_rate_mbps"]) == (["b"], "b", None, 11.0)

    g_n = describe(2437, rates_ie(1, 2, 5.5, 11, extended=(6, 9, 12, 18, 24, 36, 48, 54)), ht_cap(2), ht_op(6, 0))
    assert (g_n["phys"], g_n["phy"], g_n["generation"]) == (["g", "n"], "n", "Wi-Fi 4")
    assert g_n["max_rate_mbps"] == 144.4, "2 streams of MCS 7 at 20 MHz with a short guard interval"

    ac = describe(5180, rates_ie(6, 9, 12, 18, 24, 36, 48, 54), ht_cap(3), vht_cap(3, 2), ht_op(36, 1), vht_op(1, 42))
    assert (ac["phys"], ac["generation"], ac["max_rate_mbps"]) == (["a", "n", "ac"], "Wi-Fi 5", 1299.9)

    ax = describe(5180, ht_cap(2), vht_cap(2, 2), he_cap(2, 2), ht_op(36, 1), vht_op(1, 42))
    assert (ax["phys"], ax["phy"], ax["generation"], ax["max_rate_mbps"]) == (["a", "n", "ac", "ax"], "ax", "Wi-Fi 6", 1201.0)

    six = describe(5975, he_op(six=six_info(5, 2, 7)))
    assert (six["phys"], six["generation"]) == (["ax"], "Wi-Fi 6E"), "6 GHz is HE-only"

    be = describe(5975, he_cap(2, 2), eht_cap(2, 13), he_op(six=six_info(5, 3, 7, 15)), eht_op(4, 15, 31))
    assert (be["phys"], be["phy"], be["generation"], be["max_rate_mbps"]) == (["ax", "be"], "be", "Wi-Fi 7", 5764.8)

    g_ax = describe(2412, rates_ie(1, 2, 5.5, 11, 6, 54), ht_cap(2), he_cap(1, 1), ht_op(1, 1))
    assert (g_ax["phys"], g_ax["generation"], g_ax["max_rate_mbps"]) == (["g", "n", "ax"], "Wi-Fi 6", 229.4)


def test_vht_capabilities_on_2_4_ghz_are_not_802_11ac():
    """Many 2.4 GHz APs carry a VHT Capabilities element for a proprietary 256-QAM mode; VHT itself is 5 GHz only."""
    turbo = describe(2437, rates_ie(1, 2, 5.5, 11, extended=(6, 9, 12, 18, 24, 36, 48, 54)), ht_cap(2), vht_cap(2, 2),
                     ht_op(6, 0))
    assert (turbo["phys"], turbo["generation"], turbo["max_rate_mbps"]) == (["g", "n"], "Wi-Fi 4", 144.4)
    with_he = describe(2437, rates_ie(1, 54), ht_cap(2), vht_cap(2, 2), he_cap(2, 2), ht_op(6, 0))
    assert (with_he["phys"], with_he["generation"]) == (["g", "n", "ax"], "Wi-Fi 6")
    assert describe(2437, ht_cap(2), phy_type=8)["phys"] == ["g", "n"], "a VHT PHY type Windows reports on 2.4 GHz"
    assert describe(5975, he_op(six=six_info(5, 2, 7)), vht_cap(2, 2))["phys"] == ["ax"], "nor on 6 GHz"
    five = describe(5180, ht_cap(2), vht_cap(2, 2), ht_op(36, 1), vht_op(1, 42))
    assert five["phys"] == ["a", "n", "ac"] and five["max_rate_mbps"] == 866.6


def test_phy_fallbacks_without_elements():
    assert describe(2412, phy_type=5)["phys"] == ["b"], "HR/DSSS reported by Windows"
    assert describe(2412)["phys"] == ["g"], "nothing known on 2.4 GHz"
    assert describe(5180, phy_type=8)["phys"] == ["a", "ac"], "a newer PHY Windows reports is added"
    assert describe(5180, ht_cap(), phy_type=7)["phys"] == ["a", "n"]
    assert describe(2412, rates_ie(1, 2), phy_type=6)["phys"] == ["b"], "the rate element beats the reported type"
    rs = describe(2437, rate_set=(0x8002, 0x8004, 0x000B, 0x0016, 0x006C))
    assert rs["phys"] == ["g"] and rs["max_rate_mbps"] == 54.0, "WLAN_RATE_SET is in 500 kb/s units with a basic bit"
    selectors = describe(2437, rates_ie(1, 2, 5.5, 11) + ie(50, bytes([0xFF, 0xFB])))
    assert selectors["phys"] == ["b"] and selectors["max_rate_mbps"] == 11.0, "BSS membership selectors are not rates"


def test_ht_rate_uses_the_long_guard_interval_without_the_short_gi_bit():
    d = describe(5180, ht_cap(1, sgi40=False), ht_op(36, 1))
    assert d["width_mhz"] == 40 and d["max_rate_mbps"] == 135.0


# =========================================================================== security
SECURITY_CASES = [
    ("open", b"", 0x0001, "Open"),
    ("wep", b"", 0x0011, "WEP"),
    ("wpa personal", wpa_ie(2), 0x0011, "WPA-Personal"),
    ("wpa enterprise", wpa_ie(1), 0x0011, "WPA-Enterprise"),
    ("wpa mixed akms", wpa_ie(1, 2), 0x0011, "Unknown"),
    ("wpa2 psk", rsn_ie(2), 0x0011, "WPA2-Personal"),
    ("wpa2 ft-psk", rsn_ie(4), 0x0011, "WPA2-Personal"),
    ("wpa2 psk-sha256", rsn_ie(2, 6), 0x0011, "WPA2-Personal"),
    ("wpa3 sae", rsn_ie(8, mfpr=True), 0x0011, "WPA3-Personal"),
    ("wpa3 ft-sae", rsn_ie(8, 9, mfpr=True), 0x0011, "WPA3-Personal"),
    ("wpa3 sae-ext-key", rsn_ie(24, mfpr=True), 0x0011, "WPA3-Personal"),
    ("wpa3 ft-sae-ext-key", rsn_ie(25, mfpr=True), 0x0011, "WPA3-Personal"),
    ("wpa2/wpa3 transition", rsn_ie(2, 8), 0x0011, "WPA2/WPA3-Personal"),
    ("wpa2/wpa3 transition with ft", rsn_ie(2, 4, 8, 9), 0x0011, "WPA2/WPA3-Personal"),
    ("wpa2 enterprise", rsn_ie(1), 0x0011, "WPA2-Enterprise"),
    ("wpa2 enterprise ft", rsn_ie(1, 3), 0x0011, "WPA2-Enterprise"),
    ("802.1x-sha256 without mfpr", rsn_ie(5), 0x0011, "WPA2-Enterprise"),
    ("wpa2/wpa3 enterprise transition (mfpr clear)", rsn_ie(1, 5), 0x0011, "WPA2-Enterprise"),
    ("wpa3 enterprise", rsn_ie(5, mfpr=True), 0x0011, "WPA3-Enterprise"),
    # PMF required keeps every WPA2-only client out: WPA3-Enterprise whichever 802.1X AKMs are offered
    ("802.1x with mfpr", rsn_ie(1, mfpr=True), 0x0011, "WPA3-Enterprise"),
    ("ft 802.1x with mfpr", rsn_ie(3, 5, mfpr=True), 0x0011, "WPA3-Enterprise"),
    ("802.1x + 802.1x-sha256 with mfpr", rsn_ie(1, 5, mfpr=True), 0x0011, "WPA3-Enterprise"),
    ("802.1x-sha384 with mfpr", rsn_ie(23, mfpr=True), 0x0011, "WPA3-Enterprise"),
    ("wpa3 enterprise 192-bit", rsn_ie(12, mfpr=True), 0x0011, "WPA3-Enterprise 192-bit"),
    ("suite b sha-256 is not 192-bit", rsn_ie(11, mfpr=True), 0x0011, "WPA3-Enterprise"),
    ("suite b sha-256 without mfpr", rsn_ie(11), 0x0011, "WPA2-Enterprise"),
    ("ft 802.1x sha-384", rsn_ie(12, 13, mfpr=True), 0x0011, "WPA3-Enterprise 192-bit"),
    ("192-bit offered beside 802.1x-sha256", rsn_ie(5, 12, mfpr=True), 0x0011, "WPA3-Enterprise"),
    ("owe", rsn_ie(18, mfpr=True), 0x0011, "OWE"),
    ("vendor akm only", rsn_ie(1, akm_oui=b"\x00\x40\x96"), 0x0011, "Unknown"),
    ("psk and 802.1x", rsn_ie(1, 2), 0x0011, "Unknown"),
    ("owe and psk", rsn_ie(2, 18), 0x0011, "Unknown"),
    ("empty akm list", rsn_ie(), 0x0011, "Unknown"),
    ("rsn beats wpa", rsn_ie(2) + wpa_ie(2), 0x0011, "WPA2-Personal"),
    ("rsn beats the privacy bit", rsn_ie(8), 0x0011, "WPA3-Personal"),
    ("rsn without an akm list defaults to 802.1x",
     ie(48, struct.pack("<H", 1) + IEEE + b"\x04" + struct.pack("<H", 1) + IEEE + b"\x04"), 0x0011, "WPA2-Enterprise"),
    ("rsn version only", ie(48, b"\x01\x00"), 0x0011, "WPA2-Enterprise"),
    ("rsn truncated in the pairwise list", ie(48, struct.pack("<H", 1) + IEEE + b"\x04" + struct.pack("<H", 2) + IEEE + b"\x04"),
     0x0011, "Unknown"),
    ("rsn truncated in the akm list",
     ie(48, struct.pack("<H", 1) + IEEE + b"\x04" + struct.pack("<H", 1) + IEEE + b"\x04" + struct.pack("<H", 2) + IEEE + b"\x02"),
     0x0011, "Unknown"),
    ("rsn of one byte", ie(48, b"\x01"), 0x0011, "Unknown"),
    ("other vendor element is not wpa", ie(221, b"\x00\x50\xf2\x04\x10\x4a"), 0x0011, "WEP"),
]


@pytest.mark.parametrize("name, ies, capability, expected", SECURITY_CASES, ids=[c[0] for c in SECURITY_CASES])
def test_security_labels(name, ies, capability, expected):
    assert describe(5180, ies, capability=capability)["security"] == expected


def test_every_contract_security_string_is_reachable():
    produced = {case[3] for case in SECURITY_CASES}
    assert produced == {"Open", "OWE", "WEP", "WPA-Personal", "WPA2-Personal", "WPA3-Personal", "WPA2/WPA3-Personal",
                        "WPA-Enterprise", "WPA2-Enterprise", "WPA3-Enterprise", "WPA3-Enterprise 192-bit", "Unknown"}


# =========================================================================== SSID, BSSID, OUI
def test_ssid_decoding_and_hidden_networks():
    assert describe(5180, ssid_ie("Synthetic Lab"))["ssid"] == "Synthetic Lab"
    for hidden in (ssid_ie(b""), ssid_ie(b"\x00" * 9), b""):
        d = describe(5180, hidden)
        assert (d["ssid"], d["hidden"]) == ("", True)
    known = describe(5180, ssid_ie(b"\x00" * 6), dot11_ssid=b"Synthetic Hidden")
    assert (known["ssid"], known["hidden"]) == ("Synthetic Hidden", False), "Windows learned the name of a hidden network"
    snowman = "Lab " + chr(0x2603)
    assert describe(5180, ssid_ie(snowman))["ssid"] == snowman
    assert describe(5180, ssid_ie(b"Caf\xe9 Test"))["ssid"] == "Caf" + chr(0xE9) + " Test", "Windows-1252 fallback"
    assert describe(5180, ssid_ie(b"a\x01b\x7fc"))["ssid"] == "a" + chr(0xFFFD) + "b" + chr(0xFFFD) + "c"
    assert describe(5180, ssid_ie(b"trail\x00\x00"))["ssid"] == "trail"
    assert wifi_ies.decode_ssid(b"x" * 40) == ("x" * 32, False), "never more than 32 bytes"
    assert wifi_ies.decode_ssid(None) == ("", True) and wifi_ies.decode_ssid(object()) == ("", True)


def test_bssid_and_oui():
    assert wifi_ies.format_bssid(BSSID_A) == TEXT_A
    assert wifi_ies.format_bssid("02-11-22-33-44-01") == TEXT_A and wifi_ies.format_bssid("0211.2233.4401") == TEXT_A
    for bad in (b"\x02\x11", "zz:11:22:33:44:55", None, 7, "02:11:22:33:44"):
        assert wifi_ies.format_bssid(bad) is None
    assert wifi_ies.oui_info("02:11:22:33:44:01") == ("02:11:22", True, "00:11:22")
    assert wifi_ies.oui_info("AE:DE:48:00:11:22") == ("AE:DE:48", True, "AC:DE:48")
    assert wifi_ies.oui_info("AC:DE:48:00:11:22") == ("AC:DE:48", False, None)
    d = describe(5180, bssid=b"\xac\xde\x48\x00\x11\x22")
    assert (d["bssid"], d["oui"], d["locally_administered"], d["base_oui"]) == ("AC:DE:48:00:11:22", "AC:DE:48", False, None)


def test_describe_shape_and_beacon_interval():
    d = describe(5180, ssid_ie("Synthetic Lab"), ht_op(36, 1), vht_op(1, 42), rsn_ie(2, 8), beacon_period=100)
    assert list(d) == ["bssid", "ssid", "hidden", "band", "channel", "center_channel", "width_mhz", "freq_mhz", "spans",
                       "phy", "phys", "generation", "security", "beacon_ms", "max_rate_mbps", "oui",
                       "locally_administered", "base_oui"]
    assert d["beacon_ms"] == 102, "100 TU"
    assert describe(5180, beacon_period=0)["beacon_ms"] is None
    json.dumps(d, allow_nan=False)
    assert wifi_ies.self_test() == (True, "5 GHz 80 MHz WPA3 sample")


# =========================================================================== native structures
def test_wlan_structure_layout():
    s = wifi_survey
    assert ctypes.sizeof(s.WLAN_BSS_ENTRY) == 360
    offsets = {name: getattr(s.WLAN_BSS_ENTRY, name).offset for name, _ in s.WLAN_BSS_ENTRY._fields_}
    assert offsets == {"dot11Ssid": 0, "uPhyId": 36, "dot11Bssid": 40, "dot11BssType": 48, "dot11BssPhyType": 52,
                       "lRssi": 56, "uLinkQuality": 60, "bInRegDomain": 64, "usBeaconPeriod": 66, "ullTimestamp": 72,
                       "ullHostTimestamp": 80, "usCapabilityInformation": 88, "ulChCenterFrequency": 92,
                       "wlanRateSet": 96, "ulIeOffset": 352, "ulIeSize": 356}
    assert ctypes.sizeof(s.DOT11_SSID) == 36 and ctypes.sizeof(s.WLAN_RATE_SET) == 256 and ctypes.sizeof(s.GUID) == 16
    assert s.WLAN_BSS_LIST.wlanBssEntries.offset == 8
    assert ctypes.sizeof(s.WLAN_INTERFACE_INFO) == 532 and s.WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset == 8
    assert ctypes.sizeof(s.WLAN_ASSOCIATION_ATTRIBUTES) == 68 and s.WLAN_ASSOCIATION_ATTRIBUTES.dot11PhyType.offset == 48
    assert (s.WLAN_ASSOCIATION_ATTRIBUTES.ulRxRate.offset, s.WLAN_ASSOCIATION_ATTRIBUTES.ulTxRate.offset) == (60, 64)
    assert ctypes.sizeof(s.WLAN_SECURITY_ATTRIBUTES) == 16
    assert ctypes.sizeof(s.WLAN_CONNECTION_ATTRIBUTES) == 604
    assert s.WLAN_CONNECTION_ATTRIBUTES.wlanAssociationAttributes.offset == 520
    assert ctypes.sizeof(s.WLAN_RADIO_STATE) == 772
    assert s.layout_ok()
    assert (s.WLAN_INTF_OPCODE_RADIO_STATE, s.WLAN_INTF_OPCODE_CURRENT_CONNECTION, s.DOT11_BSS_TYPE_ANY) == (4, 7, 3)
    assert (s.ERROR_ACCESS_DENIED, s.ERROR_SERVICE_NOT_ACTIVE, s.WLAN_API_VERSION) == (5, 1062, 2)


@pytest.mark.skipif(sys.platform != "win32", reason="wlanapi.dll is Windows only")
def test_wlanapi_prototypes_are_declared():
    dll = wifi_survey._dll()
    for name in ("WlanOpenHandle", "WlanCloseHandle", "WlanEnumInterfaces", "WlanGetNetworkBssList", "WlanScan",
                 "WlanQueryInterface", "WlanFreeMemory"):
        fn = getattr(dll, name)
        assert fn.argtypes, name
        assert fn.restype is not None or name == "WlanFreeMemory", name


def _bss_buffer(rows: List[Dict[str, Any]], extra: int = 0) -> Any:
    """A WLAN_BSS_LIST laid out like the API's: header, the entry array, then the IE blobs."""
    s = wifi_survey
    rows_end = s._BSS_ROWS_OFFSET + len(rows) * s._BSS_ENTRY_SIZE
    total = rows_end + sum(len(r["ies"]) for r in rows) + extra
    buf = ctypes.create_string_buffer(max(total, ctypes.sizeof(s.WLAN_BSS_LIST)))
    head = s.WLAN_BSS_LIST.from_buffer(buf)
    head.dwTotalSize, head.dwNumberOfItems = total, len(rows)
    blob_at = rows_end
    for i, row in enumerate(rows):
        at = s._BSS_ROWS_OFFSET + i * s._BSS_ENTRY_SIZE
        e = s.WLAN_BSS_ENTRY.from_buffer(buf, at)
        e.dot11Ssid.uSSIDLength = row.get("ssid_len", len(row["ssid"]))
        ctypes.memmove(ctypes.addressof(e.dot11Ssid.ucSSID), row["ssid"], len(row["ssid"]))
        ctypes.memmove(ctypes.addressof(e.dot11Bssid), row["bssid"], 6)
        e.dot11BssPhyType, e.lRssi, e.uLinkQuality = 8, row["rssi"], 77
        e.usBeaconPeriod, e.ullTimestamp, e.ullHostTimestamp = 100, 123456789, row["host_ts"]
        e.usCapabilityInformation, e.ulChCenterFrequency = 0x0011, row["freq_khz"]
        e.wlanRateSet.uRateSetLength = row.get("rate_len", len(row["rates"]))
        for j, rate in enumerate(row["rates"]):
            e.wlanRateSet.usRateSet[j] = rate
        e.ulIeOffset = row.get("ie_offset", blob_at - at)
        e.ulIeSize = len(row["ies"])
        ctypes.memmove(ctypes.addressof(buf) + blob_at, row["ies"], len(row["ies"]))
        blob_at += len(row["ies"])
    return buf


def test_read_bss_list_copies_entries_and_their_elements():
    ies_a = ssid_ie("Synthetic Lab") + ht_op(36, 1) + vht_op(1, 42)
    ies_b = ssid_ie(b"") + ds_ie(6)
    buf = _bss_buffer([
        {"ssid": b"Synthetic Lab", "bssid": BSSID_A, "rssi": -48, "host_ts": filetime(1_800_000_000.0),
         "freq_khz": 5180000, "rates": [0x800C, 0x0018, 0x006C], "ies": ies_a},
        {"ssid": b"", "bssid": BSSID_B, "rssi": -71, "host_ts": 0, "freq_khz": 2437000, "rates": [2, 4],
         "rate_len": 4, "ssid_len": 99, "ies": ies_b},
    ])
    rows = wifi_survey.read_bss_list(ctypes.addressof(buf))
    assert [r["bssid"] for r in rows] == [BSSID_A, BSSID_B]
    a, b = rows
    assert set(a) == set(wifi_ies.ENTRY_KEYS)
    assert (a["ssid"], a["rssi"], a["link_quality"], a["freq_khz"], a["ies"]) == (b"Synthetic Lab", -48, 77, 5180000, ies_a)
    assert a["rates"] == [0x800C, 0x0018, 0x006C] and a["capability"] == 0x0011 and a["beacon_period"] == 100
    assert a["host_timestamp"] == filetime(1_800_000_000.0) and a["timestamp"] == 123456789 and a["phy_type"] == 8
    assert b["ssid"] == b"\x00" * 32, "an SSID length past 32 is clamped"
    assert b["ies"] == ies_b and b["rates"] == [2, 4], "zero rate slots dropped"
    assert wifi_ies.describe_bss(b)["hidden"] is True
    assert wifi_ies.describe_bss(a)["width_mhz"] == 80


def test_read_bss_list_bounds_checks():
    good = {"ssid": b"x", "bssid": BSSID_A, "rssi": -50, "host_ts": 0, "freq_khz": 5180000, "rates": [], "ies": ds_ie(36)}
    past_end = dict(good, ie_offset=10_000)
    inside_rows = dict(good, ie_offset=4)
    buf = _bss_buffer([past_end, inside_rows])
    assert [r["ies"] for r in wifi_survey.read_bss_list(ctypes.addressof(buf))] == [b"", b""]
    # a count that does not fit in dwTotalSize is cut to what fits
    buf = _bss_buffer([good])
    wifi_survey.WLAN_BSS_LIST.from_buffer(buf).dwNumberOfItems = 50
    assert len(wifi_survey.read_bss_list(ctypes.addressof(buf))) == 1
    # an implausible header is an error, not a wild read
    wifi_survey.WLAN_BSS_LIST.from_buffer(buf).dwTotalSize = 4
    with pytest.raises(OSError):
        wifi_survey.read_bss_list(ctypes.addressof(buf))
    buf = _bss_buffer([])
    assert wifi_survey.read_bss_list(ctypes.addressof(buf)) == []


def test_import_is_safe_off_windows():
    assert wifi_survey._wlanapi is None or sys.platform == "win32", "wlanapi is only loaded on first use"
    assert "WinDLL" not in (ROOT / "client" / "wifi_ies.py").read_text(encoding="utf-8")
    source = (ROOT / "client" / "wifi_survey.py").read_text(encoding="utf-8")
    assert "from tnt" not in source and "import tnt" not in source, "the client bundle has no tnt.* service modules"


# =========================================================================== store + scheduler
class FakeClock:
    def __init__(self, wall: float = 1_800_000_000.0) -> None:
        self.wall = wall
        self.mono = 1000.0

    def time(self) -> float:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.mono += seconds


class World:
    """What the fake Wlan API sees: interfaces, radio, BSS entries and scripted errors."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.t0 = clock.mono
        self.events: List[Any] = []
        self.interfaces = [{"guid": GUID_A, "description": "Synthetic Wi-Fi", "state": "disconnected", "ref": "if0"}]
        self.radio: Optional[bool] = True
        self.entries: List[Dict[str, Any]] = []
        self.open_error: Any = None
        self.enum_error: Any = None
        self.read_error: Any = None
        self.scan_error: Any = None
        self.read_errors: Dict[Any, Any] = {}      # per interface ref, instead of read_error
        self.scan_errors: Dict[Any, Any] = {}
        self.connection: Optional[Dict[str, Any]] = None
        self.opened = 0
        self.closed = 0

    def factory(self) -> "FakeApi":
        return FakeApi(self)

    def log(self, name: str) -> None:
        self.events.append((round(self.clock.mono - self.t0, 2), name))

    def take(self) -> List[Any]:
        out, self.events = [e for e in self.events if e[1] in ("read", "scan")], []
        return out


def _raise(error: Any) -> None:
    if isinstance(error, int):
        raise OSError(error, f"fake Wlan error {error}")
    if error is not None:
        raise error


class FakeApi:
    def __init__(self, world: World) -> None:
        self.w = world

    def open(self) -> None:
        _raise(self.w.open_error)
        self.w.opened += 1

    def close(self) -> None:
        self.w.closed += 1

    def interfaces(self) -> List[Dict[str, Any]]:
        _raise(self.w.enum_error)
        return [dict(i) for i in self.w.interfaces]

    def radio_on(self, ref: Any) -> Optional[bool]:
        return self.w.radio

    def bss_list(self, ref: Any) -> List[Dict[str, Any]]:
        self.w.log("read")
        _raise(self.w.read_errors.get(ref, self.w.read_error))
        return [dict(e) if isinstance(e, dict) else e for e in self.w.entries]

    def scan(self, ref: Any) -> None:
        self.w.log("scan")
        _raise(self.w.scan_errors.get(ref, self.w.scan_error))

    def current_connection(self, ref: Any) -> Optional[Dict[str, Any]]:
        return self.w.connection


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def world(clock) -> World:
    return World(clock)


def make_survey(world: World, clock: FakeClock, **kw: Any) -> wifi_survey.WifiSurvey:
    kw.setdefault("threaded", False)
    return wifi_survey.WifiSurvey(api_factory=world.factory, clock=clock.time, monotonic=clock.monotonic, **kw)


def simulate(survey: wifi_survey.WifiSurvey, clock: FakeClock, seconds: float,
             renew_every: Optional[float] = None) -> None:
    """Drive the scheduler like its thread would, for *seconds* of fake time."""
    end = clock.mono + seconds
    next_renew = clock.mono if renew_every else None
    for _ in range(20000):
        if next_renew is not None and clock.mono >= next_renew:
            survey.survey({"active": True})
            next_renew += renew_every
        delay = survey.tick()
        step_end = min(end, next_renew) if next_renew is not None else end
        if clock.mono + delay >= step_end:
            if step_end >= end:
                clock.advance(end - clock.mono)
                survey.tick()
                return
            clock.advance(step_end - clock.mono)
            continue
        clock.advance(delay)
    raise AssertionError("the scheduler never settled")


def ap_entry(bssid: bytes, rssi: int, beacon: float, freq: int = 5180, name: str = "Synthetic Lab") -> Dict[str, Any]:
    return entry(freq, ssid_ie(name) + ht_op(36, 1) + vht_op(1, 42) + rsn_ie(2), bssid=bssid, rssi=rssi,
                 host_ts=filetime(beacon), tsf=int(beacon * 1000))


def test_nothing_happens_before_the_session_starts(world, clock):
    s = make_survey(world, clock)
    assert s.tick() == wifi_survey.IDLE_WAIT_S and world.events == [] and world.opened == 0
    view = s.survey({"active": False}, visible=lambda: False)
    assert (view["state"], view["started_ts"], view["error"]) == ("starting", None, wifi_survey.NOT_STARTED_TEXT)
    assert s.tick() == wifi_survey.IDLE_WAIT_S and world.opened == 0, "a hidden window's passive poll starts nothing"
    assert not s.session_started


@pytest.mark.parametrize("how", ["window_shown", "active", "visible", "no visibility check"])
def test_session_start_triggers(world, clock, how):
    s = make_survey(world, clock)
    if how == "window_shown":
        s.window_shown()
    elif how == "active":
        s.survey({"active": True}, visible=lambda: False)
    elif how == "visible":
        s.survey({}, visible=lambda: True)
    else:
        s.survey(None)
    assert s.session_started and s.survey()["started_ts"] == clock.wall
    s.tick()
    assert world.events and world.events[0][1] == "read"


def test_disabled_never_starts_a_session(world, clock):
    s = make_survey(world, clock, enabled=False)
    s.window_shown()
    view = s.survey({"active": True}, visible=lambda: True)
    assert (view["state"], view["enabled"], view["active"], view["error"]) == ("disabled", False, False, wifi_survey.DISABLED_TEXT)
    assert s.tick() == wifi_survey.IDLE_WAIT_S and world.events == [] and world.opened == 0
    assert s.scan_now() == {"ok": False, "error": wifi_survey.DISABLED_TEXT}


def test_passive_cadence_reads_the_cached_list_once_a_minute(world, clock):
    s = make_survey(world, clock)
    s.window_shown()
    simulate(s, clock, 130)
    assert world.take() == [(0, "read"), (60, "read"), (120, "read")], "no WlanScan without a lease"
    assert world.opened == 1, "one handle, reused"
    view = s.survey()
    assert view["state"] == "ok" and view["active"] is False and view["last_scan_ts"] is None
    assert (view["scan_interval_s"], view["passive_interval_s"]) == (10.0, 60.0)


def test_active_lease_scans_every_10_s_and_reads_4_s_after_each_scan(world, clock):
    s = make_survey(world, clock)
    s.window_shown()
    assert s.survey({"active": True})["active"] is True
    simulate(s, clock, 95)
    assert world.take() == [(0, "read"), (0, "scan"), (4, "read"), (9, "read"), (10, "scan"), (14, "read"),
                            (19, "read"), (20, "scan"), (24, "read"), (29, "read"), (89, "read")], \
        "the 30 s lease ran out at 30 s: back to one cached read a minute"
    view = s.survey()
    assert view["active"] is False and view["last_scan_ts"] == 1_800_000_000.0 + 20


def test_renewed_lease_keeps_scanning(world, clock):
    s = make_survey(world, clock)
    s.window_shown()
    simulate(s, clock, 60, renew_every=2)
    scans = [t for t, name in world.take() if name == "scan"]
    assert scans == [0, 10, 20, 30, 40, 50, 60]


def test_scan_interval_is_never_below_5_s(world, clock):
    s = make_survey(world, clock, scan_interval_s=1)
    assert s.scan_interval_s == 5.0
    s.window_shown()
    simulate(s, clock, 21, renew_every=1)
    scans = [t for t, name in world.take() if name == "scan"]
    assert scans == [0, 5, 10, 15, 20]


def test_scan_now_is_rate_limited_and_renews_the_lease(world, clock):
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()
    world.take()
    clock.advance(1)
    assert s.scan_now() == {"ok": True, "error": None}
    assert s.survey()["active"] is True, "scan_now counts as a lease renewal"
    assert s.scan_now() == {"ok": False, "error": wifi_survey.SCAN_TOO_SOON_TEXT}, "still pending"
    s.tick()
    assert world.take() == [(1, "read"), (1, "scan")], "an immediate read, then the scan"
    clock.advance(3)
    assert s.scan_now()["ok"] is False, "3 s after the last scan"
    clock.advance(2)
    assert s.scan_now()["ok"] is True, "5 s after it"
    s.tick()
    assert [name for _, name in world.take()] == ["read", "scan"]


def test_scan_now_during_a_pass_does_not_spin(world, clock, monkeypatch):
    s = make_survey(world, clock)
    s.window_shown()
    s.survey({"active": True})
    s.tick()
    world.take()
    clock.advance(10)                                         # the next automatic scan is due
    armed = [True]
    real_scan = FakeApi.scan

    def scan_and_click(api, ref):
        real_scan(api, ref)
        if armed:
            armed.clear()
            assert s.scan_now()["ok"] is True                 # "Scan now" clicked while that scan runs

    monkeypatch.setattr(FakeApi, "scan", scan_and_click)
    simulate(s, clock, 6)
    assert world.take() == [(10, "read"), (10, "scan"), (14, "read"), (15, "scan")], \
        "the request waits for the 5 s gap; no read storm meanwhile"


def test_scan_now_just_after_an_automatic_scan_is_accepted_and_waits_for_the_gap(world, clock):
    s = make_survey(world, clock)
    s.window_shown()
    s.survey({"active": True})
    simulate(s, clock, 12)
    assert [e for e in world.take() if e[0] >= 10] == [(10, "scan")]
    assert s.scan_now() == {"ok": True, "error": None}, "2 s after an automatic scan: taken, not refused"
    assert s.scan_now()["ok"] is False, "but still one request per 5 s"
    simulate(s, clock, 14)
    assert world.take() == [(12, "read"), (14, "read"), (15, "scan"), (19, "read"), (24, "read"), (25, "scan")], \
        "an immediate read, the scan 5 s after the automatic one, then the normal 10 s cadence from there"
    clock.advance(1)                                          # 27 s: 15 s after the request, 2 s after a scan
    assert s.scan_now()["ok"] is True
    s.tick()
    assert world.take() == [(27, "read")], "no WlanScan within 5 s of the last one"


def test_location_denied_retries_once_a_minute_or_on_scan_now(world, clock):
    world.read_error = world.scan_error = wifi_survey.ERROR_ACCESS_DENIED
    s = make_survey(world, clock)
    s.window_shown()
    s.survey({"active": True})
    s.tick()
    view = s.survey()
    assert (view["state"], view["error"], view["available"]) == ("location_denied", wifi_survey.LOCATION_DENIED_TEXT, True)
    assert "location" in view["error"].lower()
    assert world.take() == [(0, "read"), (0, "scan")]
    simulate(s, clock, 59, renew_every=2)
    assert world.take() == [], "no WLAN call for a minute, lease or not"
    simulate(s, clock, 2, renew_every=2)
    assert world.take() == [(60, "read"), (60, "scan")]
    clock.advance(10)
    world.read_error = world.scan_error = None                  # the user allowed location access
    assert s.scan_now()["ok"] is True
    s.tick()
    assert world.take() == [(71, "read"), (71, "scan")], "scan_now retries at once"
    assert s.survey()["state"] == "ok" and s.survey()["error"] is None


def test_no_adapter_and_wlan_service_stopped(world, clock):
    world.open_error = wifi_survey.ERROR_SERVICE_NOT_ACTIVE
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()
    view = s.survey()
    assert (view["state"], view["available"], view["error"], view["interfaces"]) == \
        ("no_adapter", False, wifi_survey.NO_ADAPTER_TEXT, [])
    world.open_error = None
    world.interfaces = []
    clock.advance(60)
    s.tick()
    assert s.survey()["state"] == "no_adapter"
    world.interfaces = [{"guid": GUID_A, "description": "Synthetic USB Wi-Fi", "state": "disconnected", "ref": "if0"}]
    clock.advance(60)
    s.tick()
    view = s.survey()
    assert view["state"] == "ok" and view["available"] is True and view["interfaces"][0]["description"] == "Synthetic USB Wi-Fi"


def test_other_open_failure_is_an_error_state(world, clock):
    world.open_error = 1722
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()
    view = s.survey()
    assert view["state"] == "error" and "1722" in view["error"] and world.events == []


def test_radio_off_makes_no_list_or_scan_calls(world, clock):
    world.radio = False
    s = make_survey(world, clock)
    s.window_shown()
    simulate(s, clock, 30, renew_every=5)
    assert world.take() == []
    view = s.survey()
    assert (view["state"], view["error"], view["available"]) == ("radio_off", wifi_survey.RADIO_OFF_TEXT, True)
    world.radio = None                                          # unknown radio state: try anyway
    simulate(s, clock, 6, renew_every=5)
    assert world.take() and s.survey()["state"] == "ok"


def test_readings_history_and_contract_shape(world, clock):
    start = clock.wall
    world.connection = {"ssid": b"Synthetic Lab", "bssid": BSSID_A, "rx_kbps": 433300, "tx_kbps": 390000}
    world.interfaces[0]["state"] = "connected"
    world.entries = [ap_entry(BSSID_A, -52, start - 1), ap_entry(BSSID_B, -70, start - 300, freq=2437, name="")]
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()
    view = s.survey()
    assert set(view) == {"available", "enabled", "state", "error", "started_ts", "last_read_ts", "last_scan_ts", "active",
                         "scan_interval_s", "passive_interval_s", "interfaces", "aps", "history", "link_history"}
    assert view["interfaces"] == [{"guid": GUID_A, "description": "Synthetic Wi-Fi", "state": "connected",
                                   "connected_bssid": TEXT_A, "connected_ssid": "Synthetic Lab", "rx_rate_mbps": 433.3, "tx_rate_mbps": 390.0}]
    assert view["link_history"] == [[start, 390.0]], "the transmit rate, stamped when the read pass ended"
    a, b = view["aps"]
    assert set(a) == {"bssid", "ssid", "hidden", "rssi", "quality", "band", "channel", "center_channel", "width_mhz",
                      "freq_mhz", "spans", "phy", "phys", "generation", "security", "beacon_ms", "max_rate_mbps", "oui",
                      "locally_administered", "base_oui", "connected", "first_seen", "last_seen", "seen_count", "stale"}
    assert (a["bssid"], a["ssid"], a["rssi"], a["connected"], a["stale"], a["seen_count"]) == (TEXT_A, "Synthetic Lab", -52, True, False, 1)
    assert a["last_seen"] == pytest.approx(start - 1, abs=1e-3) and a["width_mhz"] == 80 and a["quality"] == 80
    assert (b["hidden"], b["band"], b["stale"], b["connected"]) == (True, BAND_24, True, False), "its beacon is 5 min old"
    assert view["history"] == {TEXT_A: [[start, -52]], "02:11:22:33:44:02": []}, \
        "a beacon from before the session adds no point; one just before it lands on the start"
    json.dumps(view, allow_nan=False)

    # 7 s later: a fresh beacon for A, a cached (repeated) value for B
    clock.advance(7)
    world.entries = [ap_entry(BSSID_A, -49, clock.wall - 0.5), ap_entry(BSSID_B, -70, start - 300, freq=2437, name="")]
    simulate(s, clock, 61)
    view = s.survey()
    a = next(x for x in view["aps"] if x["bssid"] == TEXT_A)
    b = next(x for x in view["aps"] if x["bssid"] != TEXT_A)
    assert (a["rssi"], a["seen_count"]) == (-49, 2) and b["seen_count"] == 1, "repeated cached values are not readings"
    assert view["history"][TEXT_A] == [[start, -52], [round(start + 6.5, 1), -49]]
    assert view["history"]["02:11:22:33:44:02"] == []
    assert view["link_history"] == [[start, 390.0], [start + 60.0, 390.0]], "one point per read pass, the passive one a minute later"


def test_history_coalesces_to_one_point_per_5_s_and_is_bounded(world, clock):
    start = clock.wall
    s = make_survey(world, clock, max_points=4)
    s.window_shown()
    for offset, rssi in ((0, -60), (2, -58), (6, -57), (11, -56), (16, -55), (21, -54)):
        clock.wall = start + offset
        clock.mono = 1000.0 + offset
        world.entries = [ap_entry(BSSID_A, rssi, start + offset)]
        s._last_read_mono = None                          # read now
        s.tick()
    hist = s.survey()["history"][TEXT_A]
    assert hist == [[start + 6, -57], [start + 11, -56], [start + 16, -55], [start + 21, -54]]
    clock.advance(1)
    assert [p[1] for p in s.survey({"history_s": 11})["history"][TEXT_A]] == [-56, -55, -54], "history_s window"
    assert s.survey({"history_s": 0})["history"][TEXT_A] == []
    for junk in (None, -5, "60", True, float("nan"), float("inf")):
        assert len(s.survey({"history_s": junk})["history"][TEXT_A]) == 4, junk


def test_a_late_reading_is_never_stamped_before_the_previous_read(world, clock):
    """A scan's results can reach the cached list after a read that ran while the scan was still going. Such
    a reading lands on the previous read's time (its rssi and last_seen keep the beacon's own), so a caller
    that saw last_read_ts gets it by asking for the readings since then."""
    start = clock.wall
    s = make_survey(world, clock)
    s.window_shown()
    clock.advance(10)
    world.entries = [ap_entry(BSSID_A, -50, start + 9)]
    s.tick()                                                  # read 1 at +10
    assert s.survey()["last_read_ts"] == start + 10
    clock.advance(5)
    world.entries = [ap_entry(BSSID_A, -50, start + 9), ap_entry(BSSID_B, -61, start + 7), ap_entry(BSSID_C, -70, start + 12)]
    s._last_read_mono = None
    s.tick()                                                  # read 2 at +15: B's beacon predates read 1
    view = s.survey({"history_s": math.ceil(clock.wall - (start + 10) + 0.5)})
    assert view["history"] == {TEXT_A: [[start + 9, -50]], "02:11:22:33:44:02": [[start + 10, -61]],
                               "02:11:22:33:44:03": [[start + 12, -70]]}
    b = next(a for a in view["aps"] if a["bssid"] == "02:11:22:33:44:02")
    assert (b["rssi"], b["last_seen"]) == (-61, pytest.approx(start + 7, abs=1e-3))


def test_incremental_history_fetches_like_the_page_never_miss_a_reading(world, clock):
    """The WiFi page asks for history_s = now - (the last_read_ts it saw) + 15 s and merges. With beacons
    delivered up to 40 s late, every reading the store keeps must still reach it."""
    rng = random.Random(20260911)
    bssids = [bytes([2, 0, 0, 0, 1, i]) for i in range(6)]
    beacons = {b: clock.wall - 200.0 for b in bssids}
    s = make_survey(world, clock)
    s.window_shown()
    cache: Dict[str, set] = {}
    seen: List[Optional[float]] = [None]

    def page_poll() -> None:
        want = None if seen[0] is None else math.ceil(clock.wall - seen[0] + 15)
        view = s.survey({"active": False, "history_s": want})
        for key, pts in view["history"].items():
            cache.setdefault(key, set()).update(tuple(p) for p in pts)
        seen[0] = view["last_read_ts"]

    for _ in range(150):
        for b in bssids:
            if rng.random() < 0.6:                            # a fresh beacon, often delivered late
                beacons[b] = max(beacons[b] + 0.1, clock.wall - rng.uniform(0, 40))
        world.entries = [ap_entry(b, rng.randint(-90, -40), beacons[b]) for b in bssids]
        s._last_read_mono = None
        s.tick()
        for _ in range(rng.randint(0, 3)):
            page_poll()
            clock.advance(rng.uniform(0.5, 2.5))
        clock.advance(rng.uniform(0.5, 6))
    page_poll()
    full = s.survey({"history_s": None})["history"]
    assert sum(len(v) for v in full.values()) > 150
    for key, pts in full.items():
        missing = [p for p in pts if tuple(p) not in cache.get(key, set())]
        assert not missing, (key, missing[:3])


def test_series_ring_keeps_order_after_wrapping():
    series = wifi_survey._Series()
    for i in range(23):
        series.add(i * 100, -40 - i, 50, 8)
    assert len(series) == 8
    points = series.points(1000.0, None)
    assert [p[1] for p in points] == [-40 - i for i in range(15, 23)]
    assert [p[0] for p in points] == [1000.0 + i * 10 for i in range(15, 23)]
    series.add(5, -1, 50, 8)                              # older than the newest: ignored
    assert series.points(1000.0, None)[-1] == [1220.0, -62]


def test_series_window_on_a_wrapped_ring_matches_a_plain_filter():
    """points() searches the ring's two sorted runs in place; every cut-off must agree with filtering a copy."""
    for count in (0, 1, 5, 8, 9, 13, 16, 23):
        series = wifi_survey._Series()
        for i in range(count):
            series.add(i * 100, -40 - (i % 50), 50, 8)
        everything = series.points(1000.0, None)
        assert [p[0] for p in everything] == sorted(p[0] for p in everything), count
        for min_ds in (None, -5, 0, 1, 99.5, 100, 101, 750, 1500, 2150, 2200, 2201, 10_000):
            expected = [p for p in everything if min_ds is None or min_ds <= 0 or (p[0] - 1000.0) * 10 >= min_ds - 1e-6]
            assert series.points(1000.0, min_ds) == expected, (count, min_ds, series.head)


def test_stale_marking(world, clock):
    start = clock.wall
    world.entries = [ap_entry(BSSID_A, -50, start), ap_entry(BSSID_B, -60, start)]
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()
    assert [a["stale"] for a in s.survey()["aps"]] == [False, False]
    clock.advance(60)
    world.entries = [ap_entry(BSSID_A, -50, clock.wall)]         # B is gone
    s.tick()
    stale = {a["bssid"]: a["stale"] for a in s.survey()["aps"]}
    assert stale == {TEXT_A: False, "02:11:22:33:44:02": True}, "not in the latest read"
    clock.advance(60)
    world.entries = [ap_entry(BSSID_A, -50, start + 60)]          # still listed, but the same old beacon
    s.tick()
    assert s.survey()["aps"][0]["stale"] is False, "120 s is the limit"
    clock.advance(61)
    s.tick()
    assert all(a["stale"] for a in s.survey()["aps"]), "last beacon older than 120 s"


def test_eviction_keeps_the_most_recently_seen(world, clock):
    s = make_survey(world, clock, max_aps=3)
    s.window_shown()
    bssids = [bytes([2, 0, 0, 0, 0, i]) for i in range(1, 6)]
    for i, bssid in enumerate(bssids):
        world.entries = [ap_entry(bssid, -50, clock.wall)] + ([ap_entry(bssids[0], -50, clock.wall)] if i == 3 else [])
        s._last_read_mono = None
        s.tick()
        clock.advance(10)
    kept = sorted(a["bssid"] for a in s.survey()["aps"])
    assert kept == ["02:00:00:00:00:01", "02:00:00:00:00:04", "02:00:00:00:00:05"], "the first one was seen again"
    assert set(s.survey()["history"]) == set(kept)


def test_same_bssid_through_two_adapters_is_one_ap(world, clock):
    world.interfaces.append({"guid": GUID_B, "description": "Synthetic USB Wi-Fi", "state": "disconnected", "ref": "if1"})
    world.entries = [ap_entry(BSSID_A, -50, clock.wall)]
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()
    view = s.survey()
    assert len(view["aps"]) == 1 and view["aps"][0]["seen_count"] == 1 and len(view["interfaces"]) == 2


def test_unchanged_duplicate_copies_are_one_reading_across_reads(world, clock):
    """Two cached copies of one BSSID (two adapters, or listed twice) that never change: one reading in all,
    however many reads repeat them; a newer beacon on either copy is the next reading."""
    start = clock.wall
    world.interfaces.append({"guid": GUID_B, "description": "Synthetic USB Wi-Fi", "state": "disconnected", "ref": "if1"})
    older = dict(ap_entry(BSSID_A, -61, start - 2), timestamp=111)
    newer = dict(ap_entry(BSSID_A, -55, start - 1), timestamp=222)
    world.entries = [older, newer]
    s = make_survey(world, clock)
    s.window_shown()
    for _ in range(10):
        s._last_read_mono = None
        s.tick()
        clock.advance(10)
    view = s.survey()
    ap = view["aps"][0]
    assert (ap["seen_count"], ap["rssi"]) == (1, -55), "the copy Windows received last, counted once"
    assert view["history"][TEXT_A] == [[start, -55]], "no point per read from repeated cached values"
    world.entries = [dict(ap_entry(BSSID_A, -48, clock.wall - 1), timestamp=333), newer]
    s._last_read_mono = None
    s.tick()
    view = s.survey()
    assert (view["aps"][0]["seen_count"], view["aps"][0]["rssi"]) == (2, -48)
    assert [p[1] for p in view["history"][TEXT_A]] == [-55, -48]
    world.entries = [dict(ap_entry(BSSID_A, -50, 0), host_timestamp=0, timestamp=0, rssi=-50),
                     dict(ap_entry(BSSID_A, -70, 0), host_timestamp=0, timestamp=0, rssi=-70)]
    for _ in range(3):
        clock.advance(10)
        s._last_read_mono = None
        s.tick()
    assert s.survey()["aps"][0]["seen_count"] == 3, "no timestamps at all: the first copy, compared by its signal"


def test_connected_network_stays_named_through_scan_only_passes(world, clock):
    world.interfaces[0]["state"] = "connected"
    world.connection = {"ssid": b"Synthetic Lab", "bssid": BSSID_A}
    world.entries = [ap_entry(BSSID_A, -50, clock.wall)]
    s = make_survey(world, clock)
    s.window_shown()
    s.survey({"active": True})
    seen = []
    for _ in range(40):                       # reads at 0, 4, 9, 14 ..., scans alone at 10, 20, 30 ...
        simulate(s, clock, 1, renew_every=1)
        view = s.survey()
        seen.append((view["interfaces"][0]["connected_ssid"], view["interfaces"][0]["connected_bssid"], view["aps"][0]["connected"]))
    assert set(seen) == {("Synthetic Lab", TEXT_A, True)}
    assert any(name == "scan" for _, name in world.take()), "scan-only passes did run"
    # the adapter drops the association just before a scan-only pass (the read at 49, the scan alone at 50)
    simulate(s, clock, 9.5, renew_every=1)
    assert world.take()[-1] == (49, "read")
    world.interfaces[0]["state"] = "disconnected"
    world.connection = None
    simulate(s, clock, 1, renew_every=1)
    assert world.take() == [(50, "scan")]
    view = s.survey()
    assert (view["interfaces"][0]["connected_ssid"], view["aps"][0]["connected"]) == (None, False)


def test_a_failed_connection_query_keeps_the_last_association(world, clock, monkeypatch):
    start = clock.wall
    world.interfaces[0]["state"] = "connected"
    world.connection = {"ssid": b"Synthetic Lab", "bssid": BSSID_A, "rx_kbps": 390000, "tx_kbps": 390000}
    world.entries = [ap_entry(BSSID_A, -50, clock.wall)]
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()

    def flaky(api, ref):
        raise OSError(87, "fake: the driver refused")

    monkeypatch.setattr(FakeApi, "current_connection", flaky)
    clock.advance(60)
    s.tick()
    view = s.survey()
    assert view["interfaces"][0]["connected_ssid"] == "Synthetic Lab" and view["aps"][0]["connected"] is True
    assert (view["interfaces"][0]["tx_rate_mbps"], view["interfaces"][0]["rx_rate_mbps"]) == (390.0, 390.0), "carried with the association"
    assert view["link_history"] == [[start, 390.0]], "a read that could not ask for the association adds no link speed"


@pytest.mark.parametrize("how", ["radio off", "adapter gone", "location denied"])
def test_connected_mark_does_not_outlive_the_association(world, clock, how):
    start = clock.wall
    world.interfaces[0]["state"] = "connected"
    world.connection = {"ssid": b"Synthetic Lab", "bssid": BSSID_A, "rx_kbps": 390000, "tx_kbps": 390000}
    world.entries = [ap_entry(BSSID_A, -50, clock.wall)]
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()
    assert s.survey()["aps"][0]["connected"] is True
    if how == "radio off":
        world.radio = False
        world.interfaces[0]["state"] = "disconnected"
    elif how == "adapter gone":
        world.interfaces = []
    else:
        world.read_error = world.scan_error = wifi_survey.ERROR_ACCESS_DENIED
    clock.advance(60)
    s.tick()
    view = s.survey()
    assert view["state"] == {"radio off": "radio_off", "adapter gone": "no_adapter", "location denied": "location_denied"}[how]
    assert view["aps"][0]["connected"] is False
    assert all(i["connected_bssid"] is None for i in view["interfaces"])
    # the link is down once nothing is associated (radio off, adapter gone); a refused query is unknown and adds no point
    assert view["link_history"] == ([[start, 390.0]] if how == "location denied" else [[start, 390.0], [start + 60.0, 0.0]])


def test_link_speed_follows_the_association(world, clock):
    """The first connected interface's transmit rate, once per read pass (one point per 5 s bucket), in the history_s window
    like the signal history; 0 once nothing is associated; a garbled rate is no reading; clear() starts it again."""
    start = clock.wall
    world.interfaces[0]["state"] = "connected"
    world.connection = {"ssid": b"Synthetic Lab", "bssid": BSSID_A, "rx_kbps": 866700, "tx_kbps": 780000}
    world.entries = [ap_entry(BSSID_A, -50, clock.wall)]
    s = make_survey(world, clock)
    s.window_shown()
    s.survey({"active": True})
    simulate(s, clock, 12, renew_every=5)                      # reads at 0, 4 and 9; the scan alone at 10 asks nothing
    view = s.survey()
    assert (view["interfaces"][0]["tx_rate_mbps"], view["interfaces"][0]["rx_rate_mbps"]) == (780.0, 866.7)
    assert view["link_history"] == [[start + 4.0, 780.0], [start + 9.0, 780.0]], "0 s and 4 s share a 5 s bucket: the later stays"
    world.connection = dict(world.connection, tx_kbps=6500, rx_kbps=0)
    simulate(s, clock, 4, renew_every=5)                       # the read at 14
    view = s.survey()
    assert (view["interfaces"][0]["tx_rate_mbps"], view["interfaces"][0]["rx_rate_mbps"]) == (6.5, None)
    assert view["link_history"][-1] == [start + 14.0, 6.5]
    world.interfaces[0]["state"] = "disconnected"
    world.connection = None
    simulate(s, clock, 10, renew_every=5)                      # reads at 19 and 24
    view = s.survey({"active": True, "history_s": 6})
    assert view["interfaces"][0]["tx_rate_mbps"] is None
    assert view["link_history"] == [[start + 24.0, 0.0]], "not associated: 0, and only the readings inside history_s"
    assert [p[1] for p in s.survey()["link_history"]] == [780.0, 780.0, 6.5, 0.0, 0.0]
    world.interfaces[0]["state"] = "connected"
    world.connection = {"ssid": b"Synthetic Lab", "bssid": BSSID_A, "rx_kbps": -1, "tx_kbps": 2 ** 40}
    simulate(s, clock, 5, renew_every=5)
    view = s.survey()
    assert (view["interfaces"][0]["tx_rate_mbps"], view["interfaces"][0]["rx_rate_mbps"]) == (None, None)
    assert [p[1] for p in view["link_history"]] == [780.0, 780.0, 6.5, 0.0, 0.0], "a garbled rate adds nothing"
    json.dumps(view, allow_nan=False)
    s.clear()
    assert s.survey()["link_history"] == []


def test_an_interface_unplugged_during_a_pass_is_no_adapter(world, clock):
    world.read_error = wifi_survey.ERROR_NOT_FOUND                # WlanGetNetworkBssList after WlanEnumInterfaces
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()
    view = s.survey()
    assert (view["state"], view["available"], view["interfaces"]) == ("no_adapter", False, [])
    # two adapters, the USB one pulled between the enumeration and the list call: the other carries on
    world.read_error = None
    world.interfaces.append({"guid": GUID_B, "description": "Synthetic USB Wi-Fi", "state": "disconnected", "ref": "if1"})
    world.read_errors = {"if1": wifi_survey.ERROR_NOT_FOUND}
    world.entries = [ap_entry(BSSID_A, -50, clock.wall)]
    clock.advance(60)
    s.tick()
    view = s.survey()
    assert view["state"] == "ok" and [i["guid"] for i in view["interfaces"]] == [GUID_A] and len(view["aps"]) == 1
    # a scan-only pass finds the only interface gone
    world.read_errors = {}
    world.interfaces = world.interfaces[:1]
    s.survey({"active": True})
    simulate(s, clock, 9, renew_every=2)
    world.take()
    world.scan_errors = {"if0": wifi_survey.ERROR_NOT_FOUND}
    world.read_errors = {"if0": wifi_survey.ERROR_NOT_FOUND}
    simulate(s, clock, 2, renew_every=2)
    assert s.survey()["state"] == "no_adapter"


def test_radio_switched_off_seen_only_from_the_list_call_is_radio_off(world, clock):
    world.radio = None                                             # the radio state query gave no answer
    world.read_error = wifi_survey.ERROR_NDIS_DOT11_POWER_STATE_INVALID
    world.scan_error = wifi_survey.ERROR_NDIS_DOT11_POWER_STATE_INVALID
    s = make_survey(world, clock)
    s.window_shown()
    s.survey({"active": True})
    s.tick()
    view = s.survey()
    assert (view["state"], view["error"], view["available"]) == ("radio_off", wifi_survey.RADIO_OFF_TEXT, True)
    assert wifi_survey.ERROR_NDIS_DOT11_POWER_STATE_INVALID == 2150899714
    assert [name for _, name in world.take()] == ["read"], "no scan on a radio the list call found switched off"


@pytest.mark.parametrize("code", [wifi_survey.ERROR_SERVICE_NOT_ACTIVE, wifi_survey.ERROR_SERVICE_DOES_NOT_EXIST,
                                  wifi_survey.ERROR_MOD_NOT_FOUND])
def test_wlan_service_or_library_missing_is_no_adapter(world, clock, code):
    world.open_error = code
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()
    assert (s.survey()["state"], s.survey()["error"]) == ("no_adapter", wifi_survey.NO_ADAPTER_TEXT)


def test_missing_wlanapi_dll_is_reported_with_a_code(monkeypatch):
    def no_dll():
        raise FileNotFoundError("Could not find module 'wlanapi' (or one of its dependencies)")

    monkeypatch.setattr(wifi_survey, "_dll", no_dll)
    with pytest.raises(OSError) as info:
        wifi_survey.WlanSurveyApi().open()
    assert info.value.errno == wifi_survey.ERROR_MOD_NOT_FOUND and wifi_survey._winerror(info.value) == 126
    clock = FakeClock()
    s = wifi_survey.WifiSurvey(clock=clock.time, monotonic=clock.monotonic, threaded=False)   # the real API class
    s.window_shown()
    s.tick()
    assert s.survey()["state"] == "no_adapter"


def test_eviction_drops_the_oldest_beacon_not_the_oldest_entry(world, clock):
    s = make_survey(world, clock, max_aps=2)
    s.window_shown()
    world.entries = [ap_entry(BSSID_A, -50, clock.wall), ap_entry(BSSID_B, -60, clock.wall - 60)]
    s.tick()
    clock.advance(10)
    # C shows up for the first time with a beacon from 5 min ago; B is still cached, 70 s old
    world.entries = [ap_entry(BSSID_A, -50, clock.wall), ap_entry(BSSID_B, -60, clock.wall - 70),
                     ap_entry(BSSID_C, -70, clock.wall - 300)]
    s._last_read_mono = None
    s.tick()
    assert sorted(a["bssid"] for a in s.survey()["aps"]) == [TEXT_A, "02:11:22:33:44:02"]


def test_a_wall_clock_step_back_moves_the_session_with_it(world, clock):
    start = clock.wall
    world.entries = [ap_entry(BSSID_A, -40, start)]
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()
    clock.advance(10)
    world.entries = [ap_entry(BSSID_A, -41, clock.wall)]
    s._last_read_mono = None
    s.tick()
    clock.advance(10)
    clock.wall -= 3600                                            # an NTP correction: one hour back
    world.entries = [ap_entry(BSSID_A, -42, clock.wall)]
    s._last_read_mono = None
    s.tick()
    view = s.survey()
    assert view["started_ts"] == start - 3600 and view["last_read_ts"] == clock.wall
    assert view["history"][TEXT_A] == [[start - 3600, -40], [start - 3600 + 10, -41], [clock.wall, -42]], \
        "the new reading is kept, in order, and the older ones moved back with the clock"
    ap = view["aps"][0]
    assert ap["last_seen"] == pytest.approx(clock.wall, abs=1e-3) and ap["stale"] is False
    clock.advance(121)
    s.tick()
    assert s.survey()["aps"][0]["stale"] is True, "beacon-age staleness works right after the step"
    # a forward jump (what a sleep looks like) moves nothing
    before = s.survey()["started_ts"]
    clock.wall += 7200
    s.survey()
    assert s.survey()["started_ts"] == before


def test_history_points_thins_only_the_readings_before_the_full_window():
    ts = array("I", range(0, 20000, 10))                         # 2000 readings, one per second
    rssi = array("b", [-60 + (i % 7) - (30 if i == 777 else 0) + (25 if i == 1111 else 0) for i in range(2000)])
    everything = wifi_survey.history_points(1000.0, ts, rssi)
    assert len(everything) == 2000 and everything[0] == [1000.0, -60] and everything[-1][0] == 2999.0
    thin = wifi_survey.history_points(1000.0, ts, rssi, full_from_ds=15000, buckets=50)
    older, recent = [p for p in thin if p[0] < 2500.0], [p for p in thin if p[0] >= 2500.0]
    assert recent == everything[1500:], "the full window is returned as stored"
    assert 50 <= len(older) <= 100 and [p[0] for p in older] == sorted(p[0] for p in older)
    assert set(map(tuple, older)) <= set(map(tuple, everything[:1500])), "thinning only picks real readings"
    assert [1777.0, -90 + (777 % 7)] in older and [2111.0, -35 + (1111 % 7)] in older, "a dip and a peak survive"
    few = wifi_survey.history_points(1000.0, ts[:80], rssi[:80], full_from_ds=15000, buckets=50)
    assert few == everything[:80], "no thinning while the older readings are few"
    assert wifi_survey.history_points(1000.0, array("I"), array("b"), full_from_ds=5) == []


def test_a_survey_call_bounds_its_history_and_builds_it_outside_the_lock(world, clock, monkeypatch):
    start = clock.wall
    s = make_survey(world, clock)
    s.window_shown()
    bssids = [bytes([2, 0, 0, 0, 3, i]) for i in range(3)]
    for k in range(4 * 720):                                     # 4 h at one fresh reading per 5 s
        world.entries = [ap_entry(b, -50 - (k + i) % 30, clock.wall) for i, b in enumerate(bssids)]
        s._last_read_mono = None
        s.tick()
        clock.advance(5)
    held_while_building = []
    real = wifi_survey.history_points

    def try_lock(probe: list) -> None:
        got = s._lock.acquire(blocking=False)
        probe.append(got)
        if got:
            s._lock.release()

    def spy(*args, **kwargs):
        probe: list = []
        t = threading.Thread(target=try_lock, args=(probe,))
        t.start()
        t.join()
        held_while_building.append(not probe[0])
        return real(*args, **kwargs)

    monkeypatch.setattr(wifi_survey, "history_points", spy)
    view = s.survey({"history_s": None})
    assert held_while_building and not any(held_while_building), "the scanner thread never waits for the lists"
    for b in bssids:
        pts = view["history"][wifi_ies.format_bssid(b)]
        recent = [p for p in pts if p[0] >= clock.wall - wifi_survey.HISTORY_FULL_S]
        assert len(recent) in (720, 721), "the last hour as stored"
        assert len(pts) - len(recent) <= 2 * wifi_survey.HISTORY_THIN_BUCKETS, "older readings thinned"
        assert pts[0][0] == start and [p[0] for p in pts] == sorted(p[0] for p in pts)
    hour = s.survey({"history_s": 3600})["history"]
    assert all(len(v) in (720, 721) for v in hour.values())
    assert s.survey({"history_s": 3600})["history"] == {k: [p for p in v if p[0] >= clock.wall - 3600] for k, v in view["history"].items()}


def test_unusable_entries_are_skipped(world, clock):
    world.entries = [entry(0, ssid_ie("Synthetic Lab"), bssid=BSSID_A, host_ts=filetime(clock.wall)),
                     dict(ap_entry(BSSID_B, -50, clock.wall), bssid=b"\x02"), "junk",
                     ap_entry(BSSID_C, -55, clock.wall)]
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()
    assert [a["bssid"] for a in s.survey()["aps"]] == ["02:11:22:33:44:03"]
    assert s._parse_errors == 3


def test_implausible_host_timestamp_falls_back_to_the_read_time(world, clock):
    world.entries = [dict(ap_entry(BSSID_A, -50, clock.wall), host_timestamp=12345, timestamp=0)]
    s = make_survey(world, clock)
    s.window_shown()
    clock.advance(3)
    s.tick()
    ap = s.survey()["aps"][0]
    assert ap["last_seen"] == clock.wall and ap["stale"] is False


def test_clear_forgets_everything_and_restarts_the_session(world, clock):
    world.entries = [ap_entry(BSSID_A, -50, clock.wall)]
    s = make_survey(world, clock)
    s.window_shown()
    s.tick()
    clock.advance(30)
    world.take()
    assert s.clear() == {"ok": True}
    view = s.survey()
    assert view["aps"] == [] and view["history"] == {} and view["started_ts"] == clock.wall
    s.tick()
    assert world.take() == [(30, "read")], "the list is read again right away"
    assert len(s.survey()["aps"]) == 1
    assert s.survey()["history"][TEXT_A] == [], "a beacon from before the clear adds no point"


def test_set_enabled_off_stops_every_wlan_call_and_persists(world, clock):
    saved = []
    world.entries = [ap_entry(BSSID_A, -50, clock.wall)]
    s = make_survey(world, clock, persist=saved.append)
    s.window_shown()
    s.survey({"active": True})
    s.tick()
    world.take()
    assert s.set_enabled(False) == {"ok": True, "enabled": False} and saved == [False]
    assert [a["bssid"] for a in s.survey()["aps"]] == [TEXT_A], "switching off keeps what was collected"
    closed = world.closed
    assert s.tick() == wifi_survey.IDLE_WAIT_S and world.closed == closed + 1, "the handle is closed"
    simulate(s, clock, 120, renew_every=5)
    assert world.take() == []
    view = s.survey({"active": True})
    assert (view["state"], view["enabled"], view["active"]) == ("disabled", False, False)
    assert s.scan_now()["ok"] is False
    assert s.set_enabled(True) == {"ok": True, "enabled": True} and saved == [False, True]
    s.tick()
    assert world.take() and s.survey()["state"] == "ok"


def test_set_enabled_on_starts_the_session_when_it_never_ran(world, clock):
    s = make_survey(world, clock, enabled=False)
    s.window_shown()
    assert not s.session_started
    s.set_enabled(True)
    assert s.session_started


def test_persist_failure_does_not_break_the_switch(world, clock):
    def boom(on):
        raise OSError("disk full")

    s = make_survey(world, clock, persist=boom)
    assert s.set_enabled(False) == {"ok": True, "enabled": False} and s.enabled is False


def test_tick_never_raises(world, clock, monkeypatch):
    world.read_error = RuntimeError("driver exploded")
    s = make_survey(world, clock)
    s.window_shown()
    assert s.tick() == 60.0, "a broken driver call is an error state on the normal cadence, not a retry storm"
    assert world.closed == 1, "the handle is closed so the next pass reopens it"
    view = s.survey()
    assert view["state"] == "error" and view["error"] == "Windows could not list nearby Wi-Fi networks."

    def bad_factory():
        raise RuntimeError("no api")

    s2 = wifi_survey.WifiSurvey(api_factory=bad_factory, clock=clock.time, monotonic=clock.monotonic, threaded=False)
    s2.window_shown()
    assert s2.tick() == 60.0 and s2.survey()["state"] == "error"
    world.read_error = 87                                     # ERROR_INVALID_PARAMETER from the list call
    s3 = make_survey(world, clock)
    s3.window_shown()
    s3.tick()
    assert s3.survey()["error"] == "Windows could not list nearby Wi-Fi networks (error 87)."
    world.read_error = None
    s4 = make_survey(world, clock)
    s4.window_shown()

    def bug(*args, **kwargs):
        raise KeyError("a bug in the store")

    monkeypatch.setattr(s4, "_ingest_locked", bug)
    assert s4.tick() == wifi_survey.RETRY_AFTER_ERROR_S, "even a bug in the store never kills the thread"


def test_visibility_check_failure_starts_nothing(world, clock):
    def boom():
        raise OSError("user32 gone")

    s = make_survey(world, clock)
    assert s.survey({}, visible=boom)["state"] == "starting" and not s.session_started


def test_the_scanner_thread_runs_and_stops(world):
    s = wifi_survey.WifiSurvey(api_factory=world.factory, threaded=True)
    s.window_shown()
    deadline = time.monotonic() + 5
    while not world.events and time.monotonic() < deadline:
        time.sleep(0.02)
    assert world.events and world.events[0][1] == "read"
    thread = s._thread
    assert thread is not None and thread.daemon and thread.name == "wifi-survey"
    s.stop(timeout=2.0)
    assert not thread.is_alive() and world.closed >= 1
    s.stop()                                                  # idempotent
    assert s.survey({"active": True})["active"] is False, "a stopped survey takes no lease"
    assert s.scan_now()["ok"] is False


def test_no_ssid_or_bssid_is_logged_above_debug(world, clock, caplog):
    import logging

    world.interfaces[0]["state"] = "connected"
    world.connection = {"ssid": b"Synthetic Secret Net", "bssid": BSSID_A}
    world.entries = [ap_entry(BSSID_A, -50, clock.wall, name="Synthetic Secret Net"), entry(0, bssid=BSSID_B)]
    with caplog.at_level(logging.DEBUG, logger="client"):
        s = make_survey(world, clock)
        s.window_shown()
        s.survey({"active": True})
        simulate(s, clock, 30, renew_every=5)
        s.clear()
        s.tick()
        world.read_error = wifi_survey.ERROR_ACCESS_DENIED
        clock.advance(10)
        s.scan_now()
        s.tick()
        world.read_error = RuntimeError("driver exploded")
        s.scan_now()
        clock.advance(10)
        s.scan_now()
        s.tick()
        s.set_enabled(False)
        s.tick()
    assert any(r.levelno >= logging.INFO for r in caplog.records), "state changes are logged"
    loud = " ".join(r.getMessage() + " " + (r.exc_text or "") for r in caplog.records if r.levelno > logging.DEBUG)
    for secret in ("Synthetic Secret Net", "02:11:22:33:44", "021122334401"):
        assert secret.lower() not in loud.lower()


def test_blank_view_has_the_contract_shape(world, clock):
    blank = wifi_survey.blank_view("error", "refused")
    assert set(blank) == set(make_survey(world, clock).survey())
    assert (blank["state"], blank["error"], blank["aps"], blank["history"]) == ("error", "refused", [], {})
