"""802.11 information elements -> what the Wi-Fi survey shows for one access point.

Pure Python, import-safe on any platform and free of Windows calls, so every rule here is
unit-tested with synthetic byte vectors. :mod:`client.wifi_survey` copies each
``WLAN_BSS_ENTRY`` (and the information elements behind it) out of the Wlan API's buffer
into a plain dict (:data:`ENTRY_KEYS`); :func:`describe_bss` turns that dict into the static
half of an AP row of the survey contract (the half that does not change from beacon to
beacon)::

    {"bssid", "ssid", "hidden", "band", "channel", "center_channel", "width_mhz", "freq_mhz",
     "spans", "phy", "phys", "generation", "security", "beacon_ms", "max_rate_mbps", "oui",
     "locally_administered", "base_oui"}

Nothing here raises. An element whose length runs past the end of the blob ends the walk
(:attr:`Elements.truncated`), an element that is too short for the field being read is
ignored, a channel indication that does not add up (a centre channel the primary channel
does not sit in, a segment that runs past the edge of its band, a width the band cannot
carry, a 5 GHz centre that is not a 40/80/160 MHz channel, a 6 GHz centre off the 6 GHz
channel raster) is dropped, and an entry that cannot be placed on a band at all comes back
as ``None``.

Band and channel
----------------
``ulChCenterFrequency`` (kHz) is the frequency the frame was received on. 2.4 GHz: channel
1-13 = 2407 + 5*ch MHz, channel 14 = 2484. 5 GHz = 5000 + 5*ch (4.9 GHz channels 182-199 =
4000 + 5*ch). 6 GHz (5925-7125 MHz) = 5950 + 5*ch on the 20 MHz raster (channels 1, 5, 9 ...
233), plus channel 2 = 5935 (20 MHz only); a 6 GHz frequency between two channels is placed
only by the AP's own HE 6 GHz Operation Information naming a channel within 25 MHz of it.
The band always comes from the frequency. The *primary channel* comes from the frequency
too, unless the AP's own elements name a channel of the same band within 25 MHz of it (the
DS Parameter Set or HT Operation primary channel in 2.4/5 GHz, the HE 6 GHz Operation
Information primary channel in 6 GHz): on 2.4 GHz a radio often hears a beacon of channel 6
while tuned to channel 5 or 7, and the element is the AP's own word.

Width, centre channel and spans
-------------------------------
Every indication for the band is collected and the widest valid one wins:

* HT Operation (61): secondary channel offset 1 (above) / 3 (below) with the STA Channel
  Width bit -> 40 MHz centred 2 channels up / down (on 2.4 GHz both 20 MHz halves must be
  channels 1-13).
* VHT Operation (192), also carried inside HE Operation when its bit 14 is set: channel
  width 0 = 20/40 (HT decides); 1 = 80/160/80+80 from CCFS0/CCFS1 (CCFS1 0 -> 80 on CCFS0;
  ``|CCFS1-CCFS0| == 8`` -> 160 centred on CCFS1; ``> 16`` -> 80+80, two spans); the deprecated
  2 (160 on CCFS0) and 3 (80+80).
* HE Operation (255/36): HE Operation Parameters bit 14 (VHT Operation Information present,
  3 bytes), bit 15 (Co-Hosted BSS, 1 byte), bit 17 (6 GHz Operation Information present:
  primary channel, control (width 0/1/2/3 = 20/40/80/160), CCFS0, CCFS1, minimum rate), which
  defines the width in 6 GHz (160: CCFS1 when ``|CCFS1-CCFS0| == 8``).
* EHT Operation (255/106): parameters bit 0 (EHT Operation Information present), 4 bytes of
  basic EHT-MCS, then control (width 0-4 = 20/40/80/160/320), CCFS0, CCFS1 (CCFS1 is the
  160/320 MHz centre).

Widths are capped per band (2.4 GHz 40, 5 GHz 160, 6 GHz 320) and every segment must lie
inside its band (2400-2495, 4900-5925, 5925-7125 MHz); 5 GHz 40/80/160 MHz centres must be
channels of the IEEE 802.11 global operating classes (40: 38, 46 ... 175; 80: 42, 58, 106,
122, 138, 155, 171; 160: 50, 114, 163). ``center_channel`` is the
centre of the whole bonded channel (for 80+80, the centre of the segment holding the primary
channel); ``width_mhz`` counts 80+80 as 160; ``spans`` lists ``[low_mhz, high_mhz]`` for each
segment (a 20 MHz 2.4 GHz channel is drawn 20 MHz wide, also for 802.11b).

PHY, generation, rate
---------------------
``phys`` (oldest first): 2.4 GHz ``b`` when every supported rate is a DSSS/CCK rate (1, 2,
5.5, 11 Mb/s), else ``g``; 5 GHz ``a``; ``n`` with HT Capabilities (45), ``ac`` with VHT
Capabilities (191) in 5 GHz only (VHT is a 5 GHz PHY: a 2.4 GHz AP that adds the element for
its proprietary 256-QAM mode stays ``n``), ``ax`` with HE Capabilities (255/35) and always in
6 GHz, ``be`` with EHT Capabilities (255/108). ``dot11BssPhyType`` fills in a newer PHY the
elements do not show (again ``ac`` only in 5 GHz).
``generation``: be -> Wi-Fi 7, ax -> Wi-Fi 6 (Wi-Fi 6E in 6 GHz), ac -> Wi-Fi 5, n -> Wi-Fi 4.
``max_rate_mbps`` is an estimate: the highest legacy rate (rate elements + ``WLAN_RATE_SET``),
raised to the PHY rate of the newest capability element that applies to the band at the
operating width (spatial streams and top MCS from its MCS map; short guard interval for
HT/VHT when advertised, 0.8 s for HE/EHT).

Security
--------
RSN (48) AKM suites of 00-0F-AC: the 802.1X family (1, 3, 5, 11, 14-17, 22, 23) ->
``WPA3-Enterprise`` when management frame protection is required (MFPR: no WPA2-only client
can join, which is how the WPA3 specification tells WPA3-Enterprise only mode from transition
mode), else ``WPA2-Enterprise``; only 12/13 (Suite B 192-bit, SHA-384) ->
``WPA3-Enterprise 192-bit``; 2/4/6/19/20 PSK -> ``WPA2-Personal``; 8/9/24/25 SAE ->
``WPA3-Personal``; PSK + SAE -> ``WPA2/WPA3-Personal``; 18 -> ``OWE``. A missing AKM list means
the default 802.1X suite; an empty or truncated list, only vendor AKMs, or a mix of families
(PSK with 802.1X, OWE with PSK ...) -> ``Unknown``. Without RSN: the vendor WPA element (221,
00-50-F2 type 1) -> ``WPA-Personal`` / ``WPA-Enterprise``; the privacy capability bit alone ->
``WEP``; otherwise ``Open``.

SSID
----
The SSID element wins over ``DOT11_SSID`` only when the latter is empty. A length of 0 or
all-zero bytes is a hidden network (``ssid ""``, ``hidden True``). Text is UTF-8; bytes that
are not valid UTF-8 are read as Windows-1252 so a legacy name stays readable, and control
characters become U+FFFD.
"""
from __future__ import annotations

import logging
import struct
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

__all__ = [
    "Elements", "parse_elements", "describe_bss", "freq_to_channel", "channel_to_freq", "channel_plan",
    "spans_for", "decode_ssid", "format_bssid", "oui_info", "security_label", "phy_list", "generation_for",
    "estimate_max_rate", "self_test", "ENTRY_KEYS", "BAND_24", "BAND_5", "BAND_6",
]

BAND_24 = "2.4"
BAND_5 = "5"
BAND_6 = "6"

#: Keys of the plain dict :mod:`client.wifi_survey` builds from one ``WLAN_BSS_ENTRY``.
ENTRY_KEYS = ("ssid", "bssid", "phy_type", "rssi", "link_quality", "in_reg_domain", "beacon_period",
              "timestamp", "host_timestamp", "capability", "freq_khz", "rates", "ies")

# -- element ids ------------------------------------------------------------------------------
EID_SSID = 0
EID_SUPPORTED_RATES = 1
EID_DS_PARAMS = 3
EID_HT_CAPABILITIES = 45
EID_RSN = 48
EID_EXT_SUPPORTED_RATES = 50
EID_HT_OPERATION = 61
EID_VHT_CAPABILITIES = 191
EID_VHT_OPERATION = 192
EID_VENDOR = 221
EID_EXTENSION = 255
EXT_HE_CAPABILITIES = 35
EXT_HE_OPERATION = 36
EXT_EHT_OPERATION = 106
EXT_EHT_CAPABILITIES = 108

#: ``usCapabilityInformation`` privacy bit (WEP when no RSN/WPA element says more).
CAP_PRIVACY = 0x0010
#: RSN capabilities: management frame protection required.
RSN_CAP_MFPR = 0x0040

HE_OP_VHT_INFO_PRESENT = 1 << 14
HE_OP_CO_HOSTED_BSS = 1 << 15
HE_OP_6GHZ_INFO_PRESENT = 1 << 17
EHT_OP_INFO_PRESENT = 0x01

#: A channel named by the AP's own elements replaces the one derived from the receive frequency
#: only when it is this close (adjacent-channel reception on 2.4 GHz is up to 4 channels off).
MAX_PRIMARY_DRIFT_MHZ = 25

_BAND_MAX_WIDTH = {BAND_24: 40, BAND_5: 160, BAND_6: 320}
#: The spectrum (MHz) every segment of a band must lie in.
_BAND_EDGES = {BAND_24: (2400, 2495), BAND_5: (4900, 5925), BAND_6: (5925, 7125)}
#: 5 GHz centre channels of bonded channels (IEEE 802.11 global operating classes 116-129).
_FIVE_GHZ_CENTRES = {
    40: frozenset({38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175}),
    80: frozenset({42, 58, 106, 122, 138, 155, 171}),
    160: frozenset({50, 114, 163}),
}
_REPLACEMENT = chr(0xFFFD)

_OUI_IEEE = b"\x00\x0f\xac"
_OUI_MICROSOFT = b"\x00\x50\xf2"
_AKM_PSK = frozenset({2, 4, 6, 19, 20})
_AKM_SAE = frozenset({8, 9, 24, 25})
#: 802.1X, FT-802.1X, 802.1X-SHA256, Suite B (SHA-256), FILS, FT-802.1X-SHA384, 802.1X-SHA384
_AKM_EAP = frozenset({1, 3, 5, 11, 14, 15, 16, 17, 22, 23})
#: Suite B 192-bit (802.1X-SHA384) and its FT variant: WPA3-Enterprise 192-bit mode
_AKM_EAP_192 = frozenset({12, 13})
_AKM_OWE = frozenset({18})

_PHY_ORDER = ("b", "g", "a", "n", "ac", "ax", "be")
#: ``DOT11_PHY_TYPE`` -> PHY letter (dsss, ofdm, hrdsss, erp, ht, vht, he, eht).
_PHY_TYPE_NAMES = {2: "b", 4: "a", 5: "b", 6: "g", 7: "n", 8: "ac", 10: "ax", 11: "be"}
#: DSSS/CCK rates in 500 kb/s units: 1, 2, 5.5 and 11 Mb/s.
_DSSS_RATES = frozenset({2, 4, 11, 22})
#: The highest legacy rate (54 Mb/s); larger values in a rate element are BSS membership selectors.
_MAX_LEGACY_RATE = 108

# PHY rates per spatial stream (Mb/s) at the top MCS a capability element allows.
_HT_RATE = {20: (65.0, 72.2), 40: (135.0, 150.0)}                  # MCS 7: (long GI, short GI)
_VHT_RATE = {                                                       # top MCS -> width -> (long GI, short GI)
    7: {20: (65.0, 72.2), 40: (135.0, 150.0), 80: (292.5, 325.0), 160: (585.0, 650.0)},
    8: {20: (78.0, 86.7), 40: (162.0, 180.0), 80: (351.0, 390.0), 160: (702.0, 780.0)},
    9: {20: (78.0, 86.7), 40: (180.0, 200.0), 80: (390.0, 433.3), 160: (780.0, 866.7)},
}
_HE_RATE = {                                                        # 0.8 s guard interval
    7: {20: 86.0, 40: 172.1, 80: 360.3, 160: 720.6},
    9: {20: 114.7, 40: 229.4, 80: 480.4, 160: 960.8},
    11: {20: 143.4, 40: 286.8, 80: 600.5, 160: 1201.0},
}
_EHT_RATE = {
    9: {20: 114.7, 40: 229.4, 80: 480.4, 160: 960.8, 320: 1921.6},
    11: {20: 143.4, 40: 286.8, 80: 600.5, 160: 1201.0, 320: 2402.0},
    13: {20: 172.1, 40: 344.1, 80: 720.6, 160: 1441.2, 320: 2882.4},
}


# --- element walk ------------------------------------------------------------------------------
class Elements:
    """The information elements of one frame, keyed by ``(element id, extension id or None)``."""

    __slots__ = ("_items", "truncated")

    def __init__(self) -> None:
        self._items: Dict[Tuple[int, Optional[int]], List[bytes]] = {}
        self.truncated = False

    def add(self, eid: int, ext: Optional[int], body: bytes) -> None:
        self._items.setdefault((eid, ext), []).append(body)

    def get(self, eid: int, ext: Optional[int] = None) -> Optional[bytes]:
        """The body of the first element with that id (extension elements: without the extension id)."""
        bodies = self._items.get((eid, ext))
        return bodies[0] if bodies else None

    def all(self, eid: int, ext: Optional[int] = None) -> List[bytes]:
        return list(self._items.get((eid, ext), ()))

    def __len__(self) -> int:
        return sum(len(v) for v in self._items.values())


def parse_elements(data: Any) -> Elements:
    """Walk an information-element blob. An element that runs past the end stops the walk and
    sets :attr:`Elements.truncated`; the complete elements before it are kept."""
    els = Elements()
    try:
        buf = bytes(data or b"")
    except (TypeError, ValueError):
        els.truncated = True
        return els
    pos, end = 0, len(buf)
    while pos + 2 <= end:
        eid, length = buf[pos], buf[pos + 1]
        body = buf[pos + 2:pos + 2 + length]
        if len(body) < length:
            els.truncated = True
            return els
        pos += 2 + length
        if eid == EID_EXTENSION:
            if body:
                els.add(EID_EXTENSION, body[0], body[1:])
        else:
            els.add(eid, None, body)
    if pos != end:
        els.truncated = True
    return els


def _u16(buf: bytes, pos: int) -> Optional[int]:
    return struct.unpack_from("<H", buf, pos)[0] if len(buf) >= pos + 2 else None


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


# --- frequency <-> channel ---------------------------------------------------------------------
def freq_to_channel(freq_mhz: Any) -> Optional[Tuple[str, int]]:
    """``(band, channel)`` for a channel centre frequency in MHz (2 MHz of rounding tolerated), or None."""
    f = _int(freq_mhz)
    if f is None:
        return None
    if abs(f - 2484) <= 2:
        return BAND_24, 14
    if 2410 <= f <= 2474:
        ch = int(round((f - 2407) / 5.0))
        return (BAND_24, ch) if 1 <= ch <= 13 else None
    if abs(f - 5935) <= 2:
        return BAND_6, 2
    if 5945 <= f <= 7125:
        # the 20 MHz raster only: 5960 MHz lies between channels 1 and 5 and is no channel at all
        ch = int(round((f - 5950) / 5.0))
        on_raster = 1 <= ch <= 233 and (ch - 1) % 4 == 0 and abs(5950 + 5 * ch - f) <= 2
        return (BAND_6, ch) if on_raster else None
    if 5003 <= f <= 5907:
        ch = int(round((f - 5000) / 5.0))
        return (BAND_5, ch) if 1 <= ch <= 181 else None
    if 4908 <= f <= 4997:
        ch = int(round((f - 4000) / 5.0))
        return (BAND_5, ch) if 182 <= ch <= 199 else None
    return None


def channel_to_freq(band: Any, channel: Any) -> Optional[int]:
    """Centre frequency (MHz) of *channel* in *band*; also valid for bonded centre channels. None when
    the band has no such channel number."""
    ch = _int(channel)
    if ch is None:
        return None
    if band == BAND_24:
        if ch == 14:
            return 2484
        return 2407 + 5 * ch if 1 <= ch <= 13 else None
    if band == BAND_5:
        if 1 <= ch <= 181:
            return 5000 + 5 * ch
        return 4000 + 5 * ch if 182 <= ch <= 199 else None
    if band == BAND_6:
        if ch == 2:
            return 5935
        return 5950 + 5 * ch if 1 <= ch <= 233 else None
    return None


def _six_ghz_raster_ok(centre: int, width: int) -> bool:
    """True when *centre* is a centre channel of that width on the 6 GHz channel raster."""
    if width == 20:
        return centre == 2 or (centre - 1) % 4 == 0
    if width == 40:
        return (centre - 3) % 8 == 0
    if width == 80:
        return (centre - 7) % 16 == 0
    if width == 160:
        return (centre - 15) % 32 == 0
    if width == 320:
        return (centre - 31) % 32 == 0
    return False


def _segment_ok(band: str, primary: Optional[int], centre: int, width: int) -> bool:
    """A bonded segment exists in *band* (a real centre channel for that width, inside the band's
    spectrum) and, when *primary* is given, holds the primary channel."""
    f = channel_to_freq(band, centre)
    if width > _BAND_MAX_WIDTH.get(band, 20) or f is None:
        return False
    low, high = _BAND_EDGES[band]
    if f - width // 2 < low or f + width // 2 > high:
        return False
    if primary is not None and abs(primary - centre) * 5 > width // 2 - 10:
        return False
    if band == BAND_6 and not _six_ghz_raster_ok(centre, width):
        return False
    if band == BAND_5 and width in _FIVE_GHZ_CENTRES and centre not in _FIVE_GHZ_CENTRES[width]:
        return False
    if band == BAND_24 and width == 40 and not (1 <= centre - 2 and centre + 2 <= 13):
        return False
    return True


def _vht_segments(width_code: int, c0: int, c1: int) -> List[Tuple[int, int, List[Tuple[int, int]]]]:
    """Candidate ``(width, centre, segments)`` readings of a VHT Operation width + CCFS0/CCFS1,
    widest first (a narrower fallback follows when the wide reading turns out invalid)."""
    out: List[Tuple[int, int, List[Tuple[int, int]]]] = []
    if width_code == 1:
        if c1 and abs(c1 - c0) == 8:
            out.append((160, c1, [(c1, 160)]))
        elif c1 and abs(c1 - c0) > 16:
            out.append((160, c0, [(c0, 80), (c1, 80)]))
        out.append((80, c0, [(c0, 80)]))
    elif width_code == 2:
        out.append((160, c0, [(c0, 160)]))
    elif width_code == 3:
        if c1:
            out.append((160, c0, [(c0, 80), (c1, 80)]))
        out.append((80, c0, [(c0, 80)]))
    return out


def channel_plan(band: str, primary: int, els: Elements) -> Tuple[int, int, List[Tuple[int, int]]]:
    """``(width_mhz, centre_channel, [(segment centre channel, segment width), ...])`` from every width
    indication the elements carry for *band*; the widest valid one wins, 20 MHz on *primary* otherwise."""
    best: List[Any] = [20, primary, [(primary, 20)]]

    def offer(width: int, centre: int, segments: List[Tuple[int, int]]) -> None:
        if width <= best[0]:
            return
        first_c, first_w = segments[0]
        if not _segment_ok(band, primary, first_c, first_w):
            return
        if any(not _segment_ok(band, None, c, w) for c, w in segments[1:]):
            return
        best[:] = [width, centre, segments]

    def offer_vht(info: bytes) -> None:
        if len(info) >= 3:
            for cand in _vht_segments(info[0], info[1], info[2]):
                offer(*cand)

    ht = els.get(EID_HT_OPERATION)
    if ht is not None and len(ht) >= 2 and band in (BAND_24, BAND_5):
        offset = ht[1] & 0x03
        if ht[1] & 0x04 and offset in (1, 3):
            centre = primary + 2 if offset == 1 else primary - 2
            offer(40, centre, [(centre, 40)])

    vht = els.get(EID_VHT_OPERATION)
    if vht is not None and band == BAND_5:
        offer_vht(vht)

    he = els.get(EID_EXTENSION, EXT_HE_OPERATION)
    if he is not None and len(he) >= 6:
        params = he[0] | he[1] << 8 | he[2] << 16
        pos = 6
        if params & HE_OP_VHT_INFO_PRESENT:
            if band == BAND_5:
                offer_vht(he[pos:pos + 3])
            pos += 3
        if params & HE_OP_CO_HOSTED_BSS:
            pos += 1
        six = he[pos:pos + 5]
        if params & HE_OP_6GHZ_INFO_PRESENT and len(six) >= 4 and band == BAND_6:
            width_code, c0, c1 = six[1] & 0x03, six[2], six[3]
            if width_code == 1:
                offer(40, c0, [(c0, 40)])
            elif width_code == 2:
                offer(80, c0, [(c0, 80)])
            elif width_code == 3:
                if c1 and abs(c1 - c0) == 8:
                    offer(160, c1, [(c1, 160)])
                elif c1 and abs(c1 - c0) > 16:
                    offer(160, c0, [(c0, 80), (c1, 80)])
                elif not c1:
                    offer(160, c0, [(c0, 160)])
                offer(80, c0, [(c0, 80)])

    eht = els.get(EID_EXTENSION, EXT_EHT_OPERATION)
    if eht is not None and len(eht) >= 8 and eht[0] & EHT_OP_INFO_PRESENT:
        width_code, c0, c1 = eht[5] & 0x07, eht[6], eht[7]
        if width_code == 1:
            offer(40, c0, [(c0, 40)])
        elif width_code == 2:
            offer(80, c0, [(c0, 80)])
        elif width_code == 3:
            centre = c1 or c0
            offer(160, centre, [(centre, 160)])
        elif width_code == 4 and c1:
            offer(320, c1, [(c1, 320)])
    return best[0], best[1], list(best[2])


def spans_for(band: str, segments: Iterable[Tuple[int, int]]) -> List[List[int]]:
    """``[[low_mhz, high_mhz], ...]`` for ``(centre channel, width)`` segments (invalid ones skipped)."""
    out: List[List[int]] = []
    for centre, width in segments:
        f = channel_to_freq(band, centre)
        if f is not None:
            out.append([f - width // 2, f + width // 2])
    return out


def _he_six_ghz_primary(els: Elements) -> Optional[int]:
    he = els.get(EID_EXTENSION, EXT_HE_OPERATION)
    if he is None or len(he) < 6:
        return None
    params = he[0] | he[1] << 8 | he[2] << 16
    if not params & HE_OP_6GHZ_INFO_PRESENT:
        return None
    pos = 6 + (3 if params & HE_OP_VHT_INFO_PRESENT else 0) + (1 if params & HE_OP_CO_HOSTED_BSS else 0)
    return he[pos] if len(he) > pos else None


def _primary_channel(band: str, freq_channel: int, freq_mhz: int, els: Elements) -> int:
    candidates: List[int] = []
    if band == BAND_24:
        ds = els.get(EID_DS_PARAMS)
        if ds:
            candidates.append(ds[0])
    if band in (BAND_24, BAND_5):
        ht = els.get(EID_HT_OPERATION)
        if ht:
            candidates.append(ht[0])
    if band == BAND_6:
        six = _he_six_ghz_primary(els)
        if six is not None:
            candidates.append(six)
    for ch in candidates:
        f = channel_to_freq(band, ch)
        if band == BAND_6 and not _six_ghz_raster_ok(ch, 20):
            continue                          # a 6 GHz primary channel is a 20 MHz channel
        if f is not None and abs(f - freq_mhz) <= MAX_PRIMARY_DRIFT_MHZ:
            return ch
    return freq_channel


# --- SSID / BSSID ------------------------------------------------------------------------------
def decode_ssid(raw: Any) -> Tuple[str, bool]:
    """``(text, hidden)`` for SSID bytes: hidden when empty or all zero bytes."""
    try:
        data = bytes(raw or b"")[:32]
    except (TypeError, ValueError):
        return "", True
    if not data or not any(data):
        return "", True
    data = data.rstrip(b"\x00")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("cp1252", errors="replace")
    return "".join(_REPLACEMENT if (ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F) else c for c in text), False


def format_bssid(raw: Any) -> Optional[str]:
    """``b"\\x02\\x11..."`` (6 bytes) or an ``aa-bb-...`` string -> ``"02:11:22:33:44:55"``; None otherwise."""
    if isinstance(raw, str):
        digits = "".join(ch for ch in raw if ch not in ":-. ")
        try:
            data = bytes.fromhex(digits)
        except ValueError:
            return None
    else:
        try:
            data = bytes(raw or b"")
        except (TypeError, ValueError):
            return None
    if len(data) != 6:
        return None
    return ":".join(f"{b:02X}" for b in data)


def oui_info(bssid: str) -> Tuple[str, bool, Optional[str]]:
    """``(oui, locally_administered, base_oui)`` for ``AA:BB:CC:DD:EE:FF``. ``base_oui`` is the OUI with
    the locally-administered bit cleared (many APs derive extra BSSIDs that way), only when set."""
    first = int(bssid[:2], 16)
    oui = bssid[:8]
    local = bool(first & 0x02)
    base = f"{first & ~0x02 & 0xFF:02X}{bssid[2:8]}" if local else None
    return oui, local, base


# --- security ----------------------------------------------------------------------------------
def _suites(buf: bytes, pos: int) -> Tuple[Optional[List[Tuple[bytes, int]]], int]:
    """A 2-byte count + that many 4-byte suites at *pos*: ``(suites or None when truncated, new pos)``."""
    count = _u16(buf, pos)
    if count is None:
        return None, pos
    pos += 2
    if len(buf) < pos + 4 * count:
        return None, pos
    suites = [(buf[pos + 4 * i:pos + 4 * i + 3], buf[pos + 4 * i + 3]) for i in range(count)]
    return suites, pos + 4 * count


def _akm_label(akms: Sequence[Tuple[bytes, int]], mfpr: bool) -> str:
    families = set()
    eap_kinds = set()
    for oui, kind in akms:
        if oui != _OUI_IEEE:
            continue
        if kind in _AKM_PSK:
            families.add("psk")
        elif kind in _AKM_SAE:
            families.add("sae")
        elif kind in _AKM_OWE:
            families.add("owe")
        elif kind in _AKM_EAP or kind in _AKM_EAP_192:
            families.add("eap")
            eap_kinds.add(kind)
    if families == {"psk"}:
        return "WPA2-Personal"
    if families == {"sae"}:
        return "WPA3-Personal"
    if families == {"psk", "sae"}:
        return "WPA2/WPA3-Personal"
    if families == {"eap"}:
        if eap_kinds <= _AKM_EAP_192:
            return "WPA3-Enterprise 192-bit"
        # PMF required keeps out every client without it: WPA3-Enterprise only mode, whichever 802.1X
        # AKMs it offers; without MFPR a WPA2-Enterprise client can join (plain or transition mode)
        return "WPA3-Enterprise" if mfpr else "WPA2-Enterprise"
    if families == {"owe"}:
        return "OWE"
    return "Unknown"


def _rsn_label(body: bytes) -> str:
    if len(body) < 2:
        return "Unknown"
    default = [(_OUI_IEEE, 1)]            # no AKM list: the default suite is 802.1X
    pos = 2
    if len(body) < pos + 4:               # version only: every suite takes its default
        return _akm_label(default, False)
    pos += 4                              # group data cipher suite
    if _u16(body, pos) is None:
        return _akm_label(default, False)
    pairwise, pos = _suites(body, pos)
    if pairwise is None:
        return "Unknown"
    if _u16(body, pos) is None:
        return _akm_label(default, False)
    akms, pos = _suites(body, pos)
    if not akms:
        return "Unknown"
    caps = _u16(body, pos) or 0
    return _akm_label(akms, bool(caps & RSN_CAP_MFPR))


def _wpa_label(body: bytes) -> str:
    """The Microsoft WPA element after its OUI and type: version, group suite, pairwise and AKM lists."""
    if len(body) < 6 or _u16(body, 6) is None:
        return "WPA-Enterprise"            # WPA's default AKM is 802.1X as well
    pairwise, pos = _suites(body, 6)
    if pairwise is None:
        return "Unknown"
    if _u16(body, pos) is None:
        return "WPA-Enterprise"
    akms, _ = _suites(body, pos)
    kinds = {kind for oui, kind in (akms or []) if oui == _OUI_MICROSOFT}
    if kinds == {2}:
        return "WPA-Personal"
    if kinds == {1}:
        return "WPA-Enterprise"
    return "Unknown"


def security_label(els: Elements, capability: Any) -> str:
    """The contract's security string for these elements and ``usCapabilityInformation``."""
    rsn = els.get(EID_RSN)
    if rsn is not None:
        return _rsn_label(rsn)
    for body in els.all(EID_VENDOR):
        if body[:4] == _OUI_MICROSOFT + b"\x01":
            return _wpa_label(body[4:])
    cap = _int(capability) or 0
    return "WEP" if cap & CAP_PRIVACY else "Open"


# --- PHY, generation, rate ---------------------------------------------------------------------
def _legacy_rates(els: Elements, rate_set: Any) -> List[int]:
    """Legacy rates in 500 kb/s units from the rate elements and ``WLAN_RATE_SET`` (basic bits and
    BSS membership selectors dropped)."""
    rates = set()
    for eid in (EID_SUPPORTED_RATES, EID_EXT_SUPPORTED_RATES):
        for body in els.all(eid):
            rates.update(b & 0x7F for b in body)
    try:
        for value in rate_set or ():
            v = _int(value)
            if v is not None:
                rates.add(v & 0x7FFF)
    except TypeError:
        pass
    return sorted(r for r in rates if 0 < r <= _MAX_LEGACY_RATE)


def phy_list(band: str, els: Elements, rates: Sequence[int], phy_type: Any = None) -> List[str]:
    """Every PHY the AP advertises, oldest first (see the module docstring)."""
    phys = set()
    if band == BAND_24 and rates:
        phys.add("b" if all(r in _DSSS_RATES for r in rates) else "g")
    elif band == BAND_5:
        phys.add("a")
    if els.get(EID_HT_CAPABILITIES) is not None:
        phys.add("n")
    if els.get(EID_VHT_CAPABILITIES) is not None and band == BAND_5:
        phys.add("ac")                      # VHT is 5 GHz only (2.4 GHz "256-QAM" APs carry the element too)
    if els.get(EID_EXTENSION, EXT_HE_CAPABILITIES) is not None or band == BAND_6:
        phys.add("ax")
    if els.get(EID_EXTENSION, EXT_EHT_CAPABILITIES) is not None:
        phys.add("be")
    reported = _PHY_TYPE_NAMES.get(_int(phy_type) if phy_type is not None else None)
    if reported == "ac" and band != BAND_5:
        reported = None
    if reported in ("n", "ac", "ax", "be"):
        newest = max((_PHY_ORDER.index(p) for p in phys), default=-1)
        if _PHY_ORDER.index(reported) > newest:
            phys.add(reported)
    elif reported in ("b", "g") and band == BAND_24 and not rates:
        phys.add(reported)
    if band == BAND_24 and not phys & {"b", "g"}:
        phys.add("g")
    return [p for p in _PHY_ORDER if p in phys]


def generation_for(phys: Sequence[str], band: str) -> Optional[str]:
    if "be" in phys:
        return "Wi-Fi 7"
    if "ax" in phys:
        return "Wi-Fi 6E" if band == BAND_6 else "Wi-Fi 6"
    if "ac" in phys:
        return "Wi-Fi 5"
    if "n" in phys:
        return "Wi-Fi 4"
    return None


def _two_bit_map(value: int, codes: Dict[int, int]) -> Tuple[int, int]:
    """``(spatial streams, top MCS)`` from an 8-stream 2-bits-per-stream MCS map (code 3 = none)."""
    nss, top = 0, 0
    for i in range(8):
        code = (value >> (2 * i)) & 0x03
        if code != 3 and code in codes:
            nss = i + 1
            top = max(top, codes[code])
    return nss, top


def estimate_max_rate(band: str, width: int, els: Elements, rates: Sequence[int]) -> Optional[float]:
    """Best-effort top PHY rate in Mb/s (see the module docstring); None when nothing says."""
    best = max(rates) / 2.0 if rates else None
    est: Optional[float] = None
    ht = els.get(EID_HT_CAPABILITIES)
    vht = els.get(EID_VHT_CAPABILITIES)
    he = els.get(EID_EXTENSION, EXT_HE_CAPABILITIES)
    eht = els.get(EID_EXTENSION, EXT_EHT_CAPABILITIES)
    ht_info = _u16(ht, 0) if ht is not None else None
    if eht is not None and len(eht) >= 14:
        mcs_bytes = eht[11:14]
        nss = max(b & 0x0F for b in mcs_bytes)
        top = 13 if mcs_bytes[2] & 0x0F else 11 if mcs_bytes[1] & 0x0F else 9
        w = min(width, 320)
        if nss:
            est = _EHT_RATE[top][w] * nss
    elif he is not None and len(he) >= 19:
        nss, top = _two_bit_map(struct.unpack_from("<H", he, 17)[0], {0: 7, 1: 9, 2: 11})
        w = min(width, 160)
        if nss:
            est = _HE_RATE[top][w] * nss
    elif vht is not None and len(vht) >= 6 and band == BAND_5:
        info = struct.unpack_from("<I", vht, 0)[0]
        nss, top = _two_bit_map(struct.unpack_from("<H", vht, 4)[0], {0: 7, 1: 8, 2: 9})
        w = min(width, 160)
        if w == 160:
            sgi = bool(info & 0x40)
        elif w == 80:
            sgi = bool(info & 0x20)
        else:
            sgi = bool(ht_info is not None and ht_info & (0x40 if w == 40 else 0x20))
        if nss:
            est = _VHT_RATE[top][w][1 if sgi else 0] * nss
    elif ht is not None and len(ht) >= 7 and ht_info is not None:
        nss = max((i + 1 for i in range(4) if ht[3 + i]), default=0)
        w = min(width, 40)
        sgi = bool(ht_info & (0x40 if w == 40 else 0x20))
        if nss:
            est = _HT_RATE[w][1 if sgi else 0] * nss
    values = [v for v in (best, est) if v is not None]
    return round(max(values), 1) if values else None


# --- one BSS entry -----------------------------------------------------------------------------
def describe_bss(entry: Any) -> Optional[Dict[str, Any]]:
    """The static AP fields for one raw BSS entry dict (:data:`ENTRY_KEYS`), or None when it has no
    usable BSSID or cannot be placed on a band. Never raises."""
    try:
        return _describe(entry)
    except Exception:  # noqa: BLE001 - a hostile or corrupt entry must never break the survey
        log.debug("could not describe a BSS entry", exc_info=True)
        return None


def _describe(entry: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(entry, dict):
        return None
    bssid = format_bssid(entry.get("bssid"))
    if bssid is None:
        return None
    els = parse_elements(entry.get("ies"))
    freq_khz = _int(entry.get("freq_khz")) or 0
    freq_mhz = int(round(freq_khz / 1000.0))
    placed = freq_to_channel(freq_mhz)
    if placed is None and _BAND_EDGES[BAND_6][0] <= freq_mhz <= _BAND_EDGES[BAND_6][1]:
        # a 6 GHz frequency between two channels: only the AP's own 6 GHz Operation Information places it
        six = _he_six_ghz_primary(els)
        f = channel_to_freq(BAND_6, six)
        if f is not None and _six_ghz_raster_ok(six, 20) and abs(f - freq_mhz) <= MAX_PRIMARY_DRIFT_MHZ:
            placed = (BAND_6, six)
    if placed is None:
        # no usable receive frequency: 2.4 GHz channel numbers from the AP's own elements are unambiguous
        for body in (els.get(EID_DS_PARAMS), els.get(EID_HT_OPERATION)):
            if body and 1 <= body[0] <= 14:
                placed = (BAND_24, body[0])
                freq_mhz = channel_to_freq(BAND_24, body[0]) or 0
                break
    if placed is None:
        return None
    band, freq_channel = placed
    primary = _primary_channel(band, freq_channel, freq_mhz, els)
    width, centre, segments = channel_plan(band, primary, els)

    ssid, hidden = decode_ssid(entry.get("ssid"))
    if hidden:
        ssid, hidden = decode_ssid(els.get(EID_SSID))
    rates = _legacy_rates(els, entry.get("rates"))
    phys = phy_list(band, els, rates, entry.get("phy_type"))
    beacon_tu = _int(entry.get("beacon_period")) or 0
    oui, local, base = oui_info(bssid)
    return {
        "bssid": bssid,
        "ssid": ssid,
        "hidden": hidden,
        "band": band,
        "channel": primary,
        "center_channel": centre,
        "width_mhz": width,
        "freq_mhz": channel_to_freq(band, primary),
        "spans": spans_for(band, segments),
        "phy": phys[-1],
        "phys": phys,
        "generation": generation_for(phys, band),
        "security": security_label(els, entry.get("capability")),
        "beacon_ms": int(round(beacon_tu * 1.024)) if 0 < beacon_tu < 65536 else None,
        "max_rate_mbps": estimate_max_rate(band, width, els, rates),
        "oui": oui,
        "locally_administered": local,
        "base_oui": base,
    }


def self_test() -> Tuple[bool, str]:
    """Frozen-build check (``TNT.exe --selfcheck``): a synthetic 5 GHz 80 MHz WPA3 entry parses right."""
    rsn = struct.pack("<H", 1) + _OUI_IEEE + b"\x04" + struct.pack("<H", 1) + _OUI_IEEE + b"\x04" \
        + struct.pack("<H", 1) + _OUI_IEEE + b"\x08" + struct.pack("<H", RSN_CAP_MFPR)
    ies = (bytes([EID_SSID, 4]) + b"test" + bytes([EID_HT_OPERATION, 22, 36, 0x05]) + bytes(20)
           + bytes([EID_VHT_OPERATION, 5, 1, 42, 0, 0xFC, 0xFF]) + bytes([EID_RSN, len(rsn)]) + rsn)
    entry = {"bssid": b"\x02\x00\x00\x00\x00\x01", "freq_khz": 5180000, "ies": ies, "capability": CAP_PRIVACY}
    d = describe_bss(entry)
    ok = bool(d) and d["band"] == BAND_5 and d["width_mhz"] == 80 and d["spans"] == [[5170, 5250]] \
        and d["security"] == "WPA3-Personal" and d["ssid"] == "test"
    return ok, "5 GHz 80 MHz WPA3 sample" if ok else f"unexpected result {d!r}"
