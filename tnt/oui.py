"""MAC address normalisation and OUI vendor lookup.

* :func:`normalize_mac` accepts every common textual form (``00-00-5e-00-53-ab``,
  ``0000.5e00.53ab``, ``00:00:5E:00:53:AB``, ``00005e0053ab``, with surrounding
  whitespace) and returns the canonical ``AA:BB:CC:DD:EE:FF`` form, or ``None``.
* :func:`vendor_for_mac` looks the IAB (36-bit) prefix up first and then the OUI
  (24-bit) in the ``netaddr`` registry that ships with the package (no internet access
  is ever needed). The longer prefix must win: every IAB block sits under an OUI that is
  registered to the generic "IEEE Registration Authority", so an OUI-first order would
  never name the real owner of an IAB address. When nothing is registered and the U/L
  bit of the first octet is set (second hex digit 2/6/A/E) the address is a locally
  administered, i.e. randomised, MAC and ``"Locally administered (randomized)"`` is
  returned.
  Broadcast and multicast addresses (I/G bit set) and the all-zero placeholder
  ``00:00:00:00:00:00`` never get a vendor (the registry would say "Xerox").

Contract gaps filled here (documented as required):

* Lookups are memoised per 36-bit prefix (``functools.lru_cache``) because the
  discovery scanner may ask for hundreds of vendors per run.
* ``netaddr`` is imported lazily; if it is missing or broken the lookup degrades to
  the randomised-MAC rule only (logged once) instead of raising.
* :func:`normalize_oui` / :func:`vendor_for_oui` answer ``GET /api/oui`` for the WiFi tile,
  which only ever sends 24-bit prefixes (never a whole BSSID) to the service: the MA-L (OUI)
  registration alone, since an IAB/MA-M/MA-S owner cannot be told from 24 bits, and ``None``
  for an unregistered, multicast or locally administered prefix.
"""
from __future__ import annotations

import functools
import logging
import re
from typing import Optional

log = logging.getLogger(__name__)

__all__ = ["normalize_mac", "vendor_for_mac", "is_randomized_mac", "normalize_oui", "vendor_for_oui",
           "RANDOMIZED_TEXT", "NULL_MAC"]

RANDOMIZED_TEXT = "Locally administered (randomized)"
BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
NULL_MAC = "00:00:00:00:00:00"       # placeholder, never a device (the registry says "Xerox")

# Only hex digits and the usual separators may appear in a MAC string.
_ALLOWED_RE = re.compile(r"^[0-9A-Fa-f:\-.\s]+$")
_SEPARATORS_RE = re.compile(r"[:\-.\s]")
# A 24-bit prefix: three hex pairs joined by one separator style (":", "-" or none).
_OUI_RE = re.compile(r"^([0-9A-Fa-f]{2})([:-]?)([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})$")
_netaddr_warned = False


def normalize_mac(mac: str) -> Optional[str]:
    """Return *mac* as ``AA:BB:CC:DD:EE:FF`` (uppercase) or ``None`` if it is not a MAC."""
    if not isinstance(mac, str):
        return None
    text = mac.strip()
    if not text or _ALLOWED_RE.match(text) is None:
        return None
    digits = _SEPARATORS_RE.sub("", text)
    if len(digits) != 12:
        return None
    digits = digits.upper()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def is_randomized_mac(mac: str) -> bool:
    """True when the U/L (locally administered) bit is set and the address is unicast."""
    norm = normalize_mac(mac)
    if norm is None:
        return False
    first = int(norm[:2], 16)
    return bool(first & 0x02) and not (first & 0x01)


@functools.lru_cache(maxsize=4096)
def _registered_org(prefix36: str) -> Optional[str]:
    """Organisation registered for a 36-bit prefix (``"AA:BB:CC:DD:E"``): IAB (most specific) first, then OUI."""
    global _netaddr_warned
    try:
        from netaddr import EUI, NotRegisteredError  # noqa: WPS433 - lazy on purpose
    except Exception:  # noqa: BLE001 - keep working without the package
        if not _netaddr_warned:
            _netaddr_warned = True
            log.warning("netaddr is not importable; vendor lookups disabled")
        return None
    try:
        eui = EUI(prefix36 + "0:00")
    except Exception:  # noqa: BLE001
        return None
    for attr in ("iab", "oui"):
        try:
            entry = getattr(eui, attr, None)      # ``.oui`` raises when unregistered, ``.iab`` is None
            if entry is None:
                continue
            reg = entry.registration()
            org = str(getattr(reg, "org", "") or "").strip()
            if org:
                return org
        except NotRegisteredError:
            continue
        except Exception:  # noqa: BLE001 - a corrupt registry entry must not break discovery
            log.debug("netaddr %s lookup failed for %s", attr, prefix36, exc_info=True)
            continue
    return None


def normalize_oui(prefix: str) -> Optional[str]:
    """``aa-bb-cc`` / ``aabbcc`` / ``AA:BB:CC`` (surrounding whitespace allowed) -> ``"AA:BB:CC"``, else None."""
    if not isinstance(prefix, str):
        return None
    m = _OUI_RE.match(prefix.strip())
    if m is None:
        return None
    return f"{m.group(1)}:{m.group(3)}:{m.group(4)}".upper()


@functools.lru_cache(maxsize=4096)
def _registered_oui(prefix: str) -> Optional[str]:
    global _netaddr_warned
    try:
        from netaddr import OUI, NotRegisteredError  # noqa: WPS433 - lazy on purpose
    except Exception:  # noqa: BLE001 - keep working without the package
        if not _netaddr_warned:
            _netaddr_warned = True
            log.warning("netaddr is not importable; vendor lookups disabled")
        return None
    try:
        org = str(getattr(OUI(prefix.replace(":", "-")).registration(), "org", "") or "").strip()
        return org or None
    except NotRegisteredError:
        return None
    except Exception:  # noqa: BLE001 - a corrupt registry entry must not break the lookup
        log.debug("netaddr OUI lookup failed for %s", prefix, exc_info=True)
        return None


def vendor_for_oui(prefix: str) -> Optional[str]:
    """Organisation registered for a 24-bit OUI (MA-L), or None when *prefix* is not an OUI, is not
    registered, or has the multicast or locally-administered bit set."""
    norm = normalize_oui(prefix)
    if norm is None:
        return None
    first = int(norm[:2], 16)
    if first & 0x03:
        return None
    return _registered_oui(norm)


def vendor_for_mac(mac: str) -> Optional[str]:
    """Vendor name for *mac*, ``RANDOMIZED_TEXT`` for unregistered locally administered
    addresses, ``None`` when unknown or when *mac* is not a MAC / is broadcast / multicast."""
    norm = normalize_mac(mac)
    if norm is None or norm in (BROADCAST_MAC, NULL_MAC):
        return None
    first = int(norm[:2], 16)
    if first & 0x01:  # I/G bit: multicast / broadcast, never a device
        return None
    org = _registered_org(norm[:13])
    if org:
        return org
    if first & 0x02:
        return RANDOMIZED_TEXT
    return None
