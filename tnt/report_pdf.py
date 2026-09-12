"""Compact PDFs of saved site reports and of report comparisons.

``build_site_report(report, tz_offset_s=None) -> bytes`` renders ``GET /api/reports/{id}/pdf`` from a
``Database.get_report`` dict; ``build_compare_report(a, b, comparison, tz_offset_s=None) -> bytes``
renders ``GET /api/reports/compare/pdf`` (``comparison`` is :func:`tnt.reports.compare_reports`).

These are working documents a technician hands to a customer, so unlike the sticker-styled
monitoring report (:mod:`tnt.export_pdf`) they are dense: Letter paper, 0.45 in margins, Helvetica
6.5-9 pt, hairline grids with a grey header row, no rounded boxes, shadows or charts.  Reused from
``tnt.export_pdf``: the palette, ``_Clock`` (``tz_offset_s=None`` is the machine's DST-aware local
time, right for a seven-day window), the number formatters, ``_fit`` / ``_esc`` and the numbered-page
canvas (drawn here with a smaller footer).

* Text outside Windows-1252 (the encoding of the built-in Helvetica) is replaced with ``?``: an SSID
  with an emoji or a host name in another script would otherwise print as empty boxes and throw the
  column width measurement off.
* Tables repeat their header row on every page.  The access point table is capped at
  :data:`MAX_PDF_APS` rows (the report keeps up to 200) and says how many were left out; the device
  table lists every host the report holds (up to 512).
* A section the scan could not collect prints its reason in one line; a section whose flowables
  cannot be built prints a one-line notice instead of failing the document.  Free text inside table
  cells (outage notes, comparison notes, heading notes) is cut to :data:`CELL_TEXT_MAX` characters,
  since a table row cannot split across pages; should the layout still fail, the document is built
  again with every such text cut to :data:`CELL_TEXT_TIGHT` characters.
* The Ping and Outages headings carry their section's ``note`` on the right, what a new report left
  out ("Left out: 8 removed or disabled targets"), also above a section without data; older reports
  have none and print as before.
* Networks (ARCHITECTURE 3.20): a report read on its site's network (``window_reason`` ``site_network``)
  says so in the window line with its visits and the time monitored there ("(7.0 days; this site's network
  only: 2 visits, 1 d 7 h monitored)"), one whose network was not identified when the scan started says the
  time rule was used, one of a portable network (a hotspot) that only this connection counts, and one with
  untagged pings left out since when they count.  The Network block names the router ("Router" its MAC or
  virtual MAC, "Vendor" its vendor, "likely ..." for a locally administered MAC).  The comparison's side lines
  give each side's visits and time on its network ("(3 visits, 23 h 37 min on its network)") and the
  comparison's other ``notes`` ("A and B were scanned on the same network ...") follow them.
* Numbers read as on the Reports page: dBm rounded half away from zero, milliseconds with two
  decimals below 1 and one below 100, loss with two decimals below 10 %, loss differences in
  percentage points, and no relative change beyond ±500 % (a ratio instead).
* The key numbers strip tints what deserves a second look, with the page's thresholds
  (:func:`key_levels`).  The comparison opens with who is compared with whom (B is the reference),
  both scans' dates and windows and a few plain sentences (:func:`compare_highlights`); the Better
  column names the site, and each section has a one-line glossary.
"""
from __future__ import annotations

import logging
import math
from io import BytesIO
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Flowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.platypus.doctemplate import LayoutError

from . import APP_LONG_NAME, __version__
from .export_pdf import (BOLD, FONT, GREEN, GRID, INK, INK_SOFT, PAPER, RED, YELLOW, _Clock, _NumberedCanvas, _col_widths,
                         _esc, _fit, _fmt_duration, _fmt_missed_pct, _is_num, _mix)
from .networks import is_locally_administered
from .reports import NETWORK_TIME_NOTE, WINDOW_WORDS, monitored_text, network_time, outage_numbers, span_text

log = logging.getLogger(__name__)

PAGE_W, PAGE_H = letter
MARGIN = 0.45 * inch
CONTENT_W = PAGE_W - 2 * MARGIN
CELL_PT = 7.0
MAX_PDF_APS = 100
CELL_TEXT_MAX = 300
CELL_TEXT_TIGHT = 80
MAX_REL_PCT = 500.0
HEAD_FILL = _mix(INK, PAPER, 0.9)
BETTER_FILL = _mix(GREEN, PAPER, 0.62)
WORSE_FILL = _mix(RED, PAPER, 0.72)
WARN_FILL = _mix(YELLOW, PAPER, 0.6)
BAD_FILL = _mix(RED, PAPER, 0.72)

STYLES: Dict[str, ParagraphStyle] = {
    "title": ParagraphStyle("rpt_title", fontName=BOLD, fontSize=13, leading=16, textColor=INK),
    "sub": ParagraphStyle("rpt_sub", fontName=FONT, fontSize=7.5, leading=9.5, textColor=INK_SOFT),
    "h": ParagraphStyle("rpt_h", fontName=BOLD, fontSize=9, leading=11, textColor=INK),
    "note": ParagraphStyle("rpt_note", fontName=FONT, fontSize=6.8, leading=8.5, textColor=INK_SOFT, alignment=TA_RIGHT),
    "body": ParagraphStyle("rpt_body", fontName=FONT, fontSize=7.5, leading=9.5, textColor=INK),
    "small": ParagraphStyle("rpt_small", fontName=FONT, fontSize=6.8, leading=8.5, textColor=INK_SOFT),
    "warn": ParagraphStyle("rpt_warn", fontName=FONT, fontSize=7.5, leading=9.5, textColor=INK),
}
PHASE_TITLES = {"speed": "Speed test", "discovery": "Discovery", "wifi": "Wi-Fi", "history": "History", "save": "Save"}
WINDOW_TEXT = {"network_change": "since this PC joined its current network", "seven_days": "the last 7 days",
               "data_start": "since ping data begins", "site_network": "this site's network only"}
#: the header line of a report whose network was not identified when its Full Scan started (the window line names the rule used)
UNKNOWN_NETWORK_TEXT = "The network was not identified when the scan started, so pings and outages are read by time (the window above)."
#: the header line of a report of a portable network (a phone hotspot, a travel router)
PORTABLE_NETWORK_TEXT = ("This network is carried from site to site (a hotspot or travel router), so only this connection to it "
                         "counts (the window above).")
KIND_TEXT = {"total_local": "All local targets", "total_internet": "All internet targets", "gap": "Not monitoring"}
ROLE_TEXT = {"gateway": "Gateway", "local": "Local", "internet": "Internet"}
WARNING_TEXT = {"apipa": "self-assigned address (no DHCP answer)", "duplicate_address": "duplicate address",
                "gateway_outside_subnet": "gateway outside the subnet", "no_dns": "no DNS server",
                "multiple_default_gateways": "several default gateways"}


# --------------------------------------------------------------------------------------
# text and numbers
# --------------------------------------------------------------------------------------
def _safe(value: Any) -> str:
    """Text Helvetica can draw: control characters become spaces, characters outside Windows-1252 ``?``."""
    text = "" if value is None else str(value)
    text = "".join(" " if ord(ch) < 32 or ord(ch) == 127 else ch for ch in text)
    return text.encode("cp1252", "replace").decode("cp1252")


def _cell(value: Any, width: float, font: str = FONT, size: float = CELL_PT) -> str:
    return _fit(_safe(value), max(8.0, width - 5.0), font, size)


def _para(text: Any, style: str = "body") -> Paragraph:
    return Paragraph(_esc(_safe(text)), STYLES[style])


def _clip(text: Any, limit: int) -> str:
    """Free text for a table cell, at most *limit* characters (a row taller than a page cannot be laid out)."""
    s = _safe(text)
    return s if len(s) <= limit else s[:max(1, limit - 3)].rstrip() + "..."


def _half_up(v: float) -> int:
    """Rounded half away from zero, like the page (Python's round() goes to the even neighbour: -81.5 would be -82 here
    and -81 on screen)."""
    return int(math.floor(abs(v) + 0.5)) * (-1 if v < 0 else 1)


def _mbps(v: Any) -> str:
    if not _is_num(v):
        return "-"
    if v == 0:
        return "0"
    return f"{_half_up(v)}" if abs(v) >= 100 else f"{v:.1f}"


def _ms(v: Any) -> str:
    """Milliseconds as the page writes them: two decimals below 1, one below 100, whole above ("0" for none)."""
    if not _is_num(v):
        return "-"
    if v == 0:
        return "0"
    a = abs(v)
    return f"{v:.2f}" if a < 1 else f"{v:.1f}" if a < 100 else f"{_half_up(v)}"


def _pct(v: Any) -> str:
    if not _is_num(v):
        return "-"
    if v == 0:
        return "0%"
    return f"{v:.2f}%" if abs(v) < 10 else f"{v:.1f}%"


def _int(v: Any) -> str:
    return f"{_half_up(v):,}" if _is_num(v) else "-"


def _dbm(v: Any) -> str:
    return f"{_half_up(v)} dBm" if _is_num(v) else "-"


def _bps(v: Any) -> str:
    if not _is_num(v) or v <= 0:
        return "-"
    if v >= 1e9:
        return f"{v / 1e9:g} Gbps"
    if v >= 1e6:
        return f"{v / 1e6:g} Mbps"
    return f"{v / 1e3:g} kbps"


def _when(clock: _Clock, ts: Any) -> str:
    return clock.fmt(float(ts), "%Y-%m-%d %H:%M") if _is_num(ts) else "-"


COUNT_UNITS = ("dBm", "APs", "networks", "devices", "outages")


def _value(v: Any, unit: str) -> str:
    """A comparison value in its unit's usual precision (the page's fmtNumber)."""
    if not _is_num(v):
        return "-"
    if v == 0:
        return "0"
    if unit == "Mbps":
        return _mbps(v)
    if unit == "ms":
        return _ms(v)
    if unit == "%":
        return _pct(v)
    if unit in COUNT_UNITS:
        return _int(v)
    if unit == "per day":
        return f"{v:.2f}" if abs(v) < 10 else f"{v:.1f}"
    return f"{v:,.1f}"


def _difference(delta: Any, delta_pct: Any, unit: str, better: Any = None) -> str:
    """``"+12 dB"``, ``"-823 Mbps (-87%)"``, ``"+2.42 pts"``, ``"x33"`` beyond ±500 %; no percentage for a "same" row."""
    if not _is_num(delta):
        return "-"
    magnitude = _value(abs(delta), unit).rstrip("%")
    if unit in COUNT_UNITS and unit != "dBm":
        magnitude = _int(abs(delta))
    if magnitude.strip("0.,") == "":
        return "same" if delta == 0 else "about 0"
    text = ("+" if delta > 0 else "-") + magnitude + (" pts" if unit == "%" else " dB" if unit == "dBm" else "")
    if _is_num(delta_pct) and unit not in ("%", "dBm") and better != "same":
        if abs(delta_pct) > MAX_REL_PCT:
            b = abs(delta / (delta_pct / 100.0)) if delta_pct else 0.0
            a = b + delta
            if a > 0 and b > 0:
                ratio = a / b if a >= b else b / a
                text += f" (x{ratio:.0f})" if ratio >= 10 else f" (x{ratio:.1f})"
        else:
            text += f" ({'+' if delta_pct > 0 else ''}{delta_pct:.0f}%)"
    return text


# --------------------------------------------------------------------------------------
# building blocks
# --------------------------------------------------------------------------------------
def _grid(data: List[List[Any]], widths: Sequence[float], right: Sequence[int] = (), header: bool = True,
          extra: Optional[List[Tuple[Any, ...]]] = None) -> Table:
    t = Table(data, colWidths=list(widths), repeatRows=1 if header else 0, hAlign="LEFT")
    cmds: List[Tuple[Any, ...]] = [
        ("FONTNAME", (0, 0), (-1, -1), FONT), ("FONTSIZE", (0, 0), (-1, -1), CELL_PT),
        ("LEADING", (0, 0), (-1, -1), CELL_PT + 1.6), ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 1.0), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.4),
        ("LEFTPADDING", (0, 0), (-1, -1), 2.5), ("RIGHTPADDING", (0, 0), (-1, -1), 2.5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, GRID), ("BOX", (0, 0), (-1, -1), 0.4, GRID),
    ]
    if header:
        cmds += [("FONTNAME", (0, 0), (-1, 0), BOLD), ("BACKGROUND", (0, 0), (-1, 0), HEAD_FILL)]
    for col in right:
        cmds.append(("ALIGN", (col, 0), (col, -1), "RIGHT"))
    if extra:
        cmds.extend(extra)
    t.setStyle(TableStyle(cmds))
    return t


def _kv(pairs: Sequence[Tuple[str, Any]], per_row: int = 3) -> Table:
    widths = _col_widths([0.75, 1.75] * per_row, CONTENT_W)
    rows: List[List[str]] = []
    for i in range(0, len(pairs), per_row):
        chunk = list(pairs[i:i + per_row])
        chunk += [("", "")] * (per_row - len(chunk))
        row: List[str] = []
        for j, (key, val) in enumerate(chunk):
            row.append(_cell(key, widths[2 * j], BOLD))
            row.append(_cell(val if val not in (None, "") else ("-" if key else ""), widths[2 * j + 1]))
        rows.append(row)
    t = Table(rows, colWidths=widths, hAlign="LEFT")
    cmds: List[Tuple[Any, ...]] = [
        ("FONTNAME", (0, 0), (-1, -1), FONT), ("FONTSIZE", (0, 0), (-1, -1), CELL_PT),
        ("LEADING", (0, 0), (-1, -1), CELL_PT + 1.6), ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("TOPPADDING", (0, 0), (-1, -1), 0.8), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.2),
        ("LEFTPADDING", (0, 0), (-1, -1), 2.5), ("RIGHTPADDING", (0, 0), (-1, -1), 2.5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, GRID),
    ]
    for j in range(per_row):
        cmds += [("FONTNAME", (2 * j, 0), (2 * j, -1), BOLD), ("TEXTCOLOR", (2 * j, 0), (2 * j, -1), INK_SOFT)]
    t.setStyle(TableStyle(cmds))
    return t


def _heading(title: str, note: Optional[str] = None, limit: int = CELL_TEXT_MAX) -> Table:
    t = Table([[Paragraph(_esc(_clip(title, 120)), STYLES["h"]), Paragraph(_esc(_clip(note or "", limit)), STYLES["note"])]],
              colWidths=[CONTENT_W * 0.4, CONTENT_W * 0.6], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "BOTTOM"), ("LINEBELOW", (0, 0), (-1, -1), 0.8, INK),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
    ]))
    t.keepWithNext = 1
    return t


def _block(title: str, fn: Callable[[], List[Flowable]]) -> List[Flowable]:
    try:
        return fn()
    except Exception:  # noqa: BLE001 - one broken section must not fail the document
        log.exception("report PDF: the %s section failed", title)
        return [_heading(title), _para("This section could not be rendered.", "small")]


class _CompactCanvas(_NumberedCanvas):
    def _draw_footer(self, total: int) -> None:
        self.saveState()
        y = 0.28 * inch
        self.setStrokeColor(GRID)
        self.setLineWidth(0.4)
        self.line(MARGIN, y + 8, PAGE_W - MARGIN, y + 8)
        self.setFont(FONT, 6.5)
        self.setFillColor(INK_SOFT)
        self.drawString(MARGIN, y, _fit(self.footer_text, PAGE_W - 2 * MARGIN - 60, FONT, 6.5))
        self.drawRightString(PAGE_W - MARGIN, y, f"Page {self._pageNumber} of {total}")
        self.restoreState()


def _canvas_maker(footer_text: str) -> Callable[..., _CompactCanvas]:
    class _Canvas(_CompactCanvas):
        pass

    _Canvas.footer_text = _safe(footer_text)
    return _Canvas


def _render(build: Callable[[int], List[Flowable]], title: str, footer: str) -> bytes:
    """Lay out the story ``build(limit)`` returns (*limit*: the most characters of free text a table cell gets); a layout
    that still fails (a cell taller than a page) is built once more with every such text cut to CELL_TEXT_TIGHT."""
    for limit in (CELL_TEXT_MAX, CELL_TEXT_TIGHT):
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN,
                                bottomMargin=MARGIN + 6, title=_safe(title), author=APP_LONG_NAME, creator=f"TNT {__version__}")
        try:
            doc.build(build(limit), canvasmaker=_canvas_maker(footer))
        except LayoutError:
            if limit == CELL_TEXT_TIGHT:
                raise
            log.warning("report PDF: the layout failed; building it again with shorter text", exc_info=True)
            continue
        return buf.getvalue()
    raise AssertionError("unreachable")


# --------------------------------------------------------------------------------------
# levels (the key numbers worth a second look; ui/js/reportsui.js keyNumbers uses the same thresholds)
# --------------------------------------------------------------------------------------
def _level(value: Any, warn: float, bad: float, low_is_bad: bool = False) -> str:
    if not _is_num(value):
        return ""
    if low_is_bad:
        return "bad" if value < bad else "warn" if value < warn else ""
    return "bad" if value >= bad else "warn" if value >= warn else ""


def key_levels(summary: Any, data: Any = None) -> Dict[str, str]:
    """``{key: "" | "warn" | "bad"}`` for the key numbers: download below 25 / 10 Mbps, upload below 5 / 2 Mbps, loss from
    1 % / 5 %, any outage, a connected signal below -67 / -75 dBm, four or more access points on the connected channel."""
    s = summary if isinstance(summary, dict) else {}
    wifi = data.get("wifi") if isinstance(data, dict) and isinstance(data.get("wifi"), dict) else {}
    conn = wifi.get("connected") if wifi.get("available") and isinstance(wifi.get("connected"), dict) else {}
    rssi = s.get("wifi_connected_rssi")
    signal = "" if not _is_num(rssi) else "bad" if rssi < -75 else "warn" if rssi < -67 else ""
    crowd = _level(conn.get("channel_aps"), 4, 10**9)
    return {
        "download": _level(s.get("download_mbps"), 25, 10, low_is_bad=True),
        "upload": _level(s.get("upload_mbps"), 5, 2, low_is_bad=True),
        "gateway_loss": _level(s.get("gateway_loss_pct"), 1, 5),
        "internet_loss": _level(s.get("internet_loss_pct"), 1, 5),
        "outages": "warn" if _is_num(s.get("outages")) and s["outages"] > 0 else "",
        "wifi_signal": signal,
        "wifi_aps": crowd,
    }


# --------------------------------------------------------------------------------------
# site report
# --------------------------------------------------------------------------------------
def _site_header(report: Dict[str, Any], data: Dict[str, Any], clock: _Clock) -> List[Flowable]:
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    site = report.get("site") or meta.get("site") or "Unnamed site"
    parts = [f"Scanned {_when(clock, report.get('created_ts') or meta.get('created_ts'))}",
             f"took {_fmt_duration(meta.get('duration_s'))}", str(report.get("status") or "-"),
             f"TNT {meta.get('tnt_version') or __version__}"]
    if meta.get("hostname"):
        parts.append(f"on {meta['hostname']}")
    out: List[Flowable] = [_para(f"Site report: {site}", "title"), _para("  ·  ".join(parts), "sub")]
    ping = data.get("ping") if isinstance(data.get("ping"), dict) else {}
    start, end = ping.get("window_start"), ping.get("window_end")
    if _is_num(start) and _is_num(end):
        reason = WINDOW_TEXT.get(str(ping.get("window_reason")), str(ping.get("window_reason") or ""))
        on_network = network_time(data)
        if on_network is not None:
            # the days spent at other sites are not "not monitoring": what counts is the time on this network
            count = on_network[1]
            line = (f"Ping and outage window: {_when(clock, start)} to {_when(clock, end)} ({span_text(end - start)}; {reason}: "
                    f"{count} visit{'s' if count != 1 else ''}, {_fmt_duration(on_network[0])} monitored)")
        else:
            line = f"Ping and outage window: {_when(clock, start)} to {_when(clock, end)} ({span_text(end - start)}, {reason})"
            numbers = outage_numbers(data.get("outages"))
            if numbers and numbers["window"] - numbers["monitored"] >= 60:
                line += (f"; monitored {_fmt_duration(numbers['monitored'])} "
                         f"({_fmt_duration(numbers['window'] - numbers['monitored'])} not monitoring)")
        out.append(_para(line, "sub"))
    network = meta.get("network") if isinstance(meta.get("network"), dict) else {}
    if network.get("identity") == "unknown":
        out.append(_para(UNKNOWN_NETWORK_TEXT, "sub"))
    elif network.get("portable"):
        out.append(_para(PORTABLE_NETWORK_TEXT, "sub"))
    if _is_num(ping.get("untagged_since")):
        out.append(_para(f"Pings recorded before this PC identified its networks count only from {_when(clock, ping['untagged_since'])}, "
                         "when it joined this network.", "sub"))
    missing = [f"{PHASE_TITLES.get(p.get('key'), p.get('key'))}: {p.get('message') or p.get('status')}"
               for p in meta.get("scan_phases") or [] if isinstance(p, dict) and p.get("status") != "done"]
    if missing:
        out.append(Paragraph("<b>Not complete.</b> " + _esc(_safe("; ".join(missing))), STYLES["warn"]))
    out.append(Spacer(1, 4))
    return out


def _short_span(seconds: Any) -> str:
    """``"45 s"``, ``"7 min"``, ``"2.5 h"``, ``"3.1 d"``: the key-number strip has no room for more."""
    if not _is_num(seconds):
        return "-"
    s = max(0.0, float(seconds))
    if s < 60:
        return f"{s:.0f} s"
    if s < 3600:
        return f"{s / 60:.0f} min"
    if s < 86400:
        return f"{s / 3600:.1f} h"
    return f"{s / 86400:.1f} d"


def _key_numbers(summary: Dict[str, Any], data: Optional[Dict[str, Any]] = None) -> Table:
    levels = key_levels(summary, data)
    cells = [
        ("Down Mbps", _mbps(summary.get("download_mbps")), levels["download"]),
        ("Up Mbps", _mbps(summary.get("upload_mbps")), levels["upload"]),
        ("Latency ms", _ms(summary.get("latency_ms")), ""), ("Gateway ms", _ms(summary.get("gateway_avg_ms")), ""),
        ("Gateway loss", _pct(summary.get("gateway_loss_pct")), levels["gateway_loss"]),
        ("Internet ms", _ms(summary.get("internet_avg_ms")), ""),
        ("Internet loss", _pct(summary.get("internet_loss_pct")), levels["internet_loss"]),
        ("Outages", _int(summary.get("outages")), levels["outages"]),
        ("Network down", _short_span(summary.get("downtime_s")), ""),
        ("Devices", _int(summary.get("hosts")), ""), ("Wi-Fi APs", _int(summary.get("wifi_aps")), levels["wifi_aps"]),
        ("Wi-Fi signal", _dbm(summary.get("wifi_connected_rssi")), levels["wifi_signal"]),
    ]
    width = CONTENT_W / len(cells)
    t = Table([[_cell(k, width, FONT, 6.3) for k, _v, _l in cells], [_cell(v, width, BOLD, 9) for _k, v, _l in cells]],
              colWidths=[width] * len(cells), hAlign="LEFT")
    cmds: List[Tuple[Any, ...]] = [
        ("FONTNAME", (0, 0), (-1, 0), FONT), ("FONTSIZE", (0, 0), (-1, 0), 6.3), ("TEXTCOLOR", (0, 0), (-1, 0), INK_SOFT),
        ("FONTNAME", (0, 1), (-1, 1), BOLD), ("FONTSIZE", (0, 1), (-1, 1), 9), ("TEXTCOLOR", (0, 1), (-1, 1), INK),
        ("LEADING", (0, 1), (-1, 1), 11), ("BACKGROUND", (0, 0), (-1, -1), HEAD_FILL),
        ("BOX", (0, 0), (-1, -1), 0.4, GRID), ("LINEAFTER", (0, 0), (-2, -1), 0.25, GRID),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]
    for col, (_k, _v, level) in enumerate(cells):
        if level:
            cmds.append(("BACKGROUND", (col, 0), (col, 1), BAD_FILL if level == "bad" else WARN_FILL))
    t.setStyle(TableStyle(cmds))
    return t


def router_text(network: Any) -> Optional[Tuple[str, str]]:
    """How a report's network was identified, as the Network block's Router and Vendor cells: ``("02:00:5E:10:00:01", "Example
    Networks")`` (``"likely Example Networks"`` for a locally administered MAC, whose OUI is only a guess), ``("00:00:5E:00:01:01
    (virtual)", "by gateway and subnet")`` for a redundant gateway, ``("identified by gateway and subnet", "")``; None when it was
    not identified (or the report predates networks)."""
    if not isinstance(network, dict):
        return None
    if network.get("identity") == "mac" and network.get("mac"):
        vendor = str(network.get("vendor") or "")
        return str(network["mac"]), ("likely " + vendor if vendor and is_locally_administered(network["mac"]) else vendor)
    if network.get("identity") == "fingerprint":
        if network.get("virtual_mac"):
            return f"{network['virtual_mac']} (virtual)", "by gateway and subnet"
        return "identified by gateway and subnet", ""
    return None


def _network_block(sec: Dict[str, Any], network: Any = None) -> List[Flowable]:
    out: List[Flowable] = [_heading("Network")]
    nic = sec.get("internet_nic") if isinstance(sec.get("internet_nic"), dict) else None
    if not sec.get("available") or nic is None:
        out.append(_para(sec.get("reason") or "Not collected", "small"))
        return out
    ipv4 = nic.get("ipv4") or "-"
    if nic.get("ipv4") and nic.get("prefix") is not None:
        ipv4 = f"{nic['ipv4']}/{nic['prefix']}"
    if nic.get("dhcp"):
        dhcp = "on" + (f", server {nic['dhcp_server']}" if nic.get("dhcp_server") else "")
    else:
        dhcp = "off (static address)"
    adapter = str(nic.get("name") or "-") + ("" if nic.get("internet", True) else " (no internet route)")
    warnings = [WARNING_TEXT.get(str(w), str(w)) for w in sec.get("warnings") or []]
    router = router_text(network)
    pairs = [("Adapter", adapter), ("IPv4", ipv4), ("Gateway", nic.get("gateway")),
             ("DNS", ", ".join(str(d) for d in (nic.get("dns") or [])[:3])), ("DHCP", dhcp), ("MAC", nic.get("mac")),
             ("Link speed", _bps(nic.get("link_bps"))), ("Public IP", sec.get("public_ip")), ("ISP", sec.get("isp")),
             ("Type", nic.get("type_name")), ("Hardware", nic.get("description")),
             ("Warnings", ", ".join(warnings) or "none")]
    if router:
        # the router and its vendor first, each a cell of its own (a vendor never cuts the MAC short); the link speed joins the
        # adapter and its type the hardware, so the grid stays four rows
        link = _bps(nic.get("link_bps"))
        hardware = " · ".join(str(x) for x in (nic.get("description"), nic.get("type_name")) if x) or None
        pairs = [("Router", router[0]), ("Vendor", router[1] or None),
                 ("Adapter", adapter + (f", {link}" if nic.get("link_bps") and link and link != "-" else ""))]
        pairs += [("IPv4", ipv4), ("Gateway", nic.get("gateway")), ("DNS", ", ".join(str(d) for d in (nic.get("dns") or [])[:3])),
                  ("DHCP", dhcp), ("This PC's MAC", nic.get("mac")), ("Public IP", sec.get("public_ip")), ("ISP", sec.get("isp")),
                  ("Hardware", hardware), ("Warnings", ", ".join(warnings) or "none")]
    out.append(_kv(pairs))
    return out


def _speed_block(sec: Dict[str, Any], clock: _Clock) -> List[Flowable]:
    res = sec.get("result") if isinstance(sec.get("result"), dict) else None
    out: List[Flowable] = [_heading("Speed test")]
    if sec.get("available") and res:
        # ISP and public IP are the Network block's; the server is named once
        out.append(_kv([
            ("Download", f"{_mbps(res.get('download_mbps'))} Mbps"), ("Upload", f"{_mbps(res.get('upload_mbps'))} Mbps"),
            ("Latency", f"{_ms(res.get('latency_ms'))} ms"), ("Jitter", f"{_ms(res.get('jitter_ms'))} ms"),
            ("Packet loss", _pct(res.get("packet_loss_pct"))), ("Tested", _when(clock, res.get("ts"))),
            ("Server", res.get("server") or res.get("backend")),
        ]))
    else:
        out.append(_para(sec.get("reason") or "No speed test ran", "small"))
    win = sec.get("window") if isinstance(sec.get("window"), dict) else {}
    if win.get("count"):
        out.append(_para(
            f"Speed tests in the window (this scan's included): {win['count']}; download average {_mbps(win.get('download_avg'))} Mbps "
            f"({_mbps(win.get('download_min'))} to {_mbps(win.get('download_max'))}); upload average "
            f"{_mbps(win.get('upload_avg'))} Mbps ({_mbps(win.get('upload_min'))} to {_mbps(win.get('upload_max'))}); "
            f"latency average {_ms(win.get('latency_avg'))} ms.", "small"))
    return out


def _section_note(sec: Dict[str, Any]) -> Optional[str]:
    """A section's ``note`` for its heading (what a new report left out: ``"Left out: 8 removed or disabled targets"``), or None."""
    note = sec.get("note")
    return (note.strip() or None) if isinstance(note, str) else None


def _ping_block(sec: Dict[str, Any]) -> List[Flowable]:
    targets = [t for t in sec.get("targets") or [] if isinstance(t, dict)]
    out: List[Flowable] = [_heading("Ping", _section_note(sec))]
    if not sec.get("available") or not targets:
        out.append(_para(sec.get("reason") or "No ping data", "small"))
        return out
    widths = _col_widths([2.5, 0.8, 1.35, 0.95, 0.75, 0.7, 0.72, 0.72, 0.72, 0.72, 0.8], CONTENT_W)
    data: List[List[Any]] = [["Target", "Role", "Address", "Pings", "Lost", "Loss", "Avg ms", "Min ms", "Max ms",
                              "p95 ms", "Jitter ms"]]
    for t in targets:
        label, host = t.get("label"), t.get("host")
        same = str(label or "").strip().casefold() == str(host or "").strip().casefold()
        name = f"{label} ({host})" if label and not same else (label or host)
        data.append([_cell(name, widths[0]), ROLE_TEXT.get(str(t.get("role")), str(t.get("role") or "-")),
                     _cell(t.get("ip") or "-", widths[2]), _int(t.get("samples")), _int(t.get("lost")),
                     _pct(t.get("loss_pct")), _ms(t.get("avg_ms")), _ms(t.get("min_ms")),
                     _ms(t.get("max_ms")), _ms(t.get("p95_ms")), _ms(t.get("jitter_ms"))])
    out.append(_grid(data, widths, right=range(3, 11)))
    out.append(_para("p95 is the 95th percentile of the 1-minute averages; jitter is the mean change between "
                     "consecutive replies within each minute.", "small"))
    return out


def outage_what(item: Dict[str, Any]) -> str:
    """What an outage item was: ``"Internet down: Public DNS, example.net"``, ``"NVR (172.16.40.20)"``, ``"Not monitoring"``."""
    kind = str(item.get("kind") or "")
    if kind in ("total_local", "total_internet"):
        head = "Local network down" if kind == "total_local" else "Internet down"
        members = [str(t) for t in item.get("targets") or [] if t]
        return head + (": " + ", ".join(members) if members else "")
    if kind == "gap":
        return "Not monitoring"
    return str(item.get("name") or item.get("host") or "A target")


def _outages_block(sec: Dict[str, Any], clock: _Clock, limit: int = CELL_TEXT_MAX) -> List[Flowable]:
    out: List[Flowable] = [_heading("Outages", _section_note(sec), limit)]
    if not sec.get("available"):
        out.append(_para(sec.get("reason") or "Not collected", "small"))
        return out
    by = sec.get("by_kind") if isinstance(sec.get("by_kind"), dict) else {}
    down = sec.get("downtime_s") if isinstance(sec.get("downtime_s"), dict) else {}
    numbers = outage_numbers(sec) or {"network": 0, "targets": 0}
    count = int(sec.get("count") or 0)
    line = (f"{count} outage{'s' if count != 1 else ''}: {_int(numbers['network'])} of the network "
            f"(a whole group of targets down, {_fmt_duration(sec.get('network_down_s') or 0)} in all; longest "
            f"{_fmt_duration(sec.get('longest_s')) if _is_num(sec.get('longest_s')) else '-'}) and "
            f"{_int(numbers['targets'])} of a single target")
    if by.get("gap"):
        line += f"; not monitoring for {_fmt_duration(down.get('gap') or 0)}"
    out.append(_para(line + ".", "body"))
    items = [i for i in sec.get("items") or [] if isinstance(i, dict)]
    if items:
        widths = _col_widths([1.2, 1.2, 0.95, 2.9, 0.7, 1.7], CONTENT_W)
        data: List[List[Any]] = [["Start", "End", "Duration", "What", "Missed", "Note"]]
        for it in items:
            kind = str(it.get("kind") or "")
            note = str(it.get("note") or "")
            if kind == "gap" and note.strip().casefold() == "not monitoring":
                note = ""                               # the What column says it
            data.append([_when(clock, it.get("start_ts")), "ongoing" if it.get("open") else _when(clock, it.get("end_ts")),
                         _fmt_duration(it.get("duration_s")), Paragraph(_esc(_clip(outage_what(it), limit)), STYLES["small"]),
                         _fmt_missed_pct(it.get("missed_pct")) if kind == "target" else "",
                         Paragraph(_esc(_clip(note, limit)), STYLES["small"])])     # both wrap
        out.append(_grid(data, widths, right=(2, 4)))
    total = int(sec.get("items_total") or 0)
    if total > len(items):
        more = total - len(items)
        out.append(_para(f"{more} older outage{' is' if more == 1 else 's are'} not listed.", "small"))
    return out


def _discovery_block(sec: Dict[str, Any]) -> List[Flowable]:
    note = " · ".join(x for x in (str(sec.get("range") or ""), f"took {_fmt_duration(sec.get('duration_s'))}"
                                  if _is_num(sec.get("duration_s")) else "") if x)
    out: List[Flowable] = [_heading("Discovery", note)]
    if not sec.get("available"):
        out.append(_para(sec.get("reason") or "No Discovery scan ran", "small"))
        return out
    types = ", ".join(f"{t} {n}" for t, n in (sec.get("device_types") or {}).items())
    count = int(sec.get("host_count") or 0)
    line = f"{count} device{'s' if count != 1 else ''} found" + (f": {types}" if types else "") + "."
    if sec.get("note"):
        line += f" {sec['note']}."
    out.append(_para(line, "body"))
    hosts = [h for h in sec.get("hosts") or [] if isinstance(h, dict)]
    if hosts:
        widths = _col_widths([1.05, 2.0, 1.25, 2.1, 0.8, 1.5], CONTENT_W)
        data: List[List[Any]] = [["IP", "Hostname", "MAC", "Vendor", "Type", "Open ports"]]
        for h in hosts:
            ports = ", ".join(str(p) for p in h.get("open_ports") or [])
            data.append([_cell(h.get("ip"), widths[0]), _cell(h.get("hostname") or "-", widths[1]),
                         _cell(h.get("mac") or "-", widths[2]), _cell(h.get("vendor") or "-", widths[3]),
                         _cell(h.get("device_type") or "", widths[4]), _cell(ports or "-", widths[5])])
        out.append(_grid(data, widths))
    total = int(sec.get("hosts_total") or 0)
    if total > len(hosts):
        more = total - len(hosts)
        out.append(_para(f"{more} more device{' is' if more == 1 else 's are'} not listed.", "small"))
    return out


def _wifi_block(sec: Dict[str, Any], clock: _Clock) -> List[Flowable]:
    out: List[Flowable] = [_heading("Wi-Fi", sec.get("adapter"))]
    if not sec.get("available"):
        out.append(_para(sec.get("reason") or "Not collected", "small"))
        return out
    conn = sec.get("connected") if isinstance(sec.get("connected"), dict) else None
    if conn:
        where = []
        if conn.get("channel") is not None:
            where.append(f"channel {conn['channel']}")
        if conn.get("band"):
            where.append(f"{conn['band']} GHz")
        if conn.get("width_mhz"):
            where.append(f"{conn['width_mhz']} MHz")
        line = f"Connected to {conn.get('ssid') or '(hidden network)'}"
        if conn.get("bssid"):
            line += f" ({conn['bssid']})"
        if _is_num(conn.get("rssi")):
            line += f" at {_dbm(conn['rssi'])}"
        if where:
            line += f", {', '.join(where)}"
        if _is_num(conn.get("channel_aps")):
            n = int(conn["channel_aps"])
            line += f"; {_int(n)} access point{'s' if n != 1 else ''} on that channel"
            if _is_num(conn.get("overlap_aps")) and conn["overlap_aps"] > n:
                line += f", {_int(conn['overlap_aps'])} overlapping it"
        line += "."
    else:
        line = "Not connected to Wi-Fi."
    line += (f" {_int(sec.get('aps_count'))} access points and {_int(sec.get('networks'))} networks seen "
             f"{_when(clock, sec.get('collected_ts'))}.")
    out.append(_para(line, "body"))
    bands = sec.get("bands") if isinstance(sec.get("bands"), dict) else {}
    band_rows = [(b, bands[b]) for b in ("2.4", "5", "6") if isinstance(bands.get(b), dict) and bands[b].get("aps")]
    if band_rows:
        widths = _col_widths([0.8, 0.6, 0.8, 0.9, 0.9, 1.6], CONTENT_W * 0.62)
        data: List[List[Any]] = [["Band", "APs", "Networks", "Strongest", "Median", "Busiest channel"]]
        for band, st in band_rows:
            busiest = "-"
            if st.get("busiest_channel") is not None:
                busiest = f"{st['busiest_channel']} ({_int(st.get('busiest_channel_aps'))} APs)"
            data.append([f"{band} GHz", _int(st.get("aps")), _int(st.get("networks")), _dbm(st.get("strongest_rssi")),
                         _dbm(st.get("median_rssi")), busiest])
        out.append(Spacer(1, 2))
        out.append(_grid(data, widths, right=(1, 2, 3, 4)))
    aps = [a for a in sec.get("aps") or [] if isinstance(a, dict)]
    if aps:
        shown = aps[:MAX_PDF_APS]
        widths = _col_widths([1.9, 1.15, 0.45, 0.4, 0.5, 0.65, 1.25, 0.75, 1.85], CONTENT_W)
        data = [["SSID", "BSSID", "Band", "Ch", "Width", "Signal", "Security", "Standard", "Vendor"]]
        extra: List[Tuple[Any, ...]] = []
        for i, ap in enumerate(shown, start=1):
            ssid = "(hidden)" if ap.get("hidden") or not ap.get("ssid") else ap.get("ssid")
            data.append([_cell(ssid, widths[0]), _cell(ap.get("bssid"), widths[1]), ap.get("band") or "-",
                         _int(ap.get("channel")), f"{ap['width_mhz']}" if ap.get("width_mhz") else "-", _dbm(ap.get("rssi")),
                         _cell(ap.get("security") or "-", widths[6]), _cell(ap.get("generation") or "-", widths[7]),
                         _cell(ap.get("vendor") or "-", widths[8])])
            if ap.get("connected"):
                extra.append(("FONTNAME", (0, i), (-1, i), BOLD))
        out.append(Spacer(1, 3))
        out.append(_grid(data, widths, right=(3, 4, 5), extra=extra))
        hidden_count = int(sec.get("aps_total") or len(aps)) - len(shown)
        if hidden_count > 0:
            out.append(_para(f"{hidden_count} weaker access point{' is' if hidden_count == 1 else 's are'} not listed.", "small"))
        if any(ap.get("connected") for ap in shown):
            out.append(_para("The access point this PC is connected to is in bold.", "small"))
    return out


def build_site_report(report: Dict[str, Any], tz_offset_s: Optional[int] = None) -> bytes:
    """The compact PDF of one stored report (``Database.get_report`` dict)."""
    data = report.get("data") if isinstance(report.get("data"), dict) else {}
    clock = _Clock(tz_offset_s)

    def sec(key: str) -> Dict[str, Any]:
        value = data.get(key)
        return value if isinstance(value, dict) else {}

    site = report.get("site") or sec("meta").get("site") or "Unnamed site"
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}

    def story(limit: int) -> List[Flowable]:
        out: List[Flowable] = []
        out += _block("Header", lambda: _site_header(report, data, clock))
        out += _block("Key numbers", lambda: [_key_numbers(summary, data)])
        out += _block("Network", lambda: _network_block(sec("network"), sec("meta").get("network")))
        out += _block("Speed test", lambda: _speed_block(sec("speed"), clock))
        out += _block("Ping", lambda: _ping_block(sec("ping")))
        out += _block("Outages", lambda: _outages_block(sec("outages"), clock, limit))
        out += _block("Discovery", lambda: _discovery_block(sec("discovery")))
        out += _block("Wi-Fi", lambda: _wifi_block(sec("wifi"), clock))
        return out

    footer = f"{APP_LONG_NAME} v{__version__}  ·  Site report: {site}  ·  scanned {_when(clock, report.get('created_ts'))}"
    pdf = _render(story, f"TNT site report: {site}", footer)
    log.info("built the site report PDF for report %s: %d bytes", report.get("id"), len(pdf))
    return pdf


# --------------------------------------------------------------------------------------
# comparison
# --------------------------------------------------------------------------------------
#: one line under each section's title, for a reader who is not a technician
SECTION_GLOSSARY = {
    "speed": "Download and upload are what the speed test could move; latency is the delay to the test server, jitter "
             "how much that delay varies.",
    "ping": "From this PC's pings over each window: the average, p95 (95 % of the 1-minute averages were at or below it), "
            "loss. The maximum is a single ping, shown for information.",
    "outages": "A network outage is the local network or the internet not answering at all; a single-target outage is one "
               "device or server. Rates are per day monitored.",
    "wifi": "Signal in dBm: closer to 0 is stronger (-50 is excellent, -67 good for calls, below -75 weak). Only the network "
            "this PC used is judged; other networks are shown for information.",
    "discovery": "Devices that answered on each network, for information.",
}
TOLERANCE_TEXT = ("A - B is A minus B. Green marks the better value and red the worse; grey rows are for information. "
                  "Values count as the same when they differ by no more than 2 % of the larger one, or by 1 Mbps, 1 ms, "
                  "0.1 percentage point of loss, 1 dBm, 0.1 outage a day or 1 minute.")


def _rows_by_key(comparison: Any) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for section in (comparison or {}).get("sections") or []:
        if isinstance(section, dict):
            for row in section.get("rows") or []:
                if isinstance(row, dict) and row.get("key"):
                    out[f"{section.get('key')}.{row['key']}"] = row
    return out


def _change(row: Dict[str, Any], more: str, less: str) -> Optional[str]:
    """``"97 % slower"``, ``"33 times faster"``, ``"about the same"``, or None without both values."""
    delta, pct = row.get("delta"), row.get("delta_pct")
    if not _is_num(delta):
        return None
    if row.get("better") == "same" or delta == 0:
        return "about the same"
    word = more if delta > 0 else less
    if _is_num(pct):
        if abs(pct) > MAX_REL_PCT and _is_num(row.get("a")) and _is_num(row.get("b")) and min(row["a"], row["b"]) > 0:
            return f"{max(row['a'], row['b']) / min(row['a'], row['b']):.0f} times {word}"
        return f"{abs(pct):.0f} % {word}"
    return None


def compare_highlights(comparison: Any) -> List[str]:
    """Up to five plain sentences about A against B (the reference): speed, loss, latency, Wi-Fi, outages."""
    rows = _rows_by_key(comparison)
    lines: List[str] = []

    def both(row: Optional[Dict[str, Any]]) -> bool:
        return bool(row) and _is_num(row.get("a")) and _is_num(row.get("b"))

    down, up = rows.get("speed.download_mbps"), rows.get("speed.upload_mbps")
    if both(down):
        text = f"Download {_change(down, 'faster', 'slower')} ({_mbps(down['a'])} vs {_mbps(down['b'])} Mbps)"
        if both(up):
            text += f"; upload {_change(up, 'faster', 'slower')} ({_mbps(up['a'])} vs {_mbps(up['b'])} Mbps)"
        lines.append(text + ".")
    losses = [(label, rows.get(key)) for label, key in (("to the gateway", "ping.gateway_loss_pct"),
                                                        ("to the internet", "ping.internet_loss_pct"))]
    loss_bits = [f"{label} {_pct(row['a'])} vs {_pct(row['b'])}" for label, row in losses if both(row)]
    if loss_bits:
        lines.append("Packet loss " + "; ".join(loss_bits) + ".")
    latency = rows.get("ping.internet_avg_ms")
    if both(latency):
        lines.append(f"Internet latency {_change(latency, 'higher', 'lower')} ({_ms(latency['a'])} vs {_ms(latency['b'])} ms).")
    signal = rows.get("wifi.connected_rssi")
    if both(signal):
        diff = signal["a"] - signal["b"]
        text = ("Wi-Fi signal about the same" if signal.get("better") == "same" else
                f"Wi-Fi signal {abs(_half_up(diff))} dB {'stronger' if diff > 0 else 'weaker'}")
        text += f" ({_dbm(signal['a'])} vs {_dbm(signal['b'])})"
        crowd = rows.get("wifi.connected_channel_aps")
        if crowd and _is_num(crowd.get("a")) and crowd["a"] > 1:
            others = int(crowd["a"]) - 1
            text += f"; {others} other access point{'s' if others != 1 else ''} share{'s' if others == 1 else ''} its channel"
        lines.append(text + ".")
    rated = rows.get("outages.outages_per_day")
    counted = rows.get("outages.network_outages")
    if both(rated):
        longest = rows.get("outages.longest_outage_min")
        text = f"Network outages {_value(rated['a'], 'per day')} vs {_value(rated['b'], 'per day')} a day"
        if both(longest):
            text += f"; the longest {_fmt_duration(longest['a'] * 60)} vs {_fmt_duration(longest['b'] * 60)}"
        lines.append(text + ".")
    elif both(counted):
        lines.append(f"Network outages: {_int(counted['a'])} vs {_int(counted['b'])} in each window "
                     "(too little history to compare daily rates).")
    return lines[:5]


def _compare_table(rows: Sequence[Dict[str, Any]], name_a: str, name_b: str, limit: int = CELL_TEXT_MAX) -> Table:
    widths = _col_widths([2.4, 0.75, 0.75, 1.1, 1.3, 2.2], CONTENT_W)
    data: List[List[Any]] = [["Metric", "A", "B", "A - B", "Better", "Note"]]
    extra: List[Tuple[Any, ...]] = []
    for i, row in enumerate(rows, start=1):
        unit = str(row.get("unit") or "")
        label = str(row.get("label") or row.get("key") or "")
        if unit and unit.casefold() not in label.casefold() and unit not in COUNT_UNITS[1:]:
            label = f"{label} ({unit})"                 # "Outages per day" needs no "(per day)", a count no "(APs)"
        better = row.get("better")
        data.append([_cell(label, widths[0]), _value(row.get("a"), unit), _value(row.get("b"), unit),
                     _difference(row.get("delta"), row.get("delta_pct"), unit, better),
                     _cell({"a": name_a, "b": name_b, "same": "same"}.get(str(better), ""), widths[4]),
                     Paragraph(_esc(_clip(row.get("note") or "", limit)), STYLES["small"])])     # a note wraps
        if better == "a":
            extra += [("BACKGROUND", (1, i), (1, i), BETTER_FILL), ("BACKGROUND", (2, i), (2, i), WORSE_FILL)]
        elif better == "b":
            extra += [("BACKGROUND", (1, i), (1, i), WORSE_FILL), ("BACKGROUND", (2, i), (2, i), BETTER_FILL)]
        if row.get("higher_is_better") is None:
            extra.append(("TEXTCOLOR", (0, i), (-1, i), INK_SOFT))
    return _grid(data, widths, right=(1, 2, 3), extra=extra)


def _side_line(side: str, rep: Dict[str, Any], clock: _Clock, reference: bool) -> str:
    data = rep.get("data") if isinstance(rep.get("data"), dict) else {}
    parts = [f"{side}: {rep.get('site') or 'Unnamed site'}" + (" (the reference)" if reference else ""),
             f"scanned {_when(clock, rep.get('created_ts'))}", str(rep.get("status") or "-")]
    ping = data.get("ping") if isinstance(data.get("ping"), dict) else {}
    start, end = ping.get("window_start"), ping.get("window_end")
    if _is_num(start) and _is_num(end):
        words = WINDOW_WORDS.get(str(ping.get("window_reason")), "")
        span = span_text(end - start)
        numbers = outage_numbers(data.get("outages"))
        on_network = network_time(data)
        if on_network is not None:
            # "(3 visits, 23 h 37 min on its network)": the dates already show the week; the site PDF's duration format
            count = on_network[1]
            parts.append(f"pings and outages {_when(clock, start)} to {_when(clock, end)} "
                         f"({count} visit{'s' if count != 1 else ''}, {_fmt_duration(on_network[0])} on its network)")
            return "  ·  ".join(parts)
        if numbers:
            span = monitored_text(numbers) + (" monitored" if numbers["window"] - numbers["monitored"] >= 60 else "")
        parts.append(f"pings and outages {_when(clock, start)} to {_when(clock, end)} ({span}{', ' + words if words else ''})")
    return "  ·  ".join(parts)


def build_compare_report(a: Dict[str, Any], b: Dict[str, Any], comparison: Dict[str, Any],
                         tz_offset_s: Optional[int] = None) -> bytes:
    """The compact PDF of a comparison of report *a* (the scan being judged) with report *b* (the reference)."""
    clock = _Clock(tz_offset_s)
    site_a, site_b = a.get("site") or "Unnamed site", b.get("site") or "Unnamed site"
    same = str(site_a).strip().casefold() == str(site_b).strip().casefold()
    if same:
        title = f"{site_a}: the scan of {_when(clock, a.get('created_ts'))} compared with {_when(clock, b.get('created_ts'))} (reference)"
        name_a, name_b = "A", "B (reference)"
    else:
        title = f"{site_a} compared with {site_b} (reference)"
        name_a, name_b = str(site_a), str(site_b)

    def story(limit: int) -> List[Flowable]:
        out: List[Flowable] = [_para(title, "title")]
        out.append(_para(_side_line("A", a, clock, False), "sub"))
        out.append(_para(_side_line("B", b, clock, True), "sub"))
        for note in comparison.get("notes") or []:          # "A and B were scanned on the same network (...)"
            # the time on their networks is in the side lines already, in this PDF's format
            if isinstance(note, str) and note.strip() and not note.startswith(NETWORK_TIME_NOTE):
                out.append(_para(note, "sub"))
        highlights = compare_highlights(comparison)
        if highlights:
            out.append(Spacer(1, 3))
            out.append(Paragraph("<b>In short.</b> " + " ".join(_esc(_safe(h)) for h in highlights), STYLES["body"]))
        out.append(_para(TOLERANCE_TEXT, "small"))
        for section in comparison.get("sections") or []:
            if not isinstance(section, dict):
                continue
            section_title = str(section.get("title") or section.get("key") or "")
            rows = [r for r in section.get("rows") or [] if isinstance(r, dict)]

            def render(section_title: str = section_title, rows: List[Dict[str, Any]] = rows, note: Any = section.get("note"),
                       key: Any = section.get("key")) -> List[Flowable]:
                block: List[Flowable] = [_heading(section_title, note, limit)]
                if SECTION_GLOSSARY.get(str(key)):
                    block.append(_para(SECTION_GLOSSARY[str(key)], "small"))
                block.append(_compare_table(rows, name_a, name_b, limit) if rows else _para("Nothing to compare in this section.", "small"))
                return block

            out += _block(section_title, render)
        return out

    footer = f"{APP_LONG_NAME} v{__version__}  ·  Comparison: {site_a} vs {site_b}"
    pdf = _render(story, f"TNT comparison: {site_a} vs {site_b}", footer)
    log.info("built the comparison PDF for reports %s and %s: %d bytes", a.get("id"), b.get("id"), len(pdf))
    return pdf


__all__ = ["build_compare_report", "build_site_report", "compare_highlights", "key_levels", "outage_what", "router_text",
           "MAX_PDF_APS", "UNKNOWN_NETWORK_TEXT"]
