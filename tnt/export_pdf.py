"""PDF report export for TNT.

Public API
----------
``build_report(db, start_ts, end_ts, *, title=..., targets=None, netinfo=None, tz_offset_s=None) -> bytes``
    Render a complete report for the period ``[start_ts, end_ts]`` and return the PDF bytes.
``range_bounds(kind, now, custom_from=None, custom_to=None) -> (start_ts, end_ts)``
    Translate a range keyword (daily/weekly/monthly/yearly/custom) into epoch bounds.

Rendering uses reportlab platypus + ``reportlab.graphics`` only (no matplotlib) on Letter
paper, in the UI's visual language: rounded "sticker" boxes with hard offset shadows, pastel
fills, ink ``#2B2438`` outlines and text, big friendly headings, tabular numbers
(Helvetica digits are equal-width).

Decisions where the contract is silent
--------------------------------------
* ``range_bounds``: the kind is case-insensitive; an unknown kind raises ``ValueError`` (the
  API maps that to a 400).  For ``custom``: a missing ``custom_to`` means *now*, a missing
  ``custom_from`` means 24 h before the end, reversed bounds are swapped, and an empty period
  (equal bounds) is widened to the 24 h ending at ``custom_to``.
* Memory stays bounded for a yearly report: ping minutes and speed tests are read from the
  database in time chunks and folded into running aggregates and at most ~500 chart buckets.
  The only per-row structure kept is a slim list of speed results (ts/ok/down/up/latency)
  that feeds the pattern findings.
* Timeline strips: every local day is drawn when the period spans <= 31 days; for longer
  periods only days containing an outage or monitoring gap are drawn (capped at 100, with a
  note) so a yearly report is not 365 identical green bars.
* Grey ("not monitoring") on the strips comes from two sources: ``gap`` outage rows written by
  the OutageTracker *and* the absence of ping minute rows (derived while bucketing, bridging
  holes shorter than ``COVERAGE_HOLE_S``).  Without the second source a report run shortly after
  installation would show weeks of "monitoring OK" for time the service did not exist.
* Long tables are capped (200 outages, 400 discovery hosts) with an "and N more" note.
* Speed findings come from ``tnt.speedtest.patterns.analyse_patterns`` when it is importable
  and works; otherwise a small local rule set produces equivalent plain-English strings.
* ``netinfo`` may be either the ``/api/status`` shape (``{"internet_nic": {...}}``) or a full
  ``netinfo_snapshot()`` dict; both are understood and anything else is ignored.
* Local time uses ``tz_offset_s`` (fixed offset) when given, otherwise the machine's local
  zone via ``datetime.fromtimestamp`` (DST-aware).
* A failure while gathering one section's data is logged and rendered as a "could not load"
  box instead of failing the whole report.  ``build_report`` still raises if reportlab itself
  cannot produce a document.
"""
from __future__ import annotations

import ipaddress
import logging
import math
import socket
import statistics
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from xml.sax.saxutils import escape as _xml_escape

from reportlab.graphics.shapes import Drawing, Line, PolyLine, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import Flowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from . import APP_LONG_NAME, __version__
from .outages import missed_percentage

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------------------
# Palette (the UI's light theme) and geometry
# --------------------------------------------------------------------------------------
INK = colors.HexColor("#2B2438")
INK_SOFT = colors.HexColor("#6B6480")
BG = colors.HexColor("#FFF7E8")
PAPER = colors.white
PAPER2 = colors.HexColor("#FFF1D6")
RED = colors.HexColor("#FF5C5C")
YELLOW = colors.HexColor("#FFD166")
GREEN = colors.HexColor("#6BCB77")
BLUE = colors.HexColor("#6FA8FF")
PURPLE = colors.HexColor("#B48CFF")
ORANGE = colors.HexColor("#FFA45C")
GREY = colors.HexColor("#C9C4D6")

FONT = "Helvetica"
BOLD = "Helvetica-Bold"

PAGE_W, PAGE_H = letter
MARGIN = 0.65 * inch
CONTENT_W = PAGE_W - 2 * MARGIN

RANGE_DAYS: Dict[str, int] = {"daily": 1, "weekly": 7, "monthly": 30, "yearly": 365}

MAX_CHART_POINTS = 500
MAX_OUTAGE_ROWS = 200
MAX_HOST_ROWS = 400
MAX_TIMELINE_DAYS_ALL = 31       # draw every day up to this many days
MAX_TIMELINE_DAYS_EVENTS = 100   # otherwise only days with events, capped here
TIMELINE_DAYS_PER_BLOCK = 7
PING_CHUNK_S = 14 * 86400        # ~20k minute rows per target per DB read
SPEED_CHUNK_S = 30 * 86400       # ~3k rows per DB read at 15-min tests
MAX_FINDINGS = 8
COVERAGE_HOLE_S = 120            # missing minutes shorter than this do not break a monitoring run


def _mix(a: colors.Color, b: colors.Color, t: float) -> colors.Color:
    """Linear blend: t=0 -> a, t=1 -> b."""
    return colors.Color(a.red + (b.red - a.red) * t, a.green + (b.green - a.green) * t, a.blue + (b.blue - a.blue) * t)


def _tint(c: colors.Color, amount: float = 0.18) -> colors.Color:
    """Pastel version of an accent colour (accent at *amount* over white)."""
    return _mix(PAPER, c, amount)


GRID = _mix(INK, PAPER, 0.85)
DIVIDER = _mix(INK, PAPER, 0.75)


# --------------------------------------------------------------------------------------
# Public: range bounds
# --------------------------------------------------------------------------------------
def range_bounds(kind: str, now: float, custom_from: Optional[float] = None,
                 custom_to: Optional[float] = None) -> Tuple[float, float]:
    """Return ``(start_ts, end_ts)`` for a report range keyword.

    ``kind``: ``daily`` (last 24 h), ``weekly`` (7 d), ``monthly`` (30 d), ``yearly`` (365 d)
    or ``custom`` (uses ``custom_from``/``custom_to``, see module docstring for defaults).
    Raises ``ValueError`` for an unknown kind.
    """
    k = str(kind or "daily").strip().lower()
    now_f = float(now)
    if k == "custom":
        end = float(custom_to) if custom_to is not None else now_f
        start = float(custom_from) if custom_from is not None else end - 86400.0
        if start > end:
            start, end = end, start
        if end - start < 1.0:
            start = end - 86400.0
        return start, end
    days = RANGE_DAYS.get(k)
    if days is None:
        raise ValueError(f"unknown report range {kind!r} (expected daily, weekly, monthly, yearly or custom)")
    return now_f - days * 86400.0, now_f


# --------------------------------------------------------------------------------------
# Local-time helper
# --------------------------------------------------------------------------------------
class _Clock:
    """Epoch <-> local time. Fixed offset when ``tz_offset_s`` is given, else system local (DST-aware)."""

    def __init__(self, tz_offset_s: Optional[int]) -> None:
        self.fixed = tz_offset_s is not None
        self.tz = timezone(timedelta(seconds=int(tz_offset_s))) if self.fixed else None

    def local(self, ts: float) -> datetime:
        try:
            return datetime.fromtimestamp(float(ts), self.tz)
        except (OverflowError, OSError, ValueError):
            return datetime.fromtimestamp(0, self.tz)

    def offset(self, ts: float) -> int:
        if self.tz is not None:
            return int(self.tz.utcoffset(None).total_seconds())  # type: ignore[union-attr]
        try:
            return int(time.localtime(float(ts)).tm_gmtoff)
        except (OverflowError, OSError, ValueError):
            return 0

    def day_start(self, ts: float) -> float:
        return self.local(ts).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()

    def add_days(self, ts: float, n: int) -> float:
        return (self.local(ts) + timedelta(days=n)).timestamp()

    def fmt(self, ts: float, pattern: str = "%d %b %Y %H:%M") -> str:
        return self.local(ts).strftime(pattern)

    def hour(self, ts: float) -> int:
        return self.local(ts).hour

    def zone_label(self, ts: float) -> str:
        off = self.offset(ts)
        sign = "+" if off >= 0 else "-"
        off = abs(off)
        return f"UTC{sign}{off // 3600:02d}:{(off % 3600) // 60:02d}"


# --------------------------------------------------------------------------------------
# Formatting helpers
# --------------------------------------------------------------------------------------
def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _fmt_num(v: Any, digits: int = 1) -> str:
    if not _is_num(v):
        return "-"
    return f"{v:,.{digits}f}"


def _fmt_int(v: Any) -> str:
    if not _is_num(v):
        return "-"
    return f"{int(round(v)):,}"


def _fmt_missed_pct(pct: Any, estimated: bool = False) -> str:
    """Missed % like the Outages page: floored to one decimal so it never reads 100% while a
    ping still got through; "~" marks an estimate (Helvetica has no approximately-equal sign)."""
    if not _is_num(pct):
        return "-"
    p = float(pct)
    if p >= 100:
        text = "100%"
    elif p <= 0:
        text = "0%"
    elif p < 0.1:
        text = "<0.1%"
    else:
        text = f"{math.floor(p * 10) / 10:.1f}%"
    return ("~" if estimated else "") + text


def _fmt_ms(v: Any) -> str:
    if not _is_num(v):
        return "-"
    return f"{v:.2f}" if v < 1 else f"{v:,.1f}"


def _fmt_pct(v: Any) -> str:
    if not _is_num(v):
        return "-"
    return f"{v:.2f}%"


def _fmt_duration(s: Any) -> str:
    if not _is_num(s):
        return "-"
    s = max(0, int(round(s)))
    if s < 60:
        return f"{s} s"
    m, sec = divmod(s, 60)
    if m < 60:
        return f"{m} min {sec:02d} s"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h} h {m:02d} min"
    d, h = divmod(h, 24)
    return f"{d} d {h} h"


def _fmt_tick(v: float) -> str:
    if abs(v - round(v)) < 1e-9:
        return f"{int(round(v)):,}"
    return f"{v:g}"


def _fit(text: Any, width: float, font: str = FONT, size: float = 9) -> str:
    """Ellipsize *text* so it fits in *width* points."""
    s = "" if text is None else str(text)
    if stringWidth(s, font, size) <= width:
        return s
    ell = "…"
    lo, hi = 0, len(s)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if stringWidth(s[:mid] + ell, font, size) <= width:
            lo = mid
        else:
            hi = mid - 1
    return s[:lo] + ell


def _esc(s: Any) -> str:
    return _xml_escape("" if s is None else str(s))


def _guess_kind(host: str) -> str:
    """"local"/"internet" for display when the DB kind is "auto"."""
    try:
        from . import netinfo  # type: ignore
        k = netinfo.classify_ip(host)
        if k in ("local", "internet"):
            return k
    except Exception:  # noqa: BLE001 - optional module / hostname
        pass
    try:
        ip = ipaddress.ip_address(host)
        return "local" if (ip.is_private or ip.is_link_local or ip.is_loopback) else "internet"
    except ValueError:
        return "internet"


# --------------------------------------------------------------------------------------
# Styles
# --------------------------------------------------------------------------------------
def _make_styles() -> Dict[str, ParagraphStyle]:
    body = ParagraphStyle("tnt_body", fontName=FONT, fontSize=10, leading=14, textColor=INK)
    return {
        "title": ParagraphStyle("tnt_title", fontName=BOLD, fontSize=27, leading=31, textColor=INK),
        "subtitle": ParagraphStyle("tnt_subtitle", fontName=BOLD, fontSize=11, leading=15, textColor=INK_SOFT),
        "body": body,
        "small": ParagraphStyle("tnt_small", fontName=FONT, fontSize=8.5, leading=11.5, textColor=INK_SOFT),
        "h3": ParagraphStyle("tnt_h3", fontName=BOLD, fontSize=12, leading=15, textColor=INK, spaceBefore=4, spaceAfter=3),
        "card_label": ParagraphStyle("tnt_card_label", fontName=BOLD, fontSize=7.5, leading=9.5, textColor=INK_SOFT),
        "card_value": ParagraphStyle("tnt_card_value", fontName=BOLD, fontSize=18, leading=22, textColor=INK),
        "card_sub": ParagraphStyle("tnt_card_sub", fontName=FONT, fontSize=8.5, leading=11, textColor=INK_SOFT),
        "bullet": ParagraphStyle("tnt_bullet", parent=body, leftIndent=12, bulletIndent=0, spaceAfter=2),
        "note": ParagraphStyle("tnt_note", fontName=BOLD, fontSize=11.5, leading=15, textColor=INK, alignment=TA_CENTER),
        "note_sub": ParagraphStyle("tnt_note_sub", fontName=FONT, fontSize=9, leading=12, textColor=INK_SOFT, alignment=TA_CENTER),
        "kv_key": ParagraphStyle("tnt_kv_key", fontName=BOLD, fontSize=9, leading=12, textColor=INK_SOFT),
        "kv_val": ParagraphStyle("tnt_kv_val", fontName=FONT, fontSize=10, leading=12, textColor=INK),
    }


STYLES = _make_styles()


# --------------------------------------------------------------------------------------
# Custom flowables
# --------------------------------------------------------------------------------------
class RoundedBox(Flowable):
    """A sticker-style rounded box (pastel fill, ink outline, hard offset shadow) around flowables.

    Not splittable: keep the content short (a few paragraphs or a small table).
    """

    def __init__(self, content: Sequence[Flowable], fill: colors.Color = PAPER, stroke: colors.Color = INK,
                 radius: float = 12, padding: float = 10, shadow: float = 4, stroke_width: float = 1.8,
                 width: Optional[float] = None, min_height: float = 0) -> None:
        super().__init__()
        self.content = list(content)
        self.fill = fill
        self.stroke = stroke
        self.radius = radius
        self.padding = padding
        self.shadow = shadow
        self.stroke_width = stroke_width
        self.fixed_width = width
        self.min_height = min_height
        self._w = self._h = self._box_h = 0.0
        self._hs: List[float] = []

    def wrap(self, availWidth: float, availHeight: float) -> Tuple[float, float]:
        self._w = float(self.fixed_width or availWidth)
        inner = max(10.0, self._w - self.shadow - 2 * self.padding)
        self._hs = []
        total = 0.0
        for f in self.content:
            _, h = f.wrap(inner, max(availHeight, 10))
            self._hs.append(h)
            total += h
        self._box_h = max(total + 2 * self.padding, self.min_height)
        self._h = self._box_h + self.shadow
        return self._w, self._h

    def draw(self) -> None:
        c = self.canv
        c.saveState()
        bw, bh = self._w - self.shadow, self._box_h
        x, y = 0.0, float(self.shadow)
        if self.shadow:
            c.setFillColor(INK)
            c.roundRect(x + self.shadow, y - self.shadow, bw, bh, self.radius, stroke=0, fill=1)
        c.setFillColor(self.fill)
        c.setStrokeColor(self.stroke)
        c.setLineWidth(self.stroke_width)
        c.roundRect(x, y, bw, bh, self.radius, stroke=1, fill=1)
        cy = y + bh - self.padding
        for f, h in zip(self.content, self._hs):
            cy -= h
            f.drawOn(c, x + self.padding, cy)
        c.restoreState()


class SectionHeading(Flowable):
    """Big friendly section title with an accent sticker and a dashed divider."""

    def __init__(self, text: str, accent: colors.Color, sub: Optional[str] = None) -> None:
        super().__init__()
        self.text = text
        self.accent = accent
        self.sub = sub
        self.keepWithNext = 1
        self._w = 0.0
        self._h = 0.0

    def wrap(self, availWidth: float, availHeight: float) -> Tuple[float, float]:
        self._w = availWidth
        self._h = 36 + (13 if self.sub else 0)
        return self._w, self._h

    def draw(self) -> None:
        c = self.canv
        c.saveState()
        sq = 15
        y_text = self._h - 22
        c.setFillColor(self.accent)
        c.setStrokeColor(INK)
        c.setLineWidth(1.5)
        c.roundRect(0, y_text - 2, sq, sq, 4, stroke=1, fill=1)
        c.setFillColor(INK)
        c.setFont(BOLD, 17)
        c.drawString(sq + 8, y_text, self.text)
        if self.sub:
            c.setFillColor(INK_SOFT)
            c.setFont(FONT, 9)
            c.drawString(sq + 8, y_text - 13, _fit(self.sub, self._w - sq - 8, FONT, 9))
        c.setStrokeColor(DIVIDER)
        c.setLineWidth(1.2)
        c.setDash(3, 3)
        c.line(0, 2, self._w, 2)
        c.restoreState()


# --------------------------------------------------------------------------------------
# Small building blocks
# --------------------------------------------------------------------------------------
def _para(text: str, style: str = "body") -> Paragraph:
    return Paragraph(text, STYLES[style])


def _empty_box(text: str, accent: colors.Color, sub: Optional[str] = None) -> RoundedBox:
    content: List[Flowable] = [_para(_esc(text), "note")]
    if sub:
        content.append(Spacer(1, 3))
        content.append(_para(_esc(sub), "note_sub"))
    return RoundedBox(content, fill=_tint(accent, 0.16), padding=14, radius=14)


def _card(label: str, value: str, sub: str, accent: colors.Color, width: float) -> RoundedBox:
    return RoundedBox(
        [_para(_esc(label.upper()), "card_label"), Spacer(1, 2), _para(_esc(value), "card_value"),
         Spacer(1, 1), _para(_esc(sub), "card_sub")],
        fill=_tint(accent, 0.24), width=width, padding=9, shadow=3, radius=12, stroke_width=1.6,
    )


def _cards_row(cards: Sequence[RoundedBox], width: float, gap: float = 10) -> Table:
    """Lay out sticker cards side by side; every card is stretched to the tallest one's height."""
    n = len(cards)
    cw = (width - gap * (n - 1)) / n
    tallest = 0.0
    for card in cards:
        card.fixed_width = cw
        card.min_height = 0.0
        card.wrap(cw, PAGE_H)
        tallest = max(tallest, card._box_h)
    row: List[Any] = []
    widths: List[float] = []
    for i, card in enumerate(cards):
        card.min_height = tallest
        row.append(card)
        widths.append(cw)
        if i < n - 1:
            row.append("")
            widths.append(gap)
    t = Table([row], colWidths=widths)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


def _col_widths(weights: Sequence[float], width: float) -> List[float]:
    total = float(sum(weights)) or 1.0
    return [width * w / total for w in weights]


def _styled_table(data: List[List[Any]], col_widths: Sequence[float], header_fill: colors.Color,
                  right_cols: Sequence[int] = (), font_size: float = 8.8,
                  extra: Optional[List[Tuple[Any, ...]]] = None) -> Table:
    t = Table(data, colWidths=list(col_widths), repeatRows=1)
    cmds: List[Tuple[Any, ...]] = [
        ("FONTNAME", (0, 0), (-1, 0), BOLD),
        ("FONTNAME", (0, 1), (-1, -1), FONT),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
        ("LEADING", (0, 0), (-1, -1), font_size + 3),
        ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("BACKGROUND", (0, 0), (-1, 0), header_fill),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PAPER, PAPER2]),
        ("BOX", (0, 0), (-1, -1), 1.6, INK),
        ("LINEBELOW", (0, 0), (-1, 0), 1.2, INK),
        ("ROUNDEDCORNERS", [8, 8, 8, 8]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]
    for c in right_cols:
        cmds.append(("ALIGN", (c, 0), (c, -1), "RIGHT"))
    if extra:
        cmds.extend(extra)
    t.setStyle(TableStyle(cmds))
    return t


def _kv_table(rows: Sequence[Tuple[str, str]], width: float) -> Table:
    data = [[_para(_esc(k), "kv_key"), _para(_esc(v), "kv_val")] for k, v in rows]
    t = Table(data, colWidths=[width * 0.3, width * 0.7])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
    ]))
    return t


def _star(cx: float, cy: float, r_out: float, r_in: float) -> List[float]:
    pts: List[float] = []
    for i in range(8):
        r = r_out if i % 2 == 0 else r_in
        a = math.pi / 2 + i * math.pi / 4
        pts.extend([cx + r * math.cos(a), cy + r * math.sin(a)])
    return pts


def _logo(size: float = 46) -> Drawing:
    """Cartoon dynamite stick: red body, ink outline, fuse with an orange spark."""
    s = size / 46.0
    d = Drawing(size, size)
    d.add(Rect(9 * s, 2 * s, 17 * s, 31 * s, rx=5 * s, ry=5 * s, fillColor=RED, strokeColor=INK, strokeWidth=1.6))
    d.add(Rect(9 * s, 13 * s, 17 * s, 5 * s, fillColor=_mix(RED, INK, 0.3), strokeColor=INK, strokeWidth=1.0))
    d.add(PolyLine([17.5 * s, 33 * s, 19 * s, 37 * s, 24 * s, 38 * s, 28 * s, 41 * s],
                   strokeColor=INK, strokeWidth=1.6, strokeLineCap=1, strokeLineJoin=1))
    d.add(Polygon(_star(31 * s, 41 * s, 5.5 * s, 2.2 * s), fillColor=ORANGE, strokeColor=INK, strokeWidth=1))
    return d


# --------------------------------------------------------------------------------------
# Chart helpers (hand-drawn with reportlab.graphics shapes)
# --------------------------------------------------------------------------------------
def _nice_step(vmax: float, n: int = 4) -> float:
    if vmax <= 0:
        return 1.0
    raw = vmax / n
    mag = 10 ** math.floor(math.log10(raw))
    for m in (1, 2, 2.5, 5, 10):
        if m * mag >= raw:
            return m * mag
    return 10 * mag


def _axis(vmax: float, n: int = 4) -> Tuple[float, List[float]]:
    step = _nice_step(vmax, n)
    top = step * math.ceil(vmax / step) if vmax > 0 else step
    if top <= 0:
        top = step
    count = int(round(top / step))
    return top, [i * step for i in range(count + 1)]


def _time_ticks(clock: _Clock, x0: float, x1: float, max_ticks: int = 7) -> List[Tuple[float, str]]:
    span = max(x1 - x0, 1.0)
    steps = [3600, 2 * 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 2 * 86400, 7 * 86400, 14 * 86400,
             30 * 86400, 61 * 86400, 92 * 86400, 183 * 86400]
    step = next((s for s in steps if span / s <= max_ticks), steps[-1])
    ticks: List[Tuple[float, str]] = []
    if step < 86400:
        t = clock.day_start(x0)
        guard = 0
        while t < x0 and guard < 100:
            t += step
            guard += 1
        while t <= x1 and len(ticks) < 40:
            lt = clock.local(t)
            label = lt.strftime("%d %b") if (lt.hour == 0 and lt.minute == 0) else lt.strftime("%H:%M")
            ticks.append((t, label))
            t += step
    else:
        ndays = max(1, int(step // 86400))
        t = clock.day_start(x0)
        if t < x0:
            t = clock.add_days(t, 1)
        pattern = "%b %Y" if ndays >= 30 else "%d %b"
        while t <= x1 and len(ticks) < 40:
            ticks.append((t, clock.fmt(t, pattern)))
            t = clock.add_days(t, ndays)
    return ticks


def _runs(points: Sequence[Optional[Tuple[float, Optional[float]]]]) -> List[List[Tuple[float, float]]]:
    """Split a point list on None entries / None values into contiguous runs."""
    runs: List[List[Tuple[float, float]]] = []
    cur: List[Tuple[float, float]] = []
    for p in points:
        if p is None or p[1] is None or not _is_num(p[1]):
            if cur:
                runs.append(cur)
                cur = []
            continue
        cur.append((p[0], float(p[1])))
    if cur:
        runs.append(cur)
    return runs


def _chart_frame(d: Drawing, width: float, height: float) -> Tuple[float, float]:
    """Sticker frame with shadow; returns (inner width, inner height) of the main rect at (0, 4)."""
    w, h = width - 4, height - 4
    d.add(Rect(4, 0, w, h, rx=10, ry=10, fillColor=INK, strokeColor=None))
    d.add(Rect(0, 4, w, h, rx=10, ry=10, fillColor=PAPER, strokeColor=INK, strokeWidth=1.5))
    return w, h


def _legend(d: Drawing, x: float, y: float, entries: Sequence[Tuple[str, colors.Color, str]]) -> None:
    for label, color, kind in entries:
        if kind == "line":
            d.add(Line(x, y + 3, x + 14, y + 3, strokeColor=color, strokeWidth=2.2, strokeLineCap=1))
        else:
            d.add(Rect(x, y - 1, 12, 8, rx=2, ry=2, fillColor=color, strokeColor=INK, strokeWidth=0.6))
        d.add(String(x + 18, y, label, fontName=FONT, fontSize=7.5, fillColor=INK))
        x += 18 + stringWidth(label, FONT, 7.5) + 12


def _line_chart(width: float, height: float, clock: _Clock, x0: float, x1: float,
                left: Sequence[Dict[str, Any]], right: Optional[Sequence[Dict[str, Any]]] = None,
                band: Optional[Dict[str, Any]] = None, left_unit: str = "", right_unit: str = "",
                right_floor: float = 0.0) -> Drawing:
    """Time-series line chart. Series: {"label", "color", "points": [(ts, value)|None, ...]}.

    ``band`` = {"color", "low": [(ts, v)|None], "high": [(ts, v)|None]} draws a filled min/max band.
    None entries (or None values) break the line so data gaps stay visible.
    """
    d = Drawing(width, height)
    W, H = _chart_frame(d, width, height)
    pl, pr, pt, pb = 46, (46 if right else 14), 22, 24
    px, py = pl, 4 + pb
    pw, ph = W - pl - pr, H - pt - pb
    if x1 <= x0:
        x1 = x0 + 1.0

    def X(t: float) -> float:
        f = (t - x0) / (x1 - x0)
        return px + min(1.0, max(0.0, f)) * pw

    lvals = [p[1] for s in left for p in s["points"] if p is not None and _is_num(p[1])]
    if band:
        lvals += [p[1] for p in band["high"] if p is not None and _is_num(p[1])]
    if not lvals:
        d.add(String(px + pw / 2, py + ph / 2 - 4, "No data in this period", fontName=BOLD, fontSize=10,
                     fillColor=INK_SOFT, textAnchor="middle"))
        return d

    ltop, lticks = _axis(max(lvals))

    def YL(v: float) -> float:
        return py + max(0.0, min(1.0, v / ltop)) * ph

    for v in lticks:
        y = YL(v)
        d.add(Line(px, y, px + pw, y, strokeColor=GRID, strokeWidth=0.6, strokeDashArray=[2, 3]))
        d.add(String(px - 5, y - 2.5, _fmt_tick(v), fontName=FONT, fontSize=7.5, fillColor=INK_SOFT, textAnchor="end"))
    if left_unit:  # baseline level with the legend row so it clears the top tick label
        d.add(String(px - 5, py + ph + 9, left_unit, fontName=BOLD, fontSize=7, fillColor=INK_SOFT, textAnchor="end"))

    for t, label in _time_ticks(clock, x0, x1):
        x = X(t)
        d.add(Line(x, py, x, py + ph, strokeColor=GRID, strokeWidth=0.6, strokeDashArray=[2, 3]))
        d.add(String(x, py - 11, label, fontName=FONT, fontSize=7.5, fillColor=INK_SOFT, textAnchor="middle"))

    if band:
        lows = _runs(band["low"])
        highs = _runs(band["high"])
        for lo, hi in zip(lows, highs):
            if len(lo) < 2 or len(hi) < 2:
                continue
            pts: List[float] = []
            for t, v in hi:
                pts.extend([X(t), YL(v)])
            for t, v in reversed(lo):
                pts.extend([X(t), YL(v)])
            d.add(Polygon(pts, fillColor=band["color"], strokeColor=None))

    for s in left:
        for run in _runs(s["points"]):
            if len(run) == 1:
                t, v = run[0]
                d.add(Rect(X(t) - 1.5, YL(v) - 1.5, 3, 3, fillColor=s["color"], strokeColor=None))
                continue
            flat: List[float] = []
            for t, v in run:
                flat.extend([X(t), YL(v)])
            d.add(PolyLine(flat, strokeColor=s["color"], strokeWidth=1.8, strokeLineJoin=1, strokeLineCap=1))

    if right:
        rvals = [p[1] for s in right for p in s["points"] if p is not None and _is_num(p[1])]
        rtop, rticks = _axis(max([right_floor] + rvals))

        def YR(v: float) -> float:
            return py + max(0.0, min(1.0, v / rtop)) * ph

        for v in rticks:
            d.add(String(px + pw + 5, YR(v) - 2.5, _fmt_tick(v), fontName=FONT, fontSize=7.5, fillColor=INK_SOFT))
        if right_unit:
            d.add(String(px + pw + 5, py + ph + 9, right_unit, fontName=BOLD, fontSize=7, fillColor=INK_SOFT))
        for s in right:
            for run in _runs(s["points"]):
                if len(run) == 1:
                    t, v = run[0]
                    d.add(Rect(X(t) - 1.5, YR(v) - 1.5, 3, 3, fillColor=s["color"], strokeColor=None))
                    continue
                flat = []
                for t, v in run:
                    flat.extend([X(t), YR(v)])
                d.add(PolyLine(flat, strokeColor=s["color"], strokeWidth=1.6, strokeLineJoin=1, strokeLineCap=1,
                               strokeDashArray=[4, 2]))

    d.add(Line(px, py, px, py + ph, strokeColor=INK, strokeWidth=1))
    d.add(Line(px, py, px + pw, py, strokeColor=INK, strokeWidth=1))
    entries = [(s["label"], s["color"], "line") for s in list(left) + list(right or [])]
    if band:
        entries.append((band.get("label", "min-max"), band["color"], "box"))
    _legend(d, px, 4 + H - 13, entries)
    return d


def _bar_chart(width: float, height: float, labels: Sequence[str], series: Sequence[Dict[str, Any]],
               unit: str = "", label_every: int = 1) -> Drawing:
    """Grouped bar chart. Series: {"label", "color", "values": [float|None ...]}."""
    d = Drawing(width, height)
    W, H = _chart_frame(d, width, height)
    pl, pr, pt, pb = 46, 14, 22, 24
    px, py = pl, 4 + pb
    pw, ph = W - pl - pr, H - pt - pb
    vals = [v for s in series for v in s["values"] if _is_num(v)]
    if not vals or not labels:
        d.add(String(px + pw / 2, py + ph / 2 - 4, "No data in this period", fontName=BOLD, fontSize=10,
                     fillColor=INK_SOFT, textAnchor="middle"))
        return d
    top, ticks = _axis(max(vals))
    for v in ticks:
        y = py + v / top * ph
        d.add(Line(px, y, px + pw, y, strokeColor=GRID, strokeWidth=0.6, strokeDashArray=[2, 3]))
        d.add(String(px - 5, y - 2.5, _fmt_tick(v), fontName=FONT, fontSize=7.5, fillColor=INK_SOFT, textAnchor="end"))
    if unit:
        d.add(String(px - 5, py + ph + 9, unit, fontName=BOLD, fontSize=7, fillColor=INK_SOFT, textAnchor="end"))
    n = len(labels)
    k = max(1, len(series))
    gw = pw / n
    bw = gw * 0.78 / k
    for i in range(n):
        for j, s in enumerate(series):
            v = s["values"][i] if i < len(s["values"]) else None
            if not _is_num(v):
                continue
            h = max(0.0, min(1.0, v / top)) * ph
            x = px + i * gw + gw * 0.11 + j * bw
            r = min(2.0, bw / 3)
            d.add(Rect(x, py, bw, h, rx=r, ry=r, fillColor=s["color"], strokeColor=INK, strokeWidth=0.6))
        if i % max(1, label_every) == 0:
            d.add(String(px + i * gw + gw / 2, py - 11, labels[i], fontName=FONT, fontSize=7.5, fillColor=INK_SOFT,
                         textAnchor="middle"))
    d.add(Line(px, py, px, py + ph, strokeColor=INK, strokeWidth=1))
    d.add(Line(px, py, px + pw, py, strokeColor=INK, strokeWidth=1))
    _legend(d, px, 4 + H - 13, [(s["label"], s["color"], "box") for s in series])
    return d


def _timeline_legend(width: float) -> Drawing:
    d = Drawing(width, 14)
    _legend(d, 2, 3, [("monitoring OK", GREEN, "box"), ("target outage", YELLOW, "box"),
                      ("total outage (all local / all internet targets)", RED, "box"),
                      ("not monitoring / outside period", GREY, "box")])
    return d


def _timeline_block(clock: _Clock, day_starts: Sequence[float], period: Tuple[float, float],
                    spans: Sequence[Dict[str, Any]], width: float,
                    coverage: Optional[Sequence[Tuple[float, float]]] = None) -> Drawing:
    """One strip per local day: green base, grey (gaps / outside period / no ping data), yellow target
    spans, red totals. ``coverage`` = merged runs with ping data; ``None`` means unknown (no grey)."""
    label_w, right_pad, row_h, row_gap, top = 76.0, 8.0, 16.0, 8.0, 14.0
    n = len(day_starts)
    height = top + n * (row_h + row_gap)
    d = Drawing(width, height)
    bar_x0 = label_w
    bar_w = width - label_w - right_pad
    p0, p1 = period

    # hour grid + labels along the top
    for hh in range(0, 25, 3):
        x = bar_x0 + bar_w * hh / 24.0
        d.add(Line(x, 0, x, height - top + 2, strokeColor=GRID, strokeWidth=0.6, strokeDashArray=[2, 3]))
        if hh % 6 == 0:
            d.add(String(x, height - top + 4, f"{hh:02d}:00", fontName=FONT, fontSize=7, fillColor=INK_SOFT,
                         textAnchor="middle"))

    for i, ds in enumerate(day_starts):
        de = clock.add_days(ds, 1)
        if de <= ds:
            de = ds + 86400.0
        y = height - top - (i + 1) * (row_h + row_gap) + row_gap / 2

        def xs(t: float, _ds: float = ds, _de: float = de) -> float:
            t = min(max(t, _ds), _de)
            return bar_x0 + (t - _ds) / (_de - _ds) * bar_w

        d.add(String(0, y + row_h / 2 - 3, clock.fmt(ds, "%a %d %b"), fontName=BOLD, fontSize=8, fillColor=INK))

        # grey = outside the report period, plus (when known) time with no ping data at all
        # (service off, paused, or not yet installed); coverage is already clipped to the period.
        if coverage is not None:
            grey = _uncovered(coverage, ds, de)
        else:
            grey = []
            if p0 > ds:
                grey.append((ds, min(p0, de)))
            if p1 < de:
                grey.append((max(p1, ds), de))
        whole_day_grey = any(a <= ds + 1 and b >= de - 1 for a, b in grey)
        d.add(Rect(bar_x0, y, bar_w, row_h, rx=5, ry=5, fillColor=GREY if whole_day_grey else GREEN,
                   strokeColor=INK, strokeWidth=1.2))

        def overlay(a: float, b: float, color: colors.Color, inset: float = 2.0) -> None:
            if b <= a:
                return
            xa, xb = xs(a), xs(b)
            if xb - xa < 1.5:
                xb = min(xa + 1.5, bar_x0 + bar_w)
                xa = xb - 1.5
            d.add(Rect(xa, y + inset, xb - xa, row_h - 2 * inset, rx=2, ry=2, fillColor=color,
                       strokeColor=INK, strokeWidth=0.7))

        if not whole_day_grey:
            for a, b in grey:
                overlay(a, b, GREY, inset=1.5)
        for kind_filter, color in (("gap", GREY), ("target", YELLOW), ("total", RED)):
            for sp in spans:
                k = str(sp.get("kind") or "")
                if kind_filter == "total":
                    if not k.startswith("total"):
                        continue
                elif k != kind_filter:
                    continue
                a = max(float(sp["start_ts"]), ds, p0)
                b = min(float(sp["end_ts"]), de, p1)
                if b > a:
                    overlay(a, b, color)
    return d


# --------------------------------------------------------------------------------------
# Data gathering (bounded memory: chunked reads + running aggregates)
# --------------------------------------------------------------------------------------
def _bucket_seconds(start: float, end: float, max_points: int = MAX_CHART_POINTS) -> int:
    span = max(end - start, 3600.0)
    hours = max(1, int(math.ceil(span / 3600.0 / max_points)))
    return hours * 3600


def _collect_targets(db: Any, targets: Optional[Sequence[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    out: Dict[int, Dict[str, Any]] = {}
    try:
        db_rows = db.list_targets()
    except Exception:  # noqa: BLE001
        log.exception("export: could not list targets")
        db_rows = []
    for r in db_rows:
        try:
            tid = int(r["id"])
        except (KeyError, TypeError, ValueError):
            continue
        out[tid] = {"id": tid, "host": str(r.get("host") or ""), "label": r.get("label"),
                    "kind": str(r.get("kind") or "auto"), "enabled": bool(r.get("enabled", True))}
    for t in targets or []:
        try:
            tid = int(t["id"])
        except (KeyError, TypeError, ValueError):
            continue
        cur = out.setdefault(tid, {"id": tid, "host": str(t.get("host") or ""), "label": t.get("label"),
                                   "kind": "auto", "enabled": bool(t.get("enabled", True))})
        if t.get("kind") in ("local", "internet"):
            cur["kind"] = t["kind"]
        if t.get("label"):
            cur["label"] = t["label"]
        if t.get("host"):
            cur["host"] = str(t["host"])
    rows = sorted(out.values(), key=lambda d: d["id"])
    for r in rows:
        if r["kind"] not in ("local", "internet"):
            r["kind"] = _guess_kind(r["host"])
        r["name"] = f"{r['label']} ({r['host']})" if r.get("label") else r["host"]
    return rows


def _ping_buckets(db: Any, target_id: int, start: float, end: float, bucket_s: int,
                  clock: _Clock) -> Tuple[List[Dict[str, Any]], List[Tuple[float, float]]]:
    """Fold a target's minute rows into chart buckets (aligned to local hours).

    Returns ``(buckets, coverage)`` where *coverage* is the list of ``(start, end)`` runs during
    which pings were actually being sent (holes shorter than ``COVERAGE_HOLE_S`` are bridged).
    Rows are read in time chunks so memory stays flat for a yearly report.
    """
    off = clock.offset(start)
    base = start - ((start + off) % 3600)
    acc: Dict[int, List[Any]] = {}
    runs: List[List[float]] = []
    t = start
    while t < end:
        t2 = min(t + PING_CHUNK_S, end)
        for r in db.ping_minutes(target_id, t, t2):
            mts = float(r["minute_ts"])
            key = int((mts - base) // bucket_s)
            a = acc.get(key)
            if a is None:
                a = acc[key] = [0, 0, 0.0, None, None]
            sent, rec = int(r.get("sent") or 0), int(r.get("received") or 0)
            if sent > 0:
                if runs and mts <= runs[-1][1] + COVERAGE_HOLE_S:
                    runs[-1][1] = max(runs[-1][1], mts + 60.0)
                else:
                    runs.append([mts, mts + 60.0])
            a[0] += sent
            a[1] += rec
            if rec and _is_num(r.get("avg_ms")):
                a[2] += float(r["avg_ms"]) * rec
            mn, mx = r.get("min_ms"), r.get("max_ms")
            if _is_num(mn):
                a[3] = mn if a[3] is None else min(a[3], mn)
            if _is_num(mx):
                a[4] = mx if a[4] is None else max(a[4], mx)
        t = t2
    out: List[Dict[str, Any]] = []
    for key in sorted(acc):
        sent, rec, wsum, mn, mx = acc[key]
        out.append({
            "key": key, "ts": base + key * bucket_s + bucket_s / 2.0, "sent": sent, "received": rec,
            "avg_ms": (wsum / rec) if rec else None, "min_ms": mn, "max_ms": mx,
            "loss_pct": (100.0 * (sent - rec) / sent) if sent else None,
        })
    return out, [(a, b) for a, b in runs]


def _merge_runs(runs: Sequence[Tuple[float, float]]) -> List[Tuple[float, float]]:
    """Union of ``(start, end)`` intervals, sorted and merged."""
    out: List[List[float]] = []
    for a, b in sorted((float(a), float(b)) for a, b in runs if b > a):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]


def _uncovered(coverage: Sequence[Tuple[float, float]], a: float, b: float,
               min_len: float = 60.0) -> List[Tuple[float, float]]:
    """Parts of ``[a, b]`` not inside any coverage run (runs must be merged/sorted)."""
    out: List[Tuple[float, float]] = []
    cur = a
    for s, e in coverage:
        if e <= cur:
            continue
        if s >= b:
            break
        if s > cur:
            out.append((cur, min(s, b)))
        cur = max(cur, e)
        if cur >= b:
            break
    if cur < b:
        out.append((cur, b))
    return [(s, e) for s, e in out if e - s >= min_len]


def _gather_ping(db: Any, start: float, end: float, clock: _Clock, targets: List[Dict[str, Any]]) -> Dict[str, Any]:
    bucket_s = _bucket_seconds(start, end)
    per: List[Dict[str, Any]] = []
    tot_sent = tot_rec = 0
    all_runs: List[Tuple[float, float]] = []
    for t in targets:
        summary = db.ping_summary(t["id"], start, end) or {}
        sent = int(summary.get("sent") or 0)
        rec = int(summary.get("received") or 0)
        tot_sent += sent
        tot_rec += rec
        buckets: List[Dict[str, Any]] = []
        if sent:
            buckets, runs = _ping_buckets(db, t["id"], start, end, bucket_s, clock)
            all_runs.extend(runs)
        per.append({"target": t, "summary": summary, "buckets": buckets})
    coverage = [(max(a, start), min(b, end)) for a, b in _merge_runs(all_runs) if b > start and a < end]
    return {"bucket_s": bucket_s, "targets": per, "sent": tot_sent, "received": tot_rec,
            "loss_pct": (100.0 * (tot_sent - tot_rec) / tot_sent) if tot_sent else None,
            "coverage": coverage, "covered_s": sum(b - a for a, b in coverage)}


def _gather_outages(db: Any, start: float, end: float, targets: List[Dict[str, Any]]) -> Dict[str, Any]:
    names = {t["id"]: t["name"] for t in targets}
    rows = db.list_outages(start, end) or []
    items: List[Dict[str, Any]] = []
    for r in rows:
        kind = str(r.get("kind") or "target")
        s = float(r.get("start_ts") or 0)
        e_raw = r.get("end_ts")
        is_open = e_raw is None
        e = end if is_open else float(e_raw)
        if kind == "target":
            tid = r.get("target_id")
            what = names.get(tid, f"target #{tid}")
        elif kind == "total_local":
            what = "All local targets down"
        elif kind == "total_internet":
            what = "All internet targets down"
        elif kind == "gap":
            note = str(r.get("note") or "").strip()
            what = "Not monitoring" + (f" ({note})" if note and note.lower() != "not monitoring" else "")
        else:
            what = kind
        missed = int(r.get("missed") or 0)
        # pings are counted at the default one-per-second interval for rows without a count
        _sent, pct, estimated = missed_percentage(kind, missed, r.get("sent"), max(0.0, e - s), 1.0)
        items.append({"id": r.get("id"), "kind": kind, "start_ts": s, "end_ts": e, "open": is_open,
                      "duration_s": max(0.0, e - s), "what": what, "missed": missed,
                      "missed_pct": pct, "sent_estimated": estimated, "target_id": r.get("target_id")})
    items.sort(key=lambda x: x["start_ts"], reverse=True)
    n_target = sum(1 for x in items if x["kind"] == "target")
    n_total = sum(1 for x in items if x["kind"].startswith("total"))
    n_gap = sum(1 for x in items if x["kind"] == "gap")
    longest = max((x for x in items if x["kind"] != "gap"), key=lambda x: x["duration_s"], default=None)
    return {"items": items, "n_target": n_target, "n_total": n_total, "n_gap": n_gap, "longest": longest,
            "count": n_target + n_total}


def _speed_stat(pairs: List[Tuple[float, float]]) -> Optional[Dict[str, Any]]:
    if not pairs:
        return None
    vals = [v for v, _ in pairs]
    mn = min(pairs, key=lambda p: p[0])
    mx = max(pairs, key=lambda p: p[0])
    return {"avg": sum(vals) / len(vals), "median": statistics.median(vals), "min": mn[0], "min_ts": mn[1],
            "max": mx[0], "max_ts": mx[1], "count": len(vals)}


def _gather_speed(db: Any, start: float, end: float, clock: _Clock) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    backends: Counter = Counter()
    servers: Counter = Counter()
    isps: Counter = Counter()
    t = start
    while t < end:
        t2 = min(t + SPEED_CHUNK_S, end)
        for r in db.list_speedtests(t, t2) or []:
            ok = bool(r.get("ok"))
            rows.append({"ts": float(r.get("ts") or 0), "ok": ok, "download_mbps": r.get("download_mbps"),
                         "upload_mbps": r.get("upload_mbps"), "latency_ms": r.get("latency_ms"),
                         "jitter_ms": r.get("jitter_ms"), "error": r.get("error")})
            if r.get("backend"):
                backends[str(r["backend"])] += 1
            if ok and r.get("server"):
                servers[str(r["server"])] += 1
            if ok and r.get("isp"):
                isps[str(r["isp"])] += 1
        t = t2
    rows.sort(key=lambda r: r["ts"])
    ok_rows = [r for r in rows if r["ok"]]
    down = [(float(r["download_mbps"]), r["ts"]) for r in ok_rows if _is_num(r["download_mbps"])]
    up = [(float(r["upload_mbps"]), r["ts"]) for r in ok_rows if _is_num(r["upload_mbps"])]
    lat = [(float(r["latency_ms"]), r["ts"]) for r in ok_rows if _is_num(r["latency_ms"])]

    by_hour = [{"hour": h, "sd": 0.0, "nd": 0, "su": 0.0, "nu": 0, "sl": 0.0, "nl": 0} for h in range(24)]
    for r in ok_rows:
        b = by_hour[clock.hour(r["ts"])]
        if _is_num(r["download_mbps"]):
            b["sd"] += float(r["download_mbps"])
            b["nd"] += 1
        if _is_num(r["upload_mbps"]):
            b["su"] += float(r["upload_mbps"])
            b["nu"] += 1
        if _is_num(r["latency_ms"]):
            b["sl"] += float(r["latency_ms"])
            b["nl"] += 1
    hours = [{"hour": b["hour"], "avg_down": (b["sd"] / b["nd"]) if b["nd"] else None,
              "avg_up": (b["su"] / b["nu"]) if b["nu"] else None,
              "avg_latency": (b["sl"] / b["nl"]) if b["nl"] else None, "count": b["nd"]} for b in by_hour]

    # chart series: raw points when few, else time buckets (<= ~500)
    series_d: List[Optional[Tuple[float, Optional[float]]]] = []
    series_u: List[Optional[Tuple[float, Optional[float]]]] = []
    series_l: List[Optional[Tuple[float, Optional[float]]]] = []
    if len(ok_rows) <= MAX_CHART_POINTS:
        gaps = [b["ts"] - a["ts"] for a, b in zip(ok_rows, ok_rows[1:]) if b["ts"] > a["ts"]]
        typical = statistics.median(gaps) if gaps else 900.0
        break_s = max(2 * 3600.0, 3.0 * typical)
        prev_ts: Optional[float] = None
        for r in ok_rows:
            if prev_ts is not None and r["ts"] - prev_ts > break_s:
                series_d.append(None)
                series_u.append(None)
                series_l.append(None)
            series_d.append((r["ts"], r["download_mbps"] if _is_num(r["download_mbps"]) else None))
            series_u.append((r["ts"], r["upload_mbps"] if _is_num(r["upload_mbps"]) else None))
            series_l.append((r["ts"], r["latency_ms"] if _is_num(r["latency_ms"]) else None))
            prev_ts = r["ts"]
    else:
        bucket_s = _bucket_seconds(start, end)
        acc: Dict[int, List[Any]] = {}
        for r in ok_rows:
            key = int((r["ts"] - start) // bucket_s)
            a = acc.setdefault(key, [0.0, 0, 0.0, 0, 0.0, 0])
            if _is_num(r["download_mbps"]):
                a[0] += float(r["download_mbps"])
                a[1] += 1
            if _is_num(r["upload_mbps"]):
                a[2] += float(r["upload_mbps"])
                a[3] += 1
            if _is_num(r["latency_ms"]):
                a[4] += float(r["latency_ms"])
                a[5] += 1
        prev_key: Optional[int] = None
        for key in sorted(acc):
            if prev_key is not None and key != prev_key + 1:
                series_d.append(None)
                series_u.append(None)
                series_l.append(None)
            a = acc[key]
            ts = start + key * bucket_s + bucket_s / 2.0
            series_d.append((ts, a[0] / a[1] if a[1] else None))
            series_u.append((ts, a[2] / a[3] if a[3] else None))
            series_l.append((ts, a[4] / a[5] if a[5] else None))
            prev_key = key

    return {
        "count": len(rows), "ok_count": len(ok_rows), "fail_count": len(rows) - len(ok_rows),
        "down": _speed_stat(down), "up": _speed_stat(up), "latency": _speed_stat(lat),
        "by_hour": hours, "series": {"down": series_d, "up": series_u, "latency": series_l},
        "backends": backends, "servers": servers, "isps": isps, "rows": rows,
        "first_ts": rows[0]["ts"] if rows else None, "last_ts": rows[-1]["ts"] if rows else None,
    }


def _local_findings(rows: List[Dict[str, Any]], clock: _Clock, warn_below_pct: float = 50.0) -> List[str]:
    """Minimal plain-English rules used when tnt.speedtest.patterns is unavailable."""
    out: List[str] = []
    ok = [r for r in rows if r["ok"] and _is_num(r.get("download_mbps"))]
    failed = [r for r in rows if not r["ok"]]
    if failed:
        out.append(f"{len(failed)} speed test{'s' if len(failed) != 1 else ''} failed in this period.")
    if len(ok) < 4:
        out.append("Not enough successful speed tests for a pattern analysis yet.")
        return out
    downs = [float(r["download_mbps"]) for r in ok]
    med = statistics.median(downs)
    if med > 0:
        by_hour: List[List[float]] = [[] for _ in range(24)]
        for r in ok:
            by_hour[clock.hour(r["ts"])].append(float(r["download_mbps"]))
        blocks: List[Tuple[float, int]] = []
        for h in range(24):
            vals = by_hour[h] + by_hour[(h + 1) % 24] + by_hour[(h + 2) % 24]
            if len(vals) >= 3:
                blocks.append((sum(vals) / len(vals), h))
        if blocks:
            worst_avg, wh = min(blocks)
            slow_pct = 100.0 * (med - worst_avg) / med
            if slow_pct >= 15:
                out.append(f"Downloads are ~{slow_pct:.0f}% slower between {wh:02d}:00 and {(wh + 3) % 24:02d}:00 "
                           f"(about {worst_avg:.0f} Mbps vs a median of {med:.0f} Mbps).")
            best_avg, bh = max(blocks)
            if best_avg > 0 and (best_avg - worst_avg) / best_avg >= 0.25:
                out.append(f"Fastest downloads are between {bh:02d}:00 and {(bh + 3) % 24:02d}:00 (~{best_avg:.0f} Mbps).")
        slow = [r for r in ok if float(r["download_mbps"]) < med * warn_below_pct / 100.0]
        if slow:
            out.append(f"{len(slow)} test{'s were' if len(slow) != 1 else ' was'} below {warn_below_pct:.0f}% of the "
                       f"median download speed ({med:.0f} Mbps).")
    ups = [float(r["upload_mbps"]) for r in ok if _is_num(r.get("upload_mbps"))]
    if ups and med > 0:
        mu = statistics.median(ups)
        if mu > 0 and med / mu >= 8:
            out.append(f"Upload is much lower than download (median {mu:.0f} vs {med:.0f} Mbps, about {med / mu:.0f}:1).")
    lats = [(float(r["latency_ms"]), r["ts"]) for r in ok if _is_num(r.get("latency_ms"))]
    if len(lats) >= 4:
        ml = statistics.median([v for v, _ in lats])
        mx, mx_ts = max(lats)
        if mx > max(3 * ml, ml + 50):
            out.append(f"Latency spiked to {mx:.0f} ms on {clock.fmt(mx_ts)} (median {ml:.0f} ms).")
    if len(ok) >= 8:
        t0 = ok[0]["ts"]
        span_days = (ok[-1]["ts"] - t0) / 86400.0
        if span_days >= 3 and med > 0:
            xs = [(r["ts"] - t0) / 86400.0 for r in ok]
            mx_ = sum(xs) / len(xs)
            my_ = sum(downs) / len(downs)
            den = sum((x - mx_) ** 2 for x in xs)
            if den > 0:
                slope = sum((x - mx_) * (y - my_) for x, y in zip(xs, downs)) / den
                pct_day = 100.0 * slope / med
                if abs(pct_day) >= 1.0:
                    out.append(f"Download speed trended {'down' if pct_day < 0 else 'up'} about {abs(pct_day):.1f}% per day.")
    if not out:
        out.append("No unusual patterns: speeds were steady across the period.")
    return out


def _findings(rows: List[Dict[str, Any]], end: float, clock: _Clock) -> List[str]:
    """Plain-English findings: the speedtest package's ``analyse_patterns`` when available, else local rules."""
    analyse_patterns = None
    try:
        from .speedtest.patterns import analyse_patterns  # type: ignore
    except Exception:  # noqa: BLE001 - module may not exist (yet) or live in the package root
        try:
            from .speedtest import analyse_patterns  # type: ignore
        except Exception:  # noqa: BLE001
            analyse_patterns = None  # type: ignore
    if analyse_patterns is not None:
        try:
            res = analyse_patterns(rows, end, 50, clock.offset(end))
            findings = res.get("findings") if isinstance(res, dict) else None
            if isinstance(findings, list) and all(isinstance(f, str) for f in findings):
                return findings or ["No unusual patterns: speeds were steady across the period."]
        except Exception:  # noqa: BLE001
            log.exception("export: analyse_patterns failed; using local findings")
    return _local_findings(rows, clock)


def _gather_discovery(db: Any) -> Optional[Dict[str, Any]]:
    run = db.last_discovery_run()
    if not run:
        return None
    hosts = list(run.get("hosts") or [])
    return {"run": run, "hosts": hosts}


def _network_rows(netinfo: Optional[Dict[str, Any]]) -> List[Tuple[str, str]]:
    rows: List[Tuple[str, str]] = []
    if not isinstance(netinfo, dict):
        return rows
    nic = netinfo.get("internet_nic")
    if isinstance(nic, dict):
        if nic.get("name"):
            rows.append(("Internet adapter", str(nic["name"])))
        ip = nic.get("ipv4")
        net = nic.get("network")
        if ip:
            rows.append(("IPv4 address", f"{ip}" + (f"  ({net})" if net else "")))
        if nic.get("gateway"):
            rows.append(("Gateway", str(nic["gateway"])))
    elif isinstance(netinfo.get("adapters"), list):
        adapters = netinfo["adapters"]
        idx = netinfo.get("internet_nic_index")
        chosen = next((a for a in adapters if isinstance(a, dict) and a.get("index") == idx), None)
        if chosen is None and adapters and isinstance(adapters[0], dict):
            chosen = adapters[0]
        if chosen:
            if chosen.get("name"):
                rows.append(("Internet adapter", str(chosen["name"]) +
                             (f"  ({chosen['description']})" if chosen.get("description") else "")))
            v4 = chosen.get("ipv4") or []
            if v4 and isinstance(v4[0], dict):
                a = v4[0]
                rows.append(("IPv4 address", f"{a.get('address')}/{a.get('prefix')}" +
                             (f"  ({a.get('network')})" if a.get("network") else "")))
            gws = chosen.get("gateways") or []
            if gws:
                rows.append(("Gateway", ", ".join(str(g) for g in gws)))
            dns = chosen.get("dns") or []
            if dns:
                rows.append(("DNS", ", ".join(str(x) for x in dns[:4])))
        elif netinfo.get("default_gateway"):
            rows.append(("Gateway", str(netinfo["default_gateway"])))
    count = netinfo.get("adapter_count")
    if count is None and isinstance(netinfo.get("adapters"), list):
        count = len(netinfo["adapters"])
    if count is not None:
        rows.append(("Adapters", str(count)))
    return rows


# --------------------------------------------------------------------------------------
# Section builders
# --------------------------------------------------------------------------------------
def _error_box(what: str, accent: colors.Color) -> RoundedBox:
    return _empty_box(f"Could not load {what}", accent, "See the service log for details.")


def _title_block(title: str, start: float, end: float, now: float, clock: _Clock, hostname: str,
                 width: float) -> List[Flowable]:
    zone = clock.zone_label(end)
    same_day = clock.fmt(start, "%Y-%m-%d") == clock.fmt(end, "%Y-%m-%d")
    period = (f"{clock.fmt(start, '%a %d %b %Y %H:%M')} to {clock.fmt(end, '%H:%M' if same_day else '%a %d %b %Y %H:%M')}"
              f"  ({_fmt_duration(end - start)}, local time {zone})")
    text: List[Flowable] = [
        _para(_esc(title), "title"),
        _para(_esc("TEC Network Tool report"), "subtitle"),
        Spacer(1, 5),
        _para(f"<b>Period:</b> {_esc(period)}", "body"),
        _para(f"<b>Generated:</b> {_esc(clock.fmt(now, '%a %d %b %Y %H:%M:%S'))}   <b>Host:</b> {_esc(hostname)}"
              f"   <b>TNT</b> v{_esc(__version__)}", "body"),
    ]
    logo_w = 54
    t = Table([[_logo(46), text]], colWidths=[logo_w, width - logo_w])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return [t, Spacer(1, 12)]


def _summary_cards(ping: Optional[Dict[str, Any]], outages: Optional[Dict[str, Any]], speed: Optional[Dict[str, Any]],
                   discovery: Optional[Dict[str, Any]], clock: _Clock, width: float) -> Table:
    # ping
    if ping and ping["sent"]:
        active = sum(1 for p in ping["targets"] if int(p["summary"].get("sent") or 0))
        c1 = _card("Ping", f"{ping['loss_pct']:.2f}% loss", f"{_fmt_int(ping['sent'])} pings, {active} target{'s' if active != 1 else ''}", GREEN, 0)
    else:
        c1 = _card("Ping", "No data", "no ping minutes in this period", GREEN, 0)
    # outages
    if outages and outages["count"]:
        lg = outages["longest"]
        sub = f"{outages['n_total']} total, longest {_fmt_duration(lg['duration_s']) if lg else '-'}"
        c2 = _card("Outages", f"{outages['count']}", sub, YELLOW, 0)
    else:
        c2 = _card("Outages", "0", "none recorded" + (f", {outages['n_gap']} monitoring gap(s)" if outages and outages["n_gap"] else ""), YELLOW, 0)
    # speed
    if speed and speed["down"]:
        up = speed["up"]
        sub = "median down" + (f" · {_fmt_num(up['median'], 0)} up" if up else "") + f" · {_fmt_int(speed['ok_count'])} tests"
        c3 = _card("Speed", f"{_fmt_num(speed['down']['median'], 0)} Mbps", sub, PURPLE, 0)
    elif speed and speed["count"]:
        c3 = _card("Speed", "No results", f"{_fmt_int(speed['count'])} tests, all failed", PURPLE, 0)
    else:
        c3 = _card("Speed", "No data", "no speed tests in this period", PURPLE, 0)
    # discovery
    if discovery:
        run = discovery["run"]
        n = len(discovery["hosts"])
        c4 = _card("Discovery", f"{n} device{'s' if n != 1 else ''}", f"{run.get('cidr')} · {clock.fmt(float(run.get('ts') or 0), '%d %b %H:%M')}", ORANGE, 0)
    else:
        c4 = _card("Discovery", "No scans", "run a scan from the Discovery view", ORANGE, 0)
    return _cards_row([c1, c2, c3, c4], width)


def _network_box(rows: List[Tuple[str, str]], width: float) -> List[Flowable]:
    if not rows:
        return []
    inner_w = width - 4 - 2 * 10
    box = RoundedBox([_para("NETWORK", "card_label"), Spacer(1, 3), _kv_table(rows, inner_w)],
                     fill=_tint(BLUE, 0.16), padding=10, radius=12)
    return [box, Spacer(1, 12)]


def _ping_section(ping: Optional[Dict[str, Any]], start: float, end: float, clock: _Clock, width: float,
                  error: Optional[str]) -> List[Flowable]:
    items: List[Flowable] = [SectionHeading("Ping monitoring", GREEN, "Per-target reachability and round-trip time for the period")]
    if error:
        items.append(_error_box("ping data", GREEN))
        return items
    if not ping or not ping["sent"]:
        items.append(_empty_box("No ping data in this period", GREEN, "Add targets in the Ping view to start monitoring."))
        return items
    header = ["Target", "Kind", "Sent", "Received", "Loss", "Avg ms", "Min ms", "Max ms"]
    widths = _col_widths([3.3, 1.0, 1.1, 1.2, 1.0, 1.0, 1.0, 1.0], width)
    data: List[List[Any]] = [header]
    extra: List[Tuple[Any, ...]] = []
    for i, p in enumerate(ping["targets"], start=1):
        t, s = p["target"], p["summary"]
        sent = int(s.get("sent") or 0)
        data.append([
            _fit(t["name"], widths[0] - 14, FONT, 8.8), t["kind"], _fmt_int(sent),
            _fmt_int(s.get("received")) if sent else "-", _fmt_pct(s.get("loss_pct")) if sent else "no data",
            _fmt_ms(s.get("avg_ms")), _fmt_ms(s.get("min_ms")), _fmt_ms(s.get("max_ms")),
        ])
        loss = s.get("loss_pct")
        if _is_num(loss):
            if loss >= 15:
                extra.append(("BACKGROUND", (4, i), (4, i), _tint(RED, 0.45)))
            elif loss >= 2:
                extra.append(("BACKGROUND", (4, i), (4, i), _tint(YELLOW, 0.6)))
    items.append(_styled_table(data, widths, _tint(GREEN, 0.35), right_cols=(2, 3, 4, 5, 6, 7), extra=extra))
    items.append(Spacer(1, 10))
    bucket_s = ping["bucket_s"]
    label = "hour" if bucket_s == 3600 else f"{bucket_s // 3600} h bucket"
    for p in ping["targets"]:
        if not p["buckets"]:
            continue
        t = p["target"]
        pts_avg: List[Optional[Tuple[float, Optional[float]]]] = []
        pts_loss: List[Optional[Tuple[float, Optional[float]]]] = []
        pts_lo: List[Optional[Tuple[float, Optional[float]]]] = []
        pts_hi: List[Optional[Tuple[float, Optional[float]]]] = []
        prev_key: Optional[int] = None
        for b in p["buckets"]:
            if prev_key is not None and b["key"] != prev_key + 1:
                pts_avg.append(None)
                pts_loss.append(None)
                pts_lo.append(None)
                pts_hi.append(None)
            pts_avg.append((b["ts"], b["avg_ms"]))
            pts_loss.append((b["ts"], b["loss_pct"]))
            pts_lo.append((b["ts"], b["min_ms"]))
            pts_hi.append((b["ts"], b["max_ms"]))
            prev_key = b["key"]
        chart = _line_chart(width, 150, clock, start, end,
                            left=[{"label": "avg RTT", "color": BLUE, "points": pts_avg}],
                            right=[{"label": "loss", "color": RED, "points": pts_loss}],
                            band={"label": "min-max", "color": _tint(BLUE, 0.3), "low": pts_lo, "high": pts_hi},
                            left_unit="ms", right_unit="%", right_floor=10.0)
        items.append(KeepTogether([_para(f"{_esc(t['name'])} - avg RTT and loss per {label}", "h3"), chart, Spacer(1, 8)]))
    return items


def _outage_section(outages: Optional[Dict[str, Any]], ping: Optional[Dict[str, Any]], start: float, end: float,
                    clock: _Clock, width: float, error: Optional[str]) -> List[Flowable]:
    items: List[Flowable] = [SectionHeading("Outages", YELLOW, "Target outages, total outages and monitoring gaps")]
    if error:
        items.append(_error_box("outage data", YELLOW))
        return items
    have_ping = bool(ping and ping["sent"])
    if not outages or not outages["items"]:
        items.append(_empty_box("No outages in this period", YELLOW,
                                "Nice and steady." if have_ping else "No monitoring data was recorded in this period."))
        if not have_ping:
            return items
    else:
        header = ["Start", "End", "Duration", "What", "Missed Pings", "Missed %"]
        widths = _col_widths([1.6, 1.6, 1.3, 2.4, 1.05, 0.85], width)
        data: List[List[Any]] = [header]
        extra: List[Tuple[Any, ...]] = []
        shown = outages["items"][:MAX_OUTAGE_ROWS]
        for i, o in enumerate(shown, start=1):
            end_txt = "ongoing" if o["open"] else clock.fmt(o["end_ts"], "%d %b %H:%M:%S")
            dur = _fmt_duration(o["duration_s"]) + (" so far" if o["open"] else "")
            # only target outages count pings; total and gap rows show a dash in both columns
            is_target = o["kind"] == "target"
            data.append([clock.fmt(o["start_ts"], "%d %b %H:%M:%S"), end_txt, dur,
                         _fit(o["what"], widths[3] - 14, FONT, 8.8),
                         _fmt_int(o["missed"]) if is_target else "-",
                         _fmt_missed_pct(o.get("missed_pct"), bool(o.get("sent_estimated"))) if is_target else "-"])
            color = {"target": _tint(YELLOW, 0.55), "gap": _tint(GREY, 0.6)}.get(o["kind"], _tint(RED, 0.4))
            extra.append(("BACKGROUND", (3, i), (3, i), color))
        items.append(_styled_table(data, widths, _tint(YELLOW, 0.45), right_cols=(2, 4, 5), extra=extra))
        if len(outages["items"]) > MAX_OUTAGE_ROWS:
            items.append(Spacer(1, 4))
            items.append(_para(_esc(f"... and {len(outages['items']) - MAX_OUTAGE_ROWS} more outages not listed."), "small"))
    items.append(Spacer(1, 10))

    # timeline strips
    spans = [o for o in outages["items"]] if outages else []
    days: List[float] = []
    day = clock.day_start(start)
    guard = 0
    while day < end and guard < 400:
        days.append(day)
        day = clock.add_days(day, 1)
        guard += 1
    note: Optional[str] = None
    if len(days) > MAX_TIMELINE_DAYS_ALL:
        def has_event(ds: float) -> bool:
            de = clock.add_days(ds, 1)
            return any(sp["start_ts"] < de and sp["end_ts"] > ds for sp in spans)
        event_days = [dd for dd in days if has_event(dd)]
        if not event_days:
            items.append(_para(_esc(f"All {len(days)} days in this period were clean, so no per-day timeline strips are shown."), "small"))
            return items
        note = (f"Showing {min(len(event_days), MAX_TIMELINE_DAYS_EVENTS)} of {len(days)} calendar days "
                "(only days with outages or gaps).")
        if len(event_days) > MAX_TIMELINE_DAYS_EVENTS:
            note += f" {len(event_days) - MAX_TIMELINE_DAYS_EVENTS} more event days are not drawn."
        days = event_days[:MAX_TIMELINE_DAYS_EVENTS]
    coverage: Optional[List[Tuple[float, float]]] = list(ping.get("coverage") or []) if ping else None
    blocks: List[Flowable] = []
    for i in range(0, len(days), TIMELINE_DAYS_PER_BLOCK):
        blocks.append(_timeline_block(clock, days[i:i + TIMELINE_DAYS_PER_BLOCK], (start, end), spans, width, coverage))
        blocks.append(Spacer(1, 4))
    head: List[Flowable] = [_para("Daily timeline", "h3")]
    if ping and _is_num(ping.get("covered_s")):
        head.append(_para(_esc(f"Ping data covers {_fmt_duration(min(ping['covered_s'], end - start))} of this "
                               f"{_fmt_duration(end - start)} period; time without ping data is shown grey."), "small"))
    if note:
        head.append(_para(_esc(note), "small"))
    head.append(_timeline_legend(width))
    head.append(Spacer(1, 4))
    items.append(KeepTogether(head + blocks[:2]))
    items.extend(blocks[2:])
    return items


def _speed_section(speed: Optional[Dict[str, Any]], start: float, end: float, clock: _Clock, width: float,
                   error: Optional[str]) -> List[Flowable]:
    items: List[Flowable] = [SectionHeading("Speed tests", PURPLE, "Scheduled internet speed tests over the period")]
    if error:
        items.append(_error_box("speed test data", PURPLE))
        return items
    if not speed or not speed["count"]:
        items.append(_empty_box("No speed tests in this period", PURPLE, "Tests run automatically every few minutes while the service is up."))
        return items
    bits = [f"<b>{_fmt_int(speed['count'])}</b> tests, <b>{_fmt_int(speed['ok_count'])}</b> succeeded, "
            f"<b>{_fmt_int(speed['fail_count'])}</b> failed"]
    if speed["backends"]:
        bits.append("backend " + ", ".join(f"{_esc(k)} ({v})" for k, v in speed["backends"].most_common(3)))
    if speed["servers"]:
        bits.append("server " + _esc(speed["servers"].most_common(1)[0][0]))
    if speed["isps"]:
        bits.append("ISP " + _esc(speed["isps"].most_common(1)[0][0]))
    items.append(_para(" · ".join(bits), "body"))
    items.append(Spacer(1, 6))
    if speed["down"] or speed["up"] or speed["latency"]:
        header = ["Metric", "Average", "Median", "Minimum", "Maximum"]
        widths = _col_widths([1.5, 1.1, 1.1, 2.4, 2.4], width)
        data: List[List[Any]] = [header]
        for label, key, digits in (("Download (Mbps)", "down", 1), ("Upload (Mbps)", "up", 1), ("Latency (ms)", "latency", 1)):
            st = speed[key]
            if not st:
                data.append([label, "-", "-", "-", "-"])
                continue
            data.append([label, _fmt_num(st["avg"], digits), _fmt_num(st["median"], digits),
                         f"{_fmt_num(st['min'], digits)}  ({clock.fmt(st['min_ts'], '%d %b %H:%M')})",
                         f"{_fmt_num(st['max'], digits)}  ({clock.fmt(st['max_ts'], '%d %b %H:%M')})"])
        items.append(_styled_table(data, widths, _tint(PURPLE, 0.35), right_cols=(1, 2, 3, 4)))
        items.append(Spacer(1, 10))
        ser = speed["series"]
        chart = _line_chart(width, 170, clock, start, end,
                            left=[{"label": "download", "color": PURPLE, "points": ser["down"]},
                                  {"label": "upload", "color": BLUE, "points": ser["up"]}],
                            right=[{"label": "latency", "color": ORANGE, "points": ser["latency"]}],
                            left_unit="Mbps", right_unit="ms")
        items.append(KeepTogether([_para("Download and upload over time", "h3"), chart, Spacer(1, 8)]))
        bars = _bar_chart(width, 150, [f"{h:02d}" for h in range(24)],
                          [{"label": "avg download", "color": PURPLE, "values": [h["avg_down"] for h in speed["by_hour"]]},
                           {"label": "avg upload", "color": BLUE, "values": [h["avg_up"] for h in speed["by_hour"]]}],
                          unit="Mbps", label_every=3)
        items.append(KeepTogether([_para("Average by hour of day (local time)", "h3"), bars, Spacer(1, 8)]))
    else:
        items.append(_empty_box("All speed tests in this period failed", PURPLE, "Check the Speed view for the error details."))
        items.append(Spacer(1, 8))
    findings = _findings(speed["rows"], end, clock)[:MAX_FINDINGS]
    content: List[Flowable] = [_para("FINDINGS", "card_label"), Spacer(1, 3)]
    for f in findings:
        content.append(Paragraph(_esc(f), STYLES["bullet"], bulletText="•"))
    items.append(KeepTogether([RoundedBox(content, fill=_tint(PURPLE, 0.16), padding=10, radius=12)]))
    return items


def _discovery_section(discovery: Optional[Dict[str, Any]], start: float, clock: _Clock, width: float,
                       error: Optional[str]) -> List[Flowable]:
    items: List[Flowable] = [SectionHeading("Network discovery", ORANGE, "Devices found by the most recent scan")]
    if error:
        items.append(_error_box("discovery data", ORANGE))
        return items
    if not discovery:
        items.append(_empty_box("No discovery scans yet", ORANGE, "Run a scan from the Discovery view; the latest run appears here."))
        return items
    run, hosts = discovery["run"], discovery["hosts"]
    ts = float(run.get("ts") or 0)
    ports = run.get("ports") or []
    desc = (f"<b>{_esc(run.get('cidr'))}</b> scanned on <b>{_esc(clock.fmt(ts))}</b> "
            f"({_esc(run.get('method') or 'native')}, {_fmt_duration(run.get('duration_s'))}, "
            f"{_fmt_int(run.get('scanned'))} addresses): <b>{len(hosts)}</b> host{'s' if len(hosts) != 1 else ''} found. "
            f"Ports: {_esc(', '.join(str(p) for p in ports)) if ports else 'none'}.")
    if ts < start:
        desc += " <i>(This scan is older than the report period.)</i>"
    if not run.get("ok", True) and run.get("error"):
        desc += f" <i>Scan error: {_esc(run['error'])}</i>"
    items.append(_para(desc, "body"))
    items.append(Spacer(1, 6))
    if not hosts:
        items.append(_empty_box("Nothing found in that scan", ORANGE))
        return items
    header = ["IP", "Hostname", "MAC", "Vendor", "Open ports", "Ping"]
    widths = _col_widths([1.25, 2.3, 1.7, 2.1, 1.9, 0.85], width)
    data: List[List[Any]] = [header]
    for h in hosts[:MAX_HOST_ROWS]:
        op = h.get("open_ports") or []
        ping_txt = (_fmt_ms(h.get("rtt_ms")) + " ms") if h.get("ping_ok") and _is_num(h.get("rtt_ms")) else ("yes" if h.get("ping_ok") else "-")
        data.append([
            str(h.get("ip") or ""), _fit(h.get("hostname") or "-", widths[1] - 14, FONT, 8.5),
            str(h.get("mac") or "-"), _fit(h.get("vendor") or "-", widths[3] - 14, FONT, 8.5),
            _fit(", ".join(str(p) for p in op) if op else "-", widths[4] - 14, FONT, 8.5), ping_txt,
        ])
    items.append(_styled_table(data, widths, _tint(ORANGE, 0.4), right_cols=(5,), font_size=8.5))
    if len(hosts) > MAX_HOST_ROWS:
        items.append(Spacer(1, 4))
        items.append(_para(_esc(f"... and {len(hosts) - MAX_HOST_ROWS} more hosts not listed."), "small"))
    return items


# --------------------------------------------------------------------------------------
# Page footer with "Page x of y"
# --------------------------------------------------------------------------------------
class _NumberedCanvas(pdfcanvas.Canvas):
    footer_text = ""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Dict[str, Any]] = []

    def showPage(self) -> None:  # noqa: N802 - reportlab API
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_footer(total)
            super().showPage()
        super().save()

    def _draw_footer(self, total: int) -> None:
        self.saveState()
        y = 0.42 * inch
        self.setStrokeColor(DIVIDER)
        self.setLineWidth(1)
        self.setDash(3, 3)
        self.line(MARGIN, y + 12, PAGE_W - MARGIN, y + 12)
        self.setFont(FONT, 8)
        self.setFillColor(INK_SOFT)
        self.drawString(MARGIN, y, _fit(self.footer_text, PAGE_W - 2 * MARGIN - 80, FONT, 8))
        self.setFont(BOLD, 8)
        self.drawRightString(PAGE_W - MARGIN, y, f"Page {self._pageNumber} of {total}")
        self.restoreState()


def _canvas_maker(footer_text: str) -> Callable[..., pdfcanvas.Canvas]:
    class _Canvas(_NumberedCanvas):
        pass

    _Canvas.footer_text = footer_text
    return _Canvas


# --------------------------------------------------------------------------------------
# Public: build_report
# --------------------------------------------------------------------------------------
def build_report(db: Any, start_ts: float, end_ts: float, *, title: str = "TNT Network Report",
                 targets: Optional[List[Dict[str, Any]]] = None, netinfo: Optional[Dict[str, Any]] = None,
                 tz_offset_s: Optional[int] = None) -> bytes:
    """Build the PDF report for ``[start_ts, end_ts]`` and return its bytes.

    ``targets`` (optional) are live target views from the PingManager (used for kind/label);
    the DB target list is always consulted too so removed/disabled targets with history still
    appear.  ``netinfo`` (optional) feeds the network summary box.  ``tz_offset_s`` fixes the
    local-time offset (seconds east of UTC); default is the machine's local zone.
    """
    t0 = time.perf_counter()
    start, end = float(start_ts), float(end_ts)
    if start > end:
        start, end = end, start
    if end - start < 60.0:
        end = start + 60.0
    clock = _Clock(tz_offset_s)
    now = time.time()
    try:
        hostname = socket.gethostname()
    except Exception:  # noqa: BLE001
        hostname = "unknown"
    width = CONTENT_W

    targets_list = _collect_targets(db, targets)
    errors: Dict[str, Optional[str]] = {"ping": None, "outages": None, "speed": None, "discovery": None}
    ping = outages = speed = discovery = None
    try:
        ping = _gather_ping(db, start, end, clock, targets_list)
    except Exception as exc:  # noqa: BLE001
        log.exception("export: gathering ping data failed")
        errors["ping"] = str(exc)
    try:
        outages = _gather_outages(db, start, end, targets_list)
    except Exception as exc:  # noqa: BLE001
        log.exception("export: gathering outages failed")
        errors["outages"] = str(exc)
    try:
        speed = _gather_speed(db, start, end, clock)
    except Exception as exc:  # noqa: BLE001
        log.exception("export: gathering speed tests failed")
        errors["speed"] = str(exc)
    try:
        discovery = _gather_discovery(db)
    except Exception as exc:  # noqa: BLE001
        log.exception("export: gathering discovery run failed")
        errors["discovery"] = str(exc)

    story: List[Flowable] = []
    story += _title_block(title, start, end, now, clock, hostname, width)
    story.append(_summary_cards(ping, outages, speed, discovery, clock, width))
    story.append(Spacer(1, 12))
    story += _network_box(_network_rows(netinfo), width)
    story += _ping_section(ping, start, end, clock, width, errors["ping"])
    story.append(Spacer(1, 10))
    story += _outage_section(outages, ping, start, end, clock, width, errors["outages"])
    story.append(Spacer(1, 10))
    story += _speed_section(speed, start, end, clock, width, errors["speed"])
    story.append(Spacer(1, 10))
    story += _discovery_section(discovery, start, clock, width, errors["discovery"])

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN, bottomMargin=MARGIN + 14,
        title=title, author=APP_LONG_NAME, subject=f"{clock.fmt(start)} to {clock.fmt(end)}",
        creator=f"TNT {__version__}",
    )
    footer = f"{APP_LONG_NAME} v{__version__}  ·  {title}  ·  {clock.fmt(start)} to {clock.fmt(end)}  ·  generated {clock.fmt(now)}"
    doc.build(story, canvasmaker=_canvas_maker(footer))
    pdf = buf.getvalue()
    log.info("built PDF report for %s..%s: %d bytes, %d targets, %d outages, %d speed tests in %.2f s",
             clock.fmt(start), clock.fmt(end), len(pdf), len(targets_list),
             outages["count"] if outages else 0, speed["count"] if speed else 0, time.perf_counter() - t0)
    return pdf


__all__ = ["build_report", "range_bounds"]
