"""The TNT dynamite-stick icon, drawn with Pillow at any size.

The drawing follows the UI's visual language: a red cylinder with a thick ink outline,
a cream label band (with the word ``TNT`` when the icon is 48 px or larger), a
curved fuse and an orange four-point spark. An optional traffic-light dot
(green / yellow / red / grey) is overlaid in the bottom-right corner so the tray
icon can reflect the service's ``overall_light``.

Everything is rendered at 4x and downsampled with Lanczos, so even the 16 px
version has clean anti-aliased edges.

Public API
----------
``make_icon(size, light=None) -> PIL.Image.Image``  RGBA image ``size`` x ``size``.
``make_ico(path, sizes=(16, 24, 32, 48, 64, 128, 256)) -> Path``  multi-size .ico.
``LIGHT_COLOURS``  the palette used for the status dot.
"""
from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from PIL import Image, ImageDraw, ImageFont

log = logging.getLogger(__name__)

# Palette (the UI's light theme)
INK = (0x2B, 0x24, 0x38, 255)
RED = (0xFF, 0x5C, 0x5C, 255)
RED_DARK = (0xE0, 0x45, 0x45, 255)
CREAM = (0xFF, 0xF7, 0xE8, 255)
CREAM_2 = (0xFF, 0xF1, 0xD6, 255)
ORANGE = (0xFF, 0xA4, 0x5C, 255)
YELLOW = (0xFF, 0xD1, 0x66, 255)
GREEN = (0x6B, 0xCB, 0x77, 255)
GREY = (0x6B, 0x64, 0x80, 255)
WHITE = (255, 255, 255, 255)

LIGHT_COLOURS = {
    "green": GREEN,
    "yellow": YELLOW,
    "red": RED,
    "grey": GREY,
}

DEFAULT_ICO_SIZES: Tuple[int, ...] = (16, 24, 32, 48, 64, 128, 256)

# Supersampling factor: draw big, shrink with Lanczos.
_SS = 4
# Lean of the stick in degrees (positive = top leans to the right).
_LEAN_DEG = 22.0
# Candidate bold fonts for the label (Windows first, then Pillow's default).
_FONT_CANDIDATES = ("arialbd.ttf", "segoeuib.ttf", "verdanab.ttf", "DejaVuSans-Bold.ttf")


def _bezier(p0: Tuple[float, float], p1: Tuple[float, float], p2: Tuple[float, float],
            steps: int = 24) -> List[Tuple[float, float]]:
    """Points along a quadratic Bezier curve."""
    pts = []
    for i in range(steps + 1):
        t = i / steps
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t ** 2 * p2[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t ** 2 * p2[1]
        pts.append((x, y))
    return pts


def _thick_polyline(draw: ImageDraw.ImageDraw, pts: Sequence[Tuple[float, float]], width: float, fill) -> None:
    """Polyline with round joints (ImageDraw.line joints look ragged when thick)."""
    w = max(1.0, width)
    r = w / 2.0
    draw.line(list(pts), fill=fill, width=int(round(w)), joint="curve")
    for x, y in (pts[0], pts[-1]):
        draw.ellipse((x - r, y - r, x + r, y + r), fill=fill)


def _star_points(cx: float, cy: float, outer: float, inner: float, points: int = 4,
                 rotation_deg: float = 0.0) -> List[Tuple[float, float]]:
    pts = []
    for i in range(points * 2):
        ang = math.radians(rotation_deg) + i * math.pi / points
        rad = outer if i % 2 == 0 else inner
        pts.append((cx + rad * math.sin(ang), cy - rad * math.cos(ang)))
    return pts


def _load_font(px: int) -> ImageFont.ImageFont | ImageFont.FreeTypeFont:
    for name in _FONT_CANDIDATES:
        try:
            return ImageFont.truetype(name, px)
        except Exception:  # noqa: BLE001 - font not installed, try the next
            continue
    try:
        return ImageFont.load_default(size=px)
    except TypeError:  # very old Pillow without the size argument
        return ImageFont.load_default()


def _draw_stick(canvas: int, with_label: bool) -> Image.Image:
    """Draw the (unrotated) stick, fuse and spark on a transparent canvas."""
    img = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    u = float(canvas)
    outline = max(1.0, 0.055 * u)
    ow = int(round(outline))

    # --- fuse (drawn first so the stick's top overlaps its root) ---------
    fuse_root = (0.47 * u, 0.30 * u)
    fuse_ctrl = (0.44 * u, 0.12 * u)
    fuse_tip = (0.66 * u, 0.15 * u)
    fuse = _bezier(fuse_root, fuse_ctrl, fuse_tip)
    _thick_polyline(d, fuse, outline * 1.25, INK)
    _thick_polyline(d, fuse, max(1.0, outline * 0.45), CREAM_2)

    # --- body -------------------------------------------------------------
    x0, y0, x1, y1 = 0.30 * u, 0.28 * u, 0.64 * u, 0.92 * u
    radius = 0.07 * u
    d.rounded_rectangle((x0, y0, x1, y1), radius=radius, fill=RED, outline=INK, width=ow)
    # darker "cap" at the top and a highlight stripe for a cartoony gloss
    d.rounded_rectangle((x0, y0, x1, y0 + 0.09 * u), radius=radius, fill=RED_DARK)
    d.rectangle((x0, y0 + 0.045 * u, x1, y0 + 0.09 * u), fill=RED_DARK)
    d.line((x0, y0 + 0.09 * u, x1, y0 + 0.09 * u), fill=INK, width=max(1, int(round(outline * 0.6))))
    d.rounded_rectangle((x0 + 0.05 * u, y0 + 0.16 * u, x0 + 0.095 * u, y1 - 0.08 * u),
                        radius=0.02 * u, fill=(255, 255, 255, 70))
    # re-draw the outline on top of the cap fill
    d.rounded_rectangle((x0, y0, x1, y1), radius=radius, outline=INK, width=ow)

    # --- label band ---------------------------------------------------------
    lx0, ly0, lx1, ly1 = x0 - 0.02 * u, 0.50 * u, x1 + 0.02 * u, 0.70 * u
    d.rounded_rectangle((lx0, ly0, lx1, ly1), radius=0.03 * u, fill=CREAM, outline=INK, width=ow)
    if with_label:
        px = max(6, int(0.135 * u))
        font = _load_font(px)
        text = "TNT"
        # shrink until it fits inside the band with a little padding
        for _ in range(8):
            bbox = d.textbbox((0, 0), text, font=font)
            tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
            if tw <= (lx1 - lx0) - 2 * ow - 0.04 * u and th <= (ly1 - ly0) - 2 * ow:
                break
            px = max(4, int(px * 0.9))
            font = _load_font(px)
        bbox = d.textbbox((0, 0), text, font=font)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        tx = (lx0 + lx1) / 2 - tw / 2 - bbox[0]
        ty = (ly0 + ly1) / 2 - th / 2 - bbox[1]
        d.text((tx, ty), text, font=font, fill=INK)
    elif canvas >= 32 * _SS:
        # mid sizes: three ink ticks suggest the lettering (tiny sizes stay plain)
        gap = (lx1 - lx0) / 4
        for i in range(1, 4):
            cx = lx0 + gap * i
            d.line((cx, ly0 + 0.05 * u, cx, ly1 - 0.05 * u), fill=INK, width=max(1, int(round(outline * 0.7))))

    # --- spark ------------------------------------------------------------
    sx, sy = fuse_tip[0] + 0.02 * u, fuse_tip[1] - 0.02 * u
    outer, inner = 0.15 * u, 0.05 * u
    pts = _star_points(sx, sy, outer, inner, 4, rotation_deg=0.0)
    # thinner outline than the body so the spark reads orange even at 16-32 px
    d.polygon(pts, fill=ORANGE, outline=INK, width=max(1, int(round(outline * 0.4))))
    core = 0.035 * u
    d.ellipse((sx - core, sy - core, sx + core, sy + core), fill=YELLOW)
    return img


def _draw_dot(img: Image.Image, colour: Tuple[int, int, int, int]) -> None:
    """Traffic-light dot with an ink outline and a gloss highlight, bottom-right."""
    d = ImageDraw.Draw(img)
    u = float(img.size[0])
    r = 0.19 * u
    cx, cy = u - r - 0.03 * u, u - r - 0.03 * u
    ow = max(1, int(round(0.05 * u)))
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=colour, outline=INK, width=ow)
    hr = r * 0.28
    hx, hy = cx - r * 0.38, cy - r * 0.38
    d.ellipse((hx - hr, hy - hr, hx + hr, hy + hr), fill=(255, 255, 255, 210))


def make_icon(size: int, light: Optional[str] = None) -> Image.Image:
    """Return an RGBA ``size`` x ``size`` image of the TNT dynamite stick.

    ``light`` is ``None`` (no dot) or one of ``green``, ``yellow``, ``red``,
    ``grey``; any other string is drawn as grey (unknown state).
    """
    size = int(size)
    if size < 8:
        raise ValueError("icon size must be at least 8 px")
    canvas = size * _SS
    layer = _draw_stick(canvas, with_label=size >= 48)
    # rotate around the centre; expand=False keeps the canvas size
    layer = layer.rotate(-_LEAN_DEG, resample=Image.Resampling.BICUBIC, expand=False,
                         center=(canvas / 2, canvas / 2))
    if light is not None:
        _draw_dot(layer, LIGHT_COLOURS.get(str(light).lower(), GREY))
    out = layer.resize((size, size), Image.Resampling.LANCZOS)
    if out.mode != "RGBA":
        out = out.convert("RGBA")
    return out


def make_ico(path: Path | str, sizes: Iterable[int] = DEFAULT_ICO_SIZES) -> Path:
    """Write a multi-size Windows .ico (each size drawn natively, not resampled)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    wanted = sorted({int(s) for s in sizes if 8 <= int(s) <= 256}, reverse=True)
    if not wanted:
        raise ValueError("no valid icon sizes")
    images = [make_icon(s) for s in wanted]
    base, extra = images[0], images[1:]
    base.save(path, format="ICO", sizes=[(s, s) for s in wanted], append_images=extra)
    log.debug("wrote %s with sizes %s", path, wanted)
    return path
