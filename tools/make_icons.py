"""Generate the TNT icon assets with Pillow.

Writes (relative to the repository root, or ``--root``):

* ``assets/tnt.ico``      multi-size Windows icon (16..256 px) for the exes/installer
* ``assets/tnt-256.png``  256 px PNG (installer artwork, docs)
* ``ui/assets/logo.png``  256 px PNG used by the web UI as a fallback logo

Usage::

    python tools/make_icons.py [--root DIR] [--sizes 16,24,32,48,64,128,256]

This is a build tool, so it prints what it wrote. It is also called by
``installer/build.ps1`` before PyInstaller runs.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.icons import DEFAULT_ICO_SIZES, make_ico, make_icon  # noqa: E402


def generate(root: Path, sizes: Sequence[int] = DEFAULT_ICO_SIZES, png_size: int = 256) -> List[Path]:
    """Write every asset under *root* and return the list of written paths."""
    root = Path(root)
    written: List[Path] = []
    ico = root / "assets" / "tnt.ico"
    make_ico(ico, sizes)
    written.append(ico)
    for rel in ("assets/tnt-256.png", "ui/assets/logo.png"):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        make_icon(png_size).save(p, format="PNG", optimize=True)
        written.append(p)
    return written


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Generate TNT icon assets")
    ap.add_argument("--root", default=str(ROOT), help="project root to write into (default: repo root)")
    ap.add_argument("--sizes", default=",".join(str(s) for s in DEFAULT_ICO_SIZES),
                    help="comma-separated .ico sizes")
    args = ap.parse_args(argv)
    try:
        sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    except ValueError:
        ap.error("--sizes must be a comma-separated list of integers")
        return 2
    for p in generate(Path(args.root), sizes):
        print(f"wrote {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
