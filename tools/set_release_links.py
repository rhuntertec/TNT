"""Rewrite the README's download block from ``tnt.__version__`` (dev-only tool).

Usage::

    python tools/set_release_links.py [--check]

The block sits between :data:`BEGIN` and :data:`END` at the top of ``README.md`` and is the first
thing anyone landing on the public repository sees.  It carries two links on purpose:

* **The version-less one** (``/releases/latest``) is the one that matters.  It cannot go stale, so a
  release that forgets this script still leaves a working download on the front page.
* **The direct ``.exe``** names a version, which means it *can* go stale - so
  ``tests/test_packaging.py`` fails the suite when it does not match ``tnt.__version__``.  Forgetting
  to run this is therefore not something that can reach a release.

``--check`` rewrites nothing and exits 1 when the block is out of date, for use from a test or a
build script.  Standard library only.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
REPO_URL = "https://github.com/rhuntertec/TNT"

BEGIN = "<!-- download: rewritten by tools/set_release_links.py -->"
END = "<!-- /download -->"


def version() -> str:
    """``tnt.__version__``, read out of the source rather than imported (no dependencies here)."""
    text = (ROOT / "tnt" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        raise SystemExit("could not find __version__ in tnt/__init__.py")
    return m.group(1)


def block(ver: str) -> str:
    """The download block for *ver*.  One big link, then the specifics under it."""
    setup = f"TNT-Setup-{ver}.exe"
    return "\n".join([
        BEGIN,
        "",
        f"## [⬇ Download TNT for Windows]({REPO_URL}/releases/latest)",
        "",
        f"**Latest release: {ver}** — "
        f"[{setup}]({REPO_URL}/releases/download/v{ver}/{setup}) · "
        f"[release notes]({REPO_URL}/releases/latest) · "
        f"[checksum]({REPO_URL}/releases/download/v{ver}/{setup}.sha256)",
        "",
        "Windows 10 or 11, 64-bit. The build is not code-signed, so SmartScreen will warn: choose",
        "**More info**, then **Run anyway**. Once installed, TNT updates itself from this page.",
        "",
        END,
    ])


def rewrite(text: str, ver: str) -> str:
    """*text* with the download block replaced, or inserted under the title when it is not there."""
    fresh = block(ver)
    if BEGIN in text and END in text:
        start = text.index(BEGIN)
        end = text.index(END) + len(END)
        return text[:start] + fresh + text[end:]
    lines = text.splitlines()
    at = 1 if lines and lines[0].startswith("# ") else 0
    return "\n".join(lines[:at] + ["", fresh] + lines[at:]) + "\n"


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description="rewrite the README download block")
    ap.add_argument("--check", action="store_true", help="only report whether it is up to date")
    args = ap.parse_args(argv)

    ver = version()
    text = README.read_text(encoding="utf-8")
    wanted = rewrite(text, ver)
    if text == wanted:
        print(f"README download block is up to date ({ver})")
        return 0
    if args.check:
        print(f"README download block is stale: it should name {ver}", file=sys.stderr)
        return 1
    README.write_text(wanted, encoding="utf-8", newline="\n")
    print(f"README download block rewritten for {ver}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
