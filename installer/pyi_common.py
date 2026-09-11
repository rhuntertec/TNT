"""Helpers shared by the two PyInstaller spec files.

Conda-based interpreters (including a venv created from a Miniconda Python) keep the
DLLs that the standard-library C extensions need -- ``ffi-8.dll`` for ``_ctypes``,
``sqlite3.dll`` for ``_sqlite3``, ``libbz2``/``liblzma``/``libexpat``/OpenSSL -- in
``<base_prefix>\\Library\\bin`` instead of next to the ``.pyd`` files. PyInstaller only
finds them when that folder happens to be on ``PATH`` at build time, so a build started
from a plain ``powershell -NoProfile`` silently produced bundles whose ``import ctypes``
and ``import sqlite3`` failed at runtime ("DLL load failed while importing _ctypes").

:func:`conda_runtime_dlls` computes the list deterministically from the import tables
of the interpreter's own ``DLLs\\*.pyd`` files and returns PyInstaller ``binaries``
entries. On a python.org interpreter it returns ``[]``.

:func:`without_markdown` is the data filter both specs apply to ``Analysis.datas`` before
``COLLECT``: TNT's own Markdown (``*.md``) is developer documentation and never ships in a bundle,
wherever it sits (``ui/`` is bundled as a folder by the service spec). Markdown that comes with an
installed third-party package (its ``site-packages`` folder or its ``*.dist-info`` metadata) is
kept: it can be a licence or notice file that has to ship with the package.

:data:`NOT_BUNDLED` lists modules both specs exclude because TNT never uses them; the
redistribution notices (``THIRD-PARTY-NOTICES.txt``) rely on it.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Tuple

# extensions we never ship (tkinter) or that PyInstaller resolves itself (CRT, VC runtime)
_SKIP_PYDS = {"_tkinter.pyd", "_ctypes_test.pyd", "_msi.pyd", "winsound.pyd", "xxlimited.pyd",
              "xxlimited_35.pyd"}
_SKIP_DLL_PREFIXES = ("api-ms-win-", "vcruntime", "msvcp", "concrt", "ucrtbase", "tcl", "tk")

#: Modules neither bundle ships (added to both specs' ``excludes``). ``PIL._avif`` reads and writes
#: AVIF images, which TNT never does, and is the only Pillow module linked with libavif and the dav1d
#: and libaom AV1 codecs; Pillow's AvifImagePlugin imports without it (AVIF is reported unsupported).
NOT_BUNDLED: List[str] = ["PIL._avif"]


def conda_runtime_dlls() -> List[Tuple[str, str]]:
    base = Path(getattr(sys, "base_prefix", sys.prefix))
    libbin = base / "Library" / "bin"
    dlls_dir = base / "DLLs"
    if not (base / "conda-meta").is_dir() or not libbin.is_dir() or not dlls_dir.is_dir():
        return []
    try:
        from PyInstaller.depend.bindepend import get_imports
    except Exception:  # noqa: BLE001 - very old/new PyInstaller: fall back to a known list
        get_imports = None
    available = {p.name.lower(): p for p in libbin.glob("*.dll")}
    wanted: set[str] = set()
    if get_imports is not None:
        for pyd in dlls_dir.glob("*.pyd"):
            if pyd.name.lower() in _SKIP_PYDS or pyd.name.lower().startswith("_test"):
                continue
            try:
                imports = get_imports(str(pyd))
            except Exception:  # noqa: BLE001
                continue
            for imp in imports:
                name = imp[0] if isinstance(imp, tuple) else imp
                wanted.add(os.path.basename(str(name)).lower())
    else:
        wanted = {"ffi-8.dll", "ffi.dll", "sqlite3.dll", "libbz2.dll", "liblzma.dll", "libexpat.dll",
                  "libssl-3-x64.dll", "libcrypto-3-x64.dll", "zlib.dll"}
    out: List[Tuple[str, str]] = []
    for name in sorted(wanted):
        if name.startswith(_SKIP_DLL_PREFIXES):
            continue
        path = available.get(name)
        if path is not None:
            out.append((str(path), "."))
    return out


def describe(binaries: List[Tuple[str, str]]) -> str:
    return ", ".join(Path(src).name for src, _ in binaries) or "(none - not a conda interpreter)"


def is_markdown(name: str) -> bool:
    """True for a Markdown file (``*.md``, any case), given a file name or a bundle path."""
    return str(name).lower().endswith(".md")


def from_installed_package(entry: Tuple) -> bool:
    """A ``(dest_name, src_name, typecode)`` entry collected from an installed package: its source
    lies in a ``site-packages`` folder or its destination in a ``*.dist-info`` / ``*.egg-info`` folder."""
    dest = str(entry[0]).replace("\\", "/").lower().split("/")
    src = str(entry[1]).replace("\\", "/").lower().split("/") if len(entry) > 1 else []
    return "site-packages" in src or any(part.endswith((".dist-info", ".egg-info")) for part in dest)


def without_markdown(toc: List[Tuple]) -> List[Tuple]:
    """``Analysis.datas`` (``(dest_name, src_name, typecode)`` entries) without TNT's Markdown files;
    an installed package's own Markdown (a licence file in its dist-info, say) is kept."""
    return [entry for entry in toc if not is_markdown(entry[0]) or from_installed_package(entry)]
