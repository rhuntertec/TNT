# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for ``TNTService.exe`` - the TNT Windows service (onedir, console).

Build from the project root inside the venv::

    python -m PyInstaller --noconfirm --clean installer/tnt_service.spec

Output layout (PyInstaller 6 ``contents_directory``)::

    dist/TNTService/TNTService.exe
    dist/TNTService/_service/...        (python runtime, packages, ui/, assets/)

The support folder is called ``_service`` (not the default ``_internal``) so that
``installer/tnt.iss`` can copy the service *and* the client bundle into the same
``{app}`` folder without the two ``_internal`` trees colliding.
``tnt.paths.ui_dir()`` resolves ``sys._MEIPASS/ui`` which is exactly this folder.

* ``console=True``: the service host needs a console subsystem exe (pywin32
  services are started by the SCM; the console is never shown) and it lets
  ``TNTService.exe --console --port 7135`` run in the foreground for debugging.
* ``ui/`` is bundled as data, without Markdown files (``a.datas`` goes through
  ``pyi_common.without_markdown``); ``netaddr`` needs its OUI/IAB index files.
* ``pyi_common.NOT_BUNDLED`` (Pillow's AVIF module) is excluded, as in the client spec.
* pywin32 service modules are not discoverable by static analysis, hence the
  explicit ``hiddenimports`` (``win32timezone`` is the classic missing one).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files
from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo,
    StringFileInfo,
    StringStruct,
    StringTable,
    VarFileInfo,
    VarStruct,
    VSVersionInfo,
)

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 - SPECPATH is injected by PyInstaller
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(Path(SPECPATH).resolve()) not in sys.path:  # noqa: F821
    sys.path.insert(0, str(Path(SPECPATH).resolve()))  # noqa: F821
from pyi_common import NOT_BUNDLED, conda_runtime_dlls, describe, without_markdown  # noqa: E402

# conda interpreters keep ffi-8.dll / sqlite3.dll / libbz2 / liblzma / libexpat / OpenSSL in
# Library\bin; PyInstaller misses them unless that folder is on PATH, so add them explicitly
CONDA_DLLS = conda_runtime_dlls()
print(f"[tnt_service.spec] conda runtime DLLs: {describe(CONDA_DLLS)}")

APP_LONG_NAME = "TNT - TEC Network Tool"
COMPANY = "Total Electronics"
ICON = ROOT / "assets" / "tnt.ico"
if not ICON.is_file():
    raise SystemExit(f"{ICON} is missing - run 'python tools/make_icons.py' first")


def _version() -> str:
    text = (ROOT / "tnt" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.M)
    return m.group(1) if m else "0.0.0"


def _version_tuple(v: str) -> tuple:
    nums = [int(x) for x in re.findall(r"\d+", v)[:4]]
    while len(nums) < 4:
        nums.append(0)
    return tuple(nums)


def _version_info(exe_name: str, description: str) -> VSVersionInfo:
    ver = _version()
    vt = _version_tuple(ver)
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=vt, prodvers=vt, mask=0x3F, flags=0x0, OS=0x40004,
                          fileType=0x1, subtype=0x0, date=(0, 0)),
        kids=[
            StringFileInfo([StringTable("040904B0", [
                StringStruct("CompanyName", COMPANY),
                StringStruct("FileDescription", description),
                StringStruct("FileVersion", ver),
                StringStruct("InternalName", exe_name),
                StringStruct("LegalCopyright", f"Copyright (c) {COMPANY}"),
                StringStruct("OriginalFilename", exe_name + ".exe"),
                StringStruct("ProductName", APP_LONG_NAME),
                StringStruct("ProductVersion", ver),
            ])]),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )


def _tnt_modules() -> list:
    """Every module of the ``tnt`` package (walks the tree; no imports needed)."""
    mods = set()
    for p in (ROOT / "tnt").rglob("*.py"):
        parts = list(p.relative_to(ROOT).with_suffix("").parts)
        if "__pycache__" in parts:
            continue
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if parts[-1] == "__main__":
            continue  # the entry script itself
        mods.add(".".join(parts))
    return sorted(mods)


datas = [
    (str(ROOT / "ui"), "ui"),
    (str(ICON), "assets"),
]
datas += collect_data_files("netaddr")  # OUI / IAB vendor index files

hiddenimports = [
    # pywin32 service plumbing
    "win32timezone",
    "servicemanager",
    "win32serviceutil",
    "win32service",
    "win32event",
    "win32api",
    "win32con",
    "pywintypes",
    # our own package, including every speed-test backend and API module
    *_tnt_modules(),
]

excludes = [
    "tkinter", "_tkinter",
    "matplotlib",
    "PyQt5", "PyQt6", "PySide2", "PySide6", "qtpy",
    # client-only packages
    "webview", "pystray", "clr", "clr_loader", "pythonnet",
    "pytest", "PyInstaller",
    # modules TNT never uses (Pillow's AVIF codecs); THIRD-PARTY-NOTICES.txt relies on this
    *NOT_BUNDLED,
]

a = Analysis(  # noqa: F821
    [str(ROOT / "tnt" / "__main__.py")],
    pathex=[str(ROOT)],
    binaries=list(CONDA_DLLS),
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)
# no Markdown file ships: ui/ is copied as a whole folder (see installer/pyi_common.py)
a.datas = without_markdown(a.datas)
pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="TNTService",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON),
    version=_version_info("TNTService", f"{APP_LONG_NAME} Service"),
    contents_directory="_service",
    uac_admin=False,
)
coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="TNTService",
)
