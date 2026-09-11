# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for ``TNT.exe`` - the tray icon + WebView2 window client (onedir, no console).

Build from the project root inside the venv::

    python -m PyInstaller --noconfirm --clean installer/tnt_client.spec

Output layout (PyInstaller 6 ``contents_directory``)::

    dist/TNT/TNT.exe
    dist/TNT/_client/...        (python runtime, pywebview + pythonnet runtime, pystray, PIL, assets/)

``_client`` (instead of the default ``_internal``) lets ``installer/tnt.iss`` merge
this bundle with the service bundle into one ``{app}`` folder.

What is collected and why
* ``webview`` (pywebview): ``collect_all`` for its ``lib/`` (WebView2Loader.dll,
  WebBrowserInterop) and ``js/`` files; the non-Windows platform modules
  (qt/gtk/cocoa/android) are filtered out of the hidden imports.
* ``pythonnet`` + ``clr_loader``: the .NET bridge pywebview's edgechromium backend
  runs on (``Python.Runtime.dll``, ``ClrLoader.dll`` and the ``runtime/`` folder).
  pythonnet ships its own PyInstaller hook, the explicit collection is belt and braces.
* ``pystray`` (``collect_all`` so the ``_win32`` backend is present) and PIL
  (icon drawing; ``client.icons``).
* ``tnt`` is bundled only for ``tnt/__init__.py`` (the version string).
* ``a.datas`` goes through ``pyi_common.without_markdown``: no Markdown file of TNT's ships (the
  same filter as the service spec, which bundles ``ui/``); a package's own licence files are kept.
* ``pyi_common.NOT_BUNDLED`` (Pillow's AVIF module) is excluded, as in the service spec.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files
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

CONDA_DLLS = conda_runtime_dlls()  # see installer/pyi_common.py
print(f"[tnt_client.spec] conda runtime DLLs: {describe(CONDA_DLLS)}")

APP_LONG_NAME = "TNT - TEC Network Tool"
COMPANY = "Total Electronics"
ICON = ROOT / "assets" / "tnt.ico"
if not ICON.is_file():
    raise SystemExit(f"{ICON} is missing - run 'python tools/make_icons.py' first")

# pywebview / pystray backends for other platforms (their deps are absent or excluded)
_NON_WINDOWS_TAGS = (".qt", ".gtk", ".cocoa", ".android", "._darwin", "._gtk", "._xorg",
                     "._appindicator", "._ayatana_appindicator")


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


datas = [(str(ICON), "assets")]
binaries = list(CONDA_DLLS)
hiddenimports = [
    "clr", "pythonnet", "clr_loader", "clr_loader.netfx", "clr_loader.hostfxr",
    "webview", "webview.platforms.winforms", "webview.platforms.edgechromium",
    "pystray", "pystray._win32",
    "PIL", "PIL.Image", "PIL.ImageDraw", "PIL.ImageFont",
    "PIL.IcoImagePlugin", "PIL.PngImagePlugin", "PIL.BmpImagePlugin",
    "tnt", "client", "client.icons",
]

for _pkg in ("webview", "clr_loader", "pystray"):
    _d, _b, _h = collect_all(_pkg)
    datas += _d
    binaries += _b
    hiddenimports += [h for h in _h if not any(tag in h for tag in _NON_WINDOWS_TAGS)]

# pythonnet: Python.Runtime.dll and the runtime/ assemblies live in package data
datas += collect_data_files("pythonnet")

# de-duplicate while keeping order
hiddenimports = list(dict.fromkeys(hiddenimports))

excludes = [
    "tkinter", "_tkinter",
    "matplotlib",
    "PyQt5", "PyQt6", "PySide2", "PySide6", "qtpy", "gi", "AppKit", "Foundation", "objc",
    # service-only packages
    "reportlab", "netaddr", "psutil",
    "win32serviceutil", "win32service", "servicemanager",
    "pytest", "PyInstaller",
    # modules TNT never uses (Pillow's AVIF codecs); THIRD-PARTY-NOTICES.txt relies on this
    *NOT_BUNDLED,
]

a = Analysis(  # noqa: F821
    [str(ROOT / "client" / "tray.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)
# no Markdown file of TNT's ships; a collected package keeps its own (see installer/pyi_common.py)
a.datas = without_markdown(a.datas)
pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="TNT",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ICON),
    version=_version_info("TNT", APP_LONG_NAME),
    contents_directory="_client",
    uac_admin=False,
)
coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="TNT",
)
