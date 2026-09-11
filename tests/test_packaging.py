"""Release packaging inputs: no Markdown in a PyInstaller bundle, the licence files in the installer.

The PyInstaller specs are not executed here (that is a full build). Instead the tests check the
data filter both specs apply (``installer/pyi_common.without_markdown``) and run it over what
PyInstaller would collect from ``ui/``.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "installer"
SPECS = ("tnt_service.spec", "tnt_client.spec")


def _pyi_common():
    spec = importlib.util.spec_from_file_location("tnt_pyi_common_under_test", INSTALLER / "pyi_common.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_markdown_filter_drops_md_files_only():
    pc = _pyi_common()
    toc = [
        ("ui\\index.html", "src\\ui\\index.html", "DATA"),
        ("ui\\assets\\fonts\\README.md", "src\\ui\\assets\\fonts\\README.md", "DATA"),
        ("ui/NOTES.MD", "src/ui/NOTES.MD", "DATA"),
        ("docs\\DESIGN.md", "C:\\src\\TNT\\docs\\DESIGN.md", "DATA"),
        ("webview/js/api.js", "site/webview/js/api.js", "DATA"),
        ("ui\\assets\\fonts\\README.txt", "src\\ui\\assets\\fonts\\README.txt", "DATA"),
        ("pkg\\changes.md.txt", "site\\pkg\\changes.md.txt", "DATA"),
    ]
    assert [dest for dest, _, _ in pc.without_markdown(toc)] == [
        "ui\\index.html", "webview/js/api.js", "ui\\assets\\fonts\\README.txt", "pkg\\changes.md.txt"]
    assert pc.is_markdown("README.md") and pc.is_markdown("docs/DESIGN.MD") and not pc.is_markdown("md.txt")


def test_markdown_filter_keeps_an_installed_packages_own_markdown():
    """A package may declare a Markdown licence file (pythonnet's METADATA lists ``License-File:
    AUTHORS.md``); collecting its metadata must not strip a notice that has to ship with it."""
    pc = _pyi_common()
    site = "C:\\build\\.venv\\Lib\\site-packages"
    toc = [
        ("pythonnet-3.1.0.dist-info\\AUTHORS.md", site + "\\pythonnet-3.1.0.dist-info\\AUTHORS.md", "DATA"),
        ("somepkg/LICENSE.md", site.replace("\\", "/") + "/somepkg/LICENSE.md", "DATA"),
        ("other-1.0.dist-info/licenses/NOTICE.MD", "C:/elsewhere/other-1.0.dist-info/licenses/NOTICE.MD", "DATA"),
        ("ui\\CHANGES.md", "C:\\build\\ui\\CHANGES.md", "DATA"),
    ]
    assert [dest for dest, _, _ in pc.without_markdown(toc)] == [dest for dest, _, _ in toc[:3]]
    assert pc.from_installed_package(toc[0]) and not pc.from_installed_package(toc[3])


def test_both_specs_exclude_the_modules_tnt_never_uses():
    """THIRD-PARTY-NOTICES.txt leaves out Pillow's AVIF module (libavif, dav1d, libaom) because
    neither bundle contains it."""
    import subprocess
    import sys

    pc = _pyi_common()
    assert "PIL._avif" in pc.NOT_BUNDLED
    # Pillow copes with the module missing, as in a bundle: images still open, AVIF reports unsupported
    probe = ("import io, sys; sys.modules['PIL._avif'] = None\n"
             "from PIL import Image, AvifImagePlugin\n"
             "Image.init(); Image.new('RGB', (2, 2)).save(io.BytesIO(), 'PNG')\n"
             "print(AvifImagePlugin.SUPPORTED, 'PNG' in Image.SAVE)")
    r = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.split() == ["False", "True"], r.stderr
    for name in SPECS:
        text = (INSTALLER / name).read_text(encoding="utf-8")
        assert re.search(r"^from pyi_common import .*\bNOT_BUNDLED\b", text, re.M), name
        excludes = re.search(r"^excludes = \[(.*?)^\]", text, re.M | re.S).group(1)
        assert re.search(r"^\s*\*NOT_BUNDLED,\s*$", excludes, re.M), name
        assert "excludes=excludes" in text, name
    notices = (ROOT / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
    assert "PIL._avif" in notices and "libaom" in notices    # named as not bundled


@pytest.mark.parametrize("name", SPECS)
def test_spec_filters_markdown_before_collect(name):
    text = (INSTALLER / name).read_text(encoding="utf-8")
    assert re.search(r"^from pyi_common import .*\bwithout_markdown\b", text, re.M), name
    line = "a.datas = without_markdown(a.datas)"
    assert re.search(r"^" + re.escape(line) + r"$", text, re.M), name
    # after Analysis builds a.datas and before COLLECT copies the files
    assert text.index("a = Analysis(") < text.index(line) < text.index("coll = COLLECT("), name


def test_service_bundle_would_ship_no_markdown_from_ui():
    """Expand the service spec's ``(ui, "ui")`` data entry the way PyInstaller does, then filter it."""
    utils = pytest.importorskip("PyInstaller.building.utils")
    spec_text = (INSTALLER / "tnt_service.spec").read_text(encoding="utf-8")
    assert '(str(ROOT / "ui"), "ui")' in spec_text, "the service spec no longer bundles ui/ as one folder"
    collected = [(dest, src, "DATA") for dest, src in utils.format_binaries_and_datas([(str(ROOT / "ui"), "ui")])]
    kept = {Path(dest).as_posix() for dest, _, _ in _pyi_common().without_markdown(collected)}
    assert "ui/index.html" in kept and "ui/assets/fonts/README.txt" in kept and "ui/assets/fonts/OFL.txt" in kept
    assert not [dest for dest in kept if dest.lower().endswith(".md")]


def test_ui_tree_has_no_markdown():
    """The fonts note is README.txt; a Markdown file in ui/ would be dropped from the bundle silently."""
    assert not [p.relative_to(ROOT).as_posix() for p in (ROOT / "ui").rglob("*") if p.suffix.lower() == ".md"]


def test_installer_installs_licence_and_notices():
    iss = (INSTALLER / "tnt.iss").read_text(encoding="utf-8")
    files = re.search(r"^\[Files\]\s*$(.*?)^\[", iss, re.M | re.S).group(1)
    assert re.search(r'^Source: "\.\.\\LICENSE"; DestDir: "\{app\}"', files, re.M)
    assert re.search(r'^Source: "\.\.\\THIRD-PARTY-NOTICES\.txt"; DestDir: "\{app\}"', files, re.M)
    assert "internal tool" not in iss


def test_installer_removes_the_retired_tools_folder_and_names_no_private_doc():
    iss = (INSTALLER / "tnt.iss").read_text(encoding="utf-8")
    deletes = re.search(r"^\[InstallDelete\]\s*$(.*?)^\[", iss, re.M | re.S).group(1)
    exe = deletes.index('Type: files; Name: "{app}\\bin\\speedtest.exe"')
    assert exe < deletes.index('Type: dirifempty; Name: "{app}\\bin"')   # the file first, then the empty folder
    # the Markdown docs are not published: the installer script must not send a reader to one
    assert not re.search(r"[\w\\/]+\.md\b", iss, re.I)


def test_licence_and_notices_files():
    licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert licence.startswith("MIT License\n\nCopyright (c) 2026 Total Electronics\n\nPermission is hereby granted")
    notices = (ROOT / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
    for name in ("CPython", "OpenSSL", "PyInstaller", "Bootloader-exception", "pywebview", "pythonnet", "WebView2",
                 "pystray", "LGPL-3.0-or-later", "Pillow", "ReportLab", "netaddr", "IEEE", "pywin32", "Nunito", "OFL-1.1",
                 # code inside Pillow's text module and pywebview's / pythonnet's bundled parts
                 "libraqm", "Khaled Hosny", "FriBiDi", "LGPL-2.1-or-later", "GNU LESSER GENERAL PUBLIC LICENSE\n                       Version 2.1",
                 ".NET Foundation and Contributors", "Werkzeug", "Copyright 2007 Pallets",
                 "The name of Microsoft Corporation, or the names of its contributors"):
        assert name in notices, name
    assert "not reproduced here" not in notices
    # every [Tn] the inventory refers to is reproduced in part 2
    inventory, texts = notices.split("PART 2. LICENCE TEXTS", 1)
    refs = {int(n) for n in re.findall(r"\bT(\d+)\b", inventory)}
    present = {int(n) for n in re.findall(r"^\[T(\d+)\] ", texts, re.M)}
    assert refs and refs <= present, sorted(refs - present)
