r"""Filesystem locations used by the service.

Everything lives under ``%ProgramData%\TNT`` by default so that the service
(running as LocalSystem) and an unprivileged reader agree on where data is.
Override with the ``TNT_DATA_DIR`` environment variable (used by tests and the
console/dev mode).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from . import APP_NAME


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def data_dir() -> Path:
    override = os.environ.get("TNT_DATA_DIR")
    if override:
        return Path(override)
    base = os.environ.get("ProgramData") or r"C:\ProgramData"
    return Path(base) / APP_NAME


def logs_dir() -> Path:
    return data_dir() / "logs"


def ping_logs_dir() -> Path:
    return logs_dir() / "pings"


def exports_dir() -> Path:
    return data_dir() / "exports"


def config_path() -> Path:
    return data_dir() / "config.json"


def db_path() -> Path:
    return data_dir() / "tnt.db"


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def ui_dir() -> Path:
    """Static UI files. In a PyInstaller build they are bundled next to the exe."""
    if is_frozen():
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        cand = base / "ui"
        if cand.is_dir():
            return cand
        return Path(sys.executable).parent / "ui"
    return repo_root() / "ui"


def ensure_dirs() -> None:
    for d in (data_dir(), logs_dir(), ping_logs_dir(), exports_dir()):
        d.mkdir(parents=True, exist_ok=True)
