"""Logging: rotating file log + in-memory ring buffer for the diagnostics view."""
from __future__ import annotations

import collections
import logging
import logging.handlers
import sys
import threading
from pathlib import Path
from typing import Deque, Dict, List, Optional

from . import paths

_ring_lock = threading.Lock()
_RING: Deque[Dict[str, object]] = collections.deque(maxlen=600)
_configured = False


class RingHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:  # noqa: BLE001
            msg = record.getMessage()
        with _ring_lock:
            _RING.append({
                "ts": record.created,
                "level": record.levelname,
                "logger": record.name,
                "message": msg,
            })


def recent_records(limit: int = 200, min_level: str = "DEBUG") -> List[Dict[str, object]]:
    lvl = logging.getLevelName(min_level.upper()) if isinstance(min_level, str) else min_level
    if not isinstance(lvl, int):
        lvl = logging.DEBUG
    with _ring_lock:
        items = [r for r in _RING if logging.getLevelName(str(r["level"])) >= lvl]
    return items[-limit:]


def setup_logging(console: bool = False, level: int = logging.INFO, log_dir: Optional[Path] = None) -> Path:
    """Idempotent. Returns the path of the main log file."""
    global _configured
    log_dir = log_dir or paths.logs_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "tnt-service.log"
    root = logging.getLogger()
    if _configured:
        return log_file
    root.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    ring = RingHandler()
    ring.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    root.addHandler(ring)
    if console and sys.stderr is not None:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        root.addHandler(sh)
    _configured = True
    return log_file
