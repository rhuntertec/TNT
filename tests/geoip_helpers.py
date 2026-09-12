"""Builders for IP location (tnt/geoip.py) tests: a fake HTTP seam and managers on tmp_path folders.

This is the one place that builds a :class:`tnt.geoip.GeoIpManager` for the tests (a helper module, not collected by
pytest), so no test ever touches the real data folder or the network. ``make_manager`` injects a :class:`FakeHttp`
(every URL answers 404) unless told otherwise; ``urlopen=False`` leaves the module seam ``tnt.geoip._urlopen``, which
tests/conftest.py blocks for the whole session. Addresses are documentation ranges.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from mmdb_writer import VERIFY_PROBES_FIXTURE, fixture_pair, gzip_bytes
from tnt import geoip
from tnt.config import Config


class FakeResponse:
    """A canned response: status, headers (lower-case), url, host, readinto, close, abort; ``aborted`` flag."""

    def __init__(self, owner: "FakeHttp", url: str, status: int, headers: Dict[str, str], body: bytes,
                 chunk: int) -> None:
        self._owner = owner
        self.url = url
        self.host = geoip.host_text(urlsplit(url).hostname)
        self.status = status
        self.headers = {str(k).lower(): v for k, v in headers.items()}
        self.body = body
        self.pos = 0
        self.chunk = chunk
        self.aborted = False
        self.closed = False
        self.abort_event = threading.Event()   # set by abort(): lets a read_hook block "until the socket is shut"

    def readinto(self, buf: Any) -> int:
        hook = self._owner.read_hook
        if hook is not None:
            hook(self, self.pos)
        if self.aborted:
            return 0
        n = min(self.chunk, len(buf), len(self.body) - self.pos)
        if n <= 0:
            return 0
        buf[:n] = self.body[self.pos:self.pos + n]
        self.pos += n
        return n

    def close(self) -> None:
        self.closed = True

    def abort(self) -> None:
        self.aborted = True
        self.abort_event.set()


class FakeHttp:
    """The injected ``urlopen``: answers from ``table`` (url -> (status, headers, body)), else ``default_status``."""

    def __init__(self, table: Optional[Dict[str, Tuple[int, Dict[str, str], bytes]]] = None, *,
                 chunk: int = 65536, default_status: int = 404) -> None:
        self.table: Dict[str, Tuple[int, Dict[str, str], bytes]] = dict(table or {})
        self.chunk = chunk
        self.default_status = default_status
        self.urls: List[str] = []
        self.responses: List[FakeResponse] = []
        self.read_hook: Optional[Callable[[FakeResponse, int], None]] = None
        self._lock = threading.Lock()

    def serve_month(self, month: str, *, city: Optional[bytes] = None, asn: Optional[bytes] = None,
                    date: Optional[str] = None) -> None:
        """Both .mmdb.gz URLs of ``month`` answer 200 with the gzipped fixture pair (or the given raw .mmdb bytes)."""
        fixture_city, fixture_asn = fixture_pair(month)
        for kind, raw in (("city", fixture_city if city is None else city), ("asn", fixture_asn if asn is None else asn)):
            body = gzip_bytes(raw)
            headers = {"content-length": str(len(body))}
            if date:
                headers["date"] = date
            self.table[geoip.file_url(kind, month)] = (200, headers, body)

    def __call__(self, url: str, *, timeout: float) -> FakeResponse:
        with self._lock:
            self.urls.append(url)
            status, headers, body = self.table.get(url, (self.default_status, {}, b""))
            resp = FakeResponse(self, url, status, headers, body, self.chunk)
            self.responses.append(resp)
        return resp


def make_manager(tmp_path: Path, *, config: Any = None, bus: Any = None, clock: Optional[Callable[[], float]] = None,
                 monotonic: Optional[Callable[[], float]] = None, urlopen: Any = None,
                 public_ip: Optional[str] = "203.0.113.200", **kw: Any) -> "geoip.GeoIpManager":
    """A manager on ``tmp_path / "geoip"`` with the fixture probes, no jitter, no first-check delay and ample disk."""
    tmp_path = Path(tmp_path)
    if config is None:
        config = Config(tmp_path / "config.json").load()
    args: Dict[str, Any] = {
        "public_ip_fn": lambda: public_ip,
        "dir_fn": lambda: tmp_path / "geoip",
        "verify_probes": VERIFY_PROBES_FIXTURE,
        "jitter_s": 0.0,
        "first_check_delay_s": 0.0,
        "disk_free_fn": lambda p: 10 ** 12,
    }
    if clock is not None:
        args["clock"] = clock
    if monotonic is not None:
        args["monotonic"] = monotonic
    if urlopen is None:
        args["urlopen"] = FakeHttp()
    elif urlopen is not False:
        args["urlopen"] = urlopen
    args.update(kw)
    folder = str(args["dir_fn"]())
    assert "programdata" not in folder.lower(), f"a test manager must never use the real data folder: {folder}"
    return geoip.GeoIpManager(config, bus, **args)


def write_fixture_files(folder: Path, month: str = "2026-09") -> Tuple[Path, Path]:
    """The uncompressed fixture pair for ``month`` written to ``folder``: (city path, asn path)."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    city, asn = fixture_pair(month)
    city_path = folder / f"fixture-city-{month}.mmdb"
    asn_path = folder / f"fixture-asn-{month}.mmdb"
    city_path.write_bytes(city)
    asn_path.write_bytes(asn)
    return city_path, asn_path


def installed_manager(tmp_path: Path, month: str = "2026-09", **kw: Any) -> "geoip.GeoIpManager":
    """make_manager(...) with the fixture pair of ``month`` installed (state ready)."""
    mgr = make_manager(tmp_path, **kw)
    mgr.install_from_files(month, *write_fixture_files(Path(tmp_path) / "src", month))
    assert mgr.available and mgr.status()["state"] == "ready"
    return mgr
