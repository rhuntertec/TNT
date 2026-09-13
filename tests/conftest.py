import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# IP location (tnt.geoip): the downloader refuses every non-loopback host in this process and its children, even for a
# manager thread that outlives its test (tnt.geoip.OFFLINE_ENV)
os.environ["TNT_GEOIP_OFFLINE"] = "1"

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def pytest_addoption(parser):
    parser.addoption("--run-network", action="store_true", default=False, help="run tests marked 'network'")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-network"):
        return
    skip = pytest.mark.skip(reason="needs --run-network")
    for item in items:
        if "network" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    """Point TNT at a temporary data directory."""
    monkeypatch.setenv("TNT_DATA_DIR", str(tmp_path / "data"))
    from tnt import paths
    paths.ensure_dirs()
    return paths.data_dir()


@pytest.fixture(autouse=True, scope="session")
def _no_geoip_downloads():
    """Second layer: tnt.geoip._urlopen always fails for the whole session and is never restored."""
    try:
        from tnt import geoip
    except Exception:  # noqa: BLE001 - a tree without the module, or one that does not import yet
        yield
        return

    def blocked(url, **kwargs):
        raise OSError("network access is disabled in tests (tnt.geoip)")

    mp = pytest.MonkeyPatch()
    mp.setattr(geoip, "_urlopen", blocked)
    yield                                  # deliberately no mp.undo()


# --------------------------------------------------------------------------- module seams (NAT check, port-forward test,
# pktmon, TFTP server, folder security)
# One autouse session fixture per module. Each imports its module on its own, so a module that is not written yet (or
# does not import yet) only skips its own guard; each patches a seam only when the module defines it, and never undoes the
# patch (a thread that outlives its test still meets the guard). A module must look its seam up as a module global at call
# time: a default argument bound at import (``def f(open_socket=_udp_socket)``) would slip past the guard. Tests that need
# a socket, HTTP or a runner pass fakes explicitly.
def _network_blocked(module):
    def blocked(*args, **kwargs):
        raise OSError(f"network access is disabled in tests ({module})")

    return blocked


@pytest.fixture(autouse=True, scope="session")
def _no_natcheck_network():
    """tnt.natcheck._udp_socket and _http_connection always fail: no NAT-PMP, UPnP or HTTP toward a router."""
    try:
        from tnt import natcheck
    except Exception:  # noqa: BLE001 - a tree without the module, or one that does not import yet
        yield
        return
    mp = pytest.MonkeyPatch()
    for seam in ("_udp_socket", "_http_connection"):
        if hasattr(natcheck, seam):
            mp.setattr(natcheck, seam, _network_blocked("tnt.natcheck"))
    yield                                  # deliberately no mp.undo()


@pytest.fixture(autouse=True, scope="session")
def _no_portcheck_network():
    """tnt.portcheck._https_request always fails: no request to an outside port checker."""
    try:
        from tnt import portcheck
    except Exception:  # noqa: BLE001 - a tree without the module, or one that does not import yet
        yield
        return
    mp = pytest.MonkeyPatch()
    if hasattr(portcheck, "_https_request"):
        mp.setattr(portcheck, "_https_request", _network_blocked("tnt.portcheck"))
    yield                                  # deliberately no mp.undo()


@pytest.fixture(autouse=True, scope="session")
def _no_pktmon_runs():
    """tnt.pktmon._subprocess_run always fails: pktmon filters and sessions are system-wide, so a test must never run it."""
    try:
        from tnt import pktmon
    except Exception:  # noqa: BLE001 - a tree without the module, or one that does not import yet
        yield
        return

    def blocked(*args, **kwargs):
        raise OSError("pktmon is disabled in tests")

    mp = pytest.MonkeyPatch()
    if hasattr(pktmon, "_subprocess_run"):
        mp.setattr(pktmon, "_subprocess_run", blocked)
    yield                                  # deliberately no mp.undo()


#: UDP ports no test may bind: DHCP (tnt.dhcp's server port) and TFTP.
BLOCKED_UDP_PORTS = (67, 69)


@pytest.fixture(autouse=True, scope="session")
def _no_tftp_privileged_binds():
    """tnt.tftp._bind_udp refuses UDP 67 and 69; every other bind (127.0.0.1 port 0) goes through to the real one."""
    try:
        from tnt import tftp
    except Exception:  # noqa: BLE001 - a tree without the module, or one that does not import yet
        yield
        return
    if not hasattr(tftp, "_bind_udp"):
        yield
        return
    real_bind = tftp._bind_udp

    def guarded(sock, address):
        try:
            port = int(address[1])
        except (TypeError, ValueError, IndexError, KeyError):
            port = None
        if port in BLOCKED_UDP_PORTS:
            raise OSError(f"binding UDP port {port} is disabled in tests (tnt.tftp)")
        return real_bind(sock, address)

    mp = pytest.MonkeyPatch()
    mp.setattr(tftp, "_bind_udp", guarded)
    yield                                  # deliberately no mp.undo()


class _FolderSecurityRecorder:
    """Stands in for tnt.winacl._set_file_security: appends ``(path, sddl)`` to ``calls`` and changes no DACL.
    ``original`` keeps the real function for the one test that applies a real SDDL (tests/test_winacl.py)."""

    def __init__(self, original):
        self.original = original
        self.calls = []

    def __call__(self, path, sddl):
        self.calls.append((path, sddl))


@pytest.fixture(autouse=True, scope="session")
def _no_real_folder_security():
    """tnt.winacl._set_file_security only records: a protected SYSTEM + Administrators DACL would lock a non-elevated
    test process out of its own temp folder, and pytest could not delete it."""
    try:
        from tnt import winacl
    except Exception:  # noqa: BLE001 - a tree without the module, or one that does not import yet
        yield
        return
    mp = pytest.MonkeyPatch()
    if hasattr(winacl, "_set_file_security"):
        mp.setattr(winacl, "_set_file_security", _FolderSecurityRecorder(winacl._set_file_security))
    yield                                  # deliberately no mp.undo()


# --------------------------------------------------------------------------- the installed TNT's data folder
#: ``%ProgramData%\TNT`` of a TNT installed on this PC: its service's database and logs, the TFTP server's root and the packet
#: captures. No test may create or change anything there; tests use tmp_path, the ``data_dir`` fixture (TNT_DATA_DIR) or an
#: explicit root / captures_dir_fn / work_dir_fn.
REAL_DATA_ROOT = Path(os.environ.get("ProgramData") or r"C:\ProgramData") / "TNT"
#: the folders under it whose every entry is compared (the top level is compared by name only: the installed service writes there)
WATCHED_DATA_FOLDERS = ("tftp", "captures")
#: the running service's own SQLite side files come and go at the top level
_SERVICE_SIDE_FILE = re.compile(r".+\.db-(journal|wal|shm)$", re.IGNORECASE)
_LISTING_LIMIT = 5000
_REPARSE_POINT = 0x400                     # FILE_ATTRIBUTE_REPARSE_POINT: a junction or link is listed, never followed


def data_folder_listing(root: Path) -> Dict[str, Optional[List[tuple]]]:
    """What a test run must leave as it was, read from names and stat() only (no file is opened): ``top`` the names at the top of
    *root* as ``(name, is_dir)``, and for each of WATCHED_DATA_FOLDERS every entry below it as ``(relative name, is_dir, size,
    mtime_ns)`` (folders carry no size or time). A folder that does not exist is None."""
    def walk(folder: Path, deep: bool) -> Optional[List[tuple]]:
        if not folder.is_dir():
            return None
        found: List[tuple] = []
        pending = [str(folder)]
        while pending and len(found) < _LISTING_LIMIT:
            current = pending.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        rel = os.path.relpath(entry.path, folder).replace(os.sep, "/")
                        try:
                            st = entry.stat(follow_symlinks=False)
                            is_dir = entry.is_dir(follow_symlinks=False)
                        except OSError:
                            found.append((rel, None, None, None) if deep else (rel, None))
                            continue
                        if not deep:
                            if not _SERVICE_SIDE_FILE.match(entry.name):
                                found.append((rel, is_dir))
                            continue
                        found.append((rel, is_dir, None if is_dir else st.st_size, None if is_dir else st.st_mtime_ns))
                        if is_dir and not entry.is_symlink() and not getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
                            pending.append(entry.path)
            except OSError:
                found.append((os.path.relpath(current, folder).replace(os.sep, "/"), "unreadable", None, None) if deep
                             else (".", "unreadable"))
        return sorted(found, key=lambda e: e[0])

    listing: Dict[str, Optional[List[tuple]]] = {"top": walk(root, deep=False)}
    for name in WATCHED_DATA_FOLDERS:
        listing[name] = walk(root / name, deep=True)
    return listing


def data_folder_changes(before: Dict[str, Any], after: Dict[str, Any]) -> List[str]:
    """What differs between two data_folder_listing()s, as "added tftp/a.bin", "changed tftp/a.bin", "removed captures/x" (names
    only), and "created tftp" / "removed tftp" for a watched folder itself ("created the folder" for the root)."""
    out: List[str] = []
    for key in ("top",) + WATCHED_DATA_FOLDERS:
        was, now = before.get(key), after.get(key)
        label = "" if key == "top" else key + "/"
        if was is None and now is None:
            continue
        if was is None or now is None:
            what = "the folder" if key == "top" else key
            out.append(("created " if was is None else "removed ") + what)
            continue
        old, new = {e[0]: e for e in was}, {e[0]: e for e in now}
        out += [f"added {label}{n}" for n in sorted(set(new) - set(old))]
        out += [f"changed {label}{n}" for n in sorted(set(new) & set(old)) if new[n] != old[n]]
        out += [f"removed {label}{n}" for n in sorted(set(old) - set(new))]
    return out


@pytest.fixture(autouse=True, scope="session")
def _real_data_folder_untouched(tmp_path_factory):
    """TNT_DATA_DIR defaults to a folder of this run, so a thread that outlives its test's ``data_dir`` never resolves the real
    folder; at the end the installed TNT's data folder must list what it listed at the start (a failure names the entries only)."""
    before = data_folder_listing(REAL_DATA_ROOT)
    mp = pytest.MonkeyPatch()
    if not os.environ.get("TNT_DATA_DIR"):
        mp.setenv("TNT_DATA_DIR", str(tmp_path_factory.mktemp("tnt-data")))
    yield                                  # deliberately no mp.undo(), like the guards above
    changes = data_folder_changes(before, data_folder_listing(REAL_DATA_ROOT))
    assert not changes, f"the test run changed the installed TNT's data folder {REAL_DATA_ROOT}: {'; '.join(changes)}"
