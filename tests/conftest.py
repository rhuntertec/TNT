import os
import sys
from pathlib import Path

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
