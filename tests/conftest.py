import os
import sys
from pathlib import Path

import pytest

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
