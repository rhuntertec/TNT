"""Reordering ping tiles: PingManager.reorder persists through the db and drives targets()."""
import pytest

from tnt.config import Config
from tnt.db import Database
from tnt.events import EventBus
from tnt.icmp import PingResult
from tnt.pinger import PingManager


class FakePinger:
    def ping(self, ip, size=32, timeout_ms=1000, ttl=128):
        return PingResult(ok=True, rtt_ms=1.0, status=0, error=None, ttl=64, size=size, ip=ip)

    def close(self):
        pass


@pytest.fixture
def mgr(tmp_path):
    db = Database(tmp_path / "t.db")
    cfg = Config(tmp_path / "config.json").load()
    bus = EventBus()
    m = PingManager(db, cfg, bus, pinger=FakePinger(), clock=lambda: 1_700_000_000.0, sleep=lambda s: None)
    yield m, db, bus
    db.close()


def test_reorder_persists_and_reports(mgr):
    m, db, bus = mgr
    a = m.add_target("1.1.1.1")["id"]
    b = m.add_target("8.8.8.8")["id"]
    c = m.add_target("9.9.9.9")["id"]
    assert [t["id"] for t in m.targets()] == [a, b, c]
    events = []
    bus.subscribe(lambda e: events.append(e["type"]))

    views = m.reorder([c, a])                       # c first, a second, b keeps its place after them
    assert [t["id"] for t in views] == [c, a, b]
    assert [t["id"] for t in m.targets()] == [c, a, b]
    assert [t["id"] for t in db.list_targets()] == [c, a, b]
    assert [t["sort_order"] for t in db.list_targets()] == [1, 2, 3]
    assert "ping.targets" in events

    # a fresh manager loads the stored order
    m2 = PingManager(db, Config(db.path.parent / "config.json").load(), EventBus(), pinger=FakePinger(),
                     clock=lambda: 1_700_000_000.0, sleep=lambda s: None)
    m2.start()
    try:
        assert [t["id"] for t in m2.targets()] == [c, a, b]
    finally:
        m2.stop()

    # unknown ids and junk are refused without touching the order
    with pytest.raises(ValueError):
        m.reorder([999])
    with pytest.raises(ValueError):
        m.reorder(["x"])
    assert [t["id"] for t in m.targets()] == [c, a, b]
    # duplicates collapse, a full permutation works
    assert [t["id"] for t in m.reorder([b, b, c, a])] == [b, c, a]


def test_db_set_target_order_keeps_unlisted_targets_after(tmp_path):
    db = Database(tmp_path / "t.db")
    ids = [db.add_target(h)["id"] for h in ("a.test", "b.test", "c.test", "d.test")]
    assert db.set_target_order([ids[3], ids[1]]) == [ids[3], ids[1], ids[0], ids[2]]
    assert [t["id"] for t in db.list_targets()] == [ids[3], ids[1], ids[0], ids[2]]
    db.close()
