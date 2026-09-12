"""SQLite persistence for TNT.

Design notes
------------
* One database file, WAL mode, a single shared connection guarded by an RLock.
  The service is I/O-light (a few writes per minute per target) so a single
  connection is simpler and safer than a pool.
* Per-second ping samples are NOT stored here (they go to the daily CSV logs,
  see ``pinger.RawPingLog``). Only per-minute aggregates are kept, which keeps a
  year of three targets under ~150 MB.
* All timestamps are Unix epoch seconds (float) in UTC. ``minute_ts`` is an int
  floored to the minute.
* Every public method is thread-safe and returns plain dicts / lists so the API
  layer can serialise them directly.
* Networks (ARCHITECTURE 3.20): the ``networks`` table holds one row per network this PC was on
  (the router's MAC, else a fingerprint of gateway, subnet and DHCP server); ping minutes, outages,
  speed tests, Discovery runs and reports carry the ``network_id`` current when they were collected.
  ``ping_minutes.network_id`` is part of its primary key, and a WITHOUT ROWID key column cannot hold
  NULL, so an untagged minute is ``0`` there (:data:`UNTAGGED`); the other tables use NULL.  A 1.10.0
  database gains the columns by ``ALTER TABLE`` and ``ping_minutes`` is rebuilt once to the new key
  (:meth:`Database._migrate_networks`, after a one-time copy ``tnt.db.pre-networks.bak``); a failed
  rebuild leaves ``networks_ready`` false and the database working as before.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
#: ``ping_minutes.network_id`` of a minute recorded before networks were tagged (or while the network was unknown)
UNTAGGED = 0
#: the one-time safety copy taken before ``ping_minutes`` is rebuilt to the three-column key
NETWORKS_BACKUP_SUFFIX = ".pre-networks.bak"
#: the rebuild needs about this many times the database (plus WAL) free: the copy, the grown file and the WAL
NETWORKS_REBUILD_SPACE_FACTOR = 3.0
#: a WAL checkpoint of the migration waits this long (ms) for another program's read snapshot, not the 30 s busy timeout
QUICK_BUSY_MS = 1000
#: a merge of a network that existed before the change also moves rows dated this much before it: an echo sent just before the
#: switch and answered (or timed out) after it, an outage whose first miss was that echo (the default echo timeout is 1 s)
RETAG_SLACK_S = 5.0
#: a merge of a network the change created moves every row of it; its minute rows are looked for from this long before its
#: first_seen (a wall clock put back while it was current) so the query stays on the minute_ts index
RETAG_WIDE_S = 86400.0

_PING_COLS = "target_id, minute_ts, sent, received, avg_ms, min_ms, max_ms, jitter_ms"
_PING_MINUTES_TABLE = """CREATE TABLE {if_not_exists}{name} (
    target_id  INTEGER NOT NULL,
    minute_ts  INTEGER NOT NULL,
    sent       INTEGER NOT NULL,
    received   INTEGER NOT NULL,
    avg_ms     REAL,
    min_ms     REAL,
    max_ms     REAL,
    jitter_ms  REAL,
    network_id INTEGER NOT NULL DEFAULT 0,        -- networks.id, 0 = untagged (a WITHOUT ROWID key column cannot be NULL)
    PRIMARY KEY (target_id, minute_ts, network_id)
) WITHOUT ROWID"""
#: the upsert's merge of a second write of one (target, minute, network): used by the upsert and by a network re-tag
_PING_MERGE_SET = """sent=ping_minutes.sent+excluded.sent,
                 received=ping_minutes.received+excluded.received,
                 avg_ms=CASE WHEN ping_minutes.received+excluded.received=0 THEN NULL ELSE
                    (COALESCE(ping_minutes.avg_ms,0)*ping_minutes.received + COALESCE(excluded.avg_ms,0)*excluded.received)
                    / (ping_minutes.received+excluded.received) END,
                 min_ms=CASE WHEN ping_minutes.min_ms IS NULL THEN excluded.min_ms
                             WHEN excluded.min_ms IS NULL THEN ping_minutes.min_ms
                             ELSE MIN(ping_minutes.min_ms, excluded.min_ms) END,
                 max_ms=CASE WHEN ping_minutes.max_ms IS NULL THEN excluded.max_ms
                             WHEN excluded.max_ms IS NULL THEN ping_minutes.max_ms
                             ELSE MAX(ping_minutes.max_ms, excluded.max_ms) END,
                 jitter_ms=COALESCE(excluded.jitter_ms, ping_minutes.jitter_ms)"""

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS targets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    label      TEXT,
    kind       TEXT NOT NULL DEFAULT 'auto',   -- auto | local | internet
    enabled    INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ping_minutes (
    target_id  INTEGER NOT NULL,
    minute_ts  INTEGER NOT NULL,
    sent       INTEGER NOT NULL,
    received   INTEGER NOT NULL,
    avg_ms     REAL,
    min_ms     REAL,
    max_ms     REAL,
    jitter_ms  REAL,
    network_id INTEGER NOT NULL DEFAULT 0,        -- networks.id, 0 = untagged (a 1.10.0 database is rebuilt to this key once)
    PRIMARY KEY (target_id, minute_ts, network_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_ping_minutes_ts ON ping_minutes(minute_ts);
CREATE TABLE IF NOT EXISTS outages (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    kind      TEXT NOT NULL,          -- target | total_local | total_internet | gap
    target_id INTEGER,                -- NULL for total/gap
    start_ts  REAL NOT NULL,
    end_ts    REAL,                   -- NULL while open
    missed    INTEGER NOT NULL DEFAULT 0,
    note      TEXT,
    network_id INTEGER                -- networks.id when it opened; NULL = untagged
);
CREATE INDEX IF NOT EXISTS ix_outages_start ON outages(start_ts);
CREATE INDEX IF NOT EXISTS ix_outages_open ON outages(end_ts) WHERE end_ts IS NULL;
CREATE TABLE IF NOT EXISTS speedtests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL,
    ok              INTEGER NOT NULL,
    backend         TEXT NOT NULL,
    server          TEXT,
    isp             TEXT,
    external_ip     TEXT,
    latency_ms      REAL,
    jitter_ms       REAL,
    download_mbps   REAL,
    upload_mbps     REAL,
    packet_loss_pct REAL,
    duration_s      REAL,
    error           TEXT,
    raw_json        TEXT,
    network_id      INTEGER                   -- networks.id when the test started; NULL = untagged
);
CREATE INDEX IF NOT EXISTS ix_speedtests_ts ON speedtests(ts);
CREATE TABLE IF NOT EXISTS discovery_runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    cidr       TEXT NOT NULL,
    ports      TEXT NOT NULL,         -- JSON list of ints
    method     TEXT NOT NULL,         -- "native" (rows from releases before 1.7.0 may hold another name)
    duration_s REAL,
    scanned    INTEGER,
    found      INTEGER,
    ok         INTEGER NOT NULL DEFAULT 1,
    error      TEXT,
    network_id INTEGER                -- networks.id when the scan started; NULL = untagged
);
CREATE TABLE IF NOT EXISTS discovery_hosts (
    run_id     INTEGER NOT NULL,
    ip         TEXT NOT NULL,
    hostname   TEXT,
    mac        TEXT,
    vendor     TEXT,
    ping_ok    INTEGER NOT NULL,
    rtt_ms     REAL,
    open_ports TEXT NOT NULL,         -- JSON list of ints
    device_type TEXT,                 -- Router | DW Server | Camera | Phone | Ubiquiti | NULL (discovery.classify_device)
    PRIMARY KEY (run_id, ip)
);
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    level    TEXT NOT NULL,
    category TEXT NOT NULL,
    message  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS dhcp_leases (
    mac             TEXT PRIMARY KEY,          -- "AA:BB:CC:DD:EE:FF" (oui.normalize_mac form)
    ip              TEXT NOT NULL,
    hostname        TEXT,
    vendor          TEXT,
    client_id       TEXT,                      -- hex of DHCP option 61 (NULL when the client sent none)
    first_ts        REAL NOT NULL,
    last_ts         REAL NOT NULL,
    expires_ts      REAL,                      -- NULL for offered/released/expired/declined
    state           TEXT NOT NULL DEFAULT 'offered',   -- offered | bound | released | expired | declined
    rtt_ms          REAL,
    open_ports_json TEXT NOT NULL DEFAULT '[]',
    ping_ok         INTEGER,                   -- NULL = never probed
    probed_ts       REAL                       -- NULL = never probed
);
CREATE INDEX IF NOT EXISTS ix_dhcp_leases_ip ON dhcp_leases(ip);
CREATE INDEX IF NOT EXISTS ix_dhcp_leases_expires ON dhcp_leases(expires_ts);
CREATE TABLE IF NOT EXISTS reports (
    id           INTEGER PRIMARY KEY,
    site         TEXT NOT NULL,                -- as the technician typed it (tnt.reports.normalize_site)
    site_key     TEXT NOT NULL,                -- casefolded, whitespace-collapsed site: groups one site's reports
    created_ts   REAL NOT NULL,                -- when the Full Scan was started (the end of its ping window)
    completed_ts REAL,
    status       TEXT NOT NULL,                -- complete | partial
    tnt_version  TEXT,
    summary      TEXT NOT NULL DEFAULT '{}',   -- JSON: the key numbers (lists, quick compare)
    data         TEXT NOT NULL DEFAULT '{}',   -- JSON: the whole report (ARCHITECTURE 3.19)
    network_id   INTEGER                       -- networks.id when the Full Scan started; NULL = untagged
);
CREATE INDEX IF NOT EXISTS ix_reports_site_key ON reports(site_key);
CREATE INDEX IF NOT EXISTS ix_reports_created ON reports(created_ts);
CREATE TABLE IF NOT EXISTS networks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,   -- never reused: a deleted provisional id must not name another network
    mac         TEXT UNIQUE,                         -- the router's MAC ("AA:BB:CC:DD:EE:FF"); NULL: identified by fingerprint
    fingerprint TEXT,                                -- hash of gateway_ip|subnet|dhcp_server (tnt.networks.fingerprint)
    gateway_ip  TEXT,
    subnet      TEXT,
    dhcp_server TEXT,
    dns_suffix  TEXT,
    nic         TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    virtual_mac TEXT,                                -- a VRRP / HSRP / HA cluster router MAC (in the fingerprint, never in mac)
    portable    INTEGER NOT NULL DEFAULT 0           -- 1: carried from site to site (a phone hotspot, a travel router)
);
CREATE INDEX IF NOT EXISTS ix_networks_fingerprint ON networks(fingerprint);
CREATE TABLE IF NOT EXISTS network_offline (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id      INTEGER NOT NULL,     -- the network this PC had last (the id stays on it while offline)
    start_ts        REAL NOT NULL,
    end_ts          REAL,                 -- NULL while no network is identified yet
    next_network_id INTEGER,              -- the network identified at end_ts; another than network_id: travel
    reason          TEXT                  -- NULL: no network; 'lan': on another network without a gateway meanwhile (travel too)
);
CREATE INDEX IF NOT EXISTS ix_network_offline_net ON network_offline(network_id, start_ts);
"""
#: indexes on the network_id columns: created by _migrate once the columns exist (never in _SCHEMA, which also runs on 1.10.0 files)
_NETWORK_INDEXES = (
    "CREATE INDEX IF NOT EXISTS ix_outages_network ON outages(network_id, start_ts)",
    "CREATE INDEX IF NOT EXISTS ix_speedtests_network ON speedtests(network_id, ts)",
    "CREATE INDEX IF NOT EXISTS ix_discovery_runs_network ON discovery_runs(network_id, ts)",
    "CREATE INDEX IF NOT EXISTS ix_reports_network ON reports(network_id, created_ts)",
)
#: the tables whose network_id is a nullable column (ping_minutes is keyed on it)
_NETWORK_TAGGED = (("outages", "start_ts"), ("speedtests", "ts"), ("discovery_runs", "ts"), ("reports", "created_ts"))

DHCP_LEASE_STATES = ("offered", "bound", "released", "expired", "declined")


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {k: row[k] for k in row.keys()}


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        #: every network_id column exists and ping_minutes is keyed on it; False after a failed migration (tagging is
        #: then skipped, reports use the time rule, and the next start tries again)
        self.networks_ready = False
        self._ping_net = False                   # ping_minutes has the network_id key column
        #: (from_id, to_id, since_ts, until_ts): a write of from_id for a moment in [since, until) is stored as to_id
        #: (a provisional network merged into the router's MAC while writes of the old id were still queued)
        self._net_aliases: List[Tuple[int, int, float, float]] = []
        #: what the networks migration did at this open (``{"rebuilt", "rows", "seconds", "backup"}``), for tests and logs
        self.migration_info: Dict[str, Any] = {}
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.executescript(_SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        cur = self._conn.execute("SELECT value FROM meta WHERE key='schema_version'")
        row = cur.fetchone()
        if row is None:
            self._conn.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
        # v1.1: outages remember the host they were about, so the history still reads
        # "totalelectronics.com" after that target has been removed
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(outages)").fetchall()}
        if "host" not in cols:
            self._conn.execute("ALTER TABLE outages ADD COLUMN host TEXT")
            log.info("db migration: added outages.host")
        # v1.7: pings sent during a target outage, so the list can show the missed percentage
        # exactly; NULL on rows recorded before (the percentage is then estimated)
        if "sent" not in cols:
            self._conn.execute("ALTER TABLE outages ADD COLUMN sent INTEGER")
            log.info("db migration: added outages.sent")
        # v1.2: discovered hosts remember what they were categorised as (Router / DW Server /
        # Camera / Phone / Ubiquiti). Rows written before this are NULL and are categorised on read
        # (tnt.discovery.fill_device_types) so old runs show the column too.
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(discovery_hosts)").fetchall()}
        if "device_type" not in cols:
            self._conn.execute("ALTER TABLE discovery_hosts ADD COLUMN device_type TEXT")
            log.info("db migration: added discovery_hosts.device_type")
        # v1.11.1: 22 open + a Ubiquiti MAC is typed "Ubiquiti", no longer "Wifi" (tnt.discovery.LEGACY_DEVICE_TYPES);
        # old rows are renamed in place so every reader of an old run sees the new name (nothing written when none are left)
        if self._conn.execute("SELECT 1 FROM discovery_hosts WHERE device_type = 'Wifi' LIMIT 1").fetchone():
            renamed = self._conn.execute("UPDATE discovery_hosts SET device_type = 'Ubiquiti' WHERE device_type = 'Wifi'").rowcount
            log.info("db migration: renamed %d discovered hosts from Wifi to Ubiquiti", renamed)
        # Full Scan site reports: the ``reports`` table and its indexes are plain CREATE ... IF NOT
        # EXISTS statements in _SCHEMA, which runs on every open, so an existing database gains them
        # there (SCHEMA_VERSION stays 1). Nothing else reads or rewrites older rows.
        self._migrate_networks()

    # -- networks migration (never raises: a failure leaves the 1.10.0 shape working) --------------
    def _migration_step(self, name: str) -> None:
        """A named point of the ping_minutes rebuild (tests make one raise to check the rollback)."""

    def _columns(self, table: str) -> Dict[str, int]:
        """``{column: primary key position (0 = not in the key)}`` of *table*."""
        return {r["name"]: int(r["pk"]) for r in self._conn.execute(f"PRAGMA table_info({table})").fetchall()}

    def _migrate_networks(self) -> None:
        """v1.11: the ``network_id`` columns, their indexes and ``ping_minutes`` rebuilt to the three-column key.  Which steps
        are due is read from the tables themselves (SCHEMA_VERSION stays 1).  Any failure logs why, leaves ``networks_ready``
        false and the database as it was (the rebuild is one transaction): nothing is tagged until the next start tries again."""
        try:
            for table, _ts in _NETWORK_TAGGED:
                if "network_id" not in self._columns(table):
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN network_id INTEGER")
                    log.info("db migration: added %s.network_id", table)
            # columns of the networks tables added while they were new (a file an earlier build of this release created)
            for table, column, decl in (("networks", "virtual_mac", "TEXT"), ("networks", "portable", "INTEGER NOT NULL DEFAULT 0"),
                                        ("network_offline", "reason", "TEXT")):
                if column not in self._columns(table):
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
            for sql in _NETWORK_INDEXES:
                self._conn.execute(sql)
            cols = self._columns("ping_minutes")
        except sqlite3.Error as exc:
            log.error("db migration: the network columns could not be added (%s); data is not tagged with networks until the "
                      "next start", exc)
            return
        if not cols.get("network_id"):
            if not self._rebuild_ping_minutes():
                return
        self._ping_net = True
        self.networks_ready = True

    def _db_bytes(self) -> int:
        return sum(p.stat().st_size for p in (self.path, Path(str(self.path) + "-wal")) if p.exists())

    def _quick_checkpoint(self) -> None:
        """``wal_checkpoint(TRUNCATE)`` waiting at most QUICK_BUSY_MS for readers: another program holding a read snapshot (a
        database browser, a backup tool) must not hold the service's start for the 30 s busy timeout.  A checkpoint that cannot
        finish now is done by a later one; the copy (VACUUM INTO) reads the WAL anyway."""
        try:
            self._conn.execute(f"PRAGMA busy_timeout={int(QUICK_BUSY_MS)}")
            row = self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if row is not None and row[0]:
                log.info("db migration: the WAL checkpoint waits for another reader of the database; it is finished later")
        except sqlite3.Error as exc:
            log.info("db migration: the WAL checkpoint did not finish (%s); it is finished later", exc)
        finally:
            self._conn.execute("PRAGMA busy_timeout=30000")

    def _rebuild_ping_minutes(self) -> bool:
        """``ping_minutes`` to PRIMARY KEY (target_id, minute_ts, network_id), every row kept with network_id 0.  A safety copy
        (``tnt.db.pre-networks.bak``, VACUUM INTO: consistent under WAL and compact) is taken first, once: an existing copy is
        never overwritten.  Skipped when the disk has less than NETWORKS_REBUILD_SPACE_FACTOR x the database free."""
        t_all = time.perf_counter()
        info: Dict[str, Any] = {"rebuilt": False}
        backup = Path(str(self.path) + NETWORKS_BACKUP_SUFFIX)
        tmp = Path(str(backup) + ".tmp")
        try:
            rows = int(self._conn.execute("SELECT COUNT(*) FROM ping_minutes").fetchone()[0])
            size = self._db_bytes()
            free = int(shutil.disk_usage(str(self.path.parent)).free)
            info.update(rows=rows, db_bytes=size, free_bytes=free)
            if rows and free < NETWORKS_REBUILD_SPACE_FACTOR * size:
                log.error("db migration: tagging data with networks needs about %.0f MB free next to the database for the "
                          "rebuild of ping_minutes, only %.0f MB are; skipped until the next start",
                          NETWORKS_REBUILD_SPACE_FACTOR * size / 1e6, free / 1e6)
                self.migration_info = info
                return False
            if backup.exists():
                log.info("db migration: keeping the safety copy %s from an earlier attempt", backup)
            elif rows:
                t0 = time.perf_counter()
                if tmp.exists():
                    tmp.unlink()
                self._quick_checkpoint()
                self._migration_step("backup")
                self._conn.execute("VACUUM INTO ?", (str(tmp),))
                os.replace(tmp, backup)
                info["backup_s"] = round(time.perf_counter() - t0, 3)
                log.info("db migration: safety copy %s written in %.2f s", backup, info["backup_s"])
            info["backup"] = str(backup) if backup.exists() else None
        except (OSError, sqlite3.Error) as exc:
            log.error("db migration: the safety copy before the rebuild of ping_minutes failed (%s); skipped until the next "
                      "start", exc)
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            self.migration_info = info
            return False
        steps: Dict[str, float] = {}
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                t0 = time.perf_counter()
                self._conn.execute("DROP TABLE IF EXISTS ping_minutes_new")
                self._conn.execute(_PING_MINUTES_TABLE.format(if_not_exists="", name="ping_minutes_new"))
                self._conn.execute(f"INSERT INTO ping_minutes_new({_PING_COLS}, network_id) SELECT {_PING_COLS}, 0 FROM ping_minutes")
                copied = int(self._conn.execute("SELECT COUNT(*) FROM ping_minutes_new").fetchone()[0])
                before = int(self._conn.execute("SELECT COUNT(*) FROM ping_minutes").fetchone()[0])
                if copied != before:
                    raise sqlite3.DatabaseError(f"copied {copied} of {before} minute rows")
                steps["copy_s"] = round(time.perf_counter() - t0, 3)
                self._migration_step("copy")
                t0 = time.perf_counter()
                self._conn.execute("DROP TABLE ping_minutes")
                self._migration_step("drop")
                self._conn.execute("ALTER TABLE ping_minutes_new RENAME TO ping_minutes")
                self._conn.execute("CREATE INDEX IF NOT EXISTS ix_ping_minutes_ts ON ping_minutes(minute_ts)")
                steps["swap_and_index_s"] = round(time.perf_counter() - t0, 3)
                self._migration_step("commit")
                t0 = time.perf_counter()
                self._conn.execute("COMMIT")
                steps["commit_s"] = round(time.perf_counter() - t0, 3)
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        except Exception as exc:  # noqa: BLE001 - never out of Database(): the engine would re-run this every 30 s
            log.error("db migration: rebuilding ping_minutes for networks failed (%s: %s); the database is unchanged and "
                      "data is not tagged with networks until the next start", type(exc).__name__, exc)
            self.migration_info = info
            return False
        self._quick_checkpoint()
        info.update(rebuilt=True, seconds=round(time.perf_counter() - t_all, 3), **steps)
        self.migration_info = info
        log.info("db migration: ping_minutes rebuilt to tag networks: %d rows in %.2f s (%s; safety copy %s)", info["rows"],
                 info["seconds"], ", ".join(f"{k} {v}" for k, v in steps.items()), info.get("backup") or "not needed")
        return True

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass
            self._conn.close()

    # -- generic helpers ---------------------------------------------------
    def _exec(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, tuple(params))

    def _query(self, sql: str, params: Iterable[Any] = ()) -> List[Dict[str, Any]]:
        with self._lock:
            return [_row_to_dict(r) for r in self._conn.execute(sql, tuple(params)).fetchall()]

    def _one(self, sql: str, params: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(sql, tuple(params)).fetchone()
            return _row_to_dict(row) if row is not None else None

    # -- meta --------------------------------------------------------------
    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self._one("SELECT value FROM meta WHERE key=?", (key,))
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self._exec("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # -- targets -----------------------------------------------------------
    def list_targets(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM targets" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY sort_order, id"
        rows = self._query(sql)
        for r in rows:
            r["enabled"] = bool(r["enabled"])
        return rows

    def get_target(self, target_id: int) -> Optional[Dict[str, Any]]:
        r = self._one("SELECT * FROM targets WHERE id=?", (target_id,))
        if r:
            r["enabled"] = bool(r["enabled"])
        return r

    def find_target(self, host: str) -> Optional[Dict[str, Any]]:
        r = self._one("SELECT * FROM targets WHERE host=? COLLATE NOCASE", (host.strip(),))
        if r:
            r["enabled"] = bool(r["enabled"])
        return r

    def add_target(self, host: str, label: Optional[str] = None, kind: str = "auto") -> Dict[str, Any]:
        """Insert (or return the existing) target. Raises ValueError on empty host."""
        host = (host or "").strip()
        if not host:
            raise ValueError("host is required")
        with self._lock:
            existing = self.find_target(host)
            if existing:
                return existing
            row = self._conn.execute("SELECT COALESCE(MAX(sort_order), 0) + 1 AS n FROM targets").fetchone()
            cur = self._conn.execute(
                "INSERT INTO targets(host, label, kind, enabled, sort_order, created_ts) VALUES(?, ?, ?, 1, ?, ?)",
                (host, label, kind, int(row["n"]), time.time()),
            )
            return self.get_target(int(cur.lastrowid))  # type: ignore[return-value]

    def remove_target(self, target_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
            return cur.rowcount > 0

    def set_target_enabled(self, target_id: int, enabled: bool) -> None:
        self._exec("UPDATE targets SET enabled=? WHERE id=?", (1 if enabled else 0, target_id))

    def set_target_kind(self, target_id: int, kind: str) -> None:
        self._exec("UPDATE targets SET kind=? WHERE id=?", (kind, target_id))

    def set_target_order(self, ids: Iterable[int]) -> List[int]:
        """Put the given target ids first, in that order; everything else keeps its relative
        order after them. Returns the resulting id order."""
        wanted: List[int] = []
        for i in ids:
            try:
                ti = int(i)
            except (TypeError, ValueError):
                continue
            if ti not in wanted:
                wanted.append(ti)
        with self._lock:
            existing = [int(r["id"]) for r in self._conn.execute("SELECT id FROM targets ORDER BY sort_order, id").fetchall()]
            order = [i for i in wanted if i in existing] + [i for i in existing if i not in wanted]
            self._conn.execute("BEGIN")
            try:
                for pos, tid in enumerate(order, start=1):
                    self._conn.execute("UPDATE targets SET sort_order=? WHERE id=?", (pos, tid))
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return order

    # -- ping minutes ------------------------------------------------------
    def upsert_ping_minute(self, target_id: int, minute_ts: int, sent: int, received: int,
                           avg_ms: Optional[float], min_ms: Optional[float], max_ms: Optional[float],
                           jitter_ms: Optional[float] = None, network_id: Optional[int] = None) -> None:
        """Add one flush of a minute to its row, keyed (target, minute, network) once the networks migration ran: a minute
        that spans a network change is two rows.  *network_id* None (or before the migration: not stored) is untagged."""
        params = (target_id, int(minute_ts), int(sent), int(received), avg_ms, min_ms, max_ms, jitter_ms)
        with self._lock:
            if self._ping_net:
                nid = self._map_network(network_id, int(minute_ts) + 59.999) or UNTAGGED
                self._conn.execute(
                    f"INSERT INTO ping_minutes({_PING_COLS}, network_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    f"ON CONFLICT(target_id, minute_ts, network_id) DO UPDATE SET {_PING_MERGE_SET}", params + (nid,))
            else:
                self._conn.execute(
                    f"INSERT INTO ping_minutes({_PING_COLS}) VALUES(?, ?, ?, ?, ?, ?, ?, ?) "
                    f"ON CONFLICT(target_id, minute_ts) DO UPDATE SET {_PING_MERGE_SET}", params)

    def ping_minutes(self, target_id: int, start_ts: float, end_ts: float) -> List[Dict[str, Any]]:
        """``{"target_id","minute_ts","sent","received","avg_ms","min_ms","max_ms","jitter_ms"}`` per minute bucket overlapping the
        range (the history chart): the rows of a minute split over two networks are added back together (sums, the reply-weighted
        average, the extremes, the jitter pooled by the pairs of each part), so a chart never draws two points at one minute."""
        # a minute bucket covers [minute_ts, minute_ts + 60): return every bucket that overlaps the range
        pairs = "CASE WHEN received>1 AND jitter_ms IS NOT NULL THEN received-1 ELSE 0 END"
        return self._query(
            "SELECT target_id, minute_ts, SUM(sent) AS sent, SUM(received) AS received, "
            "CASE WHEN COUNT(*)=1 THEN MAX(avg_ms) WHEN SUM(received)>0 THEN SUM(COALESCE(avg_ms,0)*received)*1.0/SUM(received) END "
            "AS avg_ms, MIN(min_ms) AS min_ms, MAX(max_ms) AS max_ms, "
            f"CASE WHEN COUNT(*)=1 THEN MAX(jitter_ms) WHEN SUM({pairs})>0 THEN "
            f"SUM(CASE WHEN received>1 AND jitter_ms IS NOT NULL THEN jitter_ms*(received-1) ELSE 0 END)*1.0/SUM({pairs}) "
            "ELSE MAX(jitter_ms) END AS jitter_ms "
            "FROM ping_minutes WHERE target_id=? AND minute_ts+60>? AND minute_ts<? GROUP BY minute_ts ORDER BY minute_ts",
            (target_id, int(start_ts), int(end_ts)),
        )

    def ping_summary(self, target_id: int, start_ts: float, end_ts: float) -> Dict[str, Any]:
        row = self._one(
            """SELECT COALESCE(SUM(sent),0) AS sent, COALESCE(SUM(received),0) AS received,
                      SUM(COALESCE(avg_ms,0)*received) AS wsum, MIN(min_ms) AS min_ms, MAX(max_ms) AS max_ms
               FROM ping_minutes WHERE target_id=? AND minute_ts+60>? AND minute_ts<?""",
            (target_id, int(start_ts), int(end_ts)),
        ) or {}
        sent = int(row.get("sent") or 0)
        received = int(row.get("received") or 0)
        avg = (row.get("wsum") or 0) / received if received else None
        return {
            "sent": sent,
            "received": received,
            "lost": sent - received,
            "loss_pct": round(100.0 * (sent - received) / sent, 2) if sent else None,
            "avg_ms": round(avg, 2) if avg is not None else None,
            "min_ms": row.get("min_ms"),
            "max_ms": row.get("max_ms"),
        }

    def _network_clause(self, network_id: Optional[int], legacy_since: Optional[float],
                        exclude: Sequence[Tuple[float, float]] = ()) -> Tuple[str, List[Any]]:
        """SQL keeping the minutes of *network_id* plus the untagged ones overlapping ``[legacy_since, ...)`` (none when None) and
        dropping the minutes overlapping any *exclude* span ``(start, end)``; no network filter without a network or before the
        migration.  ``+network_id`` keeps the planner on the primary key / minute_ts range (there is no index on it)."""
        sql, params = "", []  # type: str, List[Any]
        if network_id is not None and self._ping_net:
            sql += " AND (+network_id=? OR (+network_id=0 AND minute_ts>?))"
            params += [int(network_id), (float(legacy_since) - 60.0) if legacy_since is not None else float(2 ** 62)]
        for s, e in exclude or ():
            sql += " AND NOT (minute_ts>? AND minute_ts<?)"
            params += [float(s) - 60.0, float(e)]
        return sql, params

    def ping_minute_rows(self, target_id: int, start_ts: float, end_ts: float, network_id: Optional[int] = None,
                         legacy_since: Optional[float] = None, exclude: Sequence[Tuple[float, float]] = ()) -> List[tuple]:
        """``(sent, received, avg_ms, min_ms, max_ms, jitter_ms)`` tuples of the minute buckets overlapping
        ``[start_ts, end_ts)``, oldest first: a week of one target's rows without a dict per row
        (tnt.reports). ``minute_ts > start - 60`` is ``minute_ts + 60 > start`` in a form the primary key serves.
        With *network_id* only that network's rows (and untagged rows since *legacy_since*), without the *exclude* spans."""
        extra, params = self._network_clause(network_id, legacy_since, exclude)
        with self._lock:
            return [tuple(r) for r in self._conn.execute(
                "SELECT sent, received, avg_ms, min_ms, max_ms, jitter_ms FROM ping_minutes "
                f"WHERE target_id=? AND minute_ts>? AND minute_ts<?{extra} ORDER BY minute_ts",
                [int(target_id), int(start_ts) - 60, int(end_ts)] + params,
            ).fetchall()]

    def ping_target_ids(self, start_ts: float, end_ts: float, network_id: Optional[int] = None,
                        legacy_since: Optional[float] = None, exclude: Sequence[Tuple[float, float]] = ()) -> List[int]:
        """Every target id (removed targets included) with a minute bucket overlapping ``[start_ts, end_ts)`` (of *network_id*,
        as :meth:`ping_minute_rows` filters)."""
        extra, params = self._network_clause(network_id, legacy_since, exclude)
        with self._lock:
            return [int(r[0]) for r in self._conn.execute(
                f"SELECT DISTINCT target_id FROM ping_minutes WHERE minute_ts>? AND minute_ts<?{extra} ORDER BY target_id",
                [int(start_ts) - 60, int(end_ts)] + params,
            ).fetchall()]

    def ping_activity_minutes(self, start_ts: float, end_ts: float, network_id: Optional[int] = None,
                              legacy_since: Optional[float] = None, exclude: Sequence[Tuple[float, float]] = ()) -> List[int]:
        """``minute_ts`` of every minute bucket overlapping ``[start_ts, end_ts)`` with a row of any target (of *network_id*, as
        :meth:`ping_minute_rows` filters), oldest first: when monitoring ran (a report's visits)."""
        extra, params = self._network_clause(network_id, legacy_since, exclude)
        with self._lock:
            return [int(r[0]) for r in self._conn.execute(
                f"SELECT DISTINCT minute_ts FROM ping_minutes WHERE minute_ts>? AND minute_ts<?{extra} ORDER BY minute_ts",
                [int(start_ts) - 60, int(end_ts)] + params,
            ).fetchall()]

    def ping_other_network_minutes(self, start_ts: float, end_ts: float, network_id: int) -> List[int]:
        """``minute_ts`` of every minute bucket overlapping ``[start_ts, end_ts)`` with a row tagged with a network other than
        *network_id* (untagged rows are nobody's), oldest first: what splits the visits of a site's network."""
        if not self._ping_net:
            return []
        with self._lock:
            return [int(r[0]) for r in self._conn.execute(
                "SELECT DISTINCT minute_ts FROM ping_minutes WHERE minute_ts>? AND minute_ts<? AND +network_id<>0 AND +network_id<>? "
                "ORDER BY minute_ts", (int(start_ts) - 60, int(end_ts), int(network_id))).fetchall()]

    def has_untagged_minutes(self, start_ts: float, end_ts: float) -> bool:
        """Whether an untagged minute bucket (recorded before networks were tagged) overlaps ``[start_ts, end_ts)``."""
        if not self._ping_net or end_ts <= start_ts:
            return False
        with self._lock:
            return self._conn.execute("SELECT 1 FROM ping_minutes WHERE minute_ts>? AND minute_ts<? AND +network_id=0 LIMIT 1",
                                      (int(start_ts) - 60, int(end_ts))).fetchone() is not None

    def oldest_ping_minute(self) -> Optional[int]:
        """``minute_ts`` of the oldest stored minute bucket (any target), or None when there is none."""
        row = self._one("SELECT MIN(minute_ts) AS m FROM ping_minutes")
        return int(row["m"]) if row and row.get("m") is not None else None

    # -- outages -----------------------------------------------------------
    def open_outage(self, kind: str, target_id: Optional[int], start_ts: float, note: Optional[str] = None,
                    host: Optional[str] = None, network_id: Optional[int] = None) -> int:
        """Insert an open outage row; *network_id* is the network current when it opened (stored once the migration ran)."""
        with self._lock:
            if self.networks_ready:
                cur = self._conn.execute(
                    "INSERT INTO outages(kind, target_id, start_ts, end_ts, missed, note, host, network_id) VALUES(?, ?, ?, NULL, 0, ?, ?, ?)",
                    (kind, target_id, float(start_ts), note, host, self._map_network(network_id, float(start_ts))),
                )
            else:
                cur = self._conn.execute(
                    "INSERT INTO outages(kind, target_id, start_ts, end_ts, missed, note, host) VALUES(?, ?, ?, NULL, 0, ?, ?)",
                    (kind, target_id, float(start_ts), note, host),
                )
            return int(cur.lastrowid)

    def outages_missing_host(self) -> List[Dict[str, Any]]:
        """Target outages recorded before the host column existed (id, target_id, start_ts)."""
        return self._query(
            "SELECT id, target_id, start_ts FROM outages WHERE kind='target' AND target_id IS NOT NULL "
            "AND (host IS NULL OR host='') ORDER BY start_ts"
        )

    def set_outage_host(self, outage_id: int, host: str) -> None:
        self._exec("UPDATE outages SET host=? WHERE id=?", (str(host), int(outage_id)))

    def last_outage_host(self, target_id: int) -> Optional[str]:
        """The host recorded on the most recent outage of *target_id* (for removed targets)."""
        row = self._one(
            "SELECT host FROM outages WHERE target_id=? AND host IS NOT NULL AND host<>'' ORDER BY start_ts DESC LIMIT 1",
            (int(target_id),),
        )
        return row["host"] if row else None

    def close_outage(self, outage_id: int, end_ts: float, missed: int = 0, note: Optional[str] = None,
                     sent: Optional[int] = None) -> None:
        """Close an outage. *sent* (pings sent during it) is kept as stored when None."""
        self._exec(
            "UPDATE outages SET end_ts=?, missed=?, note=COALESCE(?, note), sent=COALESCE(?, sent) WHERE id=?",
            (float(end_ts), int(missed), note, None if sent is None else int(sent), outage_id),
        )

    def update_outage_missed(self, outage_id: int, missed: int, sent: Optional[int] = None) -> None:
        self._exec("UPDATE outages SET missed=?, sent=COALESCE(?, sent) WHERE id=?",
                   (int(missed), None if sent is None else int(sent), outage_id))

    def get_outage(self, outage_id: int) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM outages WHERE id=?", (outage_id,))

    def open_outages(self) -> List[Dict[str, Any]]:
        return self._query("SELECT * FROM outages WHERE end_ts IS NULL ORDER BY start_ts")

    def close_all_open(self, end_ts: float, note: str) -> int:
        cur = self._exec("UPDATE outages SET end_ts=?, note=COALESCE(note, ?) WHERE end_ts IS NULL", (float(end_ts), note))
        return cur.rowcount

    def list_outages(self, start_ts: float, end_ts: float, kinds: Optional[Iterable[str]] = None,
                     include_open: bool = True, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Outages overlapping [start_ts, end_ts]. Open outages count as ending 'now'."""
        sql = "SELECT * FROM outages WHERE start_ts<=? AND (end_ts IS NULL OR end_ts>=?)"
        params: List[Any] = [float(end_ts), float(start_ts)]
        if not include_open:
            sql += " AND end_ts IS NOT NULL"
        if kinds:
            ks = list(kinds)
            sql += " AND kind IN (%s)" % ",".join("?" * len(ks))
            params += ks
        sql += " ORDER BY start_ts DESC"
        if limit:
            sql += " LIMIT %d" % int(limit)
        return self._query(sql, params)

    # -- speed tests -------------------------------------------------------
    def add_speedtest(self, r: Dict[str, Any]) -> int:
        """Insert a result; ``r["network_id"]`` is the network current when the test started (stored once the migration ran)."""
        raw = r.get("raw")
        ts = float(r.get("ts") or time.time())
        values = [
            ts, 1 if r.get("ok") else 0, str(r.get("backend") or "unknown"),
            r.get("server"), r.get("isp"), r.get("external_ip"), r.get("latency_ms"), r.get("jitter_ms"),
            r.get("download_mbps"), r.get("upload_mbps"), r.get("packet_loss_pct"), r.get("duration_s"),
            r.get("error"), json.dumps(raw) if isinstance(raw, (dict, list)) else (raw if isinstance(raw, str) else None),
        ]
        cols = ("ts, ok, backend, server, isp, external_ip, latency_ms, jitter_ms, download_mbps, upload_mbps, packet_loss_pct, "
                "duration_s, error, raw_json")
        with self._lock:
            if self.networks_ready:
                cols += ", network_id"
                values.append(self._map_network(r.get("network_id"), ts))
            cur = self._conn.execute(f"INSERT INTO speedtests({cols}) VALUES({', '.join('?' * len(values))})", values)
            return int(cur.lastrowid)

    def list_speedtests(self, start_ts: float, end_ts: float, ok_only: bool = False,
                        limit: Optional[int] = None, with_raw: bool = False, network_id: Optional[int] = None,
                        legacy_since: Optional[float] = None) -> List[Dict[str, Any]]:
        """Results in ``[start_ts, end_ts)``, newest first; with *network_id* only that network's (and untagged results from
        *legacy_since* on)."""
        cols = "*" if with_raw else ("id, ts, ok, backend, server, isp, external_ip, latency_ms, jitter_ms, "
                                     "download_mbps, upload_mbps, packet_loss_pct, duration_s, error")
        sql = f"SELECT {cols} FROM speedtests WHERE ts>=? AND ts<?"
        params: List[Any] = [float(start_ts), float(end_ts)]
        if ok_only:
            sql += " AND ok=1"
        if network_id is not None and self.networks_ready:
            sql += " AND (network_id=? OR (network_id IS NULL AND ts>=?))"
            params += [int(network_id), float(legacy_since) if legacy_since is not None else 1e18]
        sql += " ORDER BY ts DESC"
        if limit:
            sql += " LIMIT %d" % int(limit)
        rows = self._query(sql, params)
        for r in rows:
            r["ok"] = bool(r["ok"])
        return rows

    def last_speedtest(self, ok_only: bool = False) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM speedtests" + (" WHERE ok=1" if ok_only else "") + " ORDER BY ts DESC LIMIT 1"
        r = self._one(sql)
        if r:
            r["ok"] = bool(r["ok"])
        return r

    # -- discovery ---------------------------------------------------------
    def add_discovery_run(self, run: Dict[str, Any], hosts: List[Dict[str, Any]]) -> int:
        """Insert a run and its hosts; ``run["network_id"]`` is the network current when the scan started."""
        ts = float(run.get("ts") or time.time())
        values = [
            ts, str(run.get("cidr")), json.dumps(list(run.get("ports") or [])),
            str(run.get("method") or "native"), run.get("duration_s"), run.get("scanned"), len(hosts),
            1 if run.get("ok", True) else 0, run.get("error"),
        ]
        cols = "ts, cidr, ports, method, duration_s, scanned, found, ok, error"
        with self._lock:
            if self.networks_ready:
                cols += ", network_id"
                values.append(self._map_network(run.get("network_id"), ts))
            cur = self._conn.execute(f"INSERT INTO discovery_runs({cols}) VALUES({', '.join('?' * len(values))})", values)
            run_id = int(cur.lastrowid)
            self._conn.executemany(
                "INSERT OR REPLACE INTO discovery_hosts(run_id, ip, hostname, mac, vendor, ping_ok, rtt_ms, open_ports, device_type)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                [
                    (run_id, h["ip"], h.get("hostname"), h.get("mac"), h.get("vendor"), 1 if h.get("ping_ok") else 0,
                     h.get("rtt_ms"), json.dumps(list(h.get("open_ports") or [])), h.get("device_type") or None)
                    for h in hosts
                ],
            )
            return run_id

    def list_discovery_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        rows = self._query("SELECT * FROM discovery_runs ORDER BY ts DESC LIMIT ?", (int(limit),))
        for r in rows:
            r["ports"] = json.loads(r["ports"] or "[]")
            r["ok"] = bool(r["ok"])
        return rows

    def get_discovery_run(self, run_id: int) -> Optional[Dict[str, Any]]:
        run = self._one("SELECT * FROM discovery_runs WHERE id=?", (run_id,))
        if not run:
            return None
        run["ports"] = json.loads(run["ports"] or "[]")
        run["ok"] = bool(run["ok"])
        hosts = self._query("SELECT * FROM discovery_hosts WHERE run_id=? ORDER BY ip", (run_id,))
        for h in hosts:
            h["open_ports"] = json.loads(h["open_ports"] or "[]")
            h["ping_ok"] = bool(h["ping_ok"])
        hosts.sort(key=lambda h: _ip_sort_key(h["ip"]))
        run["hosts"] = hosts
        return run

    def last_discovery_run(self) -> Optional[Dict[str, Any]]:
        r = self._one("SELECT id FROM discovery_runs ORDER BY ts DESC LIMIT 1")
        return self.get_discovery_run(int(r["id"])) if r else None

    # -- DHCP leases -------------------------------------------------------
    # One row per client MAC (the UI table is keyed by MAC, like Discovery). The in-memory
    # lease table in tnt.dhcp is the source of truth while the server runs; every change is
    # written through here so a service restart does not re-offer addresses that are live.
    @staticmethod
    def _dhcp_row_out(r: Dict[str, Any]) -> Dict[str, Any]:
        try:
            ports = json.loads(r.pop("open_ports_json", None) or "[]")
        except (TypeError, ValueError):
            ports = []
        r["open_ports"] = [int(p) for p in ports if isinstance(p, (int, float)) and not isinstance(p, bool)]
        ok = r.get("ping_ok")
        r["ping_ok"] = None if ok is None else bool(ok)
        return r

    def upsert_dhcp_lease(self, lease: Dict[str, Any]) -> None:
        """Insert or update the lease row for ``lease["mac"]`` (all LEASE DICT keys optional but mac/ip).

        ``hostname``/``vendor``/``client_id``/``rtt_ms``/``ping_ok``/``probed_ts`` keep their
        stored value when the new one is ``None`` (a renewal must not wipe what the probe found);
        everything else is replaced."""
        mac = str(lease.get("mac") or "").strip().upper()
        ip = str(lease.get("ip") or "").strip()
        if not mac or not ip:
            raise ValueError("a DHCP lease needs mac and ip")
        now = time.time()
        first_ts = float(lease.get("first_ts") or now)
        last_ts = float(lease.get("last_ts") or now)
        expires = lease.get("expires_ts")
        state = str(lease.get("state") or "offered")
        ping_ok = lease.get("ping_ok")
        self._exec(
            """INSERT INTO dhcp_leases(mac, ip, hostname, vendor, client_id, first_ts, last_ts, expires_ts, state,
                                       rtt_ms, open_ports_json, ping_ok, probed_ts)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(mac) DO UPDATE SET
                 ip=excluded.ip,
                 hostname=COALESCE(excluded.hostname, dhcp_leases.hostname),
                 vendor=COALESCE(excluded.vendor, dhcp_leases.vendor),
                 client_id=COALESCE(excluded.client_id, dhcp_leases.client_id),
                 first_ts=MIN(dhcp_leases.first_ts, excluded.first_ts),
                 last_ts=excluded.last_ts,
                 expires_ts=excluded.expires_ts,
                 state=excluded.state,
                 rtt_ms=COALESCE(excluded.rtt_ms, dhcp_leases.rtt_ms),
                 open_ports_json=excluded.open_ports_json,
                 ping_ok=COALESCE(excluded.ping_ok, dhcp_leases.ping_ok),
                 probed_ts=COALESCE(excluded.probed_ts, dhcp_leases.probed_ts)""",
            (
                mac, ip, lease.get("hostname"), lease.get("vendor"), lease.get("client_id"),
                first_ts, last_ts, float(expires) if expires is not None else None, state,
                lease.get("rtt_ms"), json.dumps(list(lease.get("open_ports") or [])),
                None if ping_ok is None else (1 if ping_ok else 0), lease.get("probed_ts"),
            ),
        )

    def get_dhcp_lease(self, mac: str) -> Optional[Dict[str, Any]]:
        r = self._one("SELECT * FROM dhcp_leases WHERE mac=?", (str(mac or "").strip().upper(),))
        return self._dhcp_row_out(r) if r else None

    def list_dhcp_leases(self, include_expired: bool = True, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Leases newest-activity first; ``include_expired=False`` keeps offered/bound rows only."""
        sql = "SELECT * FROM dhcp_leases"
        if not include_expired:
            sql += " WHERE state IN ('offered', 'bound')"
        sql += " ORDER BY last_ts DESC"
        if limit:
            sql += " LIMIT %d" % int(limit)
        return [self._dhcp_row_out(r) for r in self._query(sql)]

    def set_dhcp_lease_state(self, mac: str, state: str, ts: Optional[float] = None) -> None:
        self._exec(
            "UPDATE dhcp_leases SET state=?, last_ts=?, expires_ts=CASE WHEN ?='bound' THEN expires_ts ELSE NULL END WHERE mac=?",
            (str(state), float(ts if ts is not None else time.time()), str(state), str(mac or "").strip().upper()),
        )

    def expire_dhcp_leases(self, now: float) -> int:
        """Mark bound leases whose ``expires_ts`` has passed as expired; returns the row count."""
        cur = self._exec("UPDATE dhcp_leases SET state='expired', expires_ts=NULL WHERE state='bound' AND expires_ts IS NOT NULL AND expires_ts<?",
                         (float(now),))
        return int(cur.rowcount)

    def delete_dhcp_lease(self, mac: str) -> bool:
        cur = self._exec("DELETE FROM dhcp_leases WHERE mac=?", (str(mac or "").strip().upper(),))
        return cur.rowcount > 0

    def clear_dhcp_leases(self) -> int:
        cur = self._exec("DELETE FROM dhcp_leases")
        return int(cur.rowcount)

    # -- events ------------------------------------------------------------
    def add_event(self, level: str, category: str, message: str, ts: Optional[float] = None) -> None:
        self._exec("INSERT INTO events(ts, level, category, message) VALUES(?,?,?,?)",
                   (float(ts if ts is not None else time.time()), level, category, message))

    def list_events(self, limit: int = 200, start_ts: Optional[float] = None) -> List[Dict[str, Any]]:
        if start_ts is not None:
            return self._query("SELECT * FROM events WHERE ts>=? ORDER BY ts DESC LIMIT ?", (float(start_ts), int(limit)))
        return self._query("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (int(limit),))

    def last_event_ts(self, category: str, prefix: str = "", start_ts: Optional[float] = None) -> Optional[float]:
        """``ts`` of the newest events row of *category* whose message starts with *prefix* (at or after *start_ts*)."""
        sql = "SELECT MAX(ts) AS ts FROM events WHERE category=? AND substr(message, 1, ?)=?"
        params: List[Any] = [str(category), len(prefix), str(prefix)]
        if start_ts is not None:
            sql += " AND ts>=?"
            params.append(float(start_ts))
        row = self._one(sql, tuple(params))
        return float(row["ts"]) if row and row.get("ts") is not None else None

    # -- site reports (tnt.reports) ----------------------------------------
    # A report is only ever deleted by the user: retention() leaves the table alone. The list,
    # sites and stats queries never read the ``data`` column (tens of KB of JSON per report).
    # Searches take keys the caller already casefolded (tnt.reports.site_key): SQLite's own
    # LOWER()/LIKE fold ASCII only. "!" is the LIKE escape character.
    @staticmethod
    def _json_object(text: Any) -> Dict[str, Any]:
        try:
            value = json.loads(text) if isinstance(text, str) and text else {}
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _like(text: str, prefix: str = "%") -> str:
        """A LIKE pattern for *text* anywhere (``prefix="%"``), at the start (``""``) or after a space (``"% "``)."""
        return prefix + text.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"

    def add_report(self, site: str, site_key: str, created_ts: float, completed_ts: Optional[float], status: str,
                   tnt_version: Optional[str], summary: Dict[str, Any], data: Dict[str, Any],
                   network_id: Optional[int] = None) -> int:
        """Insert a report; *network_id* is the network current when its Full Scan started (stored once the migration ran)."""
        values = [str(site), str(site_key), float(created_ts), None if completed_ts is None else float(completed_ts),
                  str(status), tnt_version, json.dumps(summary or {}, separators=(",", ":"), default=str),
                  json.dumps(data or {}, separators=(",", ":"), default=str)]
        cols = "site, site_key, created_ts, completed_ts, status, tnt_version, summary, data"
        with self._lock:
            if self.networks_ready:
                cols += ", network_id"
                values.append(self._map_network(network_id, float(created_ts)))
            cur = self._conn.execute(f"INSERT INTO reports({cols}) VALUES({', '.join('?' * len(values))})", values)
            return int(cur.lastrowid)

    def _report_row_cols(self) -> str:
        return "id, site, created_ts, completed_ts, status, summary" + (", network_id" if self.networks_ready else "")

    def newest_report_on_network(self, network_id: Any, skip_site_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """``{"id","site","created_ts"}`` of the newest report saved on *network_id* (the Full Scan's suggested site), or None.
        A report whose ``site_key`` is *skip_site_key* (the "Unnamed site" placeholder) is passed over: it names no site."""
        nid = self.map_network_id(network_id)
        if nid is None or not self.networks_ready:
            return None
        skip = "" if skip_site_key is None else " AND site_key<>?"
        params: List[Any] = [nid] + ([str(skip_site_key)] if skip_site_key is not None else [])
        return self._one(f"SELECT id, site, created_ts FROM reports WHERE network_id=?{skip} ORDER BY created_ts DESC, id DESC LIMIT 1",
                         params)

    def list_reports(self, site_key: Optional[str] = None, q_key: Optional[str] = None, limit: int = 50,
                     offset: int = 0) -> tuple:
        """``(rows, total)``: ``{"id","site","created_ts","completed_ts","status","summary","network_id"}`` newest first, of one
        site (*site_key*) and/or whose key contains *q_key*; *total* counts every match."""
        clauses: List[str] = []
        params: List[Any] = []
        if site_key:
            clauses.append("site_key=?")
            params.append(str(site_key))
        if q_key:
            clauses.append("site_key LIKE ? ESCAPE '!'")
            params.append(self._like(str(q_key)))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            total = int(self._conn.execute(f"SELECT COUNT(*) AS n FROM reports{where}", params).fetchone()["n"])
            rows = [_row_to_dict(r) for r in self._conn.execute(
                f"SELECT {self._report_row_cols()} FROM reports{where} "
                "ORDER BY created_ts DESC, id DESC LIMIT ? OFFSET ?", params + [int(limit), int(offset)],
            ).fetchall()]
        for r in rows:
            r["summary"] = self._json_object(r.get("summary"))
            r.setdefault("network_id", None)
        return rows, total

    @staticmethod
    def _id_list(text: Any) -> List[int]:
        out: set = set()
        for part in str(text or "").split(","):
            try:
                out.add(int(part))
            except ValueError:
                continue
        return sorted(out)

    def report_sites(self, q_key: Optional[str] = None, limit: int = 20) -> tuple:
        """``(rows, total)``: one ``{"site","site_key","count","last_ts","network_ids"}`` per site (``site`` as its newest report
        spells it; ``network_ids`` the networks its reports were scanned on, untagged ones not listed). Without *q_key* the most
        recently scanned first; with it only keys containing it, those starting with it first, then those with a word starting
        with it, each most recent first."""
        where, rank, params = "", "0", []
        if q_key:
            key = str(q_key)
            where = " WHERE site_key LIKE ? ESCAPE '!'"
            rank = ("CASE WHEN site_key LIKE ? ESCAPE '!' THEN 0 WHEN site_key LIKE ? ESCAPE '!' THEN 1 ELSE 2 END")
            params = [self._like(key, ""), self._like(key, "% "), self._like(key)]
        nets = "GROUP_CONCAT(DISTINCT network_id)" if self.networks_ready else "NULL"
        sql = (
            "SELECT g.site_key AS site_key, g.n AS count, g.last_ts AS last_ts, g.nets AS nets, "
            "(SELECT r.site FROM reports r WHERE r.site_key=g.site_key ORDER BY r.created_ts DESC, r.id DESC LIMIT 1) AS site "
            f"FROM (SELECT site_key, COUNT(*) AS n, MAX(created_ts) AS last_ts, {nets} AS nets, {rank} AS rank FROM reports{where} "
            "GROUP BY site_key) g ORDER BY g.rank, g.last_ts DESC, g.site_key LIMIT ?"
        )
        with self._lock:
            rows = [_row_to_dict(r) for r in self._conn.execute(sql, params + [int(limit)]).fetchall()]
            total = int(self._conn.execute(f"SELECT COUNT(DISTINCT site_key) AS n FROM reports{where}",
                                           params[2:]).fetchone()["n"])
        return [{"site": r["site"], "site_key": r["site_key"], "count": int(r["count"]), "last_ts": r["last_ts"],
                 "network_ids": self._id_list(r.get("nets"))} for r in rows], total

    def get_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        net = ", network_id" if self.networks_ready else ""
        r = self._one("SELECT id, site, site_key, created_ts, completed_ts, status, tnt_version, summary, data" + net +
                      " FROM reports WHERE id=?", (int(report_id),))
        if r is None:
            return None
        r["summary"] = self._json_object(r.get("summary"))
        r["data"] = self._json_object(r.get("data"))
        r.setdefault("network_id", None)
        return r

    def rename_report(self, report_id: int, site: str, site_key: str) -> Optional[Dict[str, Any]]:
        """New site name (and ``data.meta.site``); returns the row without ``data``, None when the id is unknown."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE reports SET site=?, site_key=?, "
                "data=CASE WHEN json_valid(data) THEN json_set(data, '$.meta.site', ?) ELSE data END WHERE id=?",
                (str(site), str(site_key), str(site), int(report_id)),
            )
            if cur.rowcount <= 0:
                return None
            row = self._conn.execute(f"SELECT {self._report_row_cols()} FROM reports WHERE id=?",
                                     (int(report_id),)).fetchone()
        out = _row_to_dict(row)
        out["summary"] = self._json_object(out.get("summary"))
        out.setdefault("network_id", None)
        return out

    def delete_report(self, report_id: int) -> bool:
        cur = self._exec("DELETE FROM reports WHERE id=?", (int(report_id),))
        return cur.rowcount > 0

    def report_stats(self) -> Dict[str, Any]:
        """``{"count", "sites", "last": {"id","site","created_ts","status"}|None}`` (the Reports tile)."""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n, COUNT(DISTINCT site_key) AS sites FROM reports").fetchone()
            last = self._conn.execute(
                "SELECT id, site, created_ts, status FROM reports ORDER BY created_ts DESC, id DESC LIMIT 1").fetchone()
        return {"count": int(row["n"]), "sites": int(row["sites"]), "last": _row_to_dict(last) if last is not None else None}

    # -- networks (tnt.networks) -------------------------------------------
    # One row per network, never retention-trimmed.  Writers tag rows with the id current when the data was collected;
    # tnt.networks.NetworkTracker decides that id and, when a provisional (fingerprint) network turns out to be a router's
    # MAC network, moves what was tagged since the change with retag_network().
    NETWORK_FIELDS = ("mac", "fingerprint", "gateway_ip", "subnet", "dhcp_server", "dns_suffix", "nic", "virtual_mac", "portable")

    def _map_network(self, network_id: Any, ts: Optional[float]) -> Optional[int]:
        """*network_id* as stored for data of the moment *ts* (call with the lock held): None for no id, else followed through
        the aliases a merge left, so a write queued under a provisional id before the merge lands on the merged network."""
        if network_id is None or isinstance(network_id, bool):
            return None
        try:
            nid = int(network_id)
        except (TypeError, ValueError):
            return None
        if nid <= 0:
            return None
        when = time.time() if ts is None else float(ts)
        for frm, to, since, until in self._net_aliases:
            if nid == frm and since <= when < until:
                nid = to
        return nid

    def map_network_id(self, network_id: Any, ts: Optional[float] = None) -> Optional[int]:
        """The id *network_id* stands for now (``ts`` None) or for data of the moment *ts* (see :meth:`retag_network`)."""
        with self._lock:
            return self._map_network(network_id, ts)

    def end_network_aliases(self, network_id: int, ts: float) -> None:
        """*network_id* is current again from *ts* on: its open-ended aliases stop there (its later data is its own)."""
        with self._lock:
            self._net_aliases = [(f, t, s, (min(u, float(ts)) if f == int(network_id) and s <= float(ts) else u))
                                 for f, t, s, u in self._net_aliases]

    def add_network(self, ts: float, **facts: Any) -> Dict[str, Any]:
        """Insert a network (``mac``, ``fingerprint``, ``gateway_ip``, ``subnet``, ``dhcp_server``, ``dns_suffix``, ``nic``);
        ``first_seen`` = ``last_seen`` = *ts*.  ``sqlite3.IntegrityError`` when another row owns the MAC."""
        cols = [k for k in self.NETWORK_FIELDS if k in facts]
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO networks({', '.join(cols + ['first_seen', 'last_seen'])}) VALUES({', '.join('?' * (len(cols) + 2))})",
                [facts[k] for k in cols] + [float(ts), float(ts)])
            return self.get_network(int(cur.lastrowid))  # type: ignore[return-value]

    def get_network(self, network_id: Any) -> Optional[Dict[str, Any]]:
        try:
            return self._one("SELECT * FROM networks WHERE id=?", (int(network_id),))
        except (TypeError, ValueError):
            return None

    def network_by_mac(self, mac: str) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM networks WHERE mac=?", (str(mac),))

    def network_by_fingerprint(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        """The most recently seen network identified by *fingerprint* alone (a row that owns a MAC is never matched)."""
        return self._one("SELECT * FROM networks WHERE mac IS NULL AND fingerprint=? ORDER BY last_seen DESC, id DESC LIMIT 1",
                         (str(fingerprint),))

    def list_networks(self) -> List[Dict[str, Any]]:
        return self._query("SELECT * FROM networks ORDER BY last_seen DESC, id DESC")

    def update_network(self, network_id: int, **fields: Any) -> None:
        """Set some of NETWORK_FIELDS (and ``last_seen``); ``sqlite3.IntegrityError`` when another row owns the MAC."""
        cols = [k for k in self.NETWORK_FIELDS + ("last_seen",) if k in fields]
        if cols:
            self._exec(f"UPDATE networks SET {', '.join(k + '=?' for k in cols)} WHERE id=?",
                       [fields[k] for k in cols] + [int(network_id)])

    def touch_network(self, network_id: int, ts: float) -> None:
        self._exec("UPDATE networks SET last_seen=MAX(last_seen, ?) WHERE id=?", (float(ts), int(network_id)))

    #: reports a router MAC row backfills at most (the newest untagged ones)
    BACKFILL_REPORTS = 1000

    def backfill_report_networks(self, network_id: int, mac: str, gateway_ip: Optional[str]) -> int:
        """Tag the untagged reports (saved before networks were identified, 1.10.0) scanned behind this router: their network
        section's gateway is *gateway_ip* and their Discovery run found that address at *mac*.  Run when a network row gets its
        MAC; bounded to the newest BACKFILL_REPORTS untagged reports.  Returns the reports tagged."""
        if not self.networks_ready or not mac or not gateway_ip:
            return 0
        with self._lock:
            return int(self._conn.execute(
                "UPDATE reports SET network_id=? WHERE id IN (SELECT id FROM reports WHERE network_id IS NULL AND json_valid(data) "
                "AND json_extract(data, '$.network.internet_nic.gateway')=? ORDER BY created_ts DESC LIMIT ?) AND EXISTS ("
                "SELECT 1 FROM json_each(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.discovery.hosts') h "
                "WHERE json_type(h.value)='object' AND json_extract(h.value, '$.ip')=? "
                "AND upper(replace(json_extract(h.value, '$.mac'), '-', ':'))=?)",
                (int(network_id), str(gateway_ip), int(self.BACKFILL_REPORTS), str(gateway_ip), str(mac).upper())).rowcount)

    def _network_used(self, nid: int) -> bool:
        """Whether any row still carries *nid* (call with the lock held; minute rows are looked for from RETAG_WIDE_S before the
        network's first_seen, on the minute_ts index: a clock put back while it was current dates them before it)."""
        row = self._conn.execute("SELECT first_seen FROM networks WHERE id=?", (nid,)).fetchone()
        first = float(row[0]) if row is not None else 0.0
        if self._conn.execute("SELECT 1 FROM ping_minutes WHERE minute_ts>=? AND +network_id=? LIMIT 1",
                              (int(first - RETAG_WIDE_S), nid)).fetchone():
            return True
        for table, _col in _NETWORK_TAGGED:
            if self._conn.execute(f"SELECT 1 FROM {table} WHERE network_id=? LIMIT 1", (nid,)).fetchone():
                return True
        return self._conn.execute("SELECT 1 FROM network_offline WHERE network_id=? OR next_network_id=? LIMIT 1",
                                  (nid, nid)).fetchone() is not None

    def retag_network(self, from_id: int, to_id: int, since_ts: float, until_ts: Optional[float] = None,
                      delete_from: bool = False) -> Dict[str, Any]:
        """What was tagged *from_id* for moments in ``[since_ts, until_ts)`` becomes *to_id*, in one transaction: minute rows are
        merged into the rows *to_id* already has for the same minute (the upsert's arithmetic; a plain UPDATE would collide),
        outages / speed tests / Discovery runs / reports / offline spells updated.  From now on a write of *from_id* for a moment
        in that span is stored as *to_id* too (an in-memory alias: minutes still queued or in memory, an outage row inserted a
        moment later).  The span starts RETAG_SLACK_S before *since_ts* (an echo sent just before the change is stored with
        what came after it).  With *delete_from* (a network the change created: every row of it is this connection's) every row
        of *from_id* moves whatever its time, minute rows from RETAG_WIDE_S before its first_seen, the alias covers every moment,
        and the *from_id* row is deleted when nothing references it any more.  Returns the rows moved per table and ``deleted``."""
        frm, to = int(from_id), int(to_id)
        since = float(since_ts) - RETAG_SLACK_S
        until = float("inf") if until_ts is None else float(until_ts)
        bound = 1e18 if until == float("inf") else until
        moved: Dict[str, Any] = {"deleted": False}
        with self._lock:
            if frm == to:
                return moved
            if delete_from:
                since, until, bound = float("-inf"), float("inf"), 1e18
            self._net_aliases.append((frm, to, since, until))
            if not self.networks_ready:
                return moved
            if delete_from:
                row = self._conn.execute("SELECT first_seen FROM networks WHERE id=?", (frm,)).fetchone()
                lo, hi, low = (float(row[0]) if row is not None else 0.0) - RETAG_WIDE_S, bound, -1e18
            else:
                lo, hi, low = since - 59.999, bound - 59.999, since      # a minute belongs to the span when it ends inside it
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    f"INSERT INTO ping_minutes({_PING_COLS}, network_id) SELECT {_PING_COLS}, ? FROM ping_minutes "
                    "WHERE +network_id=? AND minute_ts>=? AND minute_ts<? "
                    f"ON CONFLICT(target_id, minute_ts, network_id) DO UPDATE SET {_PING_MERGE_SET}", (to, frm, lo, hi))
                moved["ping_minutes"] = self._conn.execute(
                    "DELETE FROM ping_minutes WHERE +network_id=? AND minute_ts>=? AND minute_ts<?", (frm, lo, hi)).rowcount
                for table, col in _NETWORK_TAGGED:
                    moved[table] = self._conn.execute(
                        f"UPDATE {table} SET network_id=? WHERE network_id=? AND {col}>=? AND {col}<?", (to, frm, low, bound)).rowcount
                moved["network_offline"] = self._conn.execute(
                    "UPDATE network_offline SET network_id=? WHERE network_id=? AND start_ts>=? AND start_ts<?",
                    (to, frm, low, bound)).rowcount + self._conn.execute(
                    "UPDATE network_offline SET next_network_id=? WHERE next_network_id=? AND end_ts>=? AND end_ts<?",
                    (to, frm, low, bound)).rowcount
                if delete_from and not self._network_used(frm):
                    self._conn.execute("DELETE FROM networks WHERE id=?", (frm,))
                    moved["deleted"] = True
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        return moved

    # offline spells: this PC had no network, its id staying on the last one (tnt.networks)
    def open_offline_spell(self, network_id: int, start_ts: float) -> Optional[int]:
        """Open a spell for *network_id* at *start_ts*, or return the id of the one already open."""
        if not self.networks_ready:
            return None
        with self._lock:
            row = self._conn.execute("SELECT id FROM network_offline WHERE end_ts IS NULL ORDER BY start_ts DESC LIMIT 1").fetchone()
            if row is not None:
                return int(row[0])
            return int(self._conn.execute("INSERT INTO network_offline(network_id, start_ts) VALUES(?, ?)",
                                          (int(network_id), float(start_ts))).lastrowid)

    def open_offline_spell_row(self) -> Optional[Dict[str, Any]]:
        if not self.networks_ready:
            return None
        return self._one("SELECT * FROM network_offline WHERE end_ts IS NULL ORDER BY start_ts DESC LIMIT 1")

    def mark_offline_spell(self, reason: str) -> int:
        """The open spell was spent (partly) on another network without a gateway (*reason* ``lan``): travel whatever network comes
        next.  Returns the rows marked."""
        if not self.networks_ready:
            return 0
        return int(self._exec("UPDATE network_offline SET reason=? WHERE end_ts IS NULL", (str(reason),)).rowcount)

    def add_offline_spell(self, network_id: int, start_ts: float, end_ts: float, next_network_id: Optional[int],
                          reason: Optional[str] = None) -> Optional[int]:
        """A closed spell (the time the service was stopped between two networks); None before the migration."""
        if not self.networks_ready:
            return None
        start, end = float(start_ts), max(float(end_ts), float(start_ts))
        return int(self._exec("INSERT INTO network_offline(network_id, start_ts, end_ts, next_network_id, reason) VALUES(?, ?, ?, ?, ?)",
                              (int(network_id), start, end, None if next_network_id is None else int(next_network_id), reason)).lastrowid)

    def close_offline_spells(self, end_ts: float, next_network_id: Optional[int]) -> List[Dict[str, Any]]:
        """Close every open spell at *end_ts* (never before its start) with the network identified then; returns them closed."""
        if not self.networks_ready:
            return []
        with self._lock:
            rows = [_row_to_dict(r) for r in self._conn.execute("SELECT * FROM network_offline WHERE end_ts IS NULL").fetchall()]
            for r in rows:
                r["end_ts"] = max(float(end_ts), float(r["start_ts"]))
                r["next_network_id"] = None if next_network_id is None else int(next_network_id)
                self._conn.execute("UPDATE network_offline SET end_ts=?, next_network_id=? WHERE id=?",
                                   (r["end_ts"], r["next_network_id"], int(r["id"])))
        return rows

    def offline_spells(self, network_id: int, start_ts: float, end_ts: float) -> List[Dict[str, Any]]:
        """The spells of *network_id* overlapping ``[start_ts, end_ts)`` (an open one included), oldest first."""
        if not self.networks_ready:
            return []
        return self._query("SELECT * FROM network_offline WHERE network_id=? AND start_ts<? AND (end_ts IS NULL OR end_ts>?) "
                           "ORDER BY start_ts", (int(network_id), float(end_ts), float(start_ts)))

    # -- maintenance -------------------------------------------------------
    def retention(self, days: int, now: Optional[float] = None) -> Dict[str, int]:
        """Hard-delete everything older than *days*. Returns row counts removed per table.

        Site reports are not monitoring data and are never trimmed here: only the user deletes one."""
        cutoff = (now if now is not None else time.time()) - days * 86400
        out: Dict[str, int] = {}
        with self._lock:
            out["ping_minutes"] = self._conn.execute("DELETE FROM ping_minutes WHERE minute_ts<?", (int(cutoff),)).rowcount
            out["outages"] = self._conn.execute("DELETE FROM outages WHERE end_ts IS NOT NULL AND end_ts<?", (cutoff,)).rowcount
            out["speedtests"] = self._conn.execute("DELETE FROM speedtests WHERE ts<?", (cutoff,)).rowcount
            old_runs = [r["id"] for r in self._conn.execute("SELECT id FROM discovery_runs WHERE ts<?", (cutoff,)).fetchall()]
            if old_runs:
                q = ",".join("?" * len(old_runs))
                self._conn.execute(f"DELETE FROM discovery_hosts WHERE run_id IN ({q})", old_runs)
                self._conn.execute(f"DELETE FROM discovery_runs WHERE id IN ({q})", old_runs)
            out["discovery_runs"] = len(old_runs)
            out["events"] = self._conn.execute("DELETE FROM events WHERE ts<?", (cutoff,)).rowcount
            # dead leases are only kept so a returning device gets its old address back;
            # after the retention window that memory is worthless
            out["dhcp_leases"] = self._conn.execute(
                "DELETE FROM dhcp_leases WHERE state IN ('expired', 'released', 'declined') AND last_ts<?", (cutoff,)
            ).rowcount
            # the networks themselves are never trimmed (a report names them); a closed offline spell older than the data is moot
            out["network_offline"] = self._conn.execute(
                "DELETE FROM network_offline WHERE end_ts IS NOT NULL AND end_ts<?", (cutoff,)).rowcount
        return out

    def vacuum(self) -> None:
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self._conn.execute("VACUUM")
            except sqlite3.Error:
                log.exception("vacuum failed")

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            if p.exists():
                total += p.stat().st_size
        return total

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        with self._lock:
            for t in ("targets", "ping_minutes", "outages", "speedtests", "discovery_runs", "discovery_hosts", "events",
                      "dhcp_leases", "reports", "networks", "network_offline"):
                out[t] = int(self._conn.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"])
        return out


def _ip_sort_key(ip: str):
    try:
        import ipaddress
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)
