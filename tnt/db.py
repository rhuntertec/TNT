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
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1

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
    PRIMARY KEY (target_id, minute_ts)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_ping_minutes_ts ON ping_minutes(minute_ts);
CREATE TABLE IF NOT EXISTS outages (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    kind      TEXT NOT NULL,          -- target | total_local | total_internet | gap
    target_id INTEGER,                -- NULL for total/gap
    start_ts  REAL NOT NULL,
    end_ts    REAL,                   -- NULL while open
    missed    INTEGER NOT NULL DEFAULT 0,
    note      TEXT
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
    raw_json        TEXT
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
    error      TEXT
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
    device_type TEXT,                 -- Router | DW Server | Camera | Phone | Wifi | NULL (discovery.classify_device)
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
"""

DHCP_LEASE_STATES = ("offered", "bound", "released", "expired", "declined")


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {k: row[k] for k in row.keys()}


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
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
        # Camera / Phone / Wifi). Rows written before this are NULL and are categorised on read
        # (tnt.discovery.fill_device_types) so old runs show the column too.
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(discovery_hosts)").fetchall()}
        if "device_type" not in cols:
            self._conn.execute("ALTER TABLE discovery_hosts ADD COLUMN device_type TEXT")
            log.info("db migration: added discovery_hosts.device_type")

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
                           jitter_ms: Optional[float] = None) -> None:
        self._exec(
            """INSERT INTO ping_minutes(target_id, minute_ts, sent, received, avg_ms, min_ms, max_ms, jitter_ms)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(target_id, minute_ts) DO UPDATE SET
                 sent=ping_minutes.sent+excluded.sent,
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
                 jitter_ms=COALESCE(excluded.jitter_ms, ping_minutes.jitter_ms)""",
            (target_id, int(minute_ts), int(sent), int(received), avg_ms, min_ms, max_ms, jitter_ms),
        )

    def ping_minutes(self, target_id: int, start_ts: float, end_ts: float) -> List[Dict[str, Any]]:
        # a minute bucket covers [minute_ts, minute_ts + 60): return every bucket that overlaps the range
        return self._query(
            "SELECT * FROM ping_minutes WHERE target_id=? AND minute_ts+60>? AND minute_ts<? ORDER BY minute_ts",
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

    # -- outages -----------------------------------------------------------
    def open_outage(self, kind: str, target_id: Optional[int], start_ts: float, note: Optional[str] = None,
                    host: Optional[str] = None) -> int:
        cur = self._exec(
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
        raw = r.get("raw")
        cur = self._exec(
            """INSERT INTO speedtests(ts, ok, backend, server, isp, external_ip, latency_ms, jitter_ms,
                 download_mbps, upload_mbps, packet_loss_pct, duration_s, error, raw_json)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                float(r.get("ts") or time.time()), 1 if r.get("ok") else 0, str(r.get("backend") or "unknown"),
                r.get("server"), r.get("isp"), r.get("external_ip"), r.get("latency_ms"), r.get("jitter_ms"),
                r.get("download_mbps"), r.get("upload_mbps"), r.get("packet_loss_pct"), r.get("duration_s"),
                r.get("error"), json.dumps(raw) if isinstance(raw, (dict, list)) else (raw if isinstance(raw, str) else None),
            ),
        )
        return int(cur.lastrowid)

    def list_speedtests(self, start_ts: float, end_ts: float, ok_only: bool = False,
                        limit: Optional[int] = None, with_raw: bool = False) -> List[Dict[str, Any]]:
        cols = "*" if with_raw else ("id, ts, ok, backend, server, isp, external_ip, latency_ms, jitter_ms, "
                                     "download_mbps, upload_mbps, packet_loss_pct, duration_s, error")
        sql = f"SELECT {cols} FROM speedtests WHERE ts>=? AND ts<?"
        if ok_only:
            sql += " AND ok=1"
        sql += " ORDER BY ts DESC"
        if limit:
            sql += " LIMIT %d" % int(limit)
        rows = self._query(sql, (float(start_ts), float(end_ts)))
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
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO discovery_runs(ts, cidr, ports, method, duration_s, scanned, found, ok, error) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    float(run.get("ts") or time.time()), str(run.get("cidr")), json.dumps(list(run.get("ports") or [])),
                    str(run.get("method") or "native"), run.get("duration_s"), run.get("scanned"), len(hosts),
                    1 if run.get("ok", True) else 0, run.get("error"),
                ),
            )
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

    # -- maintenance -------------------------------------------------------
    def retention(self, days: int, now: Optional[float] = None) -> Dict[str, int]:
        """Hard-delete everything older than *days*. Returns row counts removed per table."""
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
                      "dhcp_leases"):
                out[t] = int(self._conn.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"])
        return out


def _ip_sort_key(ip: str):
    try:
        import ipaddress
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)
