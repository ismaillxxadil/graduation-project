"""SQLite storage: schema, one-transaction batch write, and the read API.

Rules that keep the data correct:
- WAL + synchronous=FULL: Module 5 can read while we write; a commit survives power loss.
- observations, rejected_records and the file offset are written in ONE transaction,
  so a crash can never save rows without the offset or the offset without the rows.
- event_id is UNIQUE: reading the same line twice stores it once.
- sequence is AUTOINCREMENT: numbers only go up, even after deletes, so
  `WHERE sequence > cursor` never misses a row.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .reader import FileState

DB_SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS file_offsets (
    source_id   TEXT PRIMARY KEY,           -- e.g. probe1:conn  or  probe1:conn:archive/1763650000
    probe_id    TEXT NOT NULL,
    log_type    TEXT NOT NULL,
    path        TEXT NOT NULL,
    inode       INTEGER NOT NULL,
    head_hash   TEXT,                       -- sha256 of the first line: detects a replaced file
    offset      INTEGER NOT NULL,           -- next byte to read
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    sequence        INTEGER PRIMARY KEY AUTOINCREMENT,   -- Module 5 reads in this order
    event_id        TEXT NOT NULL UNIQUE,
    source_id       TEXT NOT NULL REFERENCES file_offsets(source_id),
    probe_id        TEXT NOT NULL,
    log_type        TEXT NOT NULL,
    event_type      TEXT NOT NULL,                       -- network_connection | dhcp_observation
    schema_version  INTEGER NOT NULL,
    observed_at_us  INTEGER NOT NULL,                    -- Zeek ts in microseconds (UTC)
    observed_at     TEXT NOT NULL,                       -- same, ISO-8601 UTC
    ingested_at     TEXT NOT NULL,
    zeek_uid        TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    data_json       TEXT NOT NULL,                       -- the normalized fields
    quality_flags   TEXT NOT NULL,                       -- JSON list, e.g. ["mdns","no_reply"]
    raw_line        TEXT NOT NULL,
    raw_sha256      TEXT NOT NULL,
    path            TEXT NOT NULL,
    byte_start      INTEGER NOT NULL,
    byte_end        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS obs_natural_key ON observations(probe_id, log_type, zeek_uid, observed_at_us);
CREATE INDEX IF NOT EXISTS obs_event_type  ON observations(event_type);
CREATE INDEX IF NOT EXISTS obs_src_ip      ON observations(src_ip);
CREATE INDEX IF NOT EXISTS obs_dst_ip      ON observations(dst_ip);

CREATE TABLE IF NOT EXISTS rejected_records (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id           TEXT NOT NULL REFERENCES file_offsets(source_id),
    probe_id            TEXT NOT NULL,
    log_type            TEXT NOT NULL,
    stage               TEXT NOT NULL,               -- read | parse | validate
    error_code          TEXT NOT NULL,
    error_details_json  TEXT NOT NULL,
    raw_line            TEXT NOT NULL,
    raw_sha256          TEXT NOT NULL,
    path                TEXT NOT NULL,
    byte_start          INTEGER NOT NULL,
    byte_end            INTEGER NOT NULL,
    received_at         TEXT NOT NULL,
    UNIQUE (probe_id, log_type, raw_sha256)
);

CREATE TABLE IF NOT EXISTS consumer_cursors (
    consumer_id    TEXT PRIMARY KEY,                 -- e.g. module5
    last_sequence  INTEGER NOT NULL DEFAULT 0,       -- points to observations.sequence
    updated_at     TEXT NOT NULL
);
"""

OBS_COLS = ("event_id", "source_id", "probe_id", "log_type", "event_type", "schema_version",
            "observed_at_us", "observed_at", "ingested_at", "zeek_uid", "src_ip", "dst_ip",
            "data_json", "quality_flags", "raw_line", "raw_sha256", "path", "byte_start", "byte_end")
REJ_COLS = ("source_id", "probe_id", "log_type", "stage", "error_code", "error_details_json",
            "raw_line", "raw_sha256", "path", "byte_start", "byte_end", "received_at")

_INSERT_OBS = (f"INSERT INTO observations ({','.join(OBS_COLS)}) VALUES ({','.join('?' * len(OBS_COLS))}) "
               "ON CONFLICT(event_id) DO NOTHING")
_INSERT_REJ = (f"INSERT INTO rejected_records ({','.join(REJ_COLS)}) VALUES ({','.join('?' * len(REJ_COLS))}) "
               "ON CONFLICT(probe_id, log_type, raw_sha256) DO NOTHING")


class SchemaMismatch(Exception):
    pass


def connect(path: str | Path, create: bool = True) -> sqlite3.Connection:
    path = Path(path)
    if create:
        path.parent.mkdir(parents=True, exist_ok=True)
    elif not path.exists():
        raise FileNotFoundError(f"database not found: {path} (run `init` or `run` first)")
    # isolation_level=None: we open transactions ourselves with BEGIN IMMEDIATE.
    con = sqlite3.connect(path, isolation_level=None, timeout=5.0)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=FULL")
    con.execute("PRAGMA busy_timeout=5000")
    con.execute("PRAGMA foreign_keys=ON")
    if create:
        init_schema(con)
    return con


def init_schema(con: sqlite3.Connection) -> None:
    version = con.execute("PRAGMA user_version").fetchone()[0]
    if version not in (0, DB_SCHEMA_VERSION):
        raise SchemaMismatch(f"database schema v{version}, this code expects v{DB_SCHEMA_VERSION}")
    con.executescript("BEGIN IMMEDIATE;" + SCHEMA + f"PRAGMA user_version={DB_SCHEMA_VERSION}; COMMIT;")


# ---------- write side (Module 4) ----------

def load_offset(con: sqlite3.Connection, source_id: str) -> FileState | None:
    r = con.execute("SELECT path, inode, head_hash, offset FROM file_offsets WHERE source_id=?",
                    (source_id,)).fetchone()
    return None if r is None else FileState(r["path"], r["inode"], r["head_hash"], r["offset"])


def store_batch(con: sqlite3.Connection, source_id: str, probe_id: str, log_type: str,
                state: FileState, observations: list[dict], rejects: list[dict],
                now: str) -> tuple[int, int, int]:
    """Write rows + new offset atomically. Returns (inserted, duplicates, rejected)."""
    con.execute("BEGIN IMMEDIATE")
    try:
        con.execute(
            "INSERT INTO file_offsets (source_id, probe_id, log_type, path, inode, head_hash, offset, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET "
            "path=excluded.path, inode=excluded.inode, head_hash=excluded.head_hash, "
            "offset=excluded.offset, updated_at=excluded.updated_at",
            (source_id, probe_id, log_type, state.path, state.inode, state.head_hash, state.offset, now))
        inserted = 0
        for o in observations:
            inserted += con.execute(_INSERT_OBS, tuple(o[c] for c in OBS_COLS)).rowcount
        rejected = 0
        for r in rejects:
            rejected += con.execute(_INSERT_REJ, tuple(r[c] for c in REJ_COLS)).rowcount
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise
    return inserted, len(observations) - inserted, rejected


# ---------- read side (Module 5 or any tool) ----------

def row_to_observation(r: sqlite3.Row) -> dict:
    """Database row -> Observation v1 document (see CONTRACT.md)."""
    return {
        "sequence": r["sequence"],
        "schema_version": r["schema_version"],
        "event_id": r["event_id"],
        "event_type": r["event_type"],
        "probe_id": r["probe_id"],
        "observed_at": r["observed_at"],
        "observed_at_us": r["observed_at_us"],
        "ingested_at": r["ingested_at"],
        "data": json.loads(r["data_json"]),
        "quality_flags": json.loads(r["quality_flags"]),
        "provenance": {
            "source_id": r["source_id"], "log_type": r["log_type"], "path": r["path"],
            "byte_start": r["byte_start"], "byte_end": r["byte_end"], "raw_sha256": r["raw_sha256"],
        },
    }


def read_batch(con: sqlite3.Connection, after_sequence: int, limit: int = 500) -> list[dict]:
    rows = con.execute("SELECT * FROM observations WHERE sequence > ? ORDER BY sequence LIMIT ?",
                       (after_sequence, limit)).fetchall()
    return [row_to_observation(r) for r in rows]


def get_cursor(con: sqlite3.Connection, consumer_id: str) -> int:
    r = con.execute("SELECT last_sequence FROM consumer_cursors WHERE consumer_id=?", (consumer_id,)).fetchone()
    return 0 if r is None else r[0]


def save_cursor(con: sqlite3.Connection, consumer_id: str, last_sequence: int, now: str) -> None:
    con.execute(
        "INSERT INTO consumer_cursors (consumer_id, last_sequence, updated_at) VALUES (?,?,?) "
        "ON CONFLICT(consumer_id) DO UPDATE SET last_sequence=excluded.last_sequence, updated_at=excluded.updated_at",
        (consumer_id, last_sequence, now))


def stats(con: sqlite3.Connection) -> dict:
    q = lambda sql: [dict(r) for r in con.execute(sql).fetchall()]  # noqa: E731
    return {
        "observations": q("SELECT probe_id, log_type, COUNT(*) AS rows, MAX(sequence) AS last_sequence "
                          "FROM observations GROUP BY probe_id, log_type ORDER BY probe_id, log_type"),
        "rejected": q("SELECT probe_id, log_type, stage, error_code, COUNT(*) AS rows FROM rejected_records "
                      "GROUP BY probe_id, log_type, stage, error_code ORDER BY rows DESC"),
        "flags": q("SELECT j.value AS flag, COUNT(*) AS rows FROM observations, json_each(quality_flags) AS j "
                   "GROUP BY j.value ORDER BY rows DESC"),
        "offsets": q("SELECT source_id, path, offset, updated_at FROM file_offsets ORDER BY source_id"),
        "cursors": q("SELECT consumer_id, last_sequence, updated_at FROM consumer_cursors ORDER BY consumer_id"),
    }
