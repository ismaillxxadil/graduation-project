"""Small SQLite boundary for Module 4 reads and Module 5 state."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS cursor (
    consumer TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
    sequence INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    probe_id TEXT NOT NULL,
    observed_at_us INTEGER NOT NULL,
    observed_at TEXT NOT NULL,
    data_json TEXT NOT NULL,
    quality_flags_json TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    disposition TEXT NOT NULL,
    error TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES events(event_id),
    kind TEXT NOT NULL,
    subject_id TEXT,
    claim_json TEXT NOT NULL,
    observed_at_us INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    identity_key TEXT NOT NULL,
    identity_state TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    first_seen_us INTEGER NOT NULL,
    last_seen_us INTEGER NOT NULL,
    UNIQUE(scope, identity_key)
);
CREATE TABLE IF NOT EXISTS addresses (
    address_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    scope TEXT NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    association_state TEXT NOT NULL,
    first_seen_us INTEGER NOT NULL,
    last_seen_us INTEGER NOT NULL,
    UNIQUE(asset_id, scope, ip)
);
CREATE INDEX IF NOT EXISTS addresses_lookup ON addresses(scope, ip);
CREATE TABLE IF NOT EXISTS services (
    service_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    scope TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    transport TEXT NOT NULL,
    protocol TEXT,
    state TEXT NOT NULL,
    first_seen_us INTEGER NOT NULL,
    last_seen_us INTEGER NOT NULL,
    UNIQUE(asset_id, scope, ip, port, transport)
);
CREATE TABLE IF NOT EXISTS software_claims (
    claim_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id),
    scope TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    role TEXT NOT NULL,
    software_type TEXT NOT NULL,
    name TEXT NOT NULL,
    version_json TEXT NOT NULL,
    raw_version TEXT NOT NULL,
    attribution TEXT NOT NULL,
    first_seen_us INTEGER NOT NULL,
    last_seen_us INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS interactions (
    interaction_id TEXT PRIMARY KEY,
    communication_id TEXT NOT NULL,
    event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
    evidence_id TEXT,
    scope TEXT NOT NULL,
    source_asset_id TEXT REFERENCES assets(asset_id),
    target_asset_id TEXT REFERENCES assets(asset_id),
    source_ip TEXT,
    target_ip TEXT,
    source_port INTEGER,
    target_port INTEGER,
    transport TEXT NOT NULL,
    protocol TEXT,
    outcome TEXT NOT NULL,
    observed_at_us INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS changes (
    change_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_id TEXT NOT NULL REFERENCES events(event_id),
    action TEXT NOT NULL,
    observed_at_us INTEGER NOT NULL,
    processed_at_us INTEGER NOT NULL,
    entity_version INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    UNIQUE(entity_type, entity_id, event_id, action)
);
"""


def stable_id(*parts: object) -> str:
    """Return a deterministic identifier without exposing input data."""
    value = "\0".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _read_only_uri(path: str | Path) -> str:
    return f"file:{Path(path).resolve()}?mode=ro"


def connect_module4(path: str | Path) -> sqlite3.Connection:
    """Open the public Module 4 database without any write capability."""
    con = sqlite3.connect(_read_only_uri(path), uri=True, timeout=5.0)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    con.execute("PRAGMA busy_timeout=5000")
    required = {
        "sequence", "event_id", "event_type", "probe_id", "schema_version", "observed_at_us",
        "observed_at", "ingested_at", "data_json", "quality_flags", "source_id",
        "log_type", "path", "byte_start", "byte_end", "raw_sha256",
    }
    columns = {row[1] for row in con.execute("PRAGMA table_info(observations)")}
    missing = required - columns
    if missing:
        con.close()
        raise ValueError(f"Module 4 observations table is missing: {sorted(missing)}")
    return con


def connect_state(path: str | Path, read_only: bool = False) -> sqlite3.Connection:
    """Open or initialize the independent Module 5 state database."""
    path = Path(path)
    if read_only:
        con = sqlite3.connect(_read_only_uri(path), uri=True, timeout=5.0)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(path, isolation_level=None, timeout=5.0)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=5000")
    if read_only:
        con.execute("PRAGMA query_only=ON")
        version = con.execute("PRAGMA user_version").fetchone()[0]
    else:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=FULL")
        version = con.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1, 2, SCHEMA_VERSION):
            con.close()
            raise ValueError(f"unsupported Module 5 schema version: {version}")
        if version == 0:
            con.executescript(
                "BEGIN IMMEDIATE;\n" + SCHEMA +
                f"PRAGMA user_version={SCHEMA_VERSION};\nCOMMIT;"
            )
        elif version in (1, 2):
            con.execute("BEGIN IMMEDIATE")
            try:
                if version == 1:
                    columns = {row[1] for row in con.execute("PRAGMA table_info(interactions)")}
                    if "communication_id" not in columns:
                        con.execute("ALTER TABLE interactions ADD COLUMN communication_id TEXT")
                    con.execute("UPDATE interactions SET communication_id=interaction_id WHERE communication_id IS NULL")
                tables = {row[0] for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
                if "changes" not in tables:
                    con.execute(
                        "CREATE TABLE changes ("
                        "change_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        "entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,"
                        "event_id TEXT NOT NULL REFERENCES events(event_id),"
                        "action TEXT NOT NULL, observed_at_us INTEGER NOT NULL,"
                        "processed_at_us INTEGER, entity_version INTEGER,"
                        "payload_json TEXT NOT NULL,"
                        "UNIQUE(entity_type, entity_id, event_id, action))"
                    )
                columns = {row[1] for row in con.execute("PRAGMA table_info(changes)")}
                if "processed_at_us" not in columns:
                    con.execute("ALTER TABLE changes ADD COLUMN processed_at_us INTEGER")
                if "entity_version" not in columns:
                    con.execute("ALTER TABLE changes ADD COLUMN entity_version INTEGER")
                versions = {}
                for row in con.execute(
                    "SELECT change_id,entity_type,entity_id,observed_at_us FROM changes ORDER BY change_id"
                ):
                    key = (row[1], row[2])
                    versions[key] = versions.get(key, 0) + 1
                    con.execute(
                        "UPDATE changes SET processed_at_us=?,entity_version=? WHERE change_id=?",
                        (row[3], versions[key], row[0]),
                    )
                con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            except BaseException:
                con.execute("ROLLBACK")
                raise
            else:
                con.execute("COMMIT")
    if read_only and version not in (1, 2, SCHEMA_VERSION):
        con.close()
        raise ValueError(f"unsupported Module 5 schema version: {version}")
    return con


@contextmanager
def transaction(con: sqlite3.Connection):
    con.execute("BEGIN IMMEDIATE")
    try:
        yield con
    except BaseException:
        con.execute("ROLLBACK")
        raise
    else:
        con.execute("COMMIT")


def _decode(value: str, fallback):
    try:
        return json.loads(value), None
    except (TypeError, json.JSONDecodeError) as exc:
        return fallback, str(exc)


def read_batch(con: sqlite3.Connection, after: int, limit: int) -> list[dict]:
    rows = con.execute(
        "SELECT * FROM observations WHERE sequence > ? ORDER BY sequence LIMIT ?",
        (after, limit),
    ).fetchall()
    result = []
    for row in rows:
        data, data_error = _decode(row["data_json"], {})
        flags, flags_error = _decode(row["quality_flags"], [])
        result.append({
            "sequence": row["sequence"],
            "event_id": row["event_id"],
            "event_type": row["event_type"],
            "probe_id": row["probe_id"],
            "observed_at": row["observed_at"],
            "observed_at_us": row["observed_at_us"],
            "data": data,
            "quality_flags": flags,
            "provenance": {
                "source_id": row["source_id"], "log_type": row["log_type"],
                "path": row["path"], "byte_start": row["byte_start"],
                "byte_end": row["byte_end"], "raw_sha256": row["raw_sha256"],
                "ingested_at": row["ingested_at"], "schema_version": row["schema_version"],
            },
            "_data_json": row["data_json"],
            "_quality_flags": row["quality_flags"],
            "_decode_error": data_error or flags_error,
        })
    return result


def get_cursor(con: sqlite3.Connection, consumer: str = "module5") -> int:
    row = con.execute("SELECT sequence FROM cursor WHERE consumer=?", (consumer,)).fetchone()
    return 0 if row is None else row[0]


def save_cursor(con: sqlite3.Connection, sequence: int, consumer: str = "module5") -> None:
    con.execute(
        "INSERT INTO cursor(consumer, sequence) VALUES (?, ?) "
        "ON CONFLICT(consumer) DO UPDATE SET sequence=excluded.sequence",
        (consumer, sequence),
    )


def insert_event(con: sqlite3.Connection, obs: dict, disposition: str = "pending") -> bool:
    cur = con.execute(
        "INSERT OR IGNORE INTO events(sequence,event_id,event_type,probe_id,observed_at_us,observed_at,"
        "data_json,quality_flags_json,provenance_json,disposition) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            obs["sequence"], obs["event_id"], obs["event_type"], obs["probe_id"],
            obs["observed_at_us"], obs["observed_at"], obs["_data_json"],
            obs["_quality_flags"], json.dumps(obs["provenance"], sort_keys=True), disposition,
        ),
    )
    return cur.rowcount == 1


def finish_event(con: sqlite3.Connection, event_id: str, disposition: str, error: str | None = None) -> None:
    con.execute("UPDATE events SET disposition=?, error=? WHERE event_id=?", (disposition, error, event_id))


def add_evidence(con: sqlite3.Connection, event_id: str, kind: str, subject_id: str | None,
                 claim: dict, observed_at_us: int) -> str:
    evidence_id = stable_id("evidence", event_id, kind, subject_id)
    con.execute(
        "INSERT OR IGNORE INTO evidence(evidence_id,event_id,kind,subject_id,claim_json,observed_at_us) "
        "VALUES (?,?,?,?,?,?)",
        (evidence_id, event_id, kind, subject_id, json.dumps(claim, sort_keys=True), observed_at_us),
    )
    return evidence_id


def add_change(con: sqlite3.Connection, entity_type: str, entity_id: str, event_id: str,
               action: str, observed_at_us: int, payload: dict) -> None:
    entity_version = con.execute(
        "SELECT COUNT(*)+1 FROM changes WHERE entity_type=? AND entity_id=?",
        (entity_type, entity_id),
    ).fetchone()[0]
    con.execute(
        "INSERT OR IGNORE INTO changes(entity_type,entity_id,event_id,action,observed_at_us,"
        "processed_at_us,entity_version,payload_json) VALUES (?,?,?,?,?,?,?,?)",
        (entity_type, entity_id, event_id, action, observed_at_us, time.time_ns() // 1000,
         entity_version, json.dumps(payload, sort_keys=True)),
    )
