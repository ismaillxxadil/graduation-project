"""Read-only exports for Module 6 and simple inspection."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .db import SCHEMA_VERSION, connect_state


def _json(value, default=None):
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _rows(con, table: str) -> list[dict]:
    return [dict(row) for row in con.execute(f"SELECT * FROM {table}").fetchall()]


def _change_rows(con, after: int | None = None, limit: int | None = None) -> list[dict]:
    rows = _rows(con, "changes")
    rows.sort(key=lambda row: row["change_id"])
    versions = {}
    for row in rows:
        key = (row["entity_type"], row["entity_id"])
        versions[key] = versions.get(key, 0) + 1
        if row.get("processed_at_us") is None:
            row["processed_at_us"] = row["observed_at_us"]
        if row.get("entity_version") is None:
            row["entity_version"] = versions[key]
    if after is not None:
        rows = [row for row in rows if row["change_id"] > after]
    return rows if limit is None else rows[:limit]


def snapshot(state_path: str) -> dict:
    con = connect_state(state_path, read_only=True)
    try:
        con.execute("BEGIN")
        stored_version = con.execute("PRAGMA user_version").fetchone()[0]
        events = []
        for row in _rows(con, "events"):
            row["data"] = _json(row.pop("data_json"), {})
            row["quality_flags"] = _json(row.pop("quality_flags_json"), [])
            row["provenance"] = _json(row.pop("provenance_json"), {})
            events.append(row)
        evidence = []
        for row in _rows(con, "evidence"):
            row["claim"] = _json(row.pop("claim_json"), {})
            evidence.append(row)
        software = []
        for row in _rows(con, "software_claims"):
            row["port"] = None if row["port"] == -1 else row["port"]
            row["name"] = row["name"] or None
            row["version"] = _json(row.pop("version_json"), None)
            row["unparsed_version"] = row.pop("raw_version") or None
            software.append(row)
        interactions = _rows(con, "interactions")
        for row in interactions:
            row.setdefault("communication_id", row["interaction_id"])
        cursor = [dict(row) for row in con.execute("SELECT consumer,sequence FROM cursor").fetchall()]
        change_rows = _change_rows(con)
        return {
            "schema_version": stored_version or SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "cursor": cursor,
            "change_watermark": change_rows[-1]["change_id"] if change_rows else 0,
            "assets": _rows(con, "assets"),
            "addresses": _rows(con, "addresses"),
            "services": _rows(con, "services"),
            "software": software,
            "interactions": interactions,
            "evidence": evidence,
            "events": events,
            "changes": change_rows,
        }
    finally:
        if con.in_transaction:
            con.rollback()
        con.close()


def changes(state_path: str, after: int = 0, limit: int = 500) -> list[dict]:
    con = connect_state(state_path, read_only=True)
    try:
        rows = _change_rows(con, after, limit)
        for row in rows:
            row["payload"] = _json(row.pop("payload_json"), {})
        return rows
    finally:
        con.close()


def write_snapshot(state_path: str, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(snapshot(state_path), handle, indent=2, sort_keys=True)
        handle.write("\n")
