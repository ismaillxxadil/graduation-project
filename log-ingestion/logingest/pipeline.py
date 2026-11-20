"""One line in -> one observation row OR one rejection row. Pure: no files, no database."""

from __future__ import annotations

import json

from . import SCHEMA_VERSION
from .identity import event_id
from .normalize import normalize, us_to_iso
from .parse import ParseError, parse_line, raw_sha256
from .reader import Line
from .validate import validate


def _raw_text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def process_line(probe_id: str, log_type: str, source_id: str, path: str,
                 line: Line, ingested_at: str) -> tuple[str, dict]:
    """Return ("observation", row) or ("rejection", row). Never raises on bad input."""
    sha = raw_sha256(line.raw)
    where = {"source_id": source_id, "probe_id": probe_id, "log_type": log_type, "path": path,
             "byte_start": line.byte_start, "byte_end": line.byte_end,
             "raw_line": _raw_text(line.raw), "raw_sha256": sha}

    def reject(stage, code, details):
        return "rejection", {**where, "stage": stage, "error_code": code,
                             "error_details_json": json.dumps(details, sort_keys=True),
                             "received_at": ingested_at}

    if line.oversize:
        return reject("read", "line_too_long", {"bytes": len(line.raw)})
    try:
        rec = parse_line(line.raw)
    except ParseError as e:
        return reject("parse", e.code, {"message": e.message})

    n = normalize(log_type, rec)
    bad = validate(log_type, n)
    if bad:
        return reject(bad.stage, bad.code, bad.details)

    d = n.data
    row = {
        **where,
        "event_id": event_id(probe_id, log_type, sha),
        "event_type": n.event_type,
        "schema_version": SCHEMA_VERSION,
        "observed_at_us": n.observed_at_us,
        "observed_at": us_to_iso(n.observed_at_us),
        "ingested_at": ingested_at,
        "zeek_uid": d.get("zeek_uid"),
        "src_ip": d.get("src_ip") or d.get("client_ip"),
        "dst_ip": d.get("dst_ip") or d.get("server_ip"),
        "data_json": json.dumps(d, sort_keys=True, separators=(",", ":")),
        "quality_flags": json.dumps(n.flags, separators=(",", ":")),
    }
    return "observation", row
