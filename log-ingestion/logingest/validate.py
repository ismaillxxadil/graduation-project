"""Decide if a normalized record is accepted or rejected.

Two checks:
1. any problem found while normalizing a required field -> reject;
2. the Observation v1 contract: required data fields must be filled.
   (This second check is a safety net against bugs in normalize.py.)
"""

from __future__ import annotations

from dataclasses import dataclass

from .normalize import Normalized

REQUIRED_DATA = {
    "conn": ("zeek_uid", "src_ip", "dst_ip", "transport"),
    "dhcp": ("source_uids", "message_types"),
    "software": ("host_ip",),
}


@dataclass(frozen=True)
class Rejection:
    stage: str
    code: str
    details: dict


def validate(log_type: str, n: Normalized) -> Rejection | None:
    if "log_type" in n.problems:
        return Rejection("validate", "unknown_log_type", dict(n.problems))
    if n.problems:
        missing_only = all(r == "missing" for r in n.problems.values())
        return Rejection("validate", "missing_field" if missing_only else "invalid_field", dict(n.problems))

    gaps = [k for k in REQUIRED_DATA.get(log_type, ()) if n.data.get(k) is None]
    if log_type == "conn" and not gaps:
        if n.data["transport"] == "icmp":
            gaps += [k for k in ("icmp_type", "icmp_code") if n.data.get(k) is None]
        else:
            gaps += [k for k in ("src_port", "dst_port") if n.data.get(k) is None]
    if n.observed_at_us is None:
        gaps.append("observed_at_us")
    if gaps:
        return Rejection("validate", "contract_violation", {k: "required by Observation v1" for k in gaps})
    return None
