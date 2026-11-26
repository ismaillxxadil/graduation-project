"""Direct observation-to-state processing for Module 5."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from .db import (
    add_change,
    add_evidence,
    connect_module4,
    connect_state,
    get_cursor,
    insert_event,
    read_batch,
    save_cursor,
    stable_id,
    transaction,
    finish_event,
)
from .rules import (
    SUPPORTED_TYPES,
    connection_rule,
    dhcp_rule,
    scope_for,
    software_rule,
    usable_ip,
)

IDENTITY_WINDOW_US = 10_000_000
CORRELATION_WINDOW_US = 100_000
DEFAULT_DORMANT_AFTER_US = 3_600 * 1_000_000
DEFAULT_EXPIRED_AFTER_US = 24 * 3_600 * 1_000_000


def _identity_key(ip: str | None = None, mac: str | None = None) -> str:
    return f"mac:{mac.lower()}" if mac else f"ip:{ip}"


def _ensure_asset(con, scope: str, key: str, state: str, seen: int, ip: str | None = None,
                  initial_lifecycle: str = "active") -> str:
    row = con.execute("SELECT asset_id FROM assets WHERE scope=? AND identity_key=?", (scope, key)).fetchone()
    if row:
        asset_id = row[0]
    else:
        asset_id = None
        if key.startswith("mac:") and scope != "unscoped":
            row = con.execute(
                "SELECT a.asset_id FROM assets a "
                "WHERE a.identity_key=? AND a.scope='unscoped' "
                "AND NOT EXISTS (SELECT 1 FROM addresses x WHERE x.asset_id=a.asset_id) "
                "LIMIT 1",
                (key,),
            ).fetchone()
            if row:
                asset_id = row[0]
                con.execute("UPDATE assets SET scope=? WHERE asset_id=?", (scope, asset_id))
        if asset_id is None and key.startswith("mac:") and scope == "unscoped":
            rows = con.execute(
                "SELECT asset_id FROM assets WHERE identity_key=? AND scope!='unscoped'",
                (key,),
            ).fetchall()
            if len(rows) == 1:
                asset_id = rows[0][0]
        if asset_id is None and ip and key.startswith("ip:"):
            row = con.execute(
                "SELECT a.asset_id FROM assets a JOIN addresses x ON x.asset_id=a.asset_id "
                "WHERE x.scope=? AND x.ip=? AND x.association_state!='requested' "
                "ORDER BY x.last_seen_us DESC LIMIT 1",
                (scope, ip),
            ).fetchone()
            asset_id = row[0] if row else None
        if asset_id is None:
            asset_id = stable_id("asset", scope, key)
            con.execute(
                "INSERT INTO assets(asset_id,scope,identity_key,identity_state,lifecycle_state,first_seen_us,last_seen_us) "
                "VALUES (?,?,?,?,?,?,?)",
                (asset_id, scope, key, state, initial_lifecycle, seen, seen),
            )
    con.execute(
        "UPDATE assets SET first_seen_us=MIN(first_seen_us,?), last_seen_us=MAX(last_seen_us,?) WHERE asset_id=?",
        (seen, seen, asset_id),
    )
    return asset_id


def _address(con, asset_id: str, scope: str, ip: str, seen: int, event_id: str,
             state: str, mac: str | None = None, hostname: str | None = None) -> str:
    address_id = stable_id("address", asset_id, scope, ip)
    con.execute(
        "INSERT INTO addresses(address_id,asset_id,scope,ip,mac,hostname,association_state,first_seen_us,last_seen_us) "
        "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id,scope,ip) DO UPDATE SET "
        "mac=COALESCE(excluded.mac,mac), hostname=COALESCE(excluded.hostname,hostname), "
        "association_state=CASE WHEN excluded.association_state='assigned' THEN 'assigned' "
        "WHEN association_state='requested' THEN excluded.association_state ELSE association_state END, "
        "first_seen_us=MIN(first_seen_us,excluded.first_seen_us), "
        "last_seen_us=MAX(last_seen_us,excluded.last_seen_us)",
        (address_id, asset_id, scope, ip, mac, hostname, state, seen, seen),
    )
    add_change(con, "address", address_id, event_id, "observed", seen, {
        "asset_id": asset_id, "scope": scope, "ip": ip, "state": state,
    })
    return address_id


def _merge_asset(con, source_id: str, target_id: str, event_id: str, seen: int,
                 ip: str, mac: str) -> None:
    source = con.execute(
        "SELECT first_seen_us,last_seen_us FROM assets WHERE asset_id=?", (source_id,)
    ).fetchone()
    con.execute(
        "UPDATE assets SET first_seen_us=MIN(first_seen_us,?), last_seen_us=MAX(last_seen_us,?) "
        "WHERE asset_id=?",
        (source[0], source[1], target_id),
    )
    con.execute(
        "DELETE FROM addresses WHERE asset_id=? AND EXISTS ("
        "SELECT 1 FROM addresses a WHERE a.asset_id=? AND a.scope=addresses.scope AND a.ip=addresses.ip)",
        (source_id, target_id),
    )
    con.execute("UPDATE addresses SET asset_id=? WHERE asset_id=?", (target_id, source_id))
    con.execute(
        "DELETE FROM services WHERE asset_id=? AND EXISTS ("
        "SELECT 1 FROM services s WHERE s.asset_id=? AND s.scope=services.scope AND s.ip=services.ip "
        "AND s.port=services.port AND s.transport=services.transport)",
        (source_id, target_id),
    )
    con.execute("UPDATE services SET asset_id=? WHERE asset_id=?", (target_id, source_id))
    con.execute("UPDATE software_claims SET asset_id=? WHERE asset_id=?", (target_id, source_id))
    con.execute(
        "UPDATE interactions SET source_asset_id=CASE WHEN source_asset_id=? THEN ? ELSE source_asset_id END, "
        "target_asset_id=CASE WHEN target_asset_id=? THEN ? ELSE target_asset_id END "
        "WHERE source_asset_id=? OR target_asset_id=?",
        (source_id, target_id, source_id, target_id, source_id, source_id),
    )
    con.execute("UPDATE evidence SET subject_id=? WHERE subject_id=?", (target_id, source_id))
    con.execute("DELETE FROM assets WHERE asset_id=?", (source_id,))
    add_change(con, "asset", target_id, event_id, "identity_merged", seen, {
        "from_asset_id": source_id, "to_asset_id": target_id, "ip": ip, "mac": mac,
    })


def _reconcile_assignment(con, target_id: str, scope: str, ip: str, mac: str,
                          seen: int, event_id: str) -> str:
    row = con.execute(
        "SELECT a.asset_id,a.first_seen_us,a.last_seen_us FROM assets a "
        "JOIN addresses x ON x.asset_id=a.asset_id "
        "WHERE a.scope=? AND a.identity_key=? AND a.identity_state='provisional' "
        "AND x.scope=? AND x.ip=? AND x.association_state!='requested' LIMIT 1",
        (scope, _identity_key(ip=ip), scope, ip),
    ).fetchone()
    if not row or row["asset_id"] == target_id:
        return target_id
    prior_state = con.execute(
        "SELECT 1 FROM services WHERE asset_id=? AND first_seen_us < ? "
        "UNION ALL SELECT 1 FROM software_claims WHERE asset_id=? AND first_seen_us < ? "
        "UNION ALL SELECT 1 FROM interactions WHERE (source_asset_id=? OR target_asset_id=?) "
        "AND observed_at_us < ? LIMIT 1",
        (row["asset_id"], seen, row["asset_id"], seen, row["asset_id"], row["asset_id"], seen),
    ).fetchone()
    compatible = (row["first_seen_us"] <= seen + IDENTITY_WINDOW_US and
                  row["last_seen_us"] >= seen - IDENTITY_WINDOW_US and not prior_state)
    if compatible:
        _merge_asset(con, row["asset_id"], target_id, event_id, seen, ip, mac)
    else:
        add_change(con, "asset", target_id, event_id, "identity_conflict", seen, {
            "candidate_asset_id": row["asset_id"], "ip": ip, "mac": mac,
            "reason": "incompatible_assignment_context",
        })
    return target_id


def _communication_id(con, obs: dict, rule: dict, outcome: str) -> tuple[str, bool]:
    seen = obs["observed_at_us"]
    rows = con.execute(
        "SELECT DISTINCT i.communication_id FROM interactions i "
        "JOIN events e ON e.event_id=i.event_id "
        "WHERE e.probe_id!=? AND i.source_ip IS ? AND i.target_ip IS ? "
        "AND i.source_port IS ? AND i.target_port IS ? AND i.transport=? "
        "AND i.protocol IS ? AND i.outcome=? "
        "AND i.observed_at_us BETWEEN ? AND ? "
        "AND NOT EXISTS (SELECT 1 FROM interactions s JOIN events se ON se.event_id=s.event_id "
        "WHERE s.communication_id=i.communication_id AND se.probe_id=?) "
        "ORDER BY ABS(i.observed_at_us-?) LIMIT 2",
        (obs["probe_id"], rule["source_ip"], rule["target_ip"], rule["source_port"],
         rule["target_port"], rule["transport"], rule["protocol"], outcome,
         seen - CORRELATION_WINDOW_US, seen + CORRELATION_WINDOW_US, obs["probe_id"], seen),
    ).fetchall()
    if len(rows) == 1:
        return rows[0][0], True
    return stable_id("communication", obs["event_id"]), False


def _connection(con, obs: dict) -> None:
    data = obs["data"]
    rule = connection_rule(data)
    source_scope = scope_for(rule["source_ip"])
    target_scope = scope_for(rule["target_ip"])
    scope = source_scope if usable_ip(rule["source_ip"]) else target_scope
    source_id = target_id = None
    if usable_ip(rule["source_ip"]):
        source_id = _ensure_asset(con, source_scope, _identity_key(ip=rule["source_ip"]), "provisional",
                                  obs["observed_at_us"], rule["source_ip"])
        _address(con, source_id, source_scope, rule["source_ip"], obs["observed_at_us"], obs["event_id"], "source_observed")
        add_change(con, "asset", source_id, obs["event_id"], "observed", obs["observed_at_us"],
                   {"role": "source", "ip": rule["source_ip"]})
    if usable_ip(rule["target_ip"]):
        if rule["responder_seen"]:
            target_id = _ensure_asset(con, target_scope, _identity_key(ip=rule["target_ip"]), "provisional",
                                      obs["observed_at_us"], rule["target_ip"])
            _address(con, target_id, target_scope, rule["target_ip"], obs["observed_at_us"], obs["event_id"],
                     "responder_observed")
            add_change(con, "asset", target_id, obs["event_id"], "observed", obs["observed_at_us"],
                       {"role": "responder", "ip": rule["target_ip"]})
    outcome = "response_observed" if rule["responder_seen"] else "target_contact_only"
    communication_id, correlated = _communication_id(con, obs, rule, outcome)
    claim = {"rule": rule, "communication_id": communication_id, "correlated_sighting": correlated}
    evidence_id = add_evidence(con, obs["event_id"], "connection", target_id, claim, obs["observed_at_us"])
    if rule["service_supported"] and target_id and rule["target_port"] is not None:
        service_id = stable_id("service", target_id, target_scope, rule["target_ip"], rule["target_port"], rule["transport"])
        con.execute(
            "INSERT INTO services(service_id,asset_id,scope,ip,port,transport,protocol,state,first_seen_us,last_seen_us) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id,scope,ip,port,transport) DO UPDATE SET "
            "protocol=COALESCE(excluded.protocol,protocol), state=excluded.state, "
            "first_seen_us=MIN(first_seen_us,excluded.first_seen_us), last_seen_us=MAX(last_seen_us,excluded.last_seen_us)",
            (service_id, target_id, target_scope, rule["target_ip"], rule["target_port"], rule["transport"],
             rule["protocol"], rule["service_state"], obs["observed_at_us"], obs["observed_at_us"]),
        )
        add_change(con, "service", service_id, obs["event_id"], "observed", obs["observed_at_us"],
                   {"asset_id": target_id, "ip": rule["target_ip"], "port": rule["target_port"],
                    "protocol": rule["protocol"], "state": rule["service_state"]})
    interaction_id = stable_id("interaction", obs["event_id"])
    con.execute(
        "INSERT OR IGNORE INTO interactions(interaction_id,communication_id,event_id,evidence_id,scope,source_asset_id,target_asset_id,"
        "source_ip,target_ip,source_port,target_port,transport,protocol,outcome,observed_at_us) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (interaction_id, communication_id, obs["event_id"], evidence_id, scope, source_id, target_id, rule["source_ip"],
         rule["target_ip"], rule["source_port"], rule["target_port"], rule["transport"], rule["protocol"],
         outcome, obs["observed_at_us"]),
    )
    add_change(con, "interaction", interaction_id, obs["event_id"], "observed", obs["observed_at_us"],
               {"outcome": outcome, "communication_id": communication_id,
                "correlated_sighting": correlated})


def _dhcp(con, obs: dict) -> None:
    data = obs["data"]
    rule = dhcp_rule(data)
    ip = rule["assigned_ip"]
    key = _identity_key(ip=ip or rule["requested_ip"], mac=rule["mac"])
    if rule["mac"] or ip:
        asset_id = _ensure_asset(
            con, rule["scope"], key, "identified" if rule["mac"] else "provisional",
            obs["observed_at_us"], ip, initial_lifecycle="dormant"
        )
        if rule["mac"] and ip and usable_ip(ip):
            asset_id = _reconcile_assignment(con, asset_id, rule["scope"], ip, rule["mac"],
                                             obs["observed_at_us"], obs["event_id"])
    else:
        asset_id = None
    evidence_id = add_evidence(con, obs["event_id"], "dhcp", asset_id, {"rule": rule}, obs["observed_at_us"])
    if asset_id:
        add_change(con, "asset", asset_id, obs["event_id"], "dhcp_observed", obs["observed_at_us"],
                   {"mac": rule["mac"], "assigned_ip": ip, "requested_ip": rule["requested_ip"]})
        if ip and usable_ip(ip):
            _address(con, asset_id, rule["scope"], ip, obs["observed_at_us"], obs["event_id"], "assigned",
                     rule["mac"], rule["hostname"])
        elif rule["requested_ip"] and usable_ip(rule["requested_ip"]) and rule["mac"]:
            _address(con, asset_id, rule["scope"], rule["requested_ip"], obs["observed_at_us"], obs["event_id"],
                     "requested", rule["mac"], rule["hostname"])
    add_change(con, "evidence", evidence_id, obs["event_id"], "recorded", obs["observed_at_us"],
               {"kind": "dhcp", "asset_id": asset_id})


def _compatible_service(con, asset_id: str, scope: str, ip: str, port: int,
                        protocol: str | None) -> str | None:
    rows = con.execute(
        "SELECT service_id, protocol FROM services WHERE asset_id=? AND scope=? AND ip=? AND port=?",
        (asset_id, scope, ip, port),
    ).fetchall()
    compatible = [
        row[0] for row in rows
        if not protocol or not row[1] or protocol in row[1].split(",")
    ]
    return compatible[0] if len(compatible) == 1 else None


def _software(con, obs: dict) -> None:
    data = obs["data"]
    rule = software_rule(data)
    ip = rule["ip"]
    scope = scope_for(ip)
    asset_id = None
    if usable_ip(ip):
        asset_id = _ensure_asset(con, scope, _identity_key(ip=ip), "provisional", obs["observed_at_us"], ip)
        _address(con, asset_id, scope, ip, obs["observed_at_us"], obs["event_id"], "software_observed")
    evidence_id = add_evidence(con, obs["event_id"], "software", asset_id, {"rule": rule}, obs["observed_at_us"])
    if asset_id:
        version_json = json.dumps(rule["version"], sort_keys=True) if rule["version"] is not None else ""
        name = rule["name"] or ""
        raw = rule["unparsed_version"] or ""
        port = rule["port"] if rule["port"] is not None else -1
        claim_id = stable_id("software", asset_id, scope, ip, port, rule["role"], rule["software_type"], name,
                             version_json, raw)
        con.execute(
            "INSERT INTO software_claims(claim_id,asset_id,scope,ip,port,role,software_type,name,version_json,"
            "raw_version,attribution,first_seen_us,last_seen_us) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(claim_id) DO UPDATE SET last_seen_us=MAX(last_seen_us,excluded.last_seen_us)",
            (claim_id, asset_id, scope, ip, port, rule["role"], rule["software_type"], name, version_json, raw,
             rule["attribution"], obs["observed_at_us"], obs["observed_at_us"]),
        )
        add_change(con, "software", claim_id, obs["event_id"], "observed", obs["observed_at_us"], {
            "asset_id": asset_id, "ip": ip, "port": None if port == -1 else port,
            "role": rule["role"], "name": rule["name"], "version": rule["version"],
            "unparsed_version": rule["unparsed_version"], "attribution": rule["attribution"],
        })
        if rule["role"] in {"server", "application_server"} and port != -1:
            protocol = rule["software_type"].split("::", 1)[0].lower() or None
            service_id = _compatible_service(con, asset_id, scope, ip, port, protocol)
            if service_id:
                add_change(con, "service", service_id, obs["event_id"], "software_observed",
                           obs["observed_at_us"], {
                               "asset_id": asset_id, "ip": ip, "port": port,
                               "software_evidence": evidence_id, "software_claim_id": claim_id,
                           })
    else:
        add_change(con, "evidence", evidence_id, obs["event_id"], "recorded", obs["observed_at_us"],
                   {"kind": "software", "asset_id": None})


def _process_one(con, obs: dict) -> str:
    if not insert_event(con, obs):
        return "duplicate"
    if obs["event_type"] not in SUPPORTED_TYPES:
        error = f"unsupported event type: {obs['event_type']}"
        finish_event(con, obs["event_id"], "unsupported", error)
        add_change(con, "event", obs["event_id"], obs["event_id"], "unsupported", obs["observed_at_us"], {"error": error})
        return "unsupported"
    if obs["_decode_error"]:
        error = f"invalid Module 4 JSON: {obs['_decode_error']}"
        finish_event(con, obs["event_id"], "failed", error)
        add_change(con, "event", obs["event_id"], obs["event_id"], "failed", obs["observed_at_us"], {"error": error})
        return "failed"
    try:
        {"network_connection": _connection, "dhcp_observation": _dhcp,
         "software_observation": _software}[obs["event_type"]](con, obs)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        error = f"observation interpretation failed: {exc}"
        finish_event(con, obs["event_id"], "failed", error)
        add_change(con, "event", obs["event_id"], obs["event_id"], "failed", obs["observed_at_us"], {"error": error})
        return "failed"
    finish_event(con, obs["event_id"], "processed")
    return "processed"


def run(module4_path: str, state_path: str, batch_size: int = 500) -> dict:
    """Process all currently available observations in producer sequence order."""
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    source = connect_module4(module4_path)
    state = connect_state(state_path)
    counts = {"processed": 0, "duplicate": 0, "unsupported": 0, "failed": 0}
    try:
        while True:
            after = get_cursor(state)
            batch = read_batch(source, after, batch_size)
            if not batch:
                break
            with transaction(state):
                for obs in batch:
                    counts[_process_one(state, obs)] += 1
                save_cursor(state, batch[-1]["sequence"])
    finally:
        source.close()
        state.close()
    return counts


def maintain(state_path: str, now_us: int | None = None,
             dormant_after_us: int = DEFAULT_DORMANT_AFTER_US,
             expired_after_us: int = DEFAULT_EXPIRED_AFTER_US) -> dict:
    """Apply explicit lifecycle policy using observation times, not ingest time."""
    if dormant_after_us < 1 or expired_after_us <= dormant_after_us:
        raise ValueError("lifecycle thresholds must be positive and ordered")
    now_us = time.time_ns() // 1000 if now_us is None else now_us
    state = connect_state(state_path)
    checked = changed = 0
    try:
        with transaction(state):
            rows = state.execute(
                "SELECT a.*, "
                "(SELECT MAX(i.observed_at_us) FROM interactions i "
                " WHERE i.source_asset_id=a.asset_id OR i.target_asset_id=a.asset_id) AS interaction_seen_us, "
                "(SELECT MAX(s.last_seen_us) FROM services s WHERE s.asset_id=a.asset_id) AS service_seen_us, "
                "(SELECT MAX(c.last_seen_us) FROM software_claims c WHERE c.asset_id=a.asset_id) AS software_seen_us "
                "FROM assets a ORDER BY a.asset_id"
            ).fetchall()
            transitions = []
            for asset in rows:
                checked += 1
                activity_us = max(
                    asset["interaction_seen_us"] or 0,
                    asset["service_seen_us"] or 0,
                    asset["software_seen_us"] or 0,
                ) or None
                reference_us = activity_us or asset["first_seen_us"]
                age_us = max(0, now_us - reference_us)
                if activity_us is None:
                    desired = "expired" if age_us >= expired_after_us else "dormant"
                elif age_us < dormant_after_us:
                    desired = "active"
                else:
                    desired = "expired" if age_us >= expired_after_us else "dormant"
                if desired != asset["lifecycle_state"]:
                    transitions.append((asset, desired, activity_us))
            if transitions:
                event_id = stable_id("maintenance", now_us, dormant_after_us, expired_after_us)
                observed_at = datetime.fromtimestamp(
                    now_us / 1_000_000, tz=timezone.utc
                ).isoformat(timespec="microseconds").replace("+00:00", "Z")
                state.execute(
                    "INSERT OR IGNORE INTO events(sequence,event_id,event_type,probe_id,observed_at_us,observed_at,"
                    "data_json,quality_flags_json,provenance_json,disposition) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (-int(event_id[:15], 16), event_id, "lifecycle_maintenance", "module5", now_us,
                     observed_at, json.dumps({"dormant_after_us": dormant_after_us,
                                              "expired_after_us": expired_after_us}, sort_keys=True), "[]",
                     json.dumps({"source_id": "module5", "log_type": "lifecycle_maintenance",
                                 "operation": "maintenance"}, sort_keys=True), "processed"),
                )
                for asset, desired, activity_us in transitions:
                    state.execute(
                        "UPDATE assets SET lifecycle_state=? WHERE asset_id=?",
                        (desired, asset["asset_id"]),
                    )
                    add_change(
                        state, "asset", asset["asset_id"], event_id, "lifecycle_changed", now_us,
                        {"from": asset["lifecycle_state"], "to": desired,
                         "last_seen_us": asset["last_seen_us"], "activity_us": activity_us,
                         "evaluated_at_us": now_us, "dormant_after_us": dormant_after_us,
                         "expired_after_us": expired_after_us},
                    )
                changed = len(transitions)
    finally:
        state.close()
    return {"checked": checked, "changed": changed}
