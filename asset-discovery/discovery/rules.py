"""Pure, conservative interpretations of Module 4 observation data."""

from __future__ import annotations

import ipaddress

SUPPORTED_TYPES = {"network_connection", "dhcp_observation", "software_observation"}


def usable_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local
                or ip == ipaddress.ip_address("255.255.255.255"))


def scope_for(value: str | None) -> str:
    if not value:
        return "unscoped"
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "unscoped"
    if ip.version == 4 and ip in ipaddress.ip_network("10.10.0.0/16"):
        return "lab"
    if ip.is_private:
        return "private"
    return "external"


def connection_rule(data: dict) -> dict:
    """Return endpoint roles without treating contact as a service."""
    state = data.get("conn_state")
    resp_pkts = data.get("resp_pkts") or 0
    resp_bytes = data.get("resp_bytes") or 0
    responder_seen = bool(resp_pkts or resp_bytes or state in {"SF", "S1", "S2", "S3"})
    hints = list(data.get("service_hints") or [])
    service_supported = responder_seen and bool(hints or state in {"SF", "S1", "S2", "S3"})
    return {
        "source_ip": data.get("src_ip"),
        "target_ip": data.get("dst_ip"),
        "source_port": data.get("src_port"),
        "target_port": data.get("dst_port"),
        "transport": data.get("transport") or "unknown_transport",
        "protocol": ",".join(hints) or None,
        "responder_seen": responder_seen,
        "target_only": not responder_seen,
        "service_supported": service_supported,
        "service_state": "protocol_observed" if hints else "response_observed",
    }


def dhcp_rule(data: dict) -> dict:
    """Keep requested and assigned addresses as separate claims."""
    assigned = data.get("assigned_ip")
    requested = data.get("requested_ip")
    return {
        "mac": data.get("client_mac"),
        "assigned_ip": assigned,
        "requested_ip": requested,
        "hostname": data.get("hostname") or data.get("client_fqdn"),
        "assigned": bool(assigned),
        "scope": scope_for(assigned or requested),
    }


def software_role(software_type: str | None) -> str:
    value = (software_type or "").upper()
    if "APPSERVER" in value:
        return "application_server"
    if "SERVER" in value:
        return "server"
    if "CLIENT" in value or "BROWSER" in value:
        return "client"
    return "unknown"


def software_rule(data: dict) -> dict:
    role = software_role(data.get("software_type"))
    attribution = {
        "server": "server_fingerprint",
        "application_server": "application_server_observation",
        "client": "client_observation",
        "unknown": "unclassified_observation",
    }[role]
    return {
        "ip": data.get("host_ip"),
        "port": data.get("host_port"),
        "software_type": data.get("software_type") or "",
        "role": role,
        "name": data.get("software_name"),
        "version": data.get("version"),
        "unparsed_version": data.get("unparsed_version"),
        "attribution": attribution,
    }
