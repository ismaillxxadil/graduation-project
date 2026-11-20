"""Map a parsed Zeek record to the Observation v1 `data` fields.

Nothing is thrown away here. Problems with required fields are collected in
`problems` (validate.py turns them into a rejection). Problems with optional
fields set the value to None and add a quality flag. Noise (multicast,
link-local, broadcast, ...) is flagged, never filtered.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation

CONN_PROTOS = {"tcp", "udp", "icmp", "unknown_transport"}
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
MDNS_ADDRS = {ipaddress.ip_address("224.0.0.251"), ipaddress.ip_address("ff02::fb")}
LIMITED_BROADCAST = ipaddress.ip_address("255.255.255.255")

EVENT_TYPES = {"conn": "network_connection", "dhcp": "dhcp_observation"}

_MISSING = object()


@dataclass
class Normalized:
    event_type: str | None
    observed_at_us: int | None
    data: dict = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)
    problems: dict[str, str] = field(default_factory=dict)  # zeek field -> reason


# ---------- time helpers ----------

def us_to_iso(us: int) -> str:
    sec, frac = divmod(us, 1_000_000)
    dt = datetime.fromtimestamp(sec, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{frac:06d}Z"


def now_us() -> int:
    d = datetime.now(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (d.days * 86_400 + d.seconds) * 1_000_000 + d.microseconds


# ---------- value checkers: return (value, reason_or_None) ----------

def _is_int(v) -> bool:
    return type(v) is int  # bool is a subclass of int, so `isinstance` is not enough


def _is_number(v) -> bool:
    return _is_int(v) or (isinstance(v, Decimal) and v.is_finite())


def _ts_us(v):
    if not _is_number(v) or v < 0:
        return None, "must be a non-negative number"
    try:
        return int((Decimal(v) * 1_000_000).to_integral_value(ROUND_HALF_EVEN)), None
    except InvalidOperation:
        return None, "not a valid timestamp"


def _ip(v):
    if not isinstance(v, str):
        return None, "must be an IP address string"
    try:
        return ipaddress.ip_address(v), None
    except ValueError:
        return None, f"not a valid IP address: {v[:64]!r}"


def _int_range(v, lo, hi):
    if not _is_int(v) or not lo <= v <= hi:
        return None, f"must be an integer {lo}-{hi}"
    return v, None


def _count(v):
    return _int_range(v, 0, 2**63 - 1)


def _seconds(v):
    if not _is_number(v) or v < 0:
        return None, "must be a non-negative number"
    return float(v), None


def _bool(v):
    if type(v) is not bool:
        return None, "must be true/false"
    return v, None


def _str(v):
    if not isinstance(v, str) or not v:
        return None, "must be a non-empty string"
    return v, None


def _str_list(v):
    if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
        return None, "must be a non-empty list of strings"
    return list(v), None


class _Fields:
    """Small helper that records problems/flags while reading fields."""

    def __init__(self, rec: dict, out: Normalized):
        self.rec, self.out = rec, out

    def required(self, key, check, *args):
        v = self.rec.get(key, _MISSING)
        if v is _MISSING or v is None:
            self.out.problems[key] = "missing"
            return None
        val, why = check(v, *args)
        if why:
            self.out.problems[key] = why
        return val

    def strict_optional(self, key, check, *args):
        """Optional, but if present it must be valid (else the record is rejected)."""
        v = self.rec.get(key, _MISSING)
        if v is _MISSING or v is None:
            return None
        val, why = check(v, *args)
        if why:
            self.out.problems[key] = why
        return val

    def optional(self, key, check, *args):
        """Optional; a bad value becomes None plus a quality flag."""
        v = self.rec.get(key, _MISSING)
        if v is _MISSING or v is None:
            return None
        val, why = check(v, *args)
        if why:
            self.out.flags.append(f"invalid_optional:{key}")
            return None
        return val


# ---------- address noise flags ----------

def address_flags(ip, side: str) -> list[str]:
    if ip is None:
        return []
    flags = []
    # Check multicast first: Python calls ff02::fb and 224.0.0.251 "global".
    if ip in MDNS_ADDRS:
        flags.append("mdns")
    if ip.is_multicast:
        flags.append(f"{side}_multicast")
    elif ip == LIMITED_BROADCAST:
        flags.append(f"{side}_limited_broadcast")
    elif ip.is_unspecified:
        flags.append(f"{side}_unspecified")
    elif ip.is_loopback:
        flags.append(f"{side}_loopback")
    elif ip.is_link_local:
        flags.append(f"{side}_link_local")
    return flags


def _ipstr(ip):
    return None if ip is None else str(ip)


# ---------- conn.log ----------

def normalize_conn(rec: dict) -> Normalized:
    out = Normalized(EVENT_TYPES["conn"], None)
    f = _Fields(rec, out)

    out.observed_at_us = f.required("ts", _ts_us)
    uid = f.required("uid", _str)
    src = f.required("id.orig_h", _ip)
    dst = f.required("id.resp_h", _ip)
    proto = f.required("proto", _str)
    if proto is not None and proto not in CONN_PROTOS:
        out.problems["proto"] = f"must be one of {sorted(CONN_PROTOS)}"
        proto = None

    src_port = dst_port = icmp_type = icmp_code = None
    if proto == "icmp":
        # Zeek stores ICMP type/code in the port fields.
        icmp_type = f.required("id.orig_p", _int_range, 0, 255)
        icmp_code = f.required("id.resp_p", _int_range, 0, 255)
        out.flags.append("icmp_pseudo_ports")
    else:
        src_port = f.required("id.orig_p", _int_range, 0, 65535)
        dst_port = f.required("id.resp_p", _int_range, 0, 65535)

    service = f.optional("service", _str)
    conn_state = f.optional("conn_state", _str)
    history = f.optional("history", _str)
    missed = f.optional("missed_bytes", _count)

    out.data = {
        "zeek_uid": uid,
        "src_ip": _ipstr(src),
        "src_port": src_port,
        "dst_ip": _ipstr(dst),
        "dst_port": dst_port,
        "transport": proto,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "service_hints": [s for s in service.split(",") if s] if service else [],
        "conn_state": conn_state,
        "history": history,
        "duration_seconds": f.optional("duration", _seconds),
        "orig_bytes": f.optional("orig_bytes", _count),
        "resp_bytes": f.optional("resp_bytes", _count),
        "orig_ip_bytes": f.optional("orig_ip_bytes", _count),
        "resp_ip_bytes": f.optional("resp_ip_bytes", _count),
        "orig_pkts": f.optional("orig_pkts", _count),
        "resp_pkts": f.optional("resp_pkts", _count),
        "missed_bytes": missed,
        "local_orig": f.optional("local_orig", _bool),
        "local_resp": f.optional("local_resp", _bool),
    }

    out.flags += address_flags(src, "src") + address_flags(dst, "dst")
    if conn_state == "S0":
        out.flags.append("no_reply")
    if conn_state == "OTH" or (history and "^" in history):
        out.flags.append("partial")
    if missed:
        out.flags.append("missed_bytes")
    out.flags = sorted(set(out.flags))
    return out


# ---------- dhcp.log ----------

def _mac(v):
    if not isinstance(v, str):
        return None, "must be a MAC address string"
    m = v.strip().lower().replace("-", ":")
    if not MAC_RE.match(m):
        return None, f"not a valid MAC address: {v[:32]!r}"
    return m, None


def normalize_dhcp(rec: dict) -> Normalized:
    out = Normalized(EVENT_TYPES["dhcp"], None)
    f = _Fields(rec, out)

    out.observed_at_us = f.required("ts", _ts_us)
    uids = f.required("uids", _str_list)
    msg_types = f.required("msg_types", _str_list)
    client = f.strict_optional("client_addr", _ip)
    server = f.strict_optional("server_addr", _ip)
    requested = f.strict_optional("requested_addr", _ip)
    assigned = f.strict_optional("assigned_addr", _ip)  # never copied from requested_addr

    out.data = {
        "source_uids": sorted(set(uids)) if uids else None,  # Zeek sets have no order
        "client_ip": _ipstr(client),
        "server_ip": _ipstr(server),
        "client_mac": f.strict_optional("mac", _mac),
        "hostname": f.optional("host_name", _str),
        "client_fqdn": f.optional("client_fqdn", _str),
        "domain": f.optional("domain", _str),
        "requested_ip": _ipstr(requested),
        "assigned_ip": _ipstr(assigned),
        "lease_seconds": f.optional("lease_time", _seconds),
        "message_types": msg_types,  # arrival order kept
        "duration_seconds": f.optional("duration", _seconds),
    }

    if assigned is None:
        out.flags.append("no_assigned_ip")
    out.flags = sorted(set(out.flags))
    return out


NORMALIZERS = {"conn": normalize_conn, "dhcp": normalize_dhcp}


def normalize(log_type: str, rec: dict) -> Normalized:
    fn = NORMALIZERS.get(log_type)
    if fn is None:
        out = Normalized(None, None)
        out.problems["log_type"] = f"unknown log type {log_type!r}"
        return out
    return fn(rec)
