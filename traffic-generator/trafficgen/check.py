"""Smoke check: did the Zeek probes see what the ledger says we did?

This is a quick sanity check for the generator, not the Module 11 evaluation.
Matching rules (strongest first):
  http  -> exact User-Agent marker in http.log
  dhcp  -> dhcp.log record for the client's address in the time window
  other -> conn.log record with same proto/src/dst/port in the time window
Blocked attempts must be seen ONLY by the source-side probe.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

PROBE_DIRS = {"probe1": "probe-logs", "probe2": "probe2-logs"}
WINDOW_BEFORE_S = 2.0
WINDOW_AFTER_S = 5.0


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    with path.open(errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def _load_logs(network_dir: Path) -> dict[str, dict[str, list[dict]]]:
    logs: dict[str, dict[str, list[dict]]] = {}
    for probe, sub in PROBE_DIRS.items():
        logs[probe] = {}
        for kind in ("conn", "http", "dhcp"):
            rows = []
            for p in sorted((network_dir / sub).glob(f"{kind}*.log")):
                rows.extend(_read_jsonl(p))
            logs[probe][kind] = rows
    return logs


def _in_window(rec: dict, row: dict) -> bool:
    ts = rec.get("ts", 0)
    return row["ts_start"] - WINDOW_BEFORE_S <= ts <= row["ts_end"] + WINDOW_AFTER_S


def _conn_match(conns, row, src, dst, port, proto) -> bool:
    return any(
        c.get("id.orig_h") == src and c.get("id.resp_h") == dst and c.get("id.resp_p") == port
        and c.get("proto") == proto and _in_window(c, row)
        for c in conns
    )


def _seen(probe_logs: dict[str, list[dict]], row: dict) -> bool:
    if row["service"] == "http":
        ua = row.get("marker", {}).get("http_user_agent")
        return any(h.get("user_agent") == ua for h in probe_logs["http"])
    if row["service"] == "dhcp":
        ip = row["src_ip"]
        return any((d.get("assigned_addr") == ip or d.get("client_addr") == ip) and _in_window(d, row)
                   for d in probe_logs["dhcp"])
    return _conn_match(probe_logs["conn"], row, row["src_ip"], row["dst_ip"], row["dst_port"], row["proto"])


HOPS = {
    "web1->app1:3000": ("10.10.20.20", "10.10.25.30", 3000),
    "app1->db1:5432": ("10.10.25.30", "10.10.30.10", 5432),
}


def run_check(run_dir: Path, network_dir: Path) -> dict:
    ledger = _read_jsonl(run_dir / "ledger.jsonl")
    logs = _load_logs(network_dir)
    stats = defaultdict(lambda: defaultdict(int))
    misses = []

    for row in ledger:
        act = row["activity"]
        s = stats[act]
        s["actions"] += 1
        s["as_expected"] += bool(row["as_expected"])
        if row["result"] != "success" and row["expected"] == "allowed":
            continue  # nothing to look for if the service did not work
        vis = row["expected_visibility"]
        for probe in PROBE_DIRS:
            seen = _seen(logs[probe], row)
            if probe in vis:
                s[f"{probe}_expected"] += 1
                s[f"{probe}_seen"] += seen
                if not seen:
                    misses.append({"seq": row["seq"], "activity": act, "probe": probe, "why": "not found in logs"})
            elif row["expected"] == "blocked" and seen:
                s["leaks"] += 1
                misses.append({"seq": row["seq"], "activity": act, "probe": probe,
                               "why": "blocked attempt visible past the firewall"})
        for hop in row.get("detail", {}).get("downstream", []):
            src, dst, port = HOPS[hop]
            s["hops_expected"] += 1
            if _conn_match(logs["probe1"]["conn"], row, src, dst, port, "tcp"):
                s["hops_seen"] += 1
            else:
                misses.append({"seq": row["seq"], "activity": act, "probe": "probe1", "why": f"hop {hop} not found"})

    report = {"run_id": run_dir.name, "actions": len(ledger),
              "by_activity": {k: dict(v) for k, v in sorted(stats.items())}, "misses": misses}
    (run_dir / "check.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def print_report(report: dict) -> bool:
    print(f"\nCheck for {report['run_id']} ({report['actions']} actions)")
    head = f"  {'activity':<14} {'done':>9} {'probe1 saw':>11} {'probe2 saw':>11} {'app hops':>9} {'leaks':>6}"
    print(head)
    print("  " + "-" * (len(head) - 2))

    def frac(s, key):
        exp = s.get(f"{key}_expected", 0)
        return f"{s.get(f'{key}_seen', 0)}/{exp}" if exp else "-"

    total_exp = total_seen = 0
    for act, s in report["by_activity"].items():
        print(f"  {act:<14} {s['as_expected']:>4}/{s['actions']:<4} {frac(s, 'probe1'):>11} "
              f"{frac(s, 'probe2'):>11} {frac(s, 'hops'):>9} {s.get('leaks', 0):>6}")
        for k in ("probe1", "probe2", "hops"):
            total_exp += s.get(f"{k}_expected", 0)
            total_seen += s.get(f"{k}_seen", 0)
    ok = not report["misses"] and all(s["as_expected"] == s["actions"] for s in report["by_activity"].values())
    print(f"\n  Zeek matched {total_seen}/{total_exp} expected observations; "
          f"{len(report['misses'])} problem(s).")
    for m in report["misses"][:15]:
        print(f"    #{m['seq']} {m['activity']} on {m['probe']}: {m['why']}")
    if len(report["misses"]) > 15:
        print(f"    ... {len(report['misses']) - 15} more in check.json")
    return ok
