"""Run planned actions at their planned times, one worker thread per source host.

One thread per host keeps each host's actions in order (like one person
doing one thing at a time) while different hosts act in parallel.
"""

from __future__ import annotations

import threading
import time

from . import activities
from .labstate import docker_exec
from .ledger import RunWriter
from .planner import PlannedAction

COMMAND_TIMEOUT_S = 30


def _run_one(a: PlannedAction, writer: RunWriter, src_ip: str, t0: float) -> None:
    marker = f"NOTLINE/{writer.run_id}/{a.seq}"
    command = a.spec.command.replace(activities.MARKER, marker)
    ts_start = time.time()
    code, out = docker_exec(a.src_host, command, timeout=COMMAND_TIMEOUT_S)
    ts_end = time.time()
    result = activities.classify(a.spec, code, out)
    as_expected = (result == "blocked") if a.spec.expected == "blocked" else (result == "success")
    row = {
        "run_id": writer.run_id,
        "seq": a.seq,
        "planned_ts": round(t0 + a.at_s, 6),
        "ts_start": round(ts_start, 6),
        "ts_end": round(ts_end, 6),
        "src_host": a.src_host,
        "src_ip": src_ip,
        "dst_host": a.spec.dst_host,
        "dst_ip": a.spec.dst_ip,
        "proto": a.spec.proto,
        "dst_port": a.spec.dst_port,
        "service": a.spec.service,
        "activity": a.spec.activity,
        "detail": a.spec.detail,
        "command": command,
        "expected": a.spec.expected,
        "exit_code": code,
        "result": result,
        "as_expected": as_expected,
        "expected_visibility": activities.expected_visibility(a.src_host, a.spec),
    }
    if a.spec.service == "http":
        row["marker"] = {"http_user_agent": marker}
    if not as_expected:
        row["output_tail"] = out.strip()[-300:]
    writer.record(row)
    flag = "ok " if as_expected else "!! "
    print(f"  {flag}#{a.seq:<4} +{a.at_s:7.1f}s {a.src_host:>5} {a.spec.activity:<14} "
          f"-> {a.spec.dst_host}:{a.spec.dst_port} {result}", flush=True)


def _worker(actions: list[PlannedAction], writer: RunWriter, src_ip: str, t0: float,
            stop: threading.Event) -> None:
    for a in actions:
        delay = t0 + a.at_s - time.time()
        if delay > 0 and stop.wait(delay):
            return
        if stop.is_set():
            return
        _run_one(a, writer, src_ip, t0)


def execute(actions: list[PlannedAction], writer: RunWriter, host_ips: dict[str, str],
            t0: float) -> bool:
    """Run everything. Returns False if interrupted with Ctrl+C."""
    by_host: dict[str, list[PlannedAction]] = {}
    for a in actions:
        by_host.setdefault(a.src_host, []).append(a)
    stop = threading.Event()
    threads = [
        threading.Thread(target=_worker, args=(acts, writer, host_ips[h], t0, stop),
                         name=f"host-{h}", daemon=True)
        for h, acts in by_host.items()
    ]
    for t in threads:
        t.start()
    try:
        for t in threads:
            while t.is_alive():
                t.join(timeout=0.5)
    except KeyboardInterrupt:
        stop.set()
        for t in threads:
            t.join(timeout=COMMAND_TIMEOUT_S + 5)
        return False
    return True
