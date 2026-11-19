"""Write run outputs: plan.jsonl, ledger.jsonl and run.json.

The ledger is ground truth for Module 11 evaluation only. It must never be
fed to the discovery modules (04/05) as observed evidence.
"""

from __future__ import annotations

import json
import platform
import subprocess
import threading
import time
from pathlib import Path

from . import __version__
from .planner import PlannedAction
from .scenario import Scenario


def make_run_id(scenario: Scenario, now: float | None = None) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now or time.time()))
    return f"R{stamp}-s{scenario.seed}"


def _git_commit(path: Path) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def write_plan(path: Path, actions: list[PlannedAction]) -> None:
    with path.open("w") as f:
        for a in actions:
            f.write(json.dumps(a.to_dict(), sort_keys=True) + "\n")


class RunWriter:
    def __init__(self, runs_dir: Path, scenario: Scenario, actions: list[PlannedAction],
                 run_id: str | None = None):
        self.run_id = run_id or make_run_id(scenario)
        self.dir = runs_dir / self.run_id
        self.dir.mkdir(parents=True, exist_ok=False)
        self.scenario = scenario
        self.actions = actions
        self._lock = threading.Lock()
        self._ledger = (self.dir / "ledger.jsonl").open("a")
        self.counts: dict[str, int] = {}
        self.manifest: dict = {
            "run_id": self.run_id,
            "status": "running",
            "scenario": scenario.name,
            "scenario_path": scenario.path,
            "scenario_sha256": scenario.sha256,
            "seed": scenario.seed,
            "duration_s": scenario.duration_s,
            "planned_actions": len(actions),
            "generator_version": __version__,
            "python": platform.python_version(),
            "git_commit": _git_commit(Path(__file__).resolve().parent),
            "note": "Ground truth for Module 11 only. Do not feed to discovery.",
        }
        write_plan(self.dir / "plan.jsonl", actions)

    def start(self, t0: float, host_ips: dict[str, str]) -> None:
        self.manifest["started_at"] = t0
        self.manifest["host_ips_at_start"] = host_ips
        self._write_manifest()

    def record(self, row: dict) -> None:
        with self._lock:
            self._ledger.write(json.dumps(row, sort_keys=True) + "\n")
            self._ledger.flush()
            self.counts[row["result"]] = self.counts.get(row["result"], 0) + 1

    def finish(self, status: str) -> None:
        with self._lock:
            self._ledger.close()
            self.manifest.update(status=status, ended_at=time.time(), results=dict(self.counts))
            self._write_manifest()

    def _write_manifest(self) -> None:
        (self.dir / "run.json").write_text(json.dumps(self.manifest, indent=2, sort_keys=True) + "\n")
