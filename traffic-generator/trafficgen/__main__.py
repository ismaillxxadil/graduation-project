"""Command line: python -m trafficgen plan|run|check ..."""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from pathlib import Path

from . import check as checker
from . import executor, labstate, ledger, planner, scenario

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUNS = ROOT / "runs"
DEFAULT_NETWORK = ROOT.parent / "network"


def _load(args) -> tuple[scenario.Scenario, list[planner.PlannedAction]]:
    sc = scenario.load(args.scenario)
    if args.seed is not None or args.duration is not None:
        sc = scenario.Scenario(sc.name, args.seed if args.seed is not None else sc.seed,
                               args.duration or sc.duration_s, sc.hosts, sc.blocked, sc.sha256, sc.path)
    return sc, planner.plan(sc)


def _summary(sc, actions) -> None:
    print(f"Scenario '{sc.name}': seed={sc.seed}, duration={sc.duration_s:.0f}s, {len(actions)} actions")
    for (host, act), n in sorted(Counter((a.src_host, a.spec.activity) for a in actions).items()):
        print(f"  {host:>5}  {act:<14} x{n}")


def cmd_plan(args) -> int:
    sc, actions = _load(args)
    _summary(sc, actions)
    out = Path(args.out)
    ledger.write_plan(out, actions)
    print(f"Plan written to {out}")
    return 0


def cmd_run(args) -> int:
    sc, actions = _load(args)
    _summary(sc, actions)
    if not actions:
        print("Nothing to do.")
        return 1

    print("\nPreflight: checking the lab...")
    state = labstate.check(actions)
    if not state.ok:
        print("Lab is not ready, refusing to run:")
        for p in state.problems:
            print(f"  - {p}")
        print("Tip: run `bash network/verify-lab.sh` and wait for hosts to finish booting.")
        return 2
    print("  ok: " + ", ".join(f"{h}={ip}" for h, ip in sorted(state.host_ips.items())))

    writer = ledger.RunWriter(Path(args.runs_dir), sc, actions)
    t0 = time.time() + 2
    writer.start(t0, state.host_ips)
    print(f"\nRun {writer.run_id} -> {writer.dir}\n")
    finished = executor.execute(actions, writer, state.host_ips, t0)
    writer.finish("completed" if finished else "interrupted")
    print(f"\nRun {'completed' if finished else 'INTERRUPTED'}: {writer.counts}")
    print(f"Ledger: {writer.dir / 'ledger.jsonl'}")

    if args.check and finished:
        print(f"\nWaiting {args.settle}s for Zeek to write its logs...")
        time.sleep(args.settle)
        return 0 if checker.print_report(checker.run_check(writer.dir, Path(args.network_dir))) else 3
    return 0 if finished else 130


def cmd_check(args) -> int:
    run_dir = Path(args.run_dir)
    if not (run_dir / "ledger.jsonl").exists():
        print(f"No ledger.jsonl in {run_dir}")
        return 2
    return 0 if checker.print_report(checker.run_check(run_dir, Path(args.network_dir))) else 3


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="trafficgen", description="NOTLINE Module 02 traffic generator")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("scenario", help="scenario YAML file")
        sp.add_argument("--seed", type=int, help="override the scenario seed")
        sp.add_argument("--duration", type=float, help="override duration_s (seconds)")

    sp = sub.add_parser("plan", help="make the timetable only (no traffic)")
    common(sp)
    sp.add_argument("--out", default="plan.jsonl")
    sp.set_defaults(func=cmd_plan)

    sp = sub.add_parser("run", help="preflight, generate traffic, write the ledger")
    common(sp)
    sp.add_argument("--runs-dir", default=str(DEFAULT_RUNS))
    sp.add_argument("--network-dir", default=str(DEFAULT_NETWORK))
    sp.add_argument("--check", action="store_true", help="compare with Zeek logs after the run")
    sp.add_argument("--settle", type=int, default=75, help="seconds to wait before --check")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("check", help="compare a finished run's ledger with the Zeek logs")
    sp.add_argument("run_dir")
    sp.add_argument("--network-dir", default=str(DEFAULT_NETWORK))
    sp.set_defaults(func=cmd_check)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except scenario.ScenarioError as e:
        print(f"Scenario error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
