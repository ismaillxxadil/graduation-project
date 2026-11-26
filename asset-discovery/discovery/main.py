"""Minimal command line entry point for Module 5 processing and maintenance."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import DEFAULT_DORMANT_AFTER_US, DEFAULT_EXPIRED_AFTER_US, maintain, run
from .export import write_snapshot


def main(argv: list[str] | None = None) -> int:
    project = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Process Module 4 observations into Module 5 state")
    parser.add_argument("--module4", default=str(project / "log-ingestion/data/notline.db"))
    parser.add_argument("--state", default=str(project / "asset-discovery/data/module5.db"))
    parser.add_argument("--snapshot", help="write a complete JSON snapshot after processing")
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--maintain", action="store_true", help="apply lifecycle policy without reading Module 4")
    parser.add_argument("--now-us", type=int, help="maintenance evaluation time in Unix microseconds")
    parser.add_argument("--dormant-after-seconds", type=int,
                        default=DEFAULT_DORMANT_AFTER_US // 1_000_000)
    parser.add_argument("--expired-after-seconds", type=int,
                        default=DEFAULT_EXPIRED_AFTER_US // 1_000_000)
    args = parser.parse_args(argv)
    if args.maintain:
        result = maintain(
            args.state, now_us=args.now_us,
            dormant_after_us=args.dormant_after_seconds * 1_000_000,
            expired_after_us=args.expired_after_seconds * 1_000_000,
        )
    else:
        result = run(args.module4, args.state, args.batch_size)
    if args.snapshot:
        write_snapshot(args.state, args.snapshot)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
