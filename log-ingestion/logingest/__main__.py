"""Command line:  python3 -m logingest <command> [options]

  init      create the database (safe to run again)
  run       follow the logs and store new lines (Ctrl+C to stop); --once = one pass then exit
  status    counts per probe/log type, rejects, flags, read positions
  read      print stored observations as JSON lines (what Module 5 receives)
  rejects   print rejected lines with the reason
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from . import store
from .config import ConfigError, load_config
from .main import Ingestor

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config.toml"


def _table(rows: list[dict], cols: list[str]) -> str:
    if not rows:
        return "  (none)"
    w = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    out = ["  " + "  ".join(c.ljust(w[c]) for c in cols)]
    out += ["  " + "  ".join(str(r.get(c, "")).ljust(w[c]) for c in cols) for r in rows]
    return "\n".join(out)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="logingest", description="NOTLINE Module 4: Zeek log ingestion")
    p.add_argument("-c", "--config", default=os.environ.get("LOGINGEST_CONFIG", DEFAULT_CONFIG),
                   help="config file (default: log-ingestion/config.toml or $LOGINGEST_CONFIG)")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create the database")
    r = sub.add_parser("run", help="follow the logs")
    r.add_argument("--once", action="store_true", help="read everything new once, then exit")
    sub.add_parser("status", help="show counts")
    rd = sub.add_parser("read", help="print observations as JSON lines")
    rd.add_argument("--after", type=int, default=0, help="only rows with sequence > AFTER")
    rd.add_argument("--limit", type=int, default=20)
    rj = sub.add_parser("rejects", help="print rejected lines")
    rj.add_argument("--limit", type=int, default=20)
    a = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    try:
        cfg = load_config(a.config)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    if a.cmd == "init":
        store.connect(cfg.database).close()
        print(f"database ready: {cfg.database}")
        return 0

    if a.cmd == "run":
        ing = Ingestor(cfg)
        if a.once:
            c = ing.run_once()
            print(f"lines read: {c.lines}  inserted: {c.inserted}  duplicates: {c.duplicates}  "
                  f"rejected: {c.rejected}  replaced files: {c.new_files}")
        else:
            ing.install_signal_handlers()
            ing.run_forever()
        return 0

    try:
        con = store.connect(cfg.database, create=False)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        return 1

    if a.cmd == "status":
        s = store.stats(con)
        print(f"database: {cfg.database}\n")
        print("observations:\n" + _table(s["observations"], ["probe_id", "log_type", "rows", "last_sequence"]))
        print("\nrejected:\n" + _table(s["rejected"], ["probe_id", "log_type", "stage", "error_code", "rows"]))
        print("\nquality flags:\n" + _table(s["flags"], ["flag", "rows"]))
        print("\nread positions:\n" + _table(s["offsets"], ["source_id", "offset", "updated_at"]))
        print("\nconsumers:\n" + _table(s["cursors"], ["consumer_id", "last_sequence", "updated_at"]))
    elif a.cmd == "read":
        for o in store.read_batch(con, a.after, a.limit):
            print(json.dumps(o))
    elif a.cmd == "rejects":
        for r in con.execute("SELECT id, probe_id, log_type, stage, error_code, error_details_json, raw_line "
                             "FROM rejected_records ORDER BY id DESC LIMIT ?", (a.limit,)):
            print(f"#{r['id']} {r['probe_id']}:{r['log_type']} {r['stage']}/{r['error_code']} "
                  f"{r['error_details_json']}\n    {r['raw_line'][:200]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
