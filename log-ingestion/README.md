# Module 4: Zeek log ingestion

Module 4 reads the Zeek logs from both probes (`conn.log`, `dhcp.log`), checks
and normalizes every line, and stores it in SQLite. Module 5 then reads the new rows.

```
network/probe-logs/  conn.log dhcp.log  ─┐
network/probe2-logs/ conn.log dhcp.log  ─┤   every 1 s
   (+ archive/<run>/ copies)             │
                                         ▼
  read new full lines → parse → normalize → validate → event_id
                                         │   one SQLite transaction
                                         ▼
  data/notline.db:  observations │ rejected_records │ file_offsets │ consumer_cursors
                                         │
                                         ▼
  Module 5:  SELECT * FROM observations WHERE sequence > cursor ORDER BY sequence
```

- **One Zeek line becomes one row.** Good lines go to `observations`, bad ones go to `rejected_records` (with the reason).
- **Noise is flagged, not deleted.** IPv6 router messages, mDNS and broadcast DHCP get `quality_flags`.
- **Safe to stop at any time.** Rows and the read position are saved together, so after a crash it continues where it stopped, with no loss and no duplicates.
- **Independent.** Python standard library only. It imports nothing from the network
  lab or the traffic generator. It only reads log files (paths are set in `config.toml`) and
  writes one SQLite file. Module 5 only needs [CONTRACT.md](CONTRACT.md).

## Requirements

Python 3.11 or newer. Nothing to install.

## Run it

All commands are run from the `log-ingestion/` folder:

```bash
cd log-ingestion

python3 -m logingest run            # follow the logs, Ctrl+C to stop
python3 -m logingest run --once     # read everything new once, then exit
python3 -m logingest status         # counts per probe, rejects, flags, read positions
python3 -m logingest read --limit 3 # see rows exactly as Module 5 gets them (JSON)
python3 -m logingest rejects        # see rejected lines and why
```

The database is created automatically at `data/notline.db`. To start from zero,
stop the program and delete the `data/` folder. It is rebuilt from the logs, which
are still on disk.

Use another config: `python3 -m logingest -c my.toml run`, or set `LOGINGEST_CONFIG=my.toml`.

## Test it

```bash
python3 -m unittest discover -s tests      # 29 tests, about 10 s, no lab needed
```

The tests use real lines from both probes (`tests/fixtures/`). They cover bad JSON,
ICMP, noise flags, DHCP without an ACK, partial lines, a file truncated and rewritten,
a file deleted and recreated, a Zeek restart with the archive, the same flow seen by
both probes, a cursor reading rows in sequence order, and `kill -9` in the middle of a run.

## Files

| File | Job |
|---|---|
| `config.toml` | which log files to follow: `probe_id`, `log_type`, `path` |
| `logingest/config.py` | loads and checks the config |
| `logingest/reader.py` | reads only new, **complete** lines. Notices when a file was replaced (new inode, smaller size, or a different first line) and starts it again from 0 |
| `logingest/parse.py` | strict JSON: rejects bad UTF-8, duplicate keys, NaN, non-objects |
| `logingest/normalize.py` | Zeek names → our names (`id.orig_h` → `src_ip`), exact timestamps, canonical IPs, ICMP type/code, quality flags |
| `logingest/validate.py` | accept or reject, with the field and the reason |
| `logingest/identity.py` | `event_id = sha256(probe_id \| log_type \| sha256(raw line))` |
| `logingest/pipeline.py` | one line → one observation or one rejection (pure, easy to test) |
| `logingest/store.py` | SQLite schema, the one-transaction write, and the read/cursor API |
| `logingest/main.py` | the 1-second polling loop |
| `logingest/__main__.py` | the command line |
| `CONTRACT.md` | what Module 5 can rely on: tables, fields, flags, reject codes |

## Zeek restarts (network side)

Zeek empties its log files when it starts. So the probes are now started by
`network/config/start-zeek.sh`, which first moves the old logs into
`probe-logs/archive/<unix-time>/`. Module 4 reads those archive folders too. Lines it
already stored are recognized by `event_id` and skipped. This takes effect the next
time the lab is deployed (`bash start-lab.sh`).

## Not in this version

- Only `conn` and `dhcp` are ingested. Adding a log type means adding one
  `normalize_<type>` function, its required fields in `validate.py`, and a config entry.
- Matching against the Module 2 traffic-generator ledger is a separate step (plan step 8).
  It reads both files from outside and is not built into Module 4, so the modules stay independent.
