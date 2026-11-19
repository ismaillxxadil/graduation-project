# Traffic Generator (NOTLINE Module 02)

Makes the lab hosts talk like a small company: browsing the website, DNS
lookups, SSH, file shares, IoT DHCP, plus deliberate attempts the firewall must
block. Every run is **repeatable** (same seed = same timetable) and writes a
**ledger** of exactly what was attempted, for Module 11 to compare against Zeek.

Design and research: [PLAN.md](PLAN.md).

## Quick start

```bash
cd traffic-generator
pip install -r requirements.txt            # only PyYAML
bash ../network/verify-lab.sh              # lab must pass first

python3 -m trafficgen run scenarios/smoke.yaml --check     # 3 min test + Zeek check
python3 -m trafficgen run scenarios/baseline.yaml          # 30 min normal workday
```

| Command | What it does |
|---|---|
| `python3 -m trafficgen plan <scenario> [--out plan.jsonl]` | Make the timetable only. No traffic. |
| `python3 -m trafficgen run <scenario> [--check]` | Check the lab, generate traffic, write the ledger. `--check` compares with Zeek afterwards (waits 75 s for Zeek to write). |
| `python3 -m trafficgen check runs/<run_id>` | Compare a finished run with the Zeek logs again. |
| `--seed N`, `--duration S` | Override the scenario's seed or length. |

Stop a run with Ctrl+C. The ledger keeps what was done, and `run.json` says `interrupted`.

## How it works

1. **Scenario file** (`scenarios/*.yaml`): which hosts are active, how often
   (events per hour), which activities they pick (weights), and fixed
   blocked attempts.
2. **Planner**: turns the seed into a timetable. Each host is a random
   (Poisson) process with its own seeded stream. Same seed, same plan.
3. **Preflight**: refuses to run if a host is down, has no lab IP, would send
   traffic out of the management interface (`eth0`), or lacks a tool.
4. **Executor**: at each planned time, runs a real client in the container
   (`docker exec pc1 wget ...`), one thread per host.
5. **Ledger**: one JSON line per action, with real start/end times and result.
6. **Check**: finds each action in the Zeek logs. HTTP by its User-Agent
   marker `NOTLINE/<run_id>/<seq>`, DHCP in `dhcp.log`, everything else in
   `conn.log` by addresses, port and time.

## Activities

| Activity | From | To | Notes |
|---|---|---|---|
| `http_home` | pc | web1:80 | home page |
| `http_api` | pc | web1:80 → app1:3000 | `/api/health` or `/api/users` |
| `http_search` | pc | web1 → app1 → db1:5432 | full 3-tier chain |
| `dns_lookup` | pc, iot | dhcp1:53 | lab names only, no fake names |
| `ssh_handshake` | pc1 | srv1:22 | handshake only; login is refused (no password sent) |
| `smb_list` | pc1 | files1:445 | lists the guest share |
| `dhcp_renew` | pc, iot | dhcp1:67 | one full DHCP exchange |
| `blocked_probe` | any | any port | `nc -z`; must be **blocked** by r1 |

Only pc1 has `ssh` and `smbclient`. The preflight stops you if a scenario asks
another host to use them.

## Output: `runs/<run_id>/`

| File | Content |
|---|---|
| `plan.jsonl` | The timetable (made before running). |
| `ledger.jsonl` | One line per action: times, src/dst IP and port, command, `expected` (allowed/blocked), `result` (success/blocked/failed/timeout), `as_expected`, which probes should see it. |
| `run.json` | Manifest: scenario + SHA-256, seed, git commit, Python version, host IPs at start, result counts, status. |
| `check.json` | Result of the Zeek comparison (after `--check` or `check`). |

> The ledger is **ground truth for Module 11 only**. Never feed it to Modules 04/05 as discovered data.

## Tests

```bash
python3 -m unittest discover -s tests      # 14 tests, no Docker needed
```

Verified on the live lab (2026-11-19), `smoke.yaml`: 59/59 actions as
expected, and Zeek matched 115/115 expected observations with no firewall leaks.

## Known limits

- Zeek 7.0.5 has no PostgreSQL analyzer, so app1 → db1 is only in `conn.log`.
- Zeek writes `dhcp.log` up to about a minute late. Wait before `check`.
- pc2 and the IoT devices have only BusyBox tools (no ssh/smb clients).
- IoT VLAN 40 is isolated: IoT can only reach dhcp1.
