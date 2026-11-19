# Module 02 — Traffic Generator: Research Decision and Build Plan

> Status: **v0.1 built and verified on the live lab (2026-11-19)**, see README.md. Handbook numbering: this is **Module 02**
> ("Makes hosts talk"). Zeek probes are Module 03, log ingestion is Module 04.

## 1. The job in one paragraph

With no traffic, Zeek has nothing to record. The freshly started lab proves it:
the probes logged only IPv6 background noise and one DHCP request, and no
WEB1/APP1/DB1/SSH/SMB activity. The traffic generator makes the lab hosts act
like a small company. Users browse the website, look up names, open SSH and
file shares, IoT devices check in now and then, and someone sometimes tries a
path the firewall blocks. It does this **repeatably** (same seed, same plan) and
writes down **exactly what it tried and when** (the *ledger*). Module 11 can then
compare what Zeek saw against what really happened.

```
scenario.yaml + seed ─► [plan] ─► plan.jsonl ─► [run] ─► real packets on sw1/sw2 ─► Zeek (M03) ─► M04
                                                     └──► ledger.jsonl + run.json ───────────────► M11
```

## 2. Decision

| Option | Verdict | Why |
|---|---|---|
| **Python orchestrator + `docker exec` of real clients** (YAML scenario, seeded schedule, JSONL ledger) | **CHOSEN** | Real sessions against real servers through the real firewall. No new infrastructure. Seed + plan file make runs reproducible. The ledger is built in. |
| Bash script with `docker exec` (like the old `generate_lab_traffic.sh`) | REJECTED as final, used as reference | Same real traffic, but randomness, reproducibility and the ledger get brittle in bash. |
| Scapy | LATER (edge cases only) | Crafted packets: no real server responses, half-sessions in Zeek. Only for malformed/spoofed tests. |
| iperf3 | LATER (optional) | Only bulk "unknown service" flows in conn.log. Useful as a "backup transfer" noise source. |
| tcpreplay / TRex / Ostinato / D-ITG | REJECTED | Replayed packets never reach real servers, need IP rewriting, results aren't genuine firewall outcomes. TRex needs DPDK. Ostinato's Containerlab edition is paid. |
| CMU SEI GHOSTS | REJECTED (ideas reused) | .NET client + API + Postgres + UI, built for Windows/Ubuntu desktops. Too heavy for Alpine. Its RNG is unseeded, so runs can't be reproduced. |
| DetGen (re-runnable Docker scenarios) | Ideas reused | Closest in spirit, but built around its own compose networks, not Containerlab. |

What we copy from the literature:
- **LARIAT (MIT LL):** per-service session arrival rates, optionally shaped by time of day.
- **CIC-IDS2017:** per-user behaviour profiles; label flows by time + src/dst IP.
- **UNSW-NB15:** ship a ground-truth file next to the data.

Source links are in §12.

## 3. Lab facts that shape the design (checked on the running lab, 2026-11-19)

| Fact | Consequence |
|---|---|
| OVS mirrors and VLAN tags only take effect at the **end** of `start-lab.sh` (sudo steps). Before that, sw2 is flat and the probes see only broadcast. | The generator must not start until `network/verify-lab.sh` passes (it checks probe visibility). Fixed and verified on 2026-11-19: 42/42 checks pass. |
| IoT VLAN 40 is isolated: r1 has no VLAN 40 interface. Docker's eth0 default route used to leak IoT traffic to the management network (now removed at boot). | IoT activities can only target dhcp1 (DHCP/DNS) or a future broker inside VLAN 40. |
| pc1 had no lab IP for ~14 min after boot (stuck in `apk add` before DHCP). files1 was still installing Samba. | Runtime installs make startup slow and nondeterministic. Bake tools into images. The preflight must wait until each host is ready. |
| nginx listens only on :80, although the firewall allows :443. db1 has no app tables. | `tls_home` needs TLS on web1 first. `http_api` exercises the DB only through `/api/users/search`. |
| Only pc1 had `ssh`/`smbclient` installed (via `apk add` at boot). pc2/iot have only BusyBox `wget`, `nslookup`, `nc`. | Bake tools into a **client image**. After boot the hosts have no internet, and installing at runtime adds noise. |
| Zeek is **7.0.5**: no PostgreSQL analyzer (verified: `base/protocols/` has none). Added in 7.1. | APP1→DB1 shows up **only in conn.log** unless Module 03 upgrades Zeek or adds the `spicy-postgresql` package. |
| probe2 mirrors **sw1** (users VLAN 10); probe1 mirrors **sw2** (servers/app/db/mgmt/IoT). | A routed PC→WEB1 request is seen **by both probes** (once per side of r1). The ledger must say which probe should see what. |
| Firewall = default DROP, so blocked attempts show as `conn_state=S0` on the source side and nothing on the far side. | Expected-visibility rules can be computed per probe. |
| Containers share the host clock. | Ledger and Zeek timestamps line up. A ±2 s match window is enough. |

**Precondition the generator enforces:** before each run it checks that every
source host has a lab IP and that `ip route get <dst>` leaves through **eth1**. If
not, it refuses to start and says why.

## 4. Inputs and outputs (contract)

### Input: `scenarios/<name>.yaml`

```yaml
scenario: baseline-v1
seed: 42
duration_s: 1800          # 30 min run
hosts:
  pc1:  { tier: frequent }
  pc2:  { tier: normal }
  iot1: { tier: rare }
  iot2: { tier: quiet }   # appears once per run at most -> tests discovery limits
tiers:                    # mean events per hour (Poisson)
  frequent: 120
  normal: 40
  quiet: 2
  rare: 0.5
activities:               # weights pick WHICH activity a host does
  pc1:  { http_home: 4, http_api: 3, dns_lookup: 3, smb_list: 1, ssh_login: 1 }
  pc2:  { http_home: 3, http_api: 2, dns_lookup: 2 }
  iot1: { dhcp_renew: 1, dns_lookup: 1 }
blocked_probes:           # deliberate denied attempts, fixed times
  - { at_s: 600,  src: pc1, dst: db1,  port: 5432 }
  - { at_s: 1200, src: pc2, dst: app1, port: 3000 }
```

### Output 1: `runs/<run_id>/plan.jsonl`
The full schedule, computed from the seed **before** anything runs. Same seed
gives a byte-identical plan.

### Output 2: `runs/<run_id>/ledger.jsonl` (one line per attempted action)

```json
{"run_id":"R20261119T2100Z-s42","seq":17,"planned_ts":1795201234.0,
 "ts_start":1795201234.112,"ts_end":1795201234.398,
 "src_host":"pc1","src_ip":"10.10.10.101","dst_host":"web1","dst_ip":"10.10.20.20",
 "proto":"tcp","dst_port":80,"service":"http","activity":"http_api",
 "command":"wget -qO- -U NOTLINE/R20261119T2100Z-s42/17 http://10.10.20.20/api/health",
 "expected":"allowed","exit_code":0,"result":"success",
 "marker":{"http_user_agent":"NOTLINE/R20261119T2100Z-s42/17"},
 "expected_visibility":{"probe1":["conn","http"],"probe2":["conn","http"]}}
```

```json
{"run_id":"R20261119T2100Z-s42","seq":31,"ts_start":1795201834.0,"ts_end":1795201837.0,
 "src_host":"pc1","src_ip":"10.10.10.101","dst_host":"db1","dst_ip":"10.10.30.10",
 "proto":"tcp","dst_port":5432,"service":"postgresql","activity":"blocked_probe",
 "expected":"blocked","exit_code":1,"result":"timeout",
 "expected_visibility":{"probe2":["conn:S0"],"probe1":[]}}
```

`result` ∈ `success | refused | timeout | error`. `expected` ∈ `allowed | blocked`.
A blocked attempt that **succeeds** is a firewall finding and gets flagged.

### Output 3: `runs/<run_id>/run.json` (run manifest)
Contains: run_id, scenario name + SHA-256, seed, git commit, Python version,
planned/actual start and end, host IP map snapshot (taken from the hosts at
start, **for evaluation only**), and counts by result.

> Ground-truth rule from the handbook: the ledger and manifest go to **Module 11
> only**. They must never be fed into Module 04/05 as "discovered" data.

## 5. Activity catalogue (v1)

| Activity | Source → Destination | Command (inside source) | Expected Zeek logs | Seen by |
|---|---|---|---|---|
| `http_home` | pc → web1:80 | `wget -U <marker> http://frontend.enterprise.local/` | conn, http, files | probe2 + probe1 |
| `http_api` | pc → web1:80 → app1:3000 → db1:5432 | `wget -U <marker> http://10.10.20.20/api/users` | conn, http (+ app1→web1 hop, + conn to db1 on 7.0.5) | both |
| `dns_lookup` | pc → dhcp1:53 | `nslookup app.enterprise.local 10.10.10.2` | conn, dns | probe2 |
| `ssh_login` | pc → srv1:22 | `sshpass`-free key login or `ssh -o BatchMode=yes … true` (handshake only) | conn, ssh | both |
| `smb_list` | pc → files1:445 | `smbclient -N //10.10.35.40/shared -c ls` | conn, smb_mapping, (ntlm, dce_rpc) | both |
| `dhcp_renew` | pc/iot → dhcp1 | `kill -USR1 $(pidof udhcpc)` (BusyBox renew — verify) | dhcp, conn | probe of that VLAN |
| `blocked_probe` | any → disallowed port | `nc -w 3 -z <ip> <port>` | conn S0 (source side only) | source-side probe |
| *later:* `mqtt_publish` | iot → broker in VLAN 40 | `mosquitto_pub …` | mqtt_* | probe1 |
| *later:* `tls_home` | pc → web1:443 | `wget https://…` (needs TLS on nginx) | ssl, x509 | both |

`http_api` is valuable because one user request creates the full
**PC→WEB1→APP1→DB1** chain. That's the path Modules 6–10 reason about.

## 6. Timing model (realistic but reproducible)

- One `random.Random(seed)`, never the global RNG. Same seed means the same plan.
- For each host, draw the gaps between events from an exponential distribution
  with mean `3600 / tier_rate` (a Poisson process). Then pick the activity by its weight.
- **Quiet** and **rare** tiers exist so Module 11 can measure "how long until
  discovery sees this device" and "what does passive discovery miss".
- Optional later: a time-of-day curve (LARIAT-style), compressed so one run hour = one "day".
- Executor: runs actions at their planned time with a small thread pool (one
  worker per source host). It records **actual** start/end times, because `docker exec` adds delay.

## 7. Correlating ledger ↔ Zeek (so evaluation can prove an event happened)

Strongest to weakest:
1. **HTTP User-Agent marker** `NOTLINE/<run>/<seq>` → appears in `http.log.user_agent`. Exact match.
2. **Fixed source port** where the client allows it (`nc -p`, or ssh through
   `ProxyCommand="nc -p PORT %h %p"`). Then (src, sport, dst, dport) is unique.
3. **Community ID**: Module 03 adds `@load policy/protocols/conn/community-id-logging`.
   The generator computes the same hash once it knows the 5-tuple.
4. **Fallback:** (src_ip, dst_ip, dst_port, proto) within [ts_start−2 s, ts_end+2 s].

We **do not** put fake marker names into DNS queries. Module 05 would
"discover" names that don't exist.

## 8. Code layout (target ≈ 400–600 lines + tests)

```
traffic-generator/
  PLAN.md
  pyproject.toml            # deps: PyYAML only (docker CLI via subprocess)
  trafficgen/
    scenario.py   # load + validate YAML (hosts exist, tiers known, ports valid)
    planner.py    # seed -> list[PlannedAction]  (pure function, no Docker)
    activities.py # activity name -> (command, proto, port, expected_logs)
    labstate.py   # preflight: containers up, eth1 IP, `ip route get` via eth1, tools present
    executor.py   # docker exec with timeout; returns exit code + timings
    ledger.py     # append-only JSONL writer + run.json manifest
    cli.py        # trafficgen plan | run | check
  scenarios/baseline-v1.yaml, quiet-host.yaml, blocked-paths.yaml
  client-image/Dockerfile   # alpine + wget/curl, openssh-client, samba-client, bind-tools, mosquitto-clients
  tests/
  runs/                     # git-ignored outputs
```

CLI:
```bash
python -m trafficgen plan  scenarios/baseline-v1.yaml          # writes plan.jsonl only
python -m trafficgen run   scenarios/baseline-v1.yaml          # preflight -> execute -> ledger
python -m trafficgen check runs/<run_id>                       # quick sanity: ledger vs conn.log counts
```
`check` is a smoke test only. Real precision/recall belongs to Module 11.

## 9. Build order (each step ends with a passing test)

| # | Step | Done when |
|---|---|---|
| 0 | **Fix Module 01 blockers**: pc1 lease/route, IoT VLAN 40 + routing decision, client image with tools | Preflight passes for pc1, pc2 (and iot if in scope) |
| 1 | `scenario.py` + `planner.py` (no Docker) | Same seed → identical `plan.jsonl`; different seed → different |
| 2 | `labstate.py` preflight | Refuses to run when a host routes via eth0 or lacks a tool |
| 3 | `executor.py` + `activities.py` for http/dns | One `http_home` appears in both probes' http.log with the marker |
| 4 | `ledger.py` + `run.json` | Every planned action has exactly one ledger row, even on failure |
| 5 | ssh, smb, dhcp_renew, blocked_probe | Each produces the expected log type; blocked shows S0 and never succeeds |
| 6 | `check` command + 3 scenarios | 30-min baseline run: ≥95% of `allowed` actions matched in conn.log |
| 7 | (Module 03 asks) community-id, `Site::local_nets`, Zeek ≥7.1 or PG package | `community_id` in conn.log; known_services populated |
| 8 | Later: MQTT/IoT broker, TLS, iperf3 noise, time-of-day curve | Only if Module 05/11 need them |

## 10. Tests (handbook: 3 normal + ≥2 failure/unknown)

Normal:
1. Determinism: plan twice with seed 42 → identical files.
2. HTTP marker round-trip: run 1 action → `http.log` contains the exact User-Agent.
3. Full chain: one `http_api` → conn records pc→web1:80, web1→app1:3000, app1→db1:5432.

Failure / unknown:
4. Blocked path: pc1→db1:5432 → ledger `timeout`, Zeek `S0` on probe2, nothing on probe1.
5. Broken host: stop a container or remove the eth1 route → preflight refuses; no partial run.
6. Server down: stop nginx → ledger `refused`, run continues, other actions unaffected.
7. Quiet host: a `quiet` host with 0 events in the run → absent from Zeek, and the ledger shows why.

## 11. Noise that downstream modules should ignore (hand to Module 04)

- IPv6 router/neighbour discovery (ICMPv6 134/135/136, `ff02::*`) and mDNS 5353 from container kernels.
- Anything on eth0 / 172.20.20.0/24. It's management, not mirrored, so it should never appear.
- Package installs at boot. They go away once tools are baked into the client image.
- Retries: one ledger action may produce several conn records (e.g. DNS retry, TCP SYN retransmit).

## 12. Open questions for the team

1. **IoT:** give VLAN 40 a router interface on r1 (so IoT can reach DNS/MQTT across subnets), or keep IoT isolated and add an MQTT broker inside VLAN 40?
2. **Zeek version** (Module 03): upgrade to ≥7.1 for `postgresql.log`, add the Spicy package, or accept conn-only for DB traffic?
3. **Run length** for experiments: 30 min, 1 h, or longer for quiet-device discovery curves?
4. Should **pc2** get SSH/SMB too, or stay a "web-only" user (a more realistic mix)?

## 13. Sources

- Docker SDK for Python `exec_run`: https://docker-py.readthedocs.io/en/stable/containers.html
- Python `random` reproducibility: https://docs.python.org/3/library/random.html
- LARIAT (2002): https://archive.ll.mit.edu/ideval/files/2002_IEEE_Aero_LARIAT.pdf
- CIC-IDS2017 paper §3.2 (B-Profile): https://www.scitepress.org/Papers/2018/66398/66398.pdf · dataset: https://www.unb.ca/cic/datasets/ids-2017.html
- UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- GHOSTS: https://github.com/cmu-sei/GHOSTS (unseeded jitter: `src/Ghosts.Domain/Code/Jitter.cs`)
- DetGen: https://github.com/detlearsom/detgen
- Scapy https://github.com/secdev/scapy · iperf3 https://github.com/esnet/iperf · tcpreplay/tcprewrite https://tcpreplay.appneta.com/wiki/tcprewrite · TRex https://github.com/cisco-system-traffic-generator/trex-core
- Zeek 7.0.5 default analyzers: https://github.com/zeek/zeek/blob/v7.0.5/scripts/base/init-default.zeek
- Zeek community-id policy: https://github.com/zeek/zeek/blob/v7.0.5/scripts/policy/protocols/conn/community-id-logging.zeek · spec https://github.com/corelight/community-id-spec
- Zeek conn_state meanings: https://github.com/zeek/zeek/blob/v7.0.5/scripts/base/protocols/conn/main.zeek
- Zeek 7.1 PostgreSQL analyzer: https://docs.zeek.org/en/lts/logs/postgresql.html · package for 7.0: https://github.com/awelzel/spicy-postgresql
- BusyBox `wget -U`, `nc -p`: https://busybox.net/downloads/BusyBox.html
