# Module 4 → Module 5 contract (Observation v1)

Module 5 does **not** import any Module 4 code. The only thing the two modules
share is the SQLite file (`log-ingestion/data/notline.db` by default) and this
document. Any language that can open SQLite can be Module 5.

## How Module 5 reads

```sql
-- 1. where did I stop?
SELECT last_sequence FROM consumer_cursors WHERE consumer_id = 'module5';   -- no row = 0

-- 2. get the next batch, in sequence order (NOT ts order)
SELECT * FROM observations WHERE sequence > :cursor ORDER BY sequence LIMIT 500;

-- 3. after processing the batch, save the cursor (ideally in the same transaction
--    as Module 5's own writes, if they live in the same file)
INSERT INTO consumer_cursors (consumer_id, last_sequence, updated_at)
VALUES ('module5', :last_sequence_of_batch, :now)
ON CONFLICT(consumer_id) DO UPDATE SET last_sequence = excluded.last_sequence,
                                       updated_at   = excluded.updated_at;
```

Connection settings for the reader: `PRAGMA busy_timeout=5000;`. The database is in
WAL mode, so reading never blocks Module 4. Keep the `.db`, `-wal` and `-shm` files
together on a local disk.

Guarantees:
- `sequence` only goes up and is never reused, even after rows are deleted.
- Rows become visible in `sequence` order, so `sequence > cursor` never skips a row.
- The same Zeek line is stored once (`event_id` is UNIQUE).
- The same flow seen by **both probes** gives **two rows** (different `probe_id`).
  That's on purpose: they are two separate pieces of evidence.
- Zeek writes a connection when it ends, so `observed_at` is **not** in order.
  Use `sequence` for "what is new". Use `observed_at` for "when it happened".

To see the same thing from the shell: `python3 -m logingest read --after 0 --limit 5`.

## Table `observations` (one row per accepted Zeek line)

| Column | Type | Meaning |
|---|---|---|
| `sequence` | INTEGER PK AUTOINCREMENT | delivery order for Module 5 |
| `event_id` | TEXT UNIQUE | `sha256(probe_id \| log_type \| raw_sha256)` |
| `source_id` | TEXT | `probe1:conn`, or `probe1:conn:archive/<run>` for an archived file |
| `probe_id` | TEXT | `probe1` (sw2) or `probe2` (sw1), from the config, never guessed |
| `log_type` | TEXT | `conn`, `dhcp`, or `software` |
| `event_type` | TEXT | `network_connection`, `dhcp_observation`, or `software_observation` |
| `schema_version` | INTEGER | `1` |
| `observed_at_us` | INTEGER | Zeek `ts`, microseconds since 1970 (UTC), exact |
| `observed_at` | TEXT | same time, `2026-11-19T18:58:24.123456Z` |
| `ingested_at` | TEXT | when Module 4 stored it |
| `zeek_uid` | TEXT | conn only. Join key with other Zeek logs of the **same probe** |
| `src_ip` / `dst_ip` | TEXT | conn: originator/responder. dhcp: client_ip/server_ip. Indexed, for quick lookups |
| `data_json` | TEXT (JSON) | the normalized fields below |
| `quality_flags` | TEXT (JSON list) | see "Quality flags" |
| `raw_line` | TEXT | the original Zeek line, unchanged |
| `raw_sha256`, `path`, `byte_start`, `byte_end` | | where the line came from |

### `data_json` for `network_connection`

| Field | Type | Notes |
|---|---|---|
| `zeek_uid` | string | |
| `src_ip`, `dst_ip` | string | canonical form (IPv6 lower-case, compressed) |
| `src_port`, `dst_port` | int or null | null for ICMP |
| `transport` | string | `tcp`, `udp`, `icmp`, `unknown_transport` |
| `icmp_type`, `icmp_code` | int or null | only for ICMP (Zeek keeps them in the port fields) |
| `service_hints` | list of strings | Zeek's guess, e.g. `["http"]`. Empty list if unknown |
| `conn_state`, `history` | string or null | e.g. `SF`, `ShADadFf` |
| `duration_seconds` | float or null | Zeek omits it for one-packet connections |
| `orig_bytes`, `resp_bytes`, `orig_ip_bytes`, `resp_ip_bytes`, `orig_pkts`, `resp_pkts`, `missed_bytes` | int or null | |
| `local_orig`, `local_resp` | bool or null | |

### `data_json` for `dhcp_observation`

| Field | Type | Notes |
|---|---|---|
| `source_uids` | list of strings | sorted |
| `client_ip`, `server_ip` | string or null | |
| `client_mac` | string or null | lower-case, `aa:bb:cc:dd:ee:ff` |
| `requested_ip` | string or null | |
| `assigned_ip` | string or null | null if no ACK was seen (never copied from `requested_ip`) |
| `lease_seconds`, `duration_seconds` | float or null | |
| `message_types` | list of strings | in the order they were seen, e.g. `["DISCOVER","OFFER","REQUEST","ACK"]` |
| `hostname`, `client_fqdn`, `domain` | string or null | the lab's BusyBox clients send no hostname |

### `data_json` for `software_observation`

This is a normalized Zeek `Software::Info` record. The software log does not
carry a connection UID, so `zeek_uid` is null for this observation type. The
source probe and source log remain in the observation envelope and provenance.

| Field | Type | Notes |
|---|---|---|
| `host_ip` | string | canonical IP address where Zeek observed the software |
| `host_port` | int or null | service port when Zeek supplied one; often absent for client software |
| `software_type` | string or null | Zeek role, such as `SERVER`, `CLIENT`, `APPSERVER`, or `UNKNOWN` |
| `software_name` | string or null | Zeek's parsed software name; never inferred by Module 4 |
| `version` | object or null | only Zeek-provided `major`, `minor`, `minor2`, `minor3`, and `addl` components |
| `unparsed_version` | string or null | original version/banner string from Zeek |

## Quality flags

Module 4 flags noise but never drops it. Module 5 decides what to ignore.

| Flag | Meaning |
|---|---|
| `src_/dst_multicast` | e.g. `ff02::2`, `224.0.0.251` |
| `mdns` | to or from the mDNS address (`ff02::fb` / `224.0.0.251`) |
| `src_/dst_link_local` | `fe80::/10`, `169.254/16` |
| `src_/dst_unspecified` | `0.0.0.0`, `::` (e.g. a DHCP client before it has an IP) |
| `dst_limited_broadcast` | `255.255.255.255` |
| `src_/dst_loopback` | |
| `host_multicast`, `host_limited_broadcast`, `host_unspecified`, `host_loopback`, `host_link_local` | | address noise flags for software observations |
| `no_reply` | `conn_state = S0` (no answer seen) |
| `partial` | `conn_state = OTH` or `^` in history (Zeek saw only part of it) |
| `missed_bytes` | Zeek missed some bytes |
| `icmp_pseudo_ports` | ICMP: the ports were moved to `icmp_type`/`icmp_code` |
| `no_assigned_ip` | DHCP without an ACK |
| `invalid_optional:<field>` | an optional field had a bad value and was set to null |

## Table `rejected_records` (lines that were not accepted)

Bad lines are kept here with the reason, never silently dropped.

| `stage` / `error_code` | Meaning |
|---|---|
| `read` / `line_too_long` | one line bigger than `read_chunk_bytes` |
| `parse` / `invalid_utf8`, `invalid_json`, `duplicate_key`, `non_finite_number`, `not_object` | not valid JSON |
| `validate` / `missing_field` | a required field is missing (details list them) |
| `validate` / `invalid_field` | a required field has a bad value, or an optional IP/MAC is malformed |
| `validate` / `unknown_log_type` | the config names a log type Module 4 does not handle |
| `validate` / `contract_violation` | safety net: a required output field ended up empty |

Required fields: **conn** needs `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`
and `proto`. **dhcp** needs `ts`, `uids` and `msg_types`. **software** needs `ts` and `host`;
the version, name, role, and host port are optional because Zeek may not provide them.

## Changing the contract

Adding a new optional field in `data_json` keeps `schema_version = 1`. Renaming or
removing a field, or changing its meaning, means `schema_version = 2`, and Module 5
must be told first.
