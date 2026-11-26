# Module 5 Stage 3 contract

Module 5 consumes only the Observation v1 interface documented by
`log-ingestion/CONTRACT.md`. It does not import Module 4 code.

## Input

The reader opens `observations` using SQLite `mode=ro`, requires the documented
columns, and selects rows with `sequence > cursor ORDER BY sequence`. The
Module 4 database and its WAL files are never written by Module 5.

Supported event types are `network_connection`, `dhcp_observation`, and
`software_observation`. Every accepted source row is copied to `events`,
including its normalized data, quality flags, and provenance. Unsupported rows
are retained with an explicit `unsupported` disposition; malformed JSON is
retained with an explicit `failed` disposition.

## State

- `assets` uses a deterministic `mac:<address>` key when DHCP supplies a MAC;
  otherwise it uses `ip:<address>` and marks the identity `provisional`.
- `addresses` records `assigned`, `requested`, `source_observed`,
  `responder_observed`, or `software_observed` explicitly. A requested address
  is never treated as an assignment.
- `services` requires responder or successful-connection evidence; software
  observations attach to one compatible existing service and otherwise remain
  software claims. A port by itself never creates a service.
- `software_claims` preserves name, raw version, structured version, Zeek role,
  and attribution (`server_fingerprint`, `application_server_observation`, or
  `client_observation`).
- `interactions` retain one row per source event, including target-only
  connections. `communication_id` groups only strongly correlated cross-probe
  sightings; the source event and evidence remain separate.
- `evidence`, `events`, and `changes` preserve the source link and provenance.
- `changes` also exposes `processed_at_us` and an `entity_version`. The complete
  snapshot keeps serialized `payload_json`; the incremental helper exposes a
  decoded `payload` as well.

Confirmed DHCP assignments can merge a provisional IP asset into a MAC-backed
asset only when the scope and observation times are compatible and the older
asset has no prior service, software, or interaction state. Ambiguous reuse is
kept separate and recorded as an identity conflict.

All state writes for a batch and the cursor update are committed together.
The deterministic source-event and semantic keys make a replay harmless for
the same Module 4 sequence. Cross-probe correlation is deliberately limited to
matching endpoint tuples from different probes within 100 ms.

## Lifecycle

Lifecycle is separate from identity and address association. An explicit
`discovery.engine.maintain()` pass evaluates the newest interaction, service,
or software observation time for each asset. The default thresholds are one
hour without activity for `active -> dormant` and 24 hours for
`dormant -> expired`; both are configurable. An asset with only DHCP evidence
starts dormant because a lease is not proof that the device is online. A
target-only connection has no destination asset and therefore cannot make a
destination active. Maintenance never deletes evidence or moves historical
`first_seen_us`/`last_seen_us` values, and a late observation is evaluated by
its observation timestamp rather than its ingestion time. Repeated maintenance
with no state transition emits no new change.

Maintenance transitions are represented by a synthetic `events` row with
`event_type=lifecycle_maintenance` and a corresponding `asset` change whose
action is `lifecycle_changed`. These are Module 5 provenance records and do
not advance the Module 4 cursor.

## Export

`discovery.export.snapshot()` returns a JSON-compatible complete snapshot.
`discovery.export.changes()` returns ordered rows after a `change_id`. Both
exports read Module 5 state read-only.

Each snapshot also contains `change_watermark`, the greatest `change_id`
included in that same snapshot, or `0` when there are no changes. The snapshot
is read inside one SQLite read transaction, so every exported row and the
watermark describe one committed state. The watermark is append-only and
monotonic; the producer cursor is exported separately as `cursor`.

### Module 6 synchronization

Module 6 must bootstrap or reconcile its graph from the complete snapshot. It
persists `change_watermark` only after the graph synchronization succeeds. If a
later snapshot has a greater watermark, Module 6 reads that complete snapshot,
reconciles stable identities, changed rows, removed rows, merged identities,
and expired lifecycle states, then commits the new watermark. Repeating the
same snapshot is idempotent and restart-safe.

The compact `changes` array and `discovery.export.changes()` helper are
optional indicators for diagnostics or deciding that a refresh is needed.
They are not an independent event-sourcing stream and must not be used to
reconstruct Module 5 state from an empty consumer.

The snapshot is current state, not a historical point-in-time view. It contains
stable assets, scoped addresses, supported services, software claims, evidence
and source events, raw sensor interaction sightings, their `communication_id`
groupings, and ordered changes. An `identity_merged` change has
`from_asset_id` and `to_asset_id` in its payload; an independent consumer
removes or redirects the former to the latter. The same change stream carries
identity conflicts and lifecycle transitions, so a consumer can apply
corrections without opening Module 4 or importing Module 5.
