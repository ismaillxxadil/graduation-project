# Module 5 — Asset discovery

This Stage 3 implementation is a small, independent consumer of the public
Module 4 SQLite contract. It reads Module 4 with SQLite read-only mode and
writes only to its own state database.

Run it from this directory:

```bash
PYTHONPATH=. python3 -m discovery.main \
  --module4 ../log-ingestion/data/notline.db \
  --state ./data/module5.db \
  --snapshot ./data/snapshot.json
```

The state database keeps accepted source events, evidence, provisional or
identified assets, address claims, services, software claims, interactions,
ordered changes, and the Module 5 sequence cursor. The JSON snapshot contains
the same facts and their provenance so a downstream consumer does not need to
open Module 4.

The implementation uses direct deterministic keys. MAC-backed DHCP evidence
identifies an asset; IP-only evidence creates a provisional asset. A successful
or protocol-bearing connection can create a service, while an unanswered
target remains target-only evidence. Software observations retain their raw
version and structured version without inference.

Cross-probe correlation is intentionally limited to strong endpoint/timing
matches.

Lifecycle maintenance is explicit and does not read Module 4:

```bash
PYTHONPATH=. python3 -m discovery.main \
  --state ./data/module5.db \
  --maintain \
  --snapshot ./data/snapshot.json
```

The default policy marks an asset dormant after one hour without an observed
interaction, service, or software observation and expired after 24 hours.
Use `--now-us`, `--dormant-after-seconds`, and `--expired-after-seconds` for a
repeatable evaluation. DHCP-only assets begin dormant; target-only traffic
does not make an unobserved destination active. Maintenance preserves all
evidence and emits an ordered lifecycle change only when state changes.

The snapshot is current state rather than a point-in-time historical snapshot.
It includes a monotonic `change_watermark` captured in the same committed read
as the exported rows. Module 6 should import the complete snapshot, reconcile
its graph by stable IDs, and persist that watermark only after synchronization
succeeds. A later greater watermark requires another complete snapshot;
repeating a snapshot is safe.

Incremental changes remain useful as optional refresh indicators and include
`processed_at_us`, `entity_version`, identity correction payloads, lifecycle
transitions, and communication IDs. They are not sufficient to reconstruct
Module 5 state from an empty consumer.
