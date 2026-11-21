"""NOTLINE Module 4: Zeek log ingestion.

Reads Zeek JSON logs (conn, dhcp, software) from the probes, normalizes each line into an
Observation v1 record and stores it in SQLite. Module 5 reads the stored rows by
`sequence` (see CONTRACT.md). Standard library only; no imports from other modules.
"""

SCHEMA_VERSION = 1
__version__ = "1.0.0"
