"""Stable IDs.

event_id is built from what Zeek wrote (the raw line), never from our own
normalized output. So fixing a normalizer bug or re-reading a file can never
create a duplicate, and the two probes never collide.
"""

import hashlib


def event_id(probe_id: str, log_type: str, raw_sha256: str) -> str:
    return hashlib.sha256(f"{probe_id}|{log_type}|{raw_sha256}".encode()).hexdigest()
