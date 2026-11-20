"""Read new, complete lines from a growing log file.

Remembers where it stopped (offset) and notices when the file was replaced:
a new inode, a smaller size, or a different first line all mean "new file,
start again from byte 0". A line without its final newline is left for the
next poll.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

HEAD_PROBE_BYTES = 65_536


@dataclass(frozen=True)
class FileState:
    path: str
    inode: int
    head_hash: str | None
    offset: int


@dataclass(frozen=True)
class Line:
    raw: bytes
    byte_start: int
    byte_end: int  # exclusive, newline not included
    oversize: bool = False


@dataclass(frozen=True)
class ReadResult:
    lines: list[Line]
    state: FileState
    new_generation: bool  # file was replaced/truncated (or seen for the first time)
    more: bool  # chunk was full: call again right away


def _head_hash(f) -> str | None:
    f.seek(0)
    head = f.read(HEAD_PROBE_BYTES)
    nl = head.find(b"\n")
    if nl == -1:
        return None
    return hashlib.sha256(head[:nl]).hexdigest()


def read_new_lines(path: str | Path, saved: FileState | None, chunk_bytes: int) -> ReadResult | None:
    """Return the complete lines added since `saved`, or None if the file does not exist."""
    try:
        f = open(path, "rb")
    except FileNotFoundError:
        return None
    with f:
        st = os.fstat(f.fileno())
        head = _head_hash(f)
        new_generation = (
            saved is None
            or saved.inode != st.st_ino
            or st.st_size < saved.offset
            or (saved.head_hash is not None and head != saved.head_hash)
        )
        start = 0 if new_generation else saved.offset

        f.seek(start)
        data = f.read(chunk_bytes)
        full_chunk = len(data) == chunk_bytes

        lines: list[Line] = []
        cut = data.rfind(b"\n")
        if cut == -1:
            if full_chunk:
                # One line longer than a whole chunk: hand it over as oversize and move on.
                lines.append(Line(data, start, start + len(data), oversize=True))
                consumed = len(data)
            else:
                consumed = 0  # partial line, wait for the rest
        else:
            consumed = cut + 1
            pos = 0
            while pos < consumed:
                nl = data.index(b"\n", pos)
                raw = data[pos:nl]
                if raw.endswith(b"\r"):
                    raw = raw[:-1]
                if raw.strip():
                    lines.append(Line(raw, start + pos, start + pos + len(raw)))
                pos = nl + 1

        if head is None and start + consumed > 0:
            head = _head_hash(f)

        state = FileState(str(path), st.st_ino, head, start + consumed)
        return ReadResult(lines, state, new_generation and saved is not None, full_chunk and consumed > 0)
