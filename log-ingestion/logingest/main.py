"""The polling loop: for every source, read new lines -> process -> store, every second."""

from __future__ import annotations

import logging
import signal
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path

from . import store
from .config import Config, Source
from .normalize import now_us, us_to_iso
from .pipeline import process_line
from .reader import read_new_lines

log = logging.getLogger("logingest")


@dataclass
class Counters:
    lines: int = 0
    inserted: int = 0
    duplicates: int = 0
    rejected: int = 0
    new_files: int = 0
    per_source: dict = field(default_factory=dict)

    def add(self, source_id, lines, ins, dup, rej):
        self.lines += lines
        self.inserted += ins
        self.duplicates += dup
        self.rejected += rej
        s = self.per_source.setdefault(source_id, [0, 0, 0])
        s[0] += ins
        s[1] += dup
        s[2] += rej


class Ingestor:
    def __init__(self, cfg: Config, con: sqlite3.Connection | None = None):
        self.cfg = cfg
        self.con = con or store.connect(cfg.database)
        self.stop = threading.Event()
        self.totals = Counters()

    def _targets(self, src: Source) -> list[tuple[str, Path]]:
        # Old archived copies first (they are older), then the live file.
        return src.archive_files() + [(src.source_id, src.path)]

    def drain_file(self, src: Source, source_id: str, path: Path, counters: Counters) -> None:
        """Read one file until nothing new is left (one transaction per chunk)."""
        while not self.stop.is_set():
            saved = store.load_offset(self.con, source_id)
            res = read_new_lines(path, saved, self.cfg.read_chunk_bytes)
            if res is None:
                return  # file does not exist (yet)
            if res.new_generation:
                counters.new_files += 1
                log.warning("%s: file was replaced or truncated, reading it from the start", source_id)
            if saved is not None and res.state == saved:
                return  # nothing new

            now = us_to_iso(now_us())
            obs, rej = [], []
            for line in res.lines:
                kind, row = process_line(src.probe_id, src.log_type, source_id, str(path), line, now)
                (obs if kind == "observation" else rej).append(row)
            ins, dup, bad = store.store_batch(self.con, source_id, src.probe_id, src.log_type,
                                              res.state, obs, rej, now)
            counters.add(source_id, len(res.lines), ins, dup, bad)
            if ins or bad:
                log.info("%s: +%d observations, %d duplicates, %d rejected", source_id, ins, dup, bad)
            if not res.more:
                return

    def run_once(self) -> Counters:
        c = Counters()
        for src in self.cfg.sources:
            for source_id, path in self._targets(src):
                if self.stop.is_set():
                    return c
                try:
                    self.drain_file(src, source_id, path, c)
                except PermissionError as e:
                    log.error("%s: cannot read %s (%s)", source_id, path, e)
        for k in ("lines", "inserted", "duplicates", "rejected", "new_files"):
            setattr(self.totals, k, getattr(self.totals, k) + getattr(c, k))
        return c

    def run_forever(self) -> None:
        log.info("watching %d sources, writing to %s (Ctrl+C to stop)", len(self.cfg.sources), self.cfg.database)
        while not self.stop.is_set():
            self.run_once()
            self.stop.wait(self.cfg.poll_interval)
        log.info("stopped. this run: %d inserted, %d duplicates, %d rejected",
                 self.totals.inserted, self.totals.duplicates, self.totals.rejected)

    def install_signal_handlers(self) -> None:
        def handler(signum, _frame):
            log.info("got %s, finishing the current batch", signal.Signals(signum).name)
            self.stop.set()
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)
