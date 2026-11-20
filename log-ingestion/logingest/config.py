"""Load and check the TOML config file that lists the log sources."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

LOG_TYPES = ("conn", "dhcp")


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Source:
    """One log file Module 4 follows, e.g. probe1's conn.log."""

    probe_id: str
    log_type: str
    path: Path
    include_archive: bool = True

    @property
    def source_id(self) -> str:
        return f"{self.probe_id}:{self.log_type}"

    def archive_files(self) -> list[tuple[str, Path]]:
        """Old copies moved aside by the probe start script: <dir>/archive/<run>/<name>."""
        if not self.include_archive:
            return []
        root = self.path.parent / "archive"
        if not root.is_dir():
            return []
        found = []
        for f in sorted(root.glob(f"*/{self.path.name}")):
            if f.is_file():
                found.append((f"{self.source_id}:archive/{f.parent.name}", f))
        return found


@dataclass(frozen=True)
class Config:
    database: Path
    sources: tuple[Source, ...]
    poll_interval: float = 1.0
    read_chunk_bytes: int = 1_048_576


def load_config(path: str | Path) -> Config:
    path = Path(path).resolve()
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None

    base = path.parent

    def resolve(p: str) -> Path:
        q = Path(p).expanduser()
        return q if q.is_absolute() else (base / q).resolve()

    if "database" not in raw:
        raise ConfigError("config needs `database = \"...\"`")

    sources = []
    seen_ids, seen_paths = set(), set()
    for i, s in enumerate(raw.get("sources", [])):
        try:
            src = Source(
                probe_id=str(s["probe_id"]).strip(),
                log_type=str(s["log_type"]).strip(),
                path=resolve(s["path"]),
                include_archive=bool(s.get("include_archive", True)),
            )
        except KeyError as e:
            raise ConfigError(f"sources[{i}] is missing {e}") from None
        if not src.probe_id or ":" in src.probe_id:
            raise ConfigError(f"sources[{i}]: probe_id must be non-empty and contain no ':'")
        if src.log_type not in LOG_TYPES:
            raise ConfigError(f"sources[{i}]: log_type must be one of {LOG_TYPES}, got {src.log_type!r}")
        if src.source_id in seen_ids:
            raise ConfigError(f"sources[{i}]: duplicate source {src.source_id}")
        if src.path in seen_paths:
            raise ConfigError(f"sources[{i}]: path used twice: {src.path}")
        seen_ids.add(src.source_id)
        seen_paths.add(src.path)
        sources.append(src)

    if not sources:
        raise ConfigError("config has no [[sources]]")

    cfg = Config(
        database=resolve(raw["database"]),
        sources=tuple(sources),
        poll_interval=float(raw.get("poll_interval", 1.0)),
        read_chunk_bytes=int(raw.get("read_chunk_bytes", 1_048_576)),
    )
    if cfg.poll_interval <= 0 or cfg.read_chunk_bytes < 4096:
        raise ConfigError("poll_interval must be > 0 and read_chunk_bytes >= 4096")
    return cfg
