"""Load and validate a scenario YAML file."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import lab
from .activities import CATALOGUE


class ScenarioError(ValueError):
    pass


@dataclass(frozen=True)
class HostProfile:
    name: str
    events_per_hour: float
    activities: dict[str, float]  # activity name -> weight


@dataclass(frozen=True)
class BlockedAttempt:
    at_s: float
    src: str
    dst: str
    port: int


@dataclass(frozen=True)
class Scenario:
    name: str
    seed: int
    duration_s: float
    hosts: tuple[HostProfile, ...]
    blocked: tuple[BlockedAttempt, ...]
    sha256: str
    path: str


def load(path: str | Path) -> Scenario:
    path = Path(path)
    raw = path.read_bytes()
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ScenarioError(f"{path}: invalid YAML: {e}") from e
    if not isinstance(data, dict):
        raise ScenarioError(f"{path}: top level must be a mapping")
    return _parse(data, hashlib.sha256(raw).hexdigest(), str(path))


def _need(d: dict, key: str, where: str):
    if key not in d:
        raise ScenarioError(f"{where}: missing '{key}'")
    return d[key]


def _parse(data: dict, sha: str, path: str) -> Scenario:
    name = str(_need(data, "scenario", "scenario"))
    seed = _need(data, "seed", name)
    if not isinstance(seed, int):
        raise ScenarioError(f"{name}: seed must be an integer")
    duration = float(_need(data, "duration_s", name))
    if duration <= 0:
        raise ScenarioError(f"{name}: duration_s must be > 0")

    tiers = data.get("tiers", {})
    hosts = []
    for host, cfg in (_need(data, "hosts", name) or {}).items():
        where = f"{name}.hosts.{host}"
        if host not in lab.CLIENTS:
            raise ScenarioError(f"{where}: unknown client (allowed: {', '.join(lab.CLIENTS)})")
        if "tier" in cfg:
            if cfg["tier"] not in tiers:
                raise ScenarioError(f"{where}: unknown tier '{cfg['tier']}'")
            rate = float(tiers[cfg["tier"]])
        else:
            rate = float(_need(cfg, "events_per_hour", where))
        if rate < 0:
            raise ScenarioError(f"{where}: rate must be >= 0")
        acts = _need(cfg, "activities", where)
        if not isinstance(acts, dict) or not acts:
            raise ScenarioError(f"{where}: activities must be a non-empty mapping")
        for act, w in acts.items():
            if act not in CATALOGUE:
                raise ScenarioError(f"{where}: unknown activity '{act}' (allowed: {', '.join(CATALOGUE)})")
            if not isinstance(w, (int, float)) or w <= 0:
                raise ScenarioError(f"{where}: weight for '{act}' must be > 0")
        hosts.append(HostProfile(host, rate, {k: float(v) for k, v in acts.items()}))

    blocked = []
    for i, b in enumerate(data.get("blocked_attempts") or []):
        where = f"{name}.blocked_attempts[{i}]"
        src, dst = _need(b, "src", where), _need(b, "dst", where)
        if src not in lab.CLIENTS:
            raise ScenarioError(f"{where}: unknown src '{src}'")
        if dst not in lab.SERVERS:
            raise ScenarioError(f"{where}: unknown dst '{dst}'")
        port = int(_need(b, "port", where))
        if not 0 < port < 65536:
            raise ScenarioError(f"{where}: bad port {port}")
        at = float(_need(b, "at_s", where))
        if not 0 <= at < duration:
            raise ScenarioError(f"{where}: at_s must be within the run (0..{duration})")
        blocked.append(BlockedAttempt(at, src, dst, port))

    return Scenario(name, seed, duration, tuple(hosts), tuple(blocked), sha, path)
