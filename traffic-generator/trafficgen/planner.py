"""Turn a scenario + seed into a fixed timetable of actions.

This is a pure function: no Docker, no clock. The same scenario and seed
always give the same plan, which makes runs repeatable.

Timing model: each host is a Poisson process. The gap between two of its
events is drawn from an exponential distribution with mean
3600 / events_per_hour seconds. Which activity happens is a weighted choice.
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass

from . import activities
from .scenario import Scenario


@dataclass(frozen=True)
class PlannedAction:
    seq: int
    at_s: float  # seconds after run start
    src_host: str
    spec: activities.ActionSpec

    def to_dict(self) -> dict:
        d = {"seq": self.seq, "at_s": round(self.at_s, 3), "src_host": self.src_host}
        d.update(asdict(self.spec))
        d["zeek_logs"] = list(self.spec.zeek_logs)
        return d


def _host_rng(seed: int, host: str) -> random.Random:
    # One independent, seeded stream per host: adding a host to the scenario
    # does not change the timetable of the others. String seeds are hashed
    # with SHA-512 by Python, so this is stable across runs and machines.
    return random.Random(f"{seed}:{host}")


def plan(scenario: Scenario) -> list[PlannedAction]:
    items: list[tuple[float, str, activities.ActionSpec]] = []

    for host in scenario.hosts:
        rng = _host_rng(scenario.seed, host.name)
        if host.events_per_hour <= 0:
            continue
        mean_gap = 3600.0 / host.events_per_hour
        names = sorted(host.activities)
        weights = [host.activities[n] for n in names]
        t = rng.expovariate(1.0 / mean_gap)
        while t < scenario.duration_s:
            act = rng.choices(names, weights)[0]
            items.append((t, host.name, activities.CATALOGUE[act](host.name, rng)))
            t += rng.expovariate(1.0 / mean_gap)

    for b in scenario.blocked:
        items.append((b.at_s, b.src, activities.blocked_probe(b.src, b.dst, b.port)))

    items.sort(key=lambda x: (x[0], x[1]))
    return [PlannedAction(i + 1, t, h, s) for i, (t, h, s) in enumerate(items)]
