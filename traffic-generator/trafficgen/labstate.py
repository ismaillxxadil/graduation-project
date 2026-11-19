"""Preflight: make sure the lab can carry the planned traffic before running.

Refuses to run when a source container is down, has no lab address on eth1,
would send traffic out of the management interface (eth0), or lacks a tool.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

from . import lab
from .planner import PlannedAction


def docker_exec(container: str, command: str, timeout: float = 30) -> tuple[int | None, str]:
    """Run `sh -c command` in a container. Returns (exit code or None on timeout, output)."""
    try:
        p = subprocess.run(
            ["docker", "exec", container, "sh", "-c", command],
            capture_output=True, text=True, timeout=timeout,
        )
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"") + (e.stderr or b"")
        return None, out.decode(errors="replace") if isinstance(out, bytes) else str(out)


@dataclass
class LabState:
    host_ips: dict[str, str] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def _eth1_ip(host: str) -> str | None:
    code, out = docker_exec(host, "ip -4 -o addr show eth1", timeout=10)
    if code != 0:
        return None
    for tok in out.split():
        if "/" in tok and tok[0].isdigit():
            return tok.split("/")[0]
    return None


def check(actions: list[PlannedAction]) -> LabState:
    state = LabState()
    tools: dict[str, set[str]] = {}
    dsts: dict[str, set[str]] = {}
    for a in actions:
        tools.setdefault(a.src_host, set()).add(a.spec.tool)
        dsts.setdefault(a.src_host, set()).add(a.spec.dst_ip)

    for host in sorted(tools):
        code, out = docker_exec(host, "true", timeout=10)
        if code != 0:
            state.problems.append(f"{host}: container not running or not reachable ({out.strip()[:120]})")
            continue

        ip = _eth1_ip(host)
        if not ip:
            state.problems.append(f"{host}: no IPv4 address on eth1 (DHCP not finished?)")
            continue
        state.host_ips[host] = ip

        for dst in sorted(dsts[host]):
            code, out = docker_exec(host, f"ip route get {dst}", timeout=10)
            if code != 0 or "dev eth1" not in out:
                state.problems.append(
                    f"{host}: traffic to {dst} would not leave via eth1 "
                    f"(probes would miss it): {out.strip()[:120]}")

        for tool in sorted(tools[host]):
            code, _ = docker_exec(host, f"command -v {tool}", timeout=10)
            if code != 0:
                state.problems.append(f"{host}: '{tool}' is not installed")

    for server, ip in lab.SERVERS.items():
        if any(ip in d for d in dsts.values()):
            code, _ = docker_exec(server, "true", timeout=10)
            if code != 0:
                state.problems.append(f"{server}: destination container is not running")
    return state
