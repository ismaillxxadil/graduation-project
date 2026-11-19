"""Activity catalogue: what each named activity does inside a source container.

An activity turns (source host, random choice) into an ActionSpec: the exact
shell command plus the network facts the ledger needs (destination, port,
protocol, expected outcome, Zeek logs we expect to see).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from . import lab

MARKER = "{marker}"  # replaced by the executor with NOTLINE/<run_id>/<seq>


@dataclass(frozen=True)
class ActionSpec:
    activity: str
    dst_host: str
    dst_ip: str
    proto: str
    dst_port: int
    service: str
    command: str
    expected: str  # "allowed" | "blocked"
    zeek_logs: tuple[str, ...]
    tool: str  # program that must exist in the source container
    detail: dict = field(default_factory=dict)


def _http(src: str, rng: random.Random, path: str, activity: str, logs: tuple[str, ...], detail: dict) -> ActionSpec:
    url = f"http://{lab.SERVERS['web1']}{path}"
    return ActionSpec(
        activity=activity, dst_host="web1", dst_ip=lab.SERVERS["web1"], proto="tcp",
        dst_port=80, service="http",
        command=f"wget -q -O /dev/null -T 5 -U '{MARKER}' '{url}'",
        expected="allowed", zeek_logs=logs, tool="wget", detail=detail,
    )


def http_home(src: str, rng: random.Random) -> ActionSpec:
    return _http(src, rng, "/", "http_home", ("conn", "http"), {"path": "/"})


def http_api(src: str, rng: random.Random) -> ActionSpec:
    path = rng.choice(["/api/health", "/api/users"])
    # web1 proxies /api/ to app1:3000, so a second hop web1 -> app1 is expected.
    return _http(src, rng, path, "http_api", ("conn", "http"),
                 {"path": path, "downstream": ["web1->app1:3000"]})


def http_search(src: str, rng: random.Random) -> ActionSpec:
    name = rng.choice(["appuser", "postgres"])
    path = f"/api/users/search?name={name}"
    # Full chain: client -> web1:80 -> app1:3000 -> db1:5432.
    return _http(src, rng, path, "http_search", ("conn", "http"),
                 {"path": path, "downstream": ["web1->app1:3000", "app1->db1:5432"]})


def dns_lookup(src: str, rng: random.Random) -> ActionSpec:
    name = rng.choice(lab.DNS_NAMES)
    server = lab.DNS_SERVER[src]
    return ActionSpec(
        activity="dns_lookup", dst_host="dhcp1", dst_ip=server, proto="udp", dst_port=53,
        service="dns", command=f"nslookup {name} {server}", expected="allowed",
        zeek_logs=("conn", "dns"), tool="nslookup", detail={"query": name},
    )


def ssh_handshake(src: str, rng: random.Random) -> ActionSpec:
    # No password is sent (BatchMode). The SSH handshake still completes, so Zeek
    # writes ssh.log; the login itself is refused. That is the expected outcome.
    ip = lab.SERVERS["srv1"]
    cmd = ("ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "
           f"-o UserKnownHostsFile=/dev/null labuser@{ip} true")
    return ActionSpec(
        activity="ssh_handshake", dst_host="srv1", dst_ip=ip, proto="tcp", dst_port=22,
        service="ssh", command=cmd, expected="allowed", zeek_logs=("conn", "ssh"), tool="ssh",
    )


def smb_list(src: str, rng: random.Random) -> ActionSpec:
    ip = lab.SERVERS["files1"]
    return ActionSpec(
        activity="smb_list", dst_host="files1", dst_ip=ip, proto="tcp", dst_port=445,
        service="smb", command=f"smbclient -N //{ip}/shared -c ls", expected="allowed",
        zeek_logs=("conn", "smb_mapping"), tool="smbclient",
    )


def dhcp_renew(src: str, rng: random.Random) -> ActionSpec:
    # Run one full DHCP exchange (DISCOVER/OFFER/REQUEST/ACK) and exit.
    # -n: fail instead of retrying forever, so the exit code is honest.
    # (Signalling a running udhcpc does not work: the boot-time client is
    # started with -q and exits after its first lease.)
    server = lab.DNS_SERVER[src]
    return ActionSpec(
        activity="dhcp_renew", dst_host="dhcp1", dst_ip=server, proto="udp", dst_port=67,
        service="dhcp", command="udhcpc -q -n -t 3 -T 2 -i eth1 >/dev/null 2>&1", expected="allowed",
        zeek_logs=("dhcp",), tool="udhcpc",
    )


def blocked_probe(src: str, dst_host: str, port: int) -> ActionSpec:
    ip = lab.SERVERS[dst_host]
    return ActionSpec(
        activity="blocked_probe", dst_host=dst_host, dst_ip=ip, proto="tcp", dst_port=port,
        service="tcp", command=f"nc -w 3 -z {ip} {port}", expected="blocked",
        zeek_logs=("conn",), tool="nc",
    )


CATALOGUE = {
    "http_home": http_home,
    "http_api": http_api,
    "http_search": http_search,
    "dns_lookup": dns_lookup,
    "ssh_handshake": ssh_handshake,
    "smb_list": smb_list,
    "dhcp_renew": dhcp_renew,
}


def classify(spec: ActionSpec, exit_code: int | None, output: str) -> str:
    """Turn a command's exit code/output into a ledger result.

    success  - the conversation happened (for ssh: handshake done, login refused)
    blocked  - no answer / refused (expected for blocked_probe)
    failed   - the command ran but the service did not work
    timeout  - the generator gave up waiting for docker exec
    """
    if exit_code is None:
        return "timeout"
    if spec.activity == "blocked_probe":
        return "success" if exit_code == 0 else "blocked"
    if spec.activity == "ssh_handshake":
        return "success" if exit_code == 0 or "Permission denied" in output else "failed"
    return "success" if exit_code == 0 else "failed"


def expected_visibility(src: str, spec: ActionSpec) -> dict[str, list[str]]:
    """Which probe should log this action, and in which logs.

    Allowed traffic is seen on every switch it crosses. Blocked traffic is
    dropped by r1, so only the probe on the source's switch sees the attempt.
    DNS/DHCP to dhcp1 stays on the source's own switch.
    """
    seen: dict[str, list[str]] = {}
    for probe, hosts in lab.PROBE_SWITCH_HOSTS.items():
        on_src = src in hosts
        on_dst = spec.dst_host in hosts and spec.dst_host != "dhcp1"
        if on_src or (on_dst and spec.expected == "allowed"):
            logs = ["conn:S0"] if spec.expected == "blocked" else list(spec.zeek_logs)
            seen[probe] = logs
    return seen
