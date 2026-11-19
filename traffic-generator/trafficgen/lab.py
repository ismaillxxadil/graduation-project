"""Static facts about the lab, taken from network/enterprise.clab.yml.

Only fixed server addresses live here. Client addresses come from DHCP and
are read from the containers at run time (see labstate.py).
"""

# Container name -> fixed lab IP (eth1). Clients (pc*, iot*) use DHCP.
SERVERS = {
    "web1": "10.10.20.20",
    "app1": "10.10.25.30",
    "db1": "10.10.30.10",
    "srv1": "10.10.35.10",
    "files1": "10.10.35.40",
    "dhcp1": "10.10.10.2",  # users-VLAN leg; IoT uses 10.10.40.2
}

DNS_SERVER = {
    "pc1": "10.10.10.2",
    "pc2": "10.10.10.2",
    "iot1": "10.10.40.2",
    "iot2": "10.10.40.2",
}

DNS_NAMES = [
    "frontend.enterprise.local",
    "app.enterprise.local",
    "db.enterprise.local",
]

CLIENTS = ["pc1", "pc2", "iot1", "iot2"]

# Which probe mirrors which switch, and which hosts sit on each switch.
PROBE_SWITCH_HOSTS = {
    "probe2": {"pc1", "pc2"},                                   # sw1, VLAN 10 (+ dhcp1 eth2)
    "probe1": {"web1", "app1", "db1", "srv1", "files1", "iot1", "iot2"},  # sw2
}
