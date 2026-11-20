# Lab Network Topology: A Beginner's Guide

This page explains the whole lab network in a few minutes. Read it top to bottom once. After that, use it as a reference.

The network diagram is `/home/ismail/GP/diagram/network-topology.drawio` (open it in VS Code with the Draw.io extension, or at app.diagrams.net).

Facts here come from `enterprise.clab.yml`, `config/vlan-config.sh`, `r1/frr.conf`, `r1/firewall.sh` and `start-lab.sh`. Commands were tested on the running lab on 2026-11-19.

---

## 1. What is this lab?

This lab is a small, pretend company network. It runs on one Linux machine with [Containerlab](https://containerlab.dev). Each "computer" is a Docker container. The two switches are Open vSwitch (OVS) bridges on the host. The packets are real: the PCs really send HTTP, DNS, DHCP, SSH and SMB traffic through a real router (`r1`). The router has a firewall. Users browse a web frontend (`web1`). It calls an API (`app1`), which reads a PostgreSQL database (`db1`). Two **Zeek** probes (`probe1`, `probe2`) watch the traffic passively. Each switch copies ("mirrors") its frames to its probe, and the probe writes logs. The probes never send traffic.

> **Note: two networks per container.** Every container also has an `eth0` on `172.20.20.0/24`. That is Containerlab's management network, so you can reach containers from the host. It is **not** part of the lab design. The lab traffic uses `eth1`, `eth2` and so on.

---

## 2. VLANs and subnets

| VLAN | Purpose | Subnet | Gateway (r1 interface) | Switch | Members |
|---|---|---|---|---|---|
| 10 | Users | 10.10.10.0/24 | 10.10.10.1 (`eth1`) | sw1 | pc1, pc2, dhcp1 (`eth2`), r1 |
| 20 | Servers / frontend (DMZ) | 10.10.20.0/24 | 10.10.20.1 (`eth2`) | sw2 | web1, dhcp1 (`eth1`), r1 |
| 25 | Application | 10.10.25.0/24 | 10.10.25.1 (`eth4`) | sw2 | app1, r1 |
| 30 | Database | 10.10.30.0/24 | 10.10.30.1 (`eth3`) | sw2 | db1, r1 |
| 35 | Management / infrastructure | 10.10.35.0/24 | 10.10.35.1 (`eth5`) | sw2 | srv1, files1, r1 |
| 40 | IoT (isolated) | 10.10.40.0/24 | **none** (r1 has no leg here) | sw2 | iot1, iot2, dhcp1 (`eth3`) |

### Switch port to VLAN map

Source: `config/vlan-config.sh`. These are access ports, and there are no trunks.

| Switch | Port | Connected to | VLAN |
|---|---|---|---|
| sw1 | ovsp1 | r1:eth1 | 10 |
| sw1 | ovsp2 | pc1:eth1 | 10 |
| sw1 | ovsp3 | pc2:eth1 | 10 |
| sw1 | ovsp4 | dhcp1:eth2 | 10 |
| sw1 | ovsp_probe | probe2:eth1 | (mirror output, no tag) |
| sw2 | ovs2p1 | r1:eth2 | 20 |
| sw2 | ovs2p3 | web1:eth1 | 20 |
| sw2 | ovs2p7 | dhcp1:eth1 | 20 |
| sw2 | ovs2p12 | r1:eth4 | 25 |
| sw2 | ovs2p6 | app1:eth1 | 25 |
| sw2 | ovs2p4 | r1:eth3 | 30 |
| sw2 | ovs2p5 | db1:eth1 | 30 |
| sw2 | ovs2p13 | r1:eth5 | 35 |
| sw2 | ovs2p2 | srv1:eth1 | 35 |
| sw2 | ovs2p11 | files1:eth1 | 35 |
| sw2 | ovs2p8 | iot1:eth1 | 40 |
| sw2 | ovs2p9 | iot2:eth1 | 40 |
| sw2 | ovs2p10 | dhcp1:eth3 | 40 |
| sw2 | ovs2p_probe | probe1:eth1 | (mirror output, no tag) |

### DHCP and DNS (served by dhcp1)

| VLAN | DHCP pool | Lease | Gateway given | DNS given |
|---|---|---|---|---|
| 10 | 10.10.10.100 – .150 | 24h | 10.10.10.1 | 10.10.10.2 |
| 20 | 10.10.20.100 – .150 | 24h | 10.10.20.1 | (dnsmasq default) |
| 40 | 10.10.40.100 – .150 | 12h | 10.10.40.2 (dnsmasq default = dhcp1 itself; it does not route, so IoT stays isolated) | 10.10.40.2 |

Lab DNS names, answered by dnsmasq on dhcp1:

| Name | IP |
|---|---|
| frontend.enterprise.local | 10.10.20.20 (web1) |
| app.enterprise.local | 10.10.25.30 (app1) |
| db.enterprise.local | 10.10.30.10 (db1) |

---

## 3. Devices

Open a shell in any container with `docker exec -it <name> sh`. Use `bash` for the probes.

### r1: router and firewall
- **Role:** connects all VLANs except VLAN 40. Every packet between VLANs passes through it, and its firewall decides what is allowed.
- **Image:** `quay.io/frrouting/frr:10.7.1` (FRRouting). At boot it installs `iptables`, turns on IP forwarding and runs `r1/firewall.sh`.
- **IPs (static, from `r1/frr.conf`):** eth1 10.10.10.1, eth2 10.10.20.1, eth3 10.10.30.1, eth4 10.10.25.1, eth5 10.10.35.1.
- **Routing:** only directly connected routes. No OSPF or BGP.
- **Try:**
  ```bash
  docker exec r1 vtysh -c 'show ip route'
  docker exec r1 vtysh -c 'show interface brief'
  docker exec r1 iptables -nvL R1-FORWARD
  ```

### sw1: user switch
- **Role:** layer-2 switch for VLAN 10 (users). It mirrors all its traffic to `probe2`.
- **Kind:** Containerlab `ovs-bridge`. It is an OVS bridge on the **host**, not a container. So `docker exec sw1` does not work.
- **Try (on the host; needs sudo):**
  ```bash
  sudo ovs-vsctl list-ports sw1
  sudo ovs-vsctl get port ovsp2 tag
  ```

### sw2: server/datacenter switch
- **Role:** layer-2 switch for VLANs 20, 25, 30, 35 and 40. It mirrors all its traffic to `probe1`.
- **Kind:** OVS bridge on the host, like sw1.
- **Try (on the host; needs sudo):**
  ```bash
  sudo ovs-vsctl list-ports sw2
  sudo ovs-vsctl list mirror
  ```

### probe1: Zeek sensor on sw2
- **Role:** passive monitor for the server side (VLANs 20/25/30/35/40). It has no IP on `eth1` and never sends traffic.
- **Image:** `zeek/zeek:7.0.5`. It is started by `config/start-zeek.sh`, which runs `zeek -i eth1 LogAscii::use_json=T`.
- **Output:** JSON logs in `/opt/zeek/logs`. On the host, these appear in `./probe-logs/`.
- **Restarts:** Zeek empties its log files when it starts. So before starting, `start-zeek.sh` moves the previous run's logs into `probe-logs/archive/<unix-time>/`. Nothing is lost, and Module 4 reads the archive too.
- **Note:** `tcpdump` and `ip` are **not** installed in this image.
- **Try:**
  ```bash
  ls -lh probe-logs/
  tail -n 5 probe-logs/conn.log | jq -c '{ts, src: ."id.orig_h", dst: ."id.resp_h", port: ."id.resp_p", proto}'
  ```

### probe2: Zeek sensor on sw1
- **Role:** passive monitor for the user side (VLAN 10).
- **Image:** `zeek/zeek:7.0.5`, set up the same way as probe1.
- **Output:** `./probe2-logs/` on the host (old runs in `./probe2-logs/archive/`).
- **Try:**
  ```bash
  ls -lh probe2-logs/
  tail -n 5 probe2-logs/dns.log | jq -c '{ts, query, answers}'
  ```

### dhcp1: DHCP and DNS server
- **Role:** gives out IP addresses and answers the `*.enterprise.local` names. It has three legs: VLAN 20 (`eth1`), VLAN 10 (`eth2`) and VLAN 40 (`eth3`).
- **Image:** `alpine:3.21.3`. It installs and runs `dnsmasq` at boot.
- **IPs (static):** 10.10.20.2 (eth1), 10.10.10.2 (eth2), 10.10.40.2 (eth3).
- **Ports:** UDP 67 (DHCP), UDP/TCP 53 (DNS).
- **Try:**
  ```bash
  docker exec dhcp1 cat /var/lib/misc/dnsmasq.leases     # who got which IP
  docker exec dhcp1 tail -n 20 /var/log/dnsmasq.log       # DHCP conversation log
  ```

### pc1: user workstation
- **Role:** an employee PC. Use it as the client for most tests.
- **Image:** `alpine:3.21.3`. At boot it installs `openssh-client` and `samba-client`.
- **IP:** DHCP on VLAN 10 (10.10.10.100–150). Its DNS server is set to 10.10.10.2.
- **Tools:** `wget`, `nslookup`, `nc`, `ping` (BusyBox), plus `ssh` and `smbclient`.
- **Try:**
  ```bash
  docker exec pc1 ip -4 addr show eth1
  docker exec pc1 wget -qO- http://frontend.enterprise.local/
  docker exec -it pc1 ssh labuser@10.10.35.10        # password: labpassword
  ```

### pc2: user workstation
- **Role:** a second employee PC.
- **Image:** `alpine:3.21.3`. It has only the BusyBox tools (no ssh or smbclient).
- **IP:** DHCP on VLAN 10. Its DNS server is 10.10.10.2.
- **Try:**
  ```bash
  docker exec pc2 ip -4 addr show eth1
  docker exec pc2 nslookup app.enterprise.local
  docker exec pc2 wget -qO- http://frontend.enterprise.local/api/health
  ```

### iot1, iot2: IoT devices
- **Role:** quiet "smart devices" such as cameras or sensors. They sit on an isolated VLAN and get no default gateway, so they cannot reach other VLANs.
- **Image:** `alpine:3.21.3`.
- **IP:** DHCP on VLAN 40. They get 10.10.40.100–150 (now .136 and .144). They use dhcp1 (10.10.40.2) as gateway and DNS, and can reach only dhcp1.
- **Try:**
  ```bash
  docker exec iot1 ip -4 addr show eth1
  docker exec iot1 cat /var/log/udhcpc.log
  ```

### srv1: SSH server
- **Role:** an infrastructure or jump server on the management VLAN.
- **Image:** `alpine:3.21.3`. It installs and runs OpenSSH at boot.
- **IP:** 10.10.35.10 (static). Gateway: 10.10.35.1.
- **Ports:** TCP 22.
- **Credentials:** `labuser` / `labpassword`. Root login is disabled.
- **Try:**
  ```bash
  docker exec -it pc1 ssh labuser@10.10.35.10      # from a user PC (allowed by the firewall)
  docker exec pc2 nc -z -w 3 10.10.35.10 22 && echo open
  ```

### files1: Windows-style file server (SMB)
- **Role:** shared company folder on the management VLAN.
- **Image:** `alpine:3.21.3`. It installs and runs Samba (`smbd`) at boot.
- **IP:** 10.10.35.40 (static). Gateway: 10.10.35.1.
- **Ports:** TCP 445.
- **Contents:** share `shared` (path `/srv/share`, contains `README.txt`). Guest access, read/write.
- **Credentials:** none (anonymous guest).
- **Try (works only after Samba has finished installing; see section 7):**
  ```bash
  docker exec pc1 smbclient -N //10.10.35.40/shared -c 'ls'
  docker exec files1 ps          # look for smbd
  ```

### web1: web frontend
- **Role:** the company website. It serves a static page and forwards `/api/...` requests to app1.
- **Image:** `enterprise-web:2.0`. It is built locally from `web1/` (nginx on Alpine).
- **IP:** 10.10.20.20 (static). Gateway: 10.10.20.1. DNS name: `frontend.enterprise.local`.
- **Ports:** TCP 80 only. The firewall also allows 443, but nginx does not listen on 443.
- **What it does (`web1/nginx.conf`):** `/` serves `index.html` ("Enterprise Web Server - WEB1"). `/api/` is reverse-proxied to `http://10.10.25.30:3000`.
- **Try:**
  ```bash
  docker exec pc1 wget -qO- http://10.10.20.20/
  docker exec pc1 wget -qO- http://frontend.enterprise.local/api/users
  docker logs --tail 20 web1
  ```

### app1: application API
- **Role:** the back-end API. It is called only by web1.
- **Image:** `enterprise-app:1.0`. It is built locally from `app1/` (Node 22 + Express + `pg`).
- **IP:** 10.10.25.30 (static). Gateway: 10.10.25.1. DNS name: `app.enterprise.local`.
- **Ports:** TCP 3000.
- **Endpoints (`app1/server.js`):**

  | Path | What it returns |
  |---|---|
  | `/` | service info JSON |
  | `/api/health` | `{"status":"healthy","server":"APP1"}` |
  | `/api/users` | hard-coded list (Alice, Bob); no database |
  | `/api/users/search?name=X` | queries Postgres `pg_user`. It is **deliberately vulnerable to SQL injection** for security exercises. |

- **DB credentials it uses:** host 10.10.30.10, user `appuser`, password `labpassword`, database `enterprise_db`.
- **Try (through web1, the allowed path):**
  ```bash
  docker exec pc1 wget -qO- 'http://frontend.enterprise.local/api/users/search?name=appuser'
  # SQL injection demo: returns the database name instead of a user
  docker exec pc1 wget -qO- "http://10.10.20.20/api/users/search?name=x'%20UNION%20SELECT%201::oid,current_database()::name--"
  docker logs --tail 20 app1
  ```

### db1: database
- **Role:** PostgreSQL database. It is reachable only from app1.
- **Image:** `postgres:18.0-alpine3.21`.
- **IP:** 10.10.30.10 (static). Gateway: 10.10.30.1. DNS name: `db.enterprise.local`.
- **Ports:** TCP 5432.
- **Credentials:** `appuser` / `labpassword`, database `enterprise_db`.
- **Data:** stored on the host in `./db1/data`. It currently has **no tables**. The search endpoint reads the system view `pg_user`.
- **Try:**
  ```bash
  docker exec db1 pg_isready -U appuser -d enterprise_db
  docker exec -it db1 psql -U appuser -d enterprise_db
  ```

---

## 4. Firewall rules (r1)

`r1` uses **default deny** for traffic it forwards between VLANs. Only the connections below are allowed. Reply packets for an allowed connection are always allowed back.

| # | From | To | Port | Why |
|---|---|---|---|---|
| 1 | Users (10.10.10.0/24) | web1 10.10.20.20 | TCP 80, 443 | browse the website |
| 2 | Users | srv1 10.10.35.10 | TCP 22 | SSH to the server |
| 3 | Users | files1 10.10.35.40 | TCP 445 | SMB file share |
| 4 | web1 | app1 10.10.25.30 | TCP 3000 | frontend calls API |
| 5 | app1 | db1 10.10.30.10 | TCP 5432 | API queries database |
| – | anything else | | | **dropped**, and logged with prefix `R1-FW-DROP` (max 6/min) |

What this means in practice:
- A user can reach the API **only through web1**. Calling app1 directly is blocked.
- Nobody except app1 can reach the database.
- **Ping between VLANs is blocked**, because ICMP is not on the list. Pinging your own gateway works, because that traffic is for r1 itself and not forwarded.
- The firewall only filters routed traffic. Two hosts in the same VLAN talk directly through the switch, so r1 never sees that traffic.

Test it (results checked on the running lab):

```bash
docker exec pc1 wget -T 5 -qO- http://frontend.enterprise.local/api/health   # ALLOWED: prints {"status":"healthy",...}
docker exec pc1 wget -T 5 -qO- http://10.10.25.30:3000/api/health           # BLOCKED: "download timed out"
docker exec pc1 nc -z -w 3 10.10.30.10 5432; echo $?                         # BLOCKED: prints 1
docker exec pc1 ping -c 2 -W 2 10.10.20.20                                   # BLOCKED: 100% packet loss
docker exec pc1 ping -c 2 10.10.10.1                                         # OK: own gateway
```

See per-rule packet counters (the numbers go up as you test):

```bash
docker exec r1 iptables -nvL R1-FORWARD
```

The `R1-FW-DROP` log lines go to the **host** kernel log. Reading it needs root, for example `sudo dmesg | grep R1-FW-DROP`.

---

## 5. Monitoring

| Probe | Watches | Mirror (from `start-lab.sh`) | Logs on host |
|---|---|---|---|
| probe1 | sw2: servers, app, DB, management, IoT | OVS mirror `span`, all sw2 traffic → port `ovs2p_probe` | `./probe-logs/` |
| probe2 | sw1: users | OVS mirror `span-sw1`, all sw1 traffic → port `ovsp_probe` | `./probe2-logs/` |

Zeek writes one JSON object per line. Common files are `conn.log` (every connection), `dns.log`, `dhcp.log`, `http.log`, `ssh.log`, `smb_*.log`, and `ntlm.log`. There is **no** `postgresql.log`: Zeek 7.0.5 has no PostgreSQL analyzer (it was added in 7.1), so app1 → db1 appears only in `conn.log`. Files appear only after Zeek sees that kind of traffic.

**Watch the logs live:**
```bash
tail -f probe-logs/conn.log | jq -c '{src: ."id.orig_h", dst: ."id.resp_h", port: ."id.resp_p", proto, service}'
```

**Watch the raw packets live in Wireshark (on the host).** You cannot capture inside the probes, because they have no `tcpdump`. Capture on the host side of the probe port instead. Your user must be in the `wireshark` group, or you must use sudo.
```bash
wireshark -k -i ovs2p_probe      # everything mirrored from sw2 (what probe1 sees)
wireshark -k -i ovsp_probe       # everything mirrored from sw1 (what probe2 sees)
wireshark -k -i ovs2p3           # only web1's port; no mirror needed
sudo tcpdump -ni ovs2p_probe     # same idea, in the terminal
```

> **Note:** the old command in `commands.txt` (`docker exec -i probe1 tcpdump ...`) does **not** work, because tcpdump is not in the Zeek image.

---

## 6. Cheat sheet

Run these from the `network/` folder.

| Task | Command |
|---|---|
| Start (or rebuild) the whole lab | `./start-lab.sh`. ⚠️ This **destroys** the current lab first, then deploys, applies VLAN tags and creates the mirrors. It needs sudo. The first boot takes minutes while containers install packages. |
| Stop and remove the lab | `sudo containerlab destroy -t enterprise.clab.yml` |
| Build the two local images (first time) | `docker build -t enterprise-web:2.0 ./web1 && docker build -t enterprise-app:1.0 ./app1` |
| **Check the whole lab works** | `bash verify-lab.sh` (42 checks, no sudo, ~1 min) |
| Apply VLAN tags only | `bash config/vlan-config.sh` (needs sudo) |
| List lab containers | `docker ps --filter label=containerlab=enterprise --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'` |
| Lab overview with mgmt IPs | `containerlab inspect -t enterprise.clab.yml` |
| Shell into a node | `docker exec -it pc1 sh` (`bash` for probe1/probe2) |
| Check a node's lab IP | `docker exec pc1 ip -4 addr show eth1` |
| Check a node's routes | `docker exec pc1 ip route` |
| Web page | `docker exec pc1 wget -qO- http://frontend.enterprise.local/` |
| Full web → app → db path | `docker exec pc1 wget -qO- 'http://frontend.enterprise.local/api/users/search?name=appuser'` → `{"users":[{"id":10,"name":"appuser"}]}` |
| Is the DB up? | `docker exec db1 pg_isready -U appuser -d enterprise_db` |
| DHCP leases | `docker exec dhcp1 cat /var/lib/misc/dnsmasq.leases` |
| DHCP log | `docker exec dhcp1 tail -n 20 /var/log/dnsmasq.log` |
| A client's DHCP log | `docker exec iot1 cat /var/log/udhcpc.log` |
| DNS lookup | `docker exec pc1 nslookup frontend.enterprise.local` |
| Router table | `docker exec r1 vtysh -c 'show ip route'` |
| Firewall counters | `docker exec r1 iptables -nvL R1-FORWARD` |
| Service logs | `docker logs --tail 50 app1` (also `web1`, `db1`) |
| Check OVS VLAN tags and mirrors | `sudo ovs-vsctl show` and `sudo ovs-vsctl list mirror` |

---

## 7. Known gaps and gotchas

Observed on the running lab on 2026-11-19:

1. **Wait for `start-lab.sh` to fully finish before testing.** The VLAN tags and mirrors are applied at the end of the script, with sudo. Until then, sw2 acts as one flat network and the probes only see broadcast traffic. On 2026-11-19 this caused iot1/iot2 to lease VLAN 20 addresses. After the script finished, everything was correct. **Always run `bash verify-lab.sh` after starting the lab**: it checks addresses, routes, services, the firewall and probe visibility in about a minute, with no sudo needed.
2. **Boot is slow and happens in steps.** pc1, files1, srv1, dhcp1 and r1 run `apk add` at startup. pc1 had **no IP for about 14 minutes** while it installed `samba-client`. Its DHCP and DNS setup only run after that. If a node "doesn't work", check whether it is still installing: `docker exec <node> ps | grep apk`.
3. **files1 installs Samba at boot**, so port 445 stays closed for the first few minutes. Its default route only switches from `eth0` to `10.10.35.1` after the install. Wait, then retry the `smbclient` command.
4. **Only pc1 has `ssh` and `smbclient`.** pc2, the IoT devices and the servers have only BusyBox tools (`wget`, `nc`, `nslookup`, `ping`).
5. **The probes have no `tcpdump` or `ip`.** Use the Zeek logs, or capture on the host (section 5).
6. **The firewall allows TCP 443 to web1, but nginx serves only port 80.** There is no HTTPS.
7. **db1 has no application tables.** `/api/users` is hard-coded. Only `/api/users/search` touches the database, and it is intentionally SQL-injectable.
8. **The VLAN 20 DHCP pool exists, but no server in VLAN 20 uses DHCP.** web1 is static. The pool exists only because dhcp1 has a leg in VLAN 20.
9. **Some docs are out of date.** `README.md` says probe1 has tcpdump and lists fewer nodes. `context.md` says r1 routes only VLANs 10/20/30. When they disagree with this page, trust `enterprise.clab.yml` and the scripts.
10. **IoT devices are isolated in VLAN 40 on purpose.** r1 has no VLAN 40 interface, so iot1/iot2 can only reach dhcp1 (`10.10.40.2`, for DHCP and DNS). Docker gives them an `eth0` default route, which `enterprise.clab.yml` removes at boot. Without that, their traffic would leave through the management network, where no probe sees it.
