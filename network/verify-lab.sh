#!/usr/bin/env bash
# Checks that the running lab works end to end. No sudo needed.
# Usage: bash verify-lab.sh        (run from the network/ folder after start-lab.sh)
# Exit code 0 = all checks passed.

cd "$(dirname "$0")"
PASS=0; FAIL=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
check(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
x()    { docker exec "$@"; }

echo "1. Containers running"
for n in r1 probe1 probe2 dhcp1 pc1 pc2 iot1 iot2 srv1 files1 web1 app1 db1; do
    check "$n is running" "[ \"\$(docker inspect -f '{{.State.Running}}' $n)\" = true ]"
done

echo "2. Lab IP addresses (eth1)"
expect_ip() { check "$1 has an address in $2" "x $1 ip -4 -o addr show eth1 | grep -q 'inet $2'"; }
expect_ip pc1 10.10.10.;  expect_ip pc2 10.10.10.
expect_ip iot1 10.10.40.; expect_ip iot2 10.10.40.
expect_ip web1 10.10.20.20/; expect_ip app1 10.10.25.30/; expect_ip db1 10.10.30.10/
expect_ip srv1 10.10.35.10/; expect_ip files1 10.10.35.40/

echo "3. Traffic leaves through the lab (eth1), not the management network (eth0)"
for n in pc1 pc2 srv1 files1 app1 db1; do
    check "$n routes to web1 via eth1" "x $n ip route get 10.10.20.20 | grep -q 'dev eth1'"
done
for n in iot1 iot2; do
    check "$n has no eth0 default route" "! x $n ip route | grep -q '^default.*dev eth0'"
done

echo "4. Services answer"
MARK="VERIFY-$(date +%s)"
check "DNS: pc1 resolves frontend.enterprise.local" "x pc1 nslookup frontend.enterprise.local | grep -q 10.10.20.20"
check "DNS: iot1 resolves app.enterprise.local"     "x iot1 nslookup app.enterprise.local 10.10.40.2 | grep -q 10.10.25.30"
check "HTTP: pc1 -> web1 home page"                 "x pc1 wget -qO- -T 5 -U $MARK http://10.10.20.20/"
check "HTTP: pc1 -> web1 -> app1 (/api/health)"     "x pc1 wget -qO- -T 5 -U $MARK http://10.10.20.20/api/health | grep -q healthy"
check "DB:   web1 -> app1 -> db1 (/api/users/search)" "x pc1 wget -qO- -T 5 'http://10.10.20.20/api/users/search?name=appuser' | grep -q appuser"
check "SSH:  pc1 -> srv1:22 answers"                "x pc1 nc -w 3 -z 10.10.35.10 22"
check "SMB:  pc1 lists files1 share"                "x pc1 smbclient -N //10.10.35.40/shared -c ls | grep -q README"

echo "5. Firewall blocks what it should"
check "pc1 -> db1:5432 is blocked"  "! x pc1 nc -w 3 -z 10.10.30.10 5432"
check "pc1 -> app1:3000 is blocked" "! x pc1 nc -w 3 -z 10.10.25.30 3000"
check "pc1 -> srv1:23 is blocked"   "! x pc1 nc -w 3 -z 10.10.35.10 23"

echo "6. Zeek probes see the traffic (switch mirrors work)"
echo "     waiting 20 s for Zeek to write logs..."
sleep 20
check "probe1 (sw2) logged the test HTTP request" "grep -q $MARK probe-logs/http.log"
check "probe2 (sw1) logged the test HTTP request" "grep -q $MARK probe2-logs/http.log"

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
