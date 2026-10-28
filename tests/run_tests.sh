#!/bin/sh
# pktgate end-to-end tests. Run as root inside a VM:  sudo tests/run_tests.sh
#
# Loads kernel/pktgate.ko, exercises every command of pktgatectl against real
# traffic on the loopback interface, and unloads the module again. POSIX sh so
# it runs under BusyBox (QEMU test VM) as well as bash/dash (Ubuntu).

TESTS_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$TESTS_DIR")
MODULE="$ROOT/kernel/pktgate.ko"
CTL="$ROOT/tools/pktgatectl"
PROBE="$TESTS_DIR/netprobe"
DEV=/dev/pktgate
PROC=/proc/net/pktgate
TCP_PORT=9000
UDP_PORT=9001

passed=0
failed=0

pass() { passed=$((passed + 1)); echo "[PASS] $1"; }
fail() { failed=$((failed + 1)); echo "[FAIL] $1"; }
check() { if [ "$1" -eq 0 ]; then pass "$2"; else fail "$2"; fi; }

# Returns 0 if a single ping to 127.0.0.1 succeeds.
ping_lo() { ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; }

stat_value() { "$CTL" stats | grep "^$1:" | awk '{print $NF}'; }

# Empties the event log so the next watch only sees new events.
drain_log() { "$CTL" watch --timeout 1 >/dev/null; }

cleanup() {
	"$CTL" flush >/dev/null 2>&1
	rmmod pktgate >/dev/null 2>&1
}

if [ "$(id -u)" -ne 0 ]; then
	echo "run_tests.sh must run as root (it loads a kernel module)"
	exit 1
fi
for f in "$MODULE" "$CTL" "$PROBE"; do
	[ -e "$f" ] || { echo "missing $f (run make first)"; exit 1; }
done
rmmod pktgate >/dev/null 2>&1	# in case a previous run was interrupted

echo "pktgate tests on $(uname -r)"
echo "-----------------------------------------------"

# 1. Load the module
insmod "$MODULE"
check $? "module loads"
i=0; while [ ! -e "$DEV" ] && [ $i -lt 20 ]; do sleep 0.1; i=$((i + 1)); done
[ -c "$DEV" ]; check $? "$DEV exists"
grep -q "^policy:      accept" "$PROC"; check $? "$PROC shows the default policy"
"$CTL" stats | grep -q "^rules:       0$"; check $? "stats via ioctl: 0 rules"

# 2. Baseline traffic
ping_lo; check $? "ping 127.0.0.1 works with no rules"

# 3. Drop outbound ICMP
"$CTL" add --out --proto icmp --dst 127.0.0.1 drop >/dev/null
check $? "add rule: drop outbound icmp to 127.0.0.1"
if ping_lo; then fail "ping is blocked by the rule"; else pass "ping is blocked by the rule"; fi
[ "$(stat_value dropped)" -ge 1 ]; check $? "dropped counter increased"
"$CTL" list | grep -q "^0   out  icmp .* drop .* [1-9]"; check $? "rule 0 shows a hit count"

# 4. Event log (the blocked ping above produced one drop event)
out=$("$CTL" watch --max 1 --timeout 2)
echo "$out" | grep -q "out icmp 127.0.0.1 -> 127.0.0.1 .* drop   (rule 0) lo"
check $? "watch shows the dropped icmp packet: $(echo "$out" | head -1)"

# 5. Delete the rule
"$CTL" del 0 >/dev/null; check $? "del 0"
ping_lo; check $? "ping works again after deleting the rule"

# 6. TCP: drop inbound SYNs to a port
"$PROBE" tcp-listen $TCP_PORT >/tmp/pktgate_tcp.txt 2>&1 &
sleep 0.2
"$CTL" add --in --proto tcp --dport $TCP_PORT drop >/dev/null
"$PROBE" tcp-connect 127.0.0.1 $TCP_PORT 2 >/dev/null 2>&1
[ $? -eq 2 ]; check $? "tcp connect to port $TCP_PORT times out while the rule is active"
"$CTL" list | grep -q "^0   in   tcp .* $TCP_PORT .* drop"; check $? "list shows the tcp rule with dport $TCP_PORT"
"$CTL" del 0 >/dev/null
"$PROBE" tcp-connect 127.0.0.1 $TCP_PORT 2 >/dev/null 2>&1
check $? "tcp connect succeeds after deleting the rule"
sleep 0.2
grep -q "received: hello" /tmp/pktgate_tcp.txt; check $? "tcp server received the data"

# 7. UDP: drop outbound datagrams, the sender gets EPERM
"$PROBE" udp-listen $UDP_PORT 2 >/tmp/pktgate_udp.txt 2>&1 &
sleep 0.2
"$CTL" add --out --proto udp --dport $UDP_PORT drop >/dev/null
"$PROBE" udp-send 127.0.0.1 $UDP_PORT 2>&1 | grep -q "Operation not permitted"
check $? "udp send to port $UDP_PORT fails with EPERM while the rule is active"
wait
grep -q "no datagram" /tmp/pktgate_udp.txt; check $? "udp listener received nothing"
"$CTL" del 0 >/dev/null
"$PROBE" udp-listen $UDP_PORT 2 >/tmp/pktgate_udp.txt 2>&1 &
sleep 0.2
"$PROBE" udp-send 127.0.0.1 $UDP_PORT >/dev/null 2>&1
wait
grep -q "received: hello" /tmp/pktgate_udp.txt; check $? "udp datagram delivered after deleting the rule"

# 8. Default policy and first-match order
"$CTL" policy drop >/dev/null; check $? "policy drop"
if ping_lo; then fail "policy drop blocks ping"; else pass "policy drop blocks ping"; fi
"$CTL" add --proto icmp accept >/dev/null
ping_lo; check $? "an accept rule overrides the drop policy (first match wins)"
"$CTL" policy accept >/dev/null
"$CTL" flush >/dev/null; check $? "flush"
"$CTL" stats | grep -q "^rules:       0$"; check $? "flush leaves 0 rules"

# 9. Log modes
drain_log
"$CTL" log all >/dev/null; check $? "log all"
ping_lo
out=$("$CTL" watch --max 1 --timeout 2)
echo "$out" | grep -q "icmp .* accept (policy) lo"; check $? "log all records accepted packets"
"$CTL" log off >/dev/null
drain_log
"$CTL" reset >/dev/null
ping_lo
[ "$(stat_value logged)" -eq 0 ]; check $? "log off records nothing"
"$CTL" log drops >/dev/null
"$CTL" add --proto icmp --log accept >/dev/null
ping_lo
out=$("$CTL" watch --max 1 --timeout 2)
echo "$out" | grep -q "accept (rule 0)"; check $? "a rule with --log is recorded even in drops mode"
"$CTL" flush >/dev/null

# 10. Invalid input is rejected without harming the system
"$CTL" del 99 >/dev/null 2>&1; [ $? -eq 1 ]; check $? "del 99: no such rule"
"$CTL" add --proto tcp --dport 70000 drop >/dev/null 2>&1; [ $? -eq 2 ]; check $? "bad port is rejected"
"$CTL" add --sport 22 drop >/dev/null 2>&1; [ $? -eq 2 ]; check $? "ports without tcp/udp are rejected"
"$CTL" add --src 300.1.1.1 drop >/dev/null 2>&1; [ $? -eq 2 ]; check $? "bad address is rejected"
i=0; while [ $i -lt 64 ]; do "$CTL" add --proto tcp --dport $((10000 + i)) accept >/dev/null; i=$((i + 1)); done
"$CTL" add --proto tcp --dport 20000 accept 2>&1 | grep -q "full"; check $? "65th rule is rejected: table full"
"$CTL" stats | grep -q "^rules:       64$"; check $? "64 rules stored"
"$CTL" flush >/dev/null

# 11. Counters reset
ping_lo
"$CTL" reset >/dev/null
[ "$(stat_value packets)" -eq 0 ]; check $? "reset zeroes the counters"

# 12. Two readers at the same time
"$CTL" log all >/dev/null
"$CTL" watch --timeout 1 >/dev/null & w1=$!
"$CTL" watch --timeout 1 >/dev/null & w2=$!
ping_lo; ping_lo
wait $w1; r1=$?; wait $w2; r2=$?
[ $r1 -eq 0 ] && [ $r2 -eq 0 ]; check $? "two concurrent watch readers exit cleanly"
"$CTL" log drops >/dev/null

# 13. Rules changing while traffic flows (exercises the locking)
( i=0; while [ $i -lt 300 ]; do "$PROBE" udp-send 127.0.0.1 $UDP_PORT >/dev/null 2>&1; i=$((i + 1)); done ) & gen=$!
i=0
while [ $i -lt 100 ]; do
	"$CTL" add --proto udp --dport $UDP_PORT drop >/dev/null
	"$CTL" del 0 >/dev/null
	i=$((i + 1))
done
wait $gen
"$CTL" stats >/dev/null; check $? "device still answers after 100 rule changes under traffic"
if dmesg | grep -qiE "BUG:|Oops|general protection|pktgate.*(warn|error)"; then
	fail "no kernel errors in dmesg"
else
	pass "no kernel errors in dmesg"
fi

# 14. Unload
"$CTL" flush >/dev/null
rmmod pktgate; check $? "module unloads"
[ ! -e "$PROC" ]; check $? "$PROC is gone after unload"
ping_lo; check $? "network still works after unload"

echo "-----------------------------------------------"
echo "$passed passed, $failed failed"
[ $failed -eq 0 ]
