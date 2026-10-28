#!/bin/sh
# Runs the pktgate test suite inside a throwaway QEMU virtual machine.
#
# Needed:  a Linux kernel image (bzImage / vmlinuz) and the matching kernel
#          headers, qemu-system-x86_64, busybox (static), cpio, gzip.
# Usage:   KERNEL=/boot/vmlinuz-$(uname -r) KDIR=/lib/modules/$(uname -r)/build \
#              tests/qemu/run_qemu_tests.sh
#
# The VM has no disk and no network card: the tests only use the loopback
# interface, so nothing outside the VM can be affected by the module.
set -e

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
KERNEL=${KERNEL:?set KERNEL to a kernel image}
KDIR=${KDIR:?set KDIR to the matching kernel headers}
BUSYBOX=${BUSYBOX:-$(command -v busybox)}
WORK=${WORK:-$ROOT/build-qemu}
MEM=${MEM:-512}
LOG="$WORK/console.log"

rm -rf "$WORK"
mkdir -p "$WORK/root/bin" "$WORK/root/proc" "$WORK/root/sys" "$WORK/root/dev" "$WORK/root/tmp"

echo "== building the module against $KDIR"
make -C "$ROOT" module KDIR="$KDIR" >/dev/null

echo "== building static tools (the VM has no libc)"
gcc -O2 -Wall -static -I"$ROOT/include" "$ROOT/tools/pktgatectl.c" -o "$WORK/pktgatectl"
gcc -O2 -Wall -static "$ROOT/tests/netprobe.c" -o "$WORK/netprobe"

echo "== assembling the initramfs"
mkdir -p "$WORK/root/pktgate/kernel" "$WORK/root/pktgate/tools" "$WORK/root/pktgate/tests"
cp "$ROOT/kernel/pktgate.ko" "$WORK/root/pktgate/kernel/"
cp "$WORK/pktgatectl" "$WORK/root/pktgate/tools/"
cp "$WORK/netprobe" "$ROOT/tests/run_tests.sh" "$WORK/root/pktgate/tests/"
cp "$BUSYBOX" "$WORK/root/bin/busybox"
cat > "$WORK/root/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs dev /dev 2>/dev/null
ip link set lo up
/pktgate/tests/run_tests.sh
echo "PKTGATE_TESTS_EXIT=$?"
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . | cpio -o -H newc 2>/dev/null | gzip > "$WORK/initramfs.cpio.gz")

echo "== booting $KERNEL"
qemu-system-x86_64 -m "$MEM" -nographic -no-reboot -nic none \
	-kernel "$KERNEL" -initrd "$WORK/initramfs.cpio.gz" \
	-append "console=ttyS0 quiet panic=1" 2>&1 | tr -d '\r' | tee "$LOG" | grep -E '^\[|passed|^pktgate|^---' || true

status=$(grep -o 'PKTGATE_TESTS_EXIT=[0-9]*' "$LOG" | tail -1 | cut -d= -f2)
if [ "$status" = "0" ]; then
	echo "== all tests passed (full console log: $LOG)"
	exit 0
fi
echo "== tests failed or the VM did not finish (see $LOG)"
exit 1
