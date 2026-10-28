# Running pktgate in a virtual machine

Never load an experimental kernel module on the machine you work on: a bug can freeze or crash the whole system. Use a Linux VM, which takes about 15 minutes to set up.

## macOS (Apple Silicon or Intel)

The simplest option is **Multipass** (free, from Canonical):

```bash
brew install multipass
multipass launch 24.04 --name pktgate-vm --cpus 2 --memory 2G --disk 10G
multipass shell pktgate-vm
```

Inside the VM:

```bash
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r) git
git clone https://github.com/codingM123/pktgate.git
cd pktgate
make
sudo tests/run_tests.sh
```

To copy files in and out: `multipass transfer pktgate-vm:/home/ubuntu/pktgate/README.md .`

UTM (a QEMU front end) or VirtualBox with an Ubuntu Server 24.04 image work just as well. On Apple Silicon, use the arm64 image; the module is plain C and builds unchanged on arm64.

## Windows

Install Ubuntu 24.04 in VirtualBox or VMware, then follow the same commands. WSL 2 is **not** suitable: its kernel is custom-built and usually has no matching headers package.

## Running the suite in QEMU instead of a full VM

If the host is Linux (or a Linux VM) with QEMU and BusyBox installed, the suite can run in a disposable mini-VM without installing anything in it:

```bash
sudo apt install -y qemu-system-x86 busybox-static cpio linux-headers-$(uname -r)
KERNEL=/boot/vmlinuz-$(uname -r) KDIR=/lib/modules/$(uname -r)/build tests/qemu/run_qemu_tests.sh
```

If `/boot/vmlinuz-*` is not readable, copy it with `sudo cp /boot/vmlinuz-$(uname -r) /tmp/ && sudo chmod 644 /tmp/vmlinuz-*` and point `KERNEL` at the copy.

## If something goes wrong

- `insmod: Invalid module format`: the module was built against different kernel headers than the running kernel. Run `uname -r` and check that `linux-headers-<that version>` is installed, then `make clean && make`.
- `rmmod: Module pktgate is in use`: a `pktgatectl watch` is still running. Stop it first.
- `cannot open /dev/pktgate: Permission denied`: the device is root-only; use `sudo`.
- A kernel message with `BUG:` or `Oops`: reboot the VM and read `dmesg` from the previous boot (`journalctl -k -b -1`).
