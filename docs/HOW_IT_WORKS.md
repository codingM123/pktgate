# How pktgate works

A walkthrough of the module in the order a packet meets each part. Read it next to the source files; each section names the file it describes.

## 1. Where a kernel module sits

User programs cannot touch network packets directly: the kernel owns the network stack. A **loadable kernel module** is code that is linked into the running kernel with `insmod`, so it runs with full privileges inside the kernel. That is also why a bug in it can crash the machine, and why the tests run in a VM.

`pktgate_main.c` is the entry point. `module_init()` names the function that runs on `insmod`, `module_exit()` the one that runs on `rmmod`. Init sets things up in dependency order (event log, then `/proc`, then the hooks) and tears everything down in reverse if a step fails. Exit does the reverse order: the hooks are removed first, so nothing produces events while the log is being freed.

## 2. Netfilter hooks (`pktgate_hook.c`)

**Netfilter** is the framework inside the Linux network stack that iptables and nftables are built on. At five fixed points in the IPv4 path the stack calls every registered hook function and acts on its verdict:

```
                 PRE_ROUTING ──► routing ──► FORWARD ──► POST_ROUTING
  packet in ──►                     │                         ▲
                                    ▼                         │
                                LOCAL_IN                  LOCAL_OUT ◄── local socket
                                    │
                                    ▼
                               local socket
```

pktgate registers at `NF_INET_LOCAL_IN` (packets about to be delivered to a socket on this host) and `NF_INET_LOCAL_OUT` (packets a local socket has just sent). The registration is a `struct nf_hook_ops` array passed to `nf_register_net_hooks(&init_net, ...)`; priority `NF_IP_PRI_FILTER` places it at the same stage as iptables' filter table.

A hook function has the signature

```c
unsigned int hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
```

and must return a verdict: `NF_ACCEPT` lets the packet continue, `NF_DROP` frees it. For a dropped outbound packet the stack reports `EPERM` to the sending program, which is the "Operation not permitted" that `ping` prints.

### Reading the packet

The packet is a `struct sk_buff` ("skb"), the kernel's packet buffer. `ip_hdr(skb)` returns the IPv4 header, which gives the addresses, protocol and total length. The TCP/UDP ports come 20+ bytes further in, and two things make reading them non-trivial:

- An skb may be **non-linear**: its data can be spread over several memory fragments. `skb_header_pointer(skb, offset, len, &buf)` copies the requested bytes into `buf` if they are not contiguous, so the code never has to care.
- A large datagram may be **fragmented** at the IP layer, and only the first fragment carries the transport header. `ip_is_fragment()` plus the fragment offset detect the later fragments; their ports are marked unknown, and a rule that needs ports will not match them.

All multi-byte header fields are in **network byte order** (big-endian), so ports go through `ntohs()` before being compared with the host-order values in the rules. Addresses stay in network order everywhere, so no conversion is needed to compare them.

## 3. The rule table (`pktgate_rules.c`)

Rules live in a fixed array of `PKTGATE_MAX_RULES` (64) entries. A lookup walks the array and the **first match wins**; if nothing matches, the default policy applies. Each rule field set to 0 means "any", and addresses are compared under a mask:

```c
(pkt->src & r->src_mask) == (r->src & r->src_mask)
```

With a mask of 0 both sides are 0, so the comparison is always true: that is how "any address" works without a special case. A `/24` rule has the mask `255.255.255.0`, so only the first three bytes are compared.

### Locking

Two kinds of code touch the table:

- the hooks, which run for every packet. Inbound packets are processed in the **NET_RX softirq**, a context that can interrupt whatever the CPU was doing;
- `ioctl()`, which runs in ordinary **process context** when `pktgatectl` adds or deletes a rule.

If `ioctl` held a plain spinlock while a softirq arrived on the same CPU and tried to take the same lock, the softirq would spin forever waiting for code it had interrupted: a deadlock. `spin_lock_bh()` disables bottom halves (softirqs) on the local CPU while the lock is held, so this cannot happen. Every user of the lock takes the `_bh` form.

The global packet counters are `atomic64_t` instead: incrementing an atomic is cheaper than taking a lock, and the hot path only holds the lock during the lookup itself.

A spinlock is the right tool here because the critical sections are tiny and never sleep. A mutex would not work at all: a softirq cannot sleep, and taking a mutex can sleep.

## 4. The character device (`pktgate_dev.c`)

`/dev/pktgate` is a **misc device**: a character device registered with `misc_register()`, which gives it major number 10 and a minor chosen by the kernel, and makes devtmpfs/udev create the `/dev` node automatically. Its behaviour is a `struct file_operations`:

| Operation | Implementation |
|---|---|
| `open` | allocates a per-open staging buffer in `file->private_data`; `stream_open()` marks the file as a stream with no seek position |
| `release` | frees the staging buffer |
| `unlocked_ioctl` | the configuration commands |
| `read` | blocking read of event records |
| `poll` | lets `select`/`poll`/`epoll` wait for events |

`.owner = THIS_MODULE` makes the kernel hold a reference on the module while the device is open, so `rmmod` is refused until every reader has closed it.

### ioctl

`ioctl(fd, cmd, arg)` is the standard way to send typed commands to a device. Each command number is built with the `_IOW` / `_IOR` / `_IOWR` macros from a magic byte (`'G'`), a sequence number and the size of the argument structure, so a command meant for another driver is rejected (`ENOTTY`). The structures and numbers live in `include/pktgate_uapi.h`, which both the module and `pktgatectl` include; because it only uses fixed-width types (`__u32`, `__u64`), the layout is the same on both sides.

User memory cannot be touched directly from the kernel: the pointer might be invalid or not mapped. `copy_from_user()` and `copy_to_user()` do the transfer and return the number of bytes that could not be copied, which the code turns into `-EFAULT`. `ADD_RULE` is the one command that returns a positive value, the new rule's index.

### The event log: kfifo, wait queue, poll

Events are produced by the hooks (softirq context, cannot sleep) and consumed by `read()` (process context, may sleep). They meet in a **kfifo**, the kernel's ring buffer:

- `kfifo_alloc()` sizes it at load time (`event_capacity`, rounded up to a power of two);
- the hook calls `kfifo_in_spinlocked()`, which takes the fifo's spinlock, so several CPUs can log at once;
- if the buffer is full the call returns 0 and the event is counted in `events_lost`. Dropping an event is the right trade: the alternative is blocking the network stack.

`read()` works like this:

```c
while (kfifo_is_empty(&event_fifo)) {
        if (file->f_flags & O_NONBLOCK)
                return -EAGAIN;
        ret = wait_event_interruptible(event_wq, !kfifo_is_empty(&event_fifo));
        if (ret)
                return ret;               /* -ERESTARTSYS: interrupted by a signal */
}
got = kfifo_out_spinlocked(&event_fifo, tmp, want, &event_lock);
copy_to_user(buf, tmp, got * sizeof(*tmp));
```

`wait_event_interruptible()` puts the reader to sleep on the **wait queue** `event_wq` until the condition becomes true; the hook calls `wake_up_interruptible()` after every event. "Interruptible" means a signal such as Ctrl-C also wakes the reader, which is why `pktgatectl watch` stops cleanly. Events are copied out of the fifo into the per-open buffer first and only then to user space, because `copy_to_user()` may sleep on a page fault and a spinlock must never be held across a sleep.

`poll()` registers the caller on the same wait queue with `poll_wait()` and reports `EPOLLIN` when the fifo is not empty. `pktgatectl watch` opens the device non-blocking and uses `poll()` with a timeout, so it can stop after a given time instead of sleeping forever.

## 5. `/proc/net/pktgate` (`pktgate_proc.c`)

`seq_file` is the kernel's helper for text files that are generated on demand. The module only supplies a `show` function that calls `seq_printf()`; the helper handles buffering and partial reads. `%pI4` is a kernel `printk` extension that prints an IPv4 address in network byte order. The rules are copied out under the lock into a temporary `kmalloc` buffer, so the lock is not held while the text is formatted.

## 6. User space (`tools/pktgatectl.c`)

The tool is plain C with no dependencies. It parses the command line, fills the shared structures and calls `ioctl()`. `inet_pton()` converts text addresses to network byte order, and a `/N` prefix becomes a mask with `htonl(0xFFFFFFFF << (32 - N))`. `watch` opens the device with `O_NONBLOCK`, waits in `poll()`, then reads up to 64 records per call and formats them (`if_indextoname()` turns the interface index back into "lo" or "eth0").

## 7. Testing (`tests/`)

`run_tests.sh` drives the module with real traffic on the loopback interface. Loopback is convenient because a packet sent to 127.0.0.1 passes through LOCAL_OUT and then LOCAL_IN on the same machine, so both hooks are exercised without a network. `netprobe.c` is a minimal TCP/UDP client and server with timeouts, used to show that a blocked SYN makes `connect()` time out and that a blocked outbound datagram makes `sendto()` fail with `EPERM`.

`tests/qemu/run_qemu_tests.sh` packs the module, the tools and the script into an initramfs with BusyBox and boots a kernel in QEMU with no disk and no network card. The whole run takes about ten seconds, and nothing outside the VM can be affected.

## 8. Questions this project prepares you for

- *What is the difference between process context and softirq context?* Section 3.
- *Why `spin_lock_bh` and not `spin_lock` or a mutex?* Section 3.
- *What happens if a user passes a bad pointer to ioctl?* `copy_from_user` fails and the call returns `-EFAULT`; the kernel never dereferences user pointers directly.
- *How does a blocking read work?* Wait queue plus `wait_event_interruptible`; section 4.
- *Why can't you hold a spinlock across `copy_to_user`?* It may sleep on a page fault; sleeping with a spinlock held can deadlock or crash.
- *Why do ports need `ntohs()` but addresses do not?* Ports are compared with host-order integers from the command line; addresses stay in network order on both sides.
- *How would you scale beyond 64 rules?* Replace the array with a hash on the 5-tuple or a trie on addresses, and switch the lock to RCU so lookups never block on updates.
- *What does the module not protect against?* It has no connection tracking and does not see IPv6 or other network namespaces.
