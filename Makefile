# pktgate - top-level build
#
#   make            build the kernel module and the user-space tools
#   make module     build kernel/pktgate.ko against the running kernel's headers
#   make tools      build tools/pktgatectl and tests/netprobe
#   make test       run the end-to-end tests (needs root, loads the module)
#   make clean
#
# Build against a different kernel with: make KDIR=/path/to/kernel/build

KDIR   ?= /lib/modules/$(shell uname -r)/build
CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=gnu11
CPPFLAGS += -Iinclude

all: module tools

module:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel modules

tools: tools/pktgatectl tests/netprobe

tools/pktgatectl: tools/pktgatectl.c include/pktgate_uapi.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@

tests/netprobe: tests/netprobe.c
	$(CC) $(CFLAGS) $< -o $@

test: all
	sudo tests/run_tests.sh

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel clean
	rm -f tools/pktgatectl tests/netprobe

.PHONY: all module tools test clean
