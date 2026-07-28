# Kbuild fragment: the kernel build system reads these when it includes this
# file via `make -C $(KDIR) M=$(CURDIR) modules`.
obj-m += nemclass_mod.o
nemclass_mod-y := src/main.o src/memory_access.o src/debugger.o src/access.o
ccflags-y += -I$(src)/include/uapi

# Standalone / DKMS driver targets. Do NOT gate `all` on KERNELRELEASE: DKMS runs
# `make all KERNELRELEASE=<ver> KDIR=...`, so a KERNELRELEASE guard would send the
# DKMS build into a no-op and produce no .ko (which then reports "build failed").
# `all` recurses with an explicit `modules` goal, so Kbuild's include of this file
# during that recursion never re-triggers `all` (no infinite loop).
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean