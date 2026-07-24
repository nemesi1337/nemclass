obj-m += nemclass_mod.o
nemclass_mod-y := src/main.o src/memory_access.o src/debugger.o
ccflags-y += -I$(src)/include/uapi

# DKMS sets KERNELRELEASE automatically during compilation
ifdef KERNELRELEASE
all:
	# No-op when called inside the kernel build system
else
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
endif