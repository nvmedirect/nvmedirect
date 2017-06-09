KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)

KERNEL_VERSION_MAJOR = $(shell $(MAKE) -C $(KERNELDIR) -s kernelversion | cut -f1 -d.)
KERNEL_VERSION_MINOR = $(shell $(MAKE) -C $(KERNELDIR) -s kernelversion | cut -f2 -d.)
KERNEL_VERSION_PATCH = $(shell $(MAKE) -C $(KERNELDIR) -s kernelversion | cut -f3 -d.)

obj-m   := nvmed.o
nvmed-objs := nvmed-core.o nvmed-intr.o

default:
		$(MAKE) -C $(KERNELDIR) EXTRA_CFLAGS="-DKERNEL_VERSION_MAJOR=$(KERNEL_VERSION_MAJOR) -DKERNEL_VERSION_MINOR=$(KERNEL_VERSION_MINOR) -DKERNEL_VERSION_PATCH=$(KERNEL_VERSION_PATCH)" SUBDIRS=$(PWD) modules

install:
	   $(MAKE) -C $(KERNELDIR) SUBDIRS=$(PWD) modules_install

clean:
	   $(MAKE) -C $(KERNELDIR) SUBDIRS=$(PWD) clean
