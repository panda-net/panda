PANDADIR ?= $(realpath ..)
INSTALLDIR ?= /usr/lib/modules/$(shell uname -r)/extra
TARGETS := cls_panda.ko

.PHONY: all
all: $(TARGETS)

cls_panda.ko:
	$(MAKE) -C $(KDIR) M=$(shell pwd) PANDADIR=$(PANDADIR)

.PHONY: clean
clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

.PHONY: modules_install
modules_install: all
	@install -m 0755 -d $(INSTALLDIR)
	install -m 0644 $(TARGETS) $(INSTALLDIR)
	depmod
