TOPDIR := $(realpath ..)

.PHONY: all
all:
	$(MAKE) -C $(KDIR) M=$(shell pwd) PANDADIR=$(TOPDIR)

.PHONY: clean
clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

.PHONY: modules_install
modules_install:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

.PHONY: install
install:

