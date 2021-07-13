PANDADIR ?= $(realpath ..)
TARGETS := cls_panda.ko

.PHONY: all
all: $(TARGETS)

cls_panda.ko:
	$(MAKE) -C $(KDIR) M=$(shell pwd) PANDADIR=$(PANDADIR)

.PHONY: clean
clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

.PHONY: modules_install
modules_install:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

.PHONY: install
install:

