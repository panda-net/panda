# Makefile for building parser samples
#
# Set PANDADIR to the install directory for PANDA
#

SRC = $(shell realpath ../../../src/)
PANDADIR ?= /usr

INCDIR= $(PANDADIR)/include
LIBDIR= $(PANDADIR)/lib
BINDIR= $(PANDADIR)/bin
CC= gcc
CFLAGS= -I$(INCDIR)
LDFLAGS= -L$(LIBDIR)
KDIR ?= /lib/modules/$(shell uname -r)/build
INSTALLDIR ?= /lib/modules/$(shell uname -r)/extra

# We depend on the classifier's symbols
CLS_SYMBOLS ?= $(SRC)/kernel/Module.symvers

TARGETS= panda_big.ko
TMPFILES= parser.kmod.c

.PHONY: all
all: $(TARGETS)

$(CLS_SYMBOLS):
	$(MAKE) -C $(SRC) kernel KDIR=$(KDIR)

parser.kmod.c: bigparser.c
	$(BINDIR)/panda-compiler $< $@

panda_big.ko: $(CLS_SYMBOLS) parser.kmod.c
	$(MAKE) -C $(KDIR) M=$(shell pwd) KBUILD_EXTRA_SYMBOLS=$(CLS_SYMBOLS) PANDADIR=$(PANDADIR)

.PHONY: clean
clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@
	@rm -f $(TARGETS) $(TMPFILES)

.PHONY: modules_install
modules_install: $(TARGETS)
	@install -m 0755 -d $(INSTALLDIR)
	install -m 0644 $(TARGETS) $(INSTALLDIR)
	depmod
