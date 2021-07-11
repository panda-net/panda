# Makefile for building parser samples
#
# Set PANDADIR to the install directory for PANDA
#

PANDADIR ?= /usr

INCDIR= $(PANDADIR)/include
LIBDIR= $(PANDADIR)/lib
BINDIR= $(PANDADIR)/bin
CC= gcc
CFLAGS= -I$(INCDIR)
LDFLAGS= -L$(LIBDIR)
KDIR ?= /lib/modules/`uname -r`/build

TARGETS= panda_big
TMPFILES= parser.kmod.c

.PHONY: all
all: $(TARGETS)

parser.kmod.c: bigparser.c
	$(BINDIR)/panda-compiler $< $@

panda_big: parser.kmod.c
	$(MAKE) -C $(KDIR) M=$(shell pwd) PANDADIR=$(PANDADIR)

.PHONY: clean
clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@
	@rm -f $(TARGETS) $(TMPFILES)

.PHONY: modules_install
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@
