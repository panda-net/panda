# Makefile for building parser samples
#
# Set PANDADIR to the install directory for PANDA
#

PANDADIR ?= /usr

INCDIR= $(PANDADIR)/include
LIBDIR= $(PANDADIR)/lib
BINDIR= $(PANDADIR)/bin
CC= clang
CFLAGS= -I$(INCDIR)
CFLAGS+= -g -O2
LDFLAGS=

# uapi files are not installed. If UAPI is set assume that we are in
# the simple_parser subdirectory of samples and derive a relative
# path to find src/include/uapi

ifeq ($(UAPI), 1)
CFLAGS += -I../../src/include/uapi
endif

TARGETS= flow_tracker.o
TMPFILES= parser.xdp.h

.PHONY: all
all: $(TARGETS)

parser.xdp.h: parser.c
	$(BINDIR)/panda-compiler $< $@

flow_tracker.o: xdp_tmpl.bpf.c parser.xdp.h flow_tracker.h
	$(CC) -x c -target bpf $(CFLAGS) $(LDFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(TARGETS) $(TMPFILES)
