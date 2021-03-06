# Makefile for building parser samples
#
# Set PANDADIR to the install directory for PANDA
#

PANDADIR ?= /usr

INCDIR= $(PANDADIR)/include
LIBDIR= $(PANDADIR)/lib
BINDIR= $(PANDADIR)/bin

XCC= clang
XCFLAGS= -I$(INCDIR)
XCFLAGS+= -g -O2
XLDFLAGS=

CC= gcc
CFLAGS= -I$(INCDIR)
CFLAGS+= -g
LDFLAGS= -L$(LIBDIR)

# uapi files are not installed. If UAPI is set assume that we are in
# the simple_parser subdirectory of samples and derive a relative
# path to find src/include/uapi

ifeq ($(UAPI), 1)
CFLAGS += -I../../src/include/uapi
XCFLAGS += -I../../src/include/uapi
endif

TARGETS= flow_tracker.xdp.o flow_parser
TMPFILES= parser.xdp.h parser.p.c parser.p.h

.PHONY: all
all: $(TARGETS)

parser.xdp.h: parser.c
	$(BINDIR)/panda-compiler $< $@

flow_tracker.xdp.o: flow_tracker.xdp.c parser.xdp.h
	$(XCC) -x c -target bpf $(XCFLAGS) $(XLDFLAGS) -c -o $@ $<

parser.p.c: parser.c
	$(BINDIR)/panda-compiler $< $@

flow_parser: flow_parser.c parser.p.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ flow_parser.c parser.p.c -lpcap -lpanda

.PHONY: clean
clean:
	@rm -f $(TARGETS) $(TMPFILES)
