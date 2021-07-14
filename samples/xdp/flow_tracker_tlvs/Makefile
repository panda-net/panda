# Makefile for building parser samples
#
# Set PANDADIR to the install directory for PANDA
#

PANDADIR ?= /usr

INCDIR= $(PANDADIR)/include
LIBDIR= $(PANDADIR)/lib
BINDIR= $(PANDADIR)/bin
PANDACOMPILER ?= $(BINDIR)
XCC= clang
XCFLAGS= -I$(INCDIR)
XCFLAGS+= -g -O2
XLDFLAGS=

# uapi files are not installed. If UAPI is set assume that we are in
# the simple_parser subdirectory of samples and derive a relative
# path to find src/include/uapi

ifeq ($(UAPI), 1)
XCFLAGS += -I../../src/include/uapi
endif

TARGETS= flow_tracker.xdp.o
TMPFILES= parser.xdp.h

.PHONY: all
all: $(TARGETS)

parser.xdp.h: parser.c
	$(PANDACOMPILER)/panda-compiler $< $@

flow_tracker.xdp.o: flow_tracker.xdp.c parser.xdp.h flow_tracker.h
	$(XCC) -save-temps -fverbose-asm -x c -target bpf $(XCFLAGS) $(XLDFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(TARGETS) $(TMPFILES)
