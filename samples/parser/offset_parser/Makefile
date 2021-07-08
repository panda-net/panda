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
CFLAGS+= -g
LDFLAGS= -L$(LIBDIR)

# uapi files are not installed. If UAPI is set assume that we are in
# the simple_parser subdirectory of samples and derive a relative
# path to find src/include/uapi

ifeq ($(UAPI), 1)
CFLAGS += -I../../src/include/uapi
endif

TARGETS= parser
TMPFILES= parser.p.c parser.p.h

.PHONY: all
all: $(TARGETS)

parser.p.c: parser.c
	$(BINDIR)/panda-compiler $< $@

parser: parser.p.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpcap -lpanda

.PHONY: clean
clean:
	@rm -f $(TARGETS) $(TMPFILES)
