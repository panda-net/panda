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

TARGETS= parser_tmpl parser_notmpl
TMPFILES= parser_notmpl.p.c parser_tmpl.p.c parser_notmpl.p.h parser_tmpl.p.h

.PHONY: all
all: $(TARGETS)

parser_notmpl.p.c: parser_notmpl.c
	$(BINDIR)/panda-compiler $< $@

parser_notmpl: parser_notmpl.p.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpcap -lpanda -lsiphash

parser_tmpl.p.c: parser_tmpl.c
	$(BINDIR)/panda-compiler $< $@

parser_tmpl: parser_tmpl.p.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpcap -lpanda -lsiphash

.PHONY: clean
clean:
	@rm -f $(TARGETS) $(TMPFILES)
