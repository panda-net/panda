# Makefile for building parser samples
#
# Set ROOTDIR to the install directory for PANDA
#

ROOTDIR ?= /usr

INCDIR= $(ROOTDIR)/include
LIBDIR= $(ROOTDIR)/lib
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

.PHONY: all
all: $(TARGETS)

parser_notmpl: parser_notmpl.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpcap -lpanda -lsiphash

parser_tmpl: parser_tmpl.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpcap -lpanda -lsiphash

.PHONY: clean
clean:
	@rm -f $(TARGETS)
