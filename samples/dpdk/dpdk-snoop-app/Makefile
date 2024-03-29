# Makefile for building dpdk-panda app samples
#

# dpdk dev env related starts
PKGCONF ?= pkg-config
# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
    $(error "no installation of DPDK found")
endif

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O0 -g $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
CFLAGS += -DALLOW_EXPERIMENTAL_API
# dpdk dev env related ends

# Set PANDADIR to the install directory for PANDA
PANDADIR ?= /usr

DPDK_VER := $(shell $(PKGCONF) --modversion libdpdk)
DPDK_VER_ISGT20 := $(shell echo `$(PKGCONF) --modversion libdpdk | cut -f1-2 -d.` \< 20.11 | bc )
ifeq ($(DPDK_VER_ISGT20),1)
    $(error Present DPDK pkg version is [${DPDK_VER}], which should be atleast 20.11)
endif

INCDIR= $(PANDADIR)/include
LIBDIR= $(PANDADIR)/lib
BINDIR= $(PANDADIR)/bin
CC= gcc
CFLAGS+= -I$(INCDIR)
CFLAGS+= -g
LDFLAGS+= -L$(LIBDIR)

# uapi files are not installed. If UAPI is set assume that we are in
# the simple_parser subdirectory of samples and derive a relative
# path to find src/include/uapi

ifeq ($(UAPI), 1)
    CFLAGS += -I../../../src/include/uapi
endif

TARGETS= dpdk_snoop_app.o panda_dpdk_snoop_app
TMPFILES= main.p.c main.p.h

.PHONY: all
all: $(TARGETS)

dpdk_snoop_app.o: dpdk_snoop_app.c
	$(CC) $(CFLAGS) -c dpdk_snoop_app.c -o $@

main.p.c: main.c
	$(BINDIR)/panda-compiler $< $@

panda_dpdk_snoop_app: main.p.c
	$(CC) $(CFLAGS) $(LDFLAGS) dpdk_snoop_app.o -o $@ $< -lpcap -lpanda -lsiphash -latomic $(LDFLAGS_SHARED) $(PC_FILE)

.PHONY: clean
clean:
	@rm -f $(TARGETS) $(TMPFILES)
