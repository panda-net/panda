include ../../config.mk

COMPDIR=../../tools/compiler

ifneq ($(OPTIMIZED_PARSER),n)
CORES_LIST = cores.list
else
CORES_LIST = cores-nonopt.list
endif

IMETHODS != sed -f method.sed < imethods.list
IMETHODS_OBJ := $(foreach m,$(IMETHODS),in-$(m).o)
OMETHODS != sed -f method.sed < omethods.list
OMETHODS_OBJ := $(foreach m,$(OMETHODS),out-$(m).o)
CORES != sed -f method.sed < $(CORES_LIST)
CORES_OBJ := $(foreach m,$(CORES),core-$(m).o)

CFLAGS += -I../../lib/panda

OBJ = $(CORES_OBJ) $(IMETHODS_OBJ) $(OMETHODS_OBJ)		\
      cores.o imethods.o main.o omethods.o

LIBS = -lpcap ../../../src/lib/flowdis/libflowdis.a		\
       ../../../src/lib/panda/libpanda.a			\
       ../../../src/lib/parselite/libparselite.a		\
       ../../../src/lib/siphash/libsiphash.a

CLEANFILES = $(OBJ)

CLEANFILES += $(patsubst %.p,core-%.p.c,$(filter %.p,$(CORES)))
CLEANFILES += $(patsubst %.p,core-%.p.h,$(filter %.p,$(CORES)))

TARGETS = test_parser

.PHONY: all
all: $(TARGETS)

%.p.c: %.c
	$(COMPDIR)/panda-compiler $< $@

test_parser: $(OBJ)
	$(CC) $(LDFLAGS) -o test_parser $(OBJ) $(LIBS)

CLEANFILES += test_parser

.PHONY: install
install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $^ $(INSTALLDIR)$(BINDIR)

.PHONY: clean
clean:
	rm -f $(CLEANFILES)

main.o: imethods.inc omethods.inc cores.inc

imethods.o: imethods.inc

omethods.o: omethods.inc

cores.o: cores.inc

imethods.inc: imethods.list
	< imethods.list sed -f method_strip.sed | sed -e 's@.*@__CORE_IOP(&)@' > imethods.inc || rm -f imethods.inc
CLEANFILES += imethods.inc
PREDEPEND += imethods.inc

omethods.inc: omethods.list
	< omethods.list sed -f method_strip.sed | sed -e 's@.*@__CORE_OOP(&)@' > omethods.inc || rm -f omethods.inc
CLEANFILES += omethods.inc
PREDEPEND += omethods.inc

cores.inc: $(CORES_LIST)
	< $(CORES_LIST) sed -f method_strip.sed | sed -e 's@.*@__CORE_OP(&)@' > cores.inc || rm -f cores.inc
CLEANFILES += cores.inc
PREDEPEND += cores.inc
