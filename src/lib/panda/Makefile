include ../../config.mk
include parsers.mk

CFLAGS += -fPIC

UTILOBJ = parser.o pcap.o

# Parser files are in parsers subdirectory

PARSERDIR = parsers

PARSEROBJSEXT = $(addprefix $(PARSERDIR)/, $(PARSEROBJS))

ALLOBJS = $(UTILOBJ)

TARGETS = libpanda.so libpanda.a

.PHONY: all
all: $(TARGETS)

ifeq ($(OPTIMIZED_PARSER),n)
PARSEROSEXT = $(addprefix $(PARSERDIR)/, $(PARSEROBJS))
else

PARSERCSEXT = $(PARSEROBJSEXT:.o=.p.c)
PARSEROSEXT = $(PARSEROBJSEXT:.o=.p.o)

$(PARSERCSEXT): %.p.c: %.c
	../../tools/compiler/panda-compiler $< $@
endif

CFLAGS += -I.
ALLOBJS += $(PARSEROSEXT)

libpanda.a: $(ALLOBJS) $(ADDLIB)
	$(QUIET_AR)$(AR) rcs $@ $^

libpanda.so: $(ALLOBJS) $(ADDLIB)
	$(CC) -shared $^ -o $@ -lpcap

.PHONY: install-libs
install-libs: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $^ $(INSTALLDIR)$(LIBDIR)

.PHONY: install
install: install-libs

.PHONY: clean
clean:
	@rm -f $(ALLOBJS) $(ADDLIB) $(TARGETS) $(PARSERCSEXT) $(PARSEROSEXT)
