include ../../config.mk
include parsers.mk

CFLAGS += -fPIC

UTILOBJ = parser.o pcap.o

# Parser files are in parsers subdirectory

PARSERDIR = parsers

PARSEROBJSEXT = $(addprefix $(PARSERDIR)/, $(PARSEROBJS))

ALLOBJS = $(UTILOBJ) $(PARSEROBJSEXT)

TARGETS = libpanda.so libpanda.a

.PHONY: all
all: $(TARGETS)

libpanda.a: $(ALLOBJS) $(ADDLIB)
	$(QUIET_AR)$(AR) rcs $@ $^

libpanda.so: $(ALLOBJS) $(ADDLIB)
	$(CC) -shared $^ -o $@

.PHONY: install
install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $^ $(INSTALLDIR)$(LIBDIR)

.PHONY: clean
clean:
	@rm -f $(ALLOBJS) $(ADDLIB) $(TARGETS)
