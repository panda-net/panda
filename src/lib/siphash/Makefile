include ../../config.mk

CFLAGS += -fPIC

UTILOBJ = siphash.o

TARGETS = libsiphash.so libsiphash.a

.PHONY: all
all: $(TARGETS)

LDFLAGS +=

libsiphash.a: $(UTILOBJ) $(ADDLIB)
	$(QUIET_AR)$(AR) rcs $@ $^

libsiphash.so: $(UTILOBJ) $(ADDLIB)
	$(CC) -shared $^ -o $@

.PHONY: install
install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $^ $(INSTALLDIR)$(LIBDIR)

.PHONY: clean
clean:
	@rm -f $(UTILOBJ) $(ADDLIB) $(TARGETS)
