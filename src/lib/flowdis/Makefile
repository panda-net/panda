include ../../config.mk

CFLAGS += -fPIC

UTILOBJ = flow_dissector.o

TARGETS = libflowdis.so libflowdis.a

.PHONY: all
all: $(TARGETS)

libflowdis.a: $(UTILOBJ) $(ADDLIB)
	$(QUIET_AR)$(AR) rcs $@ $^

libflowdis.so: $(UTILOBJ) $(ADDLIB)
	$(CC) -shared $^ -o $@

.PHONY: install
install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $^ $(INSTALLDIR)$(LIBDIR)

.PHONY: clean
clean:
	@rm -f $(UTILOBJ) $(ADDLIB) $(TARGETS)
