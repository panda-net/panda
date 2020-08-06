include ../../../config.mk

INCDIR=$(INSTALLDIR)$(HDRDIR)/panda/proto_nodes

TARGETS =

.PHONY: all
all: $(TARGETS)

.PHONY: install
install: $(TARGETS)
	@install -m 0755 -d $(INCDIR)
#	$(QUIET_INSTALL)$(INSTALL) -m 0644 $^ $(INCDIR)

.PHONY: clean
clean:
