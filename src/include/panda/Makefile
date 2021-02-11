include ../../config.mk

TOPTARGETS := all clean install

TARGETS= utility.h

INCDIR=$(INSTALLDIR)$(HDRDIR)/panda

all: $(TARGET)

install: $(TARGETS)
	@install -m 0755 -d $(INCDIR)
	$(QUIET_INSTALL)$(INSTALL) -m 0644 $(TARGETS) $(INCDIR)

clean:
