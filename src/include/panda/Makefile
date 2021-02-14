include ../../config.mk

TOPTARGETS := all clean install

SUBDIRS = proto_nodes parsers

$(TOPTARGETS) : $(SUBDIRS)

$(SUBDIRS):
	@make -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

INCDIR=$(INSTALLDIR)$(HDRDIR)/panda

TARGETS= utility.h parser.h proto_nodes.h proto_nodes_def.h
TARGETS += parser_metadata.h

install: $(TARGETS)
	@install -m 0755 -d $(INCDIR)
	$(QUIET_INSTALL)$(INSTALL) -m 0644 $(TARGETS) $(INCDIR)
