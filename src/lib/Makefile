include ../config.mk

TOPTARGETS := all clean install

SUBDIRS = siphash flowdis

$(TOPTARGETS) : $(SUBDIRS)

$(SUBDIRS):
	@make -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

