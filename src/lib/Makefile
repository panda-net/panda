include ../config.mk

TOPTARGETS := all clean install

SUBDIRS = siphash flowdis panda parselite

$(TOPTARGETS) : $(SUBDIRS)

$(SUBDIRS):
	@make -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

