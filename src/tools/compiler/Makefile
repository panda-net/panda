include ../../config.mk

TEMPLATES_PATH = ../../templates/panda
TEMPLATES_LIST = $(shell sed -f $(TEMPLATES_PATH)/templates.sed $(TEMPLATES_PATH)/templates.list)
TEMPLATES_SRC = $(patsubst %,%.template.c,$(TEMPLATES_LIST))

%.cpp: %.template.c
	@echo "const char* $(<F:.template.c=)_template_str = R\"(" > $@
	$(QUIET_EMBED)$(CAT) $< >> $@
	@echo ")\";" >> $@

OBJS := src/main.o src/template.o
OBJS += $(patsubst %,$(TEMPLATES_PATH)/%.o,$(TEMPLATES_LIST))
TARGETS = panda-compiler

CXXFLAGS += -Iinclude -std=c++17 $(CFLAGS_PYTHON)
BOOST_LIBS ?= -lboost_wave -lboost_thread -lboost_filesystem -lboost_system

LIBS ?= -lpthread -ldl -lutil

panda-compiler: $(OBJS)
	$(CXX) $^ -o $@ $(BOOST_LIBS) $(LDFLAGS_PYTHON) $(LIBS)

all: $(TARGETS)

.PHONY: install
install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $^ $(INSTALLDIR)$(BINDIR)

.PHONY: clean
clean:
	@rm -f $(OBJS) $(TARGETS)
