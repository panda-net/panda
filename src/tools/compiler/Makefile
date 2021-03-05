include ../../config.mk

OBJS = src/main.o
TARGETS = panda-compiler

CXXFLAGS += -Iinclude -std=c++17
BOOST_LIBS ?= -lboost_wave -lboost_thread -lboost_filesystem -lboost_system

panda-compiler: $(OBJS)
	$(CXX) $^ -o $@ $(BOOST_LIBS)

all: $(TARGETS)

.PHONY: install
install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $^ $(INSTALLDIR)$(BINDIR)

.PHONY: clean
clean:
	@rm -f $(OBJS) $(TARGETS)
