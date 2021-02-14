include ../../../config.mk

INCDIR=$(INSTALLDIR)$(HDRDIR)/panda/proto_nodes

TARGETS = proto_ether.h proto_ipv4.h proto_ipv6.h proto_ports.h
TARGETS += proto_tcp.h proto_ip.h proto_ipv6_eh.h proto_ipv4ip.h
TARGETS += proto_ipv6ip.h proto_gre.h proto_vlan.h proto_icmp.h
TARGETS += proto_ppp.h proto_mpls.h proto_arp_rarp.h proto_tipc.h

.PHONY: all
all: $(TARGETS)

.PHONY: install
install: $(TARGETS)
	@install -m 0755 -d $(INCDIR)
	$(QUIET_INSTALL)$(INSTALL) -m 0644 $^ $(INCDIR)

.PHONY: clean
clean:
