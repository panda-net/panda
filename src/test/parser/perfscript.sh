#!/bin/bash

# Must be run from src/test/parser directory
ROOT=../../../data/pcaps

# pcaps
PCAPS="icmp_ipv4 icmp_ipv6 tcp_ipv4 tcp_ipv6 6in4 6to4 ipip vlan_icmp"

# cores
CORES="panda pandaopt pandaopt_notcpopts flowdis parselite"
for p in $PCAPS
do
	f=$ROOT/$p.pcap

	for t in $CORES
	do
		echo ""
		echo "$t: $f"
		echo "------------------------------------"
		echo "running throwaway $t test"
		./test_parser -v -n 1000000 -i pcap,$f -c $t -o null > /dev/null
		echo "running throwaway $t test"
		./test_parser -v -n 1000000 -i pcap,$f -c $t -o null > /dev/null
		./test_parser -v -n 1000000 -i pcap,$f -c $t -o null
	done
done

