Sample DPDK Application which uses a simple PANDA parser
========================================================

This directory contains a sample app which uses the DPDK stack to snoop packets
from available DPDK driver ready interfaces (DPDK RX ports). Snooped packets
are first stored in a pcap file at default location
/tmp/dpdk_snoop_app_pdump.pcap, which can be configured using -P <location>
command line parameter (NOTE: rcv time stamp is not stored). Next packets are
passed to a simple PANDA parser for parsing and parsed info is dumped to stdout.

# panda_dpdk_snoop_app

**dpdk-snoop-app** directory contains example code for a very simple DPDK
snoop app and PANDA simple parser that extracts IP addresses and port numbers
from UDP and TCP packets and prints them to stdout along with a tuple hash.
This app listens to all the available active DPDK RX ports and stores the RX
packets to the above mentioned pcap file before sending them to the PANDA
simple parser for parsing.

To setup DPDK ports once DPDK packages and required drivers are installed,
please refer to: https://doc.dpdk.org/guides/tools/devbind.html

For more information about DPDK stack setup, please refer
https://doc.dpdk.org/guides/linux_gsg/index.html

**Minimum DPDK lib version 20.11 is required for this script to work.**

Building
--------

To build this example app:

**make PANDADIR=$(MYINSTALLDIR)**

To clean:

**make clean**

Note: Default value of PANDADIR variable is "/usr".

where MYINSTALLDIR points to the directory in which the panda target files
were installed when PANDA was built. Refer to the [PANDA README](../../../README.md) file for
for more information on this.

The DPDK dev environment is also must needed to compile and run this app.
Either install the appropriate DPDK dev. packages for the target system
**(e.g. for ubuntu 21.04: sudo apt-get install dpdk-dev libdpdk-dev)**, or
compile and install from github https://github.com/DPDK/dpdk

The PANDA parser shared libs, i.e. siphash and panda are needed at run time.
Please set LD_LIBRARY_PATH to include the lib directory from the PANDA install
location. Assuming that MYINSTALLDIR contains the path to the directory in
which PANDA was installed, the library path could be set by:

**export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(MYINSTALLDIR)/lib**

Running
-------

The executable is **panda_dpdk_snoop_app**. Run example:

**./panda_dpdk_snoop_app**

Snooped packets from dpdk ports are saved at default
/tmp/dpdk_snoop_app_pdump.pcap, which can be modified using -P <location>
command line parameter. The output in stdout prints the IP addresses and port
numbers for each IP packet, the TCP timestamps if found in the options of a TCP
packet, and the computed tuple hash.

Test scripts
------------

Please see [dpdk_snoop_app test](../../../src/test/parser/samples/dpdk_snoop_app/README.md) for scripts for testing the panda_dpdk_snoop_app.
