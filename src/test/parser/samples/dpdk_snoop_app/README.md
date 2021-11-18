Test scripts for dpdk_snoop_app
===============================

These test scripts can be used to verify the operation of the
[dpdk_snoop_app](../../../../../samples/dpdk/dpdk-snoop-app/README.md).

## Requirements :

- System :
  - Ubuntu 21.04 (Hirsute Hippo)
  - x86 architecture

- Install python3
- **Command:** sudo apt install python python3-pip python3-dev

- Install the following python modules
  - pandas
  - pyshark
  - scapy
  - **Command:** pip3 install pandas pyshark scapy

## Syntax :

python3 ./test_case.py arg1 arg2

#### Note :

- arg1 is the pcap file of dpdk_snoop_app.
- arg2 is the stdout text file of dpdk_snoop_app.

If the two input files produces the same output then the test case will be successful otherwise will be failed.

**Example :**

For testing of the test_case.py use following pre-recorded two sample files -
**1.sample_dpdk_pdump.pcap** - pcap file of dpdk_snoop_app
**2.sample_panda_parser_output** - stdout text file of dpdk_snoop_app

**syntax:** python3 test_case.py sample_dpdk_pdump.pcap sample_panda_parser_output




