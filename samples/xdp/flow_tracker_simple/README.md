flow_tracker sample application
================================

This directory contains an example of code for a very simple
flow tracker that extracts IP addresses and port numbers from
TCP packets in XDP and stores them in a hash table.
Note: flow_tracker is described [here](../../../documentation/xdp.md).

To build the flow_tracker example:

cd to this directory (**samples/xdp/flow_tracker_simple**) and invoke make:

**make PANDADIR=$(MYINSTALLDIR)**

where MYINSTALLDIR is to the path for the directory in which the target files
were installed when building PANDA.

An object file **flow_tracker.xdp.o** will be created.

Load the object file into XDP:

**sudo ip link set dev \<device\> xdp obj flow_tracker.xdp.o verbose**

where `<device>` is your network device (example `eno1`, `lo` etc).

Check if the binary was loaded:

**sudo ip link ls dev \<device\>**

You should see the output annotated with "xdp" or "xdpgeneric".

Verify that the maps are loaded with `bpftool`.

```
$ bpftool map -f
7: hash  flags 0x0
        key 16B  value 8B  max_entries 32  memlock 4096B
        pinned /sys/fs/bpf/tc/globals/flowtracker
8: percpu_array  flags 0x0
        key 4B  value 224B  max_entries 2  memlock 8192B
        pinned /sys/fs/bpf/tc/globals/ctx_map
9: prog_array  flags 0x0
        key 4B  value 4B  max_entries 1  memlock 4096B
        owner_prog_type xdp  owner jited
        pinned /sys/fs/bpf/tc/globals/parsers
```

Observe that id "7" is the flowtracker map id

generate a few TCP packets (example ssh etc)

Now display the flowtracker:

```
$ sudo bpftool map dump id 7
key: 3f 74 f3 61 c0 a8 01 03  00 50 e5 c0 06 00 00 00  value: 4e 00 00 00 00 00 00 00
Found 1 element
```

The key is the memory dump of our `struct flowtuple` tuple and the
value is the memory dump of our `__u64` counter.

To unload the program and maps, you may do the following.

Unload the binary:

**sudo ip link set dev \<device\> xdp off**

Remove the BPF maps:

**sudo rm -rfv /sys/fs/bpf/tc/globals**
