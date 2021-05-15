Sample standalone parsers
=========================

This directory contains sample standalone parsers

# simple_parser

**simple_parser** contains two examples of code for a very simple
parser that extracts IP addresses and port numbers from UDP and TCP packets and
prints the information as well as a tuple hash. There are two variants,
**parser_tmpl** that uses metadata templates and **parser_notmpl** that does
not use metadata templates (see PANDA Parser [document](documentation/parser.md)
for description of metadata templates and their usage).

To build the simple_parser examples:

**make PANDADIR=$(MYINSTALLDIR)**

where MYINSTALLDIR is to the path for the directory in which the target files
were installed when building PANDA.

The parser binaries load the siphash and panda shared libraries at run time.
Please set LD_LIBRARY_PATH to include the lib directory the directory where
PANDA files were installed. Assuming that MYINSTALLDIR contains the path
to the directory in which PANDA was install, the library path could be set by :

**export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(MYINSTALLDIR)/lib**

The executables are **parser_tmpl** and **parser_notmpl**. They both take one
command line argument that is a pcap file. For example:

**./parser_tmpl test.pcap**

and

**./parser_notmpl test.pcap**

The output prints the IP address and port numbers for each packet, the
TCP timestamps if found in the options of a TCP packet, and the computed
tuple hash. For the same pcap file, **parser_tmpl** and **parser_notmpl**
should produce identical output.
