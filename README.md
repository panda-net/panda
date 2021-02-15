PANDA (Protocol And Network Datapath Acceleration)
==================================================

<img src="documentation/images/Hop.png" alt="Hop the Panda Logo" align="right"/>

**P**rotocol and **N**etwork **D**atapath **A**cceleration, or **PANDA**, is a
software programming model, framework, set of libraries, and an API used
to program serial data processing. In networking, PANDA is applied to
optimize packet and protocol processing.

The inaugural sub-feature of PANDA is the **PANDA Parser**. The PANDA Parser
is a framework and API for programming protocol parser pipelines. Protocol
parsing is a fundamental operation in network processing and is best programmed
via a declarative representation instead of a traditional imperative
representation via a sequence of instructions. In PANDA, a parser is defined
by a set of data structures and embedded functions that instantiate a
customizable parse graph for a particular use case. The PANDA Parser is
described [here](documentation/parser.md).

# Description

This repository contains the code base for the PANDA project. The PANDA code
is composed of a number of C libraries, include files for the API, test code,
and sample code.

There are four libraries:

* **panda**: the main library that implements the PANDA programming model
	 and the PANDA Parser
* **siphash**: a port of the siphash functions to userspace
* **flowdis**: contains a port of kernel flow dissector to userspace
* **parselite**: a simple handwritten parser for evaluation

# Directory structure

The top level directories are:

* **src**: contains source code for libraries, the PANDA API, and test code
* **samples**: contains standalone example applications that use the PANDA API
* **documentation**: contains documentation for PANDA

The subdirectories of **src** are:

* **lib**: contains the code for the PANDA libraries. The lib directory has
subdirectories:
	* **panda**: The main PANDA library
	* **flowdis**: Flow dissector library
	* **parselite**: A very lightweight parser
	* **siphash**: Port of siphash library to userspace

* **include**: contains the include files of the PANDA API. The include
directory has subdirectories
	* **panda**: General utility functions, header files, and API for the
	  PANDA library
	* **flowdis**: Header files for the flowdis library
	* **parselite**: Header files for the parselite library
	* **siphash**: Header files for the siphash library
	* **uapi**: "User API" header files. These are a set of C headers that
	  may be used when compiling against an older glibc or kernel version
	  that does not have some definitions needed by PANDA that are in later
	  versions glibc or the kernel. For use of these header files see the
	  notes for building below.

	For usage of the **flowdis**, **parselite**, and **siphash** libraries,
	see the include files in the corresponding directory of the library.
	For **panda**, see the include files in the panda include directory as
	well as the PANDA parser [document](documentation/parser.md).

* **test**: contains related tests for PANDA. Subdirectory is:
	* **parser** contains code and scripts for testing the PANDA
	  parser, flowdis parser, and parselite parsers

The subdirectories of **samples** are:

* **simple_parser**: Standalone example of a minimal functionality parser

# Building

Building of the main libraries and code is performed by doing make in the
**src** directory:

**cd src**

**./configure**

**make**

The compiled libraries, header files, and binaries may be installed in a
specified directory:

**make INSTALLDIR=$(MYINSTALLDIR) install**

To get verbose output from make add **V=1** to the command line. To include the
uapi files use **UAPI=1** (see note below). For example,

**make INSTALLDIR=$(MYINSTALLDIR) V=1 UAPI=1 install**

builds the with verbose output from make, includes the uapi files, and
install the target files in the given install directory (set in
MYINSTALLDIR)

*Note that the uapi files (i.e. build with **UAPI=1**) should preferably be
included only if the build system does not have up to date header files (this
can happen with an older version of glibc or older kernel version). It is
recommended to try building without the uapi includes and if that fails then
try including the uapi files (if the glibc or kernel includes are out of date
then compilation will likely fail with a number of errors for undefined names).*

# Basic validation testing

To perform basic validation of the parser do

**cd src/test/parser**

**run-tests.sh**

The output should show the the parsers being run with no reported diffs or
other errors.

For more information please see [testing](documentation/test-parser.md).

# Sample standalone parsers

**samples/simple_parser** contains two examples of code for a very simple
parser that extracts IP addresses and port numbers from UDP and TCP packets and
prints the information as well as a tuple hash. There are two variants,
**parser_tmpl** that uses metadata templates and **parser_notmpl** that does
not use metadata templates (see PANDA Parser [document](documentation/parser.md)
for description of metadata templates and their usage).

To build the simple_parser examples:

**cd samples/simple_parser**

**make ROOTDIR=$(MYINSTALLDIR)**

where MYINSTALLDIR is the directory in which the target files were installed
when building PANDA.

The executables are **parser_tmpl** and **parser_notmpl**. They both take one
command line argument that is a pcap file. For example:

**./parser_tmpl test.pcap**

and

**./parser_notmpl test.pcap**

The output prints the IP address and port numbers for each packet, the
TCP timestamps if found in the options of a TCP packet, and the computed
tuple hash. For the same pcap file, **parser_tmpl** and **parser_notmpl**
should produce identical output.

*If the build fails the uapi includes files may be used by doing
**make UAPI=1**. The uapi include files are not installed as part of
building PANDA, so a relative path to the uapi source include files is
set up by the Makefile (../../src/include/uapi). Note that is assumes that the
make is being done from that simple_parser directory.*
