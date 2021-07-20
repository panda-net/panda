Version 1.3
===========

Major features
--------------

    * PANDA Parser in the kernel

	* Add support in PANDA compiler the Linux kernel. If output file
	  argument has a mod.c suffix the panda-compiler will build kernel code
	  A .mod.c file can then be linked with a source file that contains
	  necessary kernel module glue to build a installable .ko. The
	  module glue code calls panda_parse to invoke the in-kernel PANDA
	  parser.
	* Define the PANDA TC classifier, panda_cls, in samples to demonstrate
	  the use and operation of PANDA in the kernel.

    * Use C file templates in the panda-compiler

	* Refactor the panda-compiler to take C file templates as input
	  rather than outputting lines of C code from C++ (i.e. cout).

Other features
--------------

	* Implement parser tables that allow mapping a value, probably a
	  protocol number, to a parser. A side effect is that we removed
	  the API to invoke a parser to start at some some node, instead
	  different parsers can be created for the different start nodes
	  being used
	* Support for TLV overlay parse nodes. This simplifies handling of
	  variable length TLVs such as the TCP SACK option.
	* Add panda_ctrl_data to hold control metadata as input to the
	  PANDA parser unctions. This carries the length of the current
	  header, the offset of the current header relative to the start
	  of the packet, etc.
	* Make option to not build the optimized parsers (OPTIMZED_PARSER=n)
	* Replace the call back function unknown_next_protocol with a
	  wildcard node. When a lookup fails and the wildcard is not NULL
	  for a parse node, then use the wildcard as the next node.
	* Change TLV handling overlay TLV handling to use wildcards instead
	  unknown handler functions
	* Remove post handlers from parse nodes, the functionality can
	  be provided by using wildcard or overlay nodes.
	* Remove check_length function in TLV parse nodes. We introduce
	  protocol nodes for individual TLV types. When parsing a TLV node,
	  the TLV length is compared against the min_len fied if there is an
	  associated protocol node for the parse TLV node
	* offset_parser: A simple parser in samples/parser/offset_parser
	  that just extracts the network layer and transport layer offsets
	  from a packet
	* Refactor the PANDA include header files to make them more
	  modular and cleaner
	* Define some new utilities include ntohll, htonll, PANDA_ASSET
	* Change the proto_ports structure to be a union so that we can
	  access both ports in one u32
	* Add flow_tracer_tlvs sample that extracts IP addresses and port
	  numbers from TCP packets in XDP and stores them in a hash table.
	* Add installation script for Ubunutu
	* Add a pcap file to sample pcap files that has packets with TCP SACKs
	* Clean up IPv6 and IPv4 length check code in their protocol nodes
	* Add setting of Python version in configure

Bug fixes
---------

	* Remove unnecessary check length in GREv0 protocol node
	* panda-compiler fixes
	* Fix copyright notices

Version 1.2
===========

Major features
--------------

    * PANDA Parser in XDP

	* Add support in PANDA compiler for XDP. If output file argument
	  has an XDP suffix the panda-compiler with build XDP code
	* Add document xdp.md to document PANDA in XDP
	* Add and XDP program template in xdp_tmpl.h that provides a
	  helper macro for create and XDP program that invokes the PANDA
	  parser and processes the returned metadata. The template handles
	  hides tail calls in eBPF that may be necessary to satisfy the
	  verifier for complexity limits
	* Sample XDP programs in samples/xdp. All of these are based on
	  a root flow_tracker program that is described in xdp.md.
	  flow_tracker_simple is a "simple" XDP program for flow_tracker,
	  flow_tracker_tmpl is basically the same a flow_tracker_simple but
	  employs the XDP program template instead of including the
	  code. flow_tracker_combo also uses the XDP program template and
	  creates a flow_parser application that uses the same PANDA parser
	  code, in parser.c, as the XDP flow_tracker_program

    * flag-fields: Full support for flag-fields

	* Create the flag-fields parse nodes, protocol nodes, helper macros,
	  and protocol tables for parsing and processing flag-fields
	* Add metadata for parsing GRE flag-fields
	* In big_parser, support GRE flag fields; parse them and extract
	  metadata from flag-fields
	* Add parsing and report of GRE flag fields to parser test
	* Add a post flag-fields processing function to perform any tail
	  processing for a protocol with flag-fields
	* Support flag-fields in the PANDA compiler

Other features
--------------

    * Add new pcaps to data/pcaps include ones with GRE packets
    * Add debug option to parser_test
    * Call post_tlv_handle_proto after parsing TLVs to do any tail processing
      for a protocol with TLVs
    * Eliminate default null processing and extract metadata parsing functions.
      Just set fields in the parse node to NULL instead.
    * In tipc extract metadata set '0' in metadata field instead of using
      rand() which is overly complex for some environments
    * Utility macro for always_inline
    * Change root indication for building in samples PANDADIR
    * Add length field to extract metadata and handler functions. The length
      reflects the byte length of the input protocol header
    * Explicitly support TCP options in the panda-compiler (this is a
      temporary solution until a more permanent solution can be found)
    * Makefiles to build samples
    * Add parser definition macros to allow non-static definitions of parsers

Bug fixes
---------

    * In big_parser fix PPP protocol table for endianness
    * In big_parser add IPIP and IPv6-to-IPv6 to to the IPv6 protocol table
    * Fixes to proto_gre in preparation for proper support of flag-fields
    * Make include directory before others to fix dependencies on include
      files


Version 1.1
===========

Major features:
---------------

    * panda-compiler: The PANDA Compiler is a tool that pre-processes a source
      file and extracts parser relationship used to define a specific PANDA
      Parser. See documentation in panda-compiler.md for more information.

    * A feature of the panda-compiler is to analyze a parser, form a .c
      file as input, and to produce a visual for the parse graph.

    * Use the panda-compiler to build optimized version of of big-parser,
      the simple hash parser, and the parses in the samples.

    * Add a couple of cores in src/test/parser to test the parsers produced
      by the panda-compiler. These are pandaopt and pandaopt_notcpopts.

    * Add perfscript to measure performance of various parsers including
      parselite, flowdis, pandaopt, and panda_notcpopts

Other features
--------------

    * Add support for PPPoE to big-parser
    * Add utility function for PANDA_WARN_ONCE
    * Documentation updates and fixes

Bug fixes
---------

    * Fix ICMPv6 protocol node in big-parser
    * Packet tcp_opt_union
    * Make more PANDA parser data structures to be const
    * Convert some bit fields to __u8 in PANDA parser structures
    * Fix ICMP keys in flow dissector parser test
    * Fixes to parser test to improve timing
