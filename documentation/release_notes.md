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
      the simple hash parser, and the parses in the smaples.

    * Add a couple of cores in src/test/parser to test the parsers produced
      by the panda-compiler. These are pandaopt and pandaopt_notcpopts.

    * Add perscript to measure performance of various parsers including
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
