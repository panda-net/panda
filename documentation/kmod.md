<img src="images/Hop.png" alt="Hop the Panda Logo" align="right"/>

Building the PANDA kernel modules
=================================

The `src/kernel` directory contains the code for a panda classifier kernel
module. This is code for a Linux module and and not built by default.
To build the kernel module from the `src` directory run:

```
$ make BUILD_KERNEL=y
```

The Kernel Module Target
========================

The PANDA compiler is able to generate code that runs as a Linux kernel module.
The generated code uses the PANDA parser framework as its building blocks.

## Generating the Parser

The compiler will generate C code when targeting kernel modules.

```
$ panda-compiler parser.c parser.kmod.c
```

The file `parser.kmod.c` contains the generated C code for the parser `parser.c`.

## Calling into the Parser

   To bring the generated parser into scope

   ```
      PANDA_PARSER_KMOD_EXTERN(panda_parser_foo);
   ```

   Then calling into the parser with `panda_parse`

   ```
	err = panda_parse(PANDA_PARSER_KMOD_NAME(panda_parser_foo), data,
			  datalen, &mdata.panda_data, 0, 1);
   ```

   Note that data is a pointer to a linearized buffer and datalen is the
   linearized data (that is not necessarily the length of the packet is it
   is contained in multiple skb fragments). Before calling skb_linearize or
   skb_pullup may be called to ensure that the a linear buffer containing
   the desired length of headers is created (the length may be less than the
   length of the packet to define a parsing buffer).

   `panda_parser` returns `PANDA_STOP_OKAY` in case of success and other error
   codes in case of failure.

## Samples

   The `samples/kmod` directory contains programs that uses the PANDA parser as
   a kernel module. Refer to these programs for how to integrate PANDA into the
   Linux build system and how to use the PANDA APIs for parsing.

   The kernel module samples calls `pr_debug()` when appropriate.  The messages
   are enabled by either compiling the modules in debug mode or by using dynamic
   debugging.

   Read more at
   https://www.kernel.org/doc/html/latest/admin-guide/dynamic-debug-howto.html
   https://elixir.bootlin.com/linux/latest/source/include/linux/printk.h#L411

## Special macros

- `PANDA_PARSER_KMOD_EXTERN(NAME)`

   Brings the PANDA parser named `NAME` into scope.

- `PANDA_PARSER_KMOD_NAME(NAME)`

   Reference the parser named `NAME`.
   The implementation uses an internal naming convention for kernel module
   parsers.

## Requirements

- Kbuild

   In order to use the PANDA APIs in a kernel module, add the following to your
   Kbuild file.

   ```
   ccflags-y += -I$(PANDADIR)/include
   ```

   The `PANDADIR` variable is the installation directory of PANDA.

- Code

   The parser assumes a **linear** buffer. If you are parsing skbs, then the
   caller should linearize or pullup the skb to the desired number bytes,
   the length of this linear buffer is an argument to panda_parser.

## Secure Boot

   Machines with secure boot enabled require all kernel modules to be signed by
   a trusted party.  You may need to manually sign the compiled kernel modules.
   Read more at https://ubuntu.com/blog/how-to-sign-things-for-secure-boot

