<img src="images/Hop.png" alt="Hop the Panda Logo" align="right"/>

The PANDA TC Classifier
================

The PANDA compiler is able to generate code that runs as a Linux kernel module.

We provide a TC classifier, the PANDA classifier, that can be used to leverage
the PANDA parser to do classification of packets.

## iproute2

  In order to use the classifier you must patch the iproute2 tree (for the
  time being). The patch is located under `src/tc/tc.patch`.

## Usage

   The PANDA classifier is a TC classifier that loads a dynamic parser to do
   classification.

   ```
      # Parser panda_foo.ko module
      $ tc filter [...] panda parser foo [...]
   ```

## Samples

   The `samples/kmod` directory contains programs that uses the PANDA
   classifier.  Refer to these programs for building parsing modules for the
   PANDA classifier.

## Special macros

- `PANDA_MAKE_TC_PARSER_PROGRAM(NAME, FUNC)`

   Template to register the parser `NAME` associating the function `FUNC`.
   The parser name `NAME` is used by the tc command line to load the parsing
   module.  The function `FUNC` is the entrypoint to the dynamic parser called
   by the classifier.
