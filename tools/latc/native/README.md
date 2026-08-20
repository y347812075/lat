# latc native runtime

This directory contains code shared by the future standalone LoongArch ELF and
the optional LAT fallback library. It must not include LAT decoder, IR, or code
generator headers.

`include/lat-fallback.h` is the versioned process ABI between the small runtime
and `liblat.so.1`. Both sides share `LatX86StateV1`. When a compiled TB is
missing, the runtime opens the library, copies the current state into this
structure, and asks LAT to execute until `is_compiled()` accepts the next guest
PC. A build ID check prevents an image from using a fallback library built from
incompatible LAT sources.

The current implementation provides and tests the ABI loader only. It does not
yet build a standalone LoongArch ELF or a working `liblat.so.1` adapter.

`include/lat-native-image.h` defines the stable records that will be embedded
in `.latc.image`. They contain offsets and numeric relocation kinds only. LAT's
pointer-sized `TranslationBlock` and helper addresses are intentionally not
part of this format.

`format/native-image.c` validates every section range, TB code extent,
sorted guest-PC index, and relocation kind before a native image is linked or
loaded.
