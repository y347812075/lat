# latc native runtime

This directory contains the standalone LoongArch ELF runtime and the optional
LAT fallback ABI. It must not include LAT decoder, IR, or code generator
headers.

`include/lat-fallback.h` is the versioned process ABI between the small runtime
and `liblat.so.1`. Both sides share `LatX86StateV1`. When a compiled TB is
missing, the runtime opens the library, copies the current state into this
structure, and asks LAT to execute until `is_compiled()` accepts the next guest
PC. A build ID check prevents an image from using a fallback library built from
incompatible LAT sources.

The current implementation builds and runs standalone LoongArch PIE files for
validated static x86-64 guests. A working `liblat.so.1` fallback adapter is not
implemented; static images therefore reject missing TB targets.

`include/lat-native-image.h` defines the stable records that will be embedded
in `.latc.image`. They contain offsets and numeric relocation kinds only. LAT's
pointer-sized `TranslationBlock` and helper addresses are intentionally not
part of this format.

`format/native-image.c` validates every section range, TB code extent,
the `(guest_pc, flags)` index order, and relocation kind before a native image
is linked or loaded. Static execution images also require every TB-target
relocation to resolve inside the image. Multiple code variants may share a
guest PC when their LAT execution flags differ.
TU-internal TB entries may report a zero independent code size because they
share the containing Translation Unit; their code offset must still point
inside the image.

The exporter removes LAT's process-local TU search data because it can contain
host pointers. Images currently carry `LAT_NATIVE_IMAGE_NO_PRECISE_SIGNAL_MAP`;
a stable host-PC to x86-PC map must replace that data before precise
instruction-level signal recovery is supported.
