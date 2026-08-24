# AOT v2 M0

This directory contains the first implementation slice of the AOT v2 design.

- `include/lat-aot-v2.h` is the stable ELF note, module descriptor, TB, and PC
  map ABI. LBT and LSX are mandatory; LASX is an optional artifact variant.
- `runtime/elf-validate.c` parses and checks an artifact through an already
  opened fd before `dlopen()`.
- `runtime/module-loader.c` loads the validated fd, resolves the versioned
  descriptor, and verifies all descriptor ranges against mapped ELF segments.
- `runtime/registry.c` publishes immutable guest-range snapshots and supports
  multiple guest load biases for one shared Host artifact.
- `tests/fixture.c` and `tests/fixture-entry.S` build a real LoongArch
  `ET_DYN` fixture whose synthetic TB returns `42` through the versioned runtime
  dependency.

M0 intentionally does not modify LAT execution. The next milestone connects
the current LAT code exporter to this module ABI while keeping `.text` read-only.
