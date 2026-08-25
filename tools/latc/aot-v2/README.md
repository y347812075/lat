# AOT v2 M0 and M1 test slice

This directory contains the first implementation slice of the AOT v2 design.

- `include/lat-aot-v2.h` is the stable ELF note, module descriptor, TB, and PC
  map ABI. LBT and LSX are mandatory; LASX is an optional artifact variant.
- `runtime/elf-validate.c` parses and checks an artifact through an already
  opened fd before `dlopen()`.
- `runtime/module-loader.c` loads the validated fd, resolves the versioned
  descriptor, and verifies all descriptor ranges against mapped ELF segments.
- `runtime/registry.c` publishes immutable guest-range snapshots and supports
  multiple guest load biases for one shared Host artifact. It also fills the
  guest-address slots immediately before the existing `$fp` jump-cache base.
- `compiler/module-pack.c` converts supported TBs from the current
  `.latnative` intermediate into position-independent module text and metadata.
  Runtime helper calls use a local trampoline and guest addresses use negative
  `$fp` offsets; neither operation requires runtime `.text` changes.
- `scripts/link-aot-v2-module.sh` links the generated objects into a
  deterministic LoongArch `ET_DYN` file.
- `tests/fixture.c` and `tests/fixture-entry.S` build a real LoongArch
  `ET_DYN` fixture whose synthetic TB returns `42` through the versioned runtime
  dependency.

The M1 test slice executes real LAT-generated TBs for `x86-exit42` and
`x86-static-hello`. The test captures the x86 syscall state after the translated
TB has saved it. It checks `exit(42)`, `write(1, "Hello, LATC!\n", 13)`, and
`exit(0)`, including two different guest load biases using one loaded Host
module. It does not emulate the syscalls.

These generated modules carry `LAT_AOT_MODULE_M1_TEST_ONLY` because the current
native intermediate has no precise Host-PC to guest-state map. They must not be
treated as production cache artifacts. M1 still needs to register these
modules in the real LAT execution loop, bind the syscall trampoline to LAT's
existing `helper_raise_syscall` and `linux-user/syscall.c`, add precise PC maps,
and expose the final `compile-module` and `inspect-module` commands.

On LoongArch, after producing a `.latnative` image with the existing exporter:

```sh
make -C tools/latc test-aot-v2-translated \
  NATIVE_IMAGE=/path/to/program.latnative
```
