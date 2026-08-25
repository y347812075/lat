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
`x86-static-hello`. The module-level test captures the x86 syscall state after
the translated TB has saved it. It checks `exit(42)`,
`write(1, "Hello, LATC!\n", 13)`, and `exit(0)`, including two different guest
load biases using one loaded Host module. It does not emulate the syscalls.

The disposable dynamic LAT runner performs the end-to-end test. It registers
the AOT module once, queries the registry after a normal TB lookup miss, and
routes the AOT syscall trampoline to LAT's existing `helper_raise_syscall`.
The normal x86 linux-user CPU loop then executes `linux-user/syscall.c`.
`x86-static-hello` prints `Hello, LATC!` with zero runtime translation attempts
and calls.

The AOT ELF does not contain LAT `TranslationBlock` objects and loading a
module does not insert all AOT TBs into QEMU's qht or TCG Host-PC tree. The
current `cpu_tb_exec()` interface still accepts `TranslationBlock *`, so the
M1 adapter lazily creates a small thread-local compatibility object for a TB
that is actually selected. It is never registered in the old TB indexes and
is never directly linked. A later execution-interface change should accept a
`LatAotTargetV2` directly and remove this compatibility object.

The M1 packager publishes only TBs that terminate in
`helper_raise_syscall`. This guarantees that the temporary compatibility object
never enters LAT's normal TB-return, direct-link, or invalidation paths. The
current copied LAT code generator saves vector state with LASX instructions,
so these test modules declare `LAT_AOT_FEATURE_LASX`. A separate LSX-only
lowering is still required for CPUs without LASX; LBT and LSX remain mandatory
for every variant.

These generated modules carry `LAT_AOT_MODULE_M1_TEST_ONLY` because the current
native intermediate has no precise Host-PC to guest-state map. They must not be
treated as production cache artifacts. M1 still needs to generate precise PC
maps and expose the final `compile-module` and `inspect-module` commands.

On LoongArch, after producing a `.latnative` image with the existing exporter:

```sh
make -C tools/latc test-aot-v2-translated \
  NATIVE_IMAGE=/path/to/program.latnative
```

Build and test the disposable dynamic LAT runner with:

```sh
tools/latc/scripts/build-aot-v2-runner.sh \
  /path/to/full/lat /path/to/aot-v2-runner
make -C tools/latc test-aot-v2-runner \
  AOT_V2_RUNNER=/path/to/aot-v2-runner/latx-x86_64 \
  AOT_V2_RUNTIME_DIR=/path/to/aot-v2-runner \
  X86_GUEST=build/tests/x86-static-hello \
  NATIVE_IMAGE=/path/to/x86-static-hello.latnative
```
