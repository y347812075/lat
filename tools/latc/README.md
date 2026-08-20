# latc

`latc` is an internal x86-64 to LoongArch64 binary compiler experiment. It is
built independently and does not modify or link against objects from the
parent LAT build. `latc compile` builds a startup-pretranslation bundle;
`compile-aot.sh` runs LAT's relocatable code generator on a LoongArch build host
and embeds the resulting native code and relocation records.

`latc inspect` reports this existing format as
`execution_model=lat-aot-bundle`. It is deliberately not called a standalone
native ELF: the file still contains the LAT runner and can enter LAT's JIT.

The standalone native ELF work uses the versioned interface in
`native/include/lat-fallback.h`. The small native runtime will load
`liblat.so.1` only when execution reaches a guest TB missing from the compiled
image. It rejects a library whose ABI version or LAT build ID differs from the
image. `LATC_LIBLAT` exists only as a test/development override; installed
programs otherwise resolve the system `liblat.so.1`.

Generate the current stable native image on a LoongArch build host with:

```sh
tools/latc/scripts/compile-native-image.sh build/latc \
  /path/to/latx-x86_64 /path/to/x86-program program.latnative profile.txt
build/latc inspect-native --json program.latnative
```

This image is an input to the forthcoming ELF linker. It is not directly
executable yet.

Build the current LoongArch PIE shell with:

```sh
tools/latc/scripts/link-native-shell.sh program.latnative program.la64
program.la64 --latc-inspect
```

The shell embeds the image in read-only `.latc.image` and validates it on the
target host. Normal execution currently exits with status 126 because guest
state setup, real runtime helpers, and translated-code entry are not linked yet.

`--latc-map` validates and maps the embedded static x86 ELF `PT_LOAD` segments
at their recorded addresses, applies final page permissions, prints the mapped
range, then unmaps it. This is a loader test only; it does not enter guest code.

`--latc-relocate` copies the LoongArch code into an anonymous mapping near the
PIE, applies every stable guest-address and runtime-symbol relocation, flushes
the instruction cache, changes the mapping from RW to RX, then unmaps it.
Runtime symbols are still aborting placeholders, so translated TBs must not be
entered yet.

The first execution test is intentionally independent of x86 and LAT context
switching. `tests/make-native-smoke.c` creates one TB containing two hand-coded
LoongArch instructions which return `42` under the normal C ABI. The PIE runs
it only when the image carries `LAT_NATIVE_IMAGE_C_ABI_SMOKE`; normal exported
LAT images cannot use this path.

`tests/make-native-state-smoke.c` is the next layer. Its TB receives a
`LatX86StateV1 *`, changes `gpr[0]` from 35 to 42, writes `rip=0x1234`, and
returns 42. This verifies the shared state layout and calling convention before
adding LAT's context-switch assembly.

`tests/make-native-dispatch-smoke.c` contains two TBs. The first changes
`gpr[0]` from 5 to 12 and sets `rip` to the second TB; the second doubles it to
24 and clears `rip`. The runtime performs two `(rip, flags)` lookups and stops
when `rip` becomes zero.

`tests/x86-exit42.S` is the first real x86 input. It performs only
`exit(42)`. Its native image must be explicitly marked by
`mark-native-exit-smoke` and must match the recorded LAT build ID before the
specialised entry path will run it. No other syscall is accepted.
The marker and runtime both require the exact fixture SHA-256, so the flag
cannot be applied to gzip or another x86 ELF.
`tests/x86-exit-add42.S` uses real x86 arithmetic to compute 42 before the
same restricted exit syscall.
`tests/x86-exit-loop42.S` executes a six-iteration x86 loop across four CFG
TBs, adding seven each time before exiting with 42.
`tests/x86-exit-memory42.S` loads 35 from the static guest data segment through
RIP-relative addressing, adds seven, and exits with the result.
`tests/x86-exit-call42.S` uses the guest stack for a direct call and return. The
restricted entry path initialises x86 RSP before entering translated code.
`tests/x86-write-exit42.S` writes `OK` through the restricted syscall helper,
returns to translated code, and then exits with 42.
`tests/x86-stack-exit42.S` reads `argc` and `argv[0]` from the Linux-compatible
initial guest stack before exiting with 42.
`tests/x86-brk-exit42.S` and `tests/x86-mmap-exit42.S` allocate writable guest
memory through returning syscalls, store 35, add seven, and exit with 42.
`tests/x86-file-exit42.S` opens `/dev/zero`, reads and checks one byte, closes
the descriptor, and exits with 42.
`tests/x86-open-error42.S` checks that a missing file returns x86 Linux
`-ENOENT`, not the host libc's raw `-1`.
`tests/x86-c-exit42.c` is compiled C code with a loop, local state, and normal
function calls. A minimal assembly `_start` exits with the C return value.
`tests/x86-indirect-call42.S` loads a function pointer from the guest data
segment and calls it indirectly before exiting with 42.

The AOT output is a static LoongArch PIE containing the copied LAT runner, the
x86-64 guest, its control-flow graph, and LAT AOT code. Paths not present in the
AOT image use LAT's JIT translator unless strict verification is enabled.

Build and test with:

```sh
make -C tools/latc
make -C tools/latc test
tools/latc/build/latc analyze --json /path/to/static-x86_64-elf
tools/latc/build/latc compile /path/to/static-x86_64-elf \
  -o program.la64 --runner /path/to/loongarch64/latc-runner
```

On a LoongArch build host, generate and embed relocatable LAT AOT code with:

```sh
tools/latc/scripts/compile-aot.sh tools/latc/build/latc \
  /path/to/static/latc-runner x86-program program.la64
```

Set `LATC_STRICT_AOT=1` when testing the output. The runner exits with status
125 before decoding if the runtime translator is entered after embedded AOT
loading.

Embedded AOT is installed into `$HOME/.cache/latx` on first use. Later runs
reuse it only when a read-only cache file and its latc marker still match the
recorded SHA-256 digest, inode, size, and modification time. Runtime statistics
include `aot_cache_hit`, `bundle_verify_ns`, `guest_extract_ns`, and
`aot_prepare_ns` so startup costs can be separated from guest execution.
`runtime_tb_gen_attempts` is counted at translator entry; strict mode rejects
the attempt before decoding or generating host code.

An optional train profile marks hot TBs so the runner translates them first:

```text
# x86 guest address  execution count
0x401000 120034
0x401038 98211
```

Pass it with `--profile profile.txt`. Missing CFG addresses inside executable
ELF sections are added as supplemental TB starts. Addresses outside executable
sections and malformed lines fail compilation.

On LoongArch, validate a copied LAT runner and real x86 guest with:

```sh
make -C tools/latc test-native \
  RUNNER=/path/to/latc-runner X86_GUEST=/path/to/static-x86_64-elf
```

Build a statically linked runner from the matching full LAT checkout on a
LoongArch machine:

```sh
tools/latc/scripts/build-runner.sh /path/to/full/lat /path/to/build-latc-runner
```

The script treats `/path/to/full/lat` as read-only. It creates a disposable
`/path/to/build-latc-runner.source` staging tree and applies the local adapter
there. Delete both build directories after copying out `latx-x86_64`.

Analyze all twelve SPECint2000 integer executables with:

```sh
make -C tools/latc test-spec-analyze \
  SPECINT_BINDIR=/path/to/specbin/x64_gcc12_2_0
```

Current limitation: generated LoongArch instructions are regenerated when the
output starts unless the bundle was produced by `compile-aot.sh`. An AOT bundle
stores LAT's LoongArch code and relocation records and loads them before guest
execution. Unresolved paths use JIT unless `LATC_STRICT_AOT=1` is set.

`LATC_STATS_OUT=/path/stats.json` records both startup pretranslation and
`runtime_tb_gen_attempts` and `runtime_tb_gen_calls`. The attempt count must be
checked before claiming that a test ran without entering the runtime
translator. `LATC_DISABLE_PRETRANSLATE=1` provides a JIT baseline for the same
bundle.

`LATC_PROFILE_OUT=/path/missing.profile` records runtime-generated guest PCs.
Passing that file back through `--profile` adds missing addresses that are
inside executable ELF sections; addresses outside executable sections fail the
compile instead of being trusted blindly.

All twelve SPECint2000 integer programs pass the official test workloads with
zero main-ELF runtime code generation. Ten pass full strict mode with no JIT at
all. Perlbmk and vortex use two and four guest VDSO/signal-helper TBs
respectively; they pass main-program strict mode with only that explicit system
JIT fallback. See [spec2000/SPEC2000.md](spec2000/SPEC2000.md) for counts and
AOT sizes. The same strict gzip AOT output runs on AOSC Linux and Loongnix Linux
4.19 3A6000 systems.

The official SPECint2000 train workloads are also automated:

```sh
python3 spec2000/prepare-specint-train.py \
  --latc build/latc --runner /path/to/latx-x86_64 \
  --spec-root /path/to/spec2000 --workdir /path/to/train-bundles
python3 spec2000/bench-specint-train.py \
  --runner /path/to/latx-x86_64 --spec-root /path/to/spec2000 \
  --bundle-dir /path/to/train-bundles/bundles \
  --workdir /path/to/train-benchmark --rounds 5
```

This proves that the main x86 ELF executes from LAT AOT without entering the
runtime translator for the measured workload. It does not yet produce a
standalone LoongArch program without the LAT runtime: the output remains a
static LoongArch runner containing the x86 ELF, CFG, and LAT AOT image.

Current limitations: AOT generation itself must run on a LoongArch build host;
the runner extracts the embedded AOT into `$HOME/.cache/latx` and the x86 guest
into `/tmp`, so both locations must be writable. Guest VDSO and anonymous
signal-helper pages are not yet serialised as AOT segments. Test and train
workloads are validated. Ref profiles still need separate collection because
they may expose additional indirect targets.
