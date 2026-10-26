# latc

`latc` is an internal x86-64 to LoongArch64 binary compiler experiment. It is
built independently and does not modify or link against objects from the
parent LAT build. `latc compile` builds a startup-pretranslation bundle;
`compile-aot.sh` runs LAT's relocatable code generator on a LoongArch build host
and embeds the resulting native code and relocation records.

## AOT v2 module prototype

See [candidate validation](VALIDATION.md) for build, installation and runtime
gates, evidence requirements, and the boundaries of the tested support.

The [i386 support assessment](AOT_V2_I386_PLAN.md) records the remaining
32-bit Linux ELF work, scope, estimates and proposed validation gates.
It is a planning record, not a claim of implemented i386 AOT v2 support.

### Automatic runtime setup

Legacy `LATX_AOT` remains the default. Set `LATX_AOT_V2=1` to select
AOT v2 without configuring a cache/socket or starting `latcd` manually.
An explicitly enabled `LATX_AOT` together with enabled v2 is an error before
guest execution. `LATX_AOT=0 LATX_AOT_V2=0` selects pure JIT. An explicit
`LATX_AOT_V2=0` also disables v2 when legacy cache/socket overrides remain.
Command-line options override environment values, which override LAT config.
Older explicit cache/socket/module configurations still imply v2 when the
mode is unset; they are subject to the same mutual exclusion check.

The default cache is `${XDG_CACHE_HOME:-$HOME/.cache}/lat-aot-v2/<build-id>/live`.
State and `daemon.log` are under
`${XDG_STATE_HOME:-$HOME/.local/state}/lat-aot-v2/<build-id>`.
The private socket lives under `$XDG_RUNTIME_DIR/lat-aot-v2`, or the state
root's `lat-aot-v2/run` directory when a private runtime directory is absent.
Socket names identify both the toolchain and canonical cache directory.
Long directory paths use an open directory FD for Unix socket bind/connect,
without relocating the cache or changing the working directory.
These paths are application-independent; incompatible builds use separate caches.

The runner starts matching installed tools on demand, checks the daemon's
user/build/cache identity, and serializes concurrent starts. Compilation
continues after the guest exits. A managed daemon exits after 60 seconds idle,
only when queued compilation and precompile requests have completed.
A fully covered warm run does not start a daemon. Ordinary failures retain
usable cached modules and fall back to JIT; strict AOT checks still fail.
Privileged execution does not automatically activate v2.

`LATX_AOT_V2_AUTOSTART=0` disables automatic starts but can still connect to
an existing matching daemon. Explicit `LATX_AOT_V2_LATCD_SOCKET` or
`LATX_AOT_V2_MODULE` selects manual operation; the runner never starts or
replaces that daemon. Explicit cache paths may still use automatic startup.
Precompile, collect-only and strict diagnostics remain opt-in and are not
enabled by automatic setup.

Installed tools must share one build identity. System deployment uses normal
library loader configuration; private install tests use `LD_LIBRARY_PATH`.
The automatic daemon receives only the configured runtime library directory,
not the application's loader environment.

```sh
make -C tools/latc test-aot-v2-autostart \
  INSTALL_PREFIX=/path/to/install X86_GUEST=/path/to/x86-static-hello
```

AOT v2 is the new per-x86-ELF module design. It keeps the original x86 program
as the user-visible launch target and loads cached LoongArch `ET_DYN` modules
inside LAT. The design and confirmed runtime rules are in
[`AOT_V2_DESIGN.md`](AOT_V2_DESIGN.md).

Milestone M0 defines the standalone ABI, validates an artifact before
`dlopen()`, and provides a minimal multi-instance registry. On a LoongArch
host, build and execute the real shared-object fixture with:

```sh
make -C tools/latc test-aot-v2
```

On other hosts the same target runs the architecture-independent ELF format
and registry tests. M1 packages all supported TBs from real LAT output and
executes no-libc hello, static glibc hello, and SPECint2000 train through the
AOT registry and existing linux-user syscall path.

On a LoongArch build host, compile and inspect an AOT v2 module with:

```sh
build/latc compile-module /path/to/x86-program -o program.so \
  --runner /path/to/static-exporter/latx-x86_64 \
  --runtime-dir /path/to/aot-v2-runtime
build/latc inspect-module --json program.so
```

An observed input TB set may be smaller than the actual compiled module
(CFG selection and direct closure can add entries). To preserve coverage
when rebuilding a module with the same source and codegen identity, export
the actual keys and validate the replacement, not just its observed inputs:

```sh
build/latc emit-module-tbset old.so -o old-module.tbset
build/latc validate-module-replacement old.so new.so
```

The export refuses to overwrite an existing file. Replacement validation
rejects identity changes or any missing `(RVA, flags)` pair. `latcd` performs
this check before committing a replacement of a valid current generation,
including publication of an already cached candidate.
Before compilation, `latcd` also unions the actual current module keys with
the complete requested set for any clean recompilation (including a retry
after an incremental merge failure). The observed-key manifest remains a
request record; it is not treated as a complete inventory of translated TBs.

The standalone `lat-key-journal` primitive is exercised by
`build/tests/test-key-journal` and the full `make test` target. It uses a bounded,
append-only, size-sealed shared memfd with independent reservation/commit slots.
Tests cover producer SIGKILL before/after commit, abandoned slots, concurrent
threads/forks, format/identity rejection and capacity exhaustion. An external
owner must retain the fd for the memfd backend. A named-file backend supports
reopening after all previous fd owners exit, using private-directory checks and
positioned I/O with independent OFD slot locks; it does not map unsealed files.
Each writer must open its own view and reopen after fork. File operations must
run outside the translation mmap_lock. Neither backend is connected to runner
collection yet. Service operation `LATCD_OP_REGISTER_JOURNAL` takes a source fd
and a write/grow/shrink-sealed configuration fd; its sequence is the slot capacity.
The daemon pins its verified source snapshot, stores configuration and identity,
and creates `.journals/<random-epoch>/keys`. A successful reply contains the epoch
basename, with accepted/published sequences still zero. Startup validates stored
registrations; invalid or incompatible-build stores fail visibly, without GC.
The store is bounded to 128 streams and a separate logical-byte budget equal to
`--max-cache-bytes`, not a unified module-plus-journal quota. Registration currently
performs snapshot/validation I/O in the request loop. Incomplete registration after
a daemon crash can require operator recovery; no automatic discard is attempted.
An incomplete effective-config snapshot may be retained but never authorizes cache
compatibility or compilation. Startup also scans committed slots into a quarantined
per-stream `received.tbset`; operation 9 (`COLLECT_JOURNALS`, no descriptors) repeats
this bounded scan explicitly. Collection checks executable source ranges and that
all previously received keys remain in the journal. It atomically replaces a
changed receipt and reserves space for the final and temporary maximum receipts.
Unchanged sets retain their inode. Accepted/published sequences remain zero:
receipt storage is not compiler admission, compile-job recovery or an execution
before-commit gate, and it does not provide power-loss durability. Existing runtime
collection remains best effort. `build/tests/test-journal-store` covers registration,
producer/service SIGKILL, source unlink, restart collection, binding, limits,
executable-range boundaries, receipt corruption and preservation on failure.

The client provides ordinary and authenticated inherited-channel journal
registration APIs. Both require the returned source SHA, lowercase epoch basename
and zero accepted/published watermarks to match the registration contract. Channel
registration uses a dedicated reply socket, without reconnecting by pathname;
registration may succeed remotely even if its reply is lost, so automatic retry
does not yet provide idempotence. These APIs are not connected to runner collection
or compiler admission. The store test includes a fork child registering after the
server socket pathname has been temporarily moved, then appending and collecting
its key. This is a descriptor-path test, not full namespace/seccomp acceptance.

Operation 10 (`REGISTER_JOURNAL_CAPABILITY`) has the same registration inputs,
but also transfers an owned CLOEXEC private stream directory fd in its successful
reply. The capability client APIs require exactly one descriptor on success and
none on rejection, validate the directory owner/mode, and clear outputs on any
failure. Callers still validate the complete journal identity with `open_at`.
Fork children close inherited writer views and open a fresh OFD through this
directory, without resolving the cache pathname. Protocol tests cover malformed
ancillary data and reply backpressure; service tests cover a moved store path,
fork reopen, producer SIGKILL and receipt collection. This does not establish
availability of the required host syscalls under a real application sandbox,
protect runner fds from guest operations, or implement the preexecution gate.

Experimental runner integration is now available when
`LATX_AOT_V2_KEY_JOURNAL` is present. It uses operation 10 and a dedicated
outer-loop retry to commit missing file keys before normal TB generation;
fork children reopen an independent writer OFD and JRRA retry uses guest identity.
The earlier disconnected-component descriptions above are historical boundaries.
This is not a default or complete delivery guarantee: direct TU/tunnel/bundle
misses can exit125, mapping identity/classification and exact executable ranges,
guest fd protection, real sandbox, atomic/signal/flush interleavings and managed
cold-start validation remain incomplete. Config is still incomplete/quarantined;
receipt collection does not admit compilation, recover jobs or publish modules.
See `docs/aot-v2-handoff/runtime-key-delivery.md` and `STATUS.md`.

`test-aot-v2-journal-fd` is an opt-in real guest integrity regression and is
currently expected to fail until guest descriptor isolation is implemented.
Build `tests/x86-journal-fd.S` on an x86 Docker toolchain with
`gcc -nostdlib -static -no-pie -Wl,--build-id=none -DATTACK=N`, using values
0 through 4 for `guest-control`, `guest-truncate`, `guest-setfl`,
`guest-overwrite`, and `guest-dup`. Put the five executables in `GUEST_DIR`:

```sh
make -C tools/latc test-aot-v2-journal-fd \
  INSTALL_PREFIX=/path/to/private/install/usr GUEST_DIR=/path/to/guests \
  WORK="$HOME/tmp/journal-fd-new-run"
```

The test discloses the real internal journal fd to each guest through stdin;
this is not a natural-discovery or sandbox claim. All operations must return
`EBADF`, the guest must continue, and collection after SIGKILL must preserve
both executed fixture keys. Each case records product hashes, commands,
fd state, before/after journals, raw collector replies and available receipts.
Corruption is reported as failure, never accepted as the expected test result.

In service mode, `flush-source` and `flush-all` freeze the accepted sequence
for each applicable source when admitted. They wait for those targets without
blocking the request loop or extending the barrier to later submissions.
Pending flush replies are bounded to 128; excess requests report queue-full.
Disconnected clients are reclaimed, and stopping the daemon reports failure
for unfinished barriers. `--flush-only` still requires a flush to schedule new
work; new keys received during compilation remain pending for a later compile,
and an admitted flush cannot be undone by a subsequent submission.

Use a static guest with valid instructions at entry, entry+5 and entry+10
(the service `x86-exit42` fixture) for the controlled asynchronous flush test:

```sh
make -C tools/latc test-latcd-async-flush \
  INSTALL_PREFIX=/path/to/install X86_GUEST=/path/to/x86-exit42 \
  WORK=$HOME/tmp/latcd-async-flush-test
```

The target runs concurrent flush handling, deferred scheduling and later static
failure checks
in separate work directories. An already satisfied flush must not schedule
later keys, even when another source admission wakes a compiler worker.
A later static failure must not fail an earlier runtime barrier, but a flush
including that static request must report its failure.
Runtime targets and static barriers are tracked separately: a repeated static
request cannot complete an unrelated runtime request with a larger sequence.

To calculate a bounded request's missing keys without exporting the entire
module table, use:

```sh
build/latc missing-module-tbset old.so planned-shard.tbset -o delta.tbset
```

This validates the module table, the request's source SHA and the current
compiler's codegen identity. It preserves request sequence and key ordering;
an entirely covered request produces a valid zero-record TB set. It refuses
existing output paths, including symlinks. Aggregate modules may exceed the
TB-set export limit, while each input/output request remains bounded.
This command is only a membership primitive: it does not prove a paired
native image or configuration compatibility. New daemon publications record
module/native content digests. Incremental jobs freeze and verify both files
from that manifest before passing them together to the discovery-plan consumer.
Each original shard is retained and validated; only its missing keys are
translated, and fully covered shards are skipped. When all shards are covered,
the paired native is reused without an empty translator invocation. Final
linking still validates the entire plan and all previous actual module keys.
Historical manifests without both digests do not enable this optimization,
and a cache hit does not upgrade them into a proven pair. This does not solve
the separately tracked effective-configuration identity/migration gap.
Both cached candidates and newly compiled modules must cover every requested
key; small missing sets are not accepted as implicitly JIT-only. Every fresh
compile stages a distinct immutable generation without overwriting existing
files, so failure before manifest commit leaves the old generation intact.

### Pretranslation Capability And Cache Update Contract

Pretranslation must use the translator's effective instruction and optimization
capabilities, including build options, startup options, and environment overrides.
It must not proactively compile a disabled or unsupported ISA path or enable an
optimization on its own. A disabled optimization may still have a valid ordinary
translation path; it is not automatically an unsupported instruction.
The same rule applies to static precompilation, runtime incremental compilation,
and recovery recompilation. Every entry point and compiler worker must use the
target runtime's effective configuration, not independently inherited daemon or
worker environment values or defaults.
When effective capabilities change, update the existing cache incrementally:
compile newly enabled missing entries, recompile affected existing units, and
reuse only proven-compatible unaffected code. Track effective configuration and
compatibility, validate coverage, and atomically publish the new generation;
never relabel incompatible native images or weaken the accepted-key gate.
Clearing the cache and recompiling everything is not a substitute for incremental
configuration migration.
Compare fully resolved effective values, not raw environment strings: changed
inputs that resolve to the same configuration must not cause unrelated recompiles.
This is a required contract, not a claim that environment-driven cache migration
is already implemented. See [the repository capability rules](../../docs/aot-v2-handoff/capability-consistency.md).

`latx-x86_64 --latc-translation-config GUEST` exports a versioned JSON diagnostic
snapshot after the real configuration-file, environment, and command-line
processing, CPU initialization, and guest-name adjustments. It does not execute
the guest or prepare AOT cache directories. The snapshot currently reports
`compatibility_complete: false`: its field audit and configured daemon/compiler
workflow are unfinished, and it must not be used as a cache compatibility identity or proof
that incremental configuration migration is implemented.
The shared configuration schema supplies explicit little-endian serialization,
strict decoding, a configuration SHA256 independent of the build identity, and
a field-level difference bitmap. The JSON query exposes this diagnostic digest
as `configuration_sha256`. Equality is not sufficient for reuse: the shared
compatibility predicate rejects incomplete snapshots, and native/module cache
validation does not yet consume this configuration metadata.
`--latc-translation-config-from PATH` can replay a bounded binary snapshot only
alongside the diagnostic query. Writable options are restored before CPU setup;
host/build/CPU facts are not overwritten and the final snapshot is compared
field by field. Ordinary incomplete snapshots are not accepted for real
compilation, and setting their complete flag does not enable compilation replay.
`--latc-translation-config-out PATH` selects the same diagnostic query and also
writes its canonical binary snapshot directly from the translator. The path must
not exist; a new file is created with mode 0600 (subject to umask), and a handled
write, sync, or close failure removes the partial output. It can be combined with
`--latc-translation-config-from` to export a verified replay. The exported snapshot
remains incomplete and does not authorize worker compilation or cache reuse.

An isolated native-export experiment is available through
`--latc-translation-config-native --latc-translation-config-out PATH GUEST`.
It captures a restricted non-debug x86-64 v2/parallel configuration and reports
`native_replay_domain: true`; the JSON and binary outputs describe the same
snapshot and digest. Unsupported effective settings are refused. The internal
`LATC_TRANSLATION_CONFIG_FROM=PATH` worker input accepts this snapshot only in
a verified bundle without embedded AOT, with `LATC_EMIT_AOT=1` and
`LATC_NATIVE_IMAGE_OUT` set. It projects only the internal legacy-AOT export
mode, verifies the remaining effective configuration, and requires parallel keys.
The resulting v11 native image preserves the original snapshot and digest, but
is explicitly unverified for execution: module packaging, executable marking,
and native runtime loading refuse it. Merge requires identical original
snapshots. Old native readers reject v11 rather than ignoring its metadata.
This experiment proves real option replay, not runnable configured caches,
daemon protocol propagation, or selective TU migration. Run its integration
test with `make -C tools/latc test-native-config-replay INSTALL_PREFIX=...`
and the `X86_GUEST`, `TBSET`, and fresh `WORK` paths.

`latc plan-native-tus IMAGE SEED_TBSET -o OUTPUT_TBSET` expands existing seed
keys into a native TU metadata dependency plan. It includes complete shared
TUs, all same-key physical aliases, and transitive incoming physical-target
dependencies. Source and current build identities must match; unknown seed keys,
missing TU ownership, and oversized plans fail. The output preserves the input
sequence and uses sorted unique RVA/parallel keys, including a legal empty plan.
The output path must not exist. This command neither changes native code nor
authorizes configuration compatibility: unrecorded local branches and constant
data references still need extraction proofs, and complete configuration
classification, code replacement, and atomic migration publication are pending.

Native v11 also stores a configuration-schema version and dependency mask per
physical TU. Successful ordinary translations record audited CVT option reads
under both option values; other configuration fields conservatively affect every
TU. Missing or unsupported translation records contribute all dependency bits.
Masks are unioned across TU members, preserved by merge, and validated on input.
A zero dependency version means unknown, not independent. These records alone
do not authorize cache compatibility or selective reuse. Exercise real multi-TU
exports with `make -C tools/latc test-native-tu-config INSTALL_PREFIX=...` and
`X86_GUEST`, `TBSET`, and a fresh `WORK` path.

Native v11 data relocations additionally record the complete pointer-free
constant object, its code-section offset, byte size and power-of-two alignment
(at most 4096), separately from the referenced interior address. Shared references
must agree on object bounds, flags and alignment; partial/conflicting object
overlaps, code/patch overlap and metadata on other relocation kinds are refused.
Merge preserves object alignment and shifts both object and reference addresses.
These records enable future object extraction, not proof that arbitrary TU code
is movable or authorization for configuration reuse.

`latc plan-native-config IMAGE CONFIG -o OUTPUT_TBSET` compares an embedded
native snapshot against a canonical target snapshot, then applies the same
complete-TU/alias/incoming-dependency closure. Unknown TU dependencies select
the TU on any configuration change; equal configurations produce an empty
plan. Missing snapshots, mismatched domains/builds, malformed inputs, and
existing output paths fail. Target configurations must be bounded regular
files, not symlinks or FIFOs. This command only plans recompilation: it neither
authorizes reuse nor changes native code, configuration labels, or manifests.
Run real-export regression with `make -C tools/latc test-native-config-plan
INSTALL_PREFIX=... EXPORTS=... EXPECTED=... WORK=...`; `EXPORTS` contains real
two-configuration native exports and snapshots, and `EXPECTED` maps guest PCs
to their audited CVT dependency in the fixture.

`latc extract-native-tus IMAGE REMOVE_TBSET -o OUTPUT_NATIVE` implements actual
compaction of the complement of a closed removal plan. It copies whole retained
TUs and only their referenced complete constant objects, preserving internal
layout/alignment/sharing and remapping TB/TU indices, physical target indices,
patch offsets and PC maps. Empty complements are rejected. Outputs are exclusive
new files; failed writes are removed. Only quarantined configuration-replay
images are accepted and their exact original snapshot remains unchanged.
This is not a machine-code movement certificate: unrecorded references and
producer provenance still require proof before reuse, replacement, execution or
publication. Existing CONFIG_UNVERIFIED loading/packaging restrictions remain.
Run `make -C tools/latc test-native-tu-extract INSTALL_PREFIX=... EXPORTS=...
PLANS=... WORK=...` after the real-export configuration-plan regression above.

`latc audit-native-tu-references IMAGE` checks final TU executable prefixes and
the recorded patch templates, rejects overlapping/unowned patch windows, and
checks unrecorded direct branches and supported PC-relative address expressions
remain inside the same TU prefix. It includes code beyond ordinary TB ranges,
such as moved unlink stubs. Unrecorded PCALAU12I and unsupported PCADDU12I uses
fail; recorded JRRA windows require their full patch template. Extraction runs
the audit before and after compaction. This is not an absolute-address provenance,
reachability, fallthrough or complete movement certificate; the CLI explicitly
reports `movement_certified=false`. Configuration quarantine remains mandatory.

`latc audit-native-tu-execution IMAGE` additionally walks conservative control
flow from every physical TB entry, checking branch/call continuations and
rejecting execution outside the owning TU prefix or into patch/far-pair/helper/
dispatch interiors. Relocated helper calls require an exact address-load and
JIRL sequence, optionally with one non-clobbering OR argument instruction;
returning helpers must set `ra`, whereas proved nonreturning helpers may tail
exit. Nonstandard link registers are rejected except the two recorded JIRL
epilogue `rd4` conventions. Nonzero runtime-entry addends are rejected.
Existing complete validated fast-dispatch windows may exit through cache hits,
but their miss continuation is still checked. Unresolved indirect transfers
fail. Extraction runs this audit, including the reference audit, before and
after compaction. It does not certify instruction validity, absolute-address or
dynamic-target provenance, nor the producer's executable-layout declaration;
`movement_certified=false` and configuration quarantine are unchanged.

The native WAIT producer constructs its float constants directly with numeric
bits and MOVGR2FR.W instead of embedding exporter-process addresses. On LoongArch
the full test runs the real emitter against memory loads and its single-precision
arithmetic/FCSR results under four rounding modes. The installed export test is
`make -C tools/latc test-fwait-constants INSTALL_PREFIX=... X86_GUEST=...
TBSET=... WORK=...`, using `tests/x86-fwait-constants.S` compiled on x86. It checks
the actual constant values, absence of the old FLD.S loads, repeated exports and
JIT execution. This focused producer fix is not a general provenance certificate
or a full WAIT exception/trap equivalence claim.

`LATC_TRACE_PROVENANCE=1` enables opt-in producer diagnostics on stderr. Each
emitted TB-assembly word has its guest PC, TB-relative offset, exact word,
`numeric-bits` or `unknown` origin, and `certified=0`. Legacy immediate helpers
remain unknown; only explicit numeric emitters opt in. Per-IR-index snapshots
check opcode and active operands after optimization and are cleared per
translation and destroyed with the translation thread. Native export retains
only sparse numeric-word records on their owning TB, remaps moved unlink stubs,
clears records on retranslation, and emits `native-final` records after final
export rewrites. Changed words and overlapping relocation windows become unknown.
Live JIT tracing does not retain these sparse arrays. This is not a register
dataflow proof, a complete final TU inventory, a persistent native manifest, or
authorization to move/reuse code. Use only for bounded
diagnostics: a large translation can produce a large log. The default is off;
other values do not enable it.

`make test-final-provenance-export INSTALL_PREFIX=... X86_GUEST=... TBSET=...
WORK=...` exercises final offsets in a real shared TU. A test-only builder uses
the product CFG analyzer and bundle writer to select unbounded parallel entries;
it does not change the product's bounded-key policy. Compile
`tests/x86-provenance-tu.S` on x86 and include `_start|provenance_.*` symbols in
the input key evidence set. The check compares actual final native words and verifies
that tracing does not change code outside recorded relocation windows.

`LATC_TBSET_CLOSURE_LIMIT` controls only the number of additional direct
successors (zero disables that expansion). Selection is independently set by
`LATC_TBSET_SELECTION=cfg|bounded|exact|exact-static`: direct `latc compile`
defaults to `cfg`; module compilation and `latcd` default to `bounded` with a
20000 direct-successor budget. `LATC_TBSET_EXPAND_FUNCTIONS` additionally expands
containing functions in bounded mode. Changing a budget does not switch policy.

`exact` consumes only the supplied mandatory keys; `exact-static` consumes only
the supplied static candidates and retains static capability filtering. Neither
exact mode inserts dynamic/PLT roots, expands functions or follows successors,
even if expansion environment variables are set. These are batch-consumption
primitives, not proof that discovery has finished. Static candidates must not be
replayed in `exact`, which intentionally preserves mandatory requests. Replacement
coverage is checked regardless of these choices.

Exact bundle compilation loads only the ELF executable ranges before applying
the supplied keys. It does not reconstruct the whole-program CFG for each shard.
Discovery and final module packing still perform their full analysis; in
particular, the final packer's function and edge metadata is not removed.
Ordinary non-export bundle prewarming consequently has no whole-CFG extents or
edge metadata in these exact modes; successful execution alone does not prove
equivalent prewarming coverage or zero runtime JIT compilation.

Normal module native compilation now prepares a private discovery plan before
translation. `plan-tbset ELF TBSET DIRECTORY [--static]` drains the direct/PIC
frontier, separates mandatory keys from static candidates, filters unsupported
static paths, and writes bounded sorted shards. Optional `--batch-size` and
`--work-budget` control slicing, not final coverage. `list-tbplan ELF DIRECTORY`
validates all shard hashes, source/build identities, permissions, ordering and
the complete marker before printing exact-consumption inputs. The normalized
collection identity includes provenance but not shard boundaries. Module linking
then checks every plan shard using `validate-tbplan-module ELF DIRECTORY MODULE`.
Native shards are merged in levels; successfully merged children are removed.
The plan is a private job intermediate, not a persistent daemon request format
or a restart checkpoint. Discovery memory still grows with the frontier; source
CLI inputs must remain stable (the daemon supplies an immutable snapshot).
The legacy direct bundle selector retains its one-shot closure budget behavior.

Static discovery also recognizes a bounded 64-bit CFI sequence that computes
`ROR64(pointer - base, rotation)`, rejects values above a small unsigned bound,
then calls or jumps through a fixed pointer slot. It enumerates the exact
inverse rotation, not an inferred vtable length. An optional constant-register
`BT` followed by a carry-clear rejection further filters that finite domain,
including the architectural modulo-64 bit-index behavior. Slots require unique local
`R_X86_64_RELATIVE` records from loader-declared RELA tables, unambiguous
file-backed mappings, and read-only or RELRO storage. Conflicting writes,
unknown dynamic relocation formats, dependency clobbers and known bypass
entries leave the pattern unresolved. These results are candidate TB seeds
only: they do not create function metadata, close an indirect edge, or change
guest dynamic-linker and dispatch semantics. Static capability filtering and
the complete old-key/new-request publication checks still apply.

M4 adds a separate per-user compiler process. The first implemented step
accepts one read-only x86 ELF file descriptor over a Unix socket, compiles a
stable snapshot, validates the module source digest, and publishes it with an
atomic rename:

```sh
build/latcd/latcd --once --socket "$XDG_RUNTIME_DIR/latcd.sock" \
  --cache-dir /path/to/cache --latc build/latc \
  --runner /path/to/latx-x86_64 --runtime-dir /path/to/aot-v2-runtime
build/latcd/latcd --submit --socket "$XDG_RUNTIME_DIR/latcd.sock" \
  /path/to/x86-program
```

On a LoongArch host, `make test-latcd-once` validates compiler failure cleanup,
bad sources, writable descriptors, malformed compiler output, replacement of a
bad cache entry, strict AOT execution, and an existing-module cache hit. The
The resident service uses the same trusted configuration and adds one compiler
worker, SHA-256 deduplication, a priority queue, resource limits, bounded
failure delays, and atomic status counters:

```sh
build/latcd/latcd --serve --socket "$XDG_RUNTIME_DIR/latcd.sock" \
  --cache-dir "$HOME/.cache/latx/aot-v2" --latc build/latc \
  --runner /path/to/latx-x86_64 --runtime-dir /path/to/aot-v2-runtime \
  --x86-rootfs /path/to/x86-rootfs \
  --stats "$XDG_RUNTIME_DIR/latcd-stats.json"
```

The socket parent must be owned by the current user and have no group or other
permissions. Set the same socket on the runner to request missing modules:

```sh
LATX_AOT_V2_CACHE_DIR="$HOME/.cache/latx/aot-v2" \
LATX_AOT_V2_LATCD_SOCKET="$XDG_RUNTIME_DIR/latcd.sock" \
  /path/to/latx-x86_64 -L /path/to/x86-rootfs /path/to/x86-program
```

The runner sends the already-open ELF FD with a nonblocking `sendmsg` and does
not wait for an acknowledgement or compilation. `compiler_submissions` means
the packet reached the Unix socket; daemon counters and cache files report the
final result.

The module contains instruction-level Host-PC to guest-PC records in
`.rodata.lat.map`. The runner publishes every supported native-image TB,
restores x86 state from those records on a Host signal, and puts direct Host
addresses in LAT's fast indirect jump cache after the first lookup. It does not
create compatibility `TranslationBlock` objects. M2 also discovers dynamic
main, loader, and libc mappings by source SHA-256 and actual load bias.

Run all twelve official SPECint2000 train workloads on LoongArch with:

```sh
make -C tools/latc test-specint-aot-v2 \
  RUNNER=/path/to/static-exporter/latx-x86_64 \
  AOT_V2_RUNNER=/path/to/aot-v2-runner/latx-x86_64 \
  AOT_V2_RUNTIME_DIR=/path/to/aot-v2-runner \
  SPEC_ROOT=/path/to/spec2000
```

The test rejects partial modules, any runtime TB generation, invalid SPEC
output, and a benchmark that exceeds 60 seconds. M1 passed all twelve train
workloads on `3a6000-25g` on 2026-08-25. Ref inputs were not run.

After building an AOT v2 runner, rerun the complete M4 test set with:

```sh
make -C tools/latc test-aot-v2-m4 \
  RUNNER=/path/to/exporter/latx-x86_64 \
  AOT_V2_RUNNER=/path/to/aot-v2/latx-x86_64 \
  AOT_V2_RUNTIME_DIR=/path/to/aot-v2 \
  X86_ROOTFS=/path/to/x86-rootfs SPEC_ROOT=/path/to/spec2000
```

This includes cold/warm compiler service tests, static glibc, signal recovery,
dynamic loading and symbol semantics, and a fresh SPECint train 12/12 build and
run. It does not run SPEC ref.

`latc inspect` reports this existing format as
`execution_model=lat-aot-bundle`. It is deliberately not called a standalone
native ELF: the file still contains the LAT runner and can enter LAT's JIT.

The standalone native ELF work retains the versioned fallback interface in
`native/include/lat-fallback.h`, but direct static execution currently requires
every referenced guest TB to be present. Export, image validation, relocation,
and runtime dispatch reject a missing TB instead of silently entering LAT's
JIT or another translated address.

Generate the current stable native image on a LoongArch build host with:

```sh
tools/latc/scripts/compile-native-image.sh build/latc \
  /path/to/latx-x86_64 /path/to/x86-program program.latnative program.tbset
build/latc inspect-native --json program.latnative
```

This `.latnative` image is an intermediate file. Use `compile-native-elf.sh`
to link it with the small runtime and produce the executable LoongArch ELF.

Build the current LoongArch PIE shell with:

```sh
tools/latc/scripts/link-native-shell.sh program.latnative program.la64
program.la64 --latc-inspect
```

The normal one-step command accepts a static x86-64 ELF and writes the final
LoongArch executable directly:

```sh
tools/latc/scripts/compile-native-elf.sh build/latc \
  /path/to/latx-x86_64 /path/to/static-x86-program program.la64
./program.la64 arg1 arg2
```

The command generates the native image in a temporary directory, verifies and
marks the embedded static x86 ELF, then links the runtime shell. An optional
fifth argument supplies a profile file.

Set `LATC_LA64_LDFLAGS=-static-pie` when the LoongArch toolchain provides
static libc objects and the output must have no ELF interpreter or shared
library dependency.

The shell embeds the image in read-only `.latc.image` and validates it on the
target host. Images marked for static x86 execution run the guest directly and
pass normal command-line arguments and environment variables through the x86
Linux initial stack.

`--latc-map` validates and maps the embedded static x86 ELF `PT_LOAD` segments
at their recorded addresses, applies final page permissions, prints the mapped
range, then unmaps it. This is a loader test only; it does not enter guest code.

`--latc-relocate` copies the LoongArch code into an anonymous mapping near the
PIE, applies every stable guest-address and runtime-symbol relocation, flushes
the instruction cache, changes the mapping from RW to RX, then unmaps it.

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
`exit(42)`. `compile-native-image.sh` verifies that the embedded guest is an
x86-64 ELF without `PT_INTERP`, marks it for static execution, and records the
LAT build ID required by the runtime. Guest SHA-256 values are recorded for
identity and diagnostics, not used as an execution allowlist.
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
`tests/x86-runtime-indirect-call42.S` derives two function pointers from
`argc`, performs two nested runtime indirect calls, and checks both x86 return
addresses and a callee-saved register before writing `INDIRECT OK`.
`tests/x86-helper-state42.S` executes `cpuid`, `pcmpistri`, and `pcmpistrm`,
checking their results, x86 flags, RSP, and a callee-saved register before
writing `HELPERS OK`.
`tests/x86-ifunc-like42.S` calls a resolver, invokes the returned function
pointer, and verifies RSP after both returns before writing `IFUNC OK`.
`tests/x86-auxv42.S` validates the Linux x86-64 initial stack, including the
program headers, page size, entry point, platform, random bytes, and executable
name supplied through auxv.
`tests/x86-addr32-call42.S` checks the address-size-prefixed direct call form
used by static glibc and verifies its pushed return address and restored RSP.
`tests/x86-tls42.c` parses `PT_TLS`, copies its initial image into a new static
TLS block, sets FS with `arch_prctl`, and verifies a `__thread` value before
writing `TLS OK`.
`tests/x86-prlimit42.S` queries `RLIMIT_STACK` through x86 `prlimit64` and
checks the returned limit before exiting with 42.
`tests/x86-getrandom42.S` fills 16 bytes through x86 `getrandom`, checks the
result, and exits with 42.
`tests/x86-readlinkat42.S` reads `/proc/self/exe` through x86 `readlinkat`,
checks that an absolute path was returned, and exits with 42.
`tests/x86-mprotect42.S`, `tests/x86-fstat42.S`, and
`tests/x86-exit-group42.S` cover the additional Linux calls used by static
glibc startup and shutdown. The syscall switch and x86 ABI structure
conversions are kept in `native/runtime/x86-linux-user.c`, following the
corresponding cases in `linux-user/syscall.c`.
`tests/x86-entry-regs42.S` checks that the initial guest GPRs are deterministic
and that static ELF `%rdx` is zero, as required for the dynamic-linker finalizer
hook passed to glibc startup.
`tests/x86-argv-env42.S` checks that normal LoongArch command-line arguments
and environment variables appear in the x86 Linux initial stack. Runtime
options beginning with `--latc-` remain reserved for image inspection and
diagnostics.
`tests/x86-long-tb-exit42.S` contains more than 255 straight-line x86
instructions. It verifies that pretranslation continues at LAT's TB length
limit instead of leaving a missing target in the native image.
`tests/x86-static-hello.S` is a static x86-64 ELF with no interpreter and no
host libraries. Its `_start` writes `Hello, LATC!` with the x86 Linux `write`
syscall and exits with the x86 Linux `exit` syscall. This is the first direct
static-translation test. `tests/x86-glibc-hello.c` is the separate full static
glibc fixture used after the smaller call, helper, IFUNC, and auxv tests pass.
It validates `argc`, `argv`, and `getenv`, then prints `Hello from glibc!` and
exits successfully on the 3A6000 test host. The generated LoongArch shell
currently links the small host runtime dynamically; producing a fully static
LoongArch ELF remains separate work.

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

For dependency-coverage acceptance, use `LATC_STRICT_FILE_AOT=1`. It rejects
JIT generation for code backed by an ELF file while allowing non-file mappings
such as the vDSO. `LATC_STRICT_AOT=1` remains the stronger diagnostic mode that
rejects every runtime translation attempt.

Embedded AOT is installed into `$HOME/.cache/latx` on first use. Later runs
reuse it only when a read-only cache file and its latc marker still match the
recorded SHA-256 digest, inode, size, and modification time. Runtime statistics
include `aot_cache_hit`, `bundle_verify_ns`, `guest_extract_ns`, and
`aot_prepare_ns` so startup costs can be separated from guest execution.
`runtime_tb_gen_attempts` is counted at translator entry; strict mode rejects
the attempt before decoding or generating host code.

An optional binary TB key set selects the translated blocks that belong in the
output. Its fixed header contains `LATTBKS`, the format version, source
SHA-256, record count, and sequence. Each fixed-size record contains an
ELF-relative virtual address and semantic translation flags. It deliberately
contains no execution count. Pass it with
`--tbset FILE`. TB-set compilation decodes and translates the ELF control-flow
graph once. The observed `(RVA, flags)` entries add dynamic targets and
translation variants that static decoding cannot derive. This includes CFG
paths that were not executed during collection, x86-64 lazy PLT binding
entries, and validated fixed-stride code-table targets. It avoids repeated
whole-program translation rounds. A wrong source
digest, an address outside executable sections, an unsupported flag, or a
malformed header or record fails compilation. There is no text profile format
or compatibility parser.

The native translation stage partitions the final TB set at page/TU boundaries
and translates the partitions concurrently. `LATC_AOT_THREADS=N` selects 1 to
32 translation threads; when unset, direct compilation uses up to 8 online
CPUs. `latcd` runs up to 8 ELF compile jobs concurrently by default and divides
the online CPUs among those jobs, so module-level and within-module parallelism
share one CPU budget. Explicit thread counts are honored, including 1 and 2.

An application can also seed the cache before it runs. Start the normal
resident `latcd`, then run:

```sh
latcd --precompile --socket "$XDG_RUNTIME_DIR/latcd.sock" \
  --x86-rootfs /path/to/x86-rootfs [--latc /path/to/latc] [--jobs 8] \
  /usr/bin/python3
```

The final argument is an absolute guest path inside the rootfs. The command
reads `PT_INTERP` and recursively resolves `DT_NEEDED`, using each object's
`RPATH`/`RUNPATH`, the rootfs `ld.so.cache`, and the standard x86-64 library
directories. It does not scan the rootfs or guess libraries loaded later by
`dlopen()`. It first resolves and statically analyzes every discovered ELF. If
any one fails, it submits nothing. Static analysis emits one `CF_PARALLEL` TB
variant per address; single-thread and multi-thread execution use that same
translation. After all analyses succeed, the command submits each
complete TB set to the resident service and waits for `FLUSH_SOURCE` before it
returns. A later runtime submission uses the same union-and-incremental-publish
path, so dynamically discovered TBs extend the static base instead of replacing
it.

Runtime precompilation is opt-in. Set `LATX_AOT_V2_PRECOMPILE=1` together
with `LATX_AOT_V2_CACHE_DIR` and `LATX_AOT_V2_LATCD_SOCKET`. When LAT maps an
x86 ELF that has no compatible cached module, it sends that source FD to the
resident `latcd` and blocks before guest execution. `latcd` derives the guest
path from its configured `--x86-rootfs`, runs the same dependency precompile
described above, and replies only after every accepted module is published.
LAT then loads the newly published module into the current process. The
default remains non-blocking incremental JIT collection when the variable is
unset or is not exactly `1`. A precompile failure is reported and falls back
to JIT unless strict AOT mode separately rejects the miss.

The module tables are emitted as binary data and included directly by the
assembler. They are not formatted as a large C source file for the host C
compiler to parse. `latcd` accepts a cached module as a TB-set hit only when
every requested `(RVA, flags)` pair exists in that module.

Module translation handles code-buffer exhaustion by bisecting the complete
input TB set, translating both halves, and merging their native images before
linking one module. Only the offline translator's dedicated buffer-exhaustion
status triggers this retry; other compilation failures remain failures. A
single-key input that still exhausts the buffer fails rather than retrying
indefinitely. Each successful merge removes its intermediate native children.
This resource handling does not exempt unsupported instructions or missing
requested keys from the daemon's publication checks.

For each source ELF, the version 2 `current` manifest names exactly one `.so`,
one canonical `.native` image, and one complete `.tbset`. The first publication
translates the complete set. A later publication subtracts the current module's
actual TB table, translates only keys that the module does not contain, merges
that native image into the canonical image, and links one replacement `.so`.
If the module already contains every newly observed key, `latcd` publishes only
the complete `.tbset` and manifest; it does not invoke translation or linking,
and the `.so` and `.native` remain unchanged. It does not keep a list of
incremental modules. The three
immutable generation files are synchronized before an atomic manifest rename;
only after that commit does `latcd` remove the superseded generation. A failed
compile, merge, link, or pre-manifest publication leaves the prior manifest and
all files it names unchanged. This manifest has no older-format parser.

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

`aot-v2-source-map.json` records every canonical AOT v2 integration source and
its generated copy. It covers the main LAT to `tools/latc/lat` copies, the
`tools/latc/aot-v2` runtime files copied into the main runner tree, and the
shared native headers. Generated files marked in `lat-local.json` keep the
minimal imported LAT tree complete; do not edit any mapped target directly.
Regenerate and verify all mapped targets with:

```sh
make -C tools/latc sync-aot-v2-sources
make -C tools/latc check-import
```

`prepare-runner-source.py` reads the same source map and copies its canonical
files into a staging runner. Files in `lat-local.json` without `generated=true`
exist only in the minimal imported tree and remain directly maintained there.
`check-import` prints both the generated path and its canonical source when
they differ.

## Main build and installation

`test-aot-v2-static-vector-fallback` checks that partial static modules exclude
unsupported vector TBs while strict native compilation still rejects them.
Build `tests/x86-static-vector-fallback.S` with an x86 assembler/compiler and
set `LATC_STATIC_VECTOR_GUEST` to that ELF when running the Meson integration
test. The fixture is test-only and is not built by normal product builds.

On a LoongArch host, the main Meson build installs one matching AOT v2
toolchain. Configure an explicit prefix, build, and install it as one unit:

```sh
mkdir build-aot-v2 && cd build-aot-v2
../configure --target-list=x86_64-linux-user --enable-latx \
  --optimize-O1 --disable-docs --prefix=/path/to/prefix
ninja
meson install
```

The prefix contains `bin/latx-x86_64`, `bin/latc`, `bin/latcd`,
`lib/liblat-aot-runtime.so.2`, and the compiler helper files below
`libexec/latc`. All four programs and libraries embed the same deterministic
64-character build identity. `latcd` checks the compiler, runner, runtime ABI,
and runtime identity before creating a socket, writing cache files, or running
a compile job. A mismatch is reported and the application can continue with
its normal JIT fallback.

Run the installation-tree integration test with an x86 rootfs and a dynamic
x86 guest. The test does not use binaries or helper scripts from the build
directory:

```sh
make -C tools/latc test-aot-v2-install \
  INSTALL_PREFIX=/path/to/prefix \
  X86_ROOTFS=/path/to/x86-rootfs \
  X86_GUEST=/path/to/x86-rootfs/usr/bin/echo
```

Each `latcd --serve` or `latcd --once` process takes a non-blocking exclusive
lock on `<cache>/.latcd.lock` before it creates a socket, temporary file,
module, profile, or `current` index. A second process using the same cache exits
with `cache is already owned by another latcd`; use a separate cache directory
if both daemons must run. The lock descriptor remains open for the daemon's
whole lifetime. The kernel releases it after either a normal exit or a crash,
so the text left in `.latcd.lock` is diagnostic information, not a PID-file
liveness check. Service statistics include `cache_owner_pid`.

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
bundle. `continuation_tbs` counts TBs added when LAT ends a TB before the end of
its containing CFG block, including instruction-limit and internal translator
splits. `edge_target_tbs` counts executable static-edge targets not represented
by a standalone CFG block. Jump-table case targets must be CFG TB leaders; the
runner does not scan past alignment NOPs to compensate for missing targets.

For AOT v2, the runtime does not increment counters while a TB executes. It
records the exact `(RVA, semantic flags)` key once when a file-backed TB is
created. A background thread submits pending per-source sets every 100 ms;
normal exit and pre-`execve` handling submit any remainder. It never scans the
global JIT TB table. latcd unions keys from all processes; an unchanged set
does not schedule another compile. In `--flush-only` mode it performs no
compilation until `FLUSH_SOURCE` or `FLUSH_ALL`, then schedules the accepted
source sets. Concurrent new keys may require another compile; keys accepted
after a flush need a later flush to schedule that increment. The flush waits
until every previously accepted set is published or
an explicit compile error is returned. A successful flush has already merged
and relinked every accepted increment; it never reports success for a pending
fragment.

Profile-module generation is single-pass. The compiler must include every
requested TB and its required direct branch targets in that pass. A missing
static target fails the job and is reported; the driver does not retry with
supplemental TB sets.

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

All twelve SPECint2000 integer train workloads passed on the AOSC 3A6000 host
on 2026-08-21. Each individual command used a 30-second hard timeout; the
slowest command completed in 16.76 seconds. VPR was checked with the official
numeric tolerances and all other outputs matched byte for byte. Ref inputs have
not been run. A subsequent full run through `myrun1.sh train` regenerated all
twelve ELFs first, then produced twelve official SPEC `.raw` results with
`valid=1`; the slowest whole benchmark was perlbmk at 44.11 seconds under the
60-second per-benchmark limit.

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
