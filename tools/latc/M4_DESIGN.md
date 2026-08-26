# AOT v2 M4 design

## Processes

The LAT runner is only a client. It detects an eligible file-backed executable
ELF mapping and sends a nonblocking request to the current user's `latcd` Unix
socket. `latcd` owns source snapshots, compiler children, validation, cache
publication, duplicate suppression, and failure throttling.

The translated process never forks to compile. It also never waits for a
compile result while holding an mmap lock or executing guest code.

## Request protocol

The local transport is `AF_UNIX` with `SOCK_SEQPACKET`. Each version 1 request
contains a fixed-size header and exactly one file descriptor passed with
`SCM_RIGHTS`.

```c
struct LatcdRequestV1 {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t priority;
    uint32_t flags;
    uint64_t request_id;
};
```

The request contains no source path. The service rejects a truncated packet,
unknown flags, multiple descriptors, non-regular files, writable descriptors,
non-x86 ELF files, and files larger than the configured input limit.

`latcd --once` accepts one request and replies after publication. The resident
service acknowledges a valid queued request promptly; compilation completion
is observable through the cache and service counters, not by blocking the
runtime client.

## Stable identity

After receiving the descriptor, `latcd` verifies it with `fstat`, reads it into
a private temporary snapshot, and calculates SHA-256 over the copied bytes.
The service compares file metadata before and after copying. A size or identity
change rejects the request. Compilation always reads the snapshot, never the
caller's original descriptor.

The job key is:

```text
(source_sha256, aot_abi, codegen_id, required_host_features, page_size)
```

M4 initially retains the M3 lookup-compatible published path
`<cache>/<source_sha256>.so`. Variant metadata is validated inside the module;
the resident service later adds a small atomic `current` index while retaining
the flat path until the runner has migrated.

## Compilation and publication

For one job, the service performs these steps:

1. Create cache and temporary directories with mode `0700`.
2. Copy the source FD to a mode `0600` temporary snapshot and calculate SHA-256.
3. Start `latc compile-module` with trusted daemon configuration and the
   snapshot path. The request cannot choose the compiler or output path.
4. Apply CPU-time, address-space, output-size, and file-descriptor limits to the
   compiler child.
5. Inspect the produced module and compare its embedded source SHA-256 with the
   snapshot digest. Normal runtime validation still checks ABI, codegen ID,
   required ISA features, page size, tables, and relocations when loading it.
6. `fsync` the module, atomically rename it to its final cache path, and
   `fsync` the containing directory.
7. Remove all temporary files on success or failure.

An already valid final module makes the request a cache hit. Invalid existing
files are never trusted or overwritten in place; the service builds a new
temporary module and replaces the path atomically only after validation.

## Queue and failure handling

The resident service has one compiler worker by default. Startup objects use a
higher priority than libraries discovered later. The queue has fixed limits on
job count and total input bytes. Duplicate job keys attach to the existing job
instead of starting another compiler.

A failed job records the job key, reason class, compiler identity, attempt
count, and retry time. The delay grows with repeated failures and is capped.
Changing source bytes or the compiler/codegen identity creates a different key
and does not inherit the old failure. Negative-cache records have an expiry and
a size bound.

## Runtime submission

The runner keeps a small set of source identities already submitted by the
process. It submits only a validated x86 `ET_EXEC` or `ET_DYN` regular file that
owns an executable `PT_LOAD`. Main image and interpreter submission happens
after their descriptors are available. DSO submission happens after the mmap
ELF tracker has identified the complete image.

Socket creation and sending are nonblocking. `ENOENT`, `ECONNREFUSED`, queue
full, and short-lived resource errors increment diagnostics and return to JIT.
No compile callback can replace a module in the current registry instance.

## Security boundary

`latcd` is per-user and creates its socket and cache below a user-owned `0700`
directory. It checks peer credentials, does not follow cache symlinks, does not
accept path or command arguments from requests, and drops unexpected ancillary
descriptors. Compiler children receive only the snapshot, output path, runner,
runtime directory, and a minimal environment.

## Implementation status

`WI-2273` implements the version 1 packet, `SCM_RIGHTS` transfer, stable source
snapshot and SHA-256 calculation, x86 ELF checks, existing-cache validation,
compiler invocation, output inspection, source-digest comparison, read-only
artifact mode, `fsync`, atomic rename, and temporary-file cleanup. The
`--submit` mode is a synchronous diagnostic client for this one-request step.

The resident service, peer credential check, compiler `rlimit` values, minimal
child environment, priority queue, duplicate suppression, negative cache, and
nonblocking runner client are not implemented by `WI-2273`; they belong to the
remaining M4 work items.
