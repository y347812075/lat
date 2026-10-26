#ifndef LATC_NATIVE_TU_AUDIT_H
#define LATC_NATIVE_TU_AUDIT_H

#include <stddef.h>
#include <stdint.h>

typedef struct LatNativeTuReferenceAudit {
    uint64_t instructions;
    uint64_t patch_windows;
    uint64_t local_branches;
    uint64_t local_addresses;
} LatNativeTuReferenceAudit;

/* Final-code defense for recorded patches and remaining PC-relative references.
 * Not a certificate of absolute-address provenance, reachability or fallthrough.
 * Success does not authorize execution or configuration reuse. */
int lat_native_tu_audit_references(const void *data, size_t size,
    LatNativeTuReferenceAudit *audit, char *error, size_t error_size);

typedef struct LatNativeTuExecutionAudit {
    uint64_t entries;
    uint64_t reachable_words;
    uint64_t recorded_transfers;
    uint64_t local_transfers;
    uint64_t helper_calls;
    uint64_t dispatch_windows;
} LatNativeTuExecutionAudit;

/* Walk the conservative successor graph from every recorded TB entry. Unknown
 * indirect transfers fail. This still does not prove absolute-address sources
 * or authorize movement/configuration reuse. Runs the reference audit first. */
int lat_native_tu_audit_execution(const void *data, size_t size,
    LatNativeTuExecutionAudit *audit, char *error, size_t error_size);

#endif
