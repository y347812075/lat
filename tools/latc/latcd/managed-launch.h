#ifndef LATCD_MANAGED_LAUNCH_H
#define LATCD_MANAGED_LAUNCH_H

#include <glib.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

typedef struct LatcdManagedLaunchInput {
    uint8_t build_sha256[32];
    uint8_t codegen_sha256[32];
    uint8_t config_sha256[32];
    uint8_t source_sha256[32];
    uint8_t receipt_sha256[32];
    uint8_t closure_sha256[32];
    uint64_t receipt_size;
    int compiler_fd;
    int runner_fd;
    int runtime_fd;
    int launcher_fd;
    int bootstrap_fd;
    int baseline_fd;
    const GPtrArray *options;
    const GPtrArray *exec;
    const char *const *environment;
} LatcdManagedLaunchInput;

/* Persist the exact final launch plan in the daemon-private metadata store.
 * The record is written before the first durable launch state and is verified
 * against the live inputs immediately before execution; binding the digest
 * into a versioned managed state record is still outstanding, so this record
 * is an audit/consistency artifact and not an execution barrier by itself. */
int latcd_managed_launch_prepare(const char *root, const char *id, int task_fd,
    const LatcdManagedLaunchInput *input, struct stat *identity,
    char digest[65], char *error, size_t error_size);

/* current is optional and, when present, requires exact equality with the
 * recorded argv/environment and current file identities. Recovery uses the
 * persisted identity and digest with current == NULL. */
int latcd_managed_launch_verify(const char *root, const char *id, int task_fd,
    const struct stat *identity, const char *digest,
    const LatcdManagedLaunchInput *current, char *error, size_t error_size);

/* Recovery-side structural validation. It binds the private record to the
 * held task and cache identities but cannot compare the original live fds. */
int latcd_managed_launch_validate_self(const char *root, const char *id, int task_fd,
    char *error, size_t error_size);

int latcd_managed_launch_discard(const char *root, const char *id, int task_fd,
    char *error, size_t error_size);

#endif
