#ifndef LATCD_CACHE_RETIREMENT_H
#define LATCD_CACHE_RETIREMENT_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct LatcdRecoveryCursor LatcdRecoveryCursor;
typedef struct LatcdRecoveryProgress {
    unsigned visited;
    unsigned recovered;
    uint64_t hashed_bytes;
} LatcdRecoveryProgress;

/* Owner lease required throughout cursor lifetime. Each step has entry/hash-byte
 * and soft wall-time budgets; individual syscalls/fsync may exceed the latter.
 * Returns 1 for pending, 0 for complete, -1 on error. No removal is authorized. */
LatcdRecoveryCursor *latcd_recovery_open(const char *root, bool tombstones,
                                        char *error, size_t error_size);
int latcd_recovery_step(LatcdRecoveryCursor *cursor, unsigned entries,
                        uint64_t hash_bytes, uint64_t time_us,
                        LatcdRecoveryProgress *progress, char *error, size_t error_size);
void latcd_recovery_close(LatcdRecoveryCursor *cursor);

/* Explicit rollback/migration/external roots, not domain admission. The owner
 * lease is required; these operations acquire source EX themselves. A hold is
 * bound to cache/object inode and must be explicitly released by exact id.
 * Released records remain as evidence. No automatic expiry or removal. */
int latcd_retirement_hold(const char *root, const char *source, const char *name,
                           const char *id, const char *reason, bool release,
                           char *error, size_t error_size);

/* Capture at most six immutable objects outside the daemon metadata lock.
 * Returned structured evidence is owned by the caller; NULL means unproven. */
char *latcd_retirement_capture_objects(const char *root, const char *source,
                                      const char *const *names, size_t count);

/* Strict snapshot schema and complete old/new object-set/hash binding. */
int latcd_retirement_validate_binding(const char *source,
                                      const char *previous, size_t previous_size,
                                      const char *next, size_t next_size,
                                      const char *objects, size_t objects_size);

/* Caller holds source EX and has rechecked every reference/admission root.
 * evidence is a single-object capture taken outside the source latch while the
 * caller retains the object's SH lease. Caller guarantees immutable contents.
 * Takes EX|NB on object_fd; caller closes it on success AND failure. Writes intent only;
 * this API does not admit a domain or authorize/perform unlink. */
int latcd_retirement_tombstone(const char *root, const char *source,
                               const char *name, int object_fd, const char *evidence,
                               char *error, size_t error_size);

/* The caller owns the cache management lease; prepare/finish also require the
 * source commit latch. Recovery may durably complete an exactly bound intent
 * for an already-missing non-current path. It never authorizes file removal. */
int latcd_retirement_prepare(const char *root, const char *source,
                            const char *next, size_t next_size, const char *objects,
                            char **transaction, char *error, size_t error_size);
int latcd_retirement_finish(const char *root, const char *transaction,
                           char *error, size_t error_size);
int latcd_retirement_recover(const char *root, unsigned *recovered,
                            char *error, size_t error_size);

/* Reconcile deletion evidence under the cache owner lease. Observation only:
 * no unlink, no admission, and MISSING does not prove released disk blocks. */
int latcd_tombstone_recover(const char *root, unsigned *recovered,
                            char *error, size_t error_size);

/* Internal executor, not a domain admission API. Caller owns management lease
 * and guarantees controlled access/mounts, elapsed grace, no rollback/migration/
 * worker/publication/transaction roots. Explicit holds and bounded task-input
 * and transaction roots are rechecked as defense in depth, not a full graph.
 * One pre-existing tombstone only; checks
 * current and immutable identity again. No CLI/automatic caller is enabled. */
int latcd_tombstone_delete(const char *root, const char *name,
                            char *error, size_t error_size);

/* Preferred executor entry: in addition to the same external domain/owner
 * contract, recheck fully bound retirement and BOOTTIME grace under source EX.
 * No retirement, reboot mismatch, future stamp or overflow rejects removal. */
int latcd_tombstone_delete_due(const char *root, const char *name, uint64_t grace_us,
                               char *error, size_t error_size);

typedef struct LatcdRetirementQueue LatcdRetirementQueue;
typedef struct LatcdRetirementQueueStats {
    unsigned candidates, due, visited;
    uint64_t next_deadline_us, oldest_due_wait_us;
    bool complete;
} LatcdRetirementQueueStats;

/* Single I/O worker owns this diagnostic queue under the management lease.
 * Bounded transaction discovery only, not liveness verification/admission.
 * Retains original enqueue time across sweeps; no deletion or timer handoff. */
LatcdRetirementQueue *latcd_retirement_queue_new(const char *root, uint64_t grace_us);
int latcd_retirement_queue_step(LatcdRetirementQueue *queue, unsigned entries,
                                 uint64_t time_us, LatcdRetirementQueueStats *stats,
                                 char *error, size_t error_size);
void latcd_retirement_queue_free(LatcdRetirementQueue *queue);

typedef struct LatcdRetirementAttempt {
    char name[138];
    uint64_t sequence;
} LatcdRetirementAttempt;

/* Single executor, one outstanding attempt. now_us is BOOTTIME used only for
 * scheduling, never deletion admission. Returns 1 selected, 0 no ready work,
 * -1 invalid use. Rotates sources and then least-recently-attempted objects.
 * Deferral preserves original age and uses bounded exponential busy backoff.
 * A stale completion token cannot change another attempt. No unlink occurs. */
int latcd_retirement_queue_take(LatcdRetirementQueue *queue, uint64_t now_us,
                                LatcdRetirementAttempt *attempt);
int latcd_retirement_queue_defer(LatcdRetirementQueue *queue,
                                 const LatcdRetirementAttempt *attempt,
                                 uint64_t now_us, bool busy);

/* Owner lease and single queue worker required. Strict cache/boot/grace-bound
 * scheduler checkpoint; never restores discovery completeness or deadlines.
 * Restore before the first sweep. A reboot starts fresh scheduling ages.
 * Missing checkpoint is normal; corrupt/unsafe metadata is an error. */
int latcd_retirement_queue_checkpoint(LatcdRetirementQueue *queue,
                                      char *error, size_t error_size);
int latcd_retirement_queue_restore(LatcdRetirementQueue *queue,
                                   char *error, size_t error_size);

#endif
