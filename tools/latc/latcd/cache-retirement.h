#ifndef LATCD_CACHE_RETIREMENT_H
#define LATCD_CACHE_RETIREMENT_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct LatcdRecoveryCursor LatcdRecoveryCursor;
/* Owner lease required. Acquire after source latch, never wait under cache_lock.
 * Publishers hold SH through transaction finish; retirement/deletion holds EX.
 * Returned CLOEXEC fd is released by close only. Not domain admission. */
int latcd_retirement_roots_lock(const char *root, int operation,
                                char *error, size_t error_size);
/* Owner lease and cooperating transaction writers required. Samples only;
 * caller must persist the result before using it as a pagination round bound.
 * This is not domain admission or deletion authorization. */
int latcd_retirement_round_sample(const char *root, char boot[37], uint64_t *cutoff,
                                  char *error, size_t error_size);
typedef struct LatcdRetirementRound {
    char boot[37];
    uint64_t cutoff;
} LatcdRetirementRound;
/* Validate and normalize a persisted round cursor. A cursor from another boot
 * is not reusable; the caller must sample a fresh one. Completion advances the
 * cutoff only after the caller has committed the page. No removal authority. */
int latcd_retirement_round_restore(LatcdRetirementRound *round,
                                   const char *boot, uint64_t cutoff);
int latcd_retirement_round_complete(LatcdRetirementRound *round,
                                    const char *boot, uint64_t observed_cutoff);
typedef struct LatcdRetirementPage {
    char next_cursor[138];
    unsigned count;
} LatcdRetirementPage;
typedef struct LatcdRetirementPageDeadline {
    char name[138];
    uint64_t deadline, enqueued, last_attempt, retry_at;
    unsigned busy_count;
} LatcdRetirementPageDeadline;
typedef struct LatcdRetirementPageState {
    uint64_t cache_device, cache_inode, grace_us;
    char boot[37];
    char cursor[138];
    uint64_t sequence;
    unsigned count;
    LatcdRetirementPageDeadline entries[128];
} LatcdRetirementPageState;
/* Select the next stable-name page from a caller-provided sorted list. Names
 * must be valid object basenames. This is scheduling only, never admission. */
int latcd_retirement_page_select(const char *const *names, size_t count,
                                 const char *after, LatcdRetirementPage *page);
/* Aggregate a transaction deadline into a selected page. Objects outside the
 * page are ignored; repeated observations retain the maximum deadline. */
int latcd_retirement_page_observe(LatcdRetirementPageDeadline *deadlines,
                                  size_t count, const char *name, uint64_t deadline);
/* Copy selected page names into a compact bounded array for second-pass
 * aggregation. Returns the number copied, or -1 for invalid/oversized input. */
int latcd_retirement_page_names(const char *const *names, size_t count,
                                const LatcdRetirementPage *page,
                                char selected[128][138]);
/* Validate an in-memory page state. This does not serialize, discover, or
 * authorize deletion; count is bounded and entries must be unique/sorted. */
int latcd_retirement_page_state_valid(const LatcdRetirementPageState *state);
/* Owner lease required. Persist/read only the bounded scheduler page state;
 * this is not discovery completeness, reference proof, or deletion authority. */
int latcd_retirement_page_state_store(const char *root,
                                      const LatcdRetirementPageState *state,
                                      char *error, size_t error_size);
int latcd_retirement_page_state_load(const char *root, LatcdRetirementPageState *state,
                                     char *error, size_t error_size);
/* Runtime compatibility check for a loaded page. A different boot or grace
 * invalidates retry/attempt ages; callers must rescan rather than reuse them. */
int latcd_retirement_page_state_compatible(const LatcdRetirementPageState *state,
                                           const char *boot, uint64_t grace_us);
/* Load and validate a page for the current boot/grace without consuming it.
 * Returns 1 when absent, 0 when usable, -1 when unsafe/incompatible. */
int latcd_retirement_page_state_resume(const char *root, const char *boot,
                                       uint64_t grace_us, LatcdRetirementPageState *state,
                                       char *error, size_t error_size);
/* Build a bounded page plan from the complete sorted candidate key set. The
 * input remains intact for later pages; entries outside the page are omitted. */
int latcd_retirement_page_plan(const char *const *names, size_t count,
                               const char *after, const LatcdRetirementPageDeadline *schedule,
                               size_t schedule_count, LatcdRetirementPageState *state);
typedef struct LatcdRecoveryProgress {
    unsigned visited;
    unsigned recovered;
    uint64_t hashed_bytes;
} LatcdRecoveryProgress;

/* Domain presence establishes stable participant identity only, not access or
 * mount isolation. Returns 1 for a valid managed domain, 0 for a legacy root,
 * and -1 for malformed/unsafe domain metadata. id is optional (size >= 37). */
int latcd_cache_domain_validate(const char *root, char id[37],
                                char *error, size_t error_size);
/* Explicit, idempotent initialization. Returns a new CLOEXEC lock fd only for
 * the duration of initialization; participants reopen the stable lock later. */
int latcd_cache_domain_init(const char *root, char id[37],
                            char *error, size_t error_size);

/* Owner lease required throughout cursor lifetime. Transaction steps acquire
 * roots SH nonblocking and return an error if it is busy or unsafe; the cursor
 * may be retried. The lock is not held across yields. Each step has entry/hash-byte
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

/* Controlled mount participants acquire roots SH before exposing a mount and
 * keep the returned CLOEXEC fd open for the mount lifetime. The durable ACTIVE
 * record remains a hold after participant death until exact release. Scopes are
 * CACHE, SOURCE, or OBJECT; non-participant mounts are outside this contract. */
int latcd_retirement_mount_lease(const char *root, const char *id, const char *scope,
                                 const char *source, const char *name,
                                 char *error, size_t error_size);
int latcd_retirement_mount_release(const char *root, const char *id, int lease_fd,
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

/* The caller owns the cache management lease and holds roots SH through
 * prepare, current publication and finish; it also holds the source commit
 * latch. Recovery may durably complete an exactly bound intent for an
 * already-missing non-current path. It never authorizes file removal. */
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

typedef struct LatcdRetirementDeletionReport {
    uint64_t logical_bytes, allocated_bytes_before, unlinked_allocated_bytes;
    uint64_t filesystem_available_before, filesystem_available_after;
    bool object_unlinked, namespace_durable, receipt_durable;
    bool filesystem_before_valid, filesystem_after_valid;
} LatcdRetirementDeletionReport;

/* Same internal-only admission contract as above. Reports partial progress even
 * on error. AFTER is sampled after closing the executor's object fd. Free-space
 * observations include metadata and other writers, never verified release. An
 * already-missing name does not count as a new unlink or released bytes. */
int latcd_tombstone_delete_report(const char *root, const char *name,
    LatcdRetirementDeletionReport *report, char *error, size_t error_size);
int latcd_tombstone_delete_due_report(const char *root, const char *name, uint64_t grace_us,
    LatcdRetirementDeletionReport *report, char *error, size_t error_size);

typedef struct LatcdRetirementQueue LatcdRetirementQueue;
typedef struct LatcdRetirementQueueStats {
    unsigned candidates, due, visited;
    unsigned ready, deferred;
    uint64_t next_deadline_us, oldest_due_wait_us;
    uint64_t next_attempt_us;
    bool complete;
} LatcdRetirementQueueStats;

/* Single I/O worker owns this diagnostic queue under the management lease.
 * Bounded transaction discovery only, not liveness verification/admission.
 * Creates the private transaction store if absent before monitored discovery.
 * Retains original enqueue time across sweeps; fully object-bound UNLINKED /
 * MISSING receipts remove completed names only after absence is rechecked.
 * No deletion or timer handoff; missing alone never completes a candidate. */
LatcdRetirementQueue *latcd_retirement_queue_new(const char *root, uint64_t grace_us);
/* Diagnostic only: number of distinct object keys seen in the current
 * first-pass discovery. Zero outside an active incomplete page scan. */
unsigned latcd_retirement_queue_discovered_keys(const LatcdRetirementQueue *queue);
/* Diagnostic conversion of the current complete key index into a page plan.
 * Does not select candidates, mutate queue state, or authorize deletion. */
int latcd_retirement_queue_page_plan(const LatcdRetirementQueue *queue, const char *after,
                                     LatcdRetirementPageState *state);
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
 * Deferral preserves original age and uses 60s..3600s exponential busy backoff.
 * A stale completion token cannot change another attempt. No unlink occurs. */
int latcd_retirement_queue_take(LatcdRetirementQueue *queue, uint64_t now_us,
                                LatcdRetirementAttempt *attempt);
int latcd_retirement_queue_defer(LatcdRetirementQueue *queue,
                                 const LatcdRetirementAttempt *attempt,
                                 uint64_t now_us, bool busy);

/* Internal single-candidate consumer; SAME external owner/domain/access/mount/
 * full-reference-graph guarantees as tombstone_delete_due_report are required.
 * Selection never authorizes deletion. Hash outside S, then recheck grace and
 * roots under S before intent; executor rechecks independently. Existing intent
 * is resumed, never overwritten. Returns 1 completed, 0 no ready candidate,
 * -1 deferred/error. Attempt is released on every selected path. Completion
 * remains queued until a later sweep verifies bound receipt plus absence.
 * Caller checkpoints after completion/deferral; no CLI/daemon caller enabled. */
int latcd_retirement_queue_execute_one(LatcdRetirementQueue *queue,
    LatcdRetirementDeletionReport *report, char *error, size_t error_size);

/* Same admission contract as execute_one. Adds per-step hash byte and soft
 * time budgets, returning 2 when yielded with an outstanding attempt. Hashed
 * bytes reports this step only. No S/roots lock survives a yield; only the SH
 * hashing pin may remain. Single worker must finish/cancel before checkpoint.
 * Filesystem calls and existing metadata checks are not hard-time bounded. */
int latcd_retirement_queue_execute_step(LatcdRetirementQueue *queue,
    uint64_t hash_bytes, uint64_t time_us, uint64_t *hashed_bytes,
    LatcdRetirementDeletionReport *report, char *error, size_t error_size);
/* Releases resumable state/pin and busy-defers its attempt; no unlink. Queue
 * destruction also releases pins. Persistent intent is never rolled back. */
int latcd_retirement_queue_cancel(LatcdRetirementQueue *queue,
                                  char *error, size_t error_size);

/* Owner lease and single queue worker required. Strict cache/boot/grace-bound
 * scheduler checkpoint; never restores discovery completeness or deadlines.
 * Restore before the first sweep. A reboot starts fresh scheduling ages.
 * Missing checkpoint is normal; corrupt/unsafe metadata is an error. */
int latcd_retirement_queue_checkpoint(LatcdRetirementQueue *queue,
                                      char *error, size_t error_size);
int latcd_retirement_queue_restore(LatcdRetirementQueue *queue,
                                   char *error, size_t error_size);

/* Single worker, after all publishers stop. Saves scheduling hints even for
 * partial discovery, then a cache/boot-bound exit record. A fresh sweep and
 * admission checks remain mandatory. reason is IDLE or STOP; no timer promise. */
int latcd_retirement_queue_handoff(LatcdRetirementQueue *queue, const char *reason,
                                   char *error, size_t error_size);

#endif
