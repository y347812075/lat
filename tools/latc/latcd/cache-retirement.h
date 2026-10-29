#ifndef LATCD_CACHE_RETIREMENT_H
#define LATCD_CACHE_RETIREMENT_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

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
typedef struct LatcdRetirementRetryItem {
    LatcdRetirementPageDeadline hint;
    LatcdRetirementPageDeadline aggregate;
    uint64_t shard_sequence;
    uint8_t shard_digest[32];
    bool shard_sequence_bound;
    bool matched;
} LatcdRetirementRetryItem;
/* Immutable input to a retry checkpoint. It is not removal authority. */
typedef struct LatcdRetirementRetryPage {
    uint64_t cache_device, cache_inode, grace_us, round_cutoff, round_sequence;
    uint64_t snapshot_time, snapshot_sequence;
    char boot[37], committed_cursor[138], retry_cursor[138], end_cursor[138];
    unsigned count;
    LatcdRetirementRetryItem items[128];
    /* Sequential progress and expected replacement digests; no deletion authority. */
    unsigned completed;
    bool intent_present;
    uint8_t replacement_digest[128][32];
    size_t intent_size;
    uint8_t intent_data[1024];
    size_t intent_original_size;
    uint8_t intent_original[1024];
} LatcdRetirementRetryPage;
int latcd_retirement_retry_page_identity(const LatcdRetirementRetryPage *page,
                                        uint8_t digest[32]);
int latcd_retirement_retry_page_budget_identity(const LatcdRetirementRetryPage *page,
                                               uint8_t digest[32]);
/* Codec for a complete immutable checkpoint; free encoded data with g_free. */
int latcd_retirement_retry_page_encode(const LatcdRetirementRetryPage *page,
                                       char **data, size_t *size);
int latcd_retirement_retry_page_decode(const char *data, size_t size,
                                       LatcdRetirementRetryPage *page);
/* Prepare a bounded deferral while preserving the original shard identity. */
int latcd_retirement_retry_prepare_unmatched(const LatcdRetirementRetryPage *page,
    const char *original, size_t size, uint64_t now_us, uint8_t output[1024]);
/* Select due hints in name order after a separate retry cursor, wrapping once.
 * This is a scheduling hint only; transaction rediscovery is still required. */
int latcd_retirement_retry_select(const LatcdRetirementPageDeadline *entries,
                                  size_t count, const char *after, uint64_t now_us,
                                  LatcdRetirementPageDeadline selected[128],
                                  unsigned *selected_count);
/* Read and validate all schedule shards before selecting due hints. The
 * caller owns the cache lease; output does not authorize deletion. */
int latcd_retirement_retry_snapshot(const char *root, const char *boot,
                                    uint64_t grace_us, uint64_t now_us, const char *after,
                                    LatcdRetirementPageDeadline selected[128], unsigned *selected_count,
                                    uint64_t *sequence, uint64_t selected_sequences[128],
                                    char *error, size_t error_size);
typedef struct LatcdRetirementConsumption {
    uint8_t completed[16];
    bool intent_present;
    unsigned intent_index;
    uint64_t device, inode, mode, uid, nlink, size, blocks;
    int64_t mtime_sec, ctime_sec;
    uint32_t mtime_nsec, ctime_nsec;
    uint8_t digest[32];
} LatcdRetirementConsumption;
typedef struct LatcdRetirementPageState {
    uint64_t cache_device, cache_inode, grace_us, round_cutoff;
    char boot[37];
    char committed_cursor[138];
    /* Independent position for retry selection; never advances the round cursor. */
    char retry_cursor[138];
    char cursor[138];
    uint64_t sequence;
    /* When set, cursor is the committed end; committed_cursor is its start.
     * The full page remains until a future verified reclamation protocol. */
    bool committed_pending;
    /* A validated persistent budget binding, not recovery or deletion authority. */
    bool budget_bound;
    /* Versioned consumption checkpoint, not deletion authorization. */
    bool consumption_bound;
    LatcdRetirementConsumption consumption;
    unsigned count;
    LatcdRetirementPageDeadline entries[128];
    /* Result types are populated only for a committed pending page. */
    uint8_t results[128];
} LatcdRetirementPageState;
int latcd_retirement_consumption_valid(const LatcdRetirementPageState *page,
                                       const LatcdRetirementConsumption *consumption);
int latcd_retirement_consumption_identity(const LatcdRetirementPageState *page,
                                          const LatcdRetirementConsumption *consumption,
                                          uint8_t digest[32]);
int latcd_retirement_consumption_bind(const LatcdRetirementPageState *page,
                                      LatcdRetirementConsumption *consumption,
                                      unsigned index, const struct stat *snapshot,
                                      const uint8_t digest[32]);
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
/* Deterministic page membership identity only; never grants deletion or commit. */
int latcd_retirement_page_identity(const LatcdRetirementPageState *state,
                                   uint8_t digest[32]);
/* Separate budget identity includes schedule sequence and member enqueue times.
 * It remains stable from in-flight to pending and does not reserve capacity. */
int latcd_retirement_page_budget_identity(const LatcdRetirementPageState *state,
                                          uint8_t digest[32]);
#ifdef LATCD_RETIREMENT_TESTING
/* Unrestricted fixture writer, excluded from production builds. */
int latcd_retirement_page_state_store(const char *root,
                                      const LatcdRetirementPageState *state,
                                      char *error, size_t error_size);
#endif
/* Read only bounded scheduling state, not deletion authority. */
int latcd_retirement_page_state_load(const char *root, LatcdRetirementPageState *state,
                                     char *error, size_t error_size);
/* Startup under the owner lease and closed capacity admission. Until persistent
 * page-budget recovery exists, refuse active or unsafe page checkpoints. */
int latcd_retirement_page_startup_check(const char *root, char *error, size_t error_size);
/* Owner lease required; reject incomplete lifecycle writes before recovery.
 * This checks for uncertainty, not access-domain admission. */
int latcd_retirement_startup_records_check(const char *root, char *error, size_t error_size);
/* Stage an in-flight page from an existing empty checkpoint. The caller must
 * hold the owner lease and control the namespace; this is not admission. */
int latcd_retirement_page_stage(const char *root, const LatcdRetirementPageState *page,
                                char *error, size_t error_size);
struct LatcdCacheCapacity;
struct LatcdPageBudget;
/* Owner lease required; budget storage must outlive all page writes. On error
 * a nonempty budget remains owned by the caller until recovery; never discard it. */
int latcd_retirement_page_stage_budgeted(const char *root, const LatcdRetirementPageState *page,
                                struct LatcdCacheCapacity *capacity, uint64_t limit,
                                struct LatcdPageBudget *budget, char *error, size_t error_size);
/* Owner lease required. Create an initial empty round only when no page state
 * exists, holding roots EX through clock sampling and durable storage. On any
 * error reload the state before retrying; an interrupted rename may persist.
 * This is scheduling state, not permission to consume or remove objects. */
int latcd_retirement_page_round_begin(const char *root, uint64_t grace_us,
                                      LatcdRetirementPageState *state,
                                      char *error, size_t error_size);
/* now_us is a current CLOCK_BOOTTIME sample for boot. A different boot/grace,
 * future cutoff/enqueue or retry beyond the maximum backoff invalidates it. */
int latcd_retirement_page_state_compatible(const LatcdRetirementPageState *state,
                                           const char *boot, uint64_t grace_us, uint64_t now_us);
/* Load and validate a page for the current boot/grace without consuming it.
 * Returns 1 when absent, 0 when usable, -1 when unsafe/incompatible. */
int latcd_retirement_page_state_resume(const char *root, const char *boot,
                                       uint64_t grace_us, uint64_t now_us, LatcdRetirementPageState *state,
                                       char *error, size_t error_size);
#ifdef LATCD_RETIREMENT_TESTING
extern void (*latcd_retirement_test_after_read)(void);
struct stat;
int latcd_retirement_test_read_snapshot(int directory, const char *name, size_t limit,
                                        char **contents, size_t *size, struct stat *snapshot,
                                        uint8_t digest[32]);
/* Fixture writers do not enforce a persisted in-flight page. */
int latcd_retirement_schedule_store(const char *root, const char *boot,
                                    uint64_t grace_us, uint64_t now_us,
                                    uint64_t sequence,
                                    const LatcdRetirementPageDeadline *entry,
                                    char *error, size_t error_size);
#endif
typedef enum LatcdRetirementResultKind {
    LATCD_RETIREMENT_RESULT_DONE = 1,
    LATCD_RETIREMENT_RESULT_DEFERRED = 2,
} LatcdRetirementResultKind;
#ifdef LATCD_RETIREMENT_TESTING
int latcd_retirement_schedule_store_result(const char *root, const char *boot,
                                    uint64_t grace_us, uint64_t now_us, uint64_t sequence,
                                    const LatcdRetirementPageDeadline *entry,
                                    const uint8_t page_identity[32],
                                    LatcdRetirementResultKind kind,
                                    char *error, size_t error_size);
#endif
/* Require a matching persisted in-flight page and member under scheduler lock.
 * Owner lease and controlled access remain required. DONE requires a receipt
 * witness protocol and is currently rejected. */
int latcd_retirement_schedule_store_page_result(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page,
                                    const LatcdRetirementPageDeadline *entry,
                                    LatcdRetirementResultKind kind,
                                    char *error, size_t error_size);
#ifdef LATCD_RETIREMENT_TESTING
/* Fixture-only synthetic result, including DONE without a receipt. */
int latcd_retirement_test_store_page_result(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page,
                                    const LatcdRetirementPageDeadline *entry,
                                    LatcdRetirementResultKind kind,
                                    char *error, size_t error_size);
#endif
/* Returns 0 for a matching v2 result, 1 for absent/v1/other page, -1 on
 * unsafe storage. Results are hints only, not commit or deletion authority. */
int latcd_retirement_schedule_load_result(const char *root, const char *boot,
                                    uint64_t grace_us, uint64_t now_us, const char *name,
                                    const uint8_t page_identity[32],
                                    LatcdRetirementResultKind *kind,
                                    char *error, size_t error_size);
/* Single monitored scan of all page members. Returns 0 only when all have a
 * matching result, 1 if any are absent, -1 if unsafe. No commit authority. */
int latcd_retirement_schedule_check_page(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page,
                                    char *error, size_t error_size);
/* Diagnostic snapshot only: 0 absent, 1 done, 2 deferred, 3 conflicting record,
 * 4 matching prior scheduling snapshot requiring a new result.
 * Cleared on error.
 * Caller must revalidate under its scheduling lease before using any result. */
int latcd_retirement_schedule_page_results(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page,
                                    uint8_t results[128], char *error, size_t error_size);
/* Snapshot the current persisted page and its results under the scheduling
 * lock. Caller holds the owner lease and controls writers. Results are hints,
 * not a capacity reservation or deletion authority; lock is released on return.
 * Result 3 is a conflicting member; undersized_member prevents treating an
 * existing member as a fully charged fixed-size result. Member identities are
 * diagnostic snapshots of matching results only; revalidate before use and
 * never use them alone as deletion authority. */
typedef struct LatcdRetirementPageInventory {
    unsigned occupied_slots;
    uint64_t occupied_bytes;
    bool undersized_member;
    struct {
        bool present;
        struct stat snapshot;
        uint8_t digest[32];
    } members[128];
} LatcdRetirementPageInventory;
/* Classify a pending-page inventory for consumption recovery. This does not
 * prove namespace isolation, synchronize a deletion, or grant admission. */
int latcd_retirement_consumption_check_inventory(const LatcdRetirementPageState *page,
                                    const LatcdRetirementConsumption *consumption,
                                    const uint8_t results[128],
                                    const LatcdRetirementPageInventory *inventory);
int latcd_retirement_consumption_budget_estimate(const LatcdRetirementPageState *page,
                                    const LatcdRetirementConsumption *consumption,
                                    const uint8_t results[128],
                                    const LatcdRetirementPageInventory *inventory,
                                    uint64_t *bytes);
int latcd_retirement_page_snapshot(const char *root, uint64_t now_us,
                                    LatcdRetirementPageState *page,
                                    uint8_t results[128], LatcdRetirementPageInventory *inventory,
                                    char *error, size_t error_size);
/* Estimate only; snapshot must be revalidated under the scheduling lock before
 * reserving. Conflicting or undersized members cannot be recovered this way. */
int latcd_retirement_page_budget_estimate(const LatcdRetirementPageState *page,
                                    const uint8_t results[128],
                                    const LatcdRetirementPageInventory *inventory,
                                    uint64_t *bytes);
/* Owner lease and closed capacity recovery gate required. expected_grace_us is
 * the target runtime configuration, not a value inferred from the checkpoint.
 * Restores a validated
 * in-flight or complete pending budget-bound page; caller retains budget until resolution.
 * Returns 0 on restoration, 1 if no page exists, -1 on unsafe state. */
int latcd_retirement_page_restore_budget(const char *root, struct LatcdCacheCapacity *capacity,
                                    uint64_t limit, uint64_t expected_grace_us,
                                    struct LatcdPageBudget *budget,
                                    LatcdRetirementPageState *page, char *error, size_t error_size);
/* Begin a consumption checkpoint after revalidating every pending shard. */
int latcd_retirement_consumption_begin(const char *root, uint64_t now_us,
                                    struct LatcdPageBudget *budget, char *error, size_t error_size);
/* Persist one done shard's current identity under the scheduler lock. */
int latcd_retirement_consumption_prepare(const char *root, uint64_t now_us, unsigned index,
                                    struct LatcdPageBudget *budget, char *error, size_t error_size);
/* Owner lease and controlled namespace required; recovery gate must be closed. */
int latcd_retirement_consumption_apply(const char *root, uint64_t now_us,
                                    struct LatcdPageBudget *budget, char *error, size_t error_size);
/* Advance only after all done shards were consumed; deferred shards remain. */
int latcd_retirement_consumption_finish(const char *root, uint64_t now_us,
                                    struct LatcdPageBudget *budget, char *error, size_t error_size);
/* Caller holds the owner lease and serializes budget lifetime. These operations
 * require a persisted budget binding and never authorize object deletion.
 * DONE is rejected until a receipt witness protocol is implemented. */
int latcd_retirement_page_budget_result(const char *root, uint64_t now_us,
                                    const uint8_t identity[32], struct LatcdPageBudget *budget,
                                    const LatcdRetirementPageDeadline *entry,
                                    LatcdRetirementResultKind kind, char *error, size_t error_size);
int latcd_retirement_page_budget_commit(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page, struct LatcdPageBudget *budget,
                                    char *error, size_t error_size);
/* Owner lease and controlled writers required. Preserve every result shard
 * and atomically advance to an empty page. This does not authorize object
 * deletion or guarantee fairness when the bounded shard store is full. On
 * failure reload and re-inventory before releasing an uncertain budget. */
int latcd_retirement_page_finish_preserving_results(const char *root, uint64_t now_us,
                                    struct LatcdPageBudget *budget, char *error, size_t error_size);
#if defined(LATCD_RETIREMENT_TESTING) && defined(LATCD_CAPACITY_TESTING)
extern void (*latcd_retirement_test_before_settlement)(void);
extern void (*latcd_retirement_test_before_page_finish)(struct LatcdPageBudget *budget);
/* Fixture-only bound result, including synthetic DONE without a receipt. */
int latcd_retirement_test_bound_budget_result(const char *root, uint64_t now_us,
                                    const uint8_t identity[32], struct LatcdPageBudget *budget,
                                    const LatcdRetirementPageDeadline *entry,
                                    LatcdRetirementResultKind kind, char *error, size_t error_size);
struct LatcdCacheCapacity;
struct LatcdPageBudget;
/* Test-only handoff; caller owns the lease and serializes budget lifetime. */
int latcd_retirement_test_page_reserve(const char *root, uint64_t now_us,
                                    struct LatcdCacheCapacity *capacity, uint64_t limit,
                                    struct LatcdPageBudget *budget, uint8_t identity[32],
                                    char *error, size_t error_size);
int latcd_retirement_test_page_budget_matches(const char *root, const uint8_t identity[32],
                                    char *error, size_t error_size);
int latcd_retirement_test_budget_result(const char *root, uint64_t now_us,
                                    const uint8_t identity[32], struct LatcdPageBudget *budget,
                                    const LatcdRetirementPageDeadline *entry,
                                    LatcdRetirementResultKind kind, char *error, size_t error_size);
int latcd_retirement_test_budget_commit(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page, struct LatcdPageBudget *budget,
                                    char *error, size_t error_size);
#endif
/* Experimental scheduling checkpoint only. Caller must hold an owner lease
 * and controlled access; never authorizes deletion or discovery completeness.
 * Reload after every error because rename may already have succeeded. */
int latcd_retirement_page_commit(const char *root, uint64_t now_us,
                                    const LatcdRetirementPageState *page,
                                    char *error, size_t error_size);
/* Read one hint after validating the entire bounded store. Returns 1 if
 * absent, 0 if found, -1 if unsafe. Output is cleared on failure/absence. */
int latcd_retirement_schedule_load(const char *root, const char *boot,
                                   uint64_t grace_us, uint64_t now_us,
                                   const char *name, uint64_t *sequence,
                                   LatcdRetirementPageDeadline *entry,
                                   char *error, size_t error_size);
/* Merge hints into an already discovered diagnostic page, atomically in
 * memory. Deadlines remain those from discovery; this never permits deletion. */
int latcd_retirement_schedule_merge_page(const char *root, const char *boot,
                                         uint64_t grace_us, uint64_t now_us,
                                         LatcdRetirementPageState *page,
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
/* After unmount verification, release under an internally acquired roots EX. */
int latcd_retirement_mount_release(const char *root, const char *id,
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

typedef struct LatcdRetirementPublication LatcdRetirementPublication;
/* Caller owns the cache management lease and holds source EX. The object
 * retains roots SH until close. Recovery does not authorize file removal. */
LatcdRetirementPublication *latcd_retirement_publication_open(
    const char *root, char *error, size_t error_size);
int latcd_retirement_publication_prepare(LatcdRetirementPublication *publication,
    const char *source, const char *next, size_t next_size, const char *objects,
    char *error, size_t error_size);
int latcd_retirement_publication_finish(LatcdRetirementPublication *publication,
    char *error, size_t error_size);
void latcd_retirement_publication_close(LatcdRetirementPublication *publication);
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
    bool complete, aggregating;
} LatcdRetirementQueueStats;

/* Single I/O worker owns this diagnostic queue under the management lease.
 * Bounded transaction discovery only, not liveness verification/admission.
 * Creates the private transaction store if absent before monitored discovery.
 * Retains original enqueue time across sweeps; fully object-bound UNLINKED /
 * MISSING receipts remove completed names only after absence is rechecked.
 * No deletion or timer handoff; missing alone never completes a candidate.
 * A yielded execution must be completed or cancelled before scanning. */
LatcdRetirementQueue *latcd_retirement_queue_new(const char *root, uint64_t grace_us);
/* Configure a diagnostic bounded-round discovery before scanning. The cutoff
 * must have been sampled under roots EX. This does not enable consumption or
 * persist progress; callers must rescan after any failure. */
int latcd_retirement_queue_diagnostic_round(LatcdRetirementQueue *queue,
    const char *boot, uint64_t cutoff, const char *after);
/* Restrict a diagnostic round to due shard hints. Full transaction scans
 * remain mandatory and the resulting page cannot authorize deletion. */
int latcd_retirement_queue_diagnostic_retry(LatcdRetirementQueue *queue,
    const char *boot, uint64_t cutoff, const LatcdRetirementPageDeadline *hints, unsigned count);
/* Select from an empty persisted round and remember its complete due snapshot.
 * Returns 1 when scanning is configured, 0 when no retry is due, or -1. */
int latcd_retirement_queue_retry_begin(LatcdRetirementQueue *queue,
    char *error, size_t error_size);
/* Preserve input retry order and report transaction rediscovery only. A false
 * match is not proof that a shard or its object can be removed. */
int latcd_retirement_queue_retry_matches(const LatcdRetirementQueue *queue,
    bool matches[128], unsigned *count);
/* Two-pass receipt observations for retry hints. Diagnostic only: the
 * retained witness still needs lock-bound revalidation, and does not authorize
 * deletion, DONE results, or schedule-shard consumption. */
int latcd_retirement_queue_retry_receipts(const LatcdRetirementQueue *queue,
    bool receipts[128], unsigned *count);
/* Consumes the witness after locked revalidation. Locks are released before
 * return; the output is diagnostic, not durable or removal authority. */
int latcd_retirement_queue_retry_receipts_revalidate(LatcdRetirementQueue *queue,
    bool receipts[128], unsigned *count, char *error, size_t error_size);
/* Complete monitored retry discovery in selection order, including unmatched
 * hints. The returned snapshot is diagnostic, not deletion authorization. */
int latcd_retirement_queue_retry_items(const LatcdRetirementQueue *queue,
    LatcdRetirementRetryItem items[128], unsigned *count);
/* Consume the retained scan witness after checking it under scheduler and
 * reference-roots locks. This does not authorize deletion or persist a page. */
int latcd_retirement_queue_retry_revalidate(LatcdRetirementQueue *queue,
    char *error, size_t error_size);
/* Return the validated input observed under both locks. Locks are released
 * before return, so the output is neither a durable checkpoint nor authority. */
int latcd_retirement_queue_retry_page_snapshot(LatcdRetirementQueue *queue,
    LatcdRetirementRetryPage *page, char *error, size_t error_size);
/* Atomically stage a witnessed retry input with a conservative peak budget.
 * An active retry checkpoint is not deletion authority. */
int latcd_retirement_queue_retry_page_stage(LatcdRetirementQueue *queue,
    struct LatcdCacheCapacity *capacity, uint64_t limit, struct LatcdPageBudget *budget,
    char *error, size_t error_size);
int latcd_retirement_retry_page_load(const char *root, LatcdRetirementRetryPage *page,
    char *error, size_t error_size);
/* Startup with capacity recovery gated; accepts an untouched page or an intent
 * with the original or replacement shard. Does not replay the intent. */
int latcd_retirement_retry_page_restore_budget(const char *root,
    struct LatcdCacheCapacity *capacity, uint64_t limit, uint64_t expected_grace_us,
    struct LatcdPageBudget *budget, LatcdRetirementRetryPage *page,
    char *error, size_t error_size);
int latcd_retirement_retry_page_begin_unmatched(const char *root,
    struct LatcdPageBudget *budget, char *error, size_t error_size);
/* Defer a matched member only while its aggregate deadline is still in the future. */
int latcd_retirement_retry_page_begin_not_due(const char *root,
    struct LatcdPageBudget *budget, char *error, size_t error_size);
/* Defer a due matched member without recording an execution or deletion. */
int latcd_retirement_retry_page_begin_unattempted(const char *root,
    struct LatcdPageBudget *budget, char *error, size_t error_size);
/* Defer the current member without attempting execution, regardless of its deadline. */
int latcd_retirement_retry_page_begin_deferred(const char *root,
    struct LatcdPageBudget *budget, char *error, size_t error_size);
/* Apply or idempotently recognize a deferral intent; no removal authority. */
int latcd_retirement_retry_page_apply_unmatched(const char *root,
    struct LatcdPageBudget *budget, char *error, size_t error_size);
/* Persist completion only after validating the replacement shard. */
int latcd_retirement_retry_page_finish_unmatched(const char *root,
    struct LatcdPageBudget *budget, char *error, size_t error_size);
/* Commit a fully completed retry page and release its bound budget. */
int latcd_retirement_retry_page_commit(const char *root,
    struct LatcdPageBudget *budget, char *error, size_t error_size);
/* Advance only past an entirely unmatched retry batch while preserving every
 * shard. Requires a snapshot-bound monitored scan; never authorizes removal. */
int latcd_retirement_queue_retry_advance_unmatched(LatcdRetirementQueue *queue,
    char *error, size_t error_size);
/* Resume diagnostic discovery after the committed cursor. Any in-flight page
 * is ignored and rediscovered; a v2 page never proves completion.
 * Owner lease required; missing or incompatible state is not a new round. */
int latcd_retirement_queue_diagnostic_resume(LatcdRetirementQueue *queue,
                                              char *error, size_t error_size);
/* Owner lease and controlled writers required. Consume an empty monitored
 * resumed scan to advance the persisted round; no deletion authorization. */
int latcd_retirement_queue_round_advance(LatcdRetirementQueue *queue,
                                         char *error, size_t error_size);
/* Diagnostic only: number of selected keys retained, at most 128.
 * Zero outside an active incomplete page scan. */
unsigned latcd_retirement_queue_discovered_keys(const LatcdRetirementQueue *queue);
/* Diagnostic conversion of the retained page into a plan. Other pages require
 * a fresh monitored scan with the corresponding diagnostic cursor. */
int latcd_retirement_queue_page_plan(const LatcdRetirementQueue *queue, const char *after,
                                     LatcdRetirementPageState *state);
/* Diagnostic snapshot of the last aggregation; never authorizes consumption. */
int latcd_retirement_queue_aggregated_page(const LatcdRetirementQueue *queue,
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
/* Owner lease and a complete bounded discovery are required. On write failure
 * the attempt remains active and the queue must be discarded and reloaded. */
int latcd_retirement_queue_defer_persist(LatcdRetirementQueue *queue,
    const LatcdRetirementAttempt *attempt, uint64_t now_us, bool busy,
    char *error, size_t error_size);

/* Internal single-candidate consumer; SAME external owner/domain/access/mount/
 * full-reference-graph guarantees as tombstone_delete_due_report are required.
 * Selection never authorizes deletion. Hash outside S, then recheck grace and
 * roots under S before intent; executor rechecks independently. Existing intent
 * is resumed, never overwritten. Returns 1 completed, 0 no ready candidate,
 * -1 deferred/error. Attempt is released on every selected path. Completion
 * remains queued until a later sweep verifies bound receipt plus absence.
 * Completion/deferral is checkpointed before releasing the attempt; on error
 * discard and reload the queue. No CLI/daemon caller enabled. */
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
/* Releases resumable state/pin and persistently busy-defers its attempt; no
 * unlink. On failure discard and reload the queue. Queue destruction also
 * releases pins. Persistent intent is never rolled back. */
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
