#ifndef LATCD_CACHE_CAPACITY_H
#define LATCD_CACHE_CAPACITY_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

typedef struct LatcdCacheCapacity {
    pthread_mutex_t lock;
    uint64_t committed;
    uint64_t reserved;
    uint64_t transient_reserved;
    uint64_t recovered_reserved;
    uint64_t journal_reserved;
    uint64_t metadata_committed;
    uint64_t metadata_reserved;
    uint64_t state_committed;
    uint64_t state_reserved;
    void *recovered_tasks;
    void *unknown_tasks;
    bool ready;
    bool recovery_gate;
    void *restored_page_budget;
    bool inventory_active;
    bool metadata_present;
    int watch_fd;
    int root_fd;
    int root_watch;
    void *expected_names;
    const char *removing_generation;
    void *file_watches;
    void *state_directories;
    void *state_files;
    void *state_expected;
    void *state_ignored;
    void *inventory_directories;
} LatcdCacheCapacity;

#define LATCD_CACHE_CAPACITY_INIT { .lock = PTHREAD_MUTEX_INITIALIZER, \
    .watch_fd = -1, .root_fd = -1 }

/* Startup only, under the owner lease, before publishers start. Counts immutable
 * generation/legacy superseded objects plus .gc regular-file metadata separately;
 * and current/.tbsets/.identities state separately. Not all cache state.
 * Unsafe/aliased metadata or state closes admission. Existing .gc file inodes
 * and records installed through metadata_begin/finish are watched for writes
 * and replacement. Inventoried .gc directories remain watched for self changes;
 * newly created directories and directory blocks are not fully accounted. */
int latcd_cache_capacity_scan(LatcdCacheCapacity *capacity, const char *root,
                              char *error, size_t error_size);
/* Startup, before service threads: block ordinary reservations until all
 * persistent budgets have been restored. Finish checks the inventory and
 * opens admission under the same lock. Failure leaves the gate closed. */
int latcd_cache_capacity_recovery_begin(LatcdCacheCapacity *capacity);
int latcd_cache_capacity_recovery_finish(LatcdCacheCapacity *capacity);
/* Abort startup recovery without opening admission. The owner must discard
 * outstanding budgets and re-inventory/recover before accepting work. */
int latcd_cache_capacity_recovery_abort(LatcdCacheCapacity *capacity);
/* A failed recovery under the gate requires abort and a fresh inventory. */
void latcd_cache_capacity_recovery_fail(LatcdCacheCapacity *capacity);
/* Return a readable directory fd for the inventoried root only when the configured path and
 * caller's directory fd still identify it. Caller owns the returned fd.
 * Startup/shutdown and rescans must not race this operation. */
int latcd_cache_capacity_open_matching_root(LatcdCacheCapacity *capacity,
                                            const char *root, int caller_fd);
/* Caller holds the owner and object/reference locks and supplies the verified
 * snapshot. This accounts namespace removal, not physical block release. */
int latcd_cache_capacity_remove_generation(LatcdCacheCapacity *capacity, int directory,
                                           const char *name, const struct stat *expected);
int latcd_cache_capacity_reserve(LatcdCacheCapacity *capacity, uint64_t bytes,
                                 uint64_t limit, char *error, size_t error_size);
/* Release only after cleanup proved removal. Otherwise commit conservatively. */
void latcd_cache_capacity_finish(LatcdCacheCapacity *capacity, uint64_t bytes,
                                 bool retained);
/* Publisher owns the peak reservation through all retries and cleanup. */
int latcd_cache_capacity_reserve_transient(LatcdCacheCapacity *capacity, uint64_t bytes,
                                           uint64_t limit, char *error, size_t error_size);
void latcd_cache_capacity_finish_transient(LatcdCacheCapacity *capacity, uint64_t bytes,
                                           bool retained);
/* Restore persistent task reservations before serving; release by exact task id. */
int latcd_cache_capacity_restore_task(LatcdCacheCapacity *capacity, const char *id, uint64_t bytes);
bool latcd_cache_capacity_task_restored(LatcdCacheCapacity *capacity, const char *id);
void latcd_cache_capacity_unknown_task(LatcdCacheCapacity *capacity, const char *id);
void latcd_cache_capacity_release_task(LatcdCacheCapacity *capacity, const char *id);
/* Serialized journal owner reconciles full durable quota while releasing only
 * its own in-flight reservation. Failed inventory keeps reservation, closes admission. */
int latcd_cache_capacity_journal(LatcdCacheCapacity *capacity, uint64_t total,
                                uint64_t reservation, bool valid);
/* Bind after startup inventory, before service threads. Unbound writers are
 * bootstrap/offline operations and get inventoried at the next startup.
 * Covers lifecycle .gc and persistent state regular-file writers, not directory
 * blocks or external writer charges. close() unbinds after service threads stop. */
void latcd_cache_capacity_metadata_bind(LatcdCacheCapacity *capacity, uint64_t limit);
/* Open or create a private metadata directory with monitored creation. */
int latcd_cache_capacity_open_metadata_directory(int parent, const char *name);
typedef struct LatcdPageBudget {
    LatcdCacheCapacity *capacity;
    uint64_t remaining;
    unsigned inflight;
    bool invalid;
    bool page_identity_bound;
    uint8_t page_identity[32];
} LatcdPageBudget;
/* Invalidate an owned page after an uncertain persistent transition. */
void latcd_cache_capacity_page_uncertain(LatcdCacheCapacity *capacity, LatcdPageBudget *budget);
/* Startup only, with ordinary admission gated and the page and its installed
 * fragments verified under the scheduler lock. The caller owns budget storage
 * for the entire reservation lifetime; this does not validate persisted data. */
int latcd_cache_capacity_restore_page(LatcdCacheCapacity *capacity, uint64_t bytes,
                                      uint64_t limit, const uint8_t identity[32],
                                      LatcdPageBudget *budget);
/* Under scheduler lock, before publishing a page checkpoint. Cancellation is
 * only valid when the caller has proved that checkpoint was not installed. */
int latcd_cache_capacity_reserve_page(LatcdCacheCapacity *capacity, uint64_t bytes,
                                      uint64_t limit, const uint8_t identity[32],
                                      LatcdPageBudget *budget);
int latcd_cache_capacity_cancel_page(LatcdCacheCapacity *capacity, LatcdPageBudget *budget);
/* Once an empty checkpoint is durable, failure to release requires a rescan. */
int latcd_cache_capacity_finish_page(LatcdCacheCapacity *capacity, LatcdPageBudget *budget);
/* After admission has failed, discard only the registered, idle budget.
 * This does not reopen admission or resolve a persisted checkpoint; the owner
 * must re-inventory and recover it. The recovery gate must already be closed. */
int latcd_cache_capacity_abandon_page(LatcdCacheCapacity *capacity, LatcdPageBudget *budget);
/* Compute a conservative serial-write peak after existing files have been
 * inventoried. missing is the number of new result files, not page size;
 * every other result must already occupy at least result_bytes. The caller
 * must validate this and all slot identities under the scheduling lock.
 * Includes full checkpoint growth plus a serial replacement retry peak.
 * This neither reserves capacity nor validates the persisted page or slots. */
int latcd_cache_capacity_page_peak(uint64_t missing, uint64_t free_slots,
                                   uint64_t result_bytes, uint64_t checkpoint_bytes,
                                   uint64_t *bytes);
typedef struct LatcdMetadataReservation {
    LatcdCacheCapacity *capacity;
    uint64_t bytes, previous;
    bool state;
    bool previous_present;
    struct stat previous_snapshot;
    bool installed_snapshot_present;
    struct stat installed_snapshot;
    int directory;
    char *name;
    char *staging;
    LatcdPageBudget *page_budget;
} LatcdMetadataReservation;
/* Caller holds the scheduler lock and retains the bound budget through finish. */
int latcd_cache_capacity_page_begin(int directory, const char *name, uint64_t bytes,
                                    LatcdPageBudget *budget, LatcdMetadataReservation *reservation);
#ifdef LATCD_CAPACITY_TESTING
extern void (*latcd_capacity_test_before_lock_create)(void);
extern void (*latcd_capacity_test_before_lock_finish)(void);
/* Callers serialize use across distinct capacity instances and keep storage
 * alive through release and all in-flight reservations. */
int latcd_cache_capacity_test_page_reserve(LatcdCacheCapacity *capacity, uint64_t bytes,
                                            uint64_t limit, LatcdPageBudget *budget);
int latcd_cache_capacity_test_page_begin(int directory, const char *name, uint64_t bytes,
                                         LatcdPageBudget *budget, LatcdMetadataReservation *reservation);
int latcd_cache_capacity_test_page_release(LatcdCacheCapacity *capacity, LatcdPageBudget *budget);
int latcd_cache_capacity_test_page_abandon(LatcdCacheCapacity *capacity, LatcdPageBudget *budget);
#endif
int latcd_cache_capacity_metadata_begin(int directory, const char *name, uint64_t bytes,
    LatcdMetadataReservation *reservation);
/* Create or open a zero-length metadata lock. A concurrent creator or an
 * uncertain installation closes capacity admission; external writers are not
 * authorized by this process-local protocol. */
int latcd_cache_capacity_open_metadata_lock(int directory, const char *name);
/* Only for completion of a previously persisted recovery record. */
int latcd_cache_capacity_metadata_recovery_begin(int directory, const char *name, uint64_t bytes,
    LatcdMetadataReservation *reservation);
/* Scheduling hints are not committed transaction recovery: never allow their
 * replacement to bypass a closed index or the metadata limit. */
int latcd_cache_capacity_metadata_schedule_begin(int directory, const char *name, uint64_t bytes,
    LatcdMetadataReservation *reservation);
/* Register a private metadata staging name before creation; cancel on collision. */
int latcd_cache_capacity_metadata_stage(LatcdMetadataReservation *reservation, const char *name);
void latcd_cache_capacity_metadata_unstage(LatcdMetadataReservation *reservation);
/* replaced: rename/link installed the new record. leftover: temporary removal
 * or anonymous-file close could not be proved; charge its full reservation.
 * Caller serializes replacement of the same record. Installed metadata gets a
 * fresh inode watch; unexpected events close ordinary admission. When closed,
 * only existing nonempty metadata can reserve for recovery completion. No scan here. */
void latcd_cache_capacity_metadata_finish(LatcdMetadataReservation *reservation,
    bool replaced, bool leftover);
/* Revalidate the target before replacement; this is not an atomic CAS. */
int latcd_cache_capacity_metadata_revalidate(LatcdMetadataReservation *reservation);
/* Remove an inventoried .gc regular file bound to expected device/inode.
 * Same-name writers are serialized. Failed unlink/fsync retains the charge
 * and closes admission; owner lease and controlled namespace are required. */
int latcd_cache_capacity_metadata_remove(int directory, const char *name,
                                         uint64_t device, uint64_t inode);
/* Also bind removal to the snapshot observed while validating record contents. */
/* Failure can follow unlink; re-inventory and reload before retrying. */
int latcd_cache_capacity_metadata_remove_checked(int directory, const char *name,
                                                 const struct stat *expected);
/* Confirm an inventoried absence and make a prior unlink durable. */
int latcd_cache_capacity_page_remove_checked(int directory, const char *name,
                                             const struct stat *expected, LatcdPageBudget *budget);
int latcd_cache_capacity_page_sync_absent(int directory, const char *name, LatcdPageBudget *budget);
/* Ordinary persistent state has no committed-transaction over-limit exception.
 * Allowed directories: root (only SHA.current), .tbsets, .identities.
 * Caller serializes same-record replacement through finish. Uses metadata bind. */
int latcd_cache_capacity_state_begin(int directory, const char *name, uint64_t bytes,
    LatcdMetadataReservation *reservation);
/* Register a direct-child staging name before its creation. No-op unbound.
 * The final target and staging name stay expected until finish drains events. */
int latcd_cache_capacity_state_stage(LatcdMetadataReservation *reservation,
                                    const char *name);
/* Bracket owned root namespace writes; unexpected changes invalidate admission.
 * Names stay registered through cleanup, including while cache_lock is dropped. */
int latcd_cache_capacity_expect(LatcdCacheCapacity *capacity, const char *const *names,
                                size_t count, char *error, size_t error_size);
void latcd_cache_capacity_complete(LatcdCacheCapacity *capacity, const char *const *names,
                                   size_t count);
/* Drain pending namespace/attribute events and report current admission state. */
int latcd_cache_capacity_poll(LatcdCacheCapacity *capacity);
void latcd_cache_capacity_close(LatcdCacheCapacity *capacity);

#endif
