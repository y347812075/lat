#ifndef LATCD_CACHE_CAPACITY_H
#define LATCD_CACHE_CAPACITY_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
    bool inventory_active;
    bool metadata_present;
    int watch_fd;
    int root_fd;
    int root_watch;
    void *expected_names;
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
typedef struct LatcdMetadataReservation {
    LatcdCacheCapacity *capacity;
    uint64_t bytes, previous;
    bool state;
    int directory;
    char *name;
    char *staging;
} LatcdMetadataReservation;
int latcd_cache_capacity_metadata_begin(int directory, const char *name, uint64_t bytes,
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
/* Remove an inventoried .gc regular file bound to expected device/inode.
 * Same-name writers are serialized. Failed unlink/fsync retains the charge
 * and closes admission; owner lease and controlled namespace are required. */
int latcd_cache_capacity_metadata_remove(int directory, const char *name,
                                         uint64_t device, uint64_t inode);
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
