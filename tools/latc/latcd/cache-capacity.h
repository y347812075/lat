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
    void *recovered_tasks;
    bool ready;
    int watch_fd;
    int root_watch;
    void *expected_names;
} LatcdCacheCapacity;

#define LATCD_CACHE_CAPACITY_INIT { .lock = PTHREAD_MUTEX_INITIALIZER, .watch_fd = -1 }

/* Startup only, under the owner lease, before publishers start. Counts immutable
 * generation objects and legacy superseded objects; not all cache state. */
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
void latcd_cache_capacity_release_task(LatcdCacheCapacity *capacity, const char *id);
/* Bracket owned root namespace writes; unexpected changes invalidate admission.
 * Names stay registered through cleanup, including while cache_lock is dropped. */
int latcd_cache_capacity_expect(LatcdCacheCapacity *capacity, const char *const *names,
                                size_t count, char *error, size_t error_size);
void latcd_cache_capacity_complete(LatcdCacheCapacity *capacity, const char *const *names,
                                   size_t count);
void latcd_cache_capacity_close(LatcdCacheCapacity *capacity);

#endif
