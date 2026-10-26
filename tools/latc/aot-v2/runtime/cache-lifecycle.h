#ifndef LAT_AOT_V2_CACHE_LIFECYCLE_H
#define LAT_AOT_V2_CACHE_LIFECYCLE_H

#include <stdbool.h>
#include <stddef.h>

/*
 * Operations are flock(2) modes: exactly one of LOCK_SH or LOCK_EX, with
 * optional LOCK_NB. A successful file lock remains owned by the open file
 * description and therefore survives fork but closes on exec for CLOEXEC fds.
 */
int lat_aot_v2_cache_lock_fd(int fd, int operation,
                             char *error, size_t error_size);

/* Check after taking the object lease. Any tombstone entry (even malformed)
 * blocks a new reader. This is not a domain admission or deletion permit. */
int lat_aot_v2_cache_object_available(const char *path,
                                      char *error, size_t error_size);

/* Use a stable per-source latch around manifest read and artifact-fd capture. */
int lat_aot_v2_cache_source_lock(const char *cache_dir,
                                 const char *source_hex, int operation,
                                 bool protect_from_guest,
                                 char *error, size_t error_size);

int lat_aot_v2_cache_close_fd(int fd, bool protected_from_guest,
                              char *error, size_t error_size);

#endif
