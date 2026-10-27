#ifndef LAT_AOT_V2_INTERNAL_FD_REGISTRY_H
#define LAT_AOT_V2_INTERNAL_FD_REGISTRY_H

#include <stdbool.h>

typedef bool (*LatAotV2InternalFdRangeProtected)(int fd, void *opaque);
typedef int (*LatAotV2InternalFdRangePrepare)(int fd, void *opaque);

/* Protect runtime-owned fds from direct guest close/dup/fcntl operations. */
void lat_aot_v2_internal_fd_lock(void);
/* Wait for admitted guest closes before allocating any internal descriptor. */
void lat_aot_v2_internal_fd_allocation_lock(void);
void lat_aot_v2_internal_fd_unlock(void);

/*
 * Caller holds the allocation lock from before opening/duplicating the fd.
 * Registration fails rather than running an AOT object without protection.
 */
int lat_aot_v2_internal_fd_register_locked(int fd);

/* The caller must already hold the registry lock. */
int lat_aot_v2_internal_fd_unregister_close_locked(int fd);

bool lat_aot_v2_internal_fd_is_protected(int fd);

/* Serialize guest replacement with internal fd allocation/registration. Caller
 * relocates source identity references first; no callback runs under this lock. */
int lat_aot_v2_internal_fd_dup_replace(int oldfd, int newfd, int flags, bool use_dup3);

/* Pin an admitted guest open description under the allocation/registration lock.
 * Returned CLOEXEC fd is internal; release with cache_close_fd(..., true, ...).
 * Blocking guest operations run on this copy outside the registry lock. */
int lat_aot_v2_internal_fd_snapshot_guest(int fd);

/* Never blocks under the registry lock; caller handles EWOULDBLOCK separately. */
int lat_aot_v2_internal_fd_try_flock(int fd, int operation);

/* Only nonblocking descriptor flags/dup commands; record locks are excluded. */
int lat_aot_v2_internal_fd_fcntl(int fd, int command, int argument);
int lat_aot_v2_internal_fd_close_guest(int fd);

/* Borrow a raw guest number without dup/close. Admission and internal-number
 * registration are serialized; internal allocation waits until every borrow
 * ends. Guest close/replace may still race as with a kernel syscall, but cannot
 * install an internal object in that number. No registry lock survives begin.
 * Pair every successful begin with end, including failed host calls. Not for
 * operations which need internal allocation before they can complete. */
int lat_aot_v2_internal_fd_guest_begin(int fd);
void lat_aot_v2_internal_fd_guest_end(void);

/* Apply close_range close/CLOEXEC semantics to currently open guest descriptors.
 * Registry-protected descriptors and extra_protected() descriptors are skipped.
 * Callers reject unsupported close-on-exec sharing semantics before entry. */
int lat_aot_v2_internal_fd_close_range(unsigned first, unsigned last,
                                        bool cloexec,
                                        LatAotV2InternalFdRangeProtected extra_protected,
                                        LatAotV2InternalFdRangePrepare prepare,
                                        void *opaque);

#endif
