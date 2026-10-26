#ifndef LAT_AOT_V2_INTERNAL_FD_REGISTRY_H
#define LAT_AOT_V2_INTERNAL_FD_REGISTRY_H

#include <stdbool.h>

/* Protect runtime-owned fds from direct guest close/dup/fcntl operations. */
void lat_aot_v2_internal_fd_lock(void);
void lat_aot_v2_internal_fd_unlock(void);

/*
 * Caller holds the registry lock. Registration fails rather than allowing an
 * AOT object to run without lifetime protection.
 */
int lat_aot_v2_internal_fd_register_locked(int fd);

/* The caller must already hold the registry lock. */
int lat_aot_v2_internal_fd_unregister_close_locked(int fd);

bool lat_aot_v2_internal_fd_is_protected(int fd);

/* Serialize guest replacement with internal fd allocation/registration. Caller
 * relocates source identity references first; no callback runs under this lock. */
int lat_aot_v2_internal_fd_dup_replace(int oldfd, int newfd, int flags, bool use_dup3);

#endif
