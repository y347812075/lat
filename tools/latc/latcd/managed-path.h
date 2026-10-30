#ifndef LATCD_MANAGED_PATH_H
#define LATCD_MANAGED_PATH_H
#include <sys/types.h>
#include <stddef.h>

/* Returns a held directory fd after checking every path component. */
int latcd_managed_directory(const char *path, uid_t leaf_uid, mode_t leaf_mode);
/* Rechecks the path and compares it to the held directory; not a path lock. */
int latcd_managed_directory_matches(int held, const char *path,
                                    uid_t leaf_uid, mode_t leaf_mode);
/* Opens a root-owned, non-writable regular file under trusted ancestors. */
int latcd_managed_file(const char *path, int executable);
/* Reads one bounded, root-owned configuration file from a trusted directory. */
int latcd_managed_config_read(const char *path, char *buffer, size_t capacity,
                              size_t *length);
#endif
