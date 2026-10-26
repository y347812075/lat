#ifndef LATCD_CACHE_RETIREMENT_H
#define LATCD_CACHE_RETIREMENT_H

#include <stddef.h>

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

/* The caller owns the cache management lease and the source commit latch.
 * Neither transaction completion nor recovery authorizes file removal. */
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

#endif
