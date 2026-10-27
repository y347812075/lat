#ifndef GUEST_FD_TABLE_H
#define GUEST_FD_TABLE_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Guest descriptors are explicit capabilities. Host descriptors are usable by
 * guest code only after import() or adopt(). This API owns descriptor lifetime,
 * guest numbering, duplication/replacement and guest FD_CLOEXEC metadata.
 *
 * Syscall input/output conversion is not wired yet. In particular there is no
 * syscall-pin API in this batch, so callers must not treat an unlocked table
 * lookup as protection against concurrent close/replace or POSIX record-lock
 * side effects. Those semantics belong to the syscall-integration batches.
 */
typedef struct GuestFdTable GuestFdTable;

GuestFdTable *guest_fd_table_new(void);
GuestFdTable *guest_fd_table_ref(GuestFdTable *table);
void guest_fd_table_unref(GuestFdTable *table);

/*
 * Snapshot guest numbering and logical CLOEXEC under the source-table lock.
 * Backends are refcounted, not duplicated: copies share the same host fd/OFD,
 * but descriptor numbering and logical flags are independent. Backend close
 * occurs only on its last reference. Copy/destruction/rollback do not introduce
 * temporary fd closes that could release the source's POSIX record locks.
 * This does not unshare the host fd table or integrate guest syscall handling.
 * Guest close/dup replacement still needs per-table record-lock ownership in
 * the syscall adapter before this can implement guest unshare/clone semantics.
 */
GuestFdTable *guest_fd_table_copy(GuestFdTable *table);

/*
 * Import or adopt a host descriptor. Both consume host_fd on success and leave
 * ownership with the caller on failure. The backend is marked FD_CLOEXEC;
 * cloexec is the guest-visible state. adopt() returns the lowest unused guest
 * descriptor, while dup_min() implements F_DUPFD numbering.
 */
int guest_fd_table_import(GuestFdTable *table, int guest_fd, int host_fd,
                          bool cloexec);
int guest_fd_table_adopt(GuestFdTable *table, int host_fd, bool cloexec,
                         int *guest_fd);
int guest_fd_table_dup_min(GuestFdTable *table, int guest_fd, int minimum,
                           bool cloexec, int *new_guest_fd);

/* dup_to() implements dup2/dup3 replacement; dup3(old == new) is validated by
 * its syscall adapter, not by this lower-level operation. */
int guest_fd_table_dup_to(GuestFdTable *table, int guest_fd,
                          int new_guest_fd, bool cloexec);
int guest_fd_table_close(GuestFdTable *table, int guest_fd);

int guest_fd_table_set_cloexec(GuestFdTable *table, int guest_fd,
                               bool cloexec);
int guest_fd_table_get_cloexec(GuestFdTable *table, int guest_fd,
                               bool *cloexec);

/*
 * fork_start() quiesces table mutations and backend closes before host fork.
 * Every successful start must be paired with fork_end() in both parent and
 * child. The forking thread survives in the child, so the inherited mutex
 * remains owned by it. close() holds this leaf mutex through the host close;
 * callers must not enter it while holding another lock or guest-copy context.
 */
int guest_fd_table_fork_start(GuestFdTable *table);
void guest_fd_table_fork_end(GuestFdTable *table);

#endif
