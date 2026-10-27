#ifndef GUEST_FD_TABLE_H
#define GUEST_FD_TABLE_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Guest descriptors are explicit capabilities. Host descriptors are usable by
 * guest code only after import() or adopt(). This API owns descriptor lifetime,
 * guest numbering, duplication/replacement and guest FD_CLOEXEC metadata.
 *
 * Syscall input/output conversion is not wired yet. Handles stabilize a backend
 * against close/replace, but do not implement POSIX record-lock ownership.
 */
typedef struct GuestFdTable GuestFdTable;
typedef struct GuestFdHandle GuestFdHandle;

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

/* Acquire under the table lock; use the borrowed host fd outside it, then
 * release. No dup or temporary close: handles share the backend reference.
 * Only imported/adopted guest numbers resolve, never arbitrary host numbers.
 * A handle survives table close/replacement/destruction and is single-owner.
 * The returned fd must not be closed or replaced by the caller. release(NULL)
 * is harmless and preserves errno, including when the last reference closes.
 * Each handle retains its table until release. fork_start rejects active
 * handles rather than waiting on potentially blocking I/O. Callers must still
 * quiesce all tables/handles before host fork/exec and adapt per-table
 * record locks; this API alone does not enable guest syscall virtualization. */
GuestFdHandle *guest_fd_table_acquire(GuestFdTable *table, int guest_fd);
int guest_fd_handle_host_fd(const GuestFdHandle *handle);
void guest_fd_handle_release(GuestFdHandle *handle);

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
 * Returns EBUSY without retaining the lock while this table has active handles;
 * callers must cancel/drain operations and retry, not busy-spin. Every table
 * whose backends can be inherited must be frozen; freezing one table does not
 * cover handles or mutations of independently copied tables sharing backends.
 * Every successful start must be paired with fork_end() in both parent and
 * child. The forking thread survives in the child, so the inherited mutex
 * remains owned by it. close() holds this leaf mutex through the host close;
 * callers must not enter it while holding another lock or guest-copy context.
 */
int guest_fd_table_fork_start(GuestFdTable *table);
void guest_fd_table_fork_end(GuestFdTable *table);

/* Process-wide alternative: freeze every registered live table plus creation,
 * completed-copy publication and destruction. Nonblocking acquisition returns
 * EBUSY and releases all locks if any table/registry is busy or has handles.
 * Retry only after caller quiesces operations; never combine with per-table
 * fork_start, and never create/unref/use tables inside a successful bracket.
 * Pair success with fork_end in parent and child (or on failed host fork).
 * Copies under construction are unpublished and excluded; their source stays
 * locked until registration or rollback completes, so fork cannot inherit
 * unregistered backend references. Handle release is covered through unref.
 * This does not itself wire guest clone/unshare/exec or record-lock ownership. */
int guest_fd_tables_fork_start(void);
void guest_fd_tables_fork_end(void);

#endif
