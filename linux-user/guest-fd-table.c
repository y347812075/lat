#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "guest-fd-table.h"

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

typedef struct GuestFdEntry {
    int host_fd;
    uint64_t generation;
    bool cloexec;
} GuestFdEntry;

struct GuestFdTable {
    atomic_uint refs;
    pthread_mutex_t mutex;
    GHashTable *entries;
    uint64_t next_generation;
    int max_guest_fd;
};

static gpointer guest_fd_key(int guest_fd)
{
    return GINT_TO_POINTER(guest_fd + 1);
}

static bool valid_guest_fd(int guest_fd)
{
    return guest_fd >= 0 && guest_fd < INT_MAX;
}

static int backend_close_on_exec(int host_fd)
{
    int flags = fcntl(host_fd, F_GETFD);

    if (flags < 0) {
        return -1;
    }
    if (!(flags & FD_CLOEXEC) && fcntl(host_fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        return -1;
    }
    return 0;
}

static GuestFdEntry *lookup_locked(GuestFdTable *table, int guest_fd)
{
    if (!valid_guest_fd(guest_fd)) {
        return NULL;
    }
    return g_hash_table_lookup(table->entries, guest_fd_key(guest_fd));
}

static int lowest_free_locked(const GuestFdTable *table, int minimum)
{
    if (minimum < 0) {
        minimum = 0;
    }
    for (int guest_fd = minimum; guest_fd <= table->max_guest_fd; guest_fd++) {
        if (!g_hash_table_contains(table->entries, guest_fd_key(guest_fd))) {
            return guest_fd;
        }
    }
    if (table->max_guest_fd < minimum - 1) {
        return minimum;
    }
    return table->max_guest_fd == INT_MAX - 1 ? -1 : table->max_guest_fd + 1;
}

static GuestFdEntry *alloc_entry(int host_fd, bool cloexec)
{
    GuestFdEntry *entry = g_try_new(GuestFdEntry, 1);

    if (!entry) {
        errno = ENOMEM;
        return NULL;
    }
    *entry = (GuestFdEntry) {
        .host_fd = host_fd,
        .cloexec = cloexec,
    };
    return entry;
}

static void insert_locked(GuestFdTable *table, int guest_fd,
                          GuestFdEntry *entry)
{
    g_assert(valid_guest_fd(guest_fd));
    g_assert(!lookup_locked(table, guest_fd));
    entry->generation = table->next_generation++;
    if (!entry->generation) {
        entry->generation = table->next_generation++;
    }
    g_hash_table_insert(table->entries, guest_fd_key(guest_fd), entry);
    if (guest_fd > table->max_guest_fd) {
        table->max_guest_fd = guest_fd;
    }
}

GuestFdTable *guest_fd_table_new(void)
{
    GuestFdTable *table = g_try_new0(GuestFdTable, 1);

    if (!table) {
        errno = ENOMEM;
        return NULL;
    }
    atomic_init(&table->refs, 1);
    if (pthread_mutex_init(&table->mutex, NULL)) {
        g_free(table);
        errno = ENOMEM;
        return NULL;
    }
    table->entries = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                           g_free);
    table->next_generation = 1;
    table->max_guest_fd = -1;
    return table;
}

GuestFdTable *guest_fd_table_ref(GuestFdTable *table)
{
    if (!table) {
        return NULL;
    }
    atomic_fetch_add_explicit(&table->refs, 1, memory_order_relaxed);
    return table;
}

void guest_fd_table_unref(GuestFdTable *table)
{
    GHashTableIter iter;
    gpointer value;

    if (!table || atomic_fetch_sub_explicit(&table->refs, 1,
                                             memory_order_acq_rel) != 1) {
        return;
    }

    g_hash_table_iter_init(&iter, table->entries);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        GuestFdEntry *entry = value;

        close(entry->host_fd);
    }
    g_hash_table_destroy(table->entries);
    pthread_mutex_destroy(&table->mutex);
    g_free(table);
}

GuestFdTable *guest_fd_table_copy(GuestFdTable *table)
{
    GuestFdTable *copy;
    GHashTableIter iter;
    gpointer key, value;

    if (!table) {
        errno = EINVAL;
        return NULL;
    }
    copy = guest_fd_table_new();
    if (!copy) {
        return NULL;
    }
    pthread_mutex_lock(&table->mutex);
    g_hash_table_iter_init(&iter, table->entries);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        const GuestFdEntry *source = value;
        GuestFdEntry *entry = alloc_entry(-1, source->cloexec);

        if (!entry) {
            goto failed;
        }
        entry->host_fd = fcntl(source->host_fd, F_DUPFD_CLOEXEC, 0);
        if (entry->host_fd < 0) {
            g_free(entry);
            goto failed;
        }
        insert_locked(copy, GPOINTER_TO_INT(key) - 1, entry);
    }
    pthread_mutex_unlock(&table->mutex);
    return copy;

failed:
    {
        int saved = errno;

        pthread_mutex_unlock(&table->mutex);
        guest_fd_table_unref(copy);
        errno = saved;
        return NULL;
    }
}

int guest_fd_table_import(GuestFdTable *table, int guest_fd, int host_fd,
                          bool cloexec)
{
    GuestFdEntry *entry;

    if (!table || !valid_guest_fd(guest_fd)) {
        errno = EINVAL;
        return -1;
    }
    if (host_fd < 0) {
        errno = EBADF;
        return -1;
    }
    entry = alloc_entry(host_fd, cloexec);
    if (!entry) {
        return -1;
    }

    pthread_mutex_lock(&table->mutex);
    if (lookup_locked(table, guest_fd)) {
        pthread_mutex_unlock(&table->mutex);
        g_free(entry);
        errno = EEXIST;
        return -1;
    }
    if (backend_close_on_exec(host_fd)) {
        int saved = errno;

        pthread_mutex_unlock(&table->mutex);
        g_free(entry);
        errno = saved;
        return -1;
    }
    insert_locked(table, guest_fd, entry);
    pthread_mutex_unlock(&table->mutex);
    return 0;
}

int guest_fd_table_adopt(GuestFdTable *table, int host_fd, bool cloexec,
                         int *guest_fd)
{
    GuestFdEntry *entry;
    int allocated;

    if (!table || !guest_fd) {
        errno = EINVAL;
        return -1;
    }
    if (host_fd < 0) {
        errno = EBADF;
        return -1;
    }
    entry = alloc_entry(host_fd, cloexec);
    if (!entry) {
        return -1;
    }

    pthread_mutex_lock(&table->mutex);
    allocated = lowest_free_locked(table, 0);
    if (allocated < 0) {
        pthread_mutex_unlock(&table->mutex);
        g_free(entry);
        errno = EMFILE;
        return -1;
    }
    if (backend_close_on_exec(host_fd)) {
        int saved = errno;

        pthread_mutex_unlock(&table->mutex);
        g_free(entry);
        errno = saved;
        return -1;
    }
    insert_locked(table, allocated, entry);
    pthread_mutex_unlock(&table->mutex);
    *guest_fd = allocated;
    return 0;
}

int guest_fd_table_dup_min(GuestFdTable *table, int guest_fd, int minimum,
                           bool cloexec, int *new_guest_fd)
{
    GuestFdEntry *source;
    GuestFdEntry *entry;
    int allocated;

    if (!table || !new_guest_fd || minimum < 0 || minimum >= INT_MAX) {
        errno = EINVAL;
        return -1;
    }
    entry = alloc_entry(-1, cloexec);
    if (!entry) {
        return -1;
    }

    pthread_mutex_lock(&table->mutex);
    source = lookup_locked(table, guest_fd);
    if (!source) {
        pthread_mutex_unlock(&table->mutex);
        g_free(entry);
        errno = EBADF;
        return -1;
    }
    allocated = lowest_free_locked(table, minimum);
    if (allocated < 0) {
        pthread_mutex_unlock(&table->mutex);
        g_free(entry);
        errno = EMFILE;
        return -1;
    }
    entry->host_fd = fcntl(source->host_fd, F_DUPFD_CLOEXEC, 0);
    if (entry->host_fd < 0) {
        int saved = errno;

        pthread_mutex_unlock(&table->mutex);
        g_free(entry);
        errno = saved;
        return -1;
    }
    insert_locked(table, allocated, entry);
    pthread_mutex_unlock(&table->mutex);
    *new_guest_fd = allocated;
    return 0;
}

int guest_fd_table_dup_to(GuestFdTable *table, int guest_fd,
                          int new_guest_fd, bool cloexec)
{
    GuestFdEntry *source;
    GuestFdEntry *old;
    GuestFdEntry *entry;
    int old_host_fd = -1;

    if (!table || !valid_guest_fd(new_guest_fd)) {
        errno = EBADF;
        return -1;
    }
    entry = alloc_entry(-1, cloexec);
    if (!entry) {
        return -1;
    }

    pthread_mutex_lock(&table->mutex);
    source = lookup_locked(table, guest_fd);
    if (!source) {
        pthread_mutex_unlock(&table->mutex);
        g_free(entry);
        errno = EBADF;
        return -1;
    }
    if (guest_fd == new_guest_fd) {
        pthread_mutex_unlock(&table->mutex);
        g_free(entry);
        return new_guest_fd;
    }
    entry->host_fd = fcntl(source->host_fd, F_DUPFD_CLOEXEC, 0);
    if (entry->host_fd < 0) {
        int saved = errno;

        pthread_mutex_unlock(&table->mutex);
        g_free(entry);
        errno = saved;
        return -1;
    }
    old = g_hash_table_lookup(table->entries, guest_fd_key(new_guest_fd));
    if (old) {
        g_hash_table_steal(table->entries, guest_fd_key(new_guest_fd));
        old_host_fd = old->host_fd;
        close(old_host_fd);
    }
    insert_locked(table, new_guest_fd, entry);
    pthread_mutex_unlock(&table->mutex);

    if (old) {
        g_free(old);
    }
    return new_guest_fd;
}

int guest_fd_table_close(GuestFdTable *table, int guest_fd)
{
    GuestFdEntry *entry;
    int host_fd;

    if (!table || !valid_guest_fd(guest_fd)) {
        errno = EBADF;
        return -1;
    }
    pthread_mutex_lock(&table->mutex);
    entry = lookup_locked(table, guest_fd);
    if (!entry) {
        pthread_mutex_unlock(&table->mutex);
        errno = EBADF;
        return -1;
    }
    host_fd = entry->host_fd;
    g_hash_table_steal(table->entries, guest_fd_key(guest_fd));
    int result = close(host_fd);
    pthread_mutex_unlock(&table->mutex);
    g_free(entry);
    return result;
}

int guest_fd_table_set_cloexec(GuestFdTable *table, int guest_fd,
                               bool cloexec)
{
    GuestFdEntry *entry;

    pthread_mutex_lock(&table->mutex);
    entry = lookup_locked(table, guest_fd);
    if (entry) {
        entry->cloexec = cloexec;
    }
    pthread_mutex_unlock(&table->mutex);
    if (!entry) {
        errno = EBADF;
        return -1;
    }
    return 0;
}

int guest_fd_table_get_cloexec(GuestFdTable *table, int guest_fd,
                               bool *cloexec)
{
    GuestFdEntry *entry;

    if (!cloexec) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&table->mutex);
    entry = lookup_locked(table, guest_fd);
    if (entry) {
        *cloexec = entry->cloexec;
    }
    pthread_mutex_unlock(&table->mutex);
    if (!entry) {
        errno = EBADF;
        return -1;
    }
    return 0;
}

int guest_fd_table_fork_start(GuestFdTable *table)
{
    if (!table) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&table->mutex);
    return 0;
}

void guest_fd_table_fork_end(GuestFdTable *table)
{
    if (table) {
        pthread_mutex_unlock(&table->mutex);
    }
}
