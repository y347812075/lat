#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "cache-capacity.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <unistd.h>

static bool generated_name(const char *name)
{
    if (strlen(name) < 67 || strspn(name, "0123456789abcdef") < 64) return false;
    const char *suffix = name + 64;
    if (*suffix == '-') {
        suffix++;
        if (strlen(suffix) < 64 || strspn(suffix, "0123456789abcdef") != 64) return false;
        suffix += 64;
    }
    return !strcmp(suffix, ".so") || !strcmp(suffix, ".native") || !strcmp(suffix, ".tbset");
}

static void check_changes(LatcdCacheCapacity *capacity)
{
    if (capacity->watch_fd < 0) return;
    union { struct inotify_event align; char bytes[65536]; } buffer;
    for (unsigned batch = 0; batch < 16; batch++) {
        ssize_t size = read(capacity->watch_fd, buffer.bytes, sizeof(buffer.bytes));
        if (size < 0 && errno == EINTR) continue;
        if (size < 0 && errno == EAGAIN) return;
        if (size <= 0) { capacity->ready = false; return; }
        for (size_t offset = 0; offset < (size_t)size;) {
            struct inotify_event *event = (void *)(buffer.bytes + offset);
            if (event->mask & (IN_Q_OVERFLOW | IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED))
                capacity->ready = false;
            if (event->wd != capacity->root_watch && event->mask != IN_Q_OVERFLOW)
                capacity->ready = false;
            if (event->len && (!strcmp(event->name, ".superseded") || generated_name(event->name)) &&
                (!capacity->expected_names || !g_hash_table_contains(capacity->expected_names, event->name)))
                capacity->ready = false;
            offset += sizeof(*event) + event->len;
        }
    }
    capacity->ready = false;
}

static int scan_directory(int fd, unsigned depth, GHashTable *inodes, LatcdCacheCapacity *capacity,
                           unsigned *visited, uint64_t *total)
{
    struct stat before, after;
    if (fstat(fd, &before) || !S_ISDIR(before.st_mode) || before.st_uid != geteuid() ||
        before.st_mode & 0077) { close(fd); return -1; }
    if (depth) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        if (inotify_add_watch(capacity->watch_fd, path, IN_CREATE | IN_DELETE | IN_MOVED_FROM |
            IN_MOVED_TO | IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR) < 0) {
            close(fd); return -1;
        }
    }
    DIR *directory = fdopendir(fd);
    if (!directory) { close(fd); return -1; }
    int result = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        if (++*visited > 100000) { result = -1; break; }
        bool legacy = !depth && !strcmp(name, ".superseded");
        if (!depth && !legacy && !generated_name(name)) continue;
        struct stat st;
        if (fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW)) { result = -1; break; }
        if (legacy || (depth == 1 && S_ISDIR(st.st_mode))) {
            int child = openat(fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 || scan_directory(child, depth + 1, inodes, capacity, visited, total)) {
                result = -1; break;
            }
        } else if (S_ISREG(st.st_mode) && st.st_size >= 0 && st.st_uid == geteuid()) {
            char *key = g_strdup_printf("%llu:%llu", (unsigned long long)st.st_dev,
                                       (unsigned long long)st.st_ino);
            if (!g_hash_table_contains(inodes, key)) {
                g_hash_table_add(inodes, key);
                if ((uint64_t)st.st_size > UINT64_MAX - *total) { result = -1; break; }
                *total += st.st_size;
            } else g_free(key);
        } else { result = -1; break; }
    }
    if (fstat(fd, &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        result = -1;
    closedir(directory);
    return result;
}

int latcd_cache_capacity_scan(LatcdCacheCapacity *capacity, const char *root,
                              char *error, size_t error_size)
{
    pthread_mutex_lock(&capacity->lock);
    bool busy = capacity->reserved || capacity->transient_reserved || capacity->recovered_reserved ||
        (capacity->unknown_tasks && g_hash_table_size(capacity->unknown_tasks)) ||
        (capacity->expected_names && g_hash_table_size(capacity->expected_names));
    pthread_mutex_unlock(&capacity->lock);
    if (busy) return -1;
    latcd_cache_capacity_close(capacity);
    capacity->watch_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    capacity->expected_names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    int watch = capacity->watch_fd < 0 ? -1 : inotify_add_watch(capacity->watch_fd, root,
        IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_MODIFY |
        IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR | IN_DONT_FOLLOW);
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    GHashTable *inodes = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    uint64_t total = 0;
    unsigned visited = 0;
    capacity->root_watch = watch;
    int result = fd < 0 ? -1 : scan_directory(fd, 0, inodes, capacity, &visited, &total);
    if (watch < 0) result = -1;
    g_hash_table_unref(inodes);
    pthread_mutex_lock(&capacity->lock);
    if (capacity->reserved) result = -1;
    capacity->ready = !result;
    if (!result) capacity->committed = total;
    check_changes(capacity);
    if (!capacity->ready) result = -1;
    pthread_mutex_unlock(&capacity->lock);
    if (result && error && error_size)
        snprintf(error, error_size, "capacity: incomplete or unsafe generation inventory");
    return result;
}

static int reserve_bytes(LatcdCacheCapacity *capacity, uint64_t bytes,
                           uint64_t limit, bool transient, char *error, size_t error_size)
{
    pthread_mutex_lock(&capacity->lock);
    check_changes(capacity);
    bool fits = capacity->ready &&
        (!capacity->unknown_tasks || !g_hash_table_size(capacity->unknown_tasks)) &&
        capacity->committed <= limit &&
        capacity->reserved <= limit - capacity->committed &&
        capacity->transient_reserved <= limit - capacity->committed - capacity->reserved &&
        capacity->recovered_reserved <= limit - capacity->committed - capacity->reserved - capacity->transient_reserved &&
        capacity->journal_reserved <= limit - capacity->committed - capacity->reserved - capacity->transient_reserved - capacity->recovered_reserved &&
        bytes <= limit - capacity->committed - capacity->reserved - capacity->transient_reserved - capacity->recovered_reserved - capacity->journal_reserved;
    if (fits) {
        if (transient) capacity->transient_reserved += bytes;
        else capacity->reserved += bytes;
    }
    pthread_mutex_unlock(&capacity->lock);
    if (!fits && error && error_size)
        snprintf(error, error_size, "capacity: cache capacity requires safe retirement GC (index/reservations/changes)");
    return fits ? 0 : -1;
}

int latcd_cache_capacity_reserve(LatcdCacheCapacity *capacity, uint64_t bytes,
                                 uint64_t limit, char *error, size_t error_size)
{
    return reserve_bytes(capacity, bytes, limit, false, error, error_size);
}

int latcd_cache_capacity_reserve_transient(LatcdCacheCapacity *capacity, uint64_t bytes,
                                           uint64_t limit, char *error, size_t error_size)
{
    return reserve_bytes(capacity, bytes, limit, true, error, error_size);
}

int latcd_cache_capacity_expect(LatcdCacheCapacity *capacity, const char *const *names,
                                size_t count, char *error, size_t error_size)
{
    pthread_mutex_lock(&capacity->lock);
    check_changes(capacity);
    bool valid = capacity->ready && capacity->expected_names;
    for (size_t i = 0; valid && i < count; i++)
        valid = names[i] && generated_name(names[i]) &&
            !g_hash_table_contains(capacity->expected_names, names[i]);
    if (valid) for (size_t i = 0; i < count; i++)
        g_hash_table_add(capacity->expected_names, g_strdup(names[i]));
    pthread_mutex_unlock(&capacity->lock);
    if (!valid && error && error_size)
        snprintf(error, error_size, "capacity: unexpected cache changes require startup inventory");
    return valid ? 0 : -1;
}

void latcd_cache_capacity_complete(LatcdCacheCapacity *capacity, const char *const *names,
                                   size_t count)
{
    pthread_mutex_lock(&capacity->lock);
    check_changes(capacity);
    for (size_t i = 0; i < count; i++) g_hash_table_remove(capacity->expected_names, names[i]);
    pthread_mutex_unlock(&capacity->lock);
}

void latcd_cache_capacity_close(LatcdCacheCapacity *capacity)
{
    if (capacity->watch_fd >= 0) close(capacity->watch_fd);
    capacity->watch_fd = -1;
    if (capacity->expected_names) g_hash_table_unref(capacity->expected_names);
    capacity->expected_names = NULL;
    if (capacity->recovered_tasks) g_hash_table_unref(capacity->recovered_tasks);
    capacity->recovered_tasks = NULL;
    capacity->recovered_reserved = 0;
    capacity->journal_reserved = 0;
    if (capacity->unknown_tasks) g_hash_table_unref(capacity->unknown_tasks);
    capacity->unknown_tasks = NULL;
    capacity->ready = false;
}

int latcd_cache_capacity_restore_task(LatcdCacheCapacity *capacity, const char *id, uint64_t bytes)
{
    pthread_mutex_lock(&capacity->lock);
    if (!capacity->recovered_tasks) capacity->recovered_tasks = g_hash_table_new_full(
        g_str_hash, g_str_equal, g_free, g_free);
    uint64_t *existing = g_hash_table_lookup(capacity->recovered_tasks, id);
    int result = !bytes || (existing ? *existing != bytes : bytes > UINT64_MAX - capacity->recovered_reserved);
    if (!result && !existing) {
        uint64_t *value = g_new(uint64_t, 1);
        *value = bytes;
        g_hash_table_insert(capacity->recovered_tasks, g_strdup(id), value);
        capacity->recovered_reserved += bytes;
    }
    if (!result && capacity->unknown_tasks) g_hash_table_remove(capacity->unknown_tasks, id);
    if (result) capacity->ready = false;
    pthread_mutex_unlock(&capacity->lock);
    return result ? -1 : 0;
}

void latcd_cache_capacity_unknown_task(LatcdCacheCapacity *capacity, const char *id)
{
    pthread_mutex_lock(&capacity->lock);
    if (!capacity->unknown_tasks) capacity->unknown_tasks = g_hash_table_new_full(
        g_str_hash, g_str_equal, g_free, NULL);
    if (!capacity->recovered_tasks || !g_hash_table_contains(capacity->recovered_tasks, id))
        g_hash_table_add(capacity->unknown_tasks, g_strdup(id));
    pthread_mutex_unlock(&capacity->lock);
}

void latcd_cache_capacity_release_task(LatcdCacheCapacity *capacity, const char *id)
{
    pthread_mutex_lock(&capacity->lock);
    uint64_t *bytes = capacity->recovered_tasks ? g_hash_table_lookup(capacity->recovered_tasks, id) : NULL;
    if (bytes) {
        capacity->recovered_reserved -= *bytes;
        g_hash_table_remove(capacity->recovered_tasks, id);
    }
    if (capacity->unknown_tasks) g_hash_table_remove(capacity->unknown_tasks, id);
    pthread_mutex_unlock(&capacity->lock);
}

int latcd_cache_capacity_journal(LatcdCacheCapacity *capacity, uint64_t total,
                                 uint64_t reservation, bool valid)
{
    pthread_mutex_lock(&capacity->lock);
    int result = !valid || reservation > capacity->reserved;
    if (result) capacity->ready = false;
    else {
        capacity->reserved -= reservation;
        capacity->journal_reserved = total;
    }
    pthread_mutex_unlock(&capacity->lock);
    return result ? -1 : 0;
}

static void finish_bytes(LatcdCacheCapacity *capacity, uint64_t bytes,
                           bool retained, bool transient)
{
    pthread_mutex_lock(&capacity->lock);
    uint64_t *reserved = transient ? &capacity->transient_reserved : &capacity->reserved;
    if (bytes > *reserved || (retained && bytes > UINT64_MAX - capacity->committed)) {
        capacity->ready = false;
    } else {
        *reserved -= bytes;
        if (retained) capacity->committed += bytes;
    }
    pthread_mutex_unlock(&capacity->lock);
}

void latcd_cache_capacity_finish(LatcdCacheCapacity *capacity, uint64_t bytes, bool retained)
{
    finish_bytes(capacity, bytes, retained, false);
}

void latcd_cache_capacity_finish_transient(LatcdCacheCapacity *capacity, uint64_t bytes, bool retained)
{
    finish_bytes(capacity, bytes, retained, true);
}
