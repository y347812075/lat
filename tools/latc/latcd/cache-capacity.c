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

static LatcdCacheCapacity *metadata_capacity;
static uint64_t metadata_limit;

static bool state_store_name(const char *name)
{
    return !strcmp(name, ".tbsets") || !strcmp(name, ".identities");
}

static char *metadata_record_key(int directory, const char *name)
{
    struct stat st;
    if (fstat(directory, &st) || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0077)) return NULL;
    return g_strdup_printf("@gc/%llu:%llu/%s", (unsigned long long)st.st_dev,
                           (unsigned long long)st.st_ino, name);
}

static int watch_state_directory(LatcdCacheCapacity *capacity, int fd, const char *prefix)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    int watch = inotify_add_watch(capacity->watch_fd, path,
        IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_MODIFY | IN_ATTRIB |
        IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR);
    if (watch < 0) return -1;
    g_hash_table_insert(capacity->state_directories, GINT_TO_POINTER(watch), g_strdup(prefix));
    return 0;
}

static bool same_file_snapshot(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

typedef struct StateFileWatch {
    char *key;
    struct stat snapshot;
} StateFileWatch;

static void state_file_watch_free(gpointer data)
{
    StateFileWatch *entry = data;
    g_free(entry->key);
    g_free(entry);
}

static int watch_state_file(LatcdCacheCapacity *capacity, int parent, const char *name,
                            const char *key, const struct stat *expected)
{
    int fd = openat(parent, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 1 : -1;
    struct stat st, after, path_st;
    int watch = -1;
    if (!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_nlink == 1 &&
        (!expected || same_file_snapshot(expected, &st))) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        watch = inotify_add_watch(capacity->watch_fd, path,
            IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF);
    }
    bool stable = watch >= 0 && !fstat(fd, &after) &&
        !fstatat(parent, name, &path_st, AT_SYMLINK_NOFOLLOW) &&
        same_file_snapshot(&st, &after) && same_file_snapshot(&after, &path_st);
    close(fd);
    if (!stable) return -1;
    StateFileWatch *entry = g_new0(StateFileWatch, 1);
    entry->key = g_strdup(key);
    entry->snapshot = after;
    g_hash_table_insert(capacity->state_files, GINT_TO_POINTER(watch), entry);
    return 0;
}

static bool current_name(const char *name)
{
    return strlen(name) == 72 && strspn(name, "0123456789abcdef") == 64 &&
        !strcmp(name + 64, ".current");
}

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

static bool watch_new_state_store(LatcdCacheCapacity *capacity, const char *name)
{
    int fd = openat(capacity->root_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    bool valid = !fstat(fd, &st) && st.st_uid == geteuid() && !(st.st_mode & 0077) &&
        !watch_state_directory(capacity, fd, name);
    DIR *directory = fdopendir(fd);
    if (!directory) { close(fd); return false; }
    unsigned visited = 0;
    while (valid) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) valid = false; break; }
        if (++visited > 2 || (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))) valid = false;
    }
    closedir(directory);
    return valid;
}

static bool watched_name_expected(LatcdCacheCapacity *capacity, int watch)
{
    GHashTable *names = capacity->file_watches ?
        g_hash_table_lookup(capacity->file_watches, GINT_TO_POINTER(watch)) : NULL;
    if (!names || !capacity->expected_names) return false;
    GHashTableIter iterator;
    gpointer name;
    g_hash_table_iter_init(&iterator, names);
    while (g_hash_table_iter_next(&iterator, &name, NULL))
        if (g_hash_table_contains(capacity->expected_names, name)) return true;
    return false;
}

static int watch_generation_file(LatcdCacheCapacity *capacity, int parent,
                                 const char *name)
{
    int file = openat(parent, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (file < 0) return errno == ENOENT ? 1 : -1;
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", file);
    int watch = inotify_add_watch(capacity->watch_fd, path,
        IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF);
    if (watch >= 0) {
        GHashTable *names = g_hash_table_lookup(capacity->file_watches,
                                                 GINT_TO_POINTER(watch));
        if (!names) {
            names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
            g_hash_table_insert(capacity->file_watches, GINT_TO_POINTER(watch), names);
        }
        g_hash_table_add(names, g_strdup(name));
    }
    close(file);
    return watch < 0 ? -1 : 0;
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
            offset += sizeof(*event) + event->len;
            gpointer watch = GINT_TO_POINTER(event->wd);
            if (g_hash_table_contains(capacity->state_ignored, watch) &&
                (event->mask & IN_IGNORED)) {
                g_hash_table_remove(capacity->state_ignored, watch);
                continue;
            }
            if (g_hash_table_contains(capacity->inventory_directories, watch)) {
                capacity->ready = false;
                continue;
            }
            const char *prefix = g_hash_table_lookup(capacity->state_directories, watch);
            StateFileWatch *watched_file = g_hash_table_lookup(capacity->state_files, watch);
            const char *file = watched_file ? watched_file->key : NULL;
            if (prefix || file) {
                char *key = prefix && event->len ? g_build_filename(prefix, event->name, NULL) : NULL;
                const char *expected = key ? key : file;
                if ((prefix && event->mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED)) ||
                    event->mask & IN_Q_OVERFLOW ||
                    !expected || !g_hash_table_contains(capacity->state_expected, expected))
                    capacity->ready = false;
                if (file && event->mask & IN_IGNORED) g_hash_table_remove(capacity->state_files, watch);
                g_free(key);
                continue;
            }
            if (event->mask & (IN_Q_OVERFLOW | IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED))
                capacity->ready = false;
            if (event->wd == capacity->root_watch && !event->len && (event->mask & IN_ATTRIB)) {
                struct stat st;
                if (fstat(capacity->root_fd, &st) || st.st_uid != geteuid() ||
                    (st.st_mode & 0077)) capacity->ready = false;
            }
            if (event->wd != capacity->root_watch && event->mask != IN_Q_OVERFLOW &&
                (!(event->mask & (IN_MODIFY | IN_ATTRIB)) || !watched_name_expected(capacity, event->wd)))
                capacity->ready = false;
            if (event->wd == capacity->root_watch && event->len &&
                (current_name(event->name) || state_store_name(event->name))) {
                bool created_empty = state_store_name(event->name) &&
                    event->mask == (IN_CREATE | IN_ISDIR) && watch_new_state_store(capacity, event->name);
                if (!created_empty && !g_hash_table_contains(capacity->state_expected, event->name))
                    capacity->ready = false;
            }
            if (capacity->inventory_active && event->wd == capacity->root_watch &&
                event->len && !strcmp(event->name, ".gc")) capacity->ready = false;
            if (event->len && (!strcmp(event->name, ".superseded") || generated_name(event->name)) &&
                (!capacity->expected_names || !g_hash_table_contains(capacity->expected_names, event->name)))
                capacity->ready = false;
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
            IN_MOVED_TO | IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR) < 0) {
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
            /* A directory watch reports child events but cannot reliably observe
             * an external hardlink changing attributes on the child inode. */
            if (watch_generation_file(capacity, fd, name)) { result = -1; break; }
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

static int scan_metadata(int fd, unsigned depth, unsigned *visited, uint64_t *total,
                         LatcdCacheCapacity *capacity)
{
    struct stat before, after;
    if (depth > 8 || fstat(fd, &before) || !S_ISDIR(before.st_mode) ||
        before.st_uid != geteuid() || (before.st_mode & 0077)) { close(fd); return -1; }
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    int watch = inotify_add_watch(capacity->watch_fd, path,
        IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_MODIFY | IN_ATTRIB |
        IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR);
    if (watch < 0) { close(fd); return -1; }
    g_hash_table_add(capacity->inventory_directories, GINT_TO_POINTER(watch));
    DIR *directory = fdopendir(fd);
    if (!directory) { close(fd); return -1; }
    int result = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat st;
        if (++*visited > 100000 || fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
            result = -1; break;
        }
        if (S_ISDIR(st.st_mode)) {
            int child = openat(fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 || scan_metadata(child, depth + 1, visited, total, capacity)) { result = -1; break; }
        } else if (S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_nlink == 1 &&
                   st.st_size >= 0 && (uint64_t)st.st_size <= UINT64_MAX - *total) {
            char *key = metadata_record_key(fd, entry->d_name);
            int watched = key ? watch_state_file(capacity, fd, entry->d_name, key, &st) : -1;
            g_free(key);
            if (watched) { result = -1; break; }
            *total += st.st_size;
        } else { result = -1; break; }
    }
    if (fstat(fd, &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        result = -1;
    closedir(directory);
    return result;
}

static int scan_state_store(int fd, const char *prefix, unsigned depth,
                            unsigned *visited, uint64_t *total, LatcdCacheCapacity *capacity)
{
    struct stat before, after;
    if (depth > 8 || fstat(fd, &before) || !S_ISDIR(before.st_mode) ||
        before.st_uid != geteuid() || (before.st_mode & 0077) ||
        watch_state_directory(capacity, fd, prefix)) { close(fd); return -1; }
    DIR *directory = fdopendir(fd);
    if (!directory) { close(fd); return -1; }
    int result = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat st;
        if (++*visited > 100000 || fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
            result = -1; break;
        }
        char *key = g_build_filename(prefix, entry->d_name, NULL);
        if (S_ISDIR(st.st_mode)) {
            int child = openat(fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 || scan_state_store(child, key, depth + 1, visited, total, capacity)) result = -1;
        } else if (S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_nlink == 1 &&
                   st.st_size >= 0 && (uint64_t)st.st_size <= UINT64_MAX - *total &&
                   !watch_state_file(capacity, fd, entry->d_name, key, &st)) {
            *total += st.st_size;
        } else result = -1;
        g_free(key);
        if (result) break;
    }
    if (fstat(fd, &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        result = -1;
    closedir(directory);
    return result;
}

static int scan_state(int fd, unsigned *visited, uint64_t *total, LatcdCacheCapacity *capacity)
{
    struct stat before, after;
    if (fstat(fd, &before)) { close(fd); return -1; }
    DIR *directory = fdopendir(fd);
    if (!directory) { close(fd); return -1; }
    int result = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        const char *name = entry->d_name;
        bool store = state_store_name(name);
        if (!store && !current_name(name)) continue;
        struct stat st;
        if (++*visited > 100000 || fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW)) {
            result = -1; break;
        }
        if (store) {
            int child = openat(fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 || scan_state_store(child, name, 0, visited, total, capacity)) { result = -1; break; }
        } else if (S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_nlink == 1 &&
                   st.st_size >= 0 && (uint64_t)st.st_size <= UINT64_MAX - *total &&
                   !watch_state_file(capacity, fd, name, name, &st)) {
            *total += st.st_size;
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
        capacity->metadata_reserved || capacity->state_reserved ||
        (capacity->unknown_tasks && g_hash_table_size(capacity->unknown_tasks)) ||
        (capacity->expected_names && g_hash_table_size(capacity->expected_names));
    pthread_mutex_unlock(&capacity->lock);
    if (busy) return -1;
    latcd_cache_capacity_close(capacity);
    capacity->watch_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    capacity->root_fd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    capacity->expected_names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    capacity->file_watches = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                                   (GDestroyNotify)g_hash_table_unref);
    capacity->state_directories = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    capacity->state_files = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, state_file_watch_free);
    capacity->state_expected = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    capacity->state_ignored = g_hash_table_new(g_direct_hash, g_direct_equal);
    capacity->inventory_directories = g_hash_table_new(g_direct_hash, g_direct_equal);
    int watch = capacity->watch_fd < 0 ? -1 : inotify_add_watch(capacity->watch_fd, root,
        IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_MODIFY | IN_ATTRIB |
        IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR | IN_DONT_FOLLOW);
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    GHashTable *inodes = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    uint64_t total = 0;
    unsigned visited = 0;
    capacity->root_watch = watch;
    capacity->inventory_active = true;
    int result = fd < 0 || capacity->root_fd < 0 ? -1 :
        scan_directory(fd, 0, inodes, capacity, &visited, &total);
    uint64_t metadata = 0;
    int gc = openat(capacity->root_fd, ".gc", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (gc >= 0) {
        if (scan_metadata(gc, 0, &visited, &metadata, capacity)) result = -1;
    } else if (errno != ENOENT) result = -1;
    uint64_t state = 0;
    int state_fd = openat(capacity->root_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (state_fd < 0 || scan_state(state_fd, &visited, &state, capacity)) result = -1;
    if (watch < 0) result = -1;
    g_hash_table_unref(inodes);
    pthread_mutex_lock(&capacity->lock);
    if (capacity->reserved) result = -1;
    capacity->ready = !result;
    if (!result) {
        capacity->committed = total;
        capacity->metadata_committed = metadata;
        capacity->state_committed = state;
    }
    check_changes(capacity);
    GHashTableIter watches;
    gpointer directory_watch;
    g_hash_table_iter_init(&watches, capacity->inventory_directories);
    while (g_hash_table_iter_next(&watches, &directory_watch, NULL)) {
        if (!inotify_rm_watch(capacity->watch_fd, GPOINTER_TO_INT(directory_watch)))
            g_hash_table_add(capacity->state_ignored, directory_watch);
        else capacity->ready = false;
    }
    check_changes(capacity);
    capacity->inventory_active = false;
    g_hash_table_remove_all(capacity->inventory_directories);
    if (!capacity->ready) result = -1;
    pthread_mutex_unlock(&capacity->lock);
    if (result && error && error_size)
        snprintf(error, error_size, "capacity: incomplete or unsafe generation inventory");
    return result;
}

static bool capacity_fits(LatcdCacheCapacity *capacity, uint64_t bytes, uint64_t limit)
{
    uint64_t remaining = limit;
    const uint64_t charges[] = {capacity->committed, capacity->reserved,
        capacity->transient_reserved, capacity->recovered_reserved, capacity->journal_reserved,
        capacity->metadata_committed, capacity->metadata_reserved,
        capacity->state_committed, capacity->state_reserved, bytes};
    for (size_t i = 0; i < G_N_ELEMENTS(charges); i++) {
        if (charges[i] > remaining) return false;
        remaining -= charges[i];
    }
    return true;
}

static int reserve_bytes(LatcdCacheCapacity *capacity, uint64_t bytes,
                           uint64_t limit, bool transient, char *error, size_t error_size)
{
    pthread_mutex_lock(&capacity->lock);
    check_changes(capacity);
    bool fits = capacity->ready &&
        (!capacity->unknown_tasks || !g_hash_table_size(capacity->unknown_tasks)) &&
        capacity_fits(capacity, bytes, limit);
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
    bool valid = capacity->ready && capacity->root_fd >= 0 && capacity->expected_names;
    for (size_t i = 0; valid && i < count; i++) {
        int watched = watch_generation_file(capacity, capacity->root_fd, names[i]);
        valid = watched >= 0;
    }
    if (valid) for (size_t i = 0; i < count; i++)
        g_hash_table_remove(capacity->expected_names, names[i]);
    else capacity->ready = false;
    pthread_mutex_unlock(&capacity->lock);
}

int latcd_cache_capacity_poll(LatcdCacheCapacity *capacity)
{
    pthread_mutex_lock(&capacity->lock);
    check_changes(capacity);
    int ready = capacity->ready;
    pthread_mutex_unlock(&capacity->lock);
    return ready;
}

void latcd_cache_capacity_close(LatcdCacheCapacity *capacity)
{
    if (metadata_capacity == capacity) metadata_capacity = NULL;
    if (capacity->watch_fd >= 0) close(capacity->watch_fd);
    capacity->watch_fd = -1;
    if (capacity->root_fd >= 0) close(capacity->root_fd);
    capacity->root_fd = -1;
    if (capacity->expected_names) g_hash_table_unref(capacity->expected_names);
    capacity->expected_names = NULL;
    if (capacity->file_watches) g_hash_table_unref(capacity->file_watches);
    capacity->file_watches = NULL;
    if (capacity->state_directories) g_hash_table_unref(capacity->state_directories);
    capacity->state_directories = NULL;
    if (capacity->state_files) g_hash_table_unref(capacity->state_files);
    capacity->state_files = NULL;
    if (capacity->state_expected) g_hash_table_unref(capacity->state_expected);
    capacity->state_expected = NULL;
    if (capacity->state_ignored) g_hash_table_unref(capacity->state_ignored);
    capacity->state_ignored = NULL;
    if (capacity->inventory_directories) g_hash_table_unref(capacity->inventory_directories);
    capacity->inventory_directories = NULL;
    if (capacity->recovered_tasks) g_hash_table_unref(capacity->recovered_tasks);
    capacity->recovered_tasks = NULL;
    capacity->recovered_reserved = 0;
    capacity->journal_reserved = 0;
    capacity->metadata_committed = 0;
    capacity->metadata_reserved = 0;
    capacity->state_committed = 0;
    capacity->state_reserved = 0;
    if (capacity->unknown_tasks) g_hash_table_unref(capacity->unknown_tasks);
    capacity->unknown_tasks = NULL;
    capacity->ready = false;
}

void latcd_cache_capacity_metadata_bind(LatcdCacheCapacity *capacity, uint64_t limit)
{
    metadata_capacity = capacity;
    metadata_limit = limit;
}

static bool metadata_directory_matches(LatcdCacheCapacity *capacity, int directory)
{
    struct stat expected, st;
    if (fstatat(capacity->root_fd, ".gc", &expected, AT_SYMLINK_NOFOLLOW) ||
        !S_ISDIR(expected.st_mode)) return false;
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool matched = false;
    for (unsigned depth = 0; fd >= 0 && depth <= 8; depth++) {
        if (fstat(fd, &st) || st.st_uid != geteuid() || (st.st_mode & 0077)) break;
        if (st.st_dev == expected.st_dev && st.st_ino == expected.st_ino) { matched = true; break; }
        int parent = openat(fd, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        close(fd);
        fd = parent;
    }
    if (fd >= 0) close(fd);
    return matched;
}

static char *state_record_key(LatcdCacheCapacity *capacity, int directory,
                              const char *name)
{
    struct stat actual, expected;
    if (fstat(directory, &actual) || !S_ISDIR(actual.st_mode) ||
        actual.st_uid != geteuid() || (actual.st_mode & 0077) ||
        fstat(capacity->root_fd, &expected)) return NULL;
    if (actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino)
        return current_name(name) ? g_strdup(name) : NULL;
    const char *stores[] = {".tbsets", ".identities"};
    for (unsigned i = 0; i < G_N_ELEMENTS(stores); i++) {
        if (!fstatat(capacity->root_fd, stores[i], &expected, AT_SYMLINK_NOFOLLOW) &&
            S_ISDIR(expected.st_mode) && actual.st_dev == expected.st_dev &&
            actual.st_ino == expected.st_ino) return g_build_filename(stores[i], name, NULL);
    }
    return NULL;
}

static int record_begin(int directory, const char *name, uint64_t bytes,
                        LatcdMetadataReservation *reservation, bool state,
                        bool recovery)
{
    *reservation = (LatcdMetadataReservation){0};
    LatcdCacheCapacity *capacity = metadata_capacity;
    if (!capacity) return 0;
    struct stat previous;
    uint64_t old = 0;
    if (!name || !*name || strchr(name, '/') || !strcmp(name, ".") || !strcmp(name, "..")) {
        errno = EINVAL; return -1;
    }
    char *key = state ? state_record_key(capacity, directory, name) :
        metadata_directory_matches(capacity, directory) ? metadata_record_key(directory, name) : NULL;
    if (!key) {
        errno = EINVAL; return -1;
    }
    int owned_directory = fcntl(directory, F_DUPFD_CLOEXEC, 0);
    if (owned_directory < 0) { g_free(key); return -1; }
    pthread_mutex_lock(&capacity->lock);
    check_changes(capacity);
    StateFileWatch *tracked = NULL;
    GHashTableIter tracked_iterator;
    gpointer tracked_value;
    g_hash_table_iter_init(&tracked_iterator, capacity->state_files);
    while (g_hash_table_iter_next(&tracked_iterator, NULL, &tracked_value)) {
        StateFileWatch *entry = tracked_value;
        if (!strcmp(entry->key, key)) { tracked = entry; break; }
    }
    if (!fstatat(directory, name, &previous, AT_SYMLINK_NOFOLLOW)) {
        if (!S_ISREG(previous.st_mode) || previous.st_uid != geteuid() ||
            previous.st_nlink != 1 || previous.st_size < 0 || !tracked ||
            !same_file_snapshot(&tracked->snapshot, &previous)) {
            capacity->ready = false;
            pthread_mutex_unlock(&capacity->lock);
            if (owned_directory >= 0) close(owned_directory);
            g_free(key); errno = EINVAL; return -1;
        }
        old = previous.st_size;
    } else if (errno != ENOENT || tracked) {
        int saved = errno;
        capacity->ready = false;
        pthread_mutex_unlock(&capacity->lock);
        if (owned_directory >= 0) close(owned_directory);
        g_free(key); errno = saved; return -1;
    }
    /* Recovery may need to finish a committed transaction even with the normal
     * index closed. It is still charged, but cannot open new admission. */
    bool fits = capacity->ready && capacity_fits(capacity, bytes, metadata_limit);
    bool updating = g_hash_table_contains(capacity->state_expected, key);
    if (updating) fits = false;
    if (recovery && !state && !fits && !updating && old && bytes <= UINT64_MAX - capacity->metadata_reserved) {
        /* Existing transaction completion cannot be blocked after current has
         * committed. Preserve the charge and close ordinary admission. */
        capacity->ready = false;
        fits = true;
    }
    if (fits) {
        if (state) capacity->state_reserved += bytes;
        else capacity->metadata_reserved += bytes;
        *reservation = (LatcdMetadataReservation){.capacity = capacity, .bytes = bytes,
            .previous = old, .state = state, .directory = owned_directory, .name = key};
        g_hash_table_add(capacity->state_expected, g_strdup(key));
    }
    pthread_mutex_unlock(&capacity->lock);
    if (!fits) {
        if (owned_directory >= 0) close(owned_directory);
        g_free(key);
        errno = ENOSPC;
    }
    return fits ? 0 : -1;
}

int latcd_cache_capacity_metadata_begin(int directory, const char *name, uint64_t bytes,
    LatcdMetadataReservation *reservation)
{
    return record_begin(directory, name, bytes, reservation, false, true);
}

int latcd_cache_capacity_metadata_schedule_begin(int directory, const char *name, uint64_t bytes,
    LatcdMetadataReservation *reservation)
{
    return record_begin(directory, name, bytes, reservation, false, false);
}

int latcd_cache_capacity_state_begin(int directory, const char *name, uint64_t bytes,
    LatcdMetadataReservation *reservation)
{
    return record_begin(directory, name, bytes, reservation, true, false);
}

int latcd_cache_capacity_metadata_stage(LatcdMetadataReservation *reservation, const char *name)
{
    LatcdCacheCapacity *capacity = reservation->capacity;
    if (!capacity) return 0;
    if (reservation->state || reservation->staging || !name || !*name ||
        strchr(name, '/') || !strcmp(name, ".") || !strcmp(name, "..")) {
        errno = EINVAL; return -1;
    }
    char *key = metadata_record_key(reservation->directory, name);
    if (!key) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&capacity->lock);
    check_changes(capacity);
    bool valid = !g_hash_table_contains(capacity->state_expected, key);
    if (valid) {
        reservation->staging = key;
        g_hash_table_add(capacity->state_expected, g_strdup(key));
    }
    pthread_mutex_unlock(&capacity->lock);
    if (!valid) { g_free(key); errno = EBUSY; }
    return valid ? 0 : -1;
}

void latcd_cache_capacity_metadata_unstage(LatcdMetadataReservation *reservation)
{
    LatcdCacheCapacity *capacity = reservation->capacity;
    if (!capacity || !reservation->staging) return;
    pthread_mutex_lock(&capacity->lock);
    check_changes(capacity);
    g_hash_table_remove(capacity->state_expected, reservation->staging);
    g_clear_pointer(&reservation->staging, g_free);
    pthread_mutex_unlock(&capacity->lock);
}

int latcd_cache_capacity_state_stage(LatcdMetadataReservation *reservation, const char *name)
{
    LatcdCacheCapacity *capacity = reservation->capacity;
    if (!capacity) return 0;
    if (!reservation->state || reservation->staging || !name || !*name ||
        strchr(name, '/') || !strcmp(name, ".") || !strcmp(name, "..")) { errno = EINVAL; return -1; }
    char *parent = g_path_get_dirname(reservation->name);
    char *key = !strcmp(parent, ".") ? g_strdup(name) : g_build_filename(parent, name, NULL);
    g_free(parent);
    pthread_mutex_lock(&capacity->lock);
    check_changes(capacity);
    bool valid = capacity->ready && !g_hash_table_contains(capacity->state_expected, key);
    if (valid) {
        reservation->staging = key;
        g_hash_table_add(capacity->state_expected, g_strdup(key));
    }
    pthread_mutex_unlock(&capacity->lock);
    if (!valid) { g_free(key); errno = EBUSY; }
    return valid ? 0 : -1;
}

void latcd_cache_capacity_metadata_finish(LatcdMetadataReservation *reservation,
    bool replaced, bool leftover)
{
    LatcdCacheCapacity *capacity = reservation->capacity;
    if (!capacity) return;
    pthread_mutex_lock(&capacity->lock);
    {
        /* Drain old-inode retirement events while the exact target is expected,
         * then remove its watch before installing the replacement watch. */
        check_changes(capacity);
        if (replaced) {
            GHashTableIter iterator;
            gpointer watch, value;
            g_hash_table_iter_init(&iterator, capacity->state_files);
            while (g_hash_table_iter_next(&iterator, &watch, &value)) {
                StateFileWatch *entry = value;
                if (strcmp(entry->key, reservation->name)) continue;
                if (!inotify_rm_watch(capacity->watch_fd, GPOINTER_TO_INT(watch)))
                    g_hash_table_add(capacity->state_ignored, watch);
                g_hash_table_iter_remove(&iterator);
            }
            char *basename = g_path_get_basename(reservation->name);
            int watched = watch_state_file(capacity, reservation->directory, basename, reservation->name, NULL);
            if (watched) capacity->ready = false;
            g_free(basename);
        }
        check_changes(capacity);
        g_hash_table_remove(capacity->state_expected, reservation->name);
        if (reservation->staging) g_hash_table_remove(capacity->state_expected, reservation->staging);
    }
    uint64_t *reserved = reservation->state ? &capacity->state_reserved : &capacity->metadata_reserved;
    uint64_t *committed = reservation->state ? &capacity->state_committed : &capacity->metadata_committed;
    if (reservation->bytes > *reserved ||
        (replaced && reservation->previous > *committed)) capacity->ready = false;
    else {
        *reserved -= reservation->bytes;
        uint64_t retained = replaced || leftover ? reservation->bytes : 0;
        if (replaced) *committed -= reservation->previous;
        if (retained > UINT64_MAX - *committed) capacity->ready = false;
        else *committed += retained;
        if (leftover) capacity->ready = false;
    }
    pthread_mutex_unlock(&capacity->lock);
    close(reservation->directory);
    g_free(reservation->name);
    g_free(reservation->staging);
    *reservation = (LatcdMetadataReservation){0};
}

int latcd_cache_capacity_metadata_remove(int directory, const char *name,
                                         uint64_t device, uint64_t inode)
{
    LatcdCacheCapacity *capacity = metadata_capacity;
    if (!capacity || !name || !*name || strchr(name, '/') || !strcmp(name, ".") ||
        !strcmp(name, "..") || !device || !inode) { errno = EINVAL; return -1; }
    char *key = metadata_directory_matches(capacity, directory) ?
        metadata_record_key(directory, name) : NULL;
    if (!key) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&capacity->lock);
    check_changes(capacity);
    struct stat st;
    int result = -1;
    if (!capacity->ready || g_hash_table_contains(capacity->state_expected, key)) {
        errno = EBUSY;
        goto out;
    }
    GHashTableIter iterator;
    gpointer watch, watched_key;
    StateFileWatch *inventoried = NULL;
    g_hash_table_iter_init(&iterator, capacity->state_files);
    while (g_hash_table_iter_next(&iterator, &watch, &watched_key)) {
        StateFileWatch *entry = watched_key;
        if (!strcmp(entry->key, key)) { inventoried = entry; break; }
    }
    if (!inventoried) {
        capacity->ready = false;
        errno = ESTALE;
        goto out;
    }
    g_hash_table_add(capacity->state_expected, g_strdup(key));
    if (fstatat(directory, name, &st, AT_SYMLINK_NOFOLLOW) ||
        !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 ||
        st.st_size < 0 || !same_file_snapshot(&inventoried->snapshot, &st) ||
        (uint64_t)st.st_dev != device || (uint64_t)st.st_ino != inode ||
        (uint64_t)st.st_size > capacity->metadata_committed ||
        unlinkat(directory, name, 0) || fsync(directory)) {
        capacity->ready = false;
    } else {
        capacity->metadata_committed -= (uint64_t)st.st_size;
        result = 0;
    }
    check_changes(capacity);
    g_hash_table_iter_init(&iterator, capacity->state_files);
    while (g_hash_table_iter_next(&iterator, &watch, &watched_key)) {
        StateFileWatch *entry = watched_key;
        if (strcmp(entry->key, key)) continue;
        if (!inotify_rm_watch(capacity->watch_fd, GPOINTER_TO_INT(watch)))
            g_hash_table_add(capacity->state_ignored, watch);
        g_hash_table_iter_remove(&iterator);
    }
    check_changes(capacity);
    g_hash_table_remove(capacity->state_expected, key);
out:
    pthread_mutex_unlock(&capacity->lock);
    g_free(key);
    return result;
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
