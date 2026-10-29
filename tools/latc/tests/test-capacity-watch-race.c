#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <glib.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

static int injection;
static char *target;
static char *replacement;
static int retained_writer = -1;
static int inject_watch(int fd, const char *path, uint32_t mask)
{
    bool restore_root = injection == 8 && (mask & IN_DONT_FOLLOW);
    if ((injection == 7 || restore_root) && (mask & IN_DONT_FOLLOW)) {
        if (!restore_root) injection = 0;
        assert(!rename(target, replacement) && !mkdir(target, 0700));
    }
    char *target_parent = injection == 6 ? g_path_get_dirname(target) : NULL;
    if (injection == 6 && (mask & IN_ONLYDIR) && !(mask & IN_DONT_FOLLOW) &&
        access(target_parent, F_OK) && errno == ENOENT) {
        injection = 0;
        assert(!mkdir(target_parent, 0700));
        int writer = open(target, O_CREAT | O_EXCL | O_WRONLY, 0600);
        assert(writer >= 0 && write(writer, "x", 1) == 1);
        assert(!unlink(target));
        retained_writer = writer;
    }
    g_free(target_parent);
    int result = inotify_add_watch(fd, path, mask);
    assert(result >= 0);
    if (restore_root) {
        injection = 0;
        assert(!rmdir(target) && !rename(replacement, target));
    }
    if ((injection == 3 || injection == 4) && (mask & IN_DONT_FOLLOW)) {
        int mode = injection;
        injection = 0;
        if (mode == 3) assert(!mkdir(target, 0700));
        else {
            assert(!rename(target, replacement));
            assert(!mkdir(target, 0700));
        }
    }
    struct stat watched_dir, target_dir;
    char *parent = injection == 5 ? g_path_get_dirname(target) : NULL;
    if (injection == 5 && (mask & IN_ONLYDIR) && !(mask & IN_DONT_FOLLOW) &&
        !stat(path, &watched_dir) && !stat(parent, &target_dir) &&
        watched_dir.st_dev == target_dir.st_dev && watched_dir.st_ino == target_dir.st_ino) {
        injection = 0;
        int writer = open(target, O_CREAT | O_EXCL | O_WRONLY, 0600);
        assert(writer >= 0 && write(writer, "new", 3) == 3 && !close(writer));
    }
    g_free(parent);
    if (injection == 1) assert(!rename(replacement, target));
    if (injection == 2) {
        int writer = open(target, O_WRONLY | O_TRUNC);
        assert(writer >= 0 && write(writer, "changed-long", 12) == 12 && !close(writer));
    }
    return result;
}
#define inotify_add_watch inject_watch
#include "../latcd/cache-capacity.c"
#undef inotify_add_watch

static void put_file(const char *name, const char *data)
{
    int fd = open(name, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    assert(fd >= 0 && write(fd, data, strlen(data)) == (ssize_t)strlen(data) && !close(fd));
}

int main(void)
{
    for (int mode = 7; mode <= 8; mode++) {
        char *swapped_root = g_dir_make_tmp("watch-root-swap-XXXXXX", NULL);
        target = swapped_root;
        replacement = g_strconcat(swapped_root, "-old", NULL);
        LatcdCacheCapacity swapped = LATCD_CACHE_CAPACITY_INIT;
        injection = mode;
        assert(latcd_cache_capacity_scan(&swapped, swapped_root, NULL, 0) < 0);
        assert(!swapped.ready && !injection);
        latcd_cache_capacity_close(&swapped);
        assert(!pthread_mutex_destroy(&swapped.lock));
        assert(!rmdir(swapped_root));
        if (mode == 7) assert(!rmdir(replacement));
        g_free(replacement); g_free(swapped_root);
    }
    char *root = g_dir_make_tmp("watch-race-XXXXXX", NULL);
    target = g_build_filename(root, "record", NULL);
    replacement = g_build_filename(root, "replacement", NULL);
    int directory = open(root, O_RDONLY | O_DIRECTORY);
    assert(directory >= 0);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    capacity.watch_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    capacity.state_files = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, state_file_watch_free);
    assert(capacity.watch_fd >= 0);
    struct stat expected;
    put_file(target, "old");
    assert(!fstatat(directory, "record", &expected, 0));
    put_file(replacement, "new-record");
    assert(!rename(replacement, target));
    assert(watch_state_file(&capacity, directory, "record", "a", &expected) < 0);
    for (injection = 1; injection <= 2; injection++) {
        put_file(target, "old");
        put_file(replacement, "new-record");
        assert(!fstatat(directory, "record", &expected, 0));
        assert(watch_state_file(&capacity, directory, "record", "b", &expected) < 0);
    }
    injection = 0;
    assert(!fstatat(directory, "record", &expected, 0));
    assert(!watch_state_file(&capacity, directory, "record", "c", &expected));
    close(directory);
    close(capacity.watch_fd);
    g_hash_table_unref(capacity.state_files);
    unlink(target); unlink(replacement); assert(!rmdir(root));
    g_free(target); g_free(replacement); g_free(root);
    for (int mode = 3; mode <= 4; mode++) {
        root = g_dir_make_tmp("watch-gc-race-XXXXXX", NULL);
        target = g_build_filename(root, ".gc", NULL);
        replacement = g_build_filename(root, "old-gc", NULL);
        if (mode == 4) assert(!mkdir(target, 0700));
        LatcdCacheCapacity scan = LATCD_CACHE_CAPACITY_INIT;
        injection = mode;
        assert(latcd_cache_capacity_scan(&scan, root, NULL, 0) < 0);
        assert(!scan.ready);
        latcd_cache_capacity_close(&scan);
        assert(!pthread_mutex_destroy(&scan.lock));
        assert(!rmdir(target));
        if (mode == 4) assert(!rmdir(replacement));
        assert(!rmdir(root));
        g_free(target); g_free(replacement); g_free(root);
    }
    root = g_dir_make_tmp("watch-gc-child-race-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    target = g_build_filename(gc, "new-record", NULL);
    assert(!mkdir(gc, 0700));
    LatcdCacheCapacity scan = LATCD_CACHE_CAPACITY_INIT;
    injection = 5;
    assert(latcd_cache_capacity_scan(&scan, root, NULL, 0) < 0);
    assert(!scan.ready);
    latcd_cache_capacity_close(&scan);
    assert(!pthread_mutex_destroy(&scan.lock));
    assert(!unlink(target) && !rmdir(gc) && !rmdir(root));
    g_free(target); g_free(gc); g_free(root);
    root = g_dir_make_tmp("watch-gc-registration-race-XXXXXX", NULL);
    gc = g_build_filename(root, ".gc", NULL);
    target = g_build_filename(gc, "store", "transient", NULL);
    assert(!mkdir(gc, 0700));
    LatcdCacheCapacity registering = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&registering, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&registering, UINT64_MAX);
    int gcfd = open(gc, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(gcfd >= 0);
    injection = 6;
    int created = latcd_cache_capacity_open_metadata_directory(gcfd, "store");
    assert(retained_writer >= 0);
    assert(write(retained_writer, "unaccounted", 11) == 11);
    assert(!close(retained_writer));
    retained_writer = -1;
    if (created >= 0) close(created);
    assert(created < 0);
    assert(!latcd_cache_capacity_poll(&registering));
    close(gcfd);
    latcd_cache_capacity_close(&registering);
    assert(!pthread_mutex_destroy(&registering.lock));
    char *store = g_build_filename(gc, "store", NULL);
    assert(!rmdir(store) && !rmdir(gc) && !rmdir(root));
    g_free(store); g_free(target); g_free(gc); g_free(root);
    const char *state_names[] = {".tbsets", ".identities"};
    for (unsigned i = 0; i < G_N_ELEMENTS(state_names); i++) {
        root = g_dir_make_tmp("watch-state-hidden-XXXXXX", NULL);
        char *state = g_build_filename(root, state_names[i], NULL);
        target = g_build_filename(state, "transient", NULL);
        LatcdCacheCapacity state_scan = LATCD_CACHE_CAPACITY_INIT;
        assert(!latcd_cache_capacity_scan(&state_scan, root, NULL, 0));
        assert(!mkdir(state, 0700));
        int writer = open(target, O_CREAT | O_EXCL | O_WRONLY, 0600);
        assert(writer >= 0 && !unlink(target));
        assert(!latcd_cache_capacity_poll(&state_scan));
        assert(write(writer, "unaccounted", 11) == 11 && !close(writer));
        latcd_cache_capacity_close(&state_scan);
        assert(!pthread_mutex_destroy(&state_scan.lock));
        assert(!rmdir(state) && !rmdir(root));
        g_free(target); g_free(state); g_free(root);
    }
    root = g_dir_make_tmp("watch-gc-remove-race-XXXXXX", NULL);
    gc = g_build_filename(root, ".gc", NULL);
    target = g_build_filename(root, "moved-gc", NULL);
    assert(!mkdir(gc, 0700));
    LatcdCacheCapacity removing = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&removing, root, NULL, 0));
    assert(!rename(gc, target));
    assert(!latcd_cache_capacity_poll(&removing));
    latcd_cache_capacity_close(&removing);
    assert(!pthread_mutex_destroy(&removing.lock));
    assert(!rmdir(target) && !rmdir(root));
    g_free(target); g_free(gc); g_free(root);
    puts("watch snapshot race: PASS");
    return 0;
}
