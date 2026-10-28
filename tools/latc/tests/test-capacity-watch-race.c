#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

static int injection;
static char *target;
static char *replacement;
static int inject_remove_watch(int fd, int watch)
{
    if (injection == 6) {
        injection = 0;
        int writer = open(target, O_CREAT | O_EXCL | O_WRONLY, 0600);
        assert(writer >= 0 && write(writer, "new", 3) == 3 && !close(writer));
    }
    return inotify_rm_watch(fd, watch);
}
static int inject_watch(int fd, const char *path, uint32_t mask)
{
    int result = inotify_add_watch(fd, path, mask);
    assert(result >= 0);
    if ((injection == 3 || injection == 4) && (mask & IN_DONT_FOLLOW)) {
        int mode = injection;
        injection = 0;
        if (mode == 3) assert(!mkdir(target, 0700));
        else {
            assert(!rename(target, replacement));
            assert(!mkdir(target, 0700));
        }
    }
    if (injection == 5 && (mask & IN_ONLYDIR) && !(mask & IN_DONT_FOLLOW)) {
        injection = 0;
        int writer = open(target, O_CREAT | O_EXCL | O_WRONLY, 0600);
        assert(writer >= 0 && write(writer, "new", 3) == 3 && !close(writer));
    }
    if (injection == 1) assert(!rename(replacement, target));
    if (injection == 2) {
        int writer = open(target, O_WRONLY | O_TRUNC);
        assert(writer >= 0 && write(writer, "changed-long", 12) == 12 && !close(writer));
    }
    return result;
}
#define inotify_add_watch inject_watch
#define inotify_rm_watch inject_remove_watch
#include "../latcd/cache-capacity.c"
#undef inotify_add_watch
#undef inotify_rm_watch

static void put_file(const char *name, const char *data)
{
    int fd = open(name, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    assert(fd >= 0 && write(fd, data, strlen(data)) == (ssize_t)strlen(data) && !close(fd));
}

int main(void)
{
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
    root = g_dir_make_tmp("watch-gc-remove-race-XXXXXX", NULL);
    gc = g_build_filename(root, ".gc", NULL);
    target = g_build_filename(gc, "new-record", NULL);
    assert(!mkdir(gc, 0700));
    LatcdCacheCapacity removing = LATCD_CACHE_CAPACITY_INIT;
    injection = 6;
    assert(latcd_cache_capacity_scan(&removing, root, NULL, 0) < 0);
    assert(!removing.ready && injection == 0);
    latcd_cache_capacity_close(&removing);
    assert(!pthread_mutex_destroy(&removing.lock));
    assert(!unlink(target) && !rmdir(gc) && !rmdir(root));
    g_free(target); g_free(gc); g_free(root);
    puts("watch snapshot race: PASS");
    return 0;
}
