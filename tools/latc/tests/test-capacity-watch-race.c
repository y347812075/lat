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
static int inject_watch(int fd, const char *path, uint32_t mask)
{
    int result = inotify_add_watch(fd, path, mask);
    assert(result >= 0);
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
    char *root = g_dir_make_tmp("watch-race-XXXXXX", NULL);
    target = g_build_filename(root, "record", NULL);
    replacement = g_build_filename(root, "replacement", NULL);
    int directory = open(root, O_RDONLY | O_DIRECTORY);
    assert(directory >= 0);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    capacity.watch_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    capacity.state_files = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
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
    puts("watch snapshot race: PASS");
    return 0;
}
