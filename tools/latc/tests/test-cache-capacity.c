#define _GNU_SOURCE
#include "../latcd/cache-capacity.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static int remove_fault;
int __real_unlinkat(int fd, const char *name, int flags);
int __real_fsync(int fd);
int __wrap_unlinkat(int fd, const char *name, int flags)
{
    if (remove_fault == 1) { errno = EIO; return -1; }
    return __real_unlinkat(fd, name, flags);
}
int __wrap_fsync(int fd)
{
    if (remove_fault == 2) { errno = EIO; return -1; }
    return __real_fsync(fd);
}

static void put(const char *path, const char *contents)
{
    assert(g_file_set_contents(path, contents, -1, NULL));
    assert(!chmod(path, 0400));
}

typedef struct ReservationRace {
    LatcdCacheCapacity *capacity;
    pthread_barrier_t *start;
    pthread_barrier_t *finish;
    bool accepted;
} ReservationRace;

static void *reserve_race(void *data)
{
    ReservationRace *race = data;
    pthread_barrier_wait(race->start);
    race->accepted = !latcd_cache_capacity_reserve(race->capacity, 60, 100, NULL, 0);
    pthread_barrier_wait(race->finish);
    if (race->accepted) latcd_cache_capacity_finish(race->capacity, 60, false);
    return NULL;
}

static void test_external_writer(unsigned mutation)
{
    char *root = g_dir_make_tmp("capacity-write-XXXXXX", NULL);
    char *outside = g_dir_make_tmp("capacity-writer-XXXXXX", NULL);
    char *name = g_strnfill(64, 'a');
    char *basename = g_strconcat(name, ".native", NULL);
    char *path = g_build_filename(root, basename, NULL);
    char *alias = g_build_filename(outside, "alias", NULL);
    assert(root && outside);
    assert(g_file_set_contents(path, "initial", -1, NULL));
    assert(!link(path, alias));
    int writer = open(alias, O_WRONLY | O_CLOEXEC);
    assert(writer >= 0 && !chmod(path, 0400));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(capacity.committed == 7);
    if (mutation == 0) assert(pwrite(writer, "replacement", 11, 0) == 11);
    if (mutation == 1) assert(!ftruncate(writer, 4096));
    if (mutation == 2) assert(pwrite(writer, "changed", 7, 0) == 7);
    assert(!latcd_cache_capacity_poll(&capacity));
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0) < 0);
    assert(latcd_cache_capacity_reserve_transient(&capacity, 0, UINT64_MAX, NULL, 0) < 0);
    assert(!close(writer));
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(capacity.committed == (mutation == 0 ? 11u : mutation == 1 ? 4096u : 7u));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!unlink(alias) && !unlink(path) && !rmdir(outside) && !rmdir(root));
    g_free(root); g_free(outside); g_free(name); g_free(basename); g_free(path); g_free(alias);
}

static void test_metadata(void)
{
    char *root = g_dir_make_tmp("capacity-metadata-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "transactions", NULL);
    char *record = g_build_filename(store, "record.ini", NULL);
    assert(!g_mkdir_with_parents(store, 0700));
    put(record, "12345");
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(!capacity.committed && capacity.metadata_committed == 5);
    assert(latcd_cache_capacity_reserve(&capacity, 1, 5, NULL, 0) < 0);
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    int directory = open(store, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    LatcdMetadataReservation first, second;
    assert(directory >= 0);
    assert(!latcd_cache_capacity_metadata_begin(directory, "next.ini", 5, &first));
    assert(capacity.metadata_reserved == 5);
    assert(latcd_cache_capacity_metadata_stage(&first, "../bad") < 0);
    assert(!latcd_cache_capacity_metadata_stage(&first, ".write-first"));
    assert(latcd_cache_capacity_metadata_stage(&first, ".write-second") < 0);
    latcd_cache_capacity_metadata_unstage(&first);
    assert(!latcd_cache_capacity_metadata_stage(&first, ".write-second"));
    latcd_cache_capacity_metadata_unstage(&first);
    assert(latcd_cache_capacity_metadata_begin(directory, "other.ini", 1, &second) < 0);
    assert(latcd_cache_capacity_scan(&capacity, root, NULL, 0) < 0);
    latcd_cache_capacity_metadata_finish(&first, false, false);
    assert(!capacity.metadata_reserved && capacity.metadata_committed == 5);
    char *uncharged = g_build_filename(store, "uncharged.ini", NULL);
    put(uncharged, "abc");
    assert(latcd_cache_capacity_metadata_begin(directory, "uncharged.ini", 2, &first) < 0);
    assert(!capacity.ready && capacity.metadata_committed == 5 && !capacity.metadata_reserved);
    assert(!unlink(uncharged));
    g_free(uncharged);
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    int held_replaced = open(record, O_RDONLY | O_CLOEXEC);
    assert(held_replaced >= 0);
    char *new_record = g_build_filename(store, "new-record.ini", NULL);
    put(new_record, "abc");
    assert(!rename(new_record, record));
    assert(latcd_cache_capacity_metadata_begin(directory, "record.ini", 2, &first) < 0);
    assert(!capacity.ready && capacity.metadata_committed == 5 && !capacity.metadata_reserved);
    close(held_replaced);
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    assert(capacity.metadata_committed == 3);
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 5, &first));
    put(record, "12345");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    g_free(new_record);
    int held_missing = open(record, O_RDONLY | O_CLOEXEC);
    assert(held_missing >= 0 && !unlink(record));
    assert(latcd_cache_capacity_metadata_begin(directory, "record.ini", 2, &first) < 0);
    assert(!capacity.ready && capacity.metadata_committed == 5 && !capacity.metadata_reserved);
    close(held_missing);
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    assert(!capacity.metadata_committed);
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 5, &first));
    put(record, "12345");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 3, &first));
    int prior = open(record, O_RDONLY | O_CLOEXEC);
    assert(prior >= 0);
    char *failed_replacement = g_build_filename(store, "failed-replacement.ini", NULL);
    put(failed_replacement, "abc");
    assert(!rename(failed_replacement, record));
    latcd_cache_capacity_metadata_finish(&first, false, false);
    struct stat unexpected_replacement;
    assert(!stat(record, &unexpected_replacement));
    assert(latcd_cache_capacity_metadata_remove(directory, "record.ini", unexpected_replacement.st_dev,
                                                 unexpected_replacement.st_ino) < 0);
    assert(!capacity.ready && capacity.metadata_committed == 5 && !access(record, F_OK));
    close(prior);
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    assert(capacity.metadata_committed == 3);
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 5, &first));
    put(record, "12345");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    g_free(failed_replacement);
    char *unregistered = g_build_filename(store, "unregistered.ini", NULL);
    put(unregistered, "123");
    struct stat unexpected;
    assert(!stat(unregistered, &unexpected));
    assert(latcd_cache_capacity_metadata_remove(directory, "unregistered.ini", unexpected.st_dev,
                                                 unexpected.st_ino) < 0);
    assert(!capacity.ready && capacity.metadata_committed == 5 && !access(unregistered, F_OK));
    assert(!unlink(unregistered));
    g_free(unregistered);
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    int held_old = open(record, O_RDONLY | O_CLOEXEC);
    assert(held_old >= 0);
    char *replacement = g_build_filename(store, "replacement.ini", NULL);
    put(replacement, "xyz");
    assert(!rename(replacement, record));
    struct stat replaced;
    assert(!stat(record, &replaced));
    assert(latcd_cache_capacity_metadata_remove(directory, "record.ini", replaced.st_dev,
                                                 replaced.st_ino) < 0);
    assert(!capacity.ready && capacity.metadata_committed == 5 && !access(record, F_OK));
    close(held_old);
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    assert(capacity.metadata_committed == 3);
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 5, &first));
    put(record, "12345");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    g_free(replacement);
    struct stat original;
    assert(!stat(record, &original));
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 3, &first));
    assert(latcd_cache_capacity_metadata_remove(directory, "record.ini", original.st_dev,
                                                 original.st_ino) < 0);
    assert(capacity.ready && capacity.metadata_committed == 5);
    latcd_cache_capacity_metadata_finish(&first, false, false);
    assert(latcd_cache_capacity_metadata_remove(directory, "record.ini", original.st_dev,
                                                 original.st_ino + 1) < 0);
    assert(!capacity.ready && capacity.metadata_committed == 5 && !access(record, F_OK));
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    for (int fault = 1; fault <= 2; fault++) {
        assert(!stat(record, &original));
        remove_fault = fault;
        assert(latcd_cache_capacity_metadata_remove(directory, "record.ini", original.st_dev,
                                                     original.st_ino) < 0);
        remove_fault = 0;
        assert(!capacity.ready && capacity.metadata_committed == 5);
        assert((access(record, F_OK) == 0) == (fault == 1));
        assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
        latcd_cache_capacity_metadata_bind(&capacity, 10);
        if (fault == 2) {
            assert(!capacity.metadata_committed);
            assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 5, &first));
            put(record, "12345");
            latcd_cache_capacity_metadata_finish(&first, true, false);
        }
    }
    assert(!stat(record, &original));
    assert(!latcd_cache_capacity_metadata_remove(directory, "record.ini", original.st_dev,
                                                  original.st_ino));
    assert(capacity.ready && !capacity.metadata_committed && access(record, F_OK));
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 5, &first));
    put(record, "12345");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 3, &first));
    put(record, "123");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    assert(capacity.metadata_committed == 3 && !capacity.metadata_reserved);
    latcd_cache_capacity_metadata_bind(&capacity, 3);
    assert(latcd_cache_capacity_metadata_schedule_begin(directory, "record.ini", 4, &first) < 0);
    assert(capacity.ready && capacity.metadata_committed == 3 && !capacity.metadata_reserved);
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 4, &first));
    assert(!capacity.ready && capacity.metadata_reserved == 4);
    put(record, "1234");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    assert(capacity.metadata_committed == 4);
    assert(latcd_cache_capacity_metadata_schedule_begin(directory, "record.ini", 1, &first) < 0);
    assert(!capacity.ready && capacity.metadata_committed == 4 && !capacity.metadata_reserved);
    latcd_cache_capacity_metadata_bind(&capacity, 100);
    assert(latcd_cache_capacity_metadata_begin(directory, "../escape", 1, &first) < 0);
    assert(latcd_cache_capacity_metadata_begin(directory, "new-while-closed", 1, &first) < 0);
    int outside = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(outside >= 0 && latcd_cache_capacity_metadata_begin(outside, "bad", 1, &first) < 0);
    close(outside);
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 100);
    assert(!latcd_cache_capacity_metadata_begin(directory, "partial", 6, &first));
    latcd_cache_capacity_metadata_finish(&first, false, true);
    assert(capacity.metadata_committed == 10 && !capacity.ready);
    latcd_cache_capacity_close(&capacity);
    assert(!capacity.metadata_committed && !capacity.metadata_reserved);
    assert(!latcd_cache_capacity_metadata_begin(directory, "offline", 1, &first));
    assert(!first.capacity);
    assert(!linkat(directory, "record.ini", directory, "alias", 0));
    assert(latcd_cache_capacity_scan(&capacity, root, NULL, 0) < 0 && !capacity.ready);
    assert(!unlinkat(directory, "alias", 0));
    assert(!symlinkat("record.ini", directory, "alias"));
    assert(latcd_cache_capacity_scan(&capacity, root, NULL, 0) < 0 && !capacity.ready);
    assert(!unlinkat(directory, "alias", 0));
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(capacity.metadata_committed == 4 && capacity.ready);
    latcd_cache_capacity_close(&capacity);
    close(directory);
    assert(!unlink(record) && !rmdir(store) && !rmdir(gc) && !rmdir(root));
    assert(!pthread_mutex_destroy(&capacity.lock));
    g_free(root); g_free(gc); g_free(store); g_free(record);
}

static void test_metadata_changes(unsigned mutation)
{
    char *root = g_dir_make_tmp("capacity-gc-change-XXXXXX", NULL);
    char *outside = g_dir_make_tmp("capacity-gc-writer-XXXXXX", NULL);
    char *directory = g_build_filename(root, ".gc", "transactions", NULL);
    char *path = g_build_filename(directory, "record.ini", NULL);
    char *alias = g_build_filename(outside, "alias", NULL);
    char *staging = g_build_filename(directory, "staging", NULL);
    assert(root && outside && !g_mkdir_with_parents(directory, 0700));
    put(path, "initial");
    assert(!chmod(path, 0600));
    int writer = open(path, O_RDWR | O_CLOEXEC);
    assert(writer >= 0 && !chmod(path, 0400));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(capacity.metadata_committed == 7 && latcd_cache_capacity_poll(&capacity));
    latcd_cache_capacity_metadata_bind(&capacity, 100);
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(fd >= 0);
    if (mutation >= 7) {
        LatcdMetadataReservation reservation, duplicate;
        assert(!latcd_cache_capacity_metadata_begin(fd, "record.ini", 8, &reservation));
        assert(latcd_cache_capacity_metadata_begin(fd, "record.ini", 1, &duplicate) < 0);
        put(staging, "new-data");
        assert(!rename(staging, path));
        latcd_cache_capacity_metadata_finish(&reservation, true, false);
        assert(capacity.metadata_committed == 8 && !capacity.metadata_reserved);
        assert(latcd_cache_capacity_poll(&capacity));
        if (mutation == 7) assert(!chmod(path, 0600));
        else assert(!link(path, alias));
    } else if (mutation == 0) assert(pwrite(writer, "changed", 7, 0) == 7);
    else if (mutation == 1) assert(!ftruncate(writer, 4096));
    else if (mutation == 2) assert(!chmod(path, 0600));
    else if (mutation == 3) assert(!link(path, alias));
    else if (mutation == 4) assert(!unlink(path));
    else if (mutation == 5) assert(!rename(path, alias));
    else {
        put(staging, "replacement");
        assert(!rename(staging, path));
    }
    assert(!latcd_cache_capacity_poll(&capacity));
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0) < 0);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    close(fd); close(writer);
    unlink(path); unlink(alias); unlink(staging);
    char *gc = g_build_filename(root, ".gc", NULL);
    assert(!rmdir(directory) && !rmdir(gc) && !rmdir(root) && !rmdir(outside));
    g_free(root); g_free(outside); g_free(directory); g_free(path);
    g_free(alias); g_free(staging); g_free(gc);
}

static void test_metadata_missing_after_install(void)
{
    char *root = g_dir_make_tmp("capacity-gc-missing-XXXXXX", NULL);
    char *directory = g_build_filename(root, ".gc", NULL);
    assert(root && !mkdir(directory, 0700));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 100);
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    LatcdMetadataReservation reservation;
    assert(fd >= 0 && !latcd_cache_capacity_metadata_begin(fd, "missing", 5, &reservation));
    latcd_cache_capacity_metadata_finish(&reservation, true, false);
    assert(!latcd_cache_capacity_poll(&capacity));
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0) < 0);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    close(fd);
    assert(!rmdir(directory) && !rmdir(root));
    g_free(directory); g_free(root);
}

static void test_state(void)
{
    char *root = g_dir_make_tmp("capacity-state-XXXXXX", NULL);
    char *keys = g_build_filename(root, ".tbsets", NULL);
    char *identities = g_build_filename(root, ".identities", NULL);
    char *hex = g_strnfill(64, 'a');
    char *name = g_strconcat(hex, ".current", NULL);
    char *manifest = g_build_filename(root, name, NULL);
    char *key = g_build_filename(keys, "keys", NULL);
    char *identity = g_build_filename(identities, "digest", NULL);
    assert(root && !mkdir(keys, 0700) && !mkdir(identities, 0700));
    put(manifest, "12345"); put(key, "123"); put(identity, "12");
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(capacity.state_committed == 10 && !capacity.committed && !capacity.metadata_committed);
    assert(latcd_cache_capacity_reserve(&capacity, 1, 10, NULL, 0) < 0);
    latcd_cache_capacity_metadata_bind(&capacity, 14);
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int keys_fd = open(keys, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    LatcdMetadataReservation first, second;
    assert(directory >= 0 && keys_fd >= 0);
    assert(latcd_cache_capacity_state_begin(directory, "other", 1, &first) < 0);
    assert(latcd_cache_capacity_state_begin(directory, name, 5, &first) < 0);
    assert(capacity.ready && !capacity.state_reserved && capacity.state_committed == 10);
    assert(!latcd_cache_capacity_state_begin(directory, name, 4, &first));
    assert(capacity.state_reserved == 4);
    assert(latcd_cache_capacity_state_begin(keys_fd, "next", 1, &second) < 0);
    assert(latcd_cache_capacity_scan(&capacity, root, NULL, 0) < 0);
    put(manifest, "1234");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    assert(capacity.state_committed == 9 && !capacity.state_reserved);
    assert(!latcd_cache_capacity_state_begin(keys_fd, "next", 5, &first));
    latcd_cache_capacity_metadata_finish(&first, false, false);
    assert(capacity.state_committed == 9 && !capacity.state_reserved);
    latcd_cache_capacity_metadata_bind(&capacity, 9);
    assert(latcd_cache_capacity_state_begin(directory, name, 1, &first) < 0);
    assert(capacity.ready && capacity.state_committed == 9);
    latcd_cache_capacity_metadata_bind(&capacity, 20);
    assert(!latcd_cache_capacity_state_begin(keys_fd, "partial", 6, &first));
    latcd_cache_capacity_metadata_finish(&first, false, true);
    assert(capacity.state_committed == 15 && !capacity.ready);
    assert(latcd_cache_capacity_state_begin(keys_fd, "blocked", 1, &first) < 0);
    latcd_cache_capacity_close(&capacity);
    assert(!capacity.state_committed && !capacity.state_reserved);
    char *alias = g_build_filename(keys, "alias", NULL);
    assert(!link(manifest, alias));
    assert(latcd_cache_capacity_scan(&capacity, root, NULL, 0) < 0);
    assert(!unlink(alias));
    assert(!symlink("digest", alias));
    assert(latcd_cache_capacity_scan(&capacity, root, NULL, 0) < 0);
    assert(!unlink(alias));
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(capacity.state_committed == 9);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    close(directory); close(keys_fd);
    assert(!unlink(manifest) && !unlink(key) && !unlink(identity));
    assert(!rmdir(keys) && !rmdir(identities) && !rmdir(root));
    g_free(root); g_free(keys); g_free(identities); g_free(hex); g_free(name);
    g_free(manifest); g_free(key); g_free(identity); g_free(alias);
}

static void test_state_changes(unsigned store, unsigned mutation)
{
    char *root = g_dir_make_tmp("capacity-state-change-XXXXXX", NULL);
    char *outside = g_dir_make_tmp("capacity-state-outside-XXXXXX", NULL);
    char *hex = g_strnfill(64, 'c');
    char *name = store ? g_strdup("record") : g_strconcat(hex, ".current", NULL);
    char *directory = store ? g_build_filename(root, store == 1 ? ".tbsets" : ".identities", NULL) : g_strdup(root);
    if (store) assert(!mkdir(directory, 0700));
    char *path = g_build_filename(directory, name, NULL);
    char *staging = g_build_filename(directory, "owned-staging", NULL);
    char *other_name = store ? g_strdup("external") : g_strnfill(64, 'd');
    char *other = store ? g_build_filename(directory, other_name, NULL) :
        g_strdup_printf("%s/%s.current", directory, other_name);
    g_free(other_name);
    char *alias = g_build_filename(outside, "alias", NULL);
    char *moved = g_build_filename(outside, "moved", NULL);
    put(path, "initial");
    assert(!chmod(path, 0600));
    int writer = open(path, O_RDWR | O_CLOEXEC);
    assert(writer >= 0 && !chmod(path, 0400));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(capacity.state_committed == 7 && latcd_cache_capacity_poll(&capacity));
    latcd_cache_capacity_metadata_bind(&capacity, 100);
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(fd >= 0);
    LatcdMetadataReservation reservation;
    if (mutation >= 8) {
        assert(!latcd_cache_capacity_state_begin(fd, name, 8, &reservation));
        assert(!latcd_cache_capacity_state_stage(&reservation, "owned-staging"));
        assert(latcd_cache_capacity_state_stage(&reservation, "second-staging") < 0);
        int staged = open(staging, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
        assert(staged >= 0 && write(staged, "new-data", 8) == 8 && !close(staged));
        assert(!rename(staging, path));
        if (mutation == 9) put(other, "unregistered");
        latcd_cache_capacity_metadata_finish(&reservation, true, false);
        assert(capacity.state_committed == 8 && !capacity.state_reserved);
        if (mutation == 8) {
            if (!capacity.ready) fprintf(stderr, "owned state invalid: store=%u\n", store);
            assert(latcd_cache_capacity_poll(&capacity));
            int new_writer = open(path, O_RDONLY | O_CLOEXEC);
            assert(new_writer >= 0 && !close(new_writer));
            assert(!chmod(path, 0600)); /* Replacement inode remains watched. */
        }
    } else if (mutation == 0) assert(pwrite(writer, "changed", 7, 0) == 7);
    else if (mutation == 1) assert(!ftruncate(writer, 4096));
    else if (mutation == 2) assert(!chmod(path, 0600));
    else if (mutation == 3) assert(!link(path, alias));
    else if (mutation == 4) assert(!unlink(path));
    else if (mutation == 5) assert(!rename(path, moved));
    else if (mutation == 6) {
        put(other, "replacement");
        assert(!rename(other, path));
    } else {
        if (store) put(other, "new-record");
        else assert(!chmod(root, 0755));
    }
    int ready = latcd_cache_capacity_poll(&capacity);
    if (ready) fprintf(stderr, "state change missed: store=%u mutation=%u\n", store, mutation);
    assert(!ready);
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0) < 0);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    close(fd); close(writer);
    unlink(path); unlink(staging); unlink(other); unlink(alias); unlink(moved);
    if (store) assert(!rmdir(directory));
    assert(!rmdir(root) && !rmdir(outside));
    g_free(root); g_free(outside); g_free(hex); g_free(name); g_free(directory);
    g_free(path); g_free(staging); g_free(other); g_free(alias); g_free(moved);
}

int main(void)
{
    test_metadata_missing_after_install();
    for (unsigned mutation = 0; mutation < 9; mutation++)
        test_metadata_changes(mutation);
    for (unsigned store = 0; store < 3; store++)
        for (unsigned mutation = 0; mutation < 10; mutation++)
            test_state_changes(store, mutation);
    test_state();
    test_metadata();
    for (unsigned mutation = 0; mutation < 3; mutation++) test_external_writer(mutation);
    char *root = g_dir_make_tmp("cache-capacity-XXXXXX", NULL), error[256];
    assert(root);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(latcd_cache_capacity_reserve(&capacity, 1, 100, error, sizeof(error)));
    char *source = g_strnfill(64, 'a'), *generation = g_strnfill(64, 'b');
    char *name = g_strdup_printf("%s-%s.so", source, generation);
    char *module = g_build_filename(root, name, NULL);
    char *native_name = g_strconcat(source, ".native", NULL);
    char *native = g_build_filename(root, native_name, NULL);
    char *legacy = g_build_filename(root, ".superseded", NULL);
    char *batch = g_build_filename(legacy, "batch", NULL);
    assert(!g_mkdir_with_parents(batch, 0700));
    char *alias = g_build_filename(batch, "alias", NULL);
    char *old = g_build_filename(batch, "old", NULL);
    put(module, "1234567"); put(native, "12345"); put(old, "123");
    assert(!link(module, alias));
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    const char *expected[] = {name};
    assert(!latcd_cache_capacity_expect(&capacity, expected, 1, error, sizeof(error)));
    assert(!chmod(module, 0600));
    int changed = open(module, O_WRONLY);
    assert(changed >= 0 && pwrite(changed, "1234567", 7, 0) == 7 && !close(changed));
    assert(!chmod(module, 0400));
    latcd_cache_capacity_complete(&capacity, expected, 1);
    assert(capacity.ready);
    assert(!chmod(module, 0600));
    changed = open(module, O_WRONLY);
    assert(changed >= 0 && pwrite(changed, "1234567", 7, 0) == 7 && !close(changed));
    assert(!chmod(module, 0400));
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0));
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    char *legacy_change = g_build_filename(batch, "added", NULL);
    put(legacy_change, "external");
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0));
    assert(!unlink(legacy_change)); g_free(legacy_change);
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    /* Attribute-only changes must invalidate inventory without a content or
     * directory-entry event, including a hardlink outside the watched root. */
    assert(!chmod(module, 0600));
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0));
    assert(!chmod(module, 0400));
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    char *outside = g_dir_make_tmp("capacity-alias-XXXXXX", NULL);
    assert(outside);
    char *external_alias = g_build_filename(outside, "alias", NULL);
    assert(!link(module, external_alias));
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0));
    assert(!unlink(external_alias) && !rmdir(outside));
    g_free(external_alias); g_free(outside);
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    struct timespec stamp[2] = {{.tv_nsec = UTIME_NOW}, {.tv_sec = 1}};
    assert(!utimensat(AT_FDCWD, native, stamp, 0));
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0));
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    assert(!chmod(old, 0600));
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0));
    assert(!chmod(old, 0400));
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    assert(capacity.committed == 15 && !capacity.reserved);
    assert(!latcd_cache_capacity_reserve(&capacity, 4, 20, NULL, 0));
    assert(!latcd_cache_capacity_journal(&capacity, 4, 4, true));
    assert(capacity.journal_reserved == 4 && !capacity.reserved);
    assert(latcd_cache_capacity_reserve_transient(&capacity, 2, 20, NULL, 0));
    assert(!latcd_cache_capacity_reserve_transient(&capacity, 1, 20, NULL, 0));
    latcd_cache_capacity_finish_transient(&capacity, 1, false);
    assert(!latcd_cache_capacity_journal(&capacity, 0, 0, true));
    assert(!latcd_cache_capacity_reserve_transient(&capacity, 4, 20, error, sizeof(error)));
    assert(capacity.transient_reserved == 4);
    assert(latcd_cache_capacity_reserve(&capacity, 2, 20, error, sizeof(error)));
    assert(!latcd_cache_capacity_reserve(&capacity, 1, 20, error, sizeof(error)));
    assert(latcd_cache_capacity_reserve_transient(&capacity, 1, 20, error, sizeof(error)));
    assert(latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_finish(&capacity, 1, false);
    latcd_cache_capacity_finish_transient(&capacity, 4, false);
    assert(capacity.committed == 15 && !capacity.transient_reserved && !capacity.reserved);
    assert(!latcd_cache_capacity_restore_task(&capacity, "task-a", 4));
    assert(!latcd_cache_capacity_restore_task(&capacity, "task-a", 4));
    assert(capacity.recovered_reserved == 4);
    assert(latcd_cache_capacity_reserve(&capacity, 2, 20, NULL, 0));
    assert(!latcd_cache_capacity_reserve_transient(&capacity, 1, 20, NULL, 0));
    latcd_cache_capacity_finish_transient(&capacity, 1, false);
    latcd_cache_capacity_release_task(&capacity, "unknown");
    assert(capacity.recovered_reserved == 4);
    latcd_cache_capacity_release_task(&capacity, "task-a");
    latcd_cache_capacity_release_task(&capacity, "task-a");
    assert(!capacity.recovered_reserved);
    latcd_cache_capacity_unknown_task(&capacity, "legacy");
    latcd_cache_capacity_unknown_task(&capacity, "legacy");
    assert(g_hash_table_size(capacity.unknown_tasks) == 1);
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0));
    assert(latcd_cache_capacity_reserve_transient(&capacity, 1, UINT64_MAX, NULL, 0));
    latcd_cache_capacity_release_task(&capacity, "legacy");
    assert(!g_hash_table_size(capacity.unknown_tasks));
    assert(!latcd_cache_capacity_reserve(&capacity, 5, 20, error, sizeof(error)));
    assert(latcd_cache_capacity_reserve(&capacity, 1, 20, error, sizeof(error)));
    latcd_cache_capacity_finish(&capacity, 5, false);
    assert(capacity.committed == 15 && !capacity.reserved);
    assert(!latcd_cache_capacity_reserve(&capacity, 5, 20, error, sizeof(error)));
    latcd_cache_capacity_finish(&capacity, 5, true);
    assert(capacity.committed == 20 && !capacity.reserved);
    assert(latcd_cache_capacity_reserve(&capacity, UINT64_MAX, UINT64_MAX, error, sizeof(error)));
    assert(!latcd_cache_capacity_reserve(&capacity, UINT64_MAX - 20, UINT64_MAX, NULL, 0));
    assert(latcd_cache_capacity_reserve(&capacity, 1, UINT64_MAX, NULL, 0));
    latcd_cache_capacity_finish(&capacity, UINT64_MAX - 20, true);
    assert(capacity.committed == UINT64_MAX && !capacity.reserved);
    assert(latcd_cache_capacity_reserve(&capacity, 1, UINT64_MAX, NULL, 0));

    assert(!unlink(module) && !symlink("missing", module));
    assert(latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    assert(!capacity.ready && latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0));
    assert(!unlink(module));
    put(module, "1234567");
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    /* The old alias retains its inode and is now a separate physical object. */
    assert(capacity.committed == 22);
    assert(!latcd_cache_capacity_reserve(&capacity, 1, 100, NULL, 0));
    assert(latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_finish(&capacity, 1, false);
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));

    LatcdCacheCapacity empty = LATCD_CACHE_CAPACITY_INIT;
    empty.ready = true;
    pthread_barrier_t start, finish;
    assert(!pthread_barrier_init(&start, NULL, 3) && !pthread_barrier_init(&finish, NULL, 3));
    ReservationRace races[2] = {{&empty, &start, &finish, false}, {&empty, &start, &finish, false}};
    pthread_t threads[2];
    for (unsigned i = 0; i < 2; i++) assert(!pthread_create(&threads[i], NULL, reserve_race, &races[i]));
    pthread_barrier_wait(&start);
    pthread_barrier_wait(&finish);
    for (unsigned i = 0; i < 2; i++) assert(!pthread_join(threads[i], NULL));
    assert(races[0].accepted != races[1].accepted && !empty.reserved);
    assert(!pthread_barrier_destroy(&start) && !pthread_barrier_destroy(&finish));
    latcd_cache_capacity_finish(&empty, 1, true);
    assert(!empty.ready);
    empty.ready = true;
    assert(!latcd_cache_capacity_reserve(&empty, 5, 100, NULL, 0));
    assert(latcd_cache_capacity_journal(&empty, 0, 5, false));
    assert(!empty.ready && empty.reserved == 5);
    assert(!latcd_cache_capacity_journal(&empty, 4, 5, true));
    assert(!empty.ready && !empty.reserved && empty.journal_reserved == 4);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&empty.lock) && !pthread_mutex_destroy(&capacity.lock));
    assert(!unlink(module) && !unlink(native) && !unlink(old) && !unlink(alias));
    assert(!rmdir(batch) && !rmdir(legacy) && !rmdir(root));
    g_free(root); g_free(source); g_free(generation); g_free(name); g_free(module);
    g_free(native_name); g_free(native); g_free(legacy); g_free(batch); g_free(alias); g_free(old);
    puts("test-cache-capacity: scan/dedup/boundary/concurrency/conservative-failure PASS");
    return 0;
}
