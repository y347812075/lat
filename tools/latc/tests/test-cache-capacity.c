#define _GNU_SOURCE
#include "../latcd/cache-capacity.h"

#include <assert.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

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

int main(void)
{
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
