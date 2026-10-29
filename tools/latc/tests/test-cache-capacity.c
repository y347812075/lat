#define _GNU_SOURCE
#include "../latcd/cache-capacity.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int remove_fault;
static int race_notify, race_resume;
static void lock_create_pause(void)
{
    char byte = 'x';
    assert(write(race_notify, &byte, 1) == 1);
    assert(read(race_resume, &byte, 1) == 1);
}
int __real_unlinkat(int fd, const char *name, int flags);
int __real_fsync(int fd);
int __wrap_unlinkat(int fd, const char *name, int flags)
{
    if (remove_fault == 1) { errno = EIO; return -1; }
    int result = __real_unlinkat(fd, name, flags);
    if (!result && remove_fault == 3) {
        int unexpected = openat(fd, "unexpected", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        assert(unexpected >= 0 && !close(unexpected));
    }
    return result;
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

static void test_matching_root(void)
{
    char *root = g_dir_make_tmp("capacity-root-XXXXXX", NULL);
    char *other = g_dir_make_tmp("capacity-other-XXXXXX", NULL);
    char *moved = g_strconcat(root, "-moved", NULL);
    assert(root && other && moved);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    int original = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int unrelated = open(other, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int regular = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(original >= 0 && unrelated >= 0 && regular >= 0);
    int match = latcd_cache_capacity_open_matching_root(&capacity, root, original);
    struct stat a, b;
    assert(match >= 0 && !fstat(original, &a) && !fstat(match, &b) &&
           a.st_dev == b.st_dev && a.st_ino == b.st_ino &&
           (fcntl(match, F_GETFD) & FD_CLOEXEC) && !fsync(match));
    int relative = openat(match, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(relative >= 0 && !fstat(relative, &b) && a.st_dev == b.st_dev &&
           a.st_ino == b.st_ino && !close(relative));
    close(match);
    assert(latcd_cache_capacity_open_matching_root(&capacity, root, unrelated) < 0 &&
           errno == ESTALE && latcd_cache_capacity_poll(&capacity));
    assert(latcd_cache_capacity_open_matching_root(&capacity, root, regular) < 0 &&
           errno == ESTALE && latcd_cache_capacity_poll(&capacity));
    assert(!rename(root, moved) && !mkdir(root, 0700));
    assert(latcd_cache_capacity_open_matching_root(&capacity, root, original) < 0 &&
           errno == ESTALE && !latcd_cache_capacity_poll(&capacity));
    close(original); close(unrelated); close(regular);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!rmdir(root) && !rmdir(moved) && !rmdir(other));
    g_free(root); g_free(other); g_free(moved);
}

static void test_recovery_gate(void)
{
    char *root = g_dir_make_tmp("capacity-recovery-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    assert(root && !mkdir(gc, 0700));
    char *record = g_build_filename(gc, "record", NULL);
    put(record, "x");
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(!latcd_cache_capacity_recovery_begin(&capacity));
    assert(latcd_cache_capacity_recovery_begin(&capacity));
    assert(latcd_cache_capacity_scan(&capacity, root, NULL, 0) && errno == EBUSY);
    assert(capacity.recovery_gate && capacity.ready);
    assert(latcd_cache_capacity_reserve(&capacity, 1, 100, NULL, 0));
    assert(latcd_cache_capacity_reserve_transient(&capacity, 1, 100, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 100);
    int fd = open(gc, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    LatcdMetadataReservation reservation;
    assert(fd >= 0 && latcd_cache_capacity_metadata_begin(fd, "record", 1, &reservation));
    assert(latcd_cache_capacity_metadata_recovery_begin(fd, "record", 1, &reservation));
    struct stat existing;
    assert(!stat(record, &existing));
    assert(latcd_cache_capacity_metadata_remove_checked(fd, "record", &existing));
    assert(capacity.ready && capacity.metadata_committed == 1 && !access(record, F_OK));
    uint8_t identity[32] = {1};
    LatcdPageBudget restored = {0}, duplicate = {0};
    assert(latcd_cache_capacity_restore_page(&capacity, 10, 101, identity, &restored));
    assert(!restored.capacity && !capacity.metadata_reserved);
    assert(latcd_cache_capacity_restore_page(&capacity, 100, 100, identity, &restored));
    assert(!latcd_cache_capacity_restore_page(&capacity, 10, 100, identity, &restored));
    assert(restored.page_identity_bound && !memcmp(restored.page_identity, identity, 32));
    assert(latcd_cache_capacity_restore_page(&capacity, 10, 100, identity, &duplicate));
    assert(capacity.metadata_reserved == 10 && !duplicate.capacity);
    latcd_cache_capacity_unknown_task(&capacity, "task");
    assert(latcd_cache_capacity_recovery_finish(&capacity));
    assert(latcd_cache_capacity_reserve(&capacity, 1, 100, NULL, 0));
    assert(!latcd_cache_capacity_restore_task(&capacity, "task", 70));
    assert(!latcd_cache_capacity_recovery_finish(&capacity));
    assert(latcd_cache_capacity_restore_page(&capacity, 1, 100, identity, &duplicate));
    assert(!latcd_cache_capacity_test_page_release(&capacity, &restored));
    assert(latcd_cache_capacity_reserve_page(&capacity, 10, 101, identity, &restored));
    assert(!restored.capacity && !capacity.metadata_reserved);
    assert(!latcd_cache_capacity_reserve_page(&capacity, 10, 100, identity, &restored));
    LatcdPageBudget copied = restored;
    assert(latcd_cache_capacity_page_begin(fd, "record", 1, &copied, &reservation));
    assert(restored.remaining == 10 && copied.remaining == 10 && capacity.metadata_reserved == 10);
    assert(!latcd_cache_capacity_page_begin(fd, "record", 1, &restored, &reservation));
    assert(latcd_cache_capacity_cancel_page(&capacity, &restored));
    latcd_cache_capacity_metadata_finish(&reservation, false, false);
    assert(restored.remaining == 10 && !restored.inflight);
    assert(latcd_cache_capacity_reserve_page(&capacity, 1, 100, identity, &duplicate));
    assert(latcd_cache_capacity_reserve(&capacity, 20, 100, NULL, 0));
    assert(!latcd_cache_capacity_cancel_page(&capacity, &restored));
    assert(!capacity.metadata_reserved && !restored.capacity);
    assert(latcd_cache_capacity_cancel_page(&capacity, &restored));
    assert(latcd_cache_capacity_recovery_finish(&capacity));
    assert(latcd_cache_capacity_reserve(&capacity, 30, 100, NULL, 0));
    assert(!latcd_cache_capacity_reserve(&capacity, 29, 100, NULL, 0));
    latcd_cache_capacity_finish(&capacity, 29, false);
    latcd_cache_capacity_release_task(&capacity, "task");
    assert(!latcd_cache_capacity_recovery_begin(&capacity));
    char *unexpected = g_build_filename(gc, "unexpected", NULL);
    put(unexpected, "x");
    assert(latcd_cache_capacity_recovery_finish(&capacity));
    assert(latcd_cache_capacity_reserve(&capacity, 1, 100, NULL, 0));
    close(fd);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!unlink(unexpected));
    g_free(unexpected);
    assert(!unlink(record));
    g_free(record);
    assert(!rmdir(gc) && !rmdir(root));
    g_free(gc); g_free(root);
}

static void put_metadata(LatcdMetadataReservation *reservation, const char *path,
                         const char *contents)
{
    char *parent = g_path_get_dirname(path);
    char *staging = g_build_filename(parent, ".test-staging", NULL);
    assert(!latcd_cache_capacity_metadata_stage(reservation, ".test-staging"));
    int fd = open(staging, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    size_t size = strlen(contents);
    assert(fd >= 0 && write(fd, contents, size) == (ssize_t)size &&
           !fchmod(fd, 0400) && !close(fd) && !rename(staging, path));
    g_free(staging);
    g_free(parent);
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

static void test_recovery_gate_race(void)
{
    char *root = g_dir_make_tmp("capacity-gate-race-XXXXXX", NULL);
    assert(root);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    for (unsigned i = 0; i < 200; i++) {
        pthread_barrier_t start, finish;
        assert(!pthread_barrier_init(&start, NULL, 2));
        assert(!pthread_barrier_init(&finish, NULL, 2));
        ReservationRace race = { .capacity = &capacity, .start = &start, .finish = &finish };
        pthread_t worker;
        assert(!pthread_create(&worker, NULL, reserve_race, &race));
        pthread_barrier_wait(&start);
        bool closed = !latcd_cache_capacity_recovery_begin(&capacity);
        pthread_barrier_wait(&finish);
        assert(closed != race.accepted);
        assert(!pthread_join(worker, NULL));
        if (closed) assert(!latcd_cache_capacity_recovery_finish(&capacity));
        assert(!pthread_barrier_destroy(&start));
        assert(!pthread_barrier_destroy(&finish));
    }
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!rmdir(root));
    g_free(root);
}

typedef struct PageBudgetRace {
    LatcdCacheCapacity *capacity;
    LatcdPageBudget *budget;
    pthread_barrier_t *start;
    bool accepted;
} PageBudgetRace;

static void *page_budget_race(void *data)
{
    PageBudgetRace *race = data;
    pthread_barrier_wait(race->start);
    race->accepted = !latcd_cache_capacity_test_page_reserve(race->capacity, 10, 100,
                                                              race->budget);
    return NULL;
}

static void *page_budget_compete(void *data)
{
    PageBudgetRace *race = data;
    pthread_barrier_wait(race->start);
    race->accepted = !latcd_cache_capacity_test_page_reserve(race->capacity, 60, 100,
                                                               race->budget);
    return NULL;
}

static void *ordinary_compete(void *data)
{
    PageBudgetRace *race = data;
    pthread_barrier_wait(race->start);
    race->accepted = !latcd_cache_capacity_reserve(race->capacity, 60, 100, NULL, 0);
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
    LatcdPageBudget page_budget = {0};
    assert(!latcd_cache_capacity_test_page_reserve(&capacity, 5, 10, &page_budget));
    assert(page_budget.remaining == 5 && capacity.metadata_reserved == 5);
    char scan_error[128] = {0};
    errno = 0;
    assert(latcd_cache_capacity_scan(&capacity, root, scan_error, sizeof(scan_error)) < 0);
    assert(errno == EBUSY && strstr(scan_error, "outstanding reservations"));
    assert(capacity.ready && capacity.metadata_committed == 5 &&
           capacity.metadata_reserved == 5 && page_budget.capacity == &capacity &&
           page_budget.remaining == 5 && !page_budget.invalid);
    assert(latcd_cache_capacity_metadata_begin(directory, "other.ini", 1, &second) < 0);
    assert(!latcd_cache_capacity_test_page_begin(directory, "record.ini", 3, &page_budget, &first));
    assert(page_budget.remaining == 2 && page_budget.inflight == 1 && capacity.metadata_reserved == 5);
    assert(latcd_cache_capacity_test_page_release(&capacity, &page_budget) < 0);
    assert(latcd_cache_capacity_test_page_begin(directory, "other.ini", 3, &page_budget, &second) < 0);
    latcd_cache_capacity_metadata_finish(&first, false, false);
    assert(page_budget.remaining == 5 && !page_budget.inflight && capacity.metadata_reserved == 5);
    assert(!latcd_cache_capacity_test_page_begin(directory, "record.ini", 3, &page_budget, &first));
    put_metadata(&first, record, "abc");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    assert(page_budget.remaining == 7 && capacity.metadata_reserved == 7 && capacity.metadata_committed == 3);
    assert(!latcd_cache_capacity_test_page_release(&capacity, &page_budget));
    assert(!page_budget.capacity && !capacity.metadata_reserved);
    assert(!latcd_cache_capacity_test_page_reserve(&capacity, 3, 10, &page_budget));
    assert(!latcd_cache_capacity_test_page_begin(directory, "new.ini", 3, &page_budget, &first));
    char *zero_record = g_build_filename(store, "new.ini", NULL);
    put_metadata(&first, zero_record, "abc");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    assert(!page_budget.remaining && !capacity.metadata_reserved && capacity.restored_page_budget);
    assert(latcd_cache_capacity_scan(&capacity, root, scan_error, sizeof(scan_error)) < 0 && errno == EBUSY);
    assert(capacity.ready && capacity.restored_page_budget == &page_budget);
    assert(!latcd_cache_capacity_test_page_release(&capacity, &page_budget));
    struct stat new_stat;
    assert(!stat(zero_record, &new_stat));
    assert(!latcd_cache_capacity_metadata_remove_checked(directory, "new.ini", &new_stat));
    g_free(zero_record);
    assert(!latcd_cache_capacity_journal(&capacity, 4, 0, true));
    errno = 0;
    assert(latcd_cache_capacity_scan(&capacity, root, scan_error, sizeof(scan_error)) < 0);
    assert(errno == EBUSY && capacity.ready && capacity.journal_reserved == 4 &&
           capacity.metadata_committed == 3);
    assert(!latcd_cache_capacity_journal(&capacity, 0, 0, true));
    assert(!latcd_cache_capacity_test_page_reserve(&capacity, 5, 10, &page_budget));
    assert(!latcd_cache_capacity_test_page_begin(directory, "record.ini", 3, &page_budget, &first));
    latcd_cache_capacity_metadata_finish(&first, false, true);
    assert(!capacity.ready && page_budget.remaining == 2 && capacity.metadata_reserved == 2 &&
           capacity.metadata_committed == 6);
    assert(page_budget.invalid);
    assert(latcd_cache_capacity_test_page_release(&capacity, &page_budget) < 0);
    assert(!latcd_cache_capacity_test_page_abandon(&capacity, &page_budget));
    assert(!page_budget.capacity && !capacity.metadata_reserved);
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    assert(!latcd_cache_capacity_test_page_reserve(&capacity, 5, 10, &page_budget));
    assert(!chmod(record, 0600));
    int external = open(record, O_WRONLY | O_CLOEXEC);
    assert(external >= 0 && pwrite(external, "X", 1, 0) == 1 && !close(external));
    assert(!chmod(record, 0400));
    assert(latcd_cache_capacity_test_page_release(&capacity, &page_budget) < 0);
    assert(!capacity.ready && page_budget.remaining == 5 && capacity.metadata_reserved == 5);
    assert(!latcd_cache_capacity_test_page_abandon(&capacity, &page_budget));
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 5, &first));
    put_metadata(&first, record, "12345");
    latcd_cache_capacity_metadata_finish(&first, true, false);
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
    put_metadata(&first, record, "12345");
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
    put_metadata(&first, record, "12345");
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
    put_metadata(&first, record, "12345");
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
    put_metadata(&first, record, "12345");
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
            put_metadata(&first, record, "12345");
            latcd_cache_capacity_metadata_finish(&first, true, false);
        }
    }
    assert(!stat(record, &original));
    struct stat stale = original;
    stale.st_size++;
    assert(latcd_cache_capacity_metadata_remove_checked(directory, "record.ini", &stale) < 0);
    assert(!capacity.ready && capacity.metadata_committed == 5 && !access(record, F_OK));
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    assert(!stat(record, &original));
    stale = original;
    stale.st_blocks++;
    assert(latcd_cache_capacity_metadata_remove_checked(directory, "record.ini", &stale) < 0);
    assert(!capacity.ready && capacity.metadata_committed == 5 && !access(record, F_OK));
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    assert(!stat(record, &original));
    assert(!latcd_cache_capacity_metadata_remove_checked(directory, "record.ini", &original));
    assert(capacity.ready && !capacity.metadata_committed && access(record, F_OK));
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 5, &first));
    put_metadata(&first, record, "12345");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    assert(!stat(record, &original));
    remove_fault = 3;
    assert(latcd_cache_capacity_metadata_remove_checked(directory, "record.ini", &original) < 0);
    remove_fault = 0;
    assert(!capacity.ready && !capacity.metadata_committed && access(record, F_OK));
    assert(!unlinkat(directory, "unexpected", 0));
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 5, &first));
    put_metadata(&first, record, "12345");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    assert(!latcd_cache_capacity_metadata_begin(directory, "record.ini", 3, &first));
    put_metadata(&first, record, "123");
    latcd_cache_capacity_metadata_finish(&first, true, false);
    assert(capacity.metadata_committed == 3 && !capacity.metadata_reserved);
    latcd_cache_capacity_unknown_task(&capacity, "unknown-metadata-budget");
    assert(latcd_cache_capacity_metadata_schedule_begin(directory, "record.ini", 1, &first) < 0);
    assert(latcd_cache_capacity_metadata_begin(directory, "new-unknown", 1, &first) < 0);
    assert(capacity.ready && !capacity.metadata_reserved);
    latcd_cache_capacity_release_task(&capacity, "unknown-metadata-budget");
    assert(!latcd_cache_capacity_metadata_schedule_begin(directory, "record.ini", 1, &first));
    latcd_cache_capacity_metadata_finish(&first, false, false);
    latcd_cache_capacity_unknown_task(&capacity, "unknown-existing-update");
    assert(latcd_cache_capacity_metadata_begin(directory, "record.ini", 1, &first) < 0);
    assert(!latcd_cache_capacity_metadata_recovery_begin(directory, "record.ini", 1, &first));
    assert(!capacity.ready && capacity.metadata_reserved == 1);
    latcd_cache_capacity_metadata_finish(&first, false, false);
    latcd_cache_capacity_release_task(&capacity, "unknown-existing-update");
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, 10);
    latcd_cache_capacity_metadata_bind(&capacity, 3);
    assert(latcd_cache_capacity_metadata_schedule_begin(directory, "record.ini", 4, &first) < 0);
    assert(capacity.ready && capacity.metadata_committed == 3 && !capacity.metadata_reserved);
    assert(!latcd_cache_capacity_metadata_recovery_begin(directory, "record.ini", 4, &first));
    assert(!capacity.ready && capacity.metadata_reserved == 4);
    put_metadata(&first, record, "1234");
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

static void test_metadata_root_replacement(void)
{
    char *root = g_dir_make_tmp("capacity-gc-root-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *old = g_build_filename(root, "old-gc", NULL);
    assert(root && !mkdir(gc, 0700));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(!rename(gc, old) && !mkdir(gc, 0700));
    assert(!latcd_cache_capacity_poll(&capacity));
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0) < 0);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!rmdir(gc) && !rmdir(old) && !rmdir(root));
    g_free(gc); g_free(old); g_free(root);
}

static void test_metadata_subdirectory_replacement(void)
{
    char *root = g_dir_make_tmp("capacity-gc-subdir-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "transactions", NULL);
    char *old = g_build_filename(gc, "old-transactions", NULL);
    assert(root && !g_mkdir_with_parents(store, 0700));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(!rename(store, old) && !mkdir(store, 0700));
    assert(!latcd_cache_capacity_poll(&capacity));
    assert(latcd_cache_capacity_reserve(&capacity, 0, UINT64_MAX, NULL, 0) < 0);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!rmdir(store) && !rmdir(old) && !rmdir(gc) && !rmdir(root));
    g_free(store); g_free(old); g_free(gc); g_free(root);
}

static void test_new_metadata_subdirectory_move(void)
{
    char *root = g_dir_make_tmp("capacity-gc-new-subdir-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "new-store", NULL);
    char *old = g_build_filename(root, "moved-store", NULL);
    assert(root && !mkdir(gc, 0700));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(!mkdir(store, 0700) && !latcd_cache_capacity_poll(&capacity));
    assert(!rename(store, old) && !latcd_cache_capacity_poll(&capacity));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!rmdir(old) && !rmdir(gc) && !rmdir(root));
    g_free(store); g_free(old); g_free(gc); g_free(root);
}

static void test_external_metadata_root_creation(void)
{
    char *root = g_dir_make_tmp("capacity-gc-external-root-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(root && !latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(!mkdir(gc, 0700));
    assert(!latcd_cache_capacity_poll(&capacity));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!rmdir(gc) && !rmdir(root));
    g_free(gc); g_free(root);
}

static void test_controlled_metadata_directory(void)
{
    char *root = g_dir_make_tmp("capacity-gc-controlled-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "store", NULL);
    char *unexpected = g_build_filename(store, "unexpected", NULL);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    assert(root && !latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    int rootfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int gcfd = latcd_cache_capacity_open_metadata_directory(rootfd, ".gc");
    int storefd = latcd_cache_capacity_open_metadata_directory(gcfd, "store");
    assert(rootfd >= 0 && gcfd >= 0 && storefd >= 0);
    assert(latcd_cache_capacity_poll(&capacity));
    assert(latcd_cache_capacity_open_metadata_directory(storefd, "unexpected") < 0);
    assert(errno == ENOENT && latcd_cache_capacity_poll(&capacity));
    assert(access(unexpected, F_OK) < 0 && errno == ENOENT);
    int reopened = latcd_cache_capacity_open_metadata_directory(gcfd, "store");
    assert(reopened >= 0);
    close(reopened);
    assert(latcd_cache_capacity_open_metadata_directory(gcfd, "missing") < 0);
    assert(faccessat(gcfd, "missing", F_OK, 0) < 0 && errno == ENOENT);
    close(storefd); close(gcfd); close(rootfd);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!rmdir(store) && !rmdir(gc) && !rmdir(root));
    g_free(unexpected); g_free(store); g_free(gc); g_free(root);
}

static void test_metadata_subdirectory_moved_in(void)
{
    char *root = g_dir_make_tmp("capacity-gc-move-in-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *outside = g_build_filename(root, "outside", NULL);
    char *store = g_build_filename(gc, "store", NULL);
    char *record = g_build_filename(outside, "record", NULL);
    char *moved_record = g_build_filename(store, "record", NULL);
    assert(root && !mkdir(gc, 0700) && !mkdir(outside, 0700));
    put(record, "unaccounted");
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(!rename(outside, store));
    assert(!latcd_cache_capacity_poll(&capacity));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!unlink(moved_record) && !rmdir(store) && !rmdir(gc) && !rmdir(root));
    g_free(moved_record); g_free(record); g_free(store); g_free(outside);
    g_free(gc); g_free(root);
}

static void test_new_metadata_subdirectory_unaccounted(void)
{
    char *root = g_dir_make_tmp("capacity-gc-unaccounted-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "new-store", NULL);
    char *record = g_build_filename(store, "record", NULL);
    assert(root && !mkdir(gc, 0700));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    assert(!mkdir(store, 0700));
    put(record, "unaccounted");
    assert(!latcd_cache_capacity_poll(&capacity));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!unlink(record) && !rmdir(store) && !rmdir(gc) && !rmdir(root));
    g_free(record); g_free(store); g_free(gc); g_free(root);
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
        assert(!latcd_cache_capacity_metadata_stage(&reservation, "staging"));
        int staged = open(staging, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        assert(staged >= 0 && write(staged, "new-data", 8) == 8 &&
               !fchmod(staged, 0400) && !close(staged));
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

static void test_untracked_metadata_file(unsigned mutation)
{
    char *root = g_dir_make_tmp("capacity-gc-untracked-XXXXXX", NULL);
    char *outside = g_dir_make_tmp("capacity-gc-untracked-outside-XXXXXX", NULL);
    char *directory = g_build_filename(root, ".gc", "transactions", NULL);
    char *path = g_build_filename(directory, "new.ini", NULL);
    char *source = g_build_filename(outside, "source", NULL);
    assert(root && outside && !g_mkdir_with_parents(directory, 0700));
    if (mutation) put(source, "external");
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    if (mutation) assert(!rename(source, path));
    else put(path, "external");
    assert(!latcd_cache_capacity_poll(&capacity));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!unlink(path));
    char *gc = g_build_filename(root, ".gc", NULL);
    assert(!rmdir(directory) && !rmdir(gc) && !rmdir(root) && !rmdir(outside));
    g_free(gc); g_free(source); g_free(path); g_free(directory); g_free(outside); g_free(root);
}

static void test_anonymous_metadata_file(void)
{
    char *root = g_dir_make_tmp("capacity-gc-anonymous-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    assert(root && !mkdir(gc, 0700));
    int directory = open(gc, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(directory >= 0);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    int fd = openat(directory, ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    assert(fd >= 0 && write(fd, "external", 8) == 8 && !fchmod(fd, 0400));
    assert(latcd_cache_capacity_poll(&capacity));
    char proc_fd[64];
    snprintf(proc_fd, sizeof(proc_fd), "/proc/self/fd/%d", fd);
    assert(!linkat(AT_FDCWD, proc_fd, directory, "linked", AT_SYMLINK_FOLLOW));
    assert(!latcd_cache_capacity_poll(&capacity));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!close(fd) && !unlinkat(directory, "linked", 0) && !close(directory));
    assert(!rmdir(gc) && !rmdir(root));
    g_free(gc); g_free(root);
}

static void test_metadata_lock(void)
{
    char *root = g_dir_make_tmp("capacity-gc-lock-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    assert(root && !mkdir(gc, 0700));
    int directory = open(gc, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(directory >= 0);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    int lock = latcd_cache_capacity_open_metadata_lock(directory, "lock");
    assert(lock >= 0 && !close(lock) && latcd_cache_capacity_poll(&capacity));
    latcd_cache_capacity_unknown_task(&capacity, "unknown");
    lock = latcd_cache_capacity_open_metadata_lock(directory, "lock");
    assert(lock >= 0 && !close(lock));
    latcd_cache_capacity_release_task(&capacity, "unknown");
    assert(!unlinkat(directory, "lock", 0));
    lock = openat(directory, "lock", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    assert(lock >= 0 && !close(lock));
    assert(latcd_cache_capacity_open_metadata_lock(directory, "lock") < 0);
    assert(!latcd_cache_capacity_poll(&capacity));
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    remove_fault = 2;
    assert(latcd_cache_capacity_open_metadata_lock(directory, "another") < 0);
    remove_fault = 0;
    assert(!latcd_cache_capacity_poll(&capacity));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!unlinkat(directory, "lock", 0) && !unlinkat(directory, "another", 0));
    assert(!close(directory) && !rmdir(gc) && !rmdir(root));
    g_free(gc); g_free(root);
}

static void test_metadata_lock_external_race(void)
{
    char *root = g_dir_make_tmp("capacity-lock-race-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    assert(root && !mkdir(gc, 0700));
    int directory = open(gc, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(directory >= 0);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    int notify[2], resume[2];
    assert(!pipe(notify) && !pipe(resume));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        char byte;
        if (read(notify[0], &byte, 1) != 1) _exit(1);
        int fd = openat(directory, "lock", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        if (fd < 0 || close(fd) || write(resume[1], "x", 1) != 1) _exit(1);
        _exit(0);
    }
    race_notify = notify[1]; race_resume = resume[0];
    latcd_capacity_test_before_lock_create = lock_create_pause;
    assert(latcd_cache_capacity_open_metadata_lock(directory, "lock") < 0);
    latcd_capacity_test_before_lock_create = NULL;
    assert(!latcd_cache_capacity_poll(&capacity));
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    close(notify[0]); close(notify[1]); close(resume[0]); close(resume[1]);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!unlinkat(directory, "lock", 0) && !close(directory));
    assert(!rmdir(gc) && !rmdir(root));
    g_free(gc); g_free(root);
}

static void test_metadata_lock_replaced_before_watch(void)
{
    char *root = g_dir_make_tmp("capacity-lock-replace-XXXXXX", NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    assert(root && !mkdir(gc, 0700));
    int directory = open(gc, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(directory >= 0);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, NULL, 0));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    int notify[2], resume[2];
    assert(!pipe(notify) && !pipe(resume));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        char byte;
        if (read(notify[0], &byte, 1) != 1 || unlinkat(directory, "lock", 0)) _exit(1);
        int fd = openat(directory, "lock", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        if (fd < 0 || close(fd) || write(resume[1], "x", 1) != 1) _exit(1);
        _exit(0);
    }
    race_notify = notify[1]; race_resume = resume[0];
    latcd_capacity_test_before_lock_finish = lock_create_pause;
    assert(latcd_cache_capacity_open_metadata_lock(directory, "lock") < 0);
    latcd_capacity_test_before_lock_finish = NULL;
    assert(!latcd_cache_capacity_poll(&capacity));
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    close(notify[0]); close(notify[1]); close(resume[0]); close(resume[1]);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!unlinkat(directory, "lock", 0) && !close(directory));
    assert(!rmdir(gc) && !rmdir(root));
    g_free(gc); g_free(root);
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
    uint64_t peak = 99;
    assert(!latcd_cache_capacity_page_peak(2, 2, 1024, 65536, &peak) && peak == 133120);
    assert(!latcd_cache_capacity_page_peak(0, 0, 1024, 512, &peak) && peak == 1536);
    assert(latcd_cache_capacity_page_peak(2, 1, 1024, 512, &peak) < 0 && errno == ENOSPC && !peak);
    assert(latcd_cache_capacity_page_peak(UINT64_MAX, UINT64_MAX, 2, 1, &peak) < 0 && errno == EOVERFLOW && !peak);
    assert(latcd_cache_capacity_page_peak(0, 0, 1, UINT64_MAX, &peak) < 0 && errno == EOVERFLOW && !peak);
    assert(latcd_cache_capacity_page_peak(1, 1, 0, 1, &peak) < 0 && errno == EINVAL);
    assert(latcd_cache_capacity_page_peak(1, 1, 1, 1, NULL) < 0 && errno == EINVAL);
    test_matching_root();
    test_recovery_gate();
    test_recovery_gate_race();
    test_external_metadata_root_creation();
    test_controlled_metadata_directory();
    test_metadata_subdirectory_moved_in();
    test_new_metadata_subdirectory_unaccounted();
    test_metadata_missing_after_install();
    test_untracked_metadata_file(0);
    test_untracked_metadata_file(1);
    test_anonymous_metadata_file();
    test_metadata_lock();
    test_metadata_lock_external_race();
    test_metadata_lock_replaced_before_watch();
    for (unsigned mutation = 0; mutation < 9; mutation++)
        test_metadata_changes(mutation);
    for (unsigned store = 0; store < 3; store++)
        for (unsigned mutation = 0; mutation < 10; mutation++)
            test_state_changes(store, mutation);
    test_state();
    test_metadata();
    test_metadata_root_replacement();
    test_metadata_subdirectory_replacement();
    test_new_metadata_subdirectory_move();
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
    assert(!latcd_cache_capacity_task_restored(&capacity, "task-a"));
    assert(!latcd_cache_capacity_restore_task(&capacity, "task-a", 4));
    assert(latcd_cache_capacity_task_restored(&capacity, "task-a"));
    assert(!latcd_cache_capacity_task_restored(&capacity, "task-b"));
    assert(!latcd_cache_capacity_restore_task(&capacity, "task-a", 4));
    assert(capacity.recovered_reserved == 4);
    assert(latcd_cache_capacity_reserve(&capacity, 2, 20, NULL, 0));
    assert(!latcd_cache_capacity_reserve_transient(&capacity, 1, 20, NULL, 0));
    latcd_cache_capacity_finish_transient(&capacity, 1, false);
    latcd_cache_capacity_release_task(&capacity, "unknown");
    assert(capacity.recovered_reserved == 4);
    latcd_cache_capacity_release_task(&capacity, "task-a");
    latcd_cache_capacity_release_task(&capacity, "task-a");
    assert(!latcd_cache_capacity_task_restored(&capacity, "task-a"));
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
    LatcdPageBudget shared_budget = {0};
    pthread_barrier_t page_start;
    assert(!pthread_barrier_init(&page_start, NULL, 3));
    PageBudgetRace page_races[2] = {{&empty, &shared_budget, &page_start, false},
                                     {&empty, &shared_budget, &page_start, false}};
    pthread_t page_threads[2];
    for (unsigned i = 0; i < 2; i++)
        assert(!pthread_create(&page_threads[i], NULL, page_budget_race, &page_races[i]));
    pthread_barrier_wait(&page_start);
    for (unsigned i = 0; i < 2; i++) assert(!pthread_join(page_threads[i], NULL));
    assert(page_races[0].accepted != page_races[1].accepted && empty.metadata_reserved == 10);
    assert(!latcd_cache_capacity_test_page_release(&empty, &shared_budget));
    assert(!empty.metadata_reserved && !pthread_barrier_destroy(&page_start));
    assert(!pthread_barrier_init(&page_start, NULL, 3));
    PageBudgetRace competing[2] = {{&empty, &shared_budget, &page_start, false},
                                  {&empty, &shared_budget, &page_start, false}};
    assert(!pthread_create(&page_threads[0], NULL, page_budget_compete, &competing[0]));
    assert(!pthread_create(&page_threads[1], NULL, ordinary_compete, &competing[1]));
    pthread_barrier_wait(&page_start);
    for (unsigned i = 0; i < 2; i++) assert(!pthread_join(page_threads[i], NULL));
    assert(competing[0].accepted != competing[1].accepted);
    assert(empty.metadata_reserved + empty.reserved == 60);
    if (competing[0].accepted) assert(!latcd_cache_capacity_test_page_release(&empty, &shared_budget));
    if (competing[1].accepted) latcd_cache_capacity_finish(&empty, 60, false);
    assert(!empty.metadata_reserved && !empty.reserved && !pthread_barrier_destroy(&page_start));
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
