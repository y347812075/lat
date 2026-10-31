#define _GNU_SOURCE
#include "../latcd/cache-retirement.h"
#include "../latcd/cache-capacity.h"
#include "../aot-v2/runtime/cache-domain.h"
#include "../aot-v2/runtime/cache-lifecycle.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned clock_fault;
static int consumption_io_fault;
static bool consumption_unlinked;
static bool retry_sync_fault;
static dev_t retry_sync_device;
static ino_t retry_sync_inode;
static const char *sync_swap_path, *sync_swap_saved;
int __real_unlinkat(int fd, const char *name, int flags);
int __real_fsync(int fd);
int __wrap_unlinkat(int fd, const char *name, int flags)
{
    if (consumption_io_fault == 1) { errno = EIO; return -1; }
    int result = __real_unlinkat(fd, name, flags);
    if (!result && consumption_io_fault == 2) consumption_unlinked = true;
    return result;
}
int __wrap_fsync(int fd)
{
    struct stat st;
    if (sync_swap_path && !fstat(fd, &st) && st.st_dev == retry_sync_device &&
        st.st_ino == retry_sync_inode) {
        assert(!rename(sync_swap_path, sync_swap_saved));
        assert(!mkdir(sync_swap_path, 0700));
        sync_swap_path = NULL;
    }
    if (retry_sync_fault && !fstat(fd, &st) && st.st_dev == retry_sync_device &&
        st.st_ino == retry_sync_inode) { errno = EIO; return -1; }
    if (consumption_io_fault == 2 && consumption_unlinked) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
static int64_t monotonic_tick;
static uint64_t simulated_boottime_us;
static const char *clock_swap_path, *clock_swap_old;
static const char *lock_swap_root, *lock_swap_old, *lock_swap_new;
static bool lock_swap_after;
static const char *lock_wrong_root;
static const char *schedule_scan_mutation;
static bool retry_scan_hook_called, retry_scan_change, retry_scan_hold;
static int retry_scan_held_fd = -1;
static const char *retry_scan_receipt_path, *retry_scan_receipt_data;
static void put(const char *path, const char *contents);
static void retry_scan_hook(const char *root)
{
    int fd = latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, NULL, 0);
    assert(fd >= 0);
    retry_scan_hook_called = true;
    if (retry_scan_change) {
        char *path = g_build_filename(root, ".gc", "transactions", ".retry-change", NULL);
        int changed = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        assert(changed >= 0);
        close(changed);
        assert(!unlink(path));
        g_free(path);
    }
    if (retry_scan_receipt_path) put(retry_scan_receipt_path, retry_scan_receipt_data);
    if (retry_scan_hold) retry_scan_held_fd = fd;
    else close(fd);
}
static const char *schedule_mutation_file;
static const char *snapshot_swap_store, *snapshot_swap_gc, *snapshot_swap_old;
static const char *roots_swap_path, *roots_swap_old;
static const char *page_lstat_swap_path, *page_lstat_swap_old, *page_lstat_swap_new;
static const char *scheduler_swap_root, *scheduler_swap_gc, *scheduler_swap_old;
static bool scheduler_swap_after_binding;
static const char *settlement_unexpected;
static const char *settlement_target, *settlement_saved;
static const char *read_target, *read_saved, *read_replacement;
static void replace_read_target(void)
{
    assert(!rename(read_target, read_saved));
    assert(!rename(read_replacement, read_target));
    latcd_retirement_test_after_read = NULL;
}
static void fail_page_finish(LatcdPageBudget *budget)
{
    budget->invalid = true;
    latcd_retirement_test_before_page_finish = NULL;
}
static void replace_settlement_target(void)
{
    assert(!rename(settlement_target, settlement_saved));
    int fd = open(settlement_target, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
    assert(fd >= 0 && write(fd, "x", 1) == 1 && !close(fd));
    latcd_retirement_test_before_settlement = NULL;
}
static void replace_before_target_revalidate(void)
{
    assert(!rename(settlement_target, settlement_saved));
    int fd = open(settlement_target, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
    assert(fd >= 0 && write(fd, "x", 1) == 1 && !close(fd));
    latcd_retirement_test_before_target_revalidate = NULL;
}
static void invalidate_settlement(void)
{
    int fd = open(settlement_unexpected, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0 && !close(fd));
    latcd_retirement_test_before_settlement = NULL;
}
int __real_fstatat(int directory, const char *name, struct stat *status, int flags);
int __wrap_fstatat(int directory, const char *name, struct stat *status, int flags)
{
    int result = __real_fstatat(directory, name, status, flags);
    if (!result && scheduler_swap_after_binding && !strcmp(name, ".gc")) {
        assert(!rename(scheduler_swap_gc, scheduler_swap_old));
        assert(!mkdir(scheduler_swap_gc, 0700));
        scheduler_swap_after_binding = false;
    }
    return result;
}
int __real_lstat(const char *path, struct stat *status);
int __wrap_lstat(const char *path, struct stat *status)
{
    int result = __real_lstat(path, status);
    if (!result && scheduler_swap_root && !strcmp(path, scheduler_swap_root)) {
        assert(!rename(scheduler_swap_gc, scheduler_swap_old));
        assert(!mkdir(scheduler_swap_gc, 0700));
        scheduler_swap_root = NULL;
    }
    if (!result && page_lstat_swap_path && !strcmp(path, page_lstat_swap_path)) {
        assert(!rename(page_lstat_swap_path, page_lstat_swap_old));
        assert(!rename(page_lstat_swap_new, page_lstat_swap_path));
        page_lstat_swap_path = NULL;
    }
    return result;
}
int __real_lat_aot_v2_cache_lock_fd(int fd, int operation, char *error, size_t error_size);
int __wrap_lat_aot_v2_cache_lock_fd(int fd, int operation, char *error, size_t error_size)
{
    int result = __real_lat_aot_v2_cache_lock_fd(fd, operation, error, error_size);
    if (!result && roots_swap_path && operation == (LOCK_SH | LOCK_NB)) {
        assert(!rename(roots_swap_path, roots_swap_old));
        assert(!mkdir(roots_swap_path, 0700));
        roots_swap_path = NULL;
    }
    return result;
}
struct dirent *__real_readdir(DIR *directory);
struct dirent *__wrap_readdir(DIR *directory)
{
    struct dirent *entry = __real_readdir(directory);
    if (!entry && snapshot_swap_store) {
        struct stat held, target;
        if (!fstat(dirfd(directory), &held) && !stat(snapshot_swap_store, &target) &&
            held.st_dev == target.st_dev && held.st_ino == target.st_ino) {
            assert(!rename(snapshot_swap_gc, snapshot_swap_old));
            assert(!mkdir(snapshot_swap_gc, 0700));
            snapshot_swap_store = NULL;
        }
    }
    if (!entry && schedule_scan_mutation) {
        struct stat held, target;
        if (!fstat(dirfd(directory), &held) && !stat(schedule_scan_mutation, &target) &&
            held.st_dev == target.st_dev && held.st_ino == target.st_ino) {
            if (schedule_mutation_file) {
                assert(!chmod(schedule_mutation_file, 0600));
                int fd = open(schedule_mutation_file, O_WRONLY);
                assert(fd >= 0 && pwrite(fd, "X", 1, 0) == 1);
                assert(!fchmod(fd, 0400));
                close(fd);
                schedule_mutation_file = NULL;
            } else {
                int fd = openat(dirfd(directory), ".test-mutation", O_CREAT | O_EXCL | O_WRONLY, 0600);
                assert(fd >= 0);
                close(fd);
                assert(!unlinkat(dirfd(directory), ".test-mutation", 0));
            }
            schedule_scan_mutation = NULL;
        }
    }
    return entry;
}
int __real_lat_aot_v2_cache_source_lock(const char *, const char *, int, bool, char *, size_t);
int __wrap_lat_aot_v2_cache_source_lock(const char *root, const char *source_hex,
    int operation, bool protect, char *error, size_t error_size)
{
    if (lock_swap_root && !lock_swap_after) {
        assert(!strcmp(root, lock_swap_root));
        assert(!rename(lock_swap_root, lock_swap_old));
        assert(!rename(lock_swap_new, lock_swap_root));
        lock_swap_root = NULL;
    }
    int fd = __real_lat_aot_v2_cache_source_lock(root, source_hex, operation, protect,
                                                 error, error_size);
    if (fd >= 0 && lock_wrong_root) {
        int wrong = __real_lat_aot_v2_cache_source_lock(lock_wrong_root, source_hex,
            operation, protect, error, error_size);
        assert(wrong >= 0);
        close(fd);
        fd = wrong;
        lock_wrong_root = NULL;
    }
    if (fd >= 0 && lock_swap_root && lock_swap_after) {
        assert(!strcmp(root, lock_swap_root));
        assert(!rename(lock_swap_root, lock_swap_old));
        assert(!rename(lock_swap_new, lock_swap_root));
        lock_swap_root = NULL;
        lock_swap_after = false;
    }
    return fd;
}
int __real_clock_gettime(clockid_t id, struct timespec *value);
gint64 __real_g_get_monotonic_time(void);
gboolean __real_g_file_get_contents(const gchar *name, gchar **contents,
                                   gsize *length, GError **error);

gint64 __wrap_g_get_monotonic_time(void)
{
    if (monotonic_tick) return monotonic_tick += 2000000;
    return __real_g_get_monotonic_time();
}

int __wrap_clock_gettime(clockid_t id, struct timespec *value)
{
    if (id == CLOCK_BOOTTIME && clock_swap_path) {
        assert(!rename(clock_swap_path, clock_swap_old));
        assert(!mkdir(clock_swap_path, 0700));
        clock_swap_path = NULL;
    }
    if (id == CLOCK_BOOTTIME && simulated_boottime_us && !clock_fault) {
        value->tv_sec = simulated_boottime_us / 1000000;
        value->tv_nsec = (simulated_boottime_us % 1000000) * 1000;
        return 0;
    }
    if (id == CLOCK_BOOTTIME && clock_fault && clock_fault <= 5) {
        if (clock_fault == 1) { errno = EIO; return -1; }
        *value = (struct timespec){ .tv_sec = 1 };
        if (clock_fault == 2) value->tv_sec = -1;
        if (clock_fault == 3) value->tv_sec = INT64_MAX;
        if (clock_fault == 4) value->tv_nsec = -1;
        if (clock_fault == 5) value->tv_nsec = 1000000000;
        return 0;
    }
    return __real_clock_gettime(id, value);
}

gboolean __wrap_g_file_get_contents(const gchar *name, gchar **contents,
                                   gsize *length, GError **error)
{
    if (clock_fault >= 6 && !strcmp(name, "/proc/sys/kernel/random/boot_id")) {
        if (clock_fault == 6) return FALSE;
        const char raw[] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\0hidden";
        size_t size = clock_fault == 7 ? 3 : sizeof(raw) - 1;
        *contents = g_malloc(size + 1);
        memcpy(*contents, raw, size);
        (*contents)[size] = 0;
        if (length) *length = size;
        return TRUE;
    }
    return __real_g_file_get_contents(name, contents, length, error);
}

static const char source[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char old[] = "old manifest\n";
static const char next[] = "next manifest\n";

static void put(const char *path, const char *contents)
{
    char *temporary = g_strconcat(path, ".new", NULL);
    assert(g_file_set_contents(temporary, contents, -1, NULL));
    assert(!chmod(temporary, 0400));
    int fd = open(temporary, O_RDONLY);
    assert(fd >= 0 && !fsync(fd));
    close(fd);
    assert(!rename(temporary, path));
    g_free(temporary);
}

static char *root_new(void)
{
    GError *error = NULL;
    char *root = g_dir_make_tmp("cache-retirement-XXXXXX", &error);
    assert(root && !error);
    return root;
}

static char *current_path(const char *root)
{
    return g_strdup_printf("%s/%s.current", root, source);
}

static char *single_record(const char *root)
{
    char *directory = g_build_filename(root, ".gc", "transactions", NULL);
    GDir *dir = g_dir_open(directory, 0, NULL);
    assert(dir);
    const char *name = g_dir_read_name(dir);
    assert(name);
    char *path = g_build_filename(directory, name, NULL);
    assert(!g_dir_read_name(dir));
    g_dir_close(dir);
    g_free(directory);
    return path;
}

static void assert_state(const char *root, const char *expected)
{
    char *path = single_record(root);
    GKeyFile *record = g_key_file_new();
    assert(g_key_file_load_from_file(record, path, 0, NULL));
    char *state = g_key_file_get_string(record, "transaction", "state", NULL);
    assert(state && !strcmp(state, expected));
    g_free(state);
    g_key_file_unref(record);
    g_free(path);
}

static void remove_root(const char *root)
{
    char *quoted = g_shell_quote(root);
    char *command = g_strconcat("rm -rf -- ", quoted, NULL);
    int status;
    assert(g_spawn_command_line_sync(command, NULL, NULL, &status, NULL));
    assert(status == 0);
    g_free(command);
    g_free(quoted);
}

static void test_crash(int phase, bool initial)
{
    char *root = root_new();
    char *current = current_path(root);
    if (initial) put(current, old);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        char error[256];
        LatcdRetirementPublication *publication =
            latcd_retirement_publication_open(root, error, sizeof(error));
        assert(publication);
        assert(!latcd_retirement_publication_prepare(publication, source, next, strlen(next), NULL,
                                                     error, sizeof(error)));
        if (phase >= 1) put(current, next);
        if (phase >= 2) assert(!latcd_retirement_publication_finish(publication,
                                                                   error, sizeof(error)));
        raise(SIGKILL);
        _exit(1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    unsigned recovered;
    char error[256];
    assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
    assert(recovered == 1);
    assert_state(root, phase ? "RETIRED" : "ABORTED");
    assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
    assert_state(root, phase ? "RETIRED" : "ABORTED");
    char *contents = NULL;
    if (phase || initial) {
        assert(g_file_get_contents(current, &contents, NULL, NULL));
        assert(!strcmp(contents, phase ? next : old));
    } else assert(access(current, F_OK));
    g_free(contents);
    remove_root(root);
    g_free(root);
    g_free(current);
}

static void test_recovery_capacity_admission(int outcome)
{
    char *root = root_new(), *current = current_path(root), error[256];
    put(current, old);
    LatcdRetirementPublication *publication =
        latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication && !latcd_retirement_publication_prepare(publication,
        source, next, strlen(next), NULL, error, sizeof(error)));
    latcd_retirement_publication_close(publication);
    if (outcome == 0) put(current, next);
    if (outcome == 2) put(current, "unexpected manifest\n");
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    latcd_cache_capacity_unknown_task(&capacity, "recovery-admission-test");
    unsigned recovered = 0;
    int result = latcd_retirement_recover(root, &recovered, error, sizeof(error));
    if (outcome == 0) {
        assert(!result && recovered == 1);
        assert_state(root, "RETIRED");
        assert(!latcd_cache_capacity_poll(&capacity));
    } else {
        assert(result < 0);
        assert_state(root, "PREPARED");
    }
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    remove_root(root);
    g_free(current);
    g_free(root);
}

static void test_metadata_target_revalidation(bool existing)
{
    char *root = root_new(), *gc = g_build_filename(root, ".gc", NULL);
    char *path = g_build_filename(gc, "target.ini", NULL), error[256];
    assert(!mkdir(gc, 0700));
    if (existing) put(path, "original\n");
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    int dir = open(gc, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(dir >= 0);
    LatcdMetadataReservation reservation;
    assert(!latcd_cache_capacity_metadata_begin(dir, "target.ini", 128, &reservation));
    assert(!latcd_cache_capacity_metadata_revalidate(&reservation));
    if (existing) assert(!unlink(path));
    put(path, "replacement\n");
    assert(latcd_cache_capacity_metadata_revalidate(&reservation) < 0 && errno == ESTALE);
    latcd_cache_capacity_metadata_finish(&reservation, false, false);
    assert(!latcd_cache_capacity_poll(&capacity));
    char *contents = NULL;
    assert(g_file_get_contents(path, &contents, NULL, NULL) && !strcmp(contents, "replacement\n"));
    g_free(contents);
    close(dir);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    g_free(path); g_free(gc); remove_root(root); g_free(root);
}

static void test_oversized_prepared(void)
{
    char *root = root_new(), error[256];
    char *objects = g_strnfill(65536, 'x');
    LatcdRetirementPublication *publication =
        latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication);
    assert(latcd_retirement_publication_prepare(publication, source, next, strlen(next),
                                                 objects, error, sizeof(error)) < 0);
    g_free(objects);
    objects = g_strnfill(48700, 'x');
    assert(latcd_retirement_publication_prepare(publication, source, next, strlen(next),
                                                 objects, error, sizeof(error)) < 0);
    latcd_retirement_publication_close(publication);
    unsigned recovered = 99;
    assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)) && !recovered);
    g_free(objects); remove_root(root); g_free(root);
}

static void test_unknown_and_corrupt(void)
{
    char *root = root_new(), error[256];
    char *current = current_path(root);
    put(current, old);
    LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication && !latcd_retirement_publication_prepare(publication, source, next, strlen(next),
                                                                 NULL, error, sizeof(error)));
    put(current, "unrecognized current\n");
    latcd_retirement_publication_close(publication);
    unsigned recovered;
    assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
    assert_state(root, "UNKNOWN");
    char *path = single_record(root);
    put(path, "[transaction]\nversion=1\nversion=2\n");
    assert(latcd_retirement_recover(root, &recovered, error, sizeof(error)));
    assert(!unlink(path));
    assert(!symlink(current, path));
    assert(latcd_retirement_recover(root, &recovered, error, sizeof(error)));
    remove_root(root);
    g_free(path);
    g_free(current);
    g_free(root);
}

static void test_reboot(void)
{
    char *root = root_new(), error[256];
    char *current = current_path(root);
    LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication && !latcd_retirement_publication_prepare(publication, source, next, strlen(next),
                                                                 NULL, error, sizeof(error)));
    put(current, next);
    assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
    latcd_retirement_publication_close(publication);
    char *path = single_record(root);
    GKeyFile *record = g_key_file_new();
    assert(g_key_file_load_from_file(record, path, 0, NULL));
    g_key_file_set_string(record, "transaction", "retired_boot", "previous-boot");
    g_key_file_set_uint64(record, "transaction", "retired_boottime_us", 1);
    char *data = g_key_file_to_data(record, NULL, NULL);
    put(path, data);
    g_free(data);
    unsigned recovered;
    assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
    assert(g_key_file_load_from_file(record, path, 0, NULL));
    guint64 time = g_key_file_get_uint64(record, "transaction", "retired_boottime_us", NULL);
    assert(time > 1);
    assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
    assert(g_key_file_load_from_file(record, path, 0, NULL));
    assert(time == g_key_file_get_uint64(record, "transaction", "retired_boottime_us", NULL));
    g_key_file_unref(record);
    remove_root(root);
    g_free(path);
    g_free(current);
    g_free(root);
}

static void test_clock_failure(unsigned phase, unsigned fault)
{
    char *root = root_new(), error[256];
    char *current = current_path(root), *path = NULL, *before = NULL;
    LatcdRetirementPublication *publication =
        latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication);
    if (phase) {
        assert(!latcd_retirement_publication_prepare(publication, source, next, strlen(next), NULL,
                                                     error, sizeof(error)));
        put(current, next);
        path = single_record(root);
        if (phase == 2) {
            assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
            latcd_retirement_publication_close(publication);
            publication = NULL;
            GKeyFile *record = g_key_file_new();
            assert(g_key_file_load_from_file(record, path, 0, NULL));
            g_key_file_set_string(record, "transaction", "retired_boot",
                                   "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
            char *data = g_key_file_to_data(record, NULL, NULL);
            put(path, data);
            g_free(data); g_key_file_unref(record);
        }
        assert(g_file_get_contents(path, &before, NULL, NULL));
    }
    clock_fault = fault;
    unsigned recovered;
    int result = phase == 0 ? latcd_retirement_publication_prepare(publication, source, next,
        strlen(next), NULL, error, sizeof(error)) : phase == 1 ?
        latcd_retirement_publication_finish(publication, error, sizeof(error)) :
        latcd_retirement_recover(root, &recovered, error, sizeof(error));
    clock_fault = 0;
    if (publication) latcd_retirement_publication_close(publication);
    if (result >= 0) fprintf(stderr, "clock fault accepted phase=%u fault=%u\n", phase, fault);
    assert(result < 0);
    if (!phase) {
        char *store = g_build_filename(root, ".gc", "transactions", NULL);
        GDir *directory = g_dir_open(store, 0, NULL);
        assert(directory && !g_dir_read_name(directory));
        g_dir_close(directory);
        g_free(store);
    }
    else {
        char *after;
        assert(g_file_get_contents(path, &after, NULL, NULL) && !strcmp(before, after));
        g_free(after);
        assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
        assert_state(root, "RETIRED");
    }
    remove_root(root);
    g_free(before); g_free(path); g_free(current); g_free(root);
}

static void test_record_write_fault(const char *point, bool crash,
                                    bool finishing, bool initial)
{
    char *root = root_new(), *current = current_path(root);
    char error[256];
    if (initial) put(current, old);
    LatcdRetirementPublication *publication =
        latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication);
    if (finishing) {
        assert(!latcd_retirement_publication_prepare(publication, source, next, strlen(next), NULL,
                                                     error, sizeof(error)));
        put(current, next);
    }
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        char *setting = g_strdup_printf("%s:%s", crash ? "crash" : "error", point);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", setting, 1));
        int result = finishing ?
            latcd_retirement_publication_finish(publication, error, sizeof(error)) :
            latcd_retirement_publication_prepare(publication, source, next, strlen(next), NULL,
                                                 error, sizeof(error));
        assert(!crash && result < 0);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    if (crash) assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    else assert(WIFEXITED(status) && !WEXITSTATUS(status));
    latcd_retirement_publication_close(publication);

    bool renamed = !strcmp(point, "renamed") || !strcmp(point, "directory-synced");
    unsigned expected = finishing || renamed;
    char *store = g_build_filename(root, ".gc", "transactions", NULL);
    GDir *directory = g_dir_open(store, 0, NULL);
    assert(directory);
    const char *name;
    unsigned records = 0, temporaries = 0;
    char *record_path = NULL;
    while ((name = g_dir_read_name(directory))) {
        if (g_str_has_prefix(name, ".write-")) temporaries++;
        else {
            records++;
            g_free(record_path);
            record_path = g_build_filename(store, name, NULL);
        }
    }
    g_dir_close(directory);
    assert(records == expected);
    assert(temporaries == (unsigned)(crash && !renamed));
    /* Until rename, the previous complete record must remain byte-valid. */
    GKeyFile *record = g_key_file_new();
    if (expected) {
        assert(g_key_file_load_from_file(record, record_path, 0, NULL));
        char *state = g_key_file_get_string(record, "transaction", "state", NULL);
        assert(!strcmp(state, finishing && renamed ? "RETIRED" : "PREPARED"));
        g_free(state);
    }
    for (int pass = 0; pass < 2; pass++) {
        unsigned recovered;
        int recovery = latcd_retirement_recover(root, &recovered, error, sizeof(error));
        if (recovery) fprintf(stderr, "recovery %s crash=%d finish=%d initial=%d pass=%d: %s root=%s\n",
            point, crash, finishing, initial, pass, error, root);
        assert(!recovery);
        assert(recovered == expected);
        if (expected) {
            assert(g_key_file_load_from_file(record, record_path, 0, NULL));
            char *state = g_key_file_get_string(record, "transaction", "state", NULL);
            assert(!strcmp(state, finishing ? "RETIRED" : "ABORTED"));
            g_free(state);
        }
        char *contents = NULL;
        if (finishing || initial) {
            assert(g_file_get_contents(current, &contents, NULL, NULL));
            assert(!strcmp(contents, finishing ? next : old));
        } else assert(access(current, F_OK));
        g_free(contents);
    }
    g_key_file_unref(record);
    g_free(record_path);
    g_free(store);
    g_free(current);
    remove_root(root);
    g_free(root);
}

static void test_object_identity(int mutation)
{
    char *root = root_new(), *current = current_path(root);
    char *name = g_strconcat(source, ".native", NULL);
    char *path = g_build_filename(root, name, NULL);
    put(path, "immutable native\n");
    const char *names[] = {name};
    char *objects = latcd_retirement_capture_objects(root, source, names, 1);
    assert(objects);
    char *manifest = g_strdup_printf("{\"version\":2,\"source_sha256\":\"%s\","
        "\"codegen_id\":\"%s\",\"module\":\"%s.so\",\"native\":\"%s.native\","
        "\"tbset\":\"\",\"published_sequence\":1}", source, source, source, source);
    char *module_name = g_strconcat(source, ".so", NULL);
    char *module_path = g_build_filename(root, module_name, NULL);
    put(module_path, "immutable module\n");
    const char *complete_names[] = {name, module_name};
    g_free(objects);
    objects = latcd_retirement_capture_objects(root, source, complete_names, 2);
    assert(objects);
    char error[256];
    LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication && !latcd_retirement_publication_prepare(publication, source, manifest,
                                                                strlen(manifest), objects, error, sizeof(error)));
    put(current, manifest);
    assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
    latcd_retirement_publication_close(publication);
    assert_state(root, "RETIRED");
    if (mutation == 1) {
        put(path, "immutable native\n"); /* Same bytes, different inode. */
    } else if (mutation == 2) {
        assert(!chmod(path, 0600));
        int fd = open(path, O_WRONLY);
        assert(fd >= 0 && pwrite(fd, "X", 1, 0) == 1 && !fsync(fd));
        close(fd);
        assert(!chmod(path, 0400)); /* Same inode and length, changed hash. */
    } else if (mutation == 3) {
        assert(!unlink(path));
    } else if (mutation == 4) {
        char *alias = g_build_filename(root, "alias", NULL);
        assert(!link(path, alias));
        g_free(alias);
    } else if (mutation == 5) {
        assert(!unlink(path));
        assert(!symlink(current, path));
    } else if (mutation == 6) {
        char *record_path = single_record(root);
        GKeyFile *record = g_key_file_new();
        assert(g_key_file_load_from_file(record, record_path, 0, NULL));
        char *incomplete = latcd_retirement_capture_objects(root, source, names, 1);
        assert(incomplete);
        char *encoded = g_base64_encode((guchar *)incomplete, strlen(incomplete));
        g_key_file_set_string(record, "transaction", "objects", encoded);
        char *data = g_key_file_to_data(record, NULL, NULL);
        put(record_path, data);
        g_free(data);
        g_free(encoded);
        g_free(incomplete);
        g_key_file_unref(record);
        g_free(record_path);
    }
    unsigned recovered;
    assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
    assert_state(root, mutation ? "UNKNOWN" : "RETIRED");
    assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
    assert_state(root, mutation ? "UNKNOWN" : "RETIRED");
    if (!mutation) {
        int fd = open(path, O_RDONLY);
        assert(fd >= 0 && !flock(fd, LOCK_EX | LOCK_NB));
        assert(!latcd_retirement_capture_objects(root, source, names, 1));
        close(fd);
        const char *bad[] = {"../escape.native"};
        assert(!latcd_retirement_capture_objects(root, source, bad, 1));
    }
    g_free(objects);
    g_free(manifest);
    g_free(module_name);
    g_free(module_path);
    g_free(name);
    g_free(path);
    g_free(current);
    remove_root(root);
    g_free(root);
}

static void test_legacy_and_schema(void)
{
    char *root = root_new(), *current = current_path(root);
    char error[256];
    LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication && !latcd_retirement_publication_prepare(publication, source, next, strlen(next),
                                                                 NULL, error, sizeof(error)));
    latcd_retirement_publication_close(publication);
    char *path = single_record(root);
    GKeyFile *record = g_key_file_new();
    assert(g_key_file_load_from_file(record, path, 0, NULL));
    g_key_file_set_integer(record, "transaction", "version", 1);
    assert(g_key_file_remove_key(record, "transaction", "objects", NULL));
    char *data = g_key_file_to_data(record, NULL, NULL);
    put(path, data);
    g_free(data);
    put(current, next);
    unsigned recovered;
    assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
    assert_state(root, "RETIRED");
    const char *bad[] = { "%%%", "W29iamVjdHNdCmNvdW50PTcK",
        "W29iamVjdHNdCmNvdW50PTEK" };
    for (size_t i = 0; i < G_N_ELEMENTS(bad); i++) {
        g_key_file_set_integer(record, "transaction", "version", 2);
        g_key_file_set_string(record, "transaction", "objects", bad[i]);
        data = g_key_file_to_data(record, NULL, NULL);
        put(path, data);
        g_free(data);
        assert(latcd_retirement_recover(root, &recovered, error, sizeof(error)));
        char *contents = NULL;
        assert(g_file_get_contents(current, &contents, NULL, NULL));
        assert(!strcmp(contents, next));
        g_free(contents);
    }
    g_key_file_unref(record);
    g_free(path);
    g_free(current);
    remove_root(root);
    g_free(root);
}

static void assert_binding(const char *manifest, const char *objects, bool success)
{
    int result = latcd_retirement_validate_binding(source, NULL, 0,
        manifest, strlen(manifest), objects, strlen(objects));
    assert((result == 0) == success);
}

static void test_manifest_binding(void)
{
    char *root = root_new();
    char *module = g_strconcat(source, ".so", NULL);
    char *native = g_strconcat(source, ".native", NULL);
    char *path = g_build_filename(root, module, NULL);
    put(path, "module\n");
    g_free(path);
    path = g_build_filename(root, native, NULL);
    put(path, "native\n");
    const char *names[] = {module, native};
    char *objects = latcd_retirement_capture_objects(root, source, names, 2);
    assert(objects);
    char *manifest = g_strdup_printf("{\"version\":2,\"source_sha256\":\"%s\","
        "\"codegen_id\":\"%s\",\"module\":\"%s\",\"native\":\"%s\","
        "\"tbset\":\"\",\"published_sequence\":18446744073709551615}",
        source, source, module, native);
    assert_binding(manifest, objects, true);
    char *trailing = g_strconcat(manifest, " {}", NULL);
    assert_binding(trailing, objects, false);
    g_free(trailing);
    char *duplicate = g_strconcat("{\"version\":2,", manifest + 1, NULL);
    assert_binding(duplicate, objects, false);
    g_free(duplicate);
    const char *bad_sequence[] = {"18446744073709551616", "-1", "true", "1.0", "1e2", "01"};
    for (size_t i = 0; i < G_N_ELEMENTS(bad_sequence); i++) {
        const char *position = strstr(manifest, "18446744073709551615");
        char *prefix = g_strndup(manifest, position - manifest);
        char *bad = g_strconcat(prefix, bad_sequence[i], "}", NULL);
        assert_binding(bad, objects, false);
        g_free(prefix);
        g_free(bad);
    }
    GKeyFile *table = g_key_file_new();
    assert(g_key_file_load_from_data(table, objects, -1, 0, NULL));
    g_key_file_set_integer(table, "objects", "count", 1);
    assert(g_key_file_remove_group(table, "object1", NULL));
    char *missing = g_key_file_to_data(table, NULL, NULL);
    assert_binding(manifest, missing, false);
    g_free(missing);
    assert(g_key_file_load_from_data(table, objects, -1, 0, NULL));
    g_key_file_set_string(table, "object1", "name", module);
    char *conflict = g_key_file_to_data(table, NULL, NULL);
    assert_binding(manifest, conflict, false);
    g_free(conflict);
    assert(g_key_file_load_from_data(table, objects, -1, 0, NULL));
    char *hash = g_key_file_get_string(table, "object0", "sha256", NULL);
    char *with_hash = g_strdup_printf("{\"module_sha256\":\"%s\",%s", hash, manifest + 1);
    assert_binding(with_hash, objects, true);
    hash[0] = hash[0] == '0' ? '1' : '0';
    char *wrong_hash = g_strdup_printf("{\"module_sha256\":\"%s\",%s", hash, manifest + 1);
    assert_binding(wrong_hash, objects, false);
    char *unknown = g_strdup_printf("{\"unexpected\":true,%s", manifest + 1);
    assert_binding(unknown, objects, false);
    /* A complete table may contain equal rows for a shared old/new object. */
    const char *shared_names[] = {module, native, module, native};
    char *shared = latcd_retirement_capture_objects(root, source, shared_names, 4);
    assert_binding(manifest, shared, true);
    assert(!latcd_retirement_validate_binding(source, manifest, strlen(manifest),
        manifest, strlen(manifest), shared, strlen(shared)));
    assert(g_key_file_load_from_data(table, shared, -1, 0, NULL));
    g_key_file_set_uint64(table, "object2", "inode", 1);
    conflict = g_key_file_to_data(table, NULL, NULL);
    assert_binding(manifest, conflict, false);
    g_free(conflict);
    g_free(shared);
    g_free(unknown);
    g_free(hash);
    g_free(with_hash);
    g_free(wrong_hash);
    g_key_file_unref(table);
    g_free(manifest);
    g_free(objects);
    g_free(module);
    g_free(native);
    g_free(path);
    remove_root(root);
    g_free(root);
}

static void test_tombstone(void)
{
    char *root = root_new(), *name = g_strdup_printf("%s.native", source);
    char *path = g_build_filename(root, name, NULL), error[256];
    put(path, "retired native fixture\n");
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    assert(evidence);
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int reader = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    assert(fd >= 0 && reader >= 0 && !flock(reader, LOCK_SH));
    assert(latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
    close(reader);
    char *current = current_path(root);
    char *manifest = g_strdup_printf("{\"version\":2,\"module\":\"%s.so\","
        "\"native\":\"%s\",\"tbset\":\"\",\"source_sha256\":\"%s\","
        "\"codegen_id\":\"%s\",\"published_sequence\":1}", source, name, source, source);
    put(current, manifest);
    assert(latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
    put(current, "invalid current");
    assert(latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
    assert(!unlink(current));
    GKeyFile *mismatch = g_key_file_new();
    assert(g_key_file_load_from_data(mismatch, evidence, -1, 0, NULL));
    g_key_file_set_uint64(mismatch, "object0", "inode", 0);
    char *wrong = g_key_file_to_data(mismatch, NULL, NULL);
    assert(latcd_retirement_tombstone(root, source, name, fd, wrong, error, sizeof(error)));
    g_free(wrong);
    g_key_file_unref(mismatch);
    assert(!latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
    assert(!access(path, F_OK));
    char *marker = g_build_filename(root, ".gc", "tombstones", name, NULL);
    GKeyFile *record = g_key_file_new();
    assert(g_key_file_load_from_file(record, marker, 0, NULL));
    struct stat st;
    assert(!fstat(fd, &st));
    assert(g_key_file_get_uint64(record, "tombstone", "inode", NULL) == (uint64_t)st.st_ino);
    char *before = NULL, *after = NULL;
    assert(g_file_get_contents(marker, &before, NULL, NULL));
    assert(latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
    assert(g_file_get_contents(marker, &after, NULL, NULL) && !strcmp(before, after));
    close(fd);
    g_key_file_unref(record);
    g_free(before); g_free(after); g_free(marker); g_free(current); g_free(manifest);
    g_free(evidence); g_free(path); g_free(name);
    remove_root(root); g_free(root);
}

static void test_cache_domain(void)
{
    char *root = root_new(), error[256], first[37] = {0}, second[37] = {0};
    assert(latcd_cache_domain_validate(root, first, error, sizeof(error)) == 0);
    assert(!chmod(root, 0755));
    assert(lat_aot_v2_cache_domain_validate(root, NULL, error, sizeof(error)) == 0);
    assert(!chmod(root, 0700));
    assert(!latcd_cache_domain_init(root, first, error, sizeof(error)));
    char *lock = g_build_filename(root, ".gc", "domain.lock", NULL);
    struct stat lock_before;
    assert(!stat(lock, &lock_before));
    assert(!latcd_cache_domain_init(root, second, error, sizeof(error)));
    struct stat lock_after;
    assert(!stat(lock, &lock_after));
    assert(!strcmp(first, second) && lock_before.st_ino == lock_after.st_ino);
    assert(latcd_cache_domain_validate(root, second, error, sizeof(error)) == 1);
    assert(!strcmp(first, second));

    char *marker = g_build_filename(root, ".gc", "domain.ini", NULL);
    char *raw = NULL;
    assert(g_file_get_contents(marker, &raw, NULL, NULL));
    char *version = g_strdup(raw);
    char *number = strstr(version, "version=1");
    assert(number);
    number[strlen("version=")] = '2';
    put(marker, version);
    assert(lat_aot_v2_cache_domain_validate(root, NULL, error, sizeof(error)) < 0);
    assert(latcd_cache_domain_init(root, second, error, sizeof(error)) < 0);
    g_free(version);
    put(marker, raw);
    assert(!chmod(root, 0755));
    assert(lat_aot_v2_cache_domain_validate(root, NULL, error, sizeof(error)) < 0);
    assert(!chmod(root, 0700));
    char *bad = g_strdup(raw);
    char *inode = strstr(bad, "cache_inode=");
    assert(inode);
    inode += strlen("cache_inode=");
    char *end = strchr(inode, '\n');
    assert(end && end > inode);
    end[-1] = end[-1] == '9' ? '8' : end[-1] + 1;
    put(marker, bad);
    assert(latcd_cache_domain_validate(root, second, error, sizeof(error)) < 0);
    g_free(bad);
    put(marker, raw);
    assert(latcd_cache_domain_validate(root, second, error, sizeof(error)) == 1);
    assert(!chmod(lock, 0644));
    assert(latcd_cache_domain_validate(root, second, error, sizeof(error)) < 0);
    assert(!chmod(lock, 0600));
    assert(!unlink(lock));
    assert(latcd_cache_domain_validate(root, second, error, sizeof(error)) < 0);
    g_free(raw); g_free(marker); g_free(lock);
    remove_root(root); g_free(root);
}

static void test_other_current(unsigned mutation, bool executor)
{
    char *root = root_new(), error[256];
    char *name = g_strconcat(source, ".native", NULL);
    char *path = g_build_filename(root, name, NULL);
    put(path, "retired object\n");
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0 && evidence);
    if (executor) {
        assert(!latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
        close(fd); fd = -1;
    }
    char *other = g_strnfill(64, 'b');
    char *manifest = g_strdup_printf("{\"version\":2,\"module\":\"%s.so\","
        "\"native\":\"%s.native\",\"tbset\":\"\",\"source_sha256\":\"%s\","
        "\"codegen_id\":\"%s\",\"published_sequence\":1}", other, other, other, other);
    char *current = g_strdup_printf("%s/%s.current", root, mutation == 1 ? "unattributed" : other);
    put(current, mutation == 0 ? "corrupt current" : manifest);
    char *alias = g_strconcat(current, ".alias", NULL);
    if (mutation == 2) assert(!chmod(current, 0600));
    if (mutation == 3) assert(!link(current, alias));
    if (mutation == 4) {
        assert(!rename(current, alias));
        assert(!symlink(alias, current));
    }
    int result = executor ? latcd_tombstone_delete(root, name, error, sizeof(error)) :
        latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error));
    assert((result == 0) == (mutation == 5));
    assert((access(path, F_OK) != 0) == (executor && mutation == 5));
    if (fd >= 0) close(fd);
    g_free(alias); g_free(current); g_free(manifest); g_free(other);
    g_free(evidence); g_free(path); g_free(name); remove_root(root); g_free(root);
}

static void test_roots_latch(void)
{
    char *root = root_new(), error[256];
    int first = latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, sizeof(error));
    int second = latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, sizeof(error));
    assert(first >= 0 && second >= 0);
    assert(latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB, error, sizeof(error)) < 0);
    close(first);
    assert(latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB, error, sizeof(error)) < 0);
    close(second);
    int exclusive = latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB, error, sizeof(error));
    assert(exclusive >= 0);
    assert(latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, sizeof(error)) < 0);
    close(exclusive);
    /* A publisher retains SH through transaction completion; a future round
     * cutoff must not be sampled while that publisher is in flight. */
    char *current = current_path(root);
    put(current, old);
    first = latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, sizeof(error));
    assert(first >= 0);
    char round_boot[37] = "stale";
    uint64_t cutoff = 123;
    assert(latcd_retirement_round_sample(root, round_boot, &cutoff, error, sizeof(error)) < 0);
    assert(!*round_boot && !cutoff);
    LatcdRetirementPublication *publication =
        latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication);
    assert(!latcd_retirement_publication_prepare(publication, source, next, strlen(next),
                                                 NULL, error, sizeof(error)));
    put(current, next);
    LatcdRecoveryCursor *recovery = latcd_recovery_open(root, false, error, sizeof(error));
    assert(recovery);
    assert(latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB, error, sizeof(error)) < 0);
    assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
    assert(latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB, error, sizeof(error)) < 0);
    latcd_retirement_publication_close(publication);
    close(first);
    clock_fault = 1;
    assert(latcd_retirement_round_sample(root, round_boot, &cutoff, error, sizeof(error)) < 0);
    assert(!*round_boot && !cutoff);
    clock_fault = 0;
    assert(!latcd_retirement_round_sample(root, round_boot, &cutoff, error, sizeof(error)));
    assert(g_uuid_string_is_valid(round_boot) && cutoff);
    publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication);
    assert(latcd_retirement_round_sample(root, round_boot, &cutoff, error, sizeof(error)) < 0);
    assert(latcd_retirement_publication_finish(publication, error, sizeof(error)) < 0);
    assert(!latcd_retirement_publication_prepare(publication, source, next, strlen(next),
                                                 NULL, error, sizeof(error)));
    assert(latcd_retirement_publication_prepare(publication, source, next, strlen(next),
                                                NULL, error, sizeof(error)) < 0);
    assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
    assert(latcd_retirement_round_sample(root, round_boot, &cutoff, error, sizeof(error)) < 0);
    latcd_retirement_publication_close(publication);
    assert(!latcd_retirement_round_sample(root, round_boot, &cutoff, error, sizeof(error)));
    exclusive = latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB, error, sizeof(error));
    assert(exclusive >= 0);
    LatcdRecoveryProgress progress;
    assert(latcd_recovery_step(recovery, 1, 1024, 10000, &progress, error, sizeof(error)) < 0);
    assert(!progress.visited && !progress.recovered);
    close(exclusive);
    int step;
    do {
        step = latcd_recovery_step(recovery, 1, 1024, 10000, &progress, error, sizeof(error));
        assert(step >= 0);
    } while (step);
    assert(progress.recovered == 2);
    latcd_recovery_close(recovery);
    publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication);
    assert(!latcd_retirement_publication_prepare(publication, source, next, strlen(next),
                                                 NULL, error, sizeof(error)));
    assert(latcd_retirement_round_sample(root, round_boot, &cutoff, error, sizeof(error)) < 0);
    latcd_retirement_publication_close(publication);
    assert(!latcd_retirement_round_sample(root, round_boot, &cutoff, error, sizeof(error)));
    unsigned recovered = 0;
    assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
    assert(recovered == 3);
    g_free(current);
    remove_root(root); g_free(root);
    root = root_new();
    char *name = g_strconcat(source, ".native", NULL);
    char *object = g_build_filename(root, name, NULL);
    put(object, "roots contention\n");
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    int fd = open(object, O_RDONLY | O_CLOEXEC);
    first = latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, sizeof(error));
    assert(fd >= 0 && first >= 0 && evidence);
    assert(latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)) < 0);
    close(first);
    assert(!latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
    close(fd);
    first = latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, sizeof(error));
    assert(first >= 0);
    assert(latcd_tombstone_delete(root, name, error, sizeof(error)) < 0);
    assert(!access(object, F_OK));
    close(first);
    assert(!latcd_tombstone_delete(root, name, error, sizeof(error)));
    g_free(evidence); g_free(object); g_free(name);
    char *path = g_build_filename(root, ".gc", "reference-roots.lock", NULL);
    char *alias = g_strconcat(path, ".alias", NULL);
    assert(!link(path, alias));
    assert(latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, sizeof(error)) < 0);
    assert(!unlink(alias));
    assert(!chmod(path, 0666));
    assert(latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, sizeof(error)) < 0);
    assert(!chmod(path, 0600));
    g_free(alias); g_free(path); remove_root(root); g_free(root);
}

static void test_round_cursor(void)
{
    const char *boot = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const char *other = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    LatcdRetirementRound round = {0};
    assert(latcd_retirement_round_restore(&round, boot, 100) == 0);
    assert(!strcmp(round.boot, boot) && round.cutoff == 100);
    assert(latcd_retirement_round_complete(&round, other, 200) < 0);
    assert(latcd_retirement_round_restore(&round, other, 50) == 0);
    assert(latcd_retirement_round_complete(&round, boot, 300) < 0);
    assert(latcd_retirement_round_restore(&round, boot, 100) == 0);
    assert(latcd_retirement_round_complete(&round, boot, 100) < 0);
    assert(latcd_retirement_round_complete(&round, boot, 200) == 0);
    assert(round.cutoff == 200);
    assert(latcd_retirement_round_restore(&round, boot, 0) < 0);
    assert(latcd_retirement_round_restore(&round, "bad", 1) < 0);
    const char *names[] = {"a", "b", "c", "d"};
    LatcdRetirementPage page;
    assert(latcd_retirement_page_select(names, G_N_ELEMENTS(names), "a", &page) == 1);
    assert(page.count == 3 && !strcmp(page.next_cursor, "d"));
    assert(latcd_retirement_page_select(names, G_N_ELEMENTS(names), "d", &page) == 0);
    assert(page.count == 0);
    const char *unsorted[] = {"b", "a"};
    assert(latcd_retirement_page_select(unsorted, G_N_ELEMENTS(unsorted), NULL, &page) < 0);
    GPtrArray *many = g_ptr_array_new_with_free_func(g_free);
    for (unsigned i = 0; i < 130; i++)
        g_ptr_array_add(many, g_strdup_printf("object-%03u", i));
    assert(latcd_retirement_page_select((const char *const *)many->pdata, many->len,
                                        NULL, &page) == 1);
    assert(page.count == 128 && !strcmp(page.next_cursor, "object-127"));
    gpointer saved = many->pdata[129];
    many->pdata[129] = NULL;
    assert(latcd_retirement_page_select((const char *const *)many->pdata, many->len,
                                        NULL, &page) < 0);
    many->pdata[129] = many->pdata[128];
    assert(latcd_retirement_page_select((const char *const *)many->pdata, many->len,
                                        NULL, &page) < 0);
    many->pdata[129] = saved;
    assert(latcd_retirement_page_select((const char *const *)many->pdata, many->len,
                                        NULL, &page) == 1);
    LatcdRetirementPage tail;
    assert(latcd_retirement_page_select((const char *const *)many->pdata, many->len,
                                        page.next_cursor, &tail) == 1);
    assert(tail.count == 2 && !strcmp(tail.next_cursor, "object-129"));
    char selected[128][138];
    assert(latcd_retirement_page_names((const char *const *)many->pdata, many->len,
                                       &tail, selected) == 2);
    assert(!strcmp(selected[0], "object-128") && !strcmp(selected[1], "object-129"));
    LatcdRetirementPageDeadline deadlines[2] = {
        {"a", 10, 1, 0, 0, 0}, {"b", 20, 1, 0, 0, 0}
    };
    assert(latcd_retirement_page_observe(deadlines, 2, "a", 30) == 0);
    assert(deadlines[0].deadline == 30);
    assert(latcd_retirement_page_observe(deadlines, 2, "c", 40) == 1);
    LatcdRetirementPage copy = { .next_cursor = "b", .count = 2 };
    const char *copy_names[] = {"a", "b", "c"};
    assert(latcd_retirement_page_names(copy_names, 3, &copy, selected) == 2);
    assert(!strcmp(selected[0], "a") && !strcmp(selected[1], "b"));
    g_strlcpy(copy.next_cursor, "missing", sizeof(copy.next_cursor));
    assert(latcd_retirement_page_names(copy_names, 3, &copy, selected) < 0);
    g_strlcpy(copy.next_cursor, "a", sizeof(copy.next_cursor));
    assert(latcd_retirement_page_names(copy_names, 3, &copy, selected) < 0);
    LatcdRetirementPageState state = {
        .cache_device = 1, .cache_inode = 2, .grace_us = 3, .round_cutoff = 4,
        .boot = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", .cursor = "b", .count = 2,
        .entries = {{"a", 10, 1, 0, 0, 0}, {"b", 20, 1, 0, 0, 0}}
    };
    assert(latcd_retirement_page_state_valid(&state) == 0);
    LatcdRetirementPageState unterminated = state;
    memset(unterminated.boot, 'a', sizeof(unterminated.boot));
    assert(latcd_retirement_page_state_valid(&unterminated) < 0);
    unterminated = state;
    memset(unterminated.cursor, 'a', sizeof(unterminated.cursor));
    assert(latcd_retirement_page_state_valid(&unterminated) < 0);
    unterminated = state;
    memset(unterminated.committed_cursor, 'a', sizeof(unterminated.committed_cursor));
    assert(latcd_retirement_page_state_valid(&unterminated) < 0);
    unterminated = state;
    memset(unterminated.retry_cursor, 'a', sizeof(unterminated.retry_cursor));
    assert(latcd_retirement_page_state_valid(&unterminated) < 0);
    unterminated = state;
    memset(unterminated.entries[0].name, 'a', sizeof(unterminated.entries[0].name));
    assert(latcd_retirement_page_state_valid(&unterminated) < 0);
    state.round_cutoff = 0;
    assert(latcd_retirement_page_state_valid(&state) < 0);
    state.round_cutoff = 4;
    state.entries[1].name[0] = 'a';
    assert(latcd_retirement_page_state_valid(&state) < 0);
    char *page_root = root_new(), page_error[256];
    char *page_path = g_build_filename(page_root, ".gc", "retirement-page.ini", NULL);
    struct stat page_cache;
    assert(!stat(page_root, &page_cache));
    state.cache_device = page_cache.st_dev;
    state.cache_inode = page_cache.st_ino;
    LatcdRetirementPageState loaded;
    assert(latcd_retirement_page_state_load(page_root, &loaded, page_error,
                                            sizeof(page_error)) == 1);
    assert(!latcd_retirement_page_startup_check(page_root, page_error, sizeof(page_error)));
    state.entries[1].name[0] = 'b';
    LatcdRetirementPageState empty_page = state;
    empty_page.count = 0;
    empty_page.cursor[0] = 0;
    assert(!latcd_retirement_page_state_store(page_root, &empty_page, page_error, sizeof(page_error)));
    assert(!latcd_retirement_page_startup_check(page_root, page_error, sizeof(page_error)));
    char *partial = g_build_filename(page_root, ".gc", ".write-interrupted", NULL);
    put(partial, "partial");
    assert(latcd_retirement_page_startup_check(page_root, page_error, sizeof(page_error)) < 0);
    assert(!unlink(partial));
    g_free(partial);
    assert(latcd_retirement_page_state_store(page_root, &state, page_error,
                                             sizeof(page_error)) == 0);
    assert(latcd_retirement_page_startup_check(page_root, page_error, sizeof(page_error)) < 0);
    LatcdRetirementPageState pending_page = state;
    pending_page.committed_pending = true;
    pending_page.results[0] = 1;
    pending_page.results[1] = 2;
    LatcdRetirementConsumption consumption = {0};
    assert(!latcd_retirement_consumption_valid(&pending_page, &consumption));
    assert(latcd_retirement_consumption_valid(&state, &consumption) < 0);
    struct stat intent_stat = {.st_dev = 1, .st_ino = 2, .st_mode = S_IFREG | 0400,
        .st_uid = geteuid(), .st_nlink = 1, .st_size = 1024, .st_blocks = 8};
    uint8_t intent_digest[32] = {1};
    assert(!latcd_retirement_consumption_bind(&pending_page, &consumption, 0, &intent_stat, intent_digest));
    assert(!latcd_retirement_consumption_valid(&pending_page, &consumption));
    uint8_t consumption_id[32], changed_id[32];
    LatcdRetirementPageState digest_page = pending_page;
    snprintf(digest_page.entries[0].name, sizeof(digest_page.entries[0].name), "%064x.so", 1);
    snprintf(digest_page.entries[1].name, sizeof(digest_page.entries[1].name), "%064x.so", 2);
    g_strlcpy(digest_page.cursor, digest_page.entries[1].name, sizeof(digest_page.cursor));
    assert(!latcd_retirement_consumption_identity(&digest_page, &consumption, consumption_id));
    assert(!latcd_retirement_consumption_identity(&digest_page, &consumption, changed_id));
    assert(!memcmp(consumption_id, changed_id, 32));
    consumption.digest[0]++;
    assert(!latcd_retirement_consumption_identity(&digest_page, &consumption, changed_id));
    assert(memcmp(consumption_id, changed_id, 32));
    consumption.digest[0]--;
    LatcdRetirementPageState changed_pending = digest_page;
    changed_pending.entries[0].retry_at++;
    assert(!latcd_retirement_consumption_identity(&changed_pending, &consumption, changed_id));
    assert(memcmp(consumption_id, changed_id, 32));
    consumption.size++;
    assert(latcd_retirement_consumption_valid(&pending_page, &consumption) < 0);
    consumption.size--;
    consumption.completed[0] = 1;
    assert(latcd_retirement_consumption_valid(&pending_page, &consumption) < 0);
    consumption = (LatcdRetirementConsumption){0};
    consumption.completed[0] = 1;
    assert(!latcd_retirement_consumption_valid(&pending_page, &consumption));
    consumption.completed[0] = 2;
    assert(latcd_retirement_consumption_valid(&pending_page, &consumption) < 0);
    consumption.completed[0] = 0;
    consumption.completed[15] = 128;
    assert(latcd_retirement_consumption_valid(&pending_page, &consumption) < 0);
    consumption.completed[15] = 0;
    LatcdRetirementConsumption before_bind = consumption;
    assert(latcd_retirement_consumption_bind(&pending_page, &consumption, 1, &intent_stat, intent_digest) < 0);
    assert(!memcmp(&consumption, &before_bind, sizeof(consumption)));
    assert(latcd_retirement_consumption_bind(&pending_page, &consumption, 128, &intent_stat, intent_digest) < 0);
    assert(!memcmp(&consumption, &before_bind, sizeof(consumption)));
    consumption.completed[0] = 1;
    before_bind = consumption;
    assert(latcd_retirement_consumption_bind(&pending_page, &consumption, 0, &intent_stat, intent_digest) < 0);
    assert(!memcmp(&consumption, &before_bind, sizeof(consumption)));
    LatcdRetirementPageInventory evidence = {0};
    uint8_t evidence_results[128] = {1, 2};
    evidence.members[0].present = evidence.members[1].present = true;
    evidence.members[0].snapshot = intent_stat;
    memcpy(evidence.members[0].digest, intent_digest, 32);
    evidence.occupied_slots = 4095; evidence.occupied_bytes = 4095 * 1024;
    uint64_t consumption_budget;
    consumption = (LatcdRetirementConsumption){0};
    assert(!latcd_retirement_consumption_check_inventory(&pending_page, &consumption, evidence_results, &evidence));
    assert(!latcd_retirement_consumption_budget_estimate(&pending_page, &consumption, evidence_results,
                                                          &evidence, &consumption_budget));
    assert(consumption_budget == 2 * 65536);
    evidence_results[0] = 0; evidence.members[0].present = false;
    assert(latcd_retirement_consumption_check_inventory(&pending_page, &consumption, evidence_results, &evidence) < 0);
    assert(latcd_retirement_consumption_budget_estimate(&pending_page, &consumption, evidence_results,
                                                        &evidence, &consumption_budget) < 0 && !consumption_budget);
    assert(!latcd_retirement_consumption_bind(&pending_page, &consumption, 0, &intent_stat, intent_digest));
    assert(!latcd_retirement_consumption_check_inventory(&pending_page, &consumption, evidence_results, &evidence));
    assert(!latcd_retirement_consumption_budget_estimate(&pending_page, &consumption, evidence_results,
                                                          &evidence, &consumption_budget));
    assert(consumption_budget == 2 * 65536);
    evidence_results[0] = 1; evidence.members[0].present = true;
    assert(!latcd_retirement_consumption_check_inventory(&pending_page, &consumption, evidence_results, &evidence));
    evidence.members[0].snapshot.st_ino++;
    assert(latcd_retirement_consumption_check_inventory(&pending_page, &consumption, evidence_results, &evidence) < 0);
    evidence.members[0].snapshot.st_ino--;
    evidence.members[0].digest[0]++;
    assert(latcd_retirement_consumption_check_inventory(&pending_page, &consumption, evidence_results, &evidence) < 0);
    evidence.members[0].digest[0]--;
    consumption = (LatcdRetirementConsumption){0}; consumption.completed[0] = 1;
    assert(latcd_retirement_consumption_check_inventory(&pending_page, &consumption, evidence_results, &evidence) < 0);
    evidence_results[0] = 0; evidence.members[0].present = false;
    assert(!latcd_retirement_consumption_check_inventory(&pending_page, &consumption, evidence_results, &evidence));
    evidence_results[1] = 0; evidence.members[1].present = false;
    assert(latcd_retirement_consumption_check_inventory(&pending_page, &consumption, evidence_results, &evidence) < 0);
    assert(!latcd_retirement_page_state_store(page_root, &pending_page, page_error, sizeof(page_error)));
    assert(latcd_retirement_page_startup_check(page_root, page_error, sizeof(page_error)) < 0);
    assert(!latcd_retirement_page_state_load(page_root, &loaded, page_error, sizeof(page_error)) &&
           loaded.committed_pending && loaded.results[0] == 1 && loaded.results[1] == 2);
    assert(!latcd_retirement_page_state_store(page_root, &state, page_error, sizeof(page_error)));
    assert(latcd_retirement_page_state_load(page_root, &loaded, page_error,
                                            sizeof(page_error)) == 0);
    g_strlcpy(state.committed_cursor, "0", sizeof(state.committed_cursor));
    assert(!latcd_retirement_page_state_store(page_root, &state, page_error, sizeof(page_error)));
    assert(!latcd_retirement_page_state_load(page_root, &loaded, page_error, sizeof(page_error)));
    assert(!strcmp(loaded.committed_cursor, "0"));
    g_strlcpy(state.committed_cursor, "a", sizeof(state.committed_cursor));
    assert(latcd_retirement_page_state_store(page_root, &state, page_error, sizeof(page_error)) < 0);
    state.committed_cursor[0] = 0;
    assert(!latcd_retirement_page_state_store(page_root, &state, page_error, sizeof(page_error)));
    GKeyFile *v4 = g_key_file_new();
    assert(g_key_file_load_from_file(v4, page_path, 0, NULL));
    g_key_file_set_string(v4, "page", "pending", "2");
    char *bad_pending = g_key_file_to_data(v4, NULL, NULL);
    put(page_path, bad_pending);
    g_free(bad_pending);
    assert(latcd_retirement_page_state_load(page_root, &loaded, page_error, sizeof(page_error)) < 0);
    assert(latcd_retirement_page_startup_check(page_root, page_error, sizeof(page_error)) < 0);
    g_key_file_set_string(v4, "page", "pending", "true");
    bad_pending = g_key_file_to_data(v4, NULL, NULL);
    put(page_path, bad_pending);
    g_free(bad_pending);
    assert(latcd_retirement_page_state_load(page_root, &loaded, page_error, sizeof(page_error)) < 0);
    g_key_file_set_integer(v4, "page", "version", 4);
    for (unsigned i = 0; i < state.count; i++) {
        char group[32]; snprintf(group, sizeof(group), "entry%u", i);
        assert(g_key_file_remove_key(v4, group, "result", NULL));
    }
    g_key_file_set_integer(v4, "page", "pending", 1);
    char *v4_data = g_key_file_to_data(v4, NULL, NULL);
    put(page_path, v4_data);
    g_free(v4_data);
    assert(latcd_retirement_page_state_load(page_root, &loaded, page_error, sizeof(page_error)) < 0);
    g_key_file_set_integer(v4, "page", "pending", 0);
    v4_data = g_key_file_to_data(v4, NULL, NULL);
    put(page_path, v4_data);
    g_free(v4_data);
    assert(!latcd_retirement_page_state_load(page_root, &loaded, page_error, sizeof(page_error)) &&
           !loaded.committed_pending && loaded.count == state.count);
    g_key_file_set_integer(v4, "page", "version", 3);
    assert(g_key_file_remove_key(v4, "page", "pending", NULL));
    char *v3_data = g_key_file_to_data(v4, NULL, NULL);
    put(page_path, v3_data);
    g_free(v3_data);
    assert(!latcd_retirement_page_state_load(page_root, &loaded, page_error, sizeof(page_error)) &&
           !loaded.committed_pending && loaded.count == state.count);
    g_key_file_unref(v4);
    assert(!latcd_retirement_page_state_store(page_root, &state, page_error, sizeof(page_error)));
    GKeyFile *legacy = g_key_file_new();
    assert(g_key_file_load_from_file(legacy, page_path, 0, NULL));
    g_key_file_set_integer(legacy, "page", "version", 2);
    assert(g_key_file_remove_key(legacy, "page", "pending", NULL));
    for (unsigned i = 0; i < state.count; i++) {
        char group[32]; snprintf(group, sizeof(group), "entry%u", i);
        assert(g_key_file_remove_key(legacy, group, "result", NULL));
    }
    assert(g_key_file_remove_key(legacy, "page", "committed_cursor", NULL));
    char *v2_data = g_key_file_to_data(legacy, NULL, NULL);
    put(page_path, v2_data);
    g_free(v2_data);
    assert(!latcd_retirement_page_state_load(page_root, &loaded, page_error, sizeof(page_error)));
    assert(!loaded.committed_cursor[0]);
    g_key_file_set_integer(legacy, "page", "version", 1);
    assert(g_key_file_remove_key(legacy, "page", "round_cutoff", NULL));
    char *legacy_data = g_key_file_to_data(legacy, NULL, NULL);
    put(page_path, legacy_data);
    g_free(legacy_data);
    g_key_file_unref(legacy);
    assert(latcd_retirement_page_state_load(page_root, &loaded, page_error,
                                            sizeof(page_error)) < 0);
    assert(!latcd_retirement_page_state_store(page_root, &state, page_error, sizeof(page_error)));
    assert(!latcd_retirement_page_state_load(page_root, &loaded, page_error, sizeof(page_error)));
    assert(latcd_retirement_page_state_compatible(&loaded, state.boot, state.grace_us, 4) == 0);
    assert(latcd_retirement_page_state_compatible(&loaded, state.boot, state.grace_us, 3) == 1);
    assert(latcd_retirement_page_state_compatible(&loaded, state.boot, state.grace_us, 0) == 1);
    assert(latcd_retirement_page_state_compatible(&loaded,
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", state.grace_us, 4) == 1);
    assert(latcd_retirement_page_state_compatible(&loaded, state.boot,
        state.grace_us + 1, 4) == 1);
    loaded.entries[0].enqueued = 5;
    assert(latcd_retirement_page_state_compatible(&loaded, state.boot, state.grace_us, 4) == 1);
    loaded.entries[0].enqueued = 1;
    loaded.entries[0].retry_at = UINT64_C(3600000004);
    assert(latcd_retirement_page_state_compatible(&loaded, state.boot, state.grace_us, 4) == 0);
    loaded.entries[0].retry_at++;
    assert(latcd_retirement_page_state_compatible(&loaded, state.boot, state.grace_us, 4) == 1);
    loaded.entries[0].retry_at = 0;
    assert(latcd_retirement_page_state_resume(page_root, state.boot, state.grace_us,
                                              4, &loaded, page_error, sizeof(page_error)) < 0);
    assert(!loaded.round_cutoff && !loaded.count);
    char *first_object = g_strconcat(source, ".native", NULL);
    char *second_object = g_strconcat(source, ".so", NULL);
    g_strlcpy(state.entries[0].name, first_object, sizeof(state.entries[0].name));
    g_strlcpy(state.entries[1].name, second_object, sizeof(state.entries[1].name));
    g_strlcpy(state.cursor, second_object, sizeof(state.cursor));
    assert(!latcd_retirement_page_state_store(page_root, &state, page_error, sizeof(page_error)));
    assert(!latcd_retirement_page_state_resume(page_root, state.boot, state.grace_us,
                                               4, &loaded, page_error, sizeof(page_error)));
    g_strlcpy(state.committed_cursor, "0invalid", sizeof(state.committed_cursor));
    assert(!latcd_retirement_page_state_store(page_root, &state, page_error, sizeof(page_error)));
    assert(latcd_retirement_page_state_resume(page_root, state.boot, state.grace_us,
                                              4, &loaded, page_error, sizeof(page_error)) < 0);
    assert(!loaded.round_cutoff && !loaded.count);
    state.committed_cursor[0] = 0;
    g_free(first_object); g_free(second_object);
    state.entries[0].enqueued = 5;
    assert(!latcd_retirement_page_state_store(page_root, &state, page_error, sizeof(page_error)));
    assert(latcd_retirement_page_state_resume(page_root, state.boot, state.grace_us,
                                              4, &loaded, page_error, sizeof(page_error)) < 0);
    assert(!loaded.round_cutoff && !loaded.count);
    state.entries[0].enqueued = 1;
    state.entries[0].retry_at = UINT64_C(3600000005);
    assert(!latcd_retirement_page_state_store(page_root, &state, page_error, sizeof(page_error)));
    assert(latcd_retirement_page_state_resume(page_root, state.boot, state.grace_us,
                                              4, &loaded, page_error, sizeof(page_error)) < 0);
    assert(!loaded.round_cutoff && !loaded.count);
    state.entries[0].retry_at = 0;
    assert(!latcd_retirement_page_state_store(page_root, &state, page_error, sizeof(page_error)));
    assert(latcd_retirement_page_state_resume(page_root, state.boot, state.grace_us,
                                              3, &loaded, page_error, sizeof(page_error)) < 0);
    assert(!loaded.round_cutoff && !loaded.count);
    assert(latcd_retirement_page_state_resume(page_root, state.boot, state.grace_us + 1,
                                              4, &loaded, page_error, sizeof(page_error)) < 0);
    LatcdRetirementPageDeadline plan_schedule[130];
    const char *plan_names[130];
    for (unsigned i = 0; i < 130; i++) {
        plan_names[i] = many->pdata[i];
        plan_schedule[i] = (LatcdRetirementPageDeadline){
            .deadline = i + 1, .enqueued = 1
        };
        g_strlcpy(plan_schedule[i].name, plan_names[i], sizeof(plan_schedule[i].name));
    }
    LatcdRetirementPageState plan;
    assert(latcd_retirement_page_plan(plan_names, 130, NULL, plan_schedule, 130, &plan) == 1);
    assert(plan.count == 128 && !strcmp(plan.cursor, "object-127"));
    char plan_cursor[138];
    g_strlcpy(plan_cursor, plan.cursor, sizeof(plan_cursor));
    assert(latcd_retirement_page_plan(plan_names, 130, plan_cursor, plan_schedule, 130, &plan) == 1);
    assert(plan.count == 2 && !strcmp(plan.cursor, "object-129"));
    assert(latcd_retirement_page_plan(plan_names, 130, NULL, plan_schedule, 1, &plan) < 0);
    assert(!plan.count && !plan.cursor[0] && !plan.entries[0].name[0]);
    memset(&plan, 0x5a, sizeof(plan));
    const char *invalid_plan[] = {"z", "a"};
    assert(latcd_retirement_page_plan(invalid_plan, 2, NULL, plan_schedule, 2, &plan) < 0);
    assert(!plan.count && !plan.cursor[0] && !plan.entries[0].name[0]);
    LatcdRetirementPageDeadline duplicate[] = {plan_schedule[0], plan_schedule[0]};
    duplicate[1].retry_at = 100;
    assert(latcd_retirement_page_plan(plan_names, 1, NULL, duplicate, 2, &plan) < 0);
    assert(!plan.count && !plan.cursor[0] && !plan.entries[0].name[0]);
    g_ptr_array_unref(many);
    state.cache_inode++;
    assert(latcd_retirement_page_state_store(page_root, &state, page_error,
                                             sizeof(page_error)) < 0);
    GKeyFile *wrong_cache = g_key_file_new();
    assert(g_key_file_load_from_file(wrong_cache, page_path, 0, NULL));
    g_key_file_set_uint64(wrong_cache, "page", "cache_inode", state.cache_inode);
    char *wrong_cache_data = g_key_file_to_data(wrong_cache, NULL, NULL);
    put(page_path, wrong_cache_data);
    g_free(wrong_cache_data); g_key_file_unref(wrong_cache);
    assert(latcd_retirement_page_state_load(page_root, &loaded, page_error,
                                            sizeof(page_error)) < 0);
    state.cache_inode = page_cache.st_ino;
    char cursor_first = state.cursor[0];
    state.cursor[0] = cursor_first == 'c' ? 'd' : 'c';
    assert(latcd_retirement_page_state_valid(&state) < 0);
    state.cursor[0] = cursor_first;
    assert(latcd_retirement_page_state_store(page_root, &state, page_error,
                                             sizeof(page_error)) == 0);
    GKeyFile *extra = g_key_file_new();
    assert(g_key_file_load_from_file(extra, page_path, 0, NULL));
    g_key_file_set_uint64(extra, "entry2", "unexpected", 1);
    char *extra_data = g_key_file_to_data(extra, NULL, NULL);
    put(page_path, extra_data);
    g_free(extra_data);
    g_key_file_unref(extra);
    assert(latcd_retirement_page_state_load(page_root, &loaded, page_error,
                                            sizeof(page_error)) < 0);
    assert(!loaded.round_cutoff && !loaded.count && !loaded.cursor[0]);
    assert(latcd_retirement_page_state_store(page_root, &state, page_error,
                                             sizeof(page_error)) == 0);
    assert(latcd_retirement_page_state_load(page_root, &loaded, page_error,
                                            sizeof(page_error)) == 0);
    assert(loaded.cache_device == state.cache_device && loaded.cache_inode == state.cache_inode &&
           loaded.grace_us == state.grace_us && loaded.round_cutoff == state.round_cutoff && !strcmp(loaded.boot, state.boot) &&
           !strcmp(loaded.cursor, state.cursor) && loaded.count == state.count &&
           loaded.sequence == state.sequence &&
           loaded.entries[1].deadline == state.entries[1].deadline &&
           loaded.entries[1].enqueued == state.entries[1].enqueued &&
           loaded.entries[1].last_attempt == state.entries[1].last_attempt &&
           loaded.entries[1].retry_at == state.entries[1].retry_at &&
           loaded.entries[1].busy_count == state.entries[1].busy_count);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, page_root, page_error, sizeof(page_error)));
    latcd_cache_capacity_metadata_bind(&capacity, 1);
    LatcdRetirementPageState changed = state;
    changed.sequence++;
    assert(latcd_retirement_page_state_store(page_root, &changed, page_error,
                                             sizeof(page_error)) < 0);
    assert(!latcd_retirement_page_state_load(page_root, &loaded, page_error, sizeof(page_error)));
    assert(loaded.sequence == state.sequence && capacity.ready);
    char *capacity_root = root_new();
    assert(!latcd_cache_capacity_scan(&capacity, capacity_root, page_error, sizeof(page_error)));
    latcd_cache_capacity_metadata_bind(&capacity, 1);
    LatcdRetirementPageState rejected = state;
    struct stat capacity_cache;
    assert(!stat(capacity_root, &capacity_cache));
    rejected.cache_device = capacity_cache.st_dev;
    rejected.cache_inode = capacity_cache.st_ino;
    assert(latcd_retirement_page_state_store(capacity_root, &rejected, page_error,
                                             sizeof(page_error)) < 0);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    remove_root(capacity_root); g_free(capacity_root);
    put(page_path, "[page]\nversion=1\n");
    assert(latcd_retirement_page_state_load(page_root, &loaded, page_error,
                                            sizeof(page_error)) < 0);
    g_free(page_path); remove_root(page_root); g_free(page_root);
}

static void test_tombstone_crash(const char *point, bool crash)
{
    char *root = root_new(), *name = g_strdup_printf("%s.native", source);
    char *path = g_build_filename(root, name, NULL), error[256];
    put(path, "immutable retired object\n");
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    assert(evidence);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0);
        char *setting = g_strdup_printf("%s:%s", crash ? "crash" : "error", point);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", setting, 1));
        int result = latcd_retirement_tombstone(root, source, name, fd, evidence,
                                                error, sizeof(error));
        assert(!crash && result < 0);
        close(fd);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    if (crash) assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    else assert(WIFEXITED(status) && !WEXITSTATUS(status));
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0 && !flock(fd, LOCK_EX | LOCK_NB));
    close(fd);
    char *marker = g_build_filename(root, ".gc", "tombstones", name, NULL);
    bool renamed = !strcmp(point, "renamed") || !strcmp(point, "directory-synced");
    assert((!access(marker, F_OK)) == renamed);
    if (renamed) {
        GKeyFile *record = g_key_file_new();
        assert(g_key_file_load_from_file(record, marker, 0, NULL));
        char *state = g_key_file_get_string(record, "tombstone", "state", NULL);
        assert(!g_strcmp0(state, "DELETING"));
        g_free(state);
        g_key_file_unref(record);
    }
    g_free(marker); g_free(evidence); g_free(path); g_free(name);
    remove_root(root); g_free(root);
}

static void test_empty_round_advance(void)
{
    char *root = root_new(), error[256];
    LatcdRetirementPageState state, loaded;
    simulated_boottime_us = 100;
    assert(!latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)));
    for (unsigned scenario = 0; scenario < 5; scenario++) {
        LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 100);
        assert(!latcd_retirement_queue_diagnostic_resume(queue, error, sizeof(error)));
        LatcdRetirementQueueStats stats;
        int result;
        do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
        while (result > 0);
        assert(result < 0);
        int shared = -1;
        char *added = NULL;
        simulated_boottime_us = scenario == 0 ? 100 : 101;
        if (scenario == 1) {
            shared = latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, sizeof(error));
            assert(shared >= 0);
        }
        if (scenario == 2) {
            added = g_build_filename(root, ".gc", "transactions", "unexpected", NULL);
            put(added, "unexpected");
        }
        if (scenario == 3) {
            added = g_build_filename(root, ".gc", ".write-unowned", NULL);
            put(added, "unowned");
        }
        result = latcd_retirement_queue_round_advance(queue, error, sizeof(error));
        assert(scenario == 4 ? !result : result < 0);
        if (shared >= 0) close(shared);
        if (added) { assert(!unlink(added)); g_free(added); }
        assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)));
        assert(loaded.round_cutoff == (scenario == 4 ? 101 : 100));
        assert(latcd_retirement_queue_round_advance(queue, error, sizeof(error)) < 0);
        latcd_retirement_queue_free(queue);
        simulated_boottime_us = 100;
    }
    simulated_boottime_us = 0;
    remove_root(root); g_free(root);
}

static void test_empty_round_advance_crash(const char *point)
{
    char *root = root_new(), error[256];
    LatcdRetirementPageState state, loaded;
    simulated_boottime_us = 100;
    assert(!latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 100);
        assert(!latcd_retirement_queue_diagnostic_resume(queue, error, sizeof(error)));
        LatcdRetirementQueueStats stats;
        int result;
        do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
        while (result > 0);
        assert(result < 0);
        simulated_boottime_us = 101;
        char *setting = g_strdup_printf("crash:%s", point);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", setting, 1));
        latcd_retirement_queue_round_advance(queue, error, sizeof(error));
        _exit(1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)));
    assert(loaded.round_cutoff == (!strcmp(point, "file-synced") ? 100 : 101));
    assert(!loaded.count && !loaded.cursor[0] && !loaded.committed_cursor[0]);
    simulated_boottime_us = 102;
    LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 100);
    assert(!latcd_retirement_queue_diagnostic_resume(queue, error, sizeof(error)));
    LatcdRetirementQueueStats stats;
    int result;
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0);
    if (!strcmp(point, "file-synced")) {
        assert(latcd_retirement_queue_round_advance(queue, error, sizeof(error)) < 0);
        latcd_retirement_queue_free(queue);
        char *gc = g_build_filename(root, ".gc", NULL);
        GDir *dir = g_dir_open(gc, 0, NULL);
        assert(dir);
        const char *name;
        unsigned removed = 0;
        while ((name = g_dir_read_name(dir))) {
            if (!g_str_has_prefix(name, ".write-")) continue;
            char *path = g_build_filename(gc, name, NULL);
            assert(!unlink(path));
            g_free(path);
            removed++;
        }
        assert(removed == 1);
        g_dir_close(dir); g_free(gc);
        queue = latcd_retirement_queue_new(root, 100);
        assert(!latcd_retirement_queue_diagnostic_resume(queue, error, sizeof(error)));
        do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
        while (result > 0);
        assert(result < 0);
    }
    assert(!latcd_retirement_queue_round_advance(queue, error, sizeof(error)));
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && loaded.round_cutoff == 102);
    latcd_retirement_queue_free(queue);
    simulated_boottime_us = 0;
    remove_root(root); g_free(root);
}

static void test_retry_page_stage_crash(const char *point)
{
    char *root = root_new(), error[256], *boot = NULL;
    simulated_boottime_us = 100;
    LatcdRetirementPageState state, loaded;
    assert(!latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *schedule = g_build_filename(gc, "retirement-schedule", NULL);
    char *transactions = g_build_filename(gc, "transactions", NULL);
    char *tombstones = g_build_filename(gc, "tombstones", NULL);
    assert(!mkdir(schedule, 0700) && !mkdir(transactions, 0700) && !mkdir(tombstones, 0700));
    LatcdRetirementPageDeadline hint = {.enqueued = 90, .last_attempt = 2, .retry_at = 99, .busy_count = 1};
    snprintf(hint.name, sizeof(hint.name), "%064x.so", 7);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 100, 3, &hint, error, sizeof(error)));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT; LatcdPageBudget budget = {0};
        assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
        latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
        LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 100);
        assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
        LatcdRetirementQueueStats stats; int result;
        do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
        while (result > 0);
        assert(result < 0);
        char *fault = g_strdup_printf("crash:%s", point);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
        latcd_retirement_queue_retry_page_stage(queue, &capacity, UINT64_MAX, &budget, error, sizeof(error));
        _exit(1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    if (!strcmp(point, "file-synced") || !strcmp(point, "linked")) {
        assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
               loaded.sequence == state.sequence && !loaded.count);
    } else {
        LatcdRetirementRetryPage *page = g_new0(LatcdRetirementRetryPage, 1);
        assert(!latcd_retirement_retry_page_load(root, page, error, sizeof(error)) &&
               page->count == 1 && !strcmp(page->items[0].hint.name, hint.name));
        assert(latcd_retirement_page_startup_check(root, error, sizeof(error)) < 0);
        g_free(page);
    }
    LatcdRetirementPageDeadline saved; uint64_t sequence;
    assert(!latcd_retirement_schedule_load(root, boot, 100, 100, hint.name, &sequence,
                                            &saved, error, sizeof(error)) && sequence == 3 &&
           saved.enqueued == hint.enqueued && saved.retry_at == hint.retry_at);
    if (!strcmp(point, "linked")) assert(latcd_retirement_page_startup_check(root, error, sizeof(error)) < 0);
    g_free(boot); g_free(tombstones); g_free(transactions); g_free(schedule); g_free(gc);
    simulated_boottime_us = 0;
    remove_root(root); g_free(root);
}

static void test_retry_page_stage(bool crash_commit)
{
    char *root = root_new(), error[256], *boot = NULL;
    simulated_boottime_us = 100;
    LatcdRetirementPageState state, loaded;
    assert(!latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *schedule = g_build_filename(gc, "retirement-schedule", NULL);
    char *transactions = g_build_filename(gc, "transactions", NULL);
    char *tombstones = g_build_filename(gc, "tombstones", NULL);
    assert(!mkdir(schedule, 0700) && !mkdir(transactions, 0700) && !mkdir(tombstones, 0700));
    LatcdRetirementPageDeadline hint = {.enqueued = 90, .last_attempt = 2, .retry_at = 99, .busy_count = 1};
    snprintf(hint.name, sizeof(hint.name), "%064x.so", 7);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 100, 3, &hint, error, sizeof(error)));
    LatcdRetirementPageDeadline second = hint;
    snprintf(second.name, sizeof(second.name), "%064x.so", 8);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 100, 3, &second, error, sizeof(error)));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 100);
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    LatcdRetirementQueueStats stats; int result;
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0 && latcd_retirement_queue_retry_page_stage(queue, &capacity, 1,
                                                                 &budget, error, sizeof(error)) < 0);
    assert(!budget.capacity && !latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)));
    latcd_retirement_queue_free(queue);
    queue = latcd_retirement_queue_new(root, 100);
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:file-synced", 1));
    assert(result < 0 && latcd_retirement_queue_retry_page_stage(queue, &capacity, UINT64_MAX,
                                                                 &budget, error, sizeof(error)) < 0);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(!budget.capacity && !latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)));
    latcd_retirement_queue_free(queue);
    queue = latcd_retirement_queue_new(root, 100);
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    retry_scan_hook_called = false; retry_scan_change = true;
    latcd_retirement_test_retry_scanned = retry_scan_hook;
    assert(result < 0 && latcd_retirement_queue_retry_page_stage(queue, &capacity, UINT64_MAX,
                                                                 &budget, error, sizeof(error)) < 0);
    latcd_retirement_test_retry_scanned = NULL; retry_scan_change = false;
    assert(retry_scan_hook_called && !budget.capacity &&
           !latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)));
    latcd_retirement_queue_free(queue);
    assert(!latcd_cache_capacity_poll(&capacity));
    latcd_cache_capacity_close(&capacity);
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    queue = latcd_retirement_queue_new(root, 100);
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    retry_scan_hook_called = false; retry_scan_hold = true;
    latcd_retirement_test_retry_scanned = retry_scan_hook;
    assert(result < 0 && latcd_retirement_queue_retry_page_stage(queue, &capacity, UINT64_MAX,
                                                                 &budget, error, sizeof(error)) < 0);
    latcd_retirement_test_retry_scanned = NULL; retry_scan_hold = false;
    assert(retry_scan_hook_called && retry_scan_held_fd >= 0 && !budget.capacity &&
           latcd_cache_capacity_poll(&capacity) &&
           !latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)));
    close(retry_scan_held_fd); retry_scan_held_fd = -1;
    latcd_retirement_queue_free(queue);
    queue = latcd_retirement_queue_new(root, 100);
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0);
    retry_scan_hook_called = false;
    latcd_retirement_test_retry_scanned = retry_scan_hook;
    assert(!latcd_retirement_queue_retry_page_stage(queue, &capacity, UINT64_MAX,
                                                   &budget, error, sizeof(error)));
    latcd_retirement_test_retry_scanned = NULL;
    assert(retry_scan_hook_called);
    LatcdRetirementRetryPage *page = g_new0(LatcdRetirementRetryPage, 1);
    assert(!latcd_retirement_retry_page_load(root, page, error, sizeof(error)) && page->count == 2 &&
           !strcmp(page->items[0].hint.name, hint.name) && page->round_sequence == state.sequence);
    char *original_name = g_strconcat(hint.name, ".ini", NULL);
    char *original_path = g_build_filename(schedule, original_name, NULL);
    char *original_data = NULL; gsize original_size = 0; uint8_t replacement[1024];
    assert(g_file_get_contents(original_path, &original_data, &original_size, NULL));
    assert(!latcd_retirement_retry_prepare_unmatched(page, original_data, original_size, 100, replacement));
    GKeyFile *replacement_record = g_key_file_new();
    assert(g_key_file_load_from_data(replacement_record, (char *)replacement, sizeof(replacement), 0, NULL));
    assert(g_key_file_get_uint64(replacement_record, "schedule", "retry_at", NULL) == 60000100 &&
           g_key_file_get_uint64(replacement_record, "schedule", "sequence", NULL) == 3 &&
           g_key_file_get_uint64(replacement_record, "schedule", "last_attempt", NULL) == 2);
    original_data[0] ^= 1;
    assert(latcd_retirement_retry_prepare_unmatched(page, original_data, original_size, 100, replacement) < 0);
    g_key_file_unref(replacement_record); g_free(original_data); g_free(original_path); g_free(original_name);
    assert(latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) < 0);
    assert(latcd_retirement_page_startup_check(root, error, sizeof(error)) < 0);
    assert(budget.capacity == &capacity && budget.page_identity_bound);
    latcd_retirement_queue_free(queue); latcd_cache_capacity_close(&capacity);
    LatcdCacheCapacity recovered = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget restored = {0};
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_retirement_retry_page_restore_budget(root, &recovered, UINT64_MAX, 100,
                                                       &restored, page, error, sizeof(error)));
    assert(restored.capacity == &recovered && page->count == 2 &&
           !latcd_cache_capacity_recovery_finish(&recovered));
    assert(!latcd_retirement_retry_page_begin_unmatched(root, &restored, error, sizeof(error)));
    assert(!latcd_retirement_retry_page_load(root, page, error, sizeof(error)) &&
           page->intent_present && page->intent_size == 1024 && !page->completed);
    assert(latcd_retirement_retry_page_begin_unmatched(root, &restored, error, sizeof(error)) < 0);
    latcd_cache_capacity_close(&recovered);
    LatcdCacheCapacity intent_recovered = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget intent_budget = {0};
    assert(!latcd_cache_capacity_scan(&intent_recovered, root, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_begin(&intent_recovered));
    latcd_cache_capacity_metadata_bind(&intent_recovered, UINT64_MAX);
    assert(!latcd_retirement_retry_page_restore_budget(root, &intent_recovered, UINT64_MAX, 100,
                                                       &intent_budget, page, error, sizeof(error)) &&
           page->intent_present && !latcd_cache_capacity_recovery_finish(&intent_recovered));
    assert(latcd_retirement_retry_page_finish_unmatched(root, &intent_budget, error, sizeof(error)) < 0);
    const char *apply_crashes[] = {"file-synced", "renamed"};
    for (unsigned i = 0; i < G_N_ELEMENTS(apply_crashes); i++) {
        pid_t child = fork();
        assert(child >= 0);
        if (!child) {
            char *fault = g_strdup_printf("crash:%s", apply_crashes[i]);
            assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
            latcd_retirement_retry_page_apply_unmatched(root, &intent_budget, error, sizeof(error));
            _exit(1);
        }
        int status;
        assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        latcd_cache_capacity_close(&intent_recovered);
        intent_recovered = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
        memset(&intent_budget, 0, sizeof(intent_budget));
        assert(!latcd_cache_capacity_scan(&intent_recovered, root, error, sizeof(error)));
        assert(!latcd_cache_capacity_recovery_begin(&intent_recovered));
        latcd_cache_capacity_metadata_bind(&intent_recovered, UINT64_MAX);
        assert(!latcd_retirement_retry_page_restore_budget(root, &intent_recovered, UINT64_MAX, 100,
                                                           &intent_budget, page, error, sizeof(error)) &&
               !latcd_cache_capacity_recovery_finish(&intent_recovered));
    }
    assert(!latcd_retirement_retry_page_apply_unmatched(root, &intent_budget, error, sizeof(error)));
    assert(!latcd_retirement_retry_page_apply_unmatched(root, &intent_budget, error, sizeof(error)));
    latcd_cache_capacity_close(&intent_recovered);
    char *shard_name = g_strconcat(hint.name, ".ini", NULL);
    char *shard_path = g_build_filename(schedule, shard_name, NULL);
    char *installed = NULL; gsize installed_size = 0;
    assert(g_file_get_contents(shard_path, &installed, &installed_size, NULL) &&
           installed_size == page->intent_size && !memcmp(installed, page->intent_data, installed_size));
    g_free(installed);
    LatcdCacheCapacity replaced = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget replaced_budget = {0};
    assert(!latcd_cache_capacity_scan(&replaced, root, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_begin(&replaced));
    latcd_cache_capacity_metadata_bind(&replaced, UINT64_MAX);
    assert(!latcd_retirement_retry_page_restore_budget(root, &replaced, UINT64_MAX, 100,
                                                       &replaced_budget, page, error, sizeof(error)) &&
           page->intent_present && !latcd_cache_capacity_recovery_finish(&replaced));
    struct stat schedule_stat;
    assert(!stat(schedule, &schedule_stat));
    retry_sync_device = schedule_stat.st_dev; retry_sync_inode = schedule_stat.st_ino;
    retry_sync_fault = true;
    assert(latcd_retirement_retry_page_finish_unmatched(root, &replaced_budget, error, sizeof(error)) < 0);
    retry_sync_fault = false;
    assert(!latcd_retirement_retry_page_load(root, page, error, sizeof(error)) &&
           page->intent_present && !page->completed && replaced_budget.invalid);
    latcd_cache_capacity_close(&replaced);
    replaced = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
    memset(&replaced_budget, 0, sizeof(replaced_budget));
    assert(!latcd_cache_capacity_scan(&replaced, root, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_begin(&replaced));
    latcd_cache_capacity_metadata_bind(&replaced, UINT64_MAX);
    assert(!latcd_retirement_retry_page_restore_budget(root, &replaced, UINT64_MAX, 100,
                                                       &replaced_budget, page, error, sizeof(error)) &&
           !latcd_cache_capacity_recovery_finish(&replaced));
    assert(!latcd_retirement_retry_page_apply_unmatched(root, &replaced_budget, error, sizeof(error)));
    pid_t finish_child = fork();
    assert(finish_child >= 0);
    if (!finish_child) {
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "crash:renamed", 1));
        latcd_retirement_retry_page_finish_unmatched(root, &replaced_budget, error, sizeof(error));
        _exit(1);
    }
    int finish_status;
    assert(waitpid(finish_child, &finish_status, 0) == finish_child &&
           WIFSIGNALED(finish_status) && WTERMSIG(finish_status) == SIGKILL);
    latcd_cache_capacity_close(&replaced);
    LatcdCacheCapacity completed = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget completed_budget = {0};
    assert(!latcd_cache_capacity_scan(&completed, root, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_begin(&completed));
    latcd_cache_capacity_metadata_bind(&completed, UINT64_MAX);
    assert(!latcd_retirement_retry_page_restore_budget(root, &completed, UINT64_MAX, 100,
                                                       &completed_budget, page, error, sizeof(error)) &&
           page->completed == 1 && !page->intent_present &&
           !latcd_cache_capacity_recovery_finish(&completed));
    assert(latcd_retirement_retry_page_commit(root, &completed_budget, error, sizeof(error)) < 0);
    assert(!latcd_retirement_retry_page_begin_unmatched(root, &completed_budget, error, sizeof(error)));
    assert(!latcd_retirement_retry_page_apply_unmatched(root, &completed_budget, error, sizeof(error)));
    assert(!latcd_retirement_retry_page_finish_unmatched(root, &completed_budget, error, sizeof(error)));
    assert(!latcd_retirement_retry_page_load(root, page, error, sizeof(error)) &&
           page->completed == 2 && !page->intent_present);
    assert(latcd_retirement_retry_page_begin_unmatched(root, &completed_budget, error, sizeof(error)) < 0);
    pid_t commit_child = fork();
    assert(commit_child >= 0);
    if (!commit_child) {
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "crash:file-synced", 1));
        latcd_retirement_retry_page_commit(root, &completed_budget, error, sizeof(error));
        _exit(1);
    }
    int commit_status;
    assert(waitpid(commit_child, &commit_status, 0) == commit_child &&
           WIFSIGNALED(commit_status) && WTERMSIG(commit_status) == SIGKILL);
    latcd_cache_capacity_close(&completed);
    char *saved_shard = NULL; gsize saved_size = 0;
    assert(g_file_get_contents(shard_path, &saved_shard, &saved_size, NULL));
    saved_shard[0] ^= 1;
    assert(g_file_set_contents(shard_path, saved_shard, saved_size, NULL));
    LatcdCacheCapacity changed_capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget changed_budget = {0};
    assert(!latcd_cache_capacity_scan(&changed_capacity, root, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_begin(&changed_capacity));
    latcd_cache_capacity_metadata_bind(&changed_capacity, UINT64_MAX);
    assert(latcd_retirement_retry_page_restore_budget(root, &changed_capacity, UINT64_MAX, 100,
                                                       &changed_budget, page, error, sizeof(error)) < 0 &&
           latcd_cache_capacity_recovery_finish(&changed_capacity) < 0);
    latcd_cache_capacity_close(&changed_capacity);
    saved_shard[0] ^= 1;
    assert(g_file_set_contents(shard_path, saved_shard, saved_size, NULL));
    g_free(saved_shard);
    completed = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
    memset(&completed_budget, 0, sizeof(completed_budget));
    assert(!latcd_cache_capacity_scan(&completed, root, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_begin(&completed));
    latcd_cache_capacity_metadata_bind(&completed, UINT64_MAX);
    assert(!latcd_retirement_retry_page_restore_budget(root, &completed, UINT64_MAX, 100,
                                                       &completed_budget, page, error, sizeof(error)) &&
           page->completed == 2 && !latcd_cache_capacity_recovery_finish(&completed));
    if (!crash_commit) {
        assert(!latcd_retirement_retry_page_commit(root, &completed_budget, error, sizeof(error)) &&
               !completed_budget.capacity);
    } else {
    commit_child = fork();
    assert(commit_child >= 0);
    if (!commit_child) {
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "crash:renamed", 1));
        latcd_retirement_retry_page_commit(root, &completed_budget, error, sizeof(error));
        _exit(1);
    }
    assert(waitpid(commit_child, &commit_status, 0) == commit_child &&
           WIFSIGNALED(commit_status) && WTERMSIG(commit_status) == SIGKILL);
    }
    latcd_cache_capacity_close(&completed);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
           !strcmp(loaded.retry_cursor, second.name) && !loaded.count &&
           loaded.sequence == state.sequence && !strcmp(loaded.committed_cursor, state.committed_cursor));
    assert(latcd_retirement_retry_page_load(root, page, error, sizeof(error)) < 0);
    GKeyFile *shard = g_key_file_new();
    assert(g_key_file_load_from_file(shard, shard_path, 0, NULL));
    g_key_file_set_uint64(shard, "schedule", "sequence", 4);
    char *changed = g_key_file_to_data(shard, NULL, NULL);
    put(shard_path, changed); g_free(changed); g_key_file_unref(shard);
    LatcdCacheCapacity rejected = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget rejected_budget = {0};
    assert(!latcd_cache_capacity_scan(&rejected, root, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_begin(&rejected));
    latcd_cache_capacity_metadata_bind(&rejected, UINT64_MAX);
    assert(latcd_retirement_retry_page_restore_budget(root, &rejected, UINT64_MAX, 100,
                                                      &rejected_budget, page, error, sizeof(error)) < 0);
    assert(!rejected_budget.capacity && latcd_cache_capacity_recovery_finish(&rejected) < 0);
    latcd_cache_capacity_close(&rejected); g_free(shard_path); g_free(shard_name);
    g_free(page); g_free(boot); g_free(tombstones); g_free(transactions); g_free(schedule); g_free(gc);
    simulated_boottime_us = 0;
    remove_root(root); g_free(root);
}

static void test_unmatched_retry_advance_crash(const char *point)
{
    char *root = root_new(), error[256], *boot = NULL;
    simulated_boottime_us = 100;
    LatcdRetirementPageState state, loaded;
    assert(!latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *schedule = g_build_filename(gc, "retirement-schedule", NULL);
    char *transactions = g_build_filename(gc, "transactions", NULL);
    char *tombstones = g_build_filename(gc, "tombstones", NULL);
    assert(!mkdir(schedule, 0700) && !mkdir(transactions, 0700) && !mkdir(tombstones, 0700));
    LatcdRetirementPageDeadline hint = {.enqueued = 90, .last_attempt = 2,
                                         .retry_at = 99, .busy_count = 1};
    snprintf(hint.name, sizeof(hint.name), "%064x.so", 7);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 100, 3, &hint, error, sizeof(error)));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 100);
        assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
        LatcdRetirementQueueStats stats;
        int result;
        do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
        while (result > 0);
        assert(result < 0);
        char *setting = g_strdup_printf("crash:%s", point);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", setting, 1));
        latcd_retirement_queue_retry_advance_unmatched(queue, error, sizeof(error));
        _exit(1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
           !loaded.count && !loaded.committed_cursor[0] &&
           !strcmp(loaded.retry_cursor, !strcmp(point, "file-synced") ? "" : hint.name));
    LatcdRetirementPageDeadline saved;
    uint64_t sequence;
    assert(!latcd_retirement_schedule_load(root, boot, 100, 100, hint.name, &sequence,
                                            &saved, error, sizeof(error)) && sequence == 3 &&
           saved.enqueued == hint.enqueued && saved.last_attempt == hint.last_attempt &&
           saved.retry_at == hint.retry_at && saved.busy_count == hint.busy_count);
    if (!strcmp(point, "file-synced")) {
        LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 100);
        assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
        LatcdRetirementQueueStats stats;
        int result;
        do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
        while (result > 0);
        assert(result < 0 && latcd_retirement_queue_retry_advance_unmatched(queue, error, sizeof(error)) < 0);
        latcd_retirement_queue_free(queue);
    }
    g_free(boot); g_free(tombstones); g_free(transactions); g_free(schedule); g_free(gc);
    simulated_boottime_us = 0;
    remove_root(root); g_free(root);
}

static void test_page_round_begin(const char *point, bool crash)
{
    char *root = root_new(), error[256];
    LatcdRetirementPageState state, loaded;
    simulated_boottime_us = 1234;
    if (!point) {
        int shared = latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, sizeof(error));
        assert(shared >= 0);
        assert(latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)) < 0);
        assert(!state.round_cutoff);
        close(shared);
        LatcdRetirementPublication *publication =
            latcd_retirement_publication_open(root, error, sizeof(error));
        assert(publication);
        assert(latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)) < 0);
        assert(!latcd_retirement_publication_prepare(publication, source, next, strlen(next), NULL,
                                                     error, sizeof(error)));
        assert(latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)) < 0);
        char *current = current_path(root);
        put(current, next);
        assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
        assert(latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)) < 0);
        latcd_retirement_publication_close(publication);
        g_free(current);
        assert(!latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)));
        assert(state.round_cutoff == 1234 && state.grace_us == 100 && !state.count);
        assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)));
        assert(loaded.round_cutoff == state.round_cutoff && !strcmp(loaded.boot, state.boot));
        simulated_boottime_us++;
        assert(latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)) < 0);
        assert(!state.round_cutoff);
        assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)));
        assert(loaded.round_cutoff == 1234);
        loaded.cache_inode++;
        assert(latcd_retirement_page_state_store(root, &loaded, error, sizeof(error)) < 0);
        assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)));
        assert(loaded.round_cutoff == 1234);
    } else {
        pid_t child = fork();
        assert(child >= 0);
        if (!child) {
            char *fault = g_strdup_printf("%s:%s", crash ? "crash" : "error", point);
            assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
            int result = latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error));
            assert(!crash && result < 0 && !state.round_cutoff);
            _exit(0);
        }
        int status;
        assert(waitpid(child, &status, 0) == child);
        if (crash) assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        else assert(WIFEXITED(status) && !WEXITSTATUS(status));
        int loaded_result = latcd_retirement_page_state_load(root, &loaded, error, sizeof(error));
        assert(loaded_result == 1 || (!loaded_result && loaded.round_cutoff == 1234));
        if (loaded_result == 1)
            assert(!latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)));
        else
            assert(latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)) < 0);
    }
    simulated_boottime_us = 0;
    remove_root(root); g_free(root);
}

static void test_page_identity(void)
{
    LatcdRetirementPageState state = {.cache_device = 1, .cache_inode = 2,
        .grace_us = 3, .round_cutoff = 4, .sequence = 5, .count = 1};
    g_strlcpy(state.boot, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", sizeof(state.boot));
    snprintf(state.entries[0].name, sizeof(state.entries[0].name), "%s.so", source);
    g_strlcpy(state.cursor, state.entries[0].name, sizeof(state.cursor));
    state.entries[0].deadline = 6;
    state.entries[0].enqueued = 1;
    uint8_t identity[32], other[32];
    assert(!latcd_retirement_page_identity(&state, identity));
    const uint8_t expected[32] = {
        0x85, 0x65, 0x1a, 0x93, 0x33, 0xe3, 0xc6, 0xb1,
        0x6a, 0x2e, 0x7d, 0x50, 0xca, 0x8f, 0xa7, 0xa5,
        0x4c, 0x82, 0x37, 0x6d, 0xc3, 0xf4, 0x94, 0x4b,
        0x0a, 0xd8, 0x09, 0xa4, 0x9b, 0x6f, 0x89, 0xc7,
    };
    assert(!memcmp(identity, expected, sizeof(expected)));
    uint8_t budget_identity[32], budget_other[32];
    assert(!latcd_retirement_page_budget_identity(&state, budget_identity));
    assert(!latcd_retirement_page_budget_identity(&state, budget_other) &&
           !memcmp(budget_identity, budget_other, 32));
    state.sequence++;
    assert(!latcd_retirement_page_budget_identity(&state, budget_other) &&
           memcmp(budget_identity, budget_other, 32));
    state.sequence--;
    state.entries[0].enqueued++;
    assert(!latcd_retirement_page_budget_identity(&state, budget_other) &&
           memcmp(budget_identity, budget_other, 32));
    state.entries[0].enqueued--;
    state.committed_pending = true;
    memset(budget_other, 0xff, sizeof(budget_other));
    assert(latcd_retirement_page_budget_identity(&state, budget_other) < 0);
    for (unsigned i = 0; i < sizeof(budget_other); i++) assert(!budget_other[i]);
    state.results[0] = LATCD_RETIREMENT_RESULT_DEFERRED;
    state.entries[0].last_attempt = 5;
    state.entries[0].retry_at = 9;
    state.entries[0].busy_count = 1;
    assert(!latcd_retirement_page_budget_identity(&state, budget_other) &&
           !memcmp(budget_identity, budget_other, 32));
    state.entries[0].enqueued++;
    assert(!latcd_retirement_page_budget_identity(&state, budget_other) &&
           memcmp(budget_identity, budget_other, 32));
    state.entries[0].enqueued--;
    state.results[0] = 0;
    state.committed_pending = false;
    state.sequence = 8; state.entries[0].last_attempt = 7;
    state.entries[0].retry_at = 9; state.entries[0].busy_count = 1;
    assert(!latcd_retirement_page_identity(&state, other) && !memcmp(identity, other, 32));
    state.entries[0].deadline++;
    assert(!latcd_retirement_page_identity(&state, other) && memcmp(identity, other, 32));
    state.entries[0].deadline--;
    state.round_cutoff++;
    assert(!latcd_retirement_page_identity(&state, other) && memcmp(identity, other, 32));
    state.round_cutoff--;
    state.cache_inode++;
    assert(!latcd_retirement_page_identity(&state, other) && memcmp(identity, other, 32));
    state.cache_inode--;
    state.grace_us++;
    assert(!latcd_retirement_page_identity(&state, other) && memcmp(identity, other, 32));
    state.grace_us--;
    state.boot[0] = 'b';
    assert(!latcd_retirement_page_identity(&state, other) && memcmp(identity, other, 32));
    state.boot[0] = 'a';
    state.count = 2;
    snprintf(state.entries[1].name, sizeof(state.entries[1].name), "%s.tbset", source);
    state.entries[1].deadline = 6; state.entries[1].enqueued = 1;
    g_strlcpy(state.cursor, state.entries[1].name, sizeof(state.cursor));
    assert(!latcd_retirement_page_identity(&state, other) && memcmp(identity, other, 32));
    state.count = 1;
    g_strlcpy(state.cursor, state.entries[0].name, sizeof(state.cursor));
    state.entries[0].name[0] = 'z';
    memset(other, 1, sizeof(other));
    assert(latcd_retirement_page_identity(&state, other) < 0);
    for (unsigned i = 0; i < sizeof(other); i++) assert(!other[i]);
}

static void test_schedule_store(void)
{
    char *root = root_new(), error[256];
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    char *boot = NULL;
    gsize size;
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, &size, NULL));
    g_strchomp(boot);
    LatcdRetirementPageDeadline entry = { .enqueued = 100, .last_attempt = 1,
                                           .retry_at = 200, .busy_count = 1 };
    snprintf(entry.name, sizeof(entry.name), "%s.so", source);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 1, &entry, error, sizeof(error)));
    LatcdRetirementPageDeadline loaded;
    uint64_t loaded_sequence;
    assert(!latcd_retirement_schedule_load(root, boot, 100, 150, entry.name,
                                           &loaded_sequence, &loaded, error, sizeof(error)));
    assert(loaded_sequence == 1 && !strcmp(loaded.name, entry.name) &&
           loaded.enqueued == 100 && loaded.last_attempt == 1 &&
           loaded.retry_at == 200 && loaded.busy_count == 1);
    LatcdRetirementPageState page = {.count = 1};
    page.entries[0] = entry;
    page.entries[0].deadline = 900;
    page.entries[0].enqueued = 150;
    assert(!latcd_retirement_schedule_merge_page(root, boot, 100, 150, &page, error, sizeof(error)));
    assert(page.entries[0].deadline == 900 && page.entries[0].enqueued == 100 &&
           page.entries[0].retry_at == 200 && page.sequence == 1);
    LatcdRetirementPageState snapshot = page;
    assert(latcd_retirement_schedule_merge_page(root, boot, 101, 150, &page, error, sizeof(error)) < 0);
    assert(!memcmp(&page, &snapshot, sizeof(page)));
    schedule_scan_mutation = store;
    assert(latcd_retirement_schedule_merge_page(root, boot, 100, 150, &page, error, sizeof(error)) < 0);
    assert(!schedule_scan_mutation && !memcmp(&page, &snapshot, sizeof(page)));
    assert(!latcd_retirement_schedule_load(root, boot, 100, 150, loaded.name,
                                           &loaded_sequence, &loaded, error, sizeof(error)));
    assert(loaded_sequence == 1 && !strcmp(loaded.name, entry.name));
    memset(loaded.name, 'a', sizeof(loaded.name));
    loaded_sequence = 99;
    assert(latcd_retirement_schedule_load(root, boot, 100, 150, loaded.name,
                                           &loaded_sequence, &loaded, error, sizeof(error)) < 0);
    assert(!loaded_sequence && !loaded.name[0]);
    char *missing = g_strdup_printf("%064x.so", 1);
    assert(latcd_retirement_schedule_load(root, boot, 100, 150, missing,
                                           &loaded_sequence, &loaded, error, sizeof(error)) == 1);
    assert(!loaded_sequence && !loaded.name[0]);
    assert(latcd_retirement_schedule_load(root, boot, 101, 150, entry.name,
                                           &loaded_sequence, &loaded, error, sizeof(error)) < 0);
    assert(!loaded_sequence && !loaded.name[0]);
    g_free(missing);
    char *filename = g_strconcat(entry.name, ".ini", NULL);
    char *path = g_build_filename(store, filename, NULL), *before = NULL, *after = NULL;
    struct stat shard_stat;
    assert(!stat(path, &shard_stat) && shard_stat.st_size == 1024);
    assert(g_file_get_contents(path, &before, NULL, NULL));
    entry.busy_count = 2;
    entry.last_attempt = 2;
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:file-synced", 1));
    errno = 0;
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error)) < 0);
    assert(errno == EIO);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(g_file_get_contents(path, &after, NULL, NULL) && !strcmp(before, after));
    g_free(after);
    assert(latcd_retirement_schedule_store(root, boot, 101, 150, 1, &entry, error, sizeof(error)) < 0);
    char *other_boot = g_uuid_string_random();
    assert(latcd_retirement_schedule_store(root, other_boot, 100, 150, 1, &entry, error, sizeof(error)) < 0);
    g_free(other_boot);
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:renamed", 1));
    errno = 0;
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error)) < 0);
    assert(errno == EIO);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    GKeyFile *renamed = g_key_file_new();
    assert(g_key_file_load_from_file(renamed, path, 0, NULL));
    assert(g_key_file_get_uint64(renamed, "schedule", "last_attempt", NULL) == 2);
    assert(g_key_file_get_uint64(renamed, "schedule", "busy_count", NULL) == 2);
    g_key_file_unref(renamed);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error)));
    entry.retry_at = 151;
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error)) < 0);
    entry.retry_at = 200;
    assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error)));
    g_free(before);
    assert(g_file_get_contents(path, &before, NULL, NULL));
    entry.last_attempt = 3;
    schedule_scan_mutation = store;
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 3, &entry, error, sizeof(error)) < 0);
    assert(!schedule_scan_mutation);
    assert(g_file_get_contents(path, &after, NULL, NULL) && !strcmp(before, after));
    g_free(after);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 3, &entry, error, sizeof(error)));
    entry.last_attempt = 4;
    schedule_scan_mutation = store;
    schedule_mutation_file = path;
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 4, &entry, error, sizeof(error)) < 0);
    assert(!schedule_scan_mutation && !schedule_mutation_file);
    assert(g_file_get_contents(path, &after, NULL, NULL) && after[0] == 'X');
    g_free(after);
    put(path, before);
    char *saved_read = g_strconcat(path, ".saved", NULL);
    char *replacement_read = g_strconcat(path, ".replacement", NULL);
    int read_dir = open(store, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    char *read_name = g_path_get_basename(path), *snapshot_data = NULL;
    size_t snapshot_size = 0;
    struct stat read_snapshot, actual;
    uint8_t digest[32];
    assert(read_dir >= 0 && !latcd_retirement_test_read_snapshot(read_dir, read_name, 1024,
               &snapshot_data, &snapshot_size, &read_snapshot, digest));
    assert(!stat(path, &actual) && read_snapshot.st_ino == actual.st_ino && read_snapshot.st_size == actual.st_size);
    char *expected_hash = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                         (const guchar *)snapshot_data, snapshot_size);
    char actual_hash[65];
    for (unsigned i = 0; i < 32; i++) snprintf(actual_hash + i * 2, 3, "%02x", digest[i]);
    assert(!strcmp(actual_hash, expected_hash));
    g_free(expected_hash); g_free(snapshot_data);
    put(replacement_read, before);
    read_target = path; read_saved = saved_read; read_replacement = replacement_read;
    latcd_retirement_test_after_read = replace_read_target;
    memset(&read_snapshot, 0xff, sizeof(read_snapshot)); memset(digest, 0xff, sizeof(digest));
    assert(latcd_retirement_test_read_snapshot(read_dir, read_name, 1024,
               &snapshot_data, &snapshot_size, &read_snapshot, digest) < 0);
    assert(!snapshot_data && !snapshot_size && !read_snapshot.st_ino);
    for (unsigned i = 0; i < 32; i++) assert(!digest[i]);
    assert(!unlink(path) && !rename(saved_read, path));
    put(replacement_read, before);
    latcd_retirement_test_after_read = replace_read_target;
    loaded_sequence = UINT64_MAX;
    memset(&loaded, 0xff, sizeof(loaded));
    assert(latcd_retirement_schedule_load(root, boot, 100, 150, entry.name,
                                           &loaded_sequence, &loaded, error, sizeof(error)) < 0);
    assert(!latcd_retirement_test_after_read && !loaded_sequence && !loaded.name[0]);
    assert(!unlink(path) && !rename(saved_read, path));
    close(read_dir); g_free(read_name);
    g_free(saved_read); g_free(replacement_read);
    entry.last_attempt = 0;
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 1, &entry, error, sizeof(error)) < 0);
    entry.last_attempt = 2;
    entry.enqueued = 99;
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 1, &entry, error, sizeof(error)) < 0);
    entry.enqueued = 100;
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 0, &entry, error, sizeof(error)) < 0);
    LatcdRetirementPageDeadline invalid = entry;
    memset(invalid.name, 'a', sizeof(invalid.name));
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 1, &invalid, error, sizeof(error)) < 0);
    char *bad = g_build_filename(store, "unknown", NULL);
    put(bad, "invalid\n");
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 1, &entry, error, sizeof(error)) < 0);
    assert(latcd_retirement_schedule_load(root, boot, 100, 150, entry.name,
                                           &loaded_sequence, &loaded, error, sizeof(error)) < 0);
    assert(!loaded_sequence && !loaded.name[0]);
    g_free(bad); g_free(before); g_free(path); g_free(filename); g_free(boot);
    g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_schedule_result_upgrade(void)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageDeadline entry = {.enqueued = 100, .last_attempt = 1,
                                         .retry_at = 200, .busy_count = 1};
    snprintf(entry.name, sizeof(entry.name), "%s.so", source);
    uint8_t identity[32] = {1};
    assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 1, &entry, error, sizeof(error)));
    LatcdRetirementResultKind kind = LATCD_RETIREMENT_RESULT_DONE;
    assert(latcd_retirement_schedule_load_result(root, boot, 100, 150, entry.name, identity,
                                                  &kind, error, sizeof(error)) == 1 && !kind);
    char *filename = g_strconcat(entry.name, ".ini", NULL);
    char *path = g_build_filename(store, filename, NULL), *before = NULL, *after = NULL;
    assert(g_file_get_contents(path, &before, NULL, NULL));
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:file-synced", 1));
    assert(latcd_retirement_schedule_store_result(root, boot, 100, 150, 1, &entry, identity,
           LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)) < 0);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(g_file_get_contents(path, &after, NULL, NULL) && !strcmp(before, after));
    g_free(after);
    assert(!latcd_retirement_schedule_store_result(root, boot, 100, 150, 1, &entry, identity,
           LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
    assert(!latcd_retirement_schedule_load_result(root, boot, 100, 150, entry.name, identity,
                                                   &kind, error, sizeof(error)) &&
           kind == LATCD_RETIREMENT_RESULT_DEFERRED);
    uint8_t other[32] = {2};
    assert(latcd_retirement_schedule_load_result(root, boot, 100, 150, entry.name, other,
                                                  &kind, error, sizeof(error)) == 1 && !kind);
    schedule_scan_mutation = store;
    kind = LATCD_RETIREMENT_RESULT_DONE;
    assert(latcd_retirement_schedule_load_result(root, boot, 100, 150, entry.name, identity,
                                                  &kind, error, sizeof(error)) < 0 && !kind);
    LatcdRetirementPageDeadline loaded;
    uint64_t sequence;
    assert(!latcd_retirement_schedule_load(root, boot, 100, 150, entry.name,
                                           &sequence, &loaded, error, sizeof(error)));
    assert(sequence == 1 && loaded.enqueued == 100 && loaded.retry_at == 200 && loaded.busy_count == 1);
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 1, &entry, error, sizeof(error)) < 0);
    GKeyFile *record = g_key_file_new();
    assert(g_key_file_load_from_file(record, path, 0, NULL));
    char *digest = g_key_file_get_string(record, "schedule", "page_identity", NULL);
    char *result = g_key_file_get_string(record, "schedule", "result", NULL);
    assert(digest && strlen(digest) == 64 && !strncmp(digest, "01", 2));
    assert(result && !strcmp(result, "deferred"));
    g_free(digest); g_free(result); g_key_file_unref(record);
    put(path, "[schedule]\nversion=2\n");
    kind = LATCD_RETIREMENT_RESULT_DONE;
    assert(latcd_retirement_schedule_load_result(root, boot, 100, 150, entry.name, identity,
                                                  &kind, error, sizeof(error)) < 0 && !kind);
    g_free(before); g_free(path); g_free(filename); g_free(boot);
    g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_schedule_check_page(void)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    struct stat st;
    assert(!stat(root, &st));
    LatcdRetirementPageState page = {.cache_device = st.st_dev, .cache_inode = st.st_ino,
        .grace_us = 100, .round_cutoff = 120, .sequence = 1, .count = 2};
    g_strlcpy(page.boot, boot, sizeof(page.boot));
    for (unsigned i = 0; i < page.count; i++) {
        snprintf(page.entries[i].name, sizeof(page.entries[i].name), "%064x.so", i + 1);
        page.entries[i].deadline = 140;
        page.entries[i].enqueued = 100;
        page.entries[i].last_attempt = 1;
    }
    page.entries[1].retry_at = 200;
    page.entries[1].busy_count = 2;
    g_strlcpy(page.cursor, page.entries[1].name, sizeof(page.cursor));
    uint8_t identity[32];
    assert(!latcd_retirement_page_identity(&page, identity));
    assert(latcd_retirement_schedule_check_page(root, 150, &page, error, sizeof(error)) == 1);
    uint8_t results[128];
    memset(results, 0xff, sizeof(results));
    assert(latcd_retirement_schedule_page_results(root, 150, &page, results, error, sizeof(error)) == 1);
    for (unsigned i = 0; i < sizeof(results); i++) assert(!results[i]);
    char *replacement = root_new();
    char *replacement_gc = g_build_filename(replacement, ".gc", NULL);
    char *replacement_store = g_build_filename(replacement_gc, "retirement-schedule", NULL);
    char *old_root = g_strconcat(root, ".old", NULL);
    char *filename = g_strconcat(page.entries[0].name, ".ini", NULL);
    assert(!mkdir(replacement_gc, 0700) && !mkdir(replacement_store, 0700));
    page_lstat_swap_path = root; page_lstat_swap_old = old_root; page_lstat_swap_new = replacement;
    assert(latcd_retirement_test_store_page_result(root, 150, &page, &page.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(!page_lstat_swap_path);
    char *new_record = g_build_filename(root, ".gc", "retirement-schedule", filename, NULL);
    char *old_record = g_build_filename(old_root, ".gc", "retirement-schedule", filename, NULL);
    assert(access(new_record, F_OK) && access(old_record, F_OK));
    assert(!rename(root, replacement) && !rename(old_root, root));
    remove_root(replacement);
    g_free(old_record); g_free(new_record); g_free(filename); g_free(old_root);
    g_free(replacement_store); g_free(replacement_gc); g_free(replacement);
    assert(latcd_retirement_test_store_page_result(root, 150, &page, &page.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(!latcd_retirement_page_state_store(root, &page, error, sizeof(error)));
    LatcdRetirementPageState snapshot_page;
    LatcdRetirementPageInventory inventory;
    assert(latcd_retirement_page_snapshot(root, 150, &snapshot_page, results, &inventory, error, sizeof(error)) == 1);
    assert(snapshot_page.count == 2 && !results[0] && !results[1]);
    assert(!inventory.occupied_slots && !inventory.occupied_bytes && !inventory.undersized_member);
    LatcdCacheCapacity page_capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget page_budget = {0};
    uint8_t budget_binding[32];
    char *other_root = root_new();
    LatcdCacheCapacity other_capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&other_capacity, other_root, error, sizeof(error)));
    assert(latcd_retirement_test_page_reserve(root, 150, &other_capacity, UINT64_MAX,
                                               &page_budget, budget_binding, error, sizeof(error)) < 0);
    assert(!page_budget.capacity && !other_capacity.metadata_reserved);
    latcd_cache_capacity_close(&other_capacity);
    assert(!pthread_mutex_destroy(&other_capacity.lock));
    remove_root(other_root); g_free(other_root);
    assert(!latcd_cache_capacity_scan(&page_capacity, root, error, sizeof(error)));
    assert(latcd_retirement_test_page_reserve(root, 150, &page_capacity, 1, &page_budget, budget_binding, error, sizeof(error)) < 0);
    assert(!page_budget.capacity && !page_capacity.metadata_reserved);
    assert(!latcd_retirement_test_page_reserve(root, 150, &page_capacity, UINT64_MAX, &page_budget, budget_binding, error, sizeof(error)));
    assert(page_budget.remaining == 2 * 1024 + 2 * 65536 &&
           page_capacity.metadata_reserved == page_budget.remaining);
    uint8_t saved_binding[32];
    memcpy(saved_binding, budget_binding, sizeof(saved_binding));
    uint64_t saved_reservation = page_budget.remaining;
    assert(latcd_retirement_test_page_reserve(root, 150, &page_capacity, UINT64_MAX,
                                               &page_budget, budget_binding, error, sizeof(error)) < 0);
    assert(errno == EBUSY && !memcmp(saved_binding, budget_binding, sizeof(saved_binding)) &&
           page_budget.remaining == saved_reservation && page_capacity.metadata_reserved == saved_reservation);
    assert(!latcd_retirement_test_page_budget_matches(root, budget_binding, error, sizeof(error)));
    LatcdRetirementPageState changed_binding = page;
    changed_binding.sequence++;
    latcd_cache_capacity_metadata_bind(&page_capacity, UINT64_MAX);
    assert(!latcd_retirement_page_state_store(root, &changed_binding, error, sizeof(error)));
    assert(latcd_retirement_test_page_budget_matches(root, budget_binding, error, sizeof(error)) < 0);
    assert(latcd_retirement_test_budget_result(root, 150, budget_binding, &page_budget,
           &page.entries[0], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(page_budget.remaining == saved_reservation && page_capacity.ready);
    uint8_t changed_identity[32];
    assert(!latcd_retirement_page_budget_identity(&changed_binding, changed_identity));
    assert(latcd_retirement_test_budget_result(root, 150, changed_identity, &page_budget,
           &page.entries[0], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(page_budget.remaining == saved_reservation && page_capacity.ready);
    assert(!latcd_retirement_page_state_store(root, &page, error, sizeof(error)));
    assert(!latcd_retirement_test_page_budget_matches(root, budget_binding, error, sizeof(error)));
    assert(latcd_retirement_test_bound_budget_result(root, 150, budget_binding, &page_budget,
           &page.entries[0], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    LatcdRetirementPageState claimed_bound = page;
    claimed_bound.budget_bound = true;
    assert(latcd_retirement_page_budget_commit(root, 150, &claimed_bound, &page_budget,
                                                error, sizeof(error)) < 0);
    assert(page_budget.remaining == saved_reservation && page_capacity.ready);
    int budget_scheduler = open(gc, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(budget_scheduler >= 0 && !flock(budget_scheduler, LOCK_EX | LOCK_NB));
    assert(latcd_retirement_test_budget_result(root, 150, budget_binding, &page_budget,
           &page.entries[0], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(page_budget.remaining == saved_reservation && page_capacity.ready);
    close(budget_scheduler);
    LatcdRetirementPageDeadline nonmember = page.entries[0];
    nonmember.enqueued++;
    assert(latcd_retirement_test_budget_result(root, 150, budget_binding, &page_budget,
           &nonmember, LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(page_budget.remaining == saved_reservation && page_capacity.ready);
    char *not_written = g_strconcat(page.entries[0].name, ".ini", NULL);
    char *not_written_path = g_build_filename(store, not_written, NULL);
    assert(access(not_written_path, F_OK) && errno == ENOENT);
    g_free(not_written_path); g_free(not_written);
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:file-synced", 1));
    assert(latcd_retirement_test_budget_result(root, 150, budget_binding, &page_budget,
           &page.entries[0], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(page_budget.remaining == saved_reservation && page_capacity.ready);
    assert(!latcd_retirement_test_budget_result(root, 150, budget_binding, &page_budget,
           &page.entries[0], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)));
    assert(page_budget.remaining == saved_reservation - 1024 && page_capacity.ready);
    LatcdPageBudget copy = page_budget;
    assert(latcd_retirement_test_budget_result(root, 150, budget_binding, &copy,
           &page.entries[0], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(page_budget.remaining == saved_reservation - 1024 && page_capacity.ready);
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:created", 1));
    assert(!latcd_retirement_test_budget_result(root, 150, budget_binding, &page_budget,
           &page.entries[0], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)));
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(page_budget.remaining == saved_reservation - 1024 && page_capacity.ready);
    uint64_t committed_before_fault = page_capacity.metadata_committed;
    int fd_before = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(fd_before >= 0);
    close(fd_before);
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:renamed", 1));
    assert(latcd_retirement_test_budget_result(root, 150, budget_binding, &page_budget,
           &page.entries[1], LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)) < 0);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    int fd_after = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(fd_after == fd_before);
    close(fd_after);
    assert(!latcd_cache_capacity_poll(&page_capacity) && page_budget.invalid &&
           page_budget.remaining == saved_reservation - 2048 &&
           page_capacity.metadata_committed == committed_before_fault + 1024);
    uint64_t invalid_remaining = page_budget.remaining;
    uint64_t invalid_committed = page_capacity.metadata_committed;
    assert(latcd_retirement_test_budget_result(root, 150, budget_binding, &page_budget,
           &page.entries[0], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(!page_capacity.ready && page_budget.invalid &&
           page_budget.remaining == invalid_remaining &&
           page_capacity.metadata_committed == invalid_committed);
    char *fault_name = g_strconcat(page.entries[1].name, ".ini", NULL);
    char *fault_path = g_build_filename(store, fault_name, NULL);
    assert(!access(fault_path, F_OK));
    assert(!latcd_cache_capacity_test_page_abandon(&page_capacity, &page_budget));
    latcd_cache_capacity_close(&page_capacity);
    assert(!latcd_cache_capacity_scan(&page_capacity, root, error, sizeof(error)));
    assert(page_capacity.metadata_committed == committed_before_fault + 1024);
    latcd_cache_capacity_close(&page_capacity);
    assert(!unlink(fault_path));
    assert(!latcd_cache_capacity_scan(&page_capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&page_capacity, UINT64_MAX);
    assert(!latcd_retirement_test_page_reserve(root, 150, &page_capacity, UINT64_MAX,
                                               &page_budget, budget_binding, error, sizeof(error)));
    /* Re-inventory charged the surviving result; only the missing result and
     * checkpoint/retry headroom need a fresh reservation. */
    assert(page_budget.remaining == 1024 + 2 * 65536 &&
           page_capacity.metadata_reserved == page_budget.remaining);
    uint64_t recovered_committed = page_capacity.metadata_committed;
    assert(!latcd_retirement_test_budget_result(root, 150, budget_binding, &page_budget,
           &page.entries[1], LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
    assert(page_budget.remaining == 2 * 65536 &&
           page_capacity.metadata_committed == recovered_committed + 1024);
    assert(!latcd_retirement_test_budget_result(root, 150, budget_binding, &page_budget,
           &page.entries[1], LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
    assert(page_budget.remaining == 2 * 65536 &&
           page_capacity.metadata_committed == recovered_committed + 1024);
    uint64_t checkpoint_budget = page_budget.remaining;
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:file-synced", 1));
    assert(latcd_retirement_test_budget_commit(root, 150, &page, &page_budget,
                                                error, sizeof(error)) < 0);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(page_capacity.ready && page_budget.remaining == checkpoint_budget);
    LatcdRetirementPageState checkpoint;
    assert(!latcd_retirement_page_state_load(root, &checkpoint, error, sizeof(error)) &&
           !checkpoint.committed_pending);
    assert(!latcd_retirement_test_budget_commit(root, 150, &page, &page_budget,
                                                 error, sizeof(error)));
    assert(!latcd_retirement_page_state_load(root, &checkpoint, error, sizeof(error)) &&
           checkpoint.committed_pending && page_capacity.ready);
    assert(latcd_retirement_test_budget_result(root, 150, budget_binding, &page_budget,
           &page.entries[0], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(latcd_retirement_test_budget_commit(root, 150, &page, &page_budget,
                                                error, sizeof(error)) < 0);
    assert(!latcd_cache_capacity_test_page_release(&page_capacity, &page_budget));
    assert(!latcd_retirement_page_state_store(root, &page, error, sizeof(error)));
    assert(!latcd_retirement_test_page_reserve(root, 150, &page_capacity, UINT64_MAX,
                                               &page_budget, budget_binding, error, sizeof(error)));
    char *unexpected = g_build_filename(gc, "unexpected-settlement", NULL);
    settlement_unexpected = unexpected;
    latcd_retirement_test_before_settlement = invalidate_settlement;
    errno = ENOENT;
    assert(latcd_retirement_test_budget_commit(root, 150, &page, &page_budget,
                                                error, sizeof(error)) < 0);
    assert(errno == EIO);
    assert(!latcd_retirement_test_before_settlement && !latcd_cache_capacity_poll(&page_capacity) &&
           page_budget.invalid);
    assert(!latcd_retirement_page_state_load(root, &checkpoint, error, sizeof(error)) &&
           checkpoint.committed_pending);
    assert(!latcd_cache_capacity_test_page_abandon(&page_capacity, &page_budget));
    latcd_cache_capacity_close(&page_capacity);
    assert(!unlink(unexpected));
    g_free(unexpected);
    assert(!latcd_retirement_page_state_store(root, &page, error, sizeof(error)));
    assert(!latcd_cache_capacity_scan(&page_capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&page_capacity, UINT64_MAX);
    assert(!latcd_retirement_test_page_reserve(root, 150, &page_capacity, UINT64_MAX,
                                               &page_budget, budget_binding, error, sizeof(error)));
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:renamed", 1));
    assert(latcd_retirement_test_budget_commit(root, 150, &page, &page_budget,
                                                error, sizeof(error)) < 0);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(!latcd_cache_capacity_poll(&page_capacity) && page_budget.invalid);
    assert(!latcd_retirement_page_state_load(root, &checkpoint, error, sizeof(error)) &&
           checkpoint.committed_pending);
    assert(!latcd_cache_capacity_test_page_abandon(&page_capacity, &page_budget));
    latcd_cache_capacity_close(&page_capacity);
    assert(!latcd_retirement_page_state_store(root, &page, error, sizeof(error)));
    assert(!latcd_cache_capacity_scan(&page_capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&page_capacity, UINT64_MAX);
    assert(!latcd_retirement_test_page_reserve(root, 150, &page_capacity, UINT64_MAX,
                                               &page_budget, budget_binding, error, sizeof(error)));
    g_free(fault_path); g_free(fault_name);
    char *budget_result_name = g_strconcat(page.entries[0].name, ".ini", NULL);
    char *budget_result_path = g_build_filename(store, budget_result_name, NULL);
    char *recovered_name = g_strconcat(page.entries[1].name, ".ini", NULL);
    char *recovered_path = g_build_filename(store, recovered_name, NULL);
    assert(!latcd_cache_capacity_test_page_release(&page_capacity, &page_budget));
    /* Fixture cleanup is external to the budget protocol. */
    latcd_cache_capacity_close(&page_capacity);
    assert(!unlink(budget_result_path));
    assert(!unlink(recovered_path));
    pid_t budget_child = fork();
    assert(budget_child >= 0);
    if (!budget_child) {
        LatcdCacheCapacity crash_capacity = LATCD_CACHE_CAPACITY_INIT;
        LatcdPageBudget crash_budget = {0};
        uint8_t crash_binding[32];
        assert(!latcd_cache_capacity_scan(&crash_capacity, root, error, sizeof(error)));
        latcd_cache_capacity_metadata_bind(&crash_capacity, UINT64_MAX);
        assert(!latcd_retirement_test_page_reserve(root, 150, &crash_capacity, UINT64_MAX,
                                                   &crash_budget, crash_binding, error, sizeof(error)));
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "crash:renamed", 1));
        latcd_retirement_test_budget_result(root, 150, crash_binding, &crash_budget,
            &page.entries[0], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error));
        _exit(1);
    }
    int budget_status;
    assert(waitpid(budget_child, &budget_status, 0) == budget_child);
    assert(WIFSIGNALED(budget_status) && WTERMSIG(budget_status) == SIGKILL);
    assert(!latcd_cache_capacity_scan(&page_capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&page_capacity, UINT64_MAX);
    assert(!latcd_retirement_test_page_reserve(root, 150, &page_capacity, UINT64_MAX,
                                               &page_budget, budget_binding, error, sizeof(error)));
    assert(page_budget.remaining == 1024 + 2 * 65536 &&
           page_capacity.metadata_reserved == page_budget.remaining);
    assert(!latcd_cache_capacity_test_page_release(&page_capacity, &page_budget));
    latcd_cache_capacity_close(&page_capacity);
    assert(!unlink(budget_result_path));
    g_free(recovered_path); g_free(recovered_name);
    assert(!latcd_cache_capacity_scan(&page_capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&page_capacity, UINT64_MAX);
    assert(!latcd_retirement_test_page_reserve(root, 150, &page_capacity, UINT64_MAX,
                                               &page_budget, budget_binding, error, sizeof(error)));
    g_free(budget_result_path); g_free(budget_result_name);
    char *match_old_gc = g_strconcat(gc, ".match-old", NULL);
    scheduler_swap_gc = gc; scheduler_swap_old = match_old_gc;
    scheduler_swap_after_binding = true;
    assert(latcd_retirement_test_page_budget_matches(root, budget_binding, error, sizeof(error)) < 0);
    assert(!scheduler_swap_after_binding);
    assert(!rmdir(gc) && !rename(match_old_gc, gc));
    g_free(match_old_gc);
    /* An unexpected namespace replacement invalidates the capacity index. */
    assert(!latcd_cache_capacity_poll(&page_capacity));
    assert(!latcd_cache_capacity_test_page_abandon(&page_capacity, &page_budget));
    latcd_cache_capacity_close(&page_capacity);
    assert(!latcd_cache_capacity_scan(&page_capacity, root, error, sizeof(error)));
    char *reservation_old_gc = g_strconcat(gc, ".reservation-old", NULL);
    snapshot_swap_store = store; snapshot_swap_gc = gc; snapshot_swap_old = reservation_old_gc;
    assert(latcd_retirement_test_page_reserve(root, 150, &page_capacity, UINT64_MAX,
                                               &page_budget, budget_binding, error, sizeof(error)) < 0);
    assert(!snapshot_swap_store && !page_budget.capacity && !page_capacity.metadata_reserved);
    assert(!rmdir(gc) && !rename(reservation_old_gc, gc));
    g_free(reservation_old_gc);
    latcd_cache_capacity_close(&page_capacity);
    assert(!pthread_mutex_destroy(&page_capacity.lock));
    uint64_t estimate = 0;
    assert(!latcd_retirement_page_budget_estimate(&snapshot_page, results, &inventory, &estimate));
    assert(estimate == 2 * 1024 + 2 * 65536);
    LatcdRetirementPageInventory full = {.occupied_slots = 4095, .occupied_bytes = 4095 * 1024};
    assert(latcd_retirement_page_budget_estimate(&snapshot_page, results, &full, &estimate) < 0 &&
           errno == ENOSPC && !estimate);
    results[0] = 3;
    assert(latcd_retirement_page_budget_estimate(&snapshot_page, results, &inventory, &estimate) < 0 &&
           errno == EINVAL && !estimate);
    results[0] = 0;
    char *old_gc = g_strconcat(gc, ".old", NULL);
    snapshot_swap_store = store; snapshot_swap_gc = gc; snapshot_swap_old = old_gc;
    memset(&snapshot_page, 0xff, sizeof(snapshot_page));
    memset(results, 0xff, sizeof(results));
    memset(&inventory, 0xff, sizeof(inventory));
    assert(latcd_retirement_page_snapshot(root, 150, &snapshot_page, results, &inventory, error, sizeof(error)) < 0);
    assert(!snapshot_swap_store && !snapshot_page.count && !results[0] &&
           !inventory.occupied_slots && !inventory.members[0].present &&
           !inventory.members[0].snapshot.st_ino && !inventory.members[0].digest[0]);
    assert(!rmdir(gc) && !rename(old_gc, gc));
    scheduler_swap_root = root; scheduler_swap_gc = gc; scheduler_swap_old = old_gc;
    assert(latcd_retirement_page_state_store(root, &page, error, sizeof(error)) < 0);
    assert(!scheduler_swap_root);
    char *new_page = g_build_filename(gc, "retirement-page.ini", NULL);
    assert(access(new_page, F_OK));
    assert(!rmdir(gc) && !rename(old_gc, gc));
    scheduler_swap_gc = gc; scheduler_swap_old = old_gc; scheduler_swap_after_binding = true;
    assert(latcd_retirement_page_state_store(root, &page, error, sizeof(error)) < 0);
    assert(!scheduler_swap_after_binding && access(new_page, F_OK));
    assert(!rmdir(gc) && !rename(old_gc, gc));
    g_free(new_page); g_free(old_gc);
    int scheduler = open(gc, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(scheduler >= 0 && !flock(scheduler, LOCK_EX | LOCK_NB));
    memset(&snapshot_page, 0xff, sizeof(snapshot_page));
    memset(results, 0xff, sizeof(results));
    assert(latcd_retirement_page_snapshot(root, 150, &snapshot_page, results, &inventory, error, sizeof(error)) < 0);
    assert(!snapshot_page.count && !results[0]);
    assert(latcd_retirement_page_state_store(root, &page, error, sizeof(error)) < 0);
    assert(latcd_retirement_test_store_page_result(root, 150, &page, &page.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 1, &page.entries[0],
                                           error, sizeof(error)) < 0);
    assert(latcd_retirement_schedule_store_result(root, boot, 100, 150, 1, &page.entries[0],
            identity, LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    close(scheduler);
    LatcdRetirementPageState changed = page;
    changed.entries[0].deadline++;
    assert(latcd_retirement_test_store_page_result(root, 150, &changed, &changed.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    changed = page;
    changed.sequence++;
    assert(latcd_retirement_test_store_page_result(root, 150, &changed, &changed.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    changed = page;
    changed.entries[0].enqueued++;
    assert(latcd_retirement_test_store_page_result(root, 150, &changed, &changed.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    changed = page;
    changed.entries[1].enqueued++;
    assert(latcd_retirement_test_store_page_result(root, 150, &changed, &changed.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    LatcdRetirementPageDeadline outsider = page.entries[0];
    outsider.deadline++;
    assert(latcd_retirement_test_store_page_result(root, 150, &page, &outsider,
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    snprintf(outsider.name, sizeof(outsider.name), "%064x.so", 3);
    assert(latcd_retirement_test_store_page_result(root, 150, &page, &outsider,
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(latcd_retirement_schedule_store_page_result(root, 150, &page, &page.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(strstr(error, "receipt witness"));
    assert(!latcd_retirement_test_store_page_result(root, 150, &page, &page.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)));
    assert(latcd_retirement_schedule_check_page(root, 150, &page, error, sizeof(error)) == 1);
    assert(latcd_retirement_schedule_page_results(root, 150, &page, results, error, sizeof(error)) == 1);
    assert(results[0] == LATCD_RETIREMENT_RESULT_DONE && !results[1]);
    assert(latcd_retirement_page_snapshot(root, 150, &snapshot_page, results, &inventory, error, sizeof(error)) == 1);
    assert(results[0] == LATCD_RETIREMENT_RESULT_DONE && !results[1]);
    assert(inventory.occupied_slots == 1 && inventory.occupied_bytes == 1024 && !inventory.undersized_member);
    assert(inventory.members[0].present && !inventory.members[1].present);
    assert(inventory.members[0].last_attempt == page.entries[0].last_attempt &&
           inventory.members[0].retry_at == page.entries[0].retry_at &&
           inventory.members[0].busy_count == page.entries[0].busy_count &&
           !inventory.members[1].last_attempt && !inventory.members[1].retry_at &&
           !inventory.members[1].busy_count);
    char *inventory_name = g_strconcat(page.entries[0].name, ".ini", NULL);
    char *inventory_path = g_build_filename(store, inventory_name, NULL);
    char *inventory_data = NULL;
    gsize inventory_size;
    struct stat inventory_stat;
    assert(!stat(inventory_path, &inventory_stat) &&
           inventory_stat.st_ino == inventory.members[0].snapshot.st_ino &&
           g_file_get_contents(inventory_path, &inventory_data, &inventory_size, NULL));
    char *inventory_hash = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                           (const guchar *)inventory_data, inventory_size);
    char inventory_actual[65];
    for (unsigned i = 0; i < 32; i++)
        snprintf(inventory_actual + i * 2, 3, "%02x", inventory.members[0].digest[i]);
    assert(!strcmp(inventory_hash, inventory_actual));
    g_free(inventory_hash); g_free(inventory_data); g_free(inventory_path); g_free(inventory_name);
    assert(!latcd_retirement_page_budget_estimate(&snapshot_page, results, &inventory, &estimate) &&
           estimate == 1024 + 2 * 65536);
    char *short_name = g_strconcat(page.entries[0].name, ".ini", NULL);
    char *short_path = g_build_filename(store, short_name, NULL);
    char *full_record = NULL;
    gsize full_size;
    assert(g_file_get_contents(short_path, &full_record, &full_size, NULL) && full_size == 1024);
    char *padding = strchr(full_record, '#');
    assert(padding && padding > full_record);
    assert(!chmod(short_path, 0600));
    assert(g_file_set_contents(short_path, full_record, padding - full_record, NULL));
    assert(!chmod(short_path, 0400));
    assert(latcd_retirement_page_snapshot(root, 150, &snapshot_page, results, &inventory, error, sizeof(error)) == 1);
    assert(inventory.occupied_slots == 1 && inventory.occupied_bytes < 1024 && inventory.undersized_member);
    assert(latcd_retirement_page_budget_estimate(&snapshot_page, results, &inventory, &estimate) < 0 &&
           errno == EINVAL && !estimate);
    assert(!chmod(short_path, 0600));
    assert(g_file_set_contents(short_path, full_record, full_size, NULL));
    assert(!chmod(short_path, 0400));
    g_free(full_record); g_free(short_path); g_free(short_name);
    assert(latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)) < 0);
    LatcdRetirementPageState uncommitted;
    assert(!latcd_retirement_page_state_load(root, &uncommitted, error, sizeof(error)) &&
           !uncommitted.committed_cursor[0] && uncommitted.count == 2);
    LatcdRetirementPageDeadline deferred = page.entries[1];
    deferred.last_attempt = 1; deferred.retry_at = 250; deferred.busy_count = 3;
    assert(!latcd_retirement_test_store_page_result(root, 150, &page, &deferred,
            LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
    assert(!latcd_retirement_schedule_check_page(root, 150, &page, error, sizeof(error)));
    assert(!latcd_retirement_schedule_page_results(root, 150, &page, results, error, sizeof(error)));
    assert(results[0] == LATCD_RETIREMENT_RESULT_DONE && results[1] == LATCD_RETIREMENT_RESULT_DEFERRED);
    assert(!latcd_retirement_page_snapshot(root, 150, &snapshot_page, results, &inventory,
                                            error, sizeof(error)));
    assert(inventory.members[1].present && inventory.members[1].last_attempt == deferred.last_attempt &&
           inventory.members[1].retry_at == deferred.retry_at &&
           inventory.members[1].busy_count == deferred.busy_count &&
           inventory.members[1].retry_at != snapshot_page.entries[1].retry_at);
    memset(results, 0xff, sizeof(results));
    assert(latcd_retirement_schedule_page_results(root, 0, &page, results, error, sizeof(error)) < 0);
    for (unsigned i = 0; i < sizeof(results); i++) assert(!results[i]);
    char *legacy_path = g_build_filename(gc, "retirement-page.ini", NULL);
    GKeyFile *legacy = g_key_file_new();
    assert(g_key_file_load_from_file(legacy, legacy_path, 0, NULL));
    g_key_file_set_integer(legacy, "page", "version", 2);
    assert(g_key_file_remove_key(legacy, "page", "pending", NULL));
    for (unsigned i = 0; i < page.count; i++) {
        char group[32]; snprintf(group, sizeof(group), "entry%u", i);
        assert(g_key_file_remove_key(legacy, group, "result", NULL));
    }
    assert(g_key_file_remove_key(legacy, "page", "committed_cursor", NULL));
    char *legacy_data = g_key_file_to_data(legacy, NULL, NULL);
    put(legacy_path, legacy_data);
    assert(latcd_retirement_test_store_page_result(root, 150, &page, &page.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)) < 0);
    char *after_legacy = NULL;
    assert(g_file_get_contents(legacy_path, &after_legacy, NULL, NULL));
    assert(!strcmp(legacy_data, after_legacy));
    g_free(after_legacy); g_free(legacy_data); g_key_file_unref(legacy); g_free(legacy_path);
    assert(!latcd_retirement_page_state_store(root, &page, error, sizeof(error)));
    scheduler = open(gc, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(scheduler >= 0 && !flock(scheduler, LOCK_EX | LOCK_NB));
    assert(latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)) < 0);
    assert(!latcd_retirement_page_state_load(root, &uncommitted, error, sizeof(error)) &&
           uncommitted.count == page.count && !uncommitted.committed_cursor[0] &&
           !strcmp(uncommitted.cursor, page.cursor));
    close(scheduler);
    char *corrupt = g_build_filename(store, "unknown.ini", NULL);
    put(corrupt, "invalid\n");
    memset(results, 0xff, sizeof(results));
    assert(latcd_retirement_schedule_page_results(root, 150, &page, results, error, sizeof(error)) < 0);
    for (unsigned i = 0; i < sizeof(results); i++) assert(!results[i]);
    assert(latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)) < 0);
    assert(!latcd_retirement_page_state_load(root, &uncommitted, error, sizeof(error)) &&
           uncommitted.count == page.count && !uncommitted.committed_cursor[0] &&
           !strcmp(uncommitted.cursor, page.cursor));
    assert(!unlink(corrupt));
    g_free(corrupt);
    changed = page;
    changed.entries[0].enqueued++;
    assert(latcd_retirement_page_commit(root, 150, &changed, error, sizeof(error)) < 0);
    assert(latcd_retirement_schedule_check_page(root, 150, &changed, error, sizeof(error)) == 1);
    assert(latcd_retirement_schedule_page_results(root, 150, &changed, results, error, sizeof(error)) == 1);
    assert(results[0] == 3 && results[1] == LATCD_RETIREMENT_RESULT_DEFERRED);
    assert(!latcd_retirement_page_state_store(root, &changed, error, sizeof(error)));
    assert(latcd_retirement_page_commit(root, 150, &changed, error, sizeof(error)) < 0);
    changed = page;
    changed.sequence++;
    assert(latcd_retirement_schedule_check_page(root, 150, &changed, error, sizeof(error)) == 1);
    assert(!latcd_retirement_page_state_store(root, &changed, error, sizeof(error)));
    assert(latcd_retirement_page_commit(root, 150, &changed, error, sizeof(error)) < 0);
    assert(!latcd_retirement_page_state_store(root, &page, error, sizeof(error)));
    simulated_boottime_us = 149;
    assert(latcd_retirement_schedule_check_page(root, 150, &page, error, sizeof(error)) < 0);
    simulated_boottime_us = 150;
    char saved_boot[37];
    memcpy(saved_boot, page.boot, sizeof(saved_boot));
    g_strlcpy(page.boot, "00000000-0000-4000-8000-000000000000", sizeof(page.boot));
    assert(latcd_retirement_schedule_check_page(root, 150, &page, error, sizeof(error)) < 0);
    memcpy(page.boot, saved_boot, sizeof(page.boot));
    simulated_boottime_us = 0;
    page.entries[0].deadline++;
    assert(latcd_retirement_schedule_check_page(root, 150, &page, error, sizeof(error)) == 1);
    page.entries[0].deadline--;
    page.cache_inode++;
    assert(latcd_retirement_schedule_check_page(root, 150, &page, error, sizeof(error)) < 0);
    assert(latcd_retirement_test_store_page_result(root, 150, &page, &page.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    page.cache_inode--;
    schedule_scan_mutation = store;
    assert(latcd_retirement_schedule_check_page(root, 150, &page, error, sizeof(error)) < 0);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    uint64_t initial_metadata = capacity.metadata_committed;
    latcd_cache_capacity_metadata_bind(&capacity, initial_metadata);
    errno = 0;
    assert(latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)) < 0);
    assert(errno == ENOSPC && capacity.ready &&
           capacity.metadata_committed == initial_metadata && !capacity.metadata_reserved);
    assert(!latcd_retirement_page_state_load(root, &uncommitted, error, sizeof(error)) &&
           uncommitted.count == page.count && !uncommitted.committed_cursor[0] &&
           !strcmp(uncommitted.cursor, page.cursor));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    assert(!latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    const char *commit_faults[] = {"file-synced", "renamed"};
    for (unsigned i = 0; i < G_N_ELEMENTS(commit_faults); i++) {
        for (unsigned crash = 0; crash < 2; crash++) {
            assert(!latcd_retirement_page_state_store(root, &page, error, sizeof(error)));
            pid_t child = fork();
            assert(child >= 0);
            if (!child) {
                char *fault = g_strdup_printf("%s:%s", crash ? "crash" : "error",
                                              commit_faults[i]);
                assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
                assert(latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)) < 0);
                assert(!crash);
                _exit(0);
            }
            int status;
            assert(waitpid(child, &status, 0) == child);
            assert(crash ? WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL :
                           WIFEXITED(status) && !WEXITSTATUS(status));
            assert(!latcd_retirement_page_state_load(root, &uncommitted, error, sizeof(error)));
            if (!uncommitted.committed_pending) {
                assert(uncommitted.count == page.count && !uncommitted.committed_cursor[0] &&
                       !strcmp(uncommitted.cursor, page.cursor));
                assert(!latcd_retirement_schedule_check_page(root, 150, &uncommitted,
                                                             error, sizeof(error)));
                assert(!latcd_retirement_page_commit(root, 150, &uncommitted, error, sizeof(error)));
            } else {
                assert(uncommitted.count == page.count &&
                       !strcmp(uncommitted.cursor, page.cursor));
                assert(uncommitted.results[0] == LATCD_RETIREMENT_RESULT_DONE &&
                       uncommitted.results[1] == LATCD_RETIREMENT_RESULT_DEFERRED &&
                       uncommitted.entries[1].last_attempt == deferred.last_attempt &&
                       uncommitted.entries[1].retry_at == deferred.retry_at &&
                       uncommitted.entries[1].busy_count == deferred.busy_count);
                assert(latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)) < 0);
            }
        }
    }
    assert(!latcd_retirement_page_state_store(root, &page, error, sizeof(error)));
    assert(!latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)));
    assert(!latcd_retirement_page_state_load(root, &uncommitted, error, sizeof(error)) &&
           uncommitted.committed_pending && uncommitted.count == page.count &&
           !strcmp(uncommitted.cursor, page.cursor) && !uncommitted.committed_cursor[0]);
    assert(uncommitted.results[0] == LATCD_RETIREMENT_RESULT_DONE &&
           uncommitted.results[1] == LATCD_RETIREMENT_RESULT_DEFERRED);
    assert(uncommitted.entries[1].last_attempt == deferred.last_attempt &&
           uncommitted.entries[1].retry_at == deferred.retry_at &&
           uncommitted.entries[1].busy_count == deferred.busy_count);
    char *pending_path = g_build_filename(gc, "retirement-page.ini", NULL), *pending_raw = NULL;
    assert(g_file_get_contents(pending_path, &pending_raw, NULL, NULL));
    GKeyFile *bad_page = g_key_file_new();
    assert(g_key_file_load_from_file(bad_page, pending_path, 0, NULL));
    for (unsigned bad = 0; bad < 3; bad++) {
        if (!bad) assert(g_key_file_remove_key(bad_page, "entry1", "result", NULL));
        else g_key_file_set_integer(bad_page, "entry1", "result", bad == 1 ? 0 : 3);
        char *data = g_key_file_to_data(bad_page, NULL, NULL);
        put(pending_path, data);
        g_free(data);
        LatcdRetirementPageState invalid;
        assert(latcd_retirement_page_state_load(root, &invalid, error, sizeof(error)) < 0);
    }
    put(pending_path, pending_raw);
    assert(!latcd_retirement_page_state_load(root, &uncommitted, error, sizeof(error)) &&
           uncommitted.committed_pending);
    g_key_file_unref(bad_page); g_free(pending_raw); g_free(pending_path);
    assert(!latcd_retirement_schedule_check_page(root, 150, &uncommitted, error, sizeof(error)));
    char *deferred_name = g_strconcat(page.entries[1].name, ".ini", NULL);
    char *deferred_path = g_build_filename(store, deferred_name, NULL), *saved_shard = NULL;
    assert(g_file_get_contents(deferred_path, &saved_shard, NULL, NULL));
    GKeyFile *altered = g_key_file_new();
    assert(g_key_file_load_from_file(altered, deferred_path, 0, NULL));
    g_key_file_set_uint64(altered, "schedule", "retry_at", deferred.retry_at + 1);
    char *altered_data = g_key_file_to_data(altered, NULL, NULL);
    put(deferred_path, altered_data);
    assert(latcd_retirement_schedule_check_page(root, 150, &uncommitted, error, sizeof(error)) == 1);
    g_free(altered_data);
    g_key_file_set_uint64(altered, "schedule", "retry_at", deferred.retry_at);
    g_key_file_set_string(altered, "schedule", "result", "done");
    altered_data = g_key_file_to_data(altered, NULL, NULL);
    put(deferred_path, altered_data);
    assert(latcd_retirement_schedule_check_page(root, 150, &uncommitted, error, sizeof(error)) == 1);
    put(deferred_path, saved_shard);
    assert(!latcd_retirement_schedule_check_page(root, 150, &uncommitted, error, sizeof(error)));
    assert(!unlink(deferred_path));
    assert(latcd_retirement_schedule_check_page(root, 150, &uncommitted, error, sizeof(error)) == 1);
    put(deferred_path, saved_shard);
    assert(!latcd_retirement_schedule_check_page(root, 150, &uncommitted, error, sizeof(error)));
    g_free(altered_data); g_key_file_unref(altered); g_free(saved_shard);
    g_free(deferred_path); g_free(deferred_name);
    uint8_t pending_identity[32];
    assert(!latcd_retirement_page_identity(&uncommitted, pending_identity) &&
           !memcmp(identity, pending_identity, sizeof(identity)));
    for (unsigned i = 0; i < page.count; i++)
        assert(!strcmp(uncommitted.entries[i].name, page.entries[i].name) &&
               uncommitted.entries[i].deadline == page.entries[i].deadline &&
               uncommitted.entries[i].enqueued == page.entries[i].enqueued);
    assert(latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)) < 0);
    assert(latcd_retirement_page_stage(root, &page, error, sizeof(error)) < 0);
    assert(latcd_retirement_test_store_page_result(root, 150, &page, &page.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    LatcdRetirementPageState rejected_round, retained_pending;
    assert(latcd_retirement_page_round_begin(root, 100, &rejected_round,
                                             error, sizeof(error)) < 0);
    assert(!latcd_retirement_page_state_load(root, &retained_pending, error, sizeof(error)));
    uint8_t retained_identity[32];
    assert(retained_pending.committed_pending &&
           !latcd_retirement_page_identity(&retained_pending, retained_identity) &&
           !memcmp(identity, retained_identity, sizeof(identity)));
    assert(retained_pending.results[1] == uncommitted.results[1] &&
           retained_pending.entries[1].enqueued == uncommitted.entries[1].enqueued &&
           retained_pending.entries[1].last_attempt == uncommitted.entries[1].last_attempt &&
           retained_pending.entries[1].retry_at == uncommitted.entries[1].retry_at &&
           retained_pending.entries[1].busy_count == uncommitted.entries[1].busy_count);
    LatcdRetirementPageState next = page;
    next.round_cutoff++;
    next.sequence++;
    next.entries[0].enqueued = next.entries[1].enqueued = 149;
    assert(!latcd_retirement_schedule_merge_page(root, boot, 100, 150, &next,
                                                 error, sizeof(error)));
    assert(next.entries[0].enqueued == 100 && next.entries[1].enqueued == 100);
    assert(next.entries[1].last_attempt == 1 && next.entries[1].retry_at == 250 &&
           next.entries[1].busy_count == 3);
    assert(!latcd_retirement_page_state_store(root, &next, error, sizeof(error)));
    assert(latcd_retirement_schedule_check_page(root, 150, &next, error, sizeof(error)) == 1);
    assert(latcd_retirement_page_commit(root, 150, &next, error, sizeof(error)) < 0);
    for (unsigned i = 0; i < next.count; i++)
        assert(!latcd_retirement_schedule_store_page_result(root, 150, &next,
                &next.entries[i], LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
    LatcdRetirementPageDeadline carried;
    uint64_t carried_sequence;
    assert(!latcd_retirement_schedule_load(root, boot, 100, 150, next.entries[1].name,
                                            &carried_sequence, &carried, error, sizeof(error)));
    assert(carried_sequence == next.sequence && carried.enqueued == 100 &&
           carried.last_attempt == 1 && carried.retry_at == 250 && carried.busy_count == 3);
    assert(!latcd_retirement_schedule_check_page(root, 150, &next, error, sizeof(error)));
    assert(!latcd_retirement_page_commit(root, 150, &next, error, sizeof(error)));
    g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_page_stage(void)
{
    char *root = root_new(), error[256], *boot = NULL;
    struct stat cache;
    assert(!stat(root, &cache));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageState empty = {.cache_device = cache.st_dev, .cache_inode = cache.st_ino,
        .grace_us = 100, .round_cutoff = 120, .sequence = 3};
    g_strlcpy(empty.boot, boot, sizeof(empty.boot));
    LatcdRetirementPageState page = empty;
    page.count = 1;
    snprintf(page.entries[0].name, sizeof(page.entries[0].name), "%064x.so", 1);
    page.entries[0].deadline = 140;
    page.entries[0].enqueued = 100;
    g_strlcpy(page.cursor, page.entries[0].name, sizeof(page.cursor));
    assert(latcd_retirement_page_stage(root, &page, error, sizeof(error)) < 0);
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    char *legacy_path = g_build_filename(root, ".gc", "retirement-page.ini", NULL);
    GKeyFile *legacy = g_key_file_new();
    assert(g_key_file_load_from_file(legacy, legacy_path, 0, NULL));
    g_key_file_set_integer(legacy, "page", "version", 2);
    assert(g_key_file_remove_key(legacy, "page", "pending", NULL));
    assert(g_key_file_remove_key(legacy, "page", "committed_cursor", NULL));
    char *legacy_data = g_key_file_to_data(legacy, NULL, NULL);
    put(legacy_path, legacy_data);
    LatcdRetirementPageState legacy_loaded;
    assert(!latcd_retirement_page_state_load(root, &legacy_loaded, error, sizeof(error)));
    assert(latcd_retirement_page_stage(root, &page, error, sizeof(error)) < 0);
    g_free(legacy_data); g_key_file_unref(legacy); g_free(legacy_path);
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    simulated_boottime_us = 119;
    assert(latcd_retirement_page_stage(root, &page, error, sizeof(error)) < 0);
    simulated_boottime_us = 150;
    LatcdRetirementPageState future = page;
    future.entries[0].enqueued = 151;
    assert(latcd_retirement_page_stage(root, &future, error, sizeof(error)) < 0);
    LatcdRetirementPageState wrong_boot = page;
    g_strlcpy(wrong_boot.boot, "00000000-0000-4000-8000-000000000000", sizeof(wrong_boot.boot));
    LatcdRetirementPageState wrong_empty = empty;
    g_strlcpy(wrong_empty.boot, wrong_boot.boot, sizeof(wrong_empty.boot));
    assert(!latcd_retirement_page_state_store(root, &wrong_empty, error, sizeof(error)));
    assert(latcd_retirement_page_stage(root, &wrong_boot, error, sizeof(error)) < 0);
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    LatcdRetirementPageState changed = page;
    changed.round_cutoff++;
    assert(latcd_retirement_page_stage(root, &changed, error, sizeof(error)) < 0);
    changed = page;
    changed.sequence--;
    assert(latcd_retirement_page_stage(root, &changed, error, sizeof(error)) < 0);
    changed = page;
    snprintf(changed.committed_cursor, sizeof(changed.committed_cursor), "%064x.so", 0);
    assert(latcd_retirement_page_stage(root, &changed, error, sizeof(error)) < 0);
    LatcdRetirementPageState loaded;
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
           !loaded.count && loaded.sequence == empty.sequence);
    char *gc = g_build_filename(root, ".gc", NULL);
    int scheduler = open(gc, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(scheduler >= 0 && !flock(scheduler, LOCK_EX | LOCK_NB));
    assert(latcd_retirement_page_stage(root, &page, error, sizeof(error)) < 0);
    close(scheduler);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && !loaded.count);
    char *old_gc = g_strconcat(gc, ".old", NULL);
    scheduler_swap_gc = gc; scheduler_swap_old = old_gc; scheduler_swap_after_binding = true;
    assert(latcd_retirement_page_stage(root, &page, error, sizeof(error)) < 0);
    assert(!scheduler_swap_after_binding);
    char *new_page = g_build_filename(gc, "retirement-page.ini", NULL);
    assert(access(new_page, F_OK));
    assert(!rmdir(gc) && !rename(old_gc, gc));
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && !loaded.count);
    g_free(new_page); g_free(old_gc); g_free(gc);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    uint64_t metadata = capacity.metadata_committed;
    latcd_cache_capacity_metadata_bind(&capacity, metadata);
    errno = 0;
    assert(latcd_retirement_page_stage(root, &page, error, sizeof(error)) < 0);
    assert(errno == ENOSPC && capacity.ready && capacity.metadata_committed == metadata &&
           !capacity.metadata_reserved);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && !loaded.count);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    const char *faults[] = {"file-synced", "renamed"};
    for (unsigned i = 0; i < G_N_ELEMENTS(faults); i++) {
        for (unsigned crash = 0; crash < 2; crash++) {
            assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
            pid_t child = fork();
            assert(child >= 0);
            if (!child) {
                char *fault = g_strdup_printf("%s:%s", crash ? "crash" : "error", faults[i]);
                assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
                assert(latcd_retirement_page_stage(root, &page, error, sizeof(error)) < 0);
                assert(!crash);
                _exit(0);
            }
            int status;
            assert(waitpid(child, &status, 0) == child);
            assert(crash ? WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL :
                           WIFEXITED(status) && !WEXITSTATUS(status));
            assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
                   !loaded.committed_cursor[0] && loaded.sequence == empty.sequence);
            if (!loaded.count) {
                assert(!loaded.cursor[0]);
                assert(!latcd_retirement_page_stage(root, &page, error, sizeof(error)));
            } else {
                assert(loaded.count == 1 && !strcmp(loaded.cursor, page.cursor) &&
                       !strcmp(loaded.entries[0].name, page.entries[0].name) &&
                       loaded.entries[0].deadline == page.entries[0].deadline &&
                       loaded.entries[0].enqueued == page.entries[0].enqueued);
                assert(latcd_retirement_page_stage(root, &page, error, sizeof(error)) < 0);
            }
        }
    }
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    assert(!latcd_retirement_page_stage(root, &page, error, sizeof(error)));
    assert(latcd_retirement_page_stage(root, &page, error, sizeof(error)) < 0);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
           loaded.count == 1 && !strcmp(loaded.cursor, page.cursor));
    char *bound_path = g_build_filename(root, ".gc", "retirement-page.ini", NULL);
    GKeyFile *bound = g_key_file_new();
    assert(g_key_file_load_from_file(bound, bound_path, 0, NULL));
    uint8_t digest[32];
    char identity[65];
    assert(!latcd_retirement_page_budget_identity(&page, digest));
    for (unsigned i = 0; i < 32; i++) snprintf(identity + 2 * i, 3, "%02x", digest[i]);
    g_key_file_set_integer(bound, "page", "version", 6);
    g_key_file_set_integer(bound, "page", "budget_protocol", 1);
    g_key_file_set_string(bound, "page", "budget_identity", identity);
    char *bound_data = g_key_file_to_data(bound, NULL, NULL);
    put(bound_path, bound_data);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && loaded.budget_bound);
    assert(latcd_retirement_page_state_store(root, &loaded, error, sizeof(error)) < 0);
    identity[0] = identity[0] == '0' ? '1' : '0';
    g_key_file_set_string(bound, "page", "budget_identity", identity);
    char *bad = g_key_file_to_data(bound, NULL, NULL);
    put(bound_path, bad);
    assert(latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) < 0);
    g_free(bad);
    identity[0] = identity[0] == '0' ? '1' : '0';
    g_key_file_set_string(bound, "page", "budget_identity", identity);
    g_key_file_set_integer(bound, "page", "budget_protocol", 2);
    bad = g_key_file_to_data(bound, NULL, NULL);
    put(bound_path, bad);
    assert(latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) < 0);
    g_free(bad);
    g_key_file_set_integer(bound, "page", "budget_protocol", 1);
    assert(g_key_file_remove_key(bound, "page", "budget_identity", NULL));
    bad = g_key_file_to_data(bound, NULL, NULL);
    put(bound_path, bad);
    assert(latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) < 0);
    g_free(bad); g_free(bound_data); g_key_file_unref(bound); g_free(bound_path);
    simulated_boottime_us = 0;
    g_free(boot); remove_root(root); g_free(root);
}

static int test_result_guard(void *context)
{
    int *calls = context;
    (*calls)++;
    return -1;
}

static void test_deferred_page_recovery(bool done)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    struct stat st;
    assert(!stat(root, &st));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageState page = {.cache_device = st.st_dev, .cache_inode = st.st_ino,
        .grace_us = 100, .round_cutoff = 120, .sequence = 3}, loaded;
    g_strlcpy(page.boot, boot, sizeof(page.boot));
    assert(!latcd_retirement_page_state_store(root, &page, error, sizeof(error)));
    page.count = 2;
    for (unsigned i = 0; i < page.count; i++) {
        snprintf(page.entries[i].name, sizeof(page.entries[i].name), "%064x.so", i + 1);
        page.entries[i].deadline = 140; page.entries[i].enqueued = 100;
    }
    g_strlcpy(page.cursor, page.entries[1].name, sizeof(page.cursor));
    simulated_boottime_us = 150;
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    assert(!latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                  &budget, error, sizeof(error)));
    if (done) {
        uint8_t identity[32];
        assert(!latcd_retirement_page_budget_identity(&page, identity));
        assert(!latcd_retirement_test_bound_budget_result(root, 150, identity, &budget,
            &page.entries[0], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)));
        assert(latcd_retirement_page_recover_deferred_step(root, 150, &budget, error, sizeof(error)) < 0);
    } else {
        for (unsigned phase = 0; phase < 3; phase++) {
            assert(latcd_retirement_page_recover_deferred_step(root, 150, &budget, error, sizeof(error)) == 1);
            latcd_cache_capacity_close(&capacity);
            capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
            memset(&budget, 0, sizeof(budget));
            assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
            latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
            assert(!latcd_cache_capacity_recovery_begin(&capacity));
            assert(!latcd_retirement_page_restore_budget(root, &capacity, UINT64_MAX, 100,
                                                          &budget, &loaded, error, sizeof(error)));
            assert(!latcd_cache_capacity_recovery_finish(&capacity));
        }
        assert(!latcd_retirement_page_recover_deferred_step(root, 150, &budget, error, sizeof(error)));
        assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
               !loaded.count && !strcmp(loaded.committed_cursor, page.cursor));
        for (unsigned i = 0; i < page.count; i++) {
            LatcdRetirementPageDeadline saved; uint64_t sequence;
            assert(!latcd_retirement_schedule_load(root, boot, 100, 150, page.entries[i].name,
                                                   &sequence, &saved, error, sizeof(error)));
        }
    }
    latcd_cache_capacity_close(&capacity);
    simulated_boottime_us = 0;
    g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_budgeted_page_stage(void)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    struct stat st;
    assert(!stat(root, &st));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageState empty = {.cache_device = st.st_dev, .cache_inode = st.st_ino,
        .grace_us = 100, .round_cutoff = 120, .sequence = 3};
    g_strlcpy(empty.boot, boot, sizeof(empty.boot));
    snprintf(empty.retry_cursor, sizeof(empty.retry_cursor), "%064x.so", 9);
    LatcdRetirementPageState page = empty, loaded;
    page.count = 1;
    snprintf(page.entries[0].name, sizeof(page.entries[0].name), "%064x.so", 1);
    page.entries[0].deadline = 140;
    page.entries[0].enqueued = 100;
    g_strlcpy(page.cursor, page.entries[0].name, sizeof(page.cursor));
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
           !strcmp(loaded.retry_cursor, empty.retry_cursor));
    simulated_boottime_us = 150;
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    int stage_guard_calls = 0;
    assert(latcd_retirement_test_guarded_page_stage(root, &page, &capacity, UINT64_MAX,
        &budget, test_result_guard, &stage_guard_calls, error, sizeof(error)) < 0);
    assert(stage_guard_calls == 1 && capacity.ready && !budget.capacity && !capacity.metadata_reserved);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && !loaded.count);
    LatcdRetirementPageState stale_retry = page;
    snprintf(stale_retry.retry_cursor, sizeof(stale_retry.retry_cursor), "%064x.so", 10);
    assert(latcd_retirement_page_stage_budgeted(root, &stale_retry, &capacity, UINT64_MAX,
                                                &budget, error, sizeof(error)) < 0);
    assert(latcd_retirement_page_stage_budgeted(root, &page, &capacity, capacity.metadata_committed,
                                                &budget, error, sizeof(error)) < 0);
    assert(!budget.capacity && capacity.ready);
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:file-synced", 1));
    assert(latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                &budget, error, sizeof(error)) < 0);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(!budget.capacity && capacity.ready && !capacity.metadata_reserved);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && !loaded.count);
    char *target = g_build_filename(gc, "retirement-page.ini", NULL);
    char *saved = g_build_filename(gc, "saved-settlement", NULL);
    settlement_target = target;
    settlement_saved = saved;
    latcd_retirement_test_before_target_revalidate = replace_before_target_revalidate;
    assert(latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                &budget, error, sizeof(error)) < 0);
    assert(!latcd_retirement_test_before_target_revalidate && !capacity.ready && budget.invalid);
    char *replacement = NULL;
    assert(g_file_get_contents(target, &replacement, NULL, NULL) && !strcmp(replacement, "x"));
    g_free(replacement);
    assert(!latcd_cache_capacity_abandon_page(&capacity, &budget));
    latcd_cache_capacity_close(&capacity);
    assert(!unlink(target) && !rename(saved, target));
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    latcd_retirement_test_before_settlement = replace_settlement_target;
    assert(latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                &budget, error, sizeof(error)) < 0);
    assert(!latcd_retirement_test_before_settlement && !capacity.ready && budget.invalid);
    assert(!latcd_cache_capacity_abandon_page(&capacity, &budget));
    latcd_cache_capacity_close(&capacity);
    assert(!unlink(target) && !rename(saved, target));
    g_free(target); g_free(saved);
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    assert(!latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                 &budget, error, sizeof(error)));
    assert(budget.capacity == &capacity && budget.page_identity_bound && capacity.ready);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && loaded.budget_bound &&
           !strcmp(loaded.retry_cursor, empty.retry_cursor));
    assert(latcd_retirement_page_startup_check(root, error, sizeof(error)) < 0);
    assert(latcd_retirement_test_store_page_result(root, 150, &page, &page.entries[0],
           LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)) < 0);
    uint8_t binding[32];
    assert(!latcd_retirement_page_budget_identity(&page, binding));
    int guard_calls = 0;
    assert(latcd_retirement_test_guarded_budget_result(root, 150, binding, &budget,
        &page.entries[0], test_result_guard, &guard_calls, error, sizeof(error)) < 0);
    assert(guard_calls == 1 && capacity.ready && !budget.invalid);
    char *guard_path = g_strconcat(store, "/", page.entries[0].name, ".ini", NULL);
    assert(access(guard_path, F_OK) < 0 && errno == ENOENT);
    g_free(guard_path);
    assert(latcd_retirement_page_budget_result(root, 150, binding, &budget, &page.entries[0],
                                               LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(strstr(error, "receipt witness"));
    assert(!latcd_retirement_test_bound_budget_result(root, 150, binding, &budget, &page.entries[0],
                                                LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)));
    assert(latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)) < 0);
    assert(!latcd_cache_capacity_test_page_release(&capacity, &budget));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    LatcdCacheCapacity recovered = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 100, &budget,
                                                 &loaded, error, sizeof(error)) < 0);
    assert(!budget.capacity && !loaded.count);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    assert(latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 101, &budget,
                                                &loaded, error, sizeof(error)) < 0);
    assert(!budget.capacity && !loaded.count && recovered.recovery_gate && !recovered.ready);
    assert(latcd_cache_capacity_recovery_finish(&recovered) < 0);
    assert(!latcd_cache_capacity_recovery_abort(&recovered));
    latcd_cache_capacity_close(&recovered);
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    struct stat sync_stat;
    assert(!stat(gc, &sync_stat));
    retry_sync_device = sync_stat.st_dev; retry_sync_inode = sync_stat.st_ino;
    retry_sync_fault = true;
    assert(latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 100, &budget,
                                                 &loaded, error, sizeof(error)) < 0);
    retry_sync_fault = false;
    assert(!budget.capacity && latcd_cache_capacity_recovery_finish(&recovered) < 0);
    assert(!latcd_cache_capacity_recovery_abort(&recovered));
    latcd_cache_capacity_close(&recovered);
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    char *sync_store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!stat(sync_store, &sync_stat));
    retry_sync_device = sync_stat.st_dev; retry_sync_inode = sync_stat.st_ino;
    retry_sync_fault = true;
    assert(latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 100, &budget,
                                                 &loaded, error, sizeof(error)) < 0);
    retry_sync_fault = false;
    g_free(sync_store);
    assert(!budget.capacity && latcd_cache_capacity_recovery_finish(&recovered) < 0);
    assert(!latcd_cache_capacity_recovery_abort(&recovered));
    latcd_cache_capacity_close(&recovered);
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    sync_store = g_build_filename(gc, "retirement-schedule", NULL);
    char *saved_store = g_build_filename(gc, "retirement-schedule-saved", NULL);
    assert(!stat(sync_store, &sync_stat));
    retry_sync_device = sync_stat.st_dev; retry_sync_inode = sync_stat.st_ino;
    sync_swap_path = sync_store; sync_swap_saved = saved_store;
    assert(latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 100, &budget,
                                                 &loaded, error, sizeof(error)) < 0);
    assert(!sync_swap_path && !budget.capacity && latcd_cache_capacity_recovery_finish(&recovered) < 0);
    assert(!rmdir(sync_store) && !rename(saved_store, sync_store));
    g_free(saved_store); g_free(sync_store);
    assert(!latcd_cache_capacity_recovery_abort(&recovered));
    latcd_cache_capacity_close(&recovered);
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    assert(!latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 100, &budget,
                                                  &loaded, error, sizeof(error)));
    assert(loaded.budget_bound && loaded.count == 1 && budget.capacity == &recovered &&
           budget.remaining == 2 * 65536);
    assert(latcd_cache_capacity_reserve(&recovered, 1, UINT64_MAX, error, sizeof(error)) < 0);
    assert(!latcd_cache_capacity_recovery_finish(&recovered));
    assert(!latcd_retirement_page_budget_commit(root, 150, &page, &budget, error, sizeof(error)));
    assert(!latcd_retirement_consumption_begin(root, 150, &budget, error, sizeof(error)));
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
           loaded.consumption_bound && loaded.committed_pending);
    assert(latcd_retirement_consumption_begin(root, 150, &budget, error, sizeof(error)) < 0);
    assert(latcd_retirement_page_finish_preserving_results(root, 150, &budget, error, sizeof(error)) < 0);
    assert(!latcd_cache_capacity_test_page_release(&recovered, &budget));
    latcd_cache_capacity_close(&recovered);
    assert(!pthread_mutex_destroy(&recovered.lock));
    char *checkpoint = g_build_filename(gc, "retirement-page.ini", NULL);
    char *checkpoint_data = NULL;
    assert(g_file_get_contents(checkpoint, &checkpoint_data, NULL, NULL));
    for (unsigned variant = 0; variant < 5; variant++) {
        GKeyFile *altered = g_key_file_new();
        assert(g_key_file_load_from_data(altered, checkpoint_data, -1, 0, NULL));
        const char *field[] = {"result", "last_attempt", "retry_at", "busy_count"};
        if (variant < 4)
            g_key_file_set_uint64(altered, "entry0", field[variant], variant == 0 ? 2 : 1);
        else
            g_key_file_set_string(altered, "page", "retry_cursor",
                                  "000000000000000000000000000000000000000000000000000000000000000a.so");
        char *raw = g_key_file_to_data(altered, NULL, NULL);
        put(checkpoint, raw);
        assert(latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) < 0);
        g_free(raw);
        g_key_file_unref(altered);
    }
    put(checkpoint, checkpoint_data);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
           loaded.committed_pending && loaded.consumption_bound);
    GKeyFile *altered_consumption = g_key_file_new();
    assert(g_key_file_load_from_data(altered_consumption, checkpoint_data, -1, 0, NULL));
    g_key_file_set_string(altered_consumption, "consumption", "mtime_sec", "-0");
    char *bad_consumption = g_key_file_to_data(altered_consumption, NULL, NULL);
    put(checkpoint, bad_consumption);
    assert(latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) < 0);
    put(checkpoint, checkpoint_data);
    g_free(bad_consumption);
    g_key_file_unref(altered_consumption);
    g_free(checkpoint_data);
    g_free(checkpoint);
    char *fragment_name = g_strconcat(page.entries[0].name, ".ini", NULL);
    char *fragment_path = g_build_filename(store, fragment_name, NULL);
    LatcdCacheCapacity pending = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&pending, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&pending, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&pending));
    assert(!latcd_retirement_page_restore_budget(root, &pending, UINT64_MAX, 100, &budget,
                                                  &loaded, error, sizeof(error)));
    assert(loaded.committed_pending && loaded.results[0] == LATCD_RETIREMENT_RESULT_DONE &&
           budget.remaining == 2 * 65536);
    char *unexpected = g_build_filename(gc, "unexpected", NULL);
    put(unexpected, "external change");
    assert(latcd_cache_capacity_recovery_finish(&pending) < 0);
    assert(latcd_cache_capacity_abandon_page(&pending, &budget) < 0);
    assert(!latcd_cache_capacity_recovery_abort(&pending));
    assert(!latcd_cache_capacity_abandon_page(&pending, &budget));
    assert(latcd_cache_capacity_reserve(&pending, 1, UINT64_MAX, error, sizeof(error)) < 0);
    assert(!latcd_cache_capacity_scan(&pending, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&pending, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&pending));
    assert(!latcd_retirement_page_restore_budget(root, &pending, UINT64_MAX, 100, &budget,
                                                  &loaded, error, sizeof(error)));
    assert(loaded.committed_pending && loaded.results[0] == LATCD_RETIREMENT_RESULT_DONE &&
           budget.remaining == 2 * 65536);
    assert(!latcd_cache_capacity_recovery_finish(&pending));
    assert(!latcd_cache_capacity_test_page_release(&pending, &budget));
    latcd_cache_capacity_close(&pending);
    assert(!pthread_mutex_destroy(&pending.lock));
    assert(!unlink(unexpected));
    g_free(unexpected);
    char *fragment_data = NULL;
    assert(g_file_get_contents(fragment_path, &fragment_data, NULL, NULL));
    assert(!unlink(fragment_path));
    LatcdCacheCapacity missing = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&missing, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&missing, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&missing));
    assert(latcd_retirement_page_restore_budget(root, &missing, UINT64_MAX, 100, &budget,
                                                 &loaded, error, sizeof(error)) < 0);
    assert(!budget.capacity && !loaded.count && missing.recovery_gate);
    latcd_cache_capacity_close(&missing);
    assert(!pthread_mutex_destroy(&missing.lock));
    put(fragment_path, fragment_data);
    for (unsigned variant = 0; variant < 2; variant++) {
        GKeyFile *altered = g_key_file_new();
        assert(g_key_file_load_from_data(altered, fragment_data, 1024, 0, NULL));
        if (!variant) g_key_file_set_string(altered, "schedule", "result", "deferred");
        else g_key_file_set_uint64(altered, "schedule", "retry_at", 151);
        gsize length;
        char *raw = g_key_file_to_data(altered, &length, NULL);
        assert(length < 1023);
        char padded[1025];
        memcpy(padded, raw, length);
        padded[length++] = '#';
        memset(padded + length, 'x', 1023 - length);
        padded[1023] = '\n'; padded[1024] = 0;
        put(fragment_path, padded);
        LatcdCacheCapacity mismatch = LATCD_CACHE_CAPACITY_INIT;
        assert(!latcd_cache_capacity_scan(&mismatch, root, error, sizeof(error)));
        latcd_cache_capacity_metadata_bind(&mismatch, UINT64_MAX);
        assert(!latcd_cache_capacity_recovery_begin(&mismatch));
        assert(latcd_retirement_page_restore_budget(root, &mismatch, UINT64_MAX, 100, &budget,
                                                     &loaded, error, sizeof(error)) < 0);
        assert(!budget.capacity && !loaded.count && mismatch.recovery_gate);
        latcd_cache_capacity_close(&mismatch);
        assert(!pthread_mutex_destroy(&mismatch.lock));
        g_free(raw); g_key_file_unref(altered);
    }
    put(fragment_path, fragment_data);
    g_free(fragment_data);
    GKeyFile *fragment = g_key_file_new();
    assert(g_key_file_load_from_file(fragment, fragment_path, 0, NULL));
    g_key_file_set_uint64(fragment, "schedule", "sequence", page.sequence + 1);
    char *bad_fragment = g_key_file_to_data(fragment, NULL, NULL);
    put(fragment_path, bad_fragment);
    LatcdCacheCapacity conflicting = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&conflicting, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&conflicting, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&conflicting));
    assert(latcd_retirement_page_restore_budget(root, &conflicting, UINT64_MAX, 100, &budget,
                                                 &loaded, error, sizeof(error)) < 0);
    assert(!budget.capacity && !loaded.count && conflicting.recovery_gate);
    latcd_cache_capacity_close(&conflicting);
    assert(!pthread_mutex_destroy(&conflicting.lock));
    assert(!unlink(fragment_path));
    g_free(bad_fragment); g_key_file_unref(fragment); g_free(fragment_path); g_free(fragment_name);
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    LatcdCacheCapacity uncertain = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&uncertain, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&uncertain, UINT64_MAX);
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:cleanup-sync", 1));
    assert(latcd_retirement_page_stage_budgeted(root, &page, &uncertain, UINT64_MAX,
                                                &budget, error, sizeof(error)) < 0);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(budget.capacity == &uncertain && budget.invalid && !uncertain.ready);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && !loaded.count);
    assert(!latcd_cache_capacity_abandon_page(&uncertain, &budget));
    assert(!latcd_cache_capacity_scan(&uncertain, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&uncertain, UINT64_MAX);
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:renamed", 1));
    assert(latcd_retirement_page_stage_budgeted(root, &page, &uncertain, UINT64_MAX,
                                                &budget, error, sizeof(error)) < 0);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(budget.capacity == &uncertain && budget.invalid && !uncertain.ready);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && loaded.budget_bound);
    assert(!latcd_cache_capacity_test_page_abandon(&uncertain, &budget));
    latcd_cache_capacity_close(&uncertain);
    assert(!pthread_mutex_destroy(&uncertain.lock));
    simulated_boottime_us = 0;
    g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_budgeted_crash(const char *point, bool installed, bool result_write, bool commit)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    struct stat st;
    assert(!stat(root, &st));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageState empty = {.cache_device = st.st_dev, .cache_inode = st.st_ino,
        .grace_us = 100, .round_cutoff = 120, .sequence = 3};
    g_strlcpy(empty.boot, boot, sizeof(empty.boot));
    LatcdRetirementPageState page = empty, loaded;
    page.count = 1;
    snprintf(page.entries[0].name, sizeof(page.entries[0].name), "%064x.so", 1);
    page.entries[0].deadline = 140;
    page.entries[0].enqueued = 100;
    g_strlcpy(page.cursor, page.entries[0].name, sizeof(page.cursor));
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    simulated_boottime_us = 150;
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
        LatcdPageBudget budget = {0};
        assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
        latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
        if (result_write || commit)
            assert(!latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                         &budget, error, sizeof(error)));
        if (commit) {
            uint8_t identity[32];
            assert(!latcd_retirement_page_budget_identity(&page, identity));
            assert(!latcd_retirement_test_budget_result(root, 150, identity, &budget, &page.entries[0],
                                                         LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)));
        }
        char *fault = g_strdup_printf("crash:%s", point);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
        if (commit) {
            latcd_retirement_test_budget_commit(root, 150, &page, &budget, error, sizeof(error));
        } else if (result_write) {
            uint8_t identity[32];
            assert(!latcd_retirement_page_budget_identity(&page, identity));
            latcd_retirement_test_budget_result(root, 150, identity, &budget, &page.entries[0],
                                                 LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error));
        } else latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                     &budget, error, sizeof(error));
        _exit(1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)));
    assert((installed || result_write || commit) ? loaded.count == 1 && loaded.budget_bound : !loaded.count);
    if (!result_write && !commit && !installed)
        assert((latcd_retirement_page_startup_check(root, error, sizeof(error)) < 0) ==
               !strcmp(point, "linked"));
    if (commit) assert(loaded.committed_pending == installed);
    LatcdCacheCapacity recovered = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    if (installed || result_write || commit) {
        assert(!latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 100, &budget,
                                                      &loaded, error, sizeof(error)));
        assert(budget.remaining == 2 * 65536 + ((commit || (result_write && installed)) ? 0 : 1024));
        assert(!latcd_cache_capacity_recovery_finish(&recovered));
        if (result_write) {
            uint8_t identity[32];
            assert(!latcd_retirement_page_budget_identity(&loaded, identity));
            assert(!latcd_retirement_test_budget_result(root, 150, identity, &budget, &page.entries[0],
                                                         LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)));
            assert(!latcd_retirement_test_budget_commit(root, 150, &page, &budget, error, sizeof(error)));
        }
        if (commit && !installed)
            assert(!latcd_retirement_test_budget_commit(root, 150, &page, &budget, error, sizeof(error)));
        assert(!latcd_cache_capacity_test_page_release(&recovered, &budget));
    } else {
        assert(latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 100, &budget,
                                                     &loaded, error, sizeof(error)) < 0);
        assert(!budget.capacity && recovered.recovery_gate && !recovered.ready);
        assert(latcd_cache_capacity_recovery_finish(&recovered) < 0);
    }
    latcd_cache_capacity_close(&recovered);
    assert(!pthread_mutex_destroy(&recovered.lock));
    simulated_boottime_us = 0;
    g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_deferred_finish_crash(const char *point, bool installed, bool partial)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    struct stat st;
    assert(!stat(root, &st));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageState empty = {.cache_device = st.st_dev, .cache_inode = st.st_ino,
        .grace_us = 100, .round_cutoff = 120, .sequence = 3};
    g_strlcpy(empty.boot, boot, sizeof(empty.boot));
    LatcdRetirementPageState page = empty, loaded;
    page.count = 2;
    snprintf(page.entries[0].name, sizeof(page.entries[0].name), "%064x.so", 1);
    page.entries[0].deadline = 140; page.entries[0].enqueued = 100;
    page.entries[0].last_attempt = 3; page.entries[0].retry_at = 200; page.entries[0].busy_count = 1;
    page.entries[1] = page.entries[0];
    snprintf(page.entries[1].name, sizeof(page.entries[1].name), "%064x.so", 2);
    g_strlcpy(page.cursor, page.entries[1].name, sizeof(page.cursor));
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    simulated_boottime_us = 150;
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
        LatcdPageBudget budget = {0};
        uint8_t identity[32];
        assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
        latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
        assert(!latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                     &budget, error, sizeof(error)));
        assert(!latcd_retirement_page_budget_identity(&page, identity));
        assert(!latcd_retirement_page_budget_result(root, 150, identity, &budget, &page.entries[0],
                     LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
        assert(!latcd_retirement_test_bound_budget_result(root, 150, identity, &budget, &page.entries[1],
                     LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)));
        assert(!latcd_retirement_page_budget_commit(root, 150, &page, &budget, error, sizeof(error)));
        char *fault = g_strdup_printf("crash:%s", point);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
        latcd_retirement_page_finish_preserving_results(root, 150, &budget, error, sizeof(error));
        _exit(1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)));
    assert(installed ? !loaded.count && !strcmp(loaded.committed_cursor, page.cursor) :
                       loaded.committed_pending && loaded.count == 2);
    assert((latcd_retirement_page_startup_check(root, error, sizeof(error)) < 0) == (!installed || partial));
    if (!installed && !partial) {
        LatcdRetirementPageInventory inventory;
        LatcdRetirementPageState scanned;
        uint8_t results[128];
        assert(!latcd_retirement_page_snapshot(root, 150, &scanned, results, &inventory, error, sizeof(error)));
        LatcdRetirementConsumption consumption = {0};
        assert(!latcd_retirement_consumption_bind(&scanned, &consumption, 1,
                    &inventory.members[1].snapshot, inventory.members[1].digest));
        assert(!latcd_retirement_consumption_check_inventory(&scanned, &consumption, results, &inventory));
        char *name = g_strconcat(page.entries[1].name, ".ini", NULL);
        char *path = g_build_filename(store, name, NULL), *saved = g_build_filename(root, "saved-shard", NULL);
        assert(!rename(path, saved));
        assert(latcd_retirement_page_snapshot(root, 150, &scanned, results, &inventory, error, sizeof(error)) == 1);
        assert(!latcd_retirement_consumption_check_inventory(&scanned, &consumption, results, &inventory));
        LatcdRetirementConsumption absent = {0};
        assert(latcd_retirement_consumption_check_inventory(&scanned, &absent, results, &inventory) < 0);
        uint64_t bytes;
        uint8_t binding[32];
        assert(!latcd_retirement_consumption_budget_estimate(&scanned, &consumption, results, &inventory, &bytes));
        assert(!latcd_retirement_page_budget_identity(&scanned, binding));
        LatcdCacheCapacity gate_capacity = LATCD_CACHE_CAPACITY_INIT;
        LatcdPageBudget gate_budget = {0};
        assert(!latcd_cache_capacity_scan(&gate_capacity, root, error, sizeof(error)));
        latcd_cache_capacity_metadata_bind(&gate_capacity, UINT64_MAX);
        assert(latcd_cache_capacity_restore_page(&gate_capacity, bytes, UINT64_MAX, binding, &gate_budget) < 0);
        assert(!gate_budget.capacity && !latcd_cache_capacity_recovery_begin(&gate_capacity));
        assert(!latcd_cache_capacity_restore_page(&gate_capacity, bytes, UINT64_MAX, binding, &gate_budget));
        assert(gate_budget.remaining == bytes && gate_capacity.metadata_reserved == bytes);
        assert(!latcd_cache_capacity_recovery_finish(&gate_capacity));
        assert(!latcd_cache_capacity_cancel_page(&gate_capacity, &gate_budget));
        latcd_cache_capacity_close(&gate_capacity);
        assert(!pthread_mutex_destroy(&gate_capacity.lock));
        assert(!rename(saved, path));
        g_free(saved); g_free(path); g_free(name);
    }
    LatcdCacheCapacity recovered = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    if (!installed && !partial) {
        assert(!latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 100,
                                                     &budget, &loaded, error, sizeof(error)));
        assert(!latcd_cache_capacity_recovery_finish(&recovered));
        assert(!latcd_retirement_page_finish_preserving_results(root, 150, &budget, error, sizeof(error)));
    } else assert(!latcd_cache_capacity_recovery_abort(&recovered));
    LatcdRetirementPageState merged = page;
    merged.entries[0].retry_at = 0; merged.entries[0].busy_count = 0;
    assert(!latcd_retirement_schedule_merge_page(root, boot, 100, 150, &merged, error, sizeof(error)));
    assert(merged.entries[0].retry_at == 200 && merged.entries[0].busy_count == 1);
    if (!partial) {
        assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && !loaded.count);
        LatcdRetirementPageState next = page;
        next.committed_cursor[0] = 0;
        next.round_cutoff++;
        next.sequence++;
        uint8_t results[128] = {0};
        assert(latcd_retirement_schedule_page_results(root, 150, &next, results, error, sizeof(error)) == 1);
        assert(results[0] == 4 && results[1] == 4);
        assert(latcd_retirement_page_commit(root, 150, &next, error, sizeof(error)) < 0);
    }
    latcd_cache_capacity_close(&recovered);
    assert(!pthread_mutex_destroy(&recovered.lock));
    simulated_boottime_us = 0;
    g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_rebind_crash(const char *point, bool installed, bool partial)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    struct stat st;
    assert(!stat(root, &st));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageState empty = {.cache_device = st.st_dev, .cache_inode = st.st_ino,
        .grace_us = 100, .round_cutoff = 120, .sequence = 4};
    g_strlcpy(empty.boot, boot, sizeof(empty.boot));
    LatcdRetirementPageState page = empty, loaded;
    page.count = 1;
    snprintf(page.entries[0].name, sizeof(page.entries[0].name), "%064x.so", 1);
    page.entries[0].deadline = 140; page.entries[0].enqueued = 100;
    page.entries[0].last_attempt = 3; page.entries[0].retry_at = 200; page.entries[0].busy_count = 1;
    g_strlcpy(page.cursor, page.entries[0].name, sizeof(page.cursor));
    uint8_t old_identity[32] = {1};
    assert(!latcd_retirement_schedule_store_result(root, boot, 100, 150, 3, &page.entries[0],
                       old_identity, LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
    assert(!latcd_retirement_page_state_store(root, &page, error, sizeof(error)));
    LatcdRetirementPageState stale = page;
    stale.entries[0].retry_at = 0;
    LatcdRetirementPageDeadline early = stale.entries[0];
    early.last_attempt = 4; early.busy_count = 0;
    simulated_boottime_us = 150;
    assert(latcd_retirement_test_store_page_result(root, 150, &stale, &early,
                       LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(!latcd_retirement_page_state_store(root, &stale, error, sizeof(error)));
    assert(latcd_retirement_test_store_page_result(root, 150, &stale, &early,
                       LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    LatcdRetirementPageDeadline still_deferred;
    uint64_t old_sequence;
    assert(!latcd_retirement_schedule_load(root, boot, 100, 150, early.name,
                       &old_sequence, &still_deferred, error, sizeof(error)));
    assert(old_sequence == 3 && still_deferred.last_attempt == 3 &&
           still_deferred.retry_at == 200 && still_deferred.busy_count == 1);
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
        LatcdPageBudget budget = {0};
        uint8_t identity[32];
        assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
        latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
        assert(!latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                     &budget, error, sizeof(error)));
        assert(!latcd_retirement_page_budget_identity(&page, identity));
        char *fault = g_strdup_printf("crash:%s", point);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
        latcd_retirement_test_bound_budget_result(root, 150, identity, &budget, &page.entries[0],
                                            LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error));
        _exit(1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    LatcdCacheCapacity recovered = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    int restored = latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 100,
                                                         &budget, &loaded, error, sizeof(error));
    if (partial) {
        assert(restored < 0 && !budget.capacity);
        assert(!latcd_cache_capacity_recovery_abort(&recovered));
    } else {
        assert(!restored && !latcd_cache_capacity_recovery_finish(&recovered));
        uint8_t results[128] = {0}, identity[32];
        assert(latcd_retirement_schedule_page_results(root, 150, &loaded, results, error, sizeof(error)) ==
               (installed ? 0 : 1));
        assert(results[0] == (installed ? LATCD_RETIREMENT_RESULT_DEFERRED : 4));
        assert(!latcd_retirement_page_budget_identity(&loaded, identity));
        if (!installed) assert(latcd_retirement_page_budget_commit(root, 150, &page, &budget,
                                                                    error, sizeof(error)) < 0);
        assert(!latcd_retirement_test_bound_budget_result(root, 150, identity, &budget, &page.entries[0],
                         LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
        assert(!latcd_retirement_page_budget_commit(root, 150, &page, &budget, error, sizeof(error)));
        assert(!latcd_retirement_page_finish_preserving_results(root, 150, &budget, error, sizeof(error)));
    }
    latcd_cache_capacity_close(&recovered);
    assert(!pthread_mutex_destroy(&recovered.lock));
    simulated_boottime_us = 0;
    g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_budgeted_rebind(void)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    struct stat st;
    assert(!stat(root, &st));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageState empty = {.cache_device = st.st_dev, .cache_inode = st.st_ino,
        .grace_us = 100, .round_cutoff = 120, .sequence = 4};
    g_strlcpy(empty.boot, boot, sizeof(empty.boot));
    LatcdRetirementPageState page = empty, loaded;
    page.count = 1;
    snprintf(page.entries[0].name, sizeof(page.entries[0].name), "%064x.so", 1);
    page.entries[0].deadline = 140; page.entries[0].enqueued = 100;
    page.entries[0].last_attempt = 3; page.entries[0].retry_at = 200; page.entries[0].busy_count = 1;
    g_strlcpy(page.cursor, page.entries[0].name, sizeof(page.cursor));
    uint8_t old_identity[32] = {1}, identity[32];
    assert(!latcd_retirement_schedule_store_result(root, boot, 100, 150, 3, &page.entries[0],
                       old_identity, LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    simulated_boottime_us = 150;
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    LatcdRetirementPageState mismatch = page;
    mismatch.entries[0].retry_at++;
    assert(latcd_retirement_page_stage_budgeted(root, &mismatch, &capacity, UINT64_MAX,
                                                &budget, error, sizeof(error)) < 0);
    assert(!budget.capacity && capacity.ready);
    assert(!latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                 &budget, error, sizeof(error)));
    assert(!latcd_retirement_page_budget_identity(&page, identity));
    assert(latcd_retirement_page_budget_commit(root, 150, &page, &budget, error, sizeof(error)) < 0);
    assert(latcd_retirement_test_bound_budget_result(root, 150, identity, &budget, &page.entries[0],
                      LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    LatcdRetirementPageDeadline premature = page.entries[0];
    premature.last_attempt = 4; premature.retry_at = 0; premature.busy_count = 0;
    uint64_t reserved = budget.remaining;
    assert(latcd_retirement_test_bound_budget_result(root, 150, identity, &budget, &premature,
                      LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(budget.remaining == reserved && capacity.ready);
    LatcdRetirementPageDeadline retained;
    uint64_t retained_sequence;
    assert(!latcd_retirement_schedule_load(root, boot, 100, 150, premature.name,
                                           &retained_sequence, &retained, error, sizeof(error)));
    assert(retained_sequence == 3 && retained.last_attempt == 3 && retained.retry_at == 200 &&
           retained.busy_count == 1);
    assert(!latcd_retirement_test_bound_budget_result(root, 150, identity, &budget, &page.entries[0],
                      LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
    assert(!latcd_cache_capacity_test_page_release(&capacity, &budget));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    LatcdCacheCapacity recovered = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    assert(!latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 100,
                                                 &budget, &loaded, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_finish(&recovered));
    assert(!latcd_retirement_page_budget_commit(root, 150, &page, &budget, error, sizeof(error)));
    assert(!latcd_cache_capacity_test_page_release(&recovered, &budget));
    latcd_cache_capacity_close(&recovered);
    char *shard_name = g_strconcat(page.entries[0].name, ".ini", NULL);
    char *shard_path = g_build_filename(store, shard_name, NULL), *shard = NULL;
    gsize shard_size;
    assert(g_file_get_contents(shard_path, &shard, &shard_size, NULL) && shard_size == 1024);
    char *padding = strchr(shard, '#');
    assert(padding && padding > shard);
    assert(!chmod(shard_path, 0600));
    assert(g_file_set_contents(shard_path, shard, padding - shard, NULL));
    assert(!chmod(shard_path, 0400));
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_reserve_page(&recovered, 2 * 65536, UINT64_MAX, identity, &budget));
    assert(latcd_retirement_page_finish_preserving_results(root, 150, &budget, error, sizeof(error)) < 0);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && loaded.committed_pending);
    assert(!latcd_cache_capacity_test_page_release(&recovered, &budget));
    latcd_cache_capacity_close(&recovered);
    assert(!chmod(shard_path, 0600));
    assert(g_file_set_contents(shard_path, shard, shard_size, NULL));
    assert(!chmod(shard_path, 0400));
    g_free(shard); g_free(shard_path); g_free(shard_name);
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    assert(!latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 100,
                                                 &budget, &loaded, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_finish(&recovered));
    assert(!latcd_retirement_page_finish_preserving_results(root, 150, &budget, error, sizeof(error)));
    latcd_cache_capacity_close(&recovered);
    assert(!pthread_mutex_destroy(&recovered.lock));
    simulated_boottime_us = 0;
    g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_budgeted_max_page(unsigned consumption)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    struct stat st;
    assert(!stat(root, &st));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageState empty = {.cache_device = st.st_dev, .cache_inode = st.st_ino,
        .grace_us = UINT64_MAX, .round_cutoff = UINT64_MAX - 1, .sequence = UINT64_MAX};
    g_strlcpy(empty.boot, boot, sizeof(empty.boot));
    snprintf(empty.committed_cursor, sizeof(empty.committed_cursor), "%064x-%064x.native", 0, 0);
    LatcdRetirementPageState page = empty, loaded;
    page.count = 128;
    for (unsigned i = 0; i < page.count; i++) {
        snprintf(page.entries[i].name, sizeof(page.entries[i].name), "%064x-%064x.native", i + 1, 0);
        page.entries[i].deadline = UINT64_MAX;
        page.entries[i].enqueued = UINT64_MAX - 1;
        page.entries[i].last_attempt = UINT64_MAX;
        page.entries[i].retry_at = UINT64_MAX;
        page.entries[i].busy_count = 7;
    }
    g_strlcpy(page.cursor, page.entries[127].name, sizeof(page.cursor));
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    simulated_boottime_us = UINT64_MAX;
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    assert(!latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                 &budget, error, sizeof(error)));
    uint8_t binding[32];
    assert(!latcd_retirement_page_budget_identity(&page, binding));
    for (unsigned i = 0; i < page.count; i++)
        assert(!latcd_retirement_test_bound_budget_result(root, UINT64_MAX, binding, &budget,
            &page.entries[i], i % 2 ? LATCD_RETIREMENT_RESULT_DONE : LATCD_RETIREMENT_RESULT_DEFERRED,
            error, sizeof(error)));
    assert(!latcd_retirement_page_budget_commit(root, UINT64_MAX, &page, &budget, error, sizeof(error)));
    if (consumption) {
        if (consumption == 5) {
            assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:file-synced", 1));
            assert(latcd_retirement_consumption_begin(root, UINT64_MAX, &budget, error, sizeof(error)) < 0);
            unsetenv("LATCD_TEST_RETIREMENT_IO");
            assert(!latcd_cache_capacity_poll(&capacity) && budget.invalid);
            assert(!latcd_cache_capacity_abandon_page(&capacity, &budget));
            latcd_cache_capacity_close(&capacity);
            assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
            latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
            assert(!latcd_cache_capacity_recovery_begin(&capacity));
            assert(!latcd_retirement_page_restore_budget(root, &capacity, UINT64_MAX, UINT64_MAX,
                                                         &budget, &loaded, error, sizeof(error)));
            assert(!latcd_cache_capacity_recovery_finish(&capacity));
            assert(!loaded.consumption_bound);
        }
        assert(!latcd_retirement_consumption_begin(root, UINT64_MAX, &budget, error, sizeof(error)));
        assert(latcd_retirement_consumption_prepare(root, UINT64_MAX, 0, &budget, error, sizeof(error)) < 0);
        if (consumption == 5) {
            assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:renamed", 1));
            assert(latcd_retirement_consumption_prepare(root, UINT64_MAX, 1, &budget, error, sizeof(error)) < 0);
            unsetenv("LATCD_TEST_RETIREMENT_IO");
            assert(!latcd_cache_capacity_poll(&capacity) && budget.invalid);
            assert(!latcd_cache_capacity_abandon_page(&capacity, &budget));
            latcd_cache_capacity_close(&capacity);
            assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
            latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
            assert(!latcd_cache_capacity_recovery_begin(&capacity));
            assert(!latcd_retirement_page_restore_budget(root, &capacity, UINT64_MAX, UINT64_MAX,
                                                         &budget, &loaded, error, sizeof(error)));
            assert(!latcd_cache_capacity_recovery_finish(&capacity));
            assert(loaded.consumption.intent_present);
        } else {
        assert(!latcd_retirement_consumption_prepare(root, UINT64_MAX, 1, &budget, error, sizeof(error)));
        }
        assert(latcd_retirement_consumption_prepare(root, UINT64_MAX, 1, &budget, error, sizeof(error)) < 0);
    }
    char *checkpoint = g_build_filename(gc, "retirement-page.ini", NULL);
    assert(!stat(checkpoint, &st) && st.st_size > 0 && st.st_size <= 65536);
    assert(!latcd_cache_capacity_test_page_release(&capacity, &budget));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    LatcdCacheCapacity recovered = LATCD_CACHE_CAPACITY_INIT;
    if (consumption == 5) {
        char *partial = g_build_filename(gc, ".write-unattributed", NULL);
        put(partial, "unfinished");
        assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
        latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
        assert(!latcd_cache_capacity_recovery_begin(&recovered));
        assert(latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, UINT64_MAX,
                                                    &budget, &loaded, error, sizeof(error)) < 0);
        assert(!budget.capacity && recovered.recovery_gate);
        assert(!latcd_cache_capacity_recovery_abort(&recovered));
        latcd_cache_capacity_close(&recovered);
        assert(!unlink(partial));
        g_free(partial);
    }
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    assert(!latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, UINT64_MAX,
                                                 &budget, &loaded, error, sizeof(error)));
    assert(loaded.committed_pending && loaded.count == 128 && budget.remaining == 2 * 65536);
    if (consumption)
        assert(latcd_retirement_consumption_apply(root, UINT64_MAX, &budget, error, sizeof(error)) < 0);
    assert(!latcd_cache_capacity_recovery_finish(&recovered));
    if (consumption) {
        assert(loaded.consumption_bound && loaded.consumption.intent_present && loaded.consumption.intent_index == 1);
        assert(!latcd_cache_capacity_test_page_release(&recovered, &budget));
        latcd_cache_capacity_close(&recovered);
        if (consumption > 1 && consumption < 5) {
            assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
            latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
            assert(!latcd_cache_capacity_recovery_begin(&recovered));
            assert(!latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, UINT64_MAX,
                                                         &budget, &loaded, error, sizeof(error)));
            assert(!latcd_cache_capacity_recovery_finish(&recovered));
            consumption_io_fault = consumption < 4 ? consumption - 1 : 0;
            consumption_unlinked = false;
            if (consumption == 4) assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:consumption-unlinked", 1));
            assert(latcd_retirement_consumption_apply(root, UINT64_MAX, &budget, error, sizeof(error)) < 0);
            if (consumption == 4) unsetenv("LATCD_TEST_RETIREMENT_IO");
            consumption_io_fault = 0;
            assert(!latcd_cache_capacity_poll(&recovered));
            assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
                   loaded.consumption.intent_present);
            assert(!latcd_cache_capacity_abandon_page(&recovered, &budget));
            latcd_cache_capacity_close(&recovered);
        }
        pid_t child = consumption == 1 ? fork() : -1;
        assert(consumption != 1 || child >= 0);
        if (!child) {
            LatcdCacheCapacity crash_capacity = LATCD_CACHE_CAPACITY_INIT;
            LatcdPageBudget crash_budget = {0};
            LatcdRetirementPageState crash_page;
            assert(!latcd_cache_capacity_scan(&crash_capacity, root, error, sizeof(error)));
            latcd_cache_capacity_metadata_bind(&crash_capacity, UINT64_MAX);
            assert(!latcd_cache_capacity_recovery_begin(&crash_capacity));
            assert(!latcd_retirement_page_restore_budget(root, &crash_capacity, UINT64_MAX, UINT64_MAX,
                                                         &crash_budget, &crash_page, error, sizeof(error)));
            assert(!latcd_cache_capacity_recovery_finish(&crash_capacity));
            assert(!setenv("LATCD_TEST_RETIREMENT_IO", "crash:consumption-unlinked", 1));
            latcd_retirement_consumption_apply(root, UINT64_MAX, &crash_budget, error, sizeof(error));
            _exit(1);
        }
        if (consumption == 1) {
            int crash_status;
            assert(waitpid(child, &crash_status, 0) == child && WIFSIGNALED(crash_status) &&
                   WTERMSIG(crash_status) == SIGKILL);
        }
        assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
               loaded.consumption.intent_present);
        assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
        latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
        assert(!latcd_cache_capacity_recovery_begin(&recovered));
        assert(!latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, UINT64_MAX,
                                                     &budget, &loaded, error, sizeof(error)));
        assert(!latcd_cache_capacity_recovery_finish(&recovered));
        assert(latcd_retirement_consumption_recover_step(root, UINT64_MAX, &budget, error, sizeof(error)) == 1);
        assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
               !loaded.consumption.intent_present && (loaded.consumption.completed[0] & 2));
        assert(latcd_retirement_consumption_apply(root, UINT64_MAX, &budget, error, sizeof(error)) < 0);
        assert(latcd_retirement_consumption_finish(root, UINT64_MAX, &budget, error, sizeof(error)) < 0);
        int recovery_step;
        do {
            recovery_step = latcd_retirement_consumption_recover_step(root, UINT64_MAX, &budget, error, sizeof(error));
        } while (recovery_step == 1);
        assert(!recovery_step);
        assert(!budget.capacity);
        assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
               !loaded.count && !loaded.committed_pending && !strcmp(loaded.committed_cursor, page.cursor));
        LatcdRetirementPageState merged = page;
        assert(!latcd_retirement_schedule_merge_page(root, boot, UINT64_MAX, UINT64_MAX,
                                                     &merged, error, sizeof(error)));
        assert(merged.entries[0].busy_count == page.entries[0].busy_count &&
               merged.entries[0].retry_at == page.entries[0].retry_at);
        latcd_cache_capacity_close(&recovered);
        assert(!pthread_mutex_destroy(&recovered.lock));
        simulated_boottime_us = 0;
        g_free(checkpoint); g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
        return;
    }
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:file-synced", 1));
    assert(latcd_retirement_page_finish_preserving_results(root, UINT64_MAX, &budget, error, sizeof(error)) < 0);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && loaded.committed_pending);
    assert(!latcd_cache_capacity_poll(&recovered) && budget.invalid);
    assert(!latcd_cache_capacity_abandon_page(&recovered, &budget));
    latcd_cache_capacity_close(&recovered);
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    assert(!latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, UINT64_MAX,
                                                 &budget, &loaded, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_finish(&recovered));
    latcd_retirement_test_before_page_finish = fail_page_finish;
    assert(latcd_retirement_page_finish_preserving_results(root, UINT64_MAX, &budget, error, sizeof(error)) < 0);
    assert(!latcd_retirement_test_before_page_finish && budget.invalid && !recovered.ready && budget.capacity);
    assert(latcd_cache_capacity_reserve(&recovered, 1, UINT64_MAX, error, sizeof(error)) < 0);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
           !loaded.count && !loaded.committed_pending && !strcmp(loaded.committed_cursor, page.cursor));
    LatcdRetirementPageState merged = page;
    merged.entries[0].retry_at = 0;
    merged.entries[0].busy_count = 0;
    assert(!latcd_retirement_schedule_merge_page(root, boot, UINT64_MAX, UINT64_MAX,
                                                  &merged, error, sizeof(error)));
    assert(merged.entries[0].retry_at == UINT64_MAX && merged.entries[0].busy_count == 7);
    uint64_t sequence = 0;
    LatcdRetirementPageDeadline retained;
    assert(!latcd_retirement_schedule_load(root, boot, UINT64_MAX, UINT64_MAX,
           page.entries[1].name, &sequence, &retained, error, sizeof(error)));
    assert(sequence == UINT64_MAX && !strcmp(retained.name, page.entries[1].name));
    assert(!latcd_cache_capacity_abandon_page(&recovered, &budget));
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_retirement_page_startup_check(root, error, sizeof(error)));
    latcd_cache_capacity_close(&recovered);
    assert(!pthread_mutex_destroy(&recovered.lock));
    simulated_boottime_us = 0;
    g_free(checkpoint); g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_schedule_max_record(void)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageDeadline entry = {.enqueued = UINT64_MAX,
        .last_attempt = UINT64_MAX, .retry_at = UINT64_MAX, .busy_count = 7};
    snprintf(entry.name, sizeof(entry.name), "%s-%s.native", source, source);
    assert(!latcd_retirement_schedule_store(root, boot, UINT64_MAX, UINT64_MAX,
                                            UINT64_MAX, &entry, error, sizeof(error)));
    char *filename = g_strconcat(entry.name, ".ini", NULL);
    char *path = g_build_filename(store, filename, NULL);
    struct stat st;
    assert(!stat(path, &st) && st.st_size == 1024);
    uint64_t sequence = 0;
    LatcdRetirementPageDeadline loaded;
    assert(!latcd_retirement_schedule_load(root, boot, UINT64_MAX, UINT64_MAX,
                                           entry.name, &sequence, &loaded, error, sizeof(error)));
    assert(sequence == UINT64_MAX && !strcmp(loaded.name, entry.name) &&
           loaded.enqueued == UINT64_MAX && loaded.last_attempt == UINT64_MAX &&
           loaded.retry_at == UINT64_MAX && loaded.busy_count == 7);
    g_free(path); g_free(filename); g_free(boot); g_free(store); g_free(gc);
    remove_root(root); g_free(root);
}

static void test_schedule_merge_multiple(void)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageState page = {.count = 3};
    for (unsigned i = 0; i < 3; i++) {
        snprintf(page.entries[i].name, sizeof(page.entries[i].name), "%064x.so", i + 1);
        page.entries[i].deadline = 1000 + i;
        page.entries[i].enqueued = 150;
    }
    for (unsigned i = 0; i < 3; i += 2) {
        LatcdRetirementPageDeadline hint = page.entries[i];
        hint.enqueued = 100 + i;
        hint.last_attempt = i + 1;
        hint.retry_at = 200 + i;
        hint.busy_count = i + 1;
        assert(!latcd_retirement_schedule_store(root, boot, 100, 150, i + 1,
                                                &hint, error, sizeof(error)));
    }
    assert(!latcd_retirement_schedule_merge_page(root, boot, 100, 150, &page, error, sizeof(error)));
    assert(page.sequence == 3 && page.entries[0].enqueued == 100 &&
           page.entries[0].retry_at == 200 && page.entries[1].enqueued == 150 &&
           !page.entries[1].retry_at && page.entries[2].enqueued == 102 &&
           page.entries[2].retry_at == 202);
    for (unsigned i = 0; i < 3; i++) assert(page.entries[i].deadline == 1000 + i);
    LatcdRetirementPageState snapshot = page;
    char *bad = g_build_filename(store, "unrelated", NULL);
    put(bad, "invalid\n");
    assert(latcd_retirement_schedule_merge_page(root, boot, 100, 150, &page, error, sizeof(error)) < 0);
    assert(!memcmp(&page, &snapshot, sizeof(page)));
    g_free(bad); g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_retry_page_identity(void)
{
    LatcdRetirementRetryPage *page = g_new0(LatcdRetirementRetryPage, 1);
    uint8_t original[32], changed[32];
    page->cache_device = 1; page->cache_inode = 2; page->grace_us = 10;
    page->round_cutoff = 100; page->snapshot_time = 200; page->snapshot_sequence = 150;
    strcpy(page->boot, "01234567-89ab-cdef-0123-456789abcdef");
    snprintf(page->retry_cursor, sizeof(page->retry_cursor), "%064x.so", 2);
    page->count = 3;
    const unsigned names[] = {3, 4, 1};
    for (unsigned i = 0; i < page->count; i++) {
        LatcdRetirementRetryItem *item = &page->items[i];
        snprintf(item->hint.name, sizeof(item->hint.name), "%064x.so", names[i]);
        item->hint.enqueued = 50; item->hint.last_attempt = 90; item->hint.retry_at = 180;
        item->hint.busy_count = 1; item->shard_sequence = 100 + i;
        item->shard_sequence_bound = true;
    }
    page->items[1].matched = true;
    page->items[1].aggregate = page->items[1].hint;
    page->items[1].aggregate.deadline = 190;
    strcpy(page->end_cursor, page->items[2].hint.name);
    assert(!latcd_retirement_retry_page_identity(page, original));
    uint8_t budget_identity[32], changed_budget[32];
    assert(!latcd_retirement_retry_page_budget_identity(page, budget_identity));
    char *encoded = NULL; size_t encoded_size = 0;
    LatcdRetirementRetryPage *decoded = g_new0(LatcdRetirementRetryPage, 1);
    assert(!latcd_retirement_retry_page_encode(page, &encoded, &encoded_size));
    assert(!latcd_retirement_retry_page_decode(encoded, encoded_size, decoded));
    assert(!latcd_retirement_retry_page_identity(decoded, changed) && !memcmp(original, changed, 32));
    char *tampered = g_strdup(encoded), *field = strstr(tampered, "sequence=100");
    assert(field); field[strlen("sequence=10")] = '1';
    assert(latcd_retirement_retry_page_decode(tampered, encoded_size, decoded) < 0 && !decoded->count);
    g_free(tampered);
    tampered = g_strconcat(encoded, "unexpected=1\n", NULL);
    assert(latcd_retirement_retry_page_decode(tampered, strlen(tampered), decoded) < 0);
    g_free(tampered); g_free(encoded); g_free(decoded);
    page->completed = 1; page->intent_present = true;
    memset(page->replacement_digest[0], 0x12, 32);
    memcpy(page->intent_data, "replacement", 11); page->intent_size = 11;
    memcpy(page->intent_original, "original", 8); page->intent_original_size = 8;
    GChecksum *intent_checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(intent_checksum, page->intent_data, page->intent_size);
    gsize intent_digest_size = 32;
    g_checksum_get_digest(intent_checksum, page->replacement_digest[1], &intent_digest_size);
    g_checksum_free(intent_checksum);
    intent_checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(intent_checksum, page->intent_original, page->intent_original_size);
    intent_digest_size = 32;
    g_checksum_get_digest(intent_checksum, page->items[1].shard_digest, &intent_digest_size);
    g_checksum_free(intent_checksum);
    assert(!latcd_retirement_retry_page_budget_identity(page, budget_identity));
    assert(!latcd_retirement_retry_page_budget_identity(page, changed_budget) &&
           !memcmp(budget_identity, changed_budget, 32));
    assert(!latcd_retirement_retry_page_identity(page, changed) && memcmp(original, changed, 32));
    assert(!latcd_retirement_retry_page_encode(page, &encoded, &encoded_size));
    decoded = g_new0(LatcdRetirementRetryPage, 1);
    assert(!latcd_retirement_retry_page_decode(encoded, encoded_size, decoded) &&
           decoded->completed == 1 && decoded->intent_present && decoded->intent_size == 11 &&
           !memcmp(decoded->intent_data, "replacement", 11));
    decoded->intent_data[0] ^= 1;
    assert(latcd_retirement_retry_page_identity(decoded, changed) < 0);
    tampered = g_strdup(encoded); field = strstr(tampered, "completed=1");
    assert(field); field[strlen("completed=")] = '2';
    assert(latcd_retirement_retry_page_decode(tampered, encoded_size, decoded) < 0);
    g_free(tampered); g_free(decoded); g_free(encoded);
    memset(page->replacement_digest, 0, sizeof(page->replacement_digest));
    page->completed = 0; page->intent_present = false; page->intent_size = 0; page->intent_original_size = 0;
    assert(!latcd_retirement_retry_page_budget_identity(page, budget_identity));
    page->completed = 1;
    memset(page->replacement_digest[0], 0x12, 32);
    page->deletion_intent = true;
    memset(page->receipt_digest[1], 0x34, 32);
    assert(!latcd_retirement_retry_page_budget_identity(page, changed_budget) &&
           !memcmp(budget_identity, changed_budget, 32));
    assert(!latcd_retirement_retry_page_encode(page, &encoded, &encoded_size));
    assert(strstr(encoded, "version=6\n"));
    decoded = g_new0(LatcdRetirementRetryPage, 1);
    assert(!latcd_retirement_retry_page_decode(encoded, encoded_size, decoded) &&
           decoded->deletion_intent && !decoded->deleted[1] &&
           !memcmp(decoded->receipt_digest[1], page->receipt_digest[1], 32));
    tampered = g_strdup(encoded); field = strstr(tampered, "receipt_digest=");
    assert(field); field[strlen("receipt_digest=")] = 'A';
    assert(latcd_retirement_retry_page_decode(tampered, encoded_size, decoded) < 0);
    g_free(tampered); g_free(encoded);
    page->deletion_intent = false; page->deleted[1] = true; page->completed = 2;
    assert(!latcd_retirement_retry_page_encode(page, &encoded, &encoded_size));
    assert(!latcd_retirement_retry_page_decode(encoded, encoded_size, decoded) &&
           decoded->deleted[1] && !decoded->deletion_intent);
    assert(!latcd_retirement_retry_page_budget_identity(decoded, changed_budget) &&
           !memcmp(budget_identity, changed_budget, 32));
    g_free(encoded);
    page->items[1].matched = false;
    memset(&page->items[1].aggregate, 0, sizeof(page->items[1].aggregate));
    assert(!latcd_retirement_retry_page_encode(page, &encoded, &encoded_size));
    assert(!latcd_retirement_retry_page_decode(encoded, encoded_size, decoded) &&
           decoded->deleted[1] && !decoded->items[1].matched);
    g_free(encoded);
    page->items[1].matched = true;
    page->items[1].aggregate = page->items[1].hint;
    page->items[1].aggregate.deadline = 190;
    g_free(decoded);
    page->completed = 0; page->deleted[1] = false;
    memset(page->replacement_digest, 0, sizeof(page->replacement_digest));
    memset(page->receipt_digest, 0, sizeof(page->receipt_digest));
    assert(!latcd_retirement_retry_page_identity(page, original));
    assert(!latcd_retirement_retry_page_budget_identity(page, budget_identity));
    page->items[0].shard_sequence++;
    assert(!latcd_retirement_retry_page_identity(page, changed) && memcmp(original, changed, 32));
    assert(!latcd_retirement_retry_page_budget_identity(page, changed_budget) &&
           memcmp(budget_identity, changed_budget, 32));
    page->items[0].shard_sequence--;
    page->items[1].aggregate.deadline++;
    assert(!latcd_retirement_retry_page_identity(page, changed) && memcmp(original, changed, 32));
    page->items[1].aggregate.deadline--;
    page->items[0].shard_sequence_bound = false;
    assert(latcd_retirement_retry_page_identity(page, changed) < 0);
    page->items[0].shard_sequence_bound = true;
    page->items[0].aggregate.deadline = 1;
    assert(latcd_retirement_retry_page_identity(page, changed) < 0);
    page->items[0].aggregate.deadline = 0;
    page->items[1].aggregate.enqueued++;
    assert(latcd_retirement_retry_page_identity(page, changed) < 0);
    page->items[1].aggregate.enqueued--;
    strcpy(page->items[2].hint.name, page->items[0].hint.name);
    assert(latcd_retirement_retry_page_identity(page, changed) < 0);
    memset(page->items, 0, sizeof(page->items));
    page->retry_cursor[0] = 0; page->count = 128;
    page->snapshot_time = UINT64_MAX; page->snapshot_sequence = UINT64_MAX;
    for (unsigned i = 0; i < page->count; i++) {
        LatcdRetirementRetryItem *item = &page->items[i];
        snprintf(item->hint.name, sizeof(item->hint.name), "%064x-%064x.native", i + 1, i + 1);
        item->hint.enqueued = UINT64_MAX; item->hint.last_attempt = UINT64_MAX;
        item->hint.retry_at = UINT64_MAX; item->hint.busy_count = 7;
        item->shard_sequence = UINT64_MAX; item->shard_sequence_bound = true;
        item->matched = true; item->aggregate = item->hint; item->aggregate.deadline = UINT64_MAX;
    }
    strcpy(page->end_cursor, page->items[127].hint.name);
    page->intent_present = true; page->intent_size = sizeof(page->intent_data);
    memset(page->intent_data, 0xab, page->intent_size);
    page->intent_original_size = sizeof(page->intent_original);
    memset(page->intent_original, 0xcd, page->intent_original_size);
    intent_checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(intent_checksum, page->intent_data, page->intent_size);
    intent_digest_size = 32;
    g_checksum_get_digest(intent_checksum, page->replacement_digest[0], &intent_digest_size);
    g_checksum_free(intent_checksum);
    intent_checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(intent_checksum, page->intent_original, page->intent_original_size);
    intent_digest_size = 32;
    g_checksum_get_digest(intent_checksum, page->items[0].shard_digest, &intent_digest_size);
    g_checksum_free(intent_checksum);
    decoded = g_new0(LatcdRetirementRetryPage, 1);
    assert(!latcd_retirement_retry_page_encode(page, &encoded, &encoded_size) && encoded_size < 65536);
    assert(!latcd_retirement_retry_page_decode(encoded, encoded_size, decoded) && decoded->count == 128);
    g_free(decoded); g_free(encoded);
    page->completed = 127;
    for (unsigned i = 0; i < 127; i++) memset(page->replacement_digest[i], 0x42, 32);
    memcpy(page->replacement_digest[127], page->items[0].shard_digest, 32);
    intent_checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(intent_checksum, page->intent_data, page->intent_size);
    intent_digest_size = 32;
    g_checksum_get_digest(intent_checksum, page->replacement_digest[127], &intent_digest_size);
    g_checksum_free(intent_checksum);
    memcpy(page->items[127].shard_digest, page->items[0].shard_digest, 32);
    assert(!latcd_retirement_retry_page_encode(page, &encoded, &encoded_size) && encoded_size < 65536);
    g_free(encoded);
    g_free(page);
}

static void test_retry_select(void)
{
    LatcdRetirementPageDeadline *entries = g_new0(LatcdRetirementPageDeadline, 4096);
    LatcdRetirementPageDeadline selected[128];
    unsigned count;
    for (unsigned i = 0; i < 4096; i++) {
        snprintf(entries[i].name, sizeof(entries[i].name), "%064x.so", i + 1);
        entries[i].enqueued = 100;
        entries[i].retry_at = i % 2 ? 201 : 200;
    }
    assert(!latcd_retirement_retry_select(entries, 4096, entries[4092].name, 200, selected, &count));
    assert(count == 128 && !strcmp(selected[0].name, entries[4094].name) &&
           !strcmp(selected[1].name, entries[0].name) && !strcmp(selected[127].name, entries[252].name));
    assert(!latcd_retirement_retry_select(entries, 4096, NULL, 199, selected, &count) && !count);
    assert(!latcd_retirement_retry_select(entries, 4096, NULL, 201, selected, &count) &&
           count == 128 && !strcmp(selected[127].name, entries[127].name));
    bool visited[4096] = {0};
    char cursor[138] = {0};
    for (unsigned page = 0; page < 32; page++) {
        assert(!latcd_retirement_retry_select(entries, 4096, cursor, 201, selected, &count) && count == 128);
        for (unsigned i = 0; i < count; i++) {
            unsigned id = 0;
            assert(sscanf(selected[i].name, "%x", &id) == 1 && id >= 1 && id <= 4096 && !visited[id - 1]);
            visited[id - 1] = true;
        }
        g_strlcpy(cursor, selected[count - 1].name, sizeof(cursor));
    }
    for (unsigned i = 0; i < 4096; i++) assert(visited[i]);
    assert(!latcd_retirement_retry_select(entries, 4096, cursor, 201, selected, &count) &&
           count == 128 && !strcmp(selected[0].name, entries[0].name));
    /* Replace one already visited slot per page with a later-sorting arrival.
     * Every member of the original snapshot must still be visited. */
    memset(visited, 0, sizeof(visited));
    cursor[0] = 0;
    for (unsigned page = 0; page < 32; page++) {
        assert(!latcd_retirement_retry_select(entries, 4096, cursor, 201, selected, &count) && count == 128);
        for (unsigned i = 0; i < count; i++) {
            unsigned id = 0;
            assert(sscanf(selected[i].name, "%x", &id) == 1);
            if (id <= 4096) {
                assert(id && !visited[id - 1]);
                visited[id - 1] = true;
            }
        }
        g_strlcpy(cursor, selected[count - 1].name, sizeof(cursor));
        unsigned slot = page * 128;
        assert(visited[slot]);
        memmove(&entries[slot], &entries[slot + 1], (4095 - slot) * sizeof(*entries));
        snprintf(entries[4095].name, sizeof(entries[4095].name), "%064x.so", 4097 + page);
        entries[4095].enqueued = 100;
        entries[4095].retry_at = 200;
    }
    for (unsigned i = 0; i < 4096; i++) assert(visited[i]);
    entries[1] = entries[0];
    assert(latcd_retirement_retry_select(entries, 4096, NULL, 201, selected, &count) < 0 && !count);
    g_free(entries);
}

static void test_schedule_byte_limit(void)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    struct stat cache;
    assert(!stat(root, &cache));
    for (unsigned i = 1; i <= 4095; i++) {
        char *name = g_strdup_printf("%064x.so", i);
        char *filename = g_strconcat(name, ".ini", NULL);
        char *path = g_build_filename(store, filename, NULL);
        char *record = g_strdup_printf("[schedule]\nversion=1\ndevice=%" G_GUINT64_FORMAT
            "\ninode=%" G_GUINT64_FORMAT "\nboot=%s\ngrace=100\nname=%s\n"
            "sequence=1\nenqueued=100\nlast_attempt=1\nretry_at=200\nbusy_count=1\n",
            (guint64)cache.st_dev, (guint64)cache.st_ino, boot, name);
        size_t length = strlen(record);
        assert(length < 1022);
        char *data = g_malloc(1025);
        memcpy(data, record, length);
        data[length] = '#';
        memset(data + length + 1, 'x', 1022 - length);
        data[1023] = '\n'; data[1024] = 0;
        assert(g_file_set_contents(path, data, 1024, NULL) && !chmod(path, 0400));
        g_free(data); g_free(record); g_free(path); g_free(filename); g_free(name);
    }
    LatcdRetirementPageDeadline entry = {.enqueued = 100, .last_attempt = 2,
                                          .retry_at = 201, .busy_count = 2};
    LatcdRetirementPageDeadline selected[128];
    unsigned selected_count;
    uint64_t snapshot_sequence, selected_sequences[128];
    char after[138];
    snprintf(after, sizeof(after), "%064x.so", 4093);
    assert(!latcd_retirement_retry_snapshot(root, boot, 100, 200, after,
                                            selected, &selected_count, &snapshot_sequence, selected_sequences, error, sizeof(error)));
    assert(selected_count == 128 && snapshot_sequence == 1 && selected_sequences[0] == 1 && strcmp(selected[0].name, after));
    snprintf(after, sizeof(after), "%064x.so", 4094);
    assert(!strcmp(selected[0].name, after));
    snprintf(after, sizeof(after), "%064x.so", 1);
    assert(!strcmp(selected[2].name, after));
    char *invalid = g_build_filename(store, "unexpected", NULL);
    put(invalid, "invalid");
    assert(latcd_retirement_retry_snapshot(root, boot, 100, 200, after,
                                           selected, &selected_count, &snapshot_sequence, selected_sequences, error, sizeof(error)) < 0 &&
           !selected_count && !snapshot_sequence);
    assert(!unlink(invalid));
    g_free(invalid);
    snprintf(entry.name, sizeof(entry.name), "%064x.so", 4096);
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error)) < 0);
    snprintf(entry.name, sizeof(entry.name), "%064x.so", 4095);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error)));
    LatcdRetirementPageDeadline loaded;
    uint64_t sequence;
    assert(!latcd_retirement_schedule_load(root, boot, 100, 150, entry.name,
                                           &sequence, &loaded, error, sizeof(error)));
    assert(sequence == 2 && loaded.last_attempt == 2 && loaded.busy_count == 2);
    for (unsigned i = 4094; i >= 4085; i--) {
        snprintf(entry.name, sizeof(entry.name), "%064x.so", i);
        assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry,
                                                error, sizeof(error)));
    }
    uint64_t total = 0;
    GDir *directory = g_dir_open(store, 0, NULL);
    assert(directory);
    const char *name;
    while ((name = g_dir_read_name(directory))) {
        char *path = g_build_filename(store, name, NULL);
        struct stat st;
        assert(!stat(path, &st) && st.st_size >= 0);
        total += st.st_size;
        g_free(path);
    }
    g_dir_close(directory);
    assert(total <= UINT64_C(4) * 1024 * 1024 - 1024);
    LatcdRetirementPageState empty = {.cache_device = cache.st_dev, .cache_inode = cache.st_ino,
        .grace_us = 100, .round_cutoff = 200, .sequence = 2};
    g_strlcpy(empty.boot, boot, sizeof(empty.boot));
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    simulated_boottime_us = 250;
    LatcdRetirementPageState page = empty;
    page.count = 1;
    snprintf(page.entries[0].name, sizeof(page.entries[0].name), "%064x.so", 4095);
    page.entries[0].deadline = 200;
    page.entries[0].enqueued = 100;
    page.entries[0].last_attempt = 2;
    page.entries[0].retry_at = 201;
    page.entries[0].busy_count = 2;
    g_strlcpy(page.cursor, page.entries[0].name, sizeof(page.cursor));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    assert(!latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                 &budget, error, sizeof(error)));
    uint8_t identity[32];
    assert(!latcd_retirement_page_budget_identity(&page, identity));
    assert(latcd_retirement_test_bound_budget_result(root, 200, identity, &budget, &page.entries[0],
                                               LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(!latcd_retirement_test_bound_budget_result(root, 250, identity, &budget, &page.entries[0],
                                                LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)));
    assert(!latcd_retirement_page_budget_commit(root, 250, &page, &budget, error, sizeof(error)));
    assert(!latcd_retirement_consumption_begin(root, 250, &budget, error, sizeof(error)));
    assert(!latcd_retirement_consumption_prepare(root, 250, 0, &budget, error, sizeof(error)));
    assert(!latcd_retirement_consumption_apply(root, 250, &budget, error, sizeof(error)));
    assert(!latcd_retirement_consumption_finish(root, 250, &budget, error, sizeof(error)));
    snprintf(entry.name, sizeof(entry.name), "%064x.so", 4094);
    assert(!latcd_retirement_schedule_load(root, boot, 100, 250, entry.name,
                                           &sequence, &loaded, error, sizeof(error)));
    assert(loaded.retry_at == 201 && loaded.busy_count == 2);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    simulated_boottime_us = 0;
    g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_schedule_growth_limit(void)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    struct stat cache;
    assert(!stat(root, &cache));
    for (unsigned i = 1; i <= 4096; i++) {
        char *name = g_strdup_printf("%064x.so", i);
        char *filename = g_strconcat(name, ".ini", NULL);
        char *path = g_build_filename(store, filename, NULL);
        char *record = g_strdup_printf("[schedule]\nversion=1\ndevice=%" G_GUINT64_FORMAT
            "\ninode=%" G_GUINT64_FORMAT "\nboot=%s\ngrace=100\nname=%s\n"
            "sequence=1\nenqueued=100\nlast_attempt=1\nretry_at=200\nbusy_count=1\n",
            (guint64)cache.st_dev, (guint64)cache.st_ino, boot, name);
        size_t length = strlen(record);
        size_t target = i == 4095 ? length : i == 4096 ? 1024 - length : 1024;
        assert(target >= length + (i == 4095 ? 0 : 2));
        char *data = g_malloc(target + 1);
        memcpy(data, record, length);
        if (target > length) {
            data[length] = '#';
            memset(data + length + 1, 'x', target - length - 2);
            data[target - 1] = '\n';
        }
        data[target] = 0;
        assert(g_file_set_contents(path, data, target, NULL) && !chmod(path, 0400));
        g_free(data); g_free(record); g_free(path); g_free(filename); g_free(name);
    }
    LatcdRetirementPageDeadline entry = {.enqueued = 100, .last_attempt = 100,
                                          .retry_at = 201, .busy_count = 2};
    snprintf(entry.name, sizeof(entry.name), "%064x.so", 4095);
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 100, &entry, error, sizeof(error)) < 0);
    LatcdRetirementPageDeadline loaded;
    uint64_t sequence;
    assert(!latcd_retirement_schedule_load(root, boot, 100, 150, entry.name,
                                           &sequence, &loaded, error, sizeof(error)));
    assert(sequence == 1 && loaded.last_attempt == 1 && loaded.busy_count == 1);
    snprintf(entry.name, sizeof(entry.name), "%064x.so", 4094);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 100, &entry,
                                            error, sizeof(error)));
    assert(!latcd_retirement_schedule_load(root, boot, 100, 150, entry.name,
                                           &sequence, &loaded, error, sizeof(error)));
    assert(sequence == 100 && loaded.last_attempt == 100 && loaded.busy_count == 2);
    char *filename = g_strconcat(entry.name, ".ini", NULL);
    char *path = g_build_filename(store, filename, NULL);
    struct stat shard_stat;
    assert(!stat(path, &shard_stat) && shard_stat.st_size == 1024);
    g_free(path); g_free(filename);
    g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_schedule_count_limit(void)
{
    char *root = root_new(), error[256], *boot = NULL;
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    struct stat cache;
    assert(!stat(root, &cache));
    for (unsigned i = 1; i <= 4096; i++) {
        char *name = g_strdup_printf("%064x.so", i);
        char *filename = g_strconcat(name, ".ini", NULL);
        char *path = g_build_filename(store, filename, NULL);
        char *data = g_strdup_printf("[schedule]\nversion=1\ndevice=%" G_GUINT64_FORMAT
            "\ninode=%" G_GUINT64_FORMAT "\nboot=%s\ngrace=100\nname=%s\n"
            "sequence=1\nenqueued=100\nlast_attempt=1\nretry_at=200\nbusy_count=1\n",
            (guint64)cache.st_dev, (guint64)cache.st_ino, boot, name);
        assert(g_file_set_contents(path, data, -1, NULL) && !chmod(path, 0400));
        g_free(data); g_free(path); g_free(filename); g_free(name);
    }
    LatcdRetirementPageDeadline entry = {.enqueued = 100, .last_attempt = 2,
                                          .retry_at = 201, .busy_count = 2};
    snprintf(entry.name, sizeof(entry.name), "%064x.so", 4097);
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error)) < 0);
    snprintf(entry.name, sizeof(entry.name), "%064x.so", 4096);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error)));
    LatcdRetirementPageDeadline loaded;
    uint64_t sequence;
    assert(!latcd_retirement_schedule_load(root, boot, 100, 150, entry.name,
                                           &sequence, &loaded, error, sizeof(error)));
    assert(sequence == 2 && loaded.last_attempt == 2 && loaded.busy_count == 2);
    LatcdRetirementPageState page = {.cache_device = cache.st_dev, .cache_inode = cache.st_ino,
        .grace_us = 100, .round_cutoff = 120, .sequence = 2, .count = 1};
    g_strlcpy(page.boot, boot, sizeof(page.boot));
    snprintf(page.entries[0].name, sizeof(page.entries[0].name), "%064x.so", 4097);
    page.entries[0].deadline = 140;
    page.entries[0].enqueued = 100;
    g_strlcpy(page.cursor, page.entries[0].name, sizeof(page.cursor));
    assert(!latcd_retirement_page_state_store(root, &page, error, sizeof(error)));
    assert(latcd_retirement_test_store_page_result(root, 150, &page, &page.entries[0],
            LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)) < 0);
    assert(latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)) < 0);
    LatcdRetirementPageState persisted;
    assert(!latcd_retirement_page_state_load(root, &persisted, error, sizeof(error)) &&
           persisted.count == 1 && !persisted.committed_cursor[0] &&
           !strcmp(persisted.cursor, page.cursor));
    assert(!latcd_retirement_schedule_load(root, boot, 100, 150, entry.name,
                                           &sequence, &loaded, error, sizeof(error)));
    assert(sequence == 2 && loaded.last_attempt == 2 && loaded.retry_at == 201 &&
           loaded.busy_count == 2);
    g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_schedule_capacity(void)
{
    char *root = root_new(), error[256];
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    char *boot = NULL;
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageDeadline entry = {.enqueued = 100, .last_attempt = 1,
                                          .retry_at = 200, .busy_count = 1};
    snprintf(entry.name, sizeof(entry.name), "%s.so", source);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 1, &entry, error, sizeof(error)));
    char *filename = g_strconcat(entry.name, ".ini", NULL);
    char *path = g_build_filename(store, filename, NULL), *before = NULL, *after = NULL;
    assert(g_file_get_contents(path, &before, NULL, NULL));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    uint64_t initial = capacity.metadata_committed;
    assert(initial > 0);
    latcd_cache_capacity_metadata_bind(&capacity, initial);
    entry.last_attempt = 2;
    uint8_t identity[32] = {1};
    errno = 0;
    assert(latcd_retirement_schedule_store_result(root, boot, 100, 150, 2, &entry, identity,
           LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)) < 0);
    assert(errno == ENOSPC && capacity.ready && capacity.metadata_committed == initial &&
           !capacity.metadata_reserved);
    assert(g_file_get_contents(path, &after, NULL, NULL) && !strcmp(before, after));
    g_free(after);
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:file-synced", 1));
    assert(latcd_retirement_schedule_store_result(root, boot, 100, 150, 2, &entry, identity,
           LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)) < 0);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(latcd_cache_capacity_poll(&capacity) && capacity.metadata_committed == initial &&
           !capacity.metadata_reserved);
    assert(g_file_get_contents(path, &after, NULL, NULL) && !strcmp(before, after));
    g_free(after);
    assert(!latcd_retirement_schedule_store_result(root, boot, 100, 150, 2, &entry, identity,
           LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
    assert(latcd_cache_capacity_poll(&capacity) && capacity.metadata_committed == initial &&
           !capacity.metadata_reserved);
    assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:renamed", 1));
    assert(latcd_retirement_schedule_store_result(root, boot, 100, 150, 2, &entry, identity,
           LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    unsetenv("LATCD_TEST_RETIREMENT_IO");
    assert(!latcd_cache_capacity_poll(&capacity) && capacity.metadata_committed == initial &&
           !capacity.metadata_reserved);
    LatcdRetirementResultKind kind = 0;
    assert(!latcd_retirement_schedule_load_result(root, boot, 100, 150, entry.name, identity,
                                                  &kind, error, sizeof(error)) &&
           kind == LATCD_RETIREMENT_RESULT_DONE);
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    LatcdCacheCapacity restarted = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&restarted, root, error, sizeof(error)) &&
           restarted.metadata_committed == initial && latcd_cache_capacity_poll(&restarted));
    latcd_cache_capacity_close(&restarted);
    assert(!pthread_mutex_destroy(&restarted.lock));
    g_free(before); g_free(path); g_free(filename); g_free(boot);
    g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_schedule_crash(bool renamed, bool result_record)
{
    char *root = root_new(), error[256];
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "retirement-schedule", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    char *boot = NULL;
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    LatcdRetirementPageDeadline entry = {.enqueued = 100, .last_attempt = 1,
                                          .retry_at = 200, .busy_count = 1};
    snprintf(entry.name, sizeof(entry.name), "%s.so", source);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 1, &entry, error, sizeof(error)));
    char *filename = g_strconcat(entry.name, ".ini", NULL);
    char *path = g_build_filename(store, filename, NULL), *before = NULL, *after = NULL;
    assert(g_file_get_contents(path, &before, NULL, NULL));
    entry.last_attempt = 2;
    entry.busy_count = 2;
    uint8_t identity[32] = {1};
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", renamed ? "crash:renamed" : "crash:file-synced", 1));
        if (result_record)
            latcd_retirement_schedule_store_result(root, boot, 100, 150, 2, &entry, identity,
                LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error));
        else
            latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error));
        _exit(1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    assert(g_file_get_contents(path, &after, NULL, NULL));
    if (renamed) {
        assert(strcmp(before, after));
        if (result_record) {
            LatcdRetirementResultKind kind = 0;
            assert(!latcd_retirement_schedule_load_result(root, boot, 100, 150, entry.name,
                                                          identity, &kind, error, sizeof(error)) &&
                   kind == LATCD_RETIREMENT_RESULT_DEFERRED);
        } else {
            assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error)));
        }
    } else {
        assert(!strcmp(before, after));
        assert(latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error)) < 0);
        LatcdRetirementPageDeadline loaded;
        uint64_t sequence = 99;
        memset(&loaded, 0xff, sizeof(loaded));
        assert(latcd_retirement_schedule_load(root, boot, 100, 150, entry.name,
                                               &sequence, &loaded, error, sizeof(error)) < 0);
        assert(!sequence && !loaded.name[0]);
        LatcdRetirementResultKind kind = LATCD_RETIREMENT_RESULT_DONE;
        assert(latcd_retirement_schedule_load_result(root, boot, 100, 150, entry.name,
                                                     identity, &kind, error, sizeof(error)) < 0 && !kind);
        LatcdRetirementPageState page = {.count = 1};
        page.entries[0] = entry;
        page.entries[0].deadline = 1000;
        LatcdRetirementPageState snapshot = page;
        assert(latcd_retirement_schedule_merge_page(root, boot, 100, 150, &page,
                                                     error, sizeof(error)) < 0);
        assert(!memcmp(&page, &snapshot, sizeof(page)));
        GDir *directory = g_dir_open(store, 0, NULL);
        assert(directory);
        unsigned temporary = 0;
        char *staging = NULL;
        const char *name;
        while ((name = g_dir_read_name(directory))) {
            if (g_str_has_prefix(name, ".write-")) {
                temporary++;
                staging = g_strdup(name);
            }
        }
        assert(temporary == 1);
        g_dir_close(directory);
        struct stat original, pending;
        char *staging_path = g_build_filename(store, staging, NULL);
        assert(!stat(path, &original) && !stat(staging_path, &pending));
        LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
        assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
        assert(capacity.metadata_committed == (uint64_t)(original.st_size + pending.st_size));
        latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
        int store_fd = open(store, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        assert(store_fd >= 0);
        assert(!latcd_cache_capacity_metadata_remove(store_fd, staging, pending.st_dev, pending.st_ino));
        assert(capacity.metadata_committed == (uint64_t)original.st_size);
        assert(!latcd_retirement_schedule_load(root, boot, 100, 150, entry.name,
                                               &sequence, &loaded, error, sizeof(error)));
        assert(sequence == 1 && loaded.last_attempt == 1 && loaded.busy_count == 1);
        assert(latcd_retirement_schedule_load_result(root, boot, 100, 150, entry.name,
                                                     identity, &kind, error, sizeof(error)) == 1 && !kind);
        assert(!latcd_retirement_schedule_store(root, boot, 100, 150, 2, &entry, error, sizeof(error)));
        close(store_fd);
        latcd_cache_capacity_close(&capacity);
        assert(!pthread_mutex_destroy(&capacity.lock));
        g_free(staging_path); g_free(staging);
    }
    g_free(after); g_free(before); g_free(path); g_free(filename); g_free(boot);
    g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_recovery_round_barrier(void)
{
    char *root = root_new(), error[256];
    LatcdRetirementPublication *publication =
        latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication);
    assert(!latcd_retirement_publication_prepare(publication, source, next, strlen(next),
                                                 NULL, error, sizeof(error)));
    char *current = current_path(root);
    put(current, next);
    latcd_retirement_publication_close(publication);
    char *path = single_record(root), *before = NULL, *after = NULL;
    gsize before_size, after_size;
    assert(g_file_get_contents(path, &before, &before_size, NULL));
    LatcdRecoveryCursor *cursor = latcd_recovery_open(root, false, error, sizeof(error));
    assert(cursor);
    int exclusive = latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB, error, sizeof(error));
    assert(exclusive >= 0);
    LatcdRecoveryProgress progress;
    assert(latcd_recovery_step(cursor, 32, 65536, 100000, &progress,
                               error, sizeof(error)) < 0);
    assert(g_file_get_contents(path, &after, &after_size, NULL));
    assert(before_size == after_size && !memcmp(before, after, before_size));
    close(exclusive);
    simulated_boottime_us = 1234;
    int result;
    do {
        result = latcd_recovery_step(cursor, 32, 65536, 100000, &progress,
                                     error, sizeof(error));
    } while (result > 0);
    assert(!result);
    GKeyFile *record = g_key_file_new();
    assert(g_key_file_load_from_file(record, path, 0, NULL));
    char *state = g_key_file_get_string(record, "transaction", "state", NULL);
    assert(!g_strcmp0(state, "RETIRED"));
    assert(g_key_file_get_uint64(record, "transaction", "retired_boottime_us", NULL) == 1234);
    g_free(state); g_key_file_unref(record);
    simulated_boottime_us = 0;
    latcd_recovery_close(cursor);
    g_free(before); g_free(after); g_free(path); g_free(current);
    remove_root(root); g_free(root);
}

static void test_recovery_lock_directory_swap(void)
{
    char *root = root_new(), error[256];
    LatcdRetirementPublication *publication =
        latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication && !latcd_retirement_publication_prepare(publication, source,
        next, strlen(next), NULL, error, sizeof(error)));
    char *current = current_path(root);
    put(current, next);
    latcd_retirement_publication_close(publication);
    char *record = single_record(root), *before = NULL, *after = NULL;
    gsize before_size, after_size;
    assert(g_file_get_contents(record, &before, &before_size, NULL));
    LatcdRecoveryCursor *cursor = latcd_recovery_open(root, false, error, sizeof(error));
    assert(cursor);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *old = g_build_filename(root, ".gc-old", NULL);
    roots_swap_path = gc; roots_swap_old = old;
    LatcdRecoveryProgress progress;
    assert(latcd_recovery_step(cursor, 32, 65536, 100000, &progress,
                               error, sizeof(error)) < 0);
    assert(!roots_swap_path);
    assert(!rmdir(gc) && !rename(old, gc));
    roots_swap_old = NULL;
    assert(g_file_get_contents(record, &after, &after_size, NULL));
    assert(before_size == after_size && !memcmp(before, after, before_size));
    assert(latcd_recovery_step(cursor, 32, 65536, 100000, &progress,
                               error, sizeof(error)) < 0);
    latcd_recovery_close(cursor);
    g_free(before); g_free(after); g_free(record); g_free(current); g_free(gc); g_free(old);
    remove_root(root); g_free(root);
}

static void test_round_directory_swap(bool swap_gc)
{
    char *root = root_new(), error[256];
    char *gc = g_build_filename(root, ".gc", NULL);
    char *target = g_strdup(swap_gc ? gc : root);
    char *old_path = g_strconcat(target, "-moved", NULL);
    int lock = latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, sizeof(error));
    assert(lock >= 0);
    close(lock);
    clock_swap_path = target;
    clock_swap_old = old_path;
    simulated_boottime_us = 1234;
    LatcdRetirementPageState state;
    assert(latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)) < 0);
    assert(!state.round_cutoff && !clock_swap_path);
    char *new_page = g_build_filename(root, ".gc", "retirement-page.ini", NULL);
    assert(!g_file_test(new_page, G_FILE_TEST_EXISTS));
    simulated_boottime_us = 0;
    clock_swap_old = NULL;
    g_free(new_page);
    if (swap_gc) {
        assert(!rmdir(gc));
        assert(!rename(old_path, gc));
    } else {
        assert(!rmdir(root));
        assert(!rename(old_path, root));
    }
    remove_root(root);
    g_free(old_path); g_free(target); g_free(gc); g_free(root);
}

static void test_page_state_write_fault(const char *point, bool crash)
{
    char *root = root_new(), error[256], *path = NULL;
    struct stat cache;
    assert(!stat(root, &cache));
    LatcdRetirementPageState state = {
        .cache_device = cache.st_dev, .cache_inode = cache.st_ino, .grace_us = 1, .round_cutoff = 2,
        .boot = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", .cursor = "b", .count = 1,
        .committed_cursor = "0", .entries = {{"b", 10, 1, 0, 0, 0}}
    };
    assert(!latcd_retirement_page_state_store(root, &state, error, sizeof(error)));
    state.entries[0].deadline = 20;
    state.round_cutoff = 3;
    g_strlcpy(state.committed_cursor, "a", sizeof(state.committed_cursor));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        char *fault = g_strdup_printf("%s:%s", crash ? "crash" : "error", point);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
        int result = latcd_retirement_page_state_store(root, &state, error, sizeof(error));
        assert(!crash && result < 0);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    if (crash) assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    else assert(WIFEXITED(status) && !WEXITSTATUS(status));
    LatcdRetirementPageState loaded;
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)));
    assert(loaded.count == 1 && !strcmp(loaded.cursor, "b") &&
           !strcmp(loaded.entries[0].name, "b") &&
           ((loaded.entries[0].deadline == 10 && loaded.round_cutoff == 2 &&
             !strcmp(loaded.committed_cursor, "0")) ||
            (loaded.entries[0].deadline == 20 && loaded.round_cutoff == 3 &&
             !strcmp(loaded.committed_cursor, "a"))));
    path = g_build_filename(root, ".gc", "retirement-page.ini", NULL);
    assert(g_file_test(path, G_FILE_TEST_IS_REGULAR));
    g_free(path); remove_root(root); g_free(root);
}

static void assert_tombstone_status(const char *marker, const char *expected)
{
    GKeyFile *record = g_key_file_new();
    assert(g_key_file_load_from_file(record, marker, 0, NULL));
    char *value = g_key_file_get_string(record, "tombstone", "recovery_status", NULL);
    assert(!g_strcmp0(value, expected));
    g_free(value);
    g_key_file_unref(record);
}

static void test_tombstone_capacity_admission(bool missing)
{
    char *root = root_new(), *name = g_strdup_printf("%s.native", source);
    char *path = g_build_filename(root, name, NULL), error[256];
    char *marker = g_build_filename(root, ".gc", "tombstones", name, NULL);
    put(path, "retired immutable native\n");
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(evidence && fd >= 0 && !latcd_retirement_tombstone(root, source, name,
        fd, evidence, error, sizeof(error)));
    close(fd);
    if (missing) assert(!unlink(path));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    latcd_cache_capacity_unknown_task(&capacity, "tombstone-admission-test");
    unsigned recovered = 0;
    int result = latcd_tombstone_recover(root, &recovered, error, sizeof(error));
    if (missing) {
        assert(!result && recovered == 1);
        assert_tombstone_status(marker, "MISSING");
        assert(!latcd_cache_capacity_poll(&capacity));
    } else {
        assert(result < 0);
        assert(!access(path, F_OK));
    }
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    g_free(evidence); g_free(marker); g_free(path); g_free(name);
    remove_root(root); g_free(root);
}

static void test_tombstone_recovery(int mutation)
{
    char *root = root_new(), *name = g_strdup_printf("%s.native", source);
    char *path = g_build_filename(root, name, NULL), error[256];
    char *marker = g_build_filename(root, ".gc", "tombstones", name, NULL);
    put(path, "retired immutable native\n");
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    assert(evidence);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0 && !latcd_retirement_tombstone(root, source, name, fd, evidence,
                                                error, sizeof(error)));
    close(fd);
    const char *expected = "MATCHED";
    char *alias = g_build_filename(root, "alias", NULL);
    char *current = current_path(root);
    if (mutation == 1) { assert(!unlink(path)); expected = "MISSING"; }
    if (mutation == 2) { put(path, "replaced inode\n"); expected = "UNKNOWN"; }
    if (mutation == 3) {
        assert(!chmod(path, 0600));
        fd = open(path, O_WRONLY);
        assert(fd >= 0 && write(fd, "X", 1) == 1);
        close(fd); fd = -1;
        assert(!chmod(path, 0400)); expected = "UNKNOWN";
    }
    if (mutation == 4) { assert(!link(path, alias)); expected = "UNKNOWN"; }
    if (mutation == 5) {
        assert(!rename(path, alias) && !symlink(alias, path)); expected = "UNKNOWN";
    }
    if (mutation == 6) { put(current, "broken current\n"); expected = "UNKNOWN"; }
    if (mutation == 7) {
        char *manifest = g_strdup_printf("{\"version\":2,\"module\":\"%s.so\","
            "\"native\":\"%s\",\"tbset\":\"\",\"source_sha256\":\"%s\","
            "\"codegen_id\":\"%s\",\"published_sequence\":1}", source, name, source, source);
        put(current, manifest); g_free(manifest); expected = "UNKNOWN";
    }
    if (mutation == 8) {
        fd = open(path, O_RDONLY | O_CLOEXEC);
        assert(fd >= 0 && !flock(fd, LOCK_SH)); expected = "BUSY";
    }
    if (mutation == 9) {
        put(marker, "[tombstone]\nversion=1\nversion=1\n");
        unsigned recovered;
        assert(latcd_tombstone_recover(root, &recovered, error, sizeof(error)));
        assert(!access(path, F_OK));
        goto out;
    }
    if (mutation == 10) {
        fd = lat_aot_v2_cache_source_lock(root, source, LOCK_SH, false, error, sizeof(error));
        assert(fd >= 0); expected = "BUSY";
    }
    for (int pass = 0; pass < 2; pass++) {
        unsigned recovered;
        assert(!latcd_tombstone_recover(root, &recovered, error, sizeof(error)) && recovered == 1);
        assert_tombstone_status(marker, expected);
        assert((access(path, F_OK) == 0) == (mutation != 1));
    }
    if (mutation == 8 || mutation == 10) {
        close(fd); fd = -1;
        unsigned recovered;
        assert(!latcd_tombstone_recover(root, &recovered, error, sizeof(error)));
        assert_tombstone_status(marker, "MATCHED");
    }
    if (mutation == 1) {
        put(path, "reappeared object\n");
        unsigned recovered;
        assert(!latcd_tombstone_recover(root, &recovered, error, sizeof(error)));
        assert_tombstone_status(marker, "UNKNOWN");
    }
    if (mutation == 6 || mutation == 7) {
        assert(!unlink(current));
        unsigned recovered;
        assert(!latcd_tombstone_recover(root, &recovered, error, sizeof(error)));
        assert_tombstone_status(marker, "UNKNOWN");
    }
out:
    if ((mutation == 8 || mutation == 10) && fd >= 0) close(fd);
    g_free(current); g_free(alias); g_free(evidence); g_free(marker); g_free(path); g_free(name);
    remove_root(root); g_free(root);
}

static void test_tombstone_recovery_crash(const char *point, bool crash, bool missing)
{
    char *root = root_new(), *name = g_strdup_printf("%s.native", source);
    char *path = g_build_filename(root, name, NULL), error[256];
    char *marker = g_build_filename(root, ".gc", "tombstones", name, NULL);
    put(path, "immutable recovery baseline\n");
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    assert(evidence);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0 && !latcd_retirement_tombstone(root, source, name, fd, evidence,
                                                error, sizeof(error)));
    close(fd);
    if (missing) assert(!unlink(path));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        char *setting = g_strdup_printf("%s:%s", crash ? "crash" : "error", point);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", setting, 1));
        unsigned recovered;
        int result = latcd_tombstone_recover(root, &recovered, error, sizeof(error));
        assert(!crash && result < 0);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    if (crash) assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    else assert(WIFEXITED(status) && !WEXITSTATUS(status));
    for (int pass = 0; pass < 2; pass++) {
        unsigned recovered;
        assert(!latcd_tombstone_recover(root, &recovered, error, sizeof(error)) && recovered == 1);
        assert_tombstone_status(marker, missing ? "MISSING" : "MATCHED");
        assert((!access(path, F_OK)) == !missing);
    }
    g_free(marker); g_free(evidence); g_free(path); g_free(name);
    remove_root(root); g_free(root);
}

static void test_tombstone_delete(const char *point, bool crash, int mutation)
{
    char *root = root_new(), *name = g_strdup_printf("%s.native", source);
    char *path = g_build_filename(root, name, NULL), error[256];
    char *marker = g_build_filename(root, ".gc", "tombstones", name, NULL);
    char *current = current_path(root);
    put(path, "immutable disposable test object\n");
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    assert(evidence);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0 && !latcd_retirement_tombstone(root, source, name, fd, evidence,
                                                error, sizeof(error)));
    close(fd); fd = -1;
    if (mutation == 1) {
        fd = open(path, O_RDONLY | O_CLOEXEC);
        assert(fd >= 0 && !flock(fd, LOCK_SH));
    }
    if (mutation == 2) put(path, "replacement must survive\n");
    if (mutation == 3 || mutation == 10) put(current, "invalid manifest\n");
    if (mutation == 4 || mutation == 9) {
        char *manifest = g_strdup_printf("{\"version\":2,\"module\":\"%s.so\","
            "\"native\":\"%s\",\"tbset\":\"\",\"source_sha256\":\"%s\","
            "\"codegen_id\":\"%s\",\"published_sequence\":1}", source, name, source, source);
        put(current, manifest); g_free(manifest);
    }
    if (mutation == 5) {
        fd = lat_aot_v2_cache_source_lock(root, source, LOCK_SH, false, error, sizeof(error));
        assert(fd >= 0);
    }
    if (mutation == 6 || mutation == 9 || mutation == 10) assert(!unlink(path));
    if (mutation == 7) put(marker, "broken tombstone\n");
    if (mutation == 8) {
        assert(!chmod(path, 0600));
        int writer = open(path, O_WRONLY);
        assert(writer >= 0 && write(writer, "X", 1) == 1);
        close(writer); assert(!chmod(path, 0400));
    }
    bool rejected = mutation && mutation != 6;
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        if (point) {
            char *setting = g_strdup_printf("%s:%s", crash ? "crash" : "error", point);
            assert(!setenv("LATCD_TEST_RETIREMENT_IO", setting, 1));
        }
        int result = latcd_tombstone_delete(root, name, error, sizeof(error));
        assert(!crash && ((result < 0) == (rejected || point != NULL)));
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    if (crash) assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    else assert(WIFEXITED(status) && !WEXITSTATUS(status));
    if (fd >= 0) close(fd);
    assert(!access(marker, F_OK));
    if ((rejected && mutation != 9 && mutation != 10) ||
        (point && !strcmp(point, "before-unlink"))) assert(!access(path, F_OK));
    else assert(access(path, F_OK));
    if (mutation == 9 || mutation == 10) {
        GKeyFile *record = g_key_file_new();
        assert(g_key_file_load_from_file(record, marker, 0, NULL));
        assert(!g_key_file_has_key(record, "tombstone", "deletion_status", NULL));
        g_key_file_unref(record);
        assert_tombstone_status(marker, "UNKNOWN");
    }
    if (!rejected) {
        for (int pass = 0; pass < 2; pass++) {
            unsigned recovered;
            assert(!latcd_tombstone_recover(root, &recovered, error, sizeof(error)));
            assert(!latcd_tombstone_delete(root, name, error, sizeof(error)));
            assert_tombstone_status(marker, "MISSING");
            GKeyFile *record = g_key_file_new();
            assert(g_key_file_load_from_file(record, marker, 0, NULL));
            char *value = g_key_file_get_string(record, "tombstone", "deletion_status", NULL);
            assert(!g_strcmp0(value, "UNLINKED"));
            g_free(value); g_key_file_unref(record);
        }
        /* A completed path must never authorize deleting a new inode. */
        put(path, "new object at old name\n");
        assert(latcd_tombstone_delete(root, name, error, sizeof(error)));
        assert(!access(path, F_OK));
        assert_tombstone_status(marker, "UNKNOWN");
    }
    assert(latcd_tombstone_delete(root, "../outside.native", error, sizeof(error)));
    g_free(current); g_free(marker); g_free(evidence); g_free(path); g_free(name);
    remove_root(root); g_free(root);
}

static void test_deleted_transaction_recovery(int mutation, const char *point, bool crash)
{
    char *root = root_new(), error[256];
    char *current = current_path(root);
    char *names[6], *paths[6];
    const char *suffixes[] = {".so", ".native", ".tbset"};
    for (size_t i = 0; i < 6; i++) {
        names[i] = i < 3 ? g_strconcat(source, suffixes[i], NULL) :
            g_strdup_printf("%s-%s%s", source, source, suffixes[i - 3]);
        paths[i] = g_build_filename(root, names[i], NULL);
        put(paths[i], "immutable transaction input\n");
    }
    char *previous = g_strdup_printf("{\"version\":2,\"module\":\"%s\",\"native\":\"%s\","
        "\"tbset\":\"%s\",\"source_sha256\":\"%s\",\"codegen_id\":\"%s\",\"published_sequence\":1}",
        names[0], names[1], names[2], source, source);
    char *following = g_strdup_printf("{\"version\":2,\"module\":\"%s\",\"native\":\"%s\","
        "\"tbset\":\"%s\",\"source_sha256\":\"%s\",\"codegen_id\":\"%s\",\"published_sequence\":2}",
        names[3], names[4], names[5], source, source);
    put(current, previous);
    char *evidence = latcd_retirement_capture_objects(root, source, (const char *const *)names, 6);
    LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(evidence && publication && !latcd_retirement_publication_prepare(publication, source,
        following, strlen(following), evidence, error, sizeof(error)));
    put(current, following);
    assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
    latcd_retirement_publication_close(publication);
    for (size_t i = 0; i < 3; i++) {
        const char *capture[] = {names[i]};
        char *single = latcd_retirement_capture_objects(root, source, capture, 1);
        int fd = open(paths[i], O_RDONLY | O_CLOEXEC);
        assert(single && fd >= 0 && !latcd_retirement_tombstone(root, source, names[i], fd,
            single, error, sizeof(error)));
        close(fd); g_free(single);
        if (!i && (mutation == 18 || mutation == 19 || mutation == 24)) {
            pid_t child = fork();
            assert(child >= 0);
            if (!child) {
                assert(!setenv("LATCD_TEST_RETIREMENT_IO", mutation == 18 ?
                    "crash:unlinked" : "crash:unlink-synced", 1));
                latcd_tombstone_delete(root, names[i], error, sizeof(error));
                _exit(127);
            }
            int status;
            assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
                   WTERMSIG(status) == SIGKILL);
        } else if (!i) assert(!latcd_tombstone_delete(root, names[i], error, sizeof(error)));
    }
    char *marker = g_build_filename(root, ".gc", "tombstones", names[0], NULL);
    if (mutation >= 1 && mutation <= 9) {
        GKeyFile *record = g_key_file_new();
        assert(g_key_file_load_from_file(record, marker, 0, NULL));
        if (mutation == 1) g_key_file_remove_key(record, "tombstone", "deletion_status", NULL);
        if (mutation == 2) g_key_file_set_string(record, "tombstone", "recovery_status", "UNKNOWN");
        if (mutation == 3) g_key_file_set_string(record, "tombstone", "sha256", source);
        if (mutation == 4) g_key_file_set_uint64(record, "tombstone", "inode", 0);
        if (mutation == 5) g_key_file_set_uint64(record, "tombstone", "device", 0);
        if (mutation == 6) g_key_file_set_uint64(record, "tombstone", "size", 1);
        if (mutation == 7) g_key_file_set_uint64(record, "tombstone", "allocated", 1);
        if (mutation == 8) g_key_file_set_string(record, "tombstone", "unexpected", "1");
        if (mutation == 9) g_key_file_set_string(record, "tombstone", "recovery_status", "BUSY");
        char *raw = g_key_file_to_data(record, NULL, NULL);
        put(marker, raw); g_free(raw); g_key_file_unref(record);
    }
    if (mutation == 10) put(paths[0], "replacement must survive\n");
    if (mutation == 11) assert(!unlink(marker));
    if (mutation == 12 || mutation == 21) put(current, previous);
    if (mutation == 13 || mutation == 22) assert(!unlink(current));
    if (mutation == 14 || mutation == 23) put(current, "broken current\n");
    if ((mutation >= 15 && mutation <= 17) || mutation >= 20) {
        GKeyFile *record = g_key_file_new();
        assert(g_key_file_load_from_file(record, marker, 0, NULL));
        g_key_file_remove_key(record, "tombstone", "deletion_status", NULL);
        if (mutation == 15) g_key_file_remove_key(record, "tombstone", "recovery_status", NULL);
        if (mutation == 16) g_key_file_set_string(record, "tombstone", "recovery_status", "MATCHED");
        if (mutation == 17) g_key_file_set_string(record, "tombstone", "recovery_status", "BUSY");
        char *raw = g_key_file_to_data(record, NULL, NULL);
        put(marker, raw); g_free(raw); g_key_file_unref(record);
    }
    unsigned recovered;
    if (mutation == 18 || mutation == 19) {
        char *transaction = single_record(root), *before_tx = NULL, *before_marker = NULL;
        char *after_tx = NULL, *after_marker = NULL;
        assert(g_file_get_contents(transaction, &before_tx, NULL, NULL));
        assert(g_file_get_contents(marker, &before_marker, NULL, NULL));
        LatcdRecoveryCursor *cursor = latcd_recovery_open_untrusted(root, false,
                                                                   error, sizeof(error));
        assert(cursor);
        LatcdRecoveryProgress progress;
        int result;
        do { result = latcd_recovery_step(cursor, 32, 4 * 1024 * 1024, 10000,
                                           &progress, error, sizeof(error)); } while (result > 0);
        assert(result < 0);
        latcd_recovery_close(cursor);
        assert(g_file_get_contents(transaction, &after_tx, NULL, NULL));
        assert(g_file_get_contents(marker, &after_marker, NULL, NULL));
        assert(!strcmp(before_tx, after_tx) && !strcmp(before_marker, after_marker));
        assert(access(paths[0], F_OK) && !access(paths[3], F_OK));
        g_free(transaction); g_free(before_tx); g_free(before_marker);
        g_free(after_tx); g_free(after_marker);
    }
    if (mutation == 24) {
        char *original_path = single_record(root), *original = NULL;
        assert(g_file_get_contents(original_path, &original, NULL, NULL));
        GKeyFile *pending = g_key_file_new();
        assert(g_key_file_load_from_data(pending, original, -1, 0, NULL));
        g_key_file_set_string(pending, "transaction", "state", "PREPARED");
        char *pending_data = g_key_file_to_data(pending, NULL, NULL);
        char *id = g_uuid_string_random(), *filename = g_strdup_printf("%s.ini", id);
        char *pending_path = g_build_filename(root, ".gc", "transactions", filename, NULL);
        put(pending_path, pending_data);
        assert(latcd_retirement_recover(root, &recovered, error, sizeof(error)) < 0);
        assert(!unlink(pending_path));
        assert_state(root, "RETIRED");
        g_free(pending_path); g_free(filename); g_free(id); g_free(pending_data);
        g_key_file_unref(pending); g_free(original); g_free(original_path);
        char *lease_id = g_uuid_string_random();
        int lease = latcd_retirement_mount_lease(root, lease_id, "CACHE", NULL, NULL,
                                                 error, sizeof(error));
        assert(lease >= 0);
        close(lease);
        assert(latcd_retirement_recover(root, &recovered, error, sizeof(error)) < 0);
        assert_state(root, "RETIRED");
        assert(!latcd_retirement_mount_release(root, lease_id, error, sizeof(error)));
        char *mounts = g_build_filename(root, ".gc", "mount-leases", NULL);
        int mount_lock = open(mounts, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        assert(mount_lock >= 0 && !flock(mount_lock, LOCK_EX | LOCK_NB));
        assert(latcd_retirement_recover(root, &recovered, error, sizeof(error)) < 0);
        assert_state(root, "RETIRED");
        close(mount_lock); g_free(mounts); g_free(lease_id);
    }
    if (point) {
        pid_t child = fork();
        assert(child >= 0);
        if (!child) {
            char *fault = g_strdup_printf("%s:%s", crash ? "crash" : "error", point);
            assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
            int result = latcd_retirement_recover(root, &recovered, error, sizeof(error));
            _exit(result ? 0 : 127);
        }
        int status;
        assert(waitpid(child, &status, 0) == child);
        assert(crash ? WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL :
                       WIFEXITED(status) && !WEXITSTATUS(status));
        assert_state(root, "RETIRED");
    }
    if (mutation == 20) {
        int latch = lat_aot_v2_cache_source_lock(root, source, LOCK_EX, false, NULL, 0);
        assert(latch >= 0);
        assert(latcd_retirement_recover(root, &recovered, error, sizeof(error)) < 0);
        assert_state(root, "RETIRED");
        close(latch);
    }
    for (int pass = 0; pass < 2; pass++) {
        assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)) && recovered == 1);
        bool accepted = !mutation || mutation == 1 || mutation == 15 || mutation == 16 ||
                        mutation == 18 || mutation == 19 || mutation == 20 || mutation == 24;
        assert_state(root, accepted ? "RETIRED" : "UNKNOWN");
        if (accepted) {
            GKeyFile *record = g_key_file_new();
            assert(g_key_file_load_from_file(record, marker, 0, NULL));
            char *value = g_key_file_get_string(record, "tombstone", "deletion_status", NULL);
            assert(!g_strcmp0(value, "UNLINKED"));
            g_free(value); g_key_file_unref(record);
            assert_tombstone_status(marker, "MISSING");
        }
        assert((access(paths[0], F_OK) == 0) == (mutation == 10));
        assert(!access(paths[3], F_OK) && !access(paths[4], F_OK) && !access(paths[5], F_OK));
    }
    if (!mutation) {
        /* Resume after one completed object; remaining evidence stays usable. */
        for (size_t i = 1; i < 3; i++) {
            assert(!latcd_tombstone_delete(root, names[i], error, sizeof(error)));
            assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
            assert_state(root, "RETIRED");
        }
    }
    for (size_t i = 0; i < 6; i++) { g_free(paths[i]); g_free(names[i]); }
    g_free(previous); g_free(following); g_free(evidence);
    g_free(marker); g_free(current); remove_root(root); g_free(root);
}

static void test_recovery_cursor(int mutation, bool tombstones)
{
    char *root = root_new(), error[256];
    char *names[3], *paths[3];
    const char *suffixes[] = {".so", ".native", ".tbset"};
    char *payload = g_strnfill(192 * 1024 + 1, 'x');
    for (size_t i = 0; i < 3; i++) {
        names[i] = g_strconcat(source, suffixes[i], NULL);
        paths[i] = g_build_filename(root, names[i], NULL);
        put(paths[i], payload);
    }
    char *manifest = g_strdup_printf("{\"version\":2,\"module\":\"%s\",\"native\":\"%s\","
        "\"tbset\":\"%s\",\"source_sha256\":\"%s\",\"codegen_id\":\"%s\",\"published_sequence\":1}",
        names[0], names[1], names[2], source, source);
    char *evidence = latcd_retirement_capture_objects(root, source, (const char *const *)names, 3);
    assert(evidence);
    char *current = current_path(root), *record_path;
    if (tombstones) {
        const char *capture[] = {names[0]};
        char *single = latcd_retirement_capture_objects(root, source, capture, 1);
        int fd = open(paths[0], O_RDONLY | O_CLOEXEC);
        assert(single && fd >= 0 && !latcd_retirement_tombstone(root, source, names[0], fd,
            single, error, sizeof(error)));
        close(fd); g_free(single);
        record_path = g_build_filename(root, ".gc", "tombstones", names[0], NULL);
    } else {
        LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
        assert(publication && !latcd_retirement_publication_prepare(publication, source, manifest,
            strlen(manifest), evidence, error, sizeof(error)));
        put(current, manifest);
        assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
        latcd_retirement_publication_close(publication);
        record_path = single_record(root);
    }
    LatcdRecoveryCursor *cursor = latcd_recovery_open(root, tombstones, error, sizeof(error));
    assert(cursor);
    LatcdRecoveryProgress progress = {0}, prior = {0};
    int result;
    unsigned steps = 0;
    do {
        prior = progress;
        result = latcd_recovery_step(cursor, 1, 65536, 100000, &progress, error, sizeof(error));
        assert(result >= 0 && progress.visited - prior.visited <= 1 &&
            progress.recovered - prior.recovered <= 1 &&
            progress.hashed_bytes - prior.hashed_bytes <= 65536);
        assert(++steps < 100);
    } while (!progress.hashed_bytes);
    assert(result == 1 && progress.recovered == 0 && progress.hashed_bytes == 65536);
    if (!tombstones) {
        int roots = latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB, error, sizeof(error));
        assert(roots >= 0);
        prior = progress;
        assert(latcd_recovery_step(cursor, 1, 65536, 100000, &progress,
                                   error, sizeof(error)) < 0);
        assert(progress.visited == prior.visited && progress.recovered == prior.recovered &&
               progress.hashed_bytes == prior.hashed_bytes);
        close(roots);
    }
    int contender = open(paths[0], O_RDONLY | O_CLOEXEC);
    assert(contender >= 0 && flock(contender, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK);
    close(contender);
    if (mutation == 1) put(paths[0], payload);
    if (mutation == 2) {
        char *raw = NULL;
        assert(g_file_get_contents(record_path, &raw, NULL, NULL));
        put(record_path, raw); g_free(raw);
    }
    if (mutation == 3) {
        latcd_recovery_close(cursor);
        contender = open(paths[0], O_RDONLY | O_CLOEXEC);
        assert(contender >= 0 && !flock(contender, LOCK_EX | LOCK_NB));
        close(contender);
        cursor = latcd_recovery_open(root, tombstones, error, sizeof(error));
        assert(cursor); progress = (LatcdRecoveryProgress){0};
    }
    do {
        prior = progress;
        result = latcd_recovery_step(cursor, 1, 65536, 100000, &progress, error, sizeof(error));
        assert(progress.visited - prior.visited <= 1 && progress.recovered - prior.recovered <= 1 &&
            progress.hashed_bytes - prior.hashed_bytes <= 65536);
        assert(++steps < 100);
    } while (result > 0);
    if (mutation == 2) {
        assert(result < 0);
        assert(latcd_recovery_step(cursor, 1, 65536, 100000, &progress, error, sizeof(error)) < 0);
    } else {
        assert(!result && progress.recovered == 1);
        if (tombstones) assert_tombstone_status(record_path, mutation == 1 ? "UNKNOWN" : "MATCHED");
        else assert_state(root, mutation == 1 ? "UNKNOWN" : "RETIRED");
        if (mutation != 1)
            assert(progress.hashed_bytes == strlen(payload) * (tombstones ? 1 : 3));
    }
    latcd_recovery_close(cursor);
    for (size_t i = 0; i < 3; i++) { assert(!access(paths[i], F_OK)); g_free(paths[i]); g_free(names[i]); }
    g_free(record_path); g_free(current); g_free(payload); g_free(evidence);
    g_free(manifest); remove_root(root); g_free(root);
}

static void test_recovery_directory_binding(bool replace_root)
{
    char *root = root_new(), error[256];
    LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication && !latcd_retirement_publication_prepare(publication, source, next,
        strlen(next), NULL, error, sizeof(error)));
    latcd_retirement_publication_close(publication);
    LatcdRecoveryCursor *cursor = latcd_recovery_open(root, false, error, sizeof(error));
    assert(cursor);
    char *path = replace_root ? g_strdup(root) : g_build_filename(root, ".gc", "transactions", NULL);
    char *moved = g_strconcat(path, ".moved", NULL);
    assert(!rename(path, moved) && !mkdir(path, 0700));
    LatcdRecoveryProgress progress = {0};
    assert(latcd_recovery_step(cursor, 32, 1024, 100000, &progress, error, sizeof(error)) < 0);
    assert(!progress.visited && !progress.recovered && !progress.hashed_bytes);
    assert(!rmdir(path) && !rename(moved, path));
    assert(latcd_recovery_step(cursor, 32, 1024, 100000, &progress, error, sizeof(error)) < 0);
    latcd_recovery_close(cursor);
    g_free(path); g_free(moved); remove_root(root); g_free(root);
}

static void test_publication_directory_binding(bool replace_root, bool prepared)
{
    char *root = root_new(), error[256];
    LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication);
    if (prepared) assert(!latcd_retirement_publication_prepare(publication, source, next,
        strlen(next), NULL, error, sizeof(error)));
    char *path = replace_root ? g_strdup(root) : g_build_filename(root, ".gc", NULL);
    char *moved = g_strconcat(path, ".moved", NULL);
    assert(!rename(path, moved) && !mkdir(path, 0700));
    if (prepared) assert(latcd_retirement_publication_finish(publication, error, sizeof(error)) < 0);
    else assert(latcd_retirement_publication_prepare(publication, source, next,
        strlen(next), NULL, error, sizeof(error)) < 0);
    assert(!rmdir(path) && !rename(moved, path));
    if (prepared) assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
    latcd_retirement_publication_close(publication);
    g_free(path); g_free(moved); remove_root(root); g_free(root);
}

static void test_recovery_entry_budget(void)
{
    char *root = root_new(), error[256];
    LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(publication && !latcd_retirement_publication_prepare(publication, source, next, strlen(next),
                                                                 NULL, error, sizeof(error)));
    latcd_retirement_publication_close(publication);
    char *store = g_build_filename(root, ".gc", "transactions", NULL);
    for (unsigned i = 0; i < 80; i++) {
        char *name = g_strdup_printf("%s/.write-%u", store, i);
        put(name, "incomplete write"); g_free(name);
    }
    LatcdRecoveryCursor *cursor = latcd_recovery_open(root, false, error, sizeof(error));
    assert(cursor);
    LatcdRecoveryProgress progress = {0};
    int result; unsigned steps = 0;
    assert(latcd_recovery_step(cursor, 0, 1, 1, &progress, error, sizeof(error)) < 0);
    do {
        unsigned before = progress.visited;
        result = latcd_recovery_step(cursor, 3, 1, 100000, &progress, error, sizeof(error));
        assert(result >= 0 && progress.visited - before <= 3 && ++steps < 100);
    } while (result > 0);
    assert(steps >= 27 && progress.visited == 81 && progress.recovered == 1 && !progress.hashed_bytes);
    latcd_recovery_close(cursor);
    g_free(store); remove_root(root); g_free(root);
}

static void test_startup_partial_records(void)
{
    char *root = root_new(), error[256];
    assert(!latcd_retirement_startup_records_check(root, error, sizeof(error)));
    const char *names[] = {"transactions", "tombstones", "retirement-schedule"};
    for (unsigned i = 0; i < G_N_ELEMENTS(names); i++) {
        char *store = g_build_filename(root, ".gc", names[i], NULL);
        assert(!g_mkdir_with_parents(store, 0700));
        char *partial = g_build_filename(store, ".write-interrupted", NULL);
        put(partial, "incomplete");
        assert(latcd_retirement_startup_records_check(root, error, sizeof(error)) < 0);
        assert(!access(partial, F_OK));
        assert(!unlink(partial));
        assert(!latcd_retirement_startup_records_check(root, error, sizeof(error)));
        g_free(partial); g_free(store);
    }
    remove_root(root); g_free(root);
}

static void test_delete_lock_domain_swap(void)
{
    char *root = root_new(), *other = root_new(), error[256];
    char *moved = g_strconcat(root, "-moved", NULL);
    char *name = g_strconcat(source, ".native", NULL);
    char *path = g_build_filename(root, name, NULL);
    char *other_path = g_build_filename(other, name, NULL);
    put(path, "original object\n");
    put(other_path, "replacement object\n");
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(evidence && fd >= 0 && !latcd_retirement_tombstone(root, source, name,
        fd, evidence, error, sizeof(error)));
    close(fd);
    int lock = lat_aot_v2_cache_source_lock(other, source, LOCK_EX | LOCK_NB,
                                             false, error, sizeof(error));
    assert(lock >= 0);
    close(lock);
    lock = latcd_retirement_roots_lock(other, LOCK_EX | LOCK_NB, error, sizeof(error));
    assert(lock >= 0);
    close(lock);
    lock_swap_root = root; lock_swap_old = moved; lock_swap_new = other;
    LatcdRetirementDeletionReport report;
    assert(latcd_tombstone_delete_report(root, name, &report, error, sizeof(error)) < 0);
    assert(!lock_swap_root && !report.object_unlinked);
    char *original = g_build_filename(moved, name, NULL);
    assert(!access(original, F_OK) && !access(path, F_OK));
    assert(!rename(root, other) && !rename(moved, root));
    remove_root(other); remove_root(root);
    g_free(original); g_free(evidence); g_free(other_path); g_free(path);
    g_free(name); g_free(moved); g_free(other); g_free(root);
}

static void test_partial_generation_delete(void)
{
    char *root = root_new(), error[256];
    const char *suffixes[] = {".so", ".native", ".tbset"};
    char *names[3], *paths[3];
    for (size_t i = 0; i < 3; i++) {
        names[i] = g_strconcat(source, suffixes[i], NULL);
        paths[i] = g_build_filename(root, names[i], NULL);
        put(paths[i], "disposable generation component\n");
        const char *capture[] = {names[i]};
        char *evidence = latcd_retirement_capture_objects(root, source, capture, 1);
        int fd = open(paths[i], O_RDONLY | O_CLOEXEC);
        assert(evidence && fd >= 0 && !latcd_retirement_tombstone(root, source,
            names[i], fd, evidence, error, sizeof(error)));
        close(fd); g_free(evidence);
    }
    assert(!latcd_tombstone_delete(root, names[0], error, sizeof(error)));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "crash:unlinked", 1));
        latcd_tombstone_delete(root, names[1], error, sizeof(error));
        _exit(127);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    assert(access(paths[0], F_OK) && access(paths[1], F_OK) && !access(paths[2], F_OK));
    unsigned recovered;
    assert(!latcd_tombstone_recover(root, &recovered, error, sizeof(error)) && recovered == 3);
    /* Replace the remaining name before resume: never delete the replacement. */
    put(paths[2], "replacement must survive partial recovery\n");
    assert(!latcd_tombstone_delete(root, names[0], error, sizeof(error)));
    assert(!latcd_tombstone_delete(root, names[1], error, sizeof(error)));
    assert(latcd_tombstone_delete(root, names[2], error, sizeof(error)));
    assert(!access(paths[2], F_OK));
    for (size_t i = 0; i < 3; i++) { g_free(paths[i]); g_free(names[i]); }
    remove_root(root); g_free(root);
}

static void test_bound_new_hold_directory(void)
{
    char *root = root_new(), error[256];
    char *name = g_strconcat(source, ".native", NULL);
    char *path = g_build_filename(root, name, NULL);
    char *gc = g_build_filename(root, ".gc", NULL);
    char *holds = g_build_filename(gc, "holds", NULL);
    char *locks = g_build_filename(gc, "source-locks", NULL);
    char *id = g_uuid_string_random();
    put(path, "held immutable object\n");
    assert(!mkdir(gc, 0700) && !mkdir(holds, 0700) && !mkdir(locks, 0700));
    int source_lock = lat_aot_v2_cache_source_lock(root, source, LOCK_EX | LOCK_NB,
                                                    false, error, sizeof(error));
    assert(source_lock >= 0);
    close(source_lock);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    assert(latcd_retirement_hold(root, source, name, id, "ROLLBACK", false,
                                 error, sizeof(error)) < 0);
    char *object_holds = g_build_filename(holds, name, NULL);
    assert(access(object_holds, F_OK) < 0 && errno == ENOENT);
    assert(latcd_cache_capacity_poll(&capacity));
    assert(!access(path, F_OK));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    assert(!mkdir(object_holds, 0700));
    char *tombstones = g_build_filename(gc, "tombstones", NULL);
    assert(!mkdir(tombstones, 0700));
    int roots = latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB, error, sizeof(error));
    assert(roots >= 0);
    close(roots);
    LatcdCacheCapacity prepared = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&prepared, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&prepared, UINT64_MAX);
    assert(!latcd_retirement_hold(root, source, name, id, "ROLLBACK", false,
                                  error, sizeof(error)));
    assert(latcd_cache_capacity_poll(&prepared) && prepared.metadata_committed > 0);
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    int object_fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(evidence && object_fd >= 0);
    assert(latcd_retirement_tombstone(root, source, name, object_fd, evidence,
                                      error, sizeof(error)));
    close(object_fd);
    uint64_t recorded = prepared.metadata_committed;
    latcd_cache_capacity_close(&prepared);
    assert(!pthread_mutex_destroy(&prepared.lock));
    LatcdCacheCapacity restarted = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&restarted, root, error, sizeof(error)));
    assert(restarted.metadata_committed == recorded);
    latcd_cache_capacity_metadata_bind(&restarted, UINT64_MAX);
    assert(!latcd_retirement_hold(root, source, name, id, "ROLLBACK", true,
                                  error, sizeof(error)));
    assert(latcd_cache_capacity_poll(&restarted) && restarted.metadata_committed > 0);
    object_fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(object_fd >= 0);
    assert(!latcd_retirement_tombstone(root, source, name, object_fd, evidence,
                                       error, sizeof(error)));
    close(object_fd);
    g_free(evidence);
    latcd_cache_capacity_close(&restarted);
    assert(!pthread_mutex_destroy(&restarted.lock));
    remove_root(root);
    g_free(tombstones); g_free(object_holds); g_free(id); g_free(locks); g_free(holds); g_free(gc); g_free(path); g_free(name); g_free(root);
}

static void test_explicit_holds(void)
{
    char *root = root_new(), error[256];
    char *name = g_strconcat(source, ".native", NULL);
    char *path = g_build_filename(root, name, NULL);
    char *id = g_uuid_string_random(), *second = g_uuid_string_random();
    put(path, "held immutable object\n");
    assert(!latcd_retirement_hold(root, source, name, id, "ROLLBACK", false, error, sizeof(error)));
    assert(!latcd_retirement_hold(root, source, name, id, "ROLLBACK", false, error, sizeof(error)));
    assert(latcd_retirement_hold(root, source, name, id, "MIGRATION", false, error, sizeof(error)));
    assert(!latcd_retirement_hold(root, source, name, second, "MIGRATION", false, error, sizeof(error)));
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(evidence && fd >= 0);
    assert(latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
    close(fd);
    assert(!latcd_retirement_hold(root, source, name, id, "ROLLBACK", true, error, sizeof(error)));
    assert(!latcd_retirement_hold(root, source, name, id, "ROLLBACK", true, error, sizeof(error)));
    assert(latcd_retirement_hold(root, source, name, id, "ROLLBACK", false, error, sizeof(error)));
    fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
    close(fd);
    assert(!latcd_retirement_hold(root, source, name, second, "MIGRATION", true, error, sizeof(error)));
    char *file = g_strdup_printf("%s.ini", id);
    char *hold = g_build_filename(root, ".gc", "holds", name, file, NULL);
    put(hold, "[hold]\nversion=99\n");
    fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
    close(fd);
    assert(latcd_retirement_hold(root, source, name, id, "ROLLBACK", true, error, sizeof(error)));
    assert(!unlink(hold));
    fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(!latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
    close(fd);
    char *third = g_uuid_string_random();
    assert(latcd_retirement_hold(root, source, name, third, "EXTERNAL", false, error, sizeof(error)));
    char *released_file = g_strdup_printf("%s.ini", second);
    char *released_path = g_build_filename(root, ".gc", "holds", name, released_file, NULL);
    GKeyFile *held = g_key_file_new();
    assert(g_key_file_load_from_file(held, released_path, 0, NULL));
    g_key_file_set_string(held, "hold", "state", "ACTIVE");
    char *active_data = g_key_file_to_data(held, NULL, NULL);
    put(released_path, active_data);
    assert(latcd_tombstone_delete(root, name, error, sizeof(error)));
    assert(!access(path, F_OK));
    g_free(active_data); g_key_file_unref(held); g_free(released_file); g_free(released_path);
    /* A pre-existing/corrupt hold must also block the executor's final check. */
    put(hold, "incomplete hold\n");
    assert(latcd_tombstone_delete(root, name, error, sizeof(error)));
    assert(!access(path, F_OK));
    g_free(third); g_free(hold); g_free(file); g_free(evidence);
    g_free(second); g_free(id); g_free(path); g_free(name);
    remove_root(root); g_free(root);
}

static void test_due_without_retirement(void)
{
    char *root = root_new(), error[256];
    char *name = g_strconcat(source, ".native", NULL), *path = g_build_filename(root, name, NULL);
    put(path, "no retirement evidence\n");
    const char *capture[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, capture, 1);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0 && evidence && !latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
    close(fd);
    char *lease_id = g_uuid_string_random();
    int lease = latcd_retirement_mount_lease(root, lease_id, "OBJECT",
                                             source, name, error, sizeof(error));
    assert(lease >= 0);
    assert(latcd_retirement_mount_release(root, lease_id, error, sizeof(error)) < 0);
    int competing = latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB, error, sizeof(error));
    assert(competing < 0);
    assert(latcd_tombstone_delete_due(root, name, 0, error, sizeof(error)) != 0);
    assert(!access(path, F_OK));
    close(lease);
    assert(!latcd_retirement_mount_release(root, lease_id, error, sizeof(error)));
    assert(!latcd_tombstone_delete(root, name, error, sizeof(error)));
    assert(access(path, F_OK) != 0);
    g_free(lease_id); g_free(evidence); g_free(path); g_free(name);
    remove_root(root); g_free(root);
}

static void test_mount_lease_crash_persistence(void)
{
    char *root = root_new(), error[256];
    char *name = g_strconcat(source, ".native", NULL);
    char *path = g_build_filename(root, name, NULL);
    put(path, "crash-persistent mount lease\n");
    const char *capture[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, capture, 1);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0 && evidence && !latcd_retirement_tombstone(
        root, source, name, fd, evidence, error, sizeof(error)));
    close(fd);
    char *lease_id = g_uuid_string_random();
    int lease = latcd_retirement_mount_lease(root, lease_id, "CACHE",
                                             NULL, NULL, error, sizeof(error));
    assert(lease >= 0);
    close(lease); /* Mount participant died without explicit release. */
    assert(latcd_tombstone_delete_due(root, name, 0, error, sizeof(error)));
    assert(!access(path, F_OK));
    assert(!latcd_retirement_mount_release(
        root, lease_id, error, sizeof(error)));
    assert(!latcd_tombstone_delete(root, name, error, sizeof(error)));
    assert(access(path, F_OK) != 0);
    g_free(lease_id); g_free(evidence); g_free(path); g_free(name);
    remove_root(root); g_free(root);
}

static void test_mount_lease_registration_lock(void)
{
    char *root = root_new(), error[256];
    char *gc = g_build_filename(root, ".gc", NULL);
    char *store = g_build_filename(gc, "mount-leases", NULL);
    assert(!mkdir(gc, 0700) && !mkdir(store, 0700));
    int lock = open(store, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(lock >= 0 && !flock(lock, LOCK_EX | LOCK_NB));
    char *id = g_uuid_string_random();
    assert(latcd_retirement_mount_lease(root, id, "CACHE", NULL, NULL, error, sizeof(error)) < 0);
    char *record_name = g_strconcat(id, ".ini", NULL);
    char *record = g_build_filename(store, record_name, NULL);
    assert(access(record, F_OK) && errno == ENOENT);
    close(lock);
    struct stat st;
    assert(!stat(store, &st));
    retry_sync_device = st.st_dev; retry_sync_inode = st.st_ino;
    char *saved = g_build_filename(gc, "mount-leases-saved", NULL);
    sync_swap_path = store; sync_swap_saved = saved;
    assert(latcd_retirement_mount_lease(root, id, "CACHE", NULL, NULL, error, sizeof(error)) < 0);
    assert(!sync_swap_path && access(record, F_OK) && errno == ENOENT);
    assert(!rmdir(store) && !rename(saved, store));
    g_free(saved);
    int lease = latcd_retirement_mount_lease(root, id, "CACHE", NULL, NULL, error, sizeof(error));
    assert(lease >= 0 && !access(record, F_OK));
    close(lease);
    retry_sync_fault = true;
    assert(latcd_retirement_mount_lease(root, id, "CACHE", NULL, NULL, error, sizeof(error)) < 0);
    retry_sync_fault = false;
    lease = latcd_retirement_mount_lease(root, id, "CACHE", NULL, NULL, error, sizeof(error));
    assert(lease >= 0);
    close(lease);
    assert(!latcd_retirement_mount_release(root, id, error, sizeof(error)));
    retry_sync_fault = true;
    assert(latcd_retirement_mount_release(root, id, error, sizeof(error)) < 0);
    retry_sync_fault = false;
    assert(!latcd_retirement_mount_release(root, id, error, sizeof(error)));
    g_free(record); g_free(record_name); g_free(id); g_free(store); g_free(gc);
    remove_root(root); g_free(root);
}

static LatcdRetirementQueueStats sweep_queue(LatcdRetirementQueue *queue)
{
    LatcdRetirementQueueStats stats;
    char error[256];
    int pending;
    do {
        pending = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
        if (pending < 0) fprintf(stderr, "consumer queue scan: %s\n", error);
        assert(pending >= 0);
        if (pending) assert(!stats.complete && !stats.due && !stats.ready &&
                            !stats.deferred && !stats.next_deadline_us &&
                            !stats.next_attempt_us && !stats.oldest_due_wait_us);
    } while (pending);
    return stats;
}

static void test_queue_root_replacement(bool replace, bool execute)
{
    char *root = root_new(), error[256];
    char *old = g_strconcat(root, "-old", NULL);
    LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 0);
    LatcdRetirementQueueStats stats = sweep_queue(queue);
    assert(stats.complete);
    assert(!rename(root, old));
    if (replace) assert(!mkdir(root, 0700));
    if (execute) {
        uint64_t hashed;
        LatcdRetirementDeletionReport report;
        assert(latcd_retirement_queue_execute_step(queue, 65536, 1000000, &hashed,
                                                   &report, error, sizeof(error)) < 0);
        assert(!hashed && !report.object_unlinked);
    } else {
        assert(latcd_retirement_queue_checkpoint(queue, error, sizeof(error)) < 0);
    }
    LatcdRetirementAttempt attempt;
    assert(latcd_retirement_queue_take(queue, UINT64_MAX, &attempt) < 0);
    char *gc = g_build_filename(root, ".gc", NULL);
    assert(access(gc, F_OK) < 0 && errno == ENOENT);
    assert(latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error)) < 0);
    assert(!stats.complete);
    if (replace) assert(!rmdir(root));
    assert(!rename(old, root));
    assert(latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error)) < 0);
    latcd_retirement_queue_free(queue);
    remove_root(root);
    g_free(gc); g_free(old); g_free(root);
}

static void test_queue_consumer(unsigned mutation, bool bounded)
{
    char *root = root_new(), error[256];
    LatcdCacheCapacity execution_capacity = LATCD_CACHE_CAPACITY_INIT;
    char *original_record = NULL;
    char *names[6], *paths[6];
    const char *suffixes[] = {".so", ".native", ".tbset"};
    for (unsigned i = 0; i < 6; i++) {
        names[i] = i < 3 ? g_strconcat(source, suffixes[i], NULL) :
            g_strdup_printf("%s-%s%s", source, source, suffixes[i - 3]);
        paths[i] = g_build_filename(root, names[i], NULL);
        put(paths[i], "consumer immutable object\n");
        if (mutation == 14 && i < 3) {
            char *large = g_strnfill(131073, 'x');
            put(paths[i], large);
            g_free(large);
        }
    }
    char *previous = g_strdup_printf("{\"version\":2,\"module\":\"%s\",\"native\":\"%s\","
        "\"tbset\":\"%s\",\"source_sha256\":\"%s\",\"codegen_id\":\"%s\",\"published_sequence\":1}",
        names[0], names[1], names[2], source, source);
    char *following = g_strdup_printf("{\"version\":2,\"module\":\"%s\",\"native\":\"%s\","
        "\"tbset\":\"%s\",\"source_sha256\":\"%s\",\"codegen_id\":\"%s\",\"published_sequence\":2}",
        names[3], names[4], names[5], source, source);
    char *current = current_path(root);
    put(current, previous);
    char *evidence = latcd_retirement_capture_objects(root, source, (const char *const *)names, 6);
    LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(evidence && publication && !latcd_retirement_publication_prepare(publication, source,
        following, strlen(following), evidence, error, sizeof(error)));
    put(current, following);
    assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
    latcd_retirement_publication_close(publication);
    if (mutation == 26) {
        char *gc = g_build_filename(root, ".gc", NULL);
        const char *stores[] = {"tombstones", "holds", "tasks", "compiler-releases", "mount-leases"};
        for (unsigned i = 0; i < G_N_ELEMENTS(stores); i++) {
            char *store = g_build_filename(gc, stores[i], NULL);
            if (mkdir(store, 0700)) assert(errno == EEXIST);
            g_free(store);
        }
        g_free(gc);
        int latch = lat_aot_v2_cache_source_lock(root, source, LOCK_EX | LOCK_NB,
                                                  false, error, sizeof(error));
        assert(latch >= 0);
        close(latch);
        assert(!latcd_cache_capacity_scan(&execution_capacity, root, error, sizeof(error)));
        latcd_cache_capacity_metadata_bind(&execution_capacity, UINT64_MAX);
    }
    if (!mutation && !bounded) {
        char *path = single_record(root);
        GKeyFile *record = g_key_file_new();
        assert(g_key_file_load_from_file(record, path, 0, NULL));
        uint64_t stamp = g_key_file_get_uint64(record, "transaction", "retired_boottime_us", NULL);
        assert(stamp && stamp < UINT64_MAX - 1000000);
        simulated_boottime_us = stamp + 1000;
        char *duplicate_id = g_uuid_string_random();
        char *duplicate_file = g_strconcat(duplicate_id, ".ini", NULL);
        char *duplicate = g_build_filename(root, ".gc", "transactions", duplicate_file, NULL);
        for (unsigned order = 0; order < 2; order++) {
            g_key_file_set_uint64(record, "transaction", "retired_boottime_us",
                                  stamp + (order ? 500 : 0));
            char *raw = g_key_file_to_data(record, NULL, NULL);
            put(path, raw); g_free(raw);
            g_key_file_set_uint64(record, "transaction", "retired_boottime_us",
                                  stamp + (order ? 0 : 500));
            raw = g_key_file_to_data(record, NULL, NULL);
            put(duplicate, raw); g_free(raw);
            LatcdRetirementQueue *probe = latcd_retirement_queue_new(root, 1000000);
            LatcdRetirementQueueStats stats = sweep_queue(probe);
            assert(stats.complete && stats.candidates == 3 && !stats.ready &&
                   stats.next_deadline_us == stamp + 1000500);
            latcd_retirement_queue_free(probe);
            assert(!unlink(duplicate));
        }
        g_key_file_set_uint64(record, "transaction", "retired_boottime_us", stamp);
        char *raw = g_key_file_to_data(record, NULL, NULL);
        put(path, raw); g_free(raw);
        simulated_boottime_us = 0;
        g_free(duplicate); g_free(duplicate_file); g_free(duplicate_id);
        g_key_file_unref(record); g_free(path);
    }
    if (mutation >= 15 && mutation <= 22) {
        if (mutation == 16) {
            const char *single[] = {names[0]};
            char *captured = latcd_retirement_capture_objects(root, source, single, 1);
            int fd = open(paths[0], O_RDONLY | O_CLOEXEC);
            assert(fd >= 0 && captured && !latcd_retirement_tombstone(root, source,
                names[0], fd, captured, error, sizeof(error)));
            close(fd); g_free(captured);
        }
        char *path = single_record(root);
        GKeyFile *record = g_key_file_new();
        assert(g_key_file_load_from_file(record, path, 0, NULL));
        g_key_file_set_string(record, "transaction", "retired_boot",
                               "12345678-1234-4234-8234-123456789abc");
        if (mutation == 17) g_key_file_remove_key(record, "transaction", "retired_boot", NULL);
        g_key_file_set_uint64(record, "transaction", "retired_boottime_us", 1);
        char *raw = g_key_file_to_data(record, NULL, NULL);
        put(path, raw); g_free(raw);
        simulated_boottime_us = UINT64_C(1000000000000);
        LatcdRetirementQueue *unrecovered = latcd_retirement_queue_new(root, 1000000);
        LatcdRetirementQueueStats probe;
        int pending;
        do {
            pending = latcd_retirement_queue_step(unrecovered, 1, 10000, &probe,
                                                  error, sizeof(error));
        } while (pending > 0);
        assert(pending < 0 && !probe.complete);
        latcd_retirement_queue_free(unrecovered);
        unsigned recovered;
        assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
        assert(g_key_file_load_from_file(record, path, 0, NULL));
        char *reason = g_key_file_get_string(record, "transaction", "retirement_clock_reason", NULL);
        assert(!g_strcmp0(reason, mutation == 17 ? "CLOCK_MISSING" : "BOOT_CHANGED"));
        g_free(reason);
        assert(g_key_file_get_uint64(record, "transaction", "retired_boottime_us", NULL) == simulated_boottime_us);
        g_key_file_unref(record); g_free(path);
    }
    LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, mutation >= 15 && mutation <= 22 ? 1000000 : 0);
    if (mutation == 26) assert(!latcd_retirement_queue_bind_capacity(queue, &execution_capacity));
    LatcdRetirementQueueStats stats = sweep_queue(queue);
    if (mutation >= 15 && mutation <= 22) {
        uint64_t deadline = simulated_boottime_us + 1000000;
        assert(stats.complete && stats.candidates == 3 && !stats.ready &&
               stats.next_deadline_us == deadline);
        assert(!latcd_retirement_queue_checkpoint(queue, error, sizeof(error)));
        latcd_retirement_queue_free(queue);
        queue = latcd_retirement_queue_new(root, 1000000);
        assert(!latcd_retirement_queue_restore(queue, error, sizeof(error)));
        simulated_boottime_us = deadline - 1;
        unsigned recovered;
        assert(!latcd_retirement_recover(root, &recovered, error, sizeof(error)));
        stats = sweep_queue(queue);
        assert(!stats.ready && stats.next_deadline_us == deadline);
        LatcdRetirementDeletionReport report;
        assert(!latcd_retirement_queue_execute_one(queue, &report, error, sizeof(error)));
        for (unsigned i = 0; i < 6; i++) assert(!access(paths[i], F_OK));
        simulated_boottime_us = deadline;
        stats = sweep_queue(queue);
    }
    int pins[3] = {-1, -1, -1}, gate = -1;
    assert(stats.complete && stats.ready == 3);
    if (mutation == 27) {
        struct timespec now;
        assert(!clock_gettime(CLOCK_BOOTTIME, &now));
        simulated_boottime_us = (uint64_t)now.tv_sec * 1000000 + now.tv_nsec / 1000;
        for (unsigned i = 0; i < 3; i++) {
            pins[i] = open(paths[i], O_RDONLY | O_CLOEXEC);
            assert(pins[i] >= 0 && !flock(pins[i], LOCK_SH | LOCK_NB));
        }
        for (unsigned i = 0; i < 3; i++) {
            LatcdRetirementDeletionReport report;
            assert(latcd_retirement_queue_execute_one(queue, &report, error, sizeof(error)) < 0);
            assert(!report.object_unlinked && !access(paths[i], F_OK));
        }
        for (unsigned i = 0; i < 3; i++) { close(pins[i]); pins[i] = -1; }
        latcd_retirement_queue_free(queue);
        queue = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(queue, error, sizeof(error)));
        stats = sweep_queue(queue);
        assert(stats.complete && !stats.ready && stats.deferred == 3 &&
               stats.next_attempt_us == simulated_boottime_us + 60000000);
        simulated_boottime_us = stats.next_attempt_us;
        stats = sweep_queue(queue);
        assert(stats.complete && stats.ready == 3);
        for (unsigned i = 0; i < 3; i++) {
            LatcdRetirementDeletionReport report;
            assert(latcd_retirement_queue_execute_one(queue, &report, error, sizeof(error)) == 1);
            assert(report.object_unlinked && report.receipt_durable);
        }
        stats = sweep_queue(queue);
        assert(stats.complete && !stats.candidates);
        goto cleanup;
    }
    if (mutation == 25) {
        char *other = root_new();
        lock_wrong_root = other;
        LatcdRetirementDeletionReport report;
        assert(latcd_retirement_queue_execute_one(queue, &report, error, sizeof(error)) < 0);
        assert(!lock_wrong_root && !report.object_unlinked);
        for (unsigned i = 0; i < 3; i++) {
            char *marker = g_build_filename(root, ".gc", "tombstones", names[i], NULL);
            assert(!access(paths[i], F_OK));
            assert(access(marker, F_OK) < 0 && errno == ENOENT);
            g_free(marker);
        }
        latcd_retirement_queue_free(queue);
        queue = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(queue, error, sizeof(error)));
        stats = sweep_queue(queue);
        assert(stats.complete && stats.candidates == 3);
        remove_root(other); g_free(other);
        goto cleanup;
    }
    if (mutation == 24) {
        char *other = root_new(), *moved = g_strconcat(root, "-moved", NULL);
        for (unsigned i = 0; i < 3; i++) {
            char *p = g_build_filename(other, names[i], NULL);
            put(p, "replacement object\n");
            g_free(p);
        }
        int fd = lat_aot_v2_cache_source_lock(other, source, LOCK_EX | LOCK_NB,
                                               false, error, sizeof(error));
        assert(fd >= 0); close(fd);
        lock_swap_root = root; lock_swap_old = moved; lock_swap_new = other;
        lock_swap_after = true;
        LatcdRetirementDeletionReport report;
        assert(latcd_retirement_queue_execute_one(queue, &report, error, sizeof(error)) < 0);
        assert(!lock_swap_root && !report.object_unlinked);
        for (unsigned i = 0; i < 3; i++) {
            char *original = g_build_filename(moved, names[i], NULL);
            char *replacement = g_build_filename(root, names[i], NULL);
            char *marker = g_build_filename(root, ".gc", "tombstones", names[i], NULL);
            assert(!access(original, F_OK) && !access(replacement, F_OK));
            assert(access(marker, F_OK) < 0 && errno == ENOENT);
            g_free(original); g_free(replacement); g_free(marker);
        }
        assert(!rename(root, other) && !rename(moved, root));
        remove_root(other); g_free(other); g_free(moved);
        goto cleanup;
    }
    if (bounded) {
        LatcdRetirementDeletionReport report;
        uint64_t hashed = UINT64_MAX;
        assert(latcd_retirement_queue_execute_step(queue, 0, 1000000, &hashed,
            &report, error, sizeof(error)) < 0 && !hashed);
        assert(latcd_retirement_queue_execute_step(queue, 3, 0, &hashed,
            &report, error, sizeof(error)) < 0 && !hashed);
        assert(latcd_retirement_queue_execute_step(queue, 3, UINT64_MAX, &hashed,
            &report, error, sizeof(error)) < 0 && !hashed);
    }
    if (mutation == 13) {
        LatcdRetirementDeletionReport report;
        uint64_t hashed = UINT64_MAX;
        struct timespec fixed_clock;
        assert(!clock_gettime(CLOCK_BOOTTIME, &fixed_clock));
        simulated_boottime_us = (uint64_t)fixed_clock.tv_sec * 1000000 + fixed_clock.tv_nsec / 1000;
        assert(!latcd_retirement_queue_checkpoint(queue, error, sizeof(error)));
        monotonic_tick = __real_g_get_monotonic_time();
        assert(latcd_retirement_queue_execute_step(queue, 65536, 1000000, &hashed,
            &report, error, sizeof(error)) == 2 && !hashed && !report.object_unlinked);
        monotonic_tick = 0;
        assert(latcd_retirement_queue_step(queue, 1, 10000, &stats,
                                           error, sizeof(error)) < 0);
        char *scheduler_path = g_build_filename(root, ".gc", "retirement-scheduler.ini", NULL);
        char *old_scheduler = NULL, *new_scheduler = NULL;
        gsize old_size = 0, new_size = 0;
        assert(g_file_get_contents(scheduler_path, &old_scheduler, &old_size, NULL));
        pid_t baseline = fork();
        assert(baseline >= 0);
        if (!baseline) {
            assert(!latcd_retirement_queue_cancel(queue, error, sizeof(error)));
            _exit(0);
        }
        int baseline_status;
        assert(waitpid(baseline, &baseline_status, 0) == baseline);
        assert(WIFEXITED(baseline_status) && !WEXITSTATUS(baseline_status));
        assert(g_file_get_contents(scheduler_path, &new_scheduler, &new_size, NULL));
        assert(old_size != new_size || memcmp(old_scheduler, new_scheduler, old_size));
        const char *faults[] = {"created", "partial-write", "written", "chmod",
                                "file-synced", "closed", "renamed", "directory-synced"};
        for (unsigned fi = 0; fi < G_N_ELEMENTS(faults); fi++) {
            for (unsigned crash = 0; crash < 2; crash++) {
                put(scheduler_path, old_scheduler);
                pid_t child = fork();
                assert(child >= 0);
                if (!child) {
                    char *fault = g_strdup_printf("%s:%s", crash ? "crash" : "error", faults[fi]);
                    assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
                    assert(latcd_retirement_queue_cancel(queue, error, sizeof(error)) < 0);
                    assert(!crash);
                    LatcdRetirementAttempt blocked;
                    assert(latcd_retirement_queue_take(queue, UINT64_MAX, &blocked) < 0);
                    _exit(0);
                }
                int status;
                assert(waitpid(child, &status, 0) == child);
                assert(crash ? WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL :
                               WIFEXITED(status) && !WEXITSTATUS(status));
                char *actual_scheduler = NULL;
                gsize actual_size = 0;
                assert(g_file_get_contents(scheduler_path, &actual_scheduler, &actual_size, NULL));
                assert((actual_size == old_size && !memcmp(actual_scheduler, old_scheduler, old_size)) ||
                       (actual_size == new_size && !memcmp(actual_scheduler, new_scheduler, new_size)));
                g_free(actual_scheduler);
                LatcdRetirementQueue *restart = latcd_retirement_queue_new(root, 0);
                assert(!latcd_retirement_queue_restore(restart, error, sizeof(error)));
                LatcdRetirementAttempt not_discovered;
                assert(!latcd_retirement_queue_take(restart, UINT64_MAX, &not_discovered));
                LatcdRetirementQueueStats restarted = sweep_queue(restart);
                assert(restarted.complete && restarted.candidates == 3);
                latcd_retirement_queue_free(restart);
                for (unsigned i = 0; i < 6; i++) assert(!access(paths[i], F_OK));
            }
        }
        g_free(old_scheduler); g_free(new_scheduler); g_free(scheduler_path);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:created", 1));
        assert(latcd_retirement_queue_cancel(queue, error, sizeof(error)) < 0);
        assert(!unsetenv("LATCD_TEST_RETIREMENT_IO"));
        assert(latcd_retirement_queue_cancel(queue, error, sizeof(error)) < 0);
        LatcdRetirementAttempt failed_attempt;
        assert(latcd_retirement_queue_take(queue, UINT64_MAX, &failed_attempt) < 0);
        assert(latcd_retirement_queue_step(queue, 1, 10000, &stats,
                                           error, sizeof(error)) < 0);
        latcd_retirement_queue_free(queue);
        queue = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(queue, error, sizeof(error)));
        assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &failed_attempt));
        stats = sweep_queue(queue);
        assert(stats.complete);
        goto cleanup;
    }
    if (mutation == 22) {
        int held[3];
        for (unsigned i = 0; i < 3; i++) {
            held[i] = open(paths[i], O_RDONLY | O_CLOEXEC);
            assert(held[i] >= 0 && !flock(held[i], LOCK_SH | LOCK_NB));
        }
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:completion-clock", 1));
        LatcdRetirementDeletionReport report;
        assert(latcd_retirement_queue_execute_one(queue, &report, error, sizeof(error)) < 0);
        assert(!report.object_unlinked && !report.receipt_durable);
        assert(!unsetenv("LATCD_TEST_RETIREMENT_IO"));
        LatcdRetirementAttempt blocked;
        assert(latcd_retirement_queue_take(queue, UINT64_MAX, &blocked) < 0);
        assert(latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error)) < 0);
        for (unsigned i = 0; i < 3; i++) close(held[i]);
        latcd_retirement_queue_free(queue);
        queue = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(queue, error, sizeof(error)));
        assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &blocked));
        stats = sweep_queue(queue);
        assert(stats.complete && stats.candidates == 3);
        for (unsigned i = 0; i < 6; i++) assert(!access(paths[i], F_OK));
        goto cleanup;
    }
    if (mutation == 18 || mutation == 19 || mutation == 21) {
        assert(!latcd_retirement_queue_checkpoint(queue, error, sizeof(error)));
        if (mutation == 18) {
            pid_t child = fork();
            assert(child >= 0);
            if (!child) {
                assert(!setenv("LATCD_TEST_RETIREMENT_IO", "crash:before-scheduler-checkpoint", 1));
                LatcdRetirementDeletionReport report;
                latcd_retirement_queue_execute_one(queue, &report, error, sizeof(error));
                _exit(1);
            }
            int status;
            assert(waitpid(child, &status, 0) == child);
            assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        } else {
            assert(!setenv("LATCD_TEST_RETIREMENT_IO", mutation == 21 ?
                "error:completion-clock" : "error:before-scheduler-checkpoint", 1));
            LatcdRetirementDeletionReport report;
            assert(latcd_retirement_queue_execute_one(queue, &report, error, sizeof(error)) < 0);
            assert(report.object_unlinked && report.namespace_durable && report.receipt_durable);
            assert(!unsetenv("LATCD_TEST_RETIREMENT_IO"));
            LatcdRetirementAttempt blocked;
            assert(latcd_retirement_queue_take(queue, UINT64_MAX, &blocked) < 0);
            assert(latcd_retirement_queue_cancel(queue, error, sizeof(error)) < 0);
            assert(latcd_retirement_queue_step(queue, 1, 10000, &stats,
                                               error, sizeof(error)) < 0);
        }
        unsigned missing = 0;
        for (unsigned i = 0; i < 3; i++) missing += access(paths[i], F_OK) != 0;
        assert(missing == 1);
        for (unsigned i = 3; i < 6; i++) assert(!access(paths[i], F_OK));
        latcd_retirement_queue_free(queue);
        queue = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(queue, error, sizeof(error)));
        LatcdRetirementAttempt not_discovered;
        assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &not_discovered));
        stats = sweep_queue(queue);
        assert(stats.complete && stats.candidates == 2);
        goto cleanup;
    }
    if ((mutation >= 8 && mutation < 13) || mutation == 20 || mutation == 23) {
        LatcdRetirementDeletionReport report;
        uint64_t hashed;
        assert(latcd_retirement_queue_execute_step(queue, 3, 1000000, &hashed,
            &report, error, sizeof(error)) == 2 && hashed == 3);
        assert(!report.object_unlinked && !report.receipt_durable);
        assert(latcd_retirement_queue_checkpoint(queue, error, sizeof(error)) < 0);
        int source_gate = lat_aot_v2_cache_source_lock(root, source, LOCK_EX | LOCK_NB,
                                                       false, error, sizeof(error));
        int roots_gate = latcd_retirement_roots_lock(root, LOCK_EX | LOCK_NB,
                                                     error, sizeof(error));
        assert(source_gate >= 0 && roots_gate >= 0);
        close(roots_gate); close(source_gate);
        unsigned pinned = 3;
        for (unsigned i = 0; i < 3; i++) {
            int fd = open(paths[i], O_RDONLY | O_CLOEXEC);
            assert(fd >= 0);
            if (flock(fd, LOCK_EX | LOCK_NB)) {
                assert(errno == EWOULDBLOCK && pinned == 3);
                pinned = i;
            }
            close(fd);
        }
        assert(pinned < 3);
        if (mutation == 23) {
            char *old_root = g_strconcat(root, "-moved", NULL);
            assert(!rename(root, old_root) && !mkdir(root, 0700));
            assert(latcd_retirement_queue_execute_step(queue, 3, 1000000, &hashed,
                &report, error, sizeof(error)) < 0);
            assert(!hashed && !report.object_unlinked);
            LatcdRetirementAttempt blocked;
            assert(latcd_retirement_queue_take(queue, UINT64_MAX, &blocked) < 0);
            char *old_object = g_build_filename(old_root, names[pinned], NULL);
            int fd = open(old_object, O_RDONLY | O_CLOEXEC);
            assert(fd >= 0 && !flock(fd, LOCK_EX | LOCK_NB));
            close(fd);
            assert(!rmdir(root) && !rename(old_root, root));
            latcd_retirement_queue_free(queue);
            queue = latcd_retirement_queue_new(root, 0);
            assert(!latcd_retirement_queue_restore(queue, error, sizeof(error)));
            stats = sweep_queue(queue);
            assert(stats.complete && stats.candidates == 3);
            g_free(old_object); g_free(old_root);
        } else if (mutation == 20) {
            clock_fault = 1;
            assert(latcd_retirement_queue_cancel(queue, error, sizeof(error)) < 0);
            clock_fault = 0;
            LatcdRetirementAttempt blocked;
            assert(latcd_retirement_queue_cancel(queue, error, sizeof(error)) < 0);
            assert(latcd_retirement_queue_take(queue, UINT64_MAX, &blocked) < 0);
            assert(latcd_retirement_queue_step(queue, 1, 10000, &stats,
                                               error, sizeof(error)) < 0);
            latcd_retirement_queue_free(queue);
            queue = latcd_retirement_queue_new(root, 0);
            assert(!latcd_retirement_queue_restore(queue, error, sizeof(error)));
            assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &blocked));
            stats = sweep_queue(queue);
            assert(stats.complete && stats.candidates == 3);
        } else if (mutation == 8) {
            assert(!latcd_retirement_queue_cancel(queue, error, sizeof(error)));
            assert(!latcd_retirement_queue_cancel(queue, error, sizeof(error)));
            assert(!latcd_retirement_queue_checkpoint(queue, error, sizeof(error)));
        } else if (mutation == 9) {
            latcd_retirement_queue_free(queue);
            queue = latcd_retirement_queue_new(root, 0);
            stats = sweep_queue(queue);
            assert(stats.ready == 3);
        } else {
            if (mutation == 10) put(paths[pinned], "replacement immutable object\n");
            if (mutation == 11) put(current, previous);
            if (mutation == 12) clock_fault = 1;
            int result;
            unsigned steps = 0;
            do {
                result = latcd_retirement_queue_execute_step(queue, 3, 1000000, &hashed,
                    &report, error, sizeof(error));
                assert(hashed <= 3 && !report.object_unlinked && ++steps < 100);
            } while (result == 2);
            clock_fault = 0;
            assert(result < 0);
            if (mutation == 12) {
                LatcdRetirementAttempt blocked;
                assert(latcd_retirement_queue_take(queue, UINT64_MAX, &blocked) < 0);
                assert(latcd_retirement_queue_step(queue, 1, 10000, &stats,
                                                   error, sizeof(error)) < 0);
                assert(latcd_retirement_queue_checkpoint(queue, error, sizeof(error)) < 0);
                latcd_retirement_queue_free(queue);
                queue = latcd_retirement_queue_new(root, 0);
                assert(!latcd_retirement_queue_restore(queue, error, sizeof(error)));
                assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &blocked));
                stats = sweep_queue(queue);
                assert(stats.complete && stats.candidates == 3);
            }
        }
        for (unsigned i = 0; i < 6; i++) {
            assert(!access(paths[i], F_OK));
            int fd = open(paths[i], O_RDONLY | O_CLOEXEC);
            assert(fd >= 0 && !flock(fd, LOCK_EX | LOCK_NB));
            close(fd);
        }
        goto cleanup;
    }
    if (mutation == 1) for (unsigned i = 0; i < 3; i++) {
        pins[i] = open(paths[i], O_RDONLY | O_CLOEXEC);
        assert(pins[i] >= 0 && !flock(pins[i], LOCK_SH | LOCK_NB));
    }
    if (mutation == 2) {
        gate = lat_aot_v2_cache_source_lock(root, source, LOCK_SH | LOCK_NB,
                                           false, error, sizeof(error));
        assert(gate >= 0);
    }
    if (mutation == 3) put(current, previous);
    if (mutation == 4) {
        char *path = single_record(root);
        GKeyFile *record = g_key_file_new();
        assert(g_key_file_load_from_file(record, path, 0, NULL));
        original_record = g_key_file_to_data(record, NULL, NULL);
        g_key_file_set_uint64(record, "transaction", "retired_boottime_us", UINT64_MAX);
        char *raw = g_key_file_to_data(record, NULL, NULL);
        put(path, raw);
        g_free(raw); g_key_file_unref(record); g_free(path);
    }
    if (mutation == 5) {
        gate = latcd_retirement_roots_lock(root, LOCK_SH | LOCK_NB, error, sizeof(error));
        assert(gate >= 0);
    }
    if (mutation == 6) {
        /* Existing intent is resumed, not overwritten with fresh evidence. */
        const char *single[] = {names[0]};
        char *captured = latcd_retirement_capture_objects(root, source, single, 1);
        int fd = open(paths[0], O_RDONLY | O_CLOEXEC);
        assert(fd >= 0 && captured && !latcd_retirement_tombstone(root, source,
            names[0], fd, captured, error, sizeof(error)));
        close(fd); g_free(captured);
    }
    bool rejecting = mutation >= 1 && mutation <= 5;
    unsigned completed = 0;
    if (mutation == 7) assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:unlinked", 1));
    for (unsigned i = 0; i < 3; i++) {
        LatcdRetirementDeletionReport report;
        int result;
        unsigned steps = 0;
        uint64_t total_hashed = 0;
        uint64_t budget = mutation == 14 ? 65536 : 3;
        do {
            uint64_t hashed;
            result = bounded ? latcd_retirement_queue_execute_step(queue, budget, 1000000,
                &hashed, &report, error, sizeof(error)) :
                latcd_retirement_queue_execute_one(queue, &report, error, sizeof(error));
            if (bounded) { assert(hashed <= budget); total_hashed += hashed; }
            if (result == 2) assert(!report.object_unlinked && !report.receipt_durable);
            assert(++steps < 100);
        } while (result == 2);
        if (mutation == 14) assert(total_hashed == 131073 && steps >= 3);
        if (rejecting || mutation == 7) {
            assert(result < 0 && !report.receipt_durable);
            if (mutation != 7) assert(!report.object_unlinked);
            else assert(report.object_unlinked);
        } else {
            if (mutation == 26 && result != 1)
                fprintf(stderr, "accounted execution: result=%d error=%s ready=%d committed=%llu unlinked=%d durable=%d receipt=%d\n",
                        result, error, execution_capacity.ready, (unsigned long long)execution_capacity.committed,
                        report.object_unlinked, report.namespace_durable, report.receipt_durable);
            assert(result == 1 && report.object_unlinked && report.namespace_durable &&
                   report.receipt_durable && report.logical_bytes > 0);
            completed++;
        }
    }
    assert(!unsetenv("LATCD_TEST_RETIREMENT_IO"));
    if (rejecting) {
        if (mutation == 4) {
            int pending;
            do {
                pending = latcd_retirement_queue_step(queue, 1, 10000, &stats,
                                                       error, sizeof(error));
            } while (pending > 0);
            assert(pending < 0 && !stats.complete);
            assert(latcd_retirement_queue_checkpoint(queue, error, sizeof(error)) < 0);
            LatcdRetirementDeletionReport report;
            assert(!latcd_retirement_queue_execute_one(queue, &report, error, sizeof(error)));
            char *path = single_record(root);
            put(path, original_record);
            g_free(path);
        }
        stats = sweep_queue(queue);
        assert(!stats.ready && stats.deferred == 3);
        assert(!latcd_retirement_queue_checkpoint(queue, error, sizeof(error)));
        LatcdRetirementDeletionReport report;
        assert(!latcd_retirement_queue_execute_one(queue, &report, error, sizeof(error)));
        for (unsigned i = 0; i < 6; i++) assert(!access(paths[i], F_OK));
    } else if (mutation != 7) {
        stats = sweep_queue(queue);
        assert(completed == 3 && !stats.candidates);
        if (mutation == 26) {
            uint64_t remaining = 0;
            struct stat st;
            for (unsigned i = 3; i < 6; i++) {
                assert(!stat(paths[i], &st));
                remaining += st.st_size;
            }
            assert(execution_capacity.ready && execution_capacity.committed == remaining);
        }
    }
    if (mutation == 7) {
        latcd_retirement_queue_free(queue);
        unsigned recovered;
        assert(!latcd_tombstone_recover(root, &recovered, error, sizeof(error)));
        queue = latcd_retirement_queue_new(root, 0);
        stats = sweep_queue(queue);
        assert(stats.ready == 3);
        for (unsigned i = 0; i < 3; i++) {
            LatcdRetirementDeletionReport report;
            assert(latcd_retirement_queue_execute_one(queue, &report, error, sizeof(error)) == 1);
            assert(!report.object_unlinked && report.namespace_durable && report.receipt_durable);
        }
        stats = sweep_queue(queue);
        assert(!stats.candidates);
    }
cleanup:
    simulated_boottime_us = 0;
    latcd_retirement_queue_free(queue);
    if (mutation == 26) {
        latcd_cache_capacity_close(&execution_capacity);
        pthread_mutex_destroy(&execution_capacity.lock);
    }
    for (unsigned i = 3; i < 6; i++) assert(!access(paths[i], F_OK));
    for (unsigned i = 0; i < 3; i++) if (pins[i] >= 0) close(pins[i]);
    if (gate >= 0) close(gate);
    g_free(original_record);
    g_free(previous); g_free(following); g_free(current); g_free(evidence);
    for (unsigned i = 0; i < 6; i++) { g_free(names[i]); g_free(paths[i]); }
    remove_root(root); g_free(root);
}

static void test_transaction_root_admission(unsigned mutation, bool executor)
{
    char *root = root_new(), error[256];
    char *names[6], *paths[6];
    const char *suffixes[] = {".so", ".native", ".tbset"};
    for (unsigned i = 0; i < 6; i++) {
        names[i] = i < 3 ? g_strconcat(source, suffixes[i], NULL) :
            g_strdup_printf("%s-%s%s", source, source, suffixes[i - 3]);
        paths[i] = g_build_filename(root, names[i], NULL);
        put(paths[i], "transaction root input\n");
    }
    char *previous = g_strdup_printf("{\"version\":2,\"module\":\"%s\",\"native\":\"%s\","
        "\"tbset\":\"%s\",\"source_sha256\":\"%s\",\"codegen_id\":\"%s\",\"published_sequence\":1}",
        names[0], names[1], names[2], source, source);
    char *following = g_strdup_printf("{\"version\":2,\"module\":\"%s\",\"native\":\"%s\","
        "\"tbset\":\"%s\",\"source_sha256\":\"%s\",\"codegen_id\":\"%s\",\"published_sequence\":2}",
        names[3], names[4], names[5], source, source);
    char *current = current_path(root);
    const char *capture[] = {names[0]};
    char *single = latcd_retirement_capture_objects(root, source, capture, 1);
    int fd;
    if (executor) {
        fd = open(paths[0], O_RDONLY | O_CLOEXEC);
        assert(fd >= 0 && !latcd_retirement_tombstone(root, source, names[0], fd, single, error, sizeof(error)));
        close(fd);
    }
    put(current, previous);
    char *evidence = latcd_retirement_capture_objects(root, source, (const char *const *)names, 6);
    LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(evidence && publication && !latcd_retirement_publication_prepare(publication, source,
        following, strlen(following), evidence, error, sizeof(error)));
    put(current, following);
    if (mutation != 1) assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
    latcd_retirement_publication_close(publication);
    char *record_path = single_record(root);
    GKeyFile *record = g_key_file_new();
    assert(g_key_file_load_from_file(record, record_path, 0, NULL));
    if (mutation == 2) g_key_file_set_string(record, "transaction", "state", "UNKNOWN");
    if (mutation == 3) g_key_file_set_string(record, "transaction", "state", "ABORTED");
    if (mutation == 4) g_key_file_set_string(record, "transaction", "binding_status", "UNPROVEN");
    if (mutation == 5) g_key_file_set_string(record, "transaction", "objects_status", "MISMATCH");
    if (mutation == 6) g_key_file_set_string(record, "transaction", "objects", "broken-base64");
    if (mutation == 7) g_key_file_set_string(record, "transaction", "previous", "broken-base64");
    if (mutation == 8) {
        g_key_file_set_integer(record, "transaction", "version", 1);
        g_key_file_remove_key(record, "transaction", "objects", NULL);
    }
    if (mutation == 9) g_key_file_set_string(record, "transaction", "unexpected", "value");
    if (mutation == 10) g_key_file_set_string(record, "transaction", "retired_boot", "12345678-1234-4234-8234-123456789abc");
    if (mutation == 11) g_key_file_set_uint64(record, "transaction", "retired_boottime_us", UINT64_MAX);
    if (mutation == 12) g_key_file_remove_key(record, "transaction", "retired_boot", NULL);
    if (mutation == 13) g_key_file_set_string(record, "transaction", "retired_boottime_us", "-1");
    if (mutation == 14) g_key_file_set_string(record, "transaction", "retired_boottime_us", "18446744073709551616");
    if (mutation == 15) g_key_file_set_string(record, "transaction", "retirement_clock_reason", "UNKNOWN_REASON");
    char *raw = g_key_file_to_data(record, NULL, NULL);
    put(record_path, raw);
    if (!mutation) {
        LatcdRetirementQueue *changed = latcd_retirement_queue_new(root, 0);
        LatcdRetirementQueueStats changed_stats;
        assert(latcd_retirement_queue_step(changed, 1, 10000, &changed_stats,
                                           error, sizeof(error)) == 1);
        char *transaction_dir = g_build_filename(root, ".gc", "transactions", NULL);
        char *saved_dir = g_build_filename(root, ".gc", "transactions-saved", NULL);
        assert(!rename(transaction_dir, saved_dir) && !mkdir(transaction_dir, 0700));
        int changed_result;
        do {
            changed_result = latcd_retirement_queue_step(changed, 1, 10000,
                &changed_stats, error, sizeof(error));
        } while (changed_result > 0);
        assert(changed_result < 0 && !changed_stats.complete);
        LatcdRetirementAttempt rejected;
        assert(!latcd_retirement_queue_take(changed, UINT64_MAX, &rejected));
        assert(!rmdir(transaction_dir) && !rename(saved_dir, transaction_dir));
        do {
            changed_result = latcd_retirement_queue_step(changed, 1, 10000,
                &changed_stats, error, sizeof(error));
        } while (changed_result > 0);
        assert(!changed_result && changed_stats.complete && changed_stats.candidates == 3);
        latcd_retirement_queue_free(changed);
        g_free(transaction_dir); g_free(saved_dir);
        changed = latcd_retirement_queue_new(root, 0);
        do {
            changed_result = latcd_retirement_queue_step(changed, 1, 10000,
                &changed_stats, error, sizeof(error));
            assert(changed_result > 0);
        } while (changed_stats.candidates == 0);
        assert(!chmod(record_path, 0600));
        int writer = open(record_path, O_WRONLY | O_CLOEXEC);
        assert(writer >= 0 && pwrite(writer, raw, strlen(raw), 0) == (ssize_t)strlen(raw));
        assert(!close(writer) && !chmod(record_path, 0400));
        do {
            changed_result = latcd_retirement_queue_step(changed, 1, 10000,
                &changed_stats, error, sizeof(error));
        } while (changed_result > 0);
        assert(changed_result < 0 && !changed_stats.complete);
        assert(!latcd_retirement_queue_take(changed, UINT64_MAX, &rejected));
        latcd_retirement_queue_free(changed);
        LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 0);
        LatcdRetirementQueueStats stats;
        int queued;
        unsigned steps = 0;
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0 && stats.visited <= 1 && ++steps < 100);
        } while (queued);
        assert(stats.complete && stats.candidates == 3 && stats.due == 3);
        char *handoff_path = g_build_filename(root, ".gc", "retirement-handoff.ini", NULL);
        GKeyFile *handoff = g_key_file_new();
        assert(latcd_retirement_queue_handoff(queue, "invalid", error, sizeof(error)) < 0);
        LatcdRetirementAttempt interrupted;
        assert(latcd_retirement_queue_take(queue, UINT64_MAX, &interrupted) == 1);
        assert(latcd_retirement_queue_checkpoint(queue, error, sizeof(error)) < 0);
        assert(!latcd_retirement_queue_handoff(queue, "IDLE", error, sizeof(error)));
        assert(g_key_file_load_from_file(handoff, handoff_path, 0, NULL));
        char *state = g_key_file_get_string(handoff, "handoff", "state", NULL);
        assert(!g_strcmp0(state, "PENDING_RESCAN"));
        g_free(state);
        assert(g_key_file_get_uint64(handoff, "handoff", "known_candidates", NULL) == 3);
        assert(g_key_file_get_uint64(handoff, "handoff", "known_deferred", NULL) == 1);
        assert(g_key_file_get_uint64(handoff, "handoff", "next_attempt_hint_boottime_us", NULL) > 0);
        assert(!g_key_file_get_boolean(handoff, "handoff", "unattended_gc_guaranteed", NULL));
        assert(!g_key_file_get_boolean(handoff, "handoff", "automatic_deletion_enabled", NULL));
        assert(latcd_retirement_queue_defer(queue, &interrupted, 0, true) < 0);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:created", 1));
        assert(latcd_retirement_queue_handoff(queue, "STOP", error, sizeof(error)) < 0);
        assert(!unsetenv("LATCD_TEST_RETIREMENT_IO"));
        assert(g_key_file_load_from_file(handoff, handoff_path, 0, NULL));
        char *reason = g_key_file_get_string(handoff, "handoff", "reason", NULL);
        assert(!strcmp(reason, "IDLE"));
        g_free(reason);
        clock_fault = 1;
        assert(latcd_retirement_queue_handoff(queue, "STOP", error, sizeof(error)) < 0);
        clock_fault = 0;
        char *handoff_alias = g_strconcat(handoff_path, ".alias", NULL);
        assert(!link(handoff_path, handoff_alias));
        assert(latcd_retirement_queue_handoff(queue, "STOP", error, sizeof(error)) < 0);
        assert(!unlink(handoff_alias));
        assert(!rename(handoff_path, handoff_alias));
        assert(!symlink(handoff_alias, handoff_path));
        assert(latcd_retirement_queue_handoff(queue, "STOP", error, sizeof(error)) < 0);
        assert(!unlink(handoff_path));
        assert(!rename(handoff_alias, handoff_path));
        assert(!unlink(handoff_path));
        g_free(handoff_alias);
        g_key_file_unref(handoff);
        g_free(handoff_path);
        latcd_retirement_queue_free(queue);
        queue = latcd_retirement_queue_new(root, 0);
        assert(latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error)) == 1);
        assert(!latcd_retirement_queue_handoff(queue, "STOP", error, sizeof(error)));
        char *partial_path = g_build_filename(root, ".gc", "retirement-handoff.ini", NULL);
        GKeyFile *partial_record = g_key_file_new();
        assert(g_key_file_load_from_file(partial_record, partial_path, 0, NULL));
        assert(!g_key_file_get_boolean(partial_record, "handoff", "discovery_complete", NULL));
        g_key_file_unref(partial_record);
        assert(!unlink(partial_path));
        g_free(partial_path);
        latcd_retirement_queue_free(queue);
        queue = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(queue, error, sizeof(error)));
        assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &interrupted));
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(!latcd_retirement_queue_checkpoint(queue, error, sizeof(error)));
        LatcdRetirementQueue *restored = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(restored, error, sizeof(error)));
        LatcdRetirementAttempt probe;
        assert(!latcd_retirement_queue_take(restored, UINT64_MAX, &probe));
        do {
            queued = latcd_retirement_queue_step(restored, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        struct timespec clock;
        assert(!clock_gettime(CLOCK_BOOTTIME, &clock));
        uint64_t actual_now = (uint64_t)clock.tv_sec * 1000000 + clock.tv_nsec / 1000;
        assert(latcd_retirement_queue_take(restored, actual_now, &probe) == 1);
        assert(latcd_retirement_queue_defer_persist(restored, &probe, UINT64_MAX, true,
                                                   error, sizeof(error)) < 0);
        assert(latcd_retirement_queue_defer_persist(restored, &probe, 0, true,
                                                   error, sizeof(error)) < 0);
        LatcdRetirementAttempt invalid_clock_attempt;
        assert(latcd_retirement_queue_take(restored, actual_now, &invalid_clock_attempt) < 0);
        char *capacity_checkpoint = g_build_filename(root, ".gc", "retirement-scheduler.ini", NULL);
        char *capacity_before = NULL, *capacity_after = NULL;
        gsize capacity_before_size, capacity_after_size;
        assert(g_file_get_contents(capacity_checkpoint, &capacity_before, &capacity_before_size, NULL));
        for (unsigned fault = 1; fault <= 8; fault++) {
            clock_fault = fault;
            assert(latcd_retirement_queue_defer_persist(restored, &probe, actual_now, true,
                                                       error, sizeof(error)) < 0);
            clock_fault = 0;
            assert(latcd_retirement_queue_take(restored, actual_now, &invalid_clock_attempt) < 0);
            assert(g_file_get_contents(capacity_checkpoint, &capacity_after, &capacity_after_size, NULL));
            assert(capacity_before_size == capacity_after_size &&
                   !memcmp(capacity_before, capacity_after, capacity_before_size));
            g_free(capacity_after);
            capacity_after = NULL;
        }
        pid_t capacity_child = fork();
        assert(capacity_child >= 0);
        if (!capacity_child) {
            LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
            assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
            latcd_cache_capacity_metadata_bind(&capacity, 1);
            assert(latcd_retirement_queue_defer_persist(restored, &probe, actual_now, true,
                                                       error, sizeof(error)) < 0);
            LatcdRetirementAttempt blocked;
            assert(latcd_retirement_queue_take(restored, actual_now, &blocked) < 0);
            assert(latcd_retirement_queue_checkpoint(restored, error, sizeof(error)) < 0);
            latcd_cache_capacity_close(&capacity);
            assert(!pthread_mutex_destroy(&capacity.lock));
            _exit(0);
        }
        int capacity_status;
        assert(waitpid(capacity_child, &capacity_status, 0) == capacity_child);
        assert(WIFEXITED(capacity_status) && !WEXITSTATUS(capacity_status));
        assert(g_file_get_contents(capacity_checkpoint, &capacity_after, &capacity_after_size, NULL));
        assert(capacity_before_size == capacity_after_size &&
               !memcmp(capacity_before, capacity_after, capacity_before_size));
        g_free(capacity_before); g_free(capacity_after); g_free(capacity_checkpoint);
        LatcdRetirementQueue *capacity_restart = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(capacity_restart, error, sizeof(error)));
        latcd_retirement_queue_free(capacity_restart);
        const char *persist_faults[] = {"created", "partial-write", "written", "chmod",
                                        "file-synced", "closed", "renamed", "directory-synced"};
        for (unsigned fi = 0; fi < G_N_ELEMENTS(persist_faults); fi++) {
            for (unsigned crash = 0; crash < 2; crash++) {
                assert(!latcd_retirement_queue_checkpoint(queue, error, sizeof(error)));
                pid_t child = fork();
                assert(child >= 0);
                if (!child) {
                    char *fault = g_strdup_printf("%s:%s", crash ? "crash" : "error", persist_faults[fi]);
                    assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
                    assert(latcd_retirement_queue_defer_persist(restored, &probe, actual_now, true,
                                                               error, sizeof(error)) < 0);
                    assert(!crash);
                    assert(latcd_retirement_queue_defer(restored, &probe, actual_now, true) < 0);
                    _exit(0);
                }
                int status;
                assert(waitpid(child, &status, 0) == child);
                assert(crash ? WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL :
                               WIFEXITED(status) && !WEXITSTATUS(status));
                char *scheduler = g_build_filename(root, ".gc", "retirement-scheduler.ini", NULL);
                GKeyFile *saved = g_key_file_new();
                assert(g_key_file_load_from_file(saved, scheduler, 0, NULL));
                uint64_t retry = g_key_file_get_uint64(saved, probe.name, "retry_at", NULL);
                assert(retry == 0 || retry == actual_now + UINT64_C(60000000));
                g_key_file_unref(saved);
                g_free(scheduler);
                LatcdRetirementQueue *reloaded = latcd_retirement_queue_new(root, 0);
                assert(!latcd_retirement_queue_restore(reloaded, error, sizeof(error)));
                do {
                    queued = latcd_retirement_queue_step(reloaded, 1, 10000, &stats,
                                                         error, sizeof(error));
                    assert(queued >= 0);
                } while (queued);
                bool saw_probe = false;
                LatcdRetirementAttempt observed;
                while (latcd_retirement_queue_take(reloaded, actual_now, &observed) == 1) {
                    if (!strcmp(observed.name, probe.name)) saw_probe = true;
                    assert(!latcd_retirement_queue_defer(reloaded, &observed, actual_now, true));
                }
                assert(saw_probe == (retry == 0));
                latcd_retirement_queue_free(reloaded);
            }
        }
        pid_t persistence_child = fork();
        assert(persistence_child >= 0);
        if (!persistence_child) {
            assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:renamed", 1));
            assert(latcd_retirement_queue_defer_persist(restored, &probe, actual_now, true,
                                                       error, sizeof(error)) < 0);
            assert(latcd_retirement_queue_defer(restored, &probe, actual_now, true) < 0);
            assert(!unsetenv("LATCD_TEST_RETIREMENT_IO"));
            LatcdRetirementAttempt blocked_attempt;
            assert(latcd_retirement_queue_take(restored, actual_now, &blocked_attempt) < 0);
            assert(latcd_retirement_queue_defer_persist(restored, &probe, actual_now, true,
                                                       error, sizeof(error)) < 0);
            assert(latcd_retirement_queue_checkpoint(restored, error, sizeof(error)) < 0);
            LatcdRetirementQueueStats blocked_stats;
            assert(latcd_retirement_queue_step(restored, 1, 10000, &blocked_stats,
                                               error, sizeof(error)) < 0);
            assert(!blocked_stats.complete);
            _exit(0);
        }
        int persistence_status;
        assert(waitpid(persistence_child, &persistence_status, 0) == persistence_child);
        assert(WIFEXITED(persistence_status) && !WEXITSTATUS(persistence_status));
        LatcdRetirementQueue *after_fault = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(after_fault, error, sizeof(error)));
        do {
            queued = latcd_retirement_queue_step(after_fault, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        LatcdRetirementAttempt after_fault_attempt;
        while (latcd_retirement_queue_take(after_fault, actual_now, &after_fault_attempt) == 1) {
            assert(strcmp(after_fault_attempt.name, probe.name));
            assert(!latcd_retirement_queue_defer(after_fault, &after_fault_attempt, actual_now, true));
        }
        latcd_retirement_queue_free(after_fault);
        assert(!latcd_retirement_queue_defer_persist(restored, &probe, actual_now, true,
                                                    error, sizeof(error)));
        LatcdRetirementQueue *crash_restart = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(crash_restart, error, sizeof(error)));
        do {
            queued = latcd_retirement_queue_step(crash_restart, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        LatcdRetirementAttempt crash_attempt;
        while (latcd_retirement_queue_take(crash_restart, actual_now, &crash_attempt) == 1) {
            assert(strcmp(crash_attempt.name, probe.name));
            assert(!latcd_retirement_queue_defer(crash_restart, &crash_attempt, actual_now, true));
        }
        latcd_retirement_queue_free(crash_restart);
        assert(!latcd_retirement_queue_checkpoint(restored, error, sizeof(error)));
        latcd_retirement_queue_free(restored);
        restored = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(restored, error, sizeof(error)));
        do {
            queued = latcd_retirement_queue_step(restored, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        LatcdRetirementAttempt next_attempt;
        assert(latcd_retirement_queue_take(restored, actual_now, &next_attempt) == 1);
        assert(strcmp(next_attempt.name, probe.name) && next_attempt.sequence > probe.sequence);
        assert(latcd_retirement_queue_defer(restored, &probe, actual_now, true) < 0);
        assert(!latcd_retirement_queue_defer(restored, &next_attempt, actual_now, false));
        latcd_retirement_queue_free(restored);
        char *checkpoint = g_build_filename(root, ".gc", "retirement-scheduler.ini", NULL);
        struct stat checkpoint_before, checkpoint_after;
        assert(!stat(checkpoint, &checkpoint_before));
        assert(!latcd_retirement_queue_checkpoint(queue, error, sizeof(error)));
        assert(!latcd_retirement_queue_checkpoint(queue, error, sizeof(error)));
        assert(!stat(checkpoint, &checkpoint_before));
        assert(!latcd_retirement_queue_checkpoint(queue, error, sizeof(error)));
        assert(!stat(checkpoint, &checkpoint_after));
        assert(checkpoint_before.st_ino == checkpoint_after.st_ino &&
               checkpoint_before.st_mtim.tv_sec == checkpoint_after.st_mtim.tv_sec &&
               checkpoint_before.st_mtim.tv_nsec == checkpoint_after.st_mtim.tv_nsec);
        GKeyFile *saved = g_key_file_new();
        assert(g_key_file_load_from_file(saved, checkpoint, 0, NULL));
        char *good_checkpoint = g_key_file_to_data(saved, NULL, NULL);
        for (unsigned damaged = 0; damaged < 8; damaged++) {
            assert(g_key_file_load_from_data(saved, good_checkpoint, -1, 0, NULL));
            if (damaged == 0) g_key_file_set_string(saved, "queue", "sequence", "-1");
            if (damaged == 1) g_key_file_set_string(saved, "queue", "sequence", "18446744073709551616");
            if (damaged == 2) g_key_file_set_string(saved, "queue", "unexpected", "1");
            if (damaged == 3) g_key_file_remove_key(saved, "queue", "boot", NULL);
            char *data = g_key_file_to_data(saved, NULL, NULL);
            put(checkpoint, damaged == 4 ? "[queue]\nversion=" : data);
            g_free(data);
            char *alias = g_strconcat(checkpoint, ".alias", NULL);
            if (damaged == 5) assert(!chmod(checkpoint, 0666));
            if (damaged == 6) assert(!link(checkpoint, alias));
            if (damaged == 7) {
                assert(!rename(checkpoint, alias));
                assert(!symlink(alias, checkpoint));
            }
            restored = latcd_retirement_queue_new(root, 0);
            assert(latcd_retirement_queue_restore(restored, error, sizeof(error)) < 0);
            latcd_retirement_queue_free(restored);
            if (damaged == 5) assert(!chmod(checkpoint, 0600));
            if (damaged == 6) assert(!unlink(alias));
            if (damaged == 7) {
                assert(!unlink(checkpoint));
                assert(!rename(alias, checkpoint));
            }
            g_free(alias);
        }
        for (unsigned changed = 0; changed < 2; changed++) {
            assert(g_key_file_load_from_data(saved, good_checkpoint, -1, 0, NULL));
            if (!changed) g_key_file_set_string(saved, "queue", "boot", "00000000-0000-0000-0000-000000000000");
            else g_key_file_set_uint64(saved, "queue", "grace_us", 1);
            char *data = g_key_file_to_data(saved, NULL, NULL);
            put(checkpoint, data);
            g_free(data);
            restored = latcd_retirement_queue_new(root, 0);
            assert(!latcd_retirement_queue_restore(restored, error, sizeof(error)));
            assert(!latcd_retirement_queue_take(restored, UINT64_MAX, &probe));
            do {
                queued = latcd_retirement_queue_step(restored, 1, 10000, &stats, error, sizeof(error));
                assert(queued >= 0);
            } while (queued);
            assert(latcd_retirement_queue_take(restored, UINT64_MAX, &probe) == 1);
            assert(probe.sequence == 1);
            latcd_retirement_queue_free(restored);
        }
        assert(g_key_file_load_from_data(saved, good_checkpoint, -1, 0, NULL));
        g_key_file_set_uint64(saved, "queue", "cache_inode", 0);
        char *bad_checkpoint = g_key_file_to_data(saved, NULL, NULL);
        put(checkpoint, bad_checkpoint);
        restored = latcd_retirement_queue_new(root, 0);
        assert(latcd_retirement_queue_restore(restored, error, sizeof(error)) < 0);
        latcd_retirement_queue_free(restored);
        assert(!unlink(checkpoint));
        g_free(good_checkpoint); g_free(bad_checkpoint); g_key_file_unref(saved); g_free(checkpoint);
        LatcdRetirementAttempt attempts[3], invalid;
        /* Persist retry deadlines without resetting the original enqueue age. */
        restored = latcd_retirement_queue_new(root, 0);
        do {
            queued = latcd_retirement_queue_step(restored, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(!clock_gettime(CLOCK_BOOTTIME, &clock));
        actual_now = (uint64_t)clock.tv_sec * 1000000 + clock.tv_nsec / 1000;
        for (unsigned i = 0; i < 3; i++) {
            assert(latcd_retirement_queue_take(restored, actual_now, &invalid) == 1);
            assert(!latcd_retirement_queue_defer(restored, &invalid, actual_now, true));
        }
        assert(!latcd_retirement_queue_take(restored, actual_now + 59999999, &invalid));
        do {
            queued = latcd_retirement_queue_step(restored, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.due == 3 && stats.deferred == 3 && !stats.ready);
        assert(!stats.next_deadline_us && stats.next_attempt_us == actual_now + 60000000);
        assert(!latcd_retirement_queue_checkpoint(restored, error, sizeof(error)));
        assert(latcd_retirement_queue_step(restored, 1, 10000, &stats,
                                           error, sizeof(error)) == 1);
        assert(!stats.complete);
        assert(!latcd_retirement_queue_handoff(restored, "STOP", error, sizeof(error)));
        latcd_retirement_queue_free(restored);
        restored = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(restored, error, sizeof(error)));
        do {
            queued = latcd_retirement_queue_step(restored, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.deferred == 3 && stats.next_attempt_us == actual_now + 60000000);
        assert(latcd_retirement_queue_take(restored, actual_now + 60000000, &invalid) == 1);
        assert(!latcd_retirement_queue_defer(restored, &invalid, actual_now + 60000000, true));
        for (unsigned i = 0; i < 24; i++) {
            assert(latcd_retirement_queue_take(restored, actual_now + UINT64_C(3600000000), &invalid) == 1);
            assert(!latcd_retirement_queue_defer(restored, &invalid, actual_now, true));
        }
        assert(!latcd_retirement_queue_checkpoint(restored, error, sizeof(error)));
        do {
            queued = latcd_retirement_queue_step(restored, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.deferred == 3 && stats.next_attempt_us == actual_now + UINT64_C(3600000000));
        latcd_retirement_queue_free(restored);
        restored = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(restored, error, sizeof(error)));
        do {
            queued = latcd_retirement_queue_step(restored, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.deferred == 3 && stats.next_attempt_us == actual_now + UINT64_C(3600000000));
        assert(!latcd_retirement_queue_take(restored, actual_now + UINT64_C(3599999999), &invalid));
        assert(latcd_retirement_queue_take(restored, actual_now + UINT64_C(3600000000), &invalid) == 1);
        assert(!latcd_retirement_queue_defer(restored, &invalid, actual_now, false));
        assert(latcd_retirement_queue_take(restored, actual_now + 100000, &invalid) == 1);
        latcd_retirement_queue_free(restored);
        const uint64_t before_retry = UINT64_MAX - UINT64_C(10000000000);
        for (unsigned i = 0; i < 3; i++) {
            assert(latcd_retirement_queue_take(queue, before_retry, &attempts[i]) == 1);
            assert(latcd_retirement_queue_take(queue, before_retry, &invalid) < 0);
            invalid = attempts[i]; invalid.sequence++;
            assert(latcd_retirement_queue_defer(queue, &invalid, 0, true) < 0);
            for (unsigned j = 0; j < i; j++) assert(strcmp(attempts[j].name, attempts[i].name));
            assert(!latcd_retirement_queue_defer(queue, &attempts[i], before_retry, true));
            assert(latcd_retirement_queue_defer(queue, &attempts[i], 0, true) < 0);
        }
        assert(!latcd_retirement_queue_take(queue, before_retry + 59999999, &invalid));
        assert(latcd_retirement_queue_take(queue, before_retry + 60000000, &invalid) == 1);
        assert(!strcmp(invalid.name, attempts[0].name));
        assert(!latcd_retirement_queue_defer(queue, &invalid, UINT64_MAX, true));
        const char *other_source = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        /* Snapshots and object evidence are base64, so transform the decoded
         * fields with the same parser rather than replacing encoded bytes. */
        GKeyFile *other = g_key_file_new();
        assert(g_key_file_load_from_data(other, raw, -1, 0, NULL));
        g_key_file_set_string(other, "transaction", "source", other_source);
        const char *encoded_fields[] = {"previous", "next", "objects"};
        for (unsigned field = 0; field < G_N_ELEMENTS(encoded_fields); field++) {
            char *encoded = g_key_file_get_string(other, "transaction", encoded_fields[field], NULL);
            gsize length;
            guchar *decoded = g_base64_decode(encoded, &length);
            char *text = g_strndup((char *)decoded, length);
            char **parts = g_strsplit(text, source, -1);
            char *changed = g_strjoinv(other_source, parts);
            char *updated = g_base64_encode((guchar *)changed, strlen(changed));
            g_key_file_set_string(other, "transaction", encoded_fields[field], updated);
            g_free(updated); g_free(changed); g_strfreev(parts); g_free(text); g_free(decoded); g_free(encoded);
        }
        char *other_id = g_uuid_string_random(), *other_file = g_strdup_printf("%s.ini", other_id);
        char *other_path = g_build_filename(root, ".gc", "transactions", other_file, NULL);
        char *other_raw = g_key_file_to_data(other, NULL, NULL);
        put(other_path, other_raw);
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.candidates == 6 && stats.complete);
        char last[65] = {0};
        for (unsigned turn = 0; turn < 6; turn++) {
            LatcdRetirementAttempt selected;
            assert(latcd_retirement_queue_take(queue, UINT64_MAX, &selected) == 1);
            if (turn) assert(strncmp(last, selected.name, 64));
            memcpy(last, selected.name, 64);
            assert(!latcd_retirement_queue_defer(queue, &selected, 0, true));
        }
        assert(!unlink(other_path));
        g_free(other_raw); g_free(other_path); g_free(other_file); g_free(other_id); g_key_file_unref(other);
        uint64_t wait = stats.oldest_due_wait_us;
        g_usleep(10000);
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.complete && stats.candidates == 3 && stats.oldest_due_wait_us > wait);
        LatcdRetirementQueue *active_queue = latcd_retirement_queue_new(root, 0);
        do {
            queued = latcd_retirement_queue_step(active_queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        LatcdRetirementAttempt active_attempt;
        assert(latcd_retirement_queue_take(active_queue, UINT64_MAX, &active_attempt) == 1);
        assert(!unlink(record_path));
        do {
            queued = latcd_retirement_queue_step(active_queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.complete && stats.candidates == 1);
        assert(!latcd_retirement_queue_defer(active_queue, &active_attempt, 0, false));
        assert(!latcd_retirement_queue_take(active_queue, UINT64_MAX, &invalid));
        do {
            queued = latcd_retirement_queue_step(active_queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.complete && !stats.candidates);
        latcd_retirement_queue_free(active_queue);
        put(record_path, raw);
        put(record_path, "[transaction]\nstate=BROKEN\n");
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !stats.complete && stats.candidates == 3);
        assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &invalid));
        assert(!unlink(record_path));
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.complete && !stats.candidates);
        put(record_path, raw);
        latcd_retirement_queue_free(queue);
        queue = latcd_retirement_queue_new(root, UINT64_C(3600) * 1000000);
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.candidates == 3 && !stats.due && stats.next_deadline_us);
        latcd_retirement_queue_free(queue);
    }
    fd = open(paths[0], O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    if (!mutation && executor) {
        assert(latcd_tombstone_delete_due(root, names[0], UINT64_MAX, error, sizeof(error)));
        assert(!access(paths[0], F_OK));
        /* An arithmetic overflow is unknown, not an elapsed deadline. */
        char *marker = g_build_filename(root, ".gc", "tombstones", names[0], NULL);
        assert(!unlink(marker));
        assert(!latcd_retirement_tombstone(root, source, names[0], fd, single, error, sizeof(error)));
        g_free(marker);
        close(fd);
        fd = open(paths[0], O_RDONLY | O_CLOEXEC);
        assert(fd >= 0);
        assert(latcd_tombstone_delete_due(root, names[0], 3600 * UINT64_C(1000000), error, sizeof(error)));
        assert(!access(paths[0], F_OK));
    }
    LatcdRetirementDeletionReport deletion_report;
    if (!mutation && executor) {
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:unlinked", 1));
        assert(latcd_tombstone_delete_due_report(root, names[0], 0, &deletion_report,
                                                error, sizeof(error)));
        assert(deletion_report.object_unlinked && !deletion_report.receipt_durable);
        assert(!unsetenv("LATCD_TEST_RETIREMENT_IO"));
        char *identity_marker = g_build_filename(root, ".gc", "tombstones", names[0], NULL);
        char *identity_original = NULL;
        assert(g_file_get_contents(identity_marker, &identity_original, NULL, NULL));
        GKeyFile *bad_identity = g_key_file_new();
        assert(g_key_file_load_from_data(bad_identity, identity_original, -1, 0, NULL));
        g_key_file_set_uint64(bad_identity, "tombstone", "allocated", 1);
        char *bad_identity_data = g_key_file_to_data(bad_identity, NULL, NULL);
        put(identity_marker, bad_identity_data);
        assert(latcd_tombstone_delete_due_report(root, names[0], 0, &deletion_report,
                                                 error, sizeof(error)) < 0);
        assert(!deletion_report.receipt_durable && !deletion_report.object_unlinked);
        put(identity_marker, identity_original);
        g_free(bad_identity_data); g_key_file_unref(bad_identity);
        g_free(identity_original); g_free(identity_marker);
        GKeyFile *pending = g_key_file_new();
        assert(g_key_file_load_from_data(pending, raw, -1, 0, NULL));
        g_key_file_set_string(pending, "transaction", "state", "PREPARED");
        char *pending_data = g_key_file_to_data(pending, NULL, NULL);
        char *pending_id = g_uuid_string_random();
        char *pending_name = g_strdup_printf("%s.ini", pending_id);
        char *pending_path = g_build_filename(root, ".gc", "transactions", pending_name, NULL);
        put(pending_path, pending_data);
        assert(latcd_tombstone_delete_due_report(root, names[0], 0, &deletion_report,
                                                 error, sizeof(error)) < 0);
        assert(!deletion_report.receipt_durable && !deletion_report.object_unlinked);
        assert(!unlink(pending_path));
        g_free(pending_path); g_free(pending_name); g_free(pending_id); g_free(pending_data);
        g_key_file_unref(pending);
        char *lease_id = g_uuid_string_random();
        int lease = latcd_retirement_mount_lease(root, lease_id, "CACHE", NULL, NULL,
                                                 error, sizeof(error));
        assert(lease >= 0);
        close(lease);
        assert(latcd_tombstone_delete_due_report(root, names[0], 0, &deletion_report,
                                                 error, sizeof(error)) < 0);
        assert(!deletion_report.receipt_durable && !deletion_report.object_unlinked);
        assert(!latcd_retirement_mount_release(root, lease_id, error, sizeof(error)));
        g_free(lease_id);
        char *missing_marker = g_build_filename(root, ".gc", "tombstones", names[0], NULL);
        char *missing_marker_data = NULL;
        assert(g_file_get_contents(missing_marker, &missing_marker_data, NULL, NULL));
        put(current, previous);
        assert(latcd_tombstone_delete_due_report(root, names[0], 0, &deletion_report,
                                                 error, sizeof(error)) < 0);
        assert(!deletion_report.receipt_durable && !deletion_report.object_unlinked);
        put(current, following);
        assert(latcd_tombstone_delete_due_report(root, names[0], 0, &deletion_report,
                                                 error, sizeof(error)) < 0);
        assert(!deletion_report.receipt_durable);
        put(missing_marker, missing_marker_data);
        g_free(missing_marker_data); g_free(missing_marker);
        LatcdRetirementQueue *partial = latcd_retirement_queue_new(root, 0);
        LatcdRetirementQueueStats partial_stats;
        int step;
        do {
            step = latcd_retirement_queue_step(partial, 1, 10000, &partial_stats, error, sizeof(error));
            assert(step >= 0);
        } while (step);
        assert(partial_stats.complete && partial_stats.candidates == 3);
        latcd_retirement_queue_free(partial);
    }
    int result = executor ? latcd_tombstone_delete_due_report(root, names[0], 0, &deletion_report, error, sizeof(error)) :
        latcd_retirement_tombstone(root, source, names[0], fd, single, error, sizeof(error));
    close(fd);
    bool accepted = !mutation || (!executor && mutation >= 10 && mutation < 15);
    assert((result == 0) == accepted);
    if (!mutation && !executor) assert(!latcd_tombstone_delete(root, names[0], error, sizeof(error)));
    assert((access(paths[0], F_OK) == 0) == (mutation != 0));
    if (!mutation) {
        LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 0);
        LatcdRetirementQueueStats stats;
        int queued;
        char *marker = g_build_filename(root, ".gc", "tombstones", names[0], NULL);
        char *receipt;
        assert(g_file_get_contents(marker, &receipt, NULL, NULL));
        assert(!unlink(marker));
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.complete && stats.candidates == 3); /* Missing is not complete. */
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued == 1 && !stats.complete);
        } while (!stats.aggregating);
        put(marker, receipt);
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !stats.complete);
        LatcdRetirementPageState invalid_page;
        assert(latcd_retirement_queue_aggregated_page(queue, &invalid_page) < 0);
        LatcdRetirementAttempt rejected;
        assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &rejected));
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.complete && stats.candidates == 2);
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued == 1 && !stats.complete);
        } while (!stats.aggregating);
        assert(!unlink(marker));
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !stats.complete);
        assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &rejected));
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.complete && stats.candidates == 3);
        put(marker, receipt);
        for (unsigned change = 0; change < 2; change++) {
            do {
                queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
                assert(queued == 1 && !stats.complete);
            } while (!stats.aggregating);
            char *directory = g_path_get_dirname(marker);
            char *moved = g_strconcat(directory, ".moved", NULL);
            if (!change) put(marker, receipt);
            else assert(!rename(directory, moved) && !mkdir(directory, 0700));
            do {
                queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            } while (queued > 0);
            assert(queued < 0 && !stats.complete);
            assert(latcd_retirement_queue_aggregated_page(queue, &invalid_page) < 0);
            if (change) assert(!rmdir(directory) && !rename(moved, directory));
            g_free(moved); g_free(directory);
        }
        for (unsigned variant = 0; variant < 10; variant++) {
            GKeyFile *changed = g_key_file_new();
            assert(g_key_file_load_from_data(changed, receipt, -1, 0, NULL));
            if (variant == 0) g_key_file_remove_key(changed, "tombstone", "deletion_status", NULL);
            if (variant == 1) g_key_file_set_string(changed, "tombstone", "recovery_status", "UNKNOWN");
            const char *fields[] = {"device", "inode", "size", "allocated", "sha256"};
            if (variant >= 2 && variant <= 6) {
                const char *field = fields[variant - 2];
                if (variant == 6) g_key_file_set_string(changed, "tombstone", field, source);
                else {
                    uint64_t value = g_key_file_get_uint64(changed, "tombstone", field, NULL);
                    g_key_file_set_uint64(changed, "tombstone", field, value + 1);
                }
            }
            if (variant == 7) g_key_file_set_string(changed, "tombstone", "unexpected", "1");
            char *data = g_key_file_to_data(changed, NULL, NULL);
            put(marker, data);
            if (variant == 8) put(paths[0], "replacement must not be forgotten\n");
            if (variant == 9) assert(!symlink("missing", paths[0]));
            do {
                queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            } while (queued > 0);
            if (variant < 2) assert(!queued && stats.complete && stats.candidates == 3);
            else {
                assert(queued < 0 && !stats.complete);
                LatcdRetirementAttempt attempt;
                assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &attempt));
            }
            if (variant >= 8) assert(!unlink(paths[0]));
            g_free(data); g_key_file_unref(changed);
        }
        put(marker, receipt);
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.complete && stats.candidates == 2 && stats.due == 2);
        char *fixture_gc = g_build_filename(root, ".gc", NULL);
        GDir *fixture_dir = g_dir_open(fixture_gc, 0, NULL);
        assert(fixture_dir);
        const char *fixture_name;
        while ((fixture_name = g_dir_read_name(fixture_dir))) {
            if (!g_str_has_prefix(fixture_name, ".write-")) continue;
            char *fixture_partial = g_build_filename(fixture_gc, fixture_name, NULL);
            assert(!unlink(fixture_partial));
            g_free(fixture_partial);
        }
        g_dir_close(fixture_dir);
        g_free(fixture_gc);
        char retry_boot[37];
        uint64_t retry_cutoff;
        assert(!latcd_retirement_round_sample(root, retry_boot, &retry_cutoff, error, sizeof(error)));
        LatcdRetirementPageDeadline receipt_hints[2] = {0};
        g_strlcpy(receipt_hints[0].name, names[0], sizeof(receipt_hints[0].name));
        snprintf(receipt_hints[1].name, sizeof(receipt_hints[1].name), "%064x.so", 9999);
        receipt_hints[0].enqueued = receipt_hints[1].enqueued = 1;
        char *receipt_schedule = g_build_filename(root, ".gc", "retirement-schedule", NULL);
        assert(!mkdir(receipt_schedule, 0700));
        for (unsigned i = 0; i < 2; i++)
            assert(!latcd_retirement_schedule_store(root, retry_boot, 1, retry_cutoff, 1,
                                                     &receipt_hints[i], error, sizeof(error)));
        LatcdRetirementQueue *receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_diagnostic_retry(receipt_queue, retry_boot, retry_cutoff,
                                                        receipt_hints, 2));
        LatcdRetirementQueueStats receipt_stats;
        do {
            queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                  error, sizeof(error));
        } while (queued > 0);
        bool receipts[128];
        unsigned receipt_count;
        assert(queued < 0 && !latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count));
        assert(receipt_count == 2 && receipts[0] && !receipts[1]);
        retry_scan_hook_called = false;
        latcd_retirement_test_retry_scanned = retry_scan_hook;
        assert(!latcd_retirement_queue_retry_receipts_revalidate(receipt_queue, receipts, &receipt_count,
                                                                  error, sizeof(error)));
        latcd_retirement_test_retry_scanned = NULL;
        assert(retry_scan_hook_called);
        assert(receipt_count == 2 && receipts[0] && !receipts[1]);
        assert(latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count) < 0 &&
               !receipt_count);
        latcd_retirement_queue_free(receipt_queue);
        GKeyFile *pending = g_key_file_new();
        assert(g_key_file_load_from_data(pending, raw, -1, 0, NULL));
        g_key_file_set_string(pending, "transaction", "state", "PREPARED");
        char *pending_data = g_key_file_to_data(pending, NULL, NULL);
        char *pending_id = g_uuid_string_random();
        char *pending_name = g_strdup_printf("%s.ini", pending_id);
        char *pending_path = g_build_filename(root, ".gc", "transactions", pending_name, NULL);
        put(pending_path, pending_data);
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_diagnostic_retry(receipt_queue, retry_boot, retry_cutoff,
                                                        receipt_hints, 2));
        do {
            queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                  error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count));
        assert(receipt_count == 2 && !receipts[0]);
        assert(!latcd_retirement_queue_retry_receipts_revalidate(receipt_queue, receipts, &receipt_count,
                                                                 error, sizeof(error)) && !receipts[0]);
        latcd_retirement_queue_free(receipt_queue);
        assert(!unlink(pending_path));
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_diagnostic_retry(receipt_queue, retry_boot, retry_cutoff,
                                                        receipt_hints, 2));
        do {
            queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                  error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count) && receipts[0]);
        retry_scan_hook_called = false;
        retry_scan_receipt_path = pending_path; retry_scan_receipt_data = pending_data;
        latcd_retirement_test_retry_scanned = retry_scan_hook;
        assert(latcd_retirement_queue_retry_receipts_revalidate(receipt_queue, receipts, &receipt_count,
                                                                 error, sizeof(error)) < 0);
        latcd_retirement_test_retry_scanned = NULL;
        retry_scan_receipt_path = NULL; retry_scan_receipt_data = NULL;
        assert(retry_scan_hook_called && !receipt_count && !receipts[0]);
        latcd_retirement_queue_free(receipt_queue);
        assert(!unlink(pending_path));
        g_key_file_set_string(pending, "transaction", "previous", "invalid-base64");
        char *invalid_pending = g_key_file_to_data(pending, NULL, NULL);
        put(pending_path, invalid_pending);
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_diagnostic_retry(receipt_queue, retry_boot, retry_cutoff,
                                                        receipt_hints, 2));
        do {
            queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                  error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count) < 0 &&
               !receipt_count);
        latcd_retirement_queue_free(receipt_queue);
        assert(!unlink(pending_path));
        g_free(invalid_pending);
        g_free(pending_path); g_free(pending_name); g_free(pending_id); g_free(pending_data);
        g_key_file_unref(pending);
        put(current, previous);
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_diagnostic_retry(receipt_queue, retry_boot, retry_cutoff,
                                                        receipt_hints, 2));
        do {
            queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                  error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count) < 0 &&
               !receipt_count);
        latcd_retirement_queue_free(receipt_queue);
        put(current, following);
        for (unsigned variant = 0; variant < 2; variant++) {
            if (variant) put(current, "invalid current\n");
            else assert(!unlink(current));
            receipt_queue = latcd_retirement_queue_new(root, 1);
            assert(!latcd_retirement_queue_diagnostic_retry(receipt_queue, retry_boot, retry_cutoff,
                                                            receipt_hints, 2));
            do {
                queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                      error, sizeof(error));
            } while (queued > 0);
            assert(queued < 0 && latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count) < 0 &&
                   !receipt_count);
            latcd_retirement_queue_free(receipt_queue);
            put(current, following);
        }
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_diagnostic_retry(receipt_queue, retry_boot, retry_cutoff,
                                                        receipt_hints, 2));
        do {
            queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                  error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count));
        put(paths[0], "replacement\n");
        assert(latcd_retirement_queue_retry_receipts_revalidate(receipt_queue, receipts, &receipt_count,
                                                                 error, sizeof(error)) < 0);
        assert(!receipt_count && !receipts[0]);
        assert(!unlink(paths[0]));
        latcd_retirement_queue_free(receipt_queue);
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_diagnostic_retry(receipt_queue, retry_boot, retry_cutoff,
                                                        receipt_hints, 2));
        do {
            queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                  error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count));
        retry_scan_hook_called = false; retry_scan_change = true;
        latcd_retirement_test_retry_scanned = retry_scan_hook;
        assert(latcd_retirement_queue_retry_receipts_revalidate(receipt_queue, receipts, &receipt_count,
                                                                 error, sizeof(error)) < 0);
        latcd_retirement_test_retry_scanned = NULL;
        retry_scan_change = false;
        assert(retry_scan_hook_called && !receipt_count && !receipts[0]);
        latcd_retirement_queue_free(receipt_queue);
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_diagnostic_retry(receipt_queue, retry_boot, retry_cutoff,
                                                        receipt_hints, 2));
        do {
            queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                  error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count));
        retry_scan_hook_called = false;
        retry_scan_receipt_path = marker; retry_scan_receipt_data = receipt;
        latcd_retirement_test_retry_scanned = retry_scan_hook;
        assert(latcd_retirement_queue_retry_receipts_revalidate(receipt_queue, receipts, &receipt_count,
                                                                 error, sizeof(error)) < 0);
        latcd_retirement_test_retry_scanned = NULL;
        retry_scan_receipt_path = NULL; retry_scan_receipt_data = NULL;
        assert(retry_scan_hook_called && !receipt_count && !receipts[0]);
        latcd_retirement_queue_free(receipt_queue);
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_diagnostic_retry(receipt_queue, retry_boot, retry_cutoff,
                                                        receipt_hints, 2));
        do {
            queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                  error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count));
        retry_scan_hook_called = false;
        retry_scan_receipt_path = current; retry_scan_receipt_data = previous;
        latcd_retirement_test_retry_scanned = retry_scan_hook;
        assert(latcd_retirement_queue_retry_receipts_revalidate(receipt_queue, receipts, &receipt_count,
                                                                 error, sizeof(error)) < 0);
        latcd_retirement_test_retry_scanned = NULL;
        retry_scan_receipt_path = NULL; retry_scan_receipt_data = NULL;
        assert(retry_scan_hook_called && !receipt_count && !receipts[0]);
        latcd_retirement_queue_free(receipt_queue);
        put(current, following);
        for (unsigned change = 0; change < 2; change++) {
            receipt_queue = latcd_retirement_queue_new(root, 1);
            assert(!latcd_retirement_queue_diagnostic_retry(receipt_queue, retry_boot, retry_cutoff,
                                                            receipt_hints, 2));
            do {
                queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                      error, sizeof(error));
            } while (queued > 0);
            assert(queued < 0 && !latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count));
            char *shard_name = g_strconcat(receipt_hints[0].name, ".ini", NULL);
            char *shard = g_build_filename(receipt_schedule, shard_name, NULL);
            char *saved = NULL;
            if (!change) put(marker, receipt);
            else {
                assert(g_file_get_contents(shard, &saved, NULL, NULL));
                GKeyFile *altered = g_key_file_new();
                assert(g_key_file_load_from_data(altered, saved, -1, 0, NULL));
                g_key_file_set_uint64(altered, "schedule", "enqueued", 2);
                char *data = g_key_file_to_data(altered, NULL, NULL);
                put(shard, data);
                g_free(data); g_key_file_unref(altered);
            }
            assert(latcd_retirement_queue_retry_receipts_revalidate(receipt_queue, receipts, &receipt_count,
                                                                     error, sizeof(error)) < 0);
            assert(!receipt_count && !receipts[0]);
            if (change) put(shard, saved);
            g_free(saved); g_free(shard); g_free(shard_name);
            latcd_retirement_queue_free(receipt_queue);
        }
        g_free(receipt_schedule);
        /* Matching corrupt identities in both records are not valid evidence. */
        GKeyFile *bad_receipt = g_key_file_new(), *bad_transaction = g_key_file_new();
        assert(g_key_file_load_from_data(bad_receipt, receipt, -1, 0, NULL));
        assert(g_key_file_load_from_data(bad_transaction, raw, -1, 0, NULL));
        char *bad_encoded = g_key_file_get_string(bad_transaction, "transaction", "objects", NULL);
        gsize bad_size;
        guchar *bad_decoded = g_base64_decode(bad_encoded, &bad_size);
        GKeyFile *bad_objects = g_key_file_new();
        assert(g_key_file_load_from_data(bad_objects, (char *)bad_decoded, bad_size, 0, NULL));
        int bad_count = g_key_file_get_integer(bad_objects, "objects", "count", NULL);
        bool bad_found = false;
        for (int i = 0; i < bad_count; i++) {
            char group[32];
            snprintf(group, sizeof(group), "object%d", i);
            char *object_name = g_key_file_get_string(bad_objects, group, "name", NULL);
            if (!strcmp(object_name, names[0])) {
                g_key_file_set_uint64(bad_objects, group, "allocated", 1);
                bad_found = true;
            }
            g_free(object_name);
        }
        assert(bad_found);
        g_key_file_set_uint64(bad_receipt, "tombstone", "allocated", 1);
        char *bad_object_data = g_key_file_to_data(bad_objects, &bad_size, NULL);
        char *bad_object_encoded = g_base64_encode((guchar *)bad_object_data, bad_size);
        g_key_file_set_string(bad_transaction, "transaction", "objects", bad_object_encoded);
        char *bad_transaction_data = g_key_file_to_data(bad_transaction, NULL, NULL);
        char *bad_receipt_data = g_key_file_to_data(bad_receipt, NULL, NULL);
        put(record_path, bad_transaction_data);
        put(marker, bad_receipt_data);
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !stats.complete);
        put(record_path, raw);
        put(marker, receipt);
        g_free(bad_receipt_data); g_free(bad_transaction_data); g_free(bad_object_encoded);
        g_free(bad_object_data); g_key_file_unref(bad_objects); g_free(bad_decoded);
        g_free(bad_encoded); g_key_file_unref(bad_transaction); g_key_file_unref(bad_receipt);
        /* Every transaction mentioning a removed name must bind the receipt. */
        GKeyFile *other = g_key_file_new();
        assert(g_key_file_load_from_data(other, raw, -1, 0, NULL));
        char *encoded_objects = g_key_file_get_string(other, "transaction", "objects", NULL);
        gsize object_size;
        guchar *object_data = g_base64_decode(encoded_objects, &object_size);
        GKeyFile *object_record = g_key_file_new();
        assert(g_key_file_load_from_data(object_record, (char *)object_data, object_size, 0, NULL));
        int object_count = g_key_file_get_integer(object_record, "objects", "count", NULL);
        bool changed_object = false;
        for (int i = 0; i < object_count; i++) {
            char group[32];
            snprintf(group, sizeof(group), "object%d", i);
            char *object_name = g_key_file_get_string(object_record, group, "name", NULL);
            if (!strcmp(object_name, names[0])) {
                uint64_t inode = g_key_file_get_uint64(object_record, group, "inode", NULL);
                assert(inode < UINT64_MAX);
                g_key_file_set_uint64(object_record, group, "inode", inode + 1);
                changed_object = true;
            }
            g_free(object_name);
        }
        assert(changed_object);
        gsize changed_size;
        char *changed_objects = g_key_file_to_data(object_record, &changed_size, NULL);
        char *changed_encoded = g_base64_encode((guchar *)changed_objects, changed_size);
        g_key_file_set_string(other, "transaction", "objects", changed_encoded);
        char *other_raw = g_key_file_to_data(other, NULL, NULL);
        char *other_id = g_uuid_string_random();
        char *other_file = g_strconcat(other_id, ".ini", NULL);
        char *other_path = g_build_filename(root, ".gc", "transactions", other_file, NULL);
        put(other_path, other_raw);
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !stats.complete);
        LatcdRetirementAttempt conflict_attempt;
        assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &conflict_attempt));
        put(other_path, raw);
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.complete && stats.candidates == 2);
        assert(!unlink(other_path));
        g_free(other_path); g_free(other_file); g_free(other_id); g_free(other_raw);
        g_free(changed_encoded); g_free(changed_objects); g_key_file_unref(object_record);
        g_free(object_data); g_free(encoded_objects); g_key_file_unref(other);
        assert(!latcd_retirement_queue_checkpoint(queue, error, sizeof(error)));
        latcd_retirement_queue_free(queue);
        queue = latcd_retirement_queue_new(root, 0);
        assert(!latcd_retirement_queue_restore(queue, error, sizeof(error)));
        do {
            queued = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
            assert(queued >= 0);
        } while (queued);
        assert(stats.complete && stats.candidates == 2);
        LatcdRetirementAttempt attempt;
        for (unsigned i = 0; i < 2; i++) {
            assert(latcd_retirement_queue_take(queue, 1, &attempt) == 0);
            assert(latcd_retirement_queue_take(queue, UINT64_MAX - 10000000, &attempt) == 1);
            assert(strcmp(attempt.name, names[0]));
            assert(!latcd_retirement_queue_defer(queue, &attempt, UINT64_MAX - 10000000, true));
        }
        latcd_retirement_queue_free(queue);
        char *extra_shard_name = g_strconcat(receipt_hints[1].name, ".ini", NULL);
        char *extra_shard = g_build_filename(root, ".gc", "retirement-schedule", extra_shard_name, NULL);
        assert(!unlink(extra_shard));
        g_free(extra_shard); g_free(extra_shard_name);
        LatcdRetirementPageState receipt_round;
        assert(!latcd_retirement_page_round_begin(root, 1, &receipt_round, error, sizeof(error)));
        LatcdCacheCapacity receipt_capacity = LATCD_CACHE_CAPACITY_INIT;
        LatcdPageBudget receipt_budget = {0};
        assert(!latcd_cache_capacity_scan(&receipt_capacity, root, error, sizeof(error)));
        latcd_cache_capacity_metadata_bind(&receipt_capacity, UINT64_MAX);
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(latcd_retirement_queue_retry_begin(receipt_queue, error, sizeof(error)) == 1);
        do {
            queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                  error, sizeof(error));
        } while (queued > 0);
        assert(!latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count) &&
               receipt_count == 1 && receipts[0]);
        int stage_receipt = latcd_retirement_queue_retry_page_stage(
            receipt_queue, &receipt_capacity, UINT64_MAX, &receipt_budget, error, sizeof(error));
        assert(queued < 0 && !stage_receipt);
        latcd_retirement_queue_free(receipt_queue);
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_retry_receipt_next(receipt_queue, &receipt_budget, error, sizeof(error)));
        do { queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats, error, sizeof(error)); }
        while (queued > 0);
        assert(queued < 0 && !latcd_retirement_queue_retry_receipt_stage_next(
            receipt_queue, &receipt_budget, error, sizeof(error)));
        LatcdRetirementRetryPage *receipt_page = g_new0(LatcdRetirementRetryPage, 1);
        assert(!latcd_retirement_retry_page_load(root, receipt_page, error, sizeof(error)) &&
               receipt_page->deletion_intent && !receipt_page->completed &&
               !strcmp(receipt_page->items[0].hint.name, names[0]) && !receipt_page->items[0].matched);
        GChecksum *receipt_checksum = g_checksum_new(G_CHECKSUM_SHA256);
        uint8_t receipt_hash[32]; gsize receipt_hash_size = sizeof(receipt_hash);
        g_checksum_update(receipt_checksum, (const guchar *)receipt, strlen(receipt));
        g_checksum_get_digest(receipt_checksum, receipt_hash, &receipt_hash_size);
        g_checksum_free(receipt_checksum);
        assert(receipt_hash_size == 32 && !memcmp(receipt_page->receipt_digest[0], receipt_hash, 32));
        assert(latcd_retirement_retry_page_commit(root, &receipt_budget, error, sizeof(error)) < 0);
        latcd_retirement_queue_free(receipt_queue);
        latcd_cache_capacity_close(&receipt_capacity);
        receipt_capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
        memset(&receipt_budget, 0, sizeof(receipt_budget));
        assert(!latcd_cache_capacity_scan(&receipt_capacity, root, error, sizeof(error)));
        assert(!latcd_cache_capacity_recovery_begin(&receipt_capacity));
        latcd_cache_capacity_metadata_bind(&receipt_capacity, UINT64_MAX);
        assert(!latcd_retirement_retry_page_restore_budget(root, &receipt_capacity, UINT64_MAX, 1,
                                                           &receipt_budget, receipt_page, error, sizeof(error)) &&
               receipt_page->deletion_intent && !latcd_cache_capacity_recovery_finish(&receipt_capacity));
        for (unsigned variant = 0; variant < 2; variant++) {
            receipt_queue = latcd_retirement_queue_new(root, 1);
            assert(!latcd_retirement_queue_retry_receipt_resume(receipt_queue, &receipt_budget, error, sizeof(error)));
            do {
                queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats,
                                                      error, sizeof(error));
            } while (queued > 0);
            assert(queued < 0 && !latcd_retirement_queue_retry_receipts(receipt_queue, receipts, &receipt_count) &&
                   receipt_count == 1 && receipts[0]);
            if (variant) put(marker, receipt);
            int verified = latcd_retirement_queue_retry_receipts_revalidate(receipt_queue, receipts, &receipt_count,
                                                                             error, sizeof(error));
            assert(variant ? verified < 0 : !verified && receipt_count == 1 && receipts[0]);
            latcd_retirement_queue_free(receipt_queue);
        }
        char *receipt_shard_name = g_strconcat(names[0], ".ini", NULL);
        char *receipt_shard = g_build_filename(root, ".gc", "retirement-schedule", receipt_shard_name, NULL);
        char *shard_data = NULL; gsize shard_size = 0;
        assert(g_file_get_contents(receipt_shard, &shard_data, &shard_size, NULL));
        latcd_cache_capacity_close(&receipt_capacity);
        receipt_capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
        memset(&receipt_budget, 0, sizeof(receipt_budget));
        assert(!latcd_cache_capacity_scan(&receipt_capacity, root, error, sizeof(error)));
        assert(!latcd_cache_capacity_recovery_begin(&receipt_capacity));
        latcd_cache_capacity_metadata_bind(&receipt_capacity, UINT64_MAX);
        assert(!latcd_retirement_retry_page_restore_budget(root, &receipt_capacity, UINT64_MAX, 1,
                                                           &receipt_budget, receipt_page, error, sizeof(error)) &&
               !latcd_cache_capacity_recovery_finish(&receipt_capacity));
        pid_t receipt_child = fork();
        assert(receipt_child >= 0);
        if (!receipt_child) {
            LatcdRetirementQueue *crash_queue = latcd_retirement_queue_new(root, 1);
            assert(!latcd_retirement_queue_retry_receipt_resume(crash_queue, &receipt_budget, error, sizeof(error)));
            int step;
            do { step = latcd_retirement_queue_step(crash_queue, 32, 10000, &receipt_stats, error, sizeof(error)); }
            while (step > 0);
            assert(step < 0 && !setenv("LATCD_TEST_RETIREMENT_IO", "crash:retry-receipt-unlinked", 1));
            latcd_retirement_queue_retry_receipt_consume(crash_queue, &receipt_budget, error, sizeof(error));
            _exit(1);
        }
        int receipt_status;
        assert(waitpid(receipt_child, &receipt_status, 0) == receipt_child &&
               WIFSIGNALED(receipt_status) && WTERMSIG(receipt_status) == SIGKILL);
        latcd_cache_capacity_close(&receipt_capacity);
        receipt_capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
        memset(&receipt_budget, 0, sizeof(receipt_budget));
        assert(!latcd_cache_capacity_scan(&receipt_capacity, root, error, sizeof(error)));
        assert(!latcd_cache_capacity_recovery_begin(&receipt_capacity));
        latcd_cache_capacity_metadata_bind(&receipt_capacity, UINT64_MAX);
        assert(!latcd_retirement_retry_page_restore_budget(root, &receipt_capacity, UINT64_MAX, 1,
                                                           &receipt_budget, receipt_page, error, sizeof(error)) &&
               receipt_page->deletion_intent && !latcd_cache_capacity_recovery_finish(&receipt_capacity));
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_retry_receipt_resume(receipt_queue, &receipt_budget, error, sizeof(error)));
        do {
            queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats, error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !latcd_retirement_queue_retry_receipt_consume(
            receipt_queue, &receipt_budget, error, sizeof(error)) && access(receipt_shard, F_OK) < 0 && errno == ENOENT);
        latcd_retirement_queue_free(receipt_queue);
        assert(!latcd_retirement_retry_page_load(root, receipt_page, error, sizeof(error)) &&
               receipt_page->completed == 1 && receipt_page->deleted[0] && !receipt_page->deletion_intent);
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_retry_completed_resume(receipt_queue, &receipt_budget, error, sizeof(error)));
        do {
            queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats, error, sizeof(error));
        } while (queued > 0);
        assert(queued < 0 && !latcd_retirement_queue_retry_receipts_revalidate(
            receipt_queue, receipts, &receipt_count, error, sizeof(error)) && receipt_count == 1 && receipts[0]);
        latcd_retirement_queue_free(receipt_queue);
        assert(latcd_retirement_retry_page_commit(root, &receipt_budget, error, sizeof(error)) < 0);
        latcd_cache_capacity_close(&receipt_capacity);
        for (unsigned variant = 0; variant < 2; variant++) {
            if (variant) { shard_data[0] ^= 1; assert(g_file_set_contents(receipt_shard, shard_data, shard_size, NULL)); }
            receipt_capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
            memset(&receipt_budget, 0, sizeof(receipt_budget));
            assert(!latcd_cache_capacity_scan(&receipt_capacity, root, error, sizeof(error)));
            assert(!latcd_cache_capacity_recovery_begin(&receipt_capacity));
            latcd_cache_capacity_metadata_bind(&receipt_capacity, UINT64_MAX);
            int restored = latcd_retirement_retry_page_restore_budget(root, &receipt_capacity, UINT64_MAX, 1,
                                                                      &receipt_budget, receipt_page, error, sizeof(error));
            if (variant) {
                assert(restored < 0 && !receipt_budget.capacity &&
                       latcd_cache_capacity_recovery_finish(&receipt_capacity) < 0);
            } else {
                assert(!restored && !latcd_cache_capacity_recovery_finish(&receipt_capacity));
                assert(latcd_retirement_retry_page_commit(root, &receipt_budget, error, sizeof(error)) < 0);
            }
            latcd_cache_capacity_close(&receipt_capacity);
            if (variant) shard_data[0] ^= 1;
            assert(g_file_set_contents(receipt_shard, shard_data, shard_size, NULL));
        }
        assert(!unlink(receipt_shard));
        receipt_capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
        memset(&receipt_budget, 0, sizeof(receipt_budget));
        assert(!latcd_cache_capacity_scan(&receipt_capacity, root, error, sizeof(error)));
        assert(!latcd_cache_capacity_recovery_begin(&receipt_capacity));
        latcd_cache_capacity_metadata_bind(&receipt_capacity, UINT64_MAX);
        assert(!latcd_retirement_retry_page_restore_budget(root, &receipt_capacity, UINT64_MAX, 1,
                                                           &receipt_budget, receipt_page, error, sizeof(error)) &&
               !latcd_cache_capacity_recovery_finish(&receipt_capacity));
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_retry_completed_resume(receipt_queue, &receipt_budget, error, sizeof(error)));
        do { queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats, error, sizeof(error)); }
        while (queued > 0);
        assert(queued < 0);
        put(marker, receipt);
        assert(latcd_retirement_queue_retry_completed_commit(receipt_queue, &receipt_budget, error, sizeof(error)) < 0);
        latcd_retirement_queue_free(receipt_queue);
        latcd_cache_capacity_close(&receipt_capacity);
        receipt_capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
        memset(&receipt_budget, 0, sizeof(receipt_budget));
        assert(!latcd_cache_capacity_scan(&receipt_capacity, root, error, sizeof(error)));
        assert(!latcd_cache_capacity_recovery_begin(&receipt_capacity));
        latcd_cache_capacity_metadata_bind(&receipt_capacity, UINT64_MAX);
        assert(!latcd_retirement_retry_page_restore_budget(root, &receipt_capacity, UINT64_MAX, 1,
                                                           &receipt_budget, receipt_page, error, sizeof(error)) &&
               !latcd_cache_capacity_recovery_finish(&receipt_capacity));
        receipt_queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_retry_completed_resume(receipt_queue, &receipt_budget, error, sizeof(error)));
        do { queued = latcd_retirement_queue_step(receipt_queue, 32, 10000, &receipt_stats, error, sizeof(error)); }
        while (queued > 0);
        assert(queued < 0 && !latcd_retirement_queue_retry_completed_commit(receipt_queue, &receipt_budget, error, sizeof(error)));
        LatcdRetirementPageState committed;
        assert(!latcd_retirement_page_state_load(root, &committed, error, sizeof(error)) &&
               !strcmp(committed.retry_cursor, names[0]) && !receipt_budget.capacity);
        latcd_retirement_queue_free(receipt_queue);
        latcd_cache_capacity_close(&receipt_capacity);
        g_free(shard_data); g_free(receipt_shard); g_free(receipt_shard_name);
        g_free(receipt_page);
        g_free(receipt); g_free(marker);
    }
    g_free(raw); g_key_file_unref(record); g_free(record_path); g_free(evidence);
    g_free(single); g_free(current); g_free(previous); g_free(following);
    for (unsigned i = 0; i < 6; i++) { g_free(paths[i]); g_free(names[i]); }
    remove_root(root); g_free(root);
}

static void test_task_root_admission(bool copying, bool executor)
{
    char *root = root_new(), error[256];
    char *name = g_strconcat(source, ".native", NULL), *path = g_build_filename(root, name, NULL);
    put(path, "task root object\n");
    char *tasks = g_build_filename(root, ".gc", "tasks", NULL);
    char *temporary = g_build_filename(root, ".tmp", NULL);
    assert(!g_mkdir_with_parents(tasks, 0700) && !mkdir(temporary, 0700));
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    assert(evidence);
    if (executor) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        assert(fd >= 0 && !latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
        close(fd);
    }
    char *id = g_uuid_string_random(), *filename = g_strdup_printf("%s.ini", id);
    char *task_path = g_build_filename(tasks, filename, NULL);
    struct stat cache, object;
    assert(!stat(root, &cache) && !stat(path, &object));
    char *record = g_strdup_printf("[task]\nversion=%d\nid=%s\nstate=BOUND\nsource=%s\nbuild_id=%s\n%s=%s\n"
        "[cache]\ndevice=%llu\ninode=%llu\nsize=0\nmode=16832\nuid=0\nmtime_sec=0\nmtime_nsec=0\n"
        "[temporary]\ndevice=0\ninode=0\nsize=0\nmode=16832\nuid=0\nmtime_sec=0\nmtime_nsec=0\n"
        "[%s]\nname=%s\ndirectory=cache\ndevice=%llu\ninode=%llu\nsize=%llu\nmode=%u\nuid=%u\nmtime_sec=0\nmtime_nsec=0\n"
        "[%s]\nname=task-output\n%s", copying ? 2 : 1, id, source, source,
        copying ? "kind" : "environment_sha256", copying ? "COPY" : source,
        (unsigned long long)cache.st_dev, (unsigned long long)cache.st_ino,
        copying ? "input" : "source", name, (unsigned long long)object.st_dev,
        (unsigned long long)object.st_ino, (unsigned long long)object.st_size,
        object.st_mode, object.st_uid, copying ? "output" : "output_native",
        copying ? "" : "[output_module]\nname=task-module\n");
    put(task_path, record);
    int task = open(task_path, O_RDONLY | O_CLOEXEC);
    assert(task >= 0 && !flock(task, LOCK_SH | LOCK_NB));
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    int result = executor ? latcd_tombstone_delete(root, name, error, sizeof(error)) :
        latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error));
    assert(result && !access(path, F_OK));
    close(fd);
    char *release_dir = g_build_filename(root, ".gc", copying ? "copy-releases" : "compiler-releases", NULL);
    assert(!mkdir(release_dir, 0700));
    char *release_path = g_build_filename(release_dir, filename, NULL);
    struct stat task_identity;
    assert(!fstat(task, &task_identity));
    char *release = g_strdup_printf("[handoff]\nversion=1\ntask_id=%s\nstate=%s\ntask_device=%llu\ntask_inode=%llu\n",
        id, copying ? "RELEASED" : "INPUTS_RELEASED", (unsigned long long)task_identity.st_dev,
        (unsigned long long)task_identity.st_ino);
    put(release_path, release);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    result = executor ? latcd_tombstone_delete(root, name, error, sizeof(error)) :
        latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error));
    assert(result && !access(path, F_OK));
    close(fd); close(task);
    const char *bad_receipts[] = {"[handoff]\nversion=9\n", "[handoff]\nstate=INPUTS_RELEASED\n"};
    for (unsigned i = 0; i < G_N_ELEMENTS(bad_receipts); i++) {
        put(release_path, bad_receipts[i]);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        assert(fd >= 0);
        result = executor ? latcd_tombstone_delete(root, name, error, sizeof(error)) :
            latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error));
        assert(result && !access(path, F_OK));
        close(fd);
    }
    put(release_path, release);
    if (executor) {
        /* UNKNOWN is sticky after corrupt metadata; a new test tombstone is
         * needed to exercise successful release without pretending recovery. */
        char *marker = g_build_filename(root, ".gc", "tombstones", name, NULL);
        assert(!unlink(marker));
        g_free(marker);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        assert(!latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
        close(fd);
    }
    if (copying) {
        char *output = g_build_filename(temporary, "task-output", NULL);
        put(output, "copy output still exists\n");
        fd = open(path, O_RDONLY | O_CLOEXEC);
        result = executor ? latcd_tombstone_delete(root, name, error, sizeof(error)) :
            latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error));
        assert(result && !access(path, F_OK));
        close(fd); assert(!unlink(output)); g_free(output);
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    result = executor ? latcd_tombstone_delete(root, name, error, sizeof(error)) :
        latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error));
    assert(!result);
    close(fd);
    if (!executor) assert(!latcd_tombstone_delete(root, name, error, sizeof(error)));
    assert(access(path, F_OK));
    g_free(release); g_free(release_path); g_free(release_dir); g_free(record); g_free(filename);
    g_free(id); g_free(task_path); g_free(tasks); g_free(temporary); g_free(evidence); g_free(path); g_free(name);
    remove_root(root); g_free(root);
}

static void test_unknown_task_release(bool executor, bool managed)
{
    char *root = root_new(), error[256];
    char *name = g_strconcat(source, ".native", NULL);
    char *path = g_build_filename(root, name, NULL);
    put(path, "unknown task input\n");
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    assert(evidence);
    if (executor) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        assert(fd >= 0 && !latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error)));
        close(fd);
    }
    char *tasks = g_build_filename(root, ".gc", "tasks", NULL);
    char *releases = g_build_filename(root, ".gc", "compiler-releases", NULL);
    assert(!g_mkdir_with_parents(tasks, 0700) && !mkdir(releases, 0700));
    char *id = g_uuid_string_random(), *filename = g_strdup_printf("%s.ini", id);
    char *task_path = g_build_filename(tasks, filename, NULL);
    char *release_path = g_build_filename(releases, filename, NULL);
    struct stat cache, object;
    assert(!stat(root, &cache) && !stat(path, &object));
    char *task = g_strdup_printf("[task]\nversion=3\nid=%s\nstate=%s\nsource=%s\n"
        "build_id=%s\nenvironment_sha256=%s\n%s"
        "[cache]\ndevice=%llu\ninode=%llu\nsize=0\nmode=16832\nuid=0\nmtime_sec=0\nmtime_nsec=0\n"
        "[temporary]\ndevice=0\ninode=0\nsize=0\nmode=16832\nuid=0\nmtime_sec=0\nmtime_nsec=0\n"
        "[source]\nname=%s\ndirectory=cache\ndevice=%llu\ninode=%llu\nsize=%llu\n"
        "mode=%u\nuid=%u\nmtime_sec=0\nmtime_nsec=0\n"
        "[output_native]\nname=task-output\n[output_module]\nname=task-module\n",
        id, managed ? "PREPARED" : "BOUND", source, source, source,
        managed ? "kind=MANAGED_COMPILER\n" : "", (unsigned long long)cache.st_dev,
        (unsigned long long)cache.st_ino, name, (unsigned long long)object.st_dev,
        (unsigned long long)object.st_ino, (unsigned long long)object.st_size,
        object.st_mode, object.st_uid);
    put(task_path, task);
    struct stat identity;
    assert(!stat(task_path, &identity));
    char *release = g_strdup_printf("[handoff]\nversion=1\ntask_id=%s\nstate=INPUTS_RELEASED\n"
        "task_device=%llu\ntask_inode=%llu\n", id,
        (unsigned long long)identity.st_dev, (unsigned long long)identity.st_ino);
    put(release_path, release);
    char *state_dir = NULL, *state_path = NULL, *state = NULL;
    if (managed) {
        state_dir = g_build_filename(root, ".gc", "managed-task-state", NULL);
        assert(!mkdir(state_dir, 0700));
        state_path = g_build_filename(state_dir, filename, NULL);
        char *digest = g_compute_checksum_for_string(G_CHECKSUM_SHA256, task, -1);
        state = g_strdup_printf("[managed]\nversion=1\ntask_id=%s\ntask_device=%llu\n"
            "task_inode=%llu\ntask_sha256=%s\nstate=PREPARED\n", id,
            (unsigned long long)identity.st_dev, (unsigned long long)identity.st_ino, digest);
        g_free(digest);
        int task_fd = open(task_path, O_RDONLY | O_CLOEXEC);
        assert(task_fd >= 0 && !flock(task_fd, LOCK_SH | LOCK_NB));
        int wrong_fd = open(path, O_RDONLY | O_CLOEXEC);
        assert(wrong_fd >= 0 && latcd_managed_task_prepare(root, id, wrong_fd, error, sizeof(error)));
        close(wrong_fd);
        assert(access(state_path, F_OK));
        assert(!latcd_managed_task_prepare(root, id, task_fd, error, sizeof(error)));
        assert(latcd_managed_task_prepare(root, id, task_fd, error, sizeof(error)));
        close(task_fd);
        if (!executor) {
            char *other = g_strdup_printf("%s.so", source);
            char *other_path = g_build_filename(root, other, NULL);
            put(other_path, "unrelated object\n");
            const char *other_names[] = {other};
            char *other_evidence = latcd_retirement_capture_objects(root, source, other_names, 1);
            int other_fd = open(other_path, O_RDONLY | O_CLOEXEC);
            assert(other_evidence && other_fd >= 0 &&
                !latcd_retirement_tombstone(root, source, other, other_fd, other_evidence, error, sizeof(error)));
            close(other_fd);
            char *bad_state = g_strdup_printf("[managed]\nversion=1\ntask_id=%s\ntask_device=%llu\n"
                "task_inode=%llu\ntask_sha256=%s\nstate=PREPARED\n", id,
                (unsigned long long)identity.st_dev, (unsigned long long)identity.st_ino + 1, source);
            put(state_path, bad_state);
            other_fd = open(other_path, O_RDONLY | O_CLOEXEC);
            assert(other_fd >= 0 && latcd_retirement_tombstone(root, source, other, other_fd,
                                                               other_evidence, error, sizeof(error)));
            close(other_fd);
            put(state_path, state);
            g_free(bad_state);
            g_free(other_evidence); g_free(other_path); g_free(other);
        }
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    int result = executor ? latcd_tombstone_delete(root, name, error, sizeof(error)) :
        latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error));
    assert(result && !access(path, F_OK));
    close(fd);
    if (managed) {
        assert(!unlink(state_path));
        fd = open(path, O_RDONLY | O_CLOEXEC);
        assert(fd >= 0);
        result = executor ? latcd_tombstone_delete(root, name, error, sizeof(error)) :
            latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error));
        assert(result && !access(path, F_OK));
        close(fd);
    }
    g_free(state); g_free(state_path); g_free(state_dir);
    g_free(release); g_free(task); g_free(release_path); g_free(task_path);
    g_free(filename); g_free(id); g_free(releases); g_free(tasks);
    g_free(evidence); g_free(path); g_free(name); remove_root(root); g_free(root);
}

static void test_hold_crash(bool release, const char *point)
{
    char *root = root_new(), error[256];
    char *name = g_strconcat(source, ".native", NULL);
    char *path = g_build_filename(root, name, NULL), *id = g_uuid_string_random();
    put(path, "hold crash input\n");
    if (release) assert(!latcd_retirement_hold(root, source, name, id, "ROLLBACK", false, error, sizeof(error)));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        char *fault = g_strconcat("crash:", point, NULL);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", fault, 1));
        latcd_retirement_hold(root, source, name, id, "ROLLBACK", release, error, sizeof(error));
        _exit(127);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    const char *names[] = {name};
    char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(evidence && fd >= 0);
    bool published_release = release && (!strcmp(point, "renamed") || !strcmp(point, "directory-synced"));
    int result = latcd_retirement_tombstone(root, source, name, fd, evidence, error, sizeof(error));
    assert((result == 0) == published_release);
    close(fd);
    assert(!access(path, F_OK));
    g_free(evidence); g_free(id); g_free(path); g_free(name); remove_root(root); g_free(root);
}

static uint64_t space_available(const char *root)
{
    struct statvfs fs;
    assert(!statvfs(root, &fs));
    return (uint64_t)fs.f_bavail * fs.f_frsize;
}

static void test_deletion_report(const char *parent, bool isolated)
{
    for (unsigned mode = 0; mode < 3; mode++) {
        char *root = parent ? g_build_filename(parent, mode == 0 ? "normal" :
                                               mode == 1 ? "held" : "partial", NULL) : root_new();
        if (parent) assert(!mkdir(root, 0700));
        char *name = g_strconcat(source, ".native", NULL);
        char *path = g_build_filename(root, name, NULL), error[256];
        size_t length = 8 * 1024 * 1024;
        char *payload = g_malloc0(length);
        memset(payload, 'x', length);
        assert(g_file_set_contents(path, payload, length, NULL));
        g_free(payload);
        assert(!chmod(path, 0400));
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        struct stat st;
        assert(fd >= 0 && !fstat(fd, &st));
        uint64_t allocated = (uint64_t)st.st_blocks * 512;
        const char *names[] = {name};
        char *evidence = latcd_retirement_capture_objects(root, source, names, 1);
        assert(evidence && !latcd_retirement_tombstone(root, source, name, fd,
                                                      evidence, error, sizeof(error)));
        close(fd);
        LatcdRetirementDeletionReport report;
        if (mode == 1) {
            fd = open(path, O_RDONLY | O_CLOEXEC);
            assert(fd >= 0 && !flock(fd, LOCK_SH | LOCK_NB));
            void *mapping = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
            assert(mapping != MAP_FAILED);
            assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:created", 1));
            assert(latcd_tombstone_delete_report(root, name, &report, error, sizeof(error)) < 0);
            assert(!report.busy_observation_durable && !report.object_unlinked);
            unsetenv("LATCD_TEST_RETIREMENT_IO");
            assert(latcd_tombstone_delete_report(root, name, &report, error, sizeof(error)) < 0);
            assert(report.busy_observation_durable && !report.object_unlinked &&
                   !report.unlinked_allocated_bytes && !access(path, F_OK));
            assert(((char *)mapping)[length - 1] == 'x');
            assert(!munmap(mapping, length));
            close(fd);
        }
        if (mode == 2) assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:unlinked", 1));
        int result = latcd_tombstone_delete_report(root, name, &report, error, sizeof(error));
        unsetenv("LATCD_TEST_RETIREMENT_IO");
        assert((result == 0) == (mode != 2));
        assert(!report.busy_observation_durable);
        assert(report.object_unlinked && report.logical_bytes == length &&
               report.allocated_bytes_before == allocated && report.unlinked_allocated_bytes == allocated);
        assert(report.namespace_durable == (mode != 2) && report.receipt_durable == (mode != 2));
        assert(report.filesystem_before_valid && report.filesystem_after_valid);
        if (isolated) {
            assert(report.filesystem_available_after > report.filesystem_available_before);
            uint64_t delta = report.filesystem_available_after - report.filesystem_available_before;
            assert(delta <= allocated && allocated - delta <= 65536);
            printf("deletion-report mode=%u allocated=%" G_GUINT64_FORMAT
                   " available_before=%" G_GUINT64_FORMAT " available_after=%" G_GUINT64_FORMAT "\n",
                   mode, allocated, report.filesystem_available_before, report.filesystem_available_after);
        }
        assert(!latcd_tombstone_delete_report(root, name, &report, error, sizeof(error)));
        assert(!report.object_unlinked && !report.unlinked_allocated_bytes &&
               report.namespace_durable && report.receipt_durable);
        g_free(evidence); g_free(path); g_free(name); remove_root(root); g_free(root);
    }
    if (isolated) {
        /* Nonparticipant negative control, never admitted to the executor:
         * unlink alone cannot reclaim a file kept alive by a mapping. */
        char *path = g_build_filename(parent, "mapping-control", NULL);
        size_t length = 8 * 1024 * 1024;
        int fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        assert(fd >= 0 && !ftruncate(fd, length));
        char *mapping = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        assert(mapping != MAP_FAILED);
        memset(mapping, 'x', length);
        assert(!msync(mapping, length, MS_SYNC));
        struct stat st;
        assert(!fstat(fd, &st));
        uint64_t allocated = (uint64_t)st.st_blocks * 512;
        uint64_t before = space_available(parent);
        assert(!unlink(path));
        close(fd);
        uint64_t mapped = space_available(parent);
        assert(mapped <= before + 4096 && mapping[length - 1] == 'x');
        assert(!munmap(mapping, length));
        uint64_t after = space_available(parent);
        assert(after >= mapped && after - mapped == allocated);
        printf("mapping-control allocated=%" G_GUINT64_FORMAT " before=%" G_GUINT64_FORMAT
               " mapped=%" G_GUINT64_FORMAT " after=%" G_GUINT64_FORMAT "\n",
               allocated, before, mapped, after);
        g_free(path);
    }
}

static void test_queue_empty_store(void)
{
    char *root = root_new(), error[256];
    char *store = g_build_filename(root, ".gc", "transactions", NULL);
    LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 0);
    LatcdRetirementQueueStats stats;
    int result;
    do {
        result = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
        assert(result >= 0);
    } while (result);
    assert(stats.complete && !stats.candidates && g_file_test(store, G_FILE_TEST_IS_DIR));
    LatcdRetirementAttempt attempt;
    assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &attempt));

    /* Mutation during a later scan invalidates the empty snapshot. */
    result = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
    assert(result == 1 && !stats.complete);
    char *entry = g_build_filename(store, "invalid.ini", NULL);
    put(entry, "invalid\n");
    do {
        result = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
    } while (result > 0);
    assert(result < 0 && !stats.complete);
    assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &attempt));
    assert(!unlink(entry));
    do {
        result = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
        assert(result >= 0);
    } while (result);
    assert(stats.complete && !stats.candidates);

    /* The end of the first pass yields before the aggregation pass. */
    do {
        result = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
        assert(result == 1 && !stats.complete);
    } while (!stats.aggregating);
    put(entry, "invalid\n");
    assert(!unlink(entry));
    do {
        result = latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error));
    } while (result > 0);
    assert(result < 0 && !stats.complete);
    assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &attempt));
    latcd_retirement_queue_free(queue);
    g_free(entry); g_free(store);
    remove_root(root); g_free(root);
}

static gint compare_string_pointers(gconstpointer a, gconstpointer b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void publish_page_fixture(const char *root, unsigned id)
{
    char error[256];
    const char *suffix[] = {".so", ".native", ".tbset"};
    char *src = g_strdup_printf("%064x", id), *names[6], *paths[6];
    for (unsigned j = 0; j < 6; j++) {
        names[j] = j < 3 ? g_strconcat(src, suffix[j], NULL) :
            g_strdup_printf("%s-%s%s", src, src, suffix[j - 3]);
        paths[j] = g_build_filename(root, names[j], NULL);
        put(paths[j], "fixture\n");
    }
    char *previous = g_strdup_printf("{\"version\":2,\"module\":\"%s\",\"native\":\"%s\","
        "\"tbset\":\"%s\",\"source_sha256\":\"%s\",\"codegen_id\":\"%s\",\"published_sequence\":1}",
        names[0], names[1], names[2], src, src);
    char *next_manifest = g_strdup_printf("{\"version\":2,\"module\":\"%s\",\"native\":\"%s\","
        "\"tbset\":\"%s\",\"source_sha256\":\"%s\",\"codegen_id\":\"%s\",\"published_sequence\":2}",
        names[3], names[4], names[5], src, src);
    char *current = g_strdup_printf("%s/%s.current", root, src);
    put(current, previous);
    char *evidence = latcd_retirement_capture_objects(root, src, (const char *const *)names, 6);
    LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
    assert(evidence && publication && !latcd_retirement_publication_prepare(publication, src,
        next_manifest, strlen(next_manifest), evidence, error, sizeof(error)));
    put(current, next_manifest);
    assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
    latcd_retirement_publication_close(publication);
    for (unsigned j = 0; j < 6; j++) { g_free(names[j]); g_free(paths[j]); }
    g_free(evidence); g_free(current); g_free(previous); g_free(next_manifest); g_free(src);
}

static void test_page_discovery_witness(void)
{
    char *root = root_new(), error[256];
    simulated_boottime_us = 100;
    publish_page_fixture(root, 7);
    LatcdRetirementPageState round, page;
    simulated_boottime_us = 101;
    assert(!latcd_retirement_page_round_begin(root, 1, &round, error, sizeof(error)));
    simulated_boottime_us = 102;
    LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 1);
    assert(!latcd_retirement_queue_page_discovery_begin(queue, error, sizeof(error)));
    LatcdRetirementQueueStats stats; int step;
    do { step = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (step > 0);
    assert(step < 0 && !latcd_retirement_queue_aggregated_page(queue, &page) && page.count == 3);
    char *schedule = g_build_filename(root, ".gc", "retirement-schedule", NULL);
    assert(!mkdir(schedule, 0700));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    retry_scan_hook_called = false;
    retry_scan_change = true;
    latcd_retirement_test_page_scanned = retry_scan_hook;
    assert(latcd_retirement_queue_page_stage(queue, &capacity, UINT64_MAX, &budget,
                                             error, sizeof(error)) < 0);
    latcd_retirement_test_page_scanned = NULL;
    retry_scan_change = false;
    assert(retry_scan_hook_called);
    assert(strstr(error, "page witness"));
    assert(!capacity.ready && budget.invalid &&
           !latcd_retirement_page_state_load(root, &page, error, sizeof(error)) && !page.count);
    latcd_cache_capacity_close(&capacity);
    latcd_retirement_queue_free(queue);

    memset(&budget, 0, sizeof(budget));
    queue = latcd_retirement_queue_new(root, 1);
    assert(!latcd_retirement_queue_page_discovery_begin(queue, error, sizeof(error)));
    do { step = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (step > 0);
    assert(step < 0 && !latcd_retirement_queue_aggregated_page(queue, &page) && page.count == 3);
    capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    int page_stage_result = latcd_retirement_queue_page_stage(queue, &capacity, UINT64_MAX,
                                                               &budget, error, sizeof(error));
    assert(!page_stage_result);
    assert(!latcd_retirement_page_state_load(root, &page, error, sizeof(error)) &&
           page.count == 3 && page.budget_bound);
    LatcdRetirementAttempt attempt;
    assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &attempt));
    assert(latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)) < 0);
    latcd_cache_capacity_close(&capacity);
    latcd_retirement_queue_free(queue);
    g_free(schedule);
    simulated_boottime_us = 0;
    remove_root(root); g_free(root);
}

static void test_page_execution_restriction(void)
{
    char *root = root_new(), error[256];
    simulated_boottime_us = 100;
    publish_page_fixture(root, 9);
    publish_page_fixture(root, 10);
    char *src = g_strdup_printf("%064x", 9);
    char *selected = g_strconcat(src, ".so", NULL);
    char *sibling = g_strconcat(src, ".native", NULL);
    char *outsider_src = g_strdup_printf("%064x", 10);
    char *outsider = g_strconcat(outsider_src, ".so", NULL);
    char *selected_path = g_build_filename(root, selected, NULL);
    char *sibling_path = g_build_filename(root, sibling, NULL);
    char *outsider_path = g_build_filename(root, outsider, NULL);
    simulated_boottime_us = 101;
    LatcdRetirementPageState page;
    assert(!latcd_retirement_page_round_begin(root, 1, &page, error, sizeof(error)));
    page.count = 1;
    g_strlcpy(page.entries[0].name, selected, sizeof(page.entries[0].name));
    page.entries[0].enqueued = 100;
    page.entries[0].deadline = 101;
    g_strlcpy(page.cursor, selected, sizeof(page.cursor));
    char *schedule = g_build_filename(root, ".gc", "retirement-schedule", NULL);
    char *transactions = g_build_filename(root, ".gc", "transactions", NULL);
    char *tombstones = g_build_filename(root, ".gc", "tombstones", NULL);
    char *source_locks = g_build_filename(root, ".gc", "source-locks", NULL);
    assert(!mkdir(schedule, 0700));
    assert(!mkdir(transactions, 0700) || errno == EEXIST);
    assert(!mkdir(tombstones, 0700) || errno == EEXIST);
    assert(!mkdir(source_locks, 0700) || errno == EEXIST);
    int source_lock = lat_aot_v2_cache_source_lock(root, src, LOCK_SH | LOCK_NB,
                                                    false, error, sizeof(error));
    assert(source_lock >= 0);
    close(source_lock);
    source_lock = lat_aot_v2_cache_source_lock(root, outsider_src, LOCK_SH | LOCK_NB,
                                                false, error, sizeof(error));
    assert(source_lock >= 0);
    close(source_lock);
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    simulated_boottime_us = 102;
    assert(!latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                  &budget, error, sizeof(error)));
    assert(!latcd_retirement_page_state_load(root, &page, error, sizeof(error)) &&
           page.count == 1 && page.budget_bound);
    LatcdRetirementQueue *executor = latcd_retirement_queue_new(root, 1);
    assert(!latcd_retirement_queue_bind_capacity(executor, &capacity));
    LatcdRetirementQueueStats stats = sweep_queue(executor);
    assert(stats.complete && stats.ready >= 2);
    assert(!latcd_retirement_queue_restrict_to_page(executor, &page, error, sizeof(error)));
    LatcdRetirementDeletionReport report;
    const char *selected_names[] = {selected};
    char *evidence = latcd_retirement_capture_objects(root, src, selected_names, 1);
    int pin = open(selected_path, O_RDONLY | O_CLOEXEC);
    assert(evidence && pin >= 0 && !latcd_retirement_tombstone(root, src, selected, pin,
                                                                 evidence, error, sizeof(error)));
    g_free(evidence);
    assert(pin >= 0 && !flock(pin, LOCK_SH | LOCK_NB));
    assert(latcd_retirement_queue_execute_one(executor, &report, error, sizeof(error)) < 0);
    assert(report.busy_observation_durable && report.scheduler_deferral_durable &&
           !strcmp(report.attempt_name, selected) && report.attempt_sequence &&
           report.retry_at_boottime_us > simulated_boottime_us && !access(selected_path, F_OK));
    uint64_t retry_at = report.retry_at_boottime_us;
    LatcdRetirementDeletionReport invalid = report;
    invalid.busy_observation_durable = false;
    assert(latcd_retirement_page_wait_busy(root, &budget, 0, &invalid,
                                            simulated_boottime_us, error, sizeof(error)) < 0);
    invalid = report;
    invalid.attempt_started_boottime_us = simulated_boottime_us + 1;
    assert(latcd_retirement_page_wait_busy(root, &budget, 0, &invalid,
                                            simulated_boottime_us, error, sizeof(error)) < 0);
    assert(report.attempt_started_boottime_us == simulated_boottime_us);
    assert(!latcd_retirement_page_wait_busy(root, &budget, 0, &report,
                                             simulated_boottime_us, error, sizeof(error)));
    assert(latcd_retirement_page_wait_busy(root, &budget, 0, &report,
                                            simulated_boottime_us, error, sizeof(error)) < 0);
    uint64_t next_attempt;
    assert(!latcd_retirement_queue_restrict_to_waiting_page(executor, &page, &budget,
                                                             &next_attempt, error, sizeof(error)));
    assert(next_attempt == retry_at);
    assert(!latcd_retirement_queue_execute_one(executor, &report, error, sizeof(error)));
    simulated_boottime_us = retry_at;
    assert(!latcd_retirement_queue_restrict_to_waiting_page(executor, &page, &budget,
                                                             &next_attempt, error, sizeof(error)));
    assert(latcd_retirement_queue_execute_one(executor, &report, error, sizeof(error)) < 0);
    assert(report.busy_observation_durable && report.scheduler_deferral_durable &&
           report.retry_at_boottime_us > retry_at);
    uint64_t later_retry = report.retry_at_boottime_us;
    assert(!latcd_retirement_queue_restrict_to_waiting_page(executor, &page, &budget,
                                                             &next_attempt, error, sizeof(error)));
    assert(next_attempt == later_retry);
    close(pin);
    assert(!latcd_retirement_queue_execute_one(executor, &report, error, sizeof(error)));
    simulated_boottime_us = later_retry;
    assert(!latcd_retirement_queue_restrict_to_waiting_page(executor, &page, &budget,
                                                             &next_attempt, error, sizeof(error)));
    int execute_result = latcd_retirement_queue_execute_one(executor, &report, error, sizeof(error));
    if (execute_result != 1) fprintf(stderr, "page execute: %d %s\n", execute_result, error);
    assert(execute_result == 1);
    assert(report.object_unlinked && access(selected_path, F_OK) < 0 && errno == ENOENT);
    assert(capacity.ready && !budget.invalid);
    assert(!access(sibling_path, F_OK) && !access(outsider_path, F_OK));
    assert(!latcd_retirement_queue_execute_one(executor, &report, error, sizeof(error)));
    latcd_retirement_queue_free(executor);
    assert(!latcd_retirement_page_state_load(root, &page, error, sizeof(error)) &&
           page.budget_bound && page.results[0] == 0);
    LatcdRetirementQueue *receipt = latcd_retirement_queue_new(root, 1);
    assert(!latcd_retirement_queue_page_receipt_begin(receipt, &budget, 0,
                                                       error, sizeof(error)));
    int receipt_step;
    do {
        receipt_step = latcd_retirement_queue_step(receipt, 32, 10000, &stats,
                                                   error, sizeof(error));
    } while (receipt_step > 0);
    assert(receipt_step < 0 &&
           !latcd_retirement_queue_page_receipt_done(receipt, &budget,
                                                      error, sizeof(error)));
    latcd_retirement_queue_free(receipt);
    assert(!latcd_retirement_page_state_load(root, &page, error, sizeof(error)) &&
           page.budget_bound && page.results[0] == 0);
    uint8_t page_results[128] = {0};
    assert(!latcd_retirement_schedule_page_results(root, simulated_boottime_us, &page, page_results,
                                                    error, sizeof(error)) &&
           page_results[0] == LATCD_RETIREMENT_RESULT_DONE);
    assert(!latcd_retirement_page_budget_commit(root, simulated_boottime_us, &page, &budget,
                                                 error, sizeof(error)));
    assert(!latcd_retirement_page_state_load(root, &page, error, sizeof(error)) &&
           page.committed_pending && page.results[0] == LATCD_RETIREMENT_RESULT_DONE);
    assert(!latcd_retirement_consumption_begin(root, simulated_boottime_us, &budget,
                                                error, sizeof(error)));
    assert(!latcd_retirement_consumption_prepare(root, simulated_boottime_us, 0, &budget,
                                                  error, sizeof(error)));
    assert(!latcd_retirement_consumption_apply(root, simulated_boottime_us, &budget,
                                                error, sizeof(error)));
    assert(!latcd_retirement_consumption_finish(root, simulated_boottime_us, &budget,
                                                 error, sizeof(error)));
    assert(!latcd_retirement_page_state_load(root, &page, error, sizeof(error)) &&
           !page.count && !page.committed_pending);
    assert(capacity.ready && !budget.capacity && !budget.invalid);
    latcd_cache_capacity_close(&capacity);
    simulated_boottime_us = 0;
    g_free(outsider_path); g_free(sibling_path); g_free(selected_path);
    g_free(outsider); g_free(outsider_src); g_free(sibling); g_free(selected); g_free(src);
    g_free(source_locks); g_free(tombstones); g_free(transactions); g_free(schedule);
    remove_root(root); g_free(root);
}

static void test_page_receipt_witness(unsigned mode)
{
    char *root = root_new(), error[256];
    simulated_boottime_us = 100;
    publish_page_fixture(root, 7);
    char *src = g_strdup_printf("%064x", 7);
    char *name = g_strconcat(src, ".so", NULL);
    char *path = g_build_filename(root, name, NULL);
    if (mode != 1 && mode != 3) {
        const char *objects[] = {name};
        char *evidence = latcd_retirement_capture_objects(root, src, objects, 1);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        assert(evidence && fd >= 0 && !latcd_retirement_tombstone(root, src, name, fd,
                                                                   evidence, error, sizeof(error)));
        close(fd);
        assert(!latcd_tombstone_delete_due(root, name, 0, error, sizeof(error)));
        g_free(evidence);
    }
    simulated_boottime_us = 101;
    if (mode == 3) {
        LatcdRetirementQueue *executor = latcd_retirement_queue_new(root, 1);
        LatcdRetirementQueueStats execution_stats = sweep_queue(executor);
        assert(execution_stats.complete && execution_stats.ready == 3);
        for (unsigned i = 0; i < 3; i++) {
            LatcdRetirementDeletionReport report;
            assert(latcd_retirement_queue_execute_one(executor, &report, error, sizeof(error)) == 1);
            assert(report.object_unlinked && report.receipt_durable);
        }
        assert(access(path, F_OK) < 0 && errno == ENOENT);
        latcd_retirement_queue_free(executor);
    }
    LatcdRetirementPageState page;
    assert(!latcd_retirement_page_round_begin(root, 1, &page, error, sizeof(error)));
    char *schedule = g_build_filename(root, ".gc", "retirement-schedule", NULL);
    assert(!mkdir(schedule, 0700) || errno == EEXIST);
    page.count = 1;
    g_strlcpy(page.entries[0].name, name, sizeof(page.entries[0].name));
    page.entries[0].enqueued = 100;
    page.entries[0].deadline = 101;
    g_strlcpy(page.cursor, name, sizeof(page.cursor));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    assert(!latcd_retirement_page_stage_budgeted(root, &page, &capacity, UINT64_MAX,
                                                  &budget, error, sizeof(error)));
    if (mode == 3) {
        latcd_cache_capacity_close(&capacity);
        capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
        memset(&budget, 0, sizeof(budget));
        assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
        latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
        assert(!latcd_cache_capacity_recovery_begin(&capacity));
        LatcdRetirementPageState recovered;
        assert(!latcd_retirement_page_restore_budget(root, &capacity, UINT64_MAX, 1,
                                                     &budget, &recovered, error, sizeof(error)));
        assert(!latcd_cache_capacity_recovery_finish(&capacity));
        assert(recovered.count == 1 && recovered.budget_bound && !recovered.committed_pending);
    }
    LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 1);
    LatcdRetirementQueueStats stats; int step;
    assert(!latcd_retirement_queue_page_receipt_begin(queue, &budget, 0, error, sizeof(error)));
    do { step = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (step > 0);
    assert(step < 0);
    char *changed = g_build_filename(root, ".gc", "transactions", "witness-change", NULL);
    if (mode == 2) put(changed, "changed");
    int result = latcd_retirement_queue_page_receipt_done(queue, &budget, error, sizeof(error));
    assert(mode == 1 || mode == 2 ? result < 0 : !result);
    uint8_t results[128];
    assert(latcd_retirement_schedule_page_results(root, 101, &page, results, error, sizeof(error)) ==
           (mode == 1 || mode == 2 ? 1 : 0));
    if (mode == 0 || mode == 3) assert(results[0] == LATCD_RETIREMENT_RESULT_DONE);
    if (mode == 2) assert(!unlink(changed));
    g_free(changed);
    latcd_retirement_queue_free(queue);
    latcd_cache_capacity_close(&capacity);
    g_free(schedule); g_free(path); g_free(name); g_free(src);
    simulated_boottime_us = 0;
    remove_root(root); g_free(root);
}

static void test_retry_multiple_receipts(unsigned mixed)
{
    char *root = root_new(), error[256], *boot = NULL;
    simulated_boottime_us = 100;
    for (unsigned i = 7; i < 9; i++) {
        publish_page_fixture(root, i);
        if (mixed && mixed != 3 && i == 8) continue;
        char *src = g_strdup_printf("%064x", i);
        char *name = g_strconcat(src, ".so", NULL);
        char *path = g_build_filename(root, name, NULL);
        const char *objects[] = {name};
        char *evidence = latcd_retirement_capture_objects(root, src, objects, 1);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        assert(evidence && fd >= 0 && !latcd_retirement_tombstone(root, src, name, fd, evidence, error, sizeof(error)));
        close(fd);
        assert(!latcd_tombstone_delete_due(root, name, 0, error, sizeof(error)));
        g_free(evidence); g_free(path); g_free(name); g_free(src);
    }
    simulated_boottime_us = 101;
    LatcdRetirementPageState state;
    assert(!latcd_retirement_page_round_begin(root, 1, &state, error, sizeof(error)));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    char *schedule = g_build_filename(root, ".gc", "retirement-schedule", NULL);
    assert(!mkdir(schedule, 0700));
    for (unsigned i = 7; i < 9; i++) {
        LatcdRetirementPageDeadline hint = {.enqueued = 100, .retry_at = 100};
        snprintf(hint.name, sizeof(hint.name), "%064x.so", i);
        assert(!latcd_retirement_schedule_store(root, boot, 1, 101, 3, &hint, error, sizeof(error)));
    }
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 1);
    LatcdRetirementQueueStats stats; int step;
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    do { step = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); } while (step > 0);
    assert(step < 0 && !latcd_retirement_queue_retry_page_stage(queue, &capacity, UINT64_MAX, &budget, error, sizeof(error)));
    latcd_retirement_queue_free(queue);
    LatcdRetirementRetryPage *page = g_new0(LatcdRetirementRetryPage, 1);
    for (unsigned i = 0; i < (mixed ? 1u : 2u); i++) {
        queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_retry_receipt_next(queue, &budget, error, sizeof(error)));
        do { step = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); } while (step > 0);
        assert(step < 0 && !latcd_retirement_queue_retry_receipt_stage_next(queue, &budget, error, sizeof(error)));
        latcd_retirement_queue_free(queue);
        if (mixed >= 2) {
            latcd_cache_capacity_close(&capacity);
            capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
            memset(&budget, 0, sizeof(budget));
            assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
            assert(!latcd_cache_capacity_recovery_begin(&capacity));
            latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
            assert(!latcd_retirement_retry_page_restore_budget(root, &capacity, UINT64_MAX, 1,
                                                               &budget, page, error, sizeof(error)));
            assert(page->deletion_intent && !latcd_cache_capacity_recovery_finish(&capacity));
            LatcdRetryRecovery *recovery = latcd_retry_recovery_new(root, 1, &budget, false);
            assert(recovery && latcd_retry_recovery_step(recovery, 1, 10000, error, sizeof(error)) < 0);
            latcd_retry_recovery_free(recovery);
            recovery = latcd_retry_recovery_new(root, 1, &budget, true);
            assert(recovery);
            unsigned steps = 0;
            do {
                step = latcd_retry_recovery_step(recovery, 1, 10000, error, sizeof(error));
                assert(++steps < 1000);
            } while (step > 0);
            if (step) fprintf(stderr, "retry recovery: %s\n", error);
            assert(!step);
            latcd_retry_recovery_free(recovery);
            assert(!latcd_retirement_page_state_load(root, &state, error, sizeof(error)) &&
                   !strcmp(state.retry_cursor, page->items[1].hint.name));
            char *second = g_build_filename(root, page->items[1].hint.name, NULL);
            if (mixed == 2) assert(!access(second, F_OK));
            else assert(access(second, F_OK) < 0 && errno == ENOENT);
            g_free(second);
            char *shard_name = g_strconcat(page->items[1].hint.name, ".ini", NULL);
            char *shard = g_build_filename(schedule, shard_name, NULL);
            if (mixed == 2) assert(!access(shard, F_OK));
            else assert(access(shard, F_OK) < 0 && errno == ENOENT);
            g_free(shard); g_free(shard_name);
            latcd_cache_capacity_close(&capacity);
            g_free(page); g_free(schedule); g_free(boot); simulated_boottime_us = 0;
            remove_root(root); g_free(root);
            return;
        }
        queue = latcd_retirement_queue_new(root, 1);
        assert(!latcd_retirement_queue_retry_receipt_resume(queue, &budget, error, sizeof(error)));
        do { step = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); } while (step > 0);
        assert(step < 0 && !latcd_retirement_queue_retry_receipt_consume(queue, &budget, error, sizeof(error)));
        latcd_retirement_queue_free(queue);
        latcd_cache_capacity_close(&capacity);
        capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
        memset(&budget, 0, sizeof(budget));
        assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
        assert(!latcd_cache_capacity_recovery_begin(&capacity));
        latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
        assert(!latcd_retirement_retry_page_restore_budget(root, &capacity, UINT64_MAX, 1, &budget, page, error, sizeof(error)) &&
               page->completed == i + 1 && !latcd_cache_capacity_recovery_finish(&capacity));
    }
    if (mixed) {
        assert(!latcd_retirement_retry_page_begin_deferred(root, &budget, error, sizeof(error)));
        assert(!latcd_retirement_retry_page_apply_unmatched(root, &budget, error, sizeof(error)));
        latcd_cache_capacity_close(&capacity);
        capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
        memset(&budget, 0, sizeof(budget));
        assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
        assert(!latcd_cache_capacity_recovery_begin(&capacity));
        latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
        assert(!latcd_retirement_retry_page_restore_budget(root, &capacity, UINT64_MAX, 1, &budget, page, error, sizeof(error)));
        assert(!latcd_cache_capacity_recovery_finish(&capacity));
        assert(!latcd_retirement_retry_page_finish_unmatched(root, &budget, error, sizeof(error)));
        assert(!latcd_retirement_retry_page_load(root, page, error, sizeof(error)) &&
               page->completed == 2 && page->deleted[0] && !page->deleted[1]);
        assert(latcd_retirement_retry_page_commit(root, &budget, error, sizeof(error)) < 0);
    }
    queue = latcd_retirement_queue_new(root, 1);
    assert(!latcd_retirement_queue_retry_completed_resume(queue, &budget, error, sizeof(error)));
    do { step = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); } while (step > 0);
    assert(step < 0 && !latcd_retirement_queue_retry_completed_commit(queue, &budget, error, sizeof(error)));
    assert(!latcd_retirement_page_state_load(root, &state, error, sizeof(error)) &&
           !strcmp(state.retry_cursor, page->items[1].hint.name));
    latcd_retirement_queue_free(queue); latcd_cache_capacity_close(&capacity);
    g_free(page); g_free(schedule); g_free(boot); simulated_boottime_us = 0;
    remove_root(root); g_free(root);
}

static void make_startup_retry_fixture(const char *root, unsigned phase)
{
    const uint64_t grace = UINT64_C(600) * 1000000;
    char error[256], *boot = NULL;
    struct timespec ts;
    assert(!clock_gettime(CLOCK_BOOTTIME, &ts));
    uint64_t now = (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    publish_page_fixture(root, 7);
    LatcdRetirementPageState state;
    assert(!latcd_retirement_page_round_begin(root, grace, &state, error, sizeof(error)));
    LatcdRetirementPageDeadline hint = {.enqueued = now, .retry_at = now};
    snprintf(hint.name, sizeof(hint.name), "%064x.so", 7);
    assert(!latcd_retirement_schedule_store(root, boot, grace, now, 3, &hint, error, sizeof(error)));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, grace);
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    LatcdRetirementQueueStats stats; int result;
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0);
    assert(!latcd_retirement_queue_retry_page_stage(queue, &capacity, UINT64_MAX,
                                                      &budget, error, sizeof(error)));
    if (phase)
        assert(!latcd_retirement_retry_page_begin_deferred(root, &budget, error, sizeof(error)));
    if (phase > 1)
        assert(!latcd_retirement_retry_page_apply_unmatched(root, &budget, error, sizeof(error)));
    latcd_retirement_queue_free(queue);
    latcd_cache_capacity_close(&capacity);
    g_free(boot);
}

static void test_retry_not_due(bool due)
{
    char *root = root_new(), error[256], *boot = NULL;
    simulated_boottime_us = 100;
    publish_page_fixture(root, 7);
    simulated_boottime_us = 101;
    LatcdRetirementPageState state;
    assert(!latcd_retirement_page_round_begin(root, 100, &state, error, sizeof(error)));
    assert(g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot, NULL, NULL));
    g_strchomp(boot);
    char *schedule = g_build_filename(root, ".gc", "retirement-schedule", NULL);
    assert(!mkdir(schedule, 0700));
    char *tombstones = g_build_filename(root, ".gc", "tombstones", NULL);
    assert(!mkdir(tombstones, 0700));
    LatcdRetirementPageDeadline hint = {.enqueued = 100, .retry_at = 100};
    snprintf(hint.name, sizeof(hint.name), "%064x.so", 7);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 101, 3, &hint, error, sizeof(error)));
    LatcdRetirementPageDeadline unmatched = hint;
    snprintf(unmatched.name, sizeof(unmatched.name), "%064x.so", 8);
    assert(!latcd_retirement_schedule_store(root, boot, 100, 101, 3, &unmatched, error, sizeof(error)));
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT; LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 100);
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    LatcdRetirementQueueStats stats; int result;
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0);
    int staged = latcd_retirement_queue_retry_page_stage(queue, &capacity, UINT64_MAX,
                                                         &budget, error, sizeof(error));
    assert(!staged);
    LatcdRetirementRetryPage *page = g_new0(LatcdRetirementRetryPage, 1);
    assert(!latcd_retirement_retry_page_load(root, page, error, sizeof(error)) &&
           page->count == 2 && page->items[0].matched && page->items[0].aggregate.deadline == 200 &&
           !page->items[1].matched);
    assert(latcd_retirement_retry_page_begin_unmatched(root, &budget, error, sizeof(error)) < 0);
    assert(latcd_retirement_retry_page_begin_unattempted(root, &budget, error, sizeof(error)) < 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        simulated_boottime_us = 200;
        _exit(latcd_retirement_retry_page_begin_not_due(root, &budget, error, sizeof(error)) < 0 ? 0 : 1);
    }
    int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    if (due) simulated_boottime_us = 200;
    child = fork(); assert(child >= 0);
    if (!child) {
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "crash:renamed", 1));
        latcd_retirement_retry_page_begin_deferred(root, &budget, error, sizeof(error));
        _exit(1);
    }
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    latcd_retirement_queue_free(queue); latcd_cache_capacity_close(&capacity);
    simulated_boottime_us = 201;
    capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT; memset(&budget, 0, sizeof(budget));
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_begin(&capacity));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    char *gc = g_build_filename(root, ".gc", NULL);
    struct stat gc_stat; assert(!stat(gc, &gc_stat));
    retry_sync_device = gc_stat.st_dev; retry_sync_inode = gc_stat.st_ino;
    retry_sync_fault = true;
    assert(latcd_retirement_retry_page_restore_budget(root, &capacity, UINT64_MAX, 100,
                                                      &budget, page, error, sizeof(error)) < 0);
    retry_sync_fault = false;
    assert(!budget.capacity && latcd_cache_capacity_recovery_finish(&capacity) < 0);
    latcd_cache_capacity_close(&capacity);
    capacity = (LatcdCacheCapacity)LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    assert(!latcd_cache_capacity_recovery_begin(&capacity));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
    assert(!latcd_retirement_retry_page_restore_budget(root, &capacity, UINT64_MAX, 100,
                                                       &budget, page, error, sizeof(error)) &&
           page->intent_present && !latcd_cache_capacity_recovery_finish(&capacity));
    assert(!latcd_retirement_retry_page_apply_unmatched(root, &budget, error, sizeof(error)));
    assert(!latcd_retirement_retry_page_finish_unmatched(root, &budget, error, sizeof(error)));
    assert(latcd_retirement_retry_page_begin_not_due(root, &budget, error, sizeof(error)) < 0);
    assert(!latcd_retirement_retry_page_begin_deferred(root, &budget, error, sizeof(error)));
    assert(!latcd_retirement_retry_page_apply_unmatched(root, &budget, error, sizeof(error)));
    assert(!latcd_retirement_retry_page_finish_unmatched(root, &budget, error, sizeof(error)));
    assert(!latcd_retirement_retry_page_commit(root, &budget, error, sizeof(error)));
    assert(!latcd_retirement_page_state_load(root, &state, error, sizeof(error)) &&
           !strcmp(state.retry_cursor, unmatched.name));
    latcd_cache_capacity_close(&capacity); g_free(page); g_free(boot); g_free(schedule); g_free(tombstones); g_free(gc);
    simulated_boottime_us = 0; remove_root(root); g_free(root);
}

static void test_page_round_insertions(void)
{
    char *root = root_new(), error[256], boot[37];
    uint64_t cutoff;
    simulated_boottime_us = 100;
    for (unsigned i = 100; i < 144; i++) publish_page_fixture(root, i);
    simulated_boottime_us = 200;
    assert(!latcd_retirement_round_sample(root, boot, &cutoff, error, sizeof(error)) && cutoff == 200);
    LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 1);
    LatcdRetirementQueueStats stats;
    LatcdRetirementPageState page;
    assert(!latcd_retirement_queue_diagnostic_round(queue, boot, cutoff, NULL));
    int result;
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0 && !latcd_retirement_queue_aggregated_page(queue, &page) && page.count == 128);
    char cursor[138];
    g_strlcpy(cursor, page.cursor, sizeof(cursor));
    latcd_retirement_queue_free(queue);

    LatcdRetirementPageDeadline hints[2] = {0};
    hints[0] = page.entries[4];
    hints[0].enqueued = 90;
    hints[0].last_attempt = 3;
    hints[0].retry_at = 199;
    hints[0].busy_count = 2;
    snprintf(hints[1].name, sizeof(hints[1].name), "%064x.so", 9999);
    hints[1].enqueued = 90;
    char *schedule_dir = g_build_filename(root, ".gc", "retirement-schedule", NULL);
    assert(!mkdir(schedule_dir, 0700));
    g_free(schedule_dir);
    assert(!latcd_retirement_schedule_store(root, boot, 1, 200, 3, &hints[0], error, sizeof(error)));
    assert(!latcd_retirement_schedule_store(root, boot, 1, 200, 3, &hints[1], error, sizeof(error)));
    queue = latcd_retirement_queue_new(root, 1);
    hints[0].retry_at = 201;
    assert(latcd_retirement_queue_diagnostic_retry(queue, boot, cutoff, hints, 2) < 0);
    hints[0].retry_at = 199;
    assert(!latcd_retirement_queue_diagnostic_retry(queue, boot, cutoff, hints, 2));
    LatcdRetirementRetryItem items[128];
    unsigned item_count = 99;
    assert(latcd_retirement_queue_retry_items(queue, items, &item_count) < 0 && !item_count);
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0 && !latcd_retirement_queue_aggregated_page(queue, &page));
    assert(page.count == 1 && !strcmp(page.entries[0].name, hints[0].name) &&
           page.entries[0].deadline == 101 && page.entries[0].enqueued == 90 &&
           page.entries[0].last_attempt == 3 && page.entries[0].retry_at == 199 &&
           page.entries[0].busy_count == 2);
    bool matches[128];
    unsigned match_count;
    assert(!latcd_retirement_queue_retry_matches(queue, matches, &match_count));
    assert(match_count == 2 && matches[0] && !matches[1]);
    assert(!latcd_retirement_queue_retry_items(queue, items, &item_count) && item_count == 2);
    assert(items[0].matched && !strcmp(items[0].hint.name, hints[0].name) &&
           !items[0].shard_sequence_bound && !items[0].shard_sequence &&
           items[0].hint.deadline == hints[0].deadline &&
           items[0].aggregate.deadline == 101 && items[0].aggregate.retry_at == 199);
    assert(!items[1].matched && !strcmp(items[1].hint.name, hints[1].name) &&
           !items[1].aggregate.name[0] && !items[1].aggregate.deadline);
    assert(latcd_retirement_queue_step(queue, 1, 10000, &stats, error, sizeof(error)) < 0);
    assert(!latcd_retirement_queue_retry_revalidate(queue, error, sizeof(error)));
    assert(latcd_retirement_queue_retry_revalidate(queue, error, sizeof(error)) < 0);
    LatcdRetirementAttempt attempt;
    assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &attempt));
    latcd_retirement_queue_free(queue);

    queue = latcd_retirement_queue_new(root, 1);
    assert(!latcd_retirement_queue_diagnostic_retry(queue, boot, cutoff, hints, 2));
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0 && !latcd_retirement_queue_retry_items(queue, items, &item_count));
    char *changed = g_build_filename(root, ".gc", "tombstones", "witness-change", NULL);
    put(changed, "changed\n");
    assert(latcd_retirement_queue_retry_revalidate(queue, error, sizeof(error)) < 0);
    assert(latcd_retirement_queue_retry_items(queue, items, &item_count) < 0 && !item_count);
    assert(!unlink(changed));
    g_free(changed);
    latcd_retirement_queue_free(queue);

    queue = latcd_retirement_queue_new(root, 1);
    assert(!latcd_retirement_queue_diagnostic_retry(queue, boot, cutoff, hints, 2));
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0 && !latcd_retirement_queue_retry_items(queue, items, &item_count));
    changed = g_build_filename(root, hints[1].name, NULL);
    put(changed, "reappeared\n");
    assert(latcd_retirement_queue_retry_revalidate(queue, error, sizeof(error)) < 0);
    assert(latcd_retirement_queue_retry_items(queue, items, &item_count) < 0 && !item_count);
    assert(!unlink(changed));
    g_free(changed);
    latcd_retirement_queue_free(queue);

    queue = latcd_retirement_queue_new(root, 1);
    assert(!latcd_retirement_queue_diagnostic_retry(queue, boot, cutoff, hints, 2));
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    char *shard_name = g_strconcat(hints[0].name, ".ini", NULL);
    char *shard_path = g_build_filename(root, ".gc", "retirement-schedule", shard_name, NULL);
    assert(!unlink(shard_path));
    g_free(shard_path); g_free(shard_name);
    assert(latcd_retirement_queue_retry_revalidate(queue, error, sizeof(error)) < 0);
    assert(latcd_retirement_queue_retry_items(queue, items, &item_count) < 0 && !item_count);
    latcd_retirement_queue_free(queue);

    assert(!latcd_retirement_schedule_store(root, boot, 1, 200, 3, &hints[0], error, sizeof(error)));
    struct stat retry_root;
    assert(!stat(root, &retry_root));
    LatcdRetirementPageState retry_state = {.cache_device = retry_root.st_dev,
        .cache_inode = retry_root.st_ino, .grace_us = 1, .round_cutoff = cutoff};
    g_strlcpy(retry_state.boot, boot, sizeof(retry_state.boot));
    g_strlcpy(retry_state.retry_cursor, hints[0].name, sizeof(retry_state.retry_cursor));
    assert(!latcd_retirement_page_state_store(root, &retry_state, error, sizeof(error)));
    queue = latcd_retirement_queue_new(root, 1);
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0 && !latcd_retirement_queue_retry_items(queue, items, &item_count) && item_count == 2);
    assert(!strcmp(items[0].hint.name, hints[1].name) && !strcmp(items[1].hint.name, hints[0].name));
    assert(items[0].shard_sequence_bound && items[1].shard_sequence_bound &&
           items[0].shard_sequence == 3 && items[1].shard_sequence == 3);
    LatcdRetirementRetryPage *retry_page = g_new0(LatcdRetirementRetryPage, 1);
    uint8_t retry_identity[32];
    assert(!latcd_retirement_queue_retry_page_snapshot(queue, retry_page, error, sizeof(error)));
    assert(retry_page->count == 2 && !strcmp(retry_page->retry_cursor, hints[0].name) &&
           !strcmp(retry_page->end_cursor, hints[0].name) && !retry_page->items[0].matched &&
           retry_page->items[1].matched && !latcd_retirement_retry_page_identity(retry_page, retry_identity));
    assert(latcd_retirement_queue_retry_page_snapshot(queue, retry_page, error, sizeof(error)) < 0 &&
           !retry_page->count);
    g_free(retry_page);
    latcd_retirement_queue_free(queue);
    queue = latcd_retirement_queue_new(root, 1);
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    retry_state.retry_cursor[0] = 0;
    assert(!latcd_retirement_page_state_store(root, &retry_state, error, sizeof(error)));
    assert(latcd_retirement_queue_retry_revalidate(queue, error, sizeof(error)) < 0);
    latcd_retirement_queue_free(queue);

    shard_name = g_strconcat(hints[0].name, ".ini", NULL);
    shard_path = g_build_filename(root, ".gc", "retirement-schedule", shard_name, NULL);
    assert(!unlink(shard_path));
    g_free(shard_path); g_free(shard_name);
    g_strlcpy(retry_state.retry_cursor, hints[0].name, sizeof(retry_state.retry_cursor));
    assert(!latcd_retirement_page_state_store(root, &retry_state, error, sizeof(error)));
    queue = latcd_retirement_queue_new(root, 1);
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0 && !latcd_retirement_queue_retry_items(queue, items, &item_count) &&
           item_count == 1 && !items[0].matched);
    assert(!latcd_retirement_queue_retry_advance_unmatched(queue, error, sizeof(error)));
    LatcdRetirementPageState advanced;
    assert(!latcd_retirement_page_state_load(root, &advanced, error, sizeof(error)) &&
           !strcmp(advanced.retry_cursor, hints[1].name) && !advanced.committed_cursor[0]);
    LatcdRetirementPageDeadline preserved;
    uint64_t preserved_sequence;
    assert(!latcd_retirement_schedule_load(root, boot, 1, 200, hints[1].name,
                                            &preserved_sequence, &preserved, error, sizeof(error)) &&
           preserved_sequence == 3 && preserved.enqueued == hints[1].enqueued);
    latcd_retirement_queue_free(queue);
    assert(!latcd_retirement_schedule_store(root, boot, 1, 200, 3, &hints[0], error, sizeof(error)));

    /* A v2 result can change while the scheduling fields and sequence stay fixed. */
    shard_name = g_strconcat(hints[0].name, ".ini", NULL);
    shard_path = g_build_filename(root, ".gc", "retirement-schedule", shard_name, NULL);
    GKeyFile *same_fields = g_key_file_new();
    assert(g_key_file_load_from_file(same_fields, shard_path, 0, NULL));
    g_key_file_set_integer(same_fields, "schedule", "version", 2);
    g_key_file_set_string(same_fields, "schedule", "page_identity",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    g_key_file_set_string(same_fields, "schedule", "result", "deferred");
    char *same_data = g_key_file_to_data(same_fields, NULL, NULL);
    put(shard_path, same_data); g_free(same_data);
    queue = latcd_retirement_queue_new(root, 1);
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    g_key_file_set_string(same_fields, "schedule", "page_identity",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    same_data = g_key_file_to_data(same_fields, NULL, NULL);
    put(shard_path, same_data); g_free(same_data); g_key_file_unref(same_fields);
    assert(result < 0 && latcd_retirement_queue_retry_revalidate(queue, error, sizeof(error)) < 0);
    latcd_retirement_queue_free(queue);
    assert(!unlink(shard_path));
    g_free(shard_path); g_free(shard_name);
    assert(!latcd_retirement_schedule_store(root, boot, 1, 200, 3, &hints[0], error, sizeof(error)));

    g_strlcpy(retry_state.retry_cursor, hints[0].name, sizeof(retry_state.retry_cursor));
    assert(!latcd_retirement_page_state_store(root, &retry_state, error, sizeof(error)));
    queue = latcd_retirement_queue_new(root, 1);
    assert(latcd_retirement_queue_retry_begin(queue, error, sizeof(error)) == 1);
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    shard_name = g_strconcat(hints[1].name, ".ini", NULL);
    shard_path = g_build_filename(root, ".gc", "retirement-schedule", shard_name, NULL);
    GKeyFile *modified_shard = g_key_file_new();
    assert(g_key_file_load_from_file(modified_shard, shard_path, 0, NULL));
    g_key_file_set_uint64(modified_shard, "schedule", "sequence", 2);
    char *modified_data = g_key_file_to_data(modified_shard, NULL, NULL);
    put(shard_path, modified_data);
    g_free(modified_data); g_key_file_unref(modified_shard);
    g_free(shard_path); g_free(shard_name);
    assert(latcd_retirement_queue_retry_revalidate(queue, error, sizeof(error)) < 0);
    latcd_retirement_queue_free(queue);

    /* Equal-cutoff and later transactions on both sides belong to a later round. */
    publish_page_fixture(root, 1);
    publish_page_fixture(root, 1000);
    simulated_boottime_us = 201;
    publish_page_fixture(root, 2);
    publish_page_fixture(root, 1001);
    queue = latcd_retirement_queue_new(root, 1);
    assert(!latcd_retirement_queue_diagnostic_round(queue, boot, cutoff, cursor));
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0 && !latcd_retirement_queue_aggregated_page(queue, &page) && page.count == 4);
    for (unsigned i = 0; i < page.count; i++) {
        char *src = g_strdup_printf("%064x", 142 + (i + 2) / 3);
        assert(!strncmp(page.entries[i].name, src, 64));
        g_free(src);
    }
    latcd_retirement_queue_free(queue);

    simulated_boottime_us = 202;
    queue = latcd_retirement_queue_new(root, 1);
    assert(!latcd_retirement_queue_diagnostic_round(queue, boot, 202, NULL));
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0 && !latcd_retirement_queue_aggregated_page(queue, &page) && page.count == 128);
    char *first = g_strdup_printf("%064x", 1);
    char *second = g_strdup_printf("%064x", 2);
    assert(!strncmp(page.entries[0].name, first, 64) && !strncmp(page.entries[3].name, second, 64));
    g_free(first); g_free(second);
    g_strlcpy(cursor, page.cursor, sizeof(cursor));
    latcd_retirement_queue_free(queue);
    queue = latcd_retirement_queue_new(root, 1);
    assert(!latcd_retirement_queue_diagnostic_round(queue, boot, 202, cursor));
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(result < 0 && !latcd_retirement_queue_aggregated_page(queue, &page) && page.count == 16);
    first = g_strdup_printf("%064x", 1000);
    second = g_strdup_printf("%064x", 1001);
    assert(!strncmp(page.entries[10].name, first, 64) && !strncmp(page.entries[13].name, second, 64));
    g_free(first); g_free(second);
    latcd_retirement_queue_free(queue);
    remove_root(root); g_free(root);
    simulated_boottime_us = 0;
}

static void test_queue_overflow_fixture(void)
{
    char *root = root_new(), error[256];
    const char *suffix[] = {".so", ".native", ".tbset"};
    simulated_boottime_us = 100;
    for (unsigned i = 44; i > 0; i--) {
        char *src = g_strdup_printf("%064x", i);
        char *names[6], *paths[6];
        for (unsigned j = 0; j < 6; j++) {
            names[j] = j < 3 ? g_strconcat(src, suffix[j], NULL) :
                g_strdup_printf("%s-%s%s", src, src, suffix[j - 3]);
            paths[j] = g_build_filename(root, names[j], NULL);
            put(paths[j], "fixture\n");
        }
        char *previous = g_strdup_printf("{\"version\":2,\"module\":\"%s\",\"native\":\"%s\","
            "\"tbset\":\"%s\",\"source_sha256\":\"%s\",\"codegen_id\":\"%s\",\"published_sequence\":1}",
            names[0], names[1], names[2], src, src);
        char *next_manifest = g_strdup_printf("{\"version\":2,\"module\":\"%s\",\"native\":\"%s\","
            "\"tbset\":\"%s\",\"source_sha256\":\"%s\",\"codegen_id\":\"%s\",\"published_sequence\":2}",
            names[3], names[4], names[5], src, src);
        char *current = g_strdup_printf("%s/%s.current", root, src);
        put(current, previous);
        char *evidence = latcd_retirement_capture_objects(root, src, (const char *const *)names, 6);
        LatcdRetirementPublication *publication = latcd_retirement_publication_open(root, error, sizeof(error));
        assert(evidence && publication && !latcd_retirement_publication_prepare(publication, src,
            next_manifest, strlen(next_manifest), evidence, error, sizeof(error)));
        put(current, next_manifest);
        assert(!latcd_retirement_publication_finish(publication, error, sizeof(error)));
        latcd_retirement_publication_close(publication);
        for (unsigned j = 0; j < 6; j++) { g_free(names[j]); g_free(paths[j]); }
        g_free(evidence); g_free(current); g_free(previous);
        g_free(next_manifest); g_free(src);
    }
    simulated_boottime_us = 200;
    char boot[37]; uint64_t cutoff;
    assert(!latcd_retirement_round_sample(root, boot, &cutoff, error, sizeof(error)));
    assert(cutoff == 200);
    char *small_source = g_strdup_printf("%064x", 1);
    char *small_name = g_strconcat(small_source, ".native", NULL);
    char *small_path = g_build_filename(root, small_name, NULL);
    const char *small_names[] = {small_name};
    char *small_evidence = latcd_retirement_capture_objects(root, small_source, small_names, 1);
    int small_fd = open(small_path, O_RDONLY | O_CLOEXEC);
    assert(small_evidence && small_fd >= 0 &&
        !latcd_retirement_tombstone(root, small_source, small_name, small_fd,
                                    small_evidence, error, sizeof(error)));
    close(small_fd);
    assert(!latcd_tombstone_delete(root, small_name, error, sizeof(error)));
    char *marker = g_build_filename(root, ".gc", "tombstones", small_name, NULL);
    char *receipt = NULL;
    assert(g_file_get_contents(marker, &receipt, NULL, NULL));
    LatcdRetirementQueue *changed_page = latcd_retirement_queue_new(root, 0);
    assert(!latcd_retirement_queue_diagnostic_round(changed_page, boot, cutoff, NULL));
    LatcdRetirementQueueStats changed_stats;
    int changed_result;
    do {
        changed_result = latcd_retirement_queue_step(changed_page, 1, 10000,
                                                     &changed_stats, error, sizeof(error));
        assert(changed_result == 1);
    } while (!changed_stats.aggregating);
    assert(!unlink(marker));
    do {
        changed_result = latcd_retirement_queue_step(changed_page, 32, 10000,
                                                     &changed_stats, error, sizeof(error));
    } while (changed_result > 0);
    LatcdRetirementPageState rejected_page;
    assert(changed_result < 0 && !changed_stats.complete &&
           latcd_retirement_queue_aggregated_page(changed_page, &rejected_page) < 0);
    latcd_retirement_queue_free(changed_page);
    put(small_path, "fixture\n");
    assert(!unlink(marker) || errno == ENOENT);
    g_free(receipt); g_free(marker); g_free(small_evidence);
    g_free(small_path); g_free(small_name); g_free(small_source);
    char *store = g_build_filename(root, ".gc", "transactions", NULL);
    GDir *directory = g_dir_open(store, 0, NULL);
    assert(directory);
    GKeyFile *duplicate = g_key_file_new();
    const char *original_name;
    bool selected_source = false;
    char *selected = g_strdup_printf("%064x", 1);
    while ((original_name = g_dir_read_name(directory))) {
        char *original_path = g_build_filename(store, original_name, NULL);
        assert(g_key_file_load_from_file(duplicate, original_path, 0, NULL));
        char *source = g_key_file_get_string(duplicate, "transaction", "source", NULL);
        selected_source = source && !strcmp(source, selected);
        g_free(source); g_free(original_path);
        if (selected_source) break;
    }
    g_free(selected);
    assert(selected_source);
    g_key_file_set_uint64(duplicate, "transaction", "retired_boottime_us", 201);
    char *duplicate_data = g_key_file_to_data(duplicate, NULL, NULL);
    char *duplicate_id = g_uuid_string_random();
    char *duplicate_name = g_strconcat(duplicate_id, ".ini", NULL);
    char *duplicate_path = g_build_filename(store, duplicate_name, NULL);
    g_free(duplicate_id); g_free(duplicate_name);
    put(duplicate_path, duplicate_data);
    g_free(duplicate_data); g_key_file_unref(duplicate);
    g_dir_close(directory);
    simulated_boottime_us = 201;
    LatcdRetirementQueue *diagnostic = latcd_retirement_queue_new(root, 0);
    assert(!latcd_retirement_queue_diagnostic_round(diagnostic, boot, cutoff, NULL));
    LatcdRetirementQueueStats diagnostic_stats;
    int diagnostic_result;
    do {
        diagnostic_result = latcd_retirement_queue_step(diagnostic, 32, 10000,
                                                         &diagnostic_stats, error, sizeof(error));
    } while (diagnostic_result > 0);
    LatcdRetirementPageState first_page, second_page;
    assert(diagnostic_result < 0 && !diagnostic_stats.complete);
    assert(!latcd_retirement_queue_aggregated_page(diagnostic, &first_page));
    assert(first_page.count == 128);
    GPtrArray *expected = g_ptr_array_new_with_free_func(g_free);
    for (unsigned i = 1; i <= 44; i++) {
        char *src = g_strdup_printf("%064x", i);
        for (unsigned j = 0; j < 3; j++)
            g_ptr_array_add(expected, g_strconcat(src, suffix[j], NULL));
        g_free(src);
    }
    g_ptr_array_sort(expected, compare_string_pointers);
    for (unsigned i = 0; i < first_page.count; i++)
        assert(!strcmp(first_page.entries[i].name, expected->pdata[i]));
    LatcdRetirementAttempt diagnostic_attempt;
    assert(!latcd_retirement_queue_take(diagnostic, UINT64_MAX, &diagnostic_attempt));
    latcd_retirement_queue_free(diagnostic);
    LatcdRetirementPageDeadline retry_hint = {0};
    for (unsigned i = 0; i < first_page.count; i++) {
        if (first_page.entries[i].deadline == 201) {
            retry_hint = first_page.entries[i];
            break;
        }
    }
    assert(retry_hint.name[0]);
    diagnostic = latcd_retirement_queue_new(root, 100);
    assert(!latcd_retirement_queue_diagnostic_retry(diagnostic, boot, cutoff, &retry_hint, 1));
    do {
        diagnostic_result = latcd_retirement_queue_step(diagnostic, 32, 10000,
                                                         &diagnostic_stats, error, sizeof(error));
    } while (diagnostic_result > 0);
    assert(diagnostic_result < 0 && !latcd_retirement_queue_aggregated_page(diagnostic, &second_page));
    assert(second_page.count == 1 && !strcmp(second_page.entries[0].name, retry_hint.name) &&
           second_page.entries[0].deadline == 301);
    assert(!latcd_retirement_queue_take(diagnostic, UINT64_MAX, &diagnostic_attempt));
    latcd_retirement_queue_free(diagnostic);
    diagnostic = latcd_retirement_queue_new(root, 100);
    assert(latcd_retirement_queue_diagnostic_resume(diagnostic, error, sizeof(error)) < 0);
    latcd_retirement_queue_free(diagnostic);
    struct stat round_cache;
    assert(!stat(root, &round_cache));
    first_page.cache_device = round_cache.st_dev;
    first_page.cache_inode = round_cache.st_ino;
    first_page.grace_us = 100;
    first_page.round_cutoff = cutoff;
    g_strlcpy(first_page.boot, boot, sizeof(first_page.boot));
    LatcdRetirementPageState stage_empty = first_page;
    stage_empty.count = 0;
    stage_empty.cursor[0] = 0;
    assert(!latcd_retirement_page_state_store(root, &stage_empty, error, sizeof(error)));
    pid_t stage_child = fork();
    assert(stage_child >= 0);
    if (!stage_child) {
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "crash:renamed", 1));
        latcd_retirement_page_stage(root, &first_page, error, sizeof(error));
        _exit(1);
    }
    int stage_status;
    assert(waitpid(stage_child, &stage_status, 0) == stage_child &&
           WIFSIGNALED(stage_status) && WTERMSIG(stage_status) == SIGKILL);
    diagnostic = latcd_retirement_queue_new(root, 101);
    assert(latcd_retirement_queue_diagnostic_resume(diagnostic, error, sizeof(error)) < 0);
    assert(!latcd_retirement_queue_take(diagnostic, UINT64_MAX, &diagnostic_attempt));
    latcd_retirement_queue_free(diagnostic);
    diagnostic = latcd_retirement_queue_new(root, 100);
    assert(!latcd_retirement_queue_diagnostic_resume(diagnostic, error, sizeof(error)));
    do {
        diagnostic_result = latcd_retirement_queue_step(diagnostic, 32, 10000,
                                                         &diagnostic_stats, error, sizeof(error));
    } while (diagnostic_result > 0);
    assert(diagnostic_result < 0 && !diagnostic_stats.complete);
    assert(!latcd_retirement_queue_aggregated_page(diagnostic, &second_page));
    assert(second_page.count == first_page.count);
    for (unsigned i = 0; i < first_page.count; i++) {
        assert(!strcmp(first_page.entries[i].name, second_page.entries[i].name));
        assert(first_page.entries[i].deadline + 100 == second_page.entries[i].deadline);
    }
    char *schedule_dir = g_build_filename(root, ".gc", "retirement-schedule", NULL);
    assert(!mkdir(schedule_dir, 0700));
    for (unsigned i = 0; i < first_page.count; i++) {
        int stored = latcd_retirement_test_store_page_result(root, 201, &first_page,
                &first_page.entries[i], LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error));
        if (stored) fprintf(stderr, "page result %u: %s enqueued=%" G_GUINT64_FORMAT "\n",
                            i, error, first_page.entries[i].enqueued);
        assert(!stored);
    }
    pid_t commit_child = fork();
    assert(commit_child >= 0);
    if (!commit_child) {
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "crash:file-synced", 1));
        latcd_retirement_page_commit(root, 201, &first_page, error, sizeof(error));
        _exit(1);
    }
    int commit_status;
    assert(waitpid(commit_child, &commit_status, 0) == commit_child &&
           WIFSIGNALED(commit_status) && WTERMSIG(commit_status) == SIGKILL);
    LatcdRetirementQueue *rediscovery = latcd_retirement_queue_new(root, 100);
    assert(!latcd_retirement_queue_diagnostic_resume(rediscovery, error, sizeof(error)));
    LatcdRetirementQueueStats rediscovery_stats;
    int rediscovery_result;
    do {
        rediscovery_result = latcd_retirement_queue_step(rediscovery, 32, 10000,
                                                         &rediscovery_stats, error, sizeof(error));
    } while (rediscovery_result > 0);
    LatcdRetirementPageState rediscovered;
    assert(rediscovery_result < 0 && !rediscovery_stats.complete &&
           !latcd_retirement_queue_aggregated_page(rediscovery, &rediscovered) &&
           rediscovered.count == first_page.count);
    for (unsigned i = 0; i < first_page.count; i++)
        assert(!strcmp(rediscovered.entries[i].name, first_page.entries[i].name));
    latcd_retirement_queue_free(rediscovery);
    commit_child = fork();
    assert(commit_child >= 0);
    if (!commit_child) {
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", "crash:renamed", 1));
        latcd_retirement_page_commit(root, 201, &first_page, error, sizeof(error));
        _exit(1);
    }
    assert(waitpid(commit_child, &commit_status, 0) == commit_child &&
           WIFSIGNALED(commit_status) && WTERMSIG(commit_status) == SIGKILL);
    LatcdRetirementPageState committed;
    assert(!latcd_retirement_page_state_load(root, &committed, error, sizeof(error)) &&
           committed.committed_pending && committed.count == first_page.count &&
           !strcmp(committed.cursor, first_page.cursor));
    rediscovery = latcd_retirement_queue_new(root, 100);
    assert(!latcd_retirement_queue_diagnostic_resume(rediscovery, error, sizeof(error)));
    do {
        rediscovery_result = latcd_retirement_queue_step(rediscovery, 32, 10000,
                                                         &rediscovery_stats, error, sizeof(error));
    } while (rediscovery_result > 0);
    assert(rediscovery_result < 0 && !rediscovery_stats.complete &&
           !latcd_retirement_queue_aggregated_page(rediscovery, &rediscovered) &&
           rediscovered.count == expected->len - first_page.count);
    for (unsigned i = 0; i < rediscovered.count; i++)
        assert(!strcmp(rediscovered.entries[i].name, expected->pdata[first_page.count + i]));
    latcd_retirement_queue_free(rediscovery);
    assert(!latcd_retirement_page_state_store(root, &first_page, error, sizeof(error)));
    for (unsigned i = 0; i < first_page.count; i++) {
        char *filename = g_strconcat(first_page.entries[i].name, ".ini", NULL);
        char *path = g_build_filename(schedule_dir, filename, NULL);
        assert(!unlink(path));
        g_free(path); g_free(filename);
    }
    for (unsigned i = 0; i < second_page.count; i += second_page.count - 1) {
        LatcdRetirementPageDeadline hint = second_page.entries[i];
        hint.enqueued = 150;
        hint.last_attempt = i ? 2 : 1;
        hint.retry_at = 250 + i;
        hint.busy_count = i ? 2 : 1;
        assert(!latcd_retirement_schedule_store(root, boot, 100, 201, hint.last_attempt,
                                                &hint, error, sizeof(error)));
    }
    LatcdRetirementPageState unmerged = second_page;
    assert(!latcd_retirement_schedule_merge_page(root, boot, 100, 201, &second_page,
                                                 error, sizeof(error)));
    for (unsigned i = 0; i < second_page.count; i++)
        assert(second_page.entries[i].deadline == unmerged.entries[i].deadline);
    assert(second_page.entries[0].enqueued == 150 && second_page.entries[0].retry_at == 250 &&
           second_page.entries[127].retry_at == 377 && second_page.sequence == 2);
    g_free(schedule_dir);
    assert(!latcd_retirement_queue_take(diagnostic, UINT64_MAX, &diagnostic_attempt));
    latcd_retirement_queue_free(diagnostic);
    char *legacy_page_path = g_build_filename(root, ".gc", "retirement-page.ini", NULL);
    GKeyFile *legacy_page = g_key_file_new();
    assert(g_key_file_load_from_file(legacy_page, legacy_page_path, 0, NULL));
    g_key_file_set_integer(legacy_page, "page", "version", 2);
    assert(g_key_file_remove_key(legacy_page, "page", "pending", NULL));
    for (unsigned i = 0; i < first_page.count; i++) {
        char group[32]; snprintf(group, sizeof(group), "entry%u", i);
        assert(g_key_file_remove_key(legacy_page, group, "result", NULL));
    }
    assert(g_key_file_remove_key(legacy_page, "page", "committed_cursor", NULL));
    char *legacy_page_data = g_key_file_to_data(legacy_page, NULL, NULL);
    put(legacy_page_path, legacy_page_data);
    g_free(legacy_page_data);
    g_key_file_unref(legacy_page);
    diagnostic = latcd_retirement_queue_new(root, 100);
    assert(!latcd_retirement_queue_diagnostic_resume(diagnostic, error, sizeof(error)));
    do {
        diagnostic_result = latcd_retirement_queue_step(diagnostic, 32, 10000,
                                                         &diagnostic_stats, error, sizeof(error));
    } while (diagnostic_result > 0);
    assert(diagnostic_result < 0 && !diagnostic_stats.complete);
    assert(!latcd_retirement_queue_aggregated_page(diagnostic, &second_page));
    assert(second_page.count == first_page.count);
    for (unsigned i = 0; i < first_page.count; i++)
        assert(!strcmp(first_page.entries[i].name, second_page.entries[i].name));
    assert(!latcd_retirement_queue_take(diagnostic, UINT64_MAX, &diagnostic_attempt));
    latcd_retirement_queue_free(diagnostic);
    g_free(legacy_page_path);
    LatcdRetirementPageState initial = first_page;
    initial.count = 0;
    initial.cursor[0] = 0;
    assert(!latcd_retirement_page_state_store(root, &initial, error, sizeof(error)));
    g_strlcpy(initial.committed_cursor, first_page.entries[0].name,
              sizeof(initial.committed_cursor));
    initial.count = 1;
    initial.entries[0] = first_page.entries[2];
    g_strlcpy(initial.cursor, initial.entries[0].name, sizeof(initial.cursor));
    assert(!latcd_retirement_page_state_store(root, &initial, error, sizeof(error)));
    diagnostic = latcd_retirement_queue_new(root, 100);
    assert(!latcd_retirement_queue_diagnostic_resume(diagnostic, error, sizeof(error)));
    do {
        diagnostic_result = latcd_retirement_queue_step(diagnostic, 32, 10000,
                                                         &diagnostic_stats, error, sizeof(error));
    } while (diagnostic_result > 0);
    assert(diagnostic_result < 0 && !diagnostic_stats.complete);
    assert(!latcd_retirement_queue_aggregated_page(diagnostic, &second_page));
    assert(second_page.count == 128);
    for (unsigned i = 0; i < second_page.count; i++)
        assert(!strcmp(second_page.entries[i].name, expected->pdata[i + 1]));
    assert(!latcd_retirement_queue_take(diagnostic, UINT64_MAX, &diagnostic_attempt));
    latcd_retirement_queue_free(diagnostic);
    initial.committed_cursor[0] = 0;
    initial.count = 0;
    initial.cursor[0] = 0;
    assert(!latcd_retirement_page_state_store(root, &initial, error, sizeof(error)));
    diagnostic = latcd_retirement_queue_new(root, 100);
    assert(!latcd_retirement_queue_diagnostic_resume(diagnostic, error, sizeof(error)));
    assert(latcd_retirement_queue_diagnostic_resume(diagnostic, error, sizeof(error)) < 0);
    do {
        diagnostic_result = latcd_retirement_queue_step(diagnostic, 32, 10000,
                                                         &diagnostic_stats, error, sizeof(error));
    } while (diagnostic_result > 0);
    assert(diagnostic_result < 0 && !diagnostic_stats.complete);
    assert(!latcd_retirement_queue_aggregated_page(diagnostic, &second_page));
    assert(second_page.count == 128 && !strcmp(first_page.entries[0].name, second_page.entries[0].name));
    assert(!latcd_retirement_queue_take(diagnostic, UINT64_MAX, &diagnostic_attempt));
    latcd_retirement_queue_free(diagnostic);
    char *different_boot = g_uuid_string_random();
    g_strlcpy(first_page.boot, different_boot, sizeof(first_page.boot));
    assert(!latcd_retirement_page_state_store(root, &first_page, error, sizeof(error)));
    diagnostic = latcd_retirement_queue_new(root, 100);
    assert(latcd_retirement_queue_diagnostic_resume(diagnostic, error, sizeof(error)) < 0);
    assert(!latcd_retirement_queue_take(diagnostic, UINT64_MAX, &diagnostic_attempt));
    latcd_retirement_queue_free(diagnostic);
    g_free(different_boot);
    char *round_path = g_build_filename(root, ".gc", "retirement-page.ini", NULL);
    put(round_path, "invalid\n");
    diagnostic = latcd_retirement_queue_new(root, 100);
    assert(latcd_retirement_queue_diagnostic_resume(diagnostic, error, sizeof(error)) < 0);
    latcd_retirement_queue_free(diagnostic);
    assert(!unlink(round_path));
    g_free(round_path);
    diagnostic = latcd_retirement_queue_new(root, 0);
    assert(!latcd_retirement_queue_diagnostic_round(diagnostic, boot, cutoff, first_page.cursor));
    do {
        diagnostic_result = latcd_retirement_queue_step(diagnostic, 32, 10000,
                                                         &diagnostic_stats, error, sizeof(error));
    } while (diagnostic_result > 0);
    assert(diagnostic_result < 0 && !diagnostic_stats.complete);
    assert(!latcd_retirement_queue_aggregated_page(diagnostic, &second_page));
    assert(second_page.count == 4 && strcmp(first_page.cursor, second_page.entries[0].name) < 0);
    for (unsigned i = 0; i < second_page.count; i++)
        assert(!strcmp(second_page.entries[i].name, expected->pdata[128 + i]));
    g_ptr_array_unref(expected);
    unsigned extended = 0;
    for (unsigned i = 0; i < first_page.count; i++) extended += first_page.entries[i].deadline == 201;
    for (unsigned i = 0; i < second_page.count; i++) extended += second_page.entries[i].deadline == 201;
    assert(extended == 3);
    clock_fault = 1;
    assert(latcd_retirement_queue_step(diagnostic, 32, 10000, &diagnostic_stats,
                                       error, sizeof(error)) < 0);
    assert(latcd_retirement_queue_aggregated_page(diagnostic, &second_page) < 0);
    clock_fault = 0;
    latcd_retirement_queue_free(diagnostic);
    diagnostic = latcd_retirement_queue_new(root, 0);
    assert(!latcd_retirement_queue_diagnostic_round(diagnostic, boot, 100, NULL));
    do {
        diagnostic_result = latcd_retirement_queue_step(diagnostic, 32, 10000,
                                                         &diagnostic_stats, error, sizeof(error));
    } while (diagnostic_result > 0);
    assert(diagnostic_result < 0 && !latcd_retirement_queue_aggregated_page(diagnostic, &second_page));
    assert(!second_page.count);
    latcd_retirement_queue_free(diagnostic);
    diagnostic = latcd_retirement_queue_new(root, 0);
    assert(!latcd_retirement_queue_diagnostic_round(diagnostic, boot, cutoff, NULL));
    assert(latcd_retirement_queue_step(diagnostic, 1, 10000, &diagnostic_stats,
                                      error, sizeof(error)) == 1);
    assert(latcd_retirement_queue_diagnostic_round(diagnostic, boot, cutoff, NULL) < 0);
    simulated_boottime_us = cutoff - 1;
    assert(latcd_retirement_queue_step(diagnostic, 1, 10000, &diagnostic_stats,
                                      error, sizeof(error)) < 0);
    assert(latcd_retirement_queue_aggregated_page(diagnostic, &second_page) < 0);
    simulated_boottime_us = cutoff + 100;
    assert(latcd_retirement_queue_step(diagnostic, 1, 10000, &diagnostic_stats,
                                      error, sizeof(error)) == 1);
    simulated_boottime_us = cutoff + 50;
    assert(latcd_retirement_queue_step(diagnostic, 1, 10000, &diagnostic_stats,
                                      error, sizeof(error)) < 0);
    assert(latcd_retirement_queue_aggregated_page(diagnostic, &second_page) < 0);
    simulated_boottime_us = cutoff + 100;
    assert(latcd_retirement_queue_step(diagnostic, 1, 10000, &diagnostic_stats,
                                      error, sizeof(error)) == 1);
    char *replacement = NULL;
    assert(g_file_get_contents(duplicate_path, &replacement, NULL, NULL));
    put(duplicate_path, replacement);
    g_free(replacement);
    do {
        diagnostic_result = latcd_retirement_queue_step(diagnostic, 32, 10000,
                                                         &diagnostic_stats, error, sizeof(error));
    } while (diagnostic_result > 0);
    assert(diagnostic_result < 0 && !diagnostic_stats.complete);
    assert(latcd_retirement_queue_aggregated_page(diagnostic, &second_page) < 0);
    assert(!latcd_retirement_queue_take(diagnostic, UINT64_MAX, &diagnostic_attempt));
    latcd_retirement_queue_free(diagnostic);
    diagnostic = latcd_retirement_queue_new(root, 0);
    char *other_boot = g_uuid_string_random();
    assert(!latcd_retirement_queue_diagnostic_round(diagnostic, other_boot, cutoff, NULL));
    assert(latcd_retirement_queue_step(diagnostic, 32, 10000, &diagnostic_stats,
                                      error, sizeof(error)) < 0);
    assert(latcd_retirement_queue_aggregated_page(diagnostic, &second_page) < 0);
    g_free(other_boot);
    latcd_retirement_queue_free(diagnostic);
    assert(!unlink(duplicate_path));
    g_free(duplicate_path);
    LatcdRetirementQueue *queue = latcd_retirement_queue_new(root, 0);
    LatcdRetirementQueueStats stats;
    int result;
    unsigned visited = 0;
    do {
        result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error));
        visited += stats.visited;
    }
    while (result > 0);
    assert(visited >= 88); /* Both passes must visit all 44 records. */
    assert(latcd_retirement_queue_discovered_keys(queue) == 128);
    LatcdRetirementPageState page_state;
    assert(latcd_retirement_queue_page_plan(queue, NULL, &page_state) == 1);
    assert(page_state.count == 128);
    LatcdRetirementPageState aggregated;
    assert(!latcd_retirement_queue_aggregated_page(queue, &aggregated));
    assert(aggregated.count == page_state.count);
    for (unsigned i = 0; i < aggregated.count; i++) {
        assert(!strcmp(aggregated.entries[i].name, page_state.entries[i].name));
        assert(aggregated.entries[i].deadline && aggregated.entries[i].enqueued);
    }
    char first_cursor[138];
    g_strlcpy(first_cursor, page_state.cursor, sizeof(first_cursor));
    assert(latcd_retirement_queue_page_plan(queue, first_cursor, &page_state) == 0);
    assert(result < 0 && !stats.complete && !stats.candidates);
    LatcdRetirementAttempt attempt;
    assert(!latcd_retirement_queue_take(queue, UINT64_MAX, &attempt));
    directory = g_dir_open(store, 0, NULL);
    assert(directory);
    GPtrArray *records = g_ptr_array_new_with_free_func(g_free);
    const char *entry;
    while ((entry = g_dir_read_name(directory))) g_ptr_array_add(records, g_strdup(entry));
    g_dir_close(directory);
    assert(records->len == 44);
    for (guint i = 0; i + 1 < records->len; i++) {
        char *path = g_build_filename(store, g_ptr_array_index(records, i), NULL);
        assert(!unlink(path));
        g_free(path);
    }
    do { result = latcd_retirement_queue_step(queue, 32, 10000, &stats, error, sizeof(error)); }
    while (result > 0);
    assert(!result && stats.complete && stats.candidates == 3);
    assert(latcd_retirement_queue_discovered_keys(queue) == 0);
    g_ptr_array_unref(records); g_free(store);
    latcd_retirement_queue_free(queue);
    remove_root(root); g_free(root);
    simulated_boottime_us = 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && (!strcmp(argv[1], "build-id") || !strcmp(argv[1], "--latc-build-id"))) {
        puts(LATC_BUILD_ID);
        return 0;
    }
    if (argc == 3 && (!strcmp(argv[1], "--timer-fixture") ||
                      !strcmp(argv[1], "--aged-timer-fixture"))) {
        if (!strcmp(argv[1], "--aged-timer-fixture")) simulated_boottime_us = 1;
        publish_page_fixture(argv[2], 7);
        simulated_boottime_us = 0;
        char digest[65], error[256];
        snprintf(digest, sizeof(digest), "%064x", 7);
        int fd = lat_aot_v2_cache_source_lock(argv[2], digest, LOCK_SH | LOCK_NB,
                                                false, error, sizeof(error));
        assert(fd >= 0); close(fd);
        return 0;
    }
    if (argc == 3 && (!strcmp(argv[1], "--startup-retry-fixture") ||
                      !strcmp(argv[1], "--startup-retry-intent") ||
                      !strcmp(argv[1], "--startup-retry-applied"))) {
        unsigned phase = !strcmp(argv[1], "--startup-retry-applied") ? 2 :
                         !strcmp(argv[1], "--startup-retry-intent") ? 1 : 0;
        make_startup_retry_fixture(argv[2], phase);
        return 0;
    }
    if (argc == 5 && !strcmp(argv[1], "--loader-pin-probe")) {
        const char *root = argv[2], *digest = argv[3], *name = argv[4];
        char error[256] = {0};
        const char *names[] = {name};
        char *evidence = latcd_retirement_capture_objects(root, digest, names, 1);
        char *path = g_build_filename(root, name, NULL);
        char *owner_path = g_build_filename(root, ".latcd.lock", NULL);
        int owner = open(owner_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        int latch = lat_aot_v2_cache_source_lock_existing(root, digest, LOCK_EX | LOCK_NB,
                                                            false, error, sizeof(error));
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (owner < 0 || flock(owner, LOCK_EX | LOCK_NB) || latch < 0 || !evidence || fd < 0)
            return 3;
        errno = 0;
        int result =
            latcd_retirement_tombstone(root, digest, name, fd, evidence, error, sizeof(error));
        int saved = errno;
        if (fd >= 0) close(fd);
        if (latch >= 0) close(latch);
        g_free(evidence); g_free(path); g_free(owner_path);
        if (result) {
            fprintf(stderr, "intent rejected: %s errno=%d\n", error, saved);
            close(owner);
            return saved == EWOULDBLOCK ? 1 : 3;
        }
        LatcdRetirementDeletionReport report;
        if (latcd_tombstone_delete_report(root, name, &report, error, sizeof(error)) ||
            !report.object_unlinked || !report.namespace_durable || !report.receipt_durable) {
            fprintf(stderr, "deletion incomplete: %s\n", error);
            close(owner);
            return 2;
        }
        close(owner);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--space-root")) {
        test_deletion_report(argv[2], true);
        puts("test-cache-retirement: isolated-space PASS");
        return 0;
    }
    assert(argc == 1);
    test_startup_partial_records();
    test_queue_empty_store();
    test_oversized_prepared();
    test_round_cursor();
    test_empty_round_advance();
    test_empty_round_advance_crash("file-synced");
    test_empty_round_advance_crash("renamed");
    test_empty_round_advance_crash("directory-synced");
    test_retry_page_stage(false);
    test_retry_page_stage(true);
    test_retry_page_stage_crash("file-synced");
    test_retry_page_stage_crash("linked");
    test_retry_page_stage_crash("renamed");
    test_retry_page_stage_crash("directory-synced");
    test_unmatched_retry_advance_crash("file-synced");
    test_unmatched_retry_advance_crash("renamed");
    test_unmatched_retry_advance_crash("directory-synced");
    test_page_round_begin(NULL, false);
    test_page_identity();
    test_schedule_result_upgrade();
    test_schedule_check_page();
    test_page_stage();
    test_deferred_page_recovery(false);
    test_deferred_page_recovery(true);
    test_budgeted_page_stage();
    test_budgeted_max_page(0);
    test_budgeted_max_page(1);
    test_budgeted_max_page(2);
    test_budgeted_max_page(3);
    test_budgeted_max_page(4);
    test_budgeted_max_page(5);
    test_budgeted_rebind();
    test_rebind_crash("file-synced", false, false);
    test_rebind_crash("linked", false, true);
    test_rebind_crash("renamed", true, false);
    test_rebind_crash("directory-synced", true, false);
    test_deferred_finish_crash("file-synced", false, false);
    test_deferred_finish_crash("linked", false, true);
    test_deferred_finish_crash("renamed", true, false);
    test_deferred_finish_crash("directory-synced", true, false);
    test_budgeted_crash("file-synced", false, false, false);
    test_budgeted_crash("linked", false, false, false);
    test_budgeted_crash("renamed", true, false, false);
    test_budgeted_crash("directory-synced", true, false, false);
    test_budgeted_crash("file-synced", false, true, false);
    test_budgeted_crash("renamed", true, true, false);
    test_budgeted_crash("directory-synced", true, true, false);
    test_budgeted_crash("file-synced", false, false, true);
    test_budgeted_crash("renamed", true, false, true);
    test_budgeted_crash("directory-synced", true, false, true);
    test_schedule_store();
    test_retry_page_identity();
    test_retry_select();
    test_schedule_max_record();
    test_schedule_merge_multiple();
    test_schedule_count_limit();
    test_schedule_byte_limit();
    test_schedule_growth_limit();
    test_schedule_capacity();
    test_schedule_crash(false, false);
    test_schedule_crash(true, false);
    test_schedule_crash(false, true);
    test_schedule_crash(true, true);
    test_recovery_round_barrier();
    test_recovery_lock_directory_swap();
    test_round_directory_swap(false);
    test_round_directory_swap(true);
    const char *page_faults[] = {"created", "partial-write", "file-synced",
                                 "renamed", "directory-synced"};
    for (unsigned i = 0; i < G_N_ELEMENTS(page_faults); i++) {
        test_page_round_begin(page_faults[i], false);
        test_page_round_begin(page_faults[i], true);
        test_page_state_write_fault(page_faults[i], false);
        test_page_state_write_fault(page_faults[i], true);
    }
    test_queue_overflow_fixture();
    test_retry_not_due(false);
    test_retry_not_due(true);
    test_page_discovery_witness();
    test_page_execution_restriction();
    test_page_receipt_witness(0);
    test_page_receipt_witness(1);
    test_page_receipt_witness(2);
    test_page_receipt_witness(3);
    test_retry_multiple_receipts(0);
    test_retry_multiple_receipts(1);
    test_retry_multiple_receipts(2);
    test_retry_multiple_receipts(3);
    test_page_round_insertions();
    test_deletion_report(NULL, false);
    test_roots_latch();
    test_recovery_directory_binding(false);
    test_recovery_directory_binding(true);
    test_delete_lock_domain_swap();
    test_publication_directory_binding(false, false);
    test_publication_directory_binding(true, false);
    test_publication_directory_binding(false, true);
    test_publication_directory_binding(true, true);
    for (unsigned mutation = 0; mutation < 6; mutation++) {
        test_other_current(mutation, false);
        test_other_current(mutation, true);
    }
    test_bound_new_hold_directory();
    test_explicit_holds();
    test_due_without_retirement();
    for (unsigned mutation = 0; mutation < 16; mutation++) {
        test_transaction_root_admission(mutation, false);
        test_transaction_root_admission(mutation, true);
    }
    for (unsigned copying = 0; copying < 2; copying++) {
        test_task_root_admission(copying, false);
        test_task_root_admission(copying, true);
    }
    test_unknown_task_release(false, false);
    test_unknown_task_release(true, false);
    test_unknown_task_release(false, true);
    test_unknown_task_release(true, true);
    const char *hold_points[] = {"created", "written", "file-synced", "renamed", "directory-synced"};
    for (unsigned i = 0; i < G_N_ELEMENTS(hold_points); i++) {
        test_hold_crash(false, hold_points[i]);
        test_hold_crash(true, hold_points[i]);
    }
    for (int phase = 0; phase < 3; phase++) {
        test_crash(phase, false);
        test_crash(phase, true);
    }
    for (int outcome = 0; outcome < 3; outcome++)
        test_recovery_capacity_admission(outcome);
    test_metadata_target_revalidation(false);
    test_metadata_target_revalidation(true);
    test_unknown_and_corrupt();
    test_reboot();
    for (unsigned replace = 0; replace < 2; replace++)
        for (unsigned execute = 0; execute < 2; execute++)
            test_queue_root_replacement(replace, execute);
    for (unsigned mutation = 0; mutation < 8; mutation++) test_queue_consumer(mutation, false);
    for (unsigned mutation = 0; mutation < 18; mutation++) test_queue_consumer(mutation, true);
    test_queue_consumer(18, true);
    test_queue_consumer(19, true);
    test_queue_consumer(20, true);
    test_queue_consumer(21, true);
    test_queue_consumer(22, true);
    test_queue_consumer(23, true);
    test_queue_consumer(24, true);
    test_queue_consumer(25, true);
    test_queue_consumer(26, true);
    test_queue_consumer(27, true);
    for (unsigned phase = 0; phase < 3; phase++)
        for (unsigned fault = 1; fault <= 8; fault++) test_clock_failure(phase, fault);
    for (int mutation = 0; mutation < 7; mutation++) test_object_identity(mutation);
    test_legacy_and_schema();
    test_recovery_entry_budget();
    for (int mutation = 0; mutation < 4; mutation++) {
        test_recovery_cursor(mutation, false);
        test_recovery_cursor(mutation, true);
    }
    for (int mutation = 0; mutation < 25; mutation++)
        test_deleted_transaction_recovery(mutation, NULL, false);
    test_manifest_binding();
    test_tombstone();
    test_cache_domain();
    test_mount_lease_crash_persistence();
    test_mount_lease_registration_lock();
    test_tombstone_capacity_admission(false);
    test_tombstone_capacity_admission(true);
    for (int mutation = 0; mutation < 11; mutation++) test_tombstone_recovery(mutation);
    const char *points[] = {"created", "partial-write", "written", "chmod",
        "file-synced", "closed", "renamed", "directory-synced"};
    for (size_t i = 0; i < G_N_ELEMENTS(points); i++)
        for (int crash = 0; crash < 2; crash++)
            test_deleted_transaction_recovery(15, points[i], crash);
    for (int crash = 0; crash < 2; crash++)
        test_deleted_transaction_recovery(15, "missing-synced", crash);
    for (size_t i = 0; i < G_N_ELEMENTS(points); i++)
        for (int crash = 0; crash < 2; crash++)
            for (int finishing = 0; finishing < 2; finishing++)
                for (int initial = 0; initial < 2; initial++)
                    test_record_write_fault(points[i], crash, finishing, initial);
    for (size_t i = 0; i < G_N_ELEMENTS(points); i++)
        for (int crash = 0; crash < 2; crash++)
            test_tombstone_crash(points[i], crash);
    for (size_t i = 0; i < G_N_ELEMENTS(points); i++)
        for (int crash = 0; crash < 2; crash++)
            for (int missing = 0; missing < 2; missing++)
                test_tombstone_recovery_crash(points[i], crash, missing);
    for (int mutation = 0; mutation < 11; mutation++) test_tombstone_delete(NULL, false, mutation);
    test_partial_generation_delete();
    const char *unlink_points[] = {"before-unlink", "unlinked", "unlink-synced",
        "created", "partial-write", "written", "chmod", "file-synced", "closed",
        "renamed", "directory-synced"};
    for (size_t i = 0; i < G_N_ELEMENTS(unlink_points); i++)
        for (int crash = 0; crash < 2; crash++)
            test_tombstone_delete(unlink_points[i], crash, 0);
    puts("test-cache-retirement: PASS");
    return 0;
}
