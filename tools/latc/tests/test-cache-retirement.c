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
static int64_t monotonic_tick;
static uint64_t simulated_boottime_us;
static const char *clock_swap_path, *clock_swap_old;
static const char *lock_swap_root, *lock_swap_old, *lock_swap_new;
static bool lock_swap_after;
static const char *lock_wrong_root;
static const char *schedule_scan_mutation;
static const char *schedule_mutation_file;
static const char *snapshot_swap_store, *snapshot_swap_gc, *snapshot_swap_old;
static const char *roots_swap_path, *roots_swap_old;
static const char *page_lstat_swap_path, *page_lstat_swap_old, *page_lstat_swap_new;
static const char *scheduler_swap_root, *scheduler_swap_gc, *scheduler_swap_old;
static bool scheduler_swap_after_binding;
static const char *settlement_unexpected;
static const char *settlement_target, *settlement_saved;
static void replace_settlement_target(void)
{
    assert(!rename(settlement_target, settlement_saved));
    int fd = open(settlement_target, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
    assert(fd >= 0 && write(fd, "x", 1) == 1 && !close(fd));
    latcd_retirement_test_before_settlement = NULL;
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
    assert(latcd_retirement_schedule_store_page_result(root, 150, &page, &page.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(!page_lstat_swap_path);
    char *new_record = g_build_filename(root, ".gc", "retirement-schedule", filename, NULL);
    char *old_record = g_build_filename(old_root, ".gc", "retirement-schedule", filename, NULL);
    assert(access(new_record, F_OK) && access(old_record, F_OK));
    assert(!rename(root, replacement) && !rename(old_root, root));
    remove_root(replacement);
    g_free(old_record); g_free(new_record); g_free(filename); g_free(old_root);
    g_free(replacement_store); g_free(replacement_gc); g_free(replacement);
    assert(latcd_retirement_schedule_store_page_result(root, 150, &page, &page.entries[0],
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
    assert(latcd_retirement_page_budget_result(root, 150, budget_binding, &page_budget,
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
    assert(latcd_retirement_page_snapshot(root, 150, &snapshot_page, results, &inventory, error, sizeof(error)) < 0);
    assert(!snapshot_swap_store && !snapshot_page.count && !results[0]);
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
    assert(latcd_retirement_schedule_store_page_result(root, 150, &page, &page.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(latcd_retirement_schedule_store(root, boot, 100, 150, 1, &page.entries[0],
                                           error, sizeof(error)) < 0);
    assert(latcd_retirement_schedule_store_result(root, boot, 100, 150, 1, &page.entries[0],
            identity, LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    close(scheduler);
    LatcdRetirementPageState changed = page;
    changed.entries[0].deadline++;
    assert(latcd_retirement_schedule_store_page_result(root, 150, &changed, &changed.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    changed = page;
    changed.sequence++;
    assert(latcd_retirement_schedule_store_page_result(root, 150, &changed, &changed.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    changed = page;
    changed.entries[0].enqueued++;
    assert(latcd_retirement_schedule_store_page_result(root, 150, &changed, &changed.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    changed = page;
    changed.entries[1].enqueued++;
    assert(latcd_retirement_schedule_store_page_result(root, 150, &changed, &changed.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    LatcdRetirementPageDeadline outsider = page.entries[0];
    outsider.deadline++;
    assert(latcd_retirement_schedule_store_page_result(root, 150, &page, &outsider,
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    snprintf(outsider.name, sizeof(outsider.name), "%064x.so", 3);
    assert(latcd_retirement_schedule_store_page_result(root, 150, &page, &outsider,
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(!latcd_retirement_schedule_store_page_result(root, 150, &page, &page.entries[0],
            LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)));
    assert(latcd_retirement_schedule_check_page(root, 150, &page, error, sizeof(error)) == 1);
    assert(latcd_retirement_schedule_page_results(root, 150, &page, results, error, sizeof(error)) == 1);
    assert(results[0] == LATCD_RETIREMENT_RESULT_DONE && !results[1]);
    assert(latcd_retirement_page_snapshot(root, 150, &snapshot_page, results, &inventory, error, sizeof(error)) == 1);
    assert(results[0] == LATCD_RETIREMENT_RESULT_DONE && !results[1]);
    assert(inventory.occupied_slots == 1 && inventory.occupied_bytes == 1024 && !inventory.undersized_member);
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
    assert(!latcd_retirement_schedule_store_page_result(root, 150, &page, &deferred,
            LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
    assert(!latcd_retirement_schedule_check_page(root, 150, &page, error, sizeof(error)));
    assert(!latcd_retirement_schedule_page_results(root, 150, &page, results, error, sizeof(error)));
    assert(results[0] == LATCD_RETIREMENT_RESULT_DONE && results[1] == LATCD_RETIREMENT_RESULT_DEFERRED);
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
    assert(latcd_retirement_schedule_store_page_result(root, 150, &page, &page.entries[0],
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
    assert(latcd_retirement_schedule_store_page_result(root, 150, &page, &page.entries[0],
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
    assert(latcd_retirement_schedule_store_page_result(root, 150, &page, &page.entries[0],
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
    LatcdRetirementPageState page = empty, loaded;
    page.count = 1;
    snprintf(page.entries[0].name, sizeof(page.entries[0].name), "%064x.so", 1);
    page.entries[0].deadline = 140;
    page.entries[0].enqueued = 100;
    g_strlcpy(page.cursor, page.entries[0].name, sizeof(page.cursor));
    assert(!latcd_retirement_page_state_store(root, &empty, error, sizeof(error)));
    simulated_boottime_us = 150;
    LatcdCacheCapacity capacity = LATCD_CACHE_CAPACITY_INIT;
    LatcdPageBudget budget = {0};
    assert(!latcd_cache_capacity_scan(&capacity, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&capacity, UINT64_MAX);
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
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) && loaded.budget_bound);
    assert(latcd_retirement_page_startup_check(root, error, sizeof(error)) < 0);
    assert(latcd_retirement_schedule_store_page_result(root, 150, &page, &page.entries[0],
           LATCD_RETIREMENT_RESULT_DONE, error, sizeof(error)) < 0);
    assert(latcd_retirement_page_commit(root, 150, &page, error, sizeof(error)) < 0);
    uint8_t binding[32];
    assert(!latcd_retirement_page_budget_identity(&page, binding));
    assert(!latcd_retirement_page_budget_result(root, 150, binding, &budget, &page.entries[0],
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
    assert(!budget.capacity && !loaded.count && recovered.recovery_gate && recovered.ready);
    assert(!latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, 100, &budget,
                                                  &loaded, error, sizeof(error)));
    assert(loaded.budget_bound && loaded.count == 1 && budget.capacity == &recovered &&
           budget.remaining == 2 * 65536);
    assert(latcd_cache_capacity_reserve(&recovered, 1, UINT64_MAX, error, sizeof(error)) < 0);
    assert(!latcd_cache_capacity_recovery_finish(&recovered));
    assert(!latcd_retirement_page_budget_commit(root, 150, &page, &budget, error, sizeof(error)));
    assert(!latcd_cache_capacity_test_page_release(&recovered, &budget));
    latcd_cache_capacity_close(&recovered);
    assert(!pthread_mutex_destroy(&recovered.lock));
    char *checkpoint = g_build_filename(gc, "retirement-page.ini", NULL);
    char *checkpoint_data = NULL;
    assert(g_file_get_contents(checkpoint, &checkpoint_data, NULL, NULL));
    for (unsigned variant = 0; variant < 4; variant++) {
        GKeyFile *altered = g_key_file_new();
        assert(g_key_file_load_from_data(altered, checkpoint_data, -1, 0, NULL));
        const char *field[] = {"result", "last_attempt", "retry_at", "busy_count"};
        g_key_file_set_uint64(altered, "entry0", field[variant], variant == 0 ? 2 : 1);
        char *raw = g_key_file_to_data(altered, NULL, NULL);
        put(checkpoint, raw);
        assert(latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) < 0);
        g_free(raw);
        g_key_file_unref(altered);
    }
    put(checkpoint, checkpoint_data);
    assert(!latcd_retirement_page_state_load(root, &loaded, error, sizeof(error)) &&
           loaded.committed_pending);
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
        assert(!budget.capacity && recovered.recovery_gate);
    }
    latcd_cache_capacity_close(&recovered);
    assert(!pthread_mutex_destroy(&recovered.lock));
    simulated_boottime_us = 0;
    g_free(boot); g_free(store); g_free(gc); remove_root(root); g_free(root);
}

static void test_budgeted_max_page(void)
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
        assert(!latcd_retirement_page_budget_result(root, UINT64_MAX, binding, &budget,
            &page.entries[i], LATCD_RETIREMENT_RESULT_DEFERRED, error, sizeof(error)));
    assert(!latcd_retirement_page_budget_commit(root, UINT64_MAX, &page, &budget, error, sizeof(error)));
    char *checkpoint = g_build_filename(gc, "retirement-page.ini", NULL);
    assert(!stat(checkpoint, &st) && st.st_size > 0 && st.st_size <= 65536);
    assert(!latcd_cache_capacity_test_page_release(&capacity, &budget));
    latcd_cache_capacity_close(&capacity);
    assert(!pthread_mutex_destroy(&capacity.lock));
    LatcdCacheCapacity recovered = LATCD_CACHE_CAPACITY_INIT;
    assert(!latcd_cache_capacity_scan(&recovered, root, error, sizeof(error)));
    latcd_cache_capacity_metadata_bind(&recovered, UINT64_MAX);
    assert(!latcd_cache_capacity_recovery_begin(&recovered));
    assert(!latcd_retirement_page_restore_budget(root, &recovered, UINT64_MAX, UINT64_MAX,
                                                 &budget, &loaded, error, sizeof(error)));
    assert(loaded.committed_pending && loaded.count == 128 && budget.remaining == 2 * 65536);
    assert(!latcd_cache_capacity_recovery_finish(&recovered));
    assert(!latcd_cache_capacity_test_page_release(&recovered, &budget));
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
    assert(latcd_retirement_schedule_store_page_result(root, 150, &page, &page.entries[0],
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
    if (mutation == 3) put(current, "invalid manifest\n");
    if (mutation == 4) {
        char *manifest = g_strdup_printf("{\"version\":2,\"module\":\"%s.so\","
            "\"native\":\"%s\",\"tbset\":\"\",\"source_sha256\":\"%s\","
            "\"codegen_id\":\"%s\",\"published_sequence\":1}", source, name, source, source);
        put(current, manifest); g_free(manifest);
    }
    if (mutation == 5) {
        fd = lat_aot_v2_cache_source_lock(root, source, LOCK_SH, false, error, sizeof(error));
        assert(fd >= 0);
    }
    if (mutation == 6) assert(!unlink(path));
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
    if (rejected || (point && !strcmp(point, "before-unlink"))) assert(!access(path, F_OK));
    else assert(access(path, F_OK));
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
        if (!i && (mutation == 18 || mutation == 19)) {
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
                        mutation == 18 || mutation == 19 || mutation == 20;
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
    const char *names[] = {"transactions", "tombstones"};
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
    assert(latcd_tombstone_delete_due(root, name, 0, error, sizeof(error)) != 0);
    assert(!access(path, F_OK));
    assert(!latcd_retirement_mount_release(root, lease_id, lease, error, sizeof(error)));
    close(lease);
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
    int release_latch = latcd_retirement_roots_lock(
        root, LOCK_SH | LOCK_NB, error, sizeof(error));
    assert(release_latch >= 0);
    assert(!latcd_retirement_mount_release(
        root, lease_id, release_latch, error, sizeof(error)));
    close(release_latch);
    assert(!latcd_tombstone_delete(root, name, error, sizeof(error)));
    assert(access(path, F_OK) != 0);
    g_free(lease_id); g_free(evidence); g_free(path); g_free(name);
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
            assert(latcd_tombstone_delete_report(root, name, &report, error, sizeof(error)) < 0);
            assert(!report.object_unlinked && !report.unlinked_allocated_bytes && !access(path, F_OK));
            assert(((char *)mapping)[length - 1] == 'x');
            assert(!munmap(mapping, length));
            close(fd);
        }
        if (mode == 2) assert(!setenv("LATCD_TEST_RETIREMENT_IO", "error:unlinked", 1));
        int result = latcd_tombstone_delete_report(root, name, &report, error, sizeof(error));
        unsetenv("LATCD_TEST_RETIREMENT_IO");
        assert((result == 0) == (mode != 2));
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
    const char *original_name = g_dir_read_name(directory);
    assert(original_name);
    char *original_path = g_build_filename(store, original_name, NULL);
    GKeyFile *duplicate = g_key_file_new();
    assert(g_key_file_load_from_file(duplicate, original_path, 0, NULL));
    g_key_file_set_uint64(duplicate, "transaction", "retired_boottime_us", 201);
    char *duplicate_data = g_key_file_to_data(duplicate, NULL, NULL);
    char *duplicate_id = g_uuid_string_random();
    char *duplicate_name = g_strconcat(duplicate_id, ".ini", NULL);
    char *duplicate_path = g_build_filename(store, duplicate_name, NULL);
    g_free(duplicate_id); g_free(duplicate_name);
    put(duplicate_path, duplicate_data);
    g_free(duplicate_data); g_key_file_unref(duplicate);
    g_dir_close(directory); g_free(original_path);
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
        int stored = latcd_retirement_schedule_store_page_result(root, 201, &first_page,
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
    test_page_round_begin(NULL, false);
    test_page_identity();
    test_schedule_result_upgrade();
    test_schedule_check_page();
    test_page_stage();
    test_budgeted_page_stage();
    test_budgeted_max_page();
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
    for (unsigned phase = 0; phase < 3; phase++)
        for (unsigned fault = 1; fault <= 8; fault++) test_clock_failure(phase, fault);
    for (int mutation = 0; mutation < 7; mutation++) test_object_identity(mutation);
    test_legacy_and_schema();
    test_recovery_entry_budget();
    for (int mutation = 0; mutation < 4; mutation++) {
        test_recovery_cursor(mutation, false);
        test_recovery_cursor(mutation, true);
    }
    for (int mutation = 0; mutation < 24; mutation++)
        test_deleted_transaction_recovery(mutation, NULL, false);
    test_manifest_binding();
    test_tombstone();
    test_cache_domain();
    test_mount_lease_crash_persistence();
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
    for (int mutation = 0; mutation < 9; mutation++) test_tombstone_delete(NULL, false, mutation);
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
