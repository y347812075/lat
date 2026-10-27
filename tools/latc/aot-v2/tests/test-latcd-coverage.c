#define dlopen coverage_dlopen
#define dlsym coverage_dlsym
#define dlclose coverage_dlclose
#define rename coverage_rename
#define pread coverage_pread
#define write coverage_write
#define fchmod coverage_fchmod
#define fsync coverage_fsync
#define linkat coverage_linkat
#define unlinkat coverage_unlinkat
#define main latcd_program_main
#include "../../latcd/main.c"
#undef main
#undef dlopen
#undef dlsym
#undef dlclose
#undef rename
#undef pread
#undef write
#undef fchmod
#undef fsync
#undef linkat
#undef unlinkat
#include <glib/gstdio.h>

extern ssize_t write(int fd, const void *buffer, size_t count);
extern int fchmod(int fd, mode_t mode);
extern int fsync(int fd);
extern int linkat(int olddir, const char *oldname, int newdir,
                  const char *newname, int flags);
extern int unlinkat(int directory, const char *name, int flags);

enum RecordBoundary {
    RECORD_NONE, RECORD_WRITE, RECORD_MODE, RECORD_FILE_SYNC,
    RECORD_LINK, RECORD_UNLINK, RECORD_DIRECTORY_SYNC
};
static enum RecordBoundary record_boundary;
static bool record_crash;
static unsigned record_hits, record_write_retries;

static bool record_fault(enum RecordBoundary boundary, bool after)
{
    if (record_boundary != boundary || after != record_crash) return false;
    record_boundary = RECORD_NONE; /* Cleanup must use the real syscall. */
    record_hits++;
    if (record_crash) {
        kill(getpid(), SIGKILL);
        _exit(99);
    }
    errno = EIO;
    return true;
}

ssize_t coverage_write(int fd, const void *buffer, size_t count)
{
    if (record_write_retries == 2) {
        record_write_retries--;
        errno = EINTR;
        return -1;
    }
    if (record_write_retries == 1) {
        record_write_retries--;
        count = 1;
    }
    if (record_fault(RECORD_WRITE, false)) return -1;
    ssize_t result = write(fd, buffer, count);
    if (result > 0) record_fault(RECORD_WRITE, true);
    return result;
}

int coverage_fchmod(int fd, mode_t mode)
{
    if (record_fault(RECORD_MODE, false)) return -1;
    int result = fchmod(fd, mode);
    if (!result) record_fault(RECORD_MODE, true);
    return result;
}

int coverage_fsync(int fd)
{
    struct stat status;
    g_assert_cmpint(fstat(fd, &status), ==, 0);
    enum RecordBoundary boundary = S_ISDIR(status.st_mode) ?
        RECORD_DIRECTORY_SYNC : RECORD_FILE_SYNC;
    if (record_fault(boundary, false)) return -1;
    int result = fsync(fd);
    if (!result) record_fault(boundary, true);
    return result;
}

int coverage_linkat(int olddir, const char *oldname, int newdir,
                    const char *newname, int flags)
{
    if (record_fault(RECORD_LINK, false)) return -1;
    int result = linkat(olddir, oldname, newdir, newname, flags);
    if (!result) record_fault(RECORD_LINK, true);
    return result;
}

int coverage_unlinkat(int directory, const char *name, int flags)
{
    if (record_fault(RECORD_UNLINK, false)) return -1;
    int result = unlinkat(directory, name, flags);
    if (!result) record_fault(RECORD_UNLINK, true);
    return result;
}

extern ssize_t pread(int fd, void *buffer, size_t count, off_t offset);
static void (*read_hook)(int fd);
static const char *hook_read_path;
ssize_t coverage_pread(int fd, void *buffer, size_t count, off_t offset)
{
    struct stat file, selected;
    if (read_hook && hook_read_path && !fstat(fd, &file) &&
        !stat(hook_read_path, &selected) && file.st_dev == selected.st_dev &&
        file.st_ino == selected.st_ino) {
        void (*hook)(int) = read_hook;
        read_hook = NULL;
        hook(fd);
    }
    return pread(fd, buffer, count, offset);
}

static const char *hook_path;
static const char *hook_contents;
static bool hook_mutate;
static void assert_unlocked_read(int fd)
{
    (void)fd;
    g_assert_cmpint(pthread_mutex_trylock(&cache_lock), ==, 0);
    pthread_mutex_unlock(&cache_lock);
}
static const char *baseline_paths[2];
static const LatcdConfig *baseline_config;
static const char *baseline_hex;
static void assert_baseline_handoff(int fd)
{
    assert_unlocked_read(fd);
    for (unsigned i = 0; i < 2; i++) {
        int contender = open(baseline_paths[i], O_RDONLY | O_CLOEXEC);
        g_assert_cmpint(contender, >=, 0);
        g_assert_cmpint(flock(contender, LOCK_EX | LOCK_NB), ==, -1);
        g_assert_cmpint(errno, ==, EWOULDBLOCK);
        close(contender);
    }
    char error[128];
    int source = lat_aot_v2_cache_source_lock(baseline_config->cache_dir,
        baseline_hex, LOCK_EX | LOCK_NB, false, error, sizeof(error));
    g_assert_cmpint(source, >=, 0); /* S is released for the long copy phase. */
    close(source);
}
static void replace_during_read(int fd)
{
    struct stat status;
    g_assert_cmpint(pthread_mutex_trylock(&cache_lock), ==, 0);
    int contender = open(hook_read_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    g_assert_cmpint(contender, >=, 0);
    errno = 0;
    g_assert_cmpint(flock(contender, LOCK_EX | LOCK_NB), ==, -1);
    g_assert_cmpint(errno, ==, EWOULDBLOCK);
    close(contender);
    g_assert_cmpint(fstat(fd, &status), ==, 0);
    g_assert_cmpuint(status.st_nlink, ==, 1);
    if (hook_mutate) {
        g_assert_cmpint(g_chmod(hook_path, 0600), ==, 0);
        int output = open(hook_path, O_WRONLY);
        g_assert_cmpint(output, >=, 0);
        g_assert_cmpint(pwrite(output, "X", 1, 0), ==, 1);
        close(output);
    } else {
        g_assert_cmpint(g_unlink(hook_path), ==, 0);
        g_assert_true(g_file_set_contents(hook_path, hook_contents, -1, NULL));
    }
    pthread_mutex_unlock(&cache_lock);
}

static void test_pinned_cache_copy(const char *directory)
{
    char *path = g_build_filename(directory, "pinned-native", NULL);
    char error[256];
    char *snapshot = NULL;
    g_assert_true(g_file_set_contents(path, "original", 8, NULL));
    g_assert_cmpint(g_chmod(path, 0444), ==, 0);
    hook_path = path;
    hook_read_path = path;
    hook_contents = "replacement";
    hook_mutate = false;
    read_hook = replace_during_read;
    int pinned = open_cached_file(path, 4096, error, sizeof(error));
    int snapshot_pin = -1;
    g_assert_cmpint(pinned, >=, 0);
    g_assert_cmpint(snapshot_cached_fd(pinned, directory, &snapshot, &snapshot_pin, NULL,
        error, sizeof(error)), ==, 0);
    close(pinned);
    close(snapshot_pin);
    gchar *bytes = NULL;
    gsize size;
    g_assert_true(g_file_get_contents(snapshot, &bytes, &size, NULL));
    g_assert_cmpmem(bytes, size, "original", 8);
    g_free(bytes);
    g_unlink(snapshot);
    g_clear_pointer(&snapshot, g_free);
    g_assert_cmpint(g_chmod(path, 0444), ==, 0);
    hook_mutate = true;
    read_hook = replace_during_read;
    pinned = open_cached_file(path, 4096, error, sizeof(error));
    g_assert_cmpint(pinned, >=, 0);
    g_assert_cmpint(snapshot_cached_fd(pinned, directory, &snapshot, &snapshot_pin, NULL,
        error, sizeof(error)), ==, -1);
    close(pinned);
    g_assert_null(snapshot);
    g_assert_nonnull(strstr(error, "changed while copying"));
    g_unlink(path);
    g_free(path);
}

static bool crash_after_manifest;
extern int rename(const char *from, const char *to);
int coverage_rename(const char *from, const char *to)
{
    int result = rename(from, to);
    if (!result && crash_after_manifest && g_str_has_suffix(to, ".current")) {
        _exit(88);
    }
    return result;
}

static uint32_t coverage_abi(void) { return LAT_AOT_V2_ABI_VERSION; }
static const char *coverage_id(void) { return LATC_BUILD_ID; }
void *coverage_dlopen(const char *path, int flags)
{
    (void)path;
    (void)flags;
    return (void *)1;
}
void *coverage_dlsym(void *handle, const char *name)
{
    (void)handle;
    return !strcmp(name, "lat_aot_runtime_abi_version") ?
        (void *)coverage_abi : (void *)coverage_id;
}
int coverage_dlclose(void *handle) { (void)handle; return 0; }
#define main module_coverage_fixture_main
#include "test-module-coverage.c"
#undef main

static void daemon_fixture(const char *path, const LatAotTbV2 *keys, size_t count)
{
    write_module(path, keys, count, 0);
    gchar *data = NULL;
    gsize size = 0;
    g_assert_true(g_file_get_contents(path, &data, &size, NULL));
    LatAotNoteV2 *note = (void *)(data + LAT_AOT_TEST_NOTE_OFFSET + 16);
    expected_codegen_id(note->codegen_id);
    g_assert_true(g_file_set_contents(path, data, size, NULL));
    g_assert_cmpint(g_chmod(path, 0444), ==, 0);
    g_free(data);
}

static void remove_fixture_tree(const char *path)
{
    GDir *directory = g_dir_open(path, 0, NULL);
    g_assert_nonnull(directory);
    const char *name;
    while ((name = g_dir_read_name(directory))) {
        char *child = g_build_filename(path, name, NULL);
        if (g_file_test(child, G_FILE_TEST_IS_DIR)) remove_fixture_tree(child);
        else g_assert_cmpint(g_unlink(child), ==, 0);
        g_free(child);
    }
    g_dir_close(directory);
    g_assert_cmpint(g_rmdir(path), ==, 0);
}

static const LatcdConfig *cleanup_config;
static const char *cleanup_names[6];
static char cleanup_hex[65];
static const LatAotModuleInfoV2 *cleanup_info;
static void publish_during_digest(int fd)
{
    (void)fd;
    char error[256];
    g_assert_cmpint(pthread_mutex_trylock(&cache_lock), ==, 0);
    int contender = open(hook_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    g_assert_cmpint(contender, >=, 0);
    errno = 0;
    g_assert_cmpint(flock(contender, LOCK_EX | LOCK_NB), ==, -1);
    g_assert_cmpint(errno, ==, EWOULDBLOCK);
    close(contender);
    g_assert_cmpint(publish_current_index(cleanup_config, cleanup_hex,
        cleanup_names[0], cleanup_names[1], cleanup_names[2], cleanup_info,
        5, true, error, sizeof(error)), ==, 0);
    pthread_mutex_unlock(&cache_lock);
}

static void cleanup_during_digest(int fd)
{
    (void)fd;
    char error[256];
    g_assert_cmpint(pthread_mutex_trylock(&cache_lock), ==, 0);
    g_assert_cmpint(latcd_cache_capacity_reserve(&generation_capacity, 0,
        cleanup_config->max_cache_bytes, error, sizeof(error)), ==, 0);
    for (unsigned i = 0; i < G_N_ELEMENTS(cleanup_names); i++) {
        if (!cleanup_names[i]) continue;
        char *path = g_build_filename(cleanup_config->cache_dir,
                                      cleanup_names[i], NULL);
        g_assert_true(g_file_test(path, G_FILE_TEST_IS_REGULAR));
        g_free(path);
    }
    /* Capacity pressure must not evict the old rollback during publication. */
    g_assert_cmpuint(generation_capacity.committed, >, 0);
    g_assert_cmpint(latcd_cache_capacity_reserve(&generation_capacity, 0,
        generation_capacity.committed - 1, error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "safe retirement GC"));
    LatcdCurrentManifest selected = {0};
    g_assert_cmpint(current_manifest_read(cleanup_config, cleanup_hex,
        &selected), ==, 0);
    g_assert_cmpstr(selected.module, ==, cleanup_names[0]);
    current_manifest_clear(&selected);
    pthread_mutex_unlock(&cache_lock);
}

static void test_publication_cleanup(void)
{
    char *directory = g_dir_make_tmp("latcd-publish-pins-XXXXXX", NULL);
    char *temporary = g_build_filename(directory, ".tmp", NULL);
    g_assert_cmpint(g_mkdir(temporary, 0700), ==, 0);
    uint8_t digest[32];
    memset(digest, 0x11, sizeof(digest));
    digest_hex(digest, cleanup_hex);
    LatcdConfig config = {.cache_dir = directory,
        .max_cache_bytes = UINT64_C(1073741824)};
    char *task_id = g_uuid_string_random();
    char *task_dir = g_build_filename(directory, ".gc", "tasks", NULL);
    g_assert_cmpint(g_mkdir_with_parents(task_dir, 0700), ==, 0);
    char *task_name = g_strdup_printf("%s.ini", task_id);
    char *task_path = g_build_filename(task_dir, task_name, NULL);
    g_assert_true(g_file_set_contents(task_path,
        "[output_native]\nname=native-output\n[output_module]\nname=module-output\n", -1, NULL));
    GKeyFile *bound = g_key_file_new();
    g_assert_true(g_key_file_load_from_file(bound, task_path, G_KEY_FILE_NONE, NULL));
    struct stat tmp_identity;
    g_assert_cmpint(stat(temporary, &tmp_identity), ==, 0);
    task_object_identity(bound, "temporary", &tmp_identity);
    gsize bound_size;
    char *bound_data = g_key_file_to_data(bound, &bound_size, NULL);
    g_assert_true(g_file_set_contents(task_path, bound_data, bound_size, NULL));
    g_free(bound_data);
    g_key_file_free(bound);
    g_assert_cmpint(g_chmod(task_path, 0400), ==, 0);
    int task_fd = open(task_path, O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(task_fd, >=, 0);
    struct stat task_identity;
    g_assert_cmpint(fstat(task_fd, &task_identity), ==, 0);
    g_assert_cmpint(flock(task_fd, LOCK_SH), ==, 0);
    g_assert_cmpint(record_compiler_release(&config, task_id, &task_identity, false), ==, -1);
    g_assert_cmpint(record_compiler_release(&config, task_id, &task_identity, true), ==, -1);
    close(task_fd);
    g_assert_cmpint(record_compiler_release(&config, task_id, &task_identity, false), ==, 0);
    char *live_output = g_build_filename(temporary, "native-output", NULL);
    g_assert_true(g_file_set_contents(live_output, "live", 4, NULL));
    g_assert_cmpint(record_compiler_release(&config, task_id, &task_identity, true), ==, -1);
    g_assert_cmpint(g_unlink(live_output), ==, 0);
    g_assert_cmpint(record_compiler_release(&config, task_id, &task_identity, true), ==, 0);
    g_free(live_output);
    g_free(task_path);
    g_free(task_name);
    g_free(task_dir);
    g_free(task_id);
    char *names[6];
    const char *suffixes[] = {"so", "native", "tbset", "so", "native", "tbset"};
    for (unsigned i = 0; i < G_N_ELEMENTS(names); i++) {
        char generation[65];
        memset(generation, i < 3 ? 'a' : 'b', 64);
        generation[64] = '\0';
        names[i] = g_strdup_printf("%s-%s.%s", cleanup_hex, generation, suffixes[i]);
        if (i == 3 || i == 4) continue;
        cleanup_names[i] = names[i];
        char *path = g_build_filename(directory, names[i], NULL);
        LatAotTbV2 keys[] = {{.guest_rva = 0x100, .flags = 3},
                             {.guest_rva = 0x200, .flags = 3}};
        if (i % 3 == 0) daemon_fixture(path, keys, G_N_ELEMENTS(keys));
        else {
            g_assert_true(g_file_set_contents(path, "fixture", 7, NULL));
            g_assert_cmpint(g_chmod(path, 0444), ==, 0);
        }
        g_free(path);
    }
    char *module = g_build_filename(directory, names[0], NULL);
    LatAotModuleInfoV2 info;
    char error[256];
    g_assert_cmpint(lat_aot_v2_module_inspect_file(module, &info,
        error, sizeof(error)), ==, 0);
    generation_capacity.committed = 100;
    pthread_mutex_lock(&cache_lock);
    g_assert_cmpint(publish_current_index(&config, cleanup_hex, names[0],
        names[1], names[2], &info, 1, true, error, sizeof(error)), ==, 0);
    cleanup_config = &config;
    hook_read_path = module;
    read_hook = cleanup_during_digest;
    /* Covered-TB publication keeps the pair but stages an unreferenced set. */
    g_assert_cmpint(publish_current_index(&config, cleanup_hex, names[0],
        names[1], names[5], &info, 2, false, error, sizeof(error)), ==, 0);
    g_assert_null(read_hook);
    /* A newly compiled pair is also unreferenced until manifest commit. */
    char *new_module = g_build_filename(directory, names[3], NULL);
    daemon_fixture(new_module, (LatAotTbV2[]) {
        {.guest_rva = 0x100, .flags = 3}, {.guest_rva = 0x200, .flags = 3}}, 2);
    char *new_native = g_build_filename(directory, names[4], NULL);
    g_assert_true(g_file_set_contents(new_native, "fixture", 7, NULL));
    g_assert_cmpint(g_chmod(new_native, 0444), ==, 0);
    cleanup_names[2] = names[5];
    cleanup_names[3] = names[3];
    cleanup_names[4] = names[4];
    cleanup_names[5] = NULL;
    hook_read_path = new_module;
    read_hook = cleanup_during_digest;
    g_assert_cmpint(publish_current_index(&config, cleanup_hex, names[3],
        names[4], names[5], &info, 3, true, error, sizeof(error)), ==, 0);
    g_assert_null(read_hook);
    /* A path pin constrains internal cleanup, not external replacement. */
    char *new_tbset = g_build_filename(directory, names[5], NULL);
    hook_path = new_tbset;
    hook_contents = "replaced";
    hook_mutate = false;
    read_hook = replace_during_read;
    g_assert_cmpint(publish_current_index(&config, cleanup_hex, names[3],
        names[4], names[5], &info, 4, true, error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "changed during digest"));
    g_assert_cmpint(g_chmod(new_tbset, 0444), ==, 0);
    cleanup_info = &info;
    read_hook = publish_during_digest;
    g_assert_cmpint(publish_current_index(&config, cleanup_hex, names[3],
        names[4], names[5], &info, 4, true, error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "changed during digest"));
    LatcdCurrentManifest latest = {0};
    g_assert_cmpint(current_manifest_read(&config, cleanup_hex, &latest), ==, 0);
    g_assert_cmpuint(latest.published_sequence, ==, 5);
    g_assert_cmpstr(latest.module, ==, names[0]);
    g_assert_cmpstr(latest.tbset, ==, names[5]);
    current_manifest_clear(&latest);
    g_assert_cmpint(g_unlink(new_tbset), ==, 0);
    g_assert_cmpint(publish_current_index(&config, cleanup_hex, names[3],
        names[4], names[5], &info, 6, true, error, sizeof(error)), ==, -1);
    pthread_mutex_unlock(&cache_lock);
    cleanup_config = NULL;
    generation_capacity.committed = 0;
    hook_read_path = NULL;
    for (unsigned i = 0; i < G_N_ELEMENTS(names); i++) {
        cleanup_names[i] = NULL;
        g_free(names[i]);
    }
    g_free(new_module);
    g_free(new_native);
    g_free(new_tbset);
    g_free(module);
    remove_fixture_tree(directory);
    g_free(temporary);
    g_free(directory);
}

static void test_incremental_retention(const char *compiler, unsigned mode)
{
    char *directory = g_dir_make_tmp("latcd-large-coverage-XXXXXX", NULL);
    char hex[65];
    uint8_t digest[32];
    memset(digest, 0x11, 32);
    digest_hex(digest, hex);
    char *temporary = g_build_filename(directory, ".tmp", NULL);
    g_assert_cmpint(g_mkdir(temporary, 0700), ==, 0);
    test_pinned_cache_copy(temporary);
    char *old_name = g_strdup_printf("%s-old.so", hex);
    char *native_name = g_strdup_printf("%s-old.native", hex);
    char *input_name = g_strdup_printf("%s-input.tbset", hex);
    char *old = g_build_filename(directory, old_name, NULL);
    char *source = g_build_filename(directory, "source.so", NULL);
    char *native = g_build_filename(directory, native_name, NULL);
    char *input = g_build_filename(directory, input_name, NULL);
    char *delta = g_build_filename(directory, "delta.tbset", NULL);
    char *marker = g_strconcat(source, ".mode", NULL);
    char *calls = g_strconcat(source, ".calls", NULL);
    char *partial = g_strconcat(source, ".partial", NULL);
    const size_t count = mode < 4 ? LAT_AOT_V2_TBSET_RECORD_LIMIT + 1 : 2;
    uint8_t codegen[32];
    expected_codegen_id(codegen);
    const char *modules[] = {old, source, partial};
    for (unsigned i = 0; i < G_N_ELEMENTS(modules); i++) {
        write_large_module(modules[i], count + (i == 1 && mode != 2));
        g_assert_cmpint(g_chmod(modules[i], 0600), ==, 0);
        int fd = g_open(modules[i], O_RDWR, 0);
        g_assert_cmpint(fd, >=, 0);
        g_assert_cmpint(pwrite(fd, codegen, 32, LAT_AOT_TEST_NOTE_OFFSET + 16 +
            offsetof(LatAotNoteV2, codegen_id)), ==, 32);
        close(fd);
        g_assert_cmpint(g_chmod(modules[i], 0444), ==, 0);
    }
    char mode_text[16];
    snprintf(mode_text, sizeof(mode_text), "%u", mode);
    g_assert_true(g_file_set_contents(marker, mode_text, -1, NULL));
    g_assert_true(g_file_set_contents(native, "native", 6, NULL));
    g_assert_cmpint(g_chmod(native, 0444), ==, 0);
    LatTbKey key = {.guest_rva = count + 1, .flags = 3};
    LatTbKeySet keys = {.keys = &key, .count = 1, .sequence = 7};
    memcpy(keys.source_sha256, digest, 32);
    for (unsigned i = 0; i < 2; i++) {
        int fd = g_open(i ? delta : input, O_RDWR | O_CREAT | O_EXCL, 0600);
        g_assert_cmpint(fd, >=, 0);
        char error[256];
        g_assert_cmpint(lat_tb_key_set_write_fd(fd, &keys, error, sizeof(error)), ==, 0);
        g_assert_cmpint(fchmod(fd, 0444), ==, 0);
        close(fd);
    }
    LatcdConfig config = {.cache_dir = directory, .compiler = compiler,
        .runner = compiler, .runtime_dir = directory, .workers = 1,
        .cpu_seconds = 20, .open_files = 128,
        .max_cache_bytes = UINT64_C(1073741824),
        .address_space_limit = RLIM_INFINITY, .file_size_limit = RLIM_INFINITY};
    char error[256];
    g_assert_cmpint(latcd_cache_capacity_scan(&generation_capacity, directory,
        error, sizeof(error)), ==, 0);
    LatAotModuleInfoV2 info;
    g_assert_cmpint(lat_aot_v2_module_inspect_file(old, &info, error, sizeof(error)), ==, 0);
    pthread_mutex_lock(&cache_lock);
    g_assert_cmpint(publish_current_index(&config, hex, old_name, native_name,
        input_name, &info, 1, true, error, sizeof(error)), ==, 0);
    pthread_mutex_unlock(&cache_lock);
    if (mode == 3) {
        g_assert_cmpint(g_unlink(native), ==, 0);
        g_assert_cmpint(latcd_cache_capacity_scan(&generation_capacity, directory,
            error, sizeof(error)), ==, 0);
    }
    g_assert_cmpint(persisted_manifest_valid(&config, hex, digest), ==, mode != 3);
    char *manifest = g_strdup_printf("%s/%s.current", directory, hex);
    gchar *before, *after;
    g_assert_true(g_file_get_contents(manifest, &before, NULL, NULL));
    LatcdResponseV2 response = {0};
    int result = publish_snapshot(&config, 0, source, delta, input, false,
                                  digest, 7, &response);
    g_assert_true(g_file_get_contents(manifest, &after, NULL, NULL));
    if (!mode || mode == 4 || mode == 5) {
        if (result) g_printerr("large incremental: %s\n", response.message);
        g_assert_cmpint(result, ==, 0);
        g_assert_cmpstr(before, !=, after);
        LatcdCurrentManifest current = {0};
        g_assert_cmpint(current_manifest_read(&config, hex, &current), ==, 0);
        char *published = g_build_filename(directory, current.module, NULL);
        g_assert_cmpint(lat_aot_v2_module_validate_tbset_file(published, delta,
            error, sizeof(error)), ==, 0);
        g_assert_cmpint(info.tb_count, ==, count);
        current_manifest_clear(&current);
        g_free(published);
    } else {
        g_assert_cmpint(result, ==, -1);
        g_assert_nonnull(strstr(response.message,
            mode == 6 ? "not fully covered" : "export limit"));
        g_assert_cmpstr(before, ==, after);
        g_assert_true(g_file_test(old, G_FILE_TEST_IS_REGULAR));
    }
    if (mode == 3) {
        g_assert_false(g_file_test(calls, G_FILE_TEST_EXISTS));
    } else {
        gchar *call_text;
        g_assert_true(g_file_get_contents(calls, &call_text, NULL, NULL));
        g_assert_cmpstr(call_text, ==, mode < 4 ? "base=1 keys=1\n" :
            "base=1 keys=1\nbase=0 keys=3\n");
        g_free(call_text);
    }
    g_free(before);
    g_free(after);
    remove_fixture_tree(directory);
    g_free(partial);
    g_free(manifest);
    g_free(calls);
    g_free(marker);
    g_free(delta);
    g_free(input);
    g_free(native);
    g_free(source);
    g_free(old);
    g_free(input_name);
    g_free(native_name);
    g_free(old_name);
    g_free(temporary);
    g_free(directory);
}

static void test_copy_root_recovery(void)
{
    char *directory = g_dir_make_tmp("latcd-copy-recovery-XXXXXX", NULL);
    g_assert_nonnull(directory);
    char *temporary = g_build_filename(directory, ".tmp", NULL);
    g_assert_cmpint(g_mkdir(temporary, 0700), ==, 0);
    char *input = g_build_filename(temporary, "input", NULL);
    char *output = g_build_filename(temporary, "output", NULL);
    g_assert_true(g_file_set_contents(input, "copy input", -1, NULL));
    int pins[] = {open(input, O_RDONLY | O_CLOEXEC), -1, -1, -1};
    g_assert_cmpint(pins[0], >=, 0);
    const char *paths[] = {input, NULL, NULL, NULL, output, NULL};
    uint8_t digest[32] = {1};
    LatcdConfig config = {.cache_dir = directory};
    char *id = NULL, error[256];
    int lease = record_task(&config, true, paths, pins, digest, NULL, &id,
        error, sizeof(error));
    g_assert_cmpint(lease, >=, 0);
    char *name = g_strdup_printf("%s.ini", id);
    char *receipt = g_build_filename(directory, ".gc", "copy-releases", name, NULL);
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_false(g_file_test(receipt, G_FILE_TEST_EXISTS));
    close(lease);
    g_assert_true(g_file_set_contents(output, "partial", -1, NULL));
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_false(g_file_test(receipt, G_FILE_TEST_EXISTS));
    char *contents = NULL;
    g_assert_true(g_file_get_contents(output, &contents, NULL, NULL));
    g_assert_cmpstr(contents, ==, "partial");
    g_free(contents);
    g_assert_cmpint(g_unlink(output), ==, 0);
    char *old = g_strconcat(temporary, "-old", NULL);
    g_assert_cmpint(g_rename(temporary, old), ==, 0);
    g_assert_cmpint(g_mkdir(temporary, 0700), ==, 0);
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_false(g_file_test(receipt, G_FILE_TEST_EXISTS));
    g_assert_cmpint(g_rmdir(temporary), ==, 0);
    g_assert_cmpint(g_rename(old, temporary), ==, 0);
    record_boundary = RECORD_FILE_SYNC;
    record_hits = 0;
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(record_hits, ==, 1);
    g_assert_false(g_file_test(receipt, G_FILE_TEST_EXISTS));
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    struct stat before, after;
    g_assert_cmpint(stat(receipt, &before), ==, 0);
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_cmpint(stat(receipt, &after), ==, 0);
    g_assert_true(metadata_equal(&before, &after));
    close(pins[0]);
    g_free(old);
    g_free(receipt);
    g_free(name);
    g_free(id);
    g_free(input);
    g_free(output);
    g_free(temporary);
    remove_fixture_tree(directory);
    g_free(directory);
}

static int restore_compiler_budgets(const LatcdConfig *config, char *error, size_t size)
{
    LatcdBudgetRecovery work = {0};
    unsigned visited;
    int result;
    do {
        result = restore_compiler_budgets_step(config, &work, 1, &visited, error, size);
        g_assert_cmpuint(visited, <=, 1);
        if (result == 1) g_assert_nonnull(work.cursor);
    } while (result == 1);
    g_assert_null(work.cursor);
    return result;
}

static void test_compiler_input_recovery(void)
{
    char *directory = g_dir_make_tmp("latcd-input-recovery-XXXXXX", NULL);
    g_assert_nonnull(directory);
    char *temporary = g_build_filename(directory, ".tmp", NULL);
    g_assert_cmpint(g_mkdir(temporary, 0700), ==, 0);
    char *source = g_build_filename(temporary, "source", NULL);
    char *output = g_build_filename(temporary, "module", NULL);
    char *native = g_build_filename(temporary, "native", NULL);
    g_assert_true(g_file_set_contents(source, "input", -1, NULL));
    int pins[4] = {open(source, O_RDONLY | O_CLOEXEC), -1, -1, -1};
    g_assert_cmpint(pins[0], >=, 0);
    const char *paths[] = {source, NULL, NULL, NULL, native, output};
    const char *environment[] = {"TEST=1", NULL};
    uint8_t digest[32] = {1};
    LatcdConfig config = {.cache_dir = directory};
    char error[256], *id = NULL;
    int task = record_task(&config, false, paths, pins, digest, environment,
        &id, error, sizeof(error));
    g_assert_cmpint(task, >=, 0);
    g_assert_true(g_file_set_contents(native, "unfinished", -1, NULL));
    struct stat budget_task;
    g_assert_cmpint(fstat(task, &budget_task), ==, 0);
    record_boundary = RECORD_FILE_SYNC;
    record_hits = 0;
    g_assert_cmpint(record_compiler_budget(&config, id, &budget_task, 12345), ==, -1);
    g_assert_cmpuint(record_hits, ==, 1);
    g_assert_cmpint(restore_compiler_budgets(&config, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(generation_capacity.recovered_reserved, ==, 0);
    g_assert_cmpuint(g_hash_table_size(generation_capacity.unknown_tasks), ==, 1);
    g_assert_cmpint(latcd_cache_capacity_reserve(&generation_capacity, 1, UINT64_MAX, NULL, 0), ==, -1);
    g_assert_cmpint(record_compiler_budget(&config, id, &budget_task, 12345), ==, 0);
    g_assert_cmpint(restore_compiler_budgets(&config, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(generation_capacity.recovered_reserved, ==, 12345);
    g_assert_cmpuint(g_hash_table_size(generation_capacity.unknown_tasks), ==, 0);
    g_assert_cmpint(restore_compiler_budgets(&config, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(generation_capacity.recovered_reserved, ==, 12345);
    char *name = g_strdup_printf("%s.ini", id);
    char *release = g_build_filename(directory, ".gc", "compiler-releases", name, NULL);
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_false(g_file_test(release, G_FILE_TEST_EXISTS));
    close(task);
    stop_requested = 1;
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 1);
    g_assert_false(g_file_test(release, G_FILE_TEST_EXISTS));
    stop_requested = 0;
    record_boundary = RECORD_FILE_SYNC;
    record_crash = false;
    record_hits = 0;
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(record_hits, ==, 1);
    g_assert_false(g_file_test(release, G_FILE_TEST_EXISTS));
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    struct stat before, after;
    g_assert_cmpint(stat(release, &before), ==, 0);
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_cmpint(stat(release, &after), ==, 0);
    g_assert_true(metadata_equal(&before, &after));
    char *output_release = g_build_filename(directory, ".gc", "compiler-output-releases", name, NULL);
    g_assert_false(g_file_test(output_release, G_FILE_TEST_EXISTS));
    char *original = NULL;
    g_assert_cmpuint(generation_capacity.recovered_reserved, ==, 12345);
    gsize original_size;
    g_assert_true(g_file_get_contents(release, &original, &original_size, NULL));
    g_assert_cmpint(g_chmod(release, 0600), ==, 0);
    g_assert_true(g_file_set_contents(release, "[handoff]\nstate=wrong\n", -1, NULL));
    g_assert_cmpint(g_chmod(release, 0400), ==, 0);
    g_assert_cmpint(g_unlink(native), ==, 0);
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_false(g_file_test(output_release, G_FILE_TEST_EXISTS));
    g_assert_cmpint(g_chmod(release, 0600), ==, 0);
    g_assert_true(g_file_set_contents(release, original, original_size, NULL));
    g_assert_cmpint(g_chmod(release, 0400), ==, 0);
    g_free(original);
    compiler_task_local(id, true);
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_false(g_file_test(output_release, G_FILE_TEST_EXISTS));
    compiler_task_local(id, false);
    char *old_temporary = g_strconcat(temporary, "-old", NULL);
    g_assert_cmpint(g_rename(temporary, old_temporary), ==, 0);
    g_assert_cmpint(g_mkdir(temporary, 0700), ==, 0);
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_false(g_file_test(output_release, G_FILE_TEST_EXISTS));
    g_assert_cmpint(g_rmdir(temporary), ==, 0);
    g_assert_cmpint(g_rename(old_temporary, temporary), ==, 0);
    g_free(old_temporary);
    record_boundary = RECORD_FILE_SYNC;
    record_hits = 0;
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(record_hits, ==, 1);
    g_assert_false(g_file_test(output_release, G_FILE_TEST_EXISTS));
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_cmpint(stat(output_release, &before), ==, 0);
    g_assert_cmpuint(generation_capacity.recovered_reserved, ==, 0);
    g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
    g_assert_cmpint(stat(output_release, &after), ==, 0);
    g_assert_true(metadata_equal(&before, &after));
    char *task_directory = g_build_filename(directory, ".gc", "tasks", NULL);
    char *budget_path = g_build_filename(directory, ".gc", "compiler-budgets", name, NULL);
    g_assert_cmpint(g_chmod(budget_path, 0600), ==, 0);
    g_assert_true(g_file_set_contents(budget_path, "bad budget", -1, NULL));
    g_assert_cmpint(g_chmod(budget_path, 0400), ==, 0);
    g_assert_cmpint(restore_compiler_budgets(&config, error, sizeof(error)), ==, -1);
    g_free(budget_path);
    for (unsigned i = 0; i < 70; i++) {
        char *unknown = g_strdup_printf("%s/unknown-%u", task_directory, i);
        g_assert_true(g_file_set_contents(unknown, "retain", -1, NULL));
        g_free(unknown);
    }
    DIR *cursor = NULL;
    unsigned visited, total = 0, batches = 0;
    int result;
    do {
        result = recover_compiler_inputs_step(&config, &cursor, 7,
            &visited, error, sizeof(error));
        g_assert_cmpint(result, >=, 0);
        g_assert_cmpuint(visited, <=, 7);
        total += visited;
        batches++;
    } while (result == 1);
    g_assert_null(cursor);
    g_assert_cmpuint(total, ==, 71);
    g_assert_cmpuint(batches, >=, 11);
    g_free(task_directory);
    for (unsigned bad = 0; bad < 7; bad++) {
        char *bad_id = NULL;
        int bad_task = record_task(&config, false, paths, pins, digest, environment,
            &bad_id, error, sizeof(error));
        g_assert_cmpint(bad_task, >=, 0);
        close(bad_task);
        char *bad_name = g_strdup_printf("%s.ini", bad_id);
        char *path = g_build_filename(directory, ".gc", "tasks", bad_name, NULL);
        char *receipt = g_build_filename(directory, ".gc", "compiler-releases", bad_name, NULL);
        char *alias = g_strconcat(path, ".alias", NULL);
        if (bad < 4) {
            GKeyFile *record = g_key_file_new();
            g_assert_true(g_key_file_load_from_file(record, path, G_KEY_FILE_NONE, NULL));
            if (bad == 0) g_key_file_set_string(record, "task", "build_id", "unknown");
            if (bad == 1) g_key_file_set_uint64(record, "cache", "inode", 0);
            if (bad == 2) g_key_file_set_string(record, "task", "version", "2");
            if (bad == 3) g_key_file_set_string(record, "task", "id", "wrong-id");
            gsize size;
            char *contents = g_key_file_to_data(record, &size, NULL);
            g_assert_cmpint(g_chmod(path, 0600), ==, 0);
            g_assert_true(g_file_set_contents(path, contents, size, NULL));
            g_assert_cmpint(g_chmod(path, 0400), ==, 0);
            g_free(contents);
            g_key_file_free(record);
        } else if (bad == 4) {
            g_assert_cmpint(g_chmod(path, 0600), ==, 0);
        } else if (bad == 5) {
            g_assert_cmpint(link(path, alias), ==, 0);
        } else {
            g_assert_cmpint(g_rename(path, alias), ==, 0);
        }
        g_assert_cmpint(recover_compiler_inputs(&config, error, sizeof(error)), ==, 0);
        g_assert_false(g_file_test(receipt, G_FILE_TEST_EXISTS));
        g_unlink(alias);
        g_unlink(path);
        g_free(alias);
        g_free(receipt);
        g_free(path);
        g_free(bad_name);
        g_free(bad_id);
    }
    close(pins[0]);
    g_free(output_release);
    g_free(release);
    g_free(name);
    g_free(id);
    g_free(native);
    g_free(output);
    g_free(source);
    g_free(temporary);
    remove_fixture_tree(directory);
    g_free(directory);
}

static void test_task_record_persistence(void)
{
    char *directory = g_dir_make_tmp("latcd-record-faults-XXXXXX", NULL);
    g_assert_nonnull(directory);
    int root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    g_assert_cmpint(root, >=, 0);
    GKeyFile *record = g_key_file_new();
    g_key_file_set_string(record, "test", "value", "complete immutable record");
    gsize length;
    char *expected = g_key_file_to_data(record, &length, NULL);
    for (unsigned crash = 0; crash < 2; crash++) {
        for (enum RecordBoundary boundary = RECORD_WRITE;
             boundary <= RECORD_DIRECTORY_SYNC; boundary++) {
            if (boundary == RECORD_UNLINK) continue; /* No named staging file. */
            char *id = g_uuid_string_random();
            char *name = g_strdup_printf("%s.ini", id);
            char *staging = g_strdup_printf(".write-%s", id);
            record_boundary = boundary;
            record_crash = crash;
            record_hits = 0;
            if (crash) {
                pid_t child = fork();
                g_assert_cmpint(child, >=, 0);
                if (!child) {
                    int lease = persist_task_record(root, id, record);
                    if (lease >= 0) close(lease);
                    _exit(98); /* Missing boundary must not pass as a crash. */
                }
                int status;
                g_assert_cmpint(waitpid(child, &status, 0), ==, child);
                g_assert_true(WIFSIGNALED(status));
                g_assert_cmpint(WTERMSIG(status), ==, SIGKILL);
            } else {
                g_assert_cmpint(persist_task_record(root, id, record), ==, -1);
                g_assert_cmpuint(record_hits, ==, 1);
            }
            record_boundary = RECORD_NONE;
            record_crash = false;
            /* SIGKILL tests process death, not power-loss durability. A final
             * name can survive a failed/unacknowledged post-link operation. */
            bool published = boundary >= (crash ? RECORD_LINK : RECORD_DIRECTORY_SYNC);
            struct stat final_status, staging_status;
            g_assert_cmpint(fstatat(root, name, &final_status, 0), ==,
                            published ? 0 : -1);
            if (!published) g_assert_cmpint(errno, ==, ENOENT);
            g_assert_cmpint(fstatat(root, staging, &staging_status, 0), ==,
                            -1);
            g_assert_cmpint(errno, ==, ENOENT);
            if (published) {
                char *path = g_build_filename(directory, name, NULL);
                char *actual = NULL;
                gsize size;
                g_assert_true(g_file_get_contents(path, &actual, &size, NULL));
                g_assert_cmpmem(actual, size, expected, length);
                g_assert_cmpuint(final_status.st_mode & 0777, ==, 0400);
                g_assert_cmpuint(final_status.st_nlink, ==, 1);
                int probe = open(path, O_RDONLY | O_CLOEXEC);
                g_assert_cmpint(probe, >=, 0);
                g_assert_cmpint(flock(probe, LOCK_EX | LOCK_NB), ==, 0);
                close(probe);
                g_free(actual);
                g_free(path);
            }
            if (published) g_assert_cmpint(unlinkat(root, name, 0), ==, 0);
            g_free(staging);
            g_free(name);
            g_free(id);
        }
    }
    char *id = g_uuid_string_random();
    char *name = g_strdup_printf("%s.ini", id);
    record_write_retries = 2;
    int lease = persist_task_record(root, id, record);
    g_assert_cmpint(lease, >=, 0);
    g_assert_cmpuint(record_write_retries, ==, 0);
    g_assert_cmpint(fcntl(lease, F_GETFL) & O_ACCMODE, ==, O_RDONLY);
    g_assert_cmpint(fcntl(lease, F_GETFD) & FD_CLOEXEC, ==, FD_CLOEXEC);
    struct stat before, after;
    g_assert_cmpint(fstat(lease, &before), ==, 0);
    int probe = openat(root, name, O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(probe, >=, 0);
    g_assert_cmpint(flock(probe, LOCK_EX | LOCK_NB), ==, -1);
    g_assert_cmpint(errno, ==, EWOULDBLOCK);
    g_key_file_set_string(record, "test", "value", "must not overwrite");
    g_assert_cmpint(persist_task_record(root, id, record), ==, -1);
    g_assert_cmpint(fstatat(root, name, &after, 0), ==, 0);
    g_assert_cmpuint(before.st_ino, ==, after.st_ino);
    g_assert_cmpuint(after.st_nlink, ==, 1);
    char contents[128];
    g_assert_cmpint(pread(lease, contents, sizeof(contents), 0), ==, length);
    g_assert_cmpmem(contents, length, expected, length);
    close(lease);
    g_assert_cmpint(flock(probe, LOCK_EX | LOCK_NB), ==, 0);
    close(probe);
    close(root);
    g_free(expected);
    g_free(name);
    g_free(id);
    g_key_file_unref(record);
    remove_fixture_tree(directory);
    g_free(directory);
}

static void test_compile_space(void)
{
    char error[256];
    dev_t same[] = {1, 1}, separate[] = {1, 2};
    uint64_t available[] = {100, 100}, bytes[] = {40, 30};
    g_assert_cmpint(reserve_compile_space(0, same, available, bytes, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(compile_space[0].bytes[0], ==, 70);
    g_assert_cmpuint(compile_space[0].bytes[1], ==, 0);
    g_assert_cmpint(reserve_compile_space(1, same, available, bytes, error, sizeof(error)), ==, -1);
    g_assert_false(compile_space[1].active);
    g_assert_cmpint(reserve_compile_space(0, same, available, bytes, error, sizeof(error)), ==, -1);
    release_compile_space(0);
    g_assert_cmpint(reserve_compile_space(1, separate, available, bytes, error, sizeof(error)), ==, 0);
    g_assert_cmpint(reserve_compile_space(2, separate, available, bytes, error, sizeof(error)), ==, 0);
    g_assert_cmpint(reserve_compile_space(3, separate, available, bytes, error, sizeof(error)), ==, -1);
    release_compile_space(1); release_compile_space(2);
    uint64_t overflow[] = {UINT64_MAX, 1};
    g_assert_cmpint(reserve_compile_space(0, same, available, overflow, error, sizeof(error)), ==, -1);
    g_assert_cmpint(reserve_compile_space(LATCD_MAX_WORKERS + 1, same, available, bytes, error, sizeof(error)), ==, -1);
    g_assert_cmpint(reserve_compile_space(LATCD_MAX_WORKERS, same, available, bytes, error, sizeof(error)), ==, 0);
    g_assert_cmpint(reserve_compile_space(0, same, available, bytes, error, sizeof(error)), ==, -1);
    release_compile_space(LATCD_MAX_WORKERS);
    g_assert_false(compile_space[LATCD_MAX_WORKERS].active);
    g_assert_cmpint(reserve_compile_space(LATCD_MAX_WORKERS, same, available, bytes, error, sizeof(error)), ==, 0);
    release_compile_space(LATCD_MAX_WORKERS);
    uint64_t n = UINT64_MAX - 1;
    g_assert_false(space_add(&n, 1, 2));
    g_assert_cmpuint(n, ==, UINT64_MAX - 1);
}

static void test_persistent_state_capacity(void)
{
    char *directory = g_dir_make_tmp("latcd-state-capacity-XXXXXX", NULL);
    char *temporary = g_build_filename(directory, ".tmp", NULL);
    g_assert_cmpint(g_mkdir(temporary, 0700), ==, 0);
    uint8_t digest[32];
    memset(digest, 0x11, sizeof(digest));
    char hex[65], error[256] = {0};
    digest_hex(digest, hex);
    char *module_name = g_strconcat(hex, ".so", NULL);
    char *native_name = g_strconcat(hex, ".native", NULL);
    char *module = g_build_filename(directory, module_name, NULL);
    char *native = g_build_filename(directory, native_name, NULL);
    char *manifest = g_strconcat(directory, "/", hex, ".current", NULL);
    char *input = g_build_filename(directory, "incoming", NULL);
    LatAotTbV2 tbs[] = {{.guest_rva = 0x100, .flags = 3}};
    daemon_fixture(module, tbs, 1);
    g_assert_true(g_file_set_contents(native, "native", 6, NULL));
    g_assert_cmpint(g_chmod(native, 0444), ==, 0);
    LatTbKey keys[] = {{.guest_rva = 0x100, .flags = 3},
                      {.guest_rva = 0x200, .flags = 3}};
    LatTbKeySet set = {.keys = keys, .count = 1, .sequence = 1};
    memcpy(set.source_sha256, digest, 32);
    int fd = open(input, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(lat_tb_key_set_write_fd(fd, &set, error, sizeof(error)), ==, 0);
    LatcdConfig config = {.cache_dir = directory, .max_cache_bytes = UINT64_C(1073741824)};
    char *canonical = NULL;
    g_assert_cmpint(merge_tbset(&config, digest, input, &canonical, NULL, error, sizeof(error)), ==, 0);
    LatAotModuleInfoV2 info;
    g_assert_cmpint(lat_aot_v2_module_inspect_file(module, &info, error, sizeof(error)), ==, 0);
    pthread_mutex_lock(&cache_lock);
    g_assert_cmpint(publish_current_index(&config, hex, module_name, native_name,
        "", &info, 1, true, error, sizeof(error)), ==, 0);
    pthread_mutex_unlock(&cache_lock);
    g_assert_cmpint(latcd_cache_capacity_scan(&generation_capacity, directory, error, sizeof(error)), ==, 0);
    uint64_t initial = generation_capacity.state_committed;
    uint64_t exact = initial + generation_capacity.committed + generation_capacity.metadata_committed;
    latcd_cache_capacity_metadata_bind(&generation_capacity, exact);
    gchar *before, *after, *key_before, *key_after;
    gsize key_before_size, key_after_size;
    g_assert_true(g_file_get_contents(manifest, &before, NULL, NULL));
    g_assert_true(g_file_get_contents(canonical, &key_before, &key_before_size, NULL));
    pthread_mutex_lock(&cache_lock);
    g_assert_cmpint(publish_current_index(&config, hex, module_name, native_name,
        "", &info, 2, true, error, sizeof(error)), ==, -1);
    pthread_mutex_unlock(&cache_lock);
    g_assert_nonnull(strstr(error, "capacity:"));
    g_assert_true(g_file_get_contents(manifest, &after, NULL, NULL));
    g_assert_cmpstr(before, ==, after);
    g_free(after);
    set.count = 2;
    g_assert_cmpint(lat_tb_key_set_write_fd(fd, &set, error, sizeof(error)), ==, 0);
    char *next = NULL;
    g_assert_cmpint(merge_tbset(&config, digest, input, &next, NULL, error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "capacity:"));
    g_assert_null(next);
    g_assert_true(g_file_get_contents(canonical, &key_after, &key_after_size, NULL));
    g_assert_cmpmem(key_before, key_before_size, key_after, key_after_size);
    g_free(key_after);
    struct stat identity;
    g_assert_cmpint(fstat(fd, &identity), ==, 0);
    publish_source_identity(&config, &identity, digest); /* Optional index can skip ENOSPC. */
    g_assert_cmpuint(generation_capacity.state_committed, ==, initial);
    g_assert_cmpuint(generation_capacity.state_reserved, ==, 0);
    g_assert_true(generation_capacity.ready);
    latcd_cache_capacity_metadata_bind(&generation_capacity, config.max_cache_bytes);
    g_assert_cmpint(merge_tbset(&config, digest, input, &next, NULL, error, sizeof(error)), ==, 0);
    g_free(next);
    publish_source_identity(&config, &identity, digest);
    pthread_mutex_lock(&cache_lock);
    g_assert_cmpint(publish_current_index(&config, hex, module_name, native_name,
        "", &info, 2, true, error, sizeof(error)), ==, 0);
    pthread_mutex_unlock(&cache_lock);
    g_assert_cmpuint(generation_capacity.state_committed, ==, initial + sizeof(LatTbKey) + 65);
    g_assert_cmpuint(generation_capacity.state_reserved, ==, 0);
    uint64_t final = generation_capacity.state_committed;
    g_assert_cmpint(latcd_cache_capacity_scan(&generation_capacity, directory, error, sizeof(error)), ==, 0);
    g_assert_cmpuint(generation_capacity.state_committed, ==, final);
    latcd_cache_capacity_close(&generation_capacity);
    close(fd);
    g_free(before); g_free(key_before); g_free(canonical);
    remove_fixture_tree(directory);
    g_free(directory); g_free(temporary); g_free(module_name); g_free(native_name);
    g_free(module); g_free(native); g_free(manifest); g_free(input);
}

int main(int argc, char **argv)
{
    if (argc > 1 && (!strcmp(argv[1], "build-id") ||
                     !strcmp(argv[1], "--latc-build-id"))) {
        puts(LATC_BUILD_ID);
        return 0;
    }
    if (argc == 1) {
        test_persistent_state_capacity();
        test_copy_root_recovery();
        test_compiler_input_recovery();
        test_task_record_persistence();
        test_compile_space();
        generation_capacity.ready = true;
        generation_capacity.expected_names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    }
    if (argc > 1 && !strcmp(argv[1], "compile-module")) {
        char *marker = g_strconcat(argv[2], ".mode", NULL);
        char *partial = NULL;
        gchar *mode_text = NULL;
        if (g_file_get_contents(marker, &mode_text, NULL, NULL)) {
            const char *input = NULL;
            for (int i = 3; i + 1 < argc; i++) {
                if (!strcmp(argv[i], "--tbset")) input = argv[i + 1];
            }
            LatTbKeySet keys;
            char error[256];
            g_assert_nonnull(input);
            g_assert_cmpint(lat_tb_key_set_read_file(input, NULL, &keys,
                error, sizeof(error)), ==, 0);
            char *calls = g_strconcat(argv[2], ".calls", NULL);
            char *record = g_strdup_printf("base=%d keys=%zu\n",
                getenv("LATC_NATIVE_BASE") != NULL, keys.count);
            int fd = g_open(calls, O_WRONLY | O_CREAT | O_APPEND, 0600);
            g_assert_cmpint(fd, >=, 0);
            g_assert_cmpint(write(fd, record, strlen(record)), ==, strlen(record));
            g_assert_cmpint(close(fd), ==, 0);
            lat_tb_key_set_destroy(&keys);
            unsigned mode = (unsigned)strtoul(mode_text, NULL, 0);
            g_free(record);
            g_free(calls);
            g_free(mode_text);
            bool base = getenv("LATC_NATIVE_BASE") != NULL;
            if ((mode == 5 && base) || (mode == 6 && !base)) {
                partial = g_strconcat(argv[2], ".partial", NULL);
            }
            if (mode == 1 || ((mode == 4 || mode == 6) && base)) {
                g_free(marker);
                return 3;
            }
        }
        g_free(marker);
        gchar *data = NULL;
        gsize size = 0;
        g_assert_true(g_file_get_contents(partial ? partial : argv[2],
                                          &data, &size, NULL));
        g_free(partial);
        g_assert_true(g_file_set_contents(argv[4], data, size, NULL));
        g_assert_cmpint(g_chmod(argv[4], 0444), ==, 0);
        g_assert_true(g_file_set_contents(getenv("LATC_NATIVE_OUTPUT"),
                                          "native", 6, NULL));
        g_free(data);
        return 0;
    }
    test_publication_cleanup();
    char error[256] = {0}, hex[65];
    uint8_t digest[32];
    memset(digest, 0x11, sizeof(digest));
    digest_hex(digest, hex);
    char *directory = g_dir_make_tmp("latcd-coverage-XXXXXX", NULL);
    g_assert_nonnull(directory);
    char *temporary = g_build_filename(directory, ".tmp", NULL);
    g_assert_cmpint(g_mkdir(temporary, 0700), ==, 0);
    char *old_name = g_strdup_printf("%s.so", hex);
    char *new_name = g_strdup_printf("%s-new.so", hex);
    char *native_name = g_strdup_printf("%s-old.native", hex);
    char *tbset_name = g_strdup_printf("%s-old.tbset", hex);
    char *tbset_path = g_build_filename(directory, tbset_name, NULL);
    g_assert_true(g_file_set_contents(tbset_path, "fixture", 7, NULL));
    g_assert_cmpint(g_chmod(tbset_path, 0444), ==, 0);
    char *old_path = g_build_filename(directory, old_name, NULL);
    char *native_path = g_build_filename(directory, native_name, NULL);
    g_assert_true(g_file_set_contents(native_path, "native", 6, NULL));
    g_assert_cmpint(g_chmod(native_path, 0444), ==, 0);
    char *new_path = g_build_filename(directory, new_name, NULL);
    char *input = g_build_filename(directory, "incoming.tbset", NULL);
    char *manifest = g_strdup_printf("%s/%s.current", directory, hex);
    LatcdConfig config = {.cache_dir = directory, .compiler = argv[0],
        .runner = argv[0], .runtime_dir = directory, .workers = 1,
        .cpu_seconds = 20, .open_files = 128,
        .max_cache_bytes = UINT64_C(1073741824),
        .address_space_limit = RLIM_INFINITY, .file_size_limit = RLIM_INFINITY};
    LatAotTbV2 keys[] = {{.guest_rva = 0x100, .flags = 3},
                         {.guest_rva = 0x200, .flags = 3},
                         {.guest_rva = 0x300, .flags = 3}};
    daemon_fixture(old_path, keys, 2);
    daemon_fixture(new_path, keys + 1, 2);
    LatAotModuleInfoV2 info;
    g_assert_cmpint(lat_aot_v2_module_inspect_file(old_path, &info,
                                                 error, sizeof(error)), ==, 0);
    pthread_mutex_lock(&cache_lock);
    g_assert_cmpint(publish_current_index(&config, hex, old_name, native_name,
        tbset_name, &info, 1, true, error, sizeof(error)), ==, 0);
    LatcdCurrentManifest paired = {0};
    g_assert_cmpint(current_manifest_read(&config, hex, &paired), ==, 0);
    char *pair_native = NULL, *pair_module = NULL;
    int pair_pins[4] = {-1, -1, -1, -1};
    g_assert_nonnull(paired.module_sha256);
    g_assert_nonnull(paired.native_sha256);
    int source_gate = lat_aot_v2_cache_source_lock(directory, hex,
        LOCK_EX | LOCK_NB, false, error, sizeof(error));
    g_assert_cmpint(source_gate, >=, 0);
    g_assert_cmpint(snapshot_current_pair(&config, &paired, digest, temporary,
        &pair_native, &pair_module, pair_pins, error, sizeof(error)), ==, -1);
    g_assert_cmpint(pthread_mutex_trylock(&cache_lock), ==, EBUSY);
    g_assert_null(pair_native);
    g_assert_null(pair_module);
    close(source_gate);
    baseline_paths[0] = native_path;
    baseline_paths[1] = old_path;
    baseline_config = &config;
    baseline_hex = hex;
    hook_read_path = native_path;
    read_hook = assert_baseline_handoff;
    g_assert_cmpint(snapshot_current_pair(&config, &paired, digest, temporary,
        &pair_native, &pair_module, pair_pins, error, sizeof(error)), ==, 0);
    g_assert_nonnull(pair_native);
    g_assert_nonnull(pair_module);
    for (unsigned i = 0; i < 2; i++) {
        int contender = open(i ? pair_module : pair_native, O_RDONLY);
        g_assert_cmpint(contender, >=, 0);
        g_assert_cmpint(flock(contender, LOCK_EX | LOCK_NB), ==, -1);
        g_assert_cmpint(errno, ==, EWOULDBLOCK);
        close(pair_pins[i]);
        pair_pins[i] = -1;
        g_assert_cmpint(flock(contender, LOCK_EX | LOCK_NB), ==, 0);
        close(contender);
    }
    close(pair_pins[2]);
    close(pair_pins[3]);
    pair_pins[2] = pair_pins[3] = -1;
    g_unlink(pair_native);
    g_unlink(pair_module);
    g_clear_pointer(&pair_native, g_free);
    g_clear_pointer(&pair_module, g_free);
    paired.native_sha256[0] = paired.native_sha256[0] == '0' ? '1' : '0';
    g_assert_cmpint(snapshot_current_pair(&config, &paired, digest, temporary,
        &pair_native, &pair_module, pair_pins, error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "changed before baseline capture"));
    g_assert_null(pair_native);
    g_assert_null(pair_module);
    g_clear_pointer(&paired.native_sha256, g_free);
    g_assert_cmpint(snapshot_current_pair(&config, &paired, digest, temporary,
        &pair_native, &pair_module, pair_pins, error, sizeof(error)), ==, -1);
    g_clear_pointer(&paired.module_sha256, g_free);
    g_assert_cmpint(snapshot_current_pair(&config, &paired, digest, temporary,
        &pair_native, &pair_module, pair_pins, error, sizeof(error)), ==, -1);
    g_assert_null(pair_native); /* Caller must re-read the selected manifest. */
    g_assert_null(pair_module);
    current_manifest_clear(&paired);
    /* A real legacy current has no hashes: capture native only, without dedup. */
    gchar *modern = NULL;
    g_assert_true(g_file_get_contents(manifest, &modern, NULL, NULL));
    char *legacy = g_strdup_printf("{\"version\":2,\"module\":\"%s\","
        "\"native\":\"%s\",\"tbset\":\"%s\",\"published_sequence\":1}",
        old_name, native_name, tbset_name);
    g_assert_true(g_file_set_contents(manifest, legacy, -1, NULL));
    g_assert_cmpint(current_manifest_read(&config, hex, &paired), ==, 0);
    g_assert_cmpint(snapshot_current_pair(&config, &paired, digest, temporary,
        &pair_native, &pair_module, pair_pins, error, sizeof(error)), ==, 0);
    g_assert_nonnull(pair_native);
    g_assert_null(pair_module);
    g_assert_cmpint(pair_pins[0], >=, 0);
    close(pair_pins[0]);
    pair_pins[0] = -1;
    close(pair_pins[2]);
    pair_pins[2] = -1;
    g_unlink(pair_native);
    g_clear_pointer(&pair_native, g_free);
    current_manifest_clear(&paired);
    g_assert_true(g_file_set_contents(manifest, modern, -1, NULL));
    g_free(legacy);
    g_free(modern);
    /* Hashing must release the lock, but a concurrent current replacement
     * must prevent the delayed publisher from rolling the manifest back. */
    gchar *selected_manifest = NULL;
    g_assert_true(g_file_get_contents(manifest, &selected_manifest, NULL, NULL));
    hook_path = manifest;
    hook_read_path = native_path;
    hook_contents = "{\"concurrent\":true}\n";
    hook_mutate = false;
    read_hook = replace_during_read;
    g_assert_cmpint(publish_current_index(&config, hex, old_name, native_name,
        tbset_name, &info, 2, true, error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "changed during digest"));
    gchar *concurrent_manifest = NULL;
    g_assert_true(g_file_get_contents(manifest, &concurrent_manifest, NULL, NULL));
    g_assert_cmpstr(concurrent_manifest, ==, hook_contents);
    g_free(concurrent_manifest);
    g_assert_true(g_file_set_contents(manifest, selected_manifest, -1, NULL));
    g_assert_cmpint(chmod(manifest, 0444), ==, 0);
    g_free(selected_manifest);
    read_hook = assert_unlocked_read;
    g_assert_cmpint(publish_current_index(&config, hex, old_name, native_name,
        tbset_name, &info, 1, true, error, sizeof(error)), ==, 0);
    char *historical_name = g_strdup_printf("%s-historical.so", hex);
    char *historical_path = g_build_filename(directory, historical_name, NULL);
    daemon_fixture(historical_path, keys, 2);
    g_assert_cmpint(publish_current_index(&config, hex, historical_name, native_name,
        tbset_name, &info, 1, false, error, sizeof(error)), ==, 0);
    g_assert_cmpint(current_manifest_read(&config, hex, &paired), ==, 0);
    g_assert_null(paired.module_sha256);
    g_assert_null(paired.native_sha256);
    current_manifest_clear(&paired);
    g_assert_cmpint(publish_current_index(&config, hex, old_name, native_name,
        tbset_name, &info, 1, true, error, sizeof(error)), ==, 0);
    g_unlink(historical_path);
    g_free(historical_name);
    g_free(historical_path);
    gchar *before = NULL, *after = NULL;
    g_assert_true(g_file_get_contents(manifest, &before, NULL, NULL));
    g_assert_cmpint(publish_current_index(&config, hex, new_name, native_name,
        tbset_name, &info, 2, true, error, sizeof(error)), ==, -1);
    g_assert_nonnull(strstr(error, "replacement loses module coverage"));
    g_assert_true(g_file_get_contents(manifest, &after, NULL, NULL));
    g_assert_cmpstr(before, ==, after);
    pthread_mutex_unlock(&cache_lock);
    g_free(after);

    LatTbKey requested = {.guest_rva = 0x300, .flags = 3};
    LatTbKeySet incoming = {.keys = &requested, .count = 1, .sequence = 7};
    memcpy(incoming.source_sha256, digest, 32);
    int fd = open(input, O_RDWR | O_CREAT | O_EXCL, 0600);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(lat_tb_key_set_write_fd(fd, &incoming, error, sizeof(error)), ==, 0);
    close(fd);
    char *retained = NULL;
    g_assert_cmpint(preserve_current_keys(&config, hex, digest, input, temporary,
        &retained, error, sizeof(error)), ==, 0);
    g_assert_nonnull(retained);
    LatTbKeySet complete = {0};
    g_assert_cmpint(lat_tb_key_set_read_file(retained, digest, &complete,
        error, sizeof(error)), ==, 0);
    g_assert_cmpuint(complete.count, ==, 3);
    for (size_t i = 0; i < complete.count; i++) {
        g_assert_cmpuint(complete.keys[i].guest_rva, ==, (i + 1) * 0x100);
    }
    lat_tb_key_set_destroy(&complete);
    /* A cached candidate covers the request but omits an unobserved old TB. */
    gchar *input_data = NULL;
    gsize input_size = 0;
    g_assert_true(g_file_get_contents(input, &input_data, &input_size, NULL));
    char *input_sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
        (guchar *)input_data, input_size);
    char *hit_name = g_strdup_printf("%s-%s.so", hex, input_sha);
    char *hit_native_name = g_strdup_printf("%s-%s.native", hex, input_sha);
    char *hit_tbset_name = g_strdup_printf("%s-%s.tbset", hex, input_sha);
    char *hit = g_build_filename(directory, hit_name, NULL);
    char *hit_native = g_build_filename(directory, hit_native_name, NULL);
    char *hit_tbset = g_build_filename(directory, hit_tbset_name, NULL);
    daemon_fixture(hit, keys + 1, 2);
    g_assert_true(g_file_set_contents(hit_native, "native", 6, NULL));
    g_assert_true(g_file_set_contents(hit_tbset, input_data, input_size, NULL));
    LatcdResponseV2 response = {0};
    g_assert_cmpint(publish_snapshot(&config, 0, "unused-snapshot", input,
        input, false, digest, 2, &response), ==, -1);
    g_assert_nonnull(strstr(response.message, "replacement loses module coverage"));
    g_assert_true(g_file_get_contents(manifest, &after, NULL, NULL));
    g_assert_cmpstr(before, ==, after);
    g_free(after);
    g_assert_true(g_file_test(old_path, G_FILE_TEST_IS_REGULAR));
    g_assert_true(g_file_test(hit, G_FILE_TEST_IS_REGULAR));
    g_unlink(hit);
    g_unlink(hit_native);
    g_unlink(hit_tbset);
    g_free(hit);
    g_free(hit_native);
    g_free(hit_tbset);
    g_free(hit_name);
    g_free(hit_native_name);
    g_free(hit_tbset_name);
    g_free(input_sha);
    g_free(input_data);
    daemon_fixture(new_path, keys, 3);
    pthread_mutex_lock(&cache_lock);
    g_assert_cmpint(publish_current_index(&config, hex, new_name, native_name,
        tbset_name, &info, 2, true, error, sizeof(error)), ==, 0);
    pthread_mutex_unlock(&cache_lock);
    g_assert_true(g_file_get_contents(manifest, &after, NULL, NULL));
    g_assert_nonnull(strstr(after, new_name));
    g_assert_cmpstr(before, !=, after);
    g_free(before);
    before = after;

    /* A missing native forces recompilation of an unchanged generation.
     * Failure after staging must not remove the current module or manifest. */
    daemon_fixture(old_path, keys, 3);
    pthread_mutex_lock(&cache_lock);
    g_assert_cmpint(publish_current_index(&config, hex, old_name, native_name,
        "", &info, 2, true, error, sizeof(error)), ==, 0);
    pthread_mutex_unlock(&cache_lock);
    g_assert_cmpint(g_unlink(native_path), ==, 0);
    g_free(before);
    g_assert_true(g_file_get_contents(manifest, &before, NULL, NULL));
    char *trigger = g_build_filename(directory, "failpoint", NULL);
    g_assert_true(g_file_set_contents(trigger, "1", 1, NULL));
    g_assert_cmpint(latcd_cache_capacity_scan(&generation_capacity, directory,
        error, sizeof(error)), ==, 0);
    setenv("LATCD_TEST_FAIL_BEFORE_MANIFEST", trigger, 1);
    setenv("LATCD_COMPILE_TMPDIR", g_get_tmp_dir(), 1);
    memset(&response, 0, sizeof(response));
    g_assert_cmpint(publish_snapshot(&config, 0, new_path, NULL, NULL,
        false, digest, 3, &response), ==, -1);
    g_assert_nonnull(strstr(response.message, "injected failure"));
    g_assert_true(g_file_get_contents(manifest, &after, NULL, NULL));
    g_assert_cmpstr(before, ==, after);
    g_assert_true(g_file_test(old_path, G_FILE_TEST_IS_REGULAR));
    g_free(after);
    unsetenv("LATCD_TEST_FAIL_BEFORE_MANIFEST");
    g_free(trigger);

    /* Neither a cache hit nor a full compile may waive a missing request,
     * even when only one key is missing and all old keys are preserved. */
    requested.guest_rva = 0x400;
    fd = open(input, O_RDWR | O_TRUNC);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(lat_tb_key_set_write_fd(fd, &incoming, error, sizeof(error)), ==, 0);
    close(fd);
    g_assert_true(g_file_get_contents(input, &input_data, &input_size, NULL));
    input_sha = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
        (guchar *)input_data, input_size);
    hit_name = g_strdup_printf("%s-%s.so", hex, input_sha);
    hit = g_build_filename(directory, hit_name, NULL);
    hit_native = g_strdup_printf("%s/%s-%s.native", directory, hex, input_sha);
    hit_tbset = g_strdup_printf("%s/%s-%s.tbset", directory, hex, input_sha);
    daemon_fixture(hit, keys, 3);
    daemon_fixture(new_path, keys, 3);
    g_assert_true(g_file_set_contents(hit_native, "native", 6, NULL));
    g_assert_true(g_file_set_contents(hit_tbset, input_data, input_size, NULL));
    /* Direct fixture construction bypasses daemon publication events. Rebuild
     * the real capacity inventory before exercising the publication path. */
    g_assert_cmpint(latcd_cache_capacity_scan(&generation_capacity, directory,
        error, sizeof(error)), ==, 0);
    g_assert_cmpint(publish_snapshot(&config, 0, new_path, input, input,
        false, digest, 4, &response), ==, -1);
    g_assert_cmpint(response.status, ==, LATCD_STATUS_INVALID_MODULE);
    g_assert_nonnull(strstr(response.message, "not fully covered"));
    g_assert_true(g_file_get_contents(manifest, &after, NULL, NULL));
    g_assert_cmpstr(before, ==, after);
    g_assert_true(g_file_test(old_path, G_FILE_TEST_IS_REGULAR));
    g_free(before);
    g_free(after);
    g_unlink(hit);
    g_unlink(hit_native);
    g_unlink(hit_tbset);
    g_assert_cmpint(latcd_cache_capacity_scan(&generation_capacity, directory,
        error, sizeof(error)), ==, 0);
    g_free(hit_name);
    g_free(hit);
    g_free(hit_native);
    g_free(hit_tbset);
    g_free(input_data);
    g_free(input_sha);
    /* Simulate death at the manifest commit, before normal function cleanup. */
    pid_t child = fork();
    g_assert_cmpint(child, >=, 0);
    if (!child) {
        crash_after_manifest = true;
        publish_snapshot(&config, 0, new_path, NULL, NULL,
                          false, digest, 5, &response);
        _exit(99);
    }
    int child_status = 0;
    g_assert_cmpint(waitpid(child, &child_status, 0), ==, child);
    g_assert_true(WIFEXITED(child_status));
    g_assert_cmpint(WEXITSTATUS(child_status), ==, 88);
    LatcdCurrentManifest committed = {0};
    g_assert_cmpint(current_manifest_read(&config, hex, &committed), ==, 0);
    char *committed_module = g_build_filename(directory, committed.module, NULL);
    char *committed_native = g_build_filename(directory, committed.native, NULL);
    char *committed_tbset = g_build_filename(directory, committed.tbset, NULL);
    struct stat committed_status;
    g_assert_cmpint(stat(committed_module, &committed_status), ==, 0);
    g_assert_cmpuint(committed_status.st_nlink, ==, 1);
    g_assert_true(cached_module_inspect(committed_module, digest, &info));
    g_assert_cmpint(publish_snapshot(&config, 0, new_path, NULL, NULL,
        false, digest, 6, &response), ==, 0);
    LatcdCurrentManifest restarted = {0};
    g_assert_cmpint(current_manifest_read(&config, hex, &restarted), ==, 0);
    g_assert_cmpstr(restarted.module, ==, committed.module);
    current_manifest_clear(&restarted);
    if (*committed.tbset) {
        g_unlink(committed_tbset);
    }
    g_unlink(committed_module);
    g_unlink(committed_native);
    g_free(committed_module);
    g_free(committed_native);
    g_free(committed_tbset);
    current_manifest_clear(&committed);
    g_unlink(old_path);
    g_unlink(new_path);
    g_unlink(input);
    g_unlink(retained);
    g_unlink(manifest);
    g_unlink(tbset_path);
    g_rmdir(temporary);
    g_rmdir(directory);
    g_free(retained);
    g_free(manifest);
    g_free(input);
    g_free(new_path);
    g_free(old_path);
    g_free(tbset_name);
    g_free(tbset_path);
    g_free(native_name);
    g_free(native_path);
    g_free(new_name);
    g_free(old_name);
    g_free(temporary);
    g_free(directory);
    for (unsigned mode = 0; mode < 7; mode++) {
        test_incremental_retention(argv[0], mode);
    }
    puts("test-latcd-coverage: PASS");
    return 0;
}
