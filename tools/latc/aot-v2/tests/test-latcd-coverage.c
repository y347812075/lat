#define dlopen coverage_dlopen
#define dlsym coverage_dlsym
#define dlclose coverage_dlclose
#define rename coverage_rename
#define pread coverage_pread
#define main latcd_program_main
#include "../../latcd/main.c"
#undef main
#undef dlopen
#undef dlsym
#undef dlclose
#undef rename
#undef pread
#include <glib/gstdio.h>

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
    LatAotModuleInfoV2 info;
    g_assert_cmpint(lat_aot_v2_module_inspect_file(old, &info, error, sizeof(error)), ==, 0);
    pthread_mutex_lock(&cache_lock);
    g_assert_cmpint(publish_current_index(&config, hex, old_name, native_name,
        input_name, &info, 1, true, error, sizeof(error)), ==, 0);
    pthread_mutex_unlock(&cache_lock);
    if (mode == 3) g_assert_cmpint(g_unlink(native), ==, 0);
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
    g_assert_cmpint(reserve_compile_space(LATCD_MAX_WORKERS, same, available, bytes, error, sizeof(error)), ==, -1);
    uint64_t n = UINT64_MAX - 1;
    g_assert_false(space_add(&n, 1, 2));
    g_assert_cmpuint(n, ==, UINT64_MAX - 1);
}

int main(int argc, char **argv)
{
    if (argc > 1 && (!strcmp(argv[1], "build-id") ||
                     !strcmp(argv[1], "--latc-build-id"))) {
        puts(LATC_BUILD_ID);
        return 0;
    }
    if (argc == 1) {
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
