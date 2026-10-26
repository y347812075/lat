#define _GNU_SOURCE
#include "../latcd/cache-retirement.h"
#include "../aot-v2/runtime/cache-lifecycle.h"

#include <assert.h>
#include <fcntl.h>
#include <glib.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

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
        char error[256], *transaction = NULL;
        assert(!latcd_retirement_prepare(root, source, next, strlen(next), NULL,
                                         &transaction, error, sizeof(error)));
        if (phase >= 1) put(current, next);
        if (phase >= 2) assert(!latcd_retirement_finish(root, transaction,
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

static void test_unknown_and_corrupt(void)
{
    char *root = root_new(), *transaction = NULL, error[256];
    char *current = current_path(root);
    put(current, old);
    assert(!latcd_retirement_prepare(root, source, next, strlen(next), NULL,
                                     &transaction, error, sizeof(error)));
    put(current, "unrecognized current\n");
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
    g_free(transaction);
    g_free(root);
}

static void test_reboot(void)
{
    char *root = root_new(), *transaction = NULL, error[256];
    char *current = current_path(root);
    assert(!latcd_retirement_prepare(root, source, next, strlen(next), NULL,
                                     &transaction, error, sizeof(error)));
    put(current, next);
    assert(!latcd_retirement_finish(root, transaction, error, sizeof(error)));
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
    g_free(transaction);
    g_free(root);
}

static void test_record_write_fault(const char *point, bool crash,
                                    bool finishing, bool initial)
{
    char *root = root_new(), *current = current_path(root);
    char *transaction = NULL, error[256];
    if (initial) put(current, old);
    if (finishing) {
        assert(!latcd_retirement_prepare(root, source, next, strlen(next), NULL,
                                         &transaction, error, sizeof(error)));
        put(current, next);
    }
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        char *setting = g_strdup_printf("%s:%s", crash ? "crash" : "error", point);
        assert(!setenv("LATCD_TEST_RETIREMENT_IO", setting, 1));
        int result = finishing ?
            latcd_retirement_finish(root, transaction, error, sizeof(error)) :
            latcd_retirement_prepare(root, source, next, strlen(next), NULL,
                                      &transaction, error, sizeof(error));
        assert(!crash && result < 0);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    if (crash) assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    else assert(WIFEXITED(status) && !WEXITSTATUS(status));

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
    g_free(transaction);
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
    char error[256], *transaction = NULL;
    assert(!latcd_retirement_prepare(root, source, manifest, strlen(manifest), objects,
                                     &transaction, error, sizeof(error)));
    put(current, manifest);
    assert(!latcd_retirement_finish(root, transaction, error, sizeof(error)));
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
    g_free(transaction);
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
    char *transaction = NULL, error[256];
    assert(!latcd_retirement_prepare(root, source, next, strlen(next), NULL,
                                     &transaction, error, sizeof(error)));
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
    g_free(transaction);
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

static void assert_tombstone_status(const char *marker, const char *expected)
{
    GKeyFile *record = g_key_file_new();
    assert(g_key_file_load_from_file(record, marker, 0, NULL));
    char *value = g_key_file_get_string(record, "tombstone", "recovery_status", NULL);
    assert(!g_strcmp0(value, expected));
    g_free(value);
    g_key_file_unref(record);
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
    char *current = current_path(root), *transaction = NULL;
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
    assert(evidence && !latcd_retirement_prepare(root, source, following, strlen(following),
        evidence, &transaction, error, sizeof(error)));
    put(current, following);
    assert(!latcd_retirement_finish(root, transaction, error, sizeof(error)));
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
    g_free(previous); g_free(following); g_free(evidence); g_free(transaction);
    g_free(marker); g_free(current); remove_root(root); g_free(root);
}

static void test_recovery_cursor(int mutation, bool tombstones)
{
    char *root = root_new(), error[256], *transaction = NULL;
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
        assert(!latcd_retirement_prepare(root, source, manifest, strlen(manifest), evidence,
                                         &transaction, error, sizeof(error)));
        put(current, manifest);
        assert(!latcd_retirement_finish(root, transaction, error, sizeof(error)));
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
    g_free(manifest); g_free(transaction); remove_root(root); g_free(root);
}

static void test_recovery_entry_budget(void)
{
    char *root = root_new(), error[256], *transaction = NULL;
    assert(!latcd_retirement_prepare(root, source, next, strlen(next), NULL,
                                     &transaction, error, sizeof(error)));
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
    g_free(store); g_free(transaction); remove_root(root); g_free(root);
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
    assert(latcd_tombstone_delete_due(root, name, 0, error, sizeof(error)));
    assert(!access(path, F_OK));
    g_free(evidence); g_free(path); g_free(name); remove_root(root); g_free(root);
}

static void test_transaction_root_admission(unsigned mutation, bool executor)
{
    char *root = root_new(), error[256], *transaction = NULL;
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
    assert(evidence && !latcd_retirement_prepare(root, source, following, strlen(following), evidence,
        &transaction, error, sizeof(error)));
    put(current, following);
    if (mutation != 1) assert(!latcd_retirement_finish(root, transaction, error, sizeof(error)));
    char *record_path = g_build_filename(root, ".gc", "transactions", transaction, NULL);
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
    char *raw = g_key_file_to_data(record, NULL, NULL);
    put(record_path, raw);
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
    int result = executor ? latcd_tombstone_delete_due(root, names[0], 0, error, sizeof(error)) :
        latcd_retirement_tombstone(root, source, names[0], fd, single, error, sizeof(error));
    close(fd);
    bool accepted = !mutation || (!executor && mutation >= 10);
    assert((result == 0) == accepted);
    if (!mutation && !executor) assert(!latcd_tombstone_delete(root, names[0], error, sizeof(error)));
    assert((access(paths[0], F_OK) == 0) == (mutation != 0));
    g_free(raw); g_key_file_unref(record); g_free(record_path); g_free(evidence);
    g_free(single); g_free(current); g_free(previous); g_free(following); g_free(transaction);
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

int main(void)
{
    test_explicit_holds();
    test_due_without_retirement();
    for (unsigned mutation = 0; mutation < 15; mutation++) {
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
    test_unknown_and_corrupt();
    test_reboot();
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
