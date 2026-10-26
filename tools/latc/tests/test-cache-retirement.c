#define _GNU_SOURCE
#include "../latcd/cache-retirement.h"

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

int main(void)
{
    for (int phase = 0; phase < 3; phase++) {
        test_crash(phase, false);
        test_crash(phase, true);
    }
    test_unknown_and_corrupt();
    test_reboot();
    for (int mutation = 0; mutation < 7; mutation++) test_object_identity(mutation);
    test_legacy_and_schema();
    test_manifest_binding();
    test_tombstone();
    const char *points[] = {"created", "partial-write", "written", "chmod",
        "file-synced", "closed", "renamed", "directory-synced"};
    for (size_t i = 0; i < G_N_ELEMENTS(points); i++)
        for (int crash = 0; crash < 2; crash++)
            for (int finishing = 0; finishing < 2; finishing++)
                for (int initial = 0; initial < 2; initial++)
                    test_record_write_fault(points[i], crash, finishing, initial);
    for (size_t i = 0; i < G_N_ELEMENTS(points); i++)
        for (int crash = 0; crash < 2; crash++)
            test_tombstone_crash(points[i], crash);
    puts("test-cache-retirement: PASS");
    return 0;
}
