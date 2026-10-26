#define _GNU_SOURCE
#include "../latcd/cache-retirement.h"

#include <assert.h>
#include <fcntl.h>
#include <glib.h>
#include <signal.h>
#include <stdbool.h>
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

static void test_object_identity(int mutation)
{
    char *root = root_new(), *current = current_path(root);
    char *name = g_strconcat(source, ".native", NULL);
    char *path = g_build_filename(root, name, NULL);
    put(path, "immutable native\n");
    const char *names[] = {name};
    char *objects = latcd_retirement_capture_objects(root, source, names, 1);
    assert(objects);
    char error[256], *transaction = NULL;
    assert(!latcd_retirement_prepare(root, source, next, strlen(next), objects,
                                     &transaction, error, sizeof(error)));
    put(current, next);
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

int main(void)
{
    for (int phase = 0; phase < 3; phase++) {
        test_crash(phase, false);
        test_crash(phase, true);
    }
    test_unknown_and_corrupt();
    test_reboot();
    for (int mutation = 0; mutation < 6; mutation++) test_object_identity(mutation);
    test_legacy_and_schema();
    puts("test-cache-retirement: PASS");
    return 0;
}
