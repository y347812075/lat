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
        assert(!latcd_retirement_prepare(root, source, next, strlen(next),
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
    assert(!latcd_retirement_prepare(root, source, next, strlen(next),
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
    assert(!latcd_retirement_prepare(root, source, next, strlen(next),
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

int main(void)
{
    for (int phase = 0; phase < 3; phase++) {
        test_crash(phase, false);
        test_crash(phase, true);
    }
    test_unknown_and_corrupt();
    test_reboot();
    puts("test-cache-retirement: PASS");
    return 0;
}
