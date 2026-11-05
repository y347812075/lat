#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "auto-config.h"
#include "latcd-client.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void allocation_lock(void) {}
static void allocation_unlock(void) {}
static int register_fd(int fd) { (void)fd; return 0; }
static void close_fd(int fd) { close(fd); }

static void test_system_defaults(const char *home, int variant)
{
    char dir[1024], path[1100];
    snprintf(dir, sizeof(dir), "%s/system-%d", home, variant);
    assert(!mkdir(dir, 0700));
    snprintf(path, sizeof(path), "%s/client.env", dir);
    FILE *file = fopen(path, "w");
    assert(file);
    assert(fputs("LATX_AOT=0\nLATX_AOT_V2=1\nLATX_AOT_V2_AUTOSTART=0\n"
                 "LATX_AOT_V2_KEY_JOURNAL=1\n"
                 "LATX_AOT_V2_JOURNAL_BROKER=/run/test/broker.sock\n"
                 "LATX_AOT_V2_JOURNAL_BROKER_UID=1234\n"
                 "LATX_AOT_V2_REPORT=1\n", file) >= 0);
    if (variant == 2) assert(fputs("LATX_AOT_V2=0\n", file) >= 0);
    assert(!fclose(file));
    assert(!chmod(path, 0644));
    if (variant == 3) assert(!chmod(path, 0666));
    if (variant == 4) {
        assert(!unlink(path));
        assert(!symlink("/dev/null", path));
    }
    if (variant == 5) assert(!chmod(dir, 0777));
    unsetenv("LATX_AOT_V2");
    unsetenv("LATX_AOT_V2_KEY_JOURNAL");
    unsetenv("LATX_AOT_V2_JOURNAL_BROKER");
    unsetenv("LATX_AOT_V2_JOURNAL_BROKER_UID");
    if (variant == 1) {
        setenv("LATX_AOT_V2", "0", 1);
        setenv("LATX_AOT_V2_KEY_JOURNAL", "1", 1);
        setenv("LATX_AOT_V2_JOURNAL_BROKER", "/inherited", 1);
        unsetenv("LATX_AOT");
    }
    lat_aot_test_system_defaults(dir);
    if (variant == 0) {
        assert(getenv("LATX_AOT_V2"));
        assert(getenv("LATX_AOT_V2_JOURNAL_BROKER_UID"));
        assert(!strcmp(getenv("LATX_AOT_V2"), "1"));
        assert(!strcmp(getenv("LATX_AOT_V2_JOURNAL_BROKER_UID"), "1234"));
    } else {
        assert((variant == 1) == (getenv("LATX_AOT_V2") != NULL));
        assert(!getenv("LATX_AOT_V2_KEY_JOURNAL"));
        assert(!getenv("LATX_AOT_V2_JOURNAL_BROKER"));
        if (variant == 1) assert(!strcmp(getenv("LATX_AOT"), "0"));
    }
    assert(!unlink(path));
    assert(!rmdir(dir));
}

static void run_case(int number)
{
    unsetenv("LATX_AOT_V2");
    unsetenv("LATX_AOT_V2_CACHE_DIR");
    unsetenv("LATX_AOT_V2_LATCD_SOCKET");
    unsetenv("LATX_AOT_V2_MODULE");
    unsetenv("LATX_AOT_V2_AUTOSTART");
    unsetenv("LATX_AOT_V2_KEY_JOURNAL");
    unsetenv("LATX_AOT_V2_JOURNAL_BROKER");
    unsetenv("LATX_AOT_V2_JOURNAL_BROKER_UID");
    int legacy = 1;
    bool explicit = false;
    if (number != 0) setenv("LATX_AOT_V2", "1", 1);
    if (number == 2) explicit = true;
    if (number == 3) legacy = 0;
    if (number == 4) setenv("LATX_AOT_V2", "0", 1);
    if (number == 5) setenv("LATX_AOT_V2", "invalid", 1);
    if (number == 6) {
        setenv("LATX_AOT_V2_CACHE_DIR", "/unused/cache", 1);
        setenv("LATX_AOT_V2_LATCD_SOCKET", "/unused/socket", 1);
    }
    if (number == 8) {
        unsetenv("LATX_AOT_V2");
        setenv("LATX_AOT_V2_CACHE_DIR", "/unused/cache", 1);
        setenv("LATX_AOT_V2_LATCD_SOCKET", "/unused/socket", 1);
    }
    if (number == 9) {
        setenv("LATX_AOT_V2", "0", 1);
        setenv("LATX_AOT_V2_CACHE_DIR", "/unused/cache", 1);
        setenv("LATX_AOT_V2_LATCD_SOCKET", "/unused/socket", 1);
    }
    if (number == 10) {
        legacy = 0;
        explicit = true;
    }
    if (number == 11) {
        setenv("LATX_AOT_V2_CACHE_DIR", "", 1);
        setenv("LATX_AOT_V2_LATCD_SOCKET", "/unused/socket", 1);
    }
    if (number == 13) {
        setenv("LATX_AOT_V2_KEY_JOURNAL", "1", 1);
        setenv("LATX_AOT_V2_JOURNAL_BROKER", "/unused/broker.sock", 1);
        setenv("LATX_AOT_V2_JOURNAL_BROKER_UID", "1234", 1);
    }
    setenv("LATX_AOT_V2_AUTOSTART", number == 12 ? "1" : "0", 1);
    lat_aot_config_environment();
    if (number == 7) lat_aot_config_option("LATX_AOT_V2", "0");
    char error[256];
    int selected_legacy = legacy;
    bool selected = false;
    int selection_rc = lat_aot_config_select(&selected_legacy, explicit,
                                            &selected, error, sizeof(error));
    assert((selection_rc != 0) == (number == 2 || number == 5));
    assert(lat_aot_cache_path() == NULL);
    assert(lat_aot_socket_path() == NULL);
    if (!selection_rc) {
        bool expected = number != 0 && number != 4 && number != 7 && number != 9;
        assert(selected == expected);
        assert(selected_legacy == (expected ? 0 : legacy));
    }
    int rc = lat_aot_config_init(&legacy, explicit, "/usr/bin", "/usr/lib", error, sizeof(error));
    assert((rc != 0) == (number == 2 || number == 5));
    if (!rc) {
        bool v2 = number != 0 && number != 4 && number != 7 && number != 9;
        assert(legacy == (v2 ? 0 : 1));
        if (number == 13) {
            assert(lat_aot_broker_enabled());
            assert(lat_aot_cache_path() == NULL);
            assert(lat_aot_socket_path() == NULL);
        } else {
            assert(!lat_aot_broker_enabled());
            assert((lat_aot_cache_path() != NULL) == v2);
        }
        if (number == 6) {
            assert(!strcmp(lat_aot_cache_path(), "/unused/cache"));
            assert(!strcmp(lat_aot_socket_path(), "/unused/socket"));
        }
        if (number == 11) {
            assert(!*lat_aot_cache_path());
            assert(!strcmp(lat_aot_socket_path(), "/unused/socket"));
        }
        if (v2 && number != 6 && number != 8 && number != 11 && number != 13) {
            assert(lat_aot_socket_path());
            assert(strlen(lat_aot_socket_path()) < 108);
            if (number != 12) assert(!lat_aot_ensure_daemon());
            assert(lat_aot_open_existing_channel(error, sizeof(error)) < 0);
            const LatcdClientFdProtection protection = {
                allocation_lock, allocation_unlock, register_fd, close_fd
            };
            assert(lat_aot_open_existing_channel_protected(
                       &protection, error, sizeof(error)) < 0);
            assert(access(lat_aot_socket_path(), F_OK) != 0);
        }
    }
}

int main(void)
{
    const char *temporary = getenv("TMPDIR");
    assert(temporary);
    char *home = malloc(strlen(temporary) + 32);
    assert(home);
    sprintf(home, "%s/lat-auto-config-XXXXXX", temporary);
    assert(mkdtemp(home));
    setenv("HOME", home, 1);
    unsetenv("XDG_CACHE_HOME");
    unsetenv("XDG_STATE_HOME");
    unsetenv("XDG_RUNTIME_DIR");
    for (int i = 0; i < 6; i++) {
        pid_t child = fork();
        assert(child >= 0);
        if (!child) { test_system_defaults(home, i); _exit(0); }
        int status;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && !WEXITSTATUS(status));
    }
    for (int i = 0; i < 14; i++) {
        pid_t child = fork();
        assert(child >= 0);
        if (!child) { run_case(i); _exit(0); }
        int status;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && !WEXITSTATUS(status));
    }
    puts("auto-config mode matrix passed");
    return 0;
}
