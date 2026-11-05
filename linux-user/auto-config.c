#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "auto-config.h"
#include "latcd-client.h"
#include "latc-build-id.h"

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <pwd.h>
#include <spawn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static char *mode, *cache, *socket_path, *module, *autostart;
static char *state, *daemon_path, *compiler_path, *runner_path, *runtime_path;
static bool enabled, managed, can_start, broker_mode;
static int64_t retry_after;

static void load_system_defaults(const char *directory, uid_t owner)
{
    char contents[4097];
    struct stat st;
    const char *requested = getenv("LATX_AOT_V2");
    if (!requested || strcmp(requested, "1") ||
        getenv("LATX_AOT_V2_CACHE_DIR") || getenv("LATX_AOT_V2_LATCD_SOCKET") ||
        getenv("LATX_AOT_V2_MODULE") || getenv("LATX_AOT_V2_JOURNAL_BROKER") ||
        getenv("LATX_AOT_V2_JOURNAL_BROKER_UID")) return;
    int dir = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return;
    if (fstat(dir, &st) || st.st_uid != owner || (st.st_mode & 0022)) {
        close(dir);
        return;
    }
    int fd = openat(dir, "client.env", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    close(dir);
    if (fd < 0) return;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != owner ||
        (st.st_mode & 0022) || st.st_size < 0 || st.st_size > 4096) {
        close(fd);
        return;
    }
    ssize_t size = read(fd, contents, sizeof(contents) - 1);
    close(fd);
    if (size != st.st_size) return;
    contents[size] = '\0';
    if (memchr(contents, '\0', size)) return;
    const char *keys[] = { "LATX_AOT", "LATX_AOT_V2", "LATX_AOT_V2_AUTOSTART",
        "LATX_AOT_V2_KEY_JOURNAL", "LATX_AOT_V2_JOURNAL_BROKER",
        "LATX_AOT_V2_JOURNAL_BROKER_UID", "LATX_AOT_V2_REPORT" };
    char *values[G_N_ELEMENTS(keys)] = { 0 };
    char **lines = g_strsplit(contents, "\n", -1);
    bool valid = true;
    for (char **line = lines; *line && valid; line++) {
        if (!**line) continue;
        char *equals = strchr(*line, '=');
        if (!equals) { valid = false; break; }
        *equals++ = '\0';
        size_t i;
        for (i = 0; i < G_N_ELEMENTS(keys); i++) {
            if (!strcmp(*line, keys[i])) break;
        }
        if (i == G_N_ELEMENTS(keys) || values[i] || !*equals) {
            valid = false;
            break;
        }
        values[i] = equals;
    }
    if (valid && (!values[2] || strcmp(values[2], "0") ||
        !values[3] || strcmp(values[3], "1") ||
        !values[4] || values[4][0] != '/' || !values[5])) valid = false;
    if (valid) {
        char *end;
        errno = 0;
        guint64 uid = g_ascii_strtoull(values[5], &end, 10);
        if (errno || *end || *values[5] == '-' || uid >= UINT32_MAX) valid = false;
    }
    if (valid) {
        for (size_t i = 2; i < G_N_ELEMENTS(keys); i++) {
            if (values[i]) setenv(keys[i], values[i], 0);
        }
    }
    g_strfreev(lines);
}

void lat_aot_config_system_defaults(void)
{
    char executable[4096];
    ssize_t size = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (size < 0 || (size_t)size >= sizeof(executable) - 1 ||
        getauxval(AT_SECURE) || getuid() != geteuid() || getgid() != getegid()) {
        return;
    }
    executable[size] = '\0';
    if (!strcmp(executable, "/usr/bin/latx-x86_64")) {
        load_system_defaults("/etc/lat-aot-v2", 0);
    }
}

#ifdef LAT_AOT_TEST_CONFIG
void lat_aot_test_system_defaults(const char *directory)
{
    load_system_defaults(directory, getuid());
}
#endif

bool lat_aot_config_option(const char *key, const char *value)
{
    char **slot = NULL;
    if (!strcmp(key, "LATX_AOT_V2")) slot = &mode;
    else if (!strcmp(key, "LATX_AOT_V2_CACHE_DIR")) slot = &cache;
    else if (!strcmp(key, "LATX_AOT_V2_LATCD_SOCKET")) slot = &socket_path;
    else if (!strcmp(key, "LATX_AOT_V2_MODULE")) slot = &module;
    else if (!strcmp(key, "LATX_AOT_V2_AUTOSTART")) slot = &autostart;
    if (!slot) return false;
    g_free(*slot);
    *slot = g_strdup(value);
    return true;
}

static bool private_directory(const char *path)
{
    if (!path || path[0] != '/') return false;
    char **parts = g_strsplit(path, "/", -1);
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    bool valid = fd >= 0;
    bool private_ancestor = false;
    for (unsigned int i = 0; valid && parts[i]; i++) {
        if (!*parts[i]) continue;
        if (!strcmp(parts[i], ".") || !strcmp(parts[i], "..")) {
            valid = false;
            break;
        }
        if (mkdirat(fd, parts[i], 0700) && errno != EEXIST) {
            valid = false;
            break;
        }
        int next = openat(fd, parts[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        struct stat st;
        struct statvfs filesystem;
        bool readonly = next >= 0 && !fstatvfs(next, &filesystem) &&
                        (filesystem.f_flag & ST_RDONLY);
        valid = next >= 0 && !fstat(next, &st) &&
            (readonly || st.st_uid == 0 || st.st_uid == geteuid()) &&
            (private_ancestor || !(st.st_mode & 0022) || (st.st_mode & S_ISVTX));
        /* A private user-owned ancestor prevents other users reaching children. */
        if (valid && st.st_uid == geteuid() && !(st.st_mode & 0077))
            private_ancestor = true;
        close(fd);
        fd = next;
    }
    struct stat st;
    valid = valid && !fstat(fd, &st) && st.st_uid == geteuid() &&
            !(st.st_mode & 0077) && (st.st_mode & 0700) == 0700;
    if (fd >= 0) close(fd);
    g_strfreev(parts);
    return valid;
}

static char *xdg_path(const char *variable, const char *home, const char *fallback)
{
    const char *value = getenv(variable);
    return value && value[0] == '/' ? g_strdup(value) :
        g_build_filename(home, fallback, NULL);
}

void lat_aot_config_environment(void)
{
    const char *keys[] = { "LATX_AOT_V2", "LATX_AOT_V2_CACHE_DIR",
        "LATX_AOT_V2_LATCD_SOCKET", "LATX_AOT_V2_MODULE",
        "LATX_AOT_V2_AUTOSTART", NULL };
    for (int i = 0; keys[i]; i++) {
        const char *value = getenv(keys[i]);
        if (value) lat_aot_config_option(keys[i], value);
    }
}

int lat_aot_config_select(int *legacy, bool explicit_legacy, bool *selected,
                         char *error, size_t error_size)
{
    (void)explicit_legacy;
    const char *broker = getenv("LATX_AOT_V2_JOURNAL_BROKER");
    const char *broker_uid = getenv("LATX_AOT_V2_JOURNAL_BROKER_UID");
    bool broker_requested = broker || broker_uid;
    if (broker_requested) {
        char *end = NULL;
        errno = 0;
        guint64 uid = broker_uid && *broker_uid ?
            g_ascii_strtoull(broker_uid, &end, 10) : UINT64_MAX;
        if (!getenv("LATX_AOT_V2_KEY_JOURNAL") || !broker || broker[0] != '/' ||
            !broker_uid || !*broker_uid || *broker_uid == '-' ||
            !end || *end || errno || uid >= UINT32_MAX) {
            snprintf(error, error_size, "invalid managed broker configuration");
            return -1;
        }
        broker_mode = true;
    }
    if ((mode && strcmp(mode, "0") && strcmp(mode, "1")) ||
        (autostart && strcmp(autostart, "0") && strcmp(autostart, "1"))) {
        snprintf(error, error_size, "AOT v2 enable/autostart values must be 0 or 1");
        return -1;
    }
    *selected = mode ? !strcmp(mode, "1") :
        ((cache && *cache) || (socket_path && *socket_path) || (module && *module) ||
         broker_mode);
    if (!*selected) return 0;
    *legacy = 0;
    return 0;
}

int lat_aot_config_init(int *legacy, bool explicit_legacy, const char *bindir,
                        const char *libdir, char *error, size_t error_size)
{
    if (lat_aot_config_select(legacy, explicit_legacy, &enabled,
                              error, error_size)) {
        return -1;
    }
    if (!enabled) return 0;
    if (getauxval(AT_SECURE) || getuid() != geteuid() || getgid() != getegid()) {
        enabled = false;
        return 0;
    }
    if (broker_mode) {
        managed = false;
        can_start = false;
        daemon_path = g_build_filename(bindir, "latcd", NULL);
        compiler_path = g_build_filename(bindir, "latc", NULL);
        runner_path = g_build_filename(bindir, "latx-x86_64", NULL);
        runtime_path = g_strdup(libdir);
        return 0;
    }
    managed = !(socket_path && *socket_path) && !(module && *module);
    can_start = managed && (!autostart || !strcmp(autostart, "1"));
    if (managed && cache && !*cache) g_clear_pointer(&cache, g_free);
    if (module && !*module) g_clear_pointer(&module, g_free);
    const char *home = getenv("HOME");
    struct passwd *pw = NULL;
    if (!home || home[0] != '/') {
        pw = getpwuid(geteuid());
        home = pw ? pw->pw_dir : NULL;
    }
    if (!home || home[0] != '/') {
        managed = false;
        return 0;
    }
    char *cache_root = xdg_path("XDG_CACHE_HOME", home, ".cache");
    char *state_root = xdg_path("XDG_STATE_HOME", home, ".local/state");
    if (!cache && !module && managed) {
        cache = g_build_filename(cache_root, "lat-aot-v2", LATC_BUILD_ID, "live", NULL);
    }
    state = g_build_filename(state_root, "lat-aot-v2", LATC_BUILD_ID, NULL);
    g_free(cache_root);
    if (managed && private_directory(state) && private_directory(cache)) {
        char *canonical = realpath(cache, NULL);
        char *digest = canonical ? g_compute_checksum_for_string(
            G_CHECKSUM_SHA256, canonical, -1) : NULL;
        free(canonical);
        const char *runtime = getenv("XDG_RUNTIME_DIR");
        char *directory = runtime && private_directory(runtime) ?
            g_build_filename(runtime, "lat-aot-v2", NULL) :
            g_build_filename(state_root, "lat-aot-v2", "run", NULL);
        if (digest && private_directory(directory)) {
            char *identity = g_strconcat(LATC_BUILD_ID, digest, NULL);
            char *socket_digest = g_compute_checksum_for_string(
                G_CHECKSUM_SHA256, identity, -1);
            char *name = g_strdup_printf("%.20s.sock", socket_digest);
            g_free(socket_digest);
            g_free(identity);
            g_free(socket_path);
            socket_path = g_build_filename(directory, name, NULL);
            g_free(name);
        }
        g_free(digest);
        g_free(directory);
    }
    g_free(state_root);
    if (!socket_path) {
        managed = false;
        g_clear_pointer(&socket_path, g_free);
    }
    daemon_path = g_build_filename(bindir, "latcd", NULL);
    compiler_path = g_build_filename(bindir, "latc", NULL);
    runner_path = g_build_filename(bindir, "latx-x86_64", NULL);
    runtime_path = g_strdup(libdir);
    return 0;
}

const char *lat_aot_cache_path(void) { return enabled ? cache : NULL; }
const char *lat_aot_socket_path(void) { return enabled ? socket_path : NULL; }
const char *lat_aot_module_path(void) { return enabled ? module : NULL; }
bool lat_aot_broker_enabled(void) { return enabled && broker_mode; }

static bool cache_identity(uint8_t digest[32])
{
    bool check_cache = cache && *cache;
    char *canonical = check_cache ? realpath(cache, NULL) : NULL;
    if (check_cache && !canonical) return false;
    if (canonical) {
        GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
        g_checksum_update(checksum, (const guchar *)canonical, strlen(canonical));
        gsize size = 32;
        g_checksum_get_digest(checksum, digest, &size);
        g_checksum_free(checksum);
        free(canonical);
    }
    return true;
}

static bool hello(void)
{
    char error[256];
    uint8_t digest[32];
    if (!cache_identity(digest)) return false;
    return !latcd_client_hello(socket_path, LATC_BUILD_ID,
                              cache && *cache ? digest : NULL, error, sizeof(error));
}

int lat_aot_open_existing_channel(char *error, size_t error_size)
{
    return lat_aot_open_existing_channel_protected(NULL, error, error_size);
}

int lat_aot_open_existing_channel_protected(
    const struct LatcdClientFdProtection *protection,
    char *error, size_t error_size)
{
    if (!enabled || !socket_path || !*socket_path) {
        errno = EINVAL;
        snprintf(error, error_size, "latcd is not configured");
        return -1;
    }
    uint8_t digest[32];
    if (!cache_identity(digest)) {
        snprintf(error, error_size, "cannot resolve channel cache identity: %s",
                 strerror(errno));
        return -1;
    }
    return latcd_client_open_channel_protected(socket_path, LATC_BUILD_ID,
        cache && *cache ? digest : NULL, protection, error, error_size);
}

int lat_aot_open_channel(char *error, size_t error_size)
{
    if (!lat_aot_ensure_daemon()) {
        snprintf(error, error_size, "latcd unavailable before namespace change");
        return -1;
    }
    return lat_aot_open_existing_channel(error, error_size);
}

bool lat_aot_ensure_daemon(void)
{
    if (!enabled || !socket_path) return false;
    if (!managed) return hello();
    if (retry_after > g_get_monotonic_time()) return false;
    if (hello()) return true;
    if (!can_start) return false;
    if (errno != ENOENT && errno != ECONNREFUSED) return false;
    retry_after = g_get_monotonic_time() + 5 * G_USEC_PER_SEC;
    char *lock_path = g_strconcat(socket_path, ".lock", NULL);
    int lock = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    g_free(lock_path);
    struct stat st;
    if (lock < 0) return false;
    if (fstat(lock, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        st.st_nlink != 1 || (st.st_mode & 0077)) {
        close(lock);
        return false;
    }
    int64_t deadline = g_get_monotonic_time() + 7 * G_USEC_PER_SEC;
    while (flock(lock, LOCK_EX | LOCK_NB)) {
        if ((errno != EWOULDBLOCK && errno != EINTR) ||
            g_get_monotonic_time() >= deadline) {
            close(lock);
            return false;
        }
        if (hello()) {
            retry_after = 0;
            close(lock);
            return true;
        }
        g_usleep(25000);
    }
    bool ready = hello();
    if (!ready && (errno == ENOENT || errno == ECONNREFUSED)) {
        char *log_path = g_build_filename(state, "daemon.log", NULL);
        int log = open(log_path, O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
        g_free(log_path);
        if (log >= 0 && !fstat(log, &st) && S_ISREG(st.st_mode) &&
            st.st_uid == geteuid() && st.st_nlink == 1 && !(st.st_mode & 0077)) {
            posix_spawn_file_actions_t actions;
            posix_spawn_file_actions_init(&actions);
            posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
            posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0);
            posix_spawn_file_actions_adddup2(&actions, log, 2);
            posix_spawnattr_t attributes;
            posix_spawnattr_init(&attributes);
            sigset_t empty;
            sigemptyset(&empty);
            posix_spawnattr_setsigmask(&attributes, &empty);
            sigset_t defaults;
            sigfillset(&defaults);
            posix_spawnattr_setsigdefault(&attributes, &defaults);
            posix_spawnattr_setflags(&attributes,
                                    POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
            const char *arguments[] = { daemon_path, "--serve", "--daemonize",
                "--socket", socket_path, "--cache-dir", cache, "--latc", compiler_path,
                "--runner", runner_path, "--runtime-dir", runtime_path,
                "--idle-seconds", "60", NULL };
            char *temporary = g_build_filename(state, "tmp", NULL);
            char *tmpenv = g_strconcat("TMPDIR=", temporary, NULL);
            char *loaderenv = g_strconcat("LD_LIBRARY_PATH=", runtime_path, NULL);
            const char *environment[] = { "PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C",
                "LATX_AOT=0", "LATX_AOT_V2=0", "LATX_AOT_V2_AUTOSTART=0",
                tmpenv, loaderenv, NULL };
            pid_t child;
            /* POSIX spawn does not modify argv/envp, despite its mutable API. */
            if (private_directory(temporary) &&
                !posix_spawn(&child, daemon_path, &actions, &attributes,
                             (char *const *)arguments,
                             (char *const *)environment)) {
                int status;
                for (int i = 0; i < 200; i++) {
                    pid_t result = waitpid(child, &status, WNOHANG);
                    if (result == child || (result < 0 && errno != EINTR)) break;
                    g_usleep(25000);
                    if (i == 199) {
                        kill(child, SIGKILL);
                        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
                    }
                }
                deadline = g_get_monotonic_time() + 2 * G_USEC_PER_SEC;
                while (!(ready = hello()) && g_get_monotonic_time() < deadline) {
                    if (errno != ENOENT && errno != ECONNREFUSED) break;
                    g_usleep(25000);
                }
            }
            g_free(loaderenv);
            g_free(tmpenv);
            g_free(temporary);
            posix_spawn_file_actions_destroy(&actions);
            posix_spawnattr_destroy(&attributes);
        }
        if (log >= 0) close(log);
    }
    close(lock);
    if (ready) retry_after = 0;
    return ready;
}
