#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "module-loader.h"

#include "internal-fd-registry.h"
#include "cache-lifecycle.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void fill(unsigned char value, unsigned char output[32])
{
    memset(output, value, 32);
}

static int exec_holder(int argc, char **argv)
{
    if (argc != 5) return 2;
    int pin = atoi(argv[2]), ready = atoi(argv[3]), release = atoi(argv[4]);
    if (fcntl(pin, F_GETFD) != 0) return 1;
    if (!strcmp(argv[1], "--inherited-holder")) {
        uint64_t count, bytes;
        char error[256];
        struct stat st;
        if (fstat(pin, &st) || lat_aot_v2_module_retain_inherited(
                &count, &bytes, error, sizeof(error)) || count != 1 ||
            bytes != (uint64_t)st.st_size ||
            !lat_aot_v2_internal_fd_is_protected(pin) ||
            lat_aot_v2_internal_fd_close_guest(pin) != -1 || errno != EACCES ||
            lat_aot_v2_internal_fd_try_flock(pin, LOCK_UN) != -1 || errno != EACCES ||
            lat_aot_v2_internal_fd_fcntl(pin, F_SETFD, FD_CLOEXEC) != -1 || errno != EACCES)
            return 1;
        if (lat_aot_v2_internal_fd_is_protected(ready) ||
            lat_aot_v2_internal_fd_is_protected(release)) return 1;
        /* Recognition preserves ordinary inherited descriptors and offsets. */
        int ordinary = open("/dev/null", O_RDONLY);
        if (ordinary < 0 || lat_aot_v2_internal_fd_close_guest(ordinary)) return 1;
    }
    char byte = 'x';
    if (write(ready, &byte, 1) != 1 || read(release, &byte, 1) != 1) return 1;
    return 0;
}

static int test_exec_lease(const char *path, const LatAotExpectedV2 *expected,
                           bool retain_in_new_image)
{
    int ready[2], release[2];
    if (pipe(ready) || pipe(release)) return -1;
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        alarm(10);
        close(ready[0]); close(release[1]);
        LatAotLoadedModuleV2 loaded;
        char error[256], pin[32], output[32], input[32];
        if (lat_aot_v2_module_open(path, expected, &loaded, error, sizeof(error))) _exit(1);
        execl("/nonexistent-lat-aot-v2-exec-test", "missing", (char *)NULL);
        if (errno != ENOENT || fcntl(loaded.backing_fd, F_GETFD) != 0) _exit(2);
        int probe = open(path, O_RDONLY | O_CLOEXEC);
        if (probe < 0 || !flock(probe, LOCK_EX | LOCK_NB) || errno != EWOULDBLOCK) _exit(3);
        close(probe);
        snprintf(pin, sizeof(pin), "%d", loaded.backing_fd);
        snprintf(output, sizeof(output), "%d", ready[1]);
        snprintf(input, sizeof(input), "%d", release[0]);
        execl("/proc/self/exe", "test-loader", retain_in_new_image ?
              "--inherited-holder" : "--native-holder", pin, output, input, (char *)NULL);
        _exit(4);
    }
    close(ready[1]); close(release[0]);
    char byte;
    int result = read(ready[0], &byte, 1) != 1;
    int probe = open(path, O_RDONLY | O_CLOEXEC);
    if (probe < 0 || !flock(probe, LOCK_EX | LOCK_NB) || errno != EWOULDBLOCK) result = -1;
    byte = 'x';
    if (write(release[1], &byte, 1) != 1) result = -1;
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) ||
        probe < 0 || flock(probe, LOCK_EX | LOCK_NB)) result = -1;
    if (probe >= 0) close(probe);
    close(ready[0]); close(release[1]);
    return result;
}

static int test_fork_lease(const char *path, const LatAotExpectedV2 *expected)
{
    LatAotLoadedModuleV2 loaded;
    char error[256], byte = 'x';
    int ready[2], release[2];
    if (pipe(ready) || pipe(release) ||
        lat_aot_v2_module_open(path, expected, &loaded, error, sizeof(error))) return -1;
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        alarm(10);
        close(ready[0]); close(release[1]);
        if (write(ready[1], &byte, 1) != 1 || read(release[0], &byte, 1) != 1) _exit(1);
        _exit(0);
    }
    close(ready[1]); close(release[0]);
    int result = read(ready[0], &byte, 1) != 1;
    if (dlclose(loaded.dl_handle) ||
        lat_aot_v2_cache_close_fd(loaded.backing_fd, true, error, sizeof(error))) result = -1;
    int probe = open(path, O_RDONLY | O_CLOEXEC);
    if (probe < 0 || !flock(probe, LOCK_EX | LOCK_NB) || errno != EWOULDBLOCK) result = -1;
    if (write(release[1], &byte, 1) != 1) result = -1;
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) ||
        probe < 0 || flock(probe, LOCK_EX | LOCK_NB)) result = -1;
    if (probe >= 0) close(probe);
    close(ready[0]); close(release[1]);
    return result;
}

static int test_capture_lease(const char *path, const LatAotExpectedV2 *expected)
{
    char error[256];
    int fd = lat_aot_v2_module_capture(path, error, sizeof(error));
    if (fd < 0 || !lat_aot_v2_internal_fd_is_protected(fd) ||
        fcntl(fd, F_GETFD) != 0) return -1;
    int probe = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (probe < 0 || !flock(probe, LOCK_EX | LOCK_NB) || errno != EWOULDBLOCK)
        return -1;
    LatAotExpectedV2 wrong = *expected;
    wrong.source_sha256[0] ^= 1;
    LatAotLoadedModuleV2 module;
    if (!lat_aot_v2_module_load_fd(fd, &wrong, &module, error, sizeof(error)) ||
        fcntl(fd, F_GETFD) != -1 || errno != EBADF ||
        flock(probe, LOCK_EX | LOCK_NB)) return -1;
    close(probe);
    fd = lat_aot_v2_module_capture(path, error, sizeof(error));
    if (fd < 0 || lat_aot_v2_module_load_fd(fd, expected, &module, error, sizeof(error)))
        return -1;
    if (module.backing_fd != fd || dlclose(module.dl_handle) ||
        lat_aot_v2_cache_close_fd(fd, true, error, sizeof(error))) return -1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && (!strcmp(argv[1], "--inherited-holder") ||
                      !strcmp(argv[1], "--native-holder"))) return exec_holder(argc, argv);
    if (argc == 4 && !strcmp(argv[1], "--config")) {
        LatAotExpectedV2 expected = { .available_features = LAT_AOT_V2_REQUIRED_BASE_FEATURES };
        LatAotConfigIdentityV2 config = { .revision = LAT_AOT_CONFIG_NOTE_REVISION,
                                         .schema = 1, .domain = 1 };
        LatAotLoadedModuleV2 loaded;
        char error[256];
        fill(0x11, expected.source_sha256);
        fill(0x22, expected.codegen_id);
        fill(0x44, config.digest);
        int fd = lat_aot_v2_module_capture(argv[2], error, sizeof(error));
        if (fd < 0 || lat_aot_v2_module_load_config_fd(fd, &expected, &config,
                                                        &loaded, error, sizeof(error))) {
            fprintf(stderr, "config load: %s\n", error);
            return 1;
        }
        int ready[2], release[2];
        if (pipe(ready) || pipe(release)) return 1;
        pid_t child = fork();
        if (child < 0) return 1;
        if (!child) {
            char pin[32], out[32], in[32];
            close(ready[0]); close(release[1]);
            snprintf(pin, sizeof(pin), "%d", loaded.backing_fd);
            snprintf(out, sizeof(out), "%d", ready[1]);
            snprintf(in, sizeof(in), "%d", release[0]);
            execl("/proc/self/exe", "test-loader", "--inherited-holder", pin, out, in, (char *)NULL);
            _exit(1);
        }
        close(ready[1]); close(release[0]);
        char byte;
        int inherited_ok = read(ready[0], &byte, 1) == 1;
        if (inherited_ok) inherited_ok = write(release[1], &byte, 1) == 1;
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status)) inherited_ok = 0;
        close(ready[0]); close(release[1]);
        if (!inherited_ok) return 1;
        if (dlclose(loaded.dl_handle) ||
            lat_aot_v2_cache_close_fd(loaded.backing_fd, true, error, sizeof(error))) return 1;
        fd = lat_aot_v2_module_capture(argv[3], error, sizeof(error));
        if (fd < 0 || !lat_aot_v2_module_load_config_fd(fd, &expected, &config,
                                                         &loaded, error, sizeof(error))) return 1;
        fd = lat_aot_v2_module_capture(argv[2], error, sizeof(error));
        if (fd < 0 || !lat_aot_v2_module_load_fd(fd, &expected, &loaded, error, sizeof(error))) return 1;
        puts("test-aot-v2-config-loader: PASS");
        return 0;
    }
    int expect_reject = argc == 3 && !strcmp(argv[1], "--expect-reject");
    int expect_pc_reject =
        argc == 3 && !strcmp(argv[1], "--expect-pc-map-reject");
    if (argc != 2 && !expect_reject && !expect_pc_reject) {
        fprintf(stderr,
                "usage: %s [--expect-reject|--expect-pc-map-reject] "
                "AOT_MODULE\n", argv[0]);
        return 2;
    }
    if (lat_aot_runtime_abi_version() != LAT_AOT_V2_ABI_VERSION) {
        fprintf(stderr, "runtime ABI version mismatch\n");
        return 1;
    }
    LatAotExpectedV2 expected = {
        .available_features = LAT_AOT_V2_REQUIRED_BASE_FEATURES,
    };
    fill(0x11, expected.source_sha256);
    fill(0x22, expected.codegen_id);
    LatAotLoadedModuleV2 module;
    char error[256] = {0};
    const char *module_path = argv[expect_reject || expect_pc_reject ? 2 : 1];
    if (!expect_reject && !expect_pc_reject &&
        (test_capture_lease(module_path, &expected) ||
         test_fork_lease(module_path, &expected) ||
         test_exec_lease(module_path, &expected, true) ||
         test_exec_lease(module_path, &expected, false))) {
        fprintf(stderr, "module exec lease test failed\n");
        return 1;
    }
    int open_result = lat_aot_v2_module_open(module_path, &expected, &module,
                                             error, sizeof(error));
    if (expect_reject) {
        if (!open_result || !strstr(error, "descriptor")) {
            fprintf(stderr, "bad descriptor was not rejected: %s\n", error);
            return 1;
        }
        puts("test-aot-v2-loader-reject: PASS");
        return 0;
    }
    if (expect_pc_reject) {
        if (!open_result || !strstr(error, "PC map")) {
            fprintf(stderr, "bad PC map was not rejected: %s\n", error);
            return 1;
        }
        puts("test-aot-v2-loader-pc-map-reject: PASS");
        return 0;
    }
    if (open_result) {
        fprintf(stderr, "cannot load fixture: %s\n", error);
        return 1;
    }
    if (!lat_aot_v2_internal_fd_is_protected(module.backing_fd)) {
        fprintf(stderr, "loaded module fd is not guest-close protected\n");
        return 1;
    }
    if (module.backing_fd < 0 || fcntl(module.backing_fd, F_GETFD) != 0) {
        fprintf(stderr, "validated module backing fd was not retained\n");
        return 1;
    }
    int contender = open(module_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (contender < 0 || !flock(contender, LOCK_EX | LOCK_NB) ||
        errno != EWOULDBLOCK) {
        fprintf(stderr, "loaded module does not retain a shared GC lease\n");
        if (contender >= 0) close(contender);
        return 1;
    }
    close(contender);


    LatAotRegistryV2 registry;
    if (lat_aot_v2_registry_init(&registry)) {
        perror("registry init");
        return 1;
    }
    LatAotModuleInstanceV2 first = {
        .module = &module,
        .guest_load_bias = 0x400000,
        .guest_begin = 0x400000,
        .guest_end = 0x500000,
    };
    LatAotModuleInstanceV2 second = {
        .module = &module,
        .guest_load_bias = 0x700000,
        .guest_begin = 0x700000,
        .guest_end = 0x800000,
    };
    if (lat_aot_v2_registry_register(&registry, &first) ||
        lat_aot_v2_registry_register(&registry, &second)) {
        perror("registry register");
        return 1;
    }
    LatAotTargetV2 target;
    if (lat_aot_v2_registry_lookup(&registry, 0x401000,
                                   LAT_AOT_TB_CODE64 |
                                   LAT_AOT_TB_PARALLEL, &target) ||
        target.instance != &first) {
        fprintf(stderr, "first module instance lookup failed\n");
        return 1;
    }
    uint64_t (*entry)(void) = (uint64_t (*)(void))target.host_address;
    if (entry() != 42) {
        fprintf(stderr, "fixture TB returned the wrong result\n");
        return 1;
    }
    lat_aot_v2_registry_target_release(&target);
    if (lat_aot_v2_registry_lookup(&registry, 0x701000,
                                   LAT_AOT_TB_CODE64 |
                                   LAT_AOT_TB_PARALLEL, &target) ||
        target.instance != &second) {
        fprintf(stderr, "second module instance lookup failed\n");
        return 1;
    }
    lat_aot_v2_registry_target_release(&target);
    if (lat_aot_v2_registry_deactivate(&registry, &first) ||
        lat_aot_v2_registry_lookup(&registry, 0x401000,
                                   LAT_AOT_TB_CODE64 |
                                   LAT_AOT_TB_PARALLEL, &target) == 0) {
        fprintf(stderr, "multiple instance or deactivation test failed\n");
        return 1;
    }
    lat_aot_v2_registry_destroy(&registry);
    dlclose(module.dl_handle);
    if (lat_aot_v2_cache_close_fd(module.backing_fd, true, error, sizeof(error))) return 1;
    puts("test-aot-v2-loader: PASS");
    return 0;
}
