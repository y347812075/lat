#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "latcd-protocol.h"
#include "lat-aot-v2.h"
#include "lat-tb-key-set.h"
#include "cache-lifecycle.h"
#include "latc-build-id.h"
#include "module-inspect.h"
#include "precompile.h"
#include "journal-store.h"
#include "cache-retirement.h"
#include "cache-capacity.h"

#include <dlfcn.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>

#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#if GLIB_CHECK_VERSION(2, 64, 0)
#define LATCD_SPAWN_CHECK_EXIT_STATUS g_spawn_check_wait_status
#else
#define LATCD_SPAWN_CHECK_EXIT_STATUS g_spawn_check_exit_status
#endif

#define LATCD_DEFAULT_MAX_INPUT (UINT64_C(1) << 30)
#define LATCD_DEFAULT_MAX_JOBS 64u
#define LATCD_DEFAULT_MAX_QUEUE_BYTES (UINT64_C(4) << 30)
#define LATCD_DEFAULT_MAX_CACHE_BYTES (UINT64_C(16) << 30)
#define LATCD_AUTO_WORKERS_MAX 8u
#define LATCD_MAX_WORKERS 32u
#define LATCD_DEFAULT_MAX_NEGATIVE 128u
#define LATCD_DEFAULT_NEGATIVE_MS 30000u
#define LATCD_DEFAULT_CPU_SECONDS 1200u
#define LATCD_DEFAULT_ADDRESS_SPACE (UINT64_C(1) << 40)
#define LATCD_DEFAULT_FILE_SIZE (UINT64_C(2) << 30)
#define LATCD_DEFAULT_OPEN_FILES 256u
#define LATCD_BATCH_QUIET_US (INT64_C(100) * 1000)
#define LATCD_BATCH_MAX_US (INT64_C(500) * 1000)
#define LATCD_SUPERSEDED_DIRNAME ".superseded"
#define LATCD_MAX_CHANNELS 128u
#define LATCD_MAX_FLUSHES 128u

typedef struct LatcdConfig {
    const char *socket_path;
    const char *cache_dir;
    const char *compiler;
    const char *runner;
    const char *runtime_dir;
    const char *x86_rootfs;
    const char *stats_path;
    uint64_t max_input;
    uint64_t address_space_limit;
    uint64_t file_size_limit;
    uint64_t max_queue_bytes;
    uint64_t max_cache_bytes;
    uint32_t max_jobs;
    uint32_t workers;
    uint32_t max_negative;
    uint32_t negative_ms;
    uint32_t cpu_seconds;
    uint32_t open_files;
    bool flush_only;
    uint32_t idle_seconds;
} LatcdConfig;

typedef struct LatcdCurrentManifest {
    char *module;
    char *native;
    char *tbset;
    char *module_sha256;
    char *native_sha256;
    uint64_t published_sequence;
} LatcdCurrentManifest;

static void current_manifest_clear(LatcdCurrentManifest *manifest);
static bool current_manifest_equal(const LatcdCurrentManifest *first,
                                    const LatcdCurrentManifest *second);
static int current_manifest_read(const LatcdConfig *config, const char *hex,
                                 LatcdCurrentManifest *manifest);
static int persisted_manifest_valid(const LatcdConfig *config,
                                    const char source_key[65],
                                    const uint8_t digest[32]);
static int cached_module_inspect(const char *path, const uint8_t digest[32],
                                 LatAotModuleInfoV2 *info);
static _Atomic unsigned int active_precompiles;

static uint32_t default_worker_count(void)
{
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    if (online < 1) {
        return 1;
    }
    return MIN((uint32_t)online, LATCD_AUTO_WORKERS_MAX);
}

typedef struct LatcdJob {
    char *snapshot;
    struct stat source_identity;
    char *tbset;
    bool tbset_canonical;
    bool static_tbset;
    bool running;
    bool dirty;
    char key[130];
    char source_key[65];
    uint8_t digest[32];
    uint32_t priority;
    uint64_t sequence;
    uint64_t accepted_sequence;
    uint64_t compile_sequence;
    uint64_t flush_sequence;
    uint64_t source_size;
    int64_t batch_started_at_us;
    int64_t ready_at_us;
} LatcdJob;

typedef struct LatcdSourceState {
    uint64_t accepted_sequence;
    uint64_t runtime_accepted_sequence;
    uint64_t published_sequence;
    uint64_t failed_sequence;
} LatcdSourceState;

typedef struct LatcdNegativeEntry {
    uint32_t failures;
    int status;
    int64_t retry_at_us;
} LatcdNegativeEntry;

typedef struct LatcdJournalReceiptState {
    char digest[65];
    uint8_t source_sha256[32];
} LatcdJournalReceiptState;

typedef struct LatcdStaticBarrier {
    char source_key[65];
    uint64_t first_sequence;
    uint64_t last_sequence;
    bool failed;
} LatcdStaticBarrier;

typedef struct LatcdService {
    const LatcdConfig *config;
    pthread_mutex_t lock;
    pthread_cond_t ready;
    GPtrArray *queue;
    GHashTable *active;
    GHashTable *running_sources;
    GHashTable *negative;
    GHashTable *source_states;
    GHashTable *static_barriers;
    GHashTable *journal_receipts;
    pthread_t *workers;
    int stopping;
    uint64_t next_sequence;
    uint64_t requests;
    uint64_t queued;
    uint64_t deduplicated;
    uint64_t cache_hits;
    uint64_t compiled;
    uint64_t failed;
    uint64_t negative_hits;
    uint64_t queue_full;
    uint64_t queued_bytes;
} LatcdService;

typedef struct LatcdWorker {
    LatcdService *service;
    uint32_t index;
} LatcdWorker;

typedef struct LatcdFlushTarget {
    char source_key[65];
    uint64_t sequence;
    uint64_t runtime_sequence;
} LatcdFlushTarget;

typedef struct LatcdFlushRequest {
    int client_fd;
    GArray *targets;
    LatcdResponseV2 response;
} LatcdFlushRequest;

typedef struct LatcdPrecompileRequest {
    const LatcdConfig *config;
    int client_fd;
    int source_fd;
    uint64_t request_id;
} LatcdPrecompileRequest;

static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t compiler_process_groups[LATCD_MAX_WORKERS];
static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
static LatcdCacheCapacity generation_capacity = LATCD_CACHE_CAPACITY_INIT;
/* Admission stays closed until both persistent compiler budget passes finish. */
static atomic_int compiler_budget_recovery_state;
typedef struct LatcdBudgetRecovery {
    DIR *cursor;
    bool scanning_tasks;
    unsigned visited;
} LatcdBudgetRecovery;
static LatcdBudgetRecovery compiler_budget_recovery;
static pthread_mutex_t retirement_queue_lock = PTHREAD_MUTEX_INITIALIZER;
static LatcdRetirementQueueStats retirement_queue_stats;

static int fail(char *error, size_t error_size, const char *format, ...);

typedef struct CompileSpaceReservation {
    dev_t device[2];
    uint64_t bytes[2];
    bool active;
} CompileSpaceReservation;

static pthread_mutex_t compile_space_lock = PTHREAD_MUTEX_INITIALIZER;
static CompileSpaceReservation compile_space[LATCD_MAX_WORKERS];

static bool space_add(uint64_t *value, uint64_t amount, uint64_t multiplier)
{
    if (multiplier && amount > (UINT64_MAX - *value) / multiplier) return false;
    *value += amount * multiplier;
    return true;
}

static int reserve_compile_space(uint32_t worker, const dev_t devices[2],
                                  const uint64_t available[2], const uint64_t bytes[2],
                                  char *error, size_t error_size)
{
    if (worker >= LATCD_MAX_WORKERS) return fail(error, error_size, "invalid reservation worker");
    CompileSpaceReservation request = { .active = true };
    memcpy(request.device, devices, sizeof(request.device));
    memcpy(request.bytes, bytes, sizeof(request.bytes));
    if (devices[0] == devices[1]) {
        if (!space_add(&request.bytes[0], request.bytes[1], 1))
            return fail(error, error_size, "capacity reservation overflow");
        request.bytes[1] = 0;
    }
    pthread_mutex_lock(&compile_space_lock);
    int result = 0;
    if (compile_space[worker].active) result = -1;
    for (size_t i = 0; !result && i < 2; i++) {
        if (!request.bytes[i]) continue;
        uint64_t required = request.bytes[i];
        for (size_t j = 0; !result && j < LATCD_MAX_WORKERS; j++) {
            if (!compile_space[j].active) continue;
            for (size_t k = 0; k < 2; k++)
                if (compile_space[j].device[k] == request.device[i] &&
                    !space_add(&required, compile_space[j].bytes[k], 1)) result = -1;
        }
        uint64_t free_bytes = available[i];
        if (devices[0] == devices[1]) free_bytes = MIN(available[0], available[1]);
        if (required > free_bytes) result = -1;
    }
    if (!result) compile_space[worker] = request;
    pthread_mutex_unlock(&compile_space_lock);
    return result ? fail(error, error_size, "capacity: insufficient filesystem space or active reservations") : 0;
}

static void release_compile_space(uint32_t worker)
{
    pthread_mutex_lock(&compile_space_lock);
    if (worker < LATCD_MAX_WORKERS) memset(&compile_space[worker], 0, sizeof(compile_space[worker]));
    pthread_mutex_unlock(&compile_space_lock);
}

static int compile_space_admit(uint32_t worker, const char *temporary,
                               const char *output, const char *source, const char *tbset,
                               const char *base_native, const char *base_module,
                               uint64_t *cache_peak, char *error, size_t error_size)
{
    /* Estimate, not a hard quota: reserve translation/merge/link coexistence.
     * Existing bytes are already reflected in statvfs; other reservations are
     * deliberately counted in full even if partially materialized. */
    uint64_t estimate = UINT64_C(64) << 20;
    const char *inputs[] = {source, tbset, base_native, base_module};
    const uint64_t factors[] = {4, 4096, 4, 4};
    for (size_t i = 0; i < G_N_ELEMENTS(inputs); i++) {
        if (!inputs[i]) continue;
        struct stat st;
        if (stat(inputs[i], &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
            !space_add(&estimate, st.st_size, factors[i]))
            return fail(error, error_size, "capacity: cannot estimate compile input");
    }
    char *parent = g_path_get_dirname(output);
    const char *paths[] = {temporary, parent};
    dev_t devices[2];
    uint64_t available[2], bytes[] = {estimate, estimate};
    int result = 0;
    for (size_t i = 0; i < 2; i++) {
        struct stat st;
        struct statvfs fs;
        if (stat(paths[i], &st) || !S_ISDIR(st.st_mode) || statvfs(paths[i], &fs) ||
            !fs.f_frsize || fs.f_bavail > UINT64_MAX / fs.f_frsize) {
            result = fail(error, error_size, "capacity: cannot inspect compile filesystem");
            break;
        }
        devices[i] = st.st_dev;
        available[i] = (uint64_t)fs.f_bavail * fs.f_frsize;
    }
    if (!result) result = reserve_compile_space(worker, devices, available, bytes, error, error_size);
    if (!result) *cache_peak = estimate;
    g_free(parent);
    return result;
}

static LatcdSourceState *source_state_locked(LatcdService *service,
                                             const char *source_key);

static int fail(char *error, size_t error_size, const char *format, ...)
{
    if (error && error_size) {
        va_list arguments;
        va_start(arguments, format);
        vsnprintf(error, error_size, format, arguments);
        va_end(arguments);
    }
    return -1;
}

static int sync_directory(const char *path, char *error, size_t error_size);

static void digest_hex(const uint8_t digest[32], char hex[65])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    hex[64] = '\0';
}

static void expected_codegen_id(uint8_t digest[32])
{
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(checksum, (const guchar *)LATC_BUILD_ID,
                      strlen(LATC_BUILD_ID));
    gsize length = 32;
    g_checksum_get_digest(checksum, digest, &length);
    g_checksum_free(checksum);
}

static int read_program_build_id(const char *label, const char *path,
                                 const char *argument,
                                 const char *runtime_dir,
                                 char actual[65], char *error,
                                 size_t error_size)
{
    int output[2];
    if (pipe2(output, O_CLOEXEC | O_NONBLOCK)) {
        return fail(error, error_size, "cannot probe %s %s: %s", label, path,
                    strerror(errno));
    }
    pid_t child = fork();
    if (child == 0) {
        dup2(output[1], STDOUT_FILENO);
        close(output[0]);
        close(output[1]);
        if (runtime_dir) {
            setenv("LD_LIBRARY_PATH", runtime_dir, 1);
        }
        execl(path, path, argument, (char *)NULL);
        _exit(127);
    }
    close(output[1]);
    if (child < 0) {
        close(output[0]);
        return fail(error, error_size, "cannot start %s %s: %s", label, path,
                    strerror(errno));
    }

    char buffer[128] = {0};
    size_t used = 0;
    int status = 0;
    int64_t deadline = g_get_monotonic_time() + 2 * G_TIME_SPAN_SECOND;
    for (;;) {
        struct pollfd poll_fd = { .fd = output[0], .events = POLLIN | POLLHUP };
        int64_t remaining = deadline - g_get_monotonic_time();
        if (remaining <= 0) {
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            close(output[0]);
            return fail(error, error_size, "%s identity probe timed out: %s",
                        label, path);
        }
        poll(&poll_fd, 1, MIN(50, (int)(remaining / 1000)));
        ssize_t count;
        while (used < sizeof(buffer) - 1 &&
               (count = read(output[0], buffer + used,
                             sizeof(buffer) - 1 - used)) > 0) {
            used += count;
        }
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            while (used < sizeof(buffer) - 1 &&
                   (count = read(output[0], buffer + used,
                                 sizeof(buffer) - 1 - used)) > 0) {
                used += count;
            }
            break;
        }
        if (waited < 0 && errno != EINTR) {
            close(output[0]);
            return fail(error, error_size, "cannot wait for %s identity: %s",
                        label, strerror(errno));
        }
    }
    close(output[0]);
    buffer[used] = '\0';
    g_strchomp(buffer);
    if (!WIFEXITED(status) || WEXITSTATUS(status) || strlen(buffer) != 64) {
        return fail(error, error_size,
                    "%s identity probe failed for %s (status=%d, output=%s)",
                    label, path, WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                    buffer[0] ? buffer : "<empty>");
    }
    memcpy(actual, buffer, 65);
    return 0;
}

static int validate_toolchain(const LatcdConfig *config, char *error,
                              size_t error_size)
{
    char actual[65];
    if (read_program_build_id("latc", config->compiler, "build-id",
                              config->runtime_dir, actual, error, error_size)) {
        return -1;
    }
    if (strcmp(actual, LATC_BUILD_ID)) {
        return fail(error, error_size,
                    "latc build identity mismatch: %s expected=%s actual=%s",
                    config->compiler, LATC_BUILD_ID, actual);
    }
    if (read_program_build_id("runner", config->runner, "--latc-build-id",
                              config->runtime_dir, actual, error, error_size)) {
        return -1;
    }
    if (strcmp(actual, LATC_BUILD_ID)) {
        return fail(error, error_size,
                    "runner build identity mismatch: %s expected=%s actual=%s",
                    config->runner, LATC_BUILD_ID, actual);
    }

    char *runtime_path = g_build_filename(
        config->runtime_dir, LAT_AOT_V2_RUNTIME_SONAME, NULL);
    void *runtime = dlopen(runtime_path, RTLD_NOW | RTLD_LOCAL);
    if (!runtime) {
        fail(error, error_size, "cannot load AOT runtime %s: %s", runtime_path,
             dlerror());
        g_free(runtime_path);
        return -1;
    }
    uint32_t (*abi_version)(void) = dlsym(runtime,
        "lat_aot_runtime_abi_version");
    const char *(*build_id)(void) = dlsym(runtime,
        "lat_aot_runtime_build_id");
    if (!abi_version || !build_id || abi_version() != LAT_AOT_V2_ABI_VERSION) {
        dlclose(runtime);
        int result = fail(error, error_size,
                          "AOT runtime ABI mismatch: %s expected=%u",
                          runtime_path, LAT_AOT_V2_ABI_VERSION);
        g_free(runtime_path);
        return result;
    }
    const char *runtime_id = build_id();
    if (!runtime_id || strcmp(runtime_id, LATC_BUILD_ID)) {
        char mismatch[65] = {0};
        g_strlcpy(mismatch, runtime_id ? runtime_id : "<missing>",
                  sizeof(mismatch));
        dlclose(runtime);
        int result = fail(error, error_size,
                          "AOT runtime build identity mismatch: %s expected=%s actual=%s",
                          runtime_path, LATC_BUILD_ID, mismatch);
        g_free(runtime_path);
        return result;
    }
    dlclose(runtime);
    g_free(runtime_path);
    return 0;
}

static void signal_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static int recover_lifecycle(const char *root, bool tombstones,
                             char *error, size_t error_size)
{
    LatcdRecoveryCursor *cursor = latcd_recovery_open(root, tombstones, error, error_size);
    if (!cursor) return -1;
    LatcdRecoveryProgress progress = {0};
    int result = 1;
    while (!stop_requested && result > 0)
        result = latcd_recovery_step(cursor, 32, 4 * 1024 * 1024, 10000,
                                     &progress, error, error_size);
    latcd_recovery_close(cursor);
    fprintf(stderr, "latcd: %s recovery %s visited=%u recovered=%u hashed_bytes=%" PRIu64 "\n",
        tombstones ? "tombstone" : "retirement", stop_requested ? "interrupted" :
        result < 0 ? "failed" : "complete", progress.visited, progress.recovered,
        progress.hashed_bytes);
    return stop_requested ? 1 : result;
}

static int ensure_private_directory(const char *path, char *error,
                                    size_t error_size)
{
    if (g_mkdir_with_parents(path, 0700)) {
        return fail(error, error_size, "cannot create %s: %s", path,
                    strerror(errno));
    }
    struct stat status;
    if (lstat(path, &status) || !S_ISDIR(status.st_mode) ||
        status.st_uid != geteuid()) {
        return fail(error, error_size, "%s is not a user-owned directory",
                    path);
    }
    if (chmod(path, 0700)) {
        return fail(error, error_size, "cannot protect %s: %s", path,
                    strerror(errno));
    }
    return 0;
}

static int acquire_cache_owner(const LatcdConfig *config, char *error,
                               size_t error_size)
{
    if (ensure_private_directory(config->cache_dir, error, error_size)) {
        return -1;
    }
    char *path = g_build_filename(config->cache_dir, ".latcd.lock", NULL);
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        fail(error, error_size, "cannot open cache owner lock %s: %s", path,
             strerror(errno));
        g_free(path);
        return -1;
    }
    struct stat status;
    if (fstat(fd, &status) || !S_ISREG(status.st_mode) ||
        status.st_uid != geteuid() || status.st_nlink != 1 ||
        fchmod(fd, 0600)) {
        fail(error, error_size,
             "cache owner lock is not a private user-owned file: %s", path);
        close(fd);
        g_free(path);
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB)) {
        if (errno == EWOULDBLOCK) {
            fail(error, error_size,
                 "cache is already owned by another latcd: %s",
                 config->cache_dir);
        } else {
            fail(error, error_size, "cannot lock cache %s: %s",
                 config->cache_dir, strerror(errno));
        }
        close(fd);
        g_free(path);
        return -1;
    }
    char *owner = g_strdup_printf("pid=%ld\nsocket=%s\nbuild_id=%s\n",
                                  (long)getpid(), config->socket_path, LATC_BUILD_ID);
    size_t length = strlen(owner);
    if (ftruncate(fd, 0) || pwrite(fd, owner, length, 0) != (ssize_t)length ||
        fsync(fd)) {
        fail(error, error_size, "cannot record cache owner in %s: %s", path,
             strerror(errno));
        close(fd);
        g_free(owner);
        g_free(path);
        return -1;
    }
    g_free(owner);
    g_free(path);
    return fd;
}

static int validate_x86_elf(int fd, uint64_t file_size, char *error,
                            size_t error_size)
{
    Elf64_Ehdr header;
    if (file_size < sizeof(header) ||
        pread(fd, &header, sizeof(header), 0) != sizeof(header)) {
        return fail(error, error_size, "source is too small for an ELF header");
    }
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) ||
        header.e_ident[EI_CLASS] != ELFCLASS64 ||
        header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_machine != EM_X86_64 ||
        (header.e_type != ET_EXEC && header.e_type != ET_DYN) ||
        header.e_phentsize != sizeof(Elf64_Phdr) || !header.e_phnum ||
        header.e_phoff > file_size ||
        header.e_phnum > (file_size - header.e_phoff) / sizeof(Elf64_Phdr)) {
        return fail(error, error_size,
                    "source is not a supported x86-64 executable ELF");
    }
    int executable_load = 0;
    for (uint16_t i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr program;
        off_t offset = header.e_phoff + (off_t)i * sizeof(program);
        if (pread(fd, &program, sizeof(program), offset) != sizeof(program) ||
            program.p_offset > file_size ||
            program.p_filesz > file_size - program.p_offset) {
            return fail(error, error_size, "source ELF program headers are invalid");
        }
        if (program.p_type == PT_LOAD && (program.p_flags & PF_X)) {
            executable_load = 1;
        }
    }
    if (!executable_load) {
        return fail(error, error_size, "source ELF has no executable PT_LOAD");
    }
    return 0;
}

static int metadata_equal(const struct stat *before, const struct stat *after)
{
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_size == after->st_size &&
           before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}

static int snapshot_source(int source_fd, const char *temporary_dir,
                           uint64_t max_input, char **snapshot_path,
                           uint8_t digest[32], struct stat *identity,
                           char *error, size_t error_size)
{
    struct stat before;
    int flags = fcntl(source_fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
        fstat(source_fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_size < 0 || (uint64_t)before.st_size > max_input) {
        return fail(error, error_size,
                    "source descriptor must be a bounded read-only regular file");
    }
    if (validate_x86_elf(source_fd, before.st_size, error, error_size)) {
        return -1;
    }
    char *path = g_build_filename(temporary_dir, "source-XXXXXX", NULL);
    int output = g_mkstemp_full(path, O_RDWR | O_CLOEXEC, 0600);
    if (output < 0) {
        g_free(path);
        return fail(error, error_size, "cannot create source snapshot: %s",
                    strerror(errno));
    }
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    unsigned char buffer[128 * 1024];
    off_t offset = 0;
    int result = -1;
    while ((uint64_t)offset < (uint64_t)before.st_size) {
        size_t wanted = sizeof(buffer);
        if (wanted > (uint64_t)before.st_size - (uint64_t)offset) {
            wanted = before.st_size - offset;
        }
        ssize_t count = pread(source_fd, buffer, wanted, offset);
        if (count <= 0) {
            fail(error, error_size, "cannot read source descriptor: %s",
                 count < 0 ? strerror(errno) : "unexpected end of file");
            goto out;
        }
        ssize_t written = 0;
        while (written < count) {
            ssize_t part = write(output, buffer + written, count - written);
            if (part < 0 && errno == EINTR) {
                continue;
            }
            if (part <= 0) {
                fail(error, error_size, "cannot write source snapshot: %s",
                     strerror(errno));
                goto out;
            }
            written += part;
        }
        g_checksum_update(checksum, buffer, count);
        offset += count;
    }
    struct stat after;
    if (fstat(source_fd, &after) || !metadata_equal(&before, &after)) {
        fail(error, error_size, "source changed while creating snapshot");
        goto out;
    }
    if (fsync(output)) {
        fail(error, error_size, "cannot sync source snapshot: %s",
             strerror(errno));
        goto out;
    }
    gsize digest_size = 32;
    g_checksum_get_digest(checksum, digest, &digest_size);
    if (identity) {
        *identity = before;
    }
    *snapshot_path = path;
    path = NULL;
    result = 0;
out:
    g_checksum_free(checksum);
    close(output);
    if (path) {
        unlink(path);
        g_free(path);
    }
    return result;
}

static int hash_source(int source_fd, uint64_t max_input, uint8_t digest[32],
                       char *error, size_t error_size)
{
    struct stat before;
    int flags = fcntl(source_fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
        fstat(source_fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_size < 0 || (uint64_t)before.st_size > max_input) {
        return fail(error, error_size,
                    "source descriptor must be a bounded read-only regular file");
    }
    if (validate_x86_elf(source_fd, before.st_size, error, error_size)) {
        return -1;
    }
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    unsigned char buffer[128 * 1024];
    off_t offset = 0;
    while ((uint64_t)offset < (uint64_t)before.st_size) {
        size_t wanted = sizeof(buffer);
        if (wanted > (uint64_t)before.st_size - (uint64_t)offset) {
            wanted = before.st_size - offset;
        }
        ssize_t count = pread(source_fd, buffer, wanted, offset);
        if (count <= 0) {
            g_checksum_free(checksum);
            return fail(error, error_size,
                        "cannot read source descriptor: %s",
                        count < 0 ? strerror(errno) : "unexpected end of file");
        }
        g_checksum_update(checksum, buffer, count);
        offset += count;
    }
    struct stat after;
    if (fstat(source_fd, &after) || !metadata_equal(&before, &after)) {
        g_checksum_free(checksum);
        return fail(error, error_size, "source changed while hashing");
    }
    gsize digest_size = 32;
    g_checksum_get_digest(checksum, digest, &digest_size);
    g_checksum_free(checksum);
    return 0;
}

static void publish_source_identity(const LatcdConfig *config,
                                    const struct stat *status,
                                    const uint8_t digest[32])
{
    char error[128];
    char *directory = g_build_filename(config->cache_dir, ".identities", NULL);
    if (ensure_private_directory(directory, error, sizeof(error))) {
        g_free(directory);
        return;
    }
    char *name = g_strdup_printf(
        "%llx-%llx-%llx-%llx-%lx-%llx-%lx.sha256",
        (unsigned long long)status->st_dev,
        (unsigned long long)status->st_ino,
        (unsigned long long)status->st_size,
        (unsigned long long)status->st_mtim.tv_sec,
        (unsigned long)status->st_mtim.tv_nsec,
        (unsigned long long)status->st_ctim.tv_sec,
        (unsigned long)status->st_ctim.tv_nsec);
    char *final = g_build_filename(directory, name, NULL);
    char *temporary = g_strdup_printf("%s.tmp.%ld", final, (long)getpid());
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                  O_NOFOLLOW, 0600);
    if (fd >= 0) {
        static const char digits[] = "0123456789abcdef";
        char text[65];
        for (size_t i = 0; i < 32; i++) {
            text[i * 2] = digits[digest[i] >> 4];
            text[i * 2 + 1] = digits[digest[i] & 15];
        }
        text[64] = '\n';
        if (write(fd, text, sizeof(text)) == sizeof(text) && !fsync(fd)) {
            close(fd);
            fd = -1;
            if (!rename(temporary, final)) {
                sync_directory(directory, error, sizeof(error));
            }
        }
        if (fd >= 0) close(fd);
        unlink(temporary);
    }
    g_free(temporary);
    g_free(final);
    g_free(name);
    g_free(directory);
}

static int snapshot_tbset(int tbset_fd, const char *source_path,
                          const char *temporary_dir,
                          const uint8_t source_digest[32],
                          char **snapshot_path,
                          char *error, size_t error_size)
{
    struct stat status;
    int flags = fcntl(tbset_fd, F_GETFL);
    int seals = fcntl(tbset_fd, F_GET_SEALS);
    bool immutable = seals >= 0 && (seals & F_SEAL_WRITE);
    if (flags < 0 || (!immutable && (flags & O_ACCMODE) != O_RDONLY) ||
        fstat(tbset_fd, &status) || !S_ISREG(status.st_mode) ||
        status.st_size <= 0 || status.st_size > 64 * 1024 * 1024) {
        return fail(error, error_size,
                    "TB set descriptor must be a bounded read-only regular file");
    }
    int source_fd = open(source_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    Elf64_Ehdr header;
    if (source_fd < 0 ||
        pread(source_fd, &header, sizeof(header), 0) != sizeof(header) ||
        header.e_phentsize != sizeof(Elf64_Phdr) || !header.e_phnum ||
        header.e_phnum > 4096) {
        if (source_fd >= 0) close(source_fd);
        return fail(error, error_size, "cannot validate TB set source ELF");
    }
    size_t phdr_size = header.e_phnum * sizeof(Elf64_Phdr);
    Elf64_Phdr *phdrs = g_malloc(phdr_size);
    if (!phdrs || pread(source_fd, phdrs, phdr_size, header.e_phoff) !=
                  (ssize_t)phdr_size) {
        g_free(phdrs);
        close(source_fd);
        return fail(error, error_size, "cannot read TB set source segments");
    }
    close(source_fd);
    uint64_t load_base = UINT64_MAX;
    for (uint16_t i = 0; i < header.e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_memsz &&
            phdrs[i].p_vaddr < load_base) {
            load_base = phdrs[i].p_vaddr;
        }
    }
    if (load_base == UINT64_MAX) {
        g_free(phdrs);
        return fail(error, error_size,
                    "TB set source ELF has no loadable segments");
    }

    LatTbKeySet set;
    if (lat_tb_key_set_read_fd(tbset_fd, source_digest, &set,
                               error, error_size)) {
        g_free(phdrs);
        return -1;
    }
    for (size_t record = 0; record < set.count; record++) {
        uint64_t rva = set.keys[record].guest_rva;
        int executable = 0;
        for (uint16_t i = 0; i < header.e_phnum; i++) {
            uint64_t segment_rva = phdrs[i].p_vaddr - load_base;
            if (phdrs[i].p_type == PT_LOAD && (phdrs[i].p_flags & PF_X) &&
                phdrs[i].p_vaddr >= load_base && rva >= segment_rva &&
                rva - segment_rva < phdrs[i].p_memsz) {
                executable = 1;
                break;
            }
        }
        if (!executable) {
            lat_tb_key_set_destroy(&set);
            g_free(phdrs);
            return fail(error, error_size,
                        "TB key record %zu is outside executable segments",
                        record);
        }
    }
    g_free(phdrs);
    char *path = g_build_filename(temporary_dir, "tbset-XXXXXX", NULL);
    int output_fd = g_mkstemp_full(path, O_RDWR | O_CLOEXEC, 0600);
    if (output_fd < 0) {
        unlink(path);
        g_free(path);
        lat_tb_key_set_destroy(&set);
        return fail(error, error_size, "cannot snapshot TB set: %s",
                    strerror(errno));
    }
    int result = lat_tb_key_set_write_fd(output_fd, &set,
                                          error, error_size) ||
                 fsync(output_fd);
    if (close(output_fd)) result = -1;
    output_fd = -1;
    lat_tb_key_set_destroy(&set);
    if (result) {
        if (output_fd >= 0) close(output_fd);
        unlink(path);
        g_free(path);
        if (!error[0]) fail(error, error_size,
                            "cannot persist TB key set snapshot");
        return -1;
    }
    *snapshot_path = path;
    return 0;
}

static int merge_tbset(const LatcdConfig *config, const uint8_t digest[32],
                       const char *incoming, char **canonical, bool *changed,
                       char *error, size_t error_size)
{
    if (changed) *changed = false;
    char source_hex[65];
    digest_hex(digest, source_hex);
    char *directory = g_build_filename(config->cache_dir, ".tbsets", NULL);
    if (ensure_private_directory(directory, error, error_size)) {
        g_free(directory);
        return -1;
    }
    char *name = g_strdup_printf("%s.tbset", source_hex);
    char *final = g_build_filename(directory, name, NULL);
    g_free(name);
    LatTbKeySet incoming_set = {0};
    LatTbKeySet existing = {0};
    LatTbKeySet merged = {0};
    pthread_mutex_lock(&cache_lock);
    int result = lat_tb_key_set_read_file(incoming, digest, &incoming_set,
                                           error, error_size);
    if (!result && lat_tb_key_set_read_file(final, digest, &existing,
                                             error, error_size)) {
        if (errno != ENOENT) {
            result = -1;
        } else {
            memset(&existing, 0, sizeof(existing));
            memcpy(existing.source_sha256, digest, 32);
            error[0] = '\0';
        }
    }
    uint64_t original_count = existing.count;
    uint64_t original_sequence = existing.sequence;
    if (!result) {
        LatcdCurrentManifest manifest = {0};
        if (!current_manifest_read(config, source_hex, &manifest) &&
            *manifest.tbset &&
            persisted_manifest_valid(config, source_hex, digest)) {
            char *published = g_build_filename(config->cache_dir,
                                                manifest.tbset, NULL);
            LatTbKeySet published_set = {0}, complete = {0};
            result = lat_tb_key_set_read_file(published, digest, &published_set,
                                              error, error_size);
            if (!result) {
                result = lat_tb_key_set_union(&existing, &published_set,
                                               &complete, error, error_size);
            }
            if (!result) {
                lat_tb_key_set_destroy(&existing);
                existing = complete;
            }
            lat_tb_key_set_destroy(&published_set);
            g_free(published);
        }
        current_manifest_clear(&manifest);
    }
    if (!result) {
        result = lat_tb_key_set_union(&existing, &incoming_set, &merged,
                                      error, error_size);
    }
    char *temporary = NULL;
    if (!result) {
        bool content_changed = merged.count != original_count;
        merged.sequence = content_changed ? original_sequence + 1 :
                                            original_sequence;
        if (changed) *changed = content_changed;
        if (!content_changed) goto merged_done;
        temporary = g_build_filename(directory, "tbset-XXXXXX", NULL);
        int fd = g_mkstemp_full(temporary, O_RDWR | O_CLOEXEC, 0600);
        if (fd < 0) {
            result = fail(error, error_size, "cannot create canonical TB set");
        } else {
            if (lat_tb_key_set_write_fd(fd, &merged, error, error_size) ||
                fsync(fd)) result = -1;
            if (close(fd)) result = -1;
            if (!result && rename(temporary, final)) {
                result = -1;
            } else if (!result) {
                result = sync_directory(directory, error, error_size);
            }
            if (result && !error[0]) {
                fail(error, error_size, "cannot publish canonical TB set: %s",
                     strerror(errno));
            }
        }
    }
merged_done:
    if (result && temporary) unlink(temporary);
    pthread_mutex_unlock(&cache_lock);
    lat_tb_key_set_destroy(&incoming_set);
    lat_tb_key_set_destroy(&existing);
    lat_tb_key_set_destroy(&merged);
    g_free(temporary);
    g_free(directory);
    if (result) {
        g_free(final);
        return -1;
    }
    *canonical = final;
    return 0;
}

static int prepare_compile_delta(const LatcdConfig *config,
                                 const uint8_t digest[32],
                                 const char *known_path, char **delta_path,
                                 bool *empty, char *error, size_t error_size)
{
    LatTbKeySet known = {0};
    LatTbKeySet delta = {0};
    *delta_path = NULL;
    *empty = false;
    int result = lat_tb_key_set_read_file(known_path, digest, &known,
                                           error, error_size);
    if (!result) {
        char source_hex[65];
        digest_hex(digest, source_hex);
        LatcdCurrentManifest manifest = {0};
        char *module_path = NULL;
        char *native_path = NULL;
        char *published_path = NULL;
        LatAotModuleInfoV2 info;
        pthread_mutex_lock(&cache_lock);
        bool current_valid = !current_manifest_read(
            config, source_hex, &manifest) && *manifest.tbset;
        if (current_valid) {
            module_path = g_build_filename(config->cache_dir,
                                            manifest.module, NULL);
            native_path = g_build_filename(config->cache_dir,
                                            manifest.native, NULL);
            published_path = g_build_filename(config->cache_dir,
                                               manifest.tbset, NULL);
            current_valid = cached_module_inspect(module_path, digest, &info) &&
                !access(native_path, R_OK) && !access(published_path, R_OK);
        }
        if (current_valid) {
            result = lat_aot_v2_module_missing_tbset_file(
                module_path, known_path, &info, &delta, error, error_size);
        } else {
            delta = known;
            memset(&known, 0, sizeof(known));
        }
        pthread_mutex_unlock(&cache_lock);
        g_free(published_path);
        g_free(native_path);
        g_free(module_path);
        current_manifest_clear(&manifest);
    }
    if (!result && !delta.count) {
        *empty = true;
    } else if (!result) {
        char *temporary_dir = g_build_filename(config->cache_dir, ".tmp", NULL);
        char *path = g_build_filename(temporary_dir, "delta-XXXXXX", NULL);
        int fd = g_mkstemp_full(path, O_RDWR | O_CLOEXEC, 0600);
        g_free(temporary_dir);
        delta.sequence = known.sequence;
        if (fd < 0 || lat_tb_key_set_write_fd(fd, &delta,
                                               error, error_size) ||
            (!config->flush_only && fsync(fd))) {
            if (fd >= 0) close(fd);
            unlink(path);
            g_free(path);
            result = -1;
        } else {
            close(fd);
            *delta_path = path;
        }
    }
    lat_tb_key_set_destroy(&known);
    lat_tb_key_set_destroy(&delta);
    return result;
}

/* Keep failed static discoveries out of the runtime collection, while
 * retaining keys already collected or published for this ELF. */
static int prepare_static_tbset(const LatcdConfig *config,
                                const uint8_t digest[32], const char *incoming,
                                char **output, char *error, size_t error_size)
{
    char hex[65];
    digest_hex(digest, hex);
    char *name = g_strdup_printf("%s.tbset", hex);
    char *known = g_build_filename(config->cache_dir, ".tbsets", name, NULL);
    LatcdCurrentManifest manifest = {0};
    LatTbKeySet complete = {0};
    int result = lat_tb_key_set_read_file(incoming, digest, &complete,
                                         error, error_size);
    pthread_mutex_lock(&cache_lock);
    char *published = NULL;
    if (!current_manifest_read(config, hex, &manifest) && *manifest.tbset &&
        persisted_manifest_valid(config, hex, digest)) {
        published = g_build_filename(config->cache_dir, manifest.tbset, NULL);
    }
    const char *paths[] = { known, published };
    for (size_t i = 0; !result && i < G_N_ELEMENTS(paths); i++) {
        if (!paths[i]) continue;
        LatTbKeySet existing = {0}, merged = {0};
        if (lat_tb_key_set_read_file(paths[i], digest, &existing,
                                      error, error_size)) {
            if (errno != ENOENT) result = -1;
            else error[0] = '\0';
        } else {
            result = lat_tb_key_set_union(&complete, &existing, &merged,
                                          error, error_size);
            if (!result) {
                lat_tb_key_set_destroy(&complete);
                complete = merged;
            }
        }
        lat_tb_key_set_destroy(&existing);
    }
    pthread_mutex_unlock(&cache_lock);
    if (!result) {
        char *path = g_build_filename(config->cache_dir, ".tmp",
                                      "static-XXXXXX", NULL);
        int fd = g_mkstemp_full(path, O_RDWR | O_CLOEXEC, 0600);
        if (fd < 0 || lat_tb_key_set_write_fd(fd, &complete,
                                              error, error_size)) {
            result = -1;
        }
        if (fd >= 0 && close(fd)) result = -1;
        if (result) {
            unlink(path);
            g_free(path);
        } else {
            *output = path;
        }
    }
    lat_tb_key_set_destroy(&complete);
    current_manifest_clear(&manifest);
    g_free(published);
    g_free(known);
    g_free(name);
    return result;
}

static void close_compiler_inputs(int pins[4])
{
    for (unsigned i = 0; i < 4; i++) {
        if (pins[i] >= 0) close(pins[i]);
        pins[i] = -1;
    }
}

static int pin_compiler_inputs(const char *const paths[4], int pins[4],
                                char *error, size_t error_size)
{
    for (unsigned i = 0; i < 4; i++) {
        if (!paths[i]) continue;
        pins[i] = open(paths[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat status;
        if (pins[i] < 0 || fstat(pins[i], &status) || !S_ISREG(status.st_mode) ||
            status.st_uid != geteuid() ||
            (status.st_mode & (S_IWGRP | S_IWOTH)) ||
            flock(pins[i], LOCK_SH | LOCK_NB)) {
            close_compiler_inputs(pins);
            return fail(error, error_size, "cannot pin compiler input: %s", paths[i]);
        }
    }
    return 0;
}

static int open_task_directory(int parent, const char *name)
{
    if (mkdirat(parent, name, 0700) && errno != EEXIST) return -1;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) || st.st_uid != geteuid() || (st.st_mode & 0077) ||
        fsync(parent)) {
        close(fd);
        return -1;
    }
    return fd;
}

static void task_object_identity(GKeyFile *record, const char *group,
                                  const struct stat *st)
{
    g_key_file_set_uint64(record, group, "device", st->st_dev);
    g_key_file_set_uint64(record, group, "inode", st->st_ino);
    g_key_file_set_uint64(record, group, "size", st->st_size);
    g_key_file_set_uint64(record, group, "mode", st->st_mode);
    g_key_file_set_uint64(record, group, "uid", st->st_uid);
    g_key_file_set_int64(record, group, "mtime_sec", st->st_mtim.tv_sec);
    g_key_file_set_uint64(record, group, "mtime_nsec", st->st_mtim.tv_nsec);
}

static int persist_task_record(int directory, const char *id, GKeyFile *record)
{
    char *staging = g_strdup_printf(".write-%s", id);
    char *name = g_strdup_printf("%s.ini", id);
    int lease = openat(directory, staging, O_RDWR | O_CREAT | O_EXCL |
                        O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lease < 0 || flock(lease, LOCK_SH | LOCK_NB)) goto failed;
    gsize length;
    char *data = g_key_file_to_data(record, &length, NULL);
    size_t done = 0;
    while (done < length) {
        ssize_t count = write(lease, data + done, length - done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        done += count;
    }
    g_free(data);
    if (done != length || fchmod(lease, 0400) || fsync(lease) ||
        linkat(directory, staging, directory, name, 0) ||
        unlinkat(directory, staging, 0) || fsync(directory)) goto failed;
    int readonly = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat writer, reader;
    if (readonly < 0 || fstat(lease, &writer) || fstat(readonly, &reader) ||
        writer.st_dev != reader.st_dev || writer.st_ino != reader.st_ino ||
        reader.st_nlink != 1 || flock(readonly, LOCK_SH | LOCK_NB)) {
        if (readonly >= 0) close(readonly);
        goto failed;
    }
    close(lease);
    lease = readonly;
    goto out;
failed:
    if (lease >= 0) close(lease);
    lease = -1;
    unlinkat(directory, staging, 0);
out:
    g_free(staging);
    g_free(name);
    return lease;
}

/* The immutable record is also the lease inode. No completion or deletion claim. */
static int record_task(const LatcdConfig *config, bool copying,
                                const char *const paths[6], const int pins[4],
                                const uint8_t digest[32],
                                const char *const environment[],
                                char **task_id, char *error, size_t error_size)
{
    int root = -1, gc = -1, tasks = -1, temporary = -1, collected = -1, lease = -1;
    GKeyFile *record = g_key_file_new();
    char *id = g_uuid_string_random();
    char *tmp = g_build_filename(config->cache_dir, ".tmp", NULL);
    char *tbsets = g_build_filename(config->cache_dir, ".tbsets", NULL);
    char source_hex[65];
    digest_hex(digest, source_hex);
    root = open(config->cache_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0 || (gc = open_task_directory(root, ".gc")) < 0 ||
        (tasks = open_task_directory(gc, "tasks")) < 0 ||
        (temporary = openat(root, ".tmp", O_RDONLY | O_DIRECTORY |
                            O_CLOEXEC | O_NOFOLLOW)) < 0) goto failed;
    struct stat st;
    if (fstat(root, &st)) goto failed;
    task_object_identity(record, "cache", &st);
    if (fstat(temporary, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0077)) goto failed;
    task_object_identity(record, "temporary", &st);
    g_key_file_set_string(record, "task", "version", copying ? "2" : "1");
    if (copying) g_key_file_set_string(record, "task", "kind", "COPY");
    g_key_file_set_string(record, "task", "id", id);
    g_key_file_set_string(record, "task", "state", "BOUND");
    g_key_file_set_string(record, "task", "source", source_hex);
    g_key_file_set_string(record, "task", "build_id", LATC_BUILD_ID);
    if (!copying) {
        GChecksum *configuration = g_checksum_new(G_CHECKSUM_SHA256);
        for (unsigned i = 0; environment[i]; i++) {
            g_checksum_update(configuration, (const guchar *)environment[i],
                              strlen(environment[i]) + 1);
        }
        g_key_file_set_string(record, "task", "environment_sha256",
                               g_checksum_get_string(configuration));
        g_checksum_free(configuration);
    }
    const char *roles[] = {copying ? "input" : "source", "tbset", "base_native",
                          "base_module", copying ? "output" : "output_native", "output_module"};
    for (unsigned i = 0; i < 6; i++) {
        if (!paths[i]) continue;
        char *parent = g_path_get_dirname(paths[i]);
        char *basename = g_path_get_basename(paths[i]);
        bool in_tmp = !strcmp(parent, tmp);
        bool in_collected = !strcmp(parent, tbsets);
        if (i < 4 && in_collected && collected < 0) {
            collected = openat(root, ".tbsets", O_RDONLY | O_DIRECTORY |
                                O_CLOEXEC | O_NOFOLLOW);
            if (collected >= 0 && !fstat(collected, &st) &&
                st.st_uid == geteuid() && !(st.st_mode & 0077)) {
                task_object_identity(record, "collected", &st);
            } else {
                if (collected >= 0) close(collected);
                collected = -1;
            }
        }
        bool valid = (in_tmp || (i < 4 && ((!strcmp(parent, config->cache_dir)) ||
                      (in_collected && collected >= 0)))) &&
                     basename[0] != '.' &&
                     strspn(basename, "abcdefghijklmnopqrstuvwxyz"
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") == strlen(basename);
        if (valid && i < 4) {
            struct stat pinned;
            valid = !fstat(pins[i], &pinned) &&
                    !fstatat(in_tmp ? temporary : in_collected ? collected : root,
                              basename, &st, AT_SYMLINK_NOFOLLOW) &&
                    st.st_dev == pinned.st_dev && st.st_ino == pinned.st_ino;
            if (valid) {
                task_object_identity(record, roles[i], &pinned);
                g_key_file_set_string(record, roles[i], "directory",
                                       in_tmp ? "temporary" : in_collected ? "collected" : "cache");
            }
        } else if (valid) {
            /* Output names are intents, not inode reservations. */
            valid = fstatat(temporary, basename, &st, AT_SYMLINK_NOFOLLOW) &&
                    errno == ENOENT;
        }
        if (valid) g_key_file_set_string(record, roles[i], "name", basename);
        g_free(parent);
        g_free(basename);
        if (!valid) goto failed;
    }
    lease = persist_task_record(tasks, id, record);
    if (lease < 0) goto failed;
    if (task_id) *task_id = g_strdup(id);
    goto out;
failed:
    if (lease >= 0) close(lease);
    lease = -1;
    fail(error, error_size, "cannot persist %s task root", copying ? "copy" : "compiler");
out:
    if (collected >= 0) close(collected);
    if (temporary >= 0) close(temporary);
    if (tasks >= 0) close(tasks);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    g_free(tmp);
    g_free(tbsets);
    g_free(id);
    g_key_file_free(record);
    return lease;
}

static int record_compiler_budget(const LatcdConfig *config, const char *id,
                                   const struct stat *task, uint64_t bytes)
{
    int root = open(config->cache_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = root < 0 ? -1 : open_task_directory(root, ".gc");
    int budgets = gc < 0 ? -1 : open_task_directory(gc, "compiler-budgets");
    int lease = -1;
    struct stat cache;
    GKeyFile *record = g_key_file_new();
    if (budgets >= 0 && !fstat(root, &cache)) {
        g_key_file_set_string(record, "budget", "version", "1");
        g_key_file_set_string(record, "budget", "task_id", id);
        g_key_file_set_uint64(record, "budget", "task_device", task->st_dev);
        g_key_file_set_uint64(record, "budget", "task_inode", task->st_ino);
        g_key_file_set_uint64(record, "budget", "cache_device", cache.st_dev);
        g_key_file_set_uint64(record, "budget", "cache_inode", cache.st_ino);
        g_key_file_set_uint64(record, "budget", "bytes", bytes);
        lease = persist_task_record(budgets, id, record);
    }
    if (lease >= 0) close(lease);
    if (budgets >= 0) close(budgets);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    g_key_file_free(record);
    return lease < 0 ? -1 : 0;
}

static int restore_compiler_budgets_step(const LatcdConfig *config,
    LatcdBudgetRecovery *work, unsigned budget, unsigned *visited,
    char *error, size_t error_size)
{
    int root = open(config->cache_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = root < 0 ? -1 : open_task_directory(root, ".gc");
    int tasks = gc < 0 ? -1 : open_task_directory(gc, "tasks");
    int budgets = gc < 0 ? -1 : open_task_directory(gc, "compiler-budgets");
    DIR *directory = work->cursor;
    int result = -1;
    *visited = 0;
    int64_t started = g_get_monotonic_time();
    struct stat cache;
    if (budgets < 0 || tasks < 0 || fstat(root, &cache)) goto out;
    if (!directory) {
        int scan = openat(work->scanning_tasks ? tasks : budgets, ".",
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        directory = scan < 0 ? NULL : fdopendir(scan);
        if (!directory) { if (scan >= 0) close(scan); goto out; }
    }
    while (!work->scanning_tasks) {
        if (stop_requested || *visited >= budget || (*visited &&
            g_get_monotonic_time() - started >= 10000)) { result = 1; goto out; }
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { result = errno ? -1 : 0; break; }
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        (*visited)++;
        if (++work->visited > 100000 || strlen(name) != 40 ||
            strcmp(name + 36, ".ini")) break;
        char id[37];
        memcpy(id, name, 36);
        id[36] = 0;
        if (!g_uuid_string_is_valid(id)) break;
        int fd = openat(budgets, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        struct stat before, after, task;
        char data[4096];
        GKeyFile *record = g_key_file_new();
        bool valid = fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) &&
            before.st_uid == geteuid() && before.st_nlink == 1 && !(before.st_mode & 0222) &&
            before.st_size > 0 && (uint64_t)before.st_size <= sizeof(data) &&
            pread(fd, data, before.st_size, 0) == before.st_size &&
            !fstat(fd, &after) && metadata_equal(&before, &after) &&
            !fstatat(tasks, name, &task, AT_SYMLINK_NOFOLLOW) && S_ISREG(task.st_mode) &&
            task.st_uid == geteuid() && task.st_nlink == 1 && !(task.st_mode & 0222) &&
            g_key_file_load_from_data(record, data, before.st_size, G_KEY_FILE_NONE, NULL);
        char *version = g_key_file_get_string(record, "budget", "version", NULL);
        gsize groups = 0, keys = 0;
        char **names = g_key_file_get_groups(record, &groups);
        g_strfreev(names);
        names = g_key_file_get_keys(record, "budget", &keys, NULL);
        g_strfreev(names);
        valid &= groups == 1 && keys == 7;
        char *task_id = g_key_file_get_string(record, "budget", "task_id", NULL);
        valid &= version && !strcmp(version, "1") && task_id && !strcmp(task_id, id);
        g_free(version);
        g_free(task_id);
        const char *fields[] = {"task_device", "task_inode", "cache_device", "cache_inode", "bytes"};
        uint64_t expected[] = {valid ? task.st_dev : 0, valid ? task.st_ino : 0,
                               cache.st_dev, cache.st_ino, 0};
        for (unsigned i = 0; valid && i < G_N_ELEMENTS(fields); i++) {
            GError *parse_error = NULL;
            guint64 value = g_key_file_get_uint64(record, "budget", fields[i], &parse_error);
            valid = !parse_error && (i == 4 ? value > 0 : value == expected[i]);
            if (i == 4 && valid) valid = !latcd_cache_capacity_restore_task(&generation_capacity, id, value);
            g_clear_error(&parse_error);
        }
        if (fd >= 0) close(fd);
        g_key_file_free(record);
        if (!valid) break;
    }
    if (!work->scanning_tasks && !result) {
        closedir(directory);
        directory = NULL;
        work->scanning_tasks = true;
        int scan = openat(tasks, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        directory = scan < 0 ? NULL : fdopendir(scan);
        if (!directory) {
            if (scan >= 0) close(scan);
            result = -1;
        }
    }
    if (work->scanning_tasks && directory) {
        result = -1;
        for (;;) {
            if (stop_requested || *visited >= budget || (*visited &&
                g_get_monotonic_time() - started >= 10000)) { result = 1; break; }
            errno = 0;
            struct dirent *entry = readdir(directory);
            if (!entry) { result = errno ? -1 : 0; break; }
            const char *name = entry->d_name;
            if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
            result = -1;
            (*visited)++;
            if (++work->visited > 100000 || strlen(name) != 40 ||
                strcmp(name + 36, ".ini")) break;
            char id[37];
            memcpy(id, name, 36);
            id[36] = 0;
            if (!g_uuid_string_is_valid(id)) break;
            struct stat budget;
            if (!fstatat(budgets, name, &budget, AT_SYMLINK_NOFOLLOW)) {
                result = 0;
                continue; /* Already validated and charged in the first pass. */
            }
            if (errno != ENOENT) break;
            int fd = openat(tasks, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            struct stat before, after;
            char data[65536];
            GKeyFile *record = g_key_file_new();
            bool valid = fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) &&
                before.st_uid == geteuid() && before.st_nlink == 1 && !(before.st_mode & 0222) &&
                before.st_size > 0 && (uint64_t)before.st_size <= sizeof(data) &&
                pread(fd, data, before.st_size, 0) == before.st_size &&
                !fstat(fd, &after) && metadata_equal(&before, &after) &&
                g_key_file_load_from_data(record, data, before.st_size, G_KEY_FILE_NONE, NULL);
            char *version = g_key_file_get_string(record, "task", "version", NULL);
            bool copying = version && !strcmp(version, "2");
            valid &= version && (!strcmp(version, "1") || copying);
            g_free(version);
            const char *fields[] = {"id", "state", "kind"};
            const char *values[] = {id, "BOUND", "COPY"};
            for (unsigned i = 0; valid && i < (copying ? 3u : 2u); i++) {
                char *value = g_key_file_get_string(record, "task", fields[i], NULL);
                valid = value && !strcmp(value, values[i]);
                g_free(value);
            }
            const char *identities[] = {"device", "inode"};
            uint64_t expected[] = {cache.st_dev, cache.st_ino};
            for (unsigned i = 0; valid && i < G_N_ELEMENTS(identities); i++) {
                GError *parse_error = NULL;
                guint64 value = g_key_file_get_uint64(record, "cache", identities[i], &parse_error);
                valid = !parse_error && value == expected[i];
                g_clear_error(&parse_error);
            }
            if (fd >= 0) close(fd);
            g_key_file_free(record);
            if (!valid) break;
            if (!copying) latcd_cache_capacity_unknown_task(&generation_capacity, id);
            result = 0;
        }
    }
out:
    work->cursor = result == 1 ? directory : NULL;
    if (result != 1 && directory) closedir(directory);
    if (budgets >= 0) close(budgets);
    if (tasks >= 0) close(tasks);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    return result < 0 ? fail(error, error_size, "capacity: compiler budget recovery incomplete or unsafe") : result;
}

static int record_compiler_release(const LatcdConfig *config, const char *id,
                                    const struct stat *expected, bool outputs)
{
    int root = -1, gc = -1, tasks = -1, releases = -1, task = -1, temporary = -1, lease = -1;
    GKeyFile *record = g_key_file_new();
    char *name = g_strdup_printf("%s.ini", id);
    struct stat observed;
    root = open(config->cache_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0 || (gc = open_task_directory(root, ".gc")) < 0 ||
        (tasks = open_task_directory(gc, "tasks")) < 0 ||
        (releases = open_task_directory(gc, outputs ? "compiler-output-releases" : "compiler-releases")) < 0 ||
        (task = openat(tasks, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0 ||
        fstat(task, &observed) || observed.st_dev != expected->st_dev ||
        observed.st_ino != expected->st_ino || observed.st_nlink != 1 ||
        !S_ISREG(observed.st_mode) || observed.st_uid != geteuid() ||
        (observed.st_mode & 0222) || flock(task, LOCK_EX | LOCK_NB)) goto out;
    if (outputs) {
        char data[65537];
        GKeyFile *bound = g_key_file_new();
        bool missing = observed.st_size > 0 && observed.st_size <= 65536 &&
            pread(task, data, observed.st_size, 0) == observed.st_size &&
            g_key_file_load_from_data(bound, data, observed.st_size, G_KEY_FILE_NONE, NULL);
        temporary = openat(root, ".tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        missing &= temporary >= 0;
        struct stat tmp;
        const char *identity_fields[] = {"device", "inode"};
        if (missing) missing = !fstat(temporary, &tmp) && tmp.st_uid == geteuid() &&
            !(tmp.st_mode & 0077);
        uint64_t identity_values[] = {missing ? tmp.st_dev : 0, missing ? tmp.st_ino : 0};
        for (unsigned i = 0; missing && i < G_N_ELEMENTS(identity_fields); i++) {
            GError *parse_error = NULL;
            guint64 value = g_key_file_get_uint64(bound, "temporary", identity_fields[i], &parse_error);
            missing = !parse_error && value == identity_values[i];
            g_clear_error(&parse_error);
        }
        const char *roles[] = {"output_native", "output_module"};
        for (unsigned i = 0; missing && i < 2; i++) {
            char *output = g_key_file_get_string(bound, roles[i], "name", NULL);
            struct stat st;
            missing = output && *output && output[0] != '.' && !strchr(output, '/') &&
                fstatat(temporary, output, &st, AT_SYMLINK_NOFOLLOW) && errno == ENOENT;
            g_free(output);
        }
        g_key_file_free(bound);
        if (!missing || fsync(temporary)) goto out;
    }
    g_key_file_set_string(record, "handoff", "version", "1");
    g_key_file_set_string(record, "handoff", "task_id", id);
    g_key_file_set_string(record, "handoff", "state", outputs ? "OUTPUTS_RELEASED" : "INPUTS_RELEASED");
    g_key_file_set_uint64(record, "handoff", "task_device", observed.st_dev);
    g_key_file_set_uint64(record, "handoff", "task_inode", observed.st_ino);
    lease = persist_task_record(releases, id, record);
out:
    if (temporary >= 0) close(temporary);
    if (lease >= 0) close(lease);
    if (task >= 0) close(task);
    if (releases >= 0) close(releases);
    if (tasks >= 0) close(tasks);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    g_free(name);
    g_key_file_free(record);
    return lease < 0 ? -1 : 0;
}

typedef struct LatcdCompilerTask {
    char id[37];
    struct stat identity;
} LatcdCompilerTask;

static pthread_mutex_t compiler_task_lock = PTHREAD_MUTEX_INITIALIZER;
static GHashTable *local_compiler_tasks;

static void compiler_task_local(const char *id, bool active)
{
    pthread_mutex_lock(&compiler_task_lock);
    if (active) {
        if (!local_compiler_tasks) local_compiler_tasks = g_hash_table_new_full(
            g_str_hash, g_str_equal, g_free, NULL);
        g_hash_table_add(local_compiler_tasks, g_strdup(id));
    } else if (local_compiler_tasks) {
        g_hash_table_remove(local_compiler_tasks, id);
        if (!g_hash_table_size(local_compiler_tasks)) {
            g_hash_table_destroy(local_compiler_tasks);
            local_compiler_tasks = NULL;
        }
    }
    pthread_mutex_unlock(&compiler_task_lock);
}

static bool compiler_task_is_local(const char *id)
{
    pthread_mutex_lock(&compiler_task_lock);
    bool active = local_compiler_tasks && g_hash_table_contains(local_compiler_tasks, id);
    pthread_mutex_unlock(&compiler_task_lock);
    return active;
}

static bool compiler_release_matches(int releases, const char *name,
                                      const char *id, const struct stat *task, bool outputs)
{
    int fd = openat(releases, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat before, after;
    char data[65536];
    GKeyFile *record = g_key_file_new();
    bool valid = fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) &&
        before.st_uid == geteuid() && before.st_nlink == 1 && !(before.st_mode & 0222) &&
        before.st_size > 0 && (uint64_t)before.st_size <= sizeof(data) &&
        pread(fd, data, before.st_size, 0) == before.st_size &&
        !fstat(fd, &after) && metadata_equal(&before, &after) &&
        g_key_file_load_from_data(record, data, before.st_size, G_KEY_FILE_NONE, NULL);
    gsize groups = 0, keys = 0;
    char **names = g_key_file_get_groups(record, &groups);
    g_strfreev(names);
    names = g_key_file_get_keys(record, "handoff", &keys, NULL);
    g_strfreev(names);
    valid &= groups == 1 && keys == 5;
    const char *fields[] = {"version", "task_id", "state"};
    const char *values[] = {"1", id, outputs ? "OUTPUTS_RELEASED" : "INPUTS_RELEASED"};
    for (unsigned i = 0; valid && i < G_N_ELEMENTS(fields); i++) {
        char *value = g_key_file_get_string(record, "handoff", fields[i], NULL);
        valid = value && !strcmp(value, values[i]);
        g_free(value);
    }
    const char *numbers[] = {"task_device", "task_inode"};
    uint64_t expected[] = {task->st_dev, task->st_ino};
    for (unsigned i = 0; valid && i < G_N_ELEMENTS(numbers); i++) {
        GError *error = NULL;
        guint64 value = g_key_file_get_uint64(record, "handoff", numbers[i], &error);
        valid = !error && value == expected[i];
        g_clear_error(&error);
    }
    if (fd >= 0) close(fd);
    g_key_file_free(record);
    return valid;
}

static int release_copy_task(const LatcdConfig *config, int task_pin,
                              char *error, size_t error_size);

/* Caller owns the daemon lease. Surviving tasks retain SH on the task inode;
 * only absent outputs may reach a recovered terminal state. */
static int recover_compiler_inputs_step(const LatcdConfig *config, DIR **cursor,
                                    unsigned budget, unsigned *visited,
                                    char *error, size_t error_size)
{
    int root = -1, gc = -1, tasks = -1, releases = -1, result = -1;
    DIR *directory = *cursor;
    unsigned recovered = 0, retained = 0;
    *visited = 0;
    int64_t started = g_get_monotonic_time();
    root = open(config->cache_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0 || (gc = open_task_directory(root, ".gc")) < 0 ||
        (tasks = open_task_directory(gc, "tasks")) < 0 ||
        (releases = open_task_directory(gc, "compiler-releases")) < 0) goto out;
    if (!directory) {
        int scan = dup(tasks);
        if (scan < 0) goto out;
        directory = fdopendir(scan);
        if (!directory) { close(scan); goto out; }
    }
    for (;;) {
        if (stop_requested) { result = 1; break; }
        if (*visited >= budget || (*visited &&
            g_get_monotonic_time() - started >= 10000)) { result = 1; break; }
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { result = errno ? -1 : 0; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        (*visited)++;
        const char *name = entry->d_name;
        char id[37];
        if (strlen(name) != 40 || strcmp(name + 36, ".ini")) { retained++; continue; }
        memcpy(id, name, 36);
        id[36] = 0;
        if (!g_uuid_string_is_valid(id)) { retained++; continue; }
        if (compiler_task_is_local(id)) { retained++; continue; }
        struct stat existing;
        bool input_exists = !fstatat(releases, name, &existing, AT_SYMLINK_NOFOLLOW);
        if (!input_exists && errno != ENOENT) { retained++; continue; }
        int task = openat(tasks, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        struct stat before, after, cache;
        char data[65536];
        GKeyFile *record = g_key_file_new();
        bool valid = task >= 0 && !fstat(task, &before) &&
            S_ISREG(before.st_mode) && before.st_uid == geteuid() &&
            before.st_nlink == 1 && !(before.st_mode & 0222) &&
            before.st_size > 0 && (uint64_t)before.st_size <= sizeof(data) &&
            !flock(task, LOCK_EX | LOCK_NB) &&
            pread(task, data, before.st_size, 0) == before.st_size &&
            !fstat(task, &after) && metadata_equal(&before, &after) &&
            g_key_file_load_from_data(record, data, before.st_size, G_KEY_FILE_NONE, NULL);
        char *version = g_key_file_get_string(record, "task", "version", NULL);
        bool copying = version && !strcmp(version, "2");
        g_free(version);
        if (valid && copying) {
            char *kind = g_key_file_get_string(record, "task", "kind", NULL);
            valid = kind && !strcmp(kind, "COPY");
            g_free(kind);
        }
        const char *fields[] = {"version", "id", "state", "build_id"};
        const char *values[] = {copying ? "2" : "1", id, "BOUND", LATC_BUILD_ID};
        for (unsigned i = 0; valid && i < G_N_ELEMENTS(fields); i++) {
            char *value = g_key_file_get_string(record, "task", fields[i], NULL);
            valid = value && !strcmp(value, values[i]);
            g_free(value);
        }
        if (valid) {
            GError *parse_error = NULL;
            guint64 device = g_key_file_get_uint64(record, "cache", "device", &parse_error);
            valid = !parse_error;
            g_clear_error(&parse_error);
            guint64 inode = g_key_file_get_uint64(record, "cache", "inode", &parse_error);
            valid &= !parse_error && !fstat(root, &cache) &&
                device == (guint64)cache.st_dev && inode == (guint64)cache.st_ino;
            g_clear_error(&parse_error);
        }
        bool temporary_matches = false;
        bool outputs_missing = false;
        if (valid) {
            GError *parse_error = NULL;
            guint64 device = g_key_file_get_uint64(record, "temporary", "device", &parse_error);
            bool parsed = !parse_error;
            g_clear_error(&parse_error);
            guint64 inode = g_key_file_get_uint64(record, "temporary", "inode", &parse_error);
            int tmp = openat(root, ".tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            struct stat identity;
            temporary_matches = parsed && !parse_error && tmp >= 0 &&
                !fstat(tmp, &identity) && identity.st_uid == geteuid() &&
                !(identity.st_mode & 0077) && device == (guint64)identity.st_dev &&
                inode == (guint64)identity.st_ino;
            outputs_missing = temporary_matches;
            const char *roles[] = {"output_native", "output_module"};
            for (unsigned i = 0; outputs_missing && i < G_N_ELEMENTS(roles); i++) {
                char *output = g_key_file_get_string(record, roles[i], "name", NULL);
                struct stat st;
                outputs_missing = output && *output && output[0] != '.' && !strchr(output, '/') &&
                    fstatat(tmp, output, &st, AT_SYMLINK_NOFOLLOW) && errno == ENOENT;
                g_free(output);
            }
            if (tmp >= 0) close(tmp);
            g_clear_error(&parse_error);
        }
        g_key_file_free(record);
        if (copying) {
            int copy_releases = open_task_directory(gc, "copy-releases");
            bool absent = copy_releases >= 0 &&
                fstatat(copy_releases, name, &existing, AT_SYMLINK_NOFOLLOW) && errno == ENOENT;
            if (copy_releases >= 0) close(copy_releases);
            /* Keep the independent EX held through receipt persistence. The
             * ordinary publisher instead still owns its original task SH. */
            if (valid && temporary_matches && absent &&
                !release_copy_task(config, task, error, error_size)) recovered++;
            else retained++;
            if (task >= 0) close(task);
            continue;
        }
        if (task >= 0) close(task);
        /* Reopen and retake EX in the normal writer; never upgrade an OFD or
         * treat the earlier observation as permanent authority. */
        bool inputs_released = valid && (input_exists ||
            !record_compiler_release(config, id, &before, false)) &&
            compiler_release_matches(releases, name, id, &before, false);
        if (!input_exists && inputs_released) recovered++;
        if (!inputs_released) { retained++; continue; }
        int outputs = open_task_directory(gc, "compiler-output-releases");
        bool output_exists = outputs >= 0 &&
            !fstatat(outputs, name, &existing, AT_SYMLINK_NOFOLLOW);
        bool output_absent = outputs >= 0 && !output_exists && errno == ENOENT;
        bool output_released = output_exists && compiler_release_matches(outputs, name, id, &before, true);
        if (outputs >= 0) close(outputs);
        if (output_absent && temporary_matches &&
            !record_compiler_release(config, id, &before, true)) {
            recovered++;
            output_released = true;
        }
        else if (!output_exists) retained++;
        if (output_released && outputs_missing)
            latcd_cache_capacity_release_task(&generation_capacity, id);
    }
out:
    if (directory && (result != 1 || stop_requested)) {
        closedir(directory);
        directory = NULL;
    }
    *cursor = directory;
    if (releases >= 0) close(releases);
    if (tasks >= 0) close(tasks);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    if (recovered) fprintf(stderr, "latcd: task root recovery recovered=%u retained=%u\n", recovered, retained);
    if (result < 0) fail(error, error_size, "cannot scan compiler task roots: %s", strerror(errno));
    return result;
}

static int recover_compiler_inputs(const LatcdConfig *config,
                                    char *error, size_t error_size)
{
    DIR *cursor = NULL;
    unsigned visited;
    int result;
    do {
        result = recover_compiler_inputs_step(config, &cursor, 32, &visited, error, error_size);
    } while (result == 1 && !stop_requested);
    if (cursor) closedir(cursor);
    return result;
}

typedef struct LatcdTaskRecovery {
    const LatcdConfig *config;
    atomic_bool stopping;
} LatcdTaskRecovery;

static void *compiler_input_recovery_worker(void *opaque)
{
    LatcdTaskRecovery *work = opaque;
    DIR *cursor = NULL;
    int64_t next = 0;
    int64_t next_retirement = 0;
    bool failed = false;
    LatcdRetirementQueue *retirement = latcd_retirement_queue_new(work->config->cache_dir,
        UINT64_C(600) * 1000000);
    while (!atomic_load(&work->stopping) && !stop_requested) {
        int64_t now = g_get_monotonic_time();
        if (now >= next_retirement) {
            LatcdRetirementQueueStats stats;
            char error[256];
            int result = latcd_retirement_queue_step(retirement, 32, 10000,
                &stats, error, sizeof(error));
            pthread_mutex_lock(&retirement_queue_lock);
            retirement_queue_stats = stats;
            pthread_mutex_unlock(&retirement_queue_lock);
            next_retirement = g_get_monotonic_time() + (result == 1 ? 100000 : 5000000);
        }
        if (now >= next) {
            char error[256];
            unsigned visited;
            if (!atomic_load(&compiler_budget_recovery_state)) {
                int result = restore_compiler_budgets_step(work->config,
                    &compiler_budget_recovery, 32, &visited, error, sizeof(error));
                if (result <= 0) {
                    atomic_store(&compiler_budget_recovery_state, result < 0 ? -1 : 1);
                    if (result < 0) fprintf(stderr, "latcd: %s\n", error);
                }
                next = g_get_monotonic_time() + 100000;
                continue;
            }
            if (atomic_load(&compiler_budget_recovery_state) < 0) break;
            int result = recover_compiler_inputs_step(work->config, &cursor, 32,
                &visited, error, sizeof(error));
            if (result < 0 && !failed) fprintf(stderr, "latcd: %s\n", error);
            failed = result < 0;
            next = g_get_monotonic_time() + (result == 1 ? 100000 : 5000000);
        }
        struct timespec pause = {.tv_nsec = 100 * 1000 * 1000};
        nanosleep(&pause, NULL);
    }
    if (cursor) closedir(cursor);
    latcd_retirement_queue_free(retirement);
    return NULL;
}

static int run_compiler(const LatcdConfig *config, uint32_t worker_index,
                        const char *source, const char *tbset,
                        bool static_tbset,
                        const char *base_native, const char *base_module,
                        const char *output_native,
                        const char *output, const uint8_t digest[32], GPtrArray *compiler_tasks,
                        uint64_t *transient_reservation,
                        char *error, size_t error_size)
{
    if (validate_toolchain(config, error, error_size)) {
        return -1;
    }
    const char *arguments[] = {
        config->compiler, "compile-module", source,
        "-o", output, "--runner", config->runner,
        "--runtime-dir", config->runtime_dir, NULL, NULL, NULL, NULL,
    };
    if (tbset) {
        arguments[9] = "--tbset";
        arguments[10] = tbset;
        if (static_tbset) arguments[11] = "--static-tbset";
    }
    char *library_path = g_strdup_printf("LD_LIBRARY_PATH=%s",
                                         config->runtime_dir);
    const char *compile_tmpdir = getenv("LATCD_COMPILE_TMPDIR");
    if (!compile_tmpdir || !*compile_tmpdir) {
        compile_tmpdir = access("/dev/shm", W_OK | X_OK) == 0 ?
                         "/dev/shm" : "/tmp";
    }
    uint64_t cache_peak = 0;
    if (compile_space_admit(worker_index, compile_tmpdir, output, source, tbset,
                              base_native, base_module, &cache_peak, error, error_size)) {
        g_free(library_path);
        return -1;
    }
    if (cache_peak > *transient_reservation) {
        if (latcd_cache_capacity_reserve_transient(&generation_capacity,
            cache_peak - *transient_reservation, config->max_cache_bytes, error, error_size)) {
            release_compile_space(worker_index);
            g_free(library_path);
            return -1;
        }
        *transient_reservation = cache_peak;
    }
    char *temporary_path = g_strdup_printf("TMPDIR=%s", compile_tmpdir);
    char *guest_prefix = config->x86_rootfs ?
        g_strdup_printf("LAT_LD_PREFIX=%s", config->x86_rootfs) : NULL;
    const char *compile_timing = getenv("LATCD_COMPILE_TIMING") ?
        "LATC_COMPILE_TIMING=1" : NULL;
    const char *expand_functions = getenv("LATC_TBSET_EXPAND_FUNCTIONS") ?
        "LATC_TBSET_EXPAND_FUNCTIONS=1" : NULL;
    const char *allow_zero_eflags_stub =
        getenv("LATC_AOT_ALLOW_ZERO_EFLAGS_STUB") ?
        "LATC_AOT_ALLOW_ZERO_EFLAGS_STUB=1" : NULL;
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    uint32_t aot_thread_count = online > 0 ?
        MAX(1u, MIN(8u, (uint32_t)online / config->workers)) : 1u;
    struct stat tbset_status;
    if (aot_thread_count == 1 && tbset &&
        !stat(tbset, &tbset_status) &&
        tbset_status.st_size >= 512 * 1024) {
        aot_thread_count = 2;
    }
    char *aot_threads = g_strdup_printf("LATC_AOT_THREADS=%u",
                                         aot_thread_count);
    char *native_base = base_native ?
        g_strdup_printf("LATC_NATIVE_BASE=%s", base_native) : NULL;
    char *module_base = base_module ?
        g_strdup_printf("LATC_NATIVE_BASE_MODULE=%s", base_module) : NULL;
    char *native_output = g_strdup_printf("LATC_NATIVE_OUTPUT=%s",
                                           output_native);
    char digest_text[65];
    digest_hex(digest, digest_text);
    char *trusted_digest = g_strdup_printf("LATC_TRUSTED_SOURCE_SHA256=%s",
                                            digest_text);
    const char *closure_limit = getenv("LATC_TBSET_CLOSURE_LIMIT");
    if (!closure_limit || !*closure_limit) {
        closure_limit = "20000";
    }
    char *closure_environment = g_strdup_printf(
        "LATC_TBSET_CLOSURE_LIMIT=%s", closure_limit);
    const char *selection = getenv("LATC_TBSET_SELECTION");
    char *selection_environment = g_strdup_printf("LATC_TBSET_SELECTION=%s",
        selection && *selection ? selection : "bounded");
    const char *environment[18];
    size_t environment_count = 0;
    environment[environment_count++] = "PATH=/usr/bin:/bin";
    environment[environment_count++] = "LANG=C";
    environment[environment_count++] = "LC_ALL=C";
    environment[environment_count++] = library_path;
    environment[environment_count++] = temporary_path;
    environment[environment_count++] = aot_threads;
    environment[environment_count++] = trusted_digest;
    if (guest_prefix) environment[environment_count++] = guest_prefix;
    if (native_base) environment[environment_count++] = native_base;
    if (module_base) environment[environment_count++] = module_base;
    environment[environment_count++] = native_output;
    if (compile_timing) environment[environment_count++] = compile_timing;
    if (expand_functions) environment[environment_count++] = expand_functions;
    if (allow_zero_eflags_stub) {
        environment[environment_count++] = allow_zero_eflags_stub;
    }
    environment[environment_count++] = closure_environment;
    environment[environment_count++] = selection_environment;
    environment[environment_count++] = "LATC_SKIP_FINAL_INSPECT=1";
    environment[environment_count] = NULL;
    const char *inputs[4] = {source, tbset, base_native, base_module};
    int input_pins[4] = {-1, -1, -1, -1};
    int pin_result = pin_compiler_inputs(inputs, input_pins, error, error_size);
    const char *task_paths[6] = {source, tbset, base_native, base_module,
                                output_native, output};
    char *task_id = NULL;
    int task_lease = pin_result ? -1 : record_task(config, false, task_paths,
        input_pins, digest, environment, &task_id, error, error_size);
    if (task_lease < 0) pin_result = -1;
    if (task_lease >= 0) {
        LatcdCompilerTask *task = g_new0(LatcdCompilerTask, 1);
        g_strlcpy(task->id, task_id, sizeof(task->id));
        if (fstat(task_lease, &task->identity)) {
            g_free(task);
            pin_result = -1;
        } else {
            compiler_task_local(task_id, true);
            g_ptr_array_add(compiler_tasks, task);
            if (record_compiler_budget(config, task_id, &task->identity, cache_peak)) {
                pin_result = -1;
                fail(error, error_size, "capacity: cannot persist compiler budget");
            }
        }
    }
    pid_t child = pin_result ? -1 : fork();
    if (child == 0) {
        /* Only this compiler inherits these OFDs; unrelated execs keep CLOEXEC. */
        for (unsigned i = 0; i < 4; i++) {
            if (input_pins[i] >= 0 && fcntl(input_pins[i], F_SETFD, 0)) _exit(126);
        }
        if (fcntl(task_lease, F_SETFD, 0)) _exit(126);
        if (setpgid(0, 0)) {
            _exit(126);
        }
        struct rlimit inherited_cpu;
        rlim_t cpu_seconds = config->cpu_seconds;
        if (!getrlimit(RLIMIT_CPU, &inherited_cpu) &&
            inherited_cpu.rlim_max != RLIM_INFINITY &&
            cpu_seconds > inherited_cpu.rlim_max) {
            /* An unprivileged child cannot raise its inherited hard limit. */
            cpu_seconds = inherited_cpu.rlim_max;
        }
        struct rlimit cpu = { cpu_seconds, cpu_seconds };
        struct rlimit memory = {
            config->address_space_limit, config->address_space_limit,
        };
        struct rlimit file = {
            config->file_size_limit, config->file_size_limit,
        };
        struct rlimit descriptors = { config->open_files, config->open_files };
        if (setrlimit(RLIMIT_CPU, &cpu) ||
            setrlimit(RLIMIT_AS, &memory) ||
            setrlimit(RLIMIT_FSIZE, &file) ||
            setrlimit(RLIMIT_NOFILE, &descriptors)) {
            _exit(126);
        }
        execve(config->compiler, (char *const *)arguments,
               (char *const *)environment);
        _exit(127);
    }
    if (child < 0) {
        if (task_lease >= 0) close(task_lease);
        g_free(task_id);
        close_compiler_inputs(input_pins);
        release_compile_space(worker_index);
        g_free(library_path);
        g_free(temporary_path);
        g_free(guest_prefix);
        g_free(aot_threads);
        g_free(native_base);
        g_free(module_base);
        g_free(native_output);
        g_free(trusted_digest);
        g_free(closure_environment);
        g_free(selection_environment);
        if (pin_result) return -1;
        return fail(error, error_size, "cannot start compiler: %s",
                    strerror(errno));
    }
    setpgid(child, child);
    compiler_process_groups[worker_index] = child;
    if (stop_requested) {
        kill(-child, SIGTERM);
    }
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    /*
     * Compiler shell scripts can exit after SIGTERM while a grandchild keeps
     * translating in the compiler's process group.  Do not lose the PGID
     * when the leader is reaped: terminate any remaining descendants before
     * marking this worker idle.
     */
    if (!kill(-child, 0) || errno == EPERM) {
        struct timespec grace = { .tv_nsec = 100 * 1000 * 1000 };
        kill(-child, SIGTERM);
        nanosleep(&grace, NULL);
        kill(-child, SIGKILL);
    }
    compiler_process_groups[worker_index] = 0;
    struct stat task_identity;
    bool task_known = !fstat(task_lease, &task_identity);
    close(task_lease);
    /* An independent EX probe cannot unlock a descendant's inherited SH OFD. */
    if (task_known && record_compiler_release(config, task_id, &task_identity, false))
        fprintf(stderr, "latcd: compiler inputs still held or release not durable; retaining task root\n");
    g_free(task_id);
    close_compiler_inputs(input_pins);
    release_compile_space(worker_index);
    g_free(library_path);
    g_free(temporary_path);
    g_free(guest_prefix);
    g_free(aot_threads);
    g_free(native_base);
    g_free(module_base);
    g_free(native_output);
    g_free(trusted_digest);
    g_free(closure_environment);
    g_free(selection_environment);
    if (waited < 0) {
        return fail(error, error_size, "cannot wait for compiler: %s",
                    strerror(errno));
    }
    if (!WIFEXITED(status)) {
        return fail(error, error_size, "compiler terminated by signal");
    }
    if (WEXITSTATUS(status)) {
        return fail(error, error_size, "compiler failed with exit status %d",
                    WEXITSTATUS(status));
    }
    return 0;
}

static int sync_file(const char *path, char *error, size_t error_size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fsync(fd)) {
        int saved = errno;
        if (fd >= 0) {
            close(fd);
        }
        return fail(error, error_size, "cannot sync module: %s",
                    strerror(saved));
    }
    close(fd);
    return 0;
}

static int open_cached_file(const char *source, uint64_t max_size,
                             char *error, size_t error_size)
{
    int input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat status;
    if (input < 0 || fstat(input, &status) || !S_ISREG(status.st_mode) ||
        status.st_uid != geteuid() || status.st_nlink != 1 ||
        (status.st_mode & 0222) || status.st_size <= 0 ||
        (uint64_t)status.st_size > max_size) {
        int saved = errno;
        if (input >= 0) close(input);
        errno = saved ? saved : ENOEXEC;
        return fail(error, error_size,
                    "cannot open canonical native image: %s",
                    strerror(errno));
    }
    if (lat_aot_v2_cache_lock_fd(input, LOCK_SH | LOCK_NB,
                                 error, error_size) ||
        lat_aot_v2_cache_object_available(source, error, error_size)) {
        close(input);
        return -1;
    }
    return input;
}

static int snapshot_cached_fd(int input, const char *temporary_dir,
                              char **snapshot, int *snapshot_pin,
                              const char *reserved_path,
                              char *error, size_t error_size)
{
    *snapshot = NULL;
    if (snapshot_pin) *snapshot_pin = -1;
    struct stat before, after;
    if (fstat(input, &before)) {
        return fail(error, error_size, "cannot inspect pinned cache file");
    }
    char *path = reserved_path ? g_strdup(reserved_path) :
        g_build_filename(temporary_dir, "base-native-XXXXXX", NULL);
    int output = reserved_path ? open(path, O_RDWR | O_CREAT | O_EXCL |
        O_CLOEXEC | O_NOFOLLOW, 0600) : g_mkstemp_full(path, O_RDWR | O_CLOEXEC, 0600);
    if (output < 0) {
        g_free(path);
        return fail(error, error_size,
                    "cannot create canonical native snapshot: %s",
                    strerror(errno));
    }
    if (flock(output, LOCK_SH | LOCK_NB)) {
        close(output);
        unlink(path);
        g_free(path);
        return fail(error, error_size, "cannot pin canonical snapshot");
    }
    unsigned char buffer[128 * 1024];
    int result = 0;
    off_t position = 0;
    while (position < before.st_size) {
        size_t wanted = MIN(sizeof(buffer), (uint64_t)(before.st_size - position));
        ssize_t count = pread(input, buffer, wanted, position);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            result = fail(error, error_size,
                          "cannot read canonical native image: %s",
                          strerror(errno));
            break;
        }
        if (!count) {
            result = fail(error, error_size, "pinned cache file was truncated");
            break;
        }
        position += count;
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write(output, buffer + offset, count - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) {
                result = fail(error, error_size,
                              "cannot write canonical native snapshot: %s",
                              strerror(errno));
                break;
            }
            offset += written;
        }
        if (result) break;
    }
    /* Rename/unlink can change ctime/link count without changing pinned bytes. */
    if (!result && (fstat(input, &after) ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mode != after.st_mode ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec)) {
        result = fail(error, error_size,
                      "pinned cache file changed while copying");
    }
    int readonly = -1;
    if (!result && snapshot_pin) {
        struct stat writer, reader;
        if (fchmod(output, 0400) || fsync(output) ||
            (readonly = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0 ||
            fstat(output, &writer) || fstat(readonly, &reader) ||
            writer.st_dev != reader.st_dev || writer.st_ino != reader.st_ino ||
            flock(readonly, LOCK_SH | LOCK_NB)) {
            result = fail(error, error_size, "cannot hand off canonical snapshot pin");
        }
    }
    if (close(output) && !result)
        result = fail(error, error_size, "cannot close canonical native snapshot");
    if (result) {
        if (readonly >= 0) close(readonly);
        unlink(path);
        g_free(path);
        return -1;
    }
    if (snapshot_pin) *snapshot_pin = readonly;
    *snapshot = path;
    return 0;
}

static void copy_test_barrier(const char *stage)
{
    const char *selected = getenv("LATCD_TEST_COPY_STAGE");
    const char *notify = getenv("LATCD_TEST_COPY_NOTIFY_FD");
    const char *resume = getenv("LATCD_TEST_COPY_RESUME_FD");
    if (!selected || strcmp(stage, selected) || !notify || !resume) return;
    char *end;
    long output = strtol(notify, &end, 10);
    if (!*notify || *end || output < 0 || output > INT_MAX) return;
    long input = strtol(resume, &end, 10);
    if (!*resume || *end || input < 0 || input > INT_MAX) return;
    char byte = 'x';
    ssize_t result;
    do { result = write((int)output, &byte, 1); } while (result < 0 && errno == EINTR);
    if (result != 1) return;
    do { result = read((int)input, &byte, 1); } while (result < 0 && errno == EINTR);
}

static char *cached_fd_digest(int fd);

static int record_copy_receipt(const LatcdConfig *config, const char *id,
                                int task_pin, const char *output, int output_pin,
                                char *error, size_t error_size)
{
    int root = -1, gc = -1, receipts = -1, lease = -1;
    GKeyFile *record = g_key_file_new();
    struct stat task, before, after, path;
    char *sha = NULL;
    char *name = g_path_get_basename(output);
    if (fstat(task_pin, &task) || fstat(output_pin, &before) ||
        !(sha = cached_fd_digest(output_pin)) || fstat(output_pin, &after) ||
        !metadata_equal(&before, &after) || before.st_mode != after.st_mode ||
        lstat(output, &path) || path.st_dev != before.st_dev ||
        path.st_ino != before.st_ino || path.st_nlink != 1) goto out;
    root = open(config->cache_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0 || (gc = open_task_directory(root, ".gc")) < 0 ||
        (receipts = open_task_directory(gc, "copy-receipts")) < 0) goto out;
    g_key_file_set_string(record, "receipt", "version", "1");
    g_key_file_set_string(record, "receipt", "task_id", id);
    g_key_file_set_uint64(record, "receipt", "task_device", task.st_dev);
    g_key_file_set_uint64(record, "receipt", "task_inode", task.st_ino);
    g_key_file_set_string(record, "receipt", "state", "COPIED");
    task_object_identity(record, "output", &before);
    g_key_file_set_string(record, "output", "name", name);
    g_key_file_set_string(record, "output", "sha256", sha);
    lease = persist_task_record(receipts, id, record);
out:
    if (lease >= 0) close(lease);
    if (receipts >= 0) close(receipts);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    g_free(name);
    g_free(sha);
    g_key_file_free(record);
    return lease < 0 ? fail(error, error_size, "cannot persist copy output receipt") : 0;
}

static int snapshot_task_copy(const LatcdConfig *config, const char *source,
                              int input, const uint8_t digest[32],
                              const char *temporary, char **snapshot,
                              int *snapshot_pin, int *task_pin, char **task_id,
                              char *error, size_t error_size)
{
    char *id = g_uuid_string_random();
    char *name = g_strdup_printf("base-native-%s", id);
    char *output = g_build_filename(temporary, name, NULL);
    const char *paths[6] = {source, NULL, NULL, NULL, output, NULL};
    int inputs[4] = {input, -1, -1, -1};
    *task_pin = record_task(config, true, paths, inputs, digest, NULL,
                            task_id, error, error_size);
    if (*task_pin >= 0) copy_test_barrier("recorded");
    int result = *task_pin < 0 ? -1 : snapshot_cached_fd(input, temporary,
        snapshot, snapshot_pin, output, error, error_size);
    if (!result) result = sync_directory(temporary, error, error_size);
    if (!result) copy_test_barrier("synced");
    if (!result) result = record_copy_receipt(config, *task_id, *task_pin,
        output, *snapshot_pin, error, error_size);
    if (!result) copy_test_barrier("copied");
    if (result) {
        if (*snapshot_pin >= 0) close(*snapshot_pin);
        *snapshot_pin = -1;
        if (*snapshot) unlink(*snapshot);
        g_clear_pointer(snapshot, g_free);
        if (*task_pin >= 0) close(*task_pin);
        *task_pin = -1;
    }
    g_free(output);
    g_free(name);
    g_free(id);
    return result;
}

static int record_copy_handoff(const LatcdConfig *config, const char *id,
                                int task_pin, char *error, size_t error_size)
{
    int root = -1, gc = -1, receipts = -1, handoffs = -1, receipt = -1, lease = -1;
    GKeyFile *record = g_key_file_new();
    char *name = g_strdup_printf("%s.ini", id);
    struct stat task, copied;
    root = open(config->cache_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0 || (gc = open_task_directory(root, ".gc")) < 0 ||
        (receipts = open_task_directory(gc, "copy-receipts")) < 0 ||
        (handoffs = open_task_directory(gc, "copy-handoffs")) < 0 ||
        (receipt = openat(receipts, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0 ||
        fstat(task_pin, &task) || fstat(receipt, &copied) ||
        !S_ISREG(copied.st_mode) || copied.st_uid != geteuid() ||
        copied.st_nlink != 1 || (copied.st_mode & 0222)) goto out;
    g_key_file_set_string(record, "handoff", "version", "1");
    g_key_file_set_string(record, "handoff", "task_id", id);
    g_key_file_set_string(record, "handoff", "state", "SNAPSHOT_OWNED");
    g_key_file_set_uint64(record, "handoff", "task_device", task.st_dev);
    g_key_file_set_uint64(record, "handoff", "task_inode", task.st_ino);
    g_key_file_set_uint64(record, "handoff", "receipt_device", copied.st_dev);
    g_key_file_set_uint64(record, "handoff", "receipt_inode", copied.st_ino);
    lease = persist_task_record(handoffs, id, record);
out:
    if (lease >= 0) close(lease);
    if (receipt >= 0) close(receipt);
    if (handoffs >= 0) close(handoffs);
    if (receipts >= 0) close(receipts);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    g_free(name);
    g_key_file_free(record);
    return lease < 0 ? fail(error, error_size, "cannot persist copy handoff") : 0;
}

static char *cached_fd_digest(int fd)
{
    struct stat status;
    if (fd < 0) return NULL;
    if (fstat(fd, &status) || !S_ISREG(status.st_mode) ||
        status.st_uid != geteuid() || (status.st_mode & 0222) ||
        status.st_size <= 0) {
        return NULL;
    }
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    unsigned char buffer[128 * 1024];
    bool failed = false;
    off_t offset = 0;
    while (offset < status.st_size) {
        size_t wanted = MIN(sizeof(buffer), (uint64_t)(status.st_size - offset));
        ssize_t count = pread(fd, buffer, wanted, offset);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { failed = true; break; }
        if (!count) { failed = true; break; }
        g_checksum_update(checksum, buffer, count);
        offset += count;
    }
    struct stat after;
    if (fstat(fd, &after) || !metadata_equal(&status, &after) ||
        status.st_mode != after.st_mode) failed = true;
    char *digest = failed ? NULL : g_strdup(g_checksum_get_string(checksum));
    g_checksum_free(checksum);
    return digest;
}

static int release_copy_task(const LatcdConfig *config, int task_pin,
                              char *error, size_t error_size)
{
    char data[65537];
    struct stat task, output;
    GKeyFile *record = g_key_file_new();
    GKeyFile *release = g_key_file_new();
    char *id = NULL, *name = NULL;
    int root = -1, gc = -1, releases = -1, temporary = -1, lease = -1;
    if (fstat(task_pin, &task) || !S_ISREG(task.st_mode) || task.st_uid != geteuid() ||
        task.st_nlink != 1 || (task.st_mode & 0222) || task.st_size <= 0 || task.st_size > 65536 ||
        pread(task_pin, data, task.st_size, 0) != task.st_size ||
        !g_key_file_load_from_data(record, data, task.st_size, G_KEY_FILE_NONE, NULL)) goto out;
    id = g_key_file_get_string(record, "task", "id", NULL);
    name = g_key_file_get_string(record, "output", "name", NULL);
    if (!id || !g_uuid_string_is_valid(id) || !name || !*name || name[0] == '.' ||
        strchr(name, '/')) goto out;
    root = open(config->cache_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0 || (gc = open_task_directory(root, ".gc")) < 0 ||
        (releases = open_task_directory(gc, "copy-releases")) < 0 ||
        (temporary = openat(root, ".tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) < 0 ||
        !fstatat(temporary, name, &output, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) goto out;
    struct stat tmp;
    if (fstat(temporary, &tmp) || tmp.st_uid != geteuid() || (tmp.st_mode & 0077)) goto out;
    const char *fields[] = {"device", "inode"};
    uint64_t expected[] = {tmp.st_dev, tmp.st_ino};
    for (unsigned i = 0; i < G_N_ELEMENTS(fields); i++) {
        GError *parse_error = NULL;
        guint64 value = g_key_file_get_uint64(record, "temporary", fields[i], &parse_error);
        bool valid = !parse_error && value == expected[i];
        g_clear_error(&parse_error);
        if (!valid) goto out;
    }
    if (fsync(temporary)) goto out;
    g_key_file_set_string(release, "handoff", "version", "1");
    g_key_file_set_string(release, "handoff", "task_id", id);
    g_key_file_set_string(release, "handoff", "state", "RELEASED");
    g_key_file_set_uint64(release, "handoff", "task_device", task.st_dev);
    g_key_file_set_uint64(release, "handoff", "task_inode", task.st_ino);
    lease = persist_task_record(releases, id, release);
out:
    if (lease >= 0) close(lease);
    if (temporary >= 0) close(temporary);
    if (releases >= 0) close(releases);
    if (gc >= 0) close(gc);
    if (root >= 0) close(root);
    g_free(name);
    g_free(id);
    g_key_file_free(record);
    g_key_file_free(release);
    return lease < 0 ? fail(error, error_size, "cannot persist copy release") : 0;
}

static int snapshot_current_pair(const LatcdConfig *config,
                                 const LatcdCurrentManifest *manifest,
                                 const uint8_t digest[32], const char *temporary,
                                 char **native, char **module, int snapshot_pins[4],
                                 char *error, size_t error_size)
{
    /* Caller holds C. Capture S outside C; G and snapshot pins overlap. */
    bool pair = manifest->module_sha256 || manifest->native_sha256;
    if (pair && (!manifest->module_sha256 || !manifest->native_sha256)) {
        return fail(error, error_size, "incomplete module/native pair digests");
    }
    if (pair && (strlen(manifest->module_sha256) != 64 ||
        strlen(manifest->native_sha256) != 64)) {
        return fail(error, error_size, "invalid module/native pair digests");
    }
    char hex[65];
    digest_hex(digest, hex);
    pthread_mutex_unlock(&cache_lock);
    int source_gate = lat_aot_v2_cache_source_lock(config->cache_dir, hex,
        LOCK_SH | LOCK_NB, false, error, error_size);
    pthread_mutex_lock(&cache_lock);
    if (source_gate < 0) return -1;
    LatcdCurrentManifest latest = {0};
    bool unchanged = !current_manifest_read(config, hex, &latest) &&
                     current_manifest_equal(manifest, &latest);
    current_manifest_clear(&latest);
    if (!unchanged) {
        close(source_gate);
        return fail(error, error_size, "current changed before baseline capture");
    }
    char *module_path = g_build_filename(config->cache_dir, manifest->module, NULL);
    char *native_path = g_build_filename(config->cache_dir, manifest->native, NULL);
    int native_fd = open_cached_file(native_path, config->file_size_limit,
                                     error, error_size);
    int module_fd = pair && native_fd >= 0 ? open_cached_file(
        module_path, config->file_size_limit, error, error_size) : -1;
    close(source_gate);
    if (native_fd < 0 || (pair && module_fd < 0)) {
        if (native_fd >= 0) close(native_fd);
        g_free(module_path);
        g_free(native_path);
        return -1;
    }
    /* Pin both members of one selected generation before releasing the lock. */
    pthread_mutex_unlock(&cache_lock);
    char *task_ids[2] = {NULL, NULL};
    int result = snapshot_task_copy(config, native_path, native_fd, digest,
        temporary, native, &snapshot_pins[0], &snapshot_pins[2], &task_ids[0], error, error_size);
    if (!result && pair) result = snapshot_task_copy(config, module_path, module_fd,
        digest, temporary, module, &snapshot_pins[1], &snapshot_pins[3], &task_ids[1], error, error_size);
    g_free(module_path);
    g_free(native_path);
    char *module_sha = !result && pair ? cached_fd_digest(snapshot_pins[1]) : NULL;
    char *native_sha = !result && pair ? cached_fd_digest(snapshot_pins[0]) : NULL;
    LatAotModuleInfoV2 info;
    if (!result && pair && (!module_sha || !native_sha ||
        strcmp(module_sha, manifest->module_sha256) ||
        strcmp(native_sha, manifest->native_sha256) ||
        !cached_module_inspect(*module, digest, &info))) {
        result = fail(error, error_size, "module/native pair snapshot mismatch");
    }
    g_free(module_sha);
    g_free(native_sha);
    for (unsigned i = 0; !result && i < (pair ? 2u : 1u); i++) {
        result = record_copy_handoff(config, task_ids[i], snapshot_pins[i + 2],
                                      error, error_size);
    }
    g_free(task_ids[0]);
    g_free(task_ids[1]);
    close(native_fd);
    if (module_fd >= 0) close(module_fd);
    if (!result) copy_test_barrier("handedoff");
    pthread_mutex_lock(&cache_lock);
    if (result) {
        for (unsigned i = 0; i < 4; i++) {
            if (snapshot_pins[i] >= 0) close(snapshot_pins[i]);
            snapshot_pins[i] = -1;
        }
        if (*native) unlink(*native);
        if (*module) unlink(*module);
        g_clear_pointer(native, g_free);
        g_clear_pointer(module, g_free);
    }
    return result;
}

static int sync_directory(const char *path, char *error, size_t error_size)
{
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0 || fsync(directory)) {
        int saved = errno;
        if (directory >= 0) {
            close(directory);
        }
        return fail(error, error_size, "cannot sync cache directory: %s",
                    strerror(saved));
    }
    close(directory);
    return 0;
}

static int owned_module_inspect(const char *path, LatAotModuleInfoV2 *info)
{
    struct stat status;
    return !lat_aot_v2_cache_object_available(path, NULL, 0) &&
           !lstat(path, &status) && S_ISREG(status.st_mode) &&
           status.st_uid == geteuid() && status.st_nlink == 1 &&
           !(status.st_mode & 0222) &&
           !lat_aot_v2_module_inspect_file(path, info, NULL, 0);
}

static int cached_module_inspect(const char *path, const uint8_t digest[32],
                                 LatAotModuleInfoV2 *info)
{
    uint8_t codegen_id[32];
    expected_codegen_id(codegen_id);
    return owned_module_inspect(path, info) &&
           !memcmp(info->note.source_sha256, digest, 32) &&
           !memcmp(info->note.codegen_id, codegen_id, 32);
}

static void current_manifest_clear(LatcdCurrentManifest *manifest)
{
    g_free(manifest->module);
    g_free(manifest->native);
    g_free(manifest->tbset);
    g_free(manifest->module_sha256);
    g_free(manifest->native_sha256);
    memset(manifest, 0, sizeof(*manifest));
}

static bool current_manifest_equal(const LatcdCurrentManifest *first,
                                    const LatcdCurrentManifest *second)
{
    return !g_strcmp0(first->module, second->module) &&
        !g_strcmp0(first->native, second->native) &&
        !g_strcmp0(first->tbset, second->tbset) &&
        !g_strcmp0(first->module_sha256, second->module_sha256) &&
        !g_strcmp0(first->native_sha256, second->native_sha256) &&
        first->published_sequence == second->published_sequence;
}

static int validate_current_replacement(const LatcdConfig *config,
                                 const char *hex, const char *candidate,
                                 const LatAotModuleInfoV2 *info,
                                 char *error, size_t error_size)
{
    /* cache_lock is held. Observed tbsets need not list every compiled TB. */
    LatcdCurrentManifest previous = {0};
    int result = 0;
    if (!current_manifest_read(config, hex, &previous)) {
        char *old_path = g_build_filename(config->cache_dir,
                                          previous.module, NULL);
        LatAotModuleInfoV2 old_info;
        if (cached_module_inspect(old_path,
            info->note.source_sha256, &old_info) &&
            lat_aot_v2_module_validate_replacement_file(
                old_path, candidate, error, error_size)) {
            result = -1;
        }
        g_free(old_path);
    }
    current_manifest_clear(&previous);
    return result;
}

static int publish_current_index(const LatcdConfig *config, const char *hex,
                                 const char *module_name,
                                 const char *native_name,
                                 const char *tbset_name,
                                 const LatAotModuleInfoV2 *info,
                                 uint64_t published_sequence,
                                 bool new_pair,
                                 char *error, size_t error_size)
{
    int source_lock_fd = -1;
    char *candidate = g_build_filename(config->cache_dir, module_name, NULL);
    int validation = validate_current_replacement(config, hex, candidate,
                                                   info, error, error_size);
    g_free(candidate);
    if (validation) {
        return -1;
    }
    char *module_path = g_build_filename(config->cache_dir, module_name, NULL);
    char *native_path = g_build_filename(config->cache_dir, native_name, NULL);
    char *tbset_path = *tbset_name ?
        g_build_filename(config->cache_dir, tbset_name, NULL) : NULL;
    LatcdCurrentManifest selected = {0}, latest = {0};
    bool selected_valid = !current_manifest_read(config, hex, &selected);
    struct stat module_before, native_before, module_after, native_after;
    struct stat tbset_before, tbset_after;
    int module_fd = open_cached_file(module_path, UINT64_MAX, error, error_size);
    int native_fd = open_cached_file(native_path, UINT64_MAX, error, error_size);
    int tbset_fd = tbset_path ?
        open_cached_file(tbset_path, UINT64_MAX, error, error_size) : -1;
    bool pinned = module_fd >= 0 && native_fd >= 0 &&
        !fstat(module_fd, &module_before) && !fstat(native_fd, &native_before) &&
        (!tbset_path || (tbset_fd >= 0 && !fstat(tbset_fd, &tbset_before)));
    /* Open descriptors hold shared leases while expensive hashes run.
     * Path and generation checks below guard the source-latched commit. */
    pthread_mutex_unlock(&cache_lock);
    const char *object_names[6] = {module_name, native_name};
    size_t object_count = 2;
    if (*tbset_name) object_names[object_count++] = tbset_name;
    if (selected_valid) {
        object_names[object_count++] = selected.module;
        object_names[object_count++] = selected.native;
        if (*selected.tbset) object_names[object_count++] = selected.tbset;
    }
    char *objects = latcd_retirement_capture_objects(config->cache_dir, hex,
                                                     object_names, object_count);
    char *module_sha256 = pinned ? cached_fd_digest(module_fd) : NULL;
    char *native_sha256 = pinned ? cached_fd_digest(native_fd) : NULL;
    /* Never wait for S while holding C. Keep object leases until S is held. */
    const char *notify = getenv("LATCD_TEST_SOURCE_COMMIT_FD");
    if (notify) {
        char *end;
        long number = strtol(notify, &end, 10);
        if (*notify && !*end && number >= 0 && number <= INT_MAX) {
            char byte = 'x';
            ssize_t ignored = write((int)number, &byte, 1);
            (void)ignored;
            const char *resume = getenv("LATCD_TEST_SOURCE_COMMIT_RESUME_FD");
            if (resume) {
                long release = strtol(resume, &end, 10);
                if (*resume && !*end && release >= 0 && release <= INT_MAX) {
                    ssize_t received;
                    do { received = read((int)release, &byte, 1); }
                    while (received < 0 && errno == EINTR);
                }
            }
        }
    }
    source_lock_fd = lat_aot_v2_cache_source_lock(
        config->cache_dir, hex, LOCK_EX, false, error, error_size);
    pthread_mutex_lock(&cache_lock);
    bool latest_valid = !current_manifest_read(config, hex, &latest);
    bool unchanged = source_lock_fd >= 0 && pinned && !lstat(module_path, &module_after) &&
        !lstat(native_path, &native_after) &&
        metadata_equal(&module_before, &module_after) &&
        metadata_equal(&native_before, &native_after) &&
        module_before.st_mode == module_after.st_mode &&
        native_before.st_mode == native_after.st_mode &&
        (!tbset_path || (!lstat(tbset_path, &tbset_after) &&
         metadata_equal(&tbset_before, &tbset_after) &&
         tbset_before.st_mode == tbset_after.st_mode)) &&
        selected_valid == latest_valid && (!selected_valid ||
        current_manifest_equal(&selected, &latest));
    if (module_fd >= 0) close(module_fd);
    if (native_fd >= 0) close(native_fd);
    if (tbset_fd >= 0) close(tbset_fd);
    current_manifest_clear(&selected);
    current_manifest_clear(&latest);
    g_free(module_path);
    g_free(native_path);
    g_free(tbset_path);
    if (!unchanged || !module_sha256 || !native_sha256) {
        if (source_lock_fd >= 0) close(source_lock_fd);
        g_free(objects);
        g_free(module_sha256);
        g_free(native_sha256);
        return fail(error, error_size,
                    "published file set or current changed during digest");
    }
    const char *candidates[] = {module_name, native_name, tbset_name};
    for (size_t i = 0; i < G_N_ELEMENTS(candidates); i++) {
        if (!*candidates[i]) continue;
        char *path = g_build_filename(config->cache_dir, candidates[i], NULL);
        int unavailable = lat_aot_v2_cache_object_available(path, error, error_size);
        g_free(path);
        if (unavailable) {
            close(source_lock_fd);
            g_free(objects);
            g_free(module_sha256);
            g_free(native_sha256);
            return -1;
        }
    }
    LatcdCurrentManifest previous = {0};
    bool same_pair = !current_manifest_read(config, hex, &previous) &&
        !strcmp(previous.module, module_name) &&
        !strcmp(previous.native, native_name);
    bool record_pair = new_pair || (same_pair && previous.module_sha256 &&
                                    previous.native_sha256);
    if (same_pair &&
        ((previous.module_sha256 && strcmp(previous.module_sha256, module_sha256)) ||
         (previous.native_sha256 && strcmp(previous.native_sha256, native_sha256)))) {
        current_manifest_clear(&previous);
        close(source_lock_fd);
        g_free(objects);
        g_free(module_sha256);
        g_free(native_sha256);
        return fail(error, error_size, "current module/native pair content changed");
    }
    current_manifest_clear(&previous);
    char *temporary_dir = g_build_filename(config->cache_dir, ".tmp", NULL);
    char *temporary = g_build_filename(temporary_dir, "current-XXXXXX", NULL);
    int fd = g_mkstemp_full(temporary, O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        close(source_lock_fd);
        g_free(objects);
        g_free(module_sha256);
        g_free(native_sha256);
        g_free(temporary_dir);
        g_free(temporary);
        return fail(error, error_size, "cannot create current index: %s",
                    strerror(errno));
    }
    char codegen[65];
    digest_hex(info->note.codegen_id, codegen);
    GString *contents = g_string_new(NULL);
    g_string_append_printf(contents,
        "{\"version\":2,\"module\":\"%s\",\"native\":\"%s\","
        "\"tbset\":\"%s\",\"source_sha256\":\"%s\","
        "\"codegen_id\":\"%s\",",
        module_name, native_name, tbset_name, hex, codegen);
    if (record_pair) {
        g_string_append_printf(contents,
            "\"module_sha256\":\"%s\",\"native_sha256\":\"%s\",",
            module_sha256, native_sha256);
    }
    g_string_append_printf(contents, "\"published_sequence\":%" PRIu64 "}\n",
        published_sequence);
    g_free(module_sha256);
    g_free(native_sha256);
    ssize_t written = write(fd, contents->str, contents->len);
    int result = 0;
    if (written != (ssize_t)contents->len || fchmod(fd, 0444) || fsync(fd)) {
        result = fail(error, error_size, "cannot write current index: %s",
                      strerror(errno));
    }
    char *transaction = NULL;
    if (close(fd) && !result) {
        result = fail(error, error_size, "cannot close current index: %s",
                      strerror(errno));
    }
    char *final = g_strdup_printf("%s/%s.current", config->cache_dir, hex);
    if (!result && latcd_retirement_prepare(config->cache_dir, hex,
            contents->str, contents->len, objects, &transaction, error, error_size)) {
        result = -1;
    }
    g_string_free(contents, TRUE);
    g_free(objects);
    const char *crash = getenv("LATCD_TEST_RETIREMENT_CRASH");
    if (!result && crash && !strcmp(crash, "prepared")) raise(SIGKILL);
    if (!result) {
        if (rename(temporary, final)) {
            result = fail(error, error_size, "cannot publish current index: %s",
                          strerror(errno));
        } else if (crash && !strcmp(crash, "current")) {
            raise(SIGKILL);
        } else if (!sync_directory(config->cache_dir, error, error_size) &&
                   crash && !strcmp(crash, "current-synced")) {
            raise(SIGKILL);
        }
    }
    if (result) {
        unlink(temporary);
    }
    if (transaction) {
        char retirement_error[256] = {0};
        if (latcd_retirement_finish(config->cache_dir, transaction,
                                    retirement_error, sizeof(retirement_error))) {
            /* current rename is the commit point. Recovery retains PREPARED. */
            fprintf(stderr, "latcd: %s; transaction retained for recovery\n",
                    retirement_error);
        }
    }
    if (!result && crash && !strcmp(crash, "retired")) raise(SIGKILL);
    g_free(transaction);
    close(source_lock_fd);
    g_free(final);
    g_free(temporary);
    g_free(temporary_dir);
    return result;
}

static char *manifest_string(const char *contents, const char *field)
{
    char *prefix = g_strdup_printf("\"%s\":\"", field);
    const char *begin = strstr(contents, prefix);
    g_free(prefix);
    if (!begin) return NULL;
    begin = strchr(begin, ':') + 2;
    const char *end = strchr(begin, '\"');
    if (!end || end - begin >= 192 ||
        memchr(begin, '/', end - begin)) return NULL;
    return g_strndup(begin, end - begin);
}

static int current_manifest_read(const LatcdConfig *config, const char *hex,
                                 LatcdCurrentManifest *manifest)
{
    char *path = g_strdup_printf("%s/%s.current", config->cache_dir, hex);
    gchar *contents = NULL;
    gsize size = 0;
    GError *read_error = NULL;
    if (!g_file_get_contents(path, &contents, &size, &read_error)) {
        int missing = read_error && read_error->domain == G_FILE_ERROR &&
                      read_error->code == G_FILE_ERROR_NOENT;
        g_clear_error(&read_error);
        g_free(path);
        errno = missing ? ENOENT : EIO;
        return missing ? 1 : -1;
    }
    g_free(path);
    if (!size || size >= 4096 || !strstr(contents, "\"version\":2")) {
        g_free(contents);
        errno = ENOEXEC;
        return -1;
    }
    manifest->module = manifest_string(contents, "module");
    manifest->native = manifest_string(contents, "native");
    manifest->tbset = manifest_string(contents, "tbset");
    manifest->module_sha256 = manifest_string(contents, "module_sha256");
    manifest->native_sha256 = manifest_string(contents, "native_sha256");
    const char *sequence = strstr(contents, "\"published_sequence\":");
    const char *sequence_value = sequence ? strchr(sequence, ':') + 1 : NULL;
    char *end = NULL;
    manifest->published_sequence = sequence ?
        g_ascii_strtoull(sequence_value, &end, 10) : 0;
    int result = !manifest->module || !manifest->native || !manifest->tbset ||
        strlen(manifest->module) <= 3 ||
        strcmp(manifest->module + strlen(manifest->module) - 3, ".so") ||
        strlen(manifest->native) <= 7 ||
        strcmp(manifest->native + strlen(manifest->native) - 7, ".native") ||
        (*manifest->tbset && (strlen(manifest->tbset) <= 6 ||
         strcmp(manifest->tbset + strlen(manifest->tbset) - 6, ".tbset"))) ||
        strncmp(manifest->module, hex, 64) ||
        strncmp(manifest->native, hex, 64) ||
        (*manifest->tbset && strncmp(manifest->tbset, hex, 64)) ||
        !sequence || end == sequence_value || (*end != ',' && *end != '}');
    g_free(contents);
    if (result) {
        current_manifest_clear(manifest);
        errno = ENOEXEC;
    }
    return result;
}

/* Publish a newer complete observed-key set when the current module already
 * contains every key.  Return 1 if the current generation changed or stopped
 * being usable and the caller must fall back to a full compile. */
static int publish_covered_tbset(const LatcdConfig *config,
                                 const char *complete_tbset,
                                 const uint8_t digest[32],
                                 uint64_t published_sequence,
                                 LatcdResponseV2 *response)
{
    char error[sizeof(response->message)] = {0};
    gchar *tbset_data = NULL;
    gsize tbset_size = 0;
    char *temporary_dir = NULL;
    char *temporary = NULL;
    char *final_tbset = NULL;
    char *tbset_name = NULL;
    char *module_path = NULL;
    char *native_path = NULL;
    bool tbset_staged = false;
    uint64_t capacity_reservation = 0;
    bool capacity_retained = false;
    bool capacity_expected = false;
    int result = -1;
    memcpy(response->source_sha256, digest, 32);
    if (!g_file_get_contents(complete_tbset, &tbset_data,
                             &tbset_size, NULL)) {
        fail(error, sizeof(error), "cannot read complete TB set");
        goto out;
    }
    char source_hex[65];
    digest_hex(digest, source_hex);
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(checksum, (const guchar *)tbset_data, tbset_size);
    tbset_name = g_strdup_printf("%s-%s.tbset", source_hex,
                                  g_checksum_get_string(checksum));
    g_checksum_free(checksum);
    final_tbset = g_build_filename(config->cache_dir, tbset_name, NULL);
    temporary_dir = g_build_filename(config->cache_dir, ".tmp", NULL);
    temporary = g_build_filename(temporary_dir, "published-XXXXXX", NULL);
    int fd = g_mkstemp_full(temporary, O_RDWR | O_CLOEXEC, 0600);
    bool stage_failed = fd < 0;
    gsize offset = 0;
    while (!stage_failed && offset < tbset_size) {
        ssize_t written = write(fd, tbset_data + offset,
                                tbset_size - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            stage_failed = true;
        } else {
            offset += written;
        }
    }
    if (!stage_failed && (fchmod(fd, 0444) || fsync(fd))) {
        stage_failed = true;
    }
    if (fd >= 0 && close(fd)) stage_failed = true;
    if (stage_failed) {
        fail(error, sizeof(error), "cannot stage complete TB set: %s",
             strerror(errno));
        goto out;
    }

    pthread_mutex_lock(&cache_lock);
    LatcdCurrentManifest manifest = {0};
    LatAotModuleInfoV2 info;
    bool covered = !current_manifest_read(config, source_hex, &manifest) &&
                   *manifest.tbset;
    if (covered) {
        module_path = g_build_filename(config->cache_dir,
                                        manifest.module, NULL);
        native_path = g_build_filename(config->cache_dir,
                                        manifest.native, NULL);
        covered = cached_module_inspect(module_path, digest, &info) &&
                  !access(native_path, R_OK) &&
                  !lat_aot_v2_module_validate_tbset_file(
                      module_path, complete_tbset, error, sizeof(error));
    }
    if (!covered) {
        current_manifest_clear(&manifest);
        pthread_mutex_unlock(&cache_lock);
        result = 1;
        goto out;
    }
    if (strcmp(manifest.tbset, tbset_name)) {
        if (latcd_cache_capacity_reserve(&generation_capacity, tbset_size,
                                         config->max_cache_bytes, error, sizeof(error))) {
            current_manifest_clear(&manifest);
            pthread_mutex_unlock(&cache_lock);
            goto out;
        }
        capacity_reservation = tbset_size;
        if (latcd_cache_capacity_expect(&generation_capacity, (const char *const *)&tbset_name, 1,
                                        error, sizeof(error))) {
            current_manifest_clear(&manifest);
            pthread_mutex_unlock(&cache_lock);
            goto out;
        }
        capacity_expected = true;
        if (rename(temporary, final_tbset)) {
            if (!error[0]) {
                fail(error, sizeof(error),
                     "cannot publish complete TB set: %s", strerror(errno));
            }
            current_manifest_clear(&manifest);
            pthread_mutex_unlock(&cache_lock);
            goto out;
        }
        temporary[0] = '\0';
        tbset_staged = true;
        if (sync_directory(config->cache_dir, error, sizeof(error))) {
            current_manifest_clear(&manifest);
            pthread_mutex_unlock(&cache_lock);
            goto out;
        }
        const char *failpoint = getenv("LATCD_TEST_FAIL_BEFORE_MANIFEST");
        if (failpoint && *failpoint && !access(failpoint, F_OK)) {
            unlink(failpoint);
            fail(error, sizeof(error),
                 "injected failure before manifest commit");
            current_manifest_clear(&manifest);
            pthread_mutex_unlock(&cache_lock);
            goto out;
        }
    }
    if (publish_current_index(config, source_hex, manifest.module,
                              manifest.native, tbset_name, &info,
                              published_sequence, false, error, sizeof(error))) {
        current_manifest_clear(&manifest);
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    tbset_staged = false;
    char sync_error[128] = {0};
    if (sync_directory(config->cache_dir, sync_error,
                       sizeof(sync_error))) {
        fprintf(stderr,
                "latcd: committed covered-TB manifest sync failed: %s\n",
                sync_error);
    }
    capacity_retained = true;
    utimensat(AT_FDCWD, module_path, NULL, AT_SYMLINK_NOFOLLOW);
    snprintf(error, sizeof(error), "published covered TB set: %s",
             module_path);
    current_manifest_clear(&manifest);
    pthread_mutex_unlock(&cache_lock);
    response->status = LATCD_STATUS_OK;
    result = 0;
out:
    if (result < 0) {
        response->status = LATCD_STATUS_IO_ERROR;
        g_strlcpy(response->message, error[0] ? error : "unknown error",
                  sizeof(response->message));
    } else if (!result) {
        g_strlcpy(response->message, error, sizeof(response->message));
    }
    if (temporary && *temporary) unlink(temporary);
    if (tbset_staged && unlink(final_tbset) && errno != ENOENT) capacity_retained = true;
    if (capacity_expected)
        latcd_cache_capacity_complete(&generation_capacity, (const char *const *)&tbset_name, 1);
    if (capacity_reservation)
        latcd_cache_capacity_finish(&generation_capacity, capacity_reservation, capacity_retained);
    g_free(native_path);
    g_free(module_path);
    g_free(tbset_name);
    g_free(final_tbset);
    g_free(temporary);
    g_free(temporary_dir);
    g_free(tbset_data);
    return result;
}

static int preserve_current_keys(const LatcdConfig *config, const char *hex,
                                 const uint8_t digest[32],
                                 const char *requested,
                                 const char *temporary_dir, char **output,
                                 char *error, size_t error_size)
{
    if (!requested) {
        return 0;
    }
    LatcdCurrentManifest previous = {0};
    LatTbKeySet old_keys = {0}, incoming = {0}, complete = {0};
    LatAotModuleInfoV2 info;
    int result = 0;
    pthread_mutex_lock(&cache_lock);
    char *module = !current_manifest_read(config, hex, &previous) ?
        g_build_filename(config->cache_dir, previous.module, NULL) : NULL;
    if (module && cached_module_inspect(module, digest, &info)) {
        result = lat_aot_v2_module_read_tbset_file(module, &info, &old_keys,
                                                   error, error_size);
    }
    g_free(module);
    current_manifest_clear(&previous);
    pthread_mutex_unlock(&cache_lock);
    if (result || !old_keys.count) {
        goto out;
    }
    if (lat_tb_key_set_read_file(requested, digest, &incoming,
                                 error, error_size) ||
        lat_tb_key_set_union(&old_keys, &incoming, &complete,
                              error, error_size)) {
        result = -1;
        goto out;
    }
    char *path = g_build_filename(temporary_dir, "retained-XXXXXX", NULL);
    int fd = g_mkstemp_full(path, O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        result = fail(error, error_size, "cannot create retained TB set: %s",
                      strerror(errno));
    } else {
        result = lat_tb_key_set_write_fd(fd, &complete, error, error_size);
        if (close(fd) && !result) {
            result = fail(error, error_size, "cannot close retained TB set: %s",
                          strerror(errno));
        }
    }
    if (result) {
        unlink(path);
        g_free(path);
    } else {
        *output = path;
    }
out:
    lat_tb_key_set_destroy(&old_keys);
    lat_tb_key_set_destroy(&incoming);
    lat_tb_key_set_destroy(&complete);
    return result;
}

static int publish_snapshot(const LatcdConfig *config, uint32_t worker_index,
                            const char *snapshot, const char *compile_tbset,
                            const char *complete_tbset,
                            bool static_tbset,
                            const uint8_t digest[32],
                            uint64_t published_sequence,
                            LatcdResponseV2 *response)
{
    char error[sizeof(response->message)] = {0};
    char *temporary_dir = g_build_filename(config->cache_dir, ".tmp", NULL);
    char *module = NULL;
    char *native = NULL;
    char *tbset_copy = NULL;
    char *final_module = NULL;
    char *final_native = NULL;
    char *final_tbset = NULL;
    char *base_native = NULL;
    char *base_module = NULL;
    int baseline_pins[4] = {-1, -1, -1, -1};
    GPtrArray *compiler_tasks = g_ptr_array_new_with_free_func(g_free);
    uint64_t transient_reservation = 0;
    char *retained_tbset = NULL;
    char *module_name = NULL;
    char *native_name = NULL;
    char *tbset_name = NULL;
    gchar *tbset_data = NULL;
    gsize tbset_size = 0;
    bool module_staged = false;
    bool native_staged = false;
    bool tbset_staged = false;
    uint64_t capacity_reservation = 0;
    bool capacity_retained = false;
    bool capacity_expected = false;
    int status = LATCD_STATUS_IO_ERROR;
    memcpy(response->source_sha256, digest, 32);
    char hex[65];
    digest_hex(digest, hex);
    char tbset_hex[65] = {0};
    if (complete_tbset) {
        if (!g_file_get_contents(complete_tbset, &tbset_data,
                                 &tbset_size, NULL)) {
            fail(error, sizeof(error), "cannot read validated TB set");
            goto out;
        }
        GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
        g_checksum_update(checksum, (const guchar *)tbset_data, tbset_size);
        if (static_tbset) {
            /* A checked compile must stage a fresh generation even when
             * its keys match the currently published generation. */
            g_checksum_update(checksum, (const guchar *)snapshot,
                              strlen(snapshot));
        }
        g_strlcpy(tbset_hex, g_checksum_get_string(checksum),
                  sizeof(tbset_hex));
        g_checksum_free(checksum);
    }
    module_name = complete_tbset ?
        g_strdup_printf("%s-%s.so", hex, tbset_hex) :
        g_strdup_printf("%s.so", hex);
    native_name = complete_tbset ?
        g_strdup_printf("%s-%s.native", hex, tbset_hex) :
        g_strdup_printf("%s.native", hex);
    tbset_name = complete_tbset ?
        g_strdup_printf("%s-%s.tbset", hex, tbset_hex) : g_strdup("");
    final_module = g_build_filename(config->cache_dir, module_name, NULL);
    final_native = g_build_filename(config->cache_dir, native_name, NULL);
    if (complete_tbset) {
        final_tbset = g_build_filename(config->cache_dir, tbset_name, NULL);
    }

    LatAotModuleInfoV2 info;
    pthread_mutex_lock(&cache_lock);
    LatcdCurrentManifest current = {0};
    if (!static_tbset && !current_manifest_read(config, hex, &current)) {
        char *current_module = g_build_filename(config->cache_dir,
                                                 current.module, NULL);
        char *current_native = g_build_filename(config->cache_dir,
                                                 current.native, NULL);
        char *current_tbset = *current.tbset ?
            g_build_filename(config->cache_dir, current.tbset, NULL) : NULL;
        bool current_hit = cached_module_inspect(current_module, digest, &info) &&
            !access(current_native, R_OK) &&
            (!complete_tbset || (current_tbset && !access(current_tbset, R_OK) &&
             !lat_aot_v2_module_validate_tbset_file(current_module,
                 complete_tbset, error, sizeof(error))));
        if (current_hit) {
            g_free(module_name);
            g_free(native_name);
            g_free(tbset_name);
            g_free(final_module);
            g_free(final_native);
            g_free(final_tbset);
            module_name = g_strdup(current.module);
            native_name = g_strdup(current.native);
            tbset_name = g_strdup(current.tbset);
            final_module = current_module;
            final_native = current_native;
            final_tbset = current_tbset;
        } else {
            g_free(current_module);
            g_free(current_native);
            g_free(current_tbset);
        }
    }
    current_manifest_clear(&current);
    bool cache_hit = !static_tbset &&
        cached_module_inspect(final_module, digest, &info) &&
        !access(final_native, R_OK) &&
        (!complete_tbset || !access(final_tbset, R_OK));
    if (cache_hit && complete_tbset) {
        cache_hit = !lat_aot_v2_module_inspect_and_validate_tbset_file(
            final_module, complete_tbset, &info, error, sizeof(error));
    }
    if (cache_hit) {
        int publish_result = publish_current_index(
            config, hex, module_name, native_name, tbset_name, &info,
            published_sequence, false, error, sizeof(error));
        if (publish_result) {
            pthread_mutex_unlock(&cache_lock);
            goto out;
        }
        char sync_error[128] = {0};
        if (sync_directory(config->cache_dir, sync_error,
                           sizeof(sync_error))) {
            fprintf(stderr,
                    "latcd: committed cache-hit manifest sync failed: %s\n",
                    sync_error);
        }
        utimensat(AT_FDCWD, final_module, NULL, AT_SYMLINK_NOFOLLOW);
        pthread_mutex_unlock(&cache_lock);
        snprintf(error, sizeof(error), "cache hit: %s", final_module);
        status = LATCD_STATUS_OK;
        goto out;
    }
    if (!static_tbset && complete_tbset && compile_tbset &&
        strcmp(compile_tbset, complete_tbset)) {
        LatcdCurrentManifest previous = {0};
        if (!current_manifest_read(config, hex, &previous) &&
            persisted_manifest_valid(config, hex, digest)) {
            if (snapshot_current_pair(config, &previous, digest, temporary_dir,
                                     &base_native, &base_module,
                                     baseline_pins,
                                     error, sizeof(error))) {
                current_manifest_clear(&previous);
                pthread_mutex_unlock(&cache_lock);
                goto out;
            }
        }
        current_manifest_clear(&previous);
    }
    pthread_mutex_unlock(&cache_lock);
    if (!base_native && preserve_current_keys(config, hex, digest, complete_tbset,
                              temporary_dir, &retained_tbset,
                              error, sizeof(error))) {
        goto out;
    }
    const char *full_compile_tbset =
        retained_tbset ? retained_tbset : complete_tbset;
    if (!base_native) {
        compile_tbset = full_compile_tbset;
    }

    module = g_build_filename(temporary_dir, "module-XXXXXX", NULL);
    int placeholder = g_mkstemp_full(module, O_RDWR | O_CLOEXEC, 0600);
    if (placeholder < 0) {
        fail(error, sizeof(error), "cannot reserve module path: %s",
             strerror(errno));
        goto out;
    }
    close(placeholder);
    unlink(module);
    native = g_build_filename(temporary_dir, "native-XXXXXX", NULL);
    placeholder = g_mkstemp_full(native, O_RDWR | O_CLOEXEC, 0600);
    if (placeholder < 0) {
        fail(error, sizeof(error), "cannot reserve native image path: %s",
             strerror(errno));
        goto out;
    }
    close(placeholder);
    unlink(native);
    int compiler_result = run_compiler(config, worker_index, snapshot,
                                       compile_tbset, static_tbset,
                                       base_native, base_module, native,
                                       module, digest, compiler_tasks, &transient_reservation, error, sizeof(error));
    if (compiler_result) {
        if (!base_native) {
            status = LATCD_STATUS_COMPILE_FAILED;
            goto out;
        }
        /*
         * Some translated TBs cannot be merged with an older native image,
         * although a clean full compile emits them successfully.  Preserve
         * the active generation and retry without the incremental base.
         */
        fprintf(stderr,
                "latcd: incremental compile failed, retrying full compile: %s\n",
                error[0] ? error : "unknown error");
        unlink(module);
        unlink(native);
        error[0] = '\0';
        if (preserve_current_keys(config, hex, digest, complete_tbset,
                                  temporary_dir, &retained_tbset,
                                  error, sizeof(error))) {
            status = LATCD_STATUS_COMPILE_FAILED;
            goto out;
        }
        full_compile_tbset = retained_tbset ? retained_tbset : complete_tbset;
        compiler_result = run_compiler(config, worker_index, snapshot,
                                       full_compile_tbset, static_tbset,
                                       NULL, NULL, native, module, digest,
                                       compiler_tasks, &transient_reservation, error, sizeof(error));
        if (compiler_result) {
            status = LATCD_STATUS_COMPILE_FAILED;
            goto out;
        }
        unlink(base_native);
        g_clear_pointer(&base_native, g_free);
        if (base_module) unlink(base_module);
        g_clear_pointer(&base_module, g_free);
    }
    uint8_t codegen_id[32];
    expected_codegen_id(codegen_id);
    int inspect_result = complete_tbset ?
        lat_aot_v2_module_inspect_and_validate_tbset_file(
            module, complete_tbset, &info, error, sizeof(error)) :
        lat_aot_v2_module_inspect_file(module, &info,
                                       error, sizeof(error));
    bool retry_full = inspect_result && complete_tbset && base_native;
    if (retry_full) {
        /*
         * Incremental merging can omit requested TBs even though a full
         * compile can emit them.  Replace a partially covered incremental
         * result with a full compile before publishing it.
         */
        unlink(module);
        unlink(native);
        error[0] = '\0';
        if (preserve_current_keys(config, hex, digest, complete_tbset,
                                  temporary_dir, &retained_tbset,
                                  error, sizeof(error))) {
            status = LATCD_STATUS_COMPILE_FAILED;
            goto out;
        }
        full_compile_tbset = retained_tbset ? retained_tbset : complete_tbset;
        compiler_result = run_compiler(config, worker_index, snapshot,
                                       full_compile_tbset, static_tbset,
                                       NULL, NULL, native, module, digest,
                                       compiler_tasks, &transient_reservation, error, sizeof(error));
        if (compiler_result) {
            status = LATCD_STATUS_COMPILE_FAILED;
            goto out;
        }
        inspect_result = lat_aot_v2_module_inspect_and_validate_tbset_file(
            module, complete_tbset, &info, error, sizeof(error));
    }
    if (inspect_result || memcmp(info.note.source_sha256, digest, 32) ||
        memcmp(info.note.codegen_id, codegen_id, 32)) {
        if (!error[0]) {
            snprintf(error, sizeof(error),
                     "compiled module source or codegen identity mismatch");
        }
        status = LATCD_STATUS_INVALID_MODULE;
        goto out;
    }
    if (retained_tbset && lat_aot_v2_module_validate_tbset_file(
            module, retained_tbset, error, sizeof(error))) {
        status = LATCD_STATUS_INVALID_MODULE;
        goto out;
    }
    if (chmod(module, 0444) || chmod(native, 0444)) {
        fail(error, sizeof(error), "cannot protect compiled output: %s",
             strerror(errno));
        goto out;
    }
    if (sync_file(module, error, sizeof(error)) ||
        sync_file(native, error, sizeof(error))) {
        goto out;
    }
    struct stat module_status, native_status;
    if (lstat(module, &module_status) || !S_ISREG(module_status.st_mode) ||
        lstat(native, &native_status) || !S_ISREG(native_status.st_mode)) {
        fail(error, sizeof(error), "cannot inspect compiled output: %s",
             strerror(errno));
        goto out;
    }
    if (complete_tbset) {
        tbset_copy = g_build_filename(temporary_dir, "published-XXXXXX", NULL);
        int fd = g_mkstemp_full(tbset_copy, O_RDWR | O_CLOEXEC, 0600);
        bool stage_failed = fd < 0;
        if (!stage_failed &&
            (write(fd, tbset_data, tbset_size) != (ssize_t)tbset_size ||
             fchmod(fd, 0444) || fsync(fd))) {
            stage_failed = true;
        }
        if (fd >= 0 && close(fd)) stage_failed = true;
        if (stage_failed) {
            fail(error, sizeof(error), "cannot stage published TB set: %s",
                 strerror(errno));
            goto out;
        }
    }

    /*
     * Recompilation must never overwrite a file referenced by current, even
     * when the requested set has not changed.  link() below also refuses any
     * unexpected collision instead of replacing an existing generation.
     */
    char *generation = g_compute_checksum_for_string(G_CHECKSUM_SHA256,
                                                       module, -1);
    g_free(module_name);
    g_free(native_name);
    g_free(tbset_name);
    g_free(final_module);
    g_free(final_native);
    g_free(final_tbset);
    module_name = g_strdup_printf("%s-%s.so", hex, generation);
    native_name = g_strdup_printf("%s-%s.native", hex, generation);
    tbset_name = complete_tbset ?
        g_strdup_printf("%s-%s.tbset", hex, generation) : g_strdup("");
    final_module = g_build_filename(config->cache_dir, module_name, NULL);
    final_native = g_build_filename(config->cache_dir, native_name, NULL);
    final_tbset = complete_tbset ?
        g_build_filename(config->cache_dir, tbset_name, NULL) : NULL;
    g_free(generation);

    pthread_mutex_lock(&cache_lock);
    if (validate_current_replacement(config, hex, module, &info,
                                      error, sizeof(error))) {
        status = LATCD_STATUS_INVALID_MODULE;
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    uint64_t incoming = 0;
    if (!space_add(&incoming, module_status.st_size, 1) ||
        !space_add(&incoming, native_status.st_size, 1) || !space_add(&incoming, tbset_size, 1) ||
        latcd_cache_capacity_reserve(&generation_capacity, incoming, config->max_cache_bytes,
                                     error, sizeof(error))) {
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    capacity_reservation = incoming;
    const char *capacity_names[] = {module_name, native_name, tbset_name};
    if (latcd_cache_capacity_expect(&generation_capacity, capacity_names, complete_tbset ? 3 : 2,
                                    error, sizeof(error))) {
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    capacity_expected = true;
    if (!link(module, final_module)) {
        module_staged = true;
    }
    if (module_staged && !link(native, final_native)) {
        native_staged = true;
    }
    if (native_staged && complete_tbset &&
        !link(tbset_copy, final_tbset)) {
        tbset_staged = true;
    }
    if (!module_staged || !native_staged ||
        (complete_tbset && !tbset_staged)) {
        if (!error[0]) {
            fail(error, sizeof(error), "cannot publish compiled files: %s",
                 strerror(errno));
        }
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    /* Drop and persist temporary links before current can reference this
     * generation: the loader requires each published file to have one link. */
    if (unlink(module) || unlink(native) ||
        (tbset_copy && unlink(tbset_copy)) ||
        sync_directory(temporary_dir, error, sizeof(error))) {
        if (!error[0]) {
            fail(error, sizeof(error), "cannot retire staged links: %s",
                 strerror(errno));
        }
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    module[0] = native[0] = '\0';
    if (tbset_copy) {
        tbset_copy[0] = '\0';
    }
    if (sync_directory(config->cache_dir, error, sizeof(error))) {
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    const char *failpoint = getenv("LATCD_TEST_FAIL_BEFORE_MANIFEST");
    if (failpoint && *failpoint && !access(failpoint, F_OK)) {
        unlink(failpoint);
        fail(error, sizeof(error), "injected failure before manifest commit");
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    int publish_result = publish_current_index(
        config, hex, module_name, native_name, tbset_name, &info,
        published_sequence, true, error, sizeof(error));
    if (publish_result) {
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    module_staged = native_staged = tbset_staged = false;
    capacity_retained = true;
    char sync_error[128] = {0};
    if (sync_directory(config->cache_dir, sync_error,
                       sizeof(sync_error))) {
        fprintf(stderr, "latcd: committed manifest directory sync failed: %s\n",
                sync_error);
    }
    pthread_mutex_unlock(&cache_lock);
    snprintf(error, sizeof(error), "published: %s", final_module);
    status = LATCD_STATUS_OK;
out:
    response->status = status;
    g_strlcpy(response->message, error[0] ? error : "unknown error",
              sizeof(response->message));
    bool transient_retained = false;
    if (module && *module && unlink(module) && errno != ENOENT) transient_retained = true;
    if (native && *native && unlink(native) && errno != ENOENT) transient_retained = true;
    for (guint i = 0; i < compiler_tasks->len; i++) {
        LatcdCompilerTask *task = g_ptr_array_index(compiler_tasks, i);
        if (record_compiler_release(config, task->id, &task->identity, true)) {
            transient_retained = true;
            fprintf(stderr, "latcd: compiler output release not durable; retaining task root\n");
        }
        compiler_task_local(task->id, false);
    }
    if (transient_reservation) latcd_cache_capacity_finish_transient(
        &generation_capacity, transient_reservation, transient_retained);
    g_ptr_array_free(compiler_tasks, TRUE);
    if (tbset_copy && *tbset_copy) unlink(tbset_copy);
    if (module_staged && unlink(final_module) && errno != ENOENT) capacity_retained = true;
    if (native_staged && unlink(final_native) && errno != ENOENT) capacity_retained = true;
    if (tbset_staged && unlink(final_tbset) && errno != ENOENT) capacity_retained = true;
    if (capacity_expected) {
        const char *names[] = {module_name, native_name, tbset_name};
        latcd_cache_capacity_complete(&generation_capacity, names, complete_tbset ? 3 : 2);
    }
    if (capacity_reservation)
        latcd_cache_capacity_finish(&generation_capacity, capacity_reservation, capacity_retained);
    g_free(tbset_data);
    if (retained_tbset) {
        unlink(retained_tbset);
    }
    g_free(retained_tbset);
    if (base_native) unlink(base_native);
    g_free(base_native);
    if (base_module) unlink(base_module);
    g_free(base_module);
    for (unsigned i = 2; i < 4; i++) {
        if (baseline_pins[i] >= 0) {
            char release_error[128];
            if (release_copy_task(config, baseline_pins[i], release_error, sizeof(release_error)))
                fprintf(stderr, "latcd: %s; retaining copy task root\n", release_error);
        }
    }
    for (unsigned i = 0; i < 4; i++) {
        if (baseline_pins[i] >= 0) close(baseline_pins[i]);
    }
    g_free(final_tbset);
    g_free(final_native);
    g_free(final_module);
    g_free(tbset_name);
    g_free(native_name);
    g_free(module_name);
    g_free(tbset_copy);
    g_free(native);
    g_free(module);
    g_free(temporary_dir);
    return status ? -1 : 0;
}

static int process_request(const LatcdConfig *config, int source_fd,
                           int tbset_fd, bool static_tbset,
                           LatcdResponseV2 *response)
{
    char error[sizeof(response->message)] = {0};
    char *temporary_dir = g_build_filename(config->cache_dir, ".tmp", NULL);
    char *snapshot = NULL;
    char *tbset = NULL;
    char *canonical = NULL;
    int result = -1;
    if (ensure_private_directory(config->cache_dir, error, sizeof(error)) ||
        ensure_private_directory(temporary_dir, error, sizeof(error))) {
        response->status = LATCD_STATUS_IO_ERROR;
        goto out;
    }
    struct stat identity;
    if (snapshot_source(source_fd, temporary_dir, config->max_input, &snapshot,
                        response->source_sha256, &identity,
                        error, sizeof(error))) {
        response->status = LATCD_STATUS_BAD_SOURCE;
        goto out;
    }
    publish_source_identity(config, &identity, response->source_sha256);
    if (tbset_fd >= 0 && snapshot_tbset(
            tbset_fd, snapshot, temporary_dir, response->source_sha256,
            &tbset, error, sizeof(error))) {
        response->status = LATCD_STATUS_BAD_REQUEST;
        goto out;
    }
    if (tbset && static_tbset &&
        prepare_static_tbset(config, response->source_sha256, tbset,
                             &canonical, error, sizeof(error))) {
        response->status = LATCD_STATUS_BAD_REQUEST;
        goto out;
    }
    if (tbset && !static_tbset &&
        merge_tbset(config, response->source_sha256, tbset,
                               &canonical, NULL, error, sizeof(error))) {
        response->status = LATCD_STATUS_BAD_REQUEST;
        goto out;
    }
    result = publish_snapshot(config, 0, snapshot,
                              canonical ? canonical : tbset,
                              canonical ? canonical : tbset,
                              static_tbset,
                              response->source_sha256, 0,
                              response);
out:
    if (result && !response->message[0]) {
        g_strlcpy(response->message, error[0] ? error : "unknown error",
                  sizeof(response->message));
    }
    if (snapshot) {
        unlink(snapshot);
    }
    g_free(snapshot);
    if (tbset) unlink(tbset);
    g_free(tbset);
    g_free(canonical);
    g_free(temporary_dir);
    return result;
}

static void job_free(LatcdJob *job)
{
    if (!job) {
        return;
    }
    if (job->snapshot) {
        unlink(job->snapshot);
    }
    if (job->tbset && !job->tbset_canonical) {
        unlink(job->tbset);
    }
    g_free(job->snapshot);
    g_free(job->tbset);
    g_free(job);
}

static int cache_contains(const LatcdConfig *config, const uint8_t digest[32])
{
    char hex[65];
    digest_hex(digest, hex);
    LatcdCurrentManifest manifest = {0};
    pthread_mutex_lock(&cache_lock);
    int valid = !current_manifest_read(config, hex, &manifest);
    char *module = valid ? g_build_filename(config->cache_dir,
                                             manifest.module, NULL) : NULL;
    char *native = valid ? g_build_filename(config->cache_dir,
                                             manifest.native, NULL) : NULL;
    LatAotModuleInfoV2 info;
    valid = valid && cached_module_inspect(module, digest, &info) &&
            !access(native, R_OK);
    pthread_mutex_unlock(&cache_lock);
    g_free(native);
    g_free(module);
    current_manifest_clear(&manifest);
    return valid;
}

static int cache_contains_tbset(const LatcdConfig *config,
                                const uint8_t digest[32],
                                const char *tbset)
{
    LatTbKeySet requested = {0};
    LatTbKeySet published = {0};
    LatTbKeySet missing = {0};
    char error[128] = {0};
    char hex[65];
    digest_hex(digest, hex);
    LatcdCurrentManifest manifest = {0};
    int manifest_valid = !current_manifest_read(config, hex, &manifest) &&
                         *manifest.tbset;
    char *path = manifest_valid ?
        g_build_filename(config->cache_dir, manifest.tbset, NULL) : NULL;
    int valid = !lat_tb_key_set_read_file(tbset, digest, &requested,
                                           error, sizeof(error)) &&
                path && !lat_tb_key_set_read_file(path, digest, &published,
                                           error, sizeof(error)) &&
                !lat_tb_key_set_difference(&requested, &published, &missing,
                                            error, sizeof(error)) &&
                !missing.count;
    pthread_mutex_lock(&cache_lock);
    char *module_path = manifest_valid ? g_build_filename(
        config->cache_dir, manifest.module, NULL) : NULL;
    char *native_path = manifest_valid ? g_build_filename(
        config->cache_dir, manifest.native, NULL) : NULL;
    LatAotModuleInfoV2 info;
    valid = valid && cached_module_inspect(module_path, digest, &info) &&
            !access(native_path, R_OK);
    pthread_mutex_unlock(&cache_lock);
    g_free(native_path);
    g_free(module_path);
    lat_tb_key_set_destroy(&requested);
    lat_tb_key_set_destroy(&published);
    lat_tb_key_set_destroy(&missing);
    current_manifest_clear(&manifest);
    g_free(path);
    return valid;
}

static void write_stats_locked(LatcdService *service)
{
    if (!service->config->stats_path) {
        return;
    }
    char *temporary = g_strdup_printf("%s.tmp.%ld",
        service->config->stats_path, (long)getpid());
    char contents[2048];
    pthread_mutex_lock(&generation_capacity.lock);
    uint64_t generation_bytes = generation_capacity.committed;
    uint64_t publication_bytes = generation_capacity.reserved;
    uint64_t transient_bytes = generation_capacity.transient_reserved;
    uint64_t recovered_bytes = generation_capacity.recovered_reserved;
    unsigned unknown_budgets = generation_capacity.unknown_tasks ?
        g_hash_table_size(generation_capacity.unknown_tasks) : 0;
    bool capacity_ready = generation_capacity.ready;
    int budget_recovery = atomic_load(&compiler_budget_recovery_state);
    pthread_mutex_unlock(&generation_capacity.lock);
    pthread_mutex_lock(&retirement_queue_lock);
    LatcdRetirementQueueStats retirement = retirement_queue_stats;
    pthread_mutex_unlock(&retirement_queue_lock);
    int length = snprintf(contents, sizeof(contents),
        "{\"requests\":%" PRIu64 ",\"queued\":%" PRIu64
        ",\"deduplicated\":%" PRIu64 ",\"cache_hits\":%" PRIu64
        ",\"compiled\":%" PRIu64 ",\"failed\":%" PRIu64
        ",\"negative_hits\":%" PRIu64 ",\"queue_full\":%" PRIu64
        ",\"queue_depth\":%u,\"queue_bytes\":%" PRIu64
        ",\"active_jobs\":%u,\"running_sources\":%u,\"workers\":%u"
        ",\"max_cache_bytes\":%" PRIu64
        ",\"cache_owner_pid\":%ld,\"generation_logical_bytes\":%" PRIu64
        ",\"publication_reserved_bytes\":%" PRIu64 ",\"compiler_peak_reserved_bytes\":%" PRIu64
        ",\"recovered_compiler_reserved_bytes\":%" PRIu64
        ",\"unknown_compiler_budget_tasks\":%u"
        ",\"compiler_budget_recovery_state\":%d"
        ",\"retirement_candidates\":%u,\"retirement_due_candidates\":%u"
        ",\"retirement_next_deadline_boottime_us\":%" PRIu64
        ",\"retirement_oldest_due_wait_us\":%" PRIu64
        ",\"retirement_discovery_complete\":%s,\"automatic_deletion_enabled\":false"
        ",\"generation_capacity_ready\":%s}\n",
        service->requests, service->queued, service->deduplicated,
        service->cache_hits, service->compiled, service->failed,
        service->negative_hits, service->queue_full, service->queue->len,
        service->queued_bytes,
        g_hash_table_size(service->active),
        g_hash_table_size(service->running_sources), service->config->workers,
        service->config->max_cache_bytes, (long)getpid(), generation_bytes,
        publication_bytes, transient_bytes, recovered_bytes, unknown_budgets, budget_recovery,
        retirement.candidates, retirement.due, retirement.next_deadline_us, retirement.oldest_due_wait_us,
        retirement.complete ? "true" : "false",
        capacity_ready ? "true" : "false");
    int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
        ssize_t written = write(fd, contents, length);
        if (written == length) {
            close(fd);
            if (!rename(temporary, service->config->stats_path)) {
                g_free(temporary);
                return;
            }
        } else {
            close(fd);
        }
    }
    unlink(temporary);
    g_free(temporary);
}

static LatcdJob *queue_take_next_locked(LatcdService *service,
                                        int64_t *next_ready_at_us)
{
    *next_ready_at_us = 0;
    if (!service->queue->len) {
        return NULL;
    }
    int64_t now = g_get_monotonic_time();
    guint selected = 0;
    LatcdJob *best = NULL;
    uint64_t best_work = 0;
    for (guint i = 0; i < service->queue->len; i++) {
        LatcdJob *candidate = g_ptr_array_index(service->queue, i);
        if (g_hash_table_contains(service->running_sources,
                                  candidate->source_key)) {
            continue;
        }
        if (!service->stopping && candidate->ready_at_us > now) {
            if (!*next_ready_at_us ||
                candidate->ready_at_us < *next_ready_at_us) {
                *next_ready_at_us = candidate->ready_at_us;
            }
            continue;
        }
        struct stat tbset_status;
        uint64_t candidate_work = candidate->source_size;
        if (service->config->flush_only && candidate->tbset &&
            !stat(candidate->tbset, &tbset_status) &&
            tbset_status.st_size > 0) {
            candidate_work = tbset_status.st_size;
        }
        bool preferred = !best;
        if (best && service->config->flush_only) {
            preferred = candidate_work > best_work ||
                (candidate_work == best_work &&
                 (candidate->priority > best->priority ||
                  (candidate->priority == best->priority &&
                   candidate->sequence < best->sequence)));
        } else if (best) {
            preferred = candidate->priority > best->priority ||
                (candidate->priority == best->priority &&
                 candidate->sequence < best->sequence);
        }
        if (preferred) {
            selected = i;
            best = candidate;
            best_work = candidate_work;
        }
    }
    if (!best) {
        return NULL;
    }
    g_ptr_array_remove_index(service->queue, selected);
    service->queued_bytes -= best->source_size;
    g_hash_table_add(service->running_sources,
                     g_strdup(best->source_key));
    best->running = true;
    return best;
}

static void negative_record_locked(LatcdService *service, const char *key,
                                   int status)
{
    LatcdNegativeEntry *entry = g_hash_table_lookup(service->negative, key);
    if (!entry) {
        if (g_hash_table_size(service->negative) >=
            service->config->max_negative) {
            GHashTableIter iterator;
            gpointer old_key;
            g_hash_table_iter_init(&iterator, service->negative);
            if (g_hash_table_iter_next(&iterator, &old_key, NULL)) {
                g_hash_table_iter_remove(&iterator);
            }
        }
        entry = g_new0(LatcdNegativeEntry, 1);
        g_hash_table_insert(service->negative, g_strdup(key), entry);
    }
    entry->failures++;
    entry->status = status;
    uint32_t shift = entry->failures > 6 ? 6 : entry->failures - 1;
    entry->retry_at_us = g_get_monotonic_time() +
        (int64_t)service->config->negative_ms * 1000 * (UINT64_C(1) << shift);
}

static void journal_receipt_admission_failed_locked(LatcdService *service,
                                                    const LatcdJob *job)
{
    GHashTableIter iterator;
    gpointer value;
    g_hash_table_iter_init(&iterator, service->journal_receipts);
    while (g_hash_table_iter_next(&iterator, NULL, &value)) {
        LatcdJournalReceiptState *receipt = value;
        if (!memcmp(receipt->source_sha256, job->digest,
                    sizeof(receipt->source_sha256)))
            g_hash_table_iter_remove(&iterator);
    }
}

static void mark_job_failed_locked(LatcdService *service, const LatcdJob *job)
{
    if (job->static_tbset) {
        LatcdStaticBarrier *barrier = g_hash_table_lookup(
            service->static_barriers, job->key);
        if (barrier) barrier->failed = true;
        return;
    }
    /* Static failures are scoped by first_sequence in their own barrier. */
    LatcdSourceState *state = source_state_locked(service, job->source_key);
    state->failed_sequence = MAX(state->failed_sequence, job->accepted_sequence);
}

static void *compiler_worker(void *opaque)
{
    LatcdWorker *worker = opaque;
    LatcdService *service = worker->service;
    for (;;) {
        pthread_mutex_lock(&service->lock);
        LatcdJob *job = NULL;
        while (!job) {
            if (service->stopping && !service->queue->len) {
                pthread_mutex_unlock(&service->lock);
                return NULL;
            }
            int64_t next_ready_at_us = 0;
            job = queue_take_next_locked(service, &next_ready_at_us);
            if (!job) {
                if (next_ready_at_us) {
                    int64_t wait_us = next_ready_at_us -
                                      g_get_monotonic_time();
                    if (wait_us < 0) wait_us = 0;
                    struct timespec deadline;
                    clock_gettime(CLOCK_REALTIME, &deadline);
                    deadline.tv_sec += wait_us / 1000000;
                    deadline.tv_nsec += (wait_us % 1000000) * 1000;
                    if (deadline.tv_nsec >= 1000000000) {
                        deadline.tv_sec++;
                        deadline.tv_nsec -= 1000000000;
                    }
                    pthread_cond_timedwait(&service->ready, &service->lock,
                                           &deadline);
                } else {
                    pthread_cond_wait(&service->ready, &service->lock);
                }
            }
        }
        write_stats_locked(service);
        job->compile_sequence = job->accepted_sequence;
        pthread_mutex_unlock(&service->lock);
        LatcdResponseV2 response = {
            .magic = LATCD_RESPONSE_MAGIC,
            .version = LATCD_PROTOCOL_VERSION,
            .size = sizeof(response),
        };
        char error[sizeof(response.message)] = {0};
        char *canonical = NULL;
        char *stable_tbset = NULL;
        char *compile_delta = NULL;
        bool delta_empty = false;
        int result = job->tbset && !job->tbset_canonical &&
            !job->static_tbset && merge_tbset(
            service->config, job->digest, job->tbset, &canonical, NULL,
            error, sizeof(error));
        if (!result && job->static_tbset) {
            result = prepare_static_tbset(service->config, job->digest,
                                           job->tbset, &stable_tbset,
                                           error, sizeof(error));
        }
        if (!result && job->tbset_canonical) {
            int tbset_fd = open(job->tbset,
                                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            char *temporary_dir = g_build_filename(
                service->config->cache_dir, ".tmp", NULL);
            if (tbset_fd < 0) {
                result = fail(error, sizeof(error),
                              "cannot open canonical TB set: %s",
                              strerror(errno));
            } else {
                result = snapshot_tbset(
                    tbset_fd, job->snapshot, temporary_dir, job->digest,
                    &stable_tbset, error, sizeof(error));
            }
            if (tbset_fd >= 0) close(tbset_fd);
            g_free(temporary_dir);
            if (!result) {
                char *complete = NULL;
                result = prepare_static_tbset(service->config, job->digest,
                                               stable_tbset, &complete,
                                               error, sizeof(error));
                if (!result) {
                    unlink(stable_tbset);
                    g_free(stable_tbset);
                    stable_tbset = complete;
                }
            }
        }
        const char *compile_tbset = job->tbset_canonical || job->static_tbset ?
                                    stable_tbset :
                                    (canonical ? canonical : job->tbset);
        if (!result && compile_tbset && !job->static_tbset) {
            result = prepare_compile_delta(service->config, job->digest,
                                           compile_tbset, &compile_delta,
                                           &delta_empty,
                                           error, sizeof(error));
                /*
                 * A published TB set only describes key coverage.  It must
                 * not suppress recompilation when its current module was
                 * removed, corrupted, or built by another code generator.
                 */
                if (!result && delta_empty) {
                    pthread_mutex_lock(&cache_lock);
                    bool manifest_valid = persisted_manifest_valid(
                        service->config, job->source_key, job->digest);
                    pthread_mutex_unlock(&cache_lock);
                    if (!manifest_valid) {
                        delta_empty = false;
                    }
                }
        }
        if (!result && !delta_empty) {
            result = publish_snapshot(service->config, worker->index,
                                      job->snapshot,
                                      compile_delta ? compile_delta :
                                      compile_tbset,
                                      compile_tbset, job->static_tbset,
                                      job->digest,
                                      job->compile_sequence, &response);
        } else if (!result) {
            int publish_result = publish_covered_tbset(
                service->config, compile_tbset, job->digest,
                job->compile_sequence, &response);
            if (publish_result > 0) {
                result = publish_snapshot(
                    service->config, worker->index, job->snapshot,
                    compile_tbset, compile_tbset, job->static_tbset,
                    job->digest,
                    job->compile_sequence, &response);
            } else {
                result = publish_result;
            }
        }
        if (result && response.status == LATCD_STATUS_OK) {
            response.status = LATCD_STATUS_BAD_REQUEST;
            g_strlcpy(response.message, error, sizeof(response.message));
        }
        g_free(canonical);
        if (compile_delta) unlink(compile_delta);
        g_free(compile_delta);
        if (stable_tbset) unlink(stable_tbset);
        g_free(stable_tbset);

        pthread_mutex_lock(&service->lock);
        g_hash_table_remove(service->running_sources, job->source_key);
        LatcdSourceState *source_state = source_state_locked(
            service, job->source_key);
        if (job->static_tbset) {
            if (!result) {
                g_hash_table_remove(service->static_barriers, job->key);
            }
        }
        if (!result) {
            service->compiled++;
            uint64_t published_sequence = job->dirty ?
                job->compile_sequence : job->accepted_sequence;
            if (!job->static_tbset &&
                published_sequence > source_state->published_sequence) {
                source_state->published_sequence = published_sequence;
            }
            if (!job->static_tbset &&
                source_state->failed_sequence <= published_sequence) {
                source_state->failed_sequence = 0;
            }
            if (job->flush_sequence <= published_sequence) {
                job->flush_sequence = 0;
            }
            g_hash_table_remove(service->negative, job->key);
        } else {
            service->failed++;
            /* This failed job is removed, including requests accepted while
             * it was running. None can wait for a nonexistent retry job. */
            journal_receipt_admission_failed_locked(service, job);
            mark_job_failed_locked(service, job);
            negative_record_locked(service, job->key, response.status);
            fprintf(stderr, "latcd: job %s failed status=%d: %s\n",
                    job->key, response.status,
                    response.message[0] ? response.message : "unknown error");
        }
        if (!result && job->tbset_canonical && job->dirty) {
            job->running = false;
            job->dirty = false;
            job->sequence = service->next_sequence++;
            if (job->flush_sequence > job->compile_sequence) {
                job->ready_at_us = 0;
            }
            g_ptr_array_add(service->queue, job);
            service->queued_bytes += job->source_size;
            service->queued++;
            write_stats_locked(service);
            pthread_cond_broadcast(&service->ready);
            pthread_mutex_unlock(&service->lock);
            continue;
        }
        g_hash_table_remove(service->active, job->key);
        write_stats_locked(service);
        pthread_cond_broadcast(&service->ready);
        pthread_mutex_unlock(&service->lock);
        job_free(job);
    }
    return NULL;
}

static void response_init(LatcdResponseV2 *response, uint64_t request_id)
{
    memset(response, 0, sizeof(*response));
    response->magic = LATCD_RESPONSE_MAGIC;
    response->version = LATCD_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->request_id = request_id;
}

static LatcdSourceState *source_state_locked(LatcdService *service,
                                             const char *source_key)
{
    LatcdSourceState *state = g_hash_table_lookup(service->source_states,
                                                   source_key);
    if (!state) {
        state = g_new0(LatcdSourceState, 1);
        g_hash_table_insert(service->source_states, g_strdup(source_key),
                            state);
    }
    return state;
}

static int hex_digest(const char text[64], uint8_t digest[32])
{
    for (size_t i = 0; i < 32; i++) {
        int high = g_ascii_xdigit_value(text[i * 2]);
        int low = g_ascii_xdigit_value(text[i * 2 + 1]);
        if (high < 0 || low < 0) return -1;
        digest[i] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static int persisted_manifest_valid(const LatcdConfig *config,
                                    const char source_key[65],
                                    const uint8_t digest[32])
{
    LatcdCurrentManifest manifest = {0};
    int valid = !current_manifest_read(config, source_key, &manifest);
    char *module = valid ? g_build_filename(config->cache_dir,
                                             manifest.module, NULL) : NULL;
    char *native = valid ? g_build_filename(config->cache_dir,
                                             manifest.native, NULL) : NULL;
    char *tbset = valid && *manifest.tbset ?
        g_build_filename(config->cache_dir, manifest.tbset, NULL) : NULL;
    LatAotModuleInfoV2 info;
    valid = valid && cached_module_inspect(module, digest, &info) &&
            !access(native, R_OK) && (!*manifest.tbset || !access(tbset, R_OK));
    g_free(tbset);
    g_free(native);
    g_free(module);
    current_manifest_clear(&manifest);
    return valid;
}

static void load_persisted_source_states(LatcdService *service)
{
    char *directory = g_build_filename(service->config->cache_dir,
                                        ".tbsets", NULL);
    GDir *entries = g_dir_open(directory, 0, NULL);
    if (!entries) {
        g_free(directory);
        return;
    }
    const char *name;
    while ((name = g_dir_read_name(entries))) {
        if (strlen(name) != 70 || strcmp(name + 64, ".tbset")) continue;
        char source_key[65];
        memcpy(source_key, name, 64);
        source_key[64] = '\0';
        uint8_t digest[32];
        if (hex_digest(source_key, digest)) continue;
        char *known_path = g_build_filename(directory, name, NULL);
        LatcdCurrentManifest manifest = {0};
        int manifest_valid = !current_manifest_read(
            service->config, source_key, &manifest) && *manifest.tbset;
        char *published_path = manifest_valid ? g_build_filename(
            service->config->cache_dir, manifest.tbset, NULL) : NULL;
        LatTbKeySet known = {0};
        LatTbKeySet published = {0};
        LatTbKeySet missing = {0};
        char error[128] = {0};
        int known_valid = !lat_tb_key_set_read_file(
            known_path, digest, &known, error, sizeof(error));
        int fully_published = known_valid && published_path &&
            !lat_tb_key_set_read_file(published_path, digest, &published,
                                      error, sizeof(error)) &&
            !lat_tb_key_set_difference(&known, &published, &missing,
                                       error, sizeof(error)) &&
            !missing.count && persisted_manifest_valid(
                service->config, source_key, digest);
        if (known_valid) {
            LatcdSourceState *state = source_state_locked(service, source_key);
            state->accepted_sequence = known.sequence;
            state->runtime_accepted_sequence = known.sequence;
            if (fully_published) state->published_sequence = known.sequence;
            else state->failed_sequence = known.sequence;
            if (known.sequence > service->next_sequence) {
                service->next_sequence = known.sequence;
            }
        }
        lat_tb_key_set_destroy(&known);
        lat_tb_key_set_destroy(&published);
        lat_tb_key_set_destroy(&missing);
        current_manifest_clear(&manifest);
        g_free(published_path);
        g_free(known_path);
    }
    g_dir_close(entries);
    g_free(directory);
}

static char *reuse_active_source(LatcdService *service, int source_fd,
                                 const char *temporary_dir,
                                 uint8_t digest[32], struct stat *identity)
{
    struct stat before, after, snapshot_before, snapshot_after;
    int flags = fcntl(source_fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
        fstat(source_fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_size < 0 ||
        (uint64_t)before.st_size > service->config->max_input) {
        return NULL;
    }
    char *path = NULL;
    pthread_mutex_lock(&service->lock);
    GHashTableIter iterator;
    gpointer value;
    g_hash_table_iter_init(&iterator, service->active);
    while (g_hash_table_iter_next(&iterator, NULL, &value)) {
        LatcdJob *job = value;
        if (!metadata_equal(&before, &job->source_identity)) continue;
        path = g_build_filename(temporary_dir, "source-reuse-XXXXXX", NULL);
        int fd = g_mkstemp_full(path, O_RDWR | O_CLOEXEC, 0600);
        if (fd >= 0) close(fd);
        if (fd < 0 || unlink(path) || link(job->snapshot, path)) {
            g_free(path);
            path = NULL;
        } else {
            memcpy(digest, job->digest, 32);
        }
        break;
    }
    pthread_mutex_unlock(&service->lock);
    if (!path) return NULL;

    /* The private link pins the snapshot while the worker finishes its job. */
    int snapshot = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    bool equal = snapshot >= 0 && !fstat(snapshot, &snapshot_before) &&
        S_ISREG(snapshot_before.st_mode) &&
        snapshot_before.st_size == before.st_size;
    unsigned char source_bytes[128 * 1024], snapshot_bytes[128 * 1024];
    for (off_t offset = 0; equal && offset < before.st_size;) {
        size_t size = MIN(sizeof(source_bytes), (uint64_t)(before.st_size - offset));
        ssize_t a, b;
        do {
            a = pread(source_fd, source_bytes, size, offset);
        } while (a < 0 && errno == EINTR);
        do {
            b = pread(snapshot, snapshot_bytes, size, offset);
        } while (b < 0 && errno == EINTR);
        equal = a == (ssize_t)size && b == a &&
                !memcmp(source_bytes, snapshot_bytes, size);
        offset += size;
    }
    equal = equal && !fstat(source_fd, &after) &&
        metadata_equal(&before, &after) &&
        !fstat(snapshot, &snapshot_after) &&
        metadata_equal(&snapshot_before, &snapshot_after);
    if (snapshot >= 0) close(snapshot);
    if (!equal) {
        unlink(path);
        g_free(path);
        return NULL;
    }
    *identity = before;
    return path;
}

static int service_queue_request(LatcdService *service, int source_fd,
                                 int tbset_fd,
                                 const LatcdRequestV2 *request,
                                 LatcdResponseV2 *response)
{
    char error[sizeof(response->message)] = {0};
    char *temporary_dir = g_build_filename(service->config->cache_dir,
                                            ".tmp", NULL);
    char *snapshot = NULL;
    char *tbset = NULL;
    response_init(response, request->request_id);
    if (atomic_load(&compiler_budget_recovery_state) != 1) {
        response->status = LATCD_STATUS_QUEUE_FULL;
        g_strlcpy(response->message, "capacity: compiler budget recovery pending or unsafe",
                  sizeof(response->message));
        g_free(temporary_dir);
        return -1;
    }
    struct stat identity;
    snapshot = reuse_active_source(service, source_fd, temporary_dir,
                                    response->source_sha256, &identity);
    if (!snapshot && snapshot_source(source_fd, temporary_dir,
                        service->config->max_input, &snapshot,
                        response->source_sha256, &identity,
                        error, sizeof(error))) {
        response->status = LATCD_STATUS_BAD_SOURCE;
        g_strlcpy(response->message, error, sizeof(response->message));
        g_free(temporary_dir);
        return -1;
    }
    publish_source_identity(service->config, &identity,
                            response->source_sha256);
    if (tbset_fd >= 0 && snapshot_tbset(
            tbset_fd, snapshot, temporary_dir, response->source_sha256,
            &tbset, error, sizeof(error))) {
        response->status = LATCD_STATUS_BAD_REQUEST;
        g_strlcpy(response->message, error, sizeof(response->message));
        unlink(snapshot);
        g_free(snapshot);
        g_free(temporary_dir);
        return -1;
    }
    bool tbset_canonical = false;
    bool tbset_changed = false;
    bool static_tbset = request->operation == LATCD_OP_SUBMIT_STATIC_KEYS;
    if (tbset && !static_tbset) {
        char *canonical = NULL;
        if (merge_tbset(service->config, response->source_sha256, tbset,
                        &canonical, &tbset_changed,
                        error, sizeof(error))) {
            response->status = LATCD_STATUS_BAD_REQUEST;
            g_strlcpy(response->message, error, sizeof(response->message));
            unlink(snapshot);
            unlink(tbset);
            g_free(snapshot);
            g_free(tbset);
            g_free(temporary_dir);
            return -1;
        }
        unlink(tbset);
        g_free(tbset);
        tbset = canonical;
        tbset_canonical = true;
    }
    g_free(temporary_dir);
    char key[130];
    digest_hex(response->source_sha256, key);
    char source_key[65];
    memcpy(source_key, key, 65);
    if (static_tbset) {
        gchar *contents = NULL;
        gsize size = 0;
        if (!g_file_get_contents(tbset, &contents, &size, NULL)) {
            response->status = LATCD_STATUS_IO_ERROR;
            g_strlcpy(response->message, "cannot hash static TB set",
                      sizeof(response->message));
            unlink(snapshot);
            unlink(tbset);
            g_free(snapshot);
            g_free(tbset);
            return -1;
        }
        gchar *hash = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
                                                   (guchar *)contents, size);
        snprintf(key + 64, sizeof(key) - 64, "-%s", hash);
        g_free(hash);
        g_free(contents);
    } else if (tbset) {
        snprintf(key + 64, sizeof(key) - 64, "-tbset");
    }
    struct stat snapshot_status;
    if (stat(snapshot, &snapshot_status) || snapshot_status.st_size < 0) {
        response->status = LATCD_STATUS_IO_ERROR;
        g_strlcpy(response->message, "cannot inspect source snapshot",
                  sizeof(response->message));
        unlink(snapshot);
        if (tbset && !tbset_canonical) unlink(tbset);
        g_free(snapshot);
        g_free(tbset);
        return -1;
    }
    uint64_t source_size = snapshot_status.st_size;

    pthread_mutex_lock(&service->lock);
    service->requests++;
    uint64_t accepted_sequence = ++service->next_sequence;
    LatcdSourceState *source_state = source_state_locked(service, source_key);
    uint64_t previous_accepted = source_state->accepted_sequence;
    source_state->accepted_sequence = accepted_sequence;
    response->accepted_sequence = accepted_sequence;
    response->published_sequence = source_state->published_sequence;
    if (!tbset && cache_contains(service->config,
                                   response->source_sha256)) {
        service->cache_hits++;
        source_state->published_sequence = accepted_sequence;
        source_state->runtime_accepted_sequence = accepted_sequence;
        response->published_sequence = accepted_sequence;
        response->status = LATCD_STATUS_OK;
        snprintf(response->message, sizeof(response->message),
                 "cache hit: %s", key);
        write_stats_locked(service);
        pthread_mutex_unlock(&service->lock);
        unlink(snapshot);
        if (tbset && !tbset_canonical) unlink(tbset);
        g_free(snapshot);
        g_free(tbset);
        return 0;
    }
    if (tbset_canonical &&
        cache_contains_tbset(service->config, response->source_sha256,
                             tbset)) {
        service->cache_hits++;
        source_state->published_sequence = accepted_sequence;
        source_state->runtime_accepted_sequence = accepted_sequence;
        response->published_sequence = accepted_sequence;
        response->status = LATCD_STATUS_OK;
        snprintf(response->message, sizeof(response->message),
                 "cache hit: %s", key);
        write_stats_locked(service);
        pthread_mutex_unlock(&service->lock);
        unlink(snapshot);
        g_free(snapshot);
        g_free(tbset);
        return 0;
    }
    if (g_hash_table_contains(service->active, key)) {
        LatcdJob *active = g_hash_table_lookup(service->active, key);
        if (tbset_canonical && tbset_changed && active) {
            int64_t now = g_get_monotonic_time();
            if (active->running) {
                if (!active->dirty) active->batch_started_at_us = now;
                active->dirty = true;
            }
            if (active->flush_sequence > (active->running ?
                                          active->compile_sequence : 0)) {
                active->ready_at_us = 0;
            } else if (service->config->flush_only) {
                active->ready_at_us = INT64_MAX;
            } else if (!active->running) {
                int64_t quiet_ready = now + LATCD_BATCH_QUIET_US;
                int64_t maximum_ready = active->batch_started_at_us +
                                        LATCD_BATCH_MAX_US;
                active->ready_at_us = quiet_ready < maximum_ready ?
                                      quiet_ready : maximum_ready;
            } else {
                int64_t quiet_ready = now + LATCD_BATCH_QUIET_US;
                int64_t maximum_ready = active->batch_started_at_us +
                                        LATCD_BATCH_MAX_US;
                active->ready_at_us = quiet_ready < maximum_ready ?
                                      quiet_ready : maximum_ready;
            }
        }
        if (active && accepted_sequence > active->accepted_sequence) {
            active->accepted_sequence = accepted_sequence;
        }
        if (static_tbset) {
            LatcdStaticBarrier *barrier = g_hash_table_lookup(
                service->static_barriers, key);
            if (barrier) barrier->last_sequence = accepted_sequence;
        }
        service->deduplicated++;
        if (!static_tbset) {
            source_state->runtime_accepted_sequence = accepted_sequence;
        }
        response->status = LATCD_STATUS_OK;
        snprintf(response->message, sizeof(response->message),
                 "deduplicated: %s", key);
        write_stats_locked(service);
        pthread_mutex_unlock(&service->lock);
        unlink(snapshot);
        if (tbset && !tbset_canonical) unlink(tbset);
        g_free(snapshot);
        g_free(tbset);
        return 0;
    }
    LatcdNegativeEntry *negative = g_hash_table_lookup(service->negative, key);
    if (negative && negative->retry_at_us > g_get_monotonic_time()) {
        source_state->accepted_sequence = previous_accepted;
        response->accepted_sequence = previous_accepted;
        service->negative_hits++;
        response->status = LATCD_STATUS_NEGATIVE_CACHE;
        snprintf(response->message, sizeof(response->message),
                 "negative cache: retry in %" PRId64 " ms",
                 (negative->retry_at_us - g_get_monotonic_time()) / 1000);
        write_stats_locked(service);
        pthread_mutex_unlock(&service->lock);
        unlink(snapshot);
        if (tbset && !tbset_canonical) unlink(tbset);
        g_free(snapshot);
        g_free(tbset);
        return -1;
    }
    if (service->queue->len >= service->config->max_jobs ||
        source_size > service->config->max_queue_bytes -
                      service->queued_bytes) {
        source_state->accepted_sequence = previous_accepted;
        response->accepted_sequence = previous_accepted;
        service->queue_full++;
        response->status = LATCD_STATUS_QUEUE_FULL;
        g_strlcpy(response->message, "compiler queue is full",
                  sizeof(response->message));
        write_stats_locked(service);
        pthread_mutex_unlock(&service->lock);
        unlink(snapshot);
        if (tbset && !tbset_canonical) unlink(tbset);
        g_free(snapshot);
        g_free(tbset);
        return -1;
    }
    LatcdJob *job = g_new0(LatcdJob, 1);
    job->snapshot = snapshot;
    job->source_identity = identity;
    job->tbset = tbset;
    job->tbset_canonical = tbset_canonical;
    job->static_tbset = static_tbset;
    g_strlcpy(job->key, key, sizeof(job->key));
    memcpy(job->source_key, key, 64);
    job->source_key[64] = '\0';
    memcpy(job->digest, response->source_sha256, sizeof(job->digest));
    job->priority = request->priority;
    job->sequence = accepted_sequence;
    job->accepted_sequence = accepted_sequence;
    job->source_size = source_size;
    job->batch_started_at_us = g_get_monotonic_time();
    job->ready_at_us = service->config->flush_only ? INT64_MAX :
                       job->batch_started_at_us + LATCD_BATCH_QUIET_US;
    if (static_tbset) {
        LatcdStaticBarrier *barrier = g_hash_table_lookup(
            service->static_barriers, key);
        if (!barrier) {
            barrier = g_new0(LatcdStaticBarrier, 1);
            g_strlcpy(barrier->source_key, source_key,
                      sizeof(barrier->source_key));
            barrier->first_sequence = accepted_sequence;
            g_hash_table_insert(service->static_barriers, g_strdup(key),
                                barrier);
        }
        barrier->last_sequence = accepted_sequence;
        barrier->failed = false;
    }
    g_ptr_array_add(service->queue, job);
    service->queued_bytes += source_size;
    g_hash_table_insert(service->active, g_strdup(key), job);
    service->queued++;
    if (!static_tbset) {
        source_state->runtime_accepted_sequence = accepted_sequence;
    }
    response->status = LATCD_STATUS_OK;
    snprintf(response->message, sizeof(response->message), "queued: %s", key);
    write_stats_locked(service);
    pthread_cond_signal(&service->ready);
    pthread_mutex_unlock(&service->lock);
    return 0;
}

static bool receipt_digest(int fd, char digest[65])
{
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    struct stat st;
    uint8_t buffer[65536];
    off_t offset = 0;
    bool ok = !fstat(fd, &st) && S_ISREG(st.st_mode);

    while (ok && offset < st.st_size) {
        ssize_t count = pread(fd, buffer,
            MIN(sizeof(buffer), (size_t)(st.st_size - offset)), offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            ok = false;
            break;
        }
        g_checksum_update(checksum, buffer, count);
        offset += count;
    }
    if (ok) {
        gsize size = 32;
        uint8_t raw[32];
        g_checksum_get_digest(checksum, raw, &size);
        digest_hex(raw, digest);
    }
    g_checksum_free(checksum);
    return ok;
}

static int journal_queue_receipts(const LatcdConfig *config,
                                  LatcdService *service,
                                  const uint8_t build[32],
                                  const uint8_t codegen[32],
                                  bool skip_unchanged,
                                  LatcdResponseV2 *response)
{
    char error[sizeof(response->message)] = {0};
    unsigned count = 0;
    uint64_t received = 0;
    uint64_t accepted = 0;
    uint64_t published = 0;
    unsigned queued = 0;
    unsigned skipped = 0;
    unsigned failures = 0;
    uint64_t request_id = response->request_id;

    response_init(response, request_id);
    if (latcd_journal_collect(config->cache_dir, build, codegen,
            config->max_cache_bytes, &count, &received, error, sizeof(error))) {
        response->status = LATCD_STATUS_BAD_REQUEST;
        g_strlcpy(response->message, error, sizeof(response->message));
        return -1;
    }

    char *root_path = g_build_filename(config->cache_dir, ".journals", NULL);
    GError *scan_error = NULL;
    GDir *root_dir = g_dir_open(root_path, 0, &scan_error);
    if (!root_dir && (!scan_error || scan_error->code != G_FILE_ERROR_NOENT)) {
        response->status = LATCD_STATUS_IO_ERROR;
        g_strlcpy(response->message,
                  scan_error ? scan_error->message : "cannot open journal store",
                  sizeof(response->message));
        g_clear_error(&scan_error);
        g_free(root_path);
        return -1;
    }
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_dir && root < 0) {
        response->status = LATCD_STATUS_IO_ERROR;
        g_strlcpy(response->message, "cannot open journal receipt root",
                  sizeof(response->message));
        g_dir_close(root_dir);
        g_free(root_path);
        return -1;
    }
    const char *name;
    while (root_dir && (name = g_dir_read_name(root_dir))) {
        if (name[0] == '.') continue;
        int directory = openat(root, name,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        int source = directory >= 0 ? openat(directory, "source",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK) : -1;
        int receipt = directory >= 0 ? openat(directory, "received.tbset",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK) : -1;
        if (source >= 0 && receipt >= 0) {
            char digest[65] = {0};
            if (!receipt_digest(receipt, digest)) {
                failures++;
                snprintf(error, sizeof(error), "cannot hash journal receipt");
            }
            pthread_mutex_lock(&service->lock);
            const LatcdJournalReceiptState *previous = g_hash_table_lookup(
                service->journal_receipts, name);
            bool unchanged = previous &&
                !strcmp(previous->digest, digest);
            pthread_mutex_unlock(&service->lock);
            if (skip_unchanged && unchanged) {
                skipped++;
            } else if (!failures) {
            static _Atomic uint64_t request_sequence;
            LatcdRequestV2 request = {
                .magic = LATCD_REQUEST_MAGIC,
                .version = LATCD_PROTOCOL_VERSION,
                .size = sizeof(request),
                .operation = LATCD_OP_SUBMIT_KEYS,
                .priority = LATCD_PRIORITY_STARTUP,
                .request_id = atomic_fetch_add(&request_sequence, 1) + 1,
            };
            LatcdResponseV2 item;
            int result = service_queue_request(service, source, receipt,
                                               &request, &item);
            accepted = MAX(accepted, item.accepted_sequence);
            published = MAX(published, item.published_sequence);
            if (result) {
                failures++;
                snprintf(error, sizeof(error), "%s", item.message);
            } else {
                pthread_mutex_lock(&service->lock);
                LatcdJournalReceiptState *receipt_state =
                    g_new0(LatcdJournalReceiptState, 1);
                g_strlcpy(receipt_state->digest, digest,
                          sizeof(receipt_state->digest));
                memcpy(receipt_state->source_sha256, item.source_sha256, 32);
                g_hash_table_insert(service->journal_receipts,
                                    g_strdup(name), receipt_state);
                pthread_mutex_unlock(&service->lock);
                queued++;
            }
            }
        }
        if (source >= 0) close(source);
        if (receipt >= 0) close(receipt);
        if (directory >= 0) close(directory);
        if (failures) break;
    }
    if (root_dir) g_dir_close(root_dir);
    if (root >= 0) close(root);
    g_clear_error(&scan_error);
    g_free(root_path);

    response->accepted_sequence = accepted;
    response->published_sequence = published;
    if (failures) {
        response->status = LATCD_STATUS_IO_ERROR;
        snprintf(response->message, sizeof(response->message),
                 "receipts=%u keys=%llu queued=%u failures=%u: %s", count,
                 (unsigned long long)received, queued, failures,
                 error[0] ? error : "receipt admission failed");
        return -1;
    }
    snprintf(response->message, sizeof(response->message),
             "receipts=%u keys=%llu queued=%u skipped=%u", count,
             (unsigned long long)received, queued, skipped);
    return 0;
}

static void admit_journal_receipts_periodically(
    const LatcdConfig *config, LatcdService *service,
    const uint8_t build[32], const uint8_t codegen[32],
    int64_t *last_admission, bool *had_error)
{
    int64_t now = g_get_monotonic_time();
    if (now - *last_admission < G_USEC_PER_SEC) return;

    LatcdResponseV2 admitted = {0};
    response_init(&admitted, 1);
    bool failed = journal_queue_receipts(
        config, service, build, codegen, true, &admitted);
    if (failed && !*had_error) {
        fprintf(stderr,
                "latcd: periodic journal admission failed: %s\n",
                admitted.message);
    } else if (!failed && *had_error) {
        fprintf(stderr, "latcd: periodic journal admission recovered\n");
    }
    *had_error = failed;
    *last_admission = g_get_monotonic_time();
}

static int source_flush_state_locked(LatcdService *service,
                                     const char *source_key,
                                     LatcdSourceState *state,
                                     uint64_t target, uint64_t runtime_target)
{
    GHashTableIter iterator;
    gpointer value;
    bool pending = false;
    g_hash_table_iter_init(&iterator, service->static_barriers);
    while (g_hash_table_iter_next(&iterator, NULL, &value)) {
        LatcdStaticBarrier *barrier = value;
        if (!strcmp(barrier->source_key, source_key) &&
            barrier->first_sequence <= target) {
            if (barrier->failed) return -1;
            pending = true;
        }
    }
    if (pending) return 0;
    if (!state || state->published_sequence >= runtime_target) return 1;
    if (state->failed_sequence >= runtime_target) return -1;
    return 0;
}

static void flush_request_free(LatcdFlushRequest *flush)
{
    close(flush->client_fd);
    g_array_free(flush->targets, TRUE);
    g_free(flush);
}

static int prepare_flush_request(LatcdService *service, int source_fd,
                                  const LatcdRequestV2 *request,
                                  LatcdFlushRequest *flush)
{
    LatcdResponseV2 *response = &flush->response;
    response_init(response, request->request_id);
    char source_key[65] = {0};
    if (request->operation == LATCD_OP_FLUSH_SOURCE) {
        char error[sizeof(response->message)] = {0};
        if (hash_source(source_fd, service->config->max_input,
                        response->source_sha256, error, sizeof(error))) {
            response->status = LATCD_STATUS_BAD_SOURCE;
            g_strlcpy(response->message, error, sizeof(response->message));
            return -1;
        }
        digest_hex(response->source_sha256, source_key);
    }

    pthread_mutex_lock(&service->lock);
    flush->targets = g_array_new(FALSE, FALSE, sizeof(LatcdFlushTarget));
    GHashTableIter states;
    gpointer key, value;
    g_hash_table_iter_init(&states, service->source_states);
    while (g_hash_table_iter_next(&states, &key, &value)) {
        LatcdSourceState *state = value;
        if (request->operation == LATCD_OP_FLUSH_SOURCE &&
            strcmp(key, source_key)) continue;
        LatcdFlushTarget target = {
            .sequence = state->accepted_sequence,
            .runtime_sequence = state->runtime_accepted_sequence,
        };
        g_strlcpy(target.source_key, key, sizeof(target.source_key));
        g_array_append_val(flush->targets, target);
        response->accepted_sequence = MAX(response->accepted_sequence,
                                           target.sequence);
    }
    GHashTableIter active_iterator;
    gpointer active_value;
    g_hash_table_iter_init(&active_iterator, service->active);
    while (g_hash_table_iter_next(&active_iterator, NULL, &active_value)) {
        LatcdJob *job = active_value;
        if (request->operation == LATCD_OP_FLUSH_ALL ||
            !strcmp(job->source_key, source_key)) {
            job->flush_sequence = job->accepted_sequence;
            job->ready_at_us = 0;
        }
    }
    pthread_cond_broadcast(&service->ready);
    pthread_mutex_unlock(&service->lock);
    return 0;
}

static int flush_request_state_locked(LatcdService *service,
                                      LatcdFlushRequest *flush)
{
    int result = 1;
    flush->response.published_sequence = 0;
    for (guint i = 0; i < flush->targets->len; i++) {
        LatcdFlushTarget *target = &g_array_index(flush->targets,
                                                  LatcdFlushTarget, i);
        LatcdSourceState *state = g_hash_table_lookup(service->source_states,
                                                       target->source_key);
        int current = source_flush_state_locked(service, target->source_key,
            state, target->sequence, target->runtime_sequence);
        if (state) {
            flush->response.published_sequence = MAX(
                flush->response.published_sequence,
                current > 0 ? target->sequence : state->published_sequence);
        }
        if (current < 0) return -1;
        if (!current) result = 0;
    }
    return result;
}

static void finish_flush_requests(LatcdService *service, GPtrArray *pending,
                                   bool stopping)
{
    for (guint i = 0; i < pending->len;) {
        LatcdFlushRequest *flush = g_ptr_array_index(pending, i);
        struct pollfd peer = {.fd = flush->client_fd, .events = POLLIN};
        bool disconnected = poll(&peer, 1, 0) > 0 &&
            (peer.revents & (POLLHUP | POLLERR | POLLNVAL));
        pthread_mutex_lock(&service->lock);
        int state = flush_request_state_locked(service, flush);
        pthread_mutex_unlock(&service->lock);
        if (!disconnected && !state && !stopping) {
            i++;
            continue;
        }
        LatcdResponseV2 *response = &flush->response;
        response->status = !state ? LATCD_STATUS_IO_ERROR :
                           state < 0 ? LATCD_STATUS_COMPILE_FAILED : LATCD_STATUS_OK;
        g_strlcpy(response->message, !state ? "latcd is stopping" :
            state < 0 ? "an accepted key set failed to compile" :
                        "all accepted key sets are published",
            sizeof(response->message));
        if (!disconnected) latcd_send_response(flush->client_fd, response, NULL, 0);
        g_ptr_array_remove_index_fast(pending, i);
        flush_request_free(flush);
    }
}

static int make_server(const char *path, char *error, size_t error_size)
{
    char *parent = g_path_get_dirname(path);
    struct stat parent_status;
    if (lstat(parent, &parent_status) || !S_ISDIR(parent_status.st_mode) ||
        parent_status.st_uid != geteuid() || (parent_status.st_mode & 0077)) {
        g_free(parent);
        return fail(error, error_size,
                    "socket directory must be private and user-owned");
    }
    g_free(parent);
    struct stat status;
    if (!lstat(path, &status)) {
        if (!S_ISSOCK(status.st_mode) || status.st_uid != geteuid() ||
            unlink(path)) {
            return fail(error, error_size, "refusing to replace socket path");
        }
    } else if (errno != ENOENT) {
        return fail(error, error_size, "cannot inspect socket path: %s",
                    strerror(errno));
    }
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return fail(error, error_size, "cannot create socket: %s",
                    strerror(errno));
    }
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    int directory_fd;
    if (latcd_socket_address(path, &address, &directory_fd, error, error_size)) {
        close(fd);
        return -1;
    }
    mode_t old_mask = umask(0077);
    int result = bind(fd, (const void *)&address, sizeof(address));
    int bind_error = errno;
    if (directory_fd >= 0) close(directory_fd);
    errno = bind_error;
    umask(old_mask);
    if (result || listen(fd, 64)) {
        fail(error, error_size, "cannot listen on %s: %s", path,
             strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }
    return fd;
}

static int peer_is_current_user(int fd);

static char *precompile_guest_path(const LatcdConfig *config, int source_fd,
                                   char *error, size_t error_size)
{
    if (!config->x86_rootfs || !*config->x86_rootfs) {
        fail(error, error_size,
             "precompile requires latcd --x86-rootfs");
        return NULL;
    }
    char *rootfs = realpath(config->x86_rootfs, NULL);
    char descriptor[64];
    snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", source_fd);
    char *source = realpath(descriptor, NULL);
    if (!rootfs || !source) {
        fail(error, error_size, "cannot resolve precompile source: %s",
             strerror(errno));
        g_free(rootfs);
        g_free(source);
        return NULL;
    }
    size_t root_length = strlen(rootfs);
    if (strncmp(source, rootfs, root_length) ||
        (source[root_length] && source[root_length] != '/')) {
        fail(error, error_size,
             "precompile source is outside configured x86 rootfs");
        g_free(rootfs);
        g_free(source);
        return NULL;
    }
    char *guest = g_strdup(source[root_length] ? source + root_length : "/");
    g_free(rootfs);
    g_free(source);
    return guest;
}

static void precompile_request_worker(gpointer data, gpointer user_data)
{
    (void)user_data;
    LatcdPrecompileRequest *work = data;
    LatcdResponseV2 response;
    response_init(&response, work->request_id);
    char error[sizeof(response.message)] = {0};
    char *guest = precompile_guest_path(work->config, work->source_fd,
                                        error, sizeof(error));
    if (guest && hash_source(work->source_fd, work->config->max_input,
                             response.source_sha256,
                             error, sizeof(error))) {
        g_free(guest);
        guest = NULL;
    }
    if (guest) {
        char *executable = g_file_read_link("/proc/self/exe", NULL);
        char jobs[16];
        snprintf(jobs, sizeof(jobs), "%u",
                 MIN(work->config->workers, LATCD_AUTO_WORKERS_MAX));
        char *arguments[] = {
            executable, (char *)"--precompile",
            (char *)"--socket", (char *)work->config->socket_path,
            (char *)"--x86-rootfs", (char *)work->config->x86_rootfs,
            (char *)"--latc", (char *)work->config->compiler,
            (char *)"--jobs", jobs, guest, NULL,
        };
        gint wait_status = 0;
        gchar *standard_error = NULL;
        GError *gerror = NULL;
        bool spawned = executable && g_spawn_sync(
            NULL, arguments, NULL, G_SPAWN_STDOUT_TO_DEV_NULL,
            NULL, NULL, NULL, &standard_error, &wait_status, &gerror);
        if (spawned && LATCD_SPAWN_CHECK_EXIT_STATUS(wait_status, &gerror)) {
            response.status = LATCD_STATUS_OK;
            g_strlcpy(response.message, "precompile published",
                      sizeof(response.message));
        } else {
            response.status = LATCD_STATUS_COMPILE_FAILED;
            g_strlcpy(response.message,
                      gerror ? gerror->message :
                      (standard_error && *standard_error ? standard_error :
                       "precompile failed"),
                      sizeof(response.message));
        }
        g_clear_error(&gerror);
        g_free(standard_error);
        g_free(executable);
    } else {
        response.status = LATCD_STATUS_BAD_SOURCE;
        g_strlcpy(response.message, error[0] ? error : "bad source",
                  sizeof(response.message));
    }
    latcd_send_response(work->client_fd, &response, NULL, 0);
    close(work->source_fd);
    close(work->client_fd);
    g_free(guest);
    g_free(work);
    atomic_fetch_sub(&active_precompiles, 1);
}

static int run_once(const LatcdConfig *config)
{
    char error[256] = {0};
    int server = make_server(config->socket_path, error, sizeof(error));
    if (server < 0) {
        fprintf(stderr, "latcd: %s\n", error);
        return 1;
    }
    int client;
    do {
        client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    } while (client < 0 && errno == EINTR);
    LatcdRequestV2 request = {0};
    int source = -1;
    int tbset = -1;
    LatcdResponseV2 response = {
        .magic = LATCD_RESPONSE_MAGIC,
        .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(response),
    };
    if (client < 0 || !peer_is_current_user(client) ||
        latcd_receive_request(client, &request, &source, &tbset,
                              error, sizeof(error))) {
        response.status = LATCD_STATUS_BAD_REQUEST;
        g_strlcpy(response.message, error[0] ? error : "accept failed",
                  sizeof(response.message));
    } else if (request.operation != LATCD_OP_SUBMIT_KEYS &&
               request.operation != LATCD_OP_SUBMIT_STATIC_KEYS) {
        response.request_id = request.request_id;
        response.status = LATCD_STATUS_BAD_REQUEST;
        g_strlcpy(response.message, "flush requires --serve mode",
                  sizeof(response.message));
    } else {
        response.request_id = request.request_id;
        process_request(config, source, tbset,
                        request.operation == LATCD_OP_SUBMIT_STATIC_KEYS,
                        &response);
    }
    if (client >= 0) {
        latcd_send_response(client, &response, NULL, 0);
        close(client);
    }
    if (source >= 0) {
        close(source);
    }
    if (tbset >= 0) {
        close(tbset);
    }
    close(server);
    unlink(config->socket_path);
    return response.status == LATCD_STATUS_OK ? 0 : 1;
}

static int peer_is_current_user(int fd)
{
    struct ucred credentials;
    socklen_t size = sizeof(credentials);
    return !getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) &&
           size == sizeof(credentials) && credentials.uid == geteuid();
}

static int journal_build_id(uint8_t build[32])
{
    return strlen(LATC_BUILD_ID) == 64 ? hex_digest(LATC_BUILD_ID, build) : -1;
}

static void register_journal(const LatcdConfig *config, int source, int config_fd,
                              const LatcdRequestV2 *request, LatcdResponseV2 *response,
                              int *directory_fd)
{
    *directory_fd = -1;
    response_init(response, request->request_id);
    uint8_t build[32], codegen[32];
    char error[sizeof(response->message)] = {0};
    char *temporary = g_build_filename(config->cache_dir, ".tmp", NULL);
    char *snapshot = NULL;
    expected_codegen_id(codegen);
    if (journal_build_id(build) || snapshot_source(source, temporary, config->max_input,
            &snapshot, response->source_sha256, NULL, error, sizeof(error))) {
        response->status = LATCD_STATUS_BAD_SOURCE;
    } else {
        char stream[33];
        int result;
        if (request->operation == LATCD_OP_REGISTER_JOURNAL_CAPABILITY) {
            result = latcd_journal_register_capability(config->cache_dir, snapshot,
                response->source_sha256, build, codegen, config_fd, request->sequence,
                config->max_cache_bytes, stream, directory_fd, error, sizeof(error));
        } else {
            result = latcd_journal_register(config->cache_dir, snapshot, response->source_sha256,
                build, codegen, config_fd, request->sequence, config->max_cache_bytes,
                stream, error, sizeof(error));
        }
        if (result) {
            response->status = LATCD_STATUS_BAD_REQUEST;
        } else {
            g_strlcpy(response->message, stream, sizeof(response->message));
        }
    }
    if (snapshot) unlink(snapshot);
    g_free(snapshot);
    g_free(temporary);
    if (response->status != LATCD_STATUS_OK)
        g_strlcpy(response->message, error[0] ? error : "journal registration failed",
                  sizeof(response->message));
}

static void append_journal(const LatcdConfig *config, int source, int config_fd,
                           const LatcdRequestV2 *request,
                           LatcdResponseV2 *response)
{
    response_init(response, request->request_id);
    uint8_t build[32], codegen[32], source_sha[32];
    char error[sizeof(response->message)] = {0};
    LatTbKey key = { .guest_rva = request->sequence, .flags = 3 };
    uint64_t slot = 0;

    expected_codegen_id(codegen);
    if (journal_build_id(build) ||
        latcd_journal_append(config->cache_dir, request->request_id,
            source, config_fd, build, codegen, &key, source_sha, &slot,
            error, sizeof(error))) {
        response->status = LATCD_STATUS_BAD_REQUEST;
        g_strlcpy(response->message,
                  error[0] ? error : "journal key append failed",
                  sizeof(response->message));
    } else {
        memcpy(response->source_sha256, source_sha, 32);
        g_strlcpy(response->message, "journal key committed",
                  sizeof(response->message));
    }
}

static int request_is_ready(int fd)
{
    struct pollfd request = { .fd = fd, .events = POLLIN };
    int result;
    do {
        result = poll(&request, 1, 1000);
    } while (result < 0 && errno == EINTR && !stop_requested);
    return result > 0 && (request.revents & POLLIN);
}

static int run_service(const LatcdConfig *config)
{
    char error[256] = {0};
    char *temporary_dir = g_build_filename(config->cache_dir, ".tmp", NULL);
    if (ensure_private_directory(config->cache_dir, error, sizeof(error)) ||
        ensure_private_directory(temporary_dir, error, sizeof(error))) {
        fprintf(stderr, "latcd: %s\n", error);
        g_free(temporary_dir);
        return 1;
    }
    g_free(temporary_dir);
    uint8_t journal_build[32], journal_codegen[32];
    unsigned recovered_journals;
    expected_codegen_id(journal_codegen);
    if (journal_build_id(journal_build) || latcd_journal_recover(config->cache_dir,
            journal_build, journal_codegen, config->max_cache_bytes,
            &recovered_journals, error, sizeof(error))) {
        fprintf(stderr, "latcd: journal recovery validation failed: %s\n", error);
        return 1;
    }
    if (recovered_journals)
    {
        fprintf(stderr, "latcd: recovered %u journal streams; receipt admission pending\n",
                recovered_journals);
    }
    int server = make_server(config->socket_path, error, sizeof(error));
    if (server < 0) {
        fprintf(stderr, "latcd: %s\n", error);
        return 1;
    }
    LatcdService service = {
        .config = config,
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .ready = PTHREAD_COND_INITIALIZER,
        .queue = g_ptr_array_new(),
        .active = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL),
        .running_sources = g_hash_table_new_full(
            g_str_hash, g_str_equal, g_free, NULL),
        .negative = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                          g_free),
        .source_states = g_hash_table_new_full(g_str_hash, g_str_equal,
                                               g_free, g_free),
        .static_barriers = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                g_free, g_free),
        .journal_receipts = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                   g_free, g_free),
        .workers = g_new0(pthread_t, config->workers),
        .stopping = 0,
        .next_sequence = 0,
        .requests = 0,
        .queued = 0,
        .deduplicated = 0,
        .cache_hits = 0,
        .compiled = 0,
        .failed = 0,
        .negative_hits = 0,
        .queue_full = 0,
        .queued_bytes = 0,
    };
    load_persisted_source_states(&service);
    LatcdWorker *worker_args = g_new0(LatcdWorker, config->workers);
    uint32_t started_workers = 0;
    for (; started_workers < config->workers; started_workers++) {
        worker_args[started_workers] = (LatcdWorker) {
            .service = &service,
            .index = started_workers,
        };
        if (pthread_create(&service.workers[started_workers], NULL,
                           compiler_worker, &worker_args[started_workers])) {
            break;
        }
    }
    if (started_workers != config->workers) {
        fprintf(stderr, "latcd: cannot start compiler worker\n");
        pthread_mutex_lock(&service.lock);
        service.stopping = 1;
        pthread_cond_broadcast(&service.ready);
        pthread_mutex_unlock(&service.lock);
        for (uint32_t i = 0; i < started_workers; i++) {
            pthread_join(service.workers[i], NULL);
        }
        close(server);
        unlink(config->socket_path);
        g_free(worker_args);
        g_free(service.workers);
        g_ptr_array_free(service.queue, TRUE);
        g_hash_table_destroy(service.active);
        g_hash_table_destroy(service.running_sources);
        g_hash_table_destroy(service.negative);
        g_hash_table_destroy(service.source_states);
        g_hash_table_destroy(service.static_barriers);
        g_hash_table_destroy(service.journal_receipts);
        return 1;
    }
    pthread_mutex_lock(&service.lock);
    write_stats_locked(&service);
    pthread_mutex_unlock(&service.lock);
    if (recovered_journals && atomic_load(&compiler_budget_recovery_state) == 1) {
        LatcdResponseV2 recovered = {0};
        response_init(&recovered, 1);
        if (journal_queue_receipts(config, &service, journal_build,
                                   journal_codegen, true, &recovered)) {
            fprintf(stderr, "latcd: journal receipt admission failed: %s\n",
                    recovered.message);
            stop_requested = 1;
        } else {
            fprintf(stderr,
                    "latcd: journal receipt admission accepted=%" PRIu64
                    " published=%" PRIu64 " %s\n",
                    recovered.accepted_sequence, recovered.published_sequence,
                    recovered.message);
        }
    }
    struct sigaction action = { .sa_handler = signal_stop };
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    GError *pool_error = NULL;
    GThreadPool *precompile_pool = g_thread_pool_new(
        precompile_request_worker, NULL, 1, FALSE, &pool_error);
    if (!precompile_pool) {
        fprintf(stderr, "latcd: cannot start precompile worker: %s\n",
                pool_error ? pool_error->message : "unknown error");
        g_clear_error(&pool_error);
        stop_requested = 1;
    }
    int64_t last_activity = g_get_monotonic_time();
    int64_t last_journal_admission = last_activity;
    bool journal_admission_error = false;
    LatcdTaskRecovery task_recovery = {.config = config};
    pthread_t recovery_thread;
    bool recovery_started = !pthread_create(&recovery_thread, NULL,
        compiler_input_recovery_worker, &task_recovery);
    if (!recovery_started) {
        fprintf(stderr, "latcd: cannot start compiler input recovery worker\n");
        stop_requested = 1;
    }
    struct pollfd channels[LATCD_MAX_CHANNELS + 1] = {
        { .fd = server, .events = POLLIN },
    };
    nfds_t channel_count = 1;
    GPtrArray *pending_flushes = g_ptr_array_new();
    int previous_budget_recovery = -2;
    int64_t last_retirement_stats = 0;
    while (!stop_requested) {
        int budget_recovery = atomic_load(&compiler_budget_recovery_state);
        if (budget_recovery != previous_budget_recovery ||
            g_get_monotonic_time() - last_retirement_stats >= G_USEC_PER_SEC) {
            pthread_mutex_lock(&service.lock);
            write_stats_locked(&service);
            pthread_mutex_unlock(&service.lock);
            previous_budget_recovery = budget_recovery;
            last_retirement_stats = g_get_monotonic_time();
        }
        finish_flush_requests(&service, pending_flushes, false);
        if (budget_recovery == 1) admit_journal_receipts_periodically(
            config, &service, journal_build, journal_codegen,
            &last_journal_admission, &journal_admission_error);
        int available = poll(channels, channel_count, 250);
        if (available < 0 && errno == EINTR) {
            continue;
        }
        if (available <= 0) {
            pthread_mutex_lock(&service.lock);
            bool busy = channel_count > 1 || pending_flushes->len || service.queue->len ||
                g_hash_table_size(service.running_sources);
            pthread_mutex_unlock(&service.lock);
            busy |= atomic_load(&active_precompiles) ||
                (precompile_pool && g_thread_pool_unprocessed(precompile_pool));
            if (busy) last_activity = g_get_monotonic_time();
            if (config->idle_seconds &&
                g_get_monotonic_time() - last_activity >=
                (int64_t)config->idle_seconds * G_USEC_PER_SEC) {
                break;
            }
            continue;
        }
        for (nfds_t i = 1; i < channel_count;) {
            short events = channels[i].revents;
            if (!(events & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) {
                i++;
                continue;
            }
            LatcdRequestV2 request = {0};
            int source = -1, tbset = -1, reply = -1, directory = -1;
            if (!(events & POLLIN) || latcd_receive_channel_request(
                    channels[i].fd, &request, &source, &tbset, &reply,
                    error, sizeof(error))) {
                close(channels[i].fd);
                channels[i] = channels[--channel_count];
                continue;
            }
            LatcdResponseV2 response;
            response_init(&response, request.request_id);
            if (request.operation == LATCD_OP_REGISTER_JOURNAL ||
                request.operation == LATCD_OP_REGISTER_JOURNAL_CAPABILITY) {
                register_journal(config, source, tbset, &request, &response, &directory);
            } else if (request.operation == LATCD_OP_APPEND_JOURNAL) {
                append_journal(config, source, tbset, &request, &response);
            } else if (request.operation == LATCD_OP_COLLECT_JOURNALS) {
                journal_queue_receipts(config, &service, journal_build,
                                       journal_codegen, false, &response);
            } else if (request.operation != LATCD_OP_SUBMIT_KEYS) {
                response.status = LATCD_STATUS_BAD_REQUEST;
                g_strlcpy(response.message,
                          "channel only accepts runtime keys or journal operations",
                          sizeof(response.message));
            } else {
                service_queue_request(&service, source, tbset,
                                      &request, &response);
            }
            /* A client that abandons its reply must not block the service. */
            latcd_send_response_fd(reply, &response, directory, NULL, 0);
            if (directory >= 0) close(directory);
            close(reply);
            if (source >= 0) close(source);
            if (tbset >= 0) close(tbset);
            last_activity = g_get_monotonic_time();
            i++;
        }
        if (!(channels[0].revents & POLLIN)) {
            continue;
        }
        int client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) {
            continue;
        }
        last_activity = g_get_monotonic_time();
        LatcdRequestV2 request = {0};
        LatcdResponseV2 response;
        response_init(&response, 0);
        int source = -1;
        int tbset = -1;
        int directory = -1;
        bool handed_off = false;
        if (!peer_is_current_user(client) || !request_is_ready(client)) {
            response.status = LATCD_STATUS_BAD_REQUEST;
            g_strlcpy(response.message, "request user does not own latcd",
                      sizeof(response.message));
        } else if (latcd_receive_request(client, &request, &source, &tbset,
                                         error, sizeof(error))) {
            response.status = LATCD_STATUS_BAD_REQUEST;
            g_strlcpy(response.message, error, sizeof(response.message));
        } else if (request.operation == LATCD_OP_HELLO ||
                   request.operation == LATCD_OP_OPEN_CHANNEL) {
            response.request_id = request.request_id;
            g_strlcpy(response.message, LATC_BUILD_ID, sizeof(response.message));
            char *canonical = realpath(config->cache_dir, NULL);
            if (canonical) {
                GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
                g_checksum_update(checksum, (const guchar *)canonical, strlen(canonical));
                gsize size = sizeof(response.source_sha256);
                g_checksum_get_digest(checksum, response.source_sha256, &size);
                g_checksum_free(checksum);
                free(canonical);
            } else {
                response.status = LATCD_STATUS_IO_ERROR;
            }
            if (request.operation == LATCD_OP_OPEN_CHANNEL &&
                response.status == LATCD_STATUS_OK) {
                if (channel_count == LATCD_MAX_CHANNELS + 1) {
                    response.status = LATCD_STATUS_QUEUE_FULL;
                    g_strlcpy(response.message, "too many runtime channels",
                              sizeof(response.message));
                } else {
                    int flags = fcntl(client, F_GETFL);
                    if (flags < 0 || fcntl(client, F_SETFL, flags | O_NONBLOCK)) {
                        response.status = LATCD_STATUS_IO_ERROR;
                    } else if (!latcd_send_response(client, &response, NULL, 0)) {
                        channels[channel_count++] = (struct pollfd) {
                            .fd = client, .events = POLLIN,
                        };
                        handed_off = true;
                    }
                }
            }
        } else if (request.operation == LATCD_OP_SUBMIT_KEYS ||
                   request.operation == LATCD_OP_SUBMIT_STATIC_KEYS) {
            service_queue_request(&service, source, tbset, &request,
                                  &response);
        } else if (request.operation == LATCD_OP_REGISTER_JOURNAL ||
                   request.operation == LATCD_OP_REGISTER_JOURNAL_CAPABILITY) {
            register_journal(config, source, tbset, &request, &response, &directory);
        } else if (request.operation == LATCD_OP_APPEND_JOURNAL) {
            append_journal(config, source, tbset, &request, &response);
        } else if (request.operation == LATCD_OP_COLLECT_JOURNALS) {
            response_init(&response, request.request_id);
            journal_queue_receipts(config, &service, journal_build,
                                   journal_codegen, false, &response);
        } else if (request.operation == LATCD_OP_PRECOMPILE_SOURCE) {
            LatcdPrecompileRequest *work = g_new0(
                LatcdPrecompileRequest, 1);
            if (work) {
                *work = (LatcdPrecompileRequest) {
                    .config = config,
                    .client_fd = client,
                    .source_fd = source,
                    .request_id = request.request_id,
                };
                atomic_fetch_add(&active_precompiles, 1);
                if (g_thread_pool_push(precompile_pool, work, NULL)) {
                    handed_off = true;
                } else {
                    atomic_fetch_sub(&active_precompiles, 1);
                    g_free(work);
                    response.status = LATCD_STATUS_QUEUE_FULL;
                    g_strlcpy(response.message,
                              "cannot queue precompile request",
                              sizeof(response.message));
                }
            } else {
                response.status = LATCD_STATUS_QUEUE_FULL;
                g_strlcpy(response.message, "out of memory",
                          sizeof(response.message));
            }
        } else {
            response_init(&response, request.request_id);
            if (pending_flushes->len >= LATCD_MAX_FLUSHES) {
                response.status = LATCD_STATUS_QUEUE_FULL;
                g_strlcpy(response.message, "too many pending flush requests",
                          sizeof(response.message));
            } else {
                LatcdFlushRequest *flush = g_new0(LatcdFlushRequest, 1);
                flush->client_fd = client;
                int flags = fcntl(client, F_GETFL);
                if (flags < 0 || fcntl(client, F_SETFL, flags | O_NONBLOCK)) {
                    response.status = LATCD_STATUS_IO_ERROR;
                    g_strlcpy(response.message, "cannot make flush reply nonblocking",
                              sizeof(response.message));
                    g_free(flush);
                } else if (prepare_flush_request(&service, source, &request, flush)) {
                    response = flush->response;
                    g_free(flush);
                } else {
                    g_ptr_array_add(pending_flushes, flush);
                    if (source >= 0) close(source);
                    handed_off = true;
                }
            }
        }
        if (handed_off) continue;
        if (directory >= 0) latcd_send_response_fd(client, &response, directory, NULL, 0);
        else latcd_send_response(client, &response, NULL, 0);
        if (directory >= 0) close(directory);
        if (source >= 0) {
            close(source);
        }
        if (tbset >= 0) {
            close(tbset);
        }
        close(client);
    }
    atomic_store(&task_recovery.stopping, true);
    if (recovery_started) pthread_join(recovery_thread, NULL);
    for (nfds_t i = 1; i < channel_count; i++) {
        close(channels[i].fd);
    }
    close(server);
    unlink(config->socket_path);
    finish_flush_requests(&service, pending_flushes, true);
    g_ptr_array_free(pending_flushes, TRUE);
    if (precompile_pool) {
        g_thread_pool_free(precompile_pool, FALSE, TRUE);
    }
    pthread_mutex_lock(&service.lock);
    service.stopping = 1;
    for (guint i = 0; i < service.queue->len; i++) {
        LatcdJob *job = g_ptr_array_index(service.queue, i);
        g_hash_table_remove(service.active, job->key);
        job_free(job);
    }
    g_ptr_array_set_size(service.queue, 0);
    service.queued_bytes = 0;
    pthread_cond_broadcast(&service.ready);
    pthread_mutex_unlock(&service.lock);
    for (uint32_t i = 0; i < config->workers; i++) {
        if (compiler_process_groups[i] > 0) {
            kill(-compiler_process_groups[i], SIGTERM);
        }
    }
    for (uint32_t i = 0; i < config->workers; i++) {
        pthread_join(service.workers[i], NULL);
    }
    pthread_mutex_lock(&service.lock);
    write_stats_locked(&service);
    pthread_mutex_unlock(&service.lock);
    for (guint i = 0; i < service.queue->len; i++) {
        job_free(g_ptr_array_index(service.queue, i));
    }
    g_ptr_array_free(service.queue, TRUE);
    g_hash_table_destroy(service.active);
    g_hash_table_destroy(service.running_sources);
    g_hash_table_destroy(service.negative);
    g_hash_table_destroy(service.source_states);
    g_hash_table_destroy(service.static_barriers);
    g_hash_table_destroy(service.journal_receipts);
    g_free(worker_args);
    g_free(service.workers);
    pthread_cond_destroy(&service.ready);
    pthread_mutex_destroy(&service.lock);
    return 0;
}

static int run_client_request(const char *socket_path, uint32_t operation,
                              const char *source_path,
                              const char *tbset_path, uint32_t priority)
{
    int source = source_path ? open(source_path, O_RDONLY | O_CLOEXEC) : -1;
    int tbset = tbset_path ? open(tbset_path, O_RDONLY | O_CLOEXEC) : -1;
    int client = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    int expected_fds = operation == LATCD_OP_SUBMIT_KEYS ? 2 :
                       operation == LATCD_OP_FLUSH_SOURCE ? 1 : 0;
    if ((expected_fds >= 1 && source < 0) ||
        (expected_fds == 2 && tbset < 0) || client < 0) {
        fprintf(stderr, "latcd: cannot open request input: %s\n",
                strerror(errno));
        if (source >= 0) close(source);
        if (tbset >= 0) close(tbset);
        if (client >= 0) close(client);
        return 1;
    }
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    int directory_fd;
    char address_error[256];
    if (latcd_socket_address(socket_path, &address, &directory_fd,
                             address_error, sizeof(address_error))) {
        fprintf(stderr, "latcd: %s\n", address_error);
        if (source >= 0) close(source);
        if (tbset >= 0) close(tbset);
        close(client);
        return 1;
    }
    int connected = connect(client, (const void *)&address, sizeof(address));
    int connect_error = errno;
    if (directory_fd >= 0) close(directory_fd);
    errno = connect_error;
    if (connected) {
        fprintf(stderr, "latcd: cannot connect: %s\n", strerror(errno));
        if (source >= 0) close(source);
        if (tbset >= 0) close(tbset);
        close(client);
        return 1;
    }
    LatcdRequestV2 request = {
        .magic = LATCD_REQUEST_MAGIC,
        .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(request),
        .priority = priority,
        .operation = operation,
        .request_id = ((uint64_t)getpid() << 32) ^ g_get_monotonic_time(),
    };
    char error[256] = {0};
    LatcdResponseV2 response;
    int result = latcd_send_request(client, source, tbset, &request, error,
                                    sizeof(error)) ||
                 latcd_receive_response(client, &response, error,
                                        sizeof(error));
    if (result) {
        fprintf(stderr, "latcd: %s\n", error);
    } else {
        char hex[65];
        digest_hex(response.source_sha256, hex);
        printf("status=%d\nrequest_id=%" PRIu64
               "\naccepted_sequence=%" PRIu64
               "\npublished_sequence=%" PRIu64
               "\nsource_sha256=%s\n%s\n",
               response.status, response.request_id,
               response.accepted_sequence, response.published_sequence,
               hex, response.message);
        result = response.status != LATCD_STATUS_OK;
    }
    if (source >= 0) close(source);
    if (tbset >= 0) close(tbset);
    close(client);
    return result;
}

static void usage(const char *name)
{
    fprintf(stderr,
            "usage:\n"
            "  %s --once --socket PATH --cache-dir DIR --latc PATH"
            " --runner PATH --runtime-dir DIR [--max-input BYTES]\n"
            "  %s --serve --socket PATH --cache-dir DIR --latc PATH"
            " --runner PATH --runtime-dir DIR [--stats PATH]"
            " [--x86-rootfs DIR]"
            " [--max-jobs N] [--negative-ms N] [--max-negative N]"
            " [--max-queue-bytes BYTES] [--max-cache-bytes BYTES]"
            " [--workers N] [--flush-only] [--idle-seconds N] [--daemonize]"
            " [--cpu-seconds N] [--address-space BYTES]"
            " [--file-size BYTES] [--open-files N]\n"
            "  %s --submit --socket PATH --tbset FILE [--priority N] X86_ELF\n"
            "  %s --flush-source --socket PATH X86_ELF\n"
            "  %s --flush-all --socket PATH\n"
            "  %s --precompile --socket PATH --x86-rootfs DIR"
            " [--latc PATH] [--jobs N] GUEST_ELF\n"
            "  %s gc --plan --cache-dir DIR\n"
            "  %s --build-id\n",
            name, name, name, name, name, name, name, name);
}

static int run_gc_plan(int argc, char **argv)
{
    bool plan = false;
    const char *cache = NULL;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--plan") && !plan) plan = true;
        else if (!strcmp(argv[i], "--cache-dir") && !cache && i + 1 < argc)
            cache = argv[++i];
        else { usage(argv[0]); return 2; }
    }
    if (!plan || !cache || !*cache) { usage(argv[0]); return 2; }
    GError *gerror = NULL;
    char *executable = g_file_read_link("/proc/self/exe", &gerror);
    if (!executable) {
        fprintf(stderr, "latcd: cannot locate GC planner: %s\n",
                gerror ? gerror->message : "unknown error");
        g_clear_error(&gerror);
        return 1;
    }
    char *directory = g_path_get_dirname(executable);
    char *script = NULL;
    char *candidate = NULL;
#ifdef LATCD_GC_RELATIVE_SCRIPT
    candidate = g_build_filename(directory, LATCD_GC_RELATIVE_SCRIPT, NULL);
    if (g_file_test(candidate, G_FILE_TEST_IS_REGULAR)) script = candidate;
    else g_free(candidate);
#endif
#ifdef LATCD_GC_SCRIPT
    if (!script) {
        candidate = g_strdup(LATCD_GC_SCRIPT);
        if (g_file_test(candidate, G_FILE_TEST_IS_REGULAR)) script = candidate;
        else g_free(candidate);
    }
#endif
#ifdef LATCD_GC_SOURCE_SCRIPT
    if (!script) {
        candidate = g_strdup(LATCD_GC_SOURCE_SCRIPT);
        if (g_file_test(candidate, G_FILE_TEST_IS_REGULAR)) script = candidate;
        else g_free(candidate);
    }
#endif
#if !defined(LATCD_GC_RELATIVE_SCRIPT) && !defined(LATCD_GC_SCRIPT)
    if (!script) {
        candidate = g_build_filename(directory, "..", "..", "latcd", "cache_gc.py", NULL);
        if (g_file_test(candidate, G_FILE_TEST_IS_REGULAR)) script = candidate;
        else g_free(candidate);
    }
#endif
    g_free(executable);
    g_free(directory);
    if (!script) {
        fprintf(stderr, "latcd: cannot locate installed GC planner\n");
        return 1;
    }
    /* A separate stdlib-only planner never opens the daemon's writable state. */
    execlp("python3", "python3", "-I", "-B", script,
           "--plan", "--cache-dir", cache, (char *)NULL);
    fprintf(stderr, "latcd: cannot execute read-only GC planner: %s\n", strerror(errno));
    g_free(script);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "gc")) {
        return run_gc_plan(argc, argv);
    }
    if (argc == 2 && !strcmp(argv[1], "--build-id")) {
        puts(LATC_BUILD_ID);
        return 0;
    }
    int once = 0, serve = 0, submit = 0, flush_source = 0, flush_all = 0;
    int precompile = 0, daemonize = 0;
    uint32_t precompile_jobs = 0;
    const char *source = NULL;
    const char *tbset = NULL;
    uint32_t priority = LATCD_PRIORITY_LIBRARY;
    LatcdConfig config = {
        .max_input = LATCD_DEFAULT_MAX_INPUT,
        .address_space_limit = LATCD_DEFAULT_ADDRESS_SPACE,
        .file_size_limit = LATCD_DEFAULT_FILE_SIZE,
        .max_queue_bytes = LATCD_DEFAULT_MAX_QUEUE_BYTES,
        .max_cache_bytes = LATCD_DEFAULT_MAX_CACHE_BYTES,
        .max_jobs = LATCD_DEFAULT_MAX_JOBS,
        .workers = 0,
        .max_negative = LATCD_DEFAULT_MAX_NEGATIVE,
        .negative_ms = LATCD_DEFAULT_NEGATIVE_MS,
        .cpu_seconds = LATCD_DEFAULT_CPU_SECONDS,
        .open_files = LATCD_DEFAULT_OPEN_FILES,
    };
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--once")) once = 1;
        else if (!strcmp(argv[i], "--daemonize")) daemonize = 1;
        else if (!strcmp(argv[i], "--serve")) serve = 1;
        else if (!strcmp(argv[i], "--submit")) submit = 1;
        else if (!strcmp(argv[i], "--flush-source")) flush_source = 1;
        else if (!strcmp(argv[i], "--flush-all")) flush_all = 1;
        else if (!strcmp(argv[i], "--precompile")) precompile = 1;
        else if (!strcmp(argv[i], "--flush-only")) config.flush_only = true;
        else if (!strcmp(argv[i], "--idle-seconds") && i + 1 < argc) {
            char *end = NULL;
            uint64_t seconds = g_ascii_strtoull(argv[++i], &end, 10);
            if (!end || *end || seconds > UINT32_MAX) return 2;
            config.idle_seconds = seconds;
        }
        else if (!strcmp(argv[i], "--socket") && i + 1 < argc)
            config.socket_path = argv[++i];
        else if (!strcmp(argv[i], "--cache-dir") && i + 1 < argc)
            config.cache_dir = argv[++i];
        else if (!strcmp(argv[i], "--latc") && i + 1 < argc)
            config.compiler = argv[++i];
        else if (!strcmp(argv[i], "--runner") && i + 1 < argc)
            config.runner = argv[++i];
        else if (!strcmp(argv[i], "--runtime-dir") && i + 1 < argc)
            config.runtime_dir = argv[++i];
        else if (!strcmp(argv[i], "--x86-rootfs") && i + 1 < argc)
            config.x86_rootfs = argv[++i];
        else if (!strcmp(argv[i], "--stats") && i + 1 < argc)
            config.stats_path = argv[++i];
        else if (!strcmp(argv[i], "--max-input") && i + 1 < argc)
            config.max_input = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--max-jobs") && i + 1 < argc)
            config.max_jobs = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--max-queue-bytes") && i + 1 < argc)
            config.max_queue_bytes = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--max-cache-bytes") && i + 1 < argc)
            config.max_cache_bytes = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--workers") && i + 1 < argc)
            config.workers = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--max-negative") && i + 1 < argc)
            config.max_negative = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--negative-ms") && i + 1 < argc)
            config.negative_ms = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--cpu-seconds") && i + 1 < argc)
            config.cpu_seconds = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--address-space") && i + 1 < argc)
            config.address_space_limit = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--file-size") && i + 1 < argc)
            config.file_size_limit = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--open-files") && i + 1 < argc)
            config.open_files = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--priority") && i + 1 < argc)
            priority = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--jobs") && i + 1 < argc)
            precompile_jobs = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--tbset") && i + 1 < argc)
            tbset = argv[++i];
        else if ((submit || flush_source || precompile) && !source)
            source = argv[i];
        else { usage(argv[0]); return 2; }
    }
    if (once + serve + submit + flush_source + flush_all + precompile != 1 ||
        !config.socket_path) {
        usage(argv[0]);
        return 2;
    }
    if (submit) {
        if (!source || !tbset) { usage(argv[0]); return 2; }
        return run_client_request(config.socket_path, LATCD_OP_SUBMIT_KEYS,
                                  source, tbset, priority);
    }
    if (flush_source) {
        if (!source || tbset) { usage(argv[0]); return 2; }
        return run_client_request(config.socket_path, LATCD_OP_FLUSH_SOURCE,
                                  source, NULL, priority);
    }
    if (flush_all) {
        if (source || tbset) { usage(argv[0]); return 2; }
        return run_client_request(config.socket_path, LATCD_OP_FLUSH_ALL,
                                  NULL, NULL, priority);
    }
    if (precompile) {
        if (!source || !config.x86_rootfs || tbset ||
            precompile_jobs > LATCD_MAX_WORKERS) {
            usage(argv[0]);
            return 2;
        }
        char *compiler = NULL;
        if (config.compiler) {
            compiler = g_canonicalize_filename(config.compiler, NULL);
        } else {
            char *executable = g_file_read_link("/proc/self/exe", NULL);
            if (!executable) {
                fprintf(stderr, "latcd: cannot resolve /proc/self/exe\n");
                return 1;
            }
            char *directory = g_path_get_dirname(executable);
            compiler = g_build_filename(directory, "latc", NULL);
            g_free(directory);
            g_free(executable);
        }
        if (!precompile_jobs) precompile_jobs = default_worker_count();
        int result = latcd_run_precompile(config.socket_path,
                                          config.x86_rootfs, compiler,
                                          source, precompile_jobs);
        g_free(compiler);
        return result;
    }
    if (!config.workers) {
        config.workers = default_worker_count();
    }
    if (!config.cache_dir || !config.compiler || !config.runner ||
        !config.runtime_dir || !config.max_input || !config.max_jobs ||
        !config.max_queue_bytes || !config.max_cache_bytes ||
        !config.workers || config.workers > LATCD_MAX_WORKERS ||
        !config.max_negative || !config.negative_ms || !config.cpu_seconds ||
        !config.address_space_limit || !config.file_size_limit ||
        !config.open_files) {
        usage(argv[0]);
        return 2;
    }
    char error[512] = {0};
    if (daemonize && !serve) {
        fprintf(stderr, "latcd: --daemonize requires --serve\n");
        return 2;
    }
    if (validate_toolchain(&config, error, sizeof(error))) {
        fprintf(stderr, "latcd: %s\n", error);
        return 1;
    }
    struct rlimit inherited_cpu;
    if (getrlimit(RLIMIT_CPU, &inherited_cpu) == 0 &&
        inherited_cpu.rlim_max != RLIM_INFINITY &&
        config.cpu_seconds > inherited_cpu.rlim_max) {
        fprintf(stderr,
                "latcd: CPU limit %u exceeds inherited hard limit %llu; using %llu seconds\n",
                config.cpu_seconds,
                (unsigned long long)inherited_cpu.rlim_max,
                (unsigned long long)inherited_cpu.rlim_max);
    }
    if (daemonize) {
        pid_t child = fork();
        if (child < 0) return 1;
        if (child > 0) return 0;
        if (setsid() < 0) _exit(1);
        child = fork();
        if (child < 0) _exit(1);
        if (child > 0) _exit(0);
        if (chdir("/")) _exit(1);
        long maximum = sysconf(_SC_OPEN_MAX);
        for (int fd = 3; fd < maximum; fd++) close(fd);
    }
    int cache_owner = acquire_cache_owner(&config, error, sizeof(error));
    if (cache_owner < 0) {
        fprintf(stderr, "latcd: %s\n", error);
        return 1;
    }
    struct sigaction recovery_action = { .sa_handler = signal_stop };
    sigemptyset(&recovery_action.sa_mask);
    sigaction(SIGINT, &recovery_action, NULL);
    sigaction(SIGTERM, &recovery_action, NULL);
    int recovery = recover_lifecycle(config.cache_dir, false, error, sizeof(error));
    if (!recovery) recovery = recover_lifecycle(config.cache_dir, true, error, sizeof(error));
    if (!recovery && !serve) recovery = recover_compiler_inputs(&config, error, sizeof(error));
    if (recovery) {
        if (recovery < 0) fprintf(stderr, "latcd: %s\n", error);
        else fprintf(stderr, "latcd: recovery deferred by stop request\n");
        close(cache_owner);
        return recovery < 0 ? 1 : 0;
    }
    if (latcd_cache_capacity_scan(&generation_capacity, config.cache_dir, error, sizeof(error))) {
        fprintf(stderr, "latcd: %s\n", error);
        close(cache_owner);
        return 1;
    }
    unsigned budget_visited;
    int budget_result;
    do {
        budget_result = restore_compiler_budgets_step(&config, &compiler_budget_recovery,
            32, &budget_visited, error, sizeof(error));
    } while (!serve && budget_result == 1 && !stop_requested);
    atomic_store(&compiler_budget_recovery_state, budget_result < 0 ? -1 : budget_result == 0);
    if (budget_result < 0 || stop_requested) {
        fprintf(stderr, "latcd: %s\n", stop_requested ? "budget recovery deferred by stop request" : error);
        if (compiler_budget_recovery.cursor) closedir(compiler_budget_recovery.cursor);
        latcd_cache_capacity_close(&generation_capacity);
        close(cache_owner);
        return 1;
    }
    if (!serve && recover_compiler_inputs(&config, error, sizeof(error))) {
        fprintf(stderr, "latcd: %s\n", error);
        latcd_cache_capacity_close(&generation_capacity);
        close(cache_owner);
        return 1;
    }
    int result = serve ? run_service(&config) : run_once(&config);
    if (compiler_budget_recovery.cursor) closedir(compiler_budget_recovery.cursor);
    latcd_cache_capacity_close(&generation_capacity);
    close(cache_owner);
    return result;
}
