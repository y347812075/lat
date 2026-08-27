#define _GNU_SOURCE

#include "latcd-protocol.h"
#include "module-inspect.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <inttypes.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define LATCD_DEFAULT_MAX_INPUT (UINT64_C(1) << 30)
#define LATCD_DEFAULT_MAX_JOBS 64u
#define LATCD_DEFAULT_MAX_QUEUE_BYTES (UINT64_C(4) << 30)
#define LATCD_DEFAULT_MAX_CACHE_BYTES (UINT64_C(16) << 30)
#define LATCD_DEFAULT_WORKERS 1u
#define LATCD_MAX_WORKERS 32u
#define LATCD_DEFAULT_MAX_NEGATIVE 128u
#define LATCD_DEFAULT_NEGATIVE_MS 30000u
#define LATCD_DEFAULT_CPU_SECONDS 60u
#define LATCD_DEFAULT_ADDRESS_SPACE (UINT64_C(1) << 40)
#define LATCD_DEFAULT_FILE_SIZE (UINT64_C(2) << 30)
#define LATCD_DEFAULT_OPEN_FILES 256u

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
} LatcdConfig;

typedef struct LatcdJob {
    char *snapshot;
    char key[65];
    uint8_t digest[32];
    uint32_t priority;
    uint64_t sequence;
    uint64_t source_size;
} LatcdJob;

typedef struct LatcdNegativeEntry {
    uint32_t failures;
    int status;
    int64_t retry_at_us;
} LatcdNegativeEntry;

typedef struct LatcdService {
    const LatcdConfig *config;
    pthread_mutex_t lock;
    pthread_cond_t ready;
    GPtrArray *queue;
    GHashTable *active;
    GHashTable *negative;
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

static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t compiler_process_groups[LATCD_MAX_WORKERS];
static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;

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

static void digest_hex(const uint8_t digest[32], char hex[65])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    hex[64] = '\0';
}

static void signal_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
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
                           uint8_t digest[32], char *error, size_t error_size)
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

static int run_compiler(const LatcdConfig *config, uint32_t worker_index,
                        const char *source, const char *output,
                        char *error, size_t error_size)
{
    char *const arguments[] = {
        (char *)config->compiler, "compile-module", (char *)source,
        "-o", (char *)output, "--runner", (char *)config->runner,
        "--runtime-dir", (char *)config->runtime_dir, NULL,
    };
    char *library_path = g_strdup_printf("LD_LIBRARY_PATH=%s",
                                         config->runtime_dir);
    char *guest_prefix = config->x86_rootfs ?
        g_strdup_printf("LAT_LD_PREFIX=%s", config->x86_rootfs) : NULL;
    char *environment[] = {
        "PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", library_path,
        guest_prefix, NULL,
    };
    pid_t child = fork();
    if (child == 0) {
        if (setpgid(0, 0)) {
            _exit(126);
        }
        struct rlimit cpu = { config->cpu_seconds, config->cpu_seconds };
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
        execve(config->compiler, arguments, environment);
        _exit(127);
    }
    if (child < 0) {
        g_free(library_path);
        g_free(guest_prefix);
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
    compiler_process_groups[worker_index] = 0;
    g_free(library_path);
    g_free(guest_prefix);
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

static int cached_module_inspect(const char *path, const uint8_t digest[32],
                                 LatAotModuleInfoV2 *info)
{
    struct stat status;
    return !lstat(path, &status) && S_ISREG(status.st_mode) &&
           status.st_uid == geteuid() && status.st_nlink == 1 &&
           !(status.st_mode & 0222) &&
           !lat_aot_v2_module_inspect_file(path, info, NULL, 0) &&
           !memcmp(info->note.source_sha256, digest, 32);
}

typedef struct LatcdCacheEntry {
    char *module_path;
    char *index_path;
    uint64_t size;
    struct timespec modified;
} LatcdCacheEntry;

static void cache_entry_free(gpointer opaque)
{
    LatcdCacheEntry *entry = opaque;
    g_free(entry->module_path);
    g_free(entry->index_path);
    g_free(entry);
}

static int cache_entry_compare(gconstpointer left, gconstpointer right)
{
    const LatcdCacheEntry *a = *(LatcdCacheEntry *const *)left;
    const LatcdCacheEntry *b = *(LatcdCacheEntry *const *)right;
    if (a->modified.tv_sec != b->modified.tv_sec) {
        return a->modified.tv_sec < b->modified.tv_sec ? -1 : 1;
    }
    if (a->modified.tv_nsec != b->modified.tv_nsec) {
        return a->modified.tv_nsec < b->modified.tv_nsec ? -1 : 1;
    }
    return strcmp(a->module_path, b->module_path);
}

static int cache_make_room(const LatcdConfig *config, uint64_t incoming,
                           const char *incoming_hex, char *error,
                           size_t error_size)
{
    if (incoming > config->max_cache_bytes) {
        return fail(error, error_size,
                    "compiled module exceeds cache capacity");
    }
    GError *directory_error = NULL;
    GDir *directory = g_dir_open(config->cache_dir, 0, &directory_error);
    if (!directory) {
        int result = fail(error, error_size, "cannot scan cache: %s",
                          directory_error ? directory_error->message :
                          "unknown error");
        g_clear_error(&directory_error);
        return result;
    }
    uint64_t total = 0;
    GPtrArray *entries = g_ptr_array_new_with_free_func(cache_entry_free);
    const char *name;
    while ((name = g_dir_read_name(directory))) {
        size_t length = strlen(name);
        if (length != 67 || strcmp(name + 64, ".so")) {
            continue;
        }
        char digest_text[65];
        memcpy(digest_text, name, 64);
        digest_text[64] = '\0';
        uint8_t digest[32];
        bool valid_name = true;
        for (size_t i = 0; i < 32; i++) {
            int high = g_ascii_xdigit_value(digest_text[i * 2]);
            int low = g_ascii_xdigit_value(digest_text[i * 2 + 1]);
            if (high < 0 || low < 0) {
                valid_name = false;
                break;
            }
            digest[i] = (high << 4) | low;
        }
        if (!valid_name) {
            continue;
        }
        char *module_path = g_build_filename(config->cache_dir, name, NULL);
        struct stat status;
        if (lstat(module_path, &status) || !S_ISREG(status.st_mode) ||
            status.st_size < 0) {
            g_free(module_path);
            continue;
        }
        if (!strcmp(digest_text, incoming_hex)) {
            g_free(module_path);
            continue;
        }
        if ((uint64_t)status.st_size > UINT64_MAX - total) {
            total = UINT64_MAX;
        } else {
            total += status.st_size;
        }
        LatAotModuleInfoV2 info;
        if (cached_module_inspect(module_path, digest, &info)) {
            LatcdCacheEntry *entry = g_new0(LatcdCacheEntry, 1);
            entry->module_path = module_path;
            entry->index_path = g_strdup_printf("%s/%s.current",
                                                config->cache_dir,
                                                digest_text);
            entry->size = status.st_size;
            entry->modified = status.st_mtim;
            g_ptr_array_add(entries, entry);
        } else {
            g_free(module_path);
        }
    }
    g_dir_close(directory);
    g_ptr_array_sort(entries, cache_entry_compare);
    for (guint i = 0;
         incoming > config->max_cache_bytes - MIN(total,
                                                   config->max_cache_bytes) &&
         i < entries->len;
         i++) {
        LatcdCacheEntry *entry = g_ptr_array_index(entries, i);
        if (!unlink(entry->module_path)) {
            unlink(entry->index_path);
            total = total > entry->size ? total - entry->size : 0;
        }
    }
    int result = 0;
    if (total > config->max_cache_bytes - incoming) {
        result = fail(error, error_size,
                      "cache capacity is occupied by non-evictable files");
    }
    g_ptr_array_free(entries, TRUE);
    return result;
}

static int publish_current_index(const LatcdConfig *config, const char *hex,
                                 const LatAotModuleInfoV2 *info, char *error,
                                 size_t error_size)
{
    char *temporary_dir = g_build_filename(config->cache_dir, ".tmp", NULL);
    char *temporary = g_build_filename(temporary_dir, "current-XXXXXX", NULL);
    int fd = g_mkstemp_full(temporary, O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        g_free(temporary_dir);
        g_free(temporary);
        return fail(error, error_size, "cannot create current index: %s",
                    strerror(errno));
    }
    char codegen[65];
    digest_hex(info->note.codegen_id, codegen);
    char contents[384];
    int length = snprintf(contents, sizeof(contents),
        "{\"module\":\"%s.so\",\"source_sha256\":\"%s\","
        "\"codegen_id\":\"%s\"}\n", hex, hex, codegen);
    ssize_t written = write(fd, contents, length);
    int result = 0;
    if (written != length || fchmod(fd, 0444) || fsync(fd)) {
        result = fail(error, error_size, "cannot write current index: %s",
                      strerror(errno));
    }
    close(fd);
    char *final = g_strdup_printf("%s/%s.current", config->cache_dir, hex);
    if (!result && rename(temporary, final)) {
        result = fail(error, error_size, "cannot publish current index: %s",
                      strerror(errno));
    }
    if (result) {
        unlink(temporary);
    }
    g_free(final);
    g_free(temporary);
    g_free(temporary_dir);
    return result;
}

static int publish_snapshot(const LatcdConfig *config, uint32_t worker_index,
                            const char *snapshot, const uint8_t digest[32],
                            LatcdResponseV1 *response)
{
    char error[sizeof(response->message)] = {0};
    char *temporary_dir = g_build_filename(config->cache_dir, ".tmp", NULL);
    char *module = NULL;
    char *final = NULL;
    int status = LATCD_STATUS_IO_ERROR;
    memcpy(response->source_sha256, digest, 32);
    char hex[65];
    digest_hex(digest, hex);
    final = g_strdup_printf("%s/%s.so", config->cache_dir, hex);

    LatAotModuleInfoV2 info;
    pthread_mutex_lock(&cache_lock);
    if (cached_module_inspect(final, digest, &info)) {
        if (publish_current_index(config, hex, &info, error, sizeof(error))) {
            pthread_mutex_unlock(&cache_lock);
            goto out;
        }
        utimensat(AT_FDCWD, final, NULL, AT_SYMLINK_NOFOLLOW);
        pthread_mutex_unlock(&cache_lock);
        snprintf(error, sizeof(error), "cache hit: %s", final);
        status = LATCD_STATUS_OK;
        goto out;
    }
    pthread_mutex_unlock(&cache_lock);

    module = g_build_filename(temporary_dir, "module-XXXXXX", NULL);
    int placeholder = g_mkstemp_full(module, O_RDWR | O_CLOEXEC, 0600);
    if (placeholder < 0) {
        fail(error, sizeof(error), "cannot reserve module path: %s",
             strerror(errno));
        goto out;
    }
    close(placeholder);
    unlink(module);
    if (run_compiler(config, worker_index, snapshot, module,
                     error, sizeof(error))) {
        status = LATCD_STATUS_COMPILE_FAILED;
        goto out;
    }
    if (lat_aot_v2_module_inspect_file(module, &info, error, sizeof(error)) ||
        memcmp(info.note.source_sha256, digest, 32)) {
        if (!error[0]) {
            snprintf(error, sizeof(error), "compiled module source digest mismatch");
        }
        status = LATCD_STATUS_INVALID_MODULE;
        goto out;
    }
    if (chmod(module, 0444)) {
        fail(error, sizeof(error), "cannot protect compiled module: %s",
             strerror(errno));
        goto out;
    }
    if (sync_file(module, error, sizeof(error))) {
        goto out;
    }
    struct stat module_status;
    if (lstat(module, &module_status) || !S_ISREG(module_status.st_mode) ||
        module_status.st_size < 0) {
        fail(error, sizeof(error), "cannot inspect compiled module: %s",
             strerror(errno));
        goto out;
    }
    pthread_mutex_lock(&cache_lock);
    if (cached_module_inspect(final, digest, &info)) {
        if (publish_current_index(config, hex, &info, error, sizeof(error))) {
            pthread_mutex_unlock(&cache_lock);
            goto out;
        }
        utimensat(AT_FDCWD, final, NULL, AT_SYMLINK_NOFOLLOW);
        pthread_mutex_unlock(&cache_lock);
        snprintf(error, sizeof(error), "cache hit: %s", final);
        status = LATCD_STATUS_OK;
        goto out;
    }
    if (cache_make_room(config, module_status.st_size, hex,
                        error, sizeof(error)) || rename(module, final)) {
        if (!error[0]) {
            fail(error, sizeof(error), "cannot publish module: %s",
                 strerror(errno));
        }
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    if (sync_directory(config->cache_dir, error, sizeof(error))) {
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    if (publish_current_index(config, hex, &info, error, sizeof(error))) {
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    if (sync_directory(config->cache_dir, error, sizeof(error))) {
        pthread_mutex_unlock(&cache_lock);
        goto out;
    }
    pthread_mutex_unlock(&cache_lock);
    snprintf(error, sizeof(error), "published: %s", final);
    status = LATCD_STATUS_OK;
out:
    response->status = status;
    g_strlcpy(response->message, error[0] ? error : "unknown error",
              sizeof(response->message));
    if (module) {
        unlink(module);
    }
    g_free(final);
    g_free(module);
    g_free(temporary_dir);
    return status ? -1 : 0;
}

static int process_request(const LatcdConfig *config, int source_fd,
                           LatcdResponseV1 *response)
{
    char error[sizeof(response->message)] = {0};
    char *temporary_dir = g_build_filename(config->cache_dir, ".tmp", NULL);
    char *snapshot = NULL;
    int result = -1;
    if (ensure_private_directory(config->cache_dir, error, sizeof(error)) ||
        ensure_private_directory(temporary_dir, error, sizeof(error))) {
        response->status = LATCD_STATUS_IO_ERROR;
        goto out;
    }
    if (snapshot_source(source_fd, temporary_dir, config->max_input, &snapshot,
                        response->source_sha256, error, sizeof(error))) {
        response->status = LATCD_STATUS_BAD_SOURCE;
        goto out;
    }
    result = publish_snapshot(config, 0, snapshot, response->source_sha256,
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
    g_free(job->snapshot);
    g_free(job);
}

static int cache_contains(const LatcdConfig *config, const uint8_t digest[32])
{
    char hex[65];
    digest_hex(digest, hex);
    char *path = g_strdup_printf("%s/%s.so", config->cache_dir, hex);
    LatAotModuleInfoV2 info;
    pthread_mutex_lock(&cache_lock);
    int valid = cached_module_inspect(path, digest, &info);
    if (valid) {
        char error[128];
        valid = !publish_current_index(config, hex, &info, error,
                                       sizeof(error));
        if (valid) {
            utimensat(AT_FDCWD, path, NULL, AT_SYMLINK_NOFOLLOW);
        }
    }
    pthread_mutex_unlock(&cache_lock);
    g_free(path);
    return valid;
}

static void write_stats_locked(const LatcdService *service)
{
    if (!service->config->stats_path) {
        return;
    }
    char *temporary = g_strdup_printf("%s.tmp.%ld",
        service->config->stats_path, (long)getpid());
    char contents[1024];
    int length = snprintf(contents, sizeof(contents),
        "{\"requests\":%" PRIu64 ",\"queued\":%" PRIu64
        ",\"deduplicated\":%" PRIu64 ",\"cache_hits\":%" PRIu64
        ",\"compiled\":%" PRIu64 ",\"failed\":%" PRIu64
        ",\"negative_hits\":%" PRIu64 ",\"queue_full\":%" PRIu64
        ",\"queue_depth\":%u,\"queue_bytes\":%" PRIu64
        ",\"active_jobs\":%u,\"workers\":%u"
        ",\"max_cache_bytes\":%" PRIu64 "}\n",
        service->requests, service->queued, service->deduplicated,
        service->cache_hits, service->compiled, service->failed,
        service->negative_hits, service->queue_full, service->queue->len,
        service->queued_bytes,
        g_hash_table_size(service->active), service->config->workers,
        service->config->max_cache_bytes);
    int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
        ssize_t written = write(fd, contents, length);
        if (written == length && !fsync(fd)) {
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

static LatcdJob *queue_take_next_locked(LatcdService *service)
{
    if (!service->queue->len) {
        return NULL;
    }
    guint selected = 0;
    LatcdJob *best = g_ptr_array_index(service->queue, 0);
    for (guint i = 1; i < service->queue->len; i++) {
        LatcdJob *candidate = g_ptr_array_index(service->queue, i);
        if (candidate->priority > best->priority ||
            (candidate->priority == best->priority &&
             candidate->sequence < best->sequence)) {
            selected = i;
            best = candidate;
        }
    }
    g_ptr_array_remove_index(service->queue, selected);
    service->queued_bytes -= best->source_size;
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

static void *compiler_worker(void *opaque)
{
    LatcdWorker *worker = opaque;
    LatcdService *service = worker->service;
    for (;;) {
        pthread_mutex_lock(&service->lock);
        while (!service->stopping && !service->queue->len) {
            pthread_cond_wait(&service->ready, &service->lock);
        }
        if (service->stopping && !service->queue->len) {
            pthread_mutex_unlock(&service->lock);
            break;
        }
        LatcdJob *job = queue_take_next_locked(service);
        write_stats_locked(service);
        pthread_mutex_unlock(&service->lock);

        LatcdResponseV1 response = {
            .magic = LATCD_RESPONSE_MAGIC,
            .version = LATCD_PROTOCOL_VERSION,
            .size = sizeof(response),
        };
        int result = publish_snapshot(service->config, worker->index,
                                      job->snapshot, job->digest, &response);

        pthread_mutex_lock(&service->lock);
        g_hash_table_remove(service->active, job->key);
        if (!result) {
            service->compiled++;
            g_hash_table_remove(service->negative, job->key);
        } else {
            service->failed++;
            negative_record_locked(service, job->key, response.status);
        }
        write_stats_locked(service);
        pthread_mutex_unlock(&service->lock);
        job_free(job);
    }
    return NULL;
}

static void response_init(LatcdResponseV1 *response, uint64_t request_id)
{
    memset(response, 0, sizeof(*response));
    response->magic = LATCD_RESPONSE_MAGIC;
    response->version = LATCD_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->request_id = request_id;
}

static int service_queue_request(LatcdService *service, int source_fd,
                                 const LatcdRequestV1 *request,
                                 LatcdResponseV1 *response)
{
    char error[sizeof(response->message)] = {0};
    char *temporary_dir = g_build_filename(service->config->cache_dir,
                                            ".tmp", NULL);
    char *snapshot = NULL;
    response_init(response, request->request_id);
    if (snapshot_source(source_fd, temporary_dir,
                        service->config->max_input, &snapshot,
                        response->source_sha256, error, sizeof(error))) {
        response->status = LATCD_STATUS_BAD_SOURCE;
        g_strlcpy(response->message, error, sizeof(response->message));
        g_free(temporary_dir);
        return -1;
    }
    g_free(temporary_dir);
    char key[65];
    digest_hex(response->source_sha256, key);
    struct stat snapshot_status;
    if (stat(snapshot, &snapshot_status) || snapshot_status.st_size < 0) {
        response->status = LATCD_STATUS_IO_ERROR;
        g_strlcpy(response->message, "cannot inspect source snapshot",
                  sizeof(response->message));
        unlink(snapshot);
        g_free(snapshot);
        return -1;
    }
    uint64_t source_size = snapshot_status.st_size;

    pthread_mutex_lock(&service->lock);
    service->requests++;
    if (cache_contains(service->config, response->source_sha256)) {
        service->cache_hits++;
        response->status = LATCD_STATUS_OK;
        snprintf(response->message, sizeof(response->message),
                 "cache hit: %s", key);
        write_stats_locked(service);
        pthread_mutex_unlock(&service->lock);
        unlink(snapshot);
        g_free(snapshot);
        return 0;
    }
    if (g_hash_table_contains(service->active, key)) {
        service->deduplicated++;
        response->status = LATCD_STATUS_OK;
        snprintf(response->message, sizeof(response->message),
                 "deduplicated: %s", key);
        write_stats_locked(service);
        pthread_mutex_unlock(&service->lock);
        unlink(snapshot);
        g_free(snapshot);
        return 0;
    }
    LatcdNegativeEntry *negative = g_hash_table_lookup(service->negative, key);
    if (negative && negative->retry_at_us > g_get_monotonic_time()) {
        service->negative_hits++;
        response->status = LATCD_STATUS_NEGATIVE_CACHE;
        snprintf(response->message, sizeof(response->message),
                 "negative cache: retry in %" PRId64 " ms",
                 (negative->retry_at_us - g_get_monotonic_time()) / 1000);
        write_stats_locked(service);
        pthread_mutex_unlock(&service->lock);
        unlink(snapshot);
        g_free(snapshot);
        return -1;
    }
    if (service->queue->len >= service->config->max_jobs ||
        source_size > service->config->max_queue_bytes -
                      service->queued_bytes) {
        service->queue_full++;
        response->status = LATCD_STATUS_QUEUE_FULL;
        g_strlcpy(response->message, "compiler queue is full",
                  sizeof(response->message));
        write_stats_locked(service);
        pthread_mutex_unlock(&service->lock);
        unlink(snapshot);
        g_free(snapshot);
        return -1;
    }
    LatcdJob *job = g_new0(LatcdJob, 1);
    job->snapshot = snapshot;
    g_strlcpy(job->key, key, sizeof(job->key));
    memcpy(job->digest, response->source_sha256, sizeof(job->digest));
    job->priority = request->priority;
    job->sequence = service->next_sequence++;
    job->source_size = source_size;
    g_ptr_array_add(service->queue, job);
    service->queued_bytes += source_size;
    g_hash_table_insert(service->active, g_strdup(key), job);
    service->queued++;
    response->status = LATCD_STATUS_OK;
    snprintf(response->message, sizeof(response->message), "queued: %s", key);
    write_stats_locked(service);
    pthread_cond_signal(&service->ready);
    pthread_mutex_unlock(&service->lock);
    return 0;
}

static int make_server(const char *path, char *error, size_t error_size)
{
    if (strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        return fail(error, error_size, "socket path is too long");
    }
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
    g_strlcpy(address.sun_path, path, sizeof(address.sun_path));
    mode_t old_mask = umask(0077);
    int result = bind(fd, (const void *)&address, sizeof(address));
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
    LatcdRequestV1 request = {0};
    int source = -1;
    LatcdResponseV1 response = {
        .magic = LATCD_RESPONSE_MAGIC,
        .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(response),
    };
    if (client < 0 || !peer_is_current_user(client) ||
        latcd_receive_request(client, &request, &source,
                              error, sizeof(error))) {
        response.status = LATCD_STATUS_BAD_REQUEST;
        g_strlcpy(response.message, error[0] ? error : "accept failed",
                  sizeof(response.message));
    } else {
        response.request_id = request.request_id;
        process_request(config, source, &response);
    }
    if (client >= 0) {
        latcd_send_response(client, &response, NULL, 0);
        close(client);
    }
    if (source >= 0) {
        close(source);
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
        .negative = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                          g_free),
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
        g_hash_table_destroy(service.negative);
        return 1;
    }
    struct sigaction action = { .sa_handler = signal_stop };
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    stop_requested = 0;
    while (!stop_requested) {
        struct pollfd poll_fd = { .fd = server, .events = POLLIN };
        int available = poll(&poll_fd, 1, 250);
        if (available < 0 && errno == EINTR) {
            continue;
        }
        if (available <= 0 || !(poll_fd.revents & POLLIN)) {
            continue;
        }
        int client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) {
            continue;
        }
        LatcdRequestV1 request = {0};
        LatcdResponseV1 response;
        response_init(&response, 0);
        int source = -1;
        if (!peer_is_current_user(client) || !request_is_ready(client)) {
            response.status = LATCD_STATUS_BAD_REQUEST;
            g_strlcpy(response.message, "request user does not own latcd",
                      sizeof(response.message));
        } else if (latcd_receive_request(client, &request, &source,
                                         error, sizeof(error))) {
            response.status = LATCD_STATUS_BAD_REQUEST;
            g_strlcpy(response.message, error, sizeof(response.message));
        } else {
            service_queue_request(&service, source, &request, &response);
        }
        latcd_send_response(client, &response, NULL, 0);
        if (source >= 0) {
            close(source);
        }
        close(client);
    }
    close(server);
    unlink(config->socket_path);
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
    g_hash_table_destroy(service.negative);
    g_free(worker_args);
    g_free(service.workers);
    pthread_cond_destroy(&service.ready);
    pthread_mutex_destroy(&service.lock);
    return 0;
}

static int run_submit(const char *socket_path, const char *source_path,
                      uint32_t priority)
{
    int source = open(source_path, O_RDONLY | O_CLOEXEC);
    int client = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (source < 0 || client < 0) {
        fprintf(stderr, "latcd: cannot open submission input: %s\n",
                strerror(errno));
        if (source >= 0) close(source);
        if (client >= 0) close(client);
        return 1;
    }
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        fprintf(stderr, "latcd: socket path is too long\n");
        close(source);
        close(client);
        return 1;
    }
    g_strlcpy(address.sun_path, socket_path, sizeof(address.sun_path));
    if (connect(client, (const void *)&address, sizeof(address))) {
        fprintf(stderr, "latcd: cannot connect: %s\n", strerror(errno));
        close(source);
        close(client);
        return 1;
    }
    LatcdRequestV1 request = {
        .magic = LATCD_REQUEST_MAGIC,
        .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(request),
        .priority = priority,
        .request_id = ((uint64_t)getpid() << 32) ^ g_get_monotonic_time(),
    };
    char error[256] = {0};
    LatcdResponseV1 response;
    int result = latcd_send_request(client, source, &request, error,
                                    sizeof(error)) ||
                 latcd_receive_response(client, &response, error,
                                        sizeof(error));
    if (result) {
        fprintf(stderr, "latcd: %s\n", error);
    } else {
        char hex[65];
        digest_hex(response.source_sha256, hex);
        printf("status=%d\nrequest_id=%" PRIu64 "\nsource_sha256=%s\n%s\n",
               response.status, response.request_id, hex, response.message);
        result = response.status != LATCD_STATUS_OK;
    }
    close(source);
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
            " [--workers N]"
            " [--cpu-seconds N] [--address-space BYTES]"
            " [--file-size BYTES] [--open-files N]\n"
            "  %s --submit --socket PATH [--priority N] X86_ELF\n",
            name, name, name);
}

int main(int argc, char **argv)
{
    int once = 0, serve = 0, submit = 0;
    const char *source = NULL;
    uint32_t priority = LATCD_PRIORITY_LIBRARY;
    LatcdConfig config = {
        .max_input = LATCD_DEFAULT_MAX_INPUT,
        .address_space_limit = LATCD_DEFAULT_ADDRESS_SPACE,
        .file_size_limit = LATCD_DEFAULT_FILE_SIZE,
        .max_queue_bytes = LATCD_DEFAULT_MAX_QUEUE_BYTES,
        .max_cache_bytes = LATCD_DEFAULT_MAX_CACHE_BYTES,
        .max_jobs = LATCD_DEFAULT_MAX_JOBS,
        .workers = LATCD_DEFAULT_WORKERS,
        .max_negative = LATCD_DEFAULT_MAX_NEGATIVE,
        .negative_ms = LATCD_DEFAULT_NEGATIVE_MS,
        .cpu_seconds = LATCD_DEFAULT_CPU_SECONDS,
        .open_files = LATCD_DEFAULT_OPEN_FILES,
    };
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--once")) once = 1;
        else if (!strcmp(argv[i], "--serve")) serve = 1;
        else if (!strcmp(argv[i], "--submit")) submit = 1;
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
        else if (submit && !source) source = argv[i];
        else { usage(argv[0]); return 2; }
    }
    if (once + serve + submit != 1 || !config.socket_path) {
        usage(argv[0]);
        return 2;
    }
    if (submit) {
        if (!source) { usage(argv[0]); return 2; }
        return run_submit(config.socket_path, source, priority);
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
    return serve ? run_service(&config) : run_once(&config);
}
