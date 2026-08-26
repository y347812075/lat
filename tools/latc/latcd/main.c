#define _GNU_SOURCE

#include "latcd-protocol.h"
#include "module-inspect.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define LATCD_DEFAULT_MAX_INPUT (UINT64_C(1) << 30)

typedef struct LatcdConfig {
    const char *socket_path;
    const char *cache_dir;
    const char *compiler;
    const char *runner;
    const char *runtime_dir;
    uint64_t max_input;
} LatcdConfig;

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

static int run_compiler(const LatcdConfig *config, const char *source,
                        const char *output, char *error, size_t error_size)
{
    pid_t child = fork();
    if (child == 0) {
        if (setenv("LD_LIBRARY_PATH", config->runtime_dir, 1)) {
            _exit(126);
        }
        execl(config->compiler, config->compiler, "compile-module", source,
              "-o", output, "--runner", config->runner, "--runtime-dir",
              config->runtime_dir, (char *)NULL);
        _exit(127);
    }
    if (child < 0) {
        return fail(error, error_size, "cannot start compiler: %s",
                    strerror(errno));
    }
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
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

static int process_request(const LatcdConfig *config, int source_fd,
                           LatcdResponseV1 *response)
{
    char error[sizeof(response->message)] = {0};
    char *temporary_dir = g_build_filename(config->cache_dir, ".tmp", NULL);
    char *snapshot = NULL;
    char *module = NULL;
    char *final = NULL;
    int status = LATCD_STATUS_IO_ERROR;
    if (ensure_private_directory(config->cache_dir, error, sizeof(error)) ||
        ensure_private_directory(temporary_dir, error, sizeof(error))) {
        goto out;
    }
    if (snapshot_source(source_fd, temporary_dir, config->max_input, &snapshot,
                        response->source_sha256, error, sizeof(error))) {
        status = LATCD_STATUS_BAD_SOURCE;
        goto out;
    }
    char hex[65];
    digest_hex(response->source_sha256, hex);
    final = g_strdup_printf("%s/%s.so", config->cache_dir, hex);

    LatAotModuleInfoV2 info;
    if (!lat_aot_v2_module_inspect_file(final, &info, NULL, 0) &&
        !memcmp(info.note.source_sha256, response->source_sha256, 32)) {
        snprintf(error, sizeof(error), "cache hit: %s", final);
        status = LATCD_STATUS_OK;
        goto out;
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
    if (run_compiler(config, snapshot, module, error, sizeof(error))) {
        status = LATCD_STATUS_COMPILE_FAILED;
        goto out;
    }
    if (lat_aot_v2_module_inspect_file(module, &info, error, sizeof(error)) ||
        memcmp(info.note.source_sha256, response->source_sha256, 32)) {
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
    if (sync_file(module, error, sizeof(error)) || rename(module, final)) {
        if (!error[0]) {
            fail(error, sizeof(error), "cannot publish module: %s",
                 strerror(errno));
        }
        goto out;
    }
    int directory = open(config->cache_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0 || fsync(directory)) {
        int saved = errno;
        if (directory >= 0) {
            close(directory);
        }
        fail(error, sizeof(error), "cannot sync cache directory: %s",
             strerror(saved));
        goto out;
    }
    close(directory);
    snprintf(error, sizeof(error), "published: %s", final);
    status = LATCD_STATUS_OK;
out:
    response->status = status;
    g_strlcpy(response->message, error[0] ? error : "unknown error",
              sizeof(response->message));
    if (snapshot) {
        unlink(snapshot);
    }
    if (module) {
        unlink(module);
    }
    g_free(final);
    g_free(module);
    g_free(snapshot);
    g_free(temporary_dir);
    return status ? -1 : 0;
}

static int make_server(const char *path, char *error, size_t error_size)
{
    if (strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        return fail(error, error_size, "socket path is too long");
    }
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
    if (result || listen(fd, 1)) {
        fail(error, error_size, "cannot listen on %s: %s", path,
             strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }
    return fd;
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
    LatcdRequestV1 request = {0};
    int source = -1;
    LatcdResponseV1 response = {
        .magic = LATCD_RESPONSE_MAGIC,
        .version = LATCD_PROTOCOL_VERSION,
        .size = sizeof(response),
    };
    if (client < 0 || latcd_receive_request(client, &request, &source,
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
            "  %s --submit --socket PATH [--priority N] X86_ELF\n",
            name, name);
}

int main(int argc, char **argv)
{
    int once = 0, submit = 0;
    const char *source = NULL;
    uint32_t priority = LATCD_PRIORITY_LIBRARY;
    LatcdConfig config = { .max_input = LATCD_DEFAULT_MAX_INPUT };
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--once")) once = 1;
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
        else if (!strcmp(argv[i], "--max-input") && i + 1 < argc)
            config.max_input = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--priority") && i + 1 < argc)
            priority = g_ascii_strtoull(argv[++i], NULL, 10);
        else if (submit && !source) source = argv[i];
        else { usage(argv[0]); return 2; }
    }
    if (once == submit || !config.socket_path) {
        usage(argv[0]);
        return 2;
    }
    if (submit) {
        if (!source) { usage(argv[0]); return 2; }
        return run_submit(config.socket_path, source, priority);
    }
    if (!config.cache_dir || !config.compiler || !config.runner ||
        !config.runtime_dir || !config.max_input) {
        usage(argv[0]);
        return 2;
    }
    return run_once(&config);
}
