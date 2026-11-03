#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "managed-launch.h"
#include "cache-capacity.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define LAUNCH_RECORD_LIMIT (1024u * 1024u)

static int fail(char *error, size_t size, const char *format, ...)
{
    if (error && size) {
        va_list arguments;
        va_start(arguments, format);
        vsnprintf(error, size, format, arguments);
        va_end(arguments);
    }
    errno = EINVAL;
    return -1;
}

static bool digest_string(const char *value)
{
    return value && strlen(value) == 64 &&
        strspn(value, "0123456789abcdef") == 64;
}

static void digest_hex(const uint8_t digest[32], char text[65])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        text[2 * i] = digits[digest[i] >> 4];
        text[2 * i + 1] = digits[digest[i] & 15];
    }
    text[64] = 0;
}

static int read_fd(int fd, void *buffer, size_t size, off_t offset)
{
    size_t done = 0;
    while (done < size) {
        ssize_t count = pread(fd, (char *)buffer + done, size - done, offset + done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        done += count;
    }
    return 0;
}

static int identity_fd(int fd, uint8_t digest[32], uint64_t *size)
{
    memset(digest, 0, 32);
    if (size) *size = 0;
    if (fd < 0) return 0;
    int input = fd;
    char path[64];
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_PATH)) {
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        input = open(path, O_RDONLY | O_CLOEXEC);
    }
    struct stat before, after;
    if (input < 0 || fstat(input, &before) || !S_ISREG(before.st_mode) || before.st_size < 0) {
        if (input >= 0 && input != fd) close(input);
        return -1;
    }
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    uint8_t buffer[65536];
    off_t offset = 0;
    bool ok = sum != NULL;
    while (ok && offset < before.st_size) {
        size_t wanted = MIN(sizeof(buffer), (size_t)(before.st_size - offset));
        if (read_fd(input, buffer, wanted, offset)) ok = false;
        else {
            g_checksum_update(sum, buffer, wanted);
            offset += wanted;
        }
    }
    gsize length = 32;
    if (ok) g_checksum_get_digest(sum, digest, &length);
    ok = ok && length == 32 && !fstat(input, &after) && before.st_dev == after.st_dev &&
        before.st_ino == after.st_ino && before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
        before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
    if (size) *size = (uint64_t)before.st_size;
    if (sum) g_checksum_free(sum);
    if (input != fd) close(input);
    return ok ? 0 : -1;
}

static GBytes *encode_array(const GPtrArray *array)
{
    GByteArray *bytes = g_byte_array_new();
    if (array) for (guint i = 0; i < array->len; i++) {
        const char *item = g_ptr_array_index(array, i);
        if (!item) continue;
        gsize length = strlen(item) + 1;
        g_byte_array_append(bytes, (const guint8 *)item, length);
    }
    return g_byte_array_free_to_bytes(bytes);
}

static GBytes *encode_environment(const char *const *environment)
{
    GByteArray *bytes = g_byte_array_new();
    if (environment) for (size_t i = 0; environment[i]; i++) {
        gsize length = strlen(environment[i]) + 1;
        g_byte_array_append(bytes, (const guint8 *)environment[i], length);
    }
    return g_byte_array_free_to_bytes(bytes);
}

static bool decode_array(const char *encoded, GPtrArray **array)
{
    gsize size = 0;
    guchar *decoded = encoded ? g_base64_decode(encoded, &size) : NULL;
    bool valid = decoded && size && decoded[size - 1] == 0;
    GPtrArray *items = valid ? g_ptr_array_new_with_free_func(g_free) : NULL;
    size_t offset = 0;
    while (valid && offset < size) {
        size_t length = strnlen((const char *)decoded + offset, size - offset);
        valid = length && offset + length < size;
        if (valid) {
            g_ptr_array_add(items, g_strndup((const char *)decoded + offset, length));
            offset += length + 1;
        }
    }
    valid = valid && offset == size;
    g_free(decoded);
    if (!valid) {
        if (items) g_ptr_array_free(items, TRUE);
        return false;
    }
    *array = items;
    return true;
}

static int open_directory(const char *root, bool create)
{
    int cache = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int gc = cache < 0 ? -1 : latcd_cache_capacity_open_metadata_directory(cache, ".gc");
    int directory = gc < 0 ? -1 :
        latcd_cache_capacity_open_metadata_directory(gc, "managed-launch");
    if (directory >= 0 && create && fsync(gc)) {
        close(directory);
        directory = -1;
    }
    if (gc >= 0) close(gc);
    if (cache >= 0) close(cache);
    return directory;
}

static int encode_contract(const char *root, const char *id, int task_fd,
                           const LatcdManagedLaunchInput *input,
                           char **data, size_t *size, struct stat *task_identity,
                           char digest[65],
                           char *error, size_t error_size)
{
    if (!id || strlen(id) != 36 || !g_uuid_string_is_valid(id) || task_fd < 0 ||
        !input || !input->receipt_size || !input->options || !input->exec ||
        !input->environment || !data || !size)
        return fail(error, error_size, "invalid managed launch contract");
    struct stat task, cache;
    int cache_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool cache_valid = cache_fd >= 0 && !fstat(cache_fd, &cache);
    if (cache_fd >= 0) close(cache_fd);
    uint8_t task_sha256[32], compiler_sha256[32], runner_sha256[32], runtime_sha256[32];
    uint8_t launcher_sha256[32], bootstrap_sha256[32], baseline_sha256[32];
    uint64_t compiler_size, runner_size, runtime_size, launcher_size, bootstrap_size, baseline_size;
    if (!cache_valid || fstat(task_fd, &task) || !S_ISREG(task.st_mode) ||
        task.st_uid != geteuid() ||
        task.st_nlink != 1 || !(task.st_mode & 0400) || (task.st_mode & 0222) ||
        identity_fd(task_fd, task_sha256, NULL) ||
        identity_fd(input->compiler_fd, compiler_sha256, &compiler_size) ||
        identity_fd(input->runner_fd, runner_sha256, &runner_size) ||
        identity_fd(input->runtime_fd, runtime_sha256, &runtime_size) ||
        identity_fd(input->launcher_fd, launcher_sha256, &launcher_size) ||
        identity_fd(input->bootstrap_fd, bootstrap_sha256, &bootstrap_size) ||
        identity_fd(input->baseline_fd, baseline_sha256, &baseline_size))
        return fail(error, error_size, "cannot identify managed launch inputs");
    GBytes *options = encode_array(input->options);
    GBytes *exec = encode_array(input->exec);
    GBytes *environment = encode_environment(input->environment);
    gsize options_size, exec_size, environment_size;
    const guint8 *options_data = g_bytes_get_data(options, &options_size);
    const guint8 *exec_data = g_bytes_get_data(exec, &exec_size);
    const guint8 *environment_data = g_bytes_get_data(environment, &environment_size);
    char *options_b64 = g_base64_encode(options_data, options_size);
    char *exec_b64 = g_base64_encode(exec_data, exec_size);
    char *environment_b64 = g_base64_encode(environment_data, environment_size);
    char task_hash[65], build[65], codegen[65], config[65], source[65], receipt[65], closure[65];
    char compiler[65], runner[65], runtime[65], launcher[65], bootstrap[65], baseline[65];
    digest_hex(task_sha256, task_hash);
    digest_hex(input->build_sha256, build);
    digest_hex(input->codegen_sha256, codegen);
    digest_hex(input->config_sha256, config);
    digest_hex(input->source_sha256, source);
    digest_hex(input->receipt_sha256, receipt);
    digest_hex(input->closure_sha256, closure);
    digest_hex(compiler_sha256, compiler);
    digest_hex(runner_sha256, runner);
    digest_hex(runtime_sha256, runtime);
    digest_hex(launcher_sha256, launcher);
    digest_hex(bootstrap_sha256, bootstrap);
    digest_hex(baseline_sha256, baseline);
    GKeyFile *record = g_key_file_new();
    g_key_file_set_string(record, "contract", "version", "1");
    g_key_file_set_string(record, "contract", "policy", "restricted-journal-replay-v1");
    g_key_file_set_string(record, "contract", "task_id", id);
    g_key_file_set_uint64(record, "contract", "task_device", task.st_dev);
    g_key_file_set_uint64(record, "contract", "task_inode", task.st_ino);
    g_key_file_set_string(record, "contract", "task_sha256", task_hash);
    g_key_file_set_uint64(record, "contract", "cache_device", cache.st_dev);
    g_key_file_set_uint64(record, "contract", "cache_inode", cache.st_ino);
    g_key_file_set_string(record, "contract", "build_sha256", build);
    g_key_file_set_string(record, "contract", "codegen_sha256", codegen);
    g_key_file_set_string(record, "contract", "config_sha256", config);
    g_key_file_set_string(record, "contract", "source_sha256", source);
    g_key_file_set_string(record, "contract", "receipt_sha256", receipt);
    g_key_file_set_string(record, "contract", "closure_sha256", closure);
    g_key_file_set_string(record, "contract", "compiler_sha256", compiler);
    g_key_file_set_string(record, "contract", "runner_sha256", runner);
    g_key_file_set_string(record, "contract", "runtime_sha256", runtime);
    g_key_file_set_string(record, "contract", "launcher_sha256", launcher);
    g_key_file_set_string(record, "contract", "bootstrap_sha256", bootstrap);
    g_key_file_set_string(record, "contract", "baseline_sha256", baseline);
    g_key_file_set_uint64(record, "contract", "receipt_size", input->receipt_size);
    g_key_file_set_uint64(record, "contract", "compiler_size", compiler_size);
    g_key_file_set_uint64(record, "contract", "runner_size", runner_size);
    g_key_file_set_uint64(record, "contract", "runtime_size", runtime_size);
    g_key_file_set_uint64(record, "contract", "launcher_size", launcher_size);
    g_key_file_set_uint64(record, "contract", "bootstrap_size", bootstrap_size);
    g_key_file_set_uint64(record, "contract", "baseline_size", baseline_size);
    g_key_file_set_string(record, "plan", "options", options_b64);
    g_key_file_set_string(record, "plan", "exec", exec_b64);
    g_key_file_set_string(record, "plan", "environment", environment_b64);
    *data = g_key_file_to_data(record, size, NULL);
    *digest = 0;
    *task_identity = task;
    char *sum = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
        (const guchar *)*data, *size);
    if (sum) g_strlcpy(digest, sum, 65);
    bool ok = *data && *size && sum && *size <= LAUNCH_RECORD_LIMIT;
    g_free(sum);
    g_key_file_unref(record);
    g_bytes_unref(environment);
    g_bytes_unref(exec);
    g_bytes_unref(options);
    g_free(environment_b64);
    g_free(exec_b64);
    g_free(options_b64);
    if (!ok) {
        g_free(*data);
        *data = NULL;
        *size = 0;
        return fail(error, error_size, "cannot encode managed launch contract");
    }
    return 0;
}

int latcd_managed_launch_prepare(const char *root, const char *id, int task_fd,
    const LatcdManagedLaunchInput *input, struct stat *identity,
    char digest[65], char *error, size_t error_size)
{
    if (!root || !identity || !digest) return fail(error, error_size, "missing launch output");
    char *data = NULL;
    size_t size = 0;
    struct stat task, expected, actual;
    if (encode_contract(root, id, task_fd, input, &data, &size, &task, digest,
                        error, error_size)) return -1;
    int directory = open_directory(root, false);
    char *name = g_strdup_printf("%s.launch", id);
    LatcdMetadataReservation reservation;
    bool reserved = false, installed = false, leftover = false;
    int fd = -1, result = -1;
    if (directory < 0 ||
        latcd_cache_capacity_metadata_begin(directory, name, size, &reservation)) goto out;
    reserved = true;
    fd = openat(directory, ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) goto out;
    size_t done = 0;
    while (done < size) {
        ssize_t count = write(fd, data + done, size - done);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto out;
        done += count;
    }
    if (fchmod(fd, 0400) || fsync(fd) || fstat(fd, &expected)) goto out;
    char descriptor[64];
    snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
    if (linkat(AT_FDCWD, descriptor, directory, name, AT_SYMLINK_FOLLOW)) goto out;
    installed = true;
    if (fsync(directory) || fstatat(directory, name, &actual, AT_SYMLINK_NOFOLLOW) ||
        actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino ||
        actual.st_size != (off_t)size) {
        leftover = true;
        goto out;
    }
    *identity = actual;
    result = 0;
out:
    if (fd >= 0 && close(fd)) leftover = true;
    if (reserved) latcd_cache_capacity_metadata_finish(&reservation, installed, leftover);
    if (directory >= 0) close(directory);
    g_free(name);
    g_free(data);
    if (result) return fail(error, error_size, "cannot persist managed launch contract");
    return 0;
}

static int read_contract(int directory, const char *name, char **data, size_t *size,
                         struct stat *identity, char digest[65],
                         char *error, size_t error_size)
{
    int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat before, after;
    if (fd < 0 || fstat(fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_uid != geteuid() || before.st_nlink != 1 || before.st_size <= 0 ||
        before.st_size > LAUNCH_RECORD_LIMIT || !(before.st_mode & 0400) ||
        (before.st_mode & 0222)) {
        if (fd >= 0) close(fd);
        return fail(error, error_size, "invalid managed launch file");
    }
    *data = g_malloc(before.st_size + 1);
    *size = before.st_size;
    int result = read_fd(fd, *data, *size, 0) || fstat(fd, &after) ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec;
    close(fd);
    if (result) {
        g_free(*data); *data = NULL; *size = 0;
        return fail(error, error_size, "managed launch file changed");
    }
    (*data)[*size] = 0;
    if (identity) *identity = before;
    char *sum = g_compute_checksum_for_data(G_CHECKSUM_SHA256,
        (const guchar *)*data, *size);
    if (!sum || !digest_string(sum)) {
        g_free(sum); g_free(*data); *data = NULL; *size = 0;
        return fail(error, error_size, "cannot hash managed launch file");
    }
    g_strlcpy(digest, sum, 65);
    g_free(sum);
    return 0;
}

static bool exact_contract(const char *root, GKeyFile *record, const char *id, int task_fd,
                           char *error, size_t error_size)
{
    const char *keys[] = {"version", "policy", "task_id", "task_device", "task_inode",
        "task_sha256", "cache_device", "cache_inode", "build_sha256", "codegen_sha256",
        "config_sha256", "source_sha256", "receipt_sha256", "closure_sha256",
        "compiler_sha256", "runner_sha256", "runtime_sha256", "launcher_sha256",
        "bootstrap_sha256", "baseline_sha256", "receipt_size", "compiler_size",
        "runner_size", "runtime_size", "launcher_size", "bootstrap_size", "baseline_size"};
    gsize groups = 0, count = 0;
    char **names = g_key_file_get_groups(record, &groups);
    char **contract = groups == 2 ? g_key_file_get_keys(record, "contract", &count, NULL) : NULL;
    bool valid = groups == 2 && !strcmp(names[0], "contract") && !strcmp(names[1], "plan") &&
        contract && count == G_N_ELEMENTS(keys) &&
        g_key_file_has_group(record, "plan");
    for (size_t i = 0; valid && i < G_N_ELEMENTS(keys); i++)
        valid = g_key_file_has_key(record, "contract", keys[i], NULL);
    gsize plan_count = 0;
    char **plan = valid ? g_key_file_get_keys(record, "plan", &plan_count, NULL) : NULL;
    valid = valid && plan && plan_count == 3 && g_key_file_has_key(record, "plan", "options", NULL) &&
        g_key_file_has_key(record, "plan", "exec", NULL) &&
        g_key_file_has_key(record, "plan", "environment", NULL);
    char *version = valid ? g_key_file_get_string(record, "contract", "version", NULL) : NULL;
    char *policy = valid ? g_key_file_get_string(record, "contract", "policy", NULL) : NULL;
    char *task_id = valid ? g_key_file_get_string(record, "contract", "task_id", NULL) : NULL;
    char *task_sha = valid ? g_key_file_get_string(record, "contract", "task_sha256", NULL) : NULL;
    /* A value key that exists but cannot be decoded yields NULL here. */
    valid = valid && version && policy && task_id &&
        !strcmp(version, "1") && !strcmp(policy, "restricted-journal-replay-v1") &&
        !strcmp(task_id, id) && digest_string(task_sha);
    const char *digests[] = {"build_sha256", "codegen_sha256", "config_sha256",
        "source_sha256", "receipt_sha256", "closure_sha256", "compiler_sha256",
        "runner_sha256", "runtime_sha256", "launcher_sha256", "bootstrap_sha256", "baseline_sha256"};
    for (size_t i = 0; valid && i < G_N_ELEMENTS(digests); i++) {
        char *value = g_key_file_get_string(record, "contract", digests[i], NULL);
        valid = digest_string(value);
        g_free(value);
    }
    GError *parse = NULL;
    uint64_t task_device = g_key_file_get_uint64(record, "contract", "task_device", &parse);
    struct stat task;
    valid = valid && !parse && task_fd >= 0 && !fstat(task_fd, &task) &&
        task_device == (uint64_t)task.st_dev;
    g_clear_error(&parse);
    uint64_t task_inode = g_key_file_get_uint64(record, "contract", "task_inode", &parse);
    valid = valid && !parse && task_inode == (uint64_t)task.st_ino;
    g_clear_error(&parse);
    uint64_t cache_device = g_key_file_get_uint64(record, "contract", "cache_device", &parse);
    int cache = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat cache_stat;
    valid = valid && !parse && cache >= 0 && !fstat(cache, &cache_stat) &&
        cache_device == (uint64_t)cache_stat.st_dev;
    if (cache >= 0) close(cache);
    g_clear_error(&parse);
    uint64_t cache_inode = g_key_file_get_uint64(record, "contract", "cache_inode", &parse);
    valid = valid && !parse && cache_inode == (uint64_t)cache_stat.st_ino;
    g_clear_error(&parse);
    uint8_t task_digest[32];
    char actual[65];
    valid = valid && !identity_fd(task_fd, task_digest, NULL);
    digest_hex(task_digest, actual);
    valid = valid && !strcmp(actual, task_sha);
    GPtrArray *options = NULL, *exec = NULL, *environment = NULL;
    char *options_b64 = valid ? g_key_file_get_string(record, "plan", "options", NULL) : NULL;
    char *exec_b64 = valid ? g_key_file_get_string(record, "plan", "exec", NULL) : NULL;
    char *environment_b64 = valid ? g_key_file_get_string(record, "plan", "environment", NULL) : NULL;
    valid = valid && decode_array(options_b64, &options) && decode_array(exec_b64, &exec) &&
        decode_array(environment_b64, &environment) && options->len && exec->len && environment->len;
    GError *size_error = NULL;
    uint64_t receipt_size = g_key_file_get_uint64(record, "contract", "receipt_size", &size_error);
    valid = valid && !size_error && receipt_size > 0;
    g_clear_error(&size_error);
    if (options) g_ptr_array_free(options, TRUE);
    if (exec) g_ptr_array_free(exec, TRUE);
    if (environment) g_ptr_array_free(environment, TRUE);
    g_free(environment_b64); g_free(exec_b64); g_free(options_b64);
    g_free(task_sha); g_free(task_id); g_free(policy); g_free(version);
    g_strfreev(plan); g_strfreev(contract); g_strfreev(names);
    if (!valid) return fail(error, error_size, "managed launch contract mismatch");
    return 0;
}

int latcd_managed_launch_verify(const char *root, const char *id, int task_fd,
    const struct stat *identity, const char *digest,
    const LatcdManagedLaunchInput *current, char *error, size_t error_size)
{
    if (!root || !id || strlen(id) != 36 || !g_uuid_string_is_valid(id) ||
        task_fd < 0 || !identity || !digest_string(digest))
        return fail(error, error_size, "invalid managed launch verification");
    int directory = open_directory(root, false);
    char *name = g_strdup_printf("%s.launch", id);
    char *data = NULL;
    size_t size = 0;
    struct stat file;
    char actual_digest[65];
    int result = directory < 0 ? -1 : read_contract(directory, name, &data, &size,
        &file, actual_digest, error, error_size);
    if (!result && (file.st_dev != identity->st_dev || file.st_ino != identity->st_ino ||
        file.st_size != identity->st_size || strcmp(actual_digest, digest)))
        result = fail(error, error_size, "managed launch identity changed");
    GKeyFile *record = g_key_file_new();
    if (!result && (!g_key_file_load_from_data(record, data, size, G_KEY_FILE_NONE, NULL) ||
        exact_contract(root, record, id, task_fd, error, error_size))) result = -1;
    if (!result && current) {
        char *encoded = NULL;
        size_t encoded_size = 0;
        struct stat task;
        char encoded_digest[65];
        result = encode_contract(root, id, task_fd, current, &encoded, &encoded_size,
            &task, encoded_digest, error, error_size);
        if (!result && (encoded_size != size || memcmp(encoded, data, size))) result = -1;
        if (!result && strcmp(encoded_digest, digest)) result = -1;
        if (result) fail(error, error_size, "current launch differs from recorded contract");
        g_free(encoded);
    }
    g_key_file_unref(record);
    g_free(data);
    g_free(name);
    if (directory >= 0) close(directory);
    return result ? -1 : 0;
}

int latcd_managed_launch_validate_self(const char *root, const char *id, int task_fd,
    char *error, size_t error_size)
{
    if (!root || !id || strlen(id) != 36 || !g_uuid_string_is_valid(id) || task_fd < 0)
        return fail(error, error_size, "invalid managed launch recovery request");
    int directory = open_directory(root, false);
    char *name = g_strdup_printf("%s.launch", id);
    char *data = NULL;
    size_t size = 0;
    struct stat identity;
    char digest[65];
    int result = directory < 0 ? -1 : read_contract(directory, name, &data, &size,
        &identity, digest, error, error_size);
    GKeyFile *record = g_key_file_new();
    if (!result && (!g_key_file_load_from_data(record, data, size, G_KEY_FILE_NONE, NULL) ||
        exact_contract(root, record, id, task_fd, error, error_size))) result = -1;
    g_key_file_unref(record);
    g_free(data);
    g_free(name);
    if (directory >= 0) close(directory);
    return result ? -1 : 0;
}

int latcd_managed_launch_validate_bound(const char *root, const char *id, int task_fd,
    const struct stat *expected, const char *expected_digest,
    char *error, size_t error_size)
{
    if (!expected || !expected_digest || !digest_string(expected_digest))
        return fail(error, error_size, "missing bound managed launch identity");
    if (latcd_managed_launch_validate_self(root, id, task_fd,
                                            error, error_size)) return -1;
    int directory = open_directory(root, false);
    char *name = g_strdup_printf("%s.launch", id);
    char *data = NULL;
    size_t size = 0;
    struct stat identity;
    char digest[65];
    int result = directory < 0 ? -1 : read_contract(directory, name, &data, &size,
        &identity, digest, error, error_size);
    if (!result && (identity.st_dev != expected->st_dev ||
                    identity.st_ino != expected->st_ino ||
                    identity.st_size != expected->st_size ||
                    strcmp(digest, expected_digest))) {
        result = fail(error, error_size,
                      "managed launch identity differs from task state");
    }
    g_free(data);
    g_free(name);
    if (directory >= 0) close(directory);
    return result;
}

int latcd_managed_launch_discard(const char *root, const char *id, int task_fd,
    char *error, size_t error_size)
{
    if (!root || !id || strlen(id) != 36 || !g_uuid_string_is_valid(id) || task_fd < 0)
        return fail(error, error_size, "invalid managed launch discard request");
    int directory = open_directory(root, false);
    char *name = g_strdup_printf("%s.launch", id);
    struct stat path;
    if (directory < 0) {
        int saved = errno;
        g_free(name);
        /* No private directory means no record was ever installed here. */
        if (saved == ENOENT) return 0;
        return fail(error, error_size, "cannot open managed launch directory");
    }
    if (fstatat(directory, name, &path, AT_SYMLINK_NOFOLLOW)) {
        int saved = errno;
        close(directory);
        g_free(name);
        if (saved == ENOENT) return 0;
        return fail(error, error_size, "cannot inspect managed launch contract");
    }
    char *data = NULL;
    size_t size = 0;
    struct stat identity;
    char digest[65];
    int result = directory < 0 ? -1 : read_contract(directory, name, &data, &size,
        &identity, digest, error, error_size);
    GKeyFile *record = g_key_file_new();
    if (!result && (!g_key_file_load_from_data(record, data, size, G_KEY_FILE_NONE, NULL) ||
        exact_contract(root, record, id, task_fd, error, error_size))) result = -1;
    if (!result) result = latcd_cache_capacity_metadata_remove_checked(directory, name, &identity);
    g_key_file_unref(record);
    g_free(data);
    g_free(name);
    if (directory >= 0) close(directory);
    return result ? fail(error, error_size, "cannot discard managed launch contract") : 0;
}
