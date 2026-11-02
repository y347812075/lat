#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "worker-closure.h"
#include "managed-path.h"
#include "parson/parson.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#define CLOSURE_MAX_FILES 256
#define CLOSURE_MAX_MANIFEST (1024 * 1024)
#define CLOSURE_MAX_BYTES (1024ULL * 1024 * 1024)

static void closure_file_free(gpointer data)
{
    LatcdClosureFile *file = data;
    if (file->fd >= 0) close(file->fd);
    g_free(file->destination);
    g_free(file);
}

void latcd_worker_closure_clear(LatcdWorkerClosure *closure)
{
    if (closure && closure->files) g_ptr_array_free(closure->files, TRUE);
    if (closure) closure->files = NULL;
}

static gboolean valid_path(const char *path)
{
    if (!path || !g_str_has_prefix(path, "/usr/") || strlen(path) > 4095 ||
        strstr(path, "//") || path[strlen(path) - 1] == '/') return FALSE;
    gchar **parts = g_strsplit(path + 1, "/", -1);
    gboolean valid = TRUE;
    for (size_t i = 0; parts[i]; i++)
        if (!strcmp(parts[i], ".") || !strcmp(parts[i], "..")) valid = FALSE;
    g_strfreev(parts);
    return valid;
}

static int verify_file(const LatcdClosureFile *file)
{
    struct stat before, after;
    const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int seals = fcntl(file->fd, F_GET_SEALS);
    if (seals < 0 || (seals & required) != required ||
        fstat(file->fd, &before) || !S_ISREG(before.st_mode) || before.st_size < 0) {
        errno = ESTALE;
        return -1;
    }
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    char buf[65536];
    off_t offset = 0;
    while (offset < before.st_size) {
        ssize_t n = pread(file->fd, buf, MIN((off_t)sizeof(buf), before.st_size - offset), offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { g_checksum_free(sum); errno = EIO; return -1; }
        g_checksum_update(sum, (const guchar *)buf, n);
        offset += n;
    }
    gboolean match = !strcmp(g_checksum_get_string(sum), file->sha256);
    g_checksum_free(sum);
    if (!match || fstat(file->fd, &after) || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int snapshot_file(int source, const struct stat *source_stat)
{
    int target = memfd_create("latcd-closure", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (target < 0) return -1;
    char buf[65536];
    off_t offset = 0;
    while (offset < source_stat->st_size) {
        ssize_t n = pread(source, buf,
                          MIN((off_t)sizeof(buf), source_stat->st_size - offset), offset);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto failed;
        if (!n) { errno = ESTALE; goto failed; }
        for (ssize_t done = 0; done < n;) {
            ssize_t w = write(target, buf + done, n - done);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) goto failed;
            done += w;
        }
        offset += n;
    }
    if (fchmod(target, source_stat->st_mode & 0777) ||
        fcntl(target, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW |
              F_SEAL_SHRINK | F_SEAL_SEAL)) goto failed;
    int high = fcntl(target, F_DUPFD_CLOEXEC, 16);
    close(target);
    return high;
failed:
    close(target);
    return -1;
}

int latcd_worker_closure_verify(const LatcdWorkerClosure *closure)
{
    if (!closure || !closure->files || !closure->files->len) { errno = EINVAL; return -1; }
    for (guint i = 0; i < closure->files->len; i++)
        if (verify_file(g_ptr_array_index(closure->files, i))) return -1;
    return 0;
}

static gint compare_destination(gconstpointer a, gconstpointer b)
{
    const LatcdClosureFile *left = *(LatcdClosureFile *const *)a;
    const LatcdClosureFile *right = *(LatcdClosureFile *const *)b;
    return strcmp(left->destination, right->destination);
}

static void checksum_u64(GChecksum *sum, uint64_t value)
{
    guint64 encoded = GUINT64_TO_BE(value);
    g_checksum_update(sum, (const guchar *)&encoded, sizeof(encoded));
}

int latcd_worker_closure_identity(const LatcdWorkerClosure *closure, char digest[65])
{
    if (!digest) { errno = EINVAL; return -1; }
    if (latcd_worker_closure_verify(closure)) return -1;
    GPtrArray *sorted = g_ptr_array_new();
    for (guint i = 0; i < closure->files->len; i++)
        g_ptr_array_add(sorted, g_ptr_array_index(closure->files, i));
    g_ptr_array_sort(sorted, compare_destination);
    GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
    const char domain[] = "latcd-worker-closure-v1";
    g_checksum_update(sum, (const guchar *)domain, sizeof(domain));
    checksum_u64(sum, sorted->len);
    int result = -1;
    for (guint i = 0; i < sorted->len; i++) {
        LatcdClosureFile *file = g_ptr_array_index(sorted, i);
        struct stat st;
        if (!valid_path(file->destination) || fstat(file->fd, &st) || st.st_size < 0)
            goto out;
        for (guint j = 0; j < i; j++) {
            LatcdClosureFile *previous = g_ptr_array_index(sorted, j);
            size_t length = strlen(previous->destination);
            if (!strncmp(previous->destination, file->destination, length) &&
                (file->destination[length] == '\0' || file->destination[length] == '/')) {
                errno = EINVAL;
                goto out;
            }
        }
        size_t length = strlen(file->destination);
        checksum_u64(sum, length);
        g_checksum_update(sum, (const guchar *)file->destination, length);
        checksum_u64(sum, st.st_mode & 0777);
        checksum_u64(sum, st.st_size);
        g_checksum_update(sum, (const guchar *)file->sha256, 64);
    }
    g_strlcpy(digest, g_checksum_get_string(sum), 65);
    result = 0;
out:
    g_checksum_free(sum);
    g_ptr_array_free(sorted, TRUE);
    return result;
}

int latcd_worker_closure_load(const char *manifest, const char *build_id,
                              gboolean trusted, LatcdWorkerClosure *closure)
{
    char *raw = NULL;
    gsize length = 0;
    JSON_Value *value = NULL;
    int result = -1;
    if (!manifest || !build_id || !closure || closure->files) { errno = EINVAL; return -1; }
    if (trusted) {
        raw = g_malloc(CLOSURE_MAX_MANIFEST + 1);
        if (latcd_managed_config_read(manifest, raw, CLOSURE_MAX_MANIFEST + 1, &length)) goto out;
    } else if (!g_file_get_contents(manifest, &raw, &length, NULL) || length > CLOSURE_MAX_MANIFEST) {
        errno = EINVAL; goto out;
    }
    if (memchr(raw, 0, length)) { errno = EINVAL; goto out; }
    value = json_parse_string(raw);
    JSON_Object *root = value ? json_value_get_object(value) : NULL;
    JSON_Array *files = root ? json_object_get_array(root, "files") : NULL;
    const char *id = root ? json_object_get_string(root, "build_id") : NULL;
    if (!root || json_object_get_count(root) != 3 ||
        json_object_get_number(root, "version") != 1 || !id ||
        strlen(id) != json_object_get_string_len(root, "build_id") || strcmp(id, build_id) ||
        !files || !json_array_get_count(files) || json_array_get_count(files) > CLOSURE_MAX_FILES) {
        errno = EINVAL; goto out;
    }
    closure->files = g_ptr_array_new_with_free_func(closure_file_free);
    uint64_t total_size = 0;
    for (size_t i = 0; i < json_array_get_count(files); i++) {
        JSON_Object *item = json_array_get_object(files, i);
        const char *source = item ? json_object_get_string(item, "source") : NULL;
        const char *dest = item ? json_object_get_string(item, "destination") : NULL;
        const char *sha = item ? json_object_get_string(item, "sha256") : NULL;
        if (!item || json_object_get_count(item) != 3 || !source || source[0] != '/' ||
            strlen(source) != json_object_get_string_len(item, "source") || !valid_path(dest) ||
            strlen(dest) != json_object_get_string_len(item, "destination") || !sha || strlen(sha) != 64 ||
            strlen(sha) != json_object_get_string_len(item, "sha256")) { errno = EINVAL; goto out; }
        for (size_t j = 0; j < 64; j++)
            if (!g_ascii_isdigit(sha[j]) && !(sha[j] >= 'a' && sha[j] <= 'f')) {
                errno = EINVAL; goto out;
            }
        for (guint j = 0; j < closure->files->len; j++) {
            LatcdClosureFile *old = g_ptr_array_index(closure->files, j);
            if (!strcmp(old->destination, dest)) { errno = EINVAL; goto out; }
        }
        LatcdClosureFile *file = g_new0(LatcdClosureFile, 1);
        file->fd = trusted ? latcd_managed_file(source, 0) : open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (file->fd >= 0) {
            int high = fcntl(file->fd, F_DUPFD_CLOEXEC, 16);
            close(file->fd);
            file->fd = high;
        }
        file->destination = g_strdup(dest);
        memcpy(file->sha256, sha, sizeof(file->sha256));
        g_ptr_array_add(closure->files, file);
        struct stat before;
        if (file->fd < 0 || fstat(file->fd, &before) || !S_ISREG(before.st_mode) ||
            before.st_size < 0 || (trusted && (before.st_mode & 06000))) goto out;
        if ((uint64_t)before.st_size > CLOSURE_MAX_BYTES - total_size) {
            errno = EFBIG;
            goto out;
        }
        total_size += (uint64_t)before.st_size;
        int snapshot = snapshot_file(file->fd, &before);
        if (snapshot < 0) goto out;
        close(file->fd);
        file->fd = snapshot;
        if (verify_file(file)) goto out;
    }
    result = 0;
out:
    if (result) latcd_worker_closure_clear(closure);
    if (value) json_value_free(value);
    g_free(raw);
    return result;
}
